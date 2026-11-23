"""ENGINE 2.3: wiring of the mailer (B29) hooks.

* the scanner skips the filter's own notification mails (never scored,
  moved or learned), a forged look-alike is scanned;
* engine start: 'Spamfilteret har været stoppet fra … til …' before the old
  heartbeat is removed, and the mail worker starts;
* alerts at once (circuit breaker, login refused, safe mode) through
  mailer.notify with de-duplication per episode - and host-monitor's later
  mail with the same subject is skipped by the mailer CLI;
* the weekly report also by mail when 'Ugerapport' is on under
  Notifikationer (once per week, whichever account thread comes first);
* without a mail server nothing changes and nothing raises.
"""

from __future__ import annotations

import datetime as dt
import logging
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fakes_ui_mail  # noqa: E402
from fakes_engine import setup_engine  # noqa: E402
from test_engine_scan import Harness  # noqa: E402

LOG = logging.getLogger("test-mailhooks")
MONDAY_0730 = dt.datetime(2026, 10, 26, 6, 30, tzinfo=dt.timezone.utc).timestamp()
CIRCUIT_SUBJECT = ("Spamfilter: Konto acct: sikkerhedsbremsen har sat flytning på pause - mange mails blev "
                   "flyttet på kort tid. Tjek Fanget spam og genoptag under Konti")


@pytest.fixture
def eng(tmp_path, monkeypatch):
    e = setup_engine(tmp_path, monkeypatch)
    m = fakes_ui_mail.install(monkeypatch)
    m.stop_worker()
    e._mailer()  # sync the mailer's paths to this engine
    yield e
    m.stop_worker()
    fakes_ui_mail.reset()


@pytest.fixture
def mail(eng):
    import mailer

    return mailer


def configured(mail, *, alert=True, weekly=False):
    fakes_ui_mail.configure_smtp(mail)
    res = mail.save_routes({"alert": {"on": alert, "to": "ole@bynet.example"},
                            "weekly": {"on": weekly, "to": "ole@bynet.example"}})
    assert res["ok"], res


def outbox(eng, kind=None):
    conn = eng._open_conn()
    try:
        rows = conn.execute("SELECT * FROM mail_outbox ORDER BY id").fetchall()
    finally:
        conn.close()
    return [r for r in rows if kind is None or r["kind"] == kind]


def notify_mail(msgid: str, *, header: bool = True) -> bytes:
    lines = ["From: Spamfilter Hjemmeserver <ole@bynet.example>", "To: ole@bynet.example",
             "Subject: Spamfilter: alarm", f"Message-ID: <{msgid}>", "Auto-Submitted: auto-generated"]
    if header:
        lines.append("X-TH-Spamfilter: notify")
    return ("\r\n".join(lines) + "\r\n\r\nTekst\r\n").encode()


# ----- own notifications ---------------------------------------------------------------


def test_own_notification_is_never_scanned(eng, mail, monkeypatch):
    h = Harness(eng, monkeypatch)
    mail.ensure_schema()
    own = mail.new_message_id()
    conn = eng._open_conn()
    conn.execute("INSERT INTO mail_outbox(kind, recipient, subject, message_id, status, created_at) "
                 "VALUES('alert', 'ole@bynet.example', 's', ?, 'sent', ?)", (own, int(time.time())))
    eng.mailidentity.bind(conn, "*notification*", own.strip("<>"), notify_mail(own.strip("<>")))
    conn.commit()
    conn.close()
    when = dt.datetime.fromtimestamp(h.t, dt.timezone.utc)
    h.client.add("INBOX", notify_mail(own.strip("<>")), internaldate=when)
    forged = mail.new_message_id().strip("<>")             # our form, never sent by us
    h.client.add("INBOX", notify_mail(forged), internaldate=when)
    no_hdr = mail.new_message_id()
    conn = eng._open_conn()
    conn.execute("INSERT INTO mail_outbox(kind, recipient, subject, message_id, status, created_at) "
                 "VALUES('alert', 'ole@bynet.example', 's', ?, 'sent', ?)", (no_hdr, int(time.time())))
    conn.close()
    h.client.add("INBOX", notify_mail(no_hdr.strip("<>"), header=False), internaldate=when)
    h.rspamd.default = 20.0
    h.scan()
    assert own.strip("<>") not in h.scanned_ids()
    assert h.row(own.strip("<>")) is None
    assert forged in h.scanned_ids() and no_hdr.strip("<>") in h.scanned_ids()
    h.advance(120)
    h.moves()
    assert own.strip("<>") in h.client.msgids("INBOX")
    assert h.rspamd.learn_calls == []


# ----- engine start ---------------------------------------------------------------------


def test_downtime_notice_before_the_old_heartbeat_is_removed(eng, mail, tmp_path):
    configured(mail)
    hb = tmp_path / "heartbeat"
    hb.write_text(f"{int(time.time()) - 3600} oldboot")
    eng._mail_startup(LOG)
    rows = outbox(eng, "alert")
    assert len(rows) == 1 and rows[0]["subject"] == "Spamfilter: kører igen efter et stop"
    assert mail.worker_alive()
    mail.stop_worker()
    # A fresh heartbeat (a quick restart) sends nothing.
    hb.write_text(f"{int(time.time()) - 60} oldboot")
    eng._mail_startup(LOG)
    assert len(outbox(eng, "alert")) == 1


def test_main_checks_the_gap_before_start_boot(eng, monkeypatch):
    order = []
    monkeypatch.setattr(eng, "_mail_startup", lambda log: order.append("mail"))
    monkeypatch.setattr(eng, "_start_boot", lambda: order.append("boot"))

    def stop(*_a, **_k):
        order.append("dashboard")
        raise SystemExit(0)

    monkeypatch.setattr(eng, "_start_dashboard", stop)
    monkeypatch.setattr(eng, "install_signal_handlers", lambda: None)
    with pytest.raises(SystemExit):
        eng.main()
    assert order[:2] == ["mail", "boot"]


def test_mail_startup_without_a_mail_server_is_silent(eng, mail, tmp_path):
    (tmp_path / "heartbeat").write_text(f"{int(time.time()) - 7200} x")
    eng._mail_startup(LOG)
    assert outbox(eng) == []
    mail.stop_worker()


# ----- alerts ---------------------------------------------------------------------------


def test_circuit_breaker_alert_once_per_episode(eng, mail, monkeypatch):
    configured(mail)
    h = Harness(eng, monkeypatch, circuit_max_moves_per_hour=1, circuit_min_moves=100)
    for i in range(3):
        h.deliver(f"c{i}@x", score=14.0)
    h.scan()
    h.advance(5)
    h.moves()
    assert eng.circuit_open(h.db.conn, "acct")
    rows = outbox(eng, "alert")
    assert [r["subject"] for r in rows] == [CIRCUIT_SUBJECT]
    h.moves()
    assert len(outbox(eng, "alert")) == 1
    # host-monitor's mail for the same problem a few minutes later is skipped.
    assert mail.main(["notify", "--kind", "alert", "--subject", CIRCUIT_SUBJECT, "--text", "x"]) == 0
    assert len(outbox(eng, "alert")) == 1
    # A new episode (resumed, tripped again) mails again.
    eng.resume_moves(h.db.conn, "acct", "admin")
    h.advance(3600)
    for i in range(3, 6):
        h.deliver(f"c{i}@x", score=14.0)
    h.scan()
    h.advance(5)
    h.moves()
    assert len(outbox(eng, "alert")) == 2


def test_login_alert_once_and_cleared_after_a_good_login(eng, mail, monkeypatch):
    configured(mail)
    h = Harness(eng, monkeypatch)
    eng._alert_auth(h.db, h.acc)
    eng._alert_auth(h.db, h.acc)
    rows = outbox(eng, "alert")
    assert len(rows) == 1 and rows[0]["subject"] == "Spamfilter: Konto acct: login afvist - tjek adgangskoden"
    eng.alert_clear(h.db.conn, "auth:acct")
    eng._alert_auth(h.db, h.acc)
    assert len(outbox(eng, "alert")) == 2
    import inspect

    src = inspect.getsource(eng._run_account)
    assert "_alert_auth(db, acc)" in src and 'alert_clear(db.conn, f"auth:{acc.name}")' in src


def test_safe_mode_alert_once(eng, mail, monkeypatch):
    configured(mail)
    h = Harness(eng, monkeypatch, safe_mode_unseen_cap=2)
    for i in range(3):
        h.deliver(f"s{i}@x")
    h.scan()
    h.scan()
    rows = outbox(eng, "alert")
    assert len(rows) == 1 and "sikkerhedstilstand" in rows[0]["subject"]
    # Back under the cap: cleared; the next episode mails again.
    for uid in h.client.uids("INBOX")[:2]:
        h.client.folders["INBOX"].msgs[uid].flags.add("\\Seen")
    h.scan()
    for i in range(3, 6):
        h.deliver(f"s{i}@x")
    h.scan()
    assert len(outbox(eng, "alert")) == 2


def test_alerts_without_a_mail_server_never_raise(eng, monkeypatch):
    h = Harness(eng, monkeypatch, circuit_max_moves_per_hour=1, circuit_min_moves=100)
    for i in range(3):
        h.deliver(f"c{i}@x", score=14.0)
    h.scan()
    h.advance(5)
    h.moves()
    assert eng.circuit_open(h.db.conn, "acct") and outbox(eng) == []


# ----- weekly report by mail ----------------------------------------------------------------


def test_weekly_report_mail_once_when_turned_on(eng, mail, monkeypatch):
    configured(mail, weekly=True)
    h = Harness(eng, monkeypatch)
    h.t = MONDAY_0730
    assert eng.maybe_mail_weekly(h.db, LOG) is True
    rows = outbox(eng, "weekly")
    assert len(rows) == 1 and "uge 43" in rows[0]["subject"] and rows[0]["recipient"] == "ole@bynet.example"
    assert eng.maybe_mail_weekly(h.db, LOG) is False
    # A second account thread does not send it again either.
    db2 = eng.Db("other")
    assert eng.maybe_mail_weekly(db2, LOG) is False
    db2.close()
    assert [e[0] for e in h.events("weekly_report_mailed")] == ["weekly_report_mailed"]
    sent = fakes_ui_mail.flush()
    assert sent and "Ugerapport" in fakes_ui_mail.text_of(sent[0])


def test_weekly_report_mail_off_or_outside_the_window(eng, mail, monkeypatch):
    configured(mail, weekly=False)
    h = Harness(eng, monkeypatch)
    h.t = MONDAY_0730
    assert eng.maybe_mail_weekly(h.db, LOG) is False
    h.t = MONDAY_0730 + 3 * 86400
    configured(mail, weekly=True)
    assert eng.maybe_mail_weekly(h.db, LOG) is False
    h.t = MONDAY_0730
    assert eng.maybe_mail_weekly(h.db, LOG) is True  # turned on later: still that week
    assert len(outbox(eng, "weekly")) == 1


def test_weekly_mail_runs_from_the_loop(eng, mail, monkeypatch):
    configured(mail, weekly=True)
    h = Harness(eng, monkeypatch)
    h.t = MONDAY_0730
    h.loop()
    assert len(outbox(eng, "weekly")) == 1


def test_recorded_notification_id_does_not_exempt_different_content(eng, mail, monkeypatch):
    h = Harness(eng, monkeypatch)
    mail.ensure_schema()
    own = mail.new_message_id()
    raw = notify_mail(own.strip('<>'))
    conn = eng._open_conn()
    try:
        conn.execute("INSERT INTO mail_outbox(kind, recipient, subject, message_id, status, created_at) "
                     "VALUES('alert', 'owner@example.org', 's', ?, 'sent', ?)", (own, int(time.time())))
        eng.mailidentity.bind(conn, '*notification*', own.strip('<>'), raw)
        conn.commit()
    finally:
        conn.close()
    h.client.add('INBOX', raw + b'\r\nDifferent malicious payload')
    h.rspamd.default = 20
    h.scan()
    assert len(h.rspamd.scan_calls) == 1 and h.db.count_pending_moves() == 1
