"""2.3 fixer: engine regressions from the review (mail-safety lens).

- the filter's own notification mails are never a user verdict / learned
  when dragged into a spam folder;
- overdue rescans do not pin the account loop to MIN_LOOP_WAIT_S while
  zap_pass cannot run (safe mode, rspamd backoff);
- the weekly-report mail claim is retried after a transient failure;
- threat mails are not held by the 30-min update hold.
"""

from __future__ import annotations

import datetime as dt
import time

from fakes_engine import setup_engine
from test_engine_mailhooks import LOG, MONDAY_0730, configured, eng, mail, notify_mail, outbox  # noqa: F401
from test_engine_scan import Harness


def _own_notification(eng, mail, h, kind="alert"):
    mail.ensure_schema()
    own = mail.new_message_id()
    conn = eng._open_conn()
    try:
        conn.execute("INSERT INTO mail_outbox(kind, recipient, subject, message_id, status, created_at) "
                     "VALUES(?, 'ole@bynet.example', 's', ?, 'sent', ?)", (kind, own, int(time.time())))
        conn.commit()
    finally:
        conn.close()
    mid = own.strip("<>")
    when = dt.datetime.fromtimestamp(h.t, dt.timezone.utc)
    h.client.add("INBOX", notify_mail(mid), internaldate=when)
    return mid


def test_own_notification_dragged_into_the_filter_folder_is_never_learned(eng, mail, monkeypatch):
    h = Harness(eng, monkeypatch, folders=("INBOX", "Junk", "Trash", "Spamfilter"), junk="Spamfilter",
                learn_grace_seconds=0)
    mid = _own_notification(eng, mail, h)
    h.scan()
    assert h.row(mid) is None
    h.poll()
    h.user_moves(mid, "INBOX", "Spamfilter")
    h.poll()
    h.advance(400)
    h.poll()
    assert h.row(mid) is None
    assert h.rspamd.learn_calls == []
    assert h.db.conn.execute("SELECT COUNT(*) FROM events WHERE event='user_junked'").fetchone()[0] == 0


def test_own_notification_in_the_provider_junk_folder_is_not_provider_junk(eng, mail, monkeypatch):
    h = Harness(eng, monkeypatch, folders=("INBOX", "Junk", "Trash", "Spamfilter"), junk="Spamfilter",
                learn_grace_seconds=0)
    mid = _own_notification(eng, mail, h)
    h.scan()
    h.poll()
    h.user_moves(mid, "INBOX", "Junk")
    h.poll()
    h.advance(400)
    h.poll()
    assert h.row(mid) is None and h.rspamd.learn_calls == []


def _wake_harness(tmp_path, monkeypatch):
    eng2 = setup_engine(tmp_path, monkeypatch)
    h = Harness(eng2, monkeypatch, idle_timeout=1500, poll_interval=600, daily_report=False)
    h.state.last_junk_poll = time.monotonic()
    h.state.last_retention = time.monotonic()
    h.deliver("z@x", score=5.0)
    h.scan()
    assert h.db.conn.execute("SELECT COUNT(*) FROM rescan_queue").fetchone()[0] == 1
    h.advance(46 * 60)
    return eng2, h


def test_overdue_rescans_do_not_pin_the_wait_in_safe_mode(tmp_path, monkeypatch):
    eng2, h = _wake_harness(tmp_path, monkeypatch)
    with h.db.tx():
        h.db.enter_safe_mode("all", "test")
    assert eng2.zap_pass(h.client, h.db, LOG, h.acc, h.acc.folder_map, h.state) == 0
    assert eng2._next_wake_in(h.db, h.acc, h.state) > 60


def test_overdue_rescans_do_not_pin_the_wait_during_rspamd_backoff(tmp_path, monkeypatch):
    eng2, h = _wake_harness(tmp_path, monkeypatch)
    h.state.rspamd_backoff_until = time.monotonic() + 600
    assert eng2.zap_pass(h.client, h.db, LOG, h.acc, h.acc.folder_map, h.state) == 0
    assert eng2._next_wake_in(h.db, h.acc, h.state) > 60


def test_an_overdue_rescan_that_can_run_waits_briefly_not_min_loop(tmp_path, monkeypatch):
    eng2, h = _wake_harness(tmp_path, monkeypatch)
    wait = eng2._next_wake_in(h.db, h.acc, h.state)
    assert wait == eng2.ZAP_OVERDUE_WAIT_S > eng2.MIN_LOOP_WAIT_S


def test_weekly_mail_is_retried_after_a_transient_failure(eng, mail, monkeypatch):
    configured(mail, weekly=True)
    h = Harness(eng, monkeypatch)
    h.t = MONDAY_0730
    svc = eng._services()
    real = svc.weekly_data
    calls = {"n": 0}

    def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("db busy")
        return real(*a, **k)

    monkeypatch.setattr(svc, "weekly_data", flaky)
    assert eng.maybe_mail_weekly(h.db, LOG) is False
    h.t += 600
    assert eng.maybe_mail_weekly(h.db, LOG) is True
    assert len(outbox(eng, "weekly")) == 1
    h.t += 600
    assert eng.maybe_mail_weekly(h.db, LOG) is False   # once per week
    assert len(outbox(eng, "weekly")) == 1


def test_threat_is_not_held_by_the_update_hold(tmp_path, monkeypatch):
    eng2 = setup_engine(tmp_path, monkeypatch)
    h = Harness(eng2, monkeypatch, threshold=10.0)
    eng2.record_version_start(h.db.conn)
    assert eng2.move_hold_until(h.db.conn) > h.t
    h.rspamd.symbols["v@x"] = {"CLAM_VIRUS": {"name": "CLAM_VIRUS", "score": 0.0, "options": ["Eicar"]}}
    h.deliver("v@x", score=2.0)
    # Ordinary spam below threshold + margin still waits for the hold.
    h.deliver("s@x", score=11.0)
    h.scan()
    assert h.row("v@x")["threat"] == "virus"
    h.advance(120)
    h.moves()
    assert "v@x" in h.client.msgids("Junk")
    assert "s@x" in h.client.msgids("INBOX")
