"""ENGINE 2.2: own platform on rspamd's domain list (B2b), aged scans (B7),
ham guard in autolearn + learn ledger (B6c/B6a) and the weekly report (B21)."""

from __future__ import annotations

import datetime as dt
import email
import email.policy
import json
import logging
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import make_account, make_message, setup_engine, stub_mailctx  # noqa: E402
from test_engine_scan import Harness  # noqa: E402

LOG = logging.getLogger("test")
DAY = 86400
HOUR = 3600


@pytest.fixture
def eng(tmp_path, monkeypatch):
    return setup_engine(tmp_path, monkeypatch)


def _sym(name, score, options=()):
    return {name: {"name": name, "score": score, "options": list(options)}}


def _syms(h, msgid):
    return {s["n"]: s for s in json.loads(h.row(msgid)["symbols"])}


# ----- config -------------------------------------------------------------------


def _write_config(eng, body):
    Path(eng.CONFIG_PATH).write_text(body)


BASE_YML = """
defaults:
  mode: move
  threshold: 10
accounts:
  - name: bynet
    user: ole@bynet.example
    imap_host: imap.example.net
    password: x
{extra}
"""


def test_config_defaults_for_22_fields(eng):
    _write_config(eng, BASE_YML.format(extra=""))
    acc = eng.load_account_configs(eng.CONFIG_PATH)[0]
    assert acc.owner_platform_domains == ["vexar.example"]
    assert acc.webshop_domains == ["pinsikbing.example", "gravisk.example", "vexar.example"]
    assert acc.aged_scan_hours == 6.0


def test_config_22_fields_are_normalised_and_validated(eng):
    _write_config(eng, BASE_YML.format(extra="    owner_platform_domains: ['*.Shop.Example', '@b.example']\n"
                                             "    webshop_domains: []\n    aged_scan_hours: 0\n"))
    acc = eng.load_account_configs(eng.CONFIG_PATH)[0]
    assert acc.owner_platform_domains == ["shop.example", "b.example"]
    assert acc.webshop_domains == [] and acc.aged_scan_hours == 0.0
    _write_config(eng, BASE_YML.format(extra="    owner_platform_domains: ['not a domain']\n"))
    with pytest.raises(eng.ConfigError):
        eng.load_account_configs(eng.CONFIG_PATH)
    _write_config(eng, BASE_YML.format(extra="    aged_scan_hours: -1\n"))
    with pytest.raises(eng.ConfigError):
        eng.load_account_configs(eng.CONFIG_PATH)


# ----- B2b: TH_OWN_PLATFORM_URIBL ------------------------------------------------

URIBL_OPTS = ["vexar.example:from_mime", "vexar.example:url", "vexar.example:email"]


def test_own_platform_uribl_is_offset(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", threshold=10.0)
    h.rspamd.scores["shop@x"] = 12.95
    h.rspamd.symbols["shop@x"] = {**_sym("RSPAMD_URIBL", 4.5, URIBL_OPTS), **_sym("BAYES_HAM", -1.0)}
    h.deliver("shop@x", sender="ordre@vexar.example")
    h.scan()
    r = h.row("shop@x")
    syms = _syms(h, "shop@x")
    assert syms["TH_OWN_PLATFORM_URIBL"]["s"] == -4.5
    assert syms["TH_OWN_PLATFORM_URIBL"]["o"] == ["vexar.example"]
    assert r["our_score"] == pytest.approx(8.45) and r["our_action"] == "none"
    assert r["rspamd_score"] == pytest.approx(12.95)
    ev = h.events("own_domain_uribl")
    assert len(ev) == 1 and "udlignet" in ev[0][2] and "vexar.example" in ev[0][2]


@pytest.mark.parametrize("extra, why", [
    (_sym("DBL_PHISH", 7.5, ["evil.example:url"]), "andre fund: DBL_PHISH"),
    (_sym("URIBL_BLACK", 7.5), "andre fund: URIBL_BLACK"),
    (_sym("ABUSE_SURBL", 5.0), "andre fund: ABUSE_SURBL"),
    (_sym("PHISHED_OPENPHISH", 7.0), "andre fund: PHISHED_OPENPHISH"),
    (_sym("CLAM_VIRUS", 20.0), "andre fund: CLAM_VIRUS"),
])
def test_no_offset_with_other_url_reputation_or_virus(eng, monkeypatch, extra, why):
    h = Harness(eng, monkeypatch, mode="move", threshold=10.0)
    h.rspamd.scores["shop@x"] = 12.0
    h.rspamd.symbols["shop@x"] = {**_sym("RSPAMD_URIBL", 4.5, URIBL_OPTS), **extra}
    h.deliver("shop@x")
    h.scan()
    assert "TH_OWN_PLATFORM_URIBL" not in _syms(h, "shop@x")
    assert h.row("shop@x")["our_score"] == pytest.approx(12.0)
    ev = h.events("own_domain_uribl")
    assert len(ev) == 1 and "beholdt" in ev[0][2] and why in ev[0][2]


def test_no_offset_when_another_domain_is_listed(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", threshold=10.0)
    h.rspamd.scores["mix@x"] = 12.0
    h.rspamd.symbols["mix@x"] = _sym("RSPAMD_URIBL", 4.5, ["vexar.example:url", "bad.example:url"])
    h.deliver("mix@x")
    h.scan()
    assert "TH_OWN_PLATFORM_URIBL" not in _syms(h, "mix@x")
    assert "andre domæner: bad.example" in h.events("own_domain_uribl")[0][2]


def test_uribl_on_foreign_domain_is_untouched_and_not_logged(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", threshold=10.0)
    h.rspamd.scores["f@x"] = 12.0
    h.rspamd.symbols["f@x"] = _sym("RSPAMD_URIBL", 4.5, ["bad.example:url"])
    h.deliver("f@x")
    h.scan()
    assert "TH_OWN_PLATFORM_URIBL" not in _syms(h, "f@x")
    assert h.events("own_domain_uribl") == []


def test_own_mailbox_and_webshop_domains_count_as_owner(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", threshold=10.0, owner_platform_domains=[])
    h.rspamd.scores["own@x"] = 6.0
    h.rspamd.symbols["own@x"] = _sym("RSPAMD_URIBL", 4.5, ["gravisk.example:url", "www.example-a.dk:url"])
    h.deliver("own@x")
    h.scan()
    assert _syms(h, "own@x")["TH_OWN_PLATFORM_URIBL"]["s"] == -4.5


def test_owner_domains_helper(eng):
    acc = type("A", (), {"user": "x@Molt.example", "owner_platform_domains": ["vexar.example"],
                         "webshop_domains": ["gravisk.example", "vexar.example"]})()
    assert eng.owner_domains(acc) == ["vexar.example", "gravisk.example", "molt.example"]
    assert eng.url_reputation_hits(["DBL_SPAM", "CLAM_VIRUS_FAIL", "MW_SURBL_MULTI", "BAYES_SPAM",
                                    "SEM_URIBL_FRESH15_UNKNOWN_FAIL", "URIBL_GREY"]) == [
        "DBL_SPAM", "MW_SURBL_MULTI", "SEM_URIBL_FRESH15_UNKNOWN_FAIL"]


# ----- B7: aged scans ------------------------------------------------------------


def _auth_stub(symbols):
    stub = stub_mailctx()
    stub.provider_auth_symbols = lambda ctx: list(symbols)
    return stub


def test_fresh_mail_is_scanned_normally(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("fresh@x", score=3.0)
    h.scan()
    call = h.rspamd.scan_calls[-1]
    assert "Settings" not in call["headers"]
    r = h.row("fresh@x")
    assert r["aged"] == 0 and "TH_AGED_SCAN" not in _syms(h, "fresh@x")
    assert h.stat("aged_scanned") == 0


def test_aged_mail_sends_settings_and_uses_provider_auth(tmp_path, monkeypatch):
    eng = setup_engine(tmp_path, monkeypatch, mailctx=_auth_stub(
        [{"n": "TH_PROVIDER_AUTH_PASS", "s": -1.0, "o": ["node4.spamfilter.io", "dkim=pass", "dmarc=pass"]}]))
    h = Harness(eng, monkeypatch, mode="move")
    old = dt.datetime.fromtimestamp(h.t - 7 * HOUR, dt.timezone.utc)
    h.rspamd.scores["old@x"] = 6.0
    h.rspamd.symbols["old@x"] = {**_sym("R_DKIM_REJECT", 1.0, ["datamail.example:s=k1"]),
                                 **_sym("R_DKIM_ALLOW", -0.2, ["mandrillapp.com:s=mte1"]),
                                 **_sym("BAYES_HAM", -1.0)}
    h.deliver("old@x", internaldate=old)
    h.scan()
    call = h.rspamd.scan_calls[-1]
    settings = json.loads(call["headers"]["Settings"])
    assert settings == {"symbols_disabled": list(eng.AGED_DISABLED_SYMBOLS)}
    assert "R_DKIM_REJECT" not in settings["symbols_disabled"]   # keeps R_DKIM_ALLOW alive
    r = h.row("old@x")
    syms = _syms(h, "old@x")
    assert r["aged"] == 1
    assert syms["R_DKIM_REJECT"]["s"] == 0.0 and "sen scanning" in syms["R_DKIM_REJECT"]["o"]
    assert r["rspamd_score"] == pytest.approx(5.0)          # 6.0 minus the neutralised DKIM reject
    assert syms["TH_AGED_SCAN"]["o"] == ["alder=7t"]
    assert syms["TH_PROVIDER_AUTH_PASS"]["s"] == -1.0
    assert r["our_score"] == pytest.approx(4.0)
    assert json.loads(r["sender_auth"])["dkim"] == ["mandrillapp.com"]
    assert h.stat("aged_scanned") == 1
    assert "aged" in h.events("scan")[-1][2]


def test_aged_scan_threshold_is_configurable_and_can_be_off(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", aged_scan_hours=0)
    h.deliver("old@x", score=1.0, internaldate=dt.datetime.fromtimestamp(h.t - 30 * DAY, dt.timezone.utc))
    h.scan()
    assert "Settings" not in h.rspamd.scan_calls[-1]["headers"] and h.row("old@x")["aged"] == 0
    h2 = Harness(eng, monkeypatch, mode="move", name="acct2", aged_scan_hours=1)
    h2.deliver("hour@x", score=1.0, internaldate=dt.datetime.fromtimestamp(h2.t - 2 * HOUR, dt.timezone.utc))
    h2.scan()
    assert "Settings" in h2.rspamd.scan_calls[-1]["headers"] and h2.row("hour@x")["aged"] == 1


def test_provider_auth_fail_distrusts_allow_rule_in_aged_scan(tmp_path, monkeypatch):
    eng = setup_engine(tmp_path, monkeypatch, mailctx=_auth_stub(
        [{"n": "TH_PROVIDER_AUTH_FAIL", "s": 2.0, "o": ["mx2.gigahost.dk", "dmarc=fail", "p=reject"]}]))
    h = Harness(eng, monkeypatch, mode="move", threshold=8.0)
    eng.add_sender_rule(h.db.conn, "*", "@bank.example", "allow")
    h.rspamd.scores["fake@x"] = 7.0
    h.deliver("fake@x", sender="kunde@bank.example",
              internaldate=dt.datetime.fromtimestamp(h.t - DAY, dt.timezone.utc))
    h.scan()
    r = h.row("fake@x")
    assert r["our_score"] == pytest.approx(9.0) and r["our_action"] == "pending_move"
    assert r["rule_hit"] is None


def test_rspamd_scan_settings_header_cannot_be_injected_by_context(eng, monkeypatch):
    seen = {}

    def post(url, data=b"", headers=None, timeout=None):
        seen.update(headers or {})
        return type("R", (), {"status_code": 200, "json": lambda self=None: {"score": 1.0, "symbols": {}}})()

    monkeypatch.setattr(eng.requests, "post", post)
    acc = make_account(eng)
    ctx = {"headers": {"Settings": '{"actions":{"reject":1}}', "Settings-Id": "x", "IP": "192.0.2.1"}}
    eng.rspamd_scan(b"Subject: x\r\n\r\nbody", acc, ctx)
    assert "Settings" not in seen and "Settings-Id" not in seen and seen["IP"] == "192.0.2.1"
    res = eng.rspamd_scan(b"Subject: x\r\n\r\nbody", acc, ctx, aged=True)
    assert seen["Settings"] == eng.AGED_SETTINGS_HEADER and res.aged is True


def test_is_aged_and_scan_age(eng):
    acc = type("A", (), {"aged_scan_hours": 6.0})()
    assert eng.is_aged(acc, 1000, now=1000 + 6 * HOUR) is False
    assert eng.is_aged(acc, 1000, now=1000 + 6 * HOUR + 1) is True
    assert eng.is_aged(acc, None, now=10 ** 9) is False
    assert eng.scan_age_s("garbage", now=5) is None


# ----- B6c: ham guard -----------------------------------------------------------


def test_ham_guard_reasons(eng):
    conn = sqlite3.connect(eng.DB_PATH)
    conn.row_factory = sqlite3.Row
    g = eng.ham_guard_reason
    assert g(conn, "a", symbols=[{"n": "TH_BRAND_SPOOF", "s": 5}], final=-1, rspamd_score=-1)[0] == "phishing"
    assert g(conn, "a", symbols=[{"n": "PHISHED_OPENPHISH", "s": 0}], final=0, rspamd_score=0)[0] == "phishing"
    # Without Bayes (-3) and our own newsletter bonus (-1.5): 0 + 3 + 1.5 = 4.5 < 5.
    syms = [{"n": "BAYES_HAM", "s": -3.0}, {"n": "TH_NEWSLETTER", "s": -1.5}, {"n": "X", "s": 4.5}]
    assert g(conn, "a", symbols=syms, final=0.0, rspamd_score=1.5) is None
    syms = [{"n": "BAYES_HAM", "s": -3.0}, {"n": "TH_NEWSLETTER", "s": -1.5}, {"n": "X", "s": 6.5}]
    assert g(conn, "a", symbols=syms, final=2.0, rspamd_score=3.5)[0] == "blind_score"
    eng.add_sender_rule(conn, "*", "@blocked.example", "block")
    assert g(conn, "a", symbols=[], final=-2, rspamd_score=-2, sender="x@mail.blocked.example") == (
        "blocked_sender", "@blocked.example")
    assert g(conn, "a", symbols=[], final=-2, rspamd_score=-2, sender="ok@else.example",
             envelope_from="b@blocked.example")[0] == "blocked_sender"
    # Under the limit only because of our own trust bonus.
    trust = [{"n": "TH_NEWSLETTER", "s": -1.5}]
    assert g(conn, "a", symbols=trust, final=-0.5, rspamd_score=1.0,
             trust_limit=eng.AUTOLEARN_HAM_MAX_SCORE)[0] == "trust_only"
    assert g(conn, "a", symbols=[{"n": "TH_REPLY", "s": -5.0}], final=-3.5, rspamd_score=1.5,
             trust_limit=eng.AUTOLEARN_HAM_MAX_SCORE) is None          # TH_REPLY allows up to 2.0
    # An error correction (own platform offset) is not a trust bonus.
    assert g(conn, "a", symbols=[{"n": "TH_OWN_PLATFORM_URIBL", "s": -4.5}, {"n": "RSPAMD_URIBL", "s": 4.5}],
             final=0.0, rspamd_score=4.5, trust_limit=eng.AUTOLEARN_HAM_MAX_SCORE) is None
    assert g(conn, "a", symbols="not json", final=None, rspamd_score=None) is None


def test_autolearn_ham_guard_skips_phishing_and_logs(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.rspamd.scores["phish@x"] = -1.0
    h.rspamd.symbols["phish@x"] = {**_sym("BAYES_HAM", -3.0), **_sym("TH_LURE_COMBO", 0.0)}
    uid = h.deliver("phish@x")
    uid2 = h.deliver("ok@x", score=-1.0)
    h.scan()
    for u in (uid, uid2):
        h.client.folders["INBOX"].msgs[u].flags.add("\\Seen")
    h.advance(7 * DAY + 1)
    assert h.eng.autolearn_pass(h.client, h.db, LOG, h.acc, h.acc.folder_map) == {"spam": 0, "ham": 1}
    outcomes = {e["message_id"]: e["outcome"] for e in eng.autolearn_entries(h.db.conn)}
    assert outcomes == {"phish@x": "ham_guard", "ok@x": "learned"}
    ev = h.events("ham_guard")
    assert ev == [("ham_guard", "phish@x", "autolearn phishing: TH_LURE_COMBO")]
    assert h.stat("ham_guarded") == 1
    assert h.row("phish@x")["learned_as"] is None
    # Recorded once: never retried.
    assert h.eng.autolearn_pass(h.client, h.db, LOG, h.acc, h.acc.folder_map) == {"spam": 0, "ham": 0}
    assert len(h.events("ham_guard")) == 1


def test_autolearn_ham_guard_trust_only(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.rspamd.scores["nl@x"] = 1.0
    h.rspamd.symbols["nl@x"] = _sym("X", 1.0)
    uid = h.deliver("nl@x")
    h.scan()
    # Pretend our own newsletter bonus brought it down to -0.5.
    with h.db.tx():
        h.db.update_message("nl@x", our_score=-0.5, symbols=json.dumps(
            [{"n": "TH_NEWSLETTER", "s": -1.5, "o": []}, {"n": "X", "s": 1.0, "o": []}]))
    h.client.folders["INBOX"].msgs[uid].flags.add("\\Seen")
    h.advance(7 * DAY + 1)
    assert h.eng.autolearn_pass(h.client, h.db, LOG, h.acc, h.acc.folder_map)["ham"] == 0
    assert "trust_only" in h.events("ham_guard")[0][2]


# ----- B6: learn ledger ------------------------------------------------------------


def test_learn_ledger_records_class_also_without_message_row(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    assert eng.learn_message(h.db, h.acc, make_message("nr@x"), "ham", "nr@x", reason="bootstrap job=22") \
        == "learned"
    row = h.db.conn.execute("SELECT kind, source FROM learn_ledger WHERE message_id='nr@x'").fetchone()
    assert tuple(row) == ("ham", "bootstrap job=22")
    h.advance(eng.FLIP_FLOP_COOLDOWN_S + 1)
    assert eng.learn_message(h.db, h.acc, make_message("nr@x"), "spam", "nr@x", reason="learn_list job=1") \
        == "learned"
    row = h.db.conn.execute("SELECT kind, source FROM learn_ledger WHERE message_id='nr@x'").fetchone()
    assert tuple(row) == ("spam", "learn_list job=1")


def test_learn_ledger_missing_table_is_harmless(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.db.conn.execute("DROP TABLE learn_ledger")
    assert eng.learn_message(h.db, h.acc, make_message("a@x"), "spam", "a@x") == "learned"


# ----- B21: weekly report ------------------------------------------------------------

# Monday 2026-10-26 07:30 Copenhagen (CET, UTC+1) = 06:30 UTC.
MONDAY_0730 = dt.datetime(2026, 10, 26, 6, 30, tzinfo=dt.timezone.utc).timestamp()


def _kv(h, **kv):
    h.db.conn.execute("CREATE TABLE IF NOT EXISTS settings_kv (key TEXT PRIMARY KEY, value TEXT)")
    for k, v in kv.items():
        h.db.conn.execute("INSERT OR REPLACE INTO settings_kv(key, value) VALUES(?,?)", (k, v))
    h.db.conn.commit()


def _weekly_harness(eng, monkeypatch, tmp_path, **over):
    _write_config(eng, BASE_YML.format(extra="").replace("name: bynet", "name: acct")
                  .replace("ole@bynet.example", "user@example-a.dk"))
    monkeypatch.setattr(eng, "RSPAMD_LEARN_URL", "http://rspamd.invalid:11334")
    h = Harness(eng, monkeypatch, mode="move", **over)
    h.t = MONDAY_0730
    return h


def test_weekly_due_window(eng):
    assert eng.weekly_due_window(MONDAY_0730)[1] == "2026-W43"
    assert eng.weekly_due_window(MONDAY_0730 - 30 * 60) is None          # Monday 07:00
    assert eng.weekly_due_window(MONDAY_0730 + 47 * HOUR)[1] == "2026-W43"
    assert eng.weekly_due_window(MONDAY_0730 + 49 * HOUR) is None         # Wednesday


def test_weekly_report_is_off_by_default(eng, monkeypatch, tmp_path):
    h = _weekly_harness(eng, monkeypatch, tmp_path)
    assert eng.maybe_send_weekly(h.client, h.db, LOG, h.acc, h.acc.folder_map) is False
    assert not any(c[0] == "append" for c in h.client.writes)


def test_weekly_report_sent_once_and_never_scanned(eng, monkeypatch, tmp_path):
    h = _weekly_harness(eng, monkeypatch, tmp_path)
    _kv(h, weekly_enabled="1")
    n_before = len(h.client.uids("INBOX"))
    assert eng.maybe_send_weekly(h.client, h.db, LOG, h.acc, h.acc.folder_map) is True
    assert eng.maybe_send_weekly(h.client, h.db, LOG, h.acc, h.acc.folder_map) is False   # once per week
    uids = h.client.uids("INBOX")
    assert len(uids) == n_before + 1
    raw = h.client.folders["INBOX"].msgs[uids[-1]].raw
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    assert msg["X-TH-Spamfilter"] == "report"
    assert msg["Subject"] == "Spamfilter: ugerapport for uge 43"
    assert msg["Message-ID"] == "<weekly-acct-2026-w43@hjemmeserver.spamfilter>"
    text = msg.get_body(("plain",)).get_content()
    assert "Webshop-post: 0 mails fra pinsikbing.example/gravisk.example/vexar.example – 0 flyttet" in text
    assert eng.receipt_sent(h.db.conn, "acct", "2026-W43", kind="weekly")
    assert h.events("weekly_report_sent")
    # The scanner skips it (registered like the daily receipt, E12).
    scans = len(h.rspamd.scan_calls)
    h.scan()
    assert len(h.rspamd.scan_calls) == scans


def test_weekly_report_only_for_admin_mailbox_unless_users_on(eng, monkeypatch, tmp_path):
    h = _weekly_harness(eng, monkeypatch, tmp_path)
    other = eng.Account(**{**h.acc.__dict__, "name": "other"})
    _kv(h, weekly_enabled="1", weekly_admin_account="acct")
    assert eng.weekly_recipient(h.db.conn, h.acc) == "full"
    assert eng.weekly_recipient(h.db.conn, other, [h.acc, other]) is None
    _kv(h, weekly_users="1")
    assert eng.weekly_recipient(h.db.conn, other, [h.acc, other]) == "short"
    shadow = eng.Account(**{**h.acc.__dict__, "name": "shadow", "mode": "shadow"})
    assert eng.weekly_recipient(h.db.conn, shadow, [h.acc, shadow]) is None
    _kv(h, weekly_admin_account="gone")
    assert eng.weekly_recipient(h.db.conn, h.acc, [h.acc, other]) == "full"   # default: first mailbox


def test_send_weekly_report_now_preview_and_real(eng, monkeypatch, tmp_path):
    h = _weekly_harness(eng, monkeypatch, tmp_path)
    res = eng.send_weekly_report("acct", preview=True, client=h.client, actor="admin")
    assert res["ok"] and res["code"] == "sent" and res["full"] is True and res["week"] == "2026-W43"
    assert "-preview-" in res["message_id"]
    assert not eng.receipt_sent(h.db.conn, "acct", "2026-W43", kind="weekly")
    raw = h.client.folders["INBOX"].msgs[h.client.uids("INBOX")[-1]].raw
    subject = email.message_from_bytes(raw, policy=email.policy.default)["Subject"]
    assert subject == "[Prøve] Spamfilter: ugerapport for uge 43"
    res = eng.send_weekly_report("acct", preview=False, client=h.client, week="2026-W42")
    assert res["ok"] and res["week"] == "2026-W42"
    assert eng.receipt_sent(h.db.conn, "acct", "2026-W42", kind="weekly")
    assert eng.send_weekly_report("acct", week="bad", client=h.client)["code"] == "invalid"
    assert eng.send_weekly_report("nobody", client=h.client)["code"] == "no_account"


def test_weekly_append_failure_unregisters(eng, monkeypatch, tmp_path):
    h = _weekly_harness(eng, monkeypatch, tmp_path)
    _kv(h, weekly_enabled="1")

    def boom(*a, **k):
        raise eng.IMAPClientError("APPEND failed")

    monkeypatch.setattr(h.client, "append", boom)
    assert eng.maybe_send_weekly(h.client, h.db, LOG, h.acc, h.acc.folder_map) is False
    assert not eng.receipt_sent(h.db.conn, "acct", "2026-W43", kind="weekly")
    assert h.events("weekly_report_failed")


def test_weekly_runs_from_the_account_loop(eng, monkeypatch, tmp_path):
    h = _weekly_harness(eng, monkeypatch, tmp_path)
    _kv(h, weekly_enabled="1")
    h.loop()
    assert eng.receipt_sent(h.db.conn, "acct", "2026-W43", kind="weekly")


# ----- real engine + trainer/services (B6) -----------------------------------------


def _trainer_env(eng, monkeypatch, tmp_path):
    import services
    import trainer

    _write_config(eng, BASE_YML.format(extra="").replace("name: bynet", "name: acct")
                  .replace("ole@bynet.example", "user@example-a.dk"))
    h = Harness(eng, monkeypatch, mode="move")
    monkeypatch.setattr(eng, "read_secret", lambda acc: "pw")
    monkeypatch.setattr(eng, "connect", lambda acc, password=None, **kw: h.client)
    monkeypatch.setattr(trainer, "MAX_PER_SECOND", 1e9)
    return h, trainer, services


def test_learn_list_flips_a_ham_learned_inbox_mail_on_the_real_engine(eng, monkeypatch, tmp_path):
    h, trainer, services = _trainer_env(eng, monkeypatch, tmp_path)
    h.client.add("INBOX", make_message("phish@x"))
    assert eng.learn_message(h.db, h.acc, make_message("phish@x"), "ham", "phish@x",
                             reason="bootstrap job=22") == "learned"
    h.advance(eng.FLIP_FLOP_COOLDOWN_S + 1)
    cand = services.bayes_repair_candidates(scope="all", engine=eng)
    assert cand["counts"]["learned_ham"] == 1
    res = services.queue_learn_list([("acct", "phish@x")], "owner", engine=eng)
    writes = list(h.client.writes)
    assert trainer.run_learn_list_job(res["job_id"], engine=eng) == "done"
    [item] = services.learn_list_items(res["job_id"], engine=eng)
    assert item["status"] == "learned" and item["previous"] == "ham" and item["folder"] == "INBOX"
    assert h.db.conn.execute("SELECT kind FROM learn_ledger WHERE message_id='phish@x'").fetchone()[0] == "spam"
    assert [c["url"].rsplit("/", 1)[1] for c in h.rspamd.learn_calls] == ["learnham", "learnspam"]
    assert h.client.writes == writes                    # EXAMINE + PEEK only


def test_ham_job_guard_on_the_real_engine(eng, monkeypatch, tmp_path):
    h, trainer, services = _trainer_env(eng, monkeypatch, tmp_path)
    h.rspamd.scores["lure@x"] = 1.0
    h.rspamd.symbols["lure@x"] = {**_sym("TH_FROM_ABUSED_TLD", 5.0), **_sym("BAYES_HAM", -4.0)}
    h.rspamd.scores["fine@x"] = -1.0
    h.client.add("INBOX", make_message("lure@x"))
    h.client.add("INBOX", make_message("fine@x"))
    jid = services.queue_train_job("acct", "INBOX", "ham", 10, engine=eng)
    assert trainer.run_job(jid, engine=eng) == "done"
    assert [c["url"].rsplit("/", 1)[1] for c in h.rspamd.learn_calls] == ["learnham"]
    assert h.events("ham_guard")[0][1] == "lure@x" and "TH_FROM_ABUSED_TLD" in h.events("ham_guard")[0][2]
    assert h.stat("ham_guarded") == 1


# ----- B30: first junk poll on a freshly booted host ----------------------------------


def test_first_junk_poll_runs_even_when_monotonic_is_small(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    monkeypatch.setattr(eng.time, "monotonic", lambda: 5.0)   # host up for 5 s
    h.state.last_junk_poll = 0.0
    polls = []
    monkeypatch.setattr(eng, "poll_junk", lambda *a, **k: polls.append(1))
    assert eng._next_wake_in(h.db, h.acc, h.state) <= eng.MIN_LOOP_WAIT_S   # due at once
    h.loop()
    assert polls == [1] and h.state.last_junk_poll == 5.0
    h.loop()
    assert polls == [1]                                        # then every junk_poll_interval


# ----- 2.2 review fixes ----------------------------------------------------------


def test_phished_excluded_does_not_block_the_own_platform_offset(eng, monkeypatch):
    # rspamd's phishing module adds PHISHED_EXCLUDED (0) for every link to a
    # host on phishing_feed_exclusion.inc (the owner's own shops) - no verdict.
    h = Harness(eng, monkeypatch, mode="move", threshold=10.0)
    h.rspamd.scores["inv@x"] = 11.25
    h.rspamd.symbols["inv@x"] = {**_sym("RSPAMD_URIBL", 4.5, URIBL_OPTS),
                                 **_sym("PHISHED_EXCLUDED", 0.0, ["www.vexar.example"])}
    h.deliver("inv@x", sender="support@vexar.example")
    h.scan()
    assert _syms(h, "inv@x")["TH_OWN_PLATFORM_URIBL"]["s"] == -4.5
    assert h.row("inv@x")["our_score"] == pytest.approx(6.75) and h.row("inv@x")["our_action"] == "none"
    assert "udlignet" in h.events("own_domain_uribl")[0][2]
    assert eng.url_reputation_hits(["PHISHED_EXCLUDED", "PHISHED_GENERIC_SERVICE"]) == []
    assert eng.url_reputation_hits(["PHISHED_EXCLUDED", "PHISHED_PHISHTANK"]) == ["PHISHED_PHISHTANK"]


def test_phished_excluded_is_not_a_ham_guard_reason(eng):
    g = eng.ham_guard_reason
    syms = [{"n": "PHISHED_EXCLUDED", "s": 0.0}, {"n": "R_DKIM_ALLOW", "s": -0.2}]
    assert g(None, "a", symbols=syms, final=-2.0, rspamd_score=-2.0) is None
    assert g(None, "a", symbols=[{"n": "PHISHED_GENERIC_SERVICE", "s": 0.0}], final=-2, rspamd_score=-2) is None
    assert g(None, "a", symbols=syms + [{"n": "PHISHED_OPENPHISH", "s": 7.0}], final=-2,
             rspamd_score=-2) == ("phishing", "PHISHED_OPENPHISH")


def test_aged_settings_disable_the_spf_dmarc_whitelist_rules(eng):
    # With the DMARC check off, the stock whitelist module would turn
    # WHITELIST_DMARC (-7) into BLACKLIST_DMARC (+6) for paypal/amazon & co.
    for sym in ("WHITELIST_DMARC", "WHITELIST_SPF_DKIM", "WHITELIST_SPF"):
        assert sym in eng.AGED_DISABLED_SYMBOLS
        assert sym in json.loads(eng.AGED_SETTINGS_HEADER)["symbols_disabled"]
    assert "WHITELIST_DKIM" not in eng.AGED_DISABLED_SYMBOLS   # DKIM stays checked
    assert "R_DKIM_REJECT" not in eng.AGED_DISABLED_SYMBOLS


def _aged(h, hours=24):
    return dt.datetime.fromtimestamp(h.t - hours * HOUR, dt.timezone.utc)


def test_provider_spf_fail_distrusts_allow_rule_in_aged_scan(tmp_path, monkeypatch):
    eng = setup_engine(tmp_path, monkeypatch, mailctx=_auth_stub(
        [{"n": "TH_PROVIDER_AUTH_SPOOF", "s": 0.0, "o": ["node4.spamfilter.io", "spf=softfail"]}]))
    h = Harness(eng, monkeypatch, mode="move", threshold=8.0)
    eng.add_sender_rule(h.db.conn, "*", "@partner.example", "allow")
    h.rspamd.scores["spoof@x"] = 8.5
    h.deliver("spoof@x", sender="chef@partner.example", internaldate=_aged(h))
    h.scan()
    r = h.row("spoof@x")
    assert r["rule_hit"] is None and r["our_action"] == "pending_move"
    assert r["our_score"] == pytest.approx(8.5)       # distrust only, no points
    assert "TH_PROVIDER_AUTH_SPOOF" in _syms(h, "spoof@x")


def test_aged_scan_without_any_provider_verdict_or_dkim_does_not_trust_allow_rule(tmp_path, monkeypatch):
    # Gigahost writes no Authentication-Results: an aged scan has nothing
    # that proves the From (rspamd's SPF is off) -> decide by score.
    eng = setup_engine(tmp_path, monkeypatch, mailctx=_auth_stub([]))
    h = Harness(eng, monkeypatch, mode="move", threshold=8.0)
    eng.add_sender_rule(h.db.conn, "*", "@partner.example", "allow")
    h.rspamd.scores["old@x"] = 9.0
    h.deliver("old@x", sender="chef@partner.example", internaldate=_aged(h))
    h.scan()
    r = h.row("old@x")
    assert r["rule_hit"] is None and r["our_action"] == "pending_move"
    assert "TH_AGED_UNVERIFIED" in _syms(h, "old@x")
    # Fresh delivery of the same kind: the allow rule works as before.
    h.rspamd.scores["new@x"] = 9.0
    h.deliver("new@x", sender="chef@partner.example")
    h.scan()
    assert h.row("new@x")["our_action"] == "allowlisted" and "TH_AGED_UNVERIFIED" not in _syms(h, "new@x")


def test_aged_allow_rule_is_trusted_with_aligned_dkim_or_a_provider_verdict(tmp_path, monkeypatch):
    stub = _auth_stub([])
    eng = setup_engine(tmp_path, monkeypatch, mailctx=stub)
    h = Harness(eng, monkeypatch, mode="move", threshold=8.0)
    eng.add_sender_rule(h.db.conn, "*", "@partner.example", "allow")
    h.rspamd.scores["dkim@x"] = 9.0
    h.rspamd.symbols["dkim@x"] = _sym("R_DKIM_ALLOW", -0.2, ["mail.partner.example:s=k1"])
    h.deliver("dkim@x", sender="chef@partner.example", internaldate=_aged(h))
    h.scan()
    assert h.row("dkim@x")["our_action"] == "allowlisted"
    # The provider recorded SPF/DMARC at delivery (and it did not fail).
    stub.provider_auth_known = lambda ctx: True
    h.rspamd.scores["spf@x"] = 9.0
    h.deliver("spf@x", sender="chef@partner.example", internaldate=_aged(h))
    h.scan()
    assert h.row("spf@x")["our_action"] == "allowlisted"
    # A provider PASS is enough on its own.
    stub.provider_auth_known = lambda ctx: False
    stub.provider_auth_symbols = lambda ctx: [{"n": "TH_PROVIDER_AUTH_PASS", "s": -1.0, "o": ["x"]}]
    h.rspamd.scores["pass@x"] = 9.5
    h.deliver("pass@x", sender="chef@partner.example", internaldate=_aged(h))
    h.scan()
    assert h.row("pass@x")["our_action"] == "allowlisted"


def test_aged_unverified_never_affects_a_verified_force_rule(tmp_path, monkeypatch):
    eng = setup_engine(tmp_path, monkeypatch, mailctx=_auth_stub([]))
    h = Harness(eng, monkeypatch, mode="move", threshold=8.0)
    eng.add_sender_rule(h.db.conn, "*", "@shop.example", "allow", force=True)
    h.rspamd.scores["shop@x"] = 14.0
    h.rspamd.symbols["shop@x"] = _sym("R_DKIM_ALLOW", -0.2, ["shop.example:s=k1"])
    h.deliver("shop@x", sender="ordre@shop.example", internaldate=_aged(h))
    h.scan()
    assert h.row("shop@x")["our_action"] == "allowlisted"


def test_aged_unverified_helper(eng):
    auth = {"dkim": ["other.example"], "host": None}
    assert eng.aged_unverified({}, auth, "a@partner.example", set()) is True
    assert eng.aged_unverified({}, {"dkim": ["partner.example"], "host": None}, "a@mail.partner.example",
                               set()) is False
    assert eng.aged_unverified({}, auth, "a@partner.example", {"TH_PROVIDER_AUTH_PASS"}) is False
    assert eng.aged_unverified({}, auth, None, set()) is True
