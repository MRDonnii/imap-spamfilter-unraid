"""ENGINE 2.1: 'Altid igennem' tied to the real sender (E8), protected
recipient addresses (E9), the modest newsletter credit (E10), the daily
receipt (E12) and the new config keys (E7 defaults)."""

from __future__ import annotations

import datetime as dt
import email
import email.policy
import logging
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import make_message, setup_engine, stub_mailctx  # noqa: E402
from test_engine_scan import Harness  # noqa: E402

LOG = logging.getLogger("test")
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "headers"


@pytest.fixture
def eng(tmp_path, monkeypatch):
    return setup_engine(tmp_path, monkeypatch)


def _syms(h, msgid, **named):
    h.rspamd.symbols[msgid] = {n: {"name": n, "score": s, "options": o} for n, (s, o) in named.items()}


def _sym_names(row):
    import json

    return {s["n"] for s in json.loads(row["symbols"])}


# ----- E8 'Altid igennem' needs proof ---------------------------------------------


def test_force_verified_by_dkim(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    fid = eng.add_sender_rule(h.db.conn, "*", "@vexar.example", "allow", force=True)
    h.deliver("d@x", score=30, sender="support@vexar.example")
    _syms(h, "d@x", R_DKIM_ALLOW=(-0.2, ["vexar.example:s=default"]), DMARC_POLICY_REJECT=(2.0, []))
    h.scan()
    r = h.row("d@x")
    assert r["our_action"] == "allowlisted" and r["rule_hit"] == f"allow:{fid}"
    assert '"dkim":["vexar.example"]' in r["sender_auth"]
    assert any("dkim:vexar.example" in (e[2] or "") for e in h.events("scan"))


def test_force_unverified_is_a_normal_allow_rule(eng, monkeypatch):
    """A forged From of the platform (spam through the same forwarder, no
    DKIM, sent from an unrelated host) gets no free pass."""
    monkeypatch.setattr(eng, "_mailctx", lambda: stub_mailctx(origin_host="mail.gadgetoutlet.example"))
    h = Harness(eng, monkeypatch, mode="move")
    fid = eng.add_sender_rule(h.db.conn, "*", "@vexar.example", "allow", force=True)
    h.deliver("spoof@x", score=30, sender="support@vexar.example")
    _syms(h, "spoof@x", R_DKIM_ALLOW=(-0.2, ["evil.example:s=x"]), R_SPF_FAIL=(1.0, []))
    h.deliver("plain@x", score=30, sender="mailbot@vexar.example")    # no distrust symbol
    h.scan()
    spoof, plain = h.row("spoof@x"), h.row("plain@x")
    assert spoof["our_action"] == "pending_move" and spoof["rule_hit"] is None
    assert "TH_FORCE_UNVERIFIED" in _sym_names(spoof)
    assert [e[1] for e in h.events("force_unverified")] == ["spoof@x", "plain@x"]
    # Without a spoof symbol it is still an (ordinary) allow rule.
    assert plain["our_action"] == "allowlisted" and plain["rule_hit"] == f"allow:{fid}"
    assert any("force_unverified; allow rule" in (e[2] or "") for e in h.events("scan"))
    h.advance(3600)
    h.moves()
    assert h.client.msgids("Junk") == ["spoof@x"]


@pytest.mark.parametrize("host,ok", [("mail-sender-3.vexar.example", True), ("vexar.example", True),
                                     ("evilvexar.example", False), ("vexar.example.evil.example", False),
                                     (None, False)])
def test_force_verification_domain_matching(eng, host, ok):
    rule = {"pattern": "support@vexar.example"}
    got = eng.force_verification(rule, {"dkim": [], "host": host})
    assert (got is not None) is ok
    assert eng.force_verification(rule, '{"dkim":["mail.vexar.example"]}') == "dkim:mail.vexar.example"
    assert eng.force_verification(rule, None) is None and eng.force_verification(None, {}) is None


def test_force_recheck_at_move_time_needs_proof_too(eng, monkeypatch):
    monkeypatch.setattr(eng, "_mailctx", lambda: stub_mailctx(origin_host="bad.example"))
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("late@x", score=30, sender="support@vexar.example")
    h.scan()
    eng.add_sender_rule(h.db.conn, "*", "@vexar.example", "allow", force=True)
    h.advance(3600)
    h.moves()
    assert h.client.msgids("Junk") == ["late@x"]


def _real_mailctx_harness(eng, monkeypatch, **over):
    import mailctx

    monkeypatch.setattr(eng, "_mailctx", lambda: mailctx)
    return Harness(eng, monkeypatch, mode="move", **over)


def _deliver_fixture(h, name, *, score, symbols=None):
    raw = (FIXTURES / name).read_bytes()
    msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    msgid = msg["Message-ID"].strip("<> ")
    h.rspamd.scores[msgid] = score
    if symbols:
        h.rspamd.symbols[msgid] = symbols
    h.client.add("INBOX", raw, internaldate=dt.datetime.fromtimestamp(h.t, dt.timezone.utc))
    return msgid


def test_real_platform_mail_passes_after_quarantine_release_with_broken_dkim(eng, monkeypatch):
    """The real chain: Scannet <- SpamExperts (quarantine release) <- the
    owner's MX <- mail-sender-N.vexar.example; DKIM broken, DMARC reject,
    SpamExperts class spam - path verification keeps it in the inbox."""
    h = _real_mailctx_harness(eng, monkeypatch, user="user@example-b.dk")
    eng.add_sender_rule(h.db.conn, "*", "@vexar.example", "allow", force=True)
    mid = _deliver_fixture(h, "scannet_spamexperts_vexar_shop_release.eml", score=25.0, symbols={
        "DMARC_POLICY_REJECT": {"name": "DMARC_POLICY_REJECT", "score": 2.0},
        "R_DKIM_REJECT": {"name": "R_DKIM_REJECT", "score": 1.0}})
    h.scan()
    r = h.row(mid)
    assert r["our_action"] == "allowlisted" and r["envelope_from"] == "support@vexar.example"
    assert r["sender_ip"] == "203.0.113.35"
    assert '"host":"mail-sender-5.vexar.example"' in r["sender_auth"]
    sent = h.rspamd.scan_calls[-1]["headers"]
    assert sent["IP"] == "203.0.113.35" and sent["From"] == "support@vexar.example"


def test_real_spam_with_forged_platform_from_is_moved(eng, monkeypatch):
    h = _real_mailctx_harness(eng, monkeypatch)
    eng.add_sender_rule(h.db.conn, "*", "@vexar.example", "allow", force=True)
    mid = _deliver_fixture(h, "gigahost_vexar_shop_spam.eml", score=25.0)
    h.scan()
    r = h.row(mid)
    assert r["our_action"] == "pending_move" and "TH_FORCE_UNVERIFIED" in _sym_names(r)
    assert r["sender_ip"] == "62.173.146.164"            # the real sender, not the forwarder
    assert r["envelope_from"] == "ephiydk@lastchance.example"


def test_real_platform_order_via_gigahost_forwarder(eng, monkeypatch):
    h = _real_mailctx_harness(eng, monkeypatch)
    eng.add_sender_rule(h.db.conn, "*", "@vexar.example", "allow", force=True)
    mid = _deliver_fixture(h, "gigahost_vexar_shop_order.eml", score=12.0)
    h.scan()
    assert h.row(mid)["our_action"] == "allowlisted"


# ----- E9 protected recipients ------------------------------------------------------


def test_protected_recipient_uses_the_higher_threshold(eng, monkeypatch):
    monkeypatch.setattr(eng, "_mailctx", lambda: stub_mailctx(recipients=["user@example-a.dk",
                                                                          "info@shop-a.example"]))
    h = Harness(eng, monkeypatch, mode="move", protected_recipients=["info@shop-a.example"],
                protected_threshold=18.0)
    h.deliver("low@x", score=15)
    h.deliver("high@x", score=20)
    h.scan()
    low, high = h.row("low@x"), h.row("high@x")
    assert low["our_action"] == "none" and "TH_PROTECTED_RCPT" in _sym_names(low)
    assert high["our_action"] == "pending_move"
    pm = h.db.conn.execute("SELECT threshold, due_at FROM pending_move").fetchone()
    assert pm["threshold"] == 18.0 and pm["due_at"] == int(h.t) + 60   # 20 < 18 + 5: normal grace


def test_unprotected_mail_keeps_the_account_threshold(eng, monkeypatch):
    monkeypatch.setattr(eng, "_mailctx", lambda: stub_mailctx(recipients=["user@example-a.dk"]))
    h = Harness(eng, monkeypatch, mode="move", protected_recipients=["info@shop-a.example"])
    h.deliver("m@x", score=15)
    h.scan()
    assert h.row("m@x")["our_action"] == "pending_move" and "TH_PROTECTED_RCPT" not in _sym_names(h.row("m@x"))


def test_effective_threshold_helper(eng):
    from types import SimpleNamespace

    acc = SimpleNamespace(threshold=10.0, protected_threshold=18.0, protected_recipients=["a@b.dk"])
    assert eng.effective_threshold(acc, {"recipients": ["A@B.DK"]}) == (18.0, "a@b.dk")
    assert eng.effective_threshold(acc, {"recipients": ["x@b.dk"]}) == (10.0, None)
    acc.protected_threshold = 5.0   # never lowers the bar
    assert eng.effective_threshold(acc, {"recipients": ["a@b.dk"]})[0] == 10.0


# ----- E10 newsletters ---------------------------------------------------------------

NEWS = "List-Unsubscribe: <https://shop.example/u/1>"


def _news_harness(eng, monkeypatch, host="o1.ptr.sendgrid.net"):
    monkeypatch.setattr(eng, "_mailctx", lambda: stub_mailctx(origin_host=host, real_helpers=True))
    return Harness(eng, monkeypatch, mode="move")


def test_newsletter_credit_for_aligned_esp_mail(eng, monkeypatch):
    h = _news_harness(eng, monkeypatch)
    h.deliver("n@x", score=8.5, sender="news@shop.example", extra_headers=NEWS)
    _syms(h, "n@x", R_DKIM_ALLOW=(-0.2, ["shop.example:s=s1"]), HIDDEN_TEXT=(2.0, ["300"]))
    h.scan()
    r = h.row("n@x")
    assert r["our_action"] == "none" and r["our_score"] == 7.0
    assert "TH_NEWSLETTER" in _sym_names(r)


@pytest.mark.parametrize("case", ["spammy", "no_unsub", "not_aligned", "no_esp", "provider_spam"])
def test_newsletter_credit_needs_everything(eng, monkeypatch, case):
    host = "mail.shop.example" if case == "no_esp" else "o1.ptr.sendgrid.net"
    h = _news_harness(eng, monkeypatch, host=host)
    if case == "provider_spam":
        monkeypatch.setattr(eng, "_mailctx", lambda: stub_mailctx(origin_host=host, real_helpers=True,
                                                                   provider_flag=True))
    score = 11.0 if case == "spammy" else 8.5
    h.deliver("n@x", score=score, sender="news@shop.example",
              extra_headers="" if case == "no_unsub" else NEWS)
    dkim = "other.example:s=s1" if case == "not_aligned" else "shop.example:s=s1"
    _syms(h, "n@x", R_DKIM_ALLOW=(-0.2, [dkim]))
    h.scan()
    assert "TH_NEWSLETTER" not in _sym_names(h.row("n@x"))


def test_newsletter_credit_needs_dkim_not_just_a_dmarc_pass(eng, monkeypatch):
    h = _news_harness(eng, monkeypatch)
    h.deliver("n@x", score=8.5, sender="news@shop.example", extra_headers=NEWS)
    _syms(h, "n@x", DMARC_POLICY_ALLOW=(-0.5, ["shop.example", "none"]))
    h.scan()
    assert "TH_NEWSLETTER" not in _sym_names(h.row("n@x"))


def test_rspamd_hidden_text_is_capped_in_local_d():
    conf = (Path(__file__).resolve().parents[1] / "rspamd" / "local.d" / "groups.conf").read_text()
    assert 'group "html"' in conf and '"HIDDEN_TEXT"' in conf and "weight = 2.0;" in conf


# ----- E12 daily receipt ---------------------------------------------------------------


def _moved(h, msgid, score=30, sender="win@lotto.example"):
    h.deliver(msgid, score=score, sender=sender, subject="Du har vundet")
    h.scan()
    h.advance(10)
    h.moves()


def test_daily_receipt_is_appended_once_and_never_scanned(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", daily_report=True, report_hour=7)
    assert eng._local_dt(h.t).hour >= 7
    assert eng.maybe_send_receipt(h.client, h.db, LOG, h.acc, h.acc.folder_map) is False  # nothing moved
    _moved(h, "s@x")
    assert eng.maybe_send_receipt(h.client, h.db, LOG, h.acc, h.acc.folder_map) is True
    assert eng.maybe_send_receipt(h.client, h.db, LOG, h.acc, h.acc.folder_map) is False  # once a day
    assert eng.receipt_sent(h.db.conn, "acct")
    [uid] = h.client.uids("INBOX")
    raw = h.client.folders["INBOX"].msgs[uid].raw
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    day = eng.stats_day(h.t)
    assert msg["Message-ID"] == f"<report-acct-{day}@hjemmeserver.spamfilter>"
    assert msg["X-TH-Spamfilter"] == "report" and msg["From"] == "Spamfilter <noreply@hjemmeserver.invalid>"
    text = msg.get_body(("plain",)).get_content()
    html = msg.get_body(("html",)).get_content()
    assert "win@lotto.example" in text and "Du har vundet" in text and "score 30,0" in text
    assert "Træk den tilbage til Indbakke, så lærer filteret det" in text
    # BAYES_SPAM explained in Danish (ui_kit's text, else the built-in table).
    assert "Ligner spam, som filteret har lært (Bayes)" in text or "Ligner tidligere spam" in text
    assert "<table" in html and "Du har vundet" in html
    # The scanner skips it and the bookmark moves past it.
    n_scans = len(h.rspamd.scan_calls)
    h.scan()
    assert len(h.rspamd.scan_calls) == n_scans and h.bookmark() == uid
    assert h.row(f"report-acct-{day}@hjemmeserver.spamfilter") is None


def test_forged_receipt_lookalike_is_scanned(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.client.add("INBOX", make_message("report-acct-2026-10-20@hjemmeserver.spamfilter",
                                       extra_headers="X-TH-Spamfilter: report"),
                 internaldate=dt.datetime.fromtimestamp(h.t, dt.timezone.utc))
    h.scan()
    assert h.scanned_ids() == ["report-acct-2026-10-20@hjemmeserver.spamfilter"]


def test_no_receipt_before_report_hour_or_when_off(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", daily_report=True,
                report_hour=min(23, eng._local_dt(1_800_000_000).hour + 1))
    _moved(h, "s@x")
    assert eng.maybe_send_receipt(h.client, h.db, LOG, h.acc, h.acc.folder_map) is False
    h2 = Harness(eng, monkeypatch, mode="move", name="acct2")      # daily_report off
    _moved(h2, "t@x")
    assert eng.maybe_send_receipt(h2.client, h2.db, LOG, h2.acc, h2.acc.folder_map) is False
    nxt = eng._next_receipt_time(h.acc, h.t)
    assert 0 < nxt - h.t <= 3600


def test_send_receipt_preview_for_admin(eng, monkeypatch, tmp_path):
    h = Harness(eng, monkeypatch, mode="move")
    cfg = tmp_path / "accounts.yml"
    cfg.write_text(yaml.safe_dump({"accounts": [{"name": "acct", "user": "user@example-a.dk",
                                                 "imap_host": "imap.example.net", "password": "pw"}]}))
    res = eng.send_receipt("acct", preview=True, actor="admin", client=h.client, path=cfg)
    assert res["ok"] and res["code"] == "sent" and res["items"] == 0 and "-preview-" in res["message_id"]
    raw = h.client.folders["INBOX"].msgs[h.client.uids("INBOX")[0]].raw
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    assert msg["Subject"].startswith("[Prøve] Spamfilter:")
    assert "Ingen mails flyttet" in msg.get_body(("plain",)).get_content()
    assert not eng.receipt_sent(h.db.conn, "acct")             # a preview is not the daily one
    assert eng.receipt_sent(h.db.conn, "acct", kind="preview")
    h.scan()
    assert h.rspamd.scan_calls == []                           # never scanned either
    assert eng.send_receipt("nope", client=h.client, path=cfg)["code"] == "no_account"
    nothing = eng.send_receipt("acct", preview=False, client=h.client, path=cfg)
    assert nothing["ok"] and nothing["code"] == "nothing"


def test_receipt_append_failure_leaves_no_record(eng, monkeypatch, tmp_path):
    from fakes_engine import IMAPClientError

    h = Harness(eng, monkeypatch, mode="move")
    cfg = tmp_path / "accounts.yml"
    cfg.write_text(yaml.safe_dump({"accounts": [{"name": "acct", "user": "u@x.dk",
                                                 "imap_host": "h", "password": "pw"}]}))
    h.client.fail_on["append"] = IMAPClientError("NO quota")
    res = eng.send_receipt("acct", preview=True, client=h.client, path=cfg)
    assert res["ok"] is False and res["code"] == "imap_error"
    assert h.db.conn.execute("SELECT COUNT(*) FROM daily_receipts").fetchone()[0] == 0


# ----- config ------------------------------------------------------------------------


def test_new_config_keys_defaults_and_validation(eng, tmp_path):
    cfg = tmp_path / "accounts.yml"
    cfg.write_text(yaml.safe_dump({"accounts": [{"name": "a", "user": "a@x.dk", "imap_host": "h",
                                                 "password": "p"}]}))
    [acc] = eng.load_account_configs(cfg)
    assert acc.trusted_forwarders == ["mail.vexar.example", "203.0.113.109"]
    assert (acc.move_grace_seconds_high, acc.fast_move_margin) == (3, 5.0)
    assert (acc.circuit_max_moves_per_hour, acc.circuit_max_ratio, acc.circuit_min_moves) == (25, 0.4, 10)
    assert acc.autolearn is True and acc.daily_report is False and acc.report_hour == 7
    assert acc.protected_recipients == [] and acc.protected_threshold == 18.0
    cfg.write_text(yaml.safe_dump({"defaults": {"trusted_forwarders": ["*.relay.example", "10.1.2.0/24"]},
                                   "accounts": [{"name": "a", "user": "a@x.dk", "imap_host": "h", "password": "p",
                                                 "protected_recipients": ["Info@Shop-A.Example"],
                                                 "daily_report": "yes", "report_hour": 6}]}))
    [acc] = eng.load_account_configs(cfg)
    assert acc.trusted_forwarders == ["*.relay.example", "10.1.2.0/24"]
    assert acc.protected_recipients == ["info@shop-a.example"] and acc.daily_report is True
    for bad in ({"trusted_forwarders": ["not a host"]}, {"trusted_forwarders": ["0.0.0.0/0"]},
                {"trusted_forwarders": ["203.0.0.0/16"]}, {"trusted_forwarders": ["2001:db8::/32"]},
                {"trusted_forwarders": ["*.com"]}, {"protected_recipients": ["nope"]},
                {"report_hour": 24}, {"protected_threshold": 1}, {"autolearn_daily_cap": -1},
                {"autolearn": "maybe"}):
        cfg.write_text(yaml.safe_dump({"accounts": [{"name": "a", "user": "a@x.dk", "imap_host": "h",
                                                     "password": "p", **bad}]}))
        with pytest.raises(ValueError):
            eng.load_account_configs(cfg)
