"""ENGINE 2.0.3: 'Altid igennem' (force) allow rules.

A force allow rule always keeps the mail in the inbox - regardless of the
spoof symbols that make a normal allow rule step aside, and regardless of
the score. Normal allow rules keep the spoof guard; block rules are
unchanged."""

from __future__ import annotations

import datetime as dt
import logging
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import make_message, setup_engine, stub_mailctx  # noqa: E402
from test_engine_scan import Harness  # noqa: E402

LOG = logging.getLogger("test")
SPOOF_SYMBOLS = ["DMARC_POLICY_REJECT", "DMARC_POLICY_QUARANTINE", "R_SPF_FAIL", "R_SPF_SOFTFAIL",
                 "TH_PROVIDER_SPAM"]


# 2.1 (E8): 'Altid igennem' needs proof the mail comes from the rule's
# domain. These tests model mail from the shop platform's own sending host
# (path verification); the spoof-guard tests below use other evidence.
SHOP_HOST = "mail-sender-3.vexar.example"


@pytest.fixture
def eng(tmp_path, monkeypatch):
    return setup_engine(tmp_path, monkeypatch, mailctx=stub_mailctx(origin_host=SHOP_HOST))


def _sym(h, msgid, *names):
    h.rspamd.symbols[msgid] = {n: {"name": n, "score": 1.0} for n in names}


# ----- decision -------------------------------------------------------------------


@pytest.mark.parametrize("sym", SPOOF_SYMBOLS)
def test_force_allow_beats_spoof_symbols_and_high_score(eng, monkeypatch, sym):
    h = Harness(eng, monkeypatch, mode="move")
    fid = eng.add_sender_rule(h.db.conn, "*", "@vexar.example", "allow", "Webshop", "admin", force=True)
    eng.add_sender_rule(h.db.conn, "*", "@normal.dk", "allow", None, "admin")
    h.deliver("f@x", score=30, sender="support@vexar.example")
    h.deliver("n@x", score=30, sender="bob@normal.dk")
    _sym(h, "f@x", sym)
    _sym(h, "n@x", sym)
    h.scan()
    f, n = h.row("f@x"), h.row("n@x")
    assert f["our_action"] == "allowlisted" and f["rule_hit"] == f"allow:{fid}"
    assert n["our_action"] == "pending_move" and n["rule_hit"] is None  # normal allow still guarded
    assert h.db.conn.execute("SELECT hits FROM sender_rules WHERE id=?", (fid,)).fetchone()[0] == 1
    assert any("force allow rule" in (e[2] or "") and sym in e[2] for e in h.events("scan") if e[1] == "f@x")
    h.advance(3600)
    h.moves()
    assert h.client.msgids("INBOX") == ["f@x"] and h.client.msgids("Junk") == ["n@x"]


def test_force_allow_with_every_spoof_symbol_at_once(eng, monkeypatch):
    """The real vexar.example case: forwarded with SRS (SPF softfail), released
    from the provider's quarantine with an altered body (DKIM fail ->
    DMARC reject) and the provider's own spam flag."""
    monkeypatch.setattr(eng, "_mailctx", lambda: stub_mailctx(provider_flag=True, provider_score=8.0,
                                                               origin_host=SHOP_HOST))
    h = Harness(eng, monkeypatch, mode="move")
    eng.add_sender_rule(h.db.conn, "*", "@vexar.example", "allow", None, "admin", force=True)
    h.deliver("order@x", score=30, sender="mailbot@vexar.example")
    _sym(h, "order@x", "DMARC_POLICY_REJECT", "R_SPF_SOFTFAIL", "R_DKIM_REJECT")
    h.scan()
    r = h.row("order@x")
    assert r["our_action"] == "allowlisted" and "TH_PROVIDER_SPAM" in r["symbols"]
    assert h.db.count_pending_moves() == 0 and h.stat("allowlisted") == 1 and h.stat("spam_detected") == 0
    h.advance(3600)
    h.loop()
    assert h.client.msgids("INBOX") == ["order@x"] and h.client.msgids("Junk") == []


def test_force_allow_is_allowlisted_even_with_a_low_score(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    fid = eng.add_sender_rule(h.db.conn, "*", "support@vexar.example", "allow", None, None, force=True)
    h.deliver("low@x", score=-2, sender="support@vexar.example")
    h.scan()
    r = h.row("low@x")
    assert r["our_action"] == "allowlisted" and r["rule_hit"] == f"allow:{fid}"


def test_force_allow_never_flags_in_flag_mode(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="flag")
    eng.add_sender_rule(h.db.conn, "acct", "@vexar.example", "allow", force=True)
    uid = h.deliver("f@x", score=30, sender="support@vexar.example")
    _sym(h, "f@x", "DMARC_POLICY_REJECT")
    h.scan()
    assert h.row("f@x")["our_action"] == "allowlisted"
    assert h.client.flags_of("INBOX", uid) == set() and h.client.writes == []


def test_force_allow_beats_an_earlier_spam_verdict_on_the_message_id(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    eng.add_sender_rule(h.db.conn, "*", "@vexar.example", "allow", force=True)
    with h.db.tx():
        h.db.upsert_message("dup@x", "INBOX", "support@vexar.example", "Ordre")
        h.db.update_message("dup@x", user_verdict="spam")
    h.deliver("dup@x", score=30, sender="support@vexar.example")
    _sym(h, "dup@x", "R_SPF_FAIL")
    h.scan()
    assert h.row("dup@x")["user_verdict"] == "spam"  # original record is preserved
    assert h.db.conn.execute("SELECT COUNT(*) FROM messages WHERE our_action='allowlisted'").fetchone()[0] == 1
    assert h.db.count_pending_moves() == 0


def test_block_rules_unchanged_and_more_specific_block_still_wins(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    eng.add_sender_rule(h.db.conn, "*", "@vexar.example", "allow", force=True)
    bid = eng.add_sender_rule(h.db.conn, "*", "spam@vexar.example", "block")
    h.deliver("b@x", score=-5, sender="spam@vexar.example")
    h.deliver("ok@x", score=30, sender="support@vexar.example")
    h.scan()
    assert h.row("b@x")["our_action"] == "pending_move" and h.row("b@x")["rule_hit"] == f"block:{bid}"
    assert h.row("ok@x")["our_action"] == "allowlisted"


# ----- other automatic paths -------------------------------------------------------


def test_force_rule_added_during_grace_cancels_the_move(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("late@x", score=30, sender="support@vexar.example")
    h.deliver("spam@x", score=30, sender="win@lotto.example")
    h.scan()
    assert h.db.count_pending_moves() == 2
    fid = eng.add_sender_rule(h.db.conn, "*", "@vexar.example", "allow", force=True)
    h.advance(3600)
    h.moves()
    assert h.client.msgids("INBOX") == ["late@x"] and h.client.msgids("Junk") == ["spam@x"]
    r = h.row("late@x")
    assert r["our_action"] == "allowlisted" and r["rule_hit"] == f"allow:{fid}"
    assert [e[1] for e in h.events("move_skipped_rule")] == ["late@x"]
    assert h.db.count_pending_moves() == 0


def test_normal_allow_rule_added_during_grace_cancels(eng, monkeypatch):
    """A current ordinary allow is re-evaluated with the original safety evidence."""
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("s@x", score=30, sender="support@vexar.example")
    h.scan()
    eng.add_sender_rule(h.db.conn, "*", "@vexar.example", "allow")
    h.advance(3600)
    h.moves()
    assert h.client.msgids("INBOX") == ["s@x"]
    assert h.db.count_pending_moves() == 0


SRS_ENVELOPE = "SRS0=N7BF=IH=gazeta.ie=user@mail.vexar.example"


def test_force_rule_never_matches_on_the_envelope_sender_alone(eng, monkeypatch):
    """mail.vexar.example forwards everything sent to the shop's mailbox (spam
    included) with an SRS envelope @mail.vexar.example. Without a From address
    the envelope is all there is - a force rule must then act as a normal
    allow rule (spoof guard applies), at scan time and at move time."""
    base = stub_mailctx(provider_flag=True, origin_host=SHOP_HOST)

    def scan_context(raw, acc):
        ctx = base.scan_context(raw, acc)
        ctx["envelope_from"] = SRS_ENVELOPE
        return ctx

    monkeypatch.setattr(eng, "_mailctx", lambda: SimpleNamespace(scan_context=scan_context,
                                                                 provider_bonus=base.provider_bonus))
    h = Harness(eng, monkeypatch, mode="move")
    eng.add_sender_rule(h.db.conn, "*", "@vexar.example", "allow", force=True)
    h.deliver("nofrom@x", score=30, sender="")
    h.deliver("shop@x", score=30, sender="support@vexar.example")
    h.scan()
    nf, shop = h.row("nofrom@x"), h.row("shop@x")
    assert nf["envelope_from"] == SRS_ENVELOPE and not nf["sender"]
    assert nf["our_action"] == "pending_move" and nf["rule_hit"] is None  # TH_PROVIDER_SPAM: normal allow steps aside
    assert shop["our_action"] == "allowlisted"
    h.advance(3600)
    h.moves()
    assert h.client.msgids("INBOX") == ["shop@x"] and h.client.msgids("Junk") == ["nofrom@x"]
    assert eng.force_allow_rule(h.db.conn, h.acc.name, SRS_ENVELOPE)["id"]  # helper itself is address-agnostic


def test_retention_never_trashes_force_allowed_mail(eng, monkeypatch):
    monkeypatch.setattr(eng, "AUTOMATIC_RETENTION_ENABLED", True)
    h = Harness(eng, monkeypatch, mode="move", junk_retention_days=3)
    old = dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)
    h.client.add("Junk", make_message("shop@x", sender="support@vexar.example"), internaldate=old)
    h.client.add("Junk", make_message("junk@x", sender="win@lotto.example"), internaldate=old)
    for mid, sender in (("shop@x", "support@vexar.example"), ("junk@x", "win@lotto.example")):
        with h.db.tx():
            h.db.upsert_message(mid, "Junk", sender, "x")
    eng.add_sender_rule(h.db.conn, "*", "@vexar.example", "allow", force=True)
    eng._housekeeping(h.client, h.db, LOG, h.acc, h.state)
    assert h.client.msgids("Junk") == ["shop@x"] and h.client.msgids("Trash") == ["junk@x"]


# ----- rule helpers ----------------------------------------------------------------


def test_add_sender_rule_force_semantics(eng):
    eng.init_db()
    conn = sqlite3.connect(eng.DB_PATH)
    conn.row_factory = sqlite3.Row
    force = lambda rid: conn.execute("SELECT force FROM sender_rules WHERE id=?", (rid,)).fetchone()[0]  # noqa: E731
    # Old positional signature still works and makes a normal rule.
    rid = eng.add_sender_rule(conn, "*", "@vexar.example", "allow", "note", "admin")
    assert force(rid) == 0
    assert eng.set_rule_force(conn, rid, True) is True and force(rid) == 1
    # Re-adding the allow rule (e.g. a one-click "Tillad afsender") never downgrades it.
    assert eng.add_sender_rule(conn, "*", "@vexar.example", "allow", None, "sofie") == rid and force(rid) == 1
    m = eng.match_sender_rule(conn, "acct", "support@vexar.example")
    assert m["force"] == 1 and eng.rule_is_force(m)
    assert eng.force_allow_rule(conn, "acct", "Support@Vexar.Example")["id"] == rid
    # Switching to block clears it; block rules can never be force.
    eng.add_sender_rule(conn, "*", "@vexar.example", "block")
    assert force(rid) == 0 and eng.set_rule_force(conn, rid, True) is False and force(rid) == 0
    assert not eng.rule_is_force(eng.match_sender_rule(conn, "acct", "support@vexar.example"))
    bid = eng.add_sender_rule(conn, "*", "@spam.example", "block", force=True)
    assert force(bid) == 0
    # Back to allow with force (the UI's Fortryd), and off again.
    eng.add_sender_rule(conn, "*", "@vexar.example", "allow", force=True)
    assert force(rid) == 1
    assert eng.set_rule_force(conn, rid, False) is True and force(rid) == 0
    assert eng.set_rule_force(conn, 99999, True) is False
    assert eng.force_allow_rule(conn, "acct", None) is None
    assert eng.rule_is_force(None) is False
