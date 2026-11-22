"""Owner's wish (2026-10-21): moving a mail OUT of the spam folder in the
mail app allows that exact sender for the account; moving it IN teaches
spam. WebUI releases keep their explicit 'Tillad afsender' button."""

from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import setup_engine  # noqa: E402
from test_engine_scan import Harness  # noqa: E402


@pytest.fixture
def eng(tmp_path, monkeypatch):
    return setup_engine(tmp_path, monkeypatch)


def _moved_spam(h, msgid="spam@x", sender="seller@shop.example"):
    h.deliver(msgid, score=12, sender=sender)
    h.scan()
    h.advance(61)
    h.moves()
    assert h.client.msgids("Junk") == [msgid]


def _rules(h):
    return [tuple(r) for r in h.db.conn.execute(
        "SELECT account, pattern, kind, created_by FROM sender_rules ORDER BY id")]


def test_moving_out_of_spam_folder_allows_the_exact_sender(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    _moved_spam(h)
    h.user_moves("spam@x", "Junk", "INBOX", flags=("\\Seen",))
    h.scan()
    rules = _rules(h)
    assert rules == [(h.acc.name, "seller@shop.example", "allow", "auto:flytning")]
    assert h.row("spam@x")["user_verdict"] == "ham"
    ev = h.db.conn.execute("SELECT detail FROM events WHERE event='rule_auto_allow'").fetchall()
    assert len(ev) == 1 and "seller@shop.example" in ev[0][0]
    # The next mail from that sender stays even with a spam score.
    h.deliver("next@x", score=14, sender="seller@shop.example")
    h.scan()
    h.advance(61)
    h.moves()
    assert "next@x" in h.client.msgids("INBOX")
    assert h.row("next@x")["our_action"] == "allowlisted"


def test_rescue_switches_an_exact_block_rule_to_allow(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    eng.add_sender_rule(h.db.conn, h.acc.name, "seller@shop.example", "block", None, "admin")
    h.deliver("spam@x", score=1, sender="seller@shop.example")
    h.scan()
    h.advance(61)
    h.moves()
    assert h.client.msgids("Junk") == ["spam@x"]          # moved by the block rule
    h.user_moves("spam@x", "Junk", "INBOX")
    h.scan()
    assert _rules(h) == [(h.acc.name, "seller@shop.example", "allow", "auto:flytning")]
    assert "(was block)" in h.db.conn.execute(
        "SELECT detail FROM events WHERE event='rule_auto_allow'").fetchone()[0]


def test_domain_and_global_rules_are_left_alone(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    eng.add_sender_rule(h.db.conn, "*", "@shop.example", "block", None, "admin")
    h.deliver("spam@x", score=1, sender="seller@shop.example")
    h.scan()
    h.advance(61)
    h.moves()
    h.user_moves("spam@x", "Junk", "INBOX")
    h.scan()
    rules = _rules(h)
    assert ("*", "@shop.example", "block", "admin") in rules            # untouched
    assert (h.acc.name, "seller@shop.example", "allow", "auto:flytning") in rules  # exact wins


def test_webui_release_does_not_auto_allow(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    _moved_spam(h)
    h.user_moves("spam@x", "Junk", "INBOX")
    with h.db.tx():
        h.db.update_message("spam@x", our_action="manual_release", user_verdict="ham",
                            verdict_by="admin", current_folder="INBOX")
    h.scan()
    assert _rules(h) == []


@pytest.mark.parametrize("cfg", [{"auto_allow_on_rescue": False}, {"mode": "flag"}])
def test_auto_allow_can_be_turned_off(eng, monkeypatch, cfg):
    mode = cfg.get("mode", "move")
    h = Harness(eng, monkeypatch, mode=mode)
    if "auto_allow_on_rescue" in cfg:
        h.acc.auto_allow_on_rescue = False
    h.deliver("spam@x", score=12, sender="seller@shop.example")
    h.scan()
    h.advance(61)
    h.moves()
    # flag mode leaves it in INBOX; simulate a user who had moved it to junk and back
    if mode == "flag":
        h.user_moves("spam@x", "INBOX", "Junk")
        h.poll()
    h.user_moves("spam@x", "Junk", "INBOX")
    h.scan()
    if "auto_allow_on_rescue" in cfg:
        assert _rules(h) == []


def test_config_key_is_validated(eng, tmp_path):
    p = tmp_path / "accounts.yml"
    p.write_text("accounts:\n  - name: a\n    user: a@x.dk\n    imap_host: imap.x.dk\n"
                 "    password: pw\n    auto_allow_on_rescue: 'ja'\n")
    with pytest.raises(Exception):
        eng.load_account_configs(p)
    p.write_text("accounts:\n  - name: a\n    user: a@x.dk\n    imap_host: imap.x.dk\n"
                 "    password: pw\n    auto_allow_on_rescue: false\n")
    assert eng.load_account_configs(p)[0].auto_allow_on_rescue is False


# ----- 2.1 review fixes --------------------------------------------------------


def _release_via_services(eng, h, msgid, *, scan_between=True, monkeypatch=None):
    """services._do_release against the harness mailbox. The engine's
    account thread wakes on the new inbox UID while the release is still
    learning/booking: simulate that with a scan right after the IMAP move."""
    import services

    real_move = eng.imap_move

    def move_then_scan(client, uids, dest, **kw):
        out = real_move(client, uids, dest, **kw)
        if scan_between:
            h.scan()
        return out

    monkeypatch.setattr(eng, "imap_move", move_then_scan)
    fmap = services._folder_map(h.acc, services._list_folders(h.client))
    caps = services._caps_for_engine(services._caps(h.client))
    res = services._do_release(eng, h.db, h.acc, services._Session(h.client), fmap, caps,
                               msgid, "admin")
    monkeypatch.setattr(eng, "imap_move", real_move)
    return res


def test_webui_release_racing_the_engine_scan_does_not_auto_allow(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    _moved_spam(h)
    res = _release_via_services(eng, h, "spam@x", monkeypatch=monkeypatch)
    assert res["ok"], res
    assert "spam@x" in h.client.msgids("INBOX")
    assert _rules(h) == []
    r = h.row("spam@x")
    assert r["our_action"] == "manual_release" and r["user_verdict"] == "ham"
    assert h.events("user_rescued") == [] and h.events("rule_auto_allow") == []
    # Never moved back.
    h.scan()
    h.advance(61)
    h.moves()
    assert "spam@x" in h.client.msgids("INBOX")


def test_webui_release_keeps_an_exact_block_rule(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    eng.add_sender_rule(h.db.conn, h.acc.name, "seller@shop.example", "block", None, "admin")
    _moved_spam(h)
    _release_via_services(eng, h, "spam@x", monkeypatch=monkeypatch)
    assert _rules(h) == [(h.acc.name, "seller@shop.example", "block", "admin")]


def test_failed_webui_release_restores_the_row(eng, monkeypatch):
    import services

    h = Harness(eng, monkeypatch, mode="move")
    _moved_spam(h)
    before = dict(h.row("spam@x"))

    def boom(*a, **kw):
        raise eng.IMAPClientError("NO move refused")

    monkeypatch.setattr(eng, "imap_move", boom)
    fmap = services._folder_map(h.acc, services._list_folders(h.client))
    res = services._do_release(eng, h.db, h.acc, services._Session(h.client), fmap,
                               frozenset(), "spam@x", "admin")
    assert res["code"] == "move_failed"
    after = dict(h.row("spam@x"))
    for col in ("current_folder", "our_action", "user_verdict", "verdict_by"):
        assert after[col] == before[col], col


def test_redelivery_after_spam_folder_was_emptied_is_not_a_rescue(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("spam@x", score=14, sender="seller@shop.example")
    h.scan()
    h.advance(61)
    h.moves()
    box = h.client.folders["Junk"]
    for uid in list(box.msgs):
        del box.msgs[uid]                       # the user empties Spamfilter
    h.state.last_junk_reconcile = 0.0
    h.poll()
    assert h.row("spam@x")["current_folder"] == "gone"
    h.advance(3600)
    h.deliver("spam@x", score=14, sender="seller@shop.example")   # same mail again
    h.scan()
    h.advance(61)
    h.moves()
    r = h.row("spam@x")
    assert _rules(h) == []
    assert r["user_verdict"] != "ham" and r["pending_learn"] != "ham"
    assert r["our_action"] != "user_rescued"
    assert "spam@x" in h.client.msgids("Junk")
    assert "spam@x" not in h.client.msgids("INBOX")


def test_rescue_after_reconcile_marked_gone_still_counts(eng, monkeypatch):
    """A real drag-out keeps INTERNALDATE: still a rescue even when the
    junk reconcile ran first and marked the row 'gone'."""
    h = Harness(eng, monkeypatch, mode="move")
    _moved_spam(h)
    with h.db.tx():
        h.db.update_message("spam@x", current_folder="gone")
    h.user_moves("spam@x", "Junk", "INBOX")
    h.scan()
    assert h.row("spam@x")["our_action"] == "user_rescued"
    assert _rules(h) == [(h.acc.name, "seller@shop.example", "allow", "auto:flytning")]


def test_moving_into_spam_again_removes_the_auto_rule(eng, monkeypatch):
    """Both directions in the mail app: out = allowed, in again = the
    automatic allow rule is removed, so the next spam is moved."""
    h = Harness(eng, monkeypatch, mode="move")
    _moved_spam(h, "s1@x")
    h.user_moves("s1@x", "Junk", "INBOX", flags=("\\Seen",))
    h.scan()
    assert _rules(h) == [(h.acc.name, "seller@shop.example", "allow", "auto:flytning")]
    h.deliver("s2@x", score=14, sender="seller@shop.example")
    h.scan()
    h.advance(61)
    h.moves()
    assert h.row("s2@x")["our_action"] == "allowlisted"
    h.user_moves("s2@x", "INBOX", "Junk")
    h.advance(400)
    h.poll()
    assert h.row("s2@x")["our_action"] == "user_junked"
    assert _rules(h) == []
    assert len(h.events("rule_auto_allow_removed")) == 1
    h.deliver("s3@x", score=14, sender="seller@shop.example")
    h.scan()
    h.advance(61)
    h.moves()
    assert "s3@x" in h.client.msgids("Junk")


def test_unknown_mail_dragged_into_filter_folder_removes_the_auto_rule(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", folders=("INBOX", "Spamfilter", "Junk"),
                junk="Spamfilter", junk_explicit=True)
    h.poll()                                    # first sight of the folders
    h.deliver("s1@x", score=12, sender="seller@shop.example")
    h.scan()
    h.advance(61)
    h.moves()
    h.user_moves("s1@x", "Spamfilter", "INBOX")
    h.scan()
    assert len(_rules(h)) == 1
    # E3: a mail the filter never saw, dragged into its folder.
    h.client.add("Spamfilter", eng_message("other@x"),
                 internaldate=dt.datetime.fromtimestamp(h.t, dt.timezone.utc))  # 2.12: after the first scan
    h.advance(400)
    h.poll()
    assert h.row("other@x")["our_action"] == "user_junked"
    assert _rules(h) == []


def eng_message(msgid):
    from fakes_engine import make_message
    return make_message(msgid, sender="seller@shop.example")


def test_moving_into_spam_keeps_hand_made_allow_rules(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    eng.add_sender_rule(h.db.conn, h.acc.name, "seller@shop.example", "allow", None, "admin")
    h.deliver("s2@x", score=14, sender="seller@shop.example")
    h.scan()
    h.advance(61)
    h.moves()
    h.user_moves("s2@x", "INBOX", "Junk")
    h.advance(400)
    h.poll()
    assert h.row("s2@x")["our_action"] == "user_junked"
    assert _rules(h) == [(h.acc.name, "seller@shop.example", "allow", "admin")]


FIX = Path(__file__).resolve().parent / "fixtures" / "headers"
_DMARC_REJECT = {"DMARC_POLICY_REJECT": {"name": "DMARC_POLICY_REJECT", "score": 2.0},
                 "R_DKIM_REJECT": {"name": "R_DKIM_REJECT", "score": 1.0}}


def _deliver_raw(h, raw, score, symbols=None, newid=None):
    import datetime as dt
    import email
    import email.policy
    import re

    if newid:
        raw = re.sub(rb"(?m)^Message-ID: .*$", f"Message-ID: <{newid}>".encode(), raw, count=1)
    msgid = email.message_from_bytes(raw, policy=email.policy.compat32)["Message-ID"].strip("<> ")
    h.rspamd.scores[msgid] = score
    if symbols:
        h.rspamd.symbols[msgid] = symbols
    h.client.add("INBOX", raw, internaldate=dt.datetime.fromtimestamp(h.t, dt.timezone.utc))
    return msgid


@pytest.mark.parametrize("rescue", [False, True])
def test_rescued_forgery_never_shadows_an_altid_igennem_rule(eng, monkeypatch, rescue):
    import mailctx

    monkeypatch.setattr(eng, "_mailctx", lambda: mailctx)
    h = Harness(eng, monkeypatch, mode="move", junk="Spamfilter", junk_explicit=True,
                threshold=10.0)
    eng.add_sender_rule(h.db.conn, "*", "@vexar.example", "allow", force=True)
    forged = (FIX / "gigahost_vexar_shop_spam.eml").read_bytes().replace(
        b"<support@vexar.example>", b"<mailbot@vexar.example>")
    fid = _deliver_raw(h, forged, 25.0)
    h.scan()
    h.advance(61)
    h.moves()
    assert h.row(fid)["our_action"] == "moved_to_junk"
    if rescue:
        h.user_moves(fid, "Spamfilter", "INBOX")
        h.scan()
        assert h.row(fid)["our_action"] == "user_rescued"
        assert [r for r in _rules(h) if r[3] == "auto:flytning"] == []
        assert len(h.events("rule_auto_allow_skipped")) == 1
    genuine = (FIX / "gigahost_vexar_shop_order.eml").read_bytes()
    gid = _deliver_raw(h, genuine, 25.0, _DMARC_REJECT, newid="order-2@vexar.example")
    h.scan()
    h.advance(61)
    h.moves()
    assert h.row(gid)["our_action"] == "allowlisted"
    assert gid in h.client.msgids("INBOX")
