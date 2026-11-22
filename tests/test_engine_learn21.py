"""ENGINE 2.1: user drags into the filter's own folder (E3) and the
balanced autolearn of confirmed mail (E6)."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import make_message, setup_engine, stub_mailctx  # noqa: E402
from test_engine_scan import Harness  # noqa: E402

LOG = logging.getLogger("test")
DAY = 86400


@pytest.fixture
def eng(tmp_path, monkeypatch):
    return setup_engine(tmp_path, monkeypatch)


def _spamfilter_harness(eng, monkeypatch, **over):
    h = Harness(eng, monkeypatch, mode="move", folders=("INBOX", "Junk", "Trash"),
                junk="Spamfilter", junk_explicit=True, **over)
    assert h.acc.folder_map["filter_junk"] == "Spamfilter"
    assert h.acc.folder_map["provider_junk"] == "Junk"
    return h


def _fresh(h):
    """2.12 (#24): an arrival time after the mailbox's first scan (the fake
    IMAP default is the real clock minus a day, long before the fake T0)."""
    import datetime as _dt

    return _dt.datetime.fromtimestamp(h.t, _dt.timezone.utc)


def _learned(h, kind):
    return [c for c in h.rspamd.learn_calls if c["url"].endswith(f"/learn{kind}")]


# ----- E3 ---------------------------------------------------------------------------


def test_user_drag_into_filter_folder_is_user_junked_and_learned(eng, monkeypatch):
    h = _spamfilter_harness(eng, monkeypatch)
    h.poll()                                    # first sight of both folders
    h.client.add("Spamfilter", make_message("drag@x", sender="x@spam.example"), internaldate=_fresh(h))
    h.client.add("Junk", make_message("prov@x"))
    h.poll()
    r = h.row("drag@x")
    assert r["our_action"] == "user_junked" and r["user_verdict"] == "spam"
    assert r["verdict_by"] == "user:move" and r["pending_learn"] == "spam"
    assert r["current_folder"] == "Spamfilter" and r["origin"] == "junk_poll"
    assert h.row("prov@x")["our_action"] == "provider_junk"   # provider's own Junk unchanged
    assert h.stat("user_junked") == 1
    h.advance(h.acc.learn_grace_seconds + 1)
    h.poll()
    assert h.row("drag@x")["learned_as"] == "spam" and len(_learned(h, "spam")) == 1


def test_preexisting_filter_folder_content_is_not_a_user_verdict(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", folders=("INBOX", "Junk", "Spamfilter"),
                junk="Spamfilter", junk_explicit=True)
    h.client.add("Spamfilter", make_message("old@x"))
    h.poll()
    assert h.row("old@x")["our_action"] == "provider_junk" and h.row("old@x")["user_verdict"] is None


def test_first_pass_spanning_several_polls_stays_preexisting(eng, monkeypatch):
    monkeypatch.setattr(eng, "JUNK_POLL_MAX_PER_RUN", 2)
    h = Harness(eng, monkeypatch, mode="move", folders=("INBOX", "Spamfilter"),
                junk="Spamfilter", junk_explicit=True)
    for i in range(5):
        h.client.add("Spamfilter", make_message(f"old{i}@x"))
    for _ in range(3):
        h.poll()
    assert {h.row(f"old{i}@x")["our_action"] for i in range(5)} == {"provider_junk"}
    h.client.add("Spamfilter", make_message("new@x"), internaldate=_fresh(h))
    h.poll()
    assert h.row("new@x")["our_action"] == "user_junked"


def test_provider_junk_moved_by_user_into_filter_folder(eng, monkeypatch):
    h = _spamfilter_harness(eng, monkeypatch)
    h.poll()
    h.client.add("Junk", make_message("p@x"), internaldate=_fresh(h))
    h.poll()
    assert h.row("p@x")["our_action"] == "provider_junk"
    h.user_moves("p@x", "Junk", "Spamfilter")
    h.poll()
    assert h.row("p@x")["our_action"] == "user_junked" and h.row("p@x")["user_verdict"] == "spam"


def test_our_own_moves_into_the_filter_folder_stay_ours(eng, monkeypatch):
    h = _spamfilter_harness(eng, monkeypatch)
    h.poll()
    h.deliver("s@x", score=30)
    h.scan()
    h.advance(10)
    h.moves()
    h.poll()
    r = h.row("s@x")
    assert r["our_action"] == "moved_to_junk" and r["user_verdict"] is None


def test_our_daily_receipt_dragged_into_the_filter_folder_is_never_learned(eng, monkeypatch, tmp_path):
    import yaml

    h = _spamfilter_harness(eng, monkeypatch)
    h.poll()
    cfg = tmp_path / "accounts.yml"
    cfg.write_text(yaml.safe_dump({"accounts": [{"name": "acct", "user": "user@example-a.dk",
                                                 "imap_host": "h", "password": "pw"}]}))
    res = eng.send_receipt("acct", preview=True, client=h.client, path=cfg)
    assert res["ok"]
    h.scan()
    rid = res["message_id"]
    [uid] = h.client.uids("INBOX")
    h.user_moves(rid, "INBOX", "Spamfilter")
    h.poll()
    assert h.row(rid) is None and h.stat("user_junked") == 0
    h.advance(h.acc.learn_grace_seconds + 1)
    h.poll()
    assert _learned(h, "spam") == []


def test_filter_folder_named_like_a_provider_folder_is_not_owned(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")      # junk: Junk (the provider's)
    assert "filter_junk" not in h.acc.folder_map
    h.poll()
    h.client.add("Junk", make_message("p@x"), internaldate=_fresh(h))
    h.poll()
    assert h.row("p@x")["our_action"] == "provider_junk"


# ----- E6 autolearn ----------------------------------------------------------------


def _moved_spam(h, msgid, score):
    h.deliver(msgid, score=score)
    h.scan()
    h.advance(10)
    h.moves()


def _autolearn(h):
    return h.eng.autolearn_pass(h.client, h.db, LOG, h.acc, h.acc.folder_map)


def test_confirmed_spam_is_autolearned_after_three_days(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    _moved_spam(h, "strong@x", 14.0)       # >= threshold + 6
    _moved_spam(h, "weak@x", 13.9)
    _moved_spam(h, "released@x", 20.0)
    with h.db.tx():
        h.db.update_message("released@x", user_verdict="ham")
    h.advance(3 * DAY - 100)
    assert _autolearn(h) == {"spam": 0, "ham": 0}
    h.advance(200)
    assert _autolearn(h) == {"spam": 1, "ham": 0}
    assert h.row("strong@x")["learned_as"] == "spam"
    assert h.row("weak@x")["learned_as"] is None and h.row("released@x")["learned_as"] is None
    assert h.stat("autolearned_spam") == 1 and h.stat("learned_spam") == 1
    entries = eng.autolearn_entries(h.db.conn, "acct")
    assert [(e["message_id"], e["kind"], e["outcome"]) for e in entries] == [("strong@x", "spam", "learned")]
    assert any(e[0] == "autolearn_spam" for e in h.events())
    assert "autolearn" in [e for e in h.events("learn_spam")][0][2]
    assert _autolearn(h) == {"spam": 0, "ham": 0}     # never twice
    assert eng.autolearn_stats(h.db.conn, "acct") == {"spam": 1, "ham": 0, "reverted": 0}


def test_kept_clear_ham_is_autolearned_after_seven_days(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("ham@x", score=-0.5)
    h.deliver("meh@x", score=0.5)
    h.deliver("deleted@x", score=-3)
    h.deliver("unread@x", score=-2)
    h.deliver("marked@x", score=-2)
    h.scan()
    box = h.client.folders["INBOX"]
    for uid, m in list(box.msgs.items()):
        if b"deleted@x" in m.raw:
            del box.msgs[uid]                     # the user deleted it
        elif b"unread@x" not in m.raw:
            m.flags.add("\\Seen")                 # the user read it and kept it
        if b"marked@x" in m.raw:
            m.flags.add("\\Deleted")              # ... or marked it deleted
    h.advance(7 * DAY + 1)
    assert _autolearn(h) == {"spam": 0, "ham": 1}
    assert h.row("ham@x")["learned_as"] == "ham" and h.row("meh@x")["learned_as"] is None
    outcomes = {e["message_id"]: e["outcome"] for e in eng.autolearn_entries(h.db.conn)}
    # Unread or deleted-marked mail is no evidence (and stays a candidate).
    assert outcomes == {"ham@x": "learned", "deleted@x": "lost"}
    assert h.row("unread@x")["learned_as"] is None and h.row("marked@x")["learned_as"] is None
    assert h.client.writes == []                     # read-only (EXAMINE + PEEK)
    box.msgs[next(u for u, m in box.msgs.items() if b"unread@x" in m.raw)].flags.add("\\Seen")
    assert _autolearn(h) == {"spam": 0, "ham": 1}    # read later: learned on the next pass


def test_autolearn_never_learns_allowlisted_senders(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    eng.add_sender_rule(h.db.conn, "*", "@friend.example", "allow")
    h.deliver("f@x", score=-2, sender="bob@friend.example")
    h.deliver("later@x", score=-2, sender="ann@force.example")
    h.scan()
    # A rule added after the scan (no rule_hit on the row) is honoured too.
    eng.add_sender_rule(h.db.conn, "*", "@force.example", "allow", force=True)
    h.advance(7 * DAY + 1)
    assert _autolearn(h) == {"spam": 0, "ham": 0}
    assert [(e["message_id"], e["outcome"]) for e in eng.autolearn_entries(h.db.conn)] == [
        ("later@x", "skipped_rule")]
    assert h.rspamd.learn_calls == []


def test_autolearn_balance_and_daily_cap(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", autolearn_daily_cap=10, circuit_min_moves=100)
    for i in range(6):
        _moved_spam(h, f"s{i}@x", 20.0)
    h.advance(3 * DAY + 1)
    # No ham learned this week: at most 3 spam (3:1).
    assert _autolearn(h)["spam"] == 3
    h2_cap = Harness(eng, monkeypatch, mode="move", autolearn_daily_cap=1, name="acct2",
                     circuit_min_moves=100)
    for i in range(3):
        _moved_spam(h2_cap, f"t{i}@x", 20.0)
    h2_cap.advance(3 * DAY + 1)
    assert _autolearn(h2_cap)["spam"] == 1
    assert _autolearn(h2_cap)["spam"] == 0           # cap per 24 h


def test_autolearn_off_in_shadow_and_by_config(eng, monkeypatch):
    for over in ({"mode": "shadow"}, {"mode": "move", "autolearn": False}):
        h = Harness(eng, monkeypatch, **over)
        h.deliver(f"ham-{over['mode']}@x", score=-5)
        h.scan()
        h.advance(8 * DAY)
        assert _autolearn(h) == {"spam": 0, "ham": 0}
    assert eng.autolearn_entries(h.db.conn) == []


def test_revert_autolearn_relearns_the_other_class_from_where_it_is(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    _moved_spam(h, "s@x", 20.0)
    h.advance(3 * DAY + 1)
    _autolearn(h)
    entry = eng.autolearn_entries(h.db.conn)[0]
    h.advance(eng.FLIP_FLOP_COOLDOWN_S + 1)
    assert eng.revert_autolearn(h.db.conn, entry["id"], "admin") is True
    assert eng.revert_autolearn(h.db.conn, entry["id"], "admin") is False
    assert h.row("s@x")["pending_learn"] == "ham"
    eng.process_pending_learns(h.client, h.db, LOG, h.acc, h.acc.folder_map)   # still in Junk
    assert h.row("s@x")["learned_as"] == "ham" and len(_learned(h, "ham")) == 1
    assert eng.autolearn_stats(h.db.conn)["reverted"] == 1


def test_explicit_user_learn_marks_autolearn_reverted(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    _moved_spam(h, "s@x", 20.0)
    h.advance(3 * DAY + 1)
    _autolearn(h)
    h.advance(eng.FLIP_FLOP_COOLDOWN_S + 1)
    res = eng.learn_message(h.db, h.acc, make_message("s@x"), "ham", "s@x", actor="anna",
                            reason="manual_release")
    assert res == "learned"
    e = eng.autolearn_entries(h.db.conn)[0]
    assert e["reverted_at"] is not None and e["reverted_by"] == "anna"


def test_housekeeping_runs_autolearn(eng, monkeypatch):
    monkeypatch.setattr(eng, "_mailctx", lambda: stub_mailctx())
    h = Harness(eng, monkeypatch, mode="move")
    uid = h.deliver("ham@x", score=-1)
    h.scan()
    h.client.folders["INBOX"].msgs[uid].flags.add("\\Seen")
    h.advance(7 * DAY + 1)
    eng._housekeeping(h.client, h.db, LOG, h.acc, h.state)
    assert h.row("ham@x")["learned_as"] == "ham"
