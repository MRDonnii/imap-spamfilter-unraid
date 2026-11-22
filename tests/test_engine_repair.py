"""ENGINE 2.1 E5: moves interrupted between UID COPY, STORE \\Deleted and
UID EXPUNGE (Gigahost has no MOVE) are completed exactly on reconnect -
one copy in the spam folder, the inbox original removed by its exact UID,
and never anything the filter did not flag itself."""

from __future__ import annotations

import datetime as dt
import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import (  # noqa: E402
    SCANNET_CAPS,
    IMAPClientAbortError,
    IMAPClientError,
    make_message,
    setup_engine,
)
from test_engine_scan import Harness  # noqa: E402

LOG = logging.getLogger("test")


@pytest.fixture
def eng(tmp_path, monkeypatch):
    return setup_engine(tmp_path, monkeypatch)


def _queue(h, msgid="spam@x", score=30):
    uid = h.deliver(msgid, score=score)
    h.scan()
    h.advance(120)
    return uid


def _reconnect(h):
    h.eng._on_connected(h.client, h.db, LOG, h.acc, h.state)


def _journal(h):
    return [dict(r) for r in h.db.conn.execute("SELECT * FROM move_journal")]


def _no_plain_expunge(h):
    assert "expunge" not in h.client.write_names()


def _expunges(h):
    return [w for w in h.client.writes if w[0] == "uid_expunge"]


def test_drop_before_copy_reached_the_server(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    _queue(h)
    h.client.fail_on["copy"] = IMAPClientAbortError("socket closed")
    with pytest.raises(IMAPClientAbortError):
        h.moves()
    assert [j["stage"] for j in _journal(h)] == ["copy"]
    assert h.row("spam@x")["our_action"] == "pending_move"
    _reconnect(h)                       # nothing happened: back to the queue
    assert _journal(h) == [] and h.db.count_pending_moves() == 1
    assert any(e[0] == "move_repair_retry" for e in h.events())
    h.moves()
    assert h.client.msgids("Junk") == ["spam@x"] and h.client.msgids("INBOX") == []
    assert h.row("spam@x")["our_action"] == "moved_to_junk"
    _no_plain_expunge(h)


def test_drop_after_copy_landed_completes_without_a_second_copy(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    uid = _queue(h)
    real_copy = h.client.copy

    def copy_then_drop(messages, folder):
        real_copy(messages, folder)
        raise IMAPClientAbortError("connection reset after COPY")

    h.client.copy = copy_then_drop
    with pytest.raises(IMAPClientAbortError):
        h.moves()
    del h.client.copy
    assert h.client.msgids("Junk") == ["spam@x"] and h.client.msgids("INBOX") == ["spam@x"]
    # The junk poll must not claim the move while it is half done.
    h.poll()
    assert h.row("spam@x")["our_action"] == "pending_move"
    _reconnect(h)
    assert h.client.msgids("Junk") == ["spam@x"] and h.client.msgids("INBOX") == []
    assert _expunges(h)[-1][2] == (uid,)
    r = h.row("spam@x")
    assert r["our_action"] == "moved_to_junk" and r["current_folder"] == "Junk"
    assert _journal(h) == [] and h.db.count_pending_moves() == 0
    assert h.stat("moved") == 1 and any(e[0] == "move_repaired" for e in h.events())
    h.moves()
    assert h.client.msgids("Junk") == ["spam@x"]           # never copied twice
    _no_plain_expunge(h)


def test_drop_between_store_deleted_and_expunge_finishes_our_expunge(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    uid = _queue(h)
    # Unrelated mail the user marked deleted must survive everything.
    other = h.client.add("INBOX", make_message("users-trash@x"), flags=("\\Deleted", "\\Seen"))
    h.client.fail_on["uid_expunge"] = IMAPClientAbortError("socket closed")
    h.client.fail_on["remove_flags"] = IMAPClientAbortError("socket closed")
    h.moves()
    r = h.row("spam@x")
    assert r["our_action"] == "move_failed" and r["moved_to_junk_at"]
    assert [j["stage"] for j in _journal(h)] == ["flag"] and _journal(h)[0]["predeleted"] == 0
    assert "\\Deleted" in h.client.flags_of("INBOX", uid)
    _reconnect(h)
    assert h.client.msgids("INBOX") == ["users-trash@x"]
    assert h.client.msgids("Junk") == ["spam@x"]
    assert _expunges(h)[-1][2] == (uid,) and other in h.client.uids("INBOX")
    assert h.row("spam@x")["our_action"] == "moved_to_junk" and _journal(h) == []
    _no_plain_expunge(h)


def test_failed_expunge_with_rollback_is_completed_on_reconnect(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    uid = _queue(h)
    h.client.fail_on["uid_expunge"] = IMAPClientError("NO expunge failed")
    h.moves()
    assert "\\Deleted" not in h.client.flags_of("INBOX", uid)   # rolled back
    assert [j["stage"] for j in _journal(h)] == ["copied"]
    assert h.row("spam@x")["our_action"] == "move_failed"
    _reconnect(h)
    assert h.client.msgids("INBOX") == [] and h.client.msgids("Junk") == ["spam@x"]
    assert h.row("spam@x")["our_action"] == "moved_to_junk"


def test_housekeeping_also_repairs_without_a_reconnect(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    _queue(h)
    h.client.fail_on["uid_expunge"] = IMAPClientError("NO expunge failed")
    h.moves()
    eng._housekeeping(h.client, h.db, LOG, h.acc, h.state)
    assert h.client.msgids("INBOX") == [] and h.row("spam@x")["our_action"] == "moved_to_junk"


def test_original_flagged_deleted_by_the_user_is_never_expunged(eng, monkeypatch):
    """Copy landed (stage 'copied'), but the \\Deleted on the original was
    not set by us (the journal says so): leave it."""
    h = Harness(eng, monkeypatch, mode="move")
    uid = _queue(h)
    h.client.fail_on["uid_expunge"] = IMAPClientError("NO expunge failed")
    h.moves()
    h.client.folders["INBOX"].msgs[uid].flags.add("\\Deleted")   # the user's client
    n_expunge = len(_expunges(h))
    _reconnect(h)
    assert uid in h.client.uids("INBOX") and len(_expunges(h)) == n_expunge
    assert h.row("spam@x")["our_action"] == "move_failed"
    assert any(e[0] == "move_repair_giveup" for e in h.events())


def test_user_intent_wins_over_completing_the_move(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    uid = _queue(h)
    h.client.fail_on["uid_expunge"] = IMAPClientError("NO expunge failed")
    h.moves()
    h.client.folders["INBOX"].msgs[uid].flags.add("\\Flagged")   # starred meanwhile
    _reconnect(h)
    assert h.client.msgids("INBOX") == ["spam@x"]
    assert h.row("spam@x")["our_action"] == "none" and _journal(h) == []


def test_move_capability_drop_after_server_moved(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", caps=SCANNET_CAPS)
    _queue(h)
    real_move = h.client.move

    def move_then_drop(messages, folder):
        real_move(messages, folder)
        raise IMAPClientAbortError("reset")

    h.client.move = move_then_drop
    with pytest.raises(IMAPClientAbortError):
        h.moves()
    del h.client.move
    assert [j["stage"] for j in _journal(h)] == ["move"]
    _reconnect(h)
    assert h.row("spam@x")["our_action"] == "moved_to_junk" and _journal(h) == []
    assert h.client.msgids("Junk") == ["spam@x"]


def test_move_capability_drop_before_server_moved_retries(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", caps=SCANNET_CAPS)
    _queue(h)
    h.client.fail_on["move"] = IMAPClientAbortError("reset")
    with pytest.raises(IMAPClientAbortError):
        h.moves()
    _reconnect(h)
    assert _journal(h) == [] and h.db.count_pending_moves() == 1
    h.moves()
    assert h.client.msgids("Junk") == ["spam@x"] and h.client.msgids("INBOX") == []


def test_legacy_move_failed_row_without_journal(eng, monkeypatch):
    """A 2.0.x 'move_failed' with a copy in junk: completed only when the
    inbox original is undeleted (nobody knows who set a \\Deleted)."""
    h = Harness(eng, monkeypatch, mode="move")
    idate = dt.datetime.fromtimestamp(h.t, dt.timezone.utc)
    for mid, flags in (("legacy@x", ()), ("legacy-del@x", ("\\Deleted",))):
        h.client.add("INBOX", make_message(mid), flags=flags, internaldate=idate)
        h.client.add("Junk", make_message(mid), internaldate=idate)
        with h.db.tx():
            h.db.upsert_message(mid, "INBOX", "a@example.org", "x", int(h.t))
            h.db.update_message(mid, our_action="move_failed", moved_to_junk_at=int(h.t), our_score=20.0)
    _reconnect(h)
    assert h.client.msgids("INBOX") == ["legacy-del@x"]
    assert h.client.msgids("Junk") == ["legacy@x", "legacy-del@x"]
    assert h.row("legacy@x")["our_action"] == "moved_to_junk"
    assert h.row("legacy-del@x")["our_action"] == "move_failed"


def test_repair_needs_the_copy_in_junk(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    idate = dt.datetime.fromtimestamp(h.t, dt.timezone.utc)
    h.client.add("INBOX", make_message("nocopy@x"), internaldate=idate)
    with h.db.tx():
        h.db.upsert_message("nocopy@x", "INBOX", "a@example.org", "x", int(h.t))
        h.db.update_message("nocopy@x", our_action="move_failed", moved_to_junk_at=int(h.t))
    _reconnect(h)
    assert h.client.msgids("INBOX") == ["nocopy@x"] and _expunges(h) == []


def test_shadow_and_flag_modes_never_repair(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="flag")
    with h.db.tx():
        h.db.upsert_message("m@x", "INBOX", "a@example.org", "x", int(h.t))
        h.db.update_message("m@x", our_action="move_failed", moved_to_junk_at=int(h.t))
    assert eng.repair_interrupted_moves(h.client, h.db, LOG, h.acc, h.acc.folder_map, h.state) == 0


# ----- duplicate copies -----------------------------------------------------------


def test_identical_copies_collapse_to_the_newest(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    idate = dt.datetime(2026, 10, 20, 8, 0, tzinfo=dt.timezone.utc)
    raw = make_message("dup@x")
    a = h.client.add("Junk", raw, internaldate=idate)
    b = h.client.add("Junk", raw, internaldate=idate)
    h.client.select_folder("Junk")
    assert eng.find_uids_by_message_id(h.client, "dup@x") == [b]
    assert eng.find_uids_by_message_id(h.client, "dup@x", collapse_copies=False) == [a, b]
    # A different delivery with the same Message-ID stays distinct (ambiguous).
    c = h.client.add("Junk", raw, internaldate=idate + dt.timedelta(minutes=5))
    assert eng.find_uids_by_message_id(h.client, "dup@x") == [b, c]


def test_legacy_row_without_internaldate_is_never_completed(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.client.add("INBOX", make_message("nodate@x"))
    h.client.add("Junk", make_message("nodate@x"))
    with h.db.tx():
        h.db.upsert_message("nodate@x", "INBOX", "a@example.org", "x", None)
        h.db.update_message("nodate@x", our_action="move_failed", moved_to_junk_at=int(h.t))
    _reconnect(h)
    assert h.client.msgids("INBOX") == ["nodate@x"] and _expunges(h) == []


def test_journal_without_internaldate_only_trusts_the_exact_uid(eng, monkeypatch):
    """The journalled UID is THE original (UIDs are never reused within a
    UIDVALIDITY). When it is gone, another inbox copy with the same
    Message-ID - here one without a usable INTERNALDATE match - is a
    different message and is never touched."""
    h = Harness(eng, monkeypatch, mode="move")
    uid = _queue(h)
    h.client.fail_on["uid_expunge"] = IMAPClientError("NO expunge failed")
    h.moves()
    with h.db.tx():
        h.db.conn.execute("UPDATE move_journal SET internaldate=NULL, uid=uid+100")
    n_expunge = len(_expunges(h))
    _reconnect(h)
    assert uid in h.client.uids("INBOX") and len(_expunges(h)) == n_expunge
    assert "\\Deleted" not in h.client.flags_of("INBOX", uid)
    assert _journal(h) == []


# ----- more interruption points (2.1 review) ---------------------------------------


def test_drop_during_store_before_the_flag_reached_the_server(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    uid = _queue(h)
    h.client.fail_on["add_flags"] = IMAPClientAbortError("socket closed")
    h.client.fail_on["remove_flags"] = IMAPClientAbortError("socket closed")
    h.moves()
    assert [j["stage"] for j in _journal(h)] == ["flag"]
    assert "\\Deleted" not in h.client.flags_of("INBOX", uid)
    assert h.row("spam@x")["our_action"] == "move_failed"
    _reconnect(h)
    assert h.client.msgids("INBOX") == [] and h.client.msgids("Junk") == ["spam@x"]
    assert _expunges(h)[-1][2] == (uid,)
    assert h.row("spam@x")["our_action"] == "moved_to_junk" and _journal(h) == []
    _no_plain_expunge(h)


def test_drop_after_store_reached_the_server(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    uid = _queue(h)
    real = h.client.add_flags

    def flag_then_drop(messages, flags, silent=False):
        real(messages, flags, silent)
        raise IMAPClientAbortError("reset after STORE")

    h.client.add_flags = flag_then_drop
    h.client.fail_on["remove_flags"] = IMAPClientAbortError("socket closed")
    h.moves()
    del h.client.add_flags
    assert "\\Deleted" in h.client.flags_of("INBOX", uid)
    _reconnect(h)
    assert h.client.msgids("INBOX") == [] and h.client.msgids("Junk") == ["spam@x"]
    assert _expunges(h)[-1][2] == (uid,)
    assert h.row("spam@x")["our_action"] == "moved_to_junk"
    _no_plain_expunge(h)


def test_drop_after_the_expunge_was_done(eng, monkeypatch):
    """Everything reached the server, only the bookkeeping was lost."""
    h = Harness(eng, monkeypatch, mode="move")
    _queue(h)
    real = h.client.uid_expunge

    def expunge_then_drop(messages):
        real(messages)
        raise IMAPClientAbortError("reset after EXPUNGE")

    h.client.uid_expunge = expunge_then_drop
    h.client.fail_on["remove_flags"] = IMAPClientAbortError("socket closed")
    h.moves()
    del h.client.uid_expunge
    n_expunge = len(_expunges(h))
    _reconnect(h)
    assert h.client.msgids("INBOX") == [] and h.client.msgids("Junk") == ["spam@x"]
    assert len(_expunges(h)) == n_expunge          # nothing left to expunge
    r = h.row("spam@x")
    assert r["our_action"] == "moved_to_junk" and r["current_folder"] == "Junk"
    assert _journal(h) == []


def test_user_rescue_of_the_copy_before_repair_is_never_expunged(eng, monkeypatch):
    """Copy in Spamfilter, original still in the inbox (failed expunge).
    The user drags the Spamfilter copy back with a client that has no MOVE
    (COPY + \\Deleted on the source): the inbox now holds the original AND
    the user's copy, the Spamfilter copy is \\Deleted. Nothing is removed."""
    h = Harness(eng, monkeypatch, mode="move")
    uid = _queue(h)
    h.client.fail_on["uid_expunge"] = IMAPClientError("NO expunge failed")
    h.moves()
    [jcopy] = h.client.uids("Junk")
    m = h.client.folders["Junk"].msgs[jcopy]
    back = h.client.add("INBOX", m.raw, internaldate=m.internaldate)
    m.flags.add("\\Deleted")
    n_expunge = len(_expunges(h))
    _reconnect(h)
    assert set(h.client.uids("INBOX")) == {uid, back} and len(_expunges(h)) == n_expunge
    assert all("\\Deleted" not in h.client.flags_of("INBOX", u) for u in (uid, back))


def test_legacy_row_with_several_identical_inbox_copies_is_left_alone(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    idate = dt.datetime.fromtimestamp(h.t, dt.timezone.utc)
    for _ in range(2):
        h.client.add("INBOX", make_message("twice@x"), internaldate=idate)
    h.client.add("Junk", make_message("twice@x"), internaldate=idate)
    with h.db.tx():
        h.db.upsert_message("twice@x", "INBOX", "a@example.org", "x", int(h.t))
        h.db.update_message("twice@x", our_action="move_failed", moved_to_junk_at=int(h.t))
    _reconnect(h)
    assert h.client.msgids("INBOX") == ["twice@x", "twice@x"] and _expunges(h) == []
    assert h.row("twice@x")["our_action"] == "move_failed"


def test_collapse_prefers_the_copy_nobody_marked_deleted(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    idate = dt.datetime(2026, 10, 20, 8, 0, tzinfo=dt.timezone.utc)
    raw = make_message("dup@x")
    a = h.client.add("Junk", raw, internaldate=idate)
    h.client.add("Junk", raw, internaldate=idate, flags=("\\Deleted",))
    h.client.select_folder("Junk")
    assert eng.find_uids_by_message_id(h.client, "dup@x") == [a]
