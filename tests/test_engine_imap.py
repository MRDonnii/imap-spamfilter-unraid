"""ENGINE: IMAP primitives - imap_move (MOVE / UIDPLUS emulation), exact
Message-ID lookup, connect, folder setup (SPEC E7, E8, A3)."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import (  # noqa: E402
    BARE_CAPS,
    GIGAHOST_CAPS,
    SCANNET_CAPS,
    FakeIMAP,
    IMAPClientAbortError,
    IMAPClientError,
    make_account,
    make_message,
    setup_engine,
)

LOG = logging.getLogger("test")


@pytest.fixture
def eng(tmp_path, monkeypatch):
    return setup_engine(tmp_path, monkeypatch)


def inbox_with(client: FakeIMAP, n: int, *, flags_for: dict[int, tuple] | None = None) -> list[int]:
    uids = [client.add("INBOX", make_message(f"m{i}@x"), flags=(flags_for or {}).get(i, ()))
            for i in range(1, n + 1)]
    client.select_folder("INBOX")
    return uids


def test_move_method_for(eng):
    assert eng.move_method_for(SCANNET_CAPS) == "MOVE"
    assert eng.move_method_for(GIGAHOST_CAPS) == "UIDPLUS"
    assert eng.move_method_for(BARE_CAPS) == "none"
    assert eng.move_method_for(["move"]) == "MOVE"
    assert eng.move_method_for(None) == "none"


def test_imap_move_uses_move_when_available(eng):
    c = FakeIMAP(capabilities=SCANNET_CAPS)
    uids = inbox_with(c, 3)
    eng.imap_move(c, [uids[0], uids[2]], "Junk", capabilities=c.capabilities())
    assert c.msgids("INBOX") == ["m2@x"]
    assert sorted(c.msgids("Junk")) == ["m1@x", "m3@x"]
    assert c.write_names() == ["move"]


def test_imap_move_uidplus_emulation_touches_only_given_uids(eng):
    """Gigahost: no MOVE, UIDPLUS. A message the user had marked \\Deleted
    must survive: never plain EXPUNGE, \\Deleted only on our UIDs."""
    c = FakeIMAP(capabilities=GIGAHOST_CAPS)
    uids = inbox_with(c, 4, flags_for={2: ("\\Deleted",)})  # m2: user-deleted, not ours
    eng.imap_move(c, [uids[0], uids[2]], "Junk", capabilities=c.capabilities())
    assert c.msgids("INBOX") == ["m2@x", "m4@x"]
    assert "\\Deleted" in c.flags_of("INBOX", uids[1])
    assert "\\Deleted" not in c.flags_of("INBOX", uids[3])
    assert sorted(c.msgids("Junk")) == ["m1@x", "m3@x"]
    names = c.write_names()
    assert names == ["copy", "add_flags", "uid_expunge"]
    assert "expunge" not in names and "move" not in names
    add = next(w for w in c.writes if w[0] == "add_flags")
    exp = next(w for w in c.writes if w[0] == "uid_expunge")
    assert add[2] == (uids[0], uids[2]) and exp[2] == (uids[0], uids[2])
    # Moved copies in Junk do not carry \Deleted.
    for u in c.uids("Junk"):
        assert "\\Deleted" not in c.flags_of("Junk", u)


def test_imap_move_uidplus_respects_copyuid_subset(eng):
    """COPYUID says only some UIDs were copied: only those get \\Deleted."""
    c = FakeIMAP(capabilities=GIGAHOST_CAPS)
    uids = inbox_with(c, 2)
    real_copy = c.copy

    def partial_copy(messages, folder):
        real_copy([uids[0]], folder)
        return b"[COPYUID 77 %d 1] Copy completed." % uids[0]

    c.copy = partial_copy
    with pytest.raises(eng.MoveError) as ei:
        eng.imap_move(c, uids, "Junk", capabilities=GIGAHOST_CAPS)
    assert ei.value.copied is True and ei.value.moved == (uids[0],)
    assert c.msgids("INBOX") == ["m2@x"]
    assert "\\Deleted" not in c.flags_of("INBOX", uids[1])


def test_imap_move_copyuid_from_imaplib_untagged(eng):
    """Real IMAPClient.copy() does not return the COPYUID code; imaplib
    files it under untagged_responses. A stale entry must not be used."""
    from types import SimpleNamespace

    c = FakeIMAP(capabilities=GIGAHOST_CAPS)
    uids = inbox_with(c, 2)
    c._imap = SimpleNamespace(untagged_responses={"COPYUID": [b"9 999 5"]})  # stale
    real_copy = c.copy

    def copy_like_imapclient(messages, folder):
        resp = real_copy(messages, folder)
        code = resp[resp.index(b"[") + 9:resp.index(b"]")]
        c._imap.untagged_responses["COPYUID"] = [code]
        return None

    c.copy = copy_like_imapclient
    eng.imap_move(c, uids, "Junk", capabilities=GIGAHOST_CAPS)
    assert c.msgids("INBOX") == []
    assert "COPYUID" not in c._imap.untagged_responses


def test_imap_move_expunge_failure_rolls_back_deleted_flag(eng):
    c = FakeIMAP(capabilities=GIGAHOST_CAPS)
    uids = inbox_with(c, 3, flags_for={2: ("\\Deleted",)})
    c.fail_on["uid_expunge"] = IMAPClientError("EXPUNGE failed")
    with pytest.raises(eng.MoveError) as ei:
        eng.imap_move(c, uids, "Junk", capabilities=GIGAHOST_CAPS)
    assert ei.value.copied is True and ei.value.moved == ()
    assert c.uids("INBOX") == uids  # nothing removed
    assert "\\Deleted" not in c.flags_of("INBOX", uids[0])
    assert "\\Deleted" not in c.flags_of("INBOX", uids[2])
    assert "\\Deleted" in c.flags_of("INBOX", uids[1])  # user's own flag preserved
    rem = next(w for w in c.writes if w[0] == "remove_flags")
    assert rem[2] == (uids[0], uids[2])
    assert "expunge" not in c.write_names()


def test_imap_move_copy_failure_sets_no_flags(eng):
    c = FakeIMAP(capabilities=GIGAHOST_CAPS)
    uids = inbox_with(c, 2)
    with pytest.raises(eng.MoveError) as ei:
        eng.imap_move(c, uids, "DoesNotExist", capabilities=GIGAHOST_CAPS)
    assert ei.value.copied is False
    assert c.write_names() == ["copy"]
    assert all("\\Deleted" not in c.flags_of("INBOX", u) for u in uids)


def test_imap_move_missing_uid_raises_before_copy(eng):
    c = FakeIMAP(capabilities=GIGAHOST_CAPS)
    inbox_with(c, 1)
    with pytest.raises(eng.MoveError):
        eng.imap_move(c, [99], "Junk", capabilities=GIGAHOST_CAPS)
    assert c.writes == []


def test_imap_move_unsupported(eng):
    c = FakeIMAP(capabilities=BARE_CAPS)
    uids = inbox_with(c, 1)
    with pytest.raises(eng.MoveUnsupported):
        eng.imap_move(c, uids, "Junk", capabilities=BARE_CAPS)
    assert c.writes == []
    eng.imap_move(c, [], "Junk", capabilities=BARE_CAPS)  # nothing to do


def test_imap_move_connection_error_propagates(eng):
    c = FakeIMAP(capabilities=SCANNET_CAPS)
    uids = inbox_with(c, 1)
    c.fail_on["move"] = IMAPClientAbortError("socket closed")
    with pytest.raises(IMAPClientAbortError):
        eng.imap_move(c, uids, "Junk", capabilities=SCANNET_CAPS)


def test_fake_uid_range_includes_highest_uid(eng):
    """Sanity check of the fake: `UID n:*` with n above the top UID still
    returns the top UID (RFC 3501) - the engine must filter it."""
    c = FakeIMAP()
    inbox_with(c, 3)
    assert c.search(["UID", "10:*"]) == [3]
    assert c.search(["UID", "2:*"]) == [2, 3]


# ----- exact Message-ID (A3) -----------------------------------------------


def test_find_uids_by_message_id_is_exact(eng):
    c = FakeIMAP()
    c.add("INBOX", make_message("abc@x"))
    u2 = c.add("INBOX", make_message("b@x"))
    c.add("INBOX", make_message("xb@x"))
    c.select_folder("INBOX", readonly=True)
    # SEARCH HEADER Message-ID b@x matches "b@x" AND "xb@x" (and "abc@x"? no).
    assert len(c.search(["HEADER", "Message-ID", "b@x"])) == 2
    assert eng.find_uids_by_message_id(c, "b@x") == [u2]
    assert eng.find_uids_by_message_id(c, "<b@x>") == [u2]
    assert eng.find_uids_by_message_id(c, "nope@x") == []


@pytest.mark.parametrize("bad", ['a"b@x', "a\r\nb@x", "æøå@x", "a b@x", "a\\b@x", ""])
def test_find_uids_rejects_unsafe_ids(eng, bad):
    c = FakeIMAP()
    c.select_folder("INBOX", readonly=True)
    assert eng.find_uids_by_message_id(c, bad) == []
    assert not any(call[0] == "search" for call in c.calls)


# ----- connect -------------------------------------------------------------


def test_connect_reads_capabilities_after_login(eng, monkeypatch, tmp_path):
    c = FakeIMAP(capabilities=GIGAHOST_CAPS)
    seen = {}

    def factory(host, port=993, ssl=True, ssl_context=None, timeout=None):
        seen.update(host=host, port=port, ssl=ssl, ctx=ssl_context, timeout=timeout)
        return c

    monkeypatch.setattr(eng, "IMAPClient", factory)
    acc = make_account(eng)
    client = eng.connect(acc, "pw")
    assert client is c
    names = [x[0] for x in c.calls]
    assert names.index("login") < names.index("capabilities")
    assert seen["ctx"] is not None and seen["timeout"] == eng.IMAP_TIMEOUT


def test_connect_closes_on_login_error(eng, monkeypatch):
    from imapclient.exceptions import LoginError

    c = FakeIMAP()
    c.fail_on["login"] = LoginError("bad credentials")
    monkeypatch.setattr(eng, "IMAPClient", lambda *a, **k: c)
    with pytest.raises(LoginError):
        eng.connect(make_account(eng), "pw")
    assert ("logout",) in c.calls


# ----- folders (E8) ----------------------------------------------------------


def test_setup_folders_creates_missing_junk_in_move_mode(eng, tmp_path):
    db = eng.Db("acct")
    c = FakeIMAP(folders=("INBOX", "Trash"))
    acc = make_account(eng, mode="move", junk="Spamfilter", junk_explicit=True)
    setup = eng.setup_folders(c, acc, LOG, db)
    assert setup.fmap["junk"] == "Spamfilter" and setup.junk_exists is True
    assert "Spamfilter" in c.folders and c.folders["Spamfilter"].subscribed
    assert c.write_names() == ["create_folder", "subscribe_folder"]
    ev = db.conn.execute("SELECT detail FROM events WHERE event='folder_created'").fetchall()
    assert [r[0] for r in ev] == ["Spamfilter"]
    # Second start: already there, nothing created.
    c.writes.clear()
    eng.setup_folders(c, acc, LOG, db)
    assert c.writes == []


def test_setup_folders_shadow_never_creates(eng):
    c = FakeIMAP(folders=("INBOX",))
    acc = make_account(eng, mode="shadow", training_folders=True)
    setup = eng.setup_folders(c, acc, LOG, None)
    assert setup.junk_exists is False and setup.trash_exists is False
    assert c.writes == []


def test_explicit_junk_wins_over_special_use(eng):
    c = FakeIMAP(capabilities=SCANNET_CAPS, folders=("INBOX", "Junk", "Spamfilter", "Trash"),
                 special_use={"Junk": "\\Junk", "Trash": "\\Trash"})
    acc = make_account(eng, mode="move", junk="Spamfilter", junk_explicit=True)
    assert eng.setup_folders(c, acc, LOG, None).fmap["junk"] == "Spamfilter"
    acc2 = make_account(eng, mode="move", junk="Junk", junk_explicit=False)
    c.folders["Junk"].flags = ("\\HasNoChildren",)
    c.add_folder("Uønsket", flags=("\\HasNoChildren", "\\Junk"))
    assert eng.setup_folders(c, acc2, LOG, None).fmap["junk"] == "Uønsket"


def test_training_folders_only_when_enabled(eng):
    c = FakeIMAP()
    acc = make_account(eng, mode="move", training_folders=False)
    eng.setup_folders(c, acc, LOG, None)
    assert c.writes == []
    acc.training_folders = True
    setup = eng.setup_folders(c, acc, LOG, None)
    assert setup.fmap["spam_train"] == "Junk.Train-Spam"
    created = [w[2] for w in c.writes if w[0] == "create_folder"]
    assert created == ["Junk.Train-Spam", "Junk.Trained-Spam", "Junk.Train-Ham", "Junk.Trained-Ham"]


def test_folder_status_listing_status_only_for_inbox_and_junk(eng):
    c = FakeIMAP(folders=("INBOX", "Junk", "Archive", "Trash"))
    c.add("INBOX", make_message("a@x"))
    c.add("Junk", make_message("b@x"))
    c.add("Junk", make_message("c@x"))
    setup = eng.setup_folders(c, make_account(eng, mode="shadow"), LOG, None)
    out = eng.folder_status_listing(c, setup.listing, ["INBOX", "Junk"])
    by = {f["name"]: f for f in out}
    assert by["INBOX"]["messages"] == 1 and by["Junk"]["messages"] == 2
    assert by["Archive"]["messages"] is None
    assert by["INBOX"]["flags"] == ["\\HasNoChildren"]
    assert [x[1] for x in c.calls if x[0] == "folder_status"] == ["INBOX", "Junk"]


def test_uidvalidity_reset_is_folder_specific(eng):
    db = eng.Db("acct")
    c = FakeIMAP()
    with db.tx():
        db.add_pending_move(1, 5, "a@x", folder="INBOX")
        db.add_pending_move(2, 6, "b@x", folder="Other")
        db.set_uidvalidity("INBOX", 1)
        db.set_scan_bookmark("INBOX", 1, 10)
        db.set_junk_bookmark("Junk", 3, 4)
    uv = eng.select_with_uidvalidity_check(c, db, "INBOX", LOG)
    assert uv == c.folders["INBOX"].uidvalidity
    rows = db.conn.execute("SELECT message_id FROM pending_move").fetchall()
    assert [r[0] for r in rows] == ["b@x"]
    assert db.get_scan_bookmark("INBOX", 1) is None
    assert db.get_junk_bookmark("Junk", 3) == 4
