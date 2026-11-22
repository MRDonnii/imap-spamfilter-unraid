"""Tests for the rspamd learn path.

Covers three behaviours that together stop a permanently-unlearnable
message from looping `learn_failed` events every poll cycle:

  * rspamd_learn classifies the controller's reply (learned / already /
    declined / error) instead of collapsing it to a bool;
  * try_learn treats a deterministic decline as terminal;
  * process_pending_learns caps retries of a transient error.

Run: STATE_DIR=/tmp/x python -m pytest test_learn.py
"""

import logging
import os
import sqlite3
import tempfile
import time

os.environ.setdefault("STATE_DIR", tempfile.mkdtemp(prefix="sf_test_"))

import filter as f  # noqa: E402

LOG = logging.getLogger("test")


# ----- helpers --------------------------------------------------------------


def _mk_db(tmp_path):
    """Fresh Db backed by a temp SQLite file with the real schema."""
    db_path = tmp_path / "spamfilter.db"
    f.DB_PATH = db_path  # Db.__init__ reads this module global
    with sqlite3.connect(db_path) as conn:
        conn.executescript(f.SCHEMA)
    return f.Db("acct")


def _mk_account(**over):
    base = dict(
        name="acct", user="u@example.com", password="x",
        imap_host="h", imap_port=993, ssl=True,
        inbox="INBOX", junk="Junk", trash="Trash",
        spam_train="Junk/Train-Spam", trained_spam="Junk/Trained-Spam",
        ham_train="Junk/Train-Ham", trained_ham="Junk/Trained-Ham",
        mode="flag", threshold=8.0, min_threshold_allowed=5.0,
        reject_score_above=100.0,
        move_grace_seconds=60, learn_grace_seconds=300, idle_timeout=1500,
        poll_interval=600, junk_poll_interval=120,
        retention_check_interval=3600,
        max_moves_per_hour=30, max_learns_per_hour=50, max_train_per_run=100,
        safe_mode_unseen_cap=500,
        junk_retention_days=10, trained_retention_days=7,
        learn_from_moves=True, auto_special_folders=True,
    )
    base.update(over)
    return f.Account(**base)


def _pending(db, msgid, folder, kind, at):
    with db.tx():
        db.upsert_message(msgid, folder, "s@example.com", "subj")
        db.update_message(msgid, pending_learn=kind, pending_learn_at=at)


def _events(db):
    return [r["event"] for r in db.conn.execute("SELECT event FROM events")]


class _FakeResp:
    def __init__(self, status_code, text=""):
        self.status_code = status_code
        self.text = text


class _FakeIMAP:
    """Minimal IMAPClient stand-in for process_pending_learns. SEARCH
    HEADER is a substring match like on a real server; the engine must
    verify candidates via the fetched Message-ID header (SPEC A3)."""

    def __init__(self, raw_by_msgid):
        self._raw = dict(raw_by_msgid)
        self._uid = {m: i + 1 for i, m in enumerate(self._raw)}
        self.calls = []

    def select_folder(self, folder, **kw):
        self.calls.append(("select_folder", folder))
        return {}

    def search(self, criteria):
        self.calls.append(("search", tuple(criteria)))
        if criteria and criteria[0] == "HEADER":
            needle = criteria[2]
            return [self._uid[m] for m in self._raw if needle in m]
        return []

    def fetch(self, uids, parts):
        self.calls.append(("fetch", tuple(uids), tuple(parts)))
        out = {}
        for u in uids:
            mid = next(m for m, uu in self._uid.items() if uu == u)
            raw = f"Message-ID: <{mid}>\r\nSubject: x\r\n\r\n".encode() + self._raw[mid]
            out[u] = {
                b"BODY[]": raw,
                b"RFC822.SIZE": len(raw),
                b"BODY[HEADER.FIELDS (MESSAGE-ID)]": f"Message-ID: <{mid}>\r\n\r\n".encode(),
            }
        return out


# ----- rspamd_learn: classify the controller reply --------------------------


def test_rspamd_learn_200_is_learned(monkeypatch):
    monkeypatch.setattr(f.requests, "post",
                        lambda *a, **k: _FakeResp(200, '{"success":true}'))
    assert f.rspamd_learn(b"raw", "ham", user="u") == "learned"


def test_rspamd_learn_208_is_already(monkeypatch):
    monkeypatch.setattr(f.requests, "post",
                        lambda *a, **k: _FakeResp(208, '{"error":"already learned"}'))
    assert f.rspamd_learn(b"raw", "ham", user="u") == "already"


def test_rspamd_learn_204_is_declined(monkeypatch):
    # 204: request processed, nothing learned (too few tokens, or already
    # in that class). Retrying the identical bytes is always futile.
    monkeypatch.setattr(f.requests, "post", lambda *a, **k: _FakeResp(204, ""))
    assert f.rspamd_learn(b"raw", "ham", user="u") == "declined"


def test_rspamd_learn_5xx_is_error(monkeypatch):
    monkeypatch.setattr(f.requests, "post", lambda *a, **k: _FakeResp(503, "busy"))
    assert f.rspamd_learn(b"raw", "ham", user="u") == "error"


def test_rspamd_learn_4xx_is_error(monkeypatch):
    # An auth/config 4xx must stay retryable - not be mistaken for a
    # per-message decline that would mark the message unlearnable.
    monkeypatch.setattr(f.requests, "post", lambda *a, **k: _FakeResp(403, "forbidden"))
    assert f.rspamd_learn(b"raw", "ham", user="u") == "error"


def test_rspamd_learn_network_exception_is_error(monkeypatch):
    def boom(*a, **k):
        raise f.requests.RequestException("connection refused")

    monkeypatch.setattr(f.requests, "post", boom)
    assert f.rspamd_learn(b"raw", "ham", user="u") == "error"


# ----- try_learn: act on the classified outcome -----------------------------


def test_try_learn_declined_is_terminal(tmp_path, monkeypatch):
    db = _mk_db(tmp_path)
    acc = _mk_account()
    _pending(db, "m1", "Junk", "ham", int(time.time()))
    monkeypatch.setattr(f, "rspamd_learn", lambda *a, **k: "declined")

    ok = f.try_learn(db, LOG, acc, b"raw", "m1", "ham", reason="x")

    assert ok is True  # caller still moves the message out
    row = db.get_message("m1")
    assert row["pending_learn"] is None  # never retried
    # rspamd's decline means "already in that class": recorded as that class,
    # not 'unlearnable' (which blocked the opposite learn for 30 days).
    assert row["learned_as"] == "ham"
    evs = _events(db)
    assert "learn_skipped" in evs
    assert "learn_failed" not in evs  # dashboard banner stays clean


def test_declined_learn_does_not_block_the_opposite_learn(tmp_path, monkeypatch):
    """'Det er spam' declined by rspamd, then Frigiv: the ham learn is POSTed."""
    db = _mk_db(tmp_path)
    acc = _mk_account()
    _pending(db, "m2", "INBOX", "spam", int(time.time()))
    calls = []

    def fake(raw, kind, *a, **k):
        calls.append(kind)
        return "declined" if kind == "spam" else "learned"

    monkeypatch.setattr(f, "rspamd_learn", fake)
    assert f.learn_message(db, acc, b"raw", "spam", "m2", bypass_rate=True) == "declined"
    assert f.learn_message(db, acc, b"raw", "spam", "m2", bypass_rate=True) == "already"  # no new POST
    monkeypatch.setattr(f, "FLIP_FLOP_COOLDOWN_S", 0)
    assert f.learn_message(db, acc, b"raw", "ham", "m2", bypass_rate=True) == "learned"
    assert calls == ["spam", "ham"]
    assert db.get_message("m2")["learned_as"] == "ham"


def test_try_learn_error_keeps_pending_for_retry(tmp_path, monkeypatch):
    db = _mk_db(tmp_path)
    acc = _mk_account()
    _pending(db, "m2", "Junk", "ham", int(time.time()))
    monkeypatch.setattr(f, "rspamd_learn", lambda *a, **k: "error")

    ok = f.try_learn(db, LOG, acc, b"raw", "m2", "ham", reason="x")

    assert ok is False
    row = db.get_message("m2")
    assert row["pending_learn"] == "ham"  # still queued
    assert row["learned_as"] is None
    assert "learn_failed" in _events(db)


def test_try_learn_learned_records_success(tmp_path, monkeypatch):
    db = _mk_db(tmp_path)
    acc = _mk_account()
    _pending(db, "m3", "Junk", "ham", int(time.time()))
    monkeypatch.setattr(f, "rspamd_learn", lambda *a, **k: "learned")

    ok = f.try_learn(db, LOG, acc, b"raw", "m3", "ham", reason="x")

    assert ok is True
    row = db.get_message("m3")
    assert row["learned_as"] == "ham"
    assert row["pending_learn"] is None
    assert "learn_ham" in _events(db)


def test_try_learn_already_records_success(tmp_path, monkeypatch):
    db = _mk_db(tmp_path)
    acc = _mk_account()
    _pending(db, "m4", "Junk", "ham", int(time.time()))
    monkeypatch.setattr(f, "rspamd_learn", lambda *a, **k: "already")

    ok = f.try_learn(db, LOG, acc, b"raw", "m4", "ham", reason="x")

    assert ok is True
    row = db.get_message("m4")
    assert row["learned_as"] == "ham"
    assert row["pending_learn"] is None


# ----- process_pending_learns: cap retries of a transient error -------------


def test_process_pending_learns_caps_repeated_errors(tmp_path, monkeypatch):
    db = _mk_db(tmp_path)
    acc = _mk_account(learn_grace_seconds=0)
    _pending(db, "loop1", "INBOX", "ham", int(time.time()) - 10)
    monkeypatch.setattr(f, "rspamd_learn", lambda *a, **k: "error")
    client = _FakeIMAP({"loop1": b"raw-bytes"})
    fmap = {"junk": "Junk", "inbox": "INBOX"}

    for _ in range(8):  # far more polls than the cap
        f.process_pending_learns(client, db, LOG, acc, fmap)

    fails = sum(e == "learn_failed" for e in _events(db))
    giveups = sum(e == "learn_giveup" for e in _events(db))
    assert fails <= 3, f"retry cap breached: {fails} learn_failed events"
    assert giveups == 1
    assert db.get_message("loop1")["pending_learn"] is None


def test_process_pending_learns_uses_exact_message_id(tmp_path, monkeypatch):
    # "m1" is a substring of "m10": SEARCH HEADER returns both, only the
    # exact Message-ID may be learned (SPEC A3).
    db = _mk_db(tmp_path)
    acc = _mk_account(learn_grace_seconds=0)
    _pending(db, "m1", "INBOX", "ham", int(time.time()) - 10)
    learned = []
    monkeypatch.setattr(f, "rspamd_learn",
                        lambda raw, kind, ident=None, **k: learned.append(raw) or "learned")
    client = _FakeIMAP({"m10": b"other", "m1": b"mine"})

    f.process_pending_learns(client, db, LOG, acc, {"junk": "Junk", "inbox": "INBOX"})

    assert len(learned) == 1 and learned[0].endswith(b"mine")
    assert db.get_message("m1")["learned_as"] == "ham"


# ----- shadow mode never learns ----------------------------------------------


def test_shadow_never_learns(tmp_path, monkeypatch):
    db = _mk_db(tmp_path)
    acc = _mk_account(mode="shadow", learn_grace_seconds=0)
    _pending(db, "s1", "INBOX", "ham", int(time.time()) - 10)
    _pending(db, "s2", "Junk", "spam", int(time.time()) - 10)
    calls = []
    monkeypatch.setattr(f, "rspamd_learn", lambda *a, **k: calls.append(a) or "learned")
    client = _FakeIMAP({"s1": b"a", "s2": b"b"})

    assert f.try_learn(db, LOG, acc, b"raw", "s1", "ham", reason="x") is False
    f.process_pending_learns(client, db, LOG, acc, {"junk": "Junk", "inbox": "INBOX"})

    assert calls == []          # no POST to rspamd at all
    assert client.calls == []   # not even an IMAP SELECT
    assert db.get_message("s1")["learned_as"] is None
    assert db.get_message("s2")["pending_learn"] == "spam"
