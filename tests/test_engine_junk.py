"""ENGINE: header-only junk polling, user moves into junk, provider junk,
reconciliation and pending learns by exact Message-ID (SPEC E5, A2, A3)."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import make_message, setup_engine  # noqa: E402
from test_engine_scan import Harness  # noqa: E402

LOG = logging.getLogger("test")


@pytest.fixture
def eng(tmp_path, monkeypatch):
    return setup_engine(tmp_path, monkeypatch)


def body_fetches_in(h, folder):
    """FETCHes of full bodies while `folder` was selected."""
    out, sel = [], None
    for c in h.client.calls:
        if c[0] == "select_folder":
            sel = c[1]
        elif c[0] == "fetch" and sel == folder and any(i.startswith(b"BODY.PEEK[]") or i == b"BODY[]"
                                                        for i in c[2]):
            out.append(c)
    return out


def test_poll_junk_fingerprints_new_arrivals_with_bookmark(eng, monkeypatch):
    # 2.12 (#13): provider junk is scored afterwards in its own, bounded
    # read-only step (test_v212.py); the poll pass itself stays header-only.
    monkeypatch.setattr(eng, "PROVIDER_JUNK_SCORE_PER_RUN", 0)
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("p1@x", folder="Junk", sender="spam@bad.dk", return_path="bounce@bad.dk")
    h.deliver("p2@x", folder="Junk")
    h.poll()
    assert len(body_fetches_in(h, "Junk")) == 2  # new arrivals bound once; no learning
    fetches = [c for c in h.client.calls if c[0] == "fetch"]
    assert fetches and all(b"BODY.PEEK[HEADER.FIELDS (MESSAGE-ID FROM SUBJECT RETURN-PATH X-TH-SPAMFILTER)]" in c[2]
                           or c[2] in ((b"BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)]",), (b"BODY.PEEK[]",)) for c in fetches)
    uv = h.client.folders["Junk"].uidvalidity
    assert h.db.get_junk_bookmark("Junk", uv) == 2
    r = h.row("p1@x")
    assert r["our_action"] == "provider_junk" and r["origin"] == "junk_poll"
    assert r["sender"] == "spam@bad.dk" and r["envelope_from"] == "bounce@bad.dk"
    assert r["current_folder"] == "Junk" and r["user_verdict"] is None
    # Second poll: no new UIDs -> no per-message fetch of old ones.
    h.client.calls.clear()
    h.state.last_junk_reconcile = 1e12  # reconcile not due
    h.poll()
    assert not any(c[0] == "fetch" for c in h.client.calls)
    # Provider junk is never learned on its own.
    assert h.rspamd.learn_calls == []


def test_user_moves_inbox_to_junk_is_spam_verdict_and_learned(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", learn_grace_seconds=300)
    h.deliver("u@x", score=1)
    h.scan()
    assert h.row("u@x")["our_action"] == "none"
    h.user_moves("u@x", "INBOX", "Junk")
    h.poll()
    r = h.row("u@x")
    assert r["our_action"] == "user_junked" and r["user_verdict"] == "spam"
    assert r["pending_learn"] == "spam" and r["current_folder"] == "Junk"
    assert h.stat("user_junked") == 1
    assert h.rspamd.learn_calls == []          # grace not over
    h.advance(301)
    h.state.last_junk_reconcile = 1e12
    h.poll()
    assert len(h.rspamd.learn_calls) == 1
    call = h.rspamd.learn_calls[0]
    assert call["url"].endswith("/learnspam") and call["headers"]["Deliver-To"] == "hjemmeserver"
    r = h.row("u@x")
    assert r["learned_as"] == "spam" and r["pending_learn"] is None
    assert h.stat("learned_spam") == 1
    # The body was fetched exactly once, only for the due learn.
    assert 1 <= len(body_fetches_in(h, "Junk")) <= 3  # identity verification + learning
    # Later the same mail (sticky spam verdict) arriving again is spam.
    h.deliver("u@x", score=0)
    h.scan()
    assert h.row("u@x")["our_action"] == "pending_move"


def test_user_junk_without_learn_from_moves(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="flag", learn_from_moves=False)
    h.deliver("u@x", score=1)
    h.scan()
    h.user_moves("u@x", "INBOX", "Junk")
    h.poll()
    r = h.row("u@x")
    assert r["user_verdict"] == "spam" and r["pending_learn"] is None


def test_our_own_moves_are_not_user_verdicts(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("s@x", score=12)
    h.scan()
    h.advance(61)
    h.moves()
    h.poll()
    r = h.row("s@x")
    assert r["our_action"] == "moved_to_junk" and r["user_verdict"] is None
    assert r["pending_learn"] is None and h.stat("user_junked") == 0


def test_lost_move_bookkeeping_is_confirmed_by_poll(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("s@x", score=12)
    h.scan()
    h.user_moves("s@x", "INBOX", "Junk")  # as if our move landed but the reply was lost
    h.poll()
    r = h.row("s@x")
    assert r["our_action"] == "moved_to_junk" and r["user_verdict"] is None
    assert h.db.count_pending_moves() == 0


def test_reconcile_marks_gone_and_runs_every_6h(eng, monkeypatch):
    monkeypatch.setattr(eng, "PROVIDER_JUNK_SCORE_PER_RUN", 0)  # 2.12: provider junk scoring tested in test_v212.py
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("p1@x", folder="Junk")
    h.deliver("p2@x", folder="Junk")
    h.poll()
    assert h.state.last_junk_reconcile > 0
    h.client.folders["Junk"].msgs.pop(1)  # user deleted p1 from junk
    h.poll()                               # reconcile not due yet
    assert h.row("p1@x")["current_folder"] == "Junk"
    h.state.last_junk_reconcile -= eng.JUNK_RECONCILE_INTERVAL_S
    h.poll()
    assert h.row("p1@x")["current_folder"] == "gone"
    assert h.row("p2@x")["current_folder"] == "Junk"
    assert len(body_fetches_in(h, "Junk")) == 2  # new arrivals bound once; no learning


def test_pending_learn_oversize_is_never_fetched(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", learn_grace_seconds=0)
    h.client.add("INBOX", make_message("big@x"))
    h.rspamd.scores["big@x"] = 1
    h.scan()
    uid = h.user_moves("big@x", "INBOX", "Junk")
    h.client.folders["Junk"].msgs[uid].size = eng.MAX_FETCH_BYTES + 10
    h.poll()
    r = h.row("big@x")
    assert r["learned_as"] == "unlearnable" and r["pending_learn"] is None
    assert h.rspamd.learn_calls == [] and body_fetches_in(h, "Junk") == []
    assert h.events("learn_oversize")


def test_pending_learn_uses_exact_message_id(eng, monkeypatch):
    """`a@x` is a substring of `ba@x`: only the exact message is learned."""
    h = Harness(eng, monkeypatch, mode="move", learn_grace_seconds=0)
    h.deliver("a@x", score=1, body="the right one\r\n")
    h.scan()
    h.user_moves("a@x", "INBOX", "Junk")
    h.deliver("ba@x", folder="Junk", body="the wrong one\r\n")
    h.poll()
    assert len(h.rspamd.learn_calls) == 1
    assert b"the right one" in h.rspamd.learn_calls[0]["data"]


def test_pending_learn_lost_when_message_vanished(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", learn_grace_seconds=300)
    h.deliver("v@x", score=1)
    h.scan()
    h.user_moves("v@x", "INBOX", "Junk")
    h.poll()
    h.client.folders["Junk"].msgs.clear()
    h.advance(301)
    h.state.last_junk_reconcile = 1e12
    h.poll()
    assert h.row("v@x")["pending_learn"] is None and h.events("pending_lost")
    assert h.rspamd.learn_calls == []


def test_rescue_learn_ham_after_grace(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", learn_grace_seconds=300)
    h.deliver("r@x", score=12)
    h.scan()
    h.advance(61)
    h.moves()
    h.user_moves("r@x", "Junk", "INBOX")
    h.scan()
    h.advance(301)
    h.poll()
    assert [c["url"].rsplit("/", 1)[1] for c in h.rspamd.learn_calls] == ["learnham"]
    assert h.row("r@x")["learned_as"] == "ham" and h.stat("learned_ham") == 1


def test_unsearchable_message_id_marked_unlearnable(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", learn_grace_seconds=0)
    h.state.last_junk_reconcile = 1e12
    with h.db.tx():
        h.db.upsert_message('we"ird@x', "Junk", "s", "x")
        h.db.update_message('we"ird@x', pending_learn="spam", pending_learn_at=0)
    h.poll()
    assert h.row('we"ird@x')["learned_as"] == "unlearnable"
    assert not any(c[0] == "search" and "HEADER" in c[1] for c in h.client.calls)


def test_junk_poll_error_isolated_per_message(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("a@x", folder="Junk")
    h.deliver("b@x", folder="Junk")
    real = eng._junk_message_seen

    def flaky(db, log, acc, fmap, uid, data, *rest, **kw):
        if uid == 1:
            raise RuntimeError("bad header")
        return real(db, log, acc, fmap, uid, data, *rest, **kw)

    monkeypatch.setattr(eng, "_junk_message_seen", flaky)
    h.poll()
    assert h.row("b@x") is not None and h.events("junk_poll_error")


def test_learn_message_rate_limit_and_flipflop(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="flag", max_learns_per_hour=1)
    with h.db.tx():
        for m in ("a@x", "b@x"):
            h.db.upsert_message(m, "INBOX", "s", "x")
    assert eng.learn_message(h.db, h.acc, b"raw", "spam", "a@x", actor="admin") == "learned"
    assert eng.learn_message(h.db, h.acc, b"raw", "spam", "b@x") == "rate_limited"
    assert eng.learn_message(h.db, h.acc, b"raw", "spam", "b@x", bypass_rate=True,
                             reason="bootstrap") == "learned"
    assert eng.learn_message(h.db, h.acc, b"raw", "spam", "a@x") == "already"
    assert eng.learn_message(h.db, h.acc, b"raw", "ham", "a@x", bypass_rate=True) == "rate_limited"
    h.advance(eng.FLIP_FLOP_COOLDOWN_S + 1)
    assert eng.learn_message(h.db, h.acc, b"raw", "ham", "a@x", bypass_rate=True) == "learned"
    # Shadow accounts may still learn from explicit WebUI/trainer requests.
    h.acc.mode = "shadow"
    assert eng.learn_message(h.db, h.acc, b"raw", "spam", None, bypass_rate=True) == "learned"
    assert h.stat("learned_spam") == 3 and h.stat("learned_ham") == 1
    assert len(h.rspamd.learn_calls) == 4


# ----- separate filter folder ("Spamfilter") + the provider's own Junk ----------


def spamfilter_harness(eng, monkeypatch, **over):
    return Harness(eng, monkeypatch, mode="move", folders=("INBOX", "Junk", "Trash"),
                   junk="Spamfilter", junk_explicit=True, **over)


def test_provider_junk_folder_is_watched_read_only(eng, monkeypatch):
    h = spamfilter_harness(eng, monkeypatch)
    assert h.acc.folder_map["junk"] == "Spamfilter"
    assert h.acc.folder_map["provider_junk"] == "Junk"
    h.client.writes.clear()
    h.deliver("p@x", folder="Junk", score=20)
    h.poll()
    r = h.row("p@x")
    assert r["our_action"] == "provider_junk" and r["current_folder"] == "Junk"
    assert h.client.writes == []
    assert all(c[2] is True for c in h.client.calls if c[0] == "select_folder" and c[1] == "Junk")


@pytest.mark.parametrize("seen", [False, True])
def test_rescue_from_provider_junk_with_separate_filter_folder(eng, monkeypatch, seen):
    monkeypatch.setattr(eng, "PROVIDER_JUNK_SCORE_PER_RUN", 0)  # 2.12: provider junk scoring tested in test_v212.py
    h = spamfilter_harness(eng, monkeypatch)
    h.deliver("p@x", folder="Junk", score=20,
              extra_headers="X-Spam: Yes")
    h.poll()
    h.user_moves("p@x", "Junk", "INBOX", flags=("\\Seen",) if seen else ())
    h.scan()
    h.advance(120)
    h.moves()
    assert h.client.msgids("INBOX") == ["p@x"] and h.client.msgids("Spamfilter") == []
    r = h.row("p@x")
    assert r["our_action"] == "user_rescued" and r["user_verdict"] == "ham"
    assert h.rspamd.scan_calls == []


def test_user_moves_into_provider_junk_is_learned(eng, monkeypatch):
    h = spamfilter_harness(eng, monkeypatch, learn_grace_seconds=0)
    h.deliver("u@x", score=1)
    h.scan()
    h.user_moves("u@x", "INBOX", "Junk")
    h.poll()
    r = h.row("u@x")
    assert r["user_verdict"] == "spam" and r["learned_as"] == "spam"
    assert len(h.rspamd.learn_calls) == 1


def test_missing_filter_folder_still_polls_provider_junk(eng, monkeypatch):
    h = spamfilter_harness(eng, monkeypatch)
    del h.client.folders["Spamfilter"]
    h.deliver("p@x", folder="Junk")
    h.loop()
    assert h.state.junk_exists is False
    assert h.row("p@x")["our_action"] == "provider_junk"


# ----- E12 retention -------------------------------------------------------------


def _old(h, folder, msgid):
    import datetime as dt

    return h.client.add(folder, make_message(msgid),
                        internaldate=dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc))


def test_retention_disabled_by_default(eng, monkeypatch):
    assert eng.AUTOMATIC_RETENTION_ENABLED is False
    h = Harness(eng, monkeypatch, mode="move")
    _old(h, "Junk", "old@x")
    h.client.writes.clear()
    eng._housekeeping(h.client, h.db, LOG, h.acc, h.state)
    assert h.client.msgids("Junk") == ["old@x"] and h.client.writes == []


def test_retention_gate_is_per_folder_and_spares_trained_ham(eng, monkeypatch):
    monkeypatch.setattr(eng, "AUTOMATIC_RETENTION_ENABLED", True)
    h = Harness(eng, monkeypatch, mode="move", training_folders=True,
                junk_retention_days=0, trained_retention_days=7)
    fm = h.acc.folder_map
    _old(h, "Junk", "junk-old@x")
    _old(h, fm["trained_spam"], "ts-old@x")
    _old(h, fm["trained_ham"], "th-old@x")
    eng._housekeeping(h.client, h.db, LOG, h.acc, h.state)
    assert h.client.msgids("Junk") == ["junk-old@x"]          # junk_retention_days = 0
    assert h.client.msgids(fm["trained_spam"]) == []
    assert h.client.msgids(fm["trained_ham"]) == ["th-old@x"]  # never swept
    assert h.client.msgids("Trash") == ["ts-old@x"]
    assert "expunge" not in h.client.write_names()


def test_retention_skips_learned_ham_in_junk(eng, monkeypatch):
    monkeypatch.setattr(eng, "AUTOMATIC_RETENTION_ENABLED", True)
    h = Harness(eng, monkeypatch, mode="move", junk_retention_days=3)
    _old(h, "Junk", "a@x")
    _old(h, "Junk", "keep@x")
    with h.db.tx():
        h.db.upsert_message("keep@x", "Junk", "s", "x")
        h.db.update_message("keep@x", user_verdict="ham")
    eng._housekeeping(h.client, h.db, LOG, h.acc, h.state)
    assert h.client.msgids("Junk") == ["keep@x"] and h.client.msgids("Trash") == ["a@x"]
