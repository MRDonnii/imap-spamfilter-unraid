"""ENGINE 2.7 fix: antivirus re-scans for CLAM_VIRUS_FAIL.

A mail (2.12: also text-only) that was scanned while ClamAV did not answer
(CLAM_VIRUS_FAIL) is scanned again by UID at +10 min, +1 h and +6 h -
independent of zap and its exclusions (zap off, known contacts, replies,
allow rules). Only a new CLAM_VIRUS (threat class virus) acts: then the
normal virus handling (to Spamfilter, threat event / notice). A clean
result or a heuristic hit changes nothing; nothing is ever deleted."""

from __future__ import annotations

import datetime as dt
import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import setup_engine  # noqa: E402
from test_engine_contacts import DMARC_OK, run_sync, sent_mail  # noqa: E402
from test_engine_scan import Harness  # noqa: E402
from test_engine_threat import mail_with_attachments  # noqa: E402

LOG = logging.getLogger("test-avrescan")
MIN = 60
FAIL = {"CLAM_VIRUS_FAIL": {"name": "CLAM_VIRUS_FAIL", "score": 0.0, "options": ["failed to scan"]}}
VIRUS = {"CLAM_VIRUS": {"name": "CLAM_VIRUS", "score": 0.0, "options": ["Win.Trojan.Agent-123"]}}
HEUR = {"CLAM_VIRUS": {"name": "CLAM_VIRUS", "score": 0.0, "options": ["Heuristics.Phishing.Email.SpoofedDomain"]}}


@pytest.fixture
def eng(tmp_path, monkeypatch):
    e = setup_engine(tmp_path, monkeypatch)
    import contacts

    contacts.forget_cached_keys()
    yield e
    contacts.forget_cached_keys()


def deliver(h, msgid, *, symbols=FAIL, score=0.5, attach=True, sender="a@example.org", flags=()):
    h.rspamd.scores[msgid] = score
    h.rspamd.symbols[msgid] = dict(symbols)
    if attach:
        raw = mail_with_attachments(msgid, [("faktura.pdf", b"%PDF-1.4 x")], sender=sender)
    else:
        from fakes_engine import make_message

        raw = make_message(msgid, sender=sender)
    h.client.add("INBOX", raw, flags=flags, internaldate=dt.datetime.fromtimestamp(h.t, dt.timezone.utc))
    h.scan()
    return h.row(msgid)


def avq(h):
    return {r["message_id"]: r for r in h.db.conn.execute("SELECT * FROM av_rescan_queue")}


def av(h):
    return h.eng.av_rescan_pass(h.client, h.db, LOG, h.acc, h.acc.folder_map, h.state)


def events(h, name):
    return [e for e in h.events(name)]


def test_queued_for_every_fail_also_text_only(eng, monkeypatch):
    # 2.12 (#21): ClamAV reads the text parts too (2.8, Sanesecurity), so a
    # text-only mail scanned while it did not answer is queued as well.
    h = Harness(eng, monkeypatch, threshold=6.0, zap=False)
    deliver(h, "f1@x")
    deliver(h, "f2@x", attach=False)
    deliver(h, "ok@x", symbols={})
    deliver(h, "sp@x", score=9.0)                                 # already spam: moved anyway
    q = avq(h)
    assert set(q) == {"f1@x", "f2@x"}
    r = q["f1@x"]
    assert r["folder"] == "INBOX" and r["attempt"] == 0 and r["due_at"] == r["queued_at"] + 10 * MIN


def test_new_virus_moves_the_mail_and_raises_the_threat(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=6.0, zap=False)
    deliver(h, "v@x")
    assert "v@x" in avq(h)
    h.advance(5 * MIN)
    assert av(h) == 0                                             # not due yet
    h.advance(6 * MIN)
    h.rspamd.symbols["v@x"] = dict(VIRUS)                         # ClamAV is back and knows it
    assert av(h) == 1
    row = h.row("v@x")
    assert row["threat"] == "virus" and row["threat_detail"] == "Win.Trojan.Agent-123"
    assert row["our_action"] == "pending_move" and not avq(h)
    assert any(e[1] == "v@x" and "genscanning" in (e[2] or "") for e in events(h, "threat_detected"))
    pm = h.db.conn.execute("SELECT origin FROM pending_move WHERE message_id='v@x'").fetchone()
    assert pm["origin"] == "zap"
    h.advance(60)
    h.moves()
    assert "v@x" in h.client.msgids("Junk")
    assert h.db.conn.execute("SELECT COUNT(*) FROM threat_notices WHERE message_id='v@x'").fetchone()[0] == 1


def test_still_failing_retries_10min_1h_6h_then_gives_up(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=6.0)
    deliver(h, "r@x")
    q0 = avq(h)["r@x"]["queued_at"]
    h.advance(10 * MIN)
    av(h)
    assert avq(h)["r@x"]["attempt"] == 1 and avq(h)["r@x"]["due_at"] == q0 + 3600
    h.advance(50 * MIN)
    av(h)
    assert avq(h)["r@x"]["attempt"] == 2 and avq(h)["r@x"]["due_at"] == q0 + 6 * 3600
    h.advance(5 * 3600)
    av(h)
    assert not avq(h)
    assert any(e[1] == "r@x" and "opgivet" in (e[2] or "") for e in events(h, "av_rescan_skipped"))
    assert h.row("r@x")["our_action"] == "none"


@pytest.mark.parametrize("symbols", [{}, HEUR])
def test_clean_or_heuristic_result_changes_nothing(eng, monkeypatch, symbols):
    h = Harness(eng, monkeypatch, threshold=6.0)
    deliver(h, "c@x")
    before = h.row("c@x")
    h.advance(11 * MIN)
    h.rspamd.symbols["c@x"] = dict(symbols)
    h.rspamd.scores["c@x"] = 3.0
    av(h)
    after = h.row("c@x")
    assert not avq(h) and after["our_action"] == "none" and after["threat"] is None
    assert after["our_score"] == before["our_score"]
    assert events(h, "av_rescan_clean")


def test_independent_of_zap_exclusions(eng, monkeypatch):
    # A known contact under an allow rule with zap switched off: still re-scanned for viruses.
    h = Harness(eng, monkeypatch, folders=("INBOX", "Junk", "Trash", "Sent"), threshold=6.0, zap=False)
    h.client.add("Sent", sent_mail("s1@x", "alice@kunde.dk"))
    run_sync(h)
    eng.add_sender_rule(h.db.conn, "acct", "alice@kunde.dk", "allow")
    deliver(h, "kc@x", symbols={**FAIL, **DMARC_OK}, sender="alice@kunde.dk")
    assert "kc@x" in avq(h)
    assert not h.db.conn.execute("SELECT 1 FROM rescan_queue WHERE message_id='kc@x'").fetchone()
    h.advance(11 * MIN)
    h.rspamd.symbols["kc@x"] = {**VIRUS, **DMARC_OK}
    av(h)
    assert h.row("kc@x")["threat"] == "virus" and h.row("kc@x")["our_action"] == "pending_move"


def test_user_verdict_and_moved_mail_are_dropped(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=6.0)
    deliver(h, "u@x")
    with h.db.tx():
        h.db.update_message("u@x", user_verdict="ham")
    deliver(h, "gone@x")
    h.user_moves("gone@x", "INBOX", "Trash")
    h.advance(11 * MIN)
    h.rspamd.symbols["u@x"] = dict(VIRUS)
    h.rspamd.symbols["gone@x"] = dict(VIRUS)
    av(h)
    assert not avq(h)
    assert h.row("u@x")["threat"] is None                          # sticky ham: the user's call
    assert h.row("gone@x")["our_action"] == "none"


def test_shadow_accounts_only_record(eng, monkeypatch):
    # Overvåg (shadow): only recorded, never moved.
    h2 = Harness(eng, monkeypatch, threshold=6.0, mode="shadow")
    deliver(h2, "sh@x")
    h2.advance(11 * MIN)
    h2.rspamd.symbols["sh@x"] = dict(VIRUS)
    av(h2)
    row = h2.row("sh@x")
    assert row["our_action"] == "shadow_spam" and row["threat"] == "virus"
    assert not h2.db.conn.execute("SELECT 1 FROM pending_move").fetchone()


def test_uid_reuse_after_a_new_uidvalidity_is_dropped(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=6.0)
    deliver(h, "uv@x")
    with h.db.tx():
        h.db.conn.execute("UPDATE av_rescan_queue SET uidvalidity=uidvalidity+1")
    h.advance(11 * MIN)
    h.rspamd.symbols["uv@x"] = dict(VIRUS)
    av(h)
    assert not avq(h) and h.row("uv@x")["threat"] is None


def test_loop_wait_includes_the_next_antivirus_rescan(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=6.0, zap=False)
    deliver(h, "w@x")
    wait = eng._next_wake_in(h.db, h.acc, h.state)
    assert wait <= 10 * MIN + 1
