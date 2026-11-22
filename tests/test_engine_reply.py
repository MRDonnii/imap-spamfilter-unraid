"""2.3 "Svar på din mail" (B11): TH_REPLY / TH_REPLY_THREAD /
TH_REPLY_UNVERIFIED, binding to the thread's recipient domains, not
cumulative with TH_KNOWN_CONTACT, freshness (incremental Sent sync during
the scan and again in execute_due_moves within the grace period)."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_engine_contacts import (  # noqa: E402,F401
    DMARC_OK, C, LOG, dkim, eng, harness, inbound, run_sync, sent_mail, syms_of,
)


def synced(eng, monkeypatch, sent, **acc):
    h = harness(eng, monkeypatch, sent=sent, **acc)
    run_sync(h)
    return h


def irt(mid):
    return f"In-Reply-To: <{mid}>\r\nReferences: <older@kunde.dk> <{mid}>"


def test_reply_to_own_mail_is_strongest_and_not_cumulative(eng, monkeypatch, C):
    h = synced(eng, monkeypatch, [sent_mail("tilbud1@example-a.dk", "kunde@kunde.dk",
                                            date="Mon, 12 Oct 2026 09:00:00 +0200")])
    r = inbound(h, "re1@x", "kunde@kunde.dk", score=11.0, symbols=DMARC_OK, extra=irt("tilbud1@example-a.dk"))
    s = syms_of(h, "re1@x")
    assert s["TH_REPLY"]["s"] == -5.0 and s["TH_REPLY"]["o"] == ["k…@kunde.dk", "sendt=2026-10-12"]
    assert "TH_KNOWN_CONTACT" not in s  # the largest bonus wins, never both
    assert r["our_score"] == pytest.approx(6.0) and r["our_action"] == "none"
    assert h.stat("reply_detected") == 1 and h.stat("known_contact") == 0


def test_new_customer_reply_and_colleague_in_the_thread(eng, monkeypatch, C):
    h = synced(eng, monkeypatch, [sent_mail("q1@example-a.dk", "info@kunde.dk")])
    # Another person at the same company answers: their domain was a recipient.
    inbound(h, "re2@x", "salg@kunde.dk", symbols=DMARC_OK, extra=irt("q1@example-a.dk"))
    assert syms_of(h, "re2@x")["TH_REPLY"]["s"] == -5.0
    # Someone from another company joined the thread: only -2.
    inbound(h, "re3@x", "revisor@andet.dk", symbols=dkim("andet.dk"), extra=irt("q1@example-a.dk"))
    s = syms_of(h, "re3@x")
    assert s["TH_REPLY_THREAD"]["s"] == -2.0 and "TH_REPLY" not in s
    # A reply never makes the sender a contact - only own sent mail does.
    masks = {r[0] for r in h.db.conn.execute("SELECT mask FROM known_contacts")}
    assert masks == {"i…@kunde.dk"}


def test_reply_without_authentication_is_only_informative(eng, monkeypatch, C):
    h = synced(eng, monkeypatch, [sent_mail("q1@example-a.dk", "info@kunde.dk")])
    r = inbound(h, "re4@x", "info@kunde.dk", score=9.0, symbols={}, extra=irt("q1@example-a.dk"))
    s = syms_of(h, "re4@x")
    assert s["TH_REPLY_UNVERIFIED"]["s"] == 0.0
    assert not set(s) & {"TH_REPLY", "TH_REPLY_THREAD", "TH_KNOWN_CONTACT", "TH_FIRST_CONTACT"}
    assert r["our_score"] == pytest.approx(9.0) and r["our_action"] == "pending_move"


def test_only_the_last_ten_references_count(eng, monkeypatch, C):
    h = synced(eng, monkeypatch, [sent_mail("first@example-a.dk", "info@kunde.dk")])
    refs = " ".join(["<first@example-a.dk>"] + [f"<r{i}@kunde.dk>" for i in range(11)])
    inbound(h, "re5@x", "salg@kunde.dk", symbols=DMARC_OK, extra=f"References: {refs}")
    assert "TH_REPLY" not in syms_of(h, "re5@x")


def test_freshness_sync_during_the_scan_keeps_a_fresh_reply(eng, monkeypatch, C):
    h = synced(eng, monkeypatch, [sent_mail("old@example-a.dk", "a@b.dk")])
    # The user just sent an offer; the 15-minute STATUS has not seen it yet.
    h.client.add("Sent", sent_mail("offer@example-a.dk", "ny.kunde@kunde.dk"))
    h.rspamd.scores["re6@x"] = 12.0
    h.rspamd.symbols["re6@x"] = DMARC_OK
    h.deliver("re6@x", sender="ny.kunde@kunde.dk", extra_headers=irt("offer@example-a.dk"))
    h.deliver("spam@x", score=12.0, sender="x@spam.example")
    h.scan()
    r = h.row("re6@x")
    assert syms_of(h, "re6@x")["TH_REPLY"]["s"] == -5.0 and r["our_action"] == "none"
    assert h.row("spam@x")["our_action"] == "pending_move"
    # The inbox was re-selected before the next mail of the batch was used.
    sel = [c for c in h.client.calls if c[0] == "select_folder"]
    assert sel[-1][1] == "INBOX"
    h.advance(61)
    h.moves()
    assert h.client.msgids("Junk") == ["spam@x"] and "re6@x" in h.client.msgids("INBOX")


def test_freshness_is_rate_limited(eng, monkeypatch, C):
    h = synced(eng, monkeypatch, [sent_mail("old@example-a.dk", "a@b.dk")])
    h.state.contacts_last_fresh = time.monotonic()
    h.client.add("Sent", sent_mail("offer@example-a.dk", "ny.kunde@kunde.dk"))
    n_status = sum(1 for c in h.client.calls if c[0] == "folder_status" and c[1] == "Sent")
    r = inbound(h, "re7@x", "ny.kunde@kunde.dk", score=12.0, symbols=DMARC_OK, extra=irt("offer@example-a.dk"))
    assert "TH_REPLY" not in syms_of(h, "re7@x") and r["our_action"] == "pending_move"
    assert sum(1 for c in h.client.calls if c[0] == "folder_status" and c[1] == "Sent") == n_status


def test_execute_due_moves_rechecks_within_the_grace_period(eng, monkeypatch, C):
    h = synced(eng, monkeypatch, [sent_mail("old@example-a.dk", "a@b.dk")])
    h.state.contacts_last_fresh = time.monotonic()  # no freshness sync during the scan
    r = inbound(h, "re8@x", "ny.kunde@kunde.dk", score=9.0, symbols=DMARC_OK, extra=irt("offer@example-a.dk"))
    assert r["our_action"] == "pending_move"
    assert h.db.conn.execute("SELECT COUNT(*) FROM contact_recheck").fetchone()[0] == 1
    # The sent mail reaches the Sent folder (e.g. sent from the phone) ...
    h.client.add("Sent", sent_mail("offer@example-a.dk", "ny.kunde@kunde.dk"))
    h.state.contacts_last_fresh = time.monotonic() - 120
    h.advance(61)
    h.moves()
    r = h.row("re8@x")
    assert r["our_action"] == "none" and r["our_score"] == pytest.approx(4.0)
    assert "re8@x" in h.client.msgids("INBOX") and h.client.msgids("Junk") == []
    assert syms_of(h, "re8@x")["TH_REPLY"]["s"] == -5.0
    ev = h.events("reply_recheck")
    assert len(ev) == 1 and "bliver i indbakken" in ev[0][2]
    assert h.db.conn.execute("SELECT COUNT(*) FROM pending_move").fetchone()[0] == 0
    assert h.stat("reply_detected") == 1


def test_recheck_without_a_match_moves_as_usual(eng, monkeypatch, C):
    h = synced(eng, monkeypatch, [sent_mail("old@example-a.dk", "a@b.dk")])
    h.state.contacts_last_fresh = time.monotonic()
    inbound(h, "re9@x", "x@spam.example", score=9.0, symbols=DMARC_OK, extra=irt("unknown@spam.example"))
    h.state.contacts_last_fresh = 0.0
    h.advance(61)
    h.moves()
    assert h.client.msgids("Junk") == ["re9@x"]
