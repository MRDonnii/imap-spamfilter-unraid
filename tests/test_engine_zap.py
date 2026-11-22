"""ENGINE 2.3 (B19): rescans ("ZAP") - move spam when the blocklists catch up.

Queued only for mail that stayed in the inbox and could turn out to be spam
(never allowlisted / sticky ham / known contact / reply); attempts at
+45 min, +4 h, +24 h (aged mode then), dropped after 26 h, max 20 per
loop, found by exact Message-ID in the INBOX only. It acts only when the
new score reaches the threshold AND a new reputation/threat symbol
appeared (never Bayes alone); unread mail is moved through pending_move
(origin 'zap', short grace, counted by the circuit breaker), read mail only
for a threat. Nothing is ever deleted."""

from __future__ import annotations

import datetime as dt
import json
import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import make_message, setup_engine  # noqa: E402
from test_engine_contacts import DMARC_OK, run_sync, sent_mail, sym  # noqa: E402
from test_engine_scan import Harness  # noqa: E402

LOG = logging.getLogger("test-zap")
MIN = 60
HOUR = 3600


@pytest.fixture
def eng(tmp_path, monkeypatch):
    e = setup_engine(tmp_path, monkeypatch)
    import contacts

    contacts.forget_cached_keys()
    yield e
    contacts.forget_cached_keys()


def H(eng, monkeypatch, **kw):
    kw.setdefault("threshold", 10.0)
    return Harness(eng, monkeypatch, **kw)


def deliver(h, msgid, *, score=5.0, symbols=None, flags=(), body="Hello there.\r\n", sender="a@example.org"):
    h.rspamd.scores[msgid] = score
    h.rspamd.symbols[msgid] = symbols if symbols is not None else {"BAYES_HAM": {"name": "BAYES_HAM",
                                                                                 "score": -1.0}}
    h.deliver(msgid, flags=flags, body=body, sender=sender)
    h.scan()
    return h.row(msgid)


def queue(h):
    return {r["message_id"]: r for r in h.db.conn.execute("SELECT * FROM rescan_queue")}


def zap(h):
    return h.eng.zap_pass(h.client, h.db, LOG, h.acc, h.acc.folder_map, h.state)


def news(h, msgid, score=13.0, extra=None):
    """Blocklists caught up: DBL_SPAM (+ optional extra symbols) at rescan."""
    h.rspamd.scores[msgid] = score
    syms = {"DBL_SPAM": {"name": "DBL_SPAM", "score": 6.5, "options": ["spam.example:url"]}}
    syms.update(extra or {})
    h.rspamd.symbols[msgid] = syms


def set_seen(h, msgid, *flags):
    box = h.client.folders["INBOX"]
    for m in box.msgs.values():
        if f"<{msgid}>".encode() in m.raw:
            m.flags |= set(flags)


# ----- queue conditions ------------------------------------------------------------------


def test_queue_conditions(eng, monkeypatch):
    h = H(eng, monkeypatch)
    deliver(h, "near@x", score=5.0)                                   # >= threshold - 6
    deliver(h, "low@x", score=1.0)                                    # low, no links
    deliver(h, "link@x", score=0.5, body="Klik https://kampagne.example/x\r\n")  # links
    deliver(h, "spam@x", score=12.0)                                  # decided spam
    eng.add_sender_rule(h.db.conn, "acct", "ven@kunde.dk", "allow")
    deliver(h, "allow@x", score=9.0, sender="ven@kunde.dk")           # allowlisted
    q = queue(h)
    assert set(q) == {"near@x", "link@x"}
    r = q["near@x"]
    assert r["attempt"] == 0 and r["due_at"] == int(h.t) + 45 * MIN and r["first_score"] == 5.0
    assert r["folder"] == "INBOX" and r["uid"] is not None
    assert "BAYES_HAM" in json.loads(r["first_symbols"])
    # ZAP_MIN_SCORE: with a low threshold the floor is 3.
    h2 = H(eng, monkeypatch, threshold=6.0, name="low")
    deliver(h2, "two@x", score=2.5)
    deliver(h2, "three@x", score=3.0)
    assert set(queue(h2)) >= {"three@x"} and "two@x" not in queue(h2)


def test_no_queue_when_zap_is_off_or_sticky_or_contact(eng, monkeypatch):
    h = H(eng, monkeypatch, zap=False)
    deliver(h, "off@x", score=6.0)
    assert queue(h) == {}
    h2 = H(eng, monkeypatch, folders=("INBOX", "Junk", "Trash", "Sent"), name="kc")
    h2.client.add("Sent", sent_mail("s1@x", "alice@kunde.dk"))
    run_sync(h2)
    deliver(h2, "kc@x", score=9.0, symbols=DMARC_OK, sender="alice@kunde.dk")
    assert "kc@x" not in queue(h2)


def test_attachment_mail_is_queued(eng, monkeypatch):
    from test_engine_threat import mail_with_attachments

    h = H(eng, monkeypatch)
    h.rspamd.scores["att@x"] = 0.5
    h.client.add("INBOX", mail_with_attachments("att@x", [("faktura.pdf", b"%PDF")]),
                 internaldate=dt.datetime.fromtimestamp(h.t, dt.timezone.utc))
    h.scan()
    assert "att@x" in queue(h)


# ----- schedule ----------------------------------------------------------------------------


def test_schedule_45min_4h_24h_then_dropped(eng, monkeypatch):
    h = H(eng, monkeypatch)
    deliver(h, "s@x", score=5.0)
    calls = len(h.rspamd.scan_calls)
    h.advance(44 * MIN)
    assert zap(h) == 0 and len(h.rspamd.scan_calls) == calls
    h.advance(2 * MIN)
    assert zap(h) == 1
    assert len(h.rspamd.scan_calls) == calls + 1
    r = queue(h)["s@x"]
    assert r["attempt"] == 1 and r["due_at"] == r["queued_at"] + 4 * HOUR
    assert [e[1] for e in h.events("zap_rescore")] == ["s@x"]
    assert "ny=-" in h.events("zap_rescore")[0][2]
    h.advance(4 * HOUR)
    zap(h)
    assert queue(h)["s@x"]["attempt"] == 2
    h.advance(20 * HOUR)
    zap(h)
    assert "s@x" not in queue(h)  # third and last attempt done
    # The scanned stat is untouched by rescans; the row keeps its first score.
    assert h.stat("scanned") == 1 and h.row("s@x")["our_score"] == 5.0


def test_rescan_after_24h_uses_aged_mode(eng, monkeypatch):
    h = H(eng, monkeypatch)
    deliver(h, "a@x", score=5.0)
    h.advance(45 * MIN)
    zap(h)
    assert "Settings" not in h.rspamd.scan_calls[-1]["headers"]
    h.advance(4 * HOUR)
    zap(h)
    assert "Settings" not in h.rspamd.scan_calls[-1]["headers"]  # 4.75 h < 6 h
    h.advance(20 * HOUR)
    zap(h)
    assert "symbols_disabled" in h.rspamd.scan_calls[-1]["headers"]["Settings"]


def test_dropped_after_26h(eng, monkeypatch):
    h = H(eng, monkeypatch)
    deliver(h, "old@x", score=5.0)
    h.advance(27 * HOUR)
    calls = len(h.rspamd.scan_calls)
    assert zap(h) == 0 and queue(h) == {} and len(h.rspamd.scan_calls) == calls


def test_max_20_per_loop(eng, monkeypatch):
    h = H(eng, monkeypatch)
    for i in range(25):
        deliver(h, f"m{i}@x", score=5.0)
    h.advance(46 * MIN)
    assert zap(h) == 20
    assert sum(1 for r in queue(h).values() if r["attempt"] == 0) == 5
    assert zap(h) == 5


def test_next_wake_includes_the_due_rescan(eng, monkeypatch):
    h = H(eng, monkeypatch)
    h.state.last_junk_poll = 1e18  # junk poll not due
    h.state.last_retention = 1e18
    deliver(h, "w@x", score=5.0)
    h.advance(40 * MIN)
    wait = eng._next_wake_in(h.db, h.acc, h.state)
    assert 4 * MIN <= wait <= 5 * MIN + 1


# ----- acting ----------------------------------------------------------------------------


def test_new_blocklist_hit_moves_unread_mail(eng, monkeypatch):
    h = H(eng, monkeypatch)
    deliver(h, "z@x", score=5.0)
    h.advance(3 * HOUR + 10 * MIN)  # due since +45 min; rescanned now
    news(h, "z@x")
    zap(h)
    r = h.row("z@x")
    assert r["our_action"] == "pending_move" and r["our_score"] == 13.0
    pm = h.db.conn.execute("SELECT * FROM pending_move WHERE message_id='z@x'").fetchone()
    assert pm["origin"] == "zap" and pm["due_at"] == int(h.t) + eng.ZAP_GRACE_S
    ev = h.events("zap_move")
    assert len(ev) == 1 and "ny=DBL_SPAM" in ev[0][2] and "efter=3 t" in ev[0][2]
    assert "z@x" not in queue(h)
    h.advance(eng.ZAP_GRACE_S)
    h.moves()
    assert h.client.msgids("Junk") == ["z@x"] and "z@x" not in h.client.msgids("INBOX")
    r = h.row("z@x")
    assert r["our_action"] == "moved_to_junk" and r["zapped_at"] == int(h.t)
    assert h.stat("zapped") == 1 and h.stat("moved") == 1
    # Never a plain EXPUNGE, only the exact UID of the moved copy.
    assert "expunge" not in h.client.write_names() and "delete_messages" not in h.client.write_names()
    assert any(w[0] == "uid_expunge" for w in h.client.writes)
    assert "genscanning" in [e for e in h.events("moved_to_junk") if e[1] == "z@x"][0][2]
    import services

    assert services.zap_timeline_text(ev[0][2]) == "Ny viden: DBL_SPAM kom til efter 3 t"


def test_bayes_change_alone_never_moves(eng, monkeypatch):
    h = H(eng, monkeypatch)
    deliver(h, "b@x", score=5.0)
    h.advance(46 * MIN)
    h.rspamd.scores["b@x"] = 14.0
    h.rspamd.symbols["b@x"] = {"BAYES_SPAM": {"name": "BAYES_SPAM", "score": 5.0}}
    zap(h)
    assert h.row("b@x")["our_action"] == "none"
    assert h.db.conn.execute("SELECT COUNT(*) FROM pending_move").fetchone()[0] == 0
    assert h.events("zap_rescore") and not h.events("zap_move")


def test_new_symbol_below_threshold_does_not_move(eng, monkeypatch):
    h = H(eng, monkeypatch)
    deliver(h, "u@x", score=5.0)
    h.advance(46 * MIN)
    news(h, "u@x", score=9.0)
    zap(h)
    assert h.row("u@x")["our_action"] == "none" and queue(h)["u@x"]["attempt"] == 1


def test_symbol_present_at_first_scan_is_not_new(eng, monkeypatch):
    h = H(eng, monkeypatch)
    deliver(h, "k@x", score=5.0, symbols={"DBL_SPAM": {"name": "DBL_SPAM", "score": 1.0}})
    h.advance(46 * MIN)
    news(h, "k@x", score=13.0)
    zap(h)
    assert h.row("k@x")["our_action"] == "none"


def test_read_mail_is_never_moved_for_spam(eng, monkeypatch):
    h = H(eng, monkeypatch)
    deliver(h, "r@x", score=5.0)
    set_seen(h, "r@x", "\\Seen")
    h.advance(46 * MIN)
    news(h, "r@x")
    writes = len(h.client.writes)
    zap(h)
    r = h.row("r@x")
    assert r["our_action"] == "none" and r["our_score"] == 13.0
    assert len(h.client.writes) == writes  # not one IMAP write
    assert [e[1] for e in h.events("would_have_zapped")] == ["r@x"] and h.stat("would_have_zapped") == 1
    h.advance(HOUR)
    h.moves()
    assert "r@x" in h.client.msgids("INBOX")


def test_read_mail_is_moved_for_a_threat(eng, monkeypatch):
    h = H(eng, monkeypatch)
    deliver(h, "t@x", score=2.0, body="Se https://bank.example/login\r\n")
    set_seen(h, "t@x", "\\Seen")
    h.advance(46 * MIN)
    news(h, "t@x", score=4.0, extra={"DBL_PHISH": {"name": "DBL_PHISH", "score": 7.5,
                                                    "options": ["bank-login.example:url"]}})
    zap(h)
    r = h.row("t@x")
    assert r["our_action"] == "pending_move" and r["threat"] == "phish"
    h.advance(eng.ZAP_GRACE_S)
    h.moves()
    assert h.client.msgids("Junk") == ["t@x"]
    assert h.stat("threat_detected") == 1


def test_mail_read_during_the_grace_stays(eng, monkeypatch):
    h = H(eng, monkeypatch)
    deliver(h, "g@x", score=5.0)
    h.advance(46 * MIN)
    news(h, "g@x")
    zap(h)
    set_seen(h, "g@x", "\\Seen")
    h.advance(eng.ZAP_GRACE_S)
    h.moves()
    assert "g@x" in h.client.msgids("INBOX") and h.row("g@x")["our_action"] == "none"
    assert [e[1] for e in h.events("zap_skipped_read")] == ["g@x"]


@pytest.mark.parametrize("how", ["gone", "flagged", "verdict", "moved_by_user"])
def test_skip_gone_flagged_or_user_verdict(eng, monkeypatch, how):
    h = H(eng, monkeypatch)
    deliver(h, "s@x", score=5.0)
    if how == "gone":
        h.user_moves("s@x", "INBOX", "Trash")
    elif how == "flagged":
        set_seen(h, "s@x", "\\Flagged")
    elif how == "verdict":
        with h.db.tx():
            h.db.update_message("s@x", user_verdict="ham")
    else:
        h.user_moves("s@x", "INBOX", "Junk")
        h.poll()
    h.advance(46 * MIN)
    news(h, "s@x")
    writes = len(h.client.writes)
    zap(h)
    assert "s@x" not in queue(h)
    assert h.db.conn.execute("SELECT COUNT(*) FROM pending_move").fetchone()[0] == 0
    assert len(h.client.writes) == writes
    if how != "moved_by_user":
        assert [e[1] for e in h.events("zap_skipped")] == ["s@x"]


def test_only_the_inbox_is_searched(eng, monkeypatch):
    h = H(eng, monkeypatch)
    deliver(h, "i@x", score=5.0)
    h.user_moves("i@x", "INBOX", "Trash")
    h.advance(46 * MIN)
    news(h, "i@x")
    h.client.calls.clear()
    zap(h)
    selected = [c[1] for c in h.client.calls if c[0] == "select_folder"]
    assert selected and set(selected) == {"INBOX"}
    assert "i@x" in h.client.msgids("Trash")


def test_flag_and_shadow_modes(eng, monkeypatch):
    h = H(eng, monkeypatch, mode="flag")
    deliver(h, "f@x", score=5.0)
    h.advance(46 * MIN)
    news(h, "f@x")
    zap(h)
    uid = h.client.uids("INBOX")[0]
    assert "$Junk" in h.client.flags_of("INBOX", uid) and "$Phishing" not in h.client.flags_of("INBOX", uid)
    r = h.row("f@x")
    assert r["our_action"] == "flagged" and r["zapped_at"] and h.stat("zapped") == 1
    s = H(eng, monkeypatch, mode="shadow", name="sh")
    deliver(s, "sh@x", score=5.0)
    s.advance(46 * MIN)
    news(s, "sh@x")
    zap(s)
    assert s.client.write_names() == []
    assert s.row("sh@x")["our_action"] == "shadow_spam" and [e[1] for e in s.events("would_have_zapped")] == ["sh@x"]


def test_circuit_breaker_counts_zap_moves(eng, monkeypatch):
    h = H(eng, monkeypatch, circuit_max_moves_per_hour=1, circuit_min_moves=100)
    for i in range(2):
        deliver(h, f"c{i}@x", score=5.0)
    h.advance(46 * MIN)
    for i in range(2):
        news(h, f"c{i}@x")
    zap(h)
    h.advance(eng.ZAP_GRACE_S)
    h.moves()
    assert len(h.client.msgids("Junk")) == 1
    assert eng.circuit_open(h.db.conn, "acct")
    assert h.db.conn.execute("SELECT COUNT(*) FROM rate_limit WHERE action='move'").fetchone()[0] == 1


def test_zap_runs_from_the_loop(eng, monkeypatch):
    h = H(eng, monkeypatch)
    deliver(h, "l@x", score=5.0)
    h.advance(46 * MIN)
    news(h, "l@x")
    h.loop()
    assert h.row("l@x")["our_action"] == "pending_move"
    h.advance(eng.ZAP_GRACE_S)
    h.loop()
    assert h.client.msgids("Junk") == ["l@x"]


def test_rspamd_outage_keeps_the_rescan(eng, monkeypatch):
    h = H(eng, monkeypatch)
    deliver(h, "o@x", score=5.0)
    h.advance(46 * MIN)
    h.rspamd.outage = True
    zap(h)
    assert queue(h)["o@x"]["attempt"] == 0  # retried after the backoff
    assert h.state.rspamd_backoff_until > 0


def test_receipt_marks_mail_moved_later(eng, monkeypatch):
    h = H(eng, monkeypatch, daily_report=True)
    deliver(h, "z@x", score=5.0)
    h.advance(46 * MIN)
    news(h, "z@x")
    zap(h)
    h.advance(eng.ZAP_GRACE_S)
    h.moves()
    items = eng._receipt_items(h.db.conn, "acct", h.t)
    assert items and items[0]["zapped"] is True
    raw, _mid = eng.build_receipt(h.acc, items, now=h.t)
    text = raw.decode("utf-8", "replace")
    assert "flyttet efterf" in text.lower()


def test_reputation_symbol_set(eng):
    rep = eng.reputation_symbols
    assert rep({"DBL_SPAM", "ABUSE_SURBL", "URIBL_BLACK", "FUZZY_DENIED", "PHISHED_OPENPHISH",
                "CLAM_VIRUS", "URLHAUS_MALWARE_URL", "PH_SURBL_MULTI"}) == {
        "DBL_SPAM", "ABUSE_SURBL", "URIBL_BLACK", "FUZZY_DENIED", "PHISHED_OPENPHISH", "CLAM_VIRUS",
        "URLHAUS_MALWARE_URL", "PH_SURBL_MULTI"}
    assert rep({"BAYES_SPAM", "PHISHED_EXCLUDED", "CLAM_VIRUS_FAIL", "URIBL_BLOCKED", "DBL_PROHIBIT",
                "PHISHING", "RBL_SPAMHAUS", "TH_ATTACH_BLOCK"}) == set()


def test_housekeeping_prunes_expired_rows(eng, monkeypatch):
    h = H(eng, monkeypatch, zap=False)
    with h.db.tx():
        h.db.conn.execute("INSERT INTO rescan_queue(account, message_id, folder, due_at, queued_at) "
                          "VALUES('acct', 'x@x', 'INBOX', 0, ?)", (int(h.t) - 30 * HOUR,))
    eng._housekeeping(h.client, h.db, LOG, h.acc, h.state)
    assert queue(h) == {}


def test_rescan_never_records_contacts_or_learns(eng, monkeypatch):
    h = H(eng, monkeypatch)
    deliver(h, "n@x", score=5.0)
    h.advance(46 * MIN)
    zap(h)
    assert h.rspamd.learn_calls == []
    assert make_message("n@x")  # sanity


# ----- 2.6 review: newsletters are rescanned too (spam has priority) ---------------------


UNSUB = "List-Unsubscribe: <https://click.example.com/u/abc>, <mailto:u@example.com>"


def test_late_phishing_is_pulled_out_of_the_newsletter_folder(eng, monkeypatch):
    h = H(eng, monkeypatch, newsletters="on")
    h.rspamd.scores["n@x"] = 5.0
    h.deliver("n@x", subject="Ugens tilbud til dig", sender="news@brand.example", extra_headers=UNSUB)
    h.scan()
    assert h.row("n@x")["our_action"] == "newsletter_pending" and "n@x" in queue(h)
    h.advance(61)
    h.loop()
    assert h.client.msgids("Nyhedsbreve") == ["n@x"] and h.row("n@x")["our_action"] == "newsletter_moved"
    h.advance(3 * HOUR)
    news(h, "n@x")
    zap(h)
    assert h.row("n@x")["our_action"] == "pending_move"
    pm = h.db.conn.execute("SELECT * FROM pending_move WHERE message_id='n@x'").fetchone()
    assert pm["origin"] == "zap" and pm["folder"] == "Nyhedsbreve"
    h.advance(eng.ZAP_GRACE_S)
    h.moves()
    assert h.client.msgids("Junk") == ["n@x"] and h.client.msgids("Nyhedsbreve") == []
    assert h.row("n@x")["our_action"] == "moved_to_junk"
    assert h.db.conn.execute("SELECT COUNT(*) FROM move_journal").fetchone()[0] == 0


def test_newsletter_waiting_for_its_move_is_rescanned_in_the_inbox(eng, monkeypatch):
    h = H(eng, monkeypatch, newsletters="on", move_grace_seconds=10 * HOUR)
    h.rspamd.scores["n@x"] = 5.0
    h.deliver("n@x", subject="Ugens tilbud til dig", sender="news@brand.example", extra_headers=UNSUB)
    h.scan()
    assert h.row("n@x")["our_action"] == "newsletter_pending"
    h.advance(46 * MIN)
    news(h, "n@x")
    zap(h)
    assert h.row("n@x")["our_action"] == "pending_move"
    assert h.db.conn.execute("SELECT COUNT(*) FROM newsletter_pending").fetchone()[0] == 0
