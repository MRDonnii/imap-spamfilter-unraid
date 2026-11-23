"""ENGINE: inbox scanning, decisions, actions and the no-bounce-back rules
(SPEC E1-E4, E11, A4)."""

from __future__ import annotations

import datetime as dt
import json
import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import (  # noqa: E402
    GIGAHOST_CAPS,
    SCANNET_CAPS,
    FakeIMAP,
    FakeRspamd,
    make_account,
    make_message,
    setup_engine,
    stub_mailctx,
)

LOG = logging.getLogger("test")
T0 = 1_800_000_000.0


class Harness:
    """One connected account: FakeIMAP + real SQLite + fake rspamd, with
    a controllable wall clock."""

    def __init__(self, eng, monkeypatch, *, caps=GIGAHOST_CAPS, folders=("INBOX", "Junk", "Trash"),
                 preexisting: int = 0, **acc_over):
        self.eng = eng
        self.t = T0
        monkeypatch.setattr(eng, "_now", lambda: self.t)
        self.rspamd = FakeRspamd(eng.requests).install(monkeypatch, eng)
        self.client = FakeIMAP(capabilities=caps, folders=folders)
        for i in range(preexisting):
            self.client.add("INBOX", make_message(f"old{i}@x"))
        self.acc = make_account(eng, **acc_over)
        self.db = eng.Db(self.acc.name)
        self.state = eng.AccountState()
        eng._on_connected(self.client, self.db, LOG, self.acc, self.state)
        # First pass initialises the bookmark (pre-existing mail is skipped).
        self.scan()

    # actions
    def scan(self):
        self.eng.scan_inbox(self.client, self.db, LOG, self.acc, self.acc.folder_map, self.state)

    def moves(self):
        self.eng.execute_due_moves(self.client, self.db, LOG, self.acc, self.acc.folder_map, self.state)

    def poll(self):
        self.eng.poll_junk(self.client, self.db, LOG, self.acc, self.acc.folder_map, self.state)

    def loop(self):
        self.eng._loop_once(self.client, self.db, LOG, self.acc, self.state)

    def deliver(self, msgid, *, score=None, flags=(), folder="INBOX", internaldate=None, **kw):
        """A new delivery: INTERNALDATE is the (fake) arrival time, so a
        redelivery differs from a copy/move, which keeps it."""
        if score is not None:
            self.rspamd.scores[msgid] = score
        if internaldate is None:
            internaldate = dt.datetime.fromtimestamp(self.t, dt.timezone.utc)
        return self.client.add(folder, make_message(msgid, **kw), flags=flags,
                               internaldate=internaldate)

    def user_moves(self, msgid, src, dst, *, flags=None):
        """What a mail client does: the message gets a new UID in dst."""
        box = self.client.folders[src]
        for uid, m in list(box.msgs.items()):
            if f"<{msgid}>" in m.raw.decode():
                del box.msgs[uid]
                # COPY/MOVE keep INTERNALDATE (RFC 3501).
                return self.client.add(dst, m.raw, flags=tuple(flags if flags is not None else m.flags),
                                       internaldate=m.internaldate)
        raise AssertionError(f"{msgid} not in {src}")

    def advance(self, seconds):
        self.t += seconds

    # inspection
    def row(self, msgid):
        return self.db.get_message(msgid)

    def stat(self, metric):
        r = self.db.conn.execute("SELECT SUM(n) FROM stats_daily WHERE account=? AND metric=?",
                                 (self.acc.name, metric)).fetchone()
        return r[0] or 0

    def events(self, name=None):
        rows = self.db.conn.execute("SELECT event, message_id, detail FROM events ORDER BY id").fetchall()
        return [tuple(r) for r in rows if name is None or r[0] == name]

    def bookmark(self):
        uv = self.client.folders["INBOX"].uidvalidity
        return self.db.get_scan_bookmark("INBOX", uv)

    def scanned_ids(self):
        return [c["msgid"] for c in self.rspamd.scan_calls]


@pytest.fixture
def eng(tmp_path, monkeypatch):
    return setup_engine(tmp_path, monkeypatch)


# ----- E1 bookmark -----------------------------------------------------------


def test_preexisting_mail_is_never_scanned(eng, monkeypatch):
    h = Harness(eng, monkeypatch, preexisting=3)
    assert h.bookmark() == 3 and h.rspamd.scan_calls == []
    h.deliver("new@x")
    h.scan()
    assert h.scanned_ids() == ["new@x"]
    assert h.bookmark() == 4


def test_uid_star_range_does_not_rescan_highest_uid(eng, monkeypatch):
    """`UID 4:*` returns UID 3 when 3 is the top UID (RFC 3501)."""
    h = Harness(eng, monkeypatch, preexisting=3)
    for _ in range(3):
        h.scan()
    assert h.rspamd.scan_calls == []
    h.deliver("n1@x")
    h.scan()
    h.scan()
    assert h.scanned_ids() == ["n1@x"]


def test_seen_at_first_sight_is_skipped(eng, monkeypatch):
    h = Harness(eng, monkeypatch)
    h.deliver("read@x", flags=("\\Seen",), score=50)
    h.deliver("unread@x", score=1)
    h.scan()
    assert h.scanned_ids() == ["unread@x"]
    assert h.row("read@x") is None
    assert h.stat("skipped_seen") == 1
    assert h.bookmark() == 2


def test_no_message_id_is_scanned_and_oversize_is_skipped(eng, monkeypatch):
    h = Harness(eng, monkeypatch)
    h.client.add("INBOX", make_message(None))
    h.client.add("INBOX", make_message("big@x"), size=eng.MAX_FETCH_BYTES + 1)
    h.scan()
    assert len(h.rspamd.scan_calls) == 1
    assert h.stat("skipped_no_msgid") == 0 and h.stat("skipped_oversize") == 1
    assert h.bookmark() == 2
    # Only the small ID-less mail is fetched; the oversize UID stays untouched.
    assert all(2 not in c[1] for c in h.client.calls if c[0] == "fetch" and b"BODY.PEEK[]" in c[2])


def test_scan_retry_gives_up_after_five_attempts(eng, monkeypatch):
    h = Harness(eng, monkeypatch)
    h.deliver("bad@x")
    h.rspamd.bad_msgids.add("bad@x")
    h.deliver("good@x", score=1)
    h.scan()
    assert h.bookmark() == 0                 # held by the failing UID
    assert h.row("good@x")["our_action"] == "none"
    scans_good = h.scanned_ids().count("good@x")
    h.scan()                                  # not due yet: no retry
    assert h.scanned_ids().count("bad@x") == 1
    for _ in range(10):
        h.advance(3600)
        h.scan()
    assert h.scanned_ids().count("bad@x") == eng.SCAN_RETRY_MAX_ATTEMPTS
    assert h.scanned_ids().count("good@x") == scans_good  # never re-scored
    assert h.bookmark() == 2
    assert h.stat("scan_failed") == 4 and h.stat("scan_giveup") == 1
    assert h.events("scan_giveup")


def test_scan_retry_gives_up_after_six_hours(eng, monkeypatch):
    h = Harness(eng, monkeypatch)
    h.deliver("bad@x")
    h.rspamd.bad_msgids.add("bad@x")
    h.scan()
    h.advance(6 * 3600 + 1)
    h.scan()
    assert h.scanned_ids().count("bad@x") == 1
    assert h.bookmark() == 1 and h.stat("scan_giveup") == 1


def test_out_of_range_score_is_clamped_not_failed(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("huge@x", score=5000.0)
    h.scan()
    r = h.row("huge@x")
    assert r["rspamd_score"] == 100.0 and r["our_action"] == "pending_move"
    assert h.stat("scan_failed") == 0 and h.bookmark() == 1
    assert any("clamped" in (e[2] or "") for e in h.events("scan"))


def test_rspamd_outage_backs_off_without_refetching(eng, monkeypatch):
    h = Harness(eng, monkeypatch)
    h.deliver("a@x")
    h.rspamd.outage = True
    h.scan()
    assert h.state.rspamd_backoff_until > 0
    assert h.stat("scan_failed") == 0 and h.bookmark() == 0
    body_fetches = sum(1 for c in h.client.calls if c[0] == "fetch" and b"BODY.PEEK[]" in c[2])
    calls_before = len(h.client.calls)
    h.scan()
    h.scan()
    assert len(h.client.calls) == calls_before  # no SEARCH, no FETCH while backing off
    st = h.db.conn.execute("SELECT state, detail, last_error FROM account_status").fetchone()
    assert st["state"] == "error" and "Rspamd" in st["detail"] and st["last_error"].startswith("rspamd:")
    # rspamd back, backoff elapsed: the message is scanned once.
    h.rspamd.outage = False
    h.state.rspamd_backoff_until = 0.0
    h.scan()
    assert h.row("a@x") is not None and h.bookmark() == 1
    assert body_fetches == 1


def test_per_message_error_is_isolated(eng, monkeypatch):
    h = Harness(eng, monkeypatch)
    real = eng.match_sender_rule

    def boom(conn, account, sender):
        if sender == "evil@x.dk":
            raise RuntimeError("kaboom")
        return real(conn, account, sender)

    monkeypatch.setattr(eng, "match_sender_rule", boom)
    h.deliver("a@x", sender="evil@x.dk")
    h.deliver("b@x", sender="ok@x.dk")
    h.scan()
    assert h.row("b@x") is not None
    assert h.events("scan_failed") and h.bookmark() == 0


def test_safe_mode_when_unseen_over_cap(eng, monkeypatch):
    h = Harness(eng, monkeypatch, safe_mode_unseen_cap=2)
    for i in range(3):
        h.deliver(f"s{i}@x")
    h.scan()
    assert h.rspamd.scan_calls == [] and h.db.in_safe_mode("all")
    h.client.folders["INBOX"].msgs.pop(1)
    h.scan()
    assert not h.db.in_safe_mode("all") and len(h.rspamd.scan_calls) == 2


# ----- E3/E4 scan request and decision ---------------------------------------


def test_rspamd_scan_sends_context_headers_and_deliver_to(eng, monkeypatch):
    h = Harness(eng, monkeypatch, bayes_user="hjemmeserver")
    h.rspamd.symbols["a@x"] = {f"S{i}": {"name": f"S{i}", "score": float(i), "options": ["a", "b", "c", "d"]}
                               for i in range(40)}
    h.rspamd.scores["a@x"] = 2.0
    h.deliver("a@x")
    h.scan()
    hdrs = h.rspamd.scan_calls[0]["headers"]
    assert hdrs["Deliver-To"] == "hjemmeserver"
    assert hdrs["Rcpt"] == "user@example-a.dk" and hdrs["IP"] == "192.0.2.10"
    assert hdrs["From"] == "bounce@example.org"
    r = h.row("a@x")
    syms = json.loads(r["symbols"])
    assert len(syms) == 30 and syms[0] == {"n": "S39", "s": 39.0, "o": ["a", "b", "c"]}
    assert r["score_version"] == 2 and r["sender_ip"] == "192.0.2.10"
    assert r["envelope_from"] == "bounce@example.org" and r["origin"] == "inbox_scan"
    assert r["rspamd_action"] == "no action" and r["scanned_at"] == int(T0)


def test_rspamd_scan_result_type(eng, monkeypatch):
    rs = FakeRspamd(eng.requests).install(monkeypatch, eng)
    rs.scores["q@x"] = 7.5
    acc = make_account(eng)
    res = eng.rspamd_scan(make_message("q@x"), acc, {"headers": {"X-Bad\r\nInjected": "1", "IP": "1.2.3.4"}})
    assert isinstance(res, eng.ScanResult)
    assert res.score == 7.5 and res.action == "add header"
    assert res.symbols[0]["n"] == "BAYES_SPAM"
    assert "X-Bad\r\nInjected" not in rs.scan_calls[0]["headers"]
    assert rs.scan_calls[0]["headers"]["IP"] == "1.2.3.4"


def test_rspamd_learn_sends_deliver_to(eng, monkeypatch):
    rs = FakeRspamd(eng.requests).install(monkeypatch, eng)
    assert eng.rspamd_learn(b"raw", "spam", "hjemmeserver") == "learned"
    call = rs.learn_calls[0]
    assert call["url"].endswith("/learnspam")
    assert call["headers"]["Deliver-To"] == "hjemmeserver"
    assert call["data"].startswith(b"Delivered-To: hjemmeserver\r\n")


def test_provider_bonus_added_to_final_score(eng, monkeypatch):
    monkeypatch.setattr(eng, "_mailctx", lambda: stub_mailctx(provider_flag=True, provider_score=5.9))
    h = Harness(eng, monkeypatch, mode="shadow")
    h.deliver("p@x", score=5.0)
    h.scan()
    r = h.row("p@x")
    assert r["rspamd_score"] == 5.0 and r["our_score"] == 9.0
    assert r["our_action"] == "shadow_spam"
    assert r["provider_flag"] == 1 and r["provider_score"] == 5.9
    assert json.loads(r["symbols"])[0]["n"] == "TH_PROVIDER_SPAM"


def test_provider_bonus_disabled(eng, monkeypatch):
    monkeypatch.setattr(eng, "_mailctx", lambda: stub_mailctx(provider_flag=True))
    h = Harness(eng, monkeypatch, mode="shadow", provider_bonus=False)
    h.deliver("p@x", score=5.0)
    h.scan()
    r = h.row("p@x")
    assert r["our_score"] == 5.0 and r["our_action"] == "none"
    assert "TH_PROVIDER_SPAM" not in r["symbols"]


def test_mailctx_failure_still_scans_as_version_1(eng, monkeypatch):
    def broken():
        raise ImportError("mailctx missing")

    monkeypatch.setattr(eng, "_mailctx", broken)
    h = Harness(eng, monkeypatch, mode="shadow")
    h.deliver("p@x", score=3.0)
    h.scan()
    assert h.row("p@x")["score_version"] == 1
    assert h.rspamd.scan_calls[0]["headers"]["Rcpt"] == "user@example-a.dk"


def test_allow_rule_wins_unless_dmarc_spoof(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    rid = eng.add_sender_rule(h.db.conn, "*", "@friend.dk", "allow", None, "admin")
    h.deliver("a@x", score=20, sender="bob@friend.dk")
    h.deliver("b@x", score=20, sender="eve@friend.dk")
    h.rspamd.symbols["b@x"] = {"DMARC_POLICY_REJECT": {"name": "DMARC_POLICY_REJECT", "score": 2.0}}
    h.scan()
    a, b = h.row("a@x"), h.row("b@x")
    assert a["our_action"] == "allowlisted" and a["rule_hit"] == f"allow:{rid}"
    assert b["our_action"] == "pending_move" and b["rule_hit"] is None
    assert h.stat("allowlisted") == 1
    hits = h.db.conn.execute("SELECT hits FROM sender_rules WHERE id=?", (rid,)).fetchone()[0]
    assert hits == 1
    h.advance(120)
    h.moves()
    assert h.client.msgids("INBOX") == ["a@x"]


@pytest.mark.parametrize("sym", ["R_SPF_FAIL", "R_SPF_SOFTFAIL", "TH_PROVIDER_SPAM"])
def test_allow_rule_ignored_for_unauthenticated_from(eng, monkeypatch, sym):
    """Owner domains publish DMARC p=none: a spoofed allowed From that fails
    SPF (or the provider flagged as spam) is decided by its score."""
    h = Harness(eng, monkeypatch, mode="move")
    eng.add_sender_rule(h.db.conn, "*", "ole@bynet.example", "allow", None, "admin")
    h.deliver("x@x", score=20, sender="ole@bynet.example")
    h.deliver("ok@x", score=1, sender="ole@bynet.example")
    h.rspamd.symbols["x@x"] = {sym: {"name": sym, "score": 1.0}}
    h.rspamd.symbols["ok@x"] = {sym: {"name": sym, "score": 1.0}}
    h.scan()
    assert h.row("x@x")["our_action"] == "pending_move" and h.row("x@x")["rule_hit"] is None
    assert h.row("ok@x")["our_action"] == "none"


def test_block_rule_is_spam_regardless_of_score(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="flag")
    rid = eng.add_sender_rule(h.db.conn, "acct", "spammer@bad.dk", "block", None, "admin")
    h.deliver("a@x", score=-5, sender="Spammer@bad.dk")
    h.scan()
    r = h.row("a@x")
    assert r["our_action"] == "flagged" and r["rule_hit"] == f"block:{rid}"
    assert h.stat("blocklisted") == 1 and h.stat("spam_detected") == 1


# ----- E4 actions per mode ---------------------------------------------------


def test_flag_mode_sets_junk_keyword_never_flagged(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="flag")
    uid = h.deliver("s@x", score=12)
    h.deliver("h@x", score=1)
    h.loop()
    assert h.client.flags_of("INBOX", uid) == {"$Junk"}
    assert all(w[0] == "add_flags" and w[3] == ("$Junk",) for w in h.client.writes)
    assert not any("\\Flagged" in str(w) for w in h.client.writes)
    assert h.row("s@x")["our_action"] == "flagged" and h.row("h@x")["our_action"] == "none"
    assert h.stat("flagged") == 1 and h.stat("scanned") == 2


def test_move_mode_gigahost_uidplus_after_grace(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", caps=GIGAHOST_CAPS)
    other = h.deliver("ham@x", score=0, flags=("\\Deleted",))  # user's own deleted mail
    h.deliver("spam@x", score=12)
    h.scan()
    h.moves()
    assert h.client.msgids("INBOX") == ["ham@x", "spam@x"]  # grace not over
    h.advance(61)
    h.moves()
    assert h.client.msgids("INBOX") == ["ham@x"] and h.client.msgids("Junk") == ["spam@x"]
    assert "\\Deleted" in h.client.flags_of("INBOX", other)  # untouched
    assert "expunge" not in h.client.write_names()
    r = h.row("spam@x")
    assert r["our_action"] == "moved_to_junk" and r["current_folder"] == "Junk"
    assert r["moved_to_junk_at"] == int(h.t)
    assert h.stat("moved") == 1 and h.db.count_pending_moves() == 0


def test_move_mode_scannet_move(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", caps=SCANNET_CAPS)
    h.deliver("spam@x", score=12)
    h.scan()
    h.advance(61)
    h.moves()
    assert h.client.write_names() == ["move"]
    assert h.client.msgids("Junk") == ["spam@x"]


def test_move_rate_limit(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", max_moves_per_hour=2)
    for i in range(4):
        h.deliver(f"s{i}@x", score=12)
    h.scan()
    h.advance(61)
    h.moves()
    assert len(h.client.msgids("Junk")) == 2
    h.advance(3601)
    h.moves()
    assert len(h.client.msgids("Junk")) == 4


def test_user_flag_during_grace_cancels_move(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    uid = h.deliver("spam@x", score=12)
    h.scan()
    h.client.folders["INBOX"].msgs[uid].flags.add("\\Flagged")
    h.advance(61)
    h.moves()
    assert h.client.msgids("INBOX") == ["spam@x"]
    assert h.db.count_pending_moves() == 0
    assert h.row("spam@x")["our_action"] == "none"


@pytest.mark.parametrize("flag", ["$NotJunk", "NotJunk", "NonJunk"])
def test_client_notjunk_tag_during_grace_does_not_cancel_move(eng, monkeypatch, flag):
    """Apple Mail tags most clean-looking mail with $NotJunk/NotJunk on its
    own (live bynet: 5 of 6 new mails), so it is not a user decision."""
    h = Harness(eng, monkeypatch, mode="move")
    uid = h.deliver("spam@x", score=12)
    h.scan()
    h.client.folders["INBOX"].msgs[uid].flags.update({flag})
    h.advance(61)
    h.moves()
    assert h.client.msgids("INBOX") == []
    assert h.row("spam@x")["our_action"] == "moved_to_junk"


def test_move_unsupported_marks_move_failed(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", caps=(b"IMAP4REV1", b"IDLE"))
    h.deliver("spam@x", score=12)
    h.scan()
    h.advance(61)
    h.moves()
    assert h.row("spam@x")["our_action"] == "move_failed"
    assert h.stat("move_failed") == 1 and h.client.writes == []


def test_pending_moves_cleared_when_mode_is_not_move(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("spam@x", score=12)
    h.scan()
    assert h.db.count_pending_moves() == 1
    h.acc.mode = "flag"
    eng._prepare_pending_moves(h.db, h.acc)
    assert h.db.count_pending_moves() == 0
    assert h.row("spam@x")["our_action"] == "none"


def test_shadow_is_strictly_read_only(eng, monkeypatch):
    """Shadow: SELECTs are read-only and no mutating command is ever sent,
    even with spam, a missing junk folder, user moves and pending learns."""
    h = Harness(eng, monkeypatch, mode="shadow", folders=("INBOX", "Trash"), training_folders=True)
    h.deliver("spam@x", score=50)
    h.deliver("ham@x", score=0)
    eng.add_sender_rule(h.db.conn, "*", "@blocked.dk", "block")
    h.deliver("blk@x", score=0, sender="x@blocked.dk")
    with h.db.tx():
        h.db.upsert_message("pend@x", "INBOX", "s", "x")
        h.db.update_message("pend@x", pending_learn="ham", pending_learn_at=0)
    for _ in range(3):
        h.loop()
        h.advance(4000)
        h.state.last_junk_poll = h.state.last_retention = 0.0
    assert h.client.writes == []
    assert all(c[2] is True for c in h.client.calls if c[0] == "select_folder")
    assert h.row("spam@x")["our_action"] == "shadow_spam"
    assert h.row("blk@x")["our_action"] == "shadow_spam"
    assert h.row("ham@x")["our_action"] == "none"
    assert h.rspamd.learn_calls == []
    assert h.db.count_pending_moves() == 0
    eng._status_after_loop(h.db, h.acc, h.state)
    st = h.db.conn.execute("SELECT junk_exists, detail FROM account_status").fetchone()
    assert st["junk_exists"] == 0 and "Overvåger" in st["detail"]


# ----- E2 no bounce-back -------------------------------------------------------


@pytest.mark.parametrize("seen", [False, True])
def test_user_rescue_from_our_junk_is_never_moved_back(eng, monkeypatch, seen):
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("spam@x", score=12)
    h.scan()
    h.advance(61)
    h.moves()
    assert h.client.msgids("Junk") == ["spam@x"]
    h.user_moves("spam@x", "Junk", "INBOX", flags=("\\Seen",) if seen else ())
    for _ in range(3):
        h.scan()
        h.advance(120)
        h.moves()
    assert h.client.msgids("INBOX") == ["spam@x"] and h.client.msgids("Junk") == []
    r = h.row("spam@x")
    assert r["our_action"] == "user_rescued" and r["user_verdict"] == "ham"
    assert r["pending_learn"] == "ham" and r["current_folder"] == "INBOX"
    assert h.scanned_ids().count("spam@x") == 1  # not re-scored
    assert h.stat("user_rescued") == 1


def test_rescue_from_provider_junk(eng, monkeypatch):
    monkeypatch.setattr(eng, "PROVIDER_JUNK_SCORE_PER_RUN", 0)  # 2.12: provider junk scoring tested in test_v212.py
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("prov@x", folder="Junk", score=12)
    h.poll()
    r = h.row("prov@x")
    assert r["our_action"] == "provider_junk" and r["origin"] == "junk_poll"
    h.user_moves("prov@x", "Junk", "INBOX", flags=("\\Seen",))
    h.scan()
    h.advance(120)
    h.moves()
    assert h.client.msgids("INBOX") == ["prov@x"]
    assert h.row("prov@x")["user_verdict"] == "ham"
    assert h.rspamd.scan_calls == []


def test_admin_release_is_never_moved_back(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("rel@x", score=12)
    h.scan()
    h.advance(61)
    h.moves()
    # services.mail_action('release') moves it and records the verdict.
    h.user_moves("rel@x", "Junk", "INBOX")
    with h.db.tx():
        h.db.update_message("rel@x", our_action="manual_release", user_verdict="ham",
                            verdict_by="admin", current_folder="INBOX")
    h.scan()
    h.advance(120)
    h.moves()
    assert h.client.msgids("INBOX") == ["rel@x"]
    r = h.row("rel@x")
    assert r["our_action"] == "manual_release" and r["verdict_by"] == "admin"
    assert h.scanned_ids().count("rel@x") == 1


def test_admin_release_with_stale_folder_keeps_manual_release(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("rel@x", score=12)
    h.scan()
    h.advance(61)
    h.moves()
    h.user_moves("rel@x", "Junk", "INBOX")
    with h.db.tx():  # current_folder still says Junk
        h.db.update_message("rel@x", our_action="manual_release", user_verdict="ham", verdict_by="admin")
    h.scan()
    h.advance(120)
    h.moves()
    r = h.row("rel@x")
    assert h.client.msgids("INBOX") == ["rel@x"]
    assert r["our_action"] == "manual_release" and r["current_folder"] == "INBOX"


def test_legacy_header_only_ham_does_not_exempt_new_delivery(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    with h.db.tx():
        h.db.upsert_message("v@x", "INBOX", "s", "x")
        h.db.update_message("v@x", user_verdict="ham")
    h.deliver("v@x", score=30)
    h.scan()
    h.advance(61)
    h.moves()
    # An old header-only verdict cannot establish that this is the same body.
    assert h.client.msgids("Junk") == ["v@x"] and h.db.count_pending_moves() == 0


def test_pending_move_dropped_if_verdict_arrives_during_grace(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("g@x", score=30)
    h.scan()
    with h.db.tx():
        h.db.update_message("g@x", user_verdict="ham", our_action="manual_release")
    h.advance(61)
    h.moves()
    assert h.client.msgids("INBOX") == ["g@x"]
    assert h.events("move_skipped_verdict")


def test_duplicate_still_in_junk_is_scored_as_new(eng, monkeypatch):
    """Same Message-ID delivered again (alias) while the first copy is
    still in junk: not a rescue - scored and moved like new mail."""
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("dup@x", score=12)
    h.scan()
    h.advance(61)
    h.moves()
    h.deliver("dup@x")
    h.scan()
    assert h.scanned_ids().count("dup@x") == 2
    assert h.row("dup@x")["user_verdict"] is None
    h.advance(61)
    h.moves()
    assert h.client.msgids("INBOX") == [] and h.client.msgids("Junk") == ["dup@x", "dup@x"]


def test_client_notjunk_keyword_at_scan_is_not_a_ham_verdict(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("nj@x", score=30, flags=("$NotJunk", "NotJunk"))
    h.scan()
    r = h.row("nj@x")
    assert r["our_action"] == "pending_move" and r["user_verdict"] is None
    assert h.db.count_pending_moves() == 1


def test_stats_daily_bumps(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("s@x", score=12)
    h.deliver("h@x", score=1)
    h.scan()
    h.advance(61)
    h.moves()
    assert (h.stat("scanned"), h.stat("spam_detected"), h.stat("moved")) == (2, 1, 1)
    day = h.db.conn.execute("SELECT DISTINCT day FROM stats_daily").fetchall()
    assert [d[0] for d in day] == [eng.stats_day(T0)]


def test_gigahost_expunge_reply_lost_then_user_rescue_no_bounce(eng, monkeypatch):
    """UIDPLUS emulation: the UID EXPUNGE ran on the server but the
    connection died before the reply (so \\Deleted could not be rolled
    back). The row says move_failed; when the user moves the mail back
    from junk it must be honoured as a rescue, not re-scored and moved."""
    from fakes_engine import IMAPClientAbortError

    h = Harness(eng, monkeypatch, mode="move", caps=GIGAHOST_CAPS)
    h.deliver("x@x", score=12)
    h.scan()
    h.advance(61)
    real_expunge = h.client.uid_expunge

    def expunge_then_drop(uids):
        h.client.fail_on.pop("uid_expunge", None)
        real_expunge(uids)
        return IMAPClientAbortError("connection reset")

    h.client.fail_on["uid_expunge"] = expunge_then_drop
    h.client.fail_on["remove_flags"] = IMAPClientAbortError("connection reset")
    h.moves()
    r = h.row("x@x")
    assert r["our_action"] == "move_failed" and r["moved_to_junk_at"]
    assert h.client.msgids("INBOX") == [] and h.client.msgids("Junk") == ["x@x"]
    h.user_moves("x@x", "Junk", "INBOX")
    h.scan()
    h.advance(120)
    h.moves()
    assert h.client.msgids("INBOX") == ["x@x"]
    assert h.row("x@x")["user_verdict"] == "ham"
    assert h.scanned_ids().count("x@x") == 1


def test_expunge_failure_rollback_leaves_mail_in_inbox(eng, monkeypatch):
    from fakes_engine import IMAPClientError

    h = Harness(eng, monkeypatch, mode="move", caps=GIGAHOST_CAPS)
    uid = h.deliver("x@x", score=12)
    h.scan()
    h.advance(61)
    h.client.fail_on["uid_expunge"] = IMAPClientError("NO expunge failed")
    h.moves()
    assert h.client.msgids("INBOX") == ["x@x"]
    assert "\\Deleted" not in h.client.flags_of("INBOX", uid)
    assert h.row("x@x")["our_action"] == "move_failed" and h.stat("move_failed") == 1
    assert h.db.count_pending_moves() == 0  # never retried: a copy already exists


# ----- review fixes: rescues on servers without MOVE, read mail, wake-up --------


def _client_copy_move(h, msgid, src, dst, *, keep_internaldate=True):
    """A mail client on a server without MOVE (Gigahost): UID COPY to dst,
    STORE +\\Deleted on the source, UID EXPUNGE later (returned UID)."""
    box = h.client.folders[src]
    for uid, m in list(box.msgs.items()):
        if f"<{msgid}>" in m.raw.decode():
            kw = {"internaldate": m.internaldate} if keep_internaldate else {}
            h.client.add(dst, m.raw, flags=tuple(m.flags), **kw)
            m.flags.add("\\Deleted")
            return uid
    raise AssertionError(f"{msgid} not in {src}")


def _spamfilter(eng, monkeypatch, **over):
    over.setdefault("caps", GIGAHOST_CAPS)
    return Harness(eng, monkeypatch, mode="move", folders=("INBOX", "Junk", "Trash"),
                   junk="Spamfilter", junk_explicit=True, **over)


@pytest.mark.parametrize("keep_internaldate", [True, False])
def test_gigahost_rescue_with_unexpunged_deleted_source_is_honoured(eng, monkeypatch, keep_internaldate):
    """The source copy still carries \\Deleted (EXPUNGE not yet sent) when
    the engine scans: a rescue, not a duplicate - never moved back. Also
    holds when the server does not keep INTERNALDATE on COPY."""
    h = _spamfilter(eng, monkeypatch)
    h.deliver("fp@x", score=20)
    h.scan(); h.advance(61); h.moves()
    assert h.client.msgids("Spamfilter") == ["fp@x"]
    h.advance(600)
    src = _client_copy_move(h, "fp@x", "Spamfilter", "INBOX", keep_internaldate=keep_internaldate)
    h.scan()
    del h.client.folders["Spamfilter"].msgs[src]  # the client's UID EXPUNGE
    r = h.row("fp@x")
    assert r["our_action"] == "user_rescued" and r["user_verdict"] == "ham"
    h.advance(61); h.moves()
    assert h.client.msgids("INBOX") == ["fp@x"] and h.client.msgids("Spamfilter") == []
    assert h.scanned_ids().count("fp@x") == 1


def test_gigahost_rescue_scanned_between_copy_and_store_is_honoured(eng, monkeypatch):
    """Scan lands after the client's COPY but before STORE \\Deleted: the
    kept INTERNALDATE identifies the inbox copy as the same message."""
    h = _spamfilter(eng, monkeypatch)
    h.deliver("fp@x", score=20)
    h.scan(); h.advance(61); h.moves()
    h.advance(600)
    m = next(iter(h.client.folders["Spamfilter"].msgs.values()))
    h.client.add("INBOX", m.raw, flags=tuple(m.flags), internaldate=m.internaldate)
    h.scan()
    h.client.folders["Spamfilter"].msgs.clear()   # STORE + EXPUNGE afterwards
    assert h.row("fp@x")["user_verdict"] == "ham"
    h.advance(61); h.moves()
    assert h.client.msgids("INBOX") == ["fp@x"] and h.client.msgids("Spamfilter") == []


def test_redelivery_while_spamfilter_copy_exists_is_still_scored(eng, monkeypatch):
    h = _spamfilter(eng, monkeypatch)
    h.deliver("dup@x", score=20)
    h.scan(); h.advance(61); h.moves()
    h.advance(600)
    h.deliver("dup@x")                            # new arrival: new INTERNALDATE
    h.scan()
    assert h.scanned_ids().count("dup@x") == 2 and h.row("dup@x")["user_verdict"] is None
    h.advance(61); h.moves()
    assert h.client.msgids("Spamfilter") == ["dup@x", "dup@x"]


def test_gigahost_rescue_from_provider_junk_with_unexpunged_source(eng, monkeypatch):
    monkeypatch.setattr(eng, "PROVIDER_JUNK_SCORE_PER_RUN", 0)  # 2.12: provider junk scoring tested in test_v212.py
    h = _spamfilter(eng, monkeypatch)
    h.deliver("prov@x", folder="Junk", score=20)
    h.poll()
    assert h.row("prov@x")["our_action"] == "provider_junk"
    h.advance(600)
    src = _client_copy_move(h, "prov@x", "Junk", "INBOX")
    h.scan()
    del h.client.folders["Junk"].msgs[src]
    h.advance(61); h.moves()
    assert h.client.msgids("INBOX") == ["prov@x"] and h.client.msgids("Spamfilter") == []
    assert h.row("prov@x")["user_verdict"] == "ham" and h.rspamd.scan_calls == []


def test_read_mail_with_old_row_back_in_inbox_is_left_alone(eng, monkeypatch):
    """A 1.x 'shadow' row (high score, user kept the mail) whose read mail
    is dragged back into the inbox from an archive: never re-scored/moved."""
    h = _spamfilter(eng, monkeypatch, caps=SCANNET_CAPS)
    with h.db.tx():
        h.db.upsert_message("news@x", "INBOX", "a@x", "Nyhedsbrev", None)
        h.db.update_message("news@x", our_score=9.0, our_action="shadow")
    h.client.add_folder("Arkiv")
    h.deliver("news@x", folder="Arkiv", flags=("\\Seen",), score=9)
    h.user_moves("news@x", "Arkiv", "INBOX")
    h.scan(); h.advance(61); h.moves()
    assert h.client.msgids("INBOX") == ["news@x"] and h.client.msgids("Spamfilter") == []
    assert h.rspamd.scan_calls == [] and h.db.count_pending_moves() == 0


def test_rspamd_backoff_does_not_pin_wake_after_recovery(eng, monkeypatch):
    """After an rspamd outage ended the loop must go back to IDLE with the
    normal timers, not wake every MIN_LOOP_WAIT_S forever."""
    import time as _t

    h = _spamfilter(eng, monkeypatch, caps=SCANNET_CAPS)
    h.loop()
    h.rspamd.outage = True
    h.deliver("a@x", score=1)
    h.scan()
    assert h.state.rspamd_backoff_until > _t.monotonic()
    h.rspamd.outage = False
    # Backoff elapsed but no successful scan yet: no negative candidate.
    h.state.rspamd_backoff_until = _t.monotonic() - 1
    assert eng._next_wake_in(h.db, h.acc, h.state) > eng.MIN_LOOP_WAIT_S
    h.loop()                                      # scan succeeds
    assert h.row("a@x") is not None and h.state.rspamd_backoff_until == 0.0
    assert eng._next_wake_in(h.db, h.acc, h.state) > 60


def test_orphaned_scan_retry_is_dropped_and_does_not_pin_wake(eng, monkeypatch):
    h = _spamfilter(eng, monkeypatch, caps=SCANNET_CAPS)
    h.loop()
    h.rspamd.bad_msgids.add("bad@x")
    uid = h.deliver("bad@x", score=30)
    h.scan()
    count = "SELECT COUNT(*) FROM scan_retry"
    assert h.db.conn.execute(count).fetchone()[0] == 1
    del h.client.folders["INBOX"].msgs[uid]       # the user deletes it
    h.advance(3600)
    h.loop()
    assert h.db.conn.execute(count).fetchone()[0] == 0
    assert eng._next_wake_in(h.db, h.acc, h.state) > 60
