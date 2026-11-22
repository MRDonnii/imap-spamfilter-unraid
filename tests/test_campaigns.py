"""2.6 (A2): the same spam in every mailbox ("Samme spam på alle postkasser").

A user's spam verdict (the mail app or the WebUI) queues the copies of the
same campaign in every mailbox; each account thread moves its own copies
through the engine's normal pending_move path (journal, quota, circuit
breaker, Fortryd). Never mail from known contacts, allowed senders, the
owner's shops, a released mail or a protected address with an allow rule;
shadow mode only records; at most 25 copies per verdict and nothing older
than 72 h. The source mail is also added to rspamd's local fuzzy storage."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import setup_engine  # noqa: E402
from test_engine_scan import Harness  # noqa: E402

import campaigns  # noqa: E402

LOG = logging.getLogger("test-campaigns")
SUBJ = "Du har vundet en iPhone 17 – bekræft nu"
SPAMMER = "promo@spammy.example"
# Below the test threshold 8, above the score floor (8 - 2).
COPY_SCORE = 6.5


@pytest.fixture
def eng(tmp_path, monkeypatch):
    return setup_engine(tmp_path, monkeypatch)


class Pair:
    """Two mailboxes ('a' and 'b') on one database, one clock, one rspamd."""

    def __init__(self, eng, monkeypatch, *, mode_b="move", **kw):
        self.eng = eng
        # The filter's own folder "Spamfilter" next to the provider's "Junk":
        # only a drag into the filter's folder proves a user action.
        kw = dict(dict(folders=("INBOX", "Spamfilter", "Junk", "Trash"), junk="Spamfilter",
                       junk_explicit=True), **kw)
        self.a = Harness(eng, monkeypatch, name="a", user="ole@a-mail.dk", mode="move", **kw)
        self.b = Harness(eng, monkeypatch, name="b", user="sofie@b-mail.dk", mode=mode_b, **kw)
        monkeypatch.setattr(eng, "_now", lambda: self.a.t)
        self.a.rspamd.install(monkeypatch, eng)
        self.b.rspamd = self.a.rspamd
        self.a.poll()
        self.b.poll() if mode_b != "shadow" else None

    def advance(self, s):
        self.a.advance(s)
        self.b.advance(s)

    def mail(self, h, msgid, *, subject=SUBJ, sender=SPAMMER, score=COPY_SCORE, **kw):
        h.deliver(msgid, score=score, subject=subject, sender=sender, **kw)
        h.scan()
        return h.row(msgid)

    def junk_in_a(self, msgid, folder="Spamfilter"):
        self.a.user_moves(msgid, "INBOX", folder)
        self.a.state.last_junk_reconcile = 1e12
        self.a.poll()
        assert self.a.row(msgid)["our_action"] == "user_junked"

    def pass_(self, h):
        return self.eng._campaigns().campaign_pass(self.eng, h.client, h.db, LOG, h.acc, h.acc.folder_map,
                                                   h.state)


def queue(h):
    return {r["message_id"]: dict(r) for r in h.db.conn.execute("SELECT * FROM campaign_queue")}


def events(h, name):
    return [tuple(r) for r in h.db.conn.execute("SELECT account, message_id, detail FROM events WHERE event=? "
                                                "ORDER BY id", (name,))]


# ---------------------------------------------------------------- the flow


def test_user_junk_in_one_mailbox_moves_the_copy_in_the_other(eng, monkeypatch):
    p = Pair(eng, monkeypatch)
    p.mail(p.a, "s1@x")
    assert p.mail(p.b, "s2@x")["our_action"] == "none"
    p.junk_in_a("s1@x")
    q = queue(p.b)
    assert set(q) == {"s2@x"} and q["s2@x"]["account"] == "b" and q["s2@x"]["src_account"] == "a"
    assert q["s2@x"]["match"] == "afsender" and q["s2@x"]["status"] == "queued"
    assert events(p.a, "campaign_sweep") == [("a", "s1@x", "1 kopi sat i kø: b=1")]
    # The target thread was woken up.
    assert eng.engine_state_get(p.b.db.conn, "wake:b")
    assert p.pass_(p.b) == 1
    r = p.b.row("s2@x")
    assert r["our_action"] == "pending_move"
    pm = p.b.db.conn.execute("SELECT * FROM pending_move WHERE account='b'").fetchone()
    assert pm["origin"] == "campaign" and pm["message_id"] == "s2@x"
    [(acct, mid, detail)] = events(p.b, "campaign_move")
    assert acct == "b" and mid == "s2@x" and detail.startswith("Samme spam som i a: samme afsender og emne")
    assert "(kilde s1@x)" in detail
    # Still in the inbox during the short grace; then the engine's own move.
    assert "s2@x" in p.b.client.msgids("INBOX")
    p.advance(campaigns.CAMPAIGN_GRACE_S + 1)
    p.b.moves()
    assert "s2@x" in p.b.client.msgids("Spamfilter") and "s2@x" not in p.b.client.msgids("INBOX")
    r = p.b.row("s2@x")
    assert r["our_action"] == "moved_to_junk" and r["moved_to_junk_at"] and r["current_folder"] == "Spamfilter"
    assert any(d.endswith("(samme spam)") for _a, _m, d in events(p.b, "moved_to_junk"))
    assert "expunge" not in p.b.client.write_names()     # never a plain EXPUNGE / delete
    # Fortryd sees it like any other filter move.
    import services
    prev = services.preview_undo("b", int(p.a.t) - 3600, int(p.a.t) + 60, engine=eng)
    assert prev["count"] == 1, prev
    # Counted for the weekly report.
    assert campaigns.weekly_counts(p.b.db.conn, 0, int(p.a.t) + 60) == {"moved": 1, "shadow": 0}
    assert queue(p.b)["s2@x"]["status"] == "moved"


def test_copy_in_the_same_mailbox_and_domain_match(eng, monkeypatch):
    p = Pair(eng, monkeypatch)
    p.mail(p.a, "s1@x")
    p.mail(p.a, "s3@x", sender="other@spammy.example", subject="RE: " + SUBJ.upper())
    p.mail(p.b, "s4@x", sender="x@gmail.com")                       # freemail: never a domain match
    p.mail(p.b, "s5@x", subject="Noget helt andet")                  # other subject
    p.junk_in_a("s1@x")
    assert set(queue(p.a)) == {"s3@x"} and queue(p.a)["s3@x"]["match"] == "domæne"
    p.pass_(p.a)
    assert p.a.row("s3@x")["our_action"] == "pending_move"
    assert p.b.row("s4@x")["our_action"] == "none" and p.b.row("s5@x")["our_action"] == "none"


def test_shadow_mailbox_only_records(eng, monkeypatch):
    p = Pair(eng, monkeypatch, mode_b="shadow")
    p.mail(p.a, "s1@x")
    p.mail(p.b, "s2@x")
    p.junk_in_a("s1@x")
    p.b.client.writes.clear()
    assert p.pass_(p.b) == 1
    assert p.b.client.writes == []
    assert p.b.row("s2@x")["our_action"] == "none"
    assert p.b.db.conn.execute("SELECT COUNT(*) FROM pending_move WHERE account='b'").fetchone()[0] == 0
    [(_a, _m, detail)] = events(p.b, "campaign_shadow")
    assert "overvåger" in detail
    assert campaigns.weekly_counts(p.b.db.conn, 0, int(p.a.t) + 60) == {"moved": 0, "shadow": 1}


def test_flag_mailbox_flags_the_copy(eng, monkeypatch):
    p = Pair(eng, monkeypatch, mode_b="flag")
    p.mail(p.a, "s1@x")
    uid = p.b.deliver("s2@x", score=COPY_SCORE, subject=SUBJ, sender=SPAMMER)
    p.b.scan()
    p.junk_in_a("s1@x")
    p.pass_(p.b)
    assert "$Junk" in p.b.client.flags_of("INBOX", uid)
    assert p.b.row("s2@x")["our_action"] == "flagged"


def _set(h, msgid, **fields):
    for k, v in fields.items():
        h.db.conn.execute(f"UPDATE messages SET {k}=? WHERE account=? AND message_id=?",
                          (json.dumps(v) if isinstance(v, list) else v, h.acc.name, msgid))


def test_guards_known_contact_allow_rule_verdict_shop_age(eng, monkeypatch):
    p = Pair(eng, monkeypatch)
    p.mail(p.a, "s1@x")
    p.mail(p.b, "kc@x")
    _set(p.b, "kc@x", symbols=[{"n": "TH_KNOWN_CONTACT", "s": -4.0, "o": []}])
    p.mail(p.b, "rel@x")
    _set(p.b, "rel@x", user_verdict="ham", our_action="manual_release")
    p.mail(p.b, "old@x")
    _set(p.b, "old@x", received_at=int(p.a.t) - campaigns.WINDOW_S - 60)
    p.mail(p.b, "ok@x")
    p.junk_in_a("s1@x")
    assert set(queue(p.b)) == {"ok@x"}
    # An allow rule made after the sweep still wins in the target thread.
    eng.add_sender_rule(p.b.db.conn, "b", SPAMMER, "allow", actor="sofie")
    p.pass_(p.b)
    assert p.b.row("ok@x")["our_action"] == "none"
    assert queue(p.b)["ok@x"]["status"] == "skipped" and queue(p.b)["ok@x"]["reason"] == "tilladt afsender"
    assert events(p.b, "campaign_skipped")


def test_vexar_shop_is_never_swept(eng, monkeypatch):
    p = Pair(eng, monkeypatch)
    p.mail(p.a, "s1@x", sender="ordre@vexar.example")
    p.mail(p.b, "s2@x", sender="ordre@vexar.example")
    p.junk_in_a("s1@x")
    assert queue(p.b) == {}
    # ... also when only the copy is from the shop domain (same subject).
    p.mail(p.a, "s6@x", sender="x@shop.vexar.example")
    p.mail(p.b, "s7@x", sender="x@shop.vexar.example")
    p.junk_in_a("s6@x")
    assert queue(p.b) == {}


def test_protected_recipient_with_allow_rule_is_skipped(eng, monkeypatch):
    p = Pair(eng, monkeypatch)
    p.mail(p.a, "s1@x")
    p.mail(p.b, "s2@x")
    _set(p.b, "s2@x", symbols=[{"n": "TH_PROTECTED_RCPT", "s": 0.0, "o": ["info@b-shop.dk", "grænse=18"]}])
    eng.add_sender_rule(p.b.db.conn, "b", "info@b-shop.dk", "allow", actor="admin")
    p.junk_in_a("s1@x")
    p.pass_(p.b)
    assert p.b.row("s2@x")["our_action"] == "none"
    assert queue(p.b)["s2@x"]["reason"] == "beskyttet adresse med Tillad-regel"


def test_starred_or_gone_copy_is_left_alone(eng, monkeypatch):
    p = Pair(eng, monkeypatch)
    p.mail(p.a, "s1@x")
    p.mail(p.b, "s2@x", flags=("\\Flagged",))
    p.mail(p.b, "s3@x")
    p.junk_in_a("s1@x")
    # s3 was deleted in the mail app before the pass ran.
    box = p.b.client.folders["INBOX"]
    for uid, m in list(box.msgs.items()):
        if b"<s3@x>" in m.raw:
            del box.msgs[uid]
    p.pass_(p.b)
    q = queue(p.b)
    assert q["s2@x"]["reason"] == "stjernemarkeret" and q["s3@x"]["reason"] == "ikke længere i indbakken"
    assert p.b.row("s2@x")["our_action"] == "none"


def test_at_most_25_copies_per_verdict(eng, monkeypatch):
    p = Pair(eng, monkeypatch)
    p.mail(p.a, "s1@x")
    for i in range(30):
        p.b.deliver(f"c{i}@x", score=COPY_SCORE, subject=SUBJ, sender=SPAMMER)
    p.b.scan()
    p.junk_in_a("s1@x")
    assert len(queue(p.b)) == campaigns.MAX_PER_TRIGGER == 25
    [(_a, _m, detail)] = events(p.a, "campaign_sweep")
    assert "(loft 25)" in detail


def test_short_subject_never_matches(eng, monkeypatch):
    p = Pair(eng, monkeypatch)
    p.mail(p.a, "s1@x", subject="Hej")
    p.mail(p.b, "s2@x", subject="Hej")
    p.junk_in_a("s1@x")
    assert queue(p.b) == {}


def test_released_copy_stays_released(eng, monkeypatch):
    """A user verdict 'ham' set while the copy waits is sticky."""
    p = Pair(eng, monkeypatch)
    p.mail(p.a, "s1@x")
    p.mail(p.b, "s2@x")
    p.junk_in_a("s1@x")
    _set(p.b, "s2@x", user_verdict="ham")
    p.pass_(p.b)
    assert p.b.row("s2@x")["our_action"] == "none"
    assert queue(p.b)["s2@x"]["reason"] == "brugerens afgørelse"


# ---------------------------------------------------------------- fuzzy


def test_pending_learn_adds_the_source_to_local_fuzzy_once(eng, monkeypatch):
    p = Pair(eng, monkeypatch, learn_grace_seconds=300)
    p.mail(p.a, "s1@x")
    p.junk_in_a("s1@x")
    p.advance(301)
    p.a.poll()
    fz = [c for c in p.a.rspamd.scan_calls if c["url"].endswith("/fuzzyadd")]
    assert len(fz) == 1 and fz[0]["headers"]["Flag"] == str(campaigns.FUZZY_FLAG)
    assert fz[0]["headers"]["Password"] == "pw"
    assert events(p.a, "fuzzy_added") == [("a", "s1@x", "lokal fuzzy-database")]
    assert campaigns.fuzzy_for_verdict(eng, p.a.db.conn, "a", "s1@x", b"raw") == "already"


class _Resp:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


def test_fuzzy_add_backs_off_after_a_failure(eng, tmp_path):
    calls = []

    def post(url, data=None, headers=None, timeout=None):
        calls.append(url)
        return responses.pop(0)

    responses = [_Resp(500), _Resp(200, {"success": True})]
    stub = SimpleNamespace(RSPAMD_LEARN_URL="http://rspamd:11334", requests=SimpleNamespace(post=post),
                           _rspamd_password=lambda: "pw")
    conn = eng.Db("a").conn
    assert campaigns.fuzzy_add(stub, b"x", conn=conn, now=1000) == "failed"
    assert campaigns.fuzzy_add(stub, b"x", conn=conn, now=1000 + 60) == "backoff"
    assert campaigns.fuzzy_add(stub, b"x", conn=conn, now=1000 + campaigns.FUZZY_BACKOFF_S + 1) == "added"
    assert len(calls) == 2 and calls[0] == "http://rspamd:11334/fuzzyadd"
    assert campaigns.fuzzy_add(SimpleNamespace(), b"x") == "unavailable"
    assert campaigns.fuzzy_add(stub, None) == "skipped"


# ---------------------------------------------------------------- helpers


@pytest.mark.parametrize("a,b", [
    ("Re: SV: Din pakke venter", "din pakke venter"),
    ("[SPAM] Din pakke venter", "din pakke venter"),
    ("***SPAM*** Din​ pakke   venter!", "din pakke venter"),
    ("FW: [Nyhedsbrev] Uge 44", "[nyhedsbrev] uge 44"),     # a non-spam tag is kept
])
def test_normalize_subject(a, b):
    assert campaigns.normalize_subject(a) == b


def test_sweep_never_raises_and_rolls_back(eng):
    db = eng.Db("a")
    with db.tx():
        res = campaigns.on_user_spam(db.conn, "a", "missing@x")
    assert res["queued"] == 0 and res["reason"] == "no_verdict"
    db.conn.execute("DROP TABLE campaign_queue")
    db.conn.execute("CREATE TABLE campaign_queue (x)")      # broken schema
    db.conn.execute("INSERT INTO messages(account, message_id, first_seen, last_seen, current_folder, sender, "
                    "subject, user_verdict) VALUES('a','m@x',1,1,'Junk','a@spam.example','Et langt emne her','spam')")
    with db.tx():
        res = campaigns.on_user_spam(db.conn, "a", "m@x")
    assert res["reason"] == "error"


def test_account_loop_runs_the_pass(eng, monkeypatch):
    p = Pair(eng, monkeypatch)
    p.mail(p.a, "s1@x")
    p.mail(p.b, "s2@x")
    p.junk_in_a("s1@x")
    p.b.loop()
    assert p.b.row("s2@x")["our_action"] == "pending_move"
    p.advance(campaigns.CAMPAIGN_GRACE_S + 1)
    p.b.loop()
    assert p.b.row("s2@x")["our_action"] == "moved_to_junk"


# ---------------------------------------------------------------- 2.6 review


def test_provider_junk_move_never_sweeps_or_adds_fuzzy(eng, monkeypatch):
    """Mail that shows up in the provider's own Junk may have been moved by
    the provider after delivery: no campaign sweep, no fuzzy entry."""
    p = Pair(eng, monkeypatch, learn_grace_seconds=300)
    p.mail(p.a, "s1@x")
    p.mail(p.b, "s2@x")
    p.a.user_moves("s1@x", "INBOX", "Junk")
    p.a.state.last_junk_reconcile = 1e12
    p.a.poll()
    assert queue(p.b) == {} and not events(p.a, "campaign_sweep")
    p.advance(301)
    p.a.poll()
    assert not [c for c in p.a.rspamd.scan_calls if c["url"].endswith("/fuzzyadd")]


def test_low_scoring_copy_needs_a_second_independent_verdict(eng, monkeypatch):
    p = Pair(eng, monkeypatch)
    p.mail(p.a, "s1@x")
    p.mail(p.b, "low@x", score=2.0)                 # far below b's threshold 8
    p.mail(p.b, "s3@x", score=2.0)
    p.junk_in_a("s1@x")
    p.pass_(p.b)
    q = queue(p.b)
    assert q["low@x"]["status"] == "skipped" and q["low@x"]["reason"] == campaigns.REASON_FLOOR
    assert p.b.row("low@x")["our_action"] == "none"
    # A second user verdict on the same campaign in ANOTHER mailbox: now it goes.
    p.b.user_moves("s3@x", "INBOX", "Spamfilter")
    p.b.state.last_junk_reconcile = 1e12
    p.b.poll()
    assert queue(p.b)["low@x"]["status"] == "queued"
    p.pass_(p.b)
    assert p.b.row("low@x")["our_action"] == "pending_move"


def test_read_copy_is_never_taken(eng, monkeypatch):
    p = Pair(eng, monkeypatch)
    p.mail(p.a, "s1@x")
    p.mail(p.b, "s2@x")
    p.junk_in_a("s1@x")
    for m in p.b.client.folders["INBOX"].msgs.values():
        if b"<s2@x>" in m.raw:
            m.flags.add("\\Seen")                    # read in the mail app before the pass
    p.pass_(p.b)
    assert queue(p.b)["s2@x"]["reason"] == "læst" and p.b.row("s2@x")["our_action"] == "none"


def test_source_released_before_the_pass_cancels_the_copies(eng, monkeypatch):
    p = Pair(eng, monkeypatch)
    p.mail(p.a, "s1@x")
    p.mail(p.b, "s2@x")
    p.junk_in_a("s1@x")
    # The user changes their mind: the mail goes back to the inbox.
    p.a.user_moves("s1@x", "Spamfilter", "INBOX")
    p.a.scan()
    assert p.a.row("s1@x")["user_verdict"] == "ham"
    assert queue(p.b)["s2@x"]["status"] == "cancelled"
    p.pass_(p.b)
    assert p.b.row("s2@x")["our_action"] == "none"


def test_source_reversed_while_the_copy_waits_restores_it(eng, monkeypatch):
    p = Pair(eng, monkeypatch)
    p.mail(p.a, "s1@x")
    p.mail(p.b, "s2@x")
    p.junk_in_a("s1@x")
    p.pass_(p.b)
    assert p.b.row("s2@x")["our_action"] == "pending_move"
    with p.a.db.tx():
        assert campaigns.cancel_for_source(p.a.db.conn, "a", "s1@x", now=int(p.a.t)) == 1
    assert p.b.row("s2@x")["our_action"] == "none"
    assert p.b.db.conn.execute("SELECT COUNT(*) FROM pending_move WHERE account='b'").fetchone()[0] == 0
    assert queue(p.b)["s2@x"]["status"] == "cancelled" and events(p.b, "campaign_cancelled")
    p.advance(campaigns.CAMPAIGN_GRACE_S + 1)
    p.b.moves()
    assert "s2@x" in p.b.client.msgids("INBOX")


def test_verdict_of_a_released_source_is_rechecked_in_the_pass(eng, monkeypatch):
    p = Pair(eng, monkeypatch)
    p.mail(p.a, "s1@x")
    p.mail(p.b, "s2@x")
    p.junk_in_a("s1@x")
    _set(p.a, "s1@x", user_verdict="ham")             # reversed by another writer
    p.pass_(p.b)
    assert queue(p.b)["s2@x"]["reason"] == campaigns.REASON_SOURCE


def test_hourly_cap_per_target_mailbox(eng, monkeypatch):
    monkeypatch.setattr(campaigns, "MAX_MOVES_PER_HOUR", 2)
    p = Pair(eng, monkeypatch)
    p.mail(p.a, "s1@x")
    for i in range(4):
        p.mail(p.b, f"c{i}@x")
    p.junk_in_a("s1@x")
    p.pass_(p.b)
    st = sorted(r["status"] for r in queue(p.b).values())
    assert st == ["moved", "moved", "queued", "queued"] and events(p.b, "campaign_deferred")
    p.advance(3601)
    p.pass_(p.b)
    assert sorted(r["status"] for r in queue(p.b).values()) == ["moved"] * 4


def test_newsletter_copies_are_candidates_and_leave_the_newsletter_folder(eng, monkeypatch):
    p = Pair(eng, monkeypatch, newsletters="on")
    p.mail(p.a, "s1@x")
    p.mail(p.b, "nlp@x")
    p.mail(p.b, "nlm@x")
    _set(p.b, "nlp@x", our_action="newsletter_pending")
    # nlm@x already sits in the newsletter folder.
    p.b.client.add_folder("Nyhedsbreve")
    p.b.user_moves("nlm@x", "INBOX", "Nyhedsbreve")
    _set(p.b, "nlm@x", our_action="newsletter_moved", current_folder="Nyhedsbreve")
    p.junk_in_a("s1@x")
    assert set(queue(p.b)) == {"nlp@x", "nlm@x"}
    p.pass_(p.b)
    assert p.b.row("nlp@x")["our_action"] == "pending_move"
    assert p.b.row("nlm@x")["our_action"] == "pending_move"
    pm = {r["message_id"]: r["folder"] for r in p.b.db.conn.execute("SELECT * FROM pending_move")}
    assert pm == {"nlp@x": "INBOX", "nlm@x": "Nyhedsbreve"}
    p.advance(campaigns.CAMPAIGN_GRACE_S + 1)
    p.b.moves()
    assert {"nlp@x", "nlm@x"} <= set(p.b.client.msgids("Spamfilter"))
    assert p.b.client.msgids("Nyhedsbreve") == []
    assert p.b.row("nlm@x")["our_action"] == "moved_to_junk"
    assert p.b.db.conn.execute("SELECT COUNT(*) FROM move_journal").fetchone()[0] == 0


def test_declined_learn_never_adds_fuzzy_and_release_removes_it(eng, monkeypatch):
    p = Pair(eng, monkeypatch, learn_grace_seconds=300)
    p.mail(p.a, "s1@x")
    p.junk_in_a("s1@x")
    real = eng.learn_message
    monkeypatch.setattr(eng, "learn_message", lambda *a, **k: "declined")
    p.advance(301)
    p.a.poll()
    assert not [c for c in p.a.rspamd.scan_calls if c["url"].endswith("/fuzzyadd")]
    assert not events(p.a, "fuzzy_added")
    # Learned this time: added. Then rescued by the user and learned as ham: removed.
    monkeypatch.setattr(eng, "learn_message", real)
    with p.a.db.tx():
        p.a.db.conn.execute("UPDATE messages SET pending_learn='spam', pending_learn_at=0, learned_as=NULL "
                            "WHERE message_id='s1@x'")
    p.a.poll()
    assert events(p.a, "fuzzy_added")
    p.a.user_moves("s1@x", "Spamfilter", "INBOX")
    p.a.scan()
    p.advance(301)
    p.a.poll()
    assert [c for c in p.a.rspamd.scan_calls if c["url"].endswith("/fuzzydel")]
    assert events(p.a, "fuzzy_removed")


def test_fuzzy_undo_only_after_an_add(eng):
    calls = []

    def post(url, data=None, headers=None, timeout=None):
        calls.append((url, headers))
        return _Resp(200, {"success": True})

    stub = SimpleNamespace(RSPAMD_LEARN_URL="http://rspamd:11334", requests=SimpleNamespace(post=post),
                           _rspamd_password=lambda: "pw")
    db = eng.Db("a")
    conn = db.conn
    assert campaigns.fuzzy_undo(stub, conn, "a", "m@x", b"raw") == "not_added"
    conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES('a', 1, 'm@x', 'fuzzy_added', '')")
    assert campaigns.fuzzy_undo(stub, conn, "a", "m@x", b"raw") == "removed"
    assert calls[-1][0] == "http://rspamd:11334/fuzzydel" and calls[-1][1]["Flag"] == str(campaigns.FUZZY_FLAG)
    assert campaigns.fuzzy_undo(stub, conn, "a", "m@x", b"raw") == "not_added"


def _verdict(conn, account, mid, sender, *, auth=None, env=None, now, actor="user:move", subject="Et emne her"):
    conn.execute("INSERT INTO messages(account, message_id, first_seen, last_seen, current_folder, sender, subject, "
                 "user_verdict, verdict_at, sender_auth, envelope_from) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                 (account, mid, now, now, "Spamfilter", sender, subject, "spam", now,
                  json.dumps(auth) if auth is not None else None, env))
    campaigns.ensure_schema(conn)
    conn.execute("INSERT INTO campaign_source(account, message_id, campaign_key, actor, at) VALUES(?,?,?,?,?)",
                 (account, mid, "k", actor, now))


def test_block_suggestions_need_genuine_authenticated_verdicts(eng):
    conn = eng.Db("a").conn
    now = 2_000_000_000
    for acc in ("a", "b"):
        _verdict(conn, acc, f"ok-{acc}", "x@spam-shop.example", auth={"dkim": ["spam-shop.example"]}, now=now)
        _verdict(conn, acc, f"forged-{acc}", "x@forged.example", auth={"dkim": ["other.example"]}, now=now)
        _verdict(conn, acc, f"env-{acc}", "x@env.example", env="bounce@mail.env.example", now=now)
        _verdict(conn, acc, f"brand-{acc}", "x@postnord.dk", auth={"dkim": ["postnord.dk"]}, now=now)
    # A user verdict that never started a sweep (the provider's junk): not counted.
    for acc in ("a", "b"):
        conn.execute("INSERT INTO messages(account, message_id, first_seen, last_seen, current_folder, sender, "
                     "user_verdict, verdict_at, sender_auth) VALUES(?,?,?,?,'Junk',?,?,?,?)",
                     (acc, f"prov-{acc}", now, now, "x@provider.example", "spam", now,
                      json.dumps({"dkim": ["provider.example"]})))
    got = {s["domain"] for s in campaigns.block_suggestions(conn, now=now + 60)}
    assert got == {"spam-shop.example", "env.example"}


def test_brand_domains_mirror_the_rspamd_map():
    path = Path(__file__).resolve().parent.parent / "rspamd/local.d/maps.d/th_brand_domains.map"
    doms = {ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.strip().startswith("#")}
    # + the own mail domains of the local site config (rspamd gets them at container start)
    import siteconfig
    assert campaigns.BRAND_DOMAINS == doms | set(siteconfig.get_list("mail_domains"))
    assert not doms & set(siteconfig.get_list("mail_domains"))     # never in the repository map
