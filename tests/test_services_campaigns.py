"""2.6: the WebUI side of A2 (a spam verdict queues the campaign's copies),
A3 block suggestions and the A6 watch for protected recipients."""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "filter"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import campaigns  # noqa: E402
import services  # noqa: E402
from fakes_engine import FakeIMAP as EngineIMAP, make_account as engine_account, setup_engine  # noqa: E402
from fakes_services import FakeEngine, FakeIMAP, make_message  # noqa: E402

NOW = int(time.time())
SUBJ = "Din pakke kunne ikke leveres - betal told"  # ASCII: the services fake does not decode headers
LOG = logging.getLogger("test-services-campaigns")


def _msg(conn, account, mid, *, sender="no-reply@pakke-spam.example", subject=SUBJ, folder="INBOX", **kw):
    row = {"account": account, "message_id": mid, "first_seen": NOW - 600, "last_seen": NOW - 600,
           "current_folder": folder, "our_action": "none", "sender": sender, "subject": subject,
           "received_at": NOW - 600, "our_score": 2.0, "symbols": "[]"}
    row.update(kw)
    if isinstance(row.get("symbols"), list):
        row["symbols"] = json.dumps(row["symbols"])
    conn.execute(f"INSERT OR REPLACE INTO messages({','.join(row)}) VALUES({','.join('?' * len(row))})",
                 list(row.values()))


# ---------------------------------------------------------------- A2 from the WebUI


@pytest.mark.parametrize("action,trigger", [("mark_spam", "manual_mark_spam"), ("learn_spam", "manual_learn_spam")])
def test_webui_spam_verdict_queues_the_copies(tmp_path, action, trigger):
    imap = FakeIMAP()
    eng = FakeEngine(tmp_path, imap=imap)
    imap.add("INBOX", make_message("src@x", subject=SUBJ, sender="no-reply@pakke-spam.example"))
    with eng.db() as conn:
        _msg(conn, "acc", "copy@x")
        _msg(conn, "acc", "other@x", subject="Helt andet emne her")
    [res] = services.mail_action("acc", ["src@x"], action, "admin", engine=eng)
    assert res["ok"], res
    with eng.db() as conn:
        q = conn.execute("SELECT * FROM campaign_queue").fetchall()
        assert [(r["account"], r["message_id"], r["src_message_id"], r["trigger"], r["actor"]) for r in q] == \
            [("acc", "copy@x", "src@x", trigger, "admin")]
        ev = conn.execute("SELECT detail FROM events WHERE event='campaign_sweep'").fetchall()
        assert [e[0] for e in ev] == ["1 kopi sat i kø: acc=1"]
        # FakeEngine has no rspamd controller: no fuzzy write was tried.
        assert conn.execute("SELECT COUNT(*) FROM events WHERE event LIKE 'fuzzy_%'").fetchone()[0] == 0


def test_release_never_sweeps(tmp_path):
    imap = FakeIMAP()
    eng = FakeEngine(tmp_path, imap=imap)
    imap.add("Junk", make_message("src@x", subject=SUBJ, sender="no-reply@pakke-spam.example"))
    with eng.db() as conn:
        _msg(conn, "acc", "copy@x")
    services.mail_action("acc", ["src@x"], "release", "admin", engine=eng)
    with eng.db() as conn:
        n = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='campaign_queue'").fetchone()[0]
        assert n == 0 or conn.execute("SELECT COUNT(*) FROM campaign_queue").fetchone()[0] == 0


@pytest.mark.parametrize("undo", ["release", "learn_ham"])
def test_webui_release_or_ham_of_the_source_cancels_its_copies(tmp_path, undo):
    imap = FakeIMAP()
    eng = FakeEngine(tmp_path, imap=imap)
    imap.add("INBOX", make_message("src@x", subject=SUBJ, sender="no-reply@pakke-spam.example"))
    with eng.db() as conn:
        _msg(conn, "acc", "copy@x")
    [res] = services.mail_action("acc", ["src@x"], "mark_spam", "admin", engine=eng)
    assert res["ok"], res
    [res] = services.mail_action("acc", ["src@x"], undo, "admin", engine=eng)
    assert res["ok"], res
    with eng.db() as conn:
        q = conn.execute("SELECT status, reason FROM campaign_queue WHERE message_id='copy@x'").fetchone()
        assert q["status"] == "cancelled" and q["reason"].startswith("kilden ")
        src = conn.execute("SELECT cancelled_at FROM campaign_source WHERE message_id='src@x'").fetchone()
        assert src["cancelled_at"] is not None
        assert not campaigns.source_active(conn, "acc", "src@x")


def test_weekly_report_counts_campaign_moves(tmp_path, monkeypatch):
    eng = setup_engine(tmp_path, monkeypatch)
    db = eng.Db("acct")
    week = eng.last_week_label()
    monday = services.parse_week(week)
    ts = services._local_midnight_ts(monday) + 3600
    for i in range(3):
        db.conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                        ("acct", ts, f"m{i}@x", "moved_to_junk", "uid=1 -> Junk (samme spam)"))
    db.conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                    ("acct", ts, "z@x", "moved_to_junk", "uid=2 -> Junk (genscanning)"))
    data = services.weekly_data(week, engine=eng)
    assert data["campaign"] == {"moved": 3, "shadow": 0}
    out = services.render_weekly(data, full=True)
    assert "Samme spam på flere postkasser: 3 flyttet" in out["text"]


# ---------------------------------------------------------------- A3


@pytest.fixture
def eng(tmp_path, monkeypatch):
    return setup_engine(tmp_path, monkeypatch)


def _spam(conn, account, mid, sender, **kw):
    """A genuine user verdict (it started a campaign sweep), From domain
    authenticated by a DKIM signature of its own."""
    dom = sender.rpartition("@")[2]
    kw.setdefault("sender_auth", json.dumps({"dkim": [dom], "host": None}))
    _msg(conn, account, mid, sender=sender, folder="Junk", our_action="user_junked", user_verdict="spam",
         verdict_at=NOW - 3600, **kw)
    campaigns.ensure_schema(conn)
    conn.execute("INSERT OR REPLACE INTO campaign_source(account, message_id, campaign_key, trigger, actor, at) "
                 "VALUES(?,?,?,?,?,?)", (account, mid, "k", "user_junked", "user:move", NOW - 3600))


def test_block_suggestion_needs_two_marks_from_two_mailboxes(eng):
    conn = eng.Db("a").conn
    _spam(conn, "a", "1@x", "x@mail.spam-shop.example")
    assert campaigns.block_suggestions(conn, now=NOW) == []
    _spam(conn, "a", "2@x", "y@spam-shop.example")
    assert campaigns.block_suggestions(conn, now=NOW) == []          # one mailbox only
    _spam(conn, "b", "3@x", "z@news.spam-shop.example")
    assert campaigns.block_suggestions(conn, now=NOW) == [
        {"domain": "spam-shop.example", "n": 3, "accounts": ["a", "b"]}]
    # The service wrapper agrees.
    assert services.block_suggestions(engine=eng)[0]["domain"] == "spam-shop.example"


def test_block_suggestion_never_counts_campaign_moves(eng):
    """Only genuine user verdicts count - a campaign copy is the filter's
    own echo of the first verdict."""
    conn = eng.Db("a").conn
    _spam(conn, "a", "1@x", "x@camp.example")
    _msg(conn, "b", "2@x", sender="x@camp.example", folder="Junk", our_action="moved_to_junk")
    campaigns.ensure_schema(conn)
    conn.execute("INSERT INTO campaign_queue(account, message_id, src_account, src_message_id, queued_at, status, "
                 "done_at) VALUES('b','2@x','a','1@x',?, 'moved', ?)", (NOW - 60, NOW - 50))
    assert campaigns.block_suggestions(conn, now=NOW) == []


@pytest.mark.parametrize("auth,env,counted", [
    ({"dkim": ["other.example"]}, None, False),           # signed by somebody else: maybe forged
    (None, "bounce@mail.camp.example", True),             # no stored result: envelope = From domain
    (None, "bounce@esp.example", False),
])
def test_block_suggestion_needs_an_authenticated_from_domain(eng, auth, env, counted):
    conn = eng.Db("a").conn
    for acc, mid in (("a", "1@x"), ("b", "2@x")):
        _spam(conn, acc, mid, "x@camp.example", sender_auth=json.dumps(auth) if auth else None, envelope_from=env)
    got = [s["domain"] for s in campaigns.block_suggestions(conn, now=NOW)]
    assert got == (["camp.example"] if counted else [])


def test_block_suggestion_never_names_a_brand_domain(eng):
    conn = eng.Db("a").conn
    _spam(conn, "a", "1@x", "x@postnord.dk")
    _spam(conn, "b", "2@x", "y@postnord.dk")
    assert campaigns.block_suggestions(conn, now=NOW) == []


@pytest.mark.parametrize("case", ["ham", "released", "freemail", "rule", "parent_rule", "dismissed", "own",
                                  "shared", "old", "refused"])
def test_block_suggestion_exclusions(eng, case):
    conn = eng.Db("a").conn
    dom = {"freemail": "gmail.com", "own": "vexar.example", "shared": "onmicrosoft.com"}.get(case, "bad.example")
    _spam(conn, "a", "1@x", f"x@{dom}")
    _spam(conn, "b", "2@x", f"y@{dom}")
    refuse = None
    if case == "ham":
        _msg(conn, "b", "3@x", sender=f"z@{dom}", user_verdict="ham")
    elif case == "released":
        _msg(conn, "a", "3@x", sender=f"z@sub.{dom}", our_action="manual_release")
    elif case == "rule":
        eng.add_sender_rule(conn, "b", f"x@{dom}", "allow", actor="sofie")
    elif case == "parent_rule":
        eng.add_sender_rule(conn, "*", f"@news.{dom}", "block", actor="admin")  # a subdomain rule exists
    elif case == "dismissed":
        assert campaigns.dismiss_suggestion(conn, f"mail.{dom}", "admin")
    elif case == "old":
        conn.execute("UPDATE messages SET verdict_at=?, last_seen=?", (NOW - 31 * 86400, NOW - 31 * 86400))
    elif case == "refused":
        refuse = lambda p: p == f"@{dom}"  # noqa: E731
    assert campaigns.block_suggestions(conn, now=NOW, refuse=refuse) == []


def test_dismiss_service(eng):
    res = services.dismiss_block_suggestion("Mail.Bad.Example", "admin", engine=eng)
    assert res["ok"] and res["domain"] == "bad.example"
    assert not services.dismiss_block_suggestion("ikke et domæne", "admin", engine=eng)["ok"]


# ---------------------------------------------------------------- A6


PROT = [{"n": "TH_PROTECTED_RCPT", "s": 0.0, "o": ["info@shop.example", "grænse=18"]}]


def _prot_acc(eng, **over):
    base = dict(name="acct", protected_recipients=["info@shop.example"], protected_threshold=18.0, threshold=6.0)
    base.update(over)
    return engine_account(eng, **base)


def _prot_mails(conn, n, *, score=7.0, account="acct", **kw):
    for i in range(n):
        _msg(conn, account, f"p{i}-{score}@x", sender=f"s{i}@spam.example", our_score=score, symbols=PROT, **kw)


def test_protected_watch_counts_only_unhandled_mail_over_the_normal_threshold(eng):
    acc = _prot_acc(eng)
    conn = eng.Db("acct").conn
    _prot_mails(conn, 2)
    _prot_mails(conn, 3, score=5.0)                                    # under the normal threshold
    _msg(conn, "acct", "v@x", our_score=9.0, symbols=PROT, user_verdict="ham")
    _msg(conn, "acct", "m@x", our_score=9.0, symbols=PROT, our_action="moved_to_junk", folder="Junk")
    _msg(conn, "acct", "r@x", our_score=9.0, symbols=PROT, rule_hit="allow:3")
    _msg(conn, "acct", "o@x", our_score=9.0, symbols=PROT, received_at=NOW - 8 * 86400)
    _msg(conn, "acct", "n@x", our_score=9.0)                           # not to a protected address
    assert campaigns.protected_watch_count(conn, acc, now=NOW) == 2
    eng.add_sender_rule(conn, "acct", "s1@spam.example", "allow", actor="admin")
    assert campaigns.protected_watch_count(conn, acc, now=NOW, match_rule=eng.match_sender_rule) == 1
    assert campaigns.protected_watch_count(conn, _prot_acc(eng, mode="shadow"), now=NOW) == 0
    assert campaigns.protected_watch_count(conn, _prot_acc(eng, protected_recipients=[]), now=NOW) == 0


def test_protected_watch_alerts_at_most_once_a_week(eng):
    acc = _prot_acc(eng)
    conn = eng.Db("acct").conn
    _prot_mails(conn, 3)
    calls = []
    stub = SimpleNamespace(alert_once=lambda c, key, ep, subj, text: calls.append((key, subj, text)) or True,
                           match_sender_rule=eng.match_sender_rule)
    assert campaigns.protected_watch_check(stub, conn, acc, now=NOW)
    [(key, subj, text)] = calls
    assert key == "protected:acct"
    assert "spam samler sig i en beskyttet indbakke" in subj
    assert text.startswith("Spam samler sig i en beskyttet indbakke: 3 mails over grænsen – overvej at sænke "
                           "grænsen for beskyttede adresser")
    assert not campaigns.protected_watch_check(stub, conn, acc, now=NOW + 6 * 86400)
    assert campaigns.protected_watch_check(stub, conn, acc, now=NOW + 7 * 86400 + 1) is False  # mails aged out
    _prot_mails(conn, 3, score=8.0, received_at=NOW + 7 * 86400)
    assert campaigns.protected_watch_check(stub, conn, acc, now=NOW + 7 * 86400 + 1)
    assert len(calls) == 2
    ev = conn.execute("SELECT detail FROM events WHERE event='protected_watch_alert'").fetchall()
    assert len(ev) == 2


def test_protected_watch_runs_in_housekeeping_and_pushes(eng, monkeypatch):
    acc = _prot_acc(eng)
    db = eng.Db("acct")
    _prot_mails(db.conn, 4)
    problems = []
    monkeypatch.setattr(eng, "_push_problem", lambda conn, key: problems.append(key))
    monkeypatch.setattr(eng, "_now", lambda: NOW)
    eng._housekeeping(EngineIMAP(), db, LOG, acc, eng.AccountState())
    assert problems == ["protected:acct"]
    assert db.conn.execute("SELECT COUNT(*) FROM events WHERE event='protected_watch_alert'").fetchone()[0] == 1
    eng._housekeeping(EngineIMAP(), db, LOG, acc, eng.AccountState())
    assert problems == ["protected:acct"]                              # not again this week


def test_protected_push_text():
    import push

    title, body, url = push.PROBLEMS["protected"]
    assert title == "Spam i en beskyttet indbakke" and url == "/accounts"
    assert len(body.format(name="Ole (BYnet)")) <= push.BODY_MAX


def test_protected_watch_service(tmp_path, monkeypatch):
    eng = setup_engine(tmp_path, monkeypatch)
    acc = _prot_acc(eng)
    monkeypatch.setattr(eng, "load_account_configs", lambda path=None: [acc])
    _prot_mails(eng.Db("acct").conn, 3)
    assert services.protected_watch(engine=eng) == [
        {"account": "acct", "n": 3, "threshold": 6.0, "protected_threshold": 18.0}]


def test_protected_watch_ignores_mail_over_todays_protected_threshold(eng):
    """2.6.2: the owner lowered the protected threshold to 7; mail that scored 7.8-16 before
    (and was long gone from the inbox) must not raise the alert - new mail like it is moved."""
    acc = _prot_acc(eng, protected_threshold=7.0)
    conn = eng.Db("acct").conn
    for i, score in enumerate((16.5, 12.2, 10.1, 7.8, 7.0)):
        _msg(conn, "acct", f"hi{i}@x", sender=f"h{i}@spam.example", our_score=score, symbols=PROT)
    assert campaigns.protected_watch_count(conn, acc, now=NOW) == 0
    _prot_mails(conn, 2, score=6.6)                                    # between 6 and 7: still counted
    _msg(conn, "acct", "b@x", sender="x@blocked.example", our_score=6.5, symbols=PROT, rule_hit="block:9")
    assert campaigns.protected_watch_count(conn, acc, now=NOW) == 2
    eng.add_sender_rule(conn, "*", "@spam.example", "block", actor="admin")
    assert campaigns.protected_watch_count(conn, acc, now=NOW, match_rule=eng.match_sender_rule) == 0
