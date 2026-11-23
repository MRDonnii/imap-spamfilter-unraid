"""trainer: Bayes training / calibration jobs and the bootstrap CLI.

Runs against tests/fakes_services (FakeEngine + FakeIMAP); filter.py is
never imported. FakeIMAP raises on any write to a read-only folder, so
every test here also proves the trainer never writes to IMAP.
"""

import datetime as dt
import sys
import time
from pathlib import Path

import pytest
from imapclient.exceptions import LoginError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "filter"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import bootstrap_train  # noqa: E402
import services  # noqa: E402
import trainer  # noqa: E402
from fakes_services import (  # noqa: E402
    FakeEngine, FakeIMAP, ScanResult, fixture, make_account, make_message, with_msgid,
)

PW = "mail-secret-pw"


@pytest.fixture
def imap():
    return FakeIMAP()


@pytest.fixture
def eng(tmp_path, imap):
    return FakeEngine(tmp_path, imap=imap)


@pytest.fixture(autouse=True)
def fast_limiter(monkeypatch):
    # The 5/s limiter is tested separately; keep job tests fast.
    monkeypatch.setattr(trainer, "MAX_PER_SECOND", 1e9)


def fill(imap, folder, n, **kw):
    return [imap.add(folder, make_message(f"m{i}@x", subject=f"S{i}"), **kw) for i in range(n)]


def job(eng, jid):
    with eng.db() as conn:
        return conn.execute("SELECT * FROM train_jobs WHERE id=?", (jid,)).fetchone()


def queue(eng, kind="ham", folder="INBOX", n=300, **kw):
    if kind == "calibrate":
        return services.queue_calibration("acc", folder, max_messages=n, engine=eng, **kw)
    return services.queue_train_job("acc", folder, kind, n, engine=eng, **kw)


def assert_read_only(imap):
    assert imap.writes == []
    assert imap.selects and all(ro for _f, ro in imap.selects)
    for _uids, items in imap.fetches:
        assert all(i in (b"RFC822.SIZE", b"FLAGS", b"INTERNALDATE") or i.startswith(b"BODY.PEEK[")
                   for i in items)


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------


def test_ham_job_learns_newest_first_up_to_limit(eng, imap):
    uids = fill(imap, "INBOX", 10)
    jid = queue(eng, "ham", n=4, actor="admin")
    assert trainer.run_job(jid, engine=eng) == "done"
    learned = [c["message_id"] for c in eng.learn_calls]
    assert learned == ["m9@x", "m8@x", "m7@x", "m6@x"]  # newest UIDs first
    call = eng.learn_calls[0]
    assert call["kind"] == "ham" and call["bypass_rate"] is True
    assert call["actor"] == "admin" and f"job={jid}" in call["reason"]
    assert "bootstrap" in call["reason"]
    j = job(eng, jid)
    assert (j["status"], j["total"], j["processed"], j["learned"], j["skipped"], j["failed"]) == \
        ("done", 4, 4, 4, 0, 0)
    assert j["started_at"] and j["finished_at"] and j["error"] is None
    assert eng.stat("acc", "learned_ham") == 4
    assert_read_only(imap)
    assert imap.selects == [("INBOX", True)] and imap.logged_out
    assert len(uids) == 10


def test_bodies_fetched_in_chunks_of_20(eng, imap):
    fill(imap, "Junk", 45)
    jid = queue(eng, "spam", folder="Junk", n=45)
    assert trainer.run_job(jid, engine=eng) == "done"
    body_fetches = [u for u, items in imap.fetches if b"BODY.PEEK[]" in items]
    assert [len(u) for u in body_fetches] == [20, 20, 5]
    assert job(eng, jid)["learned"] == 45
    assert eng.stat("acc", "learned_spam") == 45
    assert_read_only(imap)


def test_size_cap_and_already_learned_are_skipped(eng, imap):
    eng.MAX_FETCH_BYTES = 1000
    imap.add("INBOX", make_message("small1@x"))
    imap.add("INBOX", make_message("big@x", size_pad=5000))
    imap.add("INBOX", make_message("known@x"))
    with eng.db() as conn:
        conn.execute("INSERT INTO messages(account, message_id, first_seen, last_seen, "
                     "current_folder, learned_as) VALUES('acc','known@x',0,0,'INBOX','ham')")
    jid = queue(eng, "ham")
    trainer.run_job(jid, engine=eng)
    assert [c["message_id"] for c in eng.learn_calls] == ["small1@x"]
    j = job(eng, jid)
    assert (j["total"], j["processed"], j["learned"], j["skipped"]) == (3, 3, 1, 2)
    body_uids = [u for u, items in imap.fetches if b"BODY.PEEK[]" in items]
    assert body_uids == [[1]]  # neither the oversize nor the known one fetched


def test_already_and_declined_outcomes_count_as_skipped(tmp_path, imap):
    outcomes = iter(["already", "declined", "learned", "rate_limited"])
    eng = FakeEngine(tmp_path, imap=imap, learn_outcome=lambda mid, kind: next(outcomes))
    fill(imap, "INBOX", 4)
    jid = queue(eng, "ham")
    assert trainer.run_job(jid, engine=eng) == "done"
    j = job(eng, jid)
    assert (j["learned"], j["skipped"], j["failed"]) == (1, 3, 0)


def test_seen_only_and_min_age_criteria(eng, imap):
    old = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    imap.add("INBOX", make_message("old-seen@x"), flags=("\\Seen",), internaldate=old)
    imap.add("INBOX", make_message("old-unseen@x"), internaldate=old)
    imap.add("INBOX", make_message("new-seen@x"), flags=("\\Seen",))
    jid = queue(eng, "ham", seen_only=True, min_age_days=30)
    trainer.run_job(jid, engine=eng)
    assert [c["message_id"] for c in eng.learn_calls] == ["old-seen@x"]
    crit = imap.searches[0]
    assert crit[0] == "SEEN" and crit[1] == "BEFORE" and isinstance(crit[2], dt.date)


def test_criteria_helper():
    today = dt.date(2026, 10, 20)
    assert trainer._criteria(False, 0, today) == ["ALL"]
    assert trainer._criteria(True, 10, today) == ["SEEN", "BEFORE", dt.date(2026, 10, 10)]


@pytest.mark.parametrize("pf,expected", [
    ("provider_spam", ["junk1@x", "junk2@x"]),
    ("provider_clean", ["clean1@x", "clean2@x"]),
    ("any", ["unknown@x", "junk2@x", "clean2@x", "junk1@x"]),
])
def test_provider_filter_uses_mailctx_on_headers(eng, imap, pf, expected):
    imap.add("Junk", with_msgid(fixture("gigahost_inbound.eml"), "clean1@x"))
    imap.add("Junk", with_msgid(fixture("gigahost_junk.eml"), "junk1@x"))
    imap.add("Junk", with_msgid(fixture("scannet_inbound.eml"), "clean2@x"))
    imap.add("Junk", with_msgid(fixture("scannet_junk.eml"), "junk2@x"))
    imap.add("Junk", with_msgid(fixture("missing_received.eml"), "unknown@x"))
    jid = queue(eng, "spam", folder="Junk", provider_filter=pf, n=4)
    trainer.run_job(jid, engine=eng)
    got = [c["message_id"] for c in eng.learn_calls]
    assert sorted(got) == sorted(expected)
    if pf == "any":
        assert got == ["unknown@x", "junk2@x", "clean2@x", "junk1@x"]


def test_message_without_message_id_learns_directly(eng, imap):
    imap.add("INBOX", make_message(None))
    jid = queue(eng, "spam", allow_inbox_spam=True)
    trainer.run_job(jid, engine=eng)
    assert eng.learn_calls == [] and eng.rspamd_learn_calls == [("spam", "hjemmeserver")]
    assert job(eng, jid)["learned"] == 1
    assert eng.stat("acc", "learned_spam") == 1


# ---------------------------------------------------------------------------
# Cancel / shutdown / failures
# ---------------------------------------------------------------------------


def test_cancel_requested_stops_after_current_chunk(tmp_path, imap):
    eng = FakeEngine(tmp_path, imap=imap)

    def outcome(mid, kind):
        if len(eng.learn_calls) == 1:
            services.cancel_train_job(jid, engine=eng)
        return "learned"

    eng.learn_outcome = outcome
    fill(imap, "INBOX", 50)
    jid = queue(eng, "ham", n=50)
    assert trainer.run_job(jid, engine=eng) == "cancelled"
    j = job(eng, jid)
    assert j["status"] == "cancelled" and j["finished_at"]
    assert j["learned"] == 20 and len(eng.learn_calls) == 20


def test_cancel_queued_job_is_never_run(eng, imap):
    fill(imap, "INBOX", 3)
    jid = queue(eng, "ham")
    services.cancel_train_job(jid, engine=eng)
    assert trainer.run_job(jid, engine=eng) == "skipped"
    assert trainer.run_pending_once(engine=eng) is None
    assert eng.learn_calls == []


def test_shutdown_requeues_job(tmp_path, imap):
    eng = FakeEngine(tmp_path, imap=imap)

    def outcome(mid, kind):
        eng.SHUTDOWN.set()
        return "learned"

    eng.learn_outcome = outcome
    fill(imap, "INBOX", 30)
    jid = queue(eng, "ham", n=30)
    assert trainer.run_job(jid, engine=eng) == "queued"
    j = job(eng, jid)
    assert j["status"] == "queued" and j["finished_at"] is None


def test_consecutive_rspamd_failures_abort(tmp_path, imap):
    eng = FakeEngine(tmp_path, imap=imap, learn_outcome="error")
    fill(imap, "INBOX", 30)
    jid = queue(eng, "ham", n=30)
    assert trainer.run_job(jid, engine=eng) == "failed"
    j = job(eng, jid)
    assert j["failed"] == trainer.MAX_CONSECUTIVE_FAILURES and "rspamd" in j["error"]


@pytest.mark.parametrize("setup,needle", [
    (lambda e, i: setattr(e, "connect_error", LoginError(f"NO {PW}")), "logge ind"),
    (lambda e, i: setattr(e, "secret", None), "Adgangskoden"),
    (lambda e, i: setattr(e, "accounts", []), "Kontoen"),
])
def test_setup_failures_store_safe_danish_error(eng, imap, setup, needle):
    jid = queue(eng, "ham")
    setup(eng, imap)
    assert trainer.run_job(jid, engine=eng) == "failed"
    err = job(eng, jid)["error"]
    assert needle in err and PW not in err


def test_missing_folder_fails_cleanly(eng, imap):
    jid = queue(eng, "spam", folder="Nope")
    assert trainer.run_job(jid, engine=eng) == "failed"
    assert "Mappen" in job(eng, jid)["error"] and imap.logged_out


def test_unexpected_exception_hides_text(eng, imap):
    fill(imap, "INBOX", 2)
    imap.fail_on["search"] = RuntimeError(f"LOGIN {PW}")
    jid = queue(eng, "ham")
    assert trainer.run_job(jid, engine=eng) == "failed"
    assert PW not in job(eng, jid)["error"]


# ---------------------------------------------------------------------------
# Calibration
# ---------------------------------------------------------------------------


def test_calibration_scans_and_stores_without_learning(tmp_path, imap):
    def scan(raw, acc, ctx):
        return ScanResult(score=7.0, action="add header",
                          symbols=[{"n": "BAYES_SPAM", "s": 5.0, "o": ["99%"]}])

    eng = FakeEngine(tmp_path, imap=imap, scan=scan)
    imap.add("INBOX", with_msgid(fixture("gigahost_junk.eml"), "j@x"), flags=("\\Seen",))
    imap.add("INBOX", make_message("plain@x", sender="Bob <bob@example.org>", subject="Hej"))
    jid = queue(eng, "calibrate", n=10)
    assert trainer.run_job(jid, engine=eng) == "done"
    assert eng.learn_calls == [] and eng.rspamd_learn_calls == []
    assert eng.scan_calls[0]["ctx"]["headers"]["Rcpt"] == "user@example-a.dk"
    rows = {r["message_id"]: r for r in services.calibration_results(jid, engine=eng)}
    assert rows["j@x"]["rspamd_score"] == 7.0 and rows["j@x"]["final_score"] == 11.0
    assert rows["j@x"]["provider_flag"] == 1 and rows["j@x"]["seen"] == 1
    assert [s["n"] for s in rows["j@x"]["symbols"]] == ["BAYES_SPAM", "TH_PROVIDER_SPAM"]
    assert rows["plain@x"]["final_score"] == 7.0 and rows["plain@x"]["sender"] == "bob@example.org"
    assert rows["plain@x"]["subject"] == "Hej" and rows["plain@x"]["received_at"]
    assert job(eng, jid)["learned"] == 2
    assert eng.stat("acc", "learned_ham") == 0
    # Blind score (S4): without BAYES_* / TH_PROVIDER_* / SPAM_FLAG.
    assert rows["j@x"]["blind_score"] == 2.0 and rows["plain@x"]["blind_score"] == 2.0
    with eng.db() as conn:
        assert "blind_score" in {r[1] for r in conn.execute("PRAGMA table_info(calibration_results)")}
        assert conn.execute("SELECT COUNT(*) FROM calibration_results WHERE blind_score IS NULL"
                            ).fetchone()[0] == 0
    summ = services.calibration_summary(jid, [5.0, 10.0], engine=eng)
    assert [c["n"] for c in summ["caught_at"]] == [2, 1]
    assert [c["n"] for c in summ["blind"]["caught_at"]] == [0, 0]
    assert summ["blind_from_symbols"] is False
    assert_read_only(imap)


def test_calibration_respects_provider_bonus_switch(tmp_path, imap):
    eng = FakeEngine(tmp_path, imap=imap, accounts=[make_account(provider_bonus=False)])
    imap.add("INBOX", with_msgid(fixture("scannet_junk.eml"), "s@x"))
    jid = queue(eng, "calibrate")
    trainer.run_job(jid, engine=eng)
    [r] = services.calibration_results(jid, engine=eng)
    assert r["final_score"] == r["rspamd_score"] == 1.5


def test_calibration_scan_errors_count_as_failed(tmp_path, imap):
    def scan(raw, acc, ctx):
        raise RuntimeError("rspamd down")

    eng = FakeEngine(tmp_path, imap=imap, scan=scan)
    fill(imap, "INBOX", 3)
    jid = queue(eng, "calibrate")
    assert trainer.run_job(jid, engine=eng) == "done"
    assert job(eng, jid)["failed"] == 3


# ---------------------------------------------------------------------------
# Rate limiter, queue runner, thread
# ---------------------------------------------------------------------------


def test_rate_limiter_allows_five_per_second():
    now = [100.0]
    slept = []

    def sleep(s):
        slept.append(s)
        now[0] += s

    lim = trainer.RateLimiter(5.0, clock=lambda: now[0], sleep=sleep)
    for _ in range(11):
        lim.wait()
    assert now[0] - 100.0 == pytest.approx(2.0)
    assert all(s == pytest.approx(0.2) for s in slept) and len(slept) == 10


def test_job_uses_rate_limiter(eng, imap, monkeypatch):
    waits = []
    monkeypatch.setattr(trainer.RateLimiter, "wait", lambda self: waits.append(1))
    fill(imap, "INBOX", 7)
    trainer.run_job(queue(eng, "ham"), engine=eng)
    assert len(waits) == 7


def test_run_pending_once_takes_oldest_and_recover(eng, imap):
    fill(imap, "INBOX", 1)
    j1 = queue(eng, "ham")
    j2 = queue(eng, "spam", allow_inbox_spam=True)
    with eng.db() as conn:
        conn.execute("UPDATE train_jobs SET status='running' WHERE id=?", (j2,))
    trainer.recover_interrupted(engine=eng)
    assert job(eng, j2)["status"] == "queued"
    assert trainer.run_pending_once(engine=eng) == j1
    assert trainer.run_pending_once(engine=eng) == j2
    assert trainer.run_pending_once(engine=eng) is None


def test_start_thread_runs_queued_job_and_stops_on_shutdown(eng, imap, monkeypatch):
    monkeypatch.setattr(trainer, "POLL_INTERVAL_S", 0.05)
    monkeypatch.setattr(trainer, "_thread", None)
    fill(imap, "INBOX", 2)
    jid = queue(eng, "ham")
    t = trainer.start(engine=eng)
    assert t.daemon and t.name == "trainer"
    assert trainer.start(engine=eng) is t  # idempotent
    deadline = time.time() + 5
    while job(eng, jid)["status"] != "done" and time.time() < deadline:
        time.sleep(0.02)
    assert job(eng, jid)["status"] == "done"
    eng.SHUTDOWN.set()
    t.join(2)
    assert not t.is_alive()


# ---------------------------------------------------------------------------
# bootstrap_train CLI
# ---------------------------------------------------------------------------


def test_cli_dry_run_changes_nothing(eng, imap, capsys):
    fill(imap, "Junk", 5)
    assert bootstrap_train.main(["acc", "Junk", "spam", "--dry-run", "--limit", "3"],
                                engine=eng) == 0
    out = capsys.readouterr().out
    assert out.count("would learn-spam") == 3 and "3 message(s) selected" in out
    assert eng.learn_calls == [] and eng.rspamd_learn_calls == []
    assert services.list_train_jobs(engine=eng) == []
    assert_read_only(imap)


def test_cli_default_limit_is_300_and_runs_job(eng, imap, capsys):
    fill(imap, "INBOX", 3)
    assert bootstrap_train.main(["acc", "INBOX", "ham"], engine=eng) == 0
    [j] = services.list_train_jobs(engine=eng)
    assert j["max_messages"] == 300 and j["status"] == "done" and j["created_by"] == "cli"
    assert len(eng.learn_calls) == 3
    assert "done" in capsys.readouterr().out
    assert_read_only(imap)


def test_cli_queue_only_and_calibrate(eng, imap):
    assert bootstrap_train.main(["acc", "INBOX", "calibrate", "--queue"], engine=eng) == 0
    [j] = services.list_train_jobs(engine=eng)
    assert j["kind"] == "calibrate" and j["status"] == "queued"
    assert eng.scan_calls == []


def test_cli_calibrate_prints_final_and_blind_catch_counts(tmp_path, imap, capsys):
    def scan(raw, acc, ctx):
        return ScanResult(score=11.0, action="add header",
                          symbols=[{"n": "BAYES_SPAM", "s": 5.0, "o": ["99%"]},
                                   {"n": "R_SPF_FAIL", "s": 1.0}])

    eng = FakeEngine(tmp_path, imap=imap, scan=scan)
    imap.add("Junk", make_message("c1@x"))
    imap.add("Junk", make_message("c2@x"))
    assert bootstrap_train.main(["acc", "Junk", "calibrate"], engine=eng) == 0
    out = capsys.readouterr().out
    assert "calibration: 2 scored" in out
    assert "final score caught >=6:2 >=8:2 >=10:2 >=12:0" in out
    assert "blind score caught >=6:2 >=8:0 >=10:0" in out  # 11 - BAYES 5 = 6
    assert "SPAM_FLAG, TH_PROVIDER_* and BAYES_*" in out
    assert eng.learn_calls == [] and eng.rspamd_learn_calls == []
    assert_read_only(imap)


def test_cli_rejects_bad_input(eng):
    assert bootstrap_train.main(["acc", "INBOX", "ham", "--limit", "0"], engine=eng) == 2
    assert bootstrap_train.main(["nope", "INBOX", "ham"], engine=eng) == 2
    with pytest.raises(SystemExit):
        bootstrap_train.main(["acc", "INBOX", "eggs"], engine=eng)
    assert bootstrap_train.main(["acc", "INBOX", "ham", "--move-to", "Trained-Ham"],
                                engine=eng) == 2
    assert services.list_train_jobs(engine=eng) == []



# ---------------------------------------------------------------------------
# 2.1: blind score, undo jobs in the trainer thread
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("final,symbols,expected", [
    (11.0, [{"n": "BAYES_SPAM", "s": 5.0}, {"n": "TH_PROVIDER_SPAM", "s": 4.0}], 2.0),
    (9.0, [{"n": "SPAM_FLAG", "s": 2.5}, {"n": "TH_PROVIDER_SCORE", "s": 2.0},
           {"n": "R_SPF_FAIL", "s": 1.0}], 4.5),
    (-2.0, [{"n": "BAYES_HAM", "s": -3.0}], 1.0),
    (3.0, [{"n": "TH_PROTECTED_RCPT", "s": 0.0}, "junk", {"s": 1}], 3.0),
    (None, [], None),
])
def test_blind_score(final, symbols, expected):
    assert trainer.blind_score(final, symbols) == expected


def test_blind_column_is_added_to_an_existing_table(eng):
    with eng.db() as conn:
        assert "blind_score" not in {r[1] for r in conn.execute("PRAGMA table_info(calibration_results)")}
    with trainer._open_db(eng) as conn:
        assert trainer.ensure_blind_column(conn) is True
        assert trainer.ensure_blind_column(conn) is True  # idempotent
        assert "blind_score" in {r[1] for r in conn.execute("PRAGMA table_info(calibration_results)")}


def _undo_setup(eng, imap, n=2):
    eng.accounts[0].junk = "Spamfilter"
    eng.accounts[0].junk_explicit = True
    imap.folders.setdefault("Spamfilter", {})
    now = int(time.time())
    with eng.db() as conn:
        for i in range(n):
            imap.add("Spamfilter", make_message(f"u{i}@x"))
            conn.execute("INSERT INTO messages(account, message_id, first_seen, last_seen, "
                         "current_folder, our_action, moved_to_junk_at) VALUES('acc', ?, ?, ?, "
                         "'Spamfilter', 'moved_to_junk', ?)", (f"u{i}@x", now, now, now - 60))
    return now


def test_trainer_resumes_undo_jobs(eng, imap, monkeypatch):
    monkeypatch.setattr(services, "UNDO_PER_SECOND", 1e9)
    monkeypatch.setattr(services, "_spawn_undo_thread", lambda e, j: None)
    monkeypatch.setattr(services, "UNDO_CHUNK", 1)
    now = _undo_setup(eng, imap)
    res = services.undo_moves("acc", now - 3600, now, "admin", wait_s=0, engine=eng)
    assert res["status"] == "queued"
    with eng.db() as conn:  # crash while running
        conn.execute("UPDATE undo_jobs SET status='running' WHERE id=?", (res["job_id"],))
    trainer.recover_interrupted(engine=eng)
    assert services.undo_job(res["job_id"], engine=eng)["status"] == "queued"
    assert trainer.run_pending_undo_once(engine=eng) == res["job_id"]
    assert services.undo_job(res["job_id"], engine=eng)["status"] == "done"
    assert len(imap.folders["INBOX"]) == 2 and eng.learn_calls == []


def test_trainer_thread_runs_undo_jobs(eng, imap, monkeypatch):
    monkeypatch.setattr(trainer, "POLL_INTERVAL_S", 0.05)
    monkeypatch.setattr(trainer, "_thread", None)
    monkeypatch.setattr(services, "UNDO_PER_SECOND", 1e9)
    monkeypatch.setattr(services, "_spawn_undo_thread", lambda e, j: None)
    monkeypatch.setattr(services, "UNDO_CHUNK", 1)
    now = _undo_setup(eng, imap, 3)
    res = services.undo_moves("acc", now - 3600, now, "admin", wait_s=0, engine=eng)
    t = trainer.start(engine=eng)
    deadline = time.time() + 5
    while services.undo_job(res["job_id"], engine=eng)["status"] != "done" and time.time() < deadline:
        time.sleep(0.02)
    assert services.undo_job(res["job_id"], engine=eng)["moved"] == 3
    eng.SHUTDOWN.set()
    t.join(2)
    assert not t.is_alive()


def test_trainer_survives_missing_undo_support(eng, monkeypatch):
    monkeypatch.setattr(trainer, "_services_fn", lambda name: None)
    assert trainer.run_pending_undo_once(engine=eng) is None
    trainer.recover_interrupted(engine=eng)  # no error


# ---------------------------------------------------------------------------
# 2.2 B6c: ham guard in ham jobs
# ---------------------------------------------------------------------------


def _guard(calls):
    def guard(conn, account, *, symbols, final, rspamd_score, sender=None, envelope_from=None,
              trust_limit=None):
        calls.append({"names": [s["n"] for s in symbols], "final": final, "rspamd": rspamd_score,
                      "sender": sender, "limit": trust_limit})
        if any(s["n"] == "TH_BRAND_SPOOF" for s in symbols):
            return ("phishing", "TH_BRAND_SPOOF")
        return None
    return guard


def test_ham_job_scans_first_and_skips_guarded_mail(tmp_path, imap):
    def scan(raw, acc, ctx):
        bad = b"phish@x" in raw
        syms = [{"n": "BAYES_HAM", "s": -3.0, "o": []}] + ([{"n": "TH_BRAND_SPOOF", "s": 5.0, "o": []}] if bad else [])
        return ScanResult(score=2.0 if bad else -1.0, action="no action", symbols=syms)

    eng = FakeEngine(tmp_path, imap=imap, scan=scan)
    calls = []
    eng.ham_guard_reason = _guard(calls)
    imap.add("INBOX", make_message("ok@x", sender="ann@example.org"))
    imap.add("INBOX", make_message("phish@x", sender="PostNord <x@goteamup.example>"))
    jid = queue(eng, "ham")
    assert trainer.run_job(jid, engine=eng) == "done"
    assert [c["message_id"] for c in eng.learn_calls] == ["ok@x"]
    j = job(eng, jid)
    assert j["learned"] == 1 and j["skipped"] == 1 and j["failed"] == 0
    assert calls[0]["limit"] == 8.0 and calls[0]["sender"] == "x@goteamup.example"
    with eng.db() as conn:
        ev = conn.execute("SELECT message_id, detail FROM events WHERE event='ham_guard'").fetchall()
    assert [tuple(e) for e in ev] == [("phish@x", f"job={jid} phishing: TH_BRAND_SPOOF")]
    assert eng.stat("acc", "ham_guarded") == 1
    assert_read_only(imap)


def test_spam_jobs_and_engines_without_guard_do_not_scan(eng, imap):
    fill(imap, "Junk", 2)
    trainer.run_job(queue(eng, "spam", folder="Junk"), engine=eng)
    assert eng.scan_calls == [] and len(eng.learn_calls) == 2
    fill(imap, "INBOX", 2)
    trainer.run_job(queue(eng, "ham"), engine=eng)       # FakeEngine has no ham_guard_reason
    assert eng.scan_calls == []


def test_ham_guard_scan_failure_counts_as_failed(tmp_path, imap):
    def scan(raw, acc, ctx):
        raise RuntimeError("down")

    eng = FakeEngine(tmp_path, imap=imap, scan=scan)
    eng.ham_guard_reason = _guard([])
    fill(imap, "INBOX", 2)
    jid = queue(eng, "ham")
    assert trainer.run_job(jid, engine=eng) == "done"
    assert job(eng, jid)["failed"] == 2 and eng.learn_calls == []


# ---------------------------------------------------------------------------
# 2.2 B6b: stop_ratio (Bayes rebalancing)
# ---------------------------------------------------------------------------


def test_spam_job_stops_when_bayes_ratio_is_reached(eng, imap, monkeypatch):
    monkeypatch.setattr(trainer, "BODY_CHUNK", 2)
    fill(imap, "Junk", 6)
    learned = {"spam": 100}
    monkeypatch.setattr(services, "bayes_stats", lambda engine=None: {
        "ok": True, "spam_learned": learned["spam"] + len(eng.learn_calls), "ham_learned": 206})
    with trainer._open_db(eng) as conn:
        assert trainer.ensure_train_columns(conn) is True
        jid = conn.execute("INSERT INTO train_jobs(account, folder, kind, max_messages, status, created_at, "
                           "stop_ratio) VALUES('acc','Junk','spam',100,'queued',?,0.5)",
                           (int(time.time()),)).lastrowid
    assert trainer.run_job(jid, engine=eng) == "done"
    assert len(eng.learn_calls) == 4                     # 104/206 >= 0.5 after the 2nd chunk
    with eng.db() as conn:
        ev = conn.execute("SELECT detail FROM events WHERE event='train_job_done'").fetchone()[0]
    assert "stop_ratio=0.5 reached" in ev
    # Already balanced: a queued job finishes without connecting.
    with trainer._open_db(eng) as conn:
        jid2 = conn.execute("INSERT INTO train_jobs(account, folder, kind, max_messages, status, created_at, "
                            "stop_ratio) VALUES('acc','Junk','spam',100,'queued',?,0.5)",
                            (int(time.time()),)).lastrowid
    logins = imap.logins
    assert trainer.run_job(jid2, engine=eng) == "done" and imap.logins == logins


def test_stop_ratio_unknown_bayes_keeps_learning(eng, imap, monkeypatch):
    fill(imap, "Junk", 3)
    monkeypatch.setattr(services, "bayes_stats", lambda engine=None: {"ok": False})
    with trainer._open_db(eng) as conn:
        trainer.ensure_train_columns(conn)
        jid = conn.execute("INSERT INTO train_jobs(account, folder, kind, max_messages, status, created_at, "
                           "stop_ratio) VALUES('acc','Junk','spam',100,'queued',?,0.5)",
                           (int(time.time()),)).lastrowid
    assert trainer.run_job(jid, engine=eng) == "done" and len(eng.learn_calls) == 3


def test_bayes_ratio(eng, monkeypatch):
    monkeypatch.setattr(services, "bayes_stats", lambda engine=None: {"ok": True, "spam_learned": 5,
                                                                       "ham_learned": 0})
    assert trainer.bayes_ratio(eng) == float("inf")
    monkeypatch.setattr(services, "bayes_stats", lambda engine=None: {"ok": True, "spam_learned": 0,
                                                                       "ham_learned": 0})
    assert trainer.bayes_ratio(eng) is None


# ---------------------------------------------------------------------------
# 2.2 B6a: learn-list jobs
# ---------------------------------------------------------------------------


def _list(eng, items, kind="spam"):
    res = services.queue_learn_list(items, "owner", kind=kind, engine=eng)
    assert res["ok"], res
    return res["job_id"]


def _items(eng, jid):
    return {(i["account"], i["message_id"]): i for i in services.learn_list_items(jid, engine=eng)}


def test_learn_list_learns_inbox_phishing_as_spam_read_only(eng, imap):
    imap.add("INBOX", make_message("phish@x"))
    imap.add("Junk", make_message("junk@x"))
    jid = _list(eng, [{"account": "acc", "message_id": "<phish@x>"}, ("acc", "junk@x"),
                      ("acc", "gone@x")])
    assert trainer.run_pending_learn_list_once(engine=eng) == jid
    it = _items(eng, jid)
    assert it[("acc", "phish@x")]["status"] == "learned" and it[("acc", "phish@x")]["folder"] == "INBOX"
    assert it[("acc", "junk@x")]["status"] == "learned" and it[("acc", "junk@x")]["folder"] == "Junk"
    assert it[("acc", "gone@x")]["status"] == "not_found"
    assert {(c["message_id"], c["kind"], c["bypass_rate"]) for c in eng.learn_calls} == {
        ("phish@x", "spam", True), ("junk@x", "spam", True)}
    assert all(f"learn_list job={jid}" == c["reason"] and c["actor"] == "owner" for c in eng.learn_calls)
    j = services.learn_list_job(jid, engine=eng)
    assert j["status"] == "done" and j["learned"] == 2 and j["not_found"] == 1 and j["percent"] == 100
    assert imap.writes == [] and all(ro for _f, ro in imap.selects)
    with eng.db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM events WHERE event='learn_list_done'").fetchone()[0] == 1


def test_learn_list_records_previous_class_and_flips(eng, imap):
    imap.add("INBOX", make_message("p@x"))
    with eng.db() as conn:
        conn.execute("INSERT INTO messages(account, message_id, first_seen, last_seen, current_folder, "
                     "learned_as, learned_at) VALUES('acc','p@x',1,1,'INBOX','ham',1)")
    jid = _list(eng, [("acc", "p@x")])
    trainer.run_learn_list_job(jid, engine=eng)
    it = _items(eng, jid)[("acc", "p@x")]
    assert it["previous"] == "ham" and it["status"] == "learned"
    with eng.db() as conn:
        assert conn.execute("SELECT learned_as FROM messages WHERE message_id='p@x'").fetchone()[0] == "spam"


@pytest.mark.parametrize("outcome,status,counter", [
    ("already", "already", "already"), ("declined", "declined", "skipped"),
    ("held_out", "held_out", "skipped"),
    ("rate_limited", "deferred", "skipped"), ("error", "failed", "failed")])
def test_learn_list_outcomes(tmp_path, imap, outcome, status, counter):
    eng = FakeEngine(tmp_path, imap=imap, learn_outcome=outcome)
    imap.add("INBOX", make_message("a@x"))
    jid = _list(eng, [("acc", "a@x")])
    trainer.run_learn_list_job(jid, engine=eng)
    assert _items(eng, jid)[("acc", "a@x")]["status"] == status
    assert services.learn_list_job(jid, engine=eng)[counter] == 1


def test_learn_list_ambiguous_and_too_large(eng, imap, monkeypatch):
    imap.add("INBOX", make_message("dup@x", subject="one"))
    imap.add("INBOX", make_message("dup@x", subject="two"))
    imap.add("Junk", make_message("big@x", body="x" * 200))
    eng.MAX_FETCH_BYTES = 100
    jid = _list(eng, [("acc", "dup@x"), ("acc", "big@x")])
    trainer.run_learn_list_job(jid, engine=eng)
    it = _items(eng, jid)
    assert it[("acc", "dup@x")]["status"] == "ambiguous" and it[("acc", "big@x")]["status"] == "too_large"
    assert eng.learn_calls == []


def test_learn_list_ham_kind_and_retry(tmp_path, imap):
    outcomes = iter(["rate_limited", "learned"])
    eng = FakeEngine(tmp_path, imap=imap, learn_outcome=lambda mid, kind: next(outcomes))
    imap.add("Junk", make_message("fp@x"))
    jid = _list(eng, [("acc", "fp@x")], kind="ham")
    trainer.run_learn_list_job(jid, engine=eng)
    assert _items(eng, jid)[("acc", "fp@x")]["status"] == "deferred"
    res = services.retry_learn_list(jid, "owner", engine=eng)
    assert res["ok"] and res["total"] == 1
    trainer.run_learn_list_job(res["job_id"], engine=eng)
    assert _items(eng, res["job_id"])[("acc", "fp@x")]["status"] == "learned"
    assert [c["kind"] for c in eng.learn_calls] == ["ham", "ham"]
    assert services.retry_learn_list(res["job_id"], engine=eng)["code"] == "empty"


def test_learn_list_unknown_account_and_connect_failure(tmp_path, imap):
    eng = FakeEngine(tmp_path, imap=imap, accounts=[make_account(), make_account(name="b")])
    imap.add("INBOX", make_message("a@x"))
    jid = _list(eng, [("acc", "a@x"), ("b", "b@x")])
    eng.accounts = [make_account()]          # 'b' removed from the config meanwhile
    trainer.run_learn_list_job(jid, engine=eng)
    it = _items(eng, jid)
    assert it[("acc", "a@x")]["status"] == "learned" and it[("b", "b@x")]["status"] == "failed"
    eng2 = FakeEngine(tmp_path / "2", imap=imap, connect_error=OSError("down"))
    jid2 = _list(eng2, [("acc", "a@x")])
    assert trainer.run_learn_list_job(jid2, engine=eng2) == "done"
    assert _items(eng2, jid2)[("acc", "a@x")]["status"] == "failed"


def test_learn_list_cancel_and_shutdown_resume(eng, imap):
    for i in range(3):
        imap.add("INBOX", make_message(f"m{i}@x"))
    jid = _list(eng, [("acc", f"m{i}@x") for i in range(3)])
    eng.SHUTDOWN.set()
    assert trainer.run_learn_list_job(jid, engine=eng) == "queued"
    assert services.learn_list_job(jid, engine=eng)["status"] == "queued"
    eng.SHUTDOWN.clear()
    assert trainer.run_learn_list_job(jid, engine=eng) == "done"
    assert services.learn_list_job(jid, engine=eng)["learned"] == 3
    jid2 = _list(eng, [("acc", "m0@x")])
    assert services.cancel_learn_list_job(jid2, engine=eng) is True
    assert trainer.run_learn_list_job(jid2, engine=eng) == "skipped"
    assert services.learn_list_job(jid2, engine=eng)["status"] == "cancelled"
    jid3 = _list(eng, [("acc", "m1@x")])
    with eng.db() as conn:
        conn.execute("UPDATE learn_list_jobs SET status='running' WHERE id=?", (jid3,))
    assert services.cancel_learn_list_job(jid3, engine=eng) is True
    trainer.recover_interrupted(engine=eng)
    assert services.learn_list_job(jid3, engine=eng)["status"] == "cancelled"
    jid4 = _list(eng, [("acc", "m2@x")])
    with eng.db() as conn:
        conn.execute("UPDATE learn_list_jobs SET status='running' WHERE id=?", (jid4,))
    trainer.recover_interrupted(engine=eng)
    assert services.learn_list_job(jid4, engine=eng)["status"] == "queued"


def test_trainer_thread_runs_learn_lists(eng, imap, monkeypatch):
    monkeypatch.setattr(trainer, "POLL_INTERVAL_S", 0.05)
    monkeypatch.setattr(trainer, "_thread", None)
    imap.add("INBOX", make_message("t@x"))
    jid = _list(eng, [("acc", "t@x")])
    t = trainer.start(engine=eng)
    deadline = time.time() + 5
    while services.learn_list_job(jid, engine=eng)["status"] != "done" and time.time() < deadline:
        time.sleep(0.02)
    assert services.learn_list_job(jid, engine=eng)["learned"] == 1
    eng.SHUTDOWN.set()
    t.join(2)


# ---------------------------------------------------------------------------
# 2.2 B7: aged calibration scans
# ---------------------------------------------------------------------------


def test_calibration_uses_aged_mode_when_the_engine_supports_it(tmp_path, imap):
    seen = []

    def scan(raw, acc, ctx, aged=False):
        seen.append(aged)
        return ScanResult(score=5.0, action="no action", symbols=[{"n": "BAYES_HAM", "s": -1.0, "o": []}])

    eng = FakeEngine(tmp_path, imap=imap)
    eng.rspamd_scan = scan
    eng.is_aged = lambda acc, received_at: received_at is not None and received_at < time.time() - 6 * 3600
    eng.scan_age_s = lambda received_at: int(time.time() - received_at)
    eng.aged_symbols = lambda ctx, age: [{"n": "TH_AGED_SCAN", "s": 0.0, "o": ["alder=1t"]},
                                         {"n": "TH_PROVIDER_AUTH_PASS", "s": -1.0, "o": []}]
    imap.add("INBOX", make_message("old@x"))                       # 2026-10-20: old
    imap.add("INBOX", make_message("new@x"), internaldate=dt.datetime.now(dt.timezone.utc))
    jid = queue(eng, "calibrate")
    trainer.run_job(jid, engine=eng)
    rows = {r["message_id"]: r for r in services.calibration_results(jid, engine=eng)}
    assert sorted(seen) == [False, True]
    assert rows["old@x"]["aged"] == 1 and rows["old@x"]["final_score"] == 4.0
    assert rows["new@x"]["aged"] == 0 and rows["new@x"]["final_score"] == 5.0
    # TH_PROVIDER_AUTH_* is not "knowing the answer": it stays in the blind score.
    assert rows["old@x"]["blind_score"] == 5.0
    summ = services.calibration_summary(jid, [4.5], engine=eng)
    assert summ["aged_count"] == 1 and summ["fresh_count"] == 1 and summ["count"] == 2
    assert services.calibration_summary(jid, [4.5], aged="exclude", engine=eng)["count"] == 1
    assert services.calibration_summary(jid, [4.5], aged="only", engine=eng)["caught_at"][0]["n"] == 0


def test_blind_score_keeps_provider_auth():
    assert trainer.blind_score(1.0, [{"n": "TH_PROVIDER_AUTH_FAIL", "s": 2.0},
                                     {"n": "TH_PROVIDER_SPAM", "s": 4.0}]) == -3.0


def test_learn_list_retry_resumes_pending_items_of_a_cancelled_job(eng, imap):
    jid = _list(eng, [("acc", "a@x"), ("acc", "b@x")])
    assert services.retry_learn_list(jid, engine=eng)["code"] == "empty"     # queued: nothing to retry
    assert services.cancel_learn_list_job(jid, engine=eng) is True             # queued -> cancelled
    job = services.learn_list_job(jid, engine=eng)
    assert job["status"] == "cancelled" and job["retryable"] == 2
    assert {j["id"]: j["retryable"] for j in services.list_learn_list_jobs(engine=eng)}[jid] == 2
    res = services.retry_learn_list(jid, "owner", engine=eng)
    assert res["ok"] and res["total"] == 2


def test_learn_list_final_skips_are_not_retryable(eng, imap, monkeypatch):
    imap.add("INBOX", make_message("dup@x", subject="one"))
    imap.add("INBOX", make_message("dup@x", subject="two"))
    jid = _list(eng, [("acc", "dup@x")])
    trainer.run_learn_list_job(jid, engine=eng)
    job = services.learn_list_job(jid, engine=eng)
    assert job["status"] == "done" and job["skipped"] == 1 and job["retryable"] == 0
    assert services.retry_learn_list(jid, engine=eng)["code"] == "empty"


# ---------------------------------------------------------------------------
# Bayes rebuild jobs ('Byg Bayes op på ny')
# ---------------------------------------------------------------------------


def _rebuild(eng, *, ratio=2.0, status="running"):
    import services as svc

    with eng.db() as conn:
        svc._ensure_rebuild_schema(conn)
        trainer.ensure_learn_list_schema(conn)
        cur = conn.execute("INSERT INTO bayes_rebuilds(status, pool_old, pool_new, ratio, created_at, archived) "
                           "VALUES(?, 'hjemmeserver', 'hjemmeserver-r2', ?, ?, 0)", (status, ratio, int(time.time())))
        return int(cur.lastrowid)


def _link(eng, rid, jid, role, planned):
    with eng.db() as conn:
        conn.execute("INSERT INTO bayes_rebuild_jobs(rebuild_id, job_type, job_id, role, account, folder, planned) "
                     "VALUES(?, 'train', ?, ?, 'acc', 'x', ?)", (rid, jid, role, planned))


def test_only_rebuild_jobs_bypass_the_flip_flop_cooldown(eng, imap):
    fill(imap, "Junk", 2)
    plain = queue(eng, "spam", folder="Junk", n=2)
    trainer.run_job(plain, engine=eng)
    assert {c["bypass_cooldown"] for c in eng.learn_calls} == {False}
    eng.learn_calls.clear()
    with eng.db() as conn:
        conn.execute("UPDATE messages SET learned_as=NULL")
    rid = _rebuild(eng)
    jid = queue(eng, "spam", folder="Junk", n=2)
    _link(eng, rid, jid, "spam", 2)
    trainer.run_job(jid, engine=eng)
    assert [c["bypass_cooldown"] for c in eng.learn_calls] == [True, True]
    assert all(c["bypass_rate"] for c in eng.learn_calls)


def test_rebuild_ham_job_stops_at_ratio_times_spam_learned(eng, imap):
    fill(imap, "Junk", 3)
    for i in range(10):
        imap.add("Arkiv", make_message(f"h{i}@x"))
    rid = _rebuild(eng, ratio=2.0)
    sj = queue(eng, "spam", folder="Junk", n=3)
    hj = queue(eng, "ham", folder="Arkiv", n=10)
    _link(eng, rid, sj, "spam", 3)
    _link(eng, rid, hj, "ham", 10)
    eng.learn_outcome = lambda mid, kind: "declined" if mid == "m2@x" else "learned"
    assert trainer.run_job(sj, engine=eng) == "done"
    assert job(eng, sj)["learned"] == 2
    assert trainer.run_job(hj, engine=eng) == "done"
    assert job(eng, hj)["learned"] == 4  # 2 x 2 spam really learned, not the planned 10
    with eng.db() as conn:
        r = conn.execute("SELECT status, learned_spam, learned_ham FROM bayes_rebuilds WHERE id=?",
                         (rid,)).fetchone()
        ev = conn.execute("SELECT detail FROM events WHERE event='bayes_rebuild_done'").fetchone()
    assert tuple(r) == ("done", 2, 4) and f"rebuild={rid}" in ev[0]


def test_rebuild_never_flips_a_mail_it_learned_as_spam(eng, imap):
    imap.add("Arkiv", make_message("spam-in-archive@x"))
    imap.add("Arkiv", make_message("verdict@x"))
    imap.add("Arkiv", make_message("ok@x"))
    with eng.db() as conn:
        conn.execute("INSERT INTO messages(account, message_id, first_seen, last_seen, current_folder, learned_as, "
                     "learned_at) VALUES('acc', 'spam-in-archive@x', 0, 0, 'Arkiv', 'spam', 1)")
        conn.execute("INSERT INTO messages(account, message_id, first_seen, last_seen, current_folder, "
                     "user_verdict) VALUES('acc', 'verdict@x', 0, 0, 'Arkiv', 'spam')")
    rid = _rebuild(eng)
    hj = queue(eng, "ham", folder="Arkiv", n=10)
    _link(eng, rid, hj, "ham", 3)
    with eng.db() as conn:  # a spam job of the rebuild learned 5 (cap 10)
        conn.execute("INSERT INTO train_jobs(account, folder, kind, max_messages, status, learned, created_at) "
                     "VALUES('acc', 'Junk', 'spam', 5, 'done', 5, 0)")
        sid = conn.execute("SELECT MAX(id) FROM train_jobs").fetchone()[0]
    _link(eng, rid, sid, "spam", 5)
    trainer.run_job(hj, engine=eng)
    assert [c["message_id"] for c in eng.learn_calls] == ["ok@x"]
    # Outside a rebuild the normal rules apply (the cooldown lives in the engine).
    plain = queue(eng, "ham", folder="Arkiv", n=10)
    eng.learn_calls.clear()
    trainer.run_job(plain, engine=eng)
    assert "spam-in-archive@x" in [c["message_id"] for c in eng.learn_calls]
