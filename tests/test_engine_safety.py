"""ENGINE 2.1: safety nets around moving (E1 circuit breaker + update
hold), fast moves for clear spam (E2), login failure classification (E4)
and health/monitoring (E11)."""

from __future__ import annotations

import logging
import sqlite3
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import GIGAHOST_CAPS, SCANNET_CAPS, FakeIMAP, LoginError, make_account, setup_engine  # noqa: E402
from test_engine_loop import Clock, pw_account, status  # noqa: E402
from test_engine_scan import Harness  # noqa: E402

LOG = logging.getLogger("test")


@pytest.fixture
def eng(tmp_path, monkeypatch):
    e = setup_engine(tmp_path, monkeypatch)
    yield e
    e.SHUTDOWN.clear()


def _quiet(h):
    """No junk poll / housekeeping deadlines in _next_wake_in."""
    h.state.last_junk_poll = h.state.last_retention = time.monotonic()


def _events(h, name):
    return [e for e in h.events(name)]


# ----- E2: fast move for clear spam -------------------------------------------


def test_clear_spam_moves_after_a_few_seconds_borderline_after_grace(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")       # threshold 8, margin 5, grace 60, high 3
    h.deliver("clear@x", score=13.0)
    h.deliver("border@x", score=12.9)
    h.scan()
    rows = {r["message_id"]: r for r in h.db.conn.execute("SELECT * FROM pending_move")}
    assert rows["clear@x"]["due_at"] == int(h.t) + 3 and rows["clear@x"]["score"] == 13.0
    assert rows["border@x"]["due_at"] == int(h.t) + 60 and rows["border@x"]["threshold"] == 8.0
    h.advance(2)
    h.moves()
    assert h.client.msgids("Junk") == []
    h.advance(1)
    h.moves()
    assert h.client.msgids("Junk") == ["clear@x"]
    h.advance(56)
    h.moves()
    assert h.client.msgids("Junk") == ["clear@x"]
    h.advance(1)
    h.moves()
    assert h.client.msgids("Junk") == ["clear@x", "border@x"]


def test_fast_move_config_is_honoured(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", fast_move_margin=2.0, move_grace_seconds_high=10)
    h.deliver("s@x", score=10.0)
    h.scan()
    assert h.db.conn.execute("SELECT due_at FROM pending_move").fetchone()[0] == int(h.t) + 10


def test_next_wake_uses_stored_due_time(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    _quiet(h)
    h.deliver("border@x", score=9.0)
    h.scan()
    assert 59 <= eng._next_wake_in(h.db, h.acc, h.state) <= 60
    h.deliver("clear@x", score=30.0)
    h.scan()
    # 3 s grace, but never a tighter loop than MIN_LOOP_WAIT_S.
    assert eng._next_wake_in(h.db, h.acc, h.state) == eng.MIN_LOOP_WAIT_S


def test_legacy_pending_rows_without_due_at_still_move(eng, monkeypatch):
    """Rows queued by 2.0.x (no due_at/score) use flag_at + grace."""
    h = Harness(eng, monkeypatch, mode="move")
    uid = h.deliver("old@x", score=1)
    h.scan()
    uv = h.client.folders["INBOX"].uidvalidity
    with h.db.tx():
        h.db.conn.execute("INSERT INTO pending_move(account, uidvalidity, uid, message_id, flag_at, folder) "
                          "VALUES(?,?,?,?,?,?)", ("acct", uv, uid, "old@x", int(h.t), "INBOX"))
    h.advance(59)
    h.moves()
    assert h.client.msgids("Junk") == []
    h.advance(1)
    h.moves()
    assert h.client.msgids("Junk") == ["old@x"]


# ----- E1: update hold ----------------------------------------------------------


def test_update_hold_moves_only_clear_spam_for_30_minutes(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", junk_poll_interval=100000, retention_check_interval=100000,
                idle_timeout=1740)
    _quiet(h)
    assert eng.move_hold_until(h.db.conn) == 0          # never started: no hold
    started = eng.record_version_start(h.db.conn)
    assert started == int(h.t) and eng.record_version_start(h.db.conn) == started  # idempotent
    assert eng.move_hold_until(h.db.conn) == started + eng.UPDATE_HOLD_S
    h.deliver("border@x", score=12.0)    # < threshold + 5
    h.deliver("clear@x", score=13.0)     # >= threshold + 5
    h.scan()
    h.advance(120)
    h.moves()
    assert h.client.msgids("Junk") == ["clear@x"]
    wake = eng._next_wake_in(h.db, h.acc, h.state)
    assert abs(wake - (started + eng.UPDATE_HOLD_S - h.t)) < 1
    h.advance(eng.UPDATE_HOLD_S - 120)
    h.moves()
    assert h.client.msgids("Junk") == ["clear@x", "border@x"]


def test_update_hold_also_holds_rows_queued_before_the_update(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    uid = h.deliver("pre@x", score=1)
    h.scan()
    uv = h.client.folders["INBOX"].uidvalidity
    with h.db.tx():   # a 2.0.x row: no score -> held until the hold ends
        h.db.conn.execute("INSERT INTO pending_move(account, uidvalidity, uid, message_id, flag_at, folder) "
                          "VALUES(?,?,?,?,?,?)", ("acct", uv, uid, "pre@x", int(h.t) - 3600, "INBOX"))
    eng.record_version_start(h.db.conn, eng.VERSION)
    h.moves()
    assert h.client.msgids("Junk") == []
    h.advance(eng.UPDATE_HOLD_S)
    h.moves()
    assert h.client.msgids("Junk") == ["pre@x"]


def test_hold_is_per_version(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    eng.record_version_start(h.db.conn, "0.0.1")
    assert eng.move_hold_until(h.db.conn) == 0
    assert eng.move_hold_until(h.db.conn, "0.0.1") == int(h.t) + eng.UPDATE_HOLD_S


# ----- E1: circuit breaker ------------------------------------------------------


def test_circuit_opens_on_hourly_limit_keeps_pending_and_resumes_by_admin(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", circuit_max_moves_per_hour=3, circuit_min_moves=100)
    for i in range(5):
        h.deliver(f"s{i}@x", score=30)
    h.scan()
    h.advance(10)
    h.moves()
    assert len(h.client.msgids("Junk")) == 3 and h.db.count_pending_moves() == 2
    assert eng.circuit_open(h.db.conn, "acct")
    ev = _events(h, "circuit_open")
    assert len(ev) == 1 and "flytninger på en time" in ev[0][2]
    assert status(eng)["state"] == "paused_moves" and status(eng)["move_state"] == "paused"
    # Paused: nothing moves, but scanning goes on and new spam is queued.
    h.advance(3600)
    h.deliver("new@x", score=30)
    h.scan()
    h.moves()
    assert len(h.client.msgids("Junk")) == 3 and h.db.count_pending_moves() == 3
    assert h.row("new@x")["our_action"] == "pending_move"
    eng._status_after_loop(h.db, h.acc, h.state)
    st = status(eng)
    assert st["state"] == "paused_moves" and "Genoptag" in st["detail"] and st["pending_moves"] == 3
    _quiet(h)
    assert eng._next_wake_in(h.db, h.acc, h.state) >= 299  # no busy loop on held moves
    # Admin resumes: the window restarts, the kept moves run.
    assert eng.resume_moves(h.db.conn, "acct", "admin") is True
    assert eng.resume_moves(h.db.conn, "acct", "admin") is False
    assert _events(h, "circuit_resumed")[0][2] == "by admin"
    h.advance(5)
    h.moves()
    assert len(h.client.msgids("Junk")) == 6 and h.db.count_pending_moves() == 0
    assert eng.circuit_status(h.db.conn, "acct")["state"] == "closed"
    eng._status_after_loop(h.db, h.acc, h.state)
    assert status(eng)["state"] == "idle" and status(eng)["move_state"] == "active"


def test_circuit_opens_on_spam_ratio(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", circuit_min_moves=3, circuit_max_ratio=0.4)
    for i in range(3):
        h.deliver(f"s{i}@x", score=30)
    h.deliver("ham1@x", score=0)
    h.deliver("ham2@x", score=0)
    h.scan()
    h.advance(10)
    h.moves()   # 3 of 5 scanned (60 %) would be moved
    assert h.client.msgids("Junk") == [] and h.db.count_pending_moves() == 3
    assert "60 %" in _events(h, "circuit_open")[0][2]


def test_ratio_needs_the_minimum_number_of_moves(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")       # min 10 moves
    for i in range(3):
        h.deliver(f"s{i}@x", score=30)
    h.scan()
    h.advance(10)
    h.moves()
    assert len(h.client.msgids("Junk")) == 3 and not eng.circuit_open(h.db.conn, "acct")


def test_resume_after_a_ratio_trip_runs_the_waiting_moves_without_retripping(eng, monkeypatch):
    """Resuming is the admin's approval of everything that waited: those
    moves run (the hourly quota still applies) and never count towards
    the breaker again; new spam after the resume is judged afresh."""
    h = Harness(eng, monkeypatch, mode="move")       # defaults: 25/h, 40 %, min 10
    for i in range(12):
        h.deliver(f"s{i}@x", score=30)
    for i in range(3):
        h.deliver(f"ham{i}@x", score=0)
    h.scan()
    h.advance(10)
    h.moves()                                         # 12 of 15 = 80 %
    assert h.client.msgids("Junk") == [] and eng.circuit_open(h.db.conn, "acct")
    h.advance(60)
    assert eng.resume_moves(h.db.conn, "acct", "admin")
    h.advance(5)
    h.moves()
    assert len(h.client.msgids("Junk")) == 12 and h.db.count_pending_moves() == 0
    assert not eng.circuit_open(h.db.conn, "acct")
    assert eng._counted_moves(h.db.conn, "acct", 0) == 0
    # New mail after the resume: a normal amount of spam moves ...
    for i in range(4):
        h.deliver(f"new-ham{i}@x", score=0)
    h.deliver("new-spam@x", score=30)
    h.scan()
    h.advance(10)
    h.moves()
    assert "new-spam@x" in h.client.msgids("Junk") and not eng.circuit_open(h.db.conn, "acct")
    # ... and a new flood trips it again, counted only from the resume on.
    for i in range(10):
        h.deliver(f"flood{i}@x", score=30)
    h.scan()
    h.advance(10)
    h.moves()
    assert eng.circuit_open(h.db.conn, "acct") and h.db.count_pending_moves() == 10


def test_approved_moves_still_respect_the_hourly_move_quota(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", max_moves_per_hour=4, circuit_max_moves_per_hour=3,
                circuit_min_moves=100)
    for i in range(8):
        h.deliver(f"s{i}@x", score=30)
    h.scan()
    h.advance(10)
    h.moves()
    assert len(h.client.msgids("Junk")) == 3 and eng.circuit_open(h.db.conn, "acct")
    h.advance(3601)
    eng.resume_moves(h.db.conn, "acct", "admin")
    h.moves()                       # approved, but max_moves_per_hour (4) still caps the batch
    assert len(h.client.msgids("Junk")) == 7 and not eng.circuit_open(h.db.conn, "acct")
    h.advance(3601)
    h.moves()
    assert len(h.client.msgids("Junk")) == 8 and not eng.circuit_open(h.db.conn, "acct")


def test_resume_wakes_the_idling_account_thread(eng, monkeypatch):
    """resume_moves() runs in the WebUI thread; the account thread sitting
    in IDLE (up to 25 min) must notice within one slice."""
    client = FakeIMAP(capabilities=GIGAHOST_CAPS)
    acc = make_account(eng, mode="move", idle_timeout=1500)
    acc.folder_map = {"inbox": "INBOX", "junk": "Junk", "trash": "Trash"}
    db = eng.Db(acc.name)
    state = eng.AccountState(caps=frozenset({"IDLE"}))
    state.last_retention = state.last_junk_poll = time.monotonic()
    eng.open_circuit(db.conn, acc.name, "test")
    checks = []

    def on_check(c):
        checks.append(1)
        if len(checks) == 3:
            other = sqlite3.connect(eng.DB_PATH)
            other.row_factory = sqlite3.Row
            assert eng.resume_moves(other, acc.name, "admin")
            other.close()
        if len(checks) > 6:
            raise AssertionError("IDLE wait did not end after resume")

    client.on_idle_check = on_check
    eng._wait_for_activity(client, db, LOG, acc, state)
    assert len(checks) == 3 and client.idling is False


def test_circuit_state_survives_a_restart_and_blocks_repair(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    assert eng.open_circuit(h.db.conn, "acct", "test") is True
    assert eng.open_circuit(h.db.conn, "acct", "again") is False
    db2 = eng.Db("acct")
    assert eng.circuit_open(db2.conn, "acct") and eng.circuit_status(db2.conn, "acct")["reason"] == "test"
    assert eng.repair_interrupted_moves(h.client, h.db, LOG, h.acc, h.acc.folder_map, h.state) == 0


def test_circuit_config_validation(eng, tmp_path):
    for bad in ({"circuit_max_moves_per_hour": 0}, {"circuit_max_ratio": 0}, {"circuit_max_ratio": 1.5},
                {"circuit_min_moves": 0}, {"move_grace_seconds_high": -1}, {"fast_move_margin": -1}):
        (tmp_path / "accounts.yml").write_text(
            "accounts:\n  - {name: a, user: a@x.dk, imap_host: h, password: p, "
            + ", ".join(f"{k}: {v}" for k, v in bad.items()) + "}\n")
        with pytest.raises(ValueError):
            eng.load_account_configs(tmp_path / "accounts.yml")


# ----- E4: login failure classification -------------------------------------------


@pytest.mark.parametrize("exc,kind", [
    (LoginError("[AUTHENTICATIONFAILED] Authentication failed."), "auth"),
    (LoginError("b'Authentication failed'"), "auth"),
    (LoginError("bad"), "auth"),
    (LoginError("[UNAVAILABLE] Maximum number of connections from user+IP exceeded"), "limit"),
    (LoginError("[LIMIT] Too many sessions"), "limit"),
    (LoginError("[INUSE] Mailbox in use"), "limit"),
    (OSError("Too many connections, try again later"), "limit"),
    (TimeoutError("timed out"), "limit"),
    (ConnectionRefusedError("refused"), "other"),
    # The RFC 5530 response code wins over the free text.
    (LoginError("[UNAVAILABLE] Login failed: authentication backend down"), "limit"),
    (LoginError("[UNAVAILABLE] Temporary authentication failure. [mail:2026-10-21]"), "limit"),
    (LoginError("[AUTHENTICATIONFAILED] Too many failed attempts, try again later"), "auth"),
    (LoginError("[EXPIRED] Password expired"), "auth"),
])
def test_classify_login_error(eng, exc, kind):
    assert eng.classify_login_error(exc) == kind


def test_provider_limits_never_become_auth_failed(eng, monkeypatch, tmp_path):
    clock = Clock(eng, monkeypatch)
    attempts: list[float] = []
    script = [LoginError("[AUTHENTICATIONFAILED] Authentication failed"),
              LoginError("[UNAVAILABLE] Maximum number of connections exceeded"),
              TimeoutError("timed out"),
              LoginError("Authentication failed"),
              LoginError("[UNAVAILABLE] Maximum number of connections exceeded")]

    def connect(acc, password=None):
        attempts.append(clock.t)
        if len(attempts) >= len(script):
            eng.SHUTDOWN.set()
        raise script[len(attempts) - 1]

    monkeypatch.setattr(eng, "connect", connect)
    acc, _pw = pw_account(eng, tmp_path)
    eng._run_account(acc, eng.Db(acc.name))
    st = status(eng)
    assert st["state"] == "limited" and st["login_state"] == "limited"
    # The limit backoff keeps growing across an auth error in between.
    assert st["detail"] == "Udbyderen begrænser forbindelser – prøver igen om 20 min"
    assert st["last_error"].startswith("limit:")
    # auth 5 s, limit 300 s, limit (timeout) 600 s, auth 10 s.
    assert clock.sleeps[:4] == [5, 300, 600, 10]
    conn = sqlite3.connect(eng.DB_PATH)
    names = [r[0] for r in conn.execute("SELECT event FROM events ORDER BY id")]
    assert names.count("login_failed") == 2 and names.count("login_limited") == 3


def test_auth_failures_still_stop_after_three(eng, monkeypatch, tmp_path):
    clock = Clock(eng, monkeypatch)
    n = []

    def connect(acc, password=None):
        n.append(clock.t)
        if len(n) >= 3:
            eng.SHUTDOWN.set()
        raise LoginError("[AUTHENTICATIONFAILED] Authentication failed")

    monkeypatch.setattr(eng, "connect", connect)
    acc, _pw = pw_account(eng, tmp_path)
    eng._run_account(acc, eng.Db(acc.name))
    st = status(eng)
    assert st["state"] == "auth_failed" and st["login_state"] == "auth_failed"
    assert st["retry_at"] == int(clock.t) + eng.AUTH_FAILED_RETRY_S


def test_successful_connect_resets_login_state(eng, monkeypatch, tmp_path):
    Clock(eng, monkeypatch)
    calls = []

    def connect(acc, password=None):
        calls.append(1)
        if len(calls) == 1:
            raise LoginError("[UNAVAILABLE] busy")
        eng.SHUTDOWN.set()
        return FakeIMAP()

    monkeypatch.setattr(eng, "connect", connect)
    monkeypatch.setattr(eng, "_on_connected", lambda *a: None)
    acc, _pw = pw_account(eng, tmp_path)
    eng._run_account(acc, eng.Db(acc.name))
    assert status(eng)["login_state"] == "ok" and status(eng)["retry_at"] is None


# ----- E11: health ----------------------------------------------------------------


def test_health_snapshot_and_stale_watchdog(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("s@x", score=30)
    h.scan()
    h.advance(5)
    h.moves()
    eng._status_after_loop(h.db, h.acc, h.state)
    snap = eng.health_snapshot(h.db.conn)
    assert snap["ok"] is True and snap["version"] == eng.VERSION
    assert snap["accounts"] == {"acct": "idle"}
    d = snap["details"]["acct"]
    assert d["moves_today"] == 1 and d["circuit"] == "closed" and d["stale"] is False
    assert d["last_scan_age_s"] == 5 and d["pending_moves"] == 0
    assert "user@" not in repr(snap)                       # no addresses
    # Silent for > 10 min while "idle": stale (computed and by the watchdog).
    h.advance(eng.STALE_AFTER_S + 1)
    assert eng.health_snapshot(h.db.conn)["accounts"]["acct"] == "stale"
    assert eng.mark_stale_accounts(h.db.conn) == ["acct"]
    assert status(eng)["state"] == "stale" and "min" in status(eng)["detail"]
    assert eng.mark_stale_accounts(h.db.conn) == []         # once
    eng._status_after_loop(h.db, h.acc, h.state)            # the thread is back
    assert status(eng)["state"] == "idle"
    eng.open_circuit(h.db.conn, "acct", "x")
    snap = eng.health_snapshot(h.db.conn)
    assert snap["details"]["acct"]["circuit"] == "open" and snap["details"]["acct"]["circuit_reason"] == "x"


def test_auth_and_limited_are_never_stale(eng):
    conn = sqlite3.connect(eng.DB_PATH)
    for name, state in (("a", "auth_failed"), ("b", "limited"), ("c", "paused"), ("d", "working")):
        eng.update_account_status(conn, name, state=state)
    later = eng._now() + 3600
    assert eng.mark_stale_accounts(conn, now=later) == ["d"]
    assert eng.health_snapshot(conn, now=later)["accounts"] == {
        "a": "auth_failed", "b": "limited", "c": "paused", "d": "stale"}


def test_alive_touch_while_waiting_without_idle(eng, monkeypatch):
    clock = Clock(eng, monkeypatch)
    acc = make_account(eng, mode="move", poll_interval=200)
    db = eng.Db(acc.name)
    state = eng.AccountState(caps=frozenset(SCANNET_CAPS) - {b"IDLE"})
    state.caps = frozenset({"MOVE"})
    state.last_retention = state.last_junk_poll = time.monotonic()
    eng._wait_for_activity(FakeIMAP(), db, LOG, acc, state)
    assert sum(clock.sleeps) == 200 and all(s <= eng.ALIVE_TOUCH_S for s in clock.sleeps)
    assert status(eng)["alive_at"] == int(clock.t)


def test_main_records_version_start(eng, tmp_path, monkeypatch):
    conn = sqlite3.connect(eng.DB_PATH)
    assert eng.engine_state_get(conn, f"version_started:{eng.VERSION}") is None
    eng.record_version_start(conn)
    assert eng.engine_state_get(conn, f"version_started:{eng.VERSION}") is not None
