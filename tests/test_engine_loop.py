"""ENGINE: account thread robustness, status rows, shutdown and main()
(SPEC E6, E9, E10, E13)."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import (  # noqa: E402
    GIGAHOST_CAPS,
    FakeIMAP,
    FakeRspamd,
    IMAPClientAbortError,
    LoginError,
    make_account,
    setup_engine,
)
from test_engine_scan import Harness  # noqa: E402

LOG = logging.getLogger("test")
T0 = 1_800_000_000.0
SECRET = "S3cr3t-pw!"


@pytest.fixture
def eng(tmp_path, monkeypatch):
    e = setup_engine(tmp_path, monkeypatch)
    yield e
    e.SHUTDOWN.clear()


class Clock:
    """Fake wall clock + _sleep that advances it instantly."""

    def __init__(self, eng, monkeypatch):
        self.t = T0
        self.sleeps: list[float] = []
        self.hooks: list = []
        self.eng = eng
        monkeypatch.setattr(eng, "_now", lambda: self.t)
        monkeypatch.setattr(eng, "_sleep", self.sleep)

    def sleep(self, s):
        self.sleeps.append(s)
        self.t += s
        for hook in self.hooks:
            hook(self)
        return self.eng.SHUTDOWN.is_set()


def status(eng, account="acct"):
    conn = sqlite3.connect(eng.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM account_status WHERE account=?", (account,)).fetchone()
    finally:
        conn.close()


def pw_account(eng, tmp_path, **over):
    pwfile = tmp_path / "acct.pw"
    pwfile.write_text(SECRET + "\n")
    return make_account(eng, password="", password_file=str(pwfile), **over), pwfile


# ----- E6 auth_failed --------------------------------------------------------


def test_auth_failed_after_three_login_errors_waits_30_min(eng, monkeypatch, tmp_path):
    clock = Clock(eng, monkeypatch)
    attempts: list[float] = []

    def connect(acc, password=None):
        attempts.append(clock.t)
        if len(attempts) >= 4:
            eng.SHUTDOWN.set()
        raise LoginError(f"[AUTHENTICATIONFAILED] Authentication failed for {password}")

    monkeypatch.setattr(eng, "connect", connect)
    acc, _pw = pw_account(eng, tmp_path)
    eng._run_account(acc, eng.Db(acc.name))
    assert len(attempts) == 4
    assert attempts[1] - attempts[0] == 5 and attempts[2] - attempts[1] == 10
    assert attempts[3] - attempts[2] >= eng.AUTH_FAILED_RETRY_S
    st = status(eng)
    assert st["state"] == "auth_failed" and "adgangskoden" in st["detail"]
    assert SECRET not in st["last_error"] and st["last_error"].startswith("auth:")
    assert st["error_count"] >= 3


def test_auth_failed_retries_immediately_when_secret_changes(eng, monkeypatch, tmp_path):
    clock = Clock(eng, monkeypatch)
    attempts: list[float] = []
    acc, pwfile = pw_account(eng, tmp_path)

    def connect(acc_, password=None):
        attempts.append(clock.t)
        if len(attempts) >= 4:
            eng.SHUTDOWN.set()
        raise LoginError("bad")

    def touch_secret(c):
        if len(attempts) == 3 and c.t - attempts[2] >= 60 and not getattr(c, "touched", False):
            c.touched = True
            st = os.stat(pwfile)
            os.utime(pwfile, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))

    clock.hooks.append(touch_secret)
    monkeypatch.setattr(eng, "connect", connect)
    eng._run_account(acc, eng.Db(acc.name))
    assert len(attempts) == 4
    assert 60 <= attempts[3] - attempts[2] < 120


def test_unreadable_secret_is_config_error_not_crash(eng, monkeypatch, tmp_path):
    clock = Clock(eng, monkeypatch)
    acc = make_account(eng, password="", password_file=str(tmp_path / "missing.pw"))
    clock.hooks.append(lambda c: eng.SHUTDOWN.set() if len(c.sleeps) >= 2 else None)
    monkeypatch.setattr(eng, "connect", lambda *a, **k: pytest.fail("must not connect"))
    eng._run_account(acc, eng.Db(acc.name))
    st = status(eng)
    assert st["last_error"].startswith("config:") and "Adgangskoden" in st["detail"]


# ----- E6 backoff reset only after a full loop -------------------------------


def test_backoff_resets_only_after_full_loop(eng, monkeypatch, tmp_path):
    clock = Clock(eng, monkeypatch)
    client = FakeIMAP()
    monkeypatch.setattr(eng, "connect", lambda acc, password=None: client)
    monkeypatch.setattr(eng, "_on_connected", lambda *a: None)
    script = iter(["fail", "fail", "ok", "fail", "stop"])

    def loop_once(*a):
        step = next(script)
        if step == "stop":
            eng.SHUTDOWN.set()
            return
        if step == "fail":
            raise IMAPClientAbortError("connection reset")

    def wait(*a):
        raise IMAPClientAbortError("dropped while idling")

    monkeypatch.setattr(eng, "_loop_once", loop_once)
    monkeypatch.setattr(eng, "_wait_for_activity", wait)
    acc, _ = pw_account(eng, tmp_path)
    eng._run_account(acc, eng.Db(acc.name))
    assert clock.sleeps == [5, 10, 5, 10]
    assert status(eng)["state"] == "idle"  # last full loop succeeded


def test_unexpected_exception_is_contained(eng, monkeypatch, tmp_path):
    clock = Clock(eng, monkeypatch)
    client = FakeIMAP()
    monkeypatch.setattr(eng, "connect", lambda acc, password=None: client)
    monkeypatch.setattr(eng, "_on_connected", lambda *a: (_ for _ in ()).throw(KeyError(SECRET)))
    clock.hooks.append(lambda c: eng.SHUTDOWN.set())
    acc, _ = pw_account(eng, tmp_path)
    eng._run_account(acc, eng.Db(acc.name))
    st = status(eng)
    assert st["state"] == "error" and st["last_error"].startswith("internal:")
    assert SECRET not in st["last_error"]
    assert ("logout",) in client.calls


# ----- E6 shutdown latency ----------------------------------------------------


def test_shutdown_within_five_seconds_while_idling(eng, monkeypatch, tmp_path):
    rs = FakeRspamd(eng.requests).install(monkeypatch, eng)
    del rs
    client = FakeIMAP(capabilities=GIGAHOST_CAPS)
    started = threading.Event()

    def idle_check_blocks(c):
        started.set()
        timeout = c.calls[-1][1]
        time.sleep(timeout)  # a real socket read blocks for the whole slice

    client.on_idle_check = idle_check_blocks
    monkeypatch.setattr(eng, "connect", lambda acc, password=None: client)
    acc, _ = pw_account(eng, tmp_path, mode="move", idle_timeout=1500)
    t = threading.Thread(target=eng.account_loop, args=(acc,), daemon=True)
    t.start()
    assert started.wait(10)
    t0 = time.monotonic()
    eng.SHUTDOWN.set()
    t.join(timeout=8)
    elapsed = time.monotonic() - t0
    assert not t.is_alive() and elapsed <= eng.IDLE_SLICE_S + 0.8
    slices = [c[1] for c in client.calls if c[0] == "idle_check"]
    assert slices and all(s <= eng.IDLE_SLICE_S for s in slices)
    assert ("idle_done",) in client.calls and ("logout",) in client.calls
    assert status(eng)["state"] == "stopped"


def test_idle_activity_ends_wait(eng, monkeypatch, tmp_path):
    client = FakeIMAP(capabilities=GIGAHOST_CAPS)
    client.idle_responses = [[(b"OK", b"Still here")], [(5, b"EXISTS")]]
    acc = make_account(eng, mode="move")
    db = eng.Db(acc.name)
    state = eng.AccountState(caps=frozenset({"IDLE"}))
    state.last_retention = state.last_junk_poll = time.monotonic()
    eng._wait_for_activity(client, db, LOG, acc, state)
    assert [c[0] for c in client.calls].count("idle_check") == 2
    assert client.idling is False


def test_idle_done_failure_forces_reconnect(eng):
    client = FakeIMAP(capabilities=GIGAHOST_CAPS)
    client.idle_responses = [[(1, b"EXISTS")]]
    client.fail_on["idle_done"] = OSError("broken pipe")
    acc = make_account(eng, mode="move")
    state = eng.AccountState(caps=frozenset({"IDLE"}))
    with pytest.raises(IMAPClientAbortError):
        eng._wait_for_activity(client, eng.Db(acc.name), LOG, acc, state)


# ----- E8/E9 status rows --------------------------------------------------------


def test_status_row_after_connect_and_loop(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", caps=GIGAHOST_CAPS, folders=("INBOX", "Trash"),
                junk="Spamfilter", junk_explicit=True)
    h.deliver("s@x", score=12)
    h.loop()
    eng._status_after_loop(h.db, h.acc, h.state)
    st = status(eng)
    assert st["state"] == "idle" and st["detail"] == "Filtrerer spam til Spamfilter"
    assert st["move_method"] == "UIDPLUS" and st["idle_supported"] == 1
    assert "UIDPLUS" in json.loads(st["capabilities"]) and "MOVE" not in json.loads(st["capabilities"])
    folders = {f["name"]: f for f in json.loads(st["folders"])}
    assert folders["Spamfilter"]["messages"] == 0 and folders["INBOX"]["messages"] == 0
    assert folders["Trash"]["messages"] is None and folders["INBOX"]["flags"] == ["\\HasNoChildren"]
    assert json.loads(st["folder_map"]) == {"inbox": "INBOX", "junk": "Spamfilter", "trash": "Trash"}
    assert st["junk_exists"] == 1 and st["mode"] == "move" and st["threshold"] == 8.0
    assert st["pending_moves"] == 1 and st["bookmark_lag"] == 0
    assert st["last_loop_at"] == int(h.t) and st["last_scan_at"] == int(h.t)
    assert st["connected_since"] == int(eng._now())
    assert "Spamfilter" in h.client.folders  # created for move mode


def test_status_detail_shadow_with_missing_junk(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="shadow", folders=("INBOX",))
    st = status(eng)
    assert st["junk_exists"] == 0 and "findes ikke" in st["detail"]
    assert h.client.writes == []


# ----- main(): heartbeat, boot id, config errors, paused/removed accounts ------


def _wait_until(pred, timeout=8.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.05)
    return False


@pytest.fixture
def main_env(eng, monkeypatch, tmp_path):
    started = SimpleNamespace(dashboard=0, trainer=[], loops=[])
    monkeypatch.setattr(eng, "_start_dashboard", lambda log: setattr(started, "dashboard", started.dashboard + 1))
    fake_trainer = SimpleNamespace(start=lambda engine=None: started.trainer.append(engine))
    monkeypatch.setitem(sys.modules, "trainer", fake_trainer)
    monkeypatch.setattr(eng, "configure_logging", lambda: None)

    def fake_loop(acc):
        started.loops.append(acc.name)
        eng.SHUTDOWN.wait()

    monkeypatch.setattr(eng, "account_loop", fake_loop)
    return started


def _cfg(tmp_path, accounts):
    (tmp_path / "accounts.yml").write_text(yaml.safe_dump({"accounts": accounts}))


def test_main_config_error_degraded_then_recovers(eng, tmp_path, main_env):
    (tmp_path / "heartbeat").write_text("1 oldboot")
    (tmp_path / "accounts.yml").write_text("accounts: [")
    conn = sqlite3.connect(eng.DB_PATH)
    conn.execute("INSERT INTO account_status(account, updated_at, state) VALUES('removed', 1, 'idle')")
    conn.commit()
    conn.close()
    result = {}
    t = threading.Thread(target=lambda: result.setdefault("rc", eng.main()), daemon=True)
    t.start()
    assert _wait_until(lambda: status(eng, "*") is not None)
    st = status(eng, "*")
    assert st["state"] == "config_error" and st["detail"].startswith("Konfigurationsfejl")
    hb = (tmp_path / "heartbeat").read_text().split()
    assert hb[1] == eng.BOOT_ID and abs(int(hb[0]) - time.time()) < 30
    assert (tmp_path / "boot_id").read_text() == eng.BOOT_ID
    assert main_env.dashboard == 1  # WebUI up despite the broken config
    assert main_env.trainer == [eng]
    assert t.is_alive()

    _cfg(tmp_path, [
        {"name": "acct", "user": "a@x.dk", "imap_host": "h", "password": "x"},
        {"name": "paused", "user": "p@x.dk", "imap_host": "h", "enabled": False, "mode": "move"},
    ])
    (tmp_path / "reload_requested").touch()  # skip the 10 s re-check wait
    assert _wait_until(lambda: main_env.loops == ["acct"])
    assert _wait_until(lambda: status(eng, "*") is None)
    p = status(eng, "paused")
    assert p["state"] == "paused" and p["mode"] == "move"
    assert status(eng, "removed") is None
    eng.SHUTDOWN.set()
    t.join(timeout=10)
    assert not t.is_alive() and result["rc"] == 0


def test_main_reload_flag_restarts_cleanly(eng, tmp_path, main_env):
    _cfg(tmp_path, [{"name": "acct", "user": "a@x.dk", "imap_host": "h", "password": "x"}])
    result = {}
    t = threading.Thread(target=lambda: result.setdefault("rc", eng.main()), daemon=True)
    t.start()
    assert _wait_until(lambda: main_env.loops == ["acct"])
    (tmp_path / "reload_requested").touch()
    t.join(timeout=10)
    assert not t.is_alive() and result["rc"] == 0
    assert not (tmp_path / "reload_requested").exists()
