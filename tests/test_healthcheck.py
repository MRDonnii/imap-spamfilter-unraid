"""INFRA: filter/healthcheck.py (Docker HEALTHCHECK, SPEC I1)."""

from __future__ import annotations

import http.server
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "filter"))
import healthcheck as hc  # noqa: E402


@pytest.fixture
def state(tmp_path):
    return tmp_path


def write_hb(state: Path, ts: float, boot: str | None = "boot-a", boot_file: str | None = "boot-a"):
    (state / "heartbeat").write_text(f"{int(ts)} {boot}\n" if boot else f"{int(ts)}\n")
    if boot_file is not None:
        (state / "boot_id").write_text(boot_file + "\n")


# ---------------------------------------------------------------- heartbeat

def test_fresh_heartbeat_with_matching_boot_id(state):
    now = time.time()
    write_hb(state, now - 10)
    hc.check_heartbeat(state, now=now, started_at=None)
    hc.check_heartbeat(state, now=now, started_at=now - 60)


def test_missing_empty_and_malformed(state):
    with pytest.raises(hc.Unhealthy, match="missing"):
        hc.check_heartbeat(state, now=time.time(), started_at=0)
    (state / "heartbeat").write_text("")
    with pytest.raises(hc.Unhealthy, match="empty"):
        hc.check_heartbeat(state, now=time.time(), started_at=0)
    (state / "heartbeat").write_text("yesterday boot")
    with pytest.raises(hc.Unhealthy, match="malformed"):
        hc.check_heartbeat(state, now=time.time(), started_at=0)


def test_stale_heartbeat(state):
    now = time.time()
    write_hb(state, now - 91)
    with pytest.raises(hc.Unhealthy, match="stale"):
        hc.check_heartbeat(state, now=now, started_at=None)
    write_hb(state, now - 89)
    hc.check_heartbeat(state, now=now, started_at=None)


def test_future_heartbeat_rejected(state):
    now = time.time()
    write_hb(state, now + 3600)
    with pytest.raises(hc.Unhealthy, match="future"):
        hc.check_heartbeat(state, now=now, started_at=None)


def test_heartbeat_from_previous_run_rejected(state):
    now = time.time()
    write_hb(state, now - 5, boot="old-run", boot_file="new-run")
    with pytest.raises(hc.Unhealthy, match="another run"):
        hc.check_heartbeat(state, now=now, started_at=now - 100)


def test_heartbeat_older_than_container_start_rejected(state):
    now = time.time()
    # Left behind by the previous container, boot_id not (yet) rewritten.
    write_hb(state, now - 30, boot=None, boot_file=None)
    with pytest.raises(hc.Unhealthy, match="predates"):
        hc.check_heartbeat(state, now=now, started_at=now - 5)
    # Same file is fine once the container is older than the heartbeat.
    hc.check_heartbeat(state, now=now, started_at=now - 60)


def test_legacy_heartbeat_needs_some_proof(state):
    now = time.time()
    write_hb(state, now - 5, boot=None, boot_file=None)
    with pytest.raises(hc.Unhealthy, match="cannot tie"):
        hc.check_heartbeat(state, now=now, started_at=None)


def test_start_slack(state):
    # Whole seconds: write_hb stores int(ts), which made this flaky (~50 %).
    now = float(int(time.time()))
    write_hb(state, now - 10, boot=None, boot_file=None)
    hc.check_heartbeat(state, now=now, started_at=now - 10 + hc.START_SLACK - 0.5)


# ---------------------------------------------------------------- /proc

def test_container_start_time_from_fake_proc(tmp_path):
    proc = tmp_path / "proc"
    (proc / "1").mkdir(parents=True)
    ticks = os.sysconf("SC_CLK_TCK")
    # comm with spaces and a ')' must not break field parsing.
    fields = ["S"] + ["0"] * 18 + [str(500 * ticks)] + ["0"] * 10
    (proc / "1" / "stat").write_text("1 (docker init) x) " + " ".join(fields) + "\n")
    (proc / "stat").write_text("cpu  1 2 3\nbtime 1700000000\nprocesses 5\n")
    assert hc.container_start_time(proc) == pytest.approx(1700000500)


def test_container_start_time_unknown(tmp_path):
    assert hc.container_start_time(tmp_path / "nope") is None
    proc = tmp_path / "proc"
    (proc / "1").mkdir(parents=True)
    (proc / "1" / "stat").write_text("1 (init) S 0\n")
    (proc / "stat").write_text("btime 1\n")
    assert hc.container_start_time(proc) is None


def test_container_start_time_real_proc():
    if not Path("/proc/1/stat").exists():
        pytest.skip("no /proc")
    started = hc.container_start_time()
    assert started is not None and started < time.time()


# ---------------------------------------------------------------- HTTP

class _Handler(http.server.BaseHTTPRequestHandler):
    status = 200
    delay = 0.0

    def do_GET(self):  # noqa: N802
        time.sleep(self.delay)
        body = b'{"ok": true}'
        self.send_response(self.status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    class H(_Handler):
        pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield H, f"http://127.0.0.1:{srv.server_address[1]}/healthz"
    srv.shutdown()
    srv.server_close()


def test_http_ok(server):
    _h, url = server
    hc.check_http(url)


def test_http_error_status(server):
    h, url = server
    h.status = 503
    with pytest.raises(hc.Unhealthy, match="HTTP 503"):
        hc.check_http(url)


def test_http_timeout(server):
    h, url = server
    h.delay = 1.0
    with pytest.raises(hc.Unhealthy, match="unreachable|too slow"):
        hc.check_http(url, timeout=0.3)


def test_http_unreachable():
    with pytest.raises(hc.Unhealthy, match="unreachable"):
        hc.check_http("http://127.0.0.1:1/healthz", timeout=1)


# ---------------------------------------------------------------- main / CLI

def _run(state: Path, url: str, **env):
    e = dict(os.environ, STATE_DIR=str(state), HEALTHCHECK_URL=url, **env)
    return subprocess.run([sys.executable, str(ROOT / "filter" / "healthcheck.py")], env=e,
                          capture_output=True, text=True, timeout=30)


def test_cli_healthy(state, server):
    _h, url = server
    write_hb(state, time.time())
    proc = _run(state, url)
    assert proc.returncode == 0 and proc.stdout.strip() == "ok"


def test_cli_unhealthy_reason_is_short_and_secret_free(state, server):
    _h, url = server
    write_hb(state, time.time() - 500)
    proc = _run(state, url)
    assert proc.returncode == 1
    assert proc.stdout.startswith("unhealthy: heartbeat stale")
    assert len(proc.stdout.splitlines()) == 1


def test_cli_http_down(state):
    write_hb(state, time.time())
    proc = _run(state, "http://127.0.0.1:1/healthz")
    assert proc.returncode == 1 and "healthz unreachable" in proc.stdout


def test_main_respects_max_age_env(state, server, monkeypatch):
    _h, url = server
    write_hb(state, time.time() - 50)
    monkeypatch.setenv("STATE_DIR", str(state))
    monkeypatch.setenv("HEALTHCHECK_URL", url)
    monkeypatch.setenv("HEARTBEAT_MAX_AGE", "30")
    assert hc.main() == 1
    monkeypatch.setenv("HEARTBEAT_MAX_AGE", "bogus")  # falls back to 90 s
    assert hc.main() == 0


def test_healthcheck_is_stdlib_only():
    src = (ROOT / "filter" / "healthcheck.py").read_text()
    for mod in ("filter", "dashboard", "requests", "flask", "services"):
        assert f"import {mod}" not in src
