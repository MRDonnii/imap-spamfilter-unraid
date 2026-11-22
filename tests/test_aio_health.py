"""2.4 all-in-one container: filter/aio_health.py (the image's HEALTHCHECK,
sf-health wait/listeners), sfctl doctor in AIO mode and the configurable
lookalike resolver."""

from __future__ import annotations

import http.server
import json
import os
import socket
import socketserver
import struct
import subprocess
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "filter"))

import aio_health as aio  # noqa: E402
import lookalike as lk  # noqa: E402


# ---------------------------------------------------------------- fake servers

class _Pong(http.server.BaseHTTPRequestHandler):
    body = b"pong\r\n"

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *a):
        pass


@pytest.fixture
def http_server():
    servers = []

    def start(body=b"pong\r\n"):
        handler = type("H", (_Pong,), {"body": body})
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return f"http://127.0.0.1:{srv.server_address[1]}/ping"
    yield start
    for s in servers:
        s.shutdown()


def test_probe_rspamd(http_server):
    a, b = http_server(), http_server()
    assert aio.probe_rspamd([a, b]).ok
    bad = http_server(b"nope")
    r = aio.probe_rspamd([a, bad])
    assert not r.ok and "no pong" in r.detail
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    r = aio.probe_rspamd([f"http://127.0.0.1:{port}/ping"], timeout=1)
    assert not r.ok and r.detail.startswith(f"{port}: no answer")


class _UDP:
    def __init__(self, mode="ok"):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.mode = mode
        self.queries = []
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(512)
            except OSError:
                return
            self.queries.append(data)
            qid = struct.unpack(">H", data[:2])[0]
            if self.mode == "silent":
                continue
            if self.mode == "wrong-id":
                qid ^= 1
            rcode = {"ok": 0, "nx": 3, "servfail": 2}.get(self.mode, 0)
            self.sock.sendto(struct.pack(">HHHHHH", qid, 0x8180 | rcode, 1, 0, 0, 0) + data[12:], addr)


@pytest.mark.parametrize("mode,ok", [("ok", True), ("nx", True), ("servfail", False), ("wrong-id", False),
                                     ("silent", False)])
def test_probe_unbound(mode, ok):
    srv = _UDP(mode)
    r = aio.probe_unbound("127.0.0.1", srv.port, timeout=0.5)
    assert r.ok is ok, r.detail
    assert b"\x09localhost\x00" in srv.queries[0]


class _Redis(socketserver.BaseRequestHandler):
    reply = b"+PONG\r\n"

    def handle(self):
        self.request.recv(64)
        self.request.sendall(self.reply)


@pytest.mark.parametrize("reply,ok,detail", [
    (b"+PONG\r\n", True, "ok"),
    (b"-NOAUTH Authentication required.\r\n", True, "ok (password required)"),
    (b"$5\r\nhello\r\n", False, "unexpected answer"),
])
def test_probe_redis_alive(reply, ok, detail):
    handler = type("R", (_Redis,), {"reply": reply})
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        r = aio.probe_redis_alive("127.0.0.1", srv.server_address[1])
    finally:
        srv.shutdown()
        srv.server_close()
    assert (r.ok, r.detail) == (ok, detail)


@pytest.fixture
def fake_redis_cli(tmp_path):
    """redis-cli that answers PONG only for the right password in
    REDISCLI_AUTH, and records its argv (the password must never be there)."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    cli = bindir / "redis-cli"
    cli.write_text('#!/bin/sh\necho "$*" >>"' + str(tmp_path / "argv.log") + '"\n'
                   '[ "$REDISCLI_AUTH" = "s3cr3t-pw" ] && { echo PONG; exit 0; }\n'
                   'echo "AUTH failed: WRONGPASS invalid username-password pair"; exit 1\n')
    cli.chmod(0o755)

    def run(cmd, **kw):
        # setpriv cannot drop privileges in the test: run what follows "--"
        assert cmd[:5] == ["setpriv", "--reuid=999", "--regid=1000", "--clear-groups", "--"]
        env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
        return subprocess.run(cmd[5:], env=env, **kw)
    return run, tmp_path


@pytest.mark.parametrize("conf,ok,detail", [
    ('requirepass "s3cr3t-pw"\n', True, "ok"),
    ("requirepass s3cr3t-pw\n", True, "ok"),
    ('requirepass "wrong"\n', False, "no PONG with the password from redis.conf"),
    ("appendonly yes\n", False, "no password in redis.conf (or unreadable)"),
])
def test_probe_redis_auth_reads_the_password_inside_and_never_shows_it(fake_redis_cli, conf, ok, detail):
    run, tmp = fake_redis_cli
    f = tmp / "redis.conf"
    f.write_text("dir /data\n" + conf)
    r = aio.probe_redis_auth(str(f), run=run)
    assert (r.ok, r.detail) == (ok, detail)
    assert "s3cr3t" not in r.detail
    argv = (tmp / "argv.log").read_text() if (tmp / "argv.log").exists() else ""
    assert "s3cr3t" not in argv and "wrong" not in argv
    if ok:
        assert argv.strip() == "-h 127.0.0.1 -p 6379 ping"


def test_probe_redis_auth_missing_conf(fake_redis_cli):
    run, tmp = fake_redis_cli
    assert aio.probe_redis_auth(str(tmp / "nope.conf"), run=run).detail.startswith("no password")


def test_probe_filter_runs_healthcheck_as_the_filter_uid():
    seen = []

    def run(cmd, **kw):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 1, stdout="unhealthy: heartbeat stale (130 s old)\n", stderr="")
    r = aio.probe_filter(True, run=run, python="/usr/local/bin/python3", script="/app/healthcheck.py")
    assert seen[0] == ["setpriv", "--reuid=10099", "--regid=10099", "--clear-groups", "--",
                       "/usr/local/bin/python3", "-s", "/app/healthcheck.py"]
    assert not r.ok and r.detail == "heartbeat stale (130 s old)"
    r = aio.probe_filter(False, run=lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, stdout="ok\n", stderr=""))
    assert r.ok


def test_probe_filter_real_healthcheck(tmp_path, http_server):
    import time
    state = tmp_path / "state"
    state.mkdir()
    (state / "heartbeat").write_text(f"{time.time()} b1\n")
    (state / "boot_id").write_text("b1\n")
    url = http_server(b'{"ok": true}').replace("/ping", "/healthz")
    env = dict(os.environ, STATE_DIR=str(state), HEALTHCHECK_URL=url)

    def run(cmd, **kw):
        return subprocess.run(cmd, env=env, **kw)
    assert aio.probe_filter(False, run=run).ok
    (state / "heartbeat").write_text(f"{time.time() - 500} b1\n")
    r = aio.probe_filter(False, run=run)
    assert not r.ok and "stale" in r.detail


def _ok():
    return aio.Result(True, "ok")


def _clam_ok():
    return aio.Result(True, "ok (daily 27800, 5 h old)", {"optional": True, "state": "ok"})


def test_check_all_summary_and_status(tmp_path):
    probes = {"filter": _ok, "rspamd": _ok, "redis": lambda: aio.Result(False, "no PONG"), "unbound": _ok,
              "clamav": _clam_ok}
    res = aio.check_all(as_root=True, probes=probes)
    assert aio.summary_line(res) == "unhealthy: redis: no PONG"
    st = aio.status_json(res, now=100)
    assert st == {"ts": 100, "ok": False, "parts": {
        "filter": {"ok": True, "detail": "ok"}, "rspamd": {"ok": True, "detail": "ok"},
        "redis": {"ok": False, "detail": "no PONG"}, "unbound": {"ok": True, "detail": "ok"},
        "clamav": {"ok": True, "detail": "ok (daily 27800, 5 h old)", "optional": True, "state": "ok"}}}
    f = tmp_path / "run" / "health.json"
    aio.write_status(f, res, now=100)
    assert aio.read_status(f) == st and f.stat().st_mode & 0o777 == 0o644
    probes["redis"] = _ok
    assert aio.summary_line(aio.check_all(as_root=True, probes=probes)) == \
        "ok: filter ok, rspamd ok, redis ok, unbound ok, clamav ok"
    # 2.7: ClamAV down is a warning, never the verdict
    probes["clamav"] = lambda: aio.Result(False, "clamd not answering (FileNotFoundError)",
                                          {"optional": True, "state": "down"})
    res = aio.check_all(as_root=True, probes=probes)
    assert aio.summary_line(res) == ("ok: filter ok, rspamd ok, redis ok, unbound ok; "
                                     "warning: clamav: clamd not answering (FileNotFoundError)")
    assert aio.healthy(res) and aio.status_json(res)["ok"] is True
    probes["clamav"] = lambda: aio.Result(True, "off (SF_CLAMAV=0)", {"optional": True, "state": "off"})
    assert aio.summary_line(aio.check_all(as_root=True, probes=probes)).endswith("unbound ok, clamav off")

    def boom():
        raise RuntimeError("x")
    probes["unbound"] = boom
    assert aio.check_all(as_root=True, probes=probes)["unbound"].detail == "probe crashed (RuntimeError)"
    assert aio.read_status(tmp_path / "missing.json") is None
    (tmp_path / "bad.json").write_text("{nope")
    assert aio.read_status(tmp_path / "bad.json") is None


def test_check_all_uses_the_password_probe_only_as_root(monkeypatch):
    calls = []
    monkeypatch.setattr(aio, "probe_redis_auth", lambda **kw: calls.append("auth") or _ok())
    monkeypatch.setattr(aio, "probe_redis_alive", lambda: calls.append("alive") or _ok())
    base = {"filter": _ok, "rspamd": _ok, "unbound": _ok, "clamav": _clam_ok}
    aio.check_all(as_root=True, probes=base)
    aio.check_all(as_root=False, probes=base)
    assert calls == ["auth", "alive"]


def test_cli_check_prints_summary_and_json(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(aio, "check_all", lambda: {p: _ok() for p in aio.PARTS})
    assert aio.main(["check", "--status-file", str(tmp_path / "h.json")]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "ok: filter ok, rspamd ok, redis ok, unbound ok"
    assert json.loads(out[1])["ok"] is True and (tmp_path / "h.json").exists()
    monkeypatch.setattr(aio, "check_all", lambda: {**{p: _ok() for p in aio.PARTS},
                                                   "rspamd": aio.Result(False, "11334: no pong")})
    assert aio.main(["check", "--json", "--status-file", ""]) == 1
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 1 and json.loads(out[0])["parts"]["rspamd"]["detail"] == "11334: no pong"
    # 2.7: a failing ClamAV never makes the Docker health check fail
    monkeypatch.setattr(aio, "check_all", lambda: {**{p: _ok() for p in aio.PARTS},
                                                   "clamav": aio.Result(False, "waiting", {"state": "waiting"})})
    assert aio.main(["check", "--status-file", ""]) == 0
    assert "warning: clamav: waiting" in capsys.readouterr().out


def test_wait_for():
    state = {"n": 0}

    def flaky():
        state["n"] += 1
        return aio.Result(state["n"] >= 3, "x")
    t = {"now": 0.0}
    left = aio.wait_for(["redis", "unbound"], timeout=10, probes={"redis": flaky, "unbound": _ok},
                        clock=lambda: t["now"], sleep=lambda s: t.__setitem__("now", t["now"] + s))
    assert left == [] and state["n"] == 3
    left = aio.wait_for(["rspamd"], timeout=3, probes={"rspamd": lambda: aio.Result(False, "down")},
                        clock=lambda: t["now"], sleep=lambda s: t.__setitem__("now", t["now"] + s))
    assert left == ["rspamd"]
    with pytest.raises(ValueError):
        aio.wait_for(["filter"], timeout=1)


def _hex4(ip, port):
    return socket.inet_aton(ip)[::-1].hex().upper() + f":{port:04X}"


def _hex6(ip, port):
    raw = socket.inet_pton(socket.AF_INET6, ip)
    return b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)).hex().upper() + f":{port:04X}"


def test_listeners_only_the_webui_outside_loopback(tmp_path):
    net = tmp_path / "net"
    net.mkdir()
    head = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

    def row(addr, st):
        return f"   0: {addr} 00000000:0000 {st} 00000000:00000000 00:00000000 00000000     0        0 1\n"
    (net / "tcp").write_text(head + row(_hex4("0.0.0.0", 8080), "0A") + row(_hex4("127.0.0.1", 6379), "0A")
                             + row(_hex4("127.0.0.1", 11334), "0A") + row(_hex4("192.168.1.5", 44000), "01"))
    (net / "tcp6").write_text(head + row(_hex6("::", 8080), "0A") + row(_hex6("::1", 6379), "0A"))
    (net / "udp").write_text(head + row(_hex4("127.0.0.1", 53), "07") + row(_hex4("0.0.0.0", 40123), "07"))
    (net / "udp6").write_text(head)
    assert aio.listeners(tmp_path) == []
    with open(net / "tcp", "a") as fh:
        fh.write(row(_hex4("0.0.0.0", 11334), "0A"))
    with open(net / "udp", "a") as fh:
        fh.write(row(_hex4("0.0.0.0", 53), "07"))
    with open(net / "tcp6", "a") as fh:
        fh.write(row(_hex6("::", 6379), "0A"))
    assert aio.listeners(tmp_path) == ["tcp 0.0.0.0:11334", "tcp6 :::6379", "udp 0.0.0.0:53"]
    # the AIO's Unbound port 5353 is watched as well
    with open(net / "udp", "a") as fh:
        fh.write(row(_hex4("0.0.0.0", 5353), "07"))
    assert "udp 0.0.0.0:5353" in aio.listeners(tmp_path)
    assert aio.UNBOUND_PORT == 5353


def test_aio_health_is_stdlib_only():
    src = (ROOT / "filter" / "aio_health.py").read_text()
    for mod in ("requests", "flask", "yaml", "import filter", "import dashboard"):
        assert mod not in src


# ---------------------------------------------------------------- sfctl doctor (AIO)

from test_sfctl import env, run  # noqa: E402,F401  (fixtures/helpers of the sfctl suite)
import sfctl  # noqa: E402


def test_doctor_aio_mode_shows_every_part(env, capsys, monkeypatch, tmp_path):  # noqa: F811
    import time
    (env.state / "heartbeat").write_text(f"{int(time.time())} boot\n")
    status = tmp_path / "health.json"
    aio.write_status(status, {p: _ok() for p in aio.PARTS}, now=time.time() - 20)
    monkeypatch.setenv("SPAMFILTER_AIO", "1")
    monkeypatch.setattr(aio, "probe_redis_alive", lambda: aio.Result(True, "ok (password required)"))
    monkeypatch.setattr(aio, "probe_unbound", lambda: aio.Result(True, "ok"))
    real_read = aio.read_status
    monkeypatch.setattr(aio, "read_status", lambda path=None: real_read(status))
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert "[ OK ] Redis svarer (127.0.0.1:6379, i containeren)" in o
    assert "[ OK ] Unbound svarer (127.0.0.1:5353, i containeren)" in o
    assert "filter, rspamd, Redis (med adgangskode) og Unbound er ok" in o
    assert "[FEJL]" not in o


def test_doctor_aio_mode_reports_a_failing_part_with_the_fix(env, capsys, monkeypatch, tmp_path):  # noqa: F811
    import time
    (env.state / "heartbeat").write_text(f"{int(time.time())} boot\n")
    status = tmp_path / "health.json"
    res = {p: _ok() for p in aio.PARTS}
    res["unbound"] = aio.Result(False, "SERVFAIL")
    aio.write_status(status, res, now=time.time() - 400)
    monkeypatch.setenv("SPAMFILTER_AIO", "1")
    monkeypatch.setattr(aio, "probe_redis_alive", lambda: aio.Result(False, "no answer (ConnectionRefusedError)"))
    monkeypatch.setattr(aio, "probe_unbound", lambda: aio.Result(True, "ok"))
    monkeypatch.setattr(aio, "read_status", lambda path=None: json.loads(status.read_text()))
    monkeypatch.setattr(sfctl.engine, "_rspamd_alive", lambda: False)
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert code == 1
    assert "[FEJL] Redis svarer ikke (127.0.0.1:6379)" in o
    assert "docker exec spamfilter supervisorctl restart redis" in o
    assert "Unbound fejler (SERVFAIL)" in o and "supervisorctl restart unbound" in o
    assert "supervisorctl restart rspamd" in o and "docker restart spamfilter-rspamd" not in o
    assert "[ADV.] det samlede sundhedstjek er" in o


def test_doctor_aio_mode_without_status_file_and_legacy_mode(env, capsys, monkeypatch):  # noqa: F811
    monkeypatch.setenv("SPAMFILTER_AIO", "1")
    monkeypatch.setattr(aio, "probe_redis_alive", lambda: aio.Result(True, "ok"))
    monkeypatch.setattr(aio, "probe_unbound", lambda: aio.Result(True, "ok"))
    monkeypatch.setattr(aio, "read_status", lambda path=None: None)
    _, o, _ = run(capsys, monkeypatch, "doctor")
    assert "intet samlet sundhedstjek endnu" in o
    monkeypatch.delenv("SPAMFILTER_AIO")
    _, o, _ = run(capsys, monkeypatch, "doctor")
    assert "Redis svarer" not in o and "sundhedstjek endnu" not in o


# ---------------------------------------------------------------- sf-health bayes

class _Stat(http.server.BaseHTTPRequestHandler):
    password = "CTRL-S3CRET"
    seen: list = []

    def do_GET(self):  # noqa: N802
        self.seen.append((self.path, self.headers.get("Password")))
        if self.headers.get("Password") != self.password:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'{"error": "Unauthorized"}')
            return
        body = json.dumps({"scanned": 5, "statfiles": [
            {"symbol": "BAYES_SPAM", "type": "redis", "revision": 251, "users": 2},
            {"symbol": "BAYES_HAM", "type": "redis", "revision": 216, "users": 2},
            {"type": "broken"}]}).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def stat_server():
    handler = type("S", (_Stat,), {"seen": []})
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/stat", handler
    srv.shutdown()


def test_bayes_counts_send_the_controller_password(tmp_path, stat_server, monkeypatch, capsys):
    """Review finding: in ONE container every program shares rspamd's
    loopback, so the AIO exempts no client from the controller password -
    the learned counts are read WITH it (as the filter uid)."""
    url, handler = stat_server
    (tmp_path / "controller.password").write_text("CTRL-S3CRET\n")
    monkeypatch.setenv("STATE_DIR", str(tmp_path))
    assert aio.bayes_counts(url) == [("BAYES_SPAM", 251), ("BAYES_HAM", 216)]
    assert handler.seen[-1] == ("/stat", "CTRL-S3CRET")
    monkeypatch.setattr(aio, "CONTROLLER_STAT_URL", url)
    assert aio.main(["bayes"]) == 0
    out, err = capsys.readouterr()
    assert out == "BAYES_SPAM 251\nBAYES_HAM 216\n" and "S3CRET" not in out + err
    (tmp_path / "controller.password").write_text("wrong\n")
    assert aio.main(["bayes"]) == 1
    out, err = capsys.readouterr()
    assert "HTTP 403" in err and "wrong" not in out + err
    (tmp_path / "controller.password").unlink()
    assert aio.main(["bayes"]) == 1
    assert "not readable" in capsys.readouterr().err


# ---------------------------------------------------------------- lookalike resolver

def test_lookalike_dns_server_is_configurable(monkeypatch):
    monkeypatch.delenv("LOOKALIKE_DNS_SERVER", raising=False)
    assert lk.default_server() == "spamfilter-unbound" == lk.DnsResolver().server
    monkeypatch.setenv("LOOKALIKE_DNS_SERVER", "127.0.0.1")
    assert lk.DnsResolver().server == "127.0.0.1"
    assert lk.DnsResolver("10.9.9.9").server == "10.9.9.9"  # explicit wins
    monkeypatch.setenv("LOOKALIKE_DNS_SERVER", "  ")
    assert lk.DnsResolver().server == "spamfilter-unbound"  # empty (dockerMan) = unset


def test_lookalike_dns_port_is_configurable(monkeypatch):
    monkeypatch.delenv("LOOKALIKE_DNS_PORT", raising=False)
    assert lk.default_port() == 53 == lk.DnsResolver().port
    monkeypatch.setenv("LOOKALIKE_DNS_PORT", "5353")  # the AIO image
    assert lk.DnsResolver().port == 5353 and lk.DnsResolver("127.0.0.1").port == 5353
    assert lk.DnsResolver(port=1053).port == 1053  # explicit wins
    for bad in ("", "  ", "x", "0", "70000"):
        monkeypatch.setenv("LOOKALIKE_DNS_PORT", bad)
        assert lk.default_port() == 53, bad


def test_lookalike_resolver_queries_the_configured_port(monkeypatch):
    srv = _UDP("ok")
    monkeypatch.setenv("LOOKALIKE_DNS_SERVER", "127.0.0.1")
    monkeypatch.setenv("LOOKALIKE_DNS_PORT", str(srv.port))
    ans = lk.DnsResolver(timeout=2).query("example.org", "A")
    assert srv.queries and ans.rcode == 0


def test_filter_reads_the_lookalike_server_like_lookalike_does():
    src = (ROOT / "filter" / "filter.py").read_text()
    assert ('LOOKALIKE_DNS_SERVER = (os.environ.get("LOOKALIKE_DNS_SERVER") or "").strip() '
            'or "spamfilter-unbound"') in src
    for v, want in (("", "spamfilter-unbound"), ("127.0.0.1", "127.0.0.1")):
        out = subprocess.run([sys.executable, "-c", "import os; print((os.environ.get('LOOKALIKE_DNS_SERVER') or '')"
                              ".strip() or 'spamfilter-unbound')"], env=dict(os.environ, LOOKALIKE_DNS_SERVER=v),
                             capture_output=True, text=True).stdout.strip()
        assert out == want


# ---------------------------------------------------------------- 2.7: ClamAV

class _Clamd(socketserver.BaseRequestHandler):
    """A tiny clamd: zPING, zVERSION, zINSTREAM (finds b'BAD')."""
    version = b"ClamAV 1.4.3/27800/Mon Nov  2 09:30:00 2026"

    def handle(self):
        f = self.request.makefile("rb")
        cmd = b""
        while not cmd.endswith(b"\0"):
            c = f.read(1)
            if not c:
                return
            cmd += c
        if cmd == b"zPING\0":
            self.request.sendall(b"PONG\0")
        elif cmd == b"zVERSION\0":
            self.request.sendall(self.version + b"\0")
        elif cmd == b"zINSTREAM\0":
            data = b""
            while True:
                (n,) = struct.unpack(">I", f.read(4))
                if not n:
                    break
                data += f.read(n)
            self.request.sendall(b"stream: Test.Sig FOUND\0" if b"BAD" in data else b"stream: OK\0")


@pytest.fixture
def clamd_sock():
    import tempfile
    d = tempfile.mkdtemp(prefix="sfc", dir="/tmp")  # AF_UNIX paths are short
    path = os.path.join(d, "clamd.sock")
    srv = socketserver.ThreadingUnixStreamServer(path, _Clamd)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield path
    srv.shutdown()
    srv.server_close()
    import shutil
    shutil.rmtree(d, ignore_errors=True)


def test_clamd_client_ping_version_instream(clamd_sock):
    assert aio.clamd_request(b"PING", clamd_sock) == "PONG"
    assert aio.clamd_request(b"VERSION", clamd_sock).startswith("ClamAV 1.4.3/27800/")
    big = b"x" * 200_000 + b"BAD"  # several 64 KiB chunks
    assert aio.clamd_request(b"INSTREAM", clamd_sock, stream=big) == "stream: Test.Sig FOUND"
    assert aio.clamd_request(b"INSTREAM", clamd_sock, stream=b"fine") == "stream: OK"
    with pytest.raises(OSError):
        aio.clamd_request(b"PING", clamd_sock + ".missing", 1.0)


def test_parse_clamd_version():
    import time
    daily, when = aio.parse_clamd_version("ClamAV 1.4.3/27800/Mon Nov  2 09:30:00 2026")
    assert daily == 27800 and time.localtime(when)[:5] == (2026, 11, 2, 9, 30)
    assert aio.parse_clamd_version("ClamAV 1.4.3") == (None, None)
    assert aio.parse_clamd_version("ClamAV 1.4.3/x/garbage") == (None, None)


def test_clamav_db_files(tmp_path):
    assert aio.clamav_db_files(tmp_path) == (False, None)
    (tmp_path / "main.cvd").write_bytes(b"m")
    assert aio.clamav_db_files(tmp_path)[0] is False
    (tmp_path / "daily.cld").write_bytes(b"")
    assert aio.clamav_db_files(tmp_path)[0] is False  # empty file = not there
    (tmp_path / "daily.cld").write_bytes(b"d")
    os.utime(tmp_path / "daily.cld", (1000, 1000))
    assert aio.clamav_db_files(tmp_path) == (True, 1000)


def test_evaluate_clamav_states():
    now = 10 * 86400.0
    up = {"ping": True, "daily": 27800, "db_time": now - 5 * 3600, "db_files": True, "file_time": None}
    r = aio.evaluate_clamav(up, now)
    assert r.ok and r.detail == "ok (daily 27800, 5 h old)" and r.extra["state"] == "ok"
    assert r.extra["db_age_s"] == 5 * 3600 and r.extra["optional"] is True
    r = aio.evaluate_clamav({**up, "db_time": now - 4 * 86400}, now)
    assert not r.ok and r.extra["state"] == "stale" and r.detail.startswith("signatures 4 days old")
    # clamd answers but no date in VERSION: the files' mtime counts
    r = aio.evaluate_clamav({**up, "db_time": None, "file_time": now - 3600}, now)
    assert r.ok and "1 h old" in r.detail
    r = aio.evaluate_clamav({"ping": False, "error": "FileNotFoundError", "db_files": False, "file_time": None}, now)
    assert not r.ok and r.extra["state"] == "waiting" and "first signature download" in r.detail
    r = aio.evaluate_clamav({"ping": False, "error": "ConnectionRefusedError", "db_files": True,
                             "file_time": now - 86400}, now)
    assert not r.ok and r.extra["state"] == "down"
    assert r.detail == "clamd not answering (ConnectionRefusedError); signatures 1 day old"


def test_probe_clamav_follows_the_entrypoint_state(tmp_path, clamd_sock, monkeypatch):
    state = tmp_path / "clamav.state"
    r = aio.probe_clamav(False, state_file=state)
    assert r.ok and r.extra["state"] == "off" and "no ClamAV" in r.detail  # an image without 2.7
    state.write_text("off SF_CLAMAV=0\n")
    r = aio.probe_clamav(False, state_file=state)
    assert r.ok and r.detail == "off (SF_CLAMAV=0)" and r.extra["reason"] == "SF_CLAMAV=0"
    state.write_text("on \n")
    db = tmp_path / "db"
    db.mkdir()
    monkeypatch.setattr(aio, "CLAMAV_SOCKET", clamd_sock)
    monkeypatch.setattr(aio, "CLAMAV_DB", str(db))
    r = aio.probe_clamav(False, state_file=state, now=aio.parse_clamd_version(_Clamd.version.decode())[1] + 60)
    assert r.ok and r.extra["state"] == "ok" and r.extra["daily"] == 27800
    monkeypatch.setattr(aio, "CLAMAV_SOCKET", clamd_sock + ".gone")
    r = aio.probe_clamav(False, state_file=state)
    assert not r.ok and r.extra["state"] == "waiting"


def test_probe_clamav_as_root_gathers_the_facts_as_the_clamav_uid(tmp_path):
    state = tmp_path / "clamav.state"
    state.write_text("on \n")
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        out = json.dumps({"ping": True, "daily": 1, "db_time": 1000.0, "db_files": True, "file_time": None})
        return subprocess.CompletedProcess(cmd, 0, stdout="noise\n" + out + "\n", stderr="")
    r = aio.probe_clamav(True, run=run, state_file=state, now=2000.0)
    assert r.ok and r.extra["state"] == "ok"
    cmd = calls[0]
    assert cmd[:5] == ["setpriv", "--reuid=3310", "--regid=3310", "--clear-groups", "--"]
    assert cmd[-1] == "clamav-facts" and cmd[-2].endswith("aio_health.py") and "-E" in cmd

    def broken(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="setpriv: failed")
    r = aio.probe_clamav(True, run=broken, state_file=state)
    assert not r.ok and r.detail.startswith("probe failed") and r.extra["state"] == "down"


def test_cli_clamav(monkeypatch, capsys):
    monkeypatch.setattr(aio, "probe_clamav", lambda root: aio.Result(True, "off (SF_CLAMAV=0)"))
    assert aio.main(["clamav"]) == 0 and capsys.readouterr().out == "clamav: off (SF_CLAMAV=0)\n"
    monkeypatch.setattr(aio, "probe_clamav", lambda root: aio.Result(False, "clamd not answering (x)"))
    assert aio.main(["clamav"]) == 1
    monkeypatch.setattr(aio, "clamav_facts", lambda: {"ping": False})
    assert aio.main(["clamav-facts"]) == 0
    assert json.loads(capsys.readouterr().out.splitlines()[-1]) == {"ping": False}


def _doctor_with_clamav(env, capsys, monkeypatch, tmp_path, clamav):  # noqa: F811
    import time
    (env.state / "heartbeat").write_text(f"{int(time.time())} boot\n")
    status = tmp_path / "health.json"
    res = {p: _ok() for p in aio.PARTS}
    if clamav is not None:
        res["clamav"] = clamav
    aio.write_status(status, res, now=time.time() - 20)
    monkeypatch.setenv("SPAMFILTER_AIO", "1")
    monkeypatch.setattr(aio, "probe_redis_alive", lambda: aio.Result(True, "ok"))
    monkeypatch.setattr(aio, "probe_unbound", lambda: aio.Result(True, "ok"))
    real_read = aio.read_status
    monkeypatch.setattr(aio, "read_status", lambda path=None: real_read(status))
    return run(capsys, monkeypatch, "doctor")


@pytest.mark.parametrize("clamav,want,level", [
    (aio.Result(True, "ok", {"state": "ok", "db_age_s": 7200, "daily": 27800}),
     "antivirus (ClamAV) svarer, signaturerne er 2 t. 0 min. gamle (daily 27800)", "[ OK ]"),
    (aio.Result(True, "off", {"state": "off", "reason": "SF_CLAMAV=0"}),
     "antivirus (ClamAV): slået fra med SF_CLAMAV=0", "[ OK ]"),
    (aio.Result(True, "off", {"state": "off", "reason": "cannot create /appdata/clamav"}),
     "antivirus (ClamAV) er slået fra: cannot create /appdata/clamav", "[ADV.]"),
    (aio.Result(False, "waiting", {"state": "waiting", "db_age_s": None}),
     "antivirus (ClamAV) henter sine første virussignaturer", "[ADV.]"),
    (aio.Result(False, "signatures 4 days old", {"state": "stale", "db_age_s": 4 * 86400}),
     "antivirus (ClamAV): signaturerne er 4 dage gamle – freshclam opdaterer ikke", "[ADV.]"),
    (aio.Result(False, "clamd not answering (ConnectionRefusedError)", {"state": "down"}),
     "antivirus (ClamAV) svarer ikke (clamd not answering (ConnectionRefusedError))", "[ADV.]"),
])
def test_doctor_aio_reports_clamav(env, capsys, monkeypatch, tmp_path, clamav, want, level):  # noqa: F811
    code, o, _ = _doctor_with_clamav(env, capsys, monkeypatch, tmp_path, clamav)
    line = next(x for x in o.splitlines() if "antivirus (ClamAV)" in x)
    assert line.startswith(level) and want in line, line
    assert "[FEJL]" not in o  # ClamAV never makes doctor fail
    if clamav.extra["state"] == "down":
        assert "supervisorctl restart clamd" in o
    if clamav.extra["state"] == "stale":
        assert "supervisorctl restart freshclam" in o


def test_doctor_aio_without_clamav_in_health_json(env, capsys, monkeypatch, tmp_path):  # noqa: F811
    _, o, _ = _doctor_with_clamav(env, capsys, monkeypatch, tmp_path, None)
    assert "ClamAV" not in o and "Unbound er ok" in o


# ------------------------------------------------------------------ 2.7 fix: the filter waits for clamd

def test_clamav_wait_probe(tmp_path):
    state = tmp_path / "clamav.state"
    boom = lambda: (_ for _ in ()).throw(AssertionError("no scan expected"))  # noqa: E731
    state.write_text("off SF_CLAMAV=0\n")
    assert aio.probe_clamav_ready(state, scan=boom).ok
    state.write_text("on nodb\n")                       # first download: not worth waiting
    assert aio.probe_clamav_ready(state, scan=boom).ok
    state.write_text("on db\n")
    r = aio.probe_clamav_ready(state, scan=lambda: {"CLAM_VIRUS_FAIL", "R_DKIM_NA"})
    assert not r.ok and "not answering" in r.detail
    assert aio.probe_clamav_ready(state, scan=lambda: {"R_DKIM_NA"}).ok

    def down():
        raise OSError("refused")
    assert not aio.probe_clamav_ready(state, scan=down).ok
    assert aio.clamav_db_hint(state) and not aio.clamav_db_hint(tmp_path / "missing")
    assert "clamav" in aio.WAIT_PROBES


def test_rspamd_test_scan_posts_a_random_attachment(monkeypatch):
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            seen.append(self.rfile.read(int(self.headers["Content-Length"])))
            body = json.dumps({"symbols": {"CLAM_VIRUS_FAIL": {}, "MIME_GOOD": {}}}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}/checkv2"
        assert aio.rspamd_test_scan(url, timeout=5) == {"CLAM_VIRUS_FAIL", "MIME_GOOD"}
        aio.rspamd_test_scan(url, timeout=5)
    finally:
        srv.shutdown()
    assert len(seen) == 2 and seen[0] != seen[1]           # random: never answered from the cache
    assert b"Content-Disposition: attachment" in seen[0]
