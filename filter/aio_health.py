"""Health of the all-in-one container (2.4): one probe per part.

The AIO image (deploy/aio/Dockerfile) runs four programs under supervisord:
the filter (+ WebUI), rspamd, Redis and Unbound. This module checks each
of them and is used by:

  sf-health check      the image's Docker HEALTHCHECK. Runs as root, but
                       root has no CAP_DAC_OVERRIDE in the container, so
                       the filter probe (heartbeat in the 0700 state dir)
                       and the Redis probe (0600 redis.conf) drop to the
                       owning uid with setpriv. Prints one summary line and
                       one JSON line (Docker keeps both in State.Health.Log)
                       and writes /run/spamfilter/health.json for sfctl.
  sf-health wait       start order: sf-run waits for redis/unbound before
                       rspamd and for rspamd before the filter.
  sf-health listeners  only the WebUI (8080) may listen on a non-loopback
                       address (smoke test / CI).
  sf-health bayes      "BAYES_SPAM 251" lines (learned counts, like
                       `rspamc stat`) from the controller's /stat WITH the
                       controller password - the AIO exempts no client from
                       it. Runs as uid 10099 (owner of controller.password):
                       docker exec -u 10099:10099 spamfilter sf-health bayes
  sfctl doctor         (SPAMFILTER_AIO=1) the unprivileged probes plus the
                       last full check from /run/spamfilter/health.json.
  sf-health clamav     2.7: the ClamAV line alone (exit 0 = ok or off).

Parts and what "ok" means:
  filter   healthcheck.py: fresh heartbeat of THIS run + /healthz 200
  rspamd   GET /ping on the normal worker (11333) and the controller
           (11334) both answer "pong"
  redis    PING answered PONG with the password from redis.conf (root
           check); the unprivileged probe accepts PONG or NOAUTH (= Redis
           answers and wants the password)
  unbound  answers a query for localhost. (a local zone: no upstream
           needed) on 127.0.0.1:5353 (unprivileged port: no sysctl, no
           privileged DNS port any uid could take over)

2.7, OPTIONAL (reported, never part of the verdict - the container stays
healthy, rspamd fails open with CLAM_VIRUS_FAIL):
  clamav   off (SF_CLAMAV=0, or the entrypoint switched it off - reason in
           /run/spamfilter/clamav.state), or clamd answers PING on its unix
           socket and its signatures are at most 3 days old (date of the
           daily database from VERSION, else the files' mtime). States:
           ok / off / waiting (first download, no signatures yet) / down /
           stale. As root the facts are gathered as the clamav uid (3310):
           the socket dir and the signature dir are not open to root
           without CAP_DAC_OVERRIDE.

Stdlib only, and never prints a secret: the Redis password is read by the
shell inside the setpriv'd child and handed to redis-cli via REDISCLI_AUTH;
only "PONG" (or a fixed reason) comes back.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

PARTS = ("filter", "rspamd", "redis", "unbound")
# 2.7: reported in health.json and the summary, never in the verdict.
OPTIONAL_PARTS = ("clamav",)
LOOPBACK = "127.0.0.1"
RSPAMD_PING_URLS = ("http://127.0.0.1:11333/ping", "http://127.0.0.1:11334/ping")
REDIS_PORT = 6379
UNBOUND_PORT = 5353
REDIS_CONF = "/usr/local/etc/redis/redis.conf"
CONTROLLER_STAT_URL = "http://127.0.0.1:11334/stat"
STATUS_FILE = "/run/spamfilter/health.json"
FILTER_UID = FILTER_GID = 10099
REDIS_UID, REDIS_GID = 999, 1000
SETPRIV = "setpriv"
WEBUI_PORT = 8080
HTTP_TIMEOUT = 5.0
DETAIL_MAX = 120
CLAMAV_SOCKET = "/run/spamfilter/clamav/clamd.sock"
CLAMAV_DB = "/appdata/clamav"
CLAMAV_STATE_FILE = "/run/spamfilter/clamav.state"
CLAMAV_UID = CLAMAV_GID = 3310
CLAMAV_STALE_S = 3 * 86400

# Runs as uid 999 (the owner of redis.conf). Exit 3 = no usable password.
# The password only lives in this shell and in redis-cli's environment.
REDIS_AUTH_SCRIPT = r'''
conf=$1; host=$2; port=$3
[ -r "$conf" ] || exit 3
pw=$(sed -n 's/^[[:space:]]*requirepass[[:space:]]\{1,\}"\{0,1\}\([^"[:space:]]*\)"\{0,1\}[[:space:]]*$/\1/p' "$conf" | tail -n 1)
[ -n "$pw" ] || exit 3
REDISCLI_AUTH=$pw
export REDISCLI_AUTH
exec redis-cli -h "$host" -p "$port" ping
'''


@dataclass
class Result:
    ok: bool
    detail: str
    extra: dict[str, Any] | None = None  # 2.7: clamav state, signature age

    def as_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "detail": self.detail, **(self.extra or {})}


Runner = Callable[..., "subprocess.CompletedProcess[str]"]


def _short(text: Any) -> str:
    s = " ".join(str(text or "").split())
    return s[:DETAIL_MAX]


def _http_get(url: str, timeout: float) -> tuple[int, str]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=timeout) as resp:
        return resp.status, resp.read(256).decode("ascii", "replace")


# ------------------------------------------------------------------ probes

def probe_rspamd(urls: Iterable[str] = RSPAMD_PING_URLS, timeout: float = HTTP_TIMEOUT) -> Result:
    for url in urls:
        try:
            status, body = _http_get(url, timeout)
        except urllib.error.HTTPError as ex:
            return Result(False, f"{_port_of(url)}: HTTP {ex.code}")
        except (urllib.error.URLError, OSError) as ex:
            reason = getattr(ex, "reason", ex)
            return Result(False, f"{_port_of(url)}: no answer ({reason.__class__.__name__})")
        if status != 200 or "pong" not in body.lower():
            return Result(False, f"{_port_of(url)}: no pong")
    return Result(True, "ok")


def _port_of(url: str) -> str:
    rest = url.split("://", 1)[-1].split("/", 1)[0]
    return rest.rsplit(":", 1)[-1] if ":" in rest else rest


def build_query(name: str, qid: int, qtype: int = 1) -> bytes:
    labels = [x for x in name.strip(".").split(".") if x]
    qname = b"".join(bytes([len(x)]) + x.encode("ascii") for x in labels) + b"\x00"
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", qtype, 1)


def probe_unbound(host: str = LOOPBACK, port: int = UNBOUND_PORT, name: str = "localhost",
                  timeout: float = 3.0) -> Result:
    qid = random.SystemRandom().randrange(0, 65536)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((host, int(port)))
            s.send(build_query(name, qid))
            data = s.recv(4096)
    except OSError as ex:
        return Result(False, f"no answer ({ex.__class__.__name__})")
    if len(data) < 12:
        return Result(False, "malformed answer")
    rid, flags = struct.unpack(">HH", data[:4])
    if rid != qid or not flags & 0x8000:
        return Result(False, "answer does not match the query")
    rcode = flags & 0x000F
    if rcode not in (0, 3):
        return Result(False, {2: "SERVFAIL", 5: "REFUSED"}.get(rcode, f"rcode {rcode}"))
    return Result(True, "ok")


def probe_redis_alive(host: str = LOOPBACK, port: int = REDIS_PORT, timeout: float = 3.0) -> Result:
    """Unauthenticated PING: PONG or NOAUTH both prove Redis answers."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as s:
            s.sendall(b"PING\r\n")
            line = s.makefile("rb").readline(256).decode("ascii", "replace").strip()
    except OSError as ex:
        return Result(False, f"no answer ({ex.__class__.__name__})")
    if line == "+PONG":
        return Result(True, "ok")
    if line.startswith("-NOAUTH") or (line.startswith("-") and "auth" in line.lower()):
        return Result(True, "ok (password required)")
    return Result(False, "unexpected answer")


def probe_redis_auth(conf: str = REDIS_CONF, host: str = LOOPBACK, port: int = REDIS_PORT,
                     run: Runner = subprocess.run, timeout: float = 8.0) -> Result:
    """PING with the password from redis.conf, as uid 999 (root cannot read
    the 0600 file without CAP_DAC_OVERRIDE). Only "PONG" is looked at."""
    cmd = [SETPRIV, f"--reuid={REDIS_UID}", f"--regid={REDIS_GID}", "--clear-groups", "--",
           "sh", "-c", REDIS_AUTH_SCRIPT, "sf-health", conf, host, str(port)]
    try:
        proc = run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as ex:
        return Result(False, f"probe failed ({ex.__class__.__name__})")
    if proc.returncode == 3:
        return Result(False, "no password in redis.conf (or unreadable)")
    if proc.returncode == 0 and (proc.stdout or "").strip() == "PONG":
        return Result(True, "ok")
    return Result(False, "no PONG with the password from redis.conf")


def probe_filter(as_root: bool, run: Runner = subprocess.run, timeout: float = 15.0,
                 python: str | None = None, script: str | None = None) -> Result:
    """healthcheck.py (heartbeat of this run + /healthz). As root it runs
    as the filter uid: the state dir is 0700 10099."""
    py = python or sys.executable or "/usr/local/bin/python3"
    hc = script or str(Path(__file__).with_name("healthcheck.py"))
    cmd = [py, "-s", hc]
    if as_root:
        cmd = [SETPRIV, f"--reuid={FILTER_UID}", f"--regid={FILTER_GID}", "--clear-groups", "--", *cmd]
    try:
        proc = run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as ex:
        return Result(False, f"probe failed ({ex.__class__.__name__})")
    lines = [x for x in (proc.stdout or "").splitlines() if x.strip()]
    last = lines[-1] if lines else ""
    if proc.returncode == 0:
        return Result(True, "ok")
    return Result(False, _short(last.removeprefix("unhealthy:").strip() or f"exit {proc.returncode}"))


# ------------------------------------------------------------------ clamav (2.7)

def clamd_request(command: bytes, path: str | None = None, timeout: float = 5.0,
                  stream: bytes | None = None) -> str:
    """One clamd command over its unix socket ('z' form: NUL-terminated).
    stream: the data of an INSTREAM (chunks of <= 64 KiB, length-prefixed)."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(path or CLAMAV_SOCKET)
        s.sendall(b"z" + command + b"\0")
        if stream is not None:
            for i in range(0, len(stream), 65536):
                chunk = stream[i:i + 65536]
                s.sendall(struct.pack(">I", len(chunk)) + chunk)
            s.sendall(struct.pack(">I", 0))
        data = b""
        while b"\0" not in data and len(data) < 4096:
            part = s.recv(4096)
            if not part:
                break
            data += part
    return data.split(b"\0", 1)[0].decode("utf-8", "replace").strip()


def parse_clamd_version(text: str) -> tuple[int | None, float | None]:
    """'ClamAV 1.4.3/27800/Mon Nov  2 09:30:00 2026' -> (27800, epoch of
    the daily database's build time, clamd's local time)."""
    parts = str(text or "").split("/", 2)
    daily = int(parts[1]) if len(parts) > 1 and parts[1].strip().isdigit() else None
    when = None
    if len(parts) > 2:
        try:
            when = time.mktime(time.strptime(" ".join(parts[2].split()), "%a %b %d %H:%M:%S %Y"))
        except (ValueError, OverflowError):
            when = None
    return daily, when


def clamav_db_files(db_dir: str | Path | None = None) -> tuple[bool, float | None]:
    """(main and daily present, newest daily mtime) of the signature dir."""
    d = Path(db_dir or CLAMAV_DB)
    found: dict[str, float] = {}
    for part in ("main", "daily"):
        for ext in ("cvd", "cld"):
            try:
                st = (d / f"{part}.{ext}").stat()
            except OSError:
                continue
            if st.st_size > 0:
                found[part] = max(found.get(part, 0.0), st.st_mtime)
    return ("main" in found and "daily" in found), found.get("daily")


def clamav_facts(path: str | None = None, db_dir: str | Path | None = None,
                 timeout: float = 5.0) -> dict[str, Any]:
    """What clamd and the signature dir say (run as the clamav uid)."""
    facts: dict[str, Any] = {"ping": False, "daily": None, "db_time": None, "error": None}
    try:
        facts["ping"] = clamd_request(b"PING", path, timeout) == "PONG"
        if facts["ping"]:
            facts["daily"], facts["db_time"] = parse_clamd_version(clamd_request(b"VERSION", path, timeout))
    except OSError as ex:
        facts["error"] = ex.__class__.__name__
    facts["db_files"], facts["file_time"] = clamav_db_files(db_dir)
    return facts


def clamav_state(path: str | Path | None = None) -> tuple[bool, str]:
    """(on, reason) as sf-entrypoint decided it ('on' / 'off <reason>')."""
    try:
        line = Path(path or CLAMAV_STATE_FILE).read_text().strip()
    except OSError:
        return False, "no ClamAV in this container (no clamav.state)"
    word, _, reason = line.partition(" ")
    if word == "on":
        return True, ""
    return False, _short(reason) or "off"


def clamav_db_hint(path: str | Path | None = None) -> bool:
    """2.7 fix: sf-entrypoint's 'on db' - the signatures were there at start."""
    try:
        return Path(path or CLAMAV_STATE_FILE).read_text().split() == ["on", "db"]
    except OSError:
        return False


RSPAMD_CHECK_URL = "http://127.0.0.1:11333/checkv2"


def rspamd_test_scan(url: str = RSPAMD_CHECK_URL, timeout: float = 15.0) -> set[str]:
    """The symbol names rspamd gives a tiny local test mail with one random
    attachment (random: the antivirus result cache never answers for it).
    Nothing leaves the container: no IP, no links, autolearn is off."""
    marker = os.urandom(24).hex()
    body = ("From: sf-health <sf-health@localhost>\r\nTo: sf-health@localhost\r\n"
            "Subject: sf-health clamav wait\r\nMIME-Version: 1.0\r\n"
            "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nx\r\n"
            "--b\r\nContent-Type: application/octet-stream\r\n"
            'Content-Disposition: attachment; filename="probe.bin"\r\n\r\n' + marker + "\r\n--b--\r\n").encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "message/rfc822"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - loopback only
        data = json.loads(resp.read(1024 * 1024).decode("utf-8", "replace"))
    syms = data.get("symbols") if isinstance(data, dict) else None
    if not isinstance(syms, dict):
        raise ValueError("no symbols")
    return set(syms)


def probe_clamav_ready(state_file: str | Path | None = None,
                       scan: Callable[[], set[str]] | None = None) -> Result:
    """2.7 fix, 'sf-health wait clamav' (the filter's uid: it cannot reach
    clamd's socket itself, so it asks rspamd). Ready when ClamAV is off,
    when no signatures were there at start (the first download takes
    minutes - not worth waiting; the antivirus re-scans catch up), or when a
    test scan through rspamd has no CLAM_VIRUS_FAIL."""
    on, _reason = clamav_state(state_file)
    if not on:
        return Result(True, "off")
    if not clamav_db_hint(state_file):
        return Result(True, "no signatures yet - not waiting")
    try:
        names = (scan or rspamd_test_scan)()
    except (OSError, ValueError) as ex:
        return Result(False, f"rspamd test scan failed ({ex.__class__.__name__})")
    if "CLAM_VIRUS_FAIL" in names:
        return Result(False, "clamd not answering yet")
    return Result(True, "clamd answers")


def _days(seconds: float) -> str:
    d = seconds / 86400
    return f"{d:.0f} day{'s' if round(d) != 1 else ''}" if d >= 1 else f"{seconds / 3600:.0f} h"


def evaluate_clamav(facts: dict[str, Any], now: float | None = None) -> Result:
    now = time.time() if now is None else now
    db_time = facts.get("db_time") or facts.get("file_time")
    age = max(0.0, now - float(db_time)) if db_time else None
    extra: dict[str, Any] = {"optional": True, "daily": facts.get("daily"),
                             "db_age_s": int(age) if age is not None else None}
    if not facts.get("ping"):
        if not facts.get("db_files"):
            return Result(False, "waiting for the first signature download (freshclam)",
                          {**extra, "state": "waiting"})
        why = facts.get("error") or "no PONG"
        old = f"; signatures {_days(age)} old" if age is not None else ""
        return Result(False, _short(f"clamd not answering ({why}){old}"), {**extra, "state": "down"})
    if age is not None and age > CLAMAV_STALE_S:
        return Result(False, f"signatures {_days(age)} old (freshclam not updating?)", {**extra, "state": "stale"})
    daily = f"daily {facts['daily']}, " if facts.get("daily") else ""
    when = f"{_days(age)} old" if age is not None else "age unknown"
    return Result(True, f"ok ({daily}{when})", {**extra, "state": "ok"})


def probe_clamav(as_root: bool, run: Runner = subprocess.run, timeout: float = 15.0,
                 state_file: str | Path | None = None, now: float | None = None,
                 python: str | None = None) -> Result:
    on, reason = clamav_state(state_file)
    if not on:
        return Result(True, f"off ({reason})", {"optional": True, "state": "off", "reason": reason})
    if not as_root:
        return evaluate_clamav(clamav_facts(), now)
    py = python or sys.executable or "/usr/local/bin/python3"
    cmd = [SETPRIV, f"--reuid={CLAMAV_UID}", f"--regid={CLAMAV_GID}", "--clear-groups", "--",
           py, "-s", "-E", str(Path(__file__).resolve()), "clamav-facts"]
    try:
        proc = run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        facts = json.loads((proc.stdout or "").strip().splitlines()[-1])
    except (OSError, subprocess.SubprocessError, ValueError, IndexError) as ex:
        return Result(False, f"probe failed ({ex.__class__.__name__})", {"optional": True, "state": "down"})
    if not isinstance(facts, dict):
        return Result(False, "probe failed (bad answer)", {"optional": True, "state": "down"})
    return evaluate_clamav(facts, now)


# ------------------------------------------------------------------ checks

def check_all(as_root: bool | None = None, run: Runner = subprocess.run,
              probes: dict[str, Callable[[], Result]] | None = None) -> dict[str, Result]:
    """Run the four probes (and 2.7 the optional clamav one) in parallel.
    As root the Redis probe uses the password (setpriv); otherwise only the
    unauthenticated PING."""
    root = (os.geteuid() == 0) if as_root is None else as_root
    fns: dict[str, Callable[[], Result]] = {
        "filter": lambda: probe_filter(root, run=run),
        "rspamd": probe_rspamd,
        "redis": (lambda: probe_redis_auth(run=run)) if root else probe_redis_alive,
        "unbound": probe_unbound,
        "clamav": lambda: probe_clamav(root, run=run),
    }
    if probes:
        fns.update(probes)
    names = PARTS + OPTIONAL_PARTS
    out: dict[str, Result] = {}
    with ThreadPoolExecutor(max_workers=len(names)) as ex:
        futures = {name: ex.submit(fns[name]) for name in names}
        for name, fut in futures.items():
            try:
                out[name] = fut.result()
            except Exception as err:  # noqa: BLE001 - a probe must never kill the check
                out[name] = Result(False, f"probe crashed ({err.__class__.__name__})")
    return out


def healthy(results: dict[str, Result]) -> bool:
    """The verdict: every required part ok (the optional ones never count)."""
    return all(r.ok for n, r in results.items() if n not in OPTIONAL_PARTS)


def summary_line(results: dict[str, Result]) -> str:
    bad = [f"{n}: {results[n].detail}" for n in PARTS if n in results and not results[n].ok]
    opt_ok = [n for n in OPTIONAL_PARTS if n in results and results[n].ok]
    warn = [f"{n}: {results[n].detail}" for n in OPTIONAL_PARTS if n in results and not results[n].ok]
    if bad:
        line = "unhealthy: " + "; ".join(bad)
    else:
        line = "ok: " + ", ".join([f"{n} ok" for n in PARTS if n in results]
                                  + [f"{n} {'off' if (results[n].extra or {}).get('state') == 'off' else 'ok'}"
                                     for n in opt_ok])
    if warn:
        line += "; warning: " + "; ".join(warn)
    return line


def status_json(results: dict[str, Result], now: float | None = None) -> dict[str, Any]:
    return {"ts": int(time.time() if now is None else now),
            "ok": healthy(results),
            "parts": {n: results[n].as_dict() for n in PARTS + OPTIONAL_PARTS if n in results}}


def write_status(path: str | Path, results: dict[str, Result], now: float | None = None) -> None:
    """Atomic, 0644: sfctl doctor (uid 10099) reads it."""
    p = Path(path)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(f".{p.name}.{os.getpid()}")
        tmp.write_text(json.dumps(status_json(results, now)) + "\n")
        tmp.chmod(0o644)
        os.replace(tmp, p)
    except OSError:
        pass  # the health verdict never depends on the status file


def read_status(path: str | Path = STATUS_FILE) -> dict[str, Any] | None:
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("parts"), dict):
        return None
    return data


# ------------------------------------------------------------------ wait

WAIT_PROBES: dict[str, Callable[[], Result]] = {
    "redis": probe_redis_alive,
    "unbound": probe_unbound,
    "rspamd": lambda: probe_rspamd(RSPAMD_PING_URLS[:1]),
    # 2.7 fix: the filter waits for clamd at start (when signatures exist).
    "clamav": probe_clamav_ready,
}


def wait_for(parts: Iterable[str], timeout: float, interval: float = 1.0,
             probes: dict[str, Callable[[], Result]] | None = None,
             clock: Callable[[], float] = time.monotonic,
             sleep: Callable[[float], None] = time.sleep) -> list[str]:
    """Wait until every part answers; returns the parts still down."""
    table = dict(WAIT_PROBES, **(probes or {}))
    pending = [p for p in parts]
    for p in pending:
        if p not in table:
            raise ValueError(f"unknown part {p}")
    deadline = clock() + timeout
    while True:
        pending = [p for p in pending if not table[p]().ok]
        if not pending or clock() >= deadline:
            return pending
        sleep(interval)


# ------------------------------------------------------------------ bayes

def controller_password(state_dir: str | None = None) -> str:
    """The rspamd controller password (state/controller.password, 0600
    uid 10099). Never printed."""
    base = Path(state_dir or os.environ.get("STATE_DIR") or "/state")
    pw = (base / "controller.password").read_text().strip()
    if not pw:
        raise ValueError("empty controller.password")
    return pw


def bayes_counts(url: str | None = None, password: str | None = None,
                 timeout: float = 20.0) -> list[tuple[str, int]]:
    """(symbol, learned) per statfile from the controller's /stat, in the
    order rspamd lists them (`rspamc stat` prints revision as 'learned').
    Raises OSError / ValueError (never with the password in it)."""
    pw = controller_password() if password is None else password
    req = urllib.request.Request(url or CONTROLLER_STAT_URL, headers={"Password": pw})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as resp:
        data = json.loads(resp.read(1 << 20) or b"{}")
    out: list[tuple[str, int]] = []
    for sf in data.get("statfiles") or []:
        if isinstance(sf, dict) and sf.get("symbol"):
            try:
                out.append((str(sf["symbol"]), int(sf.get("revision") or 0)))
            except (TypeError, ValueError):
                continue
    return out


# ------------------------------------------------------------------ listeners

def _hex_ip(hexaddr: str) -> str:
    raw = bytes.fromhex(hexaddr)
    if len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, raw[::-1])
    # IPv6: four 32-bit words, each little-endian
    words = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
    return socket.inet_ntop(socket.AF_INET6, words)


def _is_loopback(ip: str) -> bool:
    return ip.startswith("127.") or ip == "::1" or ip.startswith("::ffff:127.")


def listeners(proc: Path = Path("/proc"), allow_ports: Iterable[int] = (WEBUI_PORT,),
              udp_ports: Iterable[int] = (53, UNBOUND_PORT, 11335)) -> list[str]:
    """Sockets that listen on a non-loopback address and are not allowed:
    every TCP LISTEN socket except the WebUI, plus UDP sockets bound to the
    DNS / fuzzy ports (outgoing UDP query sockets are not listeners)."""
    allowed = set(int(p) for p in allow_ports)
    watched_udp = set(int(p) for p in udp_ports)
    bad: list[str] = []
    for proto, want_state in (("tcp", "0A"), ("tcp6", "0A"), ("udp", "07"), ("udp6", "07")):
        try:
            lines = (proc / "net" / proto).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            f = line.split()
            if len(f) < 4 or f[3] != want_state:
                continue
            addr, _, port_hex = f[1].partition(":")
            port = int(port_hex, 16)
            ip = _hex_ip(addr)
            if _is_loopback(ip):
                continue
            if proto.startswith("tcp") and port in allowed:
                continue
            if proto.startswith("udp") and port not in watched_udp:
                continue
            bad.append(f"{proto} {ip}:{port}")
    return sorted(set(bad))


# ------------------------------------------------------------------ CLI

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sf-health", description="Health of the all-in-one container")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="check all four parts (Docker HEALTHCHECK)")
    c.add_argument("--status-file", default=STATUS_FILE)
    c.add_argument("--json", action="store_true", help="print only the JSON line")
    w = sub.add_parser("wait", help="wait until parts answer (start order)")
    w.add_argument("parts", nargs="+", choices=sorted(WAIT_PROBES))
    w.add_argument("--timeout", type=float, default=120.0)
    sub.add_parser("listeners", help="fail if anything but the WebUI listens outside loopback")
    sub.add_parser("bayes", help="learned counts per statfile (run as uid 10099)")
    sub.add_parser("clamav", help="2.7: the ClamAV status alone (exit 0 = ok or off)")
    sub.add_parser("clamav-facts", help=argparse.SUPPRESS)  # internal: run as the clamav uid
    args = ap.parse_args(argv)

    if args.cmd == "check":
        results = check_all()
        if args.status_file:
            write_status(args.status_file, results)
        if not args.json:
            print(summary_line(results))
        print(json.dumps(status_json(results)))
        return 0 if healthy(results) else 1
    if args.cmd == "clamav-facts":
        print(json.dumps(clamav_facts()))
        return 0
    if args.cmd == "clamav":
        r = probe_clamav(os.geteuid() == 0)
        print(f"clamav: {r.detail}")
        return 0 if r.ok else 1
    if args.cmd == "wait":
        missing = wait_for(args.parts, args.timeout)
        if missing:
            print("not ready: " + ", ".join(missing))
            return 1
        return 0
    if args.cmd == "bayes":
        try:
            counts = bayes_counts()
        except urllib.error.HTTPError as ex:
            print(f"bayes: controller answered HTTP {ex.code}", file=sys.stderr)
            return 1
        except (OSError, ValueError) as ex:
            print(f"bayes: not readable ({ex.__class__.__name__})", file=sys.stderr)
            return 1
        for symbol, learned in counts:
            print(f"{symbol} {learned}")
        return 0 if counts else 1
    bad = listeners()
    if bad:
        print("listening outside loopback: " + ", ".join(bad))
        return 1
    print(f"ok: only the WebUI ({WEBUI_PORT}) listens outside loopback")
    return 0


if __name__ == "__main__":
    sys.exit(main())
