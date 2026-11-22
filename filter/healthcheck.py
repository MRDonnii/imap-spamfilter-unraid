"""Docker HEALTHCHECK for the spamfilter container (SPEC I1).

Healthy (exit 0) only when ALL of these hold:

1. ``$STATE_DIR/heartbeat`` exists and is fresh (younger than 90 s). The
   engine writes ``"<unix_ts> <boot_id>"``; a bare ``"<unix_ts>"`` (1.x
   format) is still accepted.
2. The heartbeat belongs to THIS container run, so a file left behind by a
   previous container (or the rollback container) never counts:
   - if both the heartbeat and ``$STATE_DIR/boot_id`` carry a boot id they
     must be equal (main() writes boot_id at startup), and
   - the heartbeat timestamp must not predate the start of PID 1 (the
     container's init), taken from ``/proc/1/stat`` + ``/proc/stat`` btime.
   At least one of the two proofs must be available.
3. ``GET http://127.0.0.1:8080/healthz`` returns 200 within 5 s.

Anything else exits 1 with one short line on stdout, which Docker keeps in
``State.Health.Log`` (so ``docker inspect`` shows *why* it is unhealthy).
Stdlib only and never imports the application: the probe must work even
when the app's own imports are broken, and must stay cheap every 30 s.
"""

from __future__ import annotations

import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_URL = "http://127.0.0.1:8080/healthz"
MAX_HEARTBEAT_AGE = 90.0
HTTP_TIMEOUT = 5.0
# btime has 1 s resolution and starttime is in clock ticks, so the derived
# container start time can be off by up to ~1 s; allow a little slack.
START_SLACK = 2.0


class Unhealthy(Exception):
    """Raised with a short, secret-free reason."""


def read_heartbeat(path: Path) -> tuple[float, str | None]:
    """Return (timestamp, boot_id|None) from a heartbeat file."""
    try:
        text = path.read_text(encoding="ascii", errors="replace").strip()
    except FileNotFoundError:
        raise Unhealthy("heartbeat missing") from None
    except OSError as ex:
        raise Unhealthy(f"heartbeat unreadable ({ex.__class__.__name__})") from None
    parts = text.split()
    if not parts:
        raise Unhealthy("heartbeat empty")
    try:
        ts = float(parts[0])
    except ValueError:
        raise Unhealthy("heartbeat malformed") from None
    return ts, (parts[1] if len(parts) > 1 else None)


def read_boot_id(path: Path) -> str | None:
    try:
        value = path.read_text(encoding="ascii", errors="replace").strip()
    except OSError:
        return None
    return value.split()[0] if value else None


def container_start_time(proc: Path = Path("/proc")) -> float | None:
    """Unix time PID 1 of this PID namespace started, or None if unknown.

    PID 1 is docker-init (``--init``) or the app itself; either way it starts
    with the container. starttime (field 22 of /proc/<pid>/stat) is in clock
    ticks since host boot; btime in /proc/stat is the host boot time.
    """
    try:
        stat = (proc / "1" / "stat").read_text()
        # comm (field 2) may contain spaces/parens: split after the LAST ')'.
        fields = stat[stat.rindex(")") + 2:].split()
        start_ticks = int(fields[19])  # field 22 overall; list starts at field 3
        btime = None
        for line in (proc / "stat").read_text().splitlines():
            if line.startswith("btime "):
                btime = int(line.split()[1])
                break
        if btime is None:
            return None
        return btime + start_ticks / os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, IndexError):
        return None


def check_heartbeat(state_dir: Path, *, now: float, max_age: float = MAX_HEARTBEAT_AGE,
                    started_at: float | None) -> None:
    ts, hb_boot = read_heartbeat(state_dir / "heartbeat")
    age = now - ts
    if age > max_age:
        raise Unhealthy(f"heartbeat stale ({int(age)} s old)")
    if age < -max_age:
        raise Unhealthy("heartbeat timestamp in the future")
    proven = False
    file_boot = read_boot_id(state_dir / "boot_id")
    if hb_boot is not None and file_boot is not None:
        if hb_boot != file_boot:
            raise Unhealthy("heartbeat is from another run (boot id mismatch)")
        proven = True
    if started_at is not None:
        if ts < started_at - START_SLACK:
            raise Unhealthy("heartbeat predates container start")
        proven = True
    if not proven:
        raise Unhealthy("cannot tie heartbeat to this container run")


def check_http(url: str, *, timeout: float = HTTP_TIMEOUT) -> None:
    # No proxies: the probe must hit the in-container listener directly.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    started = time.monotonic()
    try:
        with opener.open(url, timeout=timeout) as resp:
            resp.read(4096)
            status = resp.status
    except urllib.error.HTTPError as ex:
        raise Unhealthy(f"healthz returned HTTP {ex.code}") from None
    except (urllib.error.URLError, OSError) as ex:
        reason = getattr(ex, "reason", ex)
        raise Unhealthy(f"healthz unreachable ({reason.__class__.__name__})") from None
    if time.monotonic() - started > timeout:
        raise Unhealthy("healthz too slow")
    if status != 200:
        raise Unhealthy(f"healthz returned HTTP {status}")


def main(argv: list[str] | None = None) -> int:
    state_dir = Path(os.environ.get("STATE_DIR", "/state"))
    url = os.environ.get("HEALTHCHECK_URL", DEFAULT_URL)
    try:
        max_age = float(os.environ.get("HEARTBEAT_MAX_AGE", MAX_HEARTBEAT_AGE))
    except ValueError:
        max_age = MAX_HEARTBEAT_AGE
    try:
        check_heartbeat(state_dir, now=time.time(), max_age=max_age,
                        started_at=container_start_time())
        check_http(url)
    except Unhealthy as ex:
        print(f"unhealthy: {ex}")
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
