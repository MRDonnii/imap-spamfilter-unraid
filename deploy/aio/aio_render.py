"""Runtime configuration of the all-in-one container (2.4).

Called by sf-entrypoint at every container start. The AIO reuses the app
dir of the 4-container layout UNCHANGED (same files, same uids), so a
rollback to the four containers keeps working. Files that name the old
container hosts (spamfilter-redis, spamfilter-unbound, *:port binds) are
therefore never edited in place: a runtime variant is rendered into the
tmpfs /run/spamfilter instead.

  rspamd   SRC_DIR (appdata rspamd/local.d) -> DST_DIR (/etc/rspamd/local.d
           is a symlink to it). Runs as uid 11333 (owner of local.d).
           Every file is copied; then
             - redis.conf: servers / read_servers / write_servers -> 127.0.0.1:6379
             - any file: the host names spamfilter-redis / spamfilter-rspamd ->
               127.0.0.1, spamfilter-unbound[:53] -> 127.0.0.1:5353 (options.inc
               nameserver)
             - bind_socket = "*:N" / "0.0.0.0:N" / "[::]:N" -> "127.0.0.1:N"
             - worker-controller.inc: secure_ip -> 192.0.2.1 (TEST-NET-1, never
               a source here). In the 4-container layout only rspamd's own
               loopback was password-exempt; in ONE container every program
               shares that loopback, so nobody may skip the controller
               password (the filter always sends it).
           Fails when the result still names an old host or redis.conf has
           no server. 2.7: --no-antivirus (SF_CLAMAV=0) renders
           antivirus.conf as 'enabled = false;' - no clamd runs then, and
           rspamd must not try its socket for every mail. 2.7 fix: with
           ClamAV on, an app-dir antivirus.conf without a clamav { } rule
           (the 4-container layout installs a disabled copy: no clamd
           there) is replaced by --antivirus-src, the image's own copy -
           so a migrated install scans from its first all-in-one start.
  unbound  SRC (appdata unbound.conf, else the image's copy of
           deploy/unbound.conf) -> DST. Runs as the unbound user. In the
           server: section directory / chroot / username / pidfile /
           auto-trust-anchor-file / interface / port are replaced
           (127.0.0.1@5353 - an unprivileged port, so the container needs no
           ip_unprivileged_port_start sysctl and no other uid can take over
           a privileged DNS port; no chroot, no privilege drop - supervisord
           already runs it as unbound); a missing forward-zone is taken from
           unbound-forward-records.conf. The DNSSEC root key is copied from
           the image (dns-root-data) into the runtime dir.
  site     config/site.yml (the local site configuration: own domains,
           webshops, platforms, DNS forwarder; read as uid 10099) ->
           /run/spamfilter/site/site.json (0644, plain lists only). A
           missing or invalid file is no error: empty lists + a warning
           (the WebUI shows "Lokal opsætning mangler"). The file is only
           READ here - never created, merged or rewritten on an existing
           install.
  rspamd --site: the own domains are added to the rendered copies of
           maps.d/surbl-whitelist.inc.local, th_brand_domains.map,
           phishing_feed_exclusion.inc and the TH_PHISHARMY_URL exclusion in
           multimap.conf - the repository and the app dir carry no
           personal values.
  init     FRESH app dir only (no state/, no redis-config/, no rspamd
           redis.conf): creates the 4-container layout with the same owners
           (10099 state/config, 999:1000 redis, 11333 rspamd), generates the
           Redis and controller passwords (never printed) and renders the
           three secret configs from the bundled templates, and writes the
           empty config/site.yml (site.seed.yml, setup_done: false). An
           existing or partial install is never touched.

Stdlib only. Never prints file content: only names and counts.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import sys
from pathlib import Path

LOOPBACK = "127.0.0.1"
OLD_HOSTS = ("spamfilter-redis", "spamfilter-unbound", "spamfilter-rspamd")
REDIS_SERVER = "127.0.0.1:6379"
# Unbound listens on an unprivileged loopback port in the AIO (see unbound).
UNBOUND_PORT = 5353
UNBOUND_RE = re.compile(r"spamfilter-unbound(?::53(?!\d))?(?![\w.-])")
# The controller's password-exempt address in the AIO: RFC 5737 TEST-NET-1,
# which no program in the container connects from (see render_rspamd_text).
CONTROLLER_SECURE_IP = "192.0.2.1"
SECURE_IP_RE = re.compile(r'^(\s*)secure_ip\s*=.*$', re.M)
SECURE_IP_LINE = f'secure_ip = "{CONTROLLER_SECURE_IP}";  # all-in-one: no password-free client'
SERVERS_RE = re.compile(r'^(\s*(?:servers|read_servers|write_servers)\s*=\s*)"[^"]*"(\s*;?)', re.M)
BIND_RE = re.compile(r'^(\s*bind_socket\s*=\s*")(?:\*v4|\*v6|\*|0\.0\.0\.0|\[::\]|::)(:\d+")', re.M)
# 2.7: the runtime antivirus.conf when ClamAV is switched off (SF_CLAMAV=0).
ANTIVIRUS_OFF = ("# all-in-one container: SF_CLAMAV=0 - no clamd runs, virus scanning is off\n"
                 "# (the app dir keeps the real antivirus.conf; see aio_render.py)\n"
                 "enabled = false;\n")
# 2.7 fix: the real antivirus.conf has a clamav { } rule.
CLAMAV_RULE_RE = re.compile(r"^\s*clamav\s*\{", re.M)
TEXT_SUFFIXES = (".conf", ".inc", ".map", ".re", ".local", ".txt", ".lua", ".readonly", ".template")

FILTER_UID = FILTER_GID = 10099
REDIS_UID, REDIS_GID = 999, 1000
RSPAMD_UID = RSPAMD_GID = 11333
# Non-secret rspamd files of a fresh install (same list as deploy/lib.sh
# SF_RSPAMD_FILES); fuzzy_check.conf is the disabled variant unless
# SPAMFILTER_ENABLE_FUZZY=1.
RSPAMD_FILES = ("actions.conf", "antivirus.conf", "classifier-bayes.conf", "composites.conf", "greylist.conf",
                "groups.conf", "multimap.conf", "neural.conf", "options.inc", "phishing.conf",
                "rbl.conf", "worker-normal.inc", "worker-fuzzy.inc", "url_redirector.conf")


class RenderError(Exception):
    """Short, secret-free reason (printed by the entrypoint)."""


def log(msg: str) -> None:
    print(f"[init] {msg}", flush=True)


# ------------------------------------------------------------------ rspamd

def render_rspamd_text(name: str, text: str) -> tuple[str, int]:
    """(new text, number of changes) for one local.d file."""
    n = 0
    if name == "redis.conf":
        text, k = SERVERS_RE.subn(lambda m: f'{m.group(1)}"{REDIS_SERVER}"{m.group(2)}', text)
        n += k
    text, k = UNBOUND_RE.subn(f"{LOOPBACK}:{UNBOUND_PORT}", text)
    n += k
    for host in OLD_HOSTS:
        k = text.count(host)
        if k:
            text = text.replace(host, LOOPBACK)
            n += k
    text, k = BIND_RE.subn(lambda m: f"{m.group(1)}{LOOPBACK}{m.group(2)}", text)
    n += k
    if name == "worker-controller.inc":
        text, k = pin_secure_ip(text)
        n += k
    return text, n


def pin_secure_ip(text: str) -> tuple[str, int]:
    """Every secure_ip line -> SECURE_IP_LINE (one is appended when there
    is none). Returns (text, number of changes)."""
    if SECURE_IP_RE.search(text):
        new, k = SECURE_IP_RE.subn(lambda m: m.group(1) + SECURE_IP_LINE, text)
        return new, (k if new != text else 0)
    return (text.rstrip("\n") + "\n" if text.strip() else "") + SECURE_IP_LINE + "\n", 1


def _is_text(p: Path) -> bool:
    return p.suffix in TEXT_SUFFIXES or p.name in ("redis.conf", "options.inc")


def render_rspamd(src: Path, dst: Path, antivirus: bool = True, antivirus_src: Path | None = None,
                  site: dict | None = None) -> dict[str, int]:
    """Copy SRC (never modified) to a fresh DST with the AIO hosts.
    antivirus=False (SF_CLAMAV=0): antivirus.conf becomes ANTIVIRUS_OFF.
    antivirus=True: an antivirus.conf without a clamav rule (the 4-container
    disabled copy) becomes `antivirus_src` (the image's copy) when given."""
    if not src.is_dir():
        raise RenderError(f"{src} missing")
    if not (src / "redis.conf").is_file():
        raise RenderError(f"{src}/redis.conf missing (rendered by init-host.sh / the first start)")
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(mode=0o750, parents=True)
    changes: dict[str, int] = {}
    for path in sorted(src.rglob("*")):
        rel = path.relative_to(src)
        target = dst / rel
        if path.is_symlink():
            continue  # never follow a link out of the shared config dir
        if path.is_dir():
            target.mkdir(mode=0o750, exist_ok=True)
            continue
        if not path.is_file():
            continue
        data = path.read_bytes()
        if _is_text(path):
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = None
            if text is not None:
                new, n = render_rspamd_text(path.name, text)
                if not antivirus and str(rel) == "antivirus.conf":
                    new, n = ANTIVIRUS_OFF, n + 1
                elif (str(rel) == "antivirus.conf" and not CLAMAV_RULE_RE.search(text)
                      and antivirus_src is not None and antivirus_src.is_file()):
                    new, n = antivirus_src.read_text("utf-8"), n + 1
                if n:
                    changes[str(rel)] = n
                data = new.encode("utf-8")
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    if site:
        for rel, n in apply_site(dst, site).items():
            changes[rel] = changes.get(rel, 0) + n
    verify_rspamd(dst)
    return changes


# ------------------------------------------------------------------ site
SITE_JSON = "site.json"
SITE_MARK = "# --- lokal opsaetning (config/site.yml), lagt paa ved containerstart ---"
PHISHARMY_ANCHOR = "regexp:/^(?!(www[.])?("
SITE_MAPS = (("maps.d/surbl-whitelist.inc.local", "surbl_whitelist", ("{d}",)),
             ("maps.d/th_brand_domains.map", "brand_domains", ("{d}",)),
             ("maps.d/phishing_feed_exclusion.inc", "phishing_feed_exclusion", ("https://{d}/", "https://www.{d}/")))
SITE_DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
SITE_IP_RE = re.compile(r"^[0-9a-fA-F:.]{2,45}$")


def _site_module():
    """filter/siteconfig.py: /app in the image, ../../filter in the repo."""
    for cand in (Path("/app"), Path(__file__).resolve().parents[2] / "filter"):
        if (cand / "siteconfig.py").is_file() and str(cand) not in sys.path:
            sys.path.insert(0, str(cand))
    import siteconfig  # noqa: PLC0415

    return siteconfig


def render_site(config: Path, out: Path) -> dict:
    """config/site.yml -> OUT/site.json (status + the lists rspamd and
    unbound need). Only reads CONFIG."""
    sc = _site_module()
    site = sc.load(config)
    data = {"status": site.status, **sc.rspamd_values(site)}
    out.mkdir(mode=0o755, parents=True, exist_ok=True)
    tmp = out / f".{SITE_JSON}.tmp"
    tmp.write_text(json.dumps(data, sort_keys=True) + "\n", encoding="utf-8")
    tmp.chmod(0o644)
    os.replace(tmp, out / SITE_JSON)
    return data


def load_site(path: Path | None) -> dict | None:
    if path is None or not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _site_list(site: dict, key: str, rx: re.Pattern[str] = SITE_DOMAIN_RE) -> list[str]:
    vals = site.get(key)
    if not isinstance(vals, list):
        return []
    return [v for v in (str(x).strip().lower() for x in vals) if rx.match(v)]


def apply_site(dst: Path, site: dict) -> dict[str, int]:
    """Add the local site values to the rendered rspamd copy DST."""
    changes: dict[str, int] = {}
    for rel, key, fmts in SITE_MAPS:
        vals = _site_list(site, key)
        target = dst / rel
        if not vals or not target.is_file():
            continue
        lines = [f.format(d=d) for d in vals for f in fmts]
        with target.open("a", encoding="utf-8") as fh:
            fh.write("\n" + SITE_MARK + "\n" + "\n".join(lines) + "\n")
        changes[rel] = len(lines)
    alts = _site_list(site, "phisharmy_exclusion")
    mm = dst / "multimap.conf"
    if alts and mm.is_file():
        text = mm.read_text("utf-8")
        if text.count(PHISHARMY_ANCHOR) == 1:
            extra = "|".join(d.replace(".", "[.]") for d in alts) + "|"
            mm.write_text(text.replace(PHISHARMY_ANCHOR, PHISHARMY_ANCHOR + extra, 1), encoding="utf-8")
            changes["multimap.conf"] = changes.get("multimap.conf", 0) + len(alts)
    return changes


def site_forward_zone(site: dict | None) -> str | None:
    ips = _site_list(site or {}, "dns_forwarders", SITE_IP_RE)
    if not ips:
        return None
    return "forward-zone:\n    name: \".\"\n" + "".join(f"    forward-addr: {ip}\n" for ip in ips)


def verify_rspamd(dst: Path) -> None:
    for path in dst.rglob("*"):
        if path.is_file() and _is_text(path):
            text = path.read_text("utf-8", "replace")
            for host in OLD_HOSTS:
                if host in text:
                    raise RenderError(f"{path.name} still names {host}")
    redis = (dst / "redis.conf").read_text("utf-8", "replace")
    if not re.search(r'^\s*servers\s*=\s*"127\.0\.0\.1:6379"', redis, re.M):
        raise RenderError("redis.conf has no servers line for 127.0.0.1:6379")
    ctrl = dst / "worker-controller.inc"
    if ctrl.is_file():
        for m in re.finditer(r'^\s*secure_ip\s*=\s*"?([^";\s]*)', ctrl.read_text("utf-8", "replace"), re.M):
            if m.group(1) != CONTROLLER_SECURE_IP:
                raise RenderError("worker-controller.inc still has a password-free secure_ip")


# ------------------------------------------------------------------ unbound

SECTION_RE = re.compile(r"^\s*([A-Za-z0-9-]+):\s*(#.*)?$")
REPLACED = ("directory", "chroot", "username", "pidfile", "auto-trust-anchor-file", "interface", "port")


def render_unbound_text(text: str, run_dir: str, forward_records: str | None = None) -> str:
    want = {
        "directory": f'"{run_dir}"',
        "chroot": '""',
        "username": '""',
        "pidfile": f'"{run_dir}/unbound.pid"',
        "auto-trust-anchor-file": f'"{run_dir}/root.key"',
        "interface": f"{LOOPBACK}@{UNBOUND_PORT}",
        "port": str(UNBOUND_PORT),
    }
    out: list[str] = []
    section = None
    seen_server = False
    inserted = False
    for line in text.splitlines():
        m = SECTION_RE.match(line)
        if m:  # a clause header ("server:", "forward-zone:", ...) has no value
            section = m.group(1)
            out.append(line)
            if section == "server" and not inserted:
                seen_server = True
                inserted = True
                out.extend(f"    {k}: {v}" for k, v in want.items())
                out.append("    # (the lines above are set by the all-in-one container)")
            continue
        if section == "server":
            km = re.match(r"^\s*([A-Za-z0-9-]+):", line)
            if km and km.group(1) in REPLACED:
                continue
        out.append(line)
    if not seen_server:
        out = ["server:", *(f"    {k}: {v}" for k, v in want.items()), *out]
    result = "\n".join(out) + "\n"
    if not re.search(r"^\s*forward-zone:", result, re.M) and forward_records:
        result += "\n# from unbound-forward-records.conf\n" + forward_records.rstrip("\n") + "\n"
    return result


def render_unbound(src: Path | None, fallback: Path, dst: Path, run_dir: Path,
                   forward: Path | None = None, root_key: Path | None = None,
                   site: dict | None = None) -> str:
    """Returns which base config was used ('appdata' or 'image')."""
    used = "image"
    base = fallback
    if src is not None and src.is_file():
        base, used = src, "appdata"
    if not base.is_file():
        raise RenderError(f"no unbound.conf ({src} and {fallback} missing)")
    fwd = forward.read_text() if forward is not None and forward.is_file() else None
    if fwd is None:
        fwd = site_forward_zone(site)  # the DNS forwarder from config/site.yml
    text = render_unbound_text(base.read_text(), str(run_dir), fwd)
    run_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
    tmp = dst.with_name(f".{dst.name}.tmp")
    tmp.write_text(text)
    tmp.chmod(0o640)
    os.replace(tmp, dst)
    if root_key is not None and root_key.is_file():
        key = run_dir / "root.key"
        key.write_bytes(root_key.read_bytes())
        key.chmod(0o640)
    if not re.search(r"^\s*forward-zone:", text, re.M):
        log("WARNING: unbound has no forward-zone - it resolves from the root servers")
    return used


# ------------------------------------------------------------------ override.d

# The rspamd image's /etc/rspamd/override.d (priority 10, beats local.d
# AND rspamd's own defaults) may bind workers to "*:port" for the
# multi-container setup. In the AIO image every worker must stay on
# loopback: rewrite those binds and pin the controller and the normal worker
# explicitly. The controller's secure_ip is pinned here too: rspamd's
# default worker-controller.inc exempts 127.0.0.1 and ::1, and only an
# override.d value replaces that list. Build time only.
# Every worker the base rspamd.conf defines with a "*" bind: controller,
# normal, proxy (11332) and fuzzy storage (11335) - all loopback-only here.
OVERRIDE_PINS = {"worker-controller.inc": 11334, "worker-normal.inc": 11333,
                 "worker-proxy.inc": 11332, "worker-fuzzy.inc": 11335}


def harden_override(d: Path) -> list[str]:
    """Rewrite worker binds in an rspamd override.d to 127.0.0.1. Returns
    the files written."""
    d.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    names = {p.name for p in d.glob("worker-*.inc")} | set(OVERRIDE_PINS)
    for name in sorted(names):
        path = d / name
        text = path.read_text() if path.is_file() else ""
        new, _ = BIND_RE.subn(lambda m: f"{m.group(1)}{LOOPBACK}{m.group(2)}", text)
        port = OVERRIDE_PINS.get(name)
        if port is not None and not re.search(r"^\s*bind_socket\s*=", new, re.M):
            new = (new.rstrip("\n") + "\n" if new.strip() else "") + f'bind_socket = "{LOOPBACK}:{port}";\n'
        if name == "worker-controller.inc":
            new, _ = pin_secure_ip(new)
        if new != text:
            path.write_text(new)
            path.chmod(0o644)
            written.append(name)
    return written


# ------------------------------------------------------------------ binds

LOOPBACK_BIND_RE = re.compile(r"^(127\.0\.0\.1|localhost|\[::1\]|::1)(:\d+)?$")


def bind_sockets(node: object) -> list[str]:
    """Every bind_socket value anywhere in an rspamadm configdump -j tree."""
    found: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "bind_socket":
                found.extend(str(x) for x in (v if isinstance(v, list) else [v]))
            else:
                found.extend(bind_sockets(v))
    elif isinstance(node, list):
        for v in node:
            found.extend(bind_sockets(v))
    return found


def check_binds(dump: dict) -> list[str]:
    """bind_socket values that are not loopback (empty list = fine)."""
    binds = bind_sockets(dump)
    if not binds:
        return ["(no bind_socket found)"]
    return [b for b in binds if not LOOPBACK_BIND_RE.match(b.strip())]


def _values(node: object, key: str) -> list[str]:
    found: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key:
                found.extend(str(x) for x in (v if isinstance(v, list) else [v]))
            else:
                found.extend(_values(v, key))
    elif isinstance(node, list):
        for v in node:
            found.extend(_values(v, key))
    return found


def check_secure_ip(dump: dict) -> list[str]:
    """secure_ip values other than CONTROLLER_SECURE_IP (empty = fine): in
    one container a loopback exemption would let every program use the
    controller (learn, maps, actions) without the password."""
    return [v for v in _values(dump, "secure_ip") if v.strip() != CONTROLLER_SECURE_IP]


# ------------------------------------------------------------------ init

def _write_new(path: Path, data: bytes, mode: int, owner: tuple[int, int], chown: bool) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(path, mode)
    if chown:
        os.chown(path, *owner)


def _mkdir(path: Path, mode: int) -> None:
    path.mkdir(mode=mode, exist_ok=True)
    os.chmod(path, mode)


def is_fresh(app: Path) -> bool:
    return not any(p.exists() for p in (app / "state", app / "redis-config", app / "config"))


def init_appdata(app: Path, bundle: Path, *, chown: bool = True, fuzzy: bool = False) -> bool:
    """Create a fresh app dir. Returns False (and changes nothing) when any
    part of an install already exists."""
    if not app.is_dir():
        raise RenderError(f"{app} missing")
    if not is_fresh(app):
        return False
    if (app / "rspamd" / "local.d" / "redis.conf").exists():
        raise RenderError("rspamd/local.d/redis.conf exists but state/ does not - partial install, "
                          "refusing to generate new passwords")
    for name in ("redis.conf.template", "rspamd/redis.conf.template",
                 "rspamd/worker-controller.inc.template", "accounts.seed.yml"):
        if not (bundle / name).is_file():
            raise RenderError(f"bundle file {name} missing")
    redis_pw = secrets.token_hex(32)
    ctrl_pw = secrets.token_hex(32)
    fu, ru, su = (FILTER_UID, FILTER_GID), (REDIS_UID, REDIS_GID), (RSPAMD_UID, RSPAMD_GID)

    # Everything is created by root first (root owns the new dirs, so no
    # CAP_DAC_OVERRIDE is needed), the owners are set last.
    state, config = app / "state", app / "config"
    for d in (state, state / "imap-secrets", config, app / "redis", app / "redis-config"):
        _mkdir(d, 0o700)
    _mkdir(app / "operations", 0o700)
    # Docker itself creates the bind source <app>/rspamd/data (root, empty)
    # before the first start, so "new" means: no rspamd/local.d yet.
    rspamd_new = not (app / "rspamd" / "local.d").exists()
    if rspamd_new:
        for d in (app / "rspamd", app / "rspamd" / "local.d", app / "rspamd" / "local.d" / "maps.d",
                  app / "rspamd" / "data"):
            _mkdir(d, 0o750)
    _write_new(state / "redis.password", (redis_pw + "\n").encode(), 0o600, fu, chown)
    _write_new(state / "controller.password", (ctrl_pw + "\n").encode(), 0o600, fu, chown)
    _write_new(config / "accounts.yml", (bundle / "accounts.seed.yml").read_bytes(), 0o600, fu, chown)
    if (bundle / "site.seed.yml").is_file():  # the empty local site config (setup_done: false)
        _write_new(config / "site.yml", (bundle / "site.seed.yml").read_bytes(), 0o600, fu, chown)
    redis_conf = (bundle / "redis.conf.template").read_text().replace("${REDIS_PASSWORD}", redis_pw)
    _write_new(app / "redis-config" / "redis.conf", redis_conf.encode(), 0o600, ru, chown)
    if rspamd_new:
        ld = app / "rspamd" / "local.d"
        rc = (bundle / "rspamd" / "redis.conf.template").read_text().replace("${REDIS_PASSWORD}", redis_pw)
        _write_new(ld / "redis.conf", rc.encode(), 0o600, su, chown)
        wc = (bundle / "rspamd" / "worker-controller.inc.template").read_text().replace(
            "${RSPAMD_PASSWORD}", ctrl_pw)
        _write_new(ld / "worker-controller.inc", wc.encode(), 0o600, su, chown)
        for name in RSPAMD_FILES:
            src = bundle / "rspamd" / name
            if src.is_file():
                _write_new(ld / name, src.read_bytes(), 0o640, su, chown)
        fz = bundle / "rspamd" / ("fuzzy_check.conf.readonly" if fuzzy else "fuzzy_check.conf")
        if fz.is_file():
            _write_new(ld / "fuzzy_check.conf", fz.read_bytes(), 0o640, su, chown)
        maps = bundle / "rspamd" / "maps.d"
        if maps.is_dir():
            for m in sorted(maps.iterdir()):
                if m.is_file() and not m.is_symlink():
                    _write_new(ld / "maps.d" / m.name, m.read_bytes(), 0o640, su, chown)
    if chown:
        for d in (state / "imap-secrets", state, config):
            os.chown(d, *fu)
        for d in (app / "redis", app / "redis-config"):
            os.chown(d, *ru)
        if rspamd_new:
            for d in (app / "rspamd" / "local.d" / "maps.d", app / "rspamd" / "local.d",
                      app / "rspamd" / "data", app / "rspamd"):
                os.chown(d, *su)
    return True


# ------------------------------------------------------------------ CLI

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="aio_render")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("rspamd")
    r.add_argument("--src", required=True)
    r.add_argument("--dst", required=True)
    r.add_argument("--no-antivirus", action="store_true", help="SF_CLAMAV=0: antivirus.conf -> enabled = false")
    r.add_argument("--antivirus-src", help="the image's antivirus.conf (replaces a disabled 4-container copy)")
    r.add_argument("--site", help="site.json from 'aio_render.py site' (own domains for the maps)")
    st = sub.add_parser("site", help="config/site.yml -> site.json (read only)")
    st.add_argument("--config", required=True)
    st.add_argument("--out", required=True)
    u = sub.add_parser("unbound")
    u.add_argument("--src", required=True)
    u.add_argument("--fallback", required=True)
    u.add_argument("--forward")
    u.add_argument("--dst", required=True)
    u.add_argument("--dir", required=True)
    u.add_argument("--root-key")
    u.add_argument("--site", help="site.json (DNS forwarder when no forward-zone is set)")
    i = sub.add_parser("init")
    i.add_argument("--appdata", required=True)
    i.add_argument("--bundle", required=True)
    i.add_argument("--no-chown", action="store_true", help="tests only")
    o = sub.add_parser("override", help="build time: rspamd override.d workers on loopback")
    o.add_argument("--dir", required=True)
    b = sub.add_parser("check-binds", help="rspamadm configdump -j file: all workers on loopback, no password-free controller client?")
    b.add_argument("dump")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "override":
            written = harden_override(Path(args.dir))
            log("rspamd override.d: " + (", ".join(written) or "nothing to change") + " (workers on 127.0.0.1)")
        elif args.cmd == "check-binds":
            import json
            dump = json.loads(Path(args.dump).read_text())
            bad = check_binds(dump)
            if bad:
                print("[init] ERROR: rspamd binds outside loopback: " + ", ".join(bad[:5]), file=sys.stderr)
                return 1
            exempt = check_secure_ip(dump)
            if exempt:
                print("[init] ERROR: the rspamd controller exempts " + ", ".join(exempt[:5])
                      + " from its password", file=sys.stderr)
                return 1
            print("[init] rspamd workers bind to loopback only; the controller always wants its password")
        elif args.cmd == "site":
            data = render_site(Path(args.config), Path(args.out))
            n = sum(len(v) for v in data.values() if isinstance(v, list))
            if data["status"] == "ok":
                log(f"local site config: {n} value(s) for rspamd/unbound")
            elif data["status"] == "missing":
                log("WARNING: config/site.yml is missing - running with an EMPTY local site config "
                    "(no own domains in the rspamd maps); the WebUI shows 'Lokal opsætning mangler'")
            else:
                log("WARNING: config/site.yml cannot be read - running with an EMPTY local site config; "
                    "the WebUI shows 'Lokal opsætning kan ikke læses'")
        elif args.cmd == "rspamd":
            site = load_site(Path(args.site)) if args.site else None
            if args.site and site is None:
                log("WARNING: no site.json - the own domains are not in the rspamd maps")
            changes = render_rspamd(Path(args.src), Path(args.dst), antivirus=not args.no_antivirus,
                                    antivirus_src=Path(args.antivirus_src) if args.antivirus_src else None,
                                    site=site)
            files = ", ".join(f"{k} ({v})" for k, v in sorted(changes.items())) or "none"
            log(f"rspamd local.d rendered for 127.0.0.1; adjusted: {files}")
        elif args.cmd == "unbound":
            used = render_unbound(Path(args.src), Path(args.fallback), Path(args.dst), Path(args.dir),
                                  Path(args.forward) if args.forward else None,
                                  Path(args.root_key) if args.root_key else None,
                                  site=load_site(Path(args.site)) if args.site else None)
            log(f"unbound.conf rendered for 127.0.0.1@{UNBOUND_PORT} from the {used} copy")
        else:
            fuzzy = os.environ.get("SPAMFILTER_ENABLE_FUZZY") == "1"
            if init_appdata(Path(args.appdata), Path(args.bundle), chown=not args.no_chown, fuzzy=fuzzy):
                log("fresh app dir initialised (passwords generated and stored 0600, never shown); "
                    "create the first login with: docker exec -it spamfilter sfctl create-admin admin --generate")
    except RenderError as ex:
        print(f"[init] ERROR: {ex}", file=sys.stderr, flush=True)
        return 1
    except ValueError as ex:
        print(f"[init] ERROR: {args.cmd}: {ex.__class__.__name__}", file=sys.stderr, flush=True)
        return 1
    except OSError as ex:
        print(f"[init] ERROR: {args.cmd}: {ex.__class__.__name__} on {getattr(ex, 'filename', '?')}",
              file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
