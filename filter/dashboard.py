"""Web UI core for the spamfilter 2.0.

Owns the Flask app, authentication, sessions, CSRF, security headers,
login throttling, the audit log, config writes and the shared helpers the
page modules build on:

  * ui_mail.py  - Oversigt, Fanget spam, Beskeder, Besked-detalje, Regler
  * ui_admin.py - Konti, Træning, Drift, Indstillinger
  * ui_kit.py   - design system (layout + components)

The page modules register their routes on `app` when imported;
register_pages() (called by start()) imports them.

Users live in state/dashboard_users, one `name:verifier[:scope[:gen]]` per
line (scope = 'admin' or pipe-separated account names; gen = session
generation, bumped to log a user out everywhere). The legacy env sources
DASHBOARD_USERS and DASHBOARD_USER/DASHBOARD_PASSWORD still work. The line
format is unchanged since 1.x so a rollback keeps reading it; a 'Bruger'
without mailboxes is written with the scope NO_ACCOUNTS ('~none', never a
valid account name), which old code reads as "non-admin, sees nothing".

Per-user permissions (2.1) live in the UI-owned SQLite table `ui_users`
(perms JSON + last login). A user without a row - every user created
before 2.1 - has ALL Bruger permissions (release, rules, see_messages):
exactly the 2.0 behaviour of an account-scoped user. Older versions ignore
the table, so after a rollback Brugere get the 2.0 rights back.

Access control is central: every route declares a policy with one of the
decorators public / login_required / admin_required /
permission_required(perm); _before() enforces it for EVERY request and
fails closed (404) for an endpoint that declares nothing. Object checks
(which mailbox, which rule) go through can(), can_access(), require_account()
and can_edit_rule(); everything is re-read on each request.

Two-step login (2.1): optional TOTP (RFC 6238, pure Python) per user in
the UI-owned table `ui_twofa`; an admin may require it per user. After the
password the session only holds a short-lived "pre" login; the code step
(/login/2fa) turns it into a real session marked `mfa`. A session without
that mark is stepped up as soon as the user has 2FA turned on.

Reverse proxy / Cloudflare Tunnel (2.1): forwarded headers are honoured
ONLY when the direct peer is in TRUSTED_PROXIES (IPs/CIDRs, default none);
see ProxyHeaders. The settings_kv key `external_url` is the public address
(CSRF origin allowlist, status card, app install guide).

PWA (2.1): /manifest.webmanifest, /sw.js (static assets + offline page
only, never authenticated HTML/JSON), /offline, /apple-touch-icon.png.

Mail (2.3, B29): the SMTP server and the notification routes are set up
under Indstillinger (ui_admin + mailer.py). Two-step login then also
offers "Kode på mail": per user a verified address (NEW table
`ui_twofa_mail`) and one-time codes (NEW table `ui_mail_codes`: 6 digits,
10 min, 5 tries, 3 sends per 15 min, salted hashes, single use). A user
may have the app, mail codes or both; recovery codes are shared. Old
versions ignore both tables (a mail-only user then logs in with the
password alone - no lock-out on rollback).

Home Assistant (2.3.6, B26): GET /api/v1/ha (ui_ha.py) uses its own
central policy POLICY_HA - a bearer API key; everything else gets the
plain 404 of an unknown URL. API keys for programs (2.11.0): several named
keys with their own scope in ui_api_keys (only sha256 + last 4 chars),
home network only by default, per-key rate limit; the old single HA token
is moved there on start (api_key_* below; Opsætning -> "Adgang for
programmer" in ui_access.py; sfctl api-key).

Passkeys + login alerts (2.6, B1/B2): passkeys.py (WebAuthn routes, Min
konto card; verification in webauthn.py) and login_alerts.py (device
cookie, login history, new-device and failed-login alerts). Their tables
are in UI_SCHEMA; every login path calls login_succeeded()/login_failed().

Kontrolrum single sign-on (2.9.0): POST /login/kontrolrum takes a signed,
short-lived assertion from the household dashboard instead of a password
(kr_sso_* below; Indstillinger -> Kontrolrum in ui_kontrolrum.py). Only
from the configured Kontrolrum IPs, only for users with the checkbox "Må
logges ind fra Kontrolrum", and the session it makes is bound to that IP.

Run `python dashboard.py` for an interactive add-user helper, or
`python dashboard.py --reset-2fa <name>` to turn off a user's two-step login
(lost phone and no recovery codes).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import ipaddress
import json
import logging
import os
import re
import secrets
import sqlite3
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, replace
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import quote, urlsplit

import yaml
from datetime import datetime, timedelta, timezone
from flask import Flask, Response, abort, g, has_request_context, jsonify, redirect, request, send_file, session
from flask.sessions import SecureCookieSessionInterface
from werkzeug.exceptions import HTTPException

import mailer
import siteconfig
import ui_kit as kit

log = logging.getLogger("dashboard")

# ---------------------------------------------------------------------------
# Paths and constants (configure_paths() re-derives them, e.g. for tests)
# ---------------------------------------------------------------------------

STATE_DIR = Path(os.environ.get("STATE_DIR", "/state"))
CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", "/app/accounts.yml"))
DB_PATH = STATE_DIR / "spamfilter.db"
USERS_FILE = STATE_DIR / "dashboard_users"
SECRET_PATH = STATE_DIR / "dashboard_secret"
AUDIT_FILE = STATE_DIR / "admin-audit.jsonl"
RELOAD_FILE = STATE_DIR / "reload_requested"
STATIC_DIR = Path(__file__).with_name("static")
FAVICON_PATH = Path(__file__).with_name("favicon.png")

FALLBACK_VERSION = "2.19.0"
DASHBOARD_PORT = 8080
PBKDF2_ITERATIONS = 600_000
SESSION_LIFETIME = 12 * 3600      # absolute
SESSION_IDLE = 2 * 3600           # sliding
REMEMBER_LIFETIME = 30 * 86400    # "Husk mig": absolute
REMEMBER_IDLE = 7 * 86400         # "Husk mig": sliding
LOGIN_MAX_FAILURES = 5
LOGIN_MAX_FAILURES_USER_EXTERNAL = 20   # 2.12 (#26): per username, all IPs outside the home network
LOGIN_WINDOW = 15 * 60
MAX_MAIL_ACTION_IDS = 200

CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
       "manifest-src 'self'; worker-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
HSTS = "max-age=31536000"
# 2.2 (B21): the weekly report's own HTML (the mail exactly as it will look)
# is shown as a separate, sandboxed document: inline styles allowed, nothing
# else (no scripts, no forms, no external loads, never framed).
CSP_MAIL_PREVIEW = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox; "
                    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'")

# Two-step login (TOTP, RFC 6238: HMAC-SHA1, 30 s steps, 6 digits).
TOTP_ISSUER = siteconfig.brand(" ")   # 'Spamfilter <server name>' (local site config)
TOTP_STEP = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1                   # accept the previous/next step (clock drift)
TWOFA_PENDING_TTL = 30 * 60       # an unconfirmed enrollment secret lives this long
MFA_PENDING_TTL = 5 * 60          # password ok -> code must follow within this time
MFA_MAX_TRIES = 5                 # wrong codes per password login
RECOVERY_CODES = 8
RECOVERY_LEN = 10
RECOVERY_ALPHABET = "23456789abcdefghjkmnpqrstuvwxyz"   # no 0/1/i/l/o
# Two-step login by mail (2.3, B29).
MAIL_CODE_TTL = 10 * 60           # a mailed code is valid this long
MAIL_CODE_MAX_TRIES = 5           # wrong guesses per mailed code
MAIL_CODE_MAX_SENDS = 3           # codes per user ...
MAIL_CODE_WINDOW = 15 * 60        # ... per this window (all purposes)
MAIL_CODE_COOLDOWN = 60           # seconds between two sends

# Legacy TRUSTED_PROXY=1 (2.0, trusted any peer) maps to the private ranges.
LEGACY_PROXY_SPEC = "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7"


def configure_paths(state_dir: Path | str | None = None, config_path: Path | str | None = None) -> None:
    """Point every derived path at a new state dir / config (tests, dev)."""
    global STATE_DIR, CONFIG_PATH, DB_PATH, USERS_FILE, SECRET_PATH, AUDIT_FILE, RELOAD_FILE
    if state_dir is not None:
        STATE_DIR = Path(state_dir)
        DB_PATH = STATE_DIR / "spamfilter.db"
        USERS_FILE = STATE_DIR / "dashboard_users"
        SECRET_PATH = STATE_DIR / "dashboard_secret"
        AUDIT_FILE = STATE_DIR / "admin-audit.jsonl"
        RELOAD_FILE = STATE_DIR / "reload_requested"
    if config_path is not None:
        CONFIG_PATH = Path(config_path)
    mailer.configure_paths(STATE_DIR, CONFIG_PATH)


def mail():
    """The mailer module, pointed at this dashboard's state dir / DB /
    config / audit file (tests swap those attributes on this module)."""
    mailer.configure_paths(STATE_DIR, CONFIG_PATH, db_path=DB_PATH, audit_file=AUDIT_FILE)
    return mailer


class _LazyModule:
    """Import a sibling module on first attribute access.

    Keeps `import dashboard` from importing filter.py/services.py (the
    engine imports the dashboard, not the other way round) and gives
    tests one attribute to swap: monkeypatch `dashboard.services` /
    `dashboard.engine` with a fake. Page modules must therefore call
    `ui.services.x()` at call time, never `from dashboard import services`.
    """

    def __init__(self, name: str) -> None:
        self.__dict__["_name"] = name
        self.__dict__["_mod"] = None

    def _load(self):
        mod = self.__dict__["_mod"]
        if mod is None:
            mod = importlib.import_module(self.__dict__["_name"])
            self.__dict__["_mod"] = mod
        return mod

    def __getattr__(self, attr: str) -> Any:
        return getattr(self._load(), attr)

    def __repr__(self) -> str:
        return f"<lazy module {self.__dict__['_name']}>"


engine: Any = _LazyModule("filter")
services: Any = _LazyModule("services")


def app_version() -> str:
    try:
        return str(getattr(engine, "VERSION", FALLBACK_VERSION))
    except Exception:  # noqa: BLE001 - engine mid-import or broken: still serve
        return FALLBACK_VERSION


# ---------------------------------------------------------------------------
# App + static assets
# ---------------------------------------------------------------------------

class _SessionInterface(SecureCookieSessionInterface):
    """Signed cookie sessions whose cookie lifetime depends on "Husk mig".

    The signature may be up to REMEMBER_LIFETIME old (PERMANENT_SESSION_LIFETIME);
    the real limits (absolute + idle, normal or remembered) are enforced by
    current_user() from the t0/ts/rm values in the session."""

    def get_expiration_time(self, app, session):  # noqa: ANN001 - Flask signature
        if not session.permanent:
            return None
        life = REMEMBER_LIFETIME if session.get("rm") else SESSION_LIFETIME
        return datetime.now(timezone.utc) + timedelta(seconds=life)

    def get_cookie_secure(self, app):  # noqa: ANN001 - Flask signature
        """Secure whenever the effective scheme is https (directly or via a
        trusted proxy), or when DASHBOARD_COOKIE_SECURE=1 forces it."""
        if app.config.get("SESSION_COOKIE_SECURE"):
            return True
        return bool(has_request_context() and request.is_secure)


app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")
app.session_interface = _SessionInterface()
app.config.update(
    SESSION_COOKIE_NAME="spamfilter_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.environ.get("DASHBOARD_COOKIE_SECURE", "").lower() in ("1", "true", "yes"),
    PERMANENT_SESSION_LIFETIME=REMEMBER_LIFETIME,
    SEND_FILE_MAX_AGE_DEFAULT=31536000,
    MAX_CONTENT_LENGTH=1024 * 1024,
)
app.json.ensure_ascii = False  # type: ignore[attr-defined]  # Danish stays readable
app.json.sort_keys = False  # type: ignore[attr-defined]

# ---------------------------------------------------------------------------
# Reverse proxy / Cloudflare Tunnel
# ---------------------------------------------------------------------------

TRUSTED_PROXY_NETS: tuple = ()
TRUSTED_PROXIES_SPEC = ""
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOST_RE = re.compile(rf"(?:{_LABEL}(?:\.{_LABEL})*|\[[0-9A-Fa-f:.]{{2,45}}\])(?::\d{{1,5}})?")
_EMAIL_HDR_RE = re.compile(r"[^@\s<>\"',;]{1,64}@[A-Za-z0-9.-]{1,253}")
_FORWARD_HEADERS = ("HTTP_X_FORWARDED_FOR", "HTTP_X_FORWARDED_PROTO", "HTTP_X_FORWARDED_HOST", "HTTP_CF_CONNECTING_IP")


def parse_trusted_proxies(spec: str | None) -> tuple[list, list[str]]:
    """'192.168.1.5, 172.18.0.0/16 ::1' -> (networks, invalid entries)."""
    nets, bad = [], []
    for tok in re.split(r"[\s,;]+", spec or ""):
        if not tok:
            continue
        try:
            nets.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            bad.append(tok[:60])
    return nets, bad


def configure_proxies(spec: str | None = None) -> None:
    """(Re)read the trusted proxies: TRUSTED_PROXIES from the environment
    unless `spec` is given (tests). Default: nobody is trusted."""
    global TRUSTED_PROXY_NETS, TRUSTED_PROXIES_SPEC
    if spec is None:
        spec = os.environ.get("TRUSTED_PROXIES", "")
        if not spec.strip() and os.environ.get("TRUSTED_PROXY", "") == "1":
            log.warning("TRUSTED_PROXY=1 is deprecated; trusting private ranges only - set TRUSTED_PROXIES")
            spec = LEGACY_PROXY_SPEC
    nets, bad = parse_trusted_proxies(spec)
    if bad:
        log.warning("TRUSTED_PROXIES: ignoring invalid entries: %s", ", ".join(bad[:5]))
    TRUSTED_PROXY_NETS = tuple(nets)
    TRUSTED_PROXIES_SPEC = ", ".join(str(n) for n in nets)


def _parse_ip(text: str | None):
    t = (text or "").strip().strip('"')
    if t.startswith("[") and "]" in t:
        t = t[1:t.index("]")]
    elif t.count(":") == 1:      # "1.2.3.4:5678"
        t = t.split(":", 1)[0]
    try:
        ip = ipaddress.ip_address(t)
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def is_trusted_proxy(addr: str | None) -> bool:
    ip = _parse_ip(addr)
    return ip is not None and any(ip in net for net in TRUSTED_PROXY_NETS)


def _last_value(raw: str | None) -> str:
    return (raw or "").split(",")[-1].strip()


def _forwarded_client(environ: dict) -> str | None:
    """Client IP behind a trusted proxy: CF-Connecting-IP (set by
    Cloudflare's edge), else the right-most X-Forwarded-For hop that is not
    itself a trusted proxy."""
    cf = _parse_ip(environ.get("HTTP_CF_CONNECTING_IP"))
    if cf is not None:
        return str(cf)
    hops = [h for h in (environ.get("HTTP_X_FORWARDED_FOR") or "").split(",") if h.strip()][-20:]
    first = None
    for raw in reversed(hops):
        ip = _parse_ip(raw)
        if ip is None:
            break
        first = ip
        if not any(ip in net for net in TRUSTED_PROXY_NETS):
            return str(ip)
    return str(first) if first is not None else None


class ProxyHeaders:
    """WSGI middleware: honour forwarded headers only from trusted peers.

    For a peer in TRUSTED_PROXIES: REMOTE_ADDR becomes the real client
    (CF-Connecting-IP / X-Forwarded-For), wsgi.url_scheme follows
    X-Forwarded-Proto and Host follows X-Forwarded-Host. Cloudflare Access'
    Cf-Access-Authenticated-User-Email is kept (for the audit log) only then;
    from anybody else every one of these headers is ignored. The direct peer
    stays available as environ['sf.peer']."""

    def __init__(self, wsgi_app: Callable) -> None:
        self.wsgi_app = wsgi_app

    def __call__(self, environ: dict, start_response: Callable):
        peer = environ.get("REMOTE_ADDR", "") or ""
        had_headers = any(environ.get(k) for k in _FORWARD_HEADERS)
        cf_user = (environ.pop("HTTP_CF_ACCESS_AUTHENTICATED_USER_EMAIL", "") or "").strip()
        environ["sf.peer"] = peer
        environ["sf.proxied"] = False
        environ["sf.cf_user"] = ""
        environ["sf.ignored_proxy_headers"] = False
        if TRUSTED_PROXY_NETS and is_trusted_proxy(peer):
            environ["sf.proxied"] = had_headers
            client = _forwarded_client(environ)
            if client:
                environ["REMOTE_ADDR"] = client
            proto = _last_value(environ.get("HTTP_X_FORWARDED_PROTO")).lower()
            if proto in ("http", "https"):
                environ["wsgi.url_scheme"] = proto
            fhost = _last_value(environ.get("HTTP_X_FORWARDED_HOST"))
            if fhost and _HOST_RE.fullmatch(fhost):
                environ["HTTP_HOST"] = fhost
            if cf_user and _EMAIL_HDR_RE.fullmatch(cf_user):
                environ["sf.cf_user"] = cf_user[:254]
        else:
            environ["sf.ignored_proxy_headers"] = had_headers or bool(cf_user)
        return self.wsgi_app(environ, start_response)


configure_proxies()
app.wsgi_app = ProxyHeaders(app.wsgi_app)  # type: ignore[method-assign]


def request_peer() -> str:
    """The direct TCP peer (the proxy when one is in front)."""
    return str(request.environ.get("sf.peer") or request.remote_addr or "")


def via_proxy() -> bool:
    return bool(request.environ.get("sf.proxied"))


def cf_access_user() -> str:
    """Cloudflare Access identity - only ever from a trusted proxy."""
    return str(request.environ.get("sf.cf_user") or "")

_ASSET_TAG: str | None = None


def static_url(name: str) -> str:
    """/static/<name>?v=<version>-<content hash>: immutable caching that
    still busts when an asset changes without a version bump."""
    global _ASSET_TAG
    if _ASSET_TAG is None:
        digest = hashlib.sha256()
        for f in sorted(STATIC_DIR.glob("*")):
            try:
                digest.update(f.name.encode() + f.read_bytes())
            except OSError:
                pass
        _ASSET_TAG = f"{app_version()}-{digest.hexdigest()[:8]}"
    return f"/static/{name}?v={_ASSET_TAG}"


def _load_secret() -> str:
    """Persist the session signing key in STATE_DIR so logins survive
    restarts; fall back to an ephemeral key if the dir is not writable."""
    try:
        if SECRET_PATH.is_file():
            existing = SECRET_PATH.read_text().strip()
            if existing:
                return existing
        fresh = secrets.token_hex(32)
        fd = os.open(SECRET_PATH, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(fresh)
        return fresh
    except OSError as ex:
        log.warning("could not persist session secret (%s); logins drop on restart", type(ex).__name__)
        return secrets.token_hex(32)


# Ephemeral until start() loads (or creates) the persisted key; importing
# the module must not write into STATE_DIR (tests, CLI helpers).
app.secret_key = secrets.token_hex(32)

# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


# Users-file scope of a Bruger without mailboxes. Never a valid account
# name (ACCOUNT_NAME_RE), so old code reads it as "non-admin, no access"
# - an empty scope would mean admin to every version.
NO_ACCOUNTS = "~none"

# Bruger permissions (admins have all of them, plus the admin-only pages).
PERMISSIONS = ("release", "rules", "see_messages")
PERMISSION_TEXT = {
    "release": ("Frigive og flytte post",
                "Må frigive mails fra Fanget spam, flytte mails til spam og lære filteret, hvad der er spam. "
                "Giver også adgang til Find en mail og Fortryd flytninger."),
    "rules": ("Tillade og blokere afsendere",
              "Må tillade eller blokere afsendere for sine egne postkasser. Aldrig for alle konti og aldrig "
              "“Altid igennem” – det kan kun en administrator."),
    "see_messages": ("Se alle beskeder",
                     "Må se siden Beskeder med al scannet post og åbne den enkelte mail. Uden den ser brugeren "
                     "kun sin fangede spam."),
}


@dataclass(frozen=True)
class User:
    name: str
    verifier: str                      # pbkdf2$... or 'plain:<pw>' (legacy env only)
    admin: bool
    accounts: frozenset[str]           # non-admin scope
    gen: int = 0                       # session generation
    source: str = "file"               # 'file' | 'env' (env users are read-only)

    @property
    def scope(self) -> str:
        if self.admin:
            return "admin"
        return "|".join(sorted(self.accounts)) or NO_ACCOUNTS


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(stored: str, password: str) -> bool:
    if stored.startswith("plain:"):
        return hmac.compare_digest(stored[len("plain:"):].encode(), password.encode())
    try:
        scheme, iters, salt_hex, hash_hex = stored.split("$")
        if scheme != "pbkdf2":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, AttributeError):
        return False


def parse_user_line(raw: str, *, source: str = "file") -> User | None:
    """`name:verifier[:scope[:gen]]`; absent scope = admin, absent gen = 0."""
    parts = raw.strip().split(":")
    if len(parts) < 2:
        return None
    name, verifier = parts[0].strip(), parts[1].strip()
    if not name or not verifier:
        return None
    scope = parts[2].strip() if len(parts) >= 3 and parts[2].strip() else "admin"
    try:
        gen = int(parts[3]) if len(parts) >= 4 and parts[3].strip() else 0
    except ValueError:
        gen = 0
    admin = scope.lower() == "admin"
    # '~...' entries (NO_ACCOUNTS) are placeholders, never account names.
    accounts = frozenset() if admin else frozenset(
        a.strip() for a in re.split(r"[|,]", scope) if a.strip() and not a.strip().startswith("~"))
    return User(name, verifier, admin, accounts, gen, source)


def format_user_line(user: User) -> str:
    return f"{user.name}:{user.verifier}:{user.scope}:{int(user.gen)}"


def load_users() -> dict[str, User]:
    """All users; file first, then DASHBOARD_USERS, then the legacy pair.
    Re-read on each request so edits apply without a restart."""
    users: dict[str, User] = {}
    try:
        if USERS_FILE.is_file():
            for line in USERS_FILE.read_text().splitlines():
                s = line.strip()
                if s and not s.startswith("#"):
                    u = parse_user_line(s)
                    if u:
                        users[u.name] = u
    except OSError as ex:
        log.warning("could not read users file: %s", type(ex).__name__)
    for entry in os.environ.get("DASHBOARD_USERS", "").split(","):
        if entry.strip():
            u = parse_user_line(entry, source="env")
            if u and u.name not in users:
                users[u.name] = u
    legacy_user = os.environ.get("DASHBOARD_USER", "").strip()
    legacy_pass = os.environ.get("DASHBOARD_PASSWORD", "")
    if legacy_user and legacy_pass and legacy_user not in users:
        users[legacy_user] = User(legacy_user, "plain:" + legacy_pass, True, frozenset(), 0, "env")
    return users


_USERS_LOCK = threading.RLock()


def write_users(users: Iterable[User]) -> None:
    """Atomically rewrite the users file (0600) with the given file users.
    Leading comment lines are preserved; env users are never written."""
    with _USERS_LOCK:
        header: list[str] = []
        if USERS_FILE.exists():
            for line in USERS_FILE.read_text().splitlines():
                if line.strip().startswith("#") or not line.strip():
                    header.append(line)
                else:
                    break
        lines = header + [format_user_line(u) for u in users if u.source == "file"]
        _atomic_write(USERS_FILE, "\n".join(lines) + "\n")


def bump_generation(name: str) -> int:
    """Invalidate every session of `name` ("Log ud alle steder", password
    change). Returns the new generation."""
    with _USERS_LOCK:
        users = load_users()
        u = users.get(name)
        if u is None or u.source != "file":
            raise ValueError("unknown or read-only user")
        users[name] = replace(u, gen=u.gen + 1)
        write_users(users.values())
        return u.gen + 1


def passkey_count(name: str) -> int:
    """How many passkeys `name` has (0 when unreadable)."""
    try:
        _ensure_ui_db()
        conn = _connect()
        try:
            return int(conn.execute("SELECT COUNT(*) FROM ui_passkeys WHERE name=?", (name,)).fetchone()[0])
        finally:
            conn.close()
    except sqlite3.Error:
        return 0


def remove_all_passkeys(name: str) -> int:
    """2.6: delete every passkey of `name` (plus the WebAuthn user handle and
    any outstanding challenge). A passkey is a full login on its own, so a
    password reset by an administrator and "Log ud overalt" must not leave
    one behind. Returns how many were removed."""
    _ensure_ui_db()
    conn = _connect()
    try:
        removed = conn.execute("DELETE FROM ui_passkeys WHERE name=?", (name,)).rowcount
        conn.execute("DELETE FROM ui_passkey_handles WHERE name=?", (name,))
        conn.execute("DELETE FROM ui_webauthn_challenges WHERE name=?", (name,))
        conn.commit()
    finally:
        conn.close()
    return int(removed or 0)


def passkeys_removed_text(n: int) -> str:
    """The sentence for a security notice / reply after remove_all_passkeys."""
    if n <= 0:
        return ""
    return (("Din passkey er" if n == 1 else f"Alle dine {n} passkeys er") + " fjernet og virker ikke længere. "
            "Du logger ind med adgangskode (og to-trins-login) og kan lave nye under Min konto.")


def logout_all_passkeys_field(name: str, *, own: bool) -> str:
    """'Fjern også passkeys' (checked) for a "Log ud overalt" form - only
    when `name` has passkeys. The hidden "0" tells "unchecked" apart from an
    older form without the field (which removes them, like the default)."""
    n = passkey_count(name)
    if not n:
        return ""
    whose = "dine" if own else "brugerens"
    return (kit.hidden("passkeys", "0")
            + '<label class="check-row mb-1"><input type="checkbox" class="check" name="passkeys" value="1" checked>'
            f"<span><b>Fjern også passkeys</b><small>{kit.h(f'{n} passkey' if n == 1 else f'{n} passkeys')} – "
            f"fx på en mistet telefon. Uden flueben kan {whose} passkeys stadig bruges til at logge ind."
            "</small></span></label>")


def logout_all_wants_passkeys_removed() -> bool:
    """The 'Fjern også passkeys' choice of a "Log ud overalt" POST: checked,
    or no such field at all (older forms, scripts) = remove."""
    vals = request.form.getlist("passkeys")
    return not vals or "1" in vals


def admin_count(users: dict[str, User] | None = None) -> int:
    return sum(1 for u in (users or load_users()).values() if u.admin)


_DUMMY_VERIFIER = f"pbkdf2${PBKDF2_ITERATIONS}${'00' * 16}${'00' * 32}"


def check_login(username: str, password: str) -> User | None:
    u = load_users().get(username)
    if u is None:
        # Same pbkdf2 cost for unknown names: timing must not reveal users.
        verify_password(_DUMMY_VERIFIER, password)
        return None
    return u if verify_password(u.verifier, password) else None


def check_login_here(username: str, password: str) -> tuple[User | None, bool]:
    """check_login() that first applies the user's login scope (2.3):
    (user or None, blocked). A 'Kun lokalt' user from outside is refused
    BEFORE the password is looked at - with the same pbkdf2 cost as any
    other attempt, so neither the reply nor its timing tells whether the
    user exists, is local-only or typed the right password. The scope is
    read for every name (known or not) to keep the work identical."""
    local_only = login_scope(username) == "local"
    if local_only and not request_is_local():
        load_users()
        verify_password(_DUMMY_VERIFIER, password)
        return None, True
    return check_login(username, password), False


# Backwards-compatible names (1.x tests/helpers).
_hash_password = hash_password
_load_users = load_users

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

UI_SCHEMA = """
CREATE TABLE IF NOT EXISTS login_attempts (
    key TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0,
    first_at INTEGER NOT NULL DEFAULT 0, locked_until INTEGER
);
CREATE TABLE IF NOT EXISTS ui_actions (
    nonce TEXT PRIMARY KEY, actor TEXT, action TEXT, created_at INTEGER, result TEXT
);
CREATE TABLE IF NOT EXISTS settings_kv (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS ui_users (
    name TEXT PRIMARY KEY, perms TEXT, last_login_at INTEGER, last_login_ip TEXT,
    updated_at INTEGER, updated_by TEXT
);
CREATE TABLE IF NOT EXISTS ui_twofa (
    name TEXT PRIMARY KEY, secret TEXT, enabled_at INTEGER, last_step INTEGER NOT NULL DEFAULT 0,
    recovery TEXT, pending_secret TEXT, pending_at INTEGER, required INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER, updated_by TEXT
);
CREATE TABLE IF NOT EXISTS ui_twofa_mail (
    name TEXT PRIMARY KEY, email TEXT, enabled_at INTEGER, updated_at INTEGER, updated_by TEXT
);
CREATE TABLE IF NOT EXISTS ui_mail_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, purpose TEXT NOT NULL, email TEXT NOT NULL,
    salt TEXT NOT NULL, code_hash TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0, used_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_ui_mail_codes_user ON ui_mail_codes(name, created_at);
CREATE TABLE IF NOT EXISTS ui_login_scope (
    name TEXT PRIMARY KEY, scope TEXT NOT NULL, updated_at INTEGER, updated_by TEXT
);
CREATE TABLE IF NOT EXISTS ui_passkeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, cred_id TEXT NOT NULL UNIQUE,
    user_handle TEXT NOT NULL, rp_id TEXT NOT NULL, public_key TEXT NOT NULL, alg INTEGER NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0, label TEXT NOT NULL, aaguid TEXT, transports TEXT,
    backup_eligible INTEGER NOT NULL DEFAULT 0, backed_up INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL, last_used_at INTEGER, last_used_ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_ui_passkeys_name ON ui_passkeys(name);
CREATE TABLE IF NOT EXISTS ui_passkey_handles (
    name TEXT PRIMARY KEY, handle TEXT NOT NULL UNIQUE, created_at INTEGER
);
CREATE TABLE IF NOT EXISTS ui_webauthn_challenges (
    id TEXT PRIMARY KEY, purpose TEXT NOT NULL, name TEXT, rp_id TEXT NOT NULL, origin TEXT NOT NULL,
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ui_login_devices (
    name TEXT NOT NULL, device TEXT NOT NULL, label TEXT, first_at INTEGER NOT NULL, last_at INTEGER NOT NULL,
    last_ip TEXT, logins INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (name, device)
);
CREATE TABLE IF NOT EXISTS ui_login_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, at INTEGER NOT NULL, ip TEXT, country TEXT,
    label TEXT, method TEXT, device TEXT, new_device INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ui_login_history_user ON ui_login_history(name, at);
CREATE TABLE IF NOT EXISTS ui_login_alerts (key TEXT PRIMARY KEY, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS ui_kontrolrum_sso (name TEXT PRIMARY KEY, updated_at INTEGER, updated_by TEXT);
CREATE TABLE IF NOT EXISTS ui_sso_nonces (nonce TEXT PRIMARY KEY, until INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS ui_api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, scope TEXT NOT NULL,
    sha256 TEXT NOT NULL UNIQUE, prefix TEXT NOT NULL, hint TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL, created_by TEXT, last_used_at INTEGER, last_used_ip TEXT,
    uses INTEGER NOT NULL DEFAULT 0, lan_only INTEGER NOT NULL DEFAULT 1, expires_at INTEGER,
    migrated INTEGER NOT NULL DEFAULT 0
);
"""

_UI_DB_READY: set[str] = set()
_UI_DB_LOCK = threading.Lock()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def init_ui_db() -> None:
    """Create the UI-owned tables (idempotent)."""
    with _UI_DB_LOCK:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = _connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(UI_SCHEMA)
            conn.commit()
            try:
                moved = _migrate_ha_token(conn)  # 2.11.0: the HA token becomes an API key (once)
                conn.commit()
            except sqlite3.Error as ex:
                conn.rollback()
                moved = False
                log.warning("api key migration failed: %s", type(ex).__name__)
        finally:
            conn.close()
        _UI_DB_READY.add(str(DB_PATH))
    if moved:
        log.info("api keys: the Home Assistant token was moved to the key list as %r", HA_KEY_NAME)
        audit("api_keys_migrated", detail=f"{HA_KEY_NAME} (sfha_-nøglen virker videre)", actor="system")


def _ensure_ui_db() -> None:
    if str(DB_PATH) not in _UI_DB_READY:
        init_ui_db()


def db() -> sqlite3.Connection:
    """Per-request read/write connection (row_factory=Row). Closed at
    teardown; commit your writes."""
    conn = g.get("_db")
    if conn is None:
        _ensure_ui_db()
        conn = _connect()
        g._db = conn
    return conn


@app.teardown_appcontext
def _close_db(_exc) -> None:
    conn = g.pop("_db", None)
    if conn is not None:
        conn.close()


def query(sql: str, params: Iterable[Any] = (), *, default: Any = None, one: bool = False) -> Any:
    """Tolerant read: returns `default` when a table/column is missing
    (older engine schema), so one absent feature never kills a page."""
    try:
        cur = db().execute(sql, tuple(params))
        return cur.fetchone() if one else cur.fetchall()
    except sqlite3.OperationalError as ex:
        if "no such" in str(ex):
            log.debug("tolerated schema gap: %s", ex)
            return default if default is not None else (None if one else [])
        raise


def settings_get(key: str, default: str | None = None) -> str | None:
    _ensure_ui_db()
    conn = _connect()
    try:
        row = conn.execute("SELECT value FROM settings_kv WHERE key=?", (key,)).fetchone()
        return row[0] if row else default
    finally:
        conn.close()


def settings_set(key: str, value: str) -> None:
    if preview_target():  # 'Se som bruger' is read-only: never store anything
        return
    _ensure_ui_db()
    conn = _connect()
    try:
        conn.execute("INSERT INTO settings_kv(key,value) VALUES(?,?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Per-user permissions + login metadata (ui_users; additive, 2.1)
# ---------------------------------------------------------------------------


def _parse_perms(raw: Any) -> frozenset[str]:
    """perms JSON -> granted Bruger permissions. Missing keys (and a
    missing/garbled value) mean granted: the 2.0 behaviour."""
    try:
        data = json.loads(raw) if raw else {}
    except (TypeError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    return frozenset(p for p in PERMISSIONS if data.get(p, True) is not False)


def user_meta(name: str) -> dict:
    """{'perms': frozenset, 'last_login_at', 'last_login_ip', 'stored': bool}."""
    row = None
    try:
        _ensure_ui_db()
        conn = _connect()
        try:
            row = conn.execute("SELECT * FROM ui_users WHERE name=?", (name,)).fetchone()
        finally:
            conn.close()
    except sqlite3.Error as ex:
        log.warning("ui_users unavailable: %s", type(ex).__name__)
    if row is None:
        return {"perms": frozenset(PERMISSIONS), "last_login_at": None, "last_login_ip": None, "stored": False}
    return {"perms": _parse_perms(row["perms"]), "last_login_at": row["last_login_at"],
            "last_login_ip": row["last_login_ip"], "stored": True}


def all_user_meta() -> dict[str, dict]:
    out: dict[str, dict] = {}
    try:
        _ensure_ui_db()
        conn = _connect()
        try:
            rows = conn.execute("SELECT * FROM ui_users").fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        rows = []
    for r in rows:
        out[str(r["name"])] = {"perms": _parse_perms(r["perms"]), "last_login_at": r["last_login_at"],
                               "last_login_ip": r["last_login_ip"], "stored": True}
    return out


def user_perms(name: str) -> frozenset[str]:
    return user_meta(name)["perms"]


def set_user_perms(name: str, perms: Iterable[str], actor: str = "") -> None:
    granted = set(perms)
    value = json.dumps({p: p in granted for p in PERMISSIONS}, sort_keys=True)
    _ensure_ui_db()
    conn = _connect()
    try:
        conn.execute("INSERT INTO ui_users(name, perms, updated_at, updated_by) VALUES(?,?,?,?) "
                     "ON CONFLICT(name) DO UPDATE SET perms=excluded.perms, updated_at=excluded.updated_at, "
                     "updated_by=excluded.updated_by", (name, value, int(time.time()), actor))
        conn.commit()
    finally:
        conn.close()


def forget_user_meta(name: str) -> None:
    """Drop permissions, login history and two-step login of a removed user."""
    try:
        _ensure_ui_db()
        conn = _connect()
        try:
            conn.execute("DELETE FROM ui_users WHERE name=?", (name,))
            conn.execute("DELETE FROM ui_login_scope WHERE name=?", (name,))
            # 2.6: passkeys, known devices and the login history go too.
            for table in ("ui_passkeys", "ui_passkey_handles", "ui_webauthn_challenges", "ui_login_devices",
                          "ui_login_history", "ui_kontrolrum_sso"):
                conn.execute(f"DELETE FROM {table} WHERE name=?", (name,))
            conn.commit()
        finally:
            conn.close()
    except sqlite3.Error as ex:
        log.warning("could not forget user meta: %s", type(ex).__name__)
    twofa_forget(name)
    # 2.5.0: a removed user's phones get nothing any more.
    try:
        import ui_push  # noqa: PLC0415

        ui_push.forget_user(name)
    except Exception as ex:  # noqa: BLE001 - push is optional
        log.warning("could not forget push devices: %s", type(ex).__name__)


# ---------------------------------------------------------------------------
# Where a user may log in (2.3, owner request): "Overalt" or "Kun lokalt
# (hjemmenetværket)". NEW table ui_login_scope (absent row = everywhere;
# older versions ignore the table, so a rollback only drops the limit).
#
# Local = the DIRECT TCP peer is in LOCAL_NETWORKS AND the request did not
# come through a proxy: a peer in TRUSTED_PROXIES (e.g. cloudflared) is
# always external, whatever its forwarded headers say, and so is any request
# that carries forwarding headers (X-Forwarded-For, CF-Connecting-IP,
# CF-Ray, Forwarded, X-Real-IP) - a browser on the LAN never sends them, a
# tunnel always does. Headers can therefore only ever make a request count
# as external (fail closed), never as local.
# ---------------------------------------------------------------------------

LOGIN_SCOPES = ("everywhere", "local")
LOGIN_SCOPE_TEXT = {"everywhere": "Overalt", "local": "Kun lokalt (hjemmenetværket)"}
LOGIN_SCOPE_SHORT = {"everywhere": "Overalt", "local": "Kun lokalt"}
LOCAL_NETWORKS_DEFAULT = "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128,fc00::/7,fe80::/10"
LOCAL_NETS: tuple = ()
LOCAL_NETWORKS_SPEC = ""
_PROXY_MARKERS = ("HTTP_X_FORWARDED_FOR", "HTTP_CF_CONNECTING_IP", "HTTP_CF_RAY", "HTTP_FORWARDED",
                  "HTTP_X_REAL_IP", "HTTP_TRUE_CLIENT_IP", "HTTP_CF_ACCESS_AUTHENTICATED_USER_EMAIL")


def configure_local_networks(spec: str | None = None) -> None:
    """(Re)read the home network: LOCAL_NETWORKS from the environment unless
    `spec` is given (tests). Empty/invalid -> the private ranges."""
    global LOCAL_NETS, LOCAL_NETWORKS_SPEC
    if spec is None:
        spec = os.environ.get("LOCAL_NETWORKS", "")
    nets, bad = parse_trusted_proxies(spec)
    if bad:
        log.warning("LOCAL_NETWORKS: ignoring invalid entries: %s", ", ".join(bad[:5]))
    if not nets:
        nets, _bad = parse_trusted_proxies(LOCAL_NETWORKS_DEFAULT)
    LOCAL_NETS = tuple(nets)
    LOCAL_NETWORKS_SPEC = ", ".join(str(n) for n in nets)


configure_local_networks()


def request_is_local() -> bool:
    """Did THIS request come straight from the home network? (Never
    through a proxy - see above.) False outside a request."""
    if not has_request_context():
        return False
    env = request.environ
    peer = env.get("sf.peer")
    if peer is None:
        peer = env.get("REMOTE_ADDR")
    if is_trusted_proxy(peer):
        return False
    if (any(env.get(k) for k in _PROXY_MARKERS) or env.get("sf.cf_user")
            or env.get("sf.ignored_proxy_headers") or env.get("sf.proxied")):
        return False
    ip = _parse_ip(peer)
    return ip is not None and any(ip in net for net in LOCAL_NETS)


def login_scope(name: str) -> str:
    """'everywhere' | 'local' for a user. A broken/unreadable table counts
    as 'local' (fail closed: the home network still works)."""
    try:
        _ensure_ui_db()
        conn = _connect()
        try:
            row = conn.execute("SELECT scope FROM ui_login_scope WHERE name=?", (name,)).fetchone()
        finally:
            conn.close()
    except sqlite3.Error as ex:
        log.warning("ui_login_scope unavailable: %s", type(ex).__name__)
        return "local"
    return "local" if row is not None and str(row["scope"]) == "local" else "everywhere"


def all_login_scopes() -> dict[str, str]:
    """name -> 'local' for every local-only user (others: everywhere)."""
    try:
        _ensure_ui_db()
        conn = _connect()
        try:
            rows = conn.execute("SELECT name, scope FROM ui_login_scope").fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return {}
    return {str(r["name"]): "local" for r in rows if str(r["scope"]) == "local"}


def set_login_scope(name: str, scope: str, actor: str = "") -> bool:
    """Store a user's login scope. Returns True when it changed."""
    if scope not in LOGIN_SCOPES:
        raise ValueError("unknown login scope")
    old = login_scope(name)
    _ensure_ui_db()
    conn = _connect()
    try:
        if scope == "everywhere":
            conn.execute("DELETE FROM ui_login_scope WHERE name=?", (name,))
        else:
            conn.execute("INSERT INTO ui_login_scope(name, scope, updated_at, updated_by) VALUES(?,?,?,?) "
                         "ON CONFLICT(name) DO UPDATE SET scope=excluded.scope, updated_at=excluded.updated_at, "
                         "updated_by=excluded.updated_by", (name, scope, int(time.time()), actor))
        conn.commit()
    finally:
        conn.close()
    return old != scope


def login_allowed_here(name: str) -> bool:
    """May `name` use the WebUI from where this request comes from?"""
    return login_scope(name) != "local" or request_is_local()


def admins_all_local(users: dict | None = None, scopes: dict[str, str] | None = None) -> bool:
    """True when every administrator is 'Kun lokalt' (warn: nobody can
    administer the filter from outside)."""
    users = users if users is not None else load_users()
    scopes = scopes if scopes is not None else all_login_scopes()
    admins = [n for n, u in users.items() if u.admin]
    return bool(admins) and all(scopes.get(n) == "local" for n in admins)


def _blocked_external(name: str, where: str) -> None:
    audit("login_blocked_external", result="blocked", actor=name,
          detail=f"{where} · kun lokalt · peer {request_peer()[:64]}")


def record_login(name: str, ip: str | None) -> None:
    try:
        _ensure_ui_db()
        conn = _connect()
        try:
            conn.execute("INSERT INTO ui_users(name, last_login_at, last_login_ip) VALUES(?,?,?) "
                         "ON CONFLICT(name) DO UPDATE SET last_login_at=excluded.last_login_at, "
                         "last_login_ip=excluded.last_login_ip", (name, int(time.time()), (ip or "")[:64]))
            conn.commit()
        finally:
            conn.close()
    except sqlite3.Error as ex:
        log.warning("could not record login: %s", type(ex).__name__)


def access_summary(is_admin: bool, accounts: Iterable[str], perms: Iterable[str],
                   label: Any = None) -> str:
    """'Kan se … · Må …' in plain Danish (the live summary in the user form
    uses the same wording, see admin.js). `label` maps an account id to
    its friendly name (default: the id)."""
    if is_admin:
        return "Kan se alle postkasser · Må alt – også konti, brugere og indstillinger"
    names = sorted((label(a) if label else a) for a in accounts)
    see = ("Kan se " + _da_join(names)) if names else "Kan ikke se nogen postkasser endnu"
    granted = [p for p in PERMISSIONS if p in set(perms)]
    words = {"release": "frigive post", "rules": "tillade og blokere afsendere", "see_messages": "se alle beskeder"}
    may = ("Må " + _da_join([words[p] for p in granted])) if granted else "Må kun se fanget spam"
    return f"{see} · {may}"


def _da_join(items: list[str]) -> str:
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " og " + items[-1]


# ---------------------------------------------------------------------------
# Two-step login: TOTP (RFC 6238) + recovery codes (ui_twofa; additive, 2.1)
# ---------------------------------------------------------------------------


def new_totp_secret() -> str:
    """160-bit secret as unpadded base32 (what authenticator apps expect)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def b32_secret_bytes(secret: str) -> bytes:
    s = re.sub(r"[\s-]", "", secret or "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def hotp(key: bytes, counter: int, digits: int = TOTP_DIGITS, digest: str = "sha1") -> str:
    """RFC 4226 HOTP with dynamic truncation."""
    mac = hmac.new(key, int(counter).to_bytes(8, "big"), digest).digest()
    offset = mac[-1] & 0x0F
    code = (int.from_bytes(mac[offset:offset + 4], "big") & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp(secret: str | bytes, at: float | None = None, *, digits: int = TOTP_DIGITS,
         step: int = TOTP_STEP, digest: str = "sha1") -> str:
    """RFC 6238 TOTP for unix time `at` (default: now)."""
    key = secret if isinstance(secret, bytes) else b32_secret_bytes(secret)
    return hotp(key, int((time.time() if at is None else at) // step), digits, digest)


def totp_match(secret: str, code: str, *, at: float | None = None, window: int = TOTP_WINDOW,
               after_step: int = -1) -> int | None:
    """The time step `code` belongs to (within +-window), or None. Steps at
    or before `after_step` (already used) never match: no replay."""
    try:
        key = b32_secret_bytes(secret)
    except (ValueError, TypeError):
        return None
    code = str(code or "")
    if not re.fullmatch(r"\d{%d}" % TOTP_DIGITS, code):
        return None
    now_step = int((time.time() if at is None else at) // TOTP_STEP)
    found = None
    for step in range(now_step - window, now_step + window + 1):
        if step <= after_step:
            continue
        if hmac.compare_digest(hotp(key, step), code) and found is None:
            found = step
    return found


def group_secret(secret: str) -> str:
    """'JBSWY3DPEHPK3PXP' -> 'JBSW Y3DP EHPK 3PXP' (easier to type)."""
    return " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))


def otpauth_uri(name: str, secret: str) -> str:
    """Key URI that authenticator apps open (Google Key Uri Format)."""
    label = quote(TOTP_ISSUER, safe="") + ":" + quote(name, safe="")
    return (f"otpauth://totp/{label}?secret={secret}&issuer={quote(TOTP_ISSUER, safe='')}"
            f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP}")


def normalize_code(text: str | None) -> tuple[str | None, str]:
    """('totp', '123456') | ('recovery', 'abcde23456') | (None, '')."""
    t = re.sub(r"[\s-]", "", str(text or "")).lower()[:40]
    if re.fullmatch(r"\d{%d}" % TOTP_DIGITS, t):
        return "totp", t
    if len(t) == RECOVERY_LEN and all(c in RECOVERY_ALPHABET for c in t):
        return "recovery", t
    return None, ""


def format_recovery(code: str) -> str:
    half = RECOVERY_LEN // 2
    return f"{code[:half]}-{code[half:]}"


def _recovery_hash(salt: str, code: str) -> str:
    return hashlib.sha256(f"{salt}:{code}".encode()).hexdigest()


def _new_recovery_codes() -> tuple[list[str], str]:
    codes = ["".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(RECOVERY_LEN)) for _ in range(RECOVERY_CODES)]
    salt = secrets.token_hex(16)
    return codes, json.dumps({"salt": salt, "codes": [_recovery_hash(salt, c) for c in codes]})


def _recovery_data(raw: Any) -> dict:
    try:
        data = json.loads(raw) if raw else {}
    except (TypeError, ValueError):
        data = {}
    if not isinstance(data, dict) or not isinstance(data.get("codes"), list):
        return {"salt": "", "codes": []}
    return {"salt": str(data.get("salt") or ""), "codes": [str(c) for c in data["codes"]]}


def _twofa_row(name: str) -> sqlite3.Row | None:
    _ensure_ui_db()
    conn = _connect()
    try:
        return conn.execute("SELECT * FROM ui_twofa WHERE name=?", (name,)).fetchone()
    finally:
        conn.close()


def _twofa_mail_row(name: str) -> sqlite3.Row | None:
    _ensure_ui_db()
    conn = _connect()
    try:
        return conn.execute("SELECT * FROM ui_twofa_mail WHERE name=?", (name,)).fetchone()
    finally:
        conn.close()


def _twofa_status_from_row(row: sqlite3.Row | None, mrow: sqlite3.Row | None = None) -> dict:
    """Status of both methods. `enabled` = at least one method is on (the
    app and/or mail codes): that is what login, "Kræv to-trins-login" and
    the admin views look at."""
    totp = bool(row is not None and row["secret"] and row["enabled_at"])
    by_mail = bool(mrow is not None and mrow["email"] and mrow["enabled_at"])
    enabled = totp or by_mail
    stamps = [int(x) for x in ((row["enabled_at"] if totp else None), (mrow["enabled_at"] if by_mail else None))
              if x]
    recovery_left = len(_recovery_data(row["recovery"])["codes"]) if (enabled and row is not None) else 0
    return {"enabled": enabled, "required": bool(row is not None and row["required"]),
            "enabled_at": min(stamps) if stamps else None,
            "recovery_left": recovery_left,
            "pending": bool(row is not None and row["pending_secret"]),
            "totp": totp, "mail": by_mail,
            "totp_enabled_at": row["enabled_at"] if totp else None,
            "mail_enabled_at": mrow["enabled_at"] if by_mail else None,
            "mail_masked": mailer.mask_address(mrow["email"]) if by_mail else "",
            "methods": [m for m, on in (("totp", totp), ("mail", by_mail)) if on]}


def twofa_status(name: str) -> dict:
    """{'enabled', 'required', 'enabled_at', 'recovery_left', 'pending',
    'totp', 'mail', 'mail_masked', 'methods', ...}. A user without rows
    (everybody before 2.1) has 2FA off, not required."""
    try:
        return _twofa_status_from_row(_twofa_row(name), _twofa_mail_row(name))
    except sqlite3.Error as ex:
        log.warning("ui_twofa unavailable: %s", type(ex).__name__)
        return _twofa_status_from_row(None)


def all_twofa_status() -> dict[str, dict]:
    try:
        _ensure_ui_db()
        conn = _connect()
        try:
            rows = {str(r["name"]): r for r in conn.execute("SELECT * FROM ui_twofa").fetchall()}
            mrows = {str(r["name"]): r for r in conn.execute("SELECT * FROM ui_twofa_mail").fetchall()}
        finally:
            conn.close()
    except sqlite3.Error:
        rows, mrows = {}, {}
    return {n: _twofa_status_from_row(rows.get(n), mrows.get(n)) for n in sorted(set(rows) | set(mrows))}


def _twofa_write(sql: str, params: Iterable[Any]) -> int:
    _ensure_ui_db()
    conn = _connect()
    try:
        cur = conn.execute(sql, tuple(params))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def _twofa_ensure_row(name: str) -> None:
    _twofa_write("INSERT OR IGNORE INTO ui_twofa(name, required, last_step) VALUES(?, 0, 0)", (name,))


def twofa_pending_secret(name: str, *, create: bool = True) -> str | None:
    """The enrollment secret shown on the setup page (stable for
    TWOFA_PENDING_TTL, so a reload shows the same QR code)."""
    row = _twofa_row(name)
    now = int(time.time())
    if row is not None and row["pending_secret"] and now - int(row["pending_at"] or 0) < TWOFA_PENDING_TTL:
        return str(row["pending_secret"])
    if not create:
        return None
    secret = new_totp_secret()
    _twofa_ensure_row(name)
    _twofa_write("UPDATE ui_twofa SET pending_secret=?, pending_at=? WHERE name=?", (secret, now, name))
    return secret


def twofa_confirm(name: str, code: str, actor: str = "") -> list[str] | None:
    """Turn the app (TOTP) on when `code` fits the pending secret. Returns
    the new recovery codes (plain, shown once), [] when mail codes were
    already on (the user keeps the recovery codes they have) or None."""
    secret = twofa_pending_secret(name, create=False)
    kind, norm = normalize_code(code)
    if secret is None or kind != "totp":
        return None
    step = totp_match(secret, norm)
    if step is None:
        return None
    now = int(time.time())
    if twofa_status(name)["mail"]:
        n = _twofa_write("UPDATE ui_twofa SET secret=pending_secret, enabled_at=?, last_step=?, "
                         "pending_secret=NULL, pending_at=NULL, updated_at=?, updated_by=? "
                         "WHERE name=? AND pending_secret=?", (now, step, now, actor or name, name, secret))
        return [] if n == 1 else None
    codes, recovery = _new_recovery_codes()
    n = _twofa_write("UPDATE ui_twofa SET secret=pending_secret, enabled_at=?, last_step=?, recovery=?, "
                     "pending_secret=NULL, pending_at=NULL, updated_at=?, updated_by=? "
                     "WHERE name=? AND pending_secret=?", (now, step, recovery, now, actor or name, name, secret))
    return codes if n == 1 else None


def twofa_verify(name: str, code: str | None) -> str | None:
    """Check a login/confirmation code: 'totp', 'mail' (a mailed one-time
    code), 'recovery' (that code is used up) or None. A TOTP step and a
    mailed code are accepted once only (replay)."""
    kind, norm = normalize_code(code)
    if kind is None:
        return None
    row, mrow = _twofa_row(name), _twofa_mail_row(name)
    st = _twofa_status_from_row(row, mrow)
    if not st["enabled"]:
        return None
    if kind == "totp":
        if st["totp"]:
            step = totp_match(str(row["secret"]), norm, after_step=int(row["last_step"] or 0))
            if step is not None:
                n = _twofa_write("UPDATE ui_twofa SET last_step=? WHERE name=? AND last_step<?", (step, name, step))
                if n == 1:
                    return "totp"
        if st["mail"] and mail_code_check(name, "login", norm, email=str(mrow["email"])) is not None:
            return "mail"
        return None
    if row is None:
        return None
    data = _recovery_data(row["recovery"])
    want = _recovery_hash(data["salt"], norm)
    match = None
    for stored in data["codes"]:
        if hmac.compare_digest(stored, want):
            match = stored
    if match is None:
        return None
    left = [c for c in data["codes"] if c != match]
    n = _twofa_write("UPDATE ui_twofa SET recovery=? WHERE name=? AND recovery=?",
                     (json.dumps({"salt": data["salt"], "codes": left}), name, row["recovery"]))
    return "recovery" if n == 1 else None


def twofa_new_recovery(name: str, actor: str = "") -> list[str] | None:
    if not twofa_status(name)["enabled"]:
        return None
    codes, recovery = _new_recovery_codes()
    _twofa_ensure_row(name)
    _twofa_write("UPDATE ui_twofa SET recovery=?, updated_at=?, updated_by=? WHERE name=?",
                 (recovery, int(time.time()), actor or name, name))
    return codes


TWOFA_METHODS = ("all", "totp", "mail")


def twofa_disable(name: str, actor: str = "", method: str = "all") -> bool:
    """Turn two-step login off. method 'all' (default; admin reset, sfctl,
    CLI) removes BOTH methods, the app secret and the recovery codes;
    'totp' / 'mail' remove one method (the recovery codes stay while the
    other method is on). `required` stays, so a required user must set it
    up again at the next request."""
    method = method if method in TWOFA_METHODS else "all"
    st = twofa_status(name)
    if (method == "mail" and not st["mail"]) or (method == "totp" and not st["totp"]):
        return False
    now = int(time.time())
    drop_mail, drop_totp = method in ("all", "mail"), method in ("all", "totp")
    remaining = (st["totp"] and not drop_totp) or (st["mail"] and not drop_mail)
    changed = 0
    if drop_mail:
        changed += _twofa_write("DELETE FROM ui_twofa_mail WHERE name=?", (name,))
        _twofa_write("DELETE FROM ui_mail_codes WHERE name=?", (name,))
    if drop_totp:
        changed += _twofa_write("UPDATE ui_twofa SET secret=NULL, enabled_at=NULL, last_step=0, "
                                "pending_secret=NULL, pending_at=NULL, "
                                + ("" if remaining else "recovery=NULL, ")
                                + "updated_at=?, updated_by=? WHERE name=?", (now, actor, name))
    elif not remaining:  # the recovery codes go with the last method
        changed += _twofa_write("UPDATE ui_twofa SET recovery=NULL, updated_at=?, updated_by=? WHERE name=?",
                                (now, actor, name))
    return changed >= 1


def twofa_set_required(name: str, required: bool, actor: str = "") -> None:
    _twofa_ensure_row(name)
    _twofa_write("UPDATE ui_twofa SET required=?, updated_at=?, updated_by=? WHERE name=?",
                 (1 if required else 0, int(time.time()), actor, name))


def twofa_forget(name: str) -> None:
    for sql in ("DELETE FROM ui_twofa WHERE name=?", "DELETE FROM ui_twofa_mail WHERE name=?",
                "DELETE FROM ui_mail_codes WHERE name=?"):
        try:
            _twofa_write(sql, (name,))
        except sqlite3.Error as ex:
            log.warning("could not forget 2fa: %s", type(ex).__name__)


# ---------------------------------------------------------------------------
# Two-step login by mail (2.3, B29): verified address + one-time codes
# ---------------------------------------------------------------------------

MAIL_PURPOSES = ("login", "verify")


def mail_2fa_available() -> bool:
    """'Kode på mail' is offered only when a mail server is set up."""
    try:
        return bool(mail().is_configured())
    except Exception as ex:  # noqa: BLE001
        log.warning("mail status unavailable: %s", type(ex).__name__)
        return False


def twofa_mail_address(name: str) -> str | None:
    """The user's VERIFIED address for codes (None when mail codes are off).
    Never rendered in full - use mailer.mask_address()."""
    try:
        row = _twofa_mail_row(name)
    except sqlite3.Error:
        return None
    if row is None or not row["email"] or not row["enabled_at"]:
        return None
    return str(row["email"])


def _mail_code_hash(salt: str, name: str, purpose: str, code: str) -> str:
    return hashlib.sha256(f"{salt}:{name}:{purpose}:{code}".encode()).hexdigest()


def mail_code_state(name: str, *, now: int | None = None) -> dict:
    """{'sends' (in the window), 'sends_left', 'wait' (s until the next
    send is allowed, 0 = now), 'last_at', 'last_login_at' (newest login
    code)} - for the resend cooldown."""
    t = int(now if now is not None else time.time())
    _ensure_ui_db()
    conn = _connect()
    try:
        rows = conn.execute("SELECT created_at, purpose FROM ui_mail_codes WHERE name=? AND created_at>? "
                            "ORDER BY created_at", (name, t - MAIL_CODE_WINDOW)).fetchall()
    finally:
        conn.close()
    stamps = [int(r[0]) for r in rows]
    logins = [int(r[0]) for r in rows if r[1] == "login"]
    wait = 0
    if stamps:
        wait = max(0, stamps[-1] + MAIL_CODE_COOLDOWN - t)
    if len(stamps) >= MAIL_CODE_MAX_SENDS:
        wait = max(wait, stamps[-MAIL_CODE_MAX_SENDS] + MAIL_CODE_WINDOW - t)
    return {"sends": len(stamps), "sends_left": max(0, MAIL_CODE_MAX_SENDS - len(stamps)), "wait": wait,
            "last_at": stamps[-1] if stamps else None, "last_login_at": logins[-1] if logins else None}


def mail_code_issue(name: str, email: str, purpose: str = "login", *, template: str | None = None) -> dict:
    """Create a 6-digit code for `name` and queue the mail. Max
    MAIL_CODE_MAX_SENDS per MAIL_CODE_WINDOW and one per MAIL_CODE_COOLDOWN
    (per user, all purposes). Only a salted hash is stored; a new code
    replaces the user's earlier unused code of the same purpose.
    -> {'ok', 'code': 'sent'|'wait'|'unavailable'|'invalid'|'error', 'wait'}."""
    if purpose not in MAIL_PURPOSES:
        return {"ok": False, "code": "invalid", "wait": 0}
    try:
        addr = mailer.validate_address(email)
    except mailer.MailError:
        return {"ok": False, "code": "invalid", "wait": 0}
    if not mail_2fa_available():
        return {"ok": False, "code": "unavailable", "wait": 0}
    now = int(time.time())
    code = str(secrets.randbelow(10 ** 6)).zfill(6)
    salt = secrets.token_hex(16)
    _ensure_ui_db()
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        stamps = [int(r[0]) for r in conn.execute(
            "SELECT created_at FROM ui_mail_codes WHERE name=? AND created_at>? ORDER BY created_at",
            (name, now - MAIL_CODE_WINDOW)).fetchall()]
        wait = max(0, stamps[-1] + MAIL_CODE_COOLDOWN - now) if stamps else 0
        if len(stamps) >= MAIL_CODE_MAX_SENDS:
            wait = max(wait, stamps[-MAIL_CODE_MAX_SENDS] + MAIL_CODE_WINDOW - now)
        if wait > 0:
            conn.execute("COMMIT")
            return {"ok": False, "code": "wait", "wait": wait}
        conn.execute("UPDATE ui_mail_codes SET expires_at=? WHERE name=? AND purpose=? AND used_at IS NULL "
                     "AND expires_at>?", (now, name, purpose, now))
        conn.execute("INSERT INTO ui_mail_codes(name, purpose, email, salt, code_hash, created_at, expires_at) "
                     "VALUES(?,?,?,?,?,?,?)",
                     (name, purpose, addr, salt, _mail_code_hash(salt, name, purpose, code), now,
                      now + MAIL_CODE_TTL))
        # Old rows are only kept for the send limit window.
        conn.execute("DELETE FROM ui_mail_codes WHERE created_at<?", (now - 86400,))
        conn.execute("COMMIT")
    except sqlite3.Error:
        conn.rollback()
        raise
    finally:
        conn.close()
    res = mail().send_code(addr, code, purpose=template or purpose, name=name)
    if not res.get("ok"):
        log.warning("2fa code mail not queued: %s", res.get("code"))
        return {"ok": False, "code": "error", "wait": 0}
    return {"ok": True, "code": "sent", "wait": MAIL_CODE_COOLDOWN}


_DUMMY_SALT = secrets.token_hex(16)


def mail_code_check(name: str, purpose: str, code: str | None, *, email: str | None = None) -> str | None:
    """Verify a mailed code: the newest unused, unexpired code of this user
    + purpose (and address, when given) with fewer than
    MAIL_CODE_MAX_TRIES wrong guesses. Single use. Returns the address the
    code was sent to, or None. The same work is done whether or not a code
    exists (no timing difference)."""
    norm = re.sub(r"[\s-]", "", str(code or ""))
    now = int(time.time())
    _ensure_ui_db()
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM ui_mail_codes WHERE name=? AND purpose=? AND used_at IS NULL "
                           "AND expires_at>? ORDER BY id DESC LIMIT 1", (name, purpose, now)).fetchone()
        usable = (row is not None and int(row["attempts"]) < MAIL_CODE_MAX_TRIES
                  and (email is None or str(row["email"]).lower() == str(email).lower()))
        salt = str(row["salt"]) if row is not None else _DUMMY_SALT
        want = str(row["code_hash"]) if row is not None else "0" * 64
        ok = hmac.compare_digest(_mail_code_hash(salt, name, purpose, norm), want)
        ok = ok and usable and bool(re.fullmatch(r"\d{6}", norm))
        if row is None:
            conn.execute("COMMIT")
            return None
        if not ok:
            if usable:
                conn.execute("UPDATE ui_mail_codes SET attempts=attempts+1 WHERE id=?", (row["id"],))
            conn.execute("COMMIT")
            return None
        n = conn.execute("UPDATE ui_mail_codes SET used_at=? WHERE id=? AND used_at IS NULL",
                         (now, row["id"])).rowcount
        conn.execute("COMMIT")
        return str(row["email"]) if n == 1 else None
    except sqlite3.Error:
        conn.rollback()
        raise
    finally:
        conn.close()


def twofa_mail_enable(name: str, email: str, actor: str = "") -> list[str] | None:
    """Turn mail codes on for a VERIFIED address. Returns new recovery
    codes when the user had none (no app), else [] (codes are kept)."""
    addr = mailer.validate_address(email)
    now = int(time.time())
    st = twofa_status(name)
    _twofa_write("INSERT INTO ui_twofa_mail(name, email, enabled_at, updated_at, updated_by) VALUES(?,?,?,?,?) "
                 "ON CONFLICT(name) DO UPDATE SET email=excluded.email, enabled_at=excluded.enabled_at, "
                 "updated_at=excluded.updated_at, updated_by=excluded.updated_by",
                 (name, addr, now, now, actor or name))
    _twofa_write("DELETE FROM ui_mail_codes WHERE name=? AND purpose='login'", (name,))
    if st["enabled"]:
        # A second method keeps the user's recovery codes (new ones only
        # come from "Lav nye genoprettelseskoder", which asks for a code).
        return []
    codes, recovery = _new_recovery_codes()
    _twofa_ensure_row(name)
    _twofa_write("UPDATE ui_twofa SET recovery=?, updated_at=?, updated_by=? WHERE name=?",
                 (recovery, now, actor or name, name))
    return codes


# A user can trigger notices (password changes, 2FA changes): at most
# SECURITY_NOTICE_MAX per user per SECURITY_NOTICE_WINDOW, so nobody can
# flood the admins' inboxes or the shared mail budget (the change itself is
# always in the audit log).
SECURITY_NOTICE_MAX = 6
SECURITY_NOTICE_WINDOW = 3600
# Successful own password changes per user per hour (each one mails).
PWCHANGE_MAX_PER_HOUR = 5
_RECENT_LOCK = threading.Lock()
_RECENT: dict[str, list[float]] = {}


def _recent_hit(key: str, limit: int, window: int, *, record: bool = True) -> bool:
    """In-memory rolling counter: True (and counted) while under `limit`
    within `window` seconds, False when the limit is reached."""
    now = time.time()
    key = f"{DB_PATH}|{key}"  # one state dir = one set of counters (tests, dev)
    with _RECENT_LOCK:
        hits = [t for t in _RECENT.get(key, []) if now - t < window]
        if len(hits) >= limit:
            _RECENT[key] = hits
            return False
        if record:
            hits.append(now)
        _RECENT[key] = hits
        return True


def security_notice(name: str, subject: str, what: str, *, also: Iterable[str | None] = ()) -> None:
    """Security mail (kind 'security') about a change to `name`'s login:
    to the user's own verified address (plus `also`, e.g. the address that
    was just removed) and the 'Sikkerhed' recipients. Only when a mail
    server is set up; never raises, never secrets. Rate-limited per user
    (SECURITY_NOTICE_MAX per SECURITY_NOTICE_WINDOW)."""
    try:
        m = mail()
        if not m.is_configured():
            return
        if not _recent_hit(f"notice:{name.lower()}", SECURITY_NOTICE_MAX, SECURITY_NOTICE_WINDOW):
            log.info("security notice for a user skipped (rate limit)")
            audit("security_notice", result="skipped", actor=name, detail="for mange på en time")
            return
        rcpts: list[str] = []
        for own in (twofa_mail_address(name), *also):
            if own and own.lower() not in {x.lower() for x in rcpts}:
                rcpts.append(own)
        for r in m.recipients_for("security"):
            if r.lower() not in {x.lower() for x in rcpts}:
                rcpts.append(r)
        if not rcpts:
            return
        ip = request.remote_addr if has_request_context() else ""
        when = time.strftime("%d.%m.%Y kl. %H:%M", time.localtime())
        text = (f"{what}\n\nBruger: {name}\nTidspunkt: {when}" + (f"\nFra IP-adresse: {ip}" if ip else "")
                + "\n\nVar det ikke dig? Skift din adgangskode under Min konto med det samme, og bed en "
                  "administrator om hjælp. Administratoren kan altid nulstille to-trins-login.")
        m.notify("security", f"Spamfilter: {subject}", text, recipients=rcpts)
    except Exception as ex:  # noqa: BLE001 - a notice must never break the change itself
        log.warning("security notice not sent: %s", type(ex).__name__)


# ---------------------------------------------------------------------------
# External address (settings_kv 'external_url')
# ---------------------------------------------------------------------------


def normalize_external_url(text: str | None) -> str:
    """'spam.example.dk' -> 'https://spam.example.dk'. '' clears it.
    Raises ValueError with a Danish message."""
    t = (text or "").strip()
    if not t:
        return ""
    if len(t) > 200 or any(ord(c) < 0x21 for c in t):
        raise ValueError("Adressen er for lang eller indeholder mellemrum.")
    if "://" not in t:
        t = "https://" + t
    try:
        parts = urlsplit(t)
        port = parts.port
    except ValueError:
        raise ValueError("Adressen kunne ikke læses. Skriv fx https://spam.dit-domæne.dk") from None
    if parts.scheme not in ("http", "https"):
        raise ValueError("Adressen skal starte med https://")
    host = (parts.hostname or "").lower()
    if not host or parts.username or parts.password or not _HOST_RE.fullmatch(host):
        raise ValueError("Skriv kun selve adressen, fx https://spam.dit-domæne.dk")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError("Skriv kun selve adressen uden sti, fx https://spam.dit-domæne.dk")
    netloc = host if port is None else f"{host}:{port}"
    return f"{parts.scheme}://{netloc}"


def external_url() -> str:
    if has_request_context() and "_external_url" in g:
        return g._external_url
    try:
        value = settings_get("external_url") or ""
    except sqlite3.Error:
        value = ""
    if has_request_context():
        g._external_url = value
    return value


# ---------------------------------------------------------------------------
# Sessions, users in requests, scopes
# ---------------------------------------------------------------------------

_NO_USER = object()


def session_limits(remember: bool) -> tuple[int, int]:
    """(absolute, idle) seconds for a normal or a "Husk mig" session."""
    return (REMEMBER_LIFETIME, REMEMBER_IDLE) if remember else (SESSION_LIFETIME, SESSION_IDLE)


def current_user() -> dict | None:
    """{'name', 'is_admin', 'accounts', 'perms', 'role', 'remember'} or None.

    accounts is None for admins (= all accounts) and a frozenset of names
    otherwise; perms is the frozenset of granted Bruger permissions (all of
    PERMISSIONS for admins). Re-read from the users file + ui_users on every
    request, so a changed scope/permission applies at once."""
    if not has_request_context():
        return None
    cached = g.get("_user", _NO_USER)
    if cached is not _NO_USER:
        return cached
    result = None
    name = session.get("u")
    if name:
        now = int(time.time())
        u = load_users().get(name)
        t0, seen = int(session.get("t0", 0)), int(session.get("ts", 0))
        lifetime, idle = session_limits(bool(session.get("rm")))
        kr = session.get("kr")
        if (u is None or int(session.get("gen", -1)) != u.gen
                or now - t0 > lifetime or now - seen > idle):
            session.clear()
        elif kr is not None and (why := kr_session_problem(u.name, kr)):
            # 2.9.0: a Kontrolrum SSO session is only valid from the
            # Kontrolrum address it was made for (a copied cookie used
            # anywhere else - the tunnel, the LAN - is logged out at once).
            session.clear()
            _kr_session_refused(u.name, why)
        elif kr is None and not login_allowed_here(u.name):
            # 2.3: a 'Kun lokalt' user's session (also "Husk mig") used from
            # outside the home network = logged out.
            session.clear()
            _blocked_external(u.name, "session")
        else:
            tf = twofa_status(u.name)
            if tf["enabled"] and not session.get("mfa"):
                # 2FA was turned on after this session started (or on another
                # device): confirm a code first, keep "Husk mig" and the page.
                begin_mfa(u, remember=bool(session.get("rm")))
            else:
                if now - seen > 60:  # sliding idle window; avoid a cookie per request
                    session["ts"] = now
                perms = frozenset(PERMISSIONS) if u.admin else user_perms(u.name)
                result = {"name": u.name, "is_admin": u.admin,
                          "accounts": None if u.admin else frozenset(u.accounts),
                          "perms": perms, "role": "admin" if u.admin else "user",
                          "remember": bool(session.get("rm")),
                          "twofa": tf["enabled"],
                          "needs_2fa_setup": tf["required"] and not tf["enabled"] and kr is None,
                          "via_kontrolrum": kr is not None}
    g._user = result
    return result


def begin_mfa(user: User, *, remember: bool = False) -> None:
    """Password verified, code still missing: the session holds only a
    short-lived 'pre' login (never counts as logged in)."""
    session.clear()
    session.permanent = False
    session["pre"] = {"u": user.name, "gen": user.gen, "t": int(time.time()), "rm": 1 if remember else 0, "n": 0}
    session["csrf"] = secrets.token_urlsafe(32)
    if has_request_context():
        g.pop("_user", None)


def pending_mfa() -> tuple[User, dict] | None:
    """(user, pre) of a valid password-ok-code-missing login, else None."""
    if not has_request_context():
        return None
    pre = session.get("pre")
    if not isinstance(pre, dict):
        return None
    try:
        name, gen, t0, tries = str(pre["u"]), int(pre["gen"]), int(pre["t"]), int(pre.get("n", 0))
    except (KeyError, TypeError, ValueError):
        return None
    u = load_users().get(name)
    if u is None or u.gen != gen or time.time() - t0 > MFA_PENDING_TTL or tries >= MFA_MAX_TRIES:
        return None
    if not login_allowed_here(u.name):
        # 2.3: the password step was done at home, the code is sent from
        # outside (or the other way round through a proxy): start over.
        session.pop("pre", None)
        _blocked_external(u.name, "to-trins")
        return None
    return u, pre


def is_admin() -> bool:
    return bool((current_user() or {}).get("is_admin"))


# 'Se som bruger' (2.1, admin only): render a page exactly as a Bruger sees
# it, read-only. The admin's session is untouched; only this request's
# g._user is swapped while the page renders (the route policy was already
# checked for the real admin in _before()).
def user_view(name: str) -> dict | None:
    """The current_user()-shaped dict a Bruger `name` would get (no session)."""
    u = load_users().get(name)
    if u is None:
        return None
    tf = twofa_status(u.name)
    return {"name": u.name, "is_admin": u.admin,
            "accounts": None if u.admin else frozenset(u.accounts),
            "perms": frozenset(PERMISSIONS) if u.admin else user_perms(u.name),
            "role": "admin" if u.admin else "user", "remember": False,
            "twofa": tf["enabled"], "needs_2fa_setup": False, "preview": True}


_G_USER_CACHES = ("_sidebar", "_nav_counts", "_spam_seen_for", "_spam_seen")


def begin_preview(name: str) -> dict:
    """Swap this request's user to the Bruger `name` (read-only preview)."""
    view = user_view(name)
    if view is None or view["is_admin"]:
        abort(404)
    g._real_user = current_user()
    for key in _G_USER_CACHES:
        g.pop(key, None)
    g._user = view
    g._preview_of = name
    return view


def end_preview() -> None:
    if g.get("_preview_of") is None:
        return
    for key in _G_USER_CACHES:
        g.pop(key, None)
    g._user = g.pop("_real_user", None)
    g.pop("_preview_of", None)


def preview_target() -> str | None:
    """Name of the Bruger being previewed in this request, else None."""
    return g.get("_preview_of") if has_request_context() else None


def can_access(account: str) -> bool:
    """May the current user see this mailbox at all?"""
    u = current_user()
    if u is None:
        return False
    return u["accounts"] is None or account in u["accounts"]


def can(perm: str, account: str | None = None) -> bool:
    """Central permission check: admin, or a Bruger holding `perm` (and,
    with `account`, that mailbox is one of theirs)."""
    u = current_user()
    if u is None:
        return False
    if u.get("is_admin"):
        return True
    if perm not in (u.get("perms") or ()):
        return False
    return account is None or account in (u.get("accounts") or ())


def can_edit_rule(account: str, *, force: bool = False) -> bool:
    """Sender rules: admins edit everything; a Bruger with the 'rules'
    permission only rules of their own mailboxes - never global ('*')
    rules and never 'Altid igennem' (force) rules."""
    if is_admin():
        return True
    if account == "*" or force:
        return False
    return can("rules", account)


def require_account(account: str) -> None:
    """404 for a mailbox the user may not see (existence is not revealed)."""
    if not can_access(account):
        abort(404)


def require(perm: str, account: str | None = None) -> None:
    """403 unless can(perm) - plus 404 first for an invisible mailbox."""
    if account is not None:
        require_account(account)
    if not can(perm, account):
        abort(403)


def scope_sql(column: str = "account") -> tuple[str, list]:
    """(' AND account IN (?,..)', params) for the current user's scope."""
    u = current_user()
    if u is None:
        return " AND 0", []
    if u["accounts"] is None:
        return "", []
    names = sorted(u["accounts"])
    if not names:
        return " AND 0", []
    return f" AND {column} IN ({','.join('?' * len(names))})", names


def wants_json() -> bool:
    if request.headers.get("X-Requested-With", "").lower() in ("fetch", "xmlhttprequest"):
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept and "text/html" not in accept


# Route access policies. Every view MUST carry one (set by the decorators
# below); _before() refuses endpoints without one.
POLICY_PUBLIC = "public"
POLICY_LOGIN = "login"
POLICY_ADMIN = "admin"
# 2.3.6 (B26): read-only Home Assistant API - LAN + bearer token, no session.
# 2.11.0: any API key with at least `read` (api_key_for_request).
POLICY_HA = "ha_token"
# 2.11.0: reserved for endpoints that change something (none yet).
POLICY_API_CONTROL = "api_control"
POLICY_API_ADMIN = "api_admin"
API_POLICIES = {POLICY_HA: "read", POLICY_API_CONTROL: "control", POLICY_API_ADMIN: "admin"}


def _not_logged_in():
    nxt = request.full_path if request.method == "GET" else "/"
    target = "/login/2fa" if pending_mfa() is not None else "/login"
    if wants_json():
        return json_err("Du er ikke logget ind.", 401, redirect=target)
    return redirect(target + "?next=" + _quote_next(nxt))


def enforce(policy: str):
    """THE central access check for a route policy. Returns a response
    (login redirect / 401 JSON) or None; aborts 403 when the user lacks the
    role/permission and 404 for an unknown policy (fail closed)."""
    if policy == POLICY_PUBLIC:
        return None
    if policy in API_POLICIES:
        # API keys (2.11.0, B26 before): no session - a valid key with the
        # right scope (home network only unless the key says otherwise),
        # else a plain 404 that says nothing (403: valid key, too few
        # rights; 429: over the key's rate limit).
        if api_key_for_request(API_POLICIES[policy]) is None:
            status = int(g.get("_api_status") or 404)
            if status == 429:
                resp = jsonify({"ok": False, "message": "For mange kald med denne nøgle. Vent lidt."})
                resp.status_code = 429
                resp.headers["Retry-After"] = str(int(g.get("_api_retry") or API_KEY_RATE_WINDOW))
                return resp
            abort(403 if status == 403 else 404)
        return None
    if current_user() is None:
        return _not_logged_in()
    if policy == POLICY_LOGIN:
        return None
    if policy == POLICY_ADMIN:
        if not is_admin():
            abort(403)
        return None
    if policy in PERMISSIONS:
        if not can(policy):
            abort(403)
        return None
    log.error("unknown access policy %r", policy)
    abort(404)


def _guard(view: Callable, policy: str) -> Callable:
    @wraps(view)
    def wrapped(*args, **kwargs):
        resp = enforce(policy)
        if resp is not None:
            return resp
        return view(*args, **kwargs)

    wrapped.sf_access = policy  # type: ignore[attr-defined]
    return wrapped


def public(view: Callable) -> Callable:
    """No login needed (health, login, static helpers)."""
    view.sf_access = POLICY_PUBLIC  # type: ignore[attr-defined]
    return view


def login_required(view: Callable) -> Callable:
    return _guard(view, POLICY_LOGIN)


def admin_required(view: Callable) -> Callable:
    return _guard(view, POLICY_ADMIN)


def ha_token_required(view: Callable) -> Callable:
    """Read-only API (Home Assistant, Kontrolrum): an API key with at least
    `read` (see api_key_for_request); everything else is a plain 404."""
    return _guard(view, POLICY_HA)


def api_key_required(scope: str) -> Callable[[Callable], Callable]:
    """An API key with at least `scope` (read|control|admin)."""
    policy = {v: k for k, v in API_POLICIES.items()}.get(scope)
    if policy is None:
        raise ValueError(f"unknown API key scope {scope!r}")
    return lambda view: _guard(view, policy)


def permission_required(perm: str) -> Callable[[Callable], Callable]:
    """Logged in and admin or a Bruger with `perm` (one of PERMISSIONS)."""
    if perm not in PERMISSIONS:
        raise ValueError(f"unknown permission {perm!r}")

    def deco(view: Callable) -> Callable:
        return _guard(view, perm)

    return deco


def route_policy(endpoint: str | None) -> str | None:
    view = app.view_functions.get(endpoint or "")
    return getattr(view, "sf_access", None) if view is not None else None


def _quote_next(path: str) -> str:
    from urllib.parse import quote

    return quote(path.rstrip("?"), safe="/")


def safe_next(target: str | None, default: str = "/") -> str:
    """Only same-site relative redirect targets."""
    from urllib.parse import urlsplit

    t = (target or "").strip()
    if not t.startswith("/") or t.startswith("//") or "\\" in t:
        return default
    # Browsers drop TAB/CR/LF (and the Location header may lose other
    # control characters), so "/\t/evil.example" would become a
    # protocol-relative "//evil.example": no control chars or spaces at all.
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in t):
        return default
    parts = urlsplit(t)
    if parts.scheme or parts.netloc:
        return default
    return t


# ---------------------------------------------------------------------------
# CSRF + origin checks
# ---------------------------------------------------------------------------


def csrf_token() -> str:
    tok = session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf"] = tok
    return tok


def _origin_key(scheme: str, netloc: str) -> str:
    """'host[:port]' in lower case without the scheme's default port."""
    n = (netloc or "").lower().rsplit("@", 1)[-1]
    default = {"https": ":443", "http": ":80"}.get((scheme or "").lower())
    if default and n.endswith(default):
        n = n[: -len(default)]
    return n


def allowed_origins() -> set[str]:
    """This request's own host (LAN or, via a trusted proxy, the public
    host) plus the configured external address."""
    keys = {_origin_key(request.scheme, request.host)}
    ext = external_url()
    if ext:
        p = urlsplit(ext)
        keys.add(_origin_key(p.scheme, p.netloc))
    return keys


def _same_origin(url: str) -> bool:
    try:
        p = urlsplit(url)
    except ValueError:
        return False
    if not p.netloc:
        return False
    return _origin_key(p.scheme or request.scheme, p.netloc) in allowed_origins()


def origin_ok() -> bool:
    """Reject explicit cross-origin POSTs. `Origin: null` (what browsers
    send under Referrer-Policy no-referrer) and absent headers fall back
    to the CSRF token + SameSite=Strict cookie."""
    origin = request.headers.get("Origin")
    if origin and origin != "null":
        return _same_origin(origin)
    ref = request.headers.get("Referer")
    if ref:
        return _same_origin(ref)
    return True


def _csrf_valid() -> bool:
    sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf") or ""
    tok = session.get("csrf") or ""
    return bool(tok) and bool(sent) and hmac.compare_digest(str(sent), str(tok)) and origin_ok()


def check_csrf() -> None:
    """Abort 400 unless the request carries this session's CSRF token."""
    if not _csrf_valid():
        abort(400, description="csrf")


# api_ha: read-only, session-less (bearer token from the LAN); every
# method is routed to it so nothing but 404 ever leaks (ui_ha).
# login_kontrolrum: server-to-server SSO (2.9.0), checked by peer IP + signature instead.
_CSRF_EXEMPT = {"login", "login_2fa", "api_ha", "login_kontrolrum"}
# What a user who must set up 2FA (admin requirement) may still open.
TWOFA_SETUP_ENDPOINTS = {"me_page", "me_2fa_setup", "me_2fa_confirm", "me_logout_all"}


@app.before_request
def _before():
    # 1) Access: every endpoint declares a policy; none = fail closed.
    endpoint = request.endpoint
    if endpoint is not None and endpoint != "static":
        policy = route_policy(endpoint)
        if policy is None:
            log.error("route %s has no access policy; refused", endpoint)
            abort(404)
        resp = enforce(policy)
        if resp is not None:
            return resp
        # 1b) An admin requires 2FA for this user and it is not set up yet:
        # only the setup pages (and logging out) until it is.
        if policy != POLICY_PUBLIC and policy not in API_POLICIES and endpoint not in TWOFA_SETUP_ENDPOINTS:
            u = current_user()
            if u is not None and u.get("needs_2fa_setup"):
                msg = "Din administrator kræver to-trins-login. Sæt det op for at fortsætte."
                if wants_json():
                    return json_err(msg, 403, redirect="/me/2fa/setup", code="twofa_setup_required")
                return redirect("/me/2fa/setup")
    # 2) CSRF for every state-changing request.
    if request.method in ("POST", "PUT", "PATCH", "DELETE") and endpoint not in _CSRF_EXEMPT:
        check_csrf()
    return None


@app.after_request
def _headers(resp: Response) -> Response:
    # A view may only make the policy STRICTER-scoped for its own document
    # (CSP_MAIL_PREVIEW); everything else gets the app-wide CSP.
    resp.headers["Content-Security-Policy"] = CSP_MAIL_PREVIEW if g.get("csp_mail_preview") else CSP
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.is_secure:
        resp.headers["Strict-Transport-Security"] = HSTS
    public_cache = PUBLIC_CACHE.get(request.path)
    if request.path.startswith("/static/") or request.path in ("/favicon.png", "/favicon.ico"):
        if resp.status_code == 200:
            resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    elif public_cache and resp.status_code == 200:
        resp.headers["Cache-Control"] = public_cache
    else:
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Pragma"] = "no-cache"
    return resp


# Public PWA files that are not under /static/ (no user data in any of them).
PUBLIC_CACHE = {
    "/manifest.webmanifest": "public, max-age=3600",
    "/sw.js": "no-cache",
    "/offline": "no-cache",
    "/apple-touch-icon.png": "public, max-age=86400",
    "/apple-touch-icon-precomposed.png": "public, max-age=86400",
}


# ---------------------------------------------------------------------------
# Responses, flashes, audit
# ---------------------------------------------------------------------------


def json_ok(message: str = "", **extra: Any) -> Response:
    payload = {"ok": True, "message": message, "results": [], "reload": False}
    payload.update(extra)
    return jsonify(payload)


def json_err(message: str, status: int = 400, **extra: Any) -> tuple[Response, int]:
    payload = {"ok": False, "message": message, "results": [], "reload": False}
    payload.update(extra)
    return jsonify(payload), status


def flash(message: str, kind: str = "ok") -> None:
    """Queue a message for the next rendered page (kind: ok|error|warn|info)."""
    items = list(session.get("_fl", []))[-4:]
    items.append([kind, str(message)[:300]])
    session["_fl"] = items


def pop_flashes() -> list[tuple[str, str]]:
    if not has_request_context():
        return []
    items = session.pop("_fl", None) or []
    return [(str(k), str(m)) for k, m in items]


def respond(message: str, *, ok: bool = True, next_url: str = "/", status: int = 400,
            **extra: Any):
    """Reply to a form POST: JSON for app.js, flash+redirect without JS."""
    if wants_json():
        return json_ok(message, **extra) if ok else json_err(message, status, **extra)
    flash(message, "ok" if ok else "error")
    return redirect(safe_next(next_url))


_AUDIT_LOCK = threading.Lock()
# `ip` of audit records written outside a request (sfctl sets 'local').
AUDIT_IP_NO_REQUEST = ""


def audit(action: str, account: str = "", result: str = "ok", detail: str = "",
          message_id: str = "", *, actor: str | None = None) -> None:
    """Append one JSON line to admin-audit.jsonl (0600, fsync). Never
    put secrets or raw exception text in `detail`."""
    if actor is None:
        u = current_user() if has_request_context() else None
        actor = u["name"] if u else ""
    record: dict[str, Any] = {"ts": int(time.time()), "actor": actor,
                              "ip": request.remote_addr if has_request_context() else AUDIT_IP_NO_REQUEST,
                              "action": action, "account": account, "result": result}
    if detail:
        record["detail"] = str(detail)[:500]
    if message_id:
        record["message_id"] = str(message_id)[:255]
    if has_request_context():
        if via_proxy():
            record["proxy"] = request_peer()[:64]
        if cf_access_user():
            record["cf_user"] = cf_access_user()
        try:
            if session.get("kr"):
                # 2.12 (#10): the person acted through Kontrolrum's SSO.
                record["via"] = "kontrolrum"
        except RuntimeError:  # no session interface (bare request context)
            pass
    try:
        with _AUDIT_LOCK:
            fd = os.open(AUDIT_FILE, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
    except OSError as ex:
        log.error("audit write failed: %s", type(ex).__name__)


# ---------------------------------------------------------------------------
# Accounts + config writes
# ---------------------------------------------------------------------------


def effective_accounts() -> list:
    """All configured accounts (incl. paused) with merged values, cached
    per request. A broken config yields [] and config_error() says why."""
    if has_request_context() and "_accounts" in g:
        return g._accounts
    err = None
    try:
        accs = list(engine.load_account_configs(CONFIG_PATH))
    except FileNotFoundError:
        accs, err = [], "accounts.yml blev ikke fundet"
    except ValueError as ex:
        accs, err = [], str(ex)[:300]
    except Exception as ex:  # noqa: BLE001 - engine bug must not kill the UI
        log.error("load_account_configs failed: %s", type(ex).__name__)
        accs, err = [], "Konfigurationen kunne ikke indlæses"
    if has_request_context():
        g._accounts, g._config_error = accs, err
    return accs


def config_error() -> str | None:
    effective_accounts()
    return g.get("_config_error") if has_request_context() else None


def visible_accounts() -> list:
    """effective_accounts() filtered to the current user's scope."""
    return [a for a in effective_accounts() if can_access(a.name)]


# Friendly account names (2.1): optional per-account key `display_name` in
# accounts.yml. The engine ignores unknown keys (old versions too), so the
# value is read from the raw YAML here, cached on the file's mtime/size.
DISPLAY_NAME_MAX = 40
_DISPLAY_CACHE: dict[str, Any] = {"key": None, "names": {}}
_DISPLAY_LOCK = threading.Lock()


def clean_display_name(text: Any) -> str:
    """Normalised friendly name ('' = none). Raises ValueError (Danish)."""
    value = " ".join(str(text or "").split())
    if not value:
        return ""
    if len(value) > DISPLAY_NAME_MAX:
        raise ValueError(f"Navnet må højst være {DISPLAY_NAME_MAX} tegn.")
    if any(ord(c) < 32 or ord(c) == 127 or c in "<>" for c in value):
        raise ValueError("Navnet indeholder tegn, der ikke er tilladt.")
    return value


def account_display_names() -> dict[str, str]:
    """account name -> display_name (only accounts that have one)."""
    try:
        st = CONFIG_PATH.stat()
        key = (str(CONFIG_PATH), st.st_mtime_ns, st.st_size)
    except OSError:
        return {}
    with _DISPLAY_LOCK:
        if _DISPLAY_CACHE["key"] == key:
            return dict(_DISPLAY_CACHE["names"])
    names: dict[str, str] = {}
    try:
        raw = load_raw_config()
        for entry in raw.get("accounts") or []:
            if isinstance(entry, dict) and entry.get("name") and entry.get("display_name"):
                try:
                    label = clean_display_name(entry.get("display_name"))
                except ValueError:
                    label = ""
                if label:
                    names[str(entry["name"])] = label
    except (OSError, ValueError, yaml.YAMLError) as ex:
        log.debug("display names unavailable: %s", type(ex).__name__)
        return {}
    with _DISPLAY_LOCK:
        _DISPLAY_CACHE.update(key=key, names=dict(names))
    return names


def account_label(name: str) -> str:
    """Friendly name of an account for the UI (falls back to the id)."""
    if has_request_context():
        if "_labels" not in g:
            g._labels = account_display_names()
        return g._labels.get(name) or name
    return account_display_names().get(name) or name


def account_name_html(name: str, *, cls: str = "") -> str:
    """Friendly name with the technical id small (escaped)."""
    return kit.acct_name(account_label(name), name, cls=cls)


def account_by_name(name: str):
    return next((a for a in effective_accounts() if a.name == name), None)


_CONFIG_LOCK = threading.RLock()


def load_raw_config() -> dict:
    if not CONFIG_PATH.exists():
        return {"defaults": {}, "accounts": []}
    raw = yaml.safe_load(CONFIG_PATH.read_text()) or {}
    if not isinstance(raw, dict):
        raise ValueError("accounts.yml is not a mapping")
    raw.setdefault("accounts", [])
    if not isinstance(raw["accounts"], list):
        raise ValueError("accounts.yml: 'accounts' must be a list")
    return raw


def _atomic_write(path: Path, text: str) -> None:
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        _fsync_dir(path.parent)
    finally:
        tmp.unlink(missing_ok=True)


def _fsync_dir(directory: Path) -> None:
    try:
        dfd = os.open(directory, os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def save_config(mutator: Callable[[dict], Any], actor: str, action: str, *,
                account: str = "", detail: str = "") -> Any:
    """Load raw YAML, let `mutator(raw)` change it in place, validate with
    engine.load_account_configs on a temp file, atomically replace
    accounts.yml, store its hash (A6), request a reload and audit.

    Raises ValueError (message safe to show) if the mutator or validation
    rejects the change; nothing is written then. Returns the mutator's
    return value."""
    with _CONFIG_LOCK:
        raw = load_raw_config()
        try:
            result = mutator(raw)
        except ValueError as ex:
            audit(action, account, "rejected", detail=str(ex), actor=actor)
            raise
        text = yaml.safe_dump(raw, sort_keys=False, allow_unicode=True, default_flow_style=False)
        parent = CONFIG_PATH.parent
        fd, tmp_name = tempfile.mkstemp(prefix=".accounts-", suffix=".yml", dir=parent)
        tmp = Path(tmp_name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())
            try:
                engine.load_account_configs(tmp)
            except SystemExit as ex:  # 1.x engine raised SystemExit
                raise ValueError(str(ex)) from None
            except ValueError as ex:
                audit(action, account, "rejected", detail=str(ex), actor=actor)
                raise
            os.replace(tmp, CONFIG_PATH)
            _fsync_dir(parent)
        finally:
            tmp.unlink(missing_ok=True)
        settings_set("config_sha256", hashlib.sha256(text.encode()).hexdigest())
        request_reload()
        audit(action, account, "ok", detail=detail, actor=actor)
        if has_request_context():
            g.pop("_accounts", None)
        return result


def request_reload() -> None:
    """Ask the engine to reload accounts (it watches this flag file)."""
    try:
        RELOAD_FILE.touch()
    except OSError as ex:
        log.error("could not request reload: %s", type(ex).__name__)


def config_sha256() -> str | None:
    try:
        return hashlib.sha256(CONFIG_PATH.read_bytes()).hexdigest()
    except OSError:
        return None


def check_external_config_change() -> bool:
    """A6: audit `config_changed_externally` when accounts.yml changed
    since the UI last wrote/saw it. Returns True if a change was found."""
    current = config_sha256()
    stored = settings_get("config_sha256")
    changed = stored is not None and current is not None and current != stored
    if changed:
        audit("config_changed_externally", result="detected",
              detail=f"sha256={current[:16]}", actor="system")
    if current is not None and current != stored:
        settings_set("config_sha256", current)
    return changed


# ---------------------------------------------------------------------------
# Status helpers shared by layout, Oversigt and /api/status
# ---------------------------------------------------------------------------

STALE_AFTER = 35 * 60  # IDLE can legitimately sit ~25 min between loops


def _row_dict(row: sqlite3.Row | None) -> dict:
    return {k: row[k] for k in row.keys()} if row is not None else {}


def account_status_map() -> dict[str, dict]:
    """account -> account_status row (dict), plus derived 'state' that
    turns silent-but-supposedly-running accounts into 'stale'."""
    if has_request_context() and "_status" in g:
        return g._status
    rows = query("SELECT * FROM account_status", default=[])
    now = int(time.time())
    out: dict[str, dict] = {}
    for r in rows:
        d = _row_dict(r)
        state = d.get("state") or "unknown"
        last = max(int(d.get("last_loop_at") or 0), int(d.get("updated_at") or 0))
        if state in ("idle", "working") and last and now - last > STALE_AFTER:
            state = "stale"
        d["raw_state"] = d.get("state")
        d["state"] = state
        out[d["account"]] = d
    if has_request_context():
        g._status = out
    return out


def account_state(acc) -> str:
    """Display state for an account object (config wins for 'paused')."""
    if not getattr(acc, "enabled", True):
        return "paused"
    st = account_status_map().get(acc.name)
    return st["state"] if st else "starting"


def sidebar_accounts() -> list[dict]:
    if has_request_context() and "_sidebar" in g:
        return g._sidebar
    out = [{"name": a.name, "label": account_label(a.name), "user": getattr(a, "user", ""),
            "mode": getattr(a, "mode", ""), "state": account_state(a)} for a in visible_accounts()]
    if has_request_context():
        g._sidebar = out
    return out


SPAM_SEEN_KEY = "spam_seen:{}"


def spam_seen_at(name: str | None = None) -> int | None:
    """When the user last looked at Fanget spam (settings_kv spam_seen:<user>),
    None = never."""
    if name is None:
        name = (current_user() or {}).get("name") or ""
    if not name:
        return None
    if has_request_context() and g.get("_spam_seen_for") == name:
        return g.get("_spam_seen")
    try:
        raw = settings_get(SPAM_SEEN_KEY.format(name))
        value = int(raw) if raw not in (None, "") else None
    except (TypeError, ValueError, sqlite3.Error):
        value = None
    if has_request_context():
        g._spam_seen_for, g._spam_seen = name, value
    return value


def set_spam_seen(name: str, ts: int | None = None) -> int:
    value = int(ts if ts is not None else time.time())
    settings_set(SPAM_SEEN_KEY.format(name), str(value))
    if has_request_context():
        g._spam_seen_for, g._spam_seen = name, value
    return value


def nav_counts() -> dict[str, int]:
    """Small badges in the navigation: caught spam that is new since the
    user last looked at Fanget spam (the last 24 h before the first visit)."""
    if current_user() is None:
        return {}
    if has_request_context() and "_nav_counts" in g:
        return g._nav_counts
    sc, params = scope_sql()
    seen = spam_seen_at()
    since = max(int(time.time()) - 86400, 0) if seen is None else seen
    row = query(
        "SELECT COUNT(*) FROM messages WHERE our_action IN "
        "('moved_to_junk','pending_move','flagged','shadow_spam')"
        " AND COALESCE(user_verdict,'') != 'ham' AND current_folder != 'gone'"
        " AND COALESCE(scanned_at, first_seen) > ?" + sc,
        [since, *params], one=True)
    out = {"spam": int(row[0]) if row else 0}
    if has_request_context():
        g._nav_counts = out
    return out


# ---------------------------------------------------------------------------
# Routes: health, auth, static
# ---------------------------------------------------------------------------


@app.get("/healthz")
@public
def healthz():
    """Minimal liveness probe (no auth, no DB)."""
    return jsonify({"ok": True, "version": app_version()})


@app.get("/api/health")
@public
def api_health():
    """A8: monitor JSON. Only states - no addresses, no error texts.

    With the 2.1 engine this is engine.health_snapshot(): the same
    {ok, version, accounts} plus a per-account `details` map (circuit
    breaker, stale thread, login state) for host-monitor.sh. `details` is
    only served to direct (LAN / host) clients - never through the reverse
    proxy / tunnel, where only the A8 minimum goes out."""
    snap = None
    fn = getattr(engine, "health_snapshot", None)
    if callable(fn):
        try:
            conn = _connect()
            try:
                snap = fn(conn)
            finally:
                conn.close()
        except Exception as ex:  # noqa: BLE001 - older/broken engine: plain A8 below
            log.warning("health_snapshot failed: %s", type(ex).__name__)
            snap = None
    if isinstance(snap, dict) and isinstance(snap.get("accounts"), dict):
        out: dict[str, Any] = {"ok": bool(snap.get("ok")), "version": app_version(),
                               "accounts": {str(k): str(v) for k, v in snap["accounts"].items()}}
        if isinstance(snap.get("details"), dict) and not via_proxy():
            out["details"] = snap["details"]
        return jsonify(out)
    try:
        conn = _connect()
        try:
            rows = conn.execute("SELECT account, state FROM account_status ORDER BY account").fetchall()
        finally:
            conn.close()
        accounts = {str(r["account"]): str(r["state"]) for r in rows}
        ok = accounts.get("*") != "config_error"
    except sqlite3.Error:
        accounts, ok = {}, False
    return jsonify({"ok": ok, "version": app_version(), "accounts": accounts})


@app.get("/favicon.png")
@app.get("/favicon.ico")
@public
def favicon():
    return send_file(FAVICON_PATH, mimetype="image/png", max_age=31536000)


def _throttle_begin(keys: list[str]) -> int:
    """Count this attempt BEFORE verifying (parallel guesses cannot slip
    through). Returns seconds to wait if locked, else 0."""
    now = int(time.time())
    _ensure_ui_db()
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        wait = 0
        rows = {}
        for k in keys:
            r = conn.execute("SELECT failures, first_at, locked_until FROM login_attempts WHERE key=?",
                             (k,)).fetchone()
            rows[k] = r
            if r and r["locked_until"] and r["locked_until"] > now:
                wait = max(wait, int(r["locked_until"]) - now)
        if wait:
            conn.execute("COMMIT")
            return wait
        for k in keys:
            r = rows[k]
            if r is None or int(r["first_at"] or 0) < now - LOGIN_WINDOW:
                failures, first_at = 1, now
            else:
                failures, first_at = int(r["failures"]) + 1, int(r["first_at"])
            locked = now + LOGIN_WINDOW if failures >= login_limit(k) else None
            conn.execute("INSERT INTO login_attempts(key, failures, first_at, locked_until) VALUES(?,?,?,?) "
                         "ON CONFLICT(key) DO UPDATE SET failures=excluded.failures, "
                         "first_at=excluded.first_at, locked_until=excluded.locked_until",
                         (k, failures, first_at, locked))
        conn.execute("COMMIT")
        return 0
    except sqlite3.Error:
        conn.rollback()
        raise
    finally:
        conn.close()


def _throttle_reset(keys: list[str]) -> None:
    conn = _connect()
    try:
        conn.executemany("DELETE FROM login_attempts WHERE key=?", [(k,) for k in keys])
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# API keys for programs (2.11.0, shared plan "Adgang for programmer")
#
# Several named keys, one per program (Home Assistant, Kontrolrum, a
# script), each with its own right (scope), shown ONCE when it is made and
# stored only as sha256 + the last 4 characters (table ui_api_keys). Format
# `sf_` + 43 characters (32 random bytes, base64url). A key is sent as
# `Authorization: Bearer <key>` - never in the URL. Scopes: read = GET
# /api/v1/ha; control and admin are reserved (no endpoint needs them yet).
# "Kun fra hjemmenetværket" (lan_only, the default) refuses every call that
# does not come straight from the home network (request_is_local: never
# through the tunnel/proxy). Unknown, expired, outside-the-LAN or
# wrong-scope keys get the same 404 as an unknown URL (wrong scope: 403);
# failed attempts are throttled per IP in login_attempts (key 'ha:<ip>', as
# in 2.3.6, so `sfctl unlock --ip` still clears it); a valid key may make 60
# reading / 10 controlling calls a minute (429 + Retry-After above that).
# Logs and audit name the key (name + id), never the key itself.
#
# Migration from the single Home Assistant token (2.3.6-2.10, settings_kv
# 'ha_token' = {sha256, created_at, created_by}): on the first start its
# hash is moved unchanged into ui_api_keys as "Home Assistant" (read,
# lan_only, migrated=1), so the old `sfha_` key keeps working; last use is
# copied. The old settings_kv keys are left for one version (rollback to
# 2.10 keeps the old key working); deleting the moved key also deletes
# them, so a rollback cannot bring a deleted key back. settings_kv
# 'api_keys_migrated' makes the move run once.
# ---------------------------------------------------------------------------

API_KEY_PREFIX = "sf_"
API_KEY_MAX_LEN = 200
API_KEY_NAME_MAX = 60
API_KEY_MAX_COUNT = 50
API_KEY_SCOPES = ("read", "control", "admin")
API_KEY_SCOPE_LABEL = {"read": "Kun læse", "control": "Læse og styre", "admin": "Administrator"}
API_KEY_EXPIRY_MAX_DAYS = 3650
# calls per key per API_KEY_RATE_WINDOW; 2.12 (#26): calls that need the
# admin scope have their own, low limit.
API_KEY_RATE = {"read": 60, "control": 10, "admin": 5}
API_KEY_RATE_WINDOW = 60
API_KEY_UNUSED_DAYS = 90
API_KEYS_MIGRATED_KEY = "api_keys_migrated"
API_KEY_REJECT_TEXT = {
    "unknown": "ukendt nøgle",
    "expired": "nøglen er udløbet",
    "outside": "kald udefra med en nøgle, der kun må bruges hjemme",
    "scope": "nøglen har ikke rettighed til det",
}
HA_KEY_NAME = "Home Assistant"
# Legacy single token (2.3.6-2.10). HA_TOKEN_REJECTED_KEY is still the
# "Sidst afvist" note under the list (now {at, ip, reason}).
HA_TOKEN_KEY = "ha_token"                  # JSON {sha256, created_at, created_by}
HA_TOKEN_USED_KEY = "ha_token_used"        # JSON {at, ip}
HA_TOKEN_REJECTED_KEY = "ha_token_rejected"  # JSON {at, ip, reason}
HA_TOKEN_PREFIX = "sfha_"
HA_TOKEN_MAX_LEN = API_KEY_MAX_LEN
HA_USE_WRITE_EVERY = 60                    # seconds between last-use writes (same key, same IP)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_API_LOCK = threading.Lock()
_API_RATE: dict[tuple[str, str], list[float]] = {}  # (sha256, kind) -> call times
_API_USES_PENDING: dict[str, int] = {}  # sha256 -> uses not yet written


def api_key_hash(token: str) -> str:
    return hashlib.sha256(str(token).encode("utf-8")).hexdigest()


ha_token_hash = api_key_hash


def _kv_json(key: str) -> dict | None:
    try:
        raw = settings_get(key)
    except sqlite3.Error:
        return None
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _kv_put(key: str, value: dict | None) -> None:
    """Write (or delete with None) one settings_kv key - also from sfctl
    and from the key-only API request (no session, no preview)."""
    _ensure_ui_db()
    conn = _connect()
    try:
        if value is None:
            conn.execute("DELETE FROM settings_kv WHERE key=?", (key,))
        else:
            conn.execute("INSERT INTO settings_kv(key,value) VALUES(?,?) "
                         "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json.dumps(value)))
        conn.commit()
    finally:
        conn.close()


def _kv_conn_json(conn: sqlite3.Connection, key: str) -> dict:
    row = conn.execute("SELECT value FROM settings_kv WHERE key=?", (key,)).fetchone()
    try:
        data = json.loads(row[0]) if row and row[0] else {}
    except (TypeError, ValueError):
        data = {}
    return data if isinstance(data, dict) else {}


def _migrate_ha_token(conn: sqlite3.Connection) -> bool:
    """Move the 2.3.6-2.10 Home Assistant token into ui_api_keys (once).
    Runs inside init_ui_db on its connection; the caller commits. True when
    a key was moved."""
    if conn.execute("SELECT 1 FROM settings_kv WHERE key=?", (API_KEYS_MIGRATED_KEY,)).fetchone():
        return False
    now = int(time.time())
    tok = _kv_conn_json(conn, HA_TOKEN_KEY)
    sha = str(tok.get("sha256") or "").lower()
    moved = False
    if _SHA256_RE.match(sha) and not conn.execute("SELECT 1 FROM ui_api_keys LIMIT 1").fetchone():
        used = _kv_conn_json(conn, HA_TOKEN_USED_KEY)
        conn.execute(
            "INSERT INTO ui_api_keys(name, scope, sha256, prefix, hint, created_at, created_by, last_used_at, "
            "last_used_ip, uses, lan_only, expires_at, migrated) VALUES(?,?,?,?,?,?,?,?,?,0,1,NULL,1)",
            (HA_KEY_NAME, "read", sha, HA_TOKEN_PREFIX, "", int(tok.get("created_at") or 0) or now,
             str(tok.get("created_by") or "")[:80], int(used.get("at") or 0) or None,
             str(used.get("ip") or "")[:64] or None))
        moved = True
    conn.execute("INSERT INTO settings_kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                 (API_KEYS_MIGRATED_KEY, json.dumps({"at": now, "moved": moved})))
    return moved


def api_keys_migrate() -> bool:
    """Run the one-time move now (init_ui_db does it on start; sfctl and
    tests may call it). True when a key was moved."""
    _ensure_ui_db()
    conn = _connect()
    try:
        moved = _migrate_ha_token(conn)
        conn.commit()
    finally:
        conn.close()
    if moved:
        log.info("api keys: the Home Assistant token was moved to the key list as %r", HA_KEY_NAME)
        audit("api_keys_migrated", detail=f"{HA_KEY_NAME} (sfha_-nøglen virker videre)", actor="system")
    return moved


def _api_key_public(r: Any) -> dict[str, Any]:
    """A ui_api_keys row for the UI/sfctl - never the hash."""
    now = int(time.time())
    created = int(r["created_at"] or 0)
    last = int(r["last_used_at"] or 0) or None
    expires = int(r["expires_at"] or 0) or None
    scope = str(r["scope"])
    return {"id": int(r["id"]), "name": str(r["name"]), "scope": scope,
            "scope_label": API_KEY_SCOPE_LABEL.get(scope, scope), "prefix": str(r["prefix"]),
            "hint": str(r["hint"] or ""), "created_at": created, "created_by": str(r["created_by"] or ""),
            "last_used_at": last, "last_used_ip": str(r["last_used_ip"] or ""), "uses": int(r["uses"] or 0),
            "lan_only": bool(r["lan_only"]), "expires_at": expires, "expired": bool(expires and expires <= now),
            "migrated": bool(r["migrated"]),
            "unused": now - (last or created) > API_KEY_UNUSED_DAYS * 86400}


def api_key_label(key: dict) -> str:
    """'sf_…Qe7n' (a moved key without a known hint: 'sfha_…')."""
    return f"{key.get('prefix') or API_KEY_PREFIX}…{key.get('hint') or ''}"


def api_keys_list() -> list[dict[str, Any]]:
    _ensure_ui_db()
    conn = _connect()
    try:
        rows = conn.execute("SELECT * FROM ui_api_keys ORDER BY id").fetchall()
    finally:
        conn.close()
    return [_api_key_public(r) for r in rows]


def api_key_get(key_id: Any) -> dict[str, Any] | None:
    try:
        kid = int(key_id)
    except (TypeError, ValueError):
        return None
    _ensure_ui_db()
    conn = _connect()
    try:
        row = conn.execute("SELECT * FROM ui_api_keys WHERE id=?", (kid,)).fetchone()
    finally:
        conn.close()
    return _api_key_public(row) if row else None


def clean_api_key_name(name: Any) -> str:
    """Strip and collapse whitespace; ValueError (Danish text) when empty,
    too long or with control characters."""
    text = re.sub(r"\s+", " ", str(name or "")).strip()
    if not text:
        raise ValueError("Giv nøglen et navn, fx navnet på programmet.")
    if len(text) > API_KEY_NAME_MAX:
        raise ValueError(f"Navnet må højst være {API_KEY_NAME_MAX} tegn.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        raise ValueError("Navnet indeholder ugyldige tegn.")
    return text


def api_key_create(name: Any, scope: str, actor: str, *, lan_only: bool = True,
                   expires_days: int = 0) -> tuple[str, dict[str, Any]]:
    """Make a new key and return (key, its public row) - the ONLY time the
    key exists in clear text. ValueError (Danish text) on bad input."""
    clean = clean_api_key_name(name)
    if scope not in API_KEY_SCOPES:
        raise ValueError("Vælg en rettighed.")
    if scope == "admin" and not lan_only:
        # 2.12 (#26): an administrator key never works from outside.
        raise ValueError("En nøgle med rettigheden Administrator kan kun bruges fra hjemmenetværket.")
    try:
        days = int(expires_days or 0)
    except (TypeError, ValueError):
        raise ValueError("Ugyldig udløbstid.") from None
    if days < 0 or days > API_KEY_EXPIRY_MAX_DAYS:
        raise ValueError("Ugyldig udløbstid.")
    now = int(time.time())
    token = API_KEY_PREFIX + secrets.token_urlsafe(32)
    _ensure_ui_db()
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        if conn.execute("SELECT COUNT(*) FROM ui_api_keys").fetchone()[0] >= API_KEY_MAX_COUNT:
            conn.rollback()
            raise ValueError(f"Der kan højst være {API_KEY_MAX_COUNT} nøgler. Slet en, du ikke bruger.")
        if conn.execute("SELECT 1 FROM ui_api_keys WHERE lower(name)=lower(?)", (clean,)).fetchone():
            conn.rollback()
            raise ValueError("Der er allerede en nøgle med det navn. Vælg et andet navn.")
        cur = conn.execute(
            "INSERT INTO ui_api_keys(name, scope, sha256, prefix, hint, created_at, created_by, uses, lan_only, "
            "expires_at, migrated) VALUES(?,?,?,?,?,?,?,0,?,?,0)",
            (clean, scope, api_key_hash(token), API_KEY_PREFIX, token[-4:], now, str(actor or "")[:80],
             1 if lan_only else 0, now + days * 86400 if days else None))
        conn.commit()
        kid = int(cur.lastrowid)
    finally:
        conn.close()
    key = api_key_get(kid)
    assert key is not None
    return token, key


def api_key_delete(key_id: Any) -> dict[str, Any] | None:
    """Delete one key (the others keep working). Returns the deleted key,
    or None when there was none. Deleting the moved Home Assistant key also
    deletes the 2.10 token, so a rollback cannot bring it back."""
    key = api_key_get(key_id)
    if key is None:
        return None
    conn = _connect()
    try:
        conn.execute("DELETE FROM ui_api_keys WHERE id=?", (key["id"],))
        if key["migrated"]:
            conn.execute("DELETE FROM settings_kv WHERE key IN (?,?)", (HA_TOKEN_KEY, HA_TOKEN_USED_KEY))
        conn.commit()
    finally:
        conn.close()
    return key


def api_key_rejected() -> dict[str, Any]:
    """The last refused call {at, ip, reason, reason_text} (or {})."""
    rej = _kv_json(HA_TOKEN_REJECTED_KEY) or {}
    if not rej.get("at"):
        return {}
    reason = str(rej.get("reason") or "unknown")
    return {"at": int(rej.get("at") or 0), "ip": str(rej.get("ip") or ""), "reason": reason,
            "reason_text": API_KEY_REJECT_TEXT.get(reason, API_KEY_REJECT_TEXT["unknown"])}


# ---- `sfctl ha-token` and the 2.3.6 helpers: now the key named "Home Assistant"

def _ha_keys() -> list[dict[str, Any]]:
    return [k for k in api_keys_list() if k["name"].lower() == HA_KEY_NAME.lower()]


def ha_token_create(actor: str) -> str:
    """A new read-only, home-network key named "Home Assistant" (replaces
    any key with that name) - returned the only time it exists."""
    for k in _ha_keys():
        api_key_delete(k["id"])
    token, _key = api_key_create(HA_KEY_NAME, "read", actor)
    return token


def ha_token_revoke(actor: str = "") -> bool:
    """Delete the key(s) named "Home Assistant". True when there was one."""
    keys = _ha_keys()
    for k in keys:
        api_key_delete(k["id"])
    return bool(keys)


def ha_token_status() -> dict[str, Any]:
    """{exists, created_at, created_by, last_used_at, last_used_ip,
    rejected_at, rejected_ip} for the "Home Assistant" key - never the key
    or its hash."""
    keys = _ha_keys()
    k = keys[0] if keys else None
    rej = api_key_rejected()
    return {"exists": k is not None,
            "created_at": k["created_at"] if k else None,
            "created_by": k["created_by"] if k else "",
            "last_used_at": k["last_used_at"] if k else None,
            "last_used_ip": k["last_used_ip"] if k else "",
            "rejected_at": rej.get("at") or None,
            "rejected_ip": rej.get("ip", "")}


def _api_key_lookup(presented: str) -> Any:
    """The ui_api_keys row for a presented key, or None (same work either
    way)."""
    if not presented or len(presented) > API_KEY_MAX_LEN:
        hmac.compare_digest(api_key_hash(presented or "-"), "0" * 64)
        return None
    digest = api_key_hash(presented)
    _ensure_ui_db()
    conn = _connect()
    try:
        row = conn.execute("SELECT * FROM ui_api_keys WHERE sha256=?", (digest,)).fetchone()
    finally:
        conn.close()
    if row is None:
        hmac.compare_digest(digest, "0" * 64)
        return None
    return row if hmac.compare_digest(str(row["sha256"]), digest) else None


def ha_token_matches(presented: str) -> bool:
    """Is this a stored key (any name, any scope)?"""
    return _api_key_lookup(presented) is not None


def _bearer() -> str:
    auth = request.headers.get("Authorization", "")
    scheme, _sp, value = auth.strip().partition(" ")
    if scheme.lower() != "bearer":
        return ""
    return value.strip()[: API_KEY_MAX_LEN + 1]


def _api_keys_remote_allowed() -> bool:
    """Is there a key that may be used from outside the home network?"""
    _ensure_ui_db()
    conn = _connect()
    try:
        return conn.execute("SELECT 1 FROM ui_api_keys WHERE lan_only=0 AND scope!='admin' LIMIT 1").fetchone() is not None
    finally:
        conn.close()


def _scope_covers(have: str, need: str) -> bool:
    try:
        return API_KEY_SCOPES.index(have) >= API_KEY_SCOPES.index(need)
    except ValueError:
        return False


def _api_rate_wait(key_sha: str, kind: str) -> int:
    """Count one call; seconds to wait when the key is over its limit
    (keyed by the hash: ids are reused in a fresh database)."""
    limit = API_KEY_RATE.get(kind, API_KEY_RATE["control"])
    now = time.monotonic()
    with _API_LOCK:
        calls = [t for t in _API_RATE.get((key_sha, kind), []) if now - t < API_KEY_RATE_WINDOW]
        if len(calls) >= limit:
            _API_RATE[(key_sha, kind)] = calls
            return max(1, int(API_KEY_RATE_WINDOW - (now - calls[0])) + 1)
        calls.append(now)
        _API_RATE[(key_sha, kind)] = calls
    return 0


def _api_key_note_use(row: Any, ip: str) -> None:
    """Last use + count, written at most once a minute per key and IP."""
    now = int(time.time())
    kid, sha = int(row["id"]), str(row["sha256"])
    with _API_LOCK:
        _API_USES_PENDING[sha] = _API_USES_PENDING.get(sha, 0) + 1
        if (str(row["last_used_ip"] or "") == ip
                and now - int(row["last_used_at"] or 0) < HA_USE_WRITE_EVERY):
            return
        n = _API_USES_PENDING.pop(sha, 0)
    try:
        conn = _connect()
        try:
            conn.execute("UPDATE ui_api_keys SET last_used_at=?, last_used_ip=?, uses=uses+? WHERE id=?",
                         (now, ip[:64], n, kid))
            conn.commit()
        finally:
            conn.close()
    except sqlite3.Error as ex:
        log.warning("api key use note failed: %s", type(ex).__name__)


def _api_key_note_reject(ip: str, reason: str, row: Any, presented: str) -> None:
    """Remember the last refusal (at most once a minute per IP) and audit
    it - with the key's name when known, never the key."""
    now = int(time.time())
    old = _kv_json(HA_TOKEN_REJECTED_KEY) or {}
    if old.get("ip") == ip and now - int(old.get("at") or 0) < HA_USE_WRITE_EVERY:
        return
    try:
        _kv_put(HA_TOKEN_REJECTED_KEY, {"at": now, "ip": ip[:64], "reason": reason})
    except sqlite3.Error as ex:
        log.warning("api key reject note failed: %s", type(ex).__name__)
    who = f"{row['name']} (#{row['id']})" if row is not None else f"…{presented[-4:]}" if len(presented) > 12 else "-"
    log.info("api key refused from %s: %s (%s)", ip, reason, who)
    audit("api_key_rejected", result="refused", detail=f"{API_KEY_REJECT_TEXT.get(reason, reason)}: {who}",
          actor="")


def api_key_for_request(need: str = "read") -> dict[str, Any] | None:
    """The key of THIS request when it may use an endpoint that needs
    `need`, else None (g._api_status: 404, 403 for a valid key without the
    right, 429 over the rate limit with g._api_retry seconds). Cached per
    request (the before-hook and the route guard both ask)."""
    if not has_request_context():
        return None
    if "_api_auth" in g:
        return g._api_auth
    g._api_auth = None
    g._api_status = 404
    local = request_is_local()
    try:
        # Nothing to find from outside unless a key allows it: the same
        # 404 as 2.10, without even touching the throttle table.
        if not local and not _api_keys_remote_allowed():
            return None
        ip = (request.remote_addr if not local else request_peer()) or "unknown"
        throttle = f"ha:{ip}"
        # Count BEFORE verifying (parallel guesses cannot slip through);
        # a valid key resets it, like a login.
        if _throttle_begin([throttle]):
            return None
        presented = _bearer()
        row = _api_key_lookup(presented)
        reason = ""
        if row is None:
            reason = "unknown"
        elif row["expires_at"] and int(row["expires_at"]) <= int(time.time()):
            reason = "expired"
        elif (row["lan_only"] or str(row["scope"]) == "admin") and not local:
            reason = "outside"   # 2.12 (#26): admin keys are LAN-only, also one made before
        if reason:
            if presented:
                _api_key_note_reject(ip, reason, row, presented)
            return None
        _throttle_reset([throttle])
        if not _scope_covers(str(row["scope"]), need):
            _api_key_note_reject(ip, "scope", row, presented)
            g._api_status = 403
            return None
        kind = "admin" if need == "admin" else "read" if request.method in ("GET", "HEAD") else "control"
        wait = _api_rate_wait(str(row["sha256"]), kind)
        if wait:
            g._api_status, g._api_retry = 429, wait
            log.info("api key %s (#%s) over its rate limit", row["name"], row["id"])
            return None
        _api_key_note_use(row, ip)
    except sqlite3.Error as ex:
        log.warning("api key check failed: %s", type(ex).__name__)
        return None
    key = _api_key_public(row)
    g._api_auth = key
    log.debug("api key %s (#%s) from %s", key["name"], key["id"], ip)
    return key


def ha_request_allowed() -> bool:
    """POLICY_HA (2.3.6 name): a key with at least `read`."""
    return api_key_for_request("read") is not None


# ---------------------------------------------------------------------------
# Kontrolrum single sign-on (2.9.0, owner request "option A")
#
# Kontrolrum (the household dashboard) shows the Spamfilter embedded and
# holds its session on the server. Instead of storing the password of the
# 'kontrolrum' user it signs a short-lived assertion ("log in as X") with a
# shared key - the same handshake as FleetDeck's POST /api/auth/kontrolrum:
#
#   sig = hex(HMAC-SHA256(key, "kontrolrum-sso\n{v}\n{aud}\n{sub}\n{iat}\n{exp}\n{nonce}"))
#
# where the key is the shown hex text as UTF-8. POST /login/kontrolrum is
# accepted ONLY when the direct TCP peer is one of the configured Kontrolrum
# IPs (exact addresses, no default, never a TRUSTED_PROXIES peer such as
# cloudflared) and the request carries no forwarding headers; then aud,
# times (max 120 s lifetime, 60 s clock skew), the one-time nonce (stored
# in ui_sso_nonces until it can no longer validate) and the signature
# (constant time) are checked, and the user must have the checkbox "Må
# logges ind fra Kontrolrum" (ui_kontrolrum_sso, absent row = off).
#
# The session gets session['kr'] = {'p': peer, 'k': key fingerprint}. It
# counts as allowed for a "Kun lokalt" user ONLY while each request comes
# from that same Kontrolrum peer, the key is unchanged, the IP is still
# configured and the user still has the checkbox - otherwise the session is
# cleared (current_user). A password login is never affected: the password
# of a "Kun lokalt" user still only works from the home network.
#
# The key is stored AES-GCM encrypted (settings_kv 'kontrolrum_sso') under a
# key derived from the session secret in STATE_DIR/dashboard_secret, so the
# database alone does not reveal it; it is shown once when it is made. Older
# versions ignore the new keys and tables (a rollback simply has no SSO).
# ---------------------------------------------------------------------------

KR_SSO_KEY = "kontrolrum_sso"                    # JSON {enc, fp, created_at, created_by}
KR_SSO_PEERS_KEY = "kontrolrum_sso_peers"        # JSON {ips, updated_at, updated_by}
KR_SSO_USED_KEY = "kontrolrum_sso_used"          # JSON {at, ip, user}
KR_SSO_REJECTED_KEY = "kontrolrum_sso_rejected"  # JSON {at, ip, reason}
KR_SSO_CONTEXT = "kontrolrum-sso"
KR_SSO_AUDIENCE = "spamfilter"
KR_SSO_VERSION = 1
KR_SSO_MAX_LIFETIME = 120
KR_SSO_SKEW = 60
KR_SSO_RATE = 10                    # requests per peer ...
KR_SSO_RATE_WINDOW = 5 * 60         # ... per this window (all outcomes)
KR_SSO_MAX_PEERS = 8
KR_SSO_DEVICE_LABEL = "Kontrolrum"
KR_SSO_REASON_TEXT = {
    "wrong_peer": "ikke fra Kontrolrums adresse", "proxied": "kom gennem en proxy", "rate_limited": "for mange forsøg",
    "sso_disabled": "SSO er slået fra", "bad_request": "ugyldig forespørgsel", "bad_signature": "forkert signatur",
    "bad_version": "ukendt version", "bad_audience": "forkert modtager", "expired": "udløbet",
    "replay": "brugt før", "unknown_user": "brugeren må ikke logges ind fra Kontrolrum",
    "key_changed": "nøglen er skiftet", "peer_changed": "ikke fra Kontrolrums adresse",
    "not_allowed": "brugeren må ikke logges ind fra Kontrolrum",
}
_KR_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,48}$")
_KR_SIG_RE = re.compile(r"^[0-9A-Fa-f]{64}$")


def _kr_aes(key_material: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415 - only for this feature

    return AESGCM(hmac.new(key_material, b"spamfilter kontrolrum-sso key v1", hashlib.sha256).digest())


def _kr_session_secret() -> bytes:
    return str(app.secret_key or "").encode("utf-8")


def kr_sso_fingerprint(key: str) -> str:
    """Short id of a key (shown, and bound into SSO sessions) - never the key."""
    return hashlib.sha256(str(key).encode("utf-8")).hexdigest()[:8]


def kr_sso_create(actor: str) -> str:
    """Make a new key (replaces any old one: its sessions end) and return
    it - the ONLY time it exists in clear text."""
    key = secrets.token_hex(32)
    nonce = secrets.token_bytes(12)
    enc = _kr_aes(_kr_session_secret()).encrypt(nonce, key.encode("utf-8"), KR_SSO_CONTEXT.encode())
    _kv_put(KR_SSO_KEY, {"enc": base64.b64encode(nonce + enc).decode("ascii"), "fp": kr_sso_fingerprint(key),
                         "created_at": int(time.time()), "created_by": str(actor or "")[:80]})
    _kv_put(KR_SSO_USED_KEY, None)
    _kv_put(KR_SSO_REJECTED_KEY, None)
    return key


def kr_sso_disable(actor: str = "") -> bool:
    """'Slå fra': delete the key (every SSO session ends). True when there was one."""
    had = _kv_json(KR_SSO_KEY) is not None
    _kv_put(KR_SSO_KEY, None)
    _kv_put(KR_SSO_USED_KEY, None)
    return had


def kr_sso_key() -> str | None:
    """The key in clear text, or None (off, or unreadable - e.g. a restore
    without dashboard_secret)."""
    data = _kv_json(KR_SSO_KEY)
    if not data or not data.get("enc"):
        return None
    try:
        raw = base64.b64decode(str(data["enc"]), validate=True)
        key = _kr_aes(_kr_session_secret()).decrypt(raw[:12], raw[12:], KR_SSO_CONTEXT.encode()).decode("utf-8")
    except Exception:  # noqa: BLE001 - wrong secret, damaged value: SSO is simply off
        return None
    return key if re.fullmatch(r"[0-9a-f]{64}", key) else None


def _kr_norm_ip(text: str | None) -> str | None:
    ip = _parse_ip(text)
    return str(ip) if ip is not None else None


def parse_kr_peers(text: str | None) -> tuple[list[str], list[str]]:
    """'192.168.1.28, 172.31.250.2' -> (exact addresses, invalid entries).
    Networks ('/24') are refused on purpose: one address per Kontrolrum."""
    ok: list[str] = []
    bad: list[str] = []
    for tok in re.split(r"[\s,;]+", text or ""):
        if not tok:
            continue
        ip = None if "/" in tok else _kr_norm_ip(tok)
        if ip is None:
            bad.append(tok[:60])
        elif ip not in ok:
            ok.append(ip)
    return ok, bad


def kr_sso_peers_configured() -> list[str]:
    data = _kv_json(KR_SSO_PEERS_KEY) or {}
    ips = data.get("ips") if isinstance(data.get("ips"), list) else []
    return [p for p in (_kr_norm_ip(str(x)) for x in ips[:KR_SSO_MAX_PEERS]) if p]


def kr_sso_peers() -> list[str]:
    """The Kontrolrum addresses that count: configured AND not a trusted
    proxy (a request from cloudflared can be anybody on the internet)."""
    return [p for p in kr_sso_peers_configured() if not is_trusted_proxy(p)]


def set_kr_sso_peers(ips: list[str], actor: str = "") -> None:
    if ips:
        _kv_put(KR_SSO_PEERS_KEY, {"ips": list(ips)[:KR_SSO_MAX_PEERS], "updated_at": int(time.time()),
                                   "updated_by": str(actor or "")[:80]})
    else:
        _kv_put(KR_SSO_PEERS_KEY, None)


def kr_peer_allowed(peer: str | None) -> bool:
    ip = _kr_norm_ip(peer)
    return ip is not None and ip in kr_sso_peers()


def _kr_proxied() -> bool:
    """Any forwarding header (or a trusted-proxy peer): not Kontrolrum's own
    server-to-server call. A browser request proxied through Kontrolrum
    from the tunnel carries CF-Ray & co. and is refused here."""
    env = request.environ
    return bool(any(env.get(k) for k in _PROXY_MARKERS) or env.get("sf.cf_user")
                or env.get("sf.ignored_proxy_headers") or env.get("sf.proxied"))


def kr_sso_allowed(name: str) -> bool:
    """The user's checkbox "Må logges ind fra Kontrolrum" (default off;
    an unreadable table counts as off)."""
    try:
        _ensure_ui_db()
        conn = _connect()
        try:
            row = conn.execute("SELECT 1 FROM ui_kontrolrum_sso WHERE name=?", (name,)).fetchone()
        finally:
            conn.close()
    except sqlite3.Error as ex:
        log.warning("ui_kontrolrum_sso unavailable: %s", type(ex).__name__)
        return False
    return row is not None


def all_kr_sso_allowed() -> set[str]:
    try:
        _ensure_ui_db()
        conn = _connect()
        try:
            return {str(r["name"]) for r in conn.execute("SELECT name FROM ui_kontrolrum_sso").fetchall()}
        finally:
            conn.close()
    except sqlite3.Error:
        return set()


def set_kr_sso_allowed(name: str, allowed: bool, actor: str = "") -> bool:
    """Tick/untick the checkbox. True when it changed (unticking ends the
    user's SSO sessions on their next request)."""
    old = kr_sso_allowed(name)
    _ensure_ui_db()
    conn = _connect()
    try:
        if allowed:
            conn.execute("INSERT INTO ui_kontrolrum_sso(name, updated_at, updated_by) VALUES(?,?,?) "
                         "ON CONFLICT(name) DO UPDATE SET updated_at=excluded.updated_at, "
                         "updated_by=excluded.updated_by", (name, int(time.time()), str(actor or "")[:80]))
        else:
            conn.execute("DELETE FROM ui_kontrolrum_sso WHERE name=?", (name,))
        conn.commit()
    finally:
        conn.close()
    return old != allowed


def kr_sso_status() -> dict[str, Any]:
    """Everything the Indstillinger card shows - never the key."""
    data = _kv_json(KR_SSO_KEY)
    used = _kv_json(KR_SSO_USED_KEY) or {}
    rej = _kv_json(KR_SSO_REJECTED_KEY) or {}
    exists = bool(data and data.get("enc"))
    configured = kr_sso_peers_configured()
    return {"exists": exists, "readable": exists and kr_sso_key() is not None,
            "fingerprint": str(data.get("fp") or "") if exists else "",
            "created_at": int(data.get("created_at") or 0) or None if exists else None,
            "created_by": str(data.get("created_by") or "") if exists else "",
            "peers": configured, "proxy_peers": [p for p in configured if is_trusted_proxy(p)],
            "users": sorted(all_kr_sso_allowed()),
            "last_used_at": int(used.get("at") or 0) or None if exists else None,
            "last_used_ip": str(used.get("ip") or "") if exists else "",
            "last_used_user": str(used.get("user") or "") if exists else "",
            "rejected_at": int(rej.get("at") or 0) or None, "rejected_ip": str(rej.get("ip") or ""),
            "rejected_reason": str(rej.get("reason") or "")}


def kr_sso_text(a: dict) -> str:
    return "\n".join([KR_SSO_CONTEXT, str(a.get("v")), str(a.get("aud")), str(a.get("sub")), str(a.get("iat")),
                      str(a.get("exp")), str(a.get("nonce"))])


def kr_sso_sign(key: str, a: dict) -> str:
    return hmac.new(str(key).encode("utf-8"), kr_sso_text(a).encode("utf-8"), hashlib.sha256).hexdigest()


def _kr_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


# 2.12 (#10): Kontrolrum 1.104.0 names the real person (the app user the
# admin linked to that Kontrolrum user, up to 128 characters there). A name
# longer than any user here is no user: "unknown_user", not "bad_request",
# so Kontrolrum can tell the admin which link to fix.
KR_SSO_SUB_MAX = 128


def kr_sso_well_formed(a: Any) -> bool:
    return (isinstance(a, dict) and _kr_int(a.get("v")) and isinstance(a.get("aud"), str)
            and isinstance(a.get("sub"), str) and 0 < len(a["sub"]) <= KR_SSO_SUB_MAX and "\n" not in a["sub"]
            and _kr_int(a.get("iat")) and _kr_int(a.get("exp"))
            and isinstance(a.get("nonce"), str) and bool(_KR_NONCE_RE.fullmatch(a["nonce"]))
            and isinstance(a.get("sig"), str) and bool(_KR_SIG_RE.fullmatch(a["sig"])))


def kr_sso_signature_valid(key: str, a: dict) -> bool:
    want = bytes.fromhex(kr_sso_sign(key, a))
    return hmac.compare_digest(want, bytes.fromhex(str(a.get("sig") or "")))


def kr_sso_check_claims(a: dict, now: int | None = None) -> str | None:
    """Version, audience and time. None = fine, else the error code."""
    if a["v"] != KR_SSO_VERSION:
        return "bad_version"
    if a["aud"] != KR_SSO_AUDIENCE:
        return "bad_audience"
    now = int(time.time()) if now is None else now
    iat, exp = int(a["iat"]), int(a["exp"])
    if exp < iat or exp - iat > KR_SSO_MAX_LIFETIME or iat > now + KR_SSO_SKEW or exp + KR_SSO_SKEW < now:
        return "expired"
    return None


def kr_sso_take_nonce(nonce: str, exp: int) -> bool:
    """Use the one-time value. False = seen before (replay). Kept until the
    assertion could no longer validate anyway (survives a restart)."""
    now = int(time.time())
    _ensure_ui_db()
    conn = _connect()
    try:
        conn.execute("DELETE FROM ui_sso_nonces WHERE until<?", (now,))
        cur = conn.execute("INSERT OR IGNORE INTO ui_sso_nonces(nonce, until) VALUES(?,?)",
                           (nonce, max(int(exp), now) + KR_SSO_SKEW + 1))
        conn.commit()
        return cur.rowcount == 1
    finally:
        conn.close()


def kr_session_problem(name: str, kr: Any) -> str:
    """'' when this request may use the SSO session `kr`, else the reason.
    Checked on EVERY request of such a session."""
    if not has_request_context() or not isinstance(kr, dict):
        return "bad_request"
    if _kr_norm_ip(request_peer()) != str(kr.get("p") or "") or not kr_peer_allowed(request_peer()):
        return "peer_changed"
    key = kr_sso_key()
    if key is None:
        return "sso_disabled"
    if not hmac.compare_digest(kr_sso_fingerprint(key), str(kr.get("k") or "")):
        return "key_changed"
    if not kr_sso_allowed(name):
        return "not_allowed"
    return ""


def _kr_note_rejected(reason: str) -> None:
    ip = request_peer()[:64]
    old = _kv_json(KR_SSO_REJECTED_KEY) or {}
    if old.get("ip") == ip and old.get("reason") == reason and time.time() - int(old.get("at") or 0) < 60:
        return
    try:
        _kv_put(KR_SSO_REJECTED_KEY, {"at": int(time.time()), "ip": ip, "reason": reason})
    except sqlite3.Error as ex:
        log.warning("kontrolrum sso note failed: %s", type(ex).__name__)


def _kr_session_refused(name: str, why: str) -> None:
    log.warning("kontrolrum sso session refused (%s) from %s", why, request_peer()[:64])
    if _recent_hit(f"krsess-audit:{request_peer()}", KR_SSO_RATE, KR_SSO_RATE_WINDOW):
        audit("login_kontrolrum", result="blocked", actor=name,
              detail=f"session afvist · {KR_SSO_REASON_TEXT.get(why, why)} · peer {request_peer()[:64]}")


def _login_page(error: str = "", username: str = "", status: int = 200, note: str = "", remember: bool = False):
    no_users = not load_users()
    if no_users:
        note = ("Der er ingen brugere endnu. Opret en med "
                "<code>docker exec -it spamfilter python /app/dashboard.py</code>.")
    err_html = kit.alert(error, "bad") if error else ""
    note_html = f'<div class="alert tone-info">{kit.icon("info", "alert-icon")}<div class="alert-body"><span>{note}</span></div></div>' if note else ""
    nxt = safe_next(request.args.get("next"))
    body = (
        '<div class="login-card">'
        f'<div class="login-brand">{kit.brand_mark("brand-mark-lg")}'
        '<h1>Spamfilter</h1><p>Log ind for at se din post og dit filter.</p></div>'
        f'{err_html}{note_html}'
        f'<form method="post" action="/login?next={kit.h(_quote_next(nxt))}" class="login-form" data-login>'
        f'{kit.hidden("csrf", csrf_token())}'
        + kit.form_field("Brugernavn", kit.input_("username", username, attrs='autocomplete="username" autocapitalize="none" spellcheck="false" required autofocus'))
        + kit.form_field("Adgangskode", kit.input_("password", "", type="password", attrs='autocomplete="current-password" required'))
        + '<label class="check-row login-remember"><input type="checkbox" class="check" name="remember" value="1"'
        + (" checked" if remember else "") + '>'
        '<span><b>Husk mig på denne enhed i 30 dage</b>'
        '<small>Kun på din egen telefon eller computer – ikke på en lånt eller delt enhed.</small></span></label>'
        + kit.button("Log ind", kind="primary", icon="arrow-right", cls="btn-block", size="lg")
        + "</form>"
        + _passkey_login_section(nxt)
        + '<p class="login-foot">' + kit.icon("lock") + "Forbindelsen er beskyttet med sikre cookies og CSRF-tokens.</p>"
        "</div>")
    resp = Response(kit.render_auth_page("Log ind", body), status=status, mimetype="text/html")
    alerts = _login_alerts()
    return alerts.with_device_cookie(resp) if alerts is not None else resp


def _passkey_login_section(nxt: str) -> str:
    """2.6 (B1): 'Log ind med passkey' (passkeys.py registers its routes
    with the page modules; without it the login page is unchanged)."""
    mod = sys.modules.get("passkeys")
    if mod is None:
        return ""
    try:
        return mod.login_section(nxt)
    except Exception as ex:  # noqa: BLE001 - the password login must always render
        log.warning("passkey login section unavailable: %s", type(ex).__name__)
        return ""


def _login_alerts():
    """2.6 (B2) login_alerts.py (no routes, safe to import lazily) or None."""
    try:
        return importlib.import_module("login_alerts")
    except Exception as ex:  # noqa: BLE001
        log.warning("login alerts unavailable: %s", type(ex).__name__)
        return None


def login_succeeded(name: str, method: str, *, device: str | None = None, label: str | None = None) -> None:
    """2.6 (B2): after EVERY successful login (password, code, passkey,
    Kontrolrum): login history + new-device alert. `device`/`label` name a
    fixed device instead of the browser's cookie (Kontrolrum). Never raises."""
    mod = _login_alerts()
    if mod is not None:
        if device is None:
            mod.on_login(name, method)
        else:
            mod.on_login(name, method, device=device, label=label)


def login_failed(username: str, step: str = "login") -> None:
    """2.6 (B2): after a failed attempt: alert the administrators once the
    username or the IP hits the lockout. Never raises."""
    mod = _login_alerts()
    if mod is not None:
        mod.on_failed(username, step)


def login_user_key(username: str, ip: str | None = None) -> str:
    """2.12 (#26): the login lockout per username counts per IP + username
    ('user:<name>@<ip>'), so wrong guesses from somewhere else can never
    lock the owner out; the per-IP lock ('ip:<ip>') stays as before."""
    return f"user:{(username or '').lower()}@{ip if ip is not None else (request.remote_addr or 'unknown')}"


def login_user_ext_key(username: str) -> str:
    """2.12 (#26): one counter per username over ALL requests from outside
    the home network ('userx:<name>', limit LOGIN_MAX_FAILURES_USER_EXTERNAL)
    - a guessing attack spread over many IPs is still slowed down, while
    the owner at home (request_is_local) can never be locked out by it."""
    return f"userx:{(username or '').lower()}"


def login_user_keys(username: str, ip: str | None = None) -> list[str]:
    """The username throttle keys of this request: per IP + username, plus
    the global per-username key for requests from outside."""
    keys = [login_user_key(username, ip)]
    if not request_is_local():
        keys.append(login_user_ext_key(username))
    return keys


def login_limit(key: str) -> int:
    """Failures before `key` locks (the global per-username key is higher)."""
    return LOGIN_MAX_FAILURES_USER_EXTERNAL if key.startswith("userx:") else LOGIN_MAX_FAILURES


def _resettable(keys: list[str]) -> list[str]:
    """A successful login clears its own counters, never the global
    per-username counter (an attacker's budget is not refilled by the
    owner logging in)."""
    return [k for k in keys if not k.startswith("userx:")]


def _throttle_success(keys: list[str]) -> None:
    """After a successful login: clear the request's own counters and take
    this (counted) attempt back off the global per-username counter, so
    good logins from outside never add up to a lock."""
    _throttle_reset(_resettable(keys))
    ext = [k for k in keys if k.startswith("userx:")]
    if not ext:
        return
    conn = _connect()
    try:
        conn.executemany("UPDATE login_attempts SET failures=MAX(0, failures-1) WHERE key=? "
                         "AND locked_until IS NULL", [(k,) for k in ext])
        conn.commit()
    finally:
        conn.close()


@app.route("/login", methods=["GET", "POST"])
@public
def login():
    if request.method == "GET":
        if current_user() is not None:
            return redirect(safe_next(request.args.get("next")))
        if pending_mfa() is not None:
            return redirect("/login/2fa?next=" + _quote_next(safe_next(request.args.get("next"))))
        return _login_page()
    username = (request.form.get("username") or "").strip()[:64]
    password = request.form.get("password") or ""
    remember = request.form.get("remember") in ("1", "on", "true")
    if not _csrf_valid():
        # Usually an expired login page; show it again with a fresh token.
        return _login_page("Siden var udløbet. Prøv igen.", username, 400, remember=remember)
    keys = [f"ip:{request.remote_addr or 'unknown'}", *login_user_keys(username)]
    wait = _throttle_begin(keys)
    if wait:
        audit("login", result="locked", actor=username)
        minutes = max(1, (wait + 59) // 60)
        return _login_page(f"For mange forsøg. Prøv igen om {minutes} min.", username, 429, remember=remember)
    user, blocked = check_login_here(username, password) if username and password else (None, False)
    if blocked:
        # Same reply as a wrong password (no oracle); only the audit log knows.
        _blocked_external(username, "login")
        login_failed(username)
        return _login_page("Forkert brugernavn eller adgangskode.", username, 401, remember=remember)
    if user is None:
        audit("login", result="failed", actor=username)
        login_failed(username)
        return _login_page("Forkert brugernavn eller adgangskode.", username, 401, remember=remember)
    _throttle_success(keys)
    nxt = safe_next(request.args.get("next"))
    tf = twofa_status(user.name)
    if tf["enabled"]:
        begin_mfa(user, remember=remember)
        audit("login", result="pending", actor=user.name, detail="adgangskode ok · venter på kode")
        if tf["mail"] and not tf["totp"] and mail_code_state(user.name)["wait"] == 0:
            send_login_code(user.name)  # mail-only: the code is on its way when the code page opens
        return redirect("/login/2fa?next=" + _quote_next(nxt))
    start_session(user, remember=remember)
    session["reauth_pw"] = [user.name, int(time.time())]  # 2.6: the password was just proven (passkeys)
    record_login(user.name, request.remote_addr)
    login_succeeded(user.name, "password")
    audit("login", result="ok", actor=user.name, detail="husk mig" if remember else "")
    if tf["required"]:
        flash("Din administrator kræver to-trins-login. Det tager et par minutter at sætte op.", "info")
        return redirect("/me/2fa/setup")
    return redirect(nxt)


def _wait_text(seconds: int) -> str:
    """'15 sek' / '2 min' - without a trailing full stop, so the text
    can end a sentence ('… om 15 sek.')."""
    s = max(1, int(seconds))
    return f"{s} sek" if s < 90 else f"{(s + 59) // 60} min"


def send_login_code(name: str, *, template: str = "login") -> tuple[bool, str]:
    """Mail a login/confirmation code to the user's verified address.
    The reply is the same whether the mail could be queued or not (the
    send happens in the background); only the resend cooldown is told."""
    addr = twofa_mail_address(name)
    if not addr:
        return False, "Kode på mail er ikke slået til."
    masked = mailer.mask_address(addr)
    res = mail_code_issue(name, addr, "login", template=template)
    audit("twofa_mail_code", result="sent" if res["code"] in ("sent", "error") else res["code"], actor=name,
          detail=f"til {masked}")
    if res["code"] == "wait":
        return False, (f"Du kan bede om en ny kode om {_wait_text(res['wait'])}. Brug den seneste kode, du har "
                       "fået – eller en genoprettelseskode.")
    if res["code"] == "unavailable":
        return False, ("Mailserveren kan ikke sende koder lige nu. Brug en genoprettelseskode – eller bed en "
                       "administrator om at nulstille dit to-trins-login.")
    return True, (f"Koden er på vej til {masked}. Den gælder i {MAIL_CODE_TTL // 60} minutter – tjek også "
                  "spam-mappen.")


def _mfa_mail_box(user: User, nxt: str) -> str:
    """'Send kode til o…@bynet.example' with the resend cooldown (no JS needed)."""
    addr = twofa_mail_address(user.name)
    if not addr:
        return ""
    masked = mailer.mask_address(addr)
    if not mail_2fa_available():
        return (f'<div class="mfa-mail is-off">{kit.icon("mail")}<div><b>Kode på mail</b>'
                "<span>Mailserveren kan ikke sende koder lige nu. Brug en genoprettelseskode – eller bed en "
                "administrator om at nulstille dit to-trins-login.</span></div></div>")
    st = mail_code_state(user.name)
    recent = bool(st["last_login_at"] and time.time() - st["last_login_at"] < MAIL_CODE_TTL)
    masked_html = f'<span class="nowrap">{kit.h(masked)}</span>'
    if recent:
        info = (f"Koden er sendt kl. {kit.h(time.strftime('%H:%M', time.localtime(st['last_login_at'])))} til "
                f"{masked_html}. Den gælder i {MAIL_CODE_TTL // 60} minutter.")
    else:
        info = f"Vi sender en 6-cifret kode til {masked_html}. Den gælder i {MAIL_CODE_TTL // 60} minutter."
    wait_s = int(st["wait"] or 0)
    # The countdown is shown by app.js ([data-countdown]); without JS the
    # button stays usable and the server answers with the cooldown.
    wait = (f'<span class="mfa-mail-wait" data-countdown-note>{kit.icon("clock")}<span>Du kan få en ny kode om '
            f'<span data-countdown-text>{kit.h(_wait_text(wait_s))}</span>.</span></span>') if wait_s else ""
    attrs = f'data-countdown="{wait_s}"' if wait_s else ""
    form = (f'<form method="post" action="/login/2fa?next={kit.h(_quote_next(nxt))}" class="mfa-mail-form">'
            f'{kit.hidden("csrf", csrf_token())}{kit.hidden("action", "send")}'
            + kit.button(f"Send kode til {masked}" if not recent else f"Send en ny kode til {masked}",
                         kind="secondary", icon="send", cls="btn-block", attrs=attrs)
            + "</form>")
    return (f'<div class="mfa-mail">{kit.icon("mail", "mfa-mail-icon")}<div class="mfa-mail-text"><b>Kode på mail</b>'
            f"<span>{info}</span>"
            f"{wait}</div>{form}</div>")


def _mfa_page(user: User, pre: dict, error: str = "", status: int = 200, note: str = ""):
    nxt = safe_next(request.args.get("next"))
    tf = twofa_status(user.name)
    err_html = kit.alert(error, "bad") if error else ""
    note_html = kit.alert(note, "info") if note else ""
    if tf["mail"] and not tf["totp"]:
        intro = f"Hej {kit.h(user.name)}. Indtast den 6-cifrede kode, vi har sendt til dig på mail."
        hint = ("Kommer mailen ikke? Tjek spam-mappen, eller send en ny kode herunder. Du kan også bruge en af dine "
                "genoprettelseskoder (fx abcde-23456). Hver kode virker kun én gang.")
    elif tf["mail"]:
        intro = (f"Hej {kit.h(user.name)}. Indtast den 6-cifrede kode fra din godkendelses-app – "
                 "eller få en kode på mail.")
        hint = ("Har du ikke telefonen? Få en kode på mail, eller skriv en af dine genoprettelseskoder i feltet "
                "(fx abcde-23456). Hver kode virker kun én gang.")
    else:
        intro = f"Hej {kit.h(user.name)}. Indtast den 6-cifrede kode fra din godkendelses-app."
        hint = ("Har du ikke telefonen? Skriv en af dine genoprettelseskoder i feltet "
                "i stedet (fx abcde-23456). Hver kode virker kun én gang.")
    remember_note = (
        f'<p class="mfa-note">{kit.icon("check-circle")}<span>“Husk mig” er valgt: denne enhed spørger ikke igen, '
        f"så længe den huskede session varer ({REMEMBER_LIFETIME // 86400} dage).</span></p>") if pre.get("rm") else ""
    body = (
        '<div class="login-card mfa-card">'
        f'<div class="login-brand">{kit.brand_mark("brand-mark-lg")}'
        '<h1>To-trins-login</h1>'
        f'<p>{intro}</p></div>'
        f"{err_html}{note_html}"
        f'<form method="post" action="/login/2fa?next={kit.h(_quote_next(nxt))}" class="login-form" data-otp-form>'
        f'{kit.hidden("csrf", csrf_token())}'
        + kit.form_field("Kode", kit.otp_input("code", id="mfa-code", autofocus=True, describedby="mfa-hint"))
        + f'<p class="field-hint" id="mfa-hint">{kit.h(hint)}</p>'
        + kit.button("Bekræft", kind="primary", icon="shield-check", cls="btn-block", size="lg")
        + "</form>"
        + _mfa_mail_box(user, nxt)
        + remember_note
        + '<form method="post" action="/logout" class="mfa-cancel">'
        f'{kit.hidden("csrf", csrf_token())}'
        '<button type="submit" class="btn btn-ghost btn-sm">' + kit.icon("arrow-left")
        + "<span>Annullér og log ind som en anden</span></button></form>"
        "</div>")
    return Response(kit.render_auth_page("To-trins-login", body), status=status, mimetype="text/html")


@app.route("/login/2fa", methods=["GET", "POST"])
@public
def login_2fa():
    """Second step of the login: TOTP, a mailed code or a one-time recovery
    code. POST action=send mails a new code (resend cooldown)."""
    nxt = safe_next(request.args.get("next"))
    if current_user() is not None:
        return redirect(nxt)
    pend = pending_mfa()
    back = "/login" + (("?next=" + _quote_next(nxt)) if nxt != "/" else "")
    if pend is None:
        if session.get("pre"):
            session.pop("pre", None)
            flash("Log ind igen – koden skal indtastes inden for få minutter efter adgangskoden.", "warn")
        return redirect(back)
    user, pre = pend
    remember = bool(pre.get("rm"))
    if not twofa_status(user.name)["enabled"]:
        # Turned off (e.g. reset by an admin) after the password was checked.
        start_session(user, remember=remember)
        record_login(user.name, request.remote_addr)
        login_succeeded(user.name, "password")
        audit("login", result="ok", actor=user.name, detail="husk mig" if remember else "")
        return redirect(nxt)
    if request.method == "GET":
        return _mfa_page(user, pre)
    if not _csrf_valid():
        return _mfa_page(user, pre, "Siden var udløbet. Prøv igen.", 400)
    if request.form.get("action") == "send":
        if not twofa_status(user.name)["mail"]:
            return _mfa_page(user, pre)
        ok, text = send_login_code(user.name)
        return _mfa_page(user, pre, note=text) if ok else _mfa_page(user, pre, error=text, status=429)
    keys = [f"2fa:{user.name.lower()}", f"2faip:{request.remote_addr or 'unknown'}"]
    wait = _throttle_begin(keys)
    if wait:
        audit("login_2fa", result="locked", actor=user.name)
        minutes = max(1, (wait + 59) // 60)
        return _mfa_page(user, pre, f"For mange forkerte koder. Prøv igen om {minutes} min.", 429)
    pre = dict(pre, n=int(pre.get("n", 0)) + 1)
    session["pre"] = pre
    kind = twofa_verify(user.name, request.form.get("code"))
    if kind is None:
        audit("login_2fa", result="failed", actor=user.name)
        login_failed(user.name, "2fa")
        if pre["n"] >= MFA_MAX_TRIES:
            session.clear()
            flash("For mange forkerte koder. Log ind forfra.", "error")
            return redirect(back)
        tf = twofa_status(user.name)
        msg = ("Koden passer ikke. Brug den nyeste kode fra appen – og tjek, at telefonens ur står rigtigt."
               if tf["totp"] else "")
        if tf["mail"]:
            msg = (msg + " " if msg else "") + ("Koder på mail gælder i 10 minutter, og kun den nyeste virker."
                                                if tf["totp"] else
                                                "Koden passer ikke. Brug den nyeste kode fra mailen – den gælder i "
                                                "10 minutter.")
        return _mfa_page(user, pre, msg, 401)
    _throttle_reset(keys)
    start_session(user, remember=remember, mfa=True)
    _mark_reauth(user.name)
    record_login(user.name, request.remote_addr)
    detail = ("to-trins-login" + {"recovery": " · genoprettelseskode", "mail": " · kode på mail"}.get(kind, "")
              + (" · husk mig" if remember else ""))
    login_succeeded(user.name, kind if kind in ("recovery", "mail") else "2fa")
    audit("login", result="ok", actor=user.name, detail=detail)
    if kind == "recovery":
        left = twofa_status(user.name)["recovery_left"]
        flash(f"Du loggede ind med en genoprettelseskode. Du har {left} tilbage – lav nye under Min konto.", "warn")
    return redirect(nxt)


def start_session(user: User, *, remember: bool = False, mfa: bool = False) -> None:
    """Fresh session for `user` (new CSRF token; "Husk mig" = 30 d / 7 d
    idle instead of 12 h / 2 h). Revoked like any session by a generation
    bump (password change, "Log ud overalt", removal). `mfa` marks that the
    second factor was given; a remembered session then skips the code for
    as long as it lives - a new login asks again."""
    now = int(time.time())
    session.clear()
    session.permanent = True
    session.update({"u": user.name, "gen": user.gen, "t0": now, "ts": now,
                    "csrf": secrets.token_urlsafe(32)})
    if remember:
        session["rm"] = 1
    if mfa:
        session["mfa"] = 1
    g.pop("_user", None)


def _kr_fail(status: int, error: str, sub: Any = "") -> tuple[Response, int]:
    """Refuse an SSO attempt: audit + journal + 'seneste afviste' (never the
    assertion or the key)."""
    who = sub[:64] if isinstance(sub, str) and 0 < len(sub) <= KR_SSO_SUB_MAX and "\n" not in sub else ""
    log.warning("kontrolrum sso refused (%s) from %s", error, request_peer()[:64])
    audit("login_kontrolrum", result="failed", actor=who,
          detail=f"{KR_SSO_REASON_TEXT.get(error, error)} · peer {request_peer()[:64]}")
    _kr_note_rejected(error)
    return jsonify({"error": error}), status


@app.route("/login/kontrolrum", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
           provide_automatic_options=False)
@public
def login_kontrolrum():
    """2.9.0: single sign-on from Kontrolrum (see kr_sso_* above). Server to
    server: JSON body {v, aud, sub, iat, exp, nonce, sig}, no browser
    session yet, so CSRF-exempt. 200 {ok, user} + the session cookie.
    Every other method is a plain 404 (like an unknown URL, never 405)."""
    if request.method != "POST":
        abort(404)
    peer = request_peer()
    if not _recent_hit(f"krsso:{peer}", KR_SSO_RATE, KR_SSO_RATE_WINDOW):
        if _recent_hit(f"krsso-429:{peer}", 1, KR_SSO_RATE_WINDOW):  # one audit line per window
            _kr_fail(429, "rate_limited")
        resp = jsonify({"error": "rate_limited"})
        resp.headers["Retry-After"] = str(KR_SSO_RATE_WINDOW)
        return resp, 429
    a = request.get_json(silent=True)
    sub = a.get("sub") if isinstance(a, dict) else ""
    if not kr_peer_allowed(peer):
        _kr_fail(404, "wrong_peer", sub)
        abort(404)
    if _kr_proxied():
        _kr_fail(404, "proxied", sub)
        abort(404)
    key = kr_sso_key()
    if key is None:
        return _kr_fail(403, "sso_disabled", sub)
    if not kr_sso_well_formed(a):
        return _kr_fail(400, "bad_request", sub)
    if not kr_sso_signature_valid(key, a):
        return _kr_fail(401, "bad_signature", sub)
    claim_error = kr_sso_check_claims(a)
    if claim_error:
        return _kr_fail(401, claim_error, sub)
    try:
        fresh = kr_sso_take_nonce(a["nonce"], a["exp"])
    except sqlite3.Error as ex:
        log.warning("kontrolrum sso nonce store failed: %s", type(ex).__name__)
        return jsonify({"error": "unavailable"}), 503
    if not fresh:
        return _kr_fail(401, "replay", sub)
    user = load_users().get(a["sub"])
    if user is None or not kr_sso_allowed(user.name):
        return _kr_fail(401, "unknown_user", sub)
    start_session(user, mfa=True)  # Kontrolrum itself requires a login (passkey/Face ID outside the LAN)
    session["kr"] = {"p": _kr_norm_ip(peer), "k": kr_sso_fingerprint(key)}
    record_login(user.name, peer)
    login_succeeded(user.name, "kontrolrum", device=f"kontrolrum:{_kr_norm_ip(peer)}",
                    label=KR_SSO_DEVICE_LABEL)
    audit("login_kontrolrum", actor=user.name, detail=f"Kontrolrum-SSO · peer {peer[:64]}")
    log.info("kontrolrum sso login for a user from %s", peer[:64])
    try:
        _kv_put(KR_SSO_USED_KEY, {"at": int(time.time()), "ip": peer[:64], "user": user.name})
    except sqlite3.Error as ex:
        log.warning("kontrolrum sso note failed: %s", type(ex).__name__)
    return jsonify({"ok": True, "user": user.name})


@app.post("/logout")
@public
def logout():
    u = current_user()
    if u:
        audit("logout", actor=u["name"])
    session.clear()
    flash("Du er logget ud.", "info")
    return redirect("/login")


@app.get("/logout")
@public
def logout_get():
    # Logging out must be a POST (CSRF); old bookmarks land on the login page.
    return redirect("/" if current_user() else "/login")


# ---------------------------------------------------------------------------
# Min konto (/me): two-step login, the app on the phone, own sessions.
# Every logged-in user (also a Bruger) manages their own login here.
# ---------------------------------------------------------------------------

AUTH_APPS = ("Google Authenticator", "Microsoft Authenticator", "1Password", "Bitwarden",
             "iPhone: Adgangskoder (iOS 18+)")


def _me_name() -> str:
    return str((current_user() or {}).get("name", ""))


def _method_row(icon_name: str, title: str, state_html: str, text: str, actions: str = "", *,
                cls: str = "") -> str:
    return (f'<li class="twofa-method{(" " + cls) if cls else ""}">{kit.icon(icon_name, "twofa-method-icon")}'
            f'<div class="twofa-method-text"><div class="row-tight"><b>{kit.h(title)}</b>{state_html}</div>'
            f'<span>{kit.h(text)}</span></div>'
            + (f'<div class="twofa-method-actions">{actions}</div>' if actions else "") + "</li>")


def _methods_list(name: str, tf: dict, *, admin: bool) -> str:
    """Both methods side by side: what is on, what can be added."""
    avail = mail_2fa_available()
    rec = " Anbefales til administratorer." if admin else ""
    if tf["totp"]:
        app_row = _method_row("smartphone", "Authenticator-app", kit.badge("Slået til", "ok"),
                              "Koden fra appen på din telefon. Virker også uden net." + rec)
    else:
        app_row = _method_row("smartphone", "Authenticator-app", kit.badge("Ikke sat op", "neutral"),
                              "En 6-cifret kode fra en app på telefonen – den sikreste løsning." + rec,
                              kit.button("Tilføj app", href="/me/2fa/setup?method=app", kind="secondary",
                                         icon="plus", size="sm"))
    mail_row = ""
    if tf["mail"]:
        change = kit.button("Skift adresse", href="/me/2fa/setup?method=mail", kind="ghost", icon="refresh",
                            size="sm") if avail else ""
        mail_row = _method_row("mail", "Kode på mail", kit.badge("Slået til", "ok"),
                               f"Koden sendes til {tf['mail_masked']}." + (
                                   "" if avail else " Mailserveren kan ikke sende lige nu."), change)
    elif avail:
        mail_row = _method_row("mail", "Kode på mail", kit.badge("Ikke sat op", "neutral"),
                               "Vi mailer dig en kode, når du logger ind. Nemt – men kun så sikkert som din "
                               "mailkonto.",
                               kit.button("Tilføj kode på mail", href="/me/2fa/setup?method=mail", kind="secondary",
                                          icon="plus", size="sm"))
    return f'<ul class="twofa-methods">{app_row}{mail_row}</ul>'


def _code_label(tf: dict) -> str:
    if tf["totp"] and tf["mail"]:
        return "Kode fra appen, fra mailen eller en genoprettelseskode"
    if tf["mail"]:
        return "Kode fra mailen eller en genoprettelseskode"
    return "Kode fra appen eller en genoprettelseskode"


def _send_code_form(tf: dict, *, next_url: str = "") -> str:
    """'Send kode på mail' for confirming changes (mail users)."""
    if not tf["mail"] or not mail_2fa_available():
        return ""
    back = kit.hidden("next", next_url) if next_url else ""
    return kit.post_form("/me/2fa/confirm", kit.hidden("method", "mail") + kit.hidden("step", "code") + back
                         + kit.button(f"Send kode til {tf['mail_masked']}", kind="ghost", icon="send", size="sm"),
                         cls="twofa-sendcode")


def twofa_card(name: str) -> str:
    """Status + actions for the user's own two-step login (app and/or mail)."""
    tf = twofa_status(name)
    me = current_user() or {}
    admin = bool(me.get("is_admin"))
    if not tf["enabled"]:
        required = (kit.alert("Din administrator kræver to-trins-login for din bruger. Sæt det op nu – det tager "
                              "et par minutter.", "warn", title="Påkrævet") if tf["required"] else "")
        avail = mail_2fa_available()
        hero = (f'<div class="twofa-hero tone-warn">{kit.icon("shield", "twofa-icon")}<div class="twofa-text">'
                f'<div class="row-tight">{kit.badge("Ikke slået til", "warn")}</div>'
                "<p>Med to-trins-login skal du ud over adgangskoden indtaste en 6-cifret kode fra en app på "
                "din telefon" + (" eller fra en mail" if avail else "")
                + ". Så kan ingen logge ind som dig – heller ikke hvis de kender din adgangskode.</p>"
                "</div></div>")
        points = ('<ul class="twofa-points">'
                  + (f'<li>{kit.icon("smartphone")}<span>Koden kommer fra en app på telefonen – eller på mail.</span></li>'
                     if avail else
                     f'<li>{kit.icon("smartphone")}<span>Virker med de fleste godkendelses-apps – også iPhonens '
                     "indbyggede Adgangskoder.</span></li>")
                  + f'<li>{kit.icon("key")}<span>Du får {RECOVERY_CODES} genoprettelseskoder, hvis du mister adgangen.</span></li>'
                  f'<li>{kit.icon("check-circle")}<span>Med “Husk mig” spørges du kun én gang pr. enhed i op til '
                  f"{REMEMBER_LIFETIME // 86400} dage.</span></li></ul>")
        if avail:
            action = ('<div class="form-actions">'
                      + kit.button("Kode på mail", href="/me/2fa/setup?method=mail", kind="secondary", icon="mail")
                      + kit.button("Authenticator-app", href="/me/2fa/setup?method=app", kind="primary",
                                   icon="smartphone")
                      + "</div>"
                      + f'<p class="faint small mt-1">Appen anbefales{" – især til administratorer" if admin else ""}: '
                        "den beskytter dig, selv hvis nogen får adgang til din mail.</p>")
        else:
            action = ('<div class="form-actions">'
                      + kit.button("Slå to-trins-login til", href="/me/2fa/setup", kind="primary", icon="shield-check")
                      + "</div>")
        return kit.card(required + hero + points + action, title="To-trins-login",
                        subtitle="Ekstra beskyttelse af dit login.", cls="twofa-card")
    left = int(tf["recovery_left"])
    tone = "bad" if left == 0 else "warn" if left <= 2 else "ok"
    how = ("koden fra din godkendelses-app eller en kode på mail" if tf["totp"] and tf["mail"]
           else "en kode, vi sender til dig på mail" if tf["mail"] else "koden fra din godkendelses-app")
    hero = (f'<div class="twofa-hero tone-ok">{kit.icon("shield-check", "twofa-icon")}<div class="twofa-text">'
            f'<div class="row-tight">{kit.badge("Slået til", "ok")}'
            + (kit.chip("Påkrævet af administrator", "brand") if tf["required"] else "")
            + f'</div><p>Siden {kit.h(kit.fmt_date(tf["enabled_at"]))}. Når du logger ind, skal du bruge '
              f"{how}.</p></div></div>")
    if admin and not tf["totp"]:
        hero += kit.alert("Som administrator bør du også tilføje en authenticator-app: den beskytter dig, selv hvis nogen "
                          "får adgang til din mail.", "info")
    device = ("Husket – spørger ikke igen, før den huskede session udløber" if me.get("remember")
              else "Spørger efter koden ved næste login")
    kv = kit.kv_list([("Genoprettelseskoder", kit.badge(f"{left} af {RECOVERY_CODES} tilbage", tone)),
                      ("Denne enhed", kit.h(device))])
    low = (kit.alert("Du har snart ingen genoprettelseskoder tilbage. Lav nye nedenfor.", "warn")
           if left <= 2 else "")
    sendcode = _send_code_form(tf)
    code_field_label = "Kode fra appen" if not tf["mail"] else _code_label(tf).replace(" eller en genoprettelseskode", "")
    regen = kit.post_form(
        "/me/2fa/recovery",
        kit.form_field(code_field_label, kit.otp_input("code", id="regen-code", recovery=False))
        + '<div class="form-actions">'
        + kit.button("Lav nye genoprettelseskoder", kind="secondary", icon="refresh") + "</div>",
        ajax=False, cls="twofa-form")
    manage = ('<div class="twofa-manage-sect"><h3>Nye genoprettelseskoder</h3>'
              '<p class="muted small">De gamle koder holder op med at virke, og du får 8 nye at gemme.</p>'
              + regen + "</div>")
    both = tf["totp"] and tf["mail"]
    if tf["required"] and not both:
        manage += ('<p class="faint small">To-trins-login er påkrævet af en administrator og kan ikke slås fra. '
                   "Har du mistet telefonen, kan en administrator nulstille det.</p>")
    else:
        if both:
            opts = [("totp", "Fjern authenticator-appen"), ("mail", "Fjern kode på mail")]
            if not tf["required"]:
                opts.append(("all", "Slå to-trins-login helt fra"))
            choose = kit.form_field("Hvad vil du slå fra?", kit.select("method", opts, "totp",
                                                                        attrs='id="off-method"'))
            title, text = "Slå fra?", "Det valgte holder op med at virke ved login."
        else:
            choose = kit.hidden("method", "all")
            title, text = "Slå to-trins-login fra?", "Så er din adgangskode igen det eneste, der skal til for at logge ind."
        disable = kit.post_form(
            "/me/2fa/disable",
            choose
            + kit.form_field(_code_label(tf), kit.otp_input("code", id="off-code"))
            + '<div class="form-actions">'
            + kit.button("Slå fra" if both else "Slå to-trins-login fra", kind="secondary", tone="bad",
                         icon="x-circle", attrs=kit.confirm_attrs(title, text, confirm="Slå fra", tone="danger"))
            + "</div>", cls="twofa-form")
        manage += ('<div class="twofa-manage-sect"><h3>Slå fra</h3>'
                   '<p class="muted small">Kun hvis du skifter telefon eller mailadresse og vil sætte det op forfra.</p>'
                   + disable + "</div>")
    if sendcode:
        manage = (f'<div class="twofa-manage-sect twofa-sendcode-sect"><p class="muted small">Ændringer bekræftes med '
                  f"en kode. Har du ikke appen ved hånden, så få en på mail:</p>{sendcode}</div>") + manage
    details = (f'<details class="twofa-manage"><summary>{kit.icon("sliders")}<span>Administrér</span>'
               f'{kit.icon("chevron-down", "twofa-caret")}</summary><div class="twofa-manage-body">{manage}</div></details>')
    return kit.card(hero + low + _methods_list(name, tf, admin=admin) + kv + details, title="To-trins-login",
                    subtitle="Ekstra beskyttelse af dit login.", cls="twofa-card")


def _sessions_card(name: str) -> str:
    me = current_user() or {}
    now = ("Husket på denne enhed i op til " + str(REMEMBER_LIFETIME // 86400) + " dage" if me.get("remember")
           else f"Udløber efter {SESSION_IDLE // 3600} timers inaktivitet")
    form = kit.post_form("/me/logout-all", logout_all_passkeys_field(name, own=True) + kit.button(
        "Log ud overalt", kind="secondary", icon="log-out",
        attrs=kit.confirm_attrs("Log ud overalt?", "Du bliver logget ud på alle enheder – også denne og dem med “Husk mig”.",
                                confirm="Log ud overalt")))
    alerts = _login_alerts()
    recent = alerts.logins_html(name) if alerts is not None else ""  # 2.6 (B2): Seneste login
    return kit.card(kit.kv_list([("Bruger", kit.h(name)), ("Denne enhed", kit.h(now))])
                    + '<p class="muted small mt-1">Har du glemt at logge ud på en fremmed computer eller mistet en '
                      "telefon? Så log ud overalt.</p>"
                    + f'<div class="form-actions">{form}</div>' + recent, title="Logget ind")


def _theme_card() -> str:
    """2.10: Udseende (menu, stil, tema) - Fleetdeck's LookPanel, stored in this browser."""
    return kit.look_card()


MIN_OWN_PASSWORD = 12


def _password_card(name: str) -> str:
    """Change your own password (also for Brugere)."""
    user_hint = (f'<input type="text" name="username" value="{kit.h(name)}" autocomplete="username" '
                 'class="sr-only" tabindex="-1" aria-hidden="true" readonly>')
    inner = (user_hint
             + kit.form_field("Nuværende adgangskode", kit.input_(
                 "current", "", type="password", attrs='id="me-pw-cur" autocomplete="current-password" required maxlength="256"'))
             + '<div class="grid grid-2 grid-tight">'
             + kit.form_field("Ny adgangskode", kit.input_(
                 "password", "", type="password",
                 attrs=f'id="me-pw" minlength="{MIN_OWN_PASSWORD}" maxlength="256" autocomplete="new-password" required'))
             + kit.form_field("Gentag", kit.input_(
                 "password2", "", type="password",
                 attrs=f'id="me-pw2" minlength="{MIN_OWN_PASSWORD}" maxlength="256" autocomplete="new-password" required'))
             + "</div>"
             f'<span class="field-hint">Mindst {MIN_OWN_PASSWORD} tegn. Du bliver logget ud på dine andre enheder.</span>'
             + '<div class="form-actions">' + kit.button("Skift adgangskode", kind="primary", icon="key") + "</div>")
    return kit.card(kit.post_form("/me/password", inner, ajax=False), title="Adgangskode",
                    subtitle="Skift den kode, du logger ind med.")


def _preview_me_page():
    """'Se som bruger': the user's own login settings are private - show
    what the page offers without any of their data."""
    items = (("key", "Adgangskode", "Brugeren kan selv skifte sin adgangskode."),
             ("shield-check", "To-trins-login", "Brugeren kan slå to-trins-login til med en app på telefonen "
                                                 "eller få koden på mail."),
             ("smartphone", "Husk mig og app", "Hold sig logget ind på sin telefon og lægge spamfilteret på hjemmeskærmen."),
             ("bell", "Beskeder på telefonen", "Få en besked, når en farlig mail er stoppet i brugerens egne postkasser."),
             ("log-out", "Log ud overalt", "Afslut alle sine sessioner, fx efter at have mistet en telefon."))
    lis = "".join(f'<li>{kit.icon(ic)}<div><b>{kit.h(t)}</b><span>{kit.h(x)}</span></div></li>' for ic, t, x in items)
    body = kit.card(f'<ul class="simple-list">{lis}</ul>', title="Min konto",
                    subtitle="Brugerens egne login-indstillinger vises ikke i forhåndsvisningen.")
    return kit.render_page("Min konto", body, active="me", subtitle="Adgangskode, to-trins-login og Husk mig.")


@app.get("/me")
@login_required
def me_page():
    if preview_target():
        return _preview_me_page()
    name = _me_name()
    u = current_user() or {}
    import ui_push  # noqa: PLC0415 - registered with the mail pages (ui_mail); 2.5.0 push card

    push_html = ui_push.push_card(name, is_admin=bool(u.get("is_admin")))
    pk = sys.modules.get("passkeys")
    pk_html = pk.passkeys_card(name) if pk is not None else ""   # 2.6 (B1)
    if u.get("is_admin"):
        body = ('<div class="grid grid-main">'
                f'<div class="stack">{twofa_card(name)}{pk_html}{_password_card(name)}'
                f'{kit.install_card(external_url(), admin=True)}</div>'
                f'<div class="stack">{push_html}{_sessions_card(name)}{_theme_card()}</div></div>')
    else:  # simple: one column, the essentials first
        body = ('<div class="stack simple-stack">'
                f'{_password_card(name)}{twofa_card(name)}{pk_html}{_sessions_card(name)}'
                f'{kit.install_card(external_url(), admin=False)}{push_html}{_theme_card()}</div>')
    return kit.render_page("Min konto", body, active="me",
                           subtitle="Din adgangskode, to-trins-login, spamfilteret som app og beskeder på telefonen.")


@app.post("/me/password")
@login_required
def me_password():
    """Own password change: the current password is required (throttled like
    a login), this session stays, every other one is logged out."""
    name = _me_name()
    current = request.form.get("current") or ""
    pw, pw2 = request.form.get("password") or "", request.form.get("password2") or ""
    if len(pw) < MIN_OWN_PASSWORD:
        return respond(f"Den nye adgangskode skal være mindst {MIN_OWN_PASSWORD} tegn.", ok=False, next_url="/me")
    if len(pw) > 256 or any(c in pw for c in "\r\n\x00"):
        return respond("Adgangskoden er for lang eller indeholder ugyldige tegn.", ok=False, next_url="/me")
    if pw != pw2:
        return respond("De to nye adgangskoder er ikke ens.", ok=False, next_url="/me")
    keys = [f"pwchange:{name}"]
    wait = _throttle_begin(keys)
    if wait:
        return respond(f"For mange forsøg. Prøv igen om {max(1, wait // 60)} min.", ok=False, next_url="/me",
                       status=429)
    if not _recent_hit(f"pwchange-ok:{name.lower()}", PWCHANGE_MAX_PER_HOUR, 3600, record=False):
        return respond("Du har skiftet adgangskode mange gange den seneste time. Prøv igen senere.", ok=False,
                       next_url="/me", status=429)
    with _USERS_LOCK:
        users = load_users()
        u = users.get(name)
        if u is not None and u.source != "file":
            return respond("Du er sat op uden for webadministrationen og kan ikke skifte kode her.",
                           ok=False, next_url="/me")
        if u is None or not u.verifier or not verify_password(u.verifier, current):
            audit("me_password", result="rejected", detail="wrong current password")
            return respond("Den nuværende adgangskode er forkert.", ok=False, next_url="/me", status=403)
        if verify_password(u.verifier, pw):
            return respond("Den nye adgangskode er den samme som den gamle.", ok=False, next_url="/me")
        users[name] = replace(u, verifier=hash_password(pw), gen=u.gen + 1)
        write_users(users.values())
    _throttle_reset(keys)
    _recent_hit(f"pwchange-ok:{name.lower()}", PWCHANGE_MAX_PER_HOUR, 3600)
    session["gen"] = u.gen + 1  # keep this session; every other one is logged out
    g.pop("_user", None)
    audit("me_password", detail=name)
    security_notice(name, "ny adgangskode", "Adgangskoden til spamfilteret er skiftet. Du er logget ud på dine andre "
                                            "enheder.")
    return respond("Din adgangskode er skiftet. Du er logget ud på dine andre enheder.", next_url="/me")


def _setup_page(name: str, secret: str, *, error: str = "") -> str:
    uri = otpauth_uri(name, secret)
    apps = "".join(kit.chip(a, "neutral") for a in AUTH_APPS)
    step1 = kit.wizard_step(1, "Hent en godkendelses-app", "Har du allerede en, så spring over.",
                            f'<div class="chip-row">{apps}</div>')
    qr = kit.qr_svg(uri, label="QR-kode til godkendelses-appen")
    step2 = kit.wizard_step(
        2, "Tilføj spamfilteret i appen",
        "På telefonen: tryk på knappen. På computeren: scan QR-koden med telefonen.",
        '<div class="enroll">'
        f'<div class="enroll-open">{kit.button("Åbn i godkendelses-app", href=uri, kind="secondary", icon="smartphone", cls="btn-block enroll-btn")}'
        '<span class="field-hint">Virker på den telefon, hvor appen er installeret.</span></div>'
        f'<div class="enroll-qr"><div class="qr-tile">{qr}</div>'
        '<span class="field-hint">Scan med appen (eller telefonens kamera).</span></div>'
        '<div class="enroll-key"><span class="field-label">Kan du ikke scanne? Indtast nøglen</span>'
        f'<div class="secret-key"><code class="mono" data-secret>{kit.h(group_secret(secret))}</code>'
        + kit.button("Kopiér", kind="ghost", icon="copy", size="sm",
                     attrs=f'type="button" data-copy-text="{kit.h(secret)}" data-copy-label="Nøglen"')
        + "</div>"
        + kit.kv_list([("Konto", kit.h(f"{TOTP_ISSUER} ({name})")),
                       ("Type", f"Tidsbaseret (TOTP) · {TOTP_DIGITS} cifre · {TOTP_STEP} sek.")])
        + "</div></div>")
    form = kit.post_form(
        "/me/2fa/confirm",
        kit.form_field("6-cifret kode", kit.otp_input("code", id="setup-code", recovery=False, autofocus=bool(error)),
                       error=error)
        + '<div class="form-actions">' + kit.button("Slå to-trins-login til", kind="primary", icon="shield-check")
        + "</div>", ajax=False, cls="enroll-confirm")
    step3 = kit.wizard_step(3, "Bekræft med en kode", "Skriv den kode, appen viser nu.", form)
    help_card = kit.card(
        '<ul class="help-list">'
        "<li><b>Hvorfor?</b><span>Selv hvis nogen gætter eller stjæler din adgangskode, kan de ikke logge ind uden "
        "din telefon.</span></li>"
        "<li><b>Mister du telefonen?</b><span>Brug en af dine genoprettelseskoder – du får dem i næste trin. "
        "En administrator kan også nulstille to-trins-login.</span></li>"
        "<li><b>Koden passer ikke?</b><span>Telefonens ur skal gå rigtigt (automatisk tid). Koden skifter hvert "
        "30. sekund.</span></li></ul>", title="Godt at vide")
    body = (f'<div class="grid grid-main"><div class="stack"><div class="card wizard">{step1}{step2}{step3}</div></div>'
            f'<div class="stack">{help_card}</div></div>')
    return kit.render_page("Slå to-trins-login til", body, active="me",
                           subtitle="Tre trin – det tager et par minutter.",
                           breadcrumbs=[("Min konto", "/me"), ("To-trins-login", None)])


def _codes_page(name: str, codes: list[str], *, first: bool, how: str = "app") -> Response:
    shown = [format_recovery(c) for c in codes]
    blob = (f"{TOTP_ISSUER} – genoprettelseskoder for {name}\n"
            f"Lavet {kit.fmt_ts(int(time.time()))}. Hver kode virker kun én gang.\n\n" + "\n".join(shown) + "\n")
    grid = '<ol class="codes-grid">' + "".join(f'<li><code class="mono">{kit.h(c)}</code></li>' for c in shown) + "</ol>"
    use = "en kode fra mailen" if how == "mail" else "koden fra appen"
    head = (kit.alert(f"To-trins-login er slået til. Næste gang du logger ind, skal du bruge {use}.", "ok",
                      title="Færdig")
            if first else kit.alert("Dine gamle genoprettelseskoder virker ikke længere.", "ok", title="Nye koder"))
    actions = ('<div class="codes-actions">'
               + kit.button("Kopiér alle", kind="secondary", icon="copy",
                            attrs=f'type="button" data-copy-text="{kit.h(blob)}" data-copy-label="Koderne"')
               + kit.button("Hent som fil", kind="secondary", icon="download",
                            attrs=f'type="button" data-download-text="{kit.h(blob)}" '
                                  'data-download-name="spamfilter-genoprettelseskoder.txt"')
               + "</div>")
    card = kit.card(
        '<p class="muted">Mister du telefonen eller adgangen til din mail, kan du logge ind med én af disse koder. '
        "Hver kode virker kun én gang.</p>"
        + grid + actions
        + kit.alert("Koderne vises kun nu. Gem dem et sikkert sted – fx i din adgangskode-app eller på papir – "
                    "ikke kun på telefonen.", "warn")
        + '<div class="form-actions">' + kit.button("Jeg har gemt koderne", href="/me", kind="primary", icon="check")
        + "</div>", title="Dine genoprettelseskoder", cls="codes-card")
    body = f'<div class="codes-wrap">{head}{card}</div>'
    html = kit.render_page("Genoprettelseskoder", body, active="me",
                           breadcrumbs=[("Min konto", "/me"), ("Genoprettelseskoder", None)])
    return Response(html, mimetype="text/html")


def _pending_verify_address(name: str) -> str | None:
    """The address of the user's newest unused, unexpired 'verify' code."""
    _ensure_ui_db()
    conn = _connect()
    try:
        row = conn.execute("SELECT email FROM ui_mail_codes WHERE name=? AND purpose='verify' AND used_at IS NULL "
                           "AND expires_at>? AND attempts<? ORDER BY id DESC LIMIT 1",
                           (name, int(time.time()), MAIL_CODE_MAX_TRIES)).fetchone()
    finally:
        conn.close()
    return str(row[0]) if row else None


def _choose_page(name: str) -> str:
    """Two ways to do two-step login (only when a mail server is set up)."""
    admin = bool((current_user() or {}).get("is_admin"))
    tiles = (
        '<div class="twofa-choose">'
        f'<a class="twofa-choice is-recommended" href="/me/2fa/setup?method=app">{kit.icon("smartphone", "twofa-choice-icon")}'
        '<span class="twofa-choice-text"><b>Authenticator-app</b>'
        "<span>En 6-cifret kode fra en app på telefonen. Virker uden net – og beskytter dig, selv hvis nogen får adgang til din mail.</span>"
        f'{kit.chip("Anbefales" + (" til administratorer" if admin else ""), "ok")}</span>'
        f'{kit.icon("chevron-right", "twofa-choice-go")}</a>'
        f'<a class="twofa-choice" href="/me/2fa/setup?method=mail">{kit.icon("mail", "twofa-choice-icon")}'
        '<span class="twofa-choice-text"><b>Kode på mail</b>'
        "<span>Vi mailer dig en kode, når du logger ind. Ingen app – men kun så sikkert som din mailkonto.</span>"
        f'{kit.chip("Nemmest", "neutral")}</span>{kit.icon("chevron-right", "twofa-choice-go")}</a>'
        "</div>"
        '<p class="faint small mt-1">Du kan altid tilføje den anden metode bagefter – så kan du logge ind med begge.</p>')
    body = f'<div class="narrow-wrap">{kit.card(tiles, title="Vælg metode", subtitle="Hvordan vil du have din kode?")}</div>'
    return kit.render_page("Slå to-trins-login til", body, active="me", subtitle="Vælg den måde, du vil få koden på.",
                           breadcrumbs=[("Min konto", "/me"), ("To-trins-login", None)])


def _mail_setup_page(name: str, *, error: str = "", note: str = "", email: str = "",
                     code_error: str = "") -> str:
    tf = twofa_status(name)
    pending = _pending_verify_address(name)
    shown = email or pending or ""
    if not shown and tf["mail"]:
        shown = ""  # never prefill the current address in full; the user types the new one
    send_form = kit.post_form(
        "/me/2fa/confirm",
        kit.hidden("method", "mail") + kit.hidden("step", "send")
        + kit.form_field("Din mailadresse", kit.input_(
            "email", shown, type="email",
            attrs='id="mail-2fa-email" autocomplete="email" inputmode="email" autocapitalize="none" '
                  'spellcheck="false" maxlength="254" required'),
            hint=("Brug en adresse, som kun du kan læse – gerne en anden end den, spamfilteret overvåger."),
            error=error)
        + '<div class="form-actions">' + kit.button("Send kode" if not pending else "Send en ny kode",
                                                    kind="secondary" if pending else "primary", icon="send")
        + "</div>", ajax=False, cls="enroll-mail")
    step1 = kit.wizard_step(1, "Skriv din mailadresse", "Vi sender en kode for at sikre, at adressen er din.",
                            send_form)
    if pending:
        sent = (kit.alert(note, "info") if note else
                kit.alert(f"Koden er sendt til {mailer.mask_address(pending)}. Den gælder i "
                          f"{MAIL_CODE_TTL // 60} minutter.", "info"))
        verify = kit.post_form(
            "/me/2fa/confirm",
            kit.hidden("method", "mail") + kit.hidden("step", "verify")
            + kit.form_field("6-cifret kode", kit.otp_input("code", id="mail-setup-code", recovery=False,
                                                             autofocus=True), error=code_error)
            + '<div class="form-actions">' + kit.button("Slå kode på mail til", kind="primary", icon="shield-check")
            + "</div>", ajax=False, cls="enroll-confirm")
        step2 = kit.wizard_step(2, "Bekræft med koden fra mailen", "Tjek også spam-mappen, hvis den ikke kommer.",
                                sent + verify)
    else:
        step2 = kit.wizard_step(2, "Bekræft med koden fra mailen", "Når du har fået koden, skriver du den her.",
                                '<p class="faint small">Send koden først.</p>')
    help_card = kit.card(
        '<ul class="help-list">'
        "<li><b>App eller mail?</b><span>Appen er sikrest: kode på mail hjælper ikke, hvis nogen får adgang til "
        "din mailkonto. Administratorer bør bruge appen.</span></li>"
        "<li><b>Kommer mailen ikke?</b><span>Tjek spam-mappen. Du kan bede om en ny kode efter et minut – højst "
        f"{MAIL_CODE_MAX_SENDS} gange på {MAIL_CODE_WINDOW // 60} minutter.</span></li>"
        "<li><b>Mister du adgangen?</b><span>Brug en genoprettelseskode, eller bed en administrator om at nulstille "
        "to-trins-login.</span></li></ul>", title="Godt at vide")
    body = (f'<div class="grid grid-main"><div class="stack"><div class="card wizard">{step1}{step2}</div></div>'
            f'<div class="stack">{help_card}</div></div>')
    return kit.render_page("Kode på mail", body, active="me",
                           subtitle="To trin – det tager et minut.",
                           breadcrumbs=[("Min konto", "/me"), ("To-trins-login", None)])


# 2.3: adding, replacing or swapping a second factor needs a fresh proof of
# an EXISTING factor (TOTP, a code to the current verified address or a
# recovery code) - a stolen or left-open session must not be able to
# enrol the attacker's own app/address and then turn the real one off.
TWOFA_REAUTH_TTL = 10 * 60
REAUTH_TARGETS = {"app": "/me/2fa/setup?method=app", "mail": "/me/2fa/setup?method=mail",
                  "passkey": "/me/passkeys/confirm"}   # 2.6 (B1): adding/removing passkeys


def _mark_reauth(name: str) -> None:
    session["reauth_2fa"] = [name, int(time.time())]


def _reauth_fresh(name: str) -> bool:
    """True when `name` has no second factor yet (nothing to prove) or this
    session proved one within TWOFA_REAUTH_TTL."""
    if not twofa_status(name)["enabled"]:
        return True
    val = session.get("reauth_2fa")
    if not isinstance(val, list) or len(val) != 2 or val[0] != name:
        return False
    try:
        return 0 <= time.time() - int(val[1]) <= TWOFA_REAUTH_TTL
    except (TypeError, ValueError):
        return False


def _reauth_target(value: str | None) -> str:
    v = str(value or "")
    return v if v in REAUTH_TARGETS.values() else "/me"


def _reauth_page(name: str, target: str, *, error: str = "", status: int = 200) -> Response:
    """'Bekræft, at det er dig': a code from a method that is already on."""
    tf = twofa_status(name)
    what = "en app" if target.endswith("=app") else "en ny mailadresse"
    form = kit.post_form(
        "/me/2fa/confirm",
        kit.hidden("method", "reauth") + kit.hidden("next", target)
        + kit.form_field(_code_label(tf), kit.otp_input("code", id="reauth-code", autofocus=True), error=error)
        + '<div class="form-actions">' + kit.button("Bekræft", kind="primary", icon="shield-check") + "</div>",
        ajax=False, cls="twofa-form")
    sendcode = _send_code_form(tf, next_url=target)
    if sendcode:
        lead = "Har du ikke appen ved hånden? Få en kode på mail:" if tf["totp"] else "Få koden på mail:"
        sendcode = (f'<div class="twofa-sendcode-sect mt-1"><p class="muted small">{lead}</p>{sendcode}</div>')
    card = kit.card(
        f'<p class="muted mb-1">Før du tilføjer {what} til dit to-trins-login, skal du bekræfte med en kode fra '
        "det, du allerede bruger. Så kan ingen, der har fået fat i en åben session, skifte din metode ud.</p>"
        + form + sendcode,
        title="Bekræft, at det er dig")
    body = f'<div class="narrow-wrap">{card}</div>'
    html = kit.render_page("Bekræft med din kode", body, active="me",
                           subtitle="Ændringer af to-trins-login kræver en kode.",
                           breadcrumbs=[("Min konto", "/me"), ("To-trins-login", None)])
    return Response(html, status=status, mimetype="text/html")


def _reauth_required(name: str, target: str):
    """None when the change may go on, else the reply that asks for a code."""
    if _reauth_fresh(name):
        return None
    audit("twofa_reauth", result="required")
    if request.method == "GET":
        return _reauth_page(name, target)
    return respond("Bekræft først med en kode fra den metode, du allerede bruger.", ok=False, status=403,
                   next_url=target)


@app.get("/me/2fa/setup")
@login_required
def me_2fa_setup():
    name = _me_name()
    tf = twofa_status(name)
    method = request.args.get("method") or ""
    avail = mail_2fa_available()
    if method == "mail":
        if not avail:
            flash("Kode på mail kræver, at en administrator har sat en mailserver op.", "info")
            return redirect("/me")
        gate = _reauth_required(name, REAUTH_TARGETS["mail"])
        if gate is not None:
            return gate
        return Response(_mail_setup_page(name), mimetype="text/html")
    if method != "app" and avail and not tf["enabled"]:
        return Response(_choose_page(name), mimetype="text/html")
    if tf["totp"] or (method != "app" and tf["enabled"]):
        flash("To-trins-login er allerede slået til." if not tf["totp"] or tf["mail"] or not avail
              else "Authenticator-appen er allerede slået til.", "info")
        return redirect("/me")
    gate = _reauth_required(name, REAUTH_TARGETS["app"])
    if gate is not None:
        return gate
    return Response(_setup_page(name, twofa_pending_secret(name) or ""), mimetype="text/html")


def _mail_confirm(name: str):
    """POST /me/2fa/confirm with method=mail: step=send (code to a new
    address), step=verify (turn mail codes on), step=code (a confirmation
    code to the verified address for changes on Min konto)."""
    step = request.form.get("step") or ""
    if step == "code":
        ok, text = send_login_code(name, template="manage")
        return respond(text, ok=ok, next_url=_reauth_target(request.form.get("next")), status=429)
    if not mail_2fa_available():
        return respond("Mailserveren er ikke sat op, så kode på mail kan ikke bruges lige nu.", ok=False,
                       next_url="/me")
    if step in ("send", "verify"):
        gate = _reauth_required(name, REAUTH_TARGETS["mail"])
        if gate is not None:
            return gate
    if step == "send":
        raw = (request.form.get("email") or "")[:300]
        try:
            addr = mailer.validate_address(raw)
        except mailer.MailError:
            return Response(_mail_setup_page(name, error="Skriv en gyldig mailadresse, fx navn@domæne.dk.",
                                             email=raw.strip()[:254]), status=400, mimetype="text/html")
        res = mail_code_issue(name, addr, "verify")
        masked = mailer.mask_address(addr)
        audit("twofa_mail_code", result="sent" if res["code"] in ("sent", "error") else res["code"],
              detail=f"bekræft {masked}")
        if res["code"] == "wait":
            return Response(_mail_setup_page(name, error=f"Du kan bede om en ny kode om {_wait_text(res['wait'])}.",
                                             email=addr), status=429, mimetype="text/html")
        if res["code"] == "unavailable":
            return Response(_mail_setup_page(name, error="Mailserveren kan ikke sende lige nu. Prøv igen senere.",
                                             email=addr), status=503, mimetype="text/html")
        return Response(_mail_setup_page(name, note=f"Koden er på vej til {masked}. Den gælder i "
                                                    f"{MAIL_CODE_TTL // 60} minutter – tjek også spam-mappen."),
                        mimetype="text/html")
    if step != "verify":
        abort(400)
    keys = [f"2fa:{name.lower()}"]
    wait = _throttle_begin(keys)
    if wait:
        audit("twofa_mail_enable", result="locked")
        return Response(_mail_setup_page(name, code_error=f"For mange forkerte koder. Prøv igen om "
                                                          f"{max(1, (wait + 59) // 60)} min."),
                        status=429, mimetype="text/html")
    addr = mail_code_check(name, "verify", request.form.get("code"))
    if addr is None:
        audit("twofa_mail_enable", result="failed")
        return Response(_mail_setup_page(name, code_error="Koden passer ikke eller er udløbet. Brug koden fra den "
                                                          "nyeste mail – eller send en ny."),
                        status=400, mimetype="text/html")
    _throttle_reset(keys)
    old = twofa_mail_address(name)
    codes = twofa_mail_enable(name, addr, actor=name)
    session["mfa"] = 1          # this session just proved a second factor
    _mark_reauth(name)
    g.pop("_user", None)
    masked = mailer.mask_address(addr)
    audit("twofa_mail_enable", detail=masked)
    security_notice(name, "kode på mail er slået til",
                    f"Login-koder til spamfilteret sendes nu til {masked}.")
    if old and old.lower() != addr.lower():
        try:
            mail().notify("security", "Spamfilter: login-koder sendes nu til en anden adresse",
                          f"Login-koder for {name} sendes ikke længere til denne adresse, men til {masked}.\n\n"
                          "Var det ikke dig? Bed en administrator om hjælp med det samme.", recipients=[old])
        except Exception as ex:  # noqa: BLE001
            log.warning("old-address notice not sent: %s", type(ex).__name__)
    if codes:
        return _codes_page(name, codes, first=True, how="mail")
    flash(f"Kode på mail er slået til. Koder sendes til {masked}.", "ok")
    return redirect("/me")


@app.post("/me/2fa/confirm")
@login_required
def me_2fa_confirm():
    name = _me_name()
    method = request.form.get("method") or "app"
    if method == "reauth":
        target = _reauth_target(request.form.get("next"))
        if not twofa_status(name)["enabled"]:
            return redirect(target)
        err = _check_own_code(name, "twofa_reauth", next_url=target)
        if err is not None:
            return err
        _mark_reauth(name)
        audit("twofa_reauth")
        return redirect(target)
    if method == "mail":
        return _mail_confirm(name)
    if twofa_status(name)["totp"]:
        return redirect("/me")
    gate = _reauth_required(name, REAUTH_TARGETS["app"])
    if gate is not None:
        return gate
    keys = [f"2fa:{name.lower()}"]
    wait = _throttle_begin(keys)
    if wait:
        audit("twofa_enable", result="locked")
        msg = f"For mange forkerte koder. Prøv igen om {max(1, (wait + 59) // 60)} min."
        return Response(_setup_page(name, twofa_pending_secret(name) or "", error=msg), status=429, mimetype="text/html")
    codes = twofa_confirm(name, request.form.get("code") or "", actor=name)
    if codes is None:
        audit("twofa_enable", result="failed")
        msg = "Koden passer ikke. Brug den nyeste kode fra appen – og tjek, at telefonens ur står rigtigt."
        return Response(_setup_page(name, twofa_pending_secret(name) or "", error=msg), status=400,
                        mimetype="text/html")
    _throttle_reset(keys)
    session["mfa"] = 1          # this session just proved the second factor
    _mark_reauth(name)
    g.pop("_user", None)
    audit("twofa_enable")
    security_notice(name, "to-trins-login med app er slået til",
                    "En authenticator-app er nu sat op til to-trins-login.")
    if not codes:
        flash("Authenticator-appen er tilføjet. Dine genoprettelseskoder er de samme som før.", "ok")
        return redirect("/me")
    return _codes_page(name, codes, first=True)


def _check_own_code(name: str, action: str, next_url: str = "/me"):
    """Throttled code check for a change to your own 2FA; returns an
    error response or None."""
    keys = [f"2fa:{name.lower()}"]
    wait = _throttle_begin(keys)
    if wait:
        audit(action, result="locked")
        return respond(f"For mange forkerte koder. Prøv igen om {max(1, (wait + 59) // 60)} min.", ok=False,
                       status=429, next_url=next_url)
    if twofa_verify(name, request.form.get("code")) is None:
        audit(action, result="failed")
        tf = twofa_status(name)
        msg = ("Koden passer ikke. Brug den nyeste kode fra appen." if not tf["mail"]
               else "Koden passer ikke. Brug den nyeste kode fra appen eller mailen.")
        return respond(msg, ok=False, next_url=next_url)
    _throttle_reset(keys)
    return None


@app.post("/me/2fa/recovery")
@login_required
def me_2fa_recovery():
    name = _me_name()
    if not twofa_status(name)["enabled"]:
        return respond("To-trins-login er ikke slået til.", ok=False, next_url="/me")
    err = _check_own_code(name, "twofa_recovery_new")
    if err is not None:
        return err
    codes = twofa_new_recovery(name, actor=name) or []
    audit("twofa_recovery_new")
    security_notice(name, "nye genoprettelseskoder", "Der er lavet nye genoprettelseskoder; de gamle virker ikke længere.")
    return _codes_page(name, codes, first=False)


METHOD_WORDS = {"totp": "Authenticator-appen", "mail": "Kode på mail", "all": "To-trins-login"}


@app.post("/me/2fa/disable")
@login_required
def me_2fa_disable():
    name = _me_name()
    tf = twofa_status(name)
    if not tf["enabled"]:
        return respond("To-trins-login er ikke slået til.", ok=False, next_url="/me")
    method = {"app": "totp"}.get(request.form.get("method") or "all", request.form.get("method") or "all")
    if method not in TWOFA_METHODS:
        method = "all"
    if (method == "totp" and not tf["totp"]) or (method == "mail" and not tf["mail"]):
        return respond("Den metode er ikke slået til.", ok=False, next_url="/me")
    remaining = (method == "totp" and tf["mail"]) or (method == "mail" and tf["totp"])
    if tf["required"] and not remaining:
        return respond("Din administrator kræver to-trins-login, så det kan ikke slås fra.", ok=False, status=403,
                       next_url="/me")
    err = _check_own_code(name, "twofa_disable")
    if err is not None:
        return err
    old_addr = twofa_mail_address(name)
    twofa_disable(name, actor=name, method=method)
    audit("twofa_disable", detail="" if method == "all" else method)
    what = f"{METHOD_WORDS[method]} er slået fra."
    security_notice(name, what.rstrip(".").lower(), what, also=[old_addr])
    return respond("To-trins-login er slået fra." if method == "all" else what, next_url="/me", refresh=True)


@app.post("/me/logout-all")
@login_required
def me_logout_all():
    name = _me_name()
    try:
        bump_generation(name)
    except ValueError:
        return respond("Denne bruger kommer fra en miljøvariabel og kan ikke logges ud overalt herfra.", ok=False,
                       next_url="/me")
    audit("user_logout_all", detail=name)
    msg = "Du er logget ud overalt."
    if logout_all_wants_passkeys_removed() and (n := remove_all_passkeys(name)):
        audit("passkey_reset", detail=f"{name} ({n})")
        security_notice(name, "passkeys fjernet", "Du har logget ud overalt. " + passkeys_removed_text(n))
        msg = f"Du er logget ud overalt, og {'din passkey' if n == 1 else f'dine {n} passkeys'} er fjernet."
    session.clear()
    flash(msg, "info")
    if wants_json():
        return json_ok(msg, redirect="/login")
    return redirect("/login")


# ---------------------------------------------------------------------------
# PWA: manifest, service worker, offline page, home-screen icons
# ---------------------------------------------------------------------------

PWA_NAME = siteconfig.brand()
PWA_SHORT_NAME = "Spamfilter"
THEME_DARK = kit.THEME_DARK
THEME_LIGHT = kit.THEME_LIGHT
PWA_ICONS = (("icon-192.png", "192x192", "any"), ("icon-512.png", "512x512", "any"),
             ("icon-maskable-192.png", "192x192", "maskable"), ("icon-maskable-512.png", "512x512", "maskable"))
SW_PRECACHE = ("app.css", "app.js", "icons.svg", "icon-192.png")


@app.get("/manifest.webmanifest")
@public
def manifest():
    data = {
        "id": "/",
        "name": PWA_NAME,
        "short_name": PWA_SHORT_NAME,
        "description": "Selvhostet spamfilter: fanget spam, regler og status for dine postkasser.",
        "lang": "da",
        "dir": "ltr",
        "start_url": "/",
        "scope": "/",
        "display": "standalone",
        "background_color": THEME_DARK,
        "theme_color": THEME_DARK,
        "categories": ["productivity", "utilities"],
        "icons": [{"src": static_url(f), "sizes": s, "type": "image/png", "purpose": p} for f, s, p in PWA_ICONS],
        "shortcuts": [{"name": "Fanget spam", "short_name": "Spam", "url": "/spam",
                       "icons": [{"src": static_url("icon-192.png"), "sizes": "192x192", "type": "image/png"}]}],
    }
    body = json.dumps(data, ensure_ascii=False, indent=1)
    return Response(body, mimetype="application/manifest+json")


@app.get("/sw.js")
@public
def service_worker():
    """Served from the root so its scope is the whole app. The asset list
    carries the cache-busting tag, so any asset change installs a new
    worker that drops the old cache."""
    src = (STATIC_DIR / "sw.js").read_text(encoding="utf-8")
    tag = static_url("app.css").rsplit("?v=", 1)[-1]
    src = (src.replace("__SF_VERSION__", json.dumps(tag))
              .replace("__SF_ASSETS__", json.dumps([static_url(n) for n in SW_PRECACHE])))
    return Response(src, mimetype="text/javascript")


@app.get("/offline")
@public
def offline():
    """Shown by the service worker when the filter cannot be reached. No
    session, no user data: safe to cache."""
    return Response(kit.render_offline_page(), mimetype="text/html")


@app.get("/apple-touch-icon.png")
@app.get("/apple-touch-icon-precomposed.png")
@public
def apple_touch_icon():
    # iOS asks for these at the site root when no link tag matched.
    return send_file(STATIC_DIR / "apple-touch-icon.png", mimetype="image/png", max_age=86400)


# ---------------------------------------------------------------------------
# Errors (Danish, inside the layout when logged in)
# ---------------------------------------------------------------------------

ERROR_TEXTS = {
    400: ("Ugyldig forespørgsel", "Forespørgslen kunne ikke behandles. Genindlæs siden og prøv igen."),
    401: ("Log ind først", "Du skal være logget ind for at se denne side."),
    403: ("Ingen adgang", "Du har ikke adgang til denne side eller konto."),
    404: ("Siden findes ikke", "Adressen er forkert, eller beskeden er ikke længere i databasen."),
    405: ("Ikke tilladt", "Denne handling kan ikke udføres på den måde."),
    413: ("For stor forespørgsel", "Der blev sendt for meget data på én gang."),
    429: ("For mange forsøg", "Vent et øjeblik og prøv igen."),
    500: ("Noget gik galt", "Der skete en uventet fejl. Prøv igen om lidt – fejlen er logget."),
    503: ("Databasen er optaget", "Filterets database svarer ikke lige nu. Prøv igen om et øjeblik."),
}


def render_error(code: int, title: str | None = None, text: str | None = None):
    t, x = ERROR_TEXTS.get(code, ERROR_TEXTS[500])
    title, text = title or t, text or x
    if has_request_context() and code == 400 and getattr(request, "_csrf_failed", False):
        text = "Sikkerhedstokenet passede ikke. Genindlæs siden og prøv igen."
    if wants_json():
        return json_err(text, code)
    try:
        user = current_user()
    except Exception:  # noqa: BLE001
        user = None
    body = kit.error_body(code, title, text, logged_in=user is not None)
    try:
        if user is not None:
            html = kit.render_page(title, body, active="", subtitle="")
        else:
            html = kit.render_auth_page(title, body)
    except Exception as ex:  # noqa: BLE001 - last resort: plain page
        log.error("error page rendering failed: %s", type(ex).__name__)
        html = f"<!doctype html><title>{code}</title><h1>{kit.h(title)}</h1><p>{kit.h(text)}</p>"
    return Response(html, status=code, mimetype="text/html")


@app.errorhandler(HTTPException)
def _http_error(ex: HTTPException):
    if ex.code == 400 and ex.description == "csrf":
        request._csrf_failed = True  # type: ignore[attr-defined]
    if ex.code in (301, 302, 303, 307, 308):
        return ex
    return render_error(ex.code or 500)


@app.errorhandler(sqlite3.Error)
def _db_error(ex: sqlite3.Error):
    log.error("dashboard DB error: %s", type(ex).__name__)
    return render_error(503)


@app.errorhandler(Exception)
def _unhandled(ex: Exception):
    if isinstance(ex, HTTPException):
        return _http_error(ex)
    log.exception("unhandled dashboard error: %s", type(ex).__name__)
    return render_error(500)


# ---------------------------------------------------------------------------
# Page modules + entrypoint
# ---------------------------------------------------------------------------


def register_pages() -> None:
    """Import the page modules (they register routes on import). ui_admin
    is optional while it is being developed."""
    import ui_mail  # noqa: F401
    import ui_tools  # noqa: F401  (Find en mail, Fortryd flytninger, Hjælp)
    import passkeys  # noqa: F401  (2.6: passkey login + Min konto -> Passkeys)

    try:
        import ui_admin  # noqa: F401
    except ModuleNotFoundError as ex:
        if ex.name != "ui_admin":
            raise
        log.warning("ui_admin.py not found; administration pages are disabled")


# waitress strips X-Forwarded-* by default (clear_untrusted_proxy_headers);
# ProxyHeaders decides what to trust (TRUSTED_PROXIES), so it must see them.
SERVE_OPTIONS = {"host": "0.0.0.0", "port": DASHBOARD_PORT, "threads": 6, "ident": "spamfilter",
                 "clear_untrusted_proxy_headers": False}


def start() -> None:
    """Start the web UI in a daemon thread (called from filter.main()).

    Always starts - even with no users - so /healthz answers for the
    container healthcheck; the login page then explains how to add one."""
    from waitress import serve

    app.secret_key = _load_secret()
    try:
        init_ui_db()
        check_external_config_change()
    except (sqlite3.Error, OSError) as ex:
        log.error("UI DB init failed: %s", type(ex).__name__)
    register_pages()
    try:
        mail().ensure_worker()  # outgoing mail (codes, notices) without blocking a request
    except Exception as ex:  # noqa: BLE001 - mail is optional, the UI is not
        log.error("mail worker not started: %s", type(ex).__name__)
    try:
        import ui_push  # noqa: PLC0415

        ui_push._push().ensure_schema()
        ui_push._push().ensure_worker()  # 2.5.0 push notifications (idempotent; the engine starts it too)
    except Exception as ex:  # noqa: BLE001 - push is optional, the UI is not
        log.error("push worker not started: %s", type(ex).__name__)
    users = load_users()
    if not users:
        log.warning("no dashboard users configured; add one with `python /app/dashboard.py`")
    log.info("dashboard on 0.0.0.0:%d (%d user(s))", DASHBOARD_PORT, len(users))

    def _serve() -> None:
        try:
            serve(app, **SERVE_OPTIONS)
        except Exception as ex:  # noqa: BLE001
            log.error("dashboard crashed: %s", type(ex).__name__)

    threading.Thread(target=_serve, name="dashboard", daemon=True).start()


def _known_accounts() -> set[str] | None:
    try:
        raw = yaml.safe_load(CONFIG_PATH.read_text()) or {}
        names = {str(a["name"]).strip() for a in (raw.get("accounts") or [])
                 if isinstance(a, dict) and a.get("name")}
        return names or None
    except Exception:  # noqa: BLE001
        return None


def _cli_add_user() -> None:
    """Interactive helper: add or update a dashboard user."""
    import getpass

    name = input("brugernavn: ").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
        raise SystemExit("brugernavn: 1-64 tegn, kun bogstaver, tal og . _ -")
    pw1 = getpass.getpass("adgangskode (mindst 12 tegn): ")
    pw2 = getpass.getpass("gentag: ")
    if pw1 != pw2:
        raise SystemExit("adgangskoderne er ikke ens")
    if len(pw1) < 12:
        raise SystemExit("adgangskoden skal være mindst 12 tegn")
    known = _known_accounts()
    if known:
        print("konti:", ", ".join(sorted(known)))
    raw_scope = input("adgang - 'admin' eller kontonavne adskilt med komma [admin]: ").strip() or "admin"
    if raw_scope.lower() == "admin":
        scope_names: frozenset[str] = frozenset()
        is_admin = True
    else:
        wanted = [a.strip() for a in re.split(r"[|,]", raw_scope) if a.strip()]
        if known and any(a not in known for a in wanted):
            raise SystemExit(f"ukendt konto: {', '.join(a for a in wanted if a not in known)}")
        scope_names, is_admin = frozenset(wanted), False
    users = {n: u for n, u in load_users().items() if u.source == "file"}
    old = users.get(name)
    users[name] = User(name, hash_password(pw1), is_admin, scope_names,
                       (old.gen + 1) if old else int(time.time()))  # never reuse a removed gen
    write_users(users.values())
    print(f"gemt: {name} ({'admin' if is_admin else ', '.join(sorted(scope_names))})")


def _cli_reset_2fa(name: str) -> None:
    """Turn off a user's two-step login (lost phone, no recovery codes)."""
    if name not in load_users():
        raise SystemExit(f"ukendt bruger: {name}")
    init_ui_db()
    if not twofa_status(name)["enabled"]:
        print(f"{name} har ikke to-trins-login slået til")
        return
    twofa_disable(name, actor="cli")
    audit("twofa_reset", detail=name, actor="cli")
    print(f"to-trins-login for {name} er slået fra; {name} kan logge ind med adgangskoden og sætte det op igen")


if __name__ == "__main__":
    import sys

    if len(sys.argv) == 3 and sys.argv[1] == "--reset-2fa":
        _cli_reset_2fa(sys.argv[2].strip())
    elif len(sys.argv) > 1:
        raise SystemExit("brug: python dashboard.py            (tilføj/opdatér bruger)\n"
                         "      python dashboard.py --reset-2fa <navn>")
    else:
        _cli_add_user()
