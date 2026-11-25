"""Push notifications on the phone (2.5.0): subscriptions, routing, queue.

'Push-beskeder direkte i appen' - when a dangerous mail is stopped, new
mail lands under 'Tjek disse', or the filter has a problem. The protocol
(VAPID, RFC 8291 encryption, the HTTP POST) lives in webpush.py; this
module owns everything with users and the database:

  push_subscriptions  one row per browser/device (UNIQUE endpoint), per
                      device preferences (JSON {threat, review, problem}),
                      at most MAX_PER_USER per user
  push_queue          what is waiting to be sent, ONE row per (user, tag)
                      while queued: a second event of the same kind is
                      merged into it (counts add up)
  push_marks          which threat_notices / Tjek-disse mails have already
                      been counted (never twice)
  settings_kv         'push:*' keys (review batching, 'push:refused')

All tables are new and additive: 2.4.1 ignores them, so a rollback keeps
working on a migrated database.

Privacy rule (SECURITY.md): a push payload is the JSON {title, body, url,
tag} and holds ONLY counts and mailbox display names - never a subject,
a sender, an address or anything else from a mail. Routing is decided per
user from the users file: a threat or Tjek-disse event of a mailbox goes
only to users who can see that mailbox (admins: all), problems only to
administrators, and it is checked AGAIN when the message is rendered, so a
user whose access was narrowed in between gets nothing of the old mailbox.
The 2.6 login alerts (LOGIN_KINDS) are about the user's own login, not
about mail: they carry a browser/OS label, a time and an IP address.

Rate limits per user: at most one push per tag per TAG_INTERVAL (10 min;
later events wait and are merged) and DAILY_MAX (20) per rolling 24 h.
Tjek disse is batched per mailbox (REVIEW_BATCH, 30 min).

Sending runs in one background thread per process (ensure_worker(),
idempotent - the engine and the dashboard both call it; they share one
process) and never blocks the engine: the engine hooks only write a queue
row with the engine's own connection and wake the worker. Network trouble
(timeouts, 429, 5xx) backs off; 404/410 delete the subscription. A
device the push service calls bad (BadDeviceToken & co.) is removed after
REJECT_DELETE refusals in a row; any OTHER refusal (401/403/400/413:
VAPID JWT, clock skew, 'sub', payload) is the service refusing the filter
itself, so every device is kept and the refusal is recorded under
settings_kv 'push:refused' for sfctl doctor / push-status (2.5.0).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator
from urllib.parse import quote

log = logging.getLogger("push")

STATE_DIR = Path(os.environ.get("STATE_DIR", "/state"))
CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", "/config/accounts.yml"))
DB_PATH = STATE_DIR / "spamfilter.db"
USERS_FILE = STATE_DIR / "dashboard_users"


def configure_paths(state_dir: Path | str | None = None, config_path: Path | str | None = None,
                    *, db_path: Path | str | None = None, users_file: Path | str | None = None) -> None:
    global STATE_DIR, CONFIG_PATH, DB_PATH, USERS_FILE
    if state_dir is not None:
        STATE_DIR = Path(state_dir)
        DB_PATH = STATE_DIR / "spamfilter.db"
        USERS_FILE = STATE_DIR / "dashboard_users"
    if config_path is not None:
        CONFIG_PATH = Path(config_path)
    if db_path is not None:
        DB_PATH = Path(db_path)
    if users_file is not None:
        USERS_FILE = Path(users_file)


# ---------------------------------------------------------------------------
# Vocabulary + limits
# ---------------------------------------------------------------------------

KINDS = ("threat", "review", "problem")
PREF_DEFAULTS = {"threat": True, "review": False, "problem": True}
PREF_LABELS = {"threat": "Farlige mails stoppet", "review": "Nye mails under Tjek disse",
               "problem": "Problemer med filteret"}
PREF_HINTS = {"threat": "Når filteret har lagt en farlig mail (virus, phishing) i Spamfilter-mappen.",
              "review": "Højst én besked pr. halve time pr. postkasse.",
              "problem": "Login afvist, sikkerhedsbremse, sikkerhedstilstand, nedetid og gentagne forkerte "
                         "login-forsøg på spamfilteret."}
ADMIN_ONLY_KINDS = frozenset({"problem"})

MAX_PER_USER = 10
TAG_INTERVAL = 10 * 60          # one push per tag per user per 10 min
DAILY_MAX = 20                  # pushes per user per rolling 24 h (test messages excluded)
REVIEW_BATCH = 30 * 60          # Tjek disse: one push per mailbox per 30 min
LOOKBACK = 6 * 3600             # events older than this are never pushed (no floods after an outage)
TEST_MAX = 5                    # test messages per user ...
TEST_WINDOW = 10 * 60           # ... per this window
MAX_ATTEMPTS = 5
BACKOFF = (60, 300, 900, 1800, 3600)
REJECT_DELETE = 3               # a subscription rejected this many times in a row is removed
REFUSED_KEY = "push:refused"    # settings_kv: the last server-wide refusal (never deletes a device)
WORKER_POLL = 30
KEEP_DAYS = 7                   # finished queue rows / marks
UA_MAX = 40
TITLE_MAX = 80
BODY_MAX = 180
TTL = {"threat": 6 * 3600, "review": 12 * 3600, "problem": 24 * 3600, "test": 600,
       "login": 6 * 3600, "login_failed": 6 * 3600}
URGENCY = {"threat": "high", "review": "normal", "problem": "high", "test": "high", "login": "high",
           "login_failed": "high"}
TAG_OF = {"threat": "sf-threat", "review": "sf-review", "problem": "sf-problem", "test": "sf-test",
          "login": "sf-login", "login_failed": "sf-login-failed"}
# 2.6 (B2) login alerts - queue kinds without their own switch:
#   login         "Nyt login på din konto" -> EVERY device of that user (a
#                 security notice about the own account; turning push on
#                 for the device is the opt-in)
#   login_failed  repeated failed logins -> administrators' devices that
#                 want 'problem' (Problemer med filteret)
# Unlike the other kinds these payloads name a browser/OS label, a time
# and an IP address (never a password, code, cookie or token).
LOGIN_KINDS = ("login", "login_failed")
LOGIN_KEEP = 3                  # merged login events kept per queued row

# Engine alerts (filter.alert_once keys + the downtime notice) -> push text.
PROBLEMS = {
    "auth": ("Login afvist", "Mailserveren afviser login for {name}. Tjek adgangskoden under Konti.", "/accounts"),
    "circuit": ("Sikkerhedsbremsen er slået til", "Flytning er sat på pause for {name}. Tjek Fanget spam og "
                "genoptag under Konti.", "/accounts"),
    "safe": ("Sikkerhedstilstand", "Filteret behandler ikke nye mails i {name} lige nu (for mange ulæste).",
             "/accounts"),
    "downtime": ("Filteret kører igen", "Spamfilteret har været stoppet og kører igen nu.", "/system"),
    # 2.6 (A6): spam over the normal threshold piles up at a protected address.
    "protected": ("Spam i en beskyttet indbakke", "Spam over grænsen samler sig hos en beskyttet adresse i {name}. "
                  "Overvej at sænke grænsen for beskyttede adresser.", "/accounts"),
    # 2.6 (B3): backup.check_alert
    "backup": ("Backup mangler", "Der er ikke lavet en krypteret backup i over 48 timer. Se Drift.", "/system"),
    # 2.7: mailcheck.process_alerts (a regression of the domain/mail server check)
    "mailcheck": ("Mailsikkerhed", "Tjekket af jeres domæner og mailservere har fundet et nyt problem. "
                  "Se Mailsikkerhed.", "/mailcheck"),
}
DOWNTIME_MIN = 10 * 60

REVIEW_ACTIONS = ("moved_to_junk", "pending_move", "flagged", "flag", "move_failed")
LEGIT_ACTIONS = ("none", "allowlisted", "manual_release", "user_rescued")
REVIEW_MARGIN = 3.0
KNOWN_DAYS = 365
DEFAULT_THRESHOLD = 8.0
_ADDR_RE = re.compile(r"[^\s<>\"',;:()\[\]]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

TEXTS = {
    "ok": "Beskeder er slået til på denne enhed.",
    "updated": "Enheden er opdateret.",
    "too_many": f"Du har allerede {MAX_PER_USER} enheder med beskeder. Fjern en af dem først.",
    "taken": "Denne enhed er allerede tilmeldt af en anden bruger.",
    "invalid_endpoint": "Enheden sendte en ugyldig adresse til beskeder.",
    "endpoint_not_allowed": "Beskeder kan kun sendes via Apple, Google, Mozilla eller Microsoft.",
    "invalid_keys": "Enheden sendte ugyldige nøgler til beskeder.",
    "no_crypto": "Beskeder er ikke tilgængelige på denne installation.",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings_kv (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS push_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT NOT NULL,
    endpoint TEXT NOT NULL UNIQUE,
    p256dh TEXT NOT NULL,
    auth TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_ok_at INTEGER,
    fail_count INTEGER NOT NULL DEFAULT 0,
    user_agent_short TEXT,
    prefs TEXT,
    last_error TEXT,
    last_error_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user ON push_subscriptions(user);
CREATE TABLE IF NOT EXISTS push_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT NOT NULL,
    kind TEXT NOT NULL,
    tag TEXT NOT NULL,
    data TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_at INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    sent_at INTEGER,
    targets TEXT,
    last_error TEXT
);
CREATE INDEX IF NOT EXISTS idx_push_queue_due ON push_queue(status, next_at);
CREATE INDEX IF NOT EXISTS idx_push_queue_user ON push_queue(user, tag, sent_at);
CREATE TABLE IF NOT EXISTS push_marks (
    kind TEXT NOT NULL,
    account TEXT NOT NULL,
    message_id TEXT NOT NULL,
    at INTEGER NOT NULL,
    PRIMARY KEY (kind, account, message_id)
);
"""

_SCHEMA_READY: set[str] = set()
_SCHEMA_LOCK = threading.Lock()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def ensure_schema() -> None:
    key = str(DB_PATH)
    if key in _SCHEMA_READY:
        return
    with _SCHEMA_LOCK:
        if key in _SCHEMA_READY:
            return
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = _connect()
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()
        _SCHEMA_READY.add(key)


def _db() -> sqlite3.Connection:
    ensure_schema()
    return _connect()


@contextmanager
def _tx(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Atomic block on any connection; joins the caller's open transaction
    (engine hooks run on the engine's own connection, maybe inside db.tx())."""
    if conn.in_transaction:
        yield conn
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.rollback()
        raise
    conn.commit()


@contextmanager
def _conn(conn: sqlite3.Connection | None) -> Iterator[sqlite3.Connection]:
    if conn is not None:
        ensure_schema()
        yield conn
        return
    own = _db()
    try:
        yield own
    finally:
        own.close()


def _kv_get(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM settings_kv WHERE key=?", (key,)).fetchone()
    return str(row[0]) if row and row[0] is not None else None


def _kv_set(conn: sqlite3.Connection, key: str, value: str | None) -> None:
    if value is None:
        conn.execute("DELETE FROM settings_kv WHERE key=?", (key,))
    else:
        conn.execute("INSERT INTO settings_kv(key, value) VALUES(?,?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


# ---------------------------------------------------------------------------
# Users (the dashboard users file; same parser as the WebUI)
# ---------------------------------------------------------------------------


def load_users() -> dict[str, dict]:
    """name -> {'admin': bool, 'accounts': frozenset}. File users first,
    then DASHBOARD_USERS, then the legacy env admin (dashboard.load_users
    semantics). Unreadable file: no users (fail closed)."""
    import dashboard  # noqa: PLC0415 - parse_user_line is the single source of the format

    users: dict[str, dict] = {}

    def add(u: Any) -> None:
        if u is not None and u.name not in users:
            users[u.name] = {"admin": bool(u.admin), "accounts": frozenset(u.accounts)}

    try:
        if USERS_FILE.is_file():
            for line in USERS_FILE.read_text(encoding="utf-8").splitlines():
                s = line.strip()
                if s and not s.startswith("#"):
                    add(dashboard.parse_user_line(s))
    except (OSError, UnicodeDecodeError) as ex:
        log.warning("push: users file unreadable: %s", type(ex).__name__)
        return {}
    for entry in os.environ.get("DASHBOARD_USERS", "").split(","):
        if entry.strip():
            add(dashboard.parse_user_line(entry, source="env"))
    legacy = os.environ.get("DASHBOARD_USER", "").strip()
    if legacy and os.environ.get("DASHBOARD_PASSWORD", "") and legacy not in users:
        users[legacy] = {"admin": True, "accounts": frozenset()}
    return users


def can_see(user: dict | None, account: str) -> bool:
    return bool(user) and (user["admin"] or account in user["accounts"])


_DISPLAY_CACHE: dict[str, Any] = {"key": None, "names": {}, "users": []}


def _config_info() -> tuple[dict[str, str], list[str]]:
    """(account -> display_name, mailbox addresses in config order) from
    accounts.yml, cached on mtime/size."""
    try:
        st = CONFIG_PATH.stat()
        key = (str(CONFIG_PATH), st.st_mtime_ns, st.st_size)
    except OSError:
        return {}, []
    if _DISPLAY_CACHE["key"] == key:
        return dict(_DISPLAY_CACHE["names"]), list(_DISPLAY_CACHE["users"])
    names: dict[str, str] = {}
    addrs: list[str] = []
    try:
        import yaml  # noqa: PLC0415

        raw = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
        for entry in raw.get("accounts") or []:
            if not isinstance(entry, dict) or not entry.get("name"):
                continue
            label = " ".join(str(entry.get("display_name") or "").split())
            if label and len(label) <= 40 and not any(ord(c) < 32 or c in "<>" for c in label):
                names[str(entry["name"])] = label
            if entry.get("user"):
                addrs.append(str(entry["user"]))
    except Exception as ex:  # noqa: BLE001 - a broken config must not break pushes
        log.debug("push: config unreadable: %s", type(ex).__name__)
    _DISPLAY_CACHE.update(key=key, names=dict(names), users=list(addrs))
    return names, addrs


def display_name(account: str) -> str:
    return _config_info()[0].get(account) or account


# ---------------------------------------------------------------------------
# VAPID key + subject (webpush.py does the crypto)
# ---------------------------------------------------------------------------

_KEY_CACHE: dict[str, Any] = {}
_KEY_LOCK = threading.Lock()


def available() -> bool:
    try:
        import webpush  # noqa: F401,PLC0415
    except Exception:  # noqa: BLE001 - cryptography missing (an old image)
        return False
    return True


def _wp():
    import webpush  # noqa: PLC0415

    return webpush


def vapid_key(*, create: bool = True):
    """The process-wide VAPID private key (generated once into
    STATE_DIR/vapid_private.pem, mode 0600). Re-read when the file changes
    (sfctl push-reset in another process)."""
    wp = _wp()
    path = wp.key_path(STATE_DIR)
    with _KEY_LOCK:
        try:
            st = path.stat()
            stamp = (str(path), st.st_mtime_ns, st.st_ino)
        except OSError:
            stamp = None
        hit = _KEY_CACHE.get(str(path))
        if hit is not None and stamp is not None and hit[0] == stamp:
            return hit[1]
        key = wp.load_private_key(STATE_DIR, create=create)
        if key is None:
            return None
        st = path.stat()
        _KEY_CACHE[str(path)] = ((str(path), st.st_mtime_ns, st.st_ino), key)
        return key


def public_key() -> str:
    return _wp().public_key_b64(vapid_key())


def vapid_subject() -> str | None:
    """RFC 8292 'sub': PUSH_VAPID_SUBJECT (mailto:/https:), else mailto: the
    SMTP sender (Indstillinger -> Mailserver), else the first mailbox in
    accounts.yml. None when nothing valid is known."""
    wp = _wp()
    env = (os.environ.get("PUSH_VAPID_SUBJECT") or "").strip()
    if env and wp.valid_subject(env):
        return env
    candidates: list[str] = []
    try:
        # Indstillinger -> Mailserver (settings_kv 'smtp', written by mailer.py):
        # read directly, so the mailer module's paths are never touched.
        with _conn(None) as conn:
            smtp = json.loads(_kv_get(conn, "smtp") or "{}")
        if isinstance(smtp, dict):
            candidates += [str(smtp.get(k) or "") for k in ("from_addr", "username")]
    except Exception:  # noqa: BLE001 - mail is optional
        pass
    candidates += _config_info()[1]
    for addr in candidates:
        sub = "mailto:" + str(addr).strip()
        if wp.valid_subject(sub):
            return sub
    return None


# ---------------------------------------------------------------------------
# Subscriptions
# ---------------------------------------------------------------------------


def endpoint_hash(endpoint: str) -> str:
    """Non-secret id of an endpoint for the page (app.js finds 'this device')."""
    return hashlib.sha256(str(endpoint).encode("utf-8")).hexdigest()[:16]


def short_user_agent(ua: Any, *, app: bool = False) -> str:
    """'iPhone · app på hjemmeskærmen', 'Android · Chrome', ... - never the full UA."""
    s = str(ua or "")
    if "iPhone" in s:
        device = "iPhone"
    elif "iPad" in s:
        device = "iPad"
    elif "Android" in s:
        device = "Android"
    elif "Macintosh" in s or "Mac OS X" in s:
        device = "Mac"
    elif "Windows" in s:
        device = "Windows"
    elif "Linux" in s or "X11" in s:
        device = "Linux"
    else:
        device = "Enhed"
    if app:
        browser = "app på hjemmeskærmen"
    elif "Edg/" in s or "EdgA/" in s or "EdgiOS/" in s:
        browser = "Edge"
    elif "Firefox/" in s or "FxiOS/" in s:
        browser = "Firefox"
    elif "Chrome/" in s or "CriOS/" in s:
        browser = "Chrome"
    elif "Safari/" in s:
        browser = "Safari"
    else:
        browser = "browser"
    return f"{device} · {browser}"[:UA_MAX]


def parse_prefs(raw: Any, *, is_admin: bool = True) -> dict[str, bool]:
    try:
        data = json.loads(raw) if isinstance(raw, (str, bytes)) and raw else (raw or {})
    except (TypeError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    out = {k: bool(data.get(k, PREF_DEFAULTS[k])) for k in KINDS}
    if not is_admin:
        out["problem"] = False   # problems are for administrators only
    return out


def _prefs_json(prefs: dict[str, bool]) -> str:
    return json.dumps({k: bool(prefs.get(k, PREF_DEFAULTS[k])) for k in KINDS}, sort_keys=True)


def subscribe(user: str, endpoint: Any, p256dh: Any, auth: Any, *, user_agent: str = "",
              prefs: dict[str, bool] | None = None, is_admin: bool = True, now: int | None = None) -> dict:
    """Register (or refresh) this device for `user`. {ok, code, text, id}.
    The endpoint must be on a known push service; an endpoint already held
    by ANOTHER user moves only when the same browser keys are presented
    (proof that it is the same subscription on this device)."""
    if not available():
        return {"ok": False, "code": "no_crypto", "text": TEXTS["no_crypto"]}
    wp = _wp()
    try:
        ep = wp.validate_endpoint(endpoint)
        p, a = wp.validate_keys(p256dh, auth)
    except wp.PushError as ex:
        code = ex.code if ex.code in TEXTS else "invalid_keys"
        return {"ok": False, "code": code, "text": TEXTS[code]}
    t = int(now if now is not None else time.time())
    ua = str(user_agent or "")[:UA_MAX]
    with _conn(None) as conn, _tx(conn):
        row = conn.execute("SELECT id, user, p256dh, auth FROM push_subscriptions WHERE endpoint=?", (ep,)).fetchone()
        if row is not None and row["user"] != user:
            if (row["p256dh"], row["auth"]) != (p, a):
                return {"ok": False, "code": "taken", "text": TEXTS["taken"]}
            conn.execute("DELETE FROM push_subscriptions WHERE id=?", (row["id"],))
            row = None
        if row is not None:
            sets = "p256dh=?, auth=?, fail_count=0, last_error=NULL, user_agent_short=?"
            args: list[Any] = [p, a, ua]
            if prefs is not None:
                sets += ", prefs=?"
                args.append(_prefs_json(prefs))
            conn.execute(f"UPDATE push_subscriptions SET {sets} WHERE id=?", (*args, row["id"]))
            return {"ok": True, "code": "updated", "text": TEXTS["updated"], "id": int(row["id"])}
        n = conn.execute("SELECT COUNT(*) FROM push_subscriptions WHERE user=?", (user,)).fetchone()[0]
        if int(n) >= MAX_PER_USER:
            return {"ok": False, "code": "too_many", "text": TEXTS["too_many"]}
        cur = conn.execute(
            "INSERT INTO push_subscriptions(user, endpoint, p256dh, auth, created_at, fail_count, user_agent_short, "
            "prefs) VALUES(?,?,?,?,?,0,?,?)",
            (user, ep, p, a, t, ua, _prefs_json(parse_prefs(prefs if prefs is not None else PREF_DEFAULTS,
                                                            is_admin=is_admin))))
        return {"ok": True, "code": "ok", "text": TEXTS["ok"], "id": int(cur.lastrowid)}


def devices(user: str, *, is_admin: bool = True) -> list[dict]:
    """The user's own devices (never the endpoint itself)."""
    with _conn(None) as conn:
        rows = conn.execute("SELECT * FROM push_subscriptions WHERE user=? ORDER BY created_at, id",
                            (user,)).fetchall()
    return [{"id": int(r["id"]), "ua": r["user_agent_short"] or "Enhed", "created_at": r["created_at"],
             "last_ok_at": r["last_ok_at"], "fail_count": int(r["fail_count"] or 0),
             "last_error": r["last_error"], "hash": endpoint_hash(r["endpoint"]),
             "host": _wp().endpoint_host(r["endpoint"]) if available() else "",
             "prefs": parse_prefs(r["prefs"], is_admin=is_admin)} for r in rows]


def set_prefs(user: str, sub_id: int, prefs: dict[str, bool], *, is_admin: bool) -> bool:
    """Only the owner's own row changes (False = not found / not theirs)."""
    clean = parse_prefs(prefs, is_admin=is_admin)
    if not is_admin:
        clean["problem"] = False
    with _conn(None) as conn, _tx(conn):
        n = conn.execute("UPDATE push_subscriptions SET prefs=? WHERE id=? AND user=?",
                         (_prefs_json(clean), int(sub_id), user)).rowcount
    return n > 0


def remove(user: str, sub_id: int) -> bool:
    with _conn(None) as conn, _tx(conn):
        n = conn.execute("DELETE FROM push_subscriptions WHERE id=? AND user=?", (int(sub_id), user)).rowcount
    return n > 0


def remove_endpoint(user: str, endpoint: str) -> bool:
    with _conn(None) as conn, _tx(conn):
        n = conn.execute("DELETE FROM push_subscriptions WHERE endpoint=? AND user=?",
                         (str(endpoint or ""), user)).rowcount
    return n > 0


def owns_endpoint(user: str, endpoint: str) -> int | None:
    with _conn(None) as conn:
        row = conn.execute("SELECT id FROM push_subscriptions WHERE endpoint=? AND user=?",
                           (str(endpoint or ""), user)).fetchone()
    return int(row[0]) if row else None


def delete_user(user: str) -> int:
    """A removed dashboard user: every device and queued message goes."""
    try:
        with _conn(None) as conn, _tx(conn):
            n = conn.execute("DELETE FROM push_subscriptions WHERE user=?", (user,)).rowcount
            conn.execute("DELETE FROM push_queue WHERE user=? AND status='queued'", (user,))
        return int(n)
    except sqlite3.Error as ex:
        log.warning("push: could not forget user: %s", type(ex).__name__)
        return 0


def reset_all() -> dict:
    """sfctl push-reset: delete every subscription and queued message and
    rotate the VAPID key pair. {subscriptions, fingerprint}."""
    with _conn(None) as conn, _tx(conn):
        n = conn.execute("DELETE FROM push_subscriptions").rowcount
        conn.execute("DELETE FROM push_queue WHERE status='queued'")
        _kv_set(conn, REFUSED_KEY, None)        # a refusal of the old key is history
    key = _wp().rotate_key(STATE_DIR)
    with _KEY_LOCK:
        _KEY_CACHE.clear()
    return {"subscriptions": int(n), "fingerprint": _wp().key_fingerprint(key)}


def _subscribed_users(conn: sqlite3.Connection, kind: str) -> set[str]:
    out: set[str] = set()
    for r in conn.execute("SELECT user, prefs FROM push_subscriptions"):
        if parse_prefs(r["prefs"]).get(kind):
            out.add(str(r["user"]))
    return out


# ---------------------------------------------------------------------------
# Routing + queue
# ---------------------------------------------------------------------------

_WAKE = threading.Event()
_STOP = threading.Event()
_WORKER: threading.Thread | None = None
_WORKER_LOCK = threading.Lock()
_PROCESS_LOCK = threading.Lock()
AUTO_WORKER = True      # sfctl (one-shot) turns it off; the filter's own worker sends


def _kick() -> None:
    _WAKE.set()
    if AUTO_WORKER:
        ensure_worker()


def recipients(conn: sqlite3.Connection, kind: str, account: str | None = None,
               users: dict[str, dict] | None = None) -> list[str]:
    """Users who may get this event AND have a device that wants it."""
    wanted = _subscribed_users(conn, kind)
    if not wanted:
        return []
    users = load_users() if users is None else users
    out = []
    for name, u in sorted(users.items()):
        if name not in wanted:
            continue
        if kind in ADMIN_ONLY_KINDS:
            if not u["admin"]:
                continue
        elif account is None or not can_see(u, account):
            continue
        out.append(name)
    return out


def _merge(data: dict, extra: dict) -> dict:
    counts = dict(data.get("counts") or {})
    for acc, n in (extra.get("counts") or {}).items():
        counts[acc] = int(counts.get(acc, 0)) + int(n)
    problems = list(data.get("problems") or [])
    for p in extra.get("problems") or []:
        if p not in problems:
            problems.append(p)
    out: dict[str, Any] = {}
    if counts:
        out["counts"] = counts
    if problems:
        out["problems"] = problems[-5:]
    for key in ("logins", "failed"):  # 2.6 login alerts: the newest few
        items = [x for x in list(data.get(key) or []) + list(extra.get(key) or []) if isinstance(x, dict)]
        if items:
            out[key] = items[-LOGIN_KEEP:]
    return out


def enqueue(conn: sqlite3.Connection | None, user: str, kind: str, data: dict, *,
            now: int | None = None) -> int:
    """Queue (or merge into the user's queued row of the same tag)."""
    if kind not in KINDS and kind not in LOGIN_KINDS:
        raise ValueError(kind)
    t = int(now if now is not None else time.time())
    tag = TAG_OF[kind]
    with _conn(conn) as c, _tx(c):
        row = c.execute("SELECT id, data FROM push_queue WHERE user=? AND tag=? AND status='queued' "
                        "AND sent_at IS NULL ORDER BY id LIMIT 1", (user, tag)).fetchone()
        if row is not None:
            try:
                old = json.loads(row["data"])
            except (TypeError, ValueError):
                old = {}
            c.execute("UPDATE push_queue SET data=?, expires_at=MAX(expires_at, ?) WHERE id=?",
                      (json.dumps(_merge(old, data), sort_keys=True), t + TTL[kind], row["id"]))
            row_id = int(row["id"])
        else:
            cur = c.execute("INSERT INTO push_queue(user, kind, tag, data, status, attempts, next_at, created_at, "
                            "expires_at) VALUES(?,?,?,?,'queued',0,?,?,?)",
                            (user, kind, tag, json.dumps(_merge({}, data), sort_keys=True), t, t, t + TTL[kind]))
            row_id = int(cur.lastrowid)
    _kick()
    return row_id


def notify_event(conn: sqlite3.Connection | None, kind: str, *, account: str | None = None, count: int = 1,
                 problem: str | None = None, now: int | None = None) -> int:
    """Route one event to every user who may and wants to get it. Never
    raises (a notification must never break the engine); the number of
    users it was queued for."""
    try:
        if not available():
            return 0
        with _conn(conn) as c:
            names = recipients(c, kind, account)
            if kind == "problem":
                data = {"problems": [[str(problem or ""), str(account or "")]]}
            else:
                if not account or int(count) <= 0:
                    return 0
                data = {"counts": {account: int(count)}}
            for name in names:
                enqueue(c, name, kind, data, now=now)
        return len(names)
    except Exception as ex:  # noqa: BLE001
        log.warning("push: event not queued: %s", type(ex).__name__)
        return 0


# ---------------------------------------------------------------------------
# Payload (counts and display names only)
# ---------------------------------------------------------------------------


def _clip(text: str, n: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 1].rstrip() + "…"


def _names(counts: dict[str, int]) -> str:
    items = sorted(counts.items(), key=lambda kv: (-kv[1], display_name(kv[0])))
    return ", ".join(f"{display_name(a)} ({n})" for a, n in items)


def render(user: str, kind: str, data: dict, users: dict[str, dict] | None = None) -> dict | None:
    """{title, body, url, tag} for this user NOW (access re-checked), or
    None when nothing visible is left."""
    users = load_users() if users is None else users
    u = users.get(user)
    if u is None:
        return None
    tag = TAG_OF.get(kind, "sf")
    if kind in ("threat", "review"):
        counts = {a: int(n) for a, n in (data.get("counts") or {}).items() if int(n) > 0 and can_see(u, a)}
        if not counts:
            return None
        n = sum(counts.values())
        one = next(iter(counts)) if len(counts) == 1 else None
        url = "/spam" + (f"?account={quote(one, safe='')}" if one else "")
        if kind == "threat":
            title = "Farlig mail stoppet" if n == 1 else f"{n} farlige mails stoppet"
            if one:
                where = f"i {display_name(one)} "
                body = (f"En farlig mail {where}er lagt i Spamfilter-mappen. Åbn den ikke." if n == 1 else
                        f"{n} farlige mails {where}er lagt i Spamfilter-mappen. Åbn dem ikke.")
            else:
                body = f"Lagt i Spamfilter-mappen: {_names(counts)}. Åbn dem ikke."
        else:
            title = "Tjek disse"
            if one:
                body = (f"En ny mail i {display_name(one)} er måske ikke spam." if n == 1 else
                        f"{n} nye mails i {display_name(one)} er måske ikke spam.")
            else:
                body = f"Nye mails, der måske ikke er spam: {_names(counts)}."
        return {"title": _clip(title, TITLE_MAX), "body": _clip(body, BODY_MAX), "url": url, "tag": tag}
    if kind == "problem":
        if not u["admin"]:
            return None
        probs = [(str(p), str(a)) for p, a in (data.get("problems") or []) if str(p) in PROBLEMS]
        if not probs:
            return None
        if len(probs) == 1:
            p, a = probs[0]
            title, body, url = PROBLEMS[p]
            body = body.format(name=display_name(a) if a else "en postkasse")
        else:
            title = f"{len(probs)} problemer med filteret"
            body = "; ".join(PROBLEMS[p][0] + (f" ({display_name(a)})" if a else "") for p, a in probs) + "."
            url = "/system"
        return {"title": _clip(title, TITLE_MAX), "body": _clip(body, BODY_MAX), "url": url, "tag": tag}
    if kind == "test":
        return {"title": "Testbesked", "body": "Beskeder virker på denne enhed.", "url": "/me", "tag": tag}
    if kind == "login":
        logins = [x for x in data.get("logins") or [] if isinstance(x, dict)]
        if not logins:
            return None
        last = logins[-1]
        when = time.strftime("%d.%m. kl. %H:%M", time.localtime(int(last.get("at") or 0)))
        where = (f", IP {_clip(str(last.get('ip') or ''), 45)}" if last.get("ip") else "") + (
            f" ({_clip(str(last.get('cc') or ''), 2)})" if last.get("cc") else "")
        lead = f"{len(logins)} nye login, senest " if len(logins) > 1 else ""
        body = (f"{lead}{_clip(str(last.get('ua') or 'ukendt enhed'), 40)}, {when}{where}. Var det ikke dig? "
                "Skift adgangskode og log ud overalt.")
        return {"title": "Nyt login på din konto", "body": _clip(body, BODY_MAX), "url": "/me#logins", "tag": tag}
    if kind == "login_failed":
        if not u["admin"]:
            return None
        failed = [x for x in data.get("failed") or [] if isinstance(x, dict)]
        if not failed:
            return None
        last = failed[-1]
        body = (f"{int(last.get('n') or 0)} forkerte forsøg på 15 minutter for {_clip(str(last.get('who') or ''), 90)}"
                ". Login er spærret i 15 minutter.")
        if len(failed) > 1:
            body = f"{len(failed)} advarsler. Senest: {body}"
        return {"title": "Gentagne forkerte login-forsøg", "body": _clip(body, BODY_MAX), "url": "/users",
                "tag": tag}
    return None


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------


def _deliver(conn: sqlite3.Connection, subs: list[sqlite3.Row], payload: dict, kind: str, *,
             now: int, session: Any = None) -> tuple[list[int], list[int], int, list[int]]:
    """Send to each subscription; (ok ids, retry ids, max retry-after,
    refused ids). Updates/deletes the subscription rows. No DB transaction
    is held during the HTTP requests."""
    wp = _wp()
    key = vapid_key()
    sub = vapid_subject()
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ok: list[int] = []
    retry: list[int] = []
    retry_after = 0
    refused: list[int] = []
    for s in subs:
        sid = int(s["id"])
        if sub is None:
            res = wp.SendResult(0, "retry", 0, "no_subject")
        else:
            try:
                res = wp.send(s["endpoint"], s["p256dh"], s["auth"], body, key=key, subject=sub,
                              ttl=TTL.get(kind, 3600), urgency=URGENCY.get(kind, "normal"),
                              topic=TAG_OF.get(kind), session=session, now=now)
            except wp.PushError as ex:
                res = wp.SendResult(0, "rejected", 0, ex.code)
        host = wp.endpoint_host(s["endpoint"])
        with _tx(conn):
            if res.outcome == "ok":
                conn.execute("UPDATE push_subscriptions SET last_ok_at=?, fail_count=0, last_error=NULL WHERE id=?",
                             (now, sid))
                ok.append(sid)
                old = _refused(conn)
                if old and old.get("host") == host:
                    _kv_set(conn, REFUSED_KEY, None)   # that service accepts us again
            elif res.outcome == "gone":
                conn.execute("DELETE FROM push_subscriptions WHERE id=?", (sid,))
                log.info("push: subscription %d on %s is gone (%d); removed", sid, host, res.status)
            elif res.outcome == "rejected":
                conn.execute("UPDATE push_subscriptions SET fail_count=fail_count+1, last_error=?, last_error_at=? "
                             "WHERE id=?", (f"{res.status} {res.detail}".strip()[:60], now, sid))
                conn.execute("DELETE FROM push_subscriptions WHERE id=? AND fail_count>=?", (sid, REJECT_DELETE))
                log.warning("push: %s rejected the message (%d %s)", host, res.status, res.detail)
            elif res.outcome == "refused":
                # The service refuses the FILTER (JWT, clock, 'sub', size), not
                # this device: keep it (no fail_count), record it for doctor.
                err = f"{res.status} {res.detail}".strip()[:60]
                conn.execute("UPDATE push_subscriptions SET last_error=?, last_error_at=? WHERE id=?",
                             (err, now, sid))
                _kv_set(conn, REFUSED_KEY, json.dumps({"status": int(res.status), "detail": res.detail[:40],
                                                       "host": host, "at": int(now)}))
                refused.append(sid)
                log.warning("push: %s refused the filter's request (%d %s); devices kept - see sfctl doctor",
                            host, res.status, res.detail)
            else:
                conn.execute("UPDATE push_subscriptions SET last_error=?, last_error_at=? WHERE id=?",
                             (f"{res.status or 'net'} {res.detail}".strip()[:60], now, sid))
                retry.append(sid)
                retry_after = max(retry_after, res.retry_after)
                log.info("push: %s busy/unreachable (%s); will retry", host, res.status or res.detail)
    return ok, retry, retry_after, refused


def _refused(conn: sqlite3.Connection) -> dict | None:
    """The last server-wide refusal ({status, detail, host, at}) or None."""
    raw = _kv_get(conn, REFUSED_KEY)
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _targets(conn: sqlite3.Connection, user: str, kind: str, ids: list[int] | None, is_admin: bool) -> list:
    rows = conn.execute("SELECT * FROM push_subscriptions WHERE user=? ORDER BY id", (user,)).fetchall()
    if ids is not None:
        wanted = set(ids)
        return [r for r in rows if int(r["id"]) in wanted]
    if kind == "login":
        return list(rows)
    pref = "problem" if kind == "login_failed" else kind
    return [r for r in rows if parse_prefs(r["prefs"], is_admin=is_admin).get(pref)]


def process_queue(*, now: int | None = None, limit: int = 50, session: Any = None) -> dict:
    """Send what is due (rate limits, merging, retries). Never raises."""
    stats = {"sent": 0, "deferred": 0, "dropped": 0, "failed": 0, "retry": 0}
    if not available() or not _PROCESS_LOCK.acquire(blocking=False):
        return stats
    try:
        t = int(now if now is not None else time.time())
        conn = _db()
        try:
            users = load_users()
            rows = conn.execute("SELECT * FROM push_queue WHERE status='queued' AND next_at<=? ORDER BY id LIMIT ?",
                                (t, int(limit))).fetchall()
            for row in rows:
                rid, user, kind = int(row["id"]), str(row["user"]), str(row["kind"])

                def finish(status: str, error: str | None = None, *, _rid: int = rid) -> None:
                    with _tx(conn):
                        conn.execute("UPDATE push_queue SET status=?, last_error=? WHERE id=?", (status, error, _rid))

                if int(row["expires_at"]) < t:
                    finish("expired", "expired")
                    stats["dropped"] += 1
                    continue
                fresh = row["sent_at"] is None and int(row["attempts"]) == 0
                if fresh:
                    last = conn.execute("SELECT MAX(sent_at) FROM push_queue WHERE user=? AND tag=? AND id<>?",
                                        (user, row["tag"], rid)).fetchone()[0]
                    if last is not None and t - int(last) < TAG_INTERVAL:
                        with _tx(conn):
                            conn.execute("UPDATE push_queue SET next_at=? WHERE id=?", (int(last) + TAG_INTERVAL, rid))
                        stats["deferred"] += 1
                        continue
                    day = conn.execute("SELECT COUNT(*) FROM push_queue WHERE user=? AND kind<>'test' AND sent_at>=?",
                                       (user, t - 86400)).fetchone()[0]
                    if int(day) >= DAILY_MAX:
                        finish("dropped", "daily_limit")
                        stats["dropped"] += 1
                        continue
                try:
                    data = json.loads(row["data"])
                except (TypeError, ValueError):
                    data = {}
                payload = render(user, kind, data, users)
                if payload is None:
                    finish("dropped", "not_visible")
                    stats["dropped"] += 1
                    continue
                u = users.get(user) or {}
                ids = json.loads(row["targets"]) if row["targets"] else None
                subs = _targets(conn, user, kind, ids, bool(u.get("admin")))
                if not subs:
                    finish("dropped", "no_devices")
                    stats["dropped"] += 1
                    continue
                ok, retry, after, _refused_ids = _deliver(conn, subs, payload, kind, now=t, session=session)
                attempts = int(row["attempts"]) + 1
                sent_at = row["sent_at"] if row["sent_at"] is not None else (t if ok else None)
                with _tx(conn):
                    if retry and attempts < MAX_ATTEMPTS:
                        wait = max(BACKOFF[min(attempts - 1, len(BACKOFF) - 1)], after)
                        conn.execute("UPDATE push_queue SET attempts=?, next_at=?, targets=?, sent_at=?, last_error=? "
                                     "WHERE id=?", (attempts, t + wait, json.dumps(retry), sent_at, "retry", rid))
                        stats["retry"] += 1
                    else:
                        status = "sent" if sent_at is not None and not retry else "failed"
                        conn.execute("UPDATE push_queue SET status=?, attempts=?, sent_at=?, targets=NULL, "
                                     "last_error=? WHERE id=?",
                                     (status, attempts, sent_at, None if status == "sent" else "undeliverable", rid))
                        stats["sent" if status == "sent" else "failed"] += 1
        finally:
            conn.close()
    except Exception as ex:  # noqa: BLE001 - the worker never dies
        log.warning("push: queue run failed: %s", type(ex).__name__)
    finally:
        _PROCESS_LOCK.release()
    return stats


def send_test(user: str, *, endpoint: str | None = None, is_admin: bool = False, now: int | None = None,
              session: Any = None) -> dict:
    """'Send testbesked' (WebUI, sfctl push-test): synchronous, to this
    device (endpoint) or all of the user's devices. {ok, code, text, sent}."""
    if not available():
        return {"ok": False, "code": "no_crypto", "text": TEXTS["no_crypto"], "sent": 0}
    t = int(now if now is not None else time.time())
    rate = {"ok": False, "code": "rate", "sent": 0,
            "text": "Du har sendt mange testbeskeder lige nu. Vent et par minutter."}

    def recent_tests() -> int:
        return int(conn.execute("SELECT COUNT(*) FROM push_queue WHERE user=? AND kind='test' AND created_at>=?",
                                (user, t - TEST_WINDOW)).fetchone()[0])

    conn = _db()
    try:
        if recent_tests() >= TEST_MAX:
            return rate
        rows = conn.execute("SELECT * FROM push_subscriptions WHERE user=? ORDER BY id", (user,)).fetchall()
        if endpoint:
            rows = [r for r in rows if r["endpoint"] == endpoint]
        if not rows:
            return {"ok": False, "code": "no_devices", "sent": 0,
                    "text": "Der er ingen enhed med beskeder slået til." if not endpoint
                    else "Denne enhed er ikke tilmeldt beskeder. Slå dem til først."}
        if vapid_subject() is None:
            return {"ok": False, "code": "no_subject", "sent": 0,
                    "text": "Der mangler en afsenderadresse til beskeder (en mailadresse i accounts.yml, "
                            "Mailserver-indstillingerne eller PUSH_VAPID_SUBJECT)."}
        # 2.5.0: reserve the slot BEFORE sending (count + insert in one
        # BEGIN IMMEDIATE), so parallel requests cannot all pass the limit
        # while the first one is still waiting for the push services.
        with _tx(conn):
            if recent_tests() >= TEST_MAX:
                return rate
            rid = conn.execute("INSERT INTO push_queue(user, kind, tag, data, status, attempts, next_at, "
                               "created_at, expires_at) VALUES(?,?,?,?,'sending',1,?,?,?)",
                               (user, "test", TAG_OF["test"], "{}", t, t, t)).lastrowid
        payload = render(user, "test", {}, {user: {"admin": is_admin, "accounts": frozenset()}})
        ok, retry, _after, refused = _deliver(conn, rows, payload or {}, "test", now=t, session=session)
        with _tx(conn):
            conn.execute("UPDATE push_queue SET status=?, sent_at=?, last_error=? WHERE id=?",
                         ("sent" if ok else "failed", t if ok else None, None if ok else "test_failed", rid))
    finally:
        conn.close()
    if ok:
        n = len(ok)
        extra = f" {len(rows) - n} enhed(er) svarede ikke." if n < len(rows) else ""
        return {"ok": True, "code": "sent", "sent": n,
                "text": ("Testbeskeden er sendt." if n == 1 else f"Testbeskeden er sendt til {n} enheder.") + extra}
    if retry:
        return {"ok": False, "code": "retry", "sent": 0,
                "text": "Beskedtjenesten svarede ikke. Prøv igen om lidt."}
    if refused:
        return {"ok": False, "code": "refused", "sent": 0,
                "text": ("Beskedtjenesten afviste filterets afsender-nøgle. Enheden er beholdt; kør sfctl doctor "
                         "(tjek uret på serveren og afsenderadressen).") if is_admin else
                        "Beskedtjenesten afviste filteret. Enheden er beholdt; sig det til administratoren."}
    return {"ok": False, "code": "rejected", "sent": 0,
            "text": "Beskedtjenesten afviste beskeden. Slå beskeder fra og til igen på enheden."}


def prune(now: int | None = None) -> int:
    t = int(now if now is not None else time.time())
    try:
        with _conn(None) as conn, _tx(conn):
            n = conn.execute("DELETE FROM push_queue WHERE status<>'queued' AND created_at<?",
                             (t - KEEP_DAYS * 86400,)).rowcount
            n += conn.execute("DELETE FROM push_marks WHERE at<?", (t - KEEP_DAYS * 86400,)).rowcount
        return int(n)
    except sqlite3.Error:
        return 0


def _worker_loop() -> None:
    last_prune = 0.0
    while not _STOP.is_set():
        woke = _WAKE.wait(WORKER_POLL)
        _WAKE.clear()
        if _STOP.is_set():
            break
        if woke:
            # An engine hook may still be inside its transaction: give it a moment.
            _STOP.wait(1.0)
        try:
            process_queue()
            if time.time() - last_prune > 6 * 3600:
                prune()
                last_prune = time.time()
        except Exception as ex:  # noqa: BLE001
            log.warning("push worker: %s", type(ex).__name__)


def ensure_worker() -> bool:
    """Start the one background sender of this process (idempotent)."""
    global _WORKER
    if not available():
        return False
    with _WORKER_LOCK:
        if _WORKER is not None and _WORKER.is_alive():
            return True
        _STOP.clear()
        try:
            _WORKER = threading.Thread(target=_worker_loop, name="push", daemon=True)
            _WORKER.start()
        except RuntimeError as ex:
            log.warning("push worker not started: %s", ex)
            _WORKER = None
            return False
        _WAKE.set()   # send whatever a previous run left queued
        return True


def stop_worker(timeout: float = 5.0) -> None:
    global _WORKER
    _STOP.set()
    _WAKE.set()
    w = _WORKER
    if w is not None:
        w.join(timeout)
    _WORKER = None


def worker_alive() -> bool:
    return _WORKER is not None and _WORKER.is_alive()


# ---------------------------------------------------------------------------
# Engine hooks (called from filter.py; all take the engine's connection)
# ---------------------------------------------------------------------------


def _unmarked(conn: sqlite3.Connection, kind: str, account: str, ids: Iterable[str]) -> list[str]:
    out = []
    for mid in ids:
        if conn.execute("SELECT 1 FROM push_marks WHERE kind=? AND account=? AND message_id=?",
                        (kind, account, mid)).fetchone() is None:
            out.append(mid)
    return out


def _mark(conn: sqlite3.Connection, kind: str, account: str, ids: Iterable[str], now: int) -> None:
    conn.executemany("INSERT OR IGNORE INTO push_marks(kind, account, message_id, at) VALUES(?,?,?,?)",
                     [(kind, account, m, now) for m in ids])


def on_threats(conn: sqlite3.Connection, account: str, *, now: int | None = None) -> int:
    """Straks-advarsel moment: threat mails moved into the Spamfilter folder
    (threat_notices.queued_at) that were not pushed yet -> one 'threat'
    event with the count. Never raises; users notified."""
    t = int(now if now is not None else time.time())
    try:
        ensure_schema()
        rows = conn.execute("SELECT message_id FROM threat_notices WHERE account=? AND queued_at IS NOT NULL "
                            "AND queued_at>=?", (account, t - LOOKBACK)).fetchall()
        new = _unmarked(conn, "threat", account, [str(r[0]) for r in rows])
        if not new:
            return 0
        with _tx(conn):
            _mark(conn, "threat", account, new, t)
        return notify_event(conn, "threat", account=account, count=len(new), now=t)
    except Exception as ex:  # noqa: BLE001
        log.warning("push: threat hook failed: %s", type(ex).__name__)
        return 0


def _symbol_list(raw: Any) -> list:
    try:
        data = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
    except (TypeError, ValueError):
        return []
    return [i for i in (data if isinstance(data, list) else []) if isinstance(i, dict)]


def _symbol_names(raw: Any) -> set[str]:
    try:
        data = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
    except (TypeError, ValueError):
        return set()
    return {str(i["n"]) for i in (data if isinstance(data, list) else []) if isinstance(i, dict) and i.get("n")}


def _addr_of(value: Any) -> str:
    found = _ADDR_RE.findall(str(value or ""))
    return found[-1].lower().strip(".") if found else ""


def _known_count(conn: sqlite3.Connection, account: str, addr: str, now: int) -> int:
    q = ",".join("?" * len(LEGIT_ACTIONS))
    rows = conn.execute(f"SELECT sender FROM messages WHERE account=? AND instr(lower(sender), ?)>0 "
                        f"AND (our_action IN ({q}) OR user_verdict='ham') AND COALESCE(user_verdict,'') != 'spam' "
                        f"AND COALESCE(scanned_at, received_at, first_seen)>=? LIMIT 50",
                        (account, addr, *LEGIT_ACTIONS, now - KNOWN_DAYS * 86400)).fetchall()
    return sum(1 for r in rows if _addr_of(r[0]) == addr)


def review_borderline_only(row: Any, *, user: str, threshold: float, known: int) -> bool:
    """review_qualifies() only because the score is close to the threshold
    (2.19.1: such a mail from a sender a person already called spam is not
    news - judged.py)."""
    return (review_qualifies(row, user=user, threshold=threshold, known=known)
            and not review_qualifies(row, user=user, threshold=float("-inf"), known=known))


def review_protected_only(row: Any, *, user: str, threshold: float, known: int) -> bool:
    """review_qualifies() only because it went to a protected address (2.19.3)."""
    syms = _symbol_names(row["symbols"])
    if "TH_PROTECTED_RCPT" not in syms:
        return False
    plain = dict(row)
    plain["symbols"] = json.dumps([{"n": n} for n in sorted(syms - {"TH_PROTECTED_RCPT"})])
    return not review_qualifies(plain, user=user, threshold=threshold, known=known)


def review_qualifies(row: Any, *, user: str, threshold: float, known: int) -> bool:
    """The same test as ui_mail.review_reasons() (non-empty): a mail the
    filter caught that may be legitimate. tests/test_push.py keeps the two
    in step."""
    syms = _symbol_names(row["symbols"])
    if known > 0:
        return True
    if syms & {"TH_KNOWN_CONTACT", "TH_REPLY", "TH_PROTECTED_RCPT", "TH_FORCE_UNVERIFIED"}:
        return True
    own = user.rsplit("@", 1)[1].lower() if "@" in user else ""
    addr = _addr_of(row["sender"])
    dom = addr.rsplit("@", 1)[1] if "@" in addr else ""
    if own and dom and (dom == own or dom.endswith("." + own)):
        return True
    try:
        score = float(row["our_score"]) if row["our_score"] is not None else None
    except (TypeError, ValueError):
        score = None
    return score is not None and score < float(threshold) + REVIEW_MARGIN


def _row_ts(row: Any) -> int | None:
    for col in ("scanned_at", "received_at", "first_seen"):
        try:
            if row[col] is not None:
                return int(row[col])
        except (IndexError, KeyError, TypeError, ValueError):
            continue
    return None


def _review_floor_key(account: str) -> str:
    return f"push:review_floor:{account}"


def _review_candidates(conn: sqlite3.Connection, account: str, now: int) -> list[sqlite3.Row]:
    since = now - LOOKBACK
    floor = _kv_get(conn, _review_floor_key(account))
    if floor is not None:
        since = max(since, int(float(floor)))
    q = ",".join("?" * len(REVIEW_ACTIONS))
    rows = conn.execute(
        f"SELECT * FROM messages WHERE account=? AND our_action IN ({q}) AND user_verdict IS NULL "
        f"AND current_folder != 'gone' AND COALESCE(scanned_at, received_at, first_seen)>=? "
        f"AND message_id NOT IN (SELECT message_id FROM push_marks WHERE kind='review' AND account=?) LIMIT 400",
        (account, *REVIEW_ACTIONS, since, account)).fetchall()
    out = []
    for r in rows:
        keys = r.keys()
        if ("threat" in keys and r["threat"]) or ("zapped_at" in keys and r["zapped_at"]):
            continue   # never offered under Tjek disse (2.3)
        out.append(r)
    return out


def _review_key(account: str) -> str:
    return f"push:review_at:{account}"


def on_review(conn: sqlite3.Connection, acc: Any, *, now: int | None = None) -> int:
    """New 'Tjek disse' mails of one mailbox -> one 'review' event (count
    only), at most once per REVIEW_BATCH. Never raises; users notified."""
    t = int(now if now is not None else time.time())
    account = str(getattr(acc, "name", ""))
    try:
        ensure_schema()
        if not _subscribed_users(conn, "review"):
            # Nobody wants it: move the floor, so turning it on later never
            # brings a pile of old mails (written at most every 5 min).
            floor = _kv_get(conn, _review_floor_key(account))
            if floor is None or t - int(float(floor)) >= 300:
                with _tx(conn):
                    _kv_set(conn, _review_floor_key(account), str(t))
            return 0
        last = _kv_get(conn, _review_key(account))
        if last is not None and t - int(float(last)) < REVIEW_BATCH:
            return 0
        rows = _review_candidates(conn, account, t)
        if not rows:
            return 0
        try:
            thr = float(getattr(acc, "threshold", DEFAULT_THRESHOLD))
        except (TypeError, ValueError):
            thr = DEFAULT_THRESHOLD
        user = str(getattr(acc, "user", "") or "")
        n = 0
        cache: dict[str, int] = {}
        judged_keys: set[str] | None = None
        ai_sure: set[tuple[str, str]] | None = None
        for r in rows:
            addr = _addr_of(r["sender"])
            if addr and addr not in cache:
                cache[addr] = _known_count(conn, account, addr, t)
            known = cache.get(addr, 0)
            if not review_qualifies(r, user=user, threshold=thr, known=known):
                continue
            if review_borderline_only(r, user=user, threshold=thr, known=known):
                import judged  # noqa: PLC0415

                if judged_keys is None:
                    judged_keys = judged.judged_spam(conn, t)
                    ai_sure = judged.ai_sure_spam(conn, t)
                if judged_keys and judged.already_judged(r["sender"], judged_keys):
                    continue
                names = _symbol_names(r["symbols"])
                bayes = judged.bayes_of(_symbol_list(r["symbols"]))
                if judged.obvious_spam(names, (account, str(r["message_id"])) in (ai_sure or set()), bayes=bayes):
                    continue
                if judged.obvious_spam(names, False, unknown=True, bayes=bayes) and judged.unknown_sender(
                        conn, account, r["sender"], str(r["message_id"]), _row_ts(r)):
                    continue
            elif review_protected_only(r, user=user, threshold=thr, known=known):
                import judged  # noqa: PLC0415

                if judged.protected_hidden(_symbol_names(r["symbols"]), r["our_score"], thr):
                    continue
            n += 1
        with _tx(conn):
            _mark(conn, "review", account, [str(r["message_id"]) for r in rows], t)
            if n:
                _kv_set(conn, _review_key(account), str(t))
        return notify_event(conn, "review", account=account, count=n, now=t) if n else 0
    except Exception as ex:  # noqa: BLE001
        log.warning("push: review hook failed: %s", type(ex).__name__)
        return 0


def review_due_in(conn: sqlite3.Connection, acc: Any, *, now: int | None = None) -> float | None:
    """Seconds until held-back Tjek-disse mails may be pushed (None: nothing waits)."""
    t = int(now if now is not None else time.time())
    account = str(getattr(acc, "name", ""))
    try:
        last = _kv_get(conn, _review_key(account))
        if last is None or t - int(float(last)) >= REVIEW_BATCH:
            return None
        if not _subscribed_users(conn, "review") or not _review_candidates(conn, account, t):
            return None
        return float(int(float(last)) + REVIEW_BATCH - t)
    except Exception:  # noqa: BLE001 - tables missing (old DB): nothing waits
        return None


def notify_login(conn: sqlite3.Connection | None, user: str, entry: dict, *, now: int | None = None) -> int:
    """2.6 (B2): 'Nyt login på din konto' to the user's own devices. entry:
    {ua, at, ip, cc}. Never raises; 1 when queued."""
    try:
        if not available():
            return 0
        clean = {"ua": str(entry.get("ua") or "")[:40], "at": int(entry.get("at") or 0),
                 "ip": str(entry.get("ip") or "")[:45], "cc": str(entry.get("cc") or "")[:2]}
        with _conn(conn) as c:
            if c.execute("SELECT 1 FROM push_subscriptions WHERE user=? LIMIT 1", (user,)).fetchone() is None:
                return 0
            if user not in load_users():
                return 0
            enqueue(c, user, "login", {"logins": [clean]}, now=now)
        return 1
    except Exception as ex:  # noqa: BLE001
        log.warning("push: login notice not queued: %s", type(ex).__name__)
        return 0


def notify_login_failed(conn: sqlite3.Connection | None, entry: dict, *, now: int | None = None) -> int:
    """2.6 (B2): repeated failed logins -> administrators whose devices want
    'Problemer med filteret'. entry: {who, n, step}. Never raises."""
    try:
        if not available():
            return 0
        clean = {"who": str(entry.get("who") or "")[:120], "n": int(entry.get("n") or 0),
                 "step": str(entry.get("step") or "")[:10]}
        with _conn(conn) as c:
            names = recipients(c, "problem")
            for name in names:
                enqueue(c, name, "login_failed", {"failed": [clean]}, now=now)
        return len(names)
    except Exception as ex:  # noqa: BLE001
        log.warning("push: failed-login notice not queued: %s", type(ex).__name__)
        return 0


def on_problem(conn: sqlite3.Connection | None, problem: str, account: str | None = None, *,
               now: int | None = None) -> int:
    """An engine alert (the same moments mailer.notify('alert') is used) ->
    'problem' push to administrators who want it. Never raises."""
    if problem not in PROBLEMS:
        return 0
    return notify_event(conn, "problem", account=account, problem=problem, now=now)


def check_heartbeat_gap(path: str | Path | None = None, *, now: float | None = None,
                        min_gap: int = DOWNTIME_MIN) -> bool:
    """Engine start: the previous heartbeat is older than min_gap -> a
    'Filteret kører igen' problem push (independent of SMTP). Call BEFORE
    the old heartbeat is removed."""
    try:
        p = Path(path) if path is not None else STATE_DIR / "heartbeat"
        last = int(float(p.read_text(encoding="utf-8", errors="replace").split()[0]))
    except (OSError, IndexError, ValueError):
        return False
    t = int(now if now is not None else time.time())
    if last <= 0 or t - last < min_gap:
        return False
    return on_problem(None, "downtime", now=t) > 0


# ---------------------------------------------------------------------------
# Status (sfctl push-status / doctor)
# ---------------------------------------------------------------------------


def status(*, now: int | None = None) -> dict:
    """No endpoints, no keys - counts, hosts and the last errors."""
    t = int(now if now is not None else time.time())
    out: dict[str, Any] = {"available": available(), "key": None, "key_mode": None, "subject_ok": False,
                           "devices": [], "queued": 0, "sent_24h": 0, "failed_24h": 0, "dropped_24h": 0,
                           "worker": worker_alive(), "refused": None}
    if not out["available"]:
        return out
    wp = _wp()
    path = wp.key_path(STATE_DIR)
    if path.exists():
        try:
            st = path.stat()
            out["key_mode"] = st.st_mode & 0o777
            out["key_uid"] = st.st_uid
            out["key"] = wp.key_fingerprint(vapid_key(create=False))
        except Exception as ex:  # noqa: BLE001
            out["key_error"] = type(ex).__name__
    out["subject_ok"] = vapid_subject() is not None
    with _conn(None) as conn:
        for r in conn.execute("SELECT * FROM push_subscriptions ORDER BY user, id"):
            out["devices"].append({"id": int(r["id"]), "user": r["user"], "ua": r["user_agent_short"] or "Enhed",
                                   "host": wp.endpoint_host(r["endpoint"]), "created_at": r["created_at"],
                                   "last_ok_at": r["last_ok_at"], "fail_count": int(r["fail_count"] or 0),
                                   "last_error": r["last_error"], "prefs": parse_prefs(r["prefs"])})
        out["queued"] = int(conn.execute("SELECT COUNT(*) FROM push_queue WHERE status='queued'").fetchone()[0])
        out["refused"] = _refused(conn)
        for key, sql in (("sent_24h", "sent_at>=?"), ("failed_24h", "status='failed' AND created_at>=?"),
                         ("dropped_24h", "status IN ('dropped','expired') AND created_at>=?")):
            out[key] = int(conn.execute(f"SELECT COUNT(*) FROM push_queue WHERE kind<>'test' AND {sql}",
                                        (t - 86400,)).fetchone()[0])
    return out
