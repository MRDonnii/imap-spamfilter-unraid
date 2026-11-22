"""Outgoing mail (SMTP) for the spamfilter 2.3 (backlog B29).

One small, dependency-free module used by the web UI (dashboard.py,
ui_admin.py), the break-glass CLI (sfctl.py), the engine and - through
`docker exec spamfilter python3 /app/mailer.py notify ...` - the host
monitor. It sends:

  * one-time codes for two-step login by mail ("Kode på mail"),
  * alarms, the daily summary, the weekly report and security notices
    to the recipients chosen under Indstillinger -> Notifikationer,
  * test mails ("Send testmail").

Settings live in settings_kv (UI-owned table, additive):

  smtp        JSON {enabled, host, port, security (starttls|ssl), auth
              (password|account), username, account, from_addr, from_name}
  smtp_state  JSON {last_ok_at, last_error {code, text, at}, last_test {...}}
  mail_notify JSON {kind: {"on": bool, "to": [addresses]}} for the kinds
              alert|digest|weekly|security

The SMTP password is a 0600 file STATE_DIR/smtp.password (owned by the
container user 10099), never stored in settings, never rendered back and
never written to logs or the audit trail. "Brug postkassens login"
(auth=account) references one configured mailbox instead: its user name is
the mailbox address and the password is read from that account's existing
password_file at send time - never copied or shown.

Security rules: TLS is mandatory (STARTTLS or implicit TLS with
ssl.create_default_context(): certificate AND host name verification);
there is no plain-text mode, so AUTH can never happen without TLS. All
addresses and header texts are validated (no CR/LF/control characters, no
lists), every connection has a timeout.

Every mail goes through the NEW additive table `mail_outbox` (older
versions ignore it). Each row records the Message-ID
(`<notify.<hex>@<msgid_domain>>`, local site config) and the header `X-TH-Spamfilter:
notify`, so the engine can recognise its own notifications in a scanned
mailbox (is_own_notification). One background worker thread per process
(ensure_worker(), idempotent) delivers queued rows with retries and
backoff, global and per-recipient rate limits; it never raises and never
blocks the engine or the web UI. One-time codes are "transient": their
text is held only in memory (bounded) and never written to the database.

CLI (inside the container):
  python3 /app/mailer.py notify --kind alert --subject S --text T [--to ADDR]
  python3 /app/mailer.py test ADDR
  python3 /app/mailer.py status
  python3 /app/mailer.py process
Exit codes: 0 sent/queued, 1 failed, 2 usage, 3 not configured / turned off.
"""

from __future__ import annotations

import argparse
import hmac
import html as _html
import json
import logging
import os
import queue
import re
import smtplib
import socket
import sqlite3
import ssl
import sys
import tempfile
import threading
import time
import uuid
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path
from typing import Any, Callable, Iterable

import siteconfig

log = logging.getLogger("mailer")

# ---------------------------------------------------------------------------
# Paths (configure_paths() re-derives them; dashboard.configure_paths and
# the dashboard's mail() helper keep them in step with the web UI)
# ---------------------------------------------------------------------------

STATE_DIR = Path(os.environ.get("STATE_DIR", "/state"))
CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", "/config/accounts.yml"))
DB_PATH = STATE_DIR / "spamfilter.db"
PASSWORD_FILE = STATE_DIR / "smtp.password"
AUDIT_FILE = STATE_DIR / "admin-audit.jsonl"
OWNER_UID = 10099
OWNER_GID = 10099


def configure_paths(state_dir: Path | str | None = None, config_path: Path | str | None = None,
                    *, db_path: Path | str | None = None, audit_file: Path | str | None = None) -> None:
    global STATE_DIR, CONFIG_PATH, DB_PATH, PASSWORD_FILE, AUDIT_FILE
    if state_dir is not None:
        STATE_DIR = Path(state_dir)
        DB_PATH = STATE_DIR / "spamfilter.db"
        PASSWORD_FILE = STATE_DIR / "smtp.password"
        AUDIT_FILE = STATE_DIR / "admin-audit.jsonl"
    if config_path is not None:
        CONFIG_PATH = Path(config_path)
    if db_path is not None:
        DB_PATH = Path(db_path)
    if audit_file is not None:
        AUDIT_FILE = Path(audit_file)


# ---------------------------------------------------------------------------
# Constants + vocabulary
# ---------------------------------------------------------------------------

SETTINGS_KEY = "smtp"
STATE_KEY = "smtp_state"
ROUTES_KEY = "mail_notify"

SECURITY_MODES = ("starttls", "ssl")
SECURITY_LABELS = {"starttls": "STARTTLS · port 587", "ssl": "SSL/TLS · port 465"}
SECURITY_SHORT = {"starttls": "STARTTLS", "ssl": "SSL/TLS"}
AUTH_MODES = ("password", "account")   # always authenticated, always TLS
DEFAULT_FROM_NAME = siteconfig.brand(" ")   # 'Spamfilter <server name>' (local site config)
DEFAULTS: dict[str, Any] = {"enabled": False, "host": "", "port": 587, "security": "starttls", "auth": "password",
                            "username": "", "account": "", "from_addr": "", "from_name": DEFAULT_FROM_NAME,
                            # "host:port:account" an admin confirmed with the mailbox password
                            # (auth 'account' with a server that is not the mailbox's own provider).
                            "account_bound": ""}

# Provider suggestions: the providers' documented submission servers. They
# are suggestions only - the test mail is what confirms them.
PROVIDER_NOTE = "forslag – bekræftes med testmail"
PROVIDERS: tuple[dict, ...] = (
    {"id": "gigahost", "label": "Gigahost", "host": "smtp.gigahost.dk", "port": 587, "security": "starttls",
     "imap_hosts": ("imap.gigahost.dk",)},
    {"id": "scannet", "label": "Scannet", "host": "mail.scannet.dk", "port": 587, "security": "starttls",
     "imap_hosts": ("mail.scannet.dk",)},
)

KINDS = ("alert", "digest", "weekly", "security")
KIND_LABELS = {"alert": "Alarmer", "digest": "Daglig opsummering", "weekly": "Ugerapport", "security": "Sikkerhed"}
KIND_HINTS = {
    "alert": "Container nede, login afvist, sikkerhedsbremsen og andre problemer – og når de er løst igen.",
    "digest": "Hver morgen: gårsdagens tal for hver postkasse – som mail, ud over Unraid-notifikationen.",
    "weekly": ("Mandag: ugerapporten som mail – uafhængigt af, om den også lægges i indbakken "
               "(se Ugerapport)."),
    "security": ("Nyt to-trins-login, ny adgangskode, passkeys og nulstillinger, login fra en ny enhed og gentagne "
                 "forkerte login-forsøg. Brugeren får også selv besked."),
}
INTERNAL_KINDS = ("code", "test")

SEND_TIMEOUT = 20                 # seconds per SMTP connection/command
GLOBAL_PER_HOUR = 60              # all mails, rolling hour
PER_RECIPIENT_PER_HOUR = 20       # one address, rolling hour
# Login codes and alerts must get through even when other mail (security
# notices a user can trigger, reports) used up its share: those kinds stop
# PRIORITY_RESERVE short of GLOBAL_PER_HOUR, and a priority mail's
# per-recipient limit only counts priority mail.
PRIORITY_KINDS = frozenset({"code", "alert"})
PRIORITY_RESERVE = 20
MAX_ATTEMPTS = 5
BACKOFF = (60, 300, 900, 1800, 3600)
RATE_DEFER = 300                  # a rate-limited row waits this long (no attempt counted)
QUEUE_MAX = 200                   # bounded in-memory wake queue + transient bodies
OUTBOX_MAX_QUEUED = 500           # never let the outbox grow without bound
DEFAULT_TTL = 24 * 3600           # an undeliverable alert older than a day is pointless
CODE_TTL = 10 * 60                # one-time codes
STALE_CLAIM = 300                 # a 'sending' row of a crashed process is retried after this
KEEP_DAYS = 30                    # outbox metadata (Message-IDs for the engine skip)
WORKER_POLL = 30
MAX_RECIPIENTS = 10
SUBJECT_MAX = 200
NAME_MAX = 64
TEXT_MAX = 100_000
PASSWORD_MAX = 256
DOWNTIME_MIN = 10 * 60

HEADER_NAME = "X-TH-Spamfilter"
HEADER_VALUE = "notify"
MSGID_DOMAIN = siteconfig.msgid_domain()   # local site config; neutral default on a fresh install
MSGID_RE = re.compile(r"^<notify\.[0-9a-f]{32}@" + re.escape(MSGID_DOMAIN) + r">$")

ERROR_TEXTS = {
    "not_configured": "Mailserveren er ikke sat op.",
    "disabled": "Afsendelse af mail er slået fra.",
    "invalid_address": "Mailadressen er ikke gyldig.",
    "invalid_header": "Emne eller navn indeholder ugyldige tegn (fx linjeskift).",
    "invalid_text": "Beskeden er tom eller for lang.",
    "invalid_kind": "Ukendt type besked.",
    "no_password": "Der er ikke gemt en adgangskode til mailserveren.",
    "no_account": "Postkassen, hvis login skal bruges, findes ikke længere.",
    "account_password": "Postkassens adgangskode kunne ikke læses.",
    "account_host": ("Postkassens login sendes kun til postkassens egen mailserver. Bekræft serveren med "
                     "postkassens adgangskode under Indstillinger → Mailserver."),
    "connect": "Kunne ikke forbinde til mailserveren. Tjek server og port.",
    "dns": "Servernavnet kunne ikke slås op. Tjek stavningen.",
    "timeout": "Mailserveren svarede ikke i tide.",
    "no_starttls": "Serveren tilbyder ikke STARTTLS på denne port. Vælg SSL/TLS (typisk port 465) eller en anden port.",
    "cert": "Serverens certifikat kunne ikke bekræftes (forkert servernavn eller ugyldigt certifikat).",
    "tls": "Den krypterede forbindelse kunne ikke oprettes. Tjek port og sikkerhed (STARTTLS = 587, SSL/TLS = 465).",
    "auth": "Mailserveren afviste brugernavn eller adgangskode.",
    "auth_unsupported": "Mailserveren tilbyder ikke login (AUTH) her.",
    "sender": "Mailserveren afviste afsenderadressen. Brug en adresse, som login'et må sende fra.",
    "recipient": "Mailserveren afviste modtageradressen.",
    "server": "Mailserveren returnerede en fejl. Prøv igen senere.",
    "rate": "For mange mails på kort tid – prøv igen senere.",
    "queue_full": "Udbakken er fuld – prøv igen senere.",
    "off": "Denne type besked er slået fra under Notifikationer.",
    "no_recipients": "Der er ingen modtagere for denne type besked.",
    "expired": "Beskeden blev for gammel, før den kunne sendes.",
    "error": "Mailen kunne ikke sendes.",
}
# Errors a retry cannot fix: the row fails at once.
PERMANENT = frozenset({"not_configured", "disabled", "invalid_address", "invalid_header", "invalid_text",
                       "invalid_kind", "no_password", "no_account", "account_password", "account_host",
                       "no_starttls", "cert",
                       "auth", "auth_unsupported", "sender", "recipient"})

_LOCAL_RE = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
_LABEL_RE = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_TLD_RE = r"(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{1,59})"
ADDRESS_RE = re.compile(rf"^(?P<local>{_LOCAL_RE})@(?P<domain>(?:{_LABEL_RE}\.)+{_TLD_RE})$")
HOST_RE = re.compile(rf"^(?:{_LABEL_RE}\.)*{_LABEL_RE}$")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")


class MailError(Exception):
    """A send/validation problem with a stable `code` and a Danish text."""

    def __init__(self, code: str, text: str | None = None) -> None:
        self.code = code if code in ERROR_TEXTS else "error"
        self.text = text or ERROR_TEXTS[self.code]
        super().__init__(self.code)


def error_text(code: str | None) -> str:
    return ERROR_TEXTS.get(str(code or ""), ERROR_TEXTS["error"])


# ---------------------------------------------------------------------------
# Validation + masking
# ---------------------------------------------------------------------------


def validate_address(value: Any) -> str:
    """One plain address ('a@b.dk'): no display name, no list, no CR/LF or
    other control characters (header injection), max 254 characters.
    Returns it with the domain lower-cased; raises MailError."""
    text = str(value if value is not None else "")
    if _CTRL_RE.search(text):
        raise MailError("invalid_address")
    text = text.strip()
    if not text or len(text) > 254:
        raise MailError("invalid_address")
    m = ADDRESS_RE.match(text)
    if not m or len(m.group("local")) > 64:
        raise MailError("invalid_address")
    return f"{m.group('local')}@{m.group('domain').lower()}"


def is_valid_address(value: Any) -> bool:
    try:
        validate_address(value)
        return True
    except MailError:
        return False


def clean_header_text(value: Any, limit: int, *, required: bool = False) -> str:
    """A single-line header value (subject, display name). CR/LF and other
    control characters are refused, not stripped: they are an injection
    attempt or a bug, never a typo."""
    text = str(value if value is not None else "")
    if _CTRL_RE.search(text):
        raise MailError("invalid_header")
    text = " ".join(text.split())
    if len(text) > limit or (required and not text):
        raise MailError("invalid_header")
    return text


def _clean_body(value: Any) -> str:
    text = str(value if value is not None else "").replace("\r\n", "\n").replace("\r", "\n")
    text = "".join(c for c in text if c in "\n\t" or not _CTRL_RE.match(c))
    if not text.strip() or len(text) > TEXT_MAX:
        raise MailError("invalid_text")
    return text


def mask_address(value: Any) -> str:
    """'ole@bynet.example' -> 'o…@bynet.example' (for logs, audit and the login page)."""
    text = str(value or "")
    local, at, domain = text.rpartition("@")
    if not at or not local:
        return "…"
    return f"{local[0]}…@{domain}"


def valid_host(value: Any) -> str:
    text = str(value or "").strip().lower().rstrip(".")
    if not text or len(text) > 253 or not HOST_RE.match(text) or "://" in text:
        raise ValueError("Skriv kun servernavnet, fx smtp.gigahost.dk (uden https:// og port).")
    return text


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings_kv (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS mail_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    recipient TEXT NOT NULL,
    subject TEXT NOT NULL,
    body_text TEXT,
    body_html TEXT,
    transient INTEGER NOT NULL DEFAULT 0,
    message_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER,
    created_at INTEGER NOT NULL,
    claimed_at INTEGER,
    sent_at INTEGER,
    last_error TEXT,
    owner TEXT
);
CREATE INDEX IF NOT EXISTS idx_mail_outbox_due ON mail_outbox(status, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_mail_outbox_rcpt ON mail_outbox(recipient, sent_at);
CREATE INDEX IF NOT EXISTS idx_mail_outbox_msgid ON mail_outbox(message_id);
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


def _kv_get(key: str) -> str | None:
    conn = _db()
    try:
        row = conn.execute("SELECT value FROM settings_kv WHERE key=?", (key,)).fetchone()
        return str(row[0]) if row and row[0] is not None else None
    finally:
        conn.close()


def _kv_set(key: str, value: str) -> None:
    conn = _db()
    try:
        conn.execute("INSERT INTO settings_kv(key, value) VALUES(?,?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
        conn.commit()
    finally:
        conn.close()


def _kv_json(key: str) -> dict:
    try:
        data = json.loads(_kv_get(key) or "{}")
    except (TypeError, ValueError, sqlite3.Error):
        return {}
    return data if isinstance(data, dict) else {}


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


def _coerce_settings(data: dict) -> dict:
    out = dict(DEFAULTS)
    for k in DEFAULTS:
        if k in data and data[k] is not None:
            out[k] = data[k]
    out["enabled"] = bool(out["enabled"]) and out["enabled"] not in ("0", "false", "off")
    try:
        out["port"] = int(out["port"])
    except (TypeError, ValueError):
        out["port"] = DEFAULTS["port"]
    if out["security"] not in SECURITY_MODES:
        out["security"] = "starttls"
    if out["auth"] not in AUTH_MODES:
        out["auth"] = "password"
    for k in ("host", "username", "account", "from_addr", "from_name", "account_bound"):
        out[k] = str(out[k] or "")
    return out


def get_settings() -> dict:
    """The stored SMTP settings merged with DEFAULTS (never the password)."""
    try:
        return _coerce_settings(_kv_json(SETTINGS_KEY))
    except Exception as ex:  # noqa: BLE001 - never break a caller
        log.warning("smtp settings unreadable: %s", type(ex).__name__)
        return dict(DEFAULTS)


def password_stored() -> bool:
    try:
        return PASSWORD_FILE.is_file() and PASSWORD_FILE.stat().st_size > 0
    except OSError:
        return False


def _read_password() -> str | None:
    try:
        value = PASSWORD_FILE.read_text(encoding="utf-8").rstrip("\r\n")
    except (OSError, UnicodeDecodeError):
        return None
    return value or None


def _write_password(password: str) -> None:
    """Atomic 0600 write into the state dir (owned by the container user)."""
    if not password or len(password) > PASSWORD_MAX or any(c in password for c in "\r\n\x00"):
        raise ValueError("Adgangskoden er tom, for lang eller indeholder ugyldige tegn.")
    PASSWORD_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".smtp.password.", dir=str(PASSWORD_FILE.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(password + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            os.chown(tmp, OWNER_UID, OWNER_GID)
        os.replace(tmp, PASSWORD_FILE)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def clear_password() -> bool:
    try:
        PASSWORD_FILE.unlink()
        return True
    except FileNotFoundError:
        return False


def _config_accounts() -> list[dict]:
    try:
        import yaml  # the container ships PyYAML (the dashboard needs it)

        raw = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001 - missing/broken config = no accounts
        return []
    accs = raw.get("accounts") if isinstance(raw, dict) else None
    return [a for a in (accs or []) if isinstance(a, dict) and a.get("name")]


def account_choices() -> list[dict]:
    """[{name, user, imap_host, suggestion}] of the configured mailboxes
    (for "Brug postkassens login")."""
    out = []
    for a in _config_accounts():
        host = str(a.get("imap_host") or "")
        out.append({"name": str(a["name"]), "user": str(a.get("user") or ""), "imap_host": host,
                    "suggestion": provider_for_imap(host)})
    return out


def provider_for_imap(imap_host: str) -> dict | None:
    host = str(imap_host or "").lower()
    for p in PROVIDERS:
        if host in p["imap_hosts"]:
            return p
    return None


def _account_login(name: str) -> tuple[str, str]:
    """(user, password) of a configured mailbox, read at send time."""
    entry = next((a for a in _config_accounts() if str(a.get("name")) == name), None)
    if entry is None or not entry.get("user"):
        raise MailError("no_account")
    pf = entry.get("password_file")
    password = None
    if pf:
        p = Path(str(pf))
        if not p.is_absolute():
            raise MailError("account_password")
        try:
            password = p.read_text(encoding="utf-8").rstrip("\r\n")
        except (OSError, UnicodeDecodeError):
            raise MailError("account_password") from None
    elif entry.get("password"):
        password = str(entry.get("password"))
    if not password:
        raise MailError("account_password")
    return str(entry["user"]), password


def _account_entry(name: str) -> dict | None:
    return next((a for a in _config_accounts() if str(a.get("name")) == name), None)


def account_binding(settings: dict) -> str:
    return f"{str(settings.get('host') or '').lower()}:{int(settings.get('port') or 0)}:{settings.get('account') or ''}"


def account_host_is_own(settings: dict) -> bool:
    """True when the SMTP server is the mailbox's OWN provider (the
    documented submission host for its IMAP server, e.g. Gigahost)."""
    entry = _account_entry(str(settings.get("account") or ""))
    prov = provider_for_imap(str((entry or {}).get("imap_host") or ""))
    return prov is not None and str(settings.get("host") or "").lower() == str(prov["host"]).lower()


def account_login_allowed(settings: dict) -> bool:
    """'Brug postkassens login' never sends a mailbox password to a server it
    was not confirmed for (the 2.2 rule of the account editor): only the
    mailbox's own provider, or the exact host:port an admin confirmed by
    typing the mailbox password (settings 'account_bound')."""
    if settings.get("auth") != "account":
        return True
    return account_host_is_own(settings) or (
        bool(settings.get("account_bound")) and settings.get("account_bound") == account_binding(settings))


def effective_from(settings: dict | None = None) -> str:
    s = settings if settings is not None else get_settings()
    if s.get("from_addr"):
        return str(s["from_addr"])
    if s.get("auth") == "account":
        entry = next((a for a in _config_accounts() if str(a.get("name")) == s.get("account")), None)
        return str((entry or {}).get("user") or "")
    return str(s.get("username") or "") if is_valid_address(s.get("username")) else ""


def is_configured(settings: dict | None = None) -> bool:
    """Enabled and complete enough to try a send (the test mail proves it)."""
    s = settings if settings is not None else get_settings()
    if not s.get("enabled") or not s.get("host") or not is_valid_address(effective_from(s)):
        return False
    if s.get("auth") == "password":
        return bool(s.get("username")) and password_stored()
    if s.get("auth") == "account":
        return any(a["name"] == s.get("account") for a in account_choices()) and account_login_allowed(s)
    return False


def _credentials(settings: dict) -> tuple[str, str]:
    auth = settings.get("auth")
    if auth == "account":
        if not account_login_allowed(settings):
            raise MailError("account_host")
        return _account_login(str(settings.get("account") or ""))
    pw = _read_password()
    if not pw or not settings.get("username"):
        raise MailError("no_password")
    return str(settings["username"]), pw


def save_settings(form: dict, *, password: str | None = None, clear_stored: bool = False,
                  account_password: str | None = None) -> dict:
    """Validate + store the SMTP settings. Returns {ok, errors {field:
    Danish text}, settings, changed [keys]}; the password (if given) goes
    to the 0600 file only. A stored password is never sent to a changed
    server or user name: those changes need the password again. The same
    holds for 'Brug postkassens login': a server that is not the mailbox's
    own provider needs `account_password` (the mailbox password, compared
    and never stored), and any later host/port/mailbox change asks again."""
    old = get_settings()
    errors: dict[str, str] = {}
    new = dict(old)
    new["enabled"] = bool(form.get("enabled"))
    host = str(form.get("host") or "").strip()
    try:
        new["host"] = valid_host(host) if host else ""
    except ValueError as ex:
        errors["host"] = str(ex)
    try:
        port = int(str(form.get("port") or "").strip() or 0)
        if not 1 <= port <= 65535:
            raise ValueError
        new["port"] = port
    except ValueError:
        errors["port"] = "Porten skal være et tal mellem 1 og 65535 (typisk 587 eller 465)."
    sec = str(form.get("security") or "")
    if sec not in SECURITY_MODES:
        errors["security"] = "Vælg STARTTLS eller SSL/TLS."
    else:
        new["security"] = sec
    auth = str(form.get("auth") or "password")
    if auth not in AUTH_MODES:
        errors["auth"] = "Vælg hvordan der logges ind."
    else:
        new["auth"] = auth
    username = str(form.get("username") or "")
    if _CTRL_RE.search(username) or len(username.strip()) > 254 or " " in username.strip():
        errors["username"] = "Brugernavnet indeholder ugyldige tegn."
    else:
        new["username"] = username.strip()
    new["account"] = str(form.get("account") or "").strip()
    if new["auth"] == "account" and new["account"] not in {a["name"] for a in account_choices()}:
        errors["account"] = "Vælg en postkasse."
    from_addr = str(form.get("from_addr") or "").strip()
    if from_addr:
        try:
            new["from_addr"] = validate_address(from_addr)
        except MailError:
            errors["from_addr"] = "Afsenderadressen er ikke en gyldig mailadresse."
    else:
        new["from_addr"] = ""
    try:
        new["from_name"] = clean_header_text(form.get("from_name") or DEFAULT_FROM_NAME, NAME_MAX)
    except MailError:
        errors["from_name"] = f"Afsendernavnet må højst være {NAME_MAX} tegn og ikke indeholde linjeskift."
    pw = password or ""
    if pw and (len(pw) > PASSWORD_MAX or any(c in pw for c in "\r\n\x00")):
        errors["password"] = "Adgangskoden er for lang eller indeholder ugyldige tegn."
    if new["auth"] == "password" and not errors:
        if not new["username"] and (new["enabled"] or pw):
            errors["username"] = "Skriv brugernavnet (typisk hele mailadressen)."
        moved = (new["host"], new["port"], new["username"]) != (old["host"], old["port"], old["username"])
        has_pw = password_stored() and not clear_stored
        if not pw and moved and has_pw and old["host"]:
            errors["password"] = ("Skriv adgangskoden igen, når server, port eller brugernavn ændres – "
                                  "den gemte sendes aldrig til en ny server.")
        elif not pw and not has_pw and new["enabled"]:
            errors["password"] = "Skriv adgangskoden til mailserveren."
    if new["auth"] == "account" and not errors:
        if not new["host"] or account_host_is_own(new):
            new["account_bound"] = ""
        elif old.get("auth") == "account" and old.get("account_bound") == account_binding(new):
            new["account_bound"] = old["account_bound"]
        else:
            ap = account_password or ""
            new["account_bound"] = ""
            if not ap:
                errors["account_password"] = (
                    f"{new['host']} er ikke postkassens egen mailserver. Skriv postkassens adgangskode for at "
                    "bekræfte, at den må sendes dertil.")
            else:
                try:
                    _user, real = _account_login(new["account"])
                except MailError:
                    errors["account_password"] = "Postkassens gemte adgangskode kunne ikke læses."
                else:
                    if hmac.compare_digest(ap.encode("utf-8"), real.encode("utf-8")):
                        new["account_bound"] = account_binding(new)
                    else:
                        errors["account_password"] = "Adgangskoden passer ikke til postkassen."
    elif new["auth"] != "account":
        new["account_bound"] = ""
    if new["enabled"] and not new["host"] and "host" not in errors:
        errors["host"] = "Skriv mailserverens navn."
    if new["enabled"] and not errors and not is_valid_address(effective_from(new)):
        errors["from_addr"] = "Skriv den adresse, mails skal sendes fra."
    if errors:
        return {"ok": False, "errors": errors, "settings": old, "changed": []}
    if clear_stored and not pw:
        clear_password()
    if pw and new["auth"] == "password":
        _write_password(pw)
    if new["auth"] == "account" and password_stored() and not pw:
        # The mailbox login is used now: do not keep an unused secret around.
        clear_password()
    changed = [k for k in DEFAULTS if new.get(k) != old.get(k)] + (["password"] if pw else [])
    _kv_set(SETTINGS_KEY, json.dumps({k: new[k] for k in DEFAULTS}, ensure_ascii=False))
    return {"ok": True, "errors": {}, "settings": new, "changed": changed}


def set_enabled(enabled: bool) -> bool:
    """Turn sending on/off without touching anything else (sfctl smtp-disable)."""
    s = get_settings()
    if bool(s["enabled"]) == bool(enabled):
        return False
    s["enabled"] = bool(enabled)
    _kv_set(SETTINGS_KEY, json.dumps({k: s[k] for k in DEFAULTS}, ensure_ascii=False))
    _WAKE.set()
    return True


# ---------------------------------------------------------------------------
# Notification routes (Indstillinger -> Notifikationer)
# ---------------------------------------------------------------------------


def get_routes() -> dict[str, dict]:
    raw = _kv_json(ROUTES_KEY)
    out: dict[str, dict] = {}
    for kind in KINDS:
        r = raw.get(kind) if isinstance(raw.get(kind), dict) else {}
        to = [a for a in (r.get("to") or []) if isinstance(a, str) and is_valid_address(a)][:MAX_RECIPIENTS]
        out[kind] = {"on": bool(r.get("on")), "to": to}
    return out


def parse_recipients(text: Any) -> tuple[list[str], list[str]]:
    """'a@x.dk, b@y.dk' -> (valid unique addresses, invalid entries)."""
    good: list[str] = []
    bad: list[str] = []
    for part in re.split(r"[,;\s]+", str(text or "")):
        if not part:
            continue
        try:
            addr = validate_address(part)
        except MailError:
            bad.append(part[:60])
            continue
        if addr.lower() not in {g.lower() for g in good}:
            good.append(addr)
    return good, bad


def save_routes(data: dict[str, dict]) -> dict:
    """data: {kind: {"on": bool, "to": "a@x.dk, b@y.dk" | [..]}} -> {ok, errors, routes}."""
    errors: dict[str, str] = {}
    routes: dict[str, dict] = {}
    for kind in KINDS:
        r = data.get(kind) or {}
        raw_to = r.get("to") or ""
        good, bad = parse_recipients(", ".join(raw_to) if isinstance(raw_to, list) else raw_to)
        if bad:
            errors[kind] = "Ugyldig adresse: " + ", ".join(bad[:3])
        elif len(good) > MAX_RECIPIENTS:
            errors[kind] = f"Højst {MAX_RECIPIENTS} modtagere."
        elif r.get("on") and not good:
            errors[kind] = "Skriv mindst én modtager – eller slå den fra."
        routes[kind] = {"on": bool(r.get("on")), "to": good[:MAX_RECIPIENTS]}
    if errors:
        return {"ok": False, "errors": errors, "routes": get_routes()}
    _kv_set(ROUTES_KEY, json.dumps(routes, ensure_ascii=False))
    return {"ok": True, "errors": {}, "routes": routes}


def recipients_for(kind: str) -> list[str]:
    """The configured recipients of `kind` (empty when turned off)."""
    try:
        r = get_routes().get(kind) or {}
    except Exception:  # noqa: BLE001
        return []
    return list(r.get("to") or []) if r.get("on") else []


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------


def new_message_id() -> str:
    return f"<notify.{uuid.uuid4().hex}@{MSGID_DOMAIN}>"


_HTML_WRAP = (
    '<!doctype html><html lang="da"><head><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width, initial-scale=1"><title>{title}</title></head>'
    '<body style="margin:0;padding:0;background:#f4f5fa;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,'
    'sans-serif;color:#1b1e2b;">'
    '<div style="max-width:560px;margin:0 auto;padding:24px 16px;">'
    '<div style="background:#ffffff;border-radius:14px;padding:24px;border:1px solid #e3e5ef;">'
    '<div style="font-size:13px;letter-spacing:.04em;text-transform:uppercase;color:#6b4ce6;font-weight:600;">'
    '{brand}</div>'
    '<h1 style="font-size:20px;line-height:1.3;margin:8px 0 16px;">{title}</h1>{body}</div>'
    '<p style="font-size:12px;color:#7a7f95;margin:16px 4px 0;">Automatisk besked fra dit spamfilter. '
    'Svar ikke på denne mail.</p></div></body></html>')


def default_html(subject: str, text: str, *, code: str | None = None) -> str:
    """Simple HTML twin of the plain text (escaped; inline styles only -
    this is a mail, not a web page)."""
    paras = []
    for block in re.split(r"\n{2,}", text.strip()):
        lines = "<br>".join(_html.escape(line) for line in block.split("\n"))
        paras.append(f'<p style="font-size:15px;line-height:1.55;margin:0 0 12px;">{lines}</p>')
    body = "".join(paras)
    if code:
        body = (f'<p style="font-size:34px;letter-spacing:.18em;font-weight:700;margin:4px 0 18px;'
                f'font-family:SFMono-Regular,Menlo,Consolas,monospace;">{_html.escape(code)}</p>') + body
    return _HTML_WRAP.format(title=_html.escape(subject), body=body, brand=_html.escape(siteconfig.brand()))


def build_message(*, to: str, subject: str, text: str, html: str | None, message_id: str,
                  settings: dict) -> EmailMessage:
    """EmailMessage with validated headers. Raises MailError."""
    rcpt = validate_address(to)
    sender = validate_address(effective_from(settings))
    subj = clean_header_text(subject, SUBJECT_MAX, required=True)
    name = clean_header_text(settings.get("from_name") or DEFAULT_FROM_NAME, NAME_MAX)
    if not MSGID_RE.match(message_id):
        raise MailError("invalid_header")
    msg = EmailMessage()
    local, _, domain = sender.partition("@")
    msg["From"] = Address(display_name=name, username=local, domain=domain)
    msg["To"] = rcpt
    msg["Subject"] = subj
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = message_id
    msg["Auto-Submitted"] = "auto-generated"
    msg["X-Auto-Response-Suppress"] = "All"
    msg["Precedence"] = "bulk"
    msg[HEADER_NAME] = HEADER_VALUE
    msg.set_content(_clean_body(text))
    if html:
        msg.add_alternative(str(html), subtype="html")
    return msg


# ---------------------------------------------------------------------------
# SMTP delivery
# ---------------------------------------------------------------------------

# Seams for tests (monkeypatch these, never the network).
SMTP_CLASS: Callable[..., Any] = smtplib.SMTP
SMTP_SSL_CLASS: Callable[..., Any] = smtplib.SMTP_SSL


def tls_context() -> ssl.SSLContext:
    """Certificate + host name verification (CERT_REQUIRED, check_hostname)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _classify(ex: BaseException) -> str:
    if isinstance(ex, MailError):
        return ex.code
    if isinstance(ex, smtplib.SMTPAuthenticationError):
        return "auth"
    if isinstance(ex, smtplib.SMTPNotSupportedError):
        return "auth_unsupported"
    if isinstance(ex, smtplib.SMTPSenderRefused):
        return "sender"
    if isinstance(ex, smtplib.SMTPRecipientsRefused):
        return "recipient"
    if isinstance(ex, ssl.SSLCertVerificationError):
        return "cert"
    if isinstance(ex, ssl.CertificateError):
        return "cert"
    if isinstance(ex, ssl.SSLError):
        return "tls"
    if isinstance(ex, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(ex, socket.gaierror):
        return "dns"
    if isinstance(ex, (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected, ConnectionError)):
        return "connect"
    if isinstance(ex, smtplib.SMTPResponseException):
        return "server"
    if isinstance(ex, smtplib.SMTPException):
        return "server"
    if isinstance(ex, OSError):
        return "connect"
    return "error"


def _deliver(settings: dict, creds: tuple[str, str], msg: EmailMessage, rcpt: str) -> None:
    """One SMTP session. TLS first, always; AUTH only on the encrypted
    channel. Raises MailError (classified)."""
    host, port = str(settings["host"]), int(settings["port"])
    ctx = tls_context()
    conn = None
    try:
        if settings.get("security") == "ssl":
            conn = SMTP_SSL_CLASS(host, port, timeout=SEND_TIMEOUT, context=ctx)
            encrypted = True
        elif settings.get("security") == "starttls":
            conn = SMTP_CLASS(host, port, timeout=SEND_TIMEOUT)
            conn.ehlo()
            if not conn.has_extn("starttls"):
                raise MailError("no_starttls")
            conn.starttls(context=ctx)
            conn.ehlo()
            encrypted = True
        else:  # never: there is no plain-text mode
            raise MailError("not_configured")
        if not encrypted:  # defence in depth: AUTH never without TLS
            raise MailError("tls")
        conn.login(creds[0], creds[1])
        refused = conn.send_message(msg, from_addr=effective_from(settings), to_addrs=[rcpt])
        if refused:
            raise MailError("recipient")
        try:
            conn.quit()
        except (smtplib.SMTPException, OSError):
            pass
        conn = None
    except BaseException as ex:  # noqa: BLE001 - classified below
        if isinstance(ex, (KeyboardInterrupt, SystemExit)):
            raise
        raise MailError(_classify(ex)) from None
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------
# State (Drift) + audit
# ---------------------------------------------------------------------------


def _state_update(**changes: Any) -> None:
    try:
        st = _kv_json(STATE_KEY)
        st.update(changes)
        _kv_set(STATE_KEY, json.dumps(st, ensure_ascii=False))
    except Exception as ex:  # noqa: BLE001
        log.debug("smtp state not stored: %s", type(ex).__name__)


def _audit(action: str, result: str = "ok", detail: str = "", actor: str = "mailer") -> None:
    """Same JSON-lines format as dashboard.audit (0600, append, fsync).
    Never content, codes or full addresses."""
    record = {"ts": int(time.time()), "actor": actor, "ip": "", "action": action, "account": "",
              "result": result}
    if detail:
        record["detail"] = str(detail)[:500]
    try:
        fd = os.open(AUDIT_FILE, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as ex:
        log.warning("mail audit not written: %s", type(ex).__name__)


# ---------------------------------------------------------------------------
# Outbox, rate limits, worker
# ---------------------------------------------------------------------------

_TRANSIENT: dict[int, tuple[str, str | None]] = {}   # outbox id -> (text, html): codes never hit the DB
_TRANSIENT_LOCK = threading.Lock()
_WAKEQ: "queue.Queue[int]" = queue.Queue(maxsize=QUEUE_MAX)
_WAKE = threading.Event()
_STOP = threading.Event()
_WORKER: threading.Thread | None = None
_WORKER_LOCK = threading.Lock()
_PROCESS_LOCK = threading.Lock()
AUTO_WORKER = True          # notify()/send_code() start the worker; the CLI turns it off
# Transient rows (codes) can only be sent by the process that holds their
# text in memory; every other process leaves them alone until they expire.
PROCESS_TOKEN = f"{os.getpid()}-{uuid.uuid4().hex[:12]}"


def _rate_ok(conn: sqlite3.Connection, rcpt: str, now: int, kind: str = "") -> bool:
    """Rolling-hour limits. Priority kinds (codes, alerts) may use the whole
    GLOBAL_PER_HOUR; every other kind stops PRIORITY_RESERVE earlier, so a
    flood of notices can never block a login code or an alert."""
    since = now - 3600
    priority = kind in PRIORITY_KINDS
    total = conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE sent_at>=?", (since,)).fetchone()[0]
    if int(total) >= (GLOBAL_PER_HOUR if priority else max(1, GLOBAL_PER_HOUR - PRIORITY_RESERVE)):
        return False
    if priority:
        kinds = tuple(sorted(PRIORITY_KINDS))
        per = conn.execute(f"SELECT COUNT(*) FROM mail_outbox WHERE sent_at>=? AND recipient=? COLLATE NOCASE "
                           f"AND kind IN ({','.join('?' * len(kinds))})", (since, rcpt, *kinds)).fetchone()[0]
    else:
        per = conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE sent_at>=? AND recipient=? COLLATE NOCASE",
                           (since, rcpt)).fetchone()[0]
    return int(per) < PER_RECIPIENT_PER_HOUR


def _kick(row_id: int | None = None) -> None:
    if row_id is not None:
        try:
            _WAKEQ.put_nowait(int(row_id))
        except queue.Full:
            pass  # the periodic scan of due rows picks it up
    _WAKE.set()
    if AUTO_WORKER:
        ensure_worker()


def _enqueue(kind: str, recipients: list[str], subject: str, text: str, html: str | None, *,
             transient: bool = False, ttl: int = DEFAULT_TTL) -> list[int]:
    now = int(time.time())
    ids: list[int] = []
    conn = _db()
    try:
        queued = conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE status IN ('queued','sending')").fetchone()[0]
        # Codes are bounded by QUEUE_MAX (in memory) and the per-user send
        # limit; every stored kind - also 'security' - by OUTBOX_MAX_QUEUED.
        if int(queued) + len(recipients) > OUTBOX_MAX_QUEUED and kind != "code":
            raise MailError("queue_full")
        if transient:
            with _TRANSIENT_LOCK:
                if len(_TRANSIENT) + len(recipients) > QUEUE_MAX:
                    raise MailError("queue_full")
        for rcpt in recipients:
            cur = conn.execute(
                "INSERT INTO mail_outbox(kind, recipient, subject, body_text, body_html, transient, message_id, "
                "status, attempts, next_attempt_at, expires_at, created_at, owner) "
                "VALUES(?,?,?,?,?,?,?,'queued',0,?,?,?,?)",
                (kind, rcpt, subject, None if transient else text, None if transient else html,
                 1 if transient else 0, new_message_id(), now, now + ttl, now,
                 PROCESS_TOKEN if transient else None))
            row_id = int(cur.lastrowid)
            ids.append(row_id)
            if transient:
                with _TRANSIENT_LOCK:
                    _TRANSIENT[row_id] = (text, html)
        conn.commit()
    except BaseException:
        conn.rollback()
        with _TRANSIENT_LOCK:
            for i in ids:
                _TRANSIENT.pop(i, None)
        raise
    finally:
        conn.close()
    for i in ids:
        _kick(i)
    return ids


def notify(kind: str, subject: str, text: str, html: str | None = None,
           recipients: Iterable[str] | None = None) -> dict:
    """Queue a notification. kind: alert|digest|weekly|security.
    recipients=None -> the configured recipients of that kind (must be
    turned on). Never raises: {ok, code, text, queued, ids}."""
    try:
        if kind not in KINDS:
            raise MailError("invalid_kind")
        settings = get_settings()
        if not settings["enabled"]:
            raise MailError("disabled" if settings.get("host") else "not_configured")
        if not is_configured(settings):
            raise MailError("not_configured")
        if recipients is None:
            route = get_routes().get(kind) or {}
            if not route.get("on"):
                raise MailError("off")
            rcpts = list(route.get("to") or [])
        else:
            rcpts = [validate_address(r) for r in recipients]
        uniq: list[str] = []
        for r in rcpts:
            if r.lower() not in {u.lower() for u in uniq}:
                uniq.append(r)
        if not uniq:
            raise MailError("no_recipients")
        if len(uniq) > MAX_RECIPIENTS:
            raise MailError("invalid_address")
        subj = clean_header_text(subject, SUBJECT_MAX, required=True)
        body = _clean_body(text)
        ids = _enqueue(kind, uniq[:MAX_RECIPIENTS], subj, body, html or default_html(subj, body))
        return {"ok": True, "code": "queued", "queued": len(ids), "ids": ids,
                "text": f"Sat i kø til {len(ids)} modtager{'e' if len(ids) != 1 else ''}."}
    except MailError as ex:
        return {"ok": False, "code": ex.code, "queued": 0, "ids": [], "text": ex.text}
    except Exception as ex:  # noqa: BLE001 - a notification must never break the caller
        log.warning("notify failed: %s", type(ex).__name__)
        return {"ok": False, "code": "error", "queued": 0, "ids": [], "text": ERROR_TEXTS["error"]}


CODE_PURPOSE_TEXT = {
    "login": ("Din login-kode til Spamfilter",
              "Hej {name}\n\nBrug koden herover til at logge ind på spamfilteret. Den gælder i {minutes} minutter "
              "og kan kun bruges én gang.\n\nHar du ikke selv prøvet at logge ind, så kender en anden din "
              "adgangskode: skift den under Min konto – eller bed administratoren om hjælp."),
    "verify": ("Bekræft din mailadresse til Spamfilter",
               "Hej {name}\n\nSkriv koden herover på siden “Kode på mail” for at bekræfte, at login-koder må "
               "sendes til denne adresse. Den gælder i {minutes} minutter.\n\nHar du ikke bedt om det, så "
               "ignorér bare mailen."),
    "manage": ("Din bekræftelseskode til Spamfilter",
               "Hej {name}\n\nBrug koden herover til at bekræfte en ændring af dit to-trins-login. Den gælder i "
               "{minutes} minutter.\n\nHar du ikke selv bedt om den, så skift din adgangskode under Min konto."),
}


def send_code(to: str, code: str, *, purpose: str = "login", name: str = "") -> dict:
    """Queue a one-time code mail (transient: the code is held only in
    memory and never stored in the outbox). {ok, code, text, ids}."""
    try:
        if not is_configured():
            raise MailError("not_configured")
        rcpt = validate_address(to)
        if not re.fullmatch(r"\d{6}", str(code or "")):
            raise MailError("invalid_text")
        subject, template = CODE_PURPOSE_TEXT.get(purpose, CODE_PURPOSE_TEXT["login"])
        shown = f"{code[:3]} {code[3:]}"
        text = f"Din kode: {shown}\n\n" + template.format(name=clean_header_text(name, NAME_MAX) or "",
                                                          minutes=CODE_TTL // 60)
        body_html = default_html(subject, template.format(name=_html.escape(name), minutes=CODE_TTL // 60),
                                 code=shown)
        ids = _enqueue("code", [rcpt], subject, text, body_html, transient=True, ttl=CODE_TTL)
        return {"ok": True, "code": "queued", "ids": ids, "text": "Koden er på vej."}
    except MailError as ex:
        return {"ok": False, "code": ex.code, "ids": [], "text": ex.text}
    except Exception as ex:  # noqa: BLE001
        log.warning("send_code failed: %s", type(ex).__name__)
        return {"ok": False, "code": "error", "ids": [], "text": ERROR_TEXTS["error"]}


def _finish(conn: sqlite3.Connection, row_id: int, status: str, *, error: str | None = None,
            sent: bool = False, clear: bool = True) -> None:
    now = int(time.time())
    conn.execute("UPDATE mail_outbox SET status=?, last_error=?, sent_at=CASE WHEN ? THEN ? ELSE sent_at END, "
                 "body_text=CASE WHEN ? THEN NULL ELSE body_text END, "
                 "body_html=CASE WHEN ? THEN NULL ELSE body_html END, claimed_at=NULL WHERE id=?",
                 (status, error, 1 if sent else 0, now, 1 if clear else 0, 1 if clear else 0, row_id))
    conn.commit()
    if clear:
        with _TRANSIENT_LOCK:
            _TRANSIENT.pop(row_id, None)


def process_outbox(*, ids: Iterable[int] | None = None, limit: int = 20, now: int | None = None) -> dict:
    """Deliver due rows (or exactly `ids` when given and due). Never raises.
    Returns counts {sent, failed, retry, deferred, expired, dropped}."""
    counts = {"sent": 0, "failed": 0, "retry": 0, "deferred": 0, "expired": 0, "dropped": 0}
    if not _PROCESS_LOCK.acquire(timeout=SEND_TIMEOUT * 3):
        return counts
    try:
        conn = _db()
    except Exception as ex:  # noqa: BLE001
        _PROCESS_LOCK.release()
        log.warning("outbox unavailable: %s", type(ex).__name__)
        return counts
    try:
        t = int(now if now is not None else time.time())
        conn.execute("UPDATE mail_outbox SET status='queued', claimed_at=NULL WHERE status='sending' "
                     "AND claimed_at IS NOT NULL AND claimed_at<?", (t - STALE_CLAIM,))
        # Codes of another (or a restarted) process: nobody can send them any more.
        n = conn.execute("UPDATE mail_outbox SET status='expired', last_error='expired' WHERE status='queued' "
                         "AND transient=1 AND expires_at IS NOT NULL AND expires_at<?", (t,)).rowcount
        counts["expired"] += max(0, int(n))
        conn.commit()
        mine = "(transient=0 OR owner=?)"
        if ids is not None:
            want = [int(i) for i in ids][:limit]
            rows = [conn.execute(f"SELECT * FROM mail_outbox WHERE id=? AND status='queued' AND next_attempt_at<=? "
                                 f"AND {mine}", (i, t, PROCESS_TOKEN)).fetchone() for i in want]
            rows = [r for r in rows if r is not None]
        else:
            rows = conn.execute(f"SELECT * FROM mail_outbox WHERE status='queued' AND next_attempt_at<=? AND {mine} "
                                "ORDER BY (kind='code') DESC, (kind='alert') DESC, id LIMIT ?", (t, PROCESS_TOKEN, int(limit))).fetchall()
        if not rows:
            return counts
        settings = get_settings()
        creds_cache: dict[str, Any] = {}
        for row in rows:
            row_id = int(row["id"])
            claimed = conn.execute("UPDATE mail_outbox SET status='sending', claimed_at=? WHERE id=? "
                                   "AND status='queued'", (t, row_id))
            conn.commit()
            if claimed.rowcount != 1:
                continue  # another process took it
            if row["expires_at"] is not None and t > int(row["expires_at"]):
                _finish(conn, row_id, "expired", error="expired")
                counts["expired"] += 1
                continue
            if not settings["enabled"] or not is_configured(settings):
                _finish(conn, row_id, "dropped", error="disabled" if not settings["enabled"] else "not_configured")
                counts["dropped"] += 1
                continue
            if row["transient"]:
                with _TRANSIENT_LOCK:
                    payload = _TRANSIENT.get(row_id)
                if payload is None:  # restarted since: the code is gone (the user asks for a new one)
                    _finish(conn, row_id, "expired", error="expired")
                    counts["expired"] += 1
                    continue
                text, body_html = payload
            else:
                text, body_html = str(row["body_text"] or ""), row["body_html"]
            rcpt = str(row["recipient"])
            if not _rate_ok(conn, rcpt, t, str(row["kind"] or "")):
                conn.execute("UPDATE mail_outbox SET status='queued', claimed_at=NULL, next_attempt_at=?, "
                             "last_error='rate' WHERE id=?", (t + RATE_DEFER, row_id))
                conn.commit()
                counts["deferred"] += 1
                continue
            try:
                if "creds" not in creds_cache:
                    try:
                        creds_cache["creds"] = _credentials(settings)
                    except MailError as ex:
                        creds_cache["error"] = ex
                        creds_cache["creds"] = None
                if creds_cache.get("error") is not None:
                    raise creds_cache["error"]
                msg = build_message(to=rcpt, subject=str(row["subject"]), text=text, html=body_html,
                                    message_id=str(row["message_id"]), settings=settings)
                _deliver(settings, creds_cache["creds"], msg, rcpt)
            except MailError as ex:
                attempts = int(row["attempts"] or 0) + 1
                if ex.code in PERMANENT or attempts >= MAX_ATTEMPTS:
                    conn.execute("UPDATE mail_outbox SET attempts=? WHERE id=?", (attempts, row_id))
                    _finish(conn, row_id, "failed", error=ex.code)
                    counts["failed"] += 1
                    _state_update(last_error={"code": ex.code, "text": ex.text, "at": time.time()})
                    _audit("mail_failed", "failed", f"{row['kind']} til {mask_address(rcpt)}: {ex.code}")
                    log.warning("mail %s to %s failed: %s", row["kind"], mask_address(rcpt), ex.code)
                else:
                    delay = BACKOFF[min(attempts - 1, len(BACKOFF) - 1)]
                    conn.execute("UPDATE mail_outbox SET status='queued', attempts=?, next_attempt_at=?, "
                                 "last_error=?, claimed_at=NULL WHERE id=?", (attempts, t + delay, ex.code, row_id))
                    conn.commit()
                    counts["retry"] += 1
                    _state_update(last_error={"code": ex.code, "text": ex.text, "at": time.time()})
                    log.info("mail %s to %s: %s, retry in %ss", row["kind"], mask_address(rcpt), ex.code, delay)
                continue
            _finish(conn, row_id, "sent", sent=True)
            counts["sent"] += 1
            _state_update(last_ok_at=time.time())
            _audit("mail_sent", "ok", f"{row['kind']} til {mask_address(rcpt)}")
        return counts
    except Exception as ex:  # noqa: BLE001 - the worker must survive anything
        log.warning("outbox run failed: %s", type(ex).__name__)
        return counts
    finally:
        try:
            conn.close()
        finally:
            _PROCESS_LOCK.release()


def prune(now: int | None = None) -> int:
    """Forget finished outbox rows older than KEEP_DAYS (metadata only;
    this is our own bookkeeping, never user mail)."""
    t = int(now if now is not None else time.time())
    try:
        conn = _db()
        try:
            n = conn.execute("DELETE FROM mail_outbox WHERE status NOT IN ('queued','sending') AND created_at<?",
                             (t - KEEP_DAYS * 86400,)).rowcount
            conn.commit()
            return int(n)
        finally:
            conn.close()
    except sqlite3.Error:
        return 0


def _worker_loop() -> None:
    last_prune = 0.0
    while not _STOP.is_set():
        try:
            wanted: list[int] = []
            while True:
                try:
                    wanted.append(_WAKEQ.get_nowait())
                except queue.Empty:
                    break
            if wanted:
                process_outbox(ids=wanted)
            process_outbox()
            if time.time() - last_prune > 6 * 3600:
                prune()
                last_prune = time.time()
        except Exception as ex:  # noqa: BLE001 - never die
            log.warning("mail worker: %s", type(ex).__name__)
        _WAKE.wait(WORKER_POLL)
        _WAKE.clear()


def ensure_worker() -> bool:
    """Start the one background sender of this process (idempotent)."""
    global _WORKER
    with _WORKER_LOCK:
        if _WORKER is not None and _WORKER.is_alive():
            return True
        _STOP.clear()
        try:
            _WORKER = threading.Thread(target=_worker_loop, name="mailer", daemon=True)
            _WORKER.start()
        except RuntimeError as ex:  # interpreter shutting down
            log.warning("mail worker not started: %s", ex)
            _WORKER = None
            return False
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
# Test mail + status
# ---------------------------------------------------------------------------


def send_test(to: str, *, actor: str = "") -> dict:
    """Send a test mail NOW (synchronous, max ~SEND_TIMEOUT per step) with
    the stored settings. {ok, code, text}; never raises."""
    t = int(time.time())
    try:
        rcpt = validate_address(to)
        settings = get_settings()
        if not settings.get("host"):
            raise MailError("not_configured")
        if not settings["enabled"]:
            raise MailError("disabled")
        if not is_configured(settings):
            raise MailError("no_password" if settings.get("auth") == "password" else "not_configured")
        conn = _db()
        try:
            if not _rate_ok(conn, rcpt, t):
                raise MailError("rate")
            msgid = new_message_id()
            cur = conn.execute(
                "INSERT INTO mail_outbox(kind, recipient, subject, transient, message_id, status, attempts, "
                "next_attempt_at, expires_at, created_at, claimed_at) VALUES('test',?,?,1,?,'sending',1,?,?,?,?)",
                (rcpt, "Testmail fra Spamfilter", msgid, t, t + CODE_TTL, t, t))
            row_id = int(cur.lastrowid)
            conn.commit()
            subject = "Testmail fra Spamfilter"
            text = ("Det virker! Spamfilteret kan sende mail via "
                    f"{settings['host']}:{settings['port']} ({SECURITY_SHORT.get(settings['security'], '')}).\n\n"
                    "Herfra kan der komme login-koder, alarmer og opsummeringer – alt efter hvad der er valgt "
                    "under Indstillinger → Notifikationer.")
            try:
                msg = build_message(to=rcpt, subject=subject, text=text, html=default_html(subject, text),
                                    message_id=msgid, settings=settings)
                _deliver(settings, _credentials(settings), msg, rcpt)
            except MailError as ex:
                _finish(conn, row_id, "failed", error=ex.code)
                raise
            _finish(conn, row_id, "sent", sent=True)
        finally:
            conn.close()
        _state_update(last_ok_at=time.time(), last_test={"ok": True, "code": "ok", "at": t, "to": mask_address(rcpt)})
        _audit("smtp_test", "ok", f"til {mask_address(rcpt)}", actor=actor or "mailer")
        return {"ok": True, "code": "ok",
                "text": f"Testmailen er sendt til {mask_address(rcpt)}. Tjek indbakken (og spam-mappen)."}
    except MailError as ex:
        changes: dict[str, Any] = {"last_test": {"ok": False, "code": ex.code, "at": t, "text": ex.text}}
        if ex.code not in ("invalid_address", "rate", "not_configured", "disabled"):
            changes["last_error"] = {"code": ex.code, "text": ex.text, "at": time.time()}
        _state_update(**changes)
        if ex.code not in ("invalid_address",):
            _audit("smtp_test", "failed", ex.code, actor=actor or "mailer")
        return {"ok": False, "code": ex.code, "text": ex.text}
    except Exception as ex:  # noqa: BLE001
        log.warning("send_test failed: %s", type(ex).__name__)
        return {"ok": False, "code": "error", "text": ERROR_TEXTS["error"]}


def status() -> dict:
    """For Drift / sfctl smtp-status. No password, no mail content."""
    s = get_settings()
    out: dict[str, Any] = {
        "configured": False, "enabled": bool(s["enabled"]), "host": s["host"], "port": s["port"],
        "security": s["security"], "auth": s["auth"], "account": s["account"], "username": s["username"],
        "from_addr": effective_from(s), "from_name": s["from_name"], "password_stored": password_stored(),
        "last_ok_at": None, "last_error": None, "last_test": None, "queued": 0, "failed_24h": 0, "sent_24h": 0,
        "worker_alive": worker_alive(), "routes": {}, "ok": None,
    }
    try:
        out["configured"] = is_configured(s)
        st = _kv_json(STATE_KEY)
        out["last_ok_at"] = st.get("last_ok_at")
        out["last_error"] = st.get("last_error") if isinstance(st.get("last_error"), dict) else None
        out["last_test"] = st.get("last_test") if isinstance(st.get("last_test"), dict) else None
        conn = _db()
        try:
            day = int(time.time()) - 86400
            out["queued"] = int(conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE status IN ('queued','sending')")
                                .fetchone()[0])
            out["failed_24h"] = int(conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE status='failed' "
                                                 "AND created_at>=?", (day,)).fetchone()[0])
            out["sent_24h"] = int(conn.execute("SELECT COUNT(*) FROM mail_outbox WHERE sent_at>=?", (day,))
                                  .fetchone()[0])
        finally:
            conn.close()
        out["routes"] = get_routes()
        last_err_at = (out["last_error"] or {}).get("at") or 0
        out["ok"] = (None if not out["configured"] else
                     bool(out["last_ok_at"]) and float(out["last_ok_at"] or 0) > float(last_err_at))
    except Exception as ex:  # noqa: BLE001
        log.warning("mail status incomplete: %s", type(ex).__name__)
    return out


# ---------------------------------------------------------------------------
# Engine helpers (hooks: own-mail skip, downtime notice)
# ---------------------------------------------------------------------------


def is_own_notification(message_id: str | None, header: bytes | str | None = None,
                        conn: sqlite3.Connection | None = None) -> bool:
    """True for a mail THIS filter sent: our Message-ID form, the header
    `X-TH-Spamfilter: notify` (when the caller has the headers) and a row in
    mail_outbox. A forged look-alike without the recorded ID is scanned."""
    mid = str(message_id or "").strip()
    if not MSGID_RE.match(mid):
        return False
    if header is not None:
        try:
            import email
            import email.policy

            raw = header if isinstance(header, bytes) else str(header).encode("utf-8", "replace")
            msg = email.message_from_bytes(raw, policy=email.policy.compat32)
            if str(msg.get(HEADER_NAME, "") or "").strip().lower() != HEADER_VALUE:
                return False
        except Exception:  # noqa: BLE001
            return False
    try:
        own = conn is None
        c = conn if conn is not None else _db()
        try:
            return c.execute("SELECT 1 FROM mail_outbox WHERE message_id=? LIMIT 1", (mid,)).fetchone() is not None
        finally:
            if own:
                c.close()
    except sqlite3.Error:
        return False


ALERT_DEDUP_S = 3600


def recently_queued(kind: str, subject: str, within_s: int = ALERT_DEDUP_S, *,
                    now: int | None = None) -> bool:
    """True when a mail of `kind` with exactly this subject was queued in the
    last `within_s` seconds (any status). The engine mails an alert at once
    (circuit breaker, login refused) with the same subject host-monitor uses
    a few minutes later; the CLI then skips the duplicate. Never raises."""
    t = int(now if now is not None else time.time())
    try:
        conn = _db()
        try:
            row = conn.execute("SELECT 1 FROM mail_outbox WHERE kind=? AND subject=? AND created_at>=? LIMIT 1",
                               (kind, str(subject or "")[:SUBJECT_MAX], t - int(within_s))).fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return False
    return row is not None


def _fmt_local(ts: int) -> str:
    return time.strftime("%d.%m.%Y kl. %H:%M", time.localtime(int(ts)))


def notify_downtime(since_ts: int, until_ts: int | None = None) -> dict:
    """'Spamfilteret har været stoppet fra … til …' (kind alert)."""
    until = int(until_ts if until_ts is not None else time.time())
    minutes = max(1, (until - int(since_ts)) // 60)
    span = f"{minutes} min." if minutes < 120 else f"{minutes // 60} t. {minutes % 60} min."
    text = (f"Spamfilteret har været stoppet fra {_fmt_local(since_ts)} til {_fmt_local(until)} ({span}).\n\n"
            "Det kører igen nu og tjekker den post, der er kommet i mellemtiden. Imens var kun Unraids egne "
            "notifikationer aktive – mail kan ikke sendes, mens filteret er stoppet.")
    return notify("alert", "Spamfilter: kører igen efter et stop", text)


def check_heartbeat_gap(path: str | Path | None = None, *, now: float | None = None,
                        min_gap: int = DOWNTIME_MIN) -> bool:
    """Engine startup hook: the previous heartbeat ('<ts> <boot_id>') is
    older than min_gap -> queue the downtime notice. Call BEFORE the old
    heartbeat is removed. Never raises; True when a notice was queued."""
    try:
        p = Path(path) if path is not None else STATE_DIR / "heartbeat"
        first = p.read_text(encoding="utf-8", errors="replace").split()[0]
        last = int(float(first))
    except (OSError, IndexError, ValueError):
        return False
    t = int(now if now is not None else time.time())
    if t - last < min_gap or last <= 0:
        return False
    return bool(notify_downtime(last, t).get("ok"))


# ---------------------------------------------------------------------------
# CLI (docker exec spamfilter python3 /app/mailer.py ...)
# ---------------------------------------------------------------------------

EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_OFF = 0, 1, 2, 3


def _read_text_arg(value: str | None, path: str | None) -> str:
    if path:
        if path == "-":
            return sys.stdin.read()
        return Path(path).read_text(encoding="utf-8")
    return value or ""


def main(argv: list[str] | None = None) -> int:
    global AUTO_WORKER
    AUTO_WORKER = False  # one-shot process: deliver inline, the filter's worker retries later
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    p = argparse.ArgumentParser(prog="mailer.py", description="Send mail fra spamfilteret.")
    sub = p.add_subparsers(dest="cmd", required=True)
    n = sub.add_parser("notify", help="send en notifikation til de valgte modtagere")
    n.add_argument("--kind", required=True, choices=KINDS)
    n.add_argument("--subject", required=True)
    n.add_argument("--text")
    n.add_argument("--text-file")
    n.add_argument("--to", action="append", help="modtager (ellers dem under Notifikationer)")
    t = sub.add_parser("test", help="send en testmail nu")
    t.add_argument("to")
    sub.add_parser("status", help="vis mailserverens status")
    sub.add_parser("process", help="send det, der venter i udbakken")
    try:
        args = p.parse_args(argv)
    except SystemExit as ex:
        return int(ex.code) if isinstance(ex.code, int) else EXIT_USAGE
    try:
        if args.cmd == "notify":
            if args.kind == "alert" and not args.to and recently_queued("alert", args.subject):
                # The engine already mailed this alert (2.3 engine hooks).
                print("Allerede sendt for nylig.")
                return EXIT_OK
            res = notify(args.kind, args.subject, _read_text_arg(args.text, args.text_file),
                         recipients=args.to or None)
            if not res["ok"]:
                print(res["text"])
                return EXIT_OFF if res["code"] in ("not_configured", "disabled", "off", "no_recipients") else EXIT_FAIL
            counts = process_outbox(ids=res["ids"])
            sent = counts["sent"]
            print(f"Sendt: {sent}, i kø: {len(res['ids']) - sent - counts['failed']}, fejlet: {counts['failed']}")
            return EXIT_OK if counts["failed"] == 0 else EXIT_FAIL
        if args.cmd == "test":
            res = send_test(args.to, actor="cli")
            print(res["text"])
            return EXIT_OK if res["ok"] else EXIT_FAIL
        if args.cmd == "process":
            print(json.dumps(process_outbox(limit=50)))
            return EXIT_OK
        st = status()
        print(json.dumps({k: v for k, v in st.items() if k != "routes"}, ensure_ascii=False, default=str))
        return EXIT_OK
    except (OSError, sqlite3.Error) as ex:
        print(f"Fejl: {type(ex).__name__}", file=sys.stderr)
        return EXIT_FAIL


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    sys.exit(main())
