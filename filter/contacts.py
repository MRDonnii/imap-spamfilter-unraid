"""Known contacts, reply detection, established senders and first contact
(spamfilter 2.3, backlog B10/B11/B12/B14).

What this module does (the engine injects itself; nothing here imports
filter.py, so every piece is testable on its own):

  * HMAC-SHA256 hashing of addresses, Message-IDs and domains with the
    secret /state/contacts.key (32 bytes, 0600, created on first use). A
    lost or replaced key means every stored hash is useless: all contact
    tables are wiped and the first sync runs again (full resync).
  * The sync (`sync_step`) runs INSIDE the account thread between IDLE
    slices, like junk polling - no extra IMAP connection. Read-only:
    EXAMINE, SEARCH, STATUS and BODY.PEEK header fetches only.
      - Sent folders (SPECIAL-USE \\Sent plus a Danish/English name list,
        or the account's `sent_folders`) -> known_contacts, sent_threads,
        own_identities.
      - B12 bootstrap over INBOX and the user's own folders (never Sent,
        Junk, the filter's folder, Trash, Drafts) -> sender_history.
      - chunks of 500 over resumable bookmarks, a per-slice time budget
        (3 s) so scanning new mail and IDLE are never starved, UIDVALIDITY
        change = that folder again; afterwards STATUS UIDNEXT every 15 min.
  * `evaluate` computes the trust pseudo-symbols for one scan:
    TH_KNOWN_CONTACT (-4/-3/-2, list mail max -2, -3 for a contact of a
    colleague mailbox in the same contact group), TH_KNOWN_DOMAIN (-1),
    TH_REPLY (-5) / TH_REPLY_THREAD (-2) / TH_REPLY_UNVERIFIED (0),
    TH_ESTABLISHED (-2) and TH_FIRST_CONTACT (+1). Only the strongest
    negative contact signal counts (not cumulative) and all negative trust
    TH_* together (incl. TH_NEWSLETTER) are capped at -6. Inactive until
    the account's first sync is complete.
  * B14 hooks: a user 'spam' verdict demotes a known contact / kills
    'established' (n_junk + 1), a rescue counts as kept.

Privacy: only header fields are read; contact addresses are stored as
hashes plus a mask ("j…@example.dk"); logs and events never contain a full
contact address.

Schema: additive only (new tables, created idempotently). 2.2.0 ignores
them, so a rollback keeps working. SCORE_VERSION is not changed.
"""

from __future__ import annotations

import email
import email.header
import email.message
import email.policy
import hashlib
import hmac
import json
import logging
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path
from typing import Any, Iterable, Sequence

import siteconfig

from imapclient.exceptions import IMAPClientAbortError

log = logging.getLogger("contacts")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KEY_FILE = "contacts.key"
KEY_BYTES = 32
HASH_HEX = 32
KEY_STATE = "contacts_key_id"           # engine_state key: id of the key the hashes use
REQUEST_STATE = "contacts_sync_request:"  # + account: 'Opdater nu' token (services)

FETCH_CHUNK = 500                       # UIDs per header FETCH
SLICE_BUDGET_S = 3.0                    # sync work per loop iteration
STATUS_INTERVAL_S = 15 * 60             # STATUS UIDNEXT of the Sent folders
FRESH_MIN_INTERVAL_S = 60               # at most one freshness sync per minute
FRESH_MARGIN = 6.0                      # freshness re-check when final >= threshold - 6
THREAD_KEEP_S = 5 * 365 * 86400         # sent_threads are kept 5 years
RECHECK_KEEP_S = 2 * 86400
MAX_REFS = 10                           # In-Reply-To + the last 10 References
MAX_RCPT_DOMS = 20
FP_MAX = 5                              # fingerprint entries per kind
IDENTITY_MIN = 3                        # a From identity used >= 3 times in Sent is "own"
MAX_HISTORY_FOLDERS = 200
TRUST_CAP = -6.0                        # sum of all negative trust TH_*

SCORE_REPLY = -5.0
SCORE_REPLY_THREAD = -2.0
SCORE_KC_DEFAULT = -4.0
SCORE_KC_5Y = -3.0
SCORE_KC_OLD = -2.0
SCORE_KC_LIST_MAX = -2.0
SCORE_KC_GROUP = -3.0
SCORE_KNOWN_DOMAIN = -1.0
SCORE_ESTABLISHED = -2.0
SCORE_FIRST_CONTACT = 1.0
KC_RECENT_S = 2 * 365 * 86400
KC_5Y_S = 5 * 365 * 86400
ESTABLISHED_MIN_KEPT = 3
ESTABLISHED_MIN_SPAN_S = 30 * 86400

# Negative trust pseudo-symbols written by this module (filter.TRUST_SYMBOLS
# also lists them, plus TH_NEWSLETTER).
CONTACT_SYMBOLS = frozenset({"TH_KNOWN_CONTACT", "TH_KNOWN_DOMAIN", "TH_REPLY", "TH_REPLY_THREAD",
                             "TH_ESTABLISHED"})
NEGATIVE_TRUST = CONTACT_SYMBOLS | {"TH_NEWSLETTER"}
INFO_SYMBOLS = frozenset({"TH_REPLY_UNVERIFIED", "TH_FIRST_CONTACT"})
ALL_SYMBOLS = CONTACT_SYMBOLS | INFO_SYMBOLS

# Stats (filter.STAT_METRICS) and events this module writes.
METRICS = ("known_contact", "reply_detected", "first_contact", "established")
EVENTS = ("contacts_sync_complete", "contacts_key_regenerated", "contacts_uidvalidity",
          "contact_demoted", "contact_removed", "contact_restored", "contacts_sync_requested",
          "reply_recheck")

# Hard exceptions (B10): never a trust bonus with one of these. The future
# threat class (B16) extends this via trust_blocked(..., threat=...).
HARD_EXCEPTION_EXACT = frozenset({
    "DBL_PHISH", "DBL_SPAM", "DBL_MALWARE", "URIBL_BLACK", "MIME_BAD_EXTENSION",
    "MIME_DOUBLE_BAD_EXTENSION", "FUZZY_DENIED", "TH_BRAND_SPOOF", "TH_FROM_NAME_HOMOGLYPH",
    "CLAM_VIRUS", "CLAM_PHISH", "PH_SURBL_MULTI", "URLHAUS_MALWARE_URL", "TH_ATTACH_BLOCK",
    "TH_IMPERSONATION", "TH_LOOKALIKE_DOMAIN",
})
HARD_EXCEPTION_PREFIXES = ("PHISHED_", "CLAM_VIRUS", "CLAM_PHISH")
HARD_EXCEPTION_INFO = frozenset({"PHISHED_EXCLUDED", "PHISHED_GENERIC_SERVICE"})

# Sent folder names (case-insensitive, also below INBOX<delim>).
SENT_NAMES = ("Sent", "Sent Messages", "Sent Items", "Sent Mail", "Sendt", "Sendt post",
              "Sendte elementer", "Sendte", "Udbakke", "INBOX.Sent", "mail.sent-mail")
_SKIP_SPECIAL = frozenset({"\\SENT", "\\JUNK", "\\TRASH", "\\DRAFTS", "\\ALL", "\\FLAGGED",
                           "\\IMPORTANT", "\\NOSELECT", "\\NONEXISTENT", "\\ARCHIVE_SKIP"})
_SKIP_NAME_RE = re.compile(
    r"(^|[./])(junk|spam|u[øo]nsket|bulk|trash|papirkurv|deleted|slettet|slettede|drafts?|kladder|"
    r"udkast|outbox|udbakke|sent|sendt|sendte|spamfilter|train-|trained-|templates|skabeloner)",
    re.I)

# Recipients that are never contacts.
_NOREPLY_LOCAL_RE = re.compile(
    r"^(no[-_.]?reply|do[-_.]?not[-_.]?reply|donotreply|noreply|bounces?|mailer[-_.]?daemon|"
    r"postmaster|list[-_.]?manager|listserv|majordomo|unsubscribe|abuse)([-+_.].*)?$|unsubscribe|"
    r"^bounce[-+_.]|[-+_.]bounces?$|^bounces?\+", re.I)
_LIST_DOMAINS = ("mcsv.net", "list-manage.com", "customer.io", "customeriomail.com",
                 "mailchimpapp.net", "bounces.google.com", "sendgrid.net", "mandrillapp.com",
                 "amazonses.com", "sparkpostmail.com", "mailgun.org", "rsgsv.net")

FREEMAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "hotmail.com", "hotmail.dk", "outlook.com", "outlook.dk",
    "live.com", "live.dk", "msn.com", "yahoo.com", "yahoo.dk", "ymail.com", "icloud.com",
    "me.com", "mac.com", "aol.com", "gmx.com", "gmx.net", "gmx.de", "web.de", "proton.me",
    "protonmail.com", "pm.me", "mail.dk", "jubii.dk", "stofanet.dk", "youmail.dk", "ofir.dk",
    "sol.dk", "webspeed.dk", "post.tele.dk", "mail.tele.dk", "get2net.dk", "email.dk",
    "privat.dk", "pc.dk", "city.dk", "tdcadsl.dk", "kabelmail.dk", "c.dk", "yandex.com",
    "mail.ru", "zoho.com", "tutanota.com", "fastmail.com", "seznam.cz", "qq.com", "163.com",
})

# Two-label public suffixes for the registered domain (no full PSL in the image).
_MULTI_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "com.au",
    "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz", "com.br", "net.br",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "com.cn", "net.cn", "org.cn", "com.tr", "co.za",
    "com.mx", "co.in", "net.in", "org.in", "com.sg", "com.hk", "co.kr", "com.tw", "com.ar",
    "com.pl", "co.il", "com.ua", "com.my", "co.id", "com.ph", "com.vn", "co.th", "com.ru",
    "com.es", "com.pt", "com.co", "com.pe", "com.de", "co.at", "or.at", "com.gr",
})

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9])?"
                        r"(?:\.[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9])?)+$")
_MSGID_RE = re.compile(r"<([^<>\s]{1,500})>")
_DKIM_D_RE = re.compile(r"(?:^|;)\s*d\s*=\s*([A-Za-z0-9._-]{1,253})", re.I)

SENT_ITEMS = [b"INTERNALDATE",
              b"BODY.PEEK[HEADER.FIELDS (FROM TO CC BCC MESSAGE-ID IN-REPLY-TO DATE)]"]
HISTORY_ITEMS = [b"FLAGS", b"INTERNALDATE",
                 b"BODY.PEEK[HEADER.FIELDS (FROM RETURN-PATH DKIM-SIGNATURE MESSAGE-ID DATE)]"]

SCHEMA = """
-- B10: people the user wrote to (hashed). status 'removed' / 'demoted'
-- survives every resync (the sync only updates counts and dates).
CREATE TABLE IF NOT EXISTS known_contacts (
    account       TEXT NOT NULL,
    h             TEXT NOT NULL,           -- HMAC-SHA256(contacts.key, address)[:32]
    domain        TEXT,
    mask          TEXT,                    -- "j…@example.dk"
    sent_count    INTEGER NOT NULL DEFAULT 0,
    first_sent_at INTEGER,
    last_sent_at  INTEGER,
    source        TEXT NOT NULL DEFAULT 'sent',     -- 'sent' | 'manual'
    status        TEXT NOT NULL DEFAULT 'active',   -- 'active' | 'removed' | 'demoted'
    status_at     INTEGER,
    status_by     TEXT,
    PRIMARY KEY (account, h)
);
CREATE INDEX IF NOT EXISTS idx_known_contacts_domain ON known_contacts(account, domain);
CREATE INDEX IF NOT EXISTS idx_known_contacts_h ON known_contacts(h);

-- Per folder sync bookmark. folder '*' = the account summary row
-- (complete = first sync done, grp = contact group, messages = sent mails).
CREATE TABLE IF NOT EXISTS contacts_sync (
    account     TEXT NOT NULL,
    folder      TEXT NOT NULL,
    kind        TEXT,                      -- 'sent' | 'history' | 'account'
    uidvalidity INTEGER,
    max_uid     INTEGER NOT NULL DEFAULT 0,
    target_uid  INTEGER,                   -- history: snapshot end (NULL = to the end)
    total       INTEGER,                   -- EXISTS at the first EXAMINE (progress)
    messages    INTEGER NOT NULL DEFAULT 0,
    synced_at   INTEGER,
    complete    INTEGER NOT NULL DEFAULT 0,
    grp         TEXT,
    PRIMARY KEY (account, folder)
);

-- From identities used in Sent (B23 uses them too). Own addresses only.
CREATE TABLE IF NOT EXISTS own_identities (
    account      TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    addr         TEXT NOT NULL,
    n            INTEGER NOT NULL DEFAULT 0,
    last_at      INTEGER,
    PRIMARY KEY (account, addr, display_name)
);

-- B11: hashed Message-IDs of sent mail + hashed recipient reg. domains.
CREATE TABLE IF NOT EXISTS sent_threads (
    account   TEXT NOT NULL,
    mid_h     TEXT NOT NULL,
    sent_at   INTEGER,
    rcpt_doms TEXT,                        -- JSON [hash], max 20
    PRIMARY KEY (account, mid_h)
);

-- B12: every sender seen (bootstrap + every scan).
CREATE TABLE IF NOT EXISTS sender_history (
    account    TEXT NOT NULL,
    h          TEXT NOT NULL,
    regdom     TEXT,
    first_seen INTEGER,
    last_seen  INTEGER,
    n_kept     INTEGER NOT NULL DEFAULT 0,
    n_seen     INTEGER NOT NULL DEFAULT 0,
    n_junk     INTEGER NOT NULL DEFAULT 0,
    fp         TEXT,                       -- JSON {"env":[..], "dkim":[..], "asn":[..]} max 5 each
    PRIMARY KEY (account, h)
);
CREATE INDEX IF NOT EXISTS idx_sender_history_regdom ON sender_history(account, regdom);

-- Message-IDs already counted into sender_history (bootstrap / scans).
CREATE TABLE IF NOT EXISTS contacts_seen (
    account TEXT NOT NULL,
    mid_h   TEXT NOT NULL,
    PRIMARY KEY (account, mid_h)
);

-- B11 freshness: pending moves whose references matched nothing yet;
-- execute_due_moves re-checks them within the grace period.
CREATE TABLE IF NOT EXISTS contact_recheck (
    account    TEXT NOT NULL,
    message_id TEXT NOT NULL,
    refs       TEXT NOT NULL,              -- JSON [mid hash]
    data       TEXT NOT NULL,              -- JSON (see _recheck_data)
    created_at INTEGER NOT NULL,
    PRIMARY KEY (account, message_id)
);
"""

_WIPE_TABLES = ("known_contacts", "contacts_sync", "own_identities", "sent_threads",
                "sender_history", "contacts_seen", "contact_recheck")


def _mono() -> float:
    """Monotonic clock for the slice budget (a hook for tests)."""
    return time.monotonic()


def _statements(script: str) -> list[str]:
    out = []
    for part in script.split(";"):
        body = "\n".join(line for line in part.splitlines() if not line.strip().startswith("--")).strip()
        if body:
            out.append(body)
    return out


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the contact tables (idempotent, additive). Statement by
    statement (never executescript: that would COMMIT a caller's open
    transaction)."""
    for stmt in _statements(SCHEMA):
        conn.execute(stmt)


# ---------------------------------------------------------------------------
# Key + hashing
# ---------------------------------------------------------------------------

_KEY_LOCK = threading.Lock()
_KEY_CACHE: dict[str, bytes] = {}
_KEY_CHECKED: set[tuple[str, str]] = set()


def key_path(state_dir: Any) -> Path:
    return Path(str(state_dir)) / KEY_FILE


def key_id(key: bytes) -> str:
    """Id of the hashing key. The label comes from the local site config
    (a migrated install keeps its old label, so its id - and the stored
    contact hashes - stay valid)."""
    return hashlib.sha256(siteconfig.contacts_key_label() + key).hexdigest()[:16]


def _write_key(path: Path, key: bytes) -> bool:
    """O_EXCL + 0600; False when another thread/process won the race."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    try:
        os.write(fd, key)
        os.fsync(fd)
    finally:
        os.close(fd)
    return True


def _kv_get(conn: sqlite3.Connection, key: str) -> str | None:
    try:
        row = conn.execute("SELECT value FROM engine_state WHERE key=?", (key,)).fetchone()
    except sqlite3.Error:
        return None
    return None if row is None else row[0]


def _kv_set(conn: sqlite3.Connection, key: str, value: str | None) -> None:
    conn.execute(
        "INSERT INTO engine_state(key, value, updated_at) VALUES(?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, value, int(time.time())))


def wipe(conn: sqlite3.Connection) -> None:
    """Forget every hashed contact row (key lost/replaced -> full resync)."""
    ensure_schema(conn)
    for table in _WIPE_TABLES:
        conn.execute(f"DELETE FROM {table}")


def load_key(state_dir: Any, conn: sqlite3.Connection | None = None, *,
             create: bool = True) -> bytes | None:
    """The 32-byte HMAC key. create=True (engine): generate it on first
    use; when a DB connection is given, the key's id is compared with the
    one the stored hashes were made with - a different (regenerated) key
    wipes every contact table so the first sync runs again.
    create=False (services/UI): None when there is no usable key.
    An unreadable key file (permissions, I/O) never triggers a wipe."""
    path = key_path(state_dir)
    with _KEY_LOCK:
        key = _KEY_CACHE.get(str(path))
        if key is not None and not path.exists() and create:
            # Deleted while running: write the key we use back (0600).
            _write_key(path, key)
        if key is None:
            try:
                data = path.read_bytes()
            except FileNotFoundError:
                data = None
            except OSError as ex:
                log.error("contacts key unreadable: %s", type(ex).__name__)
                return None
            if data is not None and len(data) != KEY_BYTES:
                if not create:
                    return None
                log.error("contacts key has the wrong size; generating a new one (full resync)")
                try:
                    path.unlink()
                except OSError:
                    return None
                data = None
            if data is None:
                if not create:
                    return None
                new = os.urandom(KEY_BYTES)
                if not _write_key(path, new):
                    try:
                        new = path.read_bytes()
                    except OSError:
                        return None
                    if len(new) != KEY_BYTES:
                        return None
                else:
                    log.info("created %s (0600)", path)
                data = new
            key = data
            _KEY_CACHE[str(path)] = key
        if conn is not None and create:
            kid = key_id(key)
            marker = (str(path), kid)
            if marker not in _KEY_CHECKED:
                ensure_schema(conn)
                stored = _kv_get(conn, KEY_STATE)
                if stored is not None and stored != kid and siteconfig.status() != "ok":
                    # The local site config is missing/unreadable: the id
                    # label may simply be unknown. Never wipe the contacts
                    # for that - the WebUI warns, nothing is lost.
                    log.warning("contacts key id not checked: local site config %s", siteconfig.status())
                    _KEY_CHECKED.add(marker)
                elif stored != kid:
                    began = not conn.in_transaction
                    if began:
                        conn.execute("BEGIN IMMEDIATE")
                    try:
                        if stored is not None:
                            wipe(conn)
                            conn.execute(
                                "INSERT INTO events(account, ts, message_id, event, detail) "
                                "VALUES('*', ?, NULL, 'contacts_key_regenerated', ?)",
                                (int(time.time()), "ny nøgle – kendte kontakter synkroniseres igen"))
                            log.warning("contacts key changed: contact tables wiped, full resync")
                        _kv_set(conn, KEY_STATE, kid)
                        if began:
                            conn.execute("COMMIT")
                    except BaseException:
                        if began:
                            conn.execute("ROLLBACK")
                        raise
                _KEY_CHECKED.add(marker)
        return key


def forget_cached_keys() -> None:
    """Tests: drop the in-process key cache (simulates a restart)."""
    with _KEY_LOCK:
        _KEY_CACHE.clear()
        _KEY_CHECKED.clear()


def _h(key: bytes, text: str) -> str:
    return hmac.new(key, text.encode("utf-8"), hashlib.sha256).hexdigest()[:HASH_HEX]


def hash_address(key: bytes, address: Any) -> str | None:
    """h of a normalised address (None when it is not an address)."""
    norm = normalize_address(address)
    return _h(key, norm) if norm else None


def hash_mid(key: bytes, message_id: Any) -> str | None:
    mid = normalize_mid(message_id)
    return _h(key, "m:" + mid) if mid else None


def hash_domain(key: bytes, domain: Any) -> str | None:
    d = normalize_domain(domain)
    return _h(key, "d:" + d) if d else None


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------


def normalize_domain(domain: Any) -> str | None:
    d = str(domain or "").strip().strip(".").lower()
    if not d:
        return None
    if not d.isascii():
        try:
            d = d.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    return d if _DOMAIN_RE.match(d) else None


def normalize_address(addr: Any) -> str | None:
    """lower-case, IDNA (punycode) domain, +tags kept. None if invalid."""
    s = str(addr or "").strip()
    if s.startswith("<") and s.endswith(">"):
        s = s[1:-1].strip()
    if not s or "@" not in s or len(s) > 254 or any(c.isspace() for c in s) or "<" in s or ">" in s:
        return None
    local, _sep, dom = s.rpartition("@")
    local = local.strip().lower()
    if not local or len(local) > 64 or '"' in local or "\\" in local:
        return None
    d = normalize_domain(dom)
    if d is None:
        return None
    return f"{local}@{d}"


def normalize_mid(value: Any) -> str | None:
    """Same rule as filter.normalize_message_id: the text inside <...>."""
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    m = re.search(r"<([^>]+)>", s)
    if m:
        s = m.group(1)
    s = s.strip()
    return s[:500] or None


def domain_of(addr: Any) -> str | None:
    norm = normalize_address(addr)
    return norm.rpartition("@")[2] if norm else None


def regdom(domain: Any) -> str | None:
    """Registered domain (simple public-suffix rule: a.b.example.co.uk ->
    example.co.uk, mail.example.dk -> example.dk)."""
    d = normalize_domain(domain)
    if d is None:
        return None
    labels = d.split(".")
    if len(labels) <= 2:
        return d
    if ".".join(labels[-2:]) in _MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _display_domain(d: str) -> str:
    try:
        return d.encode("ascii").decode("idna") if "xn--" in d else d
    except UnicodeError:
        return d


def mask(addr: Any) -> str:
    """'j…@example.dk' - safe for logs, events and the UI."""
    norm = normalize_address(addr)
    if not norm:
        return "…"
    local, _s, dom = norm.rpartition("@")
    return f"{local[:1]}…@{_display_domain(dom)}"


def under(host: str | None, domain: str | None) -> bool:
    h = (host or "").strip().lower().rstrip(".")
    d = (domain or "").strip().lower().rstrip(".")
    return bool(h) and bool(d) and (h == d or h.endswith("." + d))


def is_freemail(domain: Any) -> bool:
    d = normalize_domain(domain) or ""
    return d in FREEMAIL_DOMAINS or d.split(".")[0] in ("hotmail", "outlook", "live", "yahoo", "gmx")


def skip_recipient(addr: str) -> bool:
    """noreply/bounce/unsubscribe addresses and list-manager domains are
    never contacts."""
    norm = normalize_address(addr)
    if not norm:
        return True
    local, _s, dom = norm.rpartition("@")
    if _NOREPLY_LOCAL_RE.search(local):
        return True
    return any(under(dom, d) for d in _LIST_DOMAINS)


def trust_blocked(names: Iterable[str], threat: str | None = None, *,
                  distrust: Iterable[str] = ()) -> str | None:
    """The hard exception that forbids any trust bonus, or None. One
    helper so the threat class (B16) only has to pass `threat`. `distrust`
    = the engine's ALLOW_DISTRUST_SYMBOLS (forged-From evidence)."""
    if threat:
        return f"threat:{threat}"
    dis = frozenset(distrust)
    nameset = sorted(str(x) for x in names)
    heuristic = "TH_CLAM_HEURISTIC" in nameset
    for n in nameset:
        if n in HARD_EXCEPTION_INFO:
            continue
        if n.startswith("CLAM_") and n.endswith("_FAIL"):
            continue
        if heuristic and n == "CLAM_VIRUS":
            continue  # 2.7 fix: a heuristic / third-party ClamAV hit only (no threat): contacts stay protected
        if n in HARD_EXCEPTION_EXACT or n.startswith(HARD_EXCEPTION_PREFIXES) or n in dis:
            return n
    return None


def _ts_month(ts: Any) -> str:
    try:
        return datetime.fromtimestamp(int(ts), timezone.utc).strftime("%Y-%m")
    except (TypeError, ValueError, OverflowError, OSError):
        return "?"


def _ts_day(ts: Any) -> str:
    try:
        return datetime.fromtimestamp(int(ts), timezone.utc).strftime("%Y-%m-%d")
    except (TypeError, ValueError, OverflowError, OSError):
        return "?"


def _ts_year(ts: Any) -> str:
    try:
        return datetime.fromtimestamp(int(ts), timezone.utc).strftime("%Y")
    except (TypeError, ValueError, OverflowError, OSError):
        return "?"


def _date_ts(value: Any) -> int | None:
    if not value:
        return None
    try:
        d = parsedate_to_datetime(str(value))
    except (TypeError, ValueError, IndexError):
        return None
    if d is None:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    try:
        return int(d.timestamp())
    except (OverflowError, OSError, ValueError):
        return None


def _idate(data: dict) -> int | None:
    v = (data or {}).get(b"INTERNALDATE")
    if v is None:
        return None
    try:
        return int(v.timestamp())
    except (AttributeError, OverflowError, OSError, ValueError):
        return None


def _hdr_block(data: dict) -> bytes:
    for k, v in (data or {}).items():
        if isinstance(k, bytes) and k.upper().startswith(b"BODY[HEADER") and isinstance(v, (bytes, bytearray)):
            return bytes(v)
    return b""


def _parse(raw: bytes) -> email.message.Message:
    head = (raw or b"").split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0]
    return email.message_from_bytes(head + b"\r\n\r\n", policy=email.policy.compat32)


def _decode(value: Any) -> str:
    s = str(value or "")
    if "=?" in s:
        try:
            s = str(email.header.make_header(email.header.decode_header(s)))
        except Exception:  # noqa: BLE001 - keep the raw text
            pass
    return re.sub(r"[\r\n\t]+", " ", s).strip()


def _addresses(msg: email.message.Message, *names: str) -> list[tuple[str, str]]:
    vals: list[str] = []
    for n in names:
        vals.extend(str(v) for v in (msg.get_all(n) or []))
    try:
        return [(_decode(nm), a) for nm, a in getaddresses(vals) if a]
    except Exception:  # noqa: BLE001
        return []


def message_refs(msg: email.message.Message) -> list[str]:
    """In-Reply-To plus the last MAX_REFS References (normalised)."""
    out: list[str] = []
    irt = msg.get("In-Reply-To")
    if irt:
        for m in _MSGID_RE.findall(str(irt))[:1] or [normalize_mid(irt) or ""]:
            if m and m not in out:
                out.append(m)
    refs = _MSGID_RE.findall(str(msg.get("References") or ""))
    for m in refs[-MAX_REFS:]:
        if m not in out:
            out.append(m)
    return out[: MAX_REFS + 1]


def _fp_load(value: Any) -> dict[str, list[str]]:
    try:
        d = json.loads(value) if value else {}
    except (TypeError, ValueError):
        d = {}
    if not isinstance(d, dict):
        d = {}
    return {k: [str(x) for x in (d.get(k) or [])][:FP_MAX] for k in ("env", "dkim", "asn")}


def _fp_merge(fp: dict[str, list[str]], *, env: Iterable[str] = (), dkim: Iterable[str] = (),
              asn: Iterable[str] = ()) -> dict[str, list[str]]:
    for k, vals in (("env", env), ("dkim", dkim), ("asn", asn)):
        cur = fp.setdefault(k, [])
        for v in vals:
            v = str(v or "").strip().lower()[:100]
            if not v:
                continue
            if v in cur:
                cur.remove(v)
            cur.append(v)  # most recent last
        fp[k] = cur[-FP_MAX:]
    return fp


def asn_of(options: Iterable[Any]) -> str | None:
    """rspamd's ASN symbol options: 'asn:3301', 'ipnet:..', 'country:SE'."""
    for o in options or ():
        s = str(o).strip().lower()
        if s.startswith("asn:"):
            v = s[4:].strip()
            if v.isdigit():
                return v
    return None


# ---------------------------------------------------------------------------
# Account helpers
# ---------------------------------------------------------------------------


def enabled(acc: Any) -> bool:
    return bool(getattr(acc, "known_contacts", False))


def contact_group(acc: Any) -> str:
    grp = str(getattr(acc, "contact_group", None) or "").strip().lower()
    if grp:
        return grp
    return str(getattr(acc, "user", "") or "").rpartition("@")[2].strip().lower()


def _summary(conn: sqlite3.Connection, account: str) -> sqlite3.Row | None:
    try:
        cur = conn.cursor()
        cur.row_factory = sqlite3.Row
        return cur.execute("SELECT * FROM contacts_sync WHERE account=? AND folder='*'",
                           (account,)).fetchone()
    except sqlite3.Error:
        return None


def sync_complete(conn: sqlite3.Connection, account: str) -> bool:
    row = _summary(conn, account)
    return bool(row is not None and row["complete"])


def own_identity_addrs(conn: sqlite3.Connection, account: str) -> set[str]:
    try:
        rows = conn.execute("SELECT addr, SUM(n) FROM own_identities WHERE account=? GROUP BY addr "
                            "HAVING SUM(n) >= ?", (account, IDENTITY_MIN)).fetchall()
    except sqlite3.Error:
        return set()
    return {str(r[0]) for r in rows}


def own_domains(conn: sqlite3.Connection | None, acc: Any, extra: Iterable[str] = ()) -> set[str]:
    """The mailbox domain, its contact group, the owner's platform/webshop
    domains and the domains of From identities used >= 3 times."""
    out: set[str] = set()
    user_dom = normalize_domain(str(getattr(acc, "user", "") or "").rpartition("@")[2])
    if user_dom:
        out.add(user_dom)
    grp = normalize_domain(contact_group(acc))
    if grp:
        out.add(grp)
    for d in extra:
        nd = normalize_domain(d)
        if nd:
            out.add(nd)
    if conn is not None:
        for a in own_identity_addrs(conn, acc.name):
            d = domain_of(a)
            if d:
                out.add(d)
    return out


def _is_own(domain: str | None, owns: set[str]) -> bool:
    return bool(domain) and any(under(domain, d) or under(regdom(domain) or "", d) for d in owns)


# ---------------------------------------------------------------------------
# Sync (account thread)
# ---------------------------------------------------------------------------


@dataclass
class SyncPlan:
    sent: list[str] = field(default_factory=list)
    history: list[str] = field(default_factory=list)


def _flag_names(flags: Iterable[Any]) -> set[str]:
    return {(f.decode() if isinstance(f, (bytes, bytearray)) else str(f)) for f in flags or ()}


def _listing(client: Any, state: Any) -> list[tuple[list[str], str, str]]:
    """[(flags, name, delimiter)] from the cached LIST (filter._on_connected)
    or a fresh LIST."""
    cached = getattr(state, "folder_listing", None)
    if cached:
        delim = getattr(state, "folder_delimiter", "") or "/"
        return [(list(f), str(n), delim) for f, n in cached]
    out = []
    for flags, d, name in client.list_folders():
        dd = d.decode() if isinstance(d, (bytes, bytearray)) else str(d or "/")
        nn = name.decode() if isinstance(name, (bytes, bytearray)) else str(name)
        out.append((sorted(_flag_names(flags)), nn, dd))
    return out


def plan_folders(client: Any, acc: Any, fmap: dict[str, str], state: Any) -> SyncPlan:
    listing = _listing(client, state)
    selectable = [(set(f.upper() for f in flags), name, d) for flags, name, d in listing
                  if not ({f.upper() for f in flags} & {"\\NOSELECT", "\\NONEXISTENT"})]
    by_lower = {name.lower(): name for _f, name, _d in selectable}
    sent: list[str] = []
    configured = list(getattr(acc, "sent_folders", None) or [])
    if configured:
        delim = selectable[0][2] if selectable else "/"
        for c in configured:
            cand = c if delim == "/" or "/" not in c else c.replace("/", delim)
            hit = by_lower.get(cand.lower())
            if hit and hit not in sent:
                sent.append(hit)
    else:
        for flags, name, _d in selectable:
            if "\\SENT" in flags and name not in sent:
                sent.append(name)
        for flags, name, d in selectable:
            low = name.lower()
            for cand in SENT_NAMES:
                if low in (cand.lower(), f"inbox{d}{cand}".lower()) and name not in sent:
                    sent.append(name)
    excluded = {v for k, v in fmap.items() if v and k != "inbox"} | set(sent)
    inbox = fmap.get("inbox") or "INBOX"
    history: list[str] = []
    for flags, name, d in selectable:
        if name.upper() == inbox.upper():
            if name not in history:
                history.insert(0, name)
            continue
        if name in excluded or flags & _SKIP_SPECIAL:
            continue
        rel = name[len("INBOX") + len(d):] if name.upper().startswith("INBOX" + d.upper()) else name
        if _SKIP_NAME_RE.search(rel):
            continue
        history.append(name)
    if not any(h.upper() == inbox.upper() for h in history):
        history.insert(0, inbox)
    return SyncPlan(sent=sent, history=history[:MAX_HISTORY_FOLDERS])


def _rows(conn: sqlite3.Connection, account: str) -> dict[str, sqlite3.Row]:
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    return {r["folder"]: r for r in cur.execute(
        "SELECT * FROM contacts_sync WHERE account=?", (account,)).fetchall()}


def _upsert_summary(conn: sqlite3.Connection, account: str, **fields: Any) -> None:
    conn.execute("INSERT OR IGNORE INTO contacts_sync(account, folder, kind, max_uid, messages, complete) "
                 "VALUES(?, '*', 'account', 0, 0, 0)", (account,))
    if fields:
        cols = ", ".join(f"{k}=?" for k in fields)
        conn.execute(f"UPDATE contacts_sync SET {cols} WHERE account=? AND folder='*'",
                     (*fields.values(), account))


@dataclass
class _Ctx:
    """Everything one sync slice needs."""
    client: Any
    db: Any
    acc: Any
    key: bytes
    now: int
    own_addrs: set[str]
    is_spam_mid: Any


def _is_spam_mid_fn(db: Any) -> Any:
    def check(mid: str) -> bool:
        try:
            row = db.conn.execute(
                "SELECT 1 FROM messages WHERE account=? AND message_id=? AND (user_verdict='spam' "
                "OR our_action IN ('moved_to_junk','provider_junk','user_junked','manual_mark_spam',"
                "'pending_move','shadow_spam','flagged')) LIMIT 1", (db.account, mid)).fetchone()
        except sqlite3.Error:
            return False
        return row is not None
    return check


def _count_contact(conn: sqlite3.Connection, account: str, key: bytes, norm: str, ts: int) -> None:
    h = _h(key, norm)
    dom = norm.rpartition("@")[2]
    conn.execute(
        """
        INSERT INTO known_contacts(account, h, domain, mask, sent_count, first_sent_at, last_sent_at,
                                   source, status)
        VALUES(?,?,?,?,1,?,?,'sent','active')
        ON CONFLICT(account, h) DO UPDATE SET
            sent_count = known_contacts.sent_count + 1,
            domain = COALESCE(known_contacts.domain, excluded.domain),
            mask = COALESCE(known_contacts.mask, excluded.mask),
            first_sent_at = MIN(COALESCE(known_contacts.first_sent_at, excluded.first_sent_at),
                                excluded.first_sent_at),
            last_sent_at = MAX(COALESCE(known_contacts.last_sent_at, excluded.last_sent_at),
                               excluded.last_sent_at)
        """, (account, h, dom, mask(norm), ts, ts))


def _process_sent(c: _Ctx, data: dict) -> bool:
    """One sent mail. True = counted (False = duplicate)."""
    conn, account = c.db.conn, c.db.account
    msg = _parse(_hdr_block(data))
    mid = normalize_mid(msg.get("Message-ID"))
    mid_h = _h(c.key, "m:" + mid) if mid else None
    if mid_h and conn.execute("SELECT 1 FROM sent_threads WHERE account=? AND mid_h=?",
                              (account, mid_h)).fetchone():
        return False  # the same sent mail in a second Sent folder / after a resync
    ts = _date_ts(msg.get("Date")) or _idate(data) or c.now
    froms = []
    for name, addr in _addresses(msg, "From"):
        norm = normalize_address(addr)
        if norm:
            froms.append(norm)
            conn.execute(
                "INSERT INTO own_identities(account, display_name, addr, n, last_at) VALUES(?,?,?,1,?) "
                "ON CONFLICT(account, addr, display_name) DO UPDATE SET n=own_identities.n+1, "
                "last_at=MAX(COALESCE(own_identities.last_at, 0), excluded.last_at)",
                (account, name[:100], norm[:254], ts))
    irt = normalize_mid(msg.get("In-Reply-To"))
    spam_reply = bool(irt) and c.is_spam_mid(irt)
    own = c.own_addrs | set(froms)
    rcpt_doms: list[str] = []
    for _name, addr in _addresses(msg, "To", "Cc", "Bcc"):
        norm = normalize_address(addr)
        if not norm or norm in own or spam_reply:
            continue
        rd = regdom(norm.rpartition("@")[2])
        if rd:
            dh = _h(c.key, "d:" + rd)
            if dh not in rcpt_doms:
                rcpt_doms.append(dh)
        if skip_recipient(norm):
            continue
        _count_contact(conn, account, c.key, norm, ts)
    if mid_h and not spam_reply:
        conn.execute("INSERT OR IGNORE INTO sent_threads(account, mid_h, sent_at, rcpt_doms) VALUES(?,?,?,?)",
                     (account, mid_h, ts, json.dumps(rcpt_doms[:MAX_RCPT_DOMS])))
    return True


def _record_history(conn: sqlite3.Connection, account: str, key: bytes, norm: str, ts: int, *,
                    kept: int, junk: int, env: Iterable[str] = (), dkim: Iterable[str] = (),
                    asn: Iterable[str] = (), add_fp: bool = True) -> None:
    h = _h(key, norm)
    rd = regdom(norm.rpartition("@")[2])
    row = conn.execute("SELECT fp FROM sender_history WHERE account=? AND h=?", (account, h)).fetchone()
    fp = _fp_load(row[0] if row else None)
    if add_fp:
        fp = _fp_merge(fp, env=env, dkim=dkim, asn=asn)
    fp_json = json.dumps(fp, separators=(",", ":"))
    conn.execute(
        """
        INSERT INTO sender_history(account, h, regdom, first_seen, last_seen, n_kept, n_seen, n_junk, fp)
        VALUES(?,?,?,?,?,?,1,?,?)
        ON CONFLICT(account, h) DO UPDATE SET
            regdom = COALESCE(sender_history.regdom, excluded.regdom),
            first_seen = MIN(COALESCE(sender_history.first_seen, excluded.first_seen), excluded.first_seen),
            last_seen = MAX(COALESCE(sender_history.last_seen, excluded.last_seen), excluded.last_seen),
            n_kept = sender_history.n_kept + excluded.n_kept,
            n_seen = sender_history.n_seen + 1,
            n_junk = sender_history.n_junk + excluded.n_junk,
            fp = excluded.fp
        """, (account, h, rd, ts, ts, int(kept), int(junk), fp_json))


def _seen_once(conn: sqlite3.Connection, account: str, key: bytes, mid: str | None) -> bool:
    """True the first time a Message-ID is counted into sender_history."""
    if not mid:
        return True
    cur = conn.execute("INSERT OR IGNORE INTO contacts_seen(account, mid_h) VALUES(?,?)",
                       (account, _h(key, "m:" + mid)))
    return cur.rowcount > 0


def _process_history(c: _Ctx, data: dict) -> bool:
    flags = _flag_names(data.get(b"FLAGS"))
    if "\\Deleted" in flags or "$Junk" in flags:
        return False
    msg = _parse(_hdr_block(data))
    froms = _addresses(msg, "From")
    if len(froms) != 1:
        return False
    norm = normalize_address(froms[0][1])
    if not norm:
        return False
    conn, account = c.db.conn, c.db.account
    if not _seen_once(conn, account, c.key, normalize_mid(msg.get("Message-ID"))):
        return False
    ts = _idate(data) or _date_ts(msg.get("Date")) or c.now
    env = []
    rp = _addresses(msg, "Return-Path")
    if rp:
        rd = regdom(domain_of(rp[0][1]))
        if rd:
            env.append(rd)
    dkim = []
    for sig in msg.get_all("DKIM-Signature") or []:
        m = _DKIM_D_RE.search(re.sub(r"\s+", " ", str(sig)))
        if m:
            d = normalize_domain(m.group(1))
            if d:
                dkim.append(d)
    _record_history(conn, account, c.key, norm, ts, kept=1, junk=0, env=env, dkim=dkim)
    return True


def _sync_folder(c: _Ctx, folder: str, kind: str, row: sqlite3.Row | None, deadline: float, *,
                 inbox: str, log_: logging.Logger) -> str:
    """Advance one folder by chunks until done or the deadline.
    Returns 'done' | 'more' | 'missing'."""
    client, db = c.client, c.db
    try:
        info = client.select_folder(folder, readonly=True)
    except Exception as ex:  # noqa: BLE001 - IMAP error on one folder
        if _is_conn_error(ex):
            raise
        log_.info("contacts: folder %s not selectable (%s)", folder, type(ex).__name__)
        return "missing"
    uv = int(info.get(b"UIDVALIDITY") or 0)
    exists = info.get(b"EXISTS")
    uidnext = info.get(b"UIDNEXT")
    max_uid = int(row["max_uid"]) if row is not None else 0
    target = row["target_uid"] if row is not None else None
    if row is None or row["uidvalidity"] != uv:
        if row is not None:
            log_.warning("contacts: UIDVALIDITY of %s changed, syncing that folder again", folder)
            with db.tx():
                db.log_event("contacts_uidvalidity", detail=f"{folder} {row['uidvalidity']}->{uv}")
        max_uid = 0
        target = None
        if kind == "history":
            if folder.upper() == inbox.upper():
                bm = db.conn.execute(
                    "SELECT max_uid FROM scan_bookmark WHERE account=? AND folder=? AND uidvalidity=?",
                    (db.account, folder, uv)).fetchone()
                target = int(bm[0]) if bm else None
            if target is None:
                try:
                    target = int(uidnext) - 1 if uidnext is not None else None
                except (TypeError, ValueError):
                    target = None
                if target is None:
                    found = client.search(["ALL"])
                    target = max(int(u) for u in found) if found else 0
        with db.tx():
            db.conn.execute(
                "INSERT INTO contacts_sync(account, folder, kind, uidvalidity, max_uid, target_uid, total, "
                "messages, synced_at, complete) VALUES(?,?,?,?,0,?,?,0,?,0) "
                "ON CONFLICT(account, folder) DO UPDATE SET kind=excluded.kind, uidvalidity=excluded.uidvalidity, "
                "max_uid=0, target_uid=excluded.target_uid, total=excluded.total, messages=0, "
                "synced_at=excluded.synced_at, complete=0",
                (db.account, folder, kind, uv, target, int(exists) if exists is not None else None, c.now))
    items = SENT_ITEMS if kind == "sent" else HISTORY_ITEMS
    first = True
    while True:
        if not first and _mono() >= deadline:
            return "more"
        first = False
        found = client.search(["UID", f"{max_uid + 1}:*"])
        uids = sorted(u for u in {int(x) for x in found}
                      if u > max_uid and (target is None or u <= int(target)))
        if not uids:
            with db.tx():
                db.conn.execute("UPDATE contacts_sync SET complete=1, synced_at=? WHERE account=? AND folder=?",
                                (c.now, db.account, folder))
            return "done"
        chunk = uids[:FETCH_CHUNK]
        fetched = client.fetch(chunk, items)
        n = 0
        with db.tx():
            for uid in chunk:
                data = fetched.get(uid)
                if data is None:
                    continue
                try:
                    ok = _process_sent(c, data) if kind == "sent" else _process_history(c, data)
                except Exception as ex:  # noqa: BLE001 - one bad header never stalls the sync
                    log_.debug("contacts: header of uid %s skipped: %s", uid, type(ex).__name__)
                    ok = False
                n += 1 if ok else 0
            max_uid = chunk[-1]
            done = len(uids) <= len(chunk)
            db.conn.execute(
                "UPDATE contacts_sync SET max_uid=?, messages=messages+?, synced_at=?, complete=? "
                "WHERE account=? AND folder=?", (max_uid, n, c.now, 1 if done else 0, db.account, folder))
            if kind == "sent" and n:
                _upsert_summary(db.conn, db.account)
                db.conn.execute("UPDATE contacts_sync SET messages=messages+? WHERE account=? AND folder='*'",
                                (n, db.account))
        if done:
            return "done"


def _is_conn_error(ex: BaseException) -> bool:
    """A dropped connection (re-raised: the account loop reconnects)."""
    return isinstance(ex, (OSError, IMAPClientAbortError))


def purge_own(conn: sqlite3.Connection, acc: Any, key: bytes) -> int:
    """Delete contacts that are the user's own addresses (account user
    and From identities used >= 3 times in Sent)."""
    addrs = own_identity_addrs(conn, acc.name)
    user = normalize_address(getattr(acc, "user", ""))
    if user:
        addrs.add(user)
    hs = [_h(key, a) for a in addrs]
    n = 0
    for i in range(0, len(hs), 400):
        part = hs[i:i + 400]
        n += conn.execute(f"DELETE FROM known_contacts WHERE account=? AND source='sent' "
                          f"AND h IN ({','.join('?' * len(part))})", (acc.name, *part)).rowcount
    return n


def _ctx(client: Any, db: Any, acc: Any, key: bytes, now: int) -> _Ctx:
    own = own_identity_addrs(db.conn, acc.name)
    user = normalize_address(getattr(acc, "user", ""))
    if user:
        own.add(user)
    return _Ctx(client=client, db=db, acc=acc, key=key, now=now, own_addrs=own,
                is_spam_mid=_is_spam_mid_fn(db))


def _request_token(conn: sqlite3.Connection, account: str) -> str | None:
    return _kv_get(conn, REQUEST_STATE + account)


def sync_step(client: Any, db: Any, log_: logging.Logger, acc: Any, fmap: dict[str, str], state: Any, *,
              key: bytes | None, now: int, budget_s: float = SLICE_BUDGET_S) -> bool:
    """One slice of contact sync work (<= budget_s, at least one chunk).
    Returns True when more initial work is pending (the caller keeps the
    IDLE wait short). Read-only on IMAP."""
    if not enabled(acc) or key is None:
        return False
    deadline = _mono() + max(0.0, float(budget_s))
    conn, account = db.conn, db.account
    rows = _rows(conn, account)
    grp = contact_group(acc)
    if rows.get("*") is None or rows["*"]["grp"] != grp:
        with db.tx():
            _upsert_summary(conn, account, grp=grp)
        rows = _rows(conn, account)
    plan = getattr(state, "contacts_plan", None)
    if plan is None:
        plan = plan_folders(client, acc, fmap, state)
        state.contacts_plan = plan
    summary = rows.get("*")
    c = _ctx(client, db, acc, key, now)
    inbox = fmap.get("inbox") or "INBOX"
    # Initial pass: Sent folders first (contacts + threads), then history.
    pending = [(f, "sent") for f in plan.sent if not (rows.get(f) and rows[f]["complete"])]
    if not (summary is not None and summary["complete"]):
        pending += [(f, "history") for f in plan.history if not (rows.get(f) and rows[f]["complete"])]
    for folder, kind in pending:
        res = _sync_folder(c, folder, kind, rows.get(folder), deadline, inbox=inbox, log_=log_)
        if res == "more":
            state.contacts_busy = True
            return True
        if res == "missing":
            with db.tx():
                db.conn.execute(
                    "INSERT INTO contacts_sync(account, folder, kind, max_uid, messages, synced_at, complete) "
                    "VALUES(?,?,?,0,0,?,1) ON CONFLICT(account, folder) DO UPDATE SET complete=1, synced_at=?",
                    (account, folder, kind, now, now))
        if _mono() >= deadline:
            state.contacts_busy = True
            return True
    newly_complete = not (summary is not None and summary["complete"])
    if newly_complete or pending:
        with db.tx():
            purged = purge_own(conn, acc, key)
            _upsert_summary(conn, account, complete=1, synced_at=now)
            if newly_complete:
                counts = conn.execute(
                    "SELECT (SELECT COUNT(*) FROM known_contacts WHERE account=?),"
                    " (SELECT COUNT(*) FROM sent_threads WHERE account=?),"
                    " (SELECT COUNT(*) FROM sender_history WHERE account=?)",
                    (account, account, account)).fetchone()
                db.log_event("contacts_sync_complete",
                             detail=f"kontakter={counts[0]} sendte={counts[1]} afsendere={counts[2]}"
                                    + (f" egne={purged}" if purged else ""))
        if newly_complete:
            log_.info("contacts: first sync complete")
        state.contacts_next_status = _mono() + STATUS_INTERVAL_S
    state.contacts_busy = False
    # Incremental: STATUS UIDNEXT of the Sent folders every 15 min or on
    # request ('Opdater nu').
    token = _request_token(conn, account)
    requested = token is not None and token != getattr(state, "contacts_request_seen", None)
    if requested or _mono() >= float(getattr(state, "contacts_next_status", 0.0) or 0.0):
        state.contacts_request_seen = token
        incremental_sent(client, db, log_, acc, state, key=key, now=now, deadline=deadline + budget_s)
        state.contacts_next_status = _mono() + STATUS_INTERVAL_S
        with db.tx():
            _upsert_summary(conn, account, synced_at=now)
    return False


def incremental_sent(client: Any, db: Any, log_: logging.Logger, acc: Any, state: Any, *,
                     key: bytes, now: int, deadline: float | None = None) -> tuple[int, bool]:
    """STATUS UIDNEXT of every Sent folder; EXAMINE + fetch only where new
    mail arrived. Returns (sent mails added, another folder was selected -
    the caller must re-select the inbox before using UIDs again)."""
    plan = getattr(state, "contacts_plan", None)
    if plan is None or not plan.sent:
        return 0, False
    selected = False
    rows = _rows(db.conn, db.account)
    c = _ctx(client, db, acc, key, now)
    added = 0
    end = deadline if deadline is not None else _mono() + SLICE_BUDGET_S
    for folder in plan.sent:
        row = rows.get(folder)
        if row is None or not row["complete"]:
            continue  # the initial pass handles it
        try:
            st = client.folder_status(folder, [b"UIDNEXT", b"UIDVALIDITY"])
        except Exception as ex:  # noqa: BLE001
            if _is_conn_error(ex):
                raise
            continue
        nxt = st.get(b"UIDNEXT", st.get("UIDNEXT"))
        uv = st.get(b"UIDVALIDITY", st.get("UIDVALIDITY"))
        try:
            nxt_i = int(nxt) if nxt is not None else None
            uv_i = int(uv) if uv is not None else None
        except (TypeError, ValueError):
            continue
        if uv_i == row["uidvalidity"] and nxt_i is not None and nxt_i - 1 <= int(row["max_uid"]):
            continue
        before = int(row["messages"] or 0)
        selected = True
        _sync_folder(c, folder, "sent", row, end, inbox="", log_=log_)
        after = db.conn.execute("SELECT messages FROM contacts_sync WHERE account=? AND folder=?",
                                (db.account, folder)).fetchone()
        added += max(0, int(after[0] or 0) - before) if after else 0
    if added:
        with db.tx():
            purge_own(db.conn, acc, key)
    state.contacts_last_fresh = _mono()
    return added, selected


def prune(conn: sqlite3.Connection, account: str, now: int) -> None:
    conn.execute("DELETE FROM sent_threads WHERE account=? AND sent_at IS NOT NULL AND sent_at < ?",
                 (account, now - THREAD_KEEP_S))
    conn.execute("DELETE FROM contact_recheck WHERE account=? AND created_at < ?",
                 (account, now - RECHECK_KEEP_S))


# ---------------------------------------------------------------------------
# Scoring (B10/B11/B12)
# ---------------------------------------------------------------------------


@dataclass
class Trust:
    symbols: list[dict] = field(default_factory=list)   # pseudo-symbols to add (scores count)
    delta: float = 0.0                                  # sum of their scores
    metrics: list[str] = field(default_factory=list)    # stats to bump
    unmatched: list[str] = field(default_factory=list)  # reference hashes that matched nothing
    recheck: dict | None = None                         # data for contact_recheck
    blocked: str | None = None
    active: bool = False


def _sym(name: str, score: float, opts: Sequence[str]) -> dict:
    return {"n": name, "s": round(float(score), 3), "o": [str(o)[:120] for o in opts][:3]}


def _auth_ok(strict: bool, aligned: bool, names: frozenset) -> bool:
    if strict:
        return aligned
    return aligned or "DMARC_POLICY_ALLOW" in names or "TH_PROVIDER_AUTH_PASS" in names


def _contact_row(conn: sqlite3.Connection, account: str, h: str) -> sqlite3.Row | None:
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    return cur.execute("SELECT * FROM known_contacts WHERE account=? AND h=?", (account, h)).fetchone()


def _group_rows(conn: sqlite3.Connection, account: str, grp: str, h: str) -> list[sqlite3.Row]:
    if not grp:
        return []
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    return cur.execute(
        "SELECT k.* FROM known_contacts k JOIN contacts_sync s ON s.account=k.account AND s.folder='*' "
        "WHERE k.h=? AND k.account<>? AND k.status='active' AND s.grp=? AND s.complete=1 "
        "ORDER BY k.last_sent_at DESC", (h, account, grp)).fetchall()


def _kc_score(row: Any, now: int, base: float) -> float:
    last = int(row["last_sent_at"] or 0)
    if int(row["sent_count"] or 0) >= 2 or now - last <= KC_RECENT_S:
        return base
    if now - last <= KC_5Y_S:
        return max(base, SCORE_KC_5Y)
    return max(base, SCORE_KC_OLD)


def _first_contact(conn: sqlite3.Connection, account: str, h: str, rd: str | None, msgid: str | None,
                   sender_norm: str) -> bool:
    if conn.execute("SELECT 1 FROM sender_history WHERE account=? AND (h=? OR regdom=?) LIMIT 1",
                    (account, h, rd or "\x00")).fetchone():
        return False
    if conn.execute("SELECT 1 FROM known_contacts WHERE account=? AND (h=? OR domain=? OR domain LIKE ?) LIMIT 1",
                    (account, h, rd or "\x00", "%." + (rd or "\x00"))).fetchone():
        return False
    dom_like = "%@" + (rd or "\x00")
    sub_like = "%." + (rd or "\x00")
    row = conn.execute(
        "SELECT 1 FROM messages WHERE account=? AND message_id<>? AND sender IS NOT NULL "
        "AND (lower(sender)=? OR lower(sender) LIKE ? OR lower(sender) LIKE ?) LIMIT 1",
        (account, msgid or "", sender_norm, dom_like, sub_like)).fetchone()
    return row is None


def evaluate(conn: sqlite3.Connection, acc: Any, key: bytes | None, *, raw: bytes,
             ctx: dict[str, Any] | None, names: Iterable[str], dkim_domains: Sequence[str],
             final: float, threshold: float, newsletter: float = 0.0, now: int,
             msgid: str | None = None, asn: str | None = None, allow_rule: bool = False,
             block_rule: bool = False, distrust: Iterable[str] = (), threat: str | None = None,
             owner_domains: Iterable[str] = ()) -> Trust:
    """Trust pseudo-symbols for one scanned message (see module doc).
    `final` = score so far (incl. TH_NEWSLETTER = `newsletter`)."""
    out = Trust()
    if key is None or not enabled(acc) or not sync_complete(conn, acc.name):
        return out
    out.active = True
    ctx = ctx or {}
    nameset = frozenset(str(n) for n in names)
    msg = _parse(raw)
    froms = _addresses(msg, "From")
    sender = normalize_address(froms[0][1]) if len(froms) == 1 else None
    out.blocked = trust_blocked(nameset, threat, distrust=distrust) or ("block_rule" if block_rule else None)
    owns = own_domains(conn, acc, owner_domains)
    from_dom = sender.rpartition("@")[2] if sender else None
    own_from = _is_own(from_dom, owns)
    strict = bool(ctx.get("forwarded")) or own_from
    dk = [normalize_domain(d) for d in dkim_domains]
    dk = [d for d in dk if d]
    aligned = bool(from_dom) and any(under(from_dom, d) or under(d, from_dom) for d in dk)
    auth_ok = bool(sender) and _auth_ok(strict, aligned, nameset)
    is_list = bool(msg.get("List-Id"))
    h = _h(key, sender) if sender else None
    rd = regdom(from_dom) if from_dom else None
    candidates: list[tuple[float, dict, str | None]] = []
    info: list[dict] = []

    # --- B11: reply to one of our own sent mails ---------------------------
    refs = message_refs(msg)
    ref_hashes = [_h(key, "m:" + r) for r in refs]
    matched: list[sqlite3.Row] = []
    if ref_hashes:
        cur = conn.cursor()
        cur.row_factory = sqlite3.Row
        matched = cur.execute(
            f"SELECT * FROM sent_threads WHERE account=? AND mid_h IN ({','.join('?' * len(ref_hashes))}) "
            f"ORDER BY sent_at DESC", (acc.name, *ref_hashes)).fetchall()
        if not matched:
            out.unmatched = ref_hashes
    contact = _contact_row(conn, acc.name, h) if h else None
    contact_active = contact is not None and contact["status"] == "active"
    # "Fjern" (removed) or a spam verdict (demoted) takes away ALL trust in
    # this sender: no group contact, no known domain, no established sender
    # (a reply to the user's own mail still counts - it is thread-bound).
    contact_dropped = contact is not None and contact["status"] in ("removed", "demoted")
    if matched and sender:
        dom_h = _h(key, "d:" + rd) if rd else None
        thread_doms: set[str] = set()
        for r in matched:
            try:
                thread_doms.update(json.loads(r["rcpt_doms"] or "[]"))
            except (TypeError, ValueError):
                pass
        sent_day = _ts_day(matched[0]["sent_at"])
        if not auth_ok:
            info.append(_sym("TH_REPLY_UNVERIFIED", 0.0, [mask(sender), f"sendt={sent_day}"]))
        elif not out.blocked:
            if (dom_h and dom_h in thread_doms) or contact_active:
                candidates.append((SCORE_REPLY, _sym("TH_REPLY", SCORE_REPLY, [mask(sender), f"sendt={sent_day}"]),
                                   "reply_detected"))
            else:
                candidates.append((SCORE_REPLY_THREAD, _sym("TH_REPLY_THREAD", SCORE_REPLY_THREAD,
                                                            [mask(sender), f"sendt={sent_day}"]), "reply_detected"))

    # --- B10: known contact (own mailbox, else a colleague mailbox) --------
    base = float(getattr(acc, "known_contact_score", SCORE_KC_DEFAULT) or SCORE_KC_DEFAULT)
    if sender and h and auth_ok and not out.blocked:
        if contact_active:
            s = _kc_score(contact, now, base)
            if is_list:
                s = max(s, SCORE_KC_LIST_MAX)
            candidates.append((s, _sym("TH_KNOWN_CONTACT", s, [
                contact["mask"] or mask(sender), f"sendt={int(contact['sent_count'] or 0)}",
                f"senest={_ts_month(contact['last_sent_at'])}"]), "known_contact"))
        elif contact is None:
            grp_rows = _group_rows(conn, acc.name, contact_group(acc), h)
            if grp_rows:
                g = grp_rows[0]
                s = max(base, SCORE_KC_GROUP)
                if is_list:
                    s = max(s, SCORE_KC_LIST_MAX)
                # No count: how often COLLEAGUE mailboxes wrote to the sender is
                # not this mailbox's business (Brugere only see their own).
                candidates.append((s, _sym("TH_KNOWN_CONTACT", s, [
                    g["mask"] or mask(sender), "gruppe"]), "known_contact"))
        # TH_KNOWN_DOMAIN: >= 2 known addresses at a non-freemail, non-own
        # domain; only with an aligned DKIM signature.
        if (aligned and from_dom and not own_from and not is_freemail(from_dom)
                and not contact_active and not contact_dropped):
            n = conn.execute("SELECT COUNT(*) FROM known_contacts WHERE account=? AND status='active' "
                             "AND (domain=? OR domain LIKE ?)", (acc.name, rd, "%." + (rd or "\x00"))).fetchone()[0]
            if n >= 2:
                candidates.append((SCORE_KNOWN_DOMAIN, _sym("TH_KNOWN_DOMAIN", SCORE_KNOWN_DOMAIN,
                                                            [_display_domain(rd or from_dom), f"kendte={n}"]),
                                   None))

    # --- B12: established sender ------------------------------------------
    hist = None
    if h:
        cur = conn.cursor()
        cur.row_factory = sqlite3.Row
        hist = cur.execute("SELECT * FROM sender_history WHERE account=? AND h=?", (acc.name, h)).fetchone()
    if hist is not None and not out.blocked and sender and not contact_dropped:
        span = int(hist["last_seen"] or 0) - int(hist["first_seen"] or 0)
        if (int(hist["n_kept"] or 0) >= ESTABLISHED_MIN_KEPT and span >= ESTABLISHED_MIN_SPAN_S
                and int(hist["n_junk"] or 0) == 0):
            fp = _fp_load(hist["fp"])
            dkim_hit = any(d in fp["dkim"] or any(under(d, x) for x in fp["dkim"]) for d in dk)
            if strict:
                ok = aligned and dkim_hit
            else:
                env = regdom(domain_of(ctx.get("envelope_from")))
                net_hit = bool(env) and env in fp["env"] and bool(asn) and str(asn) in fp["asn"]
                ok = dkim_hit or net_hit
            if ok:
                candidates.append((SCORE_ESTABLISHED, _sym("TH_ESTABLISHED", SCORE_ESTABLISHED, [
                    f"n={int(hist['n_kept'])}", f"siden={_ts_year(hist['first_seen'])}"]), "established"))

    # --- pick the strongest negative signal (not cumulative) + cap --------
    chosen: tuple[float, dict, str | None] | None = None
    if candidates:
        chosen = min(candidates, key=lambda c: c[0])
        score = chosen[0]
        floor = TRUST_CAP - min(0.0, float(newsletter or 0.0))
        if score < floor:
            score = min(0.0, floor)
            sym = dict(chosen[1])
            sym["s"] = round(score, 3)
            sym["o"] = (list(sym["o"]) + ["loft -6"])[:3] if len(sym["o"]) < 3 else list(sym["o"])[:2] + ["loft -6"]
            chosen = (score, sym, chosen[2])
        if chosen[0] < 0:
            out.symbols.append(chosen[1])
            out.delta += chosen[0]
            if chosen[2]:
                out.metrics.append(chosen[2])
    # --- B12: first contact (+1), never with a reply/contact signal --------
    if (sender and h and chosen is None and not matched and not allow_rule and not own_from
            and _first_contact(conn, acc.name, h, rd, msgid, sender)):
        out.symbols.append(_sym("TH_FIRST_CONTACT", SCORE_FIRST_CONTACT, [_display_domain(rd or from_dom or "")]))
        out.delta += SCORE_FIRST_CONTACT
        out.metrics.append("first_contact")
    out.symbols.extend(info)
    out.delta = round(out.delta, 3)
    if out.unmatched and sender and not out.blocked:
        out.recheck = {"from_h": h, "dom_h": _h(key, "d:" + rd) if rd else None, "auth_ok": auth_ok,
                       "mask": mask(sender), "contact_score": chosen[0] if chosen else 0.0,
                       "contact_sym": chosen[1]["n"] if chosen else None,
                       "newsletter": float(newsletter or 0.0), "threshold": float(threshold),
                       "contact_active": contact_active,
                       "first_contact": any(s["n"] == "TH_FIRST_CONTACT" for s in out.symbols)}
    return out


def reply_match(conn: sqlite3.Connection, account: str, refs: Sequence[str], dom_h: str | None,
                contact_active: bool) -> tuple[float, str, str] | None:
    """(score, symbol, sent day) when one of `refs` (hashes) is a sent mail."""
    if not refs:
        return None
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    rows = cur.execute(
        f"SELECT * FROM sent_threads WHERE account=? AND mid_h IN ({','.join('?' * len(refs))}) "
        f"ORDER BY sent_at DESC", (account, *refs)).fetchall()
    if not rows:
        return None
    doms: set[str] = set()
    for r in rows:
        try:
            doms.update(json.loads(r["rcpt_doms"] or "[]"))
        except (TypeError, ValueError):
            pass
    day = _ts_day(rows[0]["sent_at"])
    if (dom_h and dom_h in doms) or contact_active:
        return SCORE_REPLY, "TH_REPLY", day
    return SCORE_REPLY_THREAD, "TH_REPLY_THREAD", day


def store_recheck(conn: sqlite3.Connection, account: str, message_id: str, trust: Trust, *,
                  final: float, now: int) -> None:
    if trust.recheck is None or not trust.unmatched:
        return
    data = dict(trust.recheck, final=float(final))
    conn.execute("INSERT OR REPLACE INTO contact_recheck(account, message_id, refs, data, created_at) "
                 "VALUES(?,?,?,?,?)", (account, message_id, json.dumps(trust.unmatched),
                                        json.dumps(data, separators=(",", ":")), now))


def recheck_pending(client: Any, db: Any, log_: logging.Logger, acc: Any, fmap: dict[str, str], state: Any, *,
                    key: bytes | None, now: int) -> list[str]:
    """B11 freshness inside the grace period: pending moves whose
    references matched nothing at scan time. Runs an incremental Sent sync
    (at most once a minute) and keeps the mail in the inbox when it now
    turns out to be a reply that brings it under the threshold. Returns
    the Message-IDs kept. Must run BEFORE the caller selects the inbox."""
    if key is None or not enabled(acc):
        return []
    try:
        rows = db.conn.execute(
            "SELECT r.message_id, r.refs, r.data FROM contact_recheck r WHERE r.account=? AND EXISTS "
            "(SELECT 1 FROM pending_move p WHERE p.account=r.account AND p.message_id=r.message_id)",
            (db.account,)).fetchall()
    except sqlite3.Error:
        return []
    if not rows:
        return []
    last = float(getattr(state, "contacts_last_fresh", 0.0) or 0.0)
    if not last or _mono() - last >= FRESH_MIN_INTERVAL_S:
        incremental_sent(client, db, log_, acc, state, key=key, now=now)
    kept: list[str] = []
    for r in rows:
        try:
            refs = json.loads(r[1] or "[]")
            data = json.loads(r[2] or "{}")
        except (TypeError, ValueError):
            continue
        m = reply_match(db.conn, db.account, refs, data.get("dom_h"), bool(data.get("contact_active")))
        if m is None:
            continue
        score, name, day = m
        if not data.get("auth_ok"):
            continue
        prev = float(data.get("contact_score") or 0.0)
        if score >= prev:
            continue
        newsletter = float(data.get("newsletter") or 0.0)
        floor = TRUST_CAP - min(0.0, newsletter)
        eff = max(score, floor)
        first = SCORE_FIRST_CONTACT if data.get("first_contact") else 0.0
        new_final = round(float(data.get("final") or 0.0) - prev - first + eff, 3)
        thr = float(data.get("threshold") or getattr(acc, "threshold", 8.0))
        msgid = r[0]
        row = db.conn.execute("SELECT symbols FROM messages WHERE account=? AND message_id=?",
                              (db.account, msgid)).fetchone()
        try:
            syms = json.loads(row[0]) if row and row[0] else []
        except (TypeError, ValueError):
            syms = []
        syms = [s for s in syms if isinstance(s, dict) and s.get("n") not in CONTACT_SYMBOLS
                and s.get("n") != "TH_FIRST_CONTACT"]
        syms.insert(0, _sym(name, eff, [data.get("mask") or "…", f"sendt={day}"]))
        with db.tx():
            db.conn.execute("DELETE FROM contact_recheck WHERE account=? AND message_id=?", (db.account, msgid))
            if new_final >= thr:
                db.conn.execute("UPDATE messages SET our_score=?, symbols=? WHERE account=? AND message_id=?",
                                (new_final, json.dumps(syms, ensure_ascii=False, separators=(",", ":")),
                                 db.account, msgid))
                db.log_event("reply_recheck", msgid, detail=f"svar fundet, score {new_final:.2f} – flyttes stadig")
                continue
            db.conn.execute("DELETE FROM pending_move WHERE account=? AND message_id=?", (db.account, msgid))
            db.conn.execute(
                "UPDATE messages SET our_score=?, symbols=?, our_action='none' WHERE account=? AND message_id=?",
                (new_final, json.dumps(syms, ensure_ascii=False, separators=(",", ":")), db.account, msgid))
            db.log_event("reply_recheck", msgid,
                         detail=f"svar på din mail fundet: score {float(data.get('final') or 0):.2f} -> "
                                f"{new_final:.2f}, bliver i indbakken")
            _bump(db, "reply_detected")
        kept.append(msgid)
        log_.info("reply re-check kept a mail in the inbox (%s)", data.get("mask") or "…")
    return kept


def _bump(db: Any, metric: str) -> None:
    bump = getattr(db, "bump", None)
    if bump is not None:
        bump(metric)


# ---------------------------------------------------------------------------
# Maintenance from scans and user verdicts (B12/B14)
# ---------------------------------------------------------------------------


def record_scan(conn: sqlite3.Connection, acc: Any, key: bytes | None, *, sender: str | None,
                envelope_from: str | None, dkim_domains: Sequence[str], asn: str | None,
                spam: bool, now: int, msgid: str | None) -> None:
    """Every scan updates sender_history: n_seen, n_kept (not spam) or
    n_junk (filter verdict spam). Fingerprints only from kept mail; the
    sending network (envelope domain + ASN) is only learned from a mail
    whose verified DKIM domain is aligned with the From or already in the
    fingerprint - a forger cannot teach us his own network."""
    if key is None or not enabled(acc):
        return
    norm = normalize_address(sender)
    if not norm or not _seen_once(conn, acc.name, key, msgid):
        return
    env = regdom(domain_of(envelope_from))
    dk = [d for d in (normalize_domain(x) for x in dkim_domains) if d]
    row = conn.execute("SELECT fp FROM sender_history WHERE account=? AND h=?",
                       (acc.name, _h(key, norm))).fetchone()
    known_dkim = _fp_load(row[0] if row else None)["dkim"]
    from_dom = norm.rpartition("@")[2]
    proven = any(under(from_dom, d) or under(d, from_dom) or d in known_dkim
                 or any(under(d, x) for x in known_dkim) for d in dk)
    _record_history(conn, acc.name, key, norm, now, kept=0 if spam else 1, junk=1 if spam else 0,
                    env=[env] if env and proven else [], dkim=dk,
                    asn=[asn] if asn and proven else [], add_fp=not spam)


FILTER_JUNK_ACTIONS = frozenset({"pending_move", "moved_to_junk", "move_failed", "flagged", "shadow_spam"})


def _symbol_names(symbols: Any) -> set[str]:
    try:
        data = json.loads(symbols) if isinstance(symbols, (str, bytes)) else (symbols or [])
    except (TypeError, ValueError):
        return set()
    return {str(s.get("n")) for s in data if isinstance(s, dict) and s.get("n")}


def on_user_spam(conn: sqlite3.Connection, account: str, key: bytes | None, *, sender: str | None,
                 symbols: Any = None, prior_action: str | None = None, actor: str = "",
                 demote: bool = True, now: int | None = None, message_id: str | None = None) -> dict | None:
    """B14: the user said 'spam' (drag into Spamfilter / 'Det er spam').
    n_junk + 1 (ESTABLISHED dies for the sender; n_kept - 1 when the scan
    had counted it as kept) and, when the mail carried TH_KNOWN_CONTACT or
    TH_ESTABLISHED and `demote`, the contact is demoted (event
    contact_demoted). Returns {mask, demoted, h} or None. Caller owns the
    transaction."""
    norm = normalize_address(sender)
    if key is None or not norm:
        return None
    now = int(time.time()) if now is None else int(now)
    h = _h(key, norm)
    kept_before = prior_action not in FILTER_JUNK_ACTIONS and prior_action not in (
        "user_junked", "manual_mark_spam", "provider_junk")
    conn.execute(
        "UPDATE sender_history SET n_junk = n_junk + 1, n_kept = MAX(0, n_kept - ?) WHERE account=? AND h=?",
        (1 if kept_before and prior_action is not None else 0, account, h))
    if conn.execute("SELECT 1 FROM sender_history WHERE account=? AND h=?", (account, h)).fetchone() is None:
        conn.execute("INSERT INTO sender_history(account, h, regdom, first_seen, last_seen, n_kept, n_seen, n_junk, "
                     "fp) VALUES(?,?,?,?,?,0,1,1,'{}')", (account, h, regdom(norm.rpartition('@')[2]), now, now))
    names = _symbol_names(symbols)
    demoted = False
    if demote and names & {"TH_KNOWN_CONTACT", "TH_ESTABLISHED"}:
        row = conn.execute("SELECT status FROM known_contacts WHERE account=? AND h=?", (account, h)).fetchone()
        if row is None:
            if "TH_KNOWN_CONTACT" in names:
                # A colleague mailbox's contact: block the group bonus here only.
                conn.execute("INSERT INTO known_contacts(account, h, domain, mask, sent_count, source, status, "
                             "status_at, status_by) VALUES(?,?,?,?,0,'manual','demoted',?,?)",
                             (account, h, norm.rpartition("@")[2], mask(norm), now, actor or "auto:spam"))
                demoted = True
        elif row[0] == "active":
            conn.execute("UPDATE known_contacts SET status='demoted', status_at=?, status_by=? WHERE account=? AND h=?",
                         (now, actor or "auto:spam", account, h))
            demoted = True
        if demoted or "TH_ESTABLISHED" in names:
            conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                         (account, now, message_id, "contact_demoted",
                          f"{mask(norm)}" + (" fjernet fra kendte kontakter" if demoted else "")
                          + (" – ikke længere fast afsender" if "TH_ESTABLISHED" in names else "")))
    return {"mask": mask(norm), "demoted": demoted, "h": h}


def on_user_ham(conn: sqlite3.Connection, account: str, key: bytes | None, *, sender: str | None,
                prior_action: str | None = None, now: int | None = None) -> None:
    """A rescue / release counts as kept (n_kept + 1); a filter junk
    verdict on it is taken back (n_junk - 1). The sender is no longer a
    first contact afterwards. Caller owns the transaction."""
    norm = normalize_address(sender)
    if key is None or not norm:
        return
    now = int(time.time()) if now is None else int(now)
    h = _h(key, norm)
    # The mail had been put into spam (by the filter or an earlier verdict of
    # the user, now taken back): that junk count goes again.
    undo_junk = 1 if prior_action in FILTER_JUNK_ACTIONS | {"user_junked", "manual_mark_spam"} else 0
    if conn.execute("SELECT 1 FROM sender_history WHERE account=? AND h=?", (account, h)).fetchone():
        conn.execute("UPDATE sender_history SET n_kept = n_kept + 1, n_junk = MAX(0, n_junk - ?), "
                     "last_seen = MAX(COALESCE(last_seen, 0), ?) WHERE account=? AND h=?",
                     (undo_junk, now, account, h))
    else:
        conn.execute("INSERT INTO sender_history(account, h, regdom, first_seen, last_seen, n_kept, n_seen, n_junk, "
                     "fp) VALUES(?,?,?,?,?,1,1,0,'{}')", (account, h, regdom(norm.rpartition('@')[2]), now, now))


def set_status(conn: sqlite3.Connection, account: str, h: str, status: str, actor: str, *,
               now: int | None = None, mask_hint: str | None = None) -> str | None:
    """'active' | 'removed' | 'demoted' for one contact hash (inserting a
    manual row when the account has none, e.g. a colleague's contact).
    'active' also clears n_junk (undo of a demotion). Returns the previous
    status ('' for a new row) or None for invalid input. Caller owns the
    transaction."""
    if status not in ("active", "removed", "demoted") or not re.fullmatch(r"[0-9a-f]{%d}" % HASH_HEX, h or ""):
        return None
    now = int(time.time()) if now is None else int(now)
    row = conn.execute("SELECT status FROM known_contacts WHERE account=? AND h=?", (account, h)).fetchone()
    if row is None:
        if status == "active":
            prev = ""
        else:
            conn.execute("INSERT INTO known_contacts(account, h, mask, sent_count, source, status, status_at, "
                         "status_by) VALUES(?,?,?,0,'manual',?,?,?)",
                         (account, h, mask_hint, status, now, actor or None))
            return ""
    else:
        prev = str(row[0])
        conn.execute("UPDATE known_contacts SET status=?, status_at=?, status_by=? WHERE account=? AND h=?",
                     (status, now, actor or None, account, h))
    if status == "active":
        conn.execute("UPDATE sender_history SET n_junk=0 WHERE account=? AND h=?", (account, h))
        if row is not None and conn.execute("SELECT source FROM known_contacts WHERE account=? AND h=?",
                                            (account, h)).fetchone()[0] == "manual":
            # A manual row only blocked a colleague's contact: drop it.
            conn.execute("DELETE FROM known_contacts WHERE account=? AND h=? AND source='manual' "
                         "AND sent_count=0", (account, h))
    return prev
