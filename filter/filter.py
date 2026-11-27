"""IMAP spam filter engine (spamfilter 2.0).

Hard rules enforced in this file:
  * Never plain EXPUNGE, never IMAP DELETE. The only expunge is a UID
    EXPUNGE of exactly the UIDs that were just copied elsewhere (UIDPLUS
    move emulation in imap_move); \\Deleted is never set on anything else.
  * "Remove" means moving to another folder. Trash retention is the mail
    provider's responsibility (automatic retention is off by default).
  * Shadow mode is strictly read-only on IMAP: EXAMINE, SEARCH, STATUS,
    LIST and BODY.PEEK fetches only - no folders, flags, moves or learns.
  * Fail closed: on any uncertainty (rspamd unreachable, parse error,
    folder missing) keep messages in their current folder.
  * No autolearn from rspamd scoring. Bayes learns only from explicit user
    decisions (moves, WebUI actions, training jobs).
  * User verdicts are sticky: mail the user rescued or released is never
    moved back into the spam folder.
"""

from __future__ import annotations

import email
import email.header
import email.policy
import ipaddress
import json
import logging
import math
import os
import re
import signal
import sqlite3
import ssl
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import getaddresses, parseaddr
from html import escape as _html_escape
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Sequence

import requests
import yaml
from imapclient import IMAPClient
from imapclient.exceptions import IMAPClientAbortError, IMAPClientError, LoginError

import siteconfig
import mailidentity
import quality
import decisionpolicy
import holdout
import decisiontrace
import policytrial

# A1: the container runs `python -u filter.py`, so this module is __main__.
# Register it under its import name too so `import filter` in services,
# trainer and the dashboard returns this very module (one SHUTDOWN event,
# one set of module globals) instead of importing a second copy.
if __name__ == "__main__":
    sys.modules.setdefault("filter", sys.modules[__name__])

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "2.20.1"
SCORE_VERSION = 2  # A4: scores computed with the 2.0 sender context

CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", "/app/accounts.yml"))
STATE_DIR = Path(os.environ.get("STATE_DIR", "/state"))
DB_PATH = STATE_DIR / "spamfilter.db"
# Kept for backwards compatibility only: the engine derives state file paths
# from STATE_DIR at call time (see _state_file) so a repointed STATE_DIR
# (tests, tools) stays consistent.
HEARTBEAT_PATH = STATE_DIR / "heartbeat"
RELOAD_PATH = STATE_DIR / "reload_requested"
AUTOMATIC_RETENTION_ENABLED = os.environ.get("AUTOMATIC_RETENTION_ENABLED") == "1"

RSPAMD_SCAN_URL = os.environ.get("RSPAMD_SCAN_URL", "http://spamfilter-rspamd:11333/checkv2")
RSPAMD_LEARN_URL = os.environ.get("RSPAMD_LEARN_URL", "http://spamfilter-rspamd:11334")
# The normal worker answers GET /ping; used to tell an rspamd outage apart
# from a message rspamd chokes on.
RSPAMD_PING_URL = os.environ.get(
    "RSPAMD_PING_URL", RSPAMD_SCAN_URL.rsplit("/", 1)[0] + "/ping")


def _load_rspamd_password() -> str:
    val = os.environ.get("RSPAMD_PASSWORD", "").strip()
    if val:
        return val
    # Fallback: shared appdata file written by the Unraid bootstrap script.
    pwfile = Path(os.environ.get("STATE_DIR", "/state")) / "controller.password"
    try:
        if pwfile.is_file():
            return pwfile.read_text().strip()
    except OSError:
        pass
    return ""


RSPAMD_PASSWORD = _load_rspamd_password()
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

# Optional env overrides for accounts.yml `defaults` (Unraid template uses these
# so the user can set retention windows without editing YAML). Unset = ignore.
_ENV_DEFAULT_OVERRIDES: dict[str, str] = {
    "junk_retention_days": "DEFAULT_JUNK_RETENTION_DAYS",
    "trained_retention_days": "DEFAULT_TRAINED_RETENTION_DAYS",
}

FLIP_FLOP_COOLDOWN_S = 600       # 10 min between opposite learns for one msg
UNLEARNABLE_RETRY_S = 30 * 86400 # retry messages marked 'unlearnable' after 30d
SAFE_MODE_UNSEEN_CAP = 500       # default Inbox-unseen cap; per-account override via safe_mode_unseen_cap
SCAN_FETCH_CHUNK = 50            # metadata (flags/size/header) FETCH batch
SCAN_BODY_CHUNK = 10             # body FETCH batch: <= 50 MiB resident at the size cap
MAX_SCAN_PER_RUN = 200           # bound work after a reconnect
JUNK_POLL_MAX_PER_RUN = 500      # new junk UIDs handled per poll
# 2.12 (#13): mail the PROVIDER filed in its spam folder is scored read-only
# (EXAMINE + BODY.PEEK[], never moved): at most this many per poll, received
# within PROVIDER_JUNK_SCORE_DAYS. Never learned (the score contains the
# provider's own verdict); a low score from a known sender is listed under
# Tjek disse.
PROVIDER_JUNK_SCORE_PER_RUN = 10
PROVIDER_JUNK_SCORE_DAYS = 14
JUNK_RECONCILE_INTERVAL_S = 6 * 3600
RECONCILE_FETCH_CHUNK = 200
SCAN_RETRY_MAX_ATTEMPTS = 5
SCAN_RETRY_MAX_AGE_S = 6 * 3600
SCAN_RETRY_BASE_S = 60           # retry n is due first_fail_at + 60 * (2**n - 1)
RSPAMD_BACKOFF_MIN_S = 30
RSPAMD_BACKOFF_MAX_S = 300
RECONNECT_MIN_BACKOFF = 5
RECONNECT_MAX_BACKOFF = 300
LOGIN_FAILURES_BEFORE_AUTH_FAILED = 3
AUTH_FAILED_RETRY_S = 30 * 60
AUTH_FAILED_POLL_S = 5
IDLE_SLICE_S = 5                 # SHUTDOWN is observed within one slice
MIN_LOOP_WAIT_S = 5
SHUTDOWN_JOIN_S = 8
CONFIG_RECHECK_S = 10
MOVE_RETRY_LIMIT = 3
HTTP_TIMEOUT = 30
IMAP_TIMEOUT = 60
MAX_FETCH_BYTES = 5 * 1024 * 1024
MESSAGE_RETENTION_S = 120 * 86400
SCAN_RETRY_PRUNE_S = 7 * 86400
SYMBOLS_MAX = 30
MAX_STATUS_FOLDERS = 500

# 2.1: safety net around moves (E1), fast moves (E2), autolearn (E6),
# health (E11) and the daily receipt (E12).
UPDATE_HOLD_S = 30 * 60          # moves held after a new VERSION first starts ...
UPDATE_HOLD_MARGIN = 5.0         # ... unless final score >= threshold + this
# 2.3 (B16): a stored threat (virus/phish/malware link/attachment) is clear
# spam whatever its score - it is never held by the update hold.
_PM_THREAT_SQL = ("EXISTS(SELECT 1 FROM messages tm WHERE tm.account=pending_move.account "
                  "AND tm.message_id=pending_move.message_id AND tm.threat IS NOT NULL)")
CIRCUIT_WINDOW_RATE_S = 3600
CIRCUIT_WINDOW_RATIO_S = 2 * 3600
# rate_limit action recorded next to 'move' for moves an admin approved by
# resuming the breaker (they never count towards it again).
CIRCUIT_APPROVED_ACTION = "move_approved"
LIMIT_BACKOFF_MIN_S = 5 * 60     # provider connection limits (E4)
LIMIT_BACKOFF_MAX_S = 30 * 60
MOVE_REPAIR_MAX_ATTEMPTS = 3
MOVE_REPAIR_LEGACY_WINDOW_S = 7 * 86400
AUTOLEARN_SPAM_MARGIN = 6.0      # threshold + 6
AUTOLEARN_SPAM_AGE_S = 3 * 86400
AUTOLEARN_HAM_MAX_SCORE = 0.0
AUTOLEARN_HAM_AGE_S = 7 * 86400
AUTOLEARN_BALANCE = 3.0          # spam:ham learns per week within 1:3..3:1
AUTOLEARN_SCAN_LIMIT = 200
NEWSLETTER_SCORE = -1.5
NEWSLETTER_MAX_OVER = 3.0        # only when final < threshold + 3
STALE_AFTER_S = 10 * 60          # thread silent this long while idle/working
ALIVE_TOUCH_S = 60
# Sender and Message-ID domain of the filter's own mails: local site config
# (config/site.yml), neutral defaults on a fresh install.
RECEIPT_FROM = siteconfig.receipt_from()
RECEIPT_MSGID_DOMAIN = siteconfig.msgid_domain()
RECEIPT_HEADER = "X-TH-Spamfilter"
RECEIPT_MAX_ITEMS = 50
# The owner's own MX (forwards info@ shop mailboxes with SRS): walked past
# like a provider hop so the real sender is judged (E7). All owner values
# come from the local site config (config/site.yml, Indstillinger -> Lokal
# opsætning) - empty on a fresh install; per account overridable in
# accounts.yml as before.
DEFAULT_TRUSTED_FORWARDERS = siteconfig.get_list("trusted_forwarders")
# 2.2 (B2/B21) owner domains: the platform(s) whose mail always gets through
# and the owner's webshops (the platform domains count as webshops too).
DEFAULT_OWNER_PLATFORM_DOMAINS = siteconfig.get_list("platform_domains")
DEFAULT_WEBSHOP_DOMAINS = list(dict.fromkeys([*siteconfig.get_list("webshop_domains"),
                                              *siteconfig.get_list("platform_domains")]))
# 2.3 (B17): attachment extensions that are always blocked (top level or
# inside an archive). In 12 months not one legitimate file of these types.
DEFAULT_ATTACHMENT_BLOCK = ["exe", "scr", "com", "pif", "cpl", "msi", "msix", "appx", "bat", "cmd",
                            "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "lnk", "jar",
                            "iso", "img", "vhd", "vhdx", "xll", "chm", "reg"]
ATTACHMENT_BLOCK_MAX = 100
# B22: domains whose lookalikes are flagged (TH_LOOKALIKE_*) and watched for
# new registrations; every mailbox domain is always protected on top.
DEFAULT_PROTECTED_DOMAINS = siteconfig.get_list("protected_domains")
PROTECTED_DOMAINS_MAX = 50

JUNK_KEYWORD = "$Junk"           # RFC 5788 keyword; we never touch \Flagged
NOTJUNK_KEYWORD = "$NotJunk"
# Keywords mail clients set for "not junk" (Apple Mail, Thunderbird).
# NOT a user verdict in the inbox: Apple Mail's own junk filter tags almost
# every message it considers clean with $NotJunk/NotJunk automatically
# (verified on a live mailbox: 5 of 6 new mails). Only \Flagged or
# an actual move counts as the user's decision there.
NOTJUNK_KEYWORDS = frozenset({"$NotJunk", "NotJunk", "NonJunk", "$NonJunk"})
DELETED_FLAG = b"\\Deleted"

VALID_MODES = {"shadow", "flag", "move"}
STICKY_HAM_ACTIONS = decisionpolicy.STICKY_HAM_ACTIONS
# Rows that say "this Message-ID was in a spam folder" (rescue evidence).
JUNK_ACTIONS = frozenset({"moved_to_junk", "provider_junk", "user_junked", "manual_mark_spam"})
# Junk-poll sightings of these were put there by the filter / WebUI, not
# by the user's mail client, so they never count as a user verdict.
OUR_JUNK_ACTIONS = frozenset({"pending_move", "moved_to_junk", "manual_mark_spam", "move_failed"})
DMARC_SPOOF_SYMBOLS = decisionpolicy.DMARC_SPOOF_SYMBOLS
ALLOW_DISTRUST_SYMBOLS = decisionpolicy.ALLOW_DISTRUST_SYMBOLS

STAT_METRICS = frozenset({
    "scanned", "spam_detected", "moved", "flagged", "released", "marked_spam",
    "learned_spam", "learned_ham", "skipped_seen", "skipped_no_msgid",
    "skipped_oversize", "scan_failed", "scan_giveup", "allowlisted", "junk_identity_unverified",
    "blocklisted", "user_rescued", "user_junked", "move_failed",
    # 2.1
    "autolearned_spam", "autolearned_ham",
    # 2.2: B6c ham learns refused by the ham guard, B7 late (aged) scans.
    "ham_guarded", "aged_scanned",
    # 2.3: B10-B12 trust signals (contacts.METRICS).
    "known_contact", "reply_detected", "first_contact", "established",
    # 2.3: B16 threat class, B19 rescans (ZAP).
    "threat_detected", "zapped", "would_have_zapped",
    # Straks-advarsel: notices appended to an INBOX after a threat was moved.
    "threat_notice_sent",
    # 2.6 (A4): newsletters (shadow: would have moved; moved; put back by the user).
    "newsletter_shadow", "newsletter_moved", "newsletter_kept",
    # 2.6 (C2) DMARC reports (dmarc.py: reports read; report mails moved to their folder).
    "dmarc_reports", "dmarc_moved",
})

SHUTDOWN = threading.Event()
# Identifies this process run; written to /state/boot_id and every
# heartbeat so the healthcheck never trusts a heartbeat from an older run.
BOOT_ID = uuid.uuid4().hex


def _now() -> float:
    """Wall clock. A module-level hook so tests can time-travel."""
    return time.time()


def _sleep(seconds: float) -> bool:
    """Interruptible sleep; True when shutdown was requested."""
    return SHUTDOWN.wait(timeout=max(0.0, seconds))


def _state_file(name: str) -> Path:
    return Path(STATE_DIR) / name


# ---------------------------------------------------------------------------
# Europe/Copenhagen day (stats_daily)
# ---------------------------------------------------------------------------

try:
    from zoneinfo import ZoneInfo

    _CPH: Any = ZoneInfo("Europe/Copenhagen")
except Exception:  # noqa: BLE001 - no tzdata in the image: use the EU rule
    _CPH = None


def _last_sunday_0100_utc(year: int, month: int) -> datetime:
    d = datetime(year, month, 31, 1, 0, tzinfo=timezone.utc)
    return d - timedelta(days=(d.weekday() + 1) % 7)


def stats_day(ts: float | None = None) -> str:
    """'YYYY-MM-DD' in Europe/Copenhagen for a unix timestamp."""
    ts = _now() if ts is None else ts
    if _CPH is not None:
        return datetime.fromtimestamp(ts, _CPH).strftime("%Y-%m-%d")
    utc = datetime.fromtimestamp(ts, timezone.utc)
    dst = _last_sunday_0100_utc(utc.year, 3) <= utc < _last_sunday_0100_utc(utc.year, 10)
    return (utc + timedelta(hours=2 if dst else 1)).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


class ConfigError(ValueError):
    """Invalid accounts.yml. Short English text, safe to show in the UI."""


@dataclass
class Account:
    name: str
    user: str
    password: str = field(repr=False)

    imap_host: str
    imap_port: int
    ssl: bool

    inbox: str
    junk: str
    trash: str
    spam_train: str
    trained_spam: str
    ham_train: str
    trained_ham: str

    mode: str
    threshold: float
    min_threshold_allowed: float
    reject_score_above: float

    move_grace_seconds: int
    learn_grace_seconds: int
    idle_timeout: int
    poll_interval: int
    junk_poll_interval: int
    retention_check_interval: int

    max_moves_per_hour: int
    max_learns_per_hour: int
    max_train_per_run: int
    safe_mode_unseen_cap: int

    junk_retention_days: int
    trained_retention_days: int

    learn_from_moves: bool
    auto_special_folders: bool

    # Optional rspamd Bayes identity. If unset, falls back to acc.user so
    # each IMAP account has its own per-recipient Bayes data. Set the same
    # value across multiple accounts to pool their Bayes training.
    bayes_user: str | None = None

    # Populated at runtime once IMAP delimiter is known.
    delimiter: str = "/"
    folder_map: dict[str, str] = field(default_factory=dict)

    # 2.0 fields (all defaulted so older constructors keep working).
    enabled: bool = True
    password_file: str | None = None
    junk_explicit: bool = False
    trash_explicit: bool = False
    training_folders: bool = False
    provider_bonus: bool = True
    trusted_relays: list[str] = field(default_factory=list)
    trusted_relay_domains: list[str] = field(default_factory=list)
    # Inline `password:` from accounts.yml when load_account_configs() is
    # used (password stays ""); read_secret() returns it.
    secret_inline: str = field(default="", repr=False, compare=False)

    # 2.1 fields (defaulted: older constructors and configs keep working).
    move_grace_seconds_high: int = 3
    fast_move_margin: float = 5.0
    circuit_max_moves_per_hour: int = 25
    circuit_max_ratio: float = 0.4
    circuit_min_moves: int = 10
    autolearn: bool = True
    autolearn_daily_cap: int = 10
    trusted_forwarders: list[str] = field(default_factory=lambda: list(DEFAULT_TRUSTED_FORWARDERS))
    protected_recipients: list[str] = field(default_factory=list)
    protected_threshold: float = 18.0
    daily_report: bool = False
    report_hour: int = 7
    # The user moving mail OUT of the spam folder in their mail app allows
    # that exact sender for this account (owner's wish, 2026-10-21).
    auto_allow_on_rescue: bool = True
    auto_block_repeated_spam: bool = True

    # 2.2 fields (defaulted: older constructors and configs keep working).
    # B2: the owner's own (multi-tenant) shop platform. rspamd lists it on
    # its RSPAMD_URIBL domain list; TH_OWN_PLATFORM_URIBL cancels that.
    owner_platform_domains: list[str] = field(default_factory=lambda: list(DEFAULT_OWNER_PLATFORM_DOMAINS))
    # B21: the owner's webshops (weekly report guarantee line).
    webshop_domains: list[str] = field(default_factory=lambda: list(DEFAULT_WEBSHOP_DOMAINS))
    # B7: mail older than this (INTERNALDATE) is scanned in "aged" mode;
    # 0 turns aged mode off.
    aged_scan_hours: float = 6.0

    # 2.3 fields (defaulted: older constructors and configs keep working).
    # B10-B12 (contacts.py): trust people the user wrote to, replies to
    # the user's own mail and established senders.
    known_contacts: bool = True
    known_contact_score: float = -4.0
    # Sent folders to learn from; empty = SPECIAL-USE \Sent + known names.
    sent_folders: list[str] = field(default_factory=list)
    # Mailboxes in the same group share contacts (-3); None = the domain
    # of the mailbox address (example.com for every example-* mailbox).
    contact_group: str | None = None
    # B19: rescan mail that stayed in the inbox when blocklists catch up.
    zap: bool = True
    # B17: blocked attachment extensions (lower case, no dot).
    attachment_block: list[str] = field(default_factory=lambda: list(DEFAULT_ATTACHMENT_BLOCK))
    # Straks-advarsel: a short notice in the mailbox's own INBOX when a
    # threat (virus, phishing, dangerous attachment) was moved away.
    threat_notice: bool = True
    # B22: lookalike domains (lookalike.py). The mailbox domains are always
    # protected too (lookalike_protected()).
    protected_domains: list[str] = field(default_factory=lambda: list(DEFAULT_PROTECTED_DOMAINS))

    # 2.6 fields (defaulted: older constructors and configs keep working).
    # A4 (newsletters.py): newsletters/marketing below the threshold go to
    # their own folder. off | shadow (record only) | on (move, mode move only).
    newsletters: str = "shadow"
    newsletter_folder: str = "Nyhedsbreve"


# Built-in defaults applied unless overridden in accounts.yml `defaults:` or in
# a per-account block. Required-from-the-user keys (name, user, imap_host,
# password|password_file) are NOT here on purpose.
BUILTIN_DEFAULTS: dict[str, Any] = {
    "enabled": True,
    "imap_port": 993,
    "ssl": True,
    "inbox": "INBOX",
    "junk": "Junk",
    "trash": "Trash",
    # The four training folders live under the junk folder; they are only
    # created when training_folders is true.
    "spam_train": "Junk/Train-Spam",
    "trained_spam": "Junk/Trained-Spam",
    "ham_train": "Junk/Train-Ham",
    "trained_ham": "Junk/Trained-Ham",
    "mode": "shadow",
    "threshold": 8.0,
    "min_threshold_allowed": 5.0,
    "reject_score_above": 100.0,
    "move_grace_seconds": 60,
    "learn_grace_seconds": 300,
    "idle_timeout": 1500,
    "poll_interval": 600,
    "junk_poll_interval": 300,
    "retention_check_interval": 3600,
    "max_moves_per_hour": 60,
    "max_learns_per_hour": 50,
    "max_train_per_run": 100,
    "safe_mode_unseen_cap": SAFE_MODE_UNSEEN_CAP,
    "junk_retention_days": 10,
    "trained_retention_days": 7,
    "learn_from_moves": True,
    "bayes_user": None,
    # Look up junk/trash via RFC 6154 SPECIAL-USE unless the account entry
    # names the folder explicitly (explicit always wins).
    "auto_special_folders": True,
    "training_folders": False,
    "provider_bonus": True,
    "trusted_relays": [],
    "trusted_relay_domains": [],
    # 2.1
    "move_grace_seconds_high": 3,
    "fast_move_margin": 5.0,
    "circuit_max_moves_per_hour": 25,
    "circuit_max_ratio": 0.4,
    "circuit_min_moves": 10,
    "autolearn": True,
    "autolearn_daily_cap": 10,
    "trusted_forwarders": list(DEFAULT_TRUSTED_FORWARDERS),
    "protected_recipients": [],
    "protected_threshold": 18.0,
    "daily_report": False,
    "auto_allow_on_rescue": True,
    "auto_block_repeated_spam": True,
    "report_hour": 7,
    # 2.2
    "owner_platform_domains": list(DEFAULT_OWNER_PLATFORM_DOMAINS),
    "webshop_domains": list(DEFAULT_WEBSHOP_DOMAINS),
    "aged_scan_hours": 6.0,
    # 2.3 (B10-B12, contacts.py): known contacts, replies, established
    # senders and first contact. known_contact_score is the bonus for a
    # recent contact (-6..-1; older contacts get -3/-2, list mail max -2).
    # sent_folders: override the Sent folder detection (list of names).
    # contact_group: mailboxes with the same group share contacts (-3);
    # unset = the mailbox address domain.
    "known_contacts": True,
    "known_contact_score": -4.0,
    "sent_folders": [],
    "contact_group": None,
    # 2.3 (B19): rescan ("ZAP") mail that stayed in the inbox when a
    # blocklist catches up (+45 min, +4 h, +24 h). Moves only happen in move
    # mode; flag mode flags, shadow mode only records would_have_zapped.
    "zap": True,
    # 2.3 (B17): attachment extensions that are always blocked
    # (TH_ATTACH_BLOCK +20, threat 'attachment'), also inside zip archives.
    "attachment_block": list(DEFAULT_ATTACHMENT_BLOCK),
    # Straks-advarsel: when a threat (virus, phishing/malware link,
    # dangerous attachment) is moved to the filter's folder, a short Danish
    # notice is appended to the mailbox's own INBOX (at most one per 30 min,
    # up to 10 mails listed; never a link, attachment or HTML of the
    # dangerous mail). Works without SMTP. false = no notice for this mailbox.
    "threat_notice": True,
    # B22: lookalikes of these domains in From/Reply-To/envelope/DKIM get
    # TH_LOOKALIKE_DOMAIN (+6, threat 'lookalike'), in links TH_LOOKALIKE_URL
    # (+4); a weekly DNS check reports newly registered lookalikes. Every
    # mailbox domain is protected on top of this list.
    "protected_domains": list(DEFAULT_PROTECTED_DOMAINS),
    # 2.6 (A4, newsletters.py): newsletters and marketing mail BELOW the spam
    # threshold. shadow = only record what would be moved ("Prøv"), on = move
    # them to newsletter_folder (created on the first move; only while the
    # account is in mode move), off = leave them alone. Spam always wins.
    "newsletters": "shadow",
    "newsletter_folder": "Nyhedsbreve",
}

REQUIRED_PER_ACCOUNT: tuple[str, ...] = ("name", "user", "imap_host")
TRAIN_KEYS: tuple[str, ...] = ("spam_train", "trained_spam", "ham_train", "trained_ham")

_BOOL_TRUE = frozenset({"true", "yes", "on", "1"})
_BOOL_FALSE = frozenset({"false", "no", "off", "0"})
_RELAY_DOMAIN_RE = re.compile(r"^\.?[a-z0-9-]+(\.[a-z0-9-]+)*$")


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in overlay.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _apply_env_overrides(defaults: dict[str, Any]) -> dict[str, Any]:
    out = dict(defaults)
    for cfg_key, env_key in _ENV_DEFAULT_OVERRIDES.items():
        val = os.environ.get(env_key)
        if val is None or val == "":
            continue
        try:
            out[cfg_key] = int(val)
        except ValueError:
            raise ConfigError(f"env {env_key}={val!r}: not an integer") from None
    return out


def _clean_bayes_user(raw: Any, account_name: str) -> str | None:
    """Validate the bayes_user override. Rejects CR/LF so the value cannot
    be smuggled as an extra header line via the `Delivered-To:` prefix we
    prepend to /learn{spam,ham} bodies (and the Deliver-To HTTP header)."""
    if not raw:
        return None
    s = str(raw)
    if "\r" in s or "\n" in s:
        raise ConfigError(f"account {account_name!r}: bayes_user must not contain CR or LF")
    return s


def _cfg_bool(v: Any, key: str, name: str) -> bool:
    # bool("false") is True - never coerce strings blindly.
    if isinstance(v, bool):
        return v
    if isinstance(v, int) and v in (0, 1):
        return bool(v)
    if isinstance(v, str) and v.strip().lower() in _BOOL_TRUE | _BOOL_FALSE:
        return v.strip().lower() in _BOOL_TRUE
    raise ConfigError(f"account {name!r}: {key} must be true or false")


def _cfg_int(v: Any, key: str, name: str) -> int:
    if isinstance(v, bool):
        raise ConfigError(f"account {name!r}: {key} must be an integer")
    try:
        f = float(v)
    except (TypeError, ValueError):
        raise ConfigError(f"account {name!r}: {key} must be an integer") from None
    if not math.isfinite(f) or f != int(f):
        raise ConfigError(f"account {name!r}: {key} must be an integer")
    return int(f)


def _cfg_float(v: Any, key: str, name: str) -> float:
    if isinstance(v, bool):
        raise ConfigError(f"account {name!r}: {key} must be a number")
    try:
        f = float(v)
    except (TypeError, ValueError):
        raise ConfigError(f"account {name!r}: {key} must be a number") from None
    if not math.isfinite(f):
        raise ConfigError(f"account {name!r}: {key} must be a number")
    return f


def _cfg_str_list(v: Any, key: str, name: str) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ConfigError(f"account {name!r}: {key} must be a list of strings")
    return [x.strip() for x in v if x.strip()]


def _cfg_domain_list(v: Any, key: str, name: str) -> list[str]:
    """A list of bare domains (lower-case, IDN as punycode, no '@'/'*.')."""
    out: list[str] = []
    for item in _cfg_str_list(v, key, name):
        d = _ascii_domain(str(item).strip().lstrip("*").lstrip(".").lstrip("@"))
        if d is None or not _RULE_DOMAIN_RE.match(d):
            raise ConfigError(f"account {name!r}: {key} has an invalid domain {str(item)[:60]!r}")
        if d not in out:
            out.append(d)
    return out


_EXT_RE = re.compile(r"^[a-z0-9]{1,10}$")


def _cfg_ext_list(v: Any, key: str, name: str) -> list[str]:
    """B17: a list of file extensions (lower case, leading '.'/'*.' removed)."""
    out: list[str] = []
    for item in _cfg_str_list(v, key, name):
        ext = str(item).strip().lower().lstrip("*").lstrip(".")
        if not _EXT_RE.match(ext):
            raise ConfigError(f"account {name!r}: {key} has an invalid extension {str(item)[:20]!r}")
        if ext not in out:
            out.append(ext)
    if len(out) > ATTACHMENT_BLOCK_MAX:
        raise ConfigError(f"account {name!r}: {key} may hold at most {ATTACHMENT_BLOCK_MAX} extensions")
    return out


NEWSLETTER_MODES = ("off", "shadow", "on")


def _cfg_newsletters(v: Any, key: str, name: str) -> str:
    """off | shadow | on. YAML 1.1 reads a bare on/off as a boolean."""
    if isinstance(v, bool):
        return "on" if v else "off"
    s = str(v if v is not None else "").strip().lower()
    if s not in NEWSLETTER_MODES:
        raise ConfigError(f"account {name!r}: {key} must be off, shadow or on")
    return s


def _cfg_str(v: Any, key: str, name: str) -> str:
    if v is None or isinstance(v, (dict, list, bool)):
        raise ConfigError(f"account {name!r}: {key} must be a string")
    return str(v)


def _load_raw_config(path: Path) -> dict[str, Any]:
    try:
        text = Path(path).read_text()
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path}") from None
    except OSError as ex:
        raise ConfigError(f"cannot read config file ({type(ex).__name__})") from None
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as ex:
        mark = getattr(ex, "problem_mark", None)
        where = f" at line {mark.line + 1}" if mark is not None else ""
        raise ConfigError(f"invalid YAML{where}") from None
    if not isinstance(raw, dict) or "accounts" not in raw:
        raise ConfigError("missing 'accounts' key")
    if raw["accounts"] is None:
        raw["accounts"] = []
    if not isinstance(raw["accounts"], list):
        raise ConfigError("'accounts' must be a list")
    if raw.get("defaults") is not None and not isinstance(raw.get("defaults"), dict):
        raise ConfigError("'defaults' must be a mapping")
    return raw


def _build_account(entry: dict[str, Any], defaults: dict[str, Any]) -> Account:
    merged = _deep_merge(defaults, entry)
    label = str(merged.get("name") or "?")
    missing = [k for k in REQUIRED_PER_ACCOUNT if not merged.get(k)]
    if missing:
        raise ConfigError(f"account {label!r} missing required key(s): {', '.join(missing)}")
    enabled = _cfg_bool(merged.get("enabled", True), "enabled", label)
    password_file = merged.get("password_file") or None
    inline = merged.get("password")
    if password_file and inline:
        raise ConfigError(f"account {label!r} needs exactly one of password or password_file")
    if not password_file and not inline and enabled:
        raise ConfigError(f"account {label!r} needs exactly one of password or password_file")
    if password_file is not None:
        password_file = str(password_file)
        if not Path(password_file).is_absolute():
            raise ConfigError(f"account {label!r}: password_file must be an absolute path")
    try:
        acc = Account(
            name=_cfg_str(merged["name"], "name", label),
            user=_cfg_str(merged["user"], "user", label),
            password="",
            imap_host=_cfg_str(merged["imap_host"], "imap_host", label),
            imap_port=_cfg_int(merged["imap_port"], "imap_port", label),
            ssl=_cfg_bool(merged["ssl"], "ssl", label),
            inbox=_cfg_str(merged["inbox"], "inbox", label),
            junk=_cfg_str(merged["junk"], "junk", label),
            trash=_cfg_str(merged["trash"], "trash", label),
            spam_train=_cfg_str(merged["spam_train"], "spam_train", label),
            trained_spam=_cfg_str(merged["trained_spam"], "trained_spam", label),
            ham_train=_cfg_str(merged["ham_train"], "ham_train", label),
            trained_ham=_cfg_str(merged["trained_ham"], "trained_ham", label),
            mode=_cfg_str(merged["mode"], "mode", label),
            threshold=_cfg_float(merged["threshold"], "threshold", label),
            min_threshold_allowed=_cfg_float(merged["min_threshold_allowed"], "min_threshold_allowed", label),
            reject_score_above=_cfg_float(merged["reject_score_above"], "reject_score_above", label),
            move_grace_seconds=_cfg_int(merged["move_grace_seconds"], "move_grace_seconds", label),
            learn_grace_seconds=_cfg_int(merged["learn_grace_seconds"], "learn_grace_seconds", label),
            idle_timeout=_cfg_int(merged["idle_timeout"], "idle_timeout", label),
            poll_interval=_cfg_int(merged["poll_interval"], "poll_interval", label),
            junk_poll_interval=_cfg_int(merged["junk_poll_interval"], "junk_poll_interval", label),
            retention_check_interval=_cfg_int(merged["retention_check_interval"], "retention_check_interval", label),
            max_moves_per_hour=_cfg_int(merged["max_moves_per_hour"], "max_moves_per_hour", label),
            max_learns_per_hour=_cfg_int(merged["max_learns_per_hour"], "max_learns_per_hour", label),
            max_train_per_run=_cfg_int(merged["max_train_per_run"], "max_train_per_run", label),
            safe_mode_unseen_cap=_cfg_int(merged["safe_mode_unseen_cap"], "safe_mode_unseen_cap", label),
            junk_retention_days=_cfg_int(merged["junk_retention_days"], "junk_retention_days", label),
            trained_retention_days=_cfg_int(merged["trained_retention_days"], "trained_retention_days", label),
            learn_from_moves=_cfg_bool(merged["learn_from_moves"], "learn_from_moves", label),
            auto_special_folders=_cfg_bool(merged["auto_special_folders"], "auto_special_folders", label),
            bayes_user=_clean_bayes_user(merged.get("bayes_user"), label),
            enabled=enabled,
            password_file=password_file,
            # Explicit = named in the account's own entry; SPECIAL-USE
            # autodetect may only fill in folders the entry leaves out.
            junk_explicit="junk" in entry,
            trash_explicit="trash" in entry,
            training_folders=_cfg_bool(merged["training_folders"], "training_folders", label),
            provider_bonus=_cfg_bool(merged["provider_bonus"], "provider_bonus", label),
            trusted_relays=_cfg_str_list(merged.get("trusted_relays"), "trusted_relays", label),
            trusted_relay_domains=_cfg_str_list(
                merged.get("trusted_relay_domains"), "trusted_relay_domains", label),
            secret_inline=str(inline) if inline else "",
            move_grace_seconds_high=_cfg_int(merged["move_grace_seconds_high"],
                                             "move_grace_seconds_high", label),
            fast_move_margin=_cfg_float(merged["fast_move_margin"], "fast_move_margin", label),
            circuit_max_moves_per_hour=_cfg_int(merged["circuit_max_moves_per_hour"],
                                                "circuit_max_moves_per_hour", label),
            circuit_max_ratio=_cfg_float(merged["circuit_max_ratio"], "circuit_max_ratio", label),
            circuit_min_moves=_cfg_int(merged["circuit_min_moves"], "circuit_min_moves", label),
            autolearn=_cfg_bool(merged["autolearn"], "autolearn", label),
            autolearn_daily_cap=_cfg_int(merged["autolearn_daily_cap"], "autolearn_daily_cap", label),
            trusted_forwarders=_cfg_str_list(merged.get("trusted_forwarders"), "trusted_forwarders", label),
            protected_recipients=[a.lower() for a in _cfg_str_list(
                merged.get("protected_recipients"), "protected_recipients", label)],
            protected_threshold=_cfg_float(merged["protected_threshold"], "protected_threshold", label),
            daily_report=_cfg_bool(merged["daily_report"], "daily_report", label),
            auto_block_repeated_spam=_cfg_bool(merged["auto_block_repeated_spam"], "auto_block_repeated_spam", label),
            auto_allow_on_rescue=_cfg_bool(merged["auto_allow_on_rescue"], "auto_allow_on_rescue", label),
            report_hour=_cfg_int(merged["report_hour"], "report_hour", label),
            owner_platform_domains=_cfg_domain_list(
                merged.get("owner_platform_domains"), "owner_platform_domains", label),
            webshop_domains=_cfg_domain_list(merged.get("webshop_domains"), "webshop_domains", label),
            aged_scan_hours=_cfg_float(merged.get("aged_scan_hours", 6.0), "aged_scan_hours", label),
            known_contacts=_cfg_bool(merged.get("known_contacts", True), "known_contacts", label),
            known_contact_score=_cfg_float(merged.get("known_contact_score", -4.0),
                                           "known_contact_score", label),
            sent_folders=_cfg_str_list(merged.get("sent_folders"), "sent_folders", label),
            contact_group=(_cfg_str(merged["contact_group"], "contact_group", label).strip().lower() or None)
            if merged.get("contact_group") not in (None, "") else None,
            zap=_cfg_bool(merged.get("zap", True), "zap", label),
            # absent = the default list; an explicit empty list / null = block nothing.
            attachment_block=_cfg_ext_list(merged.get("attachment_block", DEFAULT_ATTACHMENT_BLOCK),
                                           "attachment_block", label),
            threat_notice=_cfg_bool(merged.get("threat_notice", True), "threat_notice", label),
            protected_domains=_cfg_domain_list(merged.get("protected_domains", DEFAULT_PROTECTED_DOMAINS),
                                               "protected_domains", label),
            newsletters=_cfg_newsletters(merged.get("newsletters", "shadow"), "newsletters", label),
            newsletter_folder=_cfg_str(merged.get("newsletter_folder", "Nyhedsbreve"), "newsletter_folder",
                                       label).strip(),
        )
    except KeyError as ex:
        raise ConfigError(f"account {label!r}: missing config key {ex.args[0]!r}") from None
    validate_account(acc)
    return acc


def _parse_config(path: Path) -> list[Account]:
    raw = _load_raw_config(path)
    # Built-ins, then user defaults, then env overrides.
    defaults = _apply_env_overrides(_deep_merge(BUILTIN_DEFAULTS, raw.get("defaults") or {}))
    out: list[Account] = []
    seen: set[str] = set()
    for entry in raw["accounts"]:
        if not isinstance(entry, dict):
            raise ConfigError("each account must be a mapping")
        acc = _build_account(entry, defaults)
        if acc.name in seen:
            raise ConfigError(f"duplicate account name: {acc.name}")
        seen.add(acc.name)
        out.append(acc)
    return out


def load_account_configs(path: Path | None = None) -> list[Account]:
    """ALL accounts (incl. disabled) with effective merged values. Never
    reads secret files (password == ""); see read_secret(). Raises
    ConfigError (a ValueError) instead of exiting."""
    return _parse_config(Path(path) if path is not None else CONFIG_PATH)


def read_secret(acc: Account) -> str:
    """The account's IMAP password (password_file or inline). ValueError
    with a short, secret-free text when it cannot be read."""
    if acc.password_file:
        p = Path(acc.password_file)
        if not p.is_absolute():
            raise ConfigError(f"account {acc.name!r}: password_file must be an absolute path")
        try:
            secret = p.read_text().rstrip("\r\n")
        except OSError as ex:
            raise ConfigError(
                f"cannot read password_file for {acc.name!r}: {type(ex).__name__}") from None
        if not secret:
            raise ConfigError(f"empty password_file for {acc.name!r}")
        return secret
    if acc.password:
        return acc.password
    if acc.secret_inline:
        return acc.secret_inline
    raise ConfigError(f"account {acc.name!r} has no password configured")


def load_accounts(path: Path) -> list[Account]:
    """Enabled accounts with secrets read. SystemExit on invalid config
    (1.x behaviour, used by CLI tools)."""
    try:
        accounts = [a for a in _parse_config(path) if a.enabled]
        for acc in accounts:
            acc.password = read_secret(acc)
    except ValueError as ex:
        raise SystemExit(f"{path}: {ex}") from None
    return accounts


def _secret_mtime(acc: Account) -> int | None:
    if not acc.password_file:
        return None
    try:
        return os.stat(acc.password_file).st_mtime_ns
    except OSError:
        return None


def _check_folder_name(acc: Account, key: str) -> None:
    val = getattr(acc, key)
    if not val or len(val) > 200 or any(c in val for c in "\r\n\x00"):
        raise ConfigError(f"{acc.name}: invalid folder name for {key}")


def validate_account(acc: Account) -> None:
    """Raise ConfigError (ValueError) for an invalid account."""
    if acc.mode not in VALID_MODES:
        raise ConfigError(f"{acc.name}: invalid mode {acc.mode!r}")
    # acc.user is the Bayes identity fallback and ends up in a Delivered-To
    # header we inject into the rspamd /learn body. Reject CR/LF so an
    # operator who pastes a multi-line value cannot smuggle headers.
    for field_name in ("user", "name", "imap_host"):
        val = str(getattr(acc, field_name))
        if "\r" in val or "\n" in val:
            raise ConfigError(f"{acc.name}: account {field_name} must not contain CR or LF")
    if not 1 <= acc.imap_port <= 65535:
        raise ConfigError(f"{acc.name}: imap_port out of range ({acc.imap_port})")
    if acc.min_threshold_allowed <= 0:
        raise ConfigError(
            f"{acc.name}: min_threshold_allowed must be positive ({acc.min_threshold_allowed})")
    if acc.threshold < acc.min_threshold_allowed:
        raise ConfigError(
            f"{acc.name}: threshold {acc.threshold} below min_threshold_allowed "
            f"{acc.min_threshold_allowed}")
    if acc.reject_score_above < acc.threshold:
        raise ConfigError(
            f"{acc.name}: reject_score_above {acc.reject_score_above} must be "
            f">= threshold {acc.threshold}")
    for key in ("inbox", "junk", "trash", *TRAIN_KEYS):
        _check_folder_name(acc, key)
    folder_set = {acc.inbox, acc.junk, acc.trash, acc.spam_train, acc.trained_spam,
                  acc.ham_train, acc.trained_ham}
    if len(folder_set) != 7:
        raise ConfigError(
            f"{acc.name}: inbox/junk/trash/spam_train/trained_spam/ham_train/"
            f"trained_ham must all be distinct")
    if acc.inbox.upper() == acc.junk.upper():
        raise ConfigError(f"{acc.name}: junk must differ from inbox")
    if not 1 <= acc.max_moves_per_hour <= 1000:
        raise ConfigError(f"{acc.name}: max_moves_per_hour out of range")
    if not 1 <= acc.max_learns_per_hour <= 1000:
        raise ConfigError(f"{acc.name}: max_learns_per_hour out of range")
    if not 1 <= acc.max_train_per_run <= 5000:
        raise ConfigError(f"{acc.name}: max_train_per_run out of range")
    if acc.safe_mode_unseen_cap < 1:
        raise ConfigError(f"{acc.name}: safe_mode_unseen_cap must be >= 1 ({acc.safe_mode_unseen_cap})")
    if acc.poll_interval < 30:
        raise ConfigError(f"{acc.name}: poll_interval must be >= 30 seconds")
    if acc.junk_poll_interval < 30:
        raise ConfigError(f"{acc.name}: junk_poll_interval must be >= 30 seconds")
    if not 60 <= acc.idle_timeout <= 1740:
        raise ConfigError(f"{acc.name}: idle_timeout must be 60..1740 seconds")
    if acc.learn_grace_seconds < 0 or acc.move_grace_seconds < 0:
        raise ConfigError(f"{acc.name}: grace values must be >= 0")
    if acc.junk_retention_days < 0 or acc.trained_retention_days < 0:
        raise ConfigError(f"{acc.name}: retention days must be >= 0")
    if acc.bayes_user is not None and ("\r" in acc.bayes_user or "\n" in acc.bayes_user):
        raise ConfigError(f"{acc.name}: bayes_user must not contain CR or LF")
    for key in ("training_folders", "provider_bonus", "enabled", "learn_from_moves",
                "auto_special_folders", "ssl"):
        if not isinstance(getattr(acc, key), bool):
            raise ConfigError(f"{acc.name}: {key} must be true or false")
    if not isinstance(acc.trusted_relays, list) or not isinstance(acc.trusted_relay_domains, list):
        raise ConfigError(f"{acc.name}: trusted_relays/trusted_relay_domains must be lists")
    for cidr in acc.trusted_relays:
        try:
            ipaddress.ip_network(str(cidr), strict=False)
        except ValueError:
            raise ConfigError(f"{acc.name}: invalid trusted_relays entry {cidr!r}") from None
    for dom in acc.trusted_relay_domains:
        if not _RELAY_DOMAIN_RE.match(str(dom).lower()) or len(str(dom)) > 253:
            raise ConfigError(f"{acc.name}: invalid trusted_relay_domains entry {dom!r}")
    # 2.1
    if not 0 <= acc.move_grace_seconds_high <= 86400:
        raise ConfigError(f"{acc.name}: move_grace_seconds_high must be 0..86400")
    if not 0.0 <= acc.fast_move_margin <= 100.0:
        raise ConfigError(f"{acc.name}: fast_move_margin must be 0..100")
    if not 1 <= acc.circuit_max_moves_per_hour <= 1000:
        raise ConfigError(f"{acc.name}: circuit_max_moves_per_hour must be 1..1000")
    if not 0.0 < acc.circuit_max_ratio <= 1.0:
        raise ConfigError(f"{acc.name}: circuit_max_ratio must be > 0 and <= 1")
    if not 1 <= acc.circuit_min_moves <= 1000:
        raise ConfigError(f"{acc.name}: circuit_min_moves must be 1..1000")
    if not 0 <= acc.autolearn_daily_cap <= 1000:
        raise ConfigError(f"{acc.name}: autolearn_daily_cap must be 0..1000")
    if not 0 <= acc.report_hour <= 23:
        raise ConfigError(f"{acc.name}: report_hour must be 0..23")
    if acc.protected_threshold < acc.min_threshold_allowed:
        raise ConfigError(f"{acc.name}: protected_threshold below min_threshold_allowed")
    for key in ("autolearn", "daily_report", "auto_allow_on_rescue", "auto_block_repeated_spam"):
        if not isinstance(getattr(acc, key), bool):
            raise ConfigError(f"{acc.name}: {key} must be true or false")
    for key in ("trusted_forwarders", "protected_recipients"):
        if not isinstance(getattr(acc, key), list):
            raise ConfigError(f"{acc.name}: {key} must be a list")
    # 2.2
    if not 0.0 <= float(acc.aged_scan_hours) <= 24 * 365:
        raise ConfigError(f"{acc.name}: aged_scan_hours must be 0..8760 (0 = off)")
    for key in ("owner_platform_domains", "webshop_domains"):
        if not isinstance(getattr(acc, key), list):
            raise ConfigError(f"{acc.name}: {key} must be a list")
    # 2.3
    if not isinstance(acc.known_contacts, bool):
        raise ConfigError(f"{acc.name}: known_contacts must be true or false")
    if not -6.0 <= float(acc.known_contact_score) <= -1.0:
        raise ConfigError(f"{acc.name}: known_contact_score must be -6..-1")
    if not isinstance(acc.sent_folders, list) or len(acc.sent_folders) > 10:
        raise ConfigError(f"{acc.name}: sent_folders must be a list of at most 10 folder names")
    for name in acc.sent_folders:
        if not name or len(name) > 200 or any(c in name for c in "\r\n\x00"):
            raise ConfigError(f"{acc.name}: invalid folder name in sent_folders")
    if acc.contact_group is not None and not _CONTACT_GROUP_RE.match(acc.contact_group):
        raise ConfigError(f"{acc.name}: contact_group must be a short name or domain (a-z, 0-9, . and -)")
    if not isinstance(acc.zap, bool):
        raise ConfigError(f"{acc.name}: zap must be true or false")
    if (not isinstance(acc.attachment_block, list) or len(acc.attachment_block) > ATTACHMENT_BLOCK_MAX
            or not all(isinstance(e, str) and _EXT_RE.match(e) for e in acc.attachment_block)):
        raise ConfigError(f"{acc.name}: attachment_block must be a list of file extensions (a-z, 0-9)")
    if not isinstance(acc.protected_domains, list) or len(acc.protected_domains) > PROTECTED_DOMAINS_MAX:
        raise ConfigError(f"{acc.name}: protected_domains must be a list of at most "
                          f"{PROTECTED_DOMAINS_MAX} domains")
    for fwd in acc.trusted_forwarders:
        if not _forwarder_entry_valid(fwd):
            raise ConfigError(f"{acc.name}: invalid trusted_forwarders entry {fwd!r}")
    for addr in acc.protected_recipients:
        if not _PROTECTED_ADDR_RE.match(str(addr)):
            raise ConfigError(f"{acc.name}: invalid protected_recipients entry {addr!r}")
    # 2.6 (A4): the newsletter folder must never be a folder the filter
    # treats as inbox, spam, trash or training folder.
    if acc.newsletters not in NEWSLETTER_MODES:
        raise ConfigError(f"{acc.name}: newsletters must be off, shadow or on")
    _check_folder_name(acc, "newsletter_folder")
    if acc.newsletter_folder.lower() in {f.lower() for f in folder_set} or acc.newsletter_folder.upper() == "INBOX":
        raise ConfigError(f"{acc.name}: newsletter_folder must differ from inbox/junk/trash and the "
                          f"training folders")


_CONTACT_GROUP_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,99}$")
_PROTECTED_ADDR_RE = re.compile(r"^[a-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}@[a-z0-9-]+(\.[a-z0-9-]+)+$")


def _forwarder_entry_valid(entry: Any) -> bool:
    """A trusted forwarder is an IP/narrow CIDR, a host name or '*.domain'."""
    s = str(entry or "").strip().lower()
    if not s or len(s) > 253:
        return False
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        pass
    else:
        # Everything a trusted forwarder writes is trusted (the walk goes
        # past it), so a wide network would trust forged hops: at most a
        # /24 (IPv4) or /48 (IPv6).
        return net.prefixlen >= (24 if net.version == 4 else 48)
    if s.startswith("*."):
        s = s[2:]
    return bool(_RELAY_DOMAIN_RE.match(s)) and not s.startswith(".") and "." in s


# ---------------------------------------------------------------------------
# SQLite
# ---------------------------------------------------------------------------

# A7: additive only. Tables are created with their 2.0 columns; databases
# from 1.x get the new columns via _migrate() (ADD COLUMN), never a rebuild.
SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    account            TEXT NOT NULL,
    message_id         TEXT NOT NULL,
    first_seen         INTEGER NOT NULL,
    last_seen          INTEGER NOT NULL,
    current_folder     TEXT NOT NULL,
    moved_to_junk_at   INTEGER,
    our_score          REAL,         -- final score (rspamd + provider bonus)
    our_action         TEXT,
    learned_as         TEXT,
    learned_at         INTEGER,
    pending_learn      TEXT,         -- 'spam' | 'ham' | NULL
    pending_learn_at   INTEGER,
    sender             TEXT,
    subject            TEXT,
    received_at        INTEGER,      -- IMAP INTERNALDATE (unix); NULL if unknown
    rspamd_score       REAL,
    symbols            TEXT,         -- JSON [{"n","s","o"}], top 30
    rspamd_action      TEXT,
    sender_ip          TEXT,
    envelope_from      TEXT,
    provider_score     REAL,
    provider_flag      INTEGER,
    user_verdict       TEXT,         -- 'ham' | 'spam' | NULL (sticky)
    verdict_at         INTEGER,
    verdict_by         TEXT,
    rule_hit           TEXT,         -- 'allow:<id>' | 'block:<id>' | NULL
    size               INTEGER,
    scanned_at         INTEGER,
    origin             TEXT,         -- 'inbox_scan' | 'junk_poll' | 'manual'
    score_version      INTEGER,
    PRIMARY KEY (account, message_id)
);

CREATE TABLE IF NOT EXISTS uidvalidity (
    account     TEXT NOT NULL,
    folder      TEXT NOT NULL,
    uidvalidity INTEGER NOT NULL,
    PRIMARY KEY (account, folder)
);

CREATE TABLE IF NOT EXISTS pending_move (
    account     TEXT NOT NULL,
    uidvalidity INTEGER NOT NULL,
    uid         INTEGER NOT NULL,
    message_id  TEXT NOT NULL,
    flag_at     INTEGER NOT NULL,
    folder      TEXT,
    PRIMARY KEY (account, uidvalidity, uid)
);

-- High-water UID per (account, folder, uidvalidity): scan_inbox only looks
-- at UIDs above it, so pre-existing mail is never scored or acted on.
CREATE TABLE IF NOT EXISTS scan_bookmark (
    account     TEXT NOT NULL,
    folder      TEXT NOT NULL,
    uidvalidity INTEGER NOT NULL,
    max_uid     INTEGER NOT NULL,
    PRIMARY KEY (account, folder, uidvalidity)
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account     TEXT NOT NULL,
    ts          INTEGER NOT NULL,
    message_id  TEXT,
    event       TEXT NOT NULL,
    detail      TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(account, ts);

CREATE TABLE IF NOT EXISTS rate_limit (
    account TEXT NOT NULL,
    action  TEXT NOT NULL,
    ts      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_limit ON rate_limit(account, action, ts);

CREATE TABLE IF NOT EXISTS safe_mode (
    account     TEXT NOT NULL,
    scope       TEXT NOT NULL,
    entered_at  INTEGER NOT NULL,
    reason      TEXT NOT NULL,
    PRIMARY KEY (account, scope)
);

CREATE TABLE IF NOT EXISTS account_status (
    account          TEXT PRIMARY KEY,
    updated_at       INTEGER NOT NULL,
    state            TEXT NOT NULL,
    detail           TEXT,
    connected_since  INTEGER,
    last_loop_at     INTEGER,
    last_scan_at     INTEGER,
    last_error       TEXT,
    last_error_at    INTEGER,
    error_count      INTEGER NOT NULL DEFAULT 0,
    capabilities     TEXT,
    move_method      TEXT,
    idle_supported   INTEGER,
    folders          TEXT,
    folder_map       TEXT,
    junk_exists      INTEGER,
    mode             TEXT,
    threshold        REAL,
    bookmark_lag     INTEGER,
    pending_moves    INTEGER
);

CREATE TABLE IF NOT EXISTS sender_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account     TEXT NOT NULL DEFAULT '*',
    pattern     TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK(kind IN ('allow','block')),
    note        TEXT,
    created_by  TEXT,
    created_at  INTEGER NOT NULL,
    hits        INTEGER NOT NULL DEFAULT 0,
    last_hit_at INTEGER,
    force       INTEGER NOT NULL DEFAULT 0,  -- 2.0.3: allow rule 'Altid igennem'
    UNIQUE(account, pattern)
);

CREATE TABLE IF NOT EXISTS stats_daily (
    account TEXT NOT NULL,
    day     TEXT NOT NULL,
    metric  TEXT NOT NULL,
    n       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (account, day, metric)
);

CREATE TABLE IF NOT EXISTS train_jobs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    account         TEXT NOT NULL,
    folder          TEXT NOT NULL,
    kind            TEXT NOT NULL CHECK(kind IN ('spam','ham','calibrate')),
    max_messages    INTEGER NOT NULL,
    min_age_days    INTEGER NOT NULL DEFAULT 0,
    seen_only       INTEGER NOT NULL DEFAULT 0,
    provider_filter TEXT NOT NULL DEFAULT 'any',
    status          TEXT NOT NULL DEFAULT 'queued',
    total           INTEGER NOT NULL DEFAULT 0,
    processed       INTEGER NOT NULL DEFAULT 0,
    learned         INTEGER NOT NULL DEFAULT 0,
    skipped         INTEGER NOT NULL DEFAULT 0,
    failed          INTEGER NOT NULL DEFAULT 0,
    error           TEXT,
    created_by      TEXT,
    created_at      INTEGER NOT NULL,
    started_at      INTEGER,
    finished_at     INTEGER
);

CREATE TABLE IF NOT EXISTS calibration_results (
    job_id          INTEGER NOT NULL,
    account         TEXT NOT NULL,
    folder          TEXT NOT NULL,
    message_id      TEXT NOT NULL,
    final_score     REAL,
    rspamd_score    REAL,
    symbols         TEXT,
    sender          TEXT,
    subject         TEXT,
    received_at     INTEGER,
    seen            INTEGER,
    provider_flag   INTEGER,
    provider_score  REAL,
    PRIMARY KEY (job_id, account, folder, message_id)
);

CREATE TABLE IF NOT EXISTS scan_retry (
    account        TEXT NOT NULL,
    uidvalidity    INTEGER NOT NULL,
    uid            INTEGER NOT NULL,
    attempts       INTEGER NOT NULL DEFAULT 0,
    first_fail_at  INTEGER NOT NULL,
    last_error     TEXT,
    PRIMARY KEY (account, uidvalidity, uid)
);

CREATE TABLE IF NOT EXISTS junk_bookmark (
    account     TEXT NOT NULL,
    folder      TEXT NOT NULL,
    uidvalidity INTEGER NOT NULL,
    max_uid     INTEGER NOT NULL,
    PRIMARY KEY (account, folder, uidvalidity)
);

-- 2.1 (all new tables; older versions simply ignore them) --------------

-- E1: move circuit breaker. A row with state='open' pauses moving for the
-- account until an admin resumes it (resume_moves).
CREATE TABLE IF NOT EXISTS move_circuit (
    account     TEXT PRIMARY KEY,
    state       TEXT NOT NULL,          -- 'open' | 'closed'
    reason      TEXT,
    opened_at   INTEGER,
    resumed_at  INTEGER,
    resumed_by  TEXT
);

-- Engine key/value (e.g. 'version_started:<VERSION>' for the update hold).
CREATE TABLE IF NOT EXISTS engine_state (
    key         TEXT PRIMARY KEY,
    value       TEXT,
    updated_at  INTEGER NOT NULL
);

-- E5: write-ahead journal of a filter move, so a move interrupted between
-- COPY / STORE Deleted-flag / UID EXPUNGE is completed exactly on reconnect.
CREATE TABLE IF NOT EXISTS move_journal (
    account      TEXT NOT NULL,
    folder       TEXT NOT NULL,
    uidvalidity  INTEGER NOT NULL,
    uid          INTEGER NOT NULL,
    message_id   TEXT NOT NULL,
    dest         TEXT NOT NULL,
    stage        TEXT NOT NULL,         -- move|copy|copied|flag
    internaldate INTEGER,
    predeleted   INTEGER NOT NULL DEFAULT 0,
    attempts     INTEGER NOT NULL DEFAULT 0,
    started_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    PRIMARY KEY (account, folder, uidvalidity, uid)
);

-- E6: every automatic learn, so it can be explained and reverted.
CREATE TABLE IF NOT EXISTS autolearn_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    account      TEXT NOT NULL,
    message_id   TEXT NOT NULL,
    kind         TEXT NOT NULL,         -- 'spam' | 'ham'
    score        REAL,
    outcome      TEXT NOT NULL,         -- learned|already|declined|error|lost|rate_limited
    created_at   INTEGER NOT NULL,
    reverted_at  INTEGER,
    reverted_by  TEXT,
    UNIQUE(account, message_id, kind)
);

-- E12: receipts appended to an INBOX (the scanner skips exactly these).
CREATE TABLE IF NOT EXISTS daily_receipts (
    account     TEXT NOT NULL,
    message_id  TEXT NOT NULL,
    day         TEXT NOT NULL,          -- weekly reports: ISO week 'YYYY-Www'
    kind        TEXT NOT NULL,          -- 'daily' | 'preview' | 'weekly' | 'weekly_preview'
    items       INTEGER NOT NULL DEFAULT 0,
    sent_at     INTEGER NOT NULL,
    sent_by     TEXT,
    PRIMARY KEY (account, message_id)
);

-- 2.2 (all new tables; older versions simply ignore them) --------------

-- B6: the Bayes class every learned message ended up in, also for mail
-- without a messages row (training jobs learn whole folders) and beyond
-- the 30-day events window. Feeds services.bayes_repair_candidates.
CREATE TABLE IF NOT EXISTS learn_ledger (
    account     TEXT NOT NULL,
    message_id  TEXT NOT NULL,
    kind        TEXT NOT NULL,          -- 'spam' | 'ham'
    learned_at  INTEGER NOT NULL,
    source      TEXT,                   -- learn reason (e.g. 'bootstrap job=22', 'autolearn')
    PRIMARY KEY (account, message_id)
);

-- 2.3 (all new tables; older versions simply ignore them) --------------

-- B19 (ZAP): inbox mail that is rescanned later (+45 min, +4 h, +24 h) in
-- case a blocklist catches up. first_symbols = symbol names of the first
-- scan (a NEW reputation/threat symbol is required to act).
CREATE TABLE IF NOT EXISTS rescan_queue (
    account        TEXT NOT NULL,
    message_id     TEXT NOT NULL,
    folder         TEXT NOT NULL,
    uidvalidity    INTEGER,
    uid            INTEGER,
    first_score    REAL,
    attempt        INTEGER NOT NULL DEFAULT 0,
    due_at         INTEGER NOT NULL,
    queued_at      INTEGER NOT NULL,
    first_symbols  TEXT,
    last_score     REAL,
    last_at        INTEGER,
    PRIMARY KEY (account, message_id)
);
CREATE INDEX IF NOT EXISTS idx_rescan_due ON rescan_queue(account, due_at);

-- 2.7 fix: antivirus re-scans. A mail with attachments scanned while ClamAV
-- did not answer (CLAM_VIRUS_FAIL) is scanned again by UID (+10 min, +1 h,
-- +6 h) - independent of zap and its exclusions; only a new CLAM_VIRUS
-- (threat class virus) acts. Additive: older images ignore the table.
CREATE TABLE IF NOT EXISTS av_rescan_queue (
    account        TEXT NOT NULL,
    folder         TEXT NOT NULL,
    uidvalidity    INTEGER NOT NULL,
    uid            INTEGER NOT NULL,
    message_id     TEXT NOT NULL,
    attempt        INTEGER NOT NULL DEFAULT 0,
    due_at         INTEGER NOT NULL,
    queued_at      INTEGER NOT NULL,
    PRIMARY KEY (account, uidvalidity, uid)
);
CREATE INDEX IF NOT EXISTS idx_av_rescan_due ON av_rescan_queue(account, due_at);

-- B17: per-sender exception 'Tillad farlige vedhæftninger fra denne
-- afsender' (admin only). Its own table: sender_rules.kind has a CHECK
-- constraint (allow|block) that cannot be extended additively.
CREATE TABLE IF NOT EXISTS attach_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account     TEXT NOT NULL DEFAULT '*',
    pattern     TEXT NOT NULL,
    note        TEXT,
    created_by  TEXT,
    created_at  INTEGER NOT NULL,
    hits        INTEGER NOT NULL DEFAULT 0,
    last_hit_at INTEGER,
    UNIQUE(account, pattern)
);

-- 2.3 round 2 (all new tables; 2.2.0 and 2.3.0 simply ignore them) -----

-- Straks-advarsel: threat mail the filter moved away. A row is created at
-- scan time (sender display name) and queued when the move ran; notices
-- are appended to the INBOX at most once per 30 min per mailbox.
CREATE TABLE IF NOT EXISTS threat_notices (
    account      TEXT NOT NULL,
    message_id   TEXT NOT NULL,
    threat       TEXT NOT NULL,
    sender_name  TEXT,
    created_at   INTEGER NOT NULL,
    queued_at    INTEGER,               -- set when the move to the filter folder ran
    notice_id    TEXT,                  -- Message-ID of the notice that listed it
    sent_at      INTEGER,
    alerted_at   INTEGER,               -- admin alert handled (queued, or SMTP not set up)
    PRIMARY KEY (account, message_id)
);
CREATE INDEX IF NOT EXISTS idx_threat_notices_due ON threat_notices(account, sent_at, queued_at);
"""

# 'Byg Bayes op på ny' (services.bayes_rebuild_*): the rebuild history, the
# trainer jobs that belong to a rebuild, and the per-pool learned state
# (messages.learned_as, learn_ledger, autolearn_log) archived when every
# account switches to another Bayes pool. Same DDL as services.BAYES_REBUILD_DDL
# (test-enforced) so the services also work against an older engine.
BAYES_REBUILD_SCHEMA = """
CREATE TABLE IF NOT EXISTS bayes_rebuilds (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    status         TEXT NOT NULL,       -- starting|running|done|failed|restored
    pool_old       TEXT NOT NULL,
    pool_new       TEXT NOT NULL,
    ratio          REAL NOT NULL,       -- ham per spam (2.0 = 1:2)
    config_before  TEXT,                -- JSON: bayes_user keys before the switch
    accounts       TEXT,                -- JSON: {account: identity before}
    plan           TEXT,                -- JSON: the plan shown to the owner
    expected_spam  INTEGER,
    expected_ham   INTEGER,
    learned_spam   INTEGER,
    learned_ham    INTEGER,
    archived       INTEGER,
    stat_spam_start INTEGER,            -- rspamd /stat totals at the switch
    stat_ham_start  INTEGER,
    stat_spam_restore INTEGER,          -- ... and at 'Gendan tidligere Bayes'
    stat_ham_restore  INTEGER,
    created_by     TEXT,
    created_at     INTEGER NOT NULL,
    finished_at    INTEGER,
    restored_by    TEXT,
    restored_at    INTEGER,
    note           TEXT
);
CREATE TABLE IF NOT EXISTS bayes_rebuild_jobs (
    rebuild_id  INTEGER NOT NULL,
    job_type    TEXT NOT NULL,          -- 'train' (train_jobs) | 'list' (learn_list_jobs)
    job_id      INTEGER NOT NULL,
    role        TEXT NOT NULL,          -- 'spam' | 'ham'
    account     TEXT,
    folder      TEXT,
    planned     INTEGER,
    PRIMARY KEY (job_type, job_id)
);
CREATE TABLE IF NOT EXISTS bayes_pool_archive (
    pool        TEXT NOT NULL,
    src         TEXT NOT NULL,          -- 'messages' | 'ledger' | 'autolearn'
    account     TEXT NOT NULL,
    message_id  TEXT NOT NULL,
    kind        TEXT NOT NULL,
    learned_at  INTEGER,
    extra       TEXT,                   -- ledger source / autolearn row (JSON)
    archived_at INTEGER NOT NULL,
    PRIMARY KEY (pool, src, account, message_id, kind)
);
CREATE INDEX IF NOT EXISTS idx_pool_archive_msg ON bayes_pool_archive(account, message_id);
"""
SCHEMA += BAYES_REBUILD_SCHEMA

# Indexes that reference columns added by _migrate() must be created after it.
SCHEMA_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_events_msg ON events(account, message_id);
CREATE INDEX IF NOT EXISTS idx_messages_last_seen ON messages(account, last_seen);
CREATE INDEX IF NOT EXISTS idx_messages_action ON messages(account, our_action);
CREATE INDEX IF NOT EXISTS idx_messages_folder ON messages(account, current_folder);
CREATE INDEX IF NOT EXISTS idx_messages_scanned ON messages(account, scanned_at);
CREATE INDEX IF NOT EXISTS idx_messages_verdict ON messages(account, user_verdict, verdict_at);
CREATE INDEX IF NOT EXISTS idx_stats_daily_day ON stats_daily(day, metric);
CREATE INDEX IF NOT EXISTS idx_train_jobs_status ON train_jobs(status, created_at);
CREATE INDEX IF NOT EXISTS idx_daily_receipts_day ON daily_receipts(account, day, kind);
CREATE INDEX IF NOT EXISTS idx_autolearn_time ON autolearn_log(account, created_at);
"""

_ADDITIVE_COLUMNS: dict[str, tuple[tuple[str, str], ...]] = {
    "messages": (
        ("received_at", "INTEGER"), ("rspamd_score", "REAL"), ("symbols", "TEXT"),
        ("rspamd_action", "TEXT"), ("sender_ip", "TEXT"), ("envelope_from", "TEXT"),
        ("provider_score", "REAL"), ("provider_flag", "INTEGER"),
        ("user_verdict", "TEXT"), ("verdict_at", "INTEGER"), ("verdict_by", "TEXT"),
        ("rule_hit", "TEXT"), ("size", "INTEGER"), ("scanned_at", "INTEGER"),
        ("origin", "TEXT"), ("score_version", "INTEGER"),
        # 2.1: sender authentication evidence {"dkim":[..],"host":..} (E8).
        ("sender_auth", "TEXT"),
        # 2.2 (B7): 1 = scanned late (aged mode), 0 = fresh, NULL = before 2.2.
        ("aged", "INTEGER"),
        # 2.3 (B16): threat class ('virus'|'phish'|'malware_url'|'attachment';
        # later 'impersonation'|'lookalike') + its detail (signature, file
        # name, rule); NULL = no threat / before 2.3. B19: when a rescan
        # (ZAP) moved or flagged the mail.
        ("threat", "TEXT"), ("threat_detail", "TEXT"), ("zapped_at", "INTEGER"),
        ("decision_names", "TEXT"),
    ),
    "pending_move": (("folder", "TEXT"),
                     # 2.1: due time (E2 fast moves) + score/threshold (update hold).
                     ("due_at", "INTEGER"), ("score", "REAL"), ("threshold", "REAL"),
                     # 2.3 (B19): 'zap' for a move decided by a rescan; NULL = scan.
                     ("origin", "TEXT")),
    "account_status": (
        # 2.1 (E1/E4/E11): liveness, circuit and login state for monitoring.
        ("alive_at", "INTEGER"), ("moves_today", "INTEGER"), ("move_state", "TEXT"),
        ("move_state_reason", "TEXT"), ("move_state_at", "INTEGER"),
        ("login_state", "TEXT"), ("retry_at", "INTEGER"),
    ),
    # 2.0.3: 'Altid igennem' allow rules. Old rows (and rows written by a
    # rolled-back 2.0.2, which never names the column) are normal rules.
    "sender_rules": (("force", "INTEGER NOT NULL DEFAULT 0"),),
}


def init_db() -> None:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    try:
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
        conn.executescript(mailidentity.SCHEMA)
        conn.executescript(quality.SCHEMA)
        conn.execute(holdout.SCHEMA)
        conn.executescript(decisiontrace.SCHEMA)
        conn.executescript(policytrial.SCHEMA)
        _migrate(conn)
        conn.executescript(SCHEMA_INDEXES)
        try:
            # 2.3 (B10-B12): additive contact tables (contacts.SCHEMA).
            _contacts().ensure_schema(conn)
        except Exception as ex:  # noqa: BLE001 - never block the engine start
            logging.getLogger("filter").error("contact tables not created: %s", type(ex).__name__)
        try:
            # B22: lookalike_watch + lookalike_allow (lookalike.SCHEMA).
            _lookalike().ensure_schema(conn)
        except Exception as ex:  # noqa: BLE001 - never block the engine start
            logging.getLogger("filter").error("lookalike tables not created: %s", type(ex).__name__)
        try:
            # 2.6 (A2/A3): campaign_queue + block_suggestion_dismissed.
            _campaigns().ensure_schema(conn)
        except Exception as ex:  # noqa: BLE001 - never block the engine start
            logging.getLogger("filter").error("campaign tables not created: %s", type(ex).__name__)
        try:
            # 2.6 (A4): newsletter_pending + newsletter_keep (newsletters.SCHEMA).
            _newsletters().ensure_schema(conn)
        except Exception as ex:  # noqa: BLE001 - never block the engine start
            logging.getLogger("filter").error("newsletter tables not created: %s", type(ex).__name__)
        try:
            # 2.7: ai_verdicts (ai_verdict.SCHEMA, local AI second opinion).
            _ai().ensure_schema(conn)
        except Exception as ex:  # noqa: BLE001 - never block the engine start
            logging.getLogger("filter").error("ai tables not created: %s", type(ex).__name__)
        try:
            # 2.7: namespoof_names + namespoof_seed_seen (namespoof.SCHEMA).
            _namespoof().ensure_schema(conn)
        except Exception as ex:  # noqa: BLE001 - never block the engine start
            logging.getLogger("filter").error("namespoof tables not created: %s", type(ex).__name__)
        try:
            # 2.12 (#8/#9): junk_sender_moves + junk_sender_notes (junkrules.SCHEMA_STATEMENTS).
            _junkrules().ensure_schema(conn)
        except Exception as ex:  # noqa: BLE001 - never block the engine start
            logging.getLogger("filter").error("junk rule tables not created: %s", type(ex).__name__)
        conn.commit()
    finally:
        conn.close()


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns introduced after the original schema. CREATE TABLE IF
    NOT EXISTS never alters an existing table, so new columns need an
    explicit ADD COLUMN on databases created before they were added."""
    for table, columns in _ADDITIVE_COLUMNS.items():
        have = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        for name, coltype in columns:
            if name not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {coltype}")


@contextmanager
def _autocommit(conn: sqlite3.Connection) -> Iterator[None]:
    """Commit statements run inside unless the caller already holds an open
    transaction (then the caller owns commit/rollback)."""
    was_in_tx = conn.in_transaction
    try:
        yield
    except Exception:
        if not was_in_tx and conn.in_transaction:
            conn.rollback()
        raise
    if not was_in_tx and conn.in_transaction:
        conn.commit()


def _chunks(seq: Sequence[Any], n: int) -> Iterator[Sequence[Any]]:
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


# ----- stats_daily --------------------------------------------------------

_UNKNOWN_METRICS_WARNED: set[str] = set()


def bump_stat(conn: sqlite3.Connection, account: str, metric: str, n: int = 1) -> None:
    """Add n to today's (Europe/Copenhagen) counter for metric."""
    if not n:
        return
    if metric not in STAT_METRICS and metric not in _UNKNOWN_METRICS_WARNED:
        _UNKNOWN_METRICS_WARNED.add(metric)
        logging.getLogger("filter").warning("bump_stat: unknown metric %r", metric)
    with _autocommit(conn):
        conn.execute(
            """
            INSERT INTO stats_daily(account, day, metric, n) VALUES(?,?,?,?)
            ON CONFLICT(account, day, metric) DO UPDATE SET n = n + excluded.n
            """,
            (account, stats_day(), metric, int(n)),
        )


# ----- account_status -----------------------------------------------------

_STATUS_COLUMNS = frozenset({
    "state", "detail", "connected_since", "last_loop_at", "last_scan_at",
    "last_error", "last_error_at", "error_count", "capabilities", "move_method",
    "idle_supported", "folders", "folder_map", "junk_exists", "mode", "threshold",
    "bookmark_lag", "pending_moves",
    # 2.1
    "alive_at", "moves_today", "move_state", "move_state_reason", "move_state_at",
    "login_state", "retry_at",
})
_STATUS_JSON = frozenset({"capabilities", "folders", "folder_map"})


def update_account_status(conn: sqlite3.Connection, account: str, **fields: Any) -> None:
    """Upsert the account_status row; only the given columns change."""
    bad = set(fields) - _STATUS_COLUMNS
    if bad:
        raise ValueError(f"update_account_status: unknown column(s) {sorted(bad)}")
    vals: dict[str, Any] = {}
    for k, v in fields.items():
        if k in _STATUS_JSON and v is not None and not isinstance(v, str):
            v = json.dumps(v, ensure_ascii=False, separators=(",", ":"))
        elif isinstance(v, bool):
            v = int(v)
        vals[k] = v
    vals["updated_at"] = int(_now())
    insert_cols = ["account", "state", *[k for k in vals if k != "state"]]
    insert_vals = [account, vals.get("state") or "starting",
                   *[v for k, v in vals.items() if k != "state"]]
    updates = ", ".join(f"{k}=excluded.{k}" for k in vals)
    with _autocommit(conn):
        conn.execute(
            f"INSERT INTO account_status({', '.join(insert_cols)}) "
            f"VALUES({', '.join('?' * len(insert_cols))}) "
            f"ON CONFLICT(account) DO UPDATE SET {updates}",
            insert_vals,
        )


def record_account_error(conn: sqlite3.Connection, account: str, *, category: str,
                         text: str, detail: str, state: str = "error") -> None:
    """Status row for a failure: Danish detail for the UI, `last_error` =
    category + short sanitized text, consecutive error_count + 1."""
    now = int(_now())
    update_account_status(conn, account, state=state, detail=detail,
                          last_error=f"{category}: {text}"[:240], last_error_at=now)
    with _autocommit(conn):
        conn.execute("UPDATE account_status SET error_count = error_count + 1 WHERE account=?",
                     (account,))


# ----- sender rules -------------------------------------------------------

_RULE_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
_RULE_LOCAL_RE = re.compile(r"^[a-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}$")


def _ascii_domain(domain: str) -> str | None:
    domain = domain.strip().rstrip(".").lower()
    if not domain:
        return None
    if not domain.isascii():
        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    return domain


def normalize_rule_pattern(text: str) -> str:
    """'local@domain' or '@domain' (lowercase, IDN as punycode). Accepts
    'domain', '*@domain', '*.domain', '<a@b>', 'mailto:a@b'. ValueError
    when invalid."""
    s = (text or "").strip().lower()
    if s.startswith("mailto:"):
        s = s[7:]
    s = s.strip().strip("<>").strip()
    if s.startswith("*@"):
        s = s[1:]
    elif s.startswith("*."):
        s = "@" + s[2:]
    if not s:
        raise ValueError("empty pattern")
    if any(c.isspace() or ord(c) < 0x20 for c in s) or s.count("@") > 1:
        raise ValueError("invalid pattern")
    if "@" not in s:
        s = "@" + s
    local, _, domain = s.partition("@")
    ascii_dom = _ascii_domain(domain)
    if ascii_dom is None or not _RULE_DOMAIN_RE.match(ascii_dom):
        raise ValueError("invalid domain")
    if local and not _RULE_LOCAL_RE.match(local):
        raise ValueError("invalid address")
    return f"{local}@{ascii_dom}"


def _sender_parts(addr: str | None) -> tuple[str, str] | None:
    s = (addr or "").strip().lower().strip("<>").strip()
    if s.count("@") < 1:
        return None
    local, _, domain = s.rpartition("@")
    ascii_dom = _ascii_domain(domain)
    if not local or not ascii_dom:
        return None
    return local, ascii_dom


def match_sender_rule(conn: sqlite3.Connection, account: str,
                      sender_addr: str | None) -> sqlite3.Row | None:
    """Best matching allow/block rule for a sender address. Account rules
    beat '*'; an exact address beats a domain (longer domain beats its
    parent); block beats allow at equal specificity."""
    parts = _sender_parts(sender_addr)
    if parts is None:
        return None
    local, domain = parts
    exact = f"{local}@{domain}"
    labels = domain.split(".")
    patterns = [exact] + ["@" + ".".join(labels[i:]) for i in range(len(labels))]
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    rows = cur.execute(
        f"SELECT * FROM sender_rules WHERE account IN (?, '*') "
        f"AND pattern IN ({','.join('?' * len(patterns))})",
        (account, *patterns),
    ).fetchall()
    if not rows:
        return None

    def rank(r: sqlite3.Row) -> tuple[int, int, int, int]:
        return (1 if r["account"] == account and account != "*" else 0,
                1 if r["pattern"] == exact else 0,
                len(r["pattern"]),
                1 if r["kind"] == "block" else 0)

    return max(rows, key=rank)


rule_is_force = decisionpolicy.rule_is_force


def add_sender_rule(conn: sqlite3.Connection, account: str, pattern: str, kind: str,
                    note: str | None = None, actor: str | None = None,
                    force: bool = False) -> int:
    """Insert (or update kind/note of) a rule; returns its id.

    force=True makes an allow rule 'Altid igennem'. Re-adding an allow rule
    without force never downgrades an existing 'Altid igennem' rule (only
    set_rule_force does); switching a rule to block clears the flag."""
    if kind not in ("allow", "block"):
        raise ValueError("kind must be 'allow' or 'block'")
    account = (account or "*").strip() or "*"
    pat = normalize_rule_pattern(pattern)
    note = (note or "").strip()[:500] or None
    force_val = 1 if (force and kind == "allow") else 0
    with _autocommit(conn):
        conn.execute(
            """
            INSERT INTO sender_rules(account, pattern, kind, note, created_by, created_at, force)
            VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(account, pattern) DO UPDATE SET
                force=CASE WHEN excluded.kind = 'allow'
                           THEN MAX(excluded.force,
                                    CASE WHEN sender_rules.kind = 'allow' THEN sender_rules.force ELSE 0 END)
                           ELSE 0 END,
                kind=excluded.kind,
                note=COALESCE(excluded.note, sender_rules.note),
                created_by=excluded.created_by
            """,
            (account, pat, kind, note, (actor or None), int(_now()), force_val),
        )
        row = conn.execute("SELECT id FROM sender_rules WHERE account=? AND pattern=?",
                           (account, pat)).fetchone()
    return int(row[0])


def set_rule_force(conn: sqlite3.Connection, rule_id: int, force: bool) -> bool:
    """Turn 'Altid igennem' on/off for an allow rule. False when the rule
    does not exist (or is a block rule and force was asked for)."""
    with _autocommit(conn):
        if force:
            cur = conn.execute("UPDATE sender_rules SET force=1 WHERE id=? AND kind='allow'",
                               (int(rule_id),))
        else:
            cur = conn.execute("UPDATE sender_rules SET force=0 WHERE id=?", (int(rule_id),))
    return cur.rowcount > 0


def force_allow_rule(conn: sqlite3.Connection, account: str,
                     sender_addr: str | None) -> sqlite3.Row | None:
    """The rule that makes this sender 'Altid igennem', or None. Uses the
    same precedence as the scan decision (a more specific block rule wins).

    sender_addr must be the From address. Never pass the envelope sender:
    forwarded mail carries the forwarder's SRS address there (e.g.
    SRS0=...@mail.vexar.example for anything sent to the shop's mailbox,
    spam included), which must not make mail 'Altid igennem'."""
    if not sender_addr:
        return None
    rule = match_sender_rule(conn, account, sender_addr)
    return rule if rule_is_force(rule) else None


def delete_sender_rule(conn: sqlite3.Connection, rule_id: int) -> bool:
    with _autocommit(conn):
        cur = conn.execute("DELETE FROM sender_rules WHERE id=?", (int(rule_id),))
    return cur.rowcount > 0


def _bump_rule_hit(conn: sqlite3.Connection, rule_id: int) -> None:
    conn.execute("UPDATE sender_rules SET hits = hits + 1, last_hit_at=? WHERE id=?",
                 (int(_now()), rule_id))


# ----- engine_state / update hold (E1) --------------------------------------


def engine_state_get(conn: sqlite3.Connection, key: str) -> str | None:
    try:
        row = conn.execute("SELECT value FROM engine_state WHERE key=?", (key,)).fetchone()
    except sqlite3.OperationalError:
        return None
    return None if row is None else row[0]


def engine_state_set(conn: sqlite3.Connection, key: str, value: str | None) -> None:
    with _autocommit(conn):
        conn.execute(
            "INSERT INTO engine_state(key, value, updated_at) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (key, value, int(_now())))


def record_version_start(conn: sqlite3.Connection, version: str | None = None) -> int:
    """Remember when this VERSION started for the first time (idempotent).
    Returns that timestamp; moves are held for UPDATE_HOLD_S after it."""
    version = version or VERSION
    key = f"version_started:{version}"
    cur = engine_state_get(conn, key)
    if cur is not None:
        try:
            return int(cur)
        except ValueError:
            pass
    now = int(_now())
    engine_state_set(conn, key, str(now))
    return now


def move_hold_until(conn: sqlite3.Connection, version: str | None = None) -> int:
    """Unix time until which only clear spam is moved after an update
    (0 = no hold: this VERSION never recorded a first start)."""
    val = engine_state_get(conn, f"version_started:{version or VERSION}")
    try:
        return int(val) + UPDATE_HOLD_S if val is not None else 0
    except ValueError:
        return 0


# ----- move circuit breaker (E1) --------------------------------------------


def circuit_row(conn: sqlite3.Connection, account: str) -> sqlite3.Row | None:
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    try:
        return cur.execute("SELECT * FROM move_circuit WHERE account=?", (account,)).fetchone()
    except sqlite3.OperationalError:
        return None


def circuit_open(conn: sqlite3.Connection, account: str) -> bool:
    row = circuit_row(conn, account)
    return row is not None and row["state"] == "open"


def open_circuit(conn: sqlite3.Connection, account: str, reason: str) -> bool:
    """Pause moving for an account (pending moves are kept). False when it
    was already open."""
    now = int(_now())
    with _autocommit(conn):
        if circuit_open(conn, account):
            return False
        conn.execute(
            "INSERT INTO move_circuit(account, state, reason, opened_at) VALUES(?,?,?,?) "
            "ON CONFLICT(account) DO UPDATE SET state='open', reason=excluded.reason, "
            "opened_at=excluded.opened_at",
            (account, "open", reason[:300], now))
        conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                     (account, now, None, "circuit_open", reason[:500]))
    update_account_status(conn, account, move_state="paused", move_state_reason=reason[:300],
                          move_state_at=now)
    return True


def resume_moves(conn: sqlite3.Connection, account: str, actor: str = "") -> bool:
    """Admin action: close the circuit breaker so pending moves run again.
    Moves made before this moment no longer count towards the breaker's
    windows. Returns False when moving was not paused."""
    now = int(_now())
    with _autocommit(conn):
        if not circuit_open(conn, account):
            return False
        conn.execute("UPDATE move_circuit SET state='closed', resumed_at=?, resumed_by=? WHERE account=?",
                     (now, (actor or None), account))
        conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                     (account, now, None, "circuit_resumed", f"by {actor}" if actor else None))
    update_account_status(conn, account, move_state="active", move_state_reason=None,
                          move_state_at=now)
    request_wake(conn, account)
    return True


def circuit_status(conn: sqlite3.Connection, account: str) -> dict[str, Any]:
    """{'state': 'open'|'closed', 'reason', 'opened_at', 'resumed_at',
    'resumed_by'} for the UI."""
    row = circuit_row(conn, account)
    if row is None:
        return {"state": "closed", "reason": None, "opened_at": None, "resumed_at": None,
                "resumed_by": None}
    return {k: row[k] for k in ("state", "reason", "opened_at", "resumed_at", "resumed_by")}


def _circuit_since(conn: sqlite3.Connection, account: str, window_s: int) -> int:
    since = int(_now()) - window_s
    row = circuit_row(conn, account)
    if row is not None and row["resumed_at"]:
        since = max(since, int(row["resumed_at"]))
    return since


def _circuit_resumed_at(conn: sqlite3.Connection, account: str) -> int | None:
    """When an admin last resumed the breaker (None = never)."""
    row = circuit_row(conn, account)
    if row is None or row["state"] == "open" or not row["resumed_at"]:
        return None
    return int(row["resumed_at"])


def _counted_moves(conn: sqlite3.Connection, account: str, since: int) -> int:
    """Filter moves since `since` that count towards the breaker: moves an
    admin approved by resuming (CIRCUIT_APPROVED_ACTION) do not."""
    row = conn.execute(
        "SELECT SUM(action='move'), SUM(action=?) FROM rate_limit WHERE account=? "
        "AND action IN ('move', ?) AND ts>=?",
        (CIRCUIT_APPROVED_ACTION, account, CIRCUIT_APPROVED_ACTION, since)).fetchone()
    return max(0, int(row[0] or 0) - int(row[1] or 0))


def circuit_trip_reason(conn: sqlite3.Connection, acc: "Account", batch: int) -> tuple[int, str | None]:
    """How many of `batch` due moves may run now, and why the breaker must
    open (None = no trip). Danish reason (shown in the UI)."""
    if batch <= 0:
        return 0, None
    since_h = _circuit_since(conn, acc.name, CIRCUIT_WINDOW_RATE_S)
    moved_h = _counted_moves(conn, acc.name, since_h)
    since_r = _circuit_since(conn, acc.name, CIRCUIT_WINDOW_RATIO_S)
    moved_r = _counted_moves(conn, acc.name, since_r)
    scanned_r = int(conn.execute(
        "SELECT COUNT(*) FROM messages WHERE account=? AND scanned_at>=? "
        "AND COALESCE(our_action, '')!='provider_junk'",
        (acc.name, since_r)).fetchone()[0])
    projected = moved_r + batch
    if projected >= acc.circuit_min_moves and projected > acc.circuit_max_ratio * max(scanned_r, 1):
        pct = int(round(100 * projected / max(scanned_r, 1)))
        return 0, (f"{projected} af {scanned_r} scannede mails på 2 timer skulle flyttes "
                   f"({pct} % – grænsen er {int(round(acc.circuit_max_ratio * 100))} %)")
    allowed = acc.circuit_max_moves_per_hour - moved_h
    if batch > allowed:
        return max(0, allowed), (f"Mere end {acc.circuit_max_moves_per_hour} flytninger på en time "
                                 f"({moved_h + batch} ventede)")
    return batch, None


# ----- Db -----------------------------------------------------------------


class Db:
    """Per-thread SQLite handle. Use as context manager for write transactions."""

    def __init__(self, account: str) -> None:
        self.account = account
        self.conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=30000")

    def close(self) -> None:
        self.conn.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
            self.conn.execute("COMMIT")
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise

    # ----- events / stats / status -------------------------------------------

    def log_event(self, event: str, message_id: str | None = None, detail: str | None = None) -> None:
        self.conn.execute(
            "INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
            (self.account, int(_now()), message_id, event,
             detail[:500] if isinstance(detail, str) else detail),
        )

    def bump(self, metric: str, n: int = 1) -> None:
        bump_stat(self.conn, self.account, metric, n)

    def status(self, **fields: Any) -> None:
        update_account_status(self.conn, self.account, **fields)

    def status_error(self, *, category: str, text: str, detail: str, state: str = "error") -> None:
        record_account_error(self.conn, self.account, category=category, text=text,
                             detail=detail, state=state)

    # ----- messages ---------------------------------------------------------

    def get_message(self, msgid: str) -> sqlite3.Row | None:
        cur = self.conn.execute(
            "SELECT * FROM messages WHERE account=? AND message_id=?",
            (self.account, msgid),
        )
        return cur.fetchone()

    def upsert_message(
        self,
        msgid: str,
        folder: str,
        sender: str,
        subject: str,
        received_at: int | None = None,
    ) -> None:
        now = int(_now())
        self.conn.execute(
            """
            INSERT INTO messages(account, message_id, first_seen, last_seen,
                                 current_folder, sender, subject, received_at)
            VALUES(?,?,?,?,?,?,?,?)
            ON CONFLICT(account, message_id) DO UPDATE SET
                last_seen=excluded.last_seen,
                current_folder=excluded.current_folder,
                sender=COALESCE(messages.sender, excluded.sender),
                subject=COALESCE(messages.subject, excluded.subject),
                received_at=COALESCE(messages.received_at, excluded.received_at)
            """,
            (self.account, msgid, now, now, folder, sender or None, subject or None, received_at),
        )

    # Whitelist of message-table columns update_message() may set. It builds
    # its SET clause from kwarg names; the guard keeps arbitrary identifiers
    # out of the SQL.
    _UPDATABLE_MESSAGE_COLUMNS = frozenset({
        "current_folder", "moved_to_junk_at", "our_score", "our_action",
        "learned_as", "learned_at", "pending_learn", "pending_learn_at",
        "sender", "subject", "received_at", "last_seen", "rspamd_score",
        "symbols", "rspamd_action", "sender_ip", "envelope_from",
        "provider_score", "provider_flag", "user_verdict", "verdict_at",
        "verdict_by", "rule_hit", "size", "scanned_at", "origin", "score_version",
        "sender_auth", "aged", "threat", "threat_detail", "zapped_at", "decision_names",
    })

    def update_message(self, msgid: str, **fields: Any) -> None:
        if not fields:
            return
        bad = set(fields) - self._UPDATABLE_MESSAGE_COLUMNS
        if bad:
            raise ValueError(f"update_message: unknown column(s) {sorted(bad)}")
        cols = ", ".join(f"{k}=?" for k in fields)
        vals = list(fields.values()) + [self.account, msgid]
        self.conn.execute(
            f"UPDATE messages SET {cols} WHERE account=? AND message_id=?",
            vals,
        )

    # ----- uidvalidity ------------------------------------------------------

    def get_uidvalidity(self, folder: str) -> int | None:
        cur = self.conn.execute(
            "SELECT uidvalidity FROM uidvalidity WHERE account=? AND folder=?",
            (self.account, folder),
        )
        row = cur.fetchone()
        return row[0] if row else None

    def set_uidvalidity(self, folder: str, value: int) -> None:
        self.conn.execute(
            """
            INSERT INTO uidvalidity(account, folder, uidvalidity) VALUES(?,?,?)
            ON CONFLICT(account, folder) DO UPDATE SET uidvalidity=excluded.uidvalidity
            """,
            (self.account, folder, value),
        )

    # ----- pending_move (filter-initiated moves after the grace period) -----

    def add_pending_move(self, uidvalidity: int, uid: int, msgid: str, folder: str | None = None, *,
                         due_at: int | None = None, score: float | None = None,
                         threshold: float | None = None, origin: str | None = None) -> None:
        """Queue a filter move. due_at (2.1) = when the grace period ends;
        rows without it (1.x/2.0) fall back to flag_at + move_grace_seconds.
        origin (2.3): 'zap' for a move decided by a rescan (B19)."""
        self.conn.execute(
            """
            INSERT OR IGNORE INTO pending_move(account, uidvalidity, uid, message_id, flag_at, folder,
                                               due_at, score, threshold, origin)
            VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (self.account, uidvalidity, uid, msgid, int(_now()), folder, due_at, score, threshold,
             origin),
        )

    def due_pending_moves(self, uidvalidity: int, grace_s: int, folder: str | None = None, *,
                          hold_until: int = 0, hold_margin: float = UPDATE_HOLD_MARGIN,
                          default_threshold: float = 0.0) -> list[sqlite3.Row]:
        """Rows whose due time passed. While the update hold is active
        (now < hold_until) only clear spam (score >= threshold + margin)
        is due; rows without a stored score wait for the hold to end."""
        now = int(_now())
        sql = ("SELECT uid, message_id, flag_at, due_at, score, threshold, origin FROM pending_move "
               "WHERE account=? AND uidvalidity=? AND COALESCE(due_at, flag_at + ?) <= ? "
               "AND (? <= ? OR (score IS NOT NULL AND score >= COALESCE(threshold, ?) + ?) "
               f"OR {_PM_THREAT_SQL})")
        args: list[Any] = [self.account, uidvalidity, int(grace_s), now, int(hold_until), now,
                           float(default_threshold), float(hold_margin)]
        if folder is not None:
            sql += " AND folder=?"
            args.append(folder)
        return list(self.conn.execute(sql + " ORDER BY COALESCE(due_at, flag_at + ?), uid",
                                      [*args, int(grace_s)]).fetchall())

    def drop_pending_move(self, uidvalidity: int, uid: int) -> None:
        self.conn.execute(
            "DELETE FROM pending_move WHERE account=? AND uidvalidity=? AND uid=?",
            (self.account, uidvalidity, uid),
        )

    def drop_pending_moves_for(self, msgid: str) -> None:
        self.conn.execute("DELETE FROM pending_move WHERE account=? AND message_id=?",
                          (self.account, msgid))

    def count_pending_moves(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM pending_move WHERE account=?",
                                     (self.account,)).fetchone()[0])

    # ----- bookmarks --------------------------------------------------------

    def get_scan_bookmark(self, folder: str, uidvalidity: int) -> int | None:
        cur = self.conn.execute(
            "SELECT max_uid FROM scan_bookmark WHERE account=? AND folder=? AND uidvalidity=?",
            (self.account, folder, uidvalidity),
        )
        row = cur.fetchone()
        return row[0] if row else None

    def set_scan_bookmark(self, folder: str, uidvalidity: int, max_uid: int) -> None:
        # Monotonic within a uidvalidity: UIDs only grow (RFC 3501), so a
        # smaller value would mean re-scanning mail already past.
        self.conn.execute(
            """
            INSERT INTO scan_bookmark(account, folder, uidvalidity, max_uid)
            VALUES(?,?,?,?)
            ON CONFLICT(account, folder, uidvalidity) DO UPDATE SET
                max_uid=excluded.max_uid
                WHERE excluded.max_uid > scan_bookmark.max_uid
            """,
            (self.account, folder, uidvalidity, max_uid),
        )

    def get_junk_bookmark(self, folder: str, uidvalidity: int) -> int | None:
        row = self.conn.execute(
            "SELECT max_uid FROM junk_bookmark WHERE account=? AND folder=? AND uidvalidity=?",
            (self.account, folder, uidvalidity),
        ).fetchone()
        return row[0] if row else None

    def set_junk_bookmark(self, folder: str, uidvalidity: int, max_uid: int) -> None:
        self.conn.execute(
            """
            INSERT INTO junk_bookmark(account, folder, uidvalidity, max_uid)
            VALUES(?,?,?,?)
            ON CONFLICT(account, folder, uidvalidity) DO UPDATE SET
                max_uid=excluded.max_uid
                WHERE excluded.max_uid > junk_bookmark.max_uid
            """,
            (self.account, folder, uidvalidity, max_uid),
        )

    # ----- scan_retry -------------------------------------------------------

    def scan_retry_rows(self, uidvalidity: int, uids: Iterable[int]) -> dict[int, sqlite3.Row]:
        out: dict[int, sqlite3.Row] = {}
        uid_list = list(uids)
        for chunk in _chunks(uid_list, 500):
            for r in self.conn.execute(
                f"SELECT * FROM scan_retry WHERE account=? AND uidvalidity=? "
                f"AND uid IN ({','.join('?' * len(chunk))})",
                (self.account, uidvalidity, *chunk),
            ):
                out[int(r["uid"])] = r
        return out

    def record_scan_failure(self, uidvalidity: int, uid: int, error: str) -> sqlite3.Row:
        self.conn.execute(
            """
            INSERT INTO scan_retry(account, uidvalidity, uid, attempts, first_fail_at, last_error)
            VALUES(?,?,?,1,?,?)
            ON CONFLICT(account, uidvalidity, uid) DO UPDATE SET
                attempts = scan_retry.attempts + 1,
                last_error = excluded.last_error
            """,
            (self.account, uidvalidity, uid, int(_now()), error[:300]),
        )
        return self.conn.execute(
            "SELECT * FROM scan_retry WHERE account=? AND uidvalidity=? AND uid=?",
            (self.account, uidvalidity, uid),
        ).fetchone()

    def mark_scan_given_up(self, uidvalidity: int, uid: int) -> None:
        self.conn.execute(
            "UPDATE scan_retry SET attempts=? WHERE account=? AND uidvalidity=? AND uid=?",
            (SCAN_RETRY_MAX_ATTEMPTS, self.account, uidvalidity, uid),
        )

    def clear_scan_retry(self, uidvalidity: int, uid: int) -> None:
        self.conn.execute("DELETE FROM scan_retry WHERE account=? AND uidvalidity=? AND uid=?",
                          (self.account, uidvalidity, uid))

    def prune_orphan_scan_retry(self, uidvalidity: int, live_uids: Iterable[int]) -> int:
        """Drop pending retries (attempts < max) of an older UIDVALIDITY or
        for UIDs no longer above the bookmark in the inbox. Given-up rows
        stay until prune_scan_retry."""
        live = {int(u) for u in live_uids}
        rows = self.conn.execute(
            "SELECT uidvalidity, uid FROM scan_retry WHERE account=? AND attempts<?",
            (self.account, SCAN_RETRY_MAX_ATTEMPTS)).fetchall()
        gone = [(int(r["uidvalidity"]), int(r["uid"])) for r in rows
                if int(r["uidvalidity"]) != int(uidvalidity) or int(r["uid"]) not in live]
        for uv, uid in gone:
            self.clear_scan_retry(uv, uid)
        return len(gone)

    def prune_scan_retry(self, older_than_s: int = SCAN_RETRY_PRUNE_S) -> int:
        cutoff = int(_now()) - older_than_s
        return self.conn.execute("DELETE FROM scan_retry WHERE account=? AND first_fail_at<?",
                                 (self.account, cutoff)).rowcount

    # ----- rate limiting ----------------------------------------------------

    def record_rate(self, action: str) -> None:
        self.conn.execute(
            "INSERT INTO rate_limit(account, action, ts) VALUES(?,?,?)",
            (self.account, action, int(_now())),
        )

    def rate_count(self, action: str, window_s: int) -> int:
        since = int(_now()) - window_s
        cur = self.conn.execute(
            "SELECT COUNT(*) FROM rate_limit WHERE account=? AND action=? AND ts>=?",
            (self.account, action, since),
        )
        return int(cur.fetchone()[0])

    def prune_rate(self, older_than_s: int = 7200) -> None:
        cutoff = int(_now()) - older_than_s
        self.conn.execute(
            "DELETE FROM rate_limit WHERE account=? AND ts<?",
            (self.account, cutoff),
        )

    def prune_events(self, older_than_s: int = 30 * 86400) -> int:
        """Drop event rows older than the cutoff (debug/forensic only)."""
        cutoff = int(_now()) - older_than_s
        cur = self.conn.execute(
            "DELETE FROM events WHERE account=? AND ts<?",
            (self.account, cutoff),
        )
        return cur.rowcount

    def prune_messages(self, older_than_s: int) -> int:
        """Drop message rows not seen for older_than_s that wait for nothing
        (no pending learn). Junk reconciliation refreshes last_seen of mail
        still sitting in the spam folder, so those rows survive."""
        cutoff = int(_now()) - older_than_s
        cur = self.conn.execute(
            """
            DELETE FROM messages
             WHERE account=?
               AND last_seen<?
               AND pending_learn IS NULL
            """,
            (self.account, cutoff),
        )
        self.conn.execute('DELETE FROM junk_auto_evidence WHERE account=? AND at<?',
                          (self.account, int(_now())-30*86400))
        self.conn.execute("DELETE FROM policy_trial_results WHERE account=? AND NOT EXISTS "
                          "(SELECT 1 FROM messages m WHERE m.account=policy_trial_results.account "
                          "AND m.message_id=policy_trial_results.message_key)", (self.account,))
        self.conn.execute("DELETE FROM decision_traces WHERE account=? AND NOT EXISTS "
                          "(SELECT 1 FROM messages m WHERE m.account=decision_traces.account "
                          "AND m.message_id=decision_traces.message_key)", (self.account,))
        self.conn.execute("DELETE FROM scan_observations WHERE account=? AND NOT EXISTS "
                          "(SELECT 1 FROM messages m WHERE m.account=scan_observations.account "
                          "AND m.message_id=scan_observations.message_key)", (self.account,))
        self.conn.execute("DELETE FROM mail_identity WHERE account=? AND NOT EXISTS "
                          "(SELECT 1 FROM messages m WHERE m.account=mail_identity.account "
                          "AND m.message_id=mail_identity.message_key) AND NOT EXISTS "
                          "(SELECT 1 FROM daily_receipts r WHERE r.account=mail_identity.account "
                          "AND r.message_id=mail_identity.message_key)", (self.account,))
        return cur.rowcount

    def prune_stale_pending_learn(self, older_than_s: int) -> int:
        """Clear pending_learn flags that never resolved (message vanished),
        so prune_messages can eventually evict the row."""
        cutoff = int(_now()) - older_than_s
        cur = self.conn.execute(
            """
            UPDATE messages
               SET pending_learn=NULL, pending_learn_at=NULL
             WHERE account=?
               AND pending_learn IS NOT NULL
               AND pending_learn_at<?
            """,
            (self.account, cutoff),
        )
        return cur.rowcount

    def vacuum_if_due(self, every_s: int = 7 * 86400) -> None:
        """VACUUM at most once per week to reclaim space from the prunes."""
        cur = self.conn.execute("PRAGMA user_version").fetchone()
        last = int(cur[0]) if cur else 0
        now = int(_now())
        if last and now - last < every_s:
            return
        # Stamp the marker FIRST so an interrupted VACUUM cannot cause a
        # tight retry loop on every sweep.
        self.conn.execute(f"PRAGMA user_version = {now}")
        try:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.conn.execute("VACUUM")
        except sqlite3.Error as ex:
            logging.getLogger("main").error(
                "vacuum failed for %s; next attempt in %dd: %s",
                self.account, every_s // 86400, ex,
            )
            try:
                self.log_event("vacuum_failed", detail=str(ex)[:300])
            except sqlite3.Error:
                pass

    # ----- safe mode --------------------------------------------------------

    def in_safe_mode(self, scope: str) -> bool:
        cur = self.conn.execute(
            "SELECT 1 FROM safe_mode WHERE account=? AND scope IN (?, 'all')",
            (self.account, scope),
        )
        return cur.fetchone() is not None

    def enter_safe_mode(self, scope: str, reason: str) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO safe_mode(account, scope, entered_at, reason)
            VALUES(?,?,?,?)
            """,
            (self.account, scope, int(_now()), reason),
        )

    def exit_safe_mode(self, scope: str) -> None:
        self.conn.execute(
            "DELETE FROM safe_mode WHERE account=? AND scope=?",
            (self.account, scope),
        )


# ---------------------------------------------------------------------------
# rspamd
# ---------------------------------------------------------------------------


class RspamdError(Exception):
    """A scan did not produce a score. `outage` = rspamd itself looked
    unavailable (connection error, timeout, 5xx/429) rather than refusing
    this particular message."""

    def __init__(self, message: str, *, outage: bool) -> None:
        super().__init__(message)
        self.outage = outage


@dataclass
class ScanResult:
    score: float                 # rspamd score, clamped to +-reject_score_above
    action: str | None
    symbols: list[dict]          # [{"n","s","o"}] top 30, abs(score) desc
    names: frozenset = frozenset()   # every symbol name rspamd reported
    raw_score: float | None = None   # before clamping
    clamped: bool = False
    # 2.1: full option lists of a few symbols the decision needs (DKIM /
    # DMARC domains), independent of the top-30 cut.
    options: dict = field(default_factory=dict)
    # 2.2: score of every symbol rspamd reported (independent of the cut).
    scores: dict = field(default_factory=dict)
    # 2.2 (B7): scanned in aged mode (Settings header sent).
    aged: bool = False


# Symbols whose complete options are kept on ScanResult.options.
_KEEP_OPTIONS = frozenset({"R_DKIM_ALLOW", "DMARC_POLICY_ALLOW", "DKIM_TRACE",
                           # 2.2 (B2): the listed domains decide TH_OWN_PLATFORM_URIBL.
                           "RSPAMD_URIBL",
                           # 2.3 (B12): 'asn:N' of the sending host (established fingerprint).
                           "ASN",
                           # 2.3 (B17): rspamd's mime_types options carry the
                           # extensions / file names (also inside archives).
                           "MIME_BAD_EXTENSION", "MIME_DOUBLE_BAD_EXTENSION", "MIME_ARCHIVE_IN_ARCHIVE",
                           "MIME_ENCRYPTED_ARCHIVE", "MIME_BAD_UNICODE", "MIME_EXE_IN_GEN_SPLIT_RAR",
                           # 2.3 (B16/B20): virus signature names, phishing hosts.
                           "CLAM_VIRUS", "CLAM_PHISH", "DBL_PHISH", "DBL_MALWARE", "PH_SURBL_MULTI",
                           "PHISHED_OPENPHISH", "PHISHED_PHISHTANK", "URLHAUS_MALWARE_URL"})

# 2.2 (B7) aged mode: mail scanned more than aged_scan_hours after delivery.
# rspamd gets a per-request `Settings: {"symbols_disabled": [...]}` header.
# Verified on the live rspamd 4.2 worker (2026-10-21): the header is
# accepted by /checkv2, and disabling a check's (virtual) result symbol
# turns that whole check off - R_SPF_FAIL takes R_SPF_ALLOW with it,
# DMARC_POLICY_REJECT takes DMARC_POLICY_ALLOW, ARC_REJECT the ARC check.
# That is wanted for SPF/DMARC/ARC (meaningless hours later; the provider's
# own verdict at delivery replaces them, mailctx.provider_auth_symbols), but
# NOT for DKIM: disabling R_DKIM_REJECT also removes R_DKIM_ALLOW, which
# 'Altid igennem' (E8), TH_NEWSLETTER and the 2.2 trust rules rely on. So
# R_DKIM_REJECT stays enabled and is neutralised by the engine instead
# (its score is taken out of the result, AGED_NEUTRALIZED_SYMBOLS).
# The stock whitelist module's SPF/DMARC rules go too: with the DMARC check
# off, DMARC_POLICY_ALLOW never appears, so every dmarc_whitelist domain
# (paypal, amazon, ebay ...) counted as "violated" and got BLACKLIST_DMARC
# +6 instead of WHITELIST_DMARC -7 (verified live 2026-10-21: an aged
# amazon.com mail went from -5.4 to +7.3). Disabling a WHITELIST_* rule
# also stops its inverse BLACKLIST_* symbol (verified live: 7.3 -> 1.3).
# WHITELIST_DKIM stays: the DKIM check is still on.
AGED_DISABLED_SYMBOLS = ("DATE_IN_PAST", "R_SPF_FAIL", "R_SPF_SOFTFAIL", "VIOLATED_DIRECT_SPF",
                         "DMARC_POLICY_REJECT", "DMARC_POLICY_QUARANTINE", "ARC_REJECT",
                         "WHITELIST_DMARC", "WHITELIST_SPF_DKIM", "WHITELIST_SPF")
AGED_NEUTRALIZED_SYMBOLS = frozenset({"R_DKIM_REJECT"})
AGED_SETTINGS_HEADER = json.dumps({"symbols_disabled": list(AGED_DISABLED_SYMBOLS)},
                                  separators=(",", ":"))


_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")


def _header_safe(value: Any) -> bool:
    # requests/http.client would choke on (or forward) CR/LF and non-latin-1;
    # rspamd headers are ASCII by nature.
    return (isinstance(value, str) and 0 < len(value) <= 998 and value.isascii()
            and all(0x20 <= ord(c) < 0x7F for c in value))


def bayes_identity(acc: Account) -> str:
    return acc.bayes_user or acc.user


def _rspamd_password() -> str:
    global RSPAMD_PASSWORD
    if not RSPAMD_PASSWORD:
        RSPAMD_PASSWORD = _load_rspamd_password()
    return RSPAMD_PASSWORD


def _norm_symbol(name: Any, raw: Any) -> dict | None:
    if not isinstance(raw, dict):
        return None
    n = str(raw.get("name") or raw.get("n") or name or "")[:80]
    if not n:
        return None
    try:
        s = float(raw.get("score", raw.get("s", 0.0)) or 0.0)
    except (TypeError, ValueError):
        s = 0.0
    if not math.isfinite(s):
        s = 0.0
    opts = raw.get("options", raw.get("o")) or []
    if not isinstance(opts, list):
        opts = [opts]
    return {"n": n, "s": round(s, 3), "o": [str(o)[:120] for o in opts[:3]]}


def top_symbols(symbols: Iterable[dict], limit: int = SYMBOLS_MAX) -> list[dict]:
    """Sort by abs(score) desc and cap at `limit`, always keeping the
    filter's own TH_* pseudo-symbols."""
    syms = [s for s in symbols if isinstance(s, dict) and s.get("n")]
    th = [s for s in syms if str(s["n"]).startswith("TH_")][:limit]
    rest = sorted((s for s in syms if not str(s["n"]).startswith("TH_")),
                  key=lambda s: (-abs(s["s"]), s["n"]))
    keep = th + rest[: max(0, limit - len(th))]
    return sorted(keep, key=lambda s: (-abs(s["s"]), s["n"]))


def _mailctx() -> Any:
    """Lazy accessor so tests can swap in a stub and an import problem in
    mailctx can never break importing the engine."""
    import mailctx

    return mailctx


def _contacts() -> Any:
    """Lazy accessor (2.3 known contacts, contacts.py)."""
    import contacts

    return contacts


def _lookalike() -> Any:
    """Lazy accessor (B22 lookalike domains, lookalike.py)."""
    import lookalike

    return lookalike


def _campaigns() -> Any:
    """Lazy accessor (2.6 A2/A3/A6, campaigns.py)."""
    import campaigns

    return campaigns


def _campaign_sweep(db: Db, log: logging.Logger, acc: Account, msgid: str, trigger: str,
                    *, raw: bytes | None = None) -> None:
    """2.6 (A2): a user verdict spam -> queue the copies in every mailbox.
    Runs in the caller's transaction (savepoint); never raises."""
    try:
        if legit_newsletter(raw, db.get_message(msgid), acc.threshold, db.conn):
            # A personal bulk-mail preference is neither shared training nor
            # evidence that the other family's copies are a spam campaign.
            db.log_event("campaign_local_preference", msgid, detail="nyhedsbrev; ingen kampagne på andre konti")
            return
        res = _campaigns().on_user_spam(
            db.conn, db.account, msgid, actor="user:move", trigger=trigger, now=int(_now()),
            own_domains=[*(getattr(acc, "owner_platform_domains", None) or ()),
                         *(getattr(acc, "webshop_domains", None) or ())])
        if res.get("queued"):
            log.info("campaign: %d copy/copies of %s queued (%s)", res["queued"], msgid,
                     ",".join(res.get("accounts") or ()))
    except Exception as ex:  # noqa: BLE001 - a sweep never breaks the junk poll
        log.warning("campaign sweep failed: %s", type(ex).__name__)


def _newsletters() -> Any:
    """Lazy accessor (2.6 A4 newsletter folder, newsletters.py)."""
    import newsletters

    return newsletters


def _junkrules() -> Any:
    """Lazy accessor (2.12 #8/#9 rules versus the user's moves to Junk, junkrules.py)."""
    import junkrules

    return junkrules


def _ai() -> Any:
    """Lazy accessor (2.7 local AI second opinion, ai_verdict.py)."""
    import ai_verdict

    return ai_verdict


def _namespoof() -> Any:
    """Lazy accessor (2.7 Falske afsendernavne, namespoof.py)."""
    import namespoof

    return namespoof


# B22: the domains of every configured mailbox (all accounts, also paused
# ones); main() fills it in after loading the config. Each account adds its
# own mailbox domain anyway, so an empty set only narrows the protection.
LOOKALIKE_MAILBOX_DOMAINS: frozenset[str] = frozenset()


def set_lookalike_mailboxes(configs: Iterable[Any]) -> None:
    global LOOKALIKE_MAILBOX_DOMAINS
    LOOKALIKE_MAILBOX_DOMAINS = frozenset(
        str(getattr(a, "user", "") or "").rpartition("@")[2].strip().lower()
        for a in configs or () if "@" in str(getattr(a, "user", "") or ""))


def lookalike_protected(acc: Any) -> list[str]:
    """B22: the account's protected domains + every mailbox domain."""
    return _lookalike().protected_domains(
        getattr(acc, "protected_domains", None), [getattr(acc, "user", "")], sorted(LOOKALIKE_MAILBOX_DOMAINS))


def lookalike_symbols(conn: sqlite3.Connection, acc: Any, raw: bytes, ctx: dict[str, Any] | None,
                      auth: dict[str, Any] | None, sender: str | None) -> list[dict]:
    """B22 pseudo-symbols for one mail ([] when nothing matched or on any
    error - a lookalike check never blocks a scan)."""
    try:
        lk = _lookalike()
        matcher = lk.matcher_for(lookalike_protected(acc))
        ev = lk.evaluate(conn, matcher, raw=raw, sender=sender,
                         envelope_from=(ctx or {}).get("envelope_from"),
                         dkim_verified=(auth or {}).get("dkim") or [],
                         origin_host=(auth or {}).get("host"))
        return list(ev.symbols)
    except Exception as ex:  # noqa: BLE001 - optional evidence, never block a scan
        logging.getLogger("filter").warning("lookalike check failed: %s", type(ex).__name__)
        return []


# 2.7: a name-spoof hit forbids every contact trust bonus (a fraudster the
# user answered once must not earn TH_REPLY / TH_KNOWN_CONTACT).
NAME_SPOOF_DISTRUST = frozenset({"TH_NAME_SPOOF"})


def namespoof_platform_domains(acc: Any) -> list[str]:
    """2.7 fix: owner_platform_domains and webshop_domains (vexar.example ...)
    that are not a mailbox domain. Multi-tenant: every shop on the platform
    sends from it, so a protected name from there needs the person's exact
    address - neither the own-domain exception nor an '@platform' entry."""
    mailbox = {str(getattr(acc, "user", "") or "").rpartition("@")[2].strip().lower(), *LOOKALIKE_MAILBOX_DOMAINS}
    out: list[str] = []
    for d in [*(getattr(acc, "owner_platform_domains", None) or []), *(getattr(acc, "webshop_domains", None) or [])]:
        d = str(d or "").rpartition("@")[2].strip().lower().rstrip(".")
        if d and d not in mailbox and d not in out:
            out.append(d)
    return out


def namespoof_own_domains(acc: Any) -> list[str]:
    """2.7: the owner's own domains a protected name may always come from:
    every mailbox domain and the contact group (namespoof drops freemail
    domains). 2.7 fix: no longer owner_platform_domains / webshop_domains
    (namespoof_platform_domains)."""
    out = [str(getattr(acc, "user", "") or "").rpartition("@")[2].strip().lower(),
           *sorted(LOOKALIKE_MAILBOX_DOMAINS)]
    try:
        out.append(_contacts().contact_group(acc))
    except Exception:  # noqa: BLE001 - optional
        pass
    platforms = namespoof_platform_domains(acc)
    return [d for d in out if d and d not in platforms]


def clam_3p_symbols(res: Any, mode: str) -> tuple[list[dict], list[tuple[str, str]]]:
    """2.8 (A1): TH_CLAM_3P for a ClamAV hit with third-party signatures
    (never with a real virus signature, that stays the threat 'virus'). In
    Prøv only TH_CLAM_3P_TRIAL (0) and the event clam3p_trial."""
    if mode not in ("shadow", "on"):
        return [], []
    sigs = clam_heuristic_only(getattr(res, "names", None) or (), getattr(res, "symbols", None) or [],
                               getattr(res, "options", None) or {})
    third = [x for x in sigs or () if clam_is_third_party(x)]
    if not third:
        return [], []
    phish = any(w in x.lower() for x in third for w in CLAM_3P_PHISH_WORDS)
    score = CLAM_3P_PHISH_SCORE if phish else CLAM_3P_SCORE
    opts = [_clean_display(x)[:120] for x in third[:3]]
    detail = f"+{score:g} " + ", ".join(opts)
    if mode == "shadow":
        return [{"n": CLAM_3P_TRIAL, "s": 0.0, "o": [f"+{score:g}", *opts[:2]]}], [("clam3p_trial", detail[:300])]
    return [{"n": CLAM_3P_SYMBOL, "s": score, "o": opts}], [("clam3p_hit", detail[:300])]


def trial_symbols(conn: sqlite3.Connection | None, acc: Any, raw: bytes, res: Any, names: Iterable[str]
                  ) -> tuple[list[dict], list[tuple[str, str]]]:
    """2.8: the Fra/Prøv/Til protections (trialmode.py) for one mail - the
    ClamAV third-party lists (A1) and QR-code phishing (A3). Live scan and
    calibration (trainer.scan_scored) both use this; never blocks a scan."""
    syms: list[dict] = []
    events: list[tuple[str, str]] = []
    try:
        import trialmode  # noqa: PLC0415

        a, b = clam_3p_symbols(res, trialmode.mode(conn, "clam3p"))
        syms += a
        events += b
        qr_mode = trialmode.mode(conn, "qr")
        if qr_mode != "off":
            import qrscan  # noqa: PLC0415

            a, b = qrscan.judge(sys.modules[__name__], raw, set(names or ()), qr_mode)
            syms += a
            events += b
        # 2.13: mixed scripts in the subject, new domains, payment phishing.
        import phishsignals  # noqa: PLC0415

        a, b = phishsignals.judge(conn, acc, raw, set(names or ()))
        syms += a
        events += b
    except Exception as ex:  # noqa: BLE001 - optional evidence
        logging.getLogger("filter").warning("trial protections failed: %s", type(ex).__name__)
    return syms, events


def namespoof_symbols(conn: sqlite3.Connection, acc: Any, raw: bytes, names: Iterable[str],
                      auth: dict[str, Any] | None) -> tuple[list[dict], list[tuple[str, str]]]:
    """2.7 pseudo-symbol + event for one mail (([], []) when nothing
    matched, when off or on any error - never blocks a scan). The live scan
    and the calibration (trainer.scan_scored) both use this."""
    try:
        ev = _namespoof().evaluate(conn, raw=raw, names=names, dkim_domains=(auth or {}).get("dkim") or [],
                                   own_domains=namespoof_own_domains(acc), distrust=ALLOW_DISTRUST_SYMBOLS,
                                   platform_domains=namespoof_platform_domains(acc))
        return list(ev.symbols), list(ev.events)
    except Exception as ex:  # noqa: BLE001 - optional evidence, never block a scan
        logging.getLogger("filter").warning("name spoof check failed: %s", type(ex).__name__)
        return [], []


def _namespoof_seed(db: Db, log: logging.Logger) -> None:
    """2.7: protected names from the Sent identities (at most hourly)."""
    try:
        ns = _namespoof()
        if ns.get_mode(db.conn)["mode"] == "off":
            return
        res = ns.maybe_seed(db.conn, int(_now()))
        if res and (res.get("added") or res.get("extended")):
            log.info("protected names: %d added, %d extended from Sent", res["added"], res["extended"])
            db.log_event("namespoof_seeded", detail=f"added={res['added']} extended={res['extended']}")
    except Exception as ex:  # noqa: BLE001 - bookkeeping only
        log.warning("protected names seed failed: %s", type(ex).__name__)


def _contacts_key(db: Db) -> bytes | None:
    """The contacts HMAC key (created on first use; a regenerated key
    wipes the contact tables = full resync). None on any problem: the
    trust signals are then simply off."""
    try:
        return _contacts().load_key(STATE_DIR, db.conn, create=True)
    except Exception as ex:  # noqa: BLE001 - never block scanning
        logging.getLogger("filter").warning("contacts key unavailable: %s", type(ex).__name__)
        return None


def _fallback_context(acc: Account) -> dict[str, Any]:
    headers = {"Rcpt": acc.user} if _header_safe(acc.user) else {}
    return {"headers": headers, "external_ip": None, "helo": None, "hostname": None,
            "envelope_from": None, "authenticated": False, "provider_score": None,
            "provider_flag": None, "hops": []}


def _scan_context(raw: bytes, acc: Account) -> tuple[dict[str, Any], bool]:
    """(ctx, ok). ok False = mailctx unavailable/failed and a Rcpt-only
    context is used: scanning still happens, but without the 2.0 sender
    context (score_version 1)."""
    try:
        ctx = _mailctx().scan_context(raw, acc)
        if isinstance(ctx, dict):
            return ctx, True
        logging.getLogger("filter").warning("mailctx.scan_context returned %s", type(ctx).__name__)
    except Exception as ex:  # noqa: BLE001 - never let context parsing block a scan
        logging.getLogger("filter").warning("mailctx.scan_context failed: %s", type(ex).__name__)
    return _fallback_context(acc), False


def _provider_bonus(ctx: dict[str, Any]) -> list[dict]:
    try:
        raw = _mailctx().provider_bonus(ctx) or []
    except Exception as ex:  # noqa: BLE001
        logging.getLogger("filter").warning("mailctx.provider_bonus failed: %s", type(ex).__name__)
        return []
    out = []
    for item in raw if isinstance(raw, list) else []:
        sym = _norm_symbol(None, item)
        if sym is not None:
            out.append(sym)
    return out


def _effective_bonus(bonus: list[dict], symbols: list[dict]) -> list[dict]:
    """Drop the part of the provider bonus rspamd already scored (SPAM_FLAG)."""
    if not bonus:
        return bonus
    try:
        fn = getattr(_mailctx(), "effective_bonus", None)
        if fn is None:
            return bonus
        return [s for s in (_norm_symbol(None, b) for b in fn(bonus, symbols) or []) if s is not None]
    except Exception as ex:  # noqa: BLE001
        logging.getLogger("filter").warning("mailctx.effective_bonus failed: %s", type(ex).__name__)
        return bonus


def rspamd_scan(raw: bytes, acc: Account, ctx: dict[str, Any] | None = None, *,
                aged: bool = False) -> ScanResult:
    """POST to /checkv2 with the mail's sender context. Raises RspamdError
    when no score was produced. An out-of-range score is clamped (and
    flagged), never treated as a failure. aged=True (B7): SPF/DMARC/ARC
    and DATE_IN_PAST are turned off for this scan (Settings header) and
    R_DKIM_REJECT is neutralised (score 0, see AGED_DISABLED_SYMBOLS)."""
    if ctx is None:
        ctx, _ok = _scan_context(raw, acc)
    headers: dict[str, str] = {}
    for k, v in ((ctx or {}).get("headers") or {}).items():
        if isinstance(k, str) and _HEADER_NAME_RE.match(k) and v is not None and _header_safe(str(v)):
            headers[k] = str(v)
    headers.pop("Settings", None)
    headers.pop("Settings-Id", None)
    if aged:
        headers["Settings"] = AGED_SETTINGS_HEADER
    ident = bayes_identity(acc)
    if _header_safe(ident):
        # Per-user Bayes: rspamd keys the classifier on Deliver-To.
        headers["Deliver-To"] = ident
    try:
        resp = requests.post(RSPAMD_SCAN_URL, data=raw, headers=headers, timeout=HTTP_TIMEOUT)
    except requests.RequestException as ex:
        raise RspamdError(f"unreachable ({type(ex).__name__})", outage=True) from None
    if resp.status_code == 429 or resp.status_code >= 500:
        raise RspamdError(f"HTTP {resp.status_code}", outage=True)
    if resp.status_code != 200:
        raise RspamdError(f"HTTP {resp.status_code}", outage=False)
    try:
        data = resp.json()
    except ValueError:
        raise RspamdError("invalid JSON reply", outage=False) from None
    if not isinstance(data, dict):
        raise RspamdError("invalid JSON reply", outage=False)
    score = data.get("score")
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score):
        raise RspamdError("reply without score", outage=False)
    raw_score = float(score)
    syms_raw = data.get("symbols") or {}
    symbols: list[dict] = []
    if isinstance(syms_raw, dict):
        items: Iterable[tuple[Any, Any]] = syms_raw.items()
    elif isinstance(syms_raw, list):
        items = ((None, s) for s in syms_raw)
    else:
        items = ()
    options: dict[str, list[str]] = {}
    scores: dict[str, float] = {}
    for name, s in items:
        sym = _norm_symbol(name, s)
        if sym is not None:
            if aged and sym["n"] in AGED_NEUTRALIZED_SYMBOLS and sym["s"]:
                # B7: an expired signature hours after delivery is no evidence.
                raw_score = round(raw_score - sym["s"], 3)
                sym = {**sym, "s": 0.0, "o": sym["o"][:2] + ["sen scanning"]}
            symbols.append(sym)
            scores[sym["n"]] = sym["s"]
            if sym["n"] in _KEEP_OPTIONS and isinstance(s, dict):
                opts = s.get("options", s.get("o")) or []
                if not isinstance(opts, list):
                    opts = [opts]
                options[sym["n"]] = [str(o)[:200] for o in opts[:20]]
    limit = abs(float(acc.reject_score_above))
    clamped = abs(raw_score) > limit
    final = math.copysign(limit, raw_score) if clamped else raw_score
    action = data.get("action")
    return ScanResult(
        score=final,
        action=str(action)[:40] if action else None,
        symbols=top_symbols(symbols),
        names=frozenset(s["n"] for s in symbols),
        raw_score=raw_score,
        clamped=clamped,
        options=options,
        scores=scores,
        aged=bool(aged),
    )


def _rspamd_alive() -> bool:
    """Cheap /ping on the scan worker: separates an outage from a message
    rspamd fails on (which then counts as a per-message retry)."""
    try:
        resp = requests.get(RSPAMD_PING_URL, timeout=5)
        return resp.status_code == 200
    except requests.RequestException:
        return False


def rspamd_learn(raw: bytes, kind: str, identity: str | None = None, *, user: str | None = None) -> str:
    """Gate all Bayes POSTs, including trainer mail without Message-ID."""
    if kind not in ("spam", "ham"):
        raise ValueError(f"invalid learn kind {kind!r}")
    try:
        with holdout.learning_guard(DB_PATH, raw) as allowed:
            if not allowed:
                return "held_out"
            return _rspamd_learn_post(raw, kind, identity, user=user)
    except (holdout.HoldoutError, OSError, sqlite3.Error):
        logging.getLogger("filter").warning("Bayes learning skipped: holdout registry unavailable")
        return "error"


def _rspamd_learn_post(raw: bytes, kind: str, identity: str | None = None, *, user: str | None = None) -> str:
    """POST to /learnspam or /learnham; classify the controller's reply.

    Returns one of:
      * 'learned'  - HTTP 200, a fresh learn committed to Bayes;
      * 'already'  - HTTP 208, the message was already learned;
      * 'declined' - HTTP 204: processed, nothing learned (too few tokens or
        already in that class). Terminal: re-POSTing yields the same;
      * 'error'    - a network failure or any other status. Retryable.

    `identity` (alias: `user`) selects the per-user Bayes namespace: sent
    as the `Deliver-To` HTTP header and, for compatibility, prepended as a
    `Delivered-To:` header line. Must match the identity used at scan time.
    """
    if kind not in ("spam", "ham"):
        raise ValueError(f"invalid learn kind {kind!r}")
    ident = identity if identity is not None else user
    url = f"{RSPAMD_LEARN_URL}/learn{kind}"
    headers = {"Password": _rspamd_password()}
    body = raw
    if ident:
        if not _header_safe(ident):
            logging.getLogger("filter").warning("rspamd learn: unusable Bayes identity")
            return "error"
        headers["Deliver-To"] = ident
        body = f"Delivered-To: {ident}\r\n".encode() + raw
    try:
        resp = requests.post(url, data=body, headers=headers, timeout=HTTP_TIMEOUT)
    except requests.RequestException as ex:
        logging.getLogger("filter").warning("rspamd learn POST failed: %s", type(ex).__name__)
        return "error"
    if resp.status_code == 200:
        return "learned"
    if resp.status_code == 208:
        return "already"
    if resp.status_code == 204:
        return "declined"
    logging.getLogger("filter").warning(
        "rspamd learn(%s) unexpected HTTP %s: %s",
        kind, resp.status_code, (resp.text or "").strip()[:200])
    return "error"


# ---------------------------------------------------------------------------
# IMAP helpers
# ---------------------------------------------------------------------------

# Connection-level failures: the session is unusable, reconnect. Other
# IMAPClientError subclasses (NO/BAD replies) are per-command failures.
_CONN_ERRORS: tuple[type[BaseException], ...] = (IMAPClientAbortError, OSError)


class MoveError(IMAPClientError):
    """A move did not complete. `copied` = the COPY step succeeded, so the
    destination may hold copies of messages still in the source (do not
    retry). `moved` = UIDs confirmed removed from the source."""

    def __init__(self, message: str, *, copied: bool = False, moved: Sequence[int] = ()) -> None:
        super().__init__(message)
        self.copied = copied
        self.moved = tuple(moved)


class MoveUnsupported(MoveError):
    """The server offers neither MOVE nor UIDPLUS (UID EXPUNGE)."""


def _to_str(v: Any) -> str:
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).decode("utf-8", "replace")
    return str(v)


def _caps_set(capabilities: Iterable[Any] | None) -> frozenset[str]:
    return frozenset(_to_str(c).strip().upper() for c in (capabilities or ()) if c)


def move_method_for(capabilities: Iterable[Any] | None) -> str:
    """'MOVE' | 'UIDPLUS' | 'none' for a post-login capability list."""
    caps = _caps_set(capabilities)
    if "MOVE" in caps:
        return "MOVE"
    if "UIDPLUS" in caps:
        return "UIDPLUS"
    return "none"


def client_capabilities(client: IMAPClient) -> frozenset[str]:
    try:
        return _caps_set(client.capabilities())
    except _CONN_ERRORS:
        raise
    except IMAPClientError:
        return frozenset()


def _short_err(ex: BaseException, secret: str | None = None) -> str:
    text = f"{type(ex).__name__}: {ex}"
    if secret:
        text = text.replace(secret, "[redacted]")
    return re.sub(r"[\r\n\t]+", " ", text)[:200]


_COPYUID_RE = re.compile(rb"\[COPYUID\s+\d+\s+([0-9:,*]+)\s+([0-9:,*]+)\]", re.I)


def _parse_uid_set(spec: str, *, limit: int = 100000) -> set[int]:
    out: set[int] = set()
    for part in spec.split(","):
        if ":" in part:
            a, b = part.split(":", 1)
            lo, hi = sorted((int(a), int(b)))
            if hi - lo > limit:
                raise ValueError("uid range too large")
            out.update(range(lo, hi + 1))
        elif part:
            out.add(int(part))
    return out


def _pop_copyuid(client: Any) -> bytes:
    """imaplib files the tagged reply's [COPYUID ...] response code under
    untagged_responses and IMAPClient.copy() does not return it. Pop it
    (so a later COPY never sees a stale one) and rebuild "[COPYUID ...]"."""
    try:
        untagged = client._imap.untagged_responses
        vals = untagged.pop("COPYUID", None) or untagged.pop(b"COPYUID", None)
    except Exception:  # noqa: BLE001 - not an imaplib-backed client (tests)
        return b""
    if not vals:
        return b""
    last = vals[-1]
    return b"[COPYUID " + (last if isinstance(last, bytes) else str(last).encode()) + b"]"


def _flag_names(flags: Iterable[Any] | None) -> set[str]:
    return {_to_str(f) for f in (flags or ())}


def _kw(flags: Iterable[Any] | None) -> set[str]:
    return _flag_names(flags)


def imap_move(client: IMAPClient, uids: Iterable[int], dest: str, *,
              capabilities: Iterable[Any] | None,
              on_stage: Any = None) -> None:
    """Move UIDs of the selected folder to `dest`, or raise.

    MOVE capability: UID MOVE. Otherwise UIDPLUS emulation: UID COPY (must
    succeed) -> +\\Deleted on exactly the copied UIDs -> UID EXPUNGE of
    exactly those UIDs. Never a plain EXPUNGE, so mail the user marked
    deleted elsewhere in the folder is left alone. If marking/expunging
    fails, \\Deleted is removed again (only where we set it) and MoveError
    (copied=True) is raised. Neither capability: MoveUnsupported.
    Connection-level errors from the MOVE/COPY step propagate unchanged.

    on_stage(stage, uids, predeleted) (2.1, optional) is called BEFORE each
    mutating step so a caller can journal it: 'move' (UID MOVE), 'copy'
    (UID COPY), 'copied' (COPY done / \\Deleted rolled back), 'flag'
    (about to set \\Deleted), 'clear' (UIDs not copied, nothing to do).
    `predeleted` = UIDs that already carried \\Deleted (not ours).
    """
    uid_list = sorted({int(u) for u in uids})
    if not uid_list:
        return

    def stage(name: str, which: Sequence[int], predeleted: Iterable[int] = ()) -> None:
        if on_stage is not None and which:
            on_stage(name, list(which), set(predeleted))

    method = move_method_for(capabilities)
    if method == "none":
        raise MoveUnsupported("server supports neither MOVE nor UIDPLUS")
    if method == "MOVE":
        stage("move", uid_list)
        try:
            client.move(uid_list, dest)
        except _CONN_ERRORS:
            raise
        except IMAPClientError as ex:
            raise MoveError(f"MOVE failed: {_short_err(ex)}") from ex
        return

    # UIDPLUS emulation. Learn which UIDs exist and which already carry
    # \Deleted (set by the user's client), so a rollback only clears the
    # flags we set ourselves.
    before = client.fetch(uid_list, [b"FLAGS"])
    missing = [u for u in uid_list if u not in before]
    if missing:
        raise MoveError(f"UID(s) not found: {missing[:10]}")
    predeleted = {u for u in uid_list if "\\Deleted" in _flag_names(before[u].get(b"FLAGS"))}
    _pop_copyuid(client)  # discard a stale COPYUID from an earlier command
    stage("copy", uid_list, predeleted)
    try:
        resp = client.copy(uid_list, dest)
    except _CONN_ERRORS:
        raise
    except IMAPClientError as ex:
        raise MoveError(f"COPY failed: {_short_err(ex)}") from ex
    copied = uid_list
    resp_b = resp if isinstance(resp, (bytes, bytearray)) else _to_str(resp or "").encode()
    m = _COPYUID_RE.search(bytes(resp_b)) or _COPYUID_RE.search(_pop_copyuid(client))
    if m:
        try:
            src = _parse_uid_set(m.group(1).decode("ascii"))
            copied = [u for u in uid_list if u in src]
        except ValueError:
            copied = uid_list  # unparseable COPYUID: trust the tagged OK
    not_copied = [u for u in uid_list if u not in copied]
    stage("clear", not_copied)
    if not copied:
        raise MoveError("COPY reported no copied messages")
    stage("copied", copied, predeleted)
    stage("flag", copied, predeleted)
    try:
        client.add_flags(copied, [DELETED_FLAG], silent=True)
        client.uid_expunge(copied)
    except Exception as ex:  # noqa: BLE001 - roll back, then report
        to_clear = [u for u in copied if u not in predeleted]
        if to_clear:
            try:
                client.remove_flags(to_clear, [DELETED_FLAG], silent=True)
                stage("copied", copied, predeleted)
            except Exception as ex2:  # noqa: BLE001
                logging.getLogger("filter").error(
                    "imap_move: could not clear \\Deleted on %s after failed expunge: %s",
                    to_clear, type(ex2).__name__)
        raise MoveError(f"expunge after copy failed: {_short_err(ex)}", copied=True) from ex
    if not_copied:
        raise MoveError(f"COPY skipped UID(s) {not_copied[:10]}", copied=True, moved=copied)


_MSGID_UNSAFE_RE = re.compile(r'[\x00-\x20\x7f"\\]')


def message_id_searchable(msgid: str | None) -> bool:
    """True when a Message-ID may be used in IMAP SEARCH (ASCII, no
    quotes/backslashes/whitespace/control chars, sane length)."""
    return bool(msgid) and len(msgid) <= 500 and msgid.isascii() and not _MSGID_UNSAFE_RE.search(msgid)


_HDR_MSGID = b"BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)]"
_HDR_MSGID_FROM = b"BODY.PEEK[HEADER.FIELDS (MESSAGE-ID FROM)]"


def _header_bytes(data: dict | None) -> bytes:
    """The BODY[HEADER...] item of a FETCH reply, whatever the server's
    exact echo of the section spec."""
    for k, v in (data or {}).items():
        if isinstance(k, (bytes, bytearray)) and bytes(k).upper().startswith(b"BODY[HEADER"):
            return bytes(v or b"")
    return b""


def _body_bytes(data: dict | None) -> bytes | None:
    if not data:
        return None
    raw = data.get(b"BODY[]") or data.get(b"BODY.PEEK[]")
    return bytes(raw) if raw else None


def find_uids_by_message_id(client: IMAPClient, message_id: str, *,
                            undeleted: bool = False, collapse_copies: bool = True) -> list[int]:
    """UIDs in the selected folder whose Message-ID equals `message_id`
    exactly. SEARCH HEADER is a substring match, so every candidate is
    verified by fetching its Message-ID header (A3). Returns [] for IDs
    that are unsafe to put into a SEARCH. `undeleted` skips copies that
    carry \\Deleted (e.g. the source of a client's COPY-based move that
    has not been expunged yet).

    collapse_copies (2.1, default on): several COPIES of one message (same
    INTERNALDATE and size - e.g. left by an interrupted UIDPLUS move) count
    as one; only the newest (highest UID) is returned, the others are left
    alone. Different deliveries with the same Message-ID stay distinct."""
    identity = None
    legacy: tuple[str, int] | None = None
    if Path(DB_PATH).exists():
        conn = sqlite3.connect(DB_PATH, timeout=10)
        try:
            identity = mailidentity.binding(conn, getattr(client, "_sf_account", None), message_id)
            account = getattr(client, "_sf_account", None)
            row = (conn.execute('SELECT sender, size FROM messages WHERE account=? AND message_id=?',
                                (account, message_id)).fetchone()
                   if identity is None and account is not None else None)
            if row is not None:
                # Legacy verdicts/learns cannot select a new payload by ID
                # alone. 2.20.1: a row scanned before the identity table
                # (most caught mail in 'Tjek disse') is proven by the sender
                # address and exact size recorded at scan time - a new mail
                # reusing the ID must match both. Without them: nothing.
                sender = (parseaddr(str(row[0] or ""))[1] or "").strip().lower()
                if not sender or row[1] is None:
                    return []
                legacy = (sender, int(row[1]))
        except sqlite3.OperationalError:
            pass  # rollback / test databases without the additive table
        finally:
            conn.close()
    if identity is not None:
        wire, digest = identity
        crit = (["HEADER", "Message-ID", wire] if wire and message_id_searchable(wire) else ["ALL"])
        if undeleted:
            crit = ["UNDELETED", *crit] if crit != ["ALL"] else ["UNDELETED"]
        candidates = sorted({int(u) for u in client.search(crit)})
        matching = []
        copies = {}
        for chunk in _chunks(candidates, RECONCILE_FETCH_CHUNK):
            meta = client.fetch(list(chunk), [_HDR_MSGID, b"RFC822.SIZE", b"FLAGS", b"INTERNALDATE"])
            for uid, data in meta.items():
                if parse_envelope(_header_bytes(data))[0] != wire:
                    continue
                if int(data.get(b"RFC822.SIZE") or 0) > MAX_FETCH_BYTES:
                    continue
                raw = _body_bytes(client.fetch([uid], [b"BODY.PEEK[]"]).get(uid))
                if raw and mailidentity.fingerprint(raw) == digest:
                    matching.append(uid)
                    copies[uid] = (_internaldate_ts(data), data.get(b"RFC822.SIZE"),
                                   "\\Deleted" not in _flag_names(data.get(b"FLAGS")))
        if collapse_copies:
            best = {}
            for uid in matching:
                date, size, live = copies[uid]
                k = (date, size) if date is not None and size is not None else ("uid", uid)
                old = best.get(k)
                if old is None or (live, uid) > (copies[old][2], old):
                    best[k] = uid
            return sorted(best.values())
        return matching
    if message_id.startswith(mailidentity.PREFIX):
        return []  # missing binding: never search an internal key as a header
    target = normalize_message_id(message_id)
    if not target or not message_id_searchable(target):
        return []
    crit = ["UNDELETED", "HEADER", "Message-ID", target] if undeleted else ["HEADER", "Message-ID", target]
    cands = sorted({int(u) for u in client.search(crit)})
    if not cands:
        return []
    hdr = _HDR_MSGID_FROM if legacy is not None else _HDR_MSGID
    items = ([hdr, b"INTERNALDATE", b"RFC822.SIZE", b"FLAGS"] if collapse_copies
             else [hdr, b"RFC822.SIZE"] if legacy is not None else [hdr])
    out: list[int] = []
    keys: dict[int, tuple] = {}
    live: dict[int, bool] = {}
    for chunk in _chunks(cands, RECONCILE_FETCH_CHUNK):
        fetched = client.fetch(list(chunk), items)
        for uid in chunk:
            data = fetched.get(uid)
            mid, _subj, _from = parse_envelope(_header_bytes(data))
            if mid == target and legacy is not None and (
                    (_from or "").strip().lower() != legacy[0]
                    or int((data or {}).get(b"RFC822.SIZE") or -1) != legacy[1]):
                continue
            if mid == target:
                out.append(uid)
                if collapse_copies:
                    keys[uid] = (_internaldate_ts(data or {}), (data or {}).get(b"RFC822.SIZE"))
                    live[uid] = "\\Deleted" not in _flag_names((data or {}).get(b"FLAGS"))
    if collapse_copies and len(out) > 1:
        # Per group of identical copies keep the newest one nobody marked
        # deleted (else the newest).
        best: dict[tuple, int] = {}
        for uid in out:
            k = keys.get(uid, (None, None))
            if k[0] is None or k[1] is None:
                best[("uid", uid)] = uid   # unknown date/size: never merged
                continue
            cur = best.get(k)
            if cur is None or (live.get(uid, True), uid) > (live.get(cur, True), cur):
                best[k] = uid
        out = sorted(best.values())
    return out


def connect(acc: Account, password: str | None = None, *, timeout: float = IMAP_TIMEOUT) -> IMAPClient:
    """TLS (default context: hostname verification, system CAs) + LOGIN.
    Capabilities are fetched after login - the pre-auth list is reduced
    (Scannet/Gigahost only announce MOVE/UIDPLUS after authentication)."""
    if password is None:
        password = read_secret(acc)
    ssl_ctx = ssl.create_default_context() if acc.ssl else None
    client = IMAPClient(acc.imap_host, port=acc.imap_port, ssl=acc.ssl,
                        ssl_context=ssl_ctx, timeout=timeout)
    client._sf_account = acc.name
    try:
        client.login(acc.user, password)
        client.capabilities()
    except BaseException:
        _close_quietly(client)
        raise
    return client


def _close_quietly(client: Any) -> None:
    try:
        client.logout()
    except Exception:  # noqa: BLE001
        try:
            client.shutdown()
        except Exception:  # noqa: BLE001
            pass


def detect_delimiter(client: IMAPClient) -> str:
    try:
        folders = client.list_folders()
    except IMAPClientError:
        return "/"
    for _flags, delim, _name in folders:
        if delim:
            return delim if isinstance(delim, str) else delim.decode("ascii", "replace")
    return "/"


def resolve_folder(name: str, delim: str) -> str:
    if delim == "/" or "/" not in name:
        return name
    return name.replace("/", delim)


def build_folder_map(acc: Account, delim: str) -> dict[str, str]:
    return {
        "inbox": resolve_folder(acc.inbox, delim),
        "junk": resolve_folder(acc.junk, delim),
        "trash": resolve_folder(acc.trash, delim),
        "spam_train": resolve_folder(acc.spam_train, delim),
        "trained_spam": resolve_folder(acc.trained_spam, delim),
        "ham_train": resolve_folder(acc.ham_train, delim),
        "trained_ham": resolve_folder(acc.trained_ham, delim),
    }


def detect_special_folders(client: IMAPClient) -> dict[str, str]:
    """{'junk': name, 'trash': name} for folders carrying RFC 6154
    SPECIAL-USE flags. Empty dict if the server doesn't advertise them."""
    flag_map = {r"\Junk": "junk", r"\Trash": "trash"}
    out: dict[str, str] = {}
    for flags, _delim, name in client.list_folders():
        for f in flags or ():
            key = flag_map.get(_to_str(f))
            if key and key not in out:
                out[key] = _to_str(name)
    return out


@dataclass
class FolderSetup:
    delimiter: str
    fmap: dict[str, str]
    listing: list[tuple[list[str], str]]    # (LIST flags, name)
    junk_exists: bool
    trash_exists: bool
    created: list[str] = field(default_factory=list)


_UNSELECTABLE = frozenset({"\\NOSELECT", "\\NONEXISTENT"})
# Tried (case-insensitively) only when the account entry does not name the
# junk folder and the server has no \Junk SPECIAL-USE folder: avoids
# creating a parallel "Junk" next to an existing spam folder.
_JUNK_FALLBACK_NAMES = ("Junk", "Spam", "Junk E-mail", "Junk Email", "Uønsket post", "Uønsket e-mail")
_TRASH_FALLBACK_NAMES = ("Trash", "Deleted Items", "Deleted Messages", "Papirkurv", "Slettet post")


def _create_folder(client: IMAPClient, db: Db | None, log: logging.Logger, name: str) -> bool:
    try:
        client.create_folder(name)
    except _CONN_ERRORS:
        raise
    except IMAPClientError as ex:
        log.warning("create_folder(%s) failed: %s", name, type(ex).__name__)
        return False
    try:
        client.subscribe_folder(name)
    except _CONN_ERRORS:
        raise
    except IMAPClientError as ex:
        log.warning("subscribe_folder(%s) failed: %s", name, type(ex).__name__)
    log.info("created folder %s", name)
    if db is not None:
        db.log_event("folder_created", detail=name)
    return True


def setup_folders(client: IMAPClient, acc: Account, log: logging.Logger, db: Db | None = None) -> FolderSetup:
    """Resolve the folder map from LIST and create what the mode needs.

    Junk: an explicit per-account `junk` wins; otherwise the SPECIAL-USE
    \\Junk folder (auto_special_folders), the configured name, or a well-
    known existing name. In flag/move mode a missing junk folder is
    created + subscribed once; in shadow it is only reported. A missing
    trash is tolerated. Training folders only with training_folders: true.
    """
    listing: list[tuple[list[str], str]] = []
    delim = ""
    for flags, d, name in client.list_folders():
        listing.append((sorted(_flag_names(flags)), _to_str(name)))
        if d and not delim:
            delim = _to_str(d)
    delim = delim or "/"
    acc.delimiter = delim
    selectable = {name for flags, name in listing
                  if not ({f.upper() for f in flags} & _UNSELECTABLE)}

    def exists(name: str) -> bool:
        if name.upper() == "INBOX":
            return any(n.upper() == "INBOX" for n in selectable)
        return name in selectable

    def find_ci(cands: Iterable[str]) -> str | None:
        by_lower = {n.lower(): n for n in selectable}
        for c in cands:
            for variant in (c, f"INBOX{delim}{c}"):
                hit = by_lower.get(variant.lower())
                if hit:
                    return hit
        return None

    special: dict[str, str] = {}
    for flags, name in listing:
        for f in flags:
            key = {"\\JUNK": "junk", "\\TRASH": "trash"}.get(f.upper())
            if key and key not in special and name in selectable:
                special[key] = name

    def resolve(key: str, explicit: bool, fallbacks: tuple[str, ...]) -> str:
        configured = resolve_folder(getattr(acc, key), delim)
        if explicit:
            return configured
        if acc.auto_special_folders and special.get(key):
            return special[key]
        if exists(configured):
            return configured
        return find_ci(fallbacks) or configured

    junk = resolve("junk", acc.junk_explicit, _JUNK_FALLBACK_NAMES)
    trash = resolve("trash", acc.trash_explicit, _TRASH_FALLBACK_NAMES)
    fmap = {"inbox": resolve_folder(acc.inbox, delim), "junk": junk, "trash": trash}
    for key in TRAIN_KEYS:
        val = getattr(acc, key)
        # Default training names hang below "Junk/"; keep them below the
        # effective junk folder whatever it is called.
        if val.startswith("Junk/") and junk != "Junk":
            fmap[key] = junk + delim + resolve_folder(val[len("Junk/"):], delim)
        else:
            fmap[key] = resolve_folder(val, delim)

    # The provider's own spam folder (SPECIAL-USE \Junk or a well-known
    # name) when the filter uses a different one (e.g. "Spamfilter"): junk
    # polling watches it read-only so a user rescue out of it is honoured
    # and never bounced back.
    provider_junk = special.get("junk") or find_ci(_JUNK_FALLBACK_NAMES)
    if provider_junk and provider_junk != junk and exists(provider_junk):
        fmap["provider_junk"] = provider_junk
    # E3: the filter's own folder (e.g. "Spamfilter") is never written by
    # the provider, so unknown mail appearing there was put there by the user.
    fallback_names = {n.lower() for n in _JUNK_FALLBACK_NAMES}
    fallback_names |= {f"inbox{delim}{n}".lower() for n in _JUNK_FALLBACK_NAMES}
    if junk != special.get("junk") and junk.lower() not in fallback_names:
        fmap["filter_junk"] = junk

    created: list[str] = []
    junk_exists = exists(junk)
    if not junk_exists and acc.mode in ("flag", "move"):
        if _create_folder(client, db, log, junk):
            created.append(junk)
            junk_exists = True
            listing.append((["\\HasNoChildren"], junk))
    if acc.training_folders and acc.mode != "shadow":
        for key in TRAIN_KEYS:
            name = fmap[key]
            if not exists(name) and name not in created:
                if _create_folder(client, db, log, name):
                    created.append(name)
                    listing.append((["\\HasNoChildren"], name))
    return FolderSetup(delimiter=delim, fmap=fmap, listing=listing,
                       junk_exists=junk_exists, trash_exists=exists(trash), created=created)


def folder_status_listing(client: IMAPClient, listing: list[tuple[list[str], str]],
                          status_for: Iterable[str]) -> list[dict]:
    """[{"name","flags","messages"}] for account_status.folders; STATUS
    MESSAGES only for the named folders (INBOX + junk)."""
    want = set(status_for)
    out: list[dict] = []
    for flags, name in listing[:MAX_STATUS_FOLDERS]:
        messages = None
        if name in want and not ({f.upper() for f in flags} & _UNSELECTABLE):
            try:
                st = client.folder_status(name, [b"MESSAGES"])
                val = st.get(b"MESSAGES", st.get("MESSAGES"))
                messages = int(val) if val is not None else None
            except _CONN_ERRORS:
                raise
            except (IMAPClientError, ValueError, TypeError):
                messages = None
        out.append({"name": name, "flags": list(flags), "messages": messages})
    return out


def select_with_uidvalidity_check(
    client: IMAPClient, db: Db, folder: str, log: logging.Logger, readonly: bool = False
) -> int:
    info = client.select_folder(folder, readonly=readonly)
    uv = int(info[b"UIDVALIDITY"])
    stored = db.get_uidvalidity(folder)
    if stored is not None and stored != uv:
        log.warning("UIDVALIDITY changed for %s: %d -> %d, resyncing", folder, stored, uv)
        with db.tx():
            db.log_event("uidvalidity_change", detail=f"{folder} {stored}->{uv}")
            # Only this folder's UID-keyed state is invalid; other folders
            # keep their pending moves and bookmarks.
            db.conn.execute(
                "DELETE FROM pending_move WHERE account=? AND folder=? AND uidvalidity=?",
                (db.account, folder, stored),
            )
            for table in ("scan_bookmark", "junk_bookmark"):
                db.conn.execute(
                    f"DELETE FROM {table} WHERE account=? AND folder=? AND uidvalidity=?",
                    (db.account, folder, stored),
                )
            # A UIDVALIDITY reset usually means the mailbox was rebuilt;
            # do not learn from moves we observed before it.
            cancelled = db.conn.execute(
                """
                UPDATE messages SET pending_learn=NULL, pending_learn_at=NULL
                 WHERE account=? AND current_folder=? AND pending_learn IS NOT NULL
                """,
                (db.account, folder),
            ).rowcount
            if cancelled:
                db.log_event("pending_canceled_uidvalidity",
                             detail=f"{folder} cleared {cancelled} pending_learn rows")
    if stored != uv:
        with db.tx():
            db.set_uidvalidity(folder, uv)
    return uv


def normalize_message_id(value: Any) -> str | None:
    """The normaliser shared by parse_envelope and Message-ID matching:
    the text inside the first <...>, else the stripped header value."""
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    m = re.search(r"<([^>]+)>", s)
    if m:
        s = m.group(1)
    return s or None


def _decode_header_text(value: Any) -> str:
    if value is None:
        return ""
    s = str(value)
    if "=?" in s:
        try:
            s = str(email.header.make_header(email.header.decode_header(s)))
        except Exception:  # noqa: BLE001 - keep the raw text
            pass
    return re.sub(r"[\r\n\t]+", " ", s).strip()


def parse_envelope(raw: bytes) -> tuple[str | None, str, str]:
    """Return (message_id, subject, sender_address). Never raises. Works on
    a full message or a header block."""
    try:
        msg = email.message_from_bytes(raw or b"", policy=email.policy.compat32)
        msgid = normalize_message_id(msg.get("Message-ID", ""))
        subject = _decode_header_text(msg.get("Subject", ""))[:500]
        sender = parseaddr(str(msg.get("From", "") or ""))[1][:200]
        return (msgid, subject, sender)
    except Exception:  # noqa: BLE001
        return (None, "", "")


def _return_path(raw: bytes) -> str | None:
    try:
        msg = email.message_from_bytes(raw or b"", policy=email.policy.compat32)
        addr = parseaddr(str(msg.get("Return-Path", "") or ""))[1].strip()
        return addr[:200] or None
    except Exception:  # noqa: BLE001
        return None


def _internaldate_ts(data: dict) -> int | None:
    """Convert an IMAP FETCH INTERNALDATE value to a unix timestamp."""
    dt = (data or {}).get(b"INTERNALDATE")
    if dt is None:
        return None
    try:
        return int(dt.timestamp())
    except (AttributeError, OverflowError, OSError, ValueError):
        return None


def first_recipient(raw: bytes, fallback: str) -> str:
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)
        addrs = getaddresses(msg.get_all("To", []) + msg.get_all("Cc", []))
        for _name, addr in addrs:
            if addr:
                return addr
    except Exception:  # noqa: BLE001
        pass
    return fallback


def fetch_chunked(
    client: IMAPClient, uids: list[int], items: list[bytes], chunk: int = SCAN_FETCH_CHUNK
) -> Iterator[tuple[int, dict]]:
    """Yield (uid, data) pairs, FETCHing in batches to bound memory."""
    for start in range(0, len(uids), chunk):
        batch = client.fetch(uids[start:start + chunk], items)
        yield from batch.items()


# ---------------------------------------------------------------------------
# Per-account worker
# ---------------------------------------------------------------------------


@dataclass
class AccountState:
    last_junk_poll: float = 0.0          # monotonic
    last_junk_reconcile: float = 0.0     # monotonic; 0 = never
    last_retention: float = 0.0          # monotonic
    scan_fail_streak: int = 0
    rspamd_backoff_until: float = 0.0    # monotonic
    rspamd_backoff_s: float = 0.0
    caps: frozenset = frozenset()
    junk_exists: bool = True
    trash_exists: bool = True
    bookmark_lag: int = 0
    last_scan_at: int | None = None
    # UIDs finished this session but still above a held-back bookmark
    # (a lower UID awaits a retry): never re-fetched or re-scored.
    processed: dict[tuple[str, int], set[int]] = field(default_factory=dict)
    move_failures: dict[tuple[int, int], int] = field(default_factory=dict)
    # 2.3 (contacts.py): LIST of this connection, the contact sync plan and
    # its timers (monotonic).
    folder_listing: list = field(default_factory=list)
    folder_delimiter: str = ""
    contacts_plan: Any = None
    contacts_busy: bool = False           # initial sync pending: short IDLE waits
    contacts_next_status: float = 0.0     # next STATUS UIDNEXT of the Sent folders
    contacts_request_seen: str | None = None
    contacts_last_fresh: float = 0.0      # last freshness (incremental) Sent sync

    def processed_for(self, folder: str, uv: int) -> set[int]:
        key = (folder, uv)
        if key not in self.processed:
            # Drop sets of other uidvalidities of this folder.
            for k in [k for k in self.processed if k[0] == folder]:
                del self.processed[k]
            self.processed[key] = set()
        return self.processed[key]


_HEARTBEAT_LOCK = threading.Lock()


def _atomic_write(path: Path, text: str, mode: int = 0o644) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    tmp.write_text(text)
    try:
        os.chmod(tmp, mode)
    except OSError:
        pass
    tmp.replace(path)


def heartbeat() -> None:
    """Write "<unix_ts> <boot_id>" atomically (healthcheck contract)."""
    with _HEARTBEAT_LOCK:
        try:
            _atomic_write(_state_file("heartbeat"), f"{int(_now())} {BOOT_ID}")
        except OSError as ex:
            logging.getLogger("main").warning("heartbeat write failed: %s", ex)


def _start_boot() -> None:
    """Delete a heartbeat left by an earlier run and publish this run's
    boot id, so the healthcheck cannot pass on stale state."""
    try:
        _state_file("heartbeat").unlink(missing_ok=True)
    except OSError as ex:
        logging.getLogger("main").warning("cannot remove old heartbeat: %s", ex)
    try:
        _atomic_write(_state_file("boot_id"), BOOT_ID)
    except OSError as ex:
        logging.getLogger("main").warning("cannot write boot_id: %s", ex)


def request_reload(*_args: Any, **_kwargs: Any) -> None:
    """Ask the engine to restart cleanly (touches /state/reload_requested)."""
    path = _state_file("reload_requested")
    path.touch()


_RATE_LOG_LOCK = threading.Lock()
_RATE_LOG_LAST: dict[tuple[str, str], float] = {}


def check_rate(db: Db, log: logging.Logger, action: str, limit: int) -> bool:
    """True if allowed, False if the hourly limit is reached (soft refusal)."""
    count = db.rate_count(action, 3600)
    if count >= limit:
        key = (db.account, action)
        now = time.monotonic()
        with _RATE_LOG_LOCK:
            last = _RATE_LOG_LAST.get(key)
            should_log = last is None or (now - last) > 60
            if should_log:
                _RATE_LOG_LAST[key] = now
        if should_log:
            log.warning("%s rate limit hit (%d/%d per hour), refusing for now",
                        action, count, limit)
            db.log_event("rate_limited", detail=f"{action} {count}/{limit}")
        return False
    return True


# ----- learning -----------------------------------------------------------


OWN_MSGID_SUFFIX = "@" + RECEIPT_MSGID_DOMAIN   # receipts, reports, threat notices, mailer notifications


def is_own_registered(conn: sqlite3.Connection, account: str, message_id: str | None) -> bool:
    """A mail THIS filter created: our Message-ID domain AND a registration
    (daily_receipts row for this mailbox - receipts, weekly reports, threat
    notices - or a mail_outbox row of the mailer). A forged look-alike has
    no registration and is scanned/learned like any other mail."""
    mid = str(message_id or "").strip().strip("<>").strip()
    if not mid.lower().endswith(OWN_MSGID_SUFFIX):
        return False
    try:
        if conn.execute("SELECT 1 FROM daily_receipts WHERE account=? AND message_id=? LIMIT 1",
                        (account, mid)).fetchone() is not None:
            return True
    except sqlite3.Error:
        pass
    try:
        return conn.execute("SELECT 1 FROM mail_outbox WHERE message_id=? LIMIT 1",
                            (f"<{mid}>",)).fetchone() is not None
    except sqlite3.Error:
        return False


def learn_message(db: Db, acc: Account, raw: bytes, kind: str, message_id: str | None, *,
                  actor: str = "", reason: str = "", bypass_rate: bool = False,
                  allow_threat: bool = False, bypass_cooldown: bool = False) -> str:
    """Single learn entry point (A2) for engine, services and trainer.

    Returns 'learned' | 'already' | 'declined' | 'held_out' | 'rate_limited' | 'error'.
    Applies the safeguards: hourly learn limit (unless bypass_rate),
    flip-flop cooldown between opposite learns, 'unlearnable' bookkeeping
    for content rspamd refuses, events and stats. Does not gate on mode:
    explicit WebUI actions and training jobs may learn for any account.
    2.3 (B16): a message stored with a threat class is never learned as
    ham ('declined', event threat_ham_refused) unless allow_threat=True
    (an administrator's explicit, confirmed choice).
    Our own mails (receipts, reports, threat notices, notifications; see
    is_own_registered) are never learned ('declined'). bypass_cooldown
    (Bayes rebuild jobs only) skips the flip-flop cooldown.
    """
    if kind not in ("spam", "ham"):
        raise ValueError(f"invalid learn kind {kind!r}")
    log = logging.getLogger(acc.name)
    if holdout.reserved(db.conn, raw):
        return _holdout_learn_result(db, message_id)
    if message_id and is_own_registered(db.conn, db.account, message_id):
        log.info("not learning %s: a mail this filter created", message_id)
        return "declined"
    now = int(_now())
    detail = reason or kind
    if actor:
        detail = f"{detail} by {actor}"
    if db.in_safe_mode("learning"):
        log.warning("skip learn (%s) for %s: in safe mode", kind, message_id)
        return "rate_limited"
    row = db.get_message(message_id) if message_id else None
    if kind == "ham" and row is not None and _row_get(row, "threat") and not allow_threat:
        log.warning("refusing to learn %s as ham: threat %s", message_id, row["threat"])
        with db.tx():
            if row["pending_learn"] is not None:
                db.update_message(message_id, pending_learn=None, pending_learn_at=None)
            db.log_event("threat_ham_refused", message_id, detail=f"{row['threat']} {detail}"[:300])
        return "declined"
    if row is not None:
        learned = row["learned_as"]
        if learned == kind:
            # Already in that class: skip the POST (rspamd would say 208
            # and burn a rate slot) and resolve any pending learn.
            if row["pending_learn"] is not None:
                with db.tx():
                    db.update_message(message_id, pending_learn=None, pending_learn_at=None)
            return "already"
        if learned == "unlearnable" and now - (row["learned_at"] or 0) < UNLEARNABLE_RETRY_S:
            if row["pending_learn"] is not None:
                with db.tx():
                    db.update_message(message_id, pending_learn=None, pending_learn_at=None)
            return "declined"
        if (learned in ("spam", "ham") and not bypass_cooldown
                and now - (row["learned_at"] or 0) < FLIP_FLOP_COOLDOWN_S):
            log.warning("skip learn (%s) for %s: flip-flop cooldown active", kind, message_id)
            db.log_event("learn_flipflop_block", message_id, detail=f"{learned}->{kind}")
            return "rate_limited"
    if not bypass_rate and not check_rate(db, log, "learn", acc.max_learns_per_hour):
        return "rate_limited"
    outcome = rspamd_learn(raw, kind, bayes_identity(acc))
    if outcome == "held_out":
        return _holdout_learn_result(db, message_id)
    if outcome == "error":
        log.warning("rspamd learn(%s) failed for %s", kind, message_id)
        db.log_event("learn_failed", message_id, detail=f"{kind} {detail}"[:300])
        return "error"
    if outcome == "declined":
        # rspamd processed it and learned nothing. Live this is almost always
        # its learn condition "already in class <kind>" (Bayes is > 95 % sure),
        # rarely too few tokens. Record the message as being in that class:
        # the same learn again is futile ('already'), but the OPPOSITE learn
        # (a later Frigiv after 'Det er spam') must still be POSTed - the old
        # 'unlearnable' mark blocked it for 30 days.
        log.info("rspamd declined to learn %s as %s", message_id, kind)
        with db.tx():
            if row is not None:
                db.update_message(message_id, learned_as=kind, learned_at=now,
                                  pending_learn=None, pending_learn_at=None)
            db.log_event("learn_skipped", message_id, detail=kind)
        return "declined"
    # 'learned' or 'already': the message is in the desired Bayes class.
    with db.tx():
        if row is not None:
            db.update_message(message_id, learned_as=kind, learned_at=now,
                              pending_learn=None, pending_learn_at=None)
        if message_id:
            _ledger_record(db.conn, db.account, message_id, kind, now, reason or kind)
        if message_id and reason != "autolearn":
            # A later explicit learn of the other class reverts an autolearn.
            db.conn.execute(
                "UPDATE autolearn_log SET reverted_at=COALESCE(reverted_at, ?), "
                "reverted_by=COALESCE(reverted_by, ?) WHERE account=? AND message_id=? AND kind!=?",
                (now, (actor or reason or "user")[:80], db.account, message_id, kind))
        if not bypass_rate:
            db.record_rate("learn")
        db.log_event(f"learn_{kind}", message_id, detail=detail[:300])
        if outcome == "learned":
            db.bump(f"learned_{kind}")
    log.info("learned %s as %s (%s): %s", message_id, kind, reason or "-", outcome)
    return outcome


def _holdout_learn_result(db: Db, message_id: str | None) -> str:
    """Terminal skip without a learned_as mark, ledger entry or learn count."""
    with db.tx():
        if message_id and db.get_message(message_id) is not None:
            db.update_message(message_id, pending_learn=None, pending_learn_at=None)
        db.log_event("learn_held_out", message_id, detail="reserveret prøvemateriale; ingen læring")
    return "held_out"


def _ledger_record(conn: sqlite3.Connection, account: str, message_id: str, kind: str,
                   ts: int, source: str) -> None:
    """B6: remember the Bayes class of a learned message (learn_ledger)."""
    try:
        conn.execute(
            "INSERT INTO learn_ledger(account, message_id, kind, learned_at, source) VALUES(?,?,?,?,?) "
            "ON CONFLICT(account, message_id) DO UPDATE SET kind=excluded.kind, "
            "learned_at=excluded.learned_at, source=excluded.source",
            (account, message_id, kind, int(ts), str(source or kind)[:120]))
    except sqlite3.OperationalError as ex:  # table missing (DB from an older image)
        logging.getLogger("filter").debug("learn_ledger: %s", type(ex).__name__)


# ----- B6c: ham guard ------------------------------------------------------

# Never learn a message as ham when one of these is present: phishing /
# impersonation rules (2.2 B3/B4) and threat-class symbols (B16 feeds).
HAM_GUARD_SYMBOLS = frozenset({
    "TH_BRAND_SPOOF", "TH_FROM_NAME_HOMOGLYPH", "TH_LURE_COMBO", "TH_FROM_ABUSED_TLD",
    "DBL_PHISH", "DBL_MALWARE", "PH_SURBL_MULTI", "URLHAUS_MALWARE_URL", "CLAM_VIRUS",
    "CLAM_PHISH", "TH_ATTACH_BLOCK", "TH_IMPERSONATION", "TH_LOOKALIKE_DOMAIN",
    "TH_NAME_SPOOF",  # 2.7: display name of one of the owner's own people
    # 2.6 (A1): TH_SUBJECT_BRAND_SPOOF is deliberately NOT here: a third
    # party can name a brand in a lure-like subject legitimately, and a mail
    # the user released must stay learnable as ham.
})
HAM_GUARD_PREFIXES = ("PHISHED_",)
# rspamd's phishing module adds these informational (weight 0) symbols for
# URLs it did NOT flag: PHISHED_EXCLUDED fires for every link to a host in
# phishing_feed_exclusion.inc (the owner's own webshops, B5), whether or not
# a feed matched. They are never phishing evidence (ui_kit already treats
# PHISHED_EXCLUDED as informational). Skipped by the ham guard, the B2
# URL-reputation check and services' Bayes repair candidates.
PHISHED_INFO = frozenset({"PHISHED_EXCLUDED", "PHISHED_GENERIC_SERVICE"})
HAM_GUARD_BLIND_MAX = 5.0
# Our own negative trust pseudo-symbols (2.1 newsletter, 2.2 B10-B12): they
# may keep a mail under the threshold, but never make it ham evidence.
TRUST_SYMBOLS = frozenset({"TH_NEWSLETTER", "TH_KNOWN_CONTACT", "TH_KNOWN_DOMAIN", "TH_REPLY",
                           "TH_REPLY_THREAD", "TH_ESTABLISHED"})
HAM_GUARD_REPLY_MAX = 2.0
HAM_GUARD_TEXT = {
    "blind_score": "scoren uden Bayes og udbyder er 5 eller mere",
    "phishing": "phishing- eller trusselsregel ramte",
    "blocked_sender": "afsenderen er blokeret",
    "trust_only": "kun under grænsen pga. egne bonusser",
}


def _symbol_list(symbols: Any) -> list[dict]:
    if isinstance(symbols, (str, bytes)):
        try:
            symbols = json.loads(symbols)
        except (TypeError, ValueError):
            return []
    return [x for x in (symbols or []) if isinstance(x, dict) and x.get("n")]


def guard_blind_score(final: Any, symbols: Any) -> float | None:
    """Score without Bayes, the provider's verdict (trainer.blind_score) and
    without our own trust bonuses."""
    syms = _symbol_list(symbols)
    try:
        import trainer  # noqa: PLC0415 - pure helper, same image

        blind = trainer.blind_score(final, syms)
    except Exception:  # noqa: BLE001
        blind = None
    if blind is None:
        return None
    for x in syms:
        if x["n"] in TRUST_SYMBOLS:
            try:
                blind -= float(x.get("s") or 0)
            except (TypeError, ValueError):
                pass
    return round(blind, 3)


def _blocked_sender(conn: sqlite3.Connection, account: str, sender: str | None) -> str | None:
    """A block rule for the sender's address or (any level of) its domain."""
    parts = _sender_parts(sender)
    if parts is None:
        return None
    local, domain = parts
    labels = domain.split(".")
    patterns = [f"{local}@{domain}"] + ["@" + ".".join(labels[i:]) for i in range(len(labels) - 1)]
    row = conn.execute(
        f"SELECT pattern FROM sender_rules WHERE kind='block' AND account IN (?, '*') "
        f"AND pattern IN ({','.join('?' * len(patterns))}) LIMIT 1", (account, *patterns)).fetchone()
    return str(row[0]) if row else None


def ham_guard_reason(conn: sqlite3.Connection | None, account: str, *, symbols: Any,
                     final: Any, rspamd_score: Any, sender: str | None = None,
                     envelope_from: str | None = None, trust_limit: float | None = None
                     ) -> tuple[str, str] | None:
    """B6c: why a message must NOT be learned as ham, as (code, detail), or
    None. Codes: 'phishing' (HAM_GUARD_SYMBOLS / PHISHED_* except
    PHISHED_INFO), 'blind_score'
    (guard_blind_score >= 5), 'blocked_sender' (a block rule for the sender
    or its domain), 'trust_only' (rspamd's own score above `trust_limit`:
    only our trust bonuses kept it low; TH_REPLY allows up to 2.0 when
    trust_limit is AUTOLEARN_HAM_MAX_SCORE)."""
    syms = _symbol_list(symbols)
    names = {str(x["n"]) for x in syms}
    hits = sorted(n for n in names if n in HAM_GUARD_SYMBOLS
                  or (n.startswith(HAM_GUARD_PREFIXES) and n not in PHISHED_INFO))
    if "CLAM_VIRUS" in hits and clam_heuristic_only(names, syms):
        # 2.8: a heuristic / third-party ClamAV hit is a score, not proof:
        # a mail the user released must stay learnable as ham.
        hits.remove("CLAM_VIRUS")
    if hits:
        return "phishing", ",".join(hits)[:200]
    blind = guard_blind_score(final, syms)
    if blind is not None and blind >= HAM_GUARD_BLIND_MAX:
        return "blind_score", f"blind={blind:g}"
    if conn is not None:
        for addr in (sender, envelope_from):
            try:
                pat = _blocked_sender(conn, account, addr) if addr else None
            except sqlite3.Error:
                pat = None
            if pat:
                return "blocked_sender", pat
    if trust_limit is not None:
        raw = _untrusted_score(final, rspamd_score, syms)
        limit = float(trust_limit)
        if "TH_REPLY" in names and limit == AUTOLEARN_HAM_MAX_SCORE:
            limit = max(limit, HAM_GUARD_REPLY_MAX)
        if raw is not None and raw > limit:
            return "trust_only", f"uden bonus={raw:g} > {limit:g}"
    return None


def _untrusted_score(final: Any, rspamd_score: Any, syms: list[dict]) -> float | None:
    """The score without our own trust bonuses (TRUST_SYMBOLS). Error
    corrections (TH_OWN_PLATFORM_URIBL, aged-mode TH_PROVIDER_AUTH_*) and
    the provider bonus stay in; falls back to rspamd's own score."""
    try:
        if final is not None:
            total = float(final)
            for x in syms:
                if x["n"] in TRUST_SYMBOLS:
                    total -= float(x.get("s") or 0)
            return round(total, 3)
        return float(rspamd_score) if rspamd_score is not None else None
    except (TypeError, ValueError):
        return None


def try_learn(
    db: Db, log: logging.Logger, acc: Account, raw: bytes, msgid: str, kind: str, reason: str
) -> bool:
    """Engine-internal learn from observed user moves. Shadow mode never
    learns; learn_from_moves gates it. True = resolved (learned, already
    learned or terminally declined), False = refused/failed (retry later)."""
    if acc.mode == "shadow" or not acc.learn_from_moves:
        return False
    res = learn_message(db, acc, raw, kind, msgid, actor="engine", reason=reason)
    return res in ("learned", "already", "declined", "held_out")


# ----- status texts (Danish, shown in the WebUI) ---------------------------


def _mode_detail(acc: Account, state: AccountState) -> str:
    junk = acc.folder_map.get("junk") or acc.junk
    if acc.mode == "shadow":
        text = "Overvåger indbakken – flytter intet"
        if not state.junk_exists:
            text += f". Spam-mappen ({junk}) findes ikke endnu; den oprettes ved Markér/Filtrér"
        return text
    if not state.junk_exists:
        return f"Spam-mappen ({junk}) mangler og kunne ikke oprettes"
    if acc.mode == "move" and move_method_for(state.caps) == "none":
        return "Serveren kan ikke flytte mails (hverken MOVE eller UIDPLUS)"
    if acc.mode == "flag":
        return "Markerer spam i indbakken"
    return f"Filtrerer spam til {junk}"


# ----- scan / poll / drain -------------------------------------------------


@dataclass
class _InboxMeta:
    uid: int
    flags: set[str]
    size: int | None
    received_at: int | None
    msgid: str
    prior: sqlite3.Row | None
    raw: bytes | None = None


Decision = decisionpolicy.Decision
_sticky_ham = decisionpolicy.sticky_ham


def _spam_folders(fmap: dict[str, str]) -> list[str]:
    """Our junk folder, plus the provider's own one when it differs."""
    out = [fmap["junk"]]
    if fmap.get("provider_junk") and fmap["provider_junk"] != fmap["junk"]:
        out.append(fmap["provider_junk"])
    return out


def _rescue_source(prior: sqlite3.Row, fmap: dict[str, str]) -> str | None:
    """The folder a Message-ID was last known in, if that was a spam folder
    (filter move, junk poll, user/WebUI junking). None otherwise."""
    cf = prior["current_folder"]
    if prior["our_action"] == "move_failed" and prior["moved_to_junk_at"]:
        # A move that failed after its COPY: a copy may sit in junk (or the
        # expunge landed and only the reply was lost). Let the presence
        # check decide between a rescue and a duplicate.
        return fmap["junk"]
    if cf == fmap["inbox"]:
        return None
    if (cf in _spam_folders(fmap) or cf == "gone" or prior["moved_to_junk_at"]
            or prior["our_action"] in JUNK_ACTIONS or prior["origin"] == "junk_poll"):
        return cf
    return None


def _retry_due_at(row: sqlite3.Row) -> float:
    return row["first_fail_at"] + SCAN_RETRY_BASE_S * (2 ** int(row["attempts"]) - 1)


def _scan_failed(db: Db, log: logging.Logger, uv: int, uid: int, error: str,
                 processed: set[int]) -> bool:
    """Record a per-message scan failure. Returns True when the message was
    given up (5 attempts or 6 h): the bookmark may then pass it."""
    with db.tx():
        row = db.record_scan_failure(uv, uid, error)
        attempts = int(row["attempts"])
        if attempts >= SCAN_RETRY_MAX_ATTEMPTS or int(_now()) - row["first_fail_at"] >= SCAN_RETRY_MAX_AGE_S:
            db.mark_scan_given_up(uv, uid)
            db.log_event("scan_giveup", detail=f"uid={uid} attempts={attempts}: {error}"[:300])
            db.bump("scan_giveup")
            gave_up = True
        else:
            db.log_event("scan_failed", detail=f"uid={uid} attempt={attempts}: {error}"[:300])
            db.bump("scan_failed")
            gave_up = False
    if gave_up:
        log.error("giving up on inbox uid %s after %d attempts: %s", uid, attempts, error)
        processed.add(uid)
    else:
        log.warning("scan of inbox uid %s failed (attempt %d): %s", uid, attempts, error)
    return gave_up


def _enter_rspamd_backoff(db: Db, log: logging.Logger, state: AccountState, why: str) -> None:
    state.rspamd_backoff_s = min(max(state.rspamd_backoff_s * 2, RSPAMD_BACKOFF_MIN_S),
                                 RSPAMD_BACKOFF_MAX_S)
    state.rspamd_backoff_until = time.monotonic() + state.rspamd_backoff_s
    state.scan_fail_streak += 1
    log.error("rspamd unavailable (%s); pausing scans for %ds", why, state.rspamd_backoff_s)
    db.log_event("rspamd_unavailable", detail=f"{why} backoff={int(state.rspamd_backoff_s)}s")
    db.status_error(category="rspamd", text=why,
                    detail="Rspamd svarer ikke – scanning genoptages automatisk")


def _present_elsewhere(client: IMAPClient, db: Db, log: logging.Logger, folder: str,
                       msgid: str, inbox: str, uv: int, readonly: bool) -> bool:
    """Is `msgid` still in `folder`? Read-only look, then re-select the
    inbox. Any doubt (folder gone, unsearchable ID) counts as 'not there',
    which errs towards treating an inbox copy as a user rescue. Copies
    flagged \\Deleted do not count: clients without MOVE (Gigahost) move
    by COPY + STORE \\Deleted and expunge later, sometimes much later."""
    found = False
    if folder != "gone":
        try:
            client.select_folder(folder, readonly=True)
            found = bool(find_uids_by_message_id(client, msgid, undeleted=True))
        except _CONN_ERRORS:
            raise
        except IMAPClientError as ex:
            log.info("presence check in %s failed (%s); treating as moved out",
                     folder, type(ex).__name__)
    uv2 = select_with_uidvalidity_check(client, db, inbox, log, readonly=readonly)
    if uv2 != uv:
        raise IMAPClientError("inbox UIDVALIDITY changed during scan")
    return found


def _handle_rescue(db: Db, log: logging.Logger, acc: Account, fmap: dict[str, str],
                   msgid: str, prior: sqlite3.Row, source: str, *, proven: bool = True) -> None:
    """The user moved mail out of a spam folder into the inbox: sticky ham
    verdict, never scored or moved again, learn ham after the grace.
    proven=False: the inbox copy is not provably the moved copy (different
    INTERNALDATE) - kept, but the sender is not auto-allowed.
    A threat (B16) dragged out is kept where the user put it, but never
    learned as ham, never allows the sender and never counts as kept for
    the contact signals (event threat_rescue_ignored_learning)."""
    now = int(_now())
    released = prior["our_action"] == "manual_release"
    threat = _row_get(prior, "threat")
    fields: dict[str, Any] = dict(current_folder=fmap["inbox"], last_seen=now,
                                  user_verdict="ham", verdict_at=now,
                                  verdict_by=prior["verdict_by"] if released else "user:move")
    if not released:
        fields["our_action"] = "user_rescued"
    if (acc.mode != "shadow" and acc.learn_from_moves and prior["learned_as"] != "ham"
            and prior["pending_learn"] != "ham" and not threat):
        fields.update(pending_learn="ham", pending_learn_at=now)
    if threat and prior["pending_learn"] == "ham":
        fields.update(pending_learn=None, pending_learn_at=None)
    with db.tx():
        db.update_message(msgid, **fields)
        db.drop_pending_moves_for(msgid)
        db.conn.execute("DELETE FROM rescan_queue WHERE account=? AND message_id=?", (db.account, msgid))
        db.log_event("user_rescued", msgid, detail=f"from {source}")
        _junk_rules_after_user_ham(db, log, acc, msgid, prior['sender'])
        # 2.6 (A2): a source of a campaign sweep is back: its copies stay.
        _campaigns().cancel_for_source(db.conn, db.account, msgid, now=now, reason="flyttet tilbage")
        if threat:
            db.log_event("threat_rescue_ignored_learning", msgid,
                         detail=f"{threat}: {_row_get(prior, 'threat_detail') or '-'}"[:300])
        else:
            _contacts_user_ham(db, log, acc, prior["sender"], prior["our_action"])
        if not released:
            db.bump("user_rescued")
    log.info("user rescued %s from %s", msgid, source)
    if threat:
        log.warning("threat mail %s (%s) moved out of %s by the user: not learned, sender not allowed",
                    msgid, threat, source)
        return
    if not released and proven and acc.mode != "shadow" and acc.auto_allow_on_rescue:
        if _recent_webui_release(db, msgid):
            # A WebUI 'Frigiv' raced us (IMAP move before its bookkeeping):
            # a release is not an allow decision.
            return
        _auto_allow_sender(db, log, acc, msgid, prior["sender"])


AUTO_ALLOW_BY = "auto:flytning"
_WEBUI_RELEASE_EVENTS = ("manual_release", "undo_release", "found_to_inbox")


def _recent_webui_release(db: Db, msgid: str, window_s: int = 120) -> bool:
    """Defence in depth: a WebUI release of this Message-ID in the last
    `window_s` seconds (services premarks the row first; this covers an
    older/other writer)."""
    try:
        row = db.conn.execute(
            f"SELECT 1 FROM events WHERE account=? AND message_id=? AND event IN "
            f"({','.join('?' * len(_WEBUI_RELEASE_EVENTS))}) AND ts>=? LIMIT 1",
            (db.account, msgid, *_WEBUI_RELEASE_EVENTS, int(_now()) - window_s)).fetchone()
    except sqlite3.Error:
        return False
    return row is not None


def _rule_patterns_for(sender: str | None) -> tuple[str, list[str]] | None:
    """(exact pattern, every pattern that matches this address) or None."""
    parts = _sender_parts(sender)
    if parts is None:
        return None
    local, domain = parts
    labels = domain.split(".")
    exact = f"{local}@{domain}"
    return exact, [exact] + ["@" + ".".join(labels[i:]) for i in range(len(labels))]


def _force_rule_covering(conn: sqlite3.Connection, account: str,
                         sender: str | None) -> sqlite3.Row | None:
    """An 'Altid igennem' rule (account or global) that matches `sender`."""
    pats = _rule_patterns_for(sender)
    if pats is None:
        return None
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    return cur.execute(
        f"SELECT * FROM sender_rules WHERE account IN (?, '*') AND kind='allow' AND force=1 "
        f"AND pattern IN ({','.join('?' * len(pats[1]))}) LIMIT 1",
        (account, *pats[1])).fetchone()


def revoke_auto_allow(conn: sqlite3.Connection, account: str, sender: str | None) -> int | None:
    """Delete the account's exact-address allow rule for `sender` when the
    filter made it automatically (created_by 'auto:flytning'): the user's
    latest decision ('this is spam') wins. Rules made by hand are never
    touched and no block rule is created. Returns the deleted rule id.
    The caller handles the transaction/event."""
    pats = _rule_patterns_for(sender)
    if pats is None:
        return None
    row = conn.execute(
        "SELECT id FROM sender_rules WHERE account=? AND pattern=? AND kind='allow' "
        "AND created_by=?", (account, pats[0], AUTO_ALLOW_BY)).fetchone()
    if row is None:
        return None
    conn.execute("DELETE FROM sender_rules WHERE id=?", (int(row[0]),))
    return int(row[0])


def _revoke_auto_allow_logged(db: Db, log: logging.Logger, acc: Account, msgid: str,
                              sender: str | None) -> None:
    """Inside db.tx(): revoke_auto_allow + event."""
    try:
        rid = revoke_auto_allow(db.conn, acc.name, sender)
    except sqlite3.Error as ex:
        log.warning("auto-allow revoke for %s failed: %s", acc.name, type(ex).__name__)
        return
    if rid is not None:
        db.log_event("rule_auto_allow_removed", msgid, detail=f"rule={rid}")
        log.info("removed auto-allow rule %s for %s: mail put into spam", rid, acc.name)


_OWNER_PROTECTION_CACHE: dict[str, Any] = {}


def _owner_protection(acc: Account) -> Any:
    """junkrules.owner_protection over every configured mailbox (cached
    5 min; on a config read error at least this mailbox)."""
    jr = _junkrules()
    hit = _OWNER_PROTECTION_CACHE.get("v")
    accs: list[Any] | None = None
    if hit is not None and time.monotonic() - hit[0] < 300:
        accs = hit[1]
    else:
        try:
            accs = list(load_account_configs())
            _OWNER_PROTECTION_CACHE["v"] = (time.monotonic(), accs)
        except Exception:  # noqa: BLE001 - missing/broken config: this mailbox only
            accs = []
    if not any(getattr(a, "name", None) == acc.name for a in accs):
        accs = [*accs, acc]
    return jr.owner_protection(accs, (*DEFAULT_OWNER_PLATFORM_DOMAINS, *DEFAULT_WEBSHOP_DOMAINS))


def from_authenticated(symbols: Any, sender: str | None) -> bool:
    """2.12 (#9): the header From of a scanned mail was proven - DMARC pass
    (rspamd DMARC_POLICY_ALLOW or the provider's TH_PROVIDER_AUTH_PASS), or
    TH_NEWSLETTER / a valid DKIM signature aligned with the From domain -
    and no sign says the From is forged (ALLOW_DISTRUST_SYMBOLS). Unknown
    (never scanned) = not authenticated."""
    syms = _symbol_list(symbols)
    names = {str(x["n"]) for x in syms}
    if not names or names & ALLOW_DISTRUST_SYMBOLS:
        return False
    if names & {"DMARC_POLICY_ALLOW", "TH_PROVIDER_AUTH_PASS", "TH_NEWSLETTER"}:
        return True
    parts = _sender_parts(sender) if sender else None
    if not parts:
        return False
    dkim = [str(o).split(":", 1)[0].strip().lower().rstrip(".")
            for x in syms if x["n"] == "R_DKIM_ALLOW" for o in (x.get("o") or ())]
    return any(d and (_domain_under(parts[1], d) or _domain_under(d, parts[1])) for d in dkim)


def _junk_rules_after_user_junk(db: Db, log: logging.Logger, acc: Account, msgid: str,
                                sender: str | None, *, explicit: bool = False) -> None:
    """2.12 (#8/#9), inside db.tx(): count the user's move to Junk per sender;
    a conflicting hand-made allow rule becomes a note for the admin, and the
    third move of the same sender in this mailbox a block rule for this
    mailbox only (junkrules.on_user_junk). Never raises.

    New automated rules use three fresh corrections in 30 days, capped at
    five per rolling day; the per-account switch can retain suggestions only.
    The move counts only when the mailbox learns from moves (or the WebUI
    explicitly marks spam) and the From was authenticated (from_authenticated);
    the owner's domains and every mailbox's domain and address are protected like in the WebUI."""
    own = [*(acc.owner_platform_domains or ()), *(acc.webshop_domains or ())]
    user = str(getattr(acc, "user", "") or "")
    if "@" in user:
        own.append(user.rpartition("@")[2])
    try:
        row = db.get_message(msgid)
        authed = from_authenticated(_row_get(row, "symbols") if row is not None else None, sender)
        res = _junkrules().on_user_junk(db.conn, acc.name, sender, msgid, now=int(_now()), own_domains=own,
                                        add_rule=add_sender_rule, protection=_owner_protection(acc),
                                        count=(explicit or bool(acc.learn_from_moves)) and authed
                                              and acc.mode in ('move', 'flag'),
                                        auto_block=bool(getattr(acc, 'auto_block_repeated_spam', True)),
                                        fresh_only=True)
    except Exception as ex:  # noqa: BLE001 - bookkeeping only, never fail the junk poll
        log.warning("junk rule bookkeeping for %s failed: %s", acc.name, type(ex).__name__)
        return
    if res.get("conflict") is not None:
        db.log_event("junk_rule_conflict", msgid, detail=f"rule={res['conflict']} n={res['n']}")
    if res.get("blocked") is not None:
        db.log_event("junk_auto_block", msgid, detail=f"rule={res['blocked']} n={res['n']}")
        log.info("blocked a sender for %s after %d moves to Junk (rule %s)", acc.name, res["n"], res["blocked"])
    elif res.get("suggest"):
        db.log_event("junk_block_suggested", msgid, detail=f"n={res['n']}")


def _junk_rules_after_user_ham(db: Db, log: logging.Logger, acc: Account, msgid: str,
                               sender: str | None) -> None:
    """Inside the verdict transaction: undo only our own automatic block."""
    rid = _junkrules().reset_on_ham(db.conn, acc.name, sender, now=int(_now()))
    if rid is not None:
        # This rule may have queued other copies during their grace period.
        # Re-evaluate only its normal scan moves under current policy: an
        # independent score/threat/manual verdict or another rule still wins.
        waiting = db.conn.execute(
            'SELECT m.*, p.threshold AS pending_threshold FROM messages m JOIN pending_move p '
            'ON p.account=m.account AND p.message_id=m.message_id '
            'WHERE m.account=? AND m.rule_hit=? AND p.origin IS NULL',
            (acc.name, f'block:{rid}')).fetchall()
        cancelled = 0
        for candidate in waiting:
            decision = _auto_block_pending_decision(db, acc, candidate, candidate['pending_threshold'])
            if not decision.spam:
                db.drop_pending_moves_for(candidate['message_id'])
                db.update_message(candidate['message_id'], our_action=decision.action or 'none',
                                  rule_hit=decision.rule_hit)
                cancelled += 1
        db.log_event('junk_auto_block_removed', msgid, detail=f'rule={rid}; user ham; cancelled={cancelled}')


def _auto_block_pending_decision(db: Db, acc: Account, msg: sqlite3.Row, threshold: float | None) -> Decision:
    """Resolve remaining score/rules without a reversed automatic rule."""
    names = frozenset(json.loads(msg['decision_names'])) if msg['decision_names'] else frozenset(
        x['n'] for x in _symbol_list(msg['symbols']))
    return _decide(db, acc, msg, msg['sender'], float(msg['our_score'] or 0), names, set(),
                   threshold=max(float(threshold or acc.threshold), float(acc.threshold)),
                   auth=parse_sender_auth(msg['sender_auth']), threat=msg['threat'],
                   aged_unverified=bool(msg['aged']) and 'TH_AGED_UNVERIFIED' in (msg['symbols'] or ''))


def _auto_allow_sender(db: Db, log: logging.Logger, acc: Account, msgid: str,
                       sender: str | None) -> None:
    """Moving a mail out of the spam folder in the mail app = 'allow this
    sender' for this account (exact address). An existing exact-address
    block rule for the account is switched to allow - the user's latest
    decision wins. Domain/global rules are left alone; the exact rule beats
    them anyway. Normal allow rules keep the spoof guard."""
    try:
        pattern = normalize_rule_pattern(sender or "")
    except ValueError:
        return
    if pattern.startswith("@"):
        return
    try:
        row = db.conn.execute("SELECT id, kind FROM sender_rules WHERE account=? AND pattern=?",
                              (acc.name, pattern)).fetchone()
        if row is not None and row["kind"] == "allow":
            return
        force = _force_rule_covering(db.conn, acc.name, pattern)
        if force is not None:
            # An 'Altid igennem' rule covers this sender. A normal exact
            # allow rule would outrank it (account + exact beat '*'/domain)
            # and bring back the spoof guard - e.g. a forged shop mail
            # dragged out of spam would get the genuine shop mail moved.
            with db.tx():
                db.log_event("rule_auto_allow_skipped", msgid,
                             detail=f"{pattern} covered by force rule={force['id']}")
            log.info("auto-allow of %s skipped: 'Altid igennem' rule %s", pattern, force["id"])
            return
        note = ("Automatisk: en mail fra afsenderen blev flyttet ud af spam-mappen "
                f"{time.strftime('%d-%m-%Y', time.localtime(_now()))}.")
        with db.tx():
            rid = add_sender_rule(db.conn, acc.name, pattern, "allow", note, AUTO_ALLOW_BY)
            db.log_event("rule_auto_allow", msgid, detail=f"{pattern} rule={rid}"
                         + (" (was block)" if row is not None else ""))
        log.info("auto-allowed %s for %s after a rescue", pattern, acc.name)
    except sqlite3.Error as ex:
        log.warning("auto-allow for %s failed: %s", acc.name, type(ex).__name__)


# 2.6 (A4): our_action of a newsletter the filter moved (or one the user put
# back) - a new inbox UID of it is handled by newsletters.on_inbox_sighting.
NEWSLETTER_INBOX_ACTIONS = frozenset({"newsletter_moved", "newsletter_move_failed", "newsletter_kept"})


def _newsletter_sighting(db: Db, log: logging.Logger, acc: Account, fmap: dict[str, str],
                         prior: sqlite3.Row, msgid: str, idate: int | None) -> bool:
    """newsletters.on_inbox_sighting; a database problem there only means
    the mail is handled like any other known Message-ID."""
    try:
        return bool(_newsletters().on_inbox_sighting(db, log, acc, fmap, prior, msgid, idate, int(_now())))
    except sqlite3.Error as ex:
        log.warning("newsletter sighting failed: %s", type(ex).__name__)
        return False


def _classify_inbox_uid(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
                        fmap: dict[str, str], uv: int, uid: int, data: dict | None,
                        readonly: bool, processed: set[int]) -> _InboxMeta | None | bool:
    """Header-level triage of a new inbox UID. Returns metadata when the
    body must be scanned, None when the UID is finished, False when a
    failure was recorded (retry later)."""
    inbox = fmap["inbox"]
    if data is None:
        # Not in the FETCH reply: expunged since the SEARCH, or a glitch.
        still_there = int(uid) in {int(u) for u in client.search(["UID", str(uid)])}
        if not still_there:
            return None
        return False if not _scan_failed(db, log, uv, uid, "metadata missing", processed) else None
    flags = _flag_names(data.get(b"FLAGS"))
    size = data.get(b"RFC822.SIZE")
    size = int(size) if size is not None else None
    msgid, _subj, _from = parse_envelope(_header_bytes(data))
    prior = db.get_message(msgid) if msgid else None
    raw = None
    # A previously seen ID, an internal key, or an exemption must prove its
    # content before inheriting any decision. First deliveries stay batched.
    known_binding = mailidentity.binding(db.conn, db.account, msgid) if msgid else None
    own = bool(msgid and (_is_our_receipt(db, msgid, _header_bytes(data))
                          or _is_own_notification(db, msgid, _header_bytes(data))))
    if not msgid or prior is not None or msgid.startswith(mailidentity.PREFIX) or own:
        if size is not None and size > MAX_FETCH_BYTES:
            db.bump("skipped_oversize")
            return None
        raw = _body_bytes(client.fetch([uid], [b"BODY.PEEK[]"]).get(uid))
        if not raw:
            return False if not _scan_failed(db, log, uv, uid, "identity body missing", processed) else None
        with db.tx():
            key = mailidentity.bind(db.conn, db.account, msgid, raw,
                                    legacy_exists=prior is not None and not db.conn.execute(
                                        "SELECT 1 FROM mail_identity WHERE account=? AND message_key=?",
                                        (db.account, msgid)).fetchone())
        if own and ((known_binding and mailidentity.fingerprint(raw) == known_binding[1]) or
                    db.conn.execute("SELECT 1 FROM mail_identity WHERE account='*notification*' "
                                    "AND wire_id=? AND fingerprint=?",
                                    (parse_envelope(raw)[0], mailidentity.fingerprint(raw))).fetchone()):
            return None
        msgid = key
        prior = db.get_message(msgid)
    if prior is None and "\\Seen" in flags:
        # Read before we ever saw it (another client, or mail that predates
        # us): the user has handled it, leave it alone.
        with db.tx():
            db.bump("skipped_seen")
        return None
    if prior is not None:
        if prior["our_action"] in NEWSLETTER_INBOX_ACTIONS and _newsletter_sighting(
                db, log, acc, fmap, prior, msgid, _internaldate_ts(data)):
            # 2.6 (A4): a newsletter the filter moved, put back by the user
            # (its sender stays in the inbox from now on) - never scored.
            return None
        source = _rescue_source(prior, fmap)
        if source is not None:
            idate = _internaldate_ts(data)
            if prior["received_at"] is not None and idate == prior["received_at"]:
                # COPY/MOVE keep INTERNALDATE, a new delivery gets its own:
                # this is the very message we saw before, moved back by the
                # user - even while the source copy still exists (a client
                # without MOVE copies first and deletes afterwards).
                _handle_rescue(db, log, acc, fmap, msgid, prior, source)
                return None
            # No INTERNALDATE proof of a move. When the spam copy is 'gone'
            # (the user deleted it or emptied the spam folder) there is
            # nothing left to check: a different INTERNALDATE then means a
            # NEW delivery of the same Message-ID (alias, forwarder copy,
            # resend) - scored like new mail, never a rescue.
            redelivered = (source == "gone" and prior["received_at"] is not None
                           and idate is not None and idate != prior["received_at"])
            if not redelivered and not _present_elsewhere(client, db, log, source, msgid,
                                                          inbox, uv, readonly):
                # Gone from the spam folder, but not proven to be the same
                # copy: keep it in the inbox as before, without allowing the
                # sender (a redelivery must never allow a spammer).
                _handle_rescue(db, log, acc, fmap, msgid, prior, source,
                               proven=prior["received_at"] is None or idate is None)
                return None
            # Still in the spam folder (or a redelivery after the spam copy
            # was deleted): this inbox copy is a duplicate delivery (e.g. an
            # alias) and is scored like new mail.
        elif _sticky_ham(prior):
            with db.tx():
                db.update_message(msgid, current_folder=inbox, last_seen=int(_now()))
            return None
        if "\\Seen" in flags:
            # Known Message-ID, already read, back in the inbox (dragged back
            # from an archive, an undo, a provider restore): the user has
            # handled it, exactly like unknown read mail above - never
            # re-scored or moved.
            with db.tx():
                db.update_message(msgid, current_folder=inbox, last_seen=int(_now()))
                db.bump("skipped_seen")
            return None
    if size is not None and size > MAX_FETCH_BYTES:
        with db.tx():
            db.log_event("scan_oversize", msgid, detail=f"uid={uid} size={size}")
            db.bump("skipped_oversize")
        return None
    return _InboxMeta(uid=uid, flags=flags, size=size, received_at=_internaldate_ts(data),
                      msgid=msgid, prior=prior, raw=raw)


_rule_domain = decisionpolicy._rule_domain
_domain_under = decisionpolicy._domain_under
parse_sender_auth = decisionpolicy.parse_sender_auth
force_verification = decisionpolicy.force_verification


def _decide(db: Db, acc: Account, prior: sqlite3.Row | None, sender_addr: str | None,
            final: float, names: frozenset, flags: set[str], *, from_header: bool = True,
            threshold: float | None = None, auth: dict[str, Any] | None = None,
            aged_unverified: bool = False, threat: str | None = None) -> Decision:
    """Resolve the current account rule; apply the shared, pure policy.

    Flags are handled by the scan/move guards before this existing entry point.
    Avoid a rule lookup for sticky verdicts and viruses as before.
    """
    rule = (match_sender_rule(db.conn, acc.name, sender_addr)
            if sender_addr and not _sticky_ham(prior) and threat != "virus" else None)
    effective = acc.threshold if threshold is None else threshold
    decision = decisionpolicy.decide(prior, rule, final, names, threshold=effective,
                                     from_header=from_header, auth=auth,
                                     aged_unverified=aged_unverified, threat=threat)
    try:
        decision.policy_input = decisiontrace.inputs(prior, rule, final, names, threshold=effective,
                                                    from_header=from_header, auth=auth,
                                                    aged_unverified=aged_unverified, threat=threat)
    except (ValueError, TypeError, AttributeError) as ex:
        logging.getLogger(acc.name).warning("policy evidence unavailable: %s", type(ex).__name__)
    return decision


def _record_policy_trace(db: Db, msgid: str, stage: str, decision: Decision, now: int) -> None:
    try:
        decisiontrace.record(db.conn, db.account, msgid, stage, decision, now)
    except (sqlite3.Error, ValueError, TypeError) as ex:
        logging.getLogger(db.account).warning("policy trace unavailable: %s", type(ex).__name__)


def effective_threshold(acc: Account, ctx: dict[str, Any] | None) -> tuple[float, str | None]:
    """E9: (threshold, matched protected address). Mail to a protected
    recipient (To/Cc/Delivered-To/X-Original-To/original RCPT) uses the
    higher protected_threshold."""
    prot = {a.lower() for a in (acc.protected_recipients or [])}
    if not prot:
        return acc.threshold, None
    for addr in (ctx or {}).get("recipients") or []:
        a = str(addr).strip().lower()
        if a in prot:
            return max(acc.threshold, acc.protected_threshold), a
    return acc.threshold, None


def _sender_auth(res: ScanResult, ctx: dict[str, Any]) -> dict[str, Any]:
    dkim: list[str] = []
    for opt in (res.options or {}).get("R_DKIM_ALLOW", []):
        d = str(opt).split(":", 1)[0].strip().lower().rstrip(".")
        if d and d not in dkim:
            dkim.append(d)
    host = ctx.get("origin_host")
    return {"dkim": dkim[:20], "host": str(host).lower()[:200] if host else None}


def _dkim_aligned(from_domain: str | None, auth: dict[str, Any], names: frozenset) -> bool:
    """A valid DKIM signature (R_DKIM_ALLOW) relaxed-aligned with the From
    domain. A DMARC pass alone is not enough here: it may rest on SPF of
    the bulk sender's bounce domain only."""
    if not from_domain:
        return False
    return any(_domain_under(from_domain, d) or _domain_under(d, from_domain) for d in auth["dkim"])


# 2.12 (#9): a user's move of a legitimate newsletter to Junk is "I do not
# want this", not "this is spam": the shared Bayes pool (one bayes_user for
# every mailbox) would otherwise learn ordinary marketing as spam and fight
# the other mailboxes' ham. Spam signs that keep a newsletter learnable:
NEWSLETTER_SPAM_SIGNS = HAM_GUARD_SYMBOLS | DMARC_SPOOF_SYMBOLS | frozenset({
    "TH_PROVIDER_SPAM", "TH_PROVIDER_AUTH_FAIL", "TH_PROVIDER_AUTH_SPOOF", "R_SPF_FAIL", "R_DKIM_REJECT",
    "TH_CAMPAIGN", "TH_SUBJECT_BRAND_SPOOF", "TH_PHISHARMY_URL"})
NEWSLETTER_SPAM_PREFIXES = ("PHISHED_", "FUZZY_", "RBL_", "URIBL_", "SURBL_", "DBL_", "SEM_", "TH_LOOKALIKE",
                            "TH_AI_SPAM", "CLAM_")
NEWSLETTER_INFO_SYMBOLS = frozenset({"PHISHED_EXCLUDED", "PHISHED_WHITELISTED", "URIBL_BLOCKED", "DBL_BLOCKED",
                                     "RBL_BLOCKED", "DBL_PROHIBIT", "SURBL_BLOCKED", "FUZZY_DENIED"})


def _sender_has_ham(conn: sqlite3.Connection | None, row: Any) -> bool:
    """The pool knows the sender as ham: another mail from the same address
    (any mailbox) was learned as ham or rescued by a user."""
    sender = str(_row_get(row, "sender") or "").strip().lower()
    if conn is None or "@" not in sender:
        return False
    try:
        return conn.execute(
            "SELECT 1 FROM messages WHERE lower(sender)=? AND message_id!=? "
            "AND (learned_as='ham' OR user_verdict='ham') LIMIT 1",
            (sender, str(_row_get(row, "message_id") or ""))).fetchone() is not None
    except sqlite3.Error:
        return False


def legit_newsletter(raw: bytes | None, row: Any, threshold: float,
                     conn: sqlite3.Connection | None = None) -> bool:
    """A mail the user put into Junk that is an ordinary newsletter: an RFC
    2369 List-Unsubscribe, the filter's own scan kept it under the threshold
    (no threat), it had TH_NEWSLETTER (DKIM-aligned bulk mail of a known
    ESP), the sender has a history (TH_ESTABLISHED, or earlier ham from the
    same address in the pool via `conn`), and none of the spam signs above
    fired. Such mail is not learned as spam (#9). Any valid DKIM signature
    alone (R_DKIM_ALLOW) is not enough: fresh spam domains sign too - their
    mail is learned and the campaign sweep runs as before."""
    if raw is None or row is None:
        return False
    try:
        if _row_get(row, "threat") or _row_get(row, "scanned_at") is None:
            return False
        score = _row_get(row, "our_score")
        if score is None or float(score) >= float(threshold):
            return False
        import mailctx  # noqa: PLC0415 - the pure header parser (the engine's _mailctx may be a stub)

        if not mailctx.has_list_unsubscribe(raw):
            return False
        names = {str(x["n"]) for x in _symbol_list(_row_get(row, "symbols"))}
    except Exception:  # noqa: BLE001 - when in doubt: learn as before
        return False
    if "TH_NEWSLETTER" not in names:
        return False
    for n in names - NEWSLETTER_INFO_SYMBOLS:
        if n in NEWSLETTER_SPAM_SIGNS or n.startswith(NEWSLETTER_SPAM_PREFIXES):
            return False
    return "TH_ESTABLISHED" in names or _sender_has_ham(conn, row)


def _newsletter_symbol(raw: bytes, ctx: dict[str, Any], auth: dict[str, Any], names: frozenset,
                       final: float, threshold: float) -> dict | None:
    """E10: TH_NEWSLETTER (-1.5) for a List-Unsubscribe mail, DKIM-aligned,
    sent by a known ESP - only when it is not otherwise spammy."""
    if final >= threshold + NEWSLETTER_MAX_OVER or "TH_PROVIDER_SPAM" in names:
        return None
    try:
        mc = _mailctx()
        if not mc.has_list_unsubscribe(raw):
            return None
        if not _dkim_aligned(mc.header_from_domain(raw), auth, names):
            return None
        esp = mc.known_esp(ctx, auth["dkim"])
    except Exception as ex:  # noqa: BLE001 - optional bonus, never block a scan
        logging.getLogger("filter").debug("newsletter check failed: %s", type(ex).__name__)
        return None
    if not esp:
        return None
    return {"n": "TH_NEWSLETTER", "s": NEWSLETTER_SCORE, "o": [str(esp)[:120]]}


# ----- 2.2: aged scans (B7), own platform on a domain list (B2) -----------


def scan_age_s(received_at: Any, now: float | None = None) -> int | None:
    """Seconds since delivery (IMAP INTERNALDATE), None when unknown."""
    try:
        if received_at is None or isinstance(received_at, bool):
            return None
        return max(0, int((_now() if now is None else now) - float(received_at)))
    except (TypeError, ValueError, OverflowError):
        return None


def is_aged(acc: Any, received_at: Any, now: float | None = None) -> bool:
    """B7: more than aged_scan_hours (default 6) since delivery."""
    try:
        hours = float(getattr(acc, "aged_scan_hours", 6.0) or 0.0)
    except (TypeError, ValueError):
        hours = 6.0
    age = scan_age_s(received_at, now)
    return hours > 0 and age is not None and age > hours * 3600


def aged_unverified(ctx: dict[str, Any] | None, auth: dict[str, Any], sender: str | None,
                    names: Iterable[str]) -> bool:
    """B7: in an aged scan nothing vouches for the From - the provider
    recorded no SPF/DMARC result at delivery (e.g. Gigahost writes no
    Authentication-Results), there is no TH_PROVIDER_AUTH_PASS and no valid
    DKIM signature aligned with the sender's domain. A fresh scan would have
    had rspamd's SPF check (R_SPF_FAIL distrusts allow rules)."""
    if "TH_PROVIDER_AUTH_PASS" in set(names):
        return False
    try:
        if _mailctx().provider_auth_known(ctx):
            return False
    except Exception:  # noqa: BLE001 - unknown = unverified
        pass
    parts = _sender_parts(sender) if sender else None
    return not _dkim_aligned(parts[1] if parts else None, auth, frozenset())


def aged_symbols(ctx: dict[str, Any] | None, age_s: int | None) -> list[dict]:
    """Pseudo-symbols of an aged scan: TH_AGED_SCAN (0, informative) plus
    the provider's own delivery-time verdict (TH_PROVIDER_AUTH_PASS -1 /
    TH_PROVIDER_AUTH_FAIL +2, mailctx.provider_auth_symbols)."""
    hours = int((age_s or 0) // 3600)
    out = [{"n": "TH_AGED_SCAN", "s": 0.0, "o": [f"alder={hours}t"]}]
    try:
        fn = getattr(_mailctx(), "provider_auth_symbols", None)
        for item in (fn(ctx) if fn is not None else None) or []:
            sym = _norm_symbol(None, item)
            if sym is not None:
                out.append(sym)
    except Exception as ex:  # noqa: BLE001 - optional evidence, never block a scan
        logging.getLogger("filter").warning("provider_auth_symbols failed: %s", type(ex).__name__)
    return out


# URL reputation / threat symbols: when one of these is present the
# RSPAMD_URIBL hit on the owner's platform is NOT offset (B2) - the link
# may really be bad (a compromised shop on the platform).
# 2.6 (A5): TH_PHISHARMY_URL (Phishing Army host list) is URL reputation,
# but deliberately not a PHISHED_* symbol (no ham guard, keeps the
# known-contact bonus): the list also carries platform roots.
PHISHARMY_SYMBOL = "TH_PHISHARMY_URL"
URL_REPUTATION_EXACT = frozenset({"URIBL_BLACK", "URIBL_RED", "URIBL_MULTI", "PH_SURBL_MULTI",
                                  "JUST_EICAR", PHISHARMY_SYMBOL})
URL_REPUTATION_PREFIXES = ("DBL_", "PHISHED_", "URLHAUS_", "SEM_URIBL_FRESH", "CLAM_")


def url_reputation_hits(names: Iterable[str]) -> list[str]:
    out = []
    for n in names:
        n = str(n)
        if n.endswith("_FAIL") and n.startswith("CLAM_"):
            continue  # CLAM_VIRUS_FAIL: the scanner was unavailable, no verdict
        if n in PHISHED_INFO:
            continue  # PHISHED_EXCLUDED: a link to the owner's own shop, no verdict
        if n in URL_REPUTATION_EXACT or n.startswith(URL_REPUTATION_PREFIXES) or "SURBL" in n:
            out.append(n)
    return sorted(out)


def owner_domains(acc: Any) -> list[str]:
    """B2: the owner's platform(s), webshops and the mailbox's own domain."""
    out: list[str] = []
    user_dom = str(getattr(acc, "user", "") or "").rpartition("@")[2].strip().lower()
    for d in [*(getattr(acc, "owner_platform_domains", None) or []),
              *(getattr(acc, "webshop_domains", None) or []), user_dom]:
        d = str(d or "").strip().lower().rstrip(".")
        if d and d not in out:
            out.append(d)
    return out


def _option_domain(opt: Any) -> str:
    # rspamd's rbl options are "<domain>:<where>" (url, email, from_mime, dkim, ...).
    return str(opt or "").strip().lower().rsplit(":", 1)[0].rstrip(".")


OWN_PLATFORM_TEXT = "Jeres egen webshop-platform står fejlagtigt på en domæneliste – udlignet"


def own_platform_offset(acc: Any, res: ScanResult, names: Iterable[str]
                        ) -> tuple[dict | None, tuple[str, str] | None]:
    """B2: (TH_OWN_PLATFORM_URIBL symbol or None, (event, detail) or None).
    The symbol cancels RSPAMD_URIBL's score when EVERY listed domain is
    the owner's platform or own domain, no other URL-reputation symbol and
    no virus is present. An RSPAMD_URIBL hit on an own domain is always
    logged (a compromised own website must stay visible on Drift)."""
    if "RSPAMD_URIBL" not in res.names:
        return None, None
    score = float((res.scores or {}).get("RSPAMD_URIBL") or 0.0)
    domains = [d for d in dict.fromkeys(_option_domain(o) for o in (res.options or {}).get("RSPAMD_URIBL", []))
               if d]
    own = owner_domains(acc)
    mine = [d for d in domains if any(_domain_under(d, o) for o in own)]
    if not mine:
        return None, None
    others = [d for d in domains if d not in mine]
    rep = url_reputation_hits(n for n in names if n != "RSPAMD_URIBL")
    if others or rep or score <= 0:
        why = (f"andre domæner: {','.join(others)[:120]}" if others else
               f"andre fund: {','.join(rep)[:120]}" if rep else "ingen score")
        return None, ("own_domain_uribl", f"{','.join(mine)[:200]} beholdt ({why})")
    sym = {"n": "TH_OWN_PLATFORM_URIBL", "s": round(-score, 3), "o": mine[:3]}
    return sym, ("own_domain_uribl", f"{','.join(mine)[:200]} udlignet {score:g}")


# ----- 2.3 (B16): threat class ----------------------------------------------

# Exact feeds and signatures only. rspamd's heuristic PHISHING,
# REDIRECTOR_URL and SUSPICIOUS_URL_* stay ordinary score symbols (PHISHING
# hit 17 INBOX mails in the owner's analysis, nearly all legitimate Danish
# marketing).
THREAT_VIRUS = frozenset({"CLAM_VIRUS"})
# 2.7 fix: ClamAV signatures that are no proof of malware - heuristics
# (Heuristics.*, incl. Heuristics.Limits.Exceeded from AlertExceedsMax),
# potentially unwanted programs (PUA.*), phishing signatures and the
# third-party sets (Sanesecurity, SecuriteInfo, winnow, MiscreantPunch,
# Foxhole, Porcupine; *.UNOFFICIAL). A CLAM_VIRUS whose signatures are ALL
# of these is not the threat class 'virus' but TH_CLAM_HEURISTIC (+4): a
# Bruger can release it, 'Altid igennem' and known contacts keep working.
# Any other signature (or none given) stays 'virus'.
CLAM_HEURISTIC_SYMBOL = "TH_CLAM_HEURISTIC"
CLAM_HEURISTIC_SCORE = 4.0
CLAM_HEURISTIC_PREFIXES = ("heuristics.", "pua.", "sanesecurity.", "securiteinfo.", "winnow.", "miscreantpunch.",
                           "foxhole.", "porcupine.")
THREAT_PHISH = frozenset({"DBL_PHISH", "PH_SURBL_MULTI", "PHISHED_OPENPHISH", "PHISHED_PHISHTANK",
                          "CLAM_PHISH"})
THREAT_MALWARE = frozenset({"URLHAUS_MALWARE_URL", "DBL_MALWARE"})
THREAT_ATTACHMENT = frozenset({"TH_ATTACH_BLOCK"})
# B22: a sender field (From / Reply-To / envelope / DKIM d=) imitates a
# protected domain (lookalike.py). TH_LOOKALIKE_URL stays a score symbol.
THREAT_LOOKALIKE = frozenset({"TH_LOOKALIKE_DOMAIN"})
# Most severe first: the class a mail gets when several match.
THREAT_ORDER = (("virus", THREAT_VIRUS), ("phish", THREAT_PHISH), ("malware_url", THREAT_MALWARE),
                ("attachment", THREAT_ATTACHMENT), ("lookalike", THREAT_LOOKALIKE))
THREAT_CLASSES = ("virus", "phish", "malware_url", "attachment", "impersonation", "lookalike")
# Classes that still let a DKIM-verified 'Altid igennem' sender through
# (logged as threat_force_pass). Virus never passes.
THREAT_FORCE_PASSABLE = decisionpolicy.THREAT_FORCE_PASSABLE
THREAT_LABELS = {"virus": "Virus", "phish": "Phishing-link", "malware_url": "Malware-link",
                 "attachment": "Farlig vedhæftning", "impersonation": "Forfalsket afsender",
                 "lookalike": "Efterligner jeres domæne"}
PHISHING_KEYWORD = "$Phishing"


def _threat_option(symbols: Iterable[dict], options: dict, name: str) -> str:
    opts = list((options or {}).get(name) or [])
    if not opts:
        for x in symbols or ():
            if isinstance(x, dict) and x.get("n") == name:
                opts = list(x.get("o") or [])
                break
    for o in opts:
        o = str(o or "").strip()
        if o:
            return _clean_display(o.rsplit(":", 1)[0] if name.startswith(("DBL_", "URLHAUS_")) else o)[:120]
    return ""


def clam_signatures(symbols: Iterable[dict] = (), options: dict | None = None) -> list[str]:
    """The CLAM_VIRUS signature names of a scan (rspamd options)."""
    opts = list((options or {}).get("CLAM_VIRUS") or [])
    if not opts:
        for x in symbols or ():
            if isinstance(x, dict) and x.get("n") == "CLAM_VIRUS":
                opts = list(x.get("o") or [])
                break
    out: list[str] = []
    for o in opts:
        o = str(o or "").strip()
        if o and o not in out:
            out.append(o[:200])
    return out


def clam_is_heuristic(signature: Any) -> bool:
    s = str(signature or "").strip().lower()
    return bool(s) and (s.startswith(CLAM_HEURISTIC_PREFIXES) or "phishing" in s or s.endswith(".unofficial"))


def clam_heuristic_only(names: Iterable[str], symbols: Iterable[dict] = (), options: dict | None = None
                        ) -> list[str] | None:
    """The signatures when CLAM_VIRUS hit with heuristic / third-party
    signatures only, else None (no hit, a real signature, or no name)."""
    if "CLAM_VIRUS" not in {str(n) for n in names or ()}:
        return None
    sigs = clam_signatures(symbols, options)
    return sigs if sigs and all(clam_is_heuristic(x) for x in sigs) else None


# 2.8 (A1): third-party signature sets (deploy/aio/sf-sigs downloads
# Sanesecurity's). Their hits are TH_CLAM_3P (Prøv first, trialmode 'clam3p'):
# +6 for phishing / scam / spam signatures, +4 for the rest. clamd appends
# .UNOFFICIAL to every signature that is not from ClamAV itself.
CLAM_3P_SYMBOL, CLAM_3P_TRIAL = "TH_CLAM_3P", "TH_CLAM_3P_TRIAL"
CLAM_3P_SCORE, CLAM_3P_PHISH_SCORE = 4.0, 6.0
CLAM_3P_PREFIXES = ("sanesecurity.", "securiteinfo.", "winnow.", "miscreantpunch.", "foxhole.", "porcupine.")
CLAM_3P_PHISH_WORDS = ("phish", ".scam", "scam.", ".spam", "spam.", "fake", "fraud", "419")


def clam_is_third_party(signature: Any) -> bool:
    s = str(signature or "").strip().lower()
    return bool(s) and (s.endswith(".unofficial") or s.startswith(CLAM_3P_PREFIXES))


def clam_heuristic_symbol(res: Any) -> dict | None:
    """TH_CLAM_HEURISTIC (+4) for a scan whose ClamAV hit is heuristic only
    (2.8: ClamAV's own heuristics; third-party signatures are TH_CLAM_3P)."""
    sigs = clam_heuristic_only(getattr(res, "names", None) or (), getattr(res, "symbols", None) or [],
                               getattr(res, "options", None) or {})
    sigs = [x for x in sigs or () if not clam_is_third_party(x)]
    if not sigs:
        return None
    return {"n": CLAM_HEURISTIC_SYMBOL, "s": CLAM_HEURISTIC_SCORE, "o": [_clean_display(x)[:120] for x in sigs[:3]]}


def classify_threat(names: Iterable[str], symbols: Iterable[dict] = (), options: dict | None = None
                    ) -> tuple[str | None, str | None]:
    """B16: (threat class, detail) for a scan, or (None, None). detail =
    the virus signature, the attachment's file name or the matched rule
    (with its host when rspamd gave one)."""
    nameset = {str(n) for n in names}
    syms = list(symbols or ())
    for cls, members in THREAT_ORDER:
        hits = sorted(nameset & members)
        if not hits:
            continue
        if cls == "virus" and clam_heuristic_only(nameset, syms, options):
            continue  # 2.7 fix: TH_CLAM_HEURISTIC, a score symbol
        first = hits[0]
        opt = _threat_option(syms, options or {}, first)
        if cls == "virus":
            return cls, (opt or "ukendt signatur")[:120]
        if cls == "attachment":
            return cls, (opt or "ukendt fil")[:120]
        if cls == "lookalike":
            # 'pinslkbing.example ligner pinsikbing.example' (lookalike.threat_detail).
            look = [s for s in syms if isinstance(s, dict) and s.get("n") == first]
            if not look and (options or {}).get(first):
                look = [{"n": first, "o": list((options or {})[first])}]
            return cls, (_lookalike().threat_detail(look) or "ukendt domæne")[:160]
        return cls, (f"{first} {opt}".strip() if opt else first)[:160]
    return None, None


def threat_text(threat: str | None, detail: str | None = None) -> str:
    """Danish badge text: 'Virus: <signatur>', 'Phishing-link',
    'Farlig vedhæftning: faktura.pdf.exe'. '' when no threat."""
    if not threat:
        return ""
    label = THREAT_LABELS.get(str(threat), "Farlig mail")
    detail = str(detail or "").strip()
    if threat in ("virus", "attachment", "lookalike") and detail:
        return f"{label}: {detail}"[:200]
    return label


def threat_confirm_text(threat: str | None, detail: str | None = None) -> str:
    """The confirmation an administrator must accept before a release."""
    detail = str(detail or "").strip()
    if threat == "lookalike":
        return ("Denne mail kommer fra et domæne, der efterligner jeres eget"
                + (f" ({detail})." if detail else "."))
    if threat == "virus":
        return f"Denne mail indeholder virus: {detail or 'ukendt signatur'}."
    if threat == "attachment":
        return f"Denne mail har en farlig vedhæftning: {detail or 'ukendt fil'}."
    if threat == "malware_url":
        return "Denne mail indeholder et link til skadelig software."
    if threat == "phish":
        return "Denne mail indeholder et phishing-link."
    return "Denne mail er markeret som farlig."


def message_threat(conn: sqlite3.Connection, account: str, message_id: str | None
                   ) -> tuple[str | None, str | None]:
    """(threat, detail) stored for a message ((None, None) if none/unknown)."""
    if not message_id:
        return None, None
    try:
        row = conn.execute("SELECT threat, threat_detail FROM messages WHERE account=? AND message_id=?",
                           (account, message_id)).fetchone()
    except sqlite3.Error:
        return None, None
    if row is None or not row[0]:
        return None, None
    return str(row[0]), (str(row[1]) if row[1] else None)


# ----- 2.3 (B17): attachment policy -------------------------------------------

ATTACH_BLOCK_SCORE = 20.0
ENCRYPTED_ARCHIVE_SCORE = 4.0
ATTACH_ARCHIVE_EXTS = frozenset({"zip"})      # inspected here (rar/7z: rspamd's options)
ATTACH_MAX_ARCHIVE_ENTRIES = 500
ATTACH_MAX_NESTED_BYTES = 2 * 1024 * 1024
ATTACH_MAX_NAMES = 200
ATTACH_LINK_SCAN_BYTES = 1024 * 1024
# rspamd symbols that always block (B17), whatever the extension list says.
ATTACH_ALWAYS_BLOCK = frozenset({"MIME_DOUBLE_BAD_EXTENSION", "MIME_EXE_IN_GEN_SPLIT_RAR"})
_LINK_RE = re.compile(r"(?i)(?:\bhttps?://|\bwww\.[a-z0-9-]+\.)")


def _clean_display(text: Any) -> str:
    """Printable text without control/format characters (bidi overrides,
    zero-width spaces) - safe to store, log and show."""
    import unicodedata

    out = []
    for ch in str(text or ""):
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"):
            continue
        out.append(" " if cat == "Zs" else ch)
    return re.sub(r"\s+", " ", "".join(out)).strip()


def normalize_filename(name: Any) -> str:
    """B17: the name an operating system would actually use, for the
    extension check. Defeats the usual tricks: Unicode compatibility forms
    (full-width 'ｅｘｅ'), bidi overrides (RTLO 'faktura‮fdp.exe' shows as
    'fakturaexe.pdf'), zero-width characters ('x.e​xe'), trailing dots and
    spaces (Windows drops them: 'x.exe. '), case, and path components."""
    import unicodedata

    text = unicodedata.normalize("NFKC", str(name or ""))
    text = "".join(ch for ch in text if unicodedata.category(ch) not in ("Cc", "Cf", "Cs", "Co", "Cn"))
    text = text.replace("\\", "/").rsplit("/", 1)[-1]
    text = text.split(":", 1)[0] if re.search(r":\$data$", text, re.I) else text
    text = text.rstrip(" .\t ").strip()
    return text.casefold()


def filename_ext(name: Any) -> str:
    """Extension of a (normalised) file name, '' when there is none."""
    norm = normalize_filename(name)
    if "." not in norm:
        return ""
    return norm.rsplit(".", 1)[1].strip()


@dataclass
class AttachmentInfo:
    names: list = field(default_factory=list)      # [(display name, where)]; where = '' or the archive
    encrypted: list = field(default_factory=list)  # display names of password-protected archives
    has_links: bool = False

    @property
    def has_attachments(self) -> bool:
        return bool(self.names)


def _decode_filename(part: Any) -> str:
    try:
        name = part.get_filename()
    except Exception:  # noqa: BLE001 - malformed parameters
        name = None
    if not name:
        try:
            name = part.get_param("name", header="content-type")
        except Exception:  # noqa: BLE001
            name = None
        if isinstance(name, tuple):
            try:
                name = email.utils.collapse_rfc2231_value(name)
            except Exception:  # noqa: BLE001
                name = None
    if not name:
        return ""
    name = str(name)
    if "=?" in name:
        try:
            name = str(email.header.make_header(email.header.decode_header(name)))
        except Exception:  # noqa: BLE001
            pass
    return name


def _zip_entries(data: bytes, info: AttachmentInfo, archive: str, depth: int) -> None:
    import io
    import zipfile

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        entries = zf.infolist()[:ATTACH_MAX_ARCHIVE_ENTRIES]
    except Exception:  # noqa: BLE001 - not a readable zip: rspamd's own checks still apply
        return
    encrypted = False
    for zi in entries:
        if zi.is_dir():
            continue
        if len(info.names) >= ATTACH_MAX_NAMES:
            break
        info.names.append((_clean_display(zi.filename)[:200], archive))
        if zi.flag_bits & 0x1:
            encrypted = True
            continue
        if (depth < 2 and filename_ext(zi.filename) in ATTACH_ARCHIVE_EXTS
                and 0 < zi.file_size <= ATTACH_MAX_NESTED_BYTES
                and zi.compress_size and zi.file_size <= 100 * max(zi.compress_size, 1)):
            try:
                _zip_entries(zf.read(zi), info, f"{archive}/{_clean_display(zi.filename)[:80]}", depth + 1)
            except Exception:  # noqa: BLE001
                pass
    if encrypted and archive not in info.encrypted:
        info.encrypted.append(archive)


def mail_attachments(raw: bytes) -> AttachmentInfo:
    """File names of every attachment (also inside zip archives, two
    levels deep), password-protected archives and whether the text has
    links. Never raises."""
    info = AttachmentInfo()
    try:
        msg = email.message_from_bytes(raw or b"", policy=email.policy.compat32)
    except Exception:  # noqa: BLE001
        return info
    scanned = 0
    try:
        parts = list(msg.walk())[:500]
    except Exception:  # noqa: BLE001
        return info
    for part in parts:
        try:
            if part.is_multipart():
                continue
            name = _decode_filename(part)
            ctype = (part.get_content_type() or "").lower()
            if name:
                display = _clean_display(name)[:200]
                if len(info.names) < ATTACH_MAX_NAMES:
                    info.names.append((display, ""))
                payload = None
                if filename_ext(name) in ATTACH_ARCHIVE_EXTS or ctype in ("application/zip",
                                                                         "application/x-zip-compressed"):
                    payload = part.get_payload(decode=True)
                if payload and payload[:4] == b"PK\x03\x04":
                    _zip_entries(payload, info, display, 1)
                continue
            if ctype.startswith("text/") and not info.has_links and scanned < ATTACH_LINK_SCAN_BYTES:
                body = part.get_payload(decode=True) or b""
                body = body[:ATTACH_LINK_SCAN_BYTES - scanned]
                scanned += len(body)
                if _LINK_RE.search(body.decode("latin-1", "replace")):
                    info.has_links = True
        except Exception:  # noqa: BLE001 - one odd part never stops the check
            continue
    return info


def _option_names(options: Iterable[Any]) -> list[tuple[str, str]]:
    """rspamd mime_types options -> [(display, ext)]. The options are an
    extension ('exe'), a file name or 'ext:file' depending on the version."""
    out = []
    for opt in options or ():
        text = str(opt or "").strip()
        if not text:
            continue
        pieces = [x for x in re.split(r"[:,]", text) if x.strip()] or [text]
        named = [x.strip() for x in pieces if "." in x.strip(" .")]
        for piece in (named or pieces):
            piece = piece.strip()
            ext = filename_ext(piece) if "." in piece.strip(" .") else normalize_filename(piece).lstrip(".")
            if ext:
                out.append((_clean_display(piece)[:200] if "." in piece.strip(" .") else f".{ext}", ext))
    return out


def attach_exception(conn: sqlite3.Connection, account: str, sender: str | None) -> sqlite3.Row | None:
    """The 'Tillad farlige vedhæftninger fra denne afsender' rule for the
    sender (exact address beats domain, account beats '*'), or None."""
    pats = _rule_patterns_for(sender)
    if pats is None:
        return None
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    try:
        rows = cur.execute(
            f"SELECT * FROM attach_rules WHERE account IN (?, '*') "
            f"AND pattern IN ({','.join('?' * len(pats[1]))})", (account, *pats[1])).fetchall()
    except sqlite3.Error:
        return None
    if not rows:
        return None
    return max(rows, key=lambda r: (1 if r["account"] == account else 0, 1 if r["pattern"] == pats[0] else 0,
                                    len(r["pattern"])))


def add_attach_rule(conn: sqlite3.Connection, account: str, pattern: str, *, note: str | None = None,
                    actor: str | None = None) -> int:
    account = (account or "*").strip() or "*"
    pat = normalize_rule_pattern(pattern)
    with _autocommit(conn):
        conn.execute(
            "INSERT INTO attach_rules(account, pattern, note, created_by, created_at) VALUES(?,?,?,?,?) "
            "ON CONFLICT(account, pattern) DO UPDATE SET note=COALESCE(excluded.note, attach_rules.note), "
            "created_by=excluded.created_by",
            (account, pat, (note or "").strip()[:300] or None, actor or None, int(_now())))
        row = conn.execute("SELECT id FROM attach_rules WHERE account=? AND pattern=?", (account, pat)).fetchone()
    return int(row[0])


def delete_attach_rule(conn: sqlite3.Connection, rule_id: int) -> bool:
    with _autocommit(conn):
        cur = conn.execute("DELETE FROM attach_rules WHERE id=?", (int(rule_id),))
    return cur.rowcount > 0


def attachment_verdict(acc: Any, raw: bytes, res: ScanResult, *, info: AttachmentInfo | None = None
                       ) -> tuple[str | None, str | None, list[str]]:
    """B17: (blocking file name or None, trigger, encrypted archive names).
    Triggers: a blocked extension on a top-level attachment or inside an
    archive (our own zip listing or rspamd's MIME_BAD_EXTENSION options,
    which also cover rar/7z), MIME_DOUBLE_BAD_EXTENSION or
    MIME_EXE_IN_GEN_SPLIT_RAR."""
    info = info if info is not None else mail_attachments(raw)
    block = {str(e).lower() for e in (getattr(acc, "attachment_block", None) or [])}
    hit: tuple[str, str] | None = None
    for display, where in info.names:
        if block and filename_ext(display) in block:
            hit = (display, "archive" if where else "extension")
            break
    names = res.names or frozenset()
    opts = res.options or {}
    if hit is None and block:
        for sym in ("MIME_BAD_EXTENSION", "MIME_ARCHIVE_IN_ARCHIVE"):
            if sym in names:
                for display, ext in _option_names(opts.get(sym) or _sym_opts(res, sym)):
                    if ext in block:
                        hit = (display, "rspamd")
                        break
            if hit is not None:
                break
    if hit is None:
        for sym in sorted(names & ATTACH_ALWAYS_BLOCK):
            cand = _option_names(opts.get(sym) or _sym_opts(res, sym))
            hit = (cand[0][0] if cand else (info.names[0][0] if info.names else "ukendt fil"),
                   sym.lower())
            break
    encrypted = list(info.encrypted)
    if "MIME_ENCRYPTED_ARCHIVE" in names and not encrypted:
        cand = _option_names(opts.get("MIME_ENCRYPTED_ARCHIVE") or _sym_opts(res, "MIME_ENCRYPTED_ARCHIVE"))
        encrypted = [cand[0][0] if cand else "arkiv"]
    if hit is None:
        return None, None, encrypted
    return hit[0], hit[1], encrypted


def _sym_opts(res: ScanResult, name: str) -> list[str]:
    for x in res.symbols or ():
        if x.get("n") == name:
            return list(x.get("o") or [])
    return []


# ----- 2.3: known contacts, replies, established senders (contacts.py) ----


CONTACTS_BUSY_RETRY_S = 60.0


def contacts_sync(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
                  state: AccountState) -> None:
    """One slice (<= 3 s) of the contact sync in the account thread, between
    IDLE slices like junk polling - no extra IMAP connection. Read-only
    (EXAMINE/SEARCH/STATUS/BODY.PEEK), so it also runs in shadow mode."""
    if not getattr(acc, "known_contacts", False):
        return
    key = _contacts_key(db)
    if key is None:
        return
    try:
        _contacts().sync_step(client, db, log, acc, acc.folder_map, state, key=key, now=int(_now()))
        _namespoof_seed(db, log)
    except _CONN_ERRORS:
        raise
    except Exception as ex:  # noqa: BLE001 - the sync must never stop filtering
        state.contacts_busy = False
        # Retry with the normal STATUS rhythm, never in a tight loop - but a
        # busy database (another writer) is transient: try again in a minute.
        busy = isinstance(ex, sqlite3.OperationalError) and "locked" in str(ex).lower()
        state.contacts_next_status = time.monotonic() + (
            CONTACTS_BUSY_RETRY_S if busy else _contacts().STATUS_INTERVAL_S)
        log.warning("contact sync failed: %s", _short_err(ex))


def _contact_trust(db: Db, acc: Account, key: bytes | None, *, raw: bytes, ctx: dict[str, Any],
                   res: ScanResult, names: frozenset, auth: dict[str, Any], final: float,
                   thr: float, newsletter: float, msgid: str, sender: str | None,
                   envelope_from: str | None, threat: str | None = None) -> Any:
    """contacts.evaluate for one scan (None when off or on any error). A
    threat (B16) never gets a trust bonus (contacts.trust_blocked)."""
    if key is None:
        return None
    try:
        c = _contacts()
        who = sender or envelope_from
        rule = match_sender_rule(db.conn, acc.name, who) if who else None
        return c.evaluate(
            db.conn, acc, key, raw=raw, ctx=ctx, names=names, dkim_domains=auth.get("dkim") or [],
            final=final, threshold=thr, newsletter=newsletter, now=int(_now()), msgid=msgid,
            asn=c.asn_of((res.options or {}).get("ASN") or []),
            allow_rule=rule is not None and rule["kind"] == "allow",
            block_rule=rule is not None and rule["kind"] == "block",
            distrust=ALLOW_DISTRUST_SYMBOLS | NAME_SPOOF_DISTRUST, threat=threat, owner_domains=owner_domains(acc))
    except Exception as ex:  # noqa: BLE001 - optional bonus, never block a scan
        logging.getLogger("filter").warning("contact trust failed: %s", type(ex).__name__)
        return None


def contact_trust_symbols(conn: sqlite3.Connection, acc: Any, raw: bytes, ctx: dict[str, Any] | None,
                          res: Any, final: float, *, newsletter: float = 0.0,
                          extra_names: Iterable[str] = ()) -> list[dict]:
    """Read-only trust pseudo-symbols for calibration scans (trainer): the
    same contacts.evaluate as a live scan, without bookkeeping and without
    creating the key. `extra_names` = the pseudo-symbols the caller already
    added (TH_PROVIDER_SPAM, TH_AGED_UNVERIFIED, ...): like the live scan,
    their hard exceptions block trust; a blocked attachment is a threat.
    [] when off, before the first sync or on any error."""
    if not getattr(acc, "known_contacts", False):
        return []
    try:
        c = _contacts()
        key = c.load_key(STATE_DIR, None, create=False)
        if key is None:
            return []
        names = frozenset(getattr(res, "names", None) or ()) | frozenset(str(n) for n in extra_names or ())
        try:
            blocked, _trigger, _enc = attachment_verdict(acc, raw, res)
        except Exception:  # noqa: BLE001 - best effort, like the live scan's own guard
            blocked = None
        if blocked:
            names = names | {"TH_ATTACH_BLOCK"}
        auth = _sender_auth(res, ctx or {})
        sender = parse_envelope(raw)[2] or None
        envelope_from = (ctx or {}).get("envelope_from") or None
        who = sender or envelope_from
        rule = match_sender_rule(conn, acc.name, who) if who else None
        thr, _prot = effective_threshold(acc, ctx)
        threat, _detail = classify_threat(names, getattr(res, "symbols", None) or [],
                                          getattr(res, "options", None) or {})
        trust = c.evaluate(
            conn, acc, key, raw=raw, ctx=ctx, names=names, dkim_domains=auth.get("dkim") or [],
            final=float(final), threshold=thr, newsletter=newsletter, now=int(_now()),
            msgid=parse_envelope(raw)[0], asn=c.asn_of((getattr(res, "options", None) or {}).get("ASN") or []),
            allow_rule=rule is not None and rule["kind"] == "allow",
            block_rule=rule is not None and rule["kind"] == "block",
            distrust=ALLOW_DISTRUST_SYMBOLS | NAME_SPOOF_DISTRUST, threat=threat, owner_domains=owner_domains(acc))
        return list(trust.symbols)
    except Exception as ex:  # noqa: BLE001 - calibration must never fail on this
        logging.getLogger("filter").debug("contact trust (calibration) failed: %s", type(ex).__name__)
        return []


def _contacts_fresh(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
                    fmap: dict[str, str], state: AccountState, uv: int, key: bytes | None) -> bool:
    """B11 freshness during a scan: an incremental Sent sync (at most once
    a minute) when a mail references something unknown. Re-selects the
    inbox afterwards (scan_inbox keeps using inbox UIDs). True when new
    sent mail was added."""
    c = _contacts()
    if key is None or (state.contacts_last_fresh
                       and time.monotonic() - state.contacts_last_fresh < c.FRESH_MIN_INTERVAL_S):
        return False
    try:
        added, selected = c.incremental_sent(client, db, log, acc, state, key=key, now=int(_now()))
    except _CONN_ERRORS:
        raise
    except Exception as ex:  # noqa: BLE001 - freshness is best effort
        log.warning("contacts freshness sync failed: %s", _short_err(ex))
        added, selected = 0, True
    state.contacts_last_fresh = time.monotonic()
    if selected:
        uv2 = select_with_uidvalidity_check(client, db, fmap["inbox"], log, readonly=acc.mode == "shadow")
        if uv2 != uv:
            # A connection-level error (in _CONN_ERRORS): scan_inbox must not
            # go on with UIDs of the old UIDVALIDITY; the loop reconnects.
            raise IMAPClientAbortError("inbox UIDVALIDITY changed during scan")
    return added > 0


def _contacts_user_spam(db: Db, log: logging.Logger, acc: Account, msgid: str, sender: str | None,
                        symbols: Any, prior_action: str | None, actor: str = "user:move") -> None:
    """B14 inside the caller's transaction: n_junk + 1, demote a known
    contact / end 'established' for the sender."""
    if not getattr(acc, "known_contacts", False) or not sender:
        return
    try:
        res = _contacts().on_user_spam(db.conn, acc.name, _contacts_key(db), sender=sender, symbols=symbols,
                                       prior_action=prior_action, actor=actor, now=int(_now()),
                                       message_id=msgid)
        if res and res.get("demoted"):
            log.info("known contact %s demoted after a spam verdict", res["mask"])
    except Exception as ex:  # noqa: BLE001 - bookkeeping only
        log.warning("contact demotion failed: %s", type(ex).__name__)


def _contacts_user_ham(db: Db, log: logging.Logger, acc: Account, sender: str | None,
                       prior_action: str | None) -> None:
    """B12/B14 inside the caller's transaction: a rescue counts as kept."""
    if not getattr(acc, "known_contacts", False) or not sender:
        return
    try:
        _contacts().on_user_ham(db.conn, acc.name, _contacts_key(db), sender=sender,
                                prior_action=prior_action, now=int(_now()))
    except Exception as ex:  # noqa: BLE001 - bookkeeping only
        log.warning("contact rescue bookkeeping failed: %s", type(ex).__name__)


@dataclass
class Scored:
    """One scored message (_score_message): everything the decision used."""
    res: ScanResult
    ctx: dict
    ctx_ok: bool
    aged: bool
    final: float
    thr: float
    names: frozenset
    auth: dict
    decision: Decision
    symbols: list
    sender: str
    subject: str
    envelope_from: str | None
    threat: str | None = None
    threat_detail: str | None = None
    trust: Any = None
    ckey: bytes | None = None
    own_event: tuple | None = None
    attach: AttachmentInfo = field(default_factory=AttachmentInfo)
    events: list = field(default_factory=list)          # (event, detail)
    attach_rule_id: int | None = None


def _score_message(db: Db, acc: Account, raw: bytes, *, msgid: str, prior: sqlite3.Row | None,
                   flags: set[str], received_at: int | None, fresh: Any = None,
                   on_scanned: Any = None) -> Scored:
    """Score one message exactly like a live scan, without IMAP writes or
    bookkeeping: rspamd, provider bonus, aged mode, own platform offset,
    attachment policy (B17), newsletter, threat class (B16), contact trust
    (read-only) and the decision. `fresh(ckey) -> bool` = the B11
    freshness sync (live scans only). Raises RspamdError."""
    _mid, subject, sender = parse_envelope(raw)
    ctx, ctx_ok = _scan_context(raw, acc)
    aged = is_aged(acc, received_at)
    res = rspamd_scan(raw, acc, ctx, aged=aged)
    if on_scanned is not None:
        on_scanned()
    bonus = _effective_bonus(_provider_bonus(ctx), res.symbols) if acc.provider_bonus else []
    if aged:
        # B7: SPF/DMARC were off for this scan; the provider's verdict at
        # delivery replaces them.
        bonus.extend(aged_symbols(ctx, scan_age_s(received_at)))
    own_sym, own_event = own_platform_offset(acc, res, res.names)
    if own_sym is not None:
        bonus.append(own_sym)
    auth = _sender_auth(res, ctx)
    events: list[tuple[str, str]] = []
    # 2.3 (B17): blocked attachment types, also inside archives.
    info = mail_attachments(raw)
    blocked, trigger, encrypted = attachment_verdict(acc, raw, res, info=info)
    attach_rule_id = None
    if blocked is not None:
        exc = attach_exception(db.conn, acc.name, sender) if sender else None
        if exc is not None and force_verification(exc, auth) is not None:
            # 'Tillad farlige vedhæftninger fra denne afsender' and the mail
            # verifiably comes from that sender's domain (DKIM / path).
            pat = str(exc["pattern"])
            if not pat.startswith("@"):
                pat = f"{pat[:1]}…@{pat.rpartition('@')[2]}"  # never a full address
            bonus.append({"n": "TH_ATTACH_ALLOWED", "s": 0.0, "o": [blocked[:120], pat[:120]]})
            events.append(("attach_exception", f"rule={exc['id']} {trigger}"))
            attach_rule_id = int(exc["id"])
            blocked = None
        else:
            if exc is not None:
                events.append(("attach_exception_unverified", f"rule={exc['id']}"))
            bonus.append({"n": "TH_ATTACH_BLOCK", "s": ATTACH_BLOCK_SCORE, "o": [blocked[:120], str(trigger)]})
    # 2.3.6 (B22): lookalikes of the protected domains - in a sender field
    # TH_LOOKALIKE_DOMAIN (+6, threat 'lookalike'), in a link
    # TH_LOOKALIKE_URL (+4, score only).
    bonus.extend(lookalike_symbols(db.conn, acc, raw, ctx, auth, sender))
    # 2.7 fix: a ClamAV hit with heuristic / third-party signatures only.
    heur = clam_heuristic_symbol(res)
    if heur is not None:
        bonus.append(heur)
    # 2.7 (Falske afsendernavne): the display name of one of the owner's own
    # people from an address that is not theirs - TH_NAME_SPOOF (+5, +7 with
    # Reply-To elsewhere or a lure subject; blocks contact trust). In Prøv
    # only TH_NAME_SPOOF_TRIAL (0) and the event.
    ns_syms, ns_events = namespoof_symbols(db.conn, acc, raw, res.names | {b["n"] for b in bonus}, auth)
    bonus.extend(ns_syms)
    events.extend(ns_events)
    # 2.8 (A1, A3): Sanesecurity hits and QR-code links (Fra/Prøv/Til).
    tr_syms, tr_events = trial_symbols(db.conn, acc, raw, res, res.names | {b["n"] for b in bonus})
    bonus.extend(tr_syms)
    events.extend(tr_events)
    names = res.names | {b["n"] for b in bonus}
    final = round(res.score + sum(b["s"] for b in bonus), 3)
    thr, protected = effective_threshold(acc, ctx)
    if protected:
        bonus.append({"n": "TH_PROTECTED_RCPT", "s": 0.0, "o": [protected, f"grænse={thr:g}"]})
    newsletter = _newsletter_symbol(raw, ctx, auth, names, final, thr)
    if newsletter is not None:
        bonus.append(newsletter)
        final = round(final + newsletter["s"], 3)
    names = names | {b["n"] for b in bonus}
    threat, threat_detail = classify_threat(names, [*bonus, *res.symbols], res.options)
    envelope_from = ctx.get("envelope_from") or None
    # 2.3 (B10-B12): known contact / reply / established / first contact,
    # after the newsletter bonus and before the decision; capped at -6 with
    # TH_NEWSLETTER; off until the first contact sync is complete; never
    # for a threat (contacts.trust_blocked).
    ckey = _contacts_key(db) if getattr(acc, "known_contacts", False) else None
    trust_kw = dict(raw=raw, ctx=ctx, res=res, auth=auth, thr=thr, msgid=msgid, sender=sender,
                    envelope_from=envelope_from, threat=threat,
                    newsletter=float(newsletter["s"]) if newsletter is not None else 0.0)
    trust = _contact_trust(db, acc, ckey, names=names, final=final, **trust_kw)
    if (fresh is not None and trust is not None and trust.unmatched
            and final + trust.delta >= thr - _contacts().FRESH_MARGIN and fresh(ckey)):
        trust = _contact_trust(db, acc, ckey, names=names, final=final, **trust_kw)
    if trust is not None and trust.symbols:
        bonus.extend(trust.symbols)
        final = round(final + trust.delta, 3)
        names = names | {s["n"] for s in trust.symbols}
    flag_sym = provider_flag_offset(res.symbols, names, threat)
    if flag_sym is not None:
        # 2.12 (#20): the provider's SPAM_FLAG counts ~+2 for a sender the
        # mailbox already trusts (established / known contact / reply).
        bonus.append(flag_sym)
        final = round(final + flag_sym["s"], 3)
        names = names | {flag_sym["n"]}
    if encrypted and blocked is None and not (names & CONTACT_TRUST_NAMES):
        # B17: a password-protected archive cannot be inspected. From a
        # non-contact it costs +4 (no block: accountants send them).
        bonus.append({"n": "TH_ENCRYPTED_ARCHIVE", "s": ENCRYPTED_ARCHIVE_SCORE, "o": [encrypted[0][:120]]})
        final = round(final + ENCRYPTED_ARCHIVE_SCORE, 3)
        names = names | {"TH_ENCRYPTED_ARCHIVE"}
    decision = _decide(db, acc, prior, sender or envelope_from, final, names, flags,
                       from_header=bool(sender), threshold=thr, auth=auth,
                       aged_unverified=aged and aged_unverified(ctx, auth, sender or envelope_from, names),
                       threat=threat)
    symbols = top_symbols([*bonus, *decision.symbols, *res.symbols])
    return Scored(res=res, ctx=ctx, ctx_ok=ctx_ok, aged=aged, final=final, thr=thr, names=names, auth=auth,
                  decision=decision, symbols=symbols, sender=sender, subject=subject,
                  envelope_from=envelope_from, threat=threat, threat_detail=threat_detail, trust=trust,
                  ckey=ckey, own_event=own_event, attach=info, events=events, attach_rule_id=attach_rule_id)


# Contact trust symbols that make a sender a "contact" (B17 encrypted
# archives, B19 rescans are skipped for known contacts and replies).
CONTACT_TRUST_NAMES = frozenset({"TH_KNOWN_CONTACT", "TH_KNOWN_DOMAIN", "TH_REPLY", "TH_REPLY_THREAD",
                                 "TH_ESTABLISHED"})
ZAP_EXCLUDE_NAMES = frozenset({"TH_KNOWN_CONTACT", "TH_REPLY", "TH_REPLY_THREAD"})

# 2.12 (#20): the provider's own spam header (rspamd SPAM_FLAG, +5) was
# behind 2 of 4 releases (both from senders the mailbox already knew). For
# a trusted sender it counts at most PROVIDER_FLAG_TRUSTED_SCORE; never for
# a threat (phishing, virus) - those keep the full weight.
PROVIDER_FLAG_TRUSTED_SCORE = 2.0
PROVIDER_FLAG_TRUST_NAMES = frozenset({"TH_ESTABLISHED", "TH_KNOWN_CONTACT", "TH_REPLY", "TH_REPLY_THREAD"})


def provider_flag_offset(rspamd_symbols: list[dict[str, Any]] | None, names: Any,
                         threat: str | None) -> dict[str, Any] | None:
    """TH_PROVIDER_FLAG_TRUSTED: brings SPAM_FLAG down to +2 when the sender
    is trusted (contact trust symbols present) and the mail is no threat.
    None otherwise. Pure; never raises."""
    try:
        if threat or not (set(names or ()) & PROVIDER_FLAG_TRUST_NAMES):
            return None
        flag = sum(float(x.get("s") or 0) for x in rspamd_symbols or [] if x.get("n") == "SPAM_FLAG")
        cut = round(flag - PROVIDER_FLAG_TRUSTED_SCORE, 3)
        if cut <= 0:
            return None
        return {"n": "TH_PROVIDER_FLAG_TRUSTED", "s": -cut, "o": [f"SPAM_FLAG {flag:g} -> {PROVIDER_FLAG_TRUSTED_SCORE:g}"]}
    except Exception:
        return None


def _junk_flags(threat: str | None) -> list[str]:
    """Flag mode keywords: $Junk, plus $Phishing for a threat (B16)."""
    return [JUNK_KEYWORD, PHISHING_KEYWORD] if threat else [JUNK_KEYWORD]


def _scan_and_act(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
                  fmap: dict[str, str], state: AccountState, uv: int, meta: _InboxMeta,
                  raw: bytes, *, dmarc_cfg: dict[str, Any] | None = None) -> None:
    """Score one inbox message and act per mode. Raises RspamdError when no
    score was produced. 2.6 (C2): with `dmarc_cfg` a clean DMARC aggregate
    report from a trusted reporter is moved to the DMARC folder here, after
    the scan; one that is not moved goes on through the normal path."""
    wire_id = parse_envelope(raw)[0]
    with db.tx():
        msgid = mailidentity.bind(db.conn, db.account, wire_id, raw)
    meta.msgid = msgid
    meta.prior = db.get_message(msgid)

    def scanned() -> None:
        if state.scan_fail_streak:
            log.info("rspamd scan recovered after %d failures", state.scan_fail_streak)
            db.log_event("scan_recovered", detail=str(state.scan_fail_streak))
        state.scan_fail_streak = 0
        state.rspamd_backoff_s = 0.0
        state.rspamd_backoff_until = 0.0

    sc = _score_message(db, acc, raw, msgid=msgid, prior=meta.prior, flags=meta.flags,
                        received_at=meta.received_at, on_scanned=scanned,
                        fresh=lambda ckey: _contacts_fresh(client, db, log, acc, fmap, state, uv, ckey))
    res, ctx, decision, final, thr = sc.res, sc.ctx, sc.decision, sc.final, sc.thr
    sender, subject, envelope_from, aged = sc.sender, sc.subject, sc.envelope_from, sc.aged
    if dmarc_cfg is not None and not decision.spam and _dmarc_take(client, db, log, acc, fmap, uv, meta, raw,
                                                                   dmarc_cfg, sc):
        return  # a clean DMARC report, stored and moved: never learned, no spam statistics

    our_action = decision.action
    acted_stat: str | None = None
    if decision.spam:
        if acc.mode == "shadow":
            our_action = "shadow_spam"
        elif acc.mode == "flag":
            try:
                # $Junk (RFC 5788) - never \Flagged, that is the user's star.
                # A threat also gets $Phishing (B16).
                client.add_flags([meta.uid], _junk_flags(sc.threat))
                our_action = "flagged"
                acted_stat = "flagged"
            except _CONN_ERRORS:
                raise
            except IMAPClientError as ex:
                log.warning("setting %s on uid %s failed: %s", JUNK_KEYWORD, meta.uid, type(ex).__name__)
                db.log_event("flag_failed", msgid, detail=type(ex).__name__)
                our_action = "shadow_spam"
        else:
            our_action = "pending_move"
    # 2.6 (A4): newsletter/marketing mail the spam decision leaves in the
    # inbox (never when it acts on the mail - spam always wins).
    newsletter = (_newsletters().scan_decision(sys.modules[__name__], db, acc, sc, flags=meta.flags, raw=raw)
                  if getattr(acc, "newsletters", "off") != "off" and not decision.spam else None)

    now = int(_now())
    provider_flag = ctx.get("provider_flag")
    provider_score = ctx.get("provider_score")
    fields: dict[str, Any] = dict(
        our_score=final, rspamd_score=res.score, rspamd_action=res.action,
        symbols=json.dumps(sc.symbols, ensure_ascii=False, separators=(",", ":")),
        sender_ip=(str(ctx.get("external_ip"))[:64] if ctx.get("external_ip") else None),
        envelope_from=(str(envelope_from)[:200] if envelope_from else None),
        provider_score=float(provider_score) if isinstance(provider_score, (int, float))
        and not isinstance(provider_score, bool) else None,
        provider_flag=None if provider_flag is None else int(bool(provider_flag)),
        rule_hit=decision.rule_hit, size=meta.size, scanned_at=now,
        score_version=SCORE_VERSION if sc.ctx_ok else 1, our_action=our_action, last_seen=now,
        sender_auth=json.dumps(sc.auth, separators=(",", ":")),
        aged=1 if aged else 0,
        threat=sc.threat, threat_detail=sc.threat_detail,
        decision_names=json.dumps(sorted(sc.names | {x["n"] for x in decision.symbols})),
    )
    if decision.verdict:
        fields.update(user_verdict=decision.verdict, verdict_at=now,
                      verdict_by=decision.note or "decision")
    with db.tx():
        db.upsert_message(msgid, fmap["inbox"], sender, subject, meta.received_at)
        db.update_message(msgid, **fields)
        quality.observe(db.conn, db.account, msgid, final, thr, decision.spam, VERSION, now)
        _record_policy_trace(db, msgid, "scan", decision, now)
        try:
            policytrial.observe(db.conn, db.account, msgid, decision,
                                protected_threshold=acc.protected_threshold, version=VERSION, now=now)
        except (sqlite3.Error, ValueError, TypeError) as ex:
            log.warning("policy trial unavailable: %s", type(ex).__name__)
        db.conn.execute(
            "UPDATE messages SET origin=COALESCE(origin, 'inbox_scan') WHERE account=? AND message_id=?",
            (db.account, msgid))
        if newsletter is not None:
            try:
                nl_action = _newsletters().record_scan(db, acc, newsletter, msgid=msgid, uv=uv, uid=meta.uid,
                                                       inbox=fmap["inbox"], now=now)
            except Exception as ex:  # noqa: BLE001 - a newsletter problem never fails a scan
                log.warning("newsletter bookkeeping failed: %s", type(ex).__name__)
                nl_action = None
            if nl_action:
                our_action = nl_action
                db.update_message(msgid, our_action=nl_action)
        if our_action == "pending_move":
            # E2: clear spam goes after a few seconds, borderline after the
            # normal grace (time for the user to object). A threat is clear.
            fast = final >= thr + acc.fast_move_margin or bool(sc.threat)
            grace = acc.move_grace_seconds_high if fast else acc.move_grace_seconds
            db.add_pending_move(uv, meta.uid, msgid, folder=fmap["inbox"], due_at=now + int(grace),
                                score=final, threshold=thr)
        for ev, ev_detail in (*sc.events, *decision.events):
            db.log_event(ev, msgid, detail=ev_detail)
        if sc.threat:
            db.log_event("threat_detected", msgid, detail=f"{sc.threat}: {sc.threat_detail or '-'}"[:300])
            db.bump("threat_detected")
            _register_threat(db, msgid, sc.threat, raw, now)
        if sc.attach_rule_id is not None:
            db.conn.execute("UPDATE attach_rules SET hits=hits+1, last_hit_at=? WHERE id=?",
                            (now, sc.attach_rule_id))
        if sc.own_event is not None:
            db.log_event(sc.own_event[0], msgid, detail=sc.own_event[1])
        if aged:
            db.bump("aged_scanned")
        if sc.ckey is not None:
            try:
                c = _contacts()
                c.record_scan(db.conn, acc, sc.ckey, sender=sender, envelope_from=envelope_from,
                              dkim_domains=sc.auth.get("dkim") or [],
                              asn=c.asn_of((res.options or {}).get("ASN") or []),
                              spam=decision.spam, now=now, msgid=msgid)
                if sc.trust is not None:
                    for metric in sc.trust.metrics:
                        db.bump(metric)
                    if our_action == "pending_move" and not sc.threat:
                        c.store_recheck(db.conn, db.account, msgid, sc.trust, final=final, now=now)
            except Exception as ex:  # noqa: BLE001 - bookkeeping only
                log.warning("contact bookkeeping failed: %s", type(ex).__name__)
        if decision.rule_id is not None:
            _bump_rule_hit(db.conn, decision.rule_id)
        _zap_enqueue(db, acc, sc, msgid, meta, uv, fmap["inbox"], our_action, now)
        _av_enqueue(db, sc, msgid, meta, uv, fmap["inbox"], now)
        db.clear_scan_retry(uv, meta.uid)
        db.bump("scanned")
        if decision.spam:
            db.bump("spam_detected")
        if acted_stat:
            db.bump(acted_stat)
        if decision.rule_hit and decision.rule_hit.startswith("block:"):
            db.bump("blocklisted")
        if our_action == "allowlisted":
            db.bump("allowlisted")
        detail = (f"score={final:.2f} rspamd={res.score:.2f} action={our_action} mode={acc.mode}"
                  + (" clamped" if res.clamped else "") + (" aged" if aged else "")
                  + (f" {decision.note}" if decision.note else ""))
        db.log_event("scan", msgid, detail=detail)
        if our_action == "pending_move":
            db.log_event("pending_move", msgid, detail=f"score={final:.2f}")
        elif our_action == "flagged":
            db.log_event("flagged", msgid, detail=f"score={final:.2f}")
    # 2.7: borderline mail the decision left alone -> the local AI's second
    # opinion (queued for the worker thread; never blocks, never fails a scan).
    try:
        _ai().maybe_queue(sys.modules[__name__], db, acc, sc, msgid=msgid, uv=uv, uid=meta.uid,
                          folder=fmap["inbox"], flags=meta.flags, prior=meta.prior, raw=raw,
                          our_action=our_action, now=now)
    except Exception as ex:  # noqa: BLE001
        log.warning("ai queueing failed: %s", type(ex).__name__)
    log.debug("scored %s = %.2f (%s)", msgid, final, our_action)


# ----- 2.3 (B19): rescans ("ZAP") ---------------------------------------------

ZAP_SCHEDULE_S = (45 * 60, 4 * 3600, 24 * 3600)   # after the first scan
ZAP_MAX_AGE_S = 26 * 3600
ZAP_MAX_PER_LOOP = 20
ZAP_GRACE_S = 15
ZAP_OVERDUE_WAIT_S = 30          # wait for a due rescan that is already overdue
ZAP_MIN_SCORE = 3.0
ZAP_BELOW_THRESHOLD = 6.0
# Reputation / threat knowledge that may arrive after delivery. A change in
# Bayes (or any other content rule) alone never moves a mail.
ZAP_REPUTATION_EXACT = (frozenset({"URIBL_BLACK", "FUZZY_DENIED", PHISHARMY_SYMBOL})
                        | THREAT_PHISH | THREAT_MALWARE | THREAT_VIRUS)
ZAP_REPUTATION_PREFIXES = ("DBL_", "PHISHED_", "CLAM_", "URLHAUS_")


def reputation_symbols(names: Iterable[str]) -> set[str]:
    """B19: the reputation/threat symbols among `names` (DBL_*, *_SURBL,
    URIBL_BLACK, FUZZY_DENIED, PHISHED_*, CLAM_*, URLHAUS_* and the B16
    threat feeds). Informational and error results are not knowledge."""
    out = set()
    for n in names or ():
        n = str(n)
        if n in PHISHED_INFO or n.endswith("_FAIL") or "BLOCKED" in n or "PROHIBIT" in n:
            continue
        if n in ZAP_REPUTATION_EXACT or n.startswith(ZAP_REPUTATION_PREFIXES) or n.endswith("_SURBL"):
            out.add(n)
    return out


def _zap_enqueue(db: Db, acc: Account, sc: Scored, msgid: str, meta: _InboxMeta, uv: int,
                 inbox: str, our_action: str | None, now: int) -> bool:
    """Inside the scan transaction: queue the mail for rescans when it stayed
    in the inbox and could plausibly turn out to be spam later."""
    if not getattr(acc, "zap", False) or sc.decision.spam or our_action == "allowlisted":
        return False
    if str(sc.decision.rule_hit or "").startswith("allow:") or _sticky_ham(meta.prior):
        return False
    if sc.names & ZAP_EXCLUDE_NAMES or not message_id_searchable(msgid):
        return False
    if not (sc.final >= max(sc.thr - ZAP_BELOW_THRESHOLD, ZAP_MIN_SCORE)
            or sc.attach.has_links or sc.attach.has_attachments):
        return False
    db.conn.execute(
        "INSERT OR IGNORE INTO rescan_queue(account, message_id, folder, uidvalidity, uid, first_score, "
        "attempt, due_at, queued_at, first_symbols) VALUES(?,?,?,?,?,?,0,?,?,?)",
        (db.account, msgid, inbox, uv, meta.uid, sc.final, now + ZAP_SCHEDULE_S[0], now,
         json.dumps(sorted(sc.names), separators=(",", ":"))))
    return True


def _zap_age_text(seconds: int) -> str:
    seconds = max(0, int(seconds))
    if seconds < 3600:
        return f"{max(1, seconds // 60)} min"
    return f"{seconds // 3600} t"


def zap_pass(client: IMAPClient, db: Db, log: logging.Logger, acc: Account, fmap: dict[str, str],
             state: AccountState) -> int:
    """B19: rescan due rescan_queue rows (max ZAP_MAX_PER_LOOP). Finds each
    mail by exact Message-ID in the INBOX only. Acts only when the new score
    reaches the threshold (or a threat) AND a new reputation/threat symbol
    appeared: unread mail is moved (pending_move origin 'zap', short grace,
    counted by the circuit breaker), read mail only for a threat - else the
    score is recorded as would_have_zapped. Never deletes anything."""
    if not getattr(acc, "zap", False) or SHUTDOWN.is_set():
        return 0
    if state.rspamd_backoff_until > time.monotonic() or db.in_safe_mode("all"):
        return 0
    now = int(_now())
    with db.tx():
        dropped = db.conn.execute("DELETE FROM rescan_queue WHERE account=? AND queued_at<?",
                                  (db.account, now - ZAP_MAX_AGE_S)).rowcount
    if dropped:
        log.debug("dropped %d expired rescan(s)", dropped)
    rows = db.conn.execute(
        "SELECT * FROM rescan_queue WHERE account=? AND due_at<=? ORDER BY due_at LIMIT ?",
        (db.account, now, ZAP_MAX_PER_LOOP)).fetchall()
    if not rows:
        return 0
    inbox = fmap["inbox"]
    uv = select_with_uidvalidity_check(client, db, inbox, log, readonly=acc.mode == "shadow")
    done = 0
    for r in rows:
        if SHUTDOWN.is_set():
            break
        _touch_alive(db)
        try:
            _zap_one(client, db, log, acc, fmap, state, uv, r)
        except RspamdError as ex:
            if ex.outage and not _rspamd_alive():
                _enter_rspamd_backoff(db, log, state, str(ex))
                break
            _zap_reschedule(db, r, None, f"rspamd: {ex}")
        except _CONN_ERRORS:
            raise
        except Exception as ex:  # noqa: BLE001 - one bad mail never stops the pass
            log.warning("rescan of %s failed: %s", r["message_id"], _short_err(ex))
            _zap_reschedule(db, r, None, _short_err(ex))
        done += 1
    return done


def _zap_drop(db: Db, msgid: str, reason: str) -> None:
    with db.tx():
        db.conn.execute("DELETE FROM rescan_queue WHERE account=? AND message_id=?", (db.account, msgid))
        db.log_event("zap_skipped", msgid, detail=reason[:200])


def _zap_reschedule(db: Db, r: sqlite3.Row, score: float | None, note: str | None = None) -> None:
    nxt = int(r["attempt"]) + 1
    with db.tx():
        if nxt >= len(ZAP_SCHEDULE_S):
            db.conn.execute("DELETE FROM rescan_queue WHERE account=? AND message_id=?",
                            (db.account, r["message_id"]))
        else:
            db.conn.execute(
                "UPDATE rescan_queue SET attempt=?, due_at=?, last_score=COALESCE(?, last_score), last_at=? "
                "WHERE account=? AND message_id=?",
                (nxt, int(r["queued_at"]) + ZAP_SCHEDULE_S[nxt], score, int(_now()), db.account,
                 r["message_id"]))
        if note:
            db.log_event("zap_failed", r["message_id"], detail=note[:200])


def _zap_one(client: IMAPClient, db: Db, log: logging.Logger, acc: Account, fmap: dict[str, str],
             state: AccountState, uv: int, r: sqlite3.Row) -> str:
    msgid = r["message_id"]
    inbox = fmap["inbox"]
    row = db.get_message(msgid)
    if row is None:
        _zap_drop(db, msgid, "ukendt")
        return "dropped"
    if row["user_verdict"] or _sticky_ham(row):
        _zap_drop(db, msgid, "brugerens afgørelse")
        return "dropped"
    action = row["our_action"] or "none"
    folder = inbox
    if action == "newsletter_moved":
        # 2.6 (A4): a late reputation hit pulls a newsletter out of the
        # newsletter folder too - spam has priority.
        folder = _newsletters().folder_of(acc)
    if action not in ZAP_ACTIONS or row["current_folder"] != folder:
        _zap_drop(db, msgid, f"ændret ({row['our_action'] or row['current_folder']})")
        return "dropped"
    if folder == inbox:
        return _zap_live(client, db, log, acc, state, uv, r, row, folder)
    fuv = select_with_uidvalidity_check(client, db, folder, log, readonly=acc.mode == "shadow")
    try:
        return _zap_live(client, db, log, acc, state, fuv, r, row, folder)
    finally:
        select_with_uidvalidity_check(client, db, inbox, log, readonly=acc.mode == "shadow")


# our_action values a rescan may act on: the inbox (also a newsletter
# waiting for its move) and the newsletter folder (2.6 A4).
ZAP_ACTIONS = ("none", "newsletter_pending", "newsletter_moved")


def _zap_live(client: IMAPClient, db: Db, log: logging.Logger, acc: Account, state: AccountState, uv: int,
              r: sqlite3.Row, row: sqlite3.Row, folder: str) -> str:
    """_zap_one in the selected `folder` (the inbox or the newsletter folder)."""
    msgid = r["message_id"]
    uids = find_uids_by_message_id(client, msgid)
    if not uids:
        _zap_drop(db, msgid, "ikke længere i indbakken" if folder == r["folder"] else f"ikke længere i {folder}")
        return "dropped"
    if len(uids) > 1:
        _zap_drop(db, msgid, "flere mails med samme Message-ID")
        return "dropped"
    uid = int(uids[0])
    data = client.fetch([uid], [b"FLAGS", b"RFC822.SIZE", b"INTERNALDATE"]).get(uid) or {}
    flags = _flag_names(data.get(b"FLAGS"))
    if "\\Flagged" in flags:
        _zap_drop(db, msgid, "stjernemarkeret")
        return "dropped"
    if "\\Deleted" in flags:
        _zap_drop(db, msgid, "markeret slettet")
        return "dropped"
    size = data.get(b"RFC822.SIZE")
    if size is not None and int(size) > MAX_FETCH_BYTES:
        _zap_drop(db, msgid, "for stor")
        return "dropped"
    raw = _body_bytes(client.fetch([uid], [b"BODY.PEEK[]"]).get(uid))
    if not raw:
        _zap_reschedule(db, r, None, "body missing")
        return "retry"
    received_at = _internaldate_ts(data) or row["received_at"]
    sc = _score_message(db, acc, raw, msgid=msgid, prior=row, flags=flags, received_at=received_at)
    try:
        first = set(json.loads(r["first_symbols"] or "[]"))
    except (TypeError, ValueError):
        first = set()
    new_rep = sorted(reputation_symbols(sc.names) - reputation_symbols(first))
    now = int(_now())
    age = now - int(received_at or r["queued_at"])
    first_score = float(r["first_score"] or 0.0)
    diff = (f"ny={','.join(new_rep) or '-'} efter={_zap_age_text(age)} "
            f"score={first_score:.2f}->{sc.final:.2f}"
            + (f" trussel={sc.threat}" if sc.threat else "") + (" aged" if sc.aged else ""))
    act = sc.decision.spam and bool(new_rep)
    seen = "\\Seen" in flags
    if not act:
        with db.tx():
            db.log_event("zap_rescore", msgid, detail=diff[:300])
        _zap_reschedule(db, r, sc.final)
        return "rescored"

    def dequeue() -> None:
        db.conn.execute("DELETE FROM rescan_queue WHERE account=? AND message_id=?", (db.account, msgid))

    outcome = _rescan_act(client, db, log, acc, uv, uid, msgid, folder, sc, raw, seen, diff, now, dequeue)
    log.info("rescan of %s: %s (%s)", msgid, outcome, diff)
    return outcome


def _rescan_act(client: IMAPClient, db: Db, log: logging.Logger, acc: Account, uv: int, uid: int, msgid: str,
                folder: str, sc: Scored, raw: bytes, seen: bool, diff: str, now: int,
                dequeue: Callable[[], None]) -> str:
    """B19 / 2.7: act on a rescan that turned spam (or a threat): move
    (pending_move origin 'zap'), flag, or record in Overvåg. Read mail is
    only taken away for a threat. `dequeue` runs inside the transaction."""
    fields: dict[str, Any] = dict(
        our_score=sc.final, rspamd_score=sc.res.score,
        symbols=json.dumps(sc.symbols, ensure_ascii=False, separators=(",", ":")),
        decision_names=json.dumps(sorted(sc.names | {x["n"] for x in sc.decision.symbols})),
        sender_auth=json.dumps(sc.auth, separators=(",", ":")),
        rule_hit=sc.decision.rule_hit, threat=sc.threat, threat_detail=sc.threat_detail,
        aged=1 if sc.aged else 0, last_seen=now)
    with db.tx():
        _record_policy_trace(db, msgid, "rescan_policy", sc.decision, now)
        dequeue()
        if seen and not sc.threat:
            # Read mail is never taken away for spam alone (B19): the user
            # may be reading it right now.
            db.update_message(msgid, **fields)
            db.log_event("would_have_zapped", msgid, detail=f"læst {diff}"[:300])
            db.bump("would_have_zapped")
            outcome = "would_have_zapped"
        elif acc.mode == "move":
            fields.update(our_action="pending_move")
            db.update_message(msgid, **fields)
            db.conn.execute("DELETE FROM newsletter_pending WHERE account=? AND message_id=?",
                            (db.account, msgid))  # spam has priority over the newsletter folder
            db.add_pending_move(uv, uid, msgid, folder=folder, due_at=now + ZAP_GRACE_S, score=sc.final,
                                threshold=sc.thr, origin="zap")
            db.log_event("zap_move", msgid, detail=diff[:300])
            outcome = "zap_move"
        elif acc.mode == "flag":
            outcome = "zap_flag"
        else:
            fields.update(our_action="shadow_spam")
            db.update_message(msgid, **fields)
            db.log_event("would_have_zapped", msgid, detail=f"overvåger {diff}"[:300])
            db.bump("would_have_zapped")
            outcome = "would_have_zapped"
        if sc.threat:
            db.log_event("threat_detected", msgid, detail=f"{sc.threat}: {sc.threat_detail or '-'} (genscanning)"[:300])
            db.bump("threat_detected")
            _register_threat(db, msgid, sc.threat, raw, now)
    if outcome == "zap_flag":
        try:
            client.add_flags([uid], _junk_flags(sc.threat))
        except _CONN_ERRORS:
            raise
        except IMAPClientError as ex:
            log.warning("rescan flag on uid %s failed: %s", uid, type(ex).__name__)
            with db.tx():
                db.log_event("flag_failed", msgid, detail=type(ex).__name__)
            return "failed"
        with db.tx():
            db.update_message(msgid, our_action="flagged", zapped_at=now, **fields)
            db.log_event("zap_move", msgid, detail=f"markeret {diff}"[:300])
            db.bump("zapped")
            db.bump("flagged")
    return outcome


# ----- 2.7 fix: antivirus re-scans (CLAM_VIRUS_FAIL) ---------------------------

AV_RESCAN_SCHEDULE_S = (10 * 60, 3600, 6 * 3600)   # after the first scan
AV_RESCAN_MAX_AGE_S = 7 * 3600
AV_RESCAN_MAX_PER_LOOP = 10
# our_action values the antivirus re-scan may act on (the mail is still in the inbox).
AV_RESCAN_ACTIONS = ("none", "newsletter_pending")


# 2.12 (#21): while ClamAV is not ready (starting, first signatures) the
# queue waits instead of using up its attempts; once it answers, the first
# re-scan of a queued mail runs at once (not only after 10 min).
AV_READY_CHECK_S = 60
AV_READY_MIN_WAIT_S = 60
_AV_READY: dict[str, Any] = {"at": 0.0, "ok": None}


def clamav_ready() -> bool | None:
    """True/False in the all-in-one container (a rspamd test scan through
    aio_health, cached AV_READY_CHECK_S); None elsewhere (no clamd to ask:
    the queue then runs on its plain schedule)."""
    if os.environ.get("SPAMFILTER_AIO") != "1":
        return None
    t = time.monotonic()
    if _AV_READY["ok"] is not None and t - float(_AV_READY["at"]) < AV_READY_CHECK_S:
        return bool(_AV_READY["ok"])
    try:
        import aio_health

        ok = bool(aio_health.probe_clamav_ready().ok)
    except Exception:  # noqa: BLE001 - unknown = not ready; asked again next minute
        ok = False
    _AV_READY.update(at=t, ok=ok)
    return ok


def _av_enqueue(db: Db, sc: Scored, msgid: str, meta: _InboxMeta, uv: int, inbox: str, now: int) -> bool:
    """Inside the scan transaction: ClamAV did not answer (CLAM_VIRUS_FAIL)
    for a mail that stayed in the inbox -> scan it again by UID later.
    2.12 (#21): also without attachments - since 2.8 ClamAV reads the text
    parts too (Sanesecurity). Independent of zap and its exclusions
    (contacts, replies, allow rules, zap off): a virus is a virus whoever
    sent it."""
    names = sc.names or frozenset()
    if "CLAM_VIRUS_FAIL" not in names or "CLAM_VIRUS" in names or sc.decision.spam or sc.threat:
        return False
    db.conn.execute(
        "INSERT OR IGNORE INTO av_rescan_queue(account, folder, uidvalidity, uid, message_id, attempt, due_at, "
        "queued_at) VALUES(?,?,?,?,?,0,?,?)",
        (db.account, inbox, int(uv), int(meta.uid), msgid, now + AV_RESCAN_SCHEDULE_S[0], now))
    return True


def _av_drop(db: Db, r: sqlite3.Row, reason: str, event: str = "av_rescan_skipped") -> None:
    with db.tx():
        db.conn.execute("DELETE FROM av_rescan_queue WHERE account=? AND uidvalidity=? AND uid=?",
                        (db.account, int(r["uidvalidity"]), int(r["uid"])))
        db.log_event(event, r["message_id"], detail=reason[:200])


def _av_reschedule(db: Db, r: sqlite3.Row, note: str) -> None:
    nxt = int(r["attempt"]) + 1
    if nxt >= len(AV_RESCAN_SCHEDULE_S):
        _av_drop(db, r, f"opgivet efter {nxt} forsøg ({note})")
        return
    with db.tx():
        db.conn.execute("UPDATE av_rescan_queue SET attempt=?, due_at=? WHERE account=? AND uidvalidity=? AND uid=?",
                        (nxt, int(r["queued_at"]) + AV_RESCAN_SCHEDULE_S[nxt], db.account, int(r["uidvalidity"]),
                         int(r["uid"])))


def av_rescan_pass(client: IMAPClient, db: Db, log: logging.Logger, acc: Account, fmap: dict[str, str],
                   state: AccountState) -> int:
    """2.7 fix: due antivirus re-scans (max AV_RESCAN_MAX_PER_LOOP). Acts
    ONLY when the new scan has CLAM_VIRUS as the threat class 'virus' -
    then the normal virus handling (to Spamfilter, alert); everything else
    (still no answer, clean, a heuristic hit) changes nothing. Never deletes
    anything; Overvåg accounts only record."""
    if SHUTDOWN.is_set() or state.rspamd_backoff_until > time.monotonic() or db.in_safe_mode("all"):
        return 0
    now = int(_now())
    try:
        with db.tx():
            db.conn.execute("DELETE FROM av_rescan_queue WHERE account=? AND queued_at<?",
                            (db.account, now - AV_RESCAN_MAX_AGE_S))
        ready = None
        if db.conn.execute("SELECT 1 FROM av_rescan_queue WHERE account=? LIMIT 1", (db.account,)).fetchone():
            ready = clamav_ready()
        if ready is False:
            return 0   # ClamAV is still starting: keep the attempts for when it answers
        # Ready (all-in-one): a queued mail's first re-scan is due at once.
        early = now - AV_READY_MIN_WAIT_S if ready else -1
        rows = db.conn.execute(
            "SELECT * FROM av_rescan_queue WHERE account=? AND (due_at<=? OR (attempt=0 AND queued_at<=?)) "
            "ORDER BY due_at LIMIT ?",
            (db.account, now, early, AV_RESCAN_MAX_PER_LOOP)).fetchall()
    except sqlite3.OperationalError:
        return 0  # an odd DB without the table
    if not rows:
        return 0
    inbox = fmap["inbox"]
    uv = select_with_uidvalidity_check(client, db, inbox, log, readonly=acc.mode == "shadow")
    done = 0
    for r in rows:
        if SHUTDOWN.is_set():
            break
        _touch_alive(db)
        try:
            _av_rescan_one(client, db, log, acc, uv, inbox, r)
        except RspamdError as ex:
            if ex.outage and not _rspamd_alive():
                _enter_rspamd_backoff(db, log, state, str(ex))
                break
            _av_reschedule(db, r, f"rspamd: {ex}")
        except _CONN_ERRORS:
            raise
        except Exception as ex:  # noqa: BLE001 - one bad mail never stops the pass
            log.warning("antivirus rescan of %s failed: %s", r["message_id"], _short_err(ex))
            _av_reschedule(db, r, _short_err(ex))
        done += 1
    return done


def _av_rescan_one(client: IMAPClient, db: Db, log: logging.Logger, acc: Account, uv: int, inbox: str,
                   r: sqlite3.Row) -> str:
    msgid = r["message_id"]
    if int(r["uidvalidity"]) != int(uv) or r["folder"] != inbox:
        _av_drop(db, r, "indbakken har fået nye UID'er")
        return "dropped"
    row = db.get_message(msgid)
    if row is None:
        _av_drop(db, r, "ukendt")
        return "dropped"
    if row["user_verdict"] or _sticky_ham(row):
        _av_drop(db, r, "brugerens afgørelse")
        return "dropped"
    if (row["our_action"] or "none") not in AV_RESCAN_ACTIONS or row["current_folder"] != inbox:
        _av_drop(db, r, f"ændret ({row['our_action'] or row['current_folder']})")
        return "dropped"
    uid = int(r["uid"])
    data = client.fetch([uid], [b"FLAGS", b"RFC822.SIZE", b"INTERNALDATE"]).get(uid) or {}
    if not data:
        _av_drop(db, r, "ikke længere i indbakken")
        return "dropped"
    flags = _flag_names(data.get(b"FLAGS"))
    if "\\Deleted" in flags:
        _av_drop(db, r, "markeret slettet")
        return "dropped"
    size = data.get(b"RFC822.SIZE")
    if size is not None and int(size) > MAX_FETCH_BYTES:
        _av_drop(db, r, "for stor")
        return "dropped"
    raw = _body_bytes(client.fetch([uid], [b"BODY.PEEK[]"]).get(uid))
    if not raw:
        _av_reschedule(db, r, "body missing")
        return "retry"
    if (msgid.startswith(mailidentity.PREFIX) and msgid != mailidentity.PREFIX + mailidentity.fingerprint(raw)) or (
            not msgid.startswith(mailidentity.PREFIX) and normalize_message_id(parse_envelope(raw)[0])
            not in (None, normalize_message_id(msgid))):
        _av_drop(db, r, "en anden mail har UID'en")
        return "dropped"
    received_at = _internaldate_ts(data) or row["received_at"]
    sc = _score_message(db, acc, raw, msgid=msgid, prior=row, flags=flags, received_at=received_at)
    now = int(_now())
    age = now - int(received_at or r["queued_at"])
    if sc.threat == "virus" and sc.decision.spam:
        diff = (f"ny=CLAM_VIRUS efter={_zap_age_text(age)} score={float(row['our_score'] or 0):.2f}->"
                f"{sc.final:.2f} trussel=virus ({sc.threat_detail or '-'}) antivirus")

        def dequeue() -> None:
            db.conn.execute("DELETE FROM av_rescan_queue WHERE account=? AND uidvalidity=? AND uid=?",
                            (db.account, int(r["uidvalidity"]), uid))
            db.conn.execute("DELETE FROM rescan_queue WHERE account=? AND message_id=?", (db.account, msgid))

        outcome = _rescan_act(client, db, log, acc, uv, uid, msgid, inbox, sc, raw, "\\Seen" in flags, diff, now,
                              dequeue)
        log.info("antivirus rescan of %s: %s (%s)", msgid, outcome, diff)
        return outcome
    if "CLAM_VIRUS_FAIL" in sc.names and "CLAM_VIRUS" not in sc.names:
        _av_reschedule(db, r, "ClamAV svarer stadig ikke")
        return "retry"
    found = clam_signatures(sc.res.symbols, sc.res.options) if "CLAM_VIRUS" in sc.names else []
    _av_drop(db, r, f"efter {_zap_age_text(age)}: " + (f"kun heuristik ({', '.join(found[:2])})"[:150] if found
                                                       else "ingen virus"), event="av_rescan_clean")
    return "clean"


# Message-ID + our receipt marker (E12) in one header fetch.
_HDR_INBOX = b"BODY.PEEK[HEADER.FIELDS (MESSAGE-ID X-TH-SPAMFILTER)]"
_INBOX_META_ITEMS = [b"FLAGS", b"RFC822.SIZE", b"INTERNALDATE", _HDR_INBOX]


def scan_inbox(
    client: IMAPClient,
    db: Db,
    log: logging.Logger,
    acc: Account,
    fmap: dict[str, str],
    state: AccountState | None = None,
) -> None:
    """Score new inbox mail (UIDs above the bookmark) and act per mode."""
    state = state if state is not None else AccountState()
    if state.rspamd_backoff_until > time.monotonic():
        return  # rspamd is down: no SEARCH/FETCH until the backoff ends
    inbox = fmap["inbox"]
    readonly = acc.mode == "shadow"
    uv = select_with_uidvalidity_check(client, db, inbox, log, readonly=readonly)
    # High-water UID bookmark: mail that existed when the filter first saw
    # this (folder, uidvalidity) is never scanned. Mail moved back into the
    # inbox gets a fresh UID above the bookmark, so rescues still surface.
    bookmark = db.get_scan_bookmark(inbox, uv)
    if bookmark is None:
        existing = client.search(["ALL"])
        init_uid = max(existing) if existing else 0
        with db.tx():
            db.set_scan_bookmark(inbox, uv, init_uid)
            db.log_event("scan_bookmark_init",
                         detail=f"uv={uv} max_uid={init_uid} skipped={len(existing or [])}")
        log.info("scan_inbox: initialized bookmark for %s (uv=%d) at uid=%d, skipping %d "
                 "pre-existing messages", inbox, uv, init_uid, len(existing or []))
        state.bookmark_lag = 0
        return
    # RFC 3501: "n:*" always includes the highest UID even when it is below
    # n, so both results are filtered to uid > bookmark.
    new_range = f"{bookmark + 1}:*"
    unseen = {int(u) for u in client.search(["UNSEEN", "UID", new_range]) if int(u) > bookmark}
    new_uids = sorted({int(u) for u in client.search(["UID", new_range]) if int(u) > bookmark} | unseen)
    cap = acc.safe_mode_unseen_cap
    if len(unseen) > cap:
        reason = f"Inbox UNSEEN > {cap} ({len(unseen)}) - refusing to process"
        log.error(reason)
        with db.tx():
            db.enter_safe_mode("all", reason)
            db.log_event("safe_mode", detail=reason)
        _alert_safe_mode(db, acc, len(unseen), cap)
        return
    # The cap check above is the only way into safe mode "all", so seeing
    # unseen <= cap means it is safe to resume.
    if db.in_safe_mode("all"):
        log.info("exiting safe mode (unseen=%d back under cap=%d)", len(unseen), cap)
        with db.tx():
            db.exit_safe_mode("all")
            db.log_event("safe_mode_exit", detail=f"unseen={len(unseen)}")
        alert_clear(db.conn, f"safe:{acc.name}")
    with db.tx():
        # Retries for UIDs that are gone (deleted/moved by the user, or an
        # older UIDVALIDITY) can never succeed: drop them.
        db.prune_orphan_scan_retry(uv, new_uids)
    if not new_uids:
        state.bookmark_lag = 0
        return

    processed = state.processed_for(inbox, uv)
    retry_rows = db.scan_retry_rows(uv, new_uids)
    now = _now()
    todo: list[int] = []
    for uid in new_uids:
        if uid in processed:
            continue
        r = retry_rows.get(uid)
        if r is not None:
            if int(r["attempts"]) >= SCAN_RETRY_MAX_ATTEMPTS:
                processed.add(uid)  # given up earlier (maybe before a restart)
                continue
            if now - r["first_fail_at"] >= SCAN_RETRY_MAX_AGE_S:
                with db.tx():
                    db.mark_scan_given_up(uv, uid)
                    db.log_event("scan_giveup", detail=f"uid={uid} after {SCAN_RETRY_MAX_AGE_S // 3600} h")
                    db.bump("scan_giveup")
                processed.add(uid)
                continue
            if now < _retry_due_at(r):
                continue
        todo.append(uid)
    todo = todo[:MAX_SCAN_PER_RUN]
    if todo:
        db.status(state="working", detail="Scanner nye mails…")

    outage = False
    dmarc_cfg = _dmarc_settings(db, acc) if todo else None  # 2.6 (C2)
    if dmarc_cfg is not None and not readonly:
        _dmarc_repair(client, db, log, acc, fmap, state)
    for chunk in _chunks(todo, SCAN_FETCH_CHUNK):
        if SHUTDOWN.is_set() or outage:
            break
        meta_reply = client.fetch(list(chunk), _INBOX_META_ITEMS)
        to_scan: list[_InboxMeta] = []
        for uid in chunk:
            if SHUTDOWN.is_set():
                break
            try:
                res = _classify_inbox_uid(client, db, log, acc, fmap, uv, uid,
                                          meta_reply.get(uid), readonly, processed)
            except _CONN_ERRORS:
                raise
            except Exception as ex:  # noqa: BLE001 - isolate one bad message
                _scan_failed(db, log, uv, uid, _short_err(ex), processed)
                continue
            if res is None:
                processed.add(uid)
            elif res is not False:
                to_scan.append(res)
        for sub in _chunks(to_scan, SCAN_BODY_CHUNK):
            if SHUTDOWN.is_set() or outage:
                break
            # E11: a long backlog scan is not a silent (stale) thread.
            _touch_alive(db)
            fetch_uids = [m.uid for m in sub if m.raw is None]
            bodies = client.fetch(fetch_uids, [b"BODY.PEEK[]"]) if fetch_uids else {}
            for meta in sub:
                if SHUTDOWN.is_set():
                    break
                raw = meta.raw or _body_bytes(bodies.get(meta.uid))
                if not raw:
                    _scan_failed(db, log, uv, meta.uid, "body missing", processed)
                    continue
                try:
                    _scan_and_act(client, db, log, acc, fmap, state, uv, meta, raw, dmarc_cfg=dmarc_cfg)
                except RspamdError as ex:
                    if ex.outage and not _rspamd_alive():
                        _enter_rspamd_backoff(db, log, state, str(ex))
                        outage = True
                        break
                    _scan_failed(db, log, uv, meta.uid, f"rspamd: {ex}", processed)
                    continue
                except _CONN_ERRORS:
                    raise
                except Exception as ex:  # noqa: BLE001 - isolate one bad message
                    _scan_failed(db, log, uv, meta.uid, _short_err(ex), processed)
                    continue
                processed.add(meta.uid)

    # Advance over the contiguous prefix of finished UIDs: a UID awaiting a
    # retry (or not reached because of an outage/shutdown/cap) holds it.
    new_bm = bookmark
    for uid in new_uids:
        if uid in processed:
            new_bm = uid
        else:
            break
    if new_bm > bookmark:
        with db.tx():
            db.set_scan_bookmark(inbox, uv, new_bm)
    processed.difference_update([u for u in processed if u <= new_bm])
    state.bookmark_lag = sum(1 for u in new_uids if u > new_bm)
    if todo:
        state.last_scan_at = int(_now())
        db.status(last_scan_at=state.last_scan_at, bookmark_lag=state.bookmark_lag)


# ----- 2.6 (C2): DMARC aggregate reports (dmarc.py) --------------------------


def _dmarc_settings(db: Db, acc: Account) -> dict[str, Any] | None:
    """The DMARC settings when this mailbox takes aggregate reports, else None."""
    try:
        import dmarc  # noqa: PLC0415

        cfg = dmarc.load_settings(db.conn)
        return cfg if dmarc.account_mode(cfg, acc) == "on" else None
    except Exception as ex:  # noqa: BLE001 - optional feature
        logging.getLogger("filter").warning("dmarc settings unavailable: %s", type(ex).__name__)
        return None


def _dmarc_take(client: IMAPClient, db: Db, log: logging.Logger, acc: Account, fmap: dict[str, str],
                uv: int, meta: _InboxMeta, raw: bytes, cfg: dict[str, Any], sc: Scored) -> bool:
    """After the normal scan: True when the mail was a clean DMARC report of
    ours from a trusted reporter AND was moved to the DMARC folder
    (dmarc.take). False (or any failure) = the normal decision path goes on."""
    try:
        import dmarc  # noqa: PLC0415

        return bool(dmarc.take(sys.modules[__name__], client, db, log, acc, fmap, uv, meta, raw,
                               readonly=acc.mode == "shadow", settings=cfg, scored=sc))
    except _CONN_ERRORS:
        raise
    except Exception as ex:  # noqa: BLE001 - hostile reports must never break the scan
        log.warning("dmarc report handling failed: %s", type(ex).__name__)
        return False


def _dmarc_repair(client: IMAPClient, db: Db, log: logging.Logger, acc: Account, fmap: dict[str, str],
                  state: AccountState) -> None:
    """Finish an interrupted move to the DMARC folder (move journal)."""
    try:
        import dmarc  # noqa: PLC0415

        if acc.mode == "move" and move_method_for(state.caps or client_capabilities(client)) != "none":
            dmarc.repair_moves(sys.modules[__name__], client, db, log, acc, fmap, state)
    except _CONN_ERRORS:
        raise
    except Exception as ex:  # noqa: BLE001 - the scan goes on; the journal row stays
        log.warning("dmarc move repair failed: %s", type(ex).__name__)


def _journal_rows(db: Db, folder: str | None = None) -> list[sqlite3.Row]:
    sql = "SELECT * FROM move_journal WHERE account=?"
    args: list[Any] = [db.account]
    if folder is not None:
        sql += " AND folder=?"
        args.append(folder)
    return list(db.conn.execute(sql + " ORDER BY started_at, uid", args).fetchall())


def _journal_has(db: Db, msgid: str) -> bool:
    return db.conn.execute("SELECT 1 FROM move_journal WHERE account=? AND message_id=? LIMIT 1",
                           (db.account, msgid)).fetchone() is not None


def _journal_writer(db: Db, folder: str, uv: int, dest: str, msgids: dict[int, str],
                    idates: dict[int, int | None]) -> Any:
    """on_stage callback for imap_move: records each step BEFORE it runs, in
    its own committed statement, so a crash/disconnect leaves the truth."""

    def on_stage(stage: str, uids: list[int], predeleted: set[int]) -> None:
        now = int(_now())
        with _autocommit(db.conn):
            for uid in uids:
                if stage == "clear":
                    db.conn.execute("DELETE FROM move_journal WHERE account=? AND folder=? "
                                    "AND uidvalidity=? AND uid=?", (db.account, folder, uv, uid))
                    continue
                db.conn.execute(
                    """
                    INSERT INTO move_journal(account, folder, uidvalidity, uid, message_id, dest, stage,
                                             internaldate, predeleted, started_at, updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(account, folder, uidvalidity, uid) DO UPDATE SET
                        stage=excluded.stage, updated_at=excluded.updated_at,
                        predeleted=excluded.predeleted
                    """,
                    (db.account, folder, uv, uid, msgids.get(uid, ""), dest, stage, idates.get(uid),
                     1 if uid in predeleted else 0, now, now))
    return on_stage


def execute_due_moves(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
                      fmap: dict[str, str], state: AccountState | None = None) -> None:
    """Move pending spam to the junk folder once its due time passed (E2:
    fast for clear spam). Safety nets (E1): the circuit breaker pauses all
    moves until an admin resumes them, and right after an update only
    clear spam moves. Each move is journalled (E5)."""
    if acc.mode != "move":
        return
    if db.in_safe_mode("all"):
        return
    if circuit_open(db.conn, db.account):
        return
    state = state if state is not None else AccountState()
    _execute_due_moves_in(client, db, log, acc, fmap, state, fmap["inbox"])
    # 2.6 (A2/A4): spam caught late in the newsletter folder (a rescan or a
    # campaign verdict) moves from there, with the same safety nets.
    for src in _other_move_sources(db, acc, fmap):
        if SHUTDOWN.is_set() or circuit_open(db.conn, db.account):
            break
        try:
            _execute_due_moves_in(client, db, log, acc, fmap, state, src)
        finally:
            select_with_uidvalidity_check(client, db, fmap["inbox"], log)


def _other_move_sources(db: Db, acc: Account, fmap: dict[str, str]) -> list[str]:
    """Source folders besides the inbox with pending filter moves: only the
    newsletter folder (never junk/trash, never an unknown folder)."""
    try:
        nl = _newsletters().folder_of(acc)
    except Exception:  # noqa: BLE001
        return []
    if not nl or nl in (fmap["inbox"], fmap["junk"], fmap.get("trash"), fmap.get("provider_junk")):
        return []
    row = db.conn.execute("SELECT 1 FROM pending_move WHERE account=? AND folder=? LIMIT 1",
                          (db.account, nl)).fetchone()
    return [nl] if row is not None else []


def _execute_due_moves_in(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
                          fmap: dict[str, str], state: AccountState, source: str) -> None:
    """execute_due_moves for one source folder (`inbox` below is `source`)."""
    inbox, junk = source, fmap["junk"]
    now = int(_now())
    hold_until = move_hold_until(db.conn)
    if db.conn.execute(
        "SELECT 1 FROM pending_move WHERE account=? AND folder=? "
        "AND COALESCE(due_at, flag_at + ?) <= ? "
        "AND (? <= ? OR (score IS NOT NULL AND score >= COALESCE(threshold, ?) + ?) "
        f"OR {_PM_THREAT_SQL}) LIMIT 1",
        (db.account, inbox, acc.move_grace_seconds, now, hold_until, now, acc.threshold,
         UPDATE_HOLD_MARGIN),
    ).fetchone() is None:
        return
    if getattr(acc, "known_contacts", False) and source == fmap["inbox"]:
        # 2.3 (B11 freshness): a due move whose references matched nothing
        # at scan time - maybe the user's own mail was not synced yet.
        try:
            _contacts().recheck_pending(client, db, log, acc, fmap, state, key=_contacts_key(db), now=now)
        except _CONN_ERRORS:
            raise
        except Exception as ex:  # noqa: BLE001 - never block moving
            log.warning("reply re-check failed: %s", _short_err(ex))
    uv = select_with_uidvalidity_check(client, db, inbox, log)
    rows = db.due_pending_moves(uv, acc.move_grace_seconds, folder=inbox, hold_until=hold_until,
                                default_threshold=acc.threshold)
    if not rows:
        return
    if not check_rate(db, log, "move", acc.max_moves_per_hour):
        return

    fetched = client.fetch([r["uid"] for r in rows], [b"FLAGS", b"INTERNALDATE"])
    to_move: list[int] = []
    by_uid: dict[int, sqlite3.Row] = {}
    threats: dict[int, str] = {}
    for r in rows:
        uid, msgid = int(r["uid"]), r["message_id"]
        skip: str | None = None
        force_rule: sqlite3.Row | None = None
        if _journal_has(db, msgid):
            continue  # an interrupted move of this message awaits repair
        if db.conn.execute('SELECT 1 FROM pending_move WHERE account=? AND uidvalidity=? AND uid=?',
                           (db.account, uv, uid)).fetchone() is None:
            continue  # a user action cancelled it while FETCH was in flight
        if uid not in fetched:
            skip = "move_skipped_missing"
        else:
            msg = db.get_message(msgid)
            flags = _flag_names(fetched[uid].get(b"FLAGS"))
            force_rule = (force_allow_rule(db.conn, acc.name, msg["sender"])
                          if msg is not None else None)
            how = force_verification(force_rule, msg["sender_auth"]) if force_rule is not None else None
            if force_rule is not None and how is None:
                force_rule = None  # E8: unverified 'Altid igennem' = normal allow
            threat = _row_get(msg, "threat")
            if force_rule is not None and threat and (threat not in THREAT_FORCE_PASSABLE
                                                      or not str(how).startswith("dkim:")):
                force_rule = None  # B16: a virus always goes; other threats need DKIM
            current_allow = None
            if msg is not None and msg["sender"]:
                current_allow = match_sender_rule(db.conn, acc.name, msg["sender"])
                if (current_allow is not None and current_allow["kind"] == "allow"
                        and not rule_is_force(current_allow) and msg["decision_names"]):
                    decision = _decide(db, acc, msg, msg["sender"], float(msg["our_score"] or 0),
                                       frozenset(json.loads(msg["decision_names"])) if msg["decision_names"]
                                       else frozenset(x["n"] for x in _symbol_list(msg["symbols"])), flags,
                                       auth=parse_sender_auth(msg["sender_auth"]), threat=threat,
                                       aged_unverified=bool(msg["aged"]) and
                                       "TH_AGED_UNVERIFIED" in (msg["symbols"] or ""))
                    _record_policy_trace(db, msgid, "pending_allow_recheck", decision, int(_now()))
                    if decision.spam or not decision.rule_hit:
                        current_allow = None
                else:
                    current_allow = None
            auto_undo = None
            hit = str(_row_get(msg, 'rule_hit') or '')
            if hit.startswith('block:'):
                automatic_rule = db.conn.execute(
                    "SELECT 1 FROM junk_sender_notes WHERE account=? AND sender=? AND kind='suggest' "
                    "AND status IN ('auto_blocked','undone') AND CAST(block_rule_id AS TEXT)=?",
                    (db.account, _junkrules()._addr(_row_get(msg, 'sender')), hit.partition(':')[2])).fetchone()
                if automatic_rule is not None:
                    # Covers the existing Tjek disse undo button as well as
                    # rescued mail, including a reversal during live FETCH.
                    auto_undo = _auto_block_pending_decision(db, acc, msg, _row_get(r, 'threshold'))
            if _sticky_ham(msg):
                skip = "move_skipped_verdict"
            elif auto_undo is not None and not auto_undo.spam:
                skip = 'move_skipped_auto_block'
            elif current_allow is not None:
                force_rule = current_allow
                skip = "move_skipped_rule"
            elif (msg is not None and not threat and not msg["user_verdict"]
                  and not msg["rule_hit"] and _row_get(r, "origin") != "campaign"
                  and _row_get(r, "threshold") is not None and msg["our_score"] is not None
                  and acc.threshold > float(r["threshold"])
                  and float(msg["our_score"] or 0) < acc.threshold):
                skip = "move_skipped_threshold"
            elif (_row_get(r, "origin") in ("zap", "ai") and "\\Seen" in flags and not threat
                  and _row_get(msg, "user_verdict") != "spam"):
                # B19: read during the short grace - never taken away for
                # spam alone (2.7: nor for the AI's opinion). 2.11.1: unless
                # the user said spam ("Lær som spam" keeps the queued move).
                skip = "zap_skipped_read"
            elif force_rule is not None:
                # Marked 'Altid igennem' during the grace period.
                skip = "move_skipped_rule"
            elif "\\Flagged" in flags:
                # The user flagged it during the grace period. ($NotJunk is
                # ignored here: Apple Mail sets it automatically.)
                skip = "move_skipped_user_flag"
            elif "\\Deleted" in flags:
                skip = "move_skipped_deleted"
            if threat:
                threats[uid] = str(threat)
        if skip:
            with db.tx():
                db.drop_pending_move(uv, uid)
                db.log_event(skip, msgid, detail=f"uid={uid}")
                if skip in ("move_skipped_user_flag", "zap_skipped_read", "move_skipped_threshold"):
                    db.update_message(msgid, our_action="none")
                elif skip == 'move_skipped_auto_block':
                    db.update_message(msgid, our_action=auto_undo.action or 'none', rule_hit=auto_undo.rule_hit)
                elif skip == "move_skipped_rule":
                    db.update_message(msgid, our_action="allowlisted", rule_hit=f"allow:{force_rule['id']}")
                    db.bump("allowlisted")
            continue
        to_move.append(uid)
        by_uid[uid] = r

    # Cap this batch to the hourly quota still available.
    remaining = acc.max_moves_per_hour - db.rate_count("move", 3600)
    to_move = to_move[: max(0, remaining)]
    if not to_move:
        return
    # E1 circuit breaker: never more than the safety limits allow. Moves
    # that were already waiting when an admin resumed the breaker are
    # approved by that decision: they run (within the hourly quota above)
    # without counting towards - or re-tripping - the breaker.
    resumed_at = _circuit_resumed_at(db.conn, db.account)
    approved_set = {u for u in to_move
                    if resumed_at is not None and int(by_uid[u]["flag_at"] or 0) <= resumed_at}
    fresh = [u for u in to_move if u not in approved_set]
    allowed, trip = circuit_trip_reason(db.conn, acc, len(fresh))
    if trip is not None:
        fresh = fresh[:allowed]
        if open_circuit(db.conn, db.account, trip):
            log.error("move circuit breaker opened: %s", trip)
            _alert_circuit(db, acc, trip)
        db.status(state="paused_moves", detail=_paused_detail(trip))
    to_move = sorted(approved_set | set(fresh))
    if not to_move:
        return
    moved: list[int] = []
    failed: list[int] = []
    final_failure = False
    copied_any = False
    error_text = ""
    on_stage = _journal_writer(db, inbox, uv, junk,
                               {u: by_uid[u]["message_id"] for u in to_move},
                               {u: _internaldate_ts(fetched.get(u) or {}) for u in to_move})
    try:
        imap_move(client, to_move, junk, capabilities=state.caps or client_capabilities(client),
                  on_stage=on_stage)
        moved = list(to_move)
    except MoveUnsupported as ex:
        failed, final_failure, error_text = list(to_move), True, str(ex)
    except MoveError as ex:
        moved = [u for u in to_move if u in ex.moved]
        failed = [u for u in to_move if u not in ex.moved]
        # After a successful COPY, retrying would duplicate mail in junk.
        final_failure, copied_any, error_text = ex.copied, ex.copied, str(ex)

    now = int(_now())
    with db.tx():
        for uid in moved:
            msgid = by_uid[uid]["message_id"]
            db.drop_pending_move(uv, uid)
            db.conn.execute("DELETE FROM move_journal WHERE account=? AND folder=? AND uidvalidity=? "
                            "AND uid=?", (db.account, inbox, uv, uid))
            zap = _row_get(by_uid[uid], "origin") == "zap"
            campaign = _row_get(by_uid[uid], "origin") == "campaign"  # 2.6 (A2)
            db.update_message(msgid, current_folder=junk, our_action="moved_to_junk",
                              moved_to_junk_at=now, last_seen=now, **({"zapped_at": now} if zap else {}))
            db.record_rate("move")
            if uid in approved_set:
                db.record_rate(CIRCUIT_APPROVED_ACTION)
            db.bump("moved")
            if zap:
                db.bump("zapped")
            db.log_event("moved_to_junk", msgid, detail=f"uid={uid} -> {junk}" + (" (genscanning)" if zap else "")
                         + (" (samme spam)" if campaign else ""))
            state.move_failures.pop((uv, uid), None)
            if uid in threats:
                _queue_threat_notice(db, msgid, threats[uid], now)  # Straks-advarsel
        for uid in failed:
            msgid = by_uid[uid]["message_id"]
            if not copied_any:
                # Nothing reached junk: no journal needed.
                db.conn.execute("DELETE FROM move_journal WHERE account=? AND folder=? "
                                "AND uidvalidity=? AND uid=?", (db.account, inbox, uv, uid))
            n = state.move_failures.get((uv, uid), 0) + 1
            if final_failure or n >= MOVE_RETRY_LIMIT:
                db.drop_pending_move(uv, uid)
                # copied: a copy reached junk, which makes a later inbox
                # reappearance a possible rescue (see _rescue_source). The
                # journal row stays: repair_interrupted_moves completes it.
                db.update_message(msgid, our_action="move_failed",
                                  moved_to_junk_at=now if copied_any else None)
                db.bump("move_failed")
                db.log_event("move_failed", msgid, detail=error_text[:300])
                state.move_failures.pop((uv, uid), None)
            else:
                state.move_failures[(uv, uid)] = n
                db.log_event("move_retry", msgid, detail=f"attempt={n}: {error_text}"[:300])
    if moved:
        log.info("moved %d message(s) %s -> %s", len(moved), inbox, junk)
    if failed:
        log.warning("move of %d message(s) to %s failed: %s", len(failed), junk, error_text)


def _row_get(row: Any, key: str) -> Any:
    """row[key] for an sqlite3.Row/dict, None when the column is missing."""
    if row is None:
        return None
    try:
        return row[key]
    except (IndexError, KeyError):
        return None


def _paused_detail(reason: str | None) -> str:
    text = "Flytning er sat på pause af sikkerhedsafbryderen"
    if reason:
        text += f": {reason}"
    return (text + ". Mails scannes stadig, og fundet spam venter. Genoptag under Konti.")[:400]


# ----- E5: repair of interrupted UIDPLUS/MOVE moves --------------------------


def _uids_with_idate(client: IMAPClient, msgid: str, idate: int | None) -> dict[int, set[str]]:
    """{uid: flags} of every copy of msgid in the selected folder with the
    given INTERNALDATE (None = any)."""
    uids = find_uids_by_message_id(client, msgid, collapse_copies=False)
    if not uids:
        return {}
    data = client.fetch(uids, [b"FLAGS", b"INTERNALDATE"])
    out: dict[int, set[str]] = {}
    for uid in uids:
        d = data.get(uid)
        if d is None:
            continue
        if idate is not None and _internaldate_ts(d) != idate:
            continue
        out[uid] = _flag_names(d.get(b"FLAGS"))
    return out


def _repair_one(client: IMAPClient, db: Db, log: logging.Logger, acc: Account, fmap: dict[str, str],
                state: AccountState, *, msgid: str, stage: str, idate: int | None, predeleted: bool,
                inbox_uv: int, journal_uv: int | None, journal_uid: int | None) -> str:
    """Bring one interrupted move to a consistent end. Returns an outcome:
    'completed' | 'moved' (already done) | 'retry' (nothing happened, the
    pending move stays) | 'kept' (user intent: leave it) | 'skipped'.
    Never expunges anything but the exact original UID, and a \\Deleted
    original only when the journal proves the flag is ours."""
    inbox, junk = fmap["inbox"], fmap["junk"]
    if not message_id_searchable(msgid):
        return "skipped"
    client.select_folder(junk, readonly=True)
    copies = _uids_with_idate(client, msgid, idate)
    # Only a copy nobody marked deleted may justify removing the original:
    # a \Deleted junk copy can be the source of the user's own COPY-based
    # rescue back into the inbox (Gigahost clients have no MOVE).
    live_copies = [u for u, f in copies.items() if "\\Deleted" not in f]
    select_with_uidvalidity_check(client, db, inbox, log)
    originals = _uids_with_idate(client, msgid, idate)
    if journal_uid is not None and journal_uv == inbox_uv:
        # UIDs are never reused within a UIDVALIDITY: the journalled UID is
        # THE original. If it is gone, any other inbox copy is a different
        # message (a rescue, a redelivery) and is never touched.
        originals = {journal_uid: originals[journal_uid]} if journal_uid in originals else {}
    elif idate is None and originals:
        # Without INTERNALDATE and without the exact UID nothing proves an
        # inbox copy is the message we copied: never touch it.
        return "skipped"
    elif len(originals) > 1:
        # Several identical inbox copies (e.g. the user copied one back):
        # nothing tells which one is ours.
        return "skipped"
    if stage == "move" or (stage == "copy" and not copies):
        return "retry" if originals else ("moved" if copies else "skipped")
    if not copies:
        # The copy is not (or no longer) in junk: never remove the original.
        return "skipped"
    if not originals:
        return "moved"
    if not live_copies:
        return "skipped"
    msg = db.get_message(msgid)
    done: list[int] = []
    foreign = 0
    for uid, flags in sorted(originals.items()):
        if "\\Deleted" in flags:
            if stage == "flag" and not predeleted:
                client.uid_expunge([uid])   # finish OUR interrupted expunge
                done.append(uid)
            else:
                foreign += 1  # flagged by someone else: never touched
            continue
        force_rule = (force_allow_rule(db.conn, acc.name, msg["sender"]) if msg is not None else None)
        if (_sticky_ham(msg) or (force_rule is not None
                                 and force_verification(force_rule, msg["sender_auth"]) is not None)
                or "\\Flagged" in flags):
            return "kept"
        try:
            client.add_flags([uid], [DELETED_FLAG], silent=True)
            client.uid_expunge([uid])
        except _CONN_ERRORS:
            raise
        except IMAPClientError:
            try:
                client.remove_flags([uid], [DELETED_FLAG], silent=True)
            except IMAPClientError:
                pass
            raise
        done.append(uid)
    if done:
        return "completed"
    return "skipped" if foreign else "kept"


def repair_interrupted_moves(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
                             fmap: dict[str, str], state: AccountState | None = None) -> int:
    """E5: finish moves interrupted between COPY, STORE \\Deleted and UID
    EXPUNGE (Gigahost has no MOVE), using the move journal; legacy rows
    (move_failed with a copy in junk, no journal) are completed only when
    the inbox original is undeleted. Returns the number of rows resolved."""
    if acc.mode != "move":
        return 0
    state = state if state is not None else AccountState()
    resolved = _repair_moves_from(client, db, log, acc, fmap, state, fmap["inbox"])
    # 2.6 (A2/A4): moves out of the newsletter folder are journalled too.
    try:
        nl = _newsletters().folder_of(acc)
    except Exception:  # noqa: BLE001
        nl = ""
    if nl and nl not in (fmap["inbox"], fmap["junk"]) and any(
            r["folder"] == nl and r["dest"] == fmap["junk"] for r in _journal_rows(db)):
        try:
            resolved += _repair_moves_from(client, db, log, acc, fmap, state, nl)
        finally:
            select_with_uidvalidity_check(client, db, fmap["inbox"], log)
    # 2.6 (C2): an interrupted move to the DMARC folder (no IMAP at all
    # when its journal is empty).
    if any(r["dest"] != fmap["junk"] for r in _journal_rows(db, fmap["inbox"])) and \
            _dmarc_settings(db, acc) is not None:
        _dmarc_repair(client, db, log, acc, fmap, state)
    return resolved


def _repair_moves_from(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
                       fmap: dict[str, str], state: AccountState, source: str) -> int:
    """repair_interrupted_moves for one source folder (`inbox` below is
    `source`; legacy rows only exist for the inbox)."""
    nl_source = source != fmap["inbox"]
    fmap = dict(fmap, inbox=source)
    inbox, junk = fmap["inbox"], fmap["junk"]
    jrows = [r for r in _journal_rows(db) if r["folder"] == inbox and r["dest"] == junk]
    now = int(_now())
    journal_ids = {r["message_id"] for r in jrows}
    legacy = [] if nl_source else [r for r in db.conn.execute(
        "SELECT message_id, received_at FROM messages WHERE account=? AND our_action='move_failed' "
        "AND moved_to_junk_at IS NOT NULL AND moved_to_junk_at>=? AND received_at IS NOT NULL",
        (db.account, now - MOVE_REPAIR_LEGACY_WINDOW_S)).fetchall()
        if r["message_id"] not in journal_ids]
    if not jrows and not legacy:
        return 0
    if circuit_open(db.conn, db.account):
        return 0  # completing a move is a move: wait for the admin
    inbox_uv = select_with_uidvalidity_check(client, db, inbox, log)
    resolved = 0
    work = ([("journal", r) for r in jrows] + [("legacy", r) for r in legacy])
    for kind, r in work:
        if SHUTDOWN.is_set():
            break
        msgid = r["message_id"]
        if kind == "journal":
            args = dict(stage=r["stage"], idate=r["internaldate"], predeleted=bool(r["predeleted"]),
                        journal_uv=int(r["uidvalidity"]), journal_uid=int(r["uid"]))
        else:
            args = dict(stage="copied", idate=r["received_at"], predeleted=False,
                        journal_uv=None, journal_uid=None)
        try:
            outcome = _repair_one(client, db, log, acc, fmap, state, msgid=msgid,
                                  inbox_uv=inbox_uv, **args)
        except _CONN_ERRORS:
            raise
        except IMAPClientError as ex:
            outcome = "error"
            log.warning("move repair of %s failed: %s", msgid, _short_err(ex))
            try:
                select_with_uidvalidity_check(client, db, inbox, log)
            except IMAPClientError:
                pass
        with db.tx():
            if outcome in ("completed", "moved"):
                db.update_message(msgid, current_folder=junk, our_action="moved_to_junk",
                                  moved_to_junk_at=int(_now()), last_seen=int(_now()))
                db.drop_pending_moves_for(msgid)
                if outcome == "completed":
                    db.record_rate("move")
                    db.bump("moved")
                db.log_event("move_repaired", msgid, detail=f"{kind} stage={args['stage']} {outcome}")
            elif outcome == "kept":
                db.update_message(msgid, our_action="newsletter_moved" if nl_source else "none")
                db.drop_pending_moves_for(msgid)
                db.log_event("move_repair_kept", msgid, detail=f"user intent: left in {inbox}")
            elif outcome == "retry":
                db.log_event("move_repair_retry", msgid, detail=f"stage={args['stage']}")
            if kind == "journal":
                if outcome == "error" and int(r["attempts"]) + 1 < MOVE_REPAIR_MAX_ATTEMPTS:
                    db.conn.execute("UPDATE move_journal SET attempts=attempts+1, updated_at=? "
                                    "WHERE account=? AND folder=? AND uidvalidity=? AND uid=?",
                                    (int(_now()), db.account, r["folder"], r["uidvalidity"], r["uid"]))
                else:
                    if outcome in ("error", "skipped"):
                        db.log_event("move_repair_giveup", msgid, detail=f"stage={args['stage']} {outcome}")
                    db.conn.execute("DELETE FROM move_journal WHERE account=? AND folder=? "
                                    "AND uidvalidity=? AND uid=?",
                                    (db.account, r["folder"], r["uidvalidity"], r["uid"]))
        if outcome in ("completed", "moved", "kept"):
            resolved += 1
    if resolved:
        log.info("repaired %d interrupted move(s)", resolved)
    return resolved


def account_started(db: Db) -> int:
    """2.12 (#24): when the filter first looked at this mailbox (unix). Kept
    in engine_state; for an existing account derived once from the earliest
    message seen or the first inbox bookmark, else now."""
    key = f"account_started:{db.account}"
    v = engine_state_get(db.conn, key)
    try:
        if v is not None:
            return int(v)
    except ValueError:
        pass
    cands = []
    for sql in ("SELECT MIN(first_seen) FROM messages WHERE account=?",
                "SELECT MIN(ts) FROM events WHERE account=? AND event='scan_bookmark_init'"):
        try:
            x = db.conn.execute(sql, (db.account,)).fetchone()[0]
        except sqlite3.OperationalError:
            x = None
        if isinstance(x, (int, float)) and x > 0:
            cands.append(int(x))
    started = min(cands) if cands else int(_now())
    engine_state_set(db.conn, key, str(started))
    return started


def _preexisting(db: Db, data: dict) -> bool:
    """2.12 (#24): mail that arrived before the filter first looked at the
    mailbox. Moving it into a spam folder is tidying up old mail: never
    counted as a move to Junk, never learned."""
    ts = _internaldate_ts(data)
    return ts is not None and ts < account_started(db)


def fix_preexisting_junk_counts(db: Db, log: logging.Logger) -> int:
    """2.12 (#24), once per mailbox: user_junked moves of mail older than the
    mailbox's first scan, made within its first two days (a new mailbox
    tidied up), stop counting: the day's user_junked counter goes down, the
    event becomes junk_preexisting, a pending (not yet done) learn is
    dropped and the mail is recorded as found in the spam folder. Nothing
    on the mail server changes."""
    key = f"fix_preexisting_junk:{db.account}"
    if engine_state_get(db.conn, key):
        return 0
    started = account_started(db)
    rows = db.conn.execute(
        "SELECT message_id, verdict_at FROM messages WHERE account=? AND our_action='user_junked' "
        "AND COALESCE(verdict_by,'')='user:move' AND received_at IS NOT NULL AND received_at<? "
        "AND verdict_at>=? AND verdict_at<?",
        (db.account, started, started, started + 2 * 86400)).fetchall()
    days: dict[str, int] = {}
    with db.tx():
        for r in rows:
            mid = r["message_id"]
            db.conn.execute(
                "UPDATE messages SET our_action='provider_junk', user_verdict=NULL, verdict_at=NULL, verdict_by=NULL, "
                "pending_learn=CASE WHEN learned_as IS NULL THEN NULL ELSE pending_learn END, "
                "pending_learn_at=CASE WHEN learned_as IS NULL THEN NULL ELSE pending_learn_at END "
                "WHERE account=? AND message_id=?", (db.account, mid))
            db.conn.execute("UPDATE events SET event='junk_preexisting' WHERE account=? AND message_id=? "
                            "AND event='user_junked'", (db.account, mid))
            d = stats_day(int(r["verdict_at"]))
            days[d] = days.get(d, 0) + 1
        for d, n in days.items():
            db.conn.execute("UPDATE stats_daily SET n=MAX(0, n-?) WHERE account=? AND day=? AND metric='user_junked'",
                            (n, db.account, d))
        if rows:
            db.log_event("fix_preexisting_junk", detail=f"{len(rows)} uncounted: "
                         + ", ".join(f"{d}={n}" for d, n in sorted(days.items()))[:200])
    engine_state_set(db.conn, key, str(int(_now())))
    if rows:
        log.info("2.12: %d moves of old mail into the spam folder no longer count as moves to Junk", len(rows))
    return len(rows)


_JUNK_META_ITEMS = [b"FLAGS", b"RFC822.SIZE", b"INTERNALDATE",
                    b"BODY.PEEK[HEADER.FIELDS (MESSAGE-ID FROM SUBJECT RETURN-PATH X-TH-SPAMFILTER)]"]


def _junk_message_seen(db: Db, log: logging.Logger, acc: Account, fmap: dict[str, str],
                       uid: int, data: dict, folder: str | None = None, *,
                       first_pass: bool = False) -> None:
    hdr = _header_bytes(data)
    msgid, subject, sender = parse_envelope(hdr)
    body = _body_bytes(data)
    if not body:
        # Neither a missing FETCH body nor an oversized mail proves that
        # this is the message whose ID appears in the headers. Do not
        # overwrite a previous release or schedule header-only learning.
        db.log_event("junk_identity_unverified", detail=f"uid={uid}")
        db.bump("junk_identity_unverified")
        return
    with db.tx():
        wire = parse_envelope(body)[0]
        msgid = mailidentity.bind(db.conn, db.account, wire, body,
                                legacy_exists=wire is not None and db.get_message(wire) is not None
                                and mailidentity.binding(db.conn, db.account, wire) is None)
    if not msgid:
        return
    if _is_our_receipt(db, msgid, hdr):
        # E12: our own daily receipt dragged into a spam folder is neither a
        # user verdict nor provider junk - never learned.
        return
    if _is_own_notification(db, msgid, hdr) and body and db.conn.execute(
            "SELECT 1 FROM mail_identity WHERE account='*notification*' AND wire_id=? AND fingerprint=?",
            (parse_envelope(body)[0], mailidentity.fingerprint(body))).fetchone():
        # 2.3 (B29): the same for our own notification mails (alerts, codes,
        # reports): never a verdict, never learned, never a contact signal.
        return
    junk, inbox = folder or fmap["junk"], fmap["inbox"]
    size = data.get(b"RFC822.SIZE")
    size = int(size) if size is not None else None
    envelope_from = _return_path(hdr)
    prior = db.get_message(msgid)
    now = int(_now())
    filter_folder = bool(fmap.get("filter_junk")) and junk == fmap.get("filter_junk")
    # Only mail the filter never scanned itself: a scanned inbox mail is the
    # filter's own decision, whatever its INTERNALDATE says.
    old_mail = (prior is None or prior["scanned_at"] is None) and _preexisting(db, data)
    with db.tx():
        if prior is None and filter_folder and not first_pass and not old_mail:
            # E3: unknown mail in the filter's OWN folder - the provider never
            # files anything there, so the user dragged it in: their verdict.
            db.upsert_message(msgid, junk, sender, subject, _internaldate_ts(data))
            fields0: dict[str, Any] = dict(our_action="user_junked", origin="junk_poll", size=size,
                                           envelope_from=envelope_from, user_verdict="spam",
                                           verdict_at=now, verdict_by="user:move")
            if acc.learn_from_moves:
                fields0.update(pending_learn="spam", pending_learn_at=now)
            db.update_message(msgid, **fields0)
            _revoke_auto_allow_logged(db, log, acc, msgid, sender)
            _contacts_user_spam(db, log, acc, msgid, sender, None, None)
            _junk_rules_after_user_junk(db, log, acc, msgid, sender)
            db.bump("user_junked")
            db.log_event("user_junked", msgid, detail=f"uid={uid} into {junk}")
            _campaign_sweep(db, log, acc, msgid, "user_junked")
            log.info("user put %s into %s", msgid, junk)
            return
        if prior is None:
            # Not put there by us and never seen in the inbox.
            db.upsert_message(msgid, junk, sender, subject, _internaldate_ts(data))
            db.update_message(msgid, our_action="provider_junk", origin="junk_poll",
                              size=size, envelope_from=envelope_from)
            db.log_event("junk_preexisting" if old_mail and filter_folder and not first_pass else "provider_junk",
                         msgid, detail=f"uid={uid}")
            return
        user_put = (prior["our_action"] not in OUR_JUNK_ACTIONS
                    and (prior["current_folder"] == inbox
                         or (filter_folder and not first_pass and prior["current_folder"] != junk
                             and prior["user_verdict"] != "spam")))
        if user_put and old_mail:
            # 2.12 (#24): old mail (from before the filter's first scan) the
            # user tidies into the spam folder: the verdict is kept, but it
            # is no move to Junk - not counted, not learned.
            db.update_message(msgid, current_folder=junk, last_seen=now, user_verdict="spam",
                              verdict_at=now, verdict_by="user:move")
            db.drop_pending_moves_for(msgid)
            db.log_event("junk_preexisting", msgid, detail=f"uid={uid} into {junk}")
            return
        if user_put:
            # The user moved it Inbox -> spam folder: sticky spam verdict.
            fields: dict[str, Any] = dict(current_folder=junk, last_seen=now, user_verdict="spam",
                                          verdict_at=now, verdict_by="user:move",
                                          our_action="user_junked")
            if (acc.learn_from_moves and prior["learned_as"] != "spam"
                    and prior["pending_learn"] != "spam"):
                fields.update(pending_learn="spam", pending_learn_at=now)
            db.update_message(msgid, **fields)
            db.drop_pending_moves_for(msgid)
            _revoke_auto_allow_logged(db, log, acc, msgid, prior["sender"] or sender)
            _contacts_user_spam(db, log, acc, msgid, prior["sender"] or sender, prior["symbols"],
                                prior["our_action"])
            _junk_rules_after_user_junk(db, log, acc, msgid, prior["sender"] or sender)
            db.bump("user_junked")
            db.log_event("user_junked", msgid, detail=f"uid={uid}")
            if filter_folder:
                # 2.6 (A2): only the filter's own folder proves a user action
                # - the provider may move mail into its junk folder itself
                # after delivery.
                _campaign_sweep(db, log, acc, msgid, "user_junked", raw=body)
            log.info("user moved %s to %s", msgid, junk)
            return
        if (prior["current_folder"] == inbox and junk == fmap["junk"]
                and prior["our_action"] in ("pending_move", "move_failed")
                and not _journal_has(db, msgid)):
            # Our move landed but its bookkeeping was lost (connection drop).
            db.update_message(msgid, current_folder=junk, our_action="moved_to_junk",
                              moved_to_junk_at=now, last_seen=now)
            db.drop_pending_moves_for(msgid)
            db.log_event("moved_to_junk", msgid, detail="confirmed by junk poll")
            return
        db.update_message(msgid, current_folder=junk, last_seen=now)
        if prior["size"] is None and size is not None:
            db.update_message(msgid, size=size)
        if prior["envelope_from"] is None and envelope_from:
            db.update_message(msgid, envelope_from=envelope_from)


def reconcile_junk(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
                   fmap: dict[str, str], folder: str | None = None) -> bool:
    """Mark rows no longer present in the (selected) spam folder as 'gone'
    and refresh last_seen of those still there. Header-only. Applies
    nothing unless the full listing was read."""
    junk = folder or fmap["junk"]
    present: set[str] = set()
    uids = sorted(int(u) for u in client.search(["ALL"]))
    for chunk in _chunks(uids, RECONCILE_FETCH_CHUNK):
        if SHUTDOWN.is_set():
            return False
        fetched = client.fetch(list(chunk), [_HDR_MSGID])
        for _uid, data in fetched.items():
            mid = parse_envelope(_header_bytes(data))[0]
            if mid:
                present.add(mid)
    rows = db.conn.execute(
        "SELECT message_id, current_folder FROM messages WHERE account=? AND current_folder IN (?, 'gone')",
        (db.account, junk),
    ).fetchall()
    for r in rows:
        if r["message_id"].startswith(mailidentity.PREFIX):
            if find_uids_by_message_id(client, r["message_id"], undeleted=True):
                present.add(r["message_id"])
    gone = [r["message_id"] for r in rows if r["current_folder"] == junk and r["message_id"] not in present]
    back = [r["message_id"] for r in rows if r["current_folder"] == "gone" and r["message_id"] in present]
    still = [r["message_id"] for r in rows if r["current_folder"] == junk and r["message_id"] in present]
    now = int(_now())
    with db.tx():
        for chunk in _chunks(gone, 500):
            db.conn.execute(
                f"UPDATE messages SET current_folder='gone' WHERE account=? "
                f"AND message_id IN ({','.join('?' * len(chunk))})", (db.account, *chunk))
        for chunk in _chunks(back + still, 500):
            db.conn.execute(
                f"UPDATE messages SET current_folder=?, last_seen=? WHERE account=? "
                f"AND message_id IN ({','.join('?' * len(chunk))})", (junk, now, db.account, *chunk))
        db.log_event("junk_reconcile",
                     detail=f"{junk}: present={len(present)} gone={len(gone)} back={len(back)}")
    if gone or back:
        log.info("junk reconcile: %d gone, %d back", len(gone), len(back))
    return True


def _poll_one_junk(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
                   fmap: dict[str, str], folder: str, reconcile: bool) -> bool | None:
    """Header-only pass over new UIDs of one spam folder (EXAMINE).
    Returns None when the folder is not selectable, else whether a due
    reconciliation completed."""
    try:
        uv = select_with_uidvalidity_check(client, db, folder, log, readonly=True)
    except _CONN_ERRORS:
        raise
    except IMAPClientError as ex:
        log.warning("spam folder %s not selectable: %s", folder, type(ex).__name__)
        return None
    bm_row = db.get_junk_bookmark(folder, uv)
    first_pass = bm_row is None
    bm = bm_row or 0
    # RFC 3501: "n:*" includes the highest UID even below n - filter.
    new = sorted(u for u in {int(x) for x in client.search(["UID", f"{bm + 1}:*"])} if u > bm)
    # E3: content present when the folder was first seen is never a user
    # drag (even when the first pass needs several polls).
    pre_key = f"junk_preexisting:{db.account}:{folder}:{uv}"
    if first_pass:
        engine_state_set(db.conn, pre_key, str(max(new) if new else 0))
    try:
        preexisting_max = int(engine_state_get(db.conn, pre_key) or 0)
    except ValueError:
        preexisting_max = 0
    new = new[:JUNK_POLL_MAX_PER_RUN]
    last_done = bm
    for chunk in _chunks(new, SCAN_FETCH_CHUNK):
        if SHUTDOWN.is_set():
            break
        fetched = client.fetch(list(chunk), _JUNK_META_ITEMS)
        for uid in chunk:
            if SHUTDOWN.is_set():
                break
            data = fetched.get(uid)
            if data is not None:
                try:
                    if int(data.get(b"RFC822.SIZE") or 0) <= MAX_FETCH_BYTES:
                        body = _body_bytes(client.fetch([uid], [b"BODY.PEEK[]"]).get(uid))
                        if body:
                            data[b"BODY[]"] = body
                    _junk_message_seen(db, log, acc, fmap, uid, data, folder,
                                       first_pass=first_pass or uid <= preexisting_max)
                except _CONN_ERRORS:
                    raise
                except Exception as ex:  # noqa: BLE001 - one bad header must not stall the poll
                    log.warning("junk poll uid %s failed: %s", uid, _short_err(ex))
                    db.log_event("junk_poll_error", detail=f"{folder} uid={uid}: {_short_err(ex)}")
            last_done = uid
    if last_done > bm or first_pass:
        # Also on an empty first pass: the bookmark row marks "seen before",
        # which E3 needs to tell user drags from pre-existing content.
        with db.tx():
            db.set_junk_bookmark(folder, uv, last_done)
    if not SHUTDOWN.is_set():
        try:
            _score_provider_junk(client, db, log, acc, folder)
        except _CONN_ERRORS:
            raise
        except Exception as ex:  # noqa: BLE001 - scoring is optional, the poll goes on
            log.warning("provider junk scoring in %s failed: %s", folder, _short_err(ex))
    if reconcile and not SHUTDOWN.is_set():
        return reconcile_junk(client, db, log, acc, fmap, folder)
    return False


def _score_provider_junk(client: IMAPClient, db: Db, log: logging.Logger, acc: Account, folder: str) -> int:
    """2.12 (#13): score recent provider junk in `folder` (selected with
    EXAMINE by the caller) exactly like a live scan - read-only: no flag,
    no move, no user verdict and no learning (Bayes learns only from
    explicit user moves; the score contains the provider's own SPAM_FLAG,
    so learning from it would feed the provider's false positives into the
    shared pool). Stores the score and symbols for Tjek disse. Not found or
    too large: marked as tried (scanned_at) and never fetched again. Returns
    the number scored; stops at the first rspamd failure (next poll)."""
    now = int(_now())
    rows = db.conn.execute(
        "SELECT * FROM messages WHERE account=? AND our_action='provider_junk' AND scanned_at IS NULL "
        "AND our_score IS NULL AND user_verdict IS NULL AND current_folder=? "
        "AND COALESCE(received_at, first_seen)>=? ORDER BY COALESCE(received_at, first_seen) DESC LIMIT ?",
        (db.account, folder, now - PROVIDER_JUNK_SCORE_DAYS * 86400, PROVIDER_JUNK_SCORE_PER_RUN)).fetchall()
    done = 0
    for r in rows:
        if SHUTDOWN.is_set():
            break
        msgid = r["message_id"]

        def tried(why: str, _m: str = msgid) -> None:
            with db.tx():
                db.update_message(_m, scanned_at=now)
                db.log_event("provider_junk_unscored", _m, detail=why)

        if not message_id_searchable(msgid):
            tried("unsearchable")
            continue
        uids = find_uids_by_message_id(client, msgid)
        if not uids:
            tried("not found")
            continue
        uid = uids[0]
        size = client.fetch([uid], [b"RFC822.SIZE"]).get(uid, {}).get(b"RFC822.SIZE")
        if size is not None and int(size) > MAX_FETCH_BYTES:
            tried(f"size={size}")
            continue
        raw = _body_bytes(client.fetch([uid], [b"BODY.PEEK[]"]).get(uid))
        if not raw or len(raw) > MAX_FETCH_BYTES:
            tried("no body" if not raw else f"size={len(raw)}")
            continue
        try:
            sc = _score_message(db, acc, raw, msgid=msgid, prior=r, flags=set(), received_at=r["received_at"])
        except RspamdError as ex:
            log.info("provider junk scoring paused: %s", _short_err(ex))
            break
        known = (bool(getattr(sc.trust, "symbols", None)) or "TH_KNOWN_CONTACT" in sc.names
                 or "TH_REPLY" in sc.names or "TH_ESTABLISHED" in sc.names)
        fields: dict[str, Any] = dict(
            our_score=sc.final, rspamd_score=sc.res.score, rspamd_action=sc.res.action,
            symbols=json.dumps(sc.symbols, ensure_ascii=False, separators=(",", ":")),
            decision_names=json.dumps(sorted(sc.names | {x["n"] for x in sc.decision.symbols})),
            sender_auth=json.dumps(sc.auth, separators=(",", ":")),
            scanned_at=now, score_version=SCORE_VERSION if sc.ctx_ok else 1,
            threat=sc.threat, threat_detail=sc.threat_detail)
        with db.tx():
            db.update_message(msgid, **fields)
            db.log_event("provider_junk_scored", msgid,
                         detail=f"score={sc.final:.1f} thr={sc.thr:.1f}" + (" known" if known else ""))
        done += 1
    return done


def poll_junk(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
              fmap: dict[str, str], state: AccountState | None = None) -> None:
    """Bounded PEEK at new spam-folder mail (flag/move only): detects
    the user moving mail into it and records provider junk; reconciles
    every 6 h; then promotes due pending learns. Also watches the
    provider's own spam folder when the filter uses a separate one."""
    if acc.mode == "shadow":
        return
    state = state if state is not None else AccountState()
    due = (state.last_junk_reconcile == 0.0
           or time.monotonic() - state.last_junk_reconcile >= JUNK_RECONCILE_INTERVAL_S)
    reconciled = True
    for folder in _spam_folders(fmap):
        if SHUTDOWN.is_set():
            return
        res = _poll_one_junk(client, db, log, acc, fmap, folder, due)
        if folder == fmap["junk"]:
            state.junk_exists = res is not None
        if res is not True:
            reconciled = False
    if due and reconciled:
        state.last_junk_reconcile = time.monotonic()
    process_pending_learns(client, db, log, acc, fmap)


def _mark_unlearnable(db: Db, msgid: str, event: str, detail: str) -> None:
    with db.tx():
        db.update_message(msgid, learned_as="unlearnable", learned_at=int(_now()),
                          pending_learn=None, pending_learn_at=None)
        db.log_event(event, msgid, detail=detail)


def _learn_pending(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
                   msgid: str, kind: str, folder: str) -> str:
    if not message_id_searchable(msgid):
        _mark_unlearnable(db, msgid, "learn_unsearchable", kind)
        return "declined"
    uids = find_uids_by_message_id(client, msgid)
    if not uids:
        with db.tx():
            db.update_message(msgid, pending_learn=None, pending_learn_at=None)
            db.log_event("pending_lost", msgid, detail=f"not found in {folder}")
        return "lost"
    uid = uids[0]
    size = client.fetch([uid], [b"RFC822.SIZE"]).get(uid, {}).get(b"RFC822.SIZE")
    if size is not None and int(size) > MAX_FETCH_BYTES:
        _mark_unlearnable(db, msgid, "learn_oversize", f"{kind} size={size}")
        return "declined"
    raw = _body_bytes(client.fetch([uid], [b"BODY.PEEK[]"]).get(uid))
    if not raw:
        return "error"
    if len(raw) > MAX_FETCH_BYTES:
        _mark_unlearnable(db, msgid, "learn_oversize", f"{kind} size={len(raw)}")
        return "declined"
    if kind == "spam" and legit_newsletter(raw, db.get_message(msgid), acc.threshold, db.conn):
        # 2.12 (#9): neither Bayes nor the fuzzy storage learns it.
        with db.tx():
            db.update_message(msgid, pending_learn=None, pending_learn_at=None)
            db.log_event("learn_skip_newsletter", msgid, detail="user move")
        return "declined"
    res = learn_message(db, acc, raw, kind, msgid, actor="engine", reason="grace_elapsed")
    try:
        if kind == "spam" and res in ("learned", "already"):
            # 2.6 (A2): a user's spam verdict also teaches the local fuzzy
            # storage, so later copies of the campaign are recognised
            # (never a declined learn: the ham guard or a size limit said no).
            _campaigns().fuzzy_for_verdict(sys.modules[__name__], db.conn, db.account, msgid, raw,
                                           now=int(_now()))
        elif kind == "ham":
            # The user rescued it: undo our fuzzy entry (if any).
            _campaigns().fuzzy_undo(sys.modules[__name__], db.conn, db.account, msgid, raw, now=int(_now()))
    except Exception as ex:  # noqa: BLE001 - optional
        log.warning("fuzzy update of %s failed: %s", msgid, type(ex).__name__)
    if res == "error":
        # Cap retries of a transient error so one message cannot loop
        # learn_failed events forever.
        fails = db.conn.execute(
            "SELECT COUNT(*) FROM events WHERE account=? AND message_id=? AND event='learn_failed'",
            (db.account, msgid),
        ).fetchone()[0]
        if fails >= 3:
            _mark_unlearnable(db, msgid, "learn_giveup", f"{kind} after {fails} failures")
            log.warning("pending learn: giving up on %s after %d failures", msgid, fails)
    return res


def process_pending_learns(
    client: IMAPClient, db: Db, log: logging.Logger, acc: Account, fmap: dict[str, str]
) -> None:
    """Promote pending spam/ham learns whose grace window has passed. The
    body is located by exact Message-ID (A3) and learned via learn_message
    (A2). Shadow mode never learns."""
    if acc.mode == "shadow" or not acc.learn_from_moves:
        return
    cutoff = int(_now()) - acc.learn_grace_seconds
    candidates = list(db.conn.execute(
        """
        SELECT message_id, pending_learn, current_folder FROM messages
        WHERE account=? AND pending_learn IS NOT NULL AND pending_learn_at<=?
        ORDER BY pending_learn_at
        """,
        (db.account, cutoff),
    ).fetchall())
    if not candidates:
        return
    folder_groups: dict[str, list[sqlite3.Row]] = {}
    for row in candidates:
        folder_groups.setdefault(row["current_folder"], []).append(row)

    for folder, rows in folder_groups.items():
        if SHUTDOWN.is_set():
            return
        valid: list[sqlite3.Row] = []
        for r in rows:
            # Spam must still be in junk, ham still in the inbox.
            expected = _spam_folders(fmap) if r["pending_learn"] == "spam" else [fmap["inbox"]]
            if folder not in expected and not _autolearn_revert_pending(db, r["message_id"],
                                                                        r["pending_learn"]):
                with db.tx():
                    db.update_message(r["message_id"], pending_learn=None, pending_learn_at=None)
                    db.log_event("pending_canceled", r["message_id"], detail="moved before grace")
                continue
            valid.append(r)
        if not valid:
            continue
        try:
            client.select_folder(folder, readonly=True)
        except _CONN_ERRORS:
            raise
        except IMAPClientError as ex:
            log.warning("select %s for pending learn failed: %s", folder, type(ex).__name__)
            continue
        for r in valid:
            if SHUTDOWN.is_set():
                return
            try:
                res = _learn_pending(client, db, log, acc, r["message_id"], r["pending_learn"], folder)
            except _CONN_ERRORS:
                raise
            except Exception as ex:  # noqa: BLE001 - isolate one bad message
                log.warning("pending learn of %s failed: %s", r["message_id"], _short_err(ex))
                db.log_event("learn_error", r["message_id"], detail=_short_err(ex))
                continue
            if res == "rate_limited":
                break


def _drain_train_folder(
    client: IMAPClient,
    db: Db,
    log: logging.Logger,
    acc: Account,
    fmap: dict[str, str],
    *,
    kind: str,
    src_key: str,
    dst_key: str,
    state: AccountState | None = None,
) -> None:
    """Pull mail out of a Train-* folder, learn it as `kind`, move it to the
    matching Trained-* folder. Only with training_folders: true."""
    assert kind in {"spam", "ham"}
    if not acc.training_folders or acc.mode == "shadow" or not acc.learn_from_moves:
        return
    folder = fmap[src_key]
    try:
        uv = select_with_uidvalidity_check(client, db, folder, log)
    except _CONN_ERRORS:
        raise
    except IMAPClientError as ex:
        log.warning("select %s failed: %s", folder, type(ex).__name__)
        return
    uids = sorted(int(u) for u in client.search(["ALL"]))[: acc.max_train_per_run]
    if not uids:
        return
    sizes = {u: d.get(b"RFC822.SIZE") for u, d in client.fetch(uids, [b"RFC822.SIZE"]).items()}
    done: list[int] = []
    moved_msgids: list[str] = []
    reason = f"train_{kind}_folder"
    small = [u for u in uids if sizes.get(u) is not None and int(sizes[u]) <= MAX_FETCH_BYTES]
    done.extend(u for u in uids if sizes.get(u) is not None and int(sizes[u]) > MAX_FETCH_BYTES)
    for uid, data in fetch_chunked(client, small, [b"BODY.PEEK[]", b"INTERNALDATE"], SCAN_BODY_CHUNK):
        if SHUTDOWN.is_set():
            return
        raw = _body_bytes(data)
        if not raw:
            continue
        msgid, subject, sender = parse_envelope(raw)
        synthetic = not msgid
        if synthetic:
            # No Message-ID: no DB row (it could never be addressed again);
            # a synthetic id keeps the events readable.
            msgid = f"<no-msgid-uv-{uv}-uid-{uid}>"
        else:
            with db.tx():
                db.upsert_message(msgid, folder, sender, subject, _internaldate_ts(data))
        res = learn_message(db, acc, raw, kind, msgid, actor="engine", reason=reason)
        if res in ("learned", "already", "declined", "held_out"):
            done.append(uid)
            if not synthetic:
                moved_msgids.append(msgid)
            continue
        if res == "rate_limited":
            break
        fails = db.conn.execute(
            "SELECT COUNT(*) FROM events WHERE account=? AND message_id=? AND event='learn_failed'",
            (db.account, msgid),
        ).fetchone()[0]
        if fails >= 3:
            log.warning("drain_train_%s: giving up on %s after %d learn failures", kind, msgid, fails)
            with db.tx():
                if not synthetic:
                    db.update_message(msgid, learned_as="unlearnable", learned_at=int(_now()))
                db.log_event("learn_giveup", msgid, detail=f"{kind} after {fails} failures")
            done.append(uid)
            if not synthetic:
                moved_msgids.append(msgid)
    if not done:
        return
    caps = state.caps if state is not None and state.caps else client_capabilities(client)
    try:
        imap_move(client, done, fmap[dst_key], capabilities=caps)
    except MoveError as ex:
        log.warning("move %s -> %s failed: %s", folder, fmap[dst_key], ex)
        return
    with db.tx():
        db.log_event("trained_moved", detail=f"{len(done)} -> {fmap[dst_key]}")
        for chunk in _chunks(moved_msgids, 500):
            db.conn.execute(
                f"UPDATE messages SET current_folder=? WHERE account=? "
                f"AND message_id IN ({','.join('?' * len(chunk))})",
                (fmap[dst_key], db.account, *chunk),
            )
    log.info("drain_train_%s: learned+moved %d", kind, len(done))


def drain_train_spam(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
                     fmap: dict[str, str], state: AccountState | None = None) -> None:
    _drain_train_folder(client, db, log, acc, fmap, kind="spam", src_key="spam_train",
                        dst_key="trained_spam", state=state)


def drain_train_ham(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
                    fmap: dict[str, str], state: AccountState | None = None) -> None:
    _drain_train_folder(client, db, log, acc, fmap, kind="ham", src_key="ham_train",
                        dst_key="trained_ham", state=state)


# ----- retention ----------------------------------------------------------


def retention_sweep(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
                    fmap: dict[str, str], state: AccountState | None = None) -> None:
    """Move old junk (and Trained-Spam) to trash. Each folder's own `> 0`
    decides; Trained-Ham is never swept. Callers gate this on
    AUTOMATIC_RETENTION_ENABLED (off in production)."""
    caps = state.caps if state is not None and state.caps else client_capabilities(client)
    if acc.junk_retention_days > 0:
        _sweep_folder_to_trash(client, db, log, acc, fmap, src=fmap["junk"],
                               days=acc.junk_retention_days, exclude_learned_ham=True,
                               tag="junk_retention", caps=caps)
    if acc.training_folders and acc.trained_retention_days > 0:
        _sweep_folder_to_trash(client, db, log, acc, fmap, src=fmap["trained_spam"],
                               days=acc.trained_retention_days, exclude_learned_ham=False,
                               tag="trained_retention", caps=caps)


def _sweep_folder_to_trash(
    client: IMAPClient, db: Db, log: logging.Logger, acc: Account, fmap: dict[str, str],
    *, src: str, days: int, exclude_learned_ham: bool, tag: str, caps: frozenset,
) -> None:
    if db.in_safe_mode("all"):
        return
    try:
        client.select_folder(src)
    except _CONN_ERRORS:
        raise
    except IMAPClientError as ex:
        log.warning("retention: select %s failed: %s", src, type(ex).__name__)
        return
    # BEFORE is evaluated in the server's timezone; one extra day means
    # retention can run a day late but never a day early.
    cutoff_date = time.strftime("%d-%b-%Y", time.gmtime(_now() - (days + 1) * 86400))
    try:
        uids = client.search(["BEFORE", cutoff_date])
    except _CONN_ERRORS:
        raise
    except IMAPClientError as ex:
        log.warning("retention: search BEFORE %s failed: %s", cutoff_date, type(ex).__name__)
        return
    if not uids:
        return
    uids = sorted(int(u) for u in uids)[:500]
    to_move: list[int] = []
    moved_msgids: list[str] = []
    fetched = client.fetch(uids, [_HDR_MSGID])
    for uid in uids:
        msgid = parse_envelope(_header_bytes(fetched.get(uid)))[0]
        if exclude_learned_ham and msgid:
            row = db.get_message(msgid)
            if row is not None and (row["learned_as"] == "ham" or row["user_verdict"] == "ham"):
                continue
            if row is not None and force_allow_rule(db.conn, acc.name, row["sender"]):
                continue  # 'Altid igennem' mail is never thrown away automatically
        to_move.append(uid)
        if msgid:
            moved_msgids.append(msgid)
    if not to_move:
        return
    try:
        imap_move(client, to_move, fmap["trash"], capabilities=caps)
    except MoveError as ex:
        log.warning("retention: move %s -> %s failed: %s", src, fmap["trash"], ex)
        return
    with db.tx():
        db.log_event(tag, detail=f"moved {len(to_move)} from {src} to {fmap['trash']}")
        for chunk in _chunks(moved_msgids, 500):
            db.conn.execute(
                f"UPDATE messages SET current_folder=? WHERE account=? "
                f"AND message_id IN ({','.join('?' * len(chunk))})",
                (fmap["trash"], db.account, *chunk),
            )
    log.info("retention sweep %s: moved %d %s -> %s", tag, len(to_move), src, fmap["trash"])


# ----- E6: autolearn ------------------------------------------------------


def _week_learns(db: Db) -> tuple[int, int]:
    days = [stats_day(_now() - i * 86400) for i in range(7)]
    rows = db.conn.execute(
        f"SELECT metric, SUM(n) FROM stats_daily WHERE account=? AND metric IN ('learned_spam','learned_ham') "
        f"AND day IN ({','.join('?' * len(days))}) GROUP BY metric", (db.account, *days)).fetchall()
    got = {r[0]: int(r[1] or 0) for r in rows}
    return got.get("learned_spam", 0), got.get("learned_ham", 0)


def _autolearn_today(db: Db, kind: str) -> int:
    return int(db.conn.execute(
        "SELECT COUNT(*) FROM autolearn_log WHERE account=? AND kind=? AND created_at>=? "
        "AND outcome IN ('learned','already')", (db.account, kind, int(_now()) - 86400)).fetchone()[0])


def _balance_ok(kind: str, spam_week: int, ham_week: int) -> bool:
    """Keep spam:ham learns of the week within 1:3 .. 3:1 after this learn."""
    if kind == "spam":
        return spam_week + 1 <= AUTOLEARN_BALANCE * max(ham_week, 1)
    return ham_week + 1 <= AUTOLEARN_BALANCE * max(spam_week, 1)


def _bayes_rebuild_active(conn: sqlite3.Connection) -> bool:
    """A 'Byg Bayes op på ny' is starting/running/restoring (services)."""
    try:
        return conn.execute("SELECT 1 FROM bayes_rebuilds WHERE status IN ('starting','running','restoring') "
                            "LIMIT 1").fetchone() is not None
    except sqlite3.Error:
        return False


def autolearn_candidates(db: Db, acc: Account, fmap: dict[str, str]) -> dict[str, list[sqlite3.Row]]:
    """E6 candidates (no IMAP): confirmed spam the filter moved itself
    (score >= threshold + 6, not released within 3 days) and clear ham the
    user kept in the inbox for 7 days (score <= 0).

    After a Bayes pool switch (services.bayes_pool_switch) ham never comes
    from mail an earlier pool already learned (any class, archived in
    bayes_pool_archive): the rebuild alone decides what old mail teaches the
    new pool, so inbox mail bootstrapped as ham years ago - or an autolearn
    an admin reverted - is not fed to the new pool as ham. While a rebuild
    runs, no ham is autolearned at all (the rebuild learns ham only from
    archive folders, capped at its ratio)."""
    now = int(_now())
    if _bayes_rebuild_active(db.conn):
        ham_rows: list[sqlite3.Row] | None = []
    else:
        ham_rows = None
    spam = db.conn.execute(
        """
        SELECT m.message_id, m.our_score, m.sender, m.current_folder FROM messages m
         WHERE m.account=? AND m.our_action='moved_to_junk' AND m.current_folder=?
           AND m.user_verdict IS NULL AND m.learned_as IS NULL AND m.pending_learn IS NULL
           AND m.moved_to_junk_at<=? AND m.our_score>=? AND m.score_version=?
           AND COALESCE(m.rule_hit, '') NOT LIKE 'allow:%'
           AND NOT EXISTS (SELECT 1 FROM autolearn_log a WHERE a.account=m.account AND a.message_id=m.message_id)
         ORDER BY m.our_score DESC LIMIT ?
        """,
        (db.account, fmap["junk"], now - AUTOLEARN_SPAM_AGE_S, acc.threshold + AUTOLEARN_SPAM_MARGIN,
         SCORE_VERSION, AUTOLEARN_SCAN_LIMIT)).fetchall()
    ham = ham_rows if ham_rows is not None else db.conn.execute(
        """
        SELECT m.message_id, m.our_score, m.sender, m.current_folder, m.rspamd_score, m.symbols,
               m.envelope_from FROM messages m
         WHERE m.account=? AND m.our_action='none' AND m.current_folder=?
           AND m.user_verdict IS NULL AND m.learned_as IS NULL AND m.pending_learn IS NULL
           AND m.scanned_at<=? AND m.our_score<=? AND m.score_version=?
           AND COALESCE(m.origin, 'inbox_scan')='inbox_scan'
           AND COALESCE(m.rule_hit, '') NOT LIKE 'allow:%'
           AND NOT EXISTS (SELECT 1 FROM autolearn_log a WHERE a.account=m.account AND a.message_id=m.message_id)
           AND NOT EXISTS (SELECT 1 FROM bayes_pool_archive b WHERE b.account=m.account
                           AND b.message_id=m.message_id AND b.src IN ('messages', 'ledger', 'autolearn'))
         ORDER BY m.scanned_at LIMIT ?
        """,
        (db.account, fmap["inbox"], now - AUTOLEARN_HAM_AGE_S, AUTOLEARN_HAM_MAX_SCORE, SCORE_VERSION,
         AUTOLEARN_SCAN_LIMIT)).fetchall()
    return {"spam": list(spam), "ham": list(ham)}


def _record_autolearn(db: Db, msgid: str, kind: str, score: Any, outcome: str) -> None:
    db.conn.execute(
        "INSERT OR IGNORE INTO autolearn_log(account, message_id, kind, score, outcome, created_at) "
        "VALUES(?,?,?,?,?,?)", (db.account, msgid, kind, score, outcome, int(_now())))


def autolearn_pass(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
                   fmap: dict[str, str]) -> dict[str, int]:
    """E6: learn a few confirmed messages per day to keep the shared Bayes
    pool balanced. Never in shadow mode, never for allow-listed senders,
    capped per day and kept within a 1:3..3:1 weekly balance. Every learn
    is logged in autolearn_log (reversible: revert_autolearn)."""
    done = {"spam": 0, "ham": 0}
    if not acc.autolearn or acc.mode == "shadow" or acc.autolearn_daily_cap <= 0:
        return done
    if db.in_safe_mode("learning"):
        return done
    cands = autolearn_candidates(db, acc, fmap)
    if not cands["spam"] and not cands["ham"]:
        return done
    spam_week, ham_week = _week_learns(db)
    for kind in ("spam", "ham"):
        left = acc.autolearn_daily_cap - _autolearn_today(db, kind)
        rows = cands[kind]
        if left <= 0 or not rows:
            continue
        folder = fmap["junk"] if kind == "spam" else fmap["inbox"]
        selected = False
        for r in rows:
            if left <= 0 or SHUTDOWN.is_set():
                break
            if not _balance_ok(kind, spam_week, ham_week):
                break
            msgid = r["message_id"]
            rule = match_sender_rule(db.conn, acc.name, r["sender"]) if r["sender"] else None
            if rule is not None and rule["kind"] == "allow":
                with db.tx():
                    _record_autolearn(db, msgid, kind, r["our_score"], "skipped_rule")
                continue
            if kind == "ham":
                guard = ham_guard_reason(db.conn, acc.name, symbols=r["symbols"], final=r["our_score"],
                                         rspamd_score=r["rspamd_score"], sender=r["sender"],
                                         envelope_from=r["envelope_from"],
                                         trust_limit=AUTOLEARN_HAM_MAX_SCORE)
                if guard is not None:
                    with db.tx():
                        _record_autolearn(db, msgid, kind, r["our_score"], "ham_guard")
                        db.log_event("ham_guard", msgid, detail=f"autolearn {guard[0]}: {guard[1]}"[:300])
                        db.bump("ham_guarded")
                    continue
            if not message_id_searchable(msgid):
                with db.tx():
                    _record_autolearn(db, msgid, kind, r["our_score"], "unsearchable")
                continue
            if not selected:
                client.select_folder(folder, readonly=True)
                selected = True
            uids = find_uids_by_message_id(client, msgid)
            if len(uids) != 1:
                with db.tx():
                    _record_autolearn(db, msgid, kind, r["our_score"], "lost" if not uids else "ambiguous")
                continue
            uid = uids[0]
            meta = client.fetch([uid], [b"RFC822.SIZE", b"FLAGS"]).get(uid, {})
            size = meta.get(b"RFC822.SIZE")
            flags = _flag_names(meta.get(b"FLAGS"))
            if kind == "ham" and ("\\Seen" not in flags or "\\Deleted" in flags
                                  or JUNK_KEYWORD in flags):
                # "Kept" means read and left in the inbox; unread, deleted
                # or junk-marked mail is no evidence. Re-checked next pass.
                continue
            if kind == "spam" and (flags & NOTJUNK_KEYWORDS):
                # The user said "not junk" in their client: never spam.
                with db.tx():
                    _record_autolearn(db, msgid, kind, r["our_score"], "skipped_user")
                continue
            if size is not None and int(size) > MAX_FETCH_BYTES:
                with db.tx():
                    _record_autolearn(db, msgid, kind, r["our_score"], "oversize")
                continue
            raw = _body_bytes(client.fetch([uid], [b"BODY.PEEK[]"]).get(uid))
            if not raw:
                continue
            res = learn_message(db, acc, raw, kind, msgid, actor="engine", reason="autolearn")
            if res == "rate_limited":
                return done
            if res == "error":
                continue
            with db.tx():
                _record_autolearn(db, msgid, kind, r["our_score"], res)
                db.log_event(f"autolearn_{kind}", msgid, detail=f"score={r['our_score']} {res}")
                if res in ("learned", "already"):
                    db.bump(f"autolearned_{kind}")
            if res in ("learned", "already"):
                done[kind] += 1
                left -= 1
                if res == "learned":
                    if kind == "spam":
                        spam_week += 1
                    else:
                        ham_week += 1
    if done["spam"] or done["ham"]:
        log.info("autolearn: %d spam, %d ham", done["spam"], done["ham"])
    return done


def revert_autolearn(conn: sqlite3.Connection, entry_id: int, actor: str = "") -> bool:
    """Undo an automatic learn: the entry is marked reverted and the message
    gets a pending learn of the opposite class (the account thread relearns
    it from wherever it is, see process_pending_learns). False when the
    entry does not exist or was already reverted."""
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    row = cur.execute("SELECT * FROM autolearn_log WHERE id=?", (int(entry_id),)).fetchone()
    if row is None or row["reverted_at"] is not None or row["outcome"] not in ("learned", "already"):
        return False
    now = int(_now())
    opposite = "ham" if row["kind"] == "spam" else "spam"
    with _autocommit(conn):
        conn.execute("UPDATE autolearn_log SET reverted_at=?, reverted_by=? WHERE id=?",
                     (now, actor or None, int(entry_id)))
        conn.execute("UPDATE messages SET pending_learn=?, pending_learn_at=? WHERE account=? AND message_id=?",
                     (opposite, now - 86400, row["account"], row["message_id"]))
        conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                     (row["account"], now, row["message_id"], "autolearn_reverted",
                      f"{row['kind']} by {actor}" if actor else row["kind"]))
    return True


def autolearn_entries(conn: sqlite3.Connection, account: str | None = None, limit: int = 100) -> list[dict]:
    """Recent autolearn bookkeeping for the UI (newest first)."""
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    sql = ("SELECT a.*, m.sender, m.subject FROM autolearn_log a LEFT JOIN messages m "
           "ON m.account=a.account AND m.message_id=a.message_id")
    args: list[Any] = []
    if account:
        sql += " WHERE a.account=?"
        args.append(account)
    sql += " ORDER BY a.created_at DESC, a.id DESC LIMIT ?"
    args.append(max(1, min(int(limit), 1000)))
    return [dict(r) for r in cur.execute(sql, args).fetchall()]


def autolearn_stats(conn: sqlite3.Connection, account: str | None = None, days: int = 7) -> dict[str, int]:
    """{'spam','ham','reverted'} automatic learns over the last `days`."""
    since = int(_now()) - days * 86400
    sql = ("SELECT kind, COUNT(*), SUM(reverted_at IS NOT NULL) FROM autolearn_log "
           "WHERE created_at>=? AND outcome IN ('learned','already')")
    args: list[Any] = [since]
    if account:
        sql += " AND account=?"
        args.append(account)
    out = {"spam": 0, "ham": 0, "reverted": 0}
    for kind, n, rev in conn.execute(sql + " GROUP BY kind", args).fetchall():
        out[str(kind)] = int(n or 0)
        out["reverted"] += int(rev or 0)
    return out


def _autolearn_revert_pending(db: Db, msgid: str, kind: str) -> bool:
    """A reverted autolearn waits for its opposite relearn (any folder)."""
    return db.conn.execute(
        "SELECT 1 FROM autolearn_log WHERE account=? AND message_id=? AND kind!=? AND reverted_at IS NOT NULL",
        (db.account, msgid, kind)).fetchone() is not None


# ----- E12: daily receipt ---------------------------------------------------

# Minimal Danish reasons for the receipt when ui_kit is unavailable.
RECEIPT_SYMBOL_TEXT: dict[str, str] = {
    "BAYES_SPAM": "Ligner tidligere spam",
    "TH_PROVIDER_SPAM": "Udbyderen har markeret den som spam",
    "TH_PROVIDER_SCORE": "Udbyderen fandt den mistænkelig",
    "R_SPF_FAIL": "Afsenderens server må ikke sende for domænet (SPF)",
    "R_SPF_SOFTFAIL": "Afsenderens server er ikke godkendt af domænet (SPF)",
    "DMARC_POLICY_REJECT": "Afsenderdomænet afviser mailen (DMARC)",
    "DMARC_POLICY_QUARANTINE": "Afsenderdomænet beder om karantæne (DMARC)",
    "R_DKIM_REJECT": "Ugyldig digital signatur (DKIM)",
    "FUZZY_DENIED": "Kendt spam-indhold",
    "RBL_SPAMHAUS_SBL": "Afsenderen står på en blokeringsliste",
    "RBL_SPAMHAUS_XBL": "Afsenderen står på en blokeringsliste",
    "URIBL_BLACK": "Indeholder links fra en blokeringsliste",
    "DBL_SPAM": "Indeholder links fra en blokeringsliste",
    "HIDDEN_TEXT": "Indeholder skjult tekst",
    "FORGED_SENDER": "Afsenderen ser forfalsket ud",
    "PHISHING": "Ligner phishing",
}


def _receipt_reason(symbols_json: Any) -> str:
    try:
        syms = json.loads(symbols_json) if symbols_json else []
    except (TypeError, ValueError):
        syms = []
    best = None
    for sym in syms if isinstance(syms, list) else []:
        if isinstance(sym, dict) and float(sym.get("s") or 0) > 0:
            if best is None or float(sym["s"]) > float(best["s"]):
                best = sym
    if best is None:
        return "Samlet vurdering"
    name = str(best.get("n") or "")
    if name.startswith("block") or name == "TH_BLOCK":
        return "Afsenderen er blokeret"
    try:
        import ui_kit  # noqa: PLC0415 - optional, only for the Danish texts

        text = ui_kit.explain_symbol(name)
        if text and not text.startswith("Teknisk regel"):
            return str(text)
    except Exception:  # noqa: BLE001 - fall back to the built-in table
        pass
    for prefix, text in (("RBL_", "Afsenderen står på en blokeringsliste"),
                         ("URIBL_", "Indeholder links fra en blokeringsliste"),
                         ("BAYES_", "Ligner tidligere spam"), ("FUZZY_", "Kendt spam-indhold")):
        if name.startswith(prefix):
            return RECEIPT_SYMBOL_TEXT.get(name, text)
    return RECEIPT_SYMBOL_TEXT.get(name, "Samlet vurdering")


def _receipt_items(conn: sqlite3.Connection, account: str, now: float) -> list[dict]:
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    rows = cur.execute(
        "SELECT message_id, sender, subject, our_score, symbols, rule_hit, our_action, moved_to_junk_at, "
        "zapped_at, threat, threat_detail "
        "FROM messages WHERE account=? AND moved_to_junk_at>=? AND our_action IN "
        "('moved_to_junk','manual_release','user_rescued') ORDER BY moved_to_junk_at DESC LIMIT ?",
        (account, int(now) - 86400, RECEIPT_MAX_ITEMS)).fetchall()
    out = []
    for r in rows:
        reason = ("Afsenderen er blokeret" if str(r["rule_hit"] or "").startswith("block:")
                  else threat_text(r["threat"], r["threat_detail"]) if r["threat"]
                  else _receipt_reason(r["symbols"]))
        out.append({"sender": r["sender"] or "(ukendt afsender)", "subject": r["subject"] or "(intet emne)",
                    "score": r["our_score"], "reason": reason,
                    "released": r["our_action"] in ("manual_release", "user_rescued"),
                    "zapped": bool(r["zapped_at"])})
    return out


def _receipt_safe_name(account: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", account.lower()).strip("-")[:40] or "konto"


def _fmt_score_da(score: Any) -> str:
    try:
        return f"{float(score):.1f}".replace(".", ",")
    except (TypeError, ValueError):
        return "–"


def build_receipt(acc: Account, items: list[dict], *, now: float | None = None,
                  preview: bool = False) -> tuple[bytes, str]:
    """(raw message, Message-ID) of the Danish daily receipt."""
    import html as _html
    from email.message import EmailMessage
    from email.utils import format_datetime

    now = _now() if now is None else now
    day = stats_day(now)
    name = _receipt_safe_name(acc.name)
    msgid = (f"report-{name}-{day}-preview-{uuid.uuid4().hex[:8]}@{RECEIPT_MSGID_DOMAIN}" if preview
             else f"report-{name}-{day}@{RECEIPT_MSGID_DOMAIN}")
    n = len(items)
    title = ("Ingen mails flyttet til Spamfilter-mappen det seneste døgn" if n == 0 else
             f"{n} mail{'s' if n != 1 else ''} flyttet til Spamfilter-mappen det seneste døgn")
    subject = ("[Prøve] " if preview else "") + "Spamfilter: " + title.lower().replace(
        "spamfilter-mappen", "Spamfilter-mappen")
    lines = ["Hej", "", title + ("." if n == 0 else ":"), ""]
    zapped = sum(1 for it in items if it.get("zapped"))
    if zapped:
        # B19: some were moved later, when a blocklist caught up.
        lines[2:3] = [title + ":", f"Flyttet efterfølgende (genscanning): {zapped}"]
    for it in items:
        mark = (" (frigivet)" if it["released"] else "") + (" (flyttet efterfølgende)" if it.get("zapped") else "")
        lines.append(f"- {it['sender']} – {it['subject']} (score {_fmt_score_da(it['score'])}) "
                     f"– {it['reason']}{mark}")
    lines += ["", "Er der en mail, du gerne ville have haft? Træk den tilbage til Indbakke, "
                  "så lærer filteret det.", "", siteconfig.signature()]
    text = "\n".join(lines) + "\n"
    rows_html = "".join(
        "<tr><td style=\"padding:6px 8px;border-bottom:1px solid #e5e7eb\">"
        f"{_html.escape(str(it['sender']))}</td>"
        "<td style=\"padding:6px 8px;border-bottom:1px solid #e5e7eb\">"
        f"{_html.escape(str(it['subject']))}{' <em>(frigivet)</em>' if it['released'] else ''}"
        f"{' <em>(flyttet efterfølgende)</em>' if it.get('zapped') else ''}</td>"
        "<td style=\"padding:6px 8px;border-bottom:1px solid #e5e7eb;text-align:right\">"
        f"{_fmt_score_da(it['score'])}</td>"
        "<td style=\"padding:6px 8px;border-bottom:1px solid #e5e7eb\">"
        f"{_html.escape(str(it['reason']))}</td></tr>" for it in items)
    table = ("<table style=\"border-collapse:collapse;width:100%;font-size:14px\">"
             "<tr><th align=\"left\" style=\"padding:6px 8px\">Afsender</th>"
             "<th align=\"left\" style=\"padding:6px 8px\">Emne</th>"
             "<th align=\"right\" style=\"padding:6px 8px\">Score</th>"
             "<th align=\"left\" style=\"padding:6px 8px\">Årsag</th></tr>" + rows_html + "</table>"
             ) if items else ""
    html_body = (
        "<!doctype html><html lang=\"da\"><body style=\"font-family:-apple-system,Segoe UI,Roboto,"
        "Helvetica,Arial,sans-serif;color:#111827;max-width:720px\">"
        f"<p>Hej</p><p><strong>{_html.escape(title)}</strong></p>{table}"
        "<p>Er der en mail, du gerne ville have haft? <strong>Træk den tilbage til Indbakke, "
        "så lærer filteret det.</strong></p><p style=\"color:#6b7280\">" + _html_escape(siteconfig.signature()) + "</p>"
        "</body></html>")
    msg = EmailMessage()
    msg["From"] = RECEIPT_FROM
    msg["To"] = acc.user
    msg["Subject"] = subject
    msg["Date"] = format_datetime(datetime.fromtimestamp(now, timezone.utc))
    msg["Message-ID"] = f"<{msgid}>"
    msg[RECEIPT_HEADER] = "report"
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(text)
    msg.add_alternative(html_body, subtype="html")
    return msg.as_bytes(policy=email.policy.SMTP), msgid


def _local_dt(ts: float) -> datetime:
    if _CPH is not None:
        return datetime.fromtimestamp(ts, _CPH)
    utc = datetime.fromtimestamp(ts, timezone.utc)
    dst = _last_sunday_0100_utc(utc.year, 3) <= utc < _last_sunday_0100_utc(utc.year, 10)
    return (utc + timedelta(hours=2 if dst else 1)).replace(tzinfo=None)


def _next_receipt_time(acc: Account, now: float) -> float | None:
    """Next unix time the report_hour starts (Europe/Copenhagen)."""
    loc = _local_dt(now)
    target = loc.replace(hour=acc.report_hour, minute=0, second=0, microsecond=0)
    if target <= loc:
        target += timedelta(days=1)
    return now + (target - loc).total_seconds()


def receipt_sent(conn: sqlite3.Connection, account: str, day: str | None = None,
                 kind: str = "daily") -> bool:
    return conn.execute("SELECT 1 FROM daily_receipts WHERE account=? AND day=? AND kind=? LIMIT 1",
                        (account, day or stats_day(), kind)).fetchone() is not None


def _is_our_receipt(db: Db, msgid: str, hdr: bytes) -> bool:
    """A receipt WE appended: our Message-ID domain, our header, and a row
    in daily_receipts (a forged look-alike is scanned like any mail)."""
    if not msgid.lower().endswith("@" + RECEIPT_MSGID_DOMAIN):
        return False
    try:
        msg = email.message_from_bytes(hdr or b"", policy=email.policy.compat32)
        if str(msg.get(RECEIPT_HEADER, "") or "").strip().lower() != "report":
            return False
    except Exception:  # noqa: BLE001
        return False
    return db.conn.execute("SELECT 1 FROM daily_receipts WHERE account=? AND message_id=?",
                           (db.account, msgid)).fetchone() is not None


def _append_receipt(client: IMAPClient, conn: sqlite3.Connection, acc: Account, inbox: str, *,
                    preview: bool, actor: str = "") -> dict[str, Any]:
    now = _now()
    items = _receipt_items(conn, acc.name, now)
    if not items and not preview:
        return {"ok": True, "code": "nothing", "items": 0,
                "text": "Intet flyttet det seneste døgn – ingen kvittering sendt."}
    raw, msgid = build_receipt(acc, items, now=now, preview=preview)
    day = stats_day(now)
    with _autocommit(conn):
        # Recorded BEFORE the APPEND so the scanner already knows it.
        conn.execute("INSERT OR REPLACE INTO daily_receipts(account, message_id, day, kind, items, sent_at, sent_by) "
                     "VALUES(?,?,?,?,?,?,?)",
                     (acc.name, msgid, day, "preview" if preview else "daily", len(items), int(now),
                      actor or None))
    try:
        with _autocommit(conn):
            mailidentity.bind(conn, acc.name, msgid, raw)
        client.append(inbox, raw, flags=(), msg_time=datetime.fromtimestamp(now, timezone.utc))
    except Exception:
        with _autocommit(conn):
            conn.execute("DELETE FROM daily_receipts WHERE account=? AND message_id=?", (acc.name, msgid))
        raise
    with _autocommit(conn):
        conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                     (acc.name, int(now), msgid, "receipt_sent",
                      f"{'preview' if preview else 'daily'} items={len(items)}"
                      + (f" by {actor}" if actor else "")))
    return {"ok": True, "code": "sent", "items": len(items), "message_id": msgid,
            "text": ("Prøvekvittering lagt i indbakken." if preview else "Kvittering lagt i indbakken.")}


def maybe_send_receipt(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
                       fmap: dict[str, str]) -> bool:
    """Account thread: once per day after report_hour (move mode, opt-in),
    if the account moved mail in the last 24 h."""
    if not acc.daily_report or acc.mode != "move":
        return False
    now = _now()
    if _local_dt(now).hour < acc.report_hour or receipt_sent(db.conn, acc.name, stats_day(now)):
        return False
    if not _receipt_items(db.conn, acc.name, now):
        return False
    try:
        res = _append_receipt(client, db.conn, acc, fmap["inbox"], preview=False)
    except _CONN_ERRORS:
        raise
    except IMAPClientError as ex:
        log.warning("daily receipt append failed: %s", _short_err(ex))
        db.log_event("receipt_failed", detail=_short_err(ex))
        return False
    log.info("daily receipt sent (%s items)", res.get("items"))
    return True


def send_receipt(account: str, preview: bool = True, *, actor: str = "", client: Any = None,
                 path: Path | None = None) -> dict[str, Any]:
    """Admin: append the receipt into the account's INBOX now. preview=True
    always sends (marked '[Prøve]', not counted as the day's receipt).
    Returns {"ok","code","text",("items","message_id")}; never raises."""
    try:
        accs = {a.name: a for a in load_account_configs(path)}
    except ValueError:
        return {"ok": False, "code": "config", "text": "Konfigurationen kan ikke indlæses."}
    acc = accs.get(account)
    if acc is None:
        return {"ok": False, "code": "no_account", "text": "Kontoen findes ikke."}
    conn = _open_conn()
    own = client is None
    try:
        if own:
            try:
                client = connect(acc, read_secret(acc))
            except LoginError:
                return {"ok": False, "code": "auth", "text": "Login afvist af mailserveren."}
            except ValueError:
                return {"ok": False, "code": "no_secret", "text": "Adgangskoden kunne ikke læses."}
            except (IMAPClientError, OSError):
                return {"ok": False, "code": "connect", "text": "Kunne ikke forbinde til mailserveren."}
        inbox = acc.folder_map.get("inbox") or acc.inbox
        return _append_receipt(client, conn, acc, inbox, preview=preview, actor=actor)
    except (IMAPClientError, OSError) as ex:
        logging.getLogger(account).warning("send_receipt failed: %s", _short_err(ex))
        return {"ok": False, "code": "imap_error", "text": "Kvitteringen kunne ikke lægges i indbakken."}
    finally:
        conn.close()
        if own and client is not None:
            _close_quietly(client)


# ----- 2.2 (B21): weekly report ---------------------------------------------

WEEKLY_WEEKDAY = 0               # Monday ...
WEEKLY_HOUR, WEEKLY_MINUTE = 7, 10   # ... 07:10 Europe/Copenhagen
WEEKLY_WINDOW_S = 48 * 3600      # sent only within 48 h after that (no surprise mid-week mail)


def _services() -> Any:
    import services  # noqa: PLC0415 - services imports the engine lazily

    return services


def _kv(conn: sqlite3.Connection, key: str) -> str | None:
    """settings_kv value (UI-owned table; missing table = None)."""
    try:
        row = conn.execute("SELECT value FROM settings_kv WHERE key=?", (key,)).fetchone()
    except sqlite3.Error:
        return None
    return None if row is None else row[0]


def weekly_due_window(now: float | None = None) -> tuple[float, str] | None:
    """(start ts, report week label) when `now` lies within WEEKLY_WINDOW_S
    after this week's Monday 07:10 (Copenhagen), else None. The report
    covers the previous ISO week."""
    now = _now() if now is None else now
    loc = _local_dt(now)
    monday = (loc - timedelta(days=loc.weekday())).replace(
        hour=WEEKLY_HOUR, minute=WEEKLY_MINUTE, second=0, microsecond=0)
    start = now - (loc - monday).total_seconds()
    if not 0 <= now - start < WEEKLY_WINDOW_S:
        return None
    prev = (monday - timedelta(days=7)).date()
    y, w, _d = prev.isocalendar()
    return start, f"{y}-W{w:02d}"


def last_week_label(now: float | None = None) -> str:
    """ISO week label ('YYYY-Www') of the last completed week (Copenhagen)."""
    loc = _local_dt(_now() if now is None else now)
    y, w, _d = (loc.date() - timedelta(days=loc.weekday() + 7)).isocalendar()
    return f"{y}-W{w:02d}"


_WEEKLY_ADMIN_CACHE: dict[str, Any] = {}


def _default_weekly_admin(configs: Sequence[Account] | None = None) -> str | None:
    """First enabled mailbox not in shadow mode (accounts.yml order).
    Cached 5 min when read from disk (the account loop asks often)."""
    if configs is None:
        hit = _WEEKLY_ADMIN_CACHE.get("v")
        if hit is not None and time.monotonic() - hit[0] < 300:
            return hit[1]
        try:
            configs = load_account_configs()
        except ValueError:
            return None
        names = [a.name for a in configs if a.enabled]
        first = next((a.name for a in configs if a.enabled and a.mode != "shadow"), None)
        _WEEKLY_ADMIN_CACHE["v"] = (time.monotonic(), first, names)
        return first
    return next((a.name for a in configs if a.enabled and a.mode != "shadow"), None)


def weekly_recipient(conn: sqlite3.Connection, acc: Account,
                     configs: Sequence[Account] | None = None) -> str | None:
    """'full' | 'short' | None: what this mailbox gets when the weekly
    report is enabled (settings_kv weekly_enabled / weekly_admin_account /
    weekly_users, see services.weekly_settings)."""
    on = ("1", "true", "on", "yes", "ja")
    if str(_kv(conn, "weekly_enabled") or "").strip().lower() not in on:
        return None
    if not acc.enabled or acc.mode == "shadow":
        return None  # shadow mode never writes to the mailbox
    admin = _kv(conn, "weekly_admin_account")
    if admin != acc.name:
        if configs is not None:
            names = {a.name for a in configs if a.enabled}
        else:
            _default_weekly_admin()
            hit = _WEEKLY_ADMIN_CACHE.get("v")
            names = set(hit[2]) if hit is not None else set()
        if admin not in names:
            admin = _default_weekly_admin(configs)
    if acc.name == admin:
        return "full"
    if str(_kv(conn, "weekly_users") or "").strip().lower() in on:
        return "short"
    return None


def build_weekly_report(acc: Account, rendered: dict[str, str], *, week: str, now: float | None = None,
                        preview: bool = False, unique: bool = False) -> tuple[bytes, str]:
    """(raw message, Message-ID) of a weekly report rendered by
    services.render_weekly. Same marker as the daily receipt (E12)."""
    from email.message import EmailMessage
    from email.utils import format_datetime

    now = _now() if now is None else now
    name = _receipt_safe_name(acc.name)
    suffix = f"-preview-{uuid.uuid4().hex[:8]}" if preview else (f"-{uuid.uuid4().hex[:8]}" if unique else "")
    msgid = f"weekly-{name}-{week.lower()}{suffix}@{RECEIPT_MSGID_DOMAIN}"
    msg = EmailMessage()
    msg["From"] = RECEIPT_FROM
    msg["To"] = acc.user
    msg["Subject"] = rendered["subject"]
    msg["Date"] = format_datetime(datetime.fromtimestamp(now, timezone.utc))
    msg["Message-ID"] = f"<{msgid}>"
    msg[RECEIPT_HEADER] = "report"
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(rendered["text"])
    msg.add_alternative(rendered["html"], subtype="html")
    return msg.as_bytes(policy=email.policy.SMTP), msgid


def _append_weekly(client: IMAPClient, conn: sqlite3.Connection, acc: Account, inbox: str, *,
                   full: bool, week: str | None, preview: bool, actor: str = "",
                   unique: bool = False) -> dict[str, Any]:
    svc = _services()
    data = svc.weekly_data(week or last_week_label(), account=None if full else acc.name)
    rendered = svc.render_weekly(data, full=full, preview=preview)
    now = _now()
    raw, msgid = build_weekly_report(acc, rendered, week=data["week"], now=now, preview=preview,
                                     unique=unique)
    kind = "weekly_preview" if preview else "weekly"
    with _autocommit(conn):
        # Recorded BEFORE the APPEND so the scanner already knows it (E12).
        conn.execute("INSERT OR REPLACE INTO daily_receipts(account, message_id, day, kind, items, sent_at, sent_by) "
                     "VALUES(?,?,?,?,?,?,?)",
                     (acc.name, msgid, data["week"], kind, int(data.get("totals", {}).get("moved") or 0),
                      int(now), actor or None))
    try:
        with _autocommit(conn):
            mailidentity.bind(conn, acc.name, msgid, raw)
        client.append(inbox, raw, flags=(), msg_time=datetime.fromtimestamp(now, timezone.utc))
    except Exception:
        with _autocommit(conn):
            conn.execute("DELETE FROM daily_receipts WHERE account=? AND message_id=?", (acc.name, msgid))
        raise
    with _autocommit(conn):
        conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                     (acc.name, int(now), msgid, "weekly_report_sent",
                      f"{kind} week={data['week']} {'full' if full else 'short'}"
                      + (f" by {actor}" if actor else "")))
    return {"ok": True, "code": "sent", "week": data["week"], "message_id": msgid, "full": full,
            "text": ("Prøve på ugerapporten lagt i indbakken." if preview else "Ugerapporten er lagt i indbakken.")}


def maybe_send_weekly(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
                      fmap: dict[str, str]) -> bool:
    """Account thread: once per ISO week, Monday from 07:10 (Copenhagen),
    for the mailboxes weekly_recipient() names (opt-in, default off)."""
    due = weekly_due_window()
    if due is None:
        return False
    _start, week = due
    if receipt_sent(db.conn, acc.name, week, kind="weekly"):
        return False
    who = weekly_recipient(db.conn, acc)
    if who is None:
        return False
    try:
        res = _append_weekly(client, db.conn, acc, fmap["inbox"], full=who == "full", week=week,
                             preview=False)
    except _CONN_ERRORS:
        raise
    except IMAPClientError as ex:
        log.warning("weekly report append failed: %s", _short_err(ex))
        db.log_event("weekly_report_failed", detail=_short_err(ex))
        return False
    except Exception as ex:  # noqa: BLE001 - a report must never break the account loop
        log.warning("weekly report failed: %s", type(ex).__name__)
        db.log_event("weekly_report_failed", detail=type(ex).__name__)
        return False
    log.info("weekly report %s sent (%s)", res.get("week"), "full" if who == "full" else "short")
    return True


def send_weekly_report(account: str, preview: bool = True, *, week: str | None = None,
                       full: bool | None = None, actor: str = "", client: Any = None,
                       path: Path | None = None) -> dict[str, Any]:
    """Admin 'Send nu': append the weekly report (default the last completed
    week) to the account's INBOX now. full=None: the full report for the
    admin mailbox (weekly_admin_account), the short one otherwise.
    preview=True marks it '[Prøve]' and does not count as the week's report.
    Never raises; {"ok","code","text",("week","message_id","full")}."""
    try:
        configs = load_account_configs(path)
    except ValueError:
        return {"ok": False, "code": "config", "text": "Konfigurationen kan ikke indlæses."}
    acc = next((a for a in configs if a.name == account), None)
    if acc is None:
        return {"ok": False, "code": "no_account", "text": "Kontoen findes ikke."}
    if week is not None:
        try:
            _services().parse_week(week)
        except ValueError:
            return {"ok": False, "code": "invalid", "text": "Ugen skal skrives som ÅÅÅÅ-Uuu (fx 2026-W43)."}
    conn = _open_conn()
    own = client is None
    try:
        if full is None:
            admin = _kv(conn, "weekly_admin_account")
            if admin not in {a.name for a in configs if a.enabled}:
                admin = _default_weekly_admin(configs)
            full = acc.name == admin
        if own:
            try:
                client = connect(acc, read_secret(acc))
            except LoginError:
                return {"ok": False, "code": "auth", "text": "Login afvist af mailserveren."}
            except ValueError:
                return {"ok": False, "code": "no_secret", "text": "Adgangskoden kunne ikke læses."}
            except (IMAPClientError, OSError):
                return {"ok": False, "code": "connect", "text": "Kunne ikke forbinde til mailserveren."}
        inbox = acc.folder_map.get("inbox") or acc.inbox
        return _append_weekly(client, conn, acc, inbox, full=bool(full), week=week, preview=preview,
                              actor=actor, unique=True)
    except (IMAPClientError, OSError) as ex:
        logging.getLogger(account).warning("send_weekly_report failed: %s", _short_err(ex))
        return {"ok": False, "code": "imap_error", "text": "Ugerapporten kunne ikke lægges i indbakken."}
    finally:
        conn.close()
        if own and client is not None:
            _close_quietly(client)


# ----- 2.3 (B29): mail notifications (mailer.py) ------------------------------

NOTIFY_MSGID_SUFFIX = "@" + RECEIPT_MSGID_DOMAIN


def _mailer() -> Any | None:
    """mailer.py with its paths synchronised to the engine's (tests move
    STATE_DIR/DB_PATH; production uses the same /state for both). None
    when it cannot be imported - notifications are optional."""
    try:
        import mailer  # noqa: PLC0415
    except Exception as ex:  # noqa: BLE001
        logging.getLogger("filter").debug("mailer unavailable: %s", type(ex).__name__)
        return None
    try:
        mailer.configure_paths(STATE_DIR, CONFIG_PATH, db_path=DB_PATH,
                               audit_file=Path(STATE_DIR) / "admin-audit.jsonl")
    except Exception:  # noqa: BLE001
        pass
    return mailer


def _push() -> Any | None:
    """push.py (2.5.0 push notifications) with its paths synchronised to the
    engine's. None when it cannot be imported - notifications are optional."""
    try:
        import push  # noqa: PLC0415
    except Exception as ex:  # noqa: BLE001
        logging.getLogger("filter").debug("push unavailable: %s", type(ex).__name__)
        return None
    try:
        push.configure_paths(STATE_DIR, CONFIG_PATH, db_path=DB_PATH)
        if not push.available():
            return None
    except Exception:  # noqa: BLE001
        return None
    return push


def _push_problem(conn: sqlite3.Connection, key: str) -> None:
    """alert_once() keys 'circuit:<acc>' / 'auth:<acc>' / 'safe:<acc>' ->
    a 'problem' push to administrators (independent of SMTP). Never raises."""
    kind, _, account = str(key).partition(":")
    p = _push()
    if p is None:
        return
    try:
        p.on_problem(conn, kind, account or None)
    except Exception as ex:  # noqa: BLE001
        logging.getLogger("filter").warning("problem push failed: %s", type(ex).__name__)


def _is_own_notification(db: Db, msgid: str, hdr: bytes) -> bool:
    """A mail THIS filter sent (mailer.is_own_notification: our Message-ID
    form, X-TH-Spamfilter: notify and a mail_outbox row)."""
    mid = str(msgid or "")
    if not (mid.startswith("notify.") and mid.lower().endswith(NOTIFY_MSGID_SUFFIX)):
        return False  # cheap pre-check: no import for ordinary mail
    m = _mailer()
    if m is None:
        return False
    try:
        return bool(m.is_own_notification(f"<{mid}>", hdr, conn=db.conn))
    except Exception:  # noqa: BLE001
        return False


ALERT_KEY_PREFIX = "alert_mail:"


def alert_once(conn: sqlite3.Connection, key: str, episode: str, subject: str, text: str) -> bool:
    """Queue an 'alert' mail once per episode (engine_state de-duplication:
    the same key + episode is never mailed twice; a new episode is).
    Subjects match host-monitor's, whose mailer CLI call then skips the
    duplicate. Never raises; True when the mailer queued it."""
    k = ALERT_KEY_PREFIX + key
    try:
        if engine_state_get(conn, k) == str(episode):
            return False
        engine_state_set(conn, k, str(episode))
    except sqlite3.Error:
        return False
    _push_problem(conn, key)  # 2.5.0: the same moment as the alert mail, also without SMTP
    m = _mailer()
    if m is None:
        return False
    try:
        res = m.notify("alert", subject, text)
    except Exception as ex:  # noqa: BLE001 - a notification never breaks the engine
        logging.getLogger("filter").warning("alert mail failed: %s", type(ex).__name__)
        return False
    return bool(res.get("ok"))


def alert_clear(conn: sqlite3.Connection, key: str) -> None:
    """The problem is over: the next episode may mail again."""
    try:
        if engine_state_get(conn, ALERT_KEY_PREFIX + key) is not None:
            engine_state_set(conn, ALERT_KEY_PREFIX + key, None)
    except sqlite3.Error:
        pass


# ----- 2.3.6 (B22): lookalike registration watch -----------------------------

LOOKALIKE_WATCH_INTERVAL_S = 7 * 86400          # weekly ...
LOOKALIKE_WATCH_HOURS = (3, 4)                   # ... at a quiet hour (Copenhagen)
LOOKALIKE_WATCH_POLL_S = 60                      # how often the thread asks "due?"
LOOKALIKE_WATCH_RETRY_S = 3600                   # after an incomplete run
LOOKALIKE_STATE_LAST = "lookalike_watch_last"            # JSON summary of the last run
LOOKALIKE_STATE_COMPLETE = "lookalike_watch_complete_at"  # ts of the last complete run
LOOKALIKE_STATE_ATTEMPT = "lookalike_watch_attempt_at"
LOOKALIKE_STATE_REQUEST = "lookalike_watch_request"      # 'Kør kontrol nu' (services)
# Empty counts as unset (dockerMan passes empty variables); 2.4 AIO: 127.0.0.1.
LOOKALIKE_DNS_SERVER = (os.environ.get("LOOKALIKE_DNS_SERVER") or "").strip() or "spamfilter-unbound"


def _int_or_zero(v: Any) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def lookalike_watch_due(conn: sqlite3.Connection, now: float | None = None) -> str | None:
    """'request' (the admin pressed 'Kør kontrol nu'), 'schedule' (a week
    since the last complete run and a quiet hour) or None."""
    now = _now() if now is None else now
    if engine_state_get(conn, LOOKALIKE_STATE_REQUEST):
        return "request"
    if now - _int_or_zero(engine_state_get(conn, LOOKALIKE_STATE_ATTEMPT)) < LOOKALIKE_WATCH_RETRY_S:
        return None
    done = _int_or_zero(engine_state_get(conn, LOOKALIKE_STATE_COMPLETE))
    if done and now - done < LOOKALIKE_WATCH_INTERVAL_S - 3 * 3600:
        return None
    if _local_dt(now).hour not in LOOKALIKE_WATCH_HOURS:
        return None
    return "schedule"


def lookalike_watch_protected(configs: Iterable[Any]) -> list[str]:
    """Every protected domain of every configured mailbox."""
    configs = list(configs or ())
    lk = _lookalike()
    mailboxes = sorted({str(getattr(a, "user", "") or "").rpartition("@")[2].lower()
                        for a in configs if "@" in str(getattr(a, "user", "") or "")})
    out: list[str] = []
    for a in configs:
        for d in lk.protected_domains(getattr(a, "protected_domains", None), [], mailboxes):
            if d not in out:
                out.append(d)
    return out or lk.protected_domains(None, [], mailboxes)


def _lookalike_alert(conn: sqlite3.Connection, items: list[dict], now: int) -> bool:
    """One 'alert' mail for the new registrations of a run (only when the
    mailer is set up; the Oversigt item and the weekly report cover the
    rest). Never raises; True when queued."""
    lk = _lookalike()
    m = _mailer()
    if m is None or not items:
        return False
    targets = sorted({str(i.get("protected")) for i in items})
    subject = (f"Spamfilter: nyt domæne ligner {targets[0]}" if len(items) == 1
               else f"Spamfilter: {len(items)} nye domæner ligner jeres ({', '.join(targets)[:80]})")
    lines = ["Den ugentlige kontrol har fundet domæner, der ligner jeres egne, og som netop har fået en "
             "mailserver eller en hjemmeside:", ""]
    lines += [f"- {lk.new_text(i)}" for i in items[:20]]
    if len(items) > 20:
        lines.append(f"- ... og {len(items) - 20} mere")
    lines += ["", "Mails fra domænerne bliver lagt i Spamfilter-mappen og kan kun frigives af en administrator. "
              "Overvej at advare kunder og kolleger, og anmeld domænet til registratoren, hvis det bruges til "
              "svindel.", "",
              "Se listen under Indstillinger -> Beskyttede domæner. Er et domæne ikke en efterligning, så tryk "
              "\"Ikke en efterligning\" dér."]
    try:
        res = m.notify("alert", subject, "\n".join(lines))
    except Exception as ex:  # noqa: BLE001 - a notification never breaks the engine
        logging.getLogger("lookalike").warning("lookalike alert mail failed: %s", type(ex).__name__)
        return False
    if not res.get("ok"):
        return False
    with _autocommit(conn):
        for i in items:
            conn.execute("UPDATE lookalike_watch SET alerted_at=? WHERE domain=?", (int(now), i["domain"]))
    return True


def lookalike_watch_once(configs: Iterable[Any], *, conn: sqlite3.Connection | None = None,
                         resolver: Any = None, now: float | None = None, stop: threading.Event | None = None,
                         limiter: Any = None, reason: str = "schedule",
                         max_lookups: int | None = None) -> dict[str, Any]:
    """One registration watch run: DNS checks (lookalike.run_watch), the
    run summary in engine_state, events ('*' account) and the alert mail
    for new registrations. Returns the summary."""
    lk = _lookalike()
    own = conn is None
    conn = _open_conn() if own else conn
    log = logging.getLogger("lookalike")
    try:
        now = int(_now() if now is None else now)
        engine_state_set(conn, LOOKALIKE_STATE_ATTEMPT, str(now))
        if reason == "request" or engine_state_get(conn, LOOKALIKE_STATE_REQUEST):
            engine_state_set(conn, LOOKALIKE_STATE_REQUEST, None)
        protected = lookalike_watch_protected(configs)
        if limiter is None:
            limiter = lk.RateLimiter(lk.WATCH_RATE, sleep=lambda s: (stop or SHUTDOWN).wait(s))
        kw: dict[str, Any] = {}
        if max_lookups is not None:
            kw["max_lookups"] = max_lookups
        res = lk.run_watch(conn, protected, resolver if resolver is not None else lk.DnsResolver(LOOKALIKE_DNS_SERVER),
                           now=now, stop=stop if stop is not None else SHUTDOWN, limiter=limiter,
                           clock=_now, **kw)
        summary = res.as_dict()
        summary.update(protected=protected, reason=reason,
                       complete=not (res.capped or res.stopped or res.error))
        engine_state_set(conn, LOOKALIKE_STATE_LAST, json.dumps(summary, separators=(",", ":")))
        if summary["complete"]:
            engine_state_set(conn, LOOKALIKE_STATE_COMPLETE, str(res.finished_at or now))
        with _autocommit(conn):
            ts = int(_now())
            for item in res.new:
                conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES('*',?,NULL,?,?)",
                             (ts, "lookalike_registered",
                              f"{item['domain']} ligner {item['protected']}: {','.join(item['what'])}"[:300]))
            ev = "lookalike_watch_failed" if res.error else "lookalike_watch_done"
            conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES('*',?,NULL,?,?)",
                         (ts, ev, (f"fejl={res.error} " if res.error else "")
                          + f"kontrolleret={res.checked} nye={len(res.new)} basis={res.baseline} "
                            f"fejl_opslag={res.errors} opslag={res.lookups}" + (" loft" if res.capped else "")))
        if res.new:
            _lookalike_alert(conn, res.new, now)
        log.info("lookalike watch: %d checked, %d new, %d baseline, %d errors, %d lookups%s",
                 res.checked, len(res.new), res.baseline, res.errors, res.lookups,
                 f" ({res.error})" if res.error else "")
        return summary
    finally:
        if own:
            conn.close()


def _lookalike_watch_loop(configs: list[Any]) -> None:
    log = logging.getLogger("lookalike")
    while not SHUTDOWN.wait(LOOKALIKE_WATCH_POLL_S):
        try:
            conn = _open_conn()
            try:
                why = lookalike_watch_due(conn)
                if why:
                    log.info("lookalike watch starting (%s)", why)
                    lookalike_watch_once(configs, conn=conn, reason=why)
            finally:
                conn.close()
        except Exception as ex:  # noqa: BLE001 - the watch must never take the engine down
            log.warning("lookalike watch failed: %s", type(ex).__name__)


def _start_lookalike_watch(log: logging.Logger, configs: list[Any]) -> None:
    try:
        threading.Thread(target=_lookalike_watch_loop, args=(list(configs),), name="lookalike-watch",
                         daemon=True).start()
    except Exception as ex:  # noqa: BLE001
        log.error("failed to start the lookalike watch: %s", _short_err(ex))


def _start_mailcheck(log: logging.Logger, configs: list[Any]) -> None:
    """2.7: the nightly / on-demand Mailsikkerhed check (mailcheck.py)."""
    try:
        import mailcheck  # noqa: PLC0415

        if mailcheck.start(sys.modules[__name__], configs):
            log.info("mailcheck: nightly at %s:00 and on request", "/".join(f"{h:02d}" for h in mailcheck.RUN_HOURS))
    except Exception as ex:  # noqa: BLE001 - the check never blocks the filter
        log.error("failed to start the mailcheck: %s", _short_err(ex))


def _alert_circuit(db: Db, acc: Account, reason: str) -> None:
    row = circuit_row(db.conn, db.account)
    episode = str(row["opened_at"]) if row is not None and row["opened_at"] else str(int(_now()))
    alert_once(db.conn, f"circuit:{acc.name}", episode,
               f"Spamfilter: Konto {acc.name}: sikkerhedsbremsen har sat flytning på pause - mange mails "
               f"blev flyttet på kort tid. Tjek Fanget spam og genoptag under Konti",
               f"Sikkerhedsbremsen har sat flytning på pause for postkassen {acc.name}.\n\n"
               f"Årsag: {reason}\n\nMails scannes stadig, og fundet spam venter. Tjek Fanget spam, og "
               f"genoptag flytning under Konti, når alt ser rigtigt ud.")


def _alert_auth(db: Db, acc: Account) -> None:
    alert_once(db.conn, f"auth:{acc.name}", "1",
               f"Spamfilter: Konto {acc.name}: login afvist - tjek adgangskoden",
               f"Mailserveren har afvist login for postkassen {acc.name} {LOGIN_FAILURES_BEFORE_AUTH_FAILED} "
               f"gange i træk. Filteret prøver igen om {AUTH_FAILED_RETRY_S // 60} minutter, eller så snart "
               f"adgangskoden ændres under Konti.")


def _alert_safe_mode(db: Db, acc: Account, unseen: int, cap: int) -> None:
    alert_once(db.conn, f"safe:{acc.name}", "all",
               f"Spamfilter: Konto {acc.name}: sikkerhedstilstand - filteret behandler ikke nye mails",
               f"Postkassen {acc.name} har {unseen} ulæste mails i indbakken (grænsen er {cap}). "
               f"Filteret rører derfor ikke nye mails, før antallet er under grænsen igen. Intet er "
               f"flyttet eller slettet.")


def maybe_mail_weekly(db: Db, log: logging.Logger, *, now: float | None = None) -> bool:
    """B21 + B29: once per ISO week (Monday 07:10 + 48 h window) the FULL
    weekly report also goes out by mail when Indstillinger ->
    Notifikationer -> Ugerapport is on. Independent of the IMAP weekly
    report switch; claimed in engine_state so only one account thread
    sends it. Never raises."""
    due = weekly_due_window(now)
    if due is None:
        return False
    _start, week = due
    key = f"weekly_mail:{week}"
    try:
        if engine_state_get(db.conn, key) is not None:
            return False
    except sqlite3.Error:
        return False
    m = _mailer()
    if m is None:
        return False
    try:
        if not m.is_configured() or not m.recipients_for("weekly"):
            return False
        # A claim released after a failure is a row with value NULL: it may
        # be taken again (INSERT OR IGNORE alone would skip the week).
        cur = db.conn.execute("INSERT INTO engine_state(key, value, updated_at) VALUES(?,?,?) "
                              "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at "
                              "WHERE engine_state.value IS NULL", (key, "claimed", int(_now())))
        if not cur.rowcount:
            return False  # another account thread took it
        svc = _services()
        data = svc.weekly_data(week, account=None)
        rendered = svc.render_weekly(data, full=True, preview=False)
        res = m.notify("weekly", rendered["subject"], rendered["text"], html=rendered["html"])
    except Exception as ex:  # noqa: BLE001 - a report never breaks the account loop
        log.warning("weekly report mail failed: %s", type(ex).__name__)
        try:
            engine_state_set(db.conn, key, None)
        except sqlite3.Error:
            pass
        return False
    if not res.get("ok"):
        if res.get("code") not in ("not_configured", "disabled", "off", "no_recipients"):
            log.warning("weekly report mail not queued: %s", res.get("code"))
        try:
            engine_state_set(db.conn, key, None)
        except sqlite3.Error:
            pass
        return False
    try:
        engine_state_set(db.conn, key, "queued")
        db.log_event("weekly_report_mailed", detail=f"week={week} recipients={res.get('queued', 0)}")
    except sqlite3.Error:
        pass
    log.info("weekly report %s mailed to %s recipient(s)", week, res.get("queued"))
    return True


# ----- Straks-advarsel: threat notices in the INBOX + admin alert -------------

THREAT_NOTICE_INTERVAL_S = 30 * 60   # at most one notice per mailbox per 30 min
THREAT_NOTICE_MAX_ITEMS = 10         # listed per notice ("... og N mere")
THREAT_NOTICE_RETRY_S = 5 * 60       # after a failed APPEND
THREAT_NOTICE_KIND = "threat"        # daily_receipts.kind
THREAT_NOTICE_KEEP_S = 30 * 86400
THREAT_NOTICE_UNQUEUED_KEEP_S = 2 * 86400
THREAT_ALERT_CLASSES = frozenset({"virus", "attachment", "phish", "malware_url"})
THREAT_ALERT_INTERVAL_S = 30 * 60    # per mailbox
THREAT_ALERT_MAX_PER_HOUR = 6        # all mailboxes together
THREAT_ALERT_MAX_AGE_S = 24 * 3600   # never mail about old catches (e.g. SMTP set up later)
THREAT_NOTICE_TYPE = {
    "phish": "Phishing-link – linket fører til en falsk side",
    "virus": "Virus",
    "malware_url": "Farligt link – linket fører til skadelig software",
    "impersonation": "Forfalsket afsender – mailen udgiver sig for at være en anden",
    "lookalike": "Falsk afsenderdomæne – ligner et domæne, du kender",
}
_MONTHS_SHORT_DA = ("jan.", "feb.", "marts", "april", "maj", "juni", "juli", "aug.", "sep.", "okt.",
                    "nov.", "dec.")
# Anything a mail client could turn into a link: schemes (http:, javascript:,
# data:, ...) and www. hosts are removed; every remaining dot between two
# word characters becomes U+2024 (ONE DOT LEADER), which looks like a dot
# but is never auto-linked ("faktura.zip" -> "faktura․zip").
_NOTICE_SCHEME_RE = re.compile(r"(?i)\b(?:[a-z][a-z0-9+.-]{0,15}:/+|(?:javascript|data|vbscript|file|mailto|"
                               r"https?|ftp|tel|sms|cid|blob)\s*:)\S*")
# Also the ideographic / full-width dots (U+3002, U+FF0E, U+FF61): IDNA
# treats them as a dot, so 'paypal\u3002com' could be auto-linked too.
_NOTICE_WWW_RE = re.compile(r"(?i)\bwww\d{0,3}\s*[.\u3002\uff0e\uff61]\S*")
_NOTICE_DOT_RE = re.compile(r"(?<=\w)[.\u3002\uff0e\uff61](?=\w)")
_NOTICE_ADDR_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")


def notice_safe_text(value: Any, limit: int = 120) -> str:
    """Attacker-controlled text (display name, subject, file name) made safe
    for the notice: no control/format characters (bidi, zero-width), no
    URL or scheme, no linkable host name; shortened with '…'."""
    text = _clean_display(value)
    text = _NOTICE_SCHEME_RE.sub("[link fjernet]", text)
    text = _NOTICE_WWW_RE.sub("[link fjernet]", text)
    text = _NOTICE_DOT_RE.sub("\u2024", text)  # ONE DOT LEADER
    if len(text) > limit:
        text = text[: max(1, limit - 1)].rstrip() + "…"
    return text


def notice_safe_address(value: Any) -> str:
    """The sender address as written - unless it is not a plain address
    (then it is defanged like any other attacker text)."""
    text = _clean_display(value)[:200]
    if _NOTICE_ADDR_RE.match(text) and "www." not in text.lower() and "://" not in text:
        return text
    return notice_safe_text(text, 120)


def notice_type_text(threat: Any, detail: Any = None) -> str:
    """The threat in plain Danish for the notice (never a URL or a rule name)."""
    t = str(threat or "")
    if t == "attachment":
        name = notice_safe_text(detail, 80) if detail and str(detail) != "ukendt fil" else ""
        return f"Farlig vedhæftning: {name}" if name else "Farlig vedhæftning"
    return THREAT_NOTICE_TYPE.get(t, "Farlig mail")


def _da_datetime(ts: Any) -> str:
    try:
        d = _local_dt(float(ts))
    except (TypeError, ValueError, OverflowError, OSError):
        return "ukendt tidspunkt"
    return f"{d.day}. {_MONTHS_SHORT_DA[d.month - 1]} {d.year} kl. {d.hour:02d}.{d.minute:02d}"


def _sender_display_name(raw: bytes) -> str | None:
    """The From display name of a mail (decoded), None when there is none."""
    try:
        msg = email.message_from_bytes(raw[:65536], policy=email.policy.compat32)
        name, _addr = parseaddr(_decode_header_text(msg.get("From", "")))
    except Exception:  # noqa: BLE001
        return None
    name = _clean_display(name)[:200]
    return name or None


def _register_threat(db: Db, msgid: str, threat: str, raw: bytes | None, now: int) -> None:
    """Scan time: remember the sender's display name for a later notice."""
    try:
        db.conn.execute(
            "INSERT INTO threat_notices(account, message_id, threat, sender_name, created_at) VALUES(?,?,?,?,?) "
            "ON CONFLICT(account, message_id) DO UPDATE SET threat=excluded.threat, "
            "sender_name=COALESCE(excluded.sender_name, threat_notices.sender_name)",
            (db.account, msgid, threat, _sender_display_name(raw) if raw else None, now))
    except sqlite3.Error as ex:  # table missing on an odd DB: never block a scan
        logging.getLogger(db.account).debug("threat_notices: %s", type(ex).__name__)


def _queue_threat_notice(db: Db, msgid: str, threat: str, now: int) -> None:
    """Move time: the threat mail is now in the filter's folder."""
    try:
        db.conn.execute(
            "INSERT INTO threat_notices(account, message_id, threat, created_at, queued_at) VALUES(?,?,?,?,?) "
            "ON CONFLICT(account, message_id) DO UPDATE SET threat=excluded.threat, "
            "queued_at=COALESCE(threat_notices.queued_at, excluded.queued_at)",
            (db.account, msgid, threat, now, now))
    except sqlite3.Error as ex:
        logging.getLogger(db.account).debug("threat_notices: %s", type(ex).__name__)


def _threat_notice_items(conn: sqlite3.Connection, account: str, *, unsent_only: bool = True,
                         alert: bool = False, since: int | None = None) -> list[dict[str, Any]]:
    where = "t.account=? AND t.queued_at IS NOT NULL"
    args: list[Any] = [account]
    if unsent_only:
        where += " AND t.sent_at IS NULL"
    if alert:
        where += f" AND t.alerted_at IS NULL AND t.threat IN ({','.join('?' * len(THREAT_ALERT_CLASSES))})"
        args += sorted(THREAT_ALERT_CLASSES)
    if since is not None:
        where += " AND t.queued_at>=?"
        args.append(int(since))
    rows = conn.execute(
        f"SELECT t.message_id, t.threat, t.sender_name, t.queued_at, m.sender, m.subject, m.received_at, "
        f"m.threat_detail FROM threat_notices t LEFT JOIN messages m "
        f"ON m.account=t.account AND m.message_id=t.message_id WHERE {where} ORDER BY t.queued_at, t.rowid",
        args).fetchall()
    return [{"message_id": r[0], "threat": r[1], "sender_name": r[2], "queued_at": r[3], "sender": r[4],
             "subject": r[5], "received_at": r[6], "detail": r[7]} for r in rows]


def _notice_folder_label(acc: Account, fmap: dict[str, str] | None) -> str:
    name = str((fmap or {}).get("junk") or acc.junk or "Spamfilter")
    delim = acc.delimiter if acc.delimiter and acc.delimiter != "/" else "."
    leaf = name.rsplit(delim, 1)[-1].rsplit("/", 1)[-1] or name
    return notice_safe_text(leaf, 60) or "Spamfilter"


def build_threat_notice(acc: Account, items: list[dict[str, Any]], *, now: float | None = None,
                        folder: str = "Spamfilter") -> tuple[bytes, str, str]:
    """(raw message, Message-ID, subject) of the Danish Straks-advarsel.
    Lists at most THREAT_NOTICE_MAX_ITEMS mails (sender name + address,
    subject, type in plain words, date) - never a URL, attachment or any
    HTML from the dangerous mail. Plain text + simple, escaped HTML."""
    import html as _html
    from email.message import EmailMessage
    from email.utils import format_datetime

    now = _now() if now is None else now
    n = len(items)
    shown = items[:THREAT_NOTICE_MAX_ITEMS]
    more = n - len(shown)
    msgid = (f"threat-{_receipt_safe_name(acc.name)}-{int(now)}-{uuid.uuid4().hex[:8]}"
             f"@{RECEIPT_MSGID_DOMAIN}")
    headline = ("⚠️ Spamfilteret har stoppet en farlig mail" if n == 1 else
                f"⚠️ Spamfilteret har stoppet {n} farlige mails")
    folder = notice_safe_text(folder, 60) or "Spamfilter"
    if n == 1:
        advice = (f"Mailen ligger i mappen {folder}. Åbn den ikke, og klik ikke på links. "
                  "Ventede du mailen, så kontakt administratoren.")
    else:
        advice = (f"Mailene ligger i mappen {folder}. Åbn dem ikke, og klik ikke på links. "
                  "Ventede du en af mailene, så kontakt administratoren.")
    rows: list[tuple[str, str, str, str]] = []
    for it in shown:
        name = notice_safe_text(it.get("sender_name"), 80) if it.get("sender_name") else ""
        addr = notice_safe_address(it.get("sender")) if it.get("sender") else ""
        sender = f"{name} <{addr}>" if name and addr else (name or addr or "ukendt afsender")
        subject = notice_safe_text(it.get("subject"), 120) or "(intet emne)"
        when = _da_datetime(it.get("received_at") or it.get("queued_at"))
        rows.append((sender, subject, notice_type_text(it.get("threat"), it.get("detail")), when))
    lines = [headline, ""]
    for i, (sender, subject, kind, when) in enumerate(rows, 1):
        prefix = f"{i}. " if n > 1 else ""
        pad = " " * len(prefix)
        lines += [f"{prefix}Afsender: {sender}", f"{pad}Emne: {subject}", f"{pad}Type: {kind}",
                  f"{pad}Modtaget: {when}", ""]
    if more > 0:
        lines += [f"… og {more} mere.", ""]
    lines += [advice, "", siteconfig.signature()]
    text = "\n".join(lines) + "\n"
    esc = _html.escape
    cell = "padding:4px 8px;vertical-align:top"
    blocks = "".join(
        "<table role=\"presentation\" style=\"border-collapse:collapse;width:100%;font-size:14px;"
        "margin:0 0 12px;border:1px solid #e5e7eb\">"
        f"<tr><td style=\"{cell};color:#6b7280;width:90px\">Afsender</td><td style=\"{cell}\">{esc(s)}</td></tr>"
        f"<tr><td style=\"{cell};color:#6b7280\">Emne</td><td style=\"{cell}\">{esc(subj)}</td></tr>"
        f"<tr><td style=\"{cell};color:#6b7280\">Type</td><td style=\"{cell}\"><strong>{esc(k)}</strong></td></tr>"
        f"<tr><td style=\"{cell};color:#6b7280\">Modtaget</td><td style=\"{cell}\">{esc(w)}</td></tr>"
        "</table>" for s, subj, k, w in rows)
    more_html = f"<p>… og {more} mere.</p>" if more > 0 else ""
    html_body = (
        "<!doctype html><html lang=\"da\"><body style=\"font-family:-apple-system,Segoe UI,Roboto,"
        "Helvetica,Arial,sans-serif;color:#111827;max-width:640px\">"
        "<div style=\"border-left:4px solid #dc2626;background:#fef2f2;padding:12px 16px;margin:0 0 16px\">"
        f"<p style=\"font-size:18px;margin:0\"><strong>{esc(headline)}</strong></p></div>"
        f"{blocks}{more_html}<p><strong>{esc(advice)}</strong></p>"
        "<p style=\"color:#6b7280\">" + _html_escape(siteconfig.signature()) + "</p></body></html>")
    msg = EmailMessage()
    msg["From"] = RECEIPT_FROM
    msg["To"] = acc.user
    msg["Subject"] = headline
    msg["Date"] = format_datetime(datetime.fromtimestamp(now, timezone.utc))
    msg["Message-ID"] = f"<{msgid}>"
    msg[RECEIPT_HEADER] = "report"   # the same skip as receipts (also in 2.2/2.3 code)
    msg["X-TH-Spamfilter-Kind"] = "threat-notice"
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(text)
    msg.add_alternative(html_body, subtype="html")
    return msg.as_bytes(policy=email.policy.SMTP), msgid, headline


def _last_threat_notice(conn: sqlite3.Connection, account: str) -> int | None:
    row = conn.execute("SELECT MAX(sent_at) FROM daily_receipts WHERE account=? AND kind=?",
                       (account, THREAT_NOTICE_KIND)).fetchone()
    return int(row[0]) if row and row[0] is not None else None


def threat_notice_due_in(conn: sqlite3.Connection, acc: Account, now: float | None = None) -> float | None:
    """Seconds until a queued notice/alert may go out (None: nothing queued)."""
    now = _now() if now is None else now
    try:
        row = conn.execute("SELECT 1 FROM threat_notices WHERE account=? AND queued_at IS NOT NULL "
                           "AND sent_at IS NULL LIMIT 1", (acc.name,)).fetchone()
        if row is None:
            return None
        if not acc.threat_notice:
            return 0.0
        last = _last_threat_notice(conn, acc.name)
        retry = engine_state_get(conn, f"threat_notice_retry:{acc.name}")
    except sqlite3.Error:
        return None
    due = 0.0 if last is None else last + THREAT_NOTICE_INTERVAL_S - now
    if retry:
        try:
            due = max(due, float(retry) - now)
        except ValueError:
            pass
    return max(0.0, due)


def maybe_send_threat_notice(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
                             fmap: dict[str, str], *, now: float | None = None) -> bool:
    """Straks-advarsel: append ONE notice listing every threat moved since
    the last one into the mailbox's own INBOX (recorded in daily_receipts
    BEFORE the APPEND, so the scanner, junk poll and learning skip it), at
    most once per THREAT_NOTICE_INTERVAL_S. Also runs the admin alert.
    Never raises IMAP command errors (connection errors propagate)."""
    now = _now() if now is None else now
    try:
        _threat_admin_alert(db, acc, now=now)
    except Exception as ex:  # noqa: BLE001 - an alert never breaks the loop
        log.warning("threat alert failed: %s", type(ex).__name__)
    p = _push()
    if p is not None:
        # 2.5.0: 'Farlig mail stoppet' push to everybody who can see this
        # mailbox and wants it (counts only; the push queue rate-limits).
        p.on_threats(db.conn, acc.name, now=int(now))
    due = threat_notice_due_in(db.conn, acc, now)
    if due is None or due > 0:
        return False
    items = _threat_notice_items(db.conn, acc.name)
    if not items:
        return False
    keys = [it["message_id"] for it in items]
    if not acc.threat_notice:
        with db.tx():
            db.conn.executemany("UPDATE threat_notices SET sent_at=? WHERE account=? AND message_id=? "
                                "AND sent_at IS NULL", [(int(now), acc.name, k) for k in keys])
        return False
    raw, msgid, _subject = build_threat_notice(acc, items, now=now, folder=_notice_folder_label(acc, fmap))
    inbox = fmap.get("inbox") or acc.inbox
    with _autocommit(db.conn):
        # Recorded BEFORE the APPEND so the scanner already knows it.
        db.conn.execute("INSERT OR REPLACE INTO daily_receipts(account, message_id, day, kind, items, sent_at, "
                        "sent_by) VALUES(?,?,?,?,?,?,?)",
                        (acc.name, msgid, stats_day(now), THREAT_NOTICE_KIND, len(items), int(now), None))
    try:
        with db.tx():
            mailidentity.bind(db.conn, acc.name, msgid, raw)
        client.append(inbox, raw, flags=(), msg_time=datetime.fromtimestamp(now, timezone.utc))
    except _CONN_ERRORS:
        with _autocommit(db.conn):
            db.conn.execute("DELETE FROM daily_receipts WHERE account=? AND message_id=?", (acc.name, msgid))
        raise
    except IMAPClientError as ex:
        with _autocommit(db.conn):
            db.conn.execute("DELETE FROM daily_receipts WHERE account=? AND message_id=?", (acc.name, msgid))
            engine_state_set(db.conn, f"threat_notice_retry:{acc.name}", str(int(now) + THREAT_NOTICE_RETRY_S))
        log.warning("threat notice append failed: %s", _short_err(ex))
        db.log_event("threat_notice_failed", detail=_short_err(ex)[:200])
        return False
    with db.tx():
        db.conn.executemany("UPDATE threat_notices SET sent_at=?, notice_id=? WHERE account=? AND message_id=? "
                            "AND sent_at IS NULL", [(int(now), msgid, acc.name, k) for k in keys])
        db.log_event("threat_notice_sent", msgid, detail=f"items={len(items)}")
        db.bump("threat_notice_sent")
        if engine_state_get(db.conn, f"threat_notice_retry:{acc.name}") is not None:
            engine_state_set(db.conn, f"threat_notice_retry:{acc.name}", None)
    log.info("threat notice appended (%d item(s))", len(items))
    return True


def _threat_admin_alert(db: Db, acc: Account, *, now: float | None = None) -> bool:
    """Admin alert mail (mailer.notify kind 'alert') for virus, dangerous
    attachments and phishing/malware links that were moved away. Only when
    SMTP is set up; each mail is alerted at most once, at most one alert per
    mailbox per 30 min and THREAT_ALERT_MAX_PER_HOUR in total. The text holds
    the type, a masked sender and the time - no subject, link or file."""
    now = int(_now() if now is None else now)
    items = _threat_notice_items(db.conn, acc.name, unsent_only=False, alert=True,
                                 since=now - THREAT_ALERT_MAX_AGE_S)
    if not items:
        return False
    keys = [it["message_id"] for it in items]

    def mark() -> None:
        with db.tx():
            db.conn.executemany("UPDATE threat_notices SET alerted_at=? WHERE account=? AND message_id=? "
                                "AND alerted_at IS NULL", [(now, acc.name, k) for k in keys])

    key = f"threat_alert_at:{acc.name}"
    last = engine_state_get(db.conn, key)
    if last is not None and now - int(float(last)) < THREAT_ALERT_INTERVAL_S:
        return False
    m = _mailer()
    if m is None or not m.is_configured():
        mark()  # no SMTP: nothing to send, and never a flood of old alerts later
        return False
    recent = db.conn.execute("SELECT COUNT(*) FROM events WHERE event='threat_alert_mailed' AND ts>=?",
                             (now - 3600,)).fetchone()[0]
    if int(recent) >= THREAT_ALERT_MAX_PER_HOUR:
        return False
    n = len(items)
    subject = (f"Spamfilter: Konto {acc.name}: farlig mail stoppet" if n == 1 else
               f"Spamfilter: Konto {acc.name}: {n} farlige mails stoppet")
    lines = [f"Spamfilteret har flyttet {'en farlig mail' if n == 1 else f'{n} farlige mails'} "
             f"i postkassen {acc.name} til Spamfilter-mappen:", ""]
    for it in items[:THREAT_NOTICE_MAX_ITEMS]:
        kind = THREAT_LABELS.get(str(it["threat"]), "Farlig mail")
        who = notice_safe_text(m.mask_address(it.get("sender") or ""), 80) if it.get("sender") else "ukendt afsender"
        lines.append(f"- {kind} fra {who} ({_da_datetime(it.get('received_at') or it.get('queued_at'))})")
    if n > THREAT_NOTICE_MAX_ITEMS:
        lines.append(f"- … og {n - THREAT_NOTICE_MAX_ITEMS} mere")
    lines += ["", "Brugeren har fået en advarsel i sin indbakke." if acc.threat_notice else
              "Postkassen får ikke advarsler i indbakken (slået fra).",
              "Mailene er ikke åbnet og ikke slettet. Se dem under Fanget spam i WebUI'en; "
              "kun en administrator kan frigive dem."]
    try:
        res = m.notify("alert", subject, "\n".join(lines))
    except Exception as ex:  # noqa: BLE001
        logging.getLogger(acc.name).warning("threat alert mail failed: %s", type(ex).__name__)
        return False
    code = res.get("code")
    if res.get("ok") or code in ("not_configured", "disabled", "off", "no_recipients"):
        mark()
    if res.get("ok"):
        try:
            engine_state_set(db.conn, key, str(now))
            with db.tx():
                db.log_event("threat_alert_mailed", detail=f"items={n}")
        except sqlite3.Error:
            pass
        return True
    return False


def prune_threat_notices(conn: sqlite3.Connection, account: str, now: float | None = None) -> int:
    now = int(_now() if now is None else now)
    try:
        cur = conn.execute(
            "DELETE FROM threat_notices WHERE account=? AND (created_at<? OR (queued_at IS NULL AND created_at<?))",
            (account, now - THREAT_NOTICE_KEEP_S, now - THREAT_NOTICE_UNQUEUED_KEEP_S))
        return int(cur.rowcount or 0)
    except sqlite3.Error:
        return 0


# ----- E11: health ----------------------------------------------------------

_STALE_STATES = frozenset({"idle", "working", "paused_moves"})


def _silent_for(row: Any, now: int) -> int | None:
    vals = [int(row[k]) for k in ("alive_at", "last_loop_at", "updated_at")
            if k in row.keys() and row[k] is not None]
    return (now - max(vals)) if vals else None


def health_snapshot(conn: sqlite3.Connection | None = None, now: float | None = None) -> dict[str, Any]:
    """E11 monitor view: {"ok", "version", "accounts": {name: state},
    "details": {name: {...}}}. 'accounts' keeps the A8 shape; a thread
    silent for > 10 min while idle/working reads 'stale'. No addresses or
    error texts."""
    own = conn is None
    conn = conn or _open_conn()
    now_i = int(_now() if now is None else now)
    try:
        cur = conn.cursor()
        cur.row_factory = sqlite3.Row
        rows = cur.execute("SELECT * FROM account_status ORDER BY account").fetchall()
        day = stats_day(now_i)
        moved = {r[0]: int(r[1] or 0) for r in conn.execute(
            "SELECT account, n FROM stats_daily WHERE day=? AND metric='moved'", (day,)).fetchall()}
        circuits = {r[0]: (r[1], r[2]) for r in conn.execute(
            "SELECT account, state, reason FROM move_circuit").fetchall()}
        try:
            # 2.7: the local AI's state (a warning only, never part of "ok").
            ai = {k: v for k, v in _ai().health(conn, now_i).items() if k in ("mode", "state", "errors")}
        except Exception:  # noqa: BLE001
            ai = None
    finally:
        if own:
            conn.close()
    accounts: dict[str, str] = {}
    details: dict[str, dict[str, Any]] = {}
    for r in rows:
        name = str(r["account"])
        state = str(r["state"])
        silent = _silent_for(r, now_i)
        stale = state in _STALE_STATES and silent is not None and silent > STALE_AFTER_S
        eff = "stale" if stale else state
        accounts[name] = eff
        if name == "*":
            continue
        circ = circuits.get(name)
        last_scan = r["last_scan_at"]
        keys = r.keys()
        details[name] = {
            "state": eff, "raw_state": state, "stale": stale or state == "stale",
            "silent_s": silent,
            "circuit": "open" if circ and circ[0] == "open" else "closed",
            "circuit_reason": circ[1] if circ and circ[0] == "open" else None,
            "last_scan_at": last_scan,
            "last_scan_age_s": (now_i - int(last_scan)) if last_scan else None,
            "moves_today": moved.get(name, 0),
            "pending_moves": r["pending_moves"],
            "login_state": r["login_state"] if "login_state" in keys else None,
            "retry_at": r["retry_at"] if "retry_at" in keys else None,
            "auth_failed": state == "auth_failed",
            "limited": state == "limited",
        }
    ok = accounts.get("*") != "config_error"
    return {"ok": ok, "version": VERSION, "accounts": accounts, "details": details, "ai": ai}


def mark_stale_accounts(conn: sqlite3.Connection, now: float | None = None,
                        names: Iterable[str] | None = None) -> list[str]:
    """Main-thread watchdog: account rows that claim idle/working but whose
    thread has been silent > STALE_AFTER_S become state 'stale' (the thread
    overwrites it as soon as it runs again)."""
    now_i = int(_now() if now is None else now)
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    rows = cur.execute("SELECT * FROM account_status").fetchall()
    only = set(names) if names is not None else None
    out: list[str] = []
    for r in rows:
        if r["state"] not in _STALE_STATES or (only is not None and r["account"] not in only):
            continue
        silent = _silent_for(r, now_i)
        if silent is None or silent <= STALE_AFTER_S:
            continue
        # Keep the thread's own timestamps: only state/detail change.
        with _autocommit(conn):
            conn.execute("UPDATE account_status SET state='stale', detail=? WHERE account=? AND state=?",
                         (f"Kontoens tråd har ikke meldt sig i {silent // 60} min", r["account"], r["state"]))
            conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                         (r["account"], now_i, None, "thread_stale", f"silent={silent}s"))
        out.append(str(r["account"]))
    return out


# ----- main loop ----------------------------------------------------------


def _prepare_pending_moves(db: Db, acc: Account) -> None:
    """E11: pending moves only make sense in move mode."""
    with db.tx():
        if acc.mode != "move":
            n = db.conn.execute("DELETE FROM pending_move WHERE account=?", (db.account,)).rowcount
            if n:
                db.log_event("pending_moves_cleared", detail=f"{n} (mode={acc.mode})")
            db.conn.execute(
                "UPDATE messages SET our_action='none' WHERE account=? AND our_action='pending_move'",
                (db.account,))


def _on_connected(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
                  state: AccountState) -> None:
    client._sf_account = acc.name
    state.caps = client_capabilities(client)
    setup = setup_folders(client, acc, log, db)
    acc.folder_map = setup.fmap
    state.junk_exists = setup.junk_exists
    state.trash_exists = setup.trash_exists
    state.folder_listing = list(setup.listing)
    state.folder_delimiter = setup.delimiter
    state.contacts_plan = None  # re-planned on this connection's LIST
    if acc.mode == "move":
        # Rows from 1.x carry no folder; they were always inbox moves.
        with db.tx():
            db.conn.execute("UPDATE pending_move SET folder=? WHERE account=? AND folder IS NULL",
                            (setup.fmap["inbox"], db.account))
    folders = folder_status_listing(client, setup.listing, [setup.fmap["inbox"], setup.fmap["junk"]])
    idle = "IDLE" in state.caps
    method = move_method_for(state.caps)
    now = int(_now())
    db.status(state="idle", detail=_mode_detail(acc, state), connected_since=now,
              capabilities=sorted(state.caps), move_method=method, idle_supported=idle,
              folders=folders,
              folder_map={k: setup.fmap[k] for k in ("inbox", "junk", "trash")},
              junk_exists=setup.junk_exists, mode=acc.mode, threshold=acc.threshold)
    db.log_event("conn_ok", detail=f"idle={'yes' if idle else 'no'} move={method}")
    log.info("connected, delimiter=%r, mode=%s, IDLE=%s, move=%s, junk=%s%s",
             setup.delimiter, acc.mode, "yes" if idle else "no", method, setup.fmap["junk"],
             "" if setup.junk_exists else " (missing)")
    if acc.mode == "move" and method == "none":
        log.error("server offers neither MOVE nor UIDPLUS; spam cannot be moved")
    if acc.mode == "move" and setup.junk_exists and method != "none":
        # E5: a move interrupted by the previous disconnect is finished first.
        try:
            repair_interrupted_moves(client, db, log, acc, setup.fmap, state)
        except _CONN_ERRORS:
            raise
        except IMAPClientError as ex:
            log.warning("move repair failed: %s", _short_err(ex))


def _housekeeping(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
                  state: AccountState) -> None:
    if AUTOMATIC_RETENTION_ENABLED and acc.mode != "shadow" and state.trash_exists:
        retention_sweep(client, db, log, acc, acc.folder_map, state)
    if acc.mode == "move" and state.junk_exists and move_method_for(state.caps) != "none":
        repair_interrupted_moves(client, db, log, acc, acc.folder_map, state)
    if acc.mode != "shadow" and state.junk_exists:
        try:
            autolearn_pass(client, db, log, acc, acc.folder_map)
        except _CONN_ERRORS:
            raise
        except IMAPClientError as ex:
            log.warning("autolearn pass failed: %s", _short_err(ex))
    stale_pending_window = max(acc.learn_grace_seconds, acc.move_grace_seconds, 3600) * 24
    with db.tx():
        cleared = db.prune_stale_pending_learn(stale_pending_window)
        ev = db.prune_events()
        ms = db.prune_messages(MESSAGE_RETENTION_S)
        db.prune_scan_retry()
        # 2.3 (B19): rescans that can no longer run (zap turned off).
        db.conn.execute("DELETE FROM rescan_queue WHERE account=? AND queued_at<?",
                        (db.account, int(_now()) - ZAP_MAX_AGE_S))
        db.conn.execute("DELETE FROM av_rescan_queue WHERE account=? AND queued_at<?",
                        (db.account, int(_now()) - AV_RESCAN_MAX_AGE_S))
        try:
            _contacts().prune(db.conn, db.account, int(_now()))
        except Exception as ex:  # noqa: BLE001 - housekeeping only
            log.warning("contacts prune failed: %s", type(ex).__name__)
        prune_threat_notices(db.conn, db.account)
        _ai().prune(db.conn, int(_now()))
    if cleared or ev or ms:
        log.info("pruned events=%d messages=%d stale_pending=%d", ev, ms, cleared)
    # 2.6 (A6): spam piling up in a protected inbox -> alert (weekly at most).
    _campaigns().protected_watch_check(sys.modules[__name__], db.conn, acc, now=int(_now()))
    db.vacuum_if_due()


def _loop_once(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
               state: AccountState) -> None:
    db.prune_rate()
    fmap = acc.folder_map
    if acc.training_folders and acc.mode != "shadow":
        drain_train_spam(client, db, log, acc, fmap, state)
        if SHUTDOWN.is_set():
            return
        drain_train_ham(client, db, log, acc, fmap, state)
        if SHUTDOWN.is_set():
            return
    scan_inbox(client, db, log, acc, fmap, state)
    if SHUTDOWN.is_set():
        return
    ai_apply(db, log, acc, fmap)
    execute_due_moves(client, db, log, acc, fmap, state)
    newsletter_moves(client, db, log, acc, fmap, state)
    if acc.mode == "move":
        maybe_send_threat_notice(client, db, log, acc, fmap)
    if acc.mode != "shadow":
        p = _push()
        if p is not None:
            p.on_review(db.conn, acc, now=int(_now()))   # 2.5.0: new 'Tjek disse' mails (batched per 30 min)
    now = time.monotonic()
    if acc.mode != "shadow" and (state.last_junk_poll == 0.0
                                 or now - state.last_junk_poll >= acc.junk_poll_interval):
        # 0.0 = never polled in this connection: poll at once (B30 - on a
        # freshly booted host time.monotonic() can be below the interval).
        # Also runs with our junk folder missing: the provider's spam
        # folder is still watched and due learns still happen.
        poll_junk(client, db, log, acc, fmap, state)
        state.last_junk_poll = time.monotonic()
    if SHUTDOWN.is_set():
        return
    # 2.3 (B19): due rescans, at most ZAP_MAX_PER_LOOP per loop. Run every
    # loop (not only in the hourly housekeeping) so +45 min is honoured.
    zap_pass(client, db, log, acc, fmap, state)
    if SHUTDOWN.is_set():
        return
    # 2.7 fix: antivirus re-scans of mail ClamAV could not check (+10 min, +1 h, +6 h).
    av_rescan_pass(client, db, log, acc, fmap, state)
    if SHUTDOWN.is_set():
        return
    # 2.6 (A2): copies of spam a user marked in another (or this) mailbox.
    _campaigns().campaign_pass(sys.modules[__name__], client, db, log, acc, fmap, state)
    if SHUTDOWN.is_set():
        return
    contacts_sync(client, db, log, acc, state)
    if SHUTDOWN.is_set():
        return
    if now - state.last_retention >= acc.retention_check_interval or state.last_retention == 0.0:
        _housekeeping(client, db, log, acc, state)
        state.last_retention = time.monotonic()
    if SHUTDOWN.is_set():
        return
    maybe_send_receipt(client, db, log, acc, fmap)
    if SHUTDOWN.is_set():
        return
    maybe_send_weekly(client, db, log, acc, fmap)
    maybe_mail_weekly(db, log)


def ai_apply(db: Db, log: logging.Logger, acc: Account, fmap: dict[str, str]) -> int:
    """2.7: AI verdicts ready for this account ('Til') -> TH_AI_SPAM and,
    over the threshold, a pending move within the normal grace. No IMAP;
    a problem here is logged and the mail stays decided as without AI."""
    try:
        return int(_ai().apply_ready(sys.modules[__name__], db, log, acc, fmap) or 0)
    except Exception as ex:  # noqa: BLE001
        log.warning("ai apply failed: %s", type(ex).__name__)
        return 0


def newsletter_moves(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
                     fmap: dict[str, str], state: AccountState) -> int:
    """2.6 (A4): due newsletter moves (newsletters.execute_moves). Only
    connection errors propagate; anything else is logged - newsletters
    never stop the spam filter."""
    try:
        return int(_newsletters().execute_moves(sys.modules[__name__], client, db, log, acc, fmap, state) or 0)
    except _CONN_ERRORS:
        raise
    except (IMAPClientError, sqlite3.Error) as ex:
        log.warning("newsletter moves failed: %s", _short_err(ex))
        return 0


def _moves_today(db: Db) -> int:
    row = db.conn.execute("SELECT n FROM stats_daily WHERE account=? AND day=? AND metric='moved'",
                          (db.account, stats_day())).fetchone()
    return int(row[0]) if row else 0


def _status_after_loop(db: Db, acc: Account, state: AccountState) -> None:
    now = int(_now())
    common = dict(last_loop_at=now, alive_at=now, bookmark_lag=state.bookmark_lag,
                  pending_moves=db.count_pending_moves(), junk_exists=state.junk_exists,
                  moves_today=_moves_today(db))
    if state.rspamd_backoff_until > time.monotonic():
        db.status(**common)
        return
    circ = circuit_row(db.conn, db.account)
    if acc.mode == "move" and circ is not None and circ["state"] == "open":
        db.status(state="paused_moves", detail=_paused_detail(circ["reason"]), error_count=0,
                  move_state="paused", move_state_reason=circ["reason"],
                  move_state_at=circ["opened_at"], **common)
        return
    db.status(state="idle", detail=_mode_detail(acc, state), error_count=0,
              move_state="active" if acc.mode == "move" else None, **common)


def _next_wake_in(db: Db, acc: Account, state: AccountState) -> float:
    """Seconds until timed work is due (junk poll, pending moves - with
    their stored due time and the update hold -, scan retries, rspamd
    backoff, housekeeping, daily receipt), capped at idle_timeout."""
    now_w, now_m = _now(), time.monotonic()
    cands = [float(acc.idle_timeout),
             state.last_retention + acc.retention_check_interval - now_m]
    if acc.mode != "shadow":
        cands.append(0.0 if state.last_junk_poll == 0.0
                     else state.last_junk_poll + acc.junk_poll_interval - now_m)
    if (acc.mode == "move" and db.rate_count("move", 3600) < acc.max_moves_per_hour
            and not circuit_open(db.conn, db.account)):
        hold = move_hold_until(db.conn)
        row = db.conn.execute(
            f"""
            SELECT MIN(CASE
                WHEN ? > ? AND NOT (score IS NOT NULL AND score >= COALESCE(threshold, ?) + ?)
                     AND NOT {_PM_THREAT_SQL}
                THEN MAX(COALESCE(due_at, flag_at + ?), ?)
                ELSE COALESCE(due_at, flag_at + ?) END)
              FROM pending_move WHERE account=?
            """,
            (hold, int(now_w), acc.threshold, UPDATE_HOLD_MARGIN, acc.move_grace_seconds, hold,
             acc.move_grace_seconds, db.account)).fetchone()
        if row and row[0] is not None:
            cands.append(row[0] - now_w)
    if state.rspamd_backoff_until > now_m:
        cands.append(state.rspamd_backoff_until - now_m)
    if (getattr(acc, "zap", False) and state.rspamd_backoff_until <= now_m
            and not db.in_safe_mode("all")):
        # 2.3 (B19): the next due rescan - only while zap_pass can run (it
        # does nothing in safe mode or during an rspamd backoff), and an
        # overdue row waits ZAP_OVERDUE_WAIT_S instead of pinning the wait
        # to MIN_LOOP_WAIT_S (no IMAP hammering if a row cannot be handled).
        try:
            row = db.conn.execute("SELECT MIN(due_at) FROM rescan_queue WHERE account=?",
                                  (db.account,)).fetchone()
        except sqlite3.Error:
            row = None
        if row and row[0] is not None:
            due = row[0] - now_w
            cands.append(due if due > 0 else float(ZAP_OVERDUE_WAIT_S))
    if state.rspamd_backoff_until <= now_m and not db.in_safe_mode("all"):
        # 2.7 fix: the next antivirus re-scan (whatever zap says).
        try:
            row = db.conn.execute("SELECT MIN(due_at) FROM av_rescan_queue WHERE account=?",
                                  (db.account,)).fetchone()
        except sqlite3.Error:
            row = None
        if row and row[0] is not None:
            due = row[0] - now_w
            cands.append(due if due > 0 else float(ZAP_OVERDUE_WAIT_S))
    if getattr(acc, "known_contacts", False):
        # 2.3: the first contact sync continues after one IDLE slice; later
        # the Sent folders get a STATUS every 15 min.
        if state.contacts_busy:
            cands.append(0.0)
        elif state.contacts_next_status:
            cands.append(state.contacts_next_status - now_m)
    for r in db.conn.execute(
        "SELECT first_fail_at, attempts FROM scan_retry WHERE account=? AND attempts<?",
        (db.account, SCAN_RETRY_MAX_ATTEMPTS),
    ):
        # A retry that is already due is picked up by the very next loop;
        # an overdue row (scan_inbox prunes orphans) must not pin the wait
        # to MIN_LOOP_WAIT_S.
        due = r["first_fail_at"] + SCAN_RETRY_BASE_S * (2 ** int(r["attempts"]) - 1) - now_w
        if due > 0:
            cands.append(due)
    if acc.mode == "move":
        # Straks-advarsel: a queued threat notice waits for its 30 min slot.
        due = threat_notice_due_in(db.conn, acc, now_w)
        if due is not None:
            cands.append(due)
    if acc.mode != "shadow":
        # 2.5.0: Tjek-disse mails held back by the 30 min push batch.
        p = _push()
        due = p.review_due_in(db.conn, acc, now=int(now_w)) if p is not None else None
        if due is not None:
            cands.append(due)
    if acc.daily_report and acc.mode == "move":
        nxt = _next_receipt_time(acc, now_w)
        if nxt is not None:
            cands.append(nxt - now_w)
    return max(float(MIN_LOOP_WAIT_S), min(cands))


def request_wake(conn: sqlite3.Connection, account: str) -> None:
    """Ask an account thread to end its IDLE wait now (within one 5 s
    slice), e.g. after resume_moves. Cross-thread via SQLite."""
    try:
        engine_state_set(conn, f"wake:{account}", uuid.uuid4().hex)
    except sqlite3.Error:
        pass


def _wake_token(db: Db) -> str | None:
    try:
        return engine_state_get(db.conn, f"wake:{db.account}")
    except sqlite3.Error:
        return None


def _touch_alive(db: Db) -> None:
    try:
        db.status(alive_at=int(_now()))
    except sqlite3.Error:
        pass


def _idle_activity(responses: Iterable[Any]) -> bool:
    """Anything but untagged OK keepalives ("* OK Still here") is activity."""
    for r in responses or ():
        if isinstance(r, tuple) and r and r[0] in (b"OK", "OK"):
            continue
        return True
    return False


def _wait_for_activity(client: IMAPClient, db: Db, log: logging.Logger, acc: Account,
                       state: AccountState) -> None:
    """IDLE on the inbox until new activity or timed work is due. Waits in
    <= IDLE_SLICE_S slices so shutdown is observed within ~5 s."""
    wait = _next_wake_in(db, acc, state)
    wake0 = _wake_token(db)
    if "IDLE" not in state.caps:
        # Wall clock (_now) so tests with a fake clock terminate; at most
        # ceil(wait / ALIVE_TOUCH_S) slices.
        end = _now() + min(wait, float(acc.poll_interval))
        for _ in range(int(math.ceil(min(wait, float(acc.poll_interval)) / ALIVE_TOUCH_S)) + 1):
            left = end - _now()
            if left <= 0 or SHUTDOWN.is_set():
                break
            if _sleep(min(left, float(ALIVE_TOUCH_S))):
                break
            _touch_alive(db)
            if _wake_token(db) != wake0:
                break
        return
    client.select_folder(acc.folder_map["inbox"], readonly=acc.mode == "shadow")
    client.idle()
    idle_failed = False
    try:
        deadline = time.monotonic() + wait
        last_touch = time.monotonic()
        while not SHUTDOWN.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if time.monotonic() - last_touch >= ALIVE_TOUCH_S:
                # E11: proves the thread is alive while it waits in IDLE.
                last_touch = time.monotonic()
                _touch_alive(db)
            if _idle_activity(client.idle_check(timeout=min(float(IDLE_SLICE_S), remaining))):
                break
            if _wake_token(db) != wake0:
                break   # e.g. an admin resumed moving: run the waiting moves now
    finally:
        try:
            client.idle_done()
        except (IMAPClientError, OSError) as ex:
            # The server probably dropped the connection silently: force a
            # reconnect instead of continuing on a half-dead socket.
            log.warning("idle_done failed: %s; forcing reconnect", type(ex).__name__)
            idle_failed = True
    if idle_failed:
        raise IMAPClientAbortError("idle_done failed")


def _wait_auth_retry(db: Db, log: logging.Logger, acc: Account) -> None:
    """After repeated login failures: retry only every 30 min, or as soon as
    the password file changes."""
    since = _now()
    mtime0 = _secret_mtime(acc)
    log.error("login failed %d times; next attempt in %d min or when the password changes",
              LOGIN_FAILURES_BEFORE_AUTH_FAILED, AUTH_FAILED_RETRY_S // 60)
    while not SHUTDOWN.is_set():
        if _sleep(AUTH_FAILED_POLL_S):
            return
        if _now() - since >= AUTH_FAILED_RETRY_S:
            return
        if _secret_mtime(acc) != mtime0:
            log.info("password file changed; retrying login now")
            return


def account_loop(acc: Account) -> None:
    """Per-account thread entry point. Owns the thread's Db handle and closes
    it even if the worker raises."""
    db = Db(acc.name)
    try:
        _run_account(acc, db)
    finally:
        try:
            db.status(state="stopped", detail="Filteret er stoppet")
        except sqlite3.Error:
            pass
        db.close()
        logging.getLogger(acc.name).info("thread exiting")


_AUTH_FAIL_RE = re.compile(
    r"AUTHENTICATIONFAILED|AUTHORIZATIONFAILED|authentication failed|invalid credentials"
    r"|login failed|incorrect password|bad password", re.I)
_LIMIT_RE = re.compile(
    r"\[(?:LIMIT|UNAVAILABLE|INUSE)\]|too many (?:simultaneous |concurrent |parallel )?connections"
    r"|maximum number of connections|connection limit|try again later|temporar(?:y|ily)"
    r"|server busy|rate limit", re.I)
_RESP_CODE_RE = re.compile(r"\[([A-Z][A-Z-]*)\]", re.I)
_AUTH_CODES = frozenset({"AUTHENTICATIONFAILED", "AUTHORIZATIONFAILED", "EXPIRED"})
_LIMIT_CODES = frozenset({"LIMIT", "UNAVAILABLE", "INUSE"})


def classify_login_error(ex: BaseException) -> str:
    """E4: 'auth' (wrong credentials - counts towards auth_failed), 'limit'
    (the provider throttles/is unavailable/timed out - never counts), or
    'other' (an ordinary connection problem)."""
    text = str(ex) or ""
    if isinstance(ex, (TimeoutError, ssl.SSLError)) and not isinstance(ex, LoginError):
        return "limit" if isinstance(ex, TimeoutError) else "other"
    # An RFC 5530 response code is the server's own classification and wins
    # over free text ("NO [UNAVAILABLE] Login failed: backend down" is a
    # provider problem, not a wrong password).
    code = _RESP_CODE_RE.search(text)
    if code:
        name = code.group(1).upper()
        if name in _AUTH_CODES:
            return "auth"
        if name in _LIMIT_CODES:
            return "limit"
    if _AUTH_FAIL_RE.search(text):
        return "auth"
    if _LIMIT_RE.search(text):
        return "limit"
    if isinstance(ex, LoginError):
        return "auth"
    return "other"


def _limit_detail(seconds: float) -> str:
    mins = max(1, int(math.ceil(seconds / 60.0)))
    return f"Udbyderen begrænser forbindelser – prøver igen om {mins} min"


def _run_account(acc: Account, db: Db) -> None:
    log = logging.getLogger(acc.name)
    threading.current_thread().name = acc.name
    state = AccountState()
    backoff = RECONNECT_MIN_BACKOFF
    limit_backoff = 0.0
    login_failures = 0
    _prepare_pending_moves(db, acc)
    try:
        fix_preexisting_junk_counts(db, log)
    except Exception as ex:  # noqa: BLE001 - a statistics fix never stops the mailbox
        log.warning("2.12 statistics fix failed: %s", _short_err(ex))
    db.status(state="starting", detail="Starter…", mode=acc.mode, threshold=acc.threshold)

    while not SHUTDOWN.is_set():
        if login_failures >= LOGIN_FAILURES_BEFORE_AUTH_FAILED:
            _wait_auth_retry(db, log, acc)
            if SHUTDOWN.is_set():
                break
        client: IMAPClient | None = None
        secret: str | None = None
        limited = False
        connecting = False
        try:
            db.status(state="connecting", detail="Forbinder til mailserveren…")
            try:
                secret = read_secret(acc)
            except ValueError as ex:
                log.error("cannot read password: %s", ex)
                db.status_error(category="config", text=str(ex),
                                detail="Adgangskoden kunne ikke læses – tjek kontoens opsætning")
                raise _SkipCycle() from None
            log.info("connecting to %s:%d as %s", acc.imap_host, acc.imap_port, acc.user)
            connecting = True
            client = connect(acc, secret)
            connecting = False
            login_failures = 0
            limit_backoff = 0.0
            db.status(login_state="ok", retry_at=None)
            alert_clear(db.conn, f"auth:{acc.name}")
            _on_connected(client, db, log, acc, state)
            while not SHUTDOWN.is_set():
                _loop_once(client, db, log, acc, state)
                # Only a complete iteration proves the connection healthy.
                backoff = RECONNECT_MIN_BACKOFF
                _status_after_loop(db, acc, state)
                if SHUTDOWN.is_set():
                    break
                _wait_for_activity(client, db, log, acc, state)
        except _SkipCycle:
            pass
        except (LoginError, IMAPClientError, OSError) as ex:
            text = _short_err(ex, secret)
            kind = classify_login_error(ex) if (connecting or isinstance(ex, LoginError)) else "other"
            if kind == "limit":
                # E4: provider throttling/unavailable - not a password problem.
                limited = True
                limit_backoff = min(max(limit_backoff * 2, LIMIT_BACKOFF_MIN_S), LIMIT_BACKOFF_MAX_S)
                log.warning("provider limits connections: %s (retry in %ds)", text, limit_backoff)
                db.log_event("login_limited", detail=text)
                db.status_error(category="limit", text=text, state="limited",
                                detail=_limit_detail(limit_backoff))
                db.status(login_state="limited", retry_at=int(_now() + limit_backoff))
            elif kind == "auth":
                login_failures += 1
                log.warning("login failed (%d in a row): %s", login_failures, text)
                db.log_event("login_failed", detail=text)
                if login_failures >= LOGIN_FAILURES_BEFORE_AUTH_FAILED:
                    db.status_error(category="auth", text=text, state="auth_failed",
                                    detail="Login afvist – tjek adgangskoden. Nyt forsøg om 30 min "
                                           "eller når adgangskoden ændres")
                    db.status(login_state="auth_failed", retry_at=int(_now() + AUTH_FAILED_RETRY_S))
                    _alert_auth(db, acc)
                else:
                    db.status_error(category="auth", text=text,
                                    detail=f"Login afvist – prøver igen om {backoff} s")
            else:
                log.warning("connection error: %s (backoff %ds)", text, backoff)
                db.log_event("conn_error", detail=text)
                db.status_error(category="imap", text=text,
                                detail=f"Forbindelsesfejl – prøver igen om {backoff} s")
        except Exception as ex:  # noqa: BLE001 - last-resort guard
            # Never log.exception(): a traceback can echo LOGIN arguments.
            text = _short_err(ex, secret)
            log.error("unhandled error in account loop: %s", text)
            db.log_event("unhandled_error", detail=text)
            db.status_error(category="internal", text=text,
                            detail=f"Intern fejl – prøver igen om {backoff} s")
        finally:
            if client is not None:
                _close_quietly(client)
        if SHUTDOWN.is_set():
            break
        if limited:
            if _sleep(limit_backoff):
                break
            continue
        if login_failures >= LOGIN_FAILURES_BEFORE_AUTH_FAILED:
            continue  # the 30-minute auth wait replaces the backoff
        if _sleep(backoff):
            break
        backoff = min(backoff * 2, RECONNECT_MAX_BACKOFF)


class _SkipCycle(Exception):
    """Internal: abandon this connect attempt and back off."""


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def configure_logging() -> None:
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s [%(threadName)s] %(levelname)s %(message)s",
        stream=sys.stdout,
    )


def install_signal_handlers() -> None:
    if threading.current_thread() is not threading.main_thread():
        return  # signal.signal only works in the main thread (tests)

    def _handler(signum: int, _frame: Any) -> None:
        logging.getLogger("main").info("received signal %d, shutting down", signum)
        SHUTDOWN.set()

    signal.signal(signal.SIGTERM, _handler)
    signal.signal(signal.SIGINT, _handler)


def _open_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def _start_dashboard(log: logging.Logger) -> None:
    # The WebUI runs in-process (Flask + waitress on :8080) ALWAYS: /healthz
    # is part of the container healthcheck and the deploy gate, so it must
    # answer even before a dashboard user exists (the login page then
    # explains how to add one). It keeps running through config errors so
    # the owner can fix them.
    try:
        import dashboard as _dashboard

        _dashboard.start()
    except Exception as ex:  # noqa: BLE001
        log.error("failed to start dashboard: %s", _short_err(ex))


def _start_trainer(log: logging.Logger) -> None:
    try:
        import trainer

        trainer.start(engine=sys.modules[__name__])
    except Exception as ex:  # noqa: BLE001
        log.error("failed to start trainer: %s", _short_err(ex))


def _start_backup(log: logging.Logger) -> None:
    """2.6 (B3): the nightly encrypted backup to /backup (backup.py)."""
    try:
        import backup  # noqa: PLC0415

        if backup.start(sys.modules[__name__]):
            log.info("encrypted backup: nightly from %02d:%02d to %s", *backup.RUN_AT, backup.BACKUP_DIR)
    except Exception as ex:  # noqa: BLE001 - backups never block the filter
        log.error("failed to start the backup scheduler: %s", _short_err(ex))


def _load_configs_degraded(log: logging.Logger) -> list[Account] | None:
    """E10: keep retrying a broken config every CONFIG_RECHECK_S while the
    dashboard stays up; status row '*' = config_error. None on shutdown."""
    last_msg: str | None = None
    while not SHUTDOWN.is_set():
        try:
            configs = load_account_configs(CONFIG_PATH)
        except ValueError as ex:
            msg = str(ex)[:300]
            if msg != last_msg:
                log.error("config error: %s (dashboard keeps running; re-checking every %ds)",
                          msg, CONFIG_RECHECK_S)
                last_msg = msg
            try:
                conn = _open_conn()
                try:
                    update_account_status(conn, "*", state="config_error",
                                          detail=f"Konfigurationsfejl: {msg}",
                                          last_error=f"config: {msg}"[:240],
                                          last_error_at=int(_now()))
                finally:
                    conn.close()
            except sqlite3.Error as dbex:
                log.warning("cannot record config error: %s", dbex)
            heartbeat()
            deadline = time.monotonic() + CONFIG_RECHECK_S
            while not SHUTDOWN.is_set() and time.monotonic() < deadline:
                reload_flag = _state_file("reload_requested")
                if reload_flag.exists():
                    reload_flag.unlink(missing_ok=True)
                    break
                _sleep(min(1.0, max(0.0, deadline - time.monotonic())))
            continue
        if last_msg is not None:
            log.info("config is valid again")
        return configs
    return None


def _publish_account_rows(configs: list[Account]) -> None:
    conn = _open_conn()
    try:
        names = [a.name for a in configs]
        with _autocommit(conn):
            if names:
                conn.execute(
                    f"DELETE FROM account_status WHERE account NOT IN ({','.join('?' * len(names))})",
                    names)
            else:
                conn.execute("DELETE FROM account_status")
        for acc in configs:
            if not acc.enabled:
                update_account_status(conn, acc.name, state="paused", detail="Sat på pause",
                                      mode=acc.mode, threshold=acc.threshold,
                                      connected_since=None, error_count=0)
    finally:
        conn.close()


def _mail_startup(log: logging.Logger) -> None:
    """2.3 (B29): before the old heartbeat is removed, mail 'Spamfilteret har
    været stoppet fra ... til ...' when it is more than 10 min old, and start
    the mail worker (the dashboard starts it too; idempotent)."""
    m = _mailer()
    if m is None:
        return
    try:
        m.ensure_schema()
        if m.check_heartbeat_gap(_state_file("heartbeat")):
            log.info("downtime notice queued")
        m.ensure_worker()
    except Exception as ex:  # noqa: BLE001 - mail is optional
        log.warning("mail startup failed: %s", type(ex).__name__)


def _push_startup(log: logging.Logger) -> None:
    """2.5.0: create the push tables, push 'Filteret kører igen' after a
    stop of more than 10 min (call BEFORE the old heartbeat is removed) and
    start the push sender thread."""
    p = _push()
    if p is None:
        return
    try:
        p.ensure_schema()
        if p.check_heartbeat_gap(_state_file("heartbeat")):
            log.info("downtime push queued")
        p.ensure_worker()
    except Exception as ex:  # noqa: BLE001 - push is optional
        log.warning("push startup failed: %s", type(ex).__name__)


def main() -> int:
    configure_logging()
    log = logging.getLogger("main")
    install_signal_handlers()
    init_db()
    _mail_startup(log)
    _push_startup(log)
    _start_boot()
    heartbeat()
    log.info("spamfilter %s starting (boot %s)", VERSION, BOOT_ID[:8])
    try:
        conn0 = _open_conn()
        try:
            started = record_version_start(conn0)
        finally:
            conn0.close()
        if _now() < started + UPDATE_HOLD_S:
            log.info("update hold: until %s only clear spam (threshold + %.0f) is moved",
                     time.strftime("%H:%M", time.localtime(started + UPDATE_HOLD_S)), UPDATE_HOLD_MARGIN)
    except sqlite3.Error as ex:
        log.warning("cannot record version start: %s", ex)
    if not _rspamd_password():
        log.error("RSPAMD_PASSWORD is unset; Bayes learning will fail until it is configured")
    _start_dashboard(log)
    _start_trainer(log)
    _start_backup(log)

    configs = _load_configs_degraded(log)
    if configs is None:
        log.info("shutdown before the config could be loaded")
        return 0
    _publish_account_rows(configs)
    set_lookalike_mailboxes(configs)
    _start_lookalike_watch(log, configs)
    try:
        _ai().start_worker(sys.modules[__name__])  # 2.7: local AI second opinion (one thread)
    except Exception as ex:  # noqa: BLE001
        log.error("failed to start the ai worker: %s", _short_err(ex))
    _start_mailcheck(log, configs)
    accounts = [a for a in configs if a.enabled]
    paused = [a.name for a in configs if not a.enabled]
    log.info("loaded %d account(s): %s", len(accounts), ", ".join(a.name for a in accounts) or "-")
    if paused:
        log.info("paused account(s): %s", ", ".join(paused))
    heartbeat()

    threads: dict[str, threading.Thread] = {}
    for acc in accounts:
        # Daemon threads: a thread stuck in a socket read must not keep the
        # process alive past the shutdown join below.
        t = threading.Thread(target=account_loop, args=(acc,), name=acc.name, daemon=True)
        t.start()
        threads[acc.name] = t
    accounts_by_name = {a.name: a for a in accounts}
    # Per-account exponential backoff so a thread that crashes immediately
    # after restart does not spin the main loop.
    restart_backoff: dict[str, float] = {a.name: 0.0 for a in accounts}
    last_restart: dict[str, float] = {a.name: 0.0 for a in accounts}
    backoff_reset_after = 600.0
    last_watchdog = time.monotonic()
    while not SHUTDOWN.is_set():
        heartbeat()
        if time.monotonic() - last_watchdog >= ALIVE_TOUCH_S:
            last_watchdog = time.monotonic()
            try:
                wconn = _open_conn()
                try:
                    stale = mark_stale_accounts(wconn, names=list(threads))
                finally:
                    wconn.close()
                for name in stale:
                    log.error("account thread %s is silent; marked stale", name)
            except sqlite3.Error as ex:
                log.warning("watchdog failed: %s", ex)
        reload_flag = _state_file("reload_requested")
        if reload_flag.exists():
            reload_flag.unlink(missing_ok=True)
            log.info("configuration reload requested; restarting cleanly")
            SHUTDOWN.set()
            break
        now = time.monotonic()
        for name, t in list(threads.items()):
            if t.is_alive():
                if (restart_backoff[name] > 0 and last_restart[name]
                        and (now - last_restart[name]) > backoff_reset_after):
                    restart_backoff[name] = 0.0
                continue
            if max(0.0, last_restart[name] + restart_backoff[name] - now) > 0:
                continue
            log.error("account thread %s died; restarting (backoff was %.0fs)",
                      name, restart_backoff[name])
            nt = threading.Thread(target=account_loop, args=(accounts_by_name[name],),
                                  name=name, daemon=True)
            nt.start()
            threads[name] = nt
            last_restart[name] = now
            restart_backoff[name] = min(max(restart_backoff[name] * 2, 5.0), 300.0)
        SHUTDOWN.wait(timeout=5)

    # Account threads observe SHUTDOWN within one IDLE slice (5 s); give
    # them SHUTDOWN_JOIN_S in total, then exit regardless (daemon threads).
    deadline = time.monotonic() + SHUTDOWN_JOIN_S
    for t in threads.values():
        t.join(timeout=max(0.0, deadline - time.monotonic()))
    alive = [n for n, t in threads.items() if t.is_alive()]
    if alive:
        log.warning("threads still busy at exit: %s", ", ".join(alive))
    log.info("all threads exited")
    return 0


if __name__ == "__main__":
    sys.exit(main())
