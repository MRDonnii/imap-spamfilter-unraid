"""Operations the WebUI calls: mail actions, connection tests, folders,
training jobs, Bayes/rspamd/host status and reload requests.

Every public function takes `engine=None`; the default lazily imports the
running engine (`filter`). Tests inject a fake engine module instead.

2.1 additions (see each docstring): find_mail / move_found_to_inbox
(find a lost mail, read-only search + exact single move back), undo_moves /
preview_undo / undo_job / list_undo_jobs / cancel_undo_job /
resume_undo_job (bulk undo of filter moves as a resumable job in the
additive undo_jobs/undo_items tables), threshold_suggestion, digest_data
(daily digest for deploy/host-monitor.sh) and folder_sizes (display only).

Rules that hold for everything here:
  * Never return or log raw exception text: IMAP errors can echo the LOGIN
    command (password) and the UI shows these strings. Errors are mapped
    to short codes + fixed Danish texts; logs carry the exception type only.
  * IMAP sessions are short-lived (one per call) and read-only unless the
    action itself is a move.
"""

from __future__ import annotations

import contextlib
import imaplib
import json
import logging
import os
import re
import socket
import sqlite3
import mailidentity
import ssl
import time
from contextlib import closing
from pathlib import Path
from typing import Any, Iterable

import requests
from imapclient.exceptions import IMAPClientError, LoginError

import siteconfig

log = logging.getLogger("services")

MAIL_ACTIONS = ("release", "mark_spam", "learn_ham", "learn_spam")
MAX_MAIL_ACTION_IDS = 200
TRAIN_KINDS = ("spam", "ham")
PROVIDER_FILTERS = ("any", "provider_spam", "provider_clean")
MAX_TRAIN_MESSAGES = 5000
MAX_MIN_AGE_DAYS = 3650
HOST_STATUS_STALE_S = 15 * 60
HTTP_TIMEOUT_S = 3

JUNK_KEYWORD = "$Junk"
NOTJUNK_KEYWORD = "$NotJunk"

_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_MSGID_RE = re.compile(r"^[\x21-\x7e]{1,500}$")

# Junk/trash names seen at Danish providers and common clients, used when
# the server advertises no SPECIAL-USE flags (Gigahost).
_JUNK_NAMES = ("Junk", "Spam", "INBOX.Junk", "INBOX.Spam", "Junk E-Mail",
               "Uønsket e-mail", "Bulk Mail")
# The provider's own spam folder: the engine's fallback names first (it
# records mail found there as provider_junk), then the suggestion list.
_PROVIDER_JUNK_NAMES = ("Junk", "Spam", "Junk E-mail", "Junk Email", "Uønsket post",
                        "Uønsket e-mail", "INBOX.Junk", "INBOX.Spam", "Bulk Mail")
_TRASH_NAMES = ("Trash", "INBOX.Trash", "Deleted Items", "Deleted Messages",
                "Papirkurv", "Slettet post")

# Mail domain -> IMAP server for the add-account wizard: the local site
# config's imap_presets (config/site.yml), empty on a fresh install.
KNOWN_PROVIDERS: dict[str, dict[str, Any]] = {
    d: dict(v) for d, v in (siteconfig.get("imap_presets") or {}).items()}

_CONNECT_TEXT = {
    "ok": "Forbindelsen virker.",
    "auth": "Brugernavn eller adgangskode blev afvist af mailserveren.",
    "tls": "Der kunne ikke oprettes en sikker forbindelse (TLS/certifikat).",
    "dns": "Mailserveren kunne ikke findes. Tjek servernavnet.",
    "network": "Mailserveren kunne ikke nås. Tjek server og port.",
    "timeout": "Mailserveren svarede ikke i tide.",
    "other": "Forbindelsen mislykkedes af en ukendt årsag.",
}

_LEARN_NOTE = {
    "learned": "",
    "newsletter": " – ikke lært som spam, fordi det er et almindeligt nyhedsbrev. Kommer der flere, du ikke vil "
                  "have, så afmeld dem i mailen.",
    "already": " (var allerede lært)",
    "declined": " – filteret genkendte den allerede, så der var intet nyt at lære.",
    "rate_limited": " – læring udskudt: grænsen pr. time er nået.",
    "error": " – læring fejlede: rspamd svarede ikke.",
    "too_large": " – for stor til at blive lært (over 5 MB).",
}


def _learn_note(outcome: str, kind: str) -> str:
    """Danish suffix for a learn outcome. 'declined' is rspamd's learn
    condition 'already in class' (Bayes is > 95 % sure) in practice."""
    if outcome == "declined":
        what = "spam" if kind == "spam" else "legitim post"
        return f" – filteret genkender den allerede som {what}, så der var intet nyt at lære."
    return _LEARN_NOTE.get(outcome, "")


class ServiceError(Exception):
    """A failure with a safe Danish text for the UI (`text`) and a code."""

    def __init__(self, code: str, text: str) -> None:
        super().__init__(text)
        self.code = code
        self.text = text


# ---------------------------------------------------------------------------
# 2.3 (B16): threat class texts (mirror filter.THREAT_LABELS / threat_text,
# test-enforced equal; kept here so services work with any engine module)
# ---------------------------------------------------------------------------

THREAT_LABELS = {"virus": "Virus", "phish": "Phishing-link", "malware_url": "Malware-link",
                 "attachment": "Farlig vedhæftning", "impersonation": "Forfalsket afsender",
                 "lookalike": "Efterligner jeres domæne"}
THREAT_ADMIN_TEXT = "Kontakt administrator, hvis mailen skal frigives."
ZAP_LABEL = "Fanget ved genscanning"
ZAP_LATER_TEXT = "Flyttet efterfølgende"
CAMPAIGN_WEEKLY_TEXT = "Samme spam på flere postkasser"  # 2.6 (A2)
TRIALS_WEEKLY_TEXT = "Nye beskyttelser"


def threat_text(threat: Any, detail: Any = None) -> str:
    """'Virus: <signatur>', 'Phishing-link', 'Malware-link',
    'Farlig vedhæftning: faktura.pdf.exe' ('' without a threat)."""
    if not threat:
        return ""
    label = THREAT_LABELS.get(str(threat), "Farlig mail")
    detail = str(detail or "").strip()
    if threat in ("virus", "attachment", "lookalike") and detail:
        return f"{label}: {detail}"[:200]
    return label


def threat_confirm_text(threat: Any, detail: Any = None) -> str:
    """What an administrator confirms before a release (B16)."""
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


def _threat_of(conn: sqlite3.Connection, account: str, mid: str) -> tuple[str | None, str | None]:
    """(threat, detail) of a stored message; (None, None) without one or on
    a database from before 2.3."""
    try:
        row = conn.execute("SELECT threat, threat_detail FROM messages WHERE account=? AND message_id=?",
                           (account, mid)).fetchone()
        if (row is None or not row[0]) and mid.startswith(mailidentity.PREFIX):
            identity = mailidentity.binding(conn, account, mid)
            if identity and identity[0] and identity[0] != mid:
                scanned = conn.execute('SELECT scanned_at FROM messages WHERE account=? AND message_id=?',
                                       (account, mid)).fetchone()
                original = mailidentity.binding(conn, account, identity[0])
                if original is None or scanned is None or scanned[0] is None:
                    # A new alias must not discard an old virus restriction
                    # before this concrete payload has had its own scan.
                    legacy = conn.execute('SELECT threat, threat_detail FROM messages '
                                          'WHERE account=? AND message_id=?', (account, identity[0])).fetchone()
                    if legacy and legacy[0]:
                        row = legacy
    except sqlite3.Error:
        return None, None
    if row is None or not row[0]:
        return None, None
    return str(row[0]), (str(row[1]) if row[1] else None)


def _threat_fields(threat: Any, detail: Any) -> dict[str, Any]:
    return {"threat": threat or None, "threat_text": threat_text(threat, detail)}


def threat_gate(threat: str | None, detail: str | None, *, is_admin: bool,
                confirm_threat: bool) -> dict[str, Any] | None:
    """B16 release rule for every path that puts mail back / learns ham:
    None = allowed; else {code, text, threat, threat_text, confirm_text}.
    Non-admins: code 'threat_admin' ('Kontakt administrator'); admins
    without explicit confirmation: 'threat_confirm'."""
    if not threat:
        return None
    base = {"threat": threat, "threat_text": threat_text(threat, detail),
            "confirm_text": threat_confirm_text(threat, detail)}
    if not is_admin:
        return {**base, "code": "threat_admin",
                "text": f"{base['threat_text']}: mailen er markeret som farlig. {THREAT_ADMIN_TEXT}"}
    if not confirm_threat:
        return {**base, "code": "threat_confirm",
                "text": f"{base['confirm_text']} Bekræft, at den alligevel skal frigives."}
    return None


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _eng(engine: Any = None) -> Any:
    if engine is not None:
        return engine
    import filter as engine_module  # lazy: the engine imports us at runtime

    return engine_module


def _open_db(eng: Any) -> sqlite3.Connection:
    conn = sqlite3.connect(str(eng.DB_PATH), timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def _open_db_ro(eng: Any) -> sqlite3.Connection:
    """Read-only connection (SQLite refuses every write on it)."""
    uri = Path(str(eng.DB_PATH)).absolute().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def _find_account(eng: Any, name: str) -> Any | None:
    for acc in eng.load_account_configs(eng.CONFIG_PATH):
        if acc.name == name:
            return acc
    return None


def _to_str(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _caps(client: Any) -> list[str]:
    try:
        raw = client.capabilities() or ()
    except Exception:
        return []
    return sorted({_to_str(c).upper() for c in raw})


def _caps_for_engine(caps: Iterable[str]) -> frozenset:
    # imap_move may test either str or bytes membership; offer both.
    s = frozenset(caps)
    return s | frozenset(c.encode("ascii", "replace") for c in s)


def _move_method(eng: Any, caps: list[str]) -> str:
    fn = getattr(eng, "move_method_for", None)
    if fn is not None:
        try:
            return str(fn(_caps_for_engine(caps)))
        except Exception:
            pass
    if "MOVE" in caps:
        return "MOVE"
    if "UIDPLUS" in caps:
        return "UIDPLUS"
    return "none"


def normalize_message_id(value: Any) -> str | None:
    """'<a@b>' / 'a@b' -> 'a@b'; None if unsafe for IMAP SEARCH (CR/LF,
    whitespace, quotes, backslash, non-ASCII) or too long."""
    if not isinstance(value, str):
        return None
    s = value.strip()
    if s.startswith("<") and s.endswith(">"):
        s = s[1:-1].strip()
    if not _MSGID_RE.match(s) or any(c in s for c in '"\\<>'):
        return None
    return s


def _res(mid: str, ok: bool, code: str, text: str) -> dict[str, Any]:
    return {"message_id": mid, "ok": ok, "code": code, "text": text}


# ---------------------------------------------------------------------------
# Folder discovery
# ---------------------------------------------------------------------------


def _list_folders(client: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for flags, delim, name in client.list_folders():
        flag_list = [_to_str(f) for f in (flags or ())]
        if any(f.lower() in ("\\noselect", "\\nonexistent") for f in flag_list):
            continue
        out.append({
            "name": _to_str(name),
            "flags": flag_list,
            "delimiter": _to_str(delim) if delim else None,
            "messages": None,
        })
    out.sort(key=lambda f: (f["name"].upper() != "INBOX",))
    return out


def _special(folders: list[dict[str, Any]], flag: str) -> str | None:
    for f in folders:
        if any(x.lower() == flag.lower() for x in f["flags"]):
            return f["name"]
    return None


def _by_name(folders: list[dict[str, Any]], candidates: Iterable[str]) -> str | None:
    names = {f["name"].lower(): f["name"] for f in folders}
    for c in candidates:
        if c.lower() in names:
            return names[c.lower()]
    return None


def _suggest(folders: list[dict[str, Any]]) -> dict[str, str | None]:
    return {
        "junk": _special(folders, "\\Junk") or _by_name(folders, _JUNK_NAMES),
        "trash": _special(folders, "\\Trash") or _by_name(folders, _TRASH_NAMES),
    }


def _resolve_name(name: str, delim: str | None) -> str:
    # Config uses "/" as hierarchy separator; servers here use ".".
    if not delim or delim == "/" or "/" not in name:
        return name
    return name.replace("/", delim)


def _folder_map(acc: Any, folders: list[dict[str, Any]]) -> dict[str, Any]:
    """Same precedence as the engine: an explicit per-account junk/trash
    wins; otherwise SPECIAL-USE autodetect; otherwise the configured name."""
    delim = next((f["delimiter"] for f in folders if f["delimiter"]), None)
    auto = bool(getattr(acc, "auto_special_folders", True))
    inbox = _resolve_name(getattr(acc, "inbox", None) or "INBOX", delim)
    junk = _resolve_name(getattr(acc, "junk", None) or "Junk", delim)
    trash = _resolve_name(getattr(acc, "trash", None) or "Trash", delim)
    if auto and not getattr(acc, "junk_explicit", False):
        junk = _special(folders, "\\Junk") or junk
    if auto and not getattr(acc, "trash_explicit", False):
        trash = _special(folders, "\\Trash") or trash
    names = {f["name"] for f in folders}
    out = {"inbox": inbox, "junk": junk, "trash": trash,
           "junk_exists": junk in names, "names": names}
    # Like the engine: the provider's spam folder when the filter uses its
    # own (e.g. "Spamfilter") - mail there can be released/learned too.
    provider_junk = _special(folders, "\\Junk") or _by_name(folders, _PROVIDER_JUNK_NAMES)
    if provider_junk and provider_junk != junk and provider_junk != inbox:
        out["provider_junk"] = provider_junk
    # 2.6 (A4): the newsletter folder, when it exists (mail moved there by
    # the filter can be put back or marked as spam).
    nl_name = getattr(acc, "newsletter_folder", None)
    if isinstance(nl_name, str) and nl_name:
        nl_folder = _resolve_name(nl_name, delim)
        if nl_folder in names and nl_folder not in (inbox, junk, trash, out.get("provider_junk")):
            out["newsletters"] = nl_folder
    return out


def _status_counts(client: Any, folders: list[dict[str, Any]], wanted: Iterable[str | None]) -> None:
    want = {w for w in wanted if w}
    for f in folders:
        if f["name"] not in want:
            continue
        try:
            st = client.folder_status(f["name"], [b"MESSAGES"])
            n = st.get(b"MESSAGES", st.get("MESSAGES"))
            f["messages"] = int(n) if n is not None else None
        except Exception as ex:
            log.info("STATUS %s failed: %s", f["name"], type(ex).__name__)


def _public_folders(folders: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"name": f["name"], "flags": f["flags"], "messages": f["messages"]} for f in folders]


# ---------------------------------------------------------------------------
# Connection test
# ---------------------------------------------------------------------------


def _classify_connect_error(ex: BaseException, phase: str = "connect") -> str:
    if isinstance(ex, LoginError):
        return "auth"
    if isinstance(ex, ssl.SSLError) or isinstance(ex, ssl.CertificateError):
        return "tls"
    if phase == "starttls":
        return "tls"
    if isinstance(ex, socket.gaierror):
        return "dns"
    if isinstance(ex, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(ex, imaplib.IMAP4.abort):
        return "network"
    if isinstance(ex, OSError):
        return "network"
    if phase == "login" and isinstance(ex, IMAPClientError):
        return "auth"
    return "other"


def _imap_class(eng: Any | None) -> Any:
    cls = getattr(eng, "IMAPClient", None) if eng is not None else None
    if cls is None:
        from imapclient import IMAPClient as cls  # type: ignore[no-redef]
    return cls


def test_connection(host: str, port: int | str, user: str, password: str,
                    timeout: float = 20, *, engine: Any = None) -> dict[str, Any]:
    """Log in and look around READ-ONLY (CAPABILITY, LIST, STATUS). Never
    raises and never echoes server/exception text or the password."""
    out: dict[str, Any] = {
        "ok": False, "code": "other", "text": _CONNECT_TEXT["other"],
        "capabilities": [], "move_method": "none", "idle": False,
        "folders": [], "suggested": {"junk": None, "trash": None},
    }
    host = (host or "").strip()
    try:
        port_i = int(port)
    except (TypeError, ValueError):
        port_i = 0
    if not _HOST_RE.match(host) or not 1 <= port_i <= 65535:
        out["text"] = "Ugyldig server eller port."
        return out
    if not user or not password:
        out["code"] = "auth"
        out["text"] = "Brugernavn og adgangskode skal udfyldes."
        return out

    cls = _imap_class(engine)
    client = None
    phase = "connect"
    try:
        try:
            tls = ssl.create_default_context()
            if port_i == 143:
                # Plain port: insist on STARTTLS, never send the password in clear.
                client = cls(host, port=port_i, ssl=False, timeout=timeout)
                phase = "starttls"
                client.starttls(tls)
            else:
                client = cls(host, port=port_i, ssl=True, ssl_context=tls, timeout=timeout)
            phase = "login"
            client.login(user, password)
        except Exception as ex:
            code = _classify_connect_error(ex, phase)
            log.info("test_connection %s:%d failed in %s: %s", host, port_i, phase, type(ex).__name__)
            out.update(code=code, text=_CONNECT_TEXT[code])
            return out

        caps = _caps(client)
        out.update(ok=True, code="ok", text=_CONNECT_TEXT["ok"], capabilities=caps,
                   move_method=_move_method(engine, caps),
                   idle="IDLE" in caps)
        try:
            folders = _list_folders(client)
            suggested = _suggest(folders)
            _status_counts(client, folders, ("INBOX", suggested["junk"], suggested["trash"]))
            out["folders"] = _public_folders(folders)
            out["suggested"] = suggested
        except Exception as ex:
            log.info("test_connection LIST failed: %s", type(ex).__name__)
            out["text"] = "Forbindelsen virker, men mappelisten kunne ikke hentes."
        return out
    finally:
        if client is not None:
            try:
                client.logout()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Mail actions
# ---------------------------------------------------------------------------


class _Session:
    """Tracks the selected folder so each id doesn't re-SELECT."""

    def __init__(self, client: Any) -> None:
        self.client = client
        self.current: tuple[str, bool] | None = None

    def select(self, folder: str, readonly: bool) -> None:
        if self.current != (folder, readonly):
            self.current = None
            self.client.select_folder(folder, readonly=readonly)
            self.current = (folder, readonly)


def _locate(eng: Any, sess: _Session, mid: str, folders: list[str | None],
            existing: set[str], readonly: bool) -> tuple[str | None, list[int]]:
    seen: set[str] = set()
    for f in folders:
        if not f or f in seen or f not in existing:
            continue
        seen.add(f)
        sess.select(f, readonly)
        uids = list(eng.find_uids_by_message_id(sess.client, mid) or [])
        if uids:
            return f, uids
    return None, []


def _pick_duplicate(client: Any, uids: list[int]) -> int | None:
    """Newest UID when every candidate is the same message (COPY keeps
    INTERNALDATE and size); None when they differ (really ambiguous)."""
    try:
        data = client.fetch(sorted(uids), [b"INTERNALDATE", b"RFC822.SIZE"])
    except Exception as ex:
        log.info("duplicate check failed: %s", type(ex).__name__)
        return None
    keys = set()
    for u in uids:
        d = data.get(u)
        if not d:
            return None
        keys.add((_ts(d.get(b"INTERNALDATE")), d.get(b"RFC822.SIZE")))
    if len(keys) != 1 or None in next(iter(keys)):
        return None
    return max(uids)


def _ts(value: Any) -> int | None:
    """datetime -> unix seconds. Naive values are local time, which is how
    IMAPClient normalises INTERNALDATE (same conversion as the engine)."""
    if value is None:
        return None
    try:
        return int(value.timestamp())
    except (AttributeError, OverflowError, OSError, ValueError):
        return None


def _fetch_body(client: Any, uid: int, cap: int) -> tuple[bytes | None, set[str]]:
    meta = client.fetch([uid], [b"RFC822.SIZE", b"FLAGS"]).get(uid, {})
    flags = {_to_str(f) for f in (meta.get(b"FLAGS") or ())}
    size = meta.get(b"RFC822.SIZE")
    if size is None or int(size) > cap:
        return None, flags
    data = client.fetch([uid], [b"BODY.PEEK[]"]).get(uid, {})
    raw = data.get(b"BODY[]") or data.get(b"BODY.PEEK[]")
    return (bytes(raw) if raw else None), flags


def _legit_newsletter(eng: Any, db: Any, acc: Any, mid: str, raw: bytes | None) -> bool:
    """2.12 (#9): "Flyt til spam" on an ordinary newsletter moves it, but
    neither Bayes nor the fuzzy storage learns it as spam (engine
    legit_newsletter). Logged as learn_skip_newsletter."""
    check = getattr(eng, "legit_newsletter", None)
    if check is None or raw is None:
        return False
    try:
        row = db.conn.execute("SELECT * FROM messages WHERE account=? AND message_id=?", (acc.name, mid)).fetchone()
        if not check(raw, row, float(getattr(acc, "threshold", 0) or 0), db.conn):
            return False
        with db.tx():
            db.log_event("learn_skip_newsletter", mid, detail="webui")
        return True
    except Exception as ex:  # noqa: BLE001 - when in doubt: learn as before
        log.warning("newsletter check failed: %s", type(ex).__name__)
        return False


def _learn(eng: Any, db: Any, acc: Any, raw: bytes | None, kind: str, mid: str,
           actor: str, reason: str, *, allow_threat: bool = False) -> str:
    if raw is None:
        return "too_large"
    try:
        if allow_threat:
            return str(eng.learn_message(db, acc, raw, kind, mid, actor=actor, reason=reason,
                                         allow_threat=True))
        return str(eng.learn_message(db, acc, raw, kind, mid, actor=actor, reason=reason))
    except Exception as ex:
        log.warning("learn_message(%s) raised %s", kind, type(ex).__name__)
        return "error"


def _record_verdict(db: Any, eng: Any, acc: Any, mid: str, *, folder: str, verdict: str,
                    actor: str, our_action: str | None, moved_to_junk: bool,
                    learn_outcome: str, raw: bytes | None, stat: str | None,
                    event: str, keep_pending_move: bool = False) -> None:
    now = int(time.time())
    # A failed/deferred learn stays pending so the engine retries it.
    pending = verdict if learn_outcome in ("error", "rate_limited") else None
    # learn_message only books learned_as on an existing row; record it here
    # too so a first-time manual learn is not repeated by the engine.
    learned = verdict if learn_outcome in ("learned", "already") else None
    sender = subject = None
    if raw is not None:
        try:
            _mid, subject, sender = eng.parse_envelope(raw)
        except Exception:
            pass
    with db.tx():
        retained_threat, retained_detail = _threat_of(db.conn, acc.name, mid)
        if raw is not None and hasattr(eng, "normalize_message_id"):
            # The real engine has the additive identity table. Fake engines
            # used by old versions may expose only the original interface.
            if db.conn.execute("SELECT 1 FROM sqlite_master WHERE name='mail_identity'").fetchone():
                mailidentity.bind(db.conn, acc.name, eng.parse_envelope(raw)[0], raw)
        db.conn.execute(
            """
            INSERT INTO messages(account, message_id, first_seen, last_seen,
                                 current_folder, sender, subject, user_verdict,
                                 verdict_at, verdict_by, our_action,
                                 moved_to_junk_at, pending_learn,
                                 pending_learn_at, learned_as, learned_at, origin)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'manual')
            ON CONFLICT(account, message_id) DO UPDATE SET
                last_seen=excluded.last_seen,
                current_folder=excluded.current_folder,
                sender=COALESCE(messages.sender, excluded.sender),
                subject=COALESCE(messages.subject, excluded.subject),
                user_verdict=excluded.user_verdict,
                verdict_at=excluded.verdict_at,
                verdict_by=excluded.verdict_by,
                our_action=COALESCE(excluded.our_action, messages.our_action),
                moved_to_junk_at=COALESCE(excluded.moved_to_junk_at, messages.moved_to_junk_at),
                pending_learn=excluded.pending_learn,
                pending_learn_at=excluded.pending_learn_at,
                learned_as=COALESCE(excluded.learned_as, messages.learned_as),
                learned_at=COALESCE(excluded.learned_at, messages.learned_at),
                origin=COALESCE(messages.origin, excluded.origin)
            """,
            (acc.name, mid, now, now, folder, sender or None, subject or None, verdict,
             now, actor or None, our_action, now if moved_to_junk else None,
             pending, now if pending else None, learned, now if learned else None),
        )
        # The user decided: a queued filter move for this mail is obsolete -
        # except after "Lær som spam" (2.11.1, keep_pending_move): the user
        # agrees with the filter, so the queued move to the Spamfilter folder
        # stays and the engine carries it out when it is due, as usual.
        if not keep_pending_move:
            db.conn.execute("DELETE FROM pending_move WHERE account=? AND message_id=?",
                            (acc.name, mid))
        if retained_threat:
            db.conn.execute('UPDATE messages SET threat=?, threat_detail=? WHERE account=? AND message_id=?',
                            (retained_threat, retained_detail, acc.name, mid))
        db.log_event(event, mid, detail=f"actor={actor}" if actor else None)
    if stat:
        # Outside the transaction: bump_stat may manage its own commit.
        try:
            eng.bump_stat(db.conn, acc.name, stat)
        except Exception as ex:
            log.warning("bump_stat(%s) failed: %s", stat, type(ex).__name__)


def _do_release(eng: Any, db: Any, acc: Any, sess: _Session, fmap: dict[str, Any],
                caps: frozenset, mid: str, actor: str, *, threat: str | None = None) -> dict[str, Any]:
    folder, uids = _locate(eng, sess, mid, [fmap["junk"], fmap.get("provider_junk"), fmap["inbox"]],
                           fmap["names"], readonly=False)
    if not uids:
        return _res(mid, False, "not_found", "Beskeden blev ikke fundet i spam-mapperne eller indbakken.")
    if len(uids) > 1 and folder == fmap["junk"]:
        # Identical copies in the filter's own folder (an interrupted
        # COPY-based move on Gigahost): release the newest, leave the rest.
        uids = [u for u in [_pick_duplicate(sess.client, uids)] if u is not None] or uids
    if len(uids) > 1:
        return _res(mid, False, "ambiguous", "Flere beskeder har samme Message-ID – intet er ændret.")
    uid = uids[0]
    raw, flags = _fetch_body(sess.client, uid, eng.MAX_FETCH_BYTES)
    if hasattr(eng, 'mailidentity') and not _bind_selected(eng, db, acc, mid, raw):
        return _res(mid, False, "identity_changed", "Beskeden kunne ikke identificeres sikkert. Søg igen.")
    if folder == fmap["inbox"]:
        # Already in the inbox (shadow/flag mode): drop our $Junk mark only
        # if the filter set one, so shadow mode stays write-free.
        if JUNK_KEYWORD in flags:
            sess.client.remove_flags([uid], [JUNK_KEYWORD])
            sess.client.add_flags([uid], [NOTJUNK_KEYWORD])
        text = "Markeret som legitim (lå allerede i indbakken)"
    else:
        # Book the release BEFORE the IMAP move: the account thread idles on
        # the inbox and may see the new UID at once (Gigahost: right after
        # the COPY). Without this it would take the mail for a user rescue
        # in the mail app and auto-allow the sender - a release only
        # releases this one mail.
        sender = subject = None
        if raw is not None:
            try:
                _m, subject, sender = eng.parse_envelope(raw)
            except Exception:
                pass
        snapshot = _premark_inbox(db, acc, mid, inbox=fmap["inbox"], verdict="ham", by=actor,
                                  sender=sender, subject=subject, received_at=None)
        try:
            if "\\Deleted" in flags:
                # Marked deleted by a mail client but not purged yet: COPY/MOVE
                # keep flags, so the released copy would arrive deleted and
                # vanish at the next purge. The explicit release wins.
                sess.client.remove_flags([uid], ["\\Deleted"])
            eng.imap_move(sess.client, [uid], fmap["inbox"], capabilities=caps)
        except Exception as ex:
            if not getattr(ex, "copied", False):
                log.warning("release move failed: %s", type(ex).__name__)
                _restore(db, acc, mid, snapshot)
                return _res(mid, False, "move_failed", "Beskeden kunne ikke flyttes til indbakken.")
            # UIDPLUS: the copy reached the inbox, only the source could not
            # be expunged (harmless duplicate left in the spam folder).
            log.warning("release: copied, source kept: %s", type(ex).__name__)
        text = "Frigivet til indbakken"
    _campaign_after_ham(eng, db, acc, mid, raw, "frigivet")
    if threat:
        # B16: a confirmed release of a threat never teaches Bayes "ham".
        _record_verdict(db, eng, acc, mid, folder=fmap["inbox"], verdict="ham", actor=actor,
                        our_action="manual_release", moved_to_junk=False, learn_outcome="skipped",
                        raw=raw, stat="released", event="manual_release")
        with db.tx():
            db.log_event("threat_release", mid, detail=f"{threat} actor={actor}"[:300])
        return _res(mid, True, "ok", text + " – ikke lært som legitim, fordi mailen er markeret som farlig.")
    outcome = _learn(eng, db, acc, raw, "ham", mid, actor, "manual_release")
    _record_verdict(db, eng, acc, mid, folder=fmap["inbox"], verdict="ham", actor=actor,
                    our_action="manual_release", moved_to_junk=False, learn_outcome=outcome,
                    raw=raw, stat="released", event="manual_release")
    learned_ok = outcome in ("learned", "already", "declined")
    note = " og lært som legitim." if outcome == "learned" else _learn_note(outcome, "ham")
    if outcome == "already":
        note = " og lært som legitim" + note + "."
    return _res(mid, True, "ok" if learned_ok else f"learn_{outcome}", text + note)


def _do_mark_spam(eng: Any, db: Any, acc: Any, sess: _Session, fmap: dict[str, Any],
                  caps: frozenset, mid: str, actor: str) -> dict[str, Any]:
    folder, uids = _locate(eng, sess, mid, [fmap["inbox"], fmap.get("newsletters"), fmap["junk"],
                                            fmap.get("provider_junk")],
                           fmap["names"], readonly=False)
    if not uids:
        return _res(mid, False, "not_found", "Beskeden blev ikke fundet i indbakken eller spam-mapperne.")
    if len(uids) > 1:
        return _res(mid, False, "ambiguous", "Flere beskeder har samme Message-ID – intet er ændret.")
    uid = uids[0]
    raw, _flags = _fetch_body(sess.client, uid, eng.MAX_FETCH_BYTES)
    moved = False
    if folder == fmap["junk"]:
        text = "Markeret som spam (lå allerede i Spamfilter-mappen)"
    elif folder == fmap.get("provider_junk"):
        text = "Markeret som spam (ligger i udbyderens spam-mappe)"
    else:
        try:
            if not fmap["junk_exists"]:
                sess.client.create_folder(fmap["junk"])
                try:
                    sess.client.subscribe_folder(fmap["junk"])
                except Exception:
                    pass  # unsubscribed but usable
                fmap["junk_exists"] = True
                fmap["names"].add(fmap["junk"])
                db.log_event("folder_created", None, detail=fmap["junk"])
            eng.imap_move(sess.client, [uid], fmap["junk"], capabilities=caps)
            moved = True
        except Exception as ex:
            log.warning("mark_spam move failed: %s", type(ex).__name__)
            return _res(mid, False, "move_failed", "Beskeden kunne ikke flyttes til Spamfilter-mappen.")
        text = "Flyttet til Spamfilter-mappen"
    outcome = ("newsletter" if _legit_newsletter(eng, db, acc, mid, raw)
               else _learn(eng, db, acc, raw, "spam", mid, actor, "manual_mark_spam"))
    _record_verdict(db, eng, acc, mid, folder=folder if folder == fmap.get("provider_junk") else fmap["junk"],
                    verdict="spam", actor=actor,
                    our_action="manual_mark_spam", moved_to_junk=moved, learn_outcome=outcome,
                    raw=raw, stat="marked_spam", event="manual_mark_spam")
    _revoke_auto_allow(eng, db, acc, mid, raw)
    if outcome != "newsletter":
        # A newsletter one person does not want is no campaign for the others.
        _campaign_after_spam(eng, db, acc, mid, raw, actor, "manual_mark_spam", outcome)
    learned_ok = outcome in ("learned", "already", "declined", "newsletter")
    note = " og lært som spam." if outcome == "learned" else _learn_note(outcome, "spam")
    if outcome == "already":
        note = " og lært som spam" + note + "."
    return _res(mid, True, "ok" if learned_ok else f"learn_{outcome}", text + note)


def _revoke_auto_allow(eng: Any, db: Any, acc: Any, mid: str, raw: bytes | None) -> None:
    """'Flyt til spam' undoes an allow rule the filter made automatically
    for this sender (created_by 'auto:flytning'); hand-made rules stay."""
    revoke = getattr(eng, "revoke_auto_allow", None)
    if revoke is None:
        return
    sender = None
    row = db.conn.execute("SELECT sender FROM messages WHERE account=? AND message_id=?",
                          (acc.name, mid)).fetchone()
    if row is not None:
        sender = row["sender"]
    if not sender and raw is not None:
        try:
            sender = eng.parse_envelope(raw)[2]
        except Exception:
            sender = None
    if not sender:
        return
    try:
        with db.tx():
            rid = revoke(db.conn, acc.name, sender)
            if rid is not None:
                db.log_event("rule_auto_allow_removed", mid, detail=f"rule={rid} webui")
    except Exception as ex:
        log.warning("auto-allow revoke failed: %s", type(ex).__name__)


def _campaign_after_ham(eng: Any, db: Any, acc: Any, mid: str, raw: bytes | None, why: str) -> None:
    """2.6 (A2): the user released / learned as ham a mail: cancel the
    campaign copies it queued (and their moves not carried out yet) and
    remove it from rspamd's local fuzzy storage again. Never raises."""
    try:
        import campaigns  # noqa: PLC0415
    except Exception as ex:
        log.warning("campaigns unavailable: %s", type(ex).__name__)
        return
    try:
        with db.tx():
            campaigns.cancel_for_source(db.conn, acc.name, mid, reason=why)
    except Exception as ex:
        log.warning("campaign cancel failed: %s", type(ex).__name__)
    try:
        campaigns.fuzzy_undo(eng, db.conn, acc.name, mid, raw)
    except Exception as ex:
        log.warning("fuzzy removal failed: %s", type(ex).__name__)


def _campaign_after_spam(eng: Any, db: Any, acc: Any, mid: str, raw: bytes | None, actor: str,
                         trigger: str, learn_outcome: str | None = None) -> None:
    """2.6 (A2): a spam verdict from the WebUI -> queue the copies of the
    same campaign in every mailbox (each account thread moves its own) and
    add the mail to rspamd's local fuzzy storage once it is learned (never
    for a declined learn; a deferred learn adds it when the engine learns
    it). Never raises."""
    try:
        import campaigns  # noqa: PLC0415
    except Exception as ex:
        log.warning("campaigns unavailable: %s", type(ex).__name__)
        return
    try:
        with db.tx():
            campaigns.on_user_spam(db.conn, acc.name, mid, actor=actor or "webui", trigger=trigger,
                                   own_domains=[*(getattr(acc, "owner_platform_domains", None) or ()),
                                                *(getattr(acc, "webshop_domains", None) or ())])
    except Exception as ex:
        log.warning("campaign sweep failed: %s", type(ex).__name__)
    if learn_outcome not in ("learned", "already"):
        return
    try:
        campaigns.fuzzy_for_verdict(eng, db.conn, acc.name, mid, raw)
    except Exception as ex:
        log.warning("fuzzy add failed: %s", type(ex).__name__)


def _do_learn(eng: Any, db: Any, acc: Any, sess: _Session, fmap: dict[str, Any],
              mid: str, actor: str, kind: str, *, allow_threat: bool = False) -> dict[str, Any]:
    row = db.conn.execute(
        "SELECT current_folder FROM messages WHERE account=? AND message_id=?",
        (acc.name, mid)).fetchone()
    hint = row["current_folder"] if row is not None else None
    folder, uids = _locate(eng, sess, mid, [hint, fmap["inbox"], fmap["junk"], fmap.get("provider_junk")],
                           fmap["names"], readonly=True)
    if not uids:
        return _res(mid, False, "not_found", "Beskeden blev ikke fundet i postkassen.")
    if len(uids) > 1:
        return _res(mid, False, "ambiguous", "Flere beskeder har samme Message-ID – intet er ændret.")
    raw, _flags = _fetch_body(sess.client, uids[0], eng.MAX_FETCH_BYTES)
    outcome = _learn(eng, db, acc, raw, kind, mid, actor, f"manual_learn_{kind}",
                     allow_threat=allow_threat and kind == "ham")
    _record_verdict(db, eng, acc, mid, folder=folder or fmap["inbox"], verdict=kind,
                    actor=actor, our_action=None, moved_to_junk=False,
                    learn_outcome=outcome, raw=raw, stat=None,
                    event=f"manual_learn_{kind}",
                    keep_pending_move=kind == "spam" and folder not in (fmap["junk"], fmap.get("provider_junk")))
    if kind == "spam":
        _revoke_auto_allow(eng, db, acc, mid, raw)
        _campaign_after_spam(eng, db, acc, mid, raw, actor, "manual_learn_spam", outcome)
    else:
        _campaign_after_ham(eng, db, acc, mid, raw, "lært som legitim")
    label = "legitim" if kind == "ham" else "spam"
    if outcome in ("learned", "already"):
        return _res(mid, True, "ok", f"Lært som {label}{_LEARN_NOTE[outcome]}.")
    if outcome == "declined":   # already in that class: done, nothing to learn
        return _res(mid, True, "ok", f"Markeret som {label}{_learn_note(outcome, kind)}")
    return _res(mid, False, f"learn_{outcome}",
                f"Markeret som {label}{_LEARN_NOTE.get(outcome, ' – læring fejlede.')}")


def mail_action(account: str, message_ids: Iterable[str], action: str, actor: str,
                *, engine: Any = None, demote_contact: bool = True, is_admin: bool = False,
                confirm_threat: bool = False) -> list[dict[str, Any]]:
    """release | mark_spam | learn_ham | learn_spam for up to 200 ids in one
    IMAP session. Returns one result per distinct id, in input order.
    2.3 (B16): 'release' and 'learn_ham' of a mail with a threat class
    (virus, phishing link, malware link, dangerous attachment) need
    is_admin=True AND confirm_threat=True; otherwise nothing changes and the
    result has code 'threat_admin' (non-admin: 'Kontakt administrator') or
    'threat_confirm' (admin: show confirm_text and ask), plus threat /
    threat_text / confirm_text. A confirmed release still never learns ham;
    a confirmed learn_ham does (the administrator's explicit choice).
    Fail closed: callers that do not pass is_admin are treated as non-admins.
    2.3 (B14): a 'spam' verdict on a mail from a known contact / established
    sender demotes the sender ('Skal afsenderen også fjernes fra Kendte
    kontakter?' - yes by default; demote_contact=False keeps the contact,
    the sender still gets n_junk + 1). Release / learn ham count as kept."""
    if isinstance(message_ids, (str, bytes)):
        message_ids = [message_ids]  # a bare id, not an iterable of chars
    raw_ids: list[str] = []
    for m in message_ids or ():
        s = "" if m is None else _to_str(m)
        if s not in raw_ids:
            raw_ids.append(s)
    if action not in MAIL_ACTIONS:
        return [_res(m, False, "invalid_action", "Ukendt handling.") for m in raw_ids]

    results: dict[str, dict[str, Any]] = {}
    todo: list[tuple[str, str]] = []  # (original, normalised)
    first_for: dict[str, str] = {}    # normalised -> first original spelling
    aliases: dict[str, str] = {}      # '<a@b>' after 'a@b' -> 'a@b'
    for i, m in enumerate(raw_ids):
        if i >= MAX_MAIL_ACTION_IDS:
            results[m] = _res(m, False, "limit", f"Højst {MAX_MAIL_ACTION_IDS} beskeder ad gangen.")
            continue
        norm = normalize_message_id(m)
        if norm is None:
            results[m] = _res(m, False, "invalid_id", "Ugyldigt Message-ID.")
        elif norm in first_for:
            aliases[m] = first_for[norm]
        else:
            first_for[norm] = m
            todo.append((m, norm))

    if todo:
        eng = _eng(engine)
        for orig, res in _run_mail_actions(eng, account, todo, action, actor,
                                           demote_contact=demote_contact, is_admin=is_admin,
                                           confirm_threat=confirm_threat):
            results[orig] = res
    for alias, orig in aliases.items():
        results[alias] = {**results[orig], "message_id": alias}
    return [results[m] for m in raw_ids]


def _run_mail_actions(eng: Any, account: str, todo: list[tuple[str, str]], action: str,
                      actor: str, *, demote_contact: bool = True, is_admin: bool = False,
                      confirm_threat: bool = False) -> list[tuple[str, dict[str, Any]]]:
    def fail_all(code: str, text: str) -> list[tuple[str, dict[str, Any]]]:
        return [(o, _res(o, False, code, text)) for o, _n in todo]

    try:
        acc = _find_account(eng, account)
    except Exception as ex:
        log.warning("mail_action: config load failed: %s", type(ex).__name__)
        return fail_all("config", "Konfigurationen kunne ikke indlæses.")
    if acc is None:
        return fail_all("no_account", "Kontoen findes ikke.")
    try:
        password = eng.read_secret(acc)
    except Exception as ex:
        log.warning("mail_action: secret unavailable for %s: %s", account, type(ex).__name__)
        return fail_all("no_secret", "Adgangskoden til kontoen mangler.")
    try:
        client = eng.connect(acc, password=password)
    except Exception as ex:
        code = "auth" if isinstance(ex, LoginError) else "connect"
        log.warning("mail_action: connect failed for %s: %s", account, type(ex).__name__)
        return fail_all(code, _CONNECT_TEXT["auth"] if code == "auth"
                        else "Kunne ikke forbinde til mailserveren.")

    out: list[tuple[str, dict[str, Any]]] = []
    db = None
    try:
        caps = _caps_for_engine(_caps(client))
        try:
            fmap = _folder_map(acc, _list_folders(client))
        except Exception as ex:
            log.warning("mail_action: LIST failed: %s", type(ex).__name__)
            return fail_all("imap_error", "Mappelisten kunne ikke hentes fra mailserveren.")
        db = eng.Db(acc.name)
        sess = _Session(client)
        for orig, mid in todo:
            prior = _contact_prior(db, acc, mid)
            threat, tdetail = _threat_of(db.conn, acc.name, mid)
            if action in ("release", "learn_ham"):
                gate = threat_gate(threat, tdetail, is_admin=is_admin, confirm_threat=confirm_threat)
                if gate is not None:
                    try:
                        with db.tx():
                            db.log_event("threat_release_refused", mid,
                                         detail=f"{threat} {action} {gate['code']} actor={actor}"[:300])
                    except Exception:
                        pass
                    res = {**_res(orig, False, gate["code"], gate["text"]),
                           "threat": gate["threat"], "threat_text": gate["threat_text"],
                           "confirm_text": gate["confirm_text"]}
                    out.append((orig, res))
                    continue
            try:
                if action == "release":
                    res = _do_release(eng, db, acc, sess, fmap, caps, mid, actor, threat=threat)
                elif action == "mark_spam":
                    res = _do_mark_spam(eng, db, acc, sess, fmap, caps, mid, actor)
                else:
                    res = _do_learn(eng, db, acc, sess, fmap, mid, actor,
                                    "ham" if action == "learn_ham" else "spam",
                                    allow_threat=bool(threat))
            except Exception as ex:
                log.warning("mail_action %s failed: %s", action, type(ex).__name__)
                sess.current = None  # state unknown; force re-SELECT
                res = _res(mid, False, "imap_error", "Mailserveren afviste handlingen.")
            res["message_id"] = orig
            if threat:
                res.update(_threat_fields(threat, tdetail))
            if res.get("ok") and not (threat and action in ("release", "learn_ham")):
                # B16: a threat never counts as 'kept' for the contact signals.
                _contact_verdict(eng, db, acc, mid, action, actor, prior, demote=demote_contact, result=res)
            out.append((orig, res))
        return out
    finally:
        if db is not None:
            try:
                db.close()
            except Exception:
                pass
        try:
            client.logout()
        except Exception:
            pass


def _contact_prior(db: Any, acc: Any, mid: str) -> dict[str, Any] | None:
    """our_action/symbols before a WebUI verdict (2.3, B14)."""
    if not getattr(acc, "known_contacts", False):
        return None
    try:
        row = db.conn.execute("SELECT our_action, symbols FROM messages WHERE account=? AND message_id=?",
                              (acc.name, mid)).fetchone()
    except sqlite3.Error:
        return None
    return {"our_action": row[0], "symbols": row[1]} if row is not None else {"our_action": None,
                                                                              "symbols": None}


def _contact_verdict(eng: Any, db: Any, acc: Any, mid: str, action: str, actor: str,
                     prior: dict[str, Any] | None, *, demote: bool, result: dict[str, Any]) -> None:
    """B14 after a successful WebUI verdict: spam -> n_junk + 1 and (with
    `demote`) a known contact / established sender loses its trust; release
    / learn ham -> counts as kept. Adds result['contact'] = {mask, demoted}."""
    if prior is None:
        return
    try:
        c = _contacts_mod()
        key = c.load_key(eng.STATE_DIR, None, create=False)
        if key is None:
            return
        row = db.conn.execute("SELECT sender FROM messages WHERE account=? AND message_id=?",
                              (acc.name, mid)).fetchone()
        sender = row[0] if row is not None else None
        if not sender:
            return
        with db.tx():
            if action in ("mark_spam", "learn_spam"):
                info = c.on_user_spam(db.conn, acc.name, key, sender=sender, symbols=prior.get("symbols"),
                                      prior_action=prior.get("our_action"), actor=actor or "webui",
                                      demote=demote, now=int(time.time()), message_id=mid)
                if info is not None:
                    result["contact"] = {"mask": info["mask"], "demoted": bool(info["demoted"]),
                                         "h": info["h"]}
            else:
                c.on_user_ham(db.conn, acc.name, key, sender=sender, prior_action=prior.get("our_action"),
                              now=int(time.time()))
    except Exception as ex:
        log.warning("contact bookkeeping after %s failed: %s", action, type(ex).__name__)


# ---------------------------------------------------------------------------
# 2.6 (A3/A6): block suggestions and the protected-recipient watch
# ---------------------------------------------------------------------------


def _owner_domain_list(eng: Any) -> list[str]:
    out: list[str] = []
    try:
        configs = list(eng.load_account_configs(eng.CONFIG_PATH))
    except Exception:
        configs = []
    for d in [*getattr(eng, "DEFAULT_OWNER_PLATFORM_DOMAINS", ()), *getattr(eng, "DEFAULT_WEBSHOP_DOMAINS", ())]:
        out.append(str(d).lower())
    for a in configs:
        user = str(getattr(a, "user", "") or "").lower()
        if "@" in user:
            out.append(user.rpartition("@")[2])
        for key in ("owner_platform_domains", "webshop_domains"):
            out.extend(str(d).lower() for d in (getattr(a, key, None) or ()))
    return [d for d in dict.fromkeys(out) if d]


def block_suggestions(*, refuse: Any = None, engine: Any = None) -> list[dict[str, Any]]:
    """[{domain, n, accounts}]: sender domains several mailboxes marked as
    spam in 30 days that could be blocked for everyone (campaigns.py)."""
    import campaigns  # noqa: PLC0415

    eng = _eng(engine)
    try:
        with closing(_open_db_ro(eng)) as conn:
            return campaigns.block_suggestions(conn, refuse=refuse, own_domains=_owner_domain_list(eng))
    except sqlite3.Error as ex:
        log.warning("block_suggestions failed: %s", type(ex).__name__)
        return []


def dismiss_block_suggestion(domain: str, actor: str, *, engine: Any = None) -> dict[str, Any]:
    """'Ignorer': the domain is never suggested again."""
    import campaigns  # noqa: PLC0415

    eng = _eng(engine)
    try:
        with closing(_open_db(eng)) as conn:
            ok = campaigns.dismiss_suggestion(conn, domain, actor)
    except sqlite3.Error as ex:
        log.warning("dismiss_block_suggestion failed: %s", type(ex).__name__)
        return {"ok": False, "code": "db", "text": "Det kunne ikke gemmes lige nu."}
    if not ok:
        return {"ok": False, "code": "invalid", "text": "Ugyldigt domæne."}
    return {"ok": True, "code": "ok", "domain": campaigns.registrable(domain),
            "text": f"Forslaget om {campaigns.registrable(domain)} vises ikke igen."}


def protected_watch(*, engine: Any = None) -> list[dict[str, Any]]:
    """[{account, n, threshold, protected_threshold}] for mailboxes where
    spam over the normal threshold piles up at a protected recipient."""
    import campaigns  # noqa: PLC0415

    eng = _eng(engine)
    try:
        configs = list(eng.load_account_configs(eng.CONFIG_PATH))
    except Exception:
        return []
    try:
        with closing(_open_db_ro(eng)) as conn:
            return campaigns.protected_watch_items(conn, configs,
                                                   match_rule=getattr(eng, "match_sender_rule", None))
    except sqlite3.Error as ex:
        log.warning("protected_watch failed: %s", type(ex).__name__)
        return []


# ---------------------------------------------------------------------------
# Folders
# ---------------------------------------------------------------------------


def account_folders(account: str, *, engine: Any = None) -> list[dict[str, Any]]:
    """Folders as last written by the account thread (no IMAP)."""
    eng = _eng(engine)
    try:
        with closing(_open_db(eng)) as conn:
            row = conn.execute("SELECT folders FROM account_status WHERE account=?",
                               (account,)).fetchone()
    except sqlite3.Error:
        return []
    if row is None or not row["folders"]:
        return []
    try:
        data = json.loads(row["folders"])
    except (TypeError, ValueError):
        return []
    out = []
    for f in data if isinstance(data, list) else []:
        if isinstance(f, dict) and isinstance(f.get("name"), str):
            out.append({"name": f["name"], "flags": list(f.get("flags") or []),
                        "messages": f.get("messages")})
    return out


def refresh_folders(account: str, *, engine: Any = None) -> list[dict[str, Any]]:
    """Live LIST (+ STATUS for inbox/junk), stored in account_status.
    Read-only. Raises ServiceError with a Danish text on failure."""
    eng = _eng(engine)
    try:
        acc = _find_account(eng, account)
    except Exception:
        raise ServiceError("config", "Konfigurationen kunne ikke indlæses.") from None
    if acc is None:
        raise ServiceError("no_account", "Kontoen findes ikke.")
    try:
        client = eng.connect(acc, password=eng.read_secret(acc))
    except Exception as ex:
        log.warning("refresh_folders connect failed for %s: %s", account, type(ex).__name__)
        if isinstance(ex, LoginError):
            raise ServiceError("auth", _CONNECT_TEXT["auth"]) from None
        raise ServiceError("connect", "Kunne ikke forbinde til mailserveren.") from None
    try:
        caps = _caps(client)
        folders = _list_folders(client)
        fmap = _folder_map(acc, folders)
        _status_counts(client, folders, (fmap["inbox"], fmap["junk"]))
    except Exception as ex:
        log.warning("refresh_folders LIST failed for %s: %s", account, type(ex).__name__)
        raise ServiceError("imap_error", "Mappelisten kunne ikke hentes fra mailserveren.") from None
    finally:
        try:
            client.logout()
        except Exception:
            pass

    public = _public_folders(folders)
    now = int(time.time())
    state = "starting" if getattr(acc, "enabled", True) else "paused"
    with closing(_open_db(eng)) as conn:
        conn.execute(
            """
            INSERT INTO account_status(account, updated_at, state, folders, folder_map,
                                       junk_exists, capabilities, move_method, idle_supported)
            VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(account) DO UPDATE SET
                updated_at=excluded.updated_at, folders=excluded.folders,
                folder_map=excluded.folder_map, junk_exists=excluded.junk_exists,
                capabilities=excluded.capabilities, move_method=excluded.move_method,
                idle_supported=excluded.idle_supported
            """,
            (account, now, state, json.dumps(public, ensure_ascii=False),
             json.dumps({k: fmap[k] for k in ("inbox", "junk", "trash")}, ensure_ascii=False),
             int(fmap["junk_exists"]), json.dumps(caps), _move_method(eng, caps),
             int("IDLE" in caps)),
        )
    return public


# ---------------------------------------------------------------------------
# Training / calibration jobs
# ---------------------------------------------------------------------------


def _validate_job(eng: Any, account: str, folder: str, max_messages: Any,
                  min_age_days: Any) -> tuple[int, int]:
    try:
        acc = _find_account(eng, account)
    except Exception:
        raise ValueError("Konfigurationen kunne ikke indlæses.") from None
    if acc is None:
        raise ValueError("Kontoen findes ikke.")
    if not isinstance(folder, str) or not folder.strip() or len(folder) > 200 \
            or any(c in folder for c in "\r\n\x00"):
        raise ValueError("Ugyldig mappe.")
    try:
        n = int(max_messages)
        age = int(min_age_days or 0)
    except (TypeError, ValueError):
        raise ValueError("Antal og alder skal være heltal.") from None
    if not 1 <= n <= MAX_TRAIN_MESSAGES:
        raise ValueError(f"Antal skal være mellem 1 og {MAX_TRAIN_MESSAGES}.")
    if not 0 <= age <= MAX_MIN_AGE_DAYS:
        raise ValueError("Alder i dage er uden for det tilladte interval.")
    return n, age


def _insert_job(eng: Any, account: str, folder: str, kind: str, n: int, age: int,
                seen_only: bool, provider_filter: str, actor: str) -> int:
    with closing(_open_db(eng)) as conn:
        cur = conn.execute(
            """
            INSERT INTO train_jobs(account, folder, kind, max_messages, min_age_days,
                                   seen_only, provider_filter, status, created_by, created_at)
            VALUES(?,?,?,?,?,?,?, 'queued', ?, ?)
            """,
            (account, folder.strip(), kind, n, age, int(bool(seen_only)), provider_filter,
             actor or None, int(time.time())),
        )
        return int(cur.lastrowid)


INBOX_SPAM_REFUSED = ("Indbakken indeholder normalt legitim post og kan ikke læres som spam. "
                      "Flyt spammen til en anden mappe (fx Spamfilter-mappen) og træn fra den.")


def is_inbox_folder(acc: Any, folder: str) -> bool:
    inbox = str(getattr(acc, "inbox", None) or "INBOX")
    return folder.strip().upper() in ("INBOX", inbox.upper())


def queue_train_job(account: str, folder: str, kind: str, max_messages: int,
                    min_age_days: int = 0, seen_only: bool = False,
                    provider_filter: str = "any", actor: str = "",
                    *, allow_inbox_spam: bool = False, engine: Any = None) -> int:
    """Queue a Bayes training job; the trainer thread picks it up within
    ~5 s. Raises ValueError (Danish text) on invalid input. Learning the
    inbox as spam (one click would teach real mail as spam to the shared
    Bayes of every account) needs allow_inbox_spam=True."""
    eng = _eng(engine)
    if kind not in TRAIN_KINDS:
        raise ValueError("Typen skal være spam eller legitim.")
    if provider_filter not in PROVIDER_FILTERS:
        raise ValueError("Ukendt udbyder-filter.")
    n, age = _validate_job(eng, account, folder, max_messages, min_age_days)
    if kind == "spam" and not allow_inbox_spam and is_inbox_folder(_find_account(eng, account), folder):
        raise ValueError(INBOX_SPAM_REFUSED)
    return _insert_job(eng, account, folder, kind, n, age, seen_only, provider_filter, actor)


def queue_calibration(account: str, folder: str, max_messages: int = 300,
                      min_age_days: int = 0, actor: str = "", *, engine: Any = None) -> int:
    """Queue a read-only calibration scan (rspamd scores only, no learning)."""
    eng = _eng(engine)
    n, age = _validate_job(eng, account, folder, max_messages, min_age_days)
    return _insert_job(eng, account, folder, "calibrate", n, age, False, "any", actor)


def cancel_train_job(job_id: int, *, engine: Any = None) -> bool:
    """Queued jobs are cancelled at once; a running job gets
    'cancel_requested' and stops after its current chunk."""
    eng = _eng(engine)
    now = int(time.time())
    with closing(_open_db(eng)) as conn:
        cur = conn.execute(
            "UPDATE train_jobs SET status='cancelled', finished_at=? WHERE id=? AND status='queued'",
            (now, int(job_id)))
        if cur.rowcount:
            return True
        cur = conn.execute(
            "UPDATE train_jobs SET status='cancel_requested' WHERE id=? AND status='running'",
            (int(job_id),))
        return bool(cur.rowcount)


def list_train_jobs(limit: int = 20, *, engine: Any = None) -> list[dict[str, Any]]:
    eng = _eng(engine)
    limit = max(1, min(int(limit or 20), 500))
    try:
        with closing(_open_db(eng)) as conn:
            rows = conn.execute("SELECT * FROM train_jobs ORDER BY id DESC LIMIT ?",
                                (limit,)).fetchall()
    except sqlite3.Error:
        return []
    out = []
    for r in rows:
        d = dict(r)
        total = d.get("total") or 0
        d["percent"] = int(min(100, (d.get("processed") or 0) * 100 / total)) if total else (
            100 if d.get("status") == "done" else 0)
        out.append(d)
    return out


def _blind_fn() -> Any:
    try:
        from trainer import blind_score  # pure function, no side effects
        return blind_score
    except Exception:  # pragma: no cover - trainer ships in the same image
        return None


def calibration_results(job_id: int, *, limit: int = 2000, engine: Any = None) -> list[dict[str, Any]]:
    """Rows of one calibration job, highest final score first. Every row
    carries `blind_score` (stored, or derived from the stored symbols for
    jobs that ran before the column existed)."""
    eng = _eng(engine)
    try:
        with closing(_open_db(eng)) as conn:
            rows = conn.execute(
                "SELECT * FROM calibration_results WHERE job_id=? "
                "ORDER BY final_score DESC LIMIT ?", (int(job_id), int(limit))).fetchall()
    except sqlite3.Error:
        return []
    blind = _blind_fn()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["symbols"] = json.loads(d.get("symbols") or "[]")
        except (TypeError, ValueError):
            d["symbols"] = []
        if d.get("blind_score") is None and blind is not None:
            d["blind_score"] = blind(d.get("final_score"), d["symbols"])
        out.append(d)
    return out


BLIND_NOTE = ("Blind score er scoren uden udbyderens egen spam-markering (SPAM_FLAG, "
              "TH_PROVIDER_*) og uden Bayes (BAYES_*). Kalibrerer man på en spam-mappe, som "
              "udbyderen selv har sorteret, og som Bayes er trænet på, kender filteret allerede "
              "svaret – så fangst-tallet ser bedre ud, end det er. Blind score viser, hvad "
              "filteret fanger af ny, ukendt spam.")


def _score_stats(scores: list[float], ts: list[float]) -> dict[str, Any]:
    scores = sorted(scores)
    hist: dict[int, int] = {}
    for s in scores:
        b = int(max(-10, min(30, s // 1)))
        hist[b] = hist.get(b, 0) + 1
    median = None
    if scores:
        mid = len(scores) // 2
        median = scores[mid] if len(scores) % 2 else (scores[mid - 1] + scores[mid]) / 2
    return {
        "count": len(scores),
        "min": scores[0] if scores else None,
        "max": scores[-1] if scores else None,
        "median": median,
        "histogram": [{"lo": b, "hi": b + 1, "n": hist[b]} for b in sorted(hist)],
        "caught_at": [{"threshold": t, "n": sum(1 for s in scores if s >= t)} for t in ts],
    }


def calibration_summary(job_id: int, thresholds: Iterable[float] | None = None,
                        *, aged: str = "all", engine: Any = None) -> dict[str, Any]:
    """Histogram (1-point bins) and 'caught at threshold X' counts, for the
    final score (top level, unchanged keys) and for the blind score
    (`blind` sub-dict, same keys) - see BLIND_NOTE for why both.
    2.2 (B7): rows carry `aged` (scanned > aged_scan_hours after delivery,
    i.e. with SPF/DMARC replaced by the provider's delivery-time verdict).
    A calibration scans old mail, so normally every row is aged and the
    default keeps them all (aged='all'); 'exclude' / 'only' filter.
    Extra keys: aged_count, fresh_count, aged_filter."""
    eng = _eng(engine)
    rows: list[Any] = []
    if aged not in ("all", "exclude", "only"):
        aged = "all"
    try:
        with closing(_open_db(eng)) as conn:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(calibration_results)")}
            sel = "folder, final_score, symbols" + (", blind_score" if "blind_score" in cols else "") \
                + (", COALESCE(aged, 0) AS aged" if "aged" in cols else ", 0 AS aged")
            rows = conn.execute(
                f"SELECT {sel} FROM calibration_results WHERE job_id=? "
                "AND final_score IS NOT NULL", (int(job_id),)).fetchall()
    except sqlite3.Error:
        rows = []
    aged_count = sum(1 for r in rows if r["aged"])
    fresh_count = len(rows) - aged_count
    if aged == "exclude":
        rows = [r for r in rows if not r["aged"]]
    elif aged == "only":
        rows = [r for r in rows if r["aged"]]
    ts = list(thresholds) if thresholds is not None else [x / 2 for x in range(10, 31)]
    blind_fn = _blind_fn()
    finals: list[float] = []
    blinds: list[float] = []
    derived = False
    for r in rows:
        finals.append(float(r["final_score"]))
        b = r["blind_score"] if "blind_score" in r.keys() else None
        if b is None and blind_fn is not None:
            try:
                syms = json.loads(r["symbols"] or "[]")
            except (TypeError, ValueError):
                syms = []
            b = blind_fn(r["final_score"], syms)
            derived = True
        if b is not None:
            blinds.append(float(b))
    out = {"job_id": int(job_id), "folder": rows[0]["folder"] if rows else None}
    out.update(_score_stats(finals, ts))
    out["blind"] = _score_stats(blinds, ts)
    out["blind_from_symbols"] = derived
    out["blind_note"] = BLIND_NOTE
    out.update(aged_count=aged_count, fresh_count=fresh_count, aged_filter=aged)
    # 2.3 (B14): split by whether a known contact / reply / established
    # sender bonus (TH_KNOWN_CONTACT, TH_REPLY, ...) lowered the score.
    with_t: list[float] = []
    without_t: list[float] = []
    for r in rows:
        (with_t if _sym_names(r["symbols"]) & CONTACT_TRUST_SYMBOLS else without_t).append(
            float(r["final_score"]))
    out["trust"] = {"with_count": len(with_t), "without_count": len(without_t),
                    "with": _score_stats(with_t, ts), "without": _score_stats(without_t, ts),
                    "note": TRUST_SPLIT_NOTE}
    return out


CONTACT_TRUST_SYMBOLS = frozenset({"TH_KNOWN_CONTACT", "TH_KNOWN_DOMAIN", "TH_REPLY", "TH_REPLY_THREAD",
                                   "TH_ESTABLISHED"})
TRUST_SPLIT_NOTE = ("Opdelt efter, om mailen fik bonus som kendt kontakt, svar på din mail eller fast "
                    "afsender. Kendte kontakter er regnet med i den samlede score.")


# ---------------------------------------------------------------------------
# rspamd / Bayes
# ---------------------------------------------------------------------------


def _controller_url(eng: Any) -> str:
    return str(getattr(eng, "RSPAMD_LEARN_URL", None)
               or os.environ.get("RSPAMD_LEARN_URL", "http://spamfilter-rspamd:11334")).rstrip("/")


def _scanner_base(eng: Any) -> str:
    url = str(getattr(eng, "RSPAMD_SCAN_URL", None)
              or os.environ.get("RSPAMD_SCAN_URL", "http://spamfilter-rspamd:11333/checkv2"))
    return url.rsplit("/", 1)[0] if url.count("/") > 2 else url.rstrip("/")


def _controller_password(eng: Any) -> str:
    pw = str(getattr(eng, "RSPAMD_PASSWORD", "") or os.environ.get("RSPAMD_PASSWORD", "")).strip()
    if pw:
        return pw
    try:
        return (Path(eng.STATE_DIR) / "controller.password").read_text().strip()
    except OSError:
        return ""


def _http_get(url: str, *, headers: dict[str, str] | None = None,
              timeout: float = HTTP_TIMEOUT_S) -> tuple[int, Any]:
    """(status, parsed JSON or text). Network errors -> (0, None)."""
    try:
        r = requests.get(url, headers=headers or {}, timeout=timeout)
    except requests.RequestException:
        return 0, None
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text


def _stat_totals(eng: Any) -> dict[str, Any]:
    """Learn counts from the controller's /stat: the SUM over every Bayes
    user/pool rspamd knows (statfile revisions), not per pool."""
    min_learns = int(os.environ.get("BAYES_MIN_LEARNS", "200"))
    out: dict[str, Any] = {"ok": False, "spam_learned": 0, "ham_learned": 0,
                           "min_learns": min_learns, "users": 0}
    status, data = _http_get(f"{_controller_url(eng)}/stat",
                             headers={"Password": _controller_password(eng)})
    if status != 200 or not isinstance(data, dict):
        return out
    users = 0
    for sf in data.get("statfiles") or []:
        if not isinstance(sf, dict):
            continue
        try:
            learns = int(sf.get("revision") or sf.get("learns") or 0)
        except (TypeError, ValueError):
            learns = 0
        sym = str(sf.get("symbol") or "").upper()
        if sym.endswith("SPAM") or sf.get("is_spam") is True:
            out["spam_learned"] += learns
        elif sym.endswith("HAM") or sf.get("is_spam") is False:
            out["ham_learned"] += learns
        try:
            users = max(users, int(sf.get("users") or 0))
        except (TypeError, ValueError):
            pass
    out["users"] = users
    out["ok"] = True
    return out


def bayes_stats(*, engine: Any = None) -> dict[str, Any]:
    """Bayes learn counts. rspamd's /stat sums every pool; after a Bayes
    rebuild ('Byg Bayes op på ny') the counts of the ACTIVE pool are derived
    from the /stat totals recorded at each pool switch (counts_source
    'pool'); before any rebuild they are rspamd's totals ('rspamd').
    -> {ok, spam_learned, ham_learned (active pool), min_learns, users,
        pool, pools, all_pools_spam, all_pools_ham, counts_source
        ('rspamd'|'pool'|'all_pools'), active, text}"""
    eng = _eng(engine)
    out = _stat_totals(eng)
    out["all_pools_spam"], out["all_pools_ham"] = out["spam_learned"], out["ham_learned"]
    pool, pools = _active_pool(eng)
    out["pool"], out["pools"], out["counts_source"] = pool, pools, "rspamd"
    if out["ok"] and pool:
        counts = _pool_counts(eng, pool, out["spam_learned"], out["ham_learned"])
        if counts is not None:
            out["spam_learned"], out["ham_learned"] = counts
            out["counts_source"] = "pool"
        elif out["users"] > 1 and _has_switch_history(eng):
            # rspamd was unreachable at a switch: only the sum is known.
            out["counts_source"] = "all_pools"
    spam, ham, low = out["spam_learned"], out["ham_learned"], out["min_learns"]
    out["active"] = bool(out["ok"] and spam >= low and ham >= low)
    where = f" i puljen {pool}" if pool else ""
    if out["counts_source"] == "all_pools":
        where = " (alle Bayes-puljer tilsammen – tallet for den aktive pulje kendes ikke)"
    if not out["ok"]:
        out["text"] = "Bayes-tallene kunne ikke hentes fra rspamd."
    elif out["active"]:
        out["text"] = f"Bayes er aktiv: {_n_da(spam)} spam og {_n_da(ham)} legitime er lært{where}."
    else:
        out["text"] = (f"Bayes er ikke aktiv endnu: {_n_da(spam)} spam og {_n_da(ham)} legitime er lært{where}. "
                       f"rspamd bruger først Bayes, når der er lært mindst {_n_da(low)} af hver slags – "
                       "indtil da afgør filterets andre regler alene.")
    return out


def rspamd_health(*, engine: Any = None) -> dict[str, Any]:
    """Controller and scanner /ping with latency in ms."""
    eng = _eng(engine)
    out: dict[str, Any] = {"ok": False, "controller_ok": False, "scanner_ok": False,
                           "controller_ms": None, "scanner_ms": None, "text": ""}
    for key, url, headers in (
        ("controller", f"{_controller_url(eng)}/ping", {"Password": _controller_password(eng)}),
        ("scanner", f"{_scanner_base(eng)}/ping", {}),
    ):
        t0 = time.monotonic()
        status, body = _http_get(url, headers=headers)
        ok = status == 200 and "pong" in str(body).lower()
        out[f"{key}_ok"] = ok
        out[f"{key}_ms"] = int((time.monotonic() - t0) * 1000) if ok else None
    out["ok"] = out["controller_ok"] and out["scanner_ok"]
    out["text"] = ("rspamd svarer normalt." if out["ok"] else
                   "rspamd svarer ikke – scanning og læring er sat på pause.")
    return out


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------


def request_reload(reason: str, actor: str, *, engine: Any = None) -> bool:
    """Ask the engine to reload accounts.yml (touches the reload flag)."""
    eng = _eng(engine)
    try:
        eng.request_reload()
    except Exception as ex:
        log.warning("request_reload failed: %s", type(ex).__name__)
        return False
    try:
        with closing(_open_db(eng)) as conn:
            conn.execute(
                "INSERT INTO events(account, ts, message_id, event, detail) VALUES('*', ?, NULL, "
                "'reload_requested', ?)",
                (int(time.time()), f"{(reason or '')[:120]} actor={(actor or '')[:60]}"))
    except sqlite3.Error:
        pass  # the flag file is what matters
    return True


def known_providers(*, engine: Any = None) -> dict[str, dict[str, Any]]:
    """Mail domains with a known IMAP server (for the add-account wizard)."""
    return {k: dict(v) for k, v in KNOWN_PROVIDERS.items()}


def suggest_imap(email: str, *, engine: Any = None) -> dict[str, Any]:
    """Known provider for the address' domain, else a generic guess."""
    local, at, domain = (email or "").strip().lower().rpartition("@")
    if at and domain in KNOWN_PROVIDERS:
        return {**KNOWN_PROVIDERS[domain], "guess": False}
    if not (at and local) or "." not in domain or not _HOST_RE.match(domain):
        return {"imap_host": "", "imap_port": 993, "provider": None, "guess": True}
    return {"imap_host": f"imap.{domain}", "imap_port": 993, "provider": None, "guess": True}


def _read_state_json(eng: Any, name: str) -> tuple[dict[str, Any] | None, float | None]:
    path = Path(eng.STATE_DIR) / name
    try:
        data = json.loads(path.read_text())
        mtime = path.stat().st_mtime
    except (OSError, ValueError):
        return None, None
    return (data if isinstance(data, dict) else None), mtime


def host_status(*, engine: Any = None) -> dict[str, Any]:
    """host-status.json from the host monitor cron, plus `available`,
    `age_s` and `stale` (older than 15 min). Missing file -> available False."""
    eng = _eng(engine)
    data, mtime = _read_state_json(eng, "host-status.json")
    if data is None:
        return {"available": False, "stale": True, "age_s": None}
    ts = data.get("ts") or data.get("generated_at") or mtime
    try:
        age = max(0, int(time.time() - float(ts)))
    except (TypeError, ValueError):
        age = None
    out = dict(data)
    out.update(available=True, age_s=age, stale=age is None or age > HOST_STATUS_STALE_S)
    return out


def backup_status(*, engine: Any = None) -> dict[str, Any]:
    """backup-status.json written by backup-and-verify.sh (or available False)."""
    eng = _eng(engine)
    data, _mtime = _read_state_json(eng, "backup-status.json")
    if data is None:
        return {"available": False}
    out = dict(data)
    out["available"] = True
    try:
        out["age_s"] = max(0, int(time.time() - float(data.get("ts"))))
    except (TypeError, ValueError):
        out["age_s"] = None
    return out


# ===========================================================================
# 2.1: find a lost mail, bulk undo, threshold suggestion, digest, folder sizes
# ===========================================================================

import datetime as _dt  # noqa: E402
import email.header as _email_header  # noqa: E402
import inspect as _inspect  # noqa: E402
import threading as _threading  # noqa: E402

_clock = time.monotonic  # monkeypatched by tests

FIND_THROTTLE_S = 10
FIND_MAX_HITS = 20
FIND_MAX_FOLDERS = 15
FIND_DB_LIMIT = 50
FIND_TIMEOUT_S = 20
FIND_MAX_DAYS = 365

UNDO_CHUNK = 25
UNDO_MAX_ITEMS = 2000
UNDO_MAX_WINDOW_S = 92 * 86400
UNDO_INLINE_S = 20.0
UNDO_PER_SECOND = 10.0

FOLDER_SIZES_TTL_S = 600
FOLDER_SIZES_ERROR_TTL_S = 60

THRESHOLD_MIN = 6.0
THRESHOLD_MAX = 15.0
THRESHOLD_STEP = 0.5
SUGGEST_MIN_SCORED = 20
SUGGEST_MIN_MISSES = 2
SUGGEST_MAX_LOWER = 2.0
PROTECTED_SYMBOL = "TH_PROTECTED_RCPT"  # engine E9: decided by protected_threshold

_SPAM_LIKE_RE = re.compile(r"junk|spam|u[øo]nsket|unwanted|bulk", re.I)
_TRASH_LIKE_RE = re.compile(r"trash|papirkurv|deleted|slettet|slettede|\bbin\b", re.I)
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")

FIND_KINDS = ("inbox", "filter_junk", "provider_junk", "spam_like", "trash")
_KIND_RANK = {k: i for i, k in enumerate(FIND_KINDS)}


def _connect_kw(eng: Any, timeout: float | None) -> dict[str, Any]:
    if timeout is None:
        return {}
    try:
        params = _inspect.signature(eng.connect).parameters
    except (TypeError, ValueError):
        return {}
    if "timeout" in params or any(p.kind is p.VAR_KEYWORD for p in params.values()):
        return {"timeout": timeout}
    return {}


def _open_session(eng: Any, account: str, *, timeout: float | None = None) -> tuple[Any, Any]:
    """(account config, logged-in client) or ServiceError with Danish text."""
    try:
        acc = _find_account(eng, account)
    except Exception:
        raise ServiceError("config", "Konfigurationen kunne ikke indlæses.") from None
    if acc is None:
        raise ServiceError("no_account", "Kontoen findes ikke.")
    try:
        password = eng.read_secret(acc)
    except Exception:
        raise ServiceError("no_secret", "Adgangskoden til kontoen mangler.") from None
    try:
        client = eng.connect(acc, password=password, **_connect_kw(eng, timeout))
    except Exception as ex:
        log.warning("connect failed for %s: %s", account, type(ex).__name__)
        if isinstance(ex, LoginError):
            raise ServiceError("auth", _CONNECT_TEXT["auth"]) from None
        raise ServiceError("connect", "Kunne ikke forbinde til mailserveren.") from None
    return acc, client


def _logout(client: Any) -> None:
    try:
        client.logout()
    except Exception:
        pass


def _is_conn_error(ex: BaseException) -> bool:
    return isinstance(ex, (imaplib.IMAP4.abort, OSError)) or type(ex).__name__ == "IMAPClientAbortError"


def _decode_words(value: Any) -> str:
    """RFC 2047 encoded words (bytes/str) -> text; never raises."""
    if value is None:
        return ""
    text = value.decode("utf-8", "replace") if isinstance(value, (bytes, bytearray)) else str(value)
    try:
        return str(_email_header.make_header(_email_header.decode_header(text)))
    except Exception:
        return text


def folder_label(name: str) -> str:
    """Human folder name: IMAP modified UTF-7 decoded ('U&APg-nsket e-mail'
    -> 'Uønsket e-mail'); INBOX -> 'Indbakken'. IMAPClient normally decodes
    names already; this also covers raw names."""
    label = name
    if "&" in name:
        try:
            from imapclient import imap_utf7
            label = imap_utf7.decode(name.encode("ascii"))
        except Exception:
            label = name
    if label.upper() == "INBOX":
        return "Indbakken"
    return label


def _folder_explanation(kind: str, label: str) -> str:
    if kind == "inbox":
        return "Ligger i Indbakken – den er ikke flyttet."
    if kind == "filter_junk":
        return f"Ligger i {label} – spamfilteret har flyttet den hertil som spam."
    if kind == "provider_junk":
        return f"Ligger i {label} – mailudbyderens eget spamfilter har sorteret den fra."
    if kind == "spam_like":
        return f"Ligger i {label} – dit mailprogram har flyttet den."
    return f"Ligger i {label} – den er slettet i et mailprogram, men findes stadig."


def _find_folders(acc: Any, folders: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Folders find_mail searches (and the only ones move_found_to_inbox
    may move out of): INBOX, the filter's folder, the provider's spam
    folder, every spam-looking folder and the trash folders. Never Sent,
    Drafts, Archive or other user folders."""
    fmap = _folder_map(acc, folders)
    names = fmap["names"]
    picked: dict[str, str] = {}

    def add(name: str | None, kind: str) -> None:
        if name and name in names and name not in picked:
            picked[name] = kind

    add(fmap["inbox"], "inbox")
    add(fmap["junk"], "filter_junk")
    add(fmap.get("provider_junk"), "provider_junk")
    trash_special = _special(folders, "\\Trash")
    for f in folders:
        label = folder_label(f["name"])
        if f["name"] in picked:
            continue
        if any(x.lower() == "\\junk" for x in f["flags"]) or _SPAM_LIKE_RE.search(label):
            add(f["name"], "spam_like")
    add(trash_special, "trash")
    add(fmap["trash"], "trash")
    for f in folders:
        if f["name"] not in picked and _TRASH_LIKE_RE.search(folder_label(f["name"])):
            add(f["name"], "trash")
    out = [{"name": n, "label": folder_label(n), "kind": k} for n, k in picked.items()]
    out.sort(key=lambda d: (_KIND_RANK[d["kind"]], d["label"].lower()))
    return out[:FIND_MAX_FOLDERS]


def _clean_query(text: Any) -> str | None:
    if not isinstance(text, str):
        return None
    s = " ".join(text.split())
    if not 2 <= len(s) <= 100 or _CTRL_RE.search(s):
        return None
    return s


def _like(text: str) -> str:
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _db_find(eng: Any, account: str, text: str, since_ts: int,
             limit: int = FIND_DB_LIMIT) -> list[dict[str, Any]]:
    try:
        with closing(_open_db(eng)) as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM messages
                WHERE account=? AND COALESCE(received_at, first_seen) >= ?
                  AND (sender LIKE ? ESCAPE '\\' OR subject LIKE ? ESCAPE '\\'
                       OR envelope_from LIKE ? ESCAPE '\\')
                ORDER BY COALESCE(received_at, first_seen) DESC LIMIT ?
                """,
                (account, since_ts, _like(text), _like(text), _like(text), int(limit))).fetchall()
    except sqlite3.Error as ex:
        log.warning("find_mail DB lookup failed: %s", type(ex).__name__)
        return []
    keys = ("message_id", "sender", "subject", "envelope_from", "received_at", "first_seen",
            "current_folder", "our_action", "our_score", "user_verdict", "score_version")
    out = []
    for r in rows:
        d = {k: r[k] for k in keys}
        names = r.keys()
        d.update(_threat_fields(r["threat"] if "threat" in names else None,
                                r["threat_detail"] if "threat_detail" in names else None))
        out.append(d)
    return out


def _known_rows(eng: Any, account: str, mids: list[str]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    if not mids:
        return out
    try:
        with closing(_open_db(eng)) as conn:
            for i in range(0, len(mids), 500):
                chunk = mids[i:i + 500]
                for r in conn.execute(
                        f"SELECT * FROM messages "
                        f"WHERE account=? AND message_id IN ({','.join('?' * len(chunk))})",
                        (account, *chunk)):
                    names = r.keys()
                    out[r["message_id"]] = {
                        "message_id": r["message_id"], "our_action": r["our_action"],
                        "our_score": r["our_score"], "user_verdict": r["user_verdict"],
                        **_threat_fields(r["threat"] if "threat" in names else None,
                                         r["threat_detail"] if "threat_detail" in names else None)}
    except sqlite3.Error:
        pass
    return out


def _envelope_hit(uid: int, data: dict) -> dict[str, Any]:
    env = data.get(b"ENVELOPE")
    flags = {_to_str(f) for f in (data.get(b"FLAGS") or ())}
    subject = sender = sender_name = ""
    date_ts = None
    mid = None
    if env is not None:
        subject = _decode_words(getattr(env, "subject", None))[:300]
        frm = getattr(env, "from_", None) or ()
        if frm:
            a = frm[0]
            mbox, host = _to_str(a.mailbox or b""), _to_str(a.host or b"")
            sender = f"{mbox}@{host}" if mbox and host else mbox
            sender_name = _decode_words(a.name)[:200] if a.name else ""
        date_ts = _ts(getattr(env, "date", None))
        mid = normalize_message_id(_to_str(getattr(env, "message_id", None) or b""))
    return {
        "uid": int(uid), "message_id": mid, "subject": subject, "sender": sender[:200],
        "sender_name": sender_name, "date": date_ts,
        "received_at": _ts(data.get(b"INTERNALDATE")),
        "seen": "\\Seen" in flags, "deleted": "\\Deleted" in flags,
        "known": False, "our_action": None, "our_score": None, "user_verdict": None,
        "threat": None, "threat_text": "",
    }


def _search_folder(client: Any, text: str, since: _dt.date) -> list[int]:
    crit = ["SINCE", since, "OR", "FROM", text, "SUBJECT", text]
    try:
        return [int(u) for u in client.search(crit, charset="UTF-8")]
    except IMAPClientError:
        if not text.isascii():
            raise
        # A server without CHARSET UTF-8 support (BADCHARSET): plain ASCII
        # criteria need no charset.
        return [int(u) for u in client.search(crit)]


_find_lock = _threading.Lock()
_find_last: dict[str, float] = {}


def _throttle_find(account: str) -> float:
    """0 when a live search may start now (and records it), else seconds to wait."""
    now = _clock()
    with _find_lock:
        last = _find_last.get(account)
        if last is not None and now - last < FIND_THROTTLE_S:
            return round(FIND_THROTTLE_S - (now - last), 1)
        _find_last[account] = now
    return 0.0


def find_mail(account: str, text: str, since_days: int = 30, folders: Iterable[str] | None = None,
              *, live: bool = True, actor: str = "", engine: Any = None) -> dict[str, Any]:
    """Look for a lost mail by sender or subject.

    Always: database lookup (scored/seen mail, `db`). With live=True also a
    READ-ONLY search of the mailbox (EXAMINE + UID SEARCH CHARSET UTF-8
    SINCE <d> OR FROM x SUBJECT x) in INBOX, the filter's folder, the
    provider's spam folder, spam-looking folders and trash (see
    _find_folders); `folders` narrows that set (other names are ignored).
    At most 20 hits per folder (newest first), fetching only ENVELOPE,
    INTERNALDATE and FLAGS. One live search per account per 10 s.
    When the mailbox search finds nothing, `hints` holds plain-Danish next
    steps (longer period, Scannet's SpamExperts quarantine for Scannet
    accounts, search tips). Never raises; errors come back as ok False +
    code + Danish text."""
    eng = _eng(engine)
    q = _clean_query(text)
    try:
        days = max(1, min(FIND_MAX_DAYS, int(since_days)))
    except (TypeError, ValueError):
        days = 30
    since_date = _dt.date.today() - _dt.timedelta(days=days)
    since_ts = int(time.time()) - days * 86400
    out: dict[str, Any] = {
        "ok": False, "code": "invalid", "text": "Skriv mindst 2 tegn (afsender eller emne).",
        "account": account, "query": q or "", "since_days": days,
        "since": since_date.isoformat(), "live": bool(live), "searched_at": int(time.time()),
        "db": [], "folders": [], "searched": [], "errors": [], "total": 0,
        "retry_after": 0, "audit_detail": "", "hints": [], "spamexperts": False,
    }
    if q is None:
        out["audit_detail"] = "invalid query"
        return out
    out["db"] = _db_find(eng, account, q, since_ts)
    out["audit_detail"] = f"q={q[:60]!r} days={days} db={len(out['db'])}"
    if not live:
        out.update(ok=True, code="ok", text=_find_text(out))
        return out
    wait = _throttle_find(account)
    if wait:
        out.update(code="throttled", retry_after=wait,
                   text=f"Vent {int(wait + 0.99)} sekunder før næste søgning i postkassen.")
        out["audit_detail"] += " throttled"
        return out
    try:
        acc, client = _open_session(eng, account, timeout=FIND_TIMEOUT_S)
    except ServiceError as ex:
        out.update(code=ex.code, text=ex.text)
        out["audit_detail"] += f" error={ex.code}"
        return out
    try:
        try:
            targets = _find_folders(acc, _list_folders(client))
        except Exception as ex:
            log.warning("find_mail LIST failed: %s", type(ex).__name__)
            out.update(code="imap_error", text="Mappelisten kunne ikke hentes fra mailserveren.")
            out["audit_detail"] += " error=imap_error"
            return out
        wanted = {str(f) for f in folders} if folders is not None else None
        if wanted is not None:
            targets = [t for t in targets if t["name"] in wanted]
        for t in targets:
            group = {**t, "explanation": _folder_explanation(t["kind"], t["label"]),
                     "can_move": t["kind"] != "inbox", "count": 0, "truncated": False, "hits": []}
            try:
                client.select_folder(t["name"], readonly=True)  # EXAMINE: never writes
                uids = sorted(set(_search_folder(client, q, since_date)))
                group["count"] = len(uids)
                newest = list(reversed(uids[-FIND_MAX_HITS:]))
                group["truncated"] = len(uids) > FIND_MAX_HITS
                if newest:
                    data = client.fetch(newest, [b"ENVELOPE", b"INTERNALDATE", b"FLAGS"])
                    group["hits"] = [_envelope_hit(u, data[u]) for u in newest if u in data]
                    if hasattr(eng, 'mailidentity'):
                        with closing(_open_db(eng)) as conn:
                            for hit in group['hits']:
                                raw, _flags = _fetch_body(client, hit['uid'], eng.MAX_FETCH_BYTES)
                                if raw is None:
                                    hit['message_id'] = None
                                    continue
                                wire = eng.parse_envelope(raw)[0]
                                legacy = bool(wire and conn.execute(
                                    'SELECT 1 FROM messages WHERE account=? AND message_id=?',
                                    (acc.name, wire)).fetchone()
                                    and mailidentity.binding(conn, acc.name, wire) is None)
                                hit['message_id'] = mailidentity.bind(conn, acc.name, wire, raw,
                                                                     legacy_exists=legacy)
                            conn.commit()
            except Exception as ex:
                log.info("find_mail in %s failed: %s", t["name"], type(ex).__name__)
                out["errors"].append({"folder": t["name"], "label": t["label"],
                                      "text": "Mappen kunne ikke gennemsøges."})
                if _is_conn_error(ex):
                    break
                continue
            out["searched"].append(t["label"])
            out["folders"].append(group)
    finally:
        _logout(client)

    mids = [h["message_id"] for g in out["folders"] for h in g["hits"] if h["message_id"]]
    known = _known_rows(eng, account, mids)
    for g in out["folders"]:
        for h in g["hits"]:
            row = known.get(h["message_id"] or "")
            if row:
                h.update(known=True, our_action=row["our_action"], our_score=row["our_score"],
                         user_verdict=row["user_verdict"], threat=row["threat"],
                         threat_text=row["threat_text"])
            h["can_move"] = bool(g["can_move"] and h["message_id"])
    out["total"] = sum(len(g["hits"]) for g in out["folders"])
    out["folders"].sort(key=lambda g: (not g["hits"], _KIND_RANK[g["kind"]]))
    if not out["total"]:
        out["spamexperts"] = _spamexperts_in_front(eng, acc)
        out["hints"] = _find_hints(acc, days, spamexperts=out["spamexperts"])
    out.update(ok=True, code="ok" if not out["errors"] else "partial", text=_find_text(out))
    out["audit_detail"] += f" folders={len(out['searched'])} hits={out['total']}"
    return out


def _is_scannet(acc: Any) -> bool:
    host = str(getattr(acc, "imap_host", "") or "").lower()
    return host == "scannet.dk" or host.endswith(".scannet.dk")


def _spamexperts_in_front(eng: Any, acc: Any) -> bool:
    """2.11.1: a Scannet mailbox whose domain's MX (newest Mailsikkerhed run)
    still points at SpamExperts. The owner cancelled SpamExperts on
    2026-11-03, so the quarantine tip is shown only while it is true."""
    if not _is_scannet(acc):
        return False
    try:
        import mailcheck

        with closing(_open_db_ro(eng)) as conn:
            return mailcheck.spamexperts_in_front(conn, str(getattr(acc, "user", "") or "").rpartition("@")[2])
    except Exception as ex:  # noqa: BLE001 - a hint never breaks the search
        log.info("SpamExperts MX lookup failed: %s", type(ex).__name__)
        return False


def _find_hints(acc: Any, days: int, *, spamexperts: bool = False) -> list[str]:
    """Plain-Danish next steps when the mailbox search found nothing.
    spamexperts: the mailbox's domain still has SpamExperts in front."""
    hints = []
    if days < FIND_MAX_DAYS:
        hints.append(f"Mailen kan være ældre end {days} dage – prøv en længere periode.")
    if spamexperts and _is_scannet(acc):
        hints.append("Scannets spamfilter (SpamExperts) kan have stoppet mailen, før den nåede "
                     "postkassen – tjek karantænen hos Scannet.")
    hints.append("Søg på en del af afsenderens adresse eller domæne (fx firma.dk) eller på et "
                 "ord fra emnet.")
    hints.append("Spørg afsenderen, hvilken adresse mailen blev sendt til – den kan være sendt "
                 "til en anden postkasse.")
    return hints


def _find_text(res: dict[str, Any]) -> str:
    n_db = len(res["db"])
    if not res["live"]:
        return (f"{n_db} besked{'er' if n_db != 1 else ''} fundet i filterets oversigt."
                if n_db else "Ingen beskeder i filterets oversigt matcher.")
    total = res["total"]
    where = [g["label"] for g in res["folders"] if g["hits"]]
    if total:
        text = f"{total} mail{'s' if total != 1 else ''} fundet i postkassen ({', '.join(where)})."
    else:
        text = (f"Ingen mails i postkassen matcher de seneste {res['since_days']} dage "
                f"(søgt i {', '.join(res['searched']) or 'ingen mapper'}).")
    if res["errors"]:
        text += " Nogle mapper kunne ikke gennemsøges."
    return text


# ---------------------------------------------------------------------------
# Moving mail back into the inbox (find_mail hits, bulk undo)
# ---------------------------------------------------------------------------

_SNAPSHOT_COLS = ("current_folder", "our_action", "user_verdict", "verdict_at", "verdict_by",
                  "pending_learn", "pending_learn_at", "last_seen")


def _premark_inbox(db: Any, acc: Any, mid: str, *, inbox: str, verdict: str | None,
                   by: str, sender: str | None, subject: str | None,
                   received_at: int | None) -> dict[str, Any] | None:
    """Record the mail as back in the inbox BEFORE the IMAP move, so the
    engine (which may see the new inbox UID at any moment) treats it as a
    sticky manual release instead of a user rescue (which would learn ham
    on its own) or new mail. Returns the previous row values for _restore
    (None = the row did not exist)."""
    now = int(time.time())
    conn = db.conn
    prev = conn.execute(
        f"SELECT {', '.join(_SNAPSHOT_COLS)} FROM messages WHERE account=? AND message_id=?",
        (acc.name, mid)).fetchone()
    snapshot = dict(prev) if prev is not None else None
    with db.tx():
        retained_threat, retained_detail = _threat_of(conn, acc.name, mid)
        conn.execute(
            """
            INSERT INTO messages(account, message_id, first_seen, last_seen, current_folder,
                                 sender, subject, received_at, our_action, origin)
            VALUES(?,?,?,?,?,?,?,?, 'manual_release', 'manual')
            ON CONFLICT(account, message_id) DO UPDATE SET
                last_seen=excluded.last_seen, current_folder=excluded.current_folder,
                our_action='manual_release',
                sender=COALESCE(messages.sender, excluded.sender),
                subject=COALESCE(messages.subject, excluded.subject),
                received_at=COALESCE(messages.received_at, excluded.received_at)
            """,
            (acc.name, mid, now, now, inbox, sender or None, subject or None, received_at))
        # A pending spam learn (user_junked earlier) is obsolete now.
        conn.execute(
            "UPDATE messages SET pending_learn=NULL, pending_learn_at=NULL "
            "WHERE account=? AND message_id=? AND pending_learn='spam'", (acc.name, mid))
        if verdict:
            conn.execute(
                "UPDATE messages SET user_verdict=?, verdict_at=?, verdict_by=? "
                "WHERE account=? AND message_id=?", (verdict, now, by or None, acc.name, mid))
        else:
            conn.execute("UPDATE messages SET verdict_by=COALESCE(verdict_by, ?) "
                         "WHERE account=? AND message_id=?", (by or None, acc.name, mid))
        conn.execute("DELETE FROM pending_move WHERE account=? AND message_id=?", (acc.name, mid))
        if retained_threat:
            # Keep known danger on an alias before the inbox worker sees
            # the move. A later mail-program rescue must not learn it ham.
            conn.execute('UPDATE messages SET threat=?, threat_detail=? WHERE account=? AND message_id=?',
                         (retained_threat, retained_detail, acc.name, mid))
    return snapshot


def _restore(db: Any, acc: Any, mid: str, snapshot: dict[str, Any] | None) -> None:
    try:
        with db.tx():
            if snapshot is None:
                db.conn.execute("DELETE FROM messages WHERE account=? AND message_id=?",
                                (acc.name, mid))
            else:
                db.conn.execute(
                    f"UPDATE messages SET {', '.join(c + '=?' for c in _SNAPSHOT_COLS)} "
                    "WHERE account=? AND message_id=?",
                    (*[snapshot[c] for c in _SNAPSHOT_COLS], acc.name, mid))
    except Exception as ex:
        log.error("could not restore row after failed move: %s", type(ex).__name__)


def _after_learn(db: Any, acc: Any, mid: str, outcome: str) -> None:
    now = int(time.time())
    with db.tx():
        if outcome in ("learned", "already"):
            db.conn.execute(
                "UPDATE messages SET learned_as='ham', learned_at=COALESCE(learned_at, ?), "
                "pending_learn=NULL, pending_learn_at=NULL WHERE account=? AND message_id=?",
                (now, acc.name, mid))
        elif outcome in ("error", "rate_limited"):
            # The engine retries pending learns.
            db.conn.execute(
                "UPDATE messages SET pending_learn='ham', pending_learn_at=? "
                "WHERE account=? AND message_id=?", (now, acc.name, mid))


def _bind_selected(eng: Any, db: Any, acc: Any, mid: str, raw: bytes | None) -> bool:
    """Bind the explicit selection before an inbox worker can observe its move."""
    if raw is None:
        return False
    wire = eng.parse_envelope(raw)[0]
    with db.tx():
        return mailidentity.bind(db.conn, acc.name, wire, raw) == mid


def _move_one_to_inbox(eng: Any, db: Any, acc: Any, client: Any, fmap: dict[str, Any],
                       caps: frozenset, folder: str, uid: int, mid: str, *, learn: bool,
                       verdict: str | None, by: str, actor: str, event: str, detail: str,
                       stat: str | None, reason: str) -> tuple[bool, str, str | None]:
    """Selected folder = `folder` (read-write). Moves exactly `uid` to the
    inbox. Returns (moved, code, learn outcome or None)."""
    meta = client.fetch([uid], [b"FLAGS", b"RFC822.SIZE", b"INTERNALDATE",
                                b"BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)]"]).get(uid)
    if not meta:
        return False, "not_found", None
    flags = {_to_str(f) for f in (meta.get(b"FLAGS") or ())}
    sender = subject = None
    try:
        hdr = next((bytes(v) for k, v in meta.items()
                    if isinstance(k, bytes) and k.upper().startswith(b"BODY[HEADER")), b"")
        _m, subject, sender = eng.parse_envelope(hdr)
    except Exception:
        pass
    raw = None
    if learn or hasattr(eng, 'mailidentity'):
        raw, _f = _fetch_body(client, uid, eng.MAX_FETCH_BYTES)
    if hasattr(eng, 'mailidentity') and not _bind_selected(eng, db, acc, mid, raw):
        return False, "identity_changed", None
    snapshot = _premark_inbox(db, acc, mid, inbox=fmap["inbox"], verdict=verdict, by=by,
                              sender=sender, subject=subject,
                              received_at=_ts(meta.get(b"INTERNALDATE")))
    try:
        if "\\Deleted" in flags:
            # Marked deleted by a client but not purged: it would arrive
            # deleted and vanish at the next purge. The explicit move wins.
            client.remove_flags([uid], ["\\Deleted"])
        eng.imap_move(client, [uid], fmap["inbox"], capabilities=caps)
        code = "ok"
    except Exception as ex:
        if getattr(ex, "copied", False):
            # UIDPLUS: the COPY reached the inbox, only STORE/EXPUNGE of the
            # source failed (imap_move cleared its \Deleted again). The mail
            # IS in the inbox: keep the release bookkeeping - restoring
            # the old row would make the engine treat the inbox copy as a
            # user rescue. A harmless duplicate stays in the source folder.
            log.warning("move to inbox: copied, source kept: %s", type(ex).__name__)
            code = "copied"
        else:
            log.warning("move to inbox failed: %s", type(ex).__name__)
            _restore(db, acc, mid, snapshot)
            if _is_conn_error(ex):
                raise
            return False, "move_failed", None
    with db.tx():
        db.log_event(event, mid, detail=(detail + (" source_kept" if code == "copied" else ""))[:300])
    if stat:
        try:
            eng.bump_stat(db.conn, acc.name, stat)
        except Exception as ex:
            log.warning("bump_stat(%s) failed: %s", stat, type(ex).__name__)
    outcome = None
    if learn:
        outcome = _learn(eng, db, acc, raw, "ham", mid, actor, reason)
        _after_learn(db, acc, mid, outcome)
    return True, code, outcome


def move_found_to_inbox(account: str, folder: str, message_id: str, actor: str, *,
                        learn: bool = False, engine: Any = None, is_admin: bool = False,
                        confirm_threat: bool = False) -> dict[str, Any]:
    """Move exactly one mail (exact Message-ID) from a folder find_mail
    searches (never from anywhere else) back to the inbox. Sets the sticky
    user verdict ham; learns ham only with learn=True. Never raises.
    Returns {ok, code, text, message_id, folder, label, learned, audit_detail}.
    2.3 (B16): a mail stored with a threat class needs is_admin and
    confirm_threat (codes 'threat_admin' / 'threat_confirm' otherwise, plus
    threat / threat_text / confirm_text) and is never learned as ham."""
    eng = _eng(engine)
    mid = normalize_message_id(message_id)
    out: dict[str, Any] = {"ok": False, "code": "invalid_id", "text": "Ugyldigt Message-ID.",
                           "message_id": message_id, "folder": folder,
                           "label": folder_label(str(folder or "")), "learned": None,
                           "audit_detail": f"folder={str(folder)[:80]!r} learn={int(bool(learn))}"}
    if mid is None:
        return out
    try:
        acc, client = _open_session(eng, account, timeout=FIND_TIMEOUT_S)
    except ServiceError as ex:
        out.update(code=ex.code, text=ex.text)
        return out
    db = None
    try:
        try:
            listing = _list_folders(client)
            fmap = _folder_map(acc, listing)
            allowed = {t["name"]: t for t in _find_folders(acc, listing)}
        except Exception as ex:
            log.warning("move_found LIST failed: %s", type(ex).__name__)
            out.update(code="imap_error", text="Mappelisten kunne ikke hentes fra mailserveren.")
            return out
        target = allowed.get(folder)
        if target is None or target["kind"] == "inbox":
            out.update(code="folder_not_allowed",
                       text="Mails kan kun flyttes tilbage fra spam-mapper og papirkurven.")
            return out
        caps = _caps_for_engine(_caps(client))
        client.select_folder(folder, readonly=False)
        uids = list(eng.find_uids_by_message_id(client, mid) or [])
        if len(uids) > 1 and target["kind"] == "filter_junk":
            uids = [u for u in [_pick_duplicate(client, uids)] if u is not None] or uids
        if not uids:
            out.update(code="not_found", text="Mailen findes ikke længere i mappen.")
            return out
        if len(uids) > 1:
            out.update(code="ambiguous", text="Flere mails har samme Message-ID – intet er ændret.")
            return out
        db = eng.Db(acc.name)
        threat, tdetail = _threat_of(db.conn, acc.name, mid)
        gate = threat_gate(threat, tdetail, is_admin=is_admin, confirm_threat=confirm_threat)
        if gate is not None:
            with db.tx():
                db.log_event("threat_release_refused", mid,
                             detail=f"{threat} found_to_inbox {gate['code']} actor={actor}"[:300])
            out.update(code=gate["code"], text=gate["text"], threat=gate["threat"],
                       threat_text=gate["threat_text"], confirm_text=gate["confirm_text"])
            out["audit_detail"] += f" refused={gate['code']}"
            return out
        if threat:
            learn = False  # B16: never learned as ham
            with db.tx():
                db.log_event("threat_release", mid, detail=f"{threat} found_to_inbox actor={actor}"[:300])
            out.update(_threat_fields(threat, tdetail))
        moved, code, outcome = _move_one_to_inbox(
            eng, db, acc, client, fmap, caps, folder, uids[0], mid, learn=bool(learn),
            verdict="ham", by=actor, actor=actor, event="found_to_inbox",
            detail=f"from {folder} actor={actor}",
            stat="released" if target["kind"] == "filter_junk" else None,
            reason="manual_release")
        if not moved:
            out.update(code=code, text="Mailen kunne ikke flyttes til indbakken."
                       if code == "move_failed" else "Mailen findes ikke længere i mappen.")
            return out
        text = f"Flyttet fra {target['label']} til indbakken"
        if code == "copied":
            text = f"Kopieret fra {target['label']} til indbakken (originalen blev liggende)"
        if outcome is None:
            text += "."
        elif outcome == "learned":
            text += " og lært som legitim."
        elif outcome == "already":
            text += " og lært som legitim (var allerede lært)."
        else:
            text += _learn_note(outcome, "ham")
        out.update(ok=True, code=("copied" if code == "copied" else "ok")
                   if outcome in (None, "learned", "already") else f"learn_{outcome}",
                   text=text, learned=outcome, message_id=mid)
        out["audit_detail"] += " moved"
        return out
    except Exception as ex:
        log.warning("move_found_to_inbox failed: %s", type(ex).__name__)
        out.update(code="imap_error", text="Mailserveren afviste handlingen.")
        return out
    finally:
        if db is not None:
            try:
                db.close()
            except Exception:
                pass
        _logout(client)


# ---------------------------------------------------------------------------
# Bulk undo of filter moves (undo_jobs / undo_items, resumable)
# ---------------------------------------------------------------------------

UNDO_SCHEMA = """
CREATE TABLE IF NOT EXISTS undo_jobs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account     TEXT NOT NULL,
    since_ts    INTEGER NOT NULL,
    until_ts    INTEGER NOT NULL,
    learn       INTEGER NOT NULL DEFAULT 0,
    status      TEXT NOT NULL DEFAULT 'queued',  -- queued|running|done|failed|cancelled|cancel_requested
    total       INTEGER NOT NULL DEFAULT 0,
    processed   INTEGER NOT NULL DEFAULT 0,
    moved       INTEGER NOT NULL DEFAULT 0,
    not_found   INTEGER NOT NULL DEFAULT 0,
    skipped     INTEGER NOT NULL DEFAULT 0,
    failed      INTEGER NOT NULL DEFAULT 0,
    learned     INTEGER NOT NULL DEFAULT 0,
    error       TEXT,
    created_by  TEXT,
    created_at  INTEGER NOT NULL,
    started_at  INTEGER,
    finished_at INTEGER
);
CREATE TABLE IF NOT EXISTS undo_items (
    job_id      INTEGER NOT NULL,
    message_id  TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',  -- pending|moved|not_found|skipped|failed
    code        TEXT,
    updated_at  INTEGER,
    PRIMARY KEY (job_id, message_id)
);
CREATE INDEX IF NOT EXISTS idx_undo_items_status ON undo_items(job_id, status);
CREATE INDEX IF NOT EXISTS idx_undo_jobs_status ON undo_jobs(status, created_at);
"""

_undo_schema_ok: set[str] = set()
_undo_threads: dict[int, _threading.Thread] = {}


def ensure_undo_schema(conn: sqlite3.Connection) -> None:
    """Additive, idempotent (new tables only; older versions ignore them)."""
    key = str(conn.execute("PRAGMA database_list").fetchone()[2])
    if key in _undo_schema_ok:
        return
    conn.executescript(UNDO_SCHEMA)
    _undo_schema_ok.add(key)


def _undo_rows(conn: sqlite3.Connection, account: str, since_ts: int, until_ts: int, *,
               threats: bool = False) -> list[Any]:
    """Mail the filter moved in the window. B16: threat mail (virus,
    phishing/malware link, dangerous attachment) is never part of a bulk
    undo - threats=True returns exactly those rows instead."""
    has_threat = "threat" in _columns(conn, "messages")
    if not has_threat:
        if threats:
            return []
        cond = ""
    else:
        cond = (" AND threat IS NOT NULL AND threat != ''" if threats
                else " AND (threat IS NULL OR threat = '')")
    return conn.execute(
        f"""
        SELECT message_id, sender, subject, our_score, moved_to_junk_at, current_folder
        FROM messages
        WHERE account=? AND our_action='moved_to_junk' AND moved_to_junk_at IS NOT NULL
          AND moved_to_junk_at >= ? AND moved_to_junk_at <= ?{cond}
        ORDER BY moved_to_junk_at, message_id
        """, (account, int(since_ts), int(until_ts))).fetchall()


def _undo_window(since_ts: Any, until_ts: Any) -> tuple[int, int]:
    try:
        a, b = int(since_ts), int(until_ts)
    except (TypeError, ValueError):
        raise ValueError("Ugyldig periode.") from None
    if a >= b:
        raise ValueError("Perioden skal slutte efter den starter.")
    if b - a > UNDO_MAX_WINDOW_S:
        raise ValueError("Perioden må højst være 3 måneder.")
    return a, b


def preview_undo(account: str, since_ts: int, until_ts: int, *, sample: int = 50,
                 engine: Any = None) -> dict[str, Any]:
    """What undo_moves would do (DB only, no IMAP): mail the filter moved
    to its spam folder in [since_ts, until_ts] that is still recorded there.
    {ok, code, text, account, since_ts, until_ts, count, gone, items:[...]}"""
    eng = _eng(engine)
    out: dict[str, Any] = {"ok": False, "code": "invalid", "text": "", "account": account,
                           "since_ts": since_ts, "until_ts": until_ts, "count": 0, "gone": 0,
                           "too_many": False, "items": [], "threats": 0}
    try:
        a, b = _undo_window(since_ts, until_ts)
    except ValueError as ex:
        out["text"] = str(ex)
        return out
    try:
        with closing(_open_db(eng)) as conn:
            rows = _undo_rows(conn, account, a, b)
            n_threats = sum(1 for r in _undo_rows(conn, account, a, b, threats=True)
                            if r["current_folder"] != "gone")
    except sqlite3.Error:
        out.update(code="db_error", text="Databasen kunne ikke læses.")
        return out
    out["threats"] = n_threats
    live = [r for r in rows if r["current_folder"] != "gone"]
    out.update(ok=True, code="ok", count=len(live), gone=len(rows) - len(live),
               too_many=len(live) > UNDO_MAX_ITEMS,
               items=[{k: r[k] for k in ("message_id", "sender", "subject", "our_score",
                                         "moved_to_junk_at")} for r in live[:max(0, int(sample))]])
    if not live:
        out["text"] = "Filteret har ikke flyttet nogen mails i perioden."
    else:
        out["text"] = (f"{len(live)} mail{'s' if len(live) != 1 else ''}, som filteret flyttede til "
                       f"Spamfilter-mappen i perioden, flyttes tilbage til indbakken.")
        if out["too_many"]:
            out["text"] += f" Højst {UNDO_MAX_ITEMS} ad gangen – vælg en kortere periode."
    if out["gone"]:
        out["text"] += f" {out['gone']} er allerede væk fra mappen og springes over."
    if n_threats:
        out["text"] += (f" {n_threats} farlig{'e' if n_threats != 1 else ''} mail{'s' if n_threats != 1 else ''} "
                        "(virus, phishing eller farlig vedhæftning) flyttes ikke tilbage – en administrator "
                        "kan frigive dem én ad gangen.")
    return out


def _undo_counts(conn: sqlite3.Connection, job_id: int) -> dict[str, int]:
    c = {"total": 0, "processed": 0, "moved": 0, "not_found": 0, "skipped": 0, "failed": 0}
    for r in conn.execute("SELECT status, COUNT(*) AS n FROM undo_items WHERE job_id=? GROUP BY status",
                          (job_id,)):
        c["total"] += r["n"]
        if r["status"] != "pending":
            c["processed"] += r["n"]
        if r["status"] in c:
            c[r["status"]] += r["n"]
    return c


def _write_undo_counts(conn: sqlite3.Connection, job_id: int, learned: int | None = None) -> None:
    c = _undo_counts(conn, job_id)
    conn.execute(
        "UPDATE undo_jobs SET total=?, processed=?, moved=?, not_found=?, skipped=?, failed=?"
        + (", learned=learned+?" if learned else "") + " WHERE id=?",
        (c["total"], c["processed"], c["moved"], c["not_found"], c["skipped"], c["failed"],
         *([learned] if learned else []), job_id))


def _undo_job_dict(row: Any) -> dict[str, Any]:
    d = dict(row)
    total = d.get("total") or 0
    d["percent"] = int(min(100, (d.get("processed") or 0) * 100 / total)) if total else (
        100 if d.get("status") == "done" else 0)
    d["remaining"] = max(0, total - (d.get("processed") or 0))
    d["learn"] = bool(d.get("learn"))
    d["text"] = _undo_text(d)
    return d


_UNDO_STATUS_TEXT = {
    "queued": "Venter", "running": "I gang", "done": "Færdig", "failed": "Fejlede",
    "cancelled": "Annulleret", "cancel_requested": "Annulleres…",
}


def _undo_text(d: dict[str, Any]) -> str:
    st = d.get("status")
    if st == "failed" and d.get("error"):
        return f"{d['error']} {d.get('moved', 0)} af {d.get('total', 0)} er flyttet tilbage."
    parts = [f"{d.get('moved', 0)} af {d.get('total', 0)} flyttet tilbage til indbakken"]
    if d.get("not_found"):
        parts.append(f"{d['not_found']} fandtes ikke længere")
    if d.get("skipped"):
        parts.append(f"{d['skipped']} sprunget over")
    if d.get("failed"):
        parts.append(f"{d['failed']} fejlede")
    if d.get("learn") and d.get("learned"):
        parts.append(f"{d['learned']} lært som legitim")
    return f"{_UNDO_STATUS_TEXT.get(st, st)}: " + ", ".join(parts) + "."


def undo_job(job_id: int, *, engine: Any = None) -> dict[str, Any] | None:
    """One undo job with counts, `percent`, `remaining`, Danish `text`."""
    eng = _eng(engine)
    try:
        with closing(_open_db(eng)) as conn:
            ensure_undo_schema(conn)
            row = conn.execute("SELECT * FROM undo_jobs WHERE id=?", (int(job_id),)).fetchone()
    except sqlite3.Error:
        return None
    return _undo_job_dict(row) if row is not None else None


def list_undo_jobs(account: str | None = None, limit: int = 20, *,
                   engine: Any = None) -> list[dict[str, Any]]:
    eng = _eng(engine)
    limit = max(1, min(int(limit or 20), 200))
    try:
        with closing(_open_db(eng)) as conn:
            ensure_undo_schema(conn)
            if account is None:
                rows = conn.execute("SELECT * FROM undo_jobs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM undo_jobs WHERE account=? ORDER BY id DESC LIMIT ?",
                                    (account, limit)).fetchall()
    except sqlite3.Error:
        return []
    return [_undo_job_dict(r) for r in rows]


def cancel_undo_job(job_id: int, *, engine: Any = None) -> bool:
    """Queued -> cancelled at once; running -> stops after the current chunk.
    Mail already moved stays in the inbox."""
    eng = _eng(engine)
    now = int(time.time())
    with closing(_open_db(eng)) as conn:
        ensure_undo_schema(conn)
        cur = conn.execute("UPDATE undo_jobs SET status='cancelled', finished_at=? "
                           "WHERE id=? AND status IN ('queued','failed')", (now, int(job_id)))
        if cur.rowcount:
            return True
        cur = conn.execute("UPDATE undo_jobs SET status='cancel_requested' WHERE id=? AND status='running'",
                           (int(job_id),))
        return bool(cur.rowcount)


def recover_undo_jobs(*, engine: Any = None) -> None:
    """Startup (trainer thread): 'running' jobs were interrupted -> queued
    (they resume where they stopped: finished items are kept)."""
    eng = _eng(engine)
    with closing(_open_db(eng)) as conn:
        ensure_undo_schema(conn)
        conn.execute("UPDATE undo_jobs SET status='queued' WHERE status='running'")
        conn.execute("UPDATE undo_jobs SET status='cancelled', finished_at=? "
                     "WHERE status='cancel_requested'", (int(time.time()),))


def undo_moves(account: str, since_ts: int, until_ts: int, actor: str, learn: bool = False,
               *, wait_s: float = UNDO_INLINE_S, engine: Any = None) -> dict[str, Any]:
    """Move everything the filter moved to its spam folder in
    [since_ts, until_ts] back to the inbox, by exact Message-ID, in chunks.

    The mail list is snapshotted into undo_items; the job runs inline for
    up to `wait_s` seconds and then continues in a background thread (and
    after a restart in the trainer thread), resuming where it stopped.
    learn=False (default): nothing is learned and no user verdict is set -
    the rows only become sticky manual releases so the filter never moves
    them again. learn=True: user_verdict ham + learn ham (pending if the
    hourly learn cap is reached). Never raises.
    Returns {ok, code, text, job_id, status, total, moved, not_found,
    skipped, failed, learned, remaining, percent, audit_detail}."""
    eng = _eng(engine)
    base: dict[str, Any] = {"ok": False, "code": "invalid", "text": "", "job_id": None,
                            "status": None, "total": 0, "moved": 0, "not_found": 0, "skipped": 0,
                            "failed": 0, "learned": 0, "remaining": 0, "percent": 0,
                            "audit_detail": ""}
    try:
        a, b = _undo_window(since_ts, until_ts)
    except ValueError as ex:
        base["text"] = str(ex)
        return base
    try:
        acc = _find_account(eng, account)
    except Exception:
        return {**base, "code": "config", "text": "Konfigurationen kunne ikke indlæses."}
    if acc is None:
        return {**base, "code": "no_account", "text": "Kontoen findes ikke."}
    now = int(time.time())
    with closing(_open_db(eng)) as conn:
        ensure_undo_schema(conn)
        conn.execute("BEGIN IMMEDIATE")  # busy check + insert are one step
        try:
            busy = conn.execute(
                "SELECT id FROM undo_jobs WHERE account=? AND status IN ('queued','running','cancel_requested')",
                (account,)).fetchone()
            rows = [r for r in _undo_rows(conn, account, a, b) if r["current_folder"] != "gone"]
            refuse = None
            if busy is not None:
                refuse = {**base, "code": "busy", "job_id": int(busy["id"]),
                          "text": "En fortrydelse kører allerede for denne konto – vent til den er færdig."}
            elif not rows:
                refuse = {**base, "ok": True, "code": "nothing", "status": "done",
                          "text": "Filteret har ikke flyttet nogen mails i perioden.",
                          "audit_detail": f"since={a} until={b} total=0"}
            elif len(rows) > UNDO_MAX_ITEMS:
                refuse = {**base, "code": "too_many",
                          "text": f"{len(rows)} mails i perioden – højst {UNDO_MAX_ITEMS} ad gangen. "
                                  "Vælg en kortere periode."}
            if refuse is not None:
                conn.execute("ROLLBACK")
                return refuse
            cur = conn.execute(
                "INSERT INTO undo_jobs(account, since_ts, until_ts, learn, status, total, "
                "created_by, created_at) VALUES(?,?,?,?, 'queued', ?, ?, ?)",
                (account, a, b, int(bool(learn)), len(rows), actor or None, now))
            job_id = int(cur.lastrowid)
            conn.executemany("INSERT OR IGNORE INTO undo_items(job_id, message_id) VALUES(?,?)",
                             [(job_id, r["message_id"]) for r in rows])
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    status = run_undo_job(job_id, budget_s=wait_s, engine=eng)
    if status == "queued" and not getattr(eng, "SHUTDOWN", _threading.Event()).is_set():
        _spawn_undo_thread(eng, job_id)
    job = undo_job(job_id, engine=eng) or {}
    res = {**base, **{k: job.get(k, base.get(k)) for k in base if k in job}}
    res.update(ok=job.get("status") != "failed", job_id=job_id, status=job.get("status"),
               code="ok" if job.get("status") == "done" else (job.get("status") or "error"),
               text=job.get("text", ""),
               audit_detail=(f"job={job_id} since={a} until={b} total={job.get('total', 0)} "
                             f"moved={job.get('moved', 0)} learn={int(bool(learn))}"))
    return res


def resume_undo_job(job_id: int, *, wait_s: float = UNDO_INLINE_S, engine: Any = None) -> dict[str, Any] | None:
    """Re-run a failed (e.g. connection lost) undo job from where it stopped."""
    eng = _eng(engine)
    with closing(_open_db(eng)) as conn:
        ensure_undo_schema(conn)
        conn.execute("UPDATE undo_jobs SET status='queued', error=NULL, finished_at=NULL "
                     "WHERE id=? AND status='failed'", (int(job_id),))
    status = run_undo_job(int(job_id), budget_s=wait_s, engine=eng)
    if status == "queued":
        _spawn_undo_thread(eng, int(job_id))
    return undo_job(int(job_id), engine=eng)


def _spawn_undo_thread(eng: Any, job_id: int) -> None:
    t = _threading.Thread(target=_undo_thread_main, args=(eng, job_id),
                          name=f"undo-{job_id}", daemon=True)
    _undo_threads[job_id] = t
    t.start()


def _undo_thread_main(eng: Any, job_id: int) -> None:
    try:
        run_undo_job(job_id, engine=eng)
    except Exception as ex:
        log.warning("undo thread %s failed: %s", job_id, type(ex).__name__)


def run_pending_undo_once(*, engine: Any = None) -> int | None:
    """Run the oldest queued undo job to completion (trainer thread)."""
    eng = _eng(engine)
    with closing(_open_db(eng)) as conn:
        ensure_undo_schema(conn)
        row = conn.execute("SELECT id FROM undo_jobs WHERE status='queued' "
                           "ORDER BY created_at, id LIMIT 1").fetchone()
    if row is None:
        return None
    run_undo_job(int(row["id"]), engine=eng)
    return int(row["id"])


class _UndoStop(Exception):
    def __init__(self, status: str, error: str | None = None) -> None:
        super().__init__(status)
        self.status = status
        self.error = error


def run_undo_job(job_id: int, *, budget_s: float | None = None, engine: Any = None,
                 sleep: Any = None) -> str:
    """Process pending items of one undo job. Claims queued -> running
    (returns 'skipped' if another runner has it). Stops between chunks on
    shutdown (-> queued), cancel (-> cancelled) or when `budget_s` is used
    up after at least one chunk (-> queued). Connection loss -> failed
    (resume_undo_job continues)."""
    eng = _eng(engine)
    shutdown = getattr(eng, "SHUTDOWN", None)
    if sleep is None:
        sleep = shutdown.wait if isinstance(shutdown, _threading.Event) else time.sleep
    t0 = _clock()
    with closing(_open_db(eng)) as conn:
        ensure_undo_schema(conn)
        now = int(time.time())
        cur = conn.execute("UPDATE undo_jobs SET status='running', started_at=COALESCE(started_at, ?) "
                           "WHERE id=? AND status='queued'", (now, int(job_id)))
        if not cur.rowcount:
            return "skipped"
        job = conn.execute("SELECT * FROM undo_jobs WHERE id=?", (int(job_id),)).fetchone()
        client = None
        db = None
        status, error = "done", None
        try:
            try:
                acc, client = _open_session(eng, job["account"], timeout=FIND_TIMEOUT_S)
            except ServiceError as ex:
                raise _UndoStop("failed", ex.text) from None
            try:
                fmap = _folder_map(acc, _list_folders(client))
            except Exception as ex:
                if _is_conn_error(ex):
                    raise _UndoStop("failed", "Forbindelsen til mailserveren blev afbrudt.") from None
                raise _UndoStop("failed", "Mappelisten kunne ikke hentes fra mailserveren.") from None
            if not fmap["junk_exists"]:
                raise _UndoStop("failed", "Spamfilter-mappen findes ikke på mailserveren.")
            caps = _caps_for_engine(_caps(client))
            db = eng.Db(acc.name)
            client.select_folder(fmap["junk"], readonly=False)
            learn = bool(job["learn"])
            actor = job["created_by"] or ""
            interval = 1.0 / UNDO_PER_SECOND
            done_chunks = 0
            while True:
                if isinstance(shutdown, _threading.Event) and shutdown.is_set():
                    raise _UndoStop("queued")
                st = conn.execute("SELECT status FROM undo_jobs WHERE id=?", (int(job_id),)).fetchone()
                if st is None or st["status"] == "cancel_requested":
                    raise _UndoStop("cancelled")
                if budget_s is not None and done_chunks and _clock() - t0 >= budget_s:
                    raise _UndoStop("queued")
                items = [r["message_id"] for r in conn.execute(
                    "SELECT message_id FROM undo_items WHERE job_id=? AND status='pending' "
                    "ORDER BY rowid LIMIT ?", (int(job_id), UNDO_CHUNK))]
                if not items:
                    break
                learned = 0
                for mid in items:
                    t_item = _clock()
                    st_item, code, outcome = _undo_one(eng, db, acc, client, fmap, caps, mid,
                                                       learn=learn, actor=actor, job_id=int(job_id))
                    if outcome == "learned":
                        learned += 1
                    conn.execute("UPDATE undo_items SET status=?, code=?, updated_at=? "
                                 "WHERE job_id=? AND message_id=?",
                                 (st_item, code, int(time.time()), int(job_id), mid))
                    spent = _clock() - t_item
                    if st_item == "moved" and spent < interval:
                        sleep(interval - spent)  # be gentle with the ISP
                _write_undo_counts(conn, int(job_id), learned)
                done_chunks += 1
        except _UndoStop as stop:
            status, error = stop.status, stop.error
        except Exception as ex:
            log.warning("undo job %s stopped: %s", job_id, type(ex).__name__)
            status = "failed"
            error = ("Forbindelsen til mailserveren blev afbrudt." if _is_conn_error(ex)
                     else "Fortrydelsen stoppede uventet – se loggen.")
        finally:
            if db is not None:
                try:
                    db.close()
                except Exception:
                    pass
            if client is not None:
                _logout(client)
        _write_undo_counts(conn, int(job_id))
        finished = int(time.time()) if status in ("done", "failed", "cancelled") else None
        conn.execute("UPDATE undo_jobs SET status=?, error=?, finished_at=? WHERE id=?",
                     (status, error, finished, int(job_id)))
        if status in ("done", "failed", "cancelled"):
            c = _undo_counts(conn, int(job_id))
            try:
                conn.execute(
                    "INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,NULL,?,?)",
                    (job["account"], int(time.time()), f"undo_job_{status}",
                     f"job={job_id} moved={c['moved']} not_found={c['not_found']} "
                     f"skipped={c['skipped']} failed={c['failed']}"))
            except sqlite3.Error:
                pass
        return status


def _undo_one(eng: Any, db: Any, acc: Any, client: Any, fmap: dict[str, Any], caps: frozenset,
              mid: str, *, learn: bool, actor: str, job_id: int) -> tuple[str, str, str | None]:
    """(item status, code, learn outcome). Only mail still recorded as
    moved by the filter, only from the filter's folder, exact Message-ID."""
    row = db.conn.execute("SELECT our_action FROM messages WHERE account=? AND message_id=?",
                          (acc.name, mid)).fetchone()
    if row is None or row["our_action"] != "moved_to_junk":
        return "skipped", "changed", None  # released/junked by the user meanwhile
    if _threat_of(db.conn, acc.name, mid)[0]:
        return "skipped", "threat", None  # B16: never in a bulk undo
    norm = normalize_message_id(mid)
    if norm is None or norm != mid:
        return "skipped", "invalid_id", None
    try:
        uids = list(eng.find_uids_by_message_id(client, mid) or [])
        if len(uids) > 1:
            uids = [u for u in [_pick_duplicate(client, uids)] if u is not None] or uids
        if not uids:
            return "not_found", "not_found", None
        if len(uids) > 1:
            return "skipped", "ambiguous", None
        moved, code, outcome = _move_one_to_inbox(
            eng, db, acc, client, fmap, caps, fmap["junk"], uids[0], mid, learn=learn,
            verdict="ham" if learn else None, by=f"undo:{actor}" if actor else "undo",
            actor=actor, event="undo_release", detail=f"job={job_id} actor={actor}",
            stat="released" if learn else None, reason="undo_release")
    except Exception as ex:
        if _is_conn_error(ex):
            raise
        log.warning("undo item failed: %s", type(ex).__name__)
        return "failed", "imap_error", None
    if not moved:
        return ("not_found" if code == "not_found" else "failed"), code, None
    return "moved", "ok", outcome


# ---------------------------------------------------------------------------
# Threshold suggestion
# ---------------------------------------------------------------------------


def _fmt(x: float | None) -> str:
    if x is None:
        return "–"
    return (f"{x:.1f}".rstrip("0").rstrip(".") if abs(x - round(x)) > 1e-9 else f"{int(round(x))}"
            ).replace(".", ",")


def _grid() -> list[float]:
    n = int(round((THRESHOLD_MAX - THRESHOLD_MIN) / THRESHOLD_STEP))
    return [round(THRESHOLD_MIN + i * THRESHOLD_STEP, 1) for i in range(n + 1)]


def _grid_above(x: float) -> float | None:
    """Smallest grid value strictly above x."""
    for t in _grid():
        if t > x + 1e-9:
            return t
    return None


def _grid_at_or_below(x: float) -> float:
    best = THRESHOLD_MIN
    for t in _grid():
        if t <= x + 1e-9:
            best = t
    return best


def threshold_suggestion(account: str, days: int = 14, *, include_aged: bool = False,
                         engine: Any = None) -> dict[str, Any]:
    """See _threshold_suggestion. 2.3 (B14): when the account's known
    contacts are active (enabled and first sync done) the scores already
    contain their bonuses - the text then ends with "Kendte kontakter er
    regnet med." and `contacts_included` is True."""
    eng = _eng(engine)
    out = _threshold_suggestion(account, days, include_aged=include_aged, engine=eng)
    out["contacts_included"] = False
    if out.get("ok") and out.get("text") and _contacts_active(eng, account):
        out["text"] = out["text"].rstrip() + " Kendte kontakter er regnet med."
        out["contacts_included"] = True
    return out


def _contacts_active(eng: Any, account: str) -> bool:
    try:
        acc = _find_account(eng, account)
        if acc is None or not getattr(acc, "known_contacts", False):
            return False
        with closing(_open_db_ro(eng)) as conn:
            if not _table_exists(conn, "contacts_sync"):
                return False
            row = conn.execute("SELECT complete FROM contacts_sync WHERE account=? AND folder='*'",
                               (account,)).fetchone()
        return bool(row is not None and row[0])
    except Exception:
        return False


def _threshold_suggestion(account: str, days: int = 14, *, include_aged: bool = False,
                          engine: Any = None) -> dict[str, Any]:
    """Recommend a threshold (6..15, step 0.5) from the last `days` days of
    2.0-scored mail (score_version >= 2, no sender-rule decisions, no mail
    to protected recipients - those use protected_threshold, see
    counts.protected_excluded):

    - released = rows with user_verdict 'ham' (Frigiv, rescues, undo with
      learning, Find-en-mail moves): the recommendation is ALWAYS above the
      highest such score (+0.5 margin), so it would not have moved any of them;
    - missed = rows the user marked as spam (user_junked / manual_mark_spam)
      below the current threshold: lowering is suggested only for >= 2 of
      them, at most 2 points per step, and when the newly affected unmarked
      mail stays small.
    2.2 (B7): mail scanned late (messages.aged = 1, e.g. after an outage)
    is left out unless include_aged=True - its score was computed without
    SPF/DMARC (counts.aged_excluded).
    Never raises; read-only."""
    eng = _eng(engine)
    try:
        days = max(1, min(90, int(days)))
    except (TypeError, ValueError):
        days = 14
    out: dict[str, Any] = {"ok": False, "account": account, "days": days, "current": None,
                           "recommended": None, "change": "none", "confidence": "low",
                           "text": "", "reasons": [], "counts": {}, "max_released_score": None,
                           "histogram": [], "grid": []}
    try:
        acc = _find_account(eng, account)
    except Exception:
        out["text"] = "Konfigurationen kunne ikke indlæses."
        return out
    if acc is None:
        out["text"] = "Kontoen findes ikke."
        return out
    cur = float(getattr(acc, "threshold", 8.0) or 8.0)
    out["current"] = cur
    out["mode"] = getattr(acc, "mode", None)
    since = int(time.time()) - days * 86400
    try:
        with closing(_open_db_ro(eng)) as conn:
            aged_col = "COALESCE(aged, 0)" if "aged" in _columns(conn, "messages") else "0"
            all_rows = conn.execute(
                f"""
                SELECT our_score, our_action, user_verdict, {aged_col} AS aged,
                       instr(COALESCE(symbols, ''), ?) > 0 AS protected FROM messages
                WHERE account=? AND score_version >= 2 AND our_score IS NOT NULL
                  AND COALESCE(scanned_at, first_seen) >= ?
                  AND (rule_hit IS NULL OR rule_hit = '')
                """, (f'"{PROTECTED_SYMBOL}"', account, since)).fetchall()
    except sqlite3.Error:
        out["text"] = "Databasen kunne ikke læses."
        return out
    # Mail to a protected recipient (engine E9, TH_PROTECTED_RCPT) was
    # decided by protected_threshold, not by this threshold: leave it out,
    # or one released shop order at 16 would block every suggestion.
    rows = [r for r in all_rows if not r["protected"]]
    protected_excluded = len(all_rows) - len(rows)
    aged_excluded = 0
    if not include_aged:
        kept = [r for r in rows if not r["aged"]]
        aged_excluded = len(rows) - len(kept)
        rows = kept
    scores = [float(r["our_score"]) for r in rows]
    ham = sorted(float(r["our_score"]) for r in rows if r["user_verdict"] == "ham")
    missed_all = [float(r["our_score"]) for r in rows if r["user_verdict"] == "spam"
                  and r["our_action"] in ("user_junked", "manual_mark_spam")]
    spam_marked = [float(r["our_score"]) for r in rows if r["user_verdict"] == "spam"]
    max_ham = ham[-1] if ham else None
    out["max_released_score"] = max_ham

    def would_move(t: float) -> int:
        return sum(1 for s in scores if s >= t)

    def unconfirmed_between(lo: float, hi: float) -> int:
        return sum(1 for r in rows if lo <= float(r["our_score"]) < hi and r["user_verdict"] is None)

    out["grid"] = [{"threshold": t, "would_move": would_move(t),
                    "released_hit": sum(1 for s in ham if s >= t),
                    "missed_caught": sum(1 for s in missed_all if s >= t)} for t in _grid()]
    hist: dict[int, dict[str, int]] = {}
    for r in rows:
        b = int(max(-10, min(30, float(r["our_score"]) // 1)))
        h = hist.setdefault(b, {"n": 0, "ham": 0, "spam": 0})
        h["n"] += 1
        if r["user_verdict"] == "ham":
            h["ham"] += 1
        elif r["user_verdict"] == "spam":
            h["spam"] += 1
    out["histogram"] = [{"lo": b, "hi": b + 1, **hist[b]} for b in sorted(hist)]
    released_over = sum(1 for s in ham if s >= cur)
    missed_below = [s for s in missed_all if s < cur]
    out["counts"] = {"scored": len(scores), "released": len(ham), "released_over_current": released_over,
                     "missed": len(missed_all), "missed_below_current": len(missed_below),
                     "marked_spam": len(spam_marked), "would_move_current": would_move(cur),
                     "protected_excluded": protected_excluded, "aged_excluded": aged_excluded}

    floor = THRESHOLD_MIN
    if max_ham is not None:
        above = _grid_above(max_ham + THRESHOLD_STEP - 1e-6)  # >= max_ham + 0.5
        if above is None:
            out.update(ok=True, change="none", confidence="high" if len(scores) >= SUGGEST_MIN_SCORED else "low",
                       text=(f"En mail du har frigivet havde score {_fmt(max_ham)} – højere end den "
                             f"højeste grænse ({_fmt(THRESHOLD_MAX)}). Brug en tilladelsesregel for "
                             "afsenderen i stedet for at ændre følsomheden."))
            out["reasons"].append("released_above_max")
            return _finish_suggestion(out, cur, None, would_move, unconfirmed_between)
        floor = max(THRESHOLD_MIN, above)

    if len(scores) < SUGGEST_MIN_SCORED and not released_over:
        out.update(ok=True, change="none", recommended=None, confidence="low",
                   text=(f"For få data endnu ({len(scores)} scorede mails de seneste {days} dage). "
                         f"Behold grænsen på {_fmt(cur)} indtil videre."))
        out["reasons"].append("too_little_data")
        return _finish_suggestion(out, cur, None, would_move, unconfirmed_between)

    confidence = "high" if len(scores) >= 100 else "medium"
    if floor > cur:
        rec = floor
        out.update(ok=True, change="raise", recommended=rec, confidence=confidence,
                   text=(f"Hæv grænsen fra {_fmt(cur)} til {_fmt(rec)}: {released_over} "
                         f"mail{'s' if released_over != 1 else ''}, du har frigivet, havde en score "
                         f"op til {_fmt(max_ham)} og ville stadig blive flyttet."))
        out["reasons"].append("released_over_current")
        return _finish_suggestion(out, cur, rec, would_move, unconfirmed_between)

    catchable = sorted(s for s in missed_below if s >= floor)
    if len(catchable) >= SUGGEST_MIN_MISSES:
        rec = max(floor, _grid_at_or_below(cur - SUGGEST_MAX_LOWER), _grid_at_or_below(catchable[0]))
        rec = min(rec, _grid_at_or_below(cur - THRESHOLD_STEP))
        caught = sum(1 for s in catchable if s >= rec)
        extra = unconfirmed_between(rec, cur)
        if rec < cur and caught >= SUGGEST_MIN_MISSES and extra <= max(3, caught * 3):
            out.update(ok=True, change="lower", recommended=rec, confidence=confidence,
                       text=(f"Sænk grænsen fra {_fmt(cur)} til {_fmt(rec)}: {caught} spam-mails, "
                             f"du selv har markeret, havde score mellem {_fmt(rec)} og {_fmt(cur)}. "
                             + (f"Ingen mail du har frigivet ligger over {_fmt(rec)}."
                                if max_ham is None or max_ham < rec else "")).strip())
            out["reasons"].append("missed_below_current")
            return _finish_suggestion(out, cur, rec, would_move, unconfirmed_between)
        out["reasons"].append("lowering_too_risky")

    out.update(ok=True, change="keep", recommended=cur, confidence=confidence,
               text=(f"Grænsen på {_fmt(cur)} passer til de seneste {days} dage: "
                     + ("ingen frigivne mails ville være flyttet"
                        if not ham else f"den højeste frigivne mail havde score {_fmt(max_ham)}")
                     + (f", og {len(missed_below)} spam-mail{'s' if len(missed_below) != 1 else ''} "
                        "slap igennem." if missed_below else ", og ingen markeret spam slap igennem.")))
    return _finish_suggestion(out, cur, cur, would_move, unconfirmed_between)


def _finish_suggestion(out: dict[str, Any], cur: float, rec: float | None, would_move: Any,
                       unconfirmed_between: Any) -> dict[str, Any]:
    c = out["counts"]
    if rec is not None:
        c["would_move_recommended"] = would_move(rec)
        c["extra_at_recommended"] = unconfirmed_between(rec, cur) if rec < cur else 0
    return out


# ---------------------------------------------------------------------------
# Daily digest data (read by deploy/host-monitor.sh via docker exec)
# ---------------------------------------------------------------------------

DIGEST_METRICS = ("moved", "released", "marked_spam", "user_junked", "spam_detected", "scanned",
                  "flagged",
                  # 2.3 (B14): trust signals of known contacts / replies / first contact.
                  "known_contact", "reply_detected", "first_contact",
                  # 2.3 (B16/B19): threats stopped, mail moved by a rescan.
                  "threat_detected", "zapped")


def digest_data(day: str | None = None, *, suggestions: bool = False,
                engine: Any = None) -> dict[str, Any]:
    """Per-mailbox counts for one Copenhagen day (default: yesterday) from
    stats_daily: moved, released, marked (= marked_spam + user_junked, spam
    that reached the inbox), plus spam_detected/scanned/flagged. With
    suggestions=True also threshold_suggestion() per enabled account.
    Read-only; JSON-serialisable."""
    eng = _eng(engine)
    if day is None:
        day = (_dt.date.today() - _dt.timedelta(days=1)).isoformat()
    try:
        _dt.date.fromisoformat(day)
    except (TypeError, ValueError):
        raise ValueError("day must be YYYY-MM-DD") from None
    try:
        accounts = list(eng.load_account_configs(eng.CONFIG_PATH))
    except Exception:
        accounts = []
    stats: dict[str, dict[str, int]] = {}
    try:
        with closing(_open_db_ro(eng)) as conn:
            for r in conn.execute(
                    f"SELECT account, metric, SUM(n) AS n FROM stats_daily WHERE day=? AND metric IN "
                    f"({','.join('?' * len(DIGEST_METRICS))}) GROUP BY account, metric",
                    (day, *DIGEST_METRICS)):
                stats.setdefault(r["account"], {})[r["metric"]] = int(r["n"] or 0)
    except sqlite3.Error:
        pass
    by_name = {a.name: a for a in accounts}
    names = [a.name for a in accounts if getattr(a, "enabled", True)]
    names += sorted(n for n in stats if n not in names and n != "*")
    out_acc = []
    for n in names:
        s = stats.get(n, {})
        acc = by_name.get(n)
        out_acc.append({
            "account": n,
            "name": (getattr(acc, "display_name", None) or n) if acc is not None else n,
            "mode": getattr(acc, "mode", None) if acc is not None else None,
            "moved": s.get("moved", 0), "released": s.get("released", 0),
            "marked": s.get("marked_spam", 0) + s.get("user_junked", 0),
            "spam_detected": s.get("spam_detected", 0), "flagged": s.get("flagged", 0),
            "scanned": s.get("scanned", 0),
            "known_contact": s.get("known_contact", 0), "reply_detected": s.get("reply_detected", 0),
            "first_contact": s.get("first_contact", 0),
            "threats": s.get("threat_detected", 0), "zapped": s.get("zapped", 0),
        })
    totals = {k: sum(a[k] for a in out_acc) for k in ("moved", "released", "marked",
                                                      "spam_detected", "scanned", "known_contact",
                                                      "reply_detected", "first_contact", "threats",
                                                      "zapped")}
    res: dict[str, Any] = {"day": day, "accounts": out_acc, "totals": totals,
                           "empty": totals["moved"] + totals["released"] + totals["marked"]
                           + totals["spam_detected"] == 0}
    if suggestions:
        sugg = []
        for n in names:
            acc = by_name.get(n)
            if acc is None or getattr(acc, "mode", "shadow") not in ("flag", "move"):
                continue
            try:
                s = threshold_suggestion(n, engine=eng)
            except Exception as ex:
                log.warning("digest suggestion for %s failed: %s", n, type(ex).__name__)
                continue
            sugg.append({"account": n, "name": getattr(acc, "display_name", None) or n,
                         "current": s.get("current"), "recommended": s.get("recommended"),
                         "change": s.get("change"), "text": s.get("text")})
        res["suggestions"] = sugg
    return res


# ---------------------------------------------------------------------------
# Folder sizes (display only)
# ---------------------------------------------------------------------------

_sizes_lock = _threading.Lock()
_sizes_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def folder_sizes(account: str, *, refresh: bool = False, engine: Any = None) -> dict[str, Any]:
    """STATUS (MESSAGES, UNSEEN) of INBOX, the filter's folder and the
    provider's spam folder. Read-only, cached 10 min per account (errors 60
    s; refresh=True bypasses a cached success only after 60 s). Display
    only - there is deliberately no clean-up/delete feature.
    {ok, code, text, account, cached, fetched_at, folders:[{kind, name,
    label, exists, messages, unseen}]}"""
    eng = _eng(engine)
    now = _clock()
    with _sizes_lock:
        hit = _sizes_cache.get(account)
    if hit is not None:
        age = now - hit[0]
        ttl = FOLDER_SIZES_TTL_S if hit[1].get("ok") else FOLDER_SIZES_ERROR_TTL_S
        if age < ttl and not (refresh and age >= FOLDER_SIZES_ERROR_TTL_S):
            return {**hit[1], "cached": True}
    res = _folder_sizes_live(eng, account)
    with _sizes_lock:
        _sizes_cache[account] = (now, res)
    return {**res, "cached": False}


def _folder_sizes_live(eng: Any, account: str) -> dict[str, Any]:
    out: dict[str, Any] = {"ok": False, "code": "other", "text": "", "account": account,
                           "fetched_at": int(time.time()), "folders": []}
    try:
        acc, client = _open_session(eng, account, timeout=FIND_TIMEOUT_S)
    except ServiceError as ex:
        out.update(code=ex.code, text=ex.text)
        return out
    try:
        folders = _list_folders(client)
        fmap = _folder_map(acc, folders)
        wanted = [("inbox", fmap["inbox"]), ("filter_junk", fmap["junk"])]
        if fmap.get("provider_junk"):
            wanted.append(("provider_junk", fmap["provider_junk"]))
        for kind, name in wanted:
            entry = {"kind": kind, "name": name, "label": folder_label(name),
                     "exists": name in fmap["names"], "messages": None, "unseen": None}
            if entry["exists"]:
                try:
                    st = client.folder_status(name, [b"MESSAGES", b"UNSEEN"])
                    for key in ("messages", "unseen"):
                        v = st.get(key.upper().encode(), st.get(key.upper()))
                        entry[key] = int(v) if v is not None else None
                except Exception as ex:
                    log.info("STATUS %s failed: %s", name, type(ex).__name__)
                    if _is_conn_error(ex):
                        raise
            out["folders"].append(entry)
        out.update(ok=True, code="ok", text="")
    except Exception as ex:
        log.warning("folder_sizes failed for %s: %s", account, type(ex).__name__)
        out.update(code="imap_error", text="Mappernes størrelse kunne ikke hentes.")
    finally:
        _logout(client)
    return out


# ===========================================================================
# 2.2 (B6): Bayes repair - learn lists, candidates, rebalancing
# ===========================================================================

import math as _math  # noqa: E402

LEARN_LIST_MAX_ITEMS = 2000
LEARN_KINDS = ("spam", "ham")
# Evidence that a message learned as ham was really phishing/spam.
REPAIR_SYMBOLS = frozenset({"TH_BRAND_SPOOF", "TH_FROM_NAME_HOMOGLYPH", "TH_LURE_COMBO",
                            "TH_FROM_ABUSED_TLD", "DBL_PHISH", "TH_SUBJECT_BRAND_SPOOF"})
REPAIR_PREFIXES = ("PHISHED_",)
# Informational PHISHED_* symbols (no feed hit; PHISHED_EXCLUDED = a link to
# the owner's own webshop). Same set as filter.PHISHED_INFO (test-enforced).
REPAIR_INFO_SYMBOLS = frozenset({"PHISHED_EXCLUDED", "PHISHED_GENERIC_SERVICE"})
REPAIR_REASONS = ("phishing_rule", "user_marked_spam", "provider_spam")
REPAIR_REASON_TEXT = {
    "phishing_rule": "Phishing-regel ramte",
    "user_marked_spam": "Du har selv markeret den som spam",
    "provider_spam": "Udbyderen markerede den som spam",
}
_LEARN_LIST_STATUS_TEXT = {
    "queued": "Venter på at starte.",
    "running": "Lærer mails …",
    "done": "Færdig.",
    "failed": "Stoppet med en fejl.",
    "cancelled": "Annulleret.",
    "cancel_requested": "Stopper …",
}
_ITEM_STATUS_TEXT = {
    "pending": "Venter", "learned": "Lært", "already": "Var allerede lært",
    "declined": "rspamd ville ikke lære den", "not_found": "Mailen findes ikke længere",
    "ambiguous": "Flere forskellige mails med samme Message-ID – sprunget over",
    "too_large": "For stor (over 5 MB)", "deferred": "Udskudt – prøv igen om 10 minutter",
    "failed": "Fejlede",
}


def _trainer_mod() -> Any:
    import trainer  # noqa: PLC0415 - same image; trainer imports services lazily

    return trainer


def _item_tuple(item: Any, default_kind: str) -> tuple[Any, Any, Any, Any]:
    if isinstance(item, dict):
        return item.get("account"), item.get("message_id"), item.get("kind") or default_kind, item.get("reason")
    if isinstance(item, (list, tuple)) and len(item) >= 2:
        return item[0], item[1], (item[2] if len(item) > 2 and item[2] else default_kind), None
    return None, None, default_kind, None


def queue_learn_list(items: Iterable[Any], actor: str = "", *, kind: str = "spam", note: str = "",
                     engine: Any = None) -> dict[str, Any]:
    """B6a: queue an owner-approved list of messages to learn one by one
    (trainer thread, read-only IMAP). `items`: dicts {account, message_id,
    kind?, reason?} or (account, message_id[, kind]) tuples; `kind` is the
    default class ('spam'|'ham'). Unlike queue_train_job this may learn
    INBOX mail as spam: every message is named and approved by the owner.
    Admin only (the UI checks). Never raises.
    -> {ok, code ('queued'|'empty'|'too_many'|'invalid'|'config'), text, job_id,
        total, by_account:{account: n}, rejected:[{account, message_id, code
        ('no_account'|'invalid_id'|'invalid_kind'|'threat')}], audit_detail}"""
    eng = _eng(engine)
    out: dict[str, Any] = {"ok": False, "code": "invalid", "text": "", "job_id": None, "total": 0,
                           "by_account": {}, "rejected": [], "audit_detail": ""}
    if kind not in LEARN_KINDS:
        out["text"] = "Typen skal være spam eller legitim."
        return out
    try:
        names = {a.name for a in eng.load_account_configs(eng.CONFIG_PATH)}
    except Exception:
        out.update(code="config", text="Konfigurationen kunne ikke indlæses.")
        return out
    wanted: dict[tuple[str, str], tuple[str, str | None]] = {}
    for raw_item in items or []:
        account, mid_raw, k, reason = _item_tuple(raw_item, kind)
        mid = normalize_message_id(mid_raw) if isinstance(mid_raw, str) else None
        if not isinstance(account, str) or account not in names:
            out["rejected"].append({"account": account, "message_id": mid_raw, "code": "no_account"})
        elif mid is None:
            out["rejected"].append({"account": account, "message_id": mid_raw, "code": "invalid_id"})
        elif k not in LEARN_KINDS:
            out["rejected"].append({"account": account, "message_id": mid, "code": "invalid_kind"})
        else:
            wanted[(account, mid)] = (k, str(reason)[:200] if reason else None)
    ham = [key for key, (k, _r) in wanted.items() if k == "ham"]
    if ham:
        # B16: a mail with a threat class is never learned as ham from a list
        # (engine.learn_message would decline it anyway).
        try:
            with closing(_open_db(eng)) as conn:
                for key in ham:
                    if _threat_of(conn, key[0], key[1])[0]:
                        del wanted[key]
                        out["rejected"].append({"account": key[0], "message_id": key[1], "code": "threat"})
        except sqlite3.Error:
            pass
    if not wanted:
        out.update(code="empty", text="Ingen gyldige mails at lære.")
        return out
    if len(wanted) > LEARN_LIST_MAX_ITEMS:
        out.update(code="too_many", text=f"Højst {LEARN_LIST_MAX_ITEMS} mails ad gangen.")
        return out
    now = int(time.time())
    try:
        with closing(_open_db(eng)) as conn:
            _trainer_mod().ensure_learn_list_schema(conn)
            conn.execute("BEGIN IMMEDIATE")
            try:
                cur = conn.execute(
                    "INSERT INTO learn_list_jobs(status, total, note, created_by, created_at) "
                    "VALUES('queued', ?, ?, ?, ?)", (len(wanted), (note or "")[:200] or None,
                                                     actor or None, now))
                job_id = int(cur.lastrowid)
                conn.executemany(
                    "INSERT INTO learn_list_items(job_id, account, message_id, kind, status, reason, updated_at) "
                    "VALUES(?,?,?,?, 'pending', ?, ?)",
                    [(job_id, a, m, k, r, now) for (a, m), (k, r) in wanted.items()])
                conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES('*', ?, NULL, "
                             "'learn_list_queued', ?)", (now, f"job={job_id} n={len(wanted)} by {actor}"[:300]))
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
    except sqlite3.Error as ex:
        log.warning("queue_learn_list failed: %s", type(ex).__name__)
        out.update(code="invalid", text="Listen kunne ikke gemmes.")
        return out
    by_acc: dict[str, int] = {}
    for a, _m in wanted:
        by_acc[a] = by_acc.get(a, 0) + 1
    kinds = {k for k, _r in wanted.values()}
    what = "spam" if kinds == {"spam"} else "legitim" if kinds == {"ham"} else "spam/legitim"
    out.update(ok=True, code="queued", job_id=job_id, total=len(wanted), by_account=by_acc,
               text=(f"{len(wanted)} mail{'s' if len(wanted) != 1 else ''} lægges i kø til at blive lært "
                     f"som {what}. Det sker i baggrunden – ingen mails flyttes."),
               audit_detail=f"learn_list job={job_id} n={len(wanted)} kinds={','.join(sorted(kinds))}")
    return out


# Item states that "Prøv igen" re-queues: failed, deferred (cooldown / safe
# mode) and - when the job was stopped or crashed - the never-run pending ones.
# ambiguous / too_large / declined / not_found are final.
_RETRY_STATES = ("failed", "deferred")
_RETRY_PENDING_JOB_STATES = ("cancelled", "failed")


def _retry_states(job_status: Any) -> tuple[str, ...]:
    return _RETRY_STATES + (("pending",) if str(job_status) in _RETRY_PENDING_JOB_STATES else ())


def _retryable_count(conn: sqlite3.Connection, job_id: int, job_status: Any) -> int:
    states = _retry_states(job_status)
    row = conn.execute(f"SELECT COUNT(*) FROM learn_list_items WHERE job_id=? "
                       f"AND status IN ({','.join('?' * len(states))})", (int(job_id), *states)).fetchone()
    return int(row[0] or 0) if row else 0


def _learn_list_dict(row: Any) -> dict[str, Any]:
    d = dict(row)
    total = d.get("total") or 0
    d["percent"] = int(min(100, (d.get("processed") or 0) * 100 / total)) if total else (
        100 if d.get("status") == "done" else 0)
    d["remaining"] = max(0, total - (d.get("processed") or 0))
    d["text"] = d.get("error") or _LEARN_LIST_STATUS_TEXT.get(str(d.get("status")), "")
    return d


def learn_list_job(job_id: int, *, engine: Any = None) -> dict[str, Any] | None:
    """One learn-list job with live counts (from its items), or None."""
    eng = _eng(engine)
    try:
        with closing(_open_db(eng)) as conn:
            tr = _trainer_mod()
            tr.ensure_learn_list_schema(conn)
            row = conn.execute("SELECT * FROM learn_list_jobs WHERE id=?", (int(job_id),)).fetchone()
            if row is None:
                return None
            d = _learn_list_dict(row)
            d.update(tr.learn_list_counts(conn, int(job_id)))
            d["retryable"] = _retryable_count(conn, int(job_id), d.get("status"))
            d["percent"] = int(min(100, d["processed"] * 100 / d["total"])) if d["total"] else 100
            d["remaining"] = max(0, d["total"] - d["processed"])
            return d
    except (sqlite3.Error, TypeError, ValueError):
        return None


def list_learn_list_jobs(limit: int = 20, *, engine: Any = None) -> list[dict[str, Any]]:
    eng = _eng(engine)
    try:
        with closing(_open_db(eng)) as conn:
            _trainer_mod().ensure_learn_list_schema(conn)
            rows = conn.execute("SELECT * FROM learn_list_jobs ORDER BY id DESC LIMIT ?",
                                (max(1, min(int(limit or 20), 200)),)).fetchall()
            out = []
            for r in rows:
                d = _learn_list_dict(r)
                d["retryable"] = _retryable_count(conn, int(d["id"]), d.get("status"))
                out.append(d)
    except (sqlite3.Error, TypeError, ValueError):
        return []
    return out


def learn_list_items(job_id: int, *, status: str | None = None, account: str | None = None,
                     limit: int = 500, engine: Any = None) -> list[dict[str, Any]]:
    """Items of a learn-list job, with sender/subject from messages when
    known and a Danish status text."""
    eng = _eng(engine)
    sql = ("SELECT i.*, m.sender, m.subject FROM learn_list_items i LEFT JOIN messages m "
           "ON m.account=i.account AND m.message_id=i.message_id WHERE i.job_id=?")
    args: list[Any] = [int(job_id)]
    if status:
        sql += " AND i.status=?"
        args.append(status)
    if account:
        sql += " AND i.account=?"
        args.append(account)
    sql += " ORDER BY i.rowid LIMIT ?"
    args.append(max(1, min(int(limit or 500), LEARN_LIST_MAX_ITEMS)))
    try:
        with closing(_open_db(eng)) as conn:
            _trainer_mod().ensure_learn_list_schema(conn)
            rows = conn.execute(sql, args).fetchall()
    except sqlite3.Error:
        return []
    out = []
    for r in rows:
        d = dict(r)
        d["status_text"] = _ITEM_STATUS_TEXT.get(str(d.get("status")), "")
        out.append(d)
    return out


def cancel_learn_list_job(job_id: int, *, engine: Any = None) -> bool:
    """Queued -> cancelled at once; running -> stops after the current mail.
    Already learned mail stays learned (it can be learned back as ham)."""
    eng = _eng(engine)
    try:
        with closing(_open_db(eng)) as conn:
            _trainer_mod().ensure_learn_list_schema(conn)
            cur = conn.execute("UPDATE learn_list_jobs SET status='cancelled', finished_at=? "
                               "WHERE id=? AND status='queued'", (int(time.time()), int(job_id)))
            if cur.rowcount:
                return True
            cur = conn.execute("UPDATE learn_list_jobs SET status='cancel_requested' "
                               "WHERE id=? AND status='running'", (int(job_id),))
            return bool(cur.rowcount)
    except (sqlite3.Error, TypeError, ValueError):
        return False


def retry_learn_list(job_id: int, actor: str = "", *, engine: Any = None) -> dict[str, Any]:
    """Queue a new learn-list job with the items of `job_id` that failed or
    were deferred (flip-flop cooldown / safe mode), plus the never-run
    'pending' items of a cancelled or failed job (resume the approved
    remainder). Same result shape as queue_learn_list (code 'empty' when
    nothing is left to retry)."""
    eng = _eng(engine)
    try:
        with closing(_open_db(eng)) as conn:
            _trainer_mod().ensure_learn_list_schema(conn)
            job = conn.execute("SELECT status FROM learn_list_jobs WHERE id=?", (int(job_id),)).fetchone()
            states = _retry_states(job["status"] if job is not None else None)
            rows = conn.execute("SELECT account, message_id, kind, reason FROM learn_list_items "
                                f"WHERE job_id=? AND status IN ({','.join('?' * len(states))})",
                                (int(job_id), *states)).fetchall()
    except (sqlite3.Error, TypeError, ValueError):
        rows = []
    items = [{"account": r["account"], "message_id": r["message_id"], "kind": r["kind"],
              "reason": r["reason"]} for r in rows]
    return queue_learn_list(items, actor, note=f"genforsøg af job {job_id}", engine=eng)


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                        (name,)).fetchone() is not None


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    try:
        return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    except sqlite3.Error:
        return set()


def _sym_names(symbols_json: Any) -> set[str]:
    try:
        syms = json.loads(symbols_json) if isinstance(symbols_json, str) else (symbols_json or [])
    except (TypeError, ValueError):
        return set()
    return {str(s.get("n")) for s in syms if isinstance(s, dict) and s.get("n")}


def _repair_hits(names: set[str]) -> list[str]:
    return sorted(n for n in names if n in REPAIR_SYMBOLS
                  or (n.startswith(REPAIR_PREFIXES) and n not in REPAIR_INFO_SYMBOLS))


# Provider profiles whose spam flag alone is no evidence for a Bayes repair
# (Gigahost flags real invoices as spam).
WEAK_PROVIDER_FLAG_PROFILES = frozenset({"gigahost"})


def _provider_profile_name(acc: Any) -> str | None:
    host = str(getattr(acc, "imap_host", "") or "").lower().rstrip(".")
    if host == "gigahost.dk" or host.endswith(".gigahost.dk"):
        return "gigahost"
    if host == "scannet.dk" or host.endswith(".scannet.dk"):
        return "scannet"
    return None


def _provider_flag_weak_accounts(eng: Any) -> set[str] | None:
    """Accounts whose provider flag alone is no evidence; None = config
    unreadable (then no account's flag counts alone - fewer suggestions)."""
    try:
        accs = eng.load_account_configs(eng.CONFIG_PATH)
    except Exception as ex:  # noqa: BLE001 - suggestions only
        log.warning("bayes_repair_candidates: config unavailable: %s", type(ex).__name__)
        return None
    return {a.name for a in accs if _provider_profile_name(a) in WEAK_PROVIDER_FLAG_PROFILES}


def bayes_repair_candidates(account: str | None = None, *, scope: str = "learned_ham",
                            limit: int = 500, engine: Any = None) -> dict[str, Any]:
    """B6a suggestions for a learn list (read-only): messages whose CURRENT
    Bayes class is ham (messages.learned_as, learn_ledger, or the newest
    learn_ham/learn_spam event) with evidence that they are spam:
      * 'phishing_rule'    - stored symbols (the message row or its newest
        calibration row) contain TH_BRAND_SPOOF, TH_FROM_NAME_HOMOGLYPH,
        TH_LURE_COMBO, TH_FROM_ABUSED_TLD, TH_SUBJECT_BRAND_SPOOF, DBL_PHISH or
        PHISHED_*;
      * 'user_marked_spam' - the user later moved/marked it as spam
        (user_verdict 'spam', our_action user_junked/manual_mark_spam);
      * 'provider_spam'    - the provider flagged it (provider_flag, or
        TH_PROVIDER_SPAM in the symbols).
    scope='all' also lists messages never learned at all with the same
    evidence (learning them as spam adds spam to the shared Bayes).
    Excluded: mail the user released/kept (user_verdict 'ham') and mail
    decided by an allow rule. Gigahost mailboxes (provider profile
    'gigahost'): the provider's spam flag alone is NOT evidence - Gigahost
    flags real invoices - so 'provider_spam' only counts together with
    another reason (counts.provider_only_skipped). Rows from calibration jobs only need a
    calibration scan made AFTER the 2.2 rules are live to carry the new
    TH_* symbols.
    -> {ok, account, scope, total, truncated, counts:{by_reason, by_account,
        learned_ham}, items:[{account, message_id, sender, subject,
        received_at, folder, score, learned_as, learned_at, reasons:[codes],
        symbols:[matched], text, suggested_kind:'spam'}]}"""
    eng = _eng(engine)
    out: dict[str, Any] = {"ok": False, "account": account, "scope": scope, "total": 0,
                           "truncated": False, "items": [],
                           "counts": {"by_reason": {r: 0 for r in REPAIR_REASONS}, "by_account": {},
                                      "learned_ham": 0}}
    if scope not in ("learned_ham", "all"):
        scope = "learned_ham"
        out["scope"] = scope
    try:
        limit = max(1, min(int(limit or 500), LEARN_LIST_MAX_ITEMS))
    except (TypeError, ValueError):
        limit = 500
    acc_sql, acc_args = ("AND account=?", [account]) if account else ("", [])
    out["counts"]["provider_only_skipped"] = 0
    weak_provider = _provider_flag_weak_accounts(eng)
    try:
        with closing(_open_db_ro(eng)) as conn:
            # Current Bayes class per message: events (oldest evidence), then
            # messages.learned_as, then the ledger (newest, authoritative).
            cls: dict[tuple[str, str], tuple[str, int | None]] = {}
            # Learn events from before the last Bayes pool switch belong to
            # another pool (rebuild/restore keep each pool's state apart).
            since = _switch_ts(conn) or 0
            for r in conn.execute(
                    f"SELECT account, message_id, event, ts FROM events WHERE event IN ('learn_ham','learn_spam') "
                    f"AND message_id IS NOT NULL AND ts>=? {acc_sql} ORDER BY ts, id", [since, *acc_args]):
                cls[(r["account"], r["message_id"])] = (r["event"][6:], r["ts"])
            for r in conn.execute(
                    f"SELECT account, message_id, learned_as, learned_at FROM messages "
                    f"WHERE learned_as IN ('spam','ham') {acc_sql}", acc_args):
                cur = cls.get((r["account"], r["message_id"]))
                if cur is None or (r["learned_at"] or 0) >= (cur[1] or 0):
                    cls[(r["account"], r["message_id"])] = (r["learned_as"], r["learned_at"])
            if _table_exists(conn, "learn_ledger"):
                for r in conn.execute(f"SELECT account, message_id, kind, learned_at FROM learn_ledger "
                                      f"WHERE 1=1 {acc_sql}", acc_args):
                    cls[(r["account"], r["message_id"])] = (r["kind"], r["learned_at"])
            rows: dict[tuple[str, str], dict[str, Any]] = {}
            for r in conn.execute(
                    f"SELECT account, message_id, sender, subject, received_at, current_folder, our_score, "
                    f"symbols, user_verdict, our_action, provider_flag, rule_hit FROM messages WHERE 1=1 {acc_sql}",
                    acc_args):
                rows[(r["account"], r["message_id"])] = dict(r)
            calib: dict[tuple[str, str], dict[str, Any]] = {}
            if _table_exists(conn, "calibration_results"):
                for r in conn.execute(
                        f"SELECT job_id, account, folder, message_id, final_score, symbols, sender, subject, "
                        f"received_at, provider_flag FROM calibration_results WHERE 1=1 {acc_sql} "
                        f"ORDER BY job_id", acc_args):
                    calib[(r["account"], r["message_id"])] = dict(r)  # newest job wins
    except sqlite3.Error as ex:
        log.warning("bayes_repair_candidates failed: %s", type(ex).__name__)
        return out
    out["counts"]["learned_ham"] = sum(1 for v in cls.values() if v[0] == "ham")
    keys = set(rows) | set(calib)
    items = []
    for key in keys:
        current = cls.get(key, (None, None))
        if current[0] == "spam":
            continue
        if current[0] != "ham" and scope != "all":
            continue
        m = rows.get(key) or {}
        c = calib.get(key) or {}
        if m.get("user_verdict") == "ham" or str(m.get("rule_hit") or "").startswith("allow:"):
            continue
        names = _sym_names(m.get("symbols")) | _sym_names(c.get("symbols"))
        reasons: list[str] = []
        matched = _repair_hits(names)
        if matched:
            reasons.append("phishing_rule")
        if m.get("user_verdict") == "spam" or m.get("our_action") in ("user_junked", "manual_mark_spam"):
            reasons.append("user_marked_spam")
        if m.get("provider_flag") == 1 or c.get("provider_flag") == 1 or "TH_PROVIDER_SPAM" in names:
            reasons.append("provider_spam")
        if reasons == ["provider_spam"] and (weak_provider is None or key[0] in weak_provider):
            out["counts"]["provider_only_skipped"] += 1
            continue
        if not reasons:
            continue
        items.append({
            "account": key[0], "message_id": key[1],
            "sender": m.get("sender") or c.get("sender"), "subject": m.get("subject") or c.get("subject"),
            "received_at": m.get("received_at") or c.get("received_at"),
            "folder": m.get("current_folder") or c.get("folder"),
            "score": m.get("our_score") if m.get("our_score") is not None else c.get("final_score"),
            "learned_as": current[0], "learned_at": current[1], "reasons": reasons, "symbols": matched,
            "text": "; ".join(REPAIR_REASON_TEXT[r] + (f" ({', '.join(matched)})" if r == "phishing_rule" else "")
                              for r in reasons),
            "suggested_kind": "spam",
        })
    items.sort(key=lambda i: (-len(i["reasons"]), i["learned_as"] != "ham",
                              -(float(i["score"]) if i["score"] is not None else -99.0), i["message_id"]))
    for it in items:
        for r in it["reasons"]:
            out["counts"]["by_reason"][r] += 1
        out["counts"]["by_account"][it["account"]] = out["counts"]["by_account"].get(it["account"], 0) + 1
    out.update(ok=True, total=len(items), truncated=len(items) > limit, items=items[:limit])
    return out


REBALANCE_DEFAULT_RATIO = 0.5  # spam:ham >= 1:2


def queue_bayes_rebalance(actor: str = "", *, accounts: Iterable[str] | None = None,
                          ratio: float = REBALANCE_DEFAULT_RATIO, min_age_days: int = 3,
                          max_per_folder: int = 2000, include_trash: bool = False,
                          dry_run: bool = False, engine: Any = None) -> dict[str, Any]:
    """B6b: learn the junk-type folders as spam until the shared Bayes has
    spam:ham >= ratio (default 1:2). Plans one ordinary 'spam' train job
    per folder - the filter's own folder and the provider's spam folder of
    every enabled mailbox (plus, with include_trash, the trash folder
    filtered to provider-flagged spam) - biggest first, each with
    train_jobs.stop_ratio so the trainer stops as soon as the ratio is
    reached. Never the inbox. Mail younger than min_age_days is left (time
    for the user to rescue it). Read-only IMAP (LIST/STATUS). Admin only.
    -> {ok, code ('queued'|'plan'|'balanced'|'rspamd'|'nothing'|'invalid'|'config'),
        text, dry_run, bayes:{spam, ham, ratio}, target_ratio, needed,
        jobs:[{account, folder, label, kind, messages, max_messages,
        provider_filter, job_id}], errors:[{account, code, text}], audit_detail}"""
    eng = _eng(engine)
    out: dict[str, Any] = {"ok": False, "code": "invalid", "text": "", "dry_run": bool(dry_run),
                           "bayes": None, "target_ratio": None, "needed": None, "jobs": [],
                           "errors": [], "audit_detail": ""}
    try:
        ratio = float(ratio)
        min_age_days = int(min_age_days)
        max_per_folder = int(max_per_folder)
    except (TypeError, ValueError):
        out["text"] = "Ugyldige værdier."
        return out
    if not 0.05 <= ratio <= 5 or not 0 <= min_age_days <= MAX_MIN_AGE_DAYS or max_per_folder < 1:
        out["text"] = "Ugyldige værdier."
        return out
    out["target_ratio"] = ratio
    st = bayes_stats(engine=eng)
    if not st.get("ok"):
        out.update(code="rspamd", text="Bayes-tallene kunne ikke hentes fra rspamd.")
        return out
    spam, ham = int(st.get("spam_learned") or 0), int(st.get("ham_learned") or 0)
    out["bayes"] = {"spam": spam, "ham": ham, "ratio": round(spam / ham, 3) if ham else None}
    needed = max(0, int(_math.ceil(ham * ratio)) - spam)
    out["needed"] = needed
    if needed == 0:
        out.update(ok=True, code="balanced",
                   text=f"Bayes er i balance: {spam} spam og {ham} legitime (mål 1:{_fmt(1 / ratio)}).")
        return out
    try:
        configs = list(eng.load_account_configs(eng.CONFIG_PATH))
    except Exception:
        out.update(code="config", text="Konfigurationen kunne ikke indlæses.")
        return out
    wanted = set(accounts) if accounts is not None else None
    plan = []
    for acc in configs:
        if not getattr(acc, "enabled", True) or (wanted is not None and acc.name not in wanted):
            continue
        try:
            _acc, client = _open_session(eng, acc.name, timeout=FIND_TIMEOUT_S)
        except ServiceError as ex:
            out["errors"].append({"account": acc.name, "code": ex.code, "text": ex.text})
            continue
        try:
            folders = _list_folders(client)
            fmap = _folder_map(acc, folders)
            cands = [("filter_junk", fmap["junk"], "any"), ("provider_junk", fmap.get("provider_junk"), "any")]
            if include_trash:
                cands.append(("trash", fmap.get("trash"), "provider_spam"))
            seen: set[str] = set()
            for kind, name, pf in cands:
                if not name or name in seen or name not in fmap["names"] or is_inbox_folder(acc, name) \
                        or name == fmap["inbox"]:
                    continue
                seen.add(name)
                try:
                    st_f = client.folder_status(name, [b"MESSAGES"])
                    n = int(st_f.get(b"MESSAGES", st_f.get("MESSAGES")) or 0)
                except Exception as ex:
                    if _is_conn_error(ex):
                        raise
                    n = 0
                if n <= 0:
                    continue
                plan.append({"account": acc.name, "folder": name, "label": folder_label(name), "kind": kind,
                             "messages": n, "max_messages": min(n, max_per_folder, MAX_TRAIN_MESSAGES),
                             "provider_filter": pf, "job_id": None})
        except Exception as ex:
            log.warning("rebalance plan failed for %s: %s", acc.name, type(ex).__name__)
            out["errors"].append({"account": acc.name, "code": "imap_error",
                                  "text": "Mapperne kunne ikke læses."})
        finally:
            _logout(client)
    plan.sort(key=lambda p: (-p["messages"], p["account"], p["folder"]))
    out["jobs"] = plan
    if not plan:
        out.update(code="nothing", text="Der er ingen spam-mapper med mails at lære fra.")
        return out
    if dry_run:
        out.update(ok=True, code="plan",
                   text=(f"Bayes har {spam} spam og {ham} legitime. Der mangler ca. {needed} spam for at nå "
                         f"1:{_fmt(1 / ratio)}; {len(plan)} spam-mapper kan bruges."))
        return out
    now = int(time.time())
    try:
        with closing(_open_db(eng)) as conn:
            tr = _trainer_mod()
            stop = tr.ensure_train_columns(conn)
            for p in plan:
                cols = "account, folder, kind, max_messages, min_age_days, seen_only, provider_filter, " \
                       "status, created_by, created_at" + (", stop_ratio" if stop else "")
                vals = [p["account"], p["folder"], "spam", p["max_messages"], min_age_days, 0,
                        p["provider_filter"], "queued", actor or None, now] + ([ratio] if stop else [])
                cur = conn.execute(f"INSERT INTO train_jobs({cols}) VALUES({','.join('?' * len(vals))})", vals)
                p["job_id"] = int(cur.lastrowid)
    except sqlite3.Error as ex:
        log.warning("rebalance queue failed: %s", type(ex).__name__)
        out.update(code="invalid", text="Jobbene kunne ikke gemmes.")
        return out
    out.update(ok=True, code="queued",
               text=(f"{len(plan)} træningsjob lagt i kø. De stopper af sig selv, når Bayes har mindst "
                     f"1 spam pr. {_fmt(1 / ratio)} legitime (mangler ca. {needed})."),
               audit_detail=f"bayes_rebalance jobs={len(plan)} needed={needed} ratio={ratio:g}")
    return out


# ===========================================================================
# 2.2 (B21): weekly report with the webshop guarantee
# ===========================================================================

try:
    from zoneinfo import ZoneInfo as _ZoneInfo

    _CPH_TZ: Any = _ZoneInfo("Europe/Copenhagen")
except Exception:  # pragma: no cover - no tzdata: the engine's EU rule
    _CPH_TZ = None

WEEKLY_METRICS = ("known_contact", "reply_detected", "first_contact",
                  "scanned", "moved", "released", "user_junked", "marked_spam", "zapped",
                  "spam_detected", "flagged", "blocklisted", "ham_guarded", "aged_scanned")
WEEKLY_KEYS = ("weekly_enabled", "weekly_admin_account", "weekly_users")
_WEEK_RE = re.compile(r"^(\d{4})-W(\d{2})$")
_MONTHS_DA = ("januar", "februar", "marts", "april", "maj", "juni", "juli", "august", "september",
              "oktober", "november", "december")
_WEBSHOP_MOVED_ACTIONS = ("pending_move", "moved_to_junk", "move_failed", "flagged")


def _local_midnight_ts(day: _dt.date) -> int:
    if _CPH_TZ is not None:
        return int(_dt.datetime(day.year, day.month, day.day, tzinfo=_CPH_TZ).timestamp())
    try:
        eng = _eng(None)
        utc = _dt.datetime(day.year, day.month, day.day, tzinfo=_dt.timezone.utc)
        dst = eng._last_sunday_0100_utc(day.year, 3) <= utc < eng._last_sunday_0100_utc(day.year, 10)
        return int((utc - _dt.timedelta(hours=2 if dst else 1)).timestamp())
    except Exception:
        return int(_dt.datetime(day.year, day.month, day.day, tzinfo=_dt.timezone.utc).timestamp())


def _local_today() -> _dt.date:
    if _CPH_TZ is not None:
        return _dt.datetime.now(_CPH_TZ).date()
    return _dt.date.today()


def week_label(monday: _dt.date) -> str:
    y, w, _d = monday.isocalendar()
    return f"{y}-W{w:02d}"


def parse_week(week: str | None = None, *, today: _dt.date | None = None) -> _dt.date:
    """Monday of an ISO week 'YYYY-Www'; None = the last completed week
    (Europe/Copenhagen). ValueError on a malformed week."""
    if week is None:
        t = today or _local_today()
        return t - _dt.timedelta(days=t.weekday() + 7)
    m = _WEEK_RE.match(str(week).strip())
    if not m:
        raise ValueError("week must be YYYY-Www")
    try:
        return _dt.date.fromisocalendar(int(m.group(1)), int(m.group(2)), 1)
    except ValueError:
        raise ValueError("week must be YYYY-Www") from None


def _week_span_da(monday: _dt.date) -> str:
    sunday = monday + _dt.timedelta(days=6)
    if monday.month == sunday.month:
        return f"{monday.day}.–{sunday.day}. {_MONTHS_DA[sunday.month - 1]} {sunday.year}"
    return (f"{monday.day}. {_MONTHS_DA[monday.month - 1]} – {sunday.day}. "
            f"{_MONTHS_DA[sunday.month - 1]} {sunday.year}")


def _domain_of(addr: Any) -> str:
    s = str(addr or "").strip().lower().strip("<>")
    return s.rpartition("@")[2].rstrip(".") if "@" in s else ""


def _under(domain: str, parent: str) -> bool:
    return bool(domain) and (domain == parent or domain.endswith("." + parent))


def _settings_kv(conn: sqlite3.Connection, key: str) -> str | None:
    try:
        row = conn.execute("SELECT value FROM settings_kv WHERE key=?", (key,)).fetchone()
    except sqlite3.Error:
        return None
    return None if row is None else row[0]


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "on", "yes", "ja")


def weekly_settings(*, engine: Any = None) -> dict[str, Any]:
    """settings_kv for the weekly report (the UI writes them, admin only):
    weekly_enabled '1'/'0' (missing = OFF), weekly_admin_account (the
    mailbox that gets the full report; missing = the first enabled mailbox
    not in shadow mode), weekly_users '1'/'0' (also a short own-mailbox
    report to every other mailbox; missing = off).
    -> {enabled, admin_account, admin_account_effective, users, external_url}"""
    eng = _eng(engine)
    vals: dict[str, Any] = {}
    try:
        with closing(_open_db_ro(eng)) as conn:
            for k in (*WEEKLY_KEYS, "external_url"):
                vals[k] = _settings_kv(conn, k)
    except sqlite3.Error:
        pass
    try:
        configs = list(eng.load_account_configs(eng.CONFIG_PATH))
    except Exception:
        configs = []
    names = [a.name for a in configs if getattr(a, "enabled", True)]
    chosen = vals.get("weekly_admin_account")
    effective = chosen if chosen in names else next(
        (a.name for a in configs if getattr(a, "enabled", True) and getattr(a, "mode", "shadow") != "shadow"),
        None)
    return {"enabled": _truthy(vals.get("weekly_enabled")), "admin_account": chosen,
            "admin_account_effective": effective, "users": _truthy(vals.get("weekly_users")),
            "external_url": vals.get("external_url") or None}


def _message_link(external_url: str | None, account: str, message_id: str) -> str | None:
    if not external_url:
        return None
    import base64 as _b64  # noqa: PLC0415
    from urllib.parse import quote as _quote  # noqa: PLC0415

    token = _b64.urlsafe_b64encode(str(message_id).encode("utf-8")).decode("ascii").rstrip("=")
    return f"{str(external_url).rstrip('/')}/messages/{_quote(account, safe='')}/{token}"


def weekly_data(week: str | None = None, *, account: str | None = None,
                engine: Any = None) -> dict[str, Any]:
    """Read-only aggregate of one ISO week (Monday-Sunday, Europe/Copenhagen;
    default the last completed week) against the week before:
      accounts: [{account, name, mode, scanned, moved, released (= mistakes),
                  missed (user_junked + marked_spam), zapped, spam_detected,
                  prev:{same keys}}]
      top_blocked: [{domain, n}] (5, mail decided by a block rule)
      threats: {class: n} or None (no messages.threat column yet - B16)
      thresholds: [{account, name, current, recommended, change, text}]
      drift: {bayes:{ok, spam, ham}, backup:{available, ok, age_s},
              login_problems:[{account, events, state}], circuit_stops:[{account, n}],
              own_domain_uribl, ham_guarded, aged_scanned, signatures: None}
      webshop: {domains, total, moved, line, moved_items:[{account, message_id,
                sender, subject, our_action, released, link}]}
    account=X restricts everything to that mailbox (short user report).
    Raises ValueError for a malformed week only."""
    eng = _eng(engine)
    monday = parse_week(week)
    prev_monday = monday - _dt.timedelta(days=7)
    days = [(monday + _dt.timedelta(days=i)).isoformat() for i in range(7)]
    prev_days = [(prev_monday + _dt.timedelta(days=i)).isoformat() for i in range(7)]
    since, until = _local_midnight_ts(monday), _local_midnight_ts(monday + _dt.timedelta(days=7))
    try:
        configs = list(eng.load_account_configs(eng.CONFIG_PATH))
    except Exception:
        configs = []
    by_name = {a.name: a for a in configs}
    names = [a.name for a in configs if getattr(a, "enabled", True)]
    if account is not None:
        names = [account]
    shop_domains: list[str] = []
    for a in configs:
        if account is not None and a.name != account:
            continue
        for d in getattr(a, "webshop_domains", None) or []:
            if d not in shop_domains:
                shop_domains.append(d)
    out: dict[str, Any] = {
        "week": week_label(monday), "prev_week": week_label(prev_monday), "monday": monday.isoformat(),
        "span": _week_span_da(monday), "since": since, "until": until, "account": account,
        "accounts": [], "top_blocked": [], "threats": None, "thresholds": [], "drift": {},
        "webshop": {"domains": shop_domains, "total": 0, "moved": 0, "line": "", "moved_items": []},
        "lookalike": [],
    }
    stats: dict[tuple[str, str], int] = {}
    ext_url = None
    try:
        with closing(_open_db_ro(eng)) as conn:
            ext_url = _settings_kv(conn, "external_url")
            q = ",".join("?" * len(WEEKLY_METRICS))
            for label, dset in (("cur", days), ("prev", prev_days)):
                for r in conn.execute(
                        f"SELECT account, metric, SUM(n) AS n FROM stats_daily WHERE metric IN ({q}) "
                        f"AND day IN ({','.join('?' * 7)}) GROUP BY account, metric", (*WEEKLY_METRICS, *dset)):
                    stats[(label, r["account"], r["metric"])] = int(r["n"] or 0)  # type: ignore[index]
            acc_sql, acc_args = ("AND account=?", [account]) if account else ("", [])
            blocked: dict[str, int] = {}
            for r in conn.execute(
                    f"SELECT sender, envelope_from FROM messages WHERE rule_hit LIKE 'block:%' "
                    f"AND COALESCE(scanned_at, first_seen) >= ? AND COALESCE(scanned_at, first_seen) < ? {acc_sql}",
                    (since, until, *acc_args)):
                d = _domain_of(r["sender"]) or _domain_of(r["envelope_from"])
                if d:
                    blocked[d] = blocked.get(d, 0) + 1
            out["top_blocked"] = [{"domain": d, "n": n} for d, n in
                                  sorted(blocked.items(), key=lambda kv: (-kv[1], kv[0]))[:5]]
            if "threat" in _columns(conn, "messages"):
                out["threats"] = {r["threat"]: int(r["n"]) for r in conn.execute(
                    f"SELECT threat, COUNT(*) AS n FROM messages WHERE threat IS NOT NULL AND threat != '' "
                    f"AND COALESCE(scanned_at, first_seen) >= ? AND COALESCE(scanned_at, first_seen) < ? "
                    f"{acc_sql} GROUP BY threat", (since, until, *acc_args))}
            if account is None:
                # B22: lookalikes of the protected domains that got an MX
                # or A record during the week (full report only).
                try:
                    out["lookalike"] = [
                        {"domain": r["domain"], "protected": r["protected"], "what": r["new_what"] or ""}
                        for r in conn.execute(
                            "SELECT domain, protected, new_what FROM lookalike_watch WHERE new_at >= ? "
                            "AND new_at < ? ORDER BY new_at, domain LIMIT 20", (since, until))]
                except sqlite3.Error:
                    out["lookalike"] = []
            try:
                # 2.6 (A2): copies of marked spam moved in other mailboxes.
                import campaigns  # noqa: PLC0415

                out["campaign"] = campaigns.weekly_counts(conn, since, until, account)
            except Exception as ex:
                log.warning("weekly campaign counts failed: %s", type(ex).__name__)
            try:
                # 2.8: what the new protections found (Prøv) or scored (Til).
                sql = ("SELECT event, COUNT(DISTINCT account || message_id) FROM events WHERE ts >= ? AND ts < ? "
                       "AND event IN ('qr_trial', 'qr_hit', 'clam3p_trial', 'clam3p_hit', 'mixscript_trial', 'mixscript_hit', "
                       "'domainage_trial', 'domainage_hit', 'payphish_trial', 'payphish_hit')")
                args: list[Any] = [since, until]
                if account:
                    sql += " AND account=?"
                    args.append(account)
                out["trials"] = {str(ev): int(n) for ev, n in conn.execute(sql + " GROUP BY event", args)}
                ai_sql = ("SELECT COUNT(*), SUM(verdict='spam') FROM ai_verdicts WHERE created_at >= ? AND created_at < ?"
                          + (" AND account=?" if account else ""))
                with contextlib.suppress(sqlite3.Error):
                    n_ai, n_spam = conn.execute(ai_sql, args).fetchone()
                    out["trials"]["ai"], out["trials"]["ai_spam"] = int(n_ai or 0), int(n_spam or 0)
            except Exception as ex:
                log.warning("weekly trial counts failed: %s", type(ex).__name__)
            if shop_domains:
                for r in conn.execute(
                        f"SELECT account, message_id, sender, envelope_from, subject, our_action, moved_to_junk_at "
                        f"FROM messages WHERE COALESCE(scanned_at, first_seen) >= ? "
                        f"AND COALESCE(scanned_at, first_seen) < ? AND COALESCE(origin, 'inbox_scan')='inbox_scan' "
                        f"{acc_sql}", (since, until, *acc_args)):
                    doms = (_domain_of(r["sender"]), _domain_of(r["envelope_from"]))
                    if not any(_under(d, s) for d in doms for s in shop_domains):
                        continue
                    out["webshop"]["total"] += 1
                    if r["moved_to_junk_at"] is not None or r["our_action"] in _WEBSHOP_MOVED_ACTIONS:
                        out["webshop"]["moved"] += 1
                        out["webshop"]["moved_items"].append({
                            "account": r["account"], "message_id": r["message_id"], "sender": r["sender"],
                            "subject": r["subject"], "our_action": r["our_action"],
                            "released": r["our_action"] in ("manual_release", "user_rescued"),
                            "link": _message_link(ext_url, r["account"], r["message_id"])})
            ev_counts: dict[tuple[str, str], int] = {}
            for r in conn.execute(
                    f"SELECT account, event, COUNT(*) AS n FROM events WHERE ts >= ? AND ts < ? AND event IN "
                    f"('login_failed','login_limited','circuit_open','own_domain_uribl','ham_guard') {acc_sql} "
                    f"GROUP BY account, event", (since, until, *acc_args)):
                ev_counts[(r["account"], r["event"])] = int(r["n"])
            states = {r["account"]: r["login_state"] for r in conn.execute(
                "SELECT * FROM account_status")} if "login_state" in _columns(conn, "account_status") else {}
    except sqlite3.Error as ex:
        log.warning("weekly_data failed: %s", type(ex).__name__)
        ev_counts, states = {}, {}

    def metrics(label: str, n: str) -> dict[str, int]:
        g = lambda m: stats.get((label, n, m), 0)  # type: ignore[arg-type]  # noqa: E731
        return {"scanned": g("scanned"), "moved": g("moved"), "released": g("released"),
                "missed": g("user_junked") + g("marked_spam"), "zapped": g("zapped"),
                "spam_detected": g("spam_detected"), "flagged": g("flagged"),
                "known_contact": g("known_contact"), "reply_detected": g("reply_detected"),
                "first_contact": g("first_contact")}

    for n in names:
        acc = by_name.get(n)
        out["accounts"].append({"account": n, "name": (getattr(acc, "display_name", None) or n) if acc else n,
                                "mode": getattr(acc, "mode", None) if acc else None,
                                **metrics("cur", n), "prev": metrics("prev", n)})
    shop = out["webshop"]
    shop["line"] = (f"Webshop-post: {shop['total']} mail{'s' if shop['total'] != 1 else ''} fra "
                    f"{'/'.join(shop_domains)} – {shop['moved']} flyttet") if shop_domains else ""
    for n in names:
        acc = by_name.get(n)
        if acc is None or getattr(acc, "mode", "shadow") not in ("flag", "move"):
            continue
        try:
            s = threshold_suggestion(n, engine=eng)
        except Exception as ex:
            log.warning("weekly suggestion for %s failed: %s", n, type(ex).__name__)
            continue
        out["thresholds"].append({"account": n, "name": getattr(acc, "display_name", None) or n,
                                  "current": s.get("current"), "recommended": s.get("recommended"),
                                  "change": s.get("change"), "text": s.get("text")})
    bayes = bayes_stats(engine=eng) if account is None else {"ok": False}
    backup = backup_status(engine=eng) if account is None else {"available": False}
    out["drift"] = {
        "bayes": {"ok": bool(bayes.get("ok")), "spam": bayes.get("spam_learned"), "ham": bayes.get("ham_learned")},
        "backup": {"available": bool(backup.get("available")), "ok": backup.get("ok"),
                   "age_s": backup.get("age_s")},
        "login_problems": [{"account": n, "events": ev_counts.get((n, "login_failed"), 0)
                            + ev_counts.get((n, "login_limited"), 0), "state": states.get(n)}
                           for n in names if ev_counts.get((n, "login_failed"), 0)
                           + ev_counts.get((n, "login_limited"), 0) or states.get(n) not in (None, "ok")],
        "circuit_stops": [{"account": n, "n": ev_counts[(n, "circuit_open")]} for n in names
                          if ev_counts.get((n, "circuit_open"))],
        "own_domain_uribl": sum(ev_counts.get((n, "own_domain_uribl"), 0) for n in names),
        "ham_guarded": sum(stats.get(("cur", n, "ham_guarded"), 0) for n in names),  # type: ignore[arg-type]
        "aged_scanned": sum(stats.get(("cur", n, "aged_scanned"), 0) for n in names),  # type: ignore[arg-type]
        "signatures": None,  # ClamAV (B20) not installed yet
    }
    out["totals"] = {k: sum(a[k] for a in out["accounts"]) for k in
                     ("scanned", "moved", "released", "missed", "zapped", "spam_detected",
                      "known_contact", "reply_detected", "first_contact")}
    return out


def _n_da(n: Any) -> str:
    try:
        return f"{int(n):,}".replace(",", ".")
    except (TypeError, ValueError):
        return "–"


def _plural(n: int, one: str, many: str) -> str:
    return one if n == 1 else many


def render_weekly(data: dict[str, Any], *, full: bool = True, preview: bool = False) -> dict[str, str]:
    """Danish subject/text/html of the weekly report from weekly_data().
    full=False is the short own-mailbox version (simple user profile)."""
    import html as _html  # noqa: PLC0415

    week_no = str(data.get("week", "")).rpartition("W")[2].lstrip("0") or "?"
    subject = ("[Prøve] " if preview else "") + f"Spamfilter: ugerapport for uge {week_no}"
    lines: list[str] = ["Hej", "", f"Ugerapport for uge {week_no} ({data.get('span', '')}).", ""]
    blocks: list[str] = [f"<p>Hej</p><p><strong>Ugerapport for uge {_html.escape(week_no)}</strong> "
                         f"({_html.escape(str(data.get('span', '')))}).</p>"]
    shop = data.get("webshop") or {}
    if shop.get("line"):
        lines += [shop["line"]]
        blocks.append(f"<p><strong>{_html.escape(shop['line'])}</strong></p>")
        if shop.get("moved_items"):
            lines.append("Flyttede webshop-mails:")
            lis = []
            for it in shop["moved_items"][:20]:
                state = " (frigivet)" if it.get("released") else ""
                link = f" – Frigiv: {it['link']}" if it.get("link") and not it.get("released") else ""
                lines.append(f"- {it.get('sender') or '(ukendt)'} – {it.get('subject') or '(intet emne)'}{state}{link}")
                a = (f' <a href="{_html.escape(it["link"])}">Frigiv</a>'
                     if it.get("link") and not it.get("released") else "")
                lis.append(f"<li>{_html.escape(str(it.get('sender') or '(ukendt)'))} – "
                           f"{_html.escape(str(it.get('subject') or '(intet emne)'))}{_html.escape(state)}{a}</li>")
            blocks.append("<ul>" + "".join(lis) + "</ul>")
        lines.append("")
    accs = data.get("accounts") or []
    if full:
        lines.append("Postkasser:")
        rows = []
        for a in accs:
            prev = a.get("prev") or {}
            lines.append(f"- {a['name']}: {_n_da(a['scanned'])} scannet, {_n_da(a['moved'])} flyttet til "
                         f"Spamfilter (ugen før {_n_da(prev.get('moved'))}), {_n_da(a['released'])} frigivet, "
                         f"{_n_da(a['missed'])} spam slap igennem"
                         + (f", {_n_da(a['zapped'])} flyttet efterfølgende" if a.get("zapped") else ""))
            rows.append("<tr>" + "".join(
                f'<td style="padding:4px 8px;border-bottom:1px solid #e5e7eb{";text-align:right" if i else ""}">'
                f"{_html.escape(str(v))}</td>"
                for i, v in enumerate((a["name"], _n_da(a["scanned"]), _n_da(a["moved"]), _n_da(prev.get("moved")),
                                       _n_da(a["released"]), _n_da(a["missed"])))) + "</tr>")
        blocks.append('<table style="border-collapse:collapse;font-size:14px"><tr>'
                      + "".join(f'<th align="{al}" style="padding:4px 8px">{t}</th>' for t, al in (
                          ("Postkasse", "left"), ("Scannet", "right"), ("Flyttet", "right"),
                          ("Ugen før", "right"), ("Frigivet", "right"), ("Slap igennem", "right")))
                      + "</tr>" + "".join(rows) + "</table>")
        lines.append("")
        if data.get("top_blocked"):
            lines.append("Mest blokerede domæner:")
            lines += [f"- {b['domain']}: {_n_da(b['n'])}" for b in data["top_blocked"]]
            blocks.append("<p><strong>Mest blokerede domæner</strong></p><ul>" + "".join(
                f"<li>{_html.escape(b['domain'])}: {_n_da(b['n'])}</li>" for b in data["top_blocked"]) + "</ul>")
            lines.append("")
        zapped = sum(int(a.get("zapped") or 0) for a in accs)
        if zapped:
            # B19: mail a rescan moved after delivery.
            lines.append(f"{ZAP_LATER_TEXT} (genscanning): {_n_da(zapped)}")
            blocks.append(f"<p><strong>{ZAP_LATER_TEXT}</strong> (genscanning): {_n_da(zapped)}</p>")
            lines.append("")
        camp = data.get("campaign") or {}
        if camp.get("moved") or camp.get("shadow"):
            # 2.6 (A2): the same spam found in other mailboxes.
            text = f"{_n_da(int(camp.get('moved') or 0))} flyttet" + (
                f", {_n_da(int(camp['shadow']))} ville være flyttet (Overvåg)" if camp.get("shadow") else "")
            lines.append(f"{CAMPAIGN_WEEKLY_TEXT}: {text}")
            blocks.append(f"<p><strong>{CAMPAIGN_WEEKLY_TEXT}</strong>: {_html.escape(text)}</p>")
            lines.append("")
        tr = data.get("trials") or {}
        parts = []
        for key, label in (("qr", "QR-koder med mistænkeligt link"), ("clam3p", "Sanesecurity-fund"),
                           ("mixscript", "snydetegn i emnet"), ("domainage", "nye domæner"),
                           ("payphish", "betalingsphishing")):
            n_on, n_try = int(tr.get(f"{key}_hit") or 0), int(tr.get(f"{key}_trial") or 0)
            if n_on:
                parts.append(f"{label} {_n_da(n_on)}")
            elif n_try:
                parts.append(f"{label} {_n_da(n_try)} (Prøv)")
        if tr.get("ai"):
            parts.append(f"AI vurderede {_n_da(int(tr['ai']))}, heraf spam {_n_da(int(tr.get('ai_spam') or 0))}")
        if parts:
            # 2.8: the new protections (Indstillinger -> Nye beskyttelser).
            text = ", ".join(parts)
            lines.append(f"{TRIALS_WEEKLY_TEXT}: {text}")
            blocks.append(f"<p><strong>{TRIALS_WEEKLY_TEXT}</strong>: {_html.escape(text)}</p>")
            lines.append("")
        if data.get("threats"):
            # B16: Danish class names, most severe first.
            order = list(THREAT_LABELS)
            items = sorted(data["threats"].items(), key=lambda kv: (order.index(kv[0]) if kv[0] in order
                                                                    else len(order), kv[0]))
            text = ", ".join(f"{THREAT_LABELS.get(k, k)} {_n_da(v)}" for k, v in items)
            lines.append("Trusler stoppet: " + text)
            blocks.append(f"<p><strong>Trusler stoppet:</strong> {_html.escape(text)}</p>")
            lines.append("")
        if data.get("lookalike"):
            # B22: domains are defanged ('pinslkbing[.]example'), never a link.
            look = [_lk().new_text(i) for i in data["lookalike"]]
            lines.append("Nye domæner, der ligner jeres:")
            lines += [f"- {t}" for t in look]
            blocks.append("<p><strong>Nye domæner, der ligner jeres</strong></p><ul>"
                          + "".join(f"<li>{_html.escape(t)}</li>" for t in look) + "</ul>")
            lines.append("")
        if data.get("thresholds"):
            lines.append("Grænse:")
            lines += [f"- {t['name']}: {t.get('text') or ''}" for t in data["thresholds"]]
            blocks.append("<p><strong>Grænse</strong></p><ul>" + "".join(
                f"<li>{_html.escape(str(t['name']))}: {_html.escape(str(t.get('text') or ''))}</li>"
                for t in data["thresholds"]) + "</ul>")
            lines.append("")
        drift = data.get("drift") or {}
        dl = []
        b = drift.get("bayes") or {}
        if b.get("ok"):
            dl.append(f"Bayes: {_n_da(b.get('spam'))} spam og {_n_da(b.get('ham'))} legitime lært")
        bk = drift.get("backup") or {}
        if bk.get("available"):
            age = bk.get("age_s")
            dl.append("Backup: " + ("seneste er " + _n_da(int(age // 3600)) + " timer gammel"
                                    if isinstance(age, (int, float)) else "status ukendt")
                      + ("" if bk.get("ok") in (None, True) else " – fejlede"))
        lp = drift.get("login_problems") or []
        dl.append("Login-problemer: " + (", ".join(p["account"] for p in lp) if lp else "ingen"))
        cs = drift.get("circuit_stops") or []
        dl.append("Sikkerhedsbremse: " + (", ".join(f"{c['account']} ({c['n']})" for c in cs) if cs else "ikke udløst"))
        if drift.get("own_domain_uribl"):
            dl.append(f"Egne domæner på domænelisten: {_n_da(drift['own_domain_uribl'])} gange")
        tot = data.get("totals") or {}
        if tot.get("known_contact") or tot.get("reply_detected") or tot.get("first_contact"):
            dl.append(f"Kendte kontakter: {_n_da(tot.get('known_contact'))} mails fra kendte kontakter, "
                      f"{_n_da(tot.get('reply_detected'))} svar på jeres mails genkendt, "
                      f"{_n_da(tot.get('first_contact'))} første mails fra nye afsendere")
        lines.append("Drift:")
        lines += [f"- {x}" for x in dl]
        blocks.append("<p><strong>Drift</strong></p><ul>" + "".join(f"<li>{_html.escape(x)}</li>" for x in dl)
                      + "</ul>")
        lines.append("")
    else:
        a = accs[0] if accs else {"moved": 0, "released": 0, "missed": 0}
        moved = int(a.get("moved") or 0)
        txt = (f"Filteret flyttede {_n_da(moved)} {_plural(moved, 'mail', 'mails')} til Spamfilter-mappen. "
               f"{_n_da(a.get('released'))} blev frigivet igen.")
        lines += [txt, "", "Savner du en mail, så kig i Spamfilter-mappen. Træk den tilbage til Indbakke, "
                           "så lærer filteret det.", ""]
        blocks.append(f"<p>{_html.escape(txt)}</p><p>Savner du en mail, så kig i Spamfilter-mappen. "
                      "Træk den tilbage til Indbakke, så lærer filteret det.</p>")
    lines.append(siteconfig.signature())
    html_body = ('<!doctype html><html lang="da"><body style="font-family:-apple-system,Segoe UI,Roboto,'
                 'Helvetica,Arial,sans-serif;color:#111827;max-width:720px">' + "".join(blocks)
                 + '<p style="color:#6b7280">' + _html.escape(siteconfig.signature()) + '</p></body></html>')
    return {"subject": subject, "text": "\n".join(lines) + "\n", "html": html_body}


def weekly_preview(account: str | None = None, week: str | None = None, *, full: bool | None = None,
                   engine: Any = None) -> dict[str, Any]:
    """Admin preview without IMAP: {ok, code, text, week, full, subject,
    body_text, body_html, data}. account=None (or the admin mailbox) = the
    full report; another mailbox = its short version (full=False), unless
    `full` says otherwise."""
    eng = _eng(engine)
    try:
        settings = weekly_settings(engine=eng)
        if full is None:
            full = account is None or account == settings.get("admin_account_effective")
        data = weekly_data(week, account=None if full else account, engine=eng)
    except ValueError as ex:
        return {"ok": False, "code": "invalid", "text": "Ugen skal skrives som ÅÅÅÅ-Uuu (fx 2026-W43).",
                "error": str(ex)}
    r = render_weekly(data, full=full, preview=True)
    return {"ok": True, "code": "ok", "text": "", "week": data["week"], "full": full,
            "subject": r["subject"], "body_text": r["text"], "body_html": r["html"], "data": data}


def send_weekly_now(account: str, *, preview: bool = True, week: str | None = None,
                    full: bool | None = None, actor: str = "", engine: Any = None) -> dict[str, Any]:
    """Admin 'Send nu': append the weekly report to the mailbox's INBOX
    (engine.send_weekly_report; recorded so the scanner never scans it).
    preview=True marks it '[Prøve]' and does not count as that week's
    report. -> {ok, code ('sent'|'config'|'no_account'|'auth'|'no_secret'|
    'connect'|'imap_error'|'invalid'), text, week, message_id, full, audit_detail}"""
    eng = _eng(engine)
    fn = getattr(eng, "send_weekly_report", None)
    if fn is None:
        return {"ok": False, "code": "config", "text": "Ugerapporten findes ikke i denne version."}
    res = fn(account, preview=preview, week=week, full=full, actor=actor)
    if isinstance(res, dict) and res.get("ok"):
        res.setdefault("audit_detail", f"weekly_report {account} week={res.get('week')} "
                                       f"{'preview' if preview else 'sent'}")
    return res


# ---------------------------------------------------------------------------
# 2.3: Kendte kontakter (B10-B14) - read/write API for the UI (B13)
# ---------------------------------------------------------------------------
#
# Every function takes the account name and checks it exists in the
# configuration (the UI checks the user's permission/scope with can()/
# require_account before calling). Read-only unless the name says
# otherwise; writes return `audit_detail` (masks only, never a full
# address) for dashboard.audit. Contact addresses are stored as HMAC
# hashes; a full address is shown only when the same address also wrote
# to the mailbox (it is then in messages.sender anyway).

CONTACT_STATUSES = ("active", "removed", "demoted")
CONTACT_STATUS_TEXT = {"active": "Kendt kontakt", "removed": "Fjernet",
                       "demoted": "Fjernet efter spam"}
CONTACT_GROUPS = ("people", "orgs")
CONTACTS_HELP = ("Vi læser kun modtager-adresser og Message-ID fra dine sendte mails – "
                 "aldrig indholdet.")
CONTACTS_PER_PAGE_MAX = 200
CONTACT_TRUST_METRICS = ("known_contact", "reply_detected", "established")
_MONTHS_SHORT_DA = ("jan.", "feb.", "marts", "april", "maj", "juni", "juli", "aug.", "sep.", "okt.",
                    "nov.", "dec.")
_H_RE = re.compile(r"^[0-9a-f]{32}$")
_CONTACT_EVENT = {"removed": "contact_removed", "active": "contact_restored", "demoted": "contact_demoted"}
_CONTACT_SET_TEXT = {"removed": "Afsenderen er fjernet fra Kendte kontakter.",
                     "active": "Afsenderen er gendannet som kendt kontakt.",
                     "demoted": "Afsenderen er fjernet fra Kendte kontakter (markeret som spam)."}

# B13 label texts (message detail). tone: green | blue | amber | grey.
TRUST_LABEL_KINDS = ("known_contact", "reply", "established", "first_contact", "reply_unverified")


def _contacts_mod() -> Any:
    import contacts  # noqa: PLC0415 - same image, lazy like the engine

    return contacts


def _cph_dt(ts: Any) -> _dt.datetime | None:
    try:
        t = float(ts)
    except (TypeError, ValueError):
        return None
    try:
        from zoneinfo import ZoneInfo  # noqa: PLC0415

        return _dt.datetime.fromtimestamp(t, ZoneInfo("Europe/Copenhagen"))
    except Exception:
        return _dt.datetime.fromtimestamp(t)


def month_year_da(ts: Any) -> str:
    """'marts 2026' (Copenhagen time); '' when unknown."""
    d = _cph_dt(ts)
    return f"{_MONTHS_DA[d.month - 1]} {d.year}" if d else ""


def day_month_da(day: str | None, *, today: _dt.date | None = None) -> str:
    """'12. okt.' from 'YYYY-MM-DD' (year added when not this year)."""
    try:
        d = _dt.date.fromisoformat(str(day))
    except (TypeError, ValueError):
        return ""
    today = today or _local_today()
    text = f"{d.day}. {_MONTHS_SHORT_DA[d.month - 1]}"
    return text if d.year == today.year else f"{text} {d.year}"


def when_da(ts: Any, *, now: float | None = None) -> str:
    """'i dag 14:05' / 'i går 14:05' / '12. okt. 14:05'."""
    d = _cph_dt(ts)
    if d is None:
        return "aldrig"
    n = _cph_dt(time.time() if now is None else now)
    clock = d.strftime("%H:%M")
    if n is not None and d.date() == n.date():
        return f"i dag {clock}"
    if n is not None and d.date() == n.date() - _dt.timedelta(days=1):
        return f"i går {clock}"
    return f"{day_month_da(d.date().isoformat(), today=n.date() if n else None)} {clock}"


def _gange(n: int) -> str:
    return f"{_n_da(n)} {'gang' if int(n) == 1 else 'gange'}"


def _contact_scope(eng: Any, account: str) -> tuple[Any | None, dict[str, Any] | None]:
    try:
        acc = _find_account(eng, account)
    except Exception:
        return None, {"ok": False, "code": "config", "text": "Konfigurationen kunne ikke indlæses."}
    if acc is None:
        return None, {"ok": False, "code": "no_account", "text": "Kontoen findes ikke."}
    return acc, None


def _opt(options: Iterable[Any], prefix: str) -> str | None:
    for o in options or ():
        s = str(o)
        if s.startswith(prefix):
            return s[len(prefix):]
    return None


def trust_labels(symbols: Any, *, numbers: bool = True, today: _dt.date | None = None) -> list[dict[str, Any]]:
    """B13 labels from a message's stored symbols (JSON or list):
    [{kind, tone, text, symbol}] in the order known contact / reply /
    established / first contact / unverified reply. numbers=False ("Se som
    bruger") leaves out counts and dates."""
    try:
        data = json.loads(symbols) if isinstance(symbols, (str, bytes)) else list(symbols or [])
    except (TypeError, ValueError):
        data = []
    by = {str(s.get("n")): s for s in data if isinstance(s, dict) and s.get("n")}
    out: list[dict[str, Any]] = []

    def add(kind: str, tone: str, text: str, sym: str) -> None:
        out.append({"kind": kind, "tone": tone, "text": text, "symbol": sym})

    kc = by.get("TH_KNOWN_CONTACT")
    if kc is not None:
        opts = kc.get("o") or []
        try:
            n = int(_opt(opts, "sendt=") or 0)
        except ValueError:
            n = 0
        group = "gruppe" in opts
        if group:
            # A colleague mailbox's contact: never a count (older rows carried
            # the colleagues' total - not this mailbox's business).
            add("known_contact", "green", "Kendt kontakt – en kollega har skrevet til afsenderen" if numbers
                else "Kendt kontakt", "TH_KNOWN_CONTACT")
        elif not numbers or n <= 0:
            add("known_contact", "green", "Kendt kontakt", "TH_KNOWN_CONTACT")
        else:
            add("known_contact", "green", f"Kendt kontakt – du har skrevet til afsenderen {_gange(n)}",
                "TH_KNOWN_CONTACT")
    kd = by.get("TH_KNOWN_DOMAIN")
    if kd is not None and kc is None:
        add("known_contact", "green", "Kendt organisation – du har skrevet til andre her", "TH_KNOWN_DOMAIN")
    for sym in ("TH_REPLY", "TH_REPLY_THREAD"):
        r = by.get(sym)
        if r is None:
            continue
        day = day_month_da(_opt(r.get("o") or [], "sendt="), today=today) if numbers else ""
        text = f"Svar på din mail fra {day}" if day else "Svar på din mail"
        if sym == "TH_REPLY_THREAD":
            text += " (ny deltager i tråden)"
        add("reply", "green", text, sym)
        break
    est = by.get("TH_ESTABLISHED")
    if est is not None:
        opts = est.get("o") or []
        n = _opt(opts, "n=")
        since = _opt(opts, "siden=")
        if numbers and n and since:
            add("established", "blue", f"Fast afsender – {_n_da(n)} mails siden {since}", "TH_ESTABLISHED")
        else:
            add("established", "blue", "Fast afsender", "TH_ESTABLISHED")
    if "TH_FIRST_CONTACT" in by:
        add("first_contact", "amber", "Første mail fra denne afsender", "TH_FIRST_CONTACT")
    if "TH_REPLY_UNVERIFIED" in by:
        add("reply_unverified", "grey", "Ligner et svar, men afsenderen kunne ikke bekræftes",
            "TH_REPLY_UNVERIFIED")
    return out


def message_trust_labels(account: str, message_id: str, *, numbers: bool = True,
                         engine: Any = None) -> list[dict[str, Any]]:
    """trust_labels() of one stored message ([] when unknown)."""
    eng = _eng(engine)
    mid = normalize_message_id(message_id)
    if mid is None:
        return []
    try:
        with closing(_open_db_ro(eng)) as conn:
            row = conn.execute("SELECT symbols FROM messages WHERE account=? AND message_id=?",
                               (account, mid)).fetchone()
    except sqlite3.Error:
        return []
    return trust_labels(row["symbols"], numbers=numbers) if row is not None else []


def _contact_rows_ok(conn: sqlite3.Connection) -> bool:
    return _table_exists(conn, "known_contacts") and _table_exists(conn, "contacts_sync")


def contacts_overview(account: str, *, engine: Any = None) -> dict[str, Any]:
    """Status card: {ok, code, account, enabled, complete, contacts,
    removed, demoted, sent_mails, senders, last_sync_at, last_sync_text,
    progress:{done, total, percent}, requested, group, text, help}."""
    eng = _eng(engine)
    acc, err = _contact_scope(eng, account)
    if err:
        return {**err, "account": account}
    enabled = bool(getattr(acc, "known_contacts", False))
    out: dict[str, Any] = {"ok": True, "code": "ok", "account": account, "enabled": enabled,
                           "complete": False, "contacts": 0, "removed": 0, "demoted": 0, "sent_mails": 0,
                           "senders": 0, "last_sync_at": None, "last_sync_text": "aldrig",
                           "progress": {"done": 0, "total": 0, "percent": 0}, "requested": False,
                           "group": None, "text": "", "help": CONTACTS_HELP}
    try:
        with closing(_open_db_ro(eng)) as conn:
            if _contact_rows_ok(conn):
                for r in conn.execute("SELECT status, COUNT(*) AS n FROM known_contacts WHERE account=? "
                                      "AND source='sent' GROUP BY status", (account,)):
                    key = {"active": "contacts", "removed": "removed", "demoted": "demoted"}.get(r["status"])
                    if key:
                        out[key] = int(r["n"])
                out["sent_mails"] = int(conn.execute("SELECT COUNT(*) FROM sent_threads WHERE account=?",
                                                     (account,)).fetchone()[0])
                out["senders"] = int(conn.execute("SELECT COUNT(*) FROM sender_history WHERE account=?",
                                                  (account,)).fetchone()[0])
                done = total = 0
                summary = None
                for r in conn.execute("SELECT * FROM contacts_sync WHERE account=?", (account,)):
                    if r["folder"] == "*":
                        summary = r
                        continue
                    t = int(r["total"] or 0)
                    total += t
                    done += t if r["complete"] else min(t, int(r["messages"] or 0))
                if summary is not None:
                    out["complete"] = bool(summary["complete"])
                    out["last_sync_at"] = summary["synced_at"]
                    out["group"] = summary["grp"]
                    out["sent_mails"] = max(out["sent_mails"], int(summary["messages"] or 0))
                pct = 100 if out["complete"] else (int(done * 100 / total) if total else 0)
                out["progress"] = {"done": done, "total": total, "percent": min(100, pct)}
            token = conn.execute("SELECT value FROM engine_state WHERE key=?",
                                 (_contacts_mod().REQUEST_STATE + account,)).fetchone() \
                if _table_exists(conn, "engine_state") else None
            out["requested"] = token is not None and (
                out["last_sync_at"] is None or _request_ts(token[0]) > int(out["last_sync_at"] or 0))
    except sqlite3.Error as ex:
        log.warning("contacts_overview failed: %s", type(ex).__name__)
        return {**out, "ok": False, "code": "db", "text": "Databasen kunne ikke læses."}
    if out["last_sync_at"]:
        out["last_sync_text"] = when_da(out["last_sync_at"])
    if not enabled:
        out["text"] = "Kendte kontakter er slået fra for denne postkasse."
    elif out["complete"]:
        out["text"] = (f"Lært fra dine sendte mails: {_n_da(out['contacts'])} kontakter · "
                       f"{_n_da(out['sent_mails'])} sendte mails · opdateret {out['last_sync_text']}")
    elif out["progress"]["total"]:
        out["text"] = (f"Lærer fra dine sendte mails … {out['progress']['percent']} % – kendte kontakter "
                       "bruges, når den første gennemgang er færdig.")
    else:
        out["text"] = "Den første gennemgang af dine sendte mails er ikke startet endnu."
    return out


def _request_ts(token: Any) -> int:
    try:
        return int(str(token).split(":", 1)[0])
    except (TypeError, ValueError):
        return 0


def _inbound_addresses(conn: sqlite3.Connection, account: str, key: bytes) -> dict[str, str]:
    """h -> address for addresses that also WROTE to the mailbox."""
    c = _contacts_mod()
    out: dict[str, str] = {}
    for r in conn.execute("SELECT DISTINCT lower(sender) AS s FROM messages WHERE account=? "
                          "AND sender IS NOT NULL AND sender LIKE '%@%' LIMIT 20000", (account,)):
        norm = c.normalize_address(r["s"])
        if norm:
            out.setdefault(c.hash_address(key, norm), norm)
    return out


def contacts_list(account: str, q: str = "", page: int = 1, per_page: int = 50, group: str = "people",
                  *, status: str = "all", engine: Any = None) -> dict[str, Any]:
    """The 'Kendte kontakter' list. group='people': one row per contact
    {h, address (only when the address also wrote to you, else None),
    display (address or mask), masked, domain, sent_count, last_sent_at,
    last_sent_text, status, status_text, source, can_remove, can_restore};
    group='orgs': one row per non-freemail domain {domain, contacts,
    sent_count, last_sent_at, last_sent_text}. q: a full address is looked
    up via its hash (result in `lookup`), other text filters on domain/mask.
    status: all|active|removed|demoted (people only)."""
    eng = _eng(engine)
    acc, err = _contact_scope(eng, account)
    if err:
        return {**err, "account": account, "items": [], "total": 0}
    group = group if group in CONTACT_GROUPS else "people"
    status = status if status in (*CONTACT_STATUSES, "all") else "all"
    try:
        page = max(1, int(page))
        per_page = max(1, min(CONTACTS_PER_PAGE_MAX, int(per_page)))
    except (TypeError, ValueError):
        page, per_page = 1, 50
    q = _CTRL_RE.sub("", str(q or "")).strip()[:200]
    out: dict[str, Any] = {"ok": True, "code": "ok", "account": account, "group": group, "status": status,
                           "q": q, "page": page, "per_page": per_page, "total": 0, "pages": 1, "items": [],
                           "lookup": None, "help": CONTACTS_HELP}
    c = _contacts_mod()
    if q and "@" in q:
        out["lookup"] = contact_lookup(account, q, engine=eng)
        q_filter = ""
    else:
        q_filter = q.lower()
    try:
        with closing(_open_db_ro(eng)) as conn:
            if not _contact_rows_ok(conn):
                return out
            key = c.load_key(eng.STATE_DIR, None, create=False)
            if group == "orgs":
                rows = [r for r in conn.execute(
                    "SELECT domain, COUNT(*) AS n, SUM(sent_count) AS sent, MAX(last_sent_at) AS last "
                    "FROM known_contacts WHERE account=? AND status='active' AND domain IS NOT NULL "
                    "GROUP BY domain ORDER BY n DESC, sent DESC, domain", (account,))
                    if not c.is_freemail(r["domain"]) and (not q_filter or q_filter in r["domain"])]
                out["total"] = len(rows)
                sel = rows[(page - 1) * per_page: page * per_page]
                out["items"] = [{"domain": r["domain"], "contacts": int(r["n"]), "sent_count": int(r["sent"] or 0),
                                 "last_sent_at": r["last"], "last_sent_text": month_year_da(r["last"])}
                                for r in sel]
            else:
                where = "account=?"
                args: list[Any] = [account]
                if status != "all":
                    where += " AND status=?"
                    args.append(status)
                if q_filter:
                    where += " AND (lower(COALESCE(domain,'')) LIKE ? OR lower(COALESCE(mask,'')) LIKE ?)"
                    args += [f"%{_like(q_filter)}%", f"%{_like(q_filter)}%"]
                out["total"] = int(conn.execute(f"SELECT COUNT(*) FROM known_contacts WHERE {where}",
                                                args).fetchone()[0])
                rows = conn.execute(
                    f"SELECT * FROM known_contacts WHERE {where} ORDER BY (status='active') DESC, "
                    f"last_sent_at DESC, h LIMIT ? OFFSET ?", (*args, per_page, (page - 1) * per_page)).fetchall()
                inbound = _inbound_addresses(conn, account, key) if key is not None and rows else {}
                for r in rows:
                    addr = inbound.get(r["h"])
                    st = r["status"]
                    out["items"].append({
                        "h": r["h"], "address": addr, "display": addr or (r["mask"] or "…"),
                        "masked": addr is None, "domain": r["domain"], "sent_count": int(r["sent_count"] or 0),
                        "last_sent_at": r["last_sent_at"], "last_sent_text": month_year_da(r["last_sent_at"]),
                        "status": st, "status_text": CONTACT_STATUS_TEXT.get(st, st), "source": r["source"],
                        "can_remove": st == "active", "can_restore": st != "active"})
    except sqlite3.Error as ex:
        log.warning("contacts_list failed: %s", type(ex).__name__)
        return {**out, "ok": False, "code": "db", "text": "Databasen kunne ikke læses."}
    out["pages"] = max(1, -(-out["total"] // per_page))
    return out


def contact_lookup(account: str, address: str, *, engine: Any = None) -> dict[str, Any]:
    """'Har jeg skrevet til …?' via the hash: {ok, code ('found'|'not_found'|
    'invalid'|'not_ready'|...), found, h, mask, sent_count, last_sent_at,
    status, text}. The text echoes the address the user typed."""
    eng = _eng(engine)
    acc, err = _contact_scope(eng, account)
    if err:
        return {**err, "found": False}
    c = _contacts_mod()
    norm = c.normalize_address(address)
    base = {"ok": True, "found": False, "h": None, "mask": None, "sent_count": 0, "last_sent_at": None,
            "status": None}
    if norm is None:
        return {**base, "ok": False, "code": "invalid", "text": "Skriv en hel mailadresse, fx navn@firma.dk."}
    key = c.load_key(eng.STATE_DIR, None, create=False)
    if key is None:
        return {**base, "ok": False, "code": "not_ready", "text": "Kendte kontakter er ikke klar endnu."}
    h = c.hash_address(key, norm)
    try:
        with closing(_open_db_ro(eng)) as conn:
            row = conn.execute("SELECT * FROM known_contacts WHERE account=? AND h=?", (account, h)).fetchone() \
                if _table_exists(conn, "known_contacts") else None
    except sqlite3.Error:
        return {**base, "ok": False, "code": "db", "text": "Databasen kunne ikke læses."}
    shown = norm
    if row is None or int(row["sent_count"] or 0) <= 0:
        return {**base, "code": "not_found", "h": h, "mask": c.mask(norm),
                "status": row["status"] if row is not None else None,
                "text": f"Nej, du har ikke skrevet til {shown} fra denne postkasse."}
    n = int(row["sent_count"] or 0)
    text = f"Ja, du har skrevet til {shown} {_gange(n)}, senest {month_year_da(row['last_sent_at'])}."
    if row["status"] != "active":
        text += " Afsenderen er fjernet fra Kendte kontakter."
    return {**base, "code": "found", "found": True, "h": h, "mask": row["mask"] or c.mask(norm),
            "sent_count": n, "last_sent_at": row["last_sent_at"], "status": row["status"], "text": text}


def set_contact_status(account: str, h: str, status: str, actor: str, *,
                       engine: Any = None) -> dict[str, Any]:
    """WRITE: 'removed' (Fjern) | 'active' (Gendan; also undoes an
    automatic demotion and its n_junk) | 'demoted'. Survives every resync.
    -> {ok, code ('ok'|'invalid'|'unchanged'|'no_account'|'db'), text,
    previous, mask, audit_detail}. Logs event contact_removed /
    contact_restored / contact_demoted (mask only)."""
    eng = _eng(engine)
    acc, err = _contact_scope(eng, account)
    if err:
        return err
    h = str(h or "").strip().lower()
    if status not in CONTACT_STATUSES or not _H_RE.match(h):
        return {"ok": False, "code": "invalid", "text": "Ugyldig kontakt eller status."}
    c = _contacts_mod()
    try:
        with closing(_open_db(eng)) as conn:
            c.ensure_schema(conn)
            row = conn.execute("SELECT status, mask FROM known_contacts WHERE account=? AND h=?",
                               (account, h)).fetchone()
            if row is not None and row["status"] == status:
                return {"ok": True, "code": "unchanged", "text": _CONTACT_SET_TEXT[status],
                        "previous": status, "mask": row["mask"], "audit_detail": ""}
            if row is None and status == "active":
                hist = conn.execute("SELECT n_junk FROM sender_history WHERE account=? AND h=?",
                                    (account, h)).fetchone()
                if hist is None or not int(hist["n_junk"] or 0):
                    return {"ok": False, "code": "invalid", "text": "Kontakten findes ikke."}
            msk = row["mask"] if row is not None else None
            conn.execute("BEGIN IMMEDIATE")
            try:
                prev = c.set_status(conn, account, h, status, actor or "webui", now=int(time.time()))
                conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                             (account, int(time.time()), None, _CONTACT_EVENT[status],
                              f"{msk or h[:8]} af {actor or 'webui'}"[:300]))
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
    except sqlite3.Error as ex:
        log.warning("set_contact_status failed: %s", type(ex).__name__)
        return {"ok": False, "code": "db", "text": "Databasen kunne ikke opdateres."}
    return {"ok": True, "code": "ok", "text": _CONTACT_SET_TEXT[status], "previous": prev or None, "mask": msk,
            "audit_detail": f"{msk or h[:8]} {prev or '-'}->{status}"}


def restore_contact(account: str, h: str, actor: str, *, engine: Any = None) -> dict[str, Any]:
    """WRITE: undo a removal or an automatic demotion ('Gendan')."""
    return set_contact_status(account, h, "active", actor, engine=engine)


def request_contacts_sync(account: str, actor: str, *, engine: Any = None) -> dict[str, Any]:
    """WRITE: 'Opdater nu' - the account thread runs an incremental Sent
    sync at its next loop (woken within ~5 s). -> {ok, code ('queued'|
    'disabled'|...), text, audit_detail}."""
    eng = _eng(engine)
    acc, err = _contact_scope(eng, account)
    if err:
        return err
    if not getattr(acc, "known_contacts", False):
        return {"ok": False, "code": "disabled", "text": "Kendte kontakter er slået fra for denne postkasse."}
    token = f"{int(time.time())}:{os.urandom(4).hex()}"
    try:
        with closing(_open_db(eng)) as conn:
            conn.execute(
                "INSERT INTO engine_state(key, value, updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE "
                "SET value=excluded.value, updated_at=excluded.updated_at",
                (_contacts_mod().REQUEST_STATE + account, token, int(time.time())))
            conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                         (account, int(time.time()), None, "contacts_sync_requested", f"af {actor or 'webui'}"))
            wake = getattr(eng, "request_wake", None)
            if wake is not None:
                wake(conn, account)
    except sqlite3.Error as ex:
        log.warning("request_contacts_sync failed: %s", type(ex).__name__)
        return {"ok": False, "code": "db", "text": "Databasen kunne ikke opdateres."}
    return {"ok": True, "code": "queued", "text": "Kendte kontakter opdateres fra dine sendte mails om lidt.",
            "audit_detail": "contacts_sync"}


def set_known_contacts_enabled(account: str, enabled: bool, actor: str, *, engine: Any = None,
                               save_config: Any = None) -> dict[str, Any]:
    """WRITE: 'Stol på folk, jeg har skrevet til' on/off - the account's
    `known_contacts` key in accounts.yml via dashboard.save_config
    (validation, atomic write, reload, audit 'known_contacts').
    -> {ok, code ('ok'|'no_account'|'rejected'), text}."""
    eng = _eng(engine)
    acc, err = _contact_scope(eng, account)
    if err:
        return err
    want = bool(enabled)
    if save_config is None:
        import dashboard  # noqa: PLC0415 - the UI process; never at import time

        save_config = dashboard.save_config

    def mutate(raw: dict) -> None:
        for entry in raw.get("accounts") or []:
            if isinstance(entry, dict) and entry.get("name") == account:
                entry["known_contacts"] = want
                return
        raise ValueError("Kontoen findes ikke i konfigurationen.")

    try:
        save_config(mutate, actor, "known_contacts", account=account,
                    detail=f"known_contacts={'on' if want else 'off'}")
    except ValueError as ex:
        return {"ok": False, "code": "rejected", "text": f"Ændringen blev afvist: {str(ex)[:200]}"}
    return {"ok": True, "code": "ok",
            "text": ("Kendte kontakter er slået til." if want else "Kendte kontakter er slået fra.")
            + " Filteret genstarter postkassen om et øjeblik."}


def trust_counts_today(accounts: Iterable[str] | None = None, *, day: str | None = None,
                       engine: Any = None) -> dict[str, Any]:
    """'Beskyttet af kendte kontakter i dag: N' - mails that got a known
    contact / reply / established bonus today (Copenhagen day), for the
    accounts the user may see. -> {day, total, by_account, text}."""
    eng = _eng(engine)
    day = day or _local_today().isoformat()
    names = [str(a) for a in accounts] if accounts is not None else None
    by: dict[str, int] = {}
    try:
        with closing(_open_db_ro(eng)) as conn:
            sql = (f"SELECT account, SUM(n) AS n FROM stats_daily WHERE day=? AND metric IN "
                   f"({','.join('?' * len(CONTACT_TRUST_METRICS))})")
            args: list[Any] = [day, *CONTACT_TRUST_METRICS]
            if names is not None:
                if not names:
                    return {"day": day, "total": 0, "by_account": {}, "text": "Beskyttet af kendte kontakter i dag: 0"}
                sql += f" AND account IN ({','.join('?' * len(names))})"
                args += names
            for r in conn.execute(sql + " GROUP BY account", args):
                by[r["account"]] = int(r["n"] or 0)
    except sqlite3.Error:
        by = {}
    total = sum(by.values())
    return {"day": day, "total": total, "by_account": by,
            "text": f"Beskyttet af kendte kontakter i dag: {_n_da(total)}"}


# ---------------------------------------------------------------------------
# 2.3 (B16/B19): threat class and rescans on a message
# ---------------------------------------------------------------------------

_ZAP_EVENTS = ("zap_move", "would_have_zapped", "zap_rescore")
_ZAP_NEW_RE = re.compile(r"\bny=(\S+)")
_ZAP_AGE_RE = re.compile(r"\befter=(\d+ (?:t|min))")


def zap_timeline_text(detail: Any) -> str:
    """'Ny viden: DBL_SPAM kom til efter 3 t' from a zap_move /
    would_have_zapped / zap_rescore event detail ('' when nothing new)."""
    text = str(detail or "")
    m = _ZAP_NEW_RE.search(text)
    new = [n for n in (m.group(1).split(",") if m else []) if n and n != "-"]
    age = _ZAP_AGE_RE.search(text)
    if not new:
        return f"Genscannet efter {age.group(1)} – intet nyt" if age else "Genscannet – intet nyt"
    names = new[0] if len(new) == 1 else ", ".join(new[:-1]) + " og " + new[-1]
    return f"Ny viden: {names} kom til" + (f" efter {age.group(1)}" if age else "")


def message_threat_info(account: str, message_id: str, *, engine: Any = None) -> dict[str, Any]:
    """Threat class (B16) and rescan history (B19) of one stored message for
    the message detail / mail rows. Read-only.
    -> {ok, code ('ok'|'not_found'|'invalid_id'|'db'), account, message_id,
        threat, threat_detail, threat_text, confirm_text, tone ('red'|None),
        user_release (False for a threat: Brugere see 'Kontakt administrator'),
        admin_text, zapped (bool), zapped_at, zap_label ('Fanget ved
        genscanning' | ''), timeline:[{ts, event, text}]}"""
    eng = _eng(engine)
    mid = normalize_message_id(message_id)
    out: dict[str, Any] = {"ok": False, "code": "invalid_id", "account": account, "message_id": message_id,
                           "threat": None, "threat_detail": None, "threat_text": "", "confirm_text": "",
                           "tone": None, "user_release": True, "admin_text": "", "zapped": False,
                           "zapped_at": None, "zap_label": "", "timeline": []}
    if mid is None:
        return out
    try:
        with closing(_open_db_ro(eng)) as conn:
            row = conn.execute("SELECT * FROM messages WHERE account=? AND message_id=?",
                               (account, mid)).fetchone()
            if row is None:
                out.update(code="not_found", message_id=mid)
                return out
            evs = conn.execute(
                f"SELECT ts, event, detail FROM events WHERE account=? AND message_id=? AND event IN "
                f"({','.join('?' * len(_ZAP_EVENTS))}) ORDER BY ts, id",
                (account, mid, *_ZAP_EVENTS)).fetchall()
    except sqlite3.Error:
        out["code"] = "db"
        return out
    names = row.keys()
    threat = row["threat"] if "threat" in names and row["threat"] else None
    detail = row["threat_detail"] if "threat_detail" in names else None
    zapped_at = row["zapped_at"] if "zapped_at" in names else None
    out.update(ok=True, code="ok", message_id=mid, threat=threat, threat_detail=detail,
               threat_text=threat_text(threat, detail),
               confirm_text=threat_confirm_text(threat, detail) if threat else "",
               tone="red" if threat else None, user_release=not threat,
               admin_text=THREAT_ADMIN_TEXT if threat else "",
               zapped=bool(zapped_at), zapped_at=zapped_at, zap_label=ZAP_LABEL if zapped_at else "",
               timeline=[{"ts": e["ts"], "event": e["event"], "text": zap_timeline_text(e["detail"]),
                          "detail": str(e["detail"] or "")[:300]}
                         for e in evs])
    return out


# ---------------------------------------------------------------------------
# 2.3 (B17): attachment policy - list editor and per-sender exceptions
# ---------------------------------------------------------------------------

ATTACHMENT_HELP = ("Filer af disse typer blokeres altid – også inde i zip-filer. Mailen ligger urørt i "
                   "Spamfilter-mappen og kan frigives af en administrator.")
ATTACH_EXCEPTION_TEXT = "Tillad farlige vedhæftninger fra denne afsender"
_EXT_RE = re.compile(r"^[a-z0-9]{1,10}$")
_ATTACH_RULES_DDL = """
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
)"""


def _default_attachment_block(eng: Any) -> list[str]:
    return list(getattr(eng, "DEFAULT_ATTACHMENT_BLOCK", None) or [])


def _mask_pattern(pattern: Any) -> str:
    """'@domain' stays; an address becomes 'a…@domain' (audit/events)."""
    p = str(pattern or "")
    if p.startswith("@") or "@" not in p:
        return p[:120]
    local, _s, dom = p.rpartition("@")
    return f"{local[:1]}…@{dom}"[:120]


def attachment_policy(*, engine: Any = None) -> dict[str, Any]:
    """The blocked attachment types (B17) for the Indstillinger list editor.
    -> {ok, code, extensions, default, custom (defaults differ from the
    built-in list), per_account {account: [..]} (accounts with their own
    list), max, help}"""
    eng = _eng(engine)
    default = _default_attachment_block(eng)
    out: dict[str, Any] = {"ok": False, "code": "config", "extensions": list(default), "default": default,
                           "custom": False, "per_account": {}, "max": getattr(eng, "ATTACHMENT_BLOCK_MAX", 100),
                           "help": ATTACHMENT_HELP}
    try:
        import yaml  # noqa: PLC0415

        raw = yaml.safe_load(Path(eng.CONFIG_PATH).read_text(encoding="utf-8")) or {}
    except Exception:
        return out
    defaults = raw.get("defaults") or {}
    if isinstance(defaults, dict) and "attachment_block" in defaults:
        exts = [str(e).strip().lower().lstrip("*").lstrip(".") for e in (defaults.get("attachment_block") or [])]
        out["extensions"] = [e for e in dict.fromkeys(exts) if _EXT_RE.match(e)]
    for entry in raw.get("accounts") or []:
        if isinstance(entry, dict) and "attachment_block" in entry and entry.get("name"):
            out["per_account"][str(entry["name"])] = [str(e) for e in (entry.get("attachment_block") or [])]
    out.update(ok=True, code="ok", custom=out["extensions"] != default)
    return out


def set_attachment_block(extensions: Any, actor: str, *, reset: bool = False, engine: Any = None,
                         save_config: Any = None) -> dict[str, Any]:
    """WRITE (admin): the global list of blocked attachment types
    (accounts.yml defaults.attachment_block) via dashboard.save_config
    (validation, atomic write, reload, audit 'attachment_block').
    `extensions`: list or text ('exe, .js *.iso'). reset=True removes the
    key = the built-in list. -> {ok, code ('ok'|'unchanged'|'invalid'|
    'rejected'), text, extensions, invalid, audit_detail}"""
    eng = _eng(engine)
    default = _default_attachment_block(eng)
    limit = int(getattr(eng, "ATTACHMENT_BLOCK_MAX", 100))
    out: dict[str, Any] = {"ok": False, "code": "invalid", "text": "", "extensions": [], "invalid": [],
                           "audit_detail": ""}
    if reset:
        wanted = list(default)
    else:
        items = re.split(r"[\s,;]+", extensions) if isinstance(extensions, str) else list(extensions or [])
        wanted, bad = [], []
        for item in items:
            e = str(item or "").strip().lower().lstrip("*").lstrip(".")
            if not e:
                continue
            if not _EXT_RE.match(e):
                bad.append(str(item)[:20])
            elif e not in wanted:
                wanted.append(e)
        if bad:
            out.update(invalid=bad, text="Ugyldige filtyper: " + ", ".join(bad[:5])
                       + ". Brug kun bogstaver og tal, fx exe eller iso.")
            return out
        if len(wanted) > limit:
            out["text"] = f"Højst {limit} filtyper."
            return out
    current = attachment_policy(engine=eng)
    if current.get("ok") and current["extensions"] == wanted and (not reset or not current["custom"]):
        out.update(ok=True, code="unchanged", extensions=wanted, text="Listen er uændret.")
        return out
    if save_config is None:
        import dashboard  # noqa: PLC0415 - the UI process; never at import time

        save_config = dashboard.save_config
    before = set(current.get("extensions") or [])
    added = sorted(set(wanted) - before)
    removed = sorted(before - set(wanted))
    detail = ("reset" if reset else f"n={len(wanted)}") + (f" +{','.join(added)}" if added else "") \
        + (f" -{','.join(removed)}" if removed else "")

    def mutate(raw: dict) -> None:
        defaults = raw.setdefault("defaults", {}) if isinstance(raw.get("defaults"), dict) or "defaults" not in raw \
            else None
        if defaults is None:
            raise ValueError("defaults i konfigurationen har et ugyldigt format.")
        if reset:
            defaults.pop("attachment_block", None)
        else:
            defaults["attachment_block"] = list(wanted)

    try:
        save_config(mutate, actor, "attachment_block", detail=detail[:300])
    except ValueError as ex:
        out.update(code="rejected", text=f"Ændringen blev afvist: {str(ex)[:200]}")
        return out
    out.update(ok=True, code="ok", extensions=wanted, audit_detail=detail[:300],
               text=("Standardlisten over farlige vedhæftninger er gendannet." if reset else
                     f"{len(wanted)} filtyper blokeres nu.") + " Filteret genindlæser om et øjeblik.")
    return out


# ---------------------------------------------------------------------------
# 2.3.6 (B22): lookalike domains + weekly registration watch (lookalike.py)
# ---------------------------------------------------------------------------

LOOKALIKE_HELP = ("Filteret holder øje med domæner, der ligner jeres – fx pinslkbing.example i stedet for "
                  "pinsikbing.example. Mails fra sådan et domæne lægges i Spamfilter-mappen og kan kun frigives af en "
                  "administrator. Én gang om ugen tjekkes det også, om nogen har registreret et lignende domæne "
                  "og givet det en mailserver.")
LOOKALIKE_NEW_DAYS = 14          # Oversigt: new registrations of the last 14 days
LOOKALIKE_MAIL_DAYS = 30         # Indstillinger: lookalike mail of the last 30 days
LOOKALIKE_REQUEST_MIN_S = 15 * 60


def _lk() -> Any:
    import lookalike  # noqa: PLC0415

    return lookalike


def _lk_conn(eng: Any) -> sqlite3.Connection:
    conn = _open_db(eng)
    _lk().ensure_schema(conn)
    return conn


def _lk_state(conn: sqlite3.Connection, key: str) -> str | None:
    try:
        row = conn.execute("SELECT value FROM engine_state WHERE key=?", (key,)).fetchone()
    except sqlite3.Error:
        return None
    return None if row is None else row[0]


def _lk_state_set(conn: sqlite3.Connection, key: str, value: str | None) -> None:
    conn.execute("INSERT INTO engine_state(key, value, updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE "
                 "SET value=excluded.value, updated_at=excluded.updated_at", (key, value, int(time.time())))


def _lk_event(conn: sqlite3.Connection, event: str, detail: str) -> None:
    conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES('*', ?, NULL, ?, ?)",
                 (int(time.time()), event, detail[:300]))


def _lk_raw_config(eng: Any) -> dict:
    try:
        import yaml  # noqa: PLC0415

        raw = yaml.safe_load(Path(eng.CONFIG_PATH).read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    return raw if isinstance(raw, dict) else {}


def _lk_mailbox_domains(eng: Any) -> list[str]:
    try:
        configs = list(eng.load_account_configs(eng.CONFIG_PATH))
    except Exception:
        return []
    out: list[str] = []
    for a in configs:
        d = str(getattr(a, "user", "") or "").rpartition("@")[2].strip().lower()
        if d and d not in out:
            out.append(d)
    return out


def _lk_default(eng: Any) -> list[str]:
    return list(getattr(eng, "DEFAULT_PROTECTED_DOMAINS", None) or _lk().DEFAULT_PROTECTED)


def lookalike_settings(*, engine: Any = None) -> dict[str, Any]:
    """The protected-domain list for the editor -> {ok, configured (the
    defaults list), default, custom, mailbox (always protected),
    effective, per_account {account: [..]}, max, help}."""
    eng = _eng(engine)
    lk = _lk()
    default = _lk_default(eng)
    raw = _lk_raw_config(eng)
    defaults = raw.get("defaults") if isinstance(raw.get("defaults"), dict) else {}
    custom = "protected_domains" in defaults
    configured = lk.normalize_protected(defaults.get("protected_domains") or []) if custom else list(default)
    mailbox = lk.normalize_protected(_lk_mailbox_domains(eng))
    per = {str(e["name"]): [str(d) for d in (e.get("protected_domains") or [])]
           for e in raw.get("accounts") or [] if isinstance(e, dict) and e.get("name") and "protected_domains" in e}
    return {"ok": bool(raw), "configured": configured, "default": default, "custom": custom and configured != default,
            "mailbox": mailbox, "effective": lk.protected_domains(configured, [], mailbox), "per_account": per,
            "max": int(getattr(eng, "PROTECTED_DOMAINS_MAX", lk.PROTECTED_MAX)), "help": LOOKALIKE_HELP}


def set_protected_domains(domains: Any, actor: str, *, reset: bool = False, engine: Any = None,
                          save_config: Any = None) -> dict[str, Any]:
    """WRITE (admin): accounts.yml defaults.protected_domains via
    dashboard.save_config (validation, atomic write, reload, audit
    'protected_domains'). `domains`: list or text (space/comma/newline).
    reset=True removes the key (= the built-in list). The mailbox domains
    are always protected and need not be listed.
    -> {ok, code ('ok'|'unchanged'|'invalid'|'rejected'), text, domains, invalid}"""
    eng = _eng(engine)
    lk = _lk()
    cur = lookalike_settings(engine=eng)
    limit = int(cur["max"])
    out: dict[str, Any] = {"ok": False, "code": "invalid", "text": "", "domains": [], "invalid": []}
    if reset:
        wanted = list(cur["default"])
    else:
        items = re.split(r"[\s,;]+", domains) if isinstance(domains, str) else list(domains or [])
        wanted, bad = [], []
        for item in items:
            t = str(item or "").strip()
            if not t:
                continue
            t = re.sub(r"^[a-z]+://", "", t.lower()).split("/", 1)[0].rpartition("@")[2]
            d = lk.registrable(t.lstrip("*").lstrip("."))
            if not d or "." not in d:
                bad.append(str(item)[:40])
            elif d not in wanted:
                wanted.append(d)
        if bad:
            out.update(invalid=bad, text="Ugyldige domæner: " + ", ".join(bad[:5]) + ". Skriv fx pinsikbing.example.")
            return out
        if len(wanted) > limit:
            out["text"] = f"Højst {limit} domæner."
            return out
    if wanted == cur["configured"] and (not reset or not cur["custom"]):
        out.update(ok=True, code="unchanged", domains=wanted, text="Listen er uændret.")
        return out
    if save_config is None:
        import dashboard  # noqa: PLC0415 - the UI process; never at import time

        save_config = dashboard.save_config
    before = set(cur["configured"])
    added, removed = sorted(set(wanted) - before), sorted(before - set(wanted))
    detail = ("reset" if reset else f"n={len(wanted)}") + (f" +{','.join(added)}" if added else "") \
        + (f" -{','.join(removed)}" if removed else "")

    def mutate(raw: dict) -> None:
        if "defaults" in raw and not isinstance(raw.get("defaults"), dict) and raw.get("defaults") is not None:
            raise ValueError("defaults i konfigurationen har et ugyldigt format.")
        if not isinstance(raw.get("defaults"), dict):
            raw["defaults"] = {}
        if reset:
            raw["defaults"].pop("protected_domains", None)
        else:
            raw["defaults"]["protected_domains"] = list(wanted)

    try:
        save_config(mutate, actor, "protected_domains", detail=detail[:300])
    except ValueError as ex:
        out.update(code="rejected", text=f"Ændringen blev afvist: {str(ex)[:200]}")
        return out
    out.update(ok=True, code="ok", domains=wanted,
               text=("Standardlisten over beskyttede domæner er gendannet." if reset else
                     f"{len(wanted)} {'domæne' if len(wanted) == 1 else 'domæner'} beskyttes nu – plus "
                     "postkassernes egne.") + " Filteret genindlæser om et øjeblik.")
    return out


def _lk_symbol_hits(conn: sqlite3.Connection, since: int) -> list[dict[str, Any]]:
    """Lookalike mail of the last days, grouped per imitation domain."""
    lk = _lk()
    groups: dict[str, dict[str, Any]] = {}
    try:
        rows = conn.execute("SELECT symbols, COALESCE(scanned_at, first_seen) AS ts FROM messages "
                            "WHERE symbols LIKE '%TH_LOOKALIKE_%' AND COALESCE(scanned_at, first_seen) >= ? "
                            "ORDER BY ts DESC LIMIT 2000", (since,)).fetchall()
    except sqlite3.Error:
        return []
    for r in rows:
        try:
            syms = json.loads(r["symbols"] or "[]")
        except (TypeError, ValueError):
            continue
        for sym in syms if isinstance(syms, list) else []:
            if not isinstance(sym, dict) or sym.get("n") not in (lk.SYMBOL_DOMAIN, lk.SYMBOL_URL):
                continue
            o = [str(x) for x in sym.get("o") or []]
            if len(o) < 2:
                continue
            g = groups.setdefault(o[0], {"domain": o[0], "protected": o[1], "n": 0, "last_at": 0,
                                         "sender": False, "link": False})
            g["n"] += 1
            g["last_at"] = max(g["last_at"], int(r["ts"] or 0))
            g["sender" if sym["n"] == lk.SYMBOL_DOMAIN else "link"] = True
    return sorted(groups.values(), key=lambda g: (-g["last_at"], g["domain"]))[:50]


def lookalike_overview(*, engine: Any = None) -> dict[str, Any]:
    """Everything the Indstillinger card shows (admin) -> {ok, settings,
    last_run, complete_at, requested, candidates, checked, registered,
    findings:[{domain, protected, kind, kind_text, mx, a, ns, new, new_at,
    new_text, first_registered_at, allowed}], findings_total, mail:[{domain,
    protected, n, last_at, sender, link, allowed}], allowed:[{domain,
    protected, note, created_by, created_at}]}"""
    eng = _eng(engine)
    lk = _lk()
    now = int(time.time())
    out: dict[str, Any] = {"ok": False, "settings": lookalike_settings(engine=eng), "last_run": None,
                           "complete_at": None, "requested": False, "candidates": 0, "checked": 0,
                           "registered": 0, "findings": [], "findings_total": 0, "mail": [], "allowed": []}
    try:
        with closing(_open_db_ro(eng)) as conn:
            last = _lk_state(conn, "lookalike_watch_last")
            try:
                out["last_run"] = json.loads(last) if last else None
            except (TypeError, ValueError):
                out["last_run"] = None
            done = _lk_state(conn, "lookalike_watch_complete_at")
            out["complete_at"] = int(float(done)) if done else None
            out["requested"] = bool(_lk_state(conn, "lookalike_watch_request"))
            allowed = []
            try:
                allowed = [dict(r) for r in conn.execute(
                    "SELECT domain, protected, note, created_by, created_at FROM lookalike_allow "
                    "ORDER BY created_at DESC LIMIT 200")]
            except sqlite3.Error:
                pass
            out["allowed"] = allowed
            allow_set = [a["domain"] for a in allowed]

            def is_allowed(d: str) -> bool:
                return any(lk.under(d, a) for a in allow_set)

            try:
                c = conn.execute("SELECT COUNT(*), SUM(checked_at IS NOT NULL), SUM(registered=1) "
                                 "FROM lookalike_watch").fetchone()
                out["candidates"], out["checked"], out["registered"] = int(c[0] or 0), int(c[1] or 0), int(c[2] or 0)
                rows = conn.execute(
                    "SELECT * FROM lookalike_watch WHERE registered=1 ORDER BY (new_at IS NULL), new_at DESC, "
                    "first_registered_at DESC, domain LIMIT 100").fetchall()
            except sqlite3.Error:
                rows = []
            for r in rows:
                mx = lk._jl(r["mx"]) or []
                a = lk._jl(r["a"]) or []
                new = bool(r["new_at"]) and r["acked_at"] is None and now - int(r["new_at"]) <= LOOKALIKE_NEW_DAYS * 86400
                out["findings"].append({
                    "domain": r["domain"], "display": lk.to_unicode(r["domain"]), "protected": r["protected"],
                    "kind": r["kind"], "kind_text": lk.KIND_TEXT.get(r["kind"], r["kind"]), "mx": bool(mx),
                    "a": bool(a), "ns": bool(lk._jl(r["ns"]) or []), "new": new, "new_at": r["new_at"],
                    "new_text": lk.new_text({"domain": r["domain"], "protected": r["protected"],
                                             "what": r["new_what"] or ""}) if r["new_at"] else "",
                    "first_registered_at": r["first_registered_at"], "checked_at": r["checked_at"],
                    "allowed": is_allowed(r["domain"])})
            out["findings_total"] = out["registered"]
            out["mail"] = [{**g, "allowed": is_allowed(g["domain"])}
                           for g in _lk_symbol_hits(conn, now - LOOKALIKE_MAIL_DAYS * 86400)]
            out["ok"] = True
    except sqlite3.Error as ex:
        log.warning("lookalike_overview failed: %s", type(ex).__name__)
    return out


def lookalike_attention(*, engine: Any = None) -> list[dict[str, Any]]:
    """New registrations of the last 14 days not yet seen / allowed (Oversigt)."""
    eng = _eng(engine)
    lk = _lk()
    since = int(time.time()) - LOOKALIKE_NEW_DAYS * 86400
    try:
        with closing(_open_db_ro(eng)) as conn:
            rows = conn.execute("SELECT domain, protected, new_at, new_what FROM lookalike_watch WHERE new_at >= ? "
                                "AND acked_at IS NULL ORDER BY new_at DESC LIMIT 50", (since,)).fetchall()
            try:
                allowed = [r[0] for r in conn.execute("SELECT domain FROM lookalike_allow")]
            except sqlite3.Error:
                allowed = []
    except sqlite3.Error:
        return []
    return [{"domain": r["domain"], "protected": r["protected"], "new_at": r["new_at"],
             "what": r["new_what"] or "",
             "text": lk.new_text({"domain": r["domain"], "protected": r["protected"], "what": r["new_what"] or ""})}
            for r in rows if not any(lk.under(r["domain"], a) for a in allowed)]


def lookalike_allow(domain: Any, actor: str, *, protected: Any = None, note: Any = None,
                    engine: Any = None) -> dict[str, Any]:
    """WRITE (admin): 'Ikke en efterligning' for a domain (and its
    subdomains): no lookalike hit, no watch alert. The UI audits
    'lookalike_allow'. -> {ok, code ('ok'|'exists'|'invalid'|'own'), text, domain}"""
    eng = _eng(engine)
    lk = _lk()
    d = lk.to_ascii(str(domain or "").strip().lstrip("*").lstrip(".").rpartition("@")[2])
    if not d or "." not in d:
        return {"ok": False, "code": "invalid", "text": "Ugyldigt domæne.", "domain": None}
    eff = lookalike_settings(engine=eng)["effective"]
    if any(lk.under(d, p) or lk.under(p, d) for p in eff):
        return {"ok": False, "code": "own", "domain": d,
                "text": "Det er et af jeres egne beskyttede domæner – det bliver aldrig set som en efterligning."}
    prot = lk.to_ascii(protected) if protected else None
    try:
        with closing(_lk_conn(eng)) as conn:
            cur = conn.execute("INSERT OR IGNORE INTO lookalike_allow(domain, protected, note, created_by, created_at) "
                               "VALUES(?,?,?,?,?)", (d, prot, (str(note or "").strip()[:200] or None),
                                                     str(actor or "")[:80] or None, int(time.time())))
            if not cur.rowcount:
                return {"ok": True, "code": "exists", "domain": d,
                        "text": f"{lk.to_unicode(d)} er allerede markeret som ikke en efterligning."}
            conn.execute("UPDATE lookalike_watch SET acked_at=COALESCE(acked_at, ?) WHERE domain=? OR domain LIKE ?",
                         (int(time.time()), d, "%." + d))
            _lk_event(conn, "lookalike_allowed", f"{d}" + (f" ligner {prot}" if prot else "")
                      + (f" af {actor}" if actor else ""))
    except sqlite3.Error as ex:
        log.warning("lookalike_allow failed: %s", type(ex).__name__)
        return {"ok": False, "code": "error", "text": "Det kunne ikke gemmes lige nu.", "domain": d}
    return {"ok": True, "code": "ok", "domain": d,
            "text": f"{lk.to_unicode(d)} er markeret som ikke en efterligning. Nye mails fra domænet bedømmes "
                    "normalt."}


def lookalike_unallow(domain: Any, actor: str, *, engine: Any = None) -> dict[str, Any]:
    """WRITE (admin): undo 'Ikke en efterligning'. -> {ok, code, text, domain}"""
    eng = _eng(engine)
    lk = _lk()
    d = lk.to_ascii(domain)
    if not d:
        return {"ok": False, "code": "invalid", "text": "Ugyldigt domæne.", "domain": None}
    try:
        with closing(_lk_conn(eng)) as conn:
            cur = conn.execute("DELETE FROM lookalike_allow WHERE domain=?", (d,))
            if not cur.rowcount:
                return {"ok": False, "code": "not_found", "text": "Domænet står ikke på listen.", "domain": d}
            _lk_event(conn, "lookalike_unallowed", d + (f" af {actor}" if actor else ""))
    except sqlite3.Error as ex:
        log.warning("lookalike_unallow failed: %s", type(ex).__name__)
        return {"ok": False, "code": "error", "text": "Det kunne ikke gemmes lige nu.", "domain": d}
    return {"ok": True, "code": "ok", "domain": d,
            "text": f"{lk.to_unicode(d)} bliver igen set som en mulig efterligning."}


def lookalike_ack(actor: str, *, domain: Any = None, engine: Any = None) -> dict[str, Any]:
    """WRITE (admin): 'Set' on new registrations (one domain or all) - the
    Oversigt item disappears; the findings list keeps them."""
    eng = _eng(engine)
    lk = _lk()
    d = lk.to_ascii(domain) if domain else None
    if domain and not d:
        return {"ok": False, "code": "invalid", "text": "Ugyldigt domæne."}
    try:
        with closing(_lk_conn(eng)) as conn:
            sql = "UPDATE lookalike_watch SET acked_at=? WHERE new_at IS NOT NULL AND acked_at IS NULL"
            args: list[Any] = [int(time.time())]
            if d:
                sql += " AND domain=?"
                args.append(d)
            n = conn.execute(sql, args).rowcount
            if n:
                _lk_event(conn, "lookalike_acked", (d or f"{n} domæner") + (f" af {actor}" if actor else ""))
    except sqlite3.Error as ex:
        log.warning("lookalike_ack failed: %s", type(ex).__name__)
        return {"ok": False, "code": "error", "text": "Det kunne ikke gemmes lige nu."}
    return {"ok": True, "code": "ok" if n else "unchanged", "n": n,
            "text": "Markeret som set." if n else "Der var intet nyt at markere."}


def lookalike_request_run(actor: str, *, engine: Any = None) -> dict[str, Any]:
    """WRITE (admin): 'Kør kontrol nu' - the engine's watch thread starts a
    run within a minute (engine_state lookalike_watch_request)."""
    eng = _eng(engine)
    now = int(time.time())
    try:
        with closing(_lk_conn(eng)) as conn:
            if _lk_state(conn, "lookalike_watch_request"):
                return {"ok": True, "code": "pending", "text": "Kontrollen er allerede bestilt og starter om lidt."}
            try:
                attempt = int(float(_lk_state(conn, "lookalike_watch_attempt_at") or 0))
            except ValueError:
                attempt = 0
            if now - attempt < LOOKALIKE_REQUEST_MIN_S:
                return {"ok": False, "code": "too_soon",
                        "text": "Kontrollen har lige kørt. Prøv igen om et kvarter."}
            _lk_state_set(conn, "lookalike_watch_request", str(now))
            _lk_event(conn, "lookalike_watch_requested", f"af {actor}" if actor else "")
    except sqlite3.Error as ex:
        log.warning("lookalike_request_run failed: %s", type(ex).__name__)
        return {"ok": False, "code": "error", "text": "Kontrollen kunne ikke bestilles lige nu."}
    return {"ok": True, "code": "ok",
            "text": "Kontrollen starter inden for et minut og tager nogle minutter (højst 5 opslag i sekundet)."}


# ---------------------------------------------------------------------------
# 2.7: Falske afsendernavne - Beskyttede navne (namespoof.py)
# ---------------------------------------------------------------------------

NAMESPOOF_HELP = ("Svindlere skriver ofte under navnet på en af jeres egne – fx jeres direktørs navn fra en "
                  "fremmed gmail-adresse – og beder om en hurtig betaling eller et gavekort. Står navnet her, og kommer "
                  "mailen ikke fra en af personens rigtige adresser eller jeres egne domæner, får den point. "
                  "Navne på ét ord (fx Anna) rammer kun, når afsendernavnet er præcis det ord.")


def _ns() -> Any:
    import namespoof  # noqa: PLC0415

    return namespoof


def _ns_conn(eng: Any) -> sqlite3.Connection:
    conn = _open_db(eng)
    _ns().ensure_schema(conn)
    return conn


def _ns_own_domains(eng: Any) -> list[str]:
    # 2.7 fix: the mailbox domains and contact groups - never a shared
    # platform (owner_platform_domains / webshop_domains such as vexar.example),
    # which needs the person's exact address (filter.namespoof_platform_domains).
    out = list(_lk_mailbox_domains(eng))
    platforms: set[str] = set()
    try:
        for a in eng.load_account_configs(eng.CONFIG_PATH):
            out.append(str(getattr(a, "contact_group", None) or ""))
            platforms.update(str(d).lower() for d in (getattr(a, "owner_platform_domains", None) or []))
            platforms.update(str(d).lower() for d in (getattr(a, "webshop_domains", None) or []))
    except Exception:  # noqa: BLE001 - display only
        pass
    mailbox = set(_lk_mailbox_domains(eng))
    return [d for d in _ns().own_domains_of(out) if d in mailbox or d not in platforms]


def namespoof_overview(*, engine: Any = None) -> dict[str, Any]:
    """Everything the 'Beskyttede navne' card shows (admin) -> {ok, mode:
    {mode, at, by, explicit, days}, suggest_on, names:[entry], hits:[...],
    trial_hits, own_domains, max, help}"""
    eng = _eng(engine)
    ns = _ns()
    now = int(time.time())
    out: dict[str, Any] = {"ok": False, "mode": {"mode": ns.DEFAULT_MODE, "at": None, "by": "", "explicit": False,
                                                 "days": 0},
                           "suggest_on": False, "names": [], "hits": [], "trial_hits": 0,
                           "own_domains": _ns_own_domains(eng), "max": ns.NAMES_MAX, "help": NAMESPOOF_HELP}
    try:
        with closing(_ns_conn(eng)) as conn:
            ns.touch_default(conn, now)
            mode = ns.get_mode(conn)
            mode["days"] = max(0, (now - int(mode["at"] or now)) // 86400)
            out["mode"] = mode
            out["names"] = ns.list_names(conn)
            out["hits"] = ns.hits(conn, now - ns.HIT_DAYS * 86400)
            out["trial_hits"] = sum(int(g["trial"]) for g in out["hits"])
            out["suggest_on"] = mode["mode"] == "shadow" and mode["days"] >= ns.TRIAL_DAYS
            out["ok"] = True
    except sqlite3.Error as ex:
        log.warning("namespoof_overview failed: %s", type(ex).__name__)
    return out


def namespoof_set_mode(mode: Any, actor: str, *, engine: Any = None) -> dict[str, Any]:
    """WRITE (admin): Fra / Prøv / Til. -> {ok, code ('ok'|'unchanged'|'invalid'), text, mode}"""
    eng = _eng(engine)
    ns = _ns()
    value = str(mode or "").strip().lower()
    if value not in ns.MODES:
        return {"ok": False, "code": "invalid", "text": "Vælg Fra, Prøv eller Til.", "mode": None}
    try:
        with closing(_ns_conn(eng)) as conn:
            cur = ns.get_mode(conn)
            if cur["mode"] == value and cur["explicit"]:
                return {"ok": True, "code": "unchanged", "text": "Uændret.", "mode": value}
            ns.set_mode(conn, value, actor or "admin", int(time.time()))
            _lk_event(conn, "namespoof_mode", f"{value}" + (f" af {actor}" if actor else ""))
    except sqlite3.Error as ex:
        log.warning("namespoof_set_mode failed: %s", type(ex).__name__)
        return {"ok": False, "code": "error", "text": "Det kunne ikke gemmes lige nu.", "mode": None}
    text = {"off": "Falske afsendernavne tjekkes ikke længere.",
            "shadow": "Prøv: filteret viser kun, hvilke mails der ville få point.",
            "on": "Til: mails med et falsk afsendernavn får nu point."}[value]
    return {"ok": True, "code": "ok", "text": text, "mode": value}


def namespoof_save(name: Any, allow: Any, actor: str, *, enabled: bool = True, entry_id: Any = None,
                   engine: Any = None) -> dict[str, Any]:
    """WRITE (admin): add or edit one protected name (namespoof.save_name)."""
    eng = _eng(engine)
    try:
        with closing(_ns_conn(eng)) as conn:
            return _ns().save_name(conn, name=name, allow=allow, enabled=enabled, entry_id=entry_id or None,
                                   actor=actor, now=int(time.time()))
    except sqlite3.Error as ex:
        log.warning("namespoof_save failed: %s", type(ex).__name__)
        return {"ok": False, "code": "error", "text": "Det kunne ikke gemmes lige nu.", "entry": None}


def namespoof_delete(entry_id: Any, actor: str, *, engine: Any = None) -> dict[str, Any]:
    """WRITE (admin): remove one protected name (never seeded again)."""
    eng = _eng(engine)
    try:
        with closing(_ns_conn(eng)) as conn:
            e = _ns().delete_name(conn, entry_id)
    except sqlite3.Error as ex:
        log.warning("namespoof_delete failed: %s", type(ex).__name__)
        return {"ok": False, "code": "error", "text": "Det kunne ikke gemmes lige nu.", "entry": None}
    if e is None:
        return {"ok": False, "code": "not_found", "text": "Navnet står ikke på listen.", "entry": None}
    return {"ok": True, "code": "ok", "entry": e, "text": f"{e['name']} er fjernet fra listen."}


def namespoof_allow(entry_id: Any, address: Any, actor: str, *, engine: Any = None) -> dict[str, Any]:
    """WRITE (admin): 'Tillad adressen' on a hit - the address may use the name."""
    eng = _eng(engine)
    try:
        with closing(_ns_conn(eng)) as conn:
            return _ns().allow_address(conn, entry_id, address, actor=actor, now=int(time.time()))
    except sqlite3.Error as ex:
        log.warning("namespoof_allow failed: %s", type(ex).__name__)
        return {"ok": False, "code": "error", "text": "Det kunne ikke gemmes lige nu.", "entry": None}


def namespoof_seed_now(actor: str, *, engine: Any = None) -> dict[str, Any]:
    """WRITE (admin): 'Hent navne fra Sendt post' now (the engine also does
    it once an hour)."""
    eng = _eng(engine)
    ns = _ns()
    try:
        with closing(_ns_conn(eng)) as conn:
            now = int(time.time())
            ns.touch_default(conn, now)
            res = ns.seed(conn, now)
    except sqlite3.Error as ex:
        log.warning("namespoof_seed_now failed: %s", type(ex).__name__)
        return {"ok": False, "code": "error", "text": "Navnene kunne ikke hentes lige nu."}
    added, extended = int(res.get("added") or 0), int(res.get("extended") or 0)
    if not added and not extended:
        return {"ok": True, "code": "unchanged", **res,
                "text": "Intet nyt i Sendt post. (Kendte kontakter skal være slået til og færdige med at "
                        "læse Sendt post.)"}
    parts = ([f"{added} {'nyt navn' if added == 1 else 'nye navne'}"] if added else []) + (
        [f"{extended} {'navn' if extended == 1 else 'navne'} med nye adresser"] if extended else [])
    return {"ok": True, "code": "ok", **res, "text": "Hentet fra Sendt post: " + " og ".join(parts) + "."}


def namespoof_attention(*, engine: Any = None) -> list[dict[str, Any]]:
    """Oversigt (admins): the default Prøv has run a week -> suggest Til.
    Gone once an admin picks a mode (also 'Bliv i Prøv')."""
    eng = _eng(engine)
    ns = _ns()
    now = int(time.time())
    try:
        with closing(_open_db_ro(eng)) as conn:
            mode = ns.get_mode(conn)
            if (mode["mode"] != "shadow" or mode["explicit"] or not mode["at"]
                    or now - int(mode["at"]) < ns.TRIAL_DAYS * 86400):
                return []
            found = ns.hits(conn, int(mode["at"]))
    except sqlite3.Error:
        return []
    return [{"days": (now - int(mode["at"])) // 86400, "hits": sum(int(g["trial"]) for g in found),
             "senders": len(found)}]


def _attach_conn(eng: Any) -> sqlite3.Connection:
    conn = _open_db(eng)
    conn.execute(_ATTACH_RULES_DDL)
    return conn


def attachment_exceptions(account: str | None = None, *, engine: Any = None) -> dict[str, Any]:
    """'Tillad farlige vedhæftninger fra denne afsender' rules (admin
    page). account=None = all; otherwise that mailbox's rules plus the
    global ('*') ones. -> {ok, code, items:[{id, account, scope_text,
    pattern, note, created_by, created_at, hits, last_hit_at}], help}"""
    eng = _eng(engine)
    out: dict[str, Any] = {"ok": False, "code": "db", "items": [], "help": (
        f"{ATTACH_EXCEPTION_TEXT}: kun når mailen beviseligt kommer fra afsenderens domæne (DKIM). "
        "Virus stoppes stadig.")}
    try:
        with closing(_attach_conn(eng)) as conn:
            if account is None:
                rows = conn.execute("SELECT * FROM attach_rules ORDER BY account, pattern").fetchall()
            else:
                rows = conn.execute("SELECT * FROM attach_rules WHERE account IN (?, '*') ORDER BY account, pattern",
                                    (account,)).fetchall()
    except sqlite3.Error:
        return out
    out.update(ok=True, code="ok", items=[{
        "id": int(r["id"]), "account": r["account"],
        "scope_text": "Alle postkasser" if r["account"] == "*" else r["account"],
        "pattern": r["pattern"], "note": r["note"], "created_by": r["created_by"],
        "created_at": r["created_at"], "hits": int(r["hits"] or 0), "last_hit_at": r["last_hit_at"]}
        for r in rows])
    return out


def add_attachment_exception(account: str, pattern: str, actor: str, *, is_admin: bool = False,
                             note: str = "", engine: Any = None) -> dict[str, Any]:
    """WRITE (admin only, fail closed): allow blocked attachment types from
    one sender ('a@b.dk') or domain ('@b.dk'); account '*' = every mailbox.
    -> {ok, code ('ok'|'admin_only'|'invalid'|'no_account'|'db'), text, id,
    pattern, audit_detail (masked)}"""
    eng = _eng(engine)
    out: dict[str, Any] = {"ok": False, "code": "admin_only", "text": "", "id": None, "pattern": None,
                           "audit_detail": ""}
    if not is_admin:
        out["text"] = "Kun en administrator kan tillade farlige vedhæftninger."
        return out
    account = (account or "*").strip() or "*"
    if account != "*":
        try:
            names = {a.name for a in eng.load_account_configs(eng.CONFIG_PATH)}
        except Exception:
            names = set()
        if account not in names:
            out.update(code="no_account", text="Postkassen findes ikke.")
            return out
    norm = getattr(eng, "normalize_rule_pattern", None)
    try:
        pat = norm(pattern) if norm is not None else str(pattern or "").strip().lower()
        if not pat or "@" not in pat:
            raise ValueError("invalid")
    except ValueError:
        out.update(code="invalid", text="Skriv en afsenderadresse (navn@firma.dk) eller et domæne (@firma.dk).")
        return out
    now = int(time.time())
    try:
        with closing(_attach_conn(eng)) as conn:
            conn.execute(
                "INSERT INTO attach_rules(account, pattern, note, created_by, created_at) VALUES(?,?,?,?,?) "
                "ON CONFLICT(account, pattern) DO UPDATE SET note=COALESCE(excluded.note, attach_rules.note), "
                "created_by=excluded.created_by",
                (account, pat, (note or "").strip()[:300] or None, actor or None, now))
            rid = int(conn.execute("SELECT id FROM attach_rules WHERE account=? AND pattern=?",
                                   (account, pat)).fetchone()[0])
            conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,NULL,?,?)",
                         (account, now, "attach_exception_added", f"rule={rid} {_mask_pattern(pat)} by {actor}"[:300]))
            conn.commit()
    except sqlite3.Error:
        out.update(code="db", text="Undtagelsen kunne ikke gemmes.")
        return out
    out.update(ok=True, code="ok", id=rid, pattern=pat,
               audit_detail=f"rule={rid} {_mask_pattern(pat)} account={account}",
               text=f"Farlige vedhæftninger tillades nu fra {pat}, når afsenderen kan bekræftes.")
    return out


def remove_attachment_exception(rule_id: Any, actor: str, *, is_admin: bool = False,
                                engine: Any = None) -> dict[str, Any]:
    """WRITE (admin only): delete an attachment exception.
    -> {ok, code ('ok'|'admin_only'|'not_found'|'db'), text, audit_detail}"""
    eng = _eng(engine)
    out: dict[str, Any] = {"ok": False, "code": "admin_only", "text": "", "audit_detail": ""}
    if not is_admin:
        out["text"] = "Kun en administrator kan ændre undtagelser for vedhæftninger."
        return out
    try:
        rid = int(rule_id)
    except (TypeError, ValueError):
        out.update(code="not_found", text="Undtagelsen findes ikke.")
        return out
    try:
        with closing(_attach_conn(eng)) as conn:
            row = conn.execute("SELECT account, pattern FROM attach_rules WHERE id=?", (rid,)).fetchone()
            if row is None:
                out.update(code="not_found", text="Undtagelsen findes ikke.")
                return out
            conn.execute("DELETE FROM attach_rules WHERE id=?", (rid,))
            conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,NULL,?,?)",
                         (row["account"], int(time.time()), "attach_exception_removed",
                          f"rule={rid} {_mask_pattern(row['pattern'])} by {actor}"[:300]))
            conn.commit()
    except sqlite3.Error:
        out.update(code="db", text="Undtagelsen kunne ikke slettes.")
        return out
    out.update(ok=True, code="ok", text="Undtagelsen er slettet.",
               audit_detail=f"rule={rid} {_mask_pattern(row['pattern'])} account={row['account']}")
    return out


# ===========================================================================
# 'Byg Bayes op på ny' (owner approved 2026-10-21): switch every account to
# a NEW Bayes pool and retrain it from clean sources. The old pool stays
# untouched in Redis (nothing is ever deleted there) and 'Gendan tidligere
# Bayes' switches back. Admin only (the UI checks); config changes go
# through dashboard.save_config (validation, atomic write, reload, audit).
# ===========================================================================

# Same DDL as filter.BAYES_REBUILD_SCHEMA (test-enforced), so these work
# against an older engine's database too (tables are additive).
BAYES_REBUILD_DDL = """
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

REBUILD_DEFAULT_RATIO = 2.0           # ham per spam: target 1:2
REBUILD_RATIO_MIN, REBUILD_RATIO_MAX = 0.5, 5.0
REBUILD_POOL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
_POOL_SUFFIX_RE = re.compile(r"-r\d{1,4}$")
_REBUILD_ACTIVE = ("starting", "running", "restoring")
_STAT_FAIL_CODES = ("rspamd",)

# Ham comes ONLY from the users' own archive folders. A folder is never ham
# when one of its path parts (after a leading INBOX) looks like one of these.
_HAM_SKIP_FLAGS = frozenset({"\\sent", "\\junk", "\\trash", "\\drafts", "\\all", "\\flagged", "\\important",
                             "\\noselect", "\\nonexistent"})
_HAM_SKIP_SEARCH_RE = re.compile(r"junk|spam|u[øo]nsket|bulk|trash|papirkurv|deleted|slettet|slettede|"
                                 r"skraldespand|\bbin\b|\brss\b|outbox|udbakke|\bsent\b|\bsendt|\bsendte\b|"
                                 r"train-|trained-", re.I)
_HAM_SKIP_EXACT = frozenset({
    "drafts", "draft", "kladder", "kladde", "udkast", "sent", "sent items", "sent messages", "sent mail",
    "sendt", "sendt post", "sendte", "sendte elementer", "sendte e-mails", "mail.sent-mail",
    "outbox", "udbakke", "rss feeds", "rss-feeds", "rss", "notes", "noter", "calendar", "kalender",
    "contacts", "kontakter", "tasks", "opgaver", "journal", "conversation history", "samtaleoversigt",
    "sync issues", "synkroniseringsproblemer", "templates", "skabeloner", "outbox (gem)", "virus",
    "quarantine", "karantæne"})
_SPAM_SOURCE_LEAVES = frozenset({"junk", "spam", "junk e-mail", "junk email", "uønsket post", "uønsket e-mail",
                                 "bulk mail"})


def _ensure_rebuild_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(BAYES_REBUILD_DDL)


def _identity(eng: Any, acc: Any) -> str:
    fn = getattr(eng, "bayes_identity", None)
    try:
        return str(fn(acc)) if fn is not None else str(getattr(acc, "bayes_user", None) or acc.user)
    except Exception:  # noqa: BLE001
        return str(getattr(acc, "bayes_user", None) or acc.user)


def _active_pool(eng: Any, configs: list[Any] | None = None) -> tuple[str | None, list[str]]:
    """(the Bayes pool most enabled accounts use, every pool in use)."""
    try:
        configs = list(configs if configs is not None else eng.load_account_configs(eng.CONFIG_PATH))
    except Exception:  # noqa: BLE001
        return None, []
    counts: dict[str, int] = {}
    for acc in configs:
        if getattr(acc, "enabled", True):
            ident = _identity(eng, acc)
            counts[ident] = counts.get(ident, 0) + 1
    if not counts:
        for acc in configs:
            ident = _identity(eng, acc)
            counts[ident] = counts.get(ident, 0) + 1
    if not counts:
        return None, []
    pools = sorted(counts)
    return sorted(pools, key=lambda p: (-counts[p], p))[0], pools


def _switch_history(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    if not _table_exists(conn, "bayes_rebuilds"):
        return []
    return conn.execute("SELECT * FROM bayes_rebuilds WHERE archived IS NOT NULL ORDER BY id").fetchall()


def _pool_counts(eng: Any, pool: str, total_spam: int, total_ham: int) -> tuple[int, int] | None:
    """Learns of `pool` from rspamd's all-pool totals and the totals
    recorded at every switch (a pool owns the growth while it was active).
    None when there is no switch history or a snapshot is missing."""
    try:
        with closing(_open_db_ro(eng)) as conn:
            rows = _switch_history(conn)
    except sqlite3.Error:
        return None
    if not rows:
        return None
    marks: list[tuple[int, int, str, Any, Any]] = []
    for r in rows:
        marks.append((int(r["created_at"]), 0, r["pool_new"], r["stat_spam_start"], r["stat_ham_start"]))
        if r["restored_at"]:
            marks.append((int(r["restored_at"]), 1, r["pool_old"], r["stat_spam_restore"], r["stat_ham_restore"]))
    marks.sort(key=lambda m: (m[0], m[1]))
    totals: dict[str, list[int]] = {}
    cur_pool, cur_s, cur_h = rows[0]["pool_old"], 0, 0
    for _ts, _o, to_pool, s, h in marks:
        if s is None or h is None:
            return None
        t = totals.setdefault(cur_pool, [0, 0])
        t[0] += int(s) - cur_s
        t[1] += int(h) - cur_h
        cur_pool, cur_s, cur_h = to_pool, int(s), int(h)
    t = totals.setdefault(cur_pool, [0, 0])
    t[0] += int(total_spam) - cur_s
    t[1] += int(total_ham) - cur_h
    got = totals.get(pool)
    if got is None:
        return None
    return max(0, got[0]), max(0, got[1])


def _has_switch_history(eng: Any) -> bool:
    try:
        with closing(_open_db_ro(eng)) as conn:
            return bool(_switch_history(conn))
    except sqlite3.Error:
        return False


def _switch_ts(conn: sqlite3.Connection) -> int | None:
    """When the active pool last changed (rebuild or restore), or None."""
    rows = _switch_history(conn)
    if not rows:
        return None
    return max(max(int(r["created_at"]), int(r["restored_at"] or 0)) for r in rows)


def bayes_pool_switch(conn: sqlite3.Connection, moves: dict[str, tuple[str, str]], *,
                      now: int | None = None, then: Any = None) -> dict[str, int]:
    """Per account (from_pool -> to_pool): archive the learned state of
    from_pool (messages.learned_as/learned_at, learn_ledger, autolearn_log)
    in bayes_pool_archive, clear it, and load to_pool's archived state, so
    engine.learn_message's 'already'/'unlearnable'/cooldown checks match the
    pool the account now learns into. One transaction. Rows are only
    copied/reset - 2.2/2.3 code reads the result as 'not learned yet'.

    autolearn_log is archived but NOT cleared: it is the record that a mail
    was already judged automatically (and maybe reverted by an admin), so
    autolearn never offers it again in any pool. `then(conn, counts)` runs
    inside the same transaction (the rebuild queues its jobs / marks the
    restore there), so a failure leaves the database exactly as before.
    -> {archived, cleared, restored}"""
    now = int(time.time() if now is None else now)
    _ensure_rebuild_schema(conn)
    has_ledger = _table_exists(conn, "learn_ledger")
    has_auto = _table_exists(conn, "autolearn_log")
    out = {"archived": 0, "cleared": 0, "restored": 0}
    conn.execute("BEGIN IMMEDIATE")
    try:
        for account, (src, dst) in sorted(moves.items()):
            if not src or not dst or src == dst:
                continue
            conn.execute("DELETE FROM bayes_pool_archive WHERE pool=? AND account=?", (src, account))
            cur = conn.execute(
                "INSERT OR REPLACE INTO bayes_pool_archive(pool, src, account, message_id, kind, learned_at, extra, "
                "archived_at) SELECT ?, 'messages', account, message_id, learned_as, learned_at, NULL, ? "
                "FROM messages WHERE account=? AND learned_as IS NOT NULL", (src, now, account))
            out["archived"] += max(0, cur.rowcount or 0)
            cur = conn.execute("UPDATE messages SET learned_as=NULL, learned_at=NULL "
                               "WHERE account=? AND learned_as IS NOT NULL", (account,))
            out["cleared"] += max(0, cur.rowcount or 0)
            if has_ledger:
                cur = conn.execute(
                    "INSERT OR REPLACE INTO bayes_pool_archive(pool, src, account, message_id, kind, learned_at, "
                    "extra, archived_at) SELECT ?, 'ledger', account, message_id, kind, learned_at, source, ? "
                    "FROM learn_ledger WHERE account=?", (src, now, account))
                out["archived"] += max(0, cur.rowcount or 0)
                conn.execute("DELETE FROM learn_ledger WHERE account=?", (account,))
            if has_auto:
                rows = conn.execute("SELECT * FROM autolearn_log WHERE account=?", (account,)).fetchall()
                conn.executemany(
                    "INSERT OR REPLACE INTO bayes_pool_archive(pool, src, account, message_id, kind, learned_at, "
                    "extra, archived_at) VALUES(?, 'autolearn', ?, ?, ?, ?, ?, ?)",
                    [(src, account, r["message_id"], r["kind"], r["created_at"],
                      json.dumps({"score": r["score"], "outcome": r["outcome"], "reverted_at": r["reverted_at"],
                                  "reverted_by": r["reverted_by"]}), now) for r in rows])
                out["archived"] += len(rows)
            back = conn.execute("SELECT * FROM bayes_pool_archive WHERE pool=? AND account=?",
                                (dst, account)).fetchall()
            for r in back:
                if r["src"] == "messages":
                    cur = conn.execute("UPDATE messages SET learned_as=?, learned_at=? WHERE account=? "
                                       "AND message_id=?", (r["kind"], r["learned_at"], account, r["message_id"]))
                    out["restored"] += max(0, cur.rowcount or 0)
                elif r["src"] == "ledger" and has_ledger:
                    conn.execute("INSERT OR REPLACE INTO learn_ledger(account, message_id, kind, learned_at, source) "
                                  "VALUES(?,?,?,?,?)", (account, r["message_id"], r["kind"],
                                                        int(r["learned_at"] or now), r["extra"]))
                    out["restored"] += 1
                elif r["src"] == "autolearn" and has_auto:
                    try:
                        extra = json.loads(r["extra"] or "{}")
                    except ValueError:
                        extra = {}
                    conn.execute("INSERT OR IGNORE INTO autolearn_log(account, message_id, kind, score, outcome, "
                                 "created_at, reverted_at, reverted_by) VALUES(?,?,?,?,?,?,?,?)",
                                 (account, r["message_id"], r["kind"], extra.get("score"),
                                  extra.get("outcome") or "learned", int(r["learned_at"] or now),
                                  extra.get("reverted_at"), extra.get("reverted_by")))
                    out["restored"] += 1
        if then is not None:
            then(conn, out)
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return out


def _folder_parts(f: dict[str, Any]) -> list[str]:
    label = folder_label(f["name"]) if f["name"].upper() != "INBOX" else "INBOX"
    delim = f.get("delimiter") or "."
    parts = [p for p in re.split("[" + re.escape(delim) + "/]", label) if p]
    if len(parts) > 1 and parts[0].upper() == "INBOX":
        parts = parts[1:]
    return [p.strip() for p in parts]


def _folder_under(name: str, parent: str | None, delim: str | None) -> bool:
    if not parent:
        return False
    if name.lower() == parent.lower():
        return True
    return any(name.lower().startswith((parent + d).lower()) for d in {delim or ".", "/"})


def ham_folder_reason(acc: Any, f: dict[str, Any], fmap: dict[str, Any]) -> str | None:
    """Why a folder is never ham in a rebuild (None = a user archive folder).
    Never INBOX, Sent, Junk/Uønsket, Trash/Papirkurv/Deleted*, Drafts/
    Kladder, Outbox/Udbakke, RSS Feeds, the filter's folder or the
    provider's spam folder (and nothing below them)."""
    name = f["name"]
    delim = f.get("delimiter")
    if name.upper() == "INBOX" or name == fmap.get("inbox"):
        return "inbox"
    flags = {str(x).lower() for x in f.get("flags") or ()}
    if flags & _HAM_SKIP_FLAGS:
        return "special"
    for key in ("junk", "provider_junk", "trash"):
        if _folder_under(name, fmap.get(key), delim):
            return key
    for key in ("spam_train", "trained_spam", "ham_train", "trained_ham"):
        cfg = getattr(acc, key, None)
        if cfg and _folder_under(name, _resolve_name(str(cfg), delim), delim):
            return "training"
    for sent in getattr(acc, "sent_folders", None) or ():
        if _folder_under(name, _resolve_name(str(sent), delim), delim):
            return "sent"
    for part in _folder_parts(f):
        low = part.lower()
        if low in _HAM_SKIP_EXACT or _HAM_SKIP_SEARCH_RE.search(low) or low.startswith(("deleted", "sent ")):
            return "name"
    return None


def _spam_source_folders(acc: Any, folders: list[dict[str, Any]], fmap: dict[str, Any]) -> list[tuple[str, str]]:
    """(folder, kind) spam sources: the filter's folder, the provider's spam
    folder and any other spam folder (\\Junk or a known spam folder name)."""
    out: list[tuple[str, str]] = []
    names = fmap["names"]
    for name, kind in ((fmap.get("junk"), "filter_junk"), (fmap.get("provider_junk"), "provider_junk")):
        if name and name in names and name != fmap["inbox"] and all(name != n for n, _k in out):
            out.append((name, kind))
    for f in folders:
        name = f["name"]
        if name == fmap["inbox"] or any(name == n for n, _k in out):
            continue
        flags = {str(x).lower() for x in f.get("flags") or ()}
        leaf = (_folder_parts(f) or [""])[-1].lower()
        if "\\junk" in flags or leaf in _SPAM_SOURCE_LEAVES:
            out.append((name, "spam_folder"))
    return out


def _waterfill(counts: list[int], budget: int) -> list[int]:
    """Spread `budget` across folders as evenly as their sizes allow."""
    alloc = [0] * len(counts)
    remaining = max(0, int(budget))
    order = sorted(range(len(counts)), key=lambda i: counts[i])
    left = len(order)
    for i in order:
        share = remaining // left if left else 0
        alloc[i] = min(counts[i], share)
        remaining -= alloc[i]
        left -= 1
    for i in sorted(range(len(counts)), key=lambda i: -counts[i]):
        if remaining <= 0:
            break
        extra = min(counts[i] - alloc[i], remaining)
        alloc[i] += extra
        remaining -= extra
    return alloc


def _derive_pool_name(conn: sqlite3.Connection | None, pool_now: str | None) -> str:
    """A NEW pool name: '<base>-rN' with N above every rebuild so far (a
    used pool is never trained again)."""
    base = str(pool_now or "").strip().lower()
    if not REBUILD_POOL_RE.match(base):
        base = "spamfilter"
    base = _POOL_SUFFIX_RE.sub("", base) or "spamfilter"
    used = {str(pool_now or "").lower()}
    if conn is not None:
        try:
            if _table_exists(conn, "bayes_rebuilds"):
                for r in conn.execute("SELECT pool_old, pool_new FROM bayes_rebuilds"):
                    used |= {str(r[0]).lower(), str(r[1]).lower()}
            if _table_exists(conn, "bayes_pool_archive"):
                used |= {str(r[0]).lower() for r in conn.execute("SELECT DISTINCT pool FROM bayes_pool_archive")}
        except sqlite3.Error:
            pass
    n = 2
    while f"{base[:56]}-r{n}" in used:
        n += 1
    name = f"{base[:56]}-r{n}"
    if not REBUILD_POOL_RE.match(name):  # pragma: no cover - base is validated above
        raise ValueError("invalid pool name")
    return name


def _old_spam_learn_list(conn: sqlite3.Connection, accounts: set[str], spam_folders: dict[str, set[str]],
                         eng: Any) -> list[tuple[str, str]]:
    """Mail the CURRENT pool learned as spam that lives outside the spam
    folders: owner-approved learn-list items, the users' own spam verdicts
    (dragged to spam / 'Markér som spam') and ham autolearns an admin
    reverted ('ikke legitim'). Released mail never."""
    cls: dict[tuple[str, str], tuple[str, int]] = {}
    info: dict[tuple[str, str], sqlite3.Row] = {}
    for r in conn.execute("SELECT account, message_id, learned_as, learned_at, current_folder, our_action, "
                          "user_verdict FROM messages"):
        key = (r["account"], r["message_id"])
        info[key] = r
        if r["learned_as"] in ("spam", "ham"):
            cls[key] = (r["learned_as"], int(r["learned_at"] or 0))
    if _table_exists(conn, "learn_ledger"):
        for r in conn.execute("SELECT account, message_id, kind, learned_at FROM learn_ledger"):
            key = (r["account"], r["message_id"])
            if key not in cls or int(r["learned_at"] or 0) >= cls[key][1]:
                cls[key] = (r["kind"], int(r["learned_at"] or 0))
    wanted: set[tuple[str, str]] = set()
    if _table_exists(conn, "learn_list_items"):
        for r in conn.execute("SELECT DISTINCT account, message_id FROM learn_list_items WHERE kind='spam' "
                              "AND status IN ('learned','already')"):
            wanted.add((r[0], r[1]))
    for key, r in info.items():
        if r["our_action"] in ("user_junked", "manual_mark_spam") or r["user_verdict"] == "spam":
            wanted.add(key)
    if _table_exists(conn, "autolearn_log"):
        for r in conn.execute("SELECT DISTINCT account, message_id FROM autolearn_log WHERE kind='ham' "
                              "AND reverted_at IS NOT NULL"):
            wanted.add((r[0], r[1]))
    out: list[tuple[int, str, str]] = []
    own = getattr(eng, "is_own_registered", None)
    for key in wanted:
        account, mid = key
        if account not in accounts or cls.get(key, ("", 0))[0] != "spam":
            continue
        r = info.get(key)
        if r is not None and (r["user_verdict"] == "ham" or r["current_folder"] in spam_folders.get(account, set())):
            continue
        if own is not None:
            try:
                if own(conn, account, mid):
                    continue
            except Exception:  # noqa: BLE001
                pass
        out.append((cls[key][1], account, mid))
    out.sort(key=lambda x: (-x[0], x[1], x[2]))
    return [(a, m) for _ts, a, m in out[:LEARN_LIST_MAX_ITEMS]]


def _raw_config(eng: Any) -> dict[str, Any]:
    import yaml  # noqa: PLC0415

    raw = yaml.safe_load(Path(eng.CONFIG_PATH).read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("config is not a mapping")
    return raw


def _bayes_config_snapshot(raw: dict[str, Any]) -> dict[str, Any]:
    d = raw.get("defaults") if isinstance(raw.get("defaults"), dict) else {}
    snap: dict[str, Any] = {"defaults": {"present": "bayes_user" in d, "value": d.get("bayes_user")},
                            "accounts": {}}
    for e in raw.get("accounts") or []:
        if isinstance(e, dict) and e.get("name") and "bayes_user" in e:
            snap["accounts"][str(e["name"])] = e.get("bayes_user")
    return snap


def _plan_text(p: dict[str, Any]) -> str:
    n_spam = sum(1 for s in p["spam_sources"] if s["kind"] != "learn_list")
    n_list = sum(s["planned"] for s in p["spam_sources"] if s["kind"] == "learn_list")
    n_ham = sum(1 for h in p["ham_sources"] if h["planned"] > 0)
    ratio = _fmt(p["ratio"]) if p.get("ratio") else "2"
    parts = [f"Ny Bayes-pulje: {p['pool_new']}. Den nuværende pulje ({p['pool_now']}) gemmes urørt og kan "
             f"gendannes med »Gendan tidligere Bayes«.",
             f"Spam: ca. {_n_da(p['expected_spam'])} mails fra {n_spam} spam-mappe{'r' if n_spam != 1 else ''}"
             + (f" og {_n_da(n_list)} enkeltmails, der tidligere er lært som spam" if n_list else "") + ".",
             f"Legitime: ca. {_n_da(p['expected_ham'])} af de nyeste mails fra {n_ham} arkivmappe"
             f"{'r' if n_ham != 1 else ''} – højst {ratio} legitime pr. spam. Indbakke, Sendt, Uønsket, "
             "Papirkurv, Kladder og Udbakke bruges aldrig som legitime.",
             f"Bayes er ikke aktiv, før der er lært mindst {_n_da(p['min_learns'])} af hver slags; indtil da "
             "afgør filterets andre regler alene. Ingen mails flyttes eller slettes."]
    return " ".join(parts)


def _rebuild_plan(eng: Any, ratio: float) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    """(plan, learn-list items). Read-only: LIST + STATUS per enabled
    mailbox, the database for the learn list."""
    min_learns = int(os.environ.get("BAYES_MIN_LEARNS", "200"))
    plan: dict[str, Any] = {"ok": False, "code": "invalid", "pool_now": None, "pool_new": None, "pools": [],
                            "ratio": ratio, "spam_sources": [], "ham_sources": [], "learn_list": {"total": 0,
                            "by_account": {}}, "expected_spam": 0, "expected_ham": 0, "warnings": [],
                            "errors": [], "min_learns": min_learns, "text": "", "running": None}
    try:
        configs = list(eng.load_account_configs(eng.CONFIG_PATH))
    except Exception:  # noqa: BLE001
        plan.update(code="config", text="Konfigurationen kunne ikke indlæses.")
        return plan, []
    pool_now, pools = _active_pool(eng, configs)
    plan["pool_now"], plan["pools"] = pool_now, pools
    try:
        with closing(_open_db(eng)) as conn:
            _ensure_rebuild_schema(conn)
            run = conn.execute("SELECT id, status FROM bayes_rebuilds WHERE status IN ('starting','running',"
                               "'restoring') ORDER BY id DESC LIMIT 1").fetchone()
            plan["running"] = int(run[0]) if run else None
            plan["restoring"] = bool(run is not None and run[1] == "restoring")
            plan["pool_new"] = _derive_pool_name(conn, pool_now)
    except sqlite3.Error:
        plan.update(code="db", text="Databasen kunne ikke læses.")
        return plan, []
    if len(pools) > 1:
        plan["warnings"].append("Postkasserne bruger forskellige Bayes-puljer (" + ", ".join(pools)
                                + "). Alle flyttes til den nye pulje.")
    spam_jobs: list[dict[str, Any]] = []
    ham_cands: list[dict[str, Any]] = []
    spam_names: dict[str, set[str]] = {}
    enabled = [a for a in configs if getattr(a, "enabled", True)]
    for acc in enabled:
        try:
            _acc, client = _open_session(eng, acc.name, timeout=FIND_TIMEOUT_S)
        except ServiceError as ex:
            plan["errors"].append({"account": acc.name, "code": ex.code, "text": ex.text})
            plan["warnings"].append(f"Postkassen {acc.name} kunne ikke læses ({ex.text}) – den er ikke med i "
                                    "planen.")
            continue
        try:
            folders = _list_folders(client)
            fmap = _folder_map(acc, folders)
            sources = _spam_source_folders(acc, folders, fmap)
            spam_names[acc.name] = {n for n, _k in sources}
            archive = [f for f in folders if f["name"] not in spam_names[acc.name]
                       and ham_folder_reason(acc, f, fmap) is None]
            _status_counts(client, folders, [n for n, _k in sources] + [f["name"] for f in archive])
            by_name = {f["name"]: f for f in folders}
            for name, kind in sources:
                n = int(by_name[name]["messages"] or 0)
                if n > 0:
                    spam_jobs.append({"account": acc.name, "folder": name, "label": folder_label(name),
                                      "kind": kind, "messages": n, "planned": min(n, MAX_TRAIN_MESSAGES)})
            n_arch = 0
            for f in archive:
                n = int(f["messages"] or 0)
                if n > 0:
                    n_arch += 1
                    ham_cands.append({"account": acc.name, "folder": f["name"], "label": folder_label(f["name"]),
                                      "messages": n, "planned": 0})
            if not n_arch:
                plan["warnings"].append(f"Ingen arkivmapper med mails i {acc.name} – postkassen bidrager kun "
                                        "med spam.")
        except Exception as ex:  # noqa: BLE001
            log.warning("rebuild plan failed for %s: %s", acc.name, type(ex).__name__)
            plan["errors"].append({"account": acc.name, "code": "imap_error", "text": "Mapperne kunne ikke læses."})
            plan["warnings"].append(f"Postkassen {acc.name} kunne ikke læses – den er ikke med i planen.")
        finally:
            _logout(client)
    reachable = {a.name for a in enabled} - {e["account"] for e in plan["errors"]}
    try:
        with closing(_open_db_ro(eng)) as conn:
            items = _old_spam_learn_list(conn, reachable, spam_names, eng)
    except sqlite3.Error:
        items = []
    by_acc: dict[str, int] = {}
    for a, _m in items:
        by_acc[a] = by_acc.get(a, 0) + 1
    plan["learn_list"] = {"total": len(items), "by_account": by_acc}
    spam_jobs.sort(key=lambda p: (-p["messages"], p["account"], p["folder"]))
    plan["spam_sources"] = spam_jobs + [
        {"account": a, "folder": None, "label": "Enkeltmails, der tidligere er lært som spam (godkendte lister "
         "og mails, brugeren selv har lagt i spam)", "kind": "learn_list", "messages": n, "planned": n}
        for a, n in sorted(by_acc.items())]
    expected_spam = sum(s["planned"] for s in plan["spam_sources"])
    budget = int(ratio * expected_spam)
    alloc = _waterfill([min(h["messages"], MAX_TRAIN_MESSAGES) for h in ham_cands], budget)
    for h, a in zip(ham_cands, alloc):
        h["planned"] = a
    # Interleave mailboxes so every mailbox and folder is represented.
    per_acc: dict[str, list[dict[str, Any]]] = {}
    for h in sorted(ham_cands, key=lambda h: (-h["messages"], h["folder"])):
        per_acc.setdefault(h["account"], []).append(h)
    ordered: list[dict[str, Any]] = []
    while any(per_acc.values()):
        for a in sorted(per_acc):
            if per_acc[a]:
                ordered.append(per_acc[a].pop(0))
    plan["ham_sources"] = ordered
    plan["expected_spam"] = expected_spam
    plan["expected_ham"] = sum(h["planned"] for h in ordered)
    if expected_spam < min_learns:
        plan["warnings"].append(f"Der er kun ca. {_n_da(expected_spam)} spam at lære. Bayes er slået fra, indtil "
                                f"der er lært mindst {_n_da(min_learns)} spam – læg mere spam i Spamfilter-mappen, "
                                "så kommer det med efterhånden.")
    if plan["expected_ham"] < min_learns:
        plan["warnings"].append(f"Der er kun ca. {_n_da(plan['expected_ham'])} legitime at lære fra arkivmapperne. "
                                f"Bayes er slået fra, indtil der er lært mindst {_n_da(min_learns)} legitime.")
    if plan.get("restoring"):
        plan["warnings"].append("En gendannelse af den tidligere Bayes blev ikke gjort færdig – tryk »Gendan "
                                "tidligere Bayes« først.")
    elif plan["running"]:
        plan["warnings"].append("En genopbygning er allerede i gang – vent, til den er færdig.")
    plan.update(ok=True, code="plan")
    plan["text"] = _plan_text(plan)
    return plan, items


def _check_ratio(ratio: Any) -> float | None:
    try:
        r = float(ratio)
    except (TypeError, ValueError):
        return None
    return r if REBUILD_RATIO_MIN <= r <= REBUILD_RATIO_MAX else None


def bayes_rebuild_plan(actor: str = "", *, ratio: float = REBUILD_DEFAULT_RATIO,
                       engine: Any = None) -> dict[str, Any]:
    """Dry run of 'Byg Bayes op på ny' (read-only IMAP LIST/STATUS + DB).
    SPAM = every enabled mailbox's filter folder + the provider's spam
    folder(s), any age, + mail the current pool learned as spam that lives
    elsewhere (owner-approved learn lists, the users' own spam verdicts).
    HAM = only the users' own archive folders (never INBOX, Sent, Junk,
    Trash, Drafts, Outbox, RSS, the filter folder or provider junk), the
    newest first, spread across mailboxes and folders, capped at
    ratio x spam (default 2 = 1:2). Admin only (the UI checks).
    -> {ok, code ('plan'|'config'|'db'|'invalid'), pool_now, pool_new,
        pools, ratio, spam_sources[{account, folder, label, kind
        ('filter_junk'|'provider_junk'|'spam_folder'|'learn_list'),
        messages, planned}], ham_sources[{account, folder, label, messages,
        planned}], learn_list{total, by_account}, expected_spam,
        expected_ham, warnings[], errors[], min_learns, running, text}"""
    eng = _eng(engine)
    r = _check_ratio(ratio)
    if r is None:
        return {"ok": False, "code": "invalid", "text": "Forholdet skal være mellem 0,5 og 5 legitime pr. spam.",
                "warnings": [], "spam_sources": [], "ham_sources": [], "expected_spam": 0, "expected_ham": 0,
                "pool_now": None, "pool_new": None}
    plan, _items = _rebuild_plan(eng, r)
    return plan


def _default_save_config(save_config: Any) -> Any:
    if save_config is not None:
        return save_config
    import dashboard  # noqa: PLC0415 - the UI/sfctl process; never at import time

    return dashboard.save_config


def _rebuild_event(conn: sqlite3.Connection, event: str, detail: str) -> None:
    conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES('*', ?, NULL, ?, ?)",
                 (int(time.time()), event, detail[:300]))


def _apply_pool(raw: dict, pool: str) -> None:
    if "defaults" in raw and raw["defaults"] is not None and not isinstance(raw["defaults"], dict):
        raise ValueError("defaults i konfigurationen har et ugyldigt format.")
    if not isinstance(raw.get("defaults"), dict):
        raw["defaults"] = {}
    raw["defaults"]["bayes_user"] = pool
    for e in raw.get("accounts") or []:
        if isinstance(e, dict) and "bayes_user" in e:
            e["bayes_user"] = pool


def _restore_pool_config(raw: dict, snap: dict[str, Any], pool_new: str) -> None:
    if not isinstance(raw.get("defaults"), dict):
        raw["defaults"] = {}
    d = snap.get("defaults") or {}
    if d.get("present"):
        raw["defaults"]["bayes_user"] = d.get("value")
    else:
        raw["defaults"].pop("bayes_user", None)
    accounts = snap.get("accounts") or {}
    for e in raw.get("accounts") or []:
        if not isinstance(e, dict) or not e.get("name"):
            continue
        name = str(e["name"])
        if name in accounts:
            e["bayes_user"] = accounts[name]
        elif str(e.get("bayes_user") or "") == pool_new:
            e.pop("bayes_user", None)


def bayes_rebuild_start(actor: str, confirm: bool = True, *, ratio: float = REBUILD_DEFAULT_RATIO,
                        engine: Any = None, save_config: Any = None) -> dict[str, Any]:
    """WRITE (admin, after the owner saw bayes_rebuild_plan): switch every
    account to a new pool (config via save_config, audit 'bayes_rebuild'),
    archive + reset the per-pool learned state (bayes_pool_switch) and queue
    the retrain jobs (learn list first, then spam folders, then ham folders;
    the trainer bypasses rate limits and the flip-flop cooldown for them and
    stops ham at ratio x the spam really learned). Nothing in Redis is
    deleted; the old pool stays as the backup.
    -> {ok, code ('started'|'confirm'|'running'|'nothing'|'rejected'|'config'|
        'db'|'invalid'), text, rebuild_id, pool_old, pool_new, jobs,
        expected_spam, expected_ham, warnings, audit_detail}"""
    eng = _eng(engine)
    out: dict[str, Any] = {"ok": False, "code": "invalid", "text": "", "rebuild_id": None, "pool_old": None,
                           "pool_new": None, "jobs": 0, "expected_spam": 0, "expected_ham": 0, "warnings": [],
                           "audit_detail": ""}
    if confirm is not True:
        out.update(code="confirm", text="Bekræft, at Bayes skal bygges op på ny.")
        return out
    r = _check_ratio(ratio)
    if r is None:
        out["text"] = "Forholdet skal være mellem 0,5 og 5 legitime pr. spam."
        return out
    plan, items = _rebuild_plan(eng, r)
    out.update(pool_old=plan.get("pool_now"), pool_new=plan.get("pool_new"), warnings=plan.get("warnings") or [],
               expected_spam=plan.get("expected_spam", 0), expected_ham=plan.get("expected_ham", 0))
    if not plan.get("ok"):
        out.update(code=plan.get("code") or "invalid", text=plan.get("text") or "Planen kunne ikke laves.")
        return out
    if plan["running"]:
        out.update(code="running", text=("En gendannelse af den tidligere Bayes er ikke gjort færdig – tryk "
                                         "»Gendan tidligere Bayes« først." if plan.get("restoring") else
                                         "En genopbygning er allerede i gang."))
        return out
    if plan["expected_spam"] <= 0:
        out.update(code="nothing", text="Der er ingen spam at lære fra – intet er ændret.")
        return out
    try:
        configs = list(eng.load_account_configs(eng.CONFIG_PATH))
        snap = _bayes_config_snapshot(_raw_config(eng))
    except Exception:  # noqa: BLE001
        out.update(code="config", text="Konfigurationen kunne ikke indlæses.")
        return out
    before = {a.name: _identity(eng, a) for a in configs}
    pool_old, pool_new = plan["pool_now"], plan["pool_new"]
    st = _stat_totals(eng)
    now = int(time.time())
    public_plan = {k: plan[k] for k in ("pool_now", "pool_new", "ratio", "spam_sources", "ham_sources",
                                         "expected_spam", "expected_ham", "warnings")}
    try:
        with closing(_open_db(eng)) as conn:
            _ensure_rebuild_schema(conn)
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT 1 FROM bayes_rebuilds WHERE status IN ('starting','running','restoring')"
                            ).fetchone():
                conn.execute("ROLLBACK")
                out.update(code="running", text="En genopbygning er allerede i gang.")
                return out
            cur = conn.execute(
                "INSERT INTO bayes_rebuilds(status, pool_old, pool_new, ratio, config_before, accounts, plan, "
                "expected_spam, expected_ham, stat_spam_start, stat_ham_start, created_by, created_at) "
                "VALUES('starting',?,?,?,?,?,?,?,?,?,?,?,?)",
                (pool_old, pool_new, r, json.dumps(snap), json.dumps(before),
                 json.dumps(public_plan, ensure_ascii=False), plan["expected_spam"], plan["expected_ham"],
                 st["spam_learned"] if st["ok"] else None, st["ham_learned"] if st["ok"] else None,
                 actor or None, now))
            rid = int(cur.lastrowid)
            conn.execute("COMMIT")
    except sqlite3.Error as ex:
        log.warning("rebuild start failed: %s", type(ex).__name__)
        out.update(code="db", text="Genopbygningen kunne ikke gemmes.")
        return out
    out["rebuild_id"] = rid
    detail = (f"rebuild={rid} {pool_old}->{pool_new} spam~{plan['expected_spam']} "
              f"ham~{plan['expected_ham']} ratio={r:g}")
    save = _default_save_config(save_config)

    def fail(code: str, text: str, note: str) -> dict[str, Any]:
        try:
            with closing(_open_db(eng)) as c2:
                c2.execute("UPDATE bayes_rebuilds SET status='failed', finished_at=?, note=? WHERE id=?",
                           (int(time.time()), note[:200], rid))
        except sqlite3.Error:
            pass
        out.update(code=code, text=text)
        return out

    try:
        save(lambda raw: _apply_pool(raw, pool_new), actor, "bayes_rebuild", detail=detail)
    except ValueError as ex:
        return fail("rejected", f"Ændringen blev afvist: {str(ex)[:200]}", "config rejected")
    box: dict[str, int] = {}

    def queue(conn: sqlite3.Connection, counts: dict[str, int]) -> None:
        # Inside the pool switch's transaction: the jobs, the 'running' mark
        # and the archive are committed together or not at all, so a failure
        # here leaves the old pool's learned state exactly as it was.
        box["jobs"] = _queue_rebuild_jobs(eng, conn, rid, plan, items, actor, now, own_tx=False)
        conn.execute("UPDATE bayes_rebuilds SET status='running', archived=? WHERE id=?",
                     (counts["archived"], rid))

    try:
        after = {a.name: _identity(eng, a) for a in eng.load_account_configs(eng.CONFIG_PATH)}
        moves = {name: (before.get(name) or after[name], after[name]) for name in after}
        tr = _trainer_mod()
        with closing(_open_db(eng)) as conn:
            tr.ensure_learn_list_schema(conn)   # DDL (executescript commits) before the transaction
            tr.ensure_train_columns(conn)
            bayes_pool_switch(conn, moves, now=now, then=queue)
            jobs = box["jobs"]
            try:
                _rebuild_event(conn, "bayes_rebuild_started", f"{detail} by {actor}")
            except sqlite3.Error:
                pass
    except Exception as ex:  # noqa: BLE001 - put the config back, never leave a half switch
        log.warning("rebuild switch failed: %s", type(ex).__name__)
        try:
            save(lambda raw: _restore_pool_config(raw, snap, pool_new), actor, "bayes_restore",
                 detail=f"rebuild={rid} rollback after failure")
        except Exception:  # noqa: BLE001
            log.error("rebuild: config rollback failed")
        return fail("db", "Genopbygningen kunne ikke startes – den gamle Bayes bruges stadig.", "switch failed")
    out.update(ok=True, code="started", jobs=jobs, audit_detail=detail,
               text=(f"Bayes bygges op på ny i puljen {pool_new}: ca. {_n_da(plan['expected_spam'])} spam og "
                     f"{_n_da(plan['expected_ham'])} legitime lægges i kø ({jobs} job). Den gamle pulje "
                     f"({pool_old}) er gemt urørt. Bayes er ikke aktiv, før der er lært mindst "
                     f"{_n_da(plan['min_learns'])} af hver slags."))
    return out


def _queue_rebuild_jobs(eng: Any, conn: sqlite3.Connection, rid: int, plan: dict[str, Any],
                        items: list[tuple[str, str]], actor: str, now: int, *, own_tx: bool = True) -> int:
    """Queue the rebuild's learn-list and trainer jobs. own_tx=False: the
    caller holds the transaction (bayes_pool_switch's `then`)."""
    tr = _trainer_mod()
    if own_tx:
        tr.ensure_learn_list_schema(conn)
        tr.ensure_train_columns(conn)
    n = 0
    if own_tx:
        conn.execute("BEGIN IMMEDIATE")
    try:
        if items:
            cur = conn.execute("INSERT INTO learn_list_jobs(status, total, note, created_by, created_at) "
                               "VALUES('queued', ?, ?, ?, ?)",
                               (len(items), f"Bayes-genopbygning #{rid}", actor or None, now))
            lid = int(cur.lastrowid)
            conn.executemany("INSERT OR IGNORE INTO learn_list_items(job_id, account, message_id, kind, status, "
                             "reason, updated_at) VALUES(?,?,?, 'spam', 'pending', ?, ?)",
                             [(lid, a, m, "bayes_rebuild", now) for a, m in items])
            conn.execute("INSERT INTO bayes_rebuild_jobs(rebuild_id, job_type, job_id, role, account, folder, planned) "
                         "VALUES(?, 'list', ?, 'spam', '*', NULL, ?)", (rid, lid, len(items)))
            n += 1
        for role, sources in (("spam", plan["spam_sources"]), ("ham", plan["ham_sources"])):
            for src in sources:
                if src.get("kind") == "learn_list" or not src.get("folder") or int(src.get("planned") or 0) <= 0:
                    continue
                cur = conn.execute(
                    "INSERT INTO train_jobs(account, folder, kind, max_messages, min_age_days, seen_only, "
                    "provider_filter, status, created_by, created_at) VALUES(?,?,?,?,0,0,'any','queued',?,?)",
                    (src["account"], src["folder"], role, int(src["planned"]), actor or None, now))
                conn.execute("INSERT INTO bayes_rebuild_jobs(rebuild_id, job_type, job_id, role, account, folder, "
                             "planned) VALUES(?, 'train', ?, ?, ?, ?, ?)",
                             (rid, int(cur.lastrowid), role, src["account"], src["folder"], int(src["planned"])))
                n += 1
        if own_tx:
            conn.execute("COMMIT")
    except BaseException:
        if own_tx:
            conn.execute("ROLLBACK")
        raise
    return n


def _cancel_rebuild_jobs(conn: sqlite3.Connection, rid: int, now: int) -> None:
    """Stop every job of a rebuild: queued ones now, running ones before
    their next learn (the trainer checks cancel_requested per message)."""
    for typ, table in (("train", "train_jobs"), ("list", "learn_list_jobs")):
        ids = [r[0] for r in conn.execute("SELECT job_id FROM bayes_rebuild_jobs WHERE rebuild_id=? AND "
                                          "job_type=?", (rid, typ))]
        for jid in ids:
            conn.execute(f"UPDATE {table} SET status='cancelled', finished_at=? WHERE id=? AND "
                         f"status='queued'", (now, jid))
            conn.execute(f"UPDATE {table} SET status='cancel_requested' WHERE id=? AND status='running'",
                         (jid,))


def _set_rebuild_status(eng: Any, rid: int, expect: str, status: str) -> None:
    """Put a rebuild back to `status` (a refused restore); a running one whose
    jobs were cancelled meanwhile is closed as done right away."""
    try:
        with closing(_open_db(eng)) as conn:
            conn.execute("UPDATE bayes_rebuilds SET status=?, note=NULL WHERE id=? AND status=?",
                         (status, rid, expect))
            if status == "running":
                _trainer_mod().rebuild_after_job(conn, rid)
    except sqlite3.Error:
        pass


def _rebuild_percent(prog: dict[str, Any], expected_spam: int, expected_ham: int) -> int:
    """Progress in MAILS (learned + skipped + failed against the plan), not
    in jobs; at most 99 % until every job has ended."""
    total = done = 0
    for role, expected in (("spam", expected_spam), ("ham", expected_ham)):
        p = prog[role]
        planned = max(int(p.get("planned") or 0), int(expected or 0))
        total += planned
        done += min(planned, int(p["learned"]) + int(p["skipped"]) + int(p["failed"]))
    if not prog.get("active"):
        return 100
    if total <= 0:
        return 0
    return max(0, min(99, int(100 * done / total)))


_REBUILD_STATUS_TEXT = {"starting": "starter", "running": "i gang", "done": "færdig", "failed": "fejlede",
                        "restored": "gendannet til den tidligere pulje",
                        "restoring": "gendannelsen er ikke færdig"}


def bayes_rebuild_status(*, engine: Any = None) -> dict[str, Any]:
    """The latest Bayes rebuild with progress and plain Danish text.
    -> {ok, code ('none'|'starting'|'running'|'done'|'failed'|'restored'|'db'),
        rebuild_id, pool, pool_old, pool_new, created_at, created_by,
        finished_at, restored_at, ratio, expected_spam, expected_ham,
        learned_spam, learned_ham, percent, jobs{status: n}, bayes{spam,
        ham, active, counts_source}, min_learns, missing_spam, missing_ham,
        can_restore, warnings[], text}"""
    eng = _eng(engine)
    stats = bayes_stats(engine=eng)
    low = int(stats.get("min_learns") or 200)
    out: dict[str, Any] = {"ok": True, "code": "none", "rebuild_id": None, "pool": stats.get("pool"),
                           "pool_old": None, "pool_new": None, "created_at": None, "created_by": None,
                           "finished_at": None, "restored_at": None, "ratio": None, "expected_spam": 0,
                           "expected_ham": 0, "learned_spam": 0, "learned_ham": 0, "percent": 0, "jobs": {},
                           "bayes": {"ok": bool(stats.get("ok")), "spam": stats.get("spam_learned", 0),
                                     "ham": stats.get("ham_learned", 0), "active": bool(stats.get("active")),
                                     "counts_source": stats.get("counts_source")},
                           "min_learns": low, "missing_spam": 0, "missing_ham": 0, "can_restore": False,
                           "warnings": [], "text": ""}
    try:
        with closing(_open_db(eng)) as conn:
            _ensure_rebuild_schema(conn)
            row = conn.execute("SELECT * FROM bayes_rebuilds ORDER BY id DESC LIMIT 1").fetchone()
            prog = _trainer_mod().rebuild_progress(conn, int(row["id"])) if row is not None else None
    except sqlite3.Error:
        out.update(ok=False, code="db", text="Status for genopbygningen kunne ikke læses.")
        return out
    if stats.get("ok"):
        out["missing_spam"] = max(0, low - int(stats.get("spam_learned") or 0))
        out["missing_ham"] = max(0, low - int(stats.get("ham_learned") or 0))
    if row is None:
        out["text"] = (f"Bayes er ikke bygget op på ny. Aktiv pulje: {out['pool'] or 'ukendt'}. "
                       + (stats.get("text") or ""))
        return out
    status = str(row["status"])
    out.update(code=status, rebuild_id=int(row["id"]), pool_old=row["pool_old"], pool_new=row["pool_new"],
               created_at=row["created_at"], created_by=row["created_by"], finished_at=row["finished_at"],
               restored_at=row["restored_at"], ratio=row["ratio"], expected_spam=int(row["expected_spam"] or 0),
               expected_ham=int(row["expected_ham"] or 0))
    if prog is not None:
        out["learned_spam"], out["learned_ham"] = prog["spam"]["learned"], prog["ham"]["learned"]
        out["jobs"] = prog["jobs"]
        out["percent"] = _rebuild_percent(prog, out["expected_spam"], out["expected_ham"])
    out["can_restore"] = status in ("running", "done") and row["archived"] is not None \
        and out["pool"] == row["pool_new"]
    out["warnings"] = []
    if prog is not None and status in ("running", "done"):
        for role, word in (("spam", "spam"), ("ham", "legitime")):
            p = prog[role]
            if p["learned"] == 0 and p["skipped"] >= 20:
                # rspamd answers 208 'already learned' when its learn cache is
                # not per Bayes user: then the new pool learns nothing.
                if status == "done":
                    out["warnings"].append(
                        f"Genopbygningen lærte ingen {word}, fordi rspamd svarede »allerede lært« "
                        f"({_n_da(p['skipped'])} gange)."
                        + (" Filteret kører nu uden Bayes." if not out["bayes"]["active"] else "")
                        + " Tryk »Gendan tidligere Bayes« for at gå tilbage til den gamle.")
                else:
                    out["warnings"].append(
                        f"Ingen {word} er lært endnu, men {_n_da(p['skipped'])} blev sprunget over – rspamd har "
                        "måske svaret »allerede lært«. Tryk »Gendan tidligere Bayes«, hvis tallet ikke stiger "
                        "inden for få minutter.")
    ls, lh = _n_da(out["learned_spam"]), _n_da(out["learned_ham"])
    bayes_line = (f"Bayes er aktiv i puljen {row['pool_new']}." if out["bayes"]["active"] else
                  f"Bayes er ikke aktiv endnu – rspamd bruger først Bayes, når der er lært mindst {_n_da(low)} "
                  f"af hver slags" + (f" (mangler {_n_da(out['missing_spam'])} spam og {_n_da(out['missing_ham'])} "
                                      "legitime)." if stats.get("ok") else "."))
    if out["warnings"] and status in ("running", "done"):
        bayes_line += " " + " ".join(out["warnings"])
    if status in ("starting", "running"):
        out["text"] = (f"Genopbygning i gang ({out['percent']} %): {ls} af ca. {_n_da(out['expected_spam'])} spam og "
                       f"{lh} af ca. {_n_da(out['expected_ham'])} legitime er lært i puljen {row['pool_new']}. "
                       + bayes_line)
    elif status == "done":
        out["text"] = (f"Genopbygningen er færdig: {ls} spam og {lh} legitime er lært i puljen "
                       f"{row['pool_new']}. " + bayes_line)
    elif status == "restored":
        out["text"] = (f"Den tidligere Bayes-pulje ({row['pool_old']}) er gendannet. Puljen {row['pool_new']} "
                       "ligger urørt og bruges ikke.")
    elif status == "restoring":
        out["text"] = (f"Gendannelsen af den tidligere Bayes-pulje ({row['pool_old']}) blev ikke gjort færdig. "
                       "Tryk »Gendan tidligere Bayes« igen.")
        out["can_restore"] = row["archived"] is not None
    else:
        out["text"] = ("Genopbygningen kunne ikke gennemføres – den tidligere Bayes bruges stadig."
                       if row["archived"] is None else
                       "Genopbygningen stoppede med en fejl. Du kan gendanne den tidligere Bayes.")
        out["can_restore"] = row["archived"] is not None and out["pool"] == row["pool_new"]
    return out


def bayes_restore_previous(actor: str, confirm: bool = True, *, engine: Any = None,
                           save_config: Any = None) -> dict[str, Any]:
    """WRITE (admin): 'Gendan tidligere Bayes' - stop the rebuild's jobs,
    switch every account back to the pool it used before (config via
    save_config, audit 'bayes_restore') and bring back that pool's learned
    state. The rebuilt pool stays in Redis untouched.
    -> {ok, code ('restored'|'confirm'|'nothing'|'changed'|'rejected'|'db'),
        text, rebuild_id, pool, audit_detail}"""
    eng = _eng(engine)
    out: dict[str, Any] = {"ok": False, "code": "nothing", "text": "", "rebuild_id": None, "pool": None,
                           "audit_detail": ""}
    if confirm is not True:
        out.update(code="confirm", text="Bekræft, at den tidligere Bayes skal gendannes.")
        return out
    try:
        with closing(_open_db(eng)) as conn:
            _ensure_rebuild_schema(conn)
            row = conn.execute("SELECT * FROM bayes_rebuilds WHERE archived IS NOT NULL AND status!='restored' "
                               "ORDER BY id DESC LIMIT 1").fetchone()
    except sqlite3.Error:
        out.update(code="db", text="Databasen kunne ikke læses.")
        return out
    if row is None:
        out["text"] = "Der er ingen tidligere Bayes at gendanne."
        return out
    rid, pool_old, pool_new = int(row["id"]), row["pool_old"], row["pool_new"]
    out["rebuild_id"] = rid
    try:
        configs = list(eng.load_account_configs(eng.CONFIG_PATH))
        snap = json.loads(row["config_before"] or "{}")
    except Exception:  # noqa: BLE001
        out.update(code="config", text="Konfigurationen kunne ikke indlæses.")
        return out
    current = {a.name: _identity(eng, a) for a in configs}
    prev_status = str(row["status"])
    # 'restoring' = an earlier attempt marked the restore and maybe already
    # put the config back, but the learned state was not switched: finish it.
    resuming = prev_status == "restoring"
    config_back = resuming and pool_new not in current.values()
    if pool_new not in current.values() and not resuming:
        out.update(code="changed", text=f"Puljen {pool_new} er ikke længere i brug – konfigurationen er ændret "
                                        "siden genopbygningen. Intet er ændret.")
        return out
    now = int(time.time())
    try:
        with closing(_open_db(eng)) as conn:
            _cancel_rebuild_jobs(conn, rid, now)
            if not resuming:
                conn.execute("UPDATE bayes_rebuilds SET status='restoring', note=? WHERE id=?",
                             (f"before restore: {prev_status}", rid))
    except sqlite3.Error:
        out.update(code="db", text="Genopbygningens job kunne ikke stoppes. Intet er ændret – prøv igen.")
        return out
    st = _stat_totals(eng)
    detail = f"rebuild={rid} {pool_new}->{pool_old}"
    save = _default_save_config(save_config)
    if not config_back:
        try:
            save(lambda raw: _restore_pool_config(raw, snap, pool_new), actor, "bayes_restore", detail=detail)
        except ValueError as ex:
            if not resuming:
                _set_rebuild_status(eng, rid, "restoring", prev_status)
            out.update(code="rejected", text=f"Ændringen blev afvist: {str(ex)[:200]}")
            return out
    try:
        after = {a.name: _identity(eng, a) for a in eng.load_account_configs(eng.CONFIG_PATH)}
        if config_back:
            try:
                switched = set(json.loads(row["accounts"] or "{}"))
            except ValueError:
                switched = set()
            moves = {name: (pool_new, after[name]) for name in after
                     if after[name] != pool_new and (name in switched or not switched)}
        else:
            moves = {name: (current.get(name, pool_new), after[name]) for name in after
                     if current.get(name) == pool_new}

        def mark(conn: sqlite3.Connection, _counts: dict[str, int]) -> None:
            conn.execute("UPDATE bayes_rebuilds SET status='restored', restored_by=?, restored_at=?, "
                         "stat_spam_restore=?, stat_ham_restore=?, finished_at=COALESCE(finished_at, ?), "
                         "note=NULL WHERE id=?",
                         (actor or None, now, st["spam_learned"] if st["ok"] else None,
                          st["ham_learned"] if st["ok"] else None, now, rid))

        with closing(_open_db(eng)) as conn:
            bayes_pool_switch(conn, moves, now=now, then=mark)
            try:
                _rebuild_event(conn, "bayes_restored", f"{detail} by {actor}")
            except sqlite3.Error:
                pass
    except Exception as ex:  # noqa: BLE001
        log.warning("restore switch failed: %s", type(ex).__name__)
        out.update(code="db", text="Konfigurationen er sat tilbage, men den lærte tilstand kunne ikke gendannes "
                                   "endnu. Tryk »Gendan tidligere Bayes« igen.")
        return out
    out.update(ok=True, code="restored", pool=pool_old, audit_detail=detail,
               text=(f"Den tidligere Bayes ({pool_old}) er gendannet. Puljen {pool_new} ligger urørt og bruges "
                     "ikke. Filteret genindlæser om et øjeblik."))
    return out


# ---------------------------------------------------------------------------
# Straks-advarsel: threats stopped today (Oversigt card)
# ---------------------------------------------------------------------------

THREAT_CLASS_ORDER = ("virus", "phish", "malware_url", "attachment", "impersonation", "lookalike")
# Threat mail the filter (or the user / the provider) really took out of the
# inbox - only these count as "stoppet". Overvåg/Markér and a failed move
# leave the mail in the inbox: counted separately as `in_inbox`.
THREAT_STOPPED_ACTIONS = ("moved_to_junk", "pending_move", "user_junked", "provider_junk", "manual_mark_spam")
THREAT_IN_INBOX_ACTIONS = ("shadow_spam", "flagged", "move_failed")


def threats_today(accounts: Iterable[str] | None = None, *, day: str | None = None, days: int = 1,
                  engine: Any = None) -> dict[str, Any]:
    """Dangerous mails stopped today (Copenhagen day; days=7: the last 7
    calendar days up to `day`) for the accounts the user may see (None =
    all; the UI passes the user's mailboxes). Counts threat mail that was
    really taken out of the inbox (THREAT_STOPPED_ACTIONS); threat mail that
    still sits in the inbox (Overvåg/Markér, a failed move) is `in_inbox`.
    -> {day, days, total, by_class{cls: n}, by_account{account: n}, in_inbox,
        in_inbox_by_account, notices, items[{threat, label, n}], text}"""
    eng = _eng(engine)
    day = day or _local_today().isoformat()
    days = 7 if int(days or 1) == 7 else 1
    names = [str(a) for a in accounts] if accounts is not None else None
    out: dict[str, Any] = {"day": day, "days": days, "total": 0, "by_class": {}, "by_account": {}, "in_inbox": 0,
                           "in_inbox_by_account": {}, "notices": 0, "items": [],
                           "text": "Farlige mails stoppet i dag: 0"}
    if names is not None and not names:
        return out
    try:
        d = _dt.date.fromisoformat(day)
    except ValueError:
        return out
    start = _local_midnight_ts(d - _dt.timedelta(days=days - 1))
    end = _local_midnight_ts(d + _dt.timedelta(days=1))
    acc_sql = f" AND account IN ({','.join('?' * len(names))})" if names is not None else ""
    stopped = ",".join("?" * len(THREAT_STOPPED_ACTIONS))
    inbox = ",".join("?" * len(THREAT_IN_INBOX_ACTIONS))
    day_list = [(d - _dt.timedelta(days=i)).isoformat() for i in range(days)]
    try:
        with closing(_open_db_ro(eng)) as conn:
            for r in conn.execute(
                    "SELECT account, threat, COUNT(*) AS n FROM messages WHERE threat IS NOT NULL AND threat != '' "
                    f"AND scanned_at>=? AND scanned_at<? AND our_action IN ({stopped})" + acc_sql
                    + " GROUP BY account, threat", [start, end, *THREAT_STOPPED_ACTIONS, *(names or [])]):
                n = int(r["n"] or 0)
                out["by_class"][r["threat"]] = out["by_class"].get(r["threat"], 0) + n
                out["by_account"][r["account"]] = out["by_account"].get(r["account"], 0) + n
            for r in conn.execute(
                    "SELECT account, COUNT(*) AS n FROM messages WHERE threat IS NOT NULL AND threat != '' "
                    f"AND scanned_at>=? AND scanned_at<? AND our_action IN ({inbox})" + acc_sql
                    + " GROUP BY account", [start, end, *THREAT_IN_INBOX_ACTIONS, *(names or [])]):
                out["in_inbox_by_account"][r["account"]] = int(r["n"] or 0)
            row = conn.execute(f"SELECT SUM(n) FROM stats_daily WHERE day IN ({','.join('?' * len(day_list))}) "
                               "AND metric='threat_notice_sent'" + acc_sql, [*day_list, *(names or [])]).fetchone()
            out["notices"] = int(row[0] or 0) if row else 0
    except sqlite3.Error:
        return out
    out["total"] = sum(out["by_class"].values())
    out["in_inbox"] = sum(out["in_inbox_by_account"].values())
    order = {c: i for i, c in enumerate(THREAT_CLASS_ORDER)}
    out["items"] = [{"threat": c, "label": THREAT_LABELS.get(c, "Farlig mail"), "n": n}
                    for c, n in sorted(out["by_class"].items(), key=lambda kv: (order.get(kv[0], 99), kv[0]))]
    detail = ", ".join(f"{_n_da(i['n'])} {i['label'].lower()}" for i in out["items"])
    when = "i dag" if days == 1 else "de seneste 7 dage"
    out["text"] = f"Farlige mails stoppet {when}: {_n_da(out['total'])}" + (f" ({detail})" if detail else "")
    if out["in_inbox"]:
        out["text"] += (f". {_n_da(out['in_inbox'])} farlig{'e' if out['in_inbox'] != 1 else ''} "
                        f"mail{'s' if out['in_inbox'] != 1 else ''} ligger stadig i indbakken")
    return out
    try:
        d = _dt.date.fromisoformat(day)
    except ValueError:
        return out
    start = _local_midnight_ts(d)
    end = _local_midnight_ts(d + _dt.timedelta(days=1))
    acc_sql = f" AND account IN ({','.join('?' * len(names))})" if names is not None else ""
    try:
        with closing(_open_db_ro(eng)) as conn:
            for r in conn.execute(
                    "SELECT account, threat, COUNT(*) AS n FROM messages WHERE threat IS NOT NULL AND scanned_at>=? "
                    "AND scanned_at<? AND COALESCE(our_action, '') NOT IN ('allowlisted', 'none')" + acc_sql
                    + " GROUP BY account, threat", [start, end, *(names or [])]):
                n = int(r["n"] or 0)
                out["by_class"][r["threat"]] = out["by_class"].get(r["threat"], 0) + n
                out["by_account"][r["account"]] = out["by_account"].get(r["account"], 0) + n
            row = conn.execute("SELECT SUM(n) FROM stats_daily WHERE day=? AND metric='threat_notice_sent'"
                               + acc_sql, [day, *(names or [])]).fetchone()
            out["notices"] = int(row[0] or 0) if row else 0
    except sqlite3.Error:
        return out
    out["total"] = sum(out["by_class"].values())
    order = {c: i for i, c in enumerate(THREAT_CLASS_ORDER)}
    out["items"] = [{"threat": c, "label": THREAT_LABELS.get(c, "Farlig mail"), "n": n}
                    for c, n in sorted(out["by_class"].items(), key=lambda kv: (order.get(kv[0], 99), kv[0]))]
    detail = ", ".join(f"{_n_da(i['n'])} {i['label'].lower()}" for i in out["items"])
    out["text"] = f"Farlige mails stoppet i dag: {_n_da(out['total'])}" + (f" ({detail})" if detail else "")
    return out


# ---------------------------------------------------------------------------
# 2.6 (A4): newsletter folder "Nyhedsbreve" (newsletters.py)
# ---------------------------------------------------------------------------

NEWSLETTER_BACK_EVENT = "newsletter_back"


def _nl_mod() -> Any:
    import newsletters  # noqa: PLC0415 - pure helper module next to the engine

    return newsletters


def newsletter_to_inbox(account: str, message_id: str, actor: str, *, engine: Any = None) -> dict[str, Any]:
    """'Tilbage til indbakken': move exactly one mail (exact Message-ID)
    that the filter moved to the newsletter folder back to the inbox and
    keep its sender in the inbox from now on (newsletter_keep). Nothing is
    learned and no spam/ham verdict is set. Never raises.
    Returns {ok, code, text, message_id, sender_kept}."""
    eng = _eng(engine)
    mid = normalize_message_id(message_id)
    out: dict[str, Any] = {"ok": False, "code": "invalid_id", "text": "Ugyldigt Message-ID.",
                           "message_id": message_id, "sender_kept": None}
    if mid is None:
        return out
    try:
        acc, client = _open_session(eng, account, timeout=FIND_TIMEOUT_S)
    except ServiceError as ex:
        out.update(code=ex.code, text=ex.text)
        return out
    db = None
    try:
        try:
            fmap = _folder_map(acc, _list_folders(client))
        except Exception as ex:
            log.warning("newsletter_to_inbox LIST failed: %s", type(ex).__name__)
            out.update(code="imap_error", text="Mappelisten kunne ikke hentes fra mailserveren.")
            return out
        folder = fmap.get("newsletters")
        if not folder:
            out.update(code="no_folder", text="Mappen til nyhedsbreve findes ikke på mailserveren.")
            return out
        db = eng.Db(acc.name)
        row = db.conn.execute("SELECT our_action, sender FROM messages WHERE account=? AND message_id=?",
                              (acc.name, mid)).fetchone()
        nl = _nl_mod()
        if row is None or row["our_action"] not in (nl.ACTION_MOVED, nl.ACTION_FAILED):
            out.update(code="changed", text="Mailen er ikke flyttet til nyhedsbreve af filteret.")
            return out
        if _threat_of(db.conn, acc.name, mid)[0]:
            out.update(code="threat", text=THREAT_ADMIN_TEXT)  # never: threats are spam, not newsletters
            return out
        caps = _caps_for_engine(_caps(client))
        client.select_folder(folder, readonly=False)
        uids = list(eng.find_uids_by_message_id(client, mid) or [])
        if len(uids) > 1:
            uids = [u for u in [_pick_duplicate(client, uids)] if u is not None] or uids
        if not uids:
            out.update(code="not_found", text="Mailen findes ikke længere i mappen.")
            return out
        if len(uids) > 1:
            out.update(code="ambiguous", text="Flere mails har samme Message-ID – intet er ændret.")
            return out
        moved, code, _outcome = _move_one_to_inbox(
            eng, db, acc, client, fmap, caps, folder, uids[0], mid, learn=False, verdict=None, by=actor,
            actor=actor, event=NEWSLETTER_BACK_EVENT, detail=f"from {folder} actor={actor}", stat=None,
            reason="newsletter_back")
        if not moved:
            out.update(code=code, text="Mailen kunne ikke flyttes til indbakken."
                       if code == "move_failed" else "Mailen findes ikke længere i mappen.")
            return out
        now = int(time.time())
        with db.tx():
            # _premark_inbox booked a sticky manual release so the engine
            # never scores the new inbox UID; record what it really was.
            db.conn.execute("UPDATE messages SET our_action=?, current_folder=? WHERE account=? AND message_id=?",
                            (nl.ACTION_KEPT, fmap["inbox"], acc.name, mid))
            key = nl.add_keep(db.conn, acc.name, row["sender"], by=actor or "webui", message_id=mid, now=now)
            db.log_event(nl.EVENT_KEPT, mid, detail=f"webui actor={actor}" + (" sender kept" if key else ""))
        try:
            eng.bump_stat(db.conn, acc.name, nl.METRIC_KEPT)
        except Exception as ex:
            log.warning("bump_stat(newsletter_kept) failed: %s", type(ex).__name__)
        text = "Flyttet tilbage til indbakken."
        if key:
            text += " Mails fra afsenderen bliver i indbakken fremover."
        if code == "copied":
            text = ("Kopieret til indbakken (originalen blev liggende i nyhedsbreve)."
                    + (" Mails fra afsenderen bliver i indbakken fremover." if key else ""))
        out.update(ok=True, code="ok" if code != "copied" else "copied", text=text, message_id=mid,
                   sender_kept=key)
        return out
    except Exception as ex:
        log.warning("newsletter_to_inbox failed: %s", type(ex).__name__)
        out.update(code="imap_error", text="Mailserveren afviste handlingen.")
        return out
    finally:
        if db is not None:
            try:
                db.close()
            except Exception:
                pass
        _logout(client)


def newsletter_unkeep(account: str, sender: str, actor: str, *, engine: Any = None) -> dict[str, Any]:
    """Forget a "keep in inbox" sender: its newsletters may be moved again.
    DB only. Returns {ok, code, text}."""
    eng = _eng(engine)
    nl = _nl_mod()
    key = nl.sender_key(sender)
    if key is None:
        return {"ok": False, "code": "invalid", "text": "Ugyldig afsender."}
    try:
        with closing(_open_db(eng)) as conn:
            nl.ensure_schema(conn)
            removed = nl.remove_keep(conn, account, key)
            if removed:
                conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,NULL,?,?)",
                             (account, int(time.time()), "newsletter_unkeep", f"actor={actor}"[:300]))
            conn.commit()
    except sqlite3.Error as ex:
        log.warning("newsletter_unkeep failed: %s", type(ex).__name__)
        return {"ok": False, "code": "db", "text": "Ændringen kunne ikke gemmes."}
    if not removed:
        return {"ok": True, "code": "nothing", "text": "Afsenderen stod ikke på listen."}
    return {"ok": True, "code": "ok", "text": f"{key} kan nu flyttes til nyhedsbreve igen."}
