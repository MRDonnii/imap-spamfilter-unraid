"""Fakes for the SERVICES tests (mailctx/services/trainer).

FakeIMAP models the IMAPClient calls those modules use, records every
mutating call in `writes`, and enforces read-only SELECTs. FakeEngine is a
stand-in for the `filter` module exposing the SPEC E14/A2 primitive names
over a real SQLite file, so the code under test runs its real SQL.

Kept separate from tests/fakes.py on purpose (built concurrently with the
engine); the integrator may merge them.
"""

from __future__ import annotations

import datetime as dt
import email
import email.policy
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from email.header import decode_header, make_header
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Iterator

from imapclient.exceptions import IMAPClientError, IMAPClientReadOnlyError, LoginError
from imapclient.response_types import Address, Envelope

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "headers"


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def make_message(msgid: str | None, *, subject: str = "Hej", sender: str = "a@example.org",
                 body: str = "Hello world, this is a test body.\n", extra: str = "",
                 size_pad: int = 0, date: str = "Tue, 20 Oct 2026 10:00:00 +0000") -> bytes:
    lines = [f"From: {sender}", "To: user@example-a.dk", f"Subject: {subject}",
             f"Date: {date}"]
    if msgid is not None:
        lines.append(f"Message-ID: <{msgid}>")
    if extra:
        lines.append(extra.rstrip("\r\n"))
    text = "\r\n".join(lines) + "\r\n\r\n" + body + ("x" * size_pad)
    return text.encode()


def with_msgid(raw: bytes, msgid: str) -> bytes:
    """Fixture bytes with its Message-ID replaced (fixtures share layout)."""
    return re.sub(rb"(?mi)^Message-ID:.*$", f"Message-ID: <{msgid}>".encode(), raw, count=1)


def make_account(**over: Any) -> SimpleNamespace:
    base = dict(
        name="acc", user="user@example-a.dk", password="", imap_host="imap.example.org",
        imap_port=993, ssl=True, inbox="INBOX", junk="Junk", trash="Trash",
        junk_explicit=False, trash_explicit=False, enabled=True, mode="shadow",
        threshold=8.0, bayes_user="hjemmeserver", provider_bonus=True, trusted_relays=[],
        trusted_relay_domains=[], auto_special_folders=True, max_learns_per_hour=50,
        learn_from_moves=True, training_folders=False,
    )
    base.update(over)
    return SimpleNamespace(**base)


# ---------------------------------------------------------------------------
# IMAP
# ---------------------------------------------------------------------------


@dataclass
class FakeMsg:
    raw: bytes
    flags: set[str] = field(default_factory=set)
    internaldate: dt.datetime = field(
        default_factory=lambda: (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)).replace(microsecond=0))


GIGAHOST_CAPS = (b"IMAP4REV1", b"IDLE", b"UIDPLUS", b"NAMESPACE")
SCANNET_CAPS = (b"IMAP4REV1", b"IDLE", b"MOVE", b"UIDPLUS", b"SPECIAL-USE")


class FakeIMAP:
    def __init__(self, *, capabilities: tuple[bytes, ...] = GIGAHOST_CAPS,
                 folders: tuple[str, ...] = ("INBOX", "Junk", "Trash"),
                 special_use: dict[str, str] | None = None,
                 password: str | None = None, fail_on: dict[str, Exception] | None = None) -> None:
        self._caps = tuple(capabilities)
        self.folders: dict[str, dict[int, FakeMsg]] = {f: {} for f in folders}
        self.next_uid: dict[str, int] = {f: 1 for f in folders}
        self.special_use = dict(special_use or {})  # folder -> "\\Junk"
        self.password = password
        self.fail_on = dict(fail_on or {})          # method name -> exception
        self.selected: str | None = None
        self.readonly: bool | None = None
        self.selects: list[tuple[str, bool]] = []
        self.writes: list[tuple] = []
        self.searches: list[list[Any]] = []
        self.search_charsets: list[str | None] = []
        self.statuses: list[str] = []
        self.reject_charset = False
        self.fetches: list[tuple[list[int], list[bytes]]] = []
        self.logins = 0
        self.logged_out = False
        self.starttls_done = False

    # --- setup helpers ----------------------------------------------------
    def add(self, folder: str, raw: bytes, *, flags: tuple[str, ...] = (),
            internaldate: dt.datetime | None = None) -> int:
        self.folders.setdefault(folder, {})
        self.next_uid.setdefault(folder, 1)
        uid = self.next_uid[folder]
        self.next_uid[folder] += 1
        msg = FakeMsg(raw, set(flags))
        if internaldate is not None:
            msg.internaldate = internaldate
        self.folders[folder][uid] = msg
        return uid

    def _maybe_fail(self, name: str) -> None:
        if name in self.fail_on:
            raise self.fail_on[name]

    # --- session ----------------------------------------------------------
    def login(self, user: str, password: str) -> bytes:
        self._maybe_fail("login")
        if self.password is not None and password != self.password:
            raise LoginError("[AUTHENTICATIONFAILED] Authentication failed.")
        self.logins += 1
        return b"OK"

    def starttls(self, ctx: Any = None) -> None:
        self._maybe_fail("starttls")
        self.starttls_done = True

    def logout(self) -> None:
        self.logged_out = True

    def capabilities(self) -> tuple[bytes, ...]:
        return self._caps

    def list_folders(self, directory: str = "", pattern: str = "*") -> list[tuple]:
        self._maybe_fail("list_folders")
        out = []
        for name in self.folders:
            flags = [b"\\HasNoChildren"]
            if name in self.special_use:
                flags.append(self.special_use[name].encode())
            out.append((tuple(flags), b".", name))
        return out

    def folder_status(self, folder: str, what: list[bytes]) -> dict[bytes, int]:
        self._maybe_fail("folder_status")
        self.statuses.append(folder)
        box = self.folders[folder]
        return {b"MESSAGES": len(box),
                b"UNSEEN": sum(1 for m in box.values() if "\\Seen" not in m.flags)}

    def select_folder(self, folder: str, readonly: bool = False) -> dict[bytes, Any]:
        self._maybe_fail("select_folder")
        if folder not in self.folders:
            raise IMAPClientError(f"select failed: NO Mailbox doesn't exist: {folder}")
        self.selected = folder
        self.readonly = readonly
        self.selects.append((folder, readonly))
        return {b"UIDVALIDITY": 1, b"EXISTS": len(self.folders[folder])}

    # --- reads ------------------------------------------------------------
    def _box(self) -> dict[int, FakeMsg]:
        if self.selected is None:
            raise IMAPClientError("no mailbox selected")
        return self.folders[self.selected]

    @staticmethod
    def _header_text(raw: bytes) -> bytes:
        m = re.search(rb"\r?\n\r?\n", raw)
        return raw[: m.end()] if m else raw

    @staticmethod
    def _decoded(raw: bytes, name: str) -> str:
        # Servers search decoded text: raw 8-bit (UTF-8) and RFC 2047 alike.
        hdrs = email.message_from_string(FakeIMAP._header_text(raw).decode("utf-8", "replace"),
                                         policy=email.policy.compat32)
        val = hdrs.get(name)
        if val is None:
            return ""
        text = str(val)
        try:
            return str(make_header(decode_header(text)))
        except Exception:
            return text

    def _match(self, msg: FakeMsg, crit: list[Any], i: int) -> tuple[bool, int]:
        """Evaluate one search key at crit[i]; returns (match, next index).
        RFC 3501 semantics for the keys services/trainer use."""
        c = crit[i]
        if isinstance(c, (list, tuple)):
            ok, j = True, 0
            while j < len(c):
                m, j = self._match(msg, list(c), j)
                ok &= m
            return ok, i + 1
        cu = c.upper() if isinstance(c, str) else c
        if cu == "ALL":
            return True, i + 1
        if cu == "SEEN":
            return "\\Seen" in msg.flags, i + 1
        if cu == "UNSEEN":
            return "\\Seen" not in msg.flags, i + 1
        if cu == "DELETED":
            return "\\Deleted" in msg.flags, i + 1
        if cu == "UNDELETED":
            return "\\Deleted" not in msg.flags, i + 1
        if cu == "BEFORE":
            return msg.internaldate.date() < crit[i + 1], i + 2
        if cu == "SINCE":
            return msg.internaldate.date() >= crit[i + 1], i + 2
        if cu in ("FROM", "SUBJECT"):
            value = str(crit[i + 1]).lower()
            return value in self._decoded(msg.raw, cu.title()).lower(), i + 2
        if cu == "HEADER":
            name, value = crit[i + 1], crit[i + 2]
            return value.lower() in self._decoded(msg.raw, name).lower(), i + 3
        if cu == "OR":
            a, j = self._match(msg, crit, i + 1)
            b, k = self._match(msg, crit, j)
            return a or b, k
        if cu == "NOT":
            a, j = self._match(msg, crit, i + 1)
            return not a, j
        raise ValueError(f"unsupported criterion {c!r}")

    def search(self, criteria: list[Any], charset: str | None = None) -> list[int]:
        self._maybe_fail("search")
        crit = list(criteria) if isinstance(criteria, (list, tuple)) else [criteria]
        self.searches.append(crit)
        self.search_charsets.append(charset)
        if charset is not None and self.reject_charset:
            raise IMAPClientError("SEARCH failed: NO [BADCHARSET (US-ASCII)]")
        out = []
        for uid, msg in sorted(self._box().items()):
            ok, i = True, 0
            while i < len(crit):
                m, i = self._match(msg, crit, i)
                ok &= m
            if ok:
                out.append(uid)
        return out

    def _envelope(self, msg: FakeMsg) -> Envelope:
        hdrs = email.message_from_bytes(self._header_text(msg.raw), policy=email.policy.compat32)
        name, addr = parseaddr(str(hdrs.get("From", "") or ""))
        mbox, _, host = addr.partition("@")
        frm = (Address(name.encode() if name else None, None, mbox.encode() or None,
                       host.encode() or None),) if addr else None
        try:
            date = parsedate_to_datetime(str(hdrs.get("Date")))
        except Exception:
            date = None
        mid = hdrs.get("Message-ID")
        return Envelope(date, str(hdrs.get("Subject", "") or "").encode(), frm, frm, frm, None,
                        None, None, b"", str(mid).strip().encode() if mid else None)

    def fetch(self, uids: list[int], items: list[bytes]) -> dict[int, dict[bytes, Any]]:
        self._maybe_fail("fetch")
        uids = list(uids)
        self.fetches.append((uids, list(items)))
        box = self._box()
        out: dict[int, dict[bytes, Any]] = {}
        for uid in uids:
            msg = box.get(uid)
            if msg is None:
                continue
            d: dict[bytes, Any] = {b"SEQ": uid}
            for it in items:
                if it == b"RFC822.SIZE":
                    d[it] = len(msg.raw)
                elif it == b"FLAGS":
                    d[it] = tuple(f.encode() for f in sorted(msg.flags))
                elif it == b"INTERNALDATE":
                    d[it] = msg.internaldate
                elif it == b"BODY.PEEK[HEADER]":
                    d[b"BODY[HEADER]"] = self._header_text(msg.raw)
                elif it == b"ENVELOPE":
                    d[it] = self._envelope(msg)
                elif it.startswith(b"BODY.PEEK[HEADER.FIELDS (") and it != \
                        b"BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)]":
                    names = it[len(b"BODY.PEEK[HEADER.FIELDS ("):-2].decode().split()
                    hdrs = email.message_from_bytes(self._header_text(msg.raw),
                                                    policy=email.policy.compat32)
                    lines = [f"{n.title()}: {hdrs.get(n)}" for n in names if hdrs.get(n) is not None]
                    d[it.replace(b".PEEK", b"")] = ("\r\n".join(lines) + "\r\n\r\n").encode()
                elif it == b"BODY.PEEK[]":
                    d[b"BODY[]"] = msg.raw
                elif it.startswith(b"BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)]"):
                    hdrs = email.message_from_bytes(self._header_text(msg.raw),
                                                    policy=email.policy.compat32)
                    val = hdrs.get("Message-ID")
                    d[b"BODY[HEADER.FIELDS (MESSAGE-ID)]"] = (
                        f"Message-ID: {val}\r\n\r\n".encode() if val else b"\r\n")
                elif it in (b"BODY[]", b"RFC822"):
                    # Non-PEEK body fetch sets \Seen: a write.
                    self._write("fetch_sets_seen", uid)
                    d[it] = msg.raw
                else:
                    raise ValueError(f"unsupported fetch item {it!r}")
            out[uid] = d
        return out

    # --- writes -----------------------------------------------------------
    def _write(self, *entry: Any) -> None:
        if self.readonly:
            raise IMAPClientReadOnlyError(f"{entry[0]} on read-only folder")
        self.writes.append(entry)

    def move(self, uids: list[int], folder: str) -> None:
        self._maybe_fail("move")
        self._write("move", list(uids), folder)
        box = self._box()
        for uid in uids:
            msg = box.pop(uid)
            self.add(folder, msg.raw, flags=tuple(msg.flags), internaldate=msg.internaldate)

    def copy(self, uids: list[int], folder: str) -> bytes:
        self._write("copy", list(uids), folder)
        box = self._box()
        for uid in uids:
            msg = box[uid]
            self.add(folder, msg.raw, flags=tuple(msg.flags), internaldate=msg.internaldate)
        return b"OK"

    def add_flags(self, uids: list[int], flags: list[Any], silent: bool = False) -> None:
        self._write("add_flags", list(uids), list(flags))
        for uid in uids:
            self._box()[uid].flags.update(f.decode() if isinstance(f, bytes) else f for f in flags)

    def remove_flags(self, uids: list[int], flags: list[Any], silent: bool = False) -> None:
        self._write("remove_flags", list(uids), list(flags))
        for uid in uids:
            self._box()[uid].flags.difference_update(
                f.decode() if isinstance(f, bytes) else f for f in flags)

    def set_flags(self, uids: list[int], flags: list[Any]) -> None:
        self._write("set_flags", list(uids), list(flags))

    def uid_expunge(self, uids: list[int]) -> None:
        self._write("uid_expunge", list(uids))
        box = self._box()
        for uid in uids:
            if uid in box and "\\Deleted" in box[uid].flags:
                del box[uid]

    def expunge(self, messages: Any = None) -> None:
        self._write("expunge", messages)

    def delete_messages(self, uids: list[int]) -> None:
        self._write("delete_messages", list(uids))

    def create_folder(self, folder: str) -> None:
        self.writes.append(("create_folder", folder))
        self.folders.setdefault(folder, {})
        self.next_uid.setdefault(folder, 1)

    def subscribe_folder(self, folder: str) -> None:
        self.writes.append(("subscribe_folder", folder))

    def append(self, folder: str, msg: bytes, flags: Any = (), msg_time: Any = None) -> None:
        self.writes.append(("append", folder))


class FakeIMAPFactory:
    """Stands in for the IMAPClient class (services.test_connection)."""

    def __init__(self, client: FakeIMAP | None = None, *, connect_error: Exception | None = None):
        self.client = client or FakeIMAP()
        self.connect_error = connect_error
        self.calls: list[dict[str, Any]] = []

    def __call__(self, host: str, port: int = 993, ssl: bool = True, ssl_context: Any = None,
                 timeout: Any = None) -> FakeIMAP:
        self.calls.append({"host": host, "port": port, "ssl": ssl, "timeout": timeout})
        if self.connect_error is not None:
            raise self.connect_error
        return self.client


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    account TEXT NOT NULL, message_id TEXT NOT NULL, first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL, current_folder TEXT NOT NULL, moved_to_junk_at INTEGER,
    our_score REAL, our_action TEXT, learned_as TEXT, learned_at INTEGER,
    pending_learn TEXT, pending_learn_at INTEGER, sender TEXT, subject TEXT,
    received_at INTEGER, rspamd_score REAL, symbols TEXT, rspamd_action TEXT,
    sender_ip TEXT, envelope_from TEXT, provider_score REAL, provider_flag INTEGER,
    user_verdict TEXT, verdict_at INTEGER, verdict_by TEXT, rule_hit TEXT, size INTEGER,
    scanned_at INTEGER, origin TEXT, score_version INTEGER,
    PRIMARY KEY (account, message_id)
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, account TEXT NOT NULL, ts INTEGER NOT NULL,
    message_id TEXT, event TEXT NOT NULL, detail TEXT
);
CREATE TABLE IF NOT EXISTS pending_move (
    account TEXT NOT NULL, uidvalidity INTEGER NOT NULL, uid INTEGER NOT NULL,
    message_id TEXT NOT NULL, flag_at INTEGER NOT NULL, folder TEXT,
    PRIMARY KEY (account, uidvalidity, uid)
);
CREATE TABLE IF NOT EXISTS stats_daily (
    account TEXT, day TEXT, metric TEXT, n INTEGER, PRIMARY KEY(account, day, metric)
);
CREATE TABLE IF NOT EXISTS account_status (
    account TEXT PRIMARY KEY, updated_at INTEGER NOT NULL, state TEXT NOT NULL, detail TEXT,
    connected_since INTEGER, last_loop_at INTEGER, last_scan_at INTEGER, last_error TEXT,
    last_error_at INTEGER, error_count INTEGER NOT NULL DEFAULT 0, capabilities TEXT,
    move_method TEXT, idle_supported INTEGER, folders TEXT, folder_map TEXT,
    junk_exists INTEGER, mode TEXT, threshold REAL, bookmark_lag INTEGER, pending_moves INTEGER
);
CREATE TABLE IF NOT EXISTS train_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, account TEXT NOT NULL, folder TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('spam','ham','calibrate')), max_messages INTEGER NOT NULL,
    min_age_days INTEGER NOT NULL DEFAULT 0, seen_only INTEGER NOT NULL DEFAULT 0,
    provider_filter TEXT NOT NULL DEFAULT 'any', status TEXT NOT NULL DEFAULT 'queued',
    total INTEGER NOT NULL DEFAULT 0, processed INTEGER NOT NULL DEFAULT 0,
    learned INTEGER NOT NULL DEFAULT 0, skipped INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0, error TEXT, created_by TEXT,
    created_at INTEGER NOT NULL, started_at INTEGER, finished_at INTEGER
);
CREATE TABLE IF NOT EXISTS calibration_results (
    job_id INTEGER, account TEXT, folder TEXT, message_id TEXT, final_score REAL,
    rspamd_score REAL, symbols TEXT, sender TEXT, subject TEXT, received_at INTEGER,
    seen INTEGER, provider_flag INTEGER, provider_score REAL,
    PRIMARY KEY(job_id, account, folder, message_id)
);
"""


@dataclass
class ScanResult:
    score: float
    action: str | None
    symbols: list[dict]


def _make_db_class(db_path: Path) -> type:
    class FakeDb:
        def __init__(self, account: str) -> None:
            self.account = account
            self.conn = sqlite3.connect(db_path, timeout=30, isolation_level=None)
            self.conn.row_factory = sqlite3.Row
            self.closed = False

        def close(self) -> None:
            self.closed = True
            self.conn.close()

        @contextmanager
        def tx(self) -> Iterator[sqlite3.Connection]:
            self.conn.execute("BEGIN")
            try:
                yield self.conn
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise

        def log_event(self, event: str, message_id: str | None = None,
                      detail: str | None = None) -> None:
            self.conn.execute(
                "INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                (self.account, int(time.time()), message_id, event, detail))

    return FakeDb


class FakeEngine:
    """Duck-typed replacement for the `filter` module."""

    def __init__(self, tmp_path: Path, *, accounts: list[Any] | None = None,
                 imap: FakeIMAP | dict[str, FakeIMAP] | None = None,
                 learn_outcome: str | Callable[..., str] = "learned",
                 scan: Callable[[bytes, Any, dict], Any] | None = None,
                 secret: str | None = "mail-secret-pw",
                 connect_error: Exception | None = None) -> None:
        self.STATE_DIR = Path(tmp_path)
        self.STATE_DIR.mkdir(parents=True, exist_ok=True)
        self.DB_PATH = self.STATE_DIR / "spamfilter.db"
        self.CONFIG_PATH = self.STATE_DIR / "accounts.yml"
        self.MAX_FETCH_BYTES = 5 * 1024 * 1024
        self.RSPAMD_PASSWORD = ""
        self.RSPAMD_LEARN_URL = "http://rspamd.test:11334"
        self.RSPAMD_SCAN_URL = "http://rspamd.test:11333/checkv2"
        self.SHUTDOWN = threading.Event()
        self.accounts = accounts if accounts is not None else [make_account()]
        self.imap = imap if imap is not None else FakeIMAP()
        self.learn_outcome = learn_outcome
        self.scan = scan
        self.secret = secret
        self.connect_error = connect_error
        self.config_error: Exception | None = None
        self.learn_calls: list[dict[str, Any]] = []
        self.rspamd_learn_calls: list[tuple[str, str]] = []
        self.scan_calls: list[dict[str, Any]] = []
        self.move_calls: list[dict[str, Any]] = []
        self.connects = 0
        self.connect_kwargs: list[dict[str, Any]] = []
        self.reloads = 0
        self.Db = _make_db_class(self.DB_PATH)
        self.init_db()

    # --- schema / config --------------------------------------------------
    def init_db(self) -> None:
        with sqlite3.connect(self.DB_PATH) as conn:
            conn.executescript("PRAGMA journal_mode=WAL;")
            conn.executescript(SCHEMA)

    def load_account_configs(self, path: Path) -> list[Any]:
        if self.config_error is not None:
            raise self.config_error
        return list(self.accounts)

    def read_secret(self, acc: Any) -> str:
        if self.secret is None:
            raise FileNotFoundError("secret file missing")
        return self.secret

    def bayes_identity(self, acc: Any) -> str:
        return acc.bayes_user or acc.user

    def request_reload(self) -> None:
        self.reloads += 1
        (self.STATE_DIR / "reload_requested").touch()

    # --- IMAP primitives --------------------------------------------------
    def client_for(self, acc: Any) -> FakeIMAP:
        return self.imap[acc.name] if isinstance(self.imap, dict) else self.imap

    def connect(self, acc: Any, password: str | None = None, **kw: Any) -> FakeIMAP:
        self.connects += 1
        self.connect_kwargs.append(dict(kw))
        if self.connect_error is not None:
            raise self.connect_error
        client = self.client_for(acc)
        client.login(acc.user, password if password is not None else self.read_secret(acc))
        return client

    @staticmethod
    def move_method_for(capabilities: Any) -> str:
        caps = {c.decode() if isinstance(c, bytes) else str(c) for c in capabilities}
        caps = {c.upper() for c in caps}
        return "MOVE" if "MOVE" in caps else "UIDPLUS" if "UIDPLUS" in caps else "none"

    def imap_move(self, client: FakeIMAP, uids: list[int], dest: str, *, capabilities: Any) -> None:
        self.move_calls.append({"uids": list(uids), "dest": dest,
                                "method": self.move_method_for(capabilities)})
        client.move(uids, dest)

    def find_uids_by_message_id(self, client: FakeIMAP, message_id: str) -> list[int]:
        cands = client.search(["HEADER", "Message-ID", message_id])
        if not cands:
            return []
        data = client.fetch(cands, [b"BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)]"])
        out = []
        for uid in cands:
            hdr = data.get(uid, {}).get(b"BODY[HEADER.FIELDS (MESSAGE-ID)]", b"")
            mid, _s, _f = self.parse_envelope(hdr)
            if mid == message_id:
                out.append(uid)
        return out

    @staticmethod
    def parse_envelope(raw: bytes) -> tuple[str | None, str, str]:
        try:
            msg = email.message_from_bytes(raw, policy=email.policy.compat32)
            msgid = (msg.get("Message-ID", "") or "").strip()
            m = re.search(r"<([^>]+)>", msgid)
            if m:
                msgid = m.group(1)
            return (msgid or None, str(msg.get("Subject", "") or "")[:500],
                    parseaddr(str(msg.get("From", "") or ""))[1][:200])
        except Exception:
            return (None, "", "")

    # --- rspamd -----------------------------------------------------------
    def learn_message(self, db: Any, acc: Any, raw: bytes, kind: str, message_id: str, *,
                      actor: str = "", reason: str = "", bypass_rate: bool = False,
                      bypass_cooldown: bool = False) -> str:
        self.learn_calls.append({"account": acc.name, "kind": kind, "message_id": message_id,
                                 "actor": actor, "reason": reason, "bypass_rate": bypass_rate,
                                 "bypass_cooldown": bypass_cooldown, "raw": raw})
        outcome = self.learn_outcome(message_id, kind) if callable(self.learn_outcome) \
            else self.learn_outcome
        if outcome in ("learned", "already"):
            now = int(time.time())
            with db.tx():
                db.conn.execute(
                    """INSERT INTO messages(account, message_id, first_seen, last_seen,
                       current_folder, learned_as, learned_at) VALUES(?,?,?,?,?,?,?)
                       ON CONFLICT(account, message_id) DO UPDATE SET
                       learned_as=excluded.learned_as, learned_at=excluded.learned_at""",
                    (acc.name, message_id, now, now, "?", kind, now))
                db.log_event(f"learn_{kind}", message_id, detail=reason)
            if outcome == "learned":
                self.bump_stat(db.conn, acc.name, f"learned_{kind}")
        return outcome

    def rspamd_learn(self, raw: bytes, kind: str, identity: str) -> str:
        self.rspamd_learn_calls.append((kind, identity))
        return self.learn_outcome if isinstance(self.learn_outcome, str) else "learned"

    def rspamd_scan(self, raw: bytes, acc: Any, ctx: dict) -> Any:
        self.scan_calls.append({"account": acc.name, "ctx": ctx})
        if self.scan is not None:
            return self.scan(raw, acc, ctx)
        return ScanResult(score=1.5, action="no action",
                          symbols=[{"n": "BAYES_HAM", "s": -1.0, "o": ["90%"]}])

    # --- stats ------------------------------------------------------------
    @staticmethod
    def bump_stat(conn: sqlite3.Connection, account: str, metric: str, n: int = 1) -> None:
        day = dt.date.today().isoformat()
        conn.execute(
            "INSERT INTO stats_daily(account, day, metric, n) VALUES(?,?,?,?) "
            "ON CONFLICT(account, day, metric) DO UPDATE SET n = n + excluded.n",
            (account, day, metric, n))

    # --- test helpers -----------------------------------------------------
    def db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    def stat(self, account: str, metric: str) -> int:
        with self.db() as conn:
            row = conn.execute("SELECT SUM(n) FROM stats_daily WHERE account=? AND metric=?",
                               (account, metric)).fetchone()
        return int(row[0] or 0)


# ---------------------------------------------------------------------------
# Real-engine integration (services 2.1 against the REAL filter.py)
# ---------------------------------------------------------------------------
#
# EngineMailbox is the ENGINE's RFC-accurate FakeIMAP (tests/fakes_engine.py:
# UID-set semantics, MOVE vs UIDPLUS, EXAMINE refuses writes, \Deleted +
# UID EXPUNGE) plus what services.find_mail / folder_sizes need on top:
# FETCH ENVELOPE, SEARCH SINCE/FROM/SUBJECT/OR/NOT (decoded, substring,
# case-insensitive like a server) with CHARSET, and STATUS UNSEEN.
# `session()` returns a second connection to the same mailbox (own selected
# folder, shared folders and one combined write log) - what services open
# next to the engine's IDLE connection.

import fakes_engine as _fe  # noqa: E402  (no filter import at module level)

_SERVICES_KEYS = frozenset({"SINCE", "FROM", "SUBJECT", "OR", "NOT"})


class EngineMailbox(_fe.FakeIMAP):
    _header_text = staticmethod(FakeIMAP._header_text)
    _decoded = staticmethod(FakeIMAP._decoded)
    _match = FakeIMAP._match

    def __init__(self, *args: Any, **kw: Any) -> None:
        super().__init__(*args, **kw)
        self.search_charsets: list[str | None] = []

    def session(self) -> "EngineMailbox":
        other = EngineMailbox(capabilities=self.caps, delimiter=self.delimiter, folders=())
        other.folders = self.folders
        other.writes = self.writes
        return other

    def search(self, criteria: Any = "ALL", charset: str | None = None) -> list[int]:
        crit = [criteria] if isinstance(criteria, str) else list(criteria)
        if not any(isinstance(c, str) and c.upper() in _SERVICES_KEYS for c in crit):
            return super().search(criteria, charset)
        self._call("search", tuple(str(c) for c in crit))
        self.search_charsets.append(charset)
        out = []
        for uid, msg in sorted(self._box().msgs.items()):
            ok, i = True, 0
            while i < len(crit):
                m, i = self._match(msg, crit, i)
                ok &= m
            if ok:
                out.append(uid)
        return out

    def fetch(self, messages: Any, data: list[Any]) -> dict[int, dict[bytes, Any]]:
        items = [d.encode() if isinstance(d, str) else bytes(d) for d in data]
        rest = [it for it in items if it.upper() != b"ENVELOPE"]
        out = super().fetch(messages, rest) if rest else {}
        if len(rest) != len(items):
            if not rest:
                self._call("fetch", tuple(sorted({int(u) for u in messages})), (b"ENVELOPE",))
            box = self._box()
            for uid in sorted({int(u) for u in messages}):
                m = box.msgs.get(uid)
                if m is None:
                    continue
                out.setdefault(uid, {b"SEQ": uid})[b"ENVELOPE"] = FakeIMAP._envelope(self, m)
        return out

    def folder_status(self, folder: str, what: list[bytes] | None = None) -> dict[bytes, int]:
        st = super().folder_status(folder, what)
        st[b"UNSEEN"] = sum(1 for m in self.folders[folder].msgs.values() if "\\Seen" not in m.flags)
        return st
