"""Fakes for the ENGINE tests (filter.py).

FakeIMAP models the IMAPClient surface the engine uses with RFC-accurate
semantics where they matter for correctness:

  * UID sets: `n:*` always includes the highest UID even when it is below
    n (RFC 3501 6.4.8 / 9 "seq-range": `*` is the largest UID in use and
    a range is unordered), so `UID 5:*` on a mailbox whose top UID is 3
    returns [3].
  * MOVE (RFC 6851) and UIDPLUS (RFC 4315) are separate capabilities:
    move() raises CapabilityError without MOVE, uid_expunge() without
    UIDPLUS. COPY answers `[COPYUID uv src dst]` when UIDPLUS is offered.
  * \\Deleted + UID EXPUNGE removes only the listed UIDs that carry
    \\Deleted; plain EXPUNGE removes every \\Deleted message (and is
    recorded so tests can assert it never happens).
  * Read-only SELECT (EXAMINE) rejects every mutating command; a FETCH of
    BODY[] (non-PEEK) sets \\Seen like a real server.
  * LIST returns flags, the "." delimiter (Gigahost/Scannet) and names.

Every mutating call is appended to `writes`; every command to `calls`.
Kept separate from tests/fakes.py (built concurrently); the integrator may
merge it.
"""

from __future__ import annotations

import datetime as dt
import email
import email.policy
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "filter"))

from imapclient.exceptions import (  # noqa: E402
    CapabilityError,
    IMAPClientAbortError,
    IMAPClientError,
    IMAPClientReadOnlyError,
    LoginError,
)

GIGAHOST_CAPS = (b"IMAP4REV1", b"LITERAL+", b"SASL-IR", b"LOGIN-REFERRALS", b"ID", b"ENABLE",
                 b"IDLE", b"SORT", b"THREAD=REFERENCES", b"MULTIAPPEND", b"UNSELECT",
                 b"CHILDREN", b"NAMESPACE", b"UIDPLUS", b"LIST-EXTENDED", b"I18NLEVEL=1",
                 b"CONDSTORE", b"QRESYNC", b"ESEARCH", b"SEARCHRES", b"WITHIN",
                 b"CONTEXT=SEARCH", b"LIST-STATUS", b"BINARY")  # no MOVE, no SPECIAL-USE
SCANNET_CAPS = (b"IMAP4REV1", b"IDLE", b"MOVE", b"SPECIAL-USE", b"UIDPLUS", b"NAMESPACE",
                b"CHILDREN", b"LIST-EXTENDED", b"ESEARCH")
BARE_CAPS = (b"IMAP4REV1",)

MUTATING = frozenset({"move", "copy", "add_flags", "remove_flags", "set_flags", "uid_expunge",
                      "expunge", "create_folder", "subscribe_folder", "delete_folder",
                      "append", "delete_messages", "rename_folder"})


def make_message(msgid: str | None, *, subject: str = "Hej", sender: str = "a@example.org",
                 body: str = "Hello there.\r\n", extra_headers: str = "",
                 return_path: str | None = None) -> bytes:
    lines = []
    if return_path is not None:
        lines.append(f"Return-Path: <{return_path}>")
    lines.append("Received: from mx1.example.net (mx1.example.net [192.0.2.10]) by mail.example.net")
    lines.append(f"From: Sender <{sender}>")
    lines.append("To: user@example-a.dk")
    lines.append(f"Subject: {subject}")
    if msgid is not None:
        lines.append(f"Message-ID: <{msgid}>")
    lines.append("Date: Tue, 20 Oct 2026 10:00:00 +0200")
    if extra_headers:
        lines.append(extra_headers.rstrip("\r\n"))
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode()


@dataclass
class FakeMsg:
    raw: bytes
    flags: set[str] = field(default_factory=set)
    internaldate: dt.datetime = field(
        default_factory=lambda: (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)).replace(microsecond=0))
    size: int | None = None  # override RFC822.SIZE (oversize tests)


@dataclass
class FakeFolder:
    name: str
    uidvalidity: int
    flags: tuple[str, ...] = ("\\HasNoChildren",)
    uidnext: int = 1
    msgs: dict[int, FakeMsg] = field(default_factory=dict)
    subscribed: bool = True


def _header_fields(raw: bytes, names: list[str]) -> bytes:
    """BODY[HEADER.FIELDS (...)] of a message: the matching header lines
    (with continuations) plus the terminating blank line."""
    head = raw.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0]
    want = {n.upper() for n in names}
    out: list[bytes] = []
    keep = False
    for line in re.split(rb"\r?\n", head):
        if line[:1] in (b" ", b"\t"):
            if keep:
                out.append(line)
            continue
        name = line.split(b":", 1)[0].strip().decode("ascii", "replace").upper()
        keep = name in want
        if keep:
            out.append(line)
    return b"\r\n".join(out) + b"\r\n\r\n"


def _header_value(raw: bytes, name: str) -> str:
    msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    return str(msg.get(name, "") or "")


class FakeIMAP:
    """IMAPClient stand-in. Construct, `add_folder`/`add` mail, hand it to
    the engine. `fail_on[name] = exc | callable` injects failures (popped
    after one use unless `fail_always` contains the name)."""

    def __init__(self, *, capabilities: tuple[bytes, ...] = GIGAHOST_CAPS, delimiter: str = ".",
                 folders: tuple[str, ...] = ("INBOX", "Junk", "Trash"),
                 special_use: dict[str, str] | None = None) -> None:
        self.caps = tuple(capabilities)
        self.delimiter = delimiter
        self.folders: dict[str, FakeFolder] = {}
        self._uv_seq = 1000
        for name in folders:
            self.add_folder(name)
        for name, flag in (special_use or {}).items():
            f = self.folders[name]
            f.flags = tuple(f.flags) + (flag,)
        self.selected: str | None = None
        self.readonly = False
        self.calls: list[tuple] = []
        self.writes: list[tuple] = []
        self.fail_on: dict[str, Any] = {}
        self.fail_always: set[str] = set()
        self.logged_in = False
        self.idle_responses: list[list] = []
        self.idling = False
        self.on_idle_check: Callable[["FakeIMAP"], None] | None = None

    # ----- setup helpers ------------------------------------------------

    def add_folder(self, name: str, *, flags: tuple[str, ...] = ("\\HasNoChildren",)) -> FakeFolder:
        self._uv_seq += 1
        f = FakeFolder(name=name, uidvalidity=self._uv_seq, flags=flags)
        self.folders[name] = f
        return f

    def add(self, folder: str, raw: bytes, *, flags: tuple[str, ...] = (),
            size: int | None = None, internaldate: dt.datetime | None = None) -> int:
        f = self.folders[folder]
        uid = f.uidnext
        f.uidnext += 1
        msg = FakeMsg(raw=raw, flags=set(flags), size=size)
        if internaldate is not None:
            msg.internaldate = internaldate
        f.msgs[uid] = msg
        return uid

    def uids(self, folder: str) -> list[int]:
        return sorted(self.folders[folder].msgs)

    def msgids(self, folder: str) -> list[str]:
        out = []
        for uid in self.uids(folder):
            m = re.search(r"<([^>]+)>", _header_value(self.folders[folder].msgs[uid].raw, "Message-ID"))
            out.append(m.group(1) if m else "")
        return out

    def flags_of(self, folder: str, uid: int) -> set[str]:
        return set(self.folders[folder].msgs[uid].flags)

    def write_names(self) -> list[str]:
        return [w[0] for w in self.writes]

    # ----- plumbing -----------------------------------------------------

    def _call(self, name: str, *args: Any) -> None:
        self.calls.append((name, *args))
        exc = self.fail_on.get(name)
        if exc is not None:
            if name not in self.fail_always:
                del self.fail_on[name]
            if callable(exc) and not isinstance(exc, BaseException):
                exc = exc(*args)
                if exc is None:
                    return
            raise exc
        if name in MUTATING:
            if name not in ("create_folder", "subscribe_folder", "append") and self.readonly:
                raise IMAPClientReadOnlyError(f"{name} on read-only folder")
            self.writes.append((name, self.selected, *args))

    def _box(self) -> FakeFolder:
        if self.selected is None:
            raise IMAPClientError("No mailbox selected")
        return self.folders[self.selected]

    def _uid_set(self, spec: str) -> set[int]:
        """RFC 3501 sequence-set over UIDs of the selected folder."""
        box = self._box()
        existing = sorted(box.msgs)
        top = existing[-1] if existing else None
        out: set[int] = set()
        for part in str(spec).split(","):
            if ":" in part:
                a, b = part.split(":", 1)
                if "*" in (a, b) and top is None:
                    continue
                lo_v = top if a == "*" else int(a)
                hi_v = top if b == "*" else int(b)
                lo, hi = sorted((lo_v, hi_v))
                out.update(u for u in existing if lo <= u <= hi)
            elif part == "*":
                if top is not None:
                    out.add(top)
            elif part:
                if int(part) in box.msgs:
                    out.add(int(part))
        return out

    # ----- session ------------------------------------------------------

    def login(self, user: str, password: str) -> bytes:
        self._call("login", user)
        self.logged_in = True
        return b"Logged in"

    def logout(self) -> None:
        self.calls.append(("logout",))
        self.logged_in = False

    def shutdown(self) -> None:
        self.calls.append(("shutdown",))

    def capabilities(self) -> tuple[bytes, ...]:
        self._call("capabilities")
        return self.caps

    def has_capability(self, cap: str) -> bool:
        return cap.upper().encode() in self.caps

    # ----- folders ------------------------------------------------------

    def list_folders(self, directory: str = "", pattern: str = "*") -> list[tuple]:
        self._call("list_folders")
        return [(tuple(fl.encode() for fl in f.flags), self.delimiter.encode(), f.name)
                for f in self.folders.values()]

    def folder_status(self, folder: str, what: list[bytes] | None = None) -> dict[bytes, int]:
        self._call("folder_status", folder)
        if folder not in self.folders:
            raise IMAPClientError(f"STATUS {folder}: no such mailbox")
        f = self.folders[folder]
        return {b"MESSAGES": len(f.msgs), b"UIDNEXT": f.uidnext, b"UIDVALIDITY": f.uidvalidity}

    def select_folder(self, folder: str, readonly: bool = False) -> dict[bytes, Any]:
        self._call("select_folder", folder, readonly)
        if folder not in self.folders:
            raise IMAPClientError(f"SELECT {folder}: Mailbox doesn't exist")
        self.selected = folder
        self.readonly = readonly
        f = self.folders[folder]
        return {b"UIDVALIDITY": f.uidvalidity, b"EXISTS": len(f.msgs), b"UIDNEXT": f.uidnext,
                b"READ-ONLY": [b""] if readonly else None}

    def create_folder(self, folder: str) -> None:
        self._call("create_folder", folder)
        if folder in self.folders:
            raise IMAPClientError(f"CREATE {folder}: Mailbox already exists")
        self.add_folder(folder)
        self.folders[folder].subscribed = False

    def subscribe_folder(self, folder: str) -> None:
        self._call("subscribe_folder", folder)
        self.folders[folder].subscribed = True

    # ----- search / fetch -----------------------------------------------

    def search(self, criteria: Any = "ALL", charset: str | None = None) -> list[int]:
        crit = [criteria] if isinstance(criteria, str) else list(criteria)
        self._call("search", tuple(crit))
        box = self._box()
        cands = set(box.msgs)
        i = 0
        while i < len(crit):
            tok = str(crit[i]).upper()
            if tok == "ALL":
                pass
            elif tok == "UNSEEN":
                cands = {u for u in cands if "\\Seen" not in box.msgs[u].flags}
            elif tok == "SEEN":
                cands = {u for u in cands if "\\Seen" in box.msgs[u].flags}
            elif tok == "DELETED":
                cands = {u for u in cands if "\\Deleted" in box.msgs[u].flags}
            elif tok == "UNDELETED":
                cands = {u for u in cands if "\\Deleted" not in box.msgs[u].flags}
            elif tok == "UID":
                i += 1
                cands &= self._uid_set(str(crit[i]))
            elif tok == "HEADER":
                name, value = str(crit[i + 1]), str(crit[i + 2])
                i += 2
                # IMAP SEARCH HEADER is a case-insensitive SUBSTRING match.
                cands = {u for u in cands
                         if value.lower() in _header_value(box.msgs[u].raw, name).lower()}
            elif tok == "BEFORE":
                i += 1
                day = dt.datetime.strptime(str(crit[i]), "%d-%b-%Y").date()
                cands = {u for u in cands if box.msgs[u].internaldate.date() < day}
            else:
                raise IMAPClientError(f"SEARCH: unsupported criterion {tok}")
            i += 1
        return sorted(cands)

    def fetch(self, messages: Any, data: list[Any]) -> dict[int, dict[bytes, Any]]:
        items = [d.encode() if isinstance(d, str) else bytes(d) for d in data]
        if isinstance(messages, (int, str)):
            messages = [messages]
        uids = sorted({int(u) for u in messages})
        self._call("fetch", tuple(uids), tuple(items))
        box = self._box()
        out: dict[int, dict[bytes, Any]] = {}
        for uid in uids:
            m = box.msgs.get(uid)
            if m is None:
                continue
            d: dict[bytes, Any] = {b"SEQ": uid}
            for it in items:
                up = it.upper()
                if up == b"FLAGS":
                    d[b"FLAGS"] = tuple(f.encode() for f in sorted(m.flags))
                elif up == b"RFC822.SIZE":
                    d[b"RFC822.SIZE"] = m.size if m.size is not None else len(m.raw)
                elif up == b"INTERNALDATE":
                    d[b"INTERNALDATE"] = m.internaldate
                elif up in (b"BODY.PEEK[]", b"BODY[]", b"RFC822"):
                    if up != b"BODY.PEEK[]":
                        if self.readonly is False:
                            m.flags.add("\\Seen")
                        self.writes.append(("implicit_seen", self.selected, uid))
                    d[b"BODY[]"] = m.raw
                elif up.startswith(b"BODY.PEEK[HEADER.FIELDS") or up.startswith(b"BODY[HEADER.FIELDS"):
                    names = re.search(rb"\(([^)]*)\)", it).group(1).decode().split()
                    key = b"BODY[HEADER.FIELDS (" + b" ".join(n.upper().encode() for n in names) + b")]"
                    d[key] = _header_fields(m.raw, names)
                elif up in (b"BODY.PEEK[HEADER]", b"BODY[HEADER]"):
                    d[b"BODY[HEADER]"] = m.raw.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"
                else:
                    raise IMAPClientError(f"FETCH: unsupported item {it!r}")
            out[uid] = d
        return out

    # ----- flags / moves ------------------------------------------------

    @staticmethod
    def _flag_strs(flags: Any) -> list[str]:
        return [f.decode() if isinstance(f, (bytes, bytearray)) else str(f) for f in flags]

    def add_flags(self, messages: Any, flags: Any, silent: bool = False) -> dict:
        uids = sorted({int(u) for u in messages})
        fl = self._flag_strs(flags)
        self._call("add_flags", tuple(uids), tuple(fl))
        box = self._box()
        for u in uids:
            if u in box.msgs:
                box.msgs[u].flags.update(fl)
        return {}

    def remove_flags(self, messages: Any, flags: Any, silent: bool = False) -> dict:
        uids = sorted({int(u) for u in messages})
        fl = self._flag_strs(flags)
        self._call("remove_flags", tuple(uids), tuple(fl))
        box = self._box()
        for u in uids:
            if u in box.msgs:
                box.msgs[u].flags.difference_update(fl)
        return {}

    def _transfer(self, uids: list[int], folder: str, *, remove: bool) -> tuple[list[int], list[int]]:
        if folder not in self.folders:
            raise IMAPClientError(f"[TRYCREATE] Mailbox doesn't exist: {folder}")
        src, dst = self._box(), self.folders[folder]
        done_src, done_dst = [], []
        for u in uids:
            m = src.msgs.get(u)
            if m is None:
                continue  # UID COPY/MOVE silently ignores non-existent UIDs
            new_uid = dst.uidnext
            dst.uidnext += 1
            dst.msgs[new_uid] = FakeMsg(raw=m.raw, flags=set(m.flags) - {"\\Recent"},
                                        internaldate=m.internaldate, size=m.size)
            done_src.append(u)
            done_dst.append(new_uid)
            if remove:
                del src.msgs[u]
        return done_src, done_dst

    def move(self, messages: Any, folder: str) -> bytes:
        uids = sorted({int(u) for u in messages})
        if b"MOVE" not in self.caps:
            self.calls.append(("move", tuple(uids), folder))
            raise CapabilityError("Server does not support MOVE capability")
        self._call("move", tuple(uids), folder)
        self._transfer(uids, folder, remove=True)
        return b"Move completed."

    def copy(self, messages: Any, folder: str) -> bytes:
        uids = sorted({int(u) for u in messages})
        self._call("copy", tuple(uids), folder)
        src_uids, dst_uids = self._transfer(uids, folder, remove=False)
        if b"UIDPLUS" in self.caps and src_uids:
            uv = self.folders[folder].uidvalidity
            s = ",".join(map(str, src_uids)).encode()
            d = ",".join(map(str, dst_uids)).encode()
            return b"[COPYUID " + str(uv).encode() + b" " + s + b" " + d + b"] Copy completed."
        return b"Copy completed."

    def uid_expunge(self, messages: Any) -> bytes:
        uids = sorted({int(u) for u in messages})
        if b"UIDPLUS" not in self.caps:
            self.calls.append(("uid_expunge", tuple(uids)))
            raise CapabilityError("Server does not support UIDPLUS capability")
        self._call("uid_expunge", tuple(uids))
        box = self._box()
        for u in uids:
            if u in box.msgs and "\\Deleted" in box.msgs[u].flags:
                del box.msgs[u]
        return b"Expunge completed."

    def expunge(self, messages: Any = None) -> Any:
        self._call("expunge", messages)
        box = self._box()
        if messages:
            return self.uid_expunge(messages)
        for u in [u for u, m in box.msgs.items() if "\\Deleted" in m.flags]:
            del box.msgs[u]
        return (b"Expunge completed.", [])

    def append(self, folder: str, msg: bytes, flags: Any = (), msg_time: Any = None) -> bytes:
        self._call("append", folder)
        self.add(folder, msg, flags=tuple(self._flag_strs(flags)))
        return b"OK"

    def delete_messages(self, messages: Any, silent: bool = False) -> dict:
        self._call("delete_messages", tuple(messages))
        return self.add_flags(messages, [b"\\Deleted"])

    # ----- IDLE ---------------------------------------------------------

    def idle(self) -> None:
        self._call("idle")
        self.idling = True

    def idle_check(self, timeout: float | None = None) -> list:
        self._call("idle_check", timeout)
        if self.on_idle_check is not None:
            self.on_idle_check(self)
        if self.idle_responses:
            return self.idle_responses.pop(0)
        return []

    def idle_done(self) -> tuple:
        self._call("idle_done")
        self.idling = False
        return (b"Idle terminated", [])

    def noop(self) -> tuple:
        self._call("noop")
        return (b"OK", [])


class FakeRspamd:
    """Replaces requests.post/get in the engine. Scores come from `scores`
    keyed by Message-ID (default `default`); `outage` makes every call a
    ConnectionError; `bad_msgids` answer HTTP 400 for that message."""

    def __init__(self, requests_mod: Any, *, default: float = 1.0) -> None:
        self.requests = requests_mod
        self.default = default
        self.scores: dict[str, float] = {}
        self.symbols: dict[str, dict] = {}
        self.outage = False
        self.ping_ok: bool | None = None  # None = follow `outage`
        self.bad_msgids: set[str] = set()
        self.scan_calls: list[dict] = []
        self.learn_calls: list[dict] = []
        self.ping_calls = 0
        self.learn_status = 200

    def install(self, monkeypatch: Any, engine: Any) -> "FakeRspamd":
        monkeypatch.setattr(engine.requests, "post", self.post)
        monkeypatch.setattr(engine.requests, "get", self.get)
        return self

    def _msgid(self, raw: bytes) -> str:
        m = re.search(r"<([^>]+)>", _header_value(raw, "Message-ID"))
        return m.group(1) if m else ""

    def post(self, url: str, data: bytes = b"", headers: dict | None = None, timeout: Any = None) -> Any:
        headers = dict(headers or {})
        if self.outage:
            raise self.requests.ConnectionError("connection refused")
        if "/learn" in url:
            self.learn_calls.append({"url": url, "headers": headers, "data": data})
            return SimpleNamespace(status_code=self.learn_status, text="", json=lambda: {})
        mid = self._msgid(data)
        self.scan_calls.append({"url": url, "headers": headers, "msgid": mid})
        if mid in self.bad_msgids:
            return SimpleNamespace(status_code=400, text="bad", json=lambda: {})
        score = self.scores.get(mid, self.default)
        syms = self.symbols.get(mid, {"BAYES_SPAM" if score > 5 else "BAYES_HAM":
                                      {"name": "BAYES_SPAM" if score > 5 else "BAYES_HAM",
                                       "score": 3.0 if score > 5 else -1.0, "options": ["99%"]}})
        payload = {"score": score, "required_score": 15.0,
                   "action": "add header" if score >= 6 else "no action", "symbols": syms}
        return SimpleNamespace(status_code=200, text="", json=lambda: payload)

    def get(self, url: str, timeout: Any = None, headers: dict | None = None) -> Any:
        if url.endswith("/stat"):
            # services.bayes_stats (2.2 weekly report): no statfiles.
            return SimpleNamespace(status_code=200, text="", json=lambda: {"statfiles": []})
        self.ping_calls += 1
        ok = (not self.outage) if self.ping_ok is None else self.ping_ok
        if not ok:
            raise self.requests.ConnectionError("connection refused")
        return SimpleNamespace(status_code=200, text="pong")


def stub_mailctx(*, provider_flag: bool | None = None, provider_score: float | None = None,
                 external_ip: str | None = "192.0.2.10",
                 bonus: list[dict] | None = None, origin_host: str | None = None,
                 recipients: list[str] | None = None, real_helpers: bool = False) -> SimpleNamespace:
    """A mailctx stand-in returning the contract shape (SPEC C1/C3).
    2.1: origin_host (E8 path verification), recipients (E9) and, with
    real_helpers, the real newsletter helpers (E10)."""

    def scan_context(raw: bytes, acc: Any) -> dict:
        headers = {"Rcpt": acc.user, "IP": external_ip, "Helo": "mx1.example.net",
                   "Hostname": "mx1.example.net", "From": "bounce@example.org"}
        return {"headers": {k: v for k, v in headers.items() if v},
                "external_ip": external_ip, "helo": "mx1.example.net",
                "hostname": origin_host or "mx1.example.net", "envelope_from": "bounce@example.org",
                "authenticated": False, "provider_score": provider_score,
                "provider_flag": provider_flag, "hops": [], "origin_host": origin_host,
                "recipients": list(recipients or [])}

    def provider_bonus(ctx: dict) -> list[dict]:
        if bonus is not None:
            return list(bonus)
        if ctx.get("provider_flag"):
            return [{"n": "TH_PROVIDER_SPAM", "s": 4.0, "o": ["udbyder"]}]
        if (ctx.get("provider_score") or 0) >= 5:
            return [{"n": "TH_PROVIDER_SCORE", "s": 2.0, "o": ["udbyder"]}]
        return []

    ns = SimpleNamespace(scan_context=scan_context, provider_bonus=provider_bonus)
    if real_helpers:
        import mailctx

        ns.has_list_unsubscribe = mailctx.has_list_unsubscribe
        ns.header_from_domain = mailctx.header_from_domain
        ns.known_esp = mailctx.known_esp
    return ns


def make_account(engine: Any, **over: Any) -> Any:
    base = dict(
        name="acct", user="user@example-a.dk", password="pw",
        imap_host="imap.example.net", imap_port=993, ssl=True,
        inbox="INBOX", junk="Junk", trash="Trash",
        spam_train="Junk/Train-Spam", trained_spam="Junk/Trained-Spam",
        ham_train="Junk/Train-Ham", trained_ham="Junk/Trained-Ham",
        mode="move", threshold=8.0, min_threshold_allowed=5.0, reject_score_above=100.0,
        move_grace_seconds=60, learn_grace_seconds=300, idle_timeout=1500,
        poll_interval=600, junk_poll_interval=300, retention_check_interval=3600,
        max_moves_per_hour=60, max_learns_per_hour=50, max_train_per_run=100,
        safe_mode_unseen_cap=500, junk_retention_days=10, trained_retention_days=7,
        learn_from_moves=True, auto_special_folders=True, bayes_user="hjemmeserver",
    )
    base.update(over)
    acc = engine.Account(**base)
    acc.folder_map = engine.build_folder_map(acc, ".")
    return acc


def setup_engine(tmp_path: Path, monkeypatch: Any, *, mailctx: Any = None) -> Any:
    """Import the engine with all state under tmp_path, a fresh schema, a
    stub mailctx and SHUTDOWN cleared. Returns the module."""
    import filter as engine

    monkeypatch.setattr(engine, "STATE_DIR", tmp_path)
    monkeypatch.setattr(engine, "DB_PATH", tmp_path / "spamfilter.db")
    monkeypatch.setattr(engine, "CONFIG_PATH", tmp_path / "accounts.yml")
    monkeypatch.setattr(engine, "RSPAMD_PASSWORD", "pw")
    stub = mailctx if mailctx is not None else stub_mailctx()
    monkeypatch.setattr(engine, "_mailctx", lambda: stub)
    engine.SHUTDOWN.clear()
    engine.init_db()
    return engine


__all__ = [
    "BARE_CAPS", "GIGAHOST_CAPS", "SCANNET_CAPS", "FakeIMAP", "FakeMsg", "FakeRspamd",
    "IMAPClientAbortError", "IMAPClientError", "LoginError", "make_account", "make_message",
    "setup_engine", "stub_mailctx",
]
