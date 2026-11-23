"""Fakes + fixtures helpers for the UI tests (UI-CORE).

The UI must not need IMAP/rspamd or the real engine in tests: FakeEngine
stands in for `filter` (load_account_configs + sender-rule helpers) and
FakeServices for `services` (mail actions mutate the DB the way the real
service does, so re-rendered rows reflect the new state).

create_db() builds the REAL engine schema via filter.init_db(); the
ENGINE_SCHEMA copy below only documents the columns the UI relies on.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

FILTER_DIR = Path(__file__).resolve().parent.parent / "filter"
if str(FILTER_DIR) not in sys.path:
    sys.path.insert(0, str(FILTER_DIR))

ENGINE_SCHEMA = """
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
CREATE TABLE IF NOT EXISTS account_status (
    account TEXT PRIMARY KEY, updated_at INTEGER NOT NULL, state TEXT NOT NULL, detail TEXT,
    connected_since INTEGER, last_loop_at INTEGER, last_scan_at INTEGER, last_error TEXT,
    last_error_at INTEGER, error_count INTEGER NOT NULL DEFAULT 0, capabilities TEXT,
    move_method TEXT, idle_supported INTEGER, folders TEXT, folder_map TEXT, junk_exists INTEGER,
    mode TEXT, threshold REAL, bookmark_lag INTEGER, pending_moves INTEGER
);
CREATE TABLE IF NOT EXISTS sender_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT, account TEXT NOT NULL DEFAULT '*', pattern TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('allow','block')), note TEXT, created_by TEXT,
    created_at INTEGER NOT NULL, hits INTEGER NOT NULL DEFAULT 0, last_hit_at INTEGER,
    force INTEGER NOT NULL DEFAULT 0,
    UNIQUE(account, pattern)
);
CREATE TABLE IF NOT EXISTS stats_daily (
    account TEXT NOT NULL, day TEXT NOT NULL, metric TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (account, day, metric)
);
CREATE TABLE IF NOT EXISTS train_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, account TEXT NOT NULL, folder TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('spam','ham','calibrate')), max_messages INTEGER NOT NULL,
    min_age_days INTEGER NOT NULL DEFAULT 0, seen_only INTEGER NOT NULL DEFAULT 0,
    provider_filter TEXT NOT NULL DEFAULT 'any', status TEXT NOT NULL DEFAULT 'queued',
    total INTEGER NOT NULL DEFAULT 0, processed INTEGER NOT NULL DEFAULT 0,
    learned INTEGER NOT NULL DEFAULT 0, skipped INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0, error TEXT, created_by TEXT, created_at INTEGER NOT NULL,
    started_at INTEGER, finished_at INTEGER
);
"""

TEST_PASSWORD = "korrekt-hest-batteri-42"


def fast_hash(password: str, salt: bytes = b"0123456789abcdef", iterations: int = 1000) -> str:
    """pbkdf2 verifier in the dashboard format, cheap enough for tests."""
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2${iterations}${salt.hex()}${dk.hex()}"


# ---------------------------------------------------------------------------
# Engine fake
# ---------------------------------------------------------------------------


@dataclass
class FakeAccount:
    name: str
    user: str
    mode: str = "shadow"
    threshold: float = 8.0
    enabled: bool = True
    imap_host: str = "imap.example.dk"
    imap_port: int = 993
    inbox: str = "INBOX"
    junk: str = "Spamfilter"
    trash: str = "Trash"
    junk_explicit: bool = True
    known_contacts: bool = True      # 2.3 (B10)
    # 2.3 rules dialog: the owner's own domains (never blocked from the UI)
    owner_platform_domains: list = field(default_factory=list)
    webshop_domains: list = field(default_factory=list)
    contact_group: str | None = None
    password: str = field(default="", repr=False)


_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$")
_LOCAL_RE = re.compile(r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$")


class FakeEngine:
    VERSION = "2.18.0"
    # Same defaults as filter.py (the rules dialog never blocks them).
    DEFAULT_OWNER_PLATFORM_DOMAINS = ["vexar.example"]
    DEFAULT_WEBSHOP_DOMAINS = ["pinsikbing.example", "gravisk.example", "vexar.example"]

    def __init__(self, accounts: Iterable[FakeAccount] = (), *, config_error: str | None = None) -> None:
        self.accounts = list(accounts)
        self.config_error = config_error

    def load_account_configs(self, path: Any = None) -> list[FakeAccount]:
        if self.config_error:
            raise ValueError(self.config_error)
        return list(self.accounts)

    @staticmethod
    def normalize_rule_pattern(text: str) -> str:
        s = (text or "").strip().lower()
        if s.startswith("mailto:"):
            s = s[7:]
        s = s.strip("<> ")
        if s.startswith("*@"):
            s = s[1:]
        if not s or any(c.isspace() for c in s) or s.count("@") > 1:
            raise ValueError("invalid pattern")
        if "@" not in s:
            s = "@" + s
        local, _, domain = s.partition("@")
        if not _DOMAIN_RE.match(domain) or (local and not _LOCAL_RE.match(local)):
            raise ValueError("invalid pattern")
        return f"{local}@{domain}"

    def add_sender_rule(self, conn: sqlite3.Connection, account: str, pattern: str, kind: str,
                        note: str | None = None, actor: str | None = None, force: bool = False) -> int:
        if kind not in ("allow", "block"):
            raise ValueError("kind")
        pat = self.normalize_rule_pattern(pattern)
        conn.execute(
            "INSERT INTO sender_rules(account, pattern, kind, note, created_by, created_at, force) "
            "VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(account, pattern) DO UPDATE SET "
            "force=CASE WHEN excluded.kind='allow' THEN MAX(excluded.force, "
            "CASE WHEN sender_rules.kind='allow' THEN sender_rules.force ELSE 0 END) ELSE 0 END, "
            "kind=excluded.kind, "
            "note=COALESCE(excluded.note, sender_rules.note), created_by=excluded.created_by",
            (account or "*", pat, kind, note, actor, int(time.time()), 1 if force and kind == "allow" else 0))
        return int(conn.execute("SELECT id FROM sender_rules WHERE account=? AND pattern=?",
                                (account or "*", pat)).fetchone()[0])

    @staticmethod
    def set_rule_force(conn: sqlite3.Connection, rule_id: int, force: bool) -> bool:
        sql = ("UPDATE sender_rules SET force=1 WHERE id=? AND kind='allow'" if force
               else "UPDATE sender_rules SET force=0 WHERE id=?")
        return conn.execute(sql, (int(rule_id),)).rowcount > 0

    @staticmethod
    def delete_sender_rule(conn: sqlite3.Connection, rule_id: int) -> bool:
        return conn.execute("DELETE FROM sender_rules WHERE id=?", (int(rule_id),)).rowcount > 0

    @staticmethod
    def match_sender_rule(conn: sqlite3.Connection, account: str, sender_addr: str | None):
        return None

    @staticmethod
    def request_reload(*_a: Any, **_k: Any) -> None:
        return None


# ---------------------------------------------------------------------------
# Services fake
# ---------------------------------------------------------------------------


class FakeServices:
    """Records calls; mail_action mutates the DB like services.mail_action."""

    def __init__(self, db_path: Path, *, fail_ids: Iterable[str] = (), bayes: dict | None = None,
                 raise_on_action: bool = False) -> None:
        self.db_path = Path(db_path)
        self.calls: list[tuple[str, list[str], str, str]] = []
        self.action_kwargs = []
        self.calls23 = []
        self.fail_ids = set(fail_ids)
        self.raise_on_action = raise_on_action
        self.bayes = bayes if bayes is not None else {"ok": True, "spam_learned": 140, "ham_learned": 260,
                                                       "min_learns": 200, "users": 1}

    def mail_action(self, account: str, message_ids: Iterable[str], action: str, actor: str,
                    *, engine: Any = None, demote_contact: bool = True, is_admin: bool = False,
                    confirm_threat: bool = False) -> list[dict]:
        ids = list(message_ids)
        self.calls.append((account, ids, action, actor))
        self.action_kwargs.append({"demote_contact": demote_contact, "is_admin": is_admin,
                                   "confirm_threat": confirm_threat})
        if self.raise_on_action:
            raise RuntimeError("imap exploded: secret-detail")
        out = []
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            for mid in ids:
                if mid in self.fail_ids:
                    out.append({"message_id": mid, "ok": False, "code": "not_found",
                                "text": "Beskeden blev ikke fundet i postkassen."})
                    continue
                row = conn.execute("SELECT * FROM messages WHERE account=? AND message_id=?",
                                   (account, mid)).fetchone()
                threat = row["threat"] if row is not None and "threat" in row.keys() else None
                if action in ("release", "learn_ham") and threat:
                    # Same gate as services.mail_action (B16), fail closed.
                    gate = _real_services().threat_gate(threat, row["threat_detail"], is_admin=is_admin,
                                                        confirm_threat=confirm_threat)
                    if gate is not None:
                        out.append({"message_id": mid, "ok": False, **gate})
                        continue
                now = int(time.time())
                if action == "release":
                    conn.execute("UPDATE messages SET our_action='manual_release', user_verdict='ham', "
                                 "current_folder='INBOX', verdict_at=?, verdict_by=? WHERE account=? AND message_id=?",
                                 (now, actor, account, mid))
                    text = "Frigivet til indbakken og lært som legitim."
                elif action == "mark_spam":
                    conn.execute("UPDATE messages SET our_action='manual_mark_spam', user_verdict='spam', "
                                 "current_folder='Spamfilter', verdict_at=?, verdict_by=? WHERE account=? AND message_id=?",
                                 (now, actor, account, mid))
                    text = "Flyttet til spam og lært som spam."
                else:
                    verdict = "ham" if action == "learn_ham" else "spam"
                    conn.execute("UPDATE messages SET user_verdict=?, verdict_at=?, verdict_by=? "
                                 "WHERE account=? AND message_id=?", (verdict, now, actor, account, mid))
                    text = "Lært."
                res = {"message_id": mid, "ok": True, "code": "ok", "text": text}
                if threat:
                    res.update(threat=threat, threat_text=_real_services().threat_text(threat, row["threat_detail"]))
                if action in ("mark_spam", "learn_spam") and row is not None:
                    contact = self._demote(conn, account, row, demote_contact, actor, now)
                    if contact:
                        res["contact"] = contact
                out.append(res)
            conn.commit()
        finally:
            conn.close()
        return out

    def bayes_stats(self, *, engine: Any = None) -> dict:
        return dict(self.bayes)

    action_kwargs: list

    @staticmethod
    def _demote(conn: sqlite3.Connection, account: str, row: Any, demote: bool, actor: str,
                now: int) -> dict | None:
        """B14 like services.mail_action: a spam verdict on a known contact's
        mail demotes the contact (matched by the symbol's mask here)."""
        try:
            syms = json.loads(row["symbols"] or "[]")
        except ValueError:
            return None
        kc = next((x for x in syms if isinstance(x, dict) and x.get("n") in ("TH_KNOWN_CONTACT",
                                                                           "TH_ESTABLISHED")), None)
        if kc is None:
            return None
        msk = str((kc.get("o") or [""])[0]) if kc.get("n") == "TH_KNOWN_CONTACT" else ""
        try:
            hit = conn.execute("SELECT h, mask FROM known_contacts WHERE account=? AND mask=? AND status='active'",
                               (account, msk)).fetchone()
        except sqlite3.Error:
            hit = None
        if hit is None:
            return None
        if demote:
            conn.execute("UPDATE known_contacts SET status='demoted', status_at=?, status_by=? WHERE account=? AND h=?",
                         (now, actor, account, hit["h"]))
            conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                         (account, now, row["message_id"], "contact_demoted", f"{hit['mask']} af {actor}"))
        return {"mask": hit["mask"], "demoted": bool(demote), "h": hit["h"]}

    # ---- 2.3: contacts, trust labels, threats, attachments --------------
    # The real services functions run against this test database through an
    # engine shim (the UI must render exactly what production returns).

    def engine_shim(self) -> Any:
        return EngineShim(self.db_path)

    def _real(self, fn: str, *args: Any, **kw: Any) -> Any:
        self.calls23.append((fn, *args))
        kw.pop("engine", None)
        return getattr(_real_services(), fn)(*args, engine=self.engine_shim(), **kw)

    calls23: list

    def contacts_overview(self, account: str, *, engine: Any = None) -> dict:
        return self._real("contacts_overview", account)

    def contacts_list(self, account: str, q: str = "", page: int = 1, per_page: int = 50, group: str = "people",
                      *, status: str = "all", engine: Any = None) -> dict:
        return self._real("contacts_list", account, q, page, per_page, group, status=status)

    def contact_lookup(self, account: str, address: str, *, engine: Any = None) -> dict:
        return self._real("contact_lookup", account, address)

    def set_contact_status(self, account: str, h: str, status: str, actor: str, *, engine: Any = None) -> dict:
        return self._real("set_contact_status", account, h, status, actor)

    def restore_contact(self, account: str, h: str, actor: str, *, engine: Any = None) -> dict:
        return self._real("restore_contact", account, h, actor)

    def request_contacts_sync(self, account: str, actor: str, *, engine: Any = None) -> dict:
        return self._real("request_contacts_sync", account, actor)

    def set_known_contacts_enabled(self, account: str, enabled: bool, actor: str, *, engine: Any = None,
                                   save_config: Any = None) -> dict:
        return self._real("set_known_contacts_enabled", account, enabled, actor)

    def message_trust_labels(self, account: str, message_id: str, *, numbers: bool = True,
                             engine: Any = None) -> list:
        return self._real("message_trust_labels", account, message_id, numbers=numbers)

    def trust_counts_today(self, accounts: Any = None, *, day: str | None = None, engine: Any = None) -> dict:
        return self._real("trust_counts_today", accounts, day=day)

    def message_threat_info(self, account: str, message_id: str, *, engine: Any = None) -> dict:
        return self._real("message_threat_info", account, message_id)

    def threats_today(self, accounts: Any = None, *, day: str | None = None, days: int = 1,
                      engine: Any = None) -> dict:
        # 2.3 follow-up: the real function on the test DB (Oversigt card + strip).
        return self._real("threats_today", None if accounts is None else list(accounts), day=day, days=days)

    def attachment_policy(self, *, engine: Any = None) -> dict:
        return self._real("attachment_policy")

    def set_attachment_block(self, extensions: Any, actor: str, *, reset: bool = False, engine: Any = None,
                             save_config: Any = None) -> dict:
        return self._real("set_attachment_block", extensions, actor, reset=reset)

    def attachment_exceptions(self, account: str | None = None, *, engine: Any = None) -> dict:
        return self._real("attachment_exceptions", account)

    # ---- 2.3.6 (B22): lookalike domains - the real services on the test DB
    def lookalike_overview(self, *, engine: Any = None) -> dict:
        return self._real("lookalike_overview")

    def lookalike_settings(self, *, engine: Any = None) -> dict:
        return self._real("lookalike_settings")

    def lookalike_attention(self, *, engine: Any = None) -> list:
        return self._real("lookalike_attention")

    def set_protected_domains(self, domains: Any, actor: str, *, reset: bool = False, engine: Any = None,
                              save_config: Any = None) -> dict:
        return self._real("set_protected_domains", domains, actor, reset=reset)

    def lookalike_allow(self, domain: Any, actor: str, *, protected: Any = None, note: Any = None,
                        engine: Any = None) -> dict:
        return self._real("lookalike_allow", domain, actor, protected=protected, note=note)

    def lookalike_unallow(self, domain: Any, actor: str, *, engine: Any = None) -> dict:
        return self._real("lookalike_unallow", domain, actor)

    def lookalike_ack(self, actor: str, *, domain: Any = None, engine: Any = None) -> dict:
        return self._real("lookalike_ack", actor, domain=domain)

    def lookalike_request_run(self, actor: str, *, engine: Any = None) -> dict:
        return self._real("lookalike_request_run", actor)

    # ---- 2.7: Beskyttede navne (namespoof) - the real services on the test DB
    def namespoof_overview(self, *, engine: Any = None) -> dict:
        return self._real("namespoof_overview")

    def namespoof_attention(self, *, engine: Any = None) -> list:
        return self._real("namespoof_attention")

    def namespoof_set_mode(self, mode: Any, actor: str, *, engine: Any = None) -> dict:
        return self._real("namespoof_set_mode", mode, actor)

    def namespoof_save(self, name: Any, allow: Any, actor: str, *, enabled: bool = True, entry_id: Any = None,
                       engine: Any = None) -> dict:
        return self._real("namespoof_save", name, allow, actor, enabled=enabled, entry_id=entry_id)

    def namespoof_delete(self, entry_id: Any, actor: str, *, engine: Any = None) -> dict:
        return self._real("namespoof_delete", entry_id, actor)

    def namespoof_allow(self, entry_id: Any, address: Any, actor: str, *, engine: Any = None) -> dict:
        return self._real("namespoof_allow", entry_id, address, actor)

    def namespoof_seed_now(self, actor: str, *, engine: Any = None) -> dict:
        return self._real("namespoof_seed_now", actor)

    def add_attachment_exception(self, account: str, pattern: str, actor: str, *, is_admin: bool = False,
                                 note: str = "", engine: Any = None) -> dict:
        return self._real("add_attachment_exception", account, pattern, actor, is_admin=is_admin, note=note)

    def remove_attachment_exception(self, rule_id: Any, actor: str, *, is_admin: bool = False,
                                    engine: Any = None) -> dict:
        return self._real("remove_attachment_exception", rule_id, actor, is_admin=is_admin)

    # Pure helpers: exactly the production functions.
    @staticmethod
    def trust_labels(symbols: Any, *, numbers: bool = True, today: Any = None) -> list:
        return _real_services().trust_labels(symbols, numbers=numbers, today=today)

    @staticmethod
    def threat_text(threat: Any, detail: Any = None) -> str:
        return _real_services().threat_text(threat, detail)

    @staticmethod
    def threat_confirm_text(threat: Any, detail: Any = None) -> str:
        return _real_services().threat_confirm_text(threat, detail)

    @staticmethod
    def zap_timeline_text(detail: Any) -> str:
        return _real_services().zap_timeline_text(detail)

    # ---- 2.1 tools (shapes per services.py, 2.1) ---------------------------

    tool_calls: list

    def _tool(self, name: str, *args: Any) -> None:
        if not hasattr(self, "tool_calls"):
            self.tool_calls = []
        self.tool_calls.append((name, *args))

    @staticmethod
    def folder_label(name: str) -> str:
        return {"INBOX": "Indbakken", "U&APg-nsket e-mail": "Uønsket e-mail"}.get(name, name)

    def _rows(self, sql: str, params: Iterable[Any]) -> list[dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            return [dict(r) for r in conn.execute(sql, list(params)).fetchall()]
        finally:
            conn.close()

    live_folders: list | None = None
    find_threats: dict | None = None   # message_id -> (threat, detail) for move_found_to_inbox

    def find_mail(self, account: str, text: str, since_days: int = 30, folders: Any = None, *, live: bool = True,
                  actor: str = "", engine: Any = None) -> dict:
        self._tool("find_mail", account, text, since_days, live)
        text = " ".join(str(text or "").split())
        if not 2 <= len(text) <= 100:
            return {"ok": False, "code": "invalid", "text": "Skriv mindst 2 tegn."}
        like = f"%{text}%"
        db = self._rows("SELECT message_id, sender, subject, envelope_from, received_at, first_seen, current_folder, "
                        "our_action, our_score, user_verdict, score_version FROM messages WHERE account=? AND "
                        "(sender LIKE ? OR subject LIKE ? OR envelope_from LIKE ?) ORDER BY first_seen DESC LIMIT 50",
                        [account, like, like, like])
        res = {"ok": True, "code": "ok", "text": "", "account": account, "query": text, "since_days": since_days,
               "live": live, "searched_at": int(time.time()), "db": db, "folders": [], "searched": [], "errors": [],
               "total": len(db), "hints": [], "audit_detail": f"q_len={len(text)} days={since_days} live={int(live)}"}
        if live:
            groups = [dict(g) for g in (self.live_folders or [])]
            for g in groups:
                g["hits"] = [x for x in g.get("hits", [])
                             if text.lower() in (str(x.get("subject", "")) + str(x.get("sender", ""))
                                                 + str(x.get("sender_name", ""))).lower()]
                g["count"] = len(g["hits"])
            res["folders"] = sorted(groups, key=lambda g: not g["hits"])
            res["searched"] = [g["label"] for g in groups] or ["Indbakken", "Spamfilter", "Junk", "Papirkurv"]
            res["total"] += sum(g["count"] for g in groups)
        return res

    def move_found_to_inbox(self, account: str, folder: str, message_id: str, actor: str, *, learn: bool = False,
                            engine: Any = None, is_admin: bool = False, confirm_threat: bool = False) -> dict:
        self._tool("move_found_to_inbox", account, folder, message_id, actor)
        threat = (self.find_threats or {}).get(message_id)
        if threat:
            gate = _real_services().threat_gate(threat[0], threat[1], is_admin=is_admin, confirm_threat=confirm_threat)
            if gate is not None:
                return {"ok": False, "message_id": message_id, "folder": folder, "label": self.folder_label(folder),
                        "learned": None, "audit_detail": f"from {folder} threat", **gate}
        return {"ok": True, "code": "ok", "text": "Mailen er flyttet til indbakken.", "message_id": message_id,
                "folder": folder, "label": self.folder_label(folder), "learned": None,
                "audit_detail": f"from {folder}"}

    def preview_undo(self, account: str, since_ts: int, until_ts: int, *, sample: int = 50,
                     engine: Any = None) -> dict:
        rows = self._rows("SELECT message_id, sender, subject, our_score, moved_to_junk_at FROM messages "
                          "WHERE account=? AND our_action='moved_to_junk' AND COALESCE(moved_to_junk_at, first_seen) "
                          "BETWEEN ? AND ? ORDER BY first_seen DESC", [account, since_ts, until_ts])
        return {"ok": True, "code": "ok", "text": "", "account": account, "since_ts": since_ts, "until_ts": until_ts,
                "count": len(rows), "gone": 0, "too_many": False, "items": rows[:sample]}

    undo_jobs: dict

    def undo_moves(self, account: str, since_ts: int, until_ts: int, actor: str, learn: bool = False, *,
                   wait_s: int = 20, engine: Any = None) -> dict:
        self._tool("undo_moves", account, since_ts, until_ts, actor, learn)
        if not hasattr(self, "undo_jobs"):
            self.undo_jobs = {}
        n = self.preview_undo(account, since_ts, until_ts)["count"]
        if not n:
            return {"ok": True, "code": "nothing", "text": "Der var intet at flytte tilbage."}
        jid = len(self.undo_jobs) + 1
        job = {"id": jid, "account": account, "since_ts": since_ts, "until_ts": until_ts, "learn": int(learn),
               "status": "running", "total": n, "processed": n // 2, "moved": n // 2, "not_found": 0, "skipped": 0,
               "failed": 0, "learned": 0, "error": "", "created_by": actor, "created_at": int(time.time()),
               "started_at": int(time.time()), "finished_at": None, "percent": 50, "remaining": n - n // 2,
               "text": f"{n // 2} af {n} mails er lagt tilbage i indbakken …"}
        self.undo_jobs[jid] = job
        return {"ok": True, "code": "running", "text": job["text"], "job_id": jid, "status": "running", "total": n,
                "moved": job["moved"], "not_found": 0, "skipped": 0, "failed": 0, "learned": 0,
                "remaining": job["remaining"], "percent": 50, "audit_detail": f"job={jid} n={n} learn={int(learn)}"}

    def undo_job(self, job_id: int, *, engine: Any = None) -> dict | None:
        return dict((getattr(self, "undo_jobs", {}) or {}).get(int(job_id)) or {}) or None

    def list_undo_jobs(self, account: str | None = None, limit: int = 20, *, engine: Any = None) -> list[dict]:
        jobs = sorted((getattr(self, "undo_jobs", {}) or {}).values(), key=lambda j: -j["id"])
        return [dict(j) for j in jobs if account is None or j["account"] == account][:limit]

    def cancel_undo_job(self, job_id: int, *, engine: Any = None) -> bool:
        job = (getattr(self, "undo_jobs", {}) or {}).get(int(job_id))
        if not job or job["status"] not in ("queued", "running"):
            return False
        job["status"] = "cancel_requested"
        return True

    suggestions: dict

    def threshold_suggestion(self, account: str, days: int = 14, *, engine: Any = None) -> dict:
        sug = (getattr(self, "suggestions", {}) or {}).get(account)
        if sug:
            return dict(sug)
        return {"ok": True, "account": account, "days": days, "mode": "move", "current": 10.0, "recommended": None,
                "change": "none", "confidence": "low", "text": "For lidt data til et forslag endnu.", "reasons": [],
                "counts": {}, "histogram": [], "grid": []}

    def folder_sizes(self, account: str, *, refresh: bool = False, engine: Any = None) -> dict:
        return {"ok": True, "code": "ok", "text": "", "account": account, "cached": not refresh,
                "fetched_at": int(time.time()),
                "folders": [{"kind": "inbox", "name": "INBOX", "label": "Indbakken", "exists": True, "messages": 1243,
                             "unseen": 12},
                            {"kind": "filter_junk", "name": "Spamfilter", "label": "Spamfilter", "exists": True,
                             "messages": 386, "unseen": 41},
                            {"kind": "provider_junk", "name": "Junk", "label": "Junk", "exists": True, "messages": 57,
                             "unseen": 3}]}


def _real_services() -> Any:
    import services  # noqa: PLC0415 - the production module (pure + DB functions)

    return services


class EngineShim:
    """What services.* needs from the engine, pointed at the test state:
    DB_PATH / STATE_DIR / CONFIG_PATH from the dashboard, accounts from the
    dashboard's (fake) engine, everything else from the real filter.py."""

    def __init__(self, db_path: Path) -> None:
        self.DB_PATH = Path(db_path)
        self.STATE_DIR = self.DB_PATH.parent

    @property
    def CONFIG_PATH(self) -> Path:  # noqa: N802 - engine attribute name
        import dashboard

        return Path(dashboard.CONFIG_PATH)

    def load_account_configs(self, path: Any = None) -> list:
        import dashboard

        return list(dashboard.engine.load_account_configs(path if path is not None else self.CONFIG_PATH))

    def __getattr__(self, name: str) -> Any:
        import filter as engine

        return getattr(engine, name)


# ---------------------------------------------------------------------------
# DB + users helpers
# ---------------------------------------------------------------------------


def create_db(path: Path) -> None:
    """Create the REAL engine schema (filter.init_db) at path, so the UI is
    tested against exactly what production has. ENGINE_SCHEMA above is kept
    only as documentation of the columns the UI relies on."""
    import filter as engine

    old = engine.DB_PATH
    engine.DB_PATH = Path(path)
    try:
        engine.init_db()
    finally:
        engine.DB_PATH = old


def write_users(state_dir: Path, users: Iterable[tuple[str, str, str]]) -> None:
    """users: (name, password, scope) with scope 'admin' or 'a|b'."""
    lines = [f"{n}:{fast_hash(pw)}:{scope}:0" for n, pw, scope in users]
    p = state_dir / "dashboard_users"
    p.write_text("\n".join(lines) + "\n")
    p.chmod(0o600)


def insert_message(conn: sqlite3.Connection, account: str, message_id: str, **kw: Any) -> None:
    now = int(time.time())
    row = {"account": account, "message_id": message_id, "first_seen": now, "last_seen": now,
           "current_folder": "INBOX", "our_score": 1.0, "our_action": "none",
           "sender": "Afsender <afsender@example.dk>", "subject": "Hej", "received_at": now,
           "scanned_at": now, "origin": "inbox_scan", "score_version": 2, "symbols": "[]"}
    row.update(kw)
    if isinstance(row.get("symbols"), list):
        row["symbols"] = json.dumps(row["symbols"])
    cols = ",".join(row)
    conn.execute(f"INSERT OR REPLACE INTO messages({cols}) VALUES({','.join('?' * len(row))})",
                 list(row.values()))


def set_status(conn: sqlite3.Connection, account: str, state: str, **kw: Any) -> None:
    now = int(time.time())
    row = {"account": account, "updated_at": now, "state": state, "last_loop_at": now}
    row.update(kw)
    cols = ",".join(row)
    conn.execute(f"INSERT OR REPLACE INTO account_status({cols}) VALUES({','.join('?' * len(row))})",
                 list(row.values()))


def bump(conn: sqlite3.Connection, account: str, day: str, metric: str, n: int) -> None:
    conn.execute("INSERT INTO stats_daily(account, day, metric, n) VALUES(?,?,?,?) "
                 "ON CONFLICT(account, day, metric) DO UPDATE SET n = n + excluded.n",
                 (account, day, metric, n))


# ---------------------------------------------------------------------------
# Test environment
# ---------------------------------------------------------------------------

DEFAULT_ACCOUNTS = (
    FakeAccount("bynet", "ole@bynet.example", mode="move", threshold=8.0, imap_host="imap.gigahost.dk"),
    FakeAccount("molt", "ole@molt.example", mode="shadow", threshold=6.0, imap_host="mail.scannet.dk"),
    FakeAccount("sofie", "sofie@molt.example", mode="shadow", enabled=False, imap_host="mail.scannet.dk"),
)


def make_env(tmp_path: Path, monkeypatch: Any, *, accounts: Iterable[FakeAccount] = DEFAULT_ACCOUNTS,
             users: Iterable[tuple[str, str, str]] | None = None) -> Any:
    """Point the dashboard at a temp state dir with the SPEC schema, fake
    engine/services and two users: 'admin' (admin) and 'sofie' (scoped)."""
    from types import SimpleNamespace

    import dashboard
    import ui_mail  # noqa: F401 - registers the mail routes

    state = tmp_path / "state"
    state.mkdir()
    cfg = tmp_path / "accounts.yml"
    cfg.write_text("defaults: {}\naccounts: []\n")
    for name, value in {
        "STATE_DIR": state, "CONFIG_PATH": cfg, "DB_PATH": state / "spamfilter.db",
        "USERS_FILE": state / "dashboard_users", "SECRET_PATH": state / "dashboard_secret",
        "AUDIT_FILE": state / "admin-audit.jsonl", "RELOAD_FILE": state / "reload_requested",
    }.items():
        monkeypatch.setattr(dashboard, name, value)
    create_db(state / "spamfilter.db")
    dashboard.init_ui_db()
    eng = FakeEngine([FakeAccount(**a.__dict__) for a in accounts])
    svc = FakeServices(state / "spamfilter.db")
    monkeypatch.setattr(dashboard, "engine", eng)
    monkeypatch.setattr(dashboard, "services", svc)
    write_users(state, users if users is not None else
                [("admin", TEST_PASSWORD, "admin"), ("sofie", TEST_PASSWORD, "sofie")])
    dashboard.app.config["TESTING"] = True
    conn = sqlite3.connect(state / "spamfilter.db")
    conn.row_factory = sqlite3.Row

    def audit_records() -> list[dict]:
        p = state / "admin-audit.jsonl"
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

    return SimpleNamespace(app=dashboard.app, ui=dashboard, state=state, config=cfg, engine=eng,
                           services=svc, conn=conn, audit=audit_records)


def csrf_of(client: Any) -> str:
    with client.session_transaction() as s:
        return s.get("csrf", "")


def login(client: Any, name: str = "admin", password: str = TEST_PASSWORD) -> Any:
    client.get("/login")
    return client.post("/login", data={"username": name, "password": password, "csrf": csrf_of(client)})


def post(client: Any, url: str, data: dict | None = None, *, json_reply: bool = True, **kw: Any) -> Any:
    headers = {"X-CSRF-Token": csrf_of(client)}
    if json_reply:
        headers.update({"Accept": "application/json", "X-Requested-With": "fetch"})
    headers.update(kw.pop("headers", {}))
    return client.post(url, data=data or {}, headers=headers, **kw)
