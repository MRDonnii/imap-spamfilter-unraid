"""Fakes for the administration pages (UI-ADMIN).

Builds on tests/fakes_ui.py (UI-CORE). The admin pages write accounts.yml,
so the engine fake here is YAML-backed: load_account_configs() parses the
file it is given (save_config validates a temp file with it) and applies
a subset of the real engine's validation. FakeAdminServices adds the
services the admin pages call (connection test, folders, jobs,
calibration, health) on top of UI-CORE's FakeServices.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

from fakes_ui import FakeEngine, FakeServices, make_env

CALIBRATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS calibration_results (
    job_id INTEGER, account TEXT, folder TEXT, message_id TEXT, final_score REAL, rspamd_score REAL,
    symbols TEXT, sender TEXT, subject TEXT, received_at INTEGER, seen INTEGER, provider_flag INTEGER,
    provider_score REAL, PRIMARY KEY(job_id, account, folder, message_id)
);
"""

DEFAULTS: dict[str, Any] = {
    "enabled": True, "imap_port": 993, "ssl": True, "inbox": "INBOX", "junk": "Junk", "trash": "Trash",
    "mode": "shadow", "threshold": 8.0, "min_threshold_allowed": 5.0, "move_grace_seconds": 60,
    "max_moves_per_hour": 60, "junk_poll_interval": 300, "poll_interval": 600, "learn_from_moves": True,
    "provider_bonus": True, "bayes_user": None, "training_folders": False,
    "known_contacts": True,  # 2.3 (B10)
    "threat_notice": True,   # 2.3 follow-up: Straks-advarsel
}


@dataclass
class AdminAccount:
    name: str
    user: str
    imap_host: str
    imap_port: int = 993
    ssl: bool = True
    enabled: bool = True
    inbox: str = "INBOX"
    junk: str = "Junk"
    trash: str = "Trash"
    mode: str = "shadow"
    threshold: float = 8.0
    min_threshold_allowed: float = 5.0
    move_grace_seconds: int = 60
    max_moves_per_hour: int = 60
    junk_poll_interval: int = 300
    poll_interval: int = 600
    learn_from_moves: bool = True
    provider_bonus: bool = True
    bayes_user: str | None = None
    training_folders: bool = False
    auto_allow_on_rescue: bool = True
    known_contacts: bool = True
    threat_notice: bool = True
    newsletters: str = "shadow"           # 2.6 (A4)
    newsletter_folder: str = "Nyhedsbreve"
    junk_explicit: bool = False
    trash_explicit: bool = False
    password_file: str | None = None
    password: str = field(default="", repr=False)
    secret_inline: str = field(default="", repr=False)


class FakeAdminEngine(FakeEngine):
    """YAML-backed engine fake (load_account_configs + read_secret)."""

    def __init__(self) -> None:
        super().__init__([])
        self.loads: list[str] = []

    def load_account_configs(self, path: Any = None) -> list[AdminAccount]:  # type: ignore[override]
        if self.config_error:
            raise ValueError(self.config_error)
        p = Path(path)
        self.loads.append(str(p))
        raw = yaml.safe_load(p.read_text()) or {}
        if not isinstance(raw, dict) or not isinstance(raw.get("accounts"), list):
            raise ValueError("missing 'accounts' key")
        defaults = {**DEFAULTS, **(raw.get("defaults") or {})}
        out, seen = [], set()
        for a in raw["accounts"]:
            if not isinstance(a, dict):
                raise ValueError("each account must be a mapping")
            merged = {**defaults, **a}
            label = str(merged.get("name") or "?")
            for k in ("name", "user", "imap_host"):
                if not merged.get(k):
                    raise ValueError(f"account {label!r} missing required key(s): {k}")
            if merged["mode"] not in ("shadow", "flag", "move"):
                raise ValueError(f"account {label!r}: mode must be shadow, flag or move")
            thr = float(merged["threshold"])
            if thr < float(merged["min_threshold_allowed"]):
                raise ValueError(f"account {label!r}: threshold below min_threshold_allowed")
            inline = merged.get("password")
            if merged.get("password_file") and inline:
                raise ValueError(f"account {label!r} needs exactly one of password or password_file")
            if not merged.get("password_file") and not inline and merged.get("enabled", True):
                raise ValueError(f"account {label!r} needs exactly one of password or password_file")
            if label in seen:
                raise ValueError(f"duplicate account name {label!r}")
            seen.add(label)
            if not isinstance(merged.get("threat_notice", True), bool):
                raise ValueError(f"account {label!r}: threat_notice must be true or false")
            for k in ("imap_port", "move_grace_seconds", "max_moves_per_hour", "junk_poll_interval", "poll_interval"):
                if not isinstance(merged[k], int) or isinstance(merged[k], bool):
                    raise ValueError(f"account {label!r}: {k} must be an integer")
            kw = {k: merged[k] for k in AdminAccount.__dataclass_fields__ if k in merged
                  and k not in ("password", "secret_inline", "junk_explicit", "trash_explicit")}
            kw["threshold"] = thr
            out.append(AdminAccount(**kw, junk_explicit="junk" in a, trash_explicit="trash" in a,
                                    secret_inline=str(inline or "")))
        return out

    @staticmethod
    def read_secret(acc: AdminAccount) -> str:
        if acc.password_file:
            text = Path(acc.password_file).read_text().rstrip("\r\n")
            if not text:
                raise ValueError("empty password_file")
            return text
        if acc.secret_inline:
            return acc.secret_inline
        raise ValueError("no password")

    @staticmethod
    def bayes_identity(acc: AdminAccount) -> str:
        return acc.bayes_user or acc.user


FOLDERS = [{"name": "INBOX", "flags": [], "messages": 120}, {"name": "Junk", "flags": ["\\Junk"], "messages": 3},
           {"name": "Spamfilter", "flags": [], "messages": 7}, {"name": "Archive", "flags": [], "messages": 900},
           {"name": "Sent", "flags": ["\\Sent"], "messages": 40}]


class FakeAdminServices(FakeServices):
    """FakeServices + everything the admin pages call."""

    def __init__(self, db_path: Path, *, good_password: str = "imap-hemmelighed",
                 host_status: dict | None = None, backup: dict | None = None, **kw: Any) -> None:
        super().__init__(db_path, **kw)
        self.good_password = good_password
        self.tests: list[tuple[str, int, str, str]] = []
        self.reloads: list[tuple[str, str]] = []
        self.refresh_error: Exception | None = None
        self._host = host_status
        self._backup = backup
        self.health = {"ok": True, "controller_ok": True, "scanner_ok": True, "controller_ms": 4,
                       "scanner_ms": 9, "text": "rspamd svarer normalt."}
        self.repair_items, self.learn_lists, self.learn_items, self.rebalance = [], {}, {}, None
        self.svc22_calls: list = []

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # -- connection + folders ------------------------------------------------
    def test_connection(self, host: str, port: int, user: str, password: str, timeout: float = 20,
                        *, engine: Any = None) -> dict:
        self.tests.append((host, int(port), user, password))
        if password != self.good_password:
            return {"ok": False, "code": "auth", "text": "Brugernavn eller adgangskode blev afvist af mailserveren.",
                    "capabilities": [], "move_method": "none", "idle": False, "folders": [],
                    "suggested": {"junk": None, "trash": None}}
        return {"ok": True, "code": "ok", "text": "Forbindelsen virker.",
                "capabilities": ["IMAP4rev1", "IDLE", "UIDPLUS", "MOVE"], "move_method": "MOVE", "idle": True,
                "folders": [dict(f) for f in FOLDERS], "suggested": {"junk": "Junk", "trash": "Trash"}}

    def account_folders(self, account: str, *, engine: Any = None) -> list[dict]:
        with self._conn() as conn:
            row = conn.execute("SELECT folders FROM account_status WHERE account=?", (account,)).fetchone()
        return json.loads(row["folders"]) if row and row["folders"] else []

    def refresh_folders(self, account: str, *, engine: Any = None) -> list[dict]:
        if self.refresh_error:
            raise self.refresh_error
        with self._conn() as conn:
            conn.execute("INSERT INTO account_status(account, updated_at, state, folders) VALUES(?,?,?,?) "
                         "ON CONFLICT(account) DO UPDATE SET folders=excluded.folders",
                         (account, int(time.time()), "starting", json.dumps(FOLDERS)))
        return [dict(f) for f in FOLDERS]

    # -- jobs ------------------------------------------------------------------
    def _insert(self, account: str, folder: str, kind: str, n: int, age: int, seen: bool, pf: str, actor: str) -> int:
        with self._conn() as conn:
            cur = conn.execute("INSERT INTO train_jobs(account, folder, kind, max_messages, min_age_days, seen_only, "
                               "provider_filter, status, created_by, created_at) VALUES(?,?,?,?,?,?,?,'queued',?,?)",
                               (account, folder, kind, int(n), int(age), int(bool(seen)), pf, actor, int(time.time())))
            return int(cur.lastrowid)

    def queue_train_job(self, account: str, folder: str, kind: str, max_messages: int, min_age_days: int = 0,
                        seen_only: bool = False, provider_filter: str = "any", actor: str = "",
                        *, engine: Any = None) -> int:
        if kind not in ("spam", "ham"):
            raise ValueError("Typen skal være spam eller legitim.")
        return self._insert(account, folder, kind, max_messages, min_age_days, seen_only, provider_filter, actor)

    def queue_calibration(self, account: str, folder: str, max_messages: int = 300, min_age_days: int = 0,
                          actor: str = "", *, engine: Any = None) -> int:
        return self._insert(account, folder, "calibrate", max_messages, min_age_days, False, "any", actor)

    def cancel_train_job(self, job_id: int, *, engine: Any = None) -> bool:
        with self._conn() as conn:
            if conn.execute("UPDATE train_jobs SET status='cancelled', finished_at=? WHERE id=? AND status='queued'",
                            (int(time.time()), job_id)).rowcount:
                return True
            return bool(conn.execute("UPDATE train_jobs SET status='cancel_requested' WHERE id=? AND status='running'",
                                     (job_id,)).rowcount)

    def list_train_jobs(self, limit: int = 20, *, engine: Any = None) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM train_jobs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["percent"] = int(min(100, d["processed"] * 100 / d["total"])) if d["total"] else (100 if d["status"] == "done" else 0)
            out.append(d)
        return out

    def calibration_results(self, job_id: int, *, limit: int = 2000, engine: Any = None) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM calibration_results WHERE job_id=? ORDER BY final_score DESC LIMIT ?",
                                (job_id, limit)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["symbols"] = json.loads(d.get("symbols") or "[]")
            out.append(d)
        return out

    def calibration_summary(self, job_id: int, thresholds: Iterable[float] | None = None,
                            *, engine: Any = None) -> dict:
        with self._conn() as conn:
            rows = conn.execute("SELECT folder, final_score FROM calibration_results WHERE job_id=? "
                                "AND final_score IS NOT NULL", (job_id,)).fetchall()
        scores = sorted(float(r["final_score"]) for r in rows)
        ts = list(thresholds) if thresholds is not None else [x / 2 for x in range(10, 31)]
        hist: dict[int, int] = {}
        for s in scores:
            b = int(max(-10, min(30, s // 1)))
            hist[b] = hist.get(b, 0) + 1
        mid = len(scores) // 2
        median = (scores[mid] if len(scores) % 2 else (scores[mid - 1] + scores[mid]) / 2) if scores else None
        return {"job_id": job_id, "count": len(scores), "folder": rows[0]["folder"] if rows else None,
                "min": scores[0] if scores else None, "max": scores[-1] if scores else None, "median": median,
                "histogram": [{"lo": b, "hi": b + 1, "n": hist[b]} for b in sorted(hist)],
                "caught_at": [{"threshold": t, "n": sum(1 for s in scores if s >= t)} for t in ts]}

    # -- health + misc ------------------------------------------------------------
    def rspamd_health(self, *, engine: Any = None) -> dict:
        return dict(self.health)

    def request_reload(self, reason: str, actor: str, *, engine: Any = None) -> bool:
        self.reloads.append((reason, actor))
        return True

    def known_providers(self, *, engine: Any = None) -> dict:
        return {"molt.example": {"imap_host": "mail.scannet.dk", "imap_port": 993, "provider": "Scannet"},
                "bynet.example": {"imap_host": "imap.gigahost.dk", "imap_port": 993, "provider": "Gigahost"}}

    def suggest_imap(self, email: str, *, engine: Any = None) -> dict:
        domain = email.rpartition("@")[2].lower()
        known = self.known_providers().get(domain)
        if known:
            return {**known, "guess": False}
        return {"imap_host": f"imap.{domain}", "imap_port": 993, "provider": None, "guess": True}

    def host_status(self, *, engine: Any = None) -> dict:
        if self._host is None:
            return {"available": False, "stale": True, "age_s": None}
        return dict(self._host, available=True, age_s=self._host.get("age_s", 60), stale=self._host.get("stale", False))

    def backup_status(self, *, engine: Any = None) -> dict:
        if self._backup is None:
            return {"available": False}
        return dict(self._backup, available=True)

    # -- 2.2 (B6): Bayes repair, learn lists, rebalancing -------------------------------------
    # Tests set .repair_items (bayes_repair_candidates items), .learn_lists
    # {id: job dict}, .learn_items {id: [item dicts]}, .rebalance (result
    # dict for the dry run / queue) and read .svc22_calls.
    repair_items: list
    learn_lists: dict
    learn_items: dict
    rebalance: dict | None

    def _rec(self, *call: Any) -> None:
        if not hasattr(self, "svc22_calls"):
            self.svc22_calls = []
        self.svc22_calls.append(call)

    def bayes_repair_candidates(self, account: str | None = None, *, scope: str = "learned_ham", limit: int = 500,
                                engine: Any = None) -> dict:
        self._rec("bayes_repair_candidates", account, scope, limit)
        items = [dict(i) for i in self.repair_items if account is None or i["account"] == account]
        if scope != "all":
            items = [i for i in items if i.get("learned_as") == "ham"]
        by_reason = {r: sum(1 for i in items if r in i["reasons"])
                     for r in ("phishing_rule", "user_marked_spam", "provider_spam")}
        return {"ok": True, "account": account, "scope": scope, "total": len(items), "truncated": len(items) > limit,
                "counts": {"by_reason": by_reason, "by_account": {}, "learned_ham": len(items)},
                "items": items[:limit]}

    def queue_learn_list(self, items: Iterable[Any], actor: str = "", *, kind: str = "spam", note: str = "",
                         engine: Any = None) -> dict:
        items = list(items)
        self._rec("queue_learn_list", items, actor, kind, note)
        jid = max(self.learn_lists or {0: None}) + 1
        self.learn_lists = {**self.learn_lists, jid: {
            "id": jid, "status": "queued", "total": len(items), "processed": 0, "learned": 0, "already": 0,
            "not_found": 0, "skipped": 0, "failed": 0, "note": note, "error": None, "created_by": actor,
            "created_at": int(time.time()), "started_at": None, "finished_at": None, "percent": 0,
            "remaining": len(items), "text": "Venter på at starte."}}
        return {"ok": True, "code": "queued", "job_id": jid, "total": len(items), "by_account": {}, "rejected": [],
                "text": f"{len(items)} mails lægges i kø til at blive lært som spam. Det sker i baggrunden – "
                        "ingen mails flyttes.", "audit_detail": f"learn_list job={jid} n={len(items)} kinds=spam"}

    def _ll_states(self, job: dict) -> tuple[str, ...]:
        # Mirrors services._retry_states.
        return ("failed", "deferred") + (("pending",) if job.get("status") in ("cancelled", "failed") else ())

    def _ll_with_retryable(self, job: dict) -> dict:
        d = dict(job)
        if "retryable" not in d:
            states = self._ll_states(job)
            d["retryable"] = sum(1 for i in self.learn_items.get(int(job["id"]), []) if i["status"] in states)
        return d

    def list_learn_list_jobs(self, limit: int = 20, *, engine: Any = None) -> list[dict]:
        return [self._ll_with_retryable(self.learn_lists[k])
                for k in sorted(self.learn_lists, reverse=True)][:limit]

    def learn_list_job(self, job_id: int, *, engine: Any = None) -> dict | None:
        job = self.learn_lists.get(int(job_id))
        return self._ll_with_retryable(job) if job else None

    def learn_list_items(self, job_id: int, *, status: str | None = None, account: str | None = None,
                         limit: int = 500, engine: Any = None) -> list[dict]:
        return [dict(i) for i in self.learn_items.get(int(job_id), [])
                if (status is None or i["status"] == status) and (account is None or i["account"] == account)][:limit]

    def cancel_learn_list_job(self, job_id: int, *, engine: Any = None) -> bool:
        self._rec("cancel_learn_list_job", job_id)
        job = self.learn_lists.get(int(job_id))
        if not job or job["status"] not in ("queued", "running"):
            return False
        job["status"] = "cancelled" if job["status"] == "queued" else "cancel_requested"
        return True

    def retry_learn_list(self, job_id: int, actor: str = "", *, engine: Any = None) -> dict:
        self._rec("retry_learn_list", job_id, actor)
        job = self.learn_lists.get(int(job_id)) or {}
        states = self._ll_states(job)
        failed = [i for i in self.learn_items.get(int(job_id), []) if i["status"] in states]
        if not failed:
            return {"ok": False, "code": "empty", "text": "Ingen gyldige mails at lære.", "job_id": None}
        return self.queue_learn_list(failed, actor, note=f"genforsøg af job {job_id}")

    def queue_bayes_rebalance(self, actor: str = "", *, accounts: Any = None, ratio: float = 0.5,
                              min_age_days: int = 3, max_per_folder: int = 2000, include_trash: bool = False,
                              dry_run: bool = False, engine: Any = None) -> dict:
        self._rec("queue_bayes_rebalance", actor, include_trash, dry_run)
        res = dict(self.rebalance or {
            "ok": True, "code": "plan", "bayes": {"spam": 256, "ham": 1448, "ratio": 0.177}, "target_ratio": 0.5,
            "needed": 468, "errors": [], "jobs": [
                {"account": "bynet", "folder": "Spamfilter", "label": "Spamfilter", "kind": "filter_junk",
                 "messages": 41, "max_messages": 41, "provider_filter": "any", "job_id": None},
                {"account": "molt", "folder": "Junk", "label": "Junk", "kind": "provider_junk", "messages": 189,
                 "max_messages": 189, "provider_filter": "any", "job_id": None}],
            "text": "Bayes har 256 spam og 1448 legitime. Der mangler ca. 468 spam for at nå 1:2; 2 spam-mapper kan "
                    "bruges."})
        if not dry_run and res.get("code") == "plan":
            res.update(code="queued", text="2 træningsjob lagt i kø. De stopper af sig selv.",
                       audit_detail="bayes_rebalance jobs=2 needed=468 ratio=0.5")
        res["dry_run"] = dry_run
        return res

    # -- 2.3 follow-up: 'Byg Bayes op på ny' -----------------------------------------------------
    # Shapes exactly as services.bayes_rebuild_plan / _start / _status /
    # bayes_restore_previous document them. The start/restore fakes write
    # the config through the save_config the UI hands in (like services).

    REBUILD_PLAN: dict = {
        "ok": True, "code": "plan", "pool_now": "hjemmeserver", "pool_new": "hjemmeserver-r1", "pools": ["hjemmeserver"],
        "ratio": 2.0, "min_learns": 200, "running": False, "errors": [], "warnings": [],
        "spam_sources": [
            {"account": "bynet", "folder": "Spamfilter", "label": "Spamfilter", "kind": "filter_junk",
             "messages": 412, "planned": 412},
            {"account": "molt", "folder": "Junk", "label": "Junk", "kind": "provider_junk", "messages": 189,
             "planned": 189},
            {"account": "bynet", "folder": "INBOX.Uønsket e-mail", "label": "Uønsket e-mail", "kind": "spam_folder",
             "messages": 23, "planned": 23},
            {"account": "bynet", "folder": None, "label": "Enkeltmails, der tidligere er lært som spam (godkendte "
             "lister og mails, brugeren selv har lagt i spam)", "kind": "learn_list", "messages": 37, "planned": 37}],
        "ham_sources": [
            {"account": "bynet", "folder": "Archive", "label": "Archive", "messages": 5210, "planned": 700},
            {"account": "molt", "folder": "Arkiv", "label": "Arkiv", "messages": 1420, "planned": 622},
            {"account": "bynet", "folder": "Archive.2019", "label": "2019", "messages": 0, "planned": 0}],
        "learn_list": {"total": 37, "by_account": {"bynet": 37}},
        "expected_spam": 661, "expected_ham": 1322,
        "text": "Planen lærer ca. 661 spam og 1.322 legitime i den nye pulje hjemmeserver-r1. Den gamle pulje hjemmeserver "
                "gemmes urørt."}

    def _rebuild_state(self) -> dict:
        if not hasattr(self, "_rebuild"):
            self._rebuild = {"status": None, "plan": None, "status_override": None}
        return self._rebuild

    def bayes_rebuild_plan(self, actor: str = "", *, ratio: float = 2.0, engine: Any = None) -> dict:
        self._rec("bayes_rebuild_plan", actor, ratio)
        st = self._rebuild_state()
        plan = json.loads(json.dumps(st["plan"] or self.REBUILD_PLAN))
        plan["ratio"] = ratio
        if st["status"] in ("starting", "running"):
            plan["running"] = True
            plan["warnings"] = [*plan.get("warnings", []), "En genopbygning er allerede i gang – vent, til den er færdig."]
        return plan

    def bayes_rebuild_start(self, actor: str, confirm: bool = True, *, ratio: float = 2.0, engine: Any = None,
                            save_config: Any = None) -> dict:
        self._rec("bayes_rebuild_start", actor, confirm, ratio, save_config)
        st = self._rebuild_state()
        plan = self.bayes_rebuild_plan(actor, ratio=ratio)
        if confirm is not True:
            return {"ok": False, "code": "confirm", "text": "Bekræft, at Bayes skal bygges op på ny."}
        if plan["running"]:
            return {"ok": False, "code": "running", "text": "En genopbygning er allerede i gang."}
        if plan["expected_spam"] <= 0:
            return {"ok": False, "code": "nothing", "text": "Der er ingen spam at lære fra – intet er ændret."}
        pool_new = plan["pool_new"]

        def apply(raw: dict) -> None:
            raw.setdefault("defaults", {})["bayes_user"] = pool_new

        detail = f"rebuild=1 {plan['pool_now']}->{pool_new} spam~{plan['expected_spam']} ham~{plan['expected_ham']}"
        try:
            save_config(apply, actor, "bayes_rebuild", detail=detail)
        except ValueError as ex:
            return {"ok": False, "code": "rejected", "text": f"Ændringen blev afvist: {ex}"}
        st["status"] = "running"
        return {"ok": True, "code": "started", "rebuild_id": 1, "pool_old": plan["pool_now"], "pool_new": pool_new,
                "jobs": 6, "expected_spam": plan["expected_spam"], "expected_ham": plan["expected_ham"],
                "warnings": [], "audit_detail": detail,
                "text": f"Bayes bygges op på ny i puljen {pool_new}: ca. {plan['expected_spam']} spam og "
                        f"{plan['expected_ham']} legitime lægges i kø (6 job)."}

    def bayes_rebuild_status(self, *, engine: Any = None) -> dict:
        st = self._rebuild_state()
        if st["status_override"] is not None:
            return json.loads(json.dumps(st["status_override"]))
        base = {"ok": True, "code": "none", "rebuild_id": None, "pool": "hjemmeserver", "pool_old": None,
                "pool_new": None, "created_at": None, "created_by": None, "finished_at": None, "restored_at": None,
                "ratio": None, "expected_spam": 0, "expected_ham": 0, "learned_spam": 0, "learned_ham": 0,
                "percent": 0, "jobs": {}, "bayes": {"ok": True, "spam": 256, "ham": 1448, "active": True,
                                                    "counts_source": "rspamd"},
                "min_learns": 200, "missing_spam": 0, "missing_ham": 0, "can_restore": False, "warnings": [],
                "text": "Bayes er ikke bygget op på ny. Aktiv pulje: hjemmeserver."}
        if st["status"] == "running":
            base.update(code="running", rebuild_id=1, pool="hjemmeserver-r1", pool_old="hjemmeserver", pool_new="hjemmeserver-r1",
                        created_at=int(time.time()) - 900, created_by="admin", expected_spam=661, expected_ham=1322,
                        learned_spam=148, learned_ham=96, percent=12, jobs={"done": 2, "running": 1, "queued": 3},
                        bayes={"ok": True, "spam": 148, "ham": 96, "active": False, "counts_source": "pool"},
                        missing_spam=52, missing_ham=104, can_restore=True,
                        text="Genopbygning i gang (12 %): 148 af ca. 661 spam og 96 af ca. 1.322 legitime er lært i "
                             "puljen hjemmeserver-r1.")
        elif st["status"] == "restored":
            base.update(code="restored", rebuild_id=1, pool="hjemmeserver", pool_old="hjemmeserver", pool_new="hjemmeserver-r1",
                        created_at=int(time.time()) - 3600, created_by="admin", restored_at=int(time.time()),
                        text="Den tidligere Bayes-pulje (hjemmeserver) er gendannet. Puljen hjemmeserver-r1 ligger urørt og "
                             "bruges ikke.")
        return base

    def bayes_restore_previous(self, actor: str, confirm: bool = True, *, engine: Any = None,
                               save_config: Any = None) -> dict:
        self._rec("bayes_restore_previous", actor, confirm, save_config)
        st = self._rebuild_state()
        if confirm is not True:
            return {"ok": False, "code": "confirm", "text": "Bekræft, at den tidligere Bayes skal gendannes."}
        if st["status"] not in ("running", "done", "failed"):
            return {"ok": False, "code": "nothing", "text": "Der er ingen tidligere Bayes at gendanne."}

        def apply(raw: dict) -> None:
            raw.setdefault("defaults", {})["bayes_user"] = "hjemmeserver"

        try:
            save_config(apply, actor, "bayes_restore", detail="rebuild=1 hjemmeserver-r1->hjemmeserver")
        except ValueError as ex:
            return {"ok": False, "code": "rejected", "text": f"Ændringen blev afvist: {ex}"}
        st["status"] = "restored"
        return {"ok": True, "code": "restored", "rebuild_id": 1, "pool": "hjemmeserver",
                "audit_detail": "rebuild=1 hjemmeserver-r1->hjemmeserver",
                "text": "Den tidligere Bayes (hjemmeserver) er gendannet. Puljen hjemmeserver-r1 ligger urørt og bruges ikke. "
                        "Filteret genindlæser om et øjeblik."}

    # -- 2.2 (B21): weekly report ----------------------------------------------------------------

    def _kv(self, key: str) -> str | None:
        with self._conn() as conn:
            try:
                row = conn.execute("SELECT value FROM settings_kv WHERE key=?", (key,)).fetchone()
            except sqlite3.Error:
                return None
        return row["value"] if row else None

    def weekly_settings(self, *, engine: Any = None) -> dict:
        chosen = self._kv("weekly_admin_account") or None
        names = ["bynet", "molt"]
        return {"enabled": self._kv("weekly_enabled") == "1", "admin_account": chosen,
                "admin_account_effective": chosen if chosen in names else "bynet",
                "users": self._kv("weekly_users") == "1", "external_url": self._kv("external_url")}

    def weekly_preview(self, account: str | None = None, week: str | None = None, *, full: bool | None = None,
                       engine: Any = None) -> dict:
        self._rec("weekly_preview", account, week)
        if week is not None and not (len(week) == 8 and week[4:6] == "-W"):
            return {"ok": False, "code": "invalid", "text": "Ugen skal skrives som ÅÅÅÅ-Uuu (fx 2026-W43)."}
        wk = week or "2026-W42"
        full = account in (None, "bynet") if full is None else full
        line = "Webshop-post: 12 mails fra pinsikbing.example/gravisk.example/vexar.example – 0 flyttet"
        text = (f"Hej\n\nUgerapport for uge {int(wk[6:])} (12.–18. oktober 2026).\n\n"
                + ("bynet: 410 scannet, 58 flyttet, 0 frigivet\nmolt: 120 scannet, 9 flyttet\n" if full
                   else f"{account}: 120 scannet, 9 flyttet\n") + f"\n{line}\n")
        html_body = ('<html><body style="font-family:sans-serif"><p>Hej</p>'
                     f'<p style="color:#16a34a"><strong>{line}</strong></p></body></html>')
        return {"ok": True, "code": "ok", "text": "", "week": wk, "full": full,
                "subject": f"[Prøve] Spamfilter: ugerapport for uge {int(wk[6:])}", "body_text": text,
                "body_html": html_body,
                "data": {"week": wk, "prev_week": f"{wk[:6]}{int(wk[6:]) - 1:02d}", "span": "12.–18. oktober 2026"}}

    def send_weekly_now(self, account: str, *, preview: bool = True, week: str | None = None,
                        full: bool | None = None, actor: str = "", engine: Any = None) -> dict:
        self._rec("send_weekly_now", account, preview, week, actor)
        if account == "sofie":
            return {"ok": False, "code": "auth", "text": "Mailserveren afviste login."}
        return {"ok": True, "code": "sent", "text": "Ugerapporten er lagt i indbakken.", "week": week or "2026-W42",
                "message_id": "<weekly-x@hjemmeserver.spamfilter>", "full": account == "bynet",
                "audit_detail": f"weekly_report {account} week={week or '2026-W42'} preview"}


SECRET = "imap-hemmelighed"

HOST_STATUS = {
    "version": 1, "ts": int(time.time()) - 60, "host": "Hjemmeserver",
    "containers": {
        "spamfilter": {"exists": True, "running": True, "status": "running", "health": "healthy",
                       "started_at": "2026-10-20T13:02:11Z", "restart_count": 0, "image": "imap-spamfilter-unraid:2.0.0"},
        "spamfilter-rspamd": {"exists": True, "running": True, "status": "running", "health": None,
                              "started_at": "2026-10-20T12:58:40Z", "restart_count": 0, "image": "rspamd/rspamd:3.10"},
        "spamfilter-redis": {"exists": True, "running": True, "status": "running", "health": None,
                             "started_at": "2026-10-19T03:00:02Z", "restart_count": 1, "image": "redis:7-alpine"},
        "spamfilter-unbound": {"exists": True, "running": False, "status": "exited", "health": None,
                               "started_at": "2026-10-19T03:00:02Z", "restart_count": 4, "image": "mvance/unbound:1.21"},
    },
    "disk": {"docker_img": {"path": "/var/lib/docker", "size": 64e9, "used": 41e9, "avail": 23e9, "pct": 64},
             "appdata": {"path": "/mnt/user/appdata", "size": 1e12, "used": 9.2e11, "avail": 8e10, "pct": 92,
                         "spamfilter_bytes": 180_000_000}},
    "rspamd": {"ok": True, "ms": 41},
    "dns": {"query": "2.0.0.127.zen.spamhaus.org", "ok": True, "verdict": "ok", "rcode": "NOERROR",
            "answers": ["127.0.0.2"], "ms": 23},
    "rbl": {"window_s": 900, "scans": 40, "scans_with_dns_fail": 2, "fail_rate": 0.05, "dns_limit_hits": 0,
            "unbound_servfail": 3},
    "heartbeat": {"age_s": 12},
    "alerts": [{"key": "disk:appdata", "level": "warning", "text": "appdata er 92 % fuld", "since": 0, "age_s": 3600}],
}
BACKUP = {"ok": True, "ts": int(time.time()) - 5 * 3600, "archive": "/mnt/backup/spamfilter-20261020-0300.tar.zst",
          "size": 48_000_000, "error": None, "age_s": 5 * 3600}


def make_admin_env(tmp_path: Path, monkeypatch: Any, *, host_status: dict | None = HOST_STATUS,
                   backup: dict | None = BACKUP) -> Any:
    """make_env() + ui_admin routes, a real accounts.yml (bynet move,
    molt shadow, sofie paused), secrets on disk and the admin fakes."""
    import dashboard
    import ui_admin  # noqa: F401 - registers the admin routes

    env = make_env(tmp_path, monkeypatch)
    secrets = env.state / "imap-secrets"
    secrets.mkdir(mode=0o700)
    for name in ("bynet", "molt", "sofie"):
        (secrets / name).write_text(SECRET)
        (secrets / name).chmod(0o600)
    cfg = {"defaults": {"bayes_user": "hjemmeserver", "junk_retention_days": 0},
           "accounts": [
               {"name": "bynet", "user": "ole@bynet.example", "imap_host": "imap.gigahost.dk",
                "password_file": str(secrets / "bynet"), "mode": "move", "junk": "Spamfilter"},
               {"name": "molt", "user": "ole@molt.example", "imap_host": "mail.scannet.dk",
                "password_file": str(secrets / "molt"), "threshold": 6.0},
               {"name": "sofie", "user": "sofie@molt.example", "imap_host": "mail.scannet.dk", "enabled": False,
                "password_file": str(secrets / "sofie")},
           ]}
    env.config.write_text(yaml.safe_dump(cfg, sort_keys=False))
    eng = FakeAdminEngine()
    svc = FakeAdminServices(env.state / "spamfilter.db", host_status=host_status, backup=backup)
    monkeypatch.setattr(dashboard, "engine", eng)
    monkeypatch.setattr(dashboard, "services", svc)
    env.conn.executescript(CALIBRATION_SCHEMA)
    env.conn.commit()
    env.engine, env.services, env.secrets = eng, svc, secrets

    def raw_config() -> dict:
        return yaml.safe_load(env.config.read_text())

    def entry(name: str) -> dict:
        return next(a for a in raw_config()["accounts"] if a["name"] == name)

    env.raw_config, env.entry = raw_config, entry
    return env
