"""Bayes training and calibration jobs (train_jobs table).

One daemon thread (started by the engine's main()) polls train_jobs every
5 s and runs the oldest queued job, one at a time:

  1. connect, SELECT the folder READ-ONLY (EXAMINE) - the trainer never
     writes to IMAP;
  2. UID SEARCH (SEEN / BEFORE <date> as requested), newest first;
  3. header pass in chunks: RFC822.SIZE + header block, applying the size
     cap and the provider filter (mailctx on the headers) until
     max_messages candidates are selected;
  4. body pass in chunks of 20 (BODY.PEEK[]), at most 5 learns/scans per
     second, progress written after each chunk, cancel honoured between
     chunks.

kind 'spam'/'ham' learns through engine.learn_message (same safeguards and
bookkeeping as every other learn, hourly cap bypassed - this limiter is
the bound). kind 'calibrate' only scans (engine.rspamd_scan with the
mailctx context) and stores calibration_results; it never learns.

A job interrupted by shutdown goes back to 'queued' and restarts from
scratch on the next start; already-learned mail is skipped cheaply.

Calibration rows also store `blind_score` (see blind_score()). The same
thread resumes the services' bulk-undo jobs (undo_jobs) after a restart.

2.2 additions:
  * B6c ham guard: a 'ham' job scans every message first (read-only
    /checkv2) and skips it (event 'ham_guard') when engine.ham_guard_reason
    objects - phishing/threat rules, a blind score >= 5, a blocked sender,
    or a score over the account threshold;
  * B6b: train_jobs.stop_ratio (additive) ends a spam job as soon as the
    shared Bayes reaches spam:ham >= stop_ratio (services.queue_bayes_rebalance);
  * B6a: learn-list jobs (additive tables learn_list_jobs/learn_list_items,
    see LEARN_LIST_SCHEMA): an owner-approved list of {account, Message-ID,
    kind} learned one message at a time from wherever it is (read-only
    EXAMINE + exact Message-ID search). The only way INBOX mail is learned
    as spam: per message and approved by the owner;
  * B7: calibration scans mail older than aged_scan_hours in aged mode and
    stores calibration_results.aged.
"""

from __future__ import annotations

import datetime as dt
import inspect
import json
import logging
import sqlite3
import threading
import time
from contextlib import closing
from dataclasses import dataclass, field
from typing import Any, Callable

from imapclient.exceptions import IMAPClientAbortError, IMAPClientError

import mailctx

log = logging.getLogger("trainer")

POLL_INTERVAL_S = 5
HEADER_CHUNK = 50          # header-only FETCHes are small
BODY_CHUNK = 20
MAX_PER_SECOND = 5.0
MAX_EXAMINED = 10_000      # bound the header pass when filters reject a lot
MAX_CONSECUTIVE_FAILURES = 10

_thread: threading.Thread | None = None
_thread_lock = threading.Lock()


class JobAborted(Exception):
    """Stop the job with a safe Danish text stored in train_jobs.error."""

    def __init__(self, text: str) -> None:
        super().__init__(text)
        self.text = text


class _RebuildCap(Exception):
    """A Bayes rebuild ham job reached its share of ratio x spam."""


class _Interrupted(Exception):
    """Shutdown or cancel observed between chunks."""

    def __init__(self, status: str) -> None:
        super().__init__(status)
        self.status = status


def _eng(engine: Any = None) -> Any:
    if engine is not None:
        return engine
    import filter as engine_module  # lazy: filter.py starts us from main()

    return engine_module


def _open_db(eng: Any) -> sqlite3.Connection:
    conn = sqlite3.connect(str(eng.DB_PATH), timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def _shutdown_event(eng: Any) -> threading.Event | None:
    ev = getattr(eng, "SHUTDOWN", None)
    return ev if isinstance(ev, threading.Event) else None


class RateLimiter:
    """At most `per_second` calls to wait(); clock/sleep injectable for tests."""

    def __init__(self, per_second: float, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.interval = 1.0 / per_second
        self.clock = clock
        self.sleep = sleep
        self.next_at: float | None = None

    def wait(self) -> None:
        now = self.clock()
        if self.next_at is not None and now < self.next_at:
            self.sleep(self.next_at - now)
            now = self.next_at
        self.next_at = now + self.interval


@dataclass
class Candidate:
    uid: int
    size: int
    message_id: str | None
    subject: str
    sender: str
    received_at: int | None
    seen: bool
    ctx: dict[str, Any] = field(default_factory=dict)


@dataclass
class Counters:
    total: int = 0
    processed: int = 0
    learned: int = 0
    skipped: int = 0
    failed: int = 0


# ---------------------------------------------------------------------------
# IMAP passes
# ---------------------------------------------------------------------------


def _criteria(seen_only: bool, min_age_days: int, today: dt.date | None = None) -> list[Any]:
    crit: list[Any] = []
    if seen_only:
        crit.append("SEEN")
    if min_age_days and min_age_days > 0:
        crit += ["BEFORE", (today or dt.date.today()) - dt.timedelta(days=int(min_age_days))]
    return crit or ["ALL"]


def _flags(data: dict) -> set[str]:
    out = set()
    for f in data.get(b"FLAGS") or ():
        out.add(f.decode("ascii", "replace") if isinstance(f, bytes) else str(f))
    return out


def _internaldate(data: dict) -> int | None:
    v = data.get(b"INTERNALDATE")
    try:
        return int(v.timestamp()) if v is not None else None
    except (AttributeError, OverflowError, OSError, ValueError):
        return None


def _wanted(ctx: dict[str, Any], provider_filter: str) -> bool:
    if provider_filter == "any":
        return True
    verdict = mailctx.provider_verdict(ctx)
    if provider_filter == "provider_spam":
        return verdict == "spam"
    if provider_filter == "provider_clean":
        return verdict == "clean"
    return False


def select_candidates(eng: Any, client: Any, acc: Any, *, max_messages: int,
                      seen_only: bool = False, min_age_days: int = 0,
                      provider_filter: str = "any",
                      check: Callable[[], None] | None = None,
                      ) -> tuple[list[Candidate], int]:
    """Header pass on the selected folder. Returns (candidates newest
    first, number skipped for size)."""
    cap = int(getattr(eng, "MAX_FETCH_BYTES", 5 * 1024 * 1024))
    uids = sorted((int(u) for u in client.search(_criteria(seen_only, min_age_days))), reverse=True)
    uids = uids[:MAX_EXAMINED]
    selected: list[Candidate] = []
    oversize = 0
    for start in range(0, len(uids), HEADER_CHUNK):
        if len(selected) >= max_messages:
            break
        if check is not None:
            check()
        chunk = uids[start : start + HEADER_CHUNK]
        data = client.fetch(chunk, [b"RFC822.SIZE", b"FLAGS", b"INTERNALDATE", b"BODY.PEEK[HEADER]"])
        for uid in chunk:  # keep newest-first order (FETCH replies are unordered)
            if len(selected) >= max_messages:
                break
            d = data.get(uid)
            if not d:
                continue
            header = d.get(b"BODY[HEADER]") or d.get(b"BODY.PEEK[HEADER]") or b""
            ctx = mailctx.scan_context(header, acc)
            if not _wanted(ctx, provider_filter):
                continue
            try:
                size = int(d.get(b"RFC822.SIZE") or 0)
            except (TypeError, ValueError):
                size = 0
            if size <= 0 or size > cap:
                oversize += 1
                continue
            try:
                msgid, subject, sender = eng.parse_envelope(bytes(header))
            except Exception:
                msgid, subject, sender = None, "", ""
            selected.append(Candidate(
                uid=uid, size=size, message_id=msgid, subject=subject or "",
                sender=sender or "", received_at=_internaldate(d),
                seen="\\Seen" in _flags(d), ctx=ctx))
    return selected, oversize


def _connect_readonly(eng: Any, acc: Any, folder: str) -> Any:
    try:
        password = eng.read_secret(acc)
    except Exception:
        raise JobAborted("Adgangskoden til kontoen mangler.") from None
    try:
        client = eng.connect(acc, password=password)
    except Exception as ex:
        log.warning("trainer connect failed for %s: %s", acc.name, type(ex).__name__)
        raise JobAborted("Kunne ikke logge ind på mailserveren.") from None
    try:
        client.select_folder(folder, readonly=True)  # EXAMINE: never writes
    except Exception as ex:
        log.warning("trainer select %r failed: %s", folder, type(ex).__name__)
        _logout(client)
        raise JobAborted("Mappen findes ikke eller kunne ikke åbnes.") from None
    return client


def _logout(client: Any) -> None:
    try:
        client.logout()
    except Exception:
        pass


def _find_account(eng: Any, name: str) -> Any:
    try:
        accounts = eng.load_account_configs(eng.CONFIG_PATH)
    except Exception:
        raise JobAborted("Konfigurationen kunne ikke indlæses.") from None
    for acc in accounts:
        if acc.name == name:
            return acc
    raise JobAborted("Kontoen findes ikke længere.")


# ---------------------------------------------------------------------------
# Calibration honesty: the "blind" score
# ---------------------------------------------------------------------------
#
# A calibration of the provider's Junk folder is flattering: that mail
# carries the provider's own verdict (X-Spam-Flag -> SPAM_FLAG, our
# TH_PROVIDER_* bonus) and is typically the very mail Bayes was trained on
# (BAYES_SPAM). Those symbols "know the answer", so the catch rate at a
# threshold looks better than it will be for new, unseen spam. The blind
# score drops them and shows what the remaining rules catch on their own.

BLIND_EXCLUDED_EXACT = frozenset({"SPAM_FLAG"})
BLIND_EXCLUDED_PREFIXES = ("TH_PROVIDER_", "BAYES_")


# 2.2: TH_PROVIDER_AUTH_* (aged scans) is the provider's authentication
# record at delivery, not its spam verdict - it stays in the blind score.
BLIND_KEPT_PREFIXES = ("TH_PROVIDER_AUTH_",)


def is_blind_excluded(name: Any) -> bool:
    n = str(name or "").upper()
    if n.startswith(BLIND_KEPT_PREFIXES):
        return False
    return n in BLIND_EXCLUDED_EXACT or n.startswith(BLIND_EXCLUDED_PREFIXES)


def blind_score(final: Any, symbols: Any) -> float | None:
    """final score minus SPAM_FLAG, TH_PROVIDER_* and BAYES_* contributions
    (symbols in the stored `[{"n","s"}]` format). None if final is None."""
    if final is None:
        return None
    try:
        total = float(final)
    except (TypeError, ValueError):
        return None
    for sym in symbols or ():
        if isinstance(sym, dict) and is_blind_excluded(sym.get("n")):
            try:
                total -= float(sym.get("s") or 0)
            except (TypeError, ValueError):
                pass
    return round(total, 3)


_blind_column_ok: set[str] = set()


def ensure_blind_column(conn: sqlite3.Connection) -> bool:
    """Additive: calibration_results.blind_score REAL and (2.2) aged INTEGER
    (older code ignores both)."""
    key = str(conn.execute("PRAGMA database_list").fetchone()[2])
    if key in _blind_column_ok:
        return True
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(calibration_results)")}
        if cols and "blind_score" not in cols:
            conn.execute("ALTER TABLE calibration_results ADD COLUMN blind_score REAL")
        if cols and "aged" not in cols:
            conn.execute("ALTER TABLE calibration_results ADD COLUMN aged INTEGER")
        ok = bool(cols)
    except sqlite3.Error as ex:
        log.warning("blind_score column check failed: %s", type(ex).__name__)
        return False
    if ok:
        _blind_column_ok.add(key)
    return ok


# ---------------------------------------------------------------------------
# Job execution
# ---------------------------------------------------------------------------


def _learn_kwargs(eng: Any) -> dict[str, Any]:
    """bypass_rate=True when the engine's learn_message supports it."""
    try:
        params = inspect.signature(eng.learn_message).parameters
    except (TypeError, ValueError):
        return {}
    if "bypass_rate" in params or any(p.kind is p.VAR_KEYWORD for p in params.values()):
        return {"bypass_rate": True}
    return {}


def _already_learned(conn: sqlite3.Connection, account: str, msgid: str | None, kind: str) -> bool:
    if not msgid:
        return False
    try:
        row = conn.execute(
            "SELECT learned_as FROM messages WHERE account=? AND message_id=?",
            (account, msgid)).fetchone()
    except sqlite3.Error:
        return False
    return row is not None and row["learned_as"] == kind


def _own_mail(eng: Any, conn: sqlite3.Connection, account: str, msgid: str | None) -> bool:
    """A receipt / report / threat notice / notification THIS filter made
    (engine.is_own_registered): never learned, also not from an archive."""
    fn = getattr(eng, "is_own_registered", None)
    if fn is None or not msgid:
        return False
    try:
        return bool(fn(conn, account, msgid))
    except Exception:  # noqa: BLE001
        return False


def _rebuild_conflict(conn: sqlite3.Connection, rb: sqlite3.Row | None, account: str,
                      msgid: str | None, kind: str) -> bool:
    """Bayes rebuild jobs bypass the flip-flop cooldown, so they must never
    flip a message within the rebuild: a mail the rebuild already learned
    as the other class (e.g. a user's spam verdict on the learn list that
    now lives in an archive folder) is skipped, and ham is never learned
    for a mail with a user spam verdict, a threat class or a reverted ham
    autolearn."""
    if rb is None or not msgid:
        return False
    try:
        row = conn.execute("SELECT * FROM messages WHERE account=? AND message_id=?",
                           (account, msgid)).fetchone()
    except sqlite3.Error:
        return False
    if row is None:
        return False
    keys = row.keys()
    other = "ham" if kind == "spam" else "spam"
    if row["learned_as"] == other:
        return True
    if kind == "ham":
        if "user_verdict" in keys and row["user_verdict"] == "spam":
            return True
        if "our_action" in keys and row["our_action"] in ("user_junked", "manual_mark_spam"):
            return True
        if "threat" in keys and row["threat"]:
            return True
        try:
            # An admin reverted an automatic ham learn of this mail: not ham.
            if conn.execute("SELECT 1 FROM autolearn_log WHERE account=? AND message_id=? AND kind='ham' "
                            "AND reverted_at IS NOT NULL", (account, msgid)).fetchone():
                return True
        except sqlite3.Error:
            pass
    return False


def _write_progress(conn: sqlite3.Connection, job_id: int, c: Counters) -> None:
    conn.execute(
        "UPDATE train_jobs SET total=?, processed=?, learned=?, skipped=?, failed=? WHERE id=?",
        (c.total, c.processed, c.learned, c.skipped, c.failed, job_id))


def _check(eng: Any, conn: sqlite3.Connection, job_id: int) -> None:
    ev = _shutdown_event(eng)
    if ev is not None and ev.is_set():
        raise _Interrupted("queued")
    row = conn.execute("SELECT status FROM train_jobs WHERE id=?", (job_id,)).fetchone()
    if row is None or row["status"] == "cancel_requested":
        raise _Interrupted("cancelled")


def _learn_one(eng: Any, db: Any, acc: Any, job: sqlite3.Row, raw: bytes,
               cand: Candidate, kwargs: dict[str, Any]) -> str:
    kind = job["kind"]
    if cand.message_id:
        return str(eng.learn_message(db, acc, raw, kind, cand.message_id,
                                     actor=job["created_by"] or "",
                                     reason=f"bootstrap job={job['id']}", **kwargs))
    # No Message-ID means no per-message bookkeeping; learn directly (rspamd
    # itself answers 208 for repeats) and record the event/stat here.
    outcome = str(eng.rspamd_learn(raw, kind, eng.bayes_identity(acc)))
    if outcome == "learned":
        try:
            with db.tx():
                db.log_event(f"learn_{kind}", None, detail=f"job={job['id']} uden Message-ID")
            eng.bump_stat(db.conn, acc.name, f"learned_{kind}")
        except Exception as ex:
            log.warning("trainer bookkeeping failed: %s", type(ex).__name__)
    return outcome


def _accepts_kw(fn: Any, name: str) -> bool:
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False
    return name in params or any(p.kind is p.VAR_KEYWORD for p in params.values())


def _aged(eng: Any, acc: Any, received_at: Any) -> bool:
    fn = getattr(eng, "is_aged", None)
    try:
        return bool(fn(acc, received_at)) if fn is not None else False
    except Exception:
        return False


def scan_scored(eng: Any, acc: Any, raw: bytes, ctx: dict[str, Any],
                received_at: Any, conn: sqlite3.Connection | None = None
                ) -> tuple[Any, list[dict], float, bool]:
    """Score one message like the live scanner (provider bonus, B7 aged
    mode, B2 own-platform offset and - with a DB connection - the 2.3
    trust signals of known contacts/replies/established senders):
    (ScanResult, all symbols incl. pseudo symbols, final score, aged).
    Read-only; raises like rspamd_scan."""
    aged = _aged(eng, acc, received_at)
    if aged and _accepts_kw(eng.rspamd_scan, "aged"):
        result = eng.rspamd_scan(raw, acc, ctx, aged=True)
    else:
        aged = False
        result = eng.rspamd_scan(raw, acc, ctx)
    if result is None or getattr(result, "score", None) is None:
        return result, [], 0.0, aged
    symbols = list(getattr(result, "symbols", None) or [])
    bonus = (mailctx.effective_bonus(mailctx.provider_bonus(ctx), symbols)
             if getattr(acc, "provider_bonus", True) else [])
    if aged and getattr(eng, "aged_symbols", None) is not None:
        try:
            bonus += list(eng.aged_symbols(ctx, eng.scan_age_s(received_at)))
        except Exception as ex:
            log.warning("aged symbols failed: %s", type(ex).__name__)
    offset = getattr(eng, "own_platform_offset", None)
    if offset is not None and getattr(result, "names", None) is not None:
        try:
            sym, _event = offset(acc, result, result.names)
            if sym is not None:
                bonus.append(sym)
        except Exception as ex:
            log.warning("own platform offset failed: %s", type(ex).__name__)
    heur_fn = getattr(eng, "clam_heuristic_symbol", None)
    if heur_fn is not None:
        try:
            heur = heur_fn(result)
            if heur is not None:
                bonus.append(heur)
        except Exception as ex:
            log.warning("clam heuristic failed: %s", type(ex).__name__)
    # 2.7 fix: the name-spoof check like the live scan (TH_NAME_SPOOF scores
    # and - passed on in extra_names below - blocks every trust bonus).
    ns_fn = getattr(eng, "namespoof_symbols", None)
    auth_fn = getattr(eng, "_sender_auth", None)
    if conn is not None and ns_fn is not None and auth_fn is not None and getattr(result, "names", None) is not None:
        try:
            names = set(result.names) | {str(b.get("n")) for b in bonus if isinstance(b, dict)}
            ns_syms, _events = ns_fn(conn, acc, raw, names, auth_fn(result, ctx or {}))
            bonus += list(ns_syms or [])
        except Exception as ex:
            log.warning("name spoof check failed: %s", type(ex).__name__)
    tr_fn = getattr(eng, "trial_symbols", None)
    if tr_fn is not None and getattr(result, "names", None) is not None:
        try:
            names = set(result.names) | {str(b.get("n")) for b in bonus if isinstance(b, dict)}
            tr_syms, _events = tr_fn(conn, acc, raw, result, names)
            bonus += list(tr_syms or [])
        except Exception as ex:
            log.warning("trial protections failed: %s", type(ex).__name__)
    final = float(result.score) + sum(float(b["s"]) for b in bonus)
    trust_fn = getattr(eng, "contact_trust_symbols", None)
    if conn is not None and trust_fn is not None:
        try:
            extra = [str(b.get("n")) for b in bonus if isinstance(b, dict) and b.get("n")]
            if _accepts_kw(trust_fn, "extra_names"):
                trust = list(trust_fn(conn, acc, raw, ctx, result, round(final, 3), extra_names=extra) or [])
            else:
                trust = list(trust_fn(conn, acc, raw, ctx, result, round(final, 3)) or [])
        except Exception as ex:
            log.warning("contact trust failed: %s", type(ex).__name__)
            trust = []
        bonus += trust
        final += sum(float(t.get("s") or 0) for t in trust)
    return result, symbols + bonus, round(final, 3), aged


def _calibrate_one(eng: Any, conn: sqlite3.Connection, acc: Any, job: sqlite3.Row,
                   raw: bytes, cand: Candidate) -> bool:
    ctx = mailctx.scan_context(raw, acc)
    result, all_syms, final, aged = scan_scored(eng, acc, raw, ctx, cand.received_at, conn)
    if result is None or getattr(result, "score", None) is None:
        return False
    rspamd_score = float(result.score)
    symbols = list(getattr(result, "symbols", None) or [])
    bonus = all_syms[len(symbols):]
    blind = blind_score(final, symbols + bonus)  # full list, before the top-30 cut
    symbols = sorted(symbols + bonus, key=lambda s: abs(float(s.get("s") or 0)), reverse=True)[:30]
    flag = ctx.get("provider_flag")
    msgid = cand.message_id or f"uid:{cand.uid}"
    values = (job["id"], acc.name, job["folder"], msgid, round(final, 3), round(rspamd_score, 3),
              json.dumps(symbols, ensure_ascii=False), cand.sender[:200] or None,
              cand.subject[:500] or None, cand.received_at, int(cand.seen),
              None if flag is None else int(bool(flag)), ctx.get("provider_score"))
    if ensure_blind_column(conn):
        conn.execute(
            """
            INSERT OR REPLACE INTO calibration_results(job_id, account, folder, message_id,
                final_score, rspamd_score, symbols, sender, subject, received_at, seen,
                provider_flag, provider_score, blind_score, aged)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, values + (blind, 1 if aged else 0))
    else:
        conn.execute(
            """
            INSERT OR REPLACE INTO calibration_results(job_id, account, folder, message_id,
                final_score, rspamd_score, symbols, sender, subject, received_at, seen,
                provider_flag, provider_score)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, values)
    return True


def _ham_guard(eng: Any, conn: sqlite3.Connection, acc: Any, raw: bytes,
               cand: Candidate) -> tuple[str, str] | None:
    """B6c for a ham job: scan (read-only) and ask engine.ham_guard_reason.
    The trust limit is the account threshold: a mail rspamd itself scores
    as spam is never learned as ham. Raises when the scan fails."""
    ctx = mailctx.scan_context(raw, acc)
    result, symbols, final, _aged_scan = scan_scored(eng, acc, raw, ctx, cand.received_at)
    if result is None or getattr(result, "score", None) is None:
        raise ValueError("scan without score")
    return eng.ham_guard_reason(conn, acc.name, symbols=symbols, final=final,
                                rspamd_score=float(result.score), sender=cand.sender or None,
                                envelope_from=ctx.get("envelope_from"),
                                trust_limit=float(getattr(acc, "threshold", 8.0) or 8.0))


def _log_guard(eng: Any, db: Any, acc: Any, job_id: int, cand: Candidate,
               guard: tuple[str, str]) -> None:
    try:
        with db.tx():
            db.log_event("ham_guard", cand.message_id, detail=f"job={job_id} {guard[0]}: {guard[1]}"[:300])
        eng.bump_stat(db.conn, acc.name, "ham_guarded")
    except Exception as ex:
        log.warning("ham_guard bookkeeping failed: %s", type(ex).__name__)


_train_columns_ok: set[str] = set()


def ensure_train_columns(conn: sqlite3.Connection) -> bool:
    """Additive: train_jobs.stop_ratio REAL (2.2 B6b; older code ignores it
    and simply learns up to max_messages)."""
    key = str(conn.execute("PRAGMA database_list").fetchone()[2])
    if key in _train_columns_ok:
        return True
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(train_jobs)")}
        if cols and "stop_ratio" not in cols:
            conn.execute("ALTER TABLE train_jobs ADD COLUMN stop_ratio REAL")
    except sqlite3.Error as ex:
        log.warning("train_jobs column check failed: %s", type(ex).__name__)
        return False
    if cols:
        _train_columns_ok.add(key)
    return bool(cols)


def bayes_ratio(eng: Any) -> float | None:
    """spam/ham learns of the shared Bayes (services.bayes_stats), None
    when unknown."""
    fn = _services_fn("bayes_stats")
    if fn is None:
        return None
    try:
        st = fn(engine=eng)
    except Exception as ex:
        log.warning("bayes_stats failed: %s", type(ex).__name__)
        return None
    if not st or not st.get("ok"):
        return None
    spam, ham = int(st.get("spam_learned") or 0), int(st.get("ham_learned") or 0)
    if ham <= 0:
        return float("inf") if spam > 0 else None
    return spam / ham


def _ratio_reached(eng: Any, job: sqlite3.Row) -> bool:
    try:
        target = job["stop_ratio"] if "stop_ratio" in job.keys() else None
    except (IndexError, KeyError):
        target = None
    if not target or job["kind"] != "spam":
        return False
    ratio = bayes_ratio(eng)
    return ratio is not None and ratio >= float(target)


def _finish(conn: sqlite3.Connection, job_id: int, status: str, c: Counters,
            error: str | None = None) -> None:
    finished = None if status == "queued" else int(time.time())
    conn.execute(
        "UPDATE train_jobs SET status=?, error=?, finished_at=?, total=?, processed=?, "
        "learned=?, skipped=?, failed=? WHERE id=?",
        (status, error, finished, c.total, c.processed, c.learned, c.skipped, c.failed, job_id))


def run_job(job_id: int, *, engine: Any = None, claim: bool = True,
            clock: Callable[[], float] | None = None,
            sleep: Callable[[float], None] | None = None) -> str:
    """Run one job to completion. Returns the final status. With claim=True
    the job must be 'queued' and is atomically switched to 'running'
    (another runner may have taken it: returns 'skipped')."""
    eng = _eng(engine)
    if sleep is None:
        # Limiter pauses wake up early on shutdown.
        ev = _shutdown_event(eng)
        sleep = ev.wait if ev is not None else time.sleep
    with closing(_open_db(eng)) as conn:
        now = int(time.time())
        if claim:
            cur = conn.execute(
                "UPDATE train_jobs SET status='running', started_at=?, finished_at=NULL, "
                "error=NULL WHERE id=? AND status='queued'", (now, job_id))
            if not cur.rowcount:
                return "skipped"
        job = conn.execute("SELECT * FROM train_jobs WHERE id=?", (job_id,)).fetchone()
        if job is None:
            return "skipped"
        c = Counters()
        _write_progress(conn, job_id, c)
        client = None
        db = None
        rb = rebuild_link(conn, "train", job_id)
        try:
            if _ratio_reached(eng, job):
                return _ratio_done(eng, conn, job, c)
            acc = _find_account(eng, job["account"])
            client = _connect_readonly(eng, acc, job["folder"])
            check = lambda: _check(eng, conn, job_id)  # noqa: E731
            cands, oversize = select_candidates(
                eng, client, acc, max_messages=int(job["max_messages"]),
                seen_only=bool(job["seen_only"]), min_age_days=int(job["min_age_days"] or 0),
                provider_filter=job["provider_filter"] or "any", check=check)
            c.total = len(cands) + oversize
            c.skipped = oversize
            c.processed = oversize
            _write_progress(conn, job_id, c)

            calibrate = job["kind"] == "calibrate"
            db = None if calibrate else eng.Db(acc.name)
            kwargs = {} if calibrate else _learn_kwargs(eng)
            if rb is not None and not calibrate and _accepts_kw(eng.learn_message, "bypass_cooldown"):
                kwargs["bypass_cooldown"] = True  # Bayes rebuild jobs only
            ham_limit = rebuild_ham_limit(conn, rb, job) if rb is not None and job["kind"] == "ham" else None
            guard = job["kind"] == "ham" and getattr(eng, "ham_guard_reason", None) is not None
            limiter = RateLimiter(MAX_PER_SECOND, clock=clock or time.monotonic, sleep=sleep)
            streak = 0
            for start in range(0, len(cands), BODY_CHUNK):
                check()
                if ham_limit is not None and c.learned >= ham_limit:
                    raise _RebuildCap()
                chunk = cands[start : start + BODY_CHUNK]
                todo = []
                for cand in chunk:
                    if not calibrate and (_already_learned(conn, acc.name, cand.message_id, job["kind"])
                                          or _own_mail(eng, conn, acc.name, cand.message_id)
                                          or _rebuild_conflict(conn, rb, acc.name, cand.message_id,
                                                               job["kind"])):
                        c.skipped += 1
                        c.processed += 1
                    else:
                        todo.append(cand)
                data = client.fetch([x.uid for x in todo], [b"BODY.PEEK[]"]) if todo else {}
                for cand in todo:
                    if ham_limit is not None and c.learned >= ham_limit:
                        raise _RebuildCap()
                    if rb is not None:
                        # 'Gendan tidligere Bayes' cancels the rebuild's jobs and
                        # switches the learned state back: stop before the next
                        # learn, not only between chunks.
                        check()
                    d = data.get(cand.uid) or {}
                    raw = d.get(b"BODY[]") or d.get(b"BODY.PEEK[]")
                    c.processed += 1
                    if not raw:
                        c.failed += 1  # vanished since the header pass
                        continue
                    limiter.wait()
                    try:
                        if calibrate:
                            ok = _calibrate_one(eng, conn, acc, job, bytes(raw), cand)
                            outcome = "learned" if ok else "error"
                        elif guard and (why := _ham_guard(eng, conn, acc, bytes(raw), cand)):
                            _log_guard(eng, db, acc, job_id, cand, why)
                            outcome = "guarded"
                        else:
                            outcome = _learn_one(eng, db, acc, job, bytes(raw), cand, kwargs)
                    except Exception as ex:
                        log.warning("trainer job %s message failed: %s", job_id, type(ex).__name__)
                        outcome = "error"
                    if outcome == "learned":
                        c.learned += 1
                        streak = 0
                    elif outcome in ("already", "declined"):
                        c.skipped += 1
                        streak = 0
                    elif outcome in ("rate_limited", "guarded"):
                        # learn_message refused this one (flip-flop cooldown /
                        # safe mode) or the B6c ham guard did: not an rspamd
                        # failure, so no streak.
                        c.skipped += 1
                    else:
                        c.failed += 1
                        streak += 1
                        if streak >= MAX_CONSECUTIVE_FAILURES:
                            raise JobAborted("rspamd svarer ikke – jobbet blev stoppet.")
                _write_progress(conn, job_id, c)
                if _ratio_reached(eng, job):
                    return _ratio_done(eng, conn, job, c)
            _finish(conn, job_id, "done", c)
            _log_job_event(eng, job, "train_job_done",
                           f"job={job_id} learned={c.learned} skipped={c.skipped} failed={c.failed}")
            return "done"
        except _RebuildCap:
            # Bayes rebuild: ham stays at most `ratio` x the spam learned.
            _finish(conn, job_id, "done", c)
            _log_job_event(eng, job, "train_job_done",
                           f"job={job_id} learned={c.learned} skipped={c.skipped} failed={c.failed} "
                           f"rebuild_ham_cap reached")
            return "done"
        except _Interrupted as stop:
            if stop.status == "queued":
                # Shutdown: resume after restart (counters start over).
                _finish(conn, job_id, "queued", Counters())
            else:
                _finish(conn, job_id, "cancelled", c)
            return stop.status
        except JobAborted as ex:
            _finish(conn, job_id, "failed", c, ex.text)
            _log_job_event(eng, job, "train_job_failed", f"job={job_id}")
            return "failed"
        except Exception as ex:
            # Type only: IMAP exception text can echo credentials.
            log.warning("trainer job %s failed: %s", job_id, type(ex).__name__)
            _finish(conn, job_id, "failed", c, "Jobbet fejlede uventet – se loggen.")
            return "failed"
        finally:
            if rb is not None:
                rebuild_after_job(conn, int(rb["rebuild_id"]))
            if db is not None:
                try:
                    db.close()
                except Exception:
                    pass
            if client is not None:
                _logout(client)


def _ratio_done(eng: Any, conn: sqlite3.Connection, job: sqlite3.Row, c: Counters) -> str:
    """B6b: the shared Bayes reached the job's spam:ham target."""
    _finish(conn, int(job["id"]), "done", c)
    _log_job_event(eng, job, "train_job_done",
                   f"job={job['id']} learned={c.learned} skipped={c.skipped} failed={c.failed} "
                   f"stop_ratio={job['stop_ratio']:g} reached")
    return "done"


def _log_job_event(eng: Any, job: sqlite3.Row, event: str, detail: str) -> None:
    try:
        db = eng.Db(job["account"])
        try:
            with db.tx():
                db.log_event(event, None, detail=detail)
        finally:
            db.close()
    except Exception as ex:
        log.warning("trainer event log failed: %s", type(ex).__name__)


def plan_job(account: str, folder: str, *, max_messages: int, seen_only: bool = False,
             min_age_days: int = 0, provider_filter: str = "any",
             engine: Any = None) -> tuple[list[Candidate], int]:
    """Dry run: the header pass only (read-only IMAP, no DB, no rspamd)."""
    eng = _eng(engine)
    acc = _find_account(eng, account)
    client = _connect_readonly(eng, acc, folder)
    try:
        return select_candidates(eng, client, acc, max_messages=max_messages,
                                 seen_only=seen_only, min_age_days=min_age_days,
                                 provider_filter=provider_filter)
    finally:
        _logout(client)


# ---------------------------------------------------------------------------
# 2.2 (B6a): learn-list jobs - owner-approved, one message at a time
# ---------------------------------------------------------------------------

LEARN_LIST_SCHEMA = """
CREATE TABLE IF NOT EXISTS learn_list_jobs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    status      TEXT NOT NULL DEFAULT 'queued', -- queued|running|done|failed|cancelled|cancel_requested
    total       INTEGER NOT NULL DEFAULT 0,
    processed   INTEGER NOT NULL DEFAULT 0,
    learned     INTEGER NOT NULL DEFAULT 0,
    already     INTEGER NOT NULL DEFAULT 0,
    not_found   INTEGER NOT NULL DEFAULT 0,
    skipped     INTEGER NOT NULL DEFAULT 0,
    failed      INTEGER NOT NULL DEFAULT 0,
    note        TEXT,
    error       TEXT,
    created_by  TEXT,
    created_at  INTEGER NOT NULL,
    started_at  INTEGER,
    finished_at INTEGER
);
CREATE TABLE IF NOT EXISTS learn_list_items (
    job_id      INTEGER NOT NULL,
    account     TEXT NOT NULL,
    message_id  TEXT NOT NULL,
    kind        TEXT NOT NULL,                   -- 'spam' | 'ham'
    status      TEXT NOT NULL DEFAULT 'pending', -- see LEARN_ITEM_STATUSES
    folder      TEXT,                            -- where it was found
    previous    TEXT,                            -- Bayes class before (learned_as / ledger)
    reason      TEXT,                            -- why it was suggested (services)
    updated_at  INTEGER,
    PRIMARY KEY (job_id, account, message_id)
);
CREATE INDEX IF NOT EXISTS idx_learn_list_items_status ON learn_list_items(job_id, status);
"""
LEARN_ITEM_STATUSES = ("pending", "learned", "already", "declined", "not_found", "ambiguous",
                       "too_large", "deferred", "failed")
# Item status -> job counter.
_LEARN_COUNTER = {"learned": "learned", "already": "already", "not_found": "not_found",
                  "ambiguous": "skipped", "too_large": "skipped", "declined": "skipped",
                  "deferred": "skipped", "failed": "failed"}
_learn_list_ok: set[str] = set()


def ensure_learn_list_schema(conn: sqlite3.Connection) -> None:
    """Create the additive learn-list tables (idempotent, cached per DB)."""
    key = str(conn.execute("PRAGMA database_list").fetchone()[2])
    if key in _learn_list_ok:
        return
    conn.executescript(LEARN_LIST_SCHEMA)
    _learn_list_ok.add(key)


def learn_list_counts(conn: sqlite3.Connection, job_id: int) -> dict[str, int]:
    out = {"total": 0, "processed": 0, "learned": 0, "already": 0, "not_found": 0,
           "skipped": 0, "failed": 0}
    for status, n in conn.execute(
            "SELECT status, COUNT(*) FROM learn_list_items WHERE job_id=? GROUP BY status", (job_id,)):
        out["total"] += int(n)
        if status != "pending":
            out["processed"] += int(n)
        key = _LEARN_COUNTER.get(str(status))
        if key:
            out[key] += int(n)
    return out


def _write_list_counts(conn: sqlite3.Connection, job_id: int) -> dict[str, int]:
    c = learn_list_counts(conn, job_id)
    conn.execute("UPDATE learn_list_jobs SET total=?, processed=?, learned=?, already=?, not_found=?, "
                 "skipped=?, failed=? WHERE id=?",
                 (c["total"], c["processed"], c["learned"], c["already"], c["not_found"],
                  c["skipped"], c["failed"], job_id))
    return c


def _set_item(conn: sqlite3.Connection, job_id: int, account: str, mid: str, status: str, *,
              folder: str | None = None, previous: str | None = None) -> None:
    conn.execute("UPDATE learn_list_items SET status=?, folder=COALESCE(?, folder), "
                 "previous=COALESCE(?, previous), updated_at=? WHERE job_id=? AND account=? AND message_id=?",
                 (status, folder, previous, int(time.time()), job_id, account, mid))


def _previous_class(conn: sqlite3.Connection, account: str, mid: str) -> str | None:
    try:
        row = conn.execute("SELECT learned_as FROM messages WHERE account=? AND message_id=?",
                           (account, mid)).fetchone()
        if row is not None and row["learned_as"]:
            return str(row["learned_as"])
        row = conn.execute("SELECT kind FROM learn_ledger WHERE account=? AND message_id=?",
                           (account, mid)).fetchone()
        return str(row["kind"]) if row is not None else None
    except sqlite3.Error:
        return None


def _list_folder_order(conn: sqlite3.Connection, acc: Any, client: Any, mid: str,
                       fmap: dict[str, Any]) -> list[str]:
    """Where to look for one message: the folder the engine last saw it in,
    then the inbox, the filter's folder and the provider's spam folder."""
    names = fmap.get("names") or set()
    order: list[str] = []
    try:
        row = conn.execute("SELECT current_folder FROM messages WHERE account=? AND message_id=?",
                           (acc.name, mid)).fetchone()
        if row is not None and row["current_folder"]:
            order.append(str(row["current_folder"]))
    except sqlite3.Error:
        pass
    order += [fmap.get("inbox"), fmap.get("junk"), fmap.get("provider_junk")]
    out = []
    for f in order:
        if f and f not in out and (not names or f in names):
            out.append(f)
    return out


def _account_folders(client: Any, acc: Any) -> dict[str, Any]:
    svc = None
    try:
        import services as svc  # noqa: PLC0415 - same image
    except Exception:
        svc = None
    if svc is not None:
        try:
            return svc._folder_map(acc, svc._list_folders(client))
        except Exception as ex:
            log.warning("learn list folder discovery failed: %s", type(ex).__name__)
    return {"inbox": getattr(acc, "inbox", "INBOX"), "junk": getattr(acc, "junk", "Junk"), "names": set()}


def _learn_list_item(eng: Any, conn: sqlite3.Connection, db: Any, acc: Any, client: Any,
                     fmap: dict[str, Any], job: sqlite3.Row, item: sqlite3.Row,
                     state: dict[str, Any], kwargs: dict[str, Any]) -> str:
    """Find one message (read-only) and learn it. Returns the item status."""
    mid = str(item["message_id"])
    kind = str(item["kind"])
    previous = _previous_class(conn, acc.name, mid)
    cap = int(getattr(eng, "MAX_FETCH_BYTES", 5 * 1024 * 1024))
    found: tuple[str, int] | None = None
    for folder in _list_folder_order(conn, acc, client, mid, fmap):
        if state.get("selected") != folder:
            try:
                client.select_folder(folder, readonly=True)  # EXAMINE: never writes
            except IMAPClientAbortError:
                raise
            except IMAPClientError:
                state["selected"] = None  # folder gone / not selectable
                continue
            state["selected"] = folder
        uids = list(eng.find_uids_by_message_id(client, mid) or [])
        if len(uids) > 1:
            _set_item(conn, int(job["id"]), acc.name, mid, "ambiguous", folder=folder, previous=previous)
            return "ambiguous"
        if uids:
            found = (folder, int(uids[0]))
            break
    if found is None:
        _set_item(conn, int(job["id"]), acc.name, mid, "not_found", previous=previous)
        return "not_found"
    folder, uid = found
    meta = client.fetch([uid], [b"RFC822.SIZE"]).get(uid) or {}
    try:
        size = int(meta.get(b"RFC822.SIZE") or 0)
    except (TypeError, ValueError):
        size = 0
    if size > cap:
        _set_item(conn, int(job["id"]), acc.name, mid, "too_large", folder=folder, previous=previous)
        return "too_large"
    d = client.fetch([uid], [b"BODY.PEEK[]"]).get(uid) or {}
    raw = d.get(b"BODY[]") or d.get(b"BODY.PEEK[]")
    if not raw:
        _set_item(conn, int(job["id"]), acc.name, mid, "not_found", folder=folder, previous=previous)
        return "not_found"
    outcome = str(eng.learn_message(db, acc, bytes(raw), kind, mid, actor=job["created_by"] or "",
                                    reason=f"learn_list job={job['id']}", **kwargs))
    status = {"learned": "learned", "already": "already", "declined": "declined",
              "rate_limited": "deferred"}.get(outcome, "failed")
    _set_item(conn, int(job["id"]), acc.name, mid, status, folder=folder, previous=previous)
    return status


def _check_list(eng: Any, conn: sqlite3.Connection, job_id: int) -> None:
    ev = _shutdown_event(eng)
    if ev is not None and ev.is_set():
        raise _Interrupted("queued")
    row = conn.execute("SELECT status FROM learn_list_jobs WHERE id=?", (job_id,)).fetchone()
    if row is None or row["status"] == "cancel_requested":
        raise _Interrupted("cancelled")


def _finish_list(conn: sqlite3.Connection, job_id: int, status: str, error: str | None = None) -> None:
    _write_list_counts(conn, job_id)
    conn.execute("UPDATE learn_list_jobs SET status=?, error=?, finished_at=? WHERE id=?",
                 (status, error, None if status == "queued" else int(time.time()), job_id))


def run_learn_list_job(job_id: int, *, engine: Any = None, claim: bool = True,
                       clock: Callable[[], float] | None = None,
                       sleep: Callable[[float], None] | None = None) -> str:
    """Run one learn-list job (B6a). Only 'pending' items are processed, so
    a job interrupted by shutdown resumes where it stopped. Never writes to
    IMAP. Returns the final status ('done'|'failed'|'cancelled'|'queued'|
    'skipped')."""
    eng = _eng(engine)
    if sleep is None:
        ev = _shutdown_event(eng)
        sleep = ev.wait if ev is not None else time.sleep
    with closing(_open_db(eng)) as conn:
        ensure_learn_list_schema(conn)
        if claim:
            cur = conn.execute(
                "UPDATE learn_list_jobs SET status='running', started_at=COALESCE(started_at, ?), "
                "finished_at=NULL, error=NULL WHERE id=? AND status='queued'", (int(time.time()), job_id))
            if not cur.rowcount:
                return "skipped"
        job = conn.execute("SELECT * FROM learn_list_jobs WHERE id=?", (job_id,)).fetchone()
        if job is None:
            return "skipped"
        limiter = RateLimiter(MAX_PER_SECOND, clock=clock or time.monotonic, sleep=sleep)
        kwargs = _learn_kwargs(eng)
        rb = rebuild_link(conn, "list", job_id)
        if rb is not None and _accepts_kw(eng.learn_message, "bypass_cooldown"):
            kwargs["bypass_cooldown"] = True  # Bayes rebuild jobs only
        streak = 0
        try:
            return _run_learn_list(eng, conn, job_id, job, limiter, kwargs, streak)
        finally:
            if rb is not None:
                rebuild_after_job(conn, int(rb["rebuild_id"]))


def _run_learn_list(eng: Any, conn: sqlite3.Connection, job_id: int, job: sqlite3.Row,
                    limiter: RateLimiter, kwargs: dict[str, Any], streak: int) -> str:
    """The body of run_learn_list_job (the job is claimed and loaded)."""
    try:
        accounts = [r["account"] for r in conn.execute(
            "SELECT DISTINCT account FROM learn_list_items WHERE job_id=? AND status='pending' "
            "ORDER BY account", (job_id,))]
        try:
            configs = {a.name: a for a in eng.load_account_configs(eng.CONFIG_PATH)}
        except Exception:
            raise JobAborted("Konfigurationen kunne ikke indlæses.") from None
        for name in accounts:
            _check_list(eng, conn, job_id)
            acc = configs.get(name)
            if acc is None:
                conn.execute("UPDATE learn_list_items SET status='failed', updated_at=? "
                             "WHERE job_id=? AND account=? AND status='pending'",
                             (int(time.time()), job_id, name))
                continue
            try:
                password = eng.read_secret(acc)
                client = eng.connect(acc, password=password)
            except Exception as ex:
                log.warning("learn list connect failed for %s: %s", name, type(ex).__name__)
                conn.execute("UPDATE learn_list_items SET status='failed', updated_at=? "
                             "WHERE job_id=? AND account=? AND status='pending'",
                             (int(time.time()), job_id, name))
                _write_list_counts(conn, job_id)
                continue
            db = eng.Db(acc.name)
            try:
                fmap = _account_folders(client, acc)
                state: dict[str, Any] = {}
                items = conn.execute(
                    "SELECT * FROM learn_list_items WHERE job_id=? AND account=? AND status='pending' "
                    "ORDER BY rowid", (job_id, name)).fetchall()
                for n, item in enumerate(items):
                    _check_list(eng, conn, job_id)
                    limiter.wait()
                    try:
                        status = _learn_list_item(eng, conn, db, acc, client, fmap, job, item,
                                                  state, kwargs)
                    except (_Interrupted, JobAborted):
                        raise
                    except Exception as ex:
                        log.warning("learn list %s item failed: %s", job_id, type(ex).__name__)
                        _set_item(conn, job_id, name, str(item["message_id"]), "failed")
                        status = "failed"
                        if isinstance(ex, (OSError, IMAPClientAbortError)):
                            break  # connection gone: the rest of this mailbox fails below
                    streak = streak + 1 if status == "failed" else 0
                    if streak >= MAX_CONSECUTIVE_FAILURES:
                        raise JobAborted("rspamd eller mailserveren svarer ikke – jobbet blev stoppet.")
                    if n % 10 == 9:
                        _write_list_counts(conn, job_id)
                conn.execute("UPDATE learn_list_items SET status='failed', updated_at=? "
                             "WHERE job_id=? AND account=? AND status='pending'",
                             (int(time.time()), job_id, name))
            finally:
                try:
                    db.close()
                except Exception:
                    pass
                _logout(client)
            c = _write_list_counts(conn, job_id)
            _log_list_event(eng, name, "learn_list_done",
                            f"job={job_id} learned={c['learned']} already={c['already']} "
                            f"not_found={c['not_found']} failed={c['failed']}")
        _finish_list(conn, job_id, "done")
        return "done"
    except _Interrupted as stop:
        _finish_list(conn, job_id, "queued" if stop.status == "queued" else "cancelled")
        return stop.status
    except JobAborted as ex:
        _finish_list(conn, job_id, "failed", ex.text)
        return "failed"
    except Exception as ex:
        log.warning("learn list job %s failed: %s", job_id, type(ex).__name__)
        _finish_list(conn, job_id, "failed", "Jobbet fejlede uventet – se loggen.")
        return "failed"


def _log_list_event(eng: Any, account: str, event: str, detail: str) -> None:
    try:
        db = eng.Db(account)
        try:
            with db.tx():
                db.log_event(event, None, detail=detail)
        finally:
            db.close()
    except Exception as ex:
        log.warning("learn list event log failed: %s", type(ex).__name__)


def run_pending_learn_list_once(*, engine: Any = None) -> int | None:
    """Run the oldest queued learn-list job, if any. Returns its id."""
    eng = _eng(engine)
    with closing(_open_db(eng)) as conn:
        ensure_learn_list_schema(conn)
        row = conn.execute("SELECT id FROM learn_list_jobs WHERE status='queued' "
                           "ORDER BY created_at, id LIMIT 1").fetchone()
    if row is None:
        return None
    run_learn_list_job(int(row["id"]), engine=eng)
    return int(row["id"])


# ---------------------------------------------------------------------------
# 'Byg Bayes op på ny' (services.bayes_rebuild_*): jobs that belong to a
# rebuild learn into the NEW pool with the flip-flop cooldown bypassed (the
# hourly limit is bypassed for every trainer job); a ham job stops when the
# rebuild's ham reaches `ratio` x the spam actually learned.
# ---------------------------------------------------------------------------

_ACTIVE_JOB_STATES = ("queued", "running", "cancel_requested")


def rebuild_link(conn: sqlite3.Connection, job_type: str, job_id: int) -> sqlite3.Row | None:
    """The rebuild a train ('train') or learn-list ('list') job belongs to
    (row with rebuild_id, role, planned, ratio, status), or None."""
    try:
        return conn.execute(
            "SELECT j.rebuild_id, j.role, j.planned, r.ratio, r.status FROM bayes_rebuild_jobs j "
            "JOIN bayes_rebuilds r ON r.id=j.rebuild_id WHERE j.job_type=? AND j.job_id=?",
            (job_type, int(job_id))).fetchone()
    except sqlite3.Error:
        return None  # tables missing (database of an older engine)


def rebuild_progress(conn: sqlite3.Connection, rebuild_id: int) -> dict[str, Any]:
    """Learned/skipped/failed per role and the job states of one rebuild."""
    ensure_learn_list_schema(conn)
    out: dict[str, Any] = {"spam": {"learned": 0, "skipped": 0, "failed": 0, "planned": 0},
                           "ham": {"learned": 0, "skipped": 0, "failed": 0, "planned": 0},
                           "jobs": {}, "active": 0, "total_jobs": 0}
    rows = conn.execute(
        "SELECT j.job_type, j.role, j.planned, t.status AS ts, t.learned AS tl, t.skipped AS tsk, "
        "t.failed AS tf, l.status AS ls, l.learned AS ll, l.already AS la, l.skipped AS lsk, "
        "l.not_found AS lnf, l.failed AS lf FROM bayes_rebuild_jobs j "
        "LEFT JOIN train_jobs t ON j.job_type='train' AND t.id=j.job_id "
        "LEFT JOIN learn_list_jobs l ON j.job_type='list' AND l.id=j.job_id "
        "WHERE j.rebuild_id=?", (int(rebuild_id),)).fetchall()
    for r in rows:
        role = out["spam"] if r["role"] == "spam" else out["ham"]
        role["planned"] += int(r["planned"] or 0)
        if r["job_type"] == "train":
            status = r["ts"] or "missing"
            role["learned"] += int(r["tl"] or 0)
            role["skipped"] += int(r["tsk"] or 0)
            role["failed"] += int(r["tf"] or 0)
        else:
            status = r["ls"] or "missing"
            role["learned"] += int(r["ll"] or 0)
            role["skipped"] += int(r["la"] or 0) + int(r["lsk"] or 0) + int(r["lnf"] or 0)
            role["failed"] += int(r["lf"] or 0)
        out["jobs"][status] = out["jobs"].get(status, 0) + 1
        out["total_jobs"] += 1
        if status in _ACTIVE_JOB_STATES:
            out["active"] += 1
    return out


def rebuild_ham_limit(conn: sqlite3.Connection, rb: sqlite3.Row, job: sqlite3.Row) -> int | None:
    """How many ham this rebuild job may still learn: its planned share,
    scaled down when less spam was learned than planned, and never above
    ratio x spam learned minus the ham other jobs of the rebuild learned."""
    try:
        ratio = float(rb["ratio"] or 2.0)
        prog = rebuild_progress(conn, int(rb["rebuild_id"]))
        mine = conn.execute("SELECT learned FROM train_jobs WHERE id=?", (int(job["id"]),)).fetchone()
    except (sqlite3.Error, TypeError, ValueError):
        return None
    cap_total = int(ratio * prog["spam"]["learned"])
    ham_other = prog["ham"]["learned"] - int((mine["learned"] if mine else 0) or 0)
    planned_total = max(1, prog["ham"]["planned"])
    planned = int(rb["planned"] or job["max_messages"] or 0)
    scale = min(1.0, cap_total / planned_total)
    share = int(planned * scale + 0.999)
    return max(0, min(cap_total - ham_other, share))


def rebuild_after_job(conn: sqlite3.Connection, rebuild_id: int) -> bool:
    """When the last job of a running rebuild ended: store the final
    numbers, mark it 'done' and log bayes_rebuild_done. True when done now."""
    try:
        prog = rebuild_progress(conn, rebuild_id)
        if prog["active"]:
            return False
        now = int(time.time())
        cur = conn.execute(
            "UPDATE bayes_rebuilds SET status='done', learned_spam=?, learned_ham=?, finished_at=? "
            "WHERE id=? AND status='running'",
            (prog["spam"]["learned"], prog["ham"]["learned"], now, int(rebuild_id)))
        if not cur.rowcount:
            return False
        conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES('*', ?, NULL, "
                     "'bayes_rebuild_done', ?)",
                     (now, f"rebuild={rebuild_id} spam={prog['spam']['learned']} ham={prog['ham']['learned']}"))
        log.info("Bayes rebuild %s done: spam=%s ham=%s", rebuild_id, prog["spam"]["learned"],
                 prog["ham"]["learned"])
        return True
    except sqlite3.Error as ex:
        log.warning("rebuild bookkeeping failed: %s", type(ex).__name__)
        return False


# ---------------------------------------------------------------------------
# Thread
# ---------------------------------------------------------------------------


def recover_interrupted(*, engine: Any = None) -> None:
    """At startup: jobs left 'running' by a crash are re-queued; a pending
    cancel request is completed. Same for the services' undo jobs."""
    eng = _eng(engine)
    with closing(_open_db(eng)) as conn:
        conn.execute("UPDATE train_jobs SET status='queued', started_at=NULL WHERE status='running'")
        conn.execute("UPDATE train_jobs SET status='cancelled', finished_at=? "
                     "WHERE status='cancel_requested'", (int(time.time()),))
        try:
            ensure_learn_list_schema(conn)
            conn.execute("UPDATE learn_list_jobs SET status='queued' WHERE status='running'")
            conn.execute("UPDATE learn_list_jobs SET status='cancelled', finished_at=? "
                         "WHERE status='cancel_requested'", (int(time.time()),))
        except sqlite3.Error as ex:
            log.warning("learn list recovery failed: %s", type(ex).__name__)
    fn = _services_fn("recover_undo_jobs")
    if fn is not None:
        try:
            fn(engine=eng)
        except Exception as ex:
            log.warning("undo job recovery failed: %s", type(ex).__name__)


def _services_fn(name: str) -> Callable[..., Any] | None:
    """A services function, or None (old/broken services module): the
    trainer must keep training even if the undo feature is unavailable."""
    try:
        import services
    except Exception as ex:  # pragma: no cover - same image
        log.warning("services unavailable: %s", type(ex).__name__)
        return None
    return getattr(services, name, None)


def run_pending_undo_once(*, engine: Any = None) -> int | None:
    """Continue the oldest queued bulk-undo job (services.undo_moves), if any."""
    fn = _services_fn("run_pending_undo_once")
    if fn is None:
        return None
    return fn(engine=_eng(engine))


def run_pending_once(*, engine: Any = None) -> int | None:
    """Run the oldest queued job, if any. Returns its id."""
    eng = _eng(engine)
    with closing(_open_db(eng)) as conn:
        row = conn.execute(
            "SELECT id FROM train_jobs WHERE status='queued' ORDER BY created_at, id LIMIT 1"
        ).fetchone()
    if row is None:
        return None
    run_job(int(row["id"]), engine=eng)
    return int(row["id"])


def _loop(eng: Any, stop: threading.Event) -> None:
    try:
        recover_interrupted(engine=eng)
    except Exception as ex:
        log.warning("trainer recovery failed: %s", type(ex).__name__)
    while not stop.is_set():
        busy = False
        # Undo jobs first: they put the user's mail back and are usually
        # finished inline by the WebUI; this resumes them after a restart.
        try:
            busy = run_pending_undo_once(engine=eng) is not None
        except Exception as ex:
            log.warning("undo loop error: %s", type(ex).__name__)
        try:
            busy = run_pending_learn_list_once(engine=eng) is not None or busy
        except Exception as ex:
            log.warning("learn list loop error: %s", type(ex).__name__)
        try:
            busy = run_pending_once(engine=eng) is not None or busy
        except Exception as ex:
            log.warning("trainer loop error: %s", type(ex).__name__)
        if not busy:
            stop.wait(POLL_INTERVAL_S)


def start(engine: Any = None) -> threading.Thread:
    """Start the single trainer daemon thread (idempotent)."""
    global _thread
    eng = _eng(engine)
    with _thread_lock:
        if _thread is not None and _thread.is_alive():
            return _thread
        stop = _shutdown_event(eng) or threading.Event()
        _thread = threading.Thread(target=_loop, args=(eng, stop), name="trainer", daemon=True)
        _thread.start()
        log.info("trainer started")
        return _thread
