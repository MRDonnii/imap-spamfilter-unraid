"""Spamfilter 2.6: campaigns across mailboxes (A2), block suggestions (A3)
and the watch for protected recipients (A6).

A2 - "Samme spam på alle postkasser"
  When a user marks a mail as spam (the mail app: user_junked into the
  filter's OWN folder - never the provider's junk folder, which the
  provider may fill itself after delivery; the WebUI: manual_mark_spam /
  Bekræft som spam), on_user_spam() records the verdict (campaign_source)
  and looks for copies of
  the same campaign in every mailbox (the same one too) and queues them in
  campaign_queue. It is a pure DB step (the UI process and the engine both
  call it); each copy is then handled by ITS OWN account thread in
  campaign_pass(), which re-checks everything against the live mailbox and
  the account's own config, and moves through the engine's normal path:
  a pending_move row (origin 'campaign', short grace) that
  execute_due_moves() carries out with the move journal, the hourly quota,
  the circuit breaker, the update hold and the "moved_to_junk" bookkeeping.
  Fortryd (undo_moves / per-mail Frigiv) therefore works unchanged, and
  nothing is ever deleted.

  A copy matches when its normalised subject equals the source's AND
    * the From address is the same, or
    * the From domain is the same (never a freemail domain), or
    * the envelope domain is the same and aligned with the From domain on
      both mails (ESP bounce domains such as amazonses.com never match).
  Only mail that is still in the inbox (per the DB), at most 72 h old, has
  no user verdict, carries no known-contact / reply / established-sender
  bonus, hit no allow rule, is not from the owner's own mailbox / shop
  domains (the platform domains of the local site config always) and - for a protected recipient - whose
  address has no allow rule. At most MAX_PER_TRIGGER copies per verdict.
  Newsletters waiting for (or already in) the newsletter folder are
  candidates too: spam has priority over the newsletter folder.
  At move time (_one) the copy must be unread, the source verdict must
  still stand, and the copy must have scored at least its mailbox's
  threshold - SCORE_FLOOR_MARGIN, unless MIN_INDEPENDENT_VERDICTS genuine
  verdicts (other mailboxes or users) agree; at most MAX_MOVES_PER_HOUR
  copies per mailbox and hour. Releasing / learning as ham / moving back
  the source cancels its queued copies and the moves not yet carried out
  (cancel_for_source).
  Shadow mode records "would move" only (event campaign_shadow), flag
  mode sets $Junk like a normal flag-mode catch.

  Learning: the copies are NOT learned as spam. The source mail is learned
  by the existing path (the WebUI learn / the engine's pending learn);
  learning N identical copies would only skew Bayes and eat the hourly
  learn limit. Instead the source mail is added to rspamd's LOCAL fuzzy
  storage (controller /fuzzyadd, flag FUZZY_FLAG; rule "local" in
  rspamd/local.d/fuzzy_check.conf.readonly), so later copies get
  FUZZY_LOCAL_SPAM - only after the verdict was learned (never when the
  learn was declined), and removed again (/fuzzydel, fuzzy_undo) when the
  user releases it or learns it as ham. A failed fuzzy write (storage not
  writable, rule missing) is logged once and retried only after
  FUZZY_BACKOFF_S.

A3 - block suggestions: block_suggestions() lists registrable sender
  domains marked as spam by a GENUINE user verdict (never a campaign copy
  or the provider's own junk move) at least SUGGEST_MIN times from at
  least SUGGEST_MIN_ACCOUNTS mailboxes in 30 days, with the From domain
  authenticated (aligned DKIM, or envelope = From domain when no result
  was stored), never released / judged legitimate, not freemail, not a
  brand domain, not the owner's own / shop domains, no existing rule and
  not dismissed ("Ignorer").

A6 - protected recipients: protected_watch_count() counts mail to a
  protected recipient (TH_PROTECTED_RCPT) in the last 7 days that scored
  at or above the account's NORMAL threshold, stayed in the inbox, has no
  user verdict and no allow rule. From PROTECTED_WATCH_MIN on, the engine
  raises an alert (mail kind "alert" + "problem" push) at most once a week
  per account (protected_watch_check, called from the hourly housekeeping).

Nothing here imports filter.py: the engine passes itself in (`eng`).
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import time
import unicodedata
from email.utils import parseaddr
from typing import Any, Callable, Iterable

import siteconfig

log = logging.getLogger("campaigns")

WINDOW_S = 72 * 3600              # never act on mail older than this
MAX_PER_TRIGGER = 25              # copies queued per user verdict
MAX_PER_PASS = 25                 # queue rows handled per account loop
MIN_SUBJECT_LEN = 6               # a normalised subject shorter than this never matches
CAMPAIGN_GRACE_S = 15             # pending_move grace for a campaign copy
QUEUE_KEEP_S = 35 * 86400         # finished queue rows (A3 counts 30 days)
FUZZY_FLAG = 100                  # fuzzy_map flag of FUZZY_LOCAL_SPAM
FUZZY_WEIGHT = 10
FUZZY_BACKOFF_S = 6 * 3600
FUZZY_STATE_KEY = "fuzzy_write_failed_at"
FUZZY_TIMEOUT_S = 10

TRIGGER_EVENTS = ("user_junked", "manual_mark_spam", "manual_learn_spam")
# 2.6 review: a copy is only moved when it already scored close to its own
# mailbox's threshold, or when at least MIN_INDEPENDENT_VERDICTS genuine
# user verdicts (other mailboxes or other users) agree on the campaign.
SCORE_FLOOR_MARGIN = 2.0
MIN_INDEPENDENT_VERDICTS = 2
MAX_MOVES_PER_HOUR = 50           # campaign copies moved/flagged per target mailbox and hour
REASON_FLOOR = "under scoregulvet"
REASON_SOURCE = "kilden er ikke længere spam"
# Candidate states: still in the inbox (none / shadow_spam / a newsletter
# waiting for its move) or already moved to the newsletter folder - spam
# has priority over the newsletter folder.
NEWSLETTER_PENDING = "newsletter_pending"
NEWSLETTER_MOVED = "newsletter_moved"
CANDIDATE_ACTIONS = ("none", "shadow_spam", NEWSLETTER_PENDING, NEWSLETTER_MOVED)
TRUST_SYMBOLS = frozenset({"TH_KNOWN_CONTACT", "TH_KNOWN_DOMAIN", "TH_REPLY", "TH_REPLY_THREAD",
                           "TH_ESTABLISHED"})
PROTECTED_SYMBOL = "TH_PROTECTED_RCPT"
# Mail from these always gets through (owner rule), whatever the config says:
# the platform domains of the local site config (config/site.yml).
ALWAYS_PROTECTED = tuple(siteconfig.get_list("platform_domains"))
DEFAULT_OWN_DOMAINS = tuple(dict.fromkeys([*ALWAYS_PROTECTED, *siteconfig.get_list("webshop_domains")]))
# Shared sending platforms: their registrable domain is never a block
# suggestion (it would hit every customer of the platform).
SHARED_DOMAINS = frozenset({
    "onmicrosoft.com", "amazonses.com", "sendgrid.net", "mailchimpapp.net", "mcsv.net", "list-manage.com",
    "mandrillapp.com", "sparkpostmail.com", "mailgun.org", "rsgsv.net", "customeriomail.com",
    "google.com", "googlegroups.com", "microsoft.com", "outlook.com", "apple.com", "facebookmail.com",
    "linkedin.com", "salesforce.com", "exacttarget.com", "hubspotemail.net", "klaviyomail.com",
})

# Brand domains (a copy of rspamd/local.d/maps.d/th_brand_domains.map, kept
# in sync by tests/test_campaigns.py - the filter image carries no rspamd
# maps) + the own mail domains of the local site config (added to the map
# at container start): a block suggestion for one of them would block the
# real brand.
BRAND_DOMAINS = frozenset(siteconfig.get_list("mail_domains")) | frozenset("""
    appleid.com trustpilotmail.com metamail.com teams-events.com bilkatogo.dk
    postnord.com postnord.dk postnord.se gls-denmark.com gls-group.eu gls-group.com gls-pakkeshop.dk
    gls.dk glsdanmark.dk pakkeshop.dk dao.as dao.dk dao365.dk bring.dk bring.com bring.se posten.no
    dhl.com dhl.dk dhl.de ups.com fedex.com easypark.net easypark.com easypark.dk brobizz.com
    brobizz.dk saphe.com saphe.dk reepay.com frisbii.com mobilepay.dk vippsmobilepay.com vipps.no
    mobilepay.fi danskebank.dk nets.eu nexigroup.com dankort.dk betalingsservice.dk e-boks.dk
    e-boks.com mitid.dk nemid.nu digst.dk skat.dk sktst.dk skattestyrelsen.dk borger.dk mit.dk
    digitalpost.dk netflix.com spotify.com apple.com icloud.com microsoft.com outlook.com office.com
    office365.com live.com hotmail.com outlook.dk live.dk hotmail.dk instagram.com facebook.com
    facebookmail.com meta.com godaddy.com punktum.dk punktum.com dk-hostmaster.dk zalando.dk
    zalando.com zalando.de silvan.dk harald-nyborg.dk jemogfix.dk jemfix.com bauhaus.dk
    elgiganten.dk coop.dk coop365.dk coopbank.dk superbrugsen.dk dagligbrugsen.dk brugsen.dk
    lokalbrugsen.dk kvickly.dk sallinggroup.com salling.dk bilka.dk netto.dk foetex.dk amazon.com
    amazon.de amazon.co.uk amazon.se amazonses.com aws.com amazonaws.com temu.com temuemail.com
    ikea.com ikea.dk makita.dk makita.com cnn.com trustpilot.com nordea.dk nordea.com
    nordeapension.dk danskebank.com jyskebank.dk sydbank.dk sparnord.dk djurslandsbank.dk lunar.app
    paypal.com paypal.dk klarna.com klarna.dk telenor.dk telia.dk yousee.dk norlys.dk tdc.dk
    crm-ts.com f-secure.com al-bank.dk nykredit.dk nykredit.com rd.dk lunarway.com tryg.dk tryg.com
    tryghedsgruppen.dk alka.dk topdanmark.dk codan.dk gjensidige.dk gjensidige.no gjensidige.com
    if.dk if-insurance.com telenor.com telia.com teliacompany.com nuuday.dk tdcnet.dk 3.dk
    andelenergi.dk andel.dk orsted.dk orsted.com ewii.dk dsb.dk rejsekort.dk rejseplanen.dk
""".split())

SUGGEST_DAYS = 30
SUGGEST_MIN = 2
SUGGEST_MIN_ACCOUNTS = 2
SUGGEST_LIMIT = 5

PROTECTED_WATCH_DAYS = 7
PROTECTED_WATCH_MIN = 3
PROTECTED_ALERT_EVERY_S = 7 * 86400
PROTECTED_STATE_PREFIX = "protected_watch_alert:"
PROTECTED_TITLE = "Spam samler sig i en beskyttet indbakke"
PROTECTED_HINT = "overvej at sænke grænsen for beskyttede adresser"

SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS campaign_queue (
        account         TEXT NOT NULL,
        message_id      TEXT NOT NULL,
        src_account     TEXT NOT NULL,
        src_message_id  TEXT NOT NULL,
        match           TEXT,
        trigger         TEXT,
        actor           TEXT,
        queued_at       INTEGER NOT NULL,
        status          TEXT NOT NULL DEFAULT 'queued',  -- queued|moved|flagged|shadow|skipped|failed|cancelled
        reason          TEXT,
        done_at         INTEGER,
        PRIMARY KEY (account, message_id)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_campaign_queue_status ON campaign_queue(account, status, queued_at)",
    "CREATE INDEX IF NOT EXISTS idx_campaign_queue_src ON campaign_queue(src_account, src_message_id)",
    # 2.6 review: every GENUINE user spam verdict that started a sweep (the
    # mail app into the filter's own folder, the WebUI). It is what counts
    # for independent verdicts, block suggestions and the fuzzy storage;
    # cancelled when the user releases the source again.
    """
    CREATE TABLE IF NOT EXISTS campaign_source (
        account       TEXT NOT NULL,
        message_id    TEXT NOT NULL,
        campaign_key  TEXT NOT NULL,
        trigger       TEXT,
        actor         TEXT,
        at            INTEGER NOT NULL,
        cancelled_at  INTEGER,
        PRIMARY KEY (account, message_id)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_campaign_source_key ON campaign_source(campaign_key)",
    """
    CREATE TABLE IF NOT EXISTS block_suggestion_dismissed (
        domain        TEXT PRIMARY KEY,
        dismissed_at  INTEGER NOT NULL,
        dismissed_by  TEXT
    )""",
)


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Additive tables (plain statements: safe inside a transaction)."""
    for stmt in SCHEMA_STATEMENTS:
        conn.execute(stmt)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(campaign_queue)")}
    if "prev_action" not in cols:  # 2.6 review: restored when a source is released
        conn.execute("ALTER TABLE campaign_queue ADD COLUMN prev_action TEXT")


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

_INVISIBLE_RE = re.compile("[\u00ad\u200b-\u200f\u2028-\u202e\u2060-\u2064\ufeff]")
_PREFIX_RE = re.compile(r"^(?:(?:re|fw|fwd|sv|vs|aw|wg|tr|ref|antw|rif|odp)(?:\s*\[\d+\])?\s*:\s*)+", re.I)
_TAG_RE = re.compile(r"^(?:\[[^\]]{1,24}\]|\*{2,}[^*]{1,24}\*{2,}|\([^)]{1,24}\))\s*")
_SPAM_TAG_RE = re.compile(r"spam|junk|uønsket|suspicious|mistænkelig", re.I)
_WS_RE = re.compile(r"\s+")


def normalize_subject(subject: Any) -> str:
    """Case-folded subject without Re:/Fwd:/SV: prefixes, provider spam
    tags ('[SPAM]', '***SPAM***'), invisible characters and extra spaces.
    Two mailboxes at different providers then see the same text."""
    t = unicodedata.normalize("NFKC", str(subject or ""))
    t = _INVISIBLE_RE.sub("", t)
    t = _WS_RE.sub(" ", t).strip()
    for _ in range(4):
        before = t
        t = _PREFIX_RE.sub("", t).strip()
        m = _TAG_RE.match(t)
        if m and _SPAM_TAG_RE.search(m.group(0)):
            t = t[m.end():].strip()
        if t == before:
            break
    return t.casefold().strip(" .!-–—:")


def sender_addr(value: Any) -> str:
    """'Name <a@b.dk>' / 'a@b.dk' -> 'a@b.dk' (lower case), '' if none."""
    addr = parseaddr(str(value or ""))[1].strip().strip("<>").lower()
    if addr.count("@") != 1:
        return ""
    local, _, dom = addr.partition("@")
    dom = dom.rstrip(".")
    return f"{local}@{dom}" if local and "." in dom else ""


def domain_of(addr: Any) -> str:
    a = sender_addr(addr)
    return a.rpartition("@")[2] if a else ""


def _registrable(domain: str) -> str:
    try:
        import lookalike  # noqa: PLC0415 - shared registrable-domain helper

        return lookalike.registrable(domain) or domain
    except Exception:  # noqa: BLE001
        labels = domain.split(".")
        return ".".join(labels[-2:]) if len(labels) > 2 else domain


def registrable(domain: Any) -> str:
    d = str(domain or "").strip().lower().lstrip("@").rstrip(".")
    return _registrable(d) if d else ""


def _is_freemail(domain: str) -> bool:
    try:
        import contacts  # noqa: PLC0415

        return bool(contacts.is_freemail(domain))
    except Exception:  # noqa: BLE001
        return domain in ("gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "icloud.com")


def _under(d: str, parent: str) -> bool:
    return bool(d) and bool(parent) and (d == parent or d.endswith("." + parent))


def _is_srs(addr: str) -> bool:
    local = addr.partition("@")[0].lower()
    return local.startswith(("srs0=", "srs1=", "srs0+", "srs1+", "prvs=", "btv1=", "bounce"))


def _symbol_names(symbols: Any) -> set[str]:
    try:
        data = json.loads(symbols) if isinstance(symbols, str) else (symbols or [])
    except (TypeError, ValueError):
        return set()
    out = set()
    for s in data if isinstance(data, list) else []:
        if isinstance(s, dict) and s.get("n"):
            out.add(str(s["n"]))
    return out


def protected_rcpt(symbols: Any) -> str:
    """The protected recipient of a mail (TH_PROTECTED_RCPT option 0)."""
    try:
        data = json.loads(symbols) if isinstance(symbols, str) else (symbols or [])
    except (TypeError, ValueError):
        return ""
    for s in data if isinstance(data, list) else []:
        if isinstance(s, dict) and s.get("n") == PROTECTED_SYMBOL:
            opts = s.get("o") or []
            return sender_addr(opts[0]) if opts else ""
    return ""


def _rows(conn: sqlite3.Connection, sql: str, args: Iterable[Any] = ()) -> list[sqlite3.Row]:
    """Rows addressable by name whatever the connection's row_factory."""
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    return list(cur.execute(sql, tuple(args)).fetchall())


def _row(row: Any, key: str) -> Any:
    try:
        return row[key]
    except (IndexError, KeyError):
        return None


def _ts(row: Any) -> int:
    return int(_row(row, "received_at") or _row(row, "first_seen") or 0)


def _own_domains(extra: Iterable[Any] = ()) -> list[str]:
    out = list(DEFAULT_OWN_DOMAINS)
    for d in extra or ():
        d = str(d or "").strip().lower().lstrip("@").rstrip(".")
        if d and d not in out:
            out.append(d)
    return out


def _wake(conn: sqlite3.Connection, account: str, now: int) -> None:
    """filter.request_wake without importing the engine (same key)."""
    import uuid  # noqa: PLC0415

    try:
        conn.execute("INSERT INTO engine_state(key, value, updated_at) VALUES(?,?,?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                     (f"wake:{account}", uuid.uuid4().hex, now))
    except sqlite3.Error:
        pass  # the thread still finds the row on its next loop


def _inbox_names(conn: sqlite3.Connection) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        for r in conn.execute("SELECT account, folder_map FROM account_status"):
            try:
                fm = json.loads(r[1]) if r[1] else {}
            except (TypeError, ValueError):
                fm = {}
            if isinstance(fm, dict) and fm.get("inbox"):
                out[str(r[0])] = str(fm["inbox"])
    except sqlite3.Error:
        pass
    return out


def _accounts_with_mail(conn: sqlite3.Connection, source: str) -> list[str]:
    names = {source}
    try:
        names |= {str(r[0]) for r in conn.execute("SELECT account FROM account_status WHERE account != '*'")}
    except sqlite3.Error:
        pass
    return sorted(names)


# ---------------------------------------------------------------------------
# A2: the sweep (DB only)
# ---------------------------------------------------------------------------


def campaign_key(subject_norm: str, from_domain: str) -> str:
    """One campaign = the normalised subject + the registrable From domain."""
    return f"{subject_norm}\x1f{registrable(from_domain)}"


def independent_verdicts(conn: sqlite3.Connection, key: str) -> int:
    """Genuine user spam verdicts on this campaign that still stand, counted
    by distinct mailbox or distinct user (whichever is more)."""
    try:
        rows = conn.execute(
            "SELECT s.account, COALESCE(s.actor, '') FROM campaign_source s JOIN messages m "
            "ON m.account=s.account AND m.message_id=s.message_id "
            "WHERE s.campaign_key=? AND s.cancelled_at IS NULL AND m.user_verdict='spam'", (key,)).fetchall()
    except sqlite3.Error:
        return 0
    return max(len({r[0] for r in rows}), len({r[1] for r in rows}))


def source_active(conn: sqlite3.Connection, account: str, message_id: str) -> bool:
    """The source verdict still stands: user verdict spam and not cancelled."""
    try:
        row = conn.execute(
            "SELECT m.user_verdict, s.cancelled_at, s.message_id FROM messages m LEFT JOIN campaign_source s "
            "ON s.account=m.account AND s.message_id=m.message_id WHERE m.account=? AND m.message_id=?",
            (account, message_id)).fetchone()
    except sqlite3.Error:
        return False
    return row is not None and row[0] == "spam" and row[2] is not None and row[1] is None


def cancel_for_source(conn: sqlite3.Connection, account: str, message_id: str, *, now: int | None = None,
                      reason: str = "frigivet") -> int:
    """The user released / learned as ham / moved back the SOURCE of a sweep:
    cancel its queued copies and the campaign moves that have not run yet
    (pending_move origin 'campaign'; the copy's previous state is
    restored). Copies already moved stay in the junk folder (Fortryd / Frigiv
    as usual). Returns the number of copies cancelled. Never raises."""
    now = int(now if now is not None else time.time())
    n = 0
    try:
        ensure_schema(conn)
        conn.execute("UPDATE campaign_source SET cancelled_at=? WHERE account=? AND message_id=? "
                     "AND cancelled_at IS NULL", (now, account, message_id))
        rows = _rows(conn, "SELECT * FROM campaign_queue WHERE src_account=? AND src_message_id=? "
                     "AND status IN ('queued', 'moved')", (account, message_id))
        for r in rows:
            if r["status"] == "moved":
                cur = conn.execute("DELETE FROM pending_move WHERE account=? AND message_id=? AND origin='campaign'",
                                   (r["account"], r["message_id"]))
                if not cur.rowcount:
                    continue  # already carried out: the copy stays where it is
                conn.execute("UPDATE messages SET our_action=? WHERE account=? AND message_id=? "
                             "AND our_action='pending_move'",
                             (_row(r, "prev_action") or "none", r["account"], r["message_id"]))
            conn.execute("UPDATE campaign_queue SET status='cancelled', reason=?, done_at=? WHERE account=? "
                         "AND message_id=?", (f"kilden {reason}"[:200], now, r["account"], r["message_id"]))
            conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                         (r["account"], now, r["message_id"], "campaign_cancelled",
                          f"kilden {r['src_message_id']} i {account} er {reason}"[:300]))
            n += 1
    except sqlite3.Error as ex:
        log.warning("campaign cancel failed: %s", type(ex).__name__)
    return n


def match_kind(src: dict[str, str], cand: Any) -> str | None:
    """'afsender' | 'domæne' | None for a candidate row against the
    normalised source (subject must already be equal)."""
    caddr = sender_addr(_row(cand, "sender"))
    if not caddr:
        return None
    if caddr == src["addr"]:
        return "afsender"
    cdom = caddr.rpartition("@")[2]
    if cdom == src["dom"] and not _is_freemail(cdom):
        return "domæne"
    cenv = sender_addr(_row(cand, "envelope_from"))
    if (cenv and src["env"] and not _is_srs(cenv) and cenv.rpartition("@")[2] == src["env_dom"]
            and not _is_freemail(src["env_dom"]) and registrable(src["env_dom"]) == registrable(cdom)
            and registrable(src["env_dom"]) == registrable(src["dom"])):
        return "domæne"
    return None


def on_user_spam(conn: sqlite3.Connection, account: str, message_id: str, *, actor: str = "",
                 trigger: str = "", now: int | None = None, limit: int = MAX_PER_TRIGGER,
                 own_domains: Iterable[Any] = ()) -> dict[str, Any]:
    """A user marked (account, message_id) as spam: queue the copies of the
    same campaign. Runs inside a savepoint (works within the caller's
    transaction or on its own); never raises. Returns {queued, accounts,
    reason}."""
    now = int(now if now is not None else time.time())
    out: dict[str, Any] = {"queued": 0, "accounts": [], "reason": ""}
    try:
        conn.execute("SAVEPOINT campaign_sweep")
    except sqlite3.Error as ex:
        log.warning("campaign sweep: no savepoint: %s", type(ex).__name__)
        return {**out, "reason": "db"}
    try:
        _sweep(conn, account, message_id, actor=actor, trigger=trigger, now=now, limit=limit,
               own=_own_domains(own_domains), out=out)
        conn.execute("RELEASE SAVEPOINT campaign_sweep")
    except Exception as ex:  # noqa: BLE001 - a sweep never breaks the user's action
        log.warning("campaign sweep failed: %s", type(ex).__name__)
        try:
            conn.execute("ROLLBACK TO SAVEPOINT campaign_sweep")
            conn.execute("RELEASE SAVEPOINT campaign_sweep")
        except sqlite3.Error:
            pass
        return {"queued": 0, "accounts": [], "reason": "error"}
    return out


def _sweep(conn: sqlite3.Connection, account: str, message_id: str, *, actor: str, trigger: str,
           now: int, limit: int, own: list[str], out: dict[str, Any]) -> None:
    ensure_schema(conn)
    conn.execute("DELETE FROM campaign_queue WHERE queued_at < ?", (now - QUEUE_KEEP_S,))
    found_src = _rows(conn, "SELECT * FROM messages WHERE account=? AND message_id=?", (account, message_id))
    src_row = found_src[0] if found_src else None
    if src_row is None or _row(src_row, "user_verdict") != "spam":
        out["reason"] = "no_verdict"
        return
    subj = normalize_subject(_row(src_row, "subject"))
    addr = sender_addr(_row(src_row, "sender"))
    if len(subj) < MIN_SUBJECT_LEN or not addr:
        out["reason"] = "too_little"
        return
    dom = addr.rpartition("@")[2]
    conn.execute(
        "INSERT INTO campaign_source(account, message_id, campaign_key, trigger, actor, at) VALUES(?,?,?,?,?,?) "
        "ON CONFLICT(account, message_id) DO UPDATE SET campaign_key=excluded.campaign_key, "
        "trigger=excluded.trigger, actor=excluded.actor, at=excluded.at, cancelled_at=NULL",
        (account, message_id, campaign_key(subj, dom), trigger or None, actor or None, now))
    if any(_under(dom, d) for d in own):
        out["reason"] = "own_domain"
        return
    env = sender_addr(_row(src_row, "envelope_from"))
    if env and _is_srs(env):
        env = ""
    src = {"addr": addr, "dom": dom, "env": env, "env_dom": env.rpartition("@")[2] if env else ""}
    src_ts = _ts(src_row) or now
    cutoff = now - WINDOW_S
    inboxes = _inbox_names(conn)
    found: list[tuple[int, str, str, str]] = []
    for acc in _accounts_with_mail(conn, account):
        rows = _rows(
            conn, "SELECT * FROM messages WHERE account=? AND last_seen >= ? AND user_verdict IS NULL "
            f"AND COALESCE(our_action, 'none') IN ({','.join('?' * len(CANDIDATE_ACTIONS))}) "
            "AND COALESCE(received_at, first_seen) >= ?", (acc, cutoff, *CANDIDATE_ACTIONS, cutoff))
        inbox = inboxes.get(acc)
        for r in rows:
            mid = str(r["message_id"])
            if acc == account and mid == message_id:
                continue
            if r["our_action"] == NEWSLETTER_MOVED:
                # In the newsletter folder (the DB knows where we put it).
                if not r["current_folder"] or (inbox and r["current_folder"] == inbox):
                    continue
            elif inbox and r["current_folder"] != inbox:
                continue
            if abs(_ts(r) - src_ts) > WINDOW_S:
                continue
            if normalize_subject(r["subject"]) != subj:
                continue
            kind = match_kind(src, r)
            if kind is None:
                continue
            cdom = domain_of(r["sender"])
            if any(_under(cdom, d) for d in own):
                continue
            if _symbol_names(r["symbols"]) & TRUST_SYMBOLS:
                continue
            if str(_row(r, "rule_hit") or "").startswith("allow:"):
                continue
            found.append((_ts(r), acc, mid, kind))
    found.sort(key=lambda t: -t[0])
    queued: dict[str, int] = {}
    for _ts_, acc, mid, kind in found:
        if sum(queued.values()) >= max(0, int(limit)):
            break
        # A copy skipped earlier only for the score floor is queued again:
        # this verdict may be the second, independent one.
        cur = conn.execute(
            "INSERT INTO campaign_queue(account, message_id, src_account, src_message_id, match, "
            "trigger, actor, queued_at) VALUES(?,?,?,?,?,?,?,?) "
            "ON CONFLICT(account, message_id) DO UPDATE SET src_account=excluded.src_account, "
            "src_message_id=excluded.src_message_id, match=excluded.match, trigger=excluded.trigger, "
            "actor=excluded.actor, queued_at=excluded.queued_at, status='queued', reason=NULL, done_at=NULL "
            "WHERE campaign_queue.status='skipped' AND campaign_queue.reason=?",
            (acc, mid, account, message_id, kind, trigger or None, (actor or None), now, REASON_FLOOR))
        if cur.rowcount:
            queued[acc] = queued.get(acc, 0) + 1
    n = sum(queued.values())
    out.update(queued=n, accounts=sorted(queued), found=len(found))
    if not n:
        out["reason"] = "none"
        return
    where = ", ".join(f"{a}={k}" for a, k in sorted(queued.items()))
    conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                 (account, now, message_id, "campaign_sweep",
                  f"{n} {'kopi' if n == 1 else 'kopier'} sat i kø: {where}"
                  + (f" (loft {limit})" if len(found) > n else "")))
    for acc in queued:
        _wake(conn, acc, now)


# ---------------------------------------------------------------------------
# A2: the per-account pass (engine)
# ---------------------------------------------------------------------------


def _finish(db: Any, r: Any, status: str, reason: str = "", *, now: int) -> None:
    db.conn.execute("UPDATE campaign_queue SET status=?, reason=?, done_at=? WHERE account=? AND message_id=?",
                    (status, reason[:200] or None, now, db.account, r["message_id"]))


def _skip(db: Any, r: Any, reason: str, *, now: int) -> str:
    with db.tx():
        _finish(db, r, "skipped", reason, now=now)
        db.log_event("campaign_skipped", r["message_id"],
                     detail=f"{reason} (samme spam som i {r['src_account']})"[:300])
    return "skipped"


def _detail(r: Any, extra: str = "") -> str:
    how = {"afsender": "samme afsender og emne", "domæne": "samme afsenderdomæne og emne"}.get(
        str(r["match"] or ""), "samme afsender og emne")
    return (f"Samme spam som i {r['src_account']}: {how}" + (f", {extra}" if extra else "")
            + f" (kilde {r['src_message_id']})")[:300]


def campaign_pass(eng: Any, client: Any, db: Any, log_: logging.Logger, acc: Any, fmap: dict[str, str],
                  state: Any = None) -> int:
    """Handle this account's queued campaign copies (max MAX_PER_PASS)."""
    try:
        ensure_schema(db.conn)
        rows = _rows(db.conn, "SELECT * FROM campaign_queue WHERE account=? AND status='queued' "
                     "ORDER BY queued_at LIMIT ?", (db.account, MAX_PER_PASS))
    except sqlite3.Error:
        return 0
    if not rows or eng.SHUTDOWN.is_set() or db.in_safe_mode("all"):
        return 0
    inbox = fmap["inbox"]
    try:
        uv = eng.select_with_uidvalidity_check(client, db, inbox, log_, readonly=acc.mode == "shadow")
    except eng._CONN_ERRORS:
        raise
    except Exception as ex:  # noqa: BLE001 - e.g. a NO to SELECT: try again next loop
        log_.warning("campaign pass: select failed: %s", type(ex).__name__)
        return 0
    done = 0
    for r in rows:
        if eng.SHUTDOWN.is_set():
            break
        now = int(eng._now())
        try:
            res = _one(eng, client, db, log_, acc, inbox, uv, r, now)
        except eng._CONN_ERRORS:
            raise
        except Exception as ex:  # noqa: BLE001 - one bad mail never stops the pass
            log_.warning("campaign copy %s failed: %s", r["message_id"], type(ex).__name__)
            with db.tx():
                _finish(db, r, "failed", type(ex).__name__, now=now)
                db.log_event("campaign_failed", r["message_id"], detail=type(ex).__name__)
            res = "failed"
            try:
                eng.select_with_uidvalidity_check(client, db, inbox, log_, readonly=acc.mode == "shadow")
            except eng._CONN_ERRORS:
                raise
            except Exception:  # noqa: BLE001 - the next loop selects again
                break
        if res == "deferred":
            break  # the hourly limit: the rest waits in the queue
        done += 1
    return done


def _hourly_used(db: Any, now: int) -> int:
    try:
        return int(db.conn.execute(
            "SELECT COUNT(*) FROM campaign_queue WHERE account=? AND status IN ('moved', 'flagged') "
            "AND done_at >= ?", (db.account, now - 3600)).fetchone()[0])
    except sqlite3.Error:
        return 0


def _effective_threshold(acc: Any, symbols: Any) -> float:
    thr = float(getattr(acc, "threshold", 0) or 0)
    if protected_rcpt(symbols):
        try:
            thr = max(thr, float(getattr(acc, "protected_threshold", 0) or 0))
        except (TypeError, ValueError):
            pass
    return thr


def _own_for(acc: Any) -> list[str]:
    extra: list[Any] = [*ALWAYS_PROTECTED, *(getattr(acc, "owner_platform_domains", None) or ()),
                        *(getattr(acc, "webshop_domains", None) or ())]
    user = str(getattr(acc, "user", "") or "").lower()
    if "@" in user:
        extra.append(user.rpartition("@")[2])
    grp = str(getattr(acc, "contact_group", "") or "").lower().lstrip("@")
    if "." in grp:
        extra.append(grp)
    return _own_domains(extra)


def _allowed(eng: Any, conn: sqlite3.Connection, account: str, addr: str) -> bool:
    if not addr:
        return False
    try:
        rule = eng.match_sender_rule(conn, account, addr)
    except Exception:  # noqa: BLE001
        return False
    try:
        return rule is not None and rule["kind"] == "allow"
    except (IndexError, KeyError, TypeError):
        return False


def _one(eng: Any, client: Any, db: Any, log_: logging.Logger, acc: Any, inbox: str, uv: int, r: Any,
         now: int) -> str:
    msgid = r["message_id"]
    row = db.get_message(msgid)
    if row is None:
        return _skip(db, r, "ukendt", now=now)
    if not source_active(db.conn, r["src_account"], r["src_message_id"]):
        # The user released / learned as ham / moved back the source meanwhile.
        return _skip(db, r, REASON_SOURCE, now=now)
    if row["user_verdict"] or eng._sticky_ham(row):
        return _skip(db, r, "brugerens afgørelse", now=now)
    action = row["our_action"] or "none"
    if action not in ("none", NEWSLETTER_PENDING, NEWSLETTER_MOVED) and not (
            acc.mode == "shadow" and action == "shadow_spam"):
        return _skip(db, r, f"ændret ({action})", now=now)
    folder = inbox
    if action == NEWSLETTER_MOVED:
        try:
            folder = eng._newsletters().folder_of(acc)
        except Exception:  # noqa: BLE001
            folder = ""
        if not folder or row["current_folder"] != folder:
            return _skip(db, r, "ikke i nyhedsbrevsmappen", now=now)
    elif row["current_folder"] != inbox:
        return _skip(db, r, "ikke i indbakken", now=now)
    if _ts(row) and _ts(row) < now - WINDOW_S:
        return _skip(db, r, "ældre end 3 døgn", now=now)
    if _symbol_names(row["symbols"]) & TRUST_SYMBOLS:
        return _skip(db, r, "kendt afsender", now=now)
    addr = sender_addr(row["sender"])
    if str(row["rule_hit"] or "").startswith("allow:") or _allowed(eng, db.conn, acc.name, addr):
        return _skip(db, r, "tilladt afsender", now=now)
    if any(_under(addr.rpartition("@")[2], d) for d in _own_for(acc)):
        return _skip(db, r, "egen afsender", now=now)
    rcpt = protected_rcpt(row["symbols"])
    if rcpt and _allowed(eng, db.conn, acc.name, rcpt):
        return _skip(db, r, "beskyttet adresse med Tillad-regel", now=now)
    # Score floor: the copy itself must already look like spam to this
    # mailbox, unless several users / mailboxes agree independently.
    try:
        score = float(row["our_score"])
    except (TypeError, ValueError):
        score = None
    floor = _effective_threshold(acc, row["symbols"]) - SCORE_FLOOR_MARGIN
    if score is None or score < floor:
        src = db.conn.execute("SELECT campaign_key FROM campaign_source WHERE account=? AND message_id=?",
                              (r["src_account"], r["src_message_id"])).fetchone()
        if src is None or independent_verdicts(db.conn, src[0]) < MIN_INDEPENDENT_VERDICTS:
            return _skip(db, r, REASON_FLOOR, now=now)
    if acc.mode in ("move", "flag") and _hourly_used(db, now) >= MAX_MOVES_PER_HOUR:
        with db.tx():
            db.log_event("campaign_deferred", msgid, detail=f"højst {MAX_MOVES_PER_HOUR} i timen")
        return "deferred"
    fuv = uv
    if folder != inbox:
        fuv = eng.select_with_uidvalidity_check(client, db, folder, log_, readonly=acc.mode == "shadow")
    try:
        return _act(eng, client, db, log_, acc, folder, fuv, r, row, action, now)
    finally:
        if folder != inbox:
            eng.select_with_uidvalidity_check(client, db, inbox, log_, readonly=acc.mode == "shadow")


def _act(eng: Any, client: Any, db: Any, log_: logging.Logger, acc: Any, folder: str, uv: int, r: Any,
         row: Any, action: str, now: int) -> str:
    """The live checks in `folder` (selected) and the move / flag / record."""
    msgid = r["message_id"]
    where = "indbakken" if action != NEWSLETTER_MOVED else "nyhedsbrevsmappen"
    uids = list(eng.find_uids_by_message_id(client, msgid) or [])
    if not uids:
        return _skip(db, r, f"ikke længere i {where}", now=now)
    if len(uids) > 1:
        return _skip(db, r, "flere mails med samme Message-ID", now=now)
    uid = int(uids[0])
    data = client.fetch([uid], [b"FLAGS", b"INTERNALDATE"]).get(uid) or {}
    flags = eng._flag_names(data.get(b"FLAGS"))
    if "\\Flagged" in flags:
        return _skip(db, r, "stjernemarkeret", now=now)
    if "\\Deleted" in flags:
        return _skip(db, r, "markeret slettet", now=now)
    if "\\Seen" in flags:
        # Like the rescans (B19): read mail is never taken away for a
        # campaign verdict - the user may be reading it right now.
        return _skip(db, r, "læst", now=now)
    idate = eng._internaldate_ts(data)
    if idate and idate < now - WINDOW_S:
        return _skip(db, r, "ældre end 3 døgn", now=now)
    if acc.mode == "move":
        with db.tx():
            db.update_message(msgid, our_action="pending_move", last_seen=now)
            if action == NEWSLETTER_PENDING:
                db.conn.execute("DELETE FROM newsletter_pending WHERE account=? AND message_id=?",
                                (db.account, msgid))  # spam has priority
            db.add_pending_move(uv, uid, msgid, folder=folder, due_at=now + CAMPAIGN_GRACE_S,
                                score=row["our_score"], threshold=acc.threshold, origin="campaign")
            _finish(db, r, "moved", now=now)
            db.conn.execute("UPDATE campaign_queue SET prev_action=? WHERE account=? AND message_id=?",
                            (action if action != "shadow_spam" else "none", db.account, msgid))
            db.log_event("campaign_move", msgid, detail=_detail(r))
        log_.info("campaign copy %s queued for move (source %s)", msgid, r["src_account"])
        return "moved"
    if acc.mode == "flag":
        client.add_flags([uid], eng._junk_flags(None))
        with db.tx():
            db.update_message(msgid, our_action="flagged", last_seen=now)
            _finish(db, r, "flagged", now=now)
            db.log_event("campaign_move", msgid, detail=_detail(r, "markeret som spam"))
            db.bump("flagged")
        return "flagged"
    with db.tx():
        _finish(db, r, "shadow", now=now)
        db.log_event("campaign_shadow", msgid, detail=_detail(r, "overvåger – ikke flyttet"))
    return "shadow"


# ---------------------------------------------------------------------------
# A2: local fuzzy storage
# ---------------------------------------------------------------------------


def _state_get(conn: sqlite3.Connection, key: str) -> str | None:
    try:
        row = conn.execute("SELECT value FROM engine_state WHERE key=?", (key,)).fetchone()
    except sqlite3.Error:
        return None
    return None if row is None else row[0]


def _state_set(conn: sqlite3.Connection, key: str, value: str | None, now: int) -> None:
    try:
        conn.execute("INSERT INTO engine_state(key, value, updated_at) VALUES(?,?,?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                     (key, value, now))
    except sqlite3.Error:
        pass


def fuzzy_add(eng: Any, raw: bytes | None, *, conn: sqlite3.Connection | None = None,
              now: int | None = None, op: str = "fuzzyadd") -> str:
    """POST the mail to the controller's /fuzzyadd (or /fuzzydel with
    op='fuzzydel'), flag FUZZY_FLAG.
    'added' | 'failed' | 'error' | 'backoff' | 'unavailable' | 'skipped'.
    Never raises; a failure pauses further writes for FUZZY_BACKOFF_S."""
    now = int(now if now is not None else time.time())
    if not raw:
        return "skipped"
    base = getattr(eng, "RSPAMD_LEARN_URL", None)
    req = getattr(eng, "requests", None)
    pw = getattr(eng, "_rspamd_password", None)
    if not base or req is None or not callable(pw):
        return "unavailable"
    if conn is not None and op == "fuzzyadd":
        try:
            last = int(_state_get(conn, FUZZY_STATE_KEY) or 0)
        except ValueError:
            last = 0
        if last and now - last < FUZZY_BACKOFF_S:
            return "backoff"
    headers = {"Password": pw(), "Flag": str(FUZZY_FLAG)}
    if op == "fuzzyadd":
        headers["Weight"] = str(FUZZY_WEIGHT)
    try:
        resp = req.post(f"{base}/{op}", data=raw, headers=headers, timeout=FUZZY_TIMEOUT_S)
    except Exception as ex:  # noqa: BLE001 - requests errors and anything else
        log.warning("fuzzy %s failed: %s", op, type(ex).__name__)
        if conn is not None:
            _state_set(conn, FUZZY_STATE_KEY, str(now), now)
        return "error"
    ok = getattr(resp, "status_code", 0) == 200
    if ok:
        try:
            body = resp.json()
            ok = not (isinstance(body, dict) and body.get("success") is False)
        except Exception:  # noqa: BLE001 - a 200 without JSON still counts
            ok = True
    if ok:
        if conn is not None and _state_get(conn, FUZZY_STATE_KEY):
            _state_set(conn, FUZZY_STATE_KEY, None, now)
        return "added"
    log.warning("fuzzy %s: HTTP %s", op, getattr(resp, "status_code", "?"))
    if conn is not None:
        _state_set(conn, FUZZY_STATE_KEY, str(now), now)
    return "failed"


def _fuzzy_state(conn: sqlite3.Connection, account: str, message_id: str) -> str | None:
    """'fuzzy_added' | 'fuzzy_removed' | None: the newest of the two events."""
    row = conn.execute("SELECT event FROM events WHERE account=? AND message_id=? "
                       "AND event IN ('fuzzy_added', 'fuzzy_removed') ORDER BY id DESC LIMIT 1",
                       (account, message_id)).fetchone()
    return None if row is None else str(row[0])


def fuzzy_for_verdict(eng: Any, conn: sqlite3.Connection, account: str, message_id: str,
                      raw: bytes | None, *, now: int | None = None) -> str:
    """Add a user-confirmed spam mail to the local fuzzy storage once
    (event fuzzy_added / fuzzy_failed). Only mail with user verdict spam
    from a GENUINE user action (a campaign_source row that still stands -
    never a mail the provider itself moved to its junk folder)."""
    now = int(now if now is not None else time.time())
    try:
        row = conn.execute("SELECT user_verdict FROM messages WHERE account=? AND message_id=?",
                           (account, message_id)).fetchone()
        if row is None or row[0] != "spam":
            return "skipped"
        ensure_schema(conn)
        if not source_active(conn, account, message_id):
            return "skipped"
        if _fuzzy_state(conn, account, message_id) == "fuzzy_added":
            return "already"
    except sqlite3.Error:
        return "skipped"
    res = fuzzy_add(eng, raw, conn=conn, now=now)
    if res in ("added", "failed", "error"):
        try:
            conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                         (account, now, message_id, "fuzzy_added" if res == "added" else "fuzzy_failed",
                          "lokal fuzzy-database" if res == "added" else res))
        except sqlite3.Error:
            pass
    return res


def fuzzy_undo(eng: Any, conn: sqlite3.Connection, account: str, message_id: str, raw: bytes | None, *,
               now: int | None = None) -> str:
    """The user released / learned as ham a mail the filter added to the
    local fuzzy storage: remove it again (/fuzzydel, event fuzzy_removed).
    'removed' | 'not_added' | 'failed' | 'error' | 'unavailable' |
    'skipped'. Never raises."""
    now = int(now if now is not None else time.time())
    try:
        if _fuzzy_state(conn, account, message_id) != "fuzzy_added":
            return "not_added"
    except sqlite3.Error:
        return "skipped"
    res = fuzzy_add(eng, raw, conn=None, now=now, op="fuzzydel")
    if res == "added":
        res = "removed"
    try:
        conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                     (account, now, message_id, "fuzzy_removed" if res == "removed" else "fuzzy_failed",
                      "fjernet fra lokal fuzzy-database" if res == "removed" else f"fjern: {res}"))
    except sqlite3.Error:
        pass
    return res


# ---------------------------------------------------------------------------
# Counts for the weekly report
# ---------------------------------------------------------------------------


def weekly_counts(conn: sqlite3.Connection, since: int, until: int, account: str | None = None) -> dict[str, int]:
    """{'moved': copies moved, 'shadow': copies seen in Overvåg} in [since, until)."""
    sql = ("SELECT event, COUNT(*) FROM events WHERE ts >= ? AND ts < ? AND "
           "(event='campaign_shadow' OR (event='moved_to_junk' AND detail LIKE '%(samme spam)%')"
           " OR (event='campaign_move' AND detail LIKE '%markeret som spam%'))")
    args: list[Any] = [since, until]
    if account:
        sql += " AND account=?"
        args.append(account)
    out = {"moved": 0, "shadow": 0}
    try:
        for ev, n in conn.execute(sql + " GROUP BY event", args):
            out["shadow" if ev == "campaign_shadow" else "moved"] += int(n)
    except sqlite3.Error:
        pass
    return out


# ---------------------------------------------------------------------------
# A3: block suggestions
# ---------------------------------------------------------------------------


def _rule_domains(conn: sqlite3.Connection) -> list[str]:
    try:
        return [str(r[0]).rpartition("@")[2].lower() for r in conn.execute("SELECT pattern FROM sender_rules")]
    except sqlite3.Error:
        return []


def _dkim_domains(sender_auth: Any) -> list[str]:
    try:
        data = json.loads(sender_auth) if isinstance(sender_auth, str) else (sender_auth or {})
    except (TypeError, ValueError):
        return []
    vals = data.get("dkim") if isinstance(data, dict) else None
    return [str(d).strip().lower().rstrip(".") for d in vals or [] if str(d).strip()]


def _from_authenticated(sender: Any, sender_auth: Any, envelope_from: Any) -> bool:
    """The From domain really sent the mail: a valid DKIM signature aligned
    with it (stored sender_auth), or - when no authentication result was
    stored - the envelope domain is the From domain's registrable domain."""
    dom = domain_of(sender)
    if not dom:
        return False
    if sender_auth:
        return any(_under(dom, d) or _under(d, dom) for d in _dkim_domains(sender_auth))
    env = sender_addr(envelope_from)
    return bool(env) and registrable(env.rpartition("@")[2]) == registrable(dom)


def block_suggestions(conn: sqlite3.Connection, *, now: int | None = None, days: int = SUGGEST_DAYS,
                      refuse: Callable[[str], Any] | None = None, own_domains: Iterable[Any] = (),
                      limit: int = SUGGEST_LIMIT) -> list[dict[str, Any]]:
    """[{domain, n, accounts}] - see the module docstring. Counts only
    GENUINE user spam verdicts (campaign_source: the mail app into the
    filter's own folder, the WebUI; never campaign copies or the provider's
    own junk moves) whose From domain was authenticated (_from_authenticated).
    Never a brand domain (BRAND_DOMAINS), a shared platform, freemail or
    the owner's own / shop domains. `refuse(pattern)` ('@domain') returning
    a truthy value drops a domain (the UI passes its freemail / own-domain
    refusals)."""
    now = int(now if now is not None else time.time())
    since = now - int(days) * 86400
    own = _own_domains(own_domains)
    marks: dict[tuple[str, str], str] = {}
    try:
        ensure_schema(conn)
        for r in conn.execute(
                "SELECT m.account, m.message_id, m.sender, m.sender_auth, m.envelope_from FROM campaign_source s "
                "JOIN messages m ON m.account=s.account AND m.message_id=s.message_id "
                "WHERE s.cancelled_at IS NULL AND m.user_verdict='spam' "
                "AND COALESCE(m.verdict_at, m.last_seen, s.at) >= ?", (since,)):
            if _from_authenticated(r[2], r[3], r[4]):
                marks[(str(r[0]), str(r[1]))] = str(r[2] or "")
        hammy = set()
        for r in conn.execute("SELECT sender FROM messages WHERE user_verdict='ham' "
                              "OR our_action IN ('manual_release','user_rescued')"):
            d = registrable(domain_of(r[0]))
            if d:
                hammy.add(d)
        try:
            dismissed = {str(r[0]) for r in conn.execute("SELECT domain FROM block_suggestion_dismissed")}
        except sqlite3.Error:
            dismissed = set()
    except sqlite3.Error as ex:
        log.warning("block suggestions failed: %s", type(ex).__name__)
        return []
    rules = _rule_domains(conn)
    brands = {registrable(d) for d in BRAND_DOMAINS} | set(BRAND_DOMAINS)
    groups: dict[str, dict[str, Any]] = {}
    for (acc, _mid), sender in marks.items():
        dom = domain_of(sender)
        reg = registrable(dom)
        if not reg or "." not in reg:
            continue
        g = groups.setdefault(reg, {"domain": reg, "n": 0, "accounts": set()})
        g["n"] += 1
        g["accounts"].add(acc)
    out = []
    for reg, g in groups.items():
        if g["n"] < SUGGEST_MIN or len(g["accounts"]) < SUGGEST_MIN_ACCOUNTS:
            continue
        if reg in hammy or reg in dismissed or reg in SHARED_DOMAINS or _is_freemail(reg) or reg in brands:
            continue
        if any(_under(reg, d) or _under(d, reg) for d in own):
            continue
        if any(_under(d, reg) or _under(reg, d) for d in rules):
            continue
        if refuse is not None:
            try:
                if refuse("@" + reg):
                    continue
            except Exception:  # noqa: BLE001 - fail closed: no suggestion
                continue
        out.append({"domain": reg, "n": int(g["n"]), "accounts": sorted(g["accounts"])})
    out.sort(key=lambda s: (-s["n"], -len(s["accounts"]), s["domain"]))
    return out[: max(0, int(limit))]


def dismiss_suggestion(conn: sqlite3.Connection, domain: str, actor: str = "", *,
                       now: int | None = None) -> bool:
    reg = registrable(domain)
    if not reg or "." not in reg or len(reg) > 253:
        return False
    ensure_schema(conn)
    conn.execute("INSERT INTO block_suggestion_dismissed(domain, dismissed_at, dismissed_by) VALUES(?,?,?) "
                 "ON CONFLICT(domain) DO UPDATE SET dismissed_at=excluded.dismissed_at, "
                 "dismissed_by=excluded.dismissed_by",
                 (reg, int(now if now is not None else time.time()), actor or None))
    return True


# ---------------------------------------------------------------------------
# A6: protected recipients
# ---------------------------------------------------------------------------


def _protected_applies(acc: Any) -> bool:
    if getattr(acc, "mode", "shadow") not in ("move", "flag") or not getattr(acc, "enabled", True):
        return False
    if not (getattr(acc, "protected_recipients", None) or []):
        return False
    try:
        return float(getattr(acc, "protected_threshold", 0) or 0) > float(getattr(acc, "threshold", 0) or 0)
    except (TypeError, ValueError):
        return False


def protected_watch_count(conn: sqlite3.Connection, acc: Any, *, now: int | None = None,
                          match_rule: Callable[..., Any] | None = None) -> int:
    """Mail to a protected recipient in the last 7 days at or above the
    NORMAL threshold but below the CURRENT protected threshold, that stayed
    in the inbox (no verdict, no allow rule, no block rule). Mail at or over
    today's protected threshold is left out: it scored before the threshold
    was lowered (or the user already dealt with it) and new mail like it is
    moved anyway - counting it alerted on mail that was long gone (2.6.2)."""
    if not _protected_applies(acc):
        return 0
    now = int(now if now is not None else time.time())
    inbox = str(getattr(acc, "inbox", "") or "INBOX")
    try:
        rows = conn.execute(
            "SELECT sender, rule_hit FROM messages WHERE account=? AND COALESCE(received_at, first_seen) >= ? "
            "AND user_verdict IS NULL AND COALESCE(our_action, 'none')='none' AND current_folder=? "
            "AND our_score >= ? AND our_score < ? AND symbols LIKE ?",
            (acc.name, now - PROTECTED_WATCH_DAYS * 86400, inbox, float(acc.threshold),
             max(float(acc.threshold), float(acc.protected_threshold)),
             f'%"{PROTECTED_SYMBOL}"%')).fetchall()
    except sqlite3.Error:
        return 0
    n = 0
    for r in rows:
        if str(r[1] or "").startswith(("allow:", "block:")):
            continue
        if match_rule is not None:
            try:
                rule = match_rule(conn, acc.name, sender_addr(r[0]))
                # An allow rule keeps it in the inbox on purpose; a block rule added since moves the next one.
                if rule is not None and rule["kind"] in ("allow", "block"):
                    continue
            except Exception:  # noqa: BLE001
                pass
        n += 1
    return n


def protected_text(n: int) -> str:
    return f"{PROTECTED_TITLE}: {n} mails over grænsen – {PROTECTED_HINT}"


def protected_watch_check(eng: Any, conn: sqlite3.Connection, acc: Any, *, now: int | None = None) -> bool:
    """Alert (mail kind 'alert' + push) when PROTECTED_WATCH_MIN or more
    such mails piled up - at most once per PROTECTED_ALERT_EVERY_S per
    account. True when an alert was raised. Never raises."""
    now = int(now if now is not None else time.time())
    try:
        n = protected_watch_count(conn, acc, now=now, match_rule=getattr(eng, "match_sender_rule", None))
        if n < PROTECTED_WATCH_MIN:
            return False
        key = PROTECTED_STATE_PREFIX + acc.name
        try:
            last = int(_state_get(conn, key) or 0)
        except ValueError:
            last = 0
        if last and now - last < PROTECTED_ALERT_EVERY_S:
            return False
        _state_set(conn, key, str(now), now)
        conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,NULL,?,?)",
                     (acc.name, now, "protected_watch_alert", f"{n} mails over grænsen {float(acc.threshold):g} "
                      f"(beskyttet grænse {float(acc.protected_threshold):g})"))
        thr = float(acc.threshold)
        pthr = float(acc.protected_threshold)
        subject = f"Spamfilter: Konto {acc.name}: {PROTECTED_TITLE.lower()}"
        text = (f"{protected_text(n)}.\n\nPostkassen {acc.name} har fået {n} mails til en beskyttet adresse "
                f"de seneste {PROTECTED_WATCH_DAYS} dage med en score på mindst den normale grænse "
                f"({thr:g}), men under grænsen for beskyttede adresser ({pthr:g}). De ligger stadig i "
                f"indbakken. Tjek dem under Beskeder, og sænk grænsen for beskyttede adresser under "
                f"Konti, hvis det er spam.")
        alert = getattr(eng, "alert_once", None)
        if alert is not None:
            alert(conn, f"protected:{acc.name}", str(now), subject, text)
        return True
    except Exception as ex:  # noqa: BLE001 - a watch never breaks the housekeeping
        log.warning("protected watch failed: %s", type(ex).__name__)
        return False


def protected_watch_items(conn: sqlite3.Connection, accounts: Iterable[Any], *, now: int | None = None,
                          match_rule: Callable[..., Any] | None = None) -> list[dict[str, Any]]:
    """[{account, n, threshold, protected_threshold}] at or above PROTECTED_WATCH_MIN."""
    out = []
    for acc in accounts or ():
        n = protected_watch_count(conn, acc, now=now, match_rule=match_rule)
        if n >= PROTECTED_WATCH_MIN:
            out.append({"account": acc.name, "n": n, "threshold": float(acc.threshold),
                        "protected_threshold": float(acc.protected_threshold)})
    return out
