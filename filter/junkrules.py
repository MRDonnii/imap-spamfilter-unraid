"""Rules versus the user's own moves to Junk (spamfilter 2.12, #8 and #9).

Two notes per (mailbox, exact sender address), kept in ``junk_sender_notes``
and shown to administrators under "Tjek disse" (Fanget spam):

  * ``conflict`` (#8): the user moved a mail to Junk although a hand-made
    allow rule of THIS mailbox lets the sender through (typically the rule an
    administrator's "Tillad afsender" made when releasing a mail in someone
    else's mailbox). The filter does not decide who is right: the admin gets
    "Fjern reglen" or "Bloker for kontoen". Automatic allow rules
    ('auto:flytning') are not conflicts - the engine already removes them
    when the user moves to Junk. 'Altid igennem' (force) and global ('*')
    rules are the administrator's deliberate policy and never a conflict.

  * ``suggest`` (#9): the user moved mail from the same sender to Junk
    ``BLOCK_AFTER`` (3) times in the same mailbox and no rule covers the
    sender. The note is a suggestion: the admin decides ("Bloker for
    kontoen" or "Ignorer"). Only with ``AUTO_BLOCK`` (off by default; the
    owner has not approved automatic blocks) does the engine make an
    exact-address block rule for that one mailbox at once (created_by
    ``auto:junk``). Existing mail is never touched: a rule only acts on
    mail that arrives later, and block rules move to the spam folder
    (never delete).

A move only counts when the From was authenticated (DMARC pass or a DKIM
signature aligned with the From domain, and no spoof sign): three phishing
mails with a forged From must not turn the real sender into a suggestion.

Never for the owner's own domains: the same refusals as every block made in
the WebUI (``block_refusal``): vexar.example, pinsikbing.example and gravisk.example
always, every mailbox's platform/webshop domains, every mailbox's domain
and every mailbox address across all accounts.

Schema: additive (CREATE TABLE IF NOT EXISTS); older images ignore it.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from typing import Any, Iterable

import siteconfig

log = logging.getLogger("filter.junkrules")

BLOCK_AFTER = 3              # moves to Junk of the same sender in one mailbox
WINDOW_DAYS = 180            # moves older than this do not count
AUTO_BLOCK = False           # suggestions only; True = the engine makes the block rule itself (#9)
AUTO_BY = "auto:junk"        # created_by of an automatic block rule
AUTO_ALLOW_BY = "auto:flytning"
NOTE_TEXT = "Flyttet til Junk {n} gange af brugeren"
# The platform(s) whose mail always gets through (local site config).
ALWAYS_THROUGH = tuple(siteconfig.get_list("platform_domains"))
# Protected even when a config overrides the owner/webshop lists (the
# engine's DEFAULT_OWNER_PLATFORM_DOMAINS + DEFAULT_WEBSHOP_DOMAINS).
ALWAYS_PROTECTED = tuple(dict.fromkeys([*ALWAYS_THROUGH, *siteconfig.get_list("webshop_domains")]))
KINDS = ("conflict", "suggest")
OPEN = "open"
STATUSES = ("open", "auto_blocked", "blocked", "rule_removed", "dismissed", "undone")
RECENT_DAYS = 14             # decided notes stay visible this long

SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS junk_sender_moves (
        account     TEXT NOT NULL,
        sender      TEXT NOT NULL,
        message_id  TEXT NOT NULL,
        at          INTEGER NOT NULL,
        PRIMARY KEY (account, sender, message_id)
    )""",
    """
    CREATE TABLE IF NOT EXISTS junk_sender_notes (
        account        TEXT NOT NULL,
        sender         TEXT NOT NULL,
        kind           TEXT NOT NULL,
        rule_id        INTEGER,
        rule_pattern   TEXT,
        rule_by        TEXT,
        n_junk         INTEGER NOT NULL DEFAULT 0,
        first_at       INTEGER NOT NULL,
        last_at        INTEGER NOT NULL,
        last_message_id TEXT,
        status         TEXT NOT NULL DEFAULT 'open',
        decided_at     INTEGER,
        decided_by     TEXT,
        block_rule_id  INTEGER,
        PRIMARY KEY (account, sender, kind)
    )""",
)


def ensure_schema(conn: sqlite3.Connection) -> None:
    for stmt in SCHEMA_STATEMENTS:
        conn.execute(stmt)


# ---------------------------------------------------------------- helpers
def _addr(value: Any) -> str | None:
    s = str(value or "").strip().lower().strip("<>").strip()
    if s.count("@") != 1:
        return None
    local, _, dom = s.partition("@")
    if not local or "." not in dom or len(s) > 254 or any(c.isspace() for c in s):
        return None
    return s


def patterns(addr: str) -> list[str]:
    """Every rule pattern that matches the address: exact first, then each
    parent domain ('@a.b.c', '@b.c', '@c')."""
    dom = addr.partition("@")[2]
    labels = dom.split(".")
    return [addr] + ["@" + ".".join(labels[i:]) for i in range(len(labels))]


def _under(dom: str, parent: str) -> bool:
    dom, parent = dom.lower().strip("."), parent.lower().strip(".")
    return bool(parent) and (dom == parent or dom.endswith("." + parent))


def protected(addr: str, own_domains: Iterable[Any] = ()) -> bool:
    dom = addr.partition("@")[2]
    for d in (*ALWAYS_THROUGH, *own_domains):
        d = str(d or "").strip().lower().lstrip("@")
        if d and _under(dom, d):
            return True
    return False


Protection = tuple[frozenset, frozenset, frozenset]


def owner_protection(accounts: Iterable[Any], defaults: Iterable[Any] = ()) -> Protection:
    """(mailbox domains incl. domain-like contact groups, owner platform /
    webshop domains, mailbox addresses) over EVERY configured mailbox -
    the owner's own domains are protected whichever mailbox a rule is for.
    ALWAYS_PROTECTED and `defaults` (the engine's default owner/webshop
    lists) are included even when a config overrides the lists. Shared by
    the WebUI (ui_mail.hard_block_refusal) and the engine (#9)."""
    mail_doms: set[str] = set()
    shop_doms: set[str] = set()
    addrs: set[str] = set()
    for d in (*ALWAYS_PROTECTED, *defaults):
        d = str(d or "").strip().lower().lstrip("@").rstrip(".")
        if d:
            shop_doms.add(d)
    for acc in accounts:
        user = str(getattr(acc, "user", "") or "").strip().lower()
        if "@" in user:
            addrs.add(user)
            mail_doms.add(user.rpartition("@")[2].rstrip("."))
        grp = str(getattr(acc, "contact_group", "") or "").strip().lower()
        if "." in grp:
            mail_doms.add(grp.lstrip("@").rstrip("."))
        for key in ("owner_platform_domains", "webshop_domains"):
            for d in getattr(acc, key, None) or ():
                d = str(d or "").strip().lower().lstrip("@").rstrip(".")
                if d:
                    shop_doms.add(d)
    return frozenset(d for d in mail_doms if d), frozenset(shop_doms), frozenset(addrs)


def block_refusal(pattern: str, prot: Protection) -> tuple[str, str] | None:
    """(code, matched address/domain) when a block of `pattern` ('x@d' or
    '@d', normalised) must be refused for the owner's sake, else None:
    'own_mailbox' (a mailbox address), 'own_shop' (a platform/webshop domain
    or a parent domain of it) or 'own_domain' (a mailbox's whole domain).
    A single address in a mailbox domain (a colleague) is no refusal here."""
    mail_doms, shop_doms, addrs = prot
    local, _, dom = pattern.partition("@")
    if local and pattern in addrs:
        return "own_mailbox", pattern
    shop = next((s for s in sorted(shop_doms) if _under(dom, s) or (not local and _under(s, dom))), "")
    if shop:
        return "own_shop", shop
    own = next((m for m in sorted(mail_doms) if _under(dom, m) or (not local and _under(m, dom))), "")
    if not local and own:
        return "own_domain", own
    return None


def _rules(conn: sqlite3.Connection, account: str, addr: str) -> list[sqlite3.Row]:
    pats = patterns(addr)
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    return list(cur.execute(
        f"SELECT * FROM sender_rules WHERE account IN (?, '*') AND pattern IN ({','.join('?' * len(pats))})",
        (account, *pats)))


def is_force(r: Any) -> bool:
    try:
        return r["kind"] == "allow" and bool(r["force"])
    except (IndexError, KeyError):
        return False


def conflicting_rule(rules: list[sqlite3.Row], account: str) -> sqlite3.Row | None:
    """The mailbox's own hand-made allow rule (not 'Altid igennem', not
    automatic) that lets the sender through, most specific first."""
    cands = [r for r in rules if r["account"] == account and r["kind"] == "allow" and not is_force(r)
             and (r["created_by"] or "") != AUTO_ALLOW_BY]
    if not cands:
        return None
    return max(cands, key=lambda r: (1 if not str(r["pattern"]).startswith("@") else 0, len(r["pattern"])))


def count_moves(conn: sqlite3.Connection, account: str, addr: str, *, now: int) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM junk_sender_moves WHERE account=? AND sender=? AND at>=?",
                            (account, addr, now - WINDOW_DAYS * 86400)).fetchone()[0])


def _upsert(conn: sqlite3.Connection, account: str, addr: str, kind: str, *, n: int, msgid: str, now: int,
            rule: sqlite3.Row | None = None) -> str:
    """Create or refresh a note; returns its status afterwards. A decided
    note stays decided, except a conflict whose rule changed (a new rule
    is a new question)."""
    row = conn.execute("SELECT status, rule_id FROM junk_sender_notes WHERE account=? AND sender=? AND kind=?",
                       (account, addr, kind)).fetchone()
    rid = int(rule["id"]) if rule is not None else None
    if row is None:
        conn.execute(
            "INSERT INTO junk_sender_notes(account, sender, kind, rule_id, rule_pattern, rule_by, n_junk, first_at, "
            "last_at, last_message_id, status) VALUES(?,?,?,?,?,?,?,?,?,?, 'open')",
            (account, addr, kind, rid, rule["pattern"] if rule is not None else None,
             (rule["created_by"] if rule is not None else None), n, now, now, msgid[:255]))
        return OPEN
    reopen = kind == "conflict" and rid is not None and row[1] != rid
    conn.execute(
        "UPDATE junk_sender_notes SET n_junk=?, last_at=?, last_message_id=?"
        + (", rule_id=?, rule_pattern=?, rule_by=?, status='open', decided_at=NULL, decided_by=NULL" if reopen else "")
        + " WHERE account=? AND sender=? AND kind=?",
        (n, now, msgid[:255], *((rid, rule["pattern"], rule["created_by"]) if reopen else ()), account, addr, kind))
    return OPEN if reopen else str(row[0])


# ---------------------------------------------------------------- engine hook
def owner_sender(addr: str, prot: Protection | None, own_domains: Iterable[Any] = ()) -> bool:
    """Never an automatic suggestion/block: vexar.example and `own_domains`,
    and with `prot` (owner_protection over every mailbox) every refusal of
    block_refusal plus any address in any mailbox or owner domain."""
    if protected(addr, own_domains):
        return True
    if prot is None:
        return False
    mail_doms, shop_doms, _ = prot
    return block_refusal(addr, prot) is not None or protected(addr, (*mail_doms, *shop_doms))


def on_user_junk(conn: sqlite3.Connection, account: str, sender: Any, message_id: str, *,
                 now: int | None = None, own_domains: Iterable[Any] = (),
                 add_rule: Any = None, auto_block: bool | None = None,
                 protection: Protection | None = None, count: bool = True) -> dict[str, Any]:
    """The user moved `message_id` from `sender` to Junk (engine, inside the
    caller's transaction). Records the move and updates the notes.
    `add_rule(conn, account, pattern, kind, note, actor)` makes the block
    rule (filter.add_sender_rule). `protection` = owner_protection() over
    every mailbox. `count=False` (From not authenticated, or the mailbox
    does not learn from moves): the move is not counted towards a
    suggestion; a conflict note is still kept. Returns {"conflict": rule
    id or None, "suggest": bool, "blocked": rule id or None, "n": moves}."""
    out: dict[str, Any] = {"conflict": None, "suggest": False, "blocked": None, "n": 0}
    addr = _addr(sender)
    if addr is None or not message_id:
        return out
    t = int(time.time() if now is None else now)
    ensure_schema(conn)
    if count:
        conn.execute("INSERT OR IGNORE INTO junk_sender_moves(account, sender, message_id, at) VALUES(?,?,?,?)",
                     (account, addr, str(message_id)[:255], t))
    n = count_moves(conn, account, addr, now=t)
    out["n"] = n
    rules = _rules(conn, account, addr)
    rule = conflicting_rule(rules, account)
    if rule is not None:
        _upsert(conn, account, addr, "conflict", n=n, msgid=message_id, now=t, rule=rule)
        out["conflict"] = int(rule["id"])
        return out
    if not count or n < BLOCK_AFTER or rules or owner_sender(addr, protection, own_domains):
        # Any other rule (block, global allow, 'Altid igennem' for this
        # mailbox or all) already says what should happen to this sender.
        return out
    status = _upsert(conn, account, addr, "suggest", n=n, msgid=message_id, now=t)
    out["suggest"] = True
    if status != OPEN or not (AUTO_BLOCK if auto_block is None else auto_block) or add_rule is None:
        return out
    rid = int(add_rule(conn, account, addr, "block", NOTE_TEXT.format(n=n), AUTO_BY))
    conn.execute("UPDATE junk_sender_notes SET status='auto_blocked', decided_at=?, decided_by=?, block_rule_id=? "
                 "WHERE account=? AND sender=? AND kind='suggest'", (t, AUTO_BY, rid, account, addr))
    out["blocked"] = rid
    return out


# ---------------------------------------------------------------- admin side
def notes(conn: sqlite3.Connection, accounts: Iterable[str] | None = None, *, now: int | None = None,
          recent_days: int = RECENT_DAYS) -> list[dict[str, Any]]:
    """Open notes plus the ones decided within `recent_days` (newest first).
    `accounts` limits the mailboxes (None = all)."""
    t = int(time.time() if now is None else now)
    try:
        ensure_schema(conn)
        cur = conn.cursor()
        cur.row_factory = sqlite3.Row
        rows = list(cur.execute(
            "SELECT * FROM junk_sender_notes WHERE status='open' OR COALESCE(decided_at, 0) >= ? "
            "ORDER BY (status='open') DESC, last_at DESC LIMIT 200", (t - recent_days * 86400,)))
    except sqlite3.Error as ex:
        log.warning("junk notes unavailable: %s", type(ex).__name__)
        return []
    allowed = None if accounts is None else set(accounts)
    out = []
    for r in rows:
        if allowed is not None and r["account"] not in allowed:
            continue
        d = dict(r)
        if d["kind"] == "conflict" and d["status"] == OPEN and d["rule_id"] is not None:
            still = conn.execute("SELECT kind FROM sender_rules WHERE id=?", (d["rule_id"],)).fetchone()
            if still is None or still[0] != "allow":
                continue          # the rule is gone or changed: nothing to decide
        out.append(d)
    return out


def get(conn: sqlite3.Connection, account: str, sender: str, kind: str) -> dict[str, Any] | None:
    ensure_schema(conn)
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    r = cur.execute("SELECT * FROM junk_sender_notes WHERE account=? AND sender=? AND kind=?",
                    (account, sender, kind)).fetchone()
    return dict(r) if r is not None else None


def decide(conn: sqlite3.Connection, account: str, sender: str, kind: str, status: str, actor: str, *,
           block_rule_id: int | None = None, now: int | None = None) -> None:
    if status not in STATUSES:
        raise ValueError("bad status")
    conn.execute("UPDATE junk_sender_notes SET status=?, decided_at=?, decided_by=?, "
                 "block_rule_id=COALESCE(?, block_rule_id) WHERE account=? AND sender=? AND kind=?",
                 (status, int(time.time() if now is None else now), (actor or "")[:80] or None, block_rule_id,
                  account, sender, kind))
