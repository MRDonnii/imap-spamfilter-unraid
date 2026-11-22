"""Display-name impersonation of the owner's own people - "CEO fraud"
(spamfilter 2.7, "Falske afsendernavne").

A mail whose From display name is the name of one of OUR people ("Ole
Storm", "Molt Handel") while the address is not one of that
person's real addresses gets TH_NAME_SPOOF. Pure Python; nothing here
imports filter.py (the engine and services pass the connection in).

  * Protected names ("Beskyttede navne", admin-editable): a name plus the
    addresses / domains allowed to use it (the person's real addresses,
    a private gmail, a shop platform or list the person mails through).
    `seed()` fills the list from contacts.own_identities (the From
    identities seen in the mailboxes' Sent folders, >= 3 uses): one entry
    per display name with the addresses it was used with. A seeded
    one-word name ("Inge") starts switched off. A name the admin deleted
    is never seeded again (namespoof_seed_seen).
  * Matching (`fold`, `tokens`, `Matcher`): NFKC + casefold, look-alike
    letters folded (Cyrillic/Greek, 0/o, 1/l/i, rn/m, vv/w, cl/d - the
    lookalike module's table), diacritics removed and Danish spellings
    folded (ø/oe -> o, æ/ae -> a, å/aa -> a: "Søren" = "Soren" =
    "Soeren"), punctuation and spaces collapsed, titles ignored. A name of
    two or more words matches when the display name CONTAINS it as
    consecutive words - in its own order, "first last" (middle names
    left out), "last first" or "Last, First" - or written as one word
    ("OleStorm"), or when the display name is "first <middle> last"
    ("Ole E. Storm"). A one-word name only matches a display name that is
    exactly that word (plus titles). A display name that contains one of
    the person's real addresses ("ole@bynet.example" <x@evil.example>) also
    matches.
  * Exceptions: the person's own listed addresses and domains, the owner's
    own domains (mailbox domains, contact groups; never a freemail domain,
    never a multi-tenant platform - owner_platform_domains /
    webshop_domains such as vexar.example count only with the person's exact
    address there). A freemail address only counts when the mail carries a
    DKIM signature of its domain, any other exception only when the mail
    has no forged-From evidence (the engine's ALLOW_DISTRUST_SYMBOLS: DMARC
    reject/quarantine, SPF fail, the provider's spam verdict ...). An odd
    From (two From headers, several addresses, a trailing comma or garbage,
    "ole@bynet.example@evil.example", a quoted local part) is parsed leniently
    for the display name and is never exempt.
  * Score: TH_NAME_SPOOF +5.0, +7.0 when the Reply-To points to another
    domain (another address for a freemail From) that is not the person's
    or the owner's, when the subject is an explicit CEO-fraud phrase
    (gift cards, "Er du ved din computer?", urgency + transfer, secrecy +
    payment - never plain billing words like faktura / regning / betaling)
    or when the From is odd. A From domain (not freemail) with its own
    aligned DKIM signature caps it at +5 (a platform / ESP sending in the
    person's name: e-conomic invoices), and "<Name> (via X)" / "<Name> via
    X" signed by X gives only +2 (Google Docs, MobilePay notifications).
    Thresholds are 6 (normal) and 7: +5 alone needs one more signal
    (first contact, freemail, Bayes) to reach 6 and never reaches 7 on a
    clean mail, so a person's new private address that nobody listed yet
    is not moved on the name alone; the classic CEO-fraud mail (reply
    elsewhere or "Er du ved din computer? Jeg skal bruge gavekort") reaches
    7 by itself. The engine also blocks every
    contact trust bonus for it (a reply from the fraudster after the
    user answered once must not earn TH_REPLY -5). Not a threat class:
    a name match is a heuristic, a false positive must stay releasable by
    a Bruger. A display name is matched on its first 256 characters.
  * Mode (engine_state 'namespoof_mode'): off (Fra) | shadow (Prøv, the
    default) | on (Til). Prøv records the same hit as TH_NAME_SPOOF_TRIAL
    (score 0) plus an event, so the admin page lists what WOULD have been
    scored; after a week the card suggests switching to Til.

Privacy: only the owner's own people are stored (their names and their
own addresses, which own_identities already holds); symbol options and
events carry the protected name and a masked sender ("e…@gmail.com").

Schema: additive only (two new tables, created idempotently). Older
images ignore them, so a rollback keeps working. SCORE_VERSION is not
changed.
"""

from __future__ import annotations

import email
import email.header
import email.policy
import json
import logging
import re
import sqlite3
import time
import unicodedata
from dataclasses import dataclass, field
from email.utils import getaddresses, parseaddr
from typing import Any, Iterable, Sequence

import contacts
import lookalike

log = logging.getLogger("namespoof")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SYMBOL = "TH_NAME_SPOOF"
SYMBOL_TRIAL = "TH_NAME_SPOOF_TRIAL"     # Prøv: the same hit, score 0
SYMBOLS = (SYMBOL, SYMBOL_TRIAL)
SCORE = 5.0
SCORE_COMBO = 2.0                        # Reply-To elsewhere, a CEO-fraud subject or an odd From (not cumulative)
SCORE_PLATFORM = 2.0                     # "<Name> via <platform>" with the platform's aligned DKIM
DISPLAY_MAX = 256                        # characters of a display name that are matched
FROM_MAX = 5                             # From headers / values looked at

MODES = ("off", "shadow", "on")
DEFAULT_MODE = "shadow"
MODE_TEXT = {"off": "Fra", "shadow": "Prøv", "on": "Til"}
TRIAL_DAYS = 7
STATE_MODE = "namespoof_mode"            # engine_state: JSON {mode, at, by}
STATE_SEED = "namespoof_seed_at"         # engine_state: last seed run
SEED_INTERVAL_S = 3600
SEED_MIN_USES = contacts.IDENTITY_MIN    # an identity used >= 3 times in Sent

NAMES_MAX = 50
ALLOW_MAX = 20
NAME_MAX_LEN = 80
HIT_DAYS = 30

# Flags in the third option of the symbol. svar-til / emne / ugyldig-afsender
# raise the hit to +7; signeret (the From domain's own aligned DKIM, not a
# freemail domain) caps it at +5; platform ("<Name> via X", signed by X)
# makes it +2.
FLAG_REPLY_TO, FLAG_LURE, FLAG_ADDRESS, FLAG_NAME = "svar-til", "emne", "adresse-i-navnet", "navn"
FLAG_ODD, FLAG_SIGNED, FLAG_PLATFORM = "ugyldig-afsender", "signeret", "platform"
COMBO_FLAGS = frozenset({FLAG_REPLY_TO, FLAG_LURE, FLAG_ODD})

# Titles and roles ignored in a display name ("Direktør Inge", "Dr. Ole
# Storm", "Ole Storm, CEO"). Compared after fold().
_TITLES_RAW = ("dr", "mr", "mrs", "ms", "miss", "sir", "hr", "fru", "frk", "prof", "professor", "ing",
               "cand", "adm", "direktør", "direktor", "ceo", "cfo", "coo", "cto", "ejer", "indehaver",
               "chef", "manager", "jr", "sr", "phd", "mba", "md")

# CEO-fraud subjects (2.7 fix): only the explicit fraud phrases - gift
# cards, "are you at your computer?", urgency TOGETHER with a transfer or
# payment, secrecy TOGETHER with a payment. Ordinary billing words alone
# (faktura, regning, betaling, invoice, payment ...) never count: invoices,
# shared documents and receipts carry them every day ("Faktura 1042 fra
# Molt Handel" via e-conomic, "Betaling modtaget" via MobilePay).
_CEO_RE = re.compile(
    r"(?i)(?<![\w])(?:gavekort\w*|gift\s?cards?|"
    r"er\s+du\s+(?:ved\s+(?:din\s+|en\s+)?(?:computer|pc|skærm|skrivebord)\w*|til\s+stede|ledig|online)|"
    r"har\s+du\s+(?:et\s+|lige\s+(?:et\s+)?)(?:øjeblik|minut)|lille\s+tjeneste|"
    r"are\s+you\s+(?:available|free|around|at\s+your\s+desk)|quick\s+favou?r)(?![\w])")
_URGENT_RE = re.compile(r"(?i)(?<![\w])(?:haster|hastende|straks|omg[åa]ende|akut\w*|hurtigst\s+muligt|"
                        r"urgent\w*|asap)(?![\w])")
_SECRET_RE = re.compile(r"(?i)(?<![\w])(?:hemmelig\w*|fortrolig\w*|diskret\w*|confidential\w*)(?![\w])")
_TRANSFER_RE = re.compile(r"(?i)(?<![\w])(?:overf[øo]rs\w*|overf[øo]re|bankoverf\w*|betal\w*|iban|swift|"
                          r"kontonummer\w*|bankkonto\w*|bankoplysning\w*|wire|transfer\w*|payment\w*)(?![\w])")

# "<Name> (via Google Docs)", "Molt Handel via MobilePay": a platform
# that sends in a user's name.
_VIA_RE = re.compile(r"(?i)^(?P<name>.*?\S)\s*[(\[]?\s*\bvia\s+(?P<via>[^()\[\]]{1,80}?)\s*[)\]]?\s*$")

_ADDR_IN_TEXT_RE = re.compile(r"[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}")

# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

# Look-alike letters (Cyrillic, Greek, Latin variants, ø -> o, æ -> ae) -
# the same table the lookalike domains use.
_CONFUSABLE = dict(lookalike._CONFUSABLE_CHARS)
_DIGIT_FOLD = {"0": "o", "1": "l", "i": "l", "3": "e", "5": "s"}
_SEQ_FOLD = (("rn", "m"), ("vv", "w"), ("cl", "d"))
# Danish spellings without æøå: Soeren/Søren, Aase/Åse, Michael/Mikæl.
_DANISH_FOLD = (("aa", "a"), ("oe", "o"), ("ae", "a"))
_SPLIT_RE = re.compile(r"[\W_]+", re.UNICODE)


def fold(text: Any) -> str:
    """Lower-case, look-alike letters folded to Latin, diacritics removed
    (å -> a, é -> e, ö -> o; ø -> o and æ -> ae through the table)."""
    s = unicodedata.normalize("NFKC", str(text or "")).casefold()
    s = "".join(_CONFUSABLE.get(c, c) for c in s)
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    return "".join(_CONFUSABLE.get(c, c) for c in s)


def _fold_token(tok: str) -> str:
    t = "".join(_DIGIT_FOLD.get(c, c) for c in tok)
    for a, b in _SEQ_FOLD:
        t = t.replace(a, b)
    for a, b in _DANISH_FOLD:
        t = t.replace(a, b)
    return t


def _raw_tokens(text: Any) -> list[str]:
    # Invisible characters (zero-width, bidi, controls) never split a name:
    # "Jo\u200bhn" is "Ole".
    s = "".join(c for c in str(text or "") if unicodedata.category(c) not in ("Cf", "Cc"))
    s = _ADDR_IN_TEXT_RE.sub(" ", s)
    return [_fold_token(t) for t in _SPLIT_RE.split(fold(s)) if t]


_TITLES = frozenset(t for raw in _TITLES_RAW for t in _raw_tokens(raw))


def tokens(text: Any) -> list[str]:
    """The comparable words of a name: folded, titles left out."""
    return [t for t in _raw_tokens(text) if t not in _TITLES]


def name_key(name: Any) -> str:
    """The canonical form of a protected name (unique per entry)."""
    return " ".join(tokens(name))


def _variants(toks: Sequence[str]) -> set[tuple[str, ...]]:
    """Word orders a multi-word name matches in."""
    t = tuple(toks)
    out = {t, (t[0], t[-1]), (t[-1], t[0]), (t[-1], *t[:-1])}
    return {v for v in out if len(v) >= 2}


def _contains(hay: Sequence[str], needle: Sequence[str]) -> bool:
    n = len(needle)
    return any(tuple(hay[i:i + n]) == tuple(needle) for i in range(len(hay) - n + 1))


# ---------------------------------------------------------------------------
# Allowed addresses / domains of an entry
# ---------------------------------------------------------------------------


def parse_allow(items: Any) -> tuple[list[str], list[str]]:
    """Text (space/comma/newline separated) or a list -> (normalised items,
    invalid items). An item is an address ('ole.storm@gmail.com') or a
    domain ('@shopify.com' / 'shopify.com', subdomains included). A
    freemail DOMAIN is refused: anybody can get an address there."""
    raw = re.split(r"[\s,;]+", items) if isinstance(items, str) else list(items or [])
    out: list[str] = []
    bad: list[str] = []
    for item in raw:
        t = str(item or "").strip().strip("<>").lower()
        if not t:
            continue
        if "@" in t and not t.startswith("@"):
            a = contacts.normalize_address(t)
            if a and a not in out:
                out.append(a)
            elif not a:
                bad.append(str(item)[:60])
            continue
        d = contacts.normalize_domain(t.lstrip("@").lstrip("*").lstrip("."))
        if not d or "." not in d or contacts.is_freemail(d):
            bad.append(str(item)[:60])
        elif "@" + d not in out:
            out.append("@" + d)
    return out, bad


def _allowed(allow: Iterable[str], addr: str | None, platforms: Iterable[str] = ()) -> str | None:
    """'address' | 'domain' when `addr` is covered by the entry's list. A
    domain entry on a multi-tenant platform (owner_platform_domains /
    webshop_domains, e.g. vexar.example) never counts: every shop on it sends
    from that domain, so only the exact address does."""
    if not addr:
        return None
    dom = addr.rpartition("@")[2]
    for a in allow or ():
        if a.startswith("@"):
            if contacts.under(dom, a[1:]) and not _on_platform(dom, platforms):
                return "domain"
        elif a == addr:
            return "address"
    return None


def _on_platform(domain: str | None, platforms: Iterable[str]) -> bool:
    return bool(domain) and any(contacts.under(domain, p) or contacts.under(p, domain) for p in platforms or ())


def _own(domain: str | None, own_domains: Iterable[str]) -> bool:
    return bool(domain) and any(contacts.under(domain, d) for d in own_domains or ())


def own_domains_of(domains: Iterable[Any]) -> list[str]:
    """The owner's own domains as exceptions: normalised, never freemail."""
    out: list[str] = []
    for d in domains or ():
        nd = contacts.normalize_domain(str(d or "").rpartition("@")[2])
        if nd and "." in nd and not contacts.is_freemail(nd) and nd not in out:
            out.append(nd)
    return out


# ---------------------------------------------------------------------------
# Schema + state
# ---------------------------------------------------------------------------

SCHEMA = """
-- 2.7: protected names ("Beskyttede navne"). allow = JSON list of the
-- addresses ('a@b.dk') and domains ('@b.dk') that may use the name.
CREATE TABLE IF NOT EXISTS namespoof_names (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    key        TEXT NOT NULL UNIQUE,
    allow      TEXT NOT NULL DEFAULT '[]',
    enabled    INTEGER NOT NULL DEFAULT 1,
    source     TEXT NOT NULL DEFAULT 'manual',   -- 'seed' | 'manual'
    created_at INTEGER NOT NULL,
    created_by TEXT,
    updated_at INTEGER,
    updated_by TEXT
);

-- 2.7: (name key, address) pairs the seed already offered once - a name
-- or address the admin removed is never added again.
CREATE TABLE IF NOT EXISTS namespoof_seed_seen (
    key     TEXT NOT NULL,
    addr    TEXT NOT NULL,
    seen_at INTEGER NOT NULL,
    PRIMARY KEY (key, addr)
);
"""


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the tables (idempotent, additive; never COMMITs a caller's
    open transaction)."""
    for stmt in lookalike._statements(SCHEMA):
        conn.execute(stmt)


def _state_get(conn: sqlite3.Connection, key: str) -> str | None:
    try:
        row = conn.execute("SELECT value FROM engine_state WHERE key=?", (key,)).fetchone()
    except sqlite3.Error:
        return None
    return None if row is None else row[0]


def _state_set(conn: sqlite3.Connection, key: str, value: str, now: int) -> None:
    conn.execute("INSERT INTO engine_state(key, value, updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE "
                 "SET value=excluded.value, updated_at=excluded.updated_at", (key, value, int(now)))


def get_mode(conn: sqlite3.Connection) -> dict[str, Any]:
    """{mode, at, by, explicit}: 'at' = when the mode was set (for the
    default Prøv: when the filter first ran it)."""
    raw = _state_get(conn, STATE_MODE)
    try:
        st = json.loads(raw) if raw else {}
    except (TypeError, ValueError):
        st = {}
    st = st if isinstance(st, dict) else {}
    mode = st.get("mode") if st.get("mode") in MODES else DEFAULT_MODE
    return {"mode": mode, "at": int(st.get("at") or 0) or None, "by": str(st.get("by") or ""),
            "explicit": bool(st.get("by"))}


def touch_default(conn: sqlite3.Connection, now: int) -> None:
    """Remember when the default Prøv started (once)."""
    if _state_get(conn, STATE_MODE) is None:
        _state_set(conn, STATE_MODE, json.dumps({"mode": DEFAULT_MODE, "at": int(now), "by": ""}), now)


def set_mode(conn: sqlite3.Connection, mode: str, actor: str, now: int) -> bool:
    if mode not in MODES:
        raise ValueError(mode)
    _state_set(conn, STATE_MODE, json.dumps({"mode": mode, "at": int(now), "by": str(actor or "admin")[:80]}), now)
    return True


# ---------------------------------------------------------------------------
# Entries
# ---------------------------------------------------------------------------


def _row(r: sqlite3.Row | tuple) -> dict[str, Any]:
    d = dict(r)
    try:
        allow = json.loads(d.get("allow") or "[]")
    except (TypeError, ValueError):
        allow = []
    d["allow"] = [str(a) for a in allow if isinstance(a, str)] if isinstance(allow, list) else []
    d["enabled"] = bool(d.get("enabled"))
    d["one_word"] = len(str(d.get("key") or "").split()) == 1
    return d


def list_names(conn: sqlite3.Connection, *, enabled_only: bool = False) -> list[dict[str, Any]]:
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    try:
        rows = cur.execute("SELECT * FROM namespoof_names" + (" WHERE enabled=1" if enabled_only else "")
                           + " ORDER BY name COLLATE NOCASE, id").fetchall()
    except sqlite3.Error:
        return []
    return [_row(r) for r in rows]


def get_name(conn: sqlite3.Connection, entry_id: Any) -> dict[str, Any] | None:
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    try:
        r = cur.execute("SELECT * FROM namespoof_names WHERE id=?", (int(entry_id),)).fetchone()
    except (sqlite3.Error, TypeError, ValueError):
        return None
    return _row(r) if r else None


def _clean_display(name: Any) -> str:
    """Visible characters only (bidi / zero-width / control removed),
    whitespace collapsed, at most NAME_MAX_LEN."""
    text = "".join(c for c in str(name or "") if unicodedata.category(c)[0] != "C")
    return " ".join(text.split())[:NAME_MAX_LEN]


def save_name(conn: sqlite3.Connection, *, name: Any, allow: Any, enabled: bool = True,
              entry_id: Any = None, actor: str = "", now: int | None = None) -> dict[str, Any]:
    """Create (entry_id None) or update one protected name.
    -> {ok, code ('ok'|'unchanged'|'invalid'|'exists'|'full'|'not_found'), text, entry, invalid}"""
    now = int(now if now is not None else time.time())
    shown = _clean_display(name)
    key = name_key(shown)
    out: dict[str, Any] = {"ok": False, "code": "invalid", "text": "", "entry": None, "invalid": []}
    if not key or not any(len(t) >= 2 for t in key.split()):
        out["text"] = "Skriv et navn, fx Anna Jensen eller Firma ApS."
        return out
    items, bad = parse_allow(allow)
    if bad:
        out.update(invalid=bad, text="Ugyldige adresser eller domæner: " + ", ".join(bad[:5])
                   + ". Skriv en hel adresse (fx navn@gmail.com) eller et domæne (fx @firma.dk) – "
                     "aldrig et gratis-maildomæne som gmail.com alene.")
        return out
    if len(items) > ALLOW_MAX:
        out["text"] = f"Højst {ALLOW_MAX} adresser og domæner pr. navn."
        return out
    other = conn.execute("SELECT id FROM namespoof_names WHERE key=?", (key,)).fetchone()
    if entry_id in (None, ""):
        if other:
            out.update(code="exists", text=f"{shown} står allerede på listen.")
            return out
        if conn.execute("SELECT COUNT(*) FROM namespoof_names").fetchone()[0] >= NAMES_MAX:
            out.update(code="full", text=f"Højst {NAMES_MAX} navne.")
            return out
        cur = conn.execute("INSERT INTO namespoof_names(name, key, allow, enabled, source, created_at, created_by) "
                           "VALUES(?,?,?,?,'manual',?,?)", (shown, key, json.dumps(items), 1 if enabled else 0,
                                                           now, str(actor or "")[:80] or None))
        out.update(ok=True, code="ok", entry=get_name(conn, cur.lastrowid),
                   text=f"{shown} er nu et beskyttet navn.")
        return out
    cur_entry = get_name(conn, entry_id)
    if cur_entry is None:
        out.update(code="not_found", text="Navnet findes ikke længere.")
        return out
    if other and int(other[0]) != int(cur_entry["id"]):
        out.update(code="exists", text=f"{shown} står allerede på listen.")
        return out
    if (shown == cur_entry["name"] and items == cur_entry["allow"] and bool(enabled) == cur_entry["enabled"]):
        out.update(ok=True, code="unchanged", entry=cur_entry, text="Uændret.")
        return out
    conn.execute("UPDATE namespoof_names SET name=?, key=?, allow=?, enabled=?, updated_at=?, updated_by=? WHERE id=?",
                 (shown, key, json.dumps(items), 1 if enabled else 0, now, str(actor or "")[:80] or None,
                  int(cur_entry["id"])))
    out.update(ok=True, code="ok", entry=get_name(conn, cur_entry["id"]), text=f"{shown} er gemt.")
    return out


def delete_name(conn: sqlite3.Connection, entry_id: Any) -> dict[str, Any] | None:
    """Remove one entry -> the removed entry (None when missing). Its seed
    key stays in namespoof_seed_seen, so the seed never brings it back."""
    e = get_name(conn, entry_id)
    if e is None:
        return None
    conn.execute("DELETE FROM namespoof_names WHERE id=?", (int(e["id"]),))
    return e


def allow_address(conn: sqlite3.Connection, entry_id: Any, address: Any, *, actor: str = "",
                  now: int | None = None) -> dict[str, Any]:
    """'Tillad adressen' from a hit: add one exact address to an entry.
    -> {ok, code ('ok'|'exists'|'invalid'|'not_found'), text, entry}"""
    e = get_name(conn, entry_id)
    if e is None:
        return {"ok": False, "code": "not_found", "text": "Navnet findes ikke længere.", "entry": None}
    addr = contacts.normalize_address(address)
    if not addr:
        return {"ok": False, "code": "invalid", "text": "Ugyldig adresse.", "entry": e}
    if _allowed(e["allow"], addr):
        return {"ok": True, "code": "exists", "entry": e, "text": f"Adressen må allerede bruge navnet {e['name']}."}
    if len(e["allow"]) >= ALLOW_MAX:
        return {"ok": False, "code": "full", "entry": e, "text": f"Højst {ALLOW_MAX} adresser og domæner pr. navn."}
    allow = [*e["allow"], addr]
    conn.execute("UPDATE namespoof_names SET allow=?, updated_at=?, updated_by=? WHERE id=?",
                 (json.dumps(allow), int(now if now is not None else time.time()), str(actor or "")[:80] or None,
                  int(e["id"])))
    return {"ok": True, "code": "ok", "entry": get_name(conn, e["id"]),
            "text": f"{contacts.mask(addr)} må nu bruge navnet {e['name']}."}


# ---------------------------------------------------------------------------
# Seeding from the Sent folders (contacts.own_identities)
# ---------------------------------------------------------------------------


def _seedable(display: str) -> bool:
    if not display or "@" in display:
        return False
    toks = tokens(display)
    return bool(toks) and any(len(t) >= 2 and t.isalpha() for t in toks)


def seed(conn: sqlite3.Connection, now: int) -> dict[str, int]:
    """Add the From display names of the mailboxes' own identities (Sent,
    >= 3 uses) as protected names, with the addresses they were used
    with. New addresses of an existing (seeded or manual) entry are added
    once; nothing the admin removed comes back. -> {added, extended}"""
    out = {"added": 0, "extended": 0}
    try:
        rows = conn.execute("SELECT display_name, addr, SUM(n) AS n FROM own_identities "
                            "GROUP BY display_name, addr HAVING SUM(n) >= ? ORDER BY SUM(n) DESC",
                            (SEED_MIN_USES,)).fetchall()
    except sqlite3.Error:
        return out
    groups: dict[str, dict[str, Any]] = {}
    for display, addr, n in rows:
        shown = _clean_display(contacts._decode(display) if display else "")
        a = contacts.normalize_address(addr)
        if not a or not _seedable(shown):
            continue
        key = name_key(shown)
        g = groups.setdefault(key, {"name": shown, "addrs": []})
        if a not in g["addrs"]:
            g["addrs"].append(a)
    for key, g in groups.items():
        seen = {str(r[0]) for r in conn.execute("SELECT addr FROM namespoof_seed_seen WHERE key=?", (key,))}
        fresh = [a for a in g["addrs"] if a not in seen]
        if not fresh:
            continue
        for a in fresh:
            conn.execute("INSERT OR IGNORE INTO namespoof_seed_seen(key, addr, seen_at) VALUES(?,?,?)",
                         (key, a, int(now)))
        e = conn.execute("SELECT id FROM namespoof_names WHERE key=?", (key,)).fetchone()
        if e is not None:
            entry = get_name(conn, e[0]) or {"allow": []}
            add = [a for a in fresh if not _allowed(entry["allow"], a)]
            if add and len(entry["allow"]) + len(add) <= ALLOW_MAX:
                conn.execute("UPDATE namespoof_names SET allow=?, updated_at=?, updated_by='auto:sendt' WHERE id=?",
                             (json.dumps([*entry["allow"], *add]), int(now), int(e[0])))
                out["extended"] += 1
            continue
        if seen:
            continue  # the admin deleted this name: never re-add it
        if conn.execute("SELECT COUNT(*) FROM namespoof_names").fetchone()[0] >= NAMES_MAX:
            break
        one_word = len(key.split()) == 1
        conn.execute("INSERT INTO namespoof_names(name, key, allow, enabled, source, created_at, created_by) "
                     "VALUES(?,?,?,?,'seed',?,'auto:sendt')",
                     (g["name"], key, json.dumps(g["addrs"][:ALLOW_MAX]), 0 if one_word else 1, int(now)))
        out["added"] += 1
    return out


def maybe_seed(conn: sqlite3.Connection, now: int, *, interval: int = SEED_INTERVAL_S) -> dict[str, int] | None:
    """seed() at most once per `interval` (engine_state). None = not due."""
    last = _state_get(conn, STATE_SEED)
    try:
        if last and int(now) - int(float(last)) < interval:
            return None
    except (TypeError, ValueError):
        pass
    ensure_schema(conn)
    touch_default(conn, now)
    res = seed(conn, now)
    _state_set(conn, STATE_SEED, str(int(now)), now)
    return res


# ---------------------------------------------------------------------------
# Matching + evaluation
# ---------------------------------------------------------------------------


@dataclass
class Hit:
    entry: dict[str, Any]
    how: str          # 'name' | 'address'


class Matcher:
    """The enabled entries, prepared for matching display names."""

    def __init__(self, entries: Iterable[dict[str, Any]]) -> None:
        self.items: list[tuple[dict[str, Any], tuple[str, ...], set[tuple[str, ...]], str]] = []
        for e in entries or ():
            if not e.get("enabled", True):
                continue
            toks = tuple(str(e.get("key") or name_key(e.get("name"))).split())
            if not toks:
                continue
            self.items.append((e, toks, _variants(toks) if len(toks) >= 2 else set(), "".join(toks)))

    def match(self, display: Any) -> Hit | None:
        # Only the start of a long display name (what a mail client shows
        # anyway): bounds the work for a 10 kB From header.
        text = str(display or "")[:DISPLAY_MAX]
        if not text.strip():
            return None
        disp = tokens(text)
        in_name = {a for a in (contacts.normalize_address(m) for m in _ADDR_IN_TEXT_RE.findall(text)) if a}
        for e, toks, variants, joined in self.items:
            if in_name and any(a in e.get("allow", ()) for a in in_name):
                return Hit(e, "address")
            if not disp:
                continue
            if len(toks) == 1:
                if tuple(disp) == toks:
                    return Hit(e, "name")
                continue
            if any(_contains(disp, v) for v in variants) or joined in disp:
                return Hit(e, "name")
            # "Ole E. Storm": the first and last word with one middle name or
            # initial between them (the whole display name).
            if 2 < len(disp) <= len(toks) + 1 and disp[0] == toks[0] and disp[-1] == toks[-1]:
                return Hit(e, "name")
        return None


@dataclass
class Evaluation:
    mode: str = "off"
    symbols: list[dict] = field(default_factory=list)
    events: list[tuple[str, str]] = field(default_factory=list)
    hit: Hit | None = None
    exempt: str | None = None
    score: float = 0.0


def _decode(value: Any) -> str:
    """A header value as text: RFC 2047 words decoded, raw 8-bit UTF-8
    (which the compat32 parser keeps as surrogate escapes) repaired."""
    s = str(value or "")
    if any("\udc80" <= c <= "\udcff" for c in s):
        s = s.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    return contacts._decode(s)


def _parse(raw: bytes) -> email.message.Message:
    return email.message_from_bytes(raw.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0] + b"\r\n\r\n",
                                    policy=email.policy.compat32)


def _raw_all(msg: email.message.Message, name: str) -> list[str]:
    """The raw values of a header (compat32 turns 8-bit values into Header
    objects that lose the text; raw_items keeps the surrogate escapes)."""
    want = name.lower()
    return [str(v) for k, v in msg.raw_items() if str(k).lower() == want]


def _addrs(msg: email.message.Message, name: str) -> list[tuple[str, str]]:
    """(display name, address) pairs; names decoded AFTER the split, so an
    encoded comma ("Storm, Ole") never splits one address into two."""
    vals = [_decode(v) if "=?" not in v else v for v in _raw_all(msg, name)]
    try:
        pairs = getaddresses(vals)
    except Exception:  # noqa: BLE001 - a broken header is simply no match
        return []
    return [(_decode(n), a.strip()) for n, a in pairs if a.strip() or n.strip()]


def is_lure(subject: Any) -> bool:
    """A CEO-fraud subject: gift cards, "are you at your computer?",
    urgency together with a transfer / payment, secrecy together with a
    payment. Plain billing words never count."""
    text = str(subject or "")[:500]
    if _CEO_RE.search(text):
        return True
    if _TRANSFER_RE.search(text):
        return bool(_URGENT_RE.search(text) or _SECRET_RE.search(text))
    return False


def _strict_from(msg: email.message.Message) -> tuple[str, str] | None:
    """(display name, address) when the From is exactly ONE header with
    exactly one valid address, else None."""
    vals = _raw_all(msg, "From")
    if len(vals) != 1:
        return None
    pairs = _addrs(msg, "From")
    if len(pairs) != 1:
        return None
    display, addr = pairs[0]
    sender = contacts.normalize_address(addr)
    # "ole@bynet.example@evil.example": a second @ in the local part is no address.
    if not sender or "@" in sender.rpartition("@")[0]:
        return None
    return display, sender


def _lenient_from(msg: email.message.Message) -> tuple[list[str], str | None, str | None]:
    """An odd From (several headers or addresses, a trailing comma, garbage,
    an unparseable address): every display-name candidate - the parsed
    names, parseaddr(strict=False)'s name, the text before the first '<'
    and the whole header - the first valid address (or None) and the
    UNAMBIGUOUS address: one From header with a single '@' whose <...> (or
    bare address) is a valid address ("Ole Storm [Molt] <ole@bynet.example>"),
    else None."""
    out: list[str] = []
    sender: str | None = None
    single: str | None = None
    vals = _raw_all(msg, "From")
    if len(vals) == 1:
        text = _decode(vals[0])[:4 * DISPLAY_MAX]
        if text.count("@") == 1:
            m = re.search(r"<([^<>]*)>", text) or _ADDR_IN_TEXT_RE.search(text)
            single = contacts.normalize_address(m.group(1) if m and m.re is not _ADDR_IN_TEXT_RE
                                                else (m.group(0) if m else ""))

    def add(text: Any) -> None:
        t = str(text or "").strip().strip('"').strip()
        if t and t not in out:
            out.append(t[:4 * DISPLAY_MAX])

    for v in _raw_all(msg, "From")[:FROM_MAX]:
        text = _decode(v)[:4 * DISPLAY_MAX]
        try:
            add(parseaddr(text, strict=False)[0])
        except Exception:  # noqa: BLE001 - a broken header is just text
            pass
        add(text.split("<", 1)[0])
        add(text)
    for n, a in _addrs(msg, "From")[:FROM_MAX]:
        add(n)
        cand = contacts.normalize_address(a)
        if sender is None and cand and "@" not in cand.rpartition("@")[0]:
            sender = cand
    return out, sender or single, single


def _platform_via(display: str, matcher: Matcher) -> bool:
    """"Ole Storm (via Google Docs)" / "Molt Handel via MobilePay":
    the protected name is the part BEFORE 'via'."""
    m = _VIA_RE.match(str(display or "")[:DISPLAY_MAX])
    return bool(m) and matcher.match(m.group("name")) is not None


def _score(flags: Iterable[str]) -> float:
    f = set(flags or ())
    if FLAG_PLATFORM in f:
        return SCORE_PLATFORM
    if FLAG_SIGNED in f:
        return SCORE
    return SCORE + (SCORE_COMBO if f & COMBO_FLAGS else 0.0)


def evaluate(conn: sqlite3.Connection, *, raw: bytes, names: Iterable[str] = (),
             dkim_domains: Sequence[str] = (), own_domains: Iterable[str] = (),
             distrust: Iterable[str] = (), mode: str | None = None,
             entries: Iterable[dict[str, Any]] | None = None,
             platform_domains: Iterable[str] = ()) -> Evaluation:
    """TH_NAME_SPOOF (mode on) / TH_NAME_SPOOF_TRIAL (shadow) for one mail.

    Score: +5; +7 with a Reply-To to another domain (another address for a
    freemail From), a CEO-fraud subject (is_lure) or an odd From; at most
    +5 when the From domain (not freemail) has its own aligned DKIM
    signature - a platform / ESP sending in the person's name, a fraudster
    would need that domain's key - and +2 for "<Name> via <platform>" so
    signed (a share / payment notification that names the person; a
    fraudster can pick any name on such a platform, so it still counts a
    little). An odd From (several or unparseable addresses) carrying a
    protected name is always the +7 variant and never exempt."""
    ev = Evaluation(mode=mode if mode in MODES else get_mode(conn)["mode"])
    if ev.mode == "off":
        return ev
    msg = _parse(raw)
    matcher = Matcher(list_names(conn, enabled_only=True) if entries is None else entries)
    strict = _strict_from(msg)
    odd = strict is None
    hit: Hit | None = None
    display = ""
    single: str | None = None
    if strict is not None:
        display, sender = strict
        if not display:
            return ev
        hit = matcher.match(display)
    else:
        candidates, sender, single = _lenient_from(msg)
        for cand in candidates:
            hit = matcher.match(cand)
            if hit is not None:
                display = cand
                break
    if hit is None:
        return ev
    ev.hit = hit
    nameset = {str(n) for n in names or ()}
    from_dom = sender.rpartition("@")[2] if sender else ""
    platforms = own_domains_of(platform_domains)
    owns = [d for d in own_domains_of(own_domains) if not _on_platform(d, platforms)]
    allow = hit.entry.get("allow") or []
    freemail = bool(from_dom) and contacts.is_freemail(from_dom)
    dk = [d for d in (contacts.normalize_domain(x) for x in dkim_domains or ()) if d]
    signed = bool(from_dom) and any(contacts.under(from_dom, d) or contacts.under(d, from_dom) for d in dk)
    if not odd:
        forged = bool(nameset & set(distrust or ()))
        why = _allowed(allow, sender, platforms) or ("own" if _own(from_dom, owns) else None)
        if why and hit.how == "address" and why == "domain":
            why = None   # "ole@bynet.example" <info@shop.example>: only the exact address itself
        if why:
            verified = signed if freemail else (signed or not forged)
            if verified:
                ev.exempt = why
                return ev
    elif single is not None and signed:
        # An odd but unambiguous From (one header, one '@') of a listed / own
        # address: only an aligned DKIM signature proves it - the forged-From
        # symbols cannot be trusted when rspamd may have read the header
        # differently.
        why = _allowed(allow, single, platforms) or ("own" if _own(from_dom, owns) else None)
        if why and not (hit.how == "address" and why == "domain"):
            ev.exempt = why
            return ev
    flags: list[str] = []
    if hit.how == "address":
        flags.append(FLAG_ADDRESS)
    if odd:
        flags.append(FLAG_ODD)
    person_doms = {(a[1:] if a.startswith("@") else a.rpartition("@")[2]) for a in allow}
    person_doms = {d for d in person_doms if d and not contacts.is_freemail(d) and not _on_platform(d, platforms)}
    for _n, rt in _addrs(msg, "Reply-To")[:FROM_MAX]:
        r = contacts.normalize_address(rt)
        if not r or r == sender:
            continue
        rdom = r.rpartition("@")[2]
        same = bool(from_dom) and not freemail and (contacts.under(rdom, from_dom) or contacts.under(from_dom, rdom))
        if (not same and not _allowed(allow, r, platforms) and not _own(rdom, owns)
                and not any(contacts.under(rdom, d) for d in person_doms)):
            flags.append(FLAG_REPLY_TO)
            break
    if is_lure(" ".join(_decode(v) for v in _raw_all(msg, "Subject")[:FROM_MAX])):
        flags.append(FLAG_LURE)
    if not odd and signed and not freemail:
        flags.append(FLAG_PLATFORM if _platform_via(display, matcher) else FLAG_SIGNED)
    ev.score = _score(flags)
    shown = str(hit.entry.get("name") or "")[:60]
    who = contacts.mask(sender) if sender else "ugyldig afsender"
    opts = [shown, who, "+".join(flags) or FLAG_NAME]
    detail = f"{shown}: {who} +{ev.score:g} {opts[2]}"[:300]
    if ev.mode == "on":
        ev.symbols.append({"n": SYMBOL, "s": ev.score, "o": opts})
        ev.events.append(("namespoof_hit", detail))
    else:
        ev.symbols.append({"n": SYMBOL_TRIAL, "s": 0.0, "o": opts})
        ev.events.append(("namespoof_trial", detail))
    return ev


def flags_of(sym: dict) -> list[str]:
    """The flags (third option) of a TH_NAME_SPOOF(_TRIAL) symbol."""
    o = list((sym or {}).get("o") or [])
    return [f for f in str(o[2] if len(o) > 2 else "").split("+") if f]


def score_of(sym: dict) -> float:
    """The score a TH_NAME_SPOOF(_TRIAL) symbol gives / would give."""
    return _score(flags_of(sym))


# ---------------------------------------------------------------------------
# Admin overview helpers (services)
# ---------------------------------------------------------------------------


def hits(conn: sqlite3.Connection, since: int, *, limit: int = 50) -> list[dict[str, Any]]:
    """Name-spoof mail since `since`, grouped per (protected name, sender):
    {name, entry_id, sender, n, last_at, trial, on, accounts, flags, score}."""
    by_key = {e["key"]: e for e in list_names(conn)}
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    try:
        rows = cur.execute("SELECT account, sender, symbols, COALESCE(scanned_at, first_seen) AS ts FROM messages "
                           "WHERE symbols LIKE '%TH_NAME_SPOOF%' AND COALESCE(scanned_at, first_seen) >= ? "
                           "ORDER BY ts DESC LIMIT 2000", (int(since),)).fetchall()
    except sqlite3.Error:
        return []
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for r in rows:
        try:
            syms = json.loads(r["symbols"] or "[]")
        except (TypeError, ValueError):
            continue
        for s in syms if isinstance(syms, list) else []:
            if not isinstance(s, dict) or s.get("n") not in SYMBOLS:
                continue
            o = [str(x) for x in s.get("o") or []]
            if not o:
                continue
            addr = contacts.normalize_address(getaddresses([str(r["sender"] or "")])[0][1]) or ""
            g = groups.setdefault((o[0], addr), {"name": o[0], "sender": addr, "masked": o[1] if len(o) > 1 else "",
                                                 "n": 0, "last_at": 0, "trial": 0, "on": 0, "accounts": [],
                                                 "flags": set(), "score": 0.0, "entry_id": None})
            g["n"] += 1
            g["last_at"] = max(g["last_at"], int(r["ts"] or 0))
            g["trial" if s["n"] == SYMBOL_TRIAL else "on"] += 1
            if r["account"] not in g["accounts"]:
                g["accounts"].append(r["account"])
            g["flags"].update(f for f in flags_of(s) if f != FLAG_NAME)
            g["score"] = max(g["score"], score_of(s))
            e = by_key.get(name_key(o[0]))
            if e is not None:
                g["entry_id"] = e["id"]
                g["allowed"] = bool(addr) and bool(_allowed(e["allow"], addr))
            break
    out = sorted(groups.values(), key=lambda g: (-g["last_at"], g["name"]))[:limit]
    for g in out:
        g["flags"] = sorted(g["flags"])
        g.setdefault("allowed", False)
    return out
