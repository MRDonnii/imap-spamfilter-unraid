"""Newsletter folder "Nyhedsbreve" (spamfilter 2.6, plan item A4).

Newsletters and marketing mail that score BELOW the spam threshold can be
moved from the inbox to a folder of their own instead of staying in the
inbox. Spam keeps priority: anything the spam decision acts on goes to the
spam folder exactly as before; this module only looks at mail the filter
leaves in the inbox.

Per-account settings (accounts.yml, validated by filter.load_account_configs):

  * ``newsletters: off | shadow | on`` - default ``shadow`` ("Prøv"):
    the decision is only recorded (event ``newsletter_shadow`` + the daily
    metric ``newsletter_shadow``) so the owner can judge the list before
    switching it on. ``on`` ("Til") moves the mail - but only while the
    account itself is in mode ``move`` (Filtrér); in shadow/flag mode the
    account moves nothing, so ``on`` then behaves like ``shadow``.
    YAML 1.1 reads a bare ``on``/``off`` as true/false; both spellings are
    accepted (true = on, false = off).
  * ``newsletter_folder`` - default ``Nyhedsbreve``; created on the first
    move (like the spam folder).

Classification (`classify`, pure): a scanned INBOX mail is a newsletter when

  1. the spam decision left it in the inbox and it scores below the
     (effective) threshold, no threat;
  2. it carries a strong bulk signal: List-Unsubscribe or
     List-Unsubscribe-Post, ``Precedence: bulk|list|junk`` or rspamd's
     HAS_LIST_UNSUB / PRECEDENCE_BULK. Known ESP signals (Mailchimp,
     Klaviyo, SendGrid, Salesforce Marketing Cloud, MailerLite ... via
     mailctx.known_esp or their own headers), Feedback-ID, List-Id and
     rspamd's MAILLIST are recorded as supporting signals but are NOT
     enough on their own: receipts and password resets are sent through
     the very same ESPs, just without an unsubscribe header;
  3. and none of these keeps it in the inbox: the sender was kept by the
     user before (see "keep in inbox" below), an allow rule (incl. 'Altid
     igennem') matches, a protected recipient (TH_PROTECTED_RCPT), the
     owner's own domains (vexar.example, webshops, the mailbox domain - also
     as DKIM signer or sending host), a known contact / reply / known
     domain (contacts.py trust symbols), a mail the user starred, or a
     transactional mail (TRANSACTIONAL_PATTERNS on the subject, a
     text/calendar part, Auto-Submitted, typical sender names such as
     faktura@ or alerts@).

Moves (`execute_moves`, engine thread): queued at scan time in
``newsletter_pending`` and moved after ``move_grace_seconds`` with the
engine's own move machinery: imap_move + the move journal (move_journal,
dest = the newsletter folder) so an interrupted COPY/expunge is repaired
(`repair_moves`, reusing filter._repair_one). The same safety nets as spam
moves apply: safe mode, an open circuit breaker and the post-update hold
pause them; ``max_moves_per_hour`` caps them (own rate bucket
``newsletter_move``, so newsletters never trip the spam circuit breaker).
A newsletter move never sets moved_to_junk_at and never learns anything:
Bayes is not trained, autolearn only takes rows the filter moved to the
spam folder (our_action 'moved_to_junk'), and the junk polling only
watches the spam folders (the newsletter folder must differ from them).
Read (\\Seen) or starred mail is left in the inbox when the grace ends.

Keep in inbox: when the user drags a moved newsletter back to the inbox
(new inbox UID with the same Message-ID and INTERNALDATE) or uses
"Tilbage til indbakken" in the web UI, the sender address is stored in
``newsletter_keep`` (per account, exact address). Mail from a kept sender
is never classified as a newsletter again. This is deliberately NOT a
sender rule: an allow rule would also weaken the spam decision (allow
rules pass mail over the threshold), while "keep in inbox" must only
switch off the newsletter folder. The list is shown (and can be emptied
per sender) on the Nyhedsbreve page.

Black Friday folder (2.21): ``black_friday: off | shadow | on`` (default
``shadow``) and ``black_friday_folder`` (default ``Black Friday``). A mail
the classification above calls a newsletter AND whose subject names a
sales event (SALE_RE: Black Friday / Week / Days / Deals / November,
Blackout, Cyber Monday / Week, Singles Day, Green Friday, 11.11) goes to the Black
Friday folder instead - independent of the ``newsletters`` setting, so it
can be switched on per mailbox on its own. Everything else is the
newsletter path: the same exclusions (contacts, allow rules, kept senders,
own domains, transactional mail ...), the same pending table (column
``dest`` = the target folder; NULL = the newsletter folder), journal,
repair, rate bucket and "keep in inbox" memory. ``shadow`` only records
(event ``blackfriday_shadow``) and leaves the mail to the newsletter
setting; ``on`` moves only while the account is in mode ``move``.

Schema: additive only (two new tables + the nullable ``dest`` column,
created idempotently by `ensure_schema`); older images ignore them.
"""

from __future__ import annotations

import logging
import re
import sqlite3
import time
from dataclasses import dataclass, field
from email.utils import parseaddr
from typing import Any, Iterable

import siteconfig

log = logging.getLogger("filter.newsletters")

MODES = ("off", "shadow", "on")
DEFAULT_MODE = "shadow"
DEFAULT_FOLDER = "Nyhedsbreve"
MODE_TEXT = {"off": "Fra", "shadow": "Prøv", "on": "Til"}

# messages.our_action values
ACTION_PENDING = "newsletter_pending"
ACTION_MOVED = "newsletter_moved"
ACTION_FAILED = "newsletter_move_failed"   # a copy may sit in the folder (journal repairs it)
ACTION_KEPT = "newsletter_kept"            # back in the inbox by the user: never moved again
ACTIONS = (ACTION_PENDING, ACTION_MOVED, ACTION_FAILED, ACTION_KEPT)

# events / stats_daily metrics
EVENT_SHADOW = "newsletter_shadow"         # shadow: would have been moved
EVENT_QUEUED = "newsletter_queued"         # on: queued for the move
EVENT_MOVE = "newsletter_move"             # on: moved
EVENT_EXCLUDED = "newsletter_excluded"     # bulk mail kept in the inbox (reason)
EVENT_KEPT = "newsletter_kept"             # user put it back: sender kept
METRIC_SHADOW = "newsletter_shadow"
METRIC_MOVED = "newsletter_moved"
METRIC_KEPT = "newsletter_kept"
METRICS = (METRIC_SHADOW, METRIC_MOVED, METRIC_KEPT)
RATE_ACTION = "newsletter_move"

# 2.21: Black Friday folder (sales-event marketing; see the module text).
KIND_NEWSLETTER = "newsletter"
KIND_SALE = "black_friday"
SALE_DEFAULT_MODE = "shadow"
SALE_DEFAULT_FOLDER = "Black Friday"
SALE_EVENT_SHADOW = "blackfriday_shadow"
SALE_EVENT_QUEUED = "blackfriday_queued"
SALE_EVENT_MOVE = "blackfriday_move"
SALE_METRIC_SHADOW = "blackfriday_shadow"
SALE_METRIC_MOVED = "blackfriday_moved"
SALE_RE = re.compile(
    r"\bblack[\W_]{0,4}(?:friday|fri|weeks?|weekend|days?|deals?|november|month|sales?|offers?|tilbud|uge)\b"
    r"|\bblackfriday|\bblackweek|\bblackout(?![\W_]*gardin)"
    r"|\bcyber[\W_]{0,4}(?:monday|weeks?|weekend|deals?|sales?)\b|\bcybermonday"
    r"|\bsingles?[\W_]{0,4}day\b|\bgreen[\W_]{0,4}friday\b|(?<![\d.,])11\.11(?![\d.,])", re.I)
LIST_DAYS = 7
MOVE_RETRY_LIMIT = 3

# The owner's platform: always in the inbox, whatever accounts.yml says.
ALWAYS_INBOX_DOMAINS = tuple(siteconfig.get_list("platform_domains"))  # local site config

# Contact trust (contacts.py): a known contact, a reply to the user's own
# mail, a reply in a thread and a domain the user corresponds with keep
# the mail in the inbox. TH_ESTABLISHED alone does not: a newsletter the
# user never junks becomes "established" after a few issues.
CONTACT_EXCLUDE = frozenset({"TH_KNOWN_CONTACT", "TH_REPLY", "TH_REPLY_THREAD", "TH_KNOWN_DOMAIN"})
PROTECTED_SYMBOL = "TH_PROTECTED_RCPT"

SCHEMA = """
CREATE TABLE IF NOT EXISTS newsletter_pending (
    account     TEXT NOT NULL,
    uidvalidity INTEGER NOT NULL,
    uid         INTEGER NOT NULL,
    message_id  TEXT NOT NULL,
    folder      TEXT NOT NULL,
    due_at      INTEGER NOT NULL,
    queued_at   INTEGER NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (account, uidvalidity, uid)
);
CREATE INDEX IF NOT EXISTS idx_newsletter_pending_msg ON newsletter_pending(account, message_id);
CREATE TABLE IF NOT EXISTS newsletter_keep (
    account     TEXT NOT NULL,
    sender      TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    created_by  TEXT,
    message_id  TEXT,
    PRIMARY KEY (account, sender)
);
"""


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the tables (idempotent, additive; never COMMITs a caller's
    open transaction)."""
    for stmt in SCHEMA.split(";"):
        if stmt.strip():
            conn.execute(stmt)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(newsletter_pending)")}
    if "dest" not in cols:  # 2.21: target folder (NULL = the newsletter folder)
        conn.execute("ALTER TABLE newsletter_pending ADD COLUMN dest TEXT")


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


def parse_mode(value: Any, account: str = "?") -> str:
    """accounts.yml value -> 'off' | 'shadow' | 'on'. YAML 1.1 turns a bare
    on/off into true/false, so booleans are accepted too. ValueError with
    a short English text otherwise."""
    if isinstance(value, bool):
        return "on" if value else "off"
    s = str(value if value is not None else "").strip().lower()
    if s in MODES:
        return s
    raise ValueError(f"account {account!r}: newsletters must be off, shadow or on")


def mode_of(acc: Any) -> str:
    m = str(getattr(acc, "newsletters", DEFAULT_MODE) or DEFAULT_MODE)
    return m if m in MODES else DEFAULT_MODE


def moves_enabled(acc: Any) -> bool:
    """'on' really moves only while the account moves spam (mode move)."""
    return mode_of(acc) == "on" and getattr(acc, "mode", "shadow") == "move"


def folder_of(acc: Any) -> str:
    """The configured folder name with the server's delimiter applied
    (like filter.resolve_folder: '/' in the config means a subfolder)."""
    name = str(getattr(acc, "newsletter_folder", "") or DEFAULT_FOLDER)
    delim = str(getattr(acc, "delimiter", "/") or "/")
    return name if delim == "/" or "/" not in name else name.replace("/", delim)


def sale_mode_of(acc: Any) -> str:
    m = str(getattr(acc, "black_friday", SALE_DEFAULT_MODE) or SALE_DEFAULT_MODE)
    return m if m in MODES else SALE_DEFAULT_MODE


def sale_moves_enabled(acc: Any) -> bool:
    return sale_mode_of(acc) == "on" and getattr(acc, "mode", "shadow") == "move"


def sale_folder_of(acc: Any) -> str:
    name = str(getattr(acc, "black_friday_folder", "") or SALE_DEFAULT_FOLDER)
    delim = str(getattr(acc, "delimiter", "/") or "/")
    return name if delim == "/" or "/" not in name else name.replace("/", delim)


def active(acc: Any) -> bool:
    """Classify inbox mail at all (either folder not off)."""
    return mode_of(acc) != "off" or sale_mode_of(acc) != "off"


def is_sale(subject: Any) -> bool:
    """The subject names a sales event (Black Friday, Cyber Monday ...)."""
    return bool(SALE_RE.search(str(subject or "")))


def folder_conflict(dest: str, fmap: dict[str, Any]) -> str | None:
    """The folder-map key the newsletter folder collides with (inbox,
    spam folders, trash, training folders), else None. Never move
    newsletters into a folder the filter treats as junk."""
    d = str(dest or "").lower()
    for key, val in (fmap or {}).items():
        if isinstance(val, str) and val.lower() == d:
            return key
    return None


# ---------------------------------------------------------------------------
# Classification (pure)
# ---------------------------------------------------------------------------

# rspamd symbols that mean "bulk mail" on their own / support it.
STRONG_SYMBOLS = frozenset({"HAS_LIST_UNSUB", "PRECEDENCE_BULK"})
SUPPORT_SYMBOLS = frozenset({"MAILLIST"})

# Header names (lower case) or prefixes set by marketing platforms.
ESP_HEADERS: tuple[tuple[str, str], ...] = (
    ("x-mc-user", "Mailchimp"), ("x-mailchimp", "Mailchimp"), ("x-mandrill-user", "Mailchimp"),
    ("x-campaignid", "Mailchimp"),
    ("x-sg-eid", "SendGrid"), ("x-sg-id", "SendGrid"),
    ("x-sfmc", "Salesforce Marketing Cloud"), ("x-job", "Salesforce Marketing Cloud"),
    ("x-klaviyo", "Klaviyo"), ("x-kmail", "Klaviyo"),
    ("x-mailerlite", "MailerLite"), ("x-ml-", "MailerLite"),
    ("x-hs-", "HubSpot"), ("x-mailgun", "Mailgun"), ("x-mailjet", "Mailjet"),
    ("x-sib-", "Brevo"), ("x-heyloyalty", "Heyloyalty"), ("x-apsis", "APSIS"),
    ("x-csa-complaints", "CSA (masseudsendelse)"),
)
# X-Mailer / User-Agent values of marketing tools.
_ESP_MAILER_RE = re.compile(
    r"mailchimp|mandrill|klaviyo|mailerlite|sendinblue|brevo|hubspot|salesforce|marketing cloud|exacttarget|"
    r"campaign ?monitor|heyloyalty|ubivox|apsis|agillic|peytz|mailjet|sendgrid|mailgun|getresponse|"
    r"activecampaign|constant ?contact|emarsys|acoustic|braze|customer\.io|omnisend|squarespace|shopify email",
    re.I)
_PRECEDENCE_RE = re.compile(r"^\s*(bulk|list|junk)\b", re.I)

# Transactional mail stays in the inbox. Subject patterns (lower case,
# Danish and English), matched as words after the MARKETING_PHRASES below
# are removed. Keep each group commented; add words, never remove them
# without a test.
TRANSACTIONAL_PATTERNS: tuple[tuple[str, str], ...] = (
    # Orders, receipts, invoices, payments
    ("ordre", r"\bordre\w*"), ("bestilling", r"\bbestilling\w*"),
    ("order", r"\b(your|din|my) order\b|\border (confirm\w*|no\.?|number|#|received|update|status|"
              r"has shipped|shipped|details)\b"),
    ("kvittering", r"\bkvittering\w*"), ("receipt", r"\breceipts?\b"),
    ("faktura", r"\bfaktura\w*|\bkreditnota\w*"), ("invoice", r"\binvoices?\b|\bcredit note\b"),
    ("betaling", r"\bbetaling(en)? (er )?(modtaget|gennemført|bekræftet|fejlede|mislykkedes|afvist)\b|"
                 r"\bbetalingspåmindelse\b|\brykker\b"),
    ("payment", r"\bpayment (received|confirm\w*|failed|declined|due|reminder|successful)\b"),
    ("refusion", r"\brefusion\w*|\brefund\w*|\btilbagebetaling\w*"),
    ("kontoudtog", r"\bkontoudtog\w*"),
    # Shipping and tracking
    ("levering", r"\blevering\w*|\bleveret\b|\budleveret\b"),
    ("pakke", r"\bpakke(n|r|rne)?\b|\bpakkeshop\w*|\bpakkeboks\w*|\bafhentning\w*"),
    ("forsendelse", r"\bforsendelse\w*|\bafsendt\b|\bsporing\w*|\bsporings\w*"),
    ("shipping", r"\bshipped\b|\bshipping (confirm\w*|update|notification)\b|\btracking\b|\btrack your\b|"
                 r"\bdelivery\b|\bdelivered\b|\bout for delivery\b"),
    # Accounts, passwords, codes and security
    ("adgangskode", r"\badgangskode\w*|\bpassword\w*|\bnulstil\w*|\breset\b"),
    ("kode", r"\bkode\b|\b(engangs|sikkerheds|bekræftelses|verifikations|aktiverings|login|pin)-?kode\w*|"
             r"\bdin kode\b|\b(verification|security|one[- ]time|login|sign[- ]in|access|confirmation|"
             r"authentication) code\b|\byour code\b|\b2fa\b|\botp\b"),
    ("totrins", r"\btwo[- ]factor\b|\bto[- ]?faktor\w*|\b2[- ]?trins\w*|\btotrins\w*"),
    ("bekræft", r"\bbekræft\w*|\bconfirm (your|my|email|e-mail|account|subscription|registration)\b|"
                r"\bverif(y|ication|icer\w*)\b|\baktiv[eé]r (din|konto)\b|\bactivate (your )?account\b"),
    ("konto oprettet", r"\b(konto|account|profil)\w*\b.{0,60}\b(oprettet|created|registreret|registered)\b"),
    ("login", r"\blog ?ind\b|\blogin\b|\bsign[- ]in\b|\bny enhed\b|\bnew (device|sign[- ]in|login)\b"),
    ("sikkerhed", r"\bsikkerhed\w*|\bsecurity (alert|notice|notification|warning)\b|\balert\b|\badvarsel\w*|"
                  r"\balarm\w*"),
    # Calendar invitations and bookings
    ("invitation", r"\binvitation\w*|\binviteret\b|\binvitere[rt]?\b|\binvite[ds]?\b|\binvited\b"),
    ("kalender", r"\bkalender\w*|\bcalendar\b|\bmødeindkaldelse\w*|\bmeeting\b|\baccepted:|\baccepteret:|"
                 r"\bdeclined:|\bafvist:|\baflyst\b|\bcancell?ed\b|\bappointment\b|\bdin (tid|aftale)\b"),
    ("booking", r"\bbooking\w*|\breservation\w*|\bbookingbekræftelse\w*"),
    # Subscriptions and contracts the user has (not marketing for them)
    ("abonnement", r"\b(dit|your) (abonnement|subscription)\b|\bfornyelse\w*|\brenewal\b|\bopsigelse\w*"),
)
_TRANSACTIONAL = tuple((label, re.compile(p, re.I)) for label, p in TRANSACTIONAL_PATTERNS)
# Marketing phrases that contain a transactional word but are marketing
# ("Gratis levering", "Brug rabatkoden"): removed before matching.
MARKETING_PHRASES = re.compile(
    r"\b(gratis|fri|hurtig) (levering|fragt|forsendelse)\w*|\bfri fragt\b|\bfree (shipping|delivery)\b|"
    r"\b\w*rabatkode\w*|\bkuponkode\w*|\b(promo|discount|coupon|voucher) codes?\b", re.I)
# Sender local parts of transactional senders.
_TRANSACTIONAL_LOCAL_RE = re.compile(
    r"^(faktura|fakturering|invoices?|billing|receipts?|kvittering|orders?|ordre|bestilling|shipping|"
    r"forsendelse|levering|tracking|security|sikkerhed|alerts?|calendar|kalender|booking)([-+_.].*)?$", re.I)
_AUTO_SUBMITTED_RE = re.compile(r"^\s*auto-(generated|replied|notified)", re.I)


@dataclass
class Verdict:
    """Outcome of `classify`. newsletter=False with a reason in
    EXCLUSION_TEXT (bulk mail kept in the inbox) or 'no_bulk'."""
    newsletter: bool
    reason: str
    detail: str = ""
    signals: list = field(default_factory=list)
    sale: bool = False  # 2.21: the subject names a sales event (SALE_RE)

    @property
    def bulk(self) -> bool:
        return bool(self.signals)

    def event_detail(self) -> str:
        sig = ",".join(self.signals[:6]) or "-"
        return (f"{self.reason}" + (f" {self.detail}" if self.detail else "") + f" signals={sig}")[:300]


EXCLUSION_TEXT = {
    "spam": "Over spamgrænsen – behandlet som spam",
    "keep": "Afsenderen skal blive i indbakken",
    "allow_rule": "Afsenderen er tilladt",
    "protected": "Sendt til en beskyttet adresse",
    "own_domain": "Fra jeres egne domæner",
    "contact": "Kendt kontakt eller svar på din mail",
    "flagged": "Stjernemarkeret",
    "transactional": "Ordre, faktura, levering, kode eller invitation",
    "no_bulk": "Ingen tegn på masseudsendelse",
}


def _headers(raw: bytes | str | None) -> list[tuple[str, str]]:
    try:
        import mailctx  # noqa: PLC0415 - pure helper, imported lazily like in the engine
        return mailctx.parse_headers(raw)
    except Exception:  # noqa: BLE001 - classification must never break a scan
        return []


def _known_esp(ctx: dict | None, dkim: Iterable[str]) -> str | None:
    try:
        import mailctx  # noqa: PLC0415
        return mailctx.known_esp(ctx or {}, list(dkim or ()))
    except Exception:  # noqa: BLE001
        return None


def bulk_signals(headers: list[tuple[str, str]], names: Iterable[str] = (), ctx: dict | None = None,
                 dkim: Iterable[str] = ()) -> tuple[list[str], list[str]]:
    """(strong, supporting) bulk signals. Strong: List-Unsubscribe(-Post),
    Precedence bulk/list/junk, rspamd HAS_LIST_UNSUB / PRECEDENCE_BULK.
    Supporting: ESP name/headers, Feedback-ID, List-Id, MAILLIST."""
    strong: list[str] = []
    support: list[str] = []

    def add(lst: list[str], s: str) -> None:
        if s not in strong and s not in support:
            lst.append(s)

    for name, value in headers:
        if name == "list-unsubscribe" and value.strip():
            add(strong, "list-unsubscribe")
        elif name == "list-unsubscribe-post" and value.strip():
            add(strong, "list-unsubscribe-post")
        elif name == "precedence" and _PRECEDENCE_RE.match(value or ""):
            add(strong, f"precedence:{_PRECEDENCE_RE.match(value).group(1).lower()}")
        elif name == "feedback-id" and value.strip():
            add(support, "feedback-id")
        elif name == "list-id" and value.strip():
            add(support, "list-id")
        elif name in ("x-mailer", "user-agent") and _ESP_MAILER_RE.search(value or ""):
            add(support, f"esp:{_ESP_MAILER_RE.search(value).group(0).lower()}")
        else:
            for prefix, esp in ESP_HEADERS:
                if name.startswith(prefix):
                    add(support, f"esp:{esp}")
                    break
    nm = set(names or ())
    for s in sorted(nm & STRONG_SYMBOLS):
        add(strong, s)
    for s in sorted(nm & SUPPORT_SYMBOLS):
        add(support, s)
    esp = _known_esp(ctx, dkim)
    if esp:
        add(support, f"esp:{esp}")
    return strong, support


def transactional_reason(subject: str, headers: list[tuple[str, str]] = (), sender: str | None = None,
                         raw: bytes | str | None = None) -> str | None:
    """Why this looks like a transactional mail (order, invoice, shipping,
    code, security notice, invitation ...), else None."""
    subj = MARKETING_PHRASES.sub(" ", re.sub(r"\s+", " ", str(subject or "")))
    for label, rx in _TRANSACTIONAL:
        if rx.search(subj):
            return f"emne:{label}"
    for name, value in headers or ():
        if name == "auto-submitted" and _AUTO_SUBMITTED_RE.match(value or ""):
            return "auto-submitted"
        if name == "content-type" and "text/calendar" in (value or "").lower():
            return "kalender"
    if raw is not None:
        blob = raw[:262144] if isinstance(raw, (bytes, bytearray)) else str(raw)[:262144].encode("utf-8", "replace")
        if b"text/calendar" in bytes(blob).lower():
            return "kalender"
    local = str(sender or "").rpartition("@")[0]
    if local and _TRANSACTIONAL_LOCAL_RE.match(local):
        return f"afsender:{local.lower()[:40]}"
    return None


def _domain_under(host: str | None, domain: str) -> bool:
    h = str(host or "").strip().lower().rstrip(".")
    d = str(domain or "").strip().lower().rstrip(".")
    return bool(h) and bool(d) and (h == d or h.endswith("." + d))


def own_domain_hit(domains: Iterable[str], *hosts: str | None) -> str | None:
    """The owner domain one of `hosts` (From/envelope domain, DKIM signer,
    sending host) lies under, else None. vexar.example always counts."""
    owners = [d for d in (*ALWAYS_INBOX_DOMAINS, *(domains or ())) if d]
    for host in hosts:
        for d in owners:
            if _domain_under(host, d):
                return d
    return None


def _dom(addr: str | None) -> str:
    return str(addr or "").rpartition("@")[2].strip().lower()


def classify(raw: bytes | str | None, *, subject: str, sender: str | None, envelope_from: str | None = None,
             names: Iterable[str] = (), ctx: dict | None = None, auth: dict | None = None,
             final: float = 0.0, threshold: float = 0.0, spam: bool = False, threat: str | None = None,
             flags: Iterable[str] = (), allow_rule: bool = False, kept: bool = False,
             owner_domains: Iterable[str] = ()) -> Verdict:
    """Is this inbox mail a newsletter that may go to the newsletter
    folder? Pure: every database fact (allow rule, kept sender) is passed
    in. Spam always wins: spam/threat/over the threshold -> 'spam'."""
    nm = frozenset(names or ())
    if spam or threat or final >= threshold:
        return Verdict(False, "spam")
    headers = _headers(raw)
    a = auth or {}
    dkim = [str(d) for d in (a.get("dkim") or [])]
    strong, support = bulk_signals(headers, nm, ctx, dkim)
    signals = strong + support
    if not strong:
        return Verdict(False, "no_bulk", signals=signals)
    if kept:
        return Verdict(False, "keep", signals=signals)
    if allow_rule:
        return Verdict(False, "allow_rule", signals=signals)
    if PROTECTED_SYMBOL in nm:
        return Verdict(False, "protected", signals=signals)
    own = own_domain_hit(owner_domains, _dom(sender), _dom(envelope_from), *dkim,
                         a.get("host"), (ctx or {}).get("origin_host"))
    if own:
        return Verdict(False, "own_domain", own, signals=signals)
    trust = sorted(nm & CONTACT_EXCLUDE)
    if trust:
        return Verdict(False, "contact", trust[0], signals=signals)
    if "\\Flagged" in set(flags or ()):
        return Verdict(False, "flagged", signals=signals)
    why = transactional_reason(subject, headers, sender, raw)
    if why:
        return Verdict(False, "transactional", why, signals=signals)
    return Verdict(True, "newsletter", signals=signals)


# ---------------------------------------------------------------------------
# Keep in inbox (per account, exact sender address)
# ---------------------------------------------------------------------------


def sender_key(sender: Any) -> str | None:
    s = parseaddr(str(sender or ""))[1] or str(sender or "")
    s = s.strip().strip("<>").strip().lower()
    if "@" not in s or len(s) > 254 or any(c in s for c in " \t\r\n\x00"):
        return None
    return s


def is_kept(conn: sqlite3.Connection, account: str, sender: Any) -> bool:
    key = sender_key(sender)
    if key is None:
        return False
    try:
        return conn.execute("SELECT 1 FROM newsletter_keep WHERE account=? AND sender=?",
                            (account, key)).fetchone() is not None
    except sqlite3.Error:
        return False


def add_keep(conn: sqlite3.Connection, account: str, sender: Any, *, by: str = "", message_id: str | None = None,
             now: int | None = None) -> str | None:
    """Remember `sender` as "keep in inbox". Caller handles the
    transaction. Returns the stored key (None for an unusable address)."""
    key = sender_key(sender)
    if key is None:
        return None
    conn.execute("INSERT OR IGNORE INTO newsletter_keep(account, sender, created_at, created_by, message_id) "
                 "VALUES(?,?,?,?,?)", (account, key, int(now if now is not None else time.time()),
                                       (by or None), message_id))
    return key


def remove_keep(conn: sqlite3.Connection, account: str, sender: Any) -> bool:
    key = sender_key(sender)
    if key is None:
        return False
    return conn.execute("DELETE FROM newsletter_keep WHERE account=? AND sender=?", (account, key)).rowcount > 0


def kept_senders(conn: sqlite3.Connection, account: str, limit: int = 500) -> list[dict[str, Any]]:
    try:
        rows = conn.execute("SELECT sender, created_at, created_by FROM newsletter_keep WHERE account=? "
                            "ORDER BY created_at DESC LIMIT ?", (account, int(limit))).fetchall()
    except sqlite3.Error:
        return []
    return [{"sender": r[0], "created_at": r[1], "created_by": r[2]} for r in rows]


# ---------------------------------------------------------------------------
# Engine glue (called from filter.py with the engine module as `eng`;
# filter.py runs as __main__, so this module never imports it)
# ---------------------------------------------------------------------------


def scan_decision(eng: Any, db: Any, acc: Any, sc: Any, *, flags: Iterable[str], raw: bytes) -> Verdict | None:
    """Classify one scanned inbox mail (inside _scan_and_act, before the
    bookkeeping transaction). None when the feature is off or the spam
    decision already acts on / decided about the mail."""
    if not active(acc):
        return None
    decision = sc.decision
    if decision.spam or (decision.action or "none") != "none" or str(decision.rule_hit or "").startswith("allow:"):
        return None
    sender = sc.sender or sc.envelope_from
    allow = False
    try:
        rule = eng.match_sender_rule(db.conn, acc.name, sender) if sender else None
        allow = rule is not None and rule["kind"] == "allow"
    except sqlite3.Error:
        allow = True  # unknown: keep it in the inbox
    try:
        v = classify(raw, subject=sc.subject, sender=sc.sender, envelope_from=sc.envelope_from,
                     names=sc.names, ctx=sc.ctx, auth=sc.auth, final=sc.final, threshold=sc.thr,
                     spam=decision.spam, threat=sc.threat, flags=flags, allow_rule=allow,
                     kept=is_kept(db.conn, acc.name, sc.sender), owner_domains=eng.owner_domains(acc))
    except Exception as ex:  # noqa: BLE001 - never block a scan
        log.warning("newsletter classification failed: %s", type(ex).__name__)
        return None
    v.sale = sale_mode_of(acc) != "off" and is_sale(sc.subject)
    if mode_of(acc) == "off" and not v.sale:
        return None  # only the Black Friday folder is on, and this is no sales mail
    return v


def record_scan(db: Any, acc: Any, verdict: Verdict | None, *, msgid: str, uv: int, uid: int, inbox: str,
                now: int) -> str | None:
    """Inside the scan transaction: log the decision; queue the move in
    'on' mode. Returns the our_action to store (ACTION_PENDING) or None."""
    if verdict is None:
        return None
    if not verdict.newsletter:
        if verdict.bulk and verdict.reason not in ("spam", "no_bulk"):
            db.log_event(EVENT_EXCLUDED, msgid, detail=verdict.event_detail())
        return None
    grace = max(0, int(getattr(acc, "move_grace_seconds", 60) or 0))

    def queue(dest: str | None, event: str) -> str:
        db.conn.execute(
            "INSERT OR REPLACE INTO newsletter_pending(account, uidvalidity, uid, message_id, folder, due_at, "
            "queued_at, attempts, dest) VALUES(?,?,?,?,?,?,?,0,?)",
            (db.account, int(uv), int(uid), msgid, inbox, now + grace, now, dest))
        db.log_event(event, msgid, detail=verdict.event_detail())
        return ACTION_PENDING

    if verdict.sale and sale_mode_of(acc) != "off":
        if sale_moves_enabled(acc):
            return queue(sale_folder_of(acc), SALE_EVENT_QUEUED)
        # Prøv: record it, and let the newsletter setting decide as before.
        db.log_event(SALE_EVENT_SHADOW, msgid, detail=verdict.event_detail())
        db.bump(SALE_METRIC_SHADOW)
    if mode_of(acc) == "off":
        return None
    if not moves_enabled(acc):
        db.log_event(EVENT_SHADOW, msgid, detail=verdict.event_detail())
        db.bump(METRIC_SHADOW)
        return None
    return queue(None, EVENT_QUEUED)


def on_inbox_sighting(db: Any, log_: logging.Logger, acc: Any, fmap: dict[str, str], prior: Any, msgid: str,
                      idate: int | None, now: int) -> bool:
    """A known Message-ID got a new inbox UID. True = handled here (the
    caller must not score it): a newsletter the filter moved, put back by
    the user (same INTERNALDATE: the very copy we moved) - its sender is
    kept in the inbox from now on - or a mail already kept."""
    act = _get(prior, "our_action")
    if act not in (ACTION_MOVED, ACTION_FAILED, ACTION_KEPT):
        return False
    received = _get(prior, "received_at")
    if received is None or idate is None or int(idate) != int(received):
        # A Message-ID alone proves nothing: only the very copy we know (same
        # INTERNALDATE - a move/copy keeps it) is skipped; a new delivery of
        # the same Message-ID, or one we cannot compare, is scored like new mail.
        return False
    if act == ACTION_KEPT:
        with db.tx():
            db.update_message(msgid, current_folder=fmap["inbox"], last_seen=now)
        return True
    sender = _get(prior, "sender")
    with db.tx():
        db.update_message(msgid, current_folder=fmap["inbox"], our_action=ACTION_KEPT, last_seen=now)
        db.conn.execute("DELETE FROM newsletter_pending WHERE account=? AND message_id=?", (db.account, msgid))
        key = add_keep(db.conn, db.account, sender, by="user:move", message_id=msgid, now=now)
        db.log_event(EVENT_KEPT, msgid, detail=f"from {_get(prior, 'current_folder') or '-'}"
                     + (" sender kept" if key else ""))
        db.bump(METRIC_KEPT)
    log_.info("newsletter %s put back into the inbox by the user; sender kept", msgid)
    return True


def _get(row: Any, key: str) -> Any:
    if row is None:
        return None
    try:
        return row[key]
    except (IndexError, KeyError):
        return None


def _cancel_pending(db: Any, rows: Iterable[Any], event: str | None = None) -> None:
    for r in rows:
        db.conn.execute("DELETE FROM newsletter_pending WHERE account=? AND uidvalidity=? AND uid=?",
                        (db.account, r["uidvalidity"], r["uid"]))
        db.conn.execute("UPDATE messages SET our_action='none' WHERE account=? AND message_id=? "
                        "AND our_action=?", (db.account, r["message_id"], ACTION_PENDING))
        if event:
            db.log_event(event, r["message_id"], detail=f"uid={r['uid']}")


def _kind_names(kind: str) -> tuple[str, str]:
    """(move event, moved metric) for a folder kind."""
    return (SALE_EVENT_MOVE, SALE_METRIC_MOVED) if kind == KIND_SALE else (EVENT_MOVE, METRIC_MOVED)


def execute_moves(eng: Any, client: Any, db: Any, log_: logging.Logger, acc: Any, fmap: dict[str, str],
                  state: Any) -> int:
    """Move due newsletters to the newsletter folder and due sales mail to
    the Black Friday folder (engine thread, after the spam moves). Returns
    the number moved."""
    try:
        pending = db.conn.execute("SELECT * FROM newsletter_pending WHERE account=? ORDER BY due_at, uid",
                                  (db.account,)).fetchall()
    except sqlite3.Error:
        return 0
    nl_dest, sale_dest = folder_of(acc), sale_folder_of(acc)
    nl_rows: list[Any] = []
    sale_rows: list[Any] = []
    stray: list[Any] = []
    for r in pending:
        d = _get(r, "dest") or nl_dest
        (nl_rows if d == nl_dest else sale_rows if d == sale_dest else stray).append(r)
    if stray:  # queued for a folder that was renamed since: leave it in the inbox
        with db.tx():
            _cancel_pending(db, stray, "newsletter_cancelled")
    moved = _execute_group(eng, client, db, log_, acc, fmap, state, nl_rows, nl_dest, moves_enabled(acc),
                           KIND_NEWSLETTER)
    if sale_dest != nl_dest:
        moved += _execute_group(eng, client, db, log_, acc, fmap, state, sale_rows, sale_dest,
                                sale_moves_enabled(acc), KIND_SALE)
    return moved


def _execute_group(eng: Any, client: Any, db: Any, log_: logging.Logger, acc: Any, fmap: dict[str, str],
                   state: Any, pending: list[Any], dest: str, enabled: bool, kind: str) -> int:
    move_event, moved_metric = _kind_names(kind)
    has_journal = any(r["dest"] == dest for r in eng._journal_rows(db, fmap["inbox"]))
    if not pending and not has_journal:
        return 0
    if not enabled:
        if pending:
            with db.tx():
                _cancel_pending(db, pending, "newsletter_cancelled")
        return 0
    if db.in_safe_mode("all") or eng.circuit_open(db.conn, db.account):
        return 0
    now = int(eng._now())
    if now < eng.move_hold_until(db.conn):
        return 0  # right after an update: wait, like borderline spam
    conflict = folder_conflict(dest, fmap)
    if conflict is not None:
        if pending:
            with db.tx():
                _cancel_pending(db, pending, None)
                db.log_event("newsletter_folder_invalid", detail=f"{dest} = {conflict}")
            log_.error("newsletter folder %s collides with the %s folder; not moving", dest, conflict)
        return 0
    if has_journal:
        repair_moves(eng, client, db, log_, acc, fmap, state, dest, kind=kind)
    inbox = fmap["inbox"]
    due = [r for r in pending if int(r["due_at"]) <= now and r["folder"] == inbox]
    if not due:
        return 0
    uv = eng.select_with_uidvalidity_check(client, db, inbox, log_)
    stale = [r for r in due if int(r["uidvalidity"]) != uv]
    if stale:
        with db.tx():
            _cancel_pending(db, stale, "newsletter_skipped_uidvalidity")
    due = [r for r in due if int(r["uidvalidity"]) == uv]
    if not due:
        return 0
    if not eng.check_rate(db, log_, RATE_ACTION, acc.max_moves_per_hour):
        return 0
    remaining = acc.max_moves_per_hour - db.rate_count(RATE_ACTION, 3600)
    fetched = client.fetch([int(r["uid"]) for r in due], [b"FLAGS", b"INTERNALDATE"])
    to_move: list[int] = []
    by_uid: dict[int, Any] = {}
    skips: list[tuple[Any, str]] = []
    for r in due:
        uid, msgid = int(r["uid"]), r["message_id"]
        if eng._journal_has(db, msgid):
            continue  # an interrupted move awaits repair
        msg = db.get_message(msgid)
        skip = None
        if uid not in fetched:
            skip = "newsletter_skipped_missing"
        elif msg is None or msg["our_action"] != ACTION_PENDING:
            skip = "newsletter_skipped_changed"  # released, junked or moved meanwhile
        elif db.conn.execute("SELECT 1 FROM pending_move WHERE account=? AND message_id=?",
                             (db.account, msgid)).fetchone() is not None:
            skip = "newsletter_skipped_spam"     # spam has priority
        else:
            flags = eng._flag_names(fetched[uid].get(b"FLAGS"))
            rule = eng.match_sender_rule(db.conn, acc.name, msg["sender"]) if msg["sender"] else None
            if "\\Seen" in flags:
                skip = "newsletter_skipped_read"   # read during the grace: the user handled it
            elif "\\Flagged" in flags:
                skip = "newsletter_skipped_flagged"
            elif "\\Deleted" in flags:
                skip = "newsletter_skipped_deleted"
            elif is_kept(db.conn, acc.name, msg["sender"]):
                skip = "newsletter_skipped_kept"
            elif rule is not None and rule["kind"] == "allow":
                skip = "newsletter_skipped_rule"
        if skip:
            skips.append((r, skip))
            continue
        to_move.append(uid)
        by_uid[uid] = r
    if skips:
        with db.tx():
            for r, ev in skips:
                _cancel_pending(db, [r], ev)
    to_move = to_move[: max(0, remaining)]
    if not to_move:
        return 0
    if not _ensure_folder(eng, client, db, log_, state, dest):
        return 0
    eng.select_with_uidvalidity_check(client, db, inbox, log_)
    msgids = {u: by_uid[u]["message_id"] for u in to_move}
    idates = {u: eng._internaldate_ts(fetched.get(u) or {}) for u in to_move}
    on_stage = eng._journal_writer(db, inbox, uv, dest, msgids, idates)
    moved: list[int] = []
    failed: list[int] = []
    copied_any = final = False
    error_text = ""
    try:
        eng.imap_move(client, to_move, dest, capabilities=getattr(state, "caps", None)
                      or eng.client_capabilities(client), on_stage=on_stage)
        moved = list(to_move)
    except eng.MoveUnsupported as ex:
        failed, final, error_text = list(to_move), True, str(ex)
    except eng.MoveError as ex:
        moved = [u for u in to_move if u in ex.moved]
        failed = [u for u in to_move if u not in ex.moved]
        copied_any = final = bool(ex.copied)
        error_text = str(ex)
    now = int(eng._now())
    with db.tx():
        for uid in moved:
            msgid = msgids[uid]
            db.conn.execute("DELETE FROM newsletter_pending WHERE account=? AND uidvalidity=? AND uid=?",
                            (db.account, uv, uid))
            db.conn.execute("DELETE FROM move_journal WHERE account=? AND folder=? AND uidvalidity=? AND uid=?",
                            (db.account, inbox, uv, uid))
            db.update_message(msgid, current_folder=dest, our_action=ACTION_MOVED, last_seen=now)
            db.record_rate(RATE_ACTION)
            db.bump(moved_metric)
            db.log_event(move_event, msgid, detail=f"uid={uid} -> {dest}")
        for uid in failed:
            msgid = msgids[uid]
            if not copied_any:
                db.conn.execute("DELETE FROM move_journal WHERE account=? AND folder=? AND uidvalidity=? "
                                "AND uid=?", (db.account, inbox, uv, uid))
            attempts = int(by_uid[uid]["attempts"] or 0) + 1
            if final or attempts >= MOVE_RETRY_LIMIT:
                db.conn.execute("DELETE FROM newsletter_pending WHERE account=? AND uidvalidity=? AND uid=?",
                                (db.account, uv, uid))
                # copied: a copy may sit in the folder - the journal row
                # stays and repair_moves finishes (or undoes) it.
                db.update_message(msgid, our_action=ACTION_FAILED if copied_any else "none")
                db.log_event("newsletter_move_failed", msgid, detail=error_text[:300])
            else:
                db.conn.execute("UPDATE newsletter_pending SET attempts=? WHERE account=? AND uidvalidity=? "
                                "AND uid=?", (attempts, db.account, uv, uid))
                db.log_event("newsletter_move_retry", msgid, detail=f"attempt={attempts}: {error_text}"[:300])
    if moved:
        log_.info("moved %d newsletter(s) %s -> %s", len(moved), inbox, dest)
    if failed:
        log_.warning("newsletter move of %d message(s) to %s failed: %s", len(failed), dest, error_text)
    return len(moved)


def _ensure_folder(eng: Any, client: Any, db: Any, log_: logging.Logger, state: Any, dest: str) -> bool:
    """Create (and subscribe) the newsletter folder on the first move."""
    listing = list(getattr(state, "folder_listing", None) or [])
    names = {str(n) for _f, n in listing}
    if dest in names:
        return True
    try:
        live = {eng._to_str(n) for _f, _d, n in client.list_folders()}
    except eng._CONN_ERRORS:
        raise
    except Exception:  # noqa: BLE001 - fall back to creating it
        live = set()
    if dest in live:
        listing.append((["\\HasNoChildren"], dest))
        state.folder_listing = listing
        return True
    ok = eng._create_folder(client, db, log_, dest)
    if ok:
        listing.append((["\\HasNoChildren"], dest))
        state.folder_listing = listing
    return ok


def repair_moves(eng: Any, client: Any, db: Any, log_: logging.Logger, acc: Any, fmap: dict[str, str],
                 state: Any, dest: str, *, kind: str = KIND_NEWSLETTER) -> int:
    """Finish newsletter moves interrupted between COPY, STORE \\Deleted and
    UID EXPUNGE, with the engine's own repair (filter._repair_one) against
    the newsletter folder. Returns the number of rows resolved."""
    inbox = fmap["inbox"]
    jrows = [r for r in eng._journal_rows(db, inbox) if r["dest"] == dest]
    if not jrows:
        return 0
    inbox_uv = eng.select_with_uidvalidity_check(client, db, inbox, log_)
    fm = dict(fmap, junk=dest)
    resolved = 0
    for r in jrows:
        msgid = r["message_id"]
        try:
            outcome = eng._repair_one(client, db, log_, acc, fm, state, msgid=msgid, stage=r["stage"],
                                      idate=r["internaldate"], predeleted=bool(r["predeleted"]),
                                      inbox_uv=inbox_uv, journal_uv=int(r["uidvalidity"]),
                                      journal_uid=int(r["uid"]))
        except eng._CONN_ERRORS:
            raise
        except eng.IMAPClientError as ex:
            outcome = "error"
            log_.warning("newsletter move repair of %s failed: %s", msgid, eng._short_err(ex))
            try:
                eng.select_with_uidvalidity_check(client, db, inbox, log_)
            except eng.IMAPClientError:
                pass
        now = int(eng._now())
        with db.tx():
            pending = db.conn.execute("SELECT 1 FROM newsletter_pending WHERE account=? AND message_id=?",
                                      (db.account, msgid)).fetchone() is not None
            if outcome in ("completed", "moved"):
                db.update_message(msgid, current_folder=dest, our_action=ACTION_MOVED, last_seen=now)
                db.conn.execute("DELETE FROM newsletter_pending WHERE account=? AND message_id=?",
                                (db.account, msgid))
                if outcome == "completed":
                    db.record_rate(RATE_ACTION)
                    db.bump(_kind_names(kind)[1])
                db.log_event(_kind_names(kind)[0], msgid, detail=f"repair stage={r['stage']} {outcome}")
            elif outcome == "kept" or (outcome in ("retry", "skipped") and not pending):
                db.conn.execute("UPDATE messages SET our_action='none' WHERE account=? AND message_id=? "
                                "AND our_action IN (?,?)", (db.account, msgid, ACTION_PENDING, ACTION_FAILED))
                db.conn.execute("DELETE FROM newsletter_pending WHERE account=? AND message_id=?",
                                (db.account, msgid))
                db.log_event("newsletter_repair_kept", msgid, detail=f"stage={r['stage']} {outcome}")
            if outcome == "error" and int(r["attempts"]) + 1 < eng.MOVE_REPAIR_MAX_ATTEMPTS:
                db.conn.execute("UPDATE move_journal SET attempts=attempts+1, updated_at=? WHERE account=? "
                                "AND folder=? AND uidvalidity=? AND uid=?",
                                (now, db.account, r["folder"], r["uidvalidity"], r["uid"]))
            else:
                db.conn.execute("DELETE FROM move_journal WHERE account=? AND folder=? AND uidvalidity=? "
                                "AND uid=?", (db.account, r["folder"], r["uidvalidity"], r["uid"]))
        if outcome in ("completed", "moved", "kept"):
            resolved += 1
    return resolved


# ---------------------------------------------------------------------------
# Read side (web UI): counts and lists
# ---------------------------------------------------------------------------


def shadow_count(conn: sqlite3.Connection, account: str, *, days: int = LIST_DAYS, now: float | None = None,
                 event: str = EVENT_SHADOW) -> int:
    """Distinct mails that would have been moved in the last `days` days."""
    since = int((now if now is not None else time.time()) - days * 86400)
    try:
        row = conn.execute("SELECT COUNT(DISTINCT message_id) FROM events WHERE account=? AND event=? AND ts>=?",
                           (account, event, since)).fetchone()
    except sqlite3.Error:
        return 0
    return int(row[0] or 0) if row else 0


def moved_count(conn: sqlite3.Connection, account: str, *, days: int = LIST_DAYS, now: float | None = None,
                event: str = EVENT_MOVE) -> int:
    since = int((now if now is not None else time.time()) - days * 86400)
    try:
        row = conn.execute("SELECT COUNT(DISTINCT message_id) FROM events WHERE account=? AND event=? AND ts>=?",
                           (account, event, since)).fetchone()
    except sqlite3.Error:
        return 0
    return int(row[0] or 0) if row else 0


def recent(conn: sqlite3.Connection, account: str, event: str = EVENT_SHADOW, *, days: int = LIST_DAYS,
           limit: int = 300, now: float | None = None) -> list[dict[str, Any]]:
    """Newest first: {message_id, ts, sender, subject, received_at,
    our_action, current_folder, signals} for one event kind."""
    since = int((now if now is not None else time.time()) - days * 86400)
    try:
        rows = conn.execute(
            "SELECT e.message_id, MAX(e.ts) AS ts, MAX(e.detail) AS detail, m.sender, m.subject, m.received_at, "
            "m.our_action, m.current_folder, m.our_score FROM events e LEFT JOIN messages m "
            "ON m.account=e.account AND m.message_id=e.message_id "
            "WHERE e.account=? AND e.event=? AND e.ts>=? AND e.message_id IS NOT NULL "
            "GROUP BY e.message_id ORDER BY ts DESC LIMIT ?", (account, event, since, int(limit))).fetchall()
    except sqlite3.Error:
        return []
    out = []
    for r in rows:
        detail = str(r[2] or "")
        sig = detail.partition("signals=")[2].split(" ")[0] if "signals=" in detail else ""
        out.append({"message_id": r[0], "ts": r[1], "sender": r[3], "subject": r[4], "received_at": r[5],
                    "our_action": r[6], "current_folder": r[7], "our_score": r[8],
                    "signals": [s for s in sig.split(",") if s and s != "-"]})
    return out


def signal_text(signal: str) -> str:
    """Danish label for a stored signal."""
    s = str(signal or "")
    if s == "list-unsubscribe":
        return "Afmeldingslink"
    if s == "list-unsubscribe-post":
        return "Afmelding med ét klik"
    if s.startswith("precedence:"):
        return "Masseudsendelse"
    if s == "HAS_LIST_UNSUB":
        return "Afmeldingslink"
    if s == "PRECEDENCE_BULK":
        return "Masseudsendelse"
    if s in ("MAILLIST", "list-id"):
        return "Mailingliste"
    if s == "feedback-id":
        return "Udsendelses-id"
    if s.startswith("esp:"):
        return "Sendt via " + s[4:]
    return s
