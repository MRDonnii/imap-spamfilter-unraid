"""Mail pages of the web UI: Oversigt, Fanget spam, Beskeder,
Besked-detalje and Regler, plus their POST/JSON endpoints and /api/status.

Routes register on dashboard.app at import (dashboard.register_pages()).
Engine helpers and services are reached through `ui.engine` /
`ui.services` at call time so tests can swap them for fakes. Every value
that comes from a mail (sender, subject, Message-ID, symbol options) is
attacker controlled and goes through kit.h() before it reaches HTML.
"""

from __future__ import annotations

import json
import logging
import math
import re
import secrets
import sqlite3
import time
from datetime import datetime
from typing import Any, Iterable
from urllib.parse import quote, urlencode

from flask import abort, g, jsonify, request, session

import dashboard as ui
import siteconfig
import ui_kit as kit
from ui_kit import h

log = logging.getLogger("dashboard.mail")
app = ui.app

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

# our_action values that mean "the filter caught it" (own decision).
FILTER_ACTIONS = ("pending_move", "moved_to_junk", "flagged", "flag", "move_failed",
                  "manual_mark_spam", "user_junked")
SHADOW_ACTIONS = ("shadow_spam", "shadow")
PROVIDER_ACTIONS = ("provider_junk",)
CAUGHT_ACTIONS = FILTER_ACTIONS + SHADOW_ACTIONS + PROVIDER_ACTIONS
RELEASED_ACTIONS = ("manual_release", "user_rescued")
# Honest KPIs (2.1): the filter's own catches vs. spam the user had to move himself.
CATCH_ACTIONS = ("pending_move", "moved_to_junk", "flagged", "flag", "move_failed") + SHADOW_ACTIONS
MISSED_ACTIONS = ("user_junked", "manual_mark_spam")
# Rows whose mail physically sits in the spam folder (unless current_folder says otherwise).
JUNK_ACTIONS = ("moved_to_junk", "provider_junk", "user_junked", "manual_mark_spam")

SOURCES = (
    ("all", "Alle", CAUGHT_ACTIONS),
    ("filter", "Filter", FILTER_ACTIONS),
    ("provider", "Udbyder", PROVIDER_ACTIONS),
    ("shadow", "Overvåg", SHADOW_ACTIONS),
)
PERIODS = (("24h", "Seneste 24 t", 86400), ("7d", "Seneste 7 dage", 7 * 86400),
           ("30d", "Seneste 30 dage", 30 * 86400), ("all", "Hele perioden", 0))
# 2.6 (A4): newsletters the filter moved to its own folder (newsletters.py).
NEWSLETTER_ACTIONS = ("newsletter_pending", "newsletter_moved", "newsletter_move_failed")
NEWSLETTER_LOC_ACTIONS = ("newsletter_moved", "newsletter_move_failed")
RESULTS = (
    ("", "Alle resultater", None),
    ("spam", "Spam", FILTER_ACTIONS),
    ("shadow", "Ville være flyttet", SHADOW_ACTIONS),
    ("legit", "Legitim", ("none", "newsletter_kept")),
    ("newsletters", "Nyhedsbreve", NEWSLETTER_ACTIONS),
    ("allowed", "Tilladt afsender", ("allowlisted",)),
    ("released", "Frigivet", RELEASED_ACTIONS),
    ("provider", "Fanget af udbyder", PROVIDER_ACTIONS),
)
BANDS = (("", "Alle scorer"), ("over", "Over grænsen"), ("near", "Tæt på grænsen"),
         ("low", "Lav score"), ("neg", "Negativ score"))

# Form action -> (services action, past-tense Danish verb for toasts).
MAIL_ACTIONS = {
    "release": ("release", "frigivet"),
    "release_allow": ("release", "frigivet"),
    "mark_spam": ("mark_spam", "flyttet til spam"),
    "learn_ham": ("learn_ham", "lært som legitim"),
    "learn_spam": ("learn_spam", "lært som spam"),
}
REMOVES_FROM_SPAM_LIST = {"release", "release_allow", "learn_ham"}

EVENT_INFO: dict[str, tuple[str, str, str]] = {
    "scan": ("Scannet af rspamd", "activity", "info"),
    "pending_move": ("Sat i kø til flytning", "clock", "warn"),
    "moved_to_junk": ("Flyttet til Spamfilter-mappen", "shield-alert", "bad"),
    "flagged": ("Markeret som spam", "flag", "bad"),
    "flag_failed": ("Markering fejlede", "alert-triangle", "warn"),
    "move_failed": ("Flytning fejlede", "alert-triangle", "warn"),
    "move_retry": ("Flytning forsøges igen", "refresh", "warn"),
    "pending_canceled": ("Flytning annulleret", "x-circle", "neutral"),
    "pending_canceled_uidvalidity": ("Flytning annulleret (mappen blev nulstillet)", "x-circle", "neutral"),
    "pending_lost": ("Beskeden forsvandt før flytning", "x-circle", "neutral"),
    "provider_junk": ("Fundet i udbyderens spam-mappe", "inbox", "neutral"),
    "user_rescued": ("Flyttet tilbage til indbakken af dig", "undo", "info"),
    "user_junked": ("Flyttet til spam af dig", "mail-x", "bad"),
    "manual_release": ("Frigivet fra webadministrationen", "undo", "ok"),
    "manual_mark_spam": ("Flyttet til spam fra webadministrationen", "shield-alert", "bad"),
    "learn_spam": ("Lært som spam", "graduation-cap", "brand"),
    "learn_ham": ("Lært som legitim", "graduation-cap", "ok"),
    "learn_skipped": ("Læring sprunget over", "info", "neutral"),
    "learn_failed": ("Læring fejlede", "alert-circle", "warn"),
    "learn_error": ("Læring fejlede", "alert-circle", "warn"),
    "learn_giveup": ("Læring opgivet", "alert-circle", "warn"),
    "learn_flipflop_block": ("Læring blokeret (skiftede mening for hurtigt)", "ban", "warn"),
    "rate_limited": ("Udskudt – grænsen for flytninger pr. time er nået", "clock", "warn"),
    "scan_failed": ("Scanning fejlede", "alert-circle", "warn"),
    "scan_giveup": ("Scanning opgivet", "alert-circle", "bad"),
    "scan_recovered": ("Scanning lykkedes ved nyt forsøg", "check-circle", "ok"),
    "scan_oversize": ("For stor til at blive scannet", "info", "neutral"),
    "skipped_no_msgid": ("Sprunget over – mangler Message-ID", "info", "neutral"),
    "trained_moved": ("Flyttet efter træning", "folder", "neutral"),
    # 2.1
    "force_unverified": ("Altid igennem kunne ikke bekræftes – vurderet efter score", "alert-triangle", "warn"),
    "move_repaired": ("Afbrudt flytning gjort færdig", "check-circle", "ok"),
    "move_repair_kept": ("Afbrudt flytning: beholdt i indbakken", "info", "info"),
    "move_repair_retry": ("Afbrudt flytning forsøges igen", "refresh", "warn"),
    "move_repair_giveup": ("Afbrudt flytning opgivet – mailen er ikke væk", "alert-circle", "warn"),
    "autolearn_spam": ("Lært som spam automatisk (ikke frigivet i 3 dage)", "graduation-cap", "brand"),
    "autolearn_ham": ("Lært som legitim automatisk (blev i indbakken)", "graduation-cap", "ok"),
    "autolearn_reverted": ("Automatisk læring fortrudt", "undo", "neutral"),
    "found_to_inbox": ("Flyttet til indbakken fra Find en mail", "undo", "ok"),
    "undo_release": ("Flyttet tilbage til indbakken (Fortryd flytninger)", "undo", "ok"),
    "rule_auto_allow": ("Afsenderen blev tilladt automatisk", "check-circle", "ok"),
    "rule_auto_allow_removed": ("Den automatiske tilladelse af afsenderen blev fjernet", "x-circle", "warn"),
    "rule_auto_allow_skipped": ("Ikke tilladt automatisk – afsenderen er sat til Altid igennem", "info", "neutral"),
    # 2.12 (#8/#9)
    "junk_rule_conflict": ("Flyttet til Junk, selv om afsenderen er tilladt – vises for administratoren",
                           "alert-triangle", "warn"),
    "junk_auto_block": ("Afsenderen er blokeret for postkassen efter 3 flytninger til Junk", "ban", "warn"),
    "junk_block_suggested": ("Forslag om at blokere afsenderen for postkassen", "ban", "info"),
    "learn_skip_newsletter": ("Ikke lært som spam – et almindeligt nyhedsbrev lærer ikke filteret noget",
                              "graduation-cap", "neutral"),
    # 2.2
    "ham_guard": ("Ikke lært som legitim – læringsvagten stoppede det", "shield", "warn"),
    "own_domain_uribl": ("Jeres eget domæne stod på en domæneliste", "alert-triangle", "warn"),
    # 2.3 (B10-B14) known contacts and replies
    "contacts_sync_complete": ("Kendte kontakter: første gennemgang færdig", "user-check", "ok"),
    "contacts_key_regenerated": ("Kendte kontakter lært forfra (ny nøgle)", "refresh", "warn"),
    "contacts_uidvalidity": ("Sendt-mappe nulstillet – læses igen", "refresh", "neutral"),
    "contact_demoted": ("Afsenderen er fjernet fra Kendte kontakter (lagt i spam)", "user-x", "warn"),
    "contact_removed": ("Afsenderen er fjernet fra Kendte kontakter", "user-x", "neutral"),
    "contact_restored": ("Afsenderen er gendannet som kendt kontakt", "user-check", "ok"),
    "contacts_sync_requested": ("Opdatering af Kendte kontakter bestilt", "refresh", "info"),
    "reply_recheck": ("Tjekket igen før flytning: svar på din mail?", "reply", "info"),
    # 2.3 (B16/B17) threats and attachments
    "threat_detected": ("Farlig mail fundet", "alert-triangle", "bad"),
    # 2.3.6 (B22) lookalike domains (global events, never on a mail's timeline)
    "lookalike_registered": ("Nyt domæne ligner jeres", "globe", "bad"),
    "lookalike_watch_done": ("Ugentlig kontrol af lignende domæner", "globe", "neutral"),
    "lookalike_watch_failed": ("Kontrol af lignende domæner fejlede", "alert-triangle", "warn"),
    "lookalike_watch_requested": ("Kontrol af lignende domæner bestilt", "globe", "info"),
    "lookalike_allowed": ("Markeret som ikke en efterligning", "check", "info"),
    "lookalike_unallowed": ("Igen set som mulig efterligning", "undo", "neutral"),
    "lookalike_acked": ("Nyt lignende domæne markeret som set", "check", "neutral"),
    # 2.7 Falske afsendernavne
    "namespoof_hit": ("Falsk afsendernavn – en af jeres egne, men ikke den rigtige adresse", "user-x", "bad"),
    "namespoof_trial": ("Prøv: falsk afsendernavn ville have fået point", "user-x", "info"),
    "namespoof_mode": ("Falske afsendernavne: Fra/Prøv/Til ændret", "shield", "info"),
    "namespoof_seeded": ("Beskyttede navne hentet fra Sendt post", "users", "neutral"),
    "threat_force_pass": ("Farlig mail sluppet igennem af Altid igennem (DKIM-bekræftet)", "shield-alert", "warn"),
    "threat_rescue_ignored_learning": ("Flyttet ud af spam – men ikke lært som legitim (farlig mail)", "shield", "warn"),
    "threat_ham_refused": ("Ikke lært som legitim – mailen er farlig", "shield", "warn"),
    "threat_release": ("Frigivet af en administrator trods advarsel", "undo", "warn"),
    "threat_release_refused": ("Frigivelse afvist – mailen er farlig", "lock", "bad"),
    "attach_exception": ("Farlig vedhæftning tilladt for afsenderen", "paperclip", "info"),
    "attach_exception_unverified": ("Undtagelse for vedhæftning ikke brugt – afsenderen kunne ikke bekræftes",
                                    "paperclip", "warn"),
    "attach_exception_added": ("Undtagelse for farlige vedhæftninger tilføjet", "paperclip", "info"),
    "attach_exception_removed": ("Undtagelse for farlige vedhæftninger fjernet", "paperclip", "neutral"),
    # 2.3 (B19) rescans
    "zap_move": ("Fanget ved genscanning – flyttet til Spamfilter-mappen", "radar", "bad"),
    "zap_rescore": ("Genscannet", "radar", "info"),
    "would_have_zapped": ("Genscanning: ville være flyttet", "radar", "warn"),
    "zap_skipped": ("Genscanning sprunget over", "radar", "neutral"),
    "zap_skipped_read": ("Genscanning: ikke flyttet, mailen var læst", "radar", "neutral"),
    "zap_failed": ("Genscanning fejlede", "alert-circle", "warn"),
    # 2.7 fix: antivirus re-scans (ClamAV did not answer at the first scan)
    "av_rescan_clean": ("Virusscannet igen – ingen virus", "shield-check", "info"),
    "av_rescan_skipped": ("Virus-genscanning sprunget over", "radar", "neutral"),
    # 2.6 (A2) the same spam in several mailboxes
    "campaign_move": ("Samme spam som i en anden postkasse – flyttes til Spamfilter-mappen", "copy", "bad"),
    "campaign_shadow": ("Samme spam som i en anden postkasse – ville være flyttet", "copy", "warn"),
    "campaign_skipped": ("Samme spam som i en anden postkasse – ikke flyttet", "copy", "neutral"),
    "campaign_failed": ("Samme spam som i en anden postkasse – fejlede", "alert-circle", "warn"),
    "campaign_sweep": ("Samme spam søgt i alle postkasser", "copy", "info"),
    "campaign_cancelled": ("Samme spam – annulleret, kilden er frigivet", "copy", "neutral"),
    "campaign_deferred": ("Samme spam – venter (højst 50 i timen)", "copy", "neutral"),
    "fuzzy_added": ("Lagt i filterets fuzzy-database", "database", "brand"),
    "fuzzy_removed": ("Fjernet fra filterets fuzzy-database", "database", "neutral"),
    "fuzzy_failed": ("Kunne ikke lægges i fuzzy-databasen", "alert-circle", "neutral"),
    # 2.3 (B29)
    "weekly_report_mailed": ("Ugerapport sendt på mail", "send", "ok"),
    # 2.3 follow-up: Straks-advarsel and 'Byg Bayes op på ny'
    "threat_notice_sent": ("Straks-advarsel lagt i indbakken", "alert-triangle", "warn"),
    "threat_notice_failed": ("Straks-advarsel kunne ikke lægges i indbakken", "alert-circle", "bad"),
    "threat_alert_mailed": ("Administratoren fik en alarm på mail", "send", "warn"),
    "bayes_rebuild_started": ("Bayes bygges op på ny", "graduation-cap", "info"),
    "bayes_rebuild_done": ("Bayes er bygget op på ny", "graduation-cap", "ok"),
    "bayes_restored": ("Tidligere Bayes gendannet", "undo", "warn"),
    # 2.6 (A4) newsletters
    "newsletter_shadow": ("Nyhedsbrev: ville være flyttet til nyhedsbreve (Prøv)", "mails", "info"),
    "newsletter_queued": ("Nyhedsbrev: flyttes til nyhedsbreve om lidt", "clock", "info"),
    "newsletter_move": ("Flyttet til nyhedsbreve", "mails", "info"),
    "newsletter_excluded": ("Nyhedsbrev – men bliver i indbakken", "inbox", "neutral"),
    "newsletter_kept": ("Flyttet tilbage til indbakken – afsenderen bliver i indbakken", "undo", "ok"),
    "newsletter_back": ("Flyttet tilbage fra nyhedsbreve i webadministrationen", "undo", "ok"),
    "newsletter_move_failed": ("Flytning til nyhedsbreve fejlede", "alert-triangle", "warn"),
    "newsletter_move_retry": ("Flytning til nyhedsbreve forsøges igen", "refresh", "warn"),
    "newsletter_skipped_read": ("Ikke flyttet til nyhedsbreve – mailen var læst", "inbox", "neutral"),
    "newsletter_skipped_flagged": ("Ikke flyttet til nyhedsbreve – stjernemarkeret", "inbox", "neutral"),
    "newsletter_skipped_kept": ("Ikke flyttet til nyhedsbreve – afsenderen bliver i indbakken", "inbox", "neutral"),
    "newsletter_skipped_rule": ("Ikke flyttet til nyhedsbreve – afsenderen er tilladt", "inbox", "neutral"),
    "newsletter_skipped_spam": ("Ikke flyttet til nyhedsbreve – behandlet som spam", "shield-alert", "neutral"),
    "newsletter_cancelled": ("Flytning til nyhedsbreve annulleret (slået fra)", "x-circle", "neutral"),
}

# 2.3 (B19): rescan events whose detail is shown as "Ny viden: … kom til efter … t".
ZAP_EVENTS = ("zap_move", "zap_rescore", "would_have_zapped")
ZAP_LABEL = "Fanget ved genscanning"
THREAT_ADMIN_TEXT = "Kontakt administrator, hvis mailen skal frigives."
THREAT_ADMIN_SHORT = "Kontakt administrator"

PAGE_SIZE = 50
DEFAULT_THRESHOLD = 8.0
MAX_RULE_LINES = 500


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _n(n: int, one: str, many: str) -> str:
    return f"{kit.fmt_int(n)} {one if n == 1 else many}"


def _qs(**changes: Any) -> str:
    """Current query string with changes applied (None/'' drop a key)."""
    args = {k: v for k, v in request.args.items()}
    for k, v in changes.items():
        args[k] = v
    clean = {k: str(v) for k, v in args.items() if v not in (None, "")}
    return ("?" + urlencode(clean)) if clean else ""


def _like(text: str) -> str:
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _in(values: Iterable[str]) -> tuple[str, list[str]]:
    vals = list(values)
    return "(" + ",".join("?" * len(vals)) + ")", vals


def _int_arg(name: str, default: int = 1, lo: int = 1, hi: int = 1_000_000) -> int:
    try:
        return max(lo, min(hi, int(request.args.get(name, default))))
    except (TypeError, ValueError):
        return default


def _selected() -> str:
    """?account=<name> ('' = all in scope); 404 for a mailbox the user may
    not see (existence is not revealed)."""
    name = (request.args.get("account") or "").strip()
    if name:
        ui.require_account(name)
    return name


def _scope(selected: str, column: str = "account") -> tuple[str, list]:
    if selected:
        return f" AND {column}=?", [selected]
    return ui.scope_sql(column)


def _accounts() -> dict[str, Any]:
    return {a.name: a for a in ui.visible_accounts()}


def _thresholds() -> dict[str, float]:
    out: dict[str, float] = {}
    for a in ui.visible_accounts():
        try:
            out[a.name] = float(a.threshold)
        except (TypeError, ValueError, AttributeError):
            out[a.name] = DEFAULT_THRESHOLD
    return out


def _thr_expr(thresholds: dict[str, float]) -> tuple[str, list]:
    """SQL expression for each row's account threshold."""
    if not thresholds:
        return str(DEFAULT_THRESHOLD), []
    parts, params = [], []
    for name, t in thresholds.items():
        parts.append("WHEN ? THEN ?")
        params += [name, t]
    return f"(CASE account {' '.join(parts)} ELSE {DEFAULT_THRESHOLD} END)", params


TS = "COALESCE(scanned_at, received_at, first_seen)"


def _nonce() -> str:
    return secrets.token_urlsafe(12)


def _key(account: str, message_id: str) -> str:
    return f"{account}:{kit.token_for(message_id)}"


def _parse_key(key: str) -> tuple[str, str] | None:
    account, sep, token = (key or "").rpartition(":")
    if not sep or not account:
        return None
    mid = kit.msgid_from_token(token)
    return (account, mid) if mid else None


def _detail_url(account: str, message_id: str) -> str:
    return f"/messages/{h(quote(account, safe=''))}/{kit.token_for(message_id)}"


def _location(row: Any, acc: Any) -> str:
    """'junk' | 'inbox' | 'newsletters' | 'gone' for a messages row."""
    cf = str(row["current_folder"] or "")
    if cf == "gone":
        return "gone"
    junk = str(getattr(acc, "junk", "Junk") or "Junk")
    inbox = str(getattr(acc, "inbox", "INBOX") or "INBOX")
    if cf.lower() == junk.lower():
        return "junk"
    if cf.lower() == inbox.lower():
        return "inbox"
    if row["our_action"] in NEWSLETTER_LOC_ACTIONS:
        return "newsletters"  # 2.6 (A4): in the newsletter folder
    return "junk" if row["our_action"] in JUNK_ACTIONS else "inbox"


def _rget(row: Any, key: str, default: Any = None) -> Any:
    try:
        v = row[key]
    except (IndexError, KeyError):
        return default
    return default if v is None else v


def _is_old(row: Any) -> bool:
    return int(_rget(row, "score_version", 0) or 0) < 2 and row["our_score"] is not None


def _svc(fn: str, *args: Any, default: Any = None, **kwargs: Any) -> Any:
    """services.<fn> that never breaks a page (older services / DB)."""
    try:
        return getattr(ui.services, fn)(*args, **kwargs)
    except Exception as ex:  # noqa: BLE001 - a missing label must never kill a list
        log.warning("services.%s failed: %s", fn, type(ex).__name__)
        return default


# ---------------------------------------------------------------------------
# 2.3: threat class (B16), trust labels (B13) and rescans (B19) on a row
# ---------------------------------------------------------------------------

# Labels a compact list chip is shown for, per view: on the spam lists a
# "Ny afsender" chip would sit on almost every row (noise), so only the
# reassuring ones; Beskeder shows all five.
LIST_TRUST_KINDS = {"messages": ("known_contact", "reply", "established", "first_contact", "reply_unverified",
                                  "distrusted")}
LIST_TRUST_DEFAULT = ("known_contact", "reply", "established", "distrusted")


def row_threat(r: Any) -> tuple[str | None, str | None]:
    """(threat class, detail) of a messages row ((None, None) before 2.3)."""
    t = _rget(r, "threat")
    return (str(t), (str(_rget(r, "threat_detail")) if _rget(r, "threat_detail") else None)) if t else (None, None)


def threat_text_of(r: Any) -> str:
    threat, detail = row_threat(r)
    if not threat:
        return ""
    return str(_svc("threat_text", threat, detail, default="") or "Farlig mail")


def trust_numbers() -> bool:
    """Counts and dates in trust labels: administrators only. A Bruger (and
    'Se som bruger') sees the labels without numbers (B13)."""
    return ui.is_admin()


_TRUSTING_KINDS = ("known_contact", "reply", "established")


def after_spam_verdict(labels: list[dict], verdict: Any) -> list[dict]:
    """The labels describe the trust AT SCAN TIME. Once the user called the
    mail spam (and a known contact was demoted), a green 'Kendt kontakt'
    next to 'Flyttet til spam manuelt' reads as a contradiction: the
    trusting labels collapse into one grey 'Ikke længere betroet'."""
    if verdict != "spam" or not any(x.get("kind") in _TRUSTING_KINDS for x in labels):
        return labels
    was_contact = any(x.get("kind") == "known_contact" for x in labels)
    text = ("Var kendt kontakt – du har markeret mailen som spam" if was_contact
            else "Ikke længere betroet – du har markeret mailen som spam")
    rest = [x for x in labels if x.get("kind") not in _TRUSTING_KINDS]
    return [{"kind": "distrusted", "tone": "grey", "text": text, "symbol": ""}] + rest


def trust_labels_of(r: Any) -> list[dict]:
    labels = _svc("trust_labels", _rget(r, "symbols") or "[]", numbers=trust_numbers(), default=[]) or []
    labels = [x for x in labels if isinstance(x, dict) and x.get("text")]
    return after_spam_verdict(labels, _rget(r, "user_verdict"))


def trust_chips(r: Any, view: str) -> str:
    kinds = LIST_TRUST_KINDS.get(view, LIST_TRUST_DEFAULT)
    out = [kit.trust_badge(x, compact=True) for x in trust_labels_of(r) if x.get("kind") in kinds]
    return "".join(out[:2])


def zap_chip(r: Any) -> str:
    if not _rget(r, "zapped_at"):
        return ""
    return (f'<span class="badge tone-info zap-badge" title="{h(ZAP_LABEL)}: sortlisterne kendte den først, '
            f'efter mailen var kommet">{kit.icon("radar")}<span>{h(ZAP_LABEL)}</span></span>')


def locked_release(*, size: str = "sm") -> str:
    """What a Bruger sees instead of Frigiv on a dangerous mail (B16): a
    short visible note - not a button-like pill that does nothing."""
    return (f'<span class="act-locked{" is-lg" if not size else ""}" role="note">'
            f'{kit.icon("lock")}<span><b>Farlig mail.</b> {h(THREAT_ADMIN_SHORT)}, hvis den skal frigives.'
            "</span></span>")


_ZAP_NEW_RE = re.compile(r"\bny=(\S+)")
_ZAP_AGE_RE = re.compile(r"\befter=(\d+) (t|min)\b")


def _age_words(n: str, unit: str) -> str:
    k = int(n)
    if unit == "t":
        return f"{k} time" if k == 1 else f"{k} timer"
    return f"{k} minut" if k == 1 else f"{k} minutter"


def zap_plain_text(detail: str) -> str:
    """B19 rescan event in plain Danish for everybody: 'Ny viden efter 3
    timer: Linkdomæne på Spamhaus' spamliste' (the raw rspamd names stay in
    the administrators' symbol table)."""
    text = str(detail or "")
    m = _ZAP_NEW_RE.search(text)
    names = [n for n in (m.group(1).split(",") if m else []) if n and n != "-"]
    age = _ZAP_AGE_RE.search(text)
    when = f" efter {_age_words(age.group(1), age.group(2))}" if age else ""
    if not names:
        return f"Genscannet{when} – intet nyt"
    seen: list[str] = []
    for n in names:
        t = kit.explain_symbol(n)
        if t and t not in seen:
            seen.append(t)
    shown = ", ".join(seen[:3]) + (f" og {len(seen) - 3} mere" if len(seen) > 3 else "")
    return f"Ny viden{when}: {shown}"


def _reason_chips(symbols: Any, n: int = 3, *, sender: Any = None) -> str:
    out = []
    admin = trust_numbers()
    for s in kit.top_reasons(symbols, n):
        tip = f"{s['n']} {'+' if s['s'] >= 0 else ''}{kit.fmt_score(s['s'])}"
        text = kit.explain_symbol_detail(s, symbols=symbols, sender=sender, ai_reason=admin)
        out.append(f'<span class="chip tone-bad" title="{h(tip)}">{h(text)}</span>')
    return "".join(out)


# ---------------------------------------------------------------------------
# Mail rows (shared by Oversigt, Fanget spam, Beskeder)
# ---------------------------------------------------------------------------


LIST_VIEWS = ("spam", "overview", "messages")
LIST_HOME = {"spam": "/spam", "overview": "/", "messages": "/messages", "rules": "/rules", "review": "/spam"}
GONE_TEXT = "Mailen findes ikke længere i postkassen – den er formentlig slettet."
MAX_SYNC_ROWS = 100


class RuleIndex:
    """All sender rules, loaded once per request and matched exactly like
    engine.match_sender_rule: an account rule beats '*', an address beats
    a domain, a longer domain beats its parent, block beats allow."""

    def __init__(self) -> None:
        self._by: dict[str, list[Any]] = {}
        try:
            # SELECT *: 'force' only exists once the 2.0.3 engine migrated the DB.
            rows = ui.query("SELECT * FROM sender_rules")
        except sqlite3.Error:
            rows = []
        for r in rows:
            self._by.setdefault(str(r["pattern"]), []).append(r)

    def match(self, account: str, exact: str) -> Any | None:
        if not exact or "@" not in exact or exact.startswith("@"):
            return None
        labels = exact.split("@", 1)[1].split(".")
        pats = [exact] + ["@" + ".".join(labels[i:]) for i in range(len(labels))]
        cands = [r for p in pats for r in self._by.get(p, ()) if r["account"] in (account, "*")]
        if not cands:
            return None
        return max(cands, key=lambda r: (1 if r["account"] == account and account != "*" else 0,
                                         1 if r["pattern"] == exact else 0, len(r["pattern"]),
                                         1 if r["kind"] == "block" else 0))


def _sender_pattern(sender: Any) -> str:
    """Exact lowercase rule pattern (local@domain) for a From header, or ''."""
    addr = kit.sender_parts(sender)[1]
    if not addr:
        return ""
    try:
        p = ui.engine.normalize_rule_pattern(addr)
    except Exception:  # noqa: BLE001 - unparsable sender: no rule buttons
        return ""
    return p if "@" in p and not p.startswith("@") else ""


def _rule_where(rule: Any) -> str:
    return "alle konti" if rule["account"] == "*" else ui.account_label(str(rule["account"]))


def _rule_force(rule: Any) -> bool:
    """Allow rule marked 'Altid igennem' (never moved, even when the From
    looks forged)."""
    return rule is not None and rule["kind"] == "allow" and bool(_rget(rule, "force", 0))


FORCE_NOTE = "Altid igennem: flyttes aldrig, heller ikke hvis afsenderen ser forfalsket ud."


def _rule_chip(rule: Any) -> str:
    if rule is None:
        return ""
    allow = rule["kind"] == "allow"
    label = "Tilladt" if allow else "Blokeret"
    tip = f"{label} af reglen {rule['pattern']} ({_rule_where(rule)})"
    if _rule_force(rule):
        tip += " · " + FORCE_NOTE
    return (f'<span class="chip rule-chip tone-{"ok" if allow else "bad"}" title="{h(tip)}">'
            f'{kit.icon("check" if allow else "ban")}{label}</span>')


def _here(view: str) -> str:
    """Where a row/detail button should send the browser back to (no JS)."""
    if request.method == "GET":
        fp = request.full_path
        return fp[:-1] if fp.endswith("?") else fp
    return ui.safe_next(request.form.get("next"), LIST_HOME.get(view, "/messages"))


def _block_confirm(pattern: str, account: str) -> str:
    what = "domænet " + pattern if pattern.startswith("@") else pattern
    return kit.confirm_attrs(f"Bloker {what}?",
                             f"Al post fra {pattern}" + (" og underdomæner" if pattern.startswith("@") else "")
                             + f" behandles som spam på {account} – uanset score. Du kan altid fjerne blokeringen igen.",
                             confirm="Bloker", tone="danger")


def _mail_btn(key: str, action: str, label: str, *, short: str = "", icon: str, tone: str, view: str,
              next_url: str, title: str = "", confirm: str = "", size: str = "sm", choose: bool = False,
              swipe: str = "") -> str:
    """One-click mail action (POST /mail/action) as a colour-coded button.
    choose=True (2.3, "Tillad afsender" = release_allow): the server first
    answers with the address/domain dialog. swipe='right'|'left' (2.5.0):
    this form is also the row's swipe action (app.js posts it as is)."""
    attrs = (f'title="{h(title)}" ' if title else "") + confirm + (' aria-haspopup="dialog"' if choose else "")
    inner = (kit.hidden("action", action) + kit.hidden("items", key) + kit.hidden("view", view)
             + kit.hidden("nonce", _nonce()) + kit.hidden("next", next_url)
             + (kit.hidden("choose", "1") if choose else "")
             + kit.button(label, kind="secondary", icon=icon, size=size, tone=tone, short=short, attrs=attrs))
    return kit.post_form("/mail/action", inner, attrs="data-sync" + (f' data-swipe-form="{h(swipe)}"' if swipe else ""))


# ---------------------------------------------------------------------------
# 2.5.0: swipe on a mail row (touch). Right = Frigiv, left = Det er spam.
# The server decides per row which swipes exist (the same rules as the
# buttons, incl. the B16 threat gate) and renders them as data attributes
# on the row plus the form to post; app.js never invents a permission.
# ---------------------------------------------------------------------------

SWIPE_VIEWS = ("spam", "messages", "review")
SWIPE_LABELS = {"right": "Frigiv", "left": "Det er spam"}


def swipe_plan(*, account: str, loc: str, view: str, verdict: Any, threat: str | None) -> dict[str, str]:
    """{'right': 'release', 'left': 'learn_spam' | 'mark_spam'} for one row.
    Only actions this user may do here: 'release' permission on the
    mailbox, never Frigiv of a dangerous mail for a non-admin (an
    administrator still gets the server's confirmation), nothing for a
    deleted mail, and nothing a row already is (released mail has no
    right swipe, confirmed spam or a mail already in spam has no 'move to
    spam')."""
    if view not in SWIPE_VIEWS or loc == "gone" or not ui.can("release", account):
        return {}
    plan: dict[str, str] = {}
    in_spam_list = view in ("spam", "review")
    if (in_spam_list or loc == "junk") and (verdict != "ham" or loc == "junk") and (not threat or ui.is_admin()):
        plan["right"] = "release"
    if view == "messages" and loc == "inbox":
        plan["left"] = "mark_spam"        # the row's own "Flyt til spam"
    elif (in_spam_list or loc == "junk") and verdict != "spam":
        plan["left"] = "learn_spam"       # stays where it is, filter learns spam ("Bekræft som spam")
    return plan


def swipe_attrs(plan: dict[str, str]) -> str:
    """data-swipe-right / data-swipe-left (the label shown under the row)."""
    return "".join(f' data-swipe-{d}="{h(SWIPE_LABELS[d])}"' for d in ("right", "left") if d in plan)


def swipe_forms(plan: dict[str, str], *, key: str, view: str, next_url: str, rendered: str) -> str:
    """Hidden forms (same fields + CSRF as the buttons) for every planned
    swipe that has no visible button form in `rendered` already."""
    out = []
    for d in ("right", "left"):
        if d not in plan or f'data-swipe-form="{d}"' in rendered:
            continue
        inner = (kit.hidden("action", plan[d]) + kit.hidden("items", key) + kit.hidden("view", view)
                 + kit.hidden("nonce", _nonce()) + kit.hidden("next", next_url))
        out.append(kit.post_form("/mail/action", inner, cls="swipe-form",
                                 attrs=f'data-sync data-swipe-form="{d}" hidden'))
    return "".join(out)


def _rule_add_btn(account: str, pattern: str, kind: str, label: str, *, short: str = "", view: str,
                  next_url: str, title: str = "", size: str = "sm", item: str = "") -> str:
    """Allow/block a sender (POST /rules/add with choose=1): the server
    answers with the dialog "Kun denne adresse / Hele domænet" (2.3) - a
    modal with JS, a small confirm page without."""
    allow = kind == "allow"
    attrs = (f'title="{h(title)}" ' if title else "") + 'aria-haspopup="dialog"'
    inner = (kit.hidden("kind", kind) + kit.hidden("pattern", pattern) + kit.hidden("account", account)
             + kit.hidden("view", view) + kit.hidden("next", next_url) + kit.hidden("choose", "1")
             + (kit.hidden("item", item) if item else "")
             + kit.button(label, kind="secondary", icon="check-circle" if allow else "ban", size=size,
                          tone="ok" if allow else "bad", short=short, attrs=attrs))
    return kit.post_form("/rules/add", inner, attrs="data-sync")


def _rule_del_btn(rule: Any, *, view: str, next_url: str, size: str = "sm") -> str:
    """'Fjern tilladelse' / 'Fjern blokering' for an existing rule (asks first)."""
    allow = rule["kind"] == "allow"
    label = "Fjern tilladelse" if allow else "Fjern blokering"
    confirm = kit.confirm_attrs(
        f"{label}?",
        f"Reglen {rule['pattern']} ({_rule_where(rule)}) slettes. Post fra afsenderen bliver igen vurderet på sin score.",
        confirm=label, tone="danger")
    inner = (kit.hidden("view", view) + kit.hidden("next", next_url)
             + kit.button(label, kind="secondary", icon="x-circle", size=size, tone="neutral",
                          attrs=f'title="{h(rule["pattern"])} · {h(_rule_where(rule))}" ' + confirm))
    # Never shortened to a bare "Fjern" (could be read as "delete the mail");
    # on phones it gets a full row of its own instead.
    return kit.post_form(f"/rules/{int(rule['id'])}/delete", inner, cls="act-wide", attrs="data-sync")


def _also_domain(pattern: str) -> str:
    """Button title tail: the dialog also offers the whole domain (never
    for a shared mail service)."""
    dom = pattern.rpartition("@")[2]
    return "" if not dom or _is_freemail(dom) else f" – eller hele domænet {dom}"


def _row_actions(*, key: str, account: str, loc: str, view: str, pattern: str, rule: Any,
                 verdict: Any, here: str, size: str = "sm", threat: str | None = None,
                 swipe: dict[str, str] | None = None) -> str:
    """Per-row buttons: what fits where the mail is now + allow/block of
    the sender (replaced by 'Fjern ...' when a rule already says so).
    2.3 (B16): a dangerous mail is released by an administrator only (the
    server asks to confirm the threat); a Bruger sees 'Kontakt
    administrator', and nobody gets 'Tillad afsender' for it."""
    btns: list[str] = []
    editable = rule is not None and _may_edit_rule(rule)
    kind = rule["kind"] if rule is not None else ""
    in_spam_list = view in ("spam", "overview")
    may_release = ui.can("release", account)
    # Rule buttons: own mailbox + 'rules' permission, and never for a sender
    # an administrator made 'Altid igennem' (a Bruger rule would override it).
    may_rules = ui.can_edit_rule(account) and (ui.is_admin() or not _rule_force(rule))
    if not may_release:
        pass
    elif in_spam_list or loc == "junk":
        if verdict != "ham" or loc == "junk":
            if threat and not ui.is_admin():
                btns.append(locked_release(size=size))
            else:
                btns.append(_mail_btn(key, "release", "Frigiv", icon="undo", tone="info", view=view, next_url=here,
                                      title=("Farlig mail – du bliver bedt om at bekræfte" if threat else
                                             "Flyt tilbage til indbakken og lær som legitim"), size=size,
                                      swipe="right" if (swipe or {}).get("right") == "release" else ""))
    elif loc == "inbox":
        btns.append(_mail_btn(key, "mark_spam", "Flyt til spam", short="Til spam", icon="shield-alert", tone="warn",
                              view=view, next_url=here, title="Flyt til Spamfilter-mappen og lær som spam", size=size,
                              swipe="left" if (swipe or {}).get("left") == "mark_spam" else ""))
    elif loc == "newsletters" and (pk := _parse_key(key)) is not None:
        btns.append(ui_newsletters.back_form(account, pk[1], next_url=here, size=size))
    if pattern and may_rules:
        if kind == "allow":
            if editable:
                btns.append(_rule_del_btn(rule, view=view, next_url=here, size=size))
        elif threat:
            pass  # never 'Tillad afsender' for a virus / phishing / dangerous attachment
        elif (in_spam_list or loc == "junk") and may_release:
            btns.append(_mail_btn(key, "release_allow", "Tillad afsender", short="Tillad", icon="check-circle",
                                  tone="ok", view=view, next_url=here, choose=True,
                                  title=f"Frigiv beskeden og tillad {pattern}{_also_domain(pattern)}", size=size))
        else:
            btns.append(_rule_add_btn(account, pattern, "allow", "Tillad afsender", short="Tillad", view=view,
                                      next_url=here, title=f"Tillad {pattern}{_also_domain(pattern)}", size=size,
                                      item=key))
        if view != "overview":
            if kind == "block":
                if editable:
                    btns.append(_rule_del_btn(rule, view=view, next_url=here, size=size))
            else:
                btns.append(_rule_add_btn(account, pattern, "block", "Bloker afsender", short="Bloker", view=view,
                                          next_url=here, title=f"Bloker {pattern}{_also_domain(pattern)}", size=size,
                                          item=key))
    return "".join(btns)


def why_reasons(r: Any, rule: Any = None) -> list[str]:
    """Plain Danish reasons (no numbers) for the calm 'Hvorfor?' of a Bruger."""
    out: list[str] = []
    action = _rget(r, "our_action")
    if rule is not None and rule["kind"] == "block":
        out.append("Afsenderen er blokeret")
    if action in PROVIDER_ACTIONS:
        out.append("Din udbyders eget spamfilter lagde den i spam")
    if action in MISSED_ACTIONS:
        out.append("Du har selv lagt den i spam")
    raw_syms = _rget(r, "symbols")
    for s in kit.top_reasons(raw_syms, 8):
        text = kit.plain_reason_detail(s, symbols=raw_syms, sender=_rget(r, "sender"))
        if text == kit.PLAIN_PROVIDER and action in PROVIDER_ACTIONS:
            continue  # already said above
        if text and text not in out:
            out.append(text)
    if not out:
        out.append("Den samlede vurdering af mailen lå over grænsen for spam")
    return out[:4]


def simple_row(r: Any, accounts: dict[str, Any], *, view: str, show_account: bool,
               rules: RuleIndex | None = None, new_since: int | None = None) -> str:
    """A Bruger's calm mail row: who, what, when, a 'Hvorfor?' expander and
    big buttons (only those their permissions allow). No score numbers."""
    account, mid = str(r["account"]), str(r["message_id"])
    key = _key(account, mid)
    name, addr = kit.sender_parts(r["sender"])
    who = name or addr or "Ukendt afsender"
    subject = (r["subject"] or "").strip() or "(intet emne)"
    acc = accounts.get(account)
    loc = _location(r, acc) if acc is not None else "gone"
    pattern = _sender_pattern(r["sender"])
    rule = (rules or RuleIndex()).match(account, pattern) if pattern else None
    when = r["ts"] if "ts" in r.keys() else (r["received_at"] or r["first_seen"])
    threat = row_threat(r)[0]
    chips = []
    if threat:
        chips.append(kit.threat_badge(threat_text_of(r), compact=True))
    if new_since is not None and when and int(when) > int(new_since):
        chips.append('<span class="chip chip-new tone-brand" title="Kommet siden du sidst kiggede">Ny</span>')
    if show_account:
        chips.append(kit.chip(ui.account_label(account), "neutral"))
    if loc == "inbox" and view in ("spam", "overview"):
        chips.append(kit.chip("I indbakken", "info"))
    if loc == "newsletters":
        chips.append(kit.chip("I nyhedsbreve", "info"))
    if loc == "gone":
        chips.append('<span class="chip chip-gone">Slettet</span>')
    chips.append(zap_chip(r))
    chips.append(trust_chips(r, view))
    actions = swipe = ""
    if acc is not None and loc != "gone":
        here = _here(view)
        plan = swipe_plan(account=account, loc=loc, view=view, verdict=_rget(r, "user_verdict"), threat=threat)
        actions = _row_actions(key=key, account=account, loc=loc, view=view, pattern=pattern, rule=rule,
                               verdict=_rget(r, "user_verdict"), here=here, size="", threat=threat, swipe=plan)
        swipe = swipe_forms(plan, key=key, view=view, next_url=here, rendered=actions)
        plan_attrs = swipe_attrs(plan)
    else:
        plan_attrs = ""
    why = "".join(f"<li>{h(x)}</li>" for x in why_reasons(r, rule))
    main_tag = (f'<a class="mail-main" href="{_detail_url(account, mid)}">' if ui.can("see_messages", account)
                else '<div class="mail-main">')
    sync = pattern.split("@", 1)[1] if pattern else ""
    return (
        f'<li class="mail-row is-simple{" is-gone" if loc == "gone" else ""}" data-row="{h(key)}"'
        + (f' data-sync-key="{h(sync)}"' if sync else "") + plan_attrs + ">"
        f'<span class="simple-avatar" aria-hidden="true">{h((who.strip() or "?")[0].upper())}</span>'
        f'{main_tag}<span class="mail-top"><span class="mail-who"><span class="mail-from">{h(who)}</span>'
        f'{_rule_chip(rule)}</span>'
        + (f'<span class="mail-addr">{h(addr)}</span>' if name and addr else "")
        + f'</span><span class="mail-subj">{h(subject)}</span>'
        f'<span class="simple-meta"><time datetime="{kit.iso_ts(when)}">{h(kit.fmt_ts(when))}</time>{"".join(chips)}</span>'
        + ("</a>" if main_tag.startswith("<a") else "</div>")
        + f'<details class="why"><summary>{kit.icon("info")}<span>Hvorfor?</span></summary>'
        f'<ul class="why-list">{why}</ul></details>'
        f'<div class="mail-actions simple-actions">{actions}</div>{swipe}</li>')


def mail_row(r: Any, thresholds: dict[str, float], accounts: dict[str, Any], *,
             view: str, selectable: bool = False, show_account: bool = True,
             rules: RuleIndex | None = None, new_since: int | None = None) -> str:
    if not ui.is_admin():
        return simple_row(r, accounts, view=view, show_account=show_account, rules=rules, new_since=new_since)
    account, mid = str(r["account"]), str(r["message_id"])
    key = _key(account, mid)
    thr = thresholds.get(account, DEFAULT_THRESHOLD)
    name, addr = kit.sender_parts(r["sender"])
    who = name or addr or "Ukendt afsender"
    subject = (r["subject"] or "").strip() or "(intet emne)"
    old = _is_old(r)
    action = r["our_action"]
    acc = accounts.get(account)
    loc = _location(r, acc) if acc is not None else "gone"
    pattern = _sender_pattern(r["sender"])
    rule = (rules or RuleIndex()).match(account, pattern) if pattern else None
    check = ""
    if selectable and ui.can("release", account):
        check = (f'<div class="mail-check"><input type="checkbox" class="check" name="items" '
                 f'value="{h(key)}" form="bulk-{h(view)}" aria-label="Vælg besked fra {h(who)}"></div>')
    meta_chips = []
    when = r["ts"] if "ts" in r.keys() else (r["received_at"] or r["first_seen"])
    if new_since is not None and when and int(when) > int(new_since):
        meta_chips.append('<span class="chip chip-new tone-brand" title="Kommet siden du sidst kiggede">Ny</span>')
    if show_account:
        meta_chips.append(kit.chip(ui.account_label(account), "neutral"))
    verdict = _rget(r, "user_verdict")
    if verdict == "spam" and action not in ("manual_mark_spam", "user_junked"):
        meta_chips.append(kit.badge("Bekræftet spam", "bad"))
    elif verdict == "ham" and action not in RELEASED_ACTIONS:
        meta_chips.append(kit.badge("Bekræftet legitim", "ok"))
    else:
        meta_chips.append(kit.badge(kit.action_label(action), kit.action_tone(action)))
    if old:
        meta_chips.append('<span class="chip tone-neutral" title="Scoret med den gamle 1.x-metode">gammel scoring</span>')
    if loc == "gone":
        meta_chips.append('<span class="chip chip-gone" title="Mailen findes ikke længere i postkassen '
                          '(formentlig slettet)">Slettet</span>')
    threat = row_threat(r)[0]
    if threat:
        meta_chips.insert(0, kit.threat_badge(threat_text_of(r), compact=True))
    meta_chips.append(zap_chip(r))
    meta_chips.append(trust_chips(r, view))
    reasons = _reason_chips(r["symbols"], sender=_rget(r, "sender")) if action not in ("none", "allowlisted") else ""
    actions = swipe = plan_attrs = ""
    if acc is not None and loc != "gone":
        here = _here(view)
        plan = swipe_plan(account=account, loc=loc, view=view, verdict=verdict, threat=threat)
        actions = _row_actions(key=key, account=account, loc=loc, view=view, pattern=pattern, rule=rule,
                               verdict=verdict, here=here, threat=threat, swipe=plan)
        swipe = swipe_forms(plan, key=key, view=view, next_url=here, rendered=actions)
        plan_attrs = swipe_attrs(plan)
    href = _detail_url(account, mid)
    # Without 'see_messages' a Bruger sees the row but cannot open the mail.
    main_tag = (f'<a class="mail-main" href="{href}">' if ui.can("see_messages", account)
                else '<div class="mail-main">')
    sync = pattern.split("@", 1)[1] if pattern else ""
    return (
        f'<li class="mail-row{" is-old" if old else ""}{" is-gone" if loc == "gone" else ""}" data-row="{h(key)}"'
        + (f' data-sync-key="{h(sync)}"' if sync else "") + plan_attrs + f'>{check}'
        f'<div class="mail-score">{kit.score_badge(r["our_score"], thr)}</div>'
        f'{main_tag}'
        f'<span class="mail-top"><span class="mail-who"><span class="mail-from">{h(who)}</span>{_rule_chip(rule)}</span>'
        + (f'<span class="mail-addr">{h(addr)}</span>' if name and addr else "")
        + f'</span><span class="mail-subj">{h(subject)}</span>'
        + (f'<span class="mail-reasons">{reasons}</span>' if reasons else "")
        + ("</a>" if main_tag.startswith("<a") else "</div>")
        + f'<div class="mail-meta"><time datetime="{kit.iso_ts(when)}" title="{h(kit.fmt_ts(when))}">{h(kit.fmt_ts(when))}</time>'
        f'<div class="row-tight">{"".join(meta_chips)}</div></div>'
        f'<div class="mail-actions">{actions}</div>{swipe}</li>')


def _bulk_form(view: str, buttons: str, next_url: str) -> str:
    """The (invisible) form the row checkboxes belong to + sticky bar.
    Rendered without is-hidden so it also works without JS; app.js hides
    it while nothing is selected."""
    fid = f"bulk-{view}"
    return (
        f'<form id="{fid}" method="post" action="/mail/action" data-ajax data-bulk>'
        f'{kit.csrf_field()}{kit.hidden("view", view)}{kit.hidden("nonce", _nonce())}{kit.hidden("next", next_url)}'
        f'<div class="bulkbar" data-bulkbar="{fid}" role="toolbar" aria-label="Handlinger for valgte beskeder">'
        f'<span class="bulk-count"><span class="num" data-bulk-count="{fid}">0</span>valgt</span>'
        f"{buttons}</div></form>")


def _list_head(view: str, text: str, right: str = "", *, select: bool = True) -> str:
    box = (f'<input type="checkbox" class="check" data-select-all="bulk-{h(view)}" aria-label="Vælg alle på siden">'
           if select else "")
    return f'<div class="list-head">{box}<span>{text}</span><span class="spacer"></span>{right}</div>'


# ---------------------------------------------------------------------------
# Status + KPI data
# ---------------------------------------------------------------------------


def _stat_sum(metrics: Iterable[str], days: int, selected: str) -> dict[str, int]:
    since = kit.today_str(days - 1)
    sc, params = _scope(selected)
    q, mparams = _in(metrics)
    rows = ui.query(f"SELECT metric, SUM(n) AS n FROM stats_daily WHERE day >= ? AND metric IN {q}{sc} "
                    "GROUP BY metric", [since, *mparams, *params])
    return {r["metric"]: int(r["n"] or 0) for r in rows}


def _today_by_account() -> dict[str, dict[str, int]]:
    rows = ui.query("SELECT account, metric, n FROM stats_daily WHERE day=?", [kit.today_str()])
    out: dict[str, dict[str, int]] = {}
    for r in rows:
        out.setdefault(r["account"], {})[r["metric"]] = int(r["n"] or 0)
    return out


def local_midnight_ts(days_ago: int = 0) -> int:
    """Unix time of local (Europe/Copenhagen) midnight `days_ago` days
    before today (DST-correct)."""
    from datetime import datetime as _dt, timedelta as _td
    now = _dt.now(kit.TZ) if kit.TZ else _dt.now()
    day = now.date() - _td(days=days_ago)
    start = _dt(day.year, day.month, day.day, tzinfo=kit.TZ) if kit.TZ else _dt(day.year, day.month, day.day)
    return int(start.timestamp())


def spam_landed_by_account(t0: int, t1: int | None = None) -> dict[str, tuple[int, int]]:
    """{account: (spam, by_user)} - UNIQUE mails that landed in the filter
    folder in [t0, t1): the filter's moves (rescans included) plus what the
    users moved there themselves (dragged in the mail app or 'Det er spam'
    from the inbox). Counters in stats_daily count scans and actions, so a
    mail scanned twice or marked after it was caught would be counted
    twice; the event log names each mail once. Shared by the Oversigt
    mailbox cards and the Home Assistant API (ui_ha)."""
    until = " AND ts < ?" if t1 is not None else ""
    rows = ui.query(
        "SELECT account, message_id, MAX(event IN ('user_junked','manual_mark_spam')) AS by_user, "
        "MAX(event = 'moved_to_junk') AS by_filter FROM events "
        f"WHERE ts >= ?{until} AND message_id IS NOT NULL "
        "AND event IN ('moved_to_junk','user_junked','manual_mark_spam') GROUP BY account, message_id",
        [t0] + ([t1] if t1 is not None else []))
    out: dict[str, tuple[int, int]] = {}
    for r in rows:
        total, user = out.get(r["account"], (0, 0))
        out[r["account"]] = (total + 1, user + (1 if r["by_user"] and not r["by_filter"] else 0))
    return out


def provider_spam_by_account(t0: int) -> dict[str, int]:
    """2.7.2: {account: n} mails the mail PROVIDER put in its own spam folder
    (e.g. Scannet's SpamExperts -> Junk) since t0 - the filter sees them in
    its junk poll (event provider_junk) but did not move them itself, so
    they are not in 'Spam'. Shown as a separate line on the mailbox cards."""
    rows = ui.query("SELECT account, COUNT(DISTINCT COALESCE(message_id, detail)) AS n FROM events "
                    "WHERE ts >= ? AND event = 'provider_junk' GROUP BY account", [t0])
    return {r["account"]: int(r["n"] or 0) for r in rows}


def _spam_today_by_account() -> dict[str, tuple[int, int]]:
    """spam_landed_by_account() since local midnight (Oversigt cards)."""
    return spam_landed_by_account(local_midnight_ts())


def _kpis(selected: str, seconds: int) -> dict[str, dict[str, Any]]:
    """KPIs for [now-seconds, now) and the period before (for trends),
    from the messages table so '24 t' really is 24 hours."""
    now = int(time.time())
    sc, params = _scope(selected)
    spam_q, spam_p = _in(CATCH_ACTIONS)
    rel_q, rel_p = _in(RELEASED_ACTIONS)
    miss_q, miss_p = _in(MISSED_ACTIONS)

    def window(a: int, b: int) -> dict[str, int]:
        # 'Spam fanget' = the filter's own catches only. Mail the user had to
        # move to spam himself (user_junked / manual_mark_spam) is spam that
        # slipped through - counted separately, never as a catch.
        row = ui.query(
            f"SELECT COUNT(*) AS scanned, "
            f"SUM(CASE WHEN our_action IN {spam_q} THEN 1 ELSE 0 END) AS spam "
            f"FROM messages WHERE {TS} >= ? AND {TS} < ? AND COALESCE(origin,'inbox_scan') != 'junk_poll'{sc}",
            [*spam_p, a, b, *params], one=True)
        rel = ui.query(f"SELECT COUNT(*) FROM messages WHERE our_action IN {rel_q} "
                       f"AND COALESCE(verdict_at, last_seen) >= ? AND COALESCE(verdict_at, last_seen) < ?{sc}",
                       [*rel_p, a, b, *params], one=True)
        miss = ui.query(f"SELECT COUNT(*) FROM messages WHERE our_action IN {miss_q} "
                        f"AND COALESCE(verdict_at, last_seen) >= ? AND COALESCE(verdict_at, last_seen) < ?{sc}",
                        [*miss_p, a, b, *params], one=True)
        return {"scanned": int((row["scanned"] if row else 0) or 0),
                "spam": int((row["spam"] if row else 0) or 0),
                "released": int((rel[0] if rel else 0) or 0),
                "missed": int((miss[0] if miss else 0) or 0)}

    cur, prev = window(now - seconds, now + 60), window(now - 2 * seconds, now - seconds)
    return {"cur": cur, "prev": prev}


def _trend(cur: int, prev: int) -> float | None:
    if prev <= 0:
        return None
    return round((cur - prev) / prev * 100)


def _status_rows(selected: str) -> list[dict[str, Any]]:
    """One dict per visible account for cards, hero and /api/status."""
    status = ui.account_status_map()
    today = _today_by_account()
    spam_today = _spam_today_by_account()
    provider_today = provider_spam_by_account(local_midnight_ts())
    out = []
    for a in ui.visible_accounts():
        if selected and a.name != selected:
            continue
        st = status.get(a.name, {})
        state = ui.account_state(a)
        t = today.get(a.name, {})
        last = max(int(st.get("last_scan_at") or 0), int(st.get("last_loop_at") or 0))
        out.append({
            "name": a.name, "label": ui.account_label(a.name), "user": getattr(a, "user", ""),
            "mode": getattr(a, "mode", "shadow"),
            "move_state_reason": st.get("move_state_reason") or "", "retry_at": st.get("retry_at"),
            "threshold": float(getattr(a, "threshold", DEFAULT_THRESHOLD) or DEFAULT_THRESHOLD),
            "enabled": bool(getattr(a, "enabled", True)), "state": state,
            "detail": st.get("detail") or "", "last_activity": last or None,
            "junk": getattr(a, "junk", "Junk"), "junk_exists": st.get("junk_exists"),
            "move_method": st.get("move_method"),
            # 'Spam' = everything that ended up in the filter folder today: the
            # filter's own catches, rescans (ZAP) and what the users moved there.
            "today": {"scanned": t.get("scanned", 0),
                      "spam": spam_today.get(a.name, (0, 0))[0],
                      "spam_user": spam_today.get(a.name, (0, 0))[1],
                      "provider_spam": provider_today.get(a.name, 0),
                      "released": t.get("released", 0) + t.get("user_rescued", 0),
                      "skipped_seen": t.get("skipped_seen", 0), "skipped_no_msgid": t.get("skipped_no_msgid", 0)},
        })
    return out


PROBLEM_STATES = ("error", "auth_failed", "config_error", "stale", "paused_moves", "limited")


def _attention(rows: list[dict], selected: str) -> list[dict[str, str]]:
    """Things the owner should look at, most severe first."""
    items: list[dict[str, str]] = []
    admin = bool((ui.current_user() or {}).get("is_admin"))
    err = ui.config_error()
    star = ui.account_status_map().get("*", {})
    if err or star.get("raw_state") == "config_error":
        # The raw error can name other mailboxes: only admins see it.
        text = (err or star.get("detail") or "accounts.yml indeholder en fejl.") if admin else \
            "Filterets opsætning har en fejl. Kontakt administratoren."
        items.append({"tone": "bad", "icon": "alert-circle", "title": "Konfigurationen kan ikke indlæses",
                      "text": text, "href": "/accounts" if admin else "", "link": "Åbn konti"})
    for r in rows:
        st = r["state"]
        nm = r.get("label") or r["name"]
        if st == "paused_moves":
            items.append({"tone": "bad", "icon": "pause", "title": f"Flytning er sat på pause for {nm}",
                          "text": (r.get("move_state_reason") or r["detail"]
                                   or "Filteret flyttede usædvanligt meget og har stoppet sig selv for en sikkerheds skyld.")
                                  + " Spam bliver liggende i indbakken, indtil flytningen genoptages.",
                          "href": f"/accounts/{quote(r['name'], safe='')}#flytning" if admin else "",
                          "link": "Se og genoptag"})
        elif st == "limited":
            items.append({"tone": "warn", "icon": "clock", "title": f"Udbyderen begrænser forbindelser til {nm}",
                          "text": r["detail"] or "Filteret venter og prøver selv igen om lidt. Intet går tabt.",
                          "href": "/system" if admin else "", "link": "Se driftsstatus"})
        if st == "auth_failed":
            items.append({"tone": "bad", "icon": "key", "title": f"Login fejler for {nm}",
                          "text": r["detail"] or "Mailserveren afviser adgangskoden. Filteret prøver igen hver halve time.",
                          "href": f"/accounts#acct-{r['name']}" if admin else "", "link": "Opdater adgangskode"})
        elif st == "error":
            items.append({"tone": "bad", "icon": "plug", "title": f"Forbindelsesfejl på {nm}",
                          "text": r["detail"] or "Filteret prøver automatisk igen.",
                          "href": f"/system" if admin else "", "link": "Se driftsstatus"})
        elif st == "stale":
            items.append({"tone": "warn", "icon": "clock", "title": f"{nm} har ikke meldt sig i et stykke tid",
                          "text": "Kontoens tråd svarer ikke. Genstart filteret, hvis det varer ved.",
                          "href": "/system" if admin else "", "link": "Se driftsstatus"})
        # In Overvåg a missing Spamfilter folder is expected (it is created
        # on the first Markér/Filtrér start; the Konti card says so) - not
        # something to act on, so it is not listed here.
        if r["enabled"] and r["junk_exists"] == 0 and r["mode"] in ("flag", "move"):
            items.append({"tone": "warn", "icon": "folder", "title": f"Spamfilter-mappen mangler på {nm}",
                          "text": f"Mappen “{r['junk']}” findes ikke. Filteret opretter den ved næste forbindelse.",
                          "href": f"/accounts#acct-{r['name']}" if admin else "", "link": "Se konto"})
    sc, params = _scope(selected)
    failed = ui.query(f"SELECT COUNT(*) FROM messages WHERE our_action='move_failed' AND last_seen >= ?{sc}",
                      [int(time.time()) - 86400, *params], one=True)
    if failed and failed[0]:
        items.append({"tone": "warn", "icon": "alert-triangle",
                      "title": f"{_n(int(failed[0]), 'flytning', 'flytninger')} fejlede det seneste døgn",
                      "text": "Beskederne ligger stadig i indbakken."
                              + (" Se dem under Beskeder." if ui.can("see_messages") else ""),
                      "href": "/messages?result=spam" if ui.can("see_messages") else "", "link": "Vis beskeder"})
    review = len(review_items(selected))
    if review:
        items.append({"tone": "info", "icon": "eye", "title": f"{_n(review, 'mail', 'mails')} bør tjekkes",
                      "text": "Fanget spam, der måske ikke er spam: lige over grænsen, kendte afsendere eller "
                              "beskyttede adresser.", "href": "/spam" + (f"?account={quote(selected, safe='')}" if selected else "") + "#tjek",
                      "link": "Tjek disse"})
    items += demoted_items(selected)
    if admin:
        items += ui_lookalike.attention_items()
        items += ui_namespoof.attention_items()  # 2.7: Prøv has run a week
        items += ui_campaigns.attention_items()  # 2.6: A6 protected inbox, A3 block suggestions
        items += _admin_hints(rows)
    order = {"bad": 0, "warn": 1, "info": 2}
    items.sort(key=lambda i: order.get(i["tone"], 3))
    return items


DEMOTED_DAYS = 7


def demoted_contacts(selected: str = "") -> list[Any]:
    """Known contacts removed in the last 7 days because one of their mails
    was put in spam (B14, in the mail app or here), still removed."""
    sc, sp = _scope(selected)
    return ui.query(f"SELECT account, h, mask, status_at FROM known_contacts WHERE status='demoted' "
                    f"AND status_at >= ?{sc} ORDER BY status_at DESC LIMIT 20",
                    [int(time.time()) - DEMOTED_DAYS * 86400, *sp], default=[]) or []


def keep_contact_form(account: str, h_: str, *, next_url: str, size: str = "sm", label: str = "Behold som kontakt") -> str:
    """One click undoes the automatic removal (services.restore_contact)."""
    inner = (kit.hidden("account", account) + kit.hidden("h", h_) + kit.hidden("status", "active")
             + kit.hidden("next", next_url)
             + kit.button(label, kind="secondary", icon="user-check", tone="ok", size=size))
    return kit.post_form("/rules/contacts/status", inner, cls="inline-form")


def demoted_items(selected: str) -> list[dict[str, str]]:
    """Attention item: 'a…@kunde.dk er fjernet fra Kendte kontakter' with
    'Behold som kontakt' (rules permission) - the default stays removed."""
    rows = [r for r in demoted_contacts(selected) if ui.can_access(str(r["account"]))]
    if not rows:
        return []
    here = _here("overview")
    first = rows[0]
    account = str(first["account"])
    contacts_href = f"/rules/contacts?account={quote(account, safe='')}&status=demoted"
    if len(rows) == 1:
        title = f"{first['mask'] or 'En afsender'} er fjernet fra Kendte kontakter"
        text = ("En mail fra afsenderen blev lagt i spam, så filteret stoler ikke længere på den"
                + (f" ({ui.account_label(account)})" if ui.is_admin() else "") + ". Var det en fejl, så behold "
                "afsenderen som kontakt.")
        form = keep_contact_form(account, str(first["h"]), next_url=here) if ui.can("rules", account) else ""
    else:
        title = f"{len(rows)} afsendere er fjernet fra Kendte kontakter"
        text = "Deres mails blev lagt i spam den seneste uge. Tjek, at det var med vilje."
        form = ""
    return [{"tone": "info", "icon": "user-x", "title": title, "text": text, "href": contacts_href,
             "link": "Se Kendte kontakter", "form": form}]


_SUGGEST_CACHE: dict[tuple[str, str], tuple[float, dict]] = {}
SUGGEST_TTL = 600


def threshold_hint(account: str) -> dict:
    """services.threshold_suggestion() cached for 10 min (Oversigt calls it
    for every mailbox on every load)."""
    key = (str(ui.DB_PATH), account)
    hit = _SUGGEST_CACHE.get(key)
    now = time.time()
    if hit and now - hit[0] < SUGGEST_TTL:
        return hit[1]
    try:
        res = ui.services.threshold_suggestion(account) or {}
    except Exception as ex:  # noqa: BLE001 - a hint must never break Oversigt
        log.warning("threshold_suggestion failed: %s", type(ex).__name__)
        res = {}
    _SUGGEST_CACHE[key] = (now, res if isinstance(res, dict) else {})
    return _SUGGEST_CACHE[key][1]


# 2.8.4: "Afvis" on a threshold suggestion. The dismissal is bound to the
# exact suggestion (direction, current and recommended threshold), so it
# comes back only when the filter arrives at a different one.
SUG_DISMISS_KEY = "threshold_suggestion_dismissed:{}"


def threshold_sig(sug: dict) -> str:
    try:
        return f"{sug.get('change')}|{float(sug.get('current')):.1f}|{float(sug.get('recommended')):.1f}"
    except (TypeError, ValueError):
        return ""


def threshold_dismissed(account: str, sug: dict) -> bool:
    if not sug or sug.get("change") not in ("raise", "lower") or not threshold_sig(sug):
        return False
    try:
        d = json.loads(ui.settings_get(SUG_DISMISS_KEY.format(account)) or "{}")
    except (TypeError, ValueError):
        return False
    return isinstance(d, dict) and d.get("sig") == threshold_sig(sug)


def threshold_dismiss_form(account: str, sug: dict, next_url: str) -> str:
    inner = (kit.hidden("sig", threshold_sig(sug)) + kit.hidden("next", next_url)
             + kit.button("Afvis", kind="ghost", icon="x", size="sm"))
    return kit.post_form(f"/accounts/{quote(account, safe='')}/threshold-suggestion/dismiss", inner,
                         cls="inline-form")


def _admin_hints(rows: list[dict]) -> list[dict[str, str]]:
    """Admin-only: update hold after a new version, threshold suggestions."""
    items: list[dict[str, str]] = []
    try:
        hold = int(ui.engine.move_hold_until(ui.db()) or 0) if hasattr(ui.engine, "move_hold_until") else 0
    except Exception:  # noqa: BLE001 - older engine/DB without engine_state
        hold = 0
    if hold > time.time():
        items.append({"tone": "info", "icon": "clock", "title": "Forsigtig start efter opdatering",
                      "text": f"Indtil kl. {kit.fmt_ts(hold).split(' ')[-1]} flyttes kun tydelig spam. "
                              "Grænsetilfælde venter i køen og flyttes bagefter.", "href": "", "link": ""})
    for r in rows:
        if not r["enabled"] or r["mode"] == "shadow":
            continue
        sug = threshold_hint(r["name"])
        if sug.get("change") in ("raise", "lower") and sug.get("confidence") in ("medium", "high") \
                and sug.get("recommended") is not None and not threshold_dismissed(r["name"], sug):
            items.append({"tone": "info", "icon": "sliders",
                          "title": f"Forslag til følsomhed for {r.get('label') or r['name']}",
                          "text": str(sug.get("text") or ""),
                          "href": f"/accounts/{quote(r['name'], safe='')}#forslag", "link": "Se forslaget",
                          "form": threshold_dismiss_form(r["name"], sug, "/")})
    return items


# ---------------------------------------------------------------------------
# 'Tjek disse' (2.1): caught spam that may not be spam
# ---------------------------------------------------------------------------

REVIEW_ACTIONS = ("moved_to_junk", "pending_move", "flagged", "flag", "move_failed")
REVIEW_DAYS = 30
REVIEW_LIMIT = 400
REVIEW_MARGIN = 3.0
REVIEW_NEAR = 1.5
KNOWN_DAYS = 365
KNOWN_TTL = 600
LEGIT_ACTIONS = ("none", "allowlisted", "manual_release", "user_rescued")
_ADDR_RE = re.compile(r"[^\s<>\"',;:()\[\]]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_KNOWN_CACHE: dict[tuple[str, str], tuple[float, dict[str, int]]] = {}


def review_cache_clear() -> None:
    _KNOWN_CACHE.clear()
    _SUGGEST_CACHE.clear()


def _addr_of(value: Any) -> str:
    """Lowercase address of a From header (the one inside <> wins)."""
    found = _ADDR_RE.findall(str(value or ""))
    return found[-1].lower().strip(".") if found else ""


def _known_senders(account: str) -> dict[str, int]:
    """From-address -> number of legitimate mails (kept, allowed, released)
    in the last year. Cached 10 min per account: it scans the table."""
    key = (str(ui.DB_PATH), account)
    hit = _KNOWN_CACHE.get(key)
    now = time.time()
    if hit and now - hit[0] < KNOWN_TTL:
        return hit[1]
    q, qp = _in(LEGIT_ACTIONS)
    rows = ui.query(f"SELECT sender FROM messages WHERE account=? AND (our_action IN {q} OR user_verdict='ham') "
                    f"AND COALESCE(user_verdict,'') != 'spam' AND {TS} >= ?",
                    [account, *qp, int(now) - KNOWN_DAYS * 86400])
    counts: dict[str, int] = {}
    for r in rows:
        addr = _addr_of(r["sender"])
        if addr:
            counts[addr] = counts.get(addr, 0) + 1
    _KNOWN_CACHE[key] = (now, counts)
    return counts


def _own_domain(acc: Any) -> str:
    user = str(getattr(acc, "user", "") or "")
    return user.rsplit("@", 1)[1].lower() if "@" in user else ""


def review_reasons(r: Any, acc: Any, thr: float, known: dict[str, int]) -> list[str]:
    """Plain Danish one-liners: why this caught mail deserves a second look."""
    out: list[str] = []
    addr = _addr_of(r["sender"])
    own = _own_domain(acc)
    syms = {s["n"]: s for s in kit.parse_symbols(r["symbols"])}
    n_known = known.get(addr, 0) if addr else 0
    if n_known:
        out.append("Du har fået " + ("en normal mail" if n_known == 1 else f"{kit.fmt_int(n_known)} normale mails")
                   + " fra denne afsender før")
    if "TH_KNOWN_CONTACT" in syms or "TH_REPLY" in syms:
        out.append("Svar på en mail, du selv har sendt" if "TH_REPLY" in syms
                   else "Afsenderen er en kendt kontakt – du har selv skrevet til den")
    if "TH_PROTECTED_RCPT" in syms:
        opt = (syms["TH_PROTECTED_RCPT"].get("o") or [""])[0]
        out.append("Sendt til en beskyttet adresse" + (f" ({opt})" if opt and "@" in opt else ""))
    if "TH_FORCE_UNVERIFIED" in syms:
        out.append("Afsenderen er sat til Altid igennem, men mailen kunne ikke bekræftes som ægte")
    dom = addr.rsplit("@", 1)[1] if "@" in addr else ""
    if own and dom and (dom == own or dom.endswith("." + own)):
        out.append(f"Afsenderen bruger dit eget domæne ({dom})")
    score = r["our_score"]
    if score is not None:
        try:
            sc = float(score)
        except (TypeError, ValueError):
            sc = None
        if sc is not None and sc < thr + REVIEW_MARGIN:
            if ui.is_admin():
                label = "Lige over grænsen" if sc < thr + REVIEW_NEAR else "Tæt på grænsen"
                out.append(f"{label}: {kit.fmt_score(sc)} af {kit.fmt_score(thr)}")
            else:
                # Neutral: borderline mail is still mostly spam (phishing too).
                out.append("Tæt på grænsen – kig en ekstra gang")
    return out


def provider_review_reasons(r: Any, thr: float, reasons: list[str]) -> list[str]:
    """2.12 (#13): provider junk is offered only when the filter scored it
    below the threshold AND the sender is known (a reason about earlier
    mail or a contact) - otherwise [] (the provider was probably right)."""
    try:
        score = float(r["our_score"])
    except (TypeError, ValueError):
        return []
    known = [x for x in reasons if x.startswith(("Du har fået", "Afsenderen er en kendt", "Svar på en mail"))]
    if score >= thr or not known:
        return []
    return ["Udbyderen lagde den i sin spam-mappe, men filteret ville have ladet den komme igennem"] + reasons


def review_items(selected: str, *, limit: int | None = None) -> list[tuple[Any, list[str]]]:
    """Caught mail of the last 30 days nobody has judged yet that is
    borderline, from a known correspondent, from the own domain or to a
    protected address. Newest first. Cached per request."""
    cache_key = f"_review:{selected}"
    from flask import g

    if cache_key in g:
        items = g.get(cache_key)
        return items[:limit] if limit else items
    sc, sp = _scope(selected)
    # 2.12 (#13): provider junk the filter scored itself (read-only) joins
    # when the filter would NOT have called it spam and the sender is known.
    # Only provider junk scored below the highest threshold is read at all,
    # so it never crowds the real candidates out of REVIEW_LIMIT.
    accounts, thresholds = _accounts(), _thresholds()
    top = max([float(v) for v in thresholds.values()] + [float(DEFAULT_THRESHOLD)])
    q, qp = _in(REVIEW_ACTIONS)
    pq, pp = _in(PROVIDER_ACTIONS)
    rows = ui.query(f"SELECT *, {TS} AS ts FROM messages WHERE (our_action IN {q} OR (our_action IN {pq} "
                    f"AND our_score IS NOT NULL AND our_score < ?)) AND user_verdict IS NULL "
                    f"AND current_folder != 'gone' AND {TS} >= ?{sc} ORDER BY ts DESC LIMIT ?",
                    [*qp, *pp, top, int(time.time()) - REVIEW_DAYS * 86400, *sp, REVIEW_LIMIT])
    items: list[tuple[Any, list[str]]] = []
    known_by: dict[str, dict[str, int]] = {}
    for r in rows:
        account = str(r["account"])
        acc = accounts.get(account)
        if acc is None or row_threat(r)[0] or _rget(r, "zapped_at"):
            # 2.3: a dangerous mail (B16) or a rescan catch with a new
            # blocklist hit (B19) is never offered as "maybe not spam".
            continue
        if account not in known_by:
            known_by[account] = _known_senders(account)
        thr = thresholds.get(account, DEFAULT_THRESHOLD)
        reasons = review_reasons(r, acc, thr, known_by[account])
        if str(r["our_action"]) in PROVIDER_ACTIONS:
            reasons = provider_review_reasons(r, thr, reasons)
        if reasons:
            items.append((r, reasons))
    setattr(g, cache_key, items)
    return items[:limit] if limit else items


def review_row(r: Any, reasons: list[str], thresholds: dict[str, float], *, show_account: bool,
               new_since: int | None, here: str, rules: RuleIndex | None = None) -> str:
    account, mid = str(r["account"]), str(r["message_id"])
    key = _key(account, mid)
    name, addr = kit.sender_parts(r["sender"])
    who = name or addr or "Ukendt afsender"
    subject = (r["subject"] or "").strip() or "(intet emne)"
    when = r["ts"]
    chips = []
    if new_since is not None and when and int(when) > int(new_since):
        chips.append('<span class="chip chip-new tone-brand">Ny</span>')
    if show_account:
        chips.append(kit.chip(ui.account_label(account), "neutral"))
    btns = ""
    # 2.5.0: Tjek disse never lists a dangerous mail (review_items), but the
    # swipe plan applies the B16 gate anyway (fail closed).
    plan = swipe_plan(account=account, loc="junk", view="review", verdict=_rget(r, "user_verdict"),
                      threat=row_threat(r)[0])
    if ui.can("release", account):
        btns = (_mail_btn(key, "release", "Frigiv", icon="undo", tone="info", view="review", next_url=here,
                          title="Flyt tilbage til indbakken og lær som legitim", size="",
                          swipe="right" if plan.get("right") == "release" else "")
                + _mail_btn(key, "learn_spam", "Det er spam", icon="shield-alert", tone="bad", view="review",
                            next_url=here, title="Behold i spam og lær filteret, at den er spam", size="",
                            swipe="left" if plan.get("left") == "learn_spam" else ""))
        # 2.3: "Tillad afsender" (release + allow) with the same address /
        # domain dialog as everywhere else. Never for a dangerous mail or a
        # sender an administrator made 'Altid igennem'.
        pattern = _sender_pattern(r["sender"])
        rule = (rules or RuleIndex()).match(account, pattern) if pattern else None
        if (pattern and ui.can_edit_rule(account) and not row_threat(r)[0]
                and (rule is None or rule["kind"] != "allow") and (ui.is_admin() or not _rule_force(rule))):
            btns += _mail_btn(key, "release_allow", "Tillad afsender", short="Tillad", icon="check-circle",
                              tone="ok", view="review", next_url=here, choose=True, size="",
                              title=f"Frigiv beskeden og tillad {pattern}{_also_domain(pattern)}")
    else:
        btns = '<span class="faint small">Træk den tilbage til Indbakken i dit mailprogram, hvis den er din.</span>'
    main_tag = (f'<a class="review-main" href="{_detail_url(account, mid)}">' if ui.can("see_messages", account)
                else '<div class="review-main">')
    reason_html = "".join(f'<li>{kit.icon("info")}<span>{h(x)}</span></li>' for x in reasons[:2])
    swipe = swipe_forms(plan, key=key, view="review", next_url=here, rendered=btns)
    # 2.8.2: tick several and judge them in one go (bulk-review in _review_section).
    check = (f'<div class="mail-check"><input type="checkbox" class="check" name="items" value="{h(key)}" '
             f'form="bulk-review" aria-label="Vælg besked fra {h(who)}"></div>') if ui.can("release", account) else ""
    return (f'<li class="review-row{" has-check" if check else ""}" data-row="review:{h(key)}"{swipe_attrs(plan)}>'
            + check
            + (f'<div class="review-score">{kit.score_badge(r["our_score"], thresholds.get(account, DEFAULT_THRESHOLD))}</div>'
               if ui.is_admin() else f'<div class="review-score review-ic">{kit.icon("eye")}</div>')
            + f'{main_tag}<span class="review-who"><b>{h(who)}</b>'
            + (f'<span class="mail-addr">{h(addr)}</span>' if name and addr else "")
            + f'</span><span class="review-subj">{h(subject)}</span>'
            f'<ul class="review-reasons">{reason_html}</ul>'
            f'<span class="review-meta"><time datetime="{kit.iso_ts(when)}">{h(kit.fmt_ts(when))}</time>{"".join(chips)}</span>'
            + ("</a>" if main_tag.startswith("<a") else "</div>")
            + f'<div class="review-actions">{btns}</div>{swipe}</li>')


def _review_section(selected: str, thresholds: dict[str, float], new_since: int | None, here: str) -> str:
    items = review_items(selected)
    if not items:
        return ""
    shown = items[:8 if ui.is_admin() else 3]
    more = len(items) - len(shown)
    multi = len(_accounts()) > 1
    rules = RuleIndex()
    rows = "".join(review_row(r, reasons, thresholds, show_account=not selected and multi, new_since=new_since, here=here,
                              rules=rules)
                   for r, reasons in shown)
    foot = (f'<p class="review-more faint">+ {_n(more, "mail mere", "mails mere")} – de vises også i listen nedenfor.</p>'
            if more > 0 else "")
    bulk = head = ""
    if any(ui.can("release", r["account"]) for r, _ in shown):
        head = _list_head("review", "Vælg flere og afgør dem på én gang")
        bulk = _bulk_form("review", (
            kit.button("Frigiv", kind="primary", icon="undo", size="sm", attrs='name="action" value="release"')
            + kit.button("Det er spam", kind="danger", icon="shield-alert", size="sm",
                         attrs='name="action" value="learn_spam"')), here)
    return (f'<section class="card review-card" id="tjek" aria-labelledby="tjek-title">'
            f'<div class="review-head"><span class="review-icon">{kit.icon("eye")}</span><div>'
            f'<h2 class="card-title" id="tjek-title">Tjek disse <span class="badge tone-info">{kit.fmt_int(len(items))}</span></h2>'
            '<p class="card-sub">Måske ikke spam. Et hurtigt kig her fanger de fleste fejl – resten er næsten '
            'altid ægte spam.</p></div></div>'
            f'{head}<ul class="review-list" data-list>{rows}</ul>{foot}{bulk}</section>')


def _junk_notes(selected: str, here: str) -> str:
    """2.12 (#8/#9): admins see rules that clash with the users' own moves to
    Junk and the senders blocked per mailbox (ui_junkrules)."""
    if not ui.is_admin():
        return ""
    import ui_junkrules  # noqa: PLC0415 - registered at the end of this module

    return ui_junkrules.section(selected, here)


WELCOME_KEY = "welcome_done:{}"


def auto_allow_on(account: str | None = None) -> bool:
    """Does dragging a mail out of the spam folder in the mail app allow
    the sender (auto_allow_on_rescue) for `account`, or for any mailbox
    the user can see? Shadow mode never moves, so never auto-allows."""
    accs = _accounts()
    if account is not None:
        accs = {account: accs[account]} if account in accs else {}
    return any(getattr(a, "mode", "move") != "shadow" and bool(getattr(a, "auto_allow_on_rescue", True))
               for a in accs.values())


def _welcome_card() -> str:
    """First-login welcome (dismissible per user, settings_kv welcome_done:<user>)."""
    user = ui.current_user() or {}
    name = user.get("name") or ""
    if not name or ui.settings_get(WELCOME_KEY.format(name)):
        return ""
    release = ui.can("release")
    auto = auto_allow_on()
    drag = ("Trækker du den selv tilbage til Indbakken i mailprogrammet, bliver afsenderen tilladt automatisk."
            if auto else "Du kan også trække den tilbage til Indbakken i mailprogrammet.")
    steps = [
        ("folder", "Spam lander i mappen “Spamfilter”",
         "Du finder den i dit mailprogram ved siden af Indbakken. Intet bliver slettet."),
        ("undo", "Er der en rigtig mail imellem?",
         (("Tryk Frigiv for at lægge den tilbage – eller Tillad, så afsenderen også slipper igennem næste gang. "
           if ui.can("rules") else "Tryk Frigiv for at lægge den tilbage i indbakken. ") + drag
          if release else "Træk den tilbage til Indbakken i dit mailprogram. Filteret lærer af det"
          + (", og afsenderen bliver tilladt." if auto else "."))),
        ("shield-alert", "Spam i indbakken?",
         "Træk den over i mappen Spamfilter – også på telefonen. Så lærer filteret, at den slags er spam."),
    ]
    if release:
        steps.append(("search", "Mangler du en mail?", "Brug “Find en mail” – den leder i alle mapperne, også udbyderens spam."))
    lis = "".join(f'<li><span class="welcome-ic">{kit.icon(ic)}</span><div><b>{h(t)}</b><span>{h(x)}</span></div></li>'
                  for ic, t, x in steps)
    dismiss = kit.post_form("/welcome/dismiss", kit.button("Forstået", kind="primary", icon="check", size="sm"),
                            cls="inline-form")
    close = kit.post_form("/welcome/dismiss", '<button type="submit" class="icon-btn welcome-x" aria-label="Luk velkomsten">'
                          + kit.icon("x") + "</button>", cls="inline-form")
    return (f'<section class="card welcome-card" data-row="welcome" aria-labelledby="welcome-title">'
            f'<div class="welcome-head">{kit.brand_mark("welcome-mark")}<div class="welcome-titles">'
            f'<h2 id="welcome-title">Velkommen{", " + h(name) if name else ""}</h2>'
            '<p>Spamfilteret holder øje med din indbakke og sorterer spam fra. Sådan bruger du det:</p></div>'
            f'{close}</div><ol class="welcome-steps">{lis}</ol>'
            f'<div class="welcome-actions">{kit.button("Læs hele vejledningen", href="/help", kind="secondary", icon="info", size="sm")}'
            f'{dismiss}</div></section>')


@app.post("/welcome/dismiss")
@ui.login_required
def welcome_dismiss():
    user = ui.current_user() or {}
    ui.settings_set(WELCOME_KEY.format(user.get("name", "")), str(int(time.time())))
    return ui.respond("Velkomsten er skjult. Du finder vejledningen under Hjælp.", next_url="/",
                      rows={"welcome": None})


SPAM_VISIT_TTL = 30 * 60


def _spam_new_since(name: str) -> int | None:
    """'Ny' marks mail newer than the user's PREVIOUS visit to Fanget spam.
    Each visit stores the new 'last visit' (settings_kv spam_seen:<user>, so
    the nav badge clears) and keeps the previous one in the session for 30
    min, so the chips survive paging and filtering during the visit."""
    now = int(time.time())
    if ui.preview_target():  # read-only preview: show, but never store a visit
        stored = ui.spam_seen_at(name)
        return stored if stored is not None else now - 86400
    visit = session.get("spam_visit")
    if isinstance(visit, dict) and visit.get("u") == name and now - int(visit.get("at") or 0) < SPAM_VISIT_TTL:
        prev = visit.get("prev")
    else:
        stored = ui.spam_seen_at(name)
        prev = stored if stored is not None else now - 86400
    session["spam_visit"] = {"u": name, "prev": prev, "at": now}
    ui.set_spam_seen(name, now)
    try:
        return int(prev) if prev is not None else None
    except (TypeError, ValueError):
        return None


def _visit_new_since() -> int | None:
    """The 'Ny' cut-off of the current Fanget spam visit (read-only: an
    AJAX row re-render must not count as a new visit)."""
    name = (ui.current_user() or {}).get("name")
    visit = session.get("spam_visit")
    if not name or not isinstance(visit, dict) or visit.get("u") != name:
        return None
    try:
        if time.time() - int(visit.get("at") or 0) >= SPAM_VISIT_TTL:
            return None
        return int(visit["prev"]) if visit.get("prev") is not None else None
    except (TypeError, ValueError, KeyError):
        return None


@app.post("/spam/seen")
@ui.login_required
def spam_mark_seen():
    user = ui.current_user() or {}
    now = ui.set_spam_seen(user.get("name", ""))
    session["spam_visit"] = {"u": user.get("name", ""), "prev": now, "at": now}
    return ui.respond("Alt er markeret som gennemset.", next_url=ui.safe_next(request.form.get("next"), "/spam"),
                      refresh=True)


# ---------------------------------------------------------------------------
# Oversigt
# ---------------------------------------------------------------------------


def _hero(rows: list[dict], attention: list[dict]) -> str:
    admin = bool((ui.current_user() or {}).get("is_admin"))
    active = [r for r in rows if r["enabled"]]
    paused = [r for r in rows if not r["enabled"]]
    problems = [r for r in active if r["state"] in PROBLEM_STATES]
    modes = {m: sum(1 for r in active if r["mode"] == m) for m in ("move", "flag", "shadow")}
    chips = []
    for m, label in (("move", "filtrerer"), ("flag", "markerer"), ("shadow", "overvåger")):
        if modes[m]:
            chips.append(kit.chip(f"{modes[m]} {label}", kit.MODE_TONES.get(m, "neutral")))
    if paused:
        chips.append(kit.chip(f"{len(paused)} på pause", "neutral"))
    actions = kit.button("Se fanget spam", href="/spam", kind="secondary", icon="shield-alert")
    config_bad = next((a for a in attention if a["title"].startswith("Konfigurationen")), None)
    if config_bad:
        tone, ic = "bad", "alert-circle"
        title, text = config_bad["title"], config_bad["text"]
        if admin:
            actions = kit.button("Åbn konti", href="/accounts", kind="primary", icon="arrow-right")
    elif not rows:
        tone, ic = "info", "inbox"
        title = "Ingen postkasser endnu"
        text = "Tilføj den første postkasse for at komme i gang." if admin else "Du har ikke adgang til nogen postkasser."
        actions = kit.button("Tilføj konto", href="/accounts", kind="primary", icon="plus") if admin else ""
    elif problems:
        tone = "bad" if any(p["state"] in ("auth_failed", "error", "paused_moves") for p in problems) else "warn"
        ic = "alert-triangle"
        names = ", ".join(p.get("label") or p["name"] for p in problems)
        title = (f"{_n(len(problems), 'postkasse', 'postkasser')} kræver opmærksomhed")
        first = problems[0]["state"]
        step = {"auth_failed": "Opdater adgangskoden under Konti.",
                "error": "Filteret prøver automatisk igen – tjek Drift, hvis det varer ved.",
                "stale": "Genstart filteret under Drift, hvis det varer ved.",
                "paused_moves": ("Flytningen er sat på pause – se kontoen og genoptag, når du har tjekket den."
                                 if admin else "Flytningen er sat på pause. Administratoren får besked."),
                "limited": "Udbyderen begrænser forbindelserne – filteret prøver selv igen."}.get(first, "")
        text = f"{names}. {step}".strip()
        if admin:
            actions = kit.button("Løs problemet", href="/accounts", kind="primary", icon="arrow-right") + actions
    elif not active:
        tone, ic = "neutral", "pause"
        title = "Alle postkasser er sat på pause"
        text = "Filteret scanner ikke post, før en konto genoptages."
    elif modes["shadow"] == len(active):
        tone, ic = "info", "eye"
        title = f"{_n(len(active), 'postkasse overvåges', 'postkasser overvåges')}"
        text = "Filteret scorer ny post uden at flytte den. Skift til Filtrér, når du er tryg ved scorerne."
        if admin:
            actions = kit.button("Aktivér filtrering", href="/accounts", kind="primary", icon="shield-check") + actions
    elif modes["move"] == len(active):
        tone, ic = "ok", "shield-check"
        title = (f"Alle {len(active)} postkasser er beskyttet" if len(active) > 1
                 else "Din postkasse er beskyttet")
        text = "Filteret holder øje med ny post i realtid og sorterer spam fra."
    else:
        # Only Filtrér moves spam out of the inbox; Markér/Overvåg do not.
        tone, ic = "info", "shield"
        title = f"{modes['move']} af {len(active)} postkasser filtreres"
        text = ("Resten overvåges eller markeres kun, så spam bliver liggende i indbakken. "
                "Slå Filtrér til under Konti, når du er tryg ved scorerne.")
        if admin:
            actions = kit.button("Aktivér filtrering", href="/accounts", kind="primary", icon="shield-check") + actions
    return (f'<section class="hero tone-{tone}"><div class="hero-icon">{kit.icon(ic)}</div>'
            f'<div class="hero-body"><h2 class="hero-title">{h(title)}</h2><p class="hero-text">{h(text)}</p>'
            + (f'<div class="hero-chips">{"".join(chips)}</div>' if chips else "")
            + "</div>"
            + (f'<div class="hero-actions">{actions}</div>' if actions else "")
            + "</section>")


def _live_dot(state: str, key: str) -> str:
    tone = kit.state_tone(state)
    pulse = " dot-pulse" if state in ("idle", "working", "connecting", "starting") else ""
    label = kit.state_label(state)
    return (f'<span class="dot tone-{tone}{pulse}" role="img" aria-label="{h(label)}" title="{h(label)}" '
            f'data-live="{h(key)}" data-live-class></span>')


def _spam_user_text(n: int, provider: int = 0) -> str:
    """Sub-line under 'Spam' on a mailbox card: how much of it the users moved,
    and (2.7.2) how much the mail provider caught in its own spam folder."""
    n, provider = int(n or 0), int(provider or 0)
    parts = [f"heraf {kit.fmt_int(n)} af jer"] if n else []
    if provider:
        parts.append(f"+ {kit.fmt_int(provider)} i udbyderens spam-mappe")
    return " · ".join(parts)


def _account_card(r: dict) -> str:
    name = r["name"]
    state = r["state"]
    tone = kit.state_tone(state)
    lk = f"acct-{name}"
    detail = ""
    if state in PROBLEM_STATES and r["detail"]:
        detail = f'<div class="acct-detail tone-{tone}">{kit.icon("alert-circle")}<span>{h(r["detail"])}</span></div>'
    skips = []
    if r["today"]["skipped_seen"]:
        skips.append(_n(r["today"]["skipped_seen"], "allerede læst", "allerede læst"))
    if r["today"]["skipped_no_msgid"]:
        skips.append(_n(r["today"]["skipped_no_msgid"], "uden Message-ID", "uden Message-ID"))
    skip_html = (f'<div class="acct-skips" title="Beskeder filteret bevidst ikke scorede i dag">'
                 f'Sprunget over i dag: {h(", ".join(skips))}</div>') if skips else ""
    last = r["last_activity"]
    mode = r["mode"]
    return (
        f'<article class="card acct-card tone-{tone}{" is-paused" if not r["enabled"] else ""}" '
        f'id="acct-{h(name)}" data-href="{"/messages" if ui.can("see_messages") else "/spam"}?account={h(name)}">'
        f'<div class="acct-head">{_live_dot(state, lk + "-dot")}'
        f'<div class="acct-titles"><div class="acct-name">{kit.acct_name(r.get("label") or name, name)}</div>'
        f'<div class="acct-user">{h(r["user"])}</div></div>'
        f'{kit.chip(kit.mode_label(mode), kit.MODE_TONES.get(mode, "neutral"))}</div>'
        f'<div class="acct-stats">'
        f'<div class="acct-stat"><b data-live="{h(lk)}-scanned">{kit.fmt_int(r["today"]["scanned"])}</b><span>Scannet i dag</span></div>'
        f'<a class="acct-stat is-spam" href="/spam?account={h(name)}" title="Al spam i Spamfilter i dag – fanget af '
        f'filteret og flyttet af jer selv. Mail, som udbyderen selv lagde i sin spam-mappe (fx Junk), står '
        f'på linjen nedenunder"><b data-live="{h(lk)}-spam">{kit.fmt_int(r["today"]["spam"])}</b>'
        f'<span>Spam</span><small class="acct-stat-sub" data-live="{h(lk)}-spamuser">'
        f'{h(_spam_user_text(r["today"].get("spam_user", 0), r["today"].get("provider_spam", 0)))}</small></a>'
        f'<div class="acct-stat"><b data-live="{h(lk)}-released">{kit.fmt_int(r["today"]["released"])}</b><span>Frigivet</span></div>'
        f'</div>{detail}'
        f'<div class="acct-foot"><span class="row-tight">{kit.icon("sliders")}'
        f'{h(kit.sensitivity_label(r["threshold"]))} · grænse {h(kit.fmt_score(r["threshold"]))}</span>'
        f'<span class="row-tight">{kit.icon("activity")}<span data-live="{h(lk)}-state">{h(kit.state_label(state))}</span>'
        f' · <span data-live="{h(lk)}-ago">{h(kit.ago(last) if last else "ingen aktivitet endnu")}</span></span></div>'
        f"{skip_html}{ui_newsletters.card_line(ui.account_by_name(name))}</article>")


def _chart(selected: str) -> str:
    days = [kit.today_str(i) for i in range(13, -1, -1)]
    sc, params = _scope(selected)
    rows = ui.query(f"SELECT day, metric, SUM(n) AS n FROM stats_daily WHERE day >= ? "
                    f"AND metric IN ('scanned','spam_detected'){sc} GROUP BY day, metric",
                    [days[0], *params])
    by: dict[tuple[str, str], int] = {(r["day"], r["metric"]): int(r["n"] or 0) for r in rows}
    spam = [by.get((d, "spam_detected"), 0) for d in days]
    legit = [max(0, by.get((d, "scanned"), 0) - s) for d, s in zip(days, spam)]
    if not any(spam) and not any(legit):
        return kit.empty_state("Ingen data endnu", "Grafen fyldes ud, efterhånden som filteret scanner ny post.", "bar-chart")
    labels, tips = [], []
    for d, s, l in zip(days, spam, legit):
        dt = datetime.strptime(d, "%Y-%m-%d")
        labels.append(f"{dt.day}/{dt.month}")
        tips.append(f"{kit.DA_WEEKDAYS[dt.weekday()]} {dt.day}. {kit.DA_MONTHS[dt.month - 1]}: "
                    f"{_n(l, 'legitim', 'legitime')}, {kit.fmt_int(s)} spam")
    return kit.bar_chart([{"label": "Legitim", "values": legit, "tone": "brand"},
                          {"label": "Spam", "values": spam, "tone": "bad"}], labels, tips=tips)


def _attention_html(items: list[dict]) -> str:
    if not items:
        return ('<div class="attn-ok">' + kit.icon("check-circle")
                + "<div><b>Alt kører som det skal</b><span>Ingen fejl eller advarsler lige nu.</span></div></div>")
    lis = []
    for i in items[:6]:
        link = f'<a href="{h(i["href"])}">{h(i["link"])} →</a>' if i.get("href") else ""
        form = i.get("form") or ""  # pre-built, escaped HTML (e.g. 'Behold som kontakt')
        acts = f'<div class="attn-acts">{form}{link}</div>' if form else link
        lis.append(f'<li class="attn-item tone-{i["tone"]}">{kit.icon(i["icon"])}'
                   f'<div class="attn-body"><b>{h(i["title"])}</b><span>{h(i["text"])}</span>{acts}</div></li>')
    return '<ul class="attn-list">' + "".join(lis) + "</ul>"


def _recent_spam(selected: str, thresholds: dict, accounts: dict, limit: int = 4) -> str:
    sc, params = _scope(selected)
    q, qp = _in(CAUGHT_ACTIONS)
    rows = ui.query(f"SELECT *, {TS} AS ts FROM messages WHERE our_action IN {q} "
                    f"AND COALESCE(user_verdict,'') != 'ham' AND current_folder != 'gone'{sc} "
                    f"ORDER BY ts DESC LIMIT ?", [*qp, *params, limit])
    rules = RuleIndex()
    if not rows:
        return kit.empty_state("Ingen spam fanget endnu", "Når filteret fanger noget, dukker det op her – og du kan frigive det med ét klik.", "shield-check")
    return ('<ul class="mail-list view-overview" data-list>'
            + "".join(mail_row(r, thresholds, accounts, view="overview", show_account=not selected, rules=rules)
                      for r in rows)
            + "</ul>")


USER_PAGE_SIZE = 30
USER_SUMMARY_DAYS = 7


def _user_summary(selected: str) -> str:
    """'inge@molt.example · 3 mails fanget de sidste 7 dage' per mailbox."""
    rows = [r for r in ui.sidebar_accounts() if not selected or r["name"] == selected]
    if not rows:
        return ""
    since = int(time.time()) - USER_SUMMARY_DAYS * 86400
    sc, sp = _scope(selected)
    q, qp = _in(CAUGHT_ACTIONS)
    counts = {str(r["account"]): int(r["n"] or 0) for r in ui.query(
        f"SELECT account, COUNT(*) AS n FROM messages WHERE our_action IN {q} AND {TS} >= ?{sc} GROUP BY account",
        [*qp, since, *sp], default=[])}
    lines = []
    for r in rows:
        n = counts.get(r["name"], 0)
        state = r.get("state") or ""
        if state in ("paused_moves",):
            note, tone = "Flytningen holder pause – administratoren er informeret", "warn"
        elif state in ("auth_failed", "error", "config_error", "stale", "limited"):
            note, tone = "Filteret kan ikke nå postkassen lige nu – administratoren er informeret", "warn"
        elif n:
            note, tone = (f"{_n(n, 'mail', 'mails')} fanget de sidste {USER_SUMMARY_DAYS} dage", "ok")
        else:
            note, tone = f"Ingen spam de sidste {USER_SUMMARY_DAYS} dage", "ok"
        addr = r.get("user") or r.get("label") or r["name"]
        lines.append(f'<li class="tone-{tone}"><span class="dot tone-{tone}" aria-hidden="true"></span>'
                     f'<span class="sum-addr">{h(addr)}</span><span class="sum-note">{h(note)}</span></li>')
    return f'<ul class="home-summary">{"".join(lines)}</ul>'


def _user_spam_page(*, home: bool):
    """A Bruger's home and 'Min spam': a short friendly summary, 'Tjek
    disse' and the caught mail with big buttons. No scores, no KPIs."""
    selected = _selected()
    user = ui.current_user() or {}
    name = user.get("name", "")
    accounts = _accounts()
    if not accounts:
        body = kit.card(kit.empty_state("Ingen postkasse endnu", "Du har ikke adgang til nogen postkasser endnu. "
                                        "Bed administratoren om at give dig adgang.", "inbox"))
        return kit.render_page("Min spam", body, active="overview", subtitle=_hello(name))
    q = (request.args.get("q") or "").strip()[:200]
    page = _int_arg("page")
    sc, sp = _scope(selected)
    aq, ap = _in(CAUGHT_ACTIONS)
    where = (f" WHERE our_action IN {aq} AND COALESCE(user_verdict,'') != 'ham' AND current_folder != 'gone'"
             f" AND {TS} >= ?{sc}")
    params: list[Any] = [*ap, int(time.time()) - 30 * 86400, *sp]
    threat_only = threat_filter_on()
    if threat_only:
        tw, tp = threat_filter_sql()
        where += tw
        params += tp
    if q:
        where += " AND (sender LIKE ? ESCAPE '\\' OR subject LIKE ? ESCAPE '\\' OR envelope_from LIKE ? ESCAPE '\\')"
        params += [_like(q)] * 3
    row = ui.query(f"SELECT COUNT(*) FROM messages{where}", params, one=True)
    total = int(row[0]) if row else 0
    pages = max(1, math.ceil(total / USER_PAGE_SIZE))
    page = min(page, pages)
    rows = ui.query(f"SELECT *, {TS} AS ts FROM messages{where} ORDER BY ts DESC LIMIT ? OFFSET ?",
                    [*params, USER_PAGE_SIZE, (page - 1) * USER_PAGE_SIZE])
    new_since = _spam_new_since(name) if name else None
    n_new = sum(1 for r in rows if new_since is not None and r["ts"] and int(r["ts"]) > new_since)
    here = request.full_path.rstrip("?")
    show_account = not selected and len(accounts) > 1
    rules = RuleIndex()
    seen_btn = (kit.post_form("/spam/seen", kit.hidden("next", here)
                              + kit.button("Markér alle som gennemset", kind="ghost", icon="check", size="sm",
                                           short="Gennemset"), cls="inline-form") if n_new else "")
    search = (f'<form method="get" action="{"/" if home else "/spam"}" class="home-search" role="search">'
              + (kit.hidden("account", selected) if selected else "")
              + f'<label class="input-icon">{kit.icon("search")}'
              + kit.input_("q", q, type="search", attrs='aria-label="Søg i afsender og emne" '
                           'placeholder="Søg i afsender og emne" autocomplete="off" enterkeyhint="search"')
              + "</label></form>")
    if rows:
        head = (f'<div class="list-head home-list-head"><span>{_n(total, "mail", "mails")} de sidste 30 dage'
                + (f' · <span class="tone-brand-text">{_n(n_new, "ny", "nye")}</span>' if n_new else "")
                + f'</span><span class="spacer"></span>{seen_btn}</div>')
        listing = (head + '<ul class="mail-list simple-list-mails" data-list>'
                   + "".join(simple_row(r, accounts, view="spam", show_account=show_account, rules=rules,
                                        new_since=new_since) for r in rows) + "</ul>")
        pager = kit.pagination(page, pages, lambda p: ("/" if home else "/spam") + _qs(page=p if p > 1 else None))
        if pager:
            listing += f'<div class="list-foot">{pager}</div>'
    elif q:
        listing = kit.empty_state("Ingen spam matcher", "Prøv et andet ord – eller brug “Find en mail”, som også "
                                  "kigger direkte i postkassen.", "search")
    else:
        listing = kit.empty_state("Ingen spam her", "Alt er roligt. Når filteret fanger noget, ser du det her – "
                                  "og kan lægge det tilbage med ét tryk.", "shield-check")
    review = _review_section(selected, _thresholds(), new_since, here) if page == 1 and not q and not threat_only else ""
    if page == 1 and not q and not threat_only:
        review = _user_demoted_notice(selected) + review + _junk_notes(selected, here)
    if threat_only:
        listing = threat_filter_note("/" if home else "/spam") + listing
    links = []
    if ui.can("release"):
        links.append(f'<a class="home-link" href="{h(_find_href("", selected))}">{kit.icon("search")}'
                     "<span><b>Mangler du en mail?</b> Find den – også i udbyderens spam-mappe.</span>"
                     f'{kit.icon("chevron-right", "home-link-caret")}</a>')
        links.append(f'<a class="home-link" href="/undo{("?account=" + quote(selected, safe="")) if selected else ""}">'
                     f'{kit.icon("undo")}<span><b>Har filteret flyttet for meget?</b> Læg mails tilbage på én gang.</span>'
                     f'{kit.icon("chevron-right", "home-link-caret")}</a>')
    links.append(f'<a class="home-link" href="/help">{kit.icon("info")}'
                 "<span><b>Sådan virker det</b> Kort vejledning i spamfilteret.</span>"
                 f'{kit.icon("chevron-right", "home-link-caret")}</a>')
    body = (_welcome_card()
            + f'<section class="card home-hero">{_user_summary(selected)}</section>'
            + (threats_today_card(selected) if home and page == 1 and not q and not threat_only else "")
            + review
            + kit.card(f'<div class="card-pad home-list-top">{search}</div>{listing}', title="Fanget spam",
                       subtitle="Ligger i mappen Spamfilter. Intet bliver slettet.", cls="flush home-list")
            + f'<nav class="home-links" aria-label="Genveje">{"".join(links)}</nav>')
    return kit.render_page("Min spam", body, active="overview" if home else "spam", subtitle=_hello(name))


def _user_demoted_notice(selected: str) -> str:
    """A Bruger's calm version of the attention item (B13/B14)."""
    items = demoted_items(selected)
    if not items:
        return ""
    i = items[0]
    acts = (i.get("form") or "") + f'<a class="card-link" href="{h(i["href"])}">{h(i["link"])} →</a>'
    return (f'<section class="card demoted-card">{kit.icon("user-x")}<div class="demoted-body"><b>{h(i["title"])}</b>'
            f'<span>{h(i["text"])}</span><div class="attn-acts">{acts}</div></div></section>')


def _hello(name: str) -> str:
    hour = (datetime.now(kit.TZ) if kit.TZ else datetime.now()).hour
    part = ("God nat" if hour < 5 else "Godmorgen" if hour < 10 else "God formiddag" if hour < 12
            else "God eftermiddag" if hour < 18 else "God aften")
    return f"{part}{', ' + name if name else ''}."


# 2.3 follow-up: "Farlige mails stoppet i dag" (services.threats_today) and
# the matching filter on Fanget spam (?threat=today, Copenhagen day).
THREAT_FILTER = "today"


def threat_filter_on() -> bool:
    return request.args.get("threat") == THREAT_FILTER


def threat_filter_sql() -> tuple[str, list]:
    """Same day boundary and threat test as services.threats_today."""
    return " AND threat IS NOT NULL AND threat != '' AND scanned_at >= ?", [_local_midnight()]


def threat_filter_note(base: str) -> str:
    """The 'only today's dangerous mails' chip with a way back to all spam."""
    args = {k: v for k, v in request.args.items() if k not in ("threat", "page")}
    back = base + (("?" + urlencode(args)) if args else "")
    return (f'<div class="threat-filter" role="status">{kit.icon("alert-triangle")}'
            "<span>Viser kun farlige mails, der er stoppet i dag.</span>"
            f'<a class="card-link" href="{h(back)}">Vis al spam {kit.icon("arrow-right")}</a></div>')


def _threat_scope(selected: str) -> list[str] | None:
    """Mailboxes for threats_today: None (= all) only for an administrator
    looking at every mailbox; a Bruger always gets their own list ([] = none)."""
    if selected:
        return [selected]
    if ui.is_admin():
        return None
    return [a.name for a in ui.visible_accounts()]


def threats_today_card(selected: str) -> str:
    """Red Oversigt card 'Farlige mails stoppet i dag: N' - only when N > 0."""
    names = _threat_scope(selected)
    res = _threats_today(names)
    if not isinstance(res, dict):
        return ""
    total = int(res.get("total") or 0)
    in_inbox = int(res.get("in_inbox") or 0)
    if total <= 0 and in_inbox <= 0:
        return ""
    chips = "".join(kit.chip(f"{it.get('label') or 'Farlig mail'} {kit.fmt_int(it.get('n') or 0)}", "bad")
                    for it in (res.get("items") or [])[:4])
    notices = int(res.get("notices") or 0)
    one = total == 1
    where = ("Mailen ligger i Spamfilter-mappen – åbn den ikke" if one else
             "Mailene ligger i Spamfilter-mappen – åbn dem ikke")
    if notices:
        sub = f"{_n(notices, 'straks-advarsel', 'straks-advarsler')} er lagt i indbakken. {where}."
    else:
        sub = f"{where}, og klik ikke på links."
    # Overvåg/Markér or a failed move: the dangerous mail is still in the
    # inbox - never say "stoppet" about it.
    inbox_line = ""
    if in_inbox:
        inbox_line = (f'<p class="threat-today-inbox">{kit.icon("alert-circle")}<span>'
                      + (f"{kit.fmt_int(in_inbox)} farlig mail ligger stadig i indbakken – slet den uden at åbne den."
                         if in_inbox == 1 else
                         f"{kit.fmt_int(in_inbox)} farlige mails ligger stadig i indbakken – slet dem uden at åbne dem.")
                      + "</span></p>")
    args = {"threat": THREAT_FILTER, **({"account": selected} if selected else {})}
    href = "/spam?" + urlencode(args)
    if total > 0:
        title = (f'Farlige mails stoppet i dag: <span class="num">{kit.fmt_int(total)}</span>')
        text = f'<p class="threat-today-text">{h(sub)}</p>'
        btn = (f'<a class="btn btn-danger threat-today-btn" href="{h(href)}">Se dem'
               f'{kit.icon("arrow-right")}</a>')
    else:
        title = f'Farlige mails i indbakken i dag: <span class="num">{kit.fmt_int(in_inbox)}</span>'
        text, btn = "", ""
    return (f'<section class="threat-today" aria-label="Farlige mails i dag">'
            f'<div class="threat-today-ic">{kit.icon("alert-triangle")}</div>'
            f'<div class="threat-today-body"><h2 class="threat-today-title">{title}</h2>'
            f'{text}{inbox_line}'
            + (f'<div class="threat-today-chips">{chips}</div>' if chips else "")
            + f'</div>{btn}</section>')


def _threats_today(names: list[str] | None, days: int = 1) -> dict[str, Any] | None:
    """services.threats_today (one source for the red card and the strip)."""
    if days == 1:
        return _svc("threats_today", names, default=None)
    return _svc("threats_today", names, days=days, default=None)


@app.get("/")
@ui.login_required
def overview():
    if not ui.is_admin():
        return _user_spam_page(home=True)
    selected = _selected()
    period = request.args.get("period", "24h")
    seconds = 7 * 86400 if period == "7d" else 86400
    rows = _status_rows(selected)
    attention = _attention(rows, selected)
    thresholds, accounts = _thresholds(), _accounts()
    k = _kpis(selected, seconds)
    cur, prev = k["cur"], k["prev"]
    share = kit.fmt_pct(cur["spam"], cur["scanned"])
    review = len(review_items(selected))
    acct_q = f"?account={quote(selected, safe='')}" if selected else ""
    kpis = (
        '<div class="kpis kpis-honest">'
        + kit.kpi("Spam fanget", cur["spam"],
                  sub=(f"{share} af {kit.fmt_int(cur['scanned'])} nye mails" if cur["scanned"] else "ingen post endnu"),
                  trend=_trend(cur["spam"], prev["spam"]), tone="bad" if cur["spam"] else "")
        + kit.kpi("Sluppet igennem", cur["missed"], sub="spam, du selv måtte flytte",
                  tone="warn" if cur["missed"] else "ok")
        + kit.kpi("Frigivet", cur["released"], sub="var ikke spam alligevel", tone="warn" if cur["released"] else "ok")
        + kit.kpi("Tjek disse", review, sub="måske ikke spam" if review else "intet at tjekke",
                  tone="info" if review else "", href=f"/spam{acct_q}#tjek")
        + "</div>" + protection_strip(selected, 7 if period == "7d" else 1))
    period_ctl = kit.seg_links([("24 t", _qs(period=None) or "?", period != "7d"),
                                ("7 dage", _qs(period="7d"), period == "7d")])
    title_suffix = f" · {selected}" if selected else ""
    bayes = ('<div data-fragment="/fragments/bayes" aria-busy="true">'
             + kit.skeleton(2, cls="skeleton-rings") + "</div>"
             '<noscript><p class="muted"><a class="card-link" href="/fragments/bayes">Vis Bayes-status</a></p></noscript>')
    accounts_html = "".join(_account_card(r) for r in rows)
    body = (
        _welcome_card()
        + _hero(rows, attention)
        + threats_today_card(selected)
        + kit.card(kpis, title="Nøgletal", subtitle=("De seneste 7 dage" if period == "7d" else "De seneste 24 timer")
                   + " sammenlignet med perioden før", actions=period_ctl)
        # Left: chart + latest spam; right: attention + Bayes. Two balanced
        # columns avoid the empty gap a lone chart left next to the taller
        # side stack. On narrow screens the stacks dissolve (display:
        # contents) and the ord-* classes put "Kræver opmærksomhed" first.
        + '<div class="grid grid-main ov-grid"><div class="stack">'
        + kit.card(_chart(selected), title="Post de seneste 14 dage", subtitle="Legitim post og spam pr. dag",
                   cls="ord-2")
        + kit.card(_recent_spam(selected, thresholds, accounts), title="Seneste fanget spam",
                   actions=f'<a class="card-link" href="/spam{_qs(period=None)}">Se alt {kit.icon("arrow-right")}</a>',
                   cls="flush ord-4")
        + '</div><div class="stack">'
        + kit.card(_attention_html(attention), title="Kræver opmærksomhed",
                   actions=(kit.badge(str(len(attention)), "bad" if any(a["tone"] == "bad" for a in attention) else "warn")
                            if attention else ""), cls="ord-1")
        + kit.card(bayes, title="Filterets hukommelse", subtitle="Bayes-træning (fælles for alle konti)", cls="ord-3")
        + "</div></div>"
        + (f'<section class="section"><div class="section-head"><h2 class="section-title">Postkasser</h2>'
           f'<span class="muted">{_n(len(rows), "konto", "konti")}</span></div>'
           f'<div class="grid grid-auto">{accounts_html}</div></section>' if rows else "")
    )
    return kit.render_page("Oversigt" + title_suffix, body, active="overview",
                           subtitle=_greeting())


def _local_midnight() -> int:
    now = datetime.now(kit.TZ) if kit.TZ else datetime.now()
    return int(now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())


CONTACT_TRUST_METRICS = ("known_contact", "reply_detected", "established")


def protection_today(selected: str = "", days: int = 1) -> dict[str, Any]:
    """2.3 extra protection for the visible mailboxes in the last `days`
    calendar days (1 = today; the Nøgletal period): known contacts (B13),
    rescans (B19) and threats by class (B16)."""
    days = 7 if days == 7 else 1
    sc, sp = _scope(selected)
    stats = _stat_sum(("zapped", "threat_detected", *CONTACT_TRUST_METRICS), days, selected)
    if days == 1:
        names = [selected] if selected else [a.name for a in ui.visible_accounts()]
        trust_total = int((_svc("trust_counts_today", names, default=None) or {}).get("total") or 0)
    else:
        trust_total = sum(int(stats.get(m, 0)) for m in CONTACT_TRUST_METRICS)
    # Dangerous mails: the same source and rules as the red card
    # (services.threats_today: really out of the inbox, by scan day).
    res = _threats_today(_threat_scope(selected), days)
    if isinstance(res, dict):
        threats = int(res.get("total") or 0)
        parts = [f"{it.get('label') or 'Farlig mail'} {kit.fmt_int(it.get('n') or 0)}"
                 for it in sorted(res.get("items") or [], key=lambda it: -int(it.get("n") or 0))]
    else:  # older services: the 2.3.0 count
        since = _local_midnight() - (days - 1) * 86400
        by_class = {str(r["threat"]): int(r["n"] or 0) for r in ui.query(
            f"SELECT threat, COUNT(*) AS n FROM messages WHERE threat IS NOT NULL AND threat != '' "
            f"AND first_seen >= ?{sc} GROUP BY threat", [since, *sp], default=[])}
        threats = max(sum(by_class.values()), int(stats.get("threat_detected", 0)))
        parts = [f"{_svc('threat_text', cls, None, default=cls) or cls} {kit.fmt_int(n)}"
                 for cls, n in sorted(by_class.items(), key=lambda kv: -kv[1])]
    return {"trust": trust_total, "zapped": int(stats.get("zapped", 0)), "threats": threats,
            "threat_parts": parts}


def protection_strip(selected: str = "", days: int = 1) -> str:
    """Follows the Nøgletal period ('i dag' / 'de seneste 7 dage')."""
    p = protection_today(selected, days)
    when = "i dag" if days != 7 else "de seneste 7 dage"

    def mini(tone: str, ic: str, label: str, n: int, sub: str = "", href: str = "") -> str:
        tag = f'a href="{h(href)}"' if href else "div"
        end = "a" if href else "div"
        return (f'<{tag} class="prot-item tone-{tone if n else "neutral"}">{kit.icon(ic)}'
                f'<span class="prot-text"><span class="prot-label">{h(label)}:</span> <b class="num">{kit.fmt_int(n)}</b>'
                + (f'<small>{h(sub)}</small>' if sub else "") + f"</span></{end}>")

    items = [mini("ok", "user-check", f"Beskyttet af kendte kontakter {when}", p["trust"]),
             mini("info", "radar", f"Flyttet efterfølgende {when}", p["zapped"],
                  "fanget ved genscanning" if p["zapped"] else "")]
    # Today with any stopped: the red card above already says it - not twice.
    if days == 7 or not p["threats"]:
        items.append(mini("bad", "alert-triangle", f"Farlige mails stoppet {when}", p["threats"],
                          " · ".join(p["threat_parts"][:3])))
    cls = "prot-strip" + (" prot-2" if len(items) == 2 else "")
    return f'<div class="{cls}" aria-label="Ekstra beskyttelse {when}">' + "".join(items) + "</div>"


def _greeting() -> str:
    hour = (datetime.now(kit.TZ) if kit.TZ else datetime.now()).hour
    part = ("God nat" if hour < 5 else "Godmorgen" if hour < 10 else "God formiddag" if hour < 12
            else "God eftermiddag" if hour < 18 else "God aften")
    name = (ui.current_user() or {}).get("name", "")
    return f"{part}{', ' + name if name else ''}. Her er status for dit spamfilter."


@app.get("/fragments/bayes")
@ui.login_required
def bayes_fragment():
    try:
        st = ui.services.bayes_stats() or {}
    except Exception as ex:  # noqa: BLE001 - rspamd down must not break Oversigt
        log.warning("bayes_stats failed: %s", type(ex).__name__)
        st = {"ok": False}
    if not st.get("ok"):
        html = kit.empty_state("rspamd svarer ikke", "Bayes-status kan ikke hentes lige nu. Scanning fortsætter, når rspamd er tilbage.", "database")
    else:
        need = int(st.get("min_learns") or 200)
        spam, ham = int(st.get("spam_learned") or 0), int(st.get("ham_learned") or 0)
        ready = spam >= need and ham >= need
        note = ("Bayes er aktiv og bruges i alle scorer." if ready else
                f"Bayes tæller først med, når der er lært mindst {kit.fmt_int(need)} spam og {kit.fmt_int(need)} legitime beskeder.")
        link = ('<a class="card-link" href="/training">Træn filteret ' + kit.icon("arrow-right") + "</a>"
                if (ui.current_user() or {}).get("is_admin") and not ready else "")
        # 2.3 follow-up: the active Bayes pool (after 'Byg Bayes op på ny') and
        # an honest note when only the sum over all pools is known.
        pool = str(st.get("pool") or "") if ui.is_admin() else ""
        extra = (f'<p class="bayes-pool">{kit.icon("database")}<span>Aktiv pulje: '
                 f'<span class="mono">{h(pool)}</span></span></p>' if pool else "")
        if st.get("counts_source") == "all_pools":
            extra += ('<p class="faint small bayes-pool-sum">Tallene er summen af alle Bayes-puljer – tallet for den '
                      "aktive pulje kendes ikke.</p>")
        html = (f'<div class="bayes-rings">{kit.ring(spam, need, label="Spam lært")}'
                f'{kit.ring(ham, need, label="Legitim lært")}</div>'
                f'<p class="bayes-note">{h(note)}</p>{extra}'
                + (f'<div class="bayes-link">{link}</div>' if link else ""))
    if request.headers.get("Accept", "").startswith("text/html") and request.headers.get("Sec-Fetch-Mode") == "navigate":
        return kit.render_page("Filterets hukommelse", kit.card(html), active="overview")
    return html


# ---------------------------------------------------------------------------
# Fanget spam
# ---------------------------------------------------------------------------


def _filters_form(fields: str, *, hidden_args: dict[str, str] | None = None) -> str:
    hid = "".join(kit.hidden(k, v) for k, v in (hidden_args or {}).items() if v)
    return (f'<form method="get" class="filters" data-autosubmit role="search">{hid}{fields}'
            f'{kit.button("Filtrér", kind="secondary", icon="filter", cls="filters-submit")}</form>')


def _search_input(q: str, placeholder: str) -> str:
    return (f'<label class="input-icon">{kit.icon("search")}<span class="sr-only">Søg</span>'
            + kit.input_("q", q, type="search", attrs=f'placeholder="{h(placeholder)}" data-search-shortcut autocomplete="off"')
            + "</label>")


def _account_select(selected: str, accounts: dict[str, Any]) -> str:
    if len(accounts) <= 1:
        return ""
    opts = [("", "Alle konti")] + [(n, ui.account_label(n)) for n in accounts]
    return kit.select("account", opts, selected, attrs='aria-label="Konto"')


@app.get("/spam")
@ui.login_required
def spam_page():
    if not ui.is_admin():
        return _user_spam_page(home=False)
    selected = _selected()
    accounts, thresholds = _accounts(), _thresholds()
    period = request.args.get("period", "30d")
    if period not in {p[0] for p in PERIODS}:
        period = "30d"
    source = request.args.get("source", "all")
    if source not in {s[0] for s in SOURCES}:
        source = "all"
    q = (request.args.get("q") or "").strip()[:200]
    page = _int_arg("page")

    sc, sp = _scope(selected)
    where = f" WHERE COALESCE(user_verdict,'') != 'ham' AND current_folder != 'gone'{sc}"
    params: list[Any] = list(sp)
    secs = dict((p[0], p[2]) for p in PERIODS)[period]
    threat_only = threat_filter_on()
    if threat_only:
        tw, tp = threat_filter_sql()   # replaces the period: exactly "today"
        where += tw
        params += tp
    elif secs:
        where += f" AND {TS} >= ?"
        params.append(int(time.time()) - secs)
    if q:
        where += " AND (sender LIKE ? ESCAPE '\\' OR subject LIKE ? ESCAPE '\\' OR envelope_from LIKE ? ESCAPE '\\')"
        params += [_like(q)] * 3

    # Counts per source for the tabs.
    counts = {}
    for key, _label, actions in SOURCES:
        aq, ap = _in(actions)
        row = ui.query(f"SELECT COUNT(*) FROM messages{where} AND our_action IN {aq}", [*params, *ap], one=True)
        counts[key] = int(row[0]) if row else 0
    actions = dict((s[0], s[2]) for s in SOURCES)[source]
    aq, ap = _in(actions)
    total = counts[source]
    pages = max(1, math.ceil(total / PAGE_SIZE))
    page = min(page, pages)
    rows = ui.query(f"SELECT *, {TS} AS ts FROM messages{where} AND our_action IN {aq} "
                    f"ORDER BY ts DESC LIMIT ? OFFSET ?", [*params, *ap, PAGE_SIZE, (page - 1) * PAGE_SIZE])

    tabs = kit.tabs([(label, "/spam" + _qs(source=None if key == "all" else key, page=None), key == source, counts[key])
                     for key, label, _a in SOURCES])
    filters = _filters_form(
        _search_input(q, "Søg i afsender og emne")
        + _account_select(selected, accounts)
        + ("" if threat_only else
           kit.select("period", [(p[0], p[1]) for p in PERIODS], period, attrs='aria-label="Periode"')),
        hidden_args={"source": source if source != "all" else "", "threat": THREAT_FILTER if threat_only else ""})
    next_url = "/spam" + _qs()
    rules = RuleIndex()
    me = (ui.current_user() or {}).get("name", "")
    new_since = _spam_new_since(me) if me else None
    n_new = sum(1 for r in rows if new_since is not None and r["ts"] and int(r["ts"]) > new_since)
    seen_btn = (kit.post_form("/spam/seen", kit.hidden("next", next_url)
                              + kit.button("Markér alle som gennemset", kind="ghost", icon="check", size="sm",
                                           short="Gennemset"), cls="inline-form")
                if n_new else "")
    if rows:
        new_txt = f' · <span class="tone-brand-text">{_n(n_new, "ny", "nye")}</span>' if n_new else ""
        listing = (_list_head("spam", f"{_n(total, 'besked', 'beskeder')}"
                              + (f" · side {page} af {pages}" if pages > 1 else "") + new_txt,
                              seen_btn, select=ui.can("release"))
                   + '<ul class="mail-list selectable" data-list>'
                   + "".join(mail_row(r, thresholds, accounts, view="spam", selectable=True,
                                      show_account=not selected, rules=rules, new_since=new_since) for r in rows)
                   + "</ul>")
        pager = kit.pagination(page, pages, lambda p: "/spam" + _qs(page=p if p > 1 else None))
        if pager:
            listing += f'<div class="list-foot">{pager}</div>'
    elif q or source != "all" or period != "all" or threat_only:
        listing = kit.empty_state("Ingen spam matcher", "Prøv en anden periode, kilde eller søgning. Leder du efter "
                                  "en bestemt mail, kan “Find en mail” også søge direkte i postkassen.", "search",
                                  kit.button("Nulstil filtre", href="/spam" + (f"?account={h(selected)}" if selected else ""),
                                             kind="secondary", icon="refresh")
                                  + kit.button("Find en mail", href=_find_href(q, selected), kind="primary", icon="search"))
    else:
        listing = kit.empty_state("Ingen spam her", "Når filteret eller din udbyder fanger noget, dukker det op her. "
                                  "Du kan frigive det med ét klik.", "shield-check",
                                  kit.button("Mangler du en mail? Find den", href=_find_href("", selected),
                                             kind="secondary", icon="search"))
    bulk = _bulk_form("spam", (
        kit.button("Frigiv", kind="primary", icon="undo", size="sm", attrs='name="action" value="release"')
        + (kit.button("Frigiv og tillad afsender", kind="secondary", icon="check-circle", size="sm",
                      attrs='name="action" value="release_allow"') if ui.can("rules") else "")
        + kit.button("Bekræft som spam", kind="ghost", icon="graduation-cap", size="sm",
                     attrs='name="action" value="learn_spam"')), next_url) if rows and ui.can("release") else ""
    review = ""
    if page == 1 and not q and source in ("all", "filter") and not threat_only:
        review = _review_section(selected, thresholds, new_since, next_url) + _junk_notes(selected, next_url)
    note = threat_filter_note("/spam") if threat_only else ""
    body = (review + kit.card(f'<div class="card-pad">{tabs}<div class="mt-2">{filters}</div>{note}</div>{listing}',
                              cls="flush")
            + bulk)
    return kit.render_page("Fanget spam", body, active="spam",
                           subtitle="Alt, som filteret og udbyderne har sorteret fra. Frigiv det, der ikke er spam – filteret lærer af det.",
                           actions_html=kit.button("Fortryd flytninger", href="/undo" + (f"?account={quote(selected, safe='')}"
                                                                                       if selected else ""),
                                                   kind="secondary", icon="undo", size="sm")
                           + kit.button("Find en mail", href=_find_href(q, selected), kind="secondary",
                                        icon="search", size="sm"))


def _find_href(q: str, selected: str) -> str:
    args = {k: v for k, v in (("account", selected), ("q", q)) if v}
    return "/find" + (("?" + urlencode(args)) if args else "")


# ---------------------------------------------------------------------------
# Beskeder
# ---------------------------------------------------------------------------


@app.get("/messages")
@ui.permission_required("see_messages")
def messages_page():
    selected = _selected()
    accounts, thresholds = _accounts(), _thresholds()
    result = request.args.get("result", "")
    if result not in {r[0] for r in RESULTS}:
        result = ""
    band = request.args.get("band", "")
    if band not in {b[0] for b in BANDS}:
        band = ""
    q = (request.args.get("q") or "").strip()[:200]
    page = _int_arg("page")

    sc, sp = _scope(selected)
    where = f" WHERE (our_score IS NOT NULL OR our_action IS NOT NULL){sc}"
    params: list[Any] = list(sp)
    acts = dict((r[0], r[2]) for r in RESULTS)[result]
    if acts:
        aq, ap = _in(acts)
        where += f" AND our_action IN {aq}"
        params += ap
    if band:
        thr, tp = _thr_expr(thresholds)
        cond = {"over": f"our_score >= {thr}",
                "near": f"our_score < {thr} AND our_score >= {thr} - 3",
                "low": f"our_score >= 0 AND our_score < {thr} - 3",
                "neg": "our_score < 0"}[band]
        n_thr = cond.count(thr)
        where += f" AND our_score IS NOT NULL AND {cond}"
        params += tp * n_thr
    if q:
        where += (" AND (sender LIKE ? ESCAPE '\\' OR subject LIKE ? ESCAPE '\\' "
                  "OR envelope_from LIKE ? ESCAPE '\\' OR message_id LIKE ? ESCAPE '\\')")
        params += [_like(q)] * 4
    row = ui.query(f"SELECT COUNT(*) FROM messages{where}", params, one=True)
    total = int(row[0]) if row else 0
    pages = max(1, math.ceil(total / PAGE_SIZE))
    page = min(page, pages)
    rows = ui.query(f"SELECT *, {TS} AS ts FROM messages{where} ORDER BY ts DESC LIMIT ? OFFSET ?",
                    [*params, PAGE_SIZE, (page - 1) * PAGE_SIZE])

    filters = _filters_form(
        _search_input(q, "Søg i afsender, emne eller Message-ID")
        + _account_select(selected, accounts)
        + kit.select("result", [(r[0], r[1]) for r in RESULTS], result, attrs='aria-label="Resultat"')
        + kit.select("band", list(BANDS), band, attrs='aria-label="Score i forhold til grænsen"'))
    next_url = "/messages" + _qs()
    rules = RuleIndex()
    if rows:
        listing = (_list_head("messages", _n(total, "besked", "beskeder")
                              + (f" · side {page} af {pages}" if pages > 1 else ""),
                              '<span class="faint">Score farves i forhold til kontoens grænse</span>',
                              select=ui.can("release"))
                   + '<ul class="mail-list selectable view-messages" data-list>'
                   + "".join(mail_row(r, thresholds, accounts, view="messages", selectable=True,
                                      show_account=not selected, rules=rules) for r in rows)
                   + "</ul>")
        pager = kit.pagination(page, pages, lambda p: "/messages" + _qs(page=p if p > 1 else None))
        if pager:
            listing += f'<div class="list-foot">{pager}</div>'
    elif q or result or band:
        listing = kit.empty_state("Ingen beskeder matcher", "Prøv at fjerne et filter eller søge efter noget andet. "
                                  "Filteret kender kun mail, det selv har scannet – “Find en mail” kan også søge i "
                                  "postkassens mapper.", "search",
                                  kit.button("Nulstil filtre", href="/messages" + (f"?account={h(selected)}" if selected else ""),
                                             kind="secondary", icon="refresh")
                                  + kit.button("Find en mail", href=_find_href(q, selected), kind="primary", icon="search"))
    else:
        listing = kit.empty_state("Ingen beskeder endnu", "Filteret har ikke scannet nogen post endnu. Ny post dukker op her, så snart den ankommer.", "mails")
    bulk = _bulk_form("messages", (
        kit.button("Flyt til spam", kind="danger", icon="shield-alert", size="sm",
                   attrs='name="action" value="mark_spam" ' + kit.confirm_attrs(
                       "Flyt de valgte til spam?", "Beskederne flyttes til Spamfilter-mappen, og filteret lærer, at de er spam.",
                       confirm="Flyt til spam", tone="danger"))
        + kit.button("Lær som legitim", kind="secondary", icon="check-circle", size="sm",
                     attrs='name="action" value="learn_ham"')
        + kit.button("Lær som spam", kind="ghost", icon="graduation-cap", size="sm",
                     attrs='name="action" value="learn_spam"')), next_url) if rows and ui.can("release") else ""
    body = kit.card(f'<div class="card-pad">{filters}</div>{listing}', cls="flush") + bulk
    return kit.render_page("Beskeder", body, active="messages",
                           subtitle="Al post, filteret har scoret. Klik på en besked for at se præcis hvorfor.")


# ---------------------------------------------------------------------------
# Besked-detalje
# ---------------------------------------------------------------------------


# Trust symbols whose options carry counts/dates/masks (administrators only).
TRUST_COUNT_SYMBOLS = frozenset({"TH_KNOWN_CONTACT", "TH_KNOWN_DOMAIN", "TH_REPLY", "TH_REPLY_THREAD",
                                 "TH_REPLY_UNVERIFIED", "TH_ESTABLISHED", "TH_FIRST_CONTACT"})


def _symbol_table(symbols: list[dict], *, sender: Any = None) -> str:
    if not symbols:
        return kit.empty_state("Ingen regler registreret", "Beskeden blev scoret uden detaljer – typisk post fra før version 2.0.", "list-checks")
    top = max((abs(s["s"]) for s in symbols), default=1.0) or 1.0
    rows = []
    numbers = trust_numbers()
    for s in sorted(symbols, key=lambda x: abs(x["s"]), reverse=True):
        sign = "pos" if s["s"] > 0.0049 else "neg" if s["s"] < -0.0049 else "zero"
        opts = kit.clean_name(", ".join(str(o) for o in s["o"]))  # 2.3: no bidi tricks (RTLO) from options
        text = kit.explain_symbol_detail(s, symbols=symbols, sender=sender, ai_reason=numbers)
        if not numbers and s["n"] in TRUST_COUNT_SYMBOLS:
            # B13: Brugere see trust signals without counts, dates or masks.
            text, opts = kit.SYMBOL_TEXT.get(s["n"], text), ""
        elif not numbers and s["n"] == "TH_AI_SPAM":
            opts = ""  # 2.7 fix: the model's free-text reason is for administrators only
        name_cell = (f'<div class="sym-name"><b>{h(text)}</b><code>{h(s["n"])}</code>'
                     + (f'<span class="sym-opts">{h(opts)}</span>' if opts else "") + "</div>")
        score_cell = (f'<span class="sym-score is-{sign}">{"+" if sign == "pos" else ""}{kit.fmt_score(s["s"])}</span>'
                      f'<div class="sym-bar is-{sign}"><span class="{kit.pct_class(abs(s["s"]), top)}"></span></div>')
        rows.append([name_cell, score_cell])
    return kit.table([("Regel", ""), ("Point", "end")], rows, cls="sym-table")


FREEMAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "hotmail.com", "hotmail.dk", "outlook.com", "outlook.dk", "live.com",
    "live.dk", "msn.com", "yahoo.com", "yahoo.dk", "ymail.com", "icloud.com", "me.com", "mac.com",
    "aol.com", "gmx.com", "gmx.net", "gmx.de", "mail.dk", "jubii.dk", "ofir.dk", "sol.dk", "post.tele.dk",
    "webspeed.dk", "privat.dk", "protonmail.com", "proton.me", "mail.com", "yandex.com", "zoho.com",
    # 2.3 rules dialog: more shared mail services (whole domain never offered)
    "email.dk", "tdcadsl.dk", "mail.tele.dk", "stofanet.dk", "youmail.dk", "get2net.dk", "godmail.dk",
    "rocketmail.com", "pm.me", "protonmail.ch", "tutanota.com", "tuta.io",
    "fastmail.com", "hey.com", "web.de", "t-online.de", "mail.ru", "yandex.ru", "qq.com", "163.com",
    "zohomail.com", "inbox.com", "online.no", "telia.com"})
# hotmail.*, outlook.*, live.*, yahoo.*, gmx.*, aol.* incl. country forms
# (hotmail.co.uk, yahoo.com.au) - but not live.nation.example.
_FREEMAIL_FAMILY_RE = re.compile(r"(?:hotmail|outlook|live|yahoo|gmx|aol)\.[a-z]{2,3}(?:\.[a-z]{2})?")


def _is_freemail(domain: str) -> bool:
    d = str(domain or "").lower().strip().lstrip("@").rstrip(".")
    return d in FREEMAIL_DOMAINS or bool(_FREEMAIL_FAMILY_RE.fullmatch(d))


RSPAMD_ACTIONS = {"no action": "ingen handling", "add header": "mærk som spam",
                  "rewrite subject": "mærk emnet", "reject": "afvis", "soft reject": "udskyd",
                  "greylist": "gråliste"}

_DETAIL_PHRASES = {
    "confirmed by junk poll": "bekræftet ved kontrol af Spamfilter-mappen",
    "from inbox": "fra indbakken",
    "from junk": "fra spam-mappen",
}


# 2.2 (B6c) ham guard codes, as filter.HAM_GUARD_TEXT (kept here so the
# web UI never imports the engine).
HAM_GUARD_TEXT = {
    "blind_score": "scoren uden Bayes og udbyder er 5 eller mere",
    "phishing": "phishing- eller trusselsregel ramte",
    "blocked_sender": "afsenderen er blokeret",
    "trust_only": "kun under grænsen pga. egne bonusser",
}
_HAM_GUARD_RE = re.compile(r"^(autolearn|job=(\d+)) ([a-z_]+): ?(.*)$")


def _human_detail(detail: str) -> str:
    """Engine event details are short technical English (`score=12.40`,
    `uid=5 -> Spamfilter`, `metode=UIDPLUS`, `bootstrap job=3`). Show the
    useful part in Danish and drop bare IMAP UIDs (meaningless to users)."""
    d = detail.strip()
    if not d:
        return ""
    m = _HAM_GUARD_RE.match(d)
    if m and m.group(3) in HAM_GUARD_TEXT:
        who = "Automatisk læring" if m.group(1) == "autolearn" else f"Træningsjob #{m.group(2)}"
        rest = f" ({m.group(4)[:120]})" if m.group(4) else ""
        return f"{who}: {HAM_GUARD_TEXT[m.group(3)]}{rest}"
    if d in _DETAIL_PHRASES:
        text = _DETAIL_PHRASES[d]
        return text[:1].upper() + text[1:]
    out = []
    for part in d.split():
        key, eq, val = part.partition("=")
        if not eq:
            out.append({"from": "fra", "to": "til", "aged": "(sen scanning)"}.get(part, part))
        elif key == "uid":
            continue
        elif key == "score":
            try:
                out.append(f"score {kit.fmt_score(float(val))}")
            except ValueError:
                out.append(part)
        elif key in ("metode", "method", "move"):
            out.append(f"metode {val}")
        elif key == "job":
            out.append(f"træningsjob #{val}")
        else:
            out.append(part)
    text = " ".join(out).replace("bootstrap ", "").replace("-> ", "til ").strip()
    return text[:1].upper() + text[1:] if text else ""


def _timeline(account: str, mid: str, r: Any) -> str:
    events = ui.query("SELECT ts, event, detail FROM events WHERE account=? AND message_id=? "
                      "ORDER BY ts DESC, id DESC LIMIT 60", [account, mid])
    items = []
    for e in events:
        label, ic, tone = EVENT_INFO.get(e["event"], (str(e["event"]).replace("_", " ").capitalize(), "info", "neutral"))
        if e["event"] in ZAP_EVENTS:
            # 'Ny viden efter 3 timer: Linkdomæne på Spamhaus' spamliste' (B19)
            detail = zap_plain_text(str(e["detail"] or ""))
        elif e["event"] == "threat_detected":
            detail = _threat_event_text(str(e["detail"] or ""))
        elif e["event"] in ui_campaigns.CAMPAIGN_EVENTS:
            detail = ui_campaigns.event_detail(str(e["detail"] or ""))  # 2.6: 'Samme spam som i <postkasse>'
        else:
            detail = _human_detail(str(e["detail"] or ""))
        items.append((int(e["ts"] or 0), label, ic, tone, detail))
    if r["received_at"]:
        items.append((int(r["received_at"]), "Modtaget på mailserveren", "inbox", "neutral", ""))
    if not events and _rget(r, "scanned_at"):
        items.append((int(r["scanned_at"]), "Scannet af rspamd", "activity", "info", ""))
    if _rget(r, "verdict_at") and not any(i[1].startswith(("Frigivet", "Flyttet til spam fra")) for i in items):
        v = r["user_verdict"]
        items.append((int(r["verdict_at"]), "Markeret som legitim" if v == "ham" else "Markeret som spam",
                      "user", "ok" if v == "ham" else "bad", f"af {r['verdict_by']}" if r["verdict_by"] else ""))
    items.sort(key=lambda i: i[0], reverse=True)
    if not items:
        return '<p class="muted">Ingen hændelser registreret for denne besked.</p>'
    lis = "".join(
        f'<li class="tl-item tone-{tone}"><span class="tl-icon">{kit.icon(ic)}</span>'
        f'<div><div class="tl-title">{h(label)}</div>'
        + (f'<div class="tl-detail">{h(detail)}</div>' if detail else "")
        + f'</div><time class="tl-time" datetime="{kit.iso_ts(ts)}">{h(kit.fmt_ts(ts))}</time></li>'
        for ts, label, ic, tone, detail in items)
    return f'<ol class="timeline">{lis}</ol>'


AGED_CHIP = "Scannet sent – udbyderens godkendelse brugt"


def is_aged(r: Any, symbols: list[dict] | None = None) -> bool:
    """2.2 (B7): the mail was scanned in aged mode (messages.aged, or the
    TH_AGED_SCAN pseudo-symbol for rows without the column)."""
    if int(_rget(r, "aged", 0) or 0) == 1:
        return True
    return any(s.get("n") == "TH_AGED_SCAN" for s in (symbols or []))


def _aged_note(symbols: list[dict]) -> str:
    names = {s["n"]: s for s in symbols}
    age = ""
    m = re.search(r"alder=(\d+)t", " ".join((names.get("TH_AGED_SCAN") or {}).get("o") or []))
    if m:
        hours = int(m.group(1))
        age = f" ({hours} timer efter modtagelsen)" if hours < 48 else f" ({hours // 24} dage efter modtagelsen)"
    if "TH_PROVIDER_AUTH_FAIL" in names:
        provider = "Udbyderen kunne ikke bekræfte afsenderen ved modtagelsen (DMARC) – det tæller imod mailen."
    elif "TH_PROVIDER_AUTH_SPOOF" in names:
        provider = ("Udbyderens SPF- eller DMARC-tjek fejlede ved modtagelsen – derfor gælder en "
                    "tilladelse for afsenderen ikke for denne mail.")
    elif "TH_PROVIDER_AUTH_PASS" in names:
        provider = "Udbyderen bekræftede afsenderen ved modtagelsen – det tæller lidt til fordel for mailen."
    else:
        provider = "Udbyderen havde ingen godkendelse at give videre, så SPF og DMARC tæller ikke med."
    return (f'<div class="aged-note">{kit.icon("clock")}<div><b>{h(AGED_CHIP)}</b>'
            f'<span>Mailen blev scannet sent{h(age)}. Så længe efter kan afsenderens SPF og DMARC ikke '
            f'kontrolleres pålideligt, så filteret brugte udbyderens godkendelse fra modtagelsen i stedet. '
            f'{h(provider)}</span></div></div>')


def _threat_event_text(detail: str) -> str:
    """'attachment: faktura.pdf.exe (genscanning)' -> 'Farlig vedhæftning:
    faktura.pdf.exe (fundet ved genscanning)'."""
    raw = kit.clean_name(detail)
    cls, _sep, rest = raw.partition(": ")
    later = rest.endswith("(genscanning)")
    rest = rest.removesuffix("(genscanning)").strip()
    text = str(_svc("threat_text", cls, None if rest in ("", "-") else rest, default="") or raw)
    return kit.short_filename(text, 120) + (" (fundet ved genscanning)" if later else "")


def _threat_banner(threat_txt: str, tinfo: dict) -> str:
    """B16: a red, unmissable line at the top of Vurdering."""
    if not threat_txt:
        return ""
    if ui.is_admin():
        text = (f"{tinfo.get('confirm_text') or 'Mailen er markeret som farlig.'} Den flyttes altid til "
                "Spamfilter-mappen – uanset score, regler og kendte kontakter – og læres aldrig som legitim.")
    else:
        # The Handlinger box says what to do; the banner only what it is.
        text = "Den flyttes altid til Spamfilter-mappen og bliver liggende der."
    label, sep, det = kit.clean_name(threat_txt).partition(": ")
    title = f"{label}: {kit.short_filename(det, 44)}" if sep else label
    return (f'<div class="threat-banner">{kit.icon("alert-triangle")}<div><b>{h(title[:200])}</b>'
            f'<span>{h(kit.clean_name(text)[:400])}</span></div></div>')


def _trust_row(labels: list[dict]) -> str:
    """B13: the reasons the filter trusts (or doubts) the sender."""
    if not labels:
        return ""
    return ('<div class="trust-row" aria-label="Afsenderen">'
            + "".join(kit.trust_badge(x) for x in labels) + "</div>")


def _zap_note(r: Any, tinfo: dict) -> str:
    """B19: 'Fanget ved genscanning' + 'Ny viden: DBL_SPAM kom til efter 3 t'."""
    if not _rget(r, "zapped_at"):
        return ""
    lines = [zap_plain_text(str(t.get("detail") or "")) if t.get("detail") is not None else str(t.get("text") or "")
             for t in (tinfo.get("timeline") or []) if isinstance(t, dict)]
    lines = [x for x in lines if x.startswith("Ny viden")]
    line = lines[-1] if lines else ""
    return (f'<div class="zap-note">{kit.icon("radar")}<div><b>{h(ZAP_LABEL)}</b>'
            f'<span>{h(line + " – " if line else "")}sortlisterne kendte den først efter, at mailen var kommet. '
            f'Flyttet {h(kit.fmt_ts(_rget(r, "zapped_at")))}.</span></div></div>')


def _verdict_text(r: Any, thr: float, loc: str, *, force_hit: bool = False, threat: str = "") -> str:
    a = r["our_action"]
    v = _rget(r, "user_verdict")
    if threat and v != "ham":
        return "Farlig mail – flyttet uanset score."
    if v == "ham":
        return "Du har markeret beskeden som legitim. Filteret flytter den aldrig igen."
    if v == "spam":
        return "Du har bekræftet, at beskeden er spam."
    if a == "allowlisted" and force_hit:
        return "Afsenderen er markeret Altid igennem, så beskeden flyttes aldrig."
    if a == "allowlisted":
        return "Scoren var høj, men afsenderen er tilladt af en regel – derfor blev den ikke rørt."
    if r["our_score"] is None:
        return "Beskeden er ikke scoret af filteret (fundet i en spam-mappe)."
    s = float(r["our_score"])
    if a in ("moved_to_junk", "pending_move"):
        return f"Scoren {kit.fmt_score(s)} er over grænsen {kit.fmt_score(thr)}, så beskeden blev flyttet til Spamfilter-mappen."
    if a in SHADOW_ACTIONS:
        return f"Scoren {kit.fmt_score(s)} er over grænsen {kit.fmt_score(thr)}. Kontoen overvåges kun, så beskeden blev ikke flyttet."
    if a in ("flagged", "flag"):
        return f"Scoren {kit.fmt_score(s)} er over grænsen {kit.fmt_score(thr)}, så beskeden blev markeret som spam i indbakken."
    if a == "provider_junk":
        return "Din udbyder sorterede beskeden fra, før filteret så den."
    if s >= thr:
        return f"Scoren {kit.fmt_score(s)} er over grænsen {kit.fmt_score(thr)}."
    margin = thr - s
    return (f"Scoren {kit.fmt_score(s)} er under grænsen {kit.fmt_score(thr)}"
            + (" – tæt på." if margin <= 3 else " – beskeden ligner legitim post."))


def _ack_clause(confirm_text: str) -> str:
    """'Denne mail indeholder virus: X.' -> 'mailen indeholder virus (X)'."""
    t = kit.clean_name(confirm_text).rstrip(".")[:300]
    if t.startswith("Denne mail "):
        t = "mailen " + t[len("Denne mail "):]
    head, sep, tail = t.partition(": ")
    return f"{head} ({tail})" if sep and tail else (t[:1].lower() + t[1:] if t else "mailen er farlig")


def _threat_release_form(key: str, here: str, confirm_text: str) -> str:
    """B16, administrator: release of a dangerous mail behind an explicit
    'Jeg forstår …' box (works without JavaScript; never learns ham)."""
    inner = (kit.hidden("action", "release") + kit.hidden("items", key) + kit.hidden("view", "detail")
             + kit.hidden("nonce", _nonce()) + kit.hidden("next", here) + kit.hidden("confirm_threat", "1")
             + f'<label class="threat-ack"><input type="checkbox" class="check" name="ack" value="1" required>'
             f'<span>Jeg forstår, at {h(_ack_clause(confirm_text))}. Den lægges i indbakken, men læres ikke som '
             "legitim.</span></label>"
             + kit.button("Frigiv alligevel", kind="secondary", icon="undo", tone="bad", size="",
                          attrs='title="Frigiv trods advarslen"'))
    return kit.post_form("/mail/action", inner, cls="threat-release")


def _detail_actions(r: Any, *, acc: Any, account: str, key: str, loc: str, here: str,
                    addr: str, symbols: list[dict], threat: str | None = None, threat_info: dict | None = None) -> str:
    verdict_v = _rget(r, "user_verdict")
    mail_btns: list[str] = []
    common = {"view": "detail", "next_url": here, "size": ""}
    may_release = ui.can("release", account)
    admin = ui.is_admin()
    threat_part = ""
    if not may_release:
        pass
    elif acc is not None and loc == "junk":
        if threat and admin:
            threat_part = _threat_release_form(key, here, str((threat_info or {}).get("confirm_text")
                                                              or "Mailen er markeret som farlig."))
        elif threat:
            threat_part = (f'<div class="act-locked-note">{kit.icon("lock")}<div><b>Kun en administrator kan frigive '
                           f'den</b><span>{h(THREAT_ADMIN_SHORT)}, hvis du venter på mailen.</span></div></div>')
        else:
            mail_btns.append(_mail_btn(key, "release", "Frigiv", icon="undo", tone="info",
                                       title="Flyt til indbakken og lær som legitim", **common))
    elif acc is not None and loc == "inbox":
        mail_btns.append(_mail_btn(key, "mark_spam", "Flyt til spam", icon="shield-alert", tone="warn",
                                   title="Flyt til Spamfilter-mappen og lær som spam", **common))
    elif acc is not None and loc == "newsletters":
        threat_part = ui_newsletters.detail_actions(r, account, here)  # 2.6 (A4): Tilbage til indbakken
        mail_btns.append(_mail_btn(key, "mark_spam", "Flyt til spam", icon="shield-alert", tone="warn",
                                   title="Flyt til Spamfilter-mappen og lær som spam", **common))
    if acc is not None and loc != "gone" and may_release:
        if loc == "inbox" and verdict_v != "ham" and not threat:
            mail_btns.append(_mail_btn(key, "learn_ham", "Lær som legitim", icon="graduation-cap", tone="ok",
                                       title="Beskeden bliver, hvor den er", **common))
        if verdict_v != "spam":
            mail_btns.append(_mail_btn(key, "learn_spam", "Lær som spam", icon="graduation-cap", tone="brand",
                                       title="Bekræft, at det er spam – uden at flytte beskeden", **common))
    junk_name = str(getattr(acc, "junk", "") or "spam") if acc is not None else "spam"
    where = {"junk": f"Ligger i {junk_name}-mappen", "inbox": "Ligger i indbakken",
             "newsletters": "Ligger i nyhedsbreve-mappen"}.get(loc, "")
    if loc == "gone" or acc is None:
        mail_part = f'<p class="act-note">{h(GONE_TEXT)}</p>'
    elif not may_release:
        mail_part = '<p class="act-note">Du må ikke frigive eller flytte post. Spørg administratoren.</p>'
    else:
        mail_part = threat_part + (f'<div class="act-grid">{"".join(mail_btns)}</div>' if mail_btns else "")
    sections = [f'<section class="act-sec"><div class="act-sec-head"><h3>Beskeden</h3>'
                f'<span class="faint">{h(where)}</span></div>{mail_part}</section>']

    pattern = ""
    try:
        pattern = ui.engine.normalize_rule_pattern(addr) if addr else ""
    except Exception:  # noqa: BLE001 - unparsable sender: no rule shortcuts
        pattern = ""
    if (pattern and "@" in pattern and not pattern.startswith("@") and ui.account_by_name(account) is not None
            and ui.can_edit_rule(account)):
        domain = pattern.split("@", 1)[1]
        rule = RuleIndex().match(account, pattern)
        editable = rule is not None and _may_edit_rule(rule)
        rb = {"view": "detail", "next_url": here, "size": "", "item": key}
        locked = _rule_force(rule) and not ui.is_admin()  # 'Altid igennem' is admin-only
        rkind = rule["kind"] if rule is not None else ""
        shared = _is_freemail(domain) or bool({"FREEMAIL_FROM", "FREEMAIL_ENVFROM"} & {sym.get("n") for sym in symbols})
        also = "" if shared else f" – eller hele domænet {domain}"
        btns: list[str] = []
        # 2.3: one "Tillad afsender" and one "Bloker afsender"; the dialog
        # asks "Kun denne adresse" or "Hele domænet" (freemail: address only).
        if not locked:
            if rkind == "allow":
                if editable:
                    btns.append(_rule_del_btn(rule, view="detail", next_url=here, size=""))
            elif not threat:
                btns.append(_rule_add_btn(account, pattern, "allow", "Tillad afsender",
                                          title=f"Tillad {pattern}{also}", **rb))
            if rkind == "block":
                if editable:
                    btns.append(_rule_del_btn(rule, view="detail", next_url=here, size=""))
            else:
                btns.append(_rule_add_btn(account, pattern, "block", "Bloker afsender",
                                          title=f"Bloker {pattern}{also}", **rb))
        if threat == "attachment" and admin:
            # B17: admin-only exception for one sender (applies only when the
            # sender is verified with DKIM; a virus is never let through).
            btns.append(_attach_exception_btn(account, pattern, here))
        if rule is None and threat:
            note = ("Mailen er farlig, så afsenderen kan ikke tillades herfra. Bloker: posten behandles altid "
                    + ("som spam (kun adressen – det er en stor mailtjeneste)." if shared else
                       "som spam – du vælger selv, om det kun gælder adressen eller hele domænet."))
        elif rule is None:
            note = ("Tillad: posten flyttes aldrig til spam – medmindre afsenderen ser forfalsket ud. "
                    "Bloker: posten behandles altid som spam. "
                    + (f"{domain} er en stor mailtjeneste, så reglen gælder kun adressen." if shared else
                       f"Du vælger bagefter, om det kun gælder adressen eller hele domænet {domain}."))
        else:
            note = (f"{'Tilladt' if rule['kind'] == 'allow' else 'Blokeret'} af reglen {rule['pattern']} "
                    f"({_rule_where(rule)}).")
            if _rule_force(rule):
                note += " " + FORCE_NOTE
            if not editable:
                note += (" Reglen gælder alle konti og kan kun ændres af en administrator." if rule["account"] == "*"
                         else " Reglen kan kun ændres af en administrator.")
        sections.append(
            f'<section class="act-sec"><div class="act-sec-head"><h3>Afsender</h3>{_rule_chip(rule)}</div>'
            f'<div class="act-sender mono">{h(pattern)}</div>'
            f'<div class="act-grid">{"".join(b for b in btns if b)}</div>'
            f'<p class="act-note">{h(note)}</p></section>')
    return '<div class="act-panel">' + "".join(sections) + "</div>"


ATTACH_EXCEPTION_TEXT = "Tillad farlige vedhæftninger fra denne afsender"


def _attach_exception_btn(account: str, pattern: str, here: str) -> str:
    confirm = kit.confirm_attrs(
        f"{ATTACH_EXCEPTION_TEXT}?",
        f"Blokerede filtyper (fx .exe og .iso) fra {pattern} går igennem på {ui.account_label(account)} – men kun "
        "når mailen beviseligt kommer fra afsenderens domæne (DKIM). Virus stoppes stadig.",
        confirm="Tillad vedhæftninger", tone="primary")
    inner = (kit.hidden("account", account) + kit.hidden("pattern", pattern) + kit.hidden("next", here)
             + kit.button(ATTACH_EXCEPTION_TEXT, kind="secondary", icon="paperclip", size="", tone="neutral",
                          attrs=confirm))
    return kit.post_form("/rules/attachments/add", inner, cls="act-wide")


@app.get("/messages/<account>/<token>")
@ui.permission_required("see_messages")
def message_detail(account: str, token: str):
    ui.require_account(account)  # 404: don't reveal other accounts' mail
    mid = kit.msgid_from_token(token)
    if mid is None:
        abort(404)
    r = ui.query("SELECT * FROM messages WHERE account=? AND message_id=?", [account, mid], one=True)
    if r is None:
        abort(404)
    acc = ui.account_by_name(account)
    thr = float(getattr(acc, "threshold", DEFAULT_THRESHOLD) or DEFAULT_THRESHOLD) if acc else DEFAULT_THRESHOLD
    loc = _location(r, acc) if acc else "gone"
    old = _is_old(r)
    symbols = kit.parse_symbols(r["symbols"])
    aged = is_aged(r, symbols)
    name, addr = kit.sender_parts(r["sender"])
    subject = (r["subject"] or "").strip() or "(intet emne)"
    key = _key(account, mid)
    here = f"/messages/{account}/{token}"
    # 2.3: threat class (B16), rescans (B19) and trust labels (B13).
    threat, _tdetail = row_threat(r)
    tinfo = _svc("message_threat_info", account, mid, default=None) or {}
    threat_txt = threat_text_of(r) if threat else ""
    labels = [x for x in (_svc("message_trust_labels", account, mid, numbers=trust_numbers(), default=[]) or [])
              if isinstance(x, dict) and x.get("text")]
    labels = after_spam_verdict(labels, _rget(r, "user_verdict"))

    # --- summary
    folder_label = {"junk": f"Spamfilter-mappen ({getattr(acc, 'junk', 'Junk')})", "inbox": "Indbakken",
                    "newsletters": f"Nyhedsbreve ({_rget(r, 'current_folder', '')})",
                    "gone": "Ikke længere i postkassen"}[loc]
    cf = str(r["current_folder"] or "")
    if loc == "junk" and cf and cf.lower() not in (str(getattr(acc, "junk", "") or "").lower(),
                                                   str(getattr(acc, "inbox", "INBOX") or "INBOX").lower()):
        # Seen by the junk poll in the provider's own spam folder.
        folder_label = f"Udbyderens spam-mappe ({cf})"
    size = _rget(r, "size")
    pairs = [
        ("Fra", (f"<b>{h(name)}</b> " if name else "") + (f'<span class="mono">{h(addr)}</span>' if addr else h(r["sender"] or "–"))),
        ("Konto", ui.account_name_html(account)),
        ("Modtaget", h(kit.fmt_ts(r["received_at"] or r["first_seen"]))),
        ("Placering", h(folder_label)),
        ("Resultat", kit.badge(kit.action_label(r["our_action"]), kit.action_tone(r["our_action"]))
         + (" " + kit.threat_badge(threat_txt) if threat else "")
         + (" " + zap_chip(r) if _rget(r, "zapped_at") else "")
         + (" " + kit.chip("gammel scoring") if old else "")
         + (" " + kit.chip(AGED_CHIP, "info") if aged else "")),
        ("Message-ID", f'<span class="mono">{h(mid)}</span>'
         f'<button type="button" class="icon-btn copy-btn" data-copy="{h(mid)}" aria-label="Kopiér Message-ID">{kit.icon("copy")}</button>'),
    ]
    if size:
        pairs.append(("Størrelse", h(f"{kit.fmt_num(int(size) / 1024, 0)} KB" if int(size) < 1024 * 1024
                                     else f"{kit.fmt_num(int(size) / 1048576, 1)} MB")))
    if len(subject) > 70:  # the page title is truncated; keep the full subject here
        pairs.insert(0, ("Emne", h(subject)))
    summary = kit.kv_list(pairs)

    # --- technical
    pflag = _rget(r, "provider_flag")
    pscore = _rget(r, "provider_score")
    provider = ("Spam" if pflag == 1 else "Ikke spam" if pflag == 0 else "Ingen vurdering")
    if pscore is not None:
        provider += f" (score {kit.fmt_score(pscore)})"
    rule_hit = _rget(r, "rule_hit") or ""
    hit_rule = None
    if rule_hit.startswith("allow:") and rule_hit[6:].isdigit():
        hit_rule = ui.query("SELECT * FROM sender_rules WHERE id=?", [int(rule_hit[6:])], one=True)
    force_hit = _rule_force(hit_rule)
    tech = kit.kv_list([
        ("Afsender-IP", f'<span class="mono">{h(_rget(r, "sender_ip") or "–")}</span>'),
        ("Afsender (konvolut)", f'<span class="mono">{h(_rget(r, "envelope_from") or "–")}</span>'),
        ("Udbyderens filter", h(provider)),
        ("rspamd", h(f"{kit.fmt_score(_rget(r, 'rspamd_score'))} · "
                     f"{RSPAMD_ACTIONS.get(_rget(r, 'rspamd_action') or '', _rget(r, 'rspamd_action') or '–')}")),
        ("Regel", h({"allow": "Tilladt afsender", "block": "Blokeret afsender"}.get(rule_hit.split(":")[0], "–"))
         + (" " + kit.badge("Altid igennem", "brand") if force_hit else "")
         + (f' <a class="card-link" href="/rules">Se regler</a>' if rule_hit and ui.can("rules") else "")),
        ("Kilde", h({"inbox_scan": "Scanning af indbakken", "junk_poll": "Fundet ved tjek af spam-mapperne",
                     "manual": "Manuel"}.get(_rget(r, "origin") or "", _rget(r, "origin") or "–"))),
    ])

    # --- verdict
    bonus = sum(s["s"] for s in symbols if s["n"].startswith("TH_PROVIDER"))
    rsp = _rget(r, "rspamd_score")
    # 2.2: the filter's own corrections (own platform on a domain list,
    # genuine newsletter): what is left of the final score after rspamd and
    # the provider. (The spamfilter_own phishing rules are rspamd's own points.)
    try:
        own_adj = round(float(r["our_score"]) - float(rsp) - bonus, 2) if rsp is not None and not old else 0.0
    except (TypeError, ValueError):
        own_adj = 0.0
    # 2.3: when the whole adjustment is the known-contact bonus, say so.
    trust_sum = round(sum(s["s"] for s in symbols if s["n"] in kit.TRUST_SYMBOLS + ("TH_FIRST_CONTACT",)), 2)
    adj_label = ("Kendte kontakter" if abs(trust_sum) >= 0.005 and abs(own_adj - trust_sum) < 0.005
                 else "Egne justeringer")

    def _signed(v: float) -> str:
        return ("+" if v > 0 else "") + kit.fmt_score(v) if v else "0"

    verdict = (f'<div class="verdict">'
               + _threat_banner(threat_txt, tinfo) + _trust_row(labels) + _zap_note(r, tinfo)
               + f'{kit.gauge(r["our_score"], thr, greyed=old)}'
               f'<p class="verdict-text">{h(_verdict_text(r, thr, loc, force_hit=force_hit, threat=threat_txt))}</p>'
               + (f'<p class="faint">Scoren er beregnet med den gamle metode og kan ikke sammenlignes direkte.</p>' if old else "")
               + (_aged_note(symbols) if aged else "")
               + f'<div class="breakdown{" breakdown-4" if abs(own_adj) >= 0.005 else ""}">'
               f'<div><b>{kit.fmt_score(rsp)}</b><span>rspamd</span></div>'
               f'<div><b>{_signed(bonus)}</b><span>Udbyder-bonus</span></div>'
               + (f'<div><b>{_signed(own_adj)}</b><span>{adj_label}</span></div>' if abs(own_adj) >= 0.005 else "")
               + f'<div><b>{kit.fmt_score(r["our_score"])}</b><span>Endelig</span></div></div></div>')

    # --- actions: the mail itself + the sender (allow/block, colour-coded)
    actions_html = _detail_actions(r, acc=acc, account=account, key=key, loc=loc, here=here,
                                   addr=addr, symbols=symbols, threat=threat, threat_info=tinfo)
    actions_html += ui_lookalike.detail_actions(symbols, here)  # B22, admins only
    actions_html += ui_namespoof.detail_actions(symbols, here, addr)  # 2.7, admins only

    # ord-N: reading order on mobile, where both columns collapse into one.
    left = (kit.card(summary, cls="detail-card ord-1")
            + kit.card(_symbol_table(symbols, sender=r["sender"]), title="Hvorfor fik den denne score?",
                       subtitle="Hver regel lægger point til eller trækker fra. Positive point trækker mod spam.",
                       cls="ord-4")
            + kit.card(_timeline(account, mid, r), title="Tidslinje", cls="ord-5"))
    right = (kit.card(verdict, title="Vurdering", cls="ord-2")
             + kit.card(actions_html, title="Handlinger", cls="ord-3")
             + kit.card(tech, title="Teknisk", cls="ord-6"))
    body = f'<div class="grid grid-detail"><div class="stack">{left}</div><div class="stack">{right}</div></div>'
    return kit.render_page(subject if len(subject) <= 70 else subject[:67] + "…", body, active="messages",
                           breadcrumbs=[("Beskeder", f"/messages?account={account}"), (ui.account_label(account), None)])


# ---------------------------------------------------------------------------
# Mail actions (POST)
# ---------------------------------------------------------------------------


def _claim_nonce(nonce: str, actor: str, action: str) -> dict | None:
    """Idempotency: returns the stored result if this nonce was already
    used, {} if it is in flight, None if it was claimed now."""
    if not nonce:
        return None
    nonce = nonce[:80]
    conn = ui.db()
    try:
        conn.execute("DELETE FROM ui_actions WHERE created_at < ?", (int(time.time()) - 7 * 86400,))
        cur = conn.execute("INSERT OR IGNORE INTO ui_actions(nonce, actor, action, created_at, result) "
                           "VALUES(?,?,?,?,NULL)", (nonce, actor, action, int(time.time())))
        conn.commit()
    except sqlite3.Error as ex:
        log.warning("ui_actions unavailable: %s", type(ex).__name__)
        return None
    if cur.rowcount:
        return None
    row = conn.execute("SELECT result FROM ui_actions WHERE nonce=?", (nonce,)).fetchone()
    if row is None or row["result"] is None:
        return {}
    try:
        return json.loads(row["result"])
    except ValueError:
        return {}


def _store_nonce(nonce: str, payload: dict) -> None:
    if not nonce:
        return
    try:
        conn = ui.db()
        conn.execute("UPDATE ui_actions SET result=? WHERE nonce=?",
                     (json.dumps({k: payload[k] for k in ("ok", "message", "results") if k in payload},
                                 ensure_ascii=False), nonce[:80]))
        conn.commit()
    except sqlite3.Error:
        pass


def _call_mail_action(account: str, ids: list[str], action: str, actor: str, *, is_admin: bool = False,
                      confirm_threat: bool = False, demote_contact: bool = True) -> list[dict]:
    try:
        # 2.3: is_admin / confirm_threat feed the B16 release gate (fail
        # closed: a Bruger is never an admin here); demote_contact = B14.
        res = list(ui.services.mail_action(account, ids, action, actor, is_admin=is_admin,
                                           confirm_threat=confirm_threat, demote_contact=demote_contact) or [])
    except Exception as ex:  # noqa: BLE001 - never leak raw exception text
        log.error("mail_action %s failed: %s", action, type(ex).__name__)
        res = [{"message_id": m, "ok": False, "code": "error",
                "text": "Handlingen kunne ikke udføres lige nu. Prøv igen om lidt."} for m in ids]
    by_id = {str(x.get("message_id")): x for x in res if isinstance(x, dict)}
    out = []
    for i, m in enumerate(ids):
        x = by_id.get(m) or by_id.get(m.strip("<>")) or by_id.get(f"<{m.strip('<>')}>")
        if x is None and i < len(res) and isinstance(res[i], dict):
            x = res[i]
        x = dict(x or {"ok": False, "code": "error", "text": "Intet svar for denne besked."})
        x["message_id"] = m
        out.append(x)
    return out


def _allow_sender(account: str, mid: str, actor: str, scope: str = "address") -> tuple[bool, str, int, str]:
    """Allow rule for the sender address (scope 'domain' = its whole domain,
    2.3 dialog). Returns (ok, pattern or reason, rule id, previous kind of
    that rule or 'none') for Fortryd."""
    r = ui.query("SELECT * FROM messages WHERE account=? AND message_id=?", [account, mid], one=True)
    addr = kit.sender_parts(r["sender"] if r else "")[1]
    if not addr:
        return False, "Afsenderen kunne ikke aflæses", 0, ""
    try:
        pattern = ui.engine.normalize_rule_pattern(addr)
        if scope == "domain":
            pattern = "@" + pattern.partition("@")[2]
            refusal = rule_refusal(account, "allow", pattern)
            if refusal is None and _freemail_symbol(r):
                refusal = ("freemail", FREEMAIL_REFUSED.format(d=pattern[1:]))
            if refusal is not None:
                return False, refusal[1].rstrip("."), 0, ""
        if _force_conflict(account, pattern) is not None:
            return False, "afsenderen er sat til Altid igennem af en administrator", 0, ""
        prev = ui.query("SELECT kind FROM sender_rules WHERE account=? AND pattern=?", [account, pattern], one=True)
        rid = ui.engine.add_sender_rule(ui.db(), account, pattern, "allow", "Frigivet fra Fanget spam", actor)
        ui.db().commit()
    except ValueError:
        return False, "Afsenderens adresse er ugyldig", 0, ""
    except Exception as ex:  # noqa: BLE001
        log.error("add_sender_rule failed: %s", type(ex).__name__)
        return False, "Reglen kunne ikke gemmes", 0, ""
    ui.audit("rule_add", account, detail=f"allow {pattern}", message_id=mid)
    return True, pattern, int(rid or 0), (str(prev["kind"]) if prev else "none")


def _release_allow_dialog(keys: list[str], parsed_keys: list[Any], *, view: str, next_url: str):
    """'Tillad afsender' on a spam row (release + allow): the address /
    domain dialog for that one mail (choose=1)."""
    if len(keys) != 1 or parsed_keys[0] is None:
        return ui.respond("Vælg én besked.", ok=False, next_url=next_url)
    account, mid = parsed_keys[0]
    if not ui.can("release", account):
        return ui.respond("Beskeden findes ikke.", ok=False, next_url=next_url, status=404)
    if not ui.can_edit_rule(account):
        return ui.respond("Du må ikke tillade afsendere.", ok=False, next_url=next_url, status=403)
    r = ui.query("SELECT * FROM messages WHERE account=? AND message_id=?", [account, mid], one=True)
    if r is None:
        return ui.respond("Beskeden findes ikke.", ok=False, next_url=next_url, status=404)
    if row_threat(r)[0]:
        return ui.respond("Mailen er farlig, så afsenderen kan ikke tillades.", ok=False, next_url=next_url,
                          status=403)
    pattern = _sender_pattern(r["sender"])
    if not pattern:
        return ui.respond("Afsenderen kunne ikke aflæses.", ok=False, next_url=next_url)
    if _force_conflict(account, pattern) is not None:
        return ui.respond(FORCE_LOCKED.format(p=pattern), ok=False, next_url=next_url, status=403)
    return rule_dialog_reply(kind="allow", account=account, raw=pattern, view=view, next_url=next_url,
                             item=keys[0], release=True)


def _mark_gone(account: str, mid: str) -> None:
    """services could not find the mail in any folder: stop offering actions."""
    try:
        conn = ui.db()
        conn.execute("UPDATE messages SET current_folder='gone' WHERE account=? AND message_id=?", (account, mid))
        conn.commit()
    except sqlite3.Error as ex:
        log.warning("mark gone failed: %s", type(ex).__name__)


def _restore_rules(specs: Iterable[str]) -> None:
    """Fortryd of 'Tillad afsender': put each rule back as it was
    ('<id>:none' deletes it, '<id>:allow|block' restores the kind)."""
    conn = ui.db()
    for spec in list(specs)[:MAX_SYNC_ROWS]:
        rid, _, prev = str(spec).partition(":")
        if not rid.isdigit() or prev not in ("none", "allow", "block"):
            continue
        r = ui.query("SELECT * FROM sender_rules WHERE id=?", [int(rid)], one=True)
        if r is None or not _may_edit_rule(r) or (prev != "none" and _force_conflict(str(r["account"]), str(r["pattern"]))):
            continue
        if prev == "block" and hard_block_refusal(str(r["pattern"])) is not None:
            continue  # the owner's shop / own addresses are never blocked again
        if prev == "none":
            ui.engine.delete_sender_rule(conn, int(rid))
        else:
            ui.engine.add_sender_rule(conn, r["account"], r["pattern"], prev, None,
                                      (ui.current_user() or {}).get("name", ""))
        conn.commit()
        ui.audit("rule_restore", "" if r["account"] == "*" else r["account"],
                 detail=f"{r['kind']}->{prev} {r['pattern']}")


@app.post("/mail/action")
@ui.permission_required("release")
def mail_action():
    user = ui.current_user() or {}
    actor = user.get("name", "")
    action = (request.form.get("action") or "").strip()
    view = (request.form.get("view") or "").strip()
    is_undo = request.form.get("undo") == "1"
    next_url = ui.safe_next(request.form.get("next"), "/spam" if view in ("spam", "review") else "/messages")
    if action not in MAIL_ACTIONS:
        return ui.respond("Ukendt handling.", ok=False, next_url=next_url)
    if action == "release_allow" and not ui.can("rules"):
        return ui.respond("Du må ikke tillade afsendere.", ok=False, next_url=next_url, status=403)
    keys = [k for k in request.form.getlist("items") if k][: ui.MAX_MAIL_ACTION_IDS + 1]
    if not keys:
        return ui.respond("Vælg mindst én besked.", ok=False, next_url=next_url)
    if len(keys) > ui.MAX_MAIL_ACTION_IDS:
        return ui.respond(f"Højst {ui.MAX_MAIL_ACTION_IDS} beskeder ad gangen.", ok=False, next_url=next_url)
    parsed_keys = [_parse_key(k) for k in keys]
    if all(p is not None and not ui.can_access(p[0]) for p in parsed_keys):
        # Only other people's mailboxes: same answer as a mail that does not exist.
        return ui.respond("Beskeden findes ikke.", ok=False, next_url=next_url, status=404)
    allow_scope = (request.form.get("scope") or "").strip()
    if action == "release_allow" and allow_scope and allow_scope not in RULE_SCOPES:
        return ui.respond("Vælg Kun denne adresse eller Hele domænet.", ok=False, next_url=next_url)
    if action == "release_allow" and request.form.get("choose") == "1" and not allow_scope and not is_undo:
        return _release_allow_dialog(keys, parsed_keys, view=view, next_url=next_url)
    if action == "release_allow" and request.form.get("dialog") == "1" and not allow_scope and not is_undo:
        return ui.respond("Vælg Kun denne adresse eller Hele domænet.", ok=False, next_url=next_url)
    nonce = (request.form.get("nonce") or "").strip()
    prior = _claim_nonce(nonce, actor, action)
    if prior is not None:
        if prior:
            ok = bool(prior.get("ok"))
            msg = "Handlingen var allerede udført." if ok else str(prior.get("message") or "Handlingen fejlede.")
            return ui.respond(msg, ok=ok, next_url=next_url,
                              **{k: v for k, v in prior.items() if k not in ("message", "ok")})
        return ui.respond("Handlingen er allerede i gang.", ok=False, next_url=next_url, status=409)

    svc_action, verb = MAIL_ACTIONS[action]
    groups: dict[str, list[tuple[str, str]]] = {}
    results: list[dict] = []
    for key in dict.fromkeys(keys):
        parsed = _parse_key(key)
        if parsed is None:
            results.append({"key": key, "message_id": "", "ok": False, "code": "invalid_id", "text": "Ugyldig besked."})
            continue
        account, mid = parsed
        if not ui.can("release", account):
            # Never reveal whether a mail exists in someone else's mailbox.
            results.append({"key": key, "message_id": "", "ok": False, "code": "not_found",
                            "text": "Beskeden findes ikke."})
            continue
        groups.setdefault(account, []).append((key, mid))

    # Where each mail was before (decides whether Fortryd is a true undo).
    before: dict[str, str] = {}
    for account, items in groups.items():
        acc = ui.account_by_name(account)
        for key, mid in items:
            row = ui.query("SELECT current_folder, our_action FROM messages WHERE account=? AND message_id=?",
                           [account, mid], one=True)
            before[key] = _location(row, acc) if (row is not None and acc is not None) else "gone"

    restore: dict[int, str] = {}
    is_admin = ui.is_admin()
    confirm_threat = is_admin and request.form.get("confirm_threat") == "1"
    demote = request.form.get("demote_contact", "1") != "0"
    for account, items in groups.items():
        ids = [m for _k, m in items]
        for (key, mid), res in zip(items, _call_mail_action(account, ids, svc_action, actor, is_admin=is_admin,
                                                            confirm_threat=confirm_threat, demote_contact=demote)):
            res["key"] = key
            res["account"] = account
            if res.get("code") == "not_found":
                _mark_gone(account, mid)
                res["gone"] = True
                res["text"] = GONE_TEXT
            if res.get("code") == "threat_confirm":
                results.append(res)  # nothing happened yet: the administrator confirms below
                continue
            if action == "release_allow" and res.get("threat"):
                res["text"] = (res.get("text") or "") + " Afsenderen blev ikke tilladt (farlig mail)."
                results.append(res)
                ui.audit("mail_" + action, account, "ok" if res.get("ok") else "failed",
                         detail=str(res.get("code") or ""), message_id=mid)
                continue
            if action == "release_allow":
                ok, info, rid, prev = _allow_sender(account, mid, actor, allow_scope or "address") \
                    if ui.can_edit_rule(account) \
                    else (False, "din bruger må ikke tillade afsendere", 0, "")
                if ok and rid:
                    restore.setdefault(rid, prev)
                res["text"] = (res.get("text") or "") + (f" Afsenderen {info} er nu tilladt." if ok
                                                         else f" Afsenderen blev ikke tilladt: {info}.")
            results.append(res)
            ui.audit("mail_" + action, account, "ok" if res.get("ok") else "failed",
                     detail=str(res.get("code") or ""), message_id=mid)
    if is_undo:
        _restore_rules(request.form.getlist("restore_rule"))

    pending = [r for r in results if r.get("code") == "threat_confirm"]
    done = [r for r in results if r.get("code") != "threat_confirm"]
    n_ok = sum(1 for r in done if r.get("ok"))
    total = len(done)
    if not done:
        message = "Bekræft frigivelsen af " + ("en farlig mail" if len(pending) == 1 else f"{len(pending)} farlige mails")
    elif n_ok == total:
        message = f"{_n(total, 'besked', 'beskeder')} {verb}"
    elif n_ok:
        message = f"{n_ok} af {total} beskeder {verb}"
    else:
        message = (done[0].get("text") if total == 1 else None) or f"Ingen af beskederne blev {verb}"
    if action == "release_allow" and n_ok and not any(r.get("threat") for r in done):
        message += " – afsenderne er tilladt" if total > 1 else " – afsenderen er tilladt"
    if is_undo and n_ok:
        message = "Fortrudt: " + message
    contacts = [r for r in done if r.get("ok") and isinstance(r.get("contact"), dict) and r["contact"].get("demoted")]
    if contacts:
        message += (" – afsenderen er fjernet fra Kendte kontakter" if len(contacts) == 1
                    else f" – {len(contacts)} afsendere er fjernet fra Kendte kontakter")

    rows = _updated_rows(results, view, action)
    rows.update(_render_rows([k for k in request.form.getlist("sync") if k not in rows], view))
    public = [{"message_id": r.get("message_id", ""), "ok": bool(r.get("ok")), "code": r.get("code", ""),
               "text": r.get("text", ""), "key": r.get("key", "")} for r in done]
    payload = {"ok": n_ok > 0, "message": message, "results": public}
    _store_nonce(nonce, payload)
    extra: dict[str, Any] = {"results": public, "rows": rows}
    if pending and is_admin:
        extra["confirm"] = _threat_confirm_payload(pending, view=view, next_url=next_url)
    follow = _contact_followups(contacts, next_url)
    if follow:
        extra["actions"] = follow
    if view == "detail" and (n_ok or any(r.get("gone") for r in results)):
        extra["refresh"] = True
    if is_undo and n_ok:
        extra["refresh"] = True
    ok_keys = [r["key"] for r in results if r.get("ok")]
    undo_to = {"release": ("mark_spam", "junk"), "release_allow": ("mark_spam", "junk"),
               "mark_spam": ("release", "inbox")}.get(action)
    if undo_to and ok_keys and not is_undo and all(before.get(k) == undo_to[1] for k in ok_keys):
        extra["undo"] = {"label": "Fortryd", "url": "/mail/action",
                         "fields": {"action": undo_to[0], "items": ok_keys, "view": view, "next": next_url,
                                    "nonce": "", "undo": "1",
                                    "restore_rule": [f"{rid}:{prev}" for rid, prev in restore.items()]}}
    if not ui.wants_json():
        failed = [r for r in done if not r.get("ok")]
        if failed and n_ok:  # partial success: also show why the rest failed
            ui.flash("; ".join(str(f.get("text") or "") for f in failed[:3]), "warn")
        if pending:
            # Without JavaScript there is no dialog: the message page has a
            # confirm box for the release of a dangerous mail.
            ui.flash(f"{kit.clean_name(pending[0].get('confirm_text') or 'Mailen er farlig.')[:200]} Åbn mailen og bekræft frigivelsen "
                     "der.", "warn")
    if pending and not done:
        return ui.respond(message, ok=False, next_url=next_url, status=409, **extra)
    return ui.respond(message, ok=n_ok > 0, next_url=next_url, status=422, **extra)


def _threat_confirm_payload(pending: list[dict], *, view: str, next_url: str) -> dict[str, Any]:
    """B16: the dialog an administrator answers before a dangerous mail is
    released (app.js posts `fields` again with confirm_threat=1)."""
    first = pending[0]
    n = len(pending)
    text = kit.clean_name(first.get("confirm_text") or "Mailen er markeret som farlig.")[:300]
    if n > 1:
        text += f" (og {n - 1} {'anden farlig mail' if n == 2 else 'andre farlige mails'})"
    text += " Den lægges i indbakken, men filteret lærer den ikke som legitim."
    return {"title": "Frigiv farlig mail?" if n == 1 else f"Frigiv {n} farlige mails?", "text": text,
            "label": "Frigiv alligevel", "tone": "danger", "url": "/mail/action",
            "fields": {"action": "release", "items": [r["key"] for r in pending], "view": view, "next": next_url,
                       "nonce": "", "confirm_threat": "1"}}


def _contact_followups(contacts: list[dict], next_url: str) -> list[dict[str, Any]]:
    """B13/B14: 'Behold som kontakt' after a known contact's mail was marked
    as spam (the default removes the sender from Kendte kontakter)."""
    out = []
    for r in contacts[:1]:
        c = r["contact"]
        account = str(r.get("account") or "")
        if not c.get("h") or not ui.can("rules", account):
            continue
        out.append({"label": "Behold som kontakt", "url": "/rules/contacts/status",
                    "fields": {"account": account, "h": c["h"], "status": "active", "next": next_url}})
    return out


def _next_selected() -> str:
    """?account= of the page a POST came from (re-rendered rows match it)."""
    from urllib.parse import parse_qs, urlsplit

    nxt = request.form.get("next") or ""
    try:
        name = (parse_qs(urlsplit(nxt).query).get("account") or [""])[0]
    except ValueError:
        return ""
    return name if name and ui.can_access(name) else ""


def _render_rows(keys: Iterable[str], view: str) -> dict[str, str | None]:
    """Fresh HTML (None = remove) for mail rows on a list page, e.g. every
    row from the same sender domain after a rule changed."""
    if view not in LIST_VIEWS:
        return {}
    accounts, thresholds, rules = _accounts(), _thresholds(), RuleIndex()
    # Same rule as the page render: a Bruger with one mailbox never gets
    # an account chip; the 'Ny' chip of the current visit is kept.
    show_account = not _next_selected() and (ui.is_admin() or len(accounts) > 1)
    new_since = _visit_new_since()
    out: dict[str, str | None] = {}
    for key in list(dict.fromkeys(k for k in keys if k))[:MAX_SYNC_ROWS]:
        parsed = _parse_key(key)
        if parsed is None or not ui.can_access(parsed[0]):
            continue
        r = ui.query(f"SELECT *, {TS} AS ts FROM messages WHERE account=? AND message_id=?",
                     list(parsed), one=True)
        if r is None or (view in ("spam", "overview")
                         and (r["current_folder"] == "gone" or _rget(r, "user_verdict") == "ham")):
            out[key] = None
            continue
        out[key] = mail_row(r, thresholds, accounts, view=view, selectable=view != "overview",
                            show_account=show_account, rules=rules,
                            new_since=new_since if view == "spam" else None)
    return out


def _updated_rows(results: list[dict], view: str, action: str) -> dict[str, str | None]:
    """Fresh HTML (or None = remove) for each touched row of a list view.
    'review' ('Tjek disse' on Fanget spam): the judged mail leaves the
    review list, and its twin in the list below is updated too."""
    if view == "review":
        out: dict[str, str | None] = {}
        for res in results:
            key = res.get("key")
            if key and (res.get("ok") or res.get("gone")):
                out[f"review:{key}"] = None
        out.update(_updated_rows(results, "spam", action))
        return out
    if view not in LIST_VIEWS:
        return {}
    rows: dict[str, str | None] = {}
    rerender = []
    for res in results:
        key = res.get("key")
        if not key or not (res.get("ok") or res.get("gone")):
            continue
        if view in ("spam", "overview") and (res.get("gone") or action in REMOVES_FROM_SPAM_LIST):
            rows[key] = None
        else:
            rerender.append(key)
    rows.update(_render_rows(rerender, view))
    return rows


# ---------------------------------------------------------------------------
# Regler
# ---------------------------------------------------------------------------


def _rule_account_options(user: dict, accounts: dict[str, Any]) -> list[tuple[str, str]]:
    opts = [("*", "Alle konti (global)")] if user.get("is_admin") else []
    return opts + [(n, ui.account_label(n)) for n in accounts if ui.can_edit_rule(n)]


def _may_edit_rule_account(account: str) -> bool:
    return ui.can_edit_rule(account)


def _may_edit_rule(rule: Any) -> bool:
    """Central check for an existing rule (global and 'Altid igennem' rules
    are admin-only)."""
    return rule is not None and ui.can_edit_rule(str(rule["account"]), force=_rule_force(rule))


def _patterns_overlap(a: str, b: str) -> bool:
    """Do two rule patterns ('x@d' / '@d', '@d' matching subdomains) match
    at least one common address?"""
    def dom_covers(parent: str, d: str) -> bool:
        return d == parent or d.endswith("." + parent)

    la, _, da = a.partition("@")
    lb, _, db = b.partition("@")
    if la and lb:
        return a == b
    if la:          # address vs domain
        return dom_covers(db, da)
    if lb:
        return dom_covers(da, db)
    return dom_covers(da, db) or dom_covers(db, da)


def _force_conflict(account: str, pattern: str) -> Any | None:
    """For a Bruger: the 'Altid igennem' rule a new/changed rule on
    `account` would override (an account rule beats a global one in the
    engine), else None. Admins are never blocked."""
    if ui.is_admin():
        return None
    try:
        rows = ui.query("SELECT * FROM sender_rules WHERE kind='allow' AND account IN ('*', ?)", [account])
    except sqlite3.Error:
        return None
    for r in rows:
        if _rule_force(r) and _patterns_overlap(pattern, str(r["pattern"])):
            return r
    return None


FORCE_LOCKED = ("{p} er sat til Altid igennem af en administrator. Kun en administrator kan ændre "
                "regler for den afsender.")


def _describe_pattern(p: str) -> str:
    if p.startswith("@"):
        return f"Matcher alle afsendere fra {p} og dets underdomæner"
    return f"Matcher kun adressen {p}"


# ---------------------------------------------------------------------------
# 2.3: one Bloker/Tillad flow everywhere ("Kun denne adresse" / "Hele
# domænet"). Every Bloker/Tillad button posts `choose=1`; the server answers
# with the dialog (JSON `dialog` for app.js, a small confirm page without
# JS). The dialog posts `scope=address|domain` and the server builds the
# pattern itself. Safety (only on this flow, the legacy single-pattern API
# used by Fortryd/import is unchanged): no whole freemail domain, never
# block the owner's own domains / webshop / mailbox addresses or an
# 'Altid igennem' sender, and an existing rule is shown with a switch.
# ---------------------------------------------------------------------------

RULE_SCOPES = ("address", "domain")
SCOPE_INVALID = "Ugyldig adresse eller domæne – skriv fx navn@firma.dk eller firma.dk."
SCOPE_NEEDS_ADDRESS = ("Du har skrevet et domæne. Vælg Hele domænet – eller skriv en hel adresse som "
                       "navn@firma.dk for kun at ramme den.")
FREEMAIL_REFUSED = ("{d} er en stor mailtjeneste, som rigtig mange private bruger. Hele domænet kan derfor "
                    "ikke vælges – vælg kun adressen.")
OWN_MAILBOX_REFUSED = "{p} er en af jeres egne postkasser og kan ikke blokeres."
OWN_DOMAIN_REFUSED = ("{d} er jeres eget domæne. Blokerer du det, ender jeres egne og kollegernes mails i "
                      "spam – derfor kan det ikke vælges.")
SHOP_REFUSED = ("{d} hører til jeres egen webshop eller platform. Mails derfra skal altid kunne komme ind, "
                "så de kan ikke blokeres.")
FORCE_REFUSED = ("{p} er sat til Altid igennem. Fjern det først under Regler, hvis afsenderen virkelig "
                 "skal blokeres.")
FORCE_REFUSED_USER = "{p} er sat til Altid igennem af en administrator og kan ikke blokeres."


# Mail from the owner's platform must always reach the inbox (owner rule;
# the platform domains of the local site config).
ALWAYS_PROTECTED = tuple(siteconfig.get_list("platform_domains"))


def _owner_domains() -> tuple[frozenset, frozenset, frozenset]:
    """(mailbox domains incl. domain-like contact groups, owner platform /
    webshop domains, mailbox addresses) over every configured mailbox -
    the owner's own domains are protected whichever mailbox a rule is for.
    The site config's platform and webshop domains stay protected even
    when a config overrides the lists. Same function as the engine's automatic
    blocks (junkrules.owner_protection, 2.12 #9)."""
    if "_rd_owner" in g:
        return g._rd_owner
    import junkrules  # noqa: PLC0415 - pure module, same image

    out = junkrules.owner_protection(
        ui.effective_accounts(),
        (*ALWAYS_PROTECTED, *getattr(ui.engine, "DEFAULT_OWNER_PLATFORM_DOMAINS", ()),
         *getattr(ui.engine, "DEFAULT_WEBSHOP_DOMAINS", ())))
    g._rd_owner = out
    return out


def _force_overlap(account: str, pattern: str) -> Any | None:
    """An 'Altid igennem' allow rule (this mailbox or global) that a block
    of `pattern` would collide with - for admins too (unlike _force_conflict)."""
    try:
        rows = ui.query("SELECT * FROM sender_rules WHERE kind='allow' AND account IN ('*', ?)", [account])
    except sqlite3.Error:
        return None
    return next((r for r in rows if _rule_force(r) and _patterns_overlap(pattern, str(r["pattern"]))), None)


HARD_BLOCK_CODES = ("own_mailbox", "own_shop", "own_domain")


def hard_block_refusal(pattern: str) -> tuple[str, str] | None:
    """Refusals that hold for EVERY way a block rule is made - the dialog,
    a plain pattern without scope, the import field, Skift til Bloker and
    Fortryd: the owner's webshop/platform (vexar.example always; address or
    domain, also a parent domain of it), a mailbox's own address, and a
    mailbox's whole domain. `pattern` is normalised ('x@d' or '@d')."""
    import junkrules  # noqa: PLC0415 - pure module, same image

    hit = junkrules.block_refusal(pattern, _owner_domains())
    if hit is None:
        return None
    code, what = hit
    if code == "own_mailbox":
        return code, OWN_MAILBOX_REFUSED.format(p=what)
    if code == "own_shop":
        return code, SHOP_REFUSED.format(d=what)
    return code, OWN_DOMAIN_REFUSED.format(d=what)


def rule_refusal(account: str, kind: str, pattern: str) -> tuple[str, str] | None:
    """(code, Danish reason) when the dialog must refuse `pattern`
    ('x@d' or '@d', already normalised) for `kind`, else None."""
    local, _, dom = pattern.partition("@")
    if not local and _is_freemail(dom):
        return "freemail", FREEMAIL_REFUSED.format(d=dom)
    if kind != "block":
        return None
    hard = hard_block_refusal(pattern)
    if hard is not None:
        return hard
    force = _force_overlap(account, pattern)
    if force is not None:
        return "force", (FORCE_REFUSED if ui.is_admin() else FORCE_REFUSED_USER).format(p=force["pattern"])
    return None


def scoped_pattern(raw: str, scope: str) -> str:
    """The rule pattern for what the user typed/clicked and the chosen
    scope. ValueError(Danish text) when it cannot be built."""
    try:
        p = ui.engine.normalize_rule_pattern((raw or "").strip()[:320])
    except ValueError:
        raise ValueError(SCOPE_INVALID) from None
    local, _, dom = p.partition("@")
    if scope == "domain":
        return "@" + dom
    if not local:
        raise ValueError(SCOPE_NEEDS_ADDRESS)
    return p


def _existing_rules(account: str, patterns: Iterable[str]) -> list[Any]:
    pats = [p for p in dict.fromkeys(patterns) if p]
    if not pats:
        return []
    accts = ["*"] if account == "*" else [account, "*"]
    try:
        rows = ui.query(f"SELECT * FROM sender_rules WHERE pattern IN ({','.join('?' * len(pats))}) "
                        f"AND account IN ({','.join('?' * len(accts))})", [*pats, *accts])
    except sqlite3.Error:
        return []
    # This mailbox's rule first (it is the one the engine uses).
    return sorted(rows, key=lambda r: (r["account"] == "*", pats.index(str(r["pattern"]))))


def rule_choices(account: str, kind: str, raw: str, *, freemail: bool = False,
                 release: bool = False) -> dict[str, Any]:
    """Everything the dialog shows for `raw` (an address or a domain).
    ValueError(Danish) for input that is neither."""
    try:
        p = ui.engine.normalize_rule_pattern((raw or "").strip()[:320])
    except ValueError:
        raise ValueError(SCOPE_INVALID) from None
    local, _, dom = p.partition("@")
    addr = p if local else ""
    # The address, its domain and the parent domains (a rule for firma.dk
    # also covers nyhed.firma.dk) - shown with a switch, not duplicated.
    labels = dom.split(".")
    parents = ["@" + ".".join(labels[i:]) for i in range(1, len(labels) - 1)]
    existing = _existing_rules(account, [addr, "@" + dom, *parents])
    opts: dict[str, dict[str, Any]] = {}
    for scope, pat in (("address", addr), ("domain", "@" + dom)):
        o: dict[str, Any] = {"pattern": pat, "ok": True, "why": "", "code": ""}
        if not pat:
            o.update(ok=False, code="no_address",
                     why="Du har skrevet et domæne. Skriv en hel adresse for kun at ramme én afsender.")
        else:
            ref = rule_refusal(account, kind, pat)
            if ref is None and scope == "domain" and freemail:
                ref = ("freemail", FREEMAIL_REFUSED.format(d=dom))
            if ref is not None:
                o.update(ok=False, code=ref[0], why=ref[1])
            else:
                same = next((r for r in existing if r["pattern"] == pat and r["kind"] == kind), None)
                other = next((r for r in existing if r["pattern"] == pat and r["kind"] != kind
                              and str(r["account"]) == account), None)
                if same is None and other is not None and not release:
                    # The same rule with the other kind: switch it (keeps its
                    # note and history) instead of overwriting it from here.
                    verb = "Skift til Bloker" if kind == "block" else "Skift til Tillad"
                    o.update(ok=False, code="switch",
                             why=(f"Der findes allerede en regel for {pat} – brug »{verb}« ovenfor."
                                  if _may_edit_rule(other) else
                                  f"Der findes allerede en regel for {pat}, som kun en administrator kan ændre."))
                elif same is not None:
                    where = "alle postkasser" if same["account"] == "*" else ui.account_label(str(same["account"]))
                    o.update(ok=False, code="exists",
                             why=f"Findes allerede – {pat} er {'tilladt' if kind == 'allow' else 'blokeret'} "
                                 f"for {where}.")
        opts[scope] = o
    # Pre-select only the narrow choice. The whole domain is pre-selected
    # only when the user gave no address at all; when the address is locked
    # (an existing rule, a refusal) nothing is pre-selected, so one tap on
    # the red button can never block a whole domain by surprise.
    if opts["address"]["ok"]:
        default = "address"
    elif opts["address"]["code"] == "no_address" and opts["domain"]["ok"]:
        default = "domain"
    else:
        default = ""
    selectable = any(opts[s]["ok"] for s in RULE_SCOPES)
    return {"account": account, "kind": kind, "input": p, "address": addr, "domain": dom,
            "options": opts, "default": default, "selectable": selectable, "existing": existing}


def _choice_texts(kind: str, scope: str, ctx: dict[str, Any] | None) -> tuple[str, str]:
    """(title HTML, description) of one radio choice. Without ctx (Regler
    page before anything is typed) the texts are generic."""
    allow = kind == "allow"
    if ctx is None:
        if scope == "address":
            return "Kun denne adresse", "Reglen gælder kun præcis den adresse, du skriver."
        return "Hele domænet", "Reglen gælder alle adresser på domænet og dets underdomæner (fx nyhed.firma.dk)."
    dom = ctx["domain"]
    if scope == "address":
        title = f'Kun denne adresse: <b class="rd-val">{h(ctx["address"] or "–")}</b>'
        desc = ((f"Mails fra præcis denne afsender flyttes ikke til spam. Andre fra {dom} vurderes som "
                 "normalt.") if allow else
                f"Kun mails fra præcis denne afsender flyttes til spam. Andre fra {dom} kommer stadig igennem.")
        return title, desc
    title = f'Hele domænet: <b class="rd-val">{h(dom)}</b>'
    desc = (f"Alle mails fra {dom} og underdomæner (fx nyhed.{dom}) "
            + ("flyttes ikke til spam." if allow else "flyttes til spam."))
    return title, desc


def rule_choices_html(ctx: dict[str, Any] | None, kind: str, *, selected: str = "", uid: str = "rd") -> str:
    """The two radio cards (a <fieldset> that sits inside the rule form)."""
    allow = kind == "allow"
    legend = ("Hvad skal reglen gælde?" if ctx is None else
              "Hvad vil du tillade?" if allow else "Hvad vil du blokere?")
    opts = (ctx or {}).get("options") or {}
    pick = selected if selected in RULE_SCOPES and (ctx is None or opts.get(selected, {}).get("ok")) else \
        ((ctx or {}).get("default", "address") if ctx is not None else "address")
    cards = []
    shown_why: dict[str, str] = {}   # the same reason on both cards is shown once
    for scope in RULE_SCOPES:
        o = opts.get(scope, {"ok": True, "why": "", "code": ""})
        title, desc = _choice_texts(kind, scope, ctx)
        rid = f"{uid}-{scope}"
        has_why = not o.get("ok") and bool(o.get("why"))
        why_id = shown_why.get(o.get("why") or "") if has_why else None
        why = ""
        if has_why and why_id is None:
            why_id = f"{rid}-why"
            shown_why[o["why"]] = why_id
            why = (f'<span class="rd-why" id="{h(why_id)}">'
                   f'{kit.icon("info" if o.get("code") in ("exists", "switch") else "lock")}'
                   f'<span>{h(o["why"])}</span></span>')
        attrs = (" checked" if scope == pick else "") + ("" if o.get("ok") else " disabled") + \
            (f' aria-describedby="{h(why_id)}"' if has_why else "")
        cards.append(
            f'<label class="rd-choice{"" if o.get("ok") else " is-disabled"}" for="{h(rid)}">'
            f'<input type="radio" class="rd-radio" name="scope" value="{scope}" id="{h(rid)}"{attrs}>'
            f'<span class="rd-dot" aria-hidden="true"></span>'
            f'<span class="rd-text"><span class="rd-title">{title}</span><span class="rd-desc">{h(desc)}</span>'
            f"{why}</span></label>")
    blocked = ctx is not None and not ctx.get("selectable", bool(ctx.get("default")))
    tone = "brand" if ctx is None else ("ok" if allow else "bad")
    return (f'<fieldset class="rd-choices tone-{tone}"' + (" data-blocked" if blocked else "")
            + f'><legend class="rd-legend">{h(legend)}</legend>{"".join(cards)}</fieldset>')


def rule_existing_html(ctx: dict[str, Any], kind: str, *, view: str, next_url: str,
                       sync: Iterable[str] = (), ajax: bool = True) -> str:
    """Existing rules for the address/domain, each with a one-click switch
    (POST /rules/<id>/kind, guard=1) instead of making a duplicate."""
    out = []
    for r in ctx.get("existing") or []:
        allow_r = r["kind"] == "allow"
        state = "tilladt" if allow_r else "blokeret"
        where = "alle postkasser" if r["account"] == "*" else ui.account_label(str(r["account"]))
        what = ("hele domænet " + str(r["pattern"])[1:]) if str(r["pattern"]).startswith("@") else str(r["pattern"])
        extra = " · Altid igennem" if _rule_force(r) else ""
        act = ""
        if r["kind"] != kind:
            target = kind
            ok_switch = _may_edit_rule(r) and _force_conflict(str(r["account"]), str(r["pattern"])) is None and \
                (target != "block" or rule_refusal(str(r["account"]), "block", str(r["pattern"])) is None)
            if ok_switch:
                label = "Skift til Bloker" if target == "block" else "Skift til Tillad"
                # The sender's own address rule: switching it IS the action
                # the user came for, so it is the primary button.
                main = bool(ctx.get("address")) and str(r["pattern"]) == ctx.get("address")
                btn = (kit.button(label, kind="danger" if target == "block" else "primary", size="sm",
                                  icon="ban" if target == "block" else "check-circle",
                                  attrs=f'aria-label="{h(label)}: {h(r["pattern"])}"') if main else
                       kit.button(label, kind="secondary", size="sm", tone="bad" if target == "block" else "ok",
                                  icon="ban" if target == "block" else "check-circle",
                                  attrs=f'aria-label="{h(label)}: {h(r["pattern"])}"'))
                inner = (kit.hidden("kind", target) + kit.hidden("guard", "1") + kit.hidden("view", view)
                         + kit.hidden("next", next_url)
                         + "".join(kit.hidden("sync", k) for k in list(sync)[:MAX_SYNC_ROWS])
                         + btn)
                act = kit.post_form(f"/rules/{int(r['id'])}/kind", inner, cls="rd-ex-act", ajax=ajax)
            elif not _may_edit_rule(r):
                act = '<span class="rd-ex-note">Kun en administrator kan ændre den.</span>'
        out.append(
            f'<div class="rd-existing tone-{"ok" if allow_r else "bad"}">'
            f'{kit.icon("check-circle" if allow_r else "ban", "rd-ex-ic")}'
            f'<div class="rd-ex-body"><b>Der findes allerede en regel</b>'
            f'<span>{h(what)} er {state} for {h(where)}{h(extra)}.</span></div>{act}</div>')
    return "".join(out)


def _item_row(key: str, account: str) -> Any | None:
    """The message a dialog was opened from (sender name + freemail hint),
    only when it belongs to `account` and the user may see it."""
    parsed = _parse_key(key) if key else None
    if parsed is None or parsed[0] != account or not ui.can_access(account):
        return None
    return ui.query("SELECT * FROM messages WHERE account=? AND message_id=?", list(parsed), one=True)


def _freemail_symbol(r: Any) -> bool:
    if r is None:
        return False
    return any(s.get("n") in ("FREEMAIL_FROM", "FREEMAIL_ENVFROM") for s in kit.parse_symbols(_rget(r, "symbols")))


def _refused_hint(ctx: dict[str, Any], kind: str) -> str:
    """What to do instead when neither choice can be picked (built from
    the refusal codes, so the user is never sent to a dead end)."""
    codes = {o.get("code") for o in (ctx.get("options") or {}).values()}
    if kind == "block" and codes & {"own_mailbox", "own_domain"}:
        return ("Mails, der kun udgiver sig for at komme fra jer, fanges af filteret alligevel. Er mailen spam, "
                "så markér selve mailen som spam i stedet (»Lær som spam« eller »Det er spam«).")
    if kind == "block" and "own_shop" in codes:
        return ("Mails fra jeres webshop skal altid igennem. Er denne mail falsk, så markér selve mailen som "
                "spam i stedet (»Lær som spam« eller »Det er spam«).")
    if codes & {"switch", "exists", "force"}:
        return "Der er ikke noget at vælge her. Luk vinduet, eller ret reglen under Regler."
    return "Der er ikke noget at vælge her. Luk vinduet."


def rule_dialog_reply(*, kind: str, account: str, raw: str, view: str, next_url: str, item: str = "",
                      release: bool = False, note: str = "", force: bool = False):
    """Answer to a `choose=1` POST: the dialog (JSON for app.js) or, without
    JavaScript, a small confirm page with the same form."""
    r = _item_row(item, account)
    try:
        # Frigiv og tillad may replace a block rule for the sender (Fortryd
        # restores it), so there the address stays selectable.
        ctx = rule_choices(account, kind, raw, freemail=_freemail_symbol(r), release=release)
    except ValueError as ex:
        return ui.respond(str(ex), ok=False, next_url=next_url)
    allow = kind == "allow"
    title = "Frigiv og tillad afsender" if release else ("Tillad afsender" if allow else "Bloker afsender")
    sync = [k for k in request.form.getlist("sync") if k][:MAX_SYNC_ROWS]
    hidden = [("view", view), ("next", next_url)] + [("sync", k) for k in sync]
    if release:
        action = "/mail/action"
        hidden += [("action", "release_allow"), ("items", item), ("nonce", _nonce())]
        submit = kit.button("Frigiv og tillad", kind="primary", icon="check-circle", cls="rd-submit")
    else:
        action = "/rules/add"
        hidden += [("kind", kind), ("account", account), ("pattern", ctx["input"])]
        if item:
            hidden.append(("item", item))
        if note:
            hidden.append(("note", note))
        if force and allow:
            hidden.append(("force", "1"))
        submit = (kit.button("Tillad", kind="primary", icon="check-circle", cls="rd-submit") if allow
                  else kit.button("Bloker", kind="danger", icon="ban", cls="rd-submit"))
    blocked = not ctx["selectable"]
    as_json = ui.wants_json()
    name = kit.clean_name(kit.sender_parts(r["sender"])[0]) if r is not None else ""
    who = (f'<span class="rd-from"><span class="faint">Fra</span> <b>{h(name[:80])}</b></span>' if name else "")
    acct = (f'<span class="rd-acct">{kit.icon("inbox")}<span>{h(ui.account_label(account))}</span></span>'
            if account != "*" else f'<span class="rd-acct">{kit.icon("globe")}<span>Alle postkasser</span></span>')
    intro = (f'<p class="rd-lead">{kit.icon("undo")}<span>Mailen flyttes tilbage til indbakken, og afsenderen '
             "bliver tilladt.</span></p>" if release else "")
    foot = ('<p class="rd-foot">Ser en mail forfalsket ud, bliver den stadig vurderet som al anden post.</p>'
            if allow and not force else "")
    refused = (f'<div class="rd-refused">{kit.icon("alert-triangle")}<span>{h(_refused_hint(ctx, kind))}</span></div>'
               if blocked else "")
    if not blocked:
        hidden.append(("dialog", "1"))   # submitted without a choice -> asked to choose, never a guess
    cancel = (f'<a class="btn btn-secondary rd-cancel" href="{h(next_url)}" data-rd-cancel>'
              "<span>Annullér</span></a>")
    form = (f'<form method="post" action="{action}" class="rd-form"{" data-ajax" if as_json else ""} data-rule-form>'
            + kit.csrf_field()
            + "".join(kit.hidden(k, v) for k, v in hidden)
            + intro + rule_choices_html(ctx, kind, uid="rdd") + refused + foot
            + f'<div class="rd-actions">{cancel}{"" if blocked else submit}</div></form>')
    existing = rule_existing_html(ctx, kind, view=view, next_url=next_url, sync=sync, ajax=as_json)
    head = (f'<div class="rd-head"><span class="rd-head-ic tone-{"ok" if allow else "bad"}">'
            f'{kit.icon("check-circle" if allow else "ban")}</span>'
            f'<div class="rd-head-txt"><h2 id="sf-rule-title">{h(title)}</h2>'
            f'<div class="rd-meta">{who}{acct}</div></div>')
    if as_json:
        card = (f'<div class="modal-card rd-card">{head}'
                '<button type="button" class="icon-btn rd-close" data-rd-cancel aria-label="Luk">'
                f'{kit.icon("x")}</button></div>{existing}{form}</div>')
        return ui.json_ok("", dialog={"title": title, "html": card})
    body = f'<div class="rd-page"><section class="card rd-card">{head}</div>{existing}{form}</section></div>'
    return kit.render_page(title, body, active=RULE_DIALOG_NAV.get(view, "rules"))


RULE_DIALOG_NAV = {"spam": "spam", "review": "spam", "overview": "overview", "messages": "messages",
                   "detail": "messages", "contacts": "rules", "rules": "rules"}


RULE_HEADS = [("Afsender", ""), ("Type", ""), ("Gælder", ""), ("Træffere", "num"), ("", "end")]
USER_RULE_HEADS = [("Afsender", ""), ("Type", ""), ("Gælder", ""), ("", "end")]


def _rule_heads() -> list[tuple[str, str]]:
    """A Bruger gets no 'Træffere' column (a statistic, not a decision)."""
    return RULE_HEADS if ui.is_admin() else USER_RULE_HEADS


def _force_confirm(pattern: str, on: bool) -> str:
    who = pattern + (" og underdomæner" if pattern.startswith("@") else "")
    if on:
        return kit.confirm_attrs(
            f"Gør {pattern} til Altid igennem?",
            f"Post fra {who} bliver så altid i indbakken – også når den ser forfalsket ud. Det betyder, at "
            "falske mails i afsenderens navn også kommer igennem. Brug det kun til afsendere, du stoler "
            "100 % på, fx jeres egen webshop-platform. Med en normal tilladelse bliver posten også i "
            "indbakken, men kun så længe den ikke ser forfalsket ud.",
            confirm="Altid igennem", tone="primary")
    return kit.confirm_attrs(
        f"Gør {pattern} til normal tilladelse?",
        f"Post fra {who} bliver stadig i indbakken, uanset scoren. Men ser en mail forfalsket ud, "
        "vurderes den som al anden post og kan blive flyttet til spam – også ægte mails fra afsenderen, "
        "hvis de fx videresendes på en måde, der ligner forfalskning.",
        confirm="Normal tilladelse", tone="primary")


def _rule_cells(r: Any, here: str, filter_kind: str = "") -> list[str]:
    rid = int(r["id"])
    allow = r["kind"] == "allow"
    note = r["note"] or _describe_pattern(r["pattern"])
    pattern_cell = f'<div class="rule-pattern"><b>{h(r["pattern"])}</b><span>{h(note)}</span></div>'
    force = _rule_force(r)
    kind_cell = (f'<span class="badge tone-ok">{kit.icon("check")}Tilladt</span>' if allow
                 else f'<span class="badge tone-bad">{kit.icon("ban")}Blokeret</span>')
    if force:
        kind_cell = (f'<span class="rule-kinds">{kind_cell}'
                     f'<span class="badge tone-brand" title="{h(FORCE_NOTE)}">{kit.icon("shield-check")}Altid igennem</span>'
                     "</span>")
    acct_cell = kit.chip("Alle konti", "brand") if r["account"] == "*" else kit.chip(ui.account_label(r["account"]))
    hits = int(r["hits"] or 0)
    hits_cell = (f'<span class="hits"><span class="num">{kit.fmt_int(hits)}</span>'
                 + (f'<small class="faint">{h(kit.ago(r["last_hit_at"]))}</small>' if r["last_hit_at"] else "")
                 + "</span>")
    buttons = ""
    if _may_edit_rule(r):
        base = kit.hidden("next", here) + kit.hidden("view", "rules") + kit.hidden("filter_kind", filter_kind)
        if allow:
            switch = kit.button("Skift til Bloker", kind="secondary", icon="ban", size="sm", tone="bad", short="Bloker",
                                attrs=f'title="Skift til Bloker" aria-label="Skift {h(r["pattern"])} til Bloker" '
                                      + _block_confirm(r["pattern"], _rule_where(r)))
        else:
            switch = kit.button("Skift til Tillad", kind="secondary", icon="check-circle", size="sm", tone="ok",
                                short="Tillad", attrs=f'title="Skift til Tillad" aria-label="Skift {h(r["pattern"])} til Tillad"')
        force_form = ""
        if allow and ui.is_admin():  # 'Altid igennem' is admin-only
            if force:
                toggle = kit.button("Normal tilladelse", kind="secondary", icon="check-circle", size="sm",
                                    tone="neutral",
                                    attrs=f'title="Normal tilladelse" aria-label="Gør {h(r["pattern"])} til normal tilladelse" '
                                          + _force_confirm(r["pattern"], False))
            else:
                toggle = kit.button("Gør til Altid igennem", kind="secondary", icon="shield-check", size="sm",
                                    tone="brand",
                                    attrs=f'title="Gør til Altid igennem" aria-label="Gør {h(r["pattern"])} til Altid igennem" '
                                          + _force_confirm(r["pattern"], True))
            force_form = kit.post_form(f"/rules/{rid}/force", base + kit.hidden("force", "0" if force else "1") + toggle,
                                       cls="rule-force-form")
        remove = kit.button("Fjern", kind="secondary", icon="trash", size="sm", tone="neutral",
                            attrs=f'aria-label="Fjern reglen {h(r["pattern"])}" ' + kit.confirm_attrs(
                                "Fjern reglen?",
                                f"{r['pattern']} ({'tilladt' if allow else 'blokeret'}, {_rule_where(r)}) slettes. "
                                "Post fra afsenderen bliver igen vurderet på sin score.",
                                confirm="Fjern", tone="danger"))
        buttons = ('<div class="rule-actions">' + force_form
                   + kit.post_form(f"/rules/{rid}/kind", base + kit.hidden("kind", "block" if allow else "allow") + switch)
                   + kit.post_form(f"/rules/{rid}/delete", base + remove) + "</div>")
    if not ui.is_admin():
        return [pattern_cell, kind_cell, acct_cell, buttons]
    return [pattern_cell, kind_cell, acct_cell, hits_cell, buttons]


def _rule_tr(r: Any, here: str, filter_kind: str = "") -> str:
    """One rules-table row (same markup as kit.table) for in-place updates."""
    tds = "".join(f'<td data-label="{h(label)}"' + (f' class="{h(c)}"' if c else "") + f">{cell}</td>"
                  for (label, c), cell in zip(_rule_heads(), _rule_cells(r, here, filter_kind)))
    return f'<tr data-row="rule:{int(r["id"])}">{tds}</tr>'


def _rule_reply_extra(view: str, *, changed: bool, is_undo: bool) -> dict[str, Any]:
    """rows for the list page the button sat on (same-domain rows are
    re-rendered so every chip/button flips at once), or a refresh."""
    extra: dict[str, Any] = {}
    if view in LIST_VIEWS:
        extra["rows"] = _render_rows(request.form.getlist("sync"), view)
    if changed and (is_undo or view not in LIST_VIEWS + ("rules",)):
        extra["refresh"] = True
    return extra


@app.get("/rules")
@ui.permission_required("rules")
def rules_page():
    user = ui.current_user() or {}
    selected = _selected()
    accounts = _accounts()
    kind = request.args.get("kind", "")
    if kind not in ("", "allow", "block"):
        kind = ""
    q = (request.args.get("q") or "").strip()[:200]
    admin = bool(user.get("is_admin"))
    # Non-admins: their own accounts' rules; the administrator's global
    # rules (read-only) sit collapsed below the table.
    if admin:
        sc, sp = (" AND account IN ('*', ?)", [selected]) if selected else ("", [])
    else:
        names = [selected] if selected else sorted(user.get("accounts") or [])
        sc = f" AND account IN ({','.join('?' * len(names)) or 'NULL'})"
        sp = names
    where = f" WHERE 1=1{sc}"
    params: list[Any] = list(sp)
    if q:
        where += " AND (pattern LIKE ? ESCAPE '\\' OR note LIKE ? ESCAPE '\\')"
        params += [_like(q)] * 2
    cnt = {r["kind"]: int(r["n"]) for r in ui.query(f"SELECT kind, COUNT(*) AS n FROM sender_rules{where} GROUP BY kind", params)}
    if kind:
        where += " AND kind=?"
        params.append(kind)
    rules = ui.query(f"SELECT * FROM sender_rules{where} ORDER BY kind, account, pattern LIMIT 2000", params)

    here = "/rules" + _qs()
    table_rows = [{"cells": _rule_cells(r, here, kind), "attrs": f'data-row="rule:{int(r["id"])}"'} for r in rules]
    total = sum(cnt.values())
    tabs = kit.tabs([("Alle", "/rules" + _qs(kind=None), kind == "", total),
                     ("Tilladt", "/rules" + _qs(kind="allow"), kind == "allow", cnt.get("allow", 0)),
                     ("Blokeret", "/rules" + _qs(kind="block"), kind == "block", cnt.get("block", 0))])
    filters = _filters_form(_search_input(q, "Søg i regler") + _account_select(selected, accounts),
                            hidden_args={"kind": kind})
    if table_rows:
        listing = kit.table(_rule_heads(), table_rows, cls="rules-table")
    elif q or kind:
        listing = kit.empty_state("Ingen regler matcher", "Prøv en anden søgning.", "search")
    else:
        listing = kit.empty_state("Ingen regler endnu",
                                  "Tillad afsendere, der fejlagtigt fanges, eller bloker dem, der slipper igennem. "
                                  "Regler kan også oprettes direkte fra en besked.", "list-checks")

    if not admin:
        listing += _global_rules_section(q, kind, here)
    acct_opts = _rule_account_options(user, accounts)
    default_acct = selected or (acct_opts[0][0] if acct_opts else "")
    can_add = bool(acct_opts)

    def acct_field(attrs: str = "") -> str:
        if len(acct_opts) == 1 and not admin:
            return kit.hidden("account", acct_opts[0][0])
        return kit.form_field("Gælder for", kit.select("account", acct_opts, default_acct, attrs=attrs))
    form = ""
    if can_add:
        form_inner = (
            '<div class="form-grid">'
            + kit.form_field("Type", kit.segmented("kind", [("allow", "Tillad"), ("block", "Bloker")], "allow")
                             .replace('class="segmented"', 'class="segmented seg-kind"'))
            + kit.form_field("Adresse eller domæne",
                             kit.input_("pattern", "", attrs='placeholder="tilbud@firma.dk" required inputmode="email" '
                                                             'autocomplete="off" autocapitalize="none" spellcheck="false" '
                                                             'data-rule-preview="rule-preview" '
                                                             'data-rule-choices="rule-choices" '
                                                             'data-rule-existing="rule-existing"'),
                             hint="Indsæt bare hele afsenderens adresse – du vælger nedenfor, om reglen kun gælder "
                                  "adressen eller hele domænet.")
            + kit.hidden("dialog", "1")   # no choice picked -> asked to choose, never a guess
            + f'<div class="rd-inline" id="rule-choices">{rule_choices_html(None, "allow", uid="rdf")}</div>'
            + '<div class="rule-preview" id="rule-preview" data-empty="Skriv en adresse eller et domæne for at se, hvad reglen matcher.">'
            + kit.icon("info") + "<span>Skriv en adresse eller et domæne for at se, hvad reglen matcher.</span></div>"
            + acct_field()
            + kit.form_field("Note (valgfri)", kit.input_("note", "", attrs='maxlength="200" placeholder="Fx nyhedsbrev fra banken"'))
            # Only for Tillad (hidden by CSS when Bloker is chosen; the server ignores it for block).
            # 'Altid igennem' is admin-only.
            + ('<div class="field field-switch force-field">'
               + kit.switch("force", False, "Altid igennem")
               + '<span class="field-hint">Posten flyttes aldrig – heller ikke når den ser forfalsket ud, så falske '
               "mails i afsenderens navn kommer også igennem. Kun til afsendere, du stoler 100 % på.</span></div>"
               if user.get("is_admin") else "")
            + f'<div class="form-actions">{kit.button("Tilføj regel", kind="primary", icon="plus")}</div></div>'
        )
        import_inner = (
            '<div class="form-grid">'
            + kit.form_field("Type", kit.segmented("kind", [("allow", "Tillad"), ("block", "Bloker")], "block")
                             .replace('class="segmented"', 'class="segmented seg-kind"'))
            + kit.form_field("Én adresse eller ét domæne pr. linje",
                             kit.textarea("patterns", "", rows=6, attrs='placeholder="@spamfirma.example&#10;tilbud@butik.example" spellcheck="false"'),
                             hint=f"Linjer der starter med # ignoreres. Højst {MAX_RULE_LINES} linjer.")
            + acct_field('id="f-import-account"')
            + f'<div class="form-actions">{kit.button("Importér", kind="secondary", icon="upload")}</div></div>'
        )
        importer = ('<details class="disclosure mt-2"><summary>' + kit.icon("chevron-right")
                    + "Importér flere på én gang</summary><div class=\"disclosure-body\">"
                    + kit.post_form("/rules/add", import_inner, attrs="data-reset") + "</div></details>"
                    if admin else "")
        form = kit.card(
            kit.post_form("/rules/add", form_inner, cls="rule-add-form", attrs="data-reset")
            # Existing rules for what was typed (one-click switch): separate
            # forms, so they live next to - not inside - the add form.
            + '<div class="rd-existing-box" id="rule-existing" aria-live="polite"></div>' + importer,
            title="Ny regel",
            subtitle=("Post fra tilladte afsendere flyttes ikke – medmindre den ser forfalsket ud "
                      "(vælg Altid igennem for at undgå det). Post fra blokerede behandles altid som spam."
                      if admin else "Tilladte afsendere flyttes ikke til spam. Blokerede afsendere flyttes altid."))
    body = (rules_tabs("rules", selected)
            + f'<div class="grid {"grid-rules" if form else ""}">{form}'
            + kit.card(f'<div class="card-pad">{tabs}<div class="mt-2">{filters}</div></div>'
                       f'<div class="card-pad-x">{listing}</div>', cls="flush")
            + "</div>")
    return kit.render_page("Regler", body, active="rules",
                           subtitle="Bestem selv, hvem der altid slipper igennem – og hvem der aldrig gør.")


def rules_tabs(active: str, account: str = "") -> str:
    """2.3: the Regler sections - Afsenderregler (rules permission),
    Kendte kontakter (every user, own mailboxes) and Vedhæftninger (admin)."""
    q = f"?account={quote(account, safe='')}" if account and ui.can_access(account) else ""
    items = []
    if ui.can("rules"):
        items.append(("rules", "/rules" + q, "Afsenderregler", "list-checks"))
    items.append(("contacts", "/rules/contacts" + q, "Kendte kontakter", "user-check"))
    if ui.is_admin():
        items.append(("attachments", "/rules/attachments", "Vedhæftninger", "paperclip"))
    if len(items) < 2:
        return ""
    links = "".join(
        f'<a class="subnav-item{" is-active" if key == active else ""}" href="{h(href)}"'
        + (' aria-current="page"' if key == active else "") + f'>{kit.icon(ic)}<span>{h(label)}</span></a>'
        for key, href, label, ic in items)
    return f'<nav class="subnav" aria-label="Regler">{links}</nav>'


def _global_rules_section(q: str, kind: str, here: str) -> str:
    """A Bruger's read-only view of the administrator's rules for all
    mailboxes, collapsed (they apply, but the Bruger cannot change them)."""
    where, params = " WHERE account='*'", []
    if q:
        where += " AND (pattern LIKE ? ESCAPE '\\' OR note LIKE ? ESCAPE '\\')"
        params += [_like(q)] * 2
    if kind:
        where += " AND kind=?"
        params.append(kind)
    rows = ui.query(f"SELECT * FROM sender_rules{where} ORDER BY kind, pattern LIMIT 500", params)
    if not rows:
        return ""
    table = kit.table(_rule_heads(), [{"cells": _rule_cells(r, here, kind)} for r in rows], cls="rules-table")
    return (f'<details class="disclosure rules-global mt-2"><summary>{kit.icon("chevron-right")}'
            f"Regler fra administratoren ({kit.fmt_int(len(rows))})</summary>"
            '<div class="disclosure-body"><p class="faint small">Gælder for alle postkasser. Kun administratoren '
            f"kan ændre dem.</p>{table}</div></details>")


@app.get("/rules/preview")
@ui.permission_required("rules")
def rules_preview():
    raw = (request.args.get("pattern") or "").strip()[:320]
    account = (request.args.get("account") or "*").strip() or "*"
    kind = (request.args.get("kind") or "").strip()
    scope = (request.args.get("scope") or "").strip()
    want_form = request.args.get("form") == "1" and kind in ("allow", "block")
    if account != "*":
        ui.require_account(account)
    if not raw:
        return ui.json_ok("", tone="", text="")
    try:
        p = ui.engine.normalize_rule_pattern(raw)
    except ValueError:
        return ui.json_ok("", tone="bad", text="Ugyldig adresse eller domæne – skriv fx navn@firma.dk eller firma.dk.")
    extra: dict[str, Any] = {}
    if want_form:
        # 2.3: the Regler form shows the same two choices as the dialog.
        ctx = rule_choices(account, kind, raw)
        if not ctx["options"].get(scope, {}).get("ok"):
            scope = ctx["default"]
        if scope == "domain":
            p = "@" + p.partition("@")[2]
        nxt = ui.safe_next(request.args.get("next"), "/rules")
        extra = {"choices_html": rule_choices_html(ctx, kind, selected=scope, uid="rdf"),
                 "existing_html": rule_existing_html(ctx, kind, view="rules", next_url=nxt),
                 "scope": scope, "blocked": not ctx["selectable"]}
    text = _describe_pattern(p)
    sc, sp = ([" AND account=?", [account]] if account != "*" else list(ui.scope_sql()))
    if p.startswith("@"):
        dom = p[1:]
        cond, cp = "(LOWER(sender) LIKE ? ESCAPE '\\' OR LOWER(sender) LIKE ? ESCAPE '\\')", [_like("@" + dom), _like("." + dom)]
    else:
        cond, cp = "LOWER(sender) LIKE ? ESCAPE '\\'", [_like(p)]
    row = ui.query(f"SELECT COUNT(*) FROM messages WHERE {cond} AND {TS} >= ?{sc}",
                   [*cp, int(time.time()) - 30 * 86400, *sp], one=True)
    n = int(row[0]) if row else 0
    text += f" · {_n(n, 'besked', 'beskeder')} de seneste 30 dage"
    existing = ui.query("SELECT * FROM sender_rules WHERE account=? AND pattern=?", [account, p], one=True)
    if existing:
        text += (f" · erstatter den eksisterende regel ({'tilladt' if existing['kind'] == 'allow' else 'blokeret'}"
                 + (", Altid igennem" if _rule_force(existing) else "") + ")")
    tone = "warn" if want_form and extra.get("blocked") else "ok"
    return ui.json_ok("", tone=tone, text=text, pattern=p, matches=n, **extra)


@app.post("/rules/add")
@ui.permission_required("rules")
def rules_add():
    actor = (ui.current_user() or {}).get("name", "")
    kind = (request.form.get("kind") or "").strip()
    account = (request.form.get("account") or "*").strip() or "*"
    note = (request.form.get("note") or "").strip()[:200]
    view = (request.form.get("view") or "").strip()
    is_undo = request.form.get("undo") == "1"
    next_url = ui.safe_next(request.form.get("next"), "/rules")
    if kind not in ("allow", "block"):
        return ui.respond("Vælg Tillad eller Bloker.", ok=False, next_url=next_url)
    # 'Altid igennem' only exists for allow rules; the one-click
    # "Tillad afsender" buttons never send it (normal allow rules).
    force = kind == "allow" and request.form.get("force") == "1"
    if account != "*":
        ui.require_account(account)  # 404 for someone else's mailbox
    if not _may_edit_rule_account(account):
        return ui.respond("Du kan kun oprette regler for dine egne konti.", ok=False, next_url=next_url, status=403)
    if force and not ui.is_admin():
        return ui.respond("Kun en administrator kan gøre en afsender til Altid igennem.", ok=False,
                          next_url=next_url, status=403)
    if account != "*" and ui.account_by_name(account) is None:
        return ui.respond("Ukendt konto.", ok=False, next_url=next_url)
    single = request.form.get("pattern") is not None
    lines = [request.form.get("pattern") or ""] if single else (request.form.get("patterns") or "").splitlines()
    lines = [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]
    if not lines:
        return ui.respond("Skriv en adresse eller et domæne.", ok=False, next_url=next_url)
    # 2.3 rules dialog: a Bloker/Tillad button asks first (choose=1), the
    # dialog / Regler form answers with scope=address|domain.
    scope = (request.form.get("scope") or "").strip()
    scoped = single and scope in RULE_SCOPES and not is_undo
    if single and request.form.get("choose") == "1" and not scoped and not is_undo:
        return rule_dialog_reply(kind=kind, account=account, raw=lines[0], view=view, next_url=next_url,
                                 item=(request.form.get("item") or "").strip(), note=note, force=force)
    if single and not scoped and not is_undo and (scope or request.form.get("dialog") == "1"):
        # A dialog submitted without a choice is never guessed.
        return ui.respond("Vælg Kun denne adresse eller Hele domænet.", ok=False, next_url=next_url)
    if scoped:
        try:
            p_scoped = scoped_pattern(lines[0], scope)
        except ValueError as ex:
            return ui.respond(str(ex), ok=False, next_url=next_url)
        refusal = rule_refusal(account, kind, p_scoped)
        if refusal is None and p_scoped.startswith("@") and \
                _freemail_symbol(_item_row((request.form.get("item") or "").strip(), account)):
            # rspamd says the mail came from a mail service (FREEMAIL_FROM):
            # same refusal as in the dialog, not only the known list.
            refusal = ("freemail", FREEMAIL_REFUSED.format(d=p_scoped[1:]))
        if refusal is not None:
            return ui.respond(refusal[1], ok=False, next_url=next_url, code=refusal[0],
                              status=403 if refusal[0] == "force" and not ui.is_admin() else 400)
        lines = [p_scoped]
    if len(lines) > MAX_RULE_LINES:
        return ui.respond(f"Højst {MAX_RULE_LINES} linjer ad gangen.", ok=False, next_url=next_url)
    results, added = [], []
    undo: dict[str, Any] | None = None
    conn = ui.db()
    for ln in dict.fromkeys(lines):
        try:
            p = ui.engine.normalize_rule_pattern(ln)
            if _force_conflict(account, p) is not None:
                results.append({"pattern": ln, "ok": False, "code": "force_locked", "text": FORCE_LOCKED.format(p=p)})
                continue
            hard = hard_block_refusal(p) if kind == "block" else None
            if hard is not None:
                # Every path (also without scope, the import field and
                # Fortryd): the owner's shop and own addresses/domains.
                results.append({"pattern": ln, "ok": False, "code": hard[0], "text": hard[1]})
                continue
            prev = ui.query("SELECT * FROM sender_rules WHERE account=? AND pattern=?", [account, p], one=True)
            if force:
                rid = ui.engine.add_sender_rule(conn, account, p, kind, note or None, actor, force=True)
            else:
                rid = ui.engine.add_sender_rule(conn, account, p, kind, note or None, actor)
            results.append({"pattern": ln, "ok": True, "code": "ok", "text": p})
            added.append(p)
            back = {"view": view, "next": next_url, "undo": "1"}
            if single and not is_undo and rid and (prev is None or prev["kind"] != kind):
                fields = {**back, "kind": prev["kind"]} if prev is not None else back
                if prev is not None and _rule_force(prev):
                    fields["force"] = "1"
                undo = ({"label": "Fortryd", "url": f"/rules/{int(rid)}/delete", "fields": back} if prev is None else
                        {"label": "Fortryd", "url": f"/rules/{int(rid)}/kind", "fields": fields})
            elif single and not is_undo and rid and force and not _rule_force(prev):
                undo = {"label": "Fortryd", "url": f"/rules/{int(rid)}/force", "fields": {**back, "force": "0"}}
        except ValueError:
            results.append({"pattern": ln, "ok": False, "code": "invalid", "text": f"Ugyldig: {ln[:80]}"})
    conn.commit()
    for p in added:
        ui.audit("rule_add", "" if account == "*" else account, detail=f"{kind} {p}" + (" force" if force else ""))
    label = ("tilladt (Altid igennem)" if force else "tilladt") if kind == "allow" else "blokeret"
    if scoped and added and added[0].startswith("@"):
        message = f"Hele domænet {added[0][1:]} er nu {label}" + \
            ("" if account == "*" else f" på {ui.account_label(account)}")
    elif len(lines) == 1:
        message = (f"{added[0]} er nu {label}" + ("" if account == "*" else f" på {ui.account_label(account)}")) \
            if added else (results[0]["text"] if results and results[0]["code"] in ("force_locked", *HARD_BLOCK_CODES)
                           else "Ugyldig adresse eller domæne.")
    else:
        locked = sum(1 for r in results if r["code"] == "force_locked")
        protected = sum(1 for r in results if r["code"] in HARD_BLOCK_CODES)
        invalid = len(lines) - len(added) - locked - protected
        message = f"{_n(len(added), 'regel', 'regler')} tilføjet" + \
            (f", {invalid} ugyldige linjer sprunget over" if invalid else "") + \
            (f", {locked} sprunget over (Altid igennem)" if locked else "") + \
            (f", {protected} sprunget over (jeres egne adresser, domæner eller webshop kan ikke blokeres)"
             if protected else "")
    if is_undo and added:
        message = "Fortrudt: " + message
    extra = _rule_reply_extra(view, changed=bool(added), is_undo=is_undo)
    if undo:
        extra["undo"] = undo
    locked_only = bool(results) and all(r["code"] == "force_locked" for r in results)
    if not added and len(results) == 1 and results[0]["code"] in HARD_BLOCK_CODES:
        extra["code"] = results[0]["code"]
    return ui.respond(message, ok=bool(added), next_url=next_url, results=results,
                      status=403 if locked_only else 400, **extra)


@app.post("/rules/<int:rule_id>/delete")
@ui.permission_required("rules")
def rules_delete(rule_id: int):
    view = (request.form.get("view") or "").strip()
    is_undo = request.form.get("undo") == "1"
    next_url = ui.safe_next(request.form.get("next"), "/rules")
    r = ui.query("SELECT * FROM sender_rules WHERE id=?", [rule_id], one=True)
    if r is not None and r["account"] != "*" and not ui.can_access(r["account"]):
        r = None  # another mailbox's rule: same answer as a missing one
    if r is None:
        return ui.respond("Reglen findes ikke længere.", ok=False, next_url=next_url, status=404,
                          rows={f"rule:{rule_id}": None, **_rule_reply_extra(view, changed=False, is_undo=False).get("rows", {})})
    if not _may_edit_rule(r):
        return ui.respond("Du har ikke adgang til at slette denne regel.", ok=False, next_url=next_url, status=403)
    conn = ui.db()
    ui.engine.delete_sender_rule(conn, rule_id)
    conn.commit()
    ui.audit("rule_delete", "" if r["account"] == "*" else r["account"], detail=f"{r['kind']} {r['pattern']}")
    extra = _rule_reply_extra(view, changed=True, is_undo=is_undo)
    extra["rows"] = {f"rule:{rule_id}": None, **extra.get("rows", {})}
    if not is_undo:
        extra["undo"] = {"label": "Fortryd", "url": "/rules/add",
                         "fields": {"kind": r["kind"], "pattern": r["pattern"], "account": r["account"],
                                    "note": r["note"] or "", "view": view, "next": next_url, "undo": "1",
                                    **({"force": "1"} if _rule_force(r) else {})}}
    if view in LIST_VIEWS + ("detail",):
        message = f"{'Tilladelsen' if r['kind'] == 'allow' else 'Blokeringen'} af {r['pattern']} er fjernet"
    else:
        message = f"Reglen for {r['pattern']} er slettet"
    return ui.respond(("Fortrudt: " if is_undo else "") + message, ok=True, next_url=next_url, **extra)


@app.post("/rules/<int:rule_id>/kind")
@ui.permission_required("rules")
def rules_kind(rule_id: int):
    """Switch a rule between Tillad and Bloker in place (keeps its note)."""
    actor = (ui.current_user() or {}).get("name", "")
    kind = (request.form.get("kind") or "").strip()
    view = (request.form.get("view") or "").strip()
    filter_kind = (request.form.get("filter_kind") or "").strip()
    is_undo = request.form.get("undo") == "1"
    next_url = ui.safe_next(request.form.get("next"), "/rules")
    if kind not in ("allow", "block"):
        return ui.respond("Vælg Tillad eller Bloker.", ok=False, next_url=next_url)
    r = ui.query("SELECT * FROM sender_rules WHERE id=?", [rule_id], one=True)
    if r is not None and r["account"] != "*" and not ui.can_access(r["account"]):
        r = None  # another mailbox's rule: same answer as a missing one
    if r is None:
        return ui.respond("Reglen findes ikke længere.", ok=False, next_url=next_url, status=404,
                          rows={f"rule:{rule_id}": None})
    if not _may_edit_rule(r):
        return ui.respond("Du har ikke adgang til at ændre denne regel.", ok=False, next_url=next_url, status=403)
    if kind != r["kind"] and _force_conflict(str(r["account"]), str(r["pattern"])) is not None:
        return ui.respond(FORCE_LOCKED.format(p=r["pattern"]), ok=False, next_url=next_url, status=403)
    if kind == "block" and kind != r["kind"]:
        # The owner's shop and own addresses/domains are never blocked (also
        # without guard and for Fortryd); the dialog's switch (guard=1) has
        # every other safety rule of the dialog too.
        refusal = hard_block_refusal(str(r["pattern"]))
        if refusal is None and request.form.get("guard") == "1" and not is_undo:
            refusal = rule_refusal(str(r["account"]), "block", str(r["pattern"]))
        if refusal is not None:
            return ui.respond(refusal[1], ok=False, next_url=next_url, code=refusal[0], status=400)
    old = str(r["kind"])
    old_force = _rule_force(r)
    changed = old != kind
    if changed:
        conn = ui.db()
        # force=1 only comes from Fortryd of "Skift til Bloker" on an
        # 'Altid igennem' rule: the undo restores the rule exactly.
        if kind == "allow" and request.form.get("force") == "1" and ui.is_admin():
            ui.engine.add_sender_rule(conn, r["account"], r["pattern"], kind, None, actor, force=True)
        else:
            ui.engine.add_sender_rule(conn, r["account"], r["pattern"], kind, None, actor)
        conn.commit()
        ui.audit("rule_kind", "" if r["account"] == "*" else r["account"], detail=f"{old}->{kind} {r['pattern']}")
    fresh = ui.query("SELECT * FROM sender_rules WHERE id=?", [rule_id], one=True)
    extra = _rule_reply_extra(view, changed=changed, is_undo=is_undo)
    if view == "rules" and fresh is not None:
        extra["rows"] = {f"rule:{rule_id}": (_rule_tr(fresh, next_url, filter_kind)
                                             if filter_kind in ("", kind) else None), **extra.get("rows", {})}
    if changed and not is_undo:
        extra["undo"] = {"label": "Fortryd", "url": f"/rules/{rule_id}/kind",
                         "fields": {"kind": old, "view": view, "next": next_url, "filter_kind": filter_kind,
                                    "undo": "1", **({"force": "1"} if old_force else {})}}
    label = "tilladt" if kind == "allow" else "blokeret"
    message = f"{r['pattern']} er nu {label}" + ("" if r["account"] == "*" else f" på {ui.account_label(r['account'])}")
    if not changed:
        message = f"{r['pattern']} var allerede {label}"
    elif is_undo:
        message = "Fortrudt: " + message
    return ui.respond(message, ok=True, next_url=next_url, **extra)


@app.post("/rules/<int:rule_id>/force")
@ui.admin_required
def rules_force(rule_id: int):
    """Turn 'Altid igennem' on/off for an allow rule (admin-only: it
    overrides the spoof protection)."""
    want = (request.form.get("force") or "").strip()
    view = (request.form.get("view") or "").strip()
    filter_kind = (request.form.get("filter_kind") or "").strip()
    is_undo = request.form.get("undo") == "1"
    next_url = ui.safe_next(request.form.get("next"), "/rules")
    if want not in ("0", "1"):
        return ui.respond("Vælg Altid igennem eller normal tilladelse.", ok=False, next_url=next_url)
    r = ui.query("SELECT * FROM sender_rules WHERE id=?", [rule_id], one=True)
    if r is None:
        return ui.respond("Reglen findes ikke længere.", ok=False, next_url=next_url, status=404,
                          rows={f"rule:{rule_id}": None})
    if not _may_edit_rule_account(r["account"]):
        return ui.respond("Du har ikke adgang til at ændre denne regel.", ok=False, next_url=next_url, status=403)
    if r["kind"] != "allow":
        return ui.respond("Kun tilladte afsendere kan markeres Altid igennem.", ok=False, next_url=next_url)
    force = want == "1"
    changed = _rule_force(r) != force
    if changed:
        conn = ui.db()
        ui.engine.set_rule_force(conn, rule_id, force)
        conn.commit()
        ui.audit("rule_force", "" if r["account"] == "*" else r["account"],
                 detail=f"{'on' if force else 'off'} {r['pattern']}")
    fresh = ui.query("SELECT * FROM sender_rules WHERE id=?", [rule_id], one=True)
    extra = _rule_reply_extra(view, changed=changed, is_undo=is_undo)
    if view == "rules" and fresh is not None:
        extra["rows"] = {f"rule:{rule_id}": _rule_tr(fresh, next_url, filter_kind), **extra.get("rows", {})}
    if changed and not is_undo:
        extra["undo"] = {"label": "Fortryd", "url": f"/rules/{rule_id}/force",
                         "fields": {"force": "0" if force else "1", "view": view, "next": next_url,
                                    "filter_kind": filter_kind, "undo": "1"}}
    where = "" if r["account"] == "*" else f" på {ui.account_label(r['account'])}"
    label = "Altid igennem" if force else "en normal tilladelse"
    message = f"{r['pattern']} er nu {label}{where}" if changed else f"{r['pattern']} var allerede {label}"
    if changed and is_undo:
        message = "Fortrudt: " + message
    return ui.respond(message, ok=True, next_url=next_url, **extra)


# ---------------------------------------------------------------------------
# /api/status
# ---------------------------------------------------------------------------


@app.get("/api/status")
@ui.login_required
def api_status():
    rows = _status_rows("")
    err = ui.config_error()
    if err and not ui.is_admin():
        err = "Filterets opsætning har en fejl. Kontakt administratoren."  # raw text may name other mailboxes
    k = _kpis("", 86400)["cur"]
    live: dict[str, dict[str, Any]] = {}
    for r in rows:
        lk = f"acct-{r['name']}"
        st = r["state"]
        live[f"{lk}-dot"] = {"tone": kit.state_tone(st), "text": kit.state_label(st),
                             "pulse": st in ("idle", "working", "connecting", "starting")}
        live[f"{lk}-state"] = {"text": kit.state_label(st)}
        live[f"{lk}-ago"] = {"text": kit.ago(r["last_activity"]) if r["last_activity"] else "ingen aktivitet endnu"}
        live[f"{lk}-scanned"] = {"text": kit.fmt_int(r["today"]["scanned"])}
        live[f"{lk}-spam"] = {"text": kit.fmt_int(r["today"]["spam"])}
        live[f"{lk}-spamuser"] = {"text": _spam_user_text(r["today"].get("spam_user", 0),
                                                         r["today"].get("provider_spam", 0))}
        live[f"{lk}-released"] = {"text": kit.fmt_int(r["today"]["released"])}
    accounts = [{
        "name": r["name"], "state": r["state"], "state_label": kit.state_label(r["state"]),
        "mode": r["mode"], "mode_label": kit.mode_label(r["mode"]), "threshold": r["threshold"],
        "enabled": r["enabled"], "detail": r["detail"], "last_activity": r["last_activity"],
        "today": {k2: v for k2, v in r["today"].items()},
    } for r in rows]
    return jsonify({"ok": True, "version": ui.app_version(), "generated_at": int(time.time()),
                       "config_error": err, "accounts": accounts,
                       "kpis": {"24h": k}, "nav": ui.nav_counts(), "live": live})


# Find en mail, Fortryd flytninger and Hjælp live in ui_tools.py; importing it
# here registers them wherever the mail pages are loaded.
import ui_tools  # noqa: E402,F401
import ui_contacts  # noqa: E402,F401  (2.3: Kendte kontakter + Vedhæftninger under Regler)
import ui_junkrules  # noqa: E402,F401  (2.12 #8/#9: Tjek disse → regler og flytninger til Junk)
import ui_lookalike  # noqa: E402  (B22: Beskyttede domæner, Oversigt item, detail button)
import ui_namespoof  # noqa: E402  (2.7: Beskyttede navne, Oversigt item, detail button)
import ui_campaigns  # noqa: E402  (2.6: block suggestions + protected inbox watch on Oversigt)
import ui_ha  # noqa: E402,F401  (B26: Home Assistant API + Indstillinger card)
import ui_push  # noqa: E402,F401  (2.5.0: Min konto -> Beskeder på denne enhed)
import passkeys  # noqa: E402,F401  (2.6: passkey login + Min konto -> Passkeys)
import ui_newsletters  # noqa: E402  (2.6 A4: Nyhedsbreve page, mailbox card line, Tilbage til indbakken)
import ui_trials  # noqa: E402,F401  (2.8: Nye beskyttelser - QR-koder og Sanesecurity, Fra/Prøv/Til)
