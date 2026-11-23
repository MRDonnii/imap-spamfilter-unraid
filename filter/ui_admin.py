"""Administration pages for the spamfilter 2.0 web UI.

  * Konti          /accounts          account cards, per-account settings, add wizard
  * Træning        /training          Bayes status, training + calibration jobs
  * Drift          /system            host status, rspamd, backups, event + audit log
  * Indstillinger  /settings          users link, adgang udefra (proxy/tunnel), sessions,
                                      own account, app on the phone, theme, about

Every page here is admin-only (dashboard.admin_required = the central
access policy), including Brugere (/users): roles, mailboxes and the
per-user permissions stored by dashboard.set_user_perms(). Config writes go through
dashboard.save_config() (one key at a time, only what the user changed),
IMAP passwords through write_secret() into /state/imap-secrets/<name>
(0600, atomic, never echoed back). services.* is reached through
`ui.services` at call time so tests can swap it for a fake.

Saving a new host/user/password requires a successful connection test of
exactly those values: the test returns an HMAC token bound to the actor
and the values; without a valid token the save handler runs the test
itself (so the no-JS path is just as strict).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import platform
import re
import sqlite3
import tempfile
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import quote, urlencode

import yaml
from flask import abort, g, jsonify, request, session

import dashboard as ui
import siteconfig
import ui_kit as kit
from ui_kit import h

log = logging.getLogger("dashboard.admin")
app = ui.app

# ---------------------------------------------------------------------------
# Constants + vocabulary
# ---------------------------------------------------------------------------

ACCOUNT_NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
USER_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
HOST_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
EMAIL_RE = re.compile(r"[^@\s:]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}")

THR_MIN, THR_MAX, THR_STEP = 5.0, 15.0, 0.5
THR_STEPS = [THR_MIN + i * THR_STEP for i in range(int((THR_MAX - THR_MIN) / THR_STEP) + 1)]
PREVIEW_LIMIT = 500           # "would have caught N of the last M mails"
TEST_TOKEN_TTL = 15 * 60      # a connection test is valid this long for saving
MIN_PASSWORD = 12
RESERVED_NAMES = {"new", "suggest", "test"}  # /accounts/<name> would clash
NEW_FOLDER = "__new__"
DEFAULT_JUNK = "Spamfilter"   # owner decision: dedicated folder on every account
PAGE_SIZE = 50
AUDIT_READ_MAX = 8 * 1024 * 1024
JOB_PAGE = 30

MODE_ICONS = {"shadow": "eye", "flag": "flag", "move": "shield-check"}
MODE_CONFIRM = {
    "shadow": ("Skift {name} til Overvåg?",
               "Filteret scorer stadig ny post, men flytter og markerer ingenting."),
    "flag": ("Skift {name} til Markér?",
             "Spam bliver liggende i indbakken og får et skjult spam-mærke. Mærket vises kun i enkelte "
             "mailprogrammer (fx Thunderbird) – på telefonen ser du ingen forskel. Brug Filtrér for at "
             "få spam ud af indbakken."),
    "move": ("Skift {name} til Filtrér?",
             "Spam flyttes til mappen “{junk}” efter {grace} sekunder. Intet slettes."),
}

# (key, label, kind, lo, hi, hint)
ADVANCED_FIELDS: tuple[tuple[str, str, str, int, int, str], ...] = (
    ("move_grace_seconds", "Ventetid før flytning", "int", 0, 3600,
     "Sekunder fra scanning til flytning. Giv beskeden et flag (stjerne) i ventetiden for at beholde den."),
    ("max_moves_per_hour", "Maks. flytninger pr. time", "int", 1, 1000,
     "Sikkerhedsgrænse: flere flytninger end dette sætter filteret på pause for kontoen."),
    ("junk_poll_interval", "Tjek spam-mappen hvert", "int", 60, 3600,
     "Sekunder mellem tjek af spam-mappen (kun beskedhoveder)."),
    ("poll_interval", "Fuld gennemgang hvert", "int", 60, 86400,
     "Sekunder mellem fulde gennemgange af indbakken ud over IDLE."),
    ("learn_from_moves", "Lær af mine flytninger", "bool", 0, 1,
     "Når du selv flytter en besked til eller fra spam, lærer filteret af det."),
    ("provider_bonus", "Brug udbyderens spam-vurdering", "bool", 0, 1,
     "Lægger point til, når udbyderen selv har kaldt beskeden spam."),
)

JOB_STATUS = {
    "queued": ("I kø", "neutral"),
    "running": ("Kører", "brand"),
    "cancel_requested": ("Stopper…", "warn"),
    "done": ("Færdig", "ok"),
    "failed": ("Fejlede", "bad"),
    "cancelled": ("Annulleret", "neutral"),
}
JOB_KIND = {"spam": ("Spam", "bad"), "ham": ("Legitim", "ok"), "calibrate": ("Kalibrering", "info")}
PROVIDER_FILTERS = (("any", "Alle beskeder"), ("provider_spam", "Kun dem udbyderen kaldte spam"),
                    ("provider_clean", "Kun dem udbyderen ikke kaldte spam"))
ACTIVE_JOB = ("queued", "running", "cancel_requested")

EVENT_LABELS: dict[str, tuple[str, str]] = {
    "scan": ("Scannet", "neutral"), "pending_move": ("Flytning planlagt", "warn"),
    "moved_to_junk": ("Flyttet til spam", "bad"), "flagged": ("Markeret som spam", "warn"),
    "flag_failed": ("Markering fejlede", "bad"), "move_failed": ("Flytning fejlede", "bad"),
    "move_retry": ("Flytning forsøgt igen", "warn"), "user_rescued": ("Flyttet tilbage af bruger", "info"),
    "user_junked": ("Flyttet til spam af bruger", "info"), "provider_junk": ("Fanget af udbyder", "neutral"),
    "manual_release": ("Frigivet", "info"), "manual_mark_spam": ("Flyttet til spam manuelt", "bad"),
    "learn_spam": ("Lært som spam", "brand"), "learn_ham": ("Lært som legitim", "ok"),
    "learn_failed": ("Læring fejlede", "bad"), "learn_error": ("Læring fejlede", "bad"),
    "learn_skipped": ("Læring sprunget over", "neutral"), "learn_giveup": ("Læring opgivet", "warn"),
    "learn_flipflop_block": ("Læring blokeret (frem og tilbage)", "warn"),
    "rate_limited": ("Grænse nået", "warn"), "scan_failed": ("Scanning fejlede", "bad"),
    "scan_giveup": ("Scanning opgivet", "bad"), "scan_recovered": ("Scanning lykkedes igen", "ok"),
    "scan_oversize": ("For stor til scanning", "neutral"), "skipped_no_msgid": ("Uden Message-ID", "neutral"),
    "scan_bookmark_init": ("Startpunkt sat", "neutral"), "conn_ok": ("Forbundet", "ok"),
    "conn_error": ("Forbindelsesfejl", "bad"), "login_failed": ("Login fejlede", "bad"),
    "folder_created": ("Mappe oprettet", "info"), "rspamd_unavailable": ("rspamd utilgængelig", "bad"),
    "safe_mode": ("Sikker tilstand", "warn"), "safe_mode_exit": ("Sikker tilstand ophævet", "ok"),
    "uidvalidity_change": ("Mappe nulstillet (UIDVALIDITY)", "warn"),
    "junk_poll_error": ("Fejl ved tjek af spam-mappe", "bad"), "junk_reconcile": ("Spam-mappe afstemt", "neutral"),
    "pending_canceled": ("Flytning annulleret", "neutral"), "pending_lost": ("Flytning mistet", "warn"),
    "pending_moves_cleared": ("Planlagte flytninger ryddet", "neutral"),
    "pending_canceled_uidvalidity": ("Flytning annulleret (mappe nulstillet)", "warn"),
    "train_job_done": ("Træningsjob færdigt", "ok"), "train_job_failed": ("Træningsjob fejlede", "bad"),
    "reload_requested": ("Genstart anmodet", "info"), "unhandled_error": ("Uventet fejl", "bad"),
    "move_skipped_rule": ("Flytning annulleret (Altid igennem)", "ok"),
    "vacuum_failed": ("Databaseoprydning fejlede", "warn"), "trained_moved": ("Trænet besked flyttet", "neutral"),
    # 2.1 engine
    "circuit_open": ("Flytning sat på pause (sikring)", "bad"), "circuit_resumed": ("Flytning genoptaget", "ok"),
    "force_unverified": ("Altid igennem ikke bekræftet", "warn"), "login_limited": ("Udbyder begrænser forbindelser", "warn"),
    "move_repaired": ("Afbrudt flytning gjort færdig", "ok"), "move_repair_kept": ("Afbrudt flytning: beholdt", "info"),
    "move_repair_retry": ("Afbrudt flytning forsøges igen", "warn"),
    "move_repair_giveup": ("Afbrudt flytning opgivet", "warn"),
    "autolearn_spam": ("Lært som spam automatisk", "brand"), "autolearn_ham": ("Lært som legitim automatisk", "ok"),
    "autolearn_reverted": ("Automatisk læring fortrudt", "neutral"),
    "receipt_sent": ("Daglig kvittering lagt i indbakken", "ok"), "receipt_failed": ("Daglig kvittering fejlede", "bad"),
    "thread_stale": ("Kontoens tråd svarer ikke", "warn"),
    # 2.1 services
    "found_to_inbox": ("Fundet og flyttet til indbakken", "ok"), "undo_release": ("Fortrudt flytning", "info"),
    "undo_job_done": ("Fortrydelse færdig", "ok"), "undo_job_failed": ("Fortrydelse afbrudt", "bad"),
    "undo_job_cancelled": ("Fortrydelse stoppet", "neutral"),
    # 2.1 auto-allow from the mail app
    "rule_auto_allow": ("Afsender tilladt automatisk (flyttet ud af spam)", "ok"),
    "rule_auto_allow_removed": ("Automatisk tilladelse fjernet (flyttet til spam)", "warn"),
    "rule_auto_allow_skipped": ("Ikke tilladt automatisk (Altid igennem gælder)", "neutral"),
    # 2.12 (#8/#9) rules versus the user's moves to Junk; newsletters not learned as spam
    "junk_rule_conflict": ("Flyttet til Junk trods en tilladelse (Tjek disse)", "warn"),
    "junk_auto_block": ("Afsender blokeret for kontoen efter gentagen spam", "warn"),
    "junk_auto_block_removed": ("Automatisk spamblokering fjernet efter brugerens rettelse", "ok"),
    "junk_block_suggested": ("Forslag: bloker afsenderen for kontoen", "info"),
    "learn_skip_newsletter": ("Ikke lært som spam – almindeligt nyhedsbrev", "neutral"),
    "campaign_local_preference": ("Personligt nyhedsbrevsvalg – andre konti er uberørte", "neutral"),
    # 2.2
    "own_domain_uribl": ("Eget domæne på en domæneliste", "warn"),
    "ham_guard": ("Ikke lært som legitim (læringsvagt)", "warn"),
    "learn_list_queued": ("Læreliste sat i kø", "info"), "learn_list_done": ("Læreliste færdig", "ok"),
    "weekly_report_sent": ("Ugerapport lagt i indbakken", "ok"), "weekly_report_failed": ("Ugerapport fejlede", "bad"),
    # 2.3 (B10-B14) known contacts
    "contacts_sync_complete": ("Kendte kontakter: første gennemgang færdig", "ok"),
    "contacts_key_regenerated": ("Kendte kontakter lært forfra (ny nøgle)", "warn"),
    "contacts_uidvalidity": ("Sendt-mappe nulstillet – læses igen", "neutral"),
    "contact_demoted": ("Kendt kontakt fjernet (lagt i spam)", "warn"),
    "contact_removed": ("Kendt kontakt fjernet", "neutral"), "contact_restored": ("Kendt kontakt gendannet", "ok"),
    "contacts_sync_requested": ("Opdatering af kendte kontakter bestilt", "info"),
    "reply_recheck": ("Tjekket igen: svar på din mail", "info"),
    # 2.3 (B16/B17) threats and attachments
    "threat_detected": ("Farlig mail fundet", "bad"),
    # 2.3.6 (B22) lookalike domains
    "lookalike_registered": ("Nyt domæne ligner jeres", "bad"),
    "lookalike_watch_done": ("Ugentlig kontrol af lignende domæner", "neutral"),
    "lookalike_watch_failed": ("Kontrol af lignende domæner fejlede", "warn"),
    "lookalike_watch_requested": ("Kontrol af lignende domæner bestilt", "info"),
    "lookalike_allowed": ("Markeret som ikke en efterligning", "info"),
    "lookalike_unallowed": ("Igen set som mulig efterligning", "neutral"),
    "lookalike_acked": ("Nyt lignende domæne markeret som set", "neutral"),
    # 2.7 Falske afsendernavne
    "namespoof_hit": ("Falsk afsendernavn (en af jeres egne)", "bad"),
    "namespoof_trial": ("Prøv: falsk afsendernavn ville have fået point", "info"),
    "namespoof_mode": ("Falske afsendernavne: Fra/Prøv/Til ændret", "info"),
    "namespoof_seeded": ("Beskyttede navne hentet fra Sendt post", "neutral"),
    # 2.6 (A2) the same spam in several mailboxes, (A6) protected inbox watch
    "campaign_move": ("Samme spam som i en anden postkasse", "bad"),
    "campaign_shadow": ("Samme spam – ville være flyttet", "warn"),
    "campaign_skipped": ("Samme spam – ikke flyttet", "neutral"),
    "campaign_failed": ("Samme spam – fejlede", "warn"),
    "campaign_sweep": ("Samme spam søgt i alle postkasser", "info"),
    "campaign_cancelled": ("Samme spam – annulleret, kilden er frigivet", "neutral"),
    "campaign_deferred": ("Samme spam – venter (timeloft)", "neutral"),
    "fuzzy_added": ("Lagt i fuzzy-databasen", "brand"), "fuzzy_failed": ("Fuzzy-databasen svarede ikke", "neutral"),
    "fuzzy_removed": ("Fjernet fra fuzzy-databasen", "neutral"),
    "protected_watch_alert": ("Spam samler sig i en beskyttet indbakke", "warn"),
    "threat_force_pass": ("Farlig mail sluppet igennem (Altid igennem)", "warn"),
    "threat_rescue_ignored_learning": ("Farlig mail flyttet ud – ikke lært", "warn"),
    "threat_ham_refused": ("Farlig mail ikke lært som legitim", "warn"),
    "threat_release": ("Farlig mail frigivet af administrator", "warn"),
    "threat_release_refused": ("Frigivelse af farlig mail afvist", "bad"),
    "attach_exception": ("Farlig vedhæftning tilladt (undtagelse)", "info"),
    "attach_exception_unverified": ("Undtagelse for vedhæftning ikke brugt (ubekræftet afsender)", "warn"),
    "attach_exception_added": ("Undtagelse for vedhæftninger tilføjet", "info"),
    "attach_exception_removed": ("Undtagelse for vedhæftninger fjernet", "neutral"),
    # 2.3 (B19) rescans
    "zap_move": ("Fanget ved genscanning", "bad"), "zap_rescore": ("Genscannet", "neutral"),
    "would_have_zapped": ("Genscanning: ville være flyttet", "warn"),
    "zap_skipped": ("Genscanning sprunget over", "neutral"),
    "zap_skipped_read": ("Genscanning: læst, ikke flyttet", "neutral"),
    "zap_failed": ("Genscanning fejlede", "warn"),
    "av_rescan_clean": ("Virusscannet igen – ingen virus", "neutral"),
    "av_rescan_skipped": ("Virus-genscanning sprunget over", "neutral"),
    # 2.3 (B29)
    "weekly_report_mailed": ("Ugerapport sendt på mail", "ok"),
    # 2.3 follow-up: Straks-advarsel and 'Byg Bayes op på ny'
    "threat_notice_sent": ("Straks-advarsel lagt i indbakken", "warn"),
    "threat_notice_failed": ("Straks-advarsel fejlede", "bad"),
    "threat_alert_mailed": ("Alarm om farlig mail sendt til administrator", "warn"),
    "bayes_rebuild_started": ("Bayes bygges op på ny", "info"),
    "bayes_rebuild_done": ("Bayes er bygget op på ny", "ok"),
    "bayes_restored": ("Tidligere Bayes gendannet", "warn"),
    # 2.6 (A4) newsletters
    "newsletter_move": ("Flyttet til nyhedsbreve", "info"),
    "newsletter_kept": ("Nyhedsbrev flyttet tilbage – afsenderen bliver i indbakken", "ok"),
    "newsletter_move_failed": ("Flytning til nyhedsbreve fejlede", "warn"),
    "newsletter_folder_invalid": ("Mappen til nyhedsbreve er en spam- eller systemmappe – intet flyttet", "bad"),
}

# 2.3: Danish names of the new daily counters (stats_daily metrics).
STAT_LABELS: dict[str, str] = {
    "known_contact": "Beskyttet af kendte kontakter", "reply_detected": "Svar på dine mails",
    "first_contact": "Første mail fra afsenderen", "established": "Faste afsendere",
    "threat_detected": "Trusler stoppet", "zapped": "Flyttet efterfølgende",
    "would_have_zapped": "Ville være flyttet efterfølgende",
    "threat_notice_sent": "Straks-advarsler sendt",
    # 2.6 (A4)
    "newsletter_shadow": "Nyhedsbreve, der ville være flyttet", "newsletter_moved": "Nyhedsbreve flyttet",
    "newsletter_kept": "Nyhedsbreve flyttet tilbage",
    # 2.6 (C2), registered in 2.11.1
    "dmarc_reports": "DMARC-rapporter læst", "dmarc_moved": "DMARC-rapporter flyttet",
}

AUDIT_LABELS: dict[str, str] = {
    "login": "Login", "logout": "Log ud", "rule_add": "Regel tilføjet", "rule_delete": "Regel slettet",
    "rule_kind": "Regel skiftet", "rule_force": "Altid igennem ændret", "rule_restore": "Regel gendannet",
    "mail_release": "Frigivet", "mail_release_allow": "Frigivet + tilladt", "mail_mark_spam": "Flyttet til spam",
    "mail_learn_ham": "Lært som legitim", "mail_learn_spam": "Lært som spam",
    "config_changed_externally": "accounts.yml ændret udefra",
    "account_add": "Konto tilføjet", "account_remove": "Konto fjernet", "account_mode": "Tilstand ændret",
    "account_threshold": "Følsomhed ændret", "account_junk": "Spam-mappe ændret",
    "account_enabled": "Pause/genoptag", "account_connection": "Forbindelse ændret",
    "account_secret": "Adgangskode gemt", "account_advanced": "Avancerede indstillinger",
    "account_test": "Forbindelse testet", "account_folders_refresh": "Mappeliste opdateret",
    "train_queue": "Træningsjob oprettet", "train_cancel": "Træningsjob annulleret",
    "calibration_queue": "Kalibrering oprettet", "train_preset": "Forslag startet",
    "filter_restart": "Filter genstartet", "user_add": "Bruger oprettet", "user_password": "Adgangskode skiftet",
    "user_scope": "Adgang ændret", "user_access": "Adgang ændret", "user_remove": "Bruger slettet",
    # 2.5.0 push notifications (Min konto -> Beskeder på denne enhed, sfctl push-reset)
    "push_subscribe": "Beskeder slået til på en enhed", "push_unsubscribe": "Beskeder slået fra på en enhed",
    "push_remove": "Enhed fjernet fra beskeder", "push_test": "Testbesked sendt",
    "push_reset": "Beskeder nulstillet (nye nøgler)",
    "user_logout_all": "Logget ud overalt", "passkey_reset": "Alle passkeys fjernet",
    "login_2fa": "To-trins-kode", "twofa_enable": "To-trins-login slået til",
    "twofa_disable": "To-trins-login slået fra", "twofa_recovery_new": "Nye genoprettelseskoder",
    "twofa_required": "To-trins-login krævet", "twofa_reset": "To-trins-login nulstillet",
    "settings_external_url": "Ekstern adresse ændret",
    "find_mail": "Søgt i postkassen", "find_move": "Fundet mail flyttet til indbakken",
    "undo_moves": "Fortryd flytninger startet", "undo_cancel": "Fortryd flytninger stoppet",
    "account_resume_moves": "Flytning genoptaget", "account_threshold_suggestion": "Forslag til følsomhed brugt",
    "threshold_suggestion_dismiss": "Forslag til følsomhed afvist",
    "account_fast_move": "Flyttetider ændret", "account_protected": "Beskyttede adresser ændret",
    "account_forwarders": "Videresendere ændret", "account_receipt": "Daglig kvittering ændret",
    "account_receipt_test": "Prøvekvittering sendt", "account_display_name": "Kontonavn ændret",
    "settings_digest": "Daglig opsummering ændret",
    # 2.2
    "bayes_repair_learn": "Reparér Bayes: valgte lært som spam", "bayes_rebalance": "Bayes rebalanceret",
    "learn_list_cancel": "Læreliste stoppet", "learn_list_retry": "Læreliste prøvet igen",
    "settings_weekly": "Ugerapport ændret", "weekly_send": "Ugerapport sendt",
    # 2.3 (B29) mail
    "settings_smtp": "Mailserver ændret", "smtp_test": "Testmail", "settings_notify": "Notifikationer ændret",
    "mail_sent": "Mail sendt", "mail_failed": "Mail fejlede", "smtp_disable": "Mail slået fra",
    "twofa_mail_enable": "Kode på mail slået til", "twofa_mail_code": "Kode sendt på mail",
    "twofa_reauth": "To-trins-login bekræftet med kode", "security_notice": "Sikkerhedsmail",
    # 2.3 (B13) known contacts, (B17) attachments
    "known_contacts": "Kendte kontakter slået til/fra", "contact_remove": "Kendt kontakt fjernet",
    "contact_restore": "Kendt kontakt gendannet", "contacts_sync": "Kendte kontakter opdateret",
    "attachment_block": "Farlige filtyper ændret",
    "protected_domains": "Beskyttede domæner ændret", "lookalike_allow": "Markeret som ikke en efterligning",
    "lookalike_unallow": "Efterligning-undtagelse fjernet", "lookalike_ack": "Nyt lignende domæne markeret som set",
    "lookalike_run": "Kontrol af lignende domæner bestilt",
    "block_suggestion_dismiss": "Forslag om blokering ignoreret",  # 2.6 (A3)
    "junk_note_remove_rule": "Tilladelse fjernet efter flytninger til Junk",  # 2.12 (#8)
    "junk_note_block": "Afsender blokeret for kontoen",  # 2.12 (#8/#9)
    "junk_note_dismiss": "Regel-konflikt ignoreret", "junk_note_undo": "Automatisk blokering fjernet",
    "ha_token_create": "Home Assistant-nøgle oprettet", "ha_token_revoke": "Home Assistant-nøgle tilbagekaldt",
    # 2.11.0 API keys for programs (Adgang for programmer)
    "api_key_create": "API-nøgle lavet", "api_key_delete": "API-nøgle slettet",
    "api_key_rejected": "API-nøgle afvist", "api_keys_migrated": "Home Assistant-nøglen flyttet til API-nøgler",
    "attach_exception_add": "Undtagelse for vedhæftninger tilføjet",
    "attach_exception_remove": "Undtagelse for vedhæftninger fjernet",
    # 2.3 (owner request) where a user may log in
    "user_login_scope": "Login-sted ændret", "login_blocked_external": "Login udefra afvist (kun lokalt)",
    # 2.9.0 Kontrolrum single sign-on
    "login_kontrolrum": "Login fra Kontrolrum", "kontrolrum_sso_key": "Kontrolrum-nøgle lavet",
    "kontrolrum_sso_off": "Login fra Kontrolrum slået fra", "kontrolrum_sso_peers": "Kontrolrums adresse ændret",
    "user_kontrolrum_sso": "Må logges ind fra Kontrolrum ændret",
    # 2.3 follow-up: 'Byg Bayes op på ny' and the Straks-advarsel switch
    "bayes_rebuild": "Bayes bygget op på ny", "bayes_restore": "Tidligere Bayes gendannet",
    "account_threat_notice": "Straks-advarsel ændret",
    # 2.6 (A4)
    "account_newsletters": "Nyhedsbreve ændret", "newsletter_back": "Nyhedsbrev flyttet tilbage til indbakken",
    "newsletter_unkeep": "Afsender fjernet fra Bliver i indbakken",
    # 2.7 Falske afsendernavne
    "namespoof_mode": "Falske afsendernavne: Fra/Prøv/Til ændret", "namespoof_name": "Beskyttet navn gemt",
    "namespoof_name_remove": "Beskyttet navn fjernet", "namespoof_allow": "Adresse tilladt for beskyttet navn",
    "namespoof_seed": "Beskyttede navne hentet fra Sendt post",
}

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _actor() -> str:
    return (ui.current_user() or {}).get("name", "")


def _n(n: int, one: str, many: str) -> str:
    return f"{kit.fmt_int(n)} {one if n == 1 else many}"


def _q(name: str) -> str:
    return quote(str(name), safe="")


def _dom_id(prefix: str, name: str) -> str:
    return prefix + re.sub(r"[^A-Za-z0-9_-]", "-", str(name))


def _form(name: str, limit: int = 255) -> str:
    return (request.form.get(name) or "").strip()[:limit]


def _flag(name: str) -> bool:
    return (request.form.get(name) or "") in ("1", "on", "true", "yes")


def _int_arg(name: str, default: int = 1, lo: int = 1, hi: int = 1_000_000) -> int:
    try:
        return max(lo, min(hi, int(request.args.get(name, default))))
    except (TypeError, ValueError):
        return default


def _qs(**changes: Any) -> str:
    args = {k: v for k, v in request.args.items()}
    args.update(changes)
    clean = {k: str(v) for k, v in args.items() if v not in (None, "")}
    return ("?" + urlencode(clean)) if clean else ""


def _like(text: str) -> str:
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _thr_key(t: float) -> str:
    return f"{float(t):.1f}"


def _parse_float(text: str) -> float | None:
    try:
        return float(str(text).replace(",", ".").replace("−", "-").strip())
    except (TypeError, ValueError):
        return None


def _admin_js() -> str:
    # Page-specific behaviour (threshold preview, connection test, job
    # progress). External file: CSP script-src 'self' forbids inline JS.
    return f'<script src="{h(ui.static_url("admin.js"))}" defer></script>'


def _platform_text() -> str:
    """'vexar.example' / 'a og b' - the site config's platform domains."""
    doms = siteconfig.get_list("platform_domains")
    if not doms:
        return "jeres egne platforme (Lokal opsætning)"
    return doms[0] if len(doms) == 1 else ", ".join(doms[:-1]) + " og " + doms[-1]


def _webshop_text() -> str:
    doms = list(dict.fromkeys([*siteconfig.get_list("webshop_domains"), *siteconfig.get_list("platform_domains")]))
    if not doms:
        return ""
    joined = doms[0] if len(doms) == 1 else ", ".join(doms[:-1]) + " og " + doms[-1]
    return f" – og at al webshop-post fra {joined} kom igennem"


def _on_server() -> str:
    name = siteconfig.server_name()
    return f" til {name}" if name else ""


def _page(title: str, body: str, *, active: str, subtitle: str = "", actions_html: str = "",
          breadcrumbs: list[tuple[str, str | None]] | None = None) -> str:
    return kit.render_page(title, body + _admin_js(), active=active, subtitle=subtitle,
                           actions_html=actions_html, breadcrumbs=breadcrumbs)


def _svc(fn: str, *args: Any, default: Any = None, **kwargs: Any) -> Any:
    """Call services.<fn> but never let a service failure kill a page."""
    try:
        return getattr(ui.services, fn)(*args, **kwargs)
    except Exception as ex:  # noqa: BLE001 - page must still render
        log.warning("services.%s failed: %s", fn, type(ex).__name__)
        return default


def _bayes() -> dict:
    """bayes_stats() once per request (rspamd may be slow)."""
    if "_adm_bayes" not in g:
        g._adm_bayes = _svc("bayes_stats", default={"ok": False}) or {"ok": False}
    return g._adm_bayes


def _status(name: str) -> dict:
    return ui.account_status_map().get(name, {})


def _json_list(raw: Any) -> list:
    if isinstance(raw, list):
        return raw
    try:
        data = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return []
    return data if isinstance(data, list) else []


def _attr(acc: Any, key: str, default: Any = None) -> Any:
    return getattr(acc, key, default)


def _thr(acc: Any) -> float:
    try:
        return float(_attr(acc, "threshold", 8.0))
    except (TypeError, ValueError):
        return 8.0


def _acc_or_404(name: str) -> Any:
    acc = ui.account_by_name(name)
    if acc is None:
        abort(404)
    return acc


def _identity(acc: Any) -> str:
    try:
        return str(ui.engine.bayes_identity(acc))
    except Exception:  # noqa: BLE001 - fake/older engine
        return str(_attr(acc, "bayes_user", None) or _attr(acc, "user", ""))


# ---------------------------------------------------------------------------
# Config + secrets
# ---------------------------------------------------------------------------


class UserError(ValueError):
    """Rejection with a Danish text that can be shown as-is."""


def _entry(raw: dict, name: str) -> dict:
    for a in raw.get("accounts") or []:
        if isinstance(a, dict) and str(a.get("name")) == name:
            return a
    raise UserError("Kontoen findes ikke i accounts.yml.")


def _write_config(mutator: Callable[[dict], Any], action: str, *, account: str = "",
                  detail: str = "") -> str | None:
    """save_config wrapper: None on success, else a Danish error text."""
    try:
        ui.save_config(mutator, _actor(), action, account=account, detail=detail)
        return None
    except UserError as ex:
        return str(ex)
    except ValueError as ex:  # engine validation (short English text)
        return f"Ændringen blev afvist: {str(ex).strip()[:220] or 'ugyldig værdi'}"
    except (OSError, yaml.YAMLError, sqlite3.Error) as ex:
        log.error("config write failed: %s", type(ex).__name__)
        return "Konfigurationen kunne ikke gemmes. Prøv igen."


def _set_changed(entry: dict, acc: Any, key: str, value: Any) -> bool:
    """Write key only when it differs from the effective value (no
    copying of defaults into the account entry)."""
    if acc is not None and _attr(acc, key, object()) == value:
        return False
    entry[key] = value
    return True


def secrets_dir() -> Path:
    return Path(ui.STATE_DIR) / "imap-secrets"


def secret_path(name: str) -> Path:
    if not ACCOUNT_NAME_RE.fullmatch(name or ""):
        raise ValueError("invalid account name")
    return secrets_dir() / name


def _valid_password(pw: str) -> bool:
    return bool(pw) and len(pw) <= 1024 and not any(c in pw for c in "\r\n\x00")


def write_secret(name: str, password: str) -> Path:
    """Atomically write an IMAP password to imap-secrets/<name> (0600)."""
    if not _valid_password(password):
        raise ValueError("invalid password")
    path = secret_path(name)
    d = path.parent
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".secret-", dir=d)
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(password)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        try:
            dfd = os.open(d, os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    finally:
        tmp.unlink(missing_ok=True)
    return path


def _archive_secret(name: str, password_file: str | None) -> None:
    """Move a removed account's secret out of the active path (kept for a
    short rollback period, readable only by the state dir owner). Only
    files inside imap-secrets/ are touched."""
    try:
        path = Path(password_file) if password_file else secret_path(name)
        if path.parent.resolve() != secrets_dir().resolve() or not path.is_file():
            return
        archive = Path(ui.STATE_DIR) / "removed-secrets"
        archive.mkdir(mode=0o700, exist_ok=True)
        path.replace(archive / f"{int(time.time())}-{path.name}")
    except (OSError, ValueError) as ex:
        log.warning("could not archive secret of %s: %s", name, type(ex).__name__)


# ---------------------------------------------------------------------------
# Connection tests + tokens
# ---------------------------------------------------------------------------


def _token_mac(actor: str, host: str, port: int, user: str, password: str, ts: int) -> str:
    key = str(ui.app.secret_key or "").encode()
    pw = hashlib.sha256(password.encode()).hexdigest()
    msg = f"conn-test|{actor}|{host.lower()}|{port}|{user}|{pw}|{ts}".encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def make_test_token(host: str, port: int, user: str, password: str) -> str:
    ts = int(time.time())
    return f"{ts}.{_token_mac(_actor(), host, port, user, password, ts)}"


def check_test_token(token: str, host: str, port: int, user: str, password: str) -> bool:
    ts_s, _, mac = (token or "").partition(".")
    try:
        ts = int(ts_s)
    except ValueError:
        return False
    if not mac or not 0 <= time.time() - ts <= TEST_TOKEN_TTL:
        return False
    return hmac.compare_digest(mac, _token_mac(_actor(), host, port, user, password, ts))


def _run_test(host: str, port: int, user: str, password: str) -> dict:
    res = _svc("test_connection", host, port, user, password, default=None)
    if not isinstance(res, dict):
        res = {"ok": False, "code": "other", "text": "Forbindelsen kunne ikke testes."}
    return res


def _public_test(res: dict) -> dict:
    """What the browser gets back from a test (never the password)."""
    folders = []
    for f in (res.get("folders") or [])[:400]:
        if isinstance(f, dict) and isinstance(f.get("name"), str):
            folders.append({"name": f["name"], "flags": [str(x) for x in (f.get("flags") or [])][:6],
                            "messages": f.get("messages")})
    sug = res.get("suggested") or {}
    return {"ok": bool(res.get("ok")), "code": str(res.get("code") or ""), "text": str(res.get("text") or ""),
            "capabilities": [str(c) for c in (res.get("capabilities") or [])][:60],
            "move_method": str(res.get("move_method") or "none"), "idle": bool(res.get("idle")),
            "folders": folders, "suggested": {"junk": sug.get("junk"), "trash": sug.get("trash")},
            "move_label": MOVE_METHOD_TEXT.get(str(res.get("move_method") or "none"), ("", ""))[0]}


MOVE_METHOD_TEXT = {
    "MOVE": ("MOVE", "Serveren flytter beskeder atomisk."),
    "UIDPLUS": ("COPY + UID EXPUNGE", "Ingen MOVE, men UIDPLUS gør flytningen sikker: kun de flyttede beskeder slettes fra indbakken."),
    "none": ("Ikke understøttet", "Hverken MOVE eller UIDPLUS – brug Markér i stedet for Filtrér."),
}


def _conn_values(acc: Any | None, fallback_user: str = "") -> tuple[str, int | None, str, str, str | None]:
    """(host, port, user, password, error) from the form; a blank password
    on an existing account means "keep the stored one"."""
    host = _form("imap_host", 253)
    user = _form("user", 254) or fallback_user
    port_raw = _form("imap_port", 6) or "993"
    password = request.form.get("password") or ""
    try:
        port = int(port_raw)
    except ValueError:
        port = None
    if not HOST_RE.fullmatch(host):
        return host, port, user, password, "Skriv en gyldig IMAP-server, fx imap.firma.dk."
    if port is None or not 1 <= port <= 65535:
        return host, port, user, password, "Porten skal være et tal mellem 1 og 65535."
    if not user or len(user) > 254 or any(c in user for c in "\r\n\x00"):
        return host, port, user, password, "Skriv brugernavnet (normalt hele e-mailadressen)."
    if password and not _valid_password(password):
        return host, port, user, password, "Adgangskoden indeholder ugyldige tegn."
    if not password:
        if acc is None:
            return host, port, user, password, "Skriv adgangskoden til postkassen."
        same = (host.lower().rstrip(".") == str(_attr(acc, "imap_host", "") or "").lower().rstrip(".")
                and port == int(_attr(acc, "imap_port", 993) or 993)
                and user == str(_attr(acc, "user", "") or ""))
        if not same:
            # Never send the stored password to a server/user it was not
            # saved for (a typo or a hostile host would receive it).
            return host, port, user, password, "Skriv adgangskoden igen, når server, port eller brugernavn ændres."
        try:
            password = str(ui.engine.read_secret(acc))
        except Exception:  # noqa: BLE001 - missing/unreadable secret
            return host, port, user, "", "Der er ingen gemt adgangskode – skriv den for at teste."
    return host, port, user, password, None


# ---------------------------------------------------------------------------
# Status pieces
# ---------------------------------------------------------------------------


def _live_dot(state: str) -> str:
    return kit.status_dot(state)


def _account_folders(name: str) -> list[dict]:
    out = _svc("account_folders", name, default=[]) or []
    return [f for f in out if isinstance(f, dict) and isinstance(f.get("name"), str)]


def _provider_junk_folder(acc: Any, folders: list[dict]) -> str | None:
    """The provider's own spam folder (\\Junk or a well-known name), not ours."""
    own = str(_attr(acc, "junk", "") or "").lower()
    for f in folders:
        if "\\junk" in [str(x).lower() for x in f.get("flags") or []] and f["name"].lower() != own:
            return f["name"]
    for cand in ("Junk", "Spam", "INBOX.Junk", "INBOX.Spam", "Junk E-Mail", "Uønsket post"):
        for f in folders:
            if f["name"].lower() == cand.lower() and f["name"].lower() != own:
                return f["name"]
    return None


def _archive_folders(acc: Any, folders: list[dict]) -> list[str]:
    out = []
    for f in folders:
        low = f["name"].lower()
        leaf = re.split(r"[./]", low)[-1]
        if leaf in ("archive", "archives", "arkiv", "arkiveret", "arkiver", "all mail") \
                or "\\archive" in [str(x).lower() for x in f.get("flags") or []]:
            out.append(f["name"])
    return out


def _folder_choices(acc: Any, folders: list[dict]) -> list[tuple[str, str]]:
    """Spam-folder picker options: the current folder first, then every
    detected folder except INBOX, then "Opret ny mappe…"."""
    current = str(_attr(acc, "junk", DEFAULT_JUNK) or DEFAULT_JUNK) if acc is not None else DEFAULT_JUNK
    names = [f["name"] for f in folders]
    inbox = str(_attr(acc, "inbox", "INBOX") or "INBOX").lower() if acc is not None else "inbox"
    opts: list[tuple[str, str]] = []
    if current not in names:
        opts.append((current, f"{current} (oprettes automatisk)"))
    if DEFAULT_JUNK not in names and current != DEFAULT_JUNK:
        opts.append((DEFAULT_JUNK, f"{DEFAULT_JUNK} (anbefalet – oprettes automatisk)"))
    for f in folders:
        if f["name"].lower() == inbox:
            continue
        flags = [str(x).lower() for x in f.get("flags") or []]
        extra = " · udbyderens spam-mappe" if "\\junk" in flags else ""
        cnt = f" · {kit.fmt_int(f['messages'])} beskeder" if isinstance(f.get("messages"), int) else ""
        label = f["name"] + (" (anbefalet)" if f["name"] == DEFAULT_JUNK else "") + extra + cnt
        opts.append((f["name"], label))
    opts.append((NEW_FOLDER, "Opret ny mappe…"))
    return opts


def _valid_folder(name: str, acc: Any | None) -> str | None:
    """Danish error text or None."""
    if not name:
        return "Vælg eller skriv en mappe."
    if len(name) > 200 or any(c in name for c in "\r\n\x00*%\"\\") or name != name.strip():
        return "Mappenavnet indeholder ugyldige tegn."
    inbox = str(_attr(acc, "inbox", "INBOX") or "INBOX") if acc is not None else "INBOX"
    if name.lower() in (inbox.lower(), "inbox"):
        return "Spam-mappen kan ikke være indbakken."
    return None


# ---------------------------------------------------------------------------
# Konti: shared pieces
# ---------------------------------------------------------------------------


def golive_done(name: str) -> bool:
    return ui.settings_get(f"golive:{name}") is not None


def _mode_needs_checklist(acc: Any) -> bool:
    return _attr(acc, "mode", "shadow") != "move" and not golive_done(acc.name)


def _mode_confirm(acc: Any, mode: str) -> str:
    title, text = MODE_CONFIRM[mode]
    fill = {"name": acc.name, "junk": _attr(acc, "junk", DEFAULT_JUNK),
            "grace": _attr(acc, "move_grace_seconds", 60)}
    return kit.confirm_attrs(title.format(**fill), text.format(**fill),
                             confirm=f"Skift til {kit.mode_label(mode)}", tone="primary")


def _mode_segmented(acc: Any) -> str:
    """Compact mode control for the account cards: three submit buttons
    (each with its own confirm); the first switch to Filtrér opens the
    go-live checklist instead (a page without JS)."""
    cur = _attr(acc, "mode", "shadow")
    parts = []
    for m in ("shadow", "flag", "move"):
        label = h(kit.mode_label(m))
        if m == cur:
            parts.append(f'<span class="seg-opt is-active" aria-current="true"><span>{label}</span></span>')
        elif m == "move" and _mode_needs_checklist(acc):
            parts.append(f'<a class="seg-opt" href="/accounts/{h(_q(acc.name))}/golive" '
                         f'data-open-modal="{_dom_id("golive-", acc.name)}"><span>{label}</span></a>')
        else:
            parts.append(f'<button class="seg-opt" type="submit" name="mode" value="{m}" '
                         f'{_mode_confirm(acc, m)}><span>{label}</span></button>')
    inner = (kit.hidden("next", request.path)
             + f'<div class="segmented seg-mode" role="group" aria-label="Tilstand for {h(acc.name)}">'
             + "".join(parts) + "</div>")
    return kit.post_form(f"/accounts/{_q(acc.name)}/mode", inner, cls="mode-form")


def _mode_tiles(acc: Any) -> str:
    """Large mode picker for the account page."""
    cur = _attr(acc, "mode", "shadow")
    tiles = []
    for m in ("shadow", "flag", "move"):
        tone = kit.MODE_TONES.get(m, "neutral")
        inner = (f'<span class="mode-ic">{kit.icon(MODE_ICONS[m])}</span>'
                 f'<span class="mode-txt"><b>{h(kit.mode_label(m))}</b><span>{h(kit.MODE_HINTS.get(m, ""))}</span></span>')
        if m == cur:
            tiles.append(f'<div class="mode-tile tone-{tone} is-active" aria-current="true">{inner}'
                         f'<span class="mode-check">{kit.icon("check")}</span></div>')
        elif m == "move" and _mode_needs_checklist(acc):
            tiles.append(f'<a class="mode-tile tone-{tone}" href="/accounts/{h(_q(acc.name))}/golive" '
                         f'data-open-modal="{_dom_id("golive-", acc.name)}">{inner}'
                         f'<span class="mode-check">{kit.icon("chevron-right")}</span></a>')
        else:
            tiles.append(f'<button class="mode-tile tone-{tone}" type="submit" name="mode" value="{m}" '
                         f'{_mode_confirm(acc, m)}>{inner}<span class="mode-check">{kit.icon("chevron-right")}</span></button>')
    inner = kit.hidden("next", request.path) + '<div class="mode-tiles">' + "".join(tiles) + "</div>"
    return kit.post_form(f"/accounts/{_q(acc.name)}/mode", inner, cls="mode-form")


def _golive_modal(acc: Any) -> str:
    """The go-live checklist modal; its body loads lazily (it asks rspamd
    for Bayes status) from the same page the no-JS link opens."""
    if not _mode_needs_checklist(acc):
        return ""
    url = f"/accounts/{_q(acc.name)}/golive?fragment=1"
    body = (f'<div data-fragment="{h(url)}" aria-busy="true">{kit.skeleton(4)}</div>')
    return kit.modal(_dom_id("golive-", acc.name), f"Klar til Filtrér på {acc.name}?", body,
                     '<button type="button" class="btn btn-secondary" data-close-modal>Annullér</button>')


def golive_checks(acc: Any) -> tuple[list[dict], bool]:
    """Checklist before the first switch to Filtrér: (items, blocked)."""
    st = _status(acc.name)
    state = ui.account_state(acc)
    items: list[dict] = []
    blocked = False

    def add(tone: str, title: str, text: str) -> None:
        items.append({"tone": tone, "title": title, "text": text})

    if state in ("auth_failed", "error", "config_error"):
        add("bad", "Forbindelsen fejler", st.get("detail") or "Ret forbindelsen under Forbindelse og test den.")
        blocked = True
    elif state in ("idle", "working") or st.get("connected_since"):
        since = st.get("connected_since")
        add("ok", "Forbindelsen virker", f"Forbundet {kit.ago(since)}." if since else "Kontoen er forbundet.")
    elif state == "paused":
        add("warn", "Kontoen er på pause", "Tilstanden gælder, når du genoptager kontoen.")
    else:
        add("warn", "Forbindelsen er ikke bekræftet endnu",
            "Kontoen har ikke meldt status endnu. Test forbindelsen, før du går videre.")

    mm = st.get("move_method")
    if mm in ("MOVE", "UIDPLUS"):
        label, text = MOVE_METHOD_TEXT[mm]
        add("ok", f"Flyttemetode: {label}", text)
    elif mm == "none":
        add("bad", "Serveren kan ikke flytte beskeder sikkert", MOVE_METHOD_TEXT["none"][1])
        blocked = True
    else:
        add("warn", "Flyttemetoden kendes ikke endnu", "Den aflæses, første gang filteret er forbundet.")

    junk = _attr(acc, "junk", DEFAULT_JUNK)
    if not _attr(acc, "junk_explicit", False):
        # Without an explicit `junk:` the engine picks the provider's own
        # spam folder (SPECIAL-USE \Junk) - not what Filtrér promises.
        add("bad", "Vælg Spamfilter-mappen først",
            "Kontoen har ingen fast spam-mappe, så spam ville havne i udbyderens egen spam-mappe. "
            "Gem en spam-mappe (fx “Spamfilter”) under kontoens indstillinger.")
        blocked = True
    elif st.get("junk_exists") == 1:
        add("ok", f"Spamfilter-mappen “{junk}” findes", "Spam flyttes hertil. Udbyderens egen Junk-mappe røres ikke.")
    else:
        add("info", f"Spamfilter-mappen “{junk}” oprettes automatisk",
            "Mappen oprettes og abonneres, første gang filteret starter i Filtrér.")

    b = _bayes()
    if not b.get("ok"):
        add("warn", "Bayes-status kunne ikke hentes", "rspamd svarer ikke lige nu. Scorerne virker stadig uden Bayes.")
    else:
        need = int(b.get("min_learns") or 200)
        spam, ham = int(b.get("spam_learned") or 0), int(b.get("ham_learned") or 0)
        if spam >= need and ham >= need:
            add("ok", "Bayes er trænet", f"{kit.fmt_int(spam)} spam og {kit.fmt_int(ham)} legitime beskeder lært.")
        else:
            add("warn", "Bayes er ikke færdigtrænet",
                f"{kit.fmt_int(spam)}/{kit.fmt_int(need)} spam og {kit.fmt_int(ham)}/{kit.fmt_int(need)} legitime. "
                "Scorerne bygger indtil videre på regler og blokeringslister – overvej at træne først.")

    thr = _thr(acc)
    row = ui.query("SELECT COUNT(*) AS n, SUM(our_score >= ?) AS caught, "
                   "SUM(our_score >= ? AND user_verdict = 'ham') AS fp FROM messages "
                   "WHERE account=? AND score_version = 2 AND our_score IS NOT NULL "
                   "AND COALESCE(scanned_at, first_seen) >= ?",
                   [thr, thr, acc.name, int(time.time()) - 14 * 86400], one=True)
    n = int(row["n"] or 0) if row else 0
    caught = int(row["caught"] or 0) if row else 0
    fp = int(row["fp"] or 0) if row else 0
    if n == 0:
        add("warn", "Ingen nye scorer de seneste 14 dage",
            "Lad kontoen køre i Overvåg et par dage, så du kan se, hvad der ville blive flyttet.")
    else:
        text = f"Ved grænsen {kit.fmt_score(thr)} ville {_n(caught, 'besked', 'beskeder')} af {kit.fmt_int(n)} være flyttet."
        if fp:
            text += f" {_n(fp, 'af dem', 'af dem')} har du selv frigivet – overvej en højere grænse."
        add("warn" if fp else "ok", "Seneste scorer", text)
    return items, blocked


def _checklist_html(items: list[dict]) -> str:
    ic = {"ok": "check-circle", "warn": "alert-triangle", "bad": "x-circle", "info": "info"}
    lis = "".join(
        f'<li class="check-item tone-{i["tone"]}">{kit.icon(ic.get(i["tone"], "info"))}'
        f'<div><b>{h(i["title"])}</b><span>{h(i["text"])}</span></div></li>' for i in items)
    return f'<ul class="checklist">{lis}</ul>'


def _golive_form(acc: Any, items: list[dict], blocked: bool) -> str:
    if blocked:
        return (kit.alert("Ret de røde punkter, før kontoen kan skifte til Filtrér.", "bad")
                + '<div class="form-actions">'
                + kit.button("Gå til kontoen", href=f"/accounts/{_q(acc.name)}", kind="secondary", icon="settings")
                + "</div>")
    inner = (kit.hidden("mode", "move") + kit.hidden("next", f"/accounts/{_q(acc.name)}")
             + '<label class="check-confirm"><input type="checkbox" name="golive" value="1" required>'
             '<span>Jeg har gennemgået tjeklisten. Spam må flyttes til Spamfilter-mappen.</span></label>'
             + '<div class="form-actions">'
             + kit.button("Skift til Filtrér", kind="primary", icon="shield-check") + "</div>")
    return kit.post_form(f"/accounts/{_q(acc.name)}/mode", inner, cls="golive-form")


# ---------------------------------------------------------------------------
# Konti: list
# ---------------------------------------------------------------------------


def _account_card(acc: Any) -> str:
    name = acc.name
    st = _status(name)
    state = ui.account_state(acc)
    circuit = circuit_info(name)
    tone = kit.state_tone(state)
    mode = _attr(acc, "mode", "shadow")
    detail = ""
    if state in ("error", "auth_failed", "config_error", "stale", "limited") and (st.get("detail") or st.get("last_error")):
        detail = (f'<div class="acct-detail tone-{tone}">{kit.icon("alert-circle")}'
                  f'<span>{h(st.get("detail") or st.get("last_error"))}</span></div>')
    if circuit["open"]:
        detail += (f'<div class="acct-detail tone-bad">{kit.icon("pause")}<span><b>Flytning på pause.</b> '
                   f'{h(circuit["reason"] or "Filteret flyttede usædvanligt meget.")}</span></div>'
                   + _resume_form(acc, size="sm"))
    mm = st.get("move_method")
    mm_txt = MOVE_METHOD_TEXT.get(str(mm), ("Ukendt endnu", ""))[0] if mm else "Ukendt endnu"
    junk = str(_attr(acc, "junk", DEFAULT_JUNK))
    junk_state = {1: kit.chip("findes", "ok"), 0: kit.chip("oprettes", "warn")}.get(st.get("junk_exists"), "")
    last = max(int(st.get("last_scan_at") or 0), int(st.get("last_loop_at") or 0))
    kv = kit.kv_list([
        ("Status", f'{h(kit.state_label(state))}<span class="faint"> · {h(kit.ago(last) if last else "ingen aktivitet")}</span>'),
        ("Server", f'<span class="mono">{h(_attr(acc, "imap_host", ""))}:{h(_attr(acc, "imap_port", 993))}</span>'),
        ("Flyttemetode", h(mm_txt)),
        ("Spam-mappe", f'{h(junk)} {junk_state}'),
        ("Følsomhed", f'{h(kit.sensitivity_label(_thr(acc)))} · {h(kit.fmt_score(_thr(acc)))}'),
    ])
    paused = not _attr(acc, "enabled", True)
    toggle = _enable_form(acc, size="sm")
    return (
        f'<article class="card acct-card adm-acct tone-{tone}{" is-paused" if paused else ""}" id="{_dom_id("acct-", name)}">'
        f'<div class="acct-head">{_live_dot(state)}'
        f'<div class="acct-titles"><a class="acct-name" href="/accounts/{h(_q(name))}">{ui.account_name_html(name)}</a>'
        f'<div class="acct-user">{h(_attr(acc, "user", ""))}</div></div>'
        f'{kit.chip(kit.mode_label(mode), kit.MODE_TONES.get(mode, "neutral"))}</div>'
        f"{detail}{kv}"
        f'<div class="adm-acct-mode"><span class="field-label">Tilstand</span>{_mode_segmented(acc)}</div>'
        f'<div class="adm-acct-foot">'
        + kit.button("Indstillinger", href=f"/accounts/{_q(name)}", kind="secondary", icon="settings", size="sm")
        + toggle + "</div>"
        + f'<a class="card-link adm-acct-user" href="/users/new?mailbox={h(_q(name))}">{kit.icon("user-plus")}'
          "Opret bruger til denne postkasse</a>"
        + _golive_modal(acc) + "</article>")


def _enable_form(acc: Any, *, size: str = "") -> str:
    name = acc.name
    if _attr(acc, "enabled", True):
        btn = kit.button("Sæt på pause", kind="ghost", icon="pause", size=size,
                         attrs=kit.confirm_attrs(f"Sæt {name} på pause?",
                                                 "Filteret stopper med at scanne postkassen, indtil du genoptager den. Intet bliver slettet.",
                                                 confirm="Sæt på pause"))
        return kit.post_form(f"/accounts/{_q(name)}/enabled", kit.hidden("enabled", "0") + btn)
    btn = kit.button("Genoptag", kind="primary", icon="play", size=size)
    return kit.post_form(f"/accounts/{_q(name)}/enabled", kit.hidden("enabled", "1") + btn)


@app.get("/accounts")
@ui.admin_required
def accounts_page():
    accs = ui.effective_accounts()
    err = ui.config_error()
    top = ""
    if err:
        top = kit.alert(err, "bad", title="accounts.yml kan ikke indlæses",
                        action_html='<span class="faint">Ret filen på serveren – ændringer her er slået fra, indtil den kan læses.</span>')
    add_btn = kit.button("Tilføj konto", href="/accounts/new", kind="primary", icon="plus")
    if not accs:
        body = top + kit.card(kit.empty_state(
            "Ingen postkasser endnu", "Tilføj den første postkasse. Den starter i Overvåg, så intet bliver flyttet, før du er klar.",
            "at-sign", "" if err else add_btn))
        return _page("Konti", body, active="accounts", subtitle="Postkasser, tilstande og forbindelser.")
    active = sum(1 for a in accs if _attr(a, "enabled", True))
    modes = {m: sum(1 for a in accs if _attr(a, "enabled", True) and _attr(a, "mode", "") == m) for m in ("move", "flag", "shadow")}
    summary = (
        '<div class="kpis">'
        + kit.kpi("Postkasser", len(accs), sub=f"{active} aktive" + (f", {len(accs) - active} på pause" if len(accs) > active else ""))
        + kit.kpi("Filtrér", modes["move"], sub="flytter spam", tone="brand" if modes["move"] else "")
        + kit.kpi("Markér", modes["flag"], sub="markerer spam")
        + kit.kpi("Overvåg", modes["shadow"], sub="scorer kun")
        + "</div>")
    cards = "".join(_account_card(a) for a in accs)
    body = (top + kit.card(summary)
            + f'<section class="section"><div class="section-head"><h2 class="section-title">Postkasser</h2>'
            f'<span class="muted">{_n(len(accs), "konto", "konti")}</span></div>'
            f'<div class="grid grid-auto adm-accounts">{cards}</div></section>')
    return _page("Konti", body, active="accounts", actions_html="" if err else add_btn,
                 subtitle="Postkasser, tilstande og forbindelser. Skift tilstand direkte på kortet.")


# ---------------------------------------------------------------------------
# Konti: one account
# ---------------------------------------------------------------------------


def threshold_preview(acc: Any) -> dict:
    """Counts per threshold step over the last PREVIEW_LIMIT score_version=2
    mails: caught, of those released by the user (ham), and user-marked
    spam that would slip through."""
    rows = ui.query("SELECT our_score, user_verdict FROM messages WHERE account=? AND score_version = 2 "
                    "AND our_score IS NOT NULL AND COALESCE(rule_hit, '') = '' "
                    "ORDER BY COALESCE(scanned_at, first_seen) DESC LIMIT ?", [acc.name, PREVIEW_LIMIT])
    scores = [(float(r["our_score"]), r["user_verdict"]) for r in rows]
    steps = {}
    for t in THR_STEPS:
        caught = sum(1 for s, _v in scores if s >= t)
        fp = sum(1 for s, v in scores if s >= t and v == "ham")
        miss = sum(1 for s, v in scores if s < t and v == "spam")
        steps[_thr_key(t)] = [caught, fp, miss]
    return {"m": len(scores), "steps": steps}


def _preview_texts(prev: dict, t: float) -> tuple[str, str, str]:
    m = prev["m"]
    caught, fp, miss = prev["steps"].get(_thr_key(t), [0, 0, 0])
    if not m:
        return "Ingen nye scorer endnu – forhåndsvisningen fyldes ud, når filteret har scannet post.", "", ""
    main = f"{kit.fmt_int(caught)} af de seneste {kit.fmt_int(m)} beskeder ville være fanget ({kit.fmt_pct(caught, m)})."
    fp_t = f"Heraf {_n(fp, 'besked', 'beskeder')}, som du selv har frigivet." if fp else ""
    miss_t = f"{_n(miss, 'besked', 'beskeder')}, du selv har kaldt spam, ville slippe igennem." if miss else ""
    return main, fp_t, miss_t


def _threshold_card(acc: Any) -> str:
    t = _thr(acc)
    t = min(THR_MAX, max(THR_MIN, t))
    prev = threshold_preview(acc)
    main, fp_t, miss_t = _preview_texts(prev, t)
    out_id = _dom_id("thr-val-", acc.name)
    data = json.dumps(prev, separators=(",", ":"))
    form = (
        kit.hidden("next", request.path)
        + f'<div class="thr-head"><span class="thr-value" id="{out_id}">{h(kit.fmt_score(t))}</span>'
        f'<span class="thr-label" data-thr-label>{h(kit.sensitivity_label(t))}</span></div>'
        f'<input class="range" type="range" name="threshold" min="{THR_MIN}" max="{THR_MAX}" step="{THR_STEP}" '
        f'value="{t:.1f}" data-range-output="{out_id}" data-thr-preview="{h(data)}" '
        f'aria-label="Følsomhed (grænse)">'
        '<div class="thr-scale" aria-hidden="true"><span>Streng</span><span>Normal</span><span>Lempelig</span></div>'
        f'<div class="thr-preview" aria-live="polite">{kit.icon("bar-chart")}<div>'
        f'<b data-tp="main">{h(main)}</b>'
        f'<span class="tone-warn" data-tp="fp"{"" if fp_t else " hidden"}>{h(fp_t)}</span>'
        f'<span class="tone-bad" data-tp="miss"{"" if miss_t else " hidden"}>{h(miss_t)}</span></div></div>'
        '<p class="field-hint">Lav grænse = strengere filter (mere bliver fanget). Forhåndsvisningen bruger kun '
        'scorer fra 2.0-filteret.</p>'
        f'<div class="form-actions">{kit.button("Gem følsomhed", kind="primary", icon="check")}</div>')
    return kit.card(kit.post_form(f"/accounts/{_q(acc.name)}/threshold", form, cls="thr-form"),
                    title="Følsomhed", subtitle="Fra hvilken score en besked regnes som spam.")


def _junk_card(acc: Any, folders: list[dict]) -> str:
    opts = _folder_choices(acc, folders)
    current = str(_attr(acc, "junk", DEFAULT_JUNK))
    sel_id = _dom_id("junk-sel-", acc.name)
    inner = (
        kit.hidden("next", request.path)
        + kit.form_field("Spam-mappe", kit.select("junk", opts, current,
                                                  attrs=f'id="{sel_id}" data-new-folder-select'),
                         hint="Filteret flytter spam hertil i Filtrér. Udbyderens egen Junk-mappe bliver ikke rørt.")
        + f'<div data-new-folder="{sel_id}">'
        + kit.form_field("Ny mappe", kit.input_("new_folder", "", attrs=f'id="{_dom_id("junk-new-", acc.name)}" '
                                                'placeholder="Spamfilter" autocomplete="off" maxlength="200"'),
                         hint="Bruges, når du vælger “Opret ny mappe…”. Oprettes automatisk i Markér og Filtrér.")
        + "</div>"
        + f'<div class="form-actions">{kit.button("Gem spam-mappe", kind="secondary", icon="folder")}</div>')
    refresh = kit.post_form(
        f"/accounts/{_q(acc.name)}/folders/refresh",
        kit.hidden("next", request.path)
        + kit.button("Opdater mappeliste", kind="ghost", icon="refresh", size="sm"), cls="inline-form")
    note = (f'<p class="faint small">{_n(len(folders), "mappe", "mapper")} fundet ved sidste forbindelse.</p>'
            if folders else '<p class="faint small">Mappelisten kendes, når filteret har været forbundet – eller opdater den nu.</p>')
    return kit.card(kit.post_form(f"/accounts/{_q(acc.name)}/junk", inner) + note,
                    title="Spam-mappe", subtitle="Spamfilter-mappen anbefales på alle konti.", actions=refresh)


def _connection_form(acc: Any | None, *, action: str, wizard: bool = False) -> str:
    """Host/port/user/password with "Test forbindelse"; saving needs a
    successful test (button disabled by admin.js until then)."""
    host = _attr(acc, "imap_host", "") if acc is not None else ""
    port = _attr(acc, "imap_port", 993) if acc is not None else 993
    user = _attr(acc, "user", "") if acc is not None else ""
    pid = "new" if acc is None else acc.name
    pw_attrs = (f'id="{_dom_id("pw-", pid)}" autocomplete="new-password" maxlength="1024" '
                + ('placeholder="Uændret – udfyld kun for at skifte"' if acc is not None else 'required'))
    fields = (
        '<div class="grid grid-host">'
        + kit.form_field("IMAP-server", kit.input_("imap_host", host, attrs=f'id="{_dom_id("host-", pid)}" required '
                                                                         'autocomplete="off" autocapitalize="none" spellcheck="false" data-conn'))
        + kit.form_field("Port", kit.input_("imap_port", port, type="number",
                                            attrs=f'id="{_dom_id("port-", pid)}" min="1" max="65535" required data-conn'))
        + "</div>"
        + kit.form_field("Brugernavn", kit.input_("user", user, attrs=f'id="{_dom_id("user-", pid)}" required '
                                                                   'autocomplete="off" autocapitalize="none" spellcheck="false" data-conn'),
                         hint="Normalt hele e-mailadressen.")
        + kit.form_field("Adgangskode", kit.input_("password", "", type="password", attrs=pw_attrs + " data-conn"),
                         hint="Gemmes i en separat fil, som kun filteret kan læse (0600) – aldrig i konfigurationen, og vises aldrig igen.")
    )
    if wizard:
        return fields
    result = f'<div class="test-result" data-test-result hidden></div>'
    actions = (
        '<div class="form-actions">'
        + kit.button("Test forbindelse", kind="secondary", icon="plug", attrs='name="op" value="test"')
        + kit.button("Gem forbindelse", kind="primary", icon="check",
                     attrs='name="op" value="save" data-needs-test')
        + "</div>")
    return kit.post_form(action, kit.hidden("next", request.path) + kit.hidden("tested", "") + fields
                         + result + actions, attrs="data-conn-test")


def _advanced_card(acc: Any) -> str:
    rows = []
    for key, label, kind, lo, hi, hint in ADVANCED_FIELDS:
        val = _attr(acc, key, None)
        if kind == "bool":
            rows.append(f'<div class="field field-switch">{kit.switch(key, bool(val), label)}'
                        f'<span class="field-hint">{h(hint)}</span></div>')
        else:
            rows.append(kit.form_field(label, kit.input_(key, "" if val is None else val, type="number",
                                                         attrs=f'id="{_dom_id(key + "-", acc.name)}" min="{lo}" max="{hi}" required'),
                                       hint=hint))
    inner = (kit.hidden("next", request.path) + kit.hidden("advanced", "1")
             + '<div class="form-grid adv-grid">' + "".join(rows) + "</div>"
             + f'<div class="form-actions">{kit.button("Gem avancerede indstillinger", kind="primary", icon="check")}</div>')
    return ('<details class="disclosure adv-disclosure"><summary>' + kit.icon("chevron-right")
            + "Avancerede indstillinger</summary><div class=\"disclosure-body\">"
            + kit.post_form(f"/accounts/{_q(acc.name)}/advanced", inner) + "</div></details>")


def _server_card(acc: Any, folders: list[dict]) -> str:
    st = _status(acc.name)
    caps = [str(c) for c in _json_list(st.get("capabilities"))]
    mm = st.get("move_method")
    mm_label, mm_text = MOVE_METHOD_TEXT.get(str(mm), ("Ukendt endnu", "Aflæses ved næste forbindelse."))
    idle = st.get("idle_supported")
    inbox = next((f for f in folders if f["name"].upper() == "INBOX"), None)
    pairs = [
        ("Status", f'{_live_dot(ui.account_state(acc))} {h(kit.state_label(ui.account_state(acc)))}'),
        ("Forbundet", h(kit.ago(st.get("connected_since")) if st.get("connected_since") else "–")),
        ("Seneste scanning", h(kit.ago(st.get("last_scan_at")) if st.get("last_scan_at") else "–")),
        ("Flyttemetode", f'{h(mm_label)}<span class="kv-sub">{h(mm_text)}</span>'),
        ("IDLE", h("Ja – ny post ses med det samme" if idle else ("Nej – tjekkes med interval" if idle == 0 else "–"))),
        ("Indbakke", h(_n(inbox["messages"], "besked", "beskeder") if inbox and isinstance(inbox.get("messages"), int) else "–")),
        ("Bayes-identitet", f'<span class="mono">{h(_identity(acc))}</span>'),
    ]
    if st.get("last_error"):
        pairs.append(("Seneste fejl", f'{h(st.get("last_error"))}<span class="kv-sub">{h(kit.fmt_ts(st.get("last_error_at")))}'
                                      f'{" · " + _n(int(st.get("error_count") or 0), "fejl", "fejl") if st.get("error_count") else ""}</span>'))
    cap_html = ""
    if caps:
        shown = [c for c in caps if c.upper() in ("MOVE", "UIDPLUS", "IDLE", "SPECIAL-USE", "CONDSTORE", "QRESYNC", "IMAP4REV1", "IMAP4REV2")]
        cap_html = ('<div class="cap-chips">' + "".join(kit.chip(c, "brand" if c.upper() in ("MOVE", "UIDPLUS", "IDLE") else "neutral")
                                                       for c in shown)
                    + (f'<span class="faint small">+{len(caps) - len(shown)} flere</span>' if len(caps) > len(shown) else "")
                    + "</div>")
    return kit.card(kit.kv_list(pairs) + cap_html, title="Server", subtitle="Det filteret ved om postkassen.")


def _danger_card(acc: Any) -> str:
    remove = kit.post_form(
        f"/accounts/{_q(acc.name)}/remove",
        kit.button("Fjern konto", kind="danger", icon="trash",
                   attrs=kit.confirm_attrs(f"Fjern {acc.name}?",
                                           "Kontoen fjernes fra filteret. Mails i postkassen røres ikke, og adgangskoden "
                                           "arkiveres. Handlingen kan ikke fortrydes her.",
                                           confirm="Fjern konto", tone="danger", typed="FJERN")))
    paused = not _attr(acc, "enabled", True)
    pause_text = ("Kontoen er på pause. Genoptag kræver, at forbindelsen virker."
                  if paused else "Stop scanning midlertidigt – fx mens du rydder op i postkassen.")
    return kit.card(
        f'<div class="danger-row"><div><b>{"Genoptag kontoen" if paused else "Sæt på pause"}</b>'
        f'<span>{h(pause_text)}</span></div>{_enable_form(acc)}</div>'
        f'<div class="danger-row"><div><b>Fjern kontoen</b><span>Skriv FJERN for at bekræfte. Mails røres ikke.</span></div>'
        f"{remove}</div>", title="Pause og fjernelse", cls="danger-card")


@app.get("/accounts/<name>")
@ui.admin_required
def account_page(name: str):
    acc = _acc_or_404(name)
    folders = _account_folders(acc.name)
    st = _status(acc.name)
    state = ui.account_state(acc)
    top = _circuit_banner(acc)
    if not _attr(acc, "enabled", True):
        top += kit.alert("Filteret scanner ikke denne postkasse. Genoptag den, når forbindelsen virker.", "info",
                        title="Kontoen er på pause", icon_name="pause",
                        action_html=_enable_form(acc, size="sm"))
    elif state in ("auth_failed", "error", "limited"):
        top += kit.alert(st.get("detail") or "Filteret kan ikke logge ind. Opdater adgangskoden under Forbindelse.", "bad",
                        title=kit.state_label(state))
    mode_card = kit.card(_mode_tiles(acc) + _golive_modal(acc), title="Tilstand",
                         subtitle="Hvad filteret gør med post, der scorer over grænsen.")
    conn_card = kit.card(_connection_form(acc, action=f"/accounts/{_q(acc.name)}/connection"),
                         title="Forbindelse", subtitle="Ændringer gemmes først efter en vellykket test.")
    body = (
        top
        + '<div class="grid grid-detail adm-detail"><div class="stack">'
        + mode_card + _threshold_card(acc) + _suggestion_card(acc) + _fast_move_card(acc)
        + _protected_card(acc) + _junk_card(acc, folders)
        + kit.card(_advanced_card(acc), cls="adv-card")
        + '</div><div class="stack">'
        + _name_card(acc) + _learning_card(acc) + _trust_card(acc) + _server_card(acc, folders) + _sizes_card(acc)
        + _receipt_card(acc) + _threat_notice_card(acc) + _newsletter_card(acc)
        + _forwarders_card(acc) + conn_card + _danger_card(acc)
        + "</div></div>")
    label = ui.account_label(acc.name)
    sub = " · ".join(x for x in ((acc.name if label != acc.name else ""), str(_attr(acc, "user", ""))) if x)
    return _page(label, body, active="accounts", subtitle=sub,
                 breadcrumbs=[("Konti", "/accounts"), (label, None)],
                 actions_html=kit.button("Se beskeder", href=f"/messages?account={_q(acc.name)}",
                                         kind="secondary", icon="mails"))


TRUST_STAT_ORDER = ("known_contact", "reply_detected", "established", "first_contact", "threat_detected", "zapped")


def _trust_card(acc: Any) -> str:
    """2.3: known contacts (B10-B13), threats (B16) and rescans (B19) for
    this mailbox - the last 7 days, with a link to Regler → Kendte kontakter."""
    ov = _svc("contacts_overview", acc.name, default=None) or {}
    since = kit.today_str(6)
    rows = ui.query("SELECT metric, SUM(n) AS n FROM stats_daily WHERE account=? AND day >= ? GROUP BY metric",
                    [acc.name, since], default=[]) or []
    got = {str(r["metric"]): int(r["n"] or 0) for r in rows}
    tiles = "".join(f'<div><b class="num">{kit.fmt_int(got.get(m, 0))}</b><span>{h(STAT_LABELS[m])}</span></div>'
                    for m in TRUST_STAT_ORDER)
    link = kit.button("Åbn Kendte kontakter", href=f"/rules/contacts?account={_q(acc.name)}", kind="secondary",
                      size="sm", icon="user-check")
    text = str(ov.get("text") or "")
    return kit.card((f'<p class="muted">{h(text)}</p>' if text else "")
                    + f'<div class="trust-stats">{tiles}</div>'
                    + f'<div class="form-actions">{link}</div>',
                    title="Kendte kontakter og trusler", subtitle="De seneste 7 dage")


@app.get("/accounts/<name>/golive")
@ui.admin_required
def golive_page(name: str):
    acc = _acc_or_404(name)
    items, blocked = golive_checks(acc)
    lead = ('<p class="muted">I Filtrér flytter filteret spam ud af indbakken. Gennemgå punkterne, '
            "før du slår det til første gang.</p>")
    inner = lead + _checklist_html(items) + _golive_form(acc, items, blocked)
    if request.args.get("fragment"):
        return inner
    return _page(f"Klar til Filtrér på {acc.name}?", kit.card(inner, cls="golive-card"), active="accounts",
                 breadcrumbs=[("Konti", "/accounts"), (acc.name, f"/accounts/{_q(acc.name)}"), ("Filtrér", None)])


# ---------------------------------------------------------------------------
# Konti: POST handlers
# ---------------------------------------------------------------------------


def _back(name: str) -> str:
    return ui.safe_next(request.form.get("next"), f"/accounts/{_q(name)}")


def _config_locked() -> str | None:
    err = ui.config_error()
    return "accounts.yml kan ikke indlæses – ret filen, før du ændrer konti her." if err else None


@app.post("/accounts/<name>/mode")
@ui.admin_required
def account_mode(name: str):
    acc = _acc_or_404(name)
    back = _back(name)
    mode = _form("mode", 10)
    if mode not in kit.MODE_LABELS:
        return ui.respond("Ukendt tilstand.", ok=False, next_url=back)
    if locked := _config_locked():
        return ui.respond(locked, ok=False, next_url=back)
    old = _attr(acc, "mode", "shadow")
    if mode == old:
        return ui.respond(f"{name} kører allerede i {kit.mode_label(mode)}.", next_url=back)
    first_move = mode == "move" and _mode_needs_checklist(acc)
    if first_move:
        if not _flag("golive"):
            return ui.respond("Gennemgå tjeklisten, før kontoen skifter til Filtrér første gang.", ok=False,
                              next_url=f"/accounts/{_q(name)}/golive")
        _items, blocked = golive_checks(acc)
        if blocked:
            return ui.respond("Kontoen er ikke klar til Filtrér – se de røde punkter på tjeklisten.", ok=False,
                              next_url=f"/accounts/{_q(name)}/golive")
    if mode == "move" and _status(name).get("move_method") == "none":
        return ui.respond("Mailserveren kan ikke flytte beskeder sikkert. Brug Markér.", ok=False, next_url=back)
    if mode == "move" and not _attr(acc, "junk_explicit", False):
        return ui.respond("Vælg Spamfilter-mappen under kontoens indstillinger, før kontoen kan filtrere.",
                          ok=False, next_url=back)

    def mutate(raw: dict) -> None:
        _entry(raw, name)["mode"] = mode

    err = _write_config(mutate, "account_mode", account=name, detail=f"{old}->{mode}")
    if err:
        return ui.respond(err, ok=False, next_url=back)
    if mode == "move" and not golive_done(name):
        ui.settings_set(f"golive:{name}", str(int(time.time())))
    return ui.respond(f"{name} kører nu i {kit.mode_label(mode)}.", next_url=back, reload=True)


@app.post("/accounts/<name>/threshold")
@ui.admin_required
def account_threshold(name: str):
    acc = _acc_or_404(name)
    back = _back(name)
    t = _parse_float(_form("threshold", 10))
    lo = max(THR_MIN, float(_attr(acc, "min_threshold_allowed", THR_MIN) or THR_MIN))
    if t is None or not lo <= t <= THR_MAX or abs(t * 2 - round(t * 2)) > 1e-9:
        return ui.respond(f"Grænsen skal være mellem {kit.fmt_score(lo)} og {kit.fmt_score(THR_MAX)} i trin af 0,5.",
                          ok=False, next_url=back)
    if locked := _config_locked():
        return ui.respond(locked, ok=False, next_url=back)
    if abs(_thr(acc) - t) < 1e-9:
        return ui.respond("Følsomheden er uændret.", next_url=back)
    old = _thr(acc)

    def mutate(raw: dict) -> None:
        _entry(raw, name)["threshold"] = t

    err = _write_config(mutate, "account_threshold", account=name, detail=f"{old}->{t}")
    if err:
        return ui.respond(err, ok=False, next_url=back)
    return ui.respond(f"Følsomheden for {name} er nu {kit.sensitivity_label(t).lower()} ({kit.fmt_score(t)}).",
                      next_url=back, reload=True)


@app.post("/accounts/<name>/junk")
@ui.admin_required
def account_junk(name: str):
    acc = _acc_or_404(name)
    back = _back(name)
    folder = request.form.get("junk") or ""
    if folder == NEW_FOLDER or (not folder and _form("new_folder", 200)):
        folder = request.form.get("new_folder") or ""
    folder = folder[:201]
    if problem := _valid_folder(folder, acc):
        return ui.respond(problem, ok=False, next_url=back)
    if locked := _config_locked():
        return ui.respond(locked, ok=False, next_url=back)
    old = str(_attr(acc, "junk", ""))
    if folder == old and _attr(acc, "junk_explicit", False):
        return ui.respond("Spam-mappen er uændret.", next_url=back)

    def mutate(raw: dict) -> None:
        # Explicit per-account `junk` always wins over SPECIAL-USE autodetect.
        _entry(raw, name)["junk"] = folder

    err = _write_config(mutate, "account_junk", account=name, detail=f"{old}->{folder}")
    if err:
        return ui.respond(err, ok=False, next_url=back)
    exists = any(f["name"] == folder for f in _account_folders(name))
    note = "" if exists else " Den oprettes automatisk, når kontoen kører i Markér eller Filtrér."
    return ui.respond(f"Spam går nu til “{folder}”.{note}", next_url=back, reload=True)


@app.post("/accounts/<name>/folders/refresh")
@ui.admin_required
def account_folders_refresh(name: str):
    acc = _acc_or_404(name)
    back = _back(name)
    try:
        folders = ui.services.refresh_folders(acc.name)
    except Exception as ex:  # noqa: BLE001 - ServiceError carries a Danish .text
        text = getattr(ex, "text", None) or "Mappelisten kunne ikke hentes fra mailserveren."
        ui.audit("account_folders_refresh", name, "failed", detail=str(getattr(ex, "code", type(ex).__name__)))
        return ui.respond(text, ok=False, next_url=back)
    ui.audit("account_folders_refresh", name, "ok", detail=f"{len(folders or [])} folders")
    return ui.respond(f"Mappelisten er opdateret ({_n(len(folders or []), 'mappe', 'mapper')}).",
                      next_url=back, refresh=True)


@app.post("/accounts/<name>/enabled")
@ui.admin_required
def account_enabled(name: str):
    acc = _acc_or_404(name)
    back = _back(name)
    want = _form("enabled", 1)
    if want not in ("0", "1"):
        return ui.respond("Ugyldig forespørgsel.", ok=False, next_url=back)
    if locked := _config_locked():
        return ui.respond(locked, ok=False, next_url=back)
    enable = want == "1"
    if enable == bool(_attr(acc, "enabled", True)):
        return ui.respond("Uændret.", next_url=back)
    if enable:
        # A9: a paused account is only resumed after a successful login.
        try:
            password = str(ui.engine.read_secret(acc))
        except Exception:  # noqa: BLE001
            return ui.respond("Der er ingen gemt adgangskode. Angiv den under Forbindelse og test den.",
                              ok=False, next_url=f"/accounts/{_q(name)}")
        res = _run_test(str(_attr(acc, "imap_host", "")), int(_attr(acc, "imap_port", 993) or 993),
                        str(_attr(acc, "user", "")), password)
        ui.audit("account_test", name, "ok" if res.get("ok") else "failed", detail=str(res.get("code") or ""))
        if not res.get("ok"):
            return ui.respond(f"Kontoen blev ikke genoptaget: {res.get('text') or 'forbindelsen fejlede.'}",
                              ok=False, next_url=f"/accounts/{_q(name)}")

    def mutate(raw: dict) -> None:
        _entry(raw, name)["enabled"] = enable

    err = _write_config(mutate, "account_enabled", account=name, detail="resume" if enable else "pause")
    if err:
        return ui.respond(err, ok=False, next_url=back)
    return ui.respond(f"{name} er genoptaget." if enable else f"{name} er sat på pause.", next_url=back, reload=True)


@app.post("/accounts/<name>/advanced")
@ui.admin_required
def account_advanced(name: str):
    acc = _acc_or_404(name)
    back = _back(name)
    values: dict[str, Any] = {}
    for key, label, kind, lo, hi, _hint in ADVANCED_FIELDS:
        if kind == "bool":
            values[key] = _flag(key)
            continue
        try:
            v = int(_form(key, 12))
        except ValueError:
            return ui.respond(f"{label}: skriv et helt tal.", ok=False, next_url=back)
        if not lo <= v <= hi:
            return ui.respond(f"{label} skal være mellem {kit.fmt_int(lo)} og {kit.fmt_int(hi)}.", ok=False, next_url=back)
        values[key] = v
    if locked := _config_locked():
        return ui.respond(locked, ok=False, next_url=back)
    changed: list[str] = []

    def mutate(raw: dict) -> None:
        entry = _entry(raw, name)
        for k, v in values.items():
            if _set_changed(entry, acc, k, v):
                changed.append(k)
        if not changed:
            raise UserError("Ingen ændringer at gemme.")

    if not any(_attr(acc, k, object()) != v for k, v in values.items()):
        return ui.respond("Ingen ændringer at gemme.", next_url=back)
    detail = ",".join(k for k, v in values.items() if _attr(acc, k, object()) != v)
    err = _write_config(mutate, "account_advanced", account=name, detail=detail)
    if err:
        return ui.respond(err, ok=False, next_url=back)
    return ui.respond(f"Avancerede indstillinger for {name} er gemt.", next_url=back, reload=True)


def _test_reply(res: dict, host: str, port: int, user: str, password: str, *, next_url: str):
    pub = _public_test(res)
    token = make_test_token(host, port, user, password) if res.get("ok") else ""
    msg = pub["text"] or ("Forbindelsen virker." if res.get("ok") else "Forbindelsen fejlede.")
    if res.get("ok") and pub["move_method"] == "none":
        msg += " Bemærk: serveren kan ikke flytte beskeder – brug Markér."
    return ui.respond(msg, ok=bool(res.get("ok")), next_url=next_url, test=pub, token=token)


@app.post("/accounts/<name>/connection")
@ui.admin_required
def account_connection(name: str):
    acc = _acc_or_404(name)
    back = _back(name)
    op = _form("op", 10) or "save"
    host, port, user, password, problem = _conn_values(acc)
    if problem:
        return ui.respond(problem, ok=False, next_url=back)
    assert port is not None
    if op == "test":
        res = _run_test(host, port, user, password)
        ui.audit("account_test", name, "ok" if res.get("ok") else "failed", detail=str(res.get("code") or ""))
        return _test_reply(res, host, port, user, password, next_url=back)
    if locked := _config_locked():
        return ui.respond(locked, ok=False, next_url=back)
    new_password = bool(request.form.get("password"))
    changes = {k: v for k, v in (("imap_host", host), ("imap_port", port), ("user", user))
               if _attr(acc, k, None) != v}
    if not changes and not new_password:
        return ui.respond("Ingen ændringer at gemme.", next_url=back)
    if not check_test_token(_form("tested", 200), host, port, user, password):
        res = _run_test(host, port, user, password)
        ui.audit("account_test", name, "ok" if res.get("ok") else "failed", detail=str(res.get("code") or ""))
        if not res.get("ok"):
            return ui.respond(f"Ikke gemt – testen fejlede: {res.get('text') or 'ukendt fejl'}", ok=False,
                              next_url=back, test=_public_test(res))
    secret_file = None
    if new_password:
        try:
            secret_file = str(write_secret(name, password))
        except (OSError, ValueError) as ex:
            log.error("secret write failed for %s: %s", name, type(ex).__name__)
            return ui.respond("Adgangskoden kunne ikke gemmes.", ok=False, next_url=back)
        ui.audit("account_secret", name, "ok")

    def mutate(raw: dict) -> None:
        entry = _entry(raw, name)
        entry.update(changes)
        if secret_file:
            entry.pop("password", None)  # never keep a password inline once it has a file
            entry["password_file"] = secret_file

    detail = ",".join(list(changes) + (["password"] if new_password else []))
    err = _write_config(mutate, "account_connection", account=name, detail=detail)
    if err:
        return ui.respond(err, ok=False, next_url=back)
    return ui.respond(f"Forbindelsen for {name} er gemt.", next_url=back, reload=True)


@app.post("/accounts/<name>/remove")
@ui.admin_required
def account_remove(name: str):
    acc = _acc_or_404(name)
    if _form("confirm", 10) != "FJERN":
        return ui.respond("Skriv FJERN for at bekræfte.", ok=False, next_url=f"/accounts/{_q(name)}")
    if locked := _config_locked():
        return ui.respond(locked, ok=False, next_url=f"/accounts/{_q(name)}")
    removed: dict = {}

    def mutate(raw: dict) -> None:
        entry = _entry(raw, name)
        removed.update(entry)
        raw["accounts"] = [a for a in raw["accounts"] if not (isinstance(a, dict) and str(a.get("name")) == name)]

    err = _write_config(mutate, "account_remove", account=name)
    if err:
        return ui.respond(err, ok=False, next_url=f"/accounts/{_q(name)}")
    _archive_secret(name, removed.get("password_file") or _attr(acc, "password_file", None))
    try:
        conn = ui.db()
        conn.execute("DELETE FROM settings_kv WHERE key=?", (f"golive:{name}",))
        conn.commit()
    except sqlite3.Error:
        pass
    return ui.respond(f"{name} er fjernet. Mails i postkassen er ikke rørt.", next_url="/accounts",
                      reload=True, location="/accounts")


# ---------------------------------------------------------------------------
# Konti 2.1: circuit breaker, threshold suggestion, move timing, protected
# recipients, trusted forwarders, daily receipt, folder sizes, display name
# ---------------------------------------------------------------------------

FAST_SECONDS_MAX = 600
PROTECTED_MAX = 50
FORWARDERS_MAX = 50
DEFAULT_FORWARDERS = tuple(siteconfig.get_list("trusted_forwarders"))   # local site config
_PROTECTED_RE = re.compile(r"^[a-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}@[a-z0-9-]+(\.[a-z0-9-]+)+$")
_FORWARDER_RE = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
SUGGEST_REASONS = {
    "released_over_current": "Du har frigivet mails, der lå over den nuværende grænse.",
    "missed_below_current": "Spam, du selv har flyttet, lå under grænsen.",
    "lowering_too_risky": "En lavere grænse ville også ramme mails, du har frigivet.",
    "too_little_data": "Der er endnu for lidt data til et sikkert forslag.",
    "released_above_max": "Nogle frigivne mails havde så høj en score, at ingen grænse redder dem – tillad hellere afsenderen.",
}
CONFIDENCE = {"high": ("Sikkert forslag", "ok"), "medium": ("Rimeligt sikkert", "info"), "low": ("Usikkert", "warn")}


def circuit_info(name: str) -> dict:
    """{'open': bool, 'reason', 'opened_at'} from the engine's breaker table,
    falling back to account_status (older engine / fake)."""
    out = {"open": False, "reason": "", "opened_at": None}
    fn = getattr(ui.engine, "circuit_status", None)
    if callable(fn):
        try:
            cs = fn(ui.db(), name) or {}
            out.update(open=cs.get("state") == "open", reason=cs.get("reason") or "", opened_at=cs.get("opened_at"))
            return out
        except Exception as ex:  # noqa: BLE001 - table missing on an older DB
            log.debug("circuit_status failed: %s", type(ex).__name__)
    st = _status(name)
    if st.get("raw_state") == "paused_moves" or st.get("move_state") == "paused":
        out.update(open=True, reason=st.get("move_state_reason") or st.get("detail") or "",
                   opened_at=st.get("move_state_at"))
    return out


def _resume_form(acc: Any, *, size: str = "") -> str:
    label = ui.account_label(acc.name)
    return kit.post_form(
        f"/accounts/{_q(acc.name)}/resume-moves",
        kit.hidden("next", request.path)
        + kit.button("Genoptag flytning", kind="primary", icon="play", size=size, attrs=kit.confirm_attrs(
            f"Genoptag flytning for {label}?",
            "Filteret flytter igen spam til Spamfilter-mappen – også de mails, der har ventet i køen. Tjek først "
            "Fanget spam og Beskeder, at det ikke var rigtige mails, der blev flyttet.", confirm="Genoptag")),
        cls="inline-form")


def _circuit_banner(acc: Any) -> str:
    out = ""
    c = circuit_info(acc.name)
    if c["open"]:
        since = f" (siden {kit.fmt_ts(c['opened_at'])})" if c.get("opened_at") else ""
        out += (f'<div id="flytning">' + kit.alert(
            (c["reason"] or "Filteret flyttede usædvanligt mange mails og har stoppet sig selv for en sikkerheds skyld.")
            + " Spam bliver liggende i indbakken (og venter i køen), indtil du genoptager flytningen."
            + " Tjek først, at det ikke var rigtige mails, der blev flyttet – brug Fortryd flytninger, hvis der var.",
            "bad", title=f"Flytning er sat på pause{since}", icon_name="pause",
            action_html=_resume_form(acc, size="sm")
            + kit.button("Fortryd flytninger", href=f"/undo?account={_q(acc.name)}&period=today", kind="secondary",
                         icon="undo", size="sm")) + "</div>")
    try:
        hold = int(ui.engine.move_hold_until(ui.db()) or 0) if hasattr(ui.engine, "move_hold_until") else 0
    except Exception:  # noqa: BLE001
        hold = 0
    if hold > time.time():
        out += kit.alert(f"Efter opdateringen flyttes kun tydelig spam indtil {kit.fmt_ts(hold)}. Grænsetilfælde venter "
                         "i køen og flyttes derefter.", "info", title="Forsigtig start", icon_name="clock")
    return out


def _suggestion(acc: Any) -> dict:
    res = _svc("threshold_suggestion", acc.name, default=None)
    return res if isinstance(res, dict) else {}


def _suggestion_card(acc: Any) -> str:
    import ui_mail

    sug = _suggestion(acc)
    if not sug or ui_mail.threshold_dismissed(acc.name, sug):
        return ""
    cur, rec, change = sug.get("current"), sug.get("recommended"), sug.get("change")
    counts = sug.get("counts") or {}
    conf_label, conf_tone = CONFIDENCE.get(str(sug.get("confidence")), ("", "neutral"))
    head = ""
    if rec is not None and change in ("raise", "lower", "keep"):
        arrow = {"raise": "arrow-up-right", "lower": "arrow-down-right"}.get(change, "check")
        head = (f'<div class="sug-head"><div class="sug-vals"><span class="sug-cur num">{h(kit.fmt_score(cur))}</span>'
                f'{kit.icon(arrow, "sug-arrow")}<span class="sug-rec num">{h(kit.fmt_score(rec))}</span></div>'
                + (kit.chip(conf_label, conf_tone) if conf_label else "") + "</div>")
    reasons = "".join(f"<li>{h(SUGGEST_REASONS.get(str(r), str(r)))}</li>" for r in (sug.get("reasons") or [])
                      if str(r) in SUGGEST_REASONS)
    facts = []
    if counts.get("scored") is not None:
        facts.append(f"{kit.fmt_int(int(counts.get('scored') or 0))} scorede mails de seneste {int(sug.get('days') or 14)} dage")
    if counts.get("released"):
        facts.append(_n(int(counts["released"]), "frigivet", "frigivet"))
    if counts.get("missed") or counts.get("marked_spam"):
        facts.append(_n(int(counts.get("missed") or counts.get("marked_spam") or 0), "sluppet igennem", "sluppet igennem"))
    if change in ("raise", "lower") and counts.get("would_move_recommended") is not None:
        facts.append(f"ved forslaget flyttes {kit.fmt_int(int(counts['would_move_recommended']))} "
                     f"(nu {kit.fmt_int(int(counts.get('would_move_current') or 0))})")
    action = ""
    lo = max(THR_MIN, float(_attr(acc, "min_threshold_allowed", THR_MIN) or THR_MIN))
    if change in ("raise", "lower") and rec is not None and lo <= float(rec) <= THR_MAX:
        action = kit.post_form(
            f"/accounts/{_q(acc.name)}/threshold-suggestion",
            kit.hidden("next", request.path + "#forslag") + kit.hidden("threshold", f"{float(rec):.1f}")
            + kit.button("Brug forslaget", kind="primary", icon="check", attrs=kit.confirm_attrs(
                f"Skift grænsen fra {kit.fmt_score(cur)} til {kit.fmt_score(rec)}?",
                str(sug.get("text") or "") + " Du kan altid ændre den igen.", confirm="Brug forslaget")))
        action += ui_mail.threshold_dismiss_form(acc.name, sug, request.path)
    body = (head + f'<p class="sug-text">{h(sug.get("text") or "Ingen forslag lige nu.")}</p>'
            + (f'<ul class="sug-reasons">{reasons}</ul>' if reasons else "")
            + (f'<p class="faint small">{h(" · ".join(facts))}.</p>' if facts else "")
            + (f'<div class="form-actions">{action}</div>' if action else ""))
    return (f'<div id="forslag">' + kit.card(body, title="Forslag til følsomhed",
                                             subtitle="Beregnet ud fra hvad du har frigivet og selv flyttet til spam.",
                                             cls="sug-card") + "</div>")


def _fast_move_card(acc: Any) -> str:
    grace = int(_attr(acc, "move_grace_seconds", 60) or 0)
    fast_s = int(_attr(acc, "move_grace_seconds_high", 3) if _attr(acc, "move_grace_seconds_high", None) is not None else 3)
    margin = float(_attr(acc, "fast_move_margin", 5.0) or 5.0)
    on = fast_s < grace
    thr = _thr(acc)
    inner = (kit.hidden("next", request.path)
             + f'<div class="field field-switch">{kit.switch("fast", on, "Flyt tydelig spam med det samme")}'
             '<span class="field-hint">Så når telefonen ikke at give lyd for åbenlys spam. Mails tæt på grænsen venter '
             f'stadig {grace} sekunder, så du kan nå at reagere.</span></div>'
             '<div class="grid grid-2">'
             + kit.form_field("Tydelig spam flyttes efter", kit.input_("fast_seconds", fast_s if on else 3, type="number",
                                                                       attrs=f'id="{_dom_id("fast-s-", acc.name)}" min="0" max="{FAST_SECONDS_MAX}" required'),
                              hint="Sekunder.")
             + kit.form_field("Tydelig spam er score over grænsen +", kit.input_(
                 "fast_margin", kit.fmt_num(margin, 1).replace(",", "."), type="number",
                 attrs=f'id="{_dom_id("fast-m-", acc.name)}" min="1" max="30" step="0.5" required'),
                 hint=f"Med grænse {kit.fmt_score(thr)}: score {kit.fmt_score(thr + margin)} eller mere.")
             + "</div>"
             + f'<div class="form-actions">{kit.button("Gem flyttetider", kind="secondary", icon="check")}</div>')
    return kit.card(kit.post_form(f"/accounts/{_q(acc.name)}/fast-move", inner), title="Flyttetider",
                    subtitle="Hvor hurtigt spam flyttes ud af indbakken.")


def _protected_card(acc: Any) -> str:
    addrs = [str(a) for a in (_attr(acc, "protected_recipients", None) or [])]
    pthr = float(_attr(acc, "protected_threshold", 18.0) or 18.0)
    inner = (kit.hidden("next", request.path)
             + kit.form_field("Beskyttede adresser", kit.textarea(
                 "protected_recipients", "\n".join(addrs), rows=3,
                 attrs=f'id="{_dom_id("prot-", acc.name)}" placeholder="info@dinbutik.dk" autocapitalize="none" '
                       'spellcheck="false" maxlength="4000"'),
                 hint="Én adresse pr. linje. Mail sendt til dem (fx en webshops kontaktadresse) skal have en meget højere "
                      "score, før den flyttes.")
             + kit.form_field("Grænse for beskyttede adresser", kit.input_(
                 "protected_threshold", kit.fmt_num(pthr, 1).replace(",", "."), type="number",
                 attrs=f'id="{_dom_id("prot-t-", acc.name)}" min="{_thr(acc):.1f}" max="100" step="0.5" required'),
                 hint=f"Normal grænse er {kit.fmt_score(_thr(acc))}. Anbefalet: 18.")
             + f'<div class="form-actions">{kit.button("Gem beskyttede adresser", kind="secondary", icon="shield-check")}</div>')
    return kit.card(kit.post_form(f"/accounts/{_q(acc.name)}/protected", inner), title="Beskyttede adresser",
                    subtitle="Kundepost må aldrig forsvinde.")


def _current_forwarders(acc: Any) -> list[str]:
    raw = _attr(acc, "trusted_forwarders", None)
    return [str(x) for x in raw] if isinstance(raw, list) else list(DEFAULT_FORWARDERS)


def _default_forwarders() -> tuple[str, ...]:
    val = getattr(ui.engine, "DEFAULT_TRUSTED_FORWARDERS", None)
    return tuple(str(x) for x in val) if isinstance(val, (list, tuple)) and val else DEFAULT_FORWARDERS


def _forwarders_card(acc: Any) -> str:
    current = _current_forwarders(acc)
    defaults = _default_forwarders()
    extras = [f for f in current if f not in defaults]
    chips = "".join(
        f'<li>{kit.icon("check-circle" if d in current else "x-circle")}<span class="mono">{h(d)}</span>'
        + kit.chip("Standard" if d in current else "Slået fra i accounts.yml", "neutral" if d in current else "warn")
        + "</li>" for d in defaults)
    inner = (kit.hidden("next", request.path)
             + f'<ul class="fwd-list">{chips}</ul>'
             + kit.form_field("Flere videresendere", kit.textarea(
                 "extra_forwarders", "\n".join(extras), rows=2,
                 attrs=f'id="{_dom_id("fwd-", acc.name)}" placeholder="mail.eksempel.dk" autocapitalize="none" '
                       'spellcheck="false" maxlength="4000"'),
                 hint="Én pr. linje: en IP-adresse, et IP-net (fx 192.168.1.0/24), et værtsnavn eller *.domæne.")
             + f'<div class="form-actions">{kit.button("Gem videresendere", kind="secondary", icon="check")}</div>')
    return kit.card(kit.post_form(f"/accounts/{_q(acc.name)}/forwarders", inner), title="Betroede videresendere",
                    subtitle="Servere, der sender din post videre. Filteret kigger forbi dem og vurderer den rigtige afsender.")


def _learning_card(acc: Any) -> str:
    """What the filter learns from moves in the mail app (2.1)."""
    on = bool(_attr(acc, "auto_allow_on_rescue", True))
    shadow = _attr(acc, "mode", "shadow") == "shadow"
    facts = ('<ul class="learn-facts">'
             f'<li>{kit.icon("shield-alert")}<span><b>Ind i Spamfilter</b> – en mail, du trækker ind i mappen, læres som spam.</span></li>'
             f'<li>{kit.icon("undo")}<span><b>Ud af Spamfilter</b> – en mail, du trækker tilbage, læres som god og flyttes aldrig igen.</span></li>'
             "</ul>")
    hint = ("Flytter man en mail ud af Spamfilter i mailprogrammet, bliver afsenderen automatisk tilladt for denne "
            "postkasse (kun den præcise adresse). Trækker man senere en mail fra afsenderen ind i Spamfilter igen, "
            "fjernes den automatiske tilladelse. Afsendere med Altid igennem røres ikke. Du kan altid fjerne reglen "
            "under Regler.")
    inner = (kit.hidden("next", request.path) + facts
             + '<div class="field field-switch">'
             + kit.switch("auto_allow_on_rescue", on, "Tillad afsenderen automatisk")
             + f'<span class="field-hint">{h(hint)}</span></div>'
             + ('<p class="faint small">Gælder ikke i Overvåg – her flytter filteret ingenting.</p>' if shadow else "")
             + f'<div class="form-actions">{kit.button("Gem", kind="secondary", icon="check")}</div>')
    block = (kit.hidden("next", request.path)
             + '<div class="field field-switch">'
             + kit.switch("auto_block_repeated_spam", bool(_attr(acc, "auto_block_repeated_spam", True)),
                          "Husk gentagen spam automatisk")
             + '<span class="field-hint">Tre nye spamrettelser af forskellige mails fra samme bekræftede adresse '
               'inden for 30 dage blokerer kun adressen i denne postkasse. Gælder både Flyt til spam og '
               'flytninger i mailprogrammet. Gamle rettelser tæller ikke med ved opgraderingen. '
               'Højst fem nye automatiske blokeringer pr. døgn. Frigiver du en mail, fjernes en sådan '
               'automatisk blokering igen. Egne domæner og eksisterende tilladelser beskyttes. '
               'Slår du fra, bevares eksisterende regler; fjern dem under Regler eller Tjek disse.</span></div>'
             + f'<div class="form-actions">{kit.button("Gem spamautomatik", kind="secondary", icon="check")}</div>')
    forms = (kit.post_form(f"/accounts/{_q(acc.name)}/auto-allow", inner)
             + kit.post_form(f"/accounts/{_q(acc.name)}/auto-block", block))
    return kit.card(forms, title="Lær af mailprogrammet",
                    subtitle="Det, du gør på telefonen eller computeren, lærer filteret af.", cls="learn-card")


def _receipt_card(acc: Any) -> str:
    on = bool(_attr(acc, "daily_report", False))
    hour = int(_attr(acc, "report_hour", 7) or 0)
    sent = ""
    fn = getattr(ui.engine, "receipt_sent", None)
    if callable(fn):
        try:
            if fn(ui.db(), acc.name):
                sent = kit.chip("Sendt i dag", "ok")
        except Exception:  # noqa: BLE001 - table missing on an older DB
            sent = ""
    mode_note = ("" if _attr(acc, "mode", "shadow") == "move"
                 else '<p class="faint small">Kvitteringen sendes kun automatisk, når kontoen kører i Filtrér.</p>')
    inner = (kit.hidden("next", request.path)
             + f'<div class="field field-switch">{kit.switch("daily_report", on, "Daglig kvittering i indbakken")}'
             '<span class="field-hint">Én kort mail om dagen med det, filteret har flyttet – kun på dage, hvor der er '
             "flyttet noget. Er en af dem din, trækker du den bare tilbage til Indbakken.</span></div>"
             + kit.form_field("Tidspunkt", kit.select("report_hour", [(i, f"kl. {i:02d}") for i in range(24)], hour,
                                                       attrs=f'id="{_dom_id("rh-", acc.name)}"'))
             + mode_note
             + f'<div class="form-actions">{kit.button("Gem", kind="secondary", icon="check")}</div>')
    test = kit.post_form(f"/accounts/{_q(acc.name)}/receipt-test",
                         kit.hidden("next", request.path)
                         + kit.button("Send prøve nu", kind="ghost", icon="send", size="sm", attrs=kit.confirm_attrs(
                             "Send en prøvekvittering?", f"En prøve lægges i indbakken på {ui.account_label(acc.name)} "
                             "nu – markeret “Prøve”.", confirm="Send prøve")), cls="inline-form")
    return kit.card(kit.post_form(f"/accounts/{_q(acc.name)}/receipt", inner), title="Daglig kvittering",
                    subtitle="Godt for familiemedlemmer, der sjældent kigger her.", actions=sent + test)


def _sizes_card(acc: Any) -> str:
    url = f"/accounts/{_q(acc.name)}/folder-sizes" + ("?refresh=1" if request.args.get("sizes") == "refresh" else "")
    refresh = kit.button("Opdater", href=f"/accounts/{_q(acc.name)}?sizes=refresh#mapper", kind="ghost",
                         icon="refresh", size="sm")
    return (f'<div id="mapper">' + kit.card(
        f'<div data-fragment="{h(url)}" aria-busy="true">{kit.skeleton(3)}</div>'
        f'<noscript><a class="card-link" href="{h(url)}">Vis mappestørrelser</a></noscript>',
        title="Mapper", subtitle="Antal mails lige nu (kun visning).", actions=refresh) + "</div>")


def _sizes_html(res: dict) -> str:
    if not res.get("ok"):
        return kit.empty_state("Kunne ikke tælle mapperne", str(res.get("text") or "Mailserveren svarede ikke."), "folder")
    rows = []
    for f in res.get("folders") or []:
        if not f.get("exists", True):
            rows.append(f'<li class="size-row is-missing">{kit.icon("folder")}<span class="size-name">{h(f.get("label") or f.get("name"))}</span>'
                        '<span class="faint small">findes ikke</span></li>')
            continue
        unseen = int(f.get("unseen") or 0)
        rows.append(f'<li class="size-row kind-{h(f.get("kind") or "")}">'
                    f'{kit.icon({"inbox": "inbox", "filter_junk": "shield-alert"}.get(str(f.get("kind")), "shield"))}'
                    f'<span class="size-name">{h(f.get("label") or f.get("name"))}</span>'
                    f'<span class="size-n num">{kit.fmt_int(int(f.get("messages") or 0))}</span>'
                    + (f'<span class="size-unseen">{kit.fmt_int(unseen)} ulæste</span>' if unseen else '<span class="size-unseen"></span>')
                    + "</li>")
    stamp = (f'<p class="faint small">Talt {h(kit.ago(res.get("fetched_at")))}'
             + (" · gemt i op til 10 minutter" if res.get("cached") else "") + "</p>") if res.get("fetched_at") else ""
    return f'<ul class="size-list">{"".join(rows)}</ul>{stamp}'


def _name_card(acc: Any) -> str:
    label = ui.account_label(acc.name)
    current = label if label != acc.name else ""
    inner = (kit.hidden("next", request.path)
             + kit.form_field("Navn", kit.input_("display_name", current, attrs=f'id="{_dom_id("dn-", acc.name)}" '
                                                 f'maxlength="{ui.DISPLAY_NAME_MAX}" placeholder="{h(acc.name)}" autocomplete="off"'),
                              hint=f"Vises overalt i stedet for “{acc.name}”, fx “Anna” eller “Butikken”. Tomt = brug kontonavnet.")
             + f'<div class="form-actions">{kit.button("Gem navn", kind="secondary", icon="check")}</div>')
    return kit.card(kit.post_form(f"/accounts/{_q(acc.name)}/display-name", inner), title="Navn",
                    subtitle="Et venligt navn til oversigten.")


def _lines(text: str, limit: int) -> list[str]:
    out = []
    for raw in (text or "").replace(",", "\n").replace(";", "\n").splitlines():
        v = raw.strip().lower()
        if v and v not in out:
            out.append(v)
    if len(out) > limit:
        raise UserError(f"Højst {limit} linjer.")
    return out


@app.post("/accounts/<name>/resume-moves")
@ui.admin_required
def account_resume_moves(name: str):
    acc = _acc_or_404(name)
    back = _back(name)
    fn = getattr(ui.engine, "resume_moves", None)
    if not callable(fn):
        return ui.respond("Filteret understøtter ikke denne handling endnu.", ok=False, next_url=back)
    try:
        ok = bool(fn(ui.db(), acc.name, _actor()))
    except Exception as ex:  # noqa: BLE001
        log.error("resume_moves failed: %s", type(ex).__name__)
        return ui.respond("Flytningen kunne ikke genoptages. Prøv igen.", ok=False, next_url=back)
    ui.audit("account_resume_moves", name, "ok" if ok else "noop")
    label = ui.account_label(name)
    return ui.respond(f"Flytning er genoptaget for {label}." if ok else f"Flytning var ikke sat på pause for {label}.",
                      next_url=back, refresh=True)


@app.post("/accounts/<name>/threshold-suggestion")
@ui.admin_required
def account_threshold_suggestion(name: str):
    acc = _acc_or_404(name)
    back = _back(name)
    if locked := _config_locked():
        return ui.respond(locked, ok=False, next_url=back)
    t = _parse_float(_form("threshold", 10))
    sug = _suggestion(acc)
    rec = sug.get("recommended")
    if t is None or rec is None or sug.get("change") not in ("raise", "lower") or abs(float(rec) - t) > 1e-9:
        return ui.respond("Forslaget har ændret sig siden siden blev åbnet. Se det nye forslag.", ok=False,
                          next_url=back, refresh=True)
    lo = max(THR_MIN, float(_attr(acc, "min_threshold_allowed", THR_MIN) or THR_MIN))
    if not lo <= t <= THR_MAX:
        return ui.respond(f"Grænsen skal være mellem {kit.fmt_score(lo)} og {kit.fmt_score(THR_MAX)}.", ok=False,
                          next_url=back)
    old = _thr(acc)

    def mutate(raw: dict) -> None:
        _entry(raw, name)["threshold"] = t

    err = _write_config(mutate, "account_threshold_suggestion", account=name,
                        detail=f"{old}->{t} {sug.get('change')} {sug.get('confidence')}")
    if err:
        return ui.respond(err, ok=False, next_url=back)
    return ui.respond(f"Grænsen for {ui.account_label(name)} er nu {kit.fmt_score(t)}.", next_url=back, reload=True)


@app.post("/accounts/<name>/threshold-suggestion/dismiss")
@ui.admin_required
def account_threshold_suggestion_dismiss(name: str):
    """2.8.4: 'Afvis' - hide this exact suggestion until the filter suggests something else."""
    import ui_mail

    acc = _acc_or_404(name)
    back = ui.safe_next(request.form.get("next"), _back(name))
    sug = _suggestion(acc)
    sig = ui_mail.threshold_sig(sug) if sug.get("change") in ("raise", "lower") else ""
    if not sig or _form("sig", 60) != sig:
        return ui.respond("Forslaget har ændret sig siden siden blev åbnet. Se det nye forslag.", ok=False,
                          next_url=back, refresh=True)
    ui.settings_set(ui_mail.SUG_DISMISS_KEY.format(name),
                    json.dumps({"sig": sig, "at": int(time.time()), "by": _actor()}))
    ui.audit("threshold_suggestion_dismiss", name, detail=sig)
    return ui.respond("Forslaget er afvist. Det kommer kun igen, hvis filteret når frem til et andet forslag.",
                      next_url=back, refresh=True)


@app.post("/accounts/<name>/fast-move")
@ui.admin_required
def account_fast_move(name: str):
    acc = _acc_or_404(name)
    back = _back(name)
    grace = int(_attr(acc, "move_grace_seconds", 60) or 0)
    fast = _flag("fast")
    try:
        seconds = int(_form("fast_seconds", 6) or 3)
    except ValueError:
        return ui.respond("Skriv et helt antal sekunder.", ok=False, next_url=back)
    margin = _parse_float(_form("fast_margin", 6))
    if margin is None or not 1 <= margin <= 30:
        return ui.respond("Tydelig spam skal være mellem 1 og 30 point over grænsen.", ok=False, next_url=back)
    if fast and not 0 <= seconds <= FAST_SECONDS_MAX:
        return ui.respond(f"Vælg mellem 0 og {FAST_SECONDS_MAX} sekunder.", ok=False, next_url=back)
    if fast and seconds >= grace:
        return ui.respond(f"Tydelig spam skal flyttes hurtigere end den normale ventetid ({grace} sekunder).",
                          ok=False, next_url=back)
    if locked := _config_locked():
        return ui.respond(locked, ok=False, next_url=back)
    # Off = clear spam waits as long as everything else.
    values = {"move_grace_seconds_high": seconds if fast else grace, "fast_move_margin": float(margin)}

    def mutate(raw: dict) -> None:
        entry = _entry(raw, name)
        for k, v in values.items():
            entry[k] = v

    err = _write_config(mutate, "account_fast_move", account=name,
                        detail=f"fast={int(fast)} s={values['move_grace_seconds_high']} margin={margin}")
    if err:
        return ui.respond(err, ok=False, next_url=back)
    return ui.respond("Flyttetiderne er gemt.", next_url=back, reload=True)


@app.post("/accounts/<name>/protected")
@ui.admin_required
def account_protected(name: str):
    acc = _acc_or_404(name)
    back = _back(name)
    try:
        addrs = _lines(request.form.get("protected_recipients") or "", PROTECTED_MAX)
    except UserError as ex:
        return ui.respond(str(ex), ok=False, next_url=back)
    bad = [a for a in addrs if not _PROTECTED_RE.match(a)]
    if bad:
        return ui.respond(f"Ugyldig adresse: {bad[0][:80]}", ok=False, next_url=back)
    t = _parse_float(_form("protected_threshold", 10))
    lo = max(_thr(acc), float(_attr(acc, "min_threshold_allowed", THR_MIN) or THR_MIN))
    if t is None or not lo <= t <= 100:
        return ui.respond(f"Grænsen for beskyttede adresser skal være mellem {kit.fmt_score(lo)} og 100.", ok=False,
                          next_url=back)
    if locked := _config_locked():
        return ui.respond(locked, ok=False, next_url=back)

    def mutate(raw: dict) -> None:
        entry = _entry(raw, name)
        entry["protected_recipients"] = addrs
        entry["protected_threshold"] = float(t)

    err = _write_config(mutate, "account_protected", account=name, detail=f"n={len(addrs)} t={t}")
    if err:
        return ui.respond(err, ok=False, next_url=back)
    return ui.respond(f"{_n(len(addrs), 'beskyttet adresse', 'beskyttede adresser')} er gemt.", next_url=back,
                      reload=True)


@app.post("/accounts/<name>/forwarders")
@ui.admin_required
def account_forwarders(name: str):
    acc = _acc_or_404(name)
    back = _back(name)
    try:
        extras = _lines(request.form.get("extra_forwarders") or "", FORWARDERS_MAX)
    except UserError as ex:
        return ui.respond(str(ex), ok=False, next_url=back)
    for e in extras:
        valid = bool(_FORWARDER_RE.match(e))
        if not valid:
            try:
                import ipaddress

                ipaddress.ip_network(e, strict=False)
                valid = True
            except ValueError:
                valid = False
        if not valid:
            return ui.respond(f"Ugyldig videresender: {e[:80]}", ok=False, next_url=back)
    current = _current_forwarders(acc)
    defaults = _default_forwarders()
    kept = [d for d in defaults if d in current]   # a default removed in accounts.yml stays removed
    value = kept + [e for e in extras if e not in kept]
    if value == current:
        return ui.respond("Videresenderne er uændrede.", next_url=back)
    if locked := _config_locked():
        return ui.respond(locked, ok=False, next_url=back)

    def mutate(raw: dict) -> None:
        entry = _entry(raw, name)
        if value == list(defaults):
            entry.pop("trusted_forwarders", None)   # back to the built-in default
        else:
            entry["trusted_forwarders"] = value

    err = _write_config(mutate, "account_forwarders", account=name, detail=f"extra={len(extras)}")
    if err:
        return ui.respond(err, ok=False, next_url=back)
    return ui.respond("Videresenderne er gemt.", next_url=back, reload=True)


@app.post("/accounts/<name>/receipt")
@ui.admin_required
def account_receipt(name: str):
    acc = _acc_or_404(name)
    back = _back(name)
    on = _flag("daily_report")
    try:
        hour = int(_form("report_hour", 2) or 7)
    except ValueError:
        hour = -1
    if not 0 <= hour <= 23:
        return ui.respond("Vælg et tidspunkt mellem kl. 00 og 23.", ok=False, next_url=back)
    if bool(_attr(acc, "daily_report", False)) == on and int(_attr(acc, "report_hour", 7) or 0) == hour:
        return ui.respond("Uændret.", next_url=back)
    if locked := _config_locked():
        return ui.respond(locked, ok=False, next_url=back)

    def mutate(raw: dict) -> None:
        entry = _entry(raw, name)
        entry["daily_report"] = on
        entry["report_hour"] = hour

    err = _write_config(mutate, "account_receipt", account=name, detail=f"on={int(on)} hour={hour}")
    if err:
        return ui.respond(err, ok=False, next_url=back)
    return ui.respond((f"Daglig kvittering er slået til (kl. {hour:02d})." if on else "Daglig kvittering er slået fra."),
                      next_url=back, reload=True)


@app.post("/accounts/<name>/auto-allow")
@ui.admin_required
def account_auto_allow(name: str):
    acc = _acc_or_404(name)
    back = _back(name)
    on = _flag("auto_allow_on_rescue")
    if bool(_attr(acc, "auto_allow_on_rescue", True)) == on:
        return ui.respond("Uændret.", next_url=back)
    if locked := _config_locked():
        return ui.respond(locked, ok=False, next_url=back)

    def mutate(raw: dict) -> None:
        _entry(raw, name)["auto_allow_on_rescue"] = on

    err = _write_config(mutate, "account_auto_allow", account=name, detail=f"on={int(on)}")
    if err:
        return ui.respond(err, ok=False, next_url=back)
    return ui.respond("Afsendere tillades nu automatisk, når en mail flyttes ud af Spamfilter." if on
                      else "Afsendere tillades ikke længere automatisk.", next_url=back, reload=True)


@app.post("/accounts/<name>/auto-block")
@ui.admin_required
def account_auto_block(name: str):
    acc = _acc_or_404(name)
    back = _back(name)
    on = _flag("auto_block_repeated_spam")
    if bool(_attr(acc, "auto_block_repeated_spam", True)) == on:
        return ui.respond("Uændret.", next_url=back)
    if locked := _config_locked():
        return ui.respond(locked, ok=False, next_url=back)

    def mutate(raw: dict) -> None:
        _entry(raw, name)["auto_block_repeated_spam"] = on

    err = _write_config(mutate, "account_auto_block", account=name, detail=f"on={int(on)}")
    if err:
        return ui.respond(err, ok=False, next_url=back)
    text = ("Gentagen bekræftet spam huskes nu automatisk for postkassen." if on else
            "Nye automatiske spamblokeringer er slået fra. Eksisterende regler er bevaret.")
    return ui.respond(text, next_url=back, reload=True)


# ---- 2.3 follow-up: Straks-advarsel ved farlige mails (config key threat_notice) ---------

NOTICE_SAMPLE = {"sender_name": "PostNord", "sender": "kundeservice@postnord-levering.example",
                 "subject": "Din pakke venter – bekræft adressen på postnord.example", "threat": "phish"}


def _engine_fn(name: str) -> Callable | None:
    fn = getattr(ui.engine, name, None)
    if callable(fn):
        return fn
    try:
        import filter as real_engine  # noqa: PLC0415 - the production module (pure helper)
    except Exception:  # noqa: BLE001
        return None
    fn = getattr(real_engine, name, None)
    return fn if callable(fn) else None


def threat_notice_preview(acc: Any) -> dict[str, str]:
    """The Straks-advarsel exactly as the engine would build it for one
    example phishing mail: {subject, text}. Empty on any failure."""
    build = _engine_fn("build_threat_notice")
    if build is None:
        return {"subject": "", "text": ""}
    try:
        import email as _email  # noqa: PLC0415
        import email.policy as _policy  # noqa: PLC0415

        item = dict(NOTICE_SAMPLE, received_at=int(time.time()) - 120, queued_at=int(time.time()) - 60)
        raw, _mid, subject = build(acc, [item], folder=str(_attr(acc, "junk", "") or DEFAULT_JUNK))
        msg = _email.message_from_bytes(raw, policy=_policy.default)
        part = msg.get_body(preferencelist=("plain",))
        text = part.get_content() if part is not None else ""
    except Exception as ex:  # noqa: BLE001 - a preview must never break Konti
        log.warning("threat notice preview failed: %s", type(ex).__name__)
        return {"subject": "", "text": ""}
    return {"subject": str(subject or ""), "text": str(text or "").strip()}


def _threat_notice_card(acc: Any) -> str:
    on = bool(_attr(acc, "threat_notice", True))
    move = _attr(acc, "mode", "shadow") == "move"
    prev = threat_notice_preview(acc)
    explain = ("Stopper filteret virus, phishing eller en farlig vedhæftning, lægges en kort advarsel straks i "
               "postkassens indbakke – højst én hver halve time, uden links eller vedhæftninger fra den farlige mail.")
    preview = ""
    if prev["text"]:
        preview = ('<details class="disclosure notice-preview"><summary>' + kit.icon("chevron-right")
                   + "Sådan ser advarslen ud</summary><div class=\"disclosure-body\">"
                   f'<div class="notice-mail"><div class="notice-from">{kit.icon("mail")}<span>Spamfilteret · '
                   f'til {h(_attr(acc, "user", ""))}</span></div>'
                   f'<div class="notice-subject">{h(prev["subject"])}</div>'
                   f'<pre class="notice-text">{h(prev["text"])}</pre></div>'
                   '<p class="faint small">Eksemplet er opdigtet. Links og domæner i afsendernavn og emne gøres '
                   "uklikbare.</p></div></details>")
    inner = (kit.hidden("next", request.path)
             + '<div class="field field-switch">'
             + kit.switch("threat_notice", on, "Straks-advarsel ved farlige mails")
             + f'<span class="field-hint">{h(explain)}</span></div>'
             + ('' if move else '<p class="faint small">Sendes kun, når kontoen kører i Filtrér – kun der flyttes '
                                "farlige mails til Spamfilter-mappen.</p>")
             + preview
             + f'<div class="form-actions">{kit.button("Gem", kind="secondary", icon="check")}</div>')
    chip = kit.chip("Til", "ok") if on else kit.chip("Fra", "neutral")
    return kit.card(kit.post_form(f"/accounts/{_q(acc.name)}/threat-notice", inner), title="Straks-advarsel",
                    subtitle="Besked i indbakken, når en farlig mail er stoppet.", actions=chip,
                    cls="notice-card")


@app.post("/accounts/<name>/threat-notice")
@ui.admin_required
def account_threat_notice(name: str):
    acc = _acc_or_404(name)
    back = _back(name)
    on = _flag("threat_notice")
    if bool(_attr(acc, "threat_notice", True)) == on:
        return ui.respond("Uændret.", next_url=back)
    if locked := _config_locked():
        return ui.respond(locked, ok=False, next_url=back)

    def mutate(raw: dict) -> None:
        _entry(raw, name)["threat_notice"] = on

    err = _write_config(mutate, "account_threat_notice", account=name, detail=f"on={int(on)}")
    if err:
        return ui.respond(err, ok=False, next_url=back)
    return ui.respond((f"Straks-advarsel er slået til for {ui.account_label(name)}." if on
                       else f"Straks-advarsel er slået fra for {ui.account_label(name)}."), next_url=back, reload=True)


# ---- 2.6 (A4): Nyhedsbreve (config keys newsletters / newsletter_folder) ---------------------

NEWSLETTER_OPTIONS = (("off", "Fra"), ("shadow", "Prøv"), ("on", "Til"))


def _newsletter_card(acc: Any) -> str:
    import newsletters as nl  # noqa: PLC0415 - pure helper next to the engine
    import ui_newsletters  # noqa: PLC0415 - registered by ui_mail

    mode = nl.mode_of(acc)
    folder = str(_attr(acc, "newsletter_folder", nl.DEFAULT_FOLDER) or nl.DEFAULT_FOLDER)
    explain = ("Nyhedsbreve og reklamer – mails under spamgrænsen med afmeldingslink eller masseudsendelse – "
               f"kan flyttes til mappen “{folder}” i stedet for at blive i indbakken. Fra: alt bliver i "
               "indbakken. Prøv: intet flyttes, filteret viser kun, hvad det ville flytte. Til: de flyttes. "
               "Mails fra kendte kontakter, afsendere du har svaret, tilladte afsendere, beskyttede adresser og "
               f"{_platform_text()} bliver altid i indbakken – det gør ordrer, fakturaer, leveringer, koder og "
               "invitationer også. Flytter du en mail tilbage, bliver afsenderen i indbakken fremover. "
               "Spam går stadig til Spamfilter-mappen, og nyhedsbreve læres aldrig som spam.")
    n_shadow = ui_newsletters.shadow_count(acc.name)
    n_moved = ui_newsletters.moved_count(acc.name)
    counts = (f'<p class="muted small">De seneste 7 dage: {kit.fmt_int(n_shadow)} ville være flyttet · '
              f'{kit.fmt_int(n_moved)} flyttet. <a class="card-link" href="{h(ui_newsletters.page_url(acc.name))}">'
              f'Se listen {kit.icon("arrow-right")}</a></p>')
    inner = (kit.hidden("next", request.path + "#nyhedsbreve")
             + kit.form_field("Nyhedsbreve", kit.segmented("newsletters", NEWSLETTER_OPTIONS, mode)
                              .replace('class="segmented"', 'class="segmented seg-newsletters"'),
                              hint=explain)
             + ('' if _attr(acc, "mode", "shadow") == "move" or mode != "on" else
                '<p class="faint small">Kontoen filtrerer ikke (Filtrér er slået fra), så Til virker som Prøv, '
                "indtil du slår Filtrér til.</p>")
             + counts
             + f'<div class="form-actions">{kit.button("Gem", kind="secondary", icon="check")}</div>')
    tone = {"off": "neutral", "shadow": "info", "on": "ok"}[mode]
    return ('<div id="nyhedsbreve"></div>'
            + kit.card(kit.post_form(f"/accounts/{_q(acc.name)}/newsletters", inner), title="Nyhedsbreve",
                       subtitle="Reklamer og nyhedsbreve i deres egen mappe.",
                       actions=kit.chip(nl.MODE_TEXT[mode], tone), cls="newsletter-card"))


@app.post("/accounts/<name>/newsletters")
@ui.admin_required
def account_newsletters(name: str):
    import newsletters as nl  # noqa: PLC0415

    acc = _acc_or_404(name)
    back = _back(name) + "#nyhedsbreve"
    value = (request.form.get("newsletters") or "").strip().lower()
    if value not in nl.MODES:
        return ui.respond("Vælg Fra, Prøv eller Til.", ok=False, next_url=back)
    if nl.mode_of(acc) == value:
        return ui.respond("Uændret.", next_url=back)
    if locked := _config_locked():
        return ui.respond(locked, ok=False, next_url=back)

    def mutate(raw: dict) -> None:
        _entry(raw, name)["newsletters"] = value

    err = _write_config(mutate, "account_newsletters", account=name, detail=f"newsletters={value}")
    if err:
        return ui.respond(err, ok=False, next_url=back)
    text = {"off": "Nyhedsbreve bliver nu i indbakken.",
            "shadow": "Prøv: filteret viser nu kun, hvilke nyhedsbreve det ville flytte.",
            "on": f"Nyhedsbreve flyttes nu til “{_attr(acc, 'newsletter_folder', nl.DEFAULT_FOLDER)}”."}[value]
    return ui.respond(f"{text} ({ui.account_label(name)})", next_url=back, reload=True)


@app.post("/accounts/<name>/receipt-test")
@ui.admin_required
def account_receipt_test(name: str):
    acc = _acc_or_404(name)
    back = _back(name)
    fn = getattr(ui.engine, "send_receipt", None)
    if not callable(fn):
        return ui.respond("Filteret understøtter ikke kvitteringer endnu.", ok=False, next_url=back)
    try:
        res = fn(acc.name, True, actor=_actor()) or {}
    except Exception as ex:  # noqa: BLE001 - send_receipt never raises, but be safe
        log.error("send_receipt failed: %s", type(ex).__name__)
        res = {"ok": False, "code": "error", "text": "Prøven kunne ikke sendes."}
    ok = bool(res.get("ok"))
    ui.audit("account_receipt_test", name, "ok" if ok else str(res.get("code") or "failed"))
    text = res.get("text") or ("Prøvekvitteringen ligger nu i indbakken." if ok else "Prøven kunne ikke sendes.")
    return ui.respond(text, ok=ok, next_url=back, status=502)


@app.get("/accounts/<name>/folder-sizes")
@ui.admin_required
def account_folder_sizes(name: str):
    acc = _acc_or_404(name)
    res = _svc("folder_sizes", acc.name, refresh=request.args.get("refresh") == "1", default=None)
    html = _sizes_html(res if isinstance(res, dict) else {"ok": False})
    if request.headers.get("Sec-Fetch-Mode") == "navigate":
        return _page("Mapper", kit.card(html), active="accounts",
                     breadcrumbs=[("Konti", "/accounts"), (ui.account_label(acc.name), f"/accounts/{_q(acc.name)}"),
                                  ("Mapper", None)])
    return html


@app.post("/accounts/<name>/display-name")
@ui.admin_required
def account_display_name(name: str):
    _acc_or_404(name)
    back = _back(name)
    try:
        value = ui.clean_display_name(request.form.get("display_name"))
    except ValueError as ex:
        return ui.respond(str(ex), ok=False, next_url=back)
    if value == name:
        value = ""
    old = ui.account_display_names().get(name, "")
    if value == old:
        return ui.respond("Navnet er uændret.", next_url=back)
    if locked := _config_locked():
        return ui.respond(locked, ok=False, next_url=back)

    def mutate(raw: dict) -> None:
        entry = _entry(raw, name)
        if value:
            entry["display_name"] = value
        else:
            entry.pop("display_name", None)

    err = _write_config(mutate, "account_display_name", account=name, detail=f"{old or '-'} -> {value or '-'}")
    if err:
        return ui.respond(err, ok=False, next_url=back)
    g.pop("_labels", None)
    return ui.respond(f"{name} hedder nu “{value}” i oversigten." if value else f"{name} vises igen med kontonavnet.",
                      next_url=back, refresh=True)


# ---------------------------------------------------------------------------
# Konti: add-account wizard
# ---------------------------------------------------------------------------


def _suggest_name(email: str, taken: Iterable[str]) -> str:
    local, _, domain = email.lower().partition("@")
    base = re.sub(r"[^a-z0-9_-]+", "-", f"{domain.split('.')[0]}-{local}").strip("-")[:48] or "konto"
    taken = set(taken)
    name, i = base, 2
    while name in taken:
        name, i = f"{base}-{i}", i + 1
    return name


@app.get("/accounts/suggest")
@ui.admin_required
def accounts_suggest():
    email = (request.args.get("email") or "").strip()[:254]
    if not EMAIL_RE.fullmatch(email):
        return jsonify({"ok": False})
    sug = _svc("suggest_imap", email, default=None) or {}
    if not sug:
        domain = email.rpartition("@")[2].lower()
        known = (_svc("known_providers", default={}) or {}).get(domain)
        sug = dict(known, guess=False) if known else {"imap_host": f"imap.{domain}", "imap_port": 993, "guess": True}
    names = [a.name for a in ui.effective_accounts()]
    users = {str(_attr(a, "user", "")).lower() for a in ui.effective_accounts()}
    return jsonify({"ok": True, "imap_host": sug.get("imap_host") or "", "imap_port": int(sug.get("imap_port") or 993),
                    "provider": sug.get("provider") or "", "guess": bool(sug.get("guess", True)),
                    "name": _suggest_name(email, names), "exists": email.lower() in users})


def _wizard_step(num: int, title: str, text: str, body: str) -> str:
    return (f'<section class="wiz-step"><div class="wiz-head"><span class="wiz-num">{num}</span>'
            f'<div><h3>{h(title)}</h3><p>{h(text)}</p></div></div><div class="wiz-body">{body}</div></section>')


@app.get("/accounts/new")
@ui.admin_required
def account_new_page():
    if _config_locked():
        return _page("Tilføj konto", kit.alert(_config_locked(), "bad"), active="accounts",
                     breadcrumbs=[("Konti", "/accounts"), ("Tilføj konto", None)])
    providers = _svc("known_providers", default={}) or {}
    prov_txt = ", ".join(f"@{d} ({p.get('provider') or p.get('imap_host')})" for d, p in sorted(providers.items()))
    step1 = (
        kit.form_field("E-mailadresse", kit.input_("email", "", type="email",
                                                   attrs='id="f-email" required autocomplete="off" autocapitalize="none" '
                                                         'spellcheck="false" placeholder="navn@firma.dk" data-suggest'),
                       hint=f"Kendte udbydere udfyldes automatisk: {prov_txt}." if prov_txt else "")
        + '<div class="wiz-provider" data-provider hidden></div>'
        + kit.form_field("Kontonavn", kit.input_("name", "", attrs='id="f-name" required maxlength="64" '
                                                                  'pattern="[A-Za-z0-9_\\-]{1,64}" autocomplete="off" '
                                                                  'placeholder="fx molt-kontor" data-autoname'),
                         hint="Vises i menuer og logs. Kun bogstaver, tal, - og _."))
    step2 = _connection_form(None, action="", wizard=True)
    test_btn = (f'<div class="form-actions wiz-test">'
                + kit.button("Test forbindelse", kind="secondary", icon="plug", attrs='name="op" value="test"')
                + "</div><div class=\"test-result\" data-test-result hidden></div>")
    opts = [(DEFAULT_JUNK, f"{DEFAULT_JUNK} (anbefalet – oprettes automatisk)"), (NEW_FOLDER, "Opret ny mappe…")]
    step3 = (kit.form_field("Spam-mappe", kit.select("junk", opts, DEFAULT_JUNK, attrs='id="f-junk" data-new-folder-select data-folder-target'),
                            hint="Efter testen kan du også vælge en af postkassens egne mapper.")
             + '<div data-new-folder="f-junk">'
             + kit.form_field("Ny mappe", kit.input_("new_folder", "", attrs='id="f-new-folder" maxlength="200" placeholder="Spamfilter"'))
             + "</div>")
    step4 = (kit.alert("Kontoen starter i Overvåg: filteret scorer ny post, men flytter og markerer intet, "
                       "før du selv skifter tilstand.", "info", icon_name="eye")
             + '<div class="form-actions">'
             + kit.button("Annullér", href="/accounts", kind="ghost")
             + kit.button("Tilføj konto", kind="primary", icon="plus", attrs='name="op" value="save" data-needs-test')
             + "</div>")
    form = kit.post_form(
        "/accounts/new",
        kit.hidden("tested", "")
        + _wizard_step(1, "Postkasse", "Hvilken e-mailadresse skal filteret beskytte?", step1)
        + _wizard_step(2, "Server og adgang", "Udfyldt automatisk for kendte udbydere. Test forbindelsen, før du gemmer.",
                       step2 + test_btn)
        + _wizard_step(3, "Spam-mappe", "Hvor skal spam hen, når du senere slår Filtrér til?", step3)
        + _wizard_step(4, "Gem", "Gennemse og tilføj kontoen.", step4),
        attrs="data-conn-test data-wizard")
    return _page("Tilføj konto", kit.card(form, cls="wizard"), active="accounts",
                 subtitle="Fire trin – kontoen starter sikkert i Overvåg.",
                 breadcrumbs=[("Konti", "/accounts"), ("Tilføj konto", None)])


@app.post("/accounts/test")
@ui.admin_required
def accounts_test():
    host, port, user, password, problem = _conn_values(None, _form("email", 254))
    if problem:
        return ui.respond(problem, ok=False, next_url="/accounts/new")
    assert port is not None
    res = _run_test(host, port, user, password)
    ui.audit("account_test", "", "ok" if res.get("ok") else "failed", detail=f"{host} {res.get('code') or ''}")
    return _test_reply(res, host, port, user, password, next_url="/accounts/new")


@app.post("/accounts/new")
@ui.admin_required
def account_create():
    if (_form("op", 10) or "save") == "test":
        return accounts_test()
    back = "/accounts/new"
    if locked := _config_locked():
        return ui.respond(locked, ok=False, next_url=back)
    name = _form("name", 65)
    email = _form("email", 254) or _form("user", 254)
    if not ACCOUNT_NAME_RE.fullmatch(name) or name.lower() in RESERVED_NAMES:
        return ui.respond("Kontonavnet må kun indeholde bogstaver, tal, - og _ (højst 64 tegn).", ok=False, next_url=back)
    host, port, user, password, problem = _conn_values(None, email)
    if problem:
        return ui.respond(problem, ok=False, next_url=back)
    assert port is not None
    accs = ui.effective_accounts()
    if any(a.name == name for a in accs):
        return ui.respond(f"Der findes allerede en konto med navnet {name}.", ok=False, next_url=back)
    if any(str(_attr(a, "user", "")).lower() == user.lower() for a in accs):
        return ui.respond(f"{user} er allerede tilføjet.", ok=False, next_url=back)
    folder = request.form.get("junk") or DEFAULT_JUNK
    if folder == NEW_FOLDER:
        folder = request.form.get("new_folder") or ""
    if folder_problem := _valid_folder(folder[:201], None):
        return ui.respond(folder_problem, ok=False, next_url=back)
    if not check_test_token(_form("tested", 200), host, port, user, password):
        res = _run_test(host, port, user, password)
        ui.audit("account_test", name, "ok" if res.get("ok") else "failed", detail=str(res.get("code") or ""))
        if not res.get("ok"):
            return ui.respond(f"Kontoen blev ikke tilføjet – testen fejlede: {res.get('text') or 'ukendt fejl'}",
                              ok=False, next_url=back, test=_public_test(res))
    path = secret_path(name)
    if path.exists() and any(str(_attr(a, "password_file", "") or "") == str(path) for a in accs):
        return ui.respond("Der findes allerede en adgangskodefil for dette navn.", ok=False, next_url=back)
    try:
        write_secret(name, password)
    except (OSError, ValueError) as ex:
        log.error("secret write failed for new account: %s", type(ex).__name__)
        return ui.respond("Adgangskoden kunne ikke gemmes.", ok=False, next_url=back)
    entry = {"name": name, "enabled": True, "user": user, "imap_host": host, "imap_port": port,
             "password_file": str(path), "mode": "shadow", "junk": folder}

    def mutate(raw: dict) -> None:
        if any(isinstance(a, dict) and str(a.get("name")) == name for a in raw["accounts"]):
            raise UserError(f"Der findes allerede en konto med navnet {name}.")
        raw["accounts"].append(entry)

    err = _write_config(mutate, "account_add", account=name, detail=f"{user} {host}:{port}")
    if err:
        path.unlink(missing_ok=True)
        return ui.respond(err, ok=False, next_url=back)
    ui.audit("account_secret", name, "ok")
    dest = f"/accounts/{_q(name)}"
    return ui.respond(f"{name} er tilføjet og starter i Overvåg.", next_url=dest, reload=True, location=dest)


# ---------------------------------------------------------------------------
# Træning
# ---------------------------------------------------------------------------


def _jobs(limit: int = JOB_PAGE) -> list[dict]:
    jobs = _svc("list_train_jobs", limit, default=[]) or []
    return [j for j in jobs if isinstance(j, dict) and "id" in j]


def _job_percent(j: dict) -> int:
    if j.get("percent") is not None:
        try:
            return int(j["percent"])
        except (TypeError, ValueError):
            pass
    total = int(j.get("total") or 0)
    if total:
        return int(min(100, int(j.get("processed") or 0) * 100 / total))
    return 100 if j.get("status") == "done" else 0


def job_row(j: dict) -> dict:
    jid = int(j["id"])
    status = str(j.get("status") or "queued")
    st_label, st_tone = JOB_STATUS.get(status, (status, "neutral"))
    kind = str(j.get("kind") or "")
    k_label, k_tone = JOB_KIND.get(kind, (kind, "neutral"))
    total = int(j.get("total") or 0)
    processed = int(j.get("processed") or 0)
    pct = _job_percent(j)
    tone = {"done": "ok", "failed": "bad", "cancelled": "neutral", "cancel_requested": "warn"}.get(status, "brand")
    of = kit.fmt_int(total) if total else ("?" if status in ACTIVE_JOB else kit.fmt_int(processed))
    prog = (f'<div class="job-prog">{kit.progress(pct, 100, tone=tone)}'
            f'<span class="faint small num">{kit.fmt_int(processed)} / {of}</span></div>')
    if kind == "calibrate":
        counts = f'<span class="num">{kit.fmt_int(j.get("learned") or processed)}</span> <span class="faint">scoret</span>'
    else:
        counts = (f'<span class="num">{kit.fmt_int(j.get("learned") or 0)}</span> <span class="faint">lært</span>'
                  + (f' · <span class="num">{kit.fmt_int(j.get("skipped") or 0)}</span> <span class="faint">sprunget over</span>'
                     if j.get("skipped") else ""))
    if j.get("failed"):
        counts += f' · <span class="num tone-bad">{kit.fmt_int(j["failed"])}</span> <span class="faint">fejl</span>'
    if j.get("error"):
        counts += f'<div class="faint small">{h(str(j["error"])[:160])}</div>'
    stop = _ratio_or_none(j.get("stop_ratio"))
    if stop:
        counts += (f'<div class="faint small">Stopper ved 1 spam pr. {h(kit.fmt_num(1 / stop, 1))} legitime '
                   "(rebalancering)</div>")
    what = (f'<div class="job-what"><b>{h(j.get("account", ""))}</b><span class="mono small">{h(j.get("folder", ""))}</span>'
            f'<span class="faint small">#{jid} · {h(kit.ago(j.get("created_at")))}'
            + (f' · {h(j.get("created_by"))}' if j.get("created_by") else "") + "</span></div>")
    actions = []
    if kind == "calibrate" and status in ("done", "running", "cancelled") and processed:
        actions.append(kit.button("Se resultat", href=f"/training/jobs/{jid}", kind="secondary", size="sm", icon="bar-chart"))
    elif kind != "calibrate":
        actions.append(kit.button("Detaljer", href=f"/training/jobs/{jid}", kind="ghost", size="sm"))
    if status in ("queued", "running"):
        actions.append(kit.post_form(
            f"/training/jobs/{jid}/cancel",
            kit.button("Annullér", kind="ghost", size="sm", icon="x",
                       attrs=kit.confirm_attrs(f"Annullér job #{jid}?",
                                               "Et kørende job stopper efter den aktuelle portion. Det, der allerede er lært, bevares.",
                                               confirm="Annullér job", tone="danger"))))
    active = ' data-job-active="1"' if status in ACTIVE_JOB else ""
    counts = f'<span class="job-counts">{counts}</span>'
    return {"cells": [what, kit.badge(k_label, k_tone), kit.badge(st_label, st_tone), prog, counts,
                      f'<div class="row-tight job-actions">{"".join(actions)}</div>'],
            "attrs": f'data-row="job:{jid}"{active}'}


JOB_HEADERS = [("Job", ""), ("Type", ""), ("Status", ""), ("Fremskridt", "job-prog-col"), ("Resultat", ""), ("", "end")]


def render_job_row(j: dict) -> str:
    """One <tr> (same markup as inside kit.table) for live updates."""
    html = kit.table(JOB_HEADERS, [job_row(j)])
    m = re.search(r"<tbody>(.*)</tbody>", html, re.S)
    return m.group(1) if m else ""


def _jobs_card() -> str:
    jobs = _jobs()
    lists = _learn_lists()
    if jobs:
        listing = kit.table(JOB_HEADERS, [job_row(j) for j in jobs], cls="jobs-table")
    else:
        listing = kit.empty_state("Ingen job endnu", "Start et træningsjob eller en kalibrering ovenfor. "
                                                     "Job kører i baggrunden – du kan lukke siden imens.", "graduation-cap")
    if lists:
        listing += ('<h3 class="sub-head" id="laerelister">Lærelister</h3>'
                    '<p class="faint small sub-note">Mails, du selv har valgt at lære – fx fra “Reparér Bayes”. '
                    "Hver mail findes og læres for sig; intet flyttes.</p>"
                    + kit.table(LL_HEADERS, [learn_list_row(j) for j in lists], cls="jobs-table"))
    return kit.card(f'<div class="card-pad-x" data-jobs-live="/training/jobs.json">{listing}</div>',
                    title="Job", subtitle="Opdateres automatisk, mens et job kører.", cls="flush")


def _account_folder_options() -> dict[str, list[tuple[str, str]]]:
    out: dict[str, list[tuple[str, str]]] = {}
    for a in ui.effective_accounts():
        folders = _account_folders(a.name)
        opts = []
        for f in folders:
            cnt = f" · {kit.fmt_int(f['messages'])}" if isinstance(f.get("messages"), int) else ""
            opts.append((f["name"], f["name"] + cnt))
        if not any(v.upper() == "INBOX" for v, _l in opts):
            opts.insert(0, (str(_attr(a, "inbox", "INBOX")), str(_attr(a, "inbox", "INBOX"))))
        out[a.name] = opts
    return out


def _folder_select(name: str, by_account: dict[str, list[tuple[str, str]]], selected_account: str,
                   *, attrs: str = "") -> str:
    """Folder dropdown: optgroups for every account (works without JS);
    admin.js narrows it to the chosen account."""
    groups = []
    for acc_name, opts in by_account.items():
        inner = "".join(f'<option value="{h(v)}">{h(l)}</option>' for v, l in opts)
        groups.append(f'<optgroup label="{h(acc_name)}">{inner}</optgroup>')
    data = json.dumps(by_account, ensure_ascii=False, separators=(",", ":"))
    fid = kit._field_id(name)
    return (f'<div class="select-wrap"><select class="select" name="{h(name)}" id="{fid}" '
            f'data-folders="{h(data)}" data-folders-for="{h(selected_account)}" {attrs}>{"".join(groups)}</select>'
            f'{kit.icon("chevron-down", "select-caret")}</div>')


def _train_form(accs: list, by_account: dict) -> str:
    acct_opts = [(a.name, a.name) for a in accs]
    first = acct_opts[0][0] if acct_opts else ""
    inner = (
        '<div class="form-grid">'
        + '<div class="grid grid-2 grid-tight">'
        + kit.form_field("Konto", kit.select("account", acct_opts, first, attrs='id="f-train-account" data-folder-source="f-train-folder"'))
        + kit.form_field("Mappe", _folder_select("folder", by_account, first, attrs='id="f-train-folder"'))
        + "</div>"
        # No preselection: the kind must be an explicit choice.
        + kit.form_field("Lær beskederne som", kit.segmented("kind", [("spam", "Spam"), ("ham", "Legitim")], None)
                         .replace('class="segmented"', 'class="segmented seg-kind seg-train"'))
        + '<div class="grid grid-2 grid-tight">'
        + kit.form_field("Antal (nyeste først)", kit.input_("max_messages", 300, type="number",
                                                            attrs='id="f-train-max" min="1" max="5000" required'))
        + kit.form_field("Kun ældre end (dage)", kit.input_("min_age_days", 0, type="number",
                                                            attrs='id="f-train-age" min="0" max="3650" required'))
        + "</div>"
        + kit.form_field("Udbyder-filter", kit.select("provider_filter", list(PROVIDER_FILTERS), "any", attrs='id="f-train-pf"'),
                         hint="Brug fx “ikke kaldt spam” for at undgå at lære udbyderens fejl som legitim post.")
        + f'<div class="field field-switch">{kit.switch("seen_only", False, "Kun læste beskeder")}'
          '<span class="field-hint">Ulæst post i indbakken kan være spam, du ikke har set endnu.</span></div>'
        + '<div class="form-actions">'
        + kit.button("Start træning", kind="primary", icon="graduation-cap",
                     attrs=kit.confirm_attrs(
                         "Start træning?",
                         "Beskederne i den valgte mappe læres som den valgte type. Det ændrer den fælles "
                         "Bayes-hukommelse for alle konti og kan ikke fortrydes med ét klik.",
                         confirm="Start træning"))
        + "</div></div>")
    return kit.post_form("/training/jobs", inner)


def _calibrate_form(accs: list) -> str:
    acct_opts = [(a.name, a.name) for a in accs]
    inner = (
        '<div class="form-grid">'
        + kit.form_field("Konto", kit.select("account", acct_opts, acct_opts[0][0] if acct_opts else "",
                                             attrs='id="f-cal-account"'))
        + '<div class="field"><span class="field-label">Mapper</span><div class="switch-list">'
        + kit.switch("inbox", True, "Indbakken (bør være legitim post)")
        + kit.switch("provider_junk", True, "Udbyderens Junk-mappe (bør være spam)")
        + kit.switch("own_junk", False, "Spamfilter-mappen")
        + "</div></div>"
        + kit.form_field("Antal pr. mappe", kit.input_("max_messages", 300, type="number",
                                                       attrs='id="f-cal-max" min="1" max="5000" required'))
        + f'<div class="form-actions">{kit.button("Start kalibrering", kind="primary", icon="sliders")}</div></div>')
    return kit.post_form("/training/calibrate", inner)


def _presets() -> list[dict]:
    """Recommended jobs computed from the folders we know about."""
    spam_jobs, ham_jobs = [], []
    for a in ui.effective_accounts():
        if not _attr(a, "enabled", True):
            continue
        folders = _account_folders(a.name)
        pj = _provider_junk_folder(a, folders)
        if pj:
            spam_jobs.append({"account": a.name, "folder": pj, "kind": "spam", "max_messages": 500,
                              "min_age_days": 0, "seen_only": False, "provider_filter": "any"})
        archives = _archive_folders(a, folders)
        if archives:
            for f in archives[:2]:
                ham_jobs.append({"account": a.name, "folder": f, "kind": "ham", "max_messages": 300,
                                 "min_age_days": 0, "seen_only": True, "provider_filter": "provider_clean"})
        else:
            ham_jobs.append({"account": a.name, "folder": str(_attr(a, "inbox", "INBOX")), "kind": "ham",
                             "max_messages": 300, "min_age_days": 14, "seen_only": True,
                             "provider_filter": "provider_clean"})
    return [
        {"key": "spam_junk", "title": "Træn spam fra Junk-mapper", "icon": "shield-alert", "tone": "bad",
         "text": "Lærer spam fra udbydernes egne Junk-mapper på alle aktive konti.", "jobs": spam_jobs},
        {"key": "ham_archive", "title": "Træn legitim fra arkivmapper", "icon": "inbox", "tone": "ok",
         "text": "Lærer læst post fra arkivmapper – eller læst post i indbakken ældre end 14 dage, "
                 "som udbyderen ikke kaldte spam.", "jobs": ham_jobs},
    ]


def _presets_card() -> str:
    items = []
    for p in _presets():
        jobs = p["jobs"]
        where = ", ".join(f"{j['account']}: {j['folder']}" for j in jobs[:6]) + (" …" if len(jobs) > 6 else "")
        sub = (f"{_n(len(jobs), 'job', 'job')} · {where}" if jobs else "Ingen egnede mapper fundet endnu.")
        btn_attrs = kit.confirm_attrs(p["title"] + "?", f"Opretter {_n(len(jobs), 'job', 'job')}: {where}. "
                                      "Jobbene kører ét ad gangen i baggrunden og ændrer intet i postkasserne.",
                                      confirm="Start")
        inner = (kit.hidden("preset", p["key"])
                 + f'<button type="submit" class="action-item tone-{p["tone"]}"{"" if jobs else " disabled"} {btn_attrs}>'
                 f'<span class="action-ic">{kit.icon(p["icon"])}</span><span class="action-txt"><b>{h(p["title"])}</b>'
                 f'<span>{h(p["text"])}</span><span class="faint small">{h(sub)}</span></span>'
                 f'{kit.icon("chevron-right", "chev")}</button>')
        items.append(kit.post_form("/training/preset", inner))
    return kit.card(f'<div class="action-list">{"".join(items)}</div>', title="Anbefalet",
                    subtitle="Et godt udgangspunkt for en ny Bayes-hukommelse.")


def _identity_text() -> str:
    accs = ui.effective_accounts()
    groups: dict[str, list[str]] = {}
    for a in accs:
        groups.setdefault(_identity(a), []).append(a.name)
    if not groups:
        return ""
    if len(groups) == 1:
        ident = next(iter(groups))
        return (f"Alle {_n(len(accs), 'konto', 'konti')} deler én fælles Bayes-hukommelse (identitet “{ident}”). "
                "Det, filteret lærer fra én postkasse, hjælper dem alle.")
    parts = [f"“{i}”: {', '.join(n)}" for i, n in groups.items()]
    return "Konti med samme identitet deler Bayes-hukommelse. " + " · ".join(parts)


def bayes_pool_note(st: dict) -> str:
    """2.3 follow-up: which Bayes pool is active, and whether its own
    numbers are known (counts_source 'all_pools' = only the sum)."""
    pool = str(st.get("pool") or "")
    out = ""
    if pool:
        out += (f'<p class="bayes-pool">{kit.icon("database")}<span>Aktiv pulje: '
                f'<span class="mono">{h(pool)}</span></span></p>')
    if st.get("counts_source") == "all_pools":
        out += ('<p class="faint small bayes-pool-sum">Tallene er summen af alle Bayes-puljer. Tallet for den aktive '
                "pulje kendes ikke.</p>")
    return out


@app.get("/training/bayes")
@ui.admin_required
def training_bayes_fragment():
    st = _bayes()
    if request.args.get("part") == "ratio":
        # Reparér Bayes: only the live spam:legitim ratio.
        return bayes_ratio_html(st)
    if not st.get("ok"):
        html = kit.empty_state("rspamd svarer ikke", "Bayes-status kan ikke hentes lige nu. Job venter, til rspamd er tilbage.",
                               "database")
    else:
        need = int(st.get("min_learns") or 200)
        spam, ham = int(st.get("spam_learned") or 0), int(st.get("ham_learned") or 0)
        ready = spam >= need and ham >= need
        if ready:
            note = "Bayes er aktiv og bruges i alle scorer."
        else:
            missing = []
            if spam < need:
                missing.append(f"{kit.fmt_int(need - spam)} spam")
            if ham < need:
                missing.append(f"{kit.fmt_int(need - ham)} legitime")
            note = f"Bayes tæller først med ved {kit.fmt_int(need)} af hver. Mangler {' og '.join(missing)}."
        balance = ""
        if spam and ham:
            ratio = max(spam, ham) / max(1, min(spam, ham))
            if ratio > 3:
                balance = kit.alert("Skævt forhold mellem spam og legitim post. Træn den mindste slags for at undgå skæve scorer.",
                                    "warn", action_html=kit.button("Reparér Bayes", href="/training#reparer",
                                                                   kind="secondary", size="sm"))
        if st.get("text"):
            note = str(st["text"])  # services: plain Danish incl. the active pool and the 200-learn rule
        html = (f'<div class="bayes-rings">{kit.ring(spam, need, label="Spam lært")}'
                f'{kit.ring(ham, need, label="Legitim lært")}</div>'
                f'<p class="bayes-note">{h(note)}</p>{balance}')
        html += bayes_pool_note(st)
    ident = _identity_text()
    if ident:
        html += f'<p class="identity-note">{kit.icon("users")}<span>{h(ident)}</span></p>'
    return html


@app.get("/training")
@ui.admin_required
def training_page():
    accs = ui.effective_accounts()
    bayes = ('<div data-fragment="/training/bayes" aria-busy="true">' + kit.skeleton(2, cls="skeleton-rings") + "</div>"
             '<noscript><p class="muted"><a class="card-link" href="/training/bayes">Vis Bayes-status</a></p></noscript>')
    if not accs:
        body = kit.card(kit.empty_state("Ingen konti", "Tilføj en konto, før du træner filteret.", "at-sign",
                                        kit.button("Tilføj konto", href="/accounts/new", icon="plus")))
        return _page("Træning", body, active="training")
    by_account = _account_folder_options()
    body = (
        '<div class="grid grid-main">'
        + kit.card(bayes, title="Filterets hukommelse", subtitle="Bayes lærer af eksempler på spam og legitim post.")
        + _presets_card()
        + "</div>"
        + '<div class="grid grid-2">'
        + kit.card(_train_form(accs, by_account), title="Start træning",
                   subtitle="Læser beskeder skrivebeskyttet og lærer dem. Intet i postkassen ændres, "
                            "men filterets fælles hukommelse gør.")
        + f'<div id="kalibrering">' + kit.card(_calibrate_form(accs), title="Kalibrering",
                   subtitle="Scorer eksisterende post uden at lære noget – så du kan se, hvor grænsen bør ligge.")
        + "</div></div>"
        + _rebuild_card()
        + _repair_card()
        + _jobs_card())
    return _page("Træning", body, active="training",
                 subtitle="Lær filteret din post at kende – og find den rigtige grænse.")


def _job_args(account: str, folder: str, kind: str, max_messages: Any, min_age_days: Any,
              seen_only: bool, provider_filter: str) -> int:
    return ui.services.queue_train_job(account, folder, kind, max_messages, min_age_days=min_age_days,
                                       seen_only=seen_only, provider_filter=provider_filter, actor=_actor())


def _check_job_folder(account: str, folder: str) -> str | None:
    acc = ui.account_by_name(account)
    if acc is None:
        return "Ukendt konto."
    if not folder or len(folder) > 200 or any(c in folder for c in "\r\n\x00"):
        return "Vælg en mappe."
    known = _account_folders(account)
    if known and folder not in {f["name"] for f in known} and folder.upper() != "INBOX":
        return f"Mappen “{folder}” findes ikke på {account}. Opdater mappelisten under Konti."
    return None


@app.post("/training/jobs")
@ui.admin_required
def training_queue():
    account, folder = _form("account", 64), (request.form.get("folder") or "")[:201]
    kind = _form("kind", 10)
    pf = _form("provider_filter", 20) or "any"
    if kind not in ("spam", "ham"):
        return ui.respond("Vælg spam eller legitim.", ok=False, next_url="/training")
    if pf not in dict(PROVIDER_FILTERS):
        return ui.respond("Ukendt udbyder-filter.", ok=False, next_url="/training")
    if problem := _check_job_folder(account, folder):
        return ui.respond(problem, ok=False, next_url="/training")
    inbox = str(_attr(ui.account_by_name(account), "inbox", "INBOX") or "INBOX")
    if kind == "spam" and folder.strip().upper() in ("INBOX", inbox.upper()):
        # services.queue_train_job refuses it as well (same text).
        return ui.respond("Indbakken indeholder normalt legitim post og kan ikke læres som spam. "
                          "Flyt spammen til en anden mappe (fx Spamfilter-mappen) og træn fra den.",
                          ok=False, next_url="/training")
    try:
        n, age = int(_form("max_messages", 6) or 300), int(_form("min_age_days", 6) or 0)
    except ValueError:
        return ui.respond("Antal og alder skal være hele tal.", ok=False, next_url="/training")
    if not 1 <= n <= 5000 or not 0 <= age <= 3650:
        return ui.respond("Antal skal være 1–5.000 og alder 0–3.650 dage.", ok=False, next_url="/training")
    try:
        jid = _job_args(account, folder, kind, n, age, _flag("seen_only"), pf)
    except ValueError as ex:
        return ui.respond(str(ex)[:200] or "Jobbet blev afvist.", ok=False, next_url="/training")
    except Exception as ex:  # noqa: BLE001
        log.error("queue_train_job failed: %s", type(ex).__name__)
        return ui.respond("Jobbet kunne ikke oprettes.", ok=False, next_url="/training")
    ui.audit("train_queue", account, detail=f"job={jid} {kind} {folder} n={n} age={age} pf={pf}")
    return ui.respond(f"Job #{jid} er sat i kø: {JOB_KIND[kind][0].lower()} fra {folder} på {account}.",
                      next_url="/training", refresh=True)


@app.post("/training/calibrate")
@ui.admin_required
def training_calibrate():
    account = _form("account", 64)
    acc = ui.account_by_name(account)
    if acc is None:
        return ui.respond("Ukendt konto.", ok=False, next_url="/training")
    try:
        n = int(_form("max_messages", 6) or 300)
    except ValueError:
        n = 0
    if not 1 <= n <= 5000:
        return ui.respond("Antal skal være 1–5.000.", ok=False, next_url="/training")
    folders = _account_folders(account)
    wanted: list[str] = []
    if _flag("inbox"):
        wanted.append(str(_attr(acc, "inbox", "INBOX")))
    if _flag("provider_junk"):
        pj = _provider_junk_folder(acc, folders)
        if pj:
            wanted.append(pj)
    if _flag("own_junk"):
        own = str(_attr(acc, "junk", DEFAULT_JUNK))
        if not folders or own in {f["name"] for f in folders}:
            wanted.append(own)
    wanted = list(dict.fromkeys(wanted))
    if not wanted:
        return ui.respond("Vælg mindst én mappe, der findes på kontoen.", ok=False, next_url="/training")
    ids = []
    for f in wanted:
        try:
            ids.append(int(ui.services.queue_calibration(account, f, n, actor=_actor())))
        except ValueError as ex:
            return ui.respond(str(ex)[:200] or "Kalibreringen blev afvist.", ok=False, next_url="/training")
        except Exception as ex:  # noqa: BLE001
            log.error("queue_calibration failed: %s", type(ex).__name__)
            return ui.respond("Kalibreringen kunne ikke oprettes.", ok=False, next_url="/training")
    ui.audit("calibration_queue", account, detail=f"jobs={','.join(map(str, ids))} folders={'|'.join(wanted)} n={n}")
    return ui.respond(f"Kalibrering sat i kø for {account}: {', '.join(wanted)}.", next_url="/training", refresh=True)


@app.post("/training/preset")
@ui.admin_required
def training_preset():
    key = _form("preset", 30)
    preset = next((p for p in _presets() if p["key"] == key), None)
    if preset is None:
        return ui.respond("Ukendt forslag.", ok=False, next_url="/training")
    if not preset["jobs"]:
        return ui.respond("Der blev ikke fundet egnede mapper.", ok=False, next_url="/training")
    ids = []
    for j in preset["jobs"]:
        try:
            ids.append(_job_args(j["account"], j["folder"], j["kind"], j["max_messages"], j["min_age_days"],
                                 j["seen_only"], j["provider_filter"]))
        except Exception as ex:  # noqa: BLE001 - keep going with the other accounts
            log.warning("preset job failed for %s: %s", j["account"], type(ex).__name__)
    if not ids:
        return ui.respond("Ingen job kunne oprettes.", ok=False, next_url="/training")
    ui.audit("train_preset", detail=f"{key} jobs={','.join(map(str, ids))}")
    return ui.respond(f"{_n(len(ids), 'job', 'job')} sat i kø: {preset['title'].lower()}.", next_url="/training",
                      refresh=True)


@app.post("/training/jobs/<int:job_id>/cancel")
@ui.admin_required
def training_cancel(job_id: int):
    try:
        ok = bool(ui.services.cancel_train_job(job_id))
    except Exception as ex:  # noqa: BLE001
        log.error("cancel_train_job failed: %s", type(ex).__name__)
        ok = False
    ui.audit("train_cancel", detail=f"job={job_id}", result="ok" if ok else "noop")
    job = next((j for j in _jobs(200) if int(j["id"]) == job_id), None)
    rows = {f"job:{job_id}": render_job_row(job)} if job else {}
    if not ok:
        return ui.respond("Jobbet kører ikke længere.", ok=False, next_url="/training", rows=rows)
    return ui.respond(f"Job #{job_id} annulleres.", next_url="/training", rows=rows)


@app.get("/training/jobs.json")
@ui.admin_required
def training_jobs_json():
    jobs = _jobs()
    lists = _learn_lists()
    rows = {f"job:{int(j['id'])}": render_job_row(j) for j in jobs}
    rows.update({f"ll:{int(j['id'])}": render_learn_list_row(j) for j in lists})
    return jsonify({"ok": True, "active": any(j.get("status") in ACTIVE_JOB for j in [*jobs, *lists]),
                    "rows": rows})


# ---- 2.2 (B6): Reparér Bayes, lærelister, rebalancering ------------------------------

REPAIR_SHOW = 300                    # rows on the Træning page (the rest come when these are learned)
REPAIR_STRONG = ("phishing_rule", "user_marked_spam")
REPAIR_LABELS = {"phishing_rule": ("Phishing-regel", "bad"), "user_marked_spam": ("Markeret som spam", "warn"),
                 "provider_spam": ("Udbyderen: spam", "neutral")}
REPAIR_MAX_PICKS = 2000              # services.LEARN_LIST_MAX_ITEMS
TARGET_RATIO = 0.5                   # spam:ham >= 1:2 (services.REBALANCE_DEFAULT_RATIO)
LL_HEADERS = [("Liste", ""), ("Status", ""), ("Fremskridt", "job-prog-col"), ("Resultat", ""), ("", "end")]
LL_ITEM_FILTERS = (("", "Alle"), ("learned", "Lært"), ("already", "Var lært"), ("not_found", "Ikke fundet"),
                   ("held_out", "Reserveret til evaluering"),
                   ("deferred", "Udskudt"), ("failed", "Fejlede"), ("pending", "Venter"))
LL_ITEM_TONES = {"learned": "ok", "already": "neutral", "pending": "neutral", "not_found": "warn",
                 "ambiguous": "warn", "too_large": "warn", "deferred": "warn", "declined": "bad", "failed": "bad",
                 "held_out": "neutral"}


def _ratio_or_none(value: Any) -> float | None:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    return v if v > 0 else None


def repair_preselected(item: dict) -> bool:
    """Pre-check only strong evidence: a phishing rule or the user's own
    spam mark. A provider flag alone stays unchecked (providers err too)."""
    return any(r in REPAIR_STRONG for r in item.get("reasons") or [])


def bayes_ratio_html(st: dict) -> str:
    """Live spam:legitim ratio of the shared Bayes against the 1:2 goal."""
    if not st.get("ok"):
        return ('<div class="bayes-ratio tone-neutral"><b>Forholdet kan ikke hentes</b>'
                "<span>rspamd svarer ikke lige nu.</span></div>")
    spam, ham = int(st.get("spam_learned") or 0), int(st.get("ham_learned") or 0)
    goal = f"Mål: mindst 1 spam pr. {kit.fmt_num(1 / TARGET_RATIO, 0)} legitime"
    if not ham:
        head, tone, fill = ("Ingen legitime lært endnu" if spam else "Intet lært endnu"), "neutral", 0
    elif not spam:
        head, tone, fill = "Ingen spam lært", "bad", 0
    else:
        ratio = spam / ham
        head = (f"1 spam pr. {kit.fmt_num(ham / spam, 1)} legitime" if ratio < 1
                else f"{kit.fmt_num(ratio, 1)} spam pr. legitim")
        tone = "ok" if ratio >= TARGET_RATIO else ("warn" if ratio >= TARGET_RATIO / 2.5 else "bad")
        fill = min(100, int(ratio / TARGET_RATIO * 100))
    note = (f"{kit.fmt_int(spam)} spam · {kit.fmt_int(ham)} legitime. {goal}."
            + (" Skævt: Bayes trækker for meget mod »legitim«, også for phishing." if tone in ("warn", "bad") else ""))
    return (f'<div class="bayes-ratio tone-{tone}"><b>{h(head)}</b><span>{h(note)}</span>'
            f'{kit.progress(fill, 100, tone=tone)}</div>')


def _repair_args() -> tuple[str, str | None]:
    scope = "all" if request.values.get("repair_scope") == "all" else "learned_ham"
    acc = (request.values.get("repair_account") or "").strip()
    return scope, (acc if acc and ui.account_by_name(acc) is not None else None)


REPAIR_RULE_SHORT = {"TH_BRAND_SPOOF": "falsk brand", "TH_FROM_NAME_HOMOGLYPH": "forklædte bogstaver",
                     "TH_LURE_COMBO": "lokkemail", "TH_FROM_ABUSED_TLD": "misbrugt topdomæne",
                     "DBL_PHISH": "phishing-link"}


def _rule_short(name: str) -> str:
    return REPAIR_RULE_SHORT.get(name) or ("kendt phishing-link" if str(name).startswith("PHISHED_") else str(name))


def _repair_reason_chips(item: dict) -> str:
    chips = []
    for r in item.get("reasons") or []:
        label, tone = REPAIR_LABELS.get(r, (r, "neutral"))
        if r == "phishing_rule" and item.get("symbols"):
            label += ": " + ", ".join(dict.fromkeys(_rule_short(n) for n in item["symbols"][:3]))
        chips.append(kit.chip(label, tone))
    return "".join(chips)


def _repair_rows(items: list[dict]) -> list[dict]:
    rows = []
    for it in items:
        acc, mid = str(it.get("account") or ""), str(it.get("message_id") or "")
        name, addr = kit.sender_parts(it.get("sender"))
        value = f"{acc}:{kit.token_for(mid)}"
        box = (f'<input type="checkbox" class="check" name="pick" value="{h(value)}" data-check-item '
               f'aria-label="Vælg {h(it.get("subject") or mid)}"{" checked" if repair_preselected(it) else ""}>')
        mail = (f'<div class="cal-mail"><a class="truncate card-link" href="/messages/{h(_q(acc))}/{h(kit.token_for(mid))}">'
                f'{h(it.get("subject") or "(intet emne)")}</a>'
                f'<span class="faint small truncate">{h(name or addr or "Ukendt afsender")}'
                f'{" · " + h(addr) if name and addr else ""}</span></div>')
        learned = {"ham": kit.badge("Legitim", "warn"), None: kit.badge("Ikke lært", "neutral")}.get(
            it.get("learned_as"), kit.badge(str(it.get("learned_as")), "neutral"))
        score = it.get("score")
        rows.append({"cells": [box, mail, ui.account_name_html(acc), f'<div class="chip-row">{_repair_reason_chips(it)}</div>',
                               (kit.fmt_score(score) if score is not None else "–"), learned],
                     "attrs": f'title="{h(it.get("text") or "")}"'})
    return rows


def _repair_filters(scope: str, account: str | None) -> str:
    opts = [("", "Alle konti")] + [(a.name, ui.account_label(a.name)) for a in ui.effective_accounts()]
    return (f'<form method="get" action="/training#reparer" class="repair-filters" data-autosubmit>'
            + kit.select("repair_account", opts, account or "", attrs='aria-label="Konto"')
            + kit.select("repair_scope", [("learned_ham", "Lært som legitim"), ("all", "Også aldrig lærte")], scope,
                         attrs='aria-label="Hvilke mails"')
            + '<noscript><button class="btn btn-secondary btn-sm" type="submit">Vis</button></noscript></form>')


def _repair_card() -> str:
    scope, account = _repair_args()
    res = _svc("bayes_repair_candidates", account, scope=scope, limit=REPAIR_SHOW, default=None)
    ratio = ('<div data-fragment="/training/bayes?part=ratio" aria-busy="true">' + kit.skeleton(1) + "</div>")
    intro = ('<p class="muted">Tidligere træningsjob lærte hele indbakken som legitim post – også den phishing, '
             "der lå der. Her er mails, filteret har lært som legitime, men som noget tyder på er spam. "
             "Lær de valgte som spam, så retter Bayes sig. Intet flyttes, og det kan fortrydes ved at lære mailen "
             "som legitim igen.</p>")
    rebalance = (f'<div class="repair-rebalance">{kit.icon("sliders")}<div><b>For lidt spam i hukommelsen?</b>'
                 "<span>Lær spam fra Spamfilter-mappen og udbydernes Junk-mapper, indtil der er mindst 1 spam "
                 "pr. 2 legitime. Du ser planen, før noget starter.</span></div>"
                 + kit.button("Rebalancér fra spam-mapper", href="/training/rebalance", kind="secondary", size="sm",
                              icon="sliders") + "</div>")
    skipped = int(((res or {}).get("counts") or {}).get("provider_only_skipped") or 0) if isinstance(res, dict) else 0
    skipped_note = (f'<p class="faint small">{kit.fmt_int(skipped)} '
                    f'{"mail" if skipped == 1 else "mails"} fra Gigahost er udeladt: udbyderens spam-markering alene '
                    "er ikke nok der, fordi Gigahost også markerer rigtige fakturaer som spam.</p>") if skipped else ""
    if not isinstance(res, dict) or not res.get("ok"):
        listing = kit.alert("Kandidaterne kunne ikke hentes lige nu.", "warn")
    elif not res.get("items"):
        listing = kit.empty_state(
            "Ingen kandidater lige nu",
            "De nye phishing-regler ser kun mails, der er scannet efter opdateringen. Kør en kalibrering af "
            "Indbakken, så filteret kan finde phishing, det tidligere har lært som legitim post.",
            "check-circle", kit.button("Kalibrér Indbakken", href="#kalibrering", kind="secondary", icon="sliders"))
    else:
        items = res["items"]
        total = int(res.get("total") or len(items))
        counts = (res.get("counts") or {}).get("by_reason") or {}
        chips = "".join(kit.chip(f"{REPAIR_LABELS[k][0]}: {kit.fmt_int(counts.get(k, 0))}", REPAIR_LABELS[k][1])
                        for k in REPAIR_LABELS if counts.get(k))
        pre = sum(1 for it in items if repair_preselected(it))
        table = kit.table([("Vælg", "check-col"), ("Mail", ""), ("Konto", ""), ("Begrundelse", ""), ("Score", "end"),
                           ("Lært som", "")], _repair_rows(items), cls="repair-table")
        more = (f'<p class="faint small">Viser de første {kit.fmt_int(len(items))} af {kit.fmt_int(total)}. '
                "Lær dem først – så kommer resten frem.</p>" if res.get("truncated") or total > len(items) else "")
        note = ("Forvalgt: mails med en phishing-regel eller som en bruger selv har lagt i spam. "
                "Mails, som kun udbyderen kaldte spam, er ikke forvalgt – udbydere tager også fejl.")
        submit = kit.button("Lær de valgte som spam", kind="danger", icon="graduation-cap", attrs=kit.confirm_attrs(
            "Lær de valgte som spam?",
            "De valgte mails læres som spam i den fælles Bayes-hukommelse – også dem, der ligger i indbakken. "
            "Intet flyttes. Det sker i baggrunden, én mail ad gangen.", confirm="Lær som spam", tone="danger"))
        inner = (kit.hidden("repair_scope", scope)
                 + f'<div class="repair-summary"><label class="check-all"><input type="checkbox" class="check" '
                 f'data-check-all{" checked" if pre == len(items) else ""}><span>Vælg alle</span></label>'
                 f'<span class="faint small"><span class="num" data-check-count>{kit.fmt_int(pre)}</span> af '
                 f'{kit.fmt_int(len(items))} valgt</span><span class="spacer"></span>'
                 f'<div class="chip-row">{chips}</div></div>'
                 + f'<div class="repair-scroll">{table}</div>{more}'
                 + f'<p class="faint small">{h(note)}</p>'
                 + f'<div class="form-actions">{submit}</div>')
        listing = kit.post_form("/training/repair/learn", inner, cls="repair-form")
    body = (ratio + intro + _repair_filters(scope, account) + listing + skipped_note + rebalance)
    return f'<div id="reparer">' + kit.card(body, title="Reparér Bayes",
                                            subtitle="Phishing, som filteret ved en fejl har lært som legitim post.",
                                            cls="repair-card") + "</div>"


@app.post("/training/repair/learn")
@ui.admin_required
def training_repair_learn():
    picks = [p for p in request.form.getlist("pick") if p][: REPAIR_MAX_PICKS + 1]
    if not picks:
        return ui.respond("Vælg mindst én mail.", ok=False, next_url="/training#reparer")
    if len(picks) > REPAIR_MAX_PICKS:
        return ui.respond(f"Højst {kit.fmt_int(REPAIR_MAX_PICKS)} mails ad gangen.", ok=False,
                          next_url="/training#reparer")
    scope, _account = _repair_args()
    cands = _svc("bayes_repair_candidates", None, scope=scope, limit=REPAIR_MAX_PICKS, default=None)
    if not isinstance(cands, dict) or not cands.get("ok"):
        return ui.respond("Kandidaterne kunne ikke hentes lige nu. Prøv igen om lidt.", ok=False,
                          next_url="/training#reparer")
    known = {(str(i.get("account")), str(i.get("message_id"))): i for i in cands.get("items") or []}
    items, stale = [], 0
    for p in dict.fromkeys(picks):
        acc, _sep, token = p.partition(":")
        mid = kit.msgid_from_token(token)
        it = known.get((acc, mid or ""))
        if it is None:
            stale += 1  # forged, or learned meanwhile: only current candidates are learned
            continue
        items.append({"account": acc, "message_id": mid, "kind": "spam", "reason": str(it.get("text") or "")[:200]})
    if not items:
        return ui.respond("De valgte mails er ikke længere kandidater. Genindlæs siden.", ok=False,
                          next_url="/training#reparer")
    try:
        res = ui.services.queue_learn_list(items, _actor(), kind="spam", note="Reparér Bayes")
    except Exception as ex:  # noqa: BLE001
        log.error("queue_learn_list failed: %s", type(ex).__name__)
        res = {"ok": False, "code": "error", "text": "Listen kunne ikke oprettes."}
    ok = bool(res.get("ok"))
    ui.audit("bayes_repair_learn", result="ok" if ok else "failed",
             detail=(res.get("audit_detail") or f"code={res.get('code')}") + (f" stale={stale}" if stale else ""))
    text = str(res.get("text") or ("Listen er sat i kø." if ok else "Listen kunne ikke oprettes."))
    if ok and stale:
        text += f" {_n(stale, 'mail', 'mails')} var ikke længere kandidater og blev sprunget over."
    return ui.respond(text, ok=ok, next_url="/training#laerelister", refresh=ok)


# ---- lærelister (learn-list jobs) ---------------------------------------------------


def _learn_lists(limit: int = 10) -> list[dict]:
    jobs = _svc("list_learn_list_jobs", limit, default=[]) or []
    return [j for j in jobs if isinstance(j, dict) and "id" in j]


def _ll_retryable(j: dict) -> bool:
    """Only when services.retry_learn_list would re-queue something: failed,
    deferred and (stopped job) pending items - not ambiguous/too_large/declined,
    which 'skipped' also counts."""
    if str(j.get("status")) not in ("done", "failed", "cancelled"):
        return False
    if "retryable" in j:
        return int(j.get("retryable") or 0) > 0
    return int(j.get("failed") or 0) > 0


def _ll_actions(j: dict, *, size: str = "sm", detail: bool = True) -> str:
    jid, status = int(j["id"]), str(j.get("status") or "")
    out = []
    if detail:
        out.append(kit.button("Detaljer", href=f"/training/learn-lists/{jid}", kind="ghost", size=size))
    if status in ("queued", "running"):
        out.append(kit.post_form(f"/training/learn-lists/{jid}/cancel", kit.button(
            "Stop", kind="ghost", size=size, icon="x",
            attrs=kit.confirm_attrs(f"Stop læreliste #{jid}?", "Det, der allerede er lært, bevares.",
                                    confirm="Stop", tone="danger"))))
    if _ll_retryable(j):
        out.append(kit.post_form(f"/training/learn-lists/{jid}/retry", kit.button(
            "Prøv igen", kind="secondary", size=size, icon="refresh",
            attrs='title="Lærer de mails igen, der fejlede, blev udskudt eller ikke nåede at komme med"')))
    return f'<div class="row-tight job-actions">{"".join(out)}</div>'


def learn_list_row(j: dict) -> dict:
    jid = int(j["id"])
    status = str(j.get("status") or "queued")
    st_label, st_tone = JOB_STATUS.get(status, (status, "neutral"))
    total, processed = int(j.get("total") or 0), int(j.get("processed") or 0)
    tone = {"done": "ok", "failed": "bad", "cancelled": "neutral", "cancel_requested": "warn"}.get(status, "brand")
    prog = (f'<div class="job-prog">{kit.progress(_job_percent(j), 100, tone=tone)}'
            f'<span class="faint small num">{kit.fmt_int(processed)} / {kit.fmt_int(total)}</span></div>')
    counts = f'<span class="num">{kit.fmt_int(j.get("learned") or 0)}</span> <span class="faint">lært</span>'
    for key, word, cls in (("already", "var lært", ""), ("not_found", "ikke fundet", ""),
                           ("skipped", "udskudt", ""), ("failed", "fejl", " tone-bad")):
        if j.get(key):
            counts += f' · <span class="num{cls}">{kit.fmt_int(j[key])}</span> <span class="faint">{word}</span>'
    if j.get("error"):
        counts += f'<div class="faint small">{h(str(j["error"])[:160])}</div>'
    what = (f'<div class="job-what"><b>{h(j.get("note") or "Læreliste")}</b>'
            f'<span class="faint small">#{jid} · {h(kit.ago(j.get("created_at")))}'
            + (f' · {h(j.get("created_by"))}' if j.get("created_by") else "") + "</span></div>")
    active = ' data-job-active="1"' if status in ACTIVE_JOB else ""
    return {"cells": [what, kit.badge(st_label, st_tone), prog, f'<span class="job-counts">{counts}</span>',
                      _ll_actions(j)],
            "attrs": f'data-row="ll:{jid}"{active}'}


def render_learn_list_row(j: dict) -> str:
    html = kit.table(LL_HEADERS, [learn_list_row(j)])
    m = re.search(r"<tbody>(.*)</tbody>", html, re.S)
    return m.group(1) if m else ""


def _learn_list_or_404(job_id: int) -> dict:
    job = _svc("learn_list_job", job_id, default=None)
    if not isinstance(job, dict):
        abort(404)
    return job


@app.get("/training/learn-lists/<int:job_id>")
@ui.admin_required
def training_learn_list_page(job_id: int):
    job = _learn_list_or_404(job_id)
    status = (request.args.get("status") or "").strip()
    if status not in dict(LL_ITEM_FILTERS):
        status = ""
    items = _svc("learn_list_items", job_id, status=status or None, limit=500, default=[]) or []
    st_label, st_tone = JOB_STATUS.get(str(job.get("status")), (str(job.get("status")), "neutral"))
    kv = kit.kv_list([
        ("Status", kit.badge(st_label, st_tone) + (f' <span class="faint">{h(job.get("text") or "")}</span>'
                                                   if job.get("text") else "")),
        ("Fremskridt", f'{kit.fmt_int(job.get("processed") or 0)} af {kit.fmt_int(job.get("total") or 0)} '
                       f'({kit.fmt_int(job.get("percent") or 0)} %)'),
        ("Lært", kit.fmt_int(job.get("learned") or 0)), ("Var allerede lært", kit.fmt_int(job.get("already") or 0)),
        ("Ikke fundet", kit.fmt_int(job.get("not_found") or 0)),
        ("Udskudt / fejl", f'{kit.fmt_int(job.get("skipped") or 0)} / {kit.fmt_int(job.get("failed") or 0)}'),
        ("Oprettet", h(kit.fmt_ts(job.get("created_at"))) + (f' af {h(job.get("created_by"))}'
                                                             if job.get("created_by") else "")),
    ])
    summary = kit.card(kv + f'<div class="form-actions">{_ll_actions(job, size="", detail=False)}</div>',
                       title=str(job.get("note") or "Læreliste"),
                       subtitle="Hver mail findes ud fra sin Message-ID og læres for sig. Intet flyttes.")
    tabs = kit.seg_links([(label, f"/training/learn-lists/{job_id}" + (f"?status={key}" if key else ""), key == status)
                          for key, label in LL_ITEM_FILTERS])
    rows = []
    for it in items:
        name, addr = kit.sender_parts(it.get("sender"))
        st = str(it.get("status") or "")
        rows.append([
            f'<div class="cal-mail"><b class="truncate">{h(it.get("subject") or it.get("message_id") or "")}</b>'
            f'<span class="faint small truncate">{h(name or addr or "Ukendt afsender")}</span></div>',
            ui.account_name_html(str(it.get("account") or "")),
            kit.badge(it.get("status_text") or st, LL_ITEM_TONES.get(st, "neutral")),
            h(_svc("folder_label", it.get("folder"), default=it.get("folder")) if it.get("folder") else "–"),
            f'<span class="faint small">{h(it.get("reason") or "")}</span>',
        ])
    listing = (kit.table([("Mail", ""), ("Konto", ""), ("Status", ""), ("Fundet i", ""), ("Begrundelse", "")], rows,
                         cls="repair-table")
               if rows else kit.empty_state("Ingen mails her", "Vælg et andet filter.", "list-checks"))
    body = summary + kit.card(f'<div class="card-pad">{tabs}</div>{listing}', title="Mails", cls="flush")
    return _page(f"Læreliste #{job_id}", body, active="training",
                 breadcrumbs=[("Træning", "/training"), (f"Læreliste #{job_id}", None)])


@app.post("/training/learn-lists/<int:job_id>/cancel")
@ui.admin_required
def training_learn_list_cancel(job_id: int):
    try:
        ok = bool(ui.services.cancel_learn_list_job(job_id))
    except Exception as ex:  # noqa: BLE001
        log.error("cancel_learn_list_job failed: %s", type(ex).__name__)
        ok = False
    ui.audit("learn_list_cancel", detail=f"learn_list={job_id}", result="ok" if ok else "noop")
    job = _svc("learn_list_job", job_id, default=None)
    rows = {f"ll:{job_id}": render_learn_list_row(job)} if isinstance(job, dict) else {}
    if not ok:
        return ui.respond("Listen kører ikke længere.", ok=False, next_url="/training#laerelister", rows=rows)
    return ui.respond(f"Læreliste #{job_id} stoppes. Det, der allerede er lært, bevares.",
                      next_url="/training#laerelister", rows=rows)


@app.post("/training/learn-lists/<int:job_id>/retry")
@ui.admin_required
def training_learn_list_retry(job_id: int):
    _learn_list_or_404(job_id)
    try:
        res = ui.services.retry_learn_list(job_id, _actor())
    except Exception as ex:  # noqa: BLE001
        log.error("retry_learn_list failed: %s", type(ex).__name__)
        res = {"ok": False, "code": "error", "text": "Listen kunne ikke oprettes."}
    ok = bool(res.get("ok"))
    if res.get("code") == "empty":
        text = "Der er ingen mails at prøve igen."
    else:
        text = str(res.get("text") or ("Sat i kø igen." if ok else "Listen kunne ikke oprettes."))
    ui.audit("learn_list_retry", result="ok" if ok else "noop",
             detail=f"from={job_id} " + (res.get("audit_detail") or f"code={res.get('code')}"))
    return ui.respond(text, ok=ok, next_url="/training#laerelister", refresh=ok)


# ---- rebalancering (B6b) ---------------------------------------------------------------

REBALANCE_KIND = {"filter_junk": ("Spamfilter-mappen", "brand"), "provider_junk": ("Udbyderens spam", "warn"),
                  "trash": ("Papirkurv (kun udbyder-spam)", "neutral")}


def _rebalance_trash() -> bool:
    return (request.values.get("trash") or "") in ("1", "on")


@app.get("/training/rebalance")
@ui.admin_required
def training_rebalance_page():
    trash = _rebalance_trash()
    res = _svc("queue_bayes_rebalance", _actor(), include_trash=trash, dry_run=True, default=None)
    crumbs = [("Træning", "/training"), ("Rebalancér", None)]
    if not isinstance(res, dict):
        body = kit.card(kit.alert("Planen kunne ikke laves lige nu. Prøv igen om lidt.", "bad"))
        return _page("Rebalancér Bayes", body, active="training", breadcrumbs=crumbs)
    st = res.get("bayes") or {}
    code = str(res.get("code") or "")
    parts = []
    if st:
        parts.append(bayes_ratio_html({"ok": True, "spam_learned": st.get("spam"), "ham_learned": st.get("ham")}))
    tone = {"plan": "info", "balanced": "ok", "rspamd": "bad", "nothing": "info", "config": "bad"}.get(code, "warn")
    parts.append(kit.alert(res.get("text") or "Ingen plan.", tone))
    for err in res.get("errors") or []:
        parts.append(kit.alert(f"{ui.account_label(str(err.get('account') or ''))}: {err.get('text') or err.get('code')}",
                               "warn"))
    jobs = res.get("jobs") or []
    if jobs:
        rows = []
        for p in jobs:
            label, ktone = REBALANCE_KIND.get(str(p.get("kind")), (str(p.get("kind")), "neutral"))
            rows.append([ui.account_name_html(str(p.get("account") or "")),
                         f'<span class="mono small">{h(p.get("label") or p.get("folder") or "")}</span>',
                         kit.badge(label, ktone), kit.fmt_int(p.get("messages") or 0),
                         kit.fmt_int(p.get("max_messages") or 0)])
        parts.append(kit.table([("Konto", ""), ("Mappe", ""), ("Type", ""), ("Mails", "end"), ("Højst", "end")], rows,
                               cls="repair-table"))
        parts.append('<p class="faint small">Hvert job tager de nyeste mails, der er mindst 3 dage gamle (så der er '
                     "tid til at redde en fejl), og stopper af sig selv, så snart forholdet er nået. "
                     "Indbakken bruges aldrig.</p>")
    opts = (f'<form method="get" action="/training/rebalance" class="rebalance-opts">'
            f'{kit.switch("trash", trash, "Brug også papirkurven (kun mails, udbyderen kaldte spam)")}'
            + kit.button("Opdatér plan", kind="secondary", size="sm", icon="refresh") + "</form>")
    parts.append(opts)
    if code == "plan" and jobs:
        start = kit.post_form("/training/rebalance", (kit.hidden("trash", "1" if trash else "0")
            + '<div class="form-actions">' + kit.button(
                f"Start {_n(len(jobs), 'job', 'job')}", kind="primary", icon="graduation-cap",
                attrs=kit.confirm_attrs("Start rebalancering?",
                                        f"{_n(len(jobs), 'træningsjob', 'træningsjob')} lærer spam fra mapperne ovenfor "
                                        "og stopper, når Bayes har mindst 1 spam pr. 2 legitime. Intet flyttes.",
                                        confirm="Start"))
            + kit.button("Tilbage", href="/training", kind="ghost") + "</div>"))
        parts.append(start)
    else:
        parts.append('<div class="form-actions">' + kit.button("Tilbage til Træning", href="/training", kind="secondary",
                                                               icon="arrow-left") + "</div>")
    body = kit.card(f'<div class="rebalance-body">{"".join(parts)}</div>', title="Plan for rebalancering",
                    subtitle="Planen bygger på mappernes størrelse – intet er ændret, og intet er startet endnu.")
    return _page("Rebalancér Bayes", body, active="training", breadcrumbs=crumbs,
                 subtitle="Lær spam fra spam-mapperne, til Bayes har mindst 1 spam pr. 2 legitime.")


@app.post("/training/rebalance")
@ui.admin_required
def training_rebalance():
    trash = _rebalance_trash()
    try:
        res = ui.services.queue_bayes_rebalance(_actor(), include_trash=trash, dry_run=False)
    except Exception as ex:  # noqa: BLE001
        log.error("queue_bayes_rebalance failed: %s", type(ex).__name__)
        res = {"ok": False, "code": "error", "text": "Rebalanceringen kunne ikke startes."}
    ok = bool(res.get("ok"))
    queued = res.get("code") == "queued"
    ui.audit("bayes_rebalance", result="ok" if queued else ("noop" if ok else "failed"),
             detail=res.get("audit_detail") or f"code={res.get('code')} trash={int(trash)}")
    return ui.respond(str(res.get("text") or ("Sat i kø." if ok else "Rebalanceringen kunne ikke startes.")),
                      ok=ok, next_url="/training", refresh=queued)


# ---- 2.3 follow-up: 'Byg Bayes op på ny' (services.bayes_rebuild_*) --------------------

REBUILD_WORD = "BYG OP"                 # typed confirmation (no-JS: the visible field)
REBUILD_DEFAULT_RATIO = 2.0              # services.REBUILD_DEFAULT_RATIO (1 spam : 2 legitime)
REBUILD_RATIOS = ((1.0, "1 legitim pr. spam"), (1.5, "1,5 legitime pr. spam"),
                  (2.0, "2 legitime pr. spam (anbefalet)"), (3.0, "3 legitime pr. spam"))
REBUILD_KIND = {"filter_junk": ("Spamfilter-mappen", "brand"), "provider_junk": ("Udbyderens spam", "warn"),
                "spam_folder": ("Anden spam-mappe", "warn"), "learn_list": ("Enkeltmails", "info")}
REBUILD_ACTIVE = ("starting", "running")
REBUILD_WHY = ("Da filteret blev sat op, lærte det hele indbakker som legitim post – også den spam og phishing, "
               "der lå i dem. Derfor trækker Bayes i dag for meget mod »legitim«. En ny Bayes lærer kun af "
               "mails, vi ved, hvad er: spam fra spam-mapperne og legitim post fra jeres egne arkivmapper.")


def _rebuild_ratio(value: Any) -> float:
    r = _parse_float(str(value or ""))
    return r if r is not None and any(abs(r - x) < 1e-9 for x, _l in REBUILD_RATIOS) else REBUILD_DEFAULT_RATIO


def _rebuild_status() -> dict:
    if "_adm_rebuild" not in g:
        st = _svc("bayes_rebuild_status", default=None)
        g._adm_rebuild = st if isinstance(st, dict) else {"ok": False, "code": "db"}
    return g._adm_rebuild


def _bayes_pool() -> str:
    return str((_rebuild_status() or {}).get("pool") or "")


def _pool_name(pool: Any) -> str:
    return f'<span class="mono">{h(pool or "ukendt")}</span>'


def _rebuild_facts(plan: dict | None = None) -> str:
    plan = plan or {}
    low = kit.fmt_int(int(plan.get("min_learns") or 200))
    old = str(plan.get("pool_now") or _bayes_pool() or "den nuværende")
    facts = [
        ("shield-alert", "Spam", "læres fra Spamfilter-mappen og udbydernes spam-mapper – også gammel spam – og fra "
                                 "enkeltmails, I selv har lagt i spam."),
        ("inbox", "Legitim post", "læres kun fra jeres egne arkivmapper, de nyeste først – aldrig fra Indbakken, Sendt, "
                              "Kladder eller Papirkurven."),
        ("pause", "Bayes er slået fra", f"indtil den nye har lært mindst {low} spam og {low} legitime. Imens afgør "
                                        "filterets andre regler alene."),
        ("database", "Den gamle Bayes gemmes", f"urørt som backup (puljen {old}). Du kan gendanne den med ét klik."),
        ("check-circle", "Intet i postkasserne", "flyttes, markeres eller slettes – mails bliver kun læst."),
    ]
    return ('<ul class="learn-facts rebuild-facts">' + "".join(
        f'<li>{kit.icon(ic)}<span><b>{h(t)}</b> {h(txt)}</span></li>'
        for ic, t, txt in facts) + "</ul>")


def _rebuild_restore_form(*, size: str = "", primary: bool = False) -> str:
    return kit.post_form("/training/rebuild/restore", kit.button(
        "Gendan tidligere Bayes", kind="primary" if primary else "secondary", icon="undo", size=size,
        attrs=kit.confirm_attrs("Gendan den tidligere Bayes?",
                                "Filteret skifter tilbage til den gamle Bayes-hukommelse, og genopbygningens job "
                                "stoppes. Den nye pulje bliver liggende urørt. Intet i postkasserne ændres.",
                                confirm="Gendan", tone="danger")), cls="inline-form")


def _rebuild_counts(st: dict) -> str:
    low = int(st.get("min_learns") or 200)
    b = st.get("bayes") or {}
    rows = []
    for key, label, exp_key in (("learned_spam", "Spam lært", "expected_spam"),
                                ("learned_ham", "Legitime lært", "expected_ham")):
        n, exp = int(st.get(key) or 0), int(st.get(exp_key) or 0)
        rows.append(f'<div class="rebuild-num"><b class="num">{kit.fmt_int(n)}</b>'
                    f'<span>{h(label)}</span><small>af ca. {kit.fmt_int(exp)}</small></div>')
    gate = ""
    if b.get("ok"):
        spam, ham = int(b.get("spam") or 0), int(b.get("ham") or 0)
        tone = "ok" if b.get("active") else "warn"
        head = ("Bayes er aktiv" if b.get("active") else
                f"Bayes er slået fra, indtil begge har {kit.fmt_int(low)}")
        gate = (f'<div class="rebuild-gate tone-{tone}"><b>{h(head)}</b>'
                + kit.progress(min(spam, low), low, tone="bad" if spam < low else "ok", label="Spam i den nye Bayes")
                + kit.progress(min(ham, low), low, tone="warn" if ham < low else "ok",
                               label="Legitime i den nye Bayes")
                + "</div>")
    return f'<div class="rebuild-nums">{"".join(rows)}</div>{gate}'


def rebuild_status_html(st: dict) -> str:
    """The live part of the 'Byg Bayes op på ny' card (polled while active)."""
    code = str(st.get("code") or "")
    if not st.get("ok") and code == "db":
        return kit.alert(st.get("text") or "Status for genopbygningen kan ikke hentes lige nu.", "warn")
    active = code in REBUILD_ACTIVE
    parts: list[str] = []
    plan_btn = kit.button("Se planen", href="/training/rebuild", kind="primary", icon="graduation-cap")
    again_btn = kit.button("Byg op på ny igen", href="/training/rebuild", kind="ghost", icon="refresh", size="sm")
    pool = st.get("pool")
    if code == "none":
        parts.append(f'<p class="rebuild-pool">Aktiv Bayes-pulje: {_pool_name(pool)}</p>')
        parts.append(f'<div class="form-actions">{plan_btn}</div>')
        return '<div class="rebuild-state">' + "".join(parts) + "</div>"
    when = kit.fmt_ts(st.get("created_at")) if st.get("created_at") else ""
    who = str(st.get("created_by") or "")
    meta = " · ".join(x for x in (f"startet {when}" if when else "", f"af {who}" if who else "") if x)
    head_tone = {"starting": "info", "running": "info", "done": "ok", "restored": "neutral",
                 "failed": "bad", "restoring": "warn"}.get(code, "neutral")
    if code == "done" and st.get("warnings"):
        head_tone = "warn"
    head = {"starting": "Genopbygningen starter", "running": "Genopbygning i gang", "done": "Genopbygningen er færdig",
            "restored": "Den tidligere Bayes er gendannet", "failed": "Genopbygningen stoppede",
            "restoring": "Gendannelsen er ikke færdig"}.get(code, "Status")
    parts.append(f'<div class="rebuild-head tone-{head_tone}">{kit.badge(head, head_tone)}'
                 f'<span class="faint small">{_pool_name(st.get("pool_old"))} → {_pool_name(st.get("pool_new"))}'
                 + (f" · {h(meta)}" if meta else "") + "</span></div>")
    if active:
        pct = max(0, min(100, int(st.get("percent") or 0)))
        parts.append(kit.progress(pct, 100, tone="brand", label="Genopbygning", value_text=f"{pct} %"))
    parts.append(f'<p class="rebuild-text">{h(st.get("text") or "")}</p>')
    if code in ("starting", "running", "done"):
        parts.append(_rebuild_counts(st))
    for w in st.get("warnings") or []:
        parts.append(kit.alert(str(w), "warn"))
    if (st.get("bayes") or {}).get("counts_source") == "all_pools":
        parts.append('<p class="faint small">Tallene er summen af alle Bayes-puljer – tallet for den aktive pulje '
                     "kendes ikke, fordi rspamd ikke svarede ved skiftet.</p>")
    acts = []
    if st.get("can_restore"):
        # When rspamd answered »allerede lært« (or a restore is unfinished)
        # going back is the right next step: make it the primary button.
        acts.append(_rebuild_restore_form(primary=bool(st.get("warnings")) or code == "restoring"))
    if not active and code != "restoring":
        acts.append(again_btn)
    if acts:
        parts.append(f'<div class="form-actions rebuild-acts">{"".join(acts)}</div>')
    marker = " data-rebuild-active" if active else ""
    return f'<div class="rebuild-state"{marker}>' + "".join(parts) + "</div>"


def _rebuild_card() -> str:
    live = ('<div class="rebuild-live" data-rebuild-live="/training/rebuild/status" '
            'data-fragment="/training/rebuild/status" aria-live="polite" aria-busy="true">'
            + kit.skeleton(2) + "</div>"
            '<noscript><p class="muted"><a class="card-link" href="/training/rebuild">Vis status og plan</a></p>'
            "</noscript>")
    why = f'<p class="muted rebuild-why">{h(REBUILD_WHY)}</p>'
    return '<div id="genopbyg">' + kit.card(
        why + live, title="Byg Bayes op på ny",
        subtitle="Start forfra med en ren Bayes, der kun lærer af sikre eksempler.", cls="rebuild-card") + "</div>"


@app.get("/training/rebuild/status")
@ui.admin_required
def training_rebuild_status():
    st = _rebuild_status()
    html = rebuild_status_html(st)
    if ui.wants_json():
        return jsonify({"ok": bool(st.get("ok")), "code": st.get("code"), "html": html,
                        "active": str(st.get("code") or "") in REBUILD_ACTIVE})
    if request.headers.get("Sec-Fetch-Mode") == "navigate":
        return _page("Byg Bayes op på ny", kit.card(html), active="training",
                     breadcrumbs=[("Træning", "/training"), ("Byg Bayes op på ny", None)])
    return html


def _rebuild_source_rows(sources: list[dict], *, spam: bool) -> list[list[str]]:
    rows = []
    for s in sources:
        planned = int(s.get("planned") or 0)
        if planned <= 0:
            continue
        acct = str(s.get("account") or "")
        if s.get("kind") == "learn_list":
            where = f'<span class="small">{h(s.get("label") or "Enkeltmails")}</span>'
        else:
            where = f'<span class="mono small">{h(s.get("label") or s.get("folder") or "")}</span>'
        cells = [ui.account_name_html(acct), where]
        if spam:
            label, tone = REBUILD_KIND.get(str(s.get("kind")), (str(s.get("kind") or ""), "neutral"))
            cells.append(kit.badge(label, tone))
        cells += [kit.fmt_int(s.get("messages") or 0), kit.fmt_int(planned)]
        rows.append(cells)
    return rows


def _rebuild_plan_html(plan: dict, ratio: float) -> str:
    code = str(plan.get("code") or "")
    parts: list[str] = []
    if not plan.get("ok"):
        parts.append(kit.alert(plan.get("text") or "Planen kunne ikke laves lige nu. Prøv igen om lidt.",
                               "bad" if code in ("config", "db") else "warn"))
        return "".join(parts)
    low = int(plan.get("min_learns") or 200)
    exp_spam, exp_ham = int(plan.get("expected_spam") or 0), int(plan.get("expected_ham") or 0)
    tiles = [("Spam læres", exp_spam, "bad"), ("Legitime læres", exp_ham, "ok")]
    parts.append('<div class="rebuild-nums is-plan">' + "".join(
        f'<div class="rebuild-num tone-{t}"><b class="num">ca. {kit.fmt_int(n)}</b><span>{h(lab)}</span>'
        f'<small>{"nok til at slå Bayes til" if n >= low else f"under de {kit.fmt_int(low)}, Bayes skal bruge"}</small>'
        "</div>" for lab, n, t in tiles)
        + f'<div class="rebuild-num"><b class="mono">{h(plan.get("pool_new") or "–")}</b><span>Ny Bayes-pulje</span>'
          f'<small>gammel: {h(plan.get("pool_now") or "–")}</small></div></div>')
    if plan.get("text"):
        parts.append(f'<p class="rebuild-text">{h(plan["text"])}</p>')
    for w in plan.get("warnings") or []:
        parts.append(kit.alert(str(w), "warn"))
    for err in plan.get("errors") or []:
        parts.append(kit.alert(f"{ui.account_label(str(err.get('account') or ''))}: "
                               f"{err.get('text') or err.get('code') or 'fejl'}", "warn"))
    spam_rows = _rebuild_source_rows(list(plan.get("spam_sources") or []), spam=True)
    ham_rows = _rebuild_source_rows(list(plan.get("ham_sources") or []), spam=False)
    parts.append('<h3 class="rebuild-sub">Spam – kilder</h3>' + kit.table(
        [("Konto", ""), ("Mappe", ""), ("Type", ""), ("Mails", "end"), ("Læres", "end")], spam_rows,
        empty="Ingen spam-mapper med mails fundet.", cls="repair-table rebuild-table"))
    parts.append('<h3 class="rebuild-sub">Legitim post – kilder</h3>' + kit.table(
        [("Konto", ""), ("Arkivmappe", ""), ("Mails", "end"), ("Læres", "end")], ham_rows,
        empty="Ingen arkivmapper med mails fundet.", cls="repair-table rebuild-table"))
    parts.append(f'<p class="faint small">Højst {h(_ratio_text(ratio))}. De legitime spredes over postkasser og '
                 "mapper, så ingen enkelt mappe fylder det hele. Jobbene kører ét ad gangen i baggrunden.</p>")
    opts = (f'<form method="get" action="/training/rebuild" class="rebalance-opts">'
            + kit.form_field("Forhold", kit.select("ratio", [(f"{r:g}", lab) for r, lab in REBUILD_RATIOS],
                                                   f"{ratio:g}", attrs='id="rebuild-ratio"'))
            + kit.button("Opdatér plan", kind="secondary", icon="refresh") + "</form>")
    parts.append(opts)
    return "".join(parts)


def _ratio_text(ratio: float) -> str:
    return f"{kit.fmt_num(ratio, 1 if ratio % 1 else 0)} legitime pr. spam"


def _rebuild_start_form(plan: dict, ratio: float) -> str:
    field_id = "rebuild-confirm"
    inner = (kit.hidden("ratio", f"{ratio:g}")
             + '<div class="rebuild-confirm">'
             + kit.form_field(f"Skriv {REBUILD_WORD} for at bekræfte",
                              kit.input_("confirm", "", attrs=(f'id="{field_id}" autocomplete="off" '
                                                                'autocapitalize="characters" spellcheck="false" '
                                                                f'data-typed-confirm="{h(REBUILD_WORD)}" '
                                                                'enterkeyhint="go" required')),
                              hint=(f"Ca. {kit.fmt_int(plan.get('expected_spam') or 0)} spam og "
                                    f"{kit.fmt_int(plan.get('expected_ham') or 0)} legitime lægges i kø. Filteret "
                                    "skifter straks til den nye, tomme Bayes – den gamle gemmes som backup."))
             + '<div class="form-actions">'
             + kit.button("Byg Bayes op på ny", kind="danger", icon="graduation-cap", attrs="data-typed-target")
             + kit.button("Tilbage", href="/training", kind="ghost") + "</div></div>")
    return kit.post_form("/training/rebuild", inner, cls="rebuild-start")


@app.get("/training/rebuild")
@ui.admin_required
def training_rebuild_page():
    crumbs = [("Træning", "/training"), ("Byg Bayes op på ny", None)]
    st = _rebuild_status()
    code = str(st.get("code") or "")

    def why(plan: dict | None) -> str:
        return kit.card(f'<p class="rebuild-why">{h(REBUILD_WHY)}</p>' + _rebuild_facts(plan),
                        title="Hvorfor bygge op på ny?",
                        subtitle="Kort fortalt: den gamle Bayes har lært forkert, og det er nemmest at starte forfra.")

    status = ""
    if code and code != "none":
        status = kit.card(rebuild_status_html(st), title="Seneste genopbygning", cls="rebuild-card")
    if code in REBUILD_ACTIVE:
        return _page("Byg Bayes op på ny", status + why(None), active="training", breadcrumbs=crumbs,
                     subtitle="En genopbygning er i gang. Følg den her eller under Træning.")
    ratio = _rebuild_ratio(request.args.get("ratio"))
    plan = _svc("bayes_rebuild_plan", _actor(), ratio=ratio, default=None)
    if not isinstance(plan, dict):
        plan = {"ok": False, "code": "error", "text": "Planen kunne ikke laves lige nu. Prøv igen om lidt."}
    can_start = bool(plan.get("ok")) and not plan.get("running") and int(plan.get("expected_spam") or 0) > 0
    plan_card = kit.card(f'<div class="rebalance-body">{_rebuild_plan_html(plan, ratio)}</div>',
                         title="Planen", subtitle="Planen bygger på mappernes størrelse – intet er ændret, og intet er startet endnu.")
    if can_start:
        start = kit.card(_rebuild_start_form(plan, ratio), title="Start genopbygningen", cls="rebuild-go")
    else:
        start = kit.card('<div class="form-actions">' + kit.button("Tilbage til Træning", href="/training",
                                                                   kind="secondary", icon="arrow-left") + "</div>",
                         title="Kan ikke startes lige nu",
                         subtitle=("Der er ingen spam at lære fra." if plan.get("ok") and not plan.get("running")
                                   else "Se beskeden i planen ovenfor."))
    body = why(plan if plan.get("ok") else None) + status + plan_card + start
    return _page("Byg Bayes op på ny", body, active="training", breadcrumbs=crumbs,
                 subtitle="Se planen, før noget starter.")


def _rebuild_typed_ok() -> bool:
    typed = " ".join((request.form.get("confirm") or "").split()).upper()
    return typed == REBUILD_WORD


@app.post("/training/rebuild")
@ui.admin_required
def training_rebuild_start():
    back = "/training/rebuild"
    if not _rebuild_typed_ok():
        return ui.respond(f"Skriv {REBUILD_WORD} for at bekræfte.", ok=False, next_url=back)
    if locked := _config_locked():
        return ui.respond(locked, ok=False, next_url=back)
    ratio = _rebuild_ratio(request.form.get("ratio"))
    try:
        res = ui.services.bayes_rebuild_start(_actor(), confirm=True, ratio=ratio, save_config=ui.save_config)
    except Exception as ex:  # noqa: BLE001 - never a stack trace in the UI
        log.error("bayes_rebuild_start failed: %s", type(ex).__name__)
        res = {"ok": False, "code": "error", "text": "Genopbygningen kunne ikke startes – den gamle Bayes bruges stadig."}
    if not isinstance(res, dict):
        res = {"ok": False, "code": "error", "text": "Genopbygningen kunne ikke startes."}
    code = str(res.get("code") or "")
    if code == "started" and res.get("ok"):
        # services audited it through save_config ('bayes_rebuild').
        return ui.respond(str(res.get("text") or "Bayes bygges op på ny."), next_url="/training#genopbyg",
                          reload=True, location="/training#genopbyg")
    ui.audit("bayes_rebuild", result="rejected" if code in ("rejected", "running", "nothing", "confirm") else "failed",
             detail=f"code={code or 'error'} ratio={ratio:g}")
    return ui.respond(str(res.get("text") or "Genopbygningen kunne ikke startes."), ok=False, next_url=back,
                      status=409 if code == "running" else 400)


@app.post("/training/rebuild/restore")
@ui.admin_required
def training_rebuild_restore():
    back = "/training#genopbyg"
    if locked := _config_locked():
        return ui.respond(locked, ok=False, next_url=back)
    try:
        res = ui.services.bayes_restore_previous(_actor(), confirm=True, save_config=ui.save_config)
    except Exception as ex:  # noqa: BLE001
        log.error("bayes_restore_previous failed: %s", type(ex).__name__)
        res = {"ok": False, "code": "error", "text": "Den tidligere Bayes kunne ikke gendannes."}
    if not isinstance(res, dict):
        res = {"ok": False, "code": "error", "text": "Den tidligere Bayes kunne ikke gendannes."}
    code = str(res.get("code") or "")
    if code == "restored" and res.get("ok"):
        return ui.respond(str(res.get("text") or "Den tidligere Bayes er gendannet."), next_url=back,
                          reload=True, location=back)
    ui.audit("bayes_restore", result="rejected" if code in ("nothing", "changed", "rejected", "confirm") else "failed",
             detail=f"code={code or 'error'}")
    return ui.respond(str(res.get("text") or "Den tidligere Bayes kunne ikke gendannes."), ok=False, next_url=back)


# ---- job detail + calibration view ----------------------------------------------------


def _job_by_id(job_id: int) -> dict | None:
    row = ui.query("SELECT * FROM train_jobs WHERE id=?", [job_id], one=True)
    if row is None:
        return None
    d = {k: row[k] for k in row.keys()}
    d["percent"] = _job_percent(d)
    return d


def _role(acc: Any, folder: str) -> str:
    inbox = str(_attr(acc, "inbox", "INBOX") if acc is not None else "INBOX")
    return "inbox" if folder.lower() == inbox.lower() else "junk"


def _companion(job: dict, acc: Any) -> dict | None:
    """Latest finished calibration of the same account in the other role
    (INBOX vs a spam folder) for the side-by-side what-if."""
    role = _role(acc, job["folder"])
    rows = ui.query("SELECT * FROM train_jobs WHERE kind='calibrate' AND account=? AND id != ? "
                    "AND status IN ('done','cancelled') ORDER BY id DESC LIMIT 20", [job["account"], job["id"]])
    for r in rows:
        if _role(acc, r["folder"]) != role:
            return {k: r[k] for k in r.keys()}
    return None


def _junk_role_label(job: dict) -> str:
    """'Spamfilter-mappen' for the filter's own folder, otherwise the
    provider's spam folder (calibration runs on either)."""
    acc = ui.account_by_name(str(job.get("account") or ""))
    own = str(_attr(acc, "junk", "") or "") if acc is not None else ""
    return "Spamfilter-mappen" if own and job["folder"].lower() == own.lower() else "Udbyderens spam-mappe"


def _histogram(jobs: list[tuple[dict, dict]], thr: float) -> str:
    """Score histogram (1-point bins) for one or two calibration jobs."""
    bins: dict[int, list[int]] = {}
    for idx, (_job, summ) in enumerate(jobs):
        for b in summ.get("histogram") or []:
            lo = max(-10, min(30, int(b.get("lo", 0))))
            bins.setdefault(lo, [0] * len(jobs))[idx] += int(b.get("n") or 0)
    if not bins:
        return kit.empty_state("Ingen scorer endnu", "Histogrammet vises, når kalibreringen har scoret beskeder.", "bar-chart")
    lo, hi = min(min(bins), int(thr) - 2), max(max(bins), int(thr) + 2)
    keys = list(range(lo, hi + 1))
    labels = [(kit.fmt_int(k) if k >= 0 else f"−{abs(k)}") if (len(keys) <= 22 or k % 2 == 0) else "" for k in keys]
    if len(jobs) == 2:
        series = []
        for idx, (job, _s) in enumerate(jobs):
            role = "Indbakke" if job.get("_role") == "inbox" else _junk_role_label(job)
            series.append({"label": f"{role} ({job['folder']})", "values": [bins.get(k, [0, 0])[idx] for k in keys],
                           "tone": "brand" if job.get("_role") == "inbox" else "bad"})
        tips = [f"Score {k} til {k + 1}: " + ", ".join(f"{s['label']} {kit.fmt_int(s['values'][i])}" for s in series)
                for i, k in enumerate(keys)]
    else:
        vals = [bins.get(k, [0])[0] for k in keys]
        series = [{"label": "Under grænsen", "values": [v if k + 1 <= thr else 0 for k, v in zip(keys, vals)], "tone": "neutral"},
                  {"label": "Over grænsen", "values": [v if k + 1 > thr else 0 for k, v in zip(keys, vals)], "tone": "bad"}]
        tips = [f"Score {k} til {k + 1}: {kit.fmt_int(v)}" for k, v in zip(keys, vals)]
    return kit.bar_chart(series, labels, tips=tips)


def _whatif(jobs: list[tuple[dict, dict]], thr: float) -> str:
    """Threshold slider: how many would be caught in INBOX vs junk."""
    data = []
    for job, summ in jobs:
        caught = {_thr_key(c["threshold"]): int(c["n"]) for c in summ.get("caught_at") or []}
        data.append({"role": job.get("_role"), "folder": job["folder"], "count": int(summ.get("count") or 0),
                     "caught": caught, "label": "" if job.get("_role") == "inbox" else _junk_role_label(job)})
    t = min(THR_MAX, max(THR_MIN, thr))
    out_id = "whatif-val"
    lines = []
    for d in data:
        c = d["caught"].get(_thr_key(t), 0)
        if d["role"] == "inbox":
            label = f"Indbakken ({d['folder']})"
            hint = "bør være lavt – det er post, der ville blive fanget fejlagtigt, hvis indbakken er ren."
            tone = "warn"
        else:
            label = f"{d['label']} ({d['folder']})"
            hint = "bør være højt – det er spam, filteret ville fange."
            tone = "ok"
        lines.append(
            f'<div class="whatif-row tone-{tone}" data-whatif-row="{h(json.dumps(d, separators=(",", ":")))}">'
            f'<div class="whatif-top"><b>{h(label)}</b><span class="num" data-wi="count">'
            f'{kit.fmt_int(c)} af {kit.fmt_int(d["count"])} ({kit.fmt_pct(c, d["count"])})</span></div>'
            f'{kit.progress(c, max(1, d["count"]), tone=tone)}<span class="faint small">{h(hint)}</span></div>')
    return (f'<div class="thr-head"><span class="thr-value" id="{out_id}">{h(kit.fmt_score(t))}</span>'
            f'<span class="thr-label" data-thr-label>{h(kit.sensitivity_label(t))}</span></div>'
            f'<input class="range" type="range" min="{THR_MIN}" max="{THR_MAX}" step="{THR_STEP}" value="{t:.1f}" '
            f'data-range-output="{out_id}" data-whatif aria-label="Grænse at afprøve">'
            '<div class="thr-scale" aria-hidden="true"><span>Streng</span><span>Normal</span><span>Lempelig</span></div>'
            f'<div class="whatif">{"".join(lines)}</div>')


@app.get("/training/jobs/<int:job_id>")
@ui.admin_required
def training_job_page(job_id: int):
    job = _job_by_id(job_id)
    if job is None:
        abort(404)
    acc = ui.account_by_name(job["account"])
    st_label, st_tone = JOB_STATUS.get(job["status"], (job["status"], "neutral"))
    k_label, k_tone = JOB_KIND.get(job["kind"], (job["kind"], "neutral"))
    info = kit.kv_list([
        ("Konto", h(job["account"])), ("Mappe", f'<span class="mono">{h(job["folder"])}</span>'),
        ("Type", kit.badge(k_label, k_tone)), ("Status", kit.badge(st_label, st_tone)),
        ("Fremskridt", kit.progress(job["percent"], 100, label=f"{kit.fmt_int(job.get('processed') or 0)} behandlet")),
        ("Oprettet", h(f"{kit.fmt_ts(job.get('created_at'))} af {job.get('created_by') or '–'}")),
        ("Startet", h(kit.fmt_ts(job.get("started_at")))), ("Færdig", h(kit.fmt_ts(job.get("finished_at")))),
        ("Indstillinger", h(f"maks. {job.get('max_messages')} · ældre end {job.get('min_age_days') or 0} dage"
                            f"{' · kun læste' if job.get('seen_only') else ''}"
                            f"{' · ' + dict(PROVIDER_FILTERS).get(job.get('provider_filter') or 'any', '') if (job.get('provider_filter') or 'any') != 'any' else ''}")),
    ] + ([("Fejl", f'<span class="tone-bad">{h(job["error"])}</span>')] if job.get("error") else []))
    crumbs = [("Træning", "/training"), (f"Job #{job_id}", None)]
    if job["kind"] != "calibrate":
        body = kit.card(info, title=f"{k_label} fra {job['folder']}")
        return _page(f"Job #{job_id}", body, active="training", breadcrumbs=crumbs)

    thr = _thr(acc) if acc is not None else 8.0
    job["_role"] = _role(acc, job["folder"])
    pairs = [(job, _svc("calibration_summary", job_id, THR_STEPS, default={}) or {})]
    comp = _companion(job, acc)
    if comp:
        comp["_role"] = _role(acc, comp["folder"])
        pairs.append((comp, _svc("calibration_summary", int(comp["id"]), THR_STEPS, default={}) or {}))
        pairs.sort(key=lambda p: 0 if p[0]["_role"] == "inbox" else 1)
    summ = pairs[0][1] if pairs[0][0] is job else pairs[1][1]
    count = int(summ.get("count") or 0)
    kpis = ('<div class="kpis">'
            + kit.kpi("Scoret", count, sub=f"i {job['folder']}")
            + kit.kpi("Median", kit.fmt_score(summ.get("median")) if count else "–", sub="halvdelen ligger under")
            + kit.kpi("Laveste", kit.fmt_score(summ.get("min")) if count else "–")
            + kit.kpi("Højeste", kit.fmt_score(summ.get("max")) if count else "–", tone="bad" if count else "")
            + "</div>")
    comp_note = ""
    if comp:
        comp_note = (f'<p class="faint small">Sammenlignet med job #{comp["id"]} ({h(comp["folder"])}) fra '
                     f'{h(kit.fmt_ts(comp.get("finished_at") or comp.get("created_at")))}.</p>')
    else:
        comp_note = ('<p class="faint small">Kalibrér også ' + ("en spam-mappe" if job["_role"] == "inbox" else "indbakken")
                     + " på samme konto for at sammenligne.</p>")
    results = _calibration_table(job_id, thr)
    body = (
        kit.card(kpis, title=f"Kalibrering af {job['folder']} på {job['account']}",
                 subtitle=f"Nuværende grænse for kontoen: {kit.fmt_score(thr)} ({kit.sensitivity_label(thr).lower()})",
                 actions=kit.badge(st_label, st_tone))
        + '<div class="grid grid-main">'
        + kit.card(_histogram(pairs, thr) + comp_note, title="Fordeling af scorer", subtitle="Antal beskeder pr. scorepoint")
        + kit.card(_whatif(pairs, thr), title="Hvad hvis grænsen var…", subtitle="Træk for at se, hvor mange der ville blive fanget.")
        + "</div>"
        + _trust_split_card(summ)
        + results
        + '<details class="disclosure mt-2"><summary>' + kit.icon("chevron-right") + "Jobdetaljer</summary>"
        + f'<div class="disclosure-body">{kit.card(info)}</div></details>')
    return _page(f"Kalibrering #{job_id}", body, active="training", breadcrumbs=crumbs)


def _trust_split_card(summ: dict) -> str:
    """2.3 (B14): the scores with / without a known-contact bonus."""
    tr = summ.get("trust") or {}
    n_with, n_without = int(tr.get("with_count") or 0), int(tr.get("without_count") or 0)
    if not n_with:
        return ""

    def part(label: str, n: int, st: dict) -> str:
        med = kit.fmt_score(st.get("median")) if n else "–"
        return kit.kpi(label, n, sub=f"median {med}" if n else "ingen")

    return kit.card('<div class="kpis kpis-2">' + part("Med kendte kontakter", n_with, tr.get("with") or {})
                    + part("Uden", n_without, tr.get("without") or {}) + "</div>"
                    + f'<p class="faint small mt-1">{h(str(tr.get("note") or ""))}</p>',
                    title="Kendte kontakter", subtitle="Mails med bonus som kendt kontakt, svar eller fast afsender.")


def _calibration_table(job_id: int, thr: float) -> str:
    rows = _svc("calibration_results", job_id, default=[]) or []
    sort = request.args.get("sort", "score")
    if sort == "low":
        rows = sorted(rows, key=lambda r: float(r.get("final_score") or 0))
    elif sort == "date":
        rows = sorted(rows, key=lambda r: int(r.get("received_at") or 0), reverse=True)
    else:
        sort = "score"
        rows = sorted(rows, key=lambda r: float(r.get("final_score") or 0), reverse=True)
    total = len(rows)
    pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = _int_arg("page", 1, 1, pages)
    chunk = rows[(page - 1) * PAGE_SIZE: page * PAGE_SIZE]
    trs = []
    for r in chunk:
        name, addr = kit.sender_parts(r.get("sender"))
        reasons = "".join(kit.chip(kit.explain_symbol_detail(s, symbols=r.get("symbols"), sender=r.get("sender"),
                                                        ai_reason=True), "bad")
                          for s in kit.top_reasons(r.get("symbols"), 2))
        prov = kit.chip("Udbyder: spam", "warn") if r.get("provider_flag") else ""
        seen = kit.chip("Ulæst", "info") if r.get("seen") == 0 else ""
        trs.append([
            kit.score_badge(r.get("final_score"), thr),
            f'<div class="cal-mail"><b class="truncate">{h(r.get("subject") or "(intet emne)")}</b>'
            f'<span class="faint small truncate">{h(name or addr or "Ukendt afsender")}'
            f'{" · " + h(addr) if name and addr else ""}</span></div>',
            f'<div class="row-tight cal-chips">{reasons}{prov}{seen}</div>',
            f'<span class="faint nowrap">{h(kit.fmt_ts(r.get("received_at")))}</span>'])
    sorter = kit.seg_links([("Højeste", "?" + urlencode({"sort": "score"}), sort == "score"),
                            ("Laveste", "?" + urlencode({"sort": "low"}), sort == "low"),
                            ("Nyeste", "?" + urlencode({"sort": "date"}), sort == "date")])
    listing = kit.table([("Score", ""), ("Besked", ""), ("Hvorfor", ""), ("Modtaget", "end")], trs,
                        empty="Ingen resultater endnu.", cls="cal-table")
    pager = kit.pagination(page, pages, lambda p: _qs(page=p))
    return kit.card(f'<div class="card-pad-x">{listing}</div>'
                    + (f'<div class="list-foot"><span>{_n(total, "besked", "beskeder")}</span>{pager}</div>' if total else ""),
                    title="Beskeder", subtitle="Ingen af beskederne er flyttet eller lært.", actions=sorter, cls="flush")


# ---------------------------------------------------------------------------
# Drift
# ---------------------------------------------------------------------------

CONTAINER_LABELS = {"spamfilter": "Filter + WebUI", "spamfilter-rspamd": "rspamd", "spamfilter-redis": "Redis",
                    "spamfilter-unbound": "Unbound (DNS)"}


def _age_text(age: Any) -> str:
    try:
        a = int(age)
    except (TypeError, ValueError):
        return "ukendt"
    if a < 60:
        return f"{a} sek."
    if a < 3600:
        return f"{a // 60} min."
    if a < 86400 * 2:
        return f"{a // 3600} t."
    return f"{a // 86400} dage"


def _bytes(n: Any) -> str:
    try:
        v = float(n)
    except (TypeError, ValueError):
        return "–"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024 or unit == "TB":
            return f"{kit.fmt_num(v, 0 if unit in ('B', 'KB') else 1)} {unit}"
        v /= 1024
    return "–"


def _iso_ts(value: Any) -> int | None:
    """Docker's RFC 3339 StartedAt (nanoseconds, Z) -> unix seconds."""
    from datetime import datetime, timedelta

    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?(Z|[+-]\d\d:\d\d)?", str(value or ""))
    if not m:
        return None
    try:
        dt = datetime.fromisoformat(m.group(1) + ("+00:00" if m.group(2) in (None, "Z") else m.group(2)))
    except ValueError:
        return None
    return int(dt.timestamp()) if dt.year > 1970 else None


def heartbeat_age() -> int | None:
    """Seconds since the engine main loop last wrote /state/heartbeat."""
    try:
        raw = (Path(ui.STATE_DIR) / "heartbeat").read_text().split()
        return max(0, int(time.time() - float(raw[0])))
    except (OSError, ValueError, IndexError):
        return None


def _containers_card(hs: dict) -> str:
    cs = hs.get("containers") if isinstance(hs.get("containers"), dict) else {}
    if not cs:
        return kit.card(kit.empty_state("Ingen containerdata", "Værtsstatus mangler – se advarslen øverst.", "server"),
                        title="Containere")
    rows = []
    for name, c in cs.items():
        c = c if isinstance(c, dict) else {}
        running = bool(c.get("running"))
        health = c.get("health")
        if not c.get("exists", True) or c.get("status") == "missing":
            state, tone = "Mangler", "bad"
        elif not running:
            state, tone = "Stoppet", "bad"
        elif health == "unhealthy":
            state, tone = "Usund", "bad"
        elif health == "starting":
            state, tone = "Starter", "warn"
        else:
            state, tone = ("Sund" if health == "healthy" else "Kører"), "ok"
        restarts = int(c.get("restart_count") or 0)
        started = _iso_ts(c.get("started_at"))
        image = str(c.get("image") or "")
        rows.append([
            f'<div class="job-what"><b>{h(CONTAINER_LABELS.get(name, name))}</b>'
            f'<span class="mono small faint truncate" title="{h(image)}">{h(image.rsplit("/", 1)[-1][:48] or name)}</span></div>',
            f'<span class="row-tight nowrap">{kit.status_dot(tone)}{h(state)}</span>',
            f'<span class="num{" tone-warn" if restarts else ""}">{kit.fmt_int(restarts)}</span>',
            f'<span class="faint small nowrap">{h(kit.ago(started) if started else "–")}</span>'])
    return kit.card(kit.table([("Container", ""), ("Tilstand", ""), ("Genstarter", "num"), ("Startet", "end")],
                              rows, cls="containers-table"), title="Containere", subtitle="Fra værtsmonitoren (hvert 5. min.).")


def _disk_card(hs: dict) -> str:
    disk = hs.get("disk") if isinstance(hs.get("disk"), dict) else {}
    bars = []
    for key, label in (("docker_img", "docker.img"), ("appdata", "appdata")):
        d = disk.get(key) if isinstance(disk.get(key), dict) else None
        if not d or d.get("pct") is None:
            continue
        pct = int(d.get("pct") or 0)
        tone = "bad" if pct >= 90 else "warn" if pct >= 80 else "ok"
        bars.append(f'<div class="disk-row"><div class="progress-label"><span>{h(label)}</span>'
                    f'<span class="num">{pct} % · {h(_bytes(d.get("avail")))} fri</span></div>'
                    f'{kit.progress(pct, 100, tone=tone)}</div>')
        if key == "appdata" and d.get("spamfilter_bytes"):
            bars.append(f'<p class="faint small">Spamfilter fylder {h(_bytes(d["spamfilter_bytes"]))}.</p>')
    body = "".join(bars) or '<p class="muted">Ingen diskdata.</p>'
    return kit.card(f'<div class="stack stack-tight">{body}</div>', title="Diskplads")


def _backup_card(hs: dict) -> str:
    b = _svc("backup_status", default=None) or {}
    if not b.get("available") and isinstance(hs.get("backup"), dict):
        b = hs["backup"]
    if not b.get("available"):
        return kit.card(kit.empty_state("Ingen backup-status", "backup-and-verify.sh har ikke skrevet backup-status.json endnu.",
                                        "database"), title="Backup")
    age = b.get("age_s")
    ok = bool(b.get("ok"))
    old = age is not None and int(age) > 26 * 3600
    tone = "bad" if not ok else "warn" if old else "ok"
    title = "Seneste backup lykkedes" if ok else "Seneste backup fejlede"
    pairs = [("Status", f'{kit.status_dot(tone)} {h(title)}'),
             ("Tidspunkt", h(f"{kit.fmt_ts(b.get('ts'))} ({_age_text(age)} siden)" if b.get("ts") else "–")),
             ("Størrelse", h(_bytes(b.get("size")))),
             ("Arkiv", f'<span class="mono small">{h(Path(str(b.get("archive") or "–")).name)}</span>')]
    if b.get("error"):
        pairs.append(("Fejl", f'<span class="tone-bad">{h(str(b["error"])[:200])}</span>'))
    extra = kit.alert("Backuppen er over 26 timer gammel. Tjek User Scripts → Spamfilter-backup.", "warn") if old else ""
    return kit.card(kit.kv_list(pairs) + extra, title="Backup", subtitle="Kører hver nat kl. 03:00.")


def _work_health_card() -> str:
    """Cached antivirus facts and queue metadata; never run network probes."""
    import opsview
    import ai_verdict
    import aio_health

    now = time.time()
    facts = opsview.antivirus(aio_health.read_status(), now=now)
    state = facts['state']
    text, tone = {
        'unknown': ('Ukendt – ingen frisk måling', 'warn'),
        'ok': ('Virker', 'ok'), 'waiting': ('Venter på virusdefinitioner', 'warn'),
        'down': ('Svarer ikke – mail scannes uden virustjek', 'bad'),
        'stale': ('Virusdefinitionerne er for gamle', 'bad'),
        'off': ('Slået fra i opsætningen' if facts.get('intentionally_off') else 'Slået fra ved en fejl',
                'neutral' if facts.get('intentionally_off') else 'bad'),
    }[state]
    pairs = [('Antivirus', kit.badge(text, tone))]
    pairs.append(('Virusdefinitionernes alder', h(_age_text(facts['signatures_age_s']))
                  if facts.get('signatures_age_s') is not None else 'Ukendt'))
    if facts.get('observed_age_s') is not None:
        pairs.append(('Antivirus målt', h(_age_text(facts['observed_age_s'])) + ' siden'))
    queues = opsview.queues(ui.db(), [a.name for a in ui.effective_accounts()], now=now)
    for kind, label in (('moves', 'Planlagte flytninger'), ('training', 'Træningsjob'), ('undo', 'Fortrydelsesjob')):
        row = queues[kind]
        if not row['available']:
            value = 'Ukendt'
        elif not row['count']:
            value = 'Ingen ventende'
        else:
            value = f"{row['count']} ventende · ældste " + (
                _age_text(row['oldest_age_s']) if row['oldest_age_s'] is not None else 'ukendt alder')
        pairs.append((label, h(value)))
    ai = ai_verdict.queue_status(now=now)
    age = _age_text(ai['oldest_age_s']) if ai['oldest_age_s'] is not None else 'ukendt alder'
    pairs.append(('AI-kø', h(f"{ai['count']} ventende · ældste {age}" if ai['count'] else 'Ingen ventende')))
    links = (kit.button('Postkasser', href='/accounts', kind='ghost', size='sm')
             + kit.button('AI-status', href='/ai', kind='ghost', size='sm')
             + kit.button('Træning', href='/training', kind='ghost', size='sm'))
    return kit.card(kit.kv_list(pairs)
                    + '<p class="faint small">Ventetid kan være planlagt eller skyldes en pause. '
                      'Køtal er ikke fejlmeldinger. AI-køen viser kun job, der endnu ikke behandles.</p>'
                    + '<div class="form-actions">' + links + '</div>',
                    title='Antivirus og ventende arbejde', subtitle='Seneste måling og aktuelt øjebliksbillede.')


def _crypt_backup_card() -> str:
    """2.6 (B3): the nightly encrypted backup + off-site copy (ui_backup.py)."""
    try:
        import ui_backup  # noqa: PLC0415

        return ui_backup.card()
    except Exception as ex:  # noqa: BLE001 - the Drift page must render
        log.warning("encrypted backup card failed: %s", type(ex).__name__)
        return ""


def _dns_card(hs: dict) -> str:
    dns = hs.get("dns") if isinstance(hs.get("dns"), dict) else {}
    rbl = hs.get("rbl") if isinstance(hs.get("rbl"), dict) else {}
    if not dns and not rbl:
        return kit.card('<p class="muted">Ingen DNS-data fra værtsmonitoren.</p>', title="DNS og blokeringslister")
    verdict = str(dns.get("verdict") or "unavailable")
    vtxt = {"ok": ("Spamhaus-testen svarer korrekt", "ok"),
            "blocked": ("Spamhaus afviser forespørgsler (offentlig resolver)", "bad"),
            "timeout": ("DNS-opslag giver timeout", "bad"), "servfail": ("DNS svarer SERVFAIL", "bad"),
            "unavailable": ("DNS-test ikke tilgængelig", "warn")}.get(verdict, (f"DNS: {verdict}", "warn"))
    fail_rate = rbl.get("fail_rate")
    scans = int(rbl.get("scans") or 0)
    rate_txt = f"{kit.fmt_pct(rbl.get('scans_with_dns_fail') or 0, scans)} af {kit.fmt_int(scans)} scanninger" if scans else "ingen scanninger"
    rate_tone = "bad" if (fail_rate or 0) >= .5 and scans >= 5 else "warn" if (fail_rate or 0) >= .1 else "ok"
    pairs = [("Spamhaus-test", f'{kit.status_dot(vtxt[1])} {h(vtxt[0])}'
                               + (f'<span class="kv-sub">{h(dns.get("ms"))} ms via Unbound</span>' if dns.get("ms") is not None else "")),
             ("RBL-fejl (15 min.)", f'{kit.status_dot(rate_tone)} {h(rate_txt)}'),
             ("SERVFAIL i Unbound", h(kit.fmt_int(rbl.get("unbound_servfail") or 0))),
             ("DNS-loft ramt", h(kit.fmt_int(rbl.get("dns_limit_hits") or 0)))]
    return kit.card(kit.kv_list(pairs), title="DNS og blokeringslister", subtitle="RBL-opslag kræver en sund lokal resolver.")


@app.get("/system/rspamd")
@ui.admin_required
def system_rspamd_fragment():
    hl = _svc("rspamd_health", default={}) or {}
    b = _bayes()
    tone = "ok" if hl.get("ok") else "bad"

    def ms(v: Any) -> str:
        return f"{v} ms" if v is not None else "svarer ikke"

    pairs = [("Status", f'{kit.status_dot(tone)} {h(hl.get("text") or ("rspamd svarer normalt." if hl.get("ok") else "rspamd svarer ikke."))}'),
             ("Scanner", h(ms(hl.get("scanner_ms")))), ("Controller", h(ms(hl.get("controller_ms"))))]
    if b.get("ok"):
        need = int(b.get("min_learns") or 200)
        pairs.append(("Bayes", h(f"{kit.fmt_int(b.get('spam_learned') or 0)} spam · {kit.fmt_int(b.get('ham_learned') or 0)} legitim "
                                 f"(kræver {kit.fmt_int(need)} af hver)")))
    else:
        pairs.append(("Bayes", '<span class="faint">ukendt</span>'))
    return kit.kv_list(pairs)


def _events_tab() -> str:
    account = (request.args.get("account") or "").strip()[:64]
    event = (request.args.get("event") or "").strip()[:64]
    q = (request.args.get("q") or "").strip()[:200]
    where, params = " WHERE 1=1", []
    if account:
        where += " AND account=?"
        params.append(account)
    if event:
        where += " AND event=?"
        params.append(event)
    if q:
        where += " AND (detail LIKE ? ESCAPE '\\' OR message_id LIKE ? ESCAPE '\\')"
        params += [_like(q)] * 2
    row = ui.query(f"SELECT COUNT(*) FROM events{where}", params, one=True)
    total = int(row[0]) if row else 0
    pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = _int_arg("page", 1, 1, pages)
    rows = ui.query(f"SELECT * FROM events{where} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",
                    [*params, PAGE_SIZE, (page - 1) * PAGE_SIZE])
    kinds = [r[0] for r in ui.query("SELECT DISTINCT event FROM events ORDER BY event LIMIT 200")]
    accs = sorted({a.name for a in ui.effective_accounts()} | {r[0] for r in ui.query("SELECT DISTINCT account FROM events LIMIT 100")})
    from ui_mail import _human_detail  # shared with the message timeline

    trs = []
    for r in rows:
        label, tone = EVENT_LABELS.get(r["event"], (r["event"], "neutral"))
        mid = r["message_id"] or ""
        acct = r["account"] or ""
        msg_link = ""
        if mid and acct and acct != "*":
            msg_link = (f'<a class="card-link small" href="/messages/{h(_q(acct))}/{kit.token_for(mid)}">'
                        f'Besked {kit.icon("arrow-right")}</a>')
        trs.append([f'<span class="faint nowrap num" title="{h(kit.iso_ts(r["ts"]))}">{h(kit.fmt_ts(r["ts"]))}</span>',
                    kit.badge(label, tone),
                    h("System" if acct == "*" else acct),
                    f'<span class="log-detail" title="{h(r["detail"] or "")}">'
                    f'{h(_human_detail(str(r["detail"] or "")))}</span>{msg_link}'])
    fields = (
        f'<div class="input-icon">{kit.icon("search")}'
        + kit.input_("q", q, type="search", attrs='placeholder="Søg i detaljer eller Message-ID" aria-label="Søg" data-search-shortcut')
        + "</div>"
        + kit.select("account", [("", "Alle konti"), ("*", "System")] + [(a, a) for a in accs if a != "*"], account,
                     attrs='aria-label="Konto"')
        + kit.select("event", [("", "Alle hændelser")] + [(k, EVENT_LABELS.get(k, (k, ""))[0]) for k in kinds], event,
                     attrs='aria-label="Hændelse"'))
    filters = (f'<form method="get" class="filters" data-autosubmit role="search">{kit.hidden("tab", "events")}{fields}'
               f'<button class="btn btn-secondary filters-submit" type="submit">Filtrér</button></form>')
    listing = kit.table([("Tid", ""), ("Hændelse", ""), ("Konto", ""), ("Detaljer", "")], trs,
                        empty="Ingen hændelser matcher." if (q or event or account) else "Ingen hændelser endnu.",
                        cls="log-table")
    pager = kit.pagination(page, pages, lambda p: "/system" + _qs(page=p))
    foot = f'<div class="list-foot"><span>{_n(total, "hændelse", "hændelser")} · gemmes i 30 dage</span>{pager}</div>'
    return f'<div class="card-pad">{filters}</div><div class="card-pad-x">{listing}</div>{foot}'


def read_audit(*, max_bytes: int = AUDIT_READ_MAX) -> list[dict]:
    """Audit records, newest first (reads at most the last max_bytes)."""
    path = Path(ui.AUDIT_FILE)
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            if size > max_bytes:
                fh.seek(size - max_bytes)
                fh.readline()  # drop the partial first line
            data = fh.read().decode("utf-8", "replace")
    except OSError:
        return []
    out = []
    for line in data.splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    out.reverse()
    return out


def _audit_tab() -> str:
    actor = (request.args.get("actor") or "").strip()[:64]
    action = (request.args.get("action") or "").strip()[:64]
    q = (request.args.get("q") or "").strip()[:200].lower()
    recs = read_audit()
    actors = sorted({str(r.get("actor") or "") for r in recs if r.get("actor")})
    actions = sorted({str(r.get("action") or "") for r in recs if r.get("action")})
    if actor:
        recs = [r for r in recs if r.get("actor") == actor]
    if action:
        recs = [r for r in recs if r.get("action") == action]
    if q:
        recs = [r for r in recs if q in " ".join(str(r.get(k) or "") for k in
                                                  ("account", "detail", "message_id", "ip", "cf_user", "proxy")).lower()]
    total = len(recs)
    pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = _int_arg("page", 1, 1, pages)
    trs = []
    for r in recs[(page - 1) * PAGE_SIZE: page * PAGE_SIZE]:
        res = str(r.get("result") or "")
        tone = "ok" if res == "ok" else "bad" if res in ("failed", "rejected", "error") else "neutral"
        label = AUDIT_LABELS.get(str(r.get("action")), str(r.get("action") or ""))
        detail = " · ".join(str(x) for x in (r.get("account"), _audit_detail(r), r.get("message_id")) if x)
        trs.append([f'<span class="faint nowrap num" title="{h(kit.iso_ts(r.get("ts")))}">{h(kit.fmt_ts(r.get("ts")))}</span>',
                    f'<span class="row-tight">{kit.avatar(str(r.get("actor") or "?"))}<span>{h(r.get("actor") or "–")}</span></span>',
                    f'<b>{h(label)}</b>' + (f' {kit.badge(AUDIT_RESULTS.get(res, res), tone)}'
                                            if res and res != "ok" else ""),
                    f'<span class="log-detail">{h(detail)}</span>',
                    _audit_origin(r)])
    fields = (
        f'<div class="input-icon">{kit.icon("search")}'
        + kit.input_("q", request.args.get("q", "")[:200], type="search", attrs='placeholder="Søg i konto, detaljer, IP" aria-label="Søg"')
        + "</div>"
        + kit.select("actor", [("", "Alle brugere")] + [(a, a) for a in actors], actor, attrs='aria-label="Bruger"')
        + kit.select("action", [("", "Alle handlinger")] + [(a, AUDIT_LABELS.get(a, a)) for a in actions], action,
                     attrs='aria-label="Handling"'))
    filters = (f'<form method="get" class="filters" data-autosubmit role="search">{kit.hidden("tab", "audit")}{fields}'
               f'<button class="btn btn-secondary filters-submit" type="submit">Filtrér</button></form>')
    listing = kit.table([("Tid", ""), ("Bruger", ""), ("Handling", ""), ("Detaljer", ""), ("IP", "end")], trs,
                        empty="Ingen poster matcher." if (q or actor or action) else "Ændringsloggen er tom.", cls="log-table")
    pager = kit.pagination(page, pages, lambda p: "/system" + _qs(page=p))
    foot = f'<div class="list-foot"><span>{_n(total, "post", "poster")} · alle admin-handlinger logges</span>{pager}</div>'
    return f'<div class="card-pad">{filters}</div><div class="card-pad-x">{listing}</div>{foot}'


AUDIT_RESULTS = {"failed": "fejlede", "rejected": "afvist", "detected": "registreret",
                 "error": "fejl", "denied": "afvist", "locked": "spærret", "pending": "venter på kode"}


def _audit_origin(r: dict) -> str:
    """IP column: client IP, plus 'via <proxy>' and the Cloudflare Access
    identity when the request came through a trusted proxy."""
    out = f'<span class="mono small faint">{h(r.get("ip") or "")}</span>'
    if r.get("proxy"):
        out += f'<span class="kv-sub">via {h(r.get("proxy"))}</span>'
    if r.get("via") == "kontrolrum":
        out += '<span class="kv-sub" title="Logget ind som personen via Kontrolrum-SSO">via Kontrolrum</span>'
    if r.get("cf_user"):
        out += f'<span class="kv-sub" title="Cloudflare Access">{kit.icon("cloud", "inline-icon")}{h(r.get("cf_user"))}</span>'
    return out


def _audit_detail(r: dict) -> str:
    """Audit details are short technical strings ('flag->move', '8.0->7.5'):
    show mode names and decimal commas like the rest of the UI."""
    d = str(r.get("detail") or "")
    old, arrow, new = d.partition("->")
    if arrow and r.get("action") == "account_mode":
        return f"{kit.mode_label(old.strip())} → {kit.mode_label(new.strip())}"
    if arrow and r.get("action") == "account_threshold":
        try:
            return f"{kit.fmt_score(float(old))} → {kit.fmt_score(float(new))}"
        except ValueError:
            pass
    return d.replace("->", " → ") if arrow else d


def _scan_coverage_card():
    from datetime import datetime, timedelta
    import quality
    since = (datetime.now(kit.TZ) - timedelta(days=13)).strftime("%Y-%m-%d")
    accounts = [a.name for a in ui.visible_accounts()]
    items = quality.coverage(ui.db(), accounts, since)
    rows = ""
    for item in items:
        cells = [h(ui.account_label(item["account"]))]
        cells += [h(str(item["counts"][m]) if item['has_observations'] else 'Intet datagrundlag')
                  for m in quality.METRICS]
        rows += "<tr>" + "".join("<td>" + str(c) + "</td>" for c in cells) + "</tr>"
    heads = ["Postkasse", *quality.METRICS.values()]
    table = ('<div class="table-wrap"><table><thead><tr>' +
             "".join("<th>" + str(h(x)) + "</th>" for x in heads) +
             "</tr></thead><tbody>" + rows + "</tbody></table></div>")
    return kit.card(table if rows else '<p class="muted">Intet datagrundlag endnu.</p>',
                    title="Scanningens dækning – 14 dage",
                    subtitle="Hændelser pr. postkasse. Fejlede forsøg kan senere lykkes; tallene er ikke en procent af al modtaget post.")


@app.get("/system")
@ui.admin_required
def system_page():
    hs = _svc("host_status", default=None) or {"available": False}
    hb = heartbeat_age()
    alerts = []
    if not hs.get("available"):
        alerts.append(kit.alert("host-status.json findes ikke. Værtsmonitoren (User Script “Spamfilter-monitor”) "
                                "kører måske ikke – containere, disk og DNS kan derfor ikke vises.", "warn",
                                title="Ingen værtsstatus"))
    elif hs.get("stale"):
        alerts.append(kit.alert(f"Værtsstatus er {_age_text(hs.get('age_s'))} gammel. Tjek, at User Script "
                                "“Spamfilter-monitor” kører hvert 5. minut.", "warn", title="Forældet værtsstatus"))
    for a in hs.get("alerts") or []:
        if isinstance(a, dict) and a.get("text"):
            tone = "bad" if a.get("level") == "alert" else "warn"
            alerts.append(kit.alert(f"{a['text']} (har varet {_age_text(a.get('age_s'))})", tone))
    hb_tone = "ok" if hb is not None and hb < 90 else "warn" if hb is not None and hb < 300 else "bad"
    rs = hs.get("rspamd") if isinstance(hs.get("rspamd"), dict) else {}
    dns = hs.get("dns") if isinstance(hs.get("dns"), dict) else {}
    b = _svc("backup_status", default=None) or (hs.get("backup") if isinstance(hs.get("backup"), dict) else {}) or {}
    kpis = ('<div class="kpis">'
            + kit.kpi("Livstegn", f"{_age_text(hb)}" if hb is not None else "mangler",
                      sub="siden filteret sidst meldte sig", tone=hb_tone if hb_tone != "ok" else "")
            + kit.kpi("rspamd", (f"{rs.get('ms')} ms" if rs.get("ok") else "nede") if rs else "–",
                      sub="svartid fra værten", tone="" if rs.get("ok") or not rs else "bad")
            + kit.kpi("DNS", {"ok": "OK"}.get(str(dns.get("verdict")), str(dns.get("verdict") or "–")),
                      sub="Spamhaus-test via Unbound", tone="" if dns.get("ok") or not dns else "bad")
            + kit.kpi("Backup", f"{_age_text(b.get('age_s'))}" if b.get("available") and b.get("age_s") is not None else "–",
                      sub="siden seneste backup", tone="bad" if b.get("available") and not b.get("ok") else "")
            + "</div>")
    restart = kit.post_form("/system/restart", kit.button(
        "Genstart filter", kind="secondary", icon="refresh",
        attrs=kit.confirm_attrs("Genstart filteret?", "Konfigurationen genindlæses, og alle konti forbinder igen. "
                                "Det tager typisk under et minut. Ingen post går tabt.", confirm="Genstart")))
    tab = request.args.get("tab", "events")
    tab = tab if tab in ("events", "audit") else "events"
    tabs = kit.tabs([("Hændelseslog", "/system?tab=events", tab == "events", None),
                     ("Ændringslog", "/system?tab=audit", tab == "audit", None)])
    log_card = kit.card(f'<div class="card-pad log-tabs">{tabs}</div>' + (_events_tab() if tab == "events" else _audit_tab()),
                        cls="flush", title="")
    version = kit.kv_list([
        ("Filter", h(ui.app_version())), ("Python", h(platform.python_version())),
        ("Vært", h(hs.get("host") or "–")), ("Værtsstatus", h(f"{kit.fmt_ts(hs.get('ts'))} ({_age_text(hs.get('age_s'))} siden)" if hs.get("ts") else "–")),
        ("Konfiguration", f'<span class="mono small">{h(str(ui.CONFIG_PATH))}</span>'),
    ])
    rspamd_card = kit.card('<div data-fragment="/system/rspamd" aria-busy="true">' + kit.skeleton(3) + "</div>",
                           title="rspamd og Bayes", subtitle="Målt live fra filteret.")
    try:
        import ui_backup  # noqa: PLC0415 - 2.6 (B3): 48 h without an encrypted backup

        alerts.append(ui_backup.alert_html())
    except Exception:  # noqa: BLE001
        pass
    body = (
        "".join(alerts)
        + kit.card(kpis)
        + '<div class="grid grid-2">'
        + _containers_card(hs) + rspamd_card
        + _dns_card(hs) + _backup_card(hs)
        + _crypt_backup_card()
        + _disk_card(hs) + _mail_drift_card() + _work_health_card()
        + kit.card(version, title="Version")
        + "</div>"
        + _scan_coverage_card()
        + log_card)
    return _page("Drift", body, active="system", actions_html=restart,
                 subtitle="Containere, rspamd, DNS, backup og logs.")


@app.post("/system/restart")
@ui.admin_required
def system_restart():
    try:
        ok = bool(ui.services.request_reload("Genstart fra Drift", _actor()))
    except Exception as ex:  # noqa: BLE001
        log.error("request_reload failed: %s", type(ex).__name__)
        ok = False
    if not ok:
        ui.request_reload()  # the flag file is what the engine watches
    ui.audit("filter_restart", result="ok")
    return ui.respond("Filteret genstarter.", next_url="/system", reload=True)


# ---------------------------------------------------------------------------
# Brugere (/users) - who may log in, which mailboxes they see, what they may do
# ---------------------------------------------------------------------------

RESERVED_USER_NAMES = {"new"}   # /users/new would clash
PERM_WORDS = {"release": "frigive post", "rules": "tillade og blokere afsendere", "see_messages": "se alle beskeder"}


def _users() -> dict:
    return ui.load_users()


def _user_access(u: Any, meta: dict | None = None) -> tuple[bool, frozenset[str], frozenset[str]]:
    perms = frozenset(ui.PERMISSIONS) if u.admin else (meta or ui.user_meta(u.name))["perms"]
    return u.admin, frozenset(u.accounts), perms


def _role_badge(is_admin: bool) -> str:
    return kit.badge("Administrator", "brand") if is_admin else kit.badge("Bruger", "neutral")


def _acc_users() -> dict[str, str]:
    """account name -> mail address (for labels)."""
    return {a.name: str(_attr(a, "user", "") or "") for a in ui.effective_accounts()}


def _mailbox_chips(is_admin: bool, accounts: Iterable[str], addr: dict[str, str]) -> str:
    if is_admin:
        return kit.chip("Alle postkasser", "brand")
    names = sorted(accounts)
    if not names:
        return kit.chip("Ingen postkasser", "warn")
    out = []
    for n in names:
        a = addr.get(n)
        out.append(f'<span class="mbx"><b>{h(n)}</b><small>{h(a or "kontoen findes ikke længere")}</small></span>')
    return '<span class="mbx-list">' + "".join(out) + "</span>"


def _last_login(meta: dict) -> str:
    ts = meta.get("last_login_at")
    if not ts:
        return '<span class="faint">Aldrig</span>'
    return f'<time datetime="{kit.iso_ts(ts)}" title="{h(kit.fmt_ts(ts))}">{h(kit.ago(ts))}</time>'


def _twofa_html(u: Any, tf: dict | None = None) -> str:
    """To-trins-login status for a user card / the edit page."""
    tf = tf if tf is not None else ui.twofa_status(u.name)
    if tf.get("enabled"):
        out = kit.badge("Slået til", "ok")
        methods = [("App", tf.get("totp")), ("Mail", tf.get("mail"))]
        out += "".join(" " + kit.chip(lbl, "neutral") for lbl, on in methods if on)
        if tf.get("required"):
            out += " " + kit.chip("Påkrævet", "brand")
        left = int(tf.get("recovery_left") or 0)
        if left <= 2:
            out += " " + kit.chip(f"{left} genoprettelseskoder tilbage", "warn")
        return out
    if tf.get("required"):
        return kit.badge("Påkrævet – ikke sat op endnu", "warn")
    return kit.badge("Ikke slået til", "neutral")


def _logout_all_form(u: Any, me: str, *, size: str = "sm", next_url: str = "/users") -> str:
    """'Log ud overalt' for a user. The full form (edit page) has the 'Fjern
    også passkeys' checkbox; the compact one on the user card removes them
    (the default) and says so in the confirm dialog."""
    you = u.name == me
    compact = size == "sm"
    field = "" if compact else ui.logout_all_passkeys_field(u.name, own=you)
    n_pk = ui.passkey_count(u.name) if compact else 0
    return kit.post_form(f"/users/{_q(u.name)}/logout-all", kit.hidden("next", next_url) + field + kit.button(
        "Log ud overalt", kind="secondary", icon="log-out", size=size,
        attrs=kit.confirm_attrs(f"Log {u.name} ud overalt?",
                                "Alle sessioner for brugeren afsluttes – også dem med “Husk mig”"
                                + (", og du skal selv logge ind igen." if you else ".")
                                + (f" Brugerens passkeys ({n_pk}) fjernes også – vil du beholde dem, så brug "
                                   "“Log ud overalt” under Rediger." if n_pk else ""),
                                confirm="Log ud overalt")))


def _remove_form(u: Any, *, size: str = "sm", view: str = "list") -> str:
    return kit.post_form(f"/users/{_q(u.name)}/remove", kit.hidden("view", view) + kit.button(
        "Slet", kind="secondary", icon="trash", size=size, tone="bad",
        attrs=f'aria-label="Slet brugeren {h(u.name)}" ' + kit.confirm_attrs(
            f"Slet brugeren {u.name}?",
            f"Brugeren logges ud overalt og kan ikke længere logge ind. Skriv {u.name} for at bekræfte.",
            confirm="Slet bruger", tone="danger", typed=u.name)))


def _scope_badge(scope: str) -> str:
    """2.3: 'Kun lokalt' on a user card (nothing for 'Overalt')."""
    if scope != "local":
        return ""
    return (f'<span class="badge tone-info scope-badge" title="Må kun logge ind fra hjemmenetværket – aldrig udefra '
            f'via Cloudflare Tunnel">{kit.icon("home")}<span>Kun lokalt</span></span>')


def _scope_html(scope: str) -> str:
    if scope == "local":
        return (_scope_badge(scope) + '<small class="faint scope-sub">Kun fra hjemmenetværket</small>')
    return kit.chip("Overalt", "neutral")


def _user_card(u: Any, me: str, admins: int, meta: dict, addr: dict[str, str], tf: dict | None = None,
               scope: str = "everywhere") -> str:
    you = u.name == me
    is_admin, accounts, perms = _user_access(u, meta)
    tags = ((kit.chip("Dig", "brand") if you else "") + _scope_badge(scope)
            + (kit.chip("Fra miljøvariabel", "neutral") if u.source != "file" else ""))
    head = (f'<div class="user-head">{kit.avatar(u.name)}<div class="user-titles"><b>{h(u.name)}</b>'
            f'<span class="row-tight">{_role_badge(is_admin)}{tags}</span></div></div>')
    summary = f'<p class="user-summary">{h(ui.access_summary(is_admin, accounts, perms, ui.account_label))}</p>'
    kv = kit.kv_list([
        ("Postkasser", _mailbox_chips(is_admin, accounts, addr)),
        ("Sidst logget ind", _last_login(meta)),
        ("To-trins-login", _twofa_html(u, tf or {})),
        ("Må logge ind", _scope_html(scope)),
    ])
    if u.source != "file":
        actions = '<p class="faint small">Denne bruger kommer fra en miljøvariabel og kan kun ændres på serveren.</p>'
    else:
        last_admin = is_admin and admins <= 1
        btns = [kit.button("Rediger", href=f"/users/{_q(u.name)}", kind="primary", icon="sliders", size="sm")]
        if not is_admin:
            btns.append(kit.button("Se som bruger", href=f"/users/{_q(u.name)}/preview", kind="secondary", icon="eye",
                                   size="sm", attrs=f'title="Se hvad {h(u.name)} ser – uden at kunne gøre noget"'))
        btns += [kit.button("Skift kode", href=f"/users/{_q(u.name)}#kode", kind="secondary", icon="key", size="sm"),
                 _logout_all_form(u, me)]
        if not you and not last_admin:
            btns.append(_remove_form(u))
        actions = f'<div class="user-actions">{"".join(btns)}</div>'
    return (f'<article class="card user-card{" is-you" if you else ""}" data-row="user:{h(u.name)}" '
            f'id="{_dom_id("user-", u.name)}">{head}{summary}{kv}{actions}</article>')


@app.get("/users")
@ui.admin_required
def users_page():
    me = _actor()
    users = _users()
    admins = ui.admin_count(users)
    meta = ui.all_user_meta()
    twofa = ui.all_twofa_status()
    scopes = ui.all_login_scopes()
    addr = _acc_users()
    default_meta = {"perms": frozenset(ui.PERMISSIONS), "last_login_at": None}
    ordered = sorted(users.values(), key=lambda x: (x.name != me, not x.admin, x.name.lower()))
    cards = "".join(_user_card(u, me, admins, meta.get(u.name, default_meta), addr, twofa.get(u.name, {}),
                               scopes.get(u.name, "everywhere"))
                    for u in ordered)
    n_users = len(users) - admins
    head = (f'<div class="section-head"><h2 class="section-title">{_n(len(users), "bruger", "brugere")}</h2>'
            f'<span class="muted">{_n(admins, "administrator", "administratorer")} · '
            f'{_n(n_users, "bruger", "brugere")} med begrænset adgang</span></div>')
    info = kit.alert("Administratorer kan alt. En Bruger ser kun de postkasser, du vælger, og må kun det, du slår til. "
                     "Ændringer gælder med det samme – også for brugere, der allerede er logget ind.", "info",
                     title="Sådan virker adgang")
    body = (info + _all_local_warning(users, scopes)
            + f'<section class="section">{head}<div class="grid grid-auto user-grid" data-list>{cards}</div></section>')
    add_btn = kit.button("Ny bruger", href="/users/new", kind="primary", icon="user-plus")
    return _page("Brugere", body, active="users", actions_html=add_btn,
                 subtitle="Hvem der kan logge ind, hvilke postkasser de ser, og hvad de må.")


ALL_LOCAL_TEXT = ("Alle administratorer må kun logge ind fra hjemmenetværket. Så kan ingen rette noget udefra – "
                  "fx hvis filteret flytter forkert, mens du er på ferie. Overvej at lade én administrator (med "
                  "to-trins-login) logge ind overalt.")


def _all_local_warning(users: dict | None = None, scopes: dict | None = None) -> str:
    """2.3: a warning (never a block) when every administrator is 'Kun lokalt'."""
    if not ui.admins_all_local(users, scopes):
        return ""
    return kit.alert(ALL_LOCAL_TEXT, "warn", title="Ingen administrator kan logge ind udefra")


def _login_scope_field(scope: str = "everywhere", *, you: bool = False) -> str:
    """2.3 (owner request): 'Må logge ind: Overalt / Kun lokalt (hjemmenetværket)'."""
    here = ("Du er på hjemmenetværket lige nu." if ui.request_is_local()
            else "Du er ikke på hjemmenetværket lige nu – vælger du “Kun lokalt” for dig selv, bliver du logget ud.")
    hint = ("Kun lokalt: brugeren kan kun logge ind derhjemme (fx http://192.168.1.10:18080) – aldrig udefra via "
            "Cloudflare Tunnel, heller ikke med “Husk mig”. Logger brugeren ind udefra, svarer login-siden "
            "bare “Forkert brugernavn eller adgangskode”." + (" " + here if you else ""))
    return (f'<div class="scope-field">'
            + kit.form_field("Må logge ind", kit.segmented("login_scope", [(k, ui.LOGIN_SCOPE_TEXT[k])
                                                                           for k in ui.LOGIN_SCOPES], scope),
                             hint=hint)
            + "</div>")


def _scope_from_form() -> str | None:
    """'everywhere' | 'local' | None (field not sent: keep)."""
    v = _form("login_scope", 20)
    return v if v in ui.LOGIN_SCOPES else None


def _password_fields(prefix: str, *, label: str = "Adgangskode", username: str = "") -> str:
    """Password + repeat with 'Generér stærk kode' (admin.js). The hidden
    username field lets password managers file the new password under the
    right login."""
    user_hint = (f'<input type="text" name="username" value="{h(username)}" autocomplete="username" '
                 'class="sr-only" tabindex="-1" aria-hidden="true" readonly>') if username else ""
    return (f'<div class="pw-group" data-pw-group>{user_hint}<div class="grid grid-2 grid-tight">'
            + kit.form_field(label, kit.input_("password", "", type="password",
                                               attrs=f'id="{prefix}-pw" minlength="{MIN_PASSWORD}" maxlength="256" '
                                                     'autocomplete="new-password" required data-pw'))
            + kit.form_field("Gentag", kit.input_("password2", "", type="password",
                                                  attrs=f'id="{prefix}-pw2" minlength="{MIN_PASSWORD}" maxlength="256" '
                                                        f'autocomplete="new-password" required data-match="{prefix}-pw"'))
            + "</div>"
            '<div class="pw-tools js-only">'
            + kit.button("Generér stærk kode", kind="secondary", icon="sparkles", size="sm", attrs='type="button" data-pw-generate')
            + '<span class="pw-out" data-pw-out hidden><code class="mono" data-pw-value></code>'
            + kit.button("Kopiér", kind="ghost", icon="copy", size="sm", attrs='type="button" data-pw-copy')
            + "</span></div>"
            f'<span class="field-hint">Mindst {MIN_PASSWORD} tegn. Den genererede kode vises her, så du kan give den videre – '
            "den gemmes kun krypteret (hash) og kan ikke ses igen.</span></div>")


def _access_fields(*, is_admin: bool, accounts: Iterable[str], perms: Iterable[str],
                   self_admin: bool = False) -> str:
    """Role + mailboxes + permission switches + the live summary."""
    chosen, granted = set(accounts), set(perms)
    accs = ui.effective_accounts()
    role = kit.form_field(
        "Rolle", kit.segmented("role", [("admin", "Administrator"), ("user", "Bruger")], "admin" if is_admin else "user"),
        hint="Administrator: alt – også konti, brugere og indstillinger. Bruger: kun de postkasser og handlinger, du vælger.")
    if accs:
        picks = "".join(
            f'<label class="pick"><input type="checkbox" class="check" name="acct:{h(a.name)}" value="1" '
            f'data-acct-name="{h(a.name)}" data-acct-label="{h(ui.account_label(a.name))}"'
            f'{" checked" if a.name in chosen else ""}>'
            f'<span class="pick-text"><b>{h(ui.account_label(a.name))}</b>'
            f'<small>{h(" · ".join(x for x in (a.name if ui.account_label(a.name) != a.name else "", _attr(a, "user", "")) if x))}</small></span>'
            + ("" if _attr(a, "enabled", True) else kit.chip("På pause", "neutral"))
            + "</label>" for a in accs)
    else:
        picks = '<p class="faint small">Der er ingen postkasser endnu.</p>'
    perm_rows = "".join(
        f'<div class="perm-row">'
        + kit.switch(f"perm:{p}", p in granted, ui.PERMISSION_TEXT[p][0],
                     attrs=f'data-perm-word="{h(PERM_WORDS[p])}"')
        + f'<span class="field-hint">{h(ui.PERMISSION_TEXT[p][1])}</span></div>'
        for p in ui.PERMISSIONS)
    user_part = (
        '<div class="access-user" data-role-user>'
        f'<fieldset class="pick-group"><legend>Postkasser brugeren kan se</legend><div class="pick-list">{picks}</div></fieldset>'
        f'<fieldset class="pick-group"><legend>Hvad må brugeren?</legend><div class="perm-list">{perm_rows}</div>'
        '<p class="faint small">En Bruger kan aldrig se Konti, Brugere, Træning, Drift eller Indstillinger, '
        "aldrig lave regler for alle konti og aldrig gøre en afsender til “Altid igennem”.</p></fieldset></div>")
    summary = (f'<div class="access-summary" data-access-summary aria-live="polite" '
               f'data-admin-text="{h(ui.access_summary(True, (), ()))}">'
               f'{kit.icon("eye")}<span data-access-summary-text>{h(ui.access_summary(is_admin, chosen, granted, ui.account_label))}</span></div>')
    demote = ""
    if self_admin:
        demote = ('<label class="check-confirm self-demote" data-self-demote>'
                  '<input type="checkbox" name="self_demote" value="1">'
                  "<span>Jeg forstår, at jeg mister adgangen til administrationen (Konti, Brugere, Indstillinger …), "
                  "når jeg gør mig selv til Bruger.</span></label>")
    return f'<div class="access-fields" data-access-form>{role}{user_part}{summary}{demote}</div>'


def _access_help_card() -> str:
    rows = "".join(
        f'<li><b>{h(ui.PERMISSION_TEXT[p][0])}</b><span>{h(ui.PERMISSION_TEXT[p][1])}</span></li>' for p in ui.PERMISSIONS)
    return kit.card(
        '<ul class="help-list">'
        '<li><b>Administrator</b><span>Ser alle postkasser og kan ændre alt – konti, brugere, træning og indstillinger.</span></li>'
        '<li><b>Bruger</b><span>Ser kun de postkasser, du sætter flueben ved. Alt andet er skjult – også tal og grafer '
        "for de andre postkasser.</span></li>"
        + rows + "</ul>"
        '<p class="faint small mt-1">Ændringer gælder med det samme, også hvis brugeren er logget ind.</p>',
        title="Sådan virker adgang")


@app.get("/users/new")
@ui.admin_required
def user_new_page():
    # ?mailbox= (not ?account=, which the layout reads as the account switcher).
    pre = (request.args.get("mailbox") or "").strip()
    known = {a.name for a in ui.effective_accounts()}
    accounts = {pre} if pre in known else set()
    is_admin = not accounts
    form = kit.post_form(
        "/users/new",
        '<div class="form-grid">'
        '<h3 class="form-sect">Login</h3>'
        + kit.form_field("Brugernavn", kit.input_("name", "", attrs='id="f-new-user" required maxlength="64" '
                                                  'pattern="[A-Za-z0-9_.\\-]{1,64}" autocomplete="off" autocapitalize="none" '
                                                  'spellcheck="false"'),
                         hint="Bogstaver, tal, punktum, - og _. Fx sofie eller inge.")
        + _password_fields("new")
        + '<h3 class="form-sect">Adgang</h3>'
        + _access_fields(is_admin=is_admin, accounts=accounts,
                         perms=ui.PERMISSIONS if is_admin else ("release",))
        + '<h3 class="form-sect">Sikkerhed</h3>'
        + '<div class="perm-row">' + kit.switch("require_2fa", False, "Kræv to-trins-login")
        + '<span class="field-hint">Brugeren skal sætte en godkendelses-app op ved første login, før spamfilteret '
          "kan bruges. Anbefales for alle, der kan logge ind udefra.</span></div>"
        + _login_scope_field("everywhere")
        + '<div class="form-actions">' + kit.button("Annullér", href="/users", kind="ghost")
        + kit.button("Opret bruger", kind="primary", icon="user-plus") + "</div></div>")
    body = (f'<div class="grid grid-main"><div class="stack">{kit.card(form)}</div>'
            f'<div class="stack">{_access_help_card()}</div></div>')
    sub = (f"Til postkassen {pre} – brugeren ser kun den og må kun frigive post, til du slår mere til."
           if accounts else "Vælg, hvad brugeren skal kunne se og gøre.")
    return _page("Ny bruger", body, active="users", subtitle=sub,
                 breadcrumbs=[("Brugere", "/users"), ("Ny bruger", None)])


def _file_user(name: str) -> Any:
    u = _users().get(name)
    if u is None:
        abort(404)
    if u.source != "file":
        abort(403)
    return u


@app.get("/users/<name>")
@ui.admin_required
def user_edit_page(name: str):
    u = _users().get(name)
    if u is None:
        abort(404)
    me = _actor()
    meta = ui.user_meta(name)
    is_admin, accounts, perms = _user_access(u, meta)
    users = _users()
    admins = ui.admin_count(users)
    you = name == me
    if u.source != "file":
        body = kit.card(kit.alert("Denne bruger kommer fra en miljøvariabel (DASHBOARD_USERS) og kan kun ændres på serveren.",
                                  "info") + kit.kv_list([("Rolle", _role_badge(is_admin)),
                                                         ("Postkasser", _mailbox_chips(is_admin, accounts, _acc_users()))]))
        return _page(name, body, active="users", breadcrumbs=[("Brugere", "/users"), (name, None)])
    last_admin = is_admin and admins <= 1
    scope = ui.login_scope(name)
    access_form = kit.post_form(
        f"/users/{_q(name)}",
        _access_fields(is_admin=is_admin, accounts=accounts, perms=perms, self_admin=you and is_admin)
        + ('<p class="faint small">Den sidste administrator kan ikke gøres til Bruger.</p>' if last_admin else "")
        + _login_scope_field(scope, you=you)
        + '<div class="form-actions">' + kit.button("Gem adgang", kind="primary", icon="check") + "</div>")
    pw_form = kit.post_form(f"/users/{_q(name)}/password",
                            _password_fields("pw", label="Ny adgangskode", username=name)
                            + '<div class="form-actions">' + kit.button("Skift kode", kind="primary", icon="key") + "</div>",
                            attrs="data-reset")
    sessions = (kit.kv_list([("Sidst logget ind", _last_login(meta))])
                + '<p class="faint small mt-1">“Log ud overalt” afslutter alle sessioner – også på enheder, hvor '
                  "brugeren har valgt “Husk mig”. Det sker også automatisk, når koden skiftes.</p>"
                + f'<div class="form-actions">{_logout_all_form(u, me, size="", next_url=f"/users/{_q(name)}")}</div>')
    danger = ""
    if not you and not last_admin:
        danger = kit.card(
            '<div class="danger-row"><div><b>Slet brugeren</b>'
            f'<span>Brugeren logges ud og kan ikke længere logge ind. Skriv {h(name)} for at bekræfte.</span></div>'
            f'{_remove_form(u, size="", view="edit")}</div>', title="Slet bruger", cls="danger-card")
    head = (f'<div class="user-hero">{kit.avatar(name)}<div><div class="row-tight">{_role_badge(is_admin)}'
            + (kit.chip("Dig", "brand") if you else "") + _scope_badge(scope) + "</div>"
            f'<p class="muted small">{h(ui.access_summary(is_admin, accounts, perms, ui.account_label))}</p></div></div>')
    body = (_all_local_warning(users)
            + f'<div class="grid grid-main"><div class="stack">'
            + kit.card(head + access_form, title="Adgang")
            + '</div><div class="stack">'
            + '<div id="kode">' + kit.card(pw_form, title="Skift kode", subtitle="Brugeren logges ud på alle andre "
                                                                                 "enheder, og passkeys fjernes.") + "</div>"
            + _twofa_admin_card(u, me)
            + kit.card(sessions, title="Sessioner") + _kontrolrum_user_card(name) + danger + "</div></div>")
    preview = ("" if is_admin else kit.button("Se som bruger", href=f"/users/{_q(name)}/preview", kind="secondary",
                                               icon="eye", size="sm"))
    return _page(name, body, active="users", subtitle="Rediger adgang, kode, to-trins-login og sessioner.",
                 breadcrumbs=[("Brugere", "/users"), (name, None)], actions_html=preview)


def _twofa_admin_card(u: Any, me: str) -> str:
    """Admin view of a user's two-step login: status, require, reset."""
    tf = ui.twofa_status(u.name)
    q = _q(u.name)
    kv = kit.kv_list([("Status", _twofa_html(u, tf))]
                     + ([("Slået til", h(kit.fmt_ts(tf["enabled_at"])))] if tf["enabled"] else []))
    if tf["required"]:
        req = kit.post_form(f"/users/{q}/2fa/require", kit.hidden("required", "0") + kit.button(
            "Kræv ikke længere", kind="secondary", icon="x-circle", size="sm"))
        req_text = "Påkrævet: brugeren kan ikke bruge spamfilteret uden to-trins-login."
    else:
        req = kit.post_form(f"/users/{q}/2fa/require", kit.hidden("required", "1") + kit.button(
            "Kræv to-trins-login", kind="primary", icon="shield-check", size="sm",
            attrs=kit.confirm_attrs(f"Kræv to-trins-login for {u.name}?",
                                    "Ved næste side skal brugeren sætte to-trins-login op (app eller kode på mail), "
                                    "før spamfilteret kan bruges.",
                                    confirm="Kræv det")))
        req_text = "Valgfrit: brugeren kan selv slå det til under Min konto."
    reset = ""
    if tf["enabled"]:
        reset = kit.post_form(f"/users/{q}/2fa/reset", kit.button(
            "Nulstil", kind="secondary", tone="bad", icon="refresh", size="sm",
            attrs=kit.confirm_attrs(f"Nulstil to-trins-login for {u.name}?",
                                    "Brug det, hvis telefonen er mistet. App-koden, kode på mail og "
                                    "genoprettelseskoderne holder op med at virke" + (" – og brugeren skal sætte det op igen ved næste side." if tf["required"]
                                                  else "; brugeren kan logge ind med adgangskoden alene."),
                                    confirm="Nulstil", tone="danger")))
    own = ('<p class="faint small mt-1">Din egen app og dine genoprettelseskoder styrer du under '
           '<a class="card-link" href="/me">Min konto</a>.</p>') if u.name == me else ""
    return kit.card(kv + f'<p class="muted small mt-1">{h(req_text)}</p>'
                    + f'<div class="form-actions">{reset}{req}</div>' + own,
                    title="To-trins-login", subtitle="Kode fra en app eller på mail ved login.")


@app.post("/users/<name>/2fa/require")
@ui.admin_required
def user_twofa_require(name: str):
    if name not in _users():
        abort(404)
    required = _flag("required")
    ui.twofa_set_required(name, required, _actor())
    ui.audit("twofa_required", detail=f"{name} {'til' if required else 'fra'}")
    msg = (f"{name} skal nu bruge to-trins-login." if required
           else f"To-trins-login er ikke længere påkrævet for {name}.")
    return ui.respond(msg, next_url=f"/users/{_q(name)}", refresh=True)


@app.post("/users/<name>/2fa/reset")
@ui.admin_required
def user_twofa_reset(name: str):
    if name not in _users():
        abort(404)
    if not ui.twofa_status(name)["enabled"]:
        return ui.respond(f"{name} har ikke to-trins-login slået til.", ok=False, next_url=f"/users/{_q(name)}")
    old_addr = ui.twofa_mail_address(name)
    ui.twofa_disable(name, _actor())
    ui.audit("twofa_reset", detail=name)
    ui.security_notice(name, "to-trins-login er nulstillet",
                       f"En administrator ({_actor()}) har nulstillet to-trins-login.", also=[old_addr])
    return ui.respond(f"To-trins-login for {name} er nulstillet.", next_url=f"/users/{_q(name)}", refresh=True)


def _password_problem() -> str | None:
    pw, pw2 = request.form.get("password") or "", request.form.get("password2") or ""
    if len(pw) < MIN_PASSWORD:
        return f"Adgangskoden skal være mindst {MIN_PASSWORD} tegn."
    if len(pw) > 256 or any(c in pw for c in "\r\n\x00"):
        return "Adgangskoden er for lang eller indeholder ugyldige tegn."
    if pw != pw2:
        return "De to adgangskoder er ikke ens."
    return None


def _access_from_form() -> tuple[bool, frozenset[str], frozenset[str]]:
    """(is_admin, accounts, perms) from the role/acct:/perm: fields. Unknown
    account names are dropped (a stale one already on the user is kept
    only if the form re-sends it)."""
    if _form("role", 10) not in ("user", "accounts"):
        return True, frozenset(), frozenset(ui.PERMISSIONS)
    known = {a.name for a in ui.effective_accounts()}
    chosen = frozenset(k[5:] for k in request.form if k.startswith("acct:") and _flag(k)
                       and ACCOUNT_NAME_RE.fullmatch(k[5:]) and k[5:] in known)
    perms = frozenset(p for p in ui.PERMISSIONS if _flag(f"perm:{p}"))
    return False, chosen, perms


def _access_audit(is_admin: bool, accounts: Iterable[str], perms: Iterable[str]) -> str:
    if is_admin:
        return "admin"
    return ("|".join(sorted(accounts)) or "-") + " perms=" + (",".join(p for p in ui.PERMISSIONS if p in set(perms)) or "-")


@app.post("/users/new")
@ui.admin_required
def user_create():
    name = _form("name", 65)
    if not USER_NAME_RE.fullmatch(name) or name.lower() in RESERVED_USER_NAMES:
        return ui.respond("Brugernavnet må kun indeholde bogstaver, tal, punktum, - og _.", ok=False, next_url="/users/new")
    if problem := _password_problem():
        return ui.respond(problem, ok=False, next_url="/users/new")
    is_admin, accounts, perms = _access_from_form()
    scope = _scope_from_form() or "everywhere"
    with ui._USERS_LOCK:
        users = _users()
        if name in users:
            return ui.respond(f"Brugeren {name} findes allerede.", ok=False, next_url="/users/new")
        # Permissions first: the user must never exist without its limits
        # (a missing ui_users row would mean "all permissions"); the same
        # for 'Kun lokalt' (2.3).
        ui.set_user_perms(name, perms, _actor())
        ui.set_login_scope(name, scope, _actor())
        # Never generation 0: a removed-and-recreated user with the same name
        # must not revive old session cookies (they carry the old gen).
        if _flag("require_2fa"):
            ui.twofa_set_required(name, True, _actor())
        users[name] = ui.User(name, ui.hash_password(request.form["password"]), is_admin, accounts,
                              int(time.time()), "file")
        ui.write_users(users.values())
    ui.audit("user_add", detail=f"{name} {_access_audit(is_admin, accounts, perms)}"
             + (" 2fa=krævet" if _flag("require_2fa") else "") + (" login=lokalt" if scope == "local" else ""))
    msg = f"Brugeren {name} er oprettet." + (" Brugeren må kun logge ind lokalt." if scope == "local" else "")
    if ui.admins_all_local():
        ui.flash(ALL_LOCAL_TEXT, "warn")
    return ui.respond(msg, next_url="/users", redirect="/users")


@app.post("/users/<name>")
@ui.admin_required
def user_update(name: str):
    is_admin, accounts, perms = _access_from_form()
    scope = _scope_from_form()
    me = _actor()
    back = f"/users/{_q(name)}"
    with ui._USERS_LOCK:
        u = _file_user(name)
        users = _users()
        new = replace(u, admin=is_admin, accounts=frozenset() if is_admin else accounts)
        users[name] = new
        if ui.admin_count(users) < 1:
            return ui.respond("Der skal være mindst én administrator.", ok=False, next_url=back)
        demoting_self = name == me and u.admin and not is_admin
        if demoting_self and not _flag("self_demote"):
            return ui.respond("Du er ved at fjerne din egen administratoradgang. Sæt flueben ved "
                              "“Jeg forstår …” for at bekræfte.", ok=False, next_url=back)
        old_scope = ui.login_scope(name)
        scope_changed = scope is not None and scope != old_scope
        if scope_changed and scope == "local" and name == me and not ui.request_is_local():
            # Would log the administrator out on the very next click.
            return ui.respond("Du er ikke på hjemmenetværket lige nu. Vælg “Kun lokalt” for dig selv hjemmefra – "
                              "ellers bliver du logget ud med det samme.", ok=False, next_url=back)
        old_perms = ui.user_perms(name)
        access_same = (u.admin, u.accounts) == (new.admin, new.accounts) and (is_admin or old_perms == perms)
        if access_same and not scope_changed:
            return ui.respond("Adgangen er uændret.", next_url=back)
        if not access_same:
            ui.set_user_perms(name, perms, me)
            if (u.admin, u.accounts) != (new.admin, new.accounts):
                ui.write_users(users.values())
        if scope_changed:
            ui.set_login_scope(name, scope, me)
    if not access_same:
        ui.audit("user_access", detail=f"{name} {_access_audit(is_admin, accounts, perms)}")
    if scope_changed:
        ui.audit("user_login_scope", detail=f"{name} {old_scope} -> {scope}")
    if demoting_self:
        return ui.respond("Du er nu Bruger og har ikke længere adgang til administrationen.", next_url="/",
                          redirect="/")
    msg = f"Adgangen for {name} er opdateret."
    if scope_changed:
        msg += (" Brugeren må nu kun logge ind lokalt – sessioner udefra er logget ud." if scope == "local"
                else " Brugeren må nu logge ind overalt.")
    if scope_changed and ui.admins_all_local():
        if not ui.wants_json():
            ui.flash(ALL_LOCAL_TEXT, "warn")
        else:
            msg += " Bemærk: ingen administrator kan nu logge ind udefra."
    return ui.respond(msg, next_url=back, refresh=True)


@app.post("/users/<name>/password")
@ui.admin_required
def user_password(name: str):
    back = f"/users/{_q(name)}"
    if problem := _password_problem():
        return ui.respond(problem, ok=False, next_url=back)
    with ui._USERS_LOCK:
        u = _file_user(name)
        users = _users()
        users[name] = replace(u, verifier=ui.hash_password(request.form["password"]), gen=u.gen + 1)
        ui.write_users(users.values())
    if name == _actor():
        session["gen"] = u.gen + 1  # keep this session; every other one is logged out
    ui.audit("user_password", detail=name)
    # A reset is for a lost or leaked login: a passkey would still let the
    # old holder in without the new password.
    n_pk = ui.remove_all_passkeys(name)
    if n_pk:
        ui.audit("passkey_reset", detail=f"{name} ({n_pk})")
    ui.security_notice(name, "ny adgangskode" + (" og passkeys fjernet" if n_pk else ""),
                       f"En administrator ({_actor()}) har sat en ny adgangskode."
                       + (" " + ui.passkeys_removed_text(n_pk) if n_pk else ""))
    msg = f"Koden for {name} er skiftet. Brugeren er logget ud på alle andre enheder."
    if n_pk:
        msg += f" {'Brugerens passkey er' if n_pk == 1 else f'Brugerens {n_pk} passkeys er'} fjernet."
    return ui.respond(msg, next_url=back)


@app.post("/users/<name>/remove")
@ui.admin_required
def user_remove(name: str):
    view = _form("view", 10)
    back = f"/users/{_q(name)}" if view == "edit" else "/users"
    if name == _actor():
        return ui.respond("Du kan ikke slette din egen bruger.", ok=False, next_url=back)
    if _form("confirm", 70) != name:
        return ui.respond(f"Skriv {name} for at bekræfte.", ok=False, next_url=back)
    with ui._USERS_LOCK:
        _file_user(name)
        users = _users()
        users.pop(name)
        if ui.admin_count(users) < 1:
            return ui.respond("Den sidste administrator kan ikke slettes.", ok=False, next_url=back)
        ui.write_users(users.values())
    ui.forget_user_meta(name)
    ui.audit("user_remove", detail=name)
    extra: dict[str, Any] = {"rows": {f"user:{name}": None}}
    if view == "edit":
        extra["redirect"] = "/users"
    return ui.respond(f"Brugeren {name} er slettet.", next_url="/users", **extra)


@app.post("/users/<name>/logout-all")
@ui.admin_required
def user_logout_all(name: str):
    _file_user(name)
    try:
        ui.bump_generation(name)
    except ValueError:
        abort(404)
    ui.audit("user_logout_all", detail=name)
    you = name == _actor()
    n_pk = ui.remove_all_passkeys(name) if ui.logout_all_wants_passkeys_removed() else 0
    if n_pk:
        ui.audit("passkey_reset", detail=f"{name} ({n_pk})")
        ui.security_notice(name, "passkeys fjernet",
                           ("Du har logget ud overalt. " if you
                            else f"En administrator ({_actor()}) har logget dig ud overalt. ")
                           + ui.passkeys_removed_text(n_pk))
    gone = ""
    if n_pk:
        gone = (f", og {'din passkey' if n_pk == 1 else f'dine {n_pk} passkeys'} er fjernet" if you
                else f", og {'brugerens passkey' if n_pk == 1 else f'brugerens {n_pk} passkeys'} er fjernet")
    if you:
        session.clear()
        return ui.respond(f"Du er logget ud overalt{gone}.", next_url="/login", redirect="/login")
    return ui.respond(f"{name} er logget ud overalt{gone}.", next_url=ui.safe_next(request.form.get("next"), "/users"))


# ---------------------------------------------------------------------------
# Indstillinger
# ---------------------------------------------------------------------------


def _admins_without_2fa(users: dict) -> list[str]:
    tf = ui.all_twofa_status()
    return sorted(n for n, u in users.items() if u.admin and not tf.get(n, {}).get("enabled"))


def _connection_card(users: dict) -> str:
    """Adgang udefra: how THIS request reached the filter (scheme, proxy,
    client IP), the configured external address and plain-Danish advice."""
    https = request.is_secure
    proxied = ui.via_proxy()
    peer = ui.request_peer()
    client = request.remote_addr or ""
    ext = ui.external_url()
    cf_user = ui.cf_access_user()
    cloudflare = bool(request.headers.get("Cf-Ray")) and proxied
    ignored = bool(request.environ.get("sf.ignored_proxy_headers"))
    trusted = ui.TRUSTED_PROXIES_SPEC
    if https:
        tone, ic, head, sub = "ok", "lock", "Krypteret forbindelse (HTTPS)", (
            "Via Cloudflare Tunnel." if cloudflare else "Via en betroet proxy." if proxied else "Direkte forbindelse.")
    elif proxied:
        tone, ic, head, sub = "warn", "alert-triangle", "Via proxy – men uden HTTPS", \
            "Proxyen sender X-Forwarded-Proto: http. Brug HTTPS hele vejen udefra."
    else:
        tone, ic, head, sub = "info", "monitor", "Lokal forbindelse (HTTP)", \
            "Du er på det lokale netværk. Det er fint hjemme – udefra skal det være HTTPS."
    hero = (f'<div class="conn-hero tone-{tone}">{kit.icon(ic, "twofa-icon")}'
            f"<div><b>{h(head)}</b><span>{h(sub)}</span></div></div>")
    trusted_html = (f'<span class="mono-list">{"".join(kit.chip(t.strip(), "neutral") for t in trusted.split(","))}</span>'
                    if trusted else '<span class="faint">Ingen – TRUSTED_PROXIES er tom</span>')
    kv = kit.kv_list([
        ("Forbindelse", kit.badge("HTTPS", "ok") if https else kit.badge("HTTP", "neutral")),
        ("Via proxy", (f"Ja – fra <span class=\"mono small\">{h(peer)}</span>" if proxied else "Nej")),
        ("Din IP", f'<span class="mono small">{h(client)}</span>'),
        # 2.3: what 'Kun lokalt' users see from where this request comes from.
        ("Hjemmenetværk", (kit.badge("Ja", "ok") + ' <span class="faint small">“Kun lokalt”-brugere kan logge ind herfra'
                           "</span>") if ui.request_is_local() else
         (kit.badge("Nej – udefra", "neutral") + ' <span class="faint small">“Kun lokalt”-brugere kan ikke logge ind '
          "herfra</span>")),
        ("Betroede proxyer", trusted_html),
        ("Ekstern adresse", (f'<a class="card-link" href="{h(ext)}">{h(ext)}</a>' if ext
                             else '<span class="faint">Ikke sat</span>')),
        ("Sikre cookies", ("Ja (Secure)" if (https or app.config.get("SESSION_COOKIE_SECURE"))
                           else "Nej – sættes automatisk over HTTPS")),
        ("HSTS", "Slået til" if https else "Kun over HTTPS"),
        ("Cloudflare Access", h(cf_user) if cf_user else '<span class="faint">Ingen identitet modtaget</span>'),
    ])
    advice: list[str] = []
    if ignored:
        advice.append(kit.alert(
            f"Forespørgslen har proxy-headers, men kommer fra {peer}, som ikke er betroet – de bliver ignoreret. "
            f"Står Cloudflare Tunnel eller en anden proxy foran, så sæt TRUSTED_PROXIES={peer} i deploy/versions.env "
            "og genskab filteret (deploy/recreate-filter.sh).", "warn", title="Proxy ikke betroet"))
    if ext and not ext.startswith("https://"):
        advice.append(kit.alert("Den eksterne adresse bruger ikke HTTPS. Adgangskoder og cookies kan så læses "
                                "undervejs – brug https://.", "bad", title="Usikker ekstern adresse"))
    no2fa = _admins_without_2fa(users)
    if (ext or proxied) and no2fa:
        advice.append(kit.alert(
            "Disse administratorer har ikke to-trins-login: " + ", ".join(no2fa) + ". Slå det til, før spamfilteret "
            "kan nås udefra.", "warn", title="To-trins-login mangler",
            action_html=kit.button("Brugere", href="/users", kind="secondary", size="sm")))
    if proxied and https and not cf_user:
        advice.append(kit.alert("Overvej Cloudflare Access (Zero Trust) foran tunnellen, så kun godkendte "
                                "e-mailadresser overhovedet når frem til login-siden.", "info"))
    if not ext:
        advice.append(kit.alert(
            "Vil du kunne bruge spamfilteret udefra – og installere det som app på Android? Opret en Cloudflare Tunnel "
            f"til {'filterets lokale adresse' if proxied else 'http://' + request.host} med dit eget domæne, beskyt "
            "den med Cloudflare Access, sæt TRUSTED_PROXIES til cloudflared's IP og skriv adressen her.", "info",
            title="Adgang udefra"))
    if https and proxied and cf_user and not no2fa:
        advice.append(kit.alert("Alt ser godt ud: HTTPS, betroet proxy, Cloudflare Access og to-trins-login.", "ok"))
    form = kit.post_form(
        "/settings/external-url",
        kit.form_field("Ekstern adresse", kit.input_("external_url", ext, attrs='id="f-external-url" maxlength="200" '
                                                     'placeholder="https://spam.dit-domæne.dk" inputmode="url" '
                                                     'autocapitalize="none" spellcheck="false"'),
                       hint="Den offentlige adresse (fx via Cloudflare Tunnel). Bruges til sikkerhedstjek af formularer "
                            "og vises i app-vejledningen. Tom = kun lokal adgang.")
        + '<div class="form-actions">' + kit.button("Gem adresse", kind="primary", icon="check") + "</div>",
        cls="ext-form")
    return (f'<div id="ekstern">' + kit.card(hero + kv + f'<div class="advice">{"".join(advice)}</div>' + form,
                                             title="Adgang udefra", subtitle="Proxy, HTTPS og Cloudflare Tunnel.")
            + "</div>")


def _my_account_card(me: str) -> str:
    tf = ui.twofa_status(me)
    text = ("Dit login er beskyttet med to-trins-login." if tf["enabled"]
            else "Du har ikke slået to-trins-login til. Det anbefales for administratorer.")
    return kit.card(kit.kv_list([("To-trins-login", _twofa_html(ui.User(me, "", True, frozenset()), tf))])
                    + f'<p class="muted small mt-1">{h(text)}</p>'
                    + '<div class="form-actions">' + kit.button("Min konto", href="/me", kind="secondary", icon="user")
                    + "</div>", title="Din konto")


@app.post("/settings/external-url")
@ui.admin_required
def settings_external_url():
    try:
        value = ui.normalize_external_url(request.form.get("external_url"))
    except ValueError as ex:
        return ui.respond(str(ex), ok=False, next_url="/settings#ekstern")
    old = ui.external_url()
    if value == old:
        return ui.respond("Adressen er uændret.", next_url="/settings#ekstern")
    ui.settings_set("external_url", value)
    g.pop("_external_url", None)
    ui.audit("settings_external_url", detail=f"{old or '-'} -> {value or '-'}")
    return ui.respond("Den eksterne adresse er gemt." if value else "Den eksterne adresse er fjernet.",
                      next_url="/settings#ekstern", refresh=True)


DIGEST_OFF = ("0", "false", "off", "no", "nej")


def digest_enabled() -> bool:
    """settings_kv digest_enabled: missing = on (host-monitor reads it)."""
    raw = (ui.settings_get("digest_enabled") or "").strip().lower()
    return raw not in DIGEST_OFF


def _digest_card() -> str:
    on = digest_enabled()
    inner = (f'<div class="field field-switch">{kit.switch("digest_enabled", on, "Daglig opsummering")}'
             '<span class="field-hint">Hver morgen en kort besked om gårsdagen: hvor meget spam der blev flyttet, '
             "hvad der blev frigivet – og et forslag, hvis en grænse bør justeres.</span></div>"
             f'<div class="digest-note">{kit.icon("smartphone")}<div><b>Kommer beskeden ikke frem på telefonen?</b>'
             "<span>Opsummeringen sendes som en Unraid-notifikation. Tjek i Unraid under "
             "<b>Settings → Notification Settings</b>, at notifikationer når din telefon (fx via e-mail, "
             "Pushover eller Telegram) – eller få den som mail: slå “Daglig opsummering på mail” til under "
             '<a class="card-link" href="#notifikationer">Notifikationer</a>.</span></div></div>'
             f'<div class="form-actions">{kit.button("Gem", kind="secondary", icon="check")}</div>')
    return kit.card(kit.post_form("/settings/digest", inner), title="Daglig opsummering",
                    subtitle="Til administratoren – ikke til brugerne.", cls="digest-card")


@app.post("/settings/digest")
@ui.admin_required
def settings_digest():
    on = _flag("digest_enabled")
    if digest_enabled() == on:
        return ui.respond("Uændret.", next_url="/settings")
    ui.settings_set("digest_enabled", "1" if on else "0")
    ui.audit("settings_digest", detail=f"on={int(on)}")
    return ui.respond("Den daglige opsummering er slået til." if on else "Den daglige opsummering er slået fra.",
                      next_url="/settings")


# ---- 2.3 (B17): blocked attachment types -------------------------------------------------


def _attachments_card() -> str:
    """List editor for defaults.attachment_block (services.attachment_policy)."""
    pol = _svc("attachment_policy", default=None) or {}
    if not isinstance(pol, dict):
        pol = {}
    exts = [str(e) for e in pol.get("extensions") or []]
    default = [str(e) for e in pol.get("default") or []]
    custom = bool(pol.get("custom"))
    limit = int(pol.get("max") or 100)
    chips = "".join(f'<span class="chip tone-neutral mono">.{h(e)}</span>' for e in exts) or \
        '<span class="faint small">Ingen – intet blokeres på filtype.</span>'
    added = [e for e in exts if e not in default]
    removed = [e for e in default if e not in exts]
    diff = ""
    if custom and (added or removed):
        diff = ('<p class="faint small ext-diff">'
                + (f"Ud over standardlisten: {h(', '.join('.' + e for e in added))}. " if added else "")
                + (f"Fjernet fra standardlisten: {h(', '.join('.' + e for e in removed))}." if removed else "")
                + "</p>")
    per = pol.get("per_account") or {}
    per_note = (f'<p class="faint small">Har sin egen liste i accounts.yml: '
                f'{h(", ".join(ui.account_label(n) for n in per))}.</p>' if per else "")
    reset = (kit.button("Gendan standardlisten", kind="ghost", icon="undo", size="sm",
                        attrs='name="reset" value="1" formnovalidate ' + kit.confirm_attrs(
                            "Gendan standardlisten?", f"Listen bliver igen de {len(default)} filtyper, filteret "
                            "kommer med (exe, scr, js, iso, lnk …).", confirm="Gendan"))
             if custom else "")
    inner = (f'<div class="ext-chips">{chips}</div>{diff}{per_note}'
             + kit.form_field("Filtyper", kit.textarea("extensions", " ".join(exts), rows=3,
                                                       attrs='spellcheck="false" autocapitalize="none"'),
                              hint=f"Adskil med mellemrum eller komma, fx exe iso js. Kun bogstaver og tal, højst "
                                   f"{limit}. En tom liste blokerer intet.")
             + f'<div class="form-actions">{reset}{kit.button("Gem", kind="primary", icon="check")}</div>')
    help_text = str(pol.get("help") or "")
    return ('<div id="vedhaeftninger">' + kit.card(
        (f'<p class="muted">{h(help_text)}</p>' if help_text else "")
        + kit.post_form("/settings/attachments", inner)
        + '<p class="faint small mt-1">Undtagelser for enkelte afsendere: '
          '<a class="card-link" href="/rules/attachments">Regler → Vedhæftninger</a>.</p>',
        title="Farlige vedhæftninger", subtitle=f"{_n(len(exts), 'filtype', 'filtyper')} blokeres – også i zip-filer.",
        cls="attach-card") + "</div>")


@app.post("/settings/attachments")
@ui.admin_required
def settings_attachments():
    reset = (request.form.get("reset") or "") == "1"
    text = (request.form.get("extensions") or "")[:4000]
    if locked := _config_locked():
        return ui.respond(locked, ok=False, next_url="/settings#vedhaeftninger")
    # save_config (inside the service) validates, writes atomically and
    # audits the action 'attachment_block'.
    res = _svc("set_attachment_block", text, _actor(), reset=reset, default=None)
    if not isinstance(res, dict):
        return ui.respond("Listen kunne ikke gemmes lige nu.", ok=False, next_url="/settings#vedhaeftninger")
    ok = bool(res.get("ok"))
    changed = ok and res.get("code") == "ok"
    return ui.respond(str(res.get("text") or ("Gemt." if ok else "Listen blev ikke gemt.")), ok=ok,
                      next_url="/settings#vedhaeftninger", **({"reload": True} if changed else {}))


# ---- 2.3.6 (B22): beskyttede domæner (ui_lookalike.py) -----------------------------------


def _site_card() -> str:
    try:
        import ui_site  # noqa: PLC0415 - registered at the end of this module

        return ui_site.site_card()
    except Exception as ex:  # noqa: BLE001 - one card must not break Indstillinger
        log.warning("site card failed: %s", type(ex).__name__)
        return ""


def _lookalike_card() -> str:
    try:
        import ui_lookalike  # noqa: PLC0415 - registered by ui_mail; lazy keeps the import order free

        return ui_lookalike.settings_card()
    except Exception as ex:  # noqa: BLE001 - one card must not break Indstillinger
        log.warning("lookalike card failed: %s", type(ex).__name__)
        return ""


def _namespoof_card() -> str:
    try:
        import ui_namespoof  # noqa: PLC0415 - registered by ui_mail; lazy keeps the import order free

        return ui_namespoof.settings_card()
    except Exception as ex:  # noqa: BLE001 - one card must not break Indstillinger
        log.warning("namespoof card failed: %s", type(ex).__name__)
        return ""


def _trials_card() -> str:
    try:
        import ui_trials  # noqa: PLC0415 - registered by ui_mail

        return ui_trials.settings_card()
    except Exception as ex:  # noqa: BLE001 - one card must not break Indstillinger
        log.warning("trials card failed: %s", type(ex).__name__)
        return ""


def _kontrolrum_user_card(name: str) -> str:
    try:
        import ui_kontrolrum  # noqa: PLC0415

        return ui_kontrolrum.user_card(name)
    except Exception as ex:  # noqa: BLE001 - one card must not break the user page
        log.warning("kontrolrum user card failed: %s", type(ex).__name__)
        return ""


def _access_card() -> str:
    """2.11.0: Home Assistant and Kontrolrum moved to Adgang for programmer."""
    return kit.card('<p class="muted">Nøgler til Home Assistant, Kontrolrum og andre programmer og login fra '
                    "Kontrolrum ligger nu samlet på én side.</p>"
                    + '<div class="form-actions">'
                    + kit.button("Adgang for programmer", href="/access", kind="secondary", icon="key", size="sm")
                    + "</div>", title="Home Assistant og Kontrolrum")


# ---- 2.2 (B21): ugerapport ---------------------------------------------------------------

WEEK_RE = re.compile(r"^\d{4}-W\d{2}$")


def _weekly_settings() -> dict:
    ws = _svc("weekly_settings", default=None)
    return ws if isinstance(ws, dict) else {}


def _weekly_accounts() -> list:
    return [a for a in ui.effective_accounts() if _attr(a, "enabled", True)]


def _weekly_account_arg(name: str) -> str | None:
    """A mailbox name the weekly report may go to, or None."""
    name = (name or "").strip()
    return name if name and any(a.name == name for a in _weekly_accounts()) else None


def _week_arg() -> str | None:
    week = (request.values.get("week") or "").strip().upper()
    return week if WEEK_RE.fullmatch(week) else None


def _week_shift(week: str, days: int) -> str | None:
    import datetime as _dt  # noqa: PLC0415
    try:
        y, w = int(week[:4]), int(week[6:8])
        monday = _dt.date.fromisocalendar(y, w, 1) + _dt.timedelta(days=days)
    except (ValueError, IndexError):
        return None
    iso = monday.isocalendar()
    return f"{iso[0]}-W{iso[1]:02d}"


def _weekly_card() -> str:
    ws = _weekly_settings()
    accs = _weekly_accounts()
    eff = ws.get("admin_account_effective") or ""
    chosen = ws.get("admin_account") if ws.get("admin_account") in {a.name for a in accs} else ""
    opts = [("", "Automatisk" + (f" ({ui.account_label(eff)})" if eff else ""))]
    for a in accs:
        shadow = " – overvåges, får ingen rapport" if _attr(a, "mode", "shadow") == "shadow" else ""
        opts.append((a.name, ui.account_label(a.name) + shadow))
    settings_form = kit.post_form("/settings/weekly", (
        f'<div class="field field-switch">{kit.switch("weekly_enabled", bool(ws.get("enabled")), "Ugerapport")}'
        '<span class="field-hint">Hver mandag morgen lægges en rapport i indbakken: hvad filteret har gjort i ugen, '
        f"hvad der blev frigivet{_webshop_text()}.</span></div>"
        + kit.form_field("Fuld rapport til", kit.select("weekly_admin_account", opts, chosen,
                                                         attrs='id="f-weekly-admin"'),
                         hint="Postkassen, der får hele rapporten med alle konti.")
        + f'<div class="field field-switch">{kit.switch("weekly_users", bool(ws.get("users")), "Kort version til de andre postkasser")}'
          '<span class="field-hint">Hver bruger får kun sin egen postkasse – uden tekniske tal. '
          "Postkasser, der kun overvåges, får aldrig en rapport.</span></div>"
        + '<p class="faint small">Vil du også have den som mail? Slå “Ugerapport på mail” til under '
          '<a class="card-link" href="#notifikationer">Notifikationer</a> – de to valg er uafhængige.</p>'
        + f'<div class="form-actions">{kit.button("Gem", kind="secondary", icon="check")}</div>'), cls="weekly-form")
    target = eff or (accs[0].name if accs else "")
    preview_opts = [(a.name, ui.account_label(a.name) + (" (fuld)" if a.name == eff else " (kort)")) for a in accs]
    try_it = ""
    if accs:
        preview_form = (
            '<form method="get" action="/settings/weekly/preview" class="weekly-try">'
            + kit.form_field("Se rapporten for", kit.select("account", preview_opts, target, attrs='id="f-weekly-acct"'))
            + f'<div class="form-actions">{kit.button("Forhåndsvis", kind="secondary", icon="eye")}</div></form>')
        send_form = kit.post_form("/settings/weekly/send", (
            kit.hidden("account", target)
            + '<div class="form-actions">'
            + kit.button(f"Send nu til {ui.account_label(target)}", kind="ghost", icon="send", attrs=kit.confirm_attrs(
                "Send ugerapporten nu?",
                f"Sidste uges rapport lægges i indbakken hos {ui.account_label(target)}, mærket “[Prøve]”. "
                "Mandagens rapport kommer stadig som normalt.", confirm="Send nu"))
            + "</div>"), cls="weekly-send")
        try_it = (f'<div class="weekly-try-box"><b>Prøv rapporten</b>{preview_form}{send_form}</div>')
    state = (kit.badge("Slået til", "ok") if ws.get("enabled") else kit.badge("Slået fra", "neutral"))
    return f'<div id="ugerapport">' + kit.card(settings_form + try_it, title="Ugerapport", actions=state,
                                                subtitle="En mail om ugen – du behøver ikke logge ind.",
                                                cls="weekly-card") + "</div>"


@app.post("/settings/weekly")
@ui.admin_required
def settings_weekly():
    enabled, users = _flag("weekly_enabled"), _flag("weekly_users")
    admin_raw = _form("weekly_admin_account", 64)
    admin = _weekly_account_arg(admin_raw) if admin_raw else ""
    if admin is None:
        return ui.respond("Ukendt postkasse.", ok=False, next_url="/settings#ugerapport")
    ws = _weekly_settings()
    changes = []
    for key, value, old in (("weekly_enabled", "1" if enabled else "0", "1" if ws.get("enabled") else "0"),
                            ("weekly_users", "1" if users else "0", "1" if ws.get("users") else "0"),
                            ("weekly_admin_account", admin, ws.get("admin_account") or "")):
        if value != old:
            ui.settings_set(key, value)
            changes.append(f"{key.removeprefix('weekly_')}={value or '-'}")
    if not changes:
        return ui.respond("Uændret.", next_url="/settings#ugerapport")
    ui.audit("settings_weekly", detail=" ".join(changes))
    text = ("Ugerapporten er slået til – den første kommer mandag morgen." if enabled
            else "Ugerapporten er slået fra.") if any(c.startswith("enabled=") for c in changes) else "Gemt."
    return ui.respond(text, next_url="/settings#ugerapport", refresh=True)


def _preview_or_error(account: str | None, week: str | None) -> dict:
    res = _svc("weekly_preview", account, week, default=None)
    if not isinstance(res, dict):
        return {"ok": False, "text": "Forhåndsvisningen kunne ikke laves lige nu."}
    return res


@app.get("/settings/weekly/preview")
@ui.admin_required
def settings_weekly_preview():
    raw_acc = (request.args.get("account") or "").strip()
    account = _weekly_account_arg(raw_acc)
    if raw_acc and account is None:
        abort(404)
    week = _week_arg()
    res = _preview_or_error(account, week)
    crumbs = [("Indstillinger", "/settings#ugerapport"), ("Ugerapport", None)]
    if not res.get("ok"):
        body = kit.card(kit.alert(res.get("text") or "Forhåndsvisningen kunne ikke laves.", "bad")
                        + '<div class="form-actions">' + kit.button("Tilbage", href="/settings#ugerapport",
                                                                    kind="secondary", icon="arrow-left") + "</div>")
        return _page("Ugerapport", body, active="settings", breadcrumbs=crumbs)
    wk = str(res.get("week") or "")
    data = res.get("data") or {}
    qs_acc = f"account={_q(account)}&" if account else ""
    prev_w = data.get("prev_week") or _week_shift(wk, -7)
    next_w = _week_shift(wk, 7)
    import datetime as _dt  # noqa: PLC0415
    today = _dt.date.today().isocalendar()
    this_week = f"{today[0]}-W{today[1]:02d}"
    nav = ('<div class="weekly-nav">'
           + (kit.button("Forrige uge", href=f"/settings/weekly/preview?{qs_acc}week={prev_w}", kind="ghost", size="sm",
                         icon="chevron-left") if prev_w else "")
           + f'<span class="weekly-span"><b>Uge {h(wk.rpartition("W")[2].lstrip("0"))}</b>'
           f'<span class="faint small">{h(data.get("span") or "")}</span></span>'
           + (kit.button("Næste uge", href=f"/settings/weekly/preview?{qs_acc}week={next_w}", kind="ghost", size="sm",
                         icon="chevron-right") if next_w and next_w < this_week else "")
           + "</div>")
    who = account or (_weekly_settings().get("admin_account_effective") or "")
    kv = kit.kv_list([
        ("Emne", f"<b>{h(res.get('subject') or '')}</b>"),
        ("Postkasse", ui.account_name_html(who) if who else "–"),
        ("Version", "Fuld rapport (alle konti)" if res.get("full") else "Kort version (kun egen postkasse)"),
    ])
    text = f'<pre class="weekly-text">{h(res.get("body_text") or "")}</pre>'
    html_link = kit.button("Vis som mail", href=f"/settings/weekly/preview.html?{qs_acc}week={wk}", kind="secondary",
                           icon="arrow-up-right", attrs='target="_blank" rel="noopener"')
    actions = ""
    if who:
        actions = kit.post_form("/settings/weekly/send", (
            kit.hidden("account", who) + kit.hidden("week", wk)
            + kit.button(f"Send denne til {ui.account_label(who)}", kind="primary", icon="send", attrs=kit.confirm_attrs(
                "Send rapporten nu?",
                f"Rapporten for uge {wk.rpartition('W')[2].lstrip('0')} lægges i indbakken hos {ui.account_label(who)}, "
                "mærket “[Prøve]”. Den ugentlige rapport kommer stadig som normalt.", confirm="Send nu"))))
    body = kit.card(nav + kv + f'<div class="form-actions">{actions}{html_link}'
                    + kit.button("Tilbage", href="/settings#ugerapport", kind="ghost") + "</div>",
                    title="Forhåndsvisning", subtitle="Sådan ser rapporten ud. Intet er sendt.")
    body += kit.card(text, title="Indhold", subtitle="Tekstudgaven. “Vis som mail” viser den formaterede udgave.")
    return _page("Ugerapport", body, active="settings", breadcrumbs=crumbs,
                 subtitle="Forhåndsvisning – intet bliver sendt, før du trykker Send.")


@app.get("/settings/weekly/preview.html")
@ui.admin_required
def settings_weekly_preview_html():
    raw_acc = (request.args.get("account") or "").strip()
    account = _weekly_account_arg(raw_acc)
    if raw_acc and account is None:
        abort(404)
    res = _preview_or_error(account, _week_arg())
    if not res.get("ok"):
        abort(404)
    g.csp_mail_preview = True  # sandboxed: the mail's inline styles, nothing else
    resp = app.response_class(str(res.get("body_html") or ""), mimetype="text/html")
    return resp


@app.post("/settings/weekly/send")
@ui.admin_required
def settings_weekly_send():
    account = _weekly_account_arg(_form("account", 64))
    if account is None:
        return ui.respond("Vælg en postkasse.", ok=False, next_url="/settings#ugerapport")
    week = _week_arg()
    try:
        res = ui.services.send_weekly_now(account, preview=True, week=week, actor=_actor())
    except Exception as ex:  # noqa: BLE001
        log.error("send_weekly_now failed: %s", type(ex).__name__)
        res = {"ok": False, "code": "error", "text": "Rapporten kunne ikke sendes."}
    res = res if isinstance(res, dict) else {"ok": False, "code": "error"}
    ok = bool(res.get("ok"))
    ui.audit("weekly_send", account, result="ok" if ok else "failed",
             detail=res.get("audit_detail") or f"code={res.get('code')} week={week or '-'}")
    text = str(res.get("text") or (f"Rapporten er lagt i indbakken hos {ui.account_label(account)}." if ok
                                   else "Rapporten kunne ikke sendes."))
    return ui.respond(text, ok=ok, next_url="/settings#ugerapport")


@app.get("/settings")
@ui.admin_required
def settings_page():
    me = _actor()
    users = _users()
    admins = ui.admin_count(users)
    users_card = kit.card(
        f'<p class="muted">{_n(len(users), "bruger", "brugere")} · {_n(admins, "administrator", "administratorer")}. '
        "Bestem hvem der kan logge ind, hvilke postkasser de ser, og hvad de må.</p>"
        + '<div class="form-actions">'
        + kit.button("Ny bruger", href="/users/new", kind="secondary", icon="user-plus")
        + kit.button("Administrér brugere", href="/users", kind="primary", icon="users") + "</div>",
        title="Brugere")
    hours_idle, hours_life = ui.SESSION_IDLE // 3600, ui.SESSION_LIFETIME // 3600
    session_card = kit.card(
        f'<p class="muted">Et login udløber efter {hours_idle} timers inaktivitet og senest efter {hours_life} timer. '
        f"Med “Husk mig” på login-siden holder det i op til {ui.REMEMBER_LIFETIME // 86400} dage "
        f"({ui.REMEMBER_IDLE // 86400} dage uden brug) – kun på den enhed.</p>"
        '<p class="muted mt-1">“Log ud overalt” afslutter alle dine sessioner på alle enheder – også denne. Brug det, '
        "hvis du har glemt at logge ud på en fremmed computer eller har mistet en telefon.</p>"
        + '<div class="form-actions">'
        + kit.post_form(f"/users/{_q(me)}/logout-all", ui.logout_all_passkeys_field(me, own=True) + kit.button(
            "Log ud overalt", kind="secondary", icon="log-out",
            attrs=kit.confirm_attrs("Log ud overalt?", "Du skal logge ind igen bagefter – også på enheder med “Husk mig”.",
                                    confirm="Log ud overalt")))
        + "</div>", title="Sessioner")
    theme_card = kit.look_card()
    about = kit.kv_list([
        ("Version", h(ui.app_version())), ("Python", h(platform.python_version())),
        ("Tilstandsmappe", f'<span class="mono small">{h(str(ui.STATE_DIR))}</span>'),
        ("Konfiguration", f'<span class="mono small">{h(str(ui.CONFIG_PATH))}</span>'),
        ("Konti", h(kit.fmt_int(len(ui.effective_accounts())))),
    ])
    about_card = kit.card(about + f'<p class="faint small mt-1">Selvhostet spamfilter{h(_on_server())}. Ingen data forlader serveren.</p>',
                          title="Om spamfilteret")
    # Brugere, your own account and the theme live on their own pages (nav,
    # Min konto) - no duplicates here.
    del users_card, theme_card
    body = ('<div class="grid grid-main">'
            + f'<div class="stack">{_smtp_card()}{_notify_card()}{_digest_card()}{_weekly_card()}'
              f'{_connection_card(users)}{session_card}</div>'
            + f'<div class="stack">{_site_card()}{_attachments_card()}{_lookalike_card()}{_namespoof_card()}{_trials_card()}{_access_card()}{_my_account_card(me)}'
              f'{kit.install_card(ui.external_url(), admin=True)}{about_card}</div>'
            + "</div>")
    # One column on a phone: the left stack first - so Notifikationer comes
    # right after Mailserver (set up the server, then who gets what).
    return _page("Indstillinger", body, active="settings",
                 subtitle="Mailserver, notifikationer, opsummering, ugerapport, adgang udefra, sessioner, farlige "
                          "vedhæftninger og beskyttede domæner.")


# ---------------------------------------------------------------------------
# Mailserver + Notifikationer (2.3, B29) - settings in settings_kv via
# mailer.py; the SMTP password is a 0600 file and never rendered back.
# ---------------------------------------------------------------------------

SMTP_FIELD_LABELS = {"host": "Server", "port": "Port", "security": "Sikkerhed", "auth": "Login",
                     "username": "Brugernavn", "account": "Postkasse", "from_addr": "Afsender",
                     "from_name": "Afsendernavn", "password": "Adgangskode",
                     "account_password": "Postkassens adgangskode"}


def _mail_status_hero(st: dict) -> str:
    err = st.get("last_error") or {}
    test = st.get("last_test") or {}
    if not st.get("host"):
        return (f'<div class="smtp-hero tone-info">{kit.icon("mail", "twofa-icon")}<div><b>Ikke sat op</b>'
                "<span>Uden mailserver kan to-trins-login kun bruge en app, og alarmer og opsummeringer kommer kun "
                "som Unraid-notifikationer.</span></div></div>")
    if not st.get("enabled"):
        return (f'<div class="smtp-hero tone-neutral">{kit.icon("pause", "twofa-icon")}<div><b>Slået fra</b>'
                "<span>Indstillingerne er gemt, men der sendes ingen mail. Kode på mail tilbydes ikke.</span>"
                "</div></div>")
    if not st.get("configured"):
        return (f'<div class="smtp-hero tone-warn">{kit.icon("alert-triangle", "twofa-icon")}<div><b>Mangler noget</b>'
                "<span>Udfyld server, login og afsender – og send en testmail.</span></div></div>")
    if err and float(err.get("at") or 0) > float(st.get("last_ok_at") or 0):
        return (f'<div class="smtp-hero tone-bad">{kit.icon("alert-circle", "twofa-icon")}<div><b>Seneste afsendelse '
                f'fejlede</b><span>{h(err.get("text") or "")} ({h(kit.ago(err.get("at")))})</span></div></div>')
    if st.get("last_ok_at"):
        return (f'<div class="smtp-hero tone-ok">{kit.icon("check-circle", "twofa-icon")}<div><b>Klar</b>'
                f'<span>Seneste mail sendt {h(kit.ago(st.get("last_ok_at")))}.</span></div></div>')
    if test and not test.get("ok"):
        return (f'<div class="smtp-hero tone-bad">{kit.icon("alert-circle", "twofa-icon")}<div><b>Testmailen fejlede'
                f'</b><span>{h(test.get("text") or "")}</span></div></div>')
    return (f'<div class="smtp-hero tone-warn">{kit.icon("send", "twofa-icon")}<div><b>Ikke testet endnu</b>'
            "<span>Send en testmail for at bekræfte server, port og login.</span></div></div>")


def _smtp_card() -> str:
    m = ui.mail()
    s = m.get_settings()
    st = m.status()
    choices = m.account_choices()
    stored = m.password_stored()
    sugg = "".join(
        f'<button type="button" class="chip chip-btn tone-neutral" data-smtp-fill data-host="{h(p["host"])}" '
        f'data-port="{int(p["port"])}" data-security="{h(p["security"])}">{kit.icon("zap")}{h(p["label"])}: '
        f'{h(p["host"])}:{int(p["port"])}</button>' for p in m.PROVIDERS)
    suggestions = (f'<div class="smtp-suggest"><div class="row-tight"><span class="field-label">Kendte udbydere</span>'
                   f'{kit.chip(m.PROVIDER_NOTE, "warn")}</div>'
                   f'<div class="chip-row">{sugg}</div>'
                   '<span class="field-hint">Klik for at udfylde server, port og sikkerhed. Det er udbydernes '
                   "dokumenterede servere – først testmailen viser, at de virker for dig.</span></div>")
    acc_opts = [("", "Vælg postkasse …")] + [
        (a["name"], f'{ui.account_label(a["name"])} – {a["user"]}') for a in choices]
    acc_attrs = 'id="f-smtp-account" data-smtp-account'
    acc_data = "".join(
        f'<span hidden data-smtp-account-hint="{h(a["name"])}" data-host="{h(a["suggestion"]["host"])}" '
        f'data-port="{int(a["suggestion"]["port"])}" data-security="{h(a["suggestion"]["security"])}"></span>'
        for a in choices if a.get("suggestion"))
    pw_hint = ("Gemt – lad feltet stå tomt for at beholde den. Den vises aldrig igen." if stored
               else "Gemmes som en beskyttet fil på serveren (kun læsbar for filteret) og vises aldrig igen.")
    auth_seg = kit.segmented("auth", [("password", "Brugernavn og adgangskode"),
                                      ("account", "Brug postkassens login")], s["auth"])
    inner = (
        f'<div class="field field-switch">{kit.switch("enabled", bool(s["enabled"]), "Send mail fra spamfilteret")}'
        '<span class="field-hint">Login-koder, alarmer og opsummeringer. Slået fra = der sendes intet.</span></div>'
        + suggestions
        + '<div class="grid grid-2 grid-tight smtp-server">'
        + kit.form_field("Server", kit.input_("host", s["host"], attrs='id="f-smtp-host" data-smtp-host maxlength="253" '
                                              'placeholder="smtp.gigahost.dk" autocapitalize="none" spellcheck="false"'))
        + kit.form_field("Port", kit.input_("port", s["port"], type="number",
                                            attrs='id="f-smtp-port" data-smtp-port min="1" max="65535" inputmode="numeric"'))
        + "</div>"
        + kit.form_field("Sikkerhed", '<div data-smtp-security>' + kit.segmented(
            "security", [(k, v) for k, v in m.SECURITY_LABELS.items()], s["security"]) + "</div>",
            hint="Altid krypteret, og certifikatet tjekkes. Mailserveren skal tilbyde STARTTLS eller SSL/TLS.")
        + kit.form_field("Login", f'<div data-smtp-auth>{auth_seg}</div>')
        + '<div class="smtp-auth-group" data-smtp-auth-group="password">'
        + '<div class="grid grid-2 grid-tight">'
        + kit.form_field("Brugernavn", kit.input_("username", s["username"], attrs='id="f-smtp-user" maxlength="254" '
                                                  'autocomplete="off" autocapitalize="none" spellcheck="false" '
                                                  'placeholder="navn@domæne.dk"'))
        + kit.form_field("Adgangskode", kit.input_("password", "", type="password",
                                                   attrs='id="f-smtp-pw" maxlength="256" autocomplete="new-password" '
                                                         + ('placeholder="•••••••• (gemt)"' if stored else "")),
                         hint=pw_hint)
        + "</div></div>"
        + '<div class="smtp-auth-group" data-smtp-auth-group="account">'
        + kit.form_field("Postkasse", kit.select("account", acc_opts, s["account"], attrs=acc_attrs),
                         hint="Brugernavnet er postkassens adresse. Adgangskoden læses fra postkassens gemte login, "
                              "når der sendes – den kopieres og vises aldrig.")
        + kit.form_field("Postkassens adgangskode", kit.input_(
            "account_password", "", type="password",
            attrs='id="f-smtp-acc-pw" maxlength="256" autocomplete="off"'),
            hint=("Kun nødvendig, hvis serveren ikke er postkassens egen udbyder: så bekræfter du, at "
                  "adgangskoden må sendes dertil. Den sammenlignes kun og gemmes ikke igen."
                  + (" Bekræftet for den nuværende server." if s["auth"] == "account" and s.get("account_bound")
                     else "")))
        + acc_data + "</div>"
        + '<div class="grid grid-2 grid-tight">'
        + kit.form_field("Afsenderadresse", kit.input_(
            "from_addr", s["from_addr"], type="email",
            attrs='id="f-smtp-from" maxlength="254" autocapitalize="none" spellcheck="false" '
                  f'placeholder="{h(m.effective_from(s) or "spamfilter@domæne.dk")}"'),
            hint="Tom = samme adresse som brugernavnet. De fleste udbydere kræver, at det er den samme.")
        + kit.form_field("Afsendernavn", kit.input_("from_name", s["from_name"],
                                                    attrs='id="f-smtp-name" maxlength="64"'))
        + "</div>"
        + f'<div class="form-actions">{kit.button("Gem mailserver", kind="primary", icon="check")}</div>')
    form = kit.post_form("/settings/smtp", inner, cls="smtp-form", attrs="data-smtp-form")
    me_addr = ui.twofa_mail_address(_actor()) or m.effective_from(s)
    test = kit.post_form(
        "/settings/smtp/test",
        kit.form_field("Send testmail til", kit.input_("to", me_addr, type="email",
                                                       attrs='id="f-smtp-test-to" maxlength="254" required '
                                                             'autocapitalize="none" spellcheck="false"'))
        + '<div class="form-actions">' + kit.button("Send testmail", kind="secondary", icon="send") + "</div>",
        cls="smtp-test")
    test_box = (f'<div class="smtp-test-box"><b>Virker det?</b><p class="muted small">Gem først, og send så en testmail. '
                "Fejler den, står der her, hvad serveren sagde – på dansk.</p>" + test + "</div>")
    state = (kit.badge("Slået til", "ok") if s["enabled"] else kit.badge("Slået fra", "neutral"))
    return ('<div id="mailserver">' + kit.card(_mail_status_hero(st) + form + test_box, title="Mailserver",
                                               subtitle="Til login-koder, alarmer og opsummeringer.",
                                               actions=state, cls="smtp-card") + "</div>")


def _notify_card() -> str:
    m = ui.mail()
    routes = m.get_routes()
    configured = m.is_configured()
    rows = []
    for kind in m.KINDS:
        r = routes.get(kind) or {"on": False, "to": []}
        rows.append(
            f'<div class="notify-row" data-notify-row="{kind}">'
            f'<div class="notify-head">{kit.switch(f"{kind}_on", bool(r["on"]), m.KIND_LABELS[kind] + " på mail")}</div>'
            f'<span class="field-hint">{h(m.KIND_HINTS[kind])}</span>'
            + kit.form_field("Modtagere", kit.input_(f"{kind}_to", ", ".join(r["to"]),
                                                     attrs=f'id="f-notify-{kind}" maxlength="1200" '
                                                           'autocapitalize="none" spellcheck="false" '
                                                           'placeholder="navn@domæne.dk, anden@domæne.dk"'))
            + "</div>")
    warn = ("" if configured else
            kit.alert("Sæt mailserveren op (og send en testmail), før der kan komme mails. Valgene her gemmes "
                      "alligevel.", "info"))
    note = ('<p class="faint small mt-1">Unraid-notifikationerne kommer stadig – mail er et ekstra spor. Mens selve '
            "filteret er stoppet, kan der kun komme Unraid-notifikationer; når det kører igen, får du en mail om, "
            "hvor længe det var nede.</p>")
    inner = (warn + "".join(rows) + note
             + f'<div class="form-actions">{kit.button("Gem notifikationer", kind="primary", icon="check")}</div>')
    return ('<div id="notifikationer">' + kit.card(kit.post_form("/settings/notifications", inner, cls="notify-form"),
                                                   title="Notifikationer", subtitle="Hvem får hvilke mails.",
                                                   cls="notify-card") + "</div>")


def _mail_drift_card() -> str:
    m = ui.mail()
    st = m.status()
    if not st.get("host"):
        body = (f'<p class="muted">Ingen mailserver sat op. Alarmer kommer kun som Unraid-notifikationer.</p>'
                + '<div class="form-actions">'
                + kit.button("Sæt mailserver op", href="/settings#mailserver", kind="secondary", icon="mail", size="sm")
                + "</div>")
        return kit.card(body, title="Mail", subtitle="Login-koder og notifikationer.")
    err = st.get("last_error") or {}
    if not st["enabled"]:
        badge = kit.badge("Slået fra", "neutral")
    elif st.get("ok"):
        badge = kit.badge("Virker", "ok")
    elif st.get("configured") and not st.get("last_ok_at") and not err:
        badge = kit.badge("Ikke testet", "warn")
    else:
        badge = kit.badge("Fejl", "bad")
    login = (f"Postkassens login ({ui.account_label(st['account'])})" if st["auth"] == "account"
             else ("Brugernavn + gemt adgangskode" if st["password_stored"] else "Adgangskode mangler"))
    kv = kit.kv_list([
        ("Status", badge),
        ("Server", f'<span class="mono small">{h(st["host"])}:{int(st["port"])}</span> · '
                   f'{h(m.SECURITY_SHORT.get(st["security"], ""))}'),
        ("Login", h(login)),
        ("Afsender", h(st.get("from_addr") or "–")),
        ("Seneste ok", h(kit.ago(st["last_ok_at"])) if st.get("last_ok_at") else '<span class="faint">Aldrig</span>'),
        ("Seneste fejl", (f'{h(err.get("text") or "")} <span class="faint">({h(kit.ago(err.get("at")))})</span>'
                          if err else '<span class="faint">Ingen</span>')),
        ("Sidste døgn", h(f'{kit.fmt_int(st.get("sent_24h") or 0)} sendt · {kit.fmt_int(st.get("failed_24h") or 0)} '
                          f'fejlet · {kit.fmt_int(st.get("queued") or 0)} i kø')),
        ("Afsender-tråd", "Kører" if st.get("worker_alive") else '<span class="faint">Starter ved næste mail</span>'),
    ])
    return kit.card(kv + '<div class="form-actions">'
                    + kit.button("Indstillinger", href="/settings#mailserver", kind="ghost", icon="settings", size="sm")
                    + "</div>", title="Mail", subtitle="Login-koder og notifikationer.")


@app.post("/settings/smtp")
@ui.admin_required
def settings_smtp():
    m = ui.mail()
    form = {k: request.form.get(k) for k in ("host", "port", "security", "auth", "username", "account",
                                             "from_addr", "from_name")}
    form["enabled"] = _flag("enabled")
    password = request.form.get("password") or ""
    account_password = request.form.get("account_password") or ""
    try:
        res = m.save_settings(form, password=password or None, account_password=account_password or None)
    except (OSError, ValueError) as ex:
        log.error("smtp settings not saved: %s", type(ex).__name__)
        return ui.respond("Indstillingerne kunne ikke gemmes (filrettigheder i /state?).", ok=False,
                          next_url="/settings#mailserver", status=500)
    if not res["ok"]:
        first = next(iter(res["errors"].items()))
        msg = f"{SMTP_FIELD_LABELS.get(first[0], first[0])}: {first[1]}"
        return ui.respond(msg, ok=False, next_url="/settings#mailserver", errors=res["errors"])
    changed = res["changed"]
    if not changed:
        return ui.respond("Uændret.", next_url="/settings#mailserver")
    s = res["settings"]
    ui.audit("settings_smtp", detail=("on" if s["enabled"] else "off") + f" {s['host'] or '-'}:{s['port']} "
             f"{s['security']} {s['auth']}" + (f"={s['account']}" if s["auth"] == "account" else "")
             + " changed=" + ",".join(changed))
    if s["enabled"]:
        m.ensure_worker()
    text = ("Mailserveren er gemt. Send en testmail for at bekræfte den." if s["enabled"]
            else "Gemt. Afsendelse af mail er slået fra.")
    return ui.respond(text, next_url="/settings#mailserver", refresh=True)


@app.post("/settings/smtp/test")
@ui.admin_required
def settings_smtp_test():
    res = ui.mail().send_test(request.form.get("to") or "", actor=_actor())
    return ui.respond(res["text"], ok=bool(res["ok"]), next_url="/settings#mailserver", status=400,
                      code=res.get("code"), refresh=bool(res["ok"]))


@app.post("/settings/notifications")
@ui.admin_required
def settings_notifications():
    m = ui.mail()
    data = {k: {"on": _flag(f"{k}_on"), "to": (request.form.get(f"{k}_to") or "")[:1200]} for k in m.KINDS}
    res = m.save_routes(data)
    if not res["ok"]:
        kind, text = next(iter(res["errors"].items()))
        return ui.respond(f"{m.KIND_LABELS[kind]}: {text}", ok=False, next_url="/settings#notifikationer",
                          errors=res["errors"])
    ui.audit("settings_notify", detail=" ".join(
        f"{k}={'on' if r['on'] else 'off'}({len(r['to'])})" for k, r in res["routes"].items()))
    return ui.respond("Notifikationerne er gemt.", next_url="/settings#notifikationer")


# ---------------------------------------------------------------------------
# Se som bruger (2.1): read-only preview of a Bruger's web UI
# ---------------------------------------------------------------------------

# page key -> endpoint of the real page (rendered with the Bruger's rights)
PREVIEW_PAGES = {"home": "overview", "spam": "spam_page", "find": "find_page", "messages": "messages_page",
                 "rules": "rules_page", "help": "help_page", "me": "me_page", "undo": "undo_page",
                 "contacts": "contacts_page"}
PREVIEW_PATHS = {"/": "home", "/spam": "spam", "/find": "find", "/messages": "messages", "/rules": "rules",
                 "/help": "help", "/me": "me", "/undo": "undo", "/rules/contacts": "contacts"}
_A_TAG_RE = re.compile(r"<a\s[^>]*>")
_FORM_TAG_RE = re.compile(r"<form\b[^>]*>")
_HREF_RE = re.compile(r'\shref="([^"]*)"')
_CONTROL_RE = re.compile(r"<(button|select|textarea)\b(?![^>]*\sdisabled)")
_INPUT_RE = re.compile(r'<input\b(?![^>]*type="hidden")(?![^>]*\sdisabled)')
_CSRF_INPUT_RE = re.compile(r'<input type="hidden" name="csrf" value="[^"]*">')
_CSRF_META_RE = re.compile(r'<meta name="csrf-token" content="[^"]*">')
_LIVE_ATTR_RE = re.compile(r'\s(data-live-class|data-live|data-fragment|data-href|data-ajax|data-sync|data-undo-poll)'
                           r'(?=[\s>=])(="[^"]*")?')


def _preview_href(name: str, href: str) -> str | None:
    """Preview URL for a link inside the preview, or None = not available."""
    from urllib.parse import parse_qsl, urlsplit

    if not href.startswith("/") or href.startswith("//"):
        return href if href.startswith("#") else None
    parts = urlsplit(href.replace("&amp;", "&"))
    key = PREVIEW_PATHS.get(parts.path)
    if key is None:
        return None
    args = [("p", key)] + [(k, v) for k, v in parse_qsl(parts.query) if k in ("account", "q", "page", "period", "source")]
    return f"/users/{_q(name)}/preview?" + h(urlencode(args)) + (f"#{h(parts.fragment)}" if parts.fragment else "")


def preview_lockdown(html: str, name: str) -> str:
    """Make a rendered page inert: no CSRF token (any POST would fail), every
    form/button/field disabled, no live polling with the admin's session,
    and links stay inside the preview (or are switched off)."""
    html = _CSRF_META_RE.sub("", html)
    html = _CSRF_INPUT_RE.sub("", html)

    def form(m: re.Match) -> str:
        tag = m.group(0)
        tag = re.sub(r'\smethod="[^"]*"', "", tag)
        tag = re.sub(r'\saction="[^"]*"', "", tag)
        return tag[:-1] + ' action="#" method="get" inert data-preview-off>'

    def anchor(m: re.Match) -> str:
        tag = m.group(0)
        if "data-preview-keep" in tag:
            return tag
        hm = _HREF_RE.search(tag)
        if not hm:
            return tag
        new = _preview_href(name, hm.group(1))
        if new is None:
            return _HREF_RE.sub("", tag, count=1)[:-1] + ' aria-disabled="true" data-preview-off>'
        return tag[:hm.start()] + f' href="{new}"' + tag[hm.end():]

    html = _FORM_TAG_RE.sub(form, html)
    html = _LIVE_ATTR_RE.sub("", html)
    html = _A_TAG_RE.sub(anchor, html)
    html = _CONTROL_RE.sub(lambda m: f"<{m.group(1)} disabled", html)
    html = _INPUT_RE.sub("<input disabled", html)
    return html.replace('<body class="', '<body class="is-preview ', 1)


def _preview_unavailable(name: str, text: str) -> str:
    body = kit.card(kit.empty_state(f"Ikke tilgængelig for {name}", text, "lock",
                                    kit.button("Til forsiden", href="/", kind="secondary", icon="arrow-left")))
    return kit.render_page("Ingen adgang", body, active="")


@app.get("/users/<name>/preview")
@ui.admin_required
def user_preview(name: str):
    from flask import Response
    from werkzeug.exceptions import HTTPException

    target = _users().get(name)
    if target is None:
        abort(404)
    if target.admin:
        abort(403)  # administrators see everything anyway; never preview another admin
    page = request.args.get("p") or "home"
    endpoint = PREVIEW_PAGES.get(page)
    if endpoint is None or endpoint not in app.view_functions:
        abort(404)
    ui.audit("user_preview", detail=f"{name} page={page}")
    view = app.view_functions[endpoint]
    ui.begin_preview(name)
    try:
        try:
            resp = view()
        except HTTPException as ex:
            if ex.code == 403:
                resp = _preview_unavailable(name, "Brugeren har ikke tilladelse til denne side, så den findes ikke i "
                                                  "brugerens menu.")
            elif ex.code == 404:
                resp = _preview_unavailable(name, "Brugeren kan ikke se denne postkasse eller side.")
            else:
                raise
        if isinstance(resp, tuple):
            resp = resp[0]
        if isinstance(resp, Response):
            if resp.status_code in (301, 302, 303, 307, 308) or not resp.mimetype.startswith("text/html"):
                resp = _preview_unavailable(name, "Siden kan ikke vises i forhåndsvisningen.")
            else:
                resp = resp.get_data(as_text=True)
        html = preview_lockdown(str(resp), name)
    finally:
        ui.end_preview()
    out = Response(html, mimetype="text/html")
    out.headers["Cache-Control"] = "no-store"
    return out


import ui_dmarc  # noqa: E402,F401  (2.6 C2: DMARC-rapporter, admin only)
import ui_ai  # noqa: E402,F401  (2.7: AI-vurdering, admin only)
import ui_mailcheck  # noqa: E402,F401  (2.7: Mailsikkerhed, admin only)
import ui_kontrolrum  # noqa: E402,F401  (2.9.0: Kontrolrum single sign-on, admin only)
import ui_updates  # noqa: E402,F401  (2.10: Opdateringer, admin only)
import ui_access  # noqa: E402,F401  (2.11.0: Adgang for programmer - API-nøgler + SSO, admin only)
import ui_site  # noqa: E402,F401  (Lokal opsætning: config/site.yml, admin only)
