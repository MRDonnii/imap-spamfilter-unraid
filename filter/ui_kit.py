"""Design system for the spamfilter web UI (spamfilter 2.0).

Every page is rendered from these helpers so markup, class names and
Danish wording stay consistent. All helpers return HTML strings. Text
arguments are escaped with h(); pass a markupsafe.Markup object when you
deliberately want to hand over pre-built HTML in a "text" slot.

CSP note: the app runs with `style-src 'self'` and `script-src 'self'`, so
nothing here may emit `style=""` attributes, `<style>` or inline scripts.
Dynamic widths use pre-generated classes (`p-0` .. `p-100`), charts use
SVG presentation attributes, behaviour hangs off `data-*` attributes that
static/app.js picks up.
"""

from __future__ import annotations

import base64
import binascii
import itertools
import json
import math
import re
import time
from datetime import datetime
from email.utils import parseaddr
from typing import Any, Iterable, Sequence

from markupsafe import Markup, escape

try:  # Danish wall-clock time for every timestamp the owner sees.
    from zoneinfo import ZoneInfo

    TZ: Any = ZoneInfo("Europe/Copenhagen")
except Exception:  # noqa: BLE001 - missing tzdata: fall back to local time
    TZ = None

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

MODE_LABELS = {"shadow": "Overvåg", "flag": "Markér", "move": "Filtrér"}
MODE_HINTS = {
    "shadow": "Scorer ny post uden at røre den",
    "flag": "Lader spam ligge i indbakken med et skjult spam-mærke",
    "move": "Flytter spam til Spamfilter-mappen",
}
MODE_TONES = {"shadow": "info", "flag": "warn", "move": "brand"}

STATE_LABELS = {
    "starting": "Starter",
    "connecting": "Forbinder",
    "idle": "Aktiv",
    "working": "Arbejder",
    "error": "Forbindelsesfejl",
    "auth_failed": "Login fejler",
    "paused": "På pause",
    "config_error": "Konfigurationsfejl",
    "stopped": "Stoppet",
    "stale": "Svarer ikke",
    "paused_moves": "Flytning på pause",
    "limited": "Udbyder begrænser",
    "unknown": "Ukendt",
}
STATE_TONES = {
    "starting": "info",
    "connecting": "info",
    "idle": "ok",
    "working": "ok",
    "error": "bad",
    "auth_failed": "bad",
    "paused": "neutral",
    "config_error": "bad",
    "stopped": "neutral",
    "stale": "warn",
    "paused_moves": "bad",
    "limited": "warn",
    "unknown": "neutral",
}

# messages.our_action -> (label, tone). Old 1.x values stay readable.
ACTION_LABELS: dict[str | None, tuple[str, str]] = {
    "none": ("Legitim", "ok"),
    "shadow_spam": ("Ville være flyttet", "warn"),
    "shadow": ("Ville være flyttet", "warn"),
    "flagged": ("Markeret som spam", "bad"),
    "flag": ("Markeret som spam", "bad"),
    "pending_move": ("Flyttes om lidt", "warn"),
    "moved_to_junk": ("Flyttet til spam", "bad"),
    "move_failed": ("Flytning fejlede", "warn"),
    "allowlisted": ("Tilladt afsender", "ok"),
    "manual_release": ("Frigivet", "info"),
    "manual_mark_spam": ("Flyttet til spam manuelt", "bad"),
    "user_rescued": ("Flyttet tilbage af bruger", "info"),
    "user_junked": ("Flyttet til spam af bruger", "bad"),
    "provider_junk": ("Fanget af udbyder", "neutral"),
    # 2.6 (A4): newsletter folder
    "newsletter_pending": ("Flyttes til nyhedsbreve", "info"),
    "newsletter_moved": ("Flyttet til nyhedsbreve", "info"),
    "newsletter_move_failed": ("Flytning til nyhedsbreve fejlede", "warn"),
    "newsletter_kept": ("Nyhedsbrev – i indbakken", "ok"),
    None: ("Ikke vurderet", "neutral"),
}

TONES = ("ok", "warn", "bad", "info", "neutral", "brand")

DA_MONTHS = ("jan.", "feb.", "mar.", "apr.", "maj", "jun.", "jul.", "aug.",
             "sep.", "okt.", "nov.", "dec.")
DA_WEEKDAYS = ("man", "tir", "ons", "tor", "fre", "lør", "søn")

# ---------------------------------------------------------------------------
# rspamd symbol explanations (Danish, short enough for chips)
# ---------------------------------------------------------------------------

SYMBOL_TEXT: dict[str, str] = {
    # Learning / reputation
    "BAYES_SPAM": "Ligner spam, som filteret har lært (Bayes)",
    "BAYES_HAM": "Ligner legitim post, som filteret har lært (Bayes)",
    "NEURAL_SPAM": "Neuralt netværk vurderer spam",
    "NEURAL_HAM": "Neuralt netværk vurderer legitim",
    "FUZZY_DENIED": "Kendt spam (fingeraftryk fra fællesdatabase)",
    "FUZZY_PROB": "Ligner kendt spam (fingeraftryk)",
    "FUZZY_WHITE": "Kendt legitim masseudsendelse (fingeraftryk)",
    "FUZZY_UNKNOWN": "Ukendt fingeraftryk",
    # SPF / DKIM / DMARC / ARC
    "R_SPF_ALLOW": "SPF bestået – serveren må sende for domænet",
    "R_SPF_FAIL": "SPF fejlede – serveren må ikke sende for domænet",
    "R_SPF_SOFTFAIL": "SPF blødt fejlet – serveren er nok ikke godkendt",
    "R_SPF_NEUTRAL": "SPF neutral – domænet tager ikke stilling",
    "R_SPF_NA": "Domænet har ingen SPF-regel",
    "R_SPF_DNSFAIL": "SPF kunne ikke slås op (DNS-fejl)",
    "R_SPF_PERMFAIL": "Domænets SPF-regel er ugyldig",
    "R_DKIM_ALLOW": "Gyldig DKIM-signatur",
    "R_DKIM_REJECT": "Ugyldig DKIM-signatur",
    "R_DKIM_NA": "Ingen DKIM-signatur",
    "R_DKIM_TEMPFAIL": "DKIM kunne ikke kontrolleres (midlertidig fejl)",
    "R_DKIM_PERMFAIL": "DKIM-signaturen er beskadiget",
    "DKIM_TRACE": "DKIM-spor (kun information)",
    "DMARC_POLICY_ALLOW": "DMARC bestået",
    "DMARC_POLICY_REJECT": "DMARC fejlet – domænet beder om afvisning (mulig forfalskning)",
    "DMARC_POLICY_QUARANTINE": "DMARC fejlet – domænet beder om karantæne",
    "DMARC_POLICY_SOFTFAIL": "DMARC fejlet, men domænet har ingen streng politik",
    "DMARC_POLICY_ALLOW_WITH_FAILURES": "DMARC bestået med enkelte fejl",
    "DMARC_NA": "Domænet har ingen DMARC-politik",
    "DMARC_BAD_POLICY": "Domænets DMARC-politik er ugyldig",
    "ARC_ALLOW": "Gyldig ARC-kæde (videresendt korrekt)",
    "ARC_REJECT": "Ugyldig ARC-kæde",
    "ARC_NA": "Ingen ARC-kæde",
    "ARC_SIGNED": "ARC-signeret",
    "AUTH_NA": "Afsenderen er hverken SPF-, DKIM- eller DMARC-godkendt",
    "AUTH_NA_OR_FAIL": "Afsendergodkendelse mangler eller fejlede",
    # Envelope / headers
    "FORGED_SENDER": "Afsenderadressen ser forfalsket ud",
    "FORGED_RECIPIENTS": "Modtagerne passer ikke med konvolutten",
    "FROM_HAS_DN": "Afsender har et visningsnavn",
    "FROM_NEQ_ENVFROM": "Afsender og returadresse er forskellige",
    "FROM_EQ_ENVFROM": "Afsender og returadresse er ens",
    "FROM_NO_DN": "Afsender har intet visningsnavn",
    "FROM_DN_EQ_ADDR": "Visningsnavnet er selve adressen",
    "SPOOF_DISPLAY_NAME": "Visningsnavnet foregiver at være en anden",
    "FROM_NAME_HAS_TITLE": "Visningsnavnet indeholder en titel (Dr., Mr. …)",
    "FREEMAIL_FROM": "Sendt fra en gratis-mailtjeneste",
    "FREEMAIL_ENVFROM": "Returadresse hos gratis-mailtjeneste",
    "FREEMAIL_REPLYTO": "Svar går til en gratis-mailtjeneste",
    "FREEMAIL_REPLYTO_NEQ_FROM_DOM": "Svar går til en anden gratis-mailadresse",
    "HAS_REPLYTO": "Har en særskilt svar-adresse",
    "REPLYTO_DOM_NEQ_FROM_DOM": "Svar-adressen er på et andet domæne",
    "REPLYTO_ADDR_EQ_FROM": "Svar-adressen er afsenderens egen",
    "MISSING_MID": "Mangler Message-ID",
    "MID_RHS_NOT_FQDN": "Message-ID har intet rigtigt domæne",
    "MID_RHS_MATCH_FROM": "Message-ID passer med afsenderdomænet",
    "MID_CONTAINS_FROM": "Message-ID indeholder afsenderadressen",
    "INVALID_MSGID": "Ugyldigt Message-ID",
    "MISSING_DATE": "Mangler dato",
    "DATE_IN_FUTURE": "Datoen ligger i fremtiden",
    "DATE_IN_PAST": "Datoen ligger langt tilbage",
    "MISSING_TO": "Mangler modtager (To)",
    "MISSING_FROM": "Mangler afsender",
    "MISSING_SUBJECT": "Mangler emne",
    "MISSING_MIME_VERSION": "Mangler MIME-version",
    "MULTIPLE_UNIQUE_HEADERS": "Dobbelte headere der kun må forekomme én gang",
    "TO_DN_NONE": "Modtager står uden navn",
    "TO_DN_ALL": "Alle modtagere har navn",
    "TO_DN_SOME": "Nogle modtagere har navn",
    "TO_MATCH_ENVRCPT_ALL": "Modtagerne passer med konvolutten",
    "TO_MATCH_ENVRCPT_SOME": "Kun nogle modtagere passer med konvolutten",
    "R_UNDISC_RCPT": "Skjulte modtagere (undisclosed-recipients)",
    "PRECEDENCE_BULK": "Markeret som masseudsendelse",
    "HAS_LIST_UNSUB": "Har afmeldingslink (nyhedsbrev)",
    "MAILLIST": "Sendt via en mailingliste",
    "HAS_X_PRIO_ONE": "Markeret som høj prioritet",
    "XM_UA_NO_VERSION": "Mailprogram uden versionsnummer",
    # Subject / body / MIME
    "SUBJ_ALL_CAPS": "Emnet er skrevet med store bogstaver",
    "SUBJECT_ENDS_EXCLAIM": "Emnet slutter med udråbstegn",
    "SUBJECT_HAS_EXCLAIM": "Emnet indeholder udråbstegn",
    "SUBJECT_HAS_CURRENCY": "Emnet nævner penge/valuta",
    "SUBJECT_HAS_QUESTION": "Emnet stiller et spørgsmål",
    "SUBJ_EXCESS_QP": "Unødigt kodet emnelinje",
    "SUBJ_EXCESS_BASE64": "Unødigt kodet emnelinje",
    "MIME_GOOD": "Korrekt opbygget besked",
    "MIME_HTML_ONLY": "Kun HTML – ingen tekstversion",
    "MIME_BASE64_TEXT": "Teksten er base64-kodet",
    "MIME_BAD_ATTACHMENT": "Mistænkelig vedhæftning",
    "MIME_BAD_EXTENSION": "Farlig type vedhæftet fil",
    "MIME_DOUBLE_BAD_EXTENSION": "Vedhæftet fil med falsk filendelse",
    "MIME_ARCHIVE_IN_ARCHIVE": "Arkiv inde i arkiv",
    "MIME_TRACE": "MIME-spor (kun information)",
    "R_MIXED_CHARSET": "Blandede tegnsæt (sløret tekst)",
    "R_MIXED_CHARSET_URL": "Link med blandede tegnsæt",
    "R_PARTS_DIFFER": "Tekst- og HTML-delen er meget forskellige",
    "HTML_SHORT_LINK_IMG_1": "Kort HTML med billede og link",
    "HTML_SHORT_LINK_IMG_2": "Kort HTML med billede og link",
    "HTML_META_REFRESH_URL": "HTML der automatisk sender dig videre",
    "ZERO_FONT": "Usynlig tekst skjult for læseren",
    "MANY_INVISIBLE_PARTS": "Mange usynlige dele",
    "CTE_CASE": "Usædvanlig skrivemåde af kodningsheader",
    "BROKEN_CONTENT_TYPE": "Ødelagt Content-Type",
    "GTUBE": "Testbesked (GTUBE)",
    # Links
    "PHISHING": "Link-tekst og -adresse peger forskellige steder (phishing)",
    "R_SUSPICIOUS_URL": "Mistænkeligt link",
    "REDIRECTOR_URL": "Link via omdirigeringstjeneste",
    "URI_COUNT_ODD": "Usædvanligt antal links",
    "HAS_LINK_TO_LARGE_IMG": "Link til stort billede",
    "OMOGRAPH_URL": "Link med forvekslelige tegn",
    "DBL_SPAM": "Linkdomæne på Spamhaus' spamliste",
    "DBL_PHISH": "Linkdomæne på Spamhaus' phishingliste",
    "DBL_MALWARE": "Linkdomæne på Spamhaus' malwareliste",
    "DBL_ABUSE": "Linkdomæne misbruges (Spamhaus)",
    "URIBL_BLACK": "Link til domæne på URIBL-sortliste",
    "URIBL_GREY": "Link til domæne på URIBL-gråliste",
    "URIBL_RED": "Link til domæne på URIBL-rødliste",
    "SURBL_MULTI": "Link til domæne på SURBL-liste",
    "SEM_URIBL": "Linkdomæne på SpamEatingMonkey-liste",
    "SEM_URIBL_FRESH15": "Linkdomæne er helt nyregistreret",
    "MSBL_EBL": "Afsenderadresse på MSBL-liste",
    # Sending host
    "RCVD_IN_DNSWL_HI": "Afsender-IP har fremragende omdømme (DNSWL)",
    "RCVD_IN_DNSWL_MED": "Afsender-IP har godt omdømme (DNSWL)",
    "RCVD_IN_DNSWL_LOW": "Afsender-IP er kendt (DNSWL)",
    "RCVD_IN_DNSWL_NONE": "Afsender-IP er registreret (DNSWL)",
    "RCVD_TLS_ALL": "Krypteret hele vejen (TLS)",
    "RCVD_TLS_LAST": "Sidste hop var krypteret",
    "RCVD_NO_TLS_LAST": "Sidste hop var ukrypteret",
    "RCVD_VIA_SMTP_AUTH": "Sendt via godkendt mailserver",
    "ONCE_RECEIVED": "Kun én server på vejen",
    "RDNS_NONE": "Afsenderserveren har intet DNS-navn",
    "RDNS_DNSFAIL": "Afsenderserverens DNS-navn kunne ikke slås op",
    "HFILTER_HOSTNAME_UNKNOWN": "Afsenderserverens navn kunne ikke verificeres",
    "HFILTER_HELO_BAREIP": "Serveren præsenterer sig med en rå IP",
    "HFILTER_HELO_NORES_A_OR_MX": "Serverens HELO-navn findes ikke i DNS",
    "HFILTER_HELO_IP_A": "Serverens HELO-navn peger på en anden IP",
    "RBL_SPAMHAUS_SBL": "Afsender-IP på Spamhaus' spamliste",
    "RBL_SPAMHAUS_XBL": "Afsender-IP er en kendt inficeret maskine",
    "RBL_SPAMHAUS_PBL": "Afsender-IP er en privat/dynamisk adresse",
    "RBL_SPAMHAUS_CSS": "Afsender-IP sender kendt snavs (Spamhaus CSS)",
    "RBL_MAILSPIKE_BAD": "Afsender-IP har dårligt omdømme (Mailspike)",
    "RBL_MAILSPIKE_VERYBAD": "Afsender-IP har meget dårligt omdømme",
    "RBL_MAILSPIKE_WORST": "Afsender-IP har elendigt omdømme",
    "RWL_MAILSPIKE_GOOD": "Afsender-IP har godt omdømme (Mailspike)",
    "RWL_MAILSPIKE_VERYGOOD": "Afsender-IP har meget godt omdømme",
    "RWL_MAILSPIKE_EXCELLENT": "Afsender-IP har fremragende omdømme",
    "RWL_MAILSPIKE_POSSIBLE": "Afsender-IP har neutralt omdømme",
    "RBL_SENDERSCORE": "Afsender-IP har lav SenderScore",
    "RBL_SEM": "Afsender-IP på SpamEatingMonkey-liste",
    "RBL_BLOCKLISTDE": "Afsender-IP har angrebet andre servere",
    "RBL_VIRUSFREE_BOTNET": "Afsender-IP er del af et botnet",
    "ASN": "Afsenderens netværk (kun information)",
    "RECEIVED_SPAMHAUS_PBL": "Tidligere hop fra privat/dynamisk adresse",
    # the filter's own pseudo-symbols
    "TH_PROVIDER_SPAM": "Udbyderens eget spamfilter mente det var spam",
    "TH_PROVIDER_SCORE": "Udbyderens spamfilter gav en høj score",
    "TH_RULE_BLOCK": "Afsenderen er blokeret af en regel",
    "TH_RULE_ALLOW": "Afsenderen er tilladt af en regel",
    "TH_FORCE_UNVERIFIED": "Altid igennem kunne ikke bekræftes – vurderet som almindelig tilladelse",
    "TH_PROTECTED_RCPT": "Sendt til en beskyttet adresse – højere grænse",
    "TH_NEWSLETTER": "Ægte nyhedsbrev (afmeldingslink og gyldig signatur)",
    # 2.2 phishing rules (rspamd multimap/composites, group spamfilter_own)
    "TH_FROM_BRAND_NAME": "Afsendernavnet nævner et kendt brand",
    "TH_FROM_BRAND_DOMAIN": "Sendt fra brandets eget domæne",
    "TH_BRAND_SPOOF": "Afsendernavnet udgiver sig for at være et kendt brand, men mailen kommer fra et andet domæne",
    "TH_FROM_NAME_HOMOGLYPH": "Afsendernavnet bruger forvekslelige bogstaver fra et andet alfabet (fx græske eller kyrilliske)",
    "TH_LURE_SUBJECT": "Emnet ligner en typisk lokkemail (betaling, pakke, konto eller gevinst)",
    "TH_LURE_COMBO": "Lokkende emne og falsk afsender på én gang – typisk phishing",
    "TH_FROM_ABUSED_TLD": "Afsenderdomænet bruger et topdomæne, som spammere ofte misbruger",
    "TH_FROM_TLD_CN_RU": "Afsenderdomænet ender på .cn eller .ru",
    "PHISHED_OPENPHISH": "Link til en kendt phishing-side (OpenPhish)",
    "PHISHED_PHISHTANK": "Link til en kendt phishing-side (PhishTank)",
    "PHISHED_EXCLUDED": "Link til jeres egen webshop – ikke tjekket mod phishing-listerne",
    # 2.6 (A1) brand in the subject, (A5) Phishing Army feed
    "TH_SUBJECT_BRAND": "Emnet nævner et kendt brand",
    "TH_SUBJECT_BRAND_SPOOF": ("Emnet udgiver sig for at komme fra et kendt brand og lokker med betaling, konto "
                               "eller pakke, men mailen kommer fra et andet domæne"),
    "TH_PHISHARMY_URL": "Link til en side på en liste over phishing-sider (Phishing Army)",
    "TH_LURE_SUBJECT_STRONG": "Emnet beder om betalings-, konto- eller MitID-oplysninger",
    # 2.7.6 Gmail phishing relayed by Google
    "TH_GOOGLE_RELAY_ENV": "Sendt gennem Googles relæ for Gmail-brugere",
    "TH_FREEMAIL_VIA_GOOGLE": "Ukendt Gmail-afsender sendt gennem Googles relæ (typisk phishing)",
    "RSPAMD_URIBL": "Linkdomæne på rspamd's egen domæneliste",
    # 2.2 engine pseudo-symbols
    "TH_OWN_PLATFORM_URIBL": "Jeres egen webshop-platform står fejlagtigt på en domæneliste – udlignet",
    "TH_AGED_SCAN": "Scannet sent – afsenderens SPF/DMARC er erstattet af udbyderens vurdering ved modtagelsen",
    "TH_PROVIDER_AUTH_PASS": "Udbyderen bekræftede afsenderen ved modtagelsen",
    "TH_PROVIDER_AUTH_FAIL": "Udbyderen kunne ikke bekræfte afsenderen ved modtagelsen (DMARC)",
    "TH_PROVIDER_AUTH_SPOOF": "Udbyderens SPF- eller DMARC-tjek fejlede ved modtagelsen – en tilladelse gælder ikke",
    "TH_AGED_UNVERIFIED": "Scannet sent uden udbyderens godkendelse eller gyldig signatur – en tilladelse gælder ikke",
    # 2.3 (B10-B12) trust signals from your own sent mail and sender history
    "TH_KNOWN_CONTACT": "Kendt kontakt – du har skrevet til afsenderen",
    "TH_KNOWN_DOMAIN": "Kendt organisation – du har skrevet til andre her",
    "TH_REPLY": "Svar på en mail, du selv har sendt",
    "TH_REPLY_THREAD": "Svar i en tråd, du selv har startet (ny deltager i tråden)",
    "TH_REPLY_UNVERIFIED": "Ligner et svar, men afsenderen kunne ikke bekræftes",
    "TH_ESTABLISHED": "Fast afsender – har skrevet til dig mange gange fra samme system",
    "TH_PROVIDER_FLAG_TRUSTED": "Udbyderens spam-markering tæller mindre – afsenderen er kendt i forvejen",
    "TH_FIRST_CONTACT": "Første mail fra denne afsender",
    # 2.3 (B16/B17) threats and attachments
    "TH_ATTACH_BLOCK": "Farlig vedhæftning – filtypen blokeres altid",
    "TH_ATTACH_ALLOWED": "Farlig vedhæftning tilladt for afsenderen",
    "TH_ENCRYPTED_ARCHIVE": "Krypteret arkiv fra ukendt afsender – kan ikke undersøges",
    # 2.7: ClamAV runs in the all-in-one container (rspamd/local.d/antivirus.conf)
    "CLAM_VIRUS": "Virus fundet af antivirus (ClamAV)",
    "CLAM_PHISH": "Phishing fundet af antivirus (ClamAV)",
    "CLAM_VIRUS_FAIL": "Antivirus (ClamAV) svarede ikke – vedhæftningerne er ikke virusscannet (giver ingen point)",
    "TH_CLAM_HEURISTIC": "Antivirus (ClamAV) fandt et mistænkeligt mønster – ikke en sikker virus",
    # 2.8 (A1, A3)
    "TH_CLAM_3P": "Sanesecurity's lister genkender mailen som phishing, svindel eller en farlig fil",
    "TH_CLAM_3P_TRIAL": "Prøv: Sanesecurity's lister genkender mailen (ingen point endnu)",
    "TH_QR_PHISH": "QR-kode i mailen fører til en kendt phishing- eller malware-side",
    "TH_QR_SUSPICIOUS": "QR-kode i mailen fører til en mistænkelig adresse",
    "TH_SUBJECT_MIXED_SCRIPT": "Emnet blander russiske/græske bogstaver ind i almindelige ord (snydetegn)",
    "TH_SUBJECT_MIXED_SCRIPT_TRIAL": "Prøv: snydetegn i emnet (ingen point endnu)",
    "TH_NEW_DOMAIN": "Afsenderdomænet er registreret for nylig",
    "TH_NEW_DOMAIN_TRIAL": "Prøv: nyregistreret afsenderdomæne (ingen point endnu)",
    "TH_PAY_PHISH": "Emne om betaling eller konto fra en afsender med faretegn",
    "TH_PAY_PHISH_TRIAL": "Prøv: betalings- eller kontophishing (ingen point endnu)",
    "TH_QR_LURE": "QR-kode med mistænkeligt link sammen med et lokkende emne",
    "TH_QR_TRIAL": "Prøv: QR-kode med mistænkeligt link (ingen point endnu)",
    "URLHAUS_MALWARE_URL": "Link til en side, der spreder skadelig software (URLhaus)",
    "PH_SURBL_MULTI": "Linkdomæne på phishingliste (SURBL)",
    "MIME_ENCRYPTED_ARCHIVE": "Krypteret arkiv – indholdet kan ikke undersøges",
    "MIME_BAD_UNICODE": "Filnavn med vildledende tegn",
    "MIME_EXE_IN_GEN_SPLIT_RAR": "Program skjult i et opdelt rar-arkiv",
    # 2.3.6 (B22) lookalike domains
    "TH_LOOKALIKE_DOMAIN": "Efterligner jeres domæne – afsenderdomænet ligner et af jeres egne",
    "TH_LOOKALIKE_URL": "Link til et domæne, der ligner et af jeres egne",
    "TH_LOOKALIKE_ALLOWED": "Ligner et af jeres domæner, men er en kendt afsender – ingen point",
    # 2.7 local AI second opinion (ai_verdict.py)
    "TH_AI_SPAM": "Den lokale AI-vurdering mener, at mailen er spam eller phishing",
    # 2.7 Falske afsendernavne
    "TH_NAME_SPOOF": "Afsendernavnet er en af jeres egne, men adressen er ikke hans/hendes rigtige",
    "TH_NAME_SPOOF_TRIAL": ("Prøv: afsendernavnet er en af jeres egne, men adressen er ikke hans/hendes rigtige "
                            "– ingen point endnu"),
}

# 2.3: the trust symbols our own engine adds (bonuses, never spam reasons).
TRUST_SYMBOLS = ("TH_KNOWN_CONTACT", "TH_KNOWN_DOMAIN", "TH_REPLY", "TH_REPLY_THREAD", "TH_REPLY_UNVERIFIED",
                 "TH_ESTABLISHED")

# 2.3.2: every rule seen in live mail gets a plain Danish text.
SYMBOL_TEXT_EXTRA = {
    # Indhold og opbygning
    "R_SUSPICIOUS_IMAGES": "Mailen er mest billeder med meget lidt tekst – et kendt spam-trick",
    "R_EMPTY_IMAGE": "Mailen består af et billede uden tekst",
    "HIDDEN_TEXT": "Mailen indeholder skjult tekst, som modtageren ikke kan se",
    "R_WHITE_ON_WHITE": "Hvid tekst på hvid baggrund – skjult tekst",
    "HIDDEN_SOURCE_OBJ": "Skjult indhold, der hentes fra et andet sted",
    "MANY_INVISIBLE_PARTS": "Mange usynlige dele i mailen",
    "EXT_CSS": "Henter design fra en ekstern server (sporing mulig)",
    "R_PARTS_DIFFER": "Tekst- og HTML-udgaven af mailen siger noget forskelligt",
    "CTYPE_MIXED_BOGUS": "Mailen påstår at have vedhæftninger, men har ingen",
    "R_BAD_CTE_7BIT": "Forkert tegnkodning af mailen",
    "SINGLE_SHORT_PART": "Mailen består af én meget kort tekst",
    "EMPTY_SUBJECT": "Mailen har intet emne",
    "LONG_SUBJ": "Usædvanligt langt emne",
    "PHISH_EMOTION": "Teksten presser på med følelser eller hast (typisk phishing)",
    "INTRODUCTION": "Mailen præsenterer sig som en ukendt afsender, der 'vil introducere sig'",
    "BITCOIN_ADDR": "Mailen indeholder en Bitcoin-adresse",
    "CRYPTO_ADDR_CHECK": "Mailen indeholder en kryptovaluta-adresse",
    "AUTOGEN_PHP_SPAMMY": "Sendt automatisk fra et webscript på en måde, spam ofte bruger",
    "HAS_PHPMAILER_SIG": "Sendt med PHPMailer (webscript)",
    "HAS_INTERSPIRE_SIG": "Sendt med et masseudsendelsesprogram",
    "X_PHPOS_FAKE": "Falske tekniske oplysninger om afsenderprogrammet",
    "HAS_DATA_URI": "Billeder eller filer er indlejret direkte i mailen",
    "HAS_ATTACHMENT": "Mailen har en vedhæftning",
    "SIGNED_SMIME": "Mailen er digitalt signeret (S/MIME)",
    "PDF_ENCRYPTED": "Vedhæftet PDF er krypteret og kan ikke kontrolleres",
    "PDF_JAVASCRIPT": "Vedhæftet PDF indeholder programkode (JavaScript)",
    "XLSX_SUSPICIOUS": "Vedhæftet Excel-fil ser mistænkelig ud",
    "XLSX_CONTENT": "Vedhæftet Excel-fil (kun information)",
    "XLSX_EXTERNAL_LINKS": "Vedhæftet Excel-fil henter indhold udefra",
    "DOCX_CONTENT": "Vedhæftet Word-fil (kun information)",
    "DOCX_EXTERNAL_LINKS": "Vedhæftet Word-fil henter indhold udefra",
    "OOXML_REMOTE_TEMPLATE": "Vedhæftet Office-fil henter en skabelon udefra (kendt angrebsmetode)",
    "SVG_SUSPICIOUS": "Vedhæftet SVG-billede indeholder mistænkelig kode",
    # Links
    "SUSPICIOUS_URL_IN_SUSPICIOUS_MESSAGE": "Mistænkeligt link i en mail, der i forvejen ser mistænkelig ud",
    "URL_QUERY_MULTIPLE_URLS": "Et link gemmer flere andre links i sig",
    "URL_MULTIPLE_AT_SIGNS": "Link med flere @-tegn – kan skjule den rigtige adresse",
    "URL_USER_PASSWORD": "Link med indbygget brugernavn – kan skjule den rigtige adresse",
    "URI_HIDDEN_PATH": "Link med skjult sti",
    "URL_IN_SUBJECT": "Emnet indeholder et link",
    "URL_VERY_LONG": "Meget langt link",
    "URL_NUMERIC_IP": "Link til en IP-adresse i stedet for et navn",
    "URL_ZERO_WIDTH_SPACES": "Link med usynlige tegn",
    "HTTP_TO_HTTPS": "Link der skifter fra usikker til sikker adresse undervejs",
    "HAS_FILE_URL": "Link til en fil på computeren (file://)",
    "HAS_GOOGLE_REDIR": "Link sendes via Googles videresendelse",
    "REDIRECTOR_URL_ONLY": "Mailen indeholder kun et videresendelses-link",
    "REDIRECTOR_FALSE": "Videresendelses-link (kun information)",
    "HAS_WP_URI": "Link til en WordPress-side",
    "ABUSE_SURBL": "Link til domæne, der er meldt for misbrug",
    "CT_SURBL": "Sporingslink (kun information)",
    "DM_SURBL": "Domæne set i spam (kun information)",
    "RSPAMD_EMAILBL": "Mailadresse i mailen står på en blokeringsliste",
    # Afsender, modtager og svar-adresse
    "MV_CASE": "Mailens tekniske felter er skrevet på en usædvanlig måde",
    "XM_CASE": "Mailens tekniske felter er skrevet på en usædvanlig måde",
    "MISSING_MIMEOLE": "Påstår at komme fra Outlook, men mangler Outlooks kendetegn",
    "MISSING_XM_UA": "Mailprogrammet er ikke oplyst (kun information)",
    "FAKE_REPLY": "Emnet starter med 'Re:', men mailen er ikke et svar",
    "REPLY": "Mailen er et svar",
    "BOUNCE": "Mailen er en returmeddelelse",
    "HEADER_FORGED_MDN": "Forfalsket anmodning om læsekvittering",
    "FROM_EXCESS_BASE64": "Afsendernavnet er unødvendigt kodet – bruges til at skjule tekst",
    "FROM_EXCESS_QP": "Afsendernavnet er unødvendigt kodet – bruges til at skjule tekst",
    "TO_EXCESS_BASE64": "Modtagerfeltet er unødvendigt kodet",
    "TO_EXCESS_QP": "Modtagerfeltet er unødvendigt kodet",
    "REPLYTO_EXCESS_BASE64": "Svar-adressen er unødvendigt kodet",
    "FROM_NAME_EXCESS_SPACE": "Afsendernavnet har mange mellemrum – bruges til at skjule tekst",
    "FROM_NEQ_DISPLAY_NAME": "Afsendernavnet ligner en anden mailadresse end den rigtige",
    "R_NO_SPACE_IN_FROM": "Afsenderfeltet er skrevet forkert",
    "FROM_SERVICE_ACCT": "Afsenderen er en servicekonto (fx noreply)",
    "HAS_ANON_DOMAIN": "Sendt via en anonymiseringstjeneste",
    "SUSPICIOUS_RECIPS": "Mistænkelig liste over modtagere",
    "FORGED_RECIPIENTS_MAILLIST": "Modtageren stemmer ikke – normalt for mailinglister",
    "FORGED_RECIPIENTS_FORWARDING": "Modtageren stemmer ikke – normalt for videresendt post",
    "FORGED_SENDER_FORWARDING": "Afsenderen stemmer ikke – normalt for videresendt post",
    "FORGED_SENDER_MAILLIST": "Afsenderen stemmer ikke – normalt for mailinglister",
    "FORGED_SENDER_VERP_SRS": "Teknisk returadresse fra en mailingliste eller videresendelse",
    "FORGED_MUA_MOZILLA_MAIL_MSGID_UNKNOWN": "Påstår at komme fra Thunderbird, men ser anderledes ud",
    "REPLYTO_LOCALPART_LONG": "Usædvanligt lang svar-adresse",
    "REPLYTO_DOM_NEQ_TO_DOM": "Svar-adressen er på et andet domæne (kun information)",
    "REPLYTO_DOM_EQ_TO_DOM": "Svar-adressen er på dit eget domæne",
    "REPLYTO_DN_EQ_FROM_DN": "Svar-adressen har samme navn som afsenderen",
    "REPLYTO_DOM_EQ_FROM_DOM": "Svar-adressen er på afsenderens domæne",
    "REPLYTO_EQ_FROM": "Svar-adressen er afsenderens egen",
    "TO_DOM_EQ_FROM_DOM": "Afsender og modtager er på samme domæne",
    "TO_EQ_FROM": "Mailen er sendt til afsenderen selv",
    "TO_DN_EQ_ADDR_ALL": "Modtagernavnet er blot mailadressen",
    "TO_DN_EQ_ADDR_SOME": "Nogle modtagernavne er blot mailadressen",
    "TAGGED_FROM": "Afsenderadressen har et +tillæg (kun information)",
    "TAGGED_RCPT": "Modtageradressen har et +tillæg (kun information)",
    "ENVFROM_PRVS": "Signeret returadresse (kun information)",
    "MID_RHS_WWW": "Mailens ID peger på en webadresse – typisk for webscripts",
    "MID_RHS_IP_LITERAL": "Mailens ID indeholder en IP-adresse",
    "MID_RHS_MATCH_FROMTLD": "Mailens ID passer til afsenderens land (kun information)",
    "INVALID_DATE": "Mailen har en ugyldig dato",
    # Omdømme og godkendelse
    "VIOLATED_DIRECT_SPF": "Serveren må ikke sende for afsenderens domæne (direkte SPF-brud)",
    "SPF_FAIL_FORWARDING": "SPF fejler, fordi mailen er videresendt (normalt)",
    "BAD_REP_POLICIES": "Afsenderdomænet har svage eller manglende sikkerhedsregler",
    "SPAM_FLAG": "Din mailudbyder har selv markeret mailen som spam",
    "WHITELIST_SPF_DKIM": "Kendt pålidelig afsender (SPF og DKIM bestået)",
    "WHITELIST_DMARC": "Kendt pålidelig afsender (DMARC bestået)",
    "DWL_DNSWL_HI": "Afsenderdomænet har meget godt omdømme",
    "DWL_DNSWL_MED": "Afsenderdomænet har godt omdømme",
    "DWL_DNSWL_LOW": "Afsenderdomænet har nogenlunde omdømme",
    "DWL_DNSWL_NONE": "Afsenderdomænet er kendt, men uden omdømme",
    "ABUSE_FROM_INJECTOR": "Sendt fra en server, der er meldt for misbrug",
    "SUSPICIOUS_AUTH_ORIGIN": "Logget ind fra et usædvanligt sted (kun information)",
    "LOCAL_OUTBOUND": "Sendt fra jeres eget netværk",
    "DIRECT_TO_MX": "Sendt direkte uden om afsenderens mailserver",
    # Kun information
    "ALIAS_RESOLVED": "Modtager er et alias (kun information)",
    "PREVIOUSLY_DELIVERED": "Allerede leveret til postkassen (kun information)",
    "FORWARDED": "Videresendt mail (kun information)",
    "HAS_X_PRIO_THREE": "Normal prioritet (kun information)",
    "HAS_XOIP": "Afsenderens IP er oplyst (kun information)",
    "HAS_ORG_HEADER": "Organisation er oplyst (kun information)",
    "HAS_CD_HEADER": "Teknisk felt fra afsenderprogrammet (kun information)",
    "HAS_X_POS": "Teknisk felt fra afsenderprogrammet (kun information)",
    "HAS_X_ANTIABUSE": "Afsenderens webhotel har tilføjet misbrugsoplysninger (kun information)",
    "HAS_X_AS": "Teknisk felt fra afsenderens webhotel (kun information)",
    "HAS_X_GMSV": "Teknisk felt fra afsenderens webhotel (kun information)",
    "HAS_X_SOURCE": "Teknisk felt fra afsenderens webhotel (kun information)",
    "HAS_X_PHP_SCRIPT": "Sendt fra et webscript (kun information)",
    "APPLE_IOS_MAILER_COMMON": "Sendt fra iPhone/iPad (kun information)",
    "APPLE_IOS_MAILER": "Sendt fra iPhone/iPad (kun information)",
    "APPLE_MAILER_COMMON": "Sendt fra Apple Mail (kun information)",
    "APPLE_MAILER": "Sendt fra Apple Mail (kun information)",
    "ASN_FAIL": "Afsenderens netværk kunne ikke slås op",
    "RSPAMD_EMAILBL_FAIL": "Blokeringslisten for mailadresser kunne ikke tjekkes",
    "RSPAMD_URIBL_FAIL": "Blokeringslisten for links kunne ikke tjekkes",
}
for _k, _v in SYMBOL_TEXT_EXTRA.items():
    SYMBOL_TEXT.setdefault(_k, _v)

_SYMBOL_PREFIXES: tuple[tuple[str, str], ...] = (
    ("TH_", "Spamfilterets egen vurdering"),
    ("RWL_", "Afsender-IP har godt omdømme"),
    ("RBL_", "Afsender-IP står på en blokeringsliste"),
    ("RECEIVED_", "Et hop på vejen står på en blokeringsliste"),
    ("URIBL", "Link til domæne på blokeringsliste"),
    ("SURBL", "Link til domæne på blokeringsliste"),
    ("DBL_", "Linkdomæne på blokeringsliste"),
    ("SEM_", "Står på en SpamEatingMonkey-liste"),
    ("R_SPF", "SPF-kontrol af afsenderserveren"),
    ("R_DKIM", "DKIM-signatur"),
    ("DKIM", "DKIM-signatur"),
    ("DMARC", "DMARC-kontrol"),
    ("ARC_", "ARC-kæde for videresendt post"),
    ("RCPT_COUNT_", "Antal modtagere"),
    ("RCVD_COUNT_", "Antal servere på vejen"),
    ("RCVD_", "Leveringsvejen"),
    ("MIME_", "Beskedens opbygning"),
    ("HFILTER_", "Afsenderserverens navn ser forkert ud"),
    ("FREEMAIL", "Gratis-mailtjeneste"),
    ("SUBJ", "Emnelinjen"),
    ("HTML_", "HTML-indholdet"),
    ("FUZZY_", "Fingeraftryk fra fællesdatabase"),
    ("BAYES_", "Lært af filteret (Bayes)"),
    ("DWL_", "Afsenderdomænets omdømme"),
    ("URL_", "Et link i mailen ser usædvanligt ud"),
    ("REPLYTO_", "Svar-adressen"),
    ("FROM_", "Afsenderfeltet"),
    ("TO_", "Modtagerfeltet"),
    ("FORGED_", "Afsender eller modtager stemmer ikke med leveringen"),
    ("HAS_X_", "Teknisk felt fra afsenderen (kun information)"),
    ("PDF_", "Vedhæftet PDF"),
    ("XLSX_", "Vedhæftet Excel-fil"),
    ("DOCX_", "Vedhæftet Word-fil"),
    ("OOXML_", "Vedhæftet Office-fil"),
    ("APPLE_", "Sendt fra et Apple-mailprogram (kun information)"),
)


# Plain words for a Bruger: a few calm sentences, no technical names.
PLAIN_BAYES = "Ligner spam, som filteret har set før"
PLAIN_AUTH = "Afsenderen kunne ikke bevise, at mailen er ægte"
PLAIN_HOST = "Sendt fra en server, der er kendt for spam"
PLAIN_LINKS = "Indeholder links til kendte spam- eller svindelsider"
PLAIN_FUZZY = "Samme mail er sendt til mange som spam"
PLAIN_CAPS = "Emnet råber med store bogstaver"
PLAIN_PROVIDER = "Din udbyders eget spamfilter mente også, at det er spam"
PLAIN_SPOOF = "Afsendernavnet foregiver at være en anden"
PLAIN_HIDDEN = "Indeholder skjult tekst"
PLAIN_ATTACH = "Har en mistænkelig vedhæftet fil"
# 2.2 phishing rules
PLAIN_BRAND = "Afsenderen udgiver sig for at være en kendt virksomhed, men er det ikke"
PLAIN_HOMOGLYPH = "Afsendernavnet er skrevet med forklædte bogstaver for at ligne et kendt navn"
PLAIN_LURE = "Emnet lokker med betaling, pakke, konto eller gevinst – typisk for svindel"
PLAIN_LURE_COMBO = "Typisk svindelmail: falsk afsender og et lokkende emne"
PLAIN_SUBJECT_BRAND = "Emnet udgiver sig for at komme fra en kendt virksomhed, men afsenderen er en anden"
PLAIN_TLD = "Sendt fra en type domæne, som spammere ofte bruger"
PLAIN_PHISH = "Indeholder et link til en kendt svindelside"
PLAIN_GOOGLE_RELAY = "Ukendt Gmail-afsender sendt gennem en Google-tjeneste, som svindlere misbruger"
PLAIN_LOOKALIKE = "Afsenderens domæne efterligner et af jeres egne"
PLAIN_LOOKALIKE_URL = "Indeholder et link til et domæne, der efterligner et af jeres egne"
# 2.3
PLAIN_VIRUS = "Indeholder virus"
PLAIN_CLAM_HEURISTIC = "Antivirus fandt noget mistænkeligt i en vedhæftning"
PLAIN_DANGER_ATTACH = "Har en farlig vedhæftet fil"
PLAIN_ENCRYPTED = "Har et krypteret arkiv, som filteret ikke kan kigge i"
PLAIN_MALWARE = "Indeholder et link til en side, der spreder skadelig software"
PLAIN_AI = "Filterets egen AI-vurdering mener, at mailen ligner spam"
PLAIN_FIRST = "Første mail fra denne afsender"
# 2.7
PLAIN_NAME_SPOOF = "Udgiver sig for at være en af jeres egne, men kommer fra en fremmed adresse"

_PLAIN_EXACT: dict[str, str] = {
    "BAYES_SPAM": PLAIN_BAYES, "NEURAL_SPAM": PLAIN_BAYES,
    "FUZZY_DENIED": PLAIN_FUZZY, "FUZZY_PROB": PLAIN_FUZZY,
    "SUBJ_ALL_CAPS": PLAIN_CAPS,
    "TH_PROVIDER_SPAM": PLAIN_PROVIDER, "TH_PROVIDER_SCORE": PLAIN_PROVIDER,
    "SPOOF_DISPLAY_NAME": PLAIN_SPOOF,
    "FORGED_SENDER": PLAIN_AUTH, "AUTH_NA": PLAIN_AUTH, "AUTH_NA_OR_FAIL": PLAIN_AUTH,
    "TH_FORCE_UNVERIFIED": PLAIN_AUTH, "ARC_REJECT": PLAIN_AUTH,
    "ZERO_FONT": PLAIN_HIDDEN, "MANY_INVISIBLE_PARTS": PLAIN_HIDDEN, "HIDDEN_TEXT": PLAIN_HIDDEN,
    "MIME_BAD_ATTACHMENT": PLAIN_ATTACH, "MIME_BAD_EXTENSION": PLAIN_ATTACH,
    "MIME_DOUBLE_BAD_EXTENSION": PLAIN_ATTACH, "MIME_ARCHIVE_IN_ARCHIVE": PLAIN_ATTACH,
    "PHISHING": PLAIN_LINKS, "R_SUSPICIOUS_URL": PLAIN_LINKS, "OMOGRAPH_URL": PLAIN_LINKS,
    # 2.2
    "TH_BRAND_SPOOF": PLAIN_BRAND, "TH_FROM_NAME_HOMOGLYPH": PLAIN_HOMOGLYPH,
    "TH_LURE_SUBJECT": PLAIN_LURE, "TH_LURE_COMBO": PLAIN_LURE_COMBO,
    "TH_SUBJECT_BRAND_SPOOF": PLAIN_SUBJECT_BRAND, "TH_PHISHARMY_URL": PLAIN_PHISH,
    "TH_FREEMAIL_VIA_GOOGLE": PLAIN_GOOGLE_RELAY,
    "TH_FROM_ABUSED_TLD": PLAIN_TLD, "TH_FROM_TLD_CN_RU": PLAIN_TLD,
    "TH_PROVIDER_AUTH_FAIL": PLAIN_AUTH, "TH_PROVIDER_AUTH_SPOOF": PLAIN_AUTH,
    "TH_AGED_UNVERIFIED": PLAIN_AUTH, "DBL_PHISH": PLAIN_PHISH,
    # 2.3
    "CLAM_VIRUS": PLAIN_VIRUS, "CLAM_PHISH": PLAIN_PHISH, "PH_SURBL_MULTI": PLAIN_PHISH,
    "TH_CLAM_HEURISTIC": PLAIN_CLAM_HEURISTIC,
    "TH_ATTACH_BLOCK": PLAIN_DANGER_ATTACH, "MIME_EXE_IN_GEN_SPLIT_RAR": PLAIN_DANGER_ATTACH,
    "TH_ENCRYPTED_ARCHIVE": PLAIN_ENCRYPTED, "MIME_ENCRYPTED_ARCHIVE": PLAIN_ENCRYPTED,
    "URLHAUS_MALWARE_URL": PLAIN_MALWARE, "DBL_MALWARE": PLAIN_MALWARE,
    "TH_FIRST_CONTACT": PLAIN_FIRST,
    "TH_LOOKALIKE_DOMAIN": PLAIN_LOOKALIKE, "TH_LOOKALIKE_URL": PLAIN_LOOKALIKE_URL,
    "TH_AI_SPAM": PLAIN_AI,
    "TH_NAME_SPOOF": PLAIN_NAME_SPOOF,
}
_PLAIN_AUTH_FAIL = ("R_SPF_FAIL", "R_SPF_SOFTFAIL", "R_SPF_PERMFAIL", "R_DKIM_REJECT",
                    "R_DKIM_PERMFAIL", "DMARC_POLICY_REJECT", "DMARC_POLICY_QUARANTINE",
                    "DMARC_POLICY_SOFTFAIL", "DMARC_BAD_POLICY")


def plain_reason(name: str) -> str | None:
    """A Bruger's wording for a spam-pointing rspamd symbol, or None when
    the symbol is too technical to be worth mentioning."""
    key = str(name or "").strip().upper()
    if key in _PLAIN_EXACT:
        return _PLAIN_EXACT[key]
    if key in _PLAIN_AUTH_FAIL:
        return PLAIN_AUTH
    if key.startswith("PHISHED_") and key not in ("PHISHED_EXCLUDED", "PHISHED_GENERIC_SERVICE"):
        return PLAIN_PHISH
    if key.startswith(("URIBL", "SURBL", "DBL_", "SEM_URIBL", "MSBL_")):
        return PLAIN_LINKS
    if (key.startswith(("RBL_", "RECEIVED_SPAMHAUS", "RECEIVED_BLOCKLIST", "RECEIVED_MAILSPIKE"))
            or "_RBL" in key):
        return PLAIN_HOST
    return None


def explain_symbol(name: str) -> str:
    """Danish explanation for an rspamd symbol, with prefix fallbacks."""
    key = str(name or "").strip().upper()
    if key in SYMBOL_TEXT:
        return SYMBOL_TEXT[key]
    for prefix, text in _SYMBOL_PREFIXES:
        if key.startswith(prefix):
            return text
    if "_RBL" in key or key.endswith("_BL"):
        return "Står på en blokeringsliste"
    return "Teknisk kontrol i spam-motoren (ingen nærmere forklaring)"


# 2.2: texts that name the brand / domain a rule saw. TH_BRAND_SPOOF is an
# rspamd composite (no options): the brand comes from TH_FROM_BRAND_NAME's
# option (the decoded display name) or the From header, the domain from
# the sender address.
_NAME_MAX = 40
_AGE_RE = re.compile(r"alder=(\d+)t")


def _short(text: Any, limit: int = _NAME_MAX) -> str:
    t = " ".join(str(text or "").replace('"', " ").split())
    return t if len(t) <= limit else t[: limit - 1].rstrip() + "…"


def _sym_map(symbols: Any) -> dict[str, dict]:
    if isinstance(symbols, dict):
        return symbols
    return {s["n"].upper(): s for s in parse_symbols(symbols)} if symbols else {}


def _first_opt(sym: dict | None) -> str:
    opts = (sym or {}).get("o") or []
    return str(opts[0]).strip() if opts else ""


def spoofed_brand(symbols: Any = None, sender: Any = None) -> str:
    """The display name a brand rule matched ('' when unknown)."""
    syms = _sym_map(symbols)
    for n in ("TH_FROM_BRAND_NAME", "TH_FROM_NAME_HOMOGLYPH"):
        opt = _first_opt(syms.get(n))
        if opt:
            return _short(opt)
    return _short(sender_parts(sender)[0]) if sender else ""


def _from_domain(sym: dict | None, sender: Any) -> str:
    opt = _first_opt(sym).lower().rstrip(".")
    if "@" in opt:
        opt = opt.rsplit("@", 1)[1]
    return opt or sender_domain(sender)


def explain_symbol_detail(sym: dict, *, symbols: Any = None, sender: Any = None, ai_reason: bool = False) -> str:
    """explain_symbol() with the brand, domain or age the rule saw filled in,
    e.g. 'Afsendernavnet udgiver sig for at være PostNord, men mailen kommer
    fra goteamup.com'. Falls back to the generic text. ai_reason=True
    (administrators only): TH_AI_SPAM shows the model's cleaned reason;
    otherwise a fixed text."""
    name = str((sym or {}).get("n") or "").strip().upper()
    opts = [str(o) for o in ((sym or {}).get("o") or []) if str(o).strip()]
    if name == "TH_BRAND_SPOOF":
        brand, dom = spoofed_brand(symbols, sender), sender_domain(sender)
        if brand and dom:
            return f"Afsendernavnet udgiver sig for at være {brand}, men mailen kommer fra {dom}"
        if brand:
            return f"Afsendernavnet udgiver sig for at være {brand}, men mailen kommer fra et andet domæne"
    elif name == "TH_SUBJECT_BRAND_SPOOF":
        dom = _short(sender_domain(sender), 60) if sender else ""
        if dom:
            return ("Emnet udgiver sig for at komme fra et kendt brand og lokker med betaling, konto eller pakke, "
                    f"men mailen kommer fra {dom}")
    elif name == "TH_PHISHARMY_URL" and opts and clean_name(opts[0]):
        return f"Link til {_short(clean_name(opts[0]), 60)}, som står på en liste over phishing-sider (Phishing Army)"
    elif name == "TH_FROM_NAME_HOMOGLYPH" and opts:
        return (f"Afsendernavnet “{_short(opts[0])}” bruger forvekslelige bogstaver fra et andet alfabet "
                "(fx græske eller kyrilliske)")
    elif name in ("TH_FROM_ABUSED_TLD", "TH_FROM_TLD_CN_RU"):
        dom = _from_domain(sym, sender)
        tld = dom.rsplit(".", 1)[-1] if "." in dom else ""
        if dom and tld:
            if name == "TH_FROM_TLD_CN_RU":
                return f"Afsenderdomænet {dom} ender på .{tld}"
            return f"Afsenderdomænet {dom} bruger topdomænet .{tld}, som spammere ofte misbruger"
    elif name == "TH_OWN_PLATFORM_URIBL" and opts:
        return (f"Jeres egen webshop-platform ({', '.join(_short(o, 60) for o in opts[:3])}) står fejlagtigt "
                "på en domæneliste – udlignet")
    elif name == "TH_AGED_SCAN":
        m = _AGE_RE.search(" ".join(opts))
        if m:
            hours = int(m.group(1))
            when = (f"{hours} timer" if hours < 48 else f"{hours // 24} dage")
            return (f"Scannet sent ({when} efter modtagelsen) – afsenderens SPF/DMARC er erstattet af "
                    "udbyderens vurdering ved modtagelsen")
    elif name in ("TH_ATTACH_BLOCK", "TH_ENCRYPTED_ARCHIVE", "TH_ATTACH_ALLOWED") and opts:
        fname = short_filename(opts[0])
        if fname:
            return {"TH_ATTACH_BLOCK": f"Farlig vedhæftning: {fname}",
                    "TH_ENCRYPTED_ARCHIVE": f"Krypteret arkiv fra ukendt afsender: {fname} – kan ikke undersøges",
                    "TH_ATTACH_ALLOWED": f"Farlig vedhæftning ({fname}) tilladt for afsenderen"}[name]
    elif name in ("TH_KNOWN_CONTACT", "TH_REPLY", "TH_REPLY_THREAD", "TH_ESTABLISHED", "TH_KNOWN_DOMAIN"):
        text = trust_symbol_text(name, opts)
        if text:
            return text
    elif name in ("TH_LOOKALIKE_DOMAIN", "TH_LOOKALIKE_URL", "TH_LOOKALIKE_ALLOWED") and len(opts) >= 2:
        text = lookalike_text(name, opts)
        if text:
            return text
    elif name in ("TH_CLAM_HEURISTIC", "CLAM_VIRUS") and opts:
        # 2.7 fix: a heuristic / third-party ClamAV signature is no virus verdict.
        heuristic = name == "TH_CLAM_HEURISTIC" or any(
            isinstance(x, dict) and x.get("n") == "TH_CLAM_HEURISTIC" for x in (symbols or []))
        sig = _short(clean_name(opts[0]), 80)
        if heuristic and sig:
            return f"Antivirus (ClamAV) fandt et mistænkeligt mønster ({sig}) – ikke en sikker virus"
    elif name == "TH_AI_SPAM" and opts:
        try:
            import ai_verdict  # noqa: PLC0415 - 2.7: the model's reason, cleaned (callers escape)

            return ai_verdict.symbol_text(opts, reason=ai_reason)
        except Exception:  # noqa: BLE001
            pass
    elif name in ("TH_NAME_SPOOF", "TH_NAME_SPOOF_TRIAL") and opts:
        text = name_spoof_text(name, opts)
        if text:
            return text
    elif name.startswith(("TH_SUBJECT_MIXED_SCRIPT", "TH_NEW_DOMAIN", "TH_PAY_PHISH")) and opts:
        text = phish_signal_text(name, opts)
        if text:
            return text
    return explain_symbol(name)


def phish_signal_text(name: str, opts: list[str]) -> str:
    """2.13 (phishsignals.py) with what the rule saw. A *_TRIAL symbol's first
    option is the points it would give ('+5')."""
    pre = ""
    if name.endswith("_TRIAL"):
        pts, opts = (opts[0], opts[1:]) if opts and opts[0].startswith("+") else ("", opts)
        pre = f"Prøv (ville give {pts.lstrip('+').replace('.', ',')} point): " if pts else "Prøv: "
        name = name[:-len("_TRIAL")]
    vals = [_short(clean_name(o), 60) for o in opts if clean_name(o)]
    if name == "TH_SUBJECT_MIXED_SCRIPT" and vals:
        import unicodedata  # noqa: PLC0415

        odd = sorted({c for c in vals[0] if unicodedata.name(c, "").startswith(("CYRILLIC", "GREEK"))})
        which = f" ({', '.join(odd[:6])})" if odd else ""
        return (pre + f"Emnet indeholder “{vals[0]}”, hvor nogle bogstaver{which} er russiske eller græske, så ordet "
                "kun ligner dansk eller engelsk – et kendt trick for at snyde spamfiltre")
    if name == "TH_NEW_DOMAIN" and len(vals) >= 2:
        return pre + f"Afsenderdomænet {vals[0]} blev registreret for {vals[1]} siden (ifølge domæneregistret)"
    if name == "TH_PAY_PHISH" and vals:
        return (pre + "Emnet handler om betaling, konto, abonnement, domæne eller MitID, og afsenderen har "
                f"faretegn: {', '.join(vals)}")
    return ""


# 2.7: what made a name-spoof hit stronger (third option of TH_NAME_SPOOF*).
NAME_SPOOF_FLAG_TEXT = {"svar-til": "svar går til en anden adresse",
                        "emne": "emnet ligner direktørsvindel (gavekort, hast eller fortrolighed om en betaling)",
                        "adresse-i-navnet": "en af jeres adresser står i afsendernavnet",
                        "ugyldig-afsender": "afsenderfeltet er ugyldigt eller har flere adresser"}
# 2.7 fix: what kept a hit lower (also in the third option).
NAME_SPOOF_CAP_TEXT = {"signeret": "afsenderdomænet har en gyldig signatur, så højst 5 point",
                       "platform": "en besked fra en platform i personens navn, så kun 2 point"}


def name_spoof_text(name: str, opts: list[str]) -> str:
    """'Afsendernavnet er en af jeres egne (Ole Storm), men adressen er ikke
    hans/hendes rigtige – og svar går til en anden adresse'. Callers escape."""
    who = _short(clean_name(opts[0]), 60)
    if not who:
        return ""
    raw_flags = (opts[2] if len(opts) > 2 else "").split("+")
    flags = [NAME_SPOOF_FLAG_TEXT[f] for f in raw_flags if f in NAME_SPOOF_FLAG_TEXT]
    caps = [NAME_SPOOF_CAP_TEXT[f] for f in raw_flags if f in NAME_SPOOF_CAP_TEXT]
    text = f"Afsendernavnet er en af jeres egne ({who}), men adressen er ikke hans/hendes rigtige"
    if flags:
        text += " – og " + " og ".join(flags)
    if caps:
        text += f" ({caps[0]})"
    if name == "TH_NAME_SPOOF_TRIAL":
        text = "Prøv: " + text[0].lower() + text[1:] + " (ingen point endnu)"
    return text


# B22: where a lookalike was found (third option of TH_LOOKALIKE_*).
LOOKALIKE_FIELD_TEXT = {"from": "afsenderen", "reply_to": "svar-til-adressen", "envelope": "konvolut-afsenderen",
                        "dkim": "DKIM-signaturen", "url": "et link"}
LOOKALIKE_EXEMPT_TEXT = {"allowed": "markeret som ikke en efterligning", "ham_history": "kendt afsender",
                         "contact": "kendt kontakt", "signed": "underskrevet af jeres eget domæne",
                         "provider": "jeres egen mail via mailudbyderen"}


def lookalike_text(name: str, opts: list[str]) -> str:
    """'Efterligner jeres domæne: pinslkbing.example ligner pinsikbing.example (afsenderen)'.
    The lookalike is attacker-chosen: cleaned and shortened (callers escape)."""
    look, prot = _short(clean_name(opts[0]), 60), _short(clean_name(opts[1]), 60)
    if not look or not prot:
        return ""
    third = opts[2] if len(opts) > 2 else ""
    if name == "TH_LOOKALIKE_ALLOWED":
        why = LOOKALIKE_EXEMPT_TEXT.get(third, "undtaget")
        return f"{look} ligner {prot}, men tæller ikke ({why})"
    where = LOOKALIKE_FIELD_TEXT.get(third, "")
    if name == "TH_LOOKALIKE_URL":
        return f"Link til {look}, der ligner jeres domæne {prot}"
    return f"Efterligner jeres domæne: {look} ligner {prot}" + (f" ({where})" if where else "")


# 2.3: attacker-controlled names (attachment file names, virus signatures)
# are shown without bidi/zero-width/control characters (RTLO tricks like
# "fakturaexe.pdf") and shortened in the MIDDLE so the real extension stays
# visible. Callers still escape with h().
_INVISIBLE_RE = re.compile("[\u0000-\u001f\u007f-\u009f­؜᠎​-‏‪-‮"
                           "⁠-⁩﻿￹-￻]")


def clean_name(text: Any) -> str:
    """Visible characters only, whitespace collapsed."""
    return " ".join(_INVISIBLE_RE.sub("", str(text or "")).split())


def short_filename(name: Any, limit: int = 48) -> str:
    """'meget-lang-faktura…2026.pdf.exe': keep the start and the last 14
    characters (the extension) when the name is too long."""
    t = clean_name(name)
    if len(t) <= limit:
        return t
    tail = 14
    return t[: max(4, limit - tail - 1)].rstrip() + "…" + t[-tail:]


def _opt_val(opts: Iterable[Any], prefix: str) -> str:
    for o in opts or ():
        s = str(o)
        if s.startswith(prefix):
            return s[len(prefix):]
    return ""


def _day_month(iso: str) -> str:
    """'2026-10-12' -> '12. okt.' (year added when not this year)."""
    try:
        d = datetime.strptime(str(iso)[:10], "%Y-%m-%d")
    except ValueError:
        return ""
    text = f"{d.day}. {DA_MONTHS[d.month - 1]}"
    return text if d.year == _now_dt().year else f"{text} {d.year}"


def _times(n: int) -> str:
    return f"{fmt_int(n)} {'gang' if n == 1 else 'gange'}"


def trust_symbol_text(name: str, opts: Iterable[Any]) -> str:
    """Danish text for a 2.3 trust symbol with the numbers its options
    carry (administrators' symbol table). '' when nothing to add."""
    opts = [str(o) for o in (opts or [])]
    capped = " (begrænset af loftet på −6)" if any(o.startswith("loft") for o in opts) else ""
    if name == "TH_KNOWN_CONTACT":
        try:
            n = int(_opt_val(opts, "sendt=") or 0)
        except ValueError:
            n = 0
        if "gruppe" in opts:
            return "Kendt kontakt – en kollega har skrevet til afsenderen" + capped
        who = "du"
        if n > 0:
            last = _opt_val(opts, "senest=")
            when = ""
            if last:
                try:
                    d = datetime.strptime(last[:7], "%Y-%m")
                    when = f", senest {DA_MONTHS_LONG[d.month - 1]} {d.year}"
                except ValueError:
                    when = ""
            return f"Kendt kontakt – {who} har skrevet til afsenderen {_times(n)}{when}{capped}"
        return SYMBOL_TEXT["TH_KNOWN_CONTACT"] + capped
    if name in ("TH_REPLY", "TH_REPLY_THREAD"):
        day = _day_month(_opt_val(opts, "sendt="))
        base = f"Svar på din mail fra {day}" if day else SYMBOL_TEXT[name]
        if name == "TH_REPLY_THREAD" and day:
            base += " (ny deltager i tråden)"
        return base + capped
    if name == "TH_ESTABLISHED":
        n, since = _opt_val(opts, "n="), _opt_val(opts, "siden=")
        if n and since:
            return f"Fast afsender – {n} mails siden {since}{capped}"
        return SYMBOL_TEXT[name] + capped
    if name == "TH_KNOWN_DOMAIN":
        return SYMBOL_TEXT[name] + capped
    return ""


DA_MONTHS_LONG = ("januar", "februar", "marts", "april", "maj", "juni", "juli", "august", "september",
                  "oktober", "november", "december")

# B13 label tones from services.trust_labels() -> badge tones.
TRUST_TONES = {"green": "ok", "blue": "info", "amber": "warn", "grey": "neutral", "red": "bad"}
TRUST_ICONS = {"known_contact": "user-check", "reply": "reply", "established": "shield-check",
               "first_contact": "sparkles", "reply_unverified": "alert-circle", "distrusted": "user-x"}
# Compact chip texts for mail lists (the full label is the title).
TRUST_SHORT = {"known_contact": "Kendt kontakt", "reply": "Svar på din mail", "established": "Fast afsender",
               "first_contact": "Ny afsender", "reply_unverified": "Ubekræftet svar",
               "distrusted": "Ikke længere betroet"}


def trust_badge(label: dict, *, compact: bool = False) -> str:
    """One B13 label ({kind, tone, text}) as a colour-coded badge."""
    kind = str(label.get("kind") or "")
    tone = TRUST_TONES.get(str(label.get("tone") or ""), "neutral")
    text = str(label.get("text") or "")
    if label.get("symbol") == "TH_KNOWN_DOMAIN" and compact:
        short = "Kendt organisation"
    else:
        short = TRUST_SHORT.get(kind, text) if compact else text
    ic = TRUST_ICONS.get(kind, "info")
    title = f' title="{h(text)}"' if compact and short != text else ""
    return (f'<span class="badge trust-badge tone-{tone}{" is-compact" if compact else ""}"{title}>'
            f'{_icon(ic)}<span>{h(short)}</span></span>')


def threat_badge(text: Any, *, compact: bool = False, limit: int = 60) -> str:
    """Red 'Virus: X' / 'Phishing-link' / 'Farlig vedhæftning: f.exe' badge.
    The text comes from services.threat_text() and may hold an attacker's
    file name: cleaned, shortened in the middle and escaped here."""
    raw = clean_name(text)
    if not raw:
        return ""
    label, sep, detail = raw.partition(": ")
    # Lists: only the class ('Virus', 'Farlig vedhæftning'); the name is in
    # the tooltip and on the message detail.
    # A dangerous attachment keeps a short file name (the real extension).
    if compact:
        shown = f"{label}: {short_filename(detail, 20)}" if sep and label == "Farlig vedhæftning" else label
    else:
        shown = f"{label}: {short_filename(detail, limit)}" if sep else raw
    title = f' title="{h(raw[:300])}"' if shown != raw else ""
    return (f'<span class="badge threat-badge tone-bad{" is-compact" if compact else ""}"{title}>'
            f'{_icon("alert-triangle")}<span>{h(shown)}</span></span>')


def plain_reason_detail(sym: dict, *, symbols: Any = None, sender: Any = None) -> str | None:
    """plain_reason() for a Bruger, naming the brand a fake sender pretends to be."""
    name = str((sym or {}).get("n") or "").strip().upper()
    if name == "TH_BRAND_SPOOF":
        brand = spoofed_brand(symbols, sender)
        if brand:
            return f"Afsenderen udgiver sig for at være {brand}, men er det ikke"
    elif name == "TH_ATTACH_BLOCK":
        opts = (sym or {}).get("o") or []
        fname = short_filename(opts[0]) if opts else ""
        if fname:
            return f"Har en farlig vedhæftet fil: {fname}"
    return plain_reason(name)


# ---------------------------------------------------------------------------
# Basics
# ---------------------------------------------------------------------------


def h(text: Any) -> str:
    """HTML-escape. None renders as ''. Markup passes through untouched.
    Mail-derived values (subject, sender, Message-ID) are attacker
    controlled: every interpolation of them must go through here."""
    return str(escape("" if text is None else text))


def _tone(tone: str | None, default: str = "neutral") -> str:
    return tone if tone in TONES else default


def icon(name: str, cls: str = "") -> str:
    """Icon from the static sprite. Decorative: hidden from screen readers."""
    safe = re.sub(r"[^a-z0-9-]", "", str(name).lower()) or "info"
    return (f'<svg class="icon{(" " + h(cls)) if cls else ""}" aria-hidden="true" '
            f'focusable="false"><use href="{_sprite()}#i-{safe}"></use></svg>')


def _sprite() -> str:
    try:
        import dashboard as ui

        return ui.static_url("icons.svg")
    except Exception:  # noqa: BLE001 - rendering must not die on a lookup
        return "/static/icons.svg"


def pct(value: float | int | None, maximum: float | int | None) -> int:
    try:
        v, m = float(value or 0), float(maximum or 0)
    except (TypeError, ValueError):
        return 0
    if m <= 0:
        return 0
    return int(max(0, min(100, round(v / m * 100))))


def pct_class(value: float | int | None, maximum: float | int | None) -> str:
    """Width class p-0..p-100 (CSS custom property, no inline style)."""
    return f"p-{pct(value, maximum)}"


def fmt_int(n: Any) -> str:
    """Danish thousands separator: 12.345."""
    try:
        return f"{int(n):,}".replace(",", ".")
    except (TypeError, ValueError):
        return "–"


def fmt_num(x: Any, digits: int = 1) -> str:
    try:
        f = float(x)
    except (TypeError, ValueError):
        return "–"
    s = f"{abs(f):,.{digits}f}".replace(",", "\x00").replace(".", ",").replace("\x00", ".")
    return ("−" if f < 0 and round(abs(f), digits) != 0 else "") + s


def fmt_score(s: Any) -> str:
    """Score with Danish decimal comma and a real minus sign."""
    if s is None or s == "":
        return "–"
    return fmt_num(s, 1)


def fmt_pct(part: Any, whole: Any) -> str:
    try:
        p, w = float(part or 0), float(whole or 0)
    except (TypeError, ValueError):
        return "–"
    if w <= 0:
        return "–"
    v = p / w * 100
    return (fmt_num(v, 1) if v < 10 else fmt_num(v, 0)) + " %"


def _dt(ts: Any) -> datetime | None:
    try:
        t = int(ts)
    except (TypeError, ValueError):
        return None
    if t <= 0:
        return None
    return datetime.fromtimestamp(t, TZ) if TZ else datetime.fromtimestamp(t)


def _now_dt() -> datetime:
    return datetime.now(TZ) if TZ else datetime.now()


def today_str(offset_days: int = 0) -> str:
    """'YYYY-MM-DD' in Europe/Copenhagen (stats_daily.day)."""
    t = time.time() - offset_days * 86400
    d = datetime.fromtimestamp(t, TZ) if TZ else datetime.fromtimestamp(t)
    return d.strftime("%Y-%m-%d")


def fmt_ts(ts: Any) -> str:
    """'i dag 14:32', 'i går 09:10', '18. okt. 14:32', '3. jan. 2025'."""
    d = _dt(ts)
    if d is None:
        return "–"
    now = _now_dt()
    hm = d.strftime("%H:%M")
    delta_days = (now.date() - d.date()).days
    if delta_days == 0:
        return f"i dag {hm}"
    if delta_days == 1:
        return f"i går {hm}"
    if d.year == now.year:
        return f"{d.day}. {DA_MONTHS[d.month - 1]} {hm}"
    return f"{d.day}. {DA_MONTHS[d.month - 1]} {d.year}"


def fmt_date(ts: Any) -> str:
    d = _dt(ts)
    if d is None:
        return "–"
    return f"{d.day}. {DA_MONTHS[d.month - 1]} {d.year}"


def iso_ts(ts: Any) -> str:
    d = _dt(ts)
    return d.isoformat() if d else ""


def ago(ts: Any) -> str:
    """Relative Danish time: 'lige nu', 'for 5 min. siden', 'for 2 t. siden'."""
    try:
        t = int(ts)
    except (TypeError, ValueError):
        return "aldrig"
    if t <= 0:
        return "aldrig"
    delta = int(time.time()) - t
    if delta < -60:
        return "om lidt"
    if delta < 60:
        return "lige nu"
    if delta < 3600:
        return f"for {delta // 60} min. siden"
    if delta < 86400:
        return f"for {delta // 3600} t. siden"
    days = delta // 86400
    if days < 45:
        return f"for {days} dag{'e' if days != 1 else ''} siden"
    return fmt_date(t)


def mode_label(mode: str | None) -> str:
    return MODE_LABELS.get(str(mode or ""), str(mode or "–"))


def state_label(state: str | None) -> str:
    return STATE_LABELS.get(str(state or "unknown"), str(state or "Ukendt"))


def state_tone(state: str | None) -> str:
    return STATE_TONES.get(str(state or "unknown"), "neutral")


def action_label(action: str | None) -> str:
    return ACTION_LABELS.get(action, (str(action), "neutral"))[0]


def action_tone(action: str | None) -> str:
    return ACTION_LABELS.get(action, ("", "neutral"))[1]


def sensitivity_label(threshold: Any) -> str:
    """Owner-facing name for a threshold: Streng ≤6 / Normal 6–9 / Lempelig ≥9."""
    try:
        t = float(threshold)
    except (TypeError, ValueError):
        return "–"
    if t <= 6:
        return "Streng"
    if t >= 9:
        return "Lempelig"
    return "Normal"


def sender_parts(sender: Any) -> tuple[str, str]:
    """('Display name', 'addr@example.dk') from a From header value."""
    raw = str(sender or "").strip()
    name, addr = parseaddr(raw)
    name = name.strip().strip('"')
    addr = addr.strip()
    if not addr and "@" in raw:
        addr = raw
    return name, addr


def sender_domain(sender: Any) -> str:
    addr = sender_parts(sender)[1]
    return addr.rsplit("@", 1)[1].lower() if "@" in addr else ""


def token_for(message_id: str) -> str:
    """URL-safe token for a Message-ID (detail page URLs)."""
    return base64.urlsafe_b64encode(str(message_id).encode("utf-8")).decode("ascii").rstrip("=")


def msgid_from_token(token: str) -> str | None:
    if not token or len(token) > 1400 or not re.fullmatch(r"[A-Za-z0-9_-]+", token):
        return None
    try:
        return base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


def parse_symbols(raw: Any) -> list[dict]:
    """messages.symbols JSON -> list of {'n','s','o'} (tolerant)."""
    if not raw:
        return []
    try:
        data = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
    except (TypeError, ValueError):
        return []
    out = []
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict) or not item.get("n"):
            continue
        try:
            score = float(item.get("s") or 0)
        except (TypeError, ValueError):
            score = 0.0
        opts = item.get("o") or []
        out.append({"n": str(item["n"]), "s": score,
                    "o": [str(o) for o in opts][:3] if isinstance(opts, list) else []})
    return out


def top_reasons(raw_symbols: Any, n: int = 3) -> list[dict]:
    """Strongest positive contributors (what made it spammy)."""
    syms = [s for s in parse_symbols(raw_symbols) if s["s"] >= 0.5]
    syms.sort(key=lambda s: s["s"], reverse=True)
    return syms[:n]


# ---------------------------------------------------------------------------
# Components
# ---------------------------------------------------------------------------


def card(body: str, *, title: str = "", subtitle: str = "", actions: str = "",
         cls: str = "") -> str:
    head = ""
    if title or subtitle or actions:
        head = (
            '<div class="card-head"><div class="card-titles">'
            + (f'<h2 class="card-title">{h(title)}</h2>' if title else "")
            + (f'<p class="card-sub">{h(subtitle)}</p>' if subtitle else "")
            + "</div>"
            + (f'<div class="card-actions">{actions}</div>' if actions else "")
            + "</div>"
        )
    return f'<section class="card{(" " + h(cls)) if cls else ""}">{head}{body}</section>'


def kpi(label: str, value: Any, *, sub: str = "", trend: float | None = None,
        tone: str = "", href: str = "") -> str:
    """Key figure tile. With href the whole tile is a link."""
    if isinstance(value, bool):
        shown = h(value)
    elif isinstance(value, int):
        shown = fmt_int(value)
    elif isinstance(value, float):
        shown = fmt_num(value, 1)
    else:
        shown = h(value)
    trend_html = ""
    if trend is not None:
        try:
            t = float(trend)
            arrow = "trend-up" if t > 0 else "trend-down" if t < 0 else "trend-flat"
            trend_html = (f'<span class="kpi-trend {arrow}">'
                          f'{icon("arrow-up-right" if t >= 0 else "arrow-down-right")}'
                          f'{fmt_num(abs(t), 0)} %</span>')
        except (TypeError, ValueError):
            trend_html = ""
    tone_cls = f" tone-{_tone(tone)}" if tone else ""
    tag, attr = ("a", f' href="{h(href)}"') if href else ("div", "")
    return (f'<{tag} class="kpi{tone_cls}{" kpi-link" if href else ""}"{attr}><div class="kpi-label">{h(label)}'
            + (_icon("arrow-right", "kpi-go") if href else "") + '</div>'
            f'<div class="kpi-value">{shown}{trend_html}</div>'
            + (f'<div class="kpi-sub">{h(sub)}</div>' if sub else "")
            + f"</{tag}>")


def badge(text: Any, tone: str = "neutral") -> str:
    return f'<span class="badge tone-{_tone(tone)}">{h(text)}</span>'


def chip(text: Any, tone: str = "neutral") -> str:
    return f'<span class="chip tone-{_tone(tone)}">{h(text)}</span>'


def status_dot(state: str | None) -> str:
    """Coloured dot for an account state (or a raw tone name)."""
    st = str(state or "unknown")
    tone = st if st in TONES else state_tone(st)
    label = state_label(st) if st not in TONES else st
    pulse = " dot-pulse" if st in ("idle", "working", "connecting", "starting") else ""
    return (f'<span class="dot tone-{tone}{pulse}" role="img" '
            f'aria-label="{h(label)}" title="{h(label)}"></span>')


def score_tone(score: Any, threshold: Any) -> str:
    try:
        s, t = float(score), float(threshold)
    except (TypeError, ValueError):
        return "neutral"
    if s >= t:
        return "bad"
    if s >= t - 3:
        return "warn"
    if s < 0:
        return "ok"
    return "neutral"


def score_badge(score: Any, threshold: Any) -> str:
    """Score pill coloured relative to the account's threshold."""
    if score is None:
        return '<span class="score tone-neutral" title="Ikke scoret">–</span>'
    tone = score_tone(score, threshold)
    tip = f"Score {fmt_score(score)} · grænse {fmt_score(threshold)}"
    return f'<span class="score tone-{tone}" title="{h(tip)}">{fmt_score(score)}</span>'


def button(label: str, *, href: str | None = None, kind: str = "primary",
           icon: str | None = None, attrs: str = "", size: str = "", cls: str = "",
           tone: str = "", short: str = "") -> str:
    """Button or link-button. kind: primary|secondary|ghost|danger;
    size: ''|sm|lg; cls: extra classes (do not put class= in attrs).
    tone: ok|warn|bad|info|neutral|brand gives a colour-coded (tinted)
    button; short: shorter label shown on narrow screens instead of label."""
    kind = kind if kind in ("primary", "secondary", "ghost", "danger") else "secondary"
    extra = cls
    cls = (f"btn btn-{kind}" + (f" btn-{size}" if size in ("sm", "lg") else "")
           + (f" btn-tone tone-{_tone(tone)}" if tone else "") + (f" {h(extra)}" if extra else ""))
    ic = _icon(icon) if icon else ""
    if short and short != label:
        inner = f'{ic}<span class="lbl-full">{h(label)}</span><span class="lbl-short">{h(short)}</span>'
    else:
        inner = f'{ic}<span>{h(label)}</span>'
    if href is not None:
        return f'<a class="{cls}" href="{h(href)}" {attrs}>{inner}</a>'
    typ = "" if "type=" in attrs else ' type="submit"'
    return f'<button class="{cls}"{typ} {attrs}>{inner}</button>'


_icon = icon  # button() shadows the name `icon` with its parameter


def table(headers: Sequence[Any], rows: Iterable[Any], *, empty: str = "",
          cls: str = "") -> str:
    """Responsive table: becomes stacked cards below 760px.

    headers: str or (label, cell_class). rows: list of cells (HTML), or a
    dict {"cells": [...], "attrs": 'data-row="x"'} for row attributes."""
    heads: list[tuple[str, str]] = []
    for hd in headers:
        if isinstance(hd, (tuple, list)):
            heads.append((str(hd[0]), str(hd[1]) if len(hd) > 1 else ""))
        else:
            heads.append((str(hd), ""))
    body = []
    for row in rows:
        attrs = ""
        cells = row
        if isinstance(row, dict):
            attrs = " " + str(row.get("attrs", "")).strip()
            cells = row.get("cells", [])
        tds = []
        for i, cell in enumerate(cells):
            label, ccls = heads[i] if i < len(heads) else ("", "")
            tds.append(f'<td data-label="{h(label)}"'
                       + (f' class="{h(ccls)}"' if ccls else "") + f">{cell}</td>")
        body.append(f"<tr{attrs.rstrip()}>" + "".join(tds) + "</tr>")
    if not body:
        if empty and not empty.lstrip().startswith("<"):
            empty = f'<p class="muted table-empty-text">{h(empty)}</p>'
        return f'<div class="table-empty">{empty or empty_state("Intet at vise", "Der er ingen rækker endnu.")}</div>'
    thead = "".join(f'<th scope="col"' + (f' class="{h(c)}"' if c else "") + f">{h(l)}</th>"
                    for l, c in heads)
    return (f'<div class="table-wrap{(" " + h(cls)) if cls else ""}"><table class="table">'
            f"<thead><tr>{thead}</tr></thead><tbody>{''.join(body)}</tbody></table></div>")


def empty_state(title: str, text: str, icon: str = "inbox", action_html: str = "") -> str:
    return (f'<div class="empty"><div class="empty-art">{_icon(icon)}</div>'
            f'<h3 class="empty-title">{h(title)}</h3><p class="empty-text">{h(text)}</p>'
            + (f'<div class="empty-action">{action_html}</div>' if action_html else "")
            + "</div>")


_ID_RE = re.compile(r'\bid="([^"]+)"')


def form_field(label: str, input_html: str, *, hint: str = "", error: str = "") -> str:
    m = _ID_RE.search(input_html)
    err_cls = " has-error" if error else ""
    extra = ((f'<span class="field-hint">{h(hint)}</span>' if hint else "")
             + (f'<span class="field-error" role="alert">{_icon("alert-circle")}{h(error)}</span>'
                if error else ""))
    if m:
        return (f'<div class="field{err_cls}"><label class="field-label" for="{m.group(1)}">'
                f"{h(label)}</label>{input_html}{extra}</div>")
    return (f'<div class="field{err_cls}"><span class="field-label">{h(label)}</span>'
            f"{input_html}{extra}</div>")


def _field_id(name: str) -> str:
    return "f-" + re.sub(r"[^A-Za-z0-9_-]", "-", str(name))


def input_(name: str, value: Any = "", *, type: str = "text", attrs: str = "") -> str:  # noqa: A002
    id_attr = "" if re.search(r"\bid=", attrs) else f' id="{_field_id(name)}"'
    val = "" if type == "password" else f' value="{h(value)}"'
    return (f'<input class="input" type="{h(type)}" name="{h(name)}"{id_attr}{val}'
            + (f" {attrs}" if attrs else "") + ">")


def textarea(name: str, value: Any = "", *, rows: int = 4, attrs: str = "") -> str:
    id_attr = "" if re.search(r"\bid=", attrs) else f' id="{_field_id(name)}"'
    return (f'<textarea class="input textarea" name="{h(name)}"{id_attr} rows="{int(rows)}"'
            + (f" {attrs}" if attrs else "") + f">{h(value)}</textarea>")


def select(name: str, options: Sequence[tuple[Any, Any]], selected: Any = None,
           attrs: str = "") -> str:
    id_attr = "" if re.search(r"\bid=", attrs) else f' id="{_field_id(name)}"'
    opts = "".join(
        f'<option value="{h(v)}"' + (" selected" if selected is not None and str(v) == str(selected) else "")
        + f">{h(lbl)}</option>" for v, lbl in options)
    return (f'<div class="select-wrap"><select class="select" name="{h(name)}"{id_attr}'
            + (f" {attrs}" if attrs else "") + f">{opts}</select>{_icon('chevron-down', 'select-caret')}</div>")


def switch(name: str, checked: bool, label: str, *, attrs: str = "") -> str:
    """Toggle switch. Unchecked sends nothing (standard checkbox semantics)."""
    return (f'<label class="switch"><input type="checkbox" role="switch" name="{h(name)}" value="1"'
            + (" checked" if checked else "") + (f" {attrs}" if attrs else "")
            + '><span class="switch-track" aria-hidden="true"><span class="switch-thumb"></span></span>'
            f'<span class="switch-label">{h(label)}</span></label>')


def segmented(name: str, options: Sequence[tuple[Any, Any]], selected: Any) -> str:
    """Radio-button segmented control (a real form input)."""
    opts = "".join(
        f'<label class="seg-opt"><input type="radio" name="{h(name)}" value="{h(v)}"'
        + (" checked" if str(v) == str(selected) else "")
        + f"><span>{h(lbl)}</span></label>" for v, lbl in options)
    return f'<div class="segmented" role="radiogroup">{opts}</div>'


def seg_links(items: Sequence[tuple[str, str, bool]]) -> str:
    """Segmented control made of links (label, href, active): no JS needed."""
    return ('<nav class="segmented seg-links">' + "".join(
        f'<a href="{h(href)}" class="seg-opt' + (' is-active" aria-current="page"' if active else '"')
        + f"><span>{h(lbl)}</span></a>" for lbl, href, active in items) + "</nav>")


def tabs(items: Sequence[tuple[str, str, bool, Any]]) -> str:
    """Underline tabs (label, href, active, count|None)."""
    out = []
    for lbl, href, active, count in items:
        cnt = f'<span class="tab-count">{fmt_int(count)}</span>' if count is not None else ""
        out.append(f'<a class="tab{" is-active" if active else ""}" href="{h(href)}"'
                   + (' aria-current="page"' if active else "") + f">{h(lbl)}{cnt}</a>")
    return '<nav class="tabs">' + "".join(out) + "</nav>"


def progress(value: Any, maximum: Any, *, tone: str = "brand", label: str = "", value_text: str = "") -> str:
    p = pct(value, maximum)
    shown = value_text or f"{fmt_int(value)} / {fmt_int(maximum)}"
    lab = (f'<div class="progress-label"><span>{h(label)}</span>'
           f'<span class="num">{h(shown)}</span></div>') if label else ""
    return (f'<div class="progress-block">{lab}<div class="progress tone-{_tone(tone, "brand")}" '
            f'role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="{p}"'
            + (f' aria-label="{h(label)}"' if label else "")
            + f'><span class="progress-fill p-{p}"></span></div></div>')


_RING_SEQ = itertools.count(1)


def ring(value: Any, maximum: Any, *, label: str, tone: str = "") -> str:
    """Circular progress (SVG). Full ring = goal reached."""
    p = pct(value, maximum)
    r = 34
    circ = 2 * math.pi * r
    filled = circ * p / 100
    tone = tone or ("ok" if p >= 100 else "brand")
    gid = f"rg{next(_RING_SEQ)}"
    return (
        f'<div class="ring tone-{_tone(tone, "brand")}" role="img" aria-label="{h(label)}: {fmt_int(value)} af {fmt_int(maximum)}">'
        f'<svg viewBox="0 0 80 80" class="ring-svg" aria-hidden="true">'
        f'<defs><linearGradient id="{gid}" x1="0" y1="0" x2="1" y2="1">'
        f'<stop offset="0" class="stop-a"/><stop offset="1" class="stop-b"/></linearGradient></defs>'
        f'<circle class="ring-track" cx="40" cy="40" r="{r}" fill="none" stroke-width="7"/>'
        f'<circle class="ring-value" cx="40" cy="40" r="{r}" fill="none" stroke-width="7" '
        f'stroke="url(#{gid})" stroke-linecap="round" stroke-dasharray="{filled:.2f} {circ:.2f}" '
        f'transform="rotate(-90 40 40)"/></svg>'
        f'<div class="ring-center"><span class="ring-pct">{p}<small>%</small></span></div>'
        f'<div class="ring-label">{h(label)}<span class="num">{fmt_int(value)} / {fmt_int(maximum)}</span></div>'
        "</div>")


def gauge(score: Any, threshold: Any, *, greyed: bool = False) -> str:
    """Semicircle gauge: final score against the account threshold."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        s = None
    try:
        t = float(threshold)
    except (TypeError, ValueError):
        t = 8.0
    top = max(t * 2, (s or 0) + 1, 10.0)
    frac = 0.0 if s is None else max(0.0, min(1.0, s / top))
    arc = math.pi * 50
    tone = "neutral" if greyed or s is None else score_tone(s, t)
    ang = math.pi * (1 - t / top)
    tx1, ty1 = 60 + 42 * math.cos(ang), 62 - 42 * math.sin(ang)
    tx2, ty2 = 60 + 58 * math.cos(ang), 62 - 58 * math.sin(ang)
    gid = f"gg{next(_RING_SEQ)}"
    return (
        f'<div class="gauge tone-{tone}{" is-greyed" if greyed else ""}">'
        f'<svg viewBox="0 0 120 70" class="gauge-svg" aria-hidden="true">'
        f'<defs><linearGradient id="{gid}" x1="0" y1="0" x2="1" y2="0">'
        f'<stop offset="0" class="stop-a"/><stop offset="1" class="stop-b"/></linearGradient></defs>'
        f'<path class="gauge-track" d="M10 62 A50 50 0 0 1 110 62" fill="none" stroke-width="9" stroke-linecap="round"/>'
        f'<path class="gauge-value" d="M10 62 A50 50 0 0 1 110 62" fill="none" stroke-width="9" '
        f'stroke="url(#{gid})" stroke-linecap="round" stroke-dasharray="{arc * frac:.2f} {arc:.2f}"/>'
        f'<line class="gauge-tick" x1="{tx1:.2f}" y1="{ty1:.2f}" x2="{tx2:.2f}" y2="{ty2:.2f}" stroke-width="2.5" stroke-linecap="round"/>'
        f"</svg>"
        f'<div class="gauge-center"><span class="gauge-score">{fmt_score(s)}</span>'
        f'<span class="gauge-cap">grænse {fmt_score(t)}</span></div></div>')


def modal(id: str, title: str, body: str, actions: str) -> str:  # noqa: A002
    """Native <dialog>. Open with a button carrying data-open-modal="id"."""
    mid = re.sub(r"[^A-Za-z0-9_-]", "", id)
    return (f'<dialog class="modal" id="{mid}" aria-labelledby="{mid}-title">'
            f'<div class="modal-card"><div class="modal-head"><h2 id="{mid}-title">{h(title)}</h2>'
            f'<button type="button" class="icon-btn" data-close-modal aria-label="Luk">{_icon("x")}</button></div>'
            f'<div class="modal-body">{body}</div>'
            f'<div class="modal-actions">{actions}</div></div></dialog>')


_CHART_SEQ = itertools.count(1)


def _nice_max(v: float) -> float:
    if v <= 0:
        return 1.0
    exp = 10 ** math.floor(math.log10(v))
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * exp:
            return m * exp
    return 10 * exp


def bar_chart(series: Sequence[dict], labels: Sequence[str], *,
              tips: Sequence[str] | None = None) -> str:
    """Stacked bar chart as inline SVG (no text inside the SVG, so it
    scales cleanly; axis labels are HTML around it).

    series: [{"label": "Spam", "values": [...], "tone": "bad"}, ...] from
    bottom to top of each stack. labels: one per column."""
    n = len(labels)
    if n == 0 or not series:
        return empty_state("Ingen data endnu", "Grafen fyldes ud, når filteret har scannet post.", "bar-chart")
    totals = [sum(float((s.get("values") or [0] * n)[i] or 0) for s in series) for i in range(n)]
    top = _nice_max(max(totals) if totals else 0)
    slot, bar_w, height = 20.0, 12.0, 90.0
    width = slot * n
    cid = next(_CHART_SEQ)
    defs = []
    for si, s in enumerate(series):
        tone = _tone(s.get("tone"), "neutral")
        defs.append(f'<linearGradient id="cg{cid}-{si}" x1="0" y1="0" x2="0" y2="1">'
                    f'<stop offset="0" class="cs-{tone}-a"/><stop offset="1" class="cs-{tone}-b"/></linearGradient>')
    cols = []
    for i in range(n):
        x = i * slot + (slot - bar_w) / 2
        y_cursor = height
        segs = []
        vals = [float((s.get("values") or [0] * n)[i] or 0) for s in series]
        visible = [k for k, v in enumerate(vals) if v > 0]
        top_idx = visible[-1] if visible else -1
        for si, v in enumerate(vals):
            if v <= 0:
                continue
            hgt = max(1.2, v / top * height)
            y = y_cursor - hgt
            if si == top_idx:
                # Round only the top: extend the rect downward under the
                # segment below (drawn later, on top of it).
                r = min(3.0, hgt / 2)
                segs.insert(0, f'<rect class="chart-seg" x="{x:.1f}" y="{y:.2f}" width="{bar_w:.1f}" '
                               f'height="{hgt + r:.2f}" rx="{r:.1f}" fill="url(#cg{cid}-{si})"/>')
            else:
                segs.append(f'<rect class="chart-seg" x="{x:.1f}" y="{y:.2f}" width="{bar_w:.1f}" '
                            f'height="{hgt:.2f}" fill="url(#cg{cid}-{si})"/>')
            y_cursor = y
        tip = (tips[i] if tips and i < len(tips) else
               f"{labels[i]}: " + ", ".join(f"{s.get('label', '')} {fmt_int(vals[k])}" for k, s in enumerate(series)))
        cols.append(f'<g class="chart-col" data-tip="{h(tip)}"><title>{h(tip)}</title>'
                    f'<rect class="chart-hit" x="{i * slot:.1f}" y="0" width="{slot:.1f}" height="{height:.0f}"/>'
                    + "".join(segs) + "</g>")
    grid = "".join(
        f'<line class="chart-grid" x1="0" x2="{width:.0f}" y1="{y:.1f}" y2="{y:.1f}" vector-effect="non-scaling-stroke"/>'
        for y in (0.5, height / 2, height - 0.5))
    # preserveAspectRatio="none": on a wide card the height is capped by CSS
    # (max-height), and the default "meet" then shrank the bars into the middle
    # while the HTML day labels spread across the full width (2.12.2).
    svg = (f'<svg class="chart-svg" viewBox="0 0 {width:.0f} {height:.0f}" preserveAspectRatio="none" role="img" '
           f'aria-label="Søjlediagram">'
           f'<defs>{"".join(defs)}</defs>{grid}{"".join(cols)}</svg>')
    xlabels = "".join(f'<span class="{"is-alt" if i % 2 else ""}">{h(lbl)}</span>' for i, lbl in enumerate(labels))
    ylabels = (f'<span>{fmt_int(top)}</span><span>{fmt_int(top / 2) if top >= 2 else ""}</span><span>0</span>')
    legend = "".join(
        f'<span class="legend-item"><i class="swatch tone-{_tone(s.get("tone"), "neutral")}"></i>'
        f'{h(s.get("label", ""))}<b class="num">{fmt_int(sum(float(v or 0) for v in (s.get("values") or [])))}</b></span>'
        for s in reversed(list(series)))
    return (f'<figure class="chart chart-n{n}"><div class="chart-plot">{svg}'
            f'<div class="chart-y" aria-hidden="true">{ylabels}</div>'
            f'<div class="chart-x" aria-hidden="true">{xlabels}</div></div>'
            f'<figcaption class="chart-legend">{legend}</figcaption></figure>')


def kv_list(pairs: Iterable[tuple[str, str]]) -> str:
    """Definition list; values are HTML (escape them yourself)."""
    return '<dl class="kv">' + "".join(
        f'<div class="kv-row"><dt>{h(k)}</dt><dd>{v}</dd></div>' for k, v in pairs) + "</dl>"


def alert(text: Any, tone: str = "info", *, title: str = "", icon_name: str = "",
          action_html: str = "") -> str:
    tone = _tone(tone, "info")
    ic = icon_name or {"ok": "check-circle", "warn": "alert-triangle", "bad": "alert-circle"}.get(tone, "info")
    return (f'<div class="alert tone-{tone}" role="{"alert" if tone == "bad" else "status"}">'
            f'{_icon(ic, "alert-icon")}<div class="alert-body">'
            + (f'<strong class="alert-title">{h(title)}</strong>' if title else "")
            + f'<span>{h(text)}</span></div>'
            + (f'<div class="alert-action">{action_html}</div>' if action_html else "")
            + "</div>")


def avatar(name: str) -> str:
    parts = [p for p in re.split(r"[\s._@-]+", str(name or "?")) if p]
    initials = "".join(p[0] for p in parts[:2]).upper() or "?"
    return f'<span class="avatar" aria-hidden="true">{h(initials)}</span>'


def skeleton(lines: int = 3, *, cls: str = "") -> str:
    return (f'<div class="skeleton{(" " + h(cls)) if cls else ""}" aria-hidden="true">'
            + "".join(f'<span class="sk-line sk-{i % 3}"></span>' for i in range(lines)) + "</div>")


def pagination(page: int, pages: int, href_for) -> str:
    """Compact pager. href_for(page) -> URL."""
    if pages <= 1:
        return ""
    nums: list[int | None] = []
    for p in range(1, pages + 1):
        if p in (1, pages) or abs(p - page) <= 1:
            nums.append(p)
        elif nums and nums[-1] is not None:
            nums.append(None)
    items = []
    prev_dis = page <= 1
    items.append(f'<a class="pg pg-nav{" is-disabled" if prev_dis else ""}" '
                 + ('aria-disabled="true"' if prev_dis else f'href="{h(href_for(page - 1))}"')
                 + f' aria-label="Forrige side">{_icon("chevron-left")}</a>')
    for p in nums:
        if p is None:
            items.append('<span class="pg pg-gap">…</span>')
        else:
            items.append(f'<a class="pg{" is-active" if p == page else ""}" href="{h(href_for(p))}"'
                         + (' aria-current="page"' if p == page else "") + f">{p}</a>")
    next_dis = page >= pages
    items.append(f'<a class="pg pg-nav{" is-disabled" if next_dis else ""}" '
                 + ('aria-disabled="true"' if next_dis else f'href="{h(href_for(page + 1))}"')
                 + f' aria-label="Næste side">{_icon("chevron-right")}</a>')
    return '<nav class="pager" aria-label="Sider">' + "".join(items) + "</nav>"


def confirm_attrs(title: str, text: str = "", *, confirm: str = "Bekræft",
                  tone: str = "primary", typed: str = "") -> str:
    """data-* attributes that make app.js show a modal confirm first."""
    out = (f'data-confirm="{h(title)}" data-confirm-text="{h(text)}" '
           f'data-confirm-label="{h(confirm)}" data-confirm-tone="{h(tone)}"')
    if typed:
        out += f' data-confirm-typed="{h(typed)}"'
    return out


def hidden(name: str, value: Any) -> str:
    return f'<input type="hidden" name="{h(name)}" value="{h(value)}">'


def csrf_field() -> str:
    import dashboard as ui

    return hidden("csrf", ui.csrf_token())


def post_form(action: str, inner: str, *, ajax: bool = True, cls: str = "",
              attrs: str = "") -> str:
    """POST form with CSRF field. ajax=True lets app.js submit it with
    fetch() and show toasts; without JS it posts normally."""
    return (f'<form method="post" action="{h(action)}"'
            + (f' class="{h(cls)}"' if cls else "")
            + (" data-ajax" if ajax else "") + (f" {attrs}" if attrs else "")
            + f">{csrf_field()}{inner}</form>")


# ---------------------------------------------------------------------------
# Two-step login + app components (2.1)
# ---------------------------------------------------------------------------

# 2.10: Fleetdeck "Command" (the default look): page background dark / light.
THEME_DARK = "#0b0b0d"
THEME_LIGHT = "#f7f7f8"


def otp_input(name: str = "code", *, id: str = "", autofocus: bool = False,  # noqa: A002
              recovery: bool = True, describedby: str = "") -> str:
    """One-time code field. With recovery=True it also takes a recovery
    code (app.js starts it with the number pad and offers a switch)."""
    fid = id or _field_id(name)
    mode = ('inputmode="text" data-otp-recovery maxlength="14" placeholder="123456"' if recovery
            else 'inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" placeholder="123456"')
    out = (f'<input class="input otp-input" type="text" name="{h(name)}" id="{h(fid)}" {mode} '
           'autocomplete="one-time-code" autocapitalize="none" autocorrect="off" spellcheck="false" required data-otp'
           + (" autofocus" if autofocus else "")
           + (f' aria-describedby="{h(describedby)}"' if describedby else "") + ">")
    if recovery:
        out += (f'<button type="button" class="link-btn otp-switch js-only" data-otp-toggle="{h(fid)}" '
                'data-alt-label="Brug koden fra appen">Brug en genoprettelseskode</button>')
    return out


def wizard_step(num: int, title: str, text: str, body: str) -> str:
    return (f'<section class="wiz-step"><div class="wiz-head"><span class="wiz-num">{int(num)}</span>'
            f'<div><h3>{h(title)}</h3><p>{h(text)}</p></div></div><div class="wiz-body">{body}</div></section>')


def install_card(external_url: str = "", *, admin: bool = False) -> str:
    """'Tilføj til hjemmeskærm' guide (iPhone + Android). app.js picks the
    visitor's platform, offers the browser's own install prompt where there
    is one and says so when the page already runs as an installed app."""
    ext = (external_url or "").strip()
    host = ext.split("://", 1)[-1]
    ios = ('<ol class="steps">'
           "<li><span>Åbn spamfilteret i <b>Safari</b>.</span></li>"
           f'<li><span>Tryk på <b>Del</b> {_icon("share", "inline-icon")} nederst på skærmen (øverst på iPad).</span></li>'
           f'<li><span>Rul ned og vælg <b>Føj til hjemmeskærm</b> {_icon("plus-square", "inline-icon")}.</span></li>'
           "<li><span>Tryk på <b>Tilføj</b>. Spamfilteret ligger nu som en app på hjemmeskærmen.</span></li></ol>")
    android = ('<ol class="steps">'
               "<li><span>Åbn spamfilteret i <b>Chrome</b>.</span></li>"
               f'<li><span>Tryk på menuen {_icon("more-vertical", "inline-icon")} øverst til højre.</span></li>'
               "<li><span>Vælg <b>Installer app</b> (eller <b>Føj til startskærm</b>).</span></li>"
               "<li><span>Bekræft. Appen ligger nu på startskærmen og i app-oversigten.</span></li></ol>")
    if not admin:
        # Family users: no HTTPS/tunnel/LAN talk - just where to open it.
        https = (f'Brug adressen <a class="card-link" href="{h(ext)}">{h(host)}</a> på telefonen.'
                 if ext.startswith("https://") else "")
    elif ext.startswith("https://"):
        https = (f'Fuld installation på Android (egen app med offline-side) kræver HTTPS. Brug derfor den eksterne '
                 f'adresse <a class="card-link" href="{h(ext)}">{h(host)}</a> på telefonen. På den lokale adresse '
                 "bliver det en genvej, der åbner i browseren.")
    else:
        https = ("Fuld installation på Android (egen app med offline-side) kræver HTTPS – fx adgang udefra via "
                 "Cloudflare Tunnel. På den lokale adresse bliver det en genvej, der åbner i browseren."
                 + (' Sæt den eksterne adresse under <a class="card-link" href="/settings#ekstern">Indstillinger</a>.'
                    if admin else ""))
    tabs = ('<div class="segmented install-tabs js-only" role="tablist" aria-label="Telefon">'
            '<button type="button" class="seg-opt is-active" role="tab" aria-selected="true" data-tab="ios">'
            "<span>iPhone / iPad</span></button>"
            '<button type="button" class="seg-opt" role="tab" aria-selected="false" data-tab="android">'
            "<span>Android</span></button></div>")
    body = (f'<div class="install" data-install>'
            f'<div class="install-status" data-install-status hidden>{_icon("check-circle")}'
            "<span>Du bruger allerede spamfilteret som app på denne enhed.</span></div>"
            f"{tabs}"
            f'<section class="install-panel" data-tab-panel="ios"><h3 class="install-h">{_icon("smartphone")}'
            f"iPhone og iPad</h3>{ios}"
            + ('<p class="faint small">Virker også på den lokale adresse.</p>' if admin else "") + "</section>"
            f'<section class="install-panel" data-tab-panel="android"><h3 class="install-h">{_icon("smartphone")}'
            f"Android</h3>{android}"
            + (f'<p class="install-note">{_icon("lock", "inline-icon")}<span>{https}</span></p>' if https else "")
            + "</section></div>")
    prompt = button("Installer app", kind="primary", icon="download", size="sm",
                    attrs='type="button" data-install-prompt hidden')
    return card(body, title="Spamfilter på hjemmeskærmen", subtitle="Åbn det som en app – uden adresselinje.",
                actions=prompt, cls="install-card")


def render_offline_page() -> str:
    """What the service worker shows when the filter cannot be reached.
    Public and cacheable: no session, no CSRF token, no user data."""
    import dashboard as ui

    body = ('<div class="login-card offline-card">'
            f'<div class="login-brand">{brand_mark("brand-mark-lg")}<h1>Du er offline</h1>'
            "<p>Spamfilteret kan ikke nås lige nu. Tjek din internetforbindelse – siden prøver selv igen, "
            "når du er online.</p></div>"
            + button("Prøv igen", href="/", kind="primary", icon="refresh", cls="btn-block", size="lg",
                     attrs="data-offline-retry")
            + "</div>")
    return (_head("Offline", ui, csrf=False)
            + '<body class="auth" data-offline><div class="app-bg" aria-hidden="true"></div>'
            f'<main class="auth-main" id="main">{body}</main>'
            f'<footer class="foot auth-foot">{h(_site().brand())}</footer></body></html>')


# ---------------------------------------------------------------------------
# QR code (byte mode, error correction level M) for the 2FA setup page
# ---------------------------------------------------------------------------
# Pure Python after ISO/IEC 18004 (structure as in Project Nayuki's
# reference implementation): versions 1-20, automatic mask by penalty.

_QR_ECC_M = (-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26)
_QR_BLOCKS_M = (-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16)
_QR_MAX_VERSION = 20
_QR_FINDER_LIKE = ((1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0), (0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1))


def _qr_gf_mul(x: int, y: int) -> int:
    z = 0
    for i in range(7, -1, -1):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z


def _qr_rs_divisor(degree: int) -> list[int]:
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(len(result)):
            result[j] = _qr_gf_mul(result[j], root)
            if j + 1 < len(result):
                result[j] ^= result[j + 1]
        root = _qr_gf_mul(root, 0x02)
    return result


def _qr_rs_remainder(data: Sequence[int], divisor: list[int]) -> list[int]:
    result = [0] * len(divisor)
    for b in data:
        factor = b ^ result.pop(0)
        result.append(0)
        for i, coef in enumerate(divisor):
            result[i] ^= _qr_gf_mul(coef, factor)
    return result


def _qr_raw_modules(ver: int) -> int:
    result = (16 * ver + 128) * ver + 64
    if ver >= 2:
        num_align = ver // 7 + 2
        result -= (25 * num_align - 10) * num_align - 55
        if ver >= 7:
            result -= 36
    return result


def _qr_data_codewords(ver: int) -> int:
    return _qr_raw_modules(ver) // 8 - _QR_ECC_M[ver] * _QR_BLOCKS_M[ver]


def _qr_align_positions(ver: int) -> list[int]:
    if ver == 1:
        return []
    num_align = ver // 7 + 2
    step = (ver * 4 + num_align * 2 + 1) // (num_align * 2 - 2) * 2
    size = ver * 4 + 17
    return [6] + sorted(size - 7 - i * step for i in range(num_align - 1))


def _qr_penalty(mod: list[list[bool]]) -> int:
    """ISO 18004 mask penalty: runs (N1), 2x2 blocks (N2), finder-like
    patterns (N3) and dark/light balance (N4)."""
    size = len(mod)
    score = 0
    lines = [list(row) for row in mod] + [[mod[y][x] for y in range(size)] for x in range(size)]
    for line in lines:
        run, prev = 0, None
        for v in line:
            if v == prev:
                run += 1
            else:
                if run >= 5:
                    score += run - 2
                run, prev = 1, v
        if run >= 5:
            score += run - 2
        padded = (0,) * 4 + tuple(int(b) for b in line) + (0,) * 4
        for k in range(len(padded) - 10):
            if padded[k:k + 11] in _QR_FINDER_LIKE:
                score += 40
    for y in range(size - 1):
        for x in range(size - 1):
            if mod[y][x] == mod[y][x + 1] == mod[y + 1][x] == mod[y + 1][x + 1]:
                score += 3
    dark = sum(v for row in mod for v in row)
    total = size * size
    k = (abs(dark * 20 - total * 10) + total - 1) // total - 1
    return score + max(0, k) * 10


def qr_matrix(text: str | bytes, *, mask: int | None = None) -> list[list[bool]]:
    """QR code modules (True = dark) for `text`: byte mode, ECC level M."""
    data = text.encode("utf-8") if isinstance(text, str) else bytes(text)
    ver = next((v for v in range(1, _QR_MAX_VERSION + 1)
                if 4 + (8 if v < 10 else 16) + 8 * len(data) <= _qr_data_codewords(v) * 8), None)
    if ver is None:
        raise ValueError("too long for a QR code")
    bits: list[int] = []

    def put(val: int, n: int) -> None:
        bits.extend((val >> i) & 1 for i in range(n - 1, -1, -1))

    put(0b0100, 4)
    put(len(data), 8 if ver < 10 else 16)
    for b in data:
        put(b, 8)
    capacity = _qr_data_codewords(ver) * 8
    put(0, min(4, capacity - len(bits)))
    put(0, (-len(bits)) % 8)
    pad = 0xEC
    while len(bits) < capacity:
        put(pad, 8)
        pad ^= 0xEC ^ 0x11
    codewords = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    # Error correction per block, then interleave.
    nblocks, ecc_len = _QR_BLOCKS_M[ver], _QR_ECC_M[ver]
    raw = _qr_raw_modules(ver) // 8
    n_short = nblocks - raw % nblocks
    short_len = raw // nblocks
    divisor = _qr_rs_divisor(ecc_len)
    blocks, k = [], 0
    for i in range(nblocks):
        dat = codewords[k:k + short_len - ecc_len + (0 if i < n_short else 1)]
        k += len(dat)
        ecc = _qr_rs_remainder(dat, divisor)
        if i < n_short:
            dat = dat + [0]
        blocks.append(dat + ecc)
    stream = [blk[i] for i in range(len(blocks[0])) for j, blk in enumerate(blocks)
              if i != short_len - ecc_len or j >= n_short]
    # Function patterns.
    size = ver * 4 + 17
    mod = [[False] * size for _ in range(size)]
    fun = [[False] * size for _ in range(size)]

    def setf(x: int, y: int, dark: bool) -> None:
        mod[y][x] = dark
        fun[y][x] = True

    for i in range(size):
        setf(6, i, i % 2 == 0)
        setf(i, 6, i % 2 == 0)
    for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                x, y = cx + dx, cy + dy
                if 0 <= x < size and 0 <= y < size:
                    setf(x, y, max(abs(dx), abs(dy)) not in (2, 4))
    align = _qr_align_positions(ver)
    last = len(align) - 1
    for i, ax in enumerate(align):
        for j, ay in enumerate(align):
            if (i, j) in ((0, 0), (0, last), (last, 0)):
                continue
            for dy in range(-2, 3):
                for dx in range(-2, 3):
                    setf(ax + dx, ay + dy, max(abs(dx), abs(dy)) != 1)

    def draw_format(m: int) -> None:
        dat = m  # ECC level M has format bits 00
        rem = dat
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        fbits = ((dat << 10) | rem) ^ 0x5412
        for i in range(6):
            setf(8, i, (fbits >> i) & 1 == 1)
        setf(8, 7, (fbits >> 6) & 1 == 1)
        setf(8, 8, (fbits >> 7) & 1 == 1)
        setf(7, 8, (fbits >> 8) & 1 == 1)
        for i in range(9, 15):
            setf(14 - i, 8, (fbits >> i) & 1 == 1)
        for i in range(8):
            setf(size - 1 - i, 8, (fbits >> i) & 1 == 1)
        for i in range(8, 15):
            setf(8, size - 15 + i, (fbits >> i) & 1 == 1)
        setf(8, size - 8, True)

    draw_format(0)
    if ver >= 7:
        rem = ver
        for _ in range(12):
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
        vbits = (ver << 12) | rem
        for i in range(18):
            dark = (vbits >> i) & 1 == 1
            a, c = size - 11 + i % 3, i // 3
            setf(a, c, dark)
            setf(c, a, dark)
    # Data modules, zig-zag from the bottom right.
    total_bits, i = len(stream) * 8, 0
    right = size - 1
    while right >= 1:
        if right == 6:
            right = 5
        for vert in range(size):
            for j in range(2):
                x = right - j
                upward = ((right + 1) & 2) == 0
                y = size - 1 - vert if upward else vert
                if not fun[y][x] and i < total_bits:
                    mod[y][x] = (stream[i >> 3] >> (7 - (i & 7))) & 1 == 1
                    i += 1
        right -= 2
    masks = (
        lambda x, y: (x + y) % 2 == 0, lambda x, y: y % 2 == 0, lambda x, y: x % 3 == 0,
        lambda x, y: (x + y) % 3 == 0, lambda x, y: (x // 3 + y // 2) % 2 == 0,
        lambda x, y: x * y % 2 + x * y % 3 == 0, lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
        lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0,
    )

    def apply_mask(m: int) -> None:
        fn = masks[m]
        for yy in range(size):
            for xx in range(size):
                if not fun[yy][xx] and fn(xx, yy):
                    mod[yy][xx] = not mod[yy][xx]

    if mask is None:
        best, best_score = 0, None
        for m in range(8):
            apply_mask(m)
            draw_format(m)
            score = _qr_penalty(mod)
            if best_score is None or score < best_score:
                best, best_score = m, score
            apply_mask(m)  # XOR again = undo
        mask = best
    apply_mask(mask)
    draw_format(mask)
    return mod


def qr_svg(text: str, *, label: str = "QR-kode") -> str:
    """Inline SVG QR code: dark modules on white with the 4-module quiet
    zone (scanners need light around it, also in the dark theme).
    Presentation attributes only, so it is CSP-clean."""
    mod = qr_matrix(text)
    size = len(mod)
    q = 4
    parts = []
    for y, row in enumerate(mod):
        x = 0
        while x < size:
            if row[x]:
                start = x
                while x < size and row[x]:
                    x += 1
                parts.append(f"M{start + q} {y + q}h{x - start}v1h{start - x}z")
            else:
                x += 1
    dim = size + 2 * q
    return (f'<svg class="qr" viewBox="0 0 {dim} {dim}" role="img" aria-label="{h(label)}" '
            'shape-rendering="crispEdges" xmlns="http://www.w3.org/2000/svg">'
            f'<rect width="{dim}" height="{dim}" fill="#ffffff"/>'
            f'<path d="{"".join(parts)}" fill="#0b0d15"/></svg>')


# ---------------------------------------------------------------------------
# Page layout
# ---------------------------------------------------------------------------

# Admin navigation (2.10, owner: "Menuen skal inddeles mere pænt og
# intuitivt"): a few groups by what you want to do - read post, tune the
# filter, check the domains, manage mailboxes and people, run the system.
# (group key, heading, items); items are (key, href, label, icon). The
# first group has no heading; Hjælp sits on its own at the end.
NAV_GROUPS: tuple[tuple[str, str, tuple[tuple[str, str, str, str], ...]], ...] = (
    ("start", "", (
        ("overview", "/", "Oversigt", "t-layout-dashboard"),)),
    ("post", "Post", (
        ("spam", "/spam", "Fanget spam", "t-shield-exclamation"),
        ("messages", "/messages", "Beskeder", "t-mail"),
        ("find", "/find", "Find en mail", "t-search"),
        ("undo", "/undo", "Fortryd flytninger", "t-arrow-back-up"))),
    ("filter", "Filtrering", (
        ("rules", "/rules", "Regler", "t-list-check"),
        ("training", "/training", "Træning", "t-school"),
        ("ai", "/ai", "AI-vurdering", "t-sparkles"))),       # 2.7: ui_ai.py
    ("security", "Sikkerhed", (
        ("mailcheck", "/mailcheck", "Mailsikkerhed", "t-radar"),  # 2.7: ui_mailcheck.py
        ("dmarc", "/dmarc", "DMARC", "t-shield-check"))),          # 2.6 (C2): ui_dmarc.py
    ("access", "Konti og adgang", (
        ("accounts", "/accounts", "Konti", "t-at"),
        ("users", "/users", "Brugere", "t-users"),
        ("access", "/access", "Adgang for programmer", "t-key"))),  # 2.11: ui_access.py
    ("system", "System", (
        ("system", "/system", "Drift", "t-server"),
        ("updates", "/updates", "Opdateringer", "t-cloud-download"),  # 2.10: ui_updates.py
        ("settings", "/settings", "Indstillinger", "t-settings"))),
)
NAV_HELP = ("help", "/help", "Hjælp", "t-info-circle")


def nav_admin_items() -> list[tuple[str, str, str, str]]:
    """Every admin menu entry in menu order (incl. Hjælp)."""
    return [item for _key, _label, items in NAV_GROUPS for item in items] + [NAV_HELP]


# Kept for callers that list the tool pages (help, undo are reached from
# the pages that need them; see _nav).
NAV_TOOLS = (
    ("find", "/find", "Find en mail", "t-search"),
    ("undo", "/undo", "Fortryd flytninger", "t-arrow-back-up"),
    ("help", "/help", "Hjælp", "t-info-circle"),
)
# A Bruger's deliberately simple navigation: their spam, then only what
# they were given. (key, href, label, icon, permission or None)
NAV_USER = (
    ("overview", "/", "Min spam", "t-shield-exclamation", None),
    ("find", "/find", "Find en mail", "t-search", "release"),
    ("messages", "/messages", "Beskeder", "t-mail", "see_messages"),
    ("rules", "/rules", "Regler", "t-list-check", "rules"),
    # 2.3 (B13): without 'rules' the Kendte kontakter tab is reached here
    # ('!rules' = only shown when the Bruger does NOT have that permission).
    ("contacts", "/rules/contacts", "Kendte kontakter", "t-user-check", "!rules"),
    ("help", "/help", "Hjælp", "t-info-circle", None),
)
# Pages a Bruger only gets with a permission (admins see all).
NAV_PERMS = {"messages": "see_messages", "rules": "rules", "undo": "release", "find": "release"}
# Which nav entry lights up for pages without their own entry.
NAV_ALIAS_ADMIN = {"contacts": "rules", "attachments": "rules", "settings-site": "settings"}
NAV_ALIAS_USER = {"spam": "overview", "undo": "overview"}
# Pages that honour ?account=<name> (the account switcher keeps you there).
ACCOUNT_AWARE = {"overview": "/", "spam": "/spam", "messages": "/messages", "rules": "/rules",
                 "find": "/find", "undo": "/undo", "contacts": "/rules/contacts"}


def brand_mark(cls: str = "") -> str:
    """The app's mark (Fleetdeck style, 2.10): rounded square with a gradient
    and a white shield. Size comes from the CSS class."""
    return f'<span class="brand-mark{(" " + cls) if cls else ""}" aria-hidden="true">{_icon("t-logo")}</span>'


def _head(title: str, ui: Any, *, csrf: bool = True) -> str:
    """<head> incl. the PWA / home-screen tags. csrf=False for public,
    cacheable pages (the offline page must not create a session).
    2.10: data-skin (command|aurora) and data-nav (side|top) are the
    Fleetdeck look; app.js applies the browser's own choice before paint."""
    return (
        '<!doctype html><html lang="da" data-theme="dark" data-skin="command" data-nav="side"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">'
        f"<title>{h(title)} · Spamfilter</title>"
        '<meta name="color-scheme" content="dark light">'
        f'<meta name="theme-color" content="{THEME_DARK}" media="(prefers-color-scheme: dark)">'
        f'<meta name="theme-color" content="{THEME_LIGHT}" media="(prefers-color-scheme: light)">'
        + (f'<meta name="csrf-token" content="{h(ui.csrf_token())}">' if csrf else "")
        + '<meta name="referrer" content="no-referrer">'
        '<meta name="application-name" content="Spamfilter">'
        '<meta name="apple-mobile-web-app-capable" content="yes">'
        '<meta name="mobile-web-app-capable" content="yes">'
        '<meta name="apple-mobile-web-app-title" content="Spamfilter">'
        '<meta name="apple-mobile-web-app-status-bar-style" content="default">'
        '<meta name="format-detection" content="telephone=no">'
        # use-credentials: behind Cloudflare Access the manifest request must
        # carry the Access cookie, or Android cannot read it (no install).
        '<link rel="manifest" href="/manifest.webmanifest" crossorigin="use-credentials">'
        '<link rel="icon" type="image/png" href="/favicon.png">'
        f'<link rel="icon" type="image/png" sizes="192x192" href="{ui.static_url("icon-192.png")}">'
        f'<link rel="apple-touch-icon" sizes="180x180" href="{ui.static_url("apple-touch-icon.png")}">'
        f'<link rel="stylesheet" href="{ui.static_url("app.css")}">'
        f'<script src="{ui.static_url("app.js")}"></script>'
        "</head>"
    )


def _flashes(ui: Any) -> str:
    items = []
    for kind, msg in ui.pop_flashes():
        tone = {"ok": "ok", "error": "bad", "bad": "bad", "warn": "warn"}.get(kind, "info")
        items.append(f'<div class="flash" data-flash="{tone}">{alert(msg, tone)}</div>')
    return f'<div class="flashes">{"".join(items)}</div>' if items else ""


def _switcher(ui: Any, active: str, accounts: list[dict], selected: str) -> str:
    if not accounts:
        return ""
    base = ACCOUNT_AWARE.get(active, "/")
    admin = bool(getattr(ui, "is_admin", lambda: True)())
    sel = next((a for a in accounts if a["name"] == selected), None)
    label = (sel.get("label") or sel["name"]) if sel else "Alle konti"
    dot = status_dot(sel["state"]) if sel else '<span class="dot tone-ok" aria-hidden="true"></span>'
    count = "" if sel else f'<span class="switcher-count">{len(accounts)}</span>'
    items = [f'<a class="menu-item{" is-active" if not sel else ""}" href="{h(base)}">'
             f'<span class="dot tone-ok" aria-hidden="true"></span><span class="menu-text">Alle konti</span>'
             f'<span class="menu-meta">{len(accounts)}</span></a>']
    for a in accounts:
        items.append(
            f'<a class="menu-item{" is-active" if sel and sel["name"] == a["name"] else ""}" '
            f'href="{h(base)}?account={h(a["name"])}">{status_dot(a["state"])}'
            f'<span class="menu-text">{h(a.get("label") or a["name"])}<small>{h(_acct_sub(a))}</small></span>'
            + (f'<span class="menu-meta">{h(mode_label(a.get("mode")))}</span>' if admin else "") + '</a>')
    return (f'<details class="switcher" data-menu><summary class="switcher-btn" aria-label="Vælg konto">'
            f'{dot}<span class="switcher-label">{h(label)}</span>{count}{_icon("t-chevron-down", "switcher-caret")}</summary>'
            f'<div class="menu" role="menu">{"".join(items)}</div></details>')


def _acct_sub(a: dict) -> str:
    """Small second line under an account: the technical id when a friendly
    name is shown, then the address."""
    label, name, user = a.get("label") or a["name"], a["name"], a.get("user", "")
    return " · ".join(x for x in ((name if label != name else ""), user) if x)


def acct_name(label: str, name: str, *, cls: str = "") -> str:
    """Friendly account name with the technical id shown small (only when
    they differ). Both escaped."""
    if not label or label == name:
        return f'<span class="acct-label{(" " + cls) if cls else ""}">{h(name)}</span>'
    return (f'<span class="acct-label{(" " + cls) if cls else ""}">{h(label)}'
            f'<small class="acct-id">{h(name)}</small></span>')


def nav_allowed(key: str, user: dict | None) -> bool:
    """Is the main-nav page `key` available to this user?"""
    if not user:
        return False
    if user.get("is_admin"):
        return True
    perm = NAV_PERMS.get(key)
    return perm is None or perm in (user.get("perms") or ())


def user_nav(user: dict | None) -> list[tuple[str, str, str, str]]:
    """The simple navigation of a Bruger (only what they were given)."""
    perms = set((user or {}).get("perms") or ())

    def ok(perm: str | None) -> bool:
        if perm is None:
            return True
        if perm.startswith("!"):
            return perm[1:] not in perms
        return perm in perms

    return [(k, href, label, ic) for k, href, label, ic, perm in NAV_USER if ok(perm)]


def _nav_active(active: str, is_admin: bool, user: dict | None = None) -> str:
    alias = NAV_ALIAS_ADMIN if is_admin else NAV_ALIAS_USER
    if not is_admin and active == "contacts" and "rules" in set((user or {}).get("perms") or ()):
        return "rules"  # a Bruger with Regler reaches Kendte kontakter as a tab there
    return alias.get(active, active)


def _nav(active: str, is_admin: bool, counts: dict, user: dict | None = None) -> str:
    """The side menu (Fleetdeck .fd-navbar): Oversigt, then the groups
    (NAV_GROUPS) with a small heading each. An admin's Hjælp is the (?)
    button in the sidebar foot (_nav_help), so the menu fits a 900 px screen."""
    cur_key = _nav_active(active, is_admin, user)

    def link(key: str, href: str, label: str, ic: str) -> str:
        cnt = counts.get("spam" if key == "overview" and not is_admin else key)
        # data-mini: the short count the folded icon rail shows on the icon.
        badge_html = (f'<span class="nav-count" data-mini="{_mini_count(cnt)}">{fmt_int(cnt)}</span>'
                      if cnt else "")
        on = key == cur_key
        cur = ' aria-current="page"' if on else ""
        aria = f"{label} ({fmt_int(cnt)})" if cnt else label
        return (f'<a class="nav-link{" is-active" if on else ""}" href="{href}" title="{label}" '
                f'aria-label="{h(aria)}"{cur}>'
                f"{_icon(ic)}<span>{label}</span>{badge_html}</a>")

    if not is_admin:
        items = [link(*i) for i in user_nav(user)]
        items.append(link("me", "/me", "Min konto", "t-user"))
        return ('<nav class="nav nav-simple" id="sidebar-nav" aria-label="Hovedmenu"><div class="nav-group">'
                + "".join(items) + "</div></nav>")
    out = ['<nav class="nav" id="sidebar-nav" aria-label="Hovedmenu">']
    for gkey, label, items in NAV_GROUPS:
        out.append(f'<div class="nav-group" data-nav-group="{gkey}">'
                   + (f'<div class="nav-label">{label}</div>' if label else "")
                   + "".join(link(*item) for item in items) + "</div>")
    out.append("</nav>")
    return "".join(out)


def _topnav(active: str, is_admin: bool, counts: dict, user: dict | None = None) -> str:
    """2.10: the menu in the top bar (Fleetdeck "I toppen", data-nav=top):
    the daily pages as buttons, the groups as drop-down menus."""
    cur_key = _nav_active(active, is_admin, user)

    def top(key: str, href: str, label: str, _ic: str) -> str:
        cnt = counts.get("spam" if key == "overview" and not is_admin else key)
        on = key == cur_key
        return (f'<a class="fd-top{" is-active" if on else ""}" href="{href}"' + (' aria-current="page"' if on else "")
                + f'>{label}' + (f'<span class="nav-count">{fmt_int(cnt)}</span>' if cnt else "") + "</a>")

    def group(label: str, items: Sequence[tuple[str, str, str, str]]) -> str:
        on = cur_key in {k for k, *_ in items}
        total = sum(int(counts.get(k) or 0) for k, *_ in items)
        links = "".join(
            f'<a class="menu-item{" is-active" if k == cur_key else ""}" href="{href}"'
            + (' aria-current="page"' if k == cur_key else "") + f'>{_icon(ic)}'
            f'<span class="menu-text">{lbl}</span>'
            + (f'<span class="menu-meta">{fmt_int(counts[k])}</span>' if counts.get(k) else "") + "</a>"
            for k, href, lbl, ic in items)
        return (f'<details class="topnav-group" data-menu><summary class="fd-top{" is-active" if on else ""}">'
                f'{label}' + (f'<span class="nav-count">{fmt_int(total)}</span>' if total else "")
                + f'{_icon("t-chevron-down")}</summary><div class="menu" role="menu">{links}</div></details>')

    if not is_admin:
        return '<nav class="topnav" aria-label="Hovedmenu">' + "".join(top(*i) for i in user_nav(user)) + "</nav>"
    out = []
    for _gkey, label, items in NAV_GROUPS:
        out += [top(*i) for i in items] if not label else [group(label, items)]
    return '<nav class="topnav" aria-label="Hovedmenu">' + "".join(out) + top(*NAV_HELP) + "</nav>"


# Extra words so the search in the top bar also finds a page from what is on it.
SEARCH_WORDS = {
    "overview": "forside status nøgletal dashboard", "spam": "karantæne frigiv tillad spammappe",
    "messages": "indbakke mails post", "find": "søg mail afsender emne", "undo": "fortryd flyt tilbage",
    "rules": "afsendere blokér tillad liste domæne kendte kontakter vedhæftninger",
    "training": "lær bayes træn kalibrering", "ai": "kunstig intelligens vurdering model",
    "mailcheck": "spf dkim dns domæne mailsikkerhed", "dmarc": "rapporter domæne", "accounts": "postkasser imap konti adgangskode",
    "users": "brugere adgang roller rettigheder",
    "access": "api nøgle api-nøgle token home assistant kontrolrum sso programmer bearer", "system": "drift backup status log genstart",
    "updates": "version opdatering beta stable", "settings": "indstillinger smtp mail push notifikationer",
    "help": "vejledning hjælp guide", "contacts": "kendte kontakter afsendere", "me": "min konto adgangskode passkey udseende tema",
}


def search_page_items(is_admin: bool, user: dict | None) -> list[tuple[str, str, str, str, str]]:
    """Every page in the user's own menu (+ Min konto), as (key, href, label,
    icon, group) for the search in the top bar."""
    if is_admin:
        items = [(k, href, lbl, ic, glabel or "") for _g, glabel, its in NAV_GROUPS for k, href, lbl, ic in its]
        items.append((*NAV_HELP, ""))
    else:
        items = [(k, href, lbl, ic, "") for k, href, lbl, ic in user_nav(user)]
    return items + [("me", "/me", "Min konto", "t-user", "")]


def _search_pages(is_admin: bool, user: dict | None) -> str:
    """2.10.x: the pages the search field can jump to. app.js shows the ones
    that match what is typed; Enter on the top row still finds mails."""
    links = "".join(
        f'<a class="menu-item" role="option" href="{h(href)}" data-search-words="{h((lbl + " " + grp + " " + SEARCH_WORDS.get(k, "")).lower())}">'
        f'{_icon(ic)}<span class="menu-text">{h(lbl)}</span>' + (f'<span class="menu-meta">{h(grp)}</span>' if grp else "") + "</a>"
        for k, href, lbl, ic, grp in search_page_items(is_admin, user))
    return ('<div class="menu fd-search-list" id="fd-search-list" role="listbox" aria-label="Søgeresultater" hidden>'
            '<button type="submit" class="menu-item fd-search-mail" role="option">' + _icon("t-mail")
            + '<span class="menu-text">Find mails med <b data-search-echo></b></span></button>'
            '<div class="menu-label" data-search-pages-label>Sider</div>' + links
            + '<div class="menu-label fd-search-none" data-search-none hidden>Ingen sider passer</div></div>')


def _nav_help(active: str) -> str:
    """2.10: an admin's Hjælp in the sidebar foot, next to the fold button."""
    on = active == "help"
    return (f'<a class="icon-btn nav-help{" is-active" if on else ""}" href="/help" aria-label="Hjælp" title="Hjælp"'
            + (' aria-current="page"' if on else "") + f'>{_icon("t-info-circle")}</a>')


NAV_FOLD_TEXT = "Klap menuen sammen"  # app.js swaps in "Fold menuen ud" when folded


def _mini_count(cnt: Any) -> str:
    """The count as the icon rail shows it on the icon: at most "99+"."""
    try:
        n = int(cnt)
    except (TypeError, ValueError):
        return ""
    return "99+" if n > 99 else str(n)


def _nav_toggle() -> str:
    """Fold the sidebar to a 64 px icon rail (2.8.1; shared rule 2026-11-21
    "sammenklappelig menu"). The last row of the sidebar: chevron + text.
    app.js toggles html.nav-mini before first paint from localStorage
    (spamfilter.nav.collapsed), keeps aria-expanded/-label/title in step and
    adds Ctrl/Cmd+B; desktop/tablet only (the phone has the tab bar)."""
    return ('<button type="button" class="nav-toggle" data-nav-toggle aria-expanded="true" '
            f'aria-controls="sidebar-nav" aria-label="{NAV_FOLD_TEXT}" title="{NAV_FOLD_TEXT} (Ctrl+B)">'
            f'{_icon("chevron-left")}<span class="nav-toggle-text">{NAV_FOLD_TEXT}</span></button>')


def _theme_button(cls: str = "") -> str:
    return (f'<button type="button" class="icon-btn theme-btn{(" " + cls) if cls else ""}" '
            f'data-theme-toggle aria-label="Skift mellem mørkt og lyst tema" title="Skift tema">'
            f'{_icon("sun", "when-dark")}{_icon("moon", "when-light")}</button>')


# 2.10: Fleetdeck's own appearance choices (stored in this browser by app.js):
# style, colour theme and where the menu sits. Default = Command, dark, side.
LOOK_SKINS = (("command", "Command", "skarp og rolig"), ("aurora", "Aurora", "farver og glas"))
LOOK_THEMES = (("light", "Lyst", "t-sun"), ("dark", "Mørkt", "t-moon"), ("system", "Som systemet", "t-device-desktop"))
LOOK_NAVS = (("side", "I siden", "t-layout-sidebar"), ("top", "I toppen", "t-layout-navbar"))


def _look_menu() -> str:
    """The 'Udseende' menu in the top bar (Fleetdeck LookMenu)."""
    def opt(attr: str, value: str, label: str, ic: str = "", note: str = "") -> str:
        return (f'<button type="button" class="menu-item look-opt" {attr}="{value}" aria-pressed="false">'
                + (_icon(ic) if ic else _icon("t-check", "look-check"))
                + f'<span class="menu-text">{label}' + (f' <small>– {note}</small>' if note else "") + "</span>"
                + (_icon("t-check", "look-check") if ic else "") + "</button>")

    return ('<details class="look-menu" data-menu><summary class="icon-btn look-btn" aria-label="Udseende" title="Udseende">'
            f'{_icon("t-moon", "when-dark")}{_icon("t-sun", "when-light")}</summary>'
            '<div class="menu menu-end look-drop" role="menu"><div class="menu-label">Stil</div>'
            + "".join(opt("data-skin-set", v, lbl, note=n) for v, lbl, n in LOOK_SKINS)
            + '<div class="menu-sep"></div><div class="menu-label">Tema</div>'
            + "".join(opt("data-theme-set", v, lbl, ic) for v, lbl, ic in LOOK_THEMES)
            + '<div class="menu-sep"></div><div class="menu-label">Menu</div>'
            + "".join(opt("data-navpos-set", v, lbl, ic) for v, lbl, ic in LOOK_NAVS)
            + "</div></details>")


def look_card() -> str:
    """The 'Udseende' card on Min konto and Indstillinger (Fleetdeck LookPanel):
    menu placement, style and theme as segmented choices."""
    def seg(label: str, attr: str, opts: Sequence[tuple[str, str]]) -> str:
        btns = "".join(f'<button type="button" class="seg-opt" {attr}="{v}" aria-pressed="false"><span>{lbl}</span></button>'
                       for v, lbl in opts)
        return (f'<div class="look-row"><div class="field-label">{label}</div>'
                f'<div class="segmented look-seg" role="group" aria-label="{label}">{btns}</div></div>')

    return card(
        '<div id="udseende" class="look-rows">'
        + seg("Menu", "data-navpos-set", [(v, lbl) for v, lbl, _ in LOOK_NAVS])
        + seg("Stil", "data-skin-set", [(v, lbl) for v, lbl, _ in LOOK_SKINS])
        + seg("Tema", "data-theme-set", [(v, lbl) for v, lbl, _ in LOOK_THEMES])
        + "</div>"
        '<p class="faint small mt-1">Gemmes i denne browser.</p>', title="Udseende")


def _logout_form(ui: Any, *, cls: str = "icon-btn", label: bool = False) -> str:
    inner = _icon("t-logout") + ("<span>Log ud</span>" if label else "")
    return (f'<form method="post" action="/logout" class="logout-form">{hidden("csrf", ui.csrf_token())}'
            f'<button type="submit" class="{cls}" aria-label="Log ud" title="Log ud">{inner}</button></form>')


def _me_menu(ui: Any, user: dict, role: str, active: str) -> str:
    """2.10: the avatar menu in the top bar: who is logged in, Min konto, Udseende, Log ud."""
    name = user.get("name", "")
    return ('<details class="me-menu" data-menu>'
            f'<summary class="me-btn" aria-label="Min konto" title="{h(name)}">{avatar(name)}</summary>'
            f'<div class="menu menu-end" role="menu"><div class="menu-head"><b>{h(name)}</b><small>{role}</small></div>'
            f'<a class="menu-item{" is-active" if active == "me" else ""}" href="/me">{_icon("t-user")}'
            '<span class="menu-text">Min konto</span></a>'
            f'<a class="menu-item" href="/me#udseende">{_icon("t-palette")}<span class="menu-text">Udseende</span></a>'
            '<div class="menu-sep"></div>'
            + _logout_form(ui, cls="menu-item menu-danger", label=True) + "</div></details>")


def _sheet_item(key: str, href: str, label: str, ic: str, active: str) -> str:
    return (f'<a class="sheet-item{" is-active" if key == active else ""}" href="{href}">'
            f"{_icon(ic)}<span>{label}</span>{_icon('t-chevron-right', 'sheet-caret')}</a>")


def _tabbar(active: str, is_admin: bool, ui: Any, counts: dict, user: dict | None = None) -> str:
    """The phone's tab bar (Fleetdeck .fd-tabbar): four fixed tabs + Mere,
    which opens the rest of the menu, Udseende, Min konto and Log ud."""
    cur_key = _nav_active(active, is_admin, user)
    if is_admin:
        items = [("overview", "/", "Oversigt", "t-layout-dashboard"), ("spam", "/spam", "Spam", "t-shield-exclamation"),
                 ("messages", "/messages", "Beskeder", "t-mail"), ("find", "/find", "Find", "t-search")]
        fixed = {k for k, *_ in items}
        groups = [(label, [i for i in its if i[0] not in fixed]) for _g, label, its in NAV_GROUPS]
    else:
        short = {"overview": "Min spam", "find": "Find", "messages": "Beskeder", "rules": "Regler", "help": "Hjælp",
                 "contacts": "Kontakter"}
        nav = [(k, href, short.get(k, label), ic) for k, href, label, ic in user_nav(user)]
        items = nav[:4]
        groups = [("", nav[4:])]
    out = []
    for key, href, label, ic in items:
        cnt = counts.get("spam" if key == "overview" and not is_admin else key)
        dot = f'<i class="tab-dot" aria-hidden="true">{fmt_int(cnt)}</i>' if cnt else ""
        on = key == cur_key
        out.append(f'<a class="tabbar-item{" is-active" if on else ""}" href="{href}"'
                   + (' aria-current="page"' if on else "")
                   + f'><span class="tab-ic">{_icon(ic)}{dot}</span><span>{label}</span></a>')
    sheet = []
    rest_keys = {"me"}
    for label, its in groups:
        if not its:
            continue
        if label:
            sheet.append(f'<div class="sheet-group">{label}</div>')
        sheet += [_sheet_item(k, href, lbl, ic, cur_key) for k, href, lbl, ic in its]
        rest_keys |= {k for k, *_ in its}
    sheet.append('<div class="sheet-group">Konto</div>')
    if is_admin:
        sheet.append(_sheet_item(*NAV_HELP, cur_key))
        rest_keys.add("help")
    sheet.append(_sheet_item("look", "/me#udseende", "Udseende", "t-palette", cur_key))
    sheet.append(_sheet_item("me", "/me", "Min konto", "t-user", cur_key))
    sheet.append(_logout_form(ui, cls="sheet-item sheet-logout", label=True))
    more_active = cur_key in rest_keys
    out.append(f'<details class="tabbar-more" data-menu><summary class="tabbar-item{" is-active" if more_active else ""}">'
               f'<span class="tab-ic">{_icon("t-dots")}</span><span>Mere</span></summary>'
               f'<div class="sheet" role="menu">{"".join(sheet)}</div></details>')
    return '<nav class="tabbar" aria-label="Navigation">' + "".join(out) + "</nav>"


def _site():
    import siteconfig  # noqa: PLC0415

    return siteconfig


def _footer(version: str) -> str:
    """'Spamfilter 2.13.0 · <server name>' (local site config)."""
    name = _site().server_name()
    return f"Spamfilter {version}" + (f" · {name}" if name else "")


SITE_SETUP_URL = "/settings/site"


def site_banner(is_admin: bool, active: str = "") -> str:
    """Admins: the local site config (config/site.yml) is missing,
    unreadable or not set up yet. Owner protection is then EMPTY - the
    filter keeps running, but the admin must know."""
    if not is_admin or active == "settings-site":   # the page shows its own notice
        return ""
    sc = _site()
    st = sc.status()
    link = button("Åbn Lokal opsætning", href=SITE_SETUP_URL, kind="secondary", size="sm", icon="settings")
    if st == "missing":
        return alert("Filteret kører videre, men uden jeres egne domæner, webshops og betroede afsendere – "
                     "de er ikke beskyttet nu. Læg den lokale opsætning (config/site.yml) på serveren, eller "
                     "udfyld den under Indstillinger → Lokal opsætning.",
                     "bad", title="Lokal opsætning mangler – egne domæner er ikke beskyttet", action_html=link)
    if st == "invalid":
        return alert("Filen config/site.yml kunne ikke læses, så filteret kører uden jeres egne domæner og "
                     "webshops. Ret filen på serveren, eller gem opsætningen igen under Lokal opsætning.",
                     "bad", title="Lokal opsætning kan ikke læses – egne domæner er ikke beskyttet",
                     action_html=link)
    if not sc.get("setup_done"):
        return alert("Skriv serverens navn, jeres egne domæner og administratorens mailadresse, så filteret "
                     "kan beskytte dem.", "warn", title="Gør opsætningen færdig", action_html=link)
    return ""


def preview_banner(ui: Any) -> str:
    """'Se som bruger' (admin, read-only): the banner over the preview."""
    name = ui.preview_target() if hasattr(ui, "preview_target") else None
    if not name:
        return ""
    from urllib.parse import quote

    return (f'<div class="preview-banner" role="status">{_icon("eye")}'
            f'<div class="preview-text"><b>Forhåndsvisning som {h(name)} – ingen handlinger mulige</b>'
            '<span>Sådan ser siden ud for brugeren. Knapperne er slået fra.</span></div>'
            f'<a class="btn btn-secondary btn-sm preview-exit" data-preview-keep href="/users/{h(quote(name, safe=""))}">'
            f'{_icon("x")}<span>Afslut</span></a></div>')


def render_page(title: str, body_html: str, *, active: str, subtitle: str = "",
                actions_html: str = "", breadcrumbs: Sequence[tuple[str, str | None]] | None = None) -> str:
    """Full HTML document for an authenticated page. Administrators get the
    full navigation; a Bruger gets the simple one (only what they may use).
    2.10 (Fleetdeck-design): top bar with search, account switcher, Udseende
    and the avatar menu; the menu sits in the side or in the top bar."""
    import dashboard as ui

    user = ui.current_user() or {"name": "", "is_admin": False, "accounts": frozenset()}
    is_admin = bool(user.get("is_admin"))
    try:
        accounts = ui.sidebar_accounts()
        counts = ui.nav_counts()
    except Exception:  # noqa: BLE001 - layout must render even if the DB is sick
        accounts, counts = [], {}
    try:
        from flask import request

        selected = request.args.get("account", "")
    except Exception:  # noqa: BLE001
        selected = ""
    crumbs = ""
    if breadcrumbs:
        parts = []
        for label, href in breadcrumbs:
            parts.append(f'<a href="{h(href)}">{h(label)}</a>' if href else f'<span aria-current="page">{h(label)}</span>')
        crumbs = f'<nav class="crumbs" aria-label="Brødkrummer">{_icon("chevron-right", "crumb-sep").join(parts)}</nav>'
    role = "Administrator" if is_admin else "Bruger"
    version = ui.app_version()
    # A Bruger with one mailbox has nothing to switch between.
    switcher = _switcher(ui, active, accounts, selected) if (is_admin or len(accounts) > 1) else ""
    cur_key = _nav_active(active, is_admin, user)
    labels = {k: lbl for k, _href, lbl, _ic in nav_admin_items()} if is_admin \
        else {k: lbl for k, _href, lbl, _ic in user_nav(user)}
    mobile_title = labels.get(cur_key) or ("Min konto" if active == "me" else title)
    search = search_btn = ""
    if nav_allowed("find", user):
        search = ('<form class="fd-search" id="fd-search" role="search" method="get" action="/find">' + _icon("t-search")
                  + (hidden("account", selected) if selected else "")
                  + '<input type="search" name="q" placeholder="Søg efter mails, afsendere og sider…" aria-label="Søg efter mails og sider" '
                    'autocomplete="off" enterkeyhint="search" role="combobox" aria-expanded="false" aria-controls="fd-search-list" '
                    'aria-autocomplete="list" data-search-shortcut><kbd>Ctrl K</kbd>'
                  + _search_pages(is_admin, user) + '</form>')
        # Phone: a clear search button in the top bar (no JS: goes to Find en mail).
        search_btn = (f'<a class="look-btn topbar-search-btn" href="/find" aria-label="Søg" title="Søg" '
                      f'aria-controls="fd-search" data-search-open>{_icon("t-search")}</a>')
    sidebar = (
        '<aside class="sidebar">'
        f'<div class="sidebar-head"><a class="brand" href="/" aria-label="Spamfilter" title="Spamfilter {h(version)}">{brand_mark()}'
        f'<span class="brand-text"><b>Spamfilter</b><small class="sidebar-version">Version {h(version)}</small></span></a></div>'
        f'{_nav(active, is_admin, counts, user)}'
        # One row (fold button + Hjælp): the menu is no taller than before (900 px screens).
        f'<div class="sidebar-foot">{_nav_help(active) if is_admin else ""}{_nav_toggle()}</div>'
        '</aside>')
    topbar = (
        '<header class="topbar">'
        f'<a class="brand brand-top" href="/" aria-label="Spamfilter">{brand_mark()}<b>Spamfilter</b></a>'
        f'{_topnav(active, is_admin, counts, user)}{search}'
        f'<span class="topbar-title">{h(mobile_title)}</span>'
        f'<div class="topbar-right">{search_btn}{switcher}{_look_menu()}{_me_menu(ui, user, role, active)}</div>'
        '</header>')
    head = (
        f'<header class="page-head">{crumbs}<div class="page-title-row"><div class="page-titles">'
        f'<h1 class="page-title">{h(title)}</h1>'
        + (f'<p class="page-sub">{h(subtitle)}</p>' if subtitle else "")
        + "</div>"
        + (f'<div class="page-actions">{actions_html}</div>' if actions_html else "")
        + "</div></header>")
    simple = "" if is_admin else " is-simple"
    return (
        _head(title, ui)
        + f'<body class="page-{h(active)}{simple}" data-page="{h(active)}">'
        '<a class="skip" href="#main">Spring til indhold</a>'
        '<div class="app-bg" aria-hidden="true"></div>'
        f'{topbar}<div class="shell">{sidebar}<div class="main-col">'
        f'<main id="main" class="main">{preview_banner(ui)}{site_banner(is_admin, active)}{head}{_flashes(ui)}'
        f'<div class="page-body">{body_html}</div></main>'
        f'<footer class="foot">{h(_footer(version))}</footer>'
        f'</div></div>{_tabbar(active, is_admin, ui, counts, user)}'
        '<div class="toasts" id="toasts" role="status" aria-live="polite"></div>'
        '<div class="restart-overlay" id="restart-overlay" hidden><div class="restart-card">'
        '<div class="spinner" aria-hidden="true"></div><h2>Filteret genstarter…</h2>'
        '<p>Ændringen er gemt. Siden genindlæses automatisk, når filteret er klar igen.</p></div></div>'
        '</body></html>')


def render_auth_page(title: str, body_html: str) -> str:
    """Standalone centered page (login, errors when logged out)."""
    import dashboard as ui

    return (
        _head(title, ui)
        + '<body class="auth"><div class="app-bg" aria-hidden="true"></div>'
        f'<main class="auth-main" id="main">{_flashes(ui)}{body_html}</main>'
        f'<footer class="foot auth-foot">{h(_footer(ui.app_version()))}</footer>'
        '<div class="toasts" id="toasts" role="status" aria-live="polite"></div>'
        "</body></html>")


def error_body(code: int, title: str, text: str, *, logged_in: bool) -> str:
    ic = {404: "search", 403: "lock", 429: "clock", 400: "alert-triangle"}.get(code, "alert-circle")
    action = button("Til oversigten", href="/", kind="primary", icon="arrow-left") if logged_in \
        else button("Til log ind", href="/login", kind="primary", icon="arrow-left")
    return (f'<div class="error-page"><div class="error-code">{code}</div>'
            + empty_state(title, text, ic, action) + "</div>")
