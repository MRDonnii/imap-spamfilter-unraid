"""Indstillinger -> Lokal opsætning (/settings/site) - the local site
configuration (config/site.yml, siteconfig.py).

Everything that belongs to this one installation and never to the program:
the server's name, the owner's own mail domains and webshops, the platform
whose mail must always get through, trusted forwarders, the admin address,
the LAN address and the DNS forwarder. A fresh install starts empty; this
page is where the admin fills it in ("Gør opsætningen færdig").

Admin only (dashboard.admin_required). A save validates every field, writes
only the fields of the form (other keys in the file are kept), replaces the
file atomically (0600), asks the engine to reload and audits the changed
key names (never the values).
"""

from __future__ import annotations

import logging
from typing import Any

from flask import request

import dashboard as ui
import siteconfig
import ui_kit as kit
from ui_kit import h

log = logging.getLogger("dashboard.site")
app = ui.app

URL = "/settings/site"

HINTS = {
    "server_name": "Vises i bunden af siderne, i appen og i to-trins-appen, fx “Hjemmeserver”. Tomt = kun “Spamfilter”.",
    "admin_email": "Standardmodtager af DMARC-rapporter, fx admin@example.com.",
    "mail_domains": "Domænerne på jeres egne postkasser, ét pr. linje, fx example.com. De slås aldrig op i "
                    "blokeringslister for links og må gerne stå i afsendernavne.",
    "webshop_domains": "Jeres egne webshops og hjemmesider, ét pr. linje. Deres mail og links behandles som jeres egne.",
    "platform_domains": "Platforme, hvor al mail altid skal i indbakken (fx jeres webshop-platform). "
                        "Kun platformens eget domæne – aldrig andre butikker på den.",
    "protected_domains": "Domæner, hvis efterligninger fanges (standard, når Beskyttede domæner ikke er sat). "
                         "Postkassernes domæner er altid med.",
    "trusted_forwarders": "Jeres egne videresendere (værtsnavn eller IP), som filteret ser forbi, så den rigtige "
                          "afsender bedømmes. Standard for alle postkasser.",
    "mailcheck_domains": "Ekstra domæner, som Mailsikkerhed tjekker ud over postkassernes.",
    "mailcheck_no_mail": "Domæner, der aldrig sender mail (fx et domæne kun til hjemmesiden).",
    "domain_providers": "Én pr. linje: domæne = udbyder, fx example.com = Gigahost. Bruges i Mailsikkerheds råd.",
    "imap_presets": "Én pr. linje: domæne = server:port udbyder, fx example.com = imap.example.com:993 Udbyder. "
                    "Udfylder mailserveren, når en postkasse tilføjes.",
    "lan_url": "Filterets adresse på hjemmenetværket til Home Assistant, fx http://192.168.1.10:18080.",
    "dns_forwarders": "Navneserveren på hjemmenetværket (IP), hvis filteret ikke selv må spørge internettet. "
                      "Bruges kun, når serverens unbound.conf ikke har sin egen.",
    "msgid_domain": "Teknisk: domænet i filterets egne Message-ID'er. Lad det stå, hvis det er udfyldt.",
    "receipt_from": "Teknisk: afsenderen på kvitteringer og rapporter.",
    "contacts_key_label": "Teknisk: mærket på nøglen til kendte kontakter. Ændres det, synkroniseres kontakterne forfra.",
}
MAIN = ("server_name", "admin_email", "mail_domains", "webshop_domains", "platform_domains", "protected_domains",
        "trusted_forwarders", "lan_url")
MORE = ("mailcheck_domains", "mailcheck_no_mail", "domain_providers", "imap_presets", "dns_forwarders")
RSPAMD_KEYS = frozenset({"mail_domains", "webshop_domains", "platform_domains", "dns_forwarders"})


def _actor() -> str:
    return (ui.current_user() or {}).get("name", "")


# --------------------------------------------------------------- form <-> values
def _to_text(key: str, val: Any) -> str:
    kind = siteconfig.FIELDS[key][0]
    if kind in siteconfig.LIST_KINDS:
        return "\n".join(str(v) for v in val or [])
    if kind == "providers":
        return "\n".join(f"{d} = {p}" for d, p in (val or {}).items())
    if kind == "presets":
        lines = []
        for d, spec in (val or {}).items():
            spec = spec if isinstance(spec, dict) else {}
            prov = f" {spec['provider']}" if spec.get("provider") else ""
            lines.append(f"{d} = {spec.get('imap_host', '')}:{spec.get('imap_port', 993)}{prov}")
        return "\n".join(lines)
    return "" if val in (None, False) else str(val)


def parse_providers(text: str) -> tuple[dict[str, str], list[str]]:
    out: dict[str, str] = {}
    bad: list[str] = []
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        dom, sep, prov = line.partition("=")
        if not sep or not dom.strip() or not prov.strip():
            bad.append(line[:60])
            continue
        out[dom.strip().lower()] = prov.strip()
    return out, bad


def parse_presets(text: str) -> tuple[dict[str, dict[str, Any]], list[str]]:
    out: dict[str, dict[str, Any]] = {}
    bad: list[str] = []
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        dom, sep, rest = line.partition("=")
        parts = rest.strip().split(None, 1)
        if not sep or not dom.strip() or not parts:
            bad.append(line[:60])
            continue
        host, _c, port = parts[0].partition(":")
        spec: dict[str, Any] = {"imap_host": host.strip().lower(), "imap_port": port.strip() or 993}
        if len(parts) > 1:
            spec["provider"] = parts[1].strip()
        out[dom.strip().lower()] = spec
    return out, bad


def form_changes(form: Any, keys: tuple[str, ...]) -> tuple[dict[str, Any], list[str]]:
    """The posted fields -> (changes for siteconfig.save, parse problems)."""
    changes: dict[str, Any] = {}
    problems: list[str] = []
    for key in keys:
        if key not in form:
            continue
        kind, label = siteconfig.FIELDS[key]
        raw = form.get(key) or ""
        if kind == "providers":
            val, bad = parse_providers(raw)
            problems += [f"{label}: skriv domæne = udbyder ({b})" for b in bad]
            changes[key] = val
        elif kind == "presets":
            val2, bad = parse_presets(raw)
            problems += [f"{label}: skriv domæne = server:port ({b})" for b in bad]
            changes[key] = val2
        else:
            changes[key] = raw
    return changes, problems


# --------------------------------------------------------------- page
def _field(key: str, val: Any) -> str:
    kind, label = siteconfig.FIELDS[key]
    text = _to_text(key, val)
    if kind in siteconfig.LIST_KINDS or kind in siteconfig.MAP_KINDS:
        rows = max(2, min(8, text.count("\n") + 2))
        ctl = kit.textarea(key, text, rows=rows, attrs='autocapitalize="none" spellcheck="false"')
    else:
        typ = "email" if kind == "email" else "url" if kind == "url" else "text"
        ctl = kit.input_(key, text, type=typ, attrs='autocomplete="off" autocapitalize="none" spellcheck="false"'
                         + (' maxlength="200"' if kind == "text" else ""))
    return kit.form_field(label, ctl, hint=HINTS.get(key, ""))


def _status_alert(site: Any) -> str:
    if site.status == "missing":
        return kit.alert("Der findes ingen config/site.yml på serveren endnu. Udfyld felterne og gem – så oprettes "
                         "filen. Har du et flyttescript fra en tidligere version, så læg filen på serveren i stedet.",
                         "bad", title="Lokal opsætning mangler")
    if site.status == "invalid":
        return kit.alert("Filen kunne ikke læses. Ret den på serveren – siden gemmer ikke over en fil, den ikke kan "
                         "læse.", "bad", title="Lokal opsætning kan ikke læses")
    if site.problems:
        return kit.alert("Nogle værdier i filen var ugyldige og bruges ikke: " + "; ".join(site.problems[:5]),
                         "warn", title="Ugyldige værdier")
    if not site.get("setup_done"):
        return kit.alert("Skriv serverens navn, jeres egne domæner og administratorens mailadresse – og tryk Gem.",
                         "warn", title="Gør opsætningen færdig")
    return ""


def site_card() -> str:
    """The short card on Indstillinger (link to the page)."""
    site = siteconfig.CURRENT
    st = {"missing": ("Mangler", "bad"), "invalid": ("Kan ikke læses", "bad")}.get(site.status)
    if st is None:
        st = ("Klar", "ok") if site.get("setup_done") else ("Ikke færdig", "warn")
    doms = siteconfig.own_domains()
    body = (f'<p class="muted">Det, der kun gælder denne server: navn, egne domæner og webshops, platforme, '
            f'betroede videresendere og adresser. Gemmes kun lokalt i config/site.yml – aldrig i programmet, '
            f'og en opdatering ændrer det ikke.</p>'
            f'<p class="mt-1">{kit.badge(st[0], st[1])} '
            f'<span class="faint small">{h(kit.fmt_int(len(doms)))} egne domæner</span></p>'
            f'<div class="form-actions">{kit.button("Åbn Lokal opsætning", href=URL, kind="secondary", icon="settings")}</div>')
    return kit.card(body, title="Lokal opsætning")


@app.get(URL)
@ui.admin_required
def site_page():
    site = siteconfig.load()
    vals = site.values
    main = "".join(_field(k, vals.get(k)) for k in MAIN)
    more = "".join(_field(k, vals.get(k)) for k in MORE)
    compat = "".join(_field(k, vals.get(k)) for k in siteconfig.COMPAT_KEYS)
    inner = (main
             + '<details class="disclosure"><summary>' + kit.icon("chevron-right") + "Flere indstillinger</summary>"
             + more + "</details>"
             + '<details class="disclosure"><summary>' + kit.icon("chevron-right") + "Avanceret (teknisk)</summary>"
             + compat + "</details>"
             + '<p class="faint small mt-1">Egne domæner, webshops, platforme og navneserver bruges også i rspamd-'
               "reglerne; dér træder ændringer i kraft ved næste start af containeren (fx næste opdatering).</p>"
             + f'<div class="form-actions">{kit.button("Gem", kind="primary", icon="check")}</div>')
    body = (_status_alert(site)
            + kit.card(kit.post_form(URL, inner, ajax=False), title="Lokal opsætning",
                       subtitle=f"Gemmes i {h(str(site.path or siteconfig.site_path()))} på serveren"))
    return kit.render_page("Lokal opsætning", body, active="settings-site",
                           subtitle="Det, der kun gælder denne server – gemt lokalt, aldrig i programmet.",
                           breadcrumbs=[("Indstillinger", "/settings"), ("Lokal opsætning", None)])


@app.post(URL)
@ui.admin_required
def site_save():
    site = siteconfig.load()
    if site.status == "invalid":
        return ui.respond("Filen config/site.yml kan ikke læses – ret den på serveren først.", ok=False,
                          next_url=URL)
    changes, problems = form_changes(request.form, (*MAIN, *MORE, *siteconfig.COMPAT_KEYS))
    if problems:
        ui.audit("site_config", result="rejected", detail="; ".join(problems)[:300], actor=_actor())
        return ui.respond("Ikke gemt: " + "; ".join(problems[:4]), ok=False, next_url=URL)
    changed = {k: v for k, v in changes.items()
               if siteconfig.clean_value(k, v)[0] != site.values.get(k) or site.status != "ok"}
    changed["setup_done"] = True
    ok, problems = siteconfig.save(changed)
    if not ok:
        ui.audit("site_config", result="rejected", detail="; ".join(problems)[:300], actor=_actor())
        return ui.respond("Ikke gemt: " + "; ".join(problems[:4]), ok=False, next_url=URL)
    keys = sorted(k for k in changed if k != "setup_done")
    ui.audit("site_config", detail="ændret: " + (", ".join(keys) or "intet"), actor=_actor())
    siteconfig.reload()
    ui.request_reload()
    text = "Lokal opsætning gemt. Filteret genstarter med de nye værdier."
    if RSPAMD_KEYS & set(keys):
        text += " rspamd-reglerne får dem ved næste start af containeren."
    return ui.respond(text, ok=True, next_url=URL)
