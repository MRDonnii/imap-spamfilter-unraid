"""DMARC (2.6, C2) - the admin page /dmarc - spamfilter.

  * per own domain, the last 30 days of DMARC aggregate reports
    (dmarc.summaries): mails, % passing DMARC, reports, the published
    policy, the top sending sources (IP + cached reverse DNS) marked
    "godkendt" / "fejler", and a plain-language recommendation;
  * the settings (settings_kv 'dmarc'): the rua address, per mailbox
    Automatisk / Til / Fra, extra own domains - and the DNS records to
    publish (including the RFC 7489 7.1 permission record when the rua
    address lives in another domain).

Access: admin only (dashboard.admin_required). Report content is
attacker-controllable (org names, IPs, PTR names): always escaped, never
a link. Changes are audited ('dmarc_settings').
"""

from __future__ import annotations

import logging
from typing import Any

from flask import request

import dashboard as ui
import dmarc
import ui_kit as kit
from ui_kit import h

log = logging.getLogger("dashboard.dmarc")
app = ui.app

URL = "/dmarc"
MODES = (("auto", "Automatisk"), ("on", "Til"), ("off", "Fra"))
POLICY_TEXT = {"none": "p=none (kun rapporter)", "quarantine": "p=quarantine (karantæne)",
               "reject": "p=reject (afvis)"}


def _actor() -> str:
    return (ui.current_user() or {}).get("name", "")


def _settings() -> dict[str, Any]:
    try:
        return dmarc.normalize_settings(ui._kv_json(dmarc.SETTINGS_KEY) or {})
    except Exception as ex:  # noqa: BLE001 - the page must render
        log.warning("dmarc settings failed: %s", type(ex).__name__)
        return dmarc.normalize_settings({})


def _known_domains(settings: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for acc in ui.effective_accounts():
        d = dmarc.clean_domain(str(getattr(acc, "user", "")).rpartition("@")[2])
        if d and d not in out:
            out.append(d)
    for d in settings.get("domains") or []:
        if d not in out:
            out.append(d)
    return out


def _summaries(settings: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        conn = ui.db()
        dmarc.ensure_schema(conn)
        conn.commit()
        try:
            # Reverse DNS only here (not in the scan): a few uncached source
            # IPs per page view, cached for two weeks.
            dmarc.resolve_for_page(conn)
            conn.commit()
        except Exception as ex:  # noqa: BLE001 - names are cosmetic
            log.info("dmarc reverse dns skipped: %s", type(ex).__name__)
        return dmarc.summaries(conn, domains=_known_domains(settings))
    except Exception as ex:  # noqa: BLE001
        log.warning("dmarc summaries failed: %s", type(ex).__name__)
        return []


def _source_rows(d: dict[str, Any]) -> list[list[str]]:
    rows = []
    for s in d.get("sources") or []:
        who = f'<span class="mono">{h(s["ip"])}</span>'
        if s.get("ptr"):
            who += f'<span class="kv-sub">{h(s["ptr"])}</span>'
        via = s.get("dkim_domain") or s.get("spf_domain") or ""
        rows.append([who, h(kit.fmt_int(s["total"])), kit.badge(s["status"], s["tone"]),
                     f'<span class="mono small">{h(via)}</span>' if via else '<span class="muted">–</span>'])
    return rows


def _domain_card(d: dict[str, Any]) -> str:
    adv = d.get("advice") or {}
    if not d.get("reports"):
        body = kit.alert(adv.get("text") or "Ingen rapporter endnu.", "info")
        return kit.card(body, title=d["domain"], subtitle="Ingen DMARC-rapporter endnu.")
    pct = d.get("pct")
    pol = POLICY_TEXT.get(str(d.get("policy") or ""), f"p={d.get('policy') or '?'}")
    if d.get("policy_pct") not in (None, 100):
        pol += f", pct={d['policy_pct']}"
    tone = "" if pct is None else ("ok" if pct >= dmarc.READY_PCT else "warn" if pct >= 90 else "bad")
    kpis = ('<div class="kpis">'
            + kit.kpi("Mails", int(d.get("total") or 0), sub="de seneste 30 dage")
            + kit.kpi("Består DMARC", "–" if pct is None else f"{dmarc._pct_da(pct)} %",
                      sub=f"{kit.fmt_int(d.get('passed') or 0)} godkendt", tone=tone)
            + kit.kpi("Rapporter", int(d.get("reports30") or 0),
                      sub=f"fra {d.get('orgs')} {'afsender' if d.get('orgs') == 1 else 'afsendere'}")
            + kit.kpi("Politik", str(d.get("policy") or "?"), sub=pol)
            + "</div>")
    advice = kit.alert(adv.get("text") or "", {"ok": "ok", "warn": "warn"}.get(adv.get("tone", ""), "info"),
                       title=f"Anbefaling: {adv['label']}" if adv.get("label") else "Anbefaling")
    if adv.get("label"):
        # 2.12 (#6): the low-volume criterion, visible at a glance.
        advice = f'<p class="row-tight">{kit.badge(str(adv["label"]), "ok")}</p>' + advice
    table = kit.table(["Kilde", ("Mails", "num"), "Status", "Godkendt via"], _source_rows(d),
                      empty="Ingen kilder de seneste 30 dage.")
    last = kit.fmt_ts(d.get("last_ts")) if d.get("last_ts") else "–"
    return kit.card(kpis + advice + '<h3 class="card-title small">Største afsendere</h3>' + table,
                    title=d["domain"], subtitle=f"Seneste rapport dækker til {last}.")


def _settings_card(settings: dict[str, Any]) -> str:
    rows = []
    for acc in ui.effective_accounts():
        explicit = (settings.get("accounts") or {}).get(acc.name)
        effective = dmarc.account_mode(settings, acc)
        sel = kit.select(f"acc:{acc.name}", MODES, explicit or "auto")
        rows.append(kit.form_field(f"{acc.name} ({getattr(acc, 'user', '')})", sel,
                                   hint="Tager imod rapporter nu." if effective == "on" else "Tager ikke imod rapporter."))
    rua = settings.get("rua") or ""
    inner = (kit.form_field("Adresse til rapporterne (rua)", kit.input_("rua", rua, type="email",
                                                                         attrs='autocomplete="off"'),
                            hint="Den adresse, der står i rua=mailto: i jeres DMARC-poster. Rapporterne til den "
                                 "flyttes til mappen “DMARC-rapporter” og bliver aldrig bedømt som spam.")
             + "".join(rows)
             + kit.form_field("Flere egne domæner", kit.textarea("domains", "\n".join(settings.get("domains") or []),
                                                                 rows=3),
                              hint="Ét domæne pr. linje, fx domæner der ikke har en postkasse her.")
             + kit.button("Gem", icon="check"))
    hints = []
    for dom in _known_domains(settings):
        for line in dmarc.dns_hint(dom, rua or dmarc.DEFAULT_RUA):
            hints.append(f'<li><code class="mono small">{h(line)}</code></li>')
    dns = ('<h3 class="card-title small">DNS-poster</h3><p class="muted small">Start med p=none. Når siden '
           'anbefaler det, skiftes til p=quarantine og senere p=reject. Ligger rua-adressen i et andet domæne, '
           'skal det domæne give lov med den ekstra post.</p><ul class="stack stack-tight">'
           + "".join(hints) + "</ul>") if hints else ""
    return kit.card(kit.post_form(f"{URL}/settings", f'<div class="stack">{inner}</div>') + dns,
                    title="Indstillinger", subtitle="Hvem modtager rapporterne, og hvilke domæner er jeres.")


@app.get(URL)
@ui.admin_required
def dmarc_page():
    import ui_admin as adm  # noqa: PLC0415 - layout helpers

    settings = _settings()
    data = _summaries(settings)
    with_data = [d for d in data if d.get("reports")]
    head = ""
    if not with_data:
        head = kit.card(kit.empty_state(
            "Ingen DMARC-rapporter endnu",
            "Udgiv DMARC-poster med rua=mailto:" + (settings.get("rua") or dmarc.DEFAULT_RUA)
            + " (se DNS-poster nedenfor). Rapporterne kommer typisk 1–2 døgn senere og vises så her.",
            "shield-check"))
    body = (head + "".join(_domain_card(d) for d in data) + _settings_card(settings))
    return adm._page("DMARC", body, active="dmarc",
                     subtitle="Hvem sender mail som jeres domæner – og består de tjekket? De seneste 30 dage.")


@app.post(f"{URL}/settings")
@ui.admin_required
def dmarc_settings():
    rua_in = (request.form.get("rua") or "").strip()[:254]
    rua = dmarc._clean_addr(rua_in)
    if rua_in and not rua:
        return ui.respond("Adressen er ikke en gyldig mailadresse.", ok=False, next_url=URL)
    accounts = {}
    for acc in ui.effective_accounts():
        v = request.form.get(f"acc:{acc.name}") or "auto"
        if v in ("on", "off"):
            accounts[acc.name] = v
    raw_domains = (request.form.get("domains") or "")[:4000].replace(",", "\n").split()
    domains, bad = [], []
    for d in raw_domains:
        cd = dmarc.clean_domain(d)
        (domains if cd else bad).append(cd or d)
    if bad:
        return ui.respond(f"Ugyldigt domæne: {kit.clean_name(bad[0])[:80]}", ok=False, next_url=URL)
    new = dmarc.normalize_settings({"rua": rua, "accounts": accounts, "domains": domains})
    try:
        ui._kv_put(dmarc.SETTINGS_KEY, new)
    except Exception as ex:  # noqa: BLE001
        log.warning("dmarc settings save failed: %s", type(ex).__name__)
        return ui.respond("Indstillingerne kunne ikke gemmes lige nu.", ok=False, next_url=URL)
    ui.audit("dmarc_settings", detail=(f"rua={new['rua'] or '-'} "
                                       + " ".join(f"{k}={v}" for k, v in sorted(new["accounts"].items()))
                                       + (f" domæner={','.join(new['domains'])}" if new["domains"] else ""))[:400])
    return ui.respond("Gemt. Filteret bruger de nye indstillinger ved næste scanning.", next_url=URL, reload=True)
