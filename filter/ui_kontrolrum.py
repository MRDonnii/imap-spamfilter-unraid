"""Kontrolrum single sign-on (2.9.0, owner request "option A").

Adgang for programmer -> card "Login fra Kontrolrum (SSO)" (admin, 2.11.0;
on Indstillinger -> "Kontrolrum" before): make the SSO key ("Lav
SSO-nøgle" shows it ONCE; it is stored encrypted), make a new one, turn SSO
off, and set the exact IP address(es) Kontrolrum calls from. On a user's
page: the checkbox "Må logges ind fra Kontrolrum" (default off).

The handshake itself (POST /login/kontrolrum), the key storage and the
per-request session binding live in dashboard.py (kr_sso_*).
"""

from __future__ import annotations

import logging
from urllib.parse import quote

from flask import Response, request

import dashboard as ui
import ui_kit as kit
from ui_kit import h

log = logging.getLogger("dashboard.kontrolrum")
app = ui.app

ANCHOR = "kontrolrum"
SETTINGS_URL = f"/access#{ANCHOR}"


def _actor() -> str:
    return (ui.current_user() or {}).get("name", "")


def _q(name: str) -> str:
    return quote(str(name), safe="")


# ---------------------------------------------------------------------------
# "Adgang for programmer" card
# ---------------------------------------------------------------------------


def _key_forms(exists: bool) -> str:
    if exists:
        attrs = kit.confirm_attrs("Lav en ny SSO-nøgle?",
                                  "Den gamle nøgle holder op med at virke med det samme, og Kontrolrum bliver logget "
                                  "ud. Sæt den nye nøgle ind i Kontrolrum bagefter.", confirm="Lav ny nøgle")
        btn = kit.button("Lav ny SSO-nøgle", kind="secondary", icon="refresh", size="sm", attrs=attrs, short="Ny nøgle")
    else:
        btn = kit.button("Lav SSO-nøgle", kind="primary", icon="key", size="sm")
    # Not ajax: the reply is the page that shows the new key once.
    forms = kit.post_form("/settings/kontrolrum/key", btn, ajax=False, cls="inline-form")
    if exists:
        attrs = kit.confirm_attrs("Slå login fra Kontrolrum fra?",
                                  "Nøglen slettes, og Kontrolrum bliver logget ud af spamfilteret.",
                                  confirm="Slå fra", tone="danger")
        forms += kit.post_form("/settings/kontrolrum/off",
                               kit.button("Slå fra", kind="secondary", tone="bad", size="sm", attrs=attrs),
                               cls="inline-form")
    return forms


def _status_html(st: dict) -> str:
    if not st.get("exists"):
        return (f'<div class="ha-state tone-neutral">{kit.icon("key")}<div><b>Slået fra</b>'
                "<span>Lav en SSO-nøgle, og sæt den ind i Kontrolrum. Nøglen vises kun én gang.</span></div></div>")
    if not st.get("readable"):
        return (f'<div class="ha-state tone-warn">{kit.icon("alert-triangle")}<div><b>Nøglen kan ikke læses</b>'
                "<span>Fx efter en gendannelse uden dashboard_secret. Lav en ny nøgle, og sæt den ind i "
                "Kontrolrum.</span></div></div>")
    used = (f"Senest brugt {kit.ago(st.get('last_used_at'))} fra {st.get('last_used_ip')}"
            + (f" som {st.get('last_used_user')}" if st.get("last_used_user") else "")
            if st.get("last_used_at") else "Ikke brugt endnu")
    return (f'<div class="ha-state tone-ok">{kit.icon("check-circle")}<div><b>Slået til</b>'
            f'<span>Nøgle <span class="mono">{h(st.get("fingerprint"))}…</span> lavet '
            f'{h(kit.fmt_ts(st.get("created_at")))}' + (f' af {h(st.get("created_by"))}' if st.get("created_by") else "")
            + f".</span><span>{h(used)}.</span></div></div>")


def _peers_form(st: dict) -> str:
    value = ", ".join(st.get("peers") or [])
    hint = ("Den eller de præcise IP-adresser, Kontrolrum kalder spamfilteret fra (ikke et net). Uden en adresse "
            "virker login fra Kontrolrum ikke. Står der et afvist forsøg herunder, kan du se adressen dér. Cloudflare-"
            "tunnellens adresse kan ikke bruges.")
    return kit.post_form(
        "/settings/kontrolrum/peers",
        kit.form_field("Kontrolrums IP-adresse", kit.input_("kontrolrum_ips", value, attrs=(
            'placeholder="fx 172.31.250.2" autocomplete="off" spellcheck="false" maxlength="400"')), hint=hint)
        + f'<div class="form-actions">{kit.button("Gem adresse", kind="secondary", icon="check", size="sm")}</div>')


def _tile(label: str, value: str, sub: str = "", *, mono: bool = False) -> str:
    return (f'<div class="ak-tile"><div class="ak-tile-l">{h(label)}</div>'
            f'<div class="ak-tile-v{" mono" if mono else ""}">{h(value)}</div>'
            + (f'<div class="ak-tile-s">{h(sub)}</div>' if sub else "") + "</div>")


def _tiles(st: dict) -> str:
    if not st.get("exists") or not st.get("readable"):
        return ""
    users = st.get("users") or []
    try:
        total = len(ui.load_users())
    except Exception:  # noqa: BLE001 - a tile must not break the page
        total = len(users)
    if st.get("last_used_at"):
        used, used_sub = kit.ago(st.get("last_used_at")), (
            (f"af {st.get('last_used_user')} " if st.get("last_used_user") else "") + f"fra {st.get('last_used_ip')}")
    else:
        used, used_sub = "Ikke brugt endnu", ""
    return ('<div class="ak-tiles">'
            + _tile("Nøgle", f"SSO · {st.get('fingerprint')}", "fingeraftryk, ikke selve nøglen", mono=True)
            + _tile("Oprettet", kit.fmt_ts(st.get("created_at")),
                    f"af {st.get('created_by')}" if st.get("created_by") else "")
            + _tile("Sidst brugt", used, used_sub)
            + _tile("Brugere", f"{len(users)} af {total}", "må logge ind fra Kontrolrum")
            + "</div>")


def access_card() -> str:
    """'Login fra Kontrolrum (SSO)' on Adgang for programmer (admin, 2.11.0;
    the same functions as the 2.9 card on Indstillinger)."""
    st = ui.kr_sso_status()
    if not st.get("exists"):
        state = kit.badge("Slået fra", "neutral")
    elif not st.get("readable"):
        state = kit.badge("Kan ikke læses", "warn")
    else:
        state = kit.badge("Slået til", "ok")
    actions = (kit.button("Vælg brugere", href="/users", kind="secondary", icon="users", size="sm")
               + _key_forms(bool(st.get("exists"))))
    head = ('<div class="card-head ak-head"><div class="ak-titles">'
            f'<span class="ak-ticon tone-grape">{kit.icon("t-login")}</span><div>'
            f'<h2 class="card-title">Login fra Kontrolrum (SSO) {state}</h2>'
            '<p class="card-sub">Browser-login for personer. Nøglen deles kun med Kontrolrum og vises én gang, når '
            "den laves. Her ses kun dens fingeraftryk.</p></div></div>"
            f'<div class="card-actions ak-actions">{actions}</div></div>')
    warn = ""
    if st.get("proxy_peers"):
        warn = kit.alert("Adressen " + ", ".join(st["proxy_peers"]) + " er en betroet proxy (TRUSTED_PROXIES) og "
                         "tæller ikke: gennem den kan alle på internettet komme. Brug Kontrolrums egen adresse.",
                         "warn", title="Adressen bruges ikke")
    elif st.get("exists") and not st.get("peers"):
        warn = kit.alert("Skriv Kontrolrums IP-adresse herunder. Indtil da afvises alle login fra Kontrolrum.",
                         "warn", title="Mangler Kontrolrums adresse")
    users = st.get("users") or []
    users_html = (('<p class="small">Må logges ind fra Kontrolrum: '
                   + ", ".join(f'<a class="card-link" href="/users/{h(_q(n))}#kontrolrum">{h(n)}</a>' for n in users)
                   + ".</p>") if users else
                  '<p class="faint small">Ingen brugere må logges ind fra Kontrolrum endnu. Sæt fluebenet på '
                  'brugerens side under <a class="card-link" href="/users">Brugere</a>.</p>')
    rej = ""
    if st.get("rejected_at") and int(st.get("rejected_at") or 0) > int(st.get("last_used_at") or 0):
        reason = ui.KR_SSO_REASON_TEXT.get(st.get("rejected_reason") or "", st.get("rejected_reason") or "")
        rej = (f'<p class="faint small ha-rej">{kit.icon("alert-triangle")}<span>Seneste afviste forsøg '
               f'{h(kit.ago(st.get("rejected_at")))} fra <span class="mono">{h(st.get("rejected_ip"))}</span>'
               f" ({h(reason)}).</span></p>")
    hero = "" if st.get("exists") and st.get("readable") else _status_html(st)
    more = ('<details class="disclosure ak-more"' + ("" if st.get("peers") else " open") + "><summary>"
            + kit.icon("chevron-right") + "Kontrolrums adresse og brugere</summary>"
            '<p class="muted">Kontrolrum skal ikke kende nogen adgangskode: det får nøglen og logger kun ind som de '
            "brugere, der har fluebenet “Må logges ind fra Kontrolrum”. Sessionen virker kun fra Kontrolrums egen "
            "adresse; adgangskoder til “Kun lokalt”-brugere virker stadig kun hjemme.</p>"
            + _peers_form(st) + users_html + "</details>")
    body = head + warn + hero + _tiles(st) + rej + more
    return f'<div id="{ANCHOR}"><section class="card ha-card ak-card">{body}</section></div>'


def _key_page(key: str, replaced: bool) -> Response:
    head = kit.alert("Kopiér den nu – den vises kun denne ene gang og kan ikke findes igen. "
                     + ("Den gamle nøgle virker ikke længere." if replaced else ""), "warn",
                     title="Ny SSO-nøgle til Kontrolrum")
    box = (f'<div class="secret-key ha-key"><code class="mono" data-secret>{h(key)}</code>'
           + kit.button("Kopiér", kind="ghost", icon="copy", size="sm",
                        attrs=f'type="button" data-copy-text="{h(key)}" data-copy-label="Nøglen"')
           + "</div>")
    steps = ('<ol class="ha-steps">'
             "<li>Åbn Spamfilter-tjenesten i Kontrolrum, og sæt nøglen ind under <b>Automatisk login → "
             "SSO-nøgle</b>. Brugernavnet er den bruger, Kontrolrum skal logge ind som.</li>"
             "<li>Sæt fluebenet “Må logges ind fra Kontrolrum” på den bruger under Brugere.</li>"
             "<li>Skriv Kontrolrums IP-adresse under Adgang for programmer → Login fra Kontrolrum, hvis den ikke "
             "står der.</li></ol>")
    body = head + kit.card(box + steps + '<div class="form-actions">'
                           + kit.button("Færdig", href=SETTINGS_URL, kind="primary", icon="check") + "</div>",
                           title="Nøglen", cls="ha-card")
    html = kit.render_page("Kontrolrum", body, active="access",
                           subtitle="Nøglen lader Kontrolrum logge ind uden adgangskode – kun fra Kontrolrums adresse.",
                           breadcrumbs=[("Adgang for programmer", SETTINGS_URL), ("Login fra Kontrolrum", None)])
    return Response(html, mimetype="text/html")


@app.post("/settings/kontrolrum/key")
@ui.admin_required
def settings_kontrolrum_key():
    replaced = bool(ui.kr_sso_status().get("exists"))
    try:
        key = ui.kr_sso_create(_actor())
    except Exception as ex:  # noqa: BLE001 - DB/crypto trouble: say so, never a stack trace
        log.warning("kontrolrum sso key create failed: %s", type(ex).__name__)
        return ui.respond("Nøglen kunne ikke laves lige nu.", ok=False, next_url=SETTINGS_URL)
    ui.audit("kontrolrum_sso_key", detail="ny nøgle (erstattede den gamle)" if replaced else "ny nøgle")
    return _key_page(key, replaced)


@app.post("/settings/kontrolrum/off")
@ui.admin_required
def settings_kontrolrum_off():
    try:
        had = ui.kr_sso_disable(_actor())
    except Exception as ex:  # noqa: BLE001
        log.warning("kontrolrum sso disable failed: %s", type(ex).__name__)
        return ui.respond("Login fra Kontrolrum kunne ikke slås fra lige nu.", ok=False, next_url=SETTINGS_URL)
    if had:
        ui.audit("kontrolrum_sso_off")
    return ui.respond("Login fra Kontrolrum er slået fra, og nøglen er slettet." if had
                      else "Login fra Kontrolrum var ikke slået til.", next_url=SETTINGS_URL, reload=had)


@app.post("/settings/kontrolrum/peers")
@ui.admin_required
def settings_kontrolrum_peers():
    ips, bad = ui.parse_kr_peers((request.form.get("kontrolrum_ips") or "")[:400])
    if bad:
        return ui.respond("Kunne ikke læse: " + ", ".join(bad[:3]) + ". Skriv hele IP-adresser, fx 172.31.250.2 "
                          "(ikke et net som /24).", ok=False, next_url=SETTINGS_URL)
    if len(ips) > ui.KR_SSO_MAX_PEERS:
        return ui.respond(f"Højst {ui.KR_SSO_MAX_PEERS} adresser.", ok=False, next_url=SETTINGS_URL)
    proxies = [ip for ip in ips if ui.is_trusted_proxy(ip)]
    if proxies:
        return ui.respond(", ".join(proxies) + " er en betroet proxy (fx Cloudflare-tunnellen). Gennem den kan alle "
                          "komme, så den kan ikke være Kontrolrums adresse.", ok=False, next_url=SETTINGS_URL)
    old = ui.kr_sso_peers_configured()
    if ips == old:
        return ui.respond("Adressen er uændret.", next_url=SETTINGS_URL)
    ui.set_kr_sso_peers(ips, _actor())
    ui.audit("kontrolrum_sso_peers", detail=f"{', '.join(old) or '-'} -> {', '.join(ips) or '-'}")
    return ui.respond("Kontrolrums adresse er gemt." if ips else "Kontrolrums adresse er fjernet – login fra "
                      "Kontrolrum afvises nu.", next_url=SETTINGS_URL, refresh=True)


# ---------------------------------------------------------------------------
# The user's checkbox
# ---------------------------------------------------------------------------


def user_card(name: str) -> str:
    """'Kontrolrum' card on /users/<name> (admin)."""
    on = ui.kr_sso_allowed(name)
    st = ui.kr_sso_status()
    note = ("" if st.get("exists") else
            '<p class="faint small">Login fra Kontrolrum er slået fra under '
            f'<a class="card-link" href="{SETTINGS_URL}">Adgang for programmer → Login fra Kontrolrum</a>, så '
            "fluebenet gør intet endnu.</p>")
    inner = (f'<div class="field field-switch">{kit.switch("kontrolrum_sso", on, "Må logges ind fra Kontrolrum")}'
             '<span class="field-hint">Kontrolrum må logge ind som denne bruger uden adgangskode og to-trins-kode – '
             "kun fra Kontrolrums adresse og med SSO-nøglen. Også når brugeren er “Kun lokalt”, men kun gennem "
             "Kontrolrum. Brug det kun til Kontrolrums egen bruger.</span></div>" + note
             + f'<div class="form-actions">{kit.button("Gem", kind="secondary", icon="check", size="sm")}</div>')
    return (f'<div id="{ANCHOR}">'
            + kit.card(kit.post_form(f"/users/{_q(name)}/kontrolrum", inner), title="Kontrolrum")
            + "</div>")


@app.post("/users/<name>/kontrolrum")
@ui.admin_required
def user_kontrolrum(name: str):
    back = f"/users/{_q(name)}"
    if name not in ui.load_users():
        return ui.respond("Brugeren findes ikke.", ok=False, next_url="/users", status=404)
    on = (request.form.get("kontrolrum_sso") or "") in ("1", "on", "true", "yes")
    if not ui.set_kr_sso_allowed(name, on, _actor()):
        return ui.respond("Uændret.", next_url=back)
    ui.audit("user_kontrolrum_sso", detail=f"{name} {'til' if on else 'fra'}")
    return ui.respond(f"{name} må nu logges ind fra Kontrolrum." if on
                      else f"{name} må ikke længere logges ind fra Kontrolrum – sessionen fra Kontrolrum er "
                           "logget ud.", next_url=back, refresh=True)
