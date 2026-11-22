"""Adgang for programmer (2.11.0, shared plan "API-nøgler i alle apps").

One admin page with the two ways in without a password, side by side:

  * Login fra Kontrolrum (SSO) for PEOPLE - the 2.9 card, unchanged in
    function (ui_kontrolrum.access_card, routes /settings/kontrolrum/*).
  * API-nøgler for PROGRAMS - several named keys (dashboard.api_key_*): a
    list (name, sf_…hint, right, made, last used + IP), "Ny API-nøgle"
    (name, right, home network only, expiry), the key shown ONCE in a
    dialog, delete one key without touching the others. The old Home
    Assistant token shows up as "Home Assistant" with the badge "Flyttet".

Below the list: the Home Assistant help (ui_ha.help_card). Nothing here
ever shows a stored key or its hash; audit records name the key, not the
key.
"""

from __future__ import annotations

import logging

from flask import Response, request

import dashboard as ui
import ui_kit as kit
from ui_kit import h

log = logging.getLogger("dashboard.access")
app = ui.app

PAGE_URL = "/access"
ANCHOR = "api-noegler"
EXPIRY_CHOICES = (("0", "Aldrig"), ("30", "Om 30 dage"), ("90", "Om 90 dage"), ("365", "Om 1 år"))
SCOPE_TEXT = {
    "read": "Se status og tal, fx Home Assistant-sensorer og Kontrolrum-kortet. Kan ikke ændre noget.",
    "control": "Også styre den daglige drift, fx scan nu og frigiv en mail. Spamfilter har endnu ingen "
               "styre-kald, så i dag kan nøglen det samme som Kun læse.",
    "admin": "Alt, også brugere og indstillinger. Brug den kun, hvis programmet virkelig skal. Spamfilter har "
             "endnu ingen kald, der kræver det.",
}
SCOPE_TONE = {"read": "neutral", "control": "brand", "admin": "warn"}


def _actor() -> str:
    return (ui.current_user() or {}).get("name", "")


# ---------------------------------------------------------------------------
# Pieces
# ---------------------------------------------------------------------------


def _ticon(icon: str, tone: str) -> str:
    return f'<span class="ak-ticon tone-{h(tone)}">{kit.icon(icon)}</span>'


def _dialog(mid: str, icon: str, tone: str, title: str, body: str, actions: str, *,
            auto_open: bool = False, closable: bool = True) -> str:
    """A <dialog> like kit.modal, with the icon tile of the mockup. With
    auto_open it is rendered open (no JS: shown in the page) and app.js
    turns it into a modal on load."""
    close = (f'<button type="button" class="icon-btn" data-close-modal aria-label="Luk">{kit.icon("x")}</button>'
             if closable else "")
    return (f'<dialog class="modal ak-modal" id="{h(mid)}" aria-labelledby="{h(mid)}-title"'
            + (" open data-auto-open" if auto_open else "") + ">"
            f'<div class="modal-card"><div class="modal-head ak-modal-head">{_ticon(icon, tone)}'
            f'<h2 id="{h(mid)}-title">{h(title)}</h2>{close}</div>'
            f'<div class="modal-body ak-modal-body">{body}</div>'
            f'<div class="modal-actions">{actions}</div></div></dialog>')


def _explain() -> str:
    def box(icon: str, tone: str, title: str, text: str) -> str:
        return (f'<section class="card ak-explain">{_ticon(icon, tone)}<div><h2 class="ak-explain-t">{h(title)}</h2>'
                f'<p class="muted">{h(text)}</p></div></section>')

    return ('<div class="grid grid-2 ak-explains">'
            + box("t-login", "grape", "Til personer: Login fra Kontrolrum",
                  "Du er logget ind i Kontrolrum og trykker dig herind. Du får dine egne rettigheder, og der står "
                  "dit navn i loggen.")
            + box("t-key", "brand", "Til programmer: API-nøgler",
                  "Home Assistant, Kontrolrum-kort, scripts. Én nøgle pr. program, så du kan slette én uden at de "
                  "andre holder op.")
            + "</div>")


def _scope_badge(key: dict) -> str:
    return kit.badge(key["scope_label"], SCOPE_TONE.get(key["scope"], "neutral"))


def _date(ts: int | None) -> str:
    """'i dag 09:40', 'i går 18:02', else '14. sep. 2026'."""
    if not ts:
        return "–"
    text = kit.fmt_ts(ts)
    return text if text.startswith(("i dag", "i går")) else kit.fmt_date(ts)


def _name_cell(key: dict) -> str:
    tags = []
    if key["migrated"]:
        tags.append(kit.badge("Flyttet", "ok"))
    if key["expired"]:
        tags.append(kit.badge("Udløbet", "bad"))
    elif key["expires_at"]:
        tags.append(f'<span class="faint small">udløber {h(kit.fmt_date(key["expires_at"]))}</span>')
    if not key["lan_only"]:
        tags.append(kit.badge("Også udefra", "warn"))
    return (f'<div class="ak-name"><b>{h(key["name"])}</b>{"".join(tags)}</div>'
            f'<div class="mono faint small">{h(ui.api_key_label(key))}</div>')


def _created_cell(key: dict) -> str:
    sub = "flyttet fra den gamle nøgle" if key["migrated"] else (key["created_by"] or "")
    return f'<div>{h(_date(key["created_at"]))}</div>' + (f'<div class="faint small">{h(sub)}</div>' if sub else "")


def _used_cell(key: dict) -> str:
    unused = key["unused"]
    if not key["last_used_at"]:
        out = '<div class="faint">Aldrig brugt endnu</div>'
        return out + (f'<div>{kit.badge("Ubrugt i 90 dage", "warn")}</div>' if unused else "")
    dot = f'<span class="dot tone-{"warn" if unused else "ok"}" aria-hidden="true"></span>'
    out = f'<div class="ak-used">{dot}<span>{h(kit.ago(key["last_used_at"]))}</span></div>'
    out += f'<div class="mono faint small">{h(key["last_used_ip"])}</div>'
    if unused:
        out += f'<div>{kit.badge("Ubrugt i 90 dage", "warn")}</div>'
    return out


def _delete_cell(key: dict) -> str:
    used = (f"Sidst brugt {kit.ago(key['last_used_at'])} fra {key['last_used_ip']}. " if key["last_used_at"]
            else "")
    attrs = kit.confirm_attrs(f"Slet nøglen “{key['name']}”?",
                              used + "Programmer, der bruger den, holder op med at få svar med det samme. "
                              "De andre nøgler virker som før.", confirm="Slet nøglen", tone="danger")
    btn = (f'<button type="submit" class="icon-btn ak-del" aria-label="Slet nøglen {h(key["name"])}" '
           f'title="Slet nøglen" {attrs}>{kit.icon("trash")}</button>')
    return kit.post_form(f"{PAGE_URL}/api-keys/{int(key['id'])}/delete", btn, cls="inline-form")


def _keys_card(keys: list[dict]) -> str:
    head = ('<div class="card-head ak-head"><div class="ak-titles">' + _ticon("t-key", "brand")
            + f'<div><h2 class="card-title">API-nøgler <span class="badge tone-neutral">{len(keys)}</span></h2>'
            '<p class="card-sub">Til programmer. Hver nøgle har sit eget navn og sin egen rettighed og kan slettes '
            "alene.</p></div></div>"
            '<div class="card-actions ak-actions">'
            + kit.button("Ny API-nøgle", kind="primary", icon="plus", size="sm",
                         attrs='type="button" data-open-modal="ak-new"')
            + "</div></div>")
    rows = [{"cells": [_name_cell(k), _scope_badge(k), _created_cell(k), _used_cell(k), _delete_cell(k)],
             "attrs": f'data-key-id="{int(k["id"])}"'} for k in keys]
    table = kit.table(["Navn", "Rettighed", "Oprettet", "Sidst brugt", ("", "ak-act")], rows,
                      empty=kit.empty_state("Ingen API-nøgler endnu",
                                            "Lav en nøgle til hvert program, der skal hente tal fra spamfilteret, "
                                            "fx Home Assistant eller Kontrolrum.", icon="key"),
                      cls="ak-table")
    foot = ""
    rej = ui.api_key_rejected()
    if rej:
        foot += (f'<div class="ak-foot">{kit.icon("alert-triangle")}<span>Sidst afvist: {h(kit.ago(rej["at"]))} fra '
                 f'<span class="mono">{h(rej["ip"])}</span> ({h(rej["reason_text"])})</span></div>')
    foot += (f'<div class="ak-foot">{kit.icon("lock")}<span>Nøglerne gemmes kun som SHA-256 og kan ikke vises igen. '
             f'Send dem som <code class="mono">Authorization: Bearer {h(ui.API_KEY_PREFIX)}…</code>. Mistet nøgle: '
             "slet den og lav en ny.</span></div>")
    return f'<div id="{ANCHOR}"><section class="card ak-card">{head}{table}{foot}</section></div>'


def _new_dialog() -> str:
    choices = "".join(
        f'<label class="rd-choice" for="ak-scope-{s}"><input class="rd-radio" type="radio" name="scope" '
        f'id="ak-scope-{s}" value="{s}"' + (" checked" if s == "read" else "") + '>'
        '<span class="rd-dot" aria-hidden="true"></span><span class="rd-text">'
        f'<span class="rd-title">{h(ui.API_KEY_SCOPE_LABEL[s])}</span><span class="rd-desc">{h(SCOPE_TEXT[s])}'
        "</span></span></label>" for s in ui.API_KEY_SCOPES)
    body = (kit.form_field("Navn", kit.input_("name", "", attrs=(
                f'id="ak-name" required maxlength="{ui.API_KEY_NAME_MAX}" autocomplete="off" spellcheck="false" '
                'placeholder="fx Home Assistant" form="ak-new-form"')),
                hint="Navnet på programmet, der skal bruge nøglen. Det står i listen og i loggen.")
            + '<div class="field"><span class="field-label">Rettighed</span>'
            + f'<fieldset class="rd-choices tone-brand" form="ak-new-form">{choices}</fieldset></div>'
            + '<div class="ak-row"><div class="field field-switch">'
            + kit.switch("lan_only", True, "Kun fra hjemmenetværket", attrs='form="ak-new-form"')
            + '<span class="field-hint">Afvis kald udefra, også gennem tunnellen. En nøgle med rettigheden '
            + 'Administrator virker altid kun hjemme.</span></div>'
            + kit.form_field("Udløber", kit.select("expires_days", EXPIRY_CHOICES, "0",
                                                   attrs='id="ak-expires" form="ak-new-form"'))
            + "</div>")
    # The radio inputs sit inside the fieldset, not the form: give them the
    # form attribute too (fieldset@form does not reach its children).
    body = body.replace('class="rd-radio" type="radio"', 'class="rd-radio" form="ak-new-form" type="radio"')
    form = kit.post_form(f"{PAGE_URL}/api-keys", "", ajax=False, attrs='id="ak-new-form"')
    actions = (form + kit.button("Annullér", kind="secondary", attrs="type=\"button\" data-close-modal")
               + kit.button("Lav nøglen", kind="primary", icon="plus", attrs='form="ak-new-form"'))
    return _dialog("ak-new", "t-key", "brand", "Ny API-nøgle", body, actions)


def _expiry_text(key: dict) -> str:
    return f"udløber {kit.fmt_date(key['expires_at'])}" if key["expires_at"] else "udløber aldrig"


def _shown_dialog(token: str, key: dict) -> str:
    import ui_ha  # noqa: PLC0415 - registered by ui_mail

    meta = " · ".join([key["scope_label"], "kun fra hjemmenetværket" if key["lan_only"] else "også udefra",
                       _expiry_text(key)])
    short = f"{token[:12]}…{token[-4:]}"
    body = (f'<div class="ak-warn">{kit.icon("alert-triangle")}<div><b>Kopiér nøglen nu – den vises kun én gang</b>'
            "<span>Bagefter kan hverken du eller Spamfilter se den igen. Mister du den, sletter du den og laver en "
            "ny.</span></div></div>"
            '<div class="field"><span class="field-label">API-nøgle</span>'
            f'<span class="field-hint">{h(meta)}</span>'
            f'<div class="ak-secret"><code class="mono" data-secret>{h(token)}</code>'
            + kit.button("Kopiér", kind="primary", icon="copy",
                         attrs=f'type="button" data-copy-text="{h(token)}" data-copy-label="Nøglen"')
            + "</div></div>"
            '<div class="field"><span class="field-label">Sådan bruges den</span>'
            f'<pre class="ak-usage"><code>Authorization: Bearer {h(short)}</code></pre></div>'
            '<details class="disclosure"><summary>' + kit.icon("chevron-right") + "Til Home Assistant</summary>"
            + ui_ha.secrets_block(token)
            + '<p class="faint small">Pakken med sensorerne står under “Home Assistant” på denne side.</p></details>'
            '<label class="ak-check"><input type="checkbox" id="ak-saved" data-enables="ak-done"> '
            "<span>Jeg har gemt nøglen i programmet eller et sikkert sted</span></label>")
    actions = kit.button("Færdig", href=PAGE_URL, kind="primary", attrs='id="ak-done" data-needs-check="ak-saved"')
    return _dialog("ak-shown", "check", "ok", f"Nøglen “{key['name']}” er lavet", body, actions,
                   auto_open=True, closable=False)


def _page_html(extra: str = "") -> str:
    import ui_ha  # noqa: PLC0415 - registered by ui_mail
    import ui_kontrolrum  # noqa: PLC0415 - registered by ui_admin

    try:
        keys = ui.api_keys_list()
    except Exception as ex:  # noqa: BLE001 - say so, never a stack trace
        log.warning("api key list failed: %s", type(ex).__name__)
        keys_html = kit.alert("Nøglerne kan ikke læses lige nu.", "bad", title="API-nøgler")
    else:
        keys_html = _keys_card(keys)
    try:
        sso = ui_kontrolrum.access_card()
    except Exception as ex:  # noqa: BLE001 - one card must not break the page
        log.warning("kontrolrum card failed: %s", type(ex).__name__)
        sso = ""
    body = (_explain() + f'<div class="stack ak-stack">{sso}{keys_html}{ui_ha.help_card()}</div>'
            + _new_dialog() + extra)
    return kit.render_page("Adgang for programmer", body, active="access",
                           subtitle="Hvem og hvad der må tale med Spamfilter uden at logge ind med kodeord")


# ---------------------------------------------------------------------------
# Routes (admin)
# ---------------------------------------------------------------------------


@app.get(PAGE_URL)
@ui.admin_required
def access_page():
    return Response(_page_html(), mimetype="text/html")


@app.post(f"{PAGE_URL}/api-keys")
@ui.admin_required
def access_api_key_create():
    f = request.form
    try:
        days = int(f.get("expires_days") or 0)
    except ValueError:
        days = -1
    if str(days) not in {v for v, _l in EXPIRY_CHOICES}:
        return ui.respond("Vælg hvornår nøglen udløber.", ok=False, next_url=PAGE_URL)
    lan_only = (f.get("lan_only") or "") in ("1", "on", "true", "yes")
    try:
        token, key = ui.api_key_create((f.get("name") or "")[:200], str(f.get("scope") or ""), _actor(),
                                       lan_only=lan_only, expires_days=days)
    except ValueError as ex:
        return ui.respond(str(ex), ok=False, next_url=PAGE_URL)
    except Exception as ex:  # noqa: BLE001 - DB trouble: say so, never a stack trace
        log.warning("api key create failed: %s", type(ex).__name__)
        return ui.respond("Nøglen kunne ikke laves lige nu.", ok=False, next_url=PAGE_URL)
    ui.audit("api_key_create", detail=f"{key['name']} (#{key['id']}, {key['scope']}, "
                                      f"{'hjemmenet' if key['lan_only'] else 'også udefra'}, "
                                      f"{_expiry_text(key)}, …{key['hint']})")
    resp = Response(_page_html(_shown_dialog(token, key)), mimetype="text/html")
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.post(f"{PAGE_URL}/api-keys/<int:key_id>/delete")
@ui.admin_required
def access_api_key_delete(key_id: int):
    try:
        key = ui.api_key_delete(key_id)
    except Exception as ex:  # noqa: BLE001
        log.warning("api key delete failed: %s", type(ex).__name__)
        return ui.respond("Nøglen kunne ikke slettes lige nu.", ok=False, next_url=PAGE_URL)
    if key is None:
        return ui.respond("Nøglen findes ikke (længere).", ok=False, next_url=PAGE_URL, status=404)
    ui.audit("api_key_delete", detail=f"{key['name']} (#{key['id']}, {key['scope']}, {ui.api_key_label(key)})")
    return ui.respond(f"Nøglen “{key['name']}” er slettet. De andre nøgler virker som før.", next_url=PAGE_URL,
                      reload=True)
