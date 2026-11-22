"""Min konto -> 'Beskeder på denne enhed' (2.5.0): push notifications.

Routes (all policy 'login' through the central policy, every POST CSRF
checked by dashboard._before; a user only ever reads or changes their OWN
subscriptions - every query is scoped to the logged-in name):

  GET  /me/push/key          {"ok", "key"}: the VAPID public key for
                             pushManager.subscribe (public by nature)
  POST /me/push/subscribe    endpoint, p256dh, auth, app=1 (installed app)
  POST /me/push/prefs        id + threat/review/problem switches
  POST /me/push/test         endpoint (this device) or none (all devices)
  POST /me/push/unsubscribe  endpoint ('Slå fra på denne enhed')
  POST /me/push/remove       id ('Fjern' in the device list)

The card works only in a secure context with a service worker and the
Push API (https://spamfilter.example.org as an installed app, iOS 16.4+);
app.js (initPush) shows the matching Danish explanation everywhere else.
Imported by ui_mail (like ui_tools/ui_contacts), so it is registered
wherever the mail pages are.
"""

from __future__ import annotations

from flask import jsonify, request

import dashboard as ui
import push
import ui_kit as kit
from ui_kit import h

app = ui.app
PREFS_FORM = ("threat", "review", "problem")


def _push():
    """push.py pointed at this dashboard's state dir / DB / config / users
    (tests move those attributes on the dashboard module)."""
    push.configure_paths(ui.STATE_DIR, ui.CONFIG_PATH, db_path=ui.DB_PATH, users_file=ui.USERS_FILE)
    return push


def _me() -> tuple[str, bool]:
    u = ui.current_user() or {}
    return str(u.get("name", "")), bool(u.get("is_admin"))


def _field(name: str, limit: int) -> str:
    return (request.form.get(name) or "").strip()[:limit]


# ---------------------------------------------------------------------------
# The card
# ---------------------------------------------------------------------------


def _why(key: str, title: str, text_html: str, tone: str = "info") -> str:
    return (f'<div class="alert tone-{tone} push-why" role="status" data-push-why="{h(key)}" hidden>'
            f'{kit.icon("info" if tone == "info" else "alert-triangle", "alert-icon")}<div class="alert-body">'
            f'<strong class="alert-title">{h(title)}</strong><span>{text_html}</span></div></div>')


def _device_row(d: dict, *, is_admin: bool) -> str:
    kinds = [k for k in PREFS_FORM if is_admin or k not in push.ADMIN_ONLY_KINDS]
    switches = "".join(
        f'<div class="push-pref">{kit.switch(k, d["prefs"].get(k, False), push.PREF_LABELS[k], attrs="data-switch-submit")}'
        f'<span class="field-hint">{h(push.PREF_HINTS[k])}</span></div>'
        for k in kinds)
    prefs = kit.post_form("/me/push/prefs", kit.hidden("id", d["id"]) + f'<div class="push-prefs">{switches}</div>'
                          + '<div class="form-actions nojs-only">'
                          + kit.button("Gem", kind="secondary", size="sm") + "</div>", cls="push-prefs-form")
    remove = kit.post_form("/me/push/remove", kit.hidden("id", d["id"]) + kit.button(
        "Fjern", kind="ghost", size="sm", icon="trash",
        attrs=kit.confirm_attrs("Fjern enheden?", "Enheden får ikke flere beskeder fra spamfilteret.",
                                confirm="Fjern", tone="danger")), cls="push-remove-form")
    last = (f"Sidste besked {h(kit.ago(d['last_ok_at']))}" if d.get("last_ok_at") else "Har ikke fået en besked endnu")
    warn = (f'<span class="chip tone-warn">{kit.icon("alert-triangle")}Seneste besked kom ikke frem</span>'
            if d.get("last_error") else "")
    return (f'<li class="push-device" data-row="push:{int(d["id"])}" data-push-hash="{h(d["hash"])}">'
            f'<div class="push-device-head">{kit.icon("smartphone")}<div class="push-device-name">'
            f'<b>{h(d["ua"])}</b> <span class="chip tone-brand push-this" data-push-this hidden>Denne enhed</span>'
            f'<span class="faint small">{last} · tilføjet {h(kit.fmt_date(d["created_at"]))}</span>{warn}</div>'
            f"{remove}</div>{prefs}</li>")


def push_card(name: str, *, is_admin: bool) -> str:
    """'Beskeder på denne enhed' for Min konto. Without JS (or before
    app.js has looked at the device) only the explanation is shown."""
    mod = _push()
    if not mod.available():
        return kit.card(kit.alert("Beskeder er ikke tilgængelige på denne installation.", "warn"),
                        title="Beskeder på denne enhed")
    try:
        devs = mod.devices(name, is_admin=is_admin)
    except Exception:  # noqa: BLE001 - a missing table must never break Min konto
        devs = []
    ext = ui.external_url()
    host = ext.split("://", 1)[-1] if ext.startswith("https://") else ""
    where = (f'<a class="card-link" href="{h(ext)}">{h(host)}</a>' if host
             else ("den eksterne https-adresse" if is_admin else "den adresse, du plejer at bruge på telefonen"))
    insecure = (f"Beskeder virker kun, når spamfilteret er åbnet fra {where} – ikke fra den lokale adresse på "
                "hjemmenetværket (http). Åbn det dér, og læg det på hjemmeskærmen." if is_admin else
                f"Beskeder virker kun i spamfilteret fra {where}. Åbn det dér, og læg det på hjemmeskærmen.")
    # The Bruger fallback is a relative clause: put it last so the sentence
    # stays correct Danish ("Åbn spamfilteret i Safari fra den adresse, du
    # plejer at bruge, tryk på Del ...").
    open_ios = (f"Åbn {where} i Safari" if host or is_admin
                else "Åbn spamfilteret i Safari fra den adresse, du plejer at bruge")
    whys = (
        _why("insecure", "Åbn spamfilteret fra den rigtige adresse", insecure)
        + _why("ios", "Læg først spamfilteret på hjemmeskærmen",
               f"På iPhone og iPad kan kun appen på hjemmeskærmen få beskeder (iOS 16.4 eller nyere). {open_ios}, "
               "tryk på Del og vælg <b>Føj til hjemmeskærm</b>. Åbn så appen fra ikonet og slå beskeder "
               "til her.")
        + _why("unsupported", "Denne browser kan ikke få beskeder",
               "Brug spamfilteret som app på hjemmeskærmen (iPhone med iOS 16.4 eller nyere) eller en nyere "
               "Chrome, Edge eller Firefox.")
        + _why("denied", "Beskeder er blokeret på enheden",
               "Du har sagt nej til beskeder fra spamfilteret. Slå dem til igen i telefonens indstillinger – på "
               "iPhone: Indstillinger → Notifikationer → Spamfilter → Tillad notifikationer. Prøv så igen her.",
               tone="warn"))
    checking = ('<p class="muted small push-checking" data-push-checking>'
                "Beskeder slås til fra appen på telefonen (kræver JavaScript).</p>")
    off = ('<div class="push-panel" data-push-off hidden><p class="muted">Få en besked på telefonen, når filteret '
           "stopper en farlig mail – og hvis du vil, når der er nye mails under Tjek disse.</p>"
           '<div class="form-actions">'
           + kit.button("Slå beskeder til", kind="primary", icon="bell", attrs='type="button" data-push-enable')
           + "</div></div>")
    test = kit.post_form("/me/push/test", '<input type="hidden" name="endpoint" value="" data-push-endpoint>'
                         + kit.button("Send testbesked", kind="secondary", icon="send"), cls="push-test-form")
    on = ('<div class="push-panel" data-push-on hidden>'
          f'<div class="install-status">{kit.icon("check-circle")}<span>Beskeder er slået til på denne enhed.</span></div>'
          f'<div class="form-actions push-actions">{test}'
          + kit.button("Slå fra på denne enhed", kind="ghost", icon="bell-off", attrs='type="button" data-push-disable')
          + "</div></div>")
    listing = ""
    if devs:
        rows = "".join(_device_row(d, is_admin=is_admin) for d in devs)
        listing = (f'<h3 class="push-h">Dine enheder <span class="badge tone-neutral">{len(devs)}</span></h3>'
                   f'<ul class="push-devices">{rows}</ul>'
                   '<p class="faint small">Beskederne siger kun, hvor mange mails det drejer sig om og i hvilken '
                   "postkasse – aldrig afsender eller emne.</p>")
    body = (f'<div class="push" data-push data-push-key-url="/me/push/key">{checking}{whys}{off}{on}{listing}</div>')
    return kit.card(body, title="Beskeder på denne enhed", subtitle="Push-beskeder direkte i appen.",
                    cls="push-card")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/me/push/key")
@ui.login_required
def me_push_key():
    mod = _push()
    if not mod.available():
        return ui.json_err(push.TEXTS["no_crypto"], 503)
    try:
        key = mod.public_key()
    except Exception as ex:  # noqa: BLE001 - unreadable key file
        ui.log.error("push key unavailable: %s", type(ex).__name__)
        return ui.json_err("Nøglen til beskeder kan ikke læses. Kør sfctl doctor.", 503)
    return jsonify({"ok": True, "key": key})


@app.post("/me/push/subscribe")
@ui.login_required
def me_push_subscribe():
    name, is_admin = _me()
    mod = _push()
    ua = mod.short_user_agent(request.headers.get("User-Agent", ""), app=_field("app", 2) == "1")
    res = mod.subscribe(name, _field("endpoint", 2048), _field("p256dh", 200), _field("auth", 100),
                        user_agent=ua, prefs=None, is_admin=is_admin)
    if res["ok"] and res["code"] == "ok":
        ui.audit("push_subscribe", detail=ua)
    return ui.respond(res["text"], ok=res["ok"], next_url="/me", status=409 if res.get("code") in ("taken", "too_many")
                      else 400, refresh=bool(res["ok"]))


@app.post("/me/push/prefs")
@ui.login_required
def me_push_prefs():
    name, is_admin = _me()
    try:
        sub_id = int(_field("id", 12))
    except ValueError:
        return ui.respond("Ugyldig enhed.", ok=False, next_url="/me")
    prefs = {k: (request.form.get(k) or "") in ("1", "on") for k in PREFS_FORM}
    if not _push().set_prefs(name, sub_id, prefs, is_admin=is_admin):
        # Not found and not yours look the same.
        return ui.respond("Enheden findes ikke.", ok=False, next_url="/me", status=404)
    return ui.respond("Valgene for enheden er gemt.", next_url="/me")


@app.post("/me/push/test")
@ui.login_required
def me_push_test():
    name, is_admin = _me()
    endpoint = _field("endpoint", 2048) or None
    res = _push().send_test(name, endpoint=endpoint, is_admin=is_admin)
    if res.get("sent"):
        ui.audit("push_test", detail=f"{res['sent']} enhed(er)")
    return ui.respond(res["text"], ok=res["ok"], next_url="/me", status=429 if res["code"] == "rate" else 400)


@app.post("/me/push/unsubscribe")
@ui.login_required
def me_push_unsubscribe():
    name, _ = _me()
    endpoint = _field("endpoint", 2048)
    removed = bool(endpoint) and _push().remove_endpoint(name, endpoint)
    if removed:
        ui.audit("push_unsubscribe")
    # Also fine when the server never knew this device: it is off either way.
    return ui.respond("Beskeder er slået fra på denne enhed.", next_url="/me", refresh=True)


@app.post("/me/push/remove")
@ui.login_required
def me_push_remove():
    name, _ = _me()
    try:
        sub_id = int(_field("id", 12))
    except ValueError:
        return ui.respond("Ugyldig enhed.", ok=False, next_url="/me")
    if not _push().remove(name, sub_id):
        return ui.respond("Enheden findes ikke.", ok=False, next_url="/me", status=404)
    ui.audit("push_remove")
    return ui.respond("Enheden er fjernet og får ikke flere beskeder.", next_url="/me",
                      rows={f"push:{sub_id}": None})


def forget_user(name: str) -> int:
    """A removed dashboard user: delete their devices (dashboard.forget_user_meta)."""
    try:
        return _push().delete_user(name)
    except Exception:  # noqa: BLE001
        return 0
