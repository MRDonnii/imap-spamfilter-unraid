"""Indstillinger -> "Nye beskyttelser" (2.8) - spamfilter.

Fra / Prøv / Til for QR-code phishing (qrscan.py) and ClamAV's third-party
signatures (Sanesecurity, trialmode 'clam3p'), with what each would have
done in Prøv over the last 7 days. Admin only; every change is audited.
"""

from __future__ import annotations

import contextlib
import json
import logging
import time
from typing import Any

from flask import request

import dashboard as ui
import trialmode
import ui_kit as kit
from ui_kit import h

log = logging.getLogger("dashboard.trials")
app = ui.app

ANCHOR = "nye-beskyttelser"
SETTINGS_URL = f"/settings#{ANCHOR}"
MODE_OPTIONS = tuple((m, trialmode.MODE_TEXT[m]) for m in trialmode.MODES)
TRIAL_EVENTS = {f: (f"{f}_trial", f"{f}_hit") for f in trialmode.FEATURES}
SIGS_STATUS = "/run/spamfilter/sigs/status.json"


def counts(conn: Any, feature: str, days: int = 7) -> dict[str, int]:
    trial, hit = TRIAL_EVENTS[feature]
    since = int(time.time()) - days * 86400
    out = {"trial": 0, "hit": 0}
    with contextlib.suppress(Exception):
        for ev, n in conn.execute("SELECT event, count(DISTINCT account || message_id) FROM events "
                                  "WHERE event IN (?, ?) AND ts > ? GROUP BY event", (trial, hit, since)):
            out["trial" if ev == trial else "hit"] = int(n)
    return out


def _sigs_line() -> str:
    try:
        with open(SIGS_STATUS, encoding="utf-8") as fh:
            st = json.load(fh)
    except (OSError, ValueError):
        return '<p class="faint small">Listerne er ikke hentet endnu (de hentes et par minutter efter start).</p>'
    files = int(st.get("files") or 0)
    when = st.get("last_update_ts") or st.get("ts")
    bad = st.get("failed") or {}
    txt = f"{files} lister hentet" + (f", senest opdateret {kit.fmt_ts(when)}" if when else "")
    if bad:
        txt += f" · {len(bad)} kunne ikke hentes: " + ", ".join(sorted(bad)[:4])
    return f'<p class="faint small">{h(txt)}</p>'


RECENT_LIMIT = 6


def recent(conn: Any, feature: str, days: int = 30, limit: int = RECENT_LIMIT) -> list[dict[str, Any]]:
    """2.13: the newest mails a protection found (Prøv or Til), newest first,
    one row per mail: {account, message_id, ts, sender, subject, hit, detail}."""
    trial, hit = TRIAL_EVENTS[feature]
    since = int(time.time()) - days * 86400
    out: list[dict[str, Any]] = []
    with contextlib.suppress(Exception):
        rows = conn.execute(
            "SELECT e.account, e.message_id, MAX(e.ts), e.event, e.detail, m.sender, m.subject FROM events e "
            "LEFT JOIN messages m ON m.account=e.account AND m.message_id=e.message_id "
            "WHERE e.event IN (?, ?) AND e.ts > ? GROUP BY e.account, e.message_id ORDER BY MAX(e.ts) DESC LIMIT ?",
            (trial, hit, since, int(limit))).fetchall()
        for acc, mid, ts, ev, detail, sender, subject in rows:
            out.append({"account": acc, "message_id": mid, "ts": ts, "hit": ev == hit, "detail": detail or "",
                        "sender": sender or "", "subject": subject or ""})
    return out


def _recent_html(items: list[dict[str, Any]]) -> str:
    if not items:
        return '<p class="faint small">Ingen fund de sidste 30 dage.</p>'
    import ui_mail  # noqa: PLC0415 - detail links

    lis = []
    for it in items:
        who = kit.sender_parts(it["sender"])[1] or it["sender"] or "ukendt afsender"
        subj = (it["subject"] or "(intet emne)")[:90]
        tag = "point" if it["hit"] else "Prøv"
        link = ui_mail._detail_url(it["account"], it["message_id"])
        lis.append(f'<li><a href="{h(link)}">{h(subj)}</a> <span class="faint small">{h(who)} · '
                   f'{h(ui.account_label(it["account"]))} · {h(kit.fmt_ts(it["ts"]))} · {tag}</span></li>')
    return f'<ul class="trial-recent">{"".join(lis)}</ul>'


def _feature_form(feature: str, mode: str, n: dict[str, int], items: list[dict[str, Any]] | None = None) -> str:
    meta = trialmode.FEATURES[feature]
    def mails(k: int) -> str:
        return f"{kit.fmt_int(k)} {'mail' if k == 1 else 'mails'}"

    seen = (f"Sidste 7 dage: {mails(n['hit'])} med point, {kit.fmt_int(n['trial'])} i Prøv"
            if n["hit"] else f"Sidste 7 dage: {mails(n['trial'])} i Prøv")
    found = ""
    if items:
        found = (f'<details class="trial-found"><summary>Seneste fund ({len(items)})</summary>'
                 f"{_recent_html(items)}</details>")
    elif items is not None:
        found = '<p class="faint small">Ingen fund de sidste 30 dage.</p>'

    inner = (kit.hidden("feature", feature)
             + kit.form_field(meta["title"], kit.segmented("mode", MODE_OPTIONS, mode),
                              hint=f"{meta['text']} Prøv: ingen point, kun registrering. {seen}.")
             + (_sigs_line() if feature == "clam3p" else "")
             + found
             + f'<div class="form-actions">{kit.button("Gem", kind="secondary", icon="check")}</div>')
    return kit.post_form("/settings/trials/mode", inner)


def settings_card() -> str:
    try:
        with contextlib.closing(ui._connect()) as conn:
            forms = "".join(_feature_form(f, trialmode.get(conn, f)["mode"], counts(conn, f), recent(conn, f))
                            for f in trialmode.FEATURES)
    except Exception as ex:  # noqa: BLE001 - one card must not break Indstillinger
        log.warning("trials card failed: %s", type(ex).__name__)
        return ""
    return (f'<div id="{ANCHOR}"></div>'
            + kit.card(forms, title="Nye beskyttelser",
                       subtitle="Ekstra regler mod phishing. Prøv viser, hvad de ville fange, før de må give point."))


@app.post("/settings/trials/mode")
@ui.admin_required
def settings_trials_mode():
    feature = (request.form.get("feature") or "").strip()
    value = (request.form.get("mode") or "").strip().lower()
    if feature not in trialmode.FEATURES or value not in trialmode.MODES:
        return ui.respond("Vælg Fra, Prøv eller Til.", ok=False, next_url=SETTINGS_URL)
    try:
        with contextlib.closing(ui._connect()) as conn:
            with conn:
                changed = trialmode.set_mode(conn, feature, value, (ui.current_user() or {}).get("name", ""))
    except Exception as ex:  # noqa: BLE001
        log.error("trial mode save failed: %s", type(ex).__name__)
        return ui.respond("Det kunne ikke gemmes lige nu.", ok=False, next_url=SETTINGS_URL)
    title = trialmode.FEATURES[feature]["title"]
    if not changed:
        return ui.respond("Uændret.", next_url=SETTINGS_URL)
    ui.audit("trial_mode", detail=f"{feature}={value}")
    return ui.respond(f"{title}: {trialmode.MODE_TEXT[value]}. Filteret bruger det inden for et halvt minut.",
                      next_url=SETTINGS_URL, reload=True)
