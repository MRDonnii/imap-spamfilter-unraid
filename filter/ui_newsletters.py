"""Nyhedsbreve (2.6, plan item A4) - spamfilter web UI.

  * /newsletters?account=X: what the newsletter folder did for one mailbox
    the last 7 days - in "Prøv" (shadow) the mails that WOULD have been
    moved (sender, subject, date, why), in "Til" the mails moved to the
    folder with "Tilbage til indbakken", and the senders kept in the
    inbox (with "Fjern" so they may be moved again);
  * the line on the Oversigt mailbox card ("N nyhedsbreve ville være
    flyttet de seneste 7 dage");
  * the "Tilbage til indbakken" button on a message detail page.

Access: the page needs login + the mailbox (require_account); the actions
need the 'release' permission (route policy) on that mailbox (object
check). The setting itself (Fra / Prøv / Til) lives on the admin account
page (ui_admin). Sender and subject are attacker-chosen text: always
escaped.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

from flask import abort, request

import dashboard as ui
import newsletters as nl
import ui_kit as kit
from ui_kit import h

log = logging.getLogger("dashboard.newsletters")
app = ui.app

PAGE = "/newsletters"
LIST_MAX = 300
BACK_LABEL = "Tilbage til indbakken"
MODE_TONES = {"off": "neutral", "shadow": "info", "on": "ok"}
MODE_EXPLAIN = {
    "off": "Nyhedsbreve og reklamer bliver i indbakken.",
    "shadow": ("Prøv: intet flyttes. Filteret noterer kun, hvilke nyhedsbreve og reklamer det ville flytte, "
               "så du kan se listen, før du slår det til."),
    "on": "Til: nyhedsbreve og reklamer under spamgrænsen flyttes til mappen {folder}.",
}


def _svc(fn: str, *args: Any, default: Any = None, **kwargs: Any) -> Any:
    try:
        return getattr(ui.services, fn)(*args, **kwargs)
    except Exception as ex:  # noqa: BLE001 - a service failure must not kill the page
        log.warning("services.%s failed: %s", fn, type(ex).__name__)
        return default


def _actor() -> str:
    return (ui.current_user() or {}).get("name", "")


def _n(n: int, one: str, many: str) -> str:
    return f"{kit.fmt_int(n)} {one if n == 1 else many}"


def page_url(account: str) -> str:
    return f"{PAGE}?account={quote(account, safe='')}"


def mode_of(acc: Any) -> str:
    return nl.mode_of(acc)


def effective_mode(acc: Any) -> str:
    """'on' only moves while the account is in Filtrér (mode move)."""
    m = mode_of(acc)
    return "shadow" if m == "on" and not nl.moves_enabled(acc) else m


def _count(account: str, event: str, days: int = nl.LIST_DAYS) -> int:
    import time  # noqa: PLC0415

    row = ui.query("SELECT COUNT(DISTINCT message_id) AS n FROM events WHERE account=? AND event=? AND ts>=?",
                   [account, event, int(time.time()) - days * 86400], one=True, default=None)
    try:
        return int(row["n"] or 0) if row is not None else 0
    except (IndexError, KeyError, TypeError):
        return 0


def shadow_count(account: str) -> int:
    return _count(account, nl.EVENT_SHADOW)


def moved_count(account: str) -> int:
    return _count(account, nl.EVENT_MOVE)


def card_line(acc: Any) -> str:
    """One line for the Oversigt mailbox card (empty when off / nothing)."""
    if acc is None:
        return ""
    mode = effective_mode(acc)
    name = acc.name
    if mode == "shadow":
        n = shadow_count(name)
        text = f"{_n(n, 'nyhedsbrev', 'nyhedsbreve')} ville være flyttet de seneste 7 dage"
    elif mode == "on":
        n = moved_count(name)
        text = f"{_n(n, 'nyhedsbrev', 'nyhedsbreve')} flyttet til {nl.folder_of(acc)} de seneste 7 dage"
    else:
        return ""
    return (f'<a class="acct-skips acct-newsletters" href="{h(page_url(name))}" '
            f'title="Se listen over nyhedsbreve og reklamer">{kit.icon("mails")}<span>{h(text)}</span></a>')


def back_form(account: str, message_id: str, *, next_url: str, size: str = "sm") -> str:
    inner = (kit.hidden("account", account) + kit.hidden("message_id", message_id) + kit.hidden("next", next_url)
             + kit.button(BACK_LABEL, kind="secondary", icon="undo", tone="info", size=size,
                          attrs=kit.confirm_attrs(
                              "Flyt tilbage til indbakken?",
                              "Mailen flyttes tilbage, og mails fra afsenderen bliver i indbakken fremover. "
                              "Filteret lærer ikke noget af det.", confirm=BACK_LABEL)))
    return kit.post_form(f"{PAGE}/back", inner, cls="inline-form")


def detail_actions(row: Any, account: str, here: str) -> str:
    """'Tilbage til indbakken' on a message detail page (moved newsletters)."""
    try:
        action = row["our_action"]
        mid = str(row["message_id"])
    except (IndexError, KeyError, TypeError):
        return ""
    if action not in (nl.ACTION_MOVED, nl.ACTION_FAILED) or not ui.can("release", account):
        return ""
    return (f'<div class="act-grid">{back_form(account, mid, next_url=here, size="")}</div>'
            f'<p class="act-note">Flyttet til nyhedsbreve af filteret. Mails fra afsenderen bliver i '
            f"indbakken, når du flytter den tilbage.</p>")


def _who(sender: Any) -> str:
    name, addr = kit.sender_parts(sender)
    who = name or addr or "Ukendt afsender"
    return (f'<span class="mail-from">{h(who)}</span>'
            + (f'<span class="faint small mono"> {h(addr)}</span>' if name and addr else ""))


def _signals(sigs: list[str]) -> str:
    seen: list[str] = []
    for s in sigs:
        t = nl.signal_text(s)
        if t and t not in seen:
            seen.append(t)
    return " ".join(kit.chip(t, "neutral") for t in seen[:3])


def _detail_link(account: str, mid: str, text: str) -> str:
    if not ui.can("see_messages", account):
        return h(text)
    return (f'<a href="/messages/{h(quote(account, safe=""))}/{kit.token_for(mid)}">{h(text)}</a>')


def _shadow_table(account: str) -> str:
    items = nl.recent(ui.db(), account, nl.EVENT_SHADOW, limit=LIST_MAX)
    rows = [[_who(it["sender"]),
             _detail_link(account, it["message_id"], (it["subject"] or "").strip() or "(intet emne)"),
             f'<time datetime="{kit.iso_ts(it["received_at"] or it["ts"])}">'
             f'{h(kit.fmt_ts(it["received_at"] or it["ts"]))}</time>',
             _signals(it["signals"])] for it in items]
    return kit.table([("Afsender", ""), ("Emne", ""), ("Dato", ""), ("Hvorfor", "")], rows,
                     empty="Ingen nyhedsbreve fundet de seneste 7 dage.")


def _moved_table(account: str, here: str) -> str:
    may = ui.can("release", account)
    rows = ui.query("SELECT message_id, sender, subject, received_at, last_seen FROM messages "
                    "WHERE account=? AND our_action IN (?, ?) ORDER BY COALESCE(last_seen, received_at) DESC "
                    "LIMIT ?", [account, nl.ACTION_MOVED, nl.ACTION_FAILED, LIST_MAX], default=[]) or []
    out = []
    for r in rows:
        mid = str(r["message_id"])
        out.append([_who(r["sender"]),
                    _detail_link(account, mid, (r["subject"] or "").strip() or "(intet emne)"),
                    f'<time datetime="{kit.iso_ts(r["received_at"])}">{h(kit.fmt_ts(r["received_at"]))}</time>',
                    back_form(account, mid, next_url=here) if may else ""])
    return kit.table([("Afsender", ""), ("Emne", ""), ("Modtaget", ""), ("", "end")], out,
                     empty="Ingen mails ligger i nyhedsbreve-mappen lige nu.")


def _kept_table(account: str, here: str) -> str:
    may = ui.can("release", account)
    rows = []
    for k in nl.kept_senders(ui.db(), account):
        btn = ""
        if may:
            inner = (kit.hidden("account", account) + kit.hidden("sender", k["sender"]) + kit.hidden("next", here)
                     + kit.button("Fjern", kind="ghost", icon="x", size="sm",
                                  attrs=kit.confirm_attrs(f"Fjern {k['sender']} fra listen?",
                                                          "Nyhedsbreve fra afsenderen kan så flyttes igen.",
                                                          confirm="Fjern")))
            btn = kit.post_form(f"{PAGE}/unkeep", inner, cls="inline-form")
        rows.append([f'<span class="mono">{h(k["sender"])}</span>', h(kit.fmt_ts(k["created_at"])), btn])
    return kit.table([("Afsender", ""), ("Siden", ""), ("", "end")], rows,
                     empty="Ingen endnu. Flytter du et nyhedsbrev tilbage til indbakken, kommer afsenderen her.")


@app.get(PAGE)
@ui.login_required
def newsletters_page():
    accounts = [a for a in ui.visible_accounts()]
    if not accounts:
        return kit.render_page("Nyhedsbreve", kit.empty_state("Ingen postkasser", "Du har ikke adgang til nogen "
                                                              "postkasser endnu.", "mails"), active="overview")
    name = request.args.get("account") or accounts[0].name
    ui.require_account(name)
    acc = ui.account_by_name(name)
    if acc is None:
        abort(404)
    here = page_url(name)
    mode = mode_of(acc)
    eff = effective_mode(acc)
    folder = nl.folder_of(acc)
    explain = MODE_EXPLAIN[mode].format(folder=folder)
    if mode == "on" and eff != "on":
        explain += " Kontoen filtrerer ikke (Filtrér er slået fra), så indtil videre flyttes intet."
    chip = kit.chip(f"Nyhedsbreve: {nl.MODE_TEXT[mode]}", MODE_TONES[mode])
    switch = ""
    if len(accounts) > 1:
        switch = kit.seg_links([(ui.account_label(a.name), page_url(a.name), a.name == name) for a in accounts])
    settings = (kit.button("Indstillinger", href=f"/accounts/{quote(name, safe='')}#nyhedsbreve", kind="secondary",
                           icon="settings", size="sm") if ui.is_admin() else "")
    stats = (f'<div class="trust-stats"><div><b class="num">{kit.fmt_int(shadow_count(name))}</b>'
             f'<span>Ville være flyttet</span></div><div><b class="num">{kit.fmt_int(moved_count(name))}</b>'
             f'<span>Flyttet</span></div><div><b class="num">{kit.fmt_int(len(nl.kept_senders(ui.db(), name)))}</b>'
             f'<span>Bliver i indbakken</span></div></div>')
    body = (switch
            + kit.card(f'<p class="muted">{h(explain)}</p>' + stats
                       + '<p class="faint small">Spam går altid til Spamfilter-mappen. Kun mails under spamgrænsen '
                         "med afmeldingslink eller masseudsendelse regnes som nyhedsbreve – aldrig mails fra kendte "
                         "kontakter, afsendere du har svaret, tilladte afsendere, ordrer, fakturaer, leveringer, "
                         "koder eller invitationer.</p>",
                       title="Nyhedsbreve og reklamer", subtitle="De seneste 7 dage", actions=chip + settings))
    if mode != "off" or shadow_count(name):
        body += kit.card(_shadow_table(name), title="Ville være flyttet",
                         subtitle="Det, filteret ville have lagt i nyhedsbreve – intet af det er flyttet",
                         cls="flush")
    body += kit.card(_moved_table(name, here), title=f"Flyttet til {folder}",
                     subtitle="Flyt en mail tilbage, hvis den skal blive i indbakken", cls="flush")
    body += kit.card(_kept_table(name, here), title="Bliver altid i indbakken",
                     subtitle="Afsendere, hvis mails ikke flyttes til nyhedsbreve", cls="flush")
    return kit.render_page("Nyhedsbreve", body, active="overview", subtitle=ui.account_label(name),
                           breadcrumbs=[("Oversigt", "/"), ("Nyhedsbreve", None)])


def _post_account() -> str:
    name = (request.form.get("account") or "").strip()
    if not name or ui.account_by_name(name) is None:
        abort(404)
    ui.require("release", name)
    return name


@app.post(f"{PAGE}/back")
@ui.permission_required("release")
def newsletters_back():
    name = _post_account()
    mid = (request.form.get("message_id") or "").strip()[:500]
    back = ui.safe_next(request.form.get("next") or "", page_url(name))
    res = _svc("newsletter_to_inbox", name, mid, _actor(), default=None)
    if not isinstance(res, dict):
        return ui.respond("Det kunne ikke lade sig gøre lige nu.", ok=False, next_url=back)
    ok = bool(res.get("ok"))
    ui.audit("newsletter_back", name, result="ok" if ok else "rejected",
             detail=f"code={res.get('code')}" + (f" kept={res.get('sender_kept')}" if res.get("sender_kept") else ""),
             message_id=mid)
    return ui.respond(str(res.get("text") or ""), ok=ok, next_url=back, reload=ok)


@app.post(f"{PAGE}/unkeep")
@ui.permission_required("release")
def newsletters_unkeep():
    name = _post_account()
    sender = (request.form.get("sender") or "").strip()[:254]
    back = ui.safe_next(request.form.get("next") or "", page_url(name))
    res = _svc("newsletter_unkeep", name, sender, _actor(), default=None)
    if not isinstance(res, dict):
        return ui.respond("Det kunne ikke gemmes lige nu.", ok=False, next_url=back)
    if res.get("code") == "ok":
        ui.audit("newsletter_unkeep", name, detail=sender[:200])
    return ui.respond(str(res.get("text") or ""), ok=bool(res.get("ok")), next_url=back, reload=bool(res.get("ok")))
