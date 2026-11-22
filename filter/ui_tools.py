"""Tools of the web UI (2.1): Find en mail, Fortryd flytninger and Hjælp.

  * Find en mail     /find             DB lookup first, then (on request) a
                                       read-only search of the mailbox folders
                                       (services.find_mail) with "Flyt til
                                       indbakken" (services.move_found_to_inbox)
  * Fortryd flytninger /undo           bulk undo of the filter's own moves in a
                                       period (services.preview_undo / undo_moves)
  * Hjælp            /help             plain-Danish guide, linkable per section
                     /help/familieguide.pdf  the family guide as a PDF (2.3.6)

Access goes through the central policy (dashboard decorators) plus the
object checks: a Bruger only ever sees and searches their own mailboxes;
moving mail needs the 'release' permission on that mailbox; without
'see_messages' the search leaves the inbox out (that permission is what
shows all mail). Nothing here deletes mail. Routes register on
dashboard.app when ui_mail (which imports this module) is loaded.
"""

from __future__ import annotations

import hashlib
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

from flask import abort, jsonify, redirect, request, send_file

import dashboard as ui
import ui_kit as kit
import ui_mail as mail
from ui_kit import h

log = logging.getLogger("dashboard.tools")
app = ui.app

FIND_PERIODS = ((7, "7 dage"), (30, "30 dage"), (90, "90 dage"))
FIND_DEFAULT_DAYS = 30
# Rows of mail that is (or was) somewhere in a spam folder: what a Bruger
# without 'see_messages' may find in the filter's history.
SPAM_KINDS = ("filter_junk", "provider_junk", "spam_like")
SPAMLIKE_ACTIONS = mail.CAUGHT_ACTIONS + mail.RELEASED_ACTIONS + ("manual_mark_spam", "user_junked")
KIND_ICONS = {"inbox": "inbox", "filter_junk": "shield-alert", "provider_junk": "shield", "spam_like": "mail-x",
              "trash": "trash"}

UNDO_PERIODS = (("hour", "Seneste time"), ("today", "I dag"), ("yesterday", "I går"), ("custom", "Vælg selv"))
UNDO_ACTIVE = ("queued", "running", "cancel_requested")
UNDO_STATUS = {
    "queued": ("Venter", "neutral"), "running": ("Flytter…", "brand"), "cancel_requested": ("Stopper…", "warn"),
    "done": ("Færdig", "ok"), "failed": ("Afbrudt", "bad"), "cancelled": ("Stoppet", "neutral"),
}


def _n(n: int, one: str, many: str) -> str:
    return f"{kit.fmt_int(n)} {one if n == 1 else many}"


def _actor() -> str:
    return (ui.current_user() or {}).get("name", "")


def _svc(fn: str, *args: Any, default: Any = None, **kwargs: Any) -> Any:
    try:
        return getattr(ui.services, fn)(*args, **kwargs)
    except Exception as ex:  # noqa: BLE001 - a service failure must not kill the page
        log.warning("services.%s failed: %s", fn, type(ex).__name__)
        return default


def _q(name: str) -> str:
    return quote(str(name), safe="")


def _page_js() -> str:
    return f'<script src="{h(ui.static_url("tools.js"))}" defer></script>'


# ---------------------------------------------------------------------------
# Find en mail
# ---------------------------------------------------------------------------


def _find_args(src: Any) -> tuple[str, str, int]:
    """(account, text, days) from request args/form; account '' = none chosen."""
    account = (src.get("account") or "").strip()
    text = " ".join((src.get("q") or "").split())[:100]
    try:
        days = int(src.get("days") or FIND_DEFAULT_DAYS)
    except (TypeError, ValueError):
        days = FIND_DEFAULT_DAYS
    if days not in {d for d, _l in FIND_PERIODS}:
        days = FIND_DEFAULT_DAYS
    return account, text, days


def _find_url(account: str, text: str, days: int) -> str:
    args = {k: v for k, v in (("account", account), ("q", text),
                              ("days", "" if days == FIND_DEFAULT_DAYS else str(days))) if v}
    return "/find" + (("?" + urlencode(args)) if args else "")


def _default_account(accounts: dict[str, Any], wanted: str) -> str:
    if wanted:
        ui.require_account(wanted)
        if wanted not in accounts:
            abort(404)
        return wanted
    return next(iter(accounts), "")


def _search_form(accounts: dict[str, Any], account: str, text: str, days: int) -> str:
    acct = (kit.form_field("Postkasse", kit.select("account", [(n, ui.account_label(n)) for n in accounts], account,
                                                    attrs='id="find-account"'))
            if len(accounts) > 1 else kit.hidden("account", account))
    period = ('<div class="field"><span class="field-label">Inden for</span><div class="segmented find-period" role="radiogroup">'
              + "".join(f'<label class="seg-opt"><input type="radio" name="days" value="{d}"'
                        + (" checked" if d == days else "") + f'><span>{h(lbl)}</span></label>'
                        for d, lbl in FIND_PERIODS) + "</div></div>")
    field = (f'<div class="field find-q"><label class="field-label" for="find-q">Afsender eller emne</label>'
             f'<label class="input-icon input-lg">{kit.icon("search")}'
             + kit.input_("q", text, type="search", attrs='id="find-q" required minlength="2" maxlength="100" '
                          'placeholder="Fx et navn, en adresse eller et ord fra emnet" autocomplete="off" '
                          'autocapitalize="none" spellcheck="false" enterkeyhint="search"')
             + "</label></div>")
    return (f'<form method="get" action="/find" class="find-form" role="search">{field}'
            f'<div class="find-row">{acct}{period}'
            f'<div class="find-go-wrap">{kit.button("Søg", kind="primary", icon="search", cls="find-go")}</div></div></form>')


def _where_label(row: dict, acc: Any) -> str:
    cf = str(row.get("current_folder") or "")
    if cf == "gone":
        return "Ikke længere i postkassen"
    if cf.lower() == str(getattr(acc, "inbox", "INBOX") or "INBOX").lower():
        return "Indbakken"
    if cf.lower() == str(getattr(acc, "junk", "") or "").lower():
        return "Spamfilter-mappen"
    if cf:
        return _folder_label(cf)
    return "Ukendt mappe"


def _folder_label(name: str) -> str:
    try:
        return str(ui.services.folder_label(name))
    except Exception:  # noqa: BLE001 - fake/older services
        return name


def _db_results(res: dict, account: str, acc: Any) -> str:
    rows = list(res.get("db") or [])
    if not ui.can("see_messages", account):
        rows = [r for r in rows if r.get("our_action") in SPAMLIKE_ACTIONS]
    if not rows:
        return ('<div class="find-none">' + kit.icon("database")
                + "<div><b>Filteret har ikke set en mail, der matcher</b>"
                "<span>Filteret kender kun mail, det selv har scannet. Søg i postkassen nedenfor – "
                "så kigger vi direkte i mapperne.</span></div></div>")
    thr = float(getattr(acc, "threshold", mail.DEFAULT_THRESHOLD) or mail.DEFAULT_THRESHOLD)
    lis = []
    for r in rows[:50]:
        mid = str(r.get("message_id") or "")
        name, addr = kit.sender_parts(r.get("sender"))
        who = name or addr or "Ukendt afsender"
        subject = (r.get("subject") or "").strip() or "(intet emne)"
        when = r.get("received_at") or r.get("first_seen")
        verdict = r.get("user_verdict")
        action = r.get("our_action")
        status = (kit.badge("Frigivet", "info") if verdict == "ham" and action not in mail.RELEASED_ACTIONS
                  else kit.badge(kit.action_label(action), kit.action_tone(action)))
        if r.get("threat"):
            status = kit.threat_badge(r.get("threat_text") or "Farlig mail", compact=True) + status
        where = _where_label(r, acc)
        link = mid and ui.can("see_messages", account)
        tag = f'<a class="find-main" href="{mail._detail_url(account, mid)}">' if link else '<div class="find-main">'
        lis.append(
            f'<li class="find-hit">{_score_or_icon(r.get("our_score"), thr, "database")}{tag}'
            f'<span class="find-who"><b>{h(who)}</b>' + (f'<span class="mail-addr">{h(addr)}</span>' if name and addr else "")
            + f'</span><span class="find-subj">{h(subject)}</span>'
            f'<span class="find-meta"><time datetime="{kit.iso_ts(when)}">{h(kit.fmt_ts(when))}</time>{status}'
            f'<span class="find-where">{kit.icon("folder")}{h(where)}</span></span>'
            + ("</a>" if link else "</div>") + "</li>")
    more = len(rows) - 50
    return (f'<ul class="find-list">{"".join(lis)}</ul>'
            + (f'<p class="faint small find-more">+ {_n(more, "mail mere", "mails mere")} – gør søgningen mere præcis.</p>'
               if more > 0 else ""))


def _score_or_icon(score: Any, thr: float, icon: str) -> str:
    """Administrators see the score; a Bruger a calm icon (no numbers)."""
    if score is not None and ui.is_admin():
        return kit.score_badge(score, thr)
    return f'<span class="find-kind">{kit.icon(icon)}</span>'


def _hit_key(folder: str, uid: Any, mid: str) -> str:
    return "find:" + hashlib.sha1(f"{folder}\0{uid}\0{mid}".encode()).hexdigest()[:16]


def _hit_html(account: str, group: dict, hit: dict, *, text: str, days: int, thr: float = mail.DEFAULT_THRESHOLD,
              moved: bool = False, result: str = "") -> str:
    folder = str(group.get("name") or "")
    mid = str(hit.get("message_id") or "")
    key = _hit_key(folder, hit.get("uid"), mid)
    name, addr = hit.get("sender_name") or "", hit.get("sender") or ""
    who = name or addr or "Ukendt afsender"
    subject = (hit.get("subject") or "").strip() or "(intet emne)"
    when = hit.get("received_at") or hit.get("date")
    chips = []
    if hit.get("known"):
        chips.append(kit.chip("Kendt af filteret", "brand"))
    if not hit.get("seen"):
        chips.append(kit.chip("Ulæst", "info"))
    if hit.get("deleted"):
        chips.append(kit.chip("Markeret slettet", "warn"))
    if hit.get("threat"):
        chips.insert(0, kit.threat_badge(hit.get("threat_text") or "Farlig mail", compact=True))
    action = ""
    if moved:
        action = (f'<span class="find-done">{kit.icon("check-circle")}'
                  f'{h(result or "Flyttet til indbakken")}</span>')
    elif group.get("can_move") and hit.get("can_move", True):
        if not mid:
            action = '<span class="faint small">Kan ikke flyttes herfra (mangler Message-ID) – træk den i dit mailprogram.</span>'
        elif hit.get("threat") and not ui.is_admin() and ui.can("release", account):
            # B16: a Bruger never moves a dangerous mail home.
            action = mail.locked_release()
        elif ui.can("release", account):
            inner = (kit.hidden("account", account) + kit.hidden("folder", folder) + kit.hidden("message_id", mid)
                     + kit.hidden("uid", str(hit.get("uid") or "")) + kit.hidden("q", text) + kit.hidden("days", str(days))
                     + kit.button("Flyt til indbakken", kind="secondary", tone="ok", icon="undo", size="sm"))
            action = kit.post_form("/find/move", inner, cls="inline-form")
    score = hit.get("our_score")
    return (f'<li class="find-hit" data-row="{h(key)}">'
            + _score_or_icon(score, thr, KIND_ICONS.get(str(group.get("kind")), "mail"))
            + f'<div class="find-main"><span class="find-who"><b>{h(who)}</b>'
            + (f'<span class="mail-addr">{h(addr)}</span>' if name and addr else "")
            + f'</span><span class="find-subj">{h(subject)}</span>'
            f'<span class="find-meta"><time datetime="{kit.iso_ts(when)}">{h(kit.fmt_ts(when))}</time>{"".join(chips)}</span></div>'
            f'<div class="find-act">{action}</div></li>')


def _hints(acc: Any, spamexperts: bool = False) -> list[tuple[str, str]]:
    """Per-mailbox advice when nothing was found anywhere. 2.11.1: the
    SpamExperts quarantine tip only while the domain's MX still points at
    SpamExperts (services.find_mail -> res["spamexperts"])."""
    host = str(getattr(acc, "imap_host", "") or "").lower()
    out: list[tuple[str, str]] = []
    if spamexperts and "scannet" in host:
        out.append(("shield", "Hos Scannet går posten først gennem SpamExperts (spamfilter.io). Stopper SpamExperts "
                              "en mail, når den aldrig frem til postkassen – den ligger i karantænen dér. Log ind i "
                              "SpamExperts' karantæne, eller bed Scannet om at frigive den."))
    if "gigahost" in host:
        out.append(("shield", "Gigahosts eget spamfilter lægger mistænkelig post i mappen Junk. Den er med i "
                              "søgningen ovenfor, så hvis den ikke er dér, er den ikke stoppet af Gigahost."))
    out += [
        ("calendar", "Prøv en længere periode – eller søg kun på en del af navnet eller adressen."),
        ("at-sign", "Er mailen sendt til en anden adresse (fx en fælles info-adresse)? Så ligger den i en anden postkasse."),
        ("send", "Bed afsenderen om at sende den igen. Nogle mails bliver afvist, allerede før de når frem."),
    ]
    return out


def _live_results(res: dict, account: str, acc: Any, text: str, days: int) -> str:
    code = res.get("code")
    if not res.get("ok") and code not in ("partial",):
        tone = "warn" if code == "throttled" else "bad"
        return kit.alert(res.get("text") or "Postkassen kunne ikke gennemsøges lige nu.", tone,
                         title="Søgningen i postkassen lykkedes ikke")
    groups = list(res.get("folders") or [])
    hide_inbox = not ui.can("see_messages", account)
    if hide_inbox:
        # Without Beskeder a Bruger only sees spam: the inbox and the trash
        # hold legitimate mail (the trash: deleted, but still legitimate).
        groups = [g for g in groups if g.get("kind") in SPAM_KINDS]
    searched = [str(x) for x in (res.get("searched") or [])]
    if hide_inbox:
        searched = [str(g.get("label") or g.get("name") or "") for g in groups]
    thr = float(getattr(acc, "threshold", mail.DEFAULT_THRESHOLD) or mail.DEFAULT_THRESHOLD)
    out = []
    if hide_inbox:
        out.append('<p class="faint small find-note">Du kan kun se spam, så der vises kun træffere fra '
                   "spam-mapperne.</p>")
    for err in res.get("errors") or []:
        out.append(kit.alert(err.get("text") or "Mappen kunne ikke gennemsøges.", "warn",
                             title=f"{err.get('label') or err.get('folder') or 'En mappe'} blev ikke gennemsøgt"))
    hits_total = 0
    for g in groups:
        hits = list(g.get("hits") or [])
        if not hits:
            continue
        hits_total += len(hits)
        count = int(g.get("count") or len(hits))
        lis = "".join(_hit_html(account, g, x, text=text, days=days, thr=thr) for x in hits)
        more = (f'<p class="faint small find-more">Viser de {len(hits)} nyeste af {kit.fmt_int(count)}. '
                "Gør søgningen mere præcis for at se resten.</p>" if g.get("truncated") or count > len(hits) else "")
        out.append(
            f'<section class="find-group kind-{h(g.get("kind") or "")}">'
            f'<div class="find-group-head"><span class="find-group-ic">{kit.icon(KIND_ICONS.get(str(g.get("kind")), "folder"))}</span>'
            f'<div><h3>{h(g.get("label") or g.get("name") or "")} <span class="badge tone-neutral">{kit.fmt_int(count)}</span></h3>'
            f'<p>{h(g.get("explanation") or "")}</p></div></div>'
            f'<ul class="find-list">{lis}</ul>{more}</section>')
    if not hits_total:
        hint_items = "".join(f'<li>{kit.icon(ic)}<span>{h(t)}</span></li>' for ic, t in _hints(acc, bool(res.get("spamexperts"))))
        where = ", ".join(searched) if searched else "postkassens mapper"
        out.append(f'<div class="find-none">{kit.icon("search")}<div><b>Ingen mails matcher i postkassen</b>'
                   f'<span>Der er søgt i {h(where)}.</span></div></div>'
                   f'<div class="find-hints"><h3>Hvor kan den ellers være?</h3><ul class="hint-list">{hint_items}</ul></div>')
    stamp = (f'<p class="faint small find-stamp">{kit.icon("clock")}Søgt {h(kit.fmt_ts(res.get("searched_at")))} · '
             "kun læsning – intet i postkassen blev ændret af søgningen.</p>")
    return "".join(out) + stamp


def _live_card(accounts: dict[str, Any], account: str, text: str, days: int, live: dict | None) -> str:
    acc = accounts.get(account)
    if live is not None:
        body = _live_results(live, account, acc, text, days)
        again = kit.post_form("/find/search", kit.hidden("account", account) + kit.hidden("q", text)
                              + kit.hidden("days", str(days))
                              + kit.button("Søg igen", kind="ghost", icon="refresh", size="sm"),
                              ajax=False, cls="inline-form", attrs="data-busy")
        return kit.card(body, title="I postkassen", subtitle=f"{ui.account_label(account)} · de seneste {days} dage",
                        actions=again, cls="find-live")
    if not (ui.can("release", account) or ui.can("see_messages", account)):
        return ""
    btn = kit.post_form("/find/search", kit.hidden("account", account) + kit.hidden("q", text)
                        + kit.hidden("days", str(days))
                        + kit.button("Søg også i postkassen", kind="primary", icon="search", size="lg"),
                        ajax=False, attrs="data-busy")
    folders = ("Indbakken, Spamfilter-mappen, udbyderens spam-mapper og papirkurven"
               if ui.can("see_messages", account) else "Spamfilter-mappen og udbyderens spam-mapper")
    return kit.card(
        f'<div class="find-step2"><div><p>Filteret kigger direkte i {h(folders)} – kun læsning, '
        f"intet bliver flyttet eller ændret.</p><p class=\"faint small\">Tager typisk 2–5 sekunder.</p></div>{btn}</div>",
        title="Ikke fundet? Søg i postkassen", subtitle="Finder også mail, filteret aldrig har set.", cls="find-live")


def _render_find(*, account: str, text: str, days: int, live: dict | None = None, status: int = 200):
    accounts = {n: a for n, a in mail._accounts().items()}
    if not accounts:
        body = kit.card(kit.empty_state("Ingen postkasser", "Du har ikke adgang til nogen postkasser endnu. "
                                        "Bed en administrator om at give dig adgang.", "inbox"))
        return kit.render_page("Find en mail", body, active="find")
    account = _default_account(accounts, account)
    acc = accounts[account]
    parts = [kit.card(_search_form(accounts, account, text, days), cls="find-card")]
    if text:
        res = _svc("find_mail", account, text, days, live=False, actor=_actor(), default=None) or {}
        if not res.get("ok"):
            parts.append(kit.alert(res.get("text") or "Søgningen kunne ikke udføres.", "warn"))
        else:
            n_db = len(res.get("db") or [])
            parts.append(kit.card(_db_results(res, account, acc), title="I filterets historik",
                                  subtitle=f"Mail, filteret har scannet de seneste {days} dage"
                                  + (f" · {_n(n_db, 'træffer', 'træffere')}" if n_db else ""), cls="flush find-db"))
            parts.append(_live_card(accounts, account, text, days, live))
    else:
        parts.append(kit.card(
            '<ol class="find-how">'
            f'<li>{kit.icon("search")}<div><b>Skriv hvad du husker</b><span>Afsenderens navn, adresse eller et ord fra emnet.</span></div></li>'
            f'<li>{kit.icon("database")}<div><b>Filterets historik først</b><span>Alt, filteret har scannet – med besked om, hvor mailen ligger nu.</span></div></li>'
            f'<li>{kit.icon("inbox")}<div><b>Derefter direkte i postkassen</b><span>Spamfilter-mappen, udbyderens spam-mapper og papirkurven. Én knap flytter mailen hjem.</span></div></li>'
            "</ol>", title="Sådan virker det", cls="find-intro"))
    body = '<div class="find-page">' + "".join(parts) + "</div>"
    html = kit.render_page("Find en mail", body + _page_js(), active="find",
                           subtitle="Led efter en mail, du mangler – i filterets historik og direkte i postkassens mapper.")
    return html, status


@app.get("/find")
@ui.login_required
def find_page():
    account, text, days = _find_args(request.args)
    return _render_find(account=account, text=text, days=days)


@app.post("/find/search")
@ui.login_required
def find_search():
    account, text, days = _find_args(request.form)
    if not account:
        abort(404)
    ui.require_account(account)
    if account not in mail._accounts():
        abort(404)
    if not (ui.can("release", account) or ui.can("see_messages", account)):
        # The live search is the 'Find en mail' tool (menu: release); a
        # Bruger with neither right only sees the database half.
        abort(403)
    res = _svc("find_mail", account, text, days, live=True, actor=_actor(), default=None)
    if not isinstance(res, dict):
        res = {"ok": False, "code": "error", "text": "Søgningen kunne ikke udføres lige nu. Prøv igen om lidt."}
    if res.get("code") != "invalid":
        ui.audit("find_mail", account, "ok" if res.get("ok") else str(res.get("code") or "failed"),
                 detail=str(res.get("audit_detail") or "")[:300])
    return _render_find(account=account, text=text, days=days, live=res)


@app.post("/find/move")
@ui.permission_required("release")
def find_move():
    account, text, days = _find_args(request.form)
    folder = (request.form.get("folder") or "")[:300]
    mid = (request.form.get("message_id") or "").strip()[:998]
    back = _find_url(account, text, days)
    if not account:
        abort(404)
    ui.require_account(account)
    if account not in mail._accounts() or not ui.can("release", account):
        abort(404)
    if not folder or not mid:
        return ui.respond("Mailen kan ikke flyttes herfra.", ok=False, next_url=back)
    is_admin = ui.is_admin()
    confirm_threat = is_admin and request.form.get("confirm_threat") == "1"
    res = _svc("move_found_to_inbox", account, folder, mid, _actor(), is_admin=is_admin,
               confirm_threat=confirm_threat, default=None)
    if not isinstance(res, dict):
        res = {"ok": False, "code": "error", "text": "Mailen kunne ikke flyttes lige nu. Prøv igen om lidt."}
    ok = bool(res.get("ok"))
    code = str(res.get("code") or "")
    if code == "threat_confirm" and is_admin:
        # B16: name the threat and ask; app.js posts the same fields again.
        confirm = {"title": "Flyt farlig mail til indbakken?",
                   "text": f"{kit.clean_name(res.get('confirm_text') or 'Mailen er markeret som farlig.')[:300]} Den lægges i indbakken, "
                           "men filteret lærer den ikke som legitim.",
                   "label": "Flyt alligevel", "tone": "danger", "url": "/find/move",
                   "fields": {"account": account, "folder": folder, "message_id": mid,
                              "uid": request.form.get("uid") or "", "q": text, "days": str(days),
                              "confirm_threat": "1"}}
        if not ui.wants_json():
            ui.flash(f"{kit.clean_name(res.get('confirm_text') or 'Mailen er farlig.')[:200]} Åbn mailen under Beskeder for at frigive den.",
                     "warn")
        return ui.respond("Bekræft flytningen af en farlig mail", ok=False, next_url=back, status=409, confirm=confirm)
    ui.audit("find_move", account, "ok" if ok else (code or "failed"),
             detail=str(res.get("audit_detail") or f"from {folder}")[:300], message_id=mid)
    rows = {}
    if ok:
        key = _hit_key(folder, request.form.get("uid") or "", mid)
        rows[key] = _moved_row(key, res)
    msg = res.get("text") or ("Flyttet til indbakken." if ok else "Mailen kunne ikke flyttes.")
    return ui.respond(msg, ok=ok, next_url=back, status=422, rows=rows)


def _moved_row(key: str, res: dict) -> str:
    text = res.get("text") or "Flyttet til indbakken."
    return (f'<li class="find-hit is-moved" data-row="{h(key)}"><span class="find-kind tone-ok">{kit.icon("check-circle")}</span>'
            f'<div class="find-main"><span class="find-who"><b>Flyttet til indbakken</b></span>'
            f'<span class="find-subj">{h(text)}</span></div></li>')


# ---------------------------------------------------------------------------
# Fortryd flytninger
# ---------------------------------------------------------------------------


def _undo_accounts() -> dict[str, Any]:
    return {n: a for n, a in mail._accounts().items() if ui.can("release", n)}


def _tz_now() -> datetime:
    return datetime.now(kit.TZ) if kit.TZ else datetime.now()


def _local_midnight(days_ago: int = 0) -> int:
    now = _tz_now()
    day = (now - timedelta(days=days_ago)).date()
    midnight = datetime(day.year, day.month, day.day, tzinfo=now.tzinfo)
    return int(midnight.timestamp())


def _parse_local(text: str) -> int | None:
    text = (text or "").strip()[:20]
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            d = datetime.strptime(text, fmt)
        except ValueError:
            continue
        if kit.TZ:
            d = d.replace(tzinfo=kit.TZ)
        return int(d.timestamp())
    return None


def undo_window(period: str, frm: str = "", to: str = "", *, now: int | None = None) -> tuple[int, int, str] | str:
    """(since, until, Danish label) for a period choice, or an error text."""
    now = int(now if now is not None else time.time())
    if period == "hour":
        return now - 3600, now, "den seneste time"
    if period == "today":
        return _local_midnight(0), now, "i dag"
    if period == "yesterday":
        return _local_midnight(1), _local_midnight(0), "i går"
    if period == "custom":
        a, b = _parse_local(frm), _parse_local(to)
        if a is None or b is None:
            return "Vælg både start og slut."
        if b <= a:
            return "Slut skal ligge efter start."
        if b - a > 92 * 86400:
            return "Vælg højst 92 dage ad gangen."
        return a, min(b, now), f"{kit.fmt_ts(a)} – {kit.fmt_ts(b)}"
    return "Vælg en periode."


def _undo_form(accounts: dict[str, Any], account: str, period: str, frm: str, to: str) -> str:
    acct = (kit.form_field("Postkasse", kit.select("account", [(n, ui.account_label(n)) for n in accounts], account,
                                                    attrs='id="undo-account"'))
            if len(accounts) > 1 else kit.hidden("account", account))
    seg = ('<div class="field"><span class="field-label">Periode</span><div class="segmented undo-period" role="radiogroup">'
           + "".join(f'<label class="seg-opt"><input type="radio" name="period" value="{v}" data-undo-period'
                     + (" checked" if v == period else "") + f'><span>{h(lbl)}</span></label>' for v, lbl in UNDO_PERIODS)
           + "</div></div>")
    custom = (f'<div class="grid grid-2 undo-custom" data-undo-custom>'
              + kit.form_field("Fra", kit.input_("from", frm, type="datetime-local", attrs='id="undo-from"'))
              + kit.form_field("Til", kit.input_("to", to, type="datetime-local", attrs='id="undo-to"'))
              + "</div>")
    return (f'<form method="get" action="/undo" class="undo-form">{acct}{seg}{custom}'
            f'<div class="form-actions">{kit.button("Vis hvad der flyttes tilbage", kind="primary", icon="eye")}</div></form>')


def _undo_preview(account: str, since: int, until: int, label: str) -> str:
    prev = _svc("preview_undo", account, since, until, sample=10, default=None) or {}
    if not prev.get("ok"):
        return kit.alert(prev.get("text") or "Forhåndsvisningen kunne ikke hentes.", "warn")
    count = int(prev.get("count") or 0)
    if not count:
        return kit.card(kit.empty_state("Intet at fortryde", f"Filteret har ikke flyttet nogen mails fra "
                                        f"{ui.account_label(account)} til Spamfilter-mappen {label}.", "check-circle"),
                        title="2. Se efter")
    items = []
    for it in prev.get("items") or []:
        name, addr = kit.sender_parts(it.get("sender"))
        items.append(f'<li><span class="undo-who">{h(name or addr or "Ukendt afsender")}</span>'
                     f'<span class="undo-subj">{h((it.get("subject") or "").strip() or "(intet emne)")}</span>'
                     f'<span class="undo-when">{h(kit.fmt_ts(it.get("moved_to_junk_at")))}</span></li>')
    more = count - len(items)
    learn = ('<div class="field field-switch">'
             + kit.switch("learn", False, "Lær at disse ikke er spam")
             + '<span class="field-hint">Kun hvis du er sikker på, at de alle er rigtige mails. Ellers lærer filteret '
               "forkert. Uden flueben bliver de bare lagt tilbage og flyttes aldrig igen.</span></div>")
    too_many = bool(prev.get("too_many"))
    run = kit.post_form(
        "/undo/run",
        kit.hidden("account", account) + kit.hidden("since", str(since)) + kit.hidden("until", str(until)) + learn
        + '<div class="form-actions">'
        + kit.button(f"Flyt {_n(count, 'mail', 'mails')} tilbage til indbakken", kind="primary", icon="undo", size="lg",
                     attrs=("disabled " if too_many else "") + kit.confirm_attrs(
                         f"Flyt {_n(count, 'mail', 'mails')} tilbage?",
                         f"Alt, som filteret flyttede fra {ui.account_label(account)} til Spamfilter-mappen {label}, "
                         "lægges tilbage i indbakken. Intet bliver slettet.", confirm="Flyt tilbage"))
        + "</div>", ajax=True)
    gone = int(prev.get("gone") or 0)
    threats = int(prev.get("threats") or 0)
    threat_note = ""
    if threats:
        who = ("Frigiv dem enkeltvis fra Fanget spam, hvis de virkelig skal ud." if ui.is_admin()
               else "Kontakt administrator, hvis de skal frigives.")
        threat_note = (f'<div class="undo-threats">{kit.icon("alert-triangle")}<span>'
                       f'{h(_n(threats, "farlig mail", "farlige mails"))} (virus, phishing eller farlig vedhæftning) '
                       f"flyttes ikke tilbage. {h(who)}</span></div>")
    return kit.card(
        f'<div class="undo-count"><b>{kit.fmt_int(count)}</b><span>{"mail" if count == 1 else "mails"} flyttet til '
        f'Spamfilter-mappen {h(label)}</span></div>'
        + (kit.alert(prev.get("text") or "", "warn") if too_many else "")
        + (f'<p class="faint small">{_n(gone, "mail er", "mails er")} allerede væk fra mappen og springes over.</p>' if gone else "")
        + threat_note
        + f'<ul class="undo-sample">{"".join(items)}</ul>'
        + (f'<p class="faint small">+ {_n(more, "mail mere", "mails mere")}</p>' if more > 0 else "")
        + run, title="2. Se efter og flyt tilbage", cls="undo-preview")


def _job_row(j: dict) -> str:
    st, tone = UNDO_STATUS.get(str(j.get("status")), (str(j.get("status") or ""), "neutral"))
    pct = int(j.get("percent") or 0)
    acct = str(j.get("account") or "")
    return (f'<li class="undo-job"><a href="/undo/jobs/{int(j["id"])}">'
            f'<span class="undo-job-top"><b>{h(ui.account_label(acct))}</b>{kit.badge(st, tone)}</span>'
            f'<span class="faint small">{h(kit.fmt_ts(j.get("since_ts")))} – {h(kit.fmt_ts(j.get("until_ts")))}'
            f' · {_n(int(j.get("moved") or 0), "flyttet", "flyttet")} af {kit.fmt_int(int(j.get("total") or 0))}'
            f' · startet af {h(j.get("created_by") or "–")}</span>'
            f'{kit.progress(pct, 100, tone="ok" if j.get("status") == "done" else "brand")}</a></li>')


def _jobs_card(accounts: dict[str, Any]) -> str:
    jobs = [j for j in (_svc("list_undo_jobs", None, 10, default=[]) or []) if str(j.get("account")) in accounts]
    if not jobs:
        return ""
    return kit.card(f'<ul class="undo-jobs">{"".join(_job_row(j) for j in jobs[:8])}</ul>', title="Seneste fortrydelser",
                    cls="flush")


@app.get("/undo")
@ui.permission_required("release")
def undo_page():
    accounts = _undo_accounts()
    if not accounts:
        body = kit.card(kit.empty_state("Ingen postkasser", "Du kan ikke flytte mail i nogen postkasser.", "inbox"))
        return kit.render_page("Fortryd flytninger", body, active="undo")
    wanted = (request.args.get("account") or "").strip()
    if wanted:
        ui.require_account(wanted)
        if wanted not in accounts:
            abort(404)
    account = wanted or next(iter(accounts))
    period = request.args.get("period") or ""
    frm, to = (request.args.get("from") or "")[:20], (request.args.get("to") or "")[:20]
    if period not in {p for p, _l in UNDO_PERIODS}:
        period = ""
    lead = ("Har filteret flyttet rigtige mails i en periode – fx efter en ændring af følsomheden? "
            if ui.is_admin() else "Har filteret flyttet rigtige mails i en periode? ")
    parts = [kit.card(
        f'<p class="muted undo-lead">{h(lead)}Her lægger du dem tilbage i indbakken på én gang. Intet bliver '
        "slettet, og filteret flytter dem ikke igen.</p>" + _undo_form(accounts, account, period or "today", frm, to),
        title="1. Vælg postkasse og periode" if len(accounts) > 1 else "1. Vælg periode", cls="undo-card")]
    if period:
        win = undo_window(period, frm, to)
        if isinstance(win, str):
            parts.append(kit.alert(win, "warn"))
        else:
            parts.append(_undo_preview(account, *win))
    parts.append(_jobs_card(accounts))
    body = '<div class="undo-page">' + "".join(p for p in parts if p) + "</div>"
    return kit.render_page("Fortryd flytninger", body + _page_js(), active="undo",
                           subtitle="Læg mails, filteret har flyttet til Spamfilter-mappen, tilbage i indbakken.")


@app.post("/undo/run")
@ui.permission_required("release")
def undo_run():
    account = (request.form.get("account") or "").strip()
    if not account:
        abort(404)
    ui.require_account(account)
    if account not in _undo_accounts():
        abort(404)
    try:
        since, until = int(request.form.get("since") or 0), int(request.form.get("until") or 0)
    except ValueError:
        return ui.respond("Ugyldig periode.", ok=False, next_url="/undo")
    learn = (request.form.get("learn") or "") in ("1", "on", "true")
    res = _svc("undo_moves", account, since, until, _actor(), learn, wait_s=0, default=None)
    if not isinstance(res, dict):
        return ui.respond("Fortrydelsen kunne ikke startes. Prøv igen om lidt.", ok=False, next_url="/undo")
    code = str(res.get("code") or "")
    ui.audit("undo_moves", account, "ok" if res.get("ok") or code in ("queued", "running") else code or "failed",
             detail=str(res.get("audit_detail") or f"job={res.get('job_id')} learn={int(learn)}")[:300])
    job = res.get("job_id")
    if job and code in ("ok", "queued", "running", "busy"):
        msg = ("Der kører allerede en fortrydelse for postkassen – her er den." if code == "busy"
               else res.get("text") or "Mails flyttes tilbage til indbakken.")
        target = f"/undo/jobs/{int(job)}"
        if ui.wants_json():
            return ui.json_ok(msg, redirect=target)
        ui.flash(msg, "ok" if code != "busy" else "info")
        return redirect(target)
    return ui.respond(res.get("text") or "Der var intet at flytte tilbage.", ok=code == "nothing",
                      next_url=f"/undo?account={_q(account)}")


def _job_or_404(undo_id: int) -> dict:
    job = _svc("undo_job", undo_id, default=None)
    if not isinstance(job, dict) or not ui.can("release", str(job.get("account") or "")):
        abort(404)
    return job


def _job_public(job: dict) -> dict:
    keys = ("id", "account", "status", "total", "processed", "moved", "not_found", "skipped", "failed", "learned",
            "percent", "remaining", "text")
    out = {k: job.get(k) for k in keys}
    st, tone = UNDO_STATUS.get(str(job.get("status")), (str(job.get("status") or ""), "neutral"))
    out.update(status_label=st, tone=tone, active=job.get("status") in UNDO_ACTIVE)
    return out


@app.get("/undo/jobs/<int:undo_id>")
@ui.permission_required("release")
def undo_job_page(undo_id: int):
    job = _job_or_404(undo_id)
    pub = _job_public(job)
    pct = int(pub.get("percent") or 0)
    account = str(job.get("account") or "")
    cancel = ""
    if pub["active"]:
        cancel = kit.post_form(f"/undo/jobs/{undo_id}/cancel",
                               kit.button("Stop", kind="ghost", icon="pause", size="sm", attrs=kit.confirm_attrs(
                                   "Stop fortrydelsen?", "Mails, der allerede er lagt tilbage, bliver i indbakken.",
                                   confirm="Stop")), cls="inline-form")
    counts = "".join(f'<div><b data-undo-n="{k}">{kit.fmt_int(int(job.get(k) or 0))}</b><span>{h(lbl)}</span></div>'
                     for k, lbl in (("moved", "lagt tilbage"), ("not_found", "ikke fundet"), ("skipped", "sprunget over"),
                                    ("failed", "fejlede")))
    body = kit.card(
        f'<div class="undo-progress" data-undo-poll="/undo/jobs/{undo_id}.json" data-undo-active="{1 if pub["active"] else 0}">'
        f'<div class="undo-progress-top"><span class="badge tone-{pub["tone"]}" data-undo-status>{h(pub["status_label"])}</span>'
        f'<span class="undo-pct num" data-undo-pct>{pct} %</span></div>'
        f'<div class="progress tone-{"ok" if job.get("status") == "done" else "brand"}" role="progressbar" '
        f'aria-valuemin="0" aria-valuemax="100" aria-valuenow="{pct}" data-undo-bar>'
        f'<span class="progress-fill p-{pct}" data-undo-fill></span></div>'
        f'<p class="undo-text" data-undo-text aria-live="polite">{h(job.get("text") or "")}</p>'
        f'<div class="breakdown undo-counts">{counts}</div></div>'
        + (f'<p class="faint small">{"Filteret lærer, at mailene ikke er spam." if job.get("learn") else "Uden læring – mailene lægges bare tilbage og flyttes ikke igen."}</p>'),
        title=f"Fortryder for {ui.account_label(account)}",
        subtitle=f"{kit.fmt_ts(job.get('since_ts'))} – {kit.fmt_ts(job.get('until_ts'))}", actions=cancel)
    back = kit.button("Tilbage", href=f"/undo?account={_q(account)}", kind="secondary", icon="arrow-left", size="sm")
    return kit.render_page("Fortryd flytninger", body + _page_js(), active="undo", actions_html=back,
                           breadcrumbs=[("Fortryd flytninger", "/undo"), (f"Job {undo_id}", None)])


@app.get("/undo/jobs/<int:undo_id>.json")
@ui.permission_required("release")
def undo_job_json(undo_id: int):
    return jsonify({"ok": True, "job": _job_public(_job_or_404(undo_id))})


@app.post("/undo/jobs/<int:undo_id>/cancel")
@ui.permission_required("release")
def undo_job_cancel(undo_id: int):
    job = _job_or_404(undo_id)
    ok = bool(_svc("cancel_undo_job", undo_id, default=False))
    ui.audit("undo_cancel", str(job.get("account") or ""), "ok" if ok else "failed", detail=f"job={undo_id}")
    return ui.respond("Fortrydelsen stopper efter den igangværende portion." if ok else "Fortrydelsen kører ikke længere.",
                      ok=ok, next_url=f"/undo/jobs/{undo_id}", refresh=True)


# ---------------------------------------------------------------------------
# Hjælp
# ---------------------------------------------------------------------------

HELP_SECTIONS: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    ("sadan-virker-det", "Sådan virker spamfilteret", "shield-check", (
        "Filteret holder øje med din indbakke døgnet rundt. Hver ny mail får en score: jo højere, jo mere ligner den spam.",
        "Når scoren når grænsen, flyttes mailen automatisk til mappen “Spamfilter”. Tydelig spam flyttes automatisk med det samme; "
        "mails tæt på grænsen venter et minut, så du kan nå at reagere.",
        "Din udbyder har også sit eget spamfilter. Det fortsætter som før – filteret rører ikke udbyderens egen spam-mappe.",
    )),
    ("spamfilter-mappen", "Spamfilter-mappen", "folder", (
        "Du finder mappen “Spamfilter” i dit mailprogram – på telefonen under Postkasser/Mapper, på computeren ved siden af Indbakken.",
        "Kig i den en gang imellem, eller brug “Tjek disse” under Fanget spam: her samler vi de få mails, der måske ikke er spam.",
    )),
    ("traek-mails", "Træk mails frem og tilbage – filteret lærer", "undo", (
        "Er der spam i indbakken? Træk mailen over i mappen Spamfilter – fx på telefonen. Så lærer filteret, "
        "at den slags er spam.",
        "Ligger der en rigtig mail i Spamfilter-mappen? Træk den tilbage til Indbakken. Filteret lærer, at den ikke er spam, "
        "flytter aldrig den mail igen – og afsenderen bliver automatisk tilladt, så du også får næste mail fra dem.",
        "Det virker både på telefonen, på computeren og her i webadministrationen.",
    )),
    ("knapperne", "Frigiv, Tillad, Bloker og Altid igennem", "list-checks", (
        "Frigiv: lægger mailen tilbage i indbakken og lærer filteret, at den ikke er spam.",
        "Tillad afsender: post fra afsenderen flyttes ikke længere – medmindre den ser forfalsket ud.",
        "Bloker afsender: post fra afsenderen behandles altid som spam.",
        "Altid igennem: kun for administratoren. Bruges til helt afgørende afsendere som en webshop-platform, så ordrer og "
        "kundehenvendelser altid når frem – men kun når mailen kan bekræftes som ægte.",
    )),
    ("folsomhed", "Følsomhed", "sliders", (
        "Følsomheden er grænsen for, hvornår en mail regnes som spam. Lav grænse = strengere filter, høj grænse = flere mails slipper igennem.",
        "Administratoren kan se et forslag til grænsen ud fra, hvad du har frigivet og selv flyttet til spam.",
    )),
    ("find-en-mail", "Find en mail", "search", (
        "Mangler du en mail? Gå til “Find en mail”, og skriv afsenderens navn, adresse eller et ord fra emnet.",
        "Først ser du, hvad filteret ved om mailen. Tryk “Søg også i postkassen” for at lede direkte i Spamfilter-mappen, "
        "udbyderens spam-mapper og papirkurven. Én knap flytter mailen hjem til indbakken.",
        "Hos nogle udbydere stoppes post af et filter, før den når postkassen. Så viser siden, hvor du kan lede.",
    )),
    ("fortryd", "Fortryd flytninger", "clock", (
        "Har filteret flyttet for meget i en periode, kan du lægge alt fra fx “i dag” tilbage i indbakken på én gang under “Fortryd flytninger”.",
        "Filteret har også en sikring: flytter det pludselig usædvanligt meget, stopper det sig selv og venter på, at administratoren kigger.",
    )),
    # 2.3
    ("kendte-kontakter", "Kendte kontakter", "user-check", (
        "Har du selv skrevet til nogen, er deres svar næsten aldrig spam. Filteret lærer derfor fra dine sendte "
        "mails, hvem du har skrevet til – og giver mails fra dem et forspring.",
        "Vi læser kun modtager-adresser og Message-ID fra dine sendte mails – aldrig indholdet. Adresserne gemmes "
        "som et fingeraftryk, ikke som tekst.",
        "Under Regler → Kendte kontakter kan du se, hvem filteret kender, tjekke en adresse og fjerne en afsender. "
        "Lægger du en mail fra en kendt kontakt i spam, fjernes afsenderen automatisk – med én knap kan du beholde den.",
        "Ser en mail forfalsket eller farlig ud, hjælper det ikke at være kendt kontakt.",
    )),
    ("svar-paa-din-mail", "Svar på din mail", "reply", (
        "Når nogen svarer på en mail, du selv har sendt, genkender filteret samtalen og beskytter svaret – også "
        "når det er første gang, afsenderen skriver til dig. Mailen får mærkatet “Svar på din mail”.",
        "“Ligner et svar, men afsenderen kunne ikke bekræftes” betyder, at samtalen passer, men at afsenderen ikke "
        "kunne bevise, at mailen er ægte. Så giver det ikke noget forspring.",
    )),
    ("fast-afsender", "Fast afsender", "shield-check", (
        "Fakturasystemer, foreninger og nyhedsbreve, du læser, skriver du sjældent selv til. Har en afsender sendt dig "
        "flere mails over mindst en måned fra det samme system, og var ingen af dem spam, bliver den “Fast afsender”.",
        "“Første mail fra denne afsender” betyder bare, at filteret ikke har set afsenderen før. Det tæller en lille "
        "smule imod mailen – aldrig mere.",
    )),
    ("trusler", "Farlige mails", "alert-triangle", (
        "Virus, links til kendte svindelsider og farlige vedhæftninger (fx .exe, .js og .iso – også inde i zip-filer) "
        "flyttes altid til Spamfilter-mappen. Det gælder også fra kendte kontakter. De får et rødt mærkat, fx "
        "“Phishing-link” eller “Farlig vedhæftning: faktura.pdf.exe”.",
        "Kun en administrator kan frigive en farlig mail – efter at have bekræftet advarslen – og filteret lærer den "
        "aldrig som god post.",
    )),
    ("genscanning", "Genscanning", "radar", (
        "Ny svindel er ofte ukendt de første timer. Filteret kigger derfor igen på tvivlsomme mails efter 45 minutter, "
        "4 timer og et døgn. Er de kommet på en sortliste i mellemtiden, flyttes de til Spamfilter-mappen med "
        "mærkatet “Fanget ved genscanning”.",
        "En mail, du allerede har læst, flyttes kun, hvis den er farlig.",
    )),
    ("kode-paa-mail", "Kode på mail", "mail", (
        "To-trins-login kan sende koden på mail i stedet for at bruge en app. Vælg det under Min konto. Koden gælder "
        "i 10 minutter og kan kun bruges én gang.",
        "En godkendelses-app er det sikreste. Brug koden på mail som alternativ eller reserve.",
    )),
    ("intet-slettes", "Intet bliver slettet", "lock", (
        "Spamfilteret sletter aldrig mail. Det flytter kun mellem Indbakken og Spamfilter-mappen – og du kan altid flytte tilbage.",
        "Vil du rydde op i Spamfilter-mappen, gør du det selv i dit mailprogram.",
    )),
)


HELP_ADMIN_ONLY = {"folsomhed"}
# 2.3.6: the family guide (FAMILIEGUIDE.md rendered by .build/make_familieguide.py)
# ships next to the code; it is served only to logged-in users.
GUIDE_PDF = Path(__file__).resolve().parent / "familieguide.pdf"
GUIDE_URL = "/help/familieguide.pdf"
GUIDE_DOWNLOAD_NAME = "Spamfilter-familieguide.pdf"


def _help_sections() -> list[tuple[str, str, str, tuple[str, ...]]]:
    """HELP_SECTIONS for the current user: a Bruger gets no scores, no
    admin-only buttons and only promises that hold for their mailboxes."""
    admin = ui.is_admin()
    auto = mail.auto_allow_on()
    rules = ui.can("rules")
    out = []
    for sid, title, ic, paras in HELP_SECTIONS:
        if not admin and sid in HELP_ADMIN_ONLY:
            continue
        if sid == "sadan-virker-det" and not admin:
            paras = ("Filteret holder øje med din indbakke døgnet rundt og vurderer hver ny mail. Ligner den tydeligt "
                     "spam, flyttes den til mappen “Spamfilter”. Er filteret i tvivl, venter det et minut, så du kan "
                     "nå at reagere.",) + paras[2:]
        elif sid == "spamfilter-mappen" and not admin:
            paras = tuple(p.replace("under Fanget spam", "under Min spam") for p in paras)
        elif sid == "traek-mails":
            back = ("Ligger der en rigtig mail i Spamfilter-mappen? Træk den tilbage til Indbakken. Filteret lærer, "
                    "at den ikke er spam, og flytter aldrig den mail igen"
                    + (" – og afsenderen bliver automatisk tilladt, så du også får næste mail fra dem." if auto else "."))
            here = ("Det virker både på telefonen og på computeren. Her på siden bruger du Frigiv (kun denne mail)"
                    + (" eller Tillad (også fremover)." if (admin or rules) else "."))
            paras = (paras[0], back, here)
        elif sid == "knapperne" and not admin:
            title = "Frigiv, Tillad og Bloker" if rules else "Frigiv"
            paras = tuple(p for p in paras if not p.startswith("Altid igennem")
                          and (rules or p.startswith("Frigiv")))
        elif sid == "kendte-kontakter" and not admin and not rules:
            paras = tuple(p.replace("Under Regler → Kendte kontakter", "Under Kendte kontakter") for p in paras)
        elif sid == "trusler":
            if admin:
                paras = paras + ("Under Indstillinger → Farlige vedhæftninger vælger du, hvilke filtyper der blokeres. "
                                 "Under Regler → Vedhæftninger kan du tillade dem fra en enkelt afsender, du stoler på.",)
            else:
                paras = (paras[0], "Venter du på en mail, der er markeret som farlig, så kontakt administratoren – "
                                   "du ser “Kontakt administrator” i stedet for Frigiv. Kun en administrator kan "
                                   "frigive den.")
        elif sid == "kode-paa-mail":
            if not ui.mail_2fa_available():
                if not admin:
                    continue
                paras = paras + ("Det kræver en mailserver under Indstillinger → Mailserver.",)
        elif sid == "find-en-mail" and not admin and not ui.can("see_messages"):
            paras = tuple(p.replace("Spamfilter-mappen, udbyderens spam-mapper og papirkurven",
                                    "Spamfilter-mappen og udbyderens spam-mapper") for p in paras)
        out.append((sid, title, ic, paras))
    return out


@app.get("/help")
@ui.login_required
def help_page():
    base = ui.external_url() or request.host_url.rstrip("/")
    secs = []
    sections = _help_sections()
    toc = "".join(f'<a class="help-toc-item" href="#{sid}">{kit.icon(ic)}<span>{h(title)}</span></a>'
                  for sid, title, ic, _p in sections)
    for sid, title, ic, paras in sections:
        link = f"{base}/help#{sid}"
        copy = (f'<button type="button" class="icon-btn help-link js-only" data-copy-text="{h(link)}" '
                f'data-copy-label="Linket er kopieret" aria-label="Kopiér link til “{h(title)}”" title="Kopiér link">'
                f'{kit.icon("link")}</button>')
        body = "".join(f"<p>{h(p)}</p>" for p in paras)
        secs.append(f'<section class="card help-sec" id="{sid}"><div class="help-head"><span class="help-ic">{kit.icon(ic)}</span>'
                    f'<h2>{h(title)}</h2>{copy}</div><div class="help-body">{body}</div></section>')
    share = (f'<div class="help-share">{kit.icon("users")}<div><b>Del vejledningen med familien</b>'
             f'<span>Send linket <span class="mono">{h(base)}/help</span> – hvert afsnit har sit eget link (kæde-ikonet).</span></div>'
             f'<button type="button" class="btn btn-secondary btn-sm js-only" data-copy-text="{h(base)}/help" '
             f'data-copy-label="Linket er kopieret">{kit.icon("copy")}<span>Kopiér link</span></button></div>'
             if ui.is_admin() else "")
    guide = (f'<div class="help-share help-pdf">{kit.icon("download")}<div><b>Familieguiden som PDF</b>'
             "<span>To sider at printe eller sende videre: mappen Spamfilter, træk mails ind og ud, den enkle "
             "spamside og hvad du gør, hvis en mail mangler.</span></div>"
             + kit.button("Hent familieguiden (PDF)", href=GUIDE_URL, kind="secondary", icon="download", size="sm",
                          attrs='download="Spamfilter-familieguide.pdf"')
             + "</div>") if GUIDE_PDF.is_file() else ""
    body = (f'<div class="help-page"><nav class="card help-toc" aria-label="Indhold">{toc}</nav>'
            f'<div class="help-main">{share}{guide}{"".join(secs)}</div></div>')
    return kit.render_page("Hjælp", body, active="help", subtitle="Kort fortalt: sådan bruger du spamfilteret.")


@app.get(GUIDE_URL)
@ui.login_required
def help_familieguide():
    """The family guide as a PDF download (login required; the central
    policy applies it before this runs)."""
    if not GUIDE_PDF.is_file():
        abort(404)
    return send_file(GUIDE_PDF, mimetype="application/pdf", as_attachment=True,
                     download_name=GUIDE_DOWNLOAD_NAME, max_age=0)
