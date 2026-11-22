"""Regler → Kendte kontakter (B13) and Vedhæftninger (B17) - spamfilter 2.3.

  * Kendte kontakter   /rules/contacts       people you wrote to (learned from
                                             your own Sent folders, stored as
                                             hashes), per mailbox
  * Vedhæftninger      /rules/attachments    admin-only exceptions "Tillad
                                             farlige vedhæftninger fra denne
                                             afsender"

Access: every route carries the central policy (dashboard decorators) plus
the object checks. A Bruger only ever sees their own mailboxes (a foreign
mailbox is a 404, never a 403, so its existence is not revealed); removing,
restoring and the "Stol på folk, jeg har skrevet til" switch need the
'rules' permission on that mailbox; "Opdater nu" only needs access to it.
Contact addresses are never shown in full unless the same address also
wrote to the mailbox (services.contacts_list decides); audit records carry
masks only (services' audit_detail). Nothing here touches mail.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote, urlencode

from flask import abort, request

import dashboard as ui
import ui_kit as kit
import ui_mail as mail
from ui_kit import h

log = logging.getLogger("dashboard.contacts")
app = ui.app

PER_PAGE = 30
STATUS_FILTERS = (("all", "Alle"), ("active", "Kendte"), ("removed", "Fjernet"), ("demoted", "Efter spam"))
GROUPS = (("people", "Personer"), ("orgs", "Organisationer"))
HELP_FALLBACK = "Vi læser kun modtager-adresser og Message-ID fra dine sendte mails – aldrig indholdet."
MASK_TITLE = "Den fulde adresse vises kun, hvis personen også har skrevet til dig. Ellers gemmes den kun som et fingeraftryk."


def _n(n: int, one: str, many: str) -> str:
    return f"{kit.fmt_int(n)} {one if n == 1 else many}"


def _times(n: int) -> str:
    return f"{kit.fmt_int(n)} {'gang' if n == 1 else 'gange'}"


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


def _page_url(account: str, **args: Any) -> str:
    clean = {k: str(v) for k, v in {"account": account, **args}.items() if v not in (None, "", "people", "all", 1)}
    return "/rules/contacts" + ("?" + urlencode(clean) if clean else "")


def _visible() -> dict[str, Any]:
    return mail._accounts()


def _mailbox_or_404(name: str) -> str:
    """A mailbox the user may see (404 otherwise, also for unknown ones)."""
    name = (name or "").strip()
    if not name:
        abort(404)
    ui.require_account(name)
    if name not in _visible():
        abort(404)
    return name


def _active_key() -> str:
    """Nav entry that lights up: Regler for admins / Brugere with the
    rules permission, the Bruger's own 'Kendte kontakter' item otherwise."""
    return "contacts"


# ---------------------------------------------------------------------------
# Status card
# ---------------------------------------------------------------------------


def _status_card(account: str, ov: dict) -> str:
    may_rules = ui.can("rules", account)
    enabled = bool(ov.get("enabled"))
    complete = bool(ov.get("complete"))
    prog = ov.get("progress") or {}
    pct = int(prog.get("percent") or 0)
    if not ov.get("ok"):
        tone, ic = "warn", "alert-triangle"
    elif not enabled:
        tone, ic = "neutral", "pause"
    elif complete:
        tone, ic = "ok", "user-check"
    else:
        tone, ic = "info", "refresh"
    text = str(ov.get("text") or "Status for kendte kontakter kunne ikke hentes.")
    syncing = enabled and not complete and int(prog.get("total") or 0) > 0
    bar = ""
    if syncing:
        # "Sendte mails gennemgået   980 / 2.400" - the percentage is already in the text.
        bar = (f'<div class="ct-progress">{kit.progress(int(prog.get("done") or 0), int(prog.get("total") or 0), tone="brand", label="Sendte mails gennemgået")}'
               "</div>")
    removed = int(ov.get("removed") or 0) + int(ov.get("demoted") or 0)
    tiles = (f'<div class="ct-tiles">'
             f'<div><b class="num">{kit.fmt_int(int(ov.get("contacts") or 0))}</b><span>Kendte kontakter</span></div>'
             f'<div><b class="num">{kit.fmt_int(int(ov.get("sent_mails") or 0))}</b><span>Sendte mails læst</span></div>'
             f'<div><b class="num">{kit.fmt_int(removed)}</b><span>Fjernet</span></div></div>')
    # Controls: the switch (rules permission) and "Opdater nu" (access).
    controls = []
    if may_rules:
        sw = kit.switch("enabled", enabled, "Stol på folk, jeg har skrevet til",
                        attrs='data-switch-submit aria-describedby="ct-switch-hint"')
        controls.append(kit.post_form(
            "/rules/contacts/enabled",
            kit.hidden("account", account) + kit.hidden("next", _page_url(account))
            + f'<div class="ct-switch">{sw}'
            + kit.button("Gem", kind="secondary", size="sm", cls="nojs-only") + "</div>"
            + '<p class="field-hint" id="ct-switch-hint">Mails fra folk, du selv har skrevet til, får et forspring '
              "– medmindre de ser forfalskede eller farlige ud.</p>",
            cls="ct-switch-form"))
    else:
        state = "slået til" if enabled else "slået fra"
        controls.append(f'<p class="ct-readonly">{kit.icon("user-check" if enabled else "pause")}'
                        f"<span>Stol på folk, jeg har skrevet til: <b>{h(state)}</b>"
                        "<small>Kun en administrator eller en bruger med adgang til regler kan ændre det.</small>"
                        "</span></p>")
    sync_btn = ""
    if enabled:
        if ov.get("requested"):
            sync_btn = (f'<span class="badge tone-info ct-requested">{kit.icon("clock")}'
                        "<span>Opdatering bestilt – kører om lidt</span></span>")
        else:
            sync_btn = kit.post_form(
                "/rules/contacts/sync",
                kit.hidden("account", account) + kit.hidden("next", _page_url(account))
                + kit.button("Opdater nu", kind="secondary", icon="refresh", size="sm",
                             attrs='title="Læs nye mails fra dine Sendt-mapper nu"'),
                cls="inline-form")
    head = (f'<div class="ct-head"><span class="ct-ic tone-{tone}">{kit.icon(ic)}</span>'
            f'<div class="ct-head-text"><h2>{h(ui.account_label(account))}</h2>'
            f'<p class="ct-text">{h(text)}</p></div>'
            + (f'<div class="ct-head-act">{sync_btn}</div>' if sync_btn else "") + "</div>")
    help_line = (f'<p class="ct-help">{kit.icon("lock")}<span>{h(str(ov.get("help") or HELP_FALLBACK))}</span></p>')
    return (f'<section class="card ct-status tone-{tone}">{head}{bar}{tiles}'
            f'<div class="ct-controls">{"".join(controls)}</div>{help_line}</section>')


# ---------------------------------------------------------------------------
# Lists
# ---------------------------------------------------------------------------


def _status_badge(item: dict) -> str:
    st = str(item.get("status") or "active")
    if st == "active":
        return ""
    tone = "warn" if st == "demoted" else "neutral"
    return kit.badge(str(item.get("status_text") or st), tone)


def _status_form(account: str, h_: str, status: str, *, next_url: str, label: str, icon: str, tone: str,
                 confirm: str = "") -> str:
    inner = (kit.hidden("account", account) + kit.hidden("h", h_) + kit.hidden("status", status)
             + kit.hidden("view", "contacts") + kit.hidden("next", next_url)
             + kit.button(label, kind="secondary", icon=icon, size="sm", tone=tone, attrs=confirm))
    return kit.post_form("/rules/contacts/status", inner, cls="inline-form")


def person_row(account: str, item: dict, *, next_url: str, rules: Any = None) -> str:
    h_ = str(item.get("h") or "")
    display = str(item.get("display") or item.get("address") or "…")
    masked = bool(item.get("masked"))
    st = str(item.get("status") or "active")
    initial = (display.strip()[:1] or "?").upper()
    n = int(item.get("sent_count") or 0)
    last = str(item.get("last_sent_text") or "")
    meta = (f"Du har skrevet {_times(n)}" if n else "Tilføjet manuelt") + (f" · senest {last}" if last else "")
    acts = []
    if ui.can("rules", account):
        if item.get("can_remove"):
            acts.append(_status_form(account, h_, "removed", next_url=next_url, label="Fjern", icon="user-x",
                                     tone="neutral"))
        if item.get("can_restore"):
            acts.append(_status_form(account, h_, "active", next_url=next_url, label="Gendan", icon="user-check",
                                     tone="ok"))
        addr = str(item.get("address") or "")
        if addr and ui.can_edit_rule(account):
            pattern = mail._sender_pattern(addr)
            rule = (rules or mail.RuleIndex()).match(account, pattern) if pattern else None
            if rule is not None and rule["kind"] == "block":
                acts.append(kit.badge("Blokeret", "bad"))
            elif pattern and not (mail._rule_force(rule) and not ui.is_admin()):
                acts.append(mail._rule_add_btn(account, pattern, "block", "Bloker afsender", short="Bloker",
                                               view="contacts", next_url=next_url,
                                               title=f"Post fra {pattern} behandles altid som spam"))
    mask_chip = (f'<span class="chip tone-neutral ct-mask is-icon" title="{h(MASK_TITLE)}">{kit.icon("lock")}'
                 '<span class="sr-only">Adresse skjult</span></span>' if masked else "")
    return (f'<li class="ct-row is-{h(st)}" data-row="contact:{h(h_)}">'
            f'<span class="ct-avatar" aria-hidden="true">{h(initial)}</span>'
            f'<div class="ct-main"><span class="ct-who"><b class="{"mono" if masked else ""}">{h(display)}</b>'
            f'{mask_chip}{_status_badge(item)}</span>'
            f'<span class="ct-meta">{h(meta)}</span></div>'
            f'<div class="ct-acts">{"".join(acts)}</div></li>')


def org_row(account: str, item: dict) -> str:
    dom = str(item.get("domain") or "")
    n = int(item.get("contacts") or 0)
    sent = int(item.get("sent_count") or 0)
    last = str(item.get("last_sent_text") or "")
    meta = f"{_n(n, 'kontakt', 'kontakter')} · skrevet til {_times(sent)}" + (f" · senest {last}" if last else "")
    see = kit.button("Se personer", href=_page_url(account, q=dom), kind="ghost", size="sm", icon="users")
    return (f'<li class="ct-row is-org"><span class="ct-avatar is-org" aria-hidden="true">{kit.icon("building")}</span>'
            f'<div class="ct-main"><span class="ct-who"><b>{h(dom)}</b></span><span class="ct-meta">{h(meta)}</span></div>'
            f'<div class="ct-acts">{see}</div></li>')


def _lookup_box(account: str, lookup: dict | None, *, next_url: str) -> str:
    if not lookup:
        return ""
    code = str(lookup.get("code") or "")
    found = bool(lookup.get("found"))
    tone = "ok" if found and lookup.get("status") == "active" else ("warn" if found else
                                                                    "bad" if code == "invalid" else "neutral")
    ic = {"ok": "user-check", "warn": "user-x", "bad": "alert-circle"}.get(tone, "search")
    acts = ""
    h_ = str(lookup.get("h") or "")
    if found and h_ and ui.can("rules", account):
        if lookup.get("status") == "active":
            acts = _status_form(account, h_, "removed", next_url=next_url, label="Fjern", icon="user-x", tone="neutral")
        else:
            acts = _status_form(account, h_, "active", next_url=next_url, label="Gendan", icon="user-check", tone="ok")
    return (f'<div class="ct-lookup tone-{tone}" role="status">{kit.icon(ic)}'
            f'<p>{h(str(lookup.get("text") or ""))}</p>'
            + (f'<div class="ct-lookup-act">{acts}</div>' if acts else "") + "</div>")


def _list_card(account: str, *, group: str, status: str, q: str, page: int, counts: dict) -> str:
    here = _page_url(account, group=group, status=status, q=q, page=page)
    res = _svc("contacts_list", account, q, page, PER_PAGE, group, status=status, default=None) or {}
    if not isinstance(res, dict):
        res = {}
    group_tabs = kit.tabs([(lbl, _page_url(account, group=g, q=q if g == group else ""), g == group,
                            counts.get(g)) for g, lbl in GROUPS])
    search = (f'<form method="get" action="/rules/contacts" class="ct-search" role="search">'
              + kit.hidden("account", account) + kit.hidden("group", group if group != "people" else "")
              + f'<label class="input-icon">{kit.icon("search")}'
              + kit.input_("q", q, type="search", attrs='aria-label="Søg i kendte kontakter" '
                           'placeholder="Domæne – eller en hel adresse" autocomplete="off" '
                           'autocapitalize="none" spellcheck="false" enterkeyhint="search" maxlength="200"')
              + "</label>" + kit.button("Søg", kind="secondary", size="sm", cls="nojs-only") + "</form>")
    filt = ""
    if group == "people":
        filt = ('<div class="ct-filters">' + kit.seg_links(
            [(lbl, _page_url(account, status=st, q=q), st == status) for st, lbl in STATUS_FILTERS]) + "</div>")
    lookup = _lookup_box(account, res.get("lookup"), next_url=here)
    items = list(res.get("items") or [])
    if not res.get("ok", True) and res.get("text"):
        listing = kit.alert(str(res.get("text")), "warn")
    elif res.get("lookup"):
        listing = ""  # an exact address: the answer above is the result
    elif items:
        rules = mail.RuleIndex()
        rows = "".join(person_row(account, it, next_url=here, rules=rules) if group == "people"
                       else org_row(account, it) for it in items)
        listing = f'<ul class="ct-list" data-list-static>{rows}</ul>'
        if group == "people" and any(it.get("masked") for it in items):
            listing = (f'<p class="faint small ct-mask-note">{kit.icon("lock")}<span>Adresser med {kit.icon("lock")} '
                       "vises forkortet (fx h…@firma.dk): den fulde adresse vises kun, hvis personen også har skrevet "
                       "til dig. Skriv en hel adresse i søgefeltet for at tjekke den.</span></p>") + listing
        pages = int(res.get("pages") or 1)
        pager = kit.pagination(min(page, pages), pages,
                               lambda p: _page_url(account, group=group, status=status, q=q, page=p if p > 1 else None))
        if pager:
            listing += f'<div class="list-foot">{pager}</div>'
    elif q:
        listing = kit.empty_state("Ingen kontakter matcher", "Prøv en del af et domæne – eller skriv en hel adresse "
                                  "for at tjekke, om du har skrevet til den.", "search")
    elif group == "orgs":
        listing = kit.empty_state("Ingen organisationer endnu", "Når du har skrevet til flere på samme firmadomæne, "
                                  "samles de her. Gratis-mail som gmail.com tæller ikke med.", "building")
    elif status != "all":
        listing = kit.empty_state("Ingen her", "Der er ingen kontakter med denne status.", "users")
    else:
        listing = kit.empty_state("Ingen kendte kontakter endnu", "Filteret lærer dem fra dine sendte mails. Den "
                                  "første gennemgang tager typisk nogle minutter.", "users")
    total = int(res.get("total") or 0)
    if group == "people" and status == "all" and not q and counts.get("dropped"):
        # The same numbers as the status card: '14 adresser · 12 kendte · 2 fjernet'.
        sub = (f"{_n(total, 'adresse', 'adresser')} · {kit.fmt_int(int(counts.get('active') or 0))} kendte · "
               f"{kit.fmt_int(int(counts.get('dropped') or 0))} fjernet")
    elif group == "people":
        sub = _n(total, "kontakt", "kontakter") if total else ""
    else:
        sub = _n(total, "organisation", "organisationer") if total else ""
    return kit.card(f'<div class="card-pad ct-tools">{group_tabs}<div class="ct-tool-row">{search}{filt}</div>'
                    f'{lookup}</div><div class="card-pad-x ct-list-wrap">{listing}</div>',
                    title="Dem, du har skrevet til", subtitle=sub, cls="flush ct-list-card")


def _mailbox_picker(accounts: dict[str, Any]) -> str:
    """Overview when several mailboxes are visible and none is chosen."""
    cards = []
    for name in accounts:
        ov = _svc("contacts_overview", name, default=None) or {}
        enabled, complete = bool(ov.get("enabled")), bool(ov.get("complete"))
        tone = "ok" if enabled and complete else ("info" if enabled else "neutral")
        n = int(ov.get("contacts") or 0)
        state = (f"{_n(n, 'kendt kontakt', 'kendte kontakter')}" if enabled and complete
                 else "Lærer fra dine sendte mails …" if enabled else "Slået fra")
        cards.append(f'<a class="card ct-pick tone-{tone}" href="{h(_page_url(name))}">'
                     f'<span class="ct-ic tone-{tone}">{kit.icon("user-check" if enabled else "pause")}</span>'
                     f'<span class="ct-pick-text"><b>{kit.acct_name(ui.account_label(name), name)}</b>'
                     f'<span>{h(state)}</span></span>{kit.icon("chevron-right", "ct-pick-caret")}</a>')
    return f'<div class="grid ct-picks">{"".join(cards)}</div>'


@app.get("/rules/contacts")
@ui.login_required
def contacts_page():
    accounts = _visible()
    wanted = (request.args.get("account") or "").strip()
    if wanted:
        _mailbox_or_404(wanted)
    subtitle = ("Folk, du selv har skrevet til, får et forspring, så deres svar ikke havner i spam. "
                "Filteret lærer dem fra dine sendte mails.")
    if not accounts:
        body = mail.rules_tabs("contacts") + kit.card(kit.empty_state(
            "Ingen postkasse endnu", "Du har ikke adgang til nogen postkasser endnu. Bed administratoren om at "
            "give dig adgang.", "inbox"))
        return kit.render_page("Kendte kontakter", body, active=_active_key(), subtitle=subtitle)
    if not wanted and len(accounts) > 1:
        body = (mail.rules_tabs("contacts")
                + f'<p class="muted ct-lead">Vælg en postkasse. Kendte kontakter læres for hver postkasse for sig.</p>'
                + _mailbox_picker(accounts)
                + f'<p class="ct-help ct-help-page">{kit.icon("lock")}<span>{h(HELP_FALLBACK)}</span></p>')
        return kit.render_page("Kendte kontakter", body, active=_active_key(), subtitle=subtitle)
    account = wanted or next(iter(accounts))
    group = request.args.get("group", "people")
    group = group if group in {g for g, _l in GROUPS} else "people"
    status = request.args.get("status", "all")
    status = status if status in {s for s, _l in STATUS_FILTERS} else "all"
    q = " ".join((request.args.get("q") or "").split())[:200]
    page = mail._int_arg("page")
    ov = _svc("contacts_overview", account, default=None) or {"ok": False}
    orgs = _svc("contacts_list", account, "", 1, 1, "orgs", default=None) or {}
    counts = {"people": int(ov.get("contacts") or 0) + int(ov.get("removed") or 0) + int(ov.get("demoted") or 0),
              "orgs": int(orgs.get("total") or 0) if isinstance(orgs, dict) else None,
              "active": int(ov.get("contacts") or 0),
              "dropped": int(ov.get("removed") or 0) + int(ov.get("demoted") or 0)}
    body = (mail.rules_tabs("contacts", account)
            + '<div class="grid ct-grid">'
            + _status_card(account, ov)
            + _list_card(account, group=group, status=status, q=q, page=page, counts=counts)
            + "</div>")
    return kit.render_page("Kendte kontakter", body, active=_active_key(), subtitle=subtitle,
                           breadcrumbs=[("Regler", "/rules"), (ui.account_label(account), None)]
                           if ui.can("rules") else None)


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------


def _next(account: str) -> str:
    return ui.safe_next(request.form.get("next"), _page_url(account))


def _fresh_row(account: str, h_: str, mask: str | None, next_url: str) -> str | None:
    """The contact's row after a status change (looked up by its domain)."""
    dom = (mask or "").rpartition("@")[2]
    res = _svc("contacts_list", account, dom, 1, 200, "people", status="all", default=None) or {}
    for it in (res.get("items") or []) if isinstance(res, dict) else []:
        if it.get("h") == h_:
            return person_row(account, it, next_url=next_url)
    return None


@app.post("/rules/contacts/status")
@ui.permission_required("rules")
def contacts_status():
    account = _mailbox_or_404(request.form.get("account") or "")
    if not ui.can("rules", account):
        abort(403)
    h_ = (request.form.get("h") or "").strip().lower()[:64]
    status = request.form.get("status") or ""
    next_url = _next(account)
    if status not in ("removed", "active"):
        return ui.respond("Ukendt handling.", ok=False, next_url=next_url)
    if status == "active":
        res = _svc("restore_contact", account, h_, _actor(), default=None)
    else:
        res = _svc("set_contact_status", account, h_, "removed", _actor(), default=None)
    if not isinstance(res, dict):
        return ui.respond("Kontakten kunne ikke opdateres lige nu. Prøv igen om lidt.", ok=False, next_url=next_url)
    ok = bool(res.get("ok"))
    code = str(res.get("code") or "")
    if code != "unchanged":
        ui.audit("contact_restore" if status == "active" else "contact_remove", account,
                 "ok" if ok else (code or "failed"), detail=str(res.get("audit_detail") or "")[:300])
    extra: dict[str, Any] = {}
    if ok and request.form.get("view") == "contacts":
        row = _fresh_row(account, h_, res.get("mask"), next_url)
        if row is not None:
            extra["rows"] = {f"contact:{h_}": row}
        else:
            extra["refresh"] = True
        if code == "ok":
            back = "removed" if status == "active" and res.get("previous") == "removed" else (
                "active" if status == "removed" else "")
            if back:
                extra["undo"] = {"label": "Fortryd", "url": "/rules/contacts/status",
                                 "fields": {"account": account, "h": h_, "status": back, "view": "contacts",
                                            "next": next_url}}
    elif ok:
        extra["refresh"] = True  # e.g. 'Behold som kontakt' on Oversigt: the notice goes away
    return ui.respond(str(res.get("text") or ("Gemt." if ok else "Kontakten kunne ikke opdateres.")), ok=ok,
                      next_url=next_url, **extra)


@app.post("/rules/contacts/sync")
@ui.login_required
def contacts_sync():
    account = _mailbox_or_404(request.form.get("account") or "")
    next_url = _next(account)
    res = _svc("request_contacts_sync", account, _actor(), default=None)
    if not isinstance(res, dict):
        return ui.respond("Opdateringen kunne ikke bestilles lige nu.", ok=False, next_url=next_url)
    ok = bool(res.get("ok"))
    ui.audit("contacts_sync", account, "ok" if ok else str(res.get("code") or "failed"),
             detail=str(res.get("audit_detail") or "")[:300])
    return ui.respond(str(res.get("text") or ""), ok=ok, next_url=next_url, refresh=ok)


@app.post("/rules/contacts/enabled")
@ui.permission_required("rules")
def contacts_enabled():
    account = _mailbox_or_404(request.form.get("account") or "")
    if not ui.can("rules", account):
        abort(403)
    next_url = _next(account)
    on = (request.form.get("enabled") or "") in ("1", "on", "true")
    acc = ui.account_by_name(account)
    if acc is not None and bool(getattr(acc, "known_contacts", True)) == on:
        return ui.respond("Uændret.", next_url=next_url)
    # save_config (inside the service) validates, writes atomically and
    # audits the action 'known_contacts'.
    res = _svc("set_known_contacts_enabled", account, on, _actor(), default=None)
    if not isinstance(res, dict):
        return ui.respond("Indstillingen kunne ikke gemmes lige nu.", ok=False, next_url=next_url)
    ok = bool(res.get("ok"))
    return ui.respond(str(res.get("text") or ""), ok=ok, next_url=next_url, **({"reload": True} if ok else {}))


# ---------------------------------------------------------------------------
# Vedhæftninger (B17): admin-only exceptions per sender
# ---------------------------------------------------------------------------

ATTACH_TITLE = "Tillad farlige vedhæftninger fra denne afsender"


def _attach_scope_options() -> list[tuple[str, str]]:
    return [("*", "Alle postkasser")] + [(a.name, ui.account_label(a.name)) for a in ui.effective_accounts()]


def _exception_rows(items: list[dict]) -> list[dict]:
    rows = []
    for it in items:
        rid = int(it.get("id") or 0)
        when = kit.fmt_ts(it.get("created_at")) if it.get("created_at") else ""
        hits = int(it.get("hits") or 0)
        pattern_cell = (f'<div class="rule-pattern"><b>{h(it.get("pattern") or "")}</b>'
                        f'<span>{h(it.get("note") or ("Tilføjet af " + str(it.get("created_by") or "–") + (" · " + when if when else "")))}'
                        "</span></div>")
        scope = kit.chip("Alle postkasser", "brand") if it.get("account") == "*" else \
            kit.chip(ui.account_label(str(it.get("account") or "")))
        hits_cell = (f'<span class="hits"><span class="num">{kit.fmt_int(hits)}</span>'
                     + (f'<small class="faint">senest {h(kit.ago(it.get("last_hit_at")))}</small>' if it.get("last_hit_at") else "")
                     + "</span>")
        remove = kit.post_form(
            f"/rules/attachments/{rid}/delete",
            kit.hidden("next", "/rules/attachments")
            + kit.button("Fjern", kind="secondary", icon="trash", size="sm", tone="neutral",
                         attrs=f'aria-label="Fjern undtagelsen for {h(it.get("pattern") or "")}" ' + kit.confirm_attrs(
                             "Fjern undtagelsen?",
                             f"Farlige vedhæftninger fra {it.get('pattern')} blokeres igen.", confirm="Fjern",
                             tone="danger")))
        rows.append({"cells": [pattern_cell, scope, hits_cell, remove], "attrs": f'data-row="attach:{rid}"'})
    return rows


@app.get("/rules/attachments")
@ui.admin_required
def attachments_page():
    res = _svc("attachment_exceptions", None, default=None) or {}
    items = list(res.get("items") or []) if isinstance(res, dict) else []
    policy = _svc("attachment_policy", default=None) or {}
    exts = list(policy.get("extensions") or []) if isinstance(policy, dict) else []
    form = kit.card(
        kit.post_form(
            "/rules/attachments/add",
            '<div class="form-grid">'
            + kit.form_field("Afsender eller domæne",
                             kit.input_("pattern", "", attrs='placeholder="bogholderi@revisor.dk eller @revisor.dk" '
                                                             'required autocomplete="off" autocapitalize="none" '
                                                             'spellcheck="false" maxlength="320"'),
                             hint="Et domæne (@firma.dk) gælder også underdomæner.")
            + kit.form_field("Gælder for", kit.select("account", _attach_scope_options(), "*"))
            + kit.form_field("Note (valgfri)", kit.input_("note", "", attrs='maxlength="200" '
                                                                         'placeholder="Fx revisoren sender .exe-installere"'))
            + kit.hidden("next", "/rules/attachments")
            + f'<div class="form-actions">{kit.button("Tilføj undtagelse", kind="primary", icon="plus")}</div></div>',
            attrs="data-reset"),
        title="Ny undtagelse",
        subtitle="Gælder kun, når mailen beviseligt kommer fra afsenderens domæne (DKIM). Virus stoppes altid.")
    chips = "".join(f'<span class="chip tone-neutral mono">.{h(e)}</span>' for e in exts[:40])
    policy_card = kit.card(
        f'<p class="muted">{h(str((policy or {}).get("help") or ""))}</p>'
        + (f'<div class="ext-chips ext-chips-ro">{chips}</div>' if chips else "")
        + f'<div class="form-actions">{kit.button("Redigér listen", href="/settings#vedhaeftninger", kind="secondary", icon="settings", size="sm")}</div>',
        title="Filtyper, der blokeres", subtitle=f"{_n(len(exts), 'filtype', 'filtyper')}" if exts else "")
    table = (kit.table([("Afsender", ""), ("Gælder", ""), ("Brugt", "num"), ("", "end")], _exception_rows(items),
                       cls="rules-table attach-table")
             if items else kit.empty_state("Ingen undtagelser", "Alle afsendere er omfattet af blokeringen af farlige "
                                           "vedhæftninger. Tilføj kun en undtagelse for en afsender, du stoler 100 % på.",
                                           "paperclip"))
    body = (mail.rules_tabs("attachments")
            + f'<div class="grid grid-rules">{form}<div class="stack">'
            + kit.card(f'<div class="card-pad-x">{table}</div>', title="Afsendere med undtagelse",
                       subtitle=str((res or {}).get("help") or ""), cls="flush")
            + policy_card + "</div></div>")
    return kit.render_page("Farlige vedhæftninger", body, active="attachments",
                           subtitle="Undtagelser for afsendere, der har brug for at sende blokerede filtyper.",
                           breadcrumbs=[("Regler", "/rules"), ("Vedhæftninger", None)])


@app.post("/rules/attachments/add")
@ui.admin_required
def attachments_add():
    account = (request.form.get("account") or "*").strip() or "*"
    if account != "*" and ui.account_by_name(account) is None:
        abort(404)
    pattern = (request.form.get("pattern") or "").strip()[:320]
    note = (request.form.get("note") or "").strip()[:200]
    next_url = ui.safe_next(request.form.get("next"), "/rules/attachments")
    res = _svc("add_attachment_exception", account, pattern, _actor(), is_admin=ui.is_admin(), note=note,
               default=None)
    if not isinstance(res, dict):
        return ui.respond("Undtagelsen kunne ikke gemmes lige nu.", ok=False, next_url=next_url)
    ok = bool(res.get("ok"))
    ui.audit("attach_exception_add", "" if account == "*" else account, "ok" if ok else str(res.get("code") or "failed"),
             detail=str(res.get("audit_detail") or "")[:300])
    return ui.respond(str(res.get("text") or ""), ok=ok, next_url=next_url, **({"refresh": True} if ok else {}))


@app.post("/rules/attachments/<int:rule_id>/delete")
@ui.admin_required
def attachments_delete(rule_id: int):
    next_url = ui.safe_next(request.form.get("next"), "/rules/attachments")
    res = _svc("remove_attachment_exception", rule_id, _actor(), is_admin=ui.is_admin(), default=None)
    if not isinstance(res, dict):
        return ui.respond("Undtagelsen kunne ikke slettes lige nu.", ok=False, next_url=next_url)
    ok = bool(res.get("ok"))
    if res.get("code") != "not_found":
        ui.audit("attach_exception_remove", "", "ok" if ok else str(res.get("code") or "failed"),
                 detail=str(res.get("audit_detail") or "")[:300])
    extra = {"rows": {f"attach:{rule_id}": None}} if ok else {}
    return ui.respond(str(res.get("text") or ""), ok=ok, next_url=next_url, status=404 if res.get("code") == "not_found"
                      else 400, **extra)
