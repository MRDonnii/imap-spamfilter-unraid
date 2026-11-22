"""Indstillinger -> Beskyttede domæner (B22) - spamfilter 2.3.6.

  * the card on /settings: the protected domains (list editor), the
    weekly registration watch (last run, "Kør kontrol nu"), registered
    lookalikes, lookalike mail of the last 30 days and the "Ikke en
    efterligning" list;
  * the Oversigt attention item for new registrations (admins only);
  * the "Ikke en efterligning" button on a message detail page (admins).

Access: every route is admin-only through the central policy
(dashboard.admin_required); a Bruger never sees protected domains or the
watch. Lookalike domains are attacker-chosen text: always escaped, never
rendered as a link. Every change is audited (save_config audits
'protected_domains'; the others here).
"""

from __future__ import annotations

import logging
import time
from typing import Any

from flask import request

import dashboard as ui
import ui_kit as kit
from ui_kit import h

log = logging.getLogger("dashboard.lookalike")
app = ui.app

ANCHOR = "beskyttede-domaener"
SETTINGS_URL = f"/settings#{ANCHOR}"
NOT_LOOKALIKE = "Ikke en efterligning"
MAX_LIST = 12            # rows shown before "Vis alle" (details)


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


def _next_url(default: str = SETTINGS_URL) -> str:
    return ui.safe_next(request.form.get("next") or "", default)


def _domain_html(domain: Any, display: Any = None) -> str:
    """A lookalike domain as plain text (never a link)."""
    shown = kit.clean_name(display or domain)
    title = f' title="{h(domain)}"' if display and str(display) != str(domain) else ""
    return f'<span class="mono lk-dom"{title}>{h(shown)}</span>'


def allow_form(domain: str, protected: str = "", *, next_url: str = SETTINGS_URL, size: str = "sm",
               label: str = NOT_LOOKALIKE) -> str:
    confirm = kit.confirm_attrs(
        f"Er {kit.clean_name(domain)} ikke en efterligning?",
        "Mails fra domænet (og dets underdomæner) bliver så bedømt helt normalt, og den ugentlige kontrol "
        "melder ikke om det igen. Mails, der allerede ligger i Spamfilter-mappen, bliver liggende."
        + (f" Domænet ligner {protected}." if protected else ""),
        confirm=NOT_LOOKALIKE, tone="primary")
    inner = (kit.hidden("domain", domain) + kit.hidden("protected", protected or "") + kit.hidden("next", next_url)
             + kit.button(label, kind="secondary", icon="check", size=size, tone="neutral", attrs=confirm))
    return kit.post_form("/settings/lookalike/allow", inner, cls="inline-form")


def _ack_form(domain: str = "", *, next_url: str = SETTINGS_URL, label: str = "Set") -> str:
    inner = (kit.hidden("domain", domain) + kit.hidden("next", next_url)
             + kit.button(label, kind="ghost", icon="check", size="sm"))
    return kit.post_form("/settings/lookalike/ack", inner, cls="inline-form")


def _unallow_form(domain: str) -> str:
    inner = (kit.hidden("domain", domain)
             + kit.button("Fjern", kind="ghost", icon="undo", size="sm",
                          attrs=kit.confirm_attrs(f"Fjern {kit.clean_name(domain)} fra listen?",
                                                  "Domænet bliver igen set som en mulig efterligning.",
                                                  confirm="Fjern")))
    return kit.post_form("/settings/lookalike/unallow", inner, cls="inline-form")


def _run_line(ov: dict) -> str:
    last = ov.get("last_run") if isinstance(ov.get("last_run"), dict) else None
    if ov.get("requested"):
        state = "Kontrollen er bestilt og starter inden for et minut."
    elif last is None:
        state = "Ikke kørt endnu. Første kontrol kører i nat mellem kl. 3 og 5 – eller tryk “Kør kontrol nu”."
    else:
        when = kit.fmt_ts(last.get("finished_at") or last.get("started_at"))
        if last.get("error"):
            why = ("navneserveren kunne ikke nås" if last.get("error") == "resolver unreachable"
                   else f"{_n(int(last.get('errors') or 0), 'opslag', 'opslag')} fejlede hos navneserveren")
            # The retry only runs in the nightly window (lookalike_watch_due).
            state = (f"Seneste forsøg {when}: {why}. Filteret prøver igen mellem kl. 3 og 5 om natten – "
                     "eller tryk “Kør kontrol nu”.")
        else:
            state = (f"Seneste kontrol {when}: {_n(int(last.get('checked') or 0), 'domæne', 'domæner')} slået op"
                     + (f", {_n(int(last.get('new') or 0), 'nyt', 'nye')} med mailserver eller hjemmeside"
                        if last.get("new") else ", intet nyt")
                     + (" (resten kommer med næste gang)" if last.get("capped") or last.get("stopped") else "")
                     + ".")
    run_btn = "" if ov.get("requested") else kit.post_form(
        "/settings/lookalike/run",
        kit.button("Kør kontrol nu", kind="secondary", icon="radar", size="sm",
                   attrs=kit.confirm_attrs("Kør kontrollen nu?",
                                           "Filteret slår de lignende domæner op hos navneserveren – højst 5 opslag "
                                           "i sekundet, så det tager nogle minutter.", confirm="Kør nu")),
        cls="inline-form")
    stats = (f'<span class="faint small">{_n(int(ov.get("candidates") or 0), "variant", "varianter")} overvåges · '
             f'{_n(int(ov.get("registered") or 0), "er registreret", "er registreret")}</span>'
             if ov.get("candidates") else "")
    return (f'<div class="lk-run">{kit.icon("radar")}<div class="lk-run-body"><b>Ugentlig kontrol af '
            f'nyregistreringer</b><span>{h(state)}</span>{stats}</div>{run_btn}</div>')


def _finding_row(f: dict) -> str:
    chips = []
    if f.get("mx"):
        chips.append(kit.chip("Mailserver", "bad"))
    if f.get("a"):
        chips.append(kit.chip("Hjemmeside", "warn"))
    if not f.get("mx") and not f.get("a"):
        chips.append(kit.chip("Kun registreret", "neutral"))
    chips.append(kit.chip(str(f.get("kind_text") or ""), "neutral"))
    if f.get("new"):
        chips.insert(0, kit.chip("Nyt", "bad"))
    act = (kit.badge(NOT_LOOKALIKE, "ok") if f.get("allowed")
           else allow_form(str(f["domain"]), str(f.get("protected") or "")))
    return (f'<li class="lk-row{" is-new" if f.get("new") else ""}"><div class="lk-row-main">'
            f'{_domain_html(f["domain"], f.get("display"))}<span class="lk-like">ligner {h(f.get("protected"))}</span>'
            f'<span class="lk-chips">{"".join(chips)}</span></div><div class="lk-row-act">{act}</div></li>')


def _mail_row(m: dict) -> str:
    where = " og ".join(w for w, on in (("afsender", m.get("sender")), ("link", m.get("link"))) if on)
    meta = f"{_n(int(m.get('n') or 0), 'mail', 'mails')} · {where} · senest {kit.ago(m.get('last_at'))}"
    act = (kit.badge(NOT_LOOKALIKE, "ok") if m.get("allowed")
           else allow_form(str(m["domain"]), str(m.get("protected") or "")))
    return (f'<li class="lk-row"><div class="lk-row-main">{_domain_html(m["domain"])}'
            f'<span class="lk-like">ligner {h(m.get("protected"))}</span>'
            f'<span class="faint small">{h(meta)}</span></div><div class="lk-row-act">{act}</div></li>')


def _list(rows: list[str]) -> str:
    if len(rows) <= MAX_LIST:
        return '<ul class="lk-list">' + "".join(rows) + "</ul>"
    return ('<ul class="lk-list">' + "".join(rows[:MAX_LIST]) + "</ul>"
            + '<details class="disclosure"><summary>' + kit.icon("chevron-right")
            + f"Vis {len(rows) - MAX_LIST} mere</summary>"
            + '<ul class="lk-list">' + "".join(rows[MAX_LIST:]) + "</ul></details>")


def settings_card() -> str:
    """The 'Beskyttede domæner' card on Indstillinger (admin)."""
    ov = _svc("lookalike_overview", default=None)
    if not isinstance(ov, dict):
        ov = {}
    st = ov.get("settings") if isinstance(ov.get("settings"), dict) else {}
    mailbox = [str(d) for d in st.get("mailbox") or []]
    configured = [str(d) for d in st.get("configured") or []]
    default = [str(d) for d in st.get("default") or []]
    limit = int(st.get("max") or 50)
    chips = ("".join(f'<span class="chip tone-brand mono" title="Postkassens domæne – altid beskyttet">{h(d)}</span>'
                     for d in mailbox)
             + "".join(f'<span class="chip tone-neutral mono">{h(d)}</span>' for d in configured if d not in mailbox))
    chips = chips or '<span class="faint small">Ingen</span>'
    parts = [f'<p class="muted">{h(st.get("help") or "")}</p>' if st.get("help") else "",
             f'<div class="ext-chips lk-chips-top">{chips}</div>', _run_line(ov)]
    findings = [f for f in ov.get("findings") or [] if isinstance(f, dict)]
    new = [f for f in findings if f.get("new") and not f.get("allowed")]
    if new:
        parts.append(f'<div class="lk-new">{kit.icon("alert-triangle")}<div><b>'
                     f'{h(_n(len(new), "nyt domæne ligner jeres", "nye domæner ligner jeres"))}</b><span>'
                     f'{"Det" if len(new) == 1 else "De"} har lige fået en mailserver eller en hjemmeside. Mails '
                     "derfra lægges i Spamfilter-mappen. Advar evt. kunder og kolleger.</span></div>" + _ack_form(label="Markér alle som set") + "</div>")
    if findings:
        parts.append(f'<h3 class="lk-h">Registrerede lignende domæner <span class="faint">'
                     f'({kit.fmt_int(int(ov.get("findings_total") or len(findings)))})</span></h3>'
                     + _list([_finding_row(f) for f in findings]))
    mails = [m for m in ov.get("mail") or [] if isinstance(m, dict)]
    if mails:
        parts.append('<h3 class="lk-h">Mails fra lignende domæner <span class="faint">(30 dage)</span></h3>'
                     + _list([_mail_row(m) for m in mails]))
    allowed = [a for a in ov.get("allowed") or [] if isinstance(a, dict)]
    if allowed:
        rows = [f'<li class="lk-row"><div class="lk-row-main">{_domain_html(a["domain"])}'
                f'<span class="faint small">{h(NOT_LOOKALIKE)} · {h(a.get("created_by") or "")} '
                f'{h(kit.fmt_ts(a.get("created_at")))}</span></div>'
                f'<div class="lk-row-act">{_unallow_form(str(a["domain"]))}</div></li>' for a in allowed]
        parts.append(f'<h3 class="lk-h">{h(NOT_LOOKALIKE)}</h3>' + _list(rows))
    reset = (kit.button("Gendan standardlisten", kind="ghost", icon="undo", size="sm",
                        attrs='name="reset" value="1" formnovalidate ' + kit.confirm_attrs(
                            "Gendan standardlisten?", f"Listen bliver igen {', '.join(default)}.", confirm="Gendan"))
             if st.get("custom") else "")
    per = st.get("per_account") or {}
    per_note = (f'<p class="faint small">Har sin egen liste i accounts.yml: '
                f'{h(", ".join(ui.account_label(n) for n in per))}.</p>' if per else "")
    editor = kit.post_form("/settings/lookalike", (
        kit.form_field("Ekstra beskyttede domæner",
                       kit.textarea("domains", "\n".join(configured), rows=3,
                                    attrs='spellcheck="false" autocapitalize="none" autocomplete="off"'),
                       hint=f"Ét domæne pr. linje (eller adskilt med mellemrum), fx jeres bank eller e-conomic.dk. "
                            f"Postkassernes egne domæner er altid med. Højst {limit}.")
        + per_note + f'<div class="form-actions">{reset}{kit.button("Gem", kind="primary", icon="check")}</div>'))
    parts.append('<details class="disclosure lk-edit"><summary>' + kit.icon("chevron-right")
                 + "Redigér listen</summary>" + editor + "</details>")
    n_prot = len(st.get("effective") or (mailbox + configured))
    return (f'<div id="{ANCHOR}">' + kit.card(
        "".join(parts), title="Beskyttede domæner",
        subtitle=f"{_n(n_prot, 'domæne', 'domæner')} – efterligninger stoppes og meldes.", cls="lk-card")
        + "</div>")


# ---------------------------------------------------------------------------
# Oversigt + message detail hooks
# ---------------------------------------------------------------------------


def attention_items() -> list[dict[str, str]]:
    """Oversigt: new registrations (last 14 days, not seen / allowed).
    Admins only (the caller checks too)."""
    if not ui.is_admin():
        return []
    items = _svc("lookalike_attention", default=[]) or []
    items = [i for i in items if isinstance(i, dict) and i.get("domain")]
    if not items:
        return []
    here = "/"
    if len(items) == 1:
        it = items[0]
        title = f"Nyt domæne ligner {it.get('protected')}"
        text = (f"{it.get('text')}. Mails derfra lægges i Spamfilter-mappen. Overvej at advare kunder og "
                "kolleger.")
        form = _ack_form(str(it["domain"]), next_url=here)
    else:
        targets = sorted({str(i.get("protected")) for i in items})
        title = f"{len(items)} nye domæner ligner jeres"
        text = (f"Domænerne ligner {ui._da_join(targets)}. De har lige fået en mailserver eller en "
                "hjemmeside, og mails derfra lægges i Spamfilter-mappen.")
        form = _ack_form(next_url=here, label="Markér som set")
    return [{"tone": "bad", "icon": "globe", "title": title, "text": text, "href": SETTINGS_URL,
             "link": "Se domænerne", "form": form}]


def detail_actions(symbols: Any, here: str) -> str:
    """Message detail (admins): 'Ikke en efterligning' for the lookalike
    domain(s) the mail was scored for."""
    if not ui.is_admin():
        return ""
    seen: list[tuple[str, str]] = []
    for s in symbols or []:
        if not isinstance(s, dict) or s.get("n") not in ("TH_LOOKALIKE_DOMAIN", "TH_LOOKALIKE_URL"):
            continue
        o = [str(x) for x in s.get("o") or []]
        if len(o) >= 2 and (o[0], o[1]) not in seen:
            seen.append((o[0], o[1]))
    if not seen:
        return ""
    btns = "".join(allow_form(d, p, next_url=here, size="", label=f"{NOT_LOOKALIKE}: {kit.clean_name(d)[:40]}")
                   for d, p in seen[:2])
    return (f'<div class="lk-detail"><p class="faint small">Domænet ligner et af jeres egne. Er det en kendt '
            f'samarbejdspartner, så markér det – kun administratorer kan.</p>{btns}</div>')


# ---------------------------------------------------------------------------
# Routes (admin only)
# ---------------------------------------------------------------------------


@app.post("/settings/lookalike")
@ui.admin_required
def settings_lookalike():
    reset = (request.form.get("reset") or "") == "1"
    text = (request.form.get("domains") or "")[:4000]
    if ui.config_error():
        return ui.respond("accounts.yml kan ikke indlæses – ret filen, før du ændrer listen.", ok=False,
                          next_url=SETTINGS_URL)
    # save_config (inside the service) validates, writes atomically and
    # audits the action 'protected_domains'.
    res = _svc("set_protected_domains", text, _actor(), reset=reset, default=None)
    if not isinstance(res, dict):
        return ui.respond("Listen kunne ikke gemmes lige nu.", ok=False, next_url=SETTINGS_URL)
    ok = bool(res.get("ok"))
    changed = ok and res.get("code") == "ok"
    return ui.respond(str(res.get("text") or ("Gemt." if ok else "Listen blev ikke gemt.")), ok=ok,
                      next_url=SETTINGS_URL, **({"reload": True} if changed else {}))


@app.post("/settings/lookalike/allow")
@ui.admin_required
def settings_lookalike_allow():
    domain = (request.form.get("domain") or "").strip()[:253]
    protected = (request.form.get("protected") or "").strip()[:253]
    back = _next_url()
    res = _svc("lookalike_allow", domain, _actor(), protected=protected or None, default=None)
    if not isinstance(res, dict):
        return ui.respond("Det kunne ikke gemmes lige nu.", ok=False, next_url=back)
    ok = bool(res.get("ok"))
    if res.get("code") == "ok":
        ui.audit("lookalike_allow", detail=f"{res.get('domain')}" + (f" ligner {protected}" if protected else ""))
    elif not ok:
        ui.audit("lookalike_allow", result="rejected", detail=f"{domain[:120]} {res.get('code')}")
    return ui.respond(str(res.get("text") or ""), ok=ok, next_url=back, reload=ok)


@app.post("/settings/lookalike/unallow")
@ui.admin_required
def settings_lookalike_unallow():
    domain = (request.form.get("domain") or "").strip()[:253]
    res = _svc("lookalike_unallow", domain, _actor(), default=None)
    if not isinstance(res, dict):
        return ui.respond("Det kunne ikke gemmes lige nu.", ok=False, next_url=SETTINGS_URL)
    if res.get("ok"):
        ui.audit("lookalike_unallow", detail=str(res.get("domain") or "")[:200])
    return ui.respond(str(res.get("text") or ""), ok=bool(res.get("ok")), next_url=SETTINGS_URL,
                      reload=bool(res.get("ok")))


@app.post("/settings/lookalike/ack")
@ui.admin_required
def settings_lookalike_ack():
    domain = (request.form.get("domain") or "").strip()[:253]
    back = _next_url()
    res = _svc("lookalike_ack", _actor(), domain=domain or None, default=None)
    if not isinstance(res, dict):
        return ui.respond("Det kunne ikke gemmes lige nu.", ok=False, next_url=back)
    if res.get("code") == "ok":
        ui.audit("lookalike_ack", detail=(domain or f"alle ({res.get('n')})")[:200])
    return ui.respond(str(res.get("text") or ""), ok=bool(res.get("ok")), next_url=back,
                      reload=bool(res.get("ok")))


@app.post("/settings/lookalike/run")
@ui.admin_required
def settings_lookalike_run():
    res = _svc("lookalike_request_run", _actor(), default=None)
    if not isinstance(res, dict):
        return ui.respond("Kontrollen kunne ikke bestilles lige nu.", ok=False, next_url=SETTINGS_URL)
    if res.get("code") == "ok":
        ui.audit("lookalike_run", detail=time.strftime("%Y-%m-%d %H:%M"))
    return ui.respond(str(res.get("text") or ""), ok=bool(res.get("ok")), next_url=SETTINGS_URL,
                      reload=bool(res.get("ok")))
