"""Indstillinger -> Beskyttede navne (2.7, Falske afsendernavne) -
spamfilter.

  * the card on /settings: Fra / Prøv / Til, the protected names with the
    addresses and domains allowed to use them (add, edit, switch off,
    remove, "Hent navne fra Sendt post"), and the mail of the last 30 days
    that used one of the names from another address - with "Tillad
    adressen" for a person's real address that was not listed yet;
  * the Oversigt attention item when the default Prøv has run a week;
  * "Tillad adressen for <navn>" on a message detail page (admins).

Access: every route is admin-only through the central policy
(dashboard.admin_required); a Bruger never sees the list. Display names
and addresses are attacker-chosen text: always escaped, never a link.
Every change is audited.
"""

from __future__ import annotations

import logging
from typing import Any

from flask import request

import dashboard as ui
import ui_kit as kit
from ui_kit import h

log = logging.getLogger("dashboard.namespoof")
app = ui.app

ANCHOR = "beskyttede-navne"
SETTINGS_URL = f"/settings#{ANCHOR}"
MODE_OPTIONS = (("off", "Fra"), ("shadow", "Prøv"), ("on", "Til"))
MODE_TONE = {"off": "neutral", "shadow": "info", "on": "ok"}
MODE_TEXT = {"off": "Fra", "shadow": "Prøv", "on": "Til"}
FLAG_TEXT = {**kit.NAME_SPOOF_FLAG_TEXT, **kit.NAME_SPOOF_CAP_TEXT}
MAX_LIST = 12


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


def _allow_chips(allow: list[str]) -> str:
    if not allow:
        return '<span class="faint small">Ingen adresser – kun jeres egne domæner</span>'
    return "".join(f'<span class="chip tone-neutral mono">{h(kit.clean_name(a))}</span>' for a in allow)


def allow_form(entry_id: Any, address: str, name: str, *, next_url: str = SETTINGS_URL, size: str = "sm",
               label: str = "Tillad adressen") -> str:
    confirm = kit.confirm_attrs(
        f"Må {kit.clean_name(address)} bruge navnet {kit.clean_name(name)}?",
        "Gør det kun, hvis adressen virkelig er personens egen (fx en privat mail). Mails fra adressen med "
        "navnet får så ingen point for falsk afsendernavn.", confirm="Tillad", tone="primary")
    inner = (kit.hidden("id", entry_id) + kit.hidden("address", address) + kit.hidden("next", next_url)
             + kit.button(label, kind="secondary", icon="check", size=size, tone="neutral", attrs=confirm))
    return kit.post_form("/settings/namespoof/allow", inner, cls="inline-form")


def _delete_form(e: dict) -> str:
    inner = (kit.hidden("id", e["id"])
             + kit.button("Fjern", kind="ghost", icon="undo", size="sm",
                          attrs=kit.confirm_attrs(f"Fjern {kit.clean_name(e['name'])} fra listen?",
                                                  "Navnet bliver ikke længere beskyttet, og filteret henter det ikke "
                                                  "igen fra Sendt post.", confirm="Fjern")))
    return kit.post_form("/settings/namespoof/delete", inner, cls="inline-form")


def _entry_form(e: dict | None = None) -> str:
    e = e or {}
    allow = "\n".join(e.get("allow") or [])
    fields = (kit.hidden("id", e.get("id") or "")
              + kit.form_field("Navn", kit.input_("name", e.get("name") or "",
                                                  attrs='maxlength="80" autocomplete="off" spellcheck="false"'),
                               hint="Fulde navn (fx Anna Jensen) eller firmanavn. Et navn på ét ord rammer kun, når "
                                    "afsendernavnet er præcis det ord.")
              + kit.form_field("Må bruges fra",
                               kit.textarea("allow", allow, rows=3,
                                            attrs='spellcheck="false" autocapitalize="none" autocomplete="off"'),
                               hint="Personens rigtige adresser (fx anna.privat@gmail.com) og domæner, personen "
                                    "skriver via (fx @butiksplatform.dk). Én pr. linje. Jeres egne domæner er "
                                    "altid med. Aldrig et gratis-maildomæne alene.")
              + kit.switch("enabled", bool(e.get("enabled", True)), "Beskyt navnet"))
    return kit.post_form("/settings/namespoof/save", fields + '<div class="form-actions">'
                         + kit.button("Gem", kind="primary", icon="check") + "</div>")


def _entry_row(e: dict) -> str:
    chips = []
    if not e.get("enabled"):
        chips.append(kit.chip("Slået fra", "neutral"))
    if e.get("one_word"):
        chips.append(kit.chip("Kun præcis navn", "neutral"))
    if e.get("source") == "seed":
        chips.append(kit.chip("Fra Sendt post", "neutral"))
    edit = ('<details class="disclosure ns-edit"><summary>' + kit.icon("chevron-right") + "Redigér</summary>"
            + _entry_form(e) + "</details>")
    return (f'<li class="lk-row"><div class="lk-row-main"><b>{h(kit.clean_name(e.get("name")))}</b>'
            f'<span class="lk-chips">{"".join(chips)}</span>'
            f'<div class="ext-chips">{_allow_chips(list(e.get("allow") or []))}</div>{edit}</div>'
            f'<div class="lk-row-act">{_delete_form(e)}</div></li>')


def _hit_row(g: dict) -> str:
    sender = str(g.get("sender") or g.get("masked") or "")
    flags = [FLAG_TEXT[f] for f in g.get("flags") or [] if f in FLAG_TEXT]
    meta = (f"{_n(int(g.get('n') or 0), 'mail', 'mails')} · senest {kit.ago(g.get('last_at'))}"
            + (f" · {', '.join(flags)}" if flags else ""))
    chip = (kit.chip(f"Prøv: ville give +{kit.fmt_num(g.get('score'), 0)}", "info") if g.get("trial") and not g.get("on")
            else kit.chip(f"+{kit.fmt_num(g.get('score'), 0)}", "bad"))
    if g.get("allowed"):
        act = kit.badge("Tilladt", "ok")
    elif g.get("entry_id") and g.get("sender"):
        act = allow_form(g["entry_id"], str(g["sender"]), str(g.get("name") or ""))
    else:
        act = ""
    return (f'<li class="lk-row"><div class="lk-row-main"><span class="mono lk-dom">{h(kit.clean_name(sender))}'
            f'</span><span class="lk-like">brugte navnet {h(kit.clean_name(g.get("name")))}</span>'
            f'<span class="lk-chips">{chip}</span><span class="faint small">{h(meta)}</span></div>'
            f'<div class="lk-row-act">{act}</div></li>')


def _list(rows: list[str]) -> str:
    if len(rows) <= MAX_LIST:
        return '<ul class="lk-list">' + "".join(rows) + "</ul>"
    return ('<ul class="lk-list">' + "".join(rows[:MAX_LIST]) + "</ul>"
            + '<details class="disclosure"><summary>' + kit.icon("chevron-right")
            + f"Vis {len(rows) - MAX_LIST} mere</summary>"
            + '<ul class="lk-list">' + "".join(rows[MAX_LIST:]) + "</ul></details>")


def _mode_form(ov: dict) -> str:
    mode = str((ov.get("mode") or {}).get("mode") or "shadow")
    explain = ("Fra: navnene tjekkes ikke. Prøv: ingen point – filteret viser kun herunder, hvilke mails der ville "
               "have fået point. Til: en mail med et af navnene fra en fremmed adresse får 5 point, 7 hvis svar går "
               "til et andet domæne, afsenderfeltet er ugyldigt, eller emnet ligner direktørsvindel (gavekort, "
               "»er du ved din computer?«, hast eller fortrolighed om en betaling) – almindelige ord som faktura "
               "og betaling tæller ikke. Har afsenderdomænet en gyldig signatur (fx e-conomic), højst 5; en "
               "besked »via« en platform (fx Google Docs, MobilePay) kun 2.")
    inner = (kit.hidden("next", SETTINGS_URL)
             + kit.form_field("Falske afsendernavne", kit.segmented("mode", MODE_OPTIONS, mode), hint=explain)
             + f'<div class="form-actions">{kit.button("Gem", kind="secondary", icon="check")}</div>')
    return kit.post_form("/settings/namespoof/mode", inner)


def _trial_line(ov: dict) -> str:
    m = ov.get("mode") or {}
    if m.get("mode") != "shadow":
        return ""
    days = int(m.get("days") or 0)
    n = int(ov.get("trial_hits") or 0)
    found = _n(n, "mail ville have fået point", "mails ville have fået point")
    if ov.get("suggest_on"):
        keep = kit.post_form("/settings/namespoof/mode", kit.hidden("mode", "shadow")
                             + kit.button("Bliv i Prøv", kind="ghost", size="sm"), cls="inline-form")
        on = kit.post_form("/settings/namespoof/mode", kit.hidden("mode", "on")
                           + kit.button("Slå til", kind="primary", icon="check", size="sm"), cls="inline-form")
        return (f'<div class="lk-new">{kit.icon("info")}<div><b>Prøv har kørt i {_n(days, "dag", "dage")}</b>'
                f"<span>{h(found)} de seneste 30 dage. Er fundene herunder rigtige svindelmails, så slå Til. Er "
                "nogle af dem jeres egne folk, så tryk Tillad adressen først.</span></div>" + on + keep + "</div>")
    return f'<p class="muted small">Prøv i {_n(days, "dag", "dage")}: {h(found)} de seneste 30 dage.</p>'


def settings_card() -> str:
    """The 'Beskyttede navne' card on Indstillinger (admin)."""
    ov = _svc("namespoof_overview", default=None)
    if not isinstance(ov, dict):
        ov = {}
    names = [e for e in ov.get("names") or [] if isinstance(e, dict)]
    hits = [g for g in ov.get("hits") or [] if isinstance(g, dict)]
    mode = str((ov.get("mode") or {}).get("mode") or "shadow")
    own = [str(d) for d in ov.get("own_domains") or []]
    parts = [f'<p class="muted">{h(ov.get("help") or "")}</p>' if ov.get("help") else "", _mode_form(ov),
             _trial_line(ov)]
    if own:
        parts.append('<p class="faint small">Altid tilladt: jeres egne domæner '
                     + "".join(f'<span class="chip tone-brand mono">{h(d)}</span>' for d in own) + "</p>")
    seed_btn = kit.post_form("/settings/namespoof/seed",
                             kit.button("Hent navne fra Sendt post", kind="secondary", icon="refresh", size="sm"),
                             cls="inline-form")
    if names:
        parts.append(f'<h3 class="lk-h">Navne <span class="faint">({kit.fmt_int(len(names))})</span></h3>'
                     + _list([_entry_row(e) for e in names]))
    else:
        parts.append('<p class="faint small">Ingen navne endnu. Filteret henter jeres egne afsendernavne fra Sendt '
                     "post, når Kendte kontakter har læst den – eller tilføj dem her.</p>")
    parts.append('<details class="disclosure ns-add"><summary>' + kit.icon("chevron-right") + "Tilføj navn</summary>"
                 + _entry_form() + "</details>")
    parts.append(f'<div class="form-actions">{seed_btn}</div>')
    if hits:
        parts.append('<h3 class="lk-h">Mails med jeres navne fra andre adresser <span class="faint">(30 dage)</span>'
                     "</h3>" + _list([_hit_row(g) for g in hits]))
    n_on = sum(1 for e in names if e.get("enabled"))
    return (f'<div id="{ANCHOR}">' + kit.card(
        "".join(parts), title="Beskyttede navne",
        subtitle=f"{_n(n_on, 'navn', 'navne')} – falske afsendernavne på jeres egne folk.",
        actions=kit.chip(MODE_TEXT.get(mode, mode), MODE_TONE.get(mode, "neutral")), cls="lk-card ns-card")
        + "</div>")


# ---------------------------------------------------------------------------
# Oversigt + message detail hooks
# ---------------------------------------------------------------------------


def attention_items() -> list[dict[str, str]]:
    """Oversigt: the default Prøv has run a week (admins only)."""
    if not ui.is_admin():
        return []
    items = [i for i in _svc("namespoof_attention", default=[]) or [] if isinstance(i, dict)]
    if not items:
        return []
    it = items[0]
    n = int(it.get("hits") or 0)
    text = (f"Falske afsendernavne har kørt i Prøv i {_n(int(it.get('days') or 0), 'dag', 'dage')}: "
            f"{_n(n, 'mail ville have fået point', 'mails ville have fået point')}. Se fundene, og slå Til.")
    return [{"tone": "info", "icon": "shield", "title": "Beskyttede navne: klar til at slå til?", "text": text,
             "href": SETTINGS_URL, "link": "Se fundene"}]


def detail_actions(symbols: Any, here: str, sender: Any = None) -> str:
    """Message detail (admins): 'Tillad adressen for <navn>' when the mail
    got TH_NAME_SPOOF(_TRIAL) and the name is still on the list."""
    if not ui.is_admin() or not sender:
        return ""
    names = [str((s.get("o") or [""])[0]) for s in symbols or []
             if isinstance(s, dict) and s.get("n") in ("TH_NAME_SPOOF", "TH_NAME_SPOOF_TRIAL") and s.get("o")]
    if not names:
        return ""
    ov = _svc("namespoof_overview", default=None) or {}
    import namespoof  # noqa: PLC0415 - pure helper

    entry = next((e for e in ov.get("names") or [] if isinstance(e, dict)
                  and e.get("key") == namespoof.name_key(names[0])), None)
    if entry is None:
        return ""
    btn = allow_form(entry["id"], str(sender), str(entry["name"]), next_url=here, size="",
                     label=f"Tillad adressen for {kit.clean_name(entry['name'])[:40]}")
    return (f'<div class="lk-detail"><p class="faint small">Afsendernavnet er en af jeres egne. Er adressen '
            f'personens egen, så tillad den – kun administratorer kan.</p>{btn}</div>')


# ---------------------------------------------------------------------------
# Routes (admin only)
# ---------------------------------------------------------------------------


@app.post("/settings/namespoof/mode")
@ui.admin_required
def settings_namespoof_mode():
    value = (request.form.get("mode") or "").strip().lower()
    res = _svc("namespoof_set_mode", value, _actor(), default=None)
    if not isinstance(res, dict):
        return ui.respond("Det kunne ikke gemmes lige nu.", ok=False, next_url=SETTINGS_URL)
    if res.get("code") == "ok":
        ui.audit("namespoof_mode", detail=f"mode={res.get('mode')}")
    return ui.respond(str(res.get("text") or ""), ok=bool(res.get("ok")), next_url=SETTINGS_URL,
                      reload=res.get("code") == "ok")


@app.post("/settings/namespoof/save")
@ui.admin_required
def settings_namespoof_save():
    entry_id = (request.form.get("id") or "").strip()[:12]
    name = (request.form.get("name") or "")[:200]
    allow = (request.form.get("allow") or "")[:4000]
    enabled = (request.form.get("enabled") or "") == "1"
    res = _svc("namespoof_save", name, allow, _actor(), enabled=enabled, entry_id=entry_id or None, default=None)
    if not isinstance(res, dict):
        return ui.respond("Det kunne ikke gemmes lige nu.", ok=False, next_url=SETTINGS_URL)
    if res.get("code") == "ok":
        e = res.get("entry") or {}
        ui.audit("namespoof_name", detail=(f"{'ændret' if entry_id else 'tilføjet'} id={e.get('id')} "
                                           f"adresser={len(e.get('allow') or [])} "
                                           f"{'til' if e.get('enabled') else 'fra'}")[:200])
    return ui.respond(str(res.get("text") or ""), ok=bool(res.get("ok")), next_url=SETTINGS_URL,
                      reload=res.get("code") == "ok")


@app.post("/settings/namespoof/delete")
@ui.admin_required
def settings_namespoof_delete():
    entry_id = (request.form.get("id") or "").strip()[:12]
    res = _svc("namespoof_delete", entry_id, _actor(), default=None)
    if not isinstance(res, dict):
        return ui.respond("Det kunne ikke gemmes lige nu.", ok=False, next_url=SETTINGS_URL)
    if res.get("ok"):
        ui.audit("namespoof_name_remove", detail=f"id={entry_id}")
    return ui.respond(str(res.get("text") or ""), ok=bool(res.get("ok")), next_url=SETTINGS_URL,
                      reload=bool(res.get("ok")))


@app.post("/settings/namespoof/allow")
@ui.admin_required
def settings_namespoof_allow():
    entry_id = (request.form.get("id") or "").strip()[:12]
    address = (request.form.get("address") or "").strip()[:254]
    back = _next_url()
    res = _svc("namespoof_allow", entry_id, address, _actor(), default=None)
    if not isinstance(res, dict):
        return ui.respond("Det kunne ikke gemmes lige nu.", ok=False, next_url=back)
    if res.get("code") == "ok":
        import contacts  # noqa: PLC0415 - mask helper

        ui.audit("namespoof_allow", detail=f"id={entry_id} {contacts.mask(address)}"[:200])
    return ui.respond(str(res.get("text") or ""), ok=bool(res.get("ok")), next_url=back,
                      reload=res.get("code") == "ok")


@app.post("/settings/namespoof/seed")
@ui.admin_required
def settings_namespoof_seed():
    res = _svc("namespoof_seed_now", _actor(), default=None)
    if not isinstance(res, dict):
        return ui.respond("Navnene kunne ikke hentes lige nu.", ok=False, next_url=SETTINGS_URL)
    if res.get("code") == "ok":
        ui.audit("namespoof_seed", detail=f"added={res.get('added')} extended={res.get('extended')}")
    return ui.respond(str(res.get("text") or ""), ok=bool(res.get("ok")), next_url=SETTINGS_URL,
                      reload=res.get("code") == "ok")
