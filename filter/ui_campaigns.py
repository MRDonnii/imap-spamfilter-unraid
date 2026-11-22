"""Oversigt items for Spamfilter 2.6 (campaigns.py):

  * A3 block suggestions: "Forslag: bloker @domæne for alle postkasser"
    with "Bloker for alle" (the normal POST /rules/add with account '*',
    scope=domain - so the same refusals, the Fortryd and the audit apply)
    and "Ignorer" (POST /rules/suggestions/dismiss, persisted);
  * A6 protected recipients: "Spam samler sig i en beskyttet indbakke".

Admins only (the routes through the central policy, the items here).
Domains come from mail headers: always escaped, never rendered as a link.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import quote

from flask import request

import dashboard as ui
import ui_kit as kit

log = logging.getLogger("dashboard.campaigns")
app = ui.app

MAX_SUGGESTIONS = 2      # Oversigt shows at most this many block suggestions
PROTECTED_TITLE = "Spam samler sig i en beskyttet indbakke"


def _svc(fn: str, *args: Any, default: Any = None, **kwargs: Any) -> Any:
    try:
        return getattr(ui.services, fn)(*args, **kwargs)
    except Exception as ex:  # noqa: BLE001 - a hint must never break Oversigt
        log.warning("services.%s failed: %s", fn, type(ex).__name__)
        return default


def _n(n: int, one: str, many: str) -> str:
    return f"{kit.fmt_int(n)} {one if n == 1 else many}"


CAMPAIGN_EVENTS = frozenset({"campaign_move", "campaign_shadow", "campaign_skipped"})
_SRC_RE = re.compile(r"[Ss]amme spam som i ([^\s:()]+)")
_KILDE_RE = re.compile(r"\s*\(kilde [^)]*\)\s*$")


def event_detail(detail: str) -> str:
    """'Samme spam som i bynet: samme afsender og emne (kilde x@y)' with
    the mailbox's friendly name; the source Message-ID only for admins."""
    text = kit.clean_name(detail)
    text = _SRC_RE.sub(lambda m: f"Samme spam som i {ui.account_label(m.group(1))}", text, count=1)
    if not ui.is_admin():
        text = _KILDE_RE.sub("", text)
    return text


def _refuse(pattern: str) -> bool:
    """The rules dialog's refusals for a global block of `pattern`
    (freemail, the owner's own domains / webshop, 'Altid igennem')."""
    import ui_mail  # noqa: PLC0415 - loaded before this module registers

    return ui_mail.rule_refusal("*", "block", pattern) is not None


def block_form(domain: str, n: int, n_acc: int, *, next_url: str = "/") -> str:
    confirm = kit.confirm_attrs(
        f"Bloker @{domain} for alle postkasser?",
        f"Alle mails fra {domain} og dets underdomæner flyttes til Spamfilter-mappen i alle postkasser. "
        "Reglen kan fjernes igen under Regler.", confirm="Bloker for alle", tone="danger")
    inner = (kit.hidden("kind", "block") + kit.hidden("account", "*") + kit.hidden("pattern", "@" + domain)
             + kit.hidden("scope", "domain") + kit.hidden("next", next_url)
             + kit.hidden("note", f"Forslag: {n} spam-mails fra {n_acc} postkasser")
             + kit.button("Bloker for alle", kind="secondary", icon="ban", tone="bad", size="sm", attrs=confirm))
    return kit.post_form("/rules/add", inner, cls="inline-form")


def dismiss_form(domain: str, *, next_url: str = "/") -> str:
    inner = (kit.hidden("domain", domain) + kit.hidden("next", next_url)
             + kit.button("Afvis", kind="ghost", icon="x", size="sm"))
    return kit.post_form("/rules/suggestions/dismiss", inner, cls="inline-form")


def suggestion_items() -> list[dict[str, str]]:
    out = []
    for s in (_svc("block_suggestions", refuse=_refuse, default=[]) or [])[:MAX_SUGGESTIONS]:
        if not isinstance(s, dict) or not s.get("domain"):
            continue
        dom = kit.clean_name(str(s["domain"]))
        n, n_acc = int(s.get("n") or 0), len(s.get("accounts") or [])
        out.append({
            "tone": "info", "icon": "ban",
            "title": f"Forslag: bloker @{dom} for alle postkasser ({n} spam-mails fra {n_acc} postkasser)",
            "text": "Mails fra domænet er markeret som spam i flere postkasser de seneste 30 dage, og ingen af "
                    "dem er frigivet. Blokerer du domænet, flyttes fremtidige mails derfra til Spamfilter-mappen.",
            "href": "", "link": "",
            "form": block_form(dom, n, n_acc) + dismiss_form(dom)})
    return out


def protected_items() -> list[dict[str, str]]:
    out = []
    for w in _svc("protected_watch", default=[]) or []:
        if not isinstance(w, dict) or not w.get("account"):
            continue
        name = str(w["account"])
        n = int(w.get("n") or 0)
        out.append({
            "tone": "warn", "icon": "shield-alert",
            "title": f"{PROTECTED_TITLE} ({ui.account_label(name)})",
            "text": (f"{_n(n, 'mail', 'mails')} over grænsen – overvej at sænke grænsen for beskyttede adresser "
                     f"(nu {kit.fmt_score(float(w.get('protected_threshold') or 0))}, normal grænse "
                     f"{kit.fmt_score(float(w.get('threshold') or 0))}). Talt de seneste 7 dage; mailene ligger "
                     "stadig i indbakken."),
            "href": f"/accounts/{quote(name, safe='')}", "link": "Se beskyttede adresser"})
    return out


def attention_items() -> list[dict[str, str]]:
    """Oversigt: A6 warnings first, then A3 suggestions. Admins only."""
    if not ui.is_admin():
        return []
    return protected_items() + suggestion_items()


@app.post("/rules/suggestions/dismiss")
@ui.admin_required
def rules_suggestion_dismiss():
    domain = (request.form.get("domain") or "").strip()[:253]
    back = ui.safe_next(request.form.get("next") or "", "/")
    actor = (ui.current_user() or {}).get("name", "")
    res = _svc("dismiss_block_suggestion", domain, actor, default=None)
    if not isinstance(res, dict):
        return ui.respond("Det kunne ikke gemmes lige nu.", ok=False, next_url=back)
    if res.get("ok"):
        ui.audit("block_suggestion_dismiss", detail=str(res.get("domain") or domain)[:200])
    return ui.respond(str(res.get("text") or ""), ok=bool(res.get("ok")), next_url=back, reload=bool(res.get("ok")))
