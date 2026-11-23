"""Tjek disse → "Regler at tjekke" (spamfilter 2.12, #8 and #9).

Administrators only. Shows the notes junkrules.py keeps:

  * conflict: a user moved mail to Junk although a hand-made allow rule of
    the mailbox lets the sender through (often the rule a release in
    someone else's mailbox made). Buttons: "Fjern reglen", "Bloker for
    kontoen", "Ignorer".
  * suggest: three moves to Junk of the same (authenticated) sender in one
    mailbox: "Bloker for kontoen" / "Ignorer". With the account's approved
    repeated-spam automation, three fresh corrections can block it directly
    (shown with "Fjern blokeringen").

Every action works on ONE mailbox and the exact address only. Nothing here
moves or deletes mail: a rule only acts on mail that arrives later.
"""

from __future__ import annotations

import logging
from typing import Any

from flask import request

import dashboard as ui
import junkrules
import ui_kit as kit
from ui_kit import h

log = logging.getLogger("dashboard.junkrules")
app = ui.app

ACTIONS = ("remove_rule", "block", "dismiss", "undo")
MAX_SHOWN = 12
STATUS_TEXT = {"auto_blocked": ("Blokeret automatisk", "warn"), "blocked": ("Blokeret", "warn"),
               "rule_removed": ("Reglen fjernet", "ok"), "dismissed": ("Ignoreret", "neutral"),
               "undone": ("Blokering fjernet", "neutral")}


def _actor() -> str:
    return str((ui.current_user() or {}).get("name", ""))


def _form(note: dict[str, Any], action: str, label: str, *, icon: str, tone: str = "", kind: str = "secondary",
          confirm: str = "", here: str = "/spam") -> str:
    attrs = ""
    if confirm:
        attrs = kit.confirm_attrs(label + "?", confirm, confirm=label, tone="danger" if tone == "bad" else "primary")
    inner = (kit.hidden("account", note["account"]) + kit.hidden("sender", note["sender"])
             + kit.hidden("kind", note["kind"]) + kit.hidden("action", action) + kit.hidden("next", here)
             + kit.button(label, kind=kind, icon=icon, tone=tone, size="sm", attrs=attrs))
    return kit.post_form("/spam/junk-notes", inner, cls="inline-form")


def _times(n: int) -> str:
    return f"{kit.fmt_int(n)} {'gang' if n == 1 else 'gange'}"


def _row(n: dict[str, Any], here: str) -> str:
    acc = ui.account_label(n["account"])
    who = h(n["sender"])
    moved = _times(int(n.get("n_junk") or 0))
    status = str(n.get("status") or "open")
    if n["kind"] == "conflict":
        by = f" (lavet af {h(n['rule_by'])})" if n.get("rule_by") else ""
        title = f"{who} er tilladt i {h(acc)}, men brugeren har flyttet mails derfra til Junk {moved}"
        text = (f"Reglen {h(n.get('rule_pattern') or '')}{by} lader afsenderen komme igennem. Hvem har ret? "
                "Fjern reglen, eller bloker afsenderen for netop denne postkasse.")
    else:
        title = f"{who} er flyttet til Junk {moved} i {h(acc)}"
        text = ("Filteret har blokeret afsenderen for netop denne postkasse. Nye mails derfra flyttes til "
                "Spamfilter-mappen; mails, der allerede ligger i postkassen, røres ikke."
                if status == "auto_blocked" else
                "Bloker afsenderen for netop denne postkasse? Nye mails derfra flyttes så til Spamfilter-mappen; "
                "mails, der allerede ligger i postkassen, røres ikke.")
    btns = ""
    if status == "open":
        block_confirm = (f"Nye mails fra {n['sender']} flyttes til Spamfilter-mappen i {acc}. Andre postkasser "
                         "påvirkes ikke, og intet slettes.")
        if n["kind"] == "conflict":
            btns += _form(n, "remove_rule", "Fjern reglen", icon="trash", here=here,
                          confirm=f"Reglen {n.get('rule_pattern') or ''} i {acc} fjernes. Filteret vurderer derefter "
                                  "mails fra afsenderen som alle andre.")
        btns += _form(n, "block", "Bloker for kontoen", icon="ban", tone="bad", here=here, confirm=block_confirm)
        btns += _form(n, "dismiss", "Ignorer", icon="x", kind="ghost", here=here)
    elif status == "auto_blocked":
        btns += _form(n, "undo", "Fjern blokeringen", icon="undo", here=here,
                      confirm=f"Blokeringen af {n['sender']} i {acc} fjernes igen.")
    badge = "" if status == "open" else kit.badge(*STATUS_TEXT.get(status, (status, "neutral")))
    return (f'<li class="review-row" data-row="junknote:{h(n["account"])}:{who}:{h(n["kind"])}">'
            f'<div class="review-main"><span class="review-who"><b>{title}</b> {badge}</span>'
            f'<span class="review-subj">{text}</span>'
            f'<span class="review-meta"><time datetime="{kit.iso_ts(n.get("last_at"))}">'
            f'{h(kit.fmt_ts(n.get("last_at")))}</time>{kit.chip(acc, "neutral")}</span></div>'
            f'<div class="review-actions">{btns}</div></li>')


def section(selected: str = "", here: str = "/spam") -> str:
    """The admin card under Tjek disse ('' when there is nothing)."""
    if not ui.is_admin():
        return ""
    try:
        accounts = [selected] if selected else None
        items = junkrules.notes(ui.db(), accounts)
    except Exception as ex:  # noqa: BLE001 - a hint must never break the page
        log.warning("junk notes failed: %s", type(ex).__name__)
        return ""
    if not items:
        return ""
    n_open = sum(1 for n in items if n.get("status") == "open")
    rows = "".join(_row(n, here) for n in items[:MAX_SHOWN])
    return ('<section class="card review-card" id="regler-at-tjekke" aria-labelledby="rt-title">'
            f'<div class="review-head"><span class="review-icon">{kit.icon("t-list-check")}</span><div>'
            f'<h2 class="card-title" id="rt-title">Tjek disse: regler og flytninger til Junk '
            f'<span class="badge tone-info">{kit.fmt_int(n_open)}</span></h2>'
            '<p class="card-sub">Afsendere, som brugerne selv flytter til Junk. Kun for administratorer; '
            "hver handling gælder én postkasse og flytter ingen mails.</p></div></div>"
            f'<ul class="review-list">{rows}</ul></section>')


def _rule(rule_id: Any) -> Any:
    if rule_id is None:
        return None
    return ui.query("SELECT * FROM sender_rules WHERE id=?", [int(rule_id)], one=True)


@app.post("/spam/junk-notes")
@ui.admin_required
def junk_notes_action():
    account = (request.form.get("account") or "").strip()[:128]
    sender = (request.form.get("sender") or "").strip().lower()[:254]
    kind = request.form.get("kind") or ""
    action = request.form.get("action") or ""
    back = ui.safe_next(request.form.get("next") or "", "/spam")
    if kind not in junkrules.KINDS or action not in ACTIONS:
        return ui.respond("Ukendt handling.", ok=False, next_url=back)
    conn = ui.db()
    note = junkrules.get(conn, account, sender, kind)
    if note is None:
        return ui.respond("Forslaget findes ikke længere.", ok=False, next_url=back, status=404)
    actor = _actor()
    status = str(note.get("status") or "")
    if action == "undo":
        if status != "auto_blocked":
            return ui.respond("Der er ingen automatisk blokering at fjerne.", ok=False, next_url=back)
        rule = _rule(note.get("block_rule_id"))
        if rule is not None and rule["kind"] == "block" and rule["created_by"] == junkrules.AUTO_BY:
            ui.engine.delete_sender_rule(conn, int(rule["id"]))
        junkrules.decide(conn, account, sender, kind, "undone", actor)
        conn.commit()
        ui.audit("junk_note_undo", account, detail=f"block {sender}")
        return ui.respond(f"Blokeringen af {sender} er fjernet.", next_url=back, reload=True)
    if status != "open":
        return ui.respond("Det er allerede afgjort.", ok=False, next_url=back)
    if action == "dismiss":
        junkrules.decide(conn, account, sender, kind, "dismissed", actor)
        conn.commit()
        ui.audit("junk_note_dismiss", account, detail=f"{kind} {sender}")
        return ui.respond("Ignoreret.", next_url=back, reload=True)
    if action == "remove_rule":
        rule = _rule(note.get("rule_id")) if kind == "conflict" else None
        if (rule is None or rule["kind"] != "allow" or rule["account"] != account
                or junkrules.is_force(rule)):
            return ui.respond("Reglen findes ikke længere eller er sat til Altid igennem.", ok=False, next_url=back)
        ui.engine.delete_sender_rule(conn, int(rule["id"]))
        junkrules.decide(conn, account, sender, kind, "rule_removed", actor)
        conn.commit()
        ui.audit("junk_note_remove_rule", account, detail=f"allow {rule['pattern']}")
        return ui.respond(f"Reglen {rule['pattern']} er fjernet for {ui.account_label(account)}.", next_url=back,
                          reload=True)
    # block: the exact address, this mailbox only, with the rules dialog's refusals
    import ui_mail  # noqa: PLC0415 - registered before this module

    try:
        pattern = ui.engine.normalize_rule_pattern(sender)
    except ValueError:
        return ui.respond("Afsenderens adresse er ugyldig.", ok=False, next_url=back)
    refusal = ui_mail.rule_refusal(account, "block", pattern)
    if refusal is None and junkrules.protected(pattern):
        refusal = ("own_shop", "Mail fra jeres egen platform skal altid igennem.")
    if refusal is not None:
        return ui.respond(refusal[1], ok=False, next_url=back, status=403)
    rid = ui.engine.add_sender_rule(conn, account, pattern, "block",
                                    junkrules.NOTE_TEXT.format(n=int(note.get("n_junk") or 0)), actor)
    junkrules.decide(conn, account, sender, kind, "blocked", actor, block_rule_id=int(rid))
    conn.commit()
    ui.audit("junk_note_block", account, detail=f"block {pattern}")
    return ui.respond(f"{pattern} er blokeret for {ui.account_label(account)}. Mails, der allerede ligger i "
                      "postkassen, er ikke flyttet.", next_url=back, reload=True)
