"""Mailsikkerhed (2.7) - the admin page /mailcheck - spamfilter.

  * the newest stored run of mailcheck.py: per domain every check with its
    status (OK / Info / Advarsel / Fejl / Ikke testet), a plain Danish
    explanation and how to fix it; the mail servers (TLS, certificate);
    the blacklist lookups of the providers' sending addresses;
  * "Siden sidst" (what changed against the run before), the history of
    the last 30 runs (?run=<id> shows an older one);
  * "Intern tilstand": the existing health results (all-in-one health
    check parts, heartbeat, encrypted backup + off-site copy, DMARC report
    freshness) with a link to Drift - read from the same functions Drift
    and sfctl doctor use;
  * "Tjek nu" (POST, CSRF) asks the engine to run within a minute; the
    settings form (extra domains, "sender ikke mail", skipped domains,
    DKIM selectors) is audited ('mailcheck_settings');
  * "Kendt – ignorér" per warning/error of the newest run (POST, CSRF,
    audited 'mailcheck_ack'): stored with the finding's fingerprint, the
    finding then shows as info, never alerts and does not count in HA
    until it changes. Nothing is acknowledged automatically.

Opening the page never touches the network. Access: admin only. Check
texts can carry DNS content (TXT records, PTR names): always escaped.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from flask import request

import dashboard as ui
import mailcheck as mc
import ui_kit as kit
from ui_kit import h

log = logging.getLogger("dashboard.mailcheck")
app = ui.app

URL = "/mailcheck"
REASON_TEXT = {"schedule": "i nat", "request": "Tjek nu", "cli": "sfctl", "manual": "manuelt"}
DIRECTION_TEXT = {"worse": ("Værre", "bad"), "new": ("Nyt", "warn"), "better": ("Bedre", "ok"),
                  "gone": ("Væk", "neutral"), "changed": ("Ændret", "info")}
PART_LABELS = {"filter": "Filter + WebUI", "rspamd": "rspamd", "redis": "Redis", "unbound": "Unbound (DNS)",
               "clamd": "ClamAV", "clamav": "ClamAV"}
DMARC_STALE_S = 3 * 86400


def _register_labels() -> None:
    """Event / audit labels for Drift (ui_admin keeps the tables)."""
    try:
        import ui_admin as adm  # noqa: PLC0415

        adm.EVENT_LABELS.setdefault("mailcheck_done", ("Mailsikkerhed tjekket", "info"))
        adm.EVENT_LABELS.setdefault("mailcheck_requested", ("Mailsikkerhed: tjek bestilt", "neutral"))
        adm.AUDIT_LABELS.setdefault("mailcheck_run", "Mailsikkerhed: tjek nu")
        adm.AUDIT_LABELS.setdefault("mailcheck_settings", "Mailsikkerhed: indstillinger")
        adm.AUDIT_LABELS.setdefault("mailcheck_ack", "Mailsikkerhed: kendt – ignorér")
        adm.AUDIT_LABELS.setdefault("mailcheck_unack", "Mailsikkerhed: ikke længere kendt")
    except Exception:  # noqa: BLE001 - labels are cosmetic
        pass


_register_labels()


def _actor() -> str:
    return (ui.current_user() or {}).get("name", "")


def _conn():
    conn = ui.db()
    mc.ensure_schema(conn)
    conn.commit()
    return conn


def _settings() -> dict[str, Any]:
    try:
        return mc.normalize_settings(ui._kv_json(mc.SETTINGS_KEY))
    except Exception as ex:  # noqa: BLE001 - the page must render
        log.warning("mailcheck settings failed: %s", type(ex).__name__)
        return mc.normalize_settings(None)


def _badge(status: str) -> str:
    return kit.badge(mc.LABEL.get(status, status), mc.TONE.get(status, "neutral"))


def _ack_action(it: dict[str, Any], actions: bool) -> str:
    """'Kendt – ignorér' on a warning/error of the newest run; on an
    acknowledged one the way back."""
    if not actions:
        return ""
    key = str(it.get("key") or "")
    if it.get("acked"):
        return ('<span class="kv-sub">'
                + kit.post_form(f"{URL}/unack", kit.hidden("key", key)
                                + kit.button("Ikke længere kendt", kind="ghost", size="sm"), cls="inline-form")
                + "</span>")
    if it.get("status") not in (mc.WARN, mc.BAD):
        return ""
    return ('<span class="kv-sub">'
            + kit.post_form(f"{URL}/ack", kit.hidden("key", key) + kit.hidden("fp", mc.fingerprint(it))
                            + kit.button("Kendt – ignorér", kind="ghost", size="sm"), cls="inline-form")
            + "</span>")


def _explain(it: dict[str, Any], actions: bool = False) -> str:
    out = f'<span>{h(it.get("text") or "")}</span>'
    if it.get("acked"):
        out += (f'<span class="kv-sub">Kendt – ignoreret (egentlig '
                f'{h(mc.LABEL.get(it.get("acked_status"), "").lower())}). Giver ingen beskeder og tæller ikke med, '
                "før det ændrer sig.</span>")
    elif it.get("fix") and it.get("status") in (mc.WARN, mc.BAD, mc.INFO):
        out += f'<span class="kv-sub"><b>Sådan retter du:</b> {h(it["fix"])}</span>'
    return out + _ack_action(it, actions)


def _badge_of(it: dict[str, Any]) -> str:
    if it.get("acked"):
        return kit.badge("Kendt", "info")
    return _badge(it.get("status", mc.UNKNOWN))


def _check_rows(items: list[dict[str, Any]], actions: bool = False) -> list[list[str]]:
    return [[f'<b>{h(it.get("area") or "")}</b>', _badge_of(it), _explain(it, actions)] for it in items]


def _domain_card(d: dict[str, Any], actions: bool = False) -> str:
    sub = []
    if d.get("provider"):
        sub.append(f"Mail: {d['provider']}")
    if d.get("dns_host") and d.get("dns_host") != d.get("provider"):
        sub.append(f"DNS: {d['dns_host']}")
    src = ", ".join(mc.SOURCE_TEXT.get(s, s) for s in d.get("sources") or [])
    if src:
        sub.append(f"fra {src}")
    if d.get("no_mail"):
        sub.append("sender ikke mail")
    table = kit.table(["Tjek", "Status", "Forklaring"], _check_rows(d.get("checks") or [], actions),
                      empty="Ingen resultater.")
    return kit.card(table, title=d.get("domain") or "", subtitle=" · ".join(sub),
                    actions=_badge(d.get("status") or mc.UNKNOWN))


def _servers_card(rows: list[dict[str, Any]], actions: bool = False) -> str:
    out = []
    for it in rows:
        role = mc.ROLE_TEXT.get(it.get("role"), it.get("role") or "")
        why = ", ".join(it.get("for") or [])
        out.append([f'<span class="mono small">{h(it.get("area") or "")}</span>',
                    h(role) + (f'<span class="kv-sub">{h(why)}</span>' if why else ""),
                    _badge_of(it), _explain(it, actions)])
    return kit.card(kit.table(["Server", "Rolle", "Status", "Detaljer"], out, empty="Ingen servere at tjekke."),
                    title="Mailservere", subtitle="Kryptering (TLS) og certifikat for MX, afsender (SMTP) og postkasser (IMAP).")


def _blacklist_card(rows: list[dict[str, Any]], actions: bool = False) -> str:
    out = []
    for it in rows:
        out.append([f'<span class="mono small">{h(it.get("ip") or "")}</span>'
                    + (f'<span class="kv-sub">{h(it.get("ptr"))}</span>' if it.get("ptr") else ""),
                    h(", ".join(it.get("why") or [])), _badge_of(it), _explain(it, actions)])
    zones = ", ".join(label for _z, label in mc.DNSBL_ZONES)
    return kit.card(kit.table(["Adresse", "Hvorfor", "Status", "Detaljer"], out,
                              empty="Ingen afsenderadresser set endnu."),
                    title="Blokeringslister", subtitle=f"De adresser, jeres mail faktisk sendes fra, og MX-serverne – slået op i {zones}.")


def _diff_card(prev: dict[str, Any] | None, cur: dict[str, Any]) -> str:
    if not prev:
        return ""
    changes = mc.diff_runs(prev, cur)
    when = kit.fmt_ts(prev.get("finished_at"))
    if not changes:
        return kit.card(f'<p class="muted">Ingen ændringer siden tjekket {h(when)}.</p>', title="Siden sidst")
    rows = []
    for c in changes[:40]:
        it = c["item"]
        label, tone = DIRECTION_TEXT[c["direction"]]
        what = (f"{it.get('domain')} – " if it.get("domain") else "") + str(it.get("area") or "")
        arrow = (mc.LABEL.get(c["before"], "–") if c["before"] else "–") + " → " + \
                (mc.LABEL.get(c["after"], "–") if c["after"] else "væk")
        rows.append([kit.badge(label, tone), f"<b>{h(what)}</b>", h(arrow), h(it.get("text") or "")])
    return kit.card(kit.table(["", "Tjek", "Status", "Nu"], rows), title="Siden sidst",
                    subtitle=f"Sammenlignet med tjekket {when}.")


def _history_card(runs: list[dict[str, Any]], shown: int | None) -> str:
    rows = []
    for r in runs:
        tone = mc.TONE.get(r["status"], "neutral")
        res = (f"{r['errors']} fejl, {r['warnings']} advarsler" if r["errors"] or r["warnings"] else "Alt OK")
        link = (f'<a class="card-link small" href="{URL}?run={int(r["id"])}">Vis</a>'
                if r["id"] != shown else '<span class="faint small">vises</span>')
        rows.append([f'<span class="nowrap num">{h(kit.fmt_ts(r["finished_at"]))}</span>',
                     h(REASON_TEXT.get(r.get("reason") or "", r.get("reason") or "")),
                     f'{kit.status_dot(tone)} {h(res)}', link])
    return kit.card(kit.table(["Tidspunkt", "Startet af", "Resultat", ""], rows, empty="Ingen tjek endnu."),
                    title="Historik", subtitle=f"De seneste {mc.HISTORY} tjek.")


# ---------------------------------------------------------------- internal state
def internal_state(conn: Any) -> list[tuple[str, str, str]]:
    """[(label, tone, text)] from the functions Drift and sfctl doctor use."""
    out: list[tuple[str, str, str]] = []
    import ui_admin as adm  # noqa: PLC0415 - Drift helpers

    try:
        import aio_health  # noqa: PLC0415

        st = aio_health.read_status()
    except Exception:  # noqa: BLE001
        st = None
    if st:
        age = max(0, int(time.time() - int(st.get("ts") or 0)))
        for name, info in (st.get("parts") or {}).items():
            info = info if isinstance(info, dict) else {}
            ok = bool(info.get("ok"))
            out.append((PART_LABELS.get(name, name), "ok" if ok else "bad",
                        ("svarer" if ok else f"fejler: {str(info.get('detail') or '')[:100]}")
                        + f" (tjekket for {adm._age_text(age)} siden)"))
    else:
        hs = adm._svc("host_status", default=None) or {}
        rs = hs.get("rspamd") if isinstance(hs.get("rspamd"), dict) else None
        if rs:
            out.append(("rspamd", "ok" if rs.get("ok") else "bad", "svarer" if rs.get("ok") else "svarer ikke"))
        else:
            out.append(("Sundhedstjek", "neutral", "ingen samlet status (kun i den samlede container)"))
    hb = adm.heartbeat_age()
    out.append(("Livstegn", "ok" if hb is not None and hb < 90 else "warn" if hb is not None and hb < 300 else "bad",
                f"for {adm._age_text(hb)} siden" if hb is not None else "mangler"))
    try:
        import ui_backup  # noqa: PLC0415

        b = ui_backup._summary()
    except Exception:  # noqa: BLE001
        b = None
    if b:
        out.append(("Krypteret backup", str(b.get("tone") or "warn"),
                    str(b.get("text") or "") + (f" (for {adm._age_text(b.get('age_s'))} siden)"
                                                 if b.get("age_s") is not None else "")))
        off = b.get("offsite")
        if off:
            if off.get("skipped"):
                out.append(("Kopi ud af huset", "warn", f"slået fra ({str(off.get('skipped'))[:80]})"))
            else:
                out.append(("Kopi ud af huset", "ok" if off.get("ok") else "bad",
                            ("lykkedes" if off.get("ok") else f"fejlede: {str(off.get('error') or '')[:100]}")
                            + (f" for {adm._age_text(off.get('age_s'))} siden" if off.get("age_s") is not None else "")))
    try:
        row = conn.execute("SELECT MAX(received_at) FROM dmarc_reports").fetchone()
        last = int(row[0]) if row and row[0] else None
    except Exception:  # noqa: BLE001 - no DMARC tables yet
        last = None
    if last is None:
        out.append(("DMARC-rapporter", "neutral", "ingen modtaget endnu"))
    else:
        age = max(0, int(time.time()) - last)
        out.append(("DMARC-rapporter", "warn" if age > DMARC_STALE_S else "ok",
                    f"seneste modtaget for {adm._age_text(age)} siden"))
    return out


def _internal_card(conn: Any) -> str:
    try:
        rows = internal_state(conn)
    except Exception as ex:  # noqa: BLE001 - the page must render
        log.warning("internal state failed: %s", type(ex).__name__)
        rows = []
    pairs = [(label, f"{kit.status_dot(tone)} {h(text)}") for label, tone, text in rows]
    body = kit.kv_list(pairs) if pairs else '<p class="muted">Kan ikke læses lige nu.</p>'
    return kit.card(body, title="Intern tilstand", subtitle="Filterets egne dele – detaljer under Drift.",
                    actions=f'<a class="card-link small" href="/system">Drift {kit.icon("arrow-right")}</a>')


# ---------------------------------------------------------------- settings
def _settings_card(settings: dict[str, Any], derived: list[dict[str, Any]]) -> str:
    sels = "\n".join(f"{d} {s}" for d, lst in sorted(settings["selectors"].items()) for s in lst)
    known = ", ".join(d["domain"] for d in derived) or "–"
    inner = (kit.form_field("Flere domæner", kit.textarea("domains", "\n".join(settings["domains"]), rows=3),
                            hint=f"Ét pr. linje. Fundet automatisk: {known}.")
             + kit.form_field("Sender ikke mail", kit.textarea("no_mail", "\n".join(settings["no_mail"]), rows=2),
                              hint="Domæner, der aldrig sender mail. De tjekkes for v=spf1 -all og p=reject.")
             + kit.form_field("Spring over", kit.textarea("skip", "\n".join(settings["skip"]), rows=2),
                              hint="Automatisk fundne domæner, der ikke skal tjekkes.")
             + kit.form_field("DKIM-selectors", kit.textarea("selectors", sels, rows=3),
                              hint="“domæne selector” pr. linje. Selectors fra jeres egne mails findes selv.")
             + kit.button("Gem", icon="check"))
    return kit.card(kit.post_form(f"{URL}/settings", f'<div class="stack">{inner}</div>'),
                    title="Indstillinger", subtitle="Hvilke domæner der tjekkes.")


def _derived(settings: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        import dmarc  # noqa: PLC0415

        dcfg = dmarc.normalize_settings(ui._kv_json(dmarc.SETTINGS_KEY) or {})
    except Exception:  # noqa: BLE001
        dcfg = None
    return mc.domain_targets(ui.effective_accounts(), {**settings, "domains": []}, dcfg)


# ---------------------------------------------------------------- routes
@app.get(URL)
@ui.admin_required
def mailcheck_page():
    import ui_admin as adm  # noqa: PLC0415 - layout helpers

    conn = _conn()
    settings = _settings()
    run_id = request.args.get("run", type=int)
    raw = mc.load_run(conn, run_id) if run_id else mc.load_run(conn)
    runs = mc.list_runs(conn)
    newest = bool(raw) and (not runs or runs[0]["id"] == raw.get("id"))
    data = mc.effective(raw, mc.load_acks(conn)) if raw else None
    pend = mc.pending(conn)
    alerts = []
    if pend.get("running"):
        alerts.append(kit.alert(f"Et tjek kører (startet {kit.fmt_ts(pend['running'])}). Genindlæs siden om lidt.",
                                "info"))
    elif pend.get("stale"):
        alerts.append(kit.alert("Tjekket blev bestilt, men er ikke startet. Kører filteret? Se Drift.", "warn"))
    elif pend.get("requested"):
        alerts.append(kit.alert("Tjekket er bestilt og starter inden for et minut.", "info"))
    if data is None:
        body = "".join(alerts) + kit.card(kit.empty_state(
            "Ikke tjekket endnu", "Tryk “Tjek nu”, eller vent til i nat. Tjekket ser på jeres domæners MX, SPF, "
            "DKIM, DMARC og DNSSEC, mailservernes kryptering og blokeringslister.", "radar"))
    else:
        if data.get("degraded"):
            alerts.append(kit.alert(f"Tjekket kunne ikke gennemføres ordentligt: {data['degraded']} Alt står som "
                                    "“Ikke testet”, og der er ikke sendt beskeder.", "warn"))
        if data.get("dns_limited"):
            alerts.append(kit.alert(f"{int(data['dns_limited'])} DNS-opslag blev ikke lavet (grænse nået) – de berørte "
                                    "punkter står som “Ikke testet”.", "info"))
        if data.get("timed_out"):
            alerts.append(kit.alert("Tjekket nåede sin tidsgrænse – resten står som “Ikke testet”.", "info"))
        if data.get("acked"):
            alerts.append(kit.alert(f"{_n_known(int(data['acked']))} markeret som kendt og tæller ikke med.", "info"))
        c = data.get("counts") or mc.counts(data)
        kpis = ('<div class="kpis">'
                + kit.kpi("Fejl", int(c.get(mc.BAD, 0)), tone="bad" if c.get(mc.BAD) else "")
                + kit.kpi("Advarsler", int(c.get(mc.WARN, 0)), tone="warn" if c.get(mc.WARN) else "")
                + kit.kpi("OK", int(c.get(mc.OK, 0)), sub=f"{int(c.get(mc.INFO, 0))} info · "
                                                          f"{int(c.get(mc.UNKNOWN, 0))} ikke testet")
                + kit.kpi("Tjekket", kit.ago(data.get("finished_at")),
                          sub=REASON_TEXT.get(data.get("reason") or "", "") or "")
                + "</div>")
        if run_id and runs and runs[0]["id"] != data.get("id"):
            alerts.append(kit.alert(f"Du ser et ældre tjek fra {kit.fmt_ts(data.get('finished_at'))}.", "info",
                                    action_html=kit.button("Vis det nyeste", href=URL, kind="secondary", size="sm")))
        prev = mc.previous_run(conn, int(data["id"]))
        body = ("".join(alerts) + kit.card(kpis) + _diff_card(prev, raw)
                + "".join(_domain_card(d, newest) for d in data.get("domains") or [])
                + _servers_card(data.get("servers") or [], newest)
                + _blacklist_card(data.get("blacklists") or [], newest))
    body += ('<div class="grid grid-2">' + _internal_card(conn) + _history_card(runs, (data or {}).get("id"))
             + "</div>" + _settings_card(settings, _derived(settings)))
    action = kit.post_form(f"{URL}/run", kit.button("Tjek nu", icon="refresh"))
    return adm._page("Mailsikkerhed", body, active="mailcheck", actions_html=action,
                     subtitle="Er jeres domæner og mailservere sat rigtigt op? Tjekkes hver nat og når du beder om det.")


@app.post(f"{URL}/run")
@ui.admin_required
def mailcheck_run():
    try:
        res = mc.request_run(_conn(), _actor())
    except Exception as ex:  # noqa: BLE001
        log.warning("mailcheck request failed: %s", type(ex).__name__)
        return ui.respond("Tjekket kunne ikke bestilles lige nu.", ok=False, next_url=URL)
    ui.audit("mailcheck_run", detail=res.get("code", ""))
    return ui.respond(res["text"], next_url=URL, reload=True)


def _n_known(n: int) -> str:
    return "Ét punkt er" if n == 1 else f"{n} punkter er"


@app.post(f"{URL}/ack")
@ui.admin_required
def mailcheck_ack():
    key = (request.form.get("key") or "")[:300]
    fp = (request.form.get("fp") or "")[:64]
    try:
        conn = _conn()
        ok = mc.acknowledge(conn, mc.load_run(conn), key, fp, _actor())
    except Exception as ex:  # noqa: BLE001
        log.warning("mailcheck ack failed: %s", type(ex).__name__)
        return ui.respond("Kunne ikke gemmes lige nu.", ok=False, next_url=URL)
    if not ok:
        return ui.respond("Punktet har ændret sig siden – genindlæs siden.", ok=False, next_url=URL)
    ui.audit("mailcheck_ack", detail=kit.clean_name(key)[:200])
    return ui.respond("Markeret som kendt. Der kommer ingen beskeder om det, før det ændrer sig.", next_url=URL,
                      reload=True)


@app.post(f"{URL}/unack")
@ui.admin_required
def mailcheck_unack():
    key = (request.form.get("key") or "")[:300]
    try:
        ok = mc.unacknowledge(_conn(), key)
    except Exception as ex:  # noqa: BLE001
        log.warning("mailcheck unack failed: %s", type(ex).__name__)
        return ui.respond("Kunne ikke gemmes lige nu.", ok=False, next_url=URL)
    if ok:
        ui.audit("mailcheck_unack", detail=kit.clean_name(key)[:200])
    return ui.respond("Tæller med igen." if ok else "Punktet var ikke markeret som kendt.", ok=ok, next_url=URL,
                      reload=True)


def _domains_field(name: str) -> tuple[list[str], str | None]:
    raw = (request.form.get(name) or "")[:4000].replace(",", "\n").split()
    out: list[str] = []
    for d in raw:
        cd = mc.clean_domain(d)
        if not cd:
            return [], d
        if cd not in out:
            out.append(cd)
    return out, None


@app.post(f"{URL}/settings")
@ui.admin_required
def mailcheck_settings():
    vals: dict[str, Any] = {}
    for name in ("domains", "no_mail", "skip"):
        lst, bad = _domains_field(name)
        if bad is not None:
            return ui.respond(f"Ugyldigt domæne: {kit.clean_name(bad)[:80]}", ok=False, next_url=URL)
        vals[name] = lst
    sels: dict[str, list[str]] = {}
    for line in (request.form.get("selectors") or "")[:4000].splitlines():
        parts = line.replace(",", " ").split()
        if not parts:
            continue
        d = mc.clean_domain(parts[0]) if len(parts) == 2 else None
        s = mc.clean_selector(parts[1]) if len(parts) == 2 else None
        if not d or not s:
            return ui.respond(f"Skriv “domæne selector” pr. linje: {kit.clean_name(line)[:80]}", ok=False,
                              next_url=URL)
        sels.setdefault(d, [])
        if s not in sels[d]:
            sels[d].append(s)
    vals["selectors"] = sels
    new = mc.normalize_settings(vals)
    try:
        ui._kv_put(mc.SETTINGS_KEY, new)
    except Exception as ex:  # noqa: BLE001
        log.warning("mailcheck settings save failed: %s", type(ex).__name__)
        return ui.respond("Indstillingerne kunne ikke gemmes lige nu.", ok=False, next_url=URL)
    ui.audit("mailcheck_settings", detail=(f"domæner={','.join(new['domains']) or '-'} "
                                           f"sender_ikke_mail={','.join(new['no_mail']) or '-'} "
                                           f"spring_over={','.join(new['skip']) or '-'} "
                                           f"selectors={sum(len(v) for v in new['selectors'].values())}")[:400])
    return ui.respond("Gemt. Ændringerne bruges ved næste tjek.", next_url=URL, reload=True)
