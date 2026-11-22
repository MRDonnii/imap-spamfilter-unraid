"""AI-vurdering (2.7) - the admin page /ai - spamfilter.

  * the global setting (settings_kv 'ai', ai_verdict.parse_form):
    Fra / Prøv / Til, the Ollama address (home network only), the model,
    the score band, the hourly cap and the time-out;
  * "Test forbindelse": GET /api/tags on the address in the form (or the
    saved one) and the installed models;
  * the evaluation for the weekly review (ai_verdict.evaluation): the
    recent verdicts with the final outcome and the user's later verdict,
    agreement with the users, how many 'Til' would have moved and the
    false positives.

Access: admin only (dashboard.admin_required). Sender, subject and the
model's reason are attacker-influenced: always escaped, never a link.
Changes are audited ('ai_settings').
"""

from __future__ import annotations

import logging
from typing import Any

from flask import request

import ai_verdict as ai
import dashboard as ui
import ui_kit as kit
from ui_kit import h

log = logging.getLogger("dashboard.ai")
app = ui.app

URL = "/ai"
MODE_OPTIONS = (("off", "Fra"), ("shadow", "Prøv – vurdér og gem, men ændr intet"),
                ("on", "Til – giv point til spam"))
VERDICT_TONE = {"spam": "bad", "phishing": "bad", "ham": "ok", "unsure": "neutral"}
STATE_TEXT = {"off": ("Slået fra", "neutral"), "unknown": ("Ingen svar endnu", "neutral"),
              "unset": ("Ikke sat op – angiv Ollama-adressen", "warn"),
              "ok": ("Ollama svarer", "ok"), "down": ("Ollama svarer ikke", "warn")}


def _actor() -> str:
    return (ui.current_user() or {}).get("name", "")


def _conn() -> Any:
    conn = ui.db()
    ai.ensure_schema(conn)
    conn.commit()
    return conn


def _settings() -> dict[str, Any]:
    try:
        return ai.normalize_settings(ui._kv_json(ai.SETTINGS_KEY) or {})
    except Exception as ex:  # noqa: BLE001 - the page must render
        log.warning("ai settings failed: %s", type(ex).__name__)
        return ai.normalize_settings({})


def _num(v: Any) -> str:
    if v is None:
        return ""
    f = float(v)
    return f"{f:g}".replace(".", ",")


def _status_card(settings: dict[str, Any], conn: Any) -> str:
    try:
        hl = ai.health(conn)
    except Exception:  # noqa: BLE001
        hl = {"state": "unknown"}
    text, tone = STATE_TEXT.get(hl.get("state", "unknown"), STATE_TEXT["unknown"])
    rows = [("Tilstand", kit.badge(ai.MODE_TEXT.get(settings["mode"], settings["mode"]),
                                   {"on": "ok", "shadow": "info"}.get(settings["mode"], "neutral"))),
            ("Forbindelse", kit.badge(text, tone)),
            ("Seneste svar", h(kit.fmt_ts(hl.get("last_ok_at"))) if hl.get("last_ok_at") else "–")]
    if hl.get("state") == "down" and hl.get("last_error"):
        rows.append(("Seneste fejl", h(f"{hl['last_error']} ({kit.fmt_ts(hl.get('last_error_at'))})")))
    if int(hl.get("backoff_until") or 0) > 0 and hl.get("state") == "down":
        rows.append(("Prøver igen", h(kit.fmt_ts(hl["backoff_until"]))))
    note = ('<p class="muted small mt-1">Mailen bliver aldrig holdt tilbage af AI-vurderingen. Svarer Ollama '
            "ikke, eller kommer svaret efter ventetiden, vurderes mailen præcis som uden AI.</p>")
    return kit.card(kit.kv_list(rows) + note, title="Status")


def _settings_card(settings: dict[str, Any]) -> str:
    url = settings["url"] or ""
    inner = (
        kit.form_field("AI-vurdering", kit.select("mode", MODE_OPTIONS, settings["mode"]),
                       hint="Prøv gemmer kun AI'ens vurdering, så I kan se, om den rammer rigtigt. Til giver "
                            f"{ai.SCORE_STRONG:g} point ved spam/phishing med mindst {round(ai.CONF_STRONG * 100)} % "
                            f"sikkerhed og {ai.SCORE_WEAK:g} point ved mindst {round(ai.CONF_WEAK * 100)} % – aldrig "
                            "minuspoint. Kun postkasser i Filtrér.")
        + kit.form_field("Ollama-adresse", kit.input_("url", url, attrs='maxlength="200" autocapitalize="none" '
                                                                         'spellcheck="false" placeholder="'
                                                                         + h(ai.EXAMPLE_URL) + '"'),
                         hint="Kun en IP-adresse på hjemmenetværket – mailene sendes aldrig ud af huset. "
                              "Indtil en adresse er gemt, sendes der intet.")
        + kit.form_field("Model", kit.input_("model", settings["model"],
                                             attrs='maxlength="80" autocapitalize="none" spellcheck="false"'),
                         hint=f"Som navnet står i Ollama, fx {ai.DEFAULT_MODEL}, qwen3:8b eller gemma3:4b.")
        + '<div class="grid grid-2 grid-tight">'
        + kit.form_field("Fra score", kit.input_("band_low", _num(settings["band_low"]),
                                                 attrs='inputmode="decimal" maxlength="6"'),
                         hint="Mails med en score herfra og op til grænsen vurderes.")
        + kit.form_field("Til score", kit.input_("band_high", _num(settings["band_high"]),
                                                 attrs='inputmode="decimal" maxlength="6" placeholder="grænsen"'),
                         hint="Tom = postkassens grænse.")
        + kit.form_field("Højst pr. time", kit.input_("max_per_hour", settings["max_per_hour"],
                                                      attrs='inputmode="numeric" maxlength="4"'))
        + kit.form_field("Ventetid (sekunder)", kit.input_("timeout", settings["timeout"],
                                                           attrs='inputmode="numeric" maxlength="3"'),
                         hint="Svarer modellen ikke inden da, vurderes mailen uden AI.")
        + "</div>"
        + f'<div class="form-actions">{kit.button("Gem", kind="primary", icon="check")}</div>')
    form = kit.post_form(f"{URL}/settings", f'<div class="stack">{inner}</div>')
    test = kit.post_form(f"{URL}/test", f'<input type="hidden" name="url" value="{h(url)}">'
                         + '<p class="muted small">Gem først, og test så forbindelsen. Testen spørger Ollama, '
                           "hvilke modeller der er installeret – den sender ingen mail.</p>"
                         + '<div class="form-actions">'
                         + kit.button("Test forbindelse", kind="secondary", icon="plug") + "</div>")
    return kit.card(form + test, title="Indstillinger",
                    subtitle="Lokal AI på jeres egen Ollama-server giver en ekstra vurdering af grænsetilfælde.")


def _pct(n: Any, d: Any) -> str:
    return f"{round(100 * n / d)} %" if d else "–"


def _summary_card(ev: dict[str, Any]) -> str:
    s = ev["summary"]
    agree = "–" if s["agree_pct"] is None else f"{kit.fmt_int(round(s['agree_pct']))} %"
    kpis = ('<div class="kpis">'
            + kit.kpi("Vurderet", int(s["ok"]), sub=f"{kit.fmt_int(s['failed'])} fejl/timeout")
            + kit.kpi("Enige med brugerne", agree,
                      sub=f"{kit.fmt_int(s['agree'])} af {kit.fmt_int(s['judged'])} med brugerens dom",
                      tone="" if s["agree_pct"] is None else ("ok" if s["agree_pct"] >= 90 else "warn"))
            + kit.kpi("Ville være flyttet med Til", int(s["would_move"]),
                      sub=f"{kit.fmt_int(s['with_points'])} ville få point")
            + kit.kpi("Falske positiver", int(s["false_pos"]),
                      sub=f"AI sagde spam, brugeren sagde nej ({kit.fmt_int(s['would_move_fp'])} ville være flyttet)",
                      tone="ok" if not s["false_pos"] else "bad")
            + "</div>")
    lat = s["latency_ms"]
    facts = kit.kv_list([
        ("Spam / phishing", h(f"{kit.fmt_int(s['spam'])} / {kit.fmt_int(s['phishing'])}")),
        ("Almindelig mail / usikker", h(f"{kit.fmt_int(s['ham'])} / {kit.fmt_int(s['unsure'])}")),
        ("Overset spam", h(f"{kit.fmt_int(s['missed'])} (AI sagde ikke spam, brugeren sagde spam)")),
        ("Flyttet af AI", h(kit.fmt_int(s["moved"]))),
        ("For sent svar", h(kit.fmt_int(s["late"]))),
        ("Typisk svartid", h("–" if lat is None else f"{lat / 1000:.1f} s".replace(".", ","))),
    ])
    return kit.card(kpis + facts, title="Evaluering",
                    subtitle=f"De seneste {s['days']} dage. Brugerens dom = flyttet til/fra spam eller frigivet.")


def _verdict_cell(it: dict[str, Any]) -> str:
    if it["status"] != "ok":
        label = "Timeout" if it["status"] == "timeout" else "Fejl"
        return kit.badge(label, "warn") + (f'<span class="kv-sub">{h(it["error"])}</span>' if it["error"] else "")
    v = it["verdict"] or "unsure"
    conf = it["confidence"]
    txt = ai.VERDICT_TEXT.get(v, v) + (f" {round(float(conf) * 100)} %" if conf is not None else "")
    pts = f"+{it['points']:g} point"
    extra = f'<span class="kv-sub">{h(pts)}</span>' if it["points"] else ""
    return kit.badge(txt, VERDICT_TONE.get(v, "neutral")) + extra


def _items_card(ev: dict[str, Any]) -> str:
    rows = []
    for it in ev["items"]:
        mail = (f'<span>{h(kit.clean_name(it["subject"])[:120] or "(intet emne)")}</span>'
                f'<span class="kv-sub">{h(ui.account_label(it["account"]))} · '
                f'{h(kit.clean_name(it["sender"])[:120])}</span>')
        score = "–" if it["score_before"] is None else f"{float(it['score_before']):.1f}".replace(".", ",")
        outcome = h(it["outcome"]) + ('<span class="kv-sub">ville være flyttet med Til</span>'
                                      if it["would_move"] and it["mode"] == "shadow" else "")
        user = {"spam": kit.badge("spam", "bad"), "ham": kit.badge("ikke spam", "ok")}.get(
            it["user"] or "", '<span class="muted">–</span>')
        rows.append([h(kit.fmt_ts(it["created_at"])), mail, h(score), _verdict_cell(it),
                     f'<span class="small">{h(it["reason"])}</span>', outcome, user])
    table = kit.table(["Tid", "Mail", ("Score", "num"), "AI", "Begrundelse", "Udfald", "Brugeren"], rows,
                      empty="Ingen AI-vurderinger endnu. De kommer, når der kommer grænsetilfælde i indbakken.")
    return kit.card(table, title="Seneste vurderinger")


@app.get(URL)
@ui.admin_required
def ai_page():
    import ui_admin as adm  # noqa: PLC0415 - layout helpers

    settings = _settings()
    try:
        conn = _conn()
        ev = ai.evaluation(conn)
    except Exception as ex:  # noqa: BLE001
        log.warning("ai evaluation failed: %s", type(ex).__name__)
        conn, ev = None, ai.evaluation(None)  # type: ignore[arg-type]
    body = ('<div class="grid grid-main">'
            + f'<div class="stack">{_summary_card(ev)}</div>'
            + f'<div class="stack">{_status_card(settings, conn)}{_settings_card(settings)}</div>'
            + "</div>" + _items_card(ev))
    return adm._page("AI-vurdering", body, active="ai",
                     subtitle="En ekstra vurdering af grænsetilfælde fra jeres egen lokale AI. Intet forlader huset.")


@app.post(f"{URL}/settings")
@ui.admin_required
def ai_settings():
    new, err = ai.parse_form({k: (request.form.get(k) or "")[:200] for k in
                              ("mode", "url", "model", "band_low", "band_high", "max_per_hour", "timeout")})
    if err or new is None:
        return ui.respond(err or "Indstillingerne er ikke gyldige.", ok=False, next_url=URL)
    try:
        ui._kv_put(ai.SETTINGS_KEY, new)
    except Exception as ex:  # noqa: BLE001
        log.warning("ai settings save failed: %s", type(ex).__name__)
        return ui.respond("Indstillingerne kunne ikke gemmes lige nu.", ok=False, next_url=URL)
    ui.audit("ai_settings", detail=(f"mode={new['mode']} url={new['url']} model={new['model']} "
                                    f"band={new['band_low']:g}-{'grænse' if new['band_high'] is None else new['band_high']} "
                                    f"max={new['max_per_hour']}/t timeout={new['timeout']}s")[:400])
    return ui.respond("Gemt. Filteret bruger de nye indstillinger ved næste mail.", next_url=URL, reload=True)


@app.post(f"{URL}/test")
@ui.admin_required
def ai_test():
    settings = _settings()
    url = (request.form.get("url") or "").strip()[:200] or settings["url"]
    base, err = ai.check_url(url)
    if base is None:
        return ui.respond(err or "Adressen er ikke gyldig.", ok=False, next_url=URL)
    try:
        models = ai.list_models(settings, url=base)
    except ai.OllamaError as ex:
        ui.audit("ai_test", result="error", detail=f"url={base} {ex}"[:300])
        return ui.respond(f"Ingen forbindelse til Ollama på {base}: {ex}.", ok=False, next_url=URL)
    ui.audit("ai_test", detail=f"url={base} modeller={len(models)}")
    if not models:
        return ui.respond(f"Ollama svarer på {base}, men der er ingen modeller installeret.", ok=False,
                          next_url=URL)
    shown = ", ".join(models[:12]) + (f" og {len(models) - 12} mere" if len(models) > 12 else "")
    if settings["model"] not in models:
        return ui.respond(f"Ollama svarer. Modeller: {shown}. Den valgte model {settings['model']} er ikke "
                          "installeret.", ok=False, next_url=URL)
    return ui.respond(f"Ollama svarer. Modeller: {shown}.", next_url=URL)
