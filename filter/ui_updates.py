"""Opdateringer (2.10, admin only): running version, the newest release on
GitHub (Stabil or Beta), the release notes of the newer versions and
"Opdatér nu", which writes a signed request the HOST picks up
(deploy/update-runner.sh -> deploy/aio/update.sh --build with backup, gate
and automatic rollback). See updates.py for the whole flow.

Every POST is admin only, CSRF-checked (dashboard.before_request) and
audited: update_check, update_settings, update_token, update_request,
update_cancel. The only value that reaches the host is a version tag that
is a published release on GitHub - no free text - and (2.11.2) the saved
read-only GitHub token, handed over with the request when the host helper
has no token file of its own (updates.write_request).
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from flask import request

import dashboard as ui
import ui_kit as kit
import updates
from ui_kit import h

log = logging.getLogger("dashboard.updates")
app = ui.app

URL = "/updates"
SETTINGS_KEY = "update_settings"     # {"channel": "beta" (default)|"stable"}
TOKEN_KEY = "update_token"           # {"enc": ..., "fp": ..., "saved_at": ..., "saved_by": ...}
RUNNER_FRESH = 5 * 60                # the host helper writes runner.json every minute

STATE_TEXT = {"venter": ("Venter", "info"), "koerer": ("Kører", "warn"), "faerdig": ("Færdig", "ok"),
              "fejlet": ("Fejlet", "bad")}
ERROR_TEXT = {
    "not_configured": ("Opdateringskilden er ikke sat op",
                       "Tilføj SF_UPDATE_REPO=ejer/repo i operations/site.env på værten og kør "
                       "deploy/aio/update.sh én gang, så containeren kender repoet."),
    "not_found": ("Repoet blev ikke fundet",
                  "Navnet er forkert, eller repoet er privat. Gem en GitHub-token med Contents: read på {name} "
                  "nedenfor."),
    "auth": ("GitHub afviste adgangen", "Tokenen er udløbet, eller den har ikke adgang til repoet."),
    "rate_limited": ("GitHub beder os vente", "For mange opslag den seneste time. Prøv igen senere, eller gem en token."),
    "network": ("GitHub kunne ikke nås", "Filteret fik ikke forbindelse til GitHub. Prøv igen om lidt."),
    "bad_reply": ("Uventet svar fra GitHub", "Svaret kunne ikke læses. Prøv igen om lidt."),
}


# 401/403/404 with a saved token: the token is the problem (2.11.2).
ACCESS_TITLE = "Tokenen har ikke adgang til repoet"
ACCESS_TEXT = ("Tokenen har ikke adgang til repoet – den skal have Contents: read på {name}. "
               "Ret den på GitHub (Fine-grained token: Repository access → {name}, Permissions → Contents: "
               "Read-only), og gem den igen nedenfor.")


def _repo_name(repo: str) -> str:
    return repo.split("/", 1)[1] if "/" in repo else (repo or "repoet")


def error_text(code: str, *, has_token: bool, repo: str) -> tuple[str, str]:
    """(title, text) for a check error. With a saved token GitHub's 404
    (private repo) and 401/403 all mean: the token cannot read the repo."""
    name = _repo_name(repo)
    if has_token and code in ("not_found", "auth"):
        return ACCESS_TITLE, ACCESS_TEXT.format(name=name)
    title, text = ERROR_TEXT.get(code, ERROR_TEXT["bad_reply"])
    return title, text.format(name=name)


def update_dir() -> Path:
    return Path(ui.STATE_DIR) / "update"


def _actor() -> str:
    return (ui.current_user() or {}).get("name", "")


def _key_material() -> bytes:
    return str(app.secret_key or "").encode("utf-8")


def _settings() -> dict:
    s = ui._kv_json(SETTINGS_KEY) or {}
    ch = s.get("channel")
    # Beta by default: every release so far is a Beta (pre-release) until the
    # owner calls one finished; Stabil then offers only those.
    return {"channel": ch if ch in updates.CHANNELS else "beta"}


def _token() -> str | None:
    rec = ui._kv_json(TOKEN_KEY) or {}
    return updates.unseal_token(rec.get("enc") or "", _key_material()) if rec.get("enc") else None


def _token_info() -> dict:
    rec = ui._kv_json(TOKEN_KEY) or {}
    return rec if rec.get("enc") else {}


def _check(force: bool = False) -> dict:
    return updates.check_releases(update_dir(), updates.repo_from_env(), _token(), force=force)


def _runner() -> dict:
    """runner.json from the host helper: when it last looked for requests,
    whether it has its own token file and understands the hand-over."""
    r = updates.read_runner(update_dir())
    return {**r, "fresh": bool(r["seen_at"]) and time.time() - r["seen_at"] < RUNNER_FRESH}


def _handover_token(runner: dict) -> str | None:
    """The token to hand to the host with a request: only when the helper
    understands it and has no token file of its own (that one wins)."""
    if not runner.get("token_handoff") or runner.get("token_file"):
        return None
    return updates.clean_token(_token() or "")


def _helper_access(runner: dict, token: dict, st: dict) -> str:
    """The "Hjælperens GitHub-adgang" row: which token the host helper
    will use, and whether GitHub refused it last time."""
    if st.get("error") == "github_access":
        return kit.badge("Afvist", "bad") + ' <span class="faint small">GitHub afviste hjælperen ved seneste ' \
            "opdatering – se beskeden ovenfor.</span>"
    if runner.get("token_file"):
        return kit.badge("Værtens token", "ok") + ' <span class="faint small">operations/github-token på værten ' \
            "(går forud for WebUI'ens)</span>"
    if not runner.get("seen_at"):
        return kit.badge("Ukendt", "warn") + ' <span class="faint small">hjælperen er ikke set</span>'
    if not runner.get("token_handoff"):
        if token:
            return kit.badge("Gammel hjælper", "warn") + ' <span class="faint small">hjælperen på værten kan ' \
                "ikke bruge WebUI'ens token endnu. Læg tokenen midlertidigt i operations/github-token på værten, " \
                "opdatér til 2.11.2 eller nyere, og slet filen igen (se INSTALLATION.md).</span>"
        return kit.badge("Ingen token", "info") + ' <span class="faint small">virker kun med et offentligt repo</span>'
    if token:
        return kit.badge("WebUI'ens token", "ok") + ' <span class="faint small">gives med til værten ved hver ' \
            "opdatering og slettes bagefter</span>"
    return kit.badge("Ingen token", "info") + ' <span class="faint small">virker kun med et offentligt repo – ' \
        "gem en token ovenfor, hvis repoet er privat</span>"


# ---------------------------------------------------------------- page parts


def _kpis(current: str, newest: dict | None, channel: str, info: dict) -> str:
    chan = "Beta" if channel == "beta" else "Stabil"
    checked = info.get("checked_at")
    return ('<div class="kpis">'
            + kit.kpi("Kører nu", h(current), sub="versionen i containeren")
            + kit.kpi(f"Seneste ({chan.lower()})", h(newest["version"]) if newest else "–",
                      sub=("udgivet " + kit.fmt_date(newest["published_ts"])) if newest and newest.get("published_ts")
                      else "ingen udgivelse fundet" if not newest else "")
            + kit.kpi("Kanal", chan, sub="vælges under Indstillinger nedenfor")
            + kit.kpi("Sidst tjekket", kit.ago(checked) if checked else "aldrig",
                      sub="automatisk højst hver 6. time")
            + "</div>")


def _status_card(st: dict, current: str = "") -> str:
    if st["state"] == "idle":
        return ""
    # 2.14.1: an old result is history once a same-or-newer version runs (e.g. installed by hand after a
    # failed attempt) - don't keep showing "Fejlet v2.11.1" while 2.14.0 is running.
    cur, tag = updates.parse_version(current), updates.parse_version(updates.tag_version(st.get("tag") or ""))
    if cur and tag and ((st["state"] == "fejlet" and tag <= cur) or (st["state"] == "faerdig" and tag < cur)):
        return ""
    label, tone = STATE_TEXT[st["state"]]
    when = st["finished_at"] or st["started_at"]
    rows = [("Status", kit.badge(label, tone)), ("Version", h(st["tag"] or "–"))]
    if st.get("requested_by"):
        rows.append(("Bestilt af", h(st["requested_by"])))
    if when:
        rows.append(("Tidspunkt", h(kit.fmt_ts(when))))
    body = kit.kv_list(rows)
    if st["message"] and st.get("error"):
        # 2.11.2: GitHub refused the helper (access or rate limit) - say it plainly.
        body += kit.alert(st["message"], "bad", title="GitHub afviste hjælperen")
    elif st["message"]:
        body += f'<p class="muted mt-1">{h(st["message"])}</p>'
    if st["stale"]:
        body += kit.alert("Opdateringen har kørt i over tre timer. Se loggen i operations/ på værten.", "warn")
    if st["log"]:
        body += ('<details class="update-log mt-1"><summary>Seneste linjer fra loggen</summary>'
                 f'<pre class="log-tail">{h(chr(10).join(st["log"]))}</pre></details>')
    actions = ""
    if st["state"] == "venter":
        actions = kit.post_form(f"{URL}/cancel", kit.button(
            "Annullér", kind="ghost", icon="x", size="sm",
            attrs=kit.confirm_attrs("Annullér opdateringen?", "Anmodningen slettes, før værten henter den.",
                                    confirm="Annullér")), cls="inline-form")
    card = kit.card(body, title="Seneste opdatering", actions=actions)
    if st["state"] in ("venter", "koerer") and not st["stale"]:
        card = f'<div data-reload-after="15">{card}</div>'  # app.js: follow the host's progress
    return card


def _release_block(r: dict) -> str:
    tag_badge = kit.badge("Beta", "info") if r.get("prerelease") else kit.badge("Stabil", "ok")
    date = kit.fmt_date(r["published_ts"]) if r.get("published_ts") else ""
    notes = updates.notes_html(r.get("body") or "", h) or '<p class="muted">Ingen ændringslog.</p>'
    return (f'<section class="release"><div class="release-head"><b>{h(r["name"])}</b>{tag_badge}'
            + (f'<span class="faint small">{h(date)}</span>' if date else "") + "</div>"
            f'<div class="release-notes">{notes}</div></section>')


def _update_card(newer: list[dict], st: dict, channel: str) -> str:
    if not newer:
        return kit.card(kit.empty_state(
            "Du kører den nyeste version",
            "Der er ingen nyere udgivelse i kanalen " + ("Beta." if channel == "beta" else "Stabil.")
            + " Siden tjekker selv igen, eller tryk på Tjek nu.", "check-circle"))
    top = newer[0]
    busy = st["state"] in ("venter", "koerer")
    if not top.get("installable"):
        action = kit.alert("Denne udgivelse har ingen kildepakke med kontrolsum, så den kan ikke installeres herfra. "
                           "Opdatér manuelt med deploy/aio/update.sh --build.", "warn")
    elif busy:
        action = kit.alert("Der er allerede en opdatering i gang – se status ovenfor.", "info")
    else:
        attrs = kit.confirm_attrs(
            f"Opdatér til {top['version']}?",
            "Værten tager først en backup, bygger den nye version og skifter containeren ud. Fejler testen bagefter, "
            "rulles der automatisk tilbage. WebUI'en er væk et par minutter undervejs. Ingen post går tabt.",
            confirm="Opdatér nu")
        action = kit.post_form(f"{URL}/request", kit.hidden("tag", top["tag"]) + kit.button(
            "Opdatér nu", kind="primary", icon="t-cloud-download", attrs=attrs), cls="inline-form")
    count = len(newer)
    sub = f"{count} nyere version{'er' if count != 1 else ''} – ændringerne står herunder, nyeste først."
    body = (f'<div class="update-cta"><p>Version <b>{h(top["version"])}</b> er klar.</p>{action}</div>'
            + "".join(_release_block(r) for r in newer))
    return kit.card(body, title="Ny version", subtitle=sub)


def _settings_card(channel: str, token: dict, runner: dict, st: dict) -> str:
    chan = kit.form_field("Kanal", kit.segmented("channel", [("stable", "Stabil"), ("beta", "Beta")], channel),
                          hint="Stabil = kun færdige udgivelser. Beta = også prøveudgivelser.")
    if token:
        tok_hint = (f"En token er gemt krypteret (id {h(token.get('fp', ''))}). Skriv en ny for at skifte den.")
    else:
        tok_hint = ("Kun nødvendig, hvis repoet er privat. Brug en fine-grained token med Contents: read på "
                    f"{_repo_name(updates.repo_from_env())}. Den bruges også af værtens hjælper, når du opdaterer.")
    tok = kit.form_field("GitHub-token (valgfri)", kit.input_(
        "token", type="password", attrs='autocomplete="off" spellcheck="false" placeholder="github_pat_…"'), hint=tok_hint)
    form = kit.post_form(f"{URL}/settings", f'<div class="stack">{chan}{tok}</div><div class="form-actions">'
                         + kit.button("Gem", kind="primary", icon="check") + "</div>")
    if token:
        form += kit.post_form(f"{URL}/settings", kit.hidden("clear_token", "1") + kit.button(
            "Fjern token", kind="ghost", icon="trash", size="sm",
            attrs=kit.confirm_attrs("Fjern GitHub-tokenen?", "Et privat repo kan så ikke tjekkes længere.",
                                    confirm="Fjern", tone="danger")), cls="inline-form mt-1")
    repo = updates.repo_from_env()
    rows = [("Repo", f'<span class="mono small">{h(repo)}</span>' if repo else "ikke sat op"),
            ("Værtshjælper", kit.badge("Aktiv", "ok") + f' <span class="faint small">sidst set {h(kit.ago(runner["seen_at"]))}</span>'
             if runner["fresh"] else kit.badge("Ikke set", "warn") + ' <span class="faint small">User Script '
             '“Spamfilter-update” kører ikke – installér med deploy/install-user-scripts.sh</span>'),
            ("Hjælperens GitHub-adgang", _helper_access(runner, token, st))]
    return kit.card(form + '<div class="mt-2">' + kit.kv_list(rows) + "</div>", title="Indstillinger",
                    subtitle="Hvilke udgivelser der tilbydes, og hvordan GitHub spørges.")


def _how_card() -> str:
    steps = ("Du trykker på Opdatér nu. Spamfilteret gemmer kun versionsnummeret som en signeret anmodning "
             "(og den gemte GitHub-token, hvis værten ikke har sin egen – den slettes, så snart pakken er hentet).",
             "Værtens hjælper (User Script “Spamfilter-update”) ser anmodningen inden for et minut.",
             "Den henter kildepakken for netop den version fra GitHub og tjekker kontrolsummen (sha256).",
             "Den tager backup, bygger og starter den nye version. Fejler testen, kommer den gamle tilbage af sig selv.")
    return kit.card('<ol class="steps-list">' + "".join(f"<li>{h(s)}</li>" for s in steps) + "</ol>",
                    title="Sådan foregår det")


@app.get(URL)
@ui.admin_required
def updates_page():
    import ui_admin as adm  # noqa: PLC0415 - layout helpers

    current = ui.app_version()
    channel = _settings()["channel"]
    info = _check()
    releases = info["releases"]
    st = updates.read_status(update_dir())
    newer = updates.newer_releases(releases, channel, current)
    alerts = ""
    if info.get("error"):
        title, text = error_text(info["error"], has_token=bool(_token_info()), repo=info.get("repo") or "")
        alerts = kit.alert(text, "warn", title=title)
    check = kit.post_form(f"{URL}/check", kit.button("Tjek nu", kind="secondary", icon="refresh"), cls="inline-form")
    body = (alerts + kit.card(_kpis(current, updates.latest(releases, channel), channel, info))
            + _status_card(st, current) + _update_card(newer, st, channel)
            + '<div class="grid grid-2">' + _settings_card(channel, _token_info(), _runner(), st) + _how_card()
            + "</div>")
    return adm._page("Opdateringer", body, active="updates", actions_html=check,
                     subtitle="Hent en ny version fra GitHub. Værten installerer den med backup og automatisk tilbagerulning.")


@app.post(f"{URL}/check")
@ui.admin_required
def updates_check():
    info = _check(force=True)
    ui.audit("update_check", result="ok" if not info.get("error") else "fejl", detail=info.get("error") or "")
    if info.get("error"):
        title, text = error_text(info["error"], has_token=bool(_token_info()), repo=info.get("repo") or "")
        return ui.respond(text if title == ACCESS_TITLE else title + ".", ok=False, next_url=URL)
    return ui.respond("Tjekket.", next_url=URL, reload=True)


@app.post(f"{URL}/settings")
@ui.admin_required
def updates_settings():
    if request.form.get("clear_token"):
        ui._kv_put(TOKEN_KEY, None)
        try:
            updates.remove_token_handover(update_dir())  # also a copy still waiting for the host
        except OSError:
            pass
        ui.audit("update_token", detail="fjernet")
        return ui.respond("Tokenen er fjernet.", next_url=URL, reload=True)
    channel = request.form.get("channel") or _settings()["channel"]
    if channel not in updates.CHANNELS:
        return ui.respond("Ukendt kanal.", ok=False, next_url=URL)
    raw = (request.form.get("token") or "").strip()
    msg = "Gemt."
    if raw:
        token = updates.clean_token(raw)
        if not token:
            return ui.respond("Det ligner ikke en GitHub-token.", ok=False, next_url=URL)
        ui._kv_put(TOKEN_KEY, {"enc": updates.seal_token(token, _key_material()), "fp": updates.token_fingerprint(token),
                               "saved_at": int(time.time()), "saved_by": _actor()[:80]})
        ui.audit("update_token", detail=f"gemt id={updates.token_fingerprint(token)}")
        msg = "Gemt. Tokenen er gemt krypteret."
    if channel != _settings()["channel"]:
        ui._kv_put(SETTINGS_KEY, {"channel": channel})
        ui.audit("update_settings", detail=f"kanal={channel}")
    return ui.respond(msg, next_url=URL, reload=True)


@app.post(f"{URL}/request")
@ui.admin_required
def updates_request():
    tag = (request.form.get("tag") or "").strip()
    info = _check()
    runner = _runner()
    token = _handover_token(runner)
    if token and not runner["fresh"]:
        # Never leave the token in clear text in state/update while no helper
        # runs to pick it up (User Scripts off, array stopped): only the helper
        # removes an orphaned copy.
        ui.audit("update_request", result="afvist", detail=f"tag={tag[:20]} runner=ikke set")
        return ui.respond("Hjælperen på værten er ikke set i de seneste minutter (User Script "
                          "Spamfilter-update kører ikke?), så tokenen gives ikke videre. Prøv igen, når "
                          "hjælperen er set.", ok=False, next_url=URL)
    try:
        updates.write_request(update_dir(), tag, _actor(), releases=info["releases"], current=ui.app_version(),
                              token=token)
    except updates.UpdateRefused as ex:
        ui.audit("update_request", result="afvist", detail=f"tag={tag[:20]}")
        return ui.respond(str(ex), ok=False, next_url=URL)
    except OSError as ex:
        log.warning("update request not written: %s", type(ex).__name__)
        return ui.respond("Anmodningen kunne ikke gemmes lige nu.", ok=False, next_url=URL)
    ui.audit("update_request", detail=f"tag={tag}" + (f" token=id {updates.token_fingerprint(token)}" if token else ""))
    return ui.respond(f"Bestilt: {tag}. Værten går i gang inden for et minut.", next_url=URL, reload=True)


@app.post(f"{URL}/cancel")
@ui.admin_required
def updates_cancel():
    if updates.read_status(update_dir())["state"] != "venter" or not updates.cancel_request(update_dir()):
        return ui.respond("Der er ingen ventende opdatering at annullere.", ok=False, next_url=URL)
    ui.audit("update_cancel")
    return ui.respond("Opdateringen er annulleret.", next_url=URL, reload=True)
