"""Home Assistant (B26) - spamfilter 2.3.6.

  * GET /api/v1/ha  read-only JSON for Home Assistant's `rest:` sensors.
    Access is the central policy dashboard.POLICY_HA: only from the home
    network (never through the tunnel/proxy) AND with the bearer token,
    else the same 404 as an unknown URL. No session, no CSRF (GET only).
    The JSON holds numbers and states only: no addresses, no subjects, no
    sender names (account ids + display names, and short Danish problem
    texts that name a mailbox or one of the owner's protected domains).
  * 2.11.0: the key is an API key on "Adgang for programmer" (ui_access.py,
    several named keys, shown ONCE, only sha256 stored); help_card() there
    shows what HA gets and the ready-made package.
  * ha_package_yaml() / ha_automation_yaml(): the snippets (HOME-ASSISTANT.md
    quotes them; a test keeps the two in sync).

Key storage and the access check live in dashboard.py (api_key_*,
api_key_for_request); sfctl has `api-key` and the alias `ha-token`.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any

from flask import abort, jsonify, request

import dashboard as ui
import siteconfig
import ui_kit as kit
import ui_mail as mail
from ui_kit import h

log = logging.getLogger("dashboard.ha")
app = ui.app

API_PATH = "/api/v1/ha"
ANCHOR = "home-assistant"
SETTINGS_URL = f"/access#{ANCHOR}"
# Where Home Assistant reaches the filter on the LAN (the snippet's
# default when the page itself is opened through the tunnel).
# SPAMFILTER_LAN_URL (container variable) or the local site config's
# lan_url; nothing set: a placeholder the admin replaces.
LAN_URL_PLACEHOLDER = "http://192.168.1.10:18080"
LAN_URL_DEFAULT = (os.environ.get("SPAMFILTER_LAN_URL") or siteconfig.get("lan_url")
                   or LAN_URL_PLACEHOLDER).rstrip("/")
SCAN_INTERVAL = 300
DAYS = 7
HEARTBEAT_STALE_S = 180
SECRET_NAME = "spamfilter_auth"
# Problem states (Oversigt shows the same as red/amber attention items).
PROBLEM_TEXT = {
    "auth_failed": "Login fejler for {label}",
    "error": "Forbindelsesfejl på {label}",
    "stale": "{label} svarer ikke",
    "paused_moves": "Flytning er sat på pause for {label}",
    "config_error": "Opsætningen af {label} har en fejl",
}
_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def _svc(fn: str, *args: Any, default: Any = None, **kwargs: Any) -> Any:
    try:
        return getattr(ui.services, fn)(*args, **kwargs)
    except Exception as ex:  # noqa: BLE001 - one source failing must not kill the API
        log.warning("services.%s failed: %s", fn, type(ex).__name__)
        return default


def _iso(ts: Any) -> str | None:
    return kit.iso_ts(ts) or None


def _n(n: int, one: str, many: str) -> str:
    return f"{kit.fmt_int(n)} {one if n == 1 else many}"


def _heartbeat_age() -> int | None:
    try:
        raw = (Path(ui.STATE_DIR) / "heartbeat").read_text().split()
        return max(0, int(time.time() - float(raw[0])))
    except (OSError, ValueError, IndexError):
        return None


def _day_windows(days: int = DAYS) -> list[tuple[int, int | None]]:
    """[(start, end)] for the last `days` local calendar days, oldest first
    (today's end is open)."""
    out: list[tuple[int, int | None]] = []
    for ago in range(days - 1, -1, -1):
        out.append((mail.local_midnight_ts(ago), mail.local_midnight_ts(ago - 1) if ago else None))
    return out


# 2.7: ClamAV state from the all-in-one container's last full health check
# (/run/spamfilter/health.json, written by sf-health check as root every
# 30 s). Older than this = unknown.
ANTIVIRUS_STATUS_MAX_AGE = 600
ANTIVIRUS_PROBLEM = {
    "down": "Antivirus (ClamAV) svarer ikke – mails scannes uden virustjek",
    "stale": "Antivirus (ClamAV) har ikke fået nye virussignaturer i over 3 dage",
}


def _antivirus() -> tuple[dict[str, Any], str | None]:
    """({state, signatures_age_hours}, problem text or None). state: ok,
    off, waiting (first signature download), down, stale - or None when
    unknown (4-container layout, no recent health check)."""
    out: dict[str, Any] = {"state": None, "signatures_age_hours": None}
    if os.environ.get("SPAMFILTER_AIO") != "1":
        return out, None
    try:
        import aio_health
        st = aio_health.read_status()
    except Exception:  # noqa: BLE001 - the HA endpoint never fails on this
        return out, None
    if not st or time.time() - int(st.get("ts") or 0) > ANTIVIRUS_STATUS_MAX_AGE:
        return out, None
    info = (st.get("parts") or {}).get("clamav")
    if not isinstance(info, dict) or not info.get("state"):
        return out, None
    state = str(info["state"])
    out["state"] = state
    age = info.get("db_age_s")
    if isinstance(age, (int, float)):
        out["signatures_age_hours"] = round(float(age) / 3600, 1)
    problem = ANTIVIRUS_PROBLEM.get(state)
    if state == "off" and info.get("reason") != "SF_CLAMAV=0":
        problem = "Antivirus (ClamAV) er slået fra ved en fejl – se sfctl doctor"
    return out, problem


def _failed_moves_24h() -> int:
    row = ui.query("SELECT COUNT(*) FROM messages WHERE our_action='move_failed' AND last_seen >= ?",
                   [int(time.time()) - 86400], one=True)
    return int(row[0] or 0) if row else 0


# ---------------------------------------------------------------------------
# The JSON
# ---------------------------------------------------------------------------


def payload() -> dict[str, Any]:
    """Everything GET /api/v1/ha returns (see HOME-ASSISTANT.md)."""
    accs = [a for a in ui.effective_accounts() if getattr(a, "name", "") and a.name != "*"]
    status = ui.account_status_map()
    today = mail._today_by_account()
    daily = [mail.spam_landed_by_account(t0, t1) for t0, t1 in _day_windows()]
    spam_today = daily[-1]
    threats = _svc("threats_today", None, default=None)
    threats = threats if isinstance(threats, dict) else {}
    t_by_acc = threats.get("by_account") if isinstance(threats.get("by_account"), dict) else {}
    t_inbox = threats.get("in_inbox_by_account") if isinstance(threats.get("in_inbox_by_account"), dict) else {}
    problems: list[str] = []

    cfg_err = ui.config_error()
    star = status.get("*", {})
    if cfg_err or star.get("raw_state") == "config_error":
        problems.append("Konfigurationen kan ikke indlæses")
    hb = _heartbeat_age()
    if hb is not None and hb > HEARTBEAT_STALE_S:
        problems.append("Filteret svarer ikke (hovedløkken står stille)")

    accounts: dict[str, dict[str, Any]] = {}
    totals = {"scanned_today": 0, "spam_today": 0, "spam_by_user_today": 0, "released_today": 0,
              "threats_today": 0, "spam_7d": [0] * DAYS}
    for a in accs:
        name = str(a.name)
        st = status.get(name, {})
        state = ui.account_state(a)
        label = ui.account_label(name)
        t = today.get(name, {})
        spam, by_user = spam_today.get(name, (0, 0))
        week = [int(d.get(name, (0, 0))[0]) for d in daily]
        last = max(int(st.get("last_scan_at") or 0), int(st.get("last_loop_at") or 0))
        row = {
            "display_name": label,
            "state": state,
            "state_label": kit.state_label(state),
            "mode": str(getattr(a, "mode", "shadow") or "shadow"),
            "mode_label": kit.mode_label(getattr(a, "mode", "shadow")),
            "enabled": bool(getattr(a, "enabled", True)),
            "threshold": float(getattr(a, "threshold", 0) or 0),
            "scanned_today": int(t.get("scanned", 0)),
            "spam_today": int(spam),
            "spam_by_user_today": int(by_user),
            "released_today": int(t.get("released", 0)) + int(t.get("user_rescued", 0)),
            "threats_today": int(t_by_acc.get(name, 0) or 0),
            "spam_7d": week,
            "last_activity": _iso(last) if last else None,
            "login_ok": state != "auth_failed",
        }
        accounts[name] = row
        for k in ("scanned_today", "spam_today", "spam_by_user_today", "released_today", "threats_today"):
            totals[k] += row[k]
        totals["spam_7d"] = [x + y for x, y in zip(totals["spam_7d"], week)]
        if row["enabled"] and state in PROBLEM_TEXT:
            problems.append(PROBLEM_TEXT[state].format(label=label))
        inbox = int(t_inbox.get(name, 0) or 0)
        if inbox:
            problems.append(f"{_n(inbox, 'farlig mail', 'farlige mails')} ligger stadig i indbakken hos {label}")

    failed = _failed_moves_24h()
    if failed:
        problems.append(f"{_n(failed, 'flytning', 'flytninger')} fejlede det seneste døgn")

    bayes = _svc("bayes_stats", default=None)
    if isinstance(bayes, dict) and bayes.get("ok"):
        bayes_out = {"active": bool(bayes.get("active", False)) if "active" in bayes else
                     (int(bayes.get("spam_learned") or 0) >= int(bayes.get("min_learns") or 200)
                      and int(bayes.get("ham_learned") or 0) >= int(bayes.get("min_learns") or 200)),
                     "spam": int(bayes.get("spam_learned") or 0), "ham": int(bayes.get("ham_learned") or 0)}
    else:
        bayes_out = {"active": None, "spam": None, "ham": None}
        problems.append("rspamd svarer ikke – scanning og læring venter")

    new = _svc("lookalike_attention", default=[]) or []
    new = [i for i in new if isinstance(i, dict) and i.get("domain")]
    for prot in sorted({str(i.get("protected") or "") for i in new if i.get("protected")}):
        problems.append(f"Nyt domæne ligner {prot}")
    antivirus, av_problem = _antivirus()
    if av_problem:
        problems.append(av_problem)

    last_run = None
    ov = _svc("lookalike_overview", default=None)
    if isinstance(ov, dict) and isinstance(ov.get("last_run"), dict):
        lr = ov["last_run"]
        last_run = _iso(lr.get("finished_at") or lr.get("started_at"))

    mailcheck = {"status": None, "errors": None, "warnings": None, "last_run": None}
    try:
        import mailcheck as mc  # noqa: PLC0415 - 2.7

        s = mc.last_summary(ui.db())
        if s:
            mailcheck = {"status": s["status"], "errors": s["errors"], "warnings": s["warnings"],
                         "last_run": _iso(s["finished_at"])}
    except Exception as ex:  # noqa: BLE001 - the payload must answer
        log.info("mailcheck summary skipped: %s", type(ex).__name__)

    return {
        "version": ui.app_version(),
        "generated_at": _iso(int(time.time())),
        "ok": not problems,
        "problems": problems,
        "problem_count": len(problems),
        "bayes": bayes_out,
        "threats_today": int(threats.get("total") or 0),
        "lookalike": {"new_registrations": len(new), "last_run": last_run},
        "antivirus": antivirus,
        "mailcheck": mailcheck,
        "accounts": accounts,
        # 2.12 (#14): the mailbox ids a package needs sensors for - the
        # package compares its own list with this one.
        "account_ids": _account_ids(list(accounts)),
        "totals": totals,
    }


# Every method is routed here so a POST/PUT/... never answers 405 (which
# would tell an outsider that the path exists): POLICY_HA answers 404
# first, and a token holder gets 404 for anything but GET/HEAD. The
# endpoint is read-only and session-less, so it is CSRF-exempt
# (dashboard._CSRF_EXEMPT) - otherwise a LAN POST would answer 400.
@app.route(API_PATH, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
           provide_automatic_options=False)
@ui.ha_token_required
def api_ha():
    if request.method not in ("GET", "HEAD"):
        abort(404)
    resp = jsonify(payload())
    resp.headers["X-Robots-Tag"] = "noindex"
    return resp


# ---------------------------------------------------------------------------
# Home Assistant snippets
# ---------------------------------------------------------------------------


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(name).lower()).strip("_") or "konto"


def _q(text: str) -> str:
    """A YAML double-quoted scalar (JSON strings are valid YAML)."""
    return json.dumps(str(text), ensure_ascii=False)


def base_url() -> str:
    """The filter's LAN address for HA: this page's own address when it is
    opened on the home network, else LAN_URL_DEFAULT."""
    try:
        if ui.request_is_local():
            return request.host_url.rstrip("/")
    except RuntimeError:
        pass
    return LAN_URL_DEFAULT


def _account_ids(accounts: Any = None) -> list[str]:
    names = accounts if accounts is not None else [a.name for a in ui.effective_accounts()]
    return [str(n) for n in names if str(n) != "*" and _ID_RE.match(str(n))]


def ha_package_yaml(base: str | None = None, accounts: Any = None) -> str:
    """packages/spamfilter.yaml for Home Assistant: one REST call every 5
    minutes; sensors per mailbox (spam i dag, scannet i dag, status) + the
    totals + binary_sensor 'Spamfilter problem'. The token comes from
    secrets.yaml (`spamfilter_auth: "Bearer <nøgle>"`)."""
    base = (base or LAN_URL_DEFAULT).rstrip("/")
    ids = _account_ids(accounts)
    lines = [
        "# Spamfilter -> Home Assistant (kun læsning: tal og tilstande, ingen adresser eller emner)",
        f"# Sensorer for {len(ids)} postkasse{'' if len(ids) == 1 else 'r'}: {', '.join(ids) or '-'}.",
        "# Kommer der en ny postkasse, så hent pakken igen (Indstillinger -> Adgang for programmer)",
        "# og erstat denne fil - binary_sensor.spamfilter_pakken_skal_hentes_igen siger til.",
        "# 1. secrets.yaml:  " + SECRET_NAME + ': "Bearer DIN-NØGLE"',
        "# 2. configuration.yaml:",
        "#      homeassistant:",
        "#        packages: !include_dir_named packages",
        "# 3. Gem denne fil som packages/spamfilter.yaml, tjek konfigurationen og genstart.",
        "rest:",
        f"  - resource: {base}{API_PATH}",
        "    headers:",
        f"      Authorization: !secret {SECRET_NAME}",
        f"    scan_interval: {SCAN_INTERVAL}",
        "    timeout: 30",
        "    sensor:",
        '      - name: "Spamfilter status"',
        "        unique_id: spamfilter_status",
        "        icon: mdi:shield-check",
        "        value_template: \"{{ 'OK' if value_json.ok else 'Problem' }}\"",
        "        json_attributes:",
        "          - problems",
        "          - version",
        "          - bayes",
        "          - lookalike",
        "          - totals",
        '      - name: "Spamfilter spam i dag"',
        "        unique_id: spamfilter_spam_i_dag",
        "        icon: mdi:email-remove",
        "        unit_of_measurement: mails",
        "        state_class: measurement",
        '        value_template: "{{ value_json.totals.spam_today }}"',
        '      - name: "Spamfilter scannet i dag"',
        "        unique_id: spamfilter_scannet_i_dag",
        "        icon: mdi:email-search",
        "        unit_of_measurement: mails",
        "        state_class: measurement",
        '        value_template: "{{ value_json.totals.scanned_today }}"',
        '      - name: "Spamfilter farlige mails i dag"',
        "        unique_id: spamfilter_farlige_i_dag",
        "        icon: mdi:alert-octagon",
        "        unit_of_measurement: mails",
        "        state_class: measurement",
        '        value_template: "{{ value_json.threats_today }}"',
        '      - name: "Spamfilter nye lignende domæner"',
        "        unique_id: spamfilter_nye_lignende_domaener",
        "        icon: mdi:web-check",
        '        value_template: "{{ value_json.lookalike.new_registrations }}"',
    ]
    for name in ids:
        s = _slug(name)
        ref = f"value_json.accounts['{name}']"
        path = f"$.accounts['{name}']"
        lines += [
            f"      # Postkasse: {name}",
            f"      - name: {_q(f'Spamfilter {name} spam i dag')}",
            f"        unique_id: spamfilter_{s}_spam_i_dag",
            "        icon: mdi:email-remove",
            "        unit_of_measurement: mails",
            "        state_class: measurement",
            f'        value_template: "{{{{ {ref}.spam_today }}}}"',
            f'        json_attributes_path: "{path}"',
            "        json_attributes:",
            "          - display_name",
            "          - spam_7d",
            "          - spam_by_user_today",
            "          - released_today",
            "          - threats_today",
            f"      - name: {_q(f'Spamfilter {name} scannet i dag')}",
            f"        unique_id: spamfilter_{s}_scannet_i_dag",
            "        icon: mdi:email-search",
            "        unit_of_measurement: mails",
            "        state_class: measurement",
            f'        value_template: "{{{{ {ref}.scanned_today }}}}"',
            f"      - name: {_q(f'Spamfilter {name} status')}",
            f"        unique_id: spamfilter_{s}_status",
            "        icon: mdi:mailbox",
            f'        value_template: "{{{{ {ref}.state_label }}}}"',
            f'        json_attributes_path: "{path}"',
            "        json_attributes:",
            "          - display_name",
            "          - state",
            "          - mode_label",
            "          - threshold",
            "          - login_ok",
            "          - last_activity",
        ]
    lines += [
        "    binary_sensor:",
        '      - name: "Spamfilter problem"',
        "        unique_id: spamfilter_problem",
        "        device_class: problem",
        '        value_template: "{{ not value_json.ok }}"',
        # 2.12 (#14): on when the filter has mailboxes this package has no sensors for.
        '      - name: "Spamfilter pakken skal hentes igen"',
        "        unique_id: spamfilter_pakken_skal_hentes_igen",
        "        device_class: update",
        "        value_template: >-",
        "          {{ value_json.account_ids is defined and",
        f"             (value_json.account_ids | sort) != {sorted(ids)!r} }}}}",
    ]
    return "\n".join(lines) + "\n"


def ha_automation_yaml() -> str:
    """automations.yaml idea: push to the phone when there is a problem or
    the filter stops answering."""
    return "\n".join([
        "# Push-besked, når spamfilteret har et problem eller ikke svarer.",
        "# Ret notify.mobile_app_din_telefon til din egen telefon (Udviklerværktøjer -> Handlinger).",
        "- alias: Spamfilter - besked ved problem",
        "  id: spamfilter_problem_push",
        "  mode: single",
        "  triggers:",
        "    - trigger: state",
        "      entity_id: binary_sensor.spamfilter_problem",
        '      to: "on"',
        "      for: { minutes: 10 }",
        "    - trigger: state",
        "      entity_id: sensor.spamfilter_status",
        '      to: "unavailable"',
        "      for: { minutes: 15 }",
        "  actions:",
        "    - action: notify.mobile_app_din_telefon",
        "      data:",
        "        title: Spamfilter",
        "        message: >-",
        "          {% set p = state_attr('sensor.spamfilter_status', 'problems') %}",
        "          {% if states('sensor.spamfilter_status') == 'unavailable' %}Spamfilteret svarer ikke.",
        "          {% elif p %}{{ p | join(', ') }}{% else %}Spamfilteret melder et problem.{% endif %}",
        "",
    ])


# ---------------------------------------------------------------------------
# "Adgang for programmer" (ui_access.py): how Home Assistant uses its key
# ---------------------------------------------------------------------------


def _code_block(text: str, *, label: str, copy_label: str) -> str:
    return (f'<div class="ha-code"><div class="ha-code-head"><span>{h(label)}</span>'
            + kit.button("Kopiér", kind="ghost", icon="copy", size="sm",
                         attrs=f'type="button" data-copy-text="{h(text)}" data-copy-label="{h(copy_label)}"')
            + f'</div><pre class="ha-pre" tabindex="0"><code>{h(text)}</code></pre></div>')


def secrets_line(token: str = "DIN-NØGLE") -> str:
    return f'{SECRET_NAME}: "Bearer {token}"'


def secrets_block(token: str) -> str:
    """The secrets.yaml line WITH a new key (shown once, ui_access)."""
    return _code_block(secrets_line(token), label="Home Assistant: secrets.yaml (med nøglen)", copy_label="Linjen")


def help_card() -> str:
    """The 'Home Assistant' card under the key list: what HA gets and the
    ready-made package (the key itself is made in the list above)."""
    base = base_url()
    intro = (f'<p class="muted">Vis dagens spam, status pr. postkasse og en besked ved problemer i Home Assistant. '
             f'Home Assistant henter tallene hvert {SCAN_INTERVAL // 60}. minut fra '
             f'<span class="mono">{h(base)}{API_PATH}</span> med en API-nøgle (Kun læse). Ingen '
             "adresser eller emner, og intet kan ændres udefra.</p>")
    steps = ('<ol class="ha-steps">'
             "<li>Lav en API-nøgle ovenfor (fx “Home Assistant”, Kun læse), og kopiér linjen til Home Assistants "
             "<span class=\"mono\">secrets.yaml</span>.</li>"
             "<li>Kopiér pakken nedenfor til <span class=\"mono\">packages/spamfilter.yaml</span>.</li>"
             "<li>Tjek konfigurationen i Home Assistant, og genstart.</li></ol>"
             f'<p class="muted small">Pakken har sensorer for de {len(_account_ids())} postkasser, der findes nu. '
             "Kommer der en ny postkasse, så kopiér pakken herfra igen og erstat filen – "
             '<span class="mono">binary_sensor.spamfilter_pakken_skal_hentes_igen</span> slår til, når den '
             "mangler en postkasse.</p>")
    snippet = (
        '<details class="disclosure ha-snippets"><summary>' + kit.icon("chevron-right")
        + "Home Assistant-pakke og push-besked</summary>"
        + _code_block(secrets_line(), label="secrets.yaml", copy_label="Linjen")
        + _code_block(ha_package_yaml(base), label="packages/spamfilter.yaml", copy_label="Pakken")
        + _code_block(ha_automation_yaml(), label="automations.yaml (idé)", copy_label="Automationen")
        + '<p class="faint small">Kort til dashboardet og flere eksempler: HOME-ASSISTANT.md i kildekoden.</p></details>')
    return (f'<div id="{ANCHOR}">' + kit.card(intro + steps + snippet, title="Home Assistant",
                                               subtitle="Dagens spam og besked ved problemer.", cls="ha-card")
            + "</div>")
