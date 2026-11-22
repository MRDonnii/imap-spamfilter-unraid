"""Home Assistant (B26): GET /api/v1/ha behind the central POLICY_HA
(home network + bearer token, else a plain 404), the JSON contract and its
no-PII promise, the token life cycle in Indstillinger (shown once, only
the sha256 stored, revoke, last use, audit), the HA package snippet, and
the family guide PDF (B26 companion: Hjælp -> "Hent familieguiden (PDF)").

The admin env of test_ui_23 runs the real services on the test DB."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import time
from pathlib import Path

import pytest
import yaml

from fakes_ui import post, set_status

import dashboard  # noqa: E402
import ui_ha  # noqa: E402
import ui_kit as kit  # noqa: E402
import ui_mail  # noqa: E402
import ui_tools  # noqa: E402
from test_ui_23 import audits, body, client_for, csp_clean, env  # noqa: F401,E402 - env = fixture

ROOT = Path(__file__).resolve().parents[1]
NOW = int(time.time())
LAN = {"REMOTE_ADDR": "192.168.1.20"}
API = "/api/v1/ha"
LIVE_IDS = ["bynet", "molt", "molt-inge", "molt-handel", "molt-sofie"]


def _event(c, account: str, mid: str, event: str, ts: int) -> None:
    c.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?, '')",
              (account, ts, mid, event))


@pytest.fixture
def henv(env):  # noqa: F811
    c = env.conn
    today0 = ui_mail.local_midnight_ts()
    t = max(today0 + 60, NOW - 120)
    # bynet today: two filter moves of the SAME mail (rescan) + one other + one
    # the user moved himself = 3 unique, 1 by the user.
    _event(c, "bynet", "a@x", "moved_to_junk", t)
    _event(c, "bynet", "a@x", "moved_to_junk", t + 1)
    _event(c, "bynet", "b@x", "moved_to_junk", t)
    _event(c, "bynet", "u@x", "user_junked", t)
    # molt: one today, plus history (yesterday and 6 days ago); 8 days ago is outside the window.
    _event(c, "molt", "m@x", "manual_mark_spam", t)
    _event(c, "molt", "y@x", "moved_to_junk", ui_mail.local_midnight_ts(1) + 3600)
    _event(c, "molt", "s@x", "moved_to_junk", ui_mail.local_midnight_ts(6) + 3600)
    _event(c, "molt", "old@x", "moved_to_junk", ui_mail.local_midnight_ts(8) + 3600)
    day = kit.today_str()
    for acc, metric, n in (("bynet", "scanned", 41), ("bynet", "released", 2), ("bynet", "user_rescued", 1),
                           ("molt", "scanned", 9)):
        c.execute("INSERT INTO stats_daily(account, day, metric, n) VALUES(?,?,?,?) "
                  "ON CONFLICT(account, day, metric) DO UPDATE SET n=excluded.n", (acc, day, metric, n))
    c.commit()
    yield env
    dashboard.configure_proxies("")


def _token(env) -> str:
    with env.app.test_request_context("/"):
        return dashboard.ha_token_create("admin")


def _get(env, token: str | None = None, *, environ=None, headers=None, client=None):
    c = client or env.app.test_client()
    hdrs = dict(headers or {})
    if token is not None:
        hdrs["Authorization"] = f"Bearer {token}"
    return c.get(API, headers=hdrs, environ_base=environ or LAN)


def _norm(html: str) -> str:
    return re.sub(r'name="csrf-token" content="[^"]*"', "", html)


def _unknown_404(env):
    return env.app.test_client().get("/api/v1/findes-ikke", environ_base=LAN)


# ===================================================================== policy


def test_route_policies(henv):
    assert dashboard.route_policy("api_ha") == dashboard.POLICY_HA == "ha_token"
    assert dashboard.route_policy("help_familieguide") == "login"
    for ep in ("access_page", "access_api_key_create", "access_api_key_delete"):
        assert dashboard.route_policy(ep) == "admin", ep


# ===================================================================== auth matrix


def test_no_token_is_a_plain_404(henv):
    ref = _unknown_404(henv)
    for hdrs in ({}, {"Authorization": "Bearer "}, {"Authorization": "Basic YWRtaW46eA=="}):
        r = _get(henv, headers=hdrs)
        assert r.status_code == 404 == ref.status_code
        assert r.content_type == ref.content_type
        # Byte-for-byte the unknown-URL page (apart from the per-session CSRF meta).
        assert _norm(body(r)) == _norm(body(ref))
        text = _norm(body(r)).lower()
        assert "bearer" not in text and "nøgle" not in text and "home assistant" not in text


def test_no_token_configured_404_even_with_a_guess(henv):
    assert _get(henv, "sfha_gæt").status_code == 404


def test_wrong_and_revoked_token(henv):
    tok = _token(henv)
    assert _get(henv, tok + "x").status_code == 404
    assert _get(henv, tok.upper()).status_code == 404
    assert _get(henv, tok).status_code == 200
    with henv.app.test_request_context("/"):
        assert dashboard.ha_token_revoke("admin") is True
    assert _get(henv, tok).status_code == 404


def test_new_token_invalidates_the_old_one(henv):
    old = _token(henv)
    new = _token(henv)
    assert old != new
    assert _get(henv, old).status_code == 404
    assert _get(henv, new).status_code == 200


def test_valid_token_from_lan(henv):
    tok = _token(henv)
    r = _get(henv, tok)
    assert r.status_code == 200 and r.content_type.startswith("application/json")
    assert r.headers["Cache-Control"] == "no-store"
    assert r.get_json()["version"] == dashboard.app_version()
    # The scheme is case-insensitive, extra spaces are tolerated.
    assert _get(henv, headers={"Authorization": f"bearer   {tok}"}).status_code == 200


def test_valid_token_from_outside_is_404(henv):
    tok = _token(henv)
    for addr in ("203.0.113.5", "8.8.8.8", "2001:db8::1"):
        assert _get(henv, tok, environ={"REMOTE_ADDR": addr}).status_code == 404, addr


@pytest.mark.parametrize("hdr", [{"X-Forwarded-For": "192.168.1.20"}, {"CF-Connecting-IP": "192.168.1.20"},
                                 {"Cf-Ray": "8a1b2c3d4e-CPH"}, {"Forwarded": "for=192.168.1.20"},
                                 {"X-Real-IP": "192.168.1.20"}])
def test_proxy_headers_from_a_lan_peer_are_404(henv, hdr):
    """A LAN browser never sends forwarding headers; the tunnel always does."""
    tok = _token(henv)
    assert _get(henv, tok, headers=hdr).status_code == 404


def test_valid_token_through_trusted_proxy_tunnel_is_404(henv):
    dashboard.configure_proxies("172.30.0.0/24")
    tok = _token(henv)
    hdrs = {"X-Forwarded-For": "192.168.1.20", "X-Forwarded-Proto": "https", "CF-Connecting-IP": "192.168.1.20",
            "Cf-Ray": "8a1b2c3d4e-CPH"}
    assert _get(henv, tok, environ={"REMOTE_ADDR": "172.30.0.2"}, headers=hdrs).status_code == 404
    # Even the bare proxy peer (cloudflared) without headers is not "local".
    assert _get(henv, tok, environ={"REMOTE_ADDR": "172.30.0.2"}).status_code == 404
    # The home network itself still works.
    assert _get(henv, tok).status_code == 200


def test_logged_in_admin_without_token_gets_404(henv):
    c = client_for(henv, "admin")
    assert c.get(API, environ_base=LAN).status_code == 404
    assert c.get(API, headers={"Accept": "application/json"}).status_code == 404


def test_failures_are_rate_limited_per_ip(henv):
    tok = _token(henv)
    for _ in range(dashboard.LOGIN_MAX_FAILURES):
        assert _get(henv, "sfha_forkert").status_code == 404
    # Locked: even the right token is refused from that IP for a while ...
    assert _get(henv, tok).status_code == 404
    row = henv.conn.execute("SELECT locked_until FROM login_attempts WHERE key='ha:192.168.1.20'").fetchone()
    assert row is not None and row[0] > NOW
    # ... other LAN hosts are not affected, and logins use their own keys.
    assert _get(henv, tok, environ={"REMOTE_ADDR": "192.168.1.21"}).status_code == 200
    assert henv.conn.execute("SELECT COUNT(*) FROM login_attempts WHERE key LIKE 'ip:%'").fetchone()[0] == 0


def test_success_resets_the_failure_count(henv):
    tok = _token(henv)
    for _round in range(3):
        for _ in range(dashboard.LOGIN_MAX_FAILURES - 1):
            _get(henv, "sfha_forkert")
        assert _get(henv, tok).status_code == 200


def test_last_use_and_last_refusal_are_remembered(henv):
    tok = _token(henv)
    _get(henv, tok)
    _get(henv, tok + "x", environ={"REMOTE_ADDR": "192.168.1.66"})
    with henv.app.test_request_context("/"):
        st = dashboard.ha_token_status()
    assert st["exists"] and st["last_used_ip"] == "192.168.1.20" and st["last_used_at"] >= NOW
    assert st["rejected_ip"] == "192.168.1.66" and st["rejected_at"] >= NOW
    assert "sha256" not in json.dumps(st) and tok not in json.dumps(st)


def test_head_and_post_do_not_leak(henv):
    tok = _token(henv)
    r = henv.app.test_client().post(API, headers={"Authorization": f"Bearer {tok}"}, environ_base=LAN)
    assert r.status_code == 404
    assert "spam_today" not in body(r)


def _anon_csrf(client, environ) -> str:
    html = client.get("/login", environ_base=environ).get_data(as_text=True)
    m = re.search(r'name="csrf" value="([^"]+)"', html) or re.search(r'name="csrf-token" content="([^"]+)"', html)
    assert m, "no anonymous CSRF token on /login"
    return m.group(1)


@pytest.mark.parametrize("environ", [{"REMOTE_ADDR": "203.0.113.9"}, LAN])
@pytest.mark.parametrize("method", ["post", "put", "patch", "delete", "options"])
def test_other_methods_answer_exactly_like_an_unknown_url(henv, environ, method):
    """2.3.6 review: a POST with a valid anonymous CSRF token answered 405
    (route exists) where an unknown path answers 404."""
    c = henv.app.test_client()
    tok = _anon_csrf(c, environ)
    kw = dict(data={"csrf": tok}, headers={"X-CSRF-Token": tok}, environ_base=environ)
    ref = getattr(c, method)("/api/v1/findes-ikke", **kw)
    r = getattr(c, method)(API, **kw)
    assert r.status_code == ref.status_code == 404, (method, r.status_code, ref.status_code)
    assert "Allow" not in r.headers
    # Even WITH the token: nothing but GET/HEAD, and still a plain 404.
    ha = _token(henv)
    r = getattr(c, method)(API, headers={"Authorization": f"Bearer {ha}"}, environ_base=LAN)
    assert r.status_code == 404 and "spam_today" not in body(r)


# ===================================================================== JSON


def _json(env) -> dict:
    tok = _token(env)
    r = _get(env, tok)
    assert r.status_code == 200
    return r.get_json()


def test_json_schema(henv):
    d = _json(henv)
    assert set(d) >= {"version", "generated_at", "ok", "problems", "problem_count", "bayes", "threats_today",
                      "lookalike", "antivirus", "accounts", "totals"}
    assert set(d["antivirus"]) == {"state", "signatures_age_hours"}
    assert isinstance(d["ok"], bool) and isinstance(d["problems"], list)
    assert d["problem_count"] == len(d["problems"])
    assert set(d["bayes"]) == {"active", "spam", "ham"}
    assert d["bayes"] == {"active": False, "spam": 140, "ham": 260}   # fake rspamd: 140 < 200
    assert set(d["lookalike"]) == {"new_registrations", "last_run"}
    assert set(d["accounts"]) == {"bynet", "molt", "sofie"}
    keys = {"display_name", "state", "state_label", "mode", "mode_label", "enabled", "threshold", "scanned_today",
            "spam_today", "spam_by_user_today", "released_today", "threats_today", "spam_7d", "last_activity",
            "login_ok"}
    for name, a in d["accounts"].items():
        assert set(a) == keys, name
        assert isinstance(a["spam_7d"], list) and len(a["spam_7d"]) == 7
        assert all(isinstance(x, int) for x in a["spam_7d"])
        assert a["spam_7d"][-1] == a["spam_today"]
        assert isinstance(a["login_ok"], bool) and isinstance(a["threshold"], float)
    assert set(d["totals"]) == {"scanned_today", "spam_today", "spam_by_user_today", "released_today",
                                "threats_today", "spam_7d"}
    assert d["generated_at"] and d["generated_at"][:4].isdigit()


def test_json_values(henv):
    d = _json(henv)
    j, m, t = d["accounts"]["bynet"], d["accounts"]["molt"], d["accounts"]["sofie"]
    assert (j["spam_today"], j["spam_by_user_today"]) == (3, 1)   # the rescanned mail counts once
    assert (m["spam_today"], m["spam_by_user_today"]) == (1, 1)
    assert m["spam_7d"] == [1, 0, 0, 0, 0, 1, 1]                  # oldest first (6 days ago); 8 days ago is outside
    assert j["scanned_today"] == 41 and j["released_today"] == 3
    assert (j["mode"], j["mode_label"]) == ("move", "Filtrér")
    assert (m["mode"], m["threshold"]) == ("shadow", 6.0)
    assert t["state"] == "paused" and t["state_label"] == "På pause" and t["enabled"] is False
    assert j["state"] == "idle" and j["state_label"] == "Aktiv" and j["login_ok"] is True
    assert j["last_activity"] and "T" in j["last_activity"]
    # Threat mails stopped today: virus + attachment for bynet, phish for molt (test_ui_23 seed).
    assert j["threats_today"] == 2 and m["threats_today"] == 1 and d["threats_today"] == 3
    tot = d["totals"]
    assert tot["spam_today"] == 4 and tot["spam_by_user_today"] == 2 and tot["scanned_today"] == 50
    assert tot["spam_7d"] == [a + b + c for a, b, c in zip(j["spam_7d"], m["spam_7d"], t["spam_7d"])]


def test_spam_today_is_the_oversigt_number(henv):
    """The API reuses the Oversigt mailbox-card helper (one source)."""
    d = _json(henv)
    with henv.app.test_request_context("/"):
        cards = ui_mail._spam_today_by_account()
    for name, (total, user) in cards.items():
        assert d["accounts"][name]["spam_today"] == total
        assert d["accounts"][name]["spam_by_user_today"] == user
    html = body(client_for(henv, "admin").get("/"))
    assert html  # the Oversigt still renders with the shared helper


def test_json_has_no_personal_data(henv):
    tok = _token(henv)
    raw = body(_get(henv, tok))
    assert "@" not in raw
    for leak in ("ole@", "sofie@", "Billing", "Faktura", "Pakkelabel", "MOLT-HEMMELIGT", "x.example",
                 "nielsen-vvs", "Win.Trojan", "imap.", "Spamfilter-mappen", tok, "sha256"):
        assert leak not in raw, leak


def test_problems_and_ok(henv):
    assert _json(henv)["ok"] is True
    set_status(henv.conn, "molt", "auth_failed", detail="Mailserveren afviser adgangskoden for ole@molt.example")
    set_status(henv.conn, "sofie", "error")  # paused accounts never count as a problem
    henv.conn.commit()
    d = _json(henv)
    assert d["ok"] is False
    assert "Login fejler for molt" in d["problems"]
    assert not any("sofie" in p for p in d["problems"])
    assert d["accounts"]["molt"]["login_ok"] is False and d["accounts"]["molt"]["state"] == "auth_failed"
    assert "@" not in json.dumps(d)


def test_problem_texts_cover_engine_and_rspamd(henv):
    (henv.state / "heartbeat").write_text(f"{NOW - 900} boot")
    henv.services.bayes = {"ok": False}
    d = _json(henv)
    assert "Filteret svarer ikke (hovedløkken står stille)" in d["problems"]
    assert any(p.startswith("rspamd svarer ikke") for p in d["problems"])
    assert d["bayes"] == {"active": None, "spam": None, "ham": None}


def test_threat_in_inbox_and_failed_moves_are_problems(henv):
    from fakes_ui import insert_message
    insert_message(henv.conn, "bynet", "phish-inbox@x.example", our_action="shadow_spam", our_score=9.0,
                   threat="phish", sender="x@x.example", subject="Log ind nu")
    insert_message(henv.conn, "bynet", "mf@x.example", our_action="move_failed", our_score=12.0)
    henv.conn.commit()
    p = _json(henv)["problems"]
    assert "1 farlig mail ligger stadig i indbakken hos bynet" in p
    assert "1 flytning fejlede det seneste døgn" in p


def test_lookalike_block(henv):
    import lookalike as lk
    c = henv.conn
    lk.ensure_schema(c)
    c.execute("INSERT INTO lookalike_watch(domain, protected, kind, created_at, checked_at, ns, mx, a, registered, "
              "first_registered_at, new_at, new_what) VALUES('pinslkbing.example', 'pinsikbing.example', 'homoglyph', ?, ?, "
              "'[]', '[\"10 mx.evil.example\"]', '[]', 1, ?, ?, 'mx')", (NOW, NOW, NOW, NOW - 60))
    c.execute("INSERT INTO engine_state(key, value, updated_at) VALUES('lookalike_watch_last', ?, ?)",
              (json.dumps({"started_at": NOW - 400, "finished_at": NOW - 300, "checked": 10, "new": 1}), NOW))
    c.commit()
    d = _json(henv)
    assert d["lookalike"]["new_registrations"] == 1
    assert d["lookalike"]["last_run"] == kit.iso_ts(NOW - 300)
    assert "Nyt domæne ligner pinsikbing.example" in d["problems"]
    assert "pinslkbing" not in json.dumps(d)            # attacker-chosen names never go to HA


def _health(tmp_path, clamav: dict | None, age: int = 20) -> Path:
    f = tmp_path / "health.json"
    parts = {p: {"ok": True, "detail": "ok"} for p in ("filter", "rspamd", "redis", "unbound")}
    if clamav is not None:
        parts["clamav"] = {"optional": True, **clamav}
    f.write_text(json.dumps({"ts": int(time.time()) - age, "ok": True, "parts": parts}))
    return f


@pytest.mark.parametrize("clamav,state,hours,problem", [
    ({"ok": True, "detail": "ok", "state": "ok", "db_age_s": 18720}, "ok", 5.2, None),
    ({"ok": True, "detail": "off", "state": "off", "reason": "SF_CLAMAV=0"}, "off", None, None),
    ({"ok": False, "detail": "waiting", "state": "waiting", "db_age_s": None}, "waiting", None, None),
    ({"ok": False, "detail": "x", "state": "down"}, "down",
     None, "Antivirus (ClamAV) svarer ikke – mails scannes uden virustjek"),
    ({"ok": False, "detail": "x", "state": "stale", "db_age_s": 4 * 86400}, "stale",
     96.0, "Antivirus (ClamAV) har ikke fået nye virussignaturer i over 3 dage"),
    ({"ok": True, "detail": "off", "state": "off", "reason": "cannot create /appdata/clamav"}, "off",
     None, "Antivirus (ClamAV) er slået fra ved en fejl – se sfctl doctor"),
])
def test_antivirus_block(henv, monkeypatch, tmp_path, clamav, state, hours, problem):
    """2.7: ClamAV's state from the AIO health check; down / stale are problems."""
    import aio_health
    status = _health(tmp_path, clamav)
    monkeypatch.setenv("SPAMFILTER_AIO", "1")
    monkeypatch.setattr(aio_health, "STATUS_FILE", str(status))
    monkeypatch.setattr(aio_health, "read_status", lambda path=None: json.loads(status.read_text()))
    d = _json(henv)
    assert d["antivirus"] == {"state": state, "signatures_age_hours": hours}
    av = [p for p in d["problems"] if p.startswith("Antivirus")]
    assert av == ([problem] if problem else [])


def test_antivirus_unknown_outside_the_aio_or_when_the_check_is_old(henv, monkeypatch, tmp_path):
    import aio_health
    monkeypatch.delenv("SPAMFILTER_AIO", raising=False)
    assert _json(henv)["antivirus"] == {"state": None, "signatures_age_hours": None}
    status = _health(tmp_path, {"ok": False, "detail": "x", "state": "down"}, age=3600)
    monkeypatch.setenv("SPAMFILTER_AIO", "1")
    monkeypatch.setattr(aio_health, "read_status", lambda path=None: json.loads(status.read_text()))
    d = _json(henv)
    assert d["antivirus"]["state"] is None and not [p for p in d["problems"] if p.startswith("Antivirus")]


def test_display_name_is_used(henv):
    raw = yaml.safe_load(henv.config.read_text())
    raw["accounts"][2]["display_name"] = "Sofie"
    henv.config.write_text(yaml.safe_dump(raw, sort_keys=False))
    d = _json(henv)
    assert d["accounts"]["sofie"]["display_name"] == "Sofie"


def test_broken_services_never_break_the_api(henv, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("x")
    for fn in ("threats_today", "bayes_stats", "lookalike_attention", "lookalike_overview"):
        monkeypatch.setattr(henv.services, fn, boom, raising=False)
    d = _json(henv)
    assert d["threats_today"] == 0 and d["lookalike"]["new_registrations"] == 0
    assert d["accounts"]["bynet"]["spam_today"] == 3


# ===================================================================== key on "Adgang for programmer" (2.11.0)


def _access(c) -> str:
    r = c.get("/access")
    assert r.status_code == 200
    return body(r)


def _ha_card(c) -> str:
    html = _access(c)
    assert 'id="home-assistant"' in html
    return html.split('id="home-assistant"')[1]


def test_help_card_without_key(henv):
    c = client_for(henv, "admin")
    card = _ha_card(c)
    assert "Home Assistant" in card and "Lav en API-nøgle ovenfor" in card
    assert "packages/spamfilter.yaml" in card and "Bearer DIN-NØGLE" in card and "data-copy-text" in card
    assert "/api/v1/ha" in card and "scan_interval: 300" in card
    csp_clean(_access(c), "/access")
    # Indstillinger only points to the new page now.
    s = body(c.get("/settings"))
    assert 'href="/access"' in s and 'id="home-assistant"' not in s and 'id="kontrolrum"' not in s


def test_create_shows_the_key_once_and_stores_only_the_hash(henv):
    c = client_for(henv, "admin")
    r = post(c, "/access/api-keys", {"name": "Home Assistant", "scope": "read", "lan_only": "1",
                                     "expires_days": "0"}, json_reply=False)
    assert r.status_code == 200 and r.headers["Cache-Control"] == "no-store"
    page = body(r)
    m = re.search(r"data-secret>(sf_[A-Za-z0-9_-]{43})<", page)
    assert m, "key not shown"
    tok = m.group(1)
    import html as _html
    assert f'spamfilter_auth: "Bearer {tok}"' in _html.unescape(page)
    assert "den vises kun én gang" in page and "data-auto-open" in page
    csp_clean(page, "key dialog")
    row = henv.conn.execute("SELECT * FROM ui_api_keys").fetchone()
    assert row["sha256"] == hashlib.sha256(tok.encode()).hexdigest() and row["hint"] == tok[-4:]
    assert tok not in json.dumps([tuple(r) for r in henv.conn.execute("SELECT * FROM ui_api_keys")])
    assert tok not in json.dumps(dict(henv.conn.execute("SELECT key, value FROM settings_kv").fetchall()))
    # Never rendered again.
    page = _access(c)
    assert tok not in page and row["sha256"] not in page
    assert f"sf_…{tok[-4:]}" in page and "Aldrig brugt endnu" in page
    a = audits(henv, "api_key_create")
    assert a and a[-1]["actor"] == "admin" and tok not in json.dumps(a) and "Home Assistant" in a[-1]["detail"]
    # It works, and the list then shows when and from where.
    assert _get(henv, tok).status_code == 200
    page = _access(c)
    assert "192.168.1.20" in page and "lige nu" in page


def test_delete_is_audited_and_the_key_stops_working(henv):
    c = client_for(henv, "admin")
    with henv.app.test_request_context("/"):
        tok, key = dashboard.api_key_create("Script", "read", "admin")
    r = post(c, f"/access/api-keys/{key['id']}/delete")
    assert r.status_code == 200 and r.get_json()["ok"] is True
    assert audits(henv, "api_key_delete")[-1]["detail"].startswith("Script (#")
    assert _get(henv, tok).status_code == 404
    assert "Ingen API-nøgler endnu" in _access(c)
    # Deleting nothing is harmless and not audited twice.
    n = len(audits(henv, "api_key_delete"))
    assert post(c, f"/access/api-keys/{key['id']}/delete").status_code == 404
    assert len(audits(henv, "api_key_delete")) == n


def test_key_routes_need_csrf(henv):
    c = client_for(henv, "admin")
    assert c.post("/access/api-keys", data={"name": "x", "scope": "read"}).status_code == 400
    assert c.post("/access/api-keys/1/delete").status_code == 400
    assert henv.conn.execute("SELECT COUNT(*) FROM ui_api_keys").fetchone()[0] == 0


@pytest.mark.parametrize("who", ["anna", "bo", "cille"])
def test_brugere_cannot_touch_the_keys(henv, who):
    c = client_for(henv, who)
    assert post(c, "/access/api-keys", {"name": "x", "scope": "admin"}).status_code == 403
    assert post(c, "/access/api-keys/1/delete").status_code == 403
    assert c.get("/access").status_code == 403
    assert henv.conn.execute("SELECT COUNT(*) FROM ui_api_keys").fetchone()[0] == 0


def test_anonymous_cannot_touch_the_keys(henv):
    c = henv.app.test_client()
    assert post(c, "/access/api-keys", {"name": "x", "scope": "read"}).status_code == 401


def test_page_survives_a_broken_key_store(henv, monkeypatch):
    def boom():
        raise RuntimeError("db")
    monkeypatch.setattr(dashboard, "api_keys_list", boom)
    r = client_for(henv, "admin").get("/access")
    assert r.status_code == 200 and "Nøglerne kan ikke læses" in body(r) and 'id="kontrolrum"' in body(r)


# ===================================================================== HA package


def _load_yaml(text: str):
    class Loader(yaml.SafeLoader):
        pass
    Loader.add_constructor("!secret", lambda loader, node: f"SECRET:{loader.construct_scalar(node)}")
    Loader.add_constructor("!include_dir_named", lambda loader, node: "INCLUDE")
    return yaml.load(text, Loader=Loader)


def test_package_yaml_is_valid_and_complete():
    text = ui_ha.ha_package_yaml("http://192.168.1.10:18080", LIVE_IDS)
    pkg = _load_yaml(text)
    rest = pkg["rest"][0]
    assert rest["resource"] == "http://192.168.1.10:18080/api/v1/ha"
    assert rest["headers"]["Authorization"] == "SECRET:spamfilter_auth" and rest["scan_interval"] == 300
    sensors, binary = rest["sensor"], rest["binary_sensor"]
    ids = [s["unique_id"] for s in sensors + binary]
    assert len(ids) == len(set(ids)) and all(ids)
    names = {s["name"] for s in sensors}
    for acc in LIVE_IDS:
        for what in ("spam i dag", "scannet i dag", "status"):
            assert f"Spamfilter {acc} {what}" in names
    sofie = next(s for s in sensors if s["unique_id"] == "spamfilter_molt_sofie_spam_i_dag")
    assert sofie["value_template"] == "{{ value_json.accounts['molt-sofie'].spam_today }}"
    assert sofie["json_attributes_path"] == "$.accounts['molt-sofie']" and "spam_7d" in sofie["json_attributes"]
    assert binary[0] == {"name": "Spamfilter problem", "unique_id": "spamfilter_problem", "device_class": "problem",
                         "value_template": "{{ not value_json.ok }}"}
    # 2.12 (#14): on when the filter has a mailbox the package has no sensors for.
    assert binary[1]["unique_id"] == "spamfilter_pakken_skal_hentes_igen" and len(binary) == 2
    assert binary[1]["value_template"] == ("{{ value_json.account_ids is defined and\n   (value_json.account_ids | sort) "
                                           "!= ['bynet', 'molt', 'molt-handel', 'molt-inge', 'molt-sofie'] }}")
    auto = _load_yaml(ui_ha.ha_automation_yaml())
    assert auto[0]["triggers"][0]["entity_id"] == "binary_sensor.spamfilter_problem"
    assert "notify.mobile_app_" in auto[0]["actions"][0]["action"]


def test_package_skips_unsafe_ids():
    text = ui_ha.ha_package_yaml("http://x:1", ["ok-id", "bad'id", "*"])
    assert "ok_id" in text and "bad" not in text


def test_docs_quote_the_generated_snippets():
    doc = (ROOT / "HOME-ASSISTANT.md").read_text()
    assert ui_ha.ha_package_yaml("http://192.168.1.10:18080", LIVE_IDS) in doc
    assert ui_ha.ha_automation_yaml() in doc
    assert not re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}", doc)
    for word in ("binary_sensor.spamfilter_problem", "secrets.yaml", "unique_id", "sfctl ha-token"):
        assert word in doc


# ===================================================================== family guide PDF


def test_pdf_needs_login(henv):
    r = henv.app.test_client().get("/help/familieguide.pdf")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


@pytest.mark.parametrize("who", ["admin", "anna", "bo", "cille"])
def test_pdf_download(henv, who):
    r = client_for(henv, who).get("/help/familieguide.pdf")
    assert r.status_code == 200
    assert r.headers["Content-Type"] == "application/pdf"
    cd = r.headers["Content-Disposition"]
    assert cd.startswith("attachment") and "Spamfilter-familieguide.pdf" in cd
    assert r.get_data()[:5] == b"%PDF-"
    assert r.headers["Cache-Control"] == "no-store"


def test_help_page_has_the_button(henv):
    for who in ("admin", "anna"):
        html = body(client_for(henv, who).get("/help"))
        assert "Hent familieguiden (PDF)" in html and 'href="/help/familieguide.pdf"' in html
        csp_clean(html, "/help")


def test_help_page_without_pdf_hides_the_button(henv, monkeypatch):
    monkeypatch.setattr(ui_tools, "GUIDE_PDF", Path("/nonexistent/familieguide.pdf"))
    c = client_for(henv, "admin")
    assert "Hent familieguiden" not in body(c.get("/help"))
    assert c.get("/help/familieguide.pdf").status_code == 404


def test_committed_pdf_is_a4_and_not_under_static():
    pdf = ROOT / "filter" / "familieguide.pdf"
    data = pdf.read_bytes()
    assert data[:5] == b"%PDF-" and len(data) > 10_000
    assert re.search(rb"/MediaBox\s*\[\s*0 0 59[45](?:\.\d+)? 84[12]", data)
    assert not (ROOT / "filter" / "static" / "familieguide.pdf").exists()
    assert "COPY familieguide.pdf /app/familieguide.pdf" in (ROOT / "filter" / "Dockerfile.unraid").read_text()


def _guide_mod():
    spec = importlib.util.spec_from_file_location("make_familieguide", ROOT / ".build" / "make_familieguide.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_guide_source_has_no_personal_data():
    text = (ROOT / "FAMILIEGUIDE.md").read_text()
    assert not re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)
    _guide_mod().check_private(text)


def test_guide_converter():
    g = _guide_mod()
    title, html_ = g.md_to_html("# Titel – undertitel\n\nTekst med **fed** og `kode <x>`.\n\n"
                                "| A | B |\n| --- | --- |\n| **1** | 2 |\n\n"
                                "1. Først:\n   - under\n2. Så\n\n- punkt\n")
    assert title == "Titel – undertitel"
    assert "<strong>fed</strong>" in html_ and "<code>kode &lt;x&gt;</code>" in html_
    assert "<table><thead><tr><th>A</th><th>B</th></tr></thead><tbody><tr><td><strong>1</strong></td>" in html_
    assert "<ol><li>Først:<ul><li>under</li></ul></li><li>Så</li></ol>" in html_
    assert "<ul><li>punkt</li></ul>" in html_
    page = g.build_html((ROOT / "FAMILIEGUIDE.md").read_text(), mark=None)
    assert page.startswith("<!doctype html>") and 'lang="da"' in page and "@page { size: A4" in page
    assert "http://" not in page.replace("http://192.168.1.10:18080", "")
    with pytest.raises(g.GuideError):
        g.build_html("# X\n\nSkriv til navn@eksempel.dk\n")
    with pytest.raises(g.GuideError):
        g.build_html("# X\n\nAdgangskode: hemmelig123\n")
