"""API keys for programs (2.11.0, shared plan "Adgang for programmer"):
several named keys in ui_api_keys (only sha256 + last 4 characters), the
move of the 2.3.6-2.10 Home Assistant token (the old sfha_ key keeps
working), home network only by default, expiry, scopes, the per-key rate
limit, the per-IP brake on wrong keys and the page that lists them.

GET /api/v1/ha (ui_ha) is the endpoint; the env fixture of test_ui_23 runs
the real services on a test DB."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time

import pytest
from werkzeug.exceptions import Forbidden, NotFound

from fakes_ui import post

import dashboard  # noqa: E402
import ui_ha  # noqa: E402,F401 - registers /api/v1/ha
from test_ui_23 import audits, body, client_for, csp_clean, env  # noqa: F401,E402 - env = fixture

API = "/api/v1/ha"
LAN = {"REMOTE_ADDR": "192.168.1.20"}
OUTSIDE = {"REMOTE_ADDR": "203.0.113.5"}


@pytest.fixture
def kenv(env):  # noqa: F811
    yield env
    dashboard.configure_proxies("")


def _make(env, name="Kontrolrum", scope="read", **kw):
    with env.app.test_request_context("/"):
        return dashboard.api_key_create(name, scope, "admin", **kw)


def _get(env, token=None, *, environ=None, headers=None, url=API):
    hdrs = dict(headers or {})
    if token is not None:
        hdrs["Authorization"] = f"Bearer {token}"
    return env.app.test_client().get(url, headers=hdrs, environ_base=environ or LAN)


def _legacy_token(env) -> str:
    """A 2.10 database: the sfha_ token's hash in settings_kv, not moved yet."""
    tok = "sfha_" + secrets.token_urlsafe(32)
    c = env.conn
    c.execute("INSERT OR REPLACE INTO settings_kv(key, value) VALUES('ha_token', ?)",
              (json.dumps({"sha256": hashlib.sha256(tok.encode()).hexdigest(), "created_at": 1_757_800_000,
                           "created_by": "admin"}),))
    c.execute("INSERT OR REPLACE INTO settings_kv(key, value) VALUES('ha_token_used', ?)",
              (json.dumps({"at": 1_763_000_000, "ip": "192.168.1.20"}),))
    c.execute("DELETE FROM settings_kv WHERE key='api_keys_migrated'")
    c.execute("DELETE FROM ui_api_keys")
    c.commit()
    return tok


def _rows(env) -> list:
    return env.conn.execute("SELECT * FROM ui_api_keys ORDER BY id").fetchall()


# ===================================================================== format and storage


def test_new_key_format_and_storage(kenv):
    tok, key = _make(kenv)
    assert re.fullmatch(r"sf_[A-Za-z0-9_-]{43}", tok)
    row, = _rows(kenv)
    assert row["sha256"] == hashlib.sha256(tok.encode()).hexdigest() and row["hint"] == tok[-4:]
    assert row["lan_only"] == 1 and row["expires_at"] is None and row["migrated"] == 0
    assert tok not in json.dumps([tuple(r) for r in _rows(kenv)])
    assert "sha256" not in key and dashboard.api_key_label(key) == f"sf_…{tok[-4:]}"


@pytest.mark.parametrize("name,scope,err", [("", "read", "navn"), ("x" * 61, "read", "højst"),
                                            ("a\x00b", "read", "ugyldige"), ("ok", "root", "rettighed")])
def test_bad_input_is_refused(kenv, name, scope, err):
    with pytest.raises(ValueError, match=err):
        _make(kenv, name, scope)
    assert _rows(kenv) == []


def test_names_are_unique_and_the_count_is_capped(kenv, monkeypatch):
    _make(kenv, "Kontrolrum")
    with pytest.raises(ValueError, match="allerede"):
        _make(kenv, "  kontrolrum ")
    monkeypatch.setattr(dashboard, "API_KEY_MAX_COUNT", 2)
    _make(kenv, "Script")
    with pytest.raises(ValueError, match="højst være 2"):
        _make(kenv, "Tredje")


# ===================================================================== migration


def test_old_ha_token_is_moved_and_keeps_working(kenv):
    tok = _legacy_token(kenv)
    assert dashboard.api_keys_migrate() is True
    row, = _rows(kenv)
    assert (row["name"], row["scope"], row["prefix"], row["hint"], row["migrated"], row["lan_only"]) == (
        "Home Assistant", "read", "sfha_", "", 1, 1)
    assert row["created_at"] == 1_757_800_000 and row["last_used_ip"] == "192.168.1.20"
    # The very same Authorization header gives the same answer as before.
    r = _get(kenv, tok)
    assert r.status_code == 200 and "accounts" in r.get_json()
    new, _key = _make(kenv, "Kontrolrum")
    assert _get(kenv, new).get_json().keys() == r.get_json().keys()
    # The old settings stay for one version (rollback to 2.10 keeps working).
    assert kenv.conn.execute("SELECT COUNT(*) FROM settings_kv WHERE key='ha_token'").fetchone()[0] == 1
    assert audits(kenv, "api_keys_migrated")
    # Only once.
    assert dashboard.api_keys_migrate() is False and len(_rows(kenv)) == 2


def test_migration_runs_on_start(kenv):
    tok = _legacy_token(kenv)
    dashboard._UI_DB_READY.clear()
    dashboard.init_ui_db()
    assert [r["name"] for r in _rows(kenv)] == ["Home Assistant"]
    assert _get(kenv, tok).status_code == 200


def test_no_old_token_nothing_to_move(kenv):
    kenv.conn.execute("DELETE FROM settings_kv WHERE key IN ('ha_token', 'api_keys_migrated')")
    kenv.conn.commit()
    assert dashboard.api_keys_migrate() is False and _rows(kenv) == []


def test_existing_new_keys_are_not_mixed_with_an_old_token(kenv):
    tok = _legacy_token(kenv)
    _make(kenv, "Kontrolrum")
    assert dashboard.api_keys_migrate() is False
    assert [r["name"] for r in _rows(kenv)] == ["Kontrolrum"] and _get(kenv, tok).status_code == 404


def test_deleting_the_moved_key_also_deletes_the_old_token(kenv):
    tok = _legacy_token(kenv)
    dashboard.api_keys_migrate()
    row, = _rows(kenv)
    assert dashboard.api_key_delete(row["id"])["migrated"] is True
    assert _get(kenv, tok).status_code == 404
    left = kenv.conn.execute("SELECT COUNT(*) FROM settings_kv WHERE key IN ('ha_token', 'ha_token_used')")
    assert left.fetchone()[0] == 0  # a rollback cannot bring it back


def test_moved_key_on_the_page(kenv):
    _legacy_token(kenv)
    dashboard.api_keys_migrate()
    page = body(client_for(kenv, "admin").get("/access"))
    assert "Home Assistant" in page and "Flyttet" in page and "flyttet fra den gamle nøgle" in page
    assert "sfha_…" in page


# ===================================================================== access


def test_several_keys_each_work_and_delete_alone(kenv):
    a, ka = _make(kenv, "Home Assistant")
    b, _kb = _make(kenv, "Kontrolrum")
    assert _get(kenv, a).status_code == 200 and _get(kenv, b).status_code == 200
    dashboard.api_key_delete(ka["id"])
    assert _get(kenv, a).status_code == 404 and _get(kenv, b).status_code == 200


def test_lan_only_is_the_default(kenv):
    tok, _ = _make(kenv)
    assert _get(kenv, tok, environ=OUTSIDE).status_code == 404
    assert _get(kenv, tok).status_code == 200


def test_key_allowed_from_outside(kenv):
    lan, _ = _make(kenv, "Hjemme")
    out, _ = _make(kenv, "Ude", lan_only=False)
    assert _get(kenv, out, environ=OUTSIDE).status_code == 200
    assert _get(kenv, lan, environ=OUTSIDE).status_code == 404
    # Through the tunnel too, and the throttle uses the client's address.
    dashboard.configure_proxies("172.30.0.0/24")
    hdrs = {"X-Forwarded-For": "198.51.100.7", "CF-Connecting-IP": "198.51.100.7", "Cf-Ray": "8a1b-CPH"}
    assert _get(kenv, out, environ={"REMOTE_ADDR": "172.30.0.2"}, headers=hdrs).status_code == 200
    assert _get(kenv, lan, environ={"REMOTE_ADDR": "172.30.0.2"}, headers=hdrs).status_code == 404
    rej = dashboard.api_key_rejected()
    assert rej["ip"] == "198.51.100.7" and rej["reason"] == "outside"


def test_outside_without_any_remote_key_touches_nothing(kenv):
    tok, _ = _make(kenv)
    for _ in range(3):
        assert _get(kenv, tok + "x", environ=OUTSIDE).status_code == 404
    assert kenv.conn.execute("SELECT COUNT(*) FROM login_attempts").fetchone()[0] == 0
    assert dashboard.api_key_rejected() == {}


def test_expired_key_is_404(kenv):
    tok, key = _make(kenv, expires_days=30)
    assert key["expires_at"] > time.time() + 29 * 86400
    assert _get(kenv, tok).status_code == 200
    kenv.conn.execute("UPDATE ui_api_keys SET expires_at=? WHERE id=?", (int(time.time()) - 1, key["id"]))
    kenv.conn.commit()
    assert _get(kenv, tok).status_code == 404
    assert dashboard.api_key_rejected()["reason"] == "expired"
    page = body(client_for(kenv, "admin").get("/access"))
    assert "Udløbet" in page


def test_key_only_in_the_header(kenv):
    tok, _ = _make(kenv)
    assert _get(kenv, url=f"{API}?token={tok}").status_code == 404
    assert _get(kenv, url=f"{API}?access_token={tok}").status_code == 404
    assert _get(kenv, headers={"X-Api-Key": tok}).status_code == 404


@pytest.mark.parametrize("scope,need,ok", [("read", "read", True), ("read", "control", False),
                                           ("control", "control", True), ("control", "admin", False),
                                           ("admin", "control", True), ("admin", "admin", True)])
def test_scopes(kenv, scope, need, ok):
    tok, _ = _make(kenv, scope=scope)
    policy = {"read": dashboard.POLICY_HA, "control": dashboard.POLICY_API_CONTROL,
              "admin": dashboard.POLICY_API_ADMIN}[need]
    with kenv.app.test_request_context(API, headers={"Authorization": f"Bearer {tok}"}, environ_base=LAN):
        if ok:
            assert dashboard.enforce(policy) is None
        else:
            with pytest.raises(Forbidden):
                dashboard.enforce(policy)
    with kenv.app.test_request_context(API, headers={"Authorization": "Bearer sf_ukendt"}, environ_base=LAN):
        with pytest.raises(NotFound):
            dashboard.enforce(policy)


def test_unknown_scope_decorator_fails_loudly():
    with pytest.raises(ValueError):
        dashboard.api_key_required("root")


def test_rate_limit_per_key(kenv, monkeypatch):
    monkeypatch.setitem(dashboard.API_KEY_RATE, "read", 3)
    tok, _ = _make(kenv)
    other, _ = _make(kenv, "Andet")
    for _ in range(3):
        assert _get(kenv, tok).status_code == 200
    r = _get(kenv, tok)
    assert r.status_code == 429 and 1 <= int(r.headers["Retry-After"]) <= 61 and "spam_today" not in body(r)
    # Another key is not affected.
    assert _get(kenv, other).status_code == 200


def test_wrong_keys_are_braked_per_ip(kenv):
    tok, _ = _make(kenv)
    for _ in range(dashboard.LOGIN_MAX_FAILURES):
        assert _get(kenv, "sf_forkert").status_code == 404
    assert _get(kenv, tok).status_code == 404
    assert _get(kenv, tok, environ={"REMOTE_ADDR": "192.168.1.21"}).status_code == 200


def test_last_use_is_written_at_most_once_a_minute(kenv):
    tok, key = _make(kenv)
    for _ in range(3):
        _get(kenv, tok)
    row, = _rows(kenv)
    assert row["last_used_ip"] == "192.168.1.20" and row["uses"] == 1
    kenv.conn.execute("UPDATE ui_api_keys SET last_used_at=last_used_at-120 WHERE id=?", (key["id"],))
    kenv.conn.commit()
    _get(kenv, tok)
    assert _rows(kenv)[0]["uses"] == 4


def test_refusal_is_noted_and_audited_by_name_never_the_key(kenv):
    tok, _ = _make(kenv, "Kontrolrum")
    _get(kenv, tok, environ=OUTSIDE)  # nothing: no key may be used from outside
    out, _ = _make(kenv, "Ude", lan_only=False)
    _get(kenv, tok, environ=OUTSIDE)
    rej = dashboard.api_key_rejected()
    assert rej["reason"] == "outside" and rej["ip"] == "203.0.113.5"
    a = audits(kenv, "api_key_rejected")
    assert a and "Kontrolrum (#" in a[-1]["detail"] and tok not in json.dumps(a) and out not in json.dumps(a)


# ===================================================================== page


def test_page_lists_keys_and_has_the_dialogs(kenv):
    _make(kenv, "Kontrolrum")
    _tok, key = _make(kenv, "Backup-script", "control")
    kenv.conn.execute("UPDATE ui_api_keys SET created_at=?, last_used_at=? WHERE id=?",
                      (int(time.time()) - 200 * 86400, int(time.time()) - 95 * 86400, key["id"]))
    kenv.conn.commit()
    c = client_for(kenv, "admin")
    page = body(c.get("/access"))
    assert "Adgang for programmer" in page and "Til personer" in page and "Til programmer" in page
    assert 'id="kontrolrum"' in page and "Login fra Kontrolrum (SSO)" in page
    assert "Kontrolrum" in page and "Backup-script" in page and "Kun læse" in page and "Læse og styre" in page
    assert "Ubrugt i 90 dage" in page and "Aldrig brugt endnu" in page
    assert 'id="ak-new"' in page and 'name="scope"' in page and 'name="lan_only"' in page and "Om 1 år" in page
    assert "Slet nøglen “Backup-script”?" in page and "De andre nøgler virker som før." in page
    assert 'href="/access"' in page  # menu entry
    csp_clean(page, "/access")


def test_create_from_the_page_with_options(kenv):
    c = client_for(kenv, "admin")
    # 2.12 (#26): an Administrator key is never allowed from outside.
    r = post(c, "/access/api-keys", {"name": "Ude", "scope": "admin", "expires_days": "90"})
    assert r.status_code == 400 and "hjemmenetværket" in r.get_json()["message"] and _rows(kenv) == []
    r = post(c, "/access/api-keys", {"name": "Ude", "scope": "control", "expires_days": "90"}, json_reply=False)
    assert r.status_code == 200
    tok = re.search(r"data-secret>(sf_[A-Za-z0-9_-]{43})<", body(r)).group(1)
    row, = _rows(kenv)
    assert (row["scope"], row["lan_only"]) == ("control", 0) and row["expires_at"] > time.time() + 89 * 86400
    assert "Læse og styre · også udefra · udløber" in body(r)
    assert _get(kenv, tok, environ=OUTSIDE).status_code == 200


@pytest.mark.parametrize("data,msg", [({"name": "", "scope": "read"}, "navn"),
                                      ({"name": "x", "scope": "root"}, "rettighed"),
                                      ({"name": "x", "scope": "read", "expires_days": "7"}, "udløber")])
def test_create_from_the_page_refuses_bad_input(kenv, data, msg):
    c = client_for(kenv, "admin")
    r = post(c, "/access/api-keys", data)
    assert r.status_code == 400 and msg in r.get_json()["message"].lower()
    assert _rows(kenv) == []
