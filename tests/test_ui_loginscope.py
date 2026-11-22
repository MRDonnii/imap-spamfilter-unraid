"""2.3 (owner request): per-user login scope "Overalt" / "Kun lokalt
(hjemmenetværket)".

Local = the DIRECT peer is in LOCAL_NETWORKS and the request did not come
through a proxy (a TRUSTED_PROXIES peer such as cloudflared is always
external; forwarding headers can only ever make a request external).
Enforced before the password (same reply + same pbkdf2 work), at the 2FA
step and on every request of an existing session (also "Husk mig").
"""

from __future__ import annotations

import re
import sqlite3

import pytest

from fakes_ui import TEST_PASSWORD, csrf_of, fast_hash, post
from fakes_ui_admin import make_admin_env

import dashboard  # noqa: E402
import ui_admin  # noqa: E402,F401 - registers the admin routes at collection time

PW = TEST_PASSWORD
LAN = "192.168.1.42"
OUTSIDE = "203.0.113.7"
TUNNEL = "192.168.1.10"          # cloudflared on the Unraid host (TRUSTED_PROXIES)
GENERIC = "Forkert brugernavn eller adgangskode."


def write_users(env, lines: list[str]) -> None:
    (env.state / "dashboard_users").write_text("\n".join(lines) + "\n")


@pytest.fixture
def env(tmp_path, monkeypatch):
    e = make_admin_env(tmp_path, monkeypatch)
    hp = fast_hash(PW)
    write_users(e, [f"admin:{hp}:admin:0", f"chef:{hp}:admin:0", f"anna:{hp}:bynet:0", f"lis:{hp}:bynet:0"])
    with e.app.test_request_context("/"):
        dashboard.set_login_scope("lis", "local", "test")
    monkeypatch.setattr(dashboard, "TRUSTED_PROXY_NETS", tuple(dashboard.parse_trusted_proxies(TUNNEL)[0]))
    monkeypatch.setattr(dashboard, "LOCAL_NETS", dashboard.LOCAL_NETS)
    return e


def client(env, ip: str = LAN, headers: dict | None = None):
    c = env.app.test_client()
    c.environ_base["REMOTE_ADDR"] = ip
    for k, v in (headers or {}).items():
        c.environ_base["HTTP_" + k.upper().replace("-", "_")] = v
    return c


def do_login(c, name: str, password: str = PW, **extra):
    c.get("/login")
    return c.post("/login", data={"username": name, "password": password, "csrf": csrf_of(c), **extra})


def audits(env, action: str) -> list[dict]:
    return [r for r in env.audit() if r["action"] == action]


# --------------------------------------------------------------------- what counts as local


@pytest.mark.parametrize("ip,headers,local", [
    ("192.168.1.42", {}, True), ("192.168.1.20", {}, True), ("172.18.0.5", {}, True), ("127.0.0.1", {}, True),
    ("::1", {}, True), ("fe80::1", {}, True), ("::ffff:192.168.1.9", {}, True),
    ("203.0.113.7", {}, False), ("2001:db8::1", {}, False),
    # The tunnel: always external, whatever its forwarded headers say.
    (TUNNEL, {}, False), (TUNNEL, {"X-Forwarded-For": "192.168.1.20"}, False),
    (TUNNEL, {"CF-Connecting-IP": "192.168.1.42"}, False),
    # Forwarding headers from an untrusted LAN peer (e.g. an untrusted proxy):
    # never MORE local, only external (fail closed).
    ("192.168.1.42", {"X-Forwarded-For": "192.168.1.42"}, False), ("172.18.0.2", {"Cf-Ray": "8a1b2c3d4e5f-CPH"}, False),
    ("172.18.0.2", {"CF-Connecting-IP": "192.168.1.5"}, False), ("192.168.1.42", {"Forwarded": "for=192.168.1.42"}, False),
    # A spoofed header from outside never makes it local.
    ("203.0.113.7", {"X-Forwarded-For": "192.168.1.20"}, False),
])
def test_request_is_local(env, ip, headers, local):
    environ = {"REMOTE_ADDR": ip}
    environ.update({"HTTP_" + k.upper().replace("-", "_"): v for k, v in headers.items()})
    with env.app.test_request_context("/", environ_base=environ):
        # The middleware sets sf.peer; emulate it like ProxyHeaders does.
        dashboard.request.environ["sf.peer"] = ip
        assert dashboard.request_is_local() is local


def test_local_networks_override(monkeypatch):
    try:
        dashboard.configure_local_networks("192.168.50.0/24")
        assert [str(n) for n in dashboard.LOCAL_NETS] == ["192.168.50.0/24"]
        dashboard.configure_local_networks("not-a-net")
        assert "10.0.0.0/8" in dashboard.LOCAL_NETWORKS_SPEC  # invalid -> the private ranges
    finally:
        dashboard.configure_local_networks("")


# --------------------------------------------------------------------- login


def test_local_only_user_logs_in_at_home(env):
    c = client(env, LAN)
    r = do_login(c, "lis")
    assert r.status_code == 302 and c.get("/").status_code == 200


@pytest.mark.parametrize("ip,headers", [(OUTSIDE, {}), (TUNNEL, {"X-Forwarded-For": "192.168.1.20"}),
                                        (TUNNEL, {"CF-Connecting-IP": LAN})])
def test_local_only_user_refused_from_outside_with_generic_error(env, ip, headers):
    c = client(env, ip, headers)
    r = do_login(c, "lis")
    assert r.status_code == 401 and GENERIC in r.get_data(as_text=True)
    assert c.get("/", headers={"Accept": "text/html"}).status_code == 302
    rec = audits(env, "login_blocked_external")
    assert rec and rec[-1]["actor"] == "lis" and rec[-1]["result"] == "blocked"
    # Same reply as a wrong password and as an unknown user (no oracle).
    wrong = do_login(client(env, ip, headers), "anna", "forkert-kode-123")
    unknown = do_login(client(env, ip, headers), "findes-ikke")
    assert wrong.status_code == unknown.status_code == r.status_code == 401
    norm = lambda resp: resp.get_data(as_text=True).replace("lis", "X").replace("anna", "X").replace("findes-ikke", "X")
    strip_csrf = lambda t: re.sub(r'(name="csrf" value|content)="[A-Za-z0-9_-]{30,}"', "", t)  # noqa: E731
    assert strip_csrf(norm(r)) == strip_csrf(norm(wrong)) == strip_csrf(norm(unknown))


def test_scope_checked_before_password_with_same_pbkdf2_work(env, monkeypatch):
    calls = []
    real = dashboard.verify_password
    monkeypatch.setattr(dashboard, "verify_password", lambda stored, pw: calls.append(stored) or real(stored, pw))
    do_login(client(env, OUTSIDE), "lis")              # blocked: only the dummy hash
    assert len(calls) == 1 and calls[0] == dashboard._DUMMY_VERIFIER
    calls.clear()
    do_login(client(env, OUTSIDE), "findes-ikke")      # unknown user: the same dummy work
    assert calls == [dashboard._DUMMY_VERIFIER]
    calls.clear()
    do_login(client(env, OUTSIDE), "anna", "forkert-kode-123")  # everywhere user: the real hash
    assert len(calls) == 1 and calls[0].startswith("pbkdf2$")
    # Even the RIGHT password of a local-only user is never verified from outside.
    calls.clear()
    r = do_login(client(env, OUTSIDE), "lis", PW)
    assert r.status_code == 401 and calls == [dashboard._DUMMY_VERIFIER]


def test_blocked_attempts_count_towards_the_lockout(env):
    c = client(env, OUTSIDE)
    for _ in range(dashboard.LOGIN_MAX_FAILURES):
        do_login(c, "lis")
    r = do_login(c, "lis")
    assert r.status_code == 429


def test_everywhere_user_unaffected(env):
    c = client(env, OUTSIDE)
    assert do_login(c, "anna").status_code == 302 and c.get("/").status_code == 200


def test_existing_session_logged_out_when_used_from_outside(env):
    c = client(env, LAN)
    assert do_login(c, "lis", remember="1").status_code == 302
    assert c.get("/").status_code == 200
    c.environ_base["REMOTE_ADDR"] = OUTSIDE      # same cookie ("Husk mig"), now from the tunnel/outside
    r = c.get("/", headers={"Accept": "text/html"})
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert audits(env, "login_blocked_external")[-1]["detail"].startswith("session")
    c.environ_base["REMOTE_ADDR"] = LAN          # the session is gone, also back home
    assert c.get("/", headers={"Accept": "text/html"}).status_code == 302
    # JSON clients get 401.
    c2 = client(env, LAN)
    do_login(c2, "lis")
    c2.environ_base["REMOTE_ADDR"] = TUNNEL
    r = c2.get("/api/status", headers={"Accept": "application/json", "X-Requested-With": "fetch"})
    assert r.status_code == 401


def test_scope_change_applies_to_running_sessions(env):
    c = client(env, OUTSIDE)
    assert do_login(c, "anna").status_code == 302
    with env.app.test_request_context("/"):
        dashboard.set_login_scope("anna", "local", "test")
    assert c.get("/", headers={"Accept": "text/html"}).status_code == 302


def test_two_step_login_step_is_enforced(env):
    with env.app.test_request_context("/"):
        dashboard.twofa_confirm("lis", dashboard.totp(dashboard.twofa_pending_secret("lis") or ""), "test")
    c = client(env, LAN)
    r = do_login(c, "lis")
    assert r.status_code == 302 and "/login/2fa" in r.headers["Location"]
    c.environ_base["REMOTE_ADDR"] = OUTSIDE       # the code is typed from outside
    secret = sqlite3.connect(env.state / "spamfilter.db").execute(
        "SELECT secret FROM ui_twofa WHERE name='lis'").fetchone()[0]
    code = dashboard.totp(secret)
    r = c.post("/login/2fa", data={"code": code, "csrf": csrf_of(c)})
    assert r.status_code == 302 and "/login" in r.headers["Location"] and "2fa" not in r.headers["Location"]
    assert c.get("/", headers={"Accept": "text/html"}).status_code == 302
    assert any(x["detail"].startswith("to-trins") for x in audits(env, "login_blocked_external"))


def test_unreadable_scope_table_fails_closed(env, monkeypatch):
    def broken():
        raise sqlite3.OperationalError("disk I/O error")
    monkeypatch.setattr(dashboard, "_connect", broken)
    with env.app.test_request_context("/"):
        assert dashboard.login_scope("anna") == "local"


# --------------------------------------------------------------------- Brugere UI


def admin_client(env):
    c = client(env, LAN)
    assert do_login(c, "admin").status_code == 302
    return c


def test_users_page_badge_and_kv(env):
    html = admin_client(env).get("/users").get_data(as_text=True)
    assert "Kun lokalt" in html and "scope-badge" in html and "Må logge ind" in html
    card = html.split('data-row="user:lis"')[1].split("</article>")[0]
    assert "Kun lokalt" in card
    anna = html.split('data-row="user:anna"')[1].split("</article>")[0]
    assert "Kun lokalt" not in anna and "Overalt" in anna


def test_create_user_local_only(env):
    c = admin_client(env)
    form = c.get("/users/new").get_data(as_text=True)
    assert 'name="login_scope"' in form and "Kun lokalt (hjemmenetværket)" in form
    r = post(c, "/users/new", {"name": "kim", "password": "x" * 14, "password2": "x" * 14, "role": "user",
                               "acct:bynet": "1", "login_scope": "local"})
    assert r.get_json()["ok"]
    with env.app.test_request_context("/"):
        assert dashboard.login_scope("kim") == "local"
    assert "login=lokalt" in [x for x in env.audit() if x["action"] == "user_add"][-1]["detail"]


def test_edit_user_scope_and_audit(env):
    c = admin_client(env)
    page = c.get("/users/anna").get_data(as_text=True)
    assert 'name="login_scope"' in page
    r = post(c, "/users/anna", {"role": "user", "acct:bynet": "1", "perm:release": "1", "perm:rules": "1",
                                "perm:see_messages": "1", "login_scope": "local"})
    data = r.get_json()
    assert data["ok"] and "kun logge ind lokalt" in data["message"]
    assert audits(env, "user_login_scope")[-1]["detail"] == "anna everywhere -> local"
    assert not audits(env, "user_access")  # access itself unchanged
    r = post(c, "/users/anna", {"role": "user", "acct:bynet": "1", "perm:release": "1", "perm:rules": "1",
                                "perm:see_messages": "1", "login_scope": "local"})
    assert "uændret" in r.get_json()["message"]
    # A form without the field (old page) keeps the scope.
    post(c, "/users/anna", {"role": "user", "acct:bynet": "1", "perm:release": "1"})
    with env.app.test_request_context("/"):
        assert dashboard.login_scope("anna") == "local"


def test_admin_cannot_lock_himself_out_from_outside(env):
    c = client(env, OUTSIDE)
    assert do_login(c, "admin").status_code == 302
    r = post(c, "/users/admin", {"role": "admin", "login_scope": "local"})
    assert not r.get_json()["ok"] and "hjemmenetværket" in r.get_json()["message"]
    with env.app.test_request_context("/"):
        assert dashboard.login_scope("admin") == "everywhere"
    assert c.get("/").status_code == 200


def test_warning_when_every_admin_is_local_only(env):
    c = admin_client(env)
    post(c, "/users/chef", {"role": "admin", "login_scope": "local"})
    assert "Ingen administrator kan logge ind udefra" not in c.get("/users").get_data(as_text=True)
    r = post(c, "/users/admin", {"role": "admin", "login_scope": "local"})
    assert r.get_json()["ok"] and "ingen administrator" in r.get_json()["message"].lower()  # warned, not blocked
    html = c.get("/users").get_data(as_text=True)
    assert "Ingen administrator kan logge ind udefra" in html
    with env.app.test_request_context("/"):
        assert dashboard.admins_all_local()


def test_scope_forgotten_on_removal(env):
    c = admin_client(env)
    post(c, "/users/lis/remove", {"confirm": "lis"})
    with env.app.test_request_context("/"):
        assert dashboard.all_login_scopes() == {}


def test_scope_route_permissions(env):
    """Only administrators can change it (the users routes are admin-only)."""
    c = client(env, LAN)
    assert do_login(c, "anna").status_code == 302
    r = post(c, "/users/anna", {"role": "user", "login_scope": "local"})
    assert r.status_code == 403
    with env.app.test_request_context("/"):
        assert dashboard.login_scope("anna") == "everywhere"
    anon = client(env, LAN)
    assert post(anon, "/users/lis", {"login_scope": "everywhere"}).status_code == 401


def test_connection_card_shows_home_network(env):
    c = admin_client(env)
    assert "“Kun lokalt”-brugere kan logge ind herfra" in c.get("/settings").get_data(as_text=True)


def test_rollback_safe_storage(env):
    """A new table only: 2.2.0 code (ui_users) is untouched."""
    conn = sqlite3.connect(env.state / "spamfilter.db")
    cols = [r[1] for r in conn.execute("PRAGMA table_info(ui_users)")]
    assert cols == ["name", "perms", "last_login_at", "last_login_ip", "updated_at", "updated_by"]
    assert conn.execute("SELECT name, scope FROM ui_login_scope").fetchall() == [("lis", "local")]
