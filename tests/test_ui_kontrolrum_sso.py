"""2.9.0 (owner request "option A"): single sign-on from Kontrolrum.

POST /login/kontrolrum takes {v, aud, sub, iat, exp, nonce, sig} with
sig = hex HMAC-SHA256(key, "kontrolrum-sso\\n{v}\\n{aud}\\n{sub}\\n{iat}\\n{exp}\\n{nonce}")
- the same handshake as FleetDeck. Only from the configured Kontrolrum IP
(exact, no default, never a trusted proxy) without forwarding headers, only
for users with the checkbox. The session it makes counts for a "Kun lokalt"
user only while requests come from that same Kontrolrum peer.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import sqlite3
import time
from contextlib import closing

import pytest

from fakes_ui import TEST_PASSWORD, csrf_of, fast_hash, post
from fakes_ui_admin import make_admin_env

import dashboard  # noqa: E402
import ui_admin  # noqa: E402,F401 - registers the admin routes (and ui_kontrolrum)

PW = TEST_PASSWORD
KR = "172.31.250.2"            # Kontrolrum's container on its Docker bridge
LAN = "192.168.1.42"
OUTSIDE = "203.0.113.7"
TUNNEL = "192.168.1.10"           # cloudflared (TRUSTED_PROXIES)
URL = "/login/kontrolrum"
COOKIE = "spamfilter_session"
CF = {"Cf-Ray": "8a1b2c3d4e5f-CPH", "Cf-Visitor": '{"scheme":"https"}'}


@pytest.fixture
def env(tmp_path, monkeypatch):
    e = make_admin_env(tmp_path, monkeypatch)
    hp = fast_hash(PW)
    (e.state / "dashboard_users").write_text(
        "\n".join([f"admin:{hp}:admin:0", f"kontrolrum:{hp}:admin:0", f"anna:{hp}:bynet:0", f"lis:{hp}:bynet:0"])
        + "\n")
    monkeypatch.setattr(dashboard, "TRUSTED_PROXY_NETS", tuple(dashboard.parse_trusted_proxies(TUNNEL)[0]))
    with e.app.test_request_context("/"):
        dashboard.set_login_scope("kontrolrum", "local", "test")
        dashboard.set_login_scope("lis", "local", "test")
        e.key = dashboard.kr_sso_create("test")
        dashboard.set_kr_sso_peers([KR], "test")
        dashboard.set_kr_sso_allowed("kontrolrum", True, "test")
    return e


def client(env, ip: str = KR, headers: dict | None = None):
    c = env.app.test_client()
    c.environ_base["REMOTE_ADDR"] = ip
    for k, v in (headers or {}).items():
        c.environ_base["HTTP_" + k.upper().replace("-", "_")] = v
    return c


def assertion(key: str, sub: str = "kontrolrum", *, aud: str = "spamfilter", iat: int | None = None,
              exp: int | None = None, nonce: str | None = None, v: int = 1) -> dict:
    iat = int(time.time()) if iat is None else iat
    a = {"v": v, "aud": aud, "sub": sub, "iat": iat, "exp": iat + 60 if exp is None else exp,
         "nonce": nonce or secrets.token_hex(16)}
    text = "\n".join(["kontrolrum-sso", str(a["v"]), a["aud"], a["sub"], str(a["iat"]), str(a["exp"]), a["nonce"]])
    a["sig"] = hmac.new(key.encode(), text.encode(), hashlib.sha256).hexdigest()
    return a


def sso(c, a: dict):
    return c.post(URL, json=a)


def audits(env, action: str) -> list[dict]:
    return [r for r in env.audit() if r["action"] == action]


def html(c, path: str = "/"):
    return c.get(path, headers={"Accept": "text/html"})


# --------------------------------------------------------------------- the handshake


def test_signature_matches_kontrolrum_and_fleetdeck_vector():
    """The same vector is in Kontrolrum's test/sso.test.js (ssoAssertion)."""
    a = {"v": 1, "aud": "spamfilter", "sub": "kontrolrum", "iat": 1763467200, "exp": 1763467260,
         "nonce": "0123456789abcdef0123456789abcdef"}
    assert dashboard.kr_sso_text(a) == ("kontrolrum-sso\n1\nspamfilter\nkontrolrum\n1763467200\n1763467260\n"
                                        "0123456789abcdef0123456789abcdef")
    assert dashboard.kr_sso_sign("a" * 64, a) == "9e6d928dae13f90eb74f31e10d25ca48ad62010392610a65d60e9c7c0a20662e"


def test_valid_assertion_logs_in_and_works_through_the_tunnel(env):
    c = client(env)
    r = sso(c, assertion(env.key))
    assert r.status_code == 200 and r.get_json() == {"ok": True, "user": "kontrolrum"}
    assert c.get_cookie(COOKIE) is not None
    # Kontrolrum relays a browser request that came in through its own
    # Cloudflare tunnel: CF headers present, peer = Kontrolrum. The local-only
    # user is allowed because the session came from Kontrolrum.
    c.environ_base.update({"HTTP_CF_RAY": CF["Cf-Ray"], "HTTP_CF_VISITOR": CF["Cf-Visitor"]})
    assert html(c).status_code == 200
    assert html(c, "/settings").status_code == 200
    rec = audits(env, "login_kontrolrum")
    assert rec and rec[-1]["result"] == "ok" and rec[-1]["actor"] == "kontrolrum" and KR in rec[-1]["detail"]
    with closing(sqlite3.connect(env.state / "spamfilter.db")) as conn:
        method, label = conn.execute("SELECT method, label FROM ui_login_history WHERE name='kontrolrum'").fetchone()
    assert (method, label) == ("kontrolrum", "Kontrolrum")
    with env.app.test_request_context("/"):
        st = dashboard.kr_sso_status()
    assert st["last_used_ip"] == KR and st["last_used_user"] == "kontrolrum"


def test_bad_signature(env):
    a = assertion(env.key)
    a["sig"] = ("0" if a["sig"][0] != "0" else "1") + a["sig"][1:]
    r = sso(client(env), a)
    assert r.status_code == 401 and r.get_json() == {"error": "bad_signature"}
    assert client(env).get_cookie(COOKIE) is None
    assert audits(env, "login_kontrolrum")[-1]["result"] == "failed"
    # A key that is not the current one (e.g. the old key after "Ny nøgle").
    r = sso(client(env), assertion(secrets.token_hex(32)))
    assert r.get_json() == {"error": "bad_signature"}


def test_wrong_audience(env):
    r = sso(client(env), assertion(env.key, aud="fleetdeck"))
    assert r.status_code == 401 and r.get_json() == {"error": "bad_audience"}


def test_wrong_version(env):
    r = sso(client(env), assertion(env.key, v=2))
    assert r.status_code == 401 and r.get_json() == {"error": "bad_version"}


@pytest.mark.parametrize("iat_delta,life", [
    (-200, 60),        # long gone
    (0, 121),          # lives longer than 120 s
    (120, 60),         # issued too far in the future (skew 60 s)
    (0, -1),           # exp before iat
])
def test_expired_or_bad_times(env, iat_delta, life):
    now = int(time.time())
    r = sso(client(env), assertion(env.key, iat=now + iat_delta, exp=now + iat_delta + life))
    assert r.status_code == 401 and r.get_json() == {"error": "expired"}


def test_clock_skew_is_tolerated(env):
    now = int(time.time())
    assert sso(client(env), assertion(env.key, iat=now + 30, exp=now + 90)).status_code == 200
    assert sso(client(env), assertion(env.key, iat=now - 100, exp=now - 10)).status_code == 200


def test_replay_is_refused(env):
    a = assertion(env.key)
    assert sso(client(env), a).status_code == 200
    r = sso(client(env), a)
    assert r.status_code == 401 and r.get_json() == {"error": "replay"}
    # The nonce is persisted (survives a restart = another process).
    with closing(sqlite3.connect(env.state / "spamfilter.db")) as conn:
        assert conn.execute("SELECT COUNT(*) FROM ui_sso_nonces WHERE nonce=?", (a["nonce"],)).fetchone()[0] == 1


@pytest.mark.parametrize("field,value", [("nonce", "kort"), ("nonce", "x" * 49), ("nonce", "ab cd" * 4),
                                         ("sig", "zz"), ("sub", ""), ("iat", "123"), ("v", True)])
def test_malformed(env, field, value):
    a = assertion(env.key)
    a[field] = value
    r = sso(client(env), a)
    assert r.status_code == 400 and r.get_json() == {"error": "bad_request"}


def test_not_json(env):
    r = client(env).post(URL, data={"sub": "kontrolrum"})
    assert r.status_code == 400


def test_disabled(env):
    with env.app.test_request_context("/"):
        assert dashboard.kr_sso_disable("test") is True
    r = sso(client(env), assertion(env.key))
    assert r.status_code == 403 and r.get_json() == {"error": "sso_disabled"}


def test_unreadable_key_counts_as_disabled(env, monkeypatch):
    monkeypatch.setattr(dashboard.app, "secret_key", "another-secret")
    r = sso(client(env), assertion(env.key))
    assert r.status_code == 403 and r.get_json() == {"error": "sso_disabled"}


def test_key_is_stored_encrypted(env):
    raw = (env.state / "spamfilter.db").read_bytes()
    assert env.key.encode() not in raw
    with env.app.test_request_context("/"):
        assert dashboard.kr_sso_key() == env.key


def test_user_not_opted_in(env):
    r = sso(client(env), assertion(env.key, sub="anna"))
    assert r.status_code == 401 and r.get_json() == {"error": "unknown_user"}
    r = sso(client(env), assertion(env.key, sub="findes-ikke"))
    assert r.status_code == 401 and r.get_json() == {"error": "unknown_user"}
    with env.app.test_request_context("/"):
        dashboard.set_kr_sso_allowed("kontrolrum", False, "test")
    assert sso(client(env), assertion(env.key)).get_json() == {"error": "unknown_user"}


@pytest.mark.parametrize("ip", [LAN, OUTSIDE, "172.31.250.3", "127.0.0.1"])
def test_wrong_peer_gets_a_plain_404(env, ip):
    r = sso(client(env, ip), assertion(env.key))
    assert r.status_code == 404 and r.get_json(silent=True) is None
    rec = audits(env, "login_kontrolrum")[-1]
    assert rec["result"] == "failed" and ip in rec["detail"]
    with env.app.test_request_context("/"):
        st = dashboard.kr_sso_status()
    assert st["rejected_ip"] == ip and st["rejected_reason"] == "wrong_peer"


def test_no_peer_configured_means_off(env):
    with env.app.test_request_context("/"):
        dashboard.set_kr_sso_peers([], "test")
    assert sso(client(env), assertion(env.key)).status_code == 404


def test_tunnel_never_counts_as_kontrolrum(env):
    # Even when the cloudflared address is stored (e.g. TRUSTED_PROXIES changed
    # afterwards), a request from it is refused: it can be anybody.
    with env.app.test_request_context("/"):
        dashboard.set_kr_sso_peers([KR, TUNNEL], "test")
        assert dashboard.kr_sso_peers() == [KR]
    r = sso(client(env, TUNNEL, {"CF-Connecting-IP": KR}), assertion(env.key))
    assert r.status_code == 404


@pytest.mark.parametrize("headers", [{"X-Forwarded-For": "203.0.113.7"}, {"CF-Connecting-IP": "203.0.113.7"}, CF,
                                     {"Forwarded": "for=203.0.113.7"}, {"X-Real-IP": "203.0.113.7"}])
def test_forwarded_request_from_kontrolrum_is_refused(env, headers):
    """A browser request relayed by Kontrolrum's proxy never reaches the handshake."""
    r = sso(client(env, KR, headers), assertion(env.key))
    assert r.status_code == 404
    assert audits(env, "login_kontrolrum")[-1]["detail"].startswith("kom gennem en proxy")


def test_rate_limit(env):
    c = client(env)
    for _ in range(dashboard.KR_SSO_RATE):
        assert sso(c, assertion(env.key, sub="anna")).status_code == 401
    r = sso(c, assertion(env.key))
    assert r.status_code == 429 and r.get_json() == {"error": "rate_limited"} and r.headers["Retry-After"]
    assert sso(c, assertion(env.key)).status_code == 429
    # One audit line for the limit, not one per request.
    assert len([x for x in audits(env, "login_kontrolrum") if "for mange" in x.get("detail", "")]) == 1
    # Other peers have their own counter (the tunnel cannot lock Kontrolrum out).
    for _ in range(dashboard.KR_SSO_RATE + 2):
        sso(client(env, OUTSIDE), assertion(env.key))
    assert sso(client(env, "172.31.250.9"), assertion(env.key)).status_code == 404


def test_csrf_exempt_but_other_posts_are_not(env):
    assert "login_kontrolrum" in dashboard._CSRF_EXEMPT
    assert dashboard.route_policy("login_kontrolrum") == dashboard.POLICY_PUBLIC


# --------------------------------------------------------------------- the session


def kr_session(env):
    c = client(env)
    assert sso(c, assertion(env.key)).status_code == 200
    return c


def steal(env, c, ip: str, headers: dict | None = None):
    thief = client(env, ip, headers)
    thief.set_cookie(COOKIE, c.get_cookie(COOKIE).value)
    return thief


@pytest.mark.parametrize("ip,headers", [
    (TUNNEL, {"CF-Connecting-IP": OUTSIDE, **CF}),   # spamfilter.example.org directly
    (LAN, {}),                                        # even from the home network
    (OUTSIDE, {}),
    ("172.31.250.3", {}),                             # a neighbour on Kontrolrum's bridge
])
def test_copied_cookie_from_another_peer_is_rejected(env, ip, headers):
    c = kr_session(env)
    thief = steal(env, c, ip, headers)
    r = html(thief)
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    rec = audits(env, "login_kontrolrum")[-1]
    assert rec["result"] == "blocked" and rec["detail"].startswith("session afvist")
    # JSON too.
    thief = steal(env, c, ip, headers)
    r = thief.get("/api/status", headers={"Accept": "application/json", "X-Requested-With": "fetch"})
    assert r.status_code == 401
    # Kontrolrum itself is unaffected.
    assert html(c).status_code == 200


def test_copied_cookie_of_an_everywhere_user_is_also_bound(env):
    with env.app.test_request_context("/"):
        dashboard.set_kr_sso_allowed("anna", True, "test")
    c = client(env)
    assert sso(c, assertion(env.key, sub="anna")).status_code == 200
    assert html(steal(env, c, OUTSIDE)).status_code == 302


@pytest.mark.parametrize("change", ["new_key", "off", "untick", "peer_removed", "password"])
def test_session_ends_when_sso_changes(env, change):
    c = kr_session(env)
    assert html(c).status_code == 200
    with env.app.test_request_context("/"):
        if change == "new_key":
            dashboard.kr_sso_create("test")
        elif change == "off":
            dashboard.kr_sso_disable("test")
        elif change == "untick":
            dashboard.set_kr_sso_allowed("kontrolrum", False, "test")
        elif change == "peer_removed":
            dashboard.set_kr_sso_peers(["172.31.250.7"], "test")
        else:
            dashboard.bump_generation("kontrolrum")   # "Log ud overalt" / new password
    assert html(c).status_code == 302


def test_password_login_of_local_only_user_still_refused_through_kontrolrum(env):
    """The password of a 'Kun lokalt' user keeps working only at home: a
    browser login relayed by Kontrolrum from the tunnel (CF headers) fails."""
    c = client(env, KR, CF)
    c.get("/login")
    r = c.post("/login", data={"username": "kontrolrum", "password": PW, "csrf": csrf_of(c)})
    assert r.status_code == 401
    assert audits(env, "login_blocked_external")


def test_normal_session_is_not_upgraded_by_the_kontrolrum_peer(env):
    """Only an SSO session gets the exception, not a password session that
    happens to be relayed by Kontrolrum."""
    c = client(env, KR)
    c.get("/login")
    assert c.post("/login", data={"username": "lis", "password": PW, "csrf": csrf_of(c)}).status_code == 302
    c.environ_base.update({"HTTP_CF_RAY": CF["Cf-Ray"]})
    assert html(c).status_code == 302


def test_two_step_login_is_satisfied_by_sso(env):
    with env.app.test_request_context("/"):
        dashboard.twofa_confirm("kontrolrum", dashboard.totp(dashboard.twofa_pending_secret("kontrolrum") or ""),
                                "test")
        dashboard.twofa_set_required("kontrolrum", True, "test")
    c = kr_session(env)
    assert html(c).status_code == 200


def test_required_2fa_setup_does_not_block_sso(env):
    with env.app.test_request_context("/"):
        dashboard.twofa_set_required("kontrolrum", True, "test")
    assert html(kr_session(env)).status_code == 200


def test_first_kontrolrum_login_alerts_like_a_new_device_then_not_again(env, monkeypatch):
    import login_alerts

    sent = []
    monkeypatch.setattr(login_alerts, "_notify_new_device", lambda *a, **k: sent.append(a))
    c = client(env, LAN)
    c.get("/login")
    c.post("/login", data={"username": "kontrolrum", "password": PW, "csrf": csrf_of(c)})   # a known device
    kr_session(env)
    kr_session(env)
    assert len(sent) == 1 and sent[0][1] == "Kontrolrum"


# --------------------------------------------------------------------- Indstillinger + Brugere


def admin_client(env):
    c = client(env, LAN)
    c.get("/login")
    assert c.post("/login", data={"username": "admin", "password": PW, "csrf": csrf_of(c)}).status_code == 302
    return c


def test_settings_card_and_key_shown_once(env):
    c = admin_client(env)
    page = html(c, "/access").get_data(as_text=True)
    assert 'id="kontrolrum"' in page and "Slået til" in page and env.key not in page
    assert dashboard.kr_sso_fingerprint(env.key) in page and KR in page
    r = c.post("/settings/kontrolrum/key", data={"csrf": csrf_of(c)})
    body = r.get_data(as_text=True)
    new = re.search(r"data-secret>([0-9a-f]{64})<", body).group(1)
    assert new != env.key and "vises kun denne ene gang" in body
    assert new not in html(c, "/access").get_data(as_text=True)
    assert audits(env, "kontrolrum_sso_key")[-1]["detail"].startswith("ny nøgle (erstattede")
    # The old key no longer works, the new one does.
    assert sso(client(env), assertion(env.key)).status_code == 401
    assert sso(client(env), assertion(new)).status_code == 200


def test_settings_turn_off(env):
    c = admin_client(env)
    r = post(c, "/settings/kontrolrum/off")
    assert r.status_code == 200 and r.get_json()["ok"]
    assert audits(env, "kontrolrum_sso_off")
    assert "Slået fra" in html(c, "/access").get_data(as_text=True)
    assert sso(client(env), assertion(env.key)).status_code == 403


@pytest.mark.parametrize("value,ok", [("172.31.250.0/24", False), ("kontrolrum.home", False), (TUNNEL, False),
                                      ("192.168.1.28, 172.31.250.2", True), ("", True)])
def test_settings_peers(env, value, ok):
    c = admin_client(env)
    r = post(c, "/settings/kontrolrum/peers", {"kontrolrum_ips": value})
    assert bool(r.get_json()["ok"]) is ok
    with env.app.test_request_context("/"):
        peers = dashboard.kr_sso_peers_configured()
    if ok:
        assert peers == [p.strip() for p in value.split(",") if p.strip()]
        assert audits(env, "kontrolrum_sso_peers")
    else:
        assert peers == [KR]


def test_settings_need_an_admin(env):
    with env.app.test_request_context("/"):
        dashboard.set_login_scope("anna", "everywhere", "test")
    c = client(env, LAN)
    c.get("/login")
    c.post("/login", data={"username": "anna", "password": PW, "csrf": csrf_of(c)})
    for url in ("/settings/kontrolrum/key", "/settings/kontrolrum/off", "/settings/kontrolrum/peers",
                "/users/anna/kontrolrum"):
        assert post(c, url, {"kontrolrum_sso": "1"}).status_code == 403
    assert sso(client(env), assertion(env.key, sub="anna")).status_code == 401


def test_user_checkbox(env):
    c = admin_client(env)
    page = html(c, "/users/anna").get_data(as_text=True)
    assert "Må logges ind fra Kontrolrum" in page
    r = post(c, "/users/anna/kontrolrum", {"kontrolrum_sso": "1"})
    assert r.get_json()["ok"]
    with env.app.test_request_context("/"):
        assert dashboard.kr_sso_allowed("anna")
    assert audits(env, "user_kontrolrum_sso")[-1]["detail"] == "anna til"
    assert sso(client(env), assertion(env.key, sub="anna")).status_code == 200
    post(c, "/users/anna/kontrolrum", {})
    with env.app.test_request_context("/"):
        assert not dashboard.kr_sso_allowed("anna")
    assert post(c, "/users/findes-ikke/kontrolrum", {"kontrolrum_sso": "1"}).get_json()["ok"] is False


def test_removed_user_loses_the_checkbox(env):
    with env.app.test_request_context("/"):
        dashboard.set_kr_sso_allowed("anna", True, "test")
        dashboard.forget_user_meta("anna")
        assert not dashboard.kr_sso_allowed("anna")


@pytest.mark.parametrize("method", ["GET", "PUT", "PATCH", "DELETE", "OPTIONS"])
def test_other_methods_are_a_plain_404(env, method):
    assert client(env).open(URL, method=method).status_code == 404
