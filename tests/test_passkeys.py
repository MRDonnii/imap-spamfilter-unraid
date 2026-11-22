"""2.6 (B1): passkeys - Min konto (register/remove with re-auth), the
passkey login (discoverable, user verification = password + 2FA), the
secure-context rules (external https address, localhost; hidden on the
plain-http LAN address), login scope, throttling, single-use challenges,
"Husk mig", removal of a user and sfctl passkeys / passkeys-reset / doctor.

The browser side is the software authenticator in tests/fakes_webauthn.py.
"""

from __future__ import annotations

import json
import time

import pytest

from fakes_ui import TEST_PASSWORD, fast_hash
from fakes_ui_admin import make_admin_env
from fakes_webauthn import UP, SoftAuthenticator

import dashboard  # noqa: E402
import passkeys  # noqa: E402
import ui_admin  # noqa: E402,F401
from test_ui_core import INLINE_PATTERNS  # noqa: E402

PW = TEST_PASSWORD
EXT = "https://spam.example.dk"
LAN_URL = "http://192.168.1.10:18080"
OUTSIDE = "203.0.113.7"
LAN = "192.168.1.42"


@pytest.fixture
def env(tmp_path, monkeypatch):
    e = make_admin_env(tmp_path, monkeypatch)
    h = fast_hash(PW)
    (e.state / "dashboard_users").write_text("\n".join([
        f"admin:{h}:admin:0", f"anna:{h}:bynet:0", f"lis:{h}:bynet:0"]) + "\n")
    dashboard.settings_set("external_url", EXT)
    return e


def body(r) -> str:
    return r.get_data().decode("utf-8", "replace")


def client(env, ip: str = OUTSIDE):
    c = env.app.test_client()
    c.environ_base["REMOTE_ADDR"] = ip
    return c


def csrf_of(c, base: str = EXT) -> str:
    with c.session_transaction(base_url=base) as s:
        return s.get("csrf", "")


def jpost(c, url: str, payload: dict | None = None, base: str = EXT):
    return c.post(url, json=payload or {}, base_url=base,
                  headers={"X-CSRF-Token": csrf_of(c, base), "Accept": "application/json", "X-Requested-With": "fetch"})


def form_post(c, url: str, data: dict | None = None, base: str = EXT):
    return c.post(url, data={**(data or {}), "csrf": csrf_of(c, base)}, base_url=base)


def pw_login(c, name: str, base: str = EXT, password: str = PW):
    c.get("/login", base_url=base)
    return c.post("/login", data={"username": name, "password": password, "csrf": csrf_of(c, base)},
                  base_url=base)


def enroll(c, auth: SoftAuthenticator, label: str = "Annas iPhone", **create_kw):
    opts = jpost(c, "/me/passkeys/options")
    assert opts.status_code == 200, body(opts)
    cred = auth.create(opts.get_json(), **create_kw)
    cred["label"] = label
    return jpost(c, "/me/passkeys/register", cred)


def pk_login(c, auth: SoftAuthenticator, *, remember: bool = False, nxt: str = "/spam", base: str = EXT, **get_kw):
    c.get("/login", base_url=base)
    opts = jpost(c, "/login/passkey/options", base=base)
    assert opts.status_code == 200, body(opts)
    cred = auth.get(opts.get_json(), **get_kw)
    cred["remember"] = remember
    return jpost(c, f"/login/passkey?next={nxt}", cred, base=base)


def enrolled(env, name: str = "anna", label: str = "Annas iPhone"):
    c = client(env)
    assert pw_login(c, name).status_code == 302
    auth = SoftAuthenticator()
    r = enroll(c, auth, label)
    assert r.status_code == 200 and r.get_json()["ok"], body(r)
    return auth


def rows(env, name: str | None = None):
    sql = "SELECT * FROM ui_passkeys" + (" WHERE name=?" if name else "")
    return env.conn.execute(sql, (name,) if name else ()).fetchall()


def audits(env, action: str) -> list[dict]:
    return [a for a in env.audit() if a["action"] == action]


def stale_reauth(c, name: str) -> None:
    with c.session_transaction(base_url=EXT) as s:
        for key in ("reauth_pw", "reauth_2fa"):
            if key in s:
                s[key] = [name, int(time.time()) - passkeys.REAUTH_TTL - 5]


# --------------------------------------------------------------------- register + login


def test_register_and_log_in_with_a_passkey(env):
    auth = enrolled(env)
    (row,) = rows(env, "anna")
    assert row["rp_id"] == "spam.example.dk" and row["label"] == "Annas iPhone" and row["alg"] == -7
    assert row["transports"] == "internal,hybrid"          # unknown transports dropped
    assert row["backup_eligible"] == 1 and row["sign_count"] == 0
    handle = env.conn.execute("SELECT handle FROM ui_passkey_handles WHERE name='anna'").fetchone()[0]
    assert row["user_handle"] == handle and "anna" not in handle
    add = audits(env, "passkey_add")[-1]
    assert add["actor"] == "anna" and "Annas iPhone" in add["detail"] and row["cred_id"] not in json.dumps(add)
    c = client(env)
    r = pk_login(c, auth)
    assert r.status_code == 200 and r.get_json() == {"ok": True, "redirect": "/spam"}
    with c.session_transaction(base_url=EXT) as s:
        assert s["u"] == "anna" and s.get("mfa") == 1 and "rm" not in s and "pk_login" not in s
    assert c.get("/", base_url=EXT).status_code == 200
    rec = [a for a in audits(env, "login") if a["result"] == "ok"][-1]
    assert rec["actor"] == "anna" and rec["detail"] == "passkey"
    row = rows(env, "anna")[0]
    assert row["sign_count"] == 1 and row["last_used_at"] and row["last_used_ip"] == OUTSIDE


@pytest.mark.parametrize("alg", [-7, -257])
def test_both_algorithms(env, alg):
    c = client(env)
    pw_login(c, "anna")
    auth = SoftAuthenticator(alg=alg)
    assert enroll(c, auth).get_json()["ok"]
    assert pk_login(client(env), auth).get_json()["ok"]


def test_passkey_counts_as_password_and_second_factor(env):
    auth = enrolled(env)
    with env.app.test_request_context("/"):
        secret = dashboard.twofa_pending_secret("anna")
        assert dashboard.twofa_confirm("anna", dashboard.totp(secret), actor="test")
    c = client(env)
    assert pk_login(c, auth).get_json()["ok"]
    r = c.get("/", base_url=EXT)
    assert r.status_code == 200              # no /login/2fa step-up
    with c.session_transaction(base_url=EXT) as s:
        assert s.get("mfa") == 1 and s["reauth_2fa"][0] == "anna"


def test_remember_me(env):
    auth = enrolled(env)
    c = client(env)
    assert pk_login(c, auth, remember=True).get_json()["ok"]
    with c.session_transaction(base_url=EXT) as s:
        assert s.get("rm") == 1


def test_session_is_fresh_and_generation_bound(env):
    auth = enrolled(env)
    c = client(env)
    c.get("/login", base_url=EXT)
    old = csrf_of(c)
    assert pk_login(c, auth).get_json()["ok"]
    assert csrf_of(c) and csrf_of(c) != old            # new session, new CSRF token
    # "Log ud overalt" (generation bump) ends the passkey session too.
    with env.app.test_request_context("/"):
        dashboard.bump_generation("anna")
    assert c.get("/", base_url=EXT, headers={"Accept": "text/html"}).status_code == 302


def test_safe_next_only(env):
    auth = enrolled(env)
    r = pk_login(client(env), auth, nxt="//evil.example")
    assert r.get_json()["redirect"] == "/"


# --------------------------------------------------------------------- failures


def test_tampered_signature_wrong_origin_and_wrong_user_handle_fail(env):
    auth = enrolled(env)
    for kw in ({"tamper": True}, {"origin": "https://evil.example"}, {"user_handle": b"x" * 32},
               {"flags": UP}, {"rp_id": "evil.example"}):
        c = client(env)
        r = pk_login(c, auth, **kw)
        assert r.status_code == 401 and r.get_json()["ok"] is False, kw
        with c.session_transaction(base_url=EXT) as s:
            assert "u" not in s
    details = [a.get("detail") for a in audits(env, "login") if a["result"] == "failed"]
    assert {"passkey · signature", "passkey · origin", "passkey · user_handle", "passkey · user_verified",
            "passkey · rp_id"} <= set(details)


def test_unknown_credential(env):
    auth = enrolled(env)
    stranger = SoftAuthenticator()
    stranger.user_handle = auth.user_handle
    r = pk_login(client(env), stranger)
    data = r.get_json()
    assert r.status_code == 401 and data["code"] == "unknown" and data["rp"] == "spam.example.dk"


def test_counter_replay_is_refused(env):
    auth = enrolled(env)
    assert pk_login(client(env), auth).get_json()["ok"]
    r = pk_login(client(env), auth, count=1)            # the same counter value again
    assert r.status_code == 401
    assert "passkey · counter" in [a.get("detail") for a in audits(env, "login")]


def test_challenge_is_single_use_and_expires(env):
    auth = enrolled(env)
    c = client(env)
    c.get("/login", base_url=EXT)
    opts = jpost(c, "/login/passkey/options").get_json()
    with c.session_transaction(base_url=EXT) as s:
        saved = s["pk_login"]
    cred = auth.get(opts)
    assert jpost(c, "/login/passkey", cred).get_json()["ok"]
    # Replay: an attacker restores the old (client-side) session with the challenge.
    c2 = client(env)
    c2.get("/login", base_url=EXT)
    with c2.session_transaction(base_url=EXT) as s:
        s["pk_login"] = saved
    auth.sign_count += 5                                 # even with a "good" counter
    r = jpost(c2, "/login/passkey", auth.get(opts))
    assert r.status_code == 400 and r.get_json()["ok"] is False
    # Expired challenge.
    c3 = client(env)
    c3.get("/login", base_url=EXT)
    opts = jpost(c3, "/login/passkey/options").get_json()
    env.conn.execute("UPDATE ui_webauthn_challenges SET expires_at=?", (int(time.time()) - 1,))
    env.conn.commit()
    assert jpost(c3, "/login/passkey", auth.get(opts)).status_code == 400
    assert env.conn.execute("SELECT COUNT(*) FROM ui_webauthn_challenges").fetchone()[0] == 0


def test_challenge_bound_to_this_session(env):
    auth = enrolled(env)
    a, b = client(env), client(env)
    a.get("/login", base_url=EXT)
    b.get("/login", base_url=EXT)
    opts_a = jpost(a, "/login/passkey/options").get_json()
    jpost(b, "/login/passkey/options")
    # b posts an assertion over a's challenge: b's session holds another one.
    r = jpost(b, "/login/passkey", auth.get(opts_a))
    assert r.status_code == 401 and r.get_json()["ok"] is False


def test_csrf_is_required(env):
    auth = enrolled(env)
    c = client(env)
    c.get("/login", base_url=EXT)
    assert c.post("/login/passkey/options", json={}, base_url=EXT).status_code == 400
    opts = jpost(c, "/login/passkey/options").get_json()
    r = c.post("/login/passkey", json=auth.get(opts), base_url=EXT, headers={"X-CSRF-Token": "falsk"})
    assert r.status_code == 400
    r = c.post("/login/passkey/options", json={}, base_url=EXT,
               headers={"X-CSRF-Token": csrf_of(c), "Origin": "https://evil.example"})
    assert r.status_code == 400


def test_ip_lockout_applies_to_passkeys(env):
    auth = enrolled(env)
    c = client(env)
    for _ in range(dashboard.LOGIN_MAX_FAILURES):          # unknown passkeys: counted per IP only
        assert pk_login(c, SoftAuthenticator()).status_code == 401
    r = pk_login(c, auth)                                  # the right passkey, but this IP is locked
    assert r.status_code == 429 and "For mange forsøg" in r.get_json()["message"]
    assert pk_login(client(env, "198.51.100.9"), auth).get_json()["ok"]   # another IP


def test_bad_assertions_lock_the_user(env):
    auth = enrolled(env)
    for _ in range(dashboard.LOGIN_MAX_FAILURES):
        assert pk_login(client(env, "198.51.100.1"), auth, tamper=True).status_code == 401
    assert pk_login(client(env, "198.51.100.1"), auth).status_code == 429
    # 2.12 (#26): the lock is per IP + username - another address is not locked out.
    assert pk_login(client(env, "192.0.2.9"), auth).status_code == 200


def test_username_lockout_applies_to_passkeys(env):
    auth = enrolled(env)
    for _ in range(dashboard.LOGIN_MAX_FAILURES):
        pw_login(client(env, "198.51.100.1"), "anna", password="forkert-kode-123")
    r = pk_login(client(env, "198.51.100.1"), auth)
    assert r.status_code == 429
    assert [a for a in audits(env, "login") if a["result"] == "locked" and a["detail"] == "passkey"]


def test_login_scope_local_only_user(env):
    auth = enrolled(env, "lis", "Lis' telefon")
    with env.app.test_request_context("/"):
        dashboard.set_login_scope("lis", "local", "test")
    r = pk_login(client(env, OUTSIDE), auth)
    assert r.status_code == 401 and r.get_json()["message"] == passkeys.GENERIC_FAIL
    rec = audits(env, "login_blocked_external")[-1]
    assert rec["actor"] == "lis" and "passkey" in rec["detail"]
    # From the home network (the hostname mapped to the LAN address) it works.
    assert pk_login(client(env, LAN), auth).get_json()["ok"]


def test_removed_user_cannot_log_in(env):
    auth = enrolled(env)
    (env.state / "dashboard_users").write_text(
        (env.state / "dashboard_users").read_text().replace(f"anna:{fast_hash(PW)}:bynet:0\n", ""))
    r = pk_login(client(env), auth)
    assert r.status_code == 401 and r.get_json()["code"] == "unknown"
    with env.app.test_request_context("/"):
        dashboard.forget_user_meta("anna")
    assert rows(env, "anna") == []
    assert env.conn.execute("SELECT COUNT(*) FROM ui_passkey_handles WHERE name='anna'").fetchone()[0] == 0


# --------------------------------------------------------------------- where passkeys work


def test_login_page_on_https_external_address(env):
    html = body(client(env).get("/login", base_url=EXT))
    assert "data-passkey-login" in html and "Log ind med passkey" in html and "passkeys.js" in html
    for rx, what in INLINE_PATTERNS:
        assert rx.search(html) is None, what


def test_hidden_on_plain_http_lan_address(env):
    c = client(env, LAN)
    html = body(c.get("/login", base_url=LAN_URL))
    assert "data-passkey-login" not in html and "passkeys.js" not in html
    assert "Log ind med passkey virker via spam.example.dk" in html
    c.get("/login", base_url=LAN_URL)
    r = c.post("/login/passkey/options", json={}, base_url=LAN_URL, headers={"X-CSRF-Token": csrf_of(c, LAN_URL)})
    assert r.status_code == 404
    # Without an external address there is nothing to point at.
    dashboard.settings_set("external_url", "")
    assert "passkey" not in body(client(env, LAN).get("/login", base_url=LAN_URL)).lower()


def test_localhost_is_a_relying_party(env):
    c = client(env, "127.0.0.1")
    base = "http://localhost:8080"
    assert pw_login(c, "anna", base=base).status_code == 302
    auth = SoftAuthenticator(rp_id="localhost", origin="http://localhost:8080")
    opts = jpost(c, "/me/passkeys/options", base=base).get_json()
    assert opts["publicKey"]["rp"]["id"] == "localhost"
    cred = auth.create(opts)
    assert jpost(c, "/me/passkeys/register", cred, base=base).get_json()["ok"]
    assert rows(env, "anna")[0]["rp_id"] == "localhost"
    assert pk_login(client(env, "127.0.0.1"), auth, base=base).get_json()["ok"]
    # A localhost passkey is not offered/accepted on the external address.
    r = pk_login(client(env), SoftAuthenticator(cred_id=auth.cred_id))
    assert r.status_code == 401


def test_registration_on_lan_address_is_refused(env):
    c = client(env, LAN)
    pw_login(c, "anna", base=LAN_URL)
    r = jpost(c, "/me/passkeys/options", base=LAN_URL)
    assert r.status_code == 400 and r.get_json()["ok"] is False
    html = body(c.get("/me", base_url=LAN_URL))
    assert "Passkeys kan kun tilføjes og bruges via https://spam.example.dk" in html


# --------------------------------------------------------------------- Min konto + re-auth


def test_registration_needs_a_fresh_password_without_2fa(env):
    c = client(env)
    pw_login(c, "anna")
    stale_reauth(c, "anna")
    r = jpost(c, "/me/passkeys/options")
    assert r.status_code == 403 and r.get_json()["redirect"] == passkeys.CONFIRM_URL
    html = body(c.get("/me", base_url=EXT))
    assert f'href="{passkeys.CONFIRM_URL}"' in html and "data-passkey-create" not in html
    page = body(c.get(passkeys.CONFIRM_URL, base_url=EXT))
    assert 'name="password"' in page and 'autocomplete="current-password"' in page
    assert form_post(c, passkeys.CONFIRM_URL, {"password": "forkert-kode-123"}).status_code == 403
    r = form_post(c, passkeys.CONFIRM_URL, {"password": PW})
    assert r.status_code == 302 and r.headers["Location"].endswith("/me#passkeys")
    assert jpost(c, "/me/passkeys/options").status_code == 200
    assert "data-passkey-create" in body(c.get("/me", base_url=EXT))
    assert [a for a in audits(env, "passkey_reauth") if a["result"] == "failed"]


def test_password_proof_is_throttled(env):
    c = client(env)
    pw_login(c, "anna")
    stale_reauth(c, "anna")
    for _ in range(dashboard.LOGIN_MAX_FAILURES):
        form_post(c, passkeys.CONFIRM_URL, {"password": "forkert-kode-123"})
    r = form_post(c, passkeys.CONFIRM_URL, {"password": PW})
    assert r.status_code == 429 and jpost(c, "/me/passkeys/options").status_code == 403


def test_registration_needs_a_code_with_2fa(env):
    with env.app.test_request_context("/"):
        secret = dashboard.twofa_pending_secret("anna")
        recovery = dashboard.twofa_confirm("anna", dashboard.totp(secret), actor="test")
    c = client(env)
    pw_login(c, "anna")
    assert c.post("/login/2fa", data={"code": dashboard.totp(secret, time.time() + 30), "csrf": csrf_of(c)},
                  base_url=EXT).status_code == 302
    assert jpost(c, "/me/passkeys/options").status_code == 200          # the 2FA login is fresh proof
    stale_reauth(c, "anna")
    with c.session_transaction(base_url=EXT) as s:
        s["reauth_pw"] = ["anna", int(time.time())]                     # a password alone is NOT enough
    assert jpost(c, "/me/passkeys/options").status_code == 403
    page = body(c.get(passkeys.CONFIRM_URL, base_url=EXT))
    assert 'name="method" value="reauth"' in page and f'value="{passkeys.CONFIRM_URL}"' in page
    assert form_post(c, passkeys.CONFIRM_URL, {"password": PW}).status_code == 400
    r = form_post(c, "/me/2fa/confirm", {"method": "reauth", "next": passkeys.CONFIRM_URL,
                                         "code": recovery[0]})
    assert r.status_code == 302 and r.headers["Location"].endswith(passkeys.CONFIRM_URL)
    assert jpost(c, "/me/passkeys/options").status_code == 200


def test_register_failures(env):
    c = client(env)
    pw_login(c, "anna")
    auth = SoftAuthenticator()
    r = enroll(c, auth, fmt="packed", att_stmt={"alg": -7, "sig": b"x"})
    assert r.status_code == 400 and "attestation" in r.get_json()["message"]
    r = enroll(c, auth, origin="https://evil.example")
    assert r.status_code == 400
    # Without the options step (no challenge in the session): refused.
    cred = auth.create({"publicKey": {"challenge": "AAAA", "user": {"id": "AAAA"}}})
    assert jpost(c, "/me/passkeys/register", cred).status_code == 400
    assert rows(env) == []
    assert [a["detail"] for a in audits(env, "passkey_add") if a["result"] == "failed"] == [
        "attestation_format", "origin"]


def test_duplicate_and_limit(env):
    c = client(env)
    pw_login(c, "anna")
    auth = SoftAuthenticator()
    assert enroll(c, auth).get_json()["ok"]
    opts = jpost(c, "/me/passkeys/options").get_json()
    assert [x["id"] for x in opts["publicKey"]["excludeCredentials"]] == [rows(env)[0]["cred_id"]]
    assert opts["publicKey"]["authenticatorSelection"] == {
        "residentKey": "required", "requireResidentKey": True, "userVerification": "required"}
    assert opts["publicKey"]["attestation"] == "none"
    assert [p["alg"] for p in opts["publicKey"]["pubKeyCredParams"]] == [-7, -257]
    r = jpost(c, "/me/passkeys/register", auth.create(opts))
    assert r.status_code == 409
    for i in range(passkeys.MAX_PER_USER - 1):
        assert enroll(c, SoftAuthenticator(), f"Nøgle {i}").get_json()["ok"]
    assert jpost(c, "/me/passkeys/options").status_code == 409


def test_card_lists_without_secrets_and_label_is_cleaned(env):
    c = client(env)
    pw_login(c, "anna")
    assert enroll(c, SoftAuthenticator(), "Min‮ <b>telefon</b>\x00").get_json()["ok"]
    (row,) = rows(env, "anna")
    assert row["label"] == "Min <b>telefon</b>"
    html = body(c.get("/me", base_url=EXT))
    assert "Min &lt;b&gt;telefon&lt;/b&gt;" in html and "Synkroniseres" in html
    assert row["cred_id"] not in html and row["public_key"] not in html and row["user_handle"] not in html
    card = html[html.index('class="card passkey-card"'):]
    card = card[:card.index("</section>")]
    for rx, what in INLINE_PATTERNS:
        assert rx.search(card) is None, what
    # The admin never sees anna's passkeys on his own Min konto.
    a = client(env)
    pw_login(a, "admin")
    assert "Min &lt;b&gt;telefon" not in body(a.get("/me", base_url=EXT))


def test_remove_own_passkey_only_with_fresh_proof(env):
    auth = enrolled(env)
    pk_id = rows(env, "anna")[0]["id"]
    admin = client(env)
    pw_login(admin, "admin")
    r = admin.post("/me/passkeys/remove", data={"id": pk_id, "csrf": csrf_of(admin)}, base_url=EXT,
                   headers={"Accept": "application/json", "X-Requested-With": "fetch"})
    assert r.status_code == 404 and len(rows(env, "anna")) == 1         # not yours = not found
    c = client(env)
    pw_login(c, "anna")
    stale_reauth(c, "anna")
    r = c.post("/me/passkeys/remove", data={"id": pk_id, "csrf": csrf_of(c)}, base_url=EXT,
               headers={"Accept": "application/json", "X-Requested-With": "fetch"})
    assert r.status_code == 403 and r.get_json()["redirect"] == passkeys.CONFIRM_URL and rows(env, "anna")
    form_post(c, passkeys.CONFIRM_URL, {"password": PW})
    r = c.post("/me/passkeys/remove", data={"id": pk_id, "csrf": csrf_of(c)}, base_url=EXT,
               headers={"Accept": "application/json", "X-Requested-With": "fetch"})
    assert r.status_code == 200 and r.get_json()["rows"] == {f"passkey:{pk_id}": None}
    assert rows(env, "anna") == []
    assert audits(env, "passkey_remove")[-1]["detail"] == "Annas iPhone"
    assert pk_login(client(env), auth).get_json()["code"] == "unknown"


def test_passkey_login_is_fresh_proof_for_changes(env):
    auth = enrolled(env)
    c = client(env)
    assert pk_login(c, auth).get_json()["ok"]
    assert jpost(c, "/me/passkeys/options").status_code == 200


def test_security_mail_on_add_and_remove(env, monkeypatch):
    sent = []
    monkeypatch.setattr(dashboard, "security_notice", lambda name, subject, what, **kw: sent.append((name, subject)))
    c = client(env)
    pw_login(c, "anna")
    assert enroll(c, SoftAuthenticator()).get_json()["ok"]
    c.post("/me/passkeys/remove", data={"id": rows(env)[0]["id"], "csrf": csrf_of(c)}, base_url=EXT)
    assert sent == [("anna", "ny passkey"), ("anna", "passkey fjernet")]


# --------------------------------------------------------------------- challenges table


def test_login_options_are_rate_limited_and_bounded(env, monkeypatch):
    c = client(env, "192.0.2.77")
    c.get("/login", base_url=EXT)
    for _ in range(passkeys.OPTIONS_PER_IP):
        assert jpost(c, "/login/passkey/options").status_code == 200
    assert jpost(c, "/login/passkey/options").status_code == 429
    monkeypatch.setattr(passkeys, "CHALLENGE_MAX", 3)
    d = client(env, "192.0.2.78")
    d.get("/login", base_url=EXT)
    env.conn.execute("DELETE FROM ui_webauthn_challenges")
    env.conn.commit()
    for _ in range(5):  # full: the oldest login challenge makes room, the table stays bounded
        assert jpost(d, "/login/passkey/options").status_code == 200
        assert env.conn.execute("SELECT COUNT(*) FROM ui_webauthn_challenges").fetchone()[0] <= 3


def challenge_count(env, purpose: str | None = None) -> int:
    sql = "SELECT COUNT(*) FROM ui_webauthn_challenges" + (" WHERE purpose=?" if purpose else "")
    return env.conn.execute(sql, (purpose,) if purpose else ()).fetchone()[0]


def test_one_actor_filling_the_challenge_cap_does_not_block_other_logins(env, monkeypatch):
    auth = enrolled(env)
    monkeypatch.setattr(passkeys, "CHALLENGE_MAX", 30)
    env.conn.execute("DELETE FROM ui_webauthn_challenges")
    env.conn.commit()
    # An attacker spread over many addresses fills the whole cap ...
    for i in range(3):
        a = client(env, f"198.51.100.{i + 1}")
        a.get("/login", base_url=EXT)
        for _ in range(passkeys.OPTIONS_PER_IP):
            assert jpost(a, "/login/passkey/options").status_code == 200
    assert challenge_count(env) == 30
    # ... yet a real user still gets a challenge and logs in; the oldest went.
    c = client(env, "192.0.2.10")
    r = pk_login(c, auth)
    assert r.status_code == 200 and r.get_json()["ok"], body(r)
    assert challenge_count(env) <= 30


def test_registration_challenges_are_never_evicted(env, monkeypatch):
    monkeypatch.setattr(passkeys, "CHALLENGE_MAX", 2)
    env.conn.execute("DELETE FROM ui_webauthn_challenges")
    now = int(time.time())
    for i, who in enumerate(("admin", "lis")):
        env.conn.execute("INSERT INTO ui_webauthn_challenges(id, purpose, name, rp_id, origin, created_at, expires_at) "
                         "VALUES(?,?,?,?,?,?,?)", (f"reg{i}", "register", who, "spam.example.dk", EXT, now - 60,
                                                   now + 240))
    env.conn.commit()
    c = client(env)
    c.get("/login", base_url=EXT)
    assert jpost(c, "/login/passkey/options").status_code == 503
    assert challenge_count(env, "register") == 2


def test_login_options_limit_is_per_ipv6_64_and_memory_bounded(env, monkeypatch):
    assert passkeys.ip_bucket("2001:db8:1:2:3:4:5:6") == "2001:db8:1:2::/64"
    assert passkeys.ip_bucket("::ffff:192.0.2.5") == "192.0.2.5"
    assert passkeys.ip_bucket("192.0.2.5") == "192.0.2.5" and passkeys.ip_bucket(None) == "unknown"
    c = client(env, "2001:db8:aa:bb::1")
    c.get("/login", base_url=EXT)
    for _ in range(passkeys.OPTIONS_PER_IP):
        assert jpost(c, "/login/passkey/options").status_code == 200
    # Another address in the same /64 shares the limit; the next /64 does not.
    same = client(env, "2001:db8:aa:bb:ffff::2")
    same.get("/login", base_url=EXT)
    assert jpost(same, "/login/passkey/options").status_code == 429
    other = client(env, "2001:db8:aa:bc::1")
    other.get("/login", base_url=EXT)
    assert jpost(other, "/login/passkey/options").status_code == 200
    monkeypatch.setattr(passkeys, "OPTIONS_BUCKETS_MAX", 5)
    for i in range(50):
        passkeys._options_allowed(f"203.0.113.{i}")
    assert len(passkeys._OPT_HITS) <= 5


# --------------------------------------------------------------------- sfctl


@pytest.fixture
def cli(env, monkeypatch, capsys):
    import sfctl

    monkeypatch.setattr(sfctl, "_euid", lambda: 10099)
    monkeypatch.setattr(sfctl, "configure", lambda *a, **k: None)
    monkeypatch.setattr(sfctl, "_fix_ownership", lambda: None)

    def run(*argv: str) -> tuple[int, str]:
        code = sfctl.main(list(argv))
        out = capsys.readouterr()
        return code, out.out + out.err

    return run


def test_sfctl_passkeys_and_reset(env, cli):
    enrolled(env)
    code, out = cli("passkeys", "anna")
    assert code == 0 and "Annas iPhone" in out and "spam.example.dk" in out
    assert rows(env)[0]["cred_id"] not in out and rows(env)[0]["public_key"] not in out
    code, out = cli("passkeys", "findes-ikke")
    assert code == 1
    code, out = cli("passkeys-reset", "anna", "--yes")
    assert code == 0 and "1 passkey" in out
    assert rows(env, "anna") == []
    rec = audits(env, "passkey_reset")[-1]
    assert rec["actor"] == "cli" and rec["detail"] == "anna (1)"
    code, out = cli("passkeys", "anna")
    assert code == 0 and "ingen passkeys" in out


def test_sfctl_doctor_passkey_checks(env, cli, monkeypatch):
    import sfctl

    enrolled(env)
    rep = sfctl.Report()
    sfctl._doctor_passkeys(rep, dashboard.load_users())
    assert rep.errors == 0 and rep.warnings == 0
    dashboard.settings_set("external_url", "https://ny.example.dk")
    rep = sfctl.Report()
    sfctl._doctor_passkeys(rep, dashboard.load_users())
    assert rep.warnings == 1                      # registered for another address
    rep = sfctl.Report()
    sfctl._doctor_passkeys(rep, {})               # the user was removed from the file
    assert rep.warnings == 2


# --------------------------------------------------------------------- reset / log out everywhere


def notices(monkeypatch) -> list[tuple[str, str, str]]:
    sent: list[tuple[str, str, str]] = []
    monkeypatch.setattr(dashboard, "security_notice", lambda name, subject, what, **kw: sent.append((name, subject, what)))
    return sent


def test_admin_password_reset_removes_the_users_passkeys(env, monkeypatch):
    auth = enrolled(env)
    sent = notices(monkeypatch)
    a = client(env)
    pw_login(a, "admin")
    assert "passkeys fjernes" in body(a.get("/users/anna", base_url=EXT))
    r = a.post("/users/anna/password", data={"password": "Ny-kode-1234567", "password2": "Ny-kode-1234567",
                                              "csrf": csrf_of(a)}, base_url=EXT,
               headers={"Accept": "application/json", "X-Requested-With": "fetch"})
    assert r.status_code == 200 and "passkey er fjernet" in r.get_json()["message"], body(r)
    assert rows(env, "anna") == []
    assert audits(env, "passkey_reset")[-1]["detail"] == "anna (1)"
    assert sent[-1][0] == "anna" and "passkeys fjernet" in sent[-1][1] and "passkey er fjernet" in sent[-1][2]
    assert pk_login(client(env), auth).get_json()["code"] == "unknown"


def test_admin_password_reset_without_passkeys_sends_the_plain_notice(env, monkeypatch):
    sent = notices(monkeypatch)
    a = client(env)
    pw_login(a, "admin")
    a.post("/users/lis/password", data={"password": "Ny-kode-1234567", "password2": "Ny-kode-1234567",
                                        "csrf": csrf_of(a)}, base_url=EXT)
    assert sent == [("lis", "ny adgangskode", "En administrator (admin) har sat en ny adgangskode.")]
    assert audits(env, "passkey_reset") == []


def test_own_logout_everywhere_removes_passkeys_by_default(env, monkeypatch):
    auth = enrolled(env)
    sent = notices(monkeypatch)
    c = client(env)
    pw_login(c, "anna")
    page = body(c.get("/me", base_url=EXT))
    assert "Fjern også passkeys" in page and 'name="passkeys" value="1" checked' in page
    r = c.post("/me/logout-all", data={"passkeys": ["0", "1"], "csrf": csrf_of(c)}, base_url=EXT,
               headers={"Accept": "application/json", "X-Requested-With": "fetch"})
    assert r.status_code == 200 and "din passkey er fjernet" in r.get_json()["message"]
    assert rows(env, "anna") == []
    assert sent[-1][:2] == ("anna", "passkeys fjernet") and "logget ud overalt" in sent[-1][2]
    assert pk_login(client(env), auth).get_json()["code"] == "unknown"


def test_own_logout_everywhere_can_keep_passkeys(env, monkeypatch):
    auth = enrolled(env)
    sent = notices(monkeypatch)
    c = client(env)
    pw_login(c, "anna")
    r = c.post("/me/logout-all", data={"passkeys": "0", "csrf": csrf_of(c)}, base_url=EXT,
               headers={"Accept": "application/json", "X-Requested-With": "fetch"})
    assert r.status_code == 200 and r.get_json()["message"] == "Du er logget ud overalt."
    assert len(rows(env, "anna")) == 1 and sent == []
    assert pk_login(client(env), auth).get_json()["ok"]


def test_no_checkbox_without_passkeys(env):
    c = client(env)
    pw_login(c, "lis")
    assert "Fjern også passkeys" not in body(c.get("/me", base_url=EXT))


def test_admin_logout_everywhere_checkbox_and_notice(env, monkeypatch):
    enrolled(env)
    sent = notices(monkeypatch)
    a = client(env)
    pw_login(a, "admin")
    edit = body(a.get("/users/anna", base_url=EXT))
    assert "Fjern også passkeys" in edit and "brugerens passkeys stadig" in edit
    cards = body(a.get("/users", base_url=EXT))
    assert "Brugerens passkeys (1) fjernes også" in cards        # compact card: said in the confirm dialog
    hdr = {"Accept": "application/json", "X-Requested-With": "fetch"}
    r = a.post("/users/anna/logout-all", data={"passkeys": "0", "csrf": csrf_of(a)}, base_url=EXT, headers=hdr)
    assert r.status_code == 200 and r.get_json()["message"] == "anna er logget ud overalt."
    assert len(rows(env, "anna")) == 1 and sent == []
    r = a.post("/users/anna/logout-all", data={"passkeys": ["0", "1"], "csrf": csrf_of(a)}, base_url=EXT,
               headers=hdr)
    assert r.status_code == 200 and "brugerens passkey er fjernet" in r.get_json()["message"]
    assert rows(env, "anna") == []
    assert sent[-1][:2] == ("anna", "passkeys fjernet") and "En administrator (admin)" in sent[-1][2]
    assert audits(env, "passkey_reset")[-1]["detail"] == "anna (1)"


def test_admin_logout_everywhere_card_form_removes_them(env):
    enrolled(env)
    a = client(env)
    pw_login(a, "admin")
    a.post("/users/anna/logout-all", data={"next": "/users", "csrf": csrf_of(a)}, base_url=EXT)
    assert rows(env, "anna") == []


def test_sfctl_reset_password_removes_passkeys(env, cli, monkeypatch):
    enrolled(env)
    sent = notices(monkeypatch)
    code, out = cli("reset-password", "anna", "--generate")
    assert code == 0 and "1 passkey(s) for anna er fjernet" in out, out
    assert rows(env, "anna") == []
    assert audits(env, "passkey_reset")[-1]["detail"] == "anna (1)"
    assert sent[-1][0] == "anna" and "passkeys fjernet" in sent[-1][1] and "passkey er fjernet" in sent[-1][2]


def test_sfctl_logout_all_points_at_passkeys_reset(env, cli):
    enrolled(env)
    code, out = cli("logout-all", "anna")
    assert code == 0 and "sfctl passkeys-reset anna" in out
    assert len(rows(env, "anna")) == 1
