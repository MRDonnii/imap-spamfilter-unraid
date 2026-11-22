"""2.1 AUTH-2: two-step login (TOTP + recovery codes), reverse proxy /
Cloudflare Tunnel trust, external address, PWA (manifest, service worker,
icons, offline page) and the deploy plumbing for TRUSTED_PROXIES.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import subprocess
import time
from email.utils import parsedate_to_datetime

import pytest

from fakes_ui import TEST_PASSWORD, csrf_of, fast_hash, login, post
from fakes_ui_admin import make_admin_env

import dashboard  # noqa: E402
import ui_kit as kit  # noqa: E402
from test_ui_core import CSP, INLINE_PATTERNS  # noqa: E402

PW = TEST_PASSWORD


@pytest.fixture
def env(tmp_path, monkeypatch):
    e = make_admin_env(tmp_path, monkeypatch)
    h = fast_hash(PW)
    (e.state / "dashboard_users").write_text("\n".join([
        f"admin:{h}:admin:0", f"anna:{h}:bynet:0", f"bo:{h}:bynet:0"]) + "\n")
    yield e
    dashboard.configure_proxies("")


def body(r) -> str:
    return r.get_data().decode("utf-8", "replace")


def client_for(env, name: str | None, **kw):
    c = env.app.test_client(**kw)
    if name:
        assert login(c, name, PW).status_code == 302
    return c


def twofa_row(env, name: str):
    return env.conn.execute("SELECT * FROM ui_twofa WHERE name=?", (name,)).fetchone()


def enroll(env, c, name: str) -> tuple[str, list[str]]:
    """Run the setup flow for the logged-in client; returns (secret, codes)."""
    r = c.get("/me/2fa/setup")
    assert r.status_code == 200
    secret = twofa_row(env, name)["pending_secret"]
    r = c.post("/me/2fa/confirm", data={"code": dashboard.totp(secret), "csrf": csrf_of(c)})
    assert r.status_code == 200, body(r)[:300]
    codes = re.findall(r'<li><code class="mono">([a-z0-9]{5}-[a-z0-9]{5})</code></li>', body(r))
    assert len(codes) == 8
    return secret, codes


def password_step(c, name: str, *, remember: bool = False, nxt: str = ""):
    c.get("/login")
    data = {"username": name, "password": PW, "csrf": csrf_of(c)}
    if remember:
        data["remember"] = "1"
    return c.post("/login" + (f"?next={nxt}" if nxt else ""), data=data)


def code_step(c, code: str, nxt: str = ""):
    return c.post("/login/2fa" + (f"?next={nxt}" if nxt else ""), data={"code": code, "csrf": csrf_of(c)})


def csrf_at(c, base_url: str) -> str:
    with c.session_transaction(base_url=base_url) as s:
        return s.get("csrf", "")


def later_code(secret: str, steps: int = 1) -> str:
    """A code from the next time step (inside the +-1 window), so a test can
    log in twice without waiting for the clock (a step is used only once)."""
    return dashboard.totp(secret, time.time() + steps * dashboard.TOTP_STEP)


# --------------------------------------------------------------------- RFC 4226 / RFC 6238


def test_hotp_rfc4226_vectors():
    key = b"12345678901234567890"
    want = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
    assert [dashboard.hotp(key, i) for i in range(10)] == want


@pytest.mark.parametrize("t,code", [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                                    (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")])
def test_totp_rfc6238_sha1_vectors(t, code):
    key = b"12345678901234567890"
    assert dashboard.totp(key, t, digits=8) == code
    # Same key through the base32 path the app uses.
    b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert dashboard.totp(b32, t, digits=8) == code


@pytest.mark.parametrize("t,code", [(59, "46119246"), (1111111109, "68084774"), (2000000000, "90698825")])
def test_totp_rfc6238_sha256_vectors(t, code):
    key = b"12345678901234567890123456789012"
    assert dashboard.totp(key, t, digits=8, digest="sha256") == code


def test_totp_window_and_replay():
    secret = dashboard.new_totp_secret()
    assert len(secret) == 32 and re.fullmatch(r"[A-Z2-7]+", secret)
    assert len(dashboard.b32_secret_bytes(secret)) == 20
    now = 1_700_000_000.0
    step = int(now // 30)
    assert dashboard.totp_match(secret, dashboard.totp(secret, now), at=now) == step
    assert dashboard.totp_match(secret, dashboard.totp(secret, now - 30), at=now) == step - 1
    assert dashboard.totp_match(secret, dashboard.totp(secret, now + 30), at=now) == step + 1
    assert dashboard.totp_match(secret, dashboard.totp(secret, now - 90), at=now) is None
    assert dashboard.totp_match(secret, dashboard.totp(secret, now), at=now, after_step=step) is None
    assert dashboard.totp_match(secret, "12345", at=now) is None
    assert dashboard.totp_match("not base32!", "123456", at=now) is None


def test_secret_formatting_and_otpauth_uri():
    assert dashboard.group_secret("JBSWY3DPEHPK3PXP") == "JBSW Y3DP EHPK 3PXP"
    uri = dashboard.otpauth_uri("anna.b", "JBSWY3DPEHPK3PXP")
    assert uri.startswith("otpauth://totp/Spamfilter%20Hjemmeserver:anna.b?secret=JBSWY3DPEHPK3PXP&")
    assert "issuer=Spamfilter%20Hjemmeserver" in uri and "digits=6" in uri and "period=30" in uri


def test_code_normalisation():
    assert dashboard.normalize_code(" 123 456 ") == ("totp", "123456")
    assert dashboard.normalize_code("ABCDE-23456") == ("recovery", "abcde23456")
    assert dashboard.normalize_code("abcde-2345") == (None, "")
    assert dashboard.normalize_code("abcd1-23456") == (None, "")   # '1' is not in the alphabet
    assert dashboard.normalize_code(None) == (None, "")


# --------------------------------------------------------------------- QR code


# Fingerprints of the module matrix from an independent encoder (python-qrcode
# 8.x, byte mode, level M, fixed mask) - checked bit for bit at build time.
QR_REFERENCE = [
    (b"otpauth://totp/Spamfilter%20Hjemmeserver:anna?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Spamfilter%20Hjemmeserver",
     0, 45, "e551602423419c0bbab24174"),
    (b"otpauth://totp/Spamfilter%20Hjemmeserver:anna?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Spamfilter%20Hjemmeserver",
     5, 45, "dde9a1497281378c9aa99940"),
    (b"HELLO WORLD 123", 0, 25, "daf7850db64b0aff25230fea"),
    (b"HELLO WORLD 123", 5, 25, "bd42798fc0f8d6a68616d7aa"),
    (b"x" * 300, 0, 69, "1b0ce35009886d141b2800ee"),
    (b"x" * 300, 5, 69, "083a752f3c787dc2c30cfa4c"),
]


@pytest.mark.parametrize("data,mask,size,fp", QR_REFERENCE)
def test_qr_matrix_matches_reference_encoder(data, mask, size, fp):
    mat = kit.qr_matrix(data, mask=mask)
    assert len(mat) == size and all(len(r) == size for r in mat)
    bits = "".join("1" if v else "0" for row in mat for v in row)
    assert hashlib.sha256(bits.encode()).hexdigest()[:24] == fp


def test_qr_structure_and_svg():
    uri = dashboard.otpauth_uri("anna", dashboard.new_totp_secret())
    mat = kit.qr_matrix(uri)
    n = len(mat)
    assert (n - 17) % 4 == 0
    finder = [[True] * 7] + [[True] + [False] * 5 + [True]] + [[True, False, True, True, True, False, True]] * 3 \
        + [[True] + [False] * 5 + [True]] + [[True] * 7]
    for ox, oy in ((0, 0), (n - 7, 0), (0, n - 7)):
        assert [row[ox:ox + 7] for row in mat[oy:oy + 7]] == finder
    assert mat[n - 8][8] is True  # the dark module
    svg = kit.qr_svg(uri, label="QR")
    assert svg.startswith('<svg class="qr" viewBox="0 0 %d %d"' % (n + 8, n + 8))
    assert "style" not in svg and "<script" not in svg and 'fill="#ffffff"' in svg
    with pytest.raises(ValueError):
        kit.qr_matrix(b"x" * 700)


# --------------------------------------------------------------------- enrollment


def test_enrollment_flow(env):
    anna = client_for(env, "anna")
    me = body(anna.get("/me"))
    assert "To-trins-login" in me and "Ikke slået til" in me and 'href="/me/2fa/setup"' in me
    page = anna.get("/me/2fa/setup")
    html = body(page)
    secret = twofa_row(env, "anna")["pending_secret"]
    assert dashboard.group_secret(secret) in html
    assert 'href="otpauth://totp/Spamfilter%20Hjemmeserver:anna?secret=' + secret in html
    assert '<svg class="qr"' in html and 'autocomplete="one-time-code"' in html
    # A reload shows the same secret (the QR code must not change under the user).
    anna.get("/me/2fa/setup")
    assert twofa_row(env, "anna")["pending_secret"] == secret
    # Wrong code: stays off.
    bad = anna.post("/me/2fa/confirm", data={"code": "000000" if dashboard.totp(secret) != "000000" else "111111",
                                             "csrf": csrf_of(anna)})
    assert bad.status_code == 400 and "Koden passer ikke" in body(bad)
    assert not dashboard.twofa_status("anna")["enabled"]
    r = anna.post("/me/2fa/confirm", data={"code": dashboard.totp(secret), "csrf": csrf_of(anna)})
    assert r.status_code == 200 and r.headers["Cache-Control"] == "no-store"
    html = body(r)
    codes = re.findall(r"<li><code class=\"mono\">([a-z0-9]{5}-[a-z0-9]{5})</code></li>", html)
    assert len(codes) == 8 and len(set(codes)) == 8
    assert "data-download-text" in html and "Koderne vises kun nu" in html
    row = twofa_row(env, "anna")
    assert row["secret"] == secret and row["pending_secret"] is None and row["enabled_at"]
    stored = json.loads(row["recovery"])
    assert len(stored["codes"]) == 8
    raw = json.dumps(dict(row))
    for c in codes:  # only hashes are stored
        assert c.replace("-", "") not in raw
    st = dashboard.twofa_status("anna")
    assert st["enabled"] and st["recovery_left"] == 8
    # This session proved the code: no step-up, pages work.
    assert anna.get("/spam").status_code == 200
    assert "Slået til" in body(anna.get("/me"))
    # Setup page now redirects; audit has the enable.
    assert anna.get("/me/2fa/setup").status_code == 302
    assert any(a["action"] == "twofa_enable" and a["result"] == "ok" for a in env.audit())
    # The users file is untouched by 2FA (old code keeps reading it).
    assert (env.state / "dashboard_users").read_text().count(":") == 9


def test_enrollment_confirm_is_throttled(env):
    anna = client_for(env, "anna")
    anna.get("/me/2fa/setup")
    secret = twofa_row(env, "anna")["pending_secret"]
    wrong = "000000" if dashboard.totp(secret) != "000000" else "111111"
    for _ in range(dashboard.LOGIN_MAX_FAILURES):
        anna.post("/me/2fa/confirm", data={"code": wrong, "csrf": csrf_of(anna)})
    r = anna.post("/me/2fa/confirm", data={"code": dashboard.totp(secret), "csrf": csrf_of(anna)})
    assert r.status_code == 429 and "For mange" in body(r)
    assert not dashboard.twofa_status("anna")["enabled"]


# --------------------------------------------------------------------- login with 2FA


def test_login_requires_code_after_password(env):
    secret, codes = enroll(env, client_for(env, "anna"), "anna")
    c = env.app.test_client()
    r = password_step(c, "anna", nxt="/spam")
    assert r.status_code == 302 and r.headers["Location"].startswith("/login/2fa?next=/spam")
    with c.session_transaction() as s:
        assert "u" not in s and s["pre"]["u"] == "anna"
    # Not logged in yet: every page sends you to the code step, JSON says 401.
    r = c.get("/spam")
    assert r.status_code == 302 and r.headers["Location"].startswith("/login/2fa")
    r = c.get("/api/status", headers={"Accept": "application/json"})
    assert r.status_code == 401 and r.get_json()["redirect"] == "/login/2fa"
    assert c.get("/login").headers["Location"].startswith("/login/2fa")
    page = c.get("/login/2fa")
    assert page.status_code == 200 and 'autocomplete="one-time-code"' in body(page)
    wrong = "000000" if dashboard.totp(secret) != "000000" else "111111"
    r = code_step(c, wrong)
    assert r.status_code == 401 and "Koden passer ikke" in body(r)
    r = code_step(c, later_code(secret), nxt="/spam")
    assert r.status_code == 302 and r.headers["Location"] == "/spam"
    assert c.get("/spam").status_code == 200
    with c.session_transaction() as s:
        assert s["u"] == "anna" and s["mfa"] == 1 and "pre" not in s
    logins = [a for a in env.audit() if a["action"] in ("login", "login_2fa")]
    assert [(a["action"], a["result"]) for a in logins][-3:] == [("login", "pending"), ("login_2fa", "failed"),
                                                                 ("login", "ok")]
    assert logins[-1]["detail"] == "to-trins-login"


def test_code_cannot_be_replayed(env):
    secret, _ = enroll(env, client_for(env, "anna"), "anna")
    code = later_code(secret)
    c1 = env.app.test_client()
    password_step(c1, "anna")
    assert code_step(c1, code).status_code == 302
    c2 = env.app.test_client()
    password_step(c2, "anna")
    assert code_step(c2, code).status_code == 401
    # Older steps are refused too (steps only move forward) ...
    assert code_step(c2, dashboard.totp(secret)).status_code == 401
    # ... the next fresh step is accepted.
    assert dashboard.twofa_verify("anna", later_code(secret, 2)) is None   # outside the +-1 window
    row = twofa_row(env, "anna")
    assert row["last_step"] == int(time.time() // 30) + 1


def test_recovery_code_works_once(env):
    secret, codes = enroll(env, client_for(env, "anna"), "anna")
    c = env.app.test_client()
    password_step(c, "anna")
    r = code_step(c, codes[3].upper())
    assert r.status_code == 302
    with c.session_transaction() as s:
        flashes = s.get("_fl", [])
    assert any("genoprettelseskode" in m for _k, m in flashes)
    assert dashboard.twofa_status("anna")["recovery_left"] == 7
    assert "genoprettelseskode" in [a for a in env.audit() if a["action"] == "login"][-1]["detail"]
    c2 = env.app.test_client()
    password_step(c2, "anna")
    assert code_step(c2, codes[3]).status_code == 401


def test_too_many_wrong_codes_end_the_login(env):
    secret, _ = enroll(env, client_for(env, "anna"), "anna")
    wrong = "000000" if dashboard.totp(secret) != "000000" else "111111"
    c = env.app.test_client()
    password_step(c, "anna")
    for i in range(dashboard.MFA_MAX_TRIES - 1):
        assert code_step(c, wrong).status_code == 401
    r = code_step(c, wrong)
    assert r.status_code == 302 and r.headers["Location"].startswith("/login")
    with c.session_transaction() as s:
        assert "pre" not in s
    # The per-user 2FA throttle is now locked: even a fresh password login
    # cannot try more codes for a while.
    c2 = env.app.test_client()
    password_step(c2, "anna")
    r = code_step(c2, later_code(secret))
    assert r.status_code == 429 and "For mange" in body(r)


def test_pending_login_expires(env, monkeypatch):
    secret, _ = enroll(env, client_for(env, "anna"), "anna")
    c = env.app.test_client()
    password_step(c, "anna")
    with c.session_transaction() as s:
        pre = dict(s["pre"])
        pre["t"] = int(time.time()) - dashboard.MFA_PENDING_TTL - 5
        s["pre"] = pre
    r = code_step(c, later_code(secret))
    assert r.status_code == 302 and r.headers["Location"] == "/login"
    assert c.get("/").headers["Location"].startswith("/login?")


def test_password_change_invalidates_pending_login(env):
    secret, _ = enroll(env, client_for(env, "anna"), "anna")
    c = env.app.test_client()
    password_step(c, "anna")
    dashboard.bump_generation("anna")
    assert code_step(c, later_code(secret)).headers["Location"] == "/login"


def test_csrf_and_cancel_on_code_step(env):
    secret, _ = enroll(env, client_for(env, "anna"), "anna")
    c = env.app.test_client()
    password_step(c, "anna")
    r = c.post("/login/2fa", data={"code": later_code(secret), "csrf": "forkert"})
    assert r.status_code == 400 and "udløbet" in body(r)
    r = c.post("/logout", data={"csrf": csrf_of(c)})
    assert r.status_code == 302
    with c.session_transaction() as s:
        assert "pre" not in s


# --------------------------------------------------------------------- remembered devices


def _cookie_expiry(resp) -> float:
    cookie = resp.headers.get("Set-Cookie", "")
    m = re.search(r"Expires=([^;]+)", cookie)
    assert m, cookie
    return parsedate_to_datetime(m.group(1)).timestamp() - time.time()


def test_remembered_session_skips_code_only_for_that_session(env):
    secret, _ = enroll(env, client_for(env, "anna"), "anna")
    phone = env.app.test_client()
    password_step(phone, "anna", remember=True)
    r = code_step(phone, later_code(secret))
    assert r.status_code == 302 and abs(_cookie_expiry(r) - dashboard.REMEMBER_LIFETIME) < 120
    with phone.session_transaction() as s:
        assert s["rm"] == 1 and s["mfa"] == 1
        s["ts"] = int(time.time()) - 3 * 86400        # days later: still in, no code asked
    assert phone.get("/spam").status_code == 200
    # Logging out and in again on the same device asks for the code again.
    phone.post("/logout", data={"csrf": csrf_of(phone)})
    r = password_step(phone, "anna", remember=True)
    assert r.headers["Location"].startswith("/login/2fa")
    assert "Husk mig" in body(phone.get("/login/2fa"))


def test_existing_session_is_stepped_up_when_2fa_is_turned_on(env):
    laptop = client_for(env, "anna")                    # logged in before 2FA existed
    assert laptop.get("/spam").status_code == 200
    secret, _ = enroll(env, client_for(env, "anna"), "anna")   # turned on from the phone
    r = laptop.get("/spam")
    assert r.status_code == 302 and r.headers["Location"].startswith("/login/2fa?next=/spam")
    assert code_step(laptop, later_code(secret), nxt="/spam").headers["Location"] == "/spam"
    assert laptop.get("/spam").status_code == 200


# --------------------------------------------------------------------- required by admin


def test_admin_can_require_2fa(env):
    admin = client_for(env, "admin")
    anna = client_for(env, "anna")
    r = post(admin, "/users/anna/2fa/require", {"required": "1"})
    assert r.get_json()["ok"]
    assert dashboard.twofa_status("anna")["required"]
    assert any(a["action"] == "twofa_required" and a["detail"] == "anna til" for a in env.audit())
    # Already logged-in user: only the setup pages until it is done.
    r = anna.get("/spam")
    assert r.status_code == 302 and r.headers["Location"] == "/me/2fa/setup"
    r = anna.get("/api/status", headers={"Accept": "application/json"})
    assert r.status_code == 403 and r.get_json()["code"] == "twofa_setup_required"
    assert post(anna, "/mail/action", {"action": "release", "items": []}).status_code == 403
    assert anna.get("/me").status_code == 200 and "Påkrævet" in body(anna.get("/me"))
    secret, _ = enroll(env, anna, "anna")
    assert anna.get("/spam").status_code == 200
    # Required: cannot be switched off by the user.
    r = post(anna, "/me/2fa/disable", {"code": later_code(secret)})
    assert r.status_code == 403 and dashboard.twofa_status("anna")["enabled"]
    # A fresh password login of a required-but-not-enrolled user lands on setup.
    post(admin, "/users/bo/2fa/require", {"required": "1"})
    c = env.app.test_client()
    r = password_step(c, "bo")
    assert r.headers["Location"] == "/me/2fa/setup"
    # Not required any more: free again.
    assert post(admin, "/users/bo/2fa/require", {"required": "0"}).get_json()["ok"]
    assert c.get("/spam").status_code == 200


def test_admin_reset_and_user_badges(env):
    admin = client_for(env, "admin")
    enroll(env, client_for(env, "anna"), "anna")
    html = body(admin.get("/users"))
    card = html[html.index('data-row="user:anna"'):]
    card = card[:card.index("</article>")]
    assert "Slået til" in card
    edit = body(admin.get("/users/anna"))
    assert 'action="/users/anna/2fa/reset"' in edit and 'action="/users/anna/2fa/require"' in edit
    assert post(admin, "/users/anna/2fa/reset", {}).get_json()["ok"]
    assert not dashboard.twofa_status("anna")["enabled"]
    assert any(a["action"] == "twofa_reset" for a in env.audit())
    assert post(admin, "/users/anna/2fa/reset", {}).get_json()["ok"] is False
    # Password alone works again.
    c = env.app.test_client()
    assert password_step(c, "anna").headers["Location"] == "/"
    # Unknown user: 404; Bruger: 403.
    assert post(admin, "/users/ghost/2fa/require", {"required": "1"}).status_code == 404
    anna = client_for(env, "anna")
    assert post(anna, "/users/bo/2fa/require", {"required": "1"}).status_code == 403
    assert post(anna, "/users/bo/2fa/reset", {}).status_code == 403


def test_new_user_can_be_created_with_2fa_required(env):
    admin = client_for(env, "admin")
    assert 'name="require_2fa"' in body(admin.get("/users/new"))
    r = post(admin, "/users/new", {"name": "carl", "password": "x" * 14, "password2": "x" * 14, "role": "user",
                                   "acct:bynet": "1", "perm:release": "1", "require_2fa": "1"})
    assert r.get_json()["ok"]
    assert dashboard.twofa_status("carl")["required"]
    assert "Påkrævet – ikke sat op endnu" in body(admin.get("/users"))


def test_removed_user_loses_2fa(env):
    admin = client_for(env, "admin")
    enroll(env, client_for(env, "anna"), "anna")
    assert post(admin, "/users/anna/remove", {"confirm": "anna"}).get_json()["ok"]
    assert twofa_row(env, "anna") is None


# --------------------------------------------------------------------- self service


def test_disable_and_new_recovery_codes(env):
    anna = client_for(env, "anna")
    secret, codes = enroll(env, anna, "anna")
    r = post(anna, "/me/2fa/disable", {"code": "999999" if later_code(secret) != "999999" else "888888"})
    assert r.get_json()["ok"] is False and dashboard.twofa_status("anna")["enabled"]
    # New recovery codes need a valid code; the old ones stop working.
    r = anna.post("/me/2fa/recovery", data={"code": later_code(secret), "csrf": csrf_of(anna)})
    assert r.status_code == 200
    new = re.findall(r"<li><code class=\"mono\">([a-z0-9]{5}-[a-z0-9]{5})</code></li>", body(r))
    assert len(new) == 8 and not set(new) & set(codes)
    assert dashboard.twofa_verify("anna", codes[0]) is None
    # Disable with a recovery code.
    r = post(anna, "/me/2fa/disable", {"code": new[0]})
    assert r.get_json()["ok"] and not dashboard.twofa_status("anna")["enabled"]
    assert [a["action"] for a in env.audit()][-1] == "twofa_disable"


def test_logout_everywhere_for_any_user(env):
    anna = client_for(env, "anna")
    other = client_for(env, "anna")
    r = post(anna, "/me/logout-all", {})
    assert r.get_json()["ok"] and r.get_json()["redirect"] == "/login"
    assert anna.get("/").status_code == 302 and other.get("/").status_code == 302


def test_cli_reset_2fa(env, capsys):
    enroll(env, client_for(env, "anna"), "anna")
    dashboard._cli_reset_2fa("anna")
    assert not dashboard.twofa_status("anna")["enabled"]
    assert "slået fra" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        dashboard._cli_reset_2fa("ghost")


def test_ui_twofa_is_additive_and_rollback_safe(env):
    enroll(env, client_for(env, "anna"), "anna")
    cols = [r[1] for r in env.conn.execute("PRAGMA table_info(ui_twofa)")]
    assert cols[:2] == ["name", "secret"]
    # Old (2.0.x) code never reads ui_twofa: the tables it knows are intact.
    for t in ("login_attempts", "ui_actions", "settings_kv", "ui_users"):
        assert env.conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone() is not None
    # The users file lines keep the 2.0 format name:verifier:scope:gen.
    for line in (env.state / "dashboard_users").read_text().splitlines():
        assert len(line.split(":")) == 4
    # init_ui_db() is idempotent on a migrated DB.
    dashboard.init_ui_db()
    dashboard.init_ui_db()


# --------------------------------------------------------------------- reverse proxy


def test_untrusted_peer_cannot_spoof_proxy_headers(env):
    dashboard.configure_proxies("172.30.0.2")
    c = env.app.test_client()
    hdrs = {"X-Forwarded-For": "203.0.113.9", "X-Forwarded-Proto": "https", "X-Forwarded-Host": "evil.example",
            "CF-Connecting-IP": "203.0.113.10", "Cf-Access-Authenticated-User-Email": "boss@example.dk"}
    c.get("/login", environ_base={"REMOTE_ADDR": "192.168.1.50"}, headers=hdrs)
    r = c.post("/login", data={"username": "admin", "password": PW, "csrf": csrf_of(c)},
               environ_base={"REMOTE_ADDR": "192.168.1.50"}, headers=hdrs)
    assert r.status_code == 302
    assert "Secure" not in r.headers["Set-Cookie"] and "Strict-Transport-Security" not in r.headers
    rec = [a for a in env.audit() if a["action"] == "login"][-1]
    assert rec["ip"] == "192.168.1.50" and "cf_user" not in rec and "proxy" not in rec
    row = env.conn.execute("SELECT last_login_ip FROM ui_users WHERE name='admin'").fetchone()
    assert row[0] == "192.168.1.50"
    html = body(c.get("/settings", environ_base={"REMOTE_ADDR": "192.168.1.50"}, headers=hdrs))
    assert "Proxy ikke betroet" in html and "TRUSTED_PROXIES=192.168.1.50" in html


def test_trusted_proxy_sets_client_scheme_and_host(env):
    dashboard.configure_proxies("172.30.0.0/24")
    c = env.app.test_client()
    base = {"REMOTE_ADDR": "172.30.0.2"}
    url = "http://spam.example.dk"     # cloudflared talks plain http to the filter, keeps the Host
    hdrs = {"X-Forwarded-For": "198.51.100.7", "X-Forwarded-Proto": "https",
            "CF-Connecting-IP": "198.51.100.8", "Cf-Ray": "8a1b2c3d4e-CPH",
            "Cf-Access-Authenticated-User-Email": "ole@bynet.example"}
    c.get("/login", environ_base=base, headers=hdrs, base_url=url)
    r = c.post("/login", data={"username": "admin", "password": PW, "csrf": csrf_at(c, url)},
               environ_base=base, headers=dict(hdrs, Origin="https://spam.example.dk"), base_url=url)
    assert r.status_code == 302
    cookie = r.headers["Set-Cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=Strict" in cookie
    assert r.headers["Strict-Transport-Security"] == "max-age=31536000"
    rec = [a for a in env.audit() if a["action"] == "login"][-1]
    assert rec["ip"] == "198.51.100.8"            # CF-Connecting-IP wins
    assert rec["proxy"] == "172.30.0.2" and rec["cf_user"] == "ole@bynet.example"
    url_s = "https://spam.example.dk"   # the browser side of the tunnel
    html = body(c.get("/settings", environ_base=base, headers=hdrs, base_url=url_s))
    assert "Krypteret forbindelse (HTTPS)" in html and "Via Cloudflare Tunnel." in html
    assert "ole@bynet.example" in html and "198.51.100.8" in html
    # Same-origin POST through the tunnel passes the Origin check.
    r = c.post("/users/bo/2fa/require", data={"required": "1", "csrf": csrf_at(c, url_s)}, environ_base=base,
               headers=dict(hdrs, Origin="https://spam.example.dk", Accept="application/json",
                            **{"X-Requested-With": "fetch"}), base_url=url_s)
    assert r.status_code == 200 and r.get_json()["ok"]
    # The audit tab shows the Cloudflare Access identity.
    assert "ole@bynet.example" in body(c.get("/system?tab=audit", environ_base=base, headers=hdrs, base_url=url_s))


def _through_middleware(remote: str, headers: dict[str, str]) -> dict:
    """Run one WSGI environ through dashboard.ProxyHeaders."""
    seen: dict = {}

    def app(environ, start_response):
        seen.update(environ)
        return []

    environ = {"REMOTE_ADDR": remote, "wsgi.url_scheme": "http", "HTTP_HOST": "192.168.1.10:18080"}
    environ.update({"HTTP_" + k.upper().replace("-", "_"): v for k, v in headers.items()})
    dashboard.ProxyHeaders(app)(environ, lambda *a: None)
    return seen


def test_x_forwarded_for_takes_rightmost_untrusted_hop():
    dashboard.configure_proxies("172.30.0.2, 10.9.0.0/16")
    try:
        e = _through_middleware("172.30.0.2", {"X-Forwarded-For": "1.1.1.1, 203.0.113.5, 10.9.1.1",
                                               "X-Forwarded-Proto": "http, https",
                                               "X-Forwarded-Host": "spam.example.dk"})
        assert (e["REMOTE_ADDR"], e["wsgi.url_scheme"], e["HTTP_HOST"]) == ("203.0.113.5", "https", "spam.example.dk")
        assert e["sf.peer"] == "172.30.0.2" and e["sf.proxied"] is True
        # Every hop trusted: the left-most one is the client.
        e = _through_middleware("172.30.0.2", {"X-Forwarded-For": "10.9.0.4, 10.9.1.1"})
        assert e["REMOTE_ADDR"] == "10.9.0.4"
        # Garbage is ignored, never trusted.
        e = _through_middleware("172.30.0.2", {"X-Forwarded-For": "not-an-ip", "X-Forwarded-Proto": "gopher",
                                               "X-Forwarded-Host": "bad host/x",
                                               "Cf-Access-Authenticated-User-Email": "<script>"})
        assert (e["REMOTE_ADDR"], e["wsgi.url_scheme"], e["HTTP_HOST"]) == ("172.30.0.2", "http", "192.168.1.10:18080")
        assert e["sf.cf_user"] == ""
        # IPv4-mapped IPv6 peer is matched against the IPv4 list; IPv6 clients work.
        e = _through_middleware("::ffff:172.30.0.2", {"X-Forwarded-For": "2001:db8::7"})
        assert e["REMOTE_ADDR"] == "2001:db8::7"
        e = _through_middleware("172.30.0.2", {"CF-Connecting-IP": "[2001:db8::8]:443", "X-Forwarded-For": "9.9.9.9"})
        assert e["REMOTE_ADDR"] == "2001:db8::8"
        # Same headers from an untrusted peer: nothing changes, and it is noted.
        e = _through_middleware("203.0.113.99", {"X-Forwarded-For": "1.2.3.4", "X-Forwarded-Proto": "https",
                                                 "Cf-Access-Authenticated-User-Email": "boss@example.dk"})
        assert (e["REMOTE_ADDR"], e["wsgi.url_scheme"]) == ("203.0.113.99", "http")
        assert e["sf.proxied"] is False and e["sf.ignored_proxy_headers"] is True and e["sf.cf_user"] == ""
        assert "HTTP_CF_ACCESS_AUTHENTICATED_USER_EMAIL" not in e
        # Nobody is trusted by default.
        dashboard.configure_proxies("")
        e = _through_middleware("172.30.0.2", {"X-Forwarded-For": "1.2.3.4", "X-Forwarded-Proto": "https"})
        assert (e["REMOTE_ADDR"], e["wsgi.url_scheme"]) == ("172.30.0.2", "http")
    finally:
        dashboard.configure_proxies("")


def test_trusted_proxy_parsing(monkeypatch):
    nets, bad = dashboard.parse_trusted_proxies("192.168.1.5, 172.18.0.0/16;fd00::/8  nonsense 300.1.1.1")
    assert [str(n) for n in nets] == ["192.168.1.5/32", "172.18.0.0/16", "fd00::/8"]
    assert bad == ["nonsense", "300.1.1.1"]
    monkeypatch.setenv("TRUSTED_PROXIES", "")
    monkeypatch.setenv("TRUSTED_PROXY", "1")      # 2.0 flag: private ranges only now
    dashboard.configure_proxies()
    assert dashboard.is_trusted_proxy("192.168.1.10") and dashboard.is_trusted_proxy("::1")
    assert not dashboard.is_trusted_proxy("8.8.8.8")
    monkeypatch.delenv("TRUSTED_PROXY")
    monkeypatch.setenv("TRUSTED_PROXIES", "192.168.1.7")
    dashboard.configure_proxies()
    assert dashboard.is_trusted_proxy("192.168.1.7") and not dashboard.is_trusted_proxy("192.168.1.8")
    monkeypatch.delenv("TRUSTED_PROXIES")
    dashboard.configure_proxies()
    assert dashboard.TRUSTED_PROXY_NETS == ()


def test_cookie_secure_follows_scheme(env, monkeypatch):
    c = env.app.test_client()
    url = "https://spam.example.dk"
    c.get("/login", base_url=url)
    r = c.post("/login", data={"username": "admin", "password": PW, "csrf": csrf_at(c, url)}, base_url=url)
    assert "Secure" in r.headers["Set-Cookie"] and r.headers["Strict-Transport-Security"]
    c2 = env.app.test_client()
    r = login(c2, "admin", PW)
    assert "Secure" not in r.headers["Set-Cookie"] and "Strict-Transport-Security" not in r.headers
    monkeypatch.setitem(env.app.config, "SESSION_COOKIE_SECURE", True)   # DASHBOARD_COOKIE_SECURE=1
    c3 = env.app.test_client()
    assert "Secure" in login(c3, "admin", PW).headers["Set-Cookie"]


# --------------------------------------------------------------------- origin allowlist + external address


def test_origin_allowlist(env):
    admin = client_for(env, "admin")
    url = "/users/bo/2fa/require"
    ok = post(admin, url, {"required": "1"}, headers={"Origin": "http://localhost"})
    assert ok.status_code == 200
    assert post(admin, url, {"required": "1"}, headers={"Origin": "https://spam.example.dk"}).status_code == 400
    assert post(admin, "/settings/external-url", {"external_url": "spam.example.dk"}).get_json()["ok"]
    assert dashboard.settings_get("external_url") == "https://spam.example.dk"
    for origin in ("https://spam.example.dk", "https://spam.example.dk:443", "http://localhost:80"):
        assert post(admin, url, {"required": "1"}, headers={"Origin": origin}).status_code == 200, origin
    for origin in ("https://evil.example", "https://spam.example.dk:8443", "https://spam.example.dk.evil.example"):
        assert post(admin, url, {"required": "1"}, headers={"Origin": origin}).status_code == 400, origin
    assert post(admin, url, {"required": "1"}, headers={"Referer": "https://evil.example/x"}).status_code == 400
    # Origin: null / absent still fall back to token + SameSite.
    assert post(admin, url, {"required": "1"}, headers={"Origin": "null"}).status_code == 200


@pytest.mark.parametrize("raw,want", [
    ("", ""), ("spam.example.dk", "https://spam.example.dk"), ("https://Spam.Example.dk/", "https://spam.example.dk"),
    ("http://192.168.1.10:18080", "http://192.168.1.10:18080"), ("https://spam.example.dk:8443", "https://spam.example.dk:8443"),
])
def test_normalize_external_url(raw, want):
    assert dashboard.normalize_external_url(raw) == want


@pytest.mark.parametrize("raw", ["ftp://x.dk", "https://x.dk/sti", "https://u:p@x.dk", "https://x.dk?q=1",
                                 "https://a b.dk", "https://", "https://x.dk:99999", "javascript:alert(1)"])
def test_normalize_external_url_rejects(raw):
    with pytest.raises(ValueError):
        dashboard.normalize_external_url(raw)


def test_external_url_setting_is_admin_only_and_audited(env):
    admin = client_for(env, "admin")
    r = post(admin, "/settings/external-url", {"external_url": "https://spam.example.dk/sti"})
    assert r.get_json()["ok"] is False and dashboard.settings_get("external_url") is None
    assert post(admin, "/settings/external-url", {"external_url": "https://spam.example.dk"}).get_json()["ok"]
    rec = [a for a in env.audit() if a["action"] == "settings_external_url"][-1]
    assert rec["detail"] == "- -> https://spam.example.dk"
    html = body(admin.get("/settings"))
    assert 'value="https://spam.example.dk"' in html and 'id="ekstern"' in html
    assert "https://spam.example.dk" in body(admin.get("/me"))   # app guide points at it
    anna = client_for(env, "anna")
    assert post(anna, "/settings/external-url", {"external_url": "https://x.dk"}).status_code == 403
    assert post(admin, "/settings/external-url", {"external_url": ""}).get_json()["ok"]
    assert dashboard.settings_get("external_url") == ""


def test_settings_connection_card_on_lan(env):
    admin = client_for(env, "admin")
    html = body(admin.get("/settings"))
    assert "Adgang udefra" in html and "Lokal forbindelse (HTTP)" in html
    assert "Ingen – TRUSTED_PROXIES er tom" in html and "Cloudflare Tunnel" in html
    assert "Din konto" in html and 'href="/me"' in html
    assert "Spamfilter på hjemmeskærmen" in html


def test_settings_warns_about_admins_without_2fa_when_exposed(env):
    dashboard.configure_proxies("172.30.0.2")
    admin = client_for(env, "admin")
    hdrs = {"X-Forwarded-Proto": "https", "X-Forwarded-For": "198.51.100.1"}
    html = body(admin.get("/settings", environ_base={"REMOTE_ADDR": "172.30.0.2"}, headers=hdrs))
    assert "To-trins-login mangler" in html and "Cloudflare Access" in html


# --------------------------------------------------------------------- PWA


def png_size(data: bytes) -> tuple[int, int]:
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    w, h = struct.unpack(">II", data[16:24])
    return w, h


def test_manifest(env):
    c = env.app.test_client()
    r = c.get("/manifest.webmanifest")
    assert r.status_code == 200 and r.mimetype == "application/manifest+json"
    assert r.headers["Cache-Control"] == "public, max-age=3600" and "Set-Cookie" not in r.headers
    m = json.loads(r.get_data(as_text=True))
    assert m["display"] == "standalone" and m["start_url"] == "/" and m["scope"] == "/" and m["lang"] == "da"
    assert m["short_name"] == "Spamfilter" and m["theme_color"] == kit.THEME_DARK
    purposes = {(i["sizes"], i["purpose"]) for i in m["icons"]}
    assert {("192x192", "any"), ("512x512", "any"), ("512x512", "maskable")} <= purposes
    for icon in m["icons"]:
        res = c.get(icon["src"])
        assert res.status_code == 200 and res.mimetype == "image/png"
        assert res.headers["Cache-Control"] == "public, max-age=31536000, immutable"
        assert "%dx%d" % png_size(res.get_data()) == icon["sizes"]


def test_apple_touch_icon(env):
    c = env.app.test_client()
    for path in ("/apple-touch-icon.png", "/apple-touch-icon-precomposed.png"):
        r = c.get(path)
        assert r.status_code == 200 and r.mimetype == "image/png"
        assert png_size(r.get_data()) == (180, 180)
        assert r.headers["Cache-Control"] == "public, max-age=86400"


def test_icons_are_opaque_where_platforms_need_it(env):
    """Maskable + apple-touch icons are full-bleed (RGB, no alpha): iOS
    would paint transparent corners black."""
    for name in ("icon-maskable-192.png", "icon-maskable-512.png", "apple-touch-icon.png"):
        data = (dashboard.STATIC_DIR / name).read_bytes()
        assert data[25] == 2, name           # colour type 2 = RGB
    for name in ("icon-192.png", "icon-512.png"):
        data = (dashboard.STATIC_DIR / name).read_bytes()
        assert data[25] in (2, 6), name


def test_service_worker(env):
    c = env.app.test_client()
    r = c.get("/sw.js")
    assert r.status_code == 200 and r.mimetype == "text/javascript"
    assert r.headers["Cache-Control"] == "no-cache" and "Set-Cookie" not in r.headers
    src = r.get_data(as_text=True)
    assert "__SF_" not in src
    assets = json.loads(re.search(r"var ASSETS = (\[.*?\]);", src).group(1))
    assert all(a.startswith("/static/") and "?v=" in a for a in assets)
    assert set(a.split("?")[0] for a in assets) >= {"/static/app.css", "/static/app.js", "/static/icons.svg"}
    # Privacy: only /static/ and /offline are ever put in the cache.
    assert src.count("cache.put(") == 1 and "isStaticAsset(url)" in src
    assert 'var OFFLINE = "/offline"' in src and "cache.addAll(ASSETS.concat([OFFLINE]))" in src
    assert 'req.method !== "GET"' in src and "url.origin !== self.location.origin" in src
    nav = src[src.index('if (req.mode === "navigate")'):src.index("if (isStaticAsset(url))")]
    assert "fetch(req).catch" in nav and "put(" not in nav
    assert "/api/" not in src.replace("/api/...", "")
    # A changed asset gives a new worker (new cache name).
    tag = json.loads(re.search(r"var VERSION = (\".*?\");", src).group(1))
    assert tag == dashboard.static_url("app.css").split("?v=")[1]


def test_offline_page_is_public_and_sessionless(env):
    c = env.app.test_client()
    r = c.get("/offline")
    assert r.status_code == 200 and r.headers["Cache-Control"] == "no-cache"
    assert "Set-Cookie" not in r.headers
    html = body(r)
    assert "Du er offline" in html and 'name="csrf-token"' not in html and "data-offline" in html
    for rx, what in INLINE_PATTERNS:
        assert rx.search(html) is None, what


def test_head_has_pwa_tags_and_csp(env):
    c = env.app.test_client()
    for path in ("/login",):
        r = c.get(path)
        html = body(r)
        assert r.headers["Content-Security-Policy"] == CSP
        assert "manifest-src 'self'" in CSP and "worker-src 'self'" in CSP
        assert '<link rel="manifest" href="/manifest.webmanifest" crossorigin="use-credentials">' in html
        assert '<meta name="theme-color" content="#0b0b0d" media="(prefers-color-scheme: dark)">' in html
        assert '<meta name="theme-color" content="#f7f7f8" media="(prefers-color-scheme: light)">' in html
        assert '<meta name="apple-mobile-web-app-capable" content="yes">' in html
        assert '<meta name="apple-mobile-web-app-title" content="Spamfilter">' in html
        assert 'viewport-fit=cover' in html
        assert re.search(r'<link rel="apple-touch-icon" sizes="180x180" href="/static/apple-touch-icon\.png\?v=', html)


def test_install_guide_on_my_account_page(env):
    anna = client_for(env, "anna")
    html = body(anna.get("/me"))
    assert "Spamfilter på hjemmeskærmen" in html and "Føj til hjemmeskærm" in html and "Installer app" in html
    assert 'data-tab-panel="ios"' in html and 'data-tab-panel="android"' in html
    # A Bruger: no HTTPS / tunnel / LAN talk, and 'Logget ind' instead of 'Sessioner'.
    for s in ("kræver HTTPS", "Cloudflare", "lokale adresse", "Sessioner", "Denne session"):
        assert s not in html, s
    assert "Logget ind" in html and "Denne enhed" in html
    admin_html = body(client_for(env, "admin").get("/me"))
    assert "kræver HTTPS" in admin_html
    assert 'href="/me"' in html                 # sidebar "me" link + mobile sheet
    assert "Indstillinger</a>" not in html      # Bruger: no admin link in the guide


# --------------------------------------------------------------------- CSP-clean new pages


@pytest.mark.parametrize("path", ["/me", "/me/2fa/setup", "/settings", "/users/anna", "/users/new", "/login/2fa"])
def test_new_pages_are_csp_clean(env, path):
    admin = client_for(env, "admin")
    if path == "/login/2fa":
        secret, _ = enroll(env, client_for(env, "anna"), "anna")
        admin = env.app.test_client()
        password_step(admin, "anna")
    r = admin.get(path)
    assert r.status_code == 200, path
    html = body(r)
    for rx, what in INLINE_PATTERNS:
        m = rx.search(html)
        assert m is None, f"{what} on {path}: {html[max(0, m.start() - 80):m.end() + 80]}"


def test_codes_page_is_csp_clean_and_not_cached(env):
    anna = client_for(env, "anna")
    anna.get("/me/2fa/setup")
    secret = twofa_row(env, "anna")["pending_secret"]
    r = anna.post("/me/2fa/confirm", data={"code": dashboard.totp(secret), "csrf": csrf_of(anna)})
    assert r.headers["Cache-Control"] == "no-store"
    for rx, what in INLINE_PATTERNS:
        assert rx.search(body(r)) is None, what


def test_icon_sprite_has_new_icons():
    sprite = (dashboard.STATIC_DIR / "icons.svg").read_text()
    for name in ("smartphone", "share", "plus-square", "more-vertical", "download", "cloud"):
        assert f'id="i-{name}"' in sprite


def test_enroll_button_and_twofa_card_css_hold_in_light_theme():
    """Regression (screenshots): on a phone the 'Åbn i godkendelses-app'
    button is a secondary button restyled with the brand gradient and
    white text; `[data-theme="light"] .btn-secondary {background:#fff}`
    used to win and left white text on white. And the long label
    'Genoprettelseskoder' needs a wider label column in the 2FA card."""
    css = (dashboard.STATIC_DIR / "app.css").read_text()
    m = re.search(r'\.btn\.enroll-btn, \[data-theme="light"\] \.btn\.enroll-btn \{([^}]*)\}', css)
    assert m and "color: #fff" in m.group(1) and "var(--grad)" in m.group(1)
    # 2.10 (Fleetdeck-design): the secondary button takes its colours from the
    # theme tokens; no light-theme rule may paint it white over the gradient.
    assert '[data-theme="light"] .btn-secondary' not in css
    assert re.search(r"\.twofa-card \.kv-row \{ grid-template-columns: 150px", css)


# --------------------------------------------------------------------- deploy plumbing


def test_trusted_proxies_in_versions_env_and_run_args(tmp_path):
    from test_deploy_scripts import DEPLOY, versions
    assert "TRUSTED_PROXIES" in versions() and versions()["TRUSTED_PROXIES"] == ""

    def run_args(extra: str) -> list[str]:
        script = (f'set -euo pipefail\nSPAMFILTER_APP={tmp_path}\n. "{DEPLOY}/lib.sh"\n{extra}\n'
                  'sf_run_args spamfilter; printf "%s\\n" "${SF_OPTS[@]}"')
        out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60)
        assert out.returncode == 0, out.stderr
        return out.stdout.splitlines()

    assert not any("TRUSTED_PROXIES" in a for a in run_args(""))
    args = run_args("TRUSTED_PROXIES=172.18.0.5,10.0.0.0/8")
    assert args[args.index("TRUSTED_PROXIES=172.18.0.5,10.0.0.0/8") - 1] == "-e"
    assert not any("TRUSTED_PROXIES" in a for a in run_args("TRUSTED_PROXIES="))


def test_real_waitress_passes_forwarded_headers_to_our_middleware(env):
    """waitress strips X-Forwarded-* unless told not to; with the options
    start() uses, ProxyHeaders sees them (and alone decides on trust)."""
    import threading
    import urllib.request

    from waitress.server import create_server

    opts = dict(dashboard.SERVE_OPTIONS, host="127.0.0.1", port=0, threads=2)
    assert opts.pop("clear_untrusted_proxy_headers") is False
    # poll(), not waitress' default select(): late in the full suite the
    # process has more than 1024 descriptors open, select() then raises
    # "filedescriptor out of range" in the server thread and the request
    # times out. The serving path under test is the same either way.
    server = create_server(env.app, clear_untrusted_proxy_headers=False, asyncore_use_poll=True, **opts)
    port = server.effective_port
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    try:
        def get(trusted: str) -> dict:
            dashboard.configure_proxies(trusted)
            req = urllib.request.Request(f"http://127.0.0.1:{port}/login",
                                         headers={"X-Forwarded-Proto": "https", "X-Forwarded-For": "198.51.100.4"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return dict(resp.headers)
        assert get("127.0.0.1").get("Strict-Transport-Security") == "max-age=31536000"
        assert "Strict-Transport-Security" not in get("")
    finally:
        server.close()
        dashboard.configure_proxies("")
