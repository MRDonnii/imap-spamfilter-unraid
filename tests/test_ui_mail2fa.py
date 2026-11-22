"""2.3 (B29): two-step login by mail ("Kode på mail") next to the app,
the Mailserver / Notifikationer cards, the Mail card on Drift, security
notices - and the access policy + CSRF of every new route.

Real dashboard + ui_admin + mailer against the fake SMTP from
tests/fakes_ui_mail.py (no network). Codes are read from the delivered
fake mails, exactly as a user would.
"""

from __future__ import annotations

import json
import re
import sqlite3
import stat
import time

import pytest

from fakes_ui import TEST_PASSWORD, csrf_of, fast_hash, login, post
from fakes_ui_admin import make_admin_env
from fakes_ui_mail import SMTP_SECRET, FakeSMTP, configure_smtp, flush, install, last_code, text_of

import dashboard  # noqa: E402
import ui_kit as kit  # noqa: E402
from test_ui_core import INLINE_PATTERNS  # noqa: E402

PW = TEST_PASSWORD
ANNA_MAIL = "anna@bynet.example"


@pytest.fixture
def env(tmp_path, monkeypatch):
    e = make_admin_env(tmp_path, monkeypatch)
    h = fast_hash(PW)
    (e.state / "dashboard_users").write_text("\n".join([
        f"admin:{h}:admin:0", f"anna:{h}:bynet:0", f"bo:{h}:bynet:0"]) + "\n")
    e.mailer = install(monkeypatch)
    dashboard.mail()  # point the mailer at this env
    yield e
    e.mailer.stop_worker()


@pytest.fixture
def smtp(env):
    configure_smtp(dashboard.mail())
    return env


def body(r) -> str:
    return r.get_data().decode("utf-8", "replace")


def client_for(env, name: str | None):
    c = env.app.test_client()
    if name:
        assert login(c, name, PW).status_code == 302
    return c


def password_step(c, name: str, *, remember: bool = False):
    c.get("/login")
    data = {"username": name, "password": PW, "csrf": csrf_of(c)}
    if remember:
        data["remember"] = "1"
    return c.post("/login", data=data)


def code_step(c, code: str):
    return c.post("/login/2fa", data={"code": code, "csrf": csrf_of(c)})


def send_step(c):
    return c.post("/login/2fa", data={"action": "send", "csrf": csrf_of(c)})


def age_codes(env, seconds: int, name: str | None = None) -> None:
    """Move the user's code history back in time (cooldown/window/expiry)."""
    sql = "UPDATE ui_mail_codes SET created_at=created_at-?, expires_at=expires_at-?"
    args: list = [seconds, seconds]
    if name:
        sql += " WHERE name=?"
        args.append(name)
    env.conn.execute(sql, args)
    env.conn.commit()


def enroll_mail(env, c, name: str = "anna", addr: str = ANNA_MAIL) -> list[str]:
    """Run the 'Kode på mail' setup for the logged-in client."""
    r = c.post("/me/2fa/confirm", data={"method": "mail", "step": "send", "email": addr, "csrf": csrf_of(c)})
    assert r.status_code == 200, body(r)[:400]
    flush()
    code = last_code(addr)
    r = c.post("/me/2fa/confirm", data={"method": "mail", "step": "verify", "code": code, "csrf": csrf_of(c)})
    assert r.status_code in (200, 302), body(r)[:400]
    return re.findall(r'<li><code class="mono">([a-z0-9]{5}-[a-z0-9]{5})</code></li>', body(r))


def enroll_app(env, c, name: str) -> str:
    c.get("/me/2fa/setup?method=app")
    secret = env.conn.execute("SELECT pending_secret FROM ui_twofa WHERE name=?", (name,)).fetchone()[0]
    r = c.post("/me/2fa/confirm", data={"code": dashboard.totp(secret), "csrf": csrf_of(c)})
    assert r.status_code in (200, 302)
    return secret


# --------------------------------------------------------------------- offered only with a mail server


def test_mail_method_not_offered_without_a_mail_server(env):
    c = client_for(env, "anna")
    html = body(c.get("/me"))
    assert "Kode på mail" not in html and "method=mail" not in html
    r = c.get("/me/2fa/setup?method=mail")
    assert r.status_code == 302 and r.headers["Location"].endswith("/me")
    # Without a mail server /me/2fa/setup is the app setup as in 2.1.
    assert "otpauth://" in body(c.get("/me/2fa/setup"))
    r = c.post("/me/2fa/confirm", data={"method": "mail", "step": "send", "email": ANNA_MAIL, "csrf": csrf_of(c)},
               headers={"Accept": "application/json", "X-Requested-With": "fetch"})
    assert r.status_code == 400 and r.get_json()["ok"] is False
    assert env.conn.execute("SELECT COUNT(*) FROM ui_mail_codes").fetchone()[0] == 0


def test_setup_offers_both_methods_and_recommends_the_app(smtp):
    c = client_for(smtp, "admin")
    html = body(c.get("/me/2fa/setup"))
    assert "Vælg metode" in html and "/me/2fa/setup?method=app" in html and "/me/2fa/setup?method=mail" in html
    assert "Anbefales til administratorer" in html
    me = body(c.get("/me"))
    assert "Kode på mail" in me and "Authenticator-app" in me


# --------------------------------------------------------------------- setup flow


def test_mail_setup_verifies_the_address_and_gives_recovery_codes(smtp):
    c = client_for(smtp, "anna")
    r = c.post("/me/2fa/confirm", data={"method": "mail", "step": "send", "email": "ikke-en-adresse",
                                        "csrf": csrf_of(c)})
    assert r.status_code == 400 and "gyldig mailadresse" in body(r)
    r = c.post("/me/2fa/confirm", data={"method": "mail", "step": "send", "email": ANNA_MAIL, "csrf": csrf_of(c)})
    assert r.status_code == 200 and "a…@bynet.example" in body(r)
    msgs = flush()
    assert len(msgs) == 1 and msgs[0]["To"] == ANNA_MAIL
    assert msgs[0]["Subject"] == "Bekræft din mailadresse til Spamfilter"
    code = last_code(ANNA_MAIL)
    # Only a salted hash is stored - never the code itself.
    rows = smtp.conn.execute("SELECT * FROM ui_mail_codes").fetchall()
    assert len(rows) == 1 and code not in json.dumps([list(r) for r in rows])
    assert len(rows[0]["salt"]) == 32 and len(rows[0]["code_hash"]) == 64
    assert code.encode() not in (smtp.state / "spamfilter.db").read_bytes()
    wrong = "000000" if code != "000000" else "111111"
    r = c.post("/me/2fa/confirm", data={"method": "mail", "step": "verify", "code": wrong, "csrf": csrf_of(c)})
    assert r.status_code == 400 and "passer ikke" in body(r)
    assert not dashboard.twofa_status("anna")["enabled"]
    r = c.post("/me/2fa/confirm", data={"method": "mail", "step": "verify", "code": code, "csrf": csrf_of(c)})
    assert r.status_code == 200
    codes = re.findall(r'<li><code class="mono">([a-z0-9]{5}-[a-z0-9]{5})</code></li>', body(r))
    assert len(codes) == 8 and "en kode fra mailen" in body(r)
    st = dashboard.twofa_status("anna")
    assert st["enabled"] and st["mail"] and not st["totp"] and st["mail_masked"] == "a…@bynet.example"
    assert st["recovery_left"] == 8
    assert dashboard.twofa_mail_address("anna") == ANNA_MAIL
    acts = [a["action"] for a in smtp.audit()]
    assert "twofa_mail_enable" in acts
    for a in smtp.audit():
        assert ANNA_MAIL not in json.dumps(a) and code not in json.dumps(a)
    # Security notice to the user's own (now verified) address.
    msgs = flush()
    assert any(m["To"] == ANNA_MAIL and "kode på mail er slået til" in m["Subject"] for m in msgs)
    # The same verification code cannot be used twice.
    r = c.post("/me/2fa/confirm", data={"method": "mail", "step": "verify", "code": code, "csrf": csrf_of(c)})
    assert r.status_code == 400


def test_rollback_safe_tables(smtp):
    c = client_for(smtp, "anna")
    enroll_mail(smtp, c)
    row = smtp.conn.execute("SELECT * FROM ui_twofa WHERE name='anna'").fetchone()
    # 2.2.0 reads ui_twofa only: no secret -> it sees 2FA off (password login, no lock-out).
    assert row["secret"] is None and row["enabled_at"] is None
    cols = [r[1] for r in smtp.conn.execute("PRAGMA table_info(ui_twofa)")]
    assert cols == ["name", "secret", "enabled_at", "last_step", "recovery", "pending_secret", "pending_at",
                    "required", "updated_at", "updated_by"]
    dashboard.init_ui_db()
    dashboard.init_ui_db()


# --------------------------------------------------------------------- login flows


def test_login_mail_only(smtp):
    c = client_for(smtp, "anna")
    enroll_mail(smtp, c)
    flush()
    age_codes(smtp, 61)  # past the resend cooldown of the verification mail
    c = smtp.app.test_client()
    r = password_step(c, "anna")
    assert r.status_code == 302 and "/login/2fa" in r.headers["Location"]
    msgs = flush()  # mail-only: the code is sent with the password step
    assert len(msgs) == 1 and msgs[0]["Subject"] == "Din login-kode til Spamfilter"
    html = body(c.get("/login/2fa"))
    assert "Send en ny kode til a…@bynet.example" in html and ANNA_MAIL not in html
    assert "Koden er sendt kl." in html and "Du kan få en ny kode om" in html
    # The countdown is app.js' job (button[data-countdown]); no "genindlæs siden" and no "sek..".
    assert re.search(r'<button[^>]*data-countdown="\d+"', html)
    assert "genindlæs" not in html and "sek.." not in html and 'class="nowrap">a…@bynet.example' in html
    for pat, label in INLINE_PATTERNS:
        assert not pat.search(html), label
    code = last_code(ANNA_MAIL)
    r = code_step(c, code)
    assert r.status_code == 302 and r.headers["Location"].endswith("/")
    assert c.get("/me").status_code == 200
    assert smtp.audit()[-1]["detail"].startswith("to-trins-login · kode på mail")
    # Reuse: the same code does not open a second login.
    c2 = smtp.app.test_client()
    password_step(c2, "anna")
    r = code_step(c2, code)
    assert r.status_code == 401 and "Koden passer ikke" in body(r)


def test_login_totp_only_is_unchanged(smtp):
    c = client_for(smtp, "anna")
    secret = enroll_app(smtp, c, "anna")
    flush()
    c = smtp.app.test_client()
    password_step(c, "anna")
    assert flush() == []  # no mail for an app-only user
    html = body(c.get("/login/2fa"))
    assert "godkendelses-app" in html and "Send kode til" not in html
    r = send_step(c)  # posting 'send' does nothing for an app user
    assert r.status_code == 200 and flush() == []
    r = code_step(c, dashboard.totp(secret, time.time() + 30))
    assert r.status_code == 302


def test_login_with_both_methods(smtp):
    c = client_for(smtp, "anna")
    secret = enroll_app(smtp, c, "anna")
    codes = enroll_mail(smtp, c)
    assert codes == []  # the app's recovery codes are kept
    st = dashboard.twofa_status("anna")
    assert st["totp"] and st["mail"] and st["methods"] == ["totp", "mail"] and st["recovery_left"] == 8
    flush()
    # 1) the app code
    c = smtp.app.test_client()
    password_step(c, "anna")
    assert flush() == []  # no automatic mail when the app is there
    html = body(c.get("/login/2fa"))
    assert "Send kode til a…@bynet.example" in html and "eller få en kode på mail" in html
    assert code_step(c, dashboard.totp(secret, time.time() + 30)).status_code == 302
    # 2) a mailed code
    c = smtp.app.test_client()
    password_step(c, "anna")
    age_codes(smtp, 61)
    r = send_step(c)
    assert r.status_code == 200 and "Koden er på vej til a…@bynet.example" in body(r)
    flush()
    assert code_step(c, last_code(ANNA_MAIL)).status_code == 302


def test_recovery_code_works_for_a_mail_user(smtp):
    c = client_for(smtp, "anna")
    codes = enroll_mail(smtp, c)
    c = smtp.app.test_client()
    password_step(c, "anna")
    r = code_step(c, codes[0])
    assert r.status_code == 302
    assert dashboard.twofa_status("anna")["recovery_left"] == 7


def test_resend_cooldown_and_three_sends_per_15_minutes(smtp):
    c = client_for(smtp, "anna")
    enroll_mail(smtp, c)
    smtp.conn.execute("DELETE FROM ui_mail_codes")
    smtp.conn.commit()
    flush()
    c = smtp.app.test_client()
    password_step(c, "anna")  # send 1 (automatic)
    r = send_step(c)  # inside the cooldown
    assert r.status_code == 429 and "Du kan bede om en ny kode om" in body(r)
    age_codes(smtp, 61)
    assert "Koden er på vej" in body(send_step(c))  # send 2
    age_codes(smtp, 61)
    assert "Koden er på vej" in body(send_step(c))  # send 3
    age_codes(smtp, 61)
    r = send_step(c)  # 4th inside 15 min
    assert r.status_code == 429 and "min." in body(r)
    assert len(flush()) == 3
    assert smtp.conn.execute("SELECT COUNT(*) FROM ui_mail_codes").fetchone()[0] == 3
    st = dashboard.mail_code_state("anna")
    assert st["sends_left"] == 0 and st["wait"] > 0
    age_codes(smtp, 15 * 60)
    assert "Koden er på vej" in body(send_step(c))


def test_only_the_newest_code_is_valid(smtp):
    c = client_for(smtp, "anna")
    enroll_mail(smtp, c)
    flush()
    c = smtp.app.test_client()
    password_step(c, "anna")
    flush()
    first = last_code(ANNA_MAIL)
    age_codes(smtp, 61)
    send_step(c)
    flush()
    second = last_code(ANNA_MAIL)
    if first != second:
        assert code_step(c, first).status_code == 401
    assert code_step(c, second).status_code == 302


def test_mail_code_lifecycle_expiry_tries_reuse_and_wrong_user(smtp):
    for name in ("anna", "bo"):
        dashboard.twofa_mail_enable(name, f"{name}@bynet.example", actor="test")
    # Expiry (10 min)
    assert dashboard.mail_code_issue("anna", "anna@bynet.example", "login")["ok"]
    flush()
    code = last_code("anna@bynet.example")
    age_codes(smtp, dashboard.MAIL_CODE_TTL + 1, "anna")
    assert dashboard.mail_code_check("anna", "login", code) is None
    # 5 wrong tries kill the code - even the right one afterwards
    smtp.conn.execute("DELETE FROM ui_mail_codes")
    smtp.conn.commit()
    dashboard.mail_code_issue("anna", "anna@bynet.example", "login")
    flush()
    code = last_code("anna@bynet.example")
    wrong = "999999" if code != "999999" else "888888"
    for _ in range(dashboard.MAIL_CODE_MAX_TRIES):
        assert dashboard.mail_code_check("anna", "login", wrong) is None
    assert smtp.conn.execute("SELECT attempts FROM ui_mail_codes").fetchone()[0] == dashboard.MAIL_CODE_MAX_TRIES
    assert dashboard.mail_code_check("anna", "login", code) is None
    # Single use
    smtp.conn.execute("DELETE FROM ui_mail_codes")
    smtp.conn.commit()
    dashboard.mail_code_issue("anna", "anna@bynet.example", "login")
    flush()
    code = last_code("anna@bynet.example")
    assert dashboard.mail_code_check("anna", "login", code) == "anna@bynet.example"
    assert dashboard.mail_code_check("anna", "login", code) is None
    # Wrong user: anna's code never logs bo in (and a verify code is not a login code)
    dashboard.mail_code_issue("bo", "bo@bynet.example", "login")
    age_codes(smtp, 61, "anna")
    dashboard.mail_code_issue("anna", "anna@bynet.example", "verify")
    flush()
    anna_code = last_code("anna@bynet.example")
    assert dashboard.twofa_verify("bo", anna_code) is None
    assert dashboard.mail_code_check("anna", "login", anna_code) is None
    assert dashboard.mail_code_check("anna", "verify", anna_code) == "anna@bynet.example"
    # Garbage input is just "no"
    for junk in (None, "", "12345", "abcdef", "1234567", "12 34 56x"):
        assert dashboard.mail_code_check("bo", "login", junk) is None


def test_send_reply_is_the_same_when_the_mail_cannot_be_sent(smtp):
    c = client_for(smtp, "anna")
    enroll_mail(smtp, c)
    flush()
    smtp.conn.execute("DELETE FROM ui_mail_codes")
    smtp.conn.commit()
    FakeSMTP.fail_connect = ConnectionRefusedError("down")
    c = smtp.app.test_client()
    password_step(c, "anna")
    age_codes(smtp, 61)
    r1 = send_step(c)
    flush()  # delivery fails in the background
    assert "Koden er på vej til a…@bynet.example" in body(r1)
    FakeSMTP.fail_connect = None
    age_codes(smtp, 61)
    r2 = send_step(c)
    assert r1.status_code == r2.status_code == 200
    strip = lambda h: re.sub(r'value="[^"]*"|kl\. \d\d:\d\d', "", h)  # noqa: E731
    assert strip(body(r1)).count("Koden er på vej") == strip(body(r2)).count("Koden er på vej") == 1


def test_mail_user_without_a_working_mail_server_sees_the_way_out(smtp):
    c = client_for(smtp, "anna")
    codes = enroll_mail(smtp, c)
    dashboard.mail().set_enabled(False)
    c = smtp.app.test_client()
    password_step(c, "anna")
    html = body(c.get("/login/2fa"))
    assert "Mailserveren kan ikke sende koder lige nu" in html and "genoprettelseskode" in html
    assert code_step(c, codes[1]).status_code == 302


def test_required_2fa_is_satisfied_by_mail(smtp):
    dashboard.twofa_set_required("anna", True, "admin")
    c = client_for(smtp, "anna")
    r = c.get("/")
    assert r.status_code == 302 and r.headers["Location"].endswith("/me/2fa/setup")
    html = body(c.get("/me/2fa/setup"))
    assert "Vælg metode" in html
    enroll_mail(smtp, c)
    assert c.get("/").status_code == 200
    # Required + only one method: it cannot be switched off.
    r = post(c, "/me/2fa/disable", {"method": "mail", "code": "123456"})
    assert r.status_code == 403 and dashboard.twofa_status("anna")["mail"]


def test_remove_one_method_keeps_the_other_and_the_recovery_codes(smtp):
    dashboard.twofa_set_required("anna", True, "admin")
    c = client_for(smtp, "anna")
    secret = enroll_app(smtp, c, "anna")
    enroll_mail(smtp, c)
    flush()
    html = body(c.get("/me"))
    assert "Fjern kode på mail" in html and "Slå to-trins-login helt fra" not in html  # required
    r = post(c, "/me/2fa/disable", {"method": "mail", "code": dashboard.totp(secret, time.time() + 30)})
    assert r.get_json()["ok"], r.get_json()
    assert smtp.audit()[-1]["action"] == "twofa_disable" and smtp.audit()[-1]["detail"] == "mail"
    st = dashboard.twofa_status("anna")
    assert st["totp"] and not st["mail"] and st["recovery_left"] == 8
    assert dashboard.twofa_mail_address("anna") is None
    # The removed address is told.
    assert any(ANNA_MAIL in m["To"] and "kode på mail" in m["Subject"].lower() for m in flush())


def test_confirm_changes_with_a_mailed_code(smtp):
    c = client_for(smtp, "anna")
    enroll_mail(smtp, c)
    flush()
    age_codes(smtp, 61)
    r = post(c, "/me/2fa/confirm", {"method": "mail", "step": "code"})
    assert r.get_json()["ok"] and "a…@bynet.example" in r.get_json()["message"]
    msgs = flush()
    assert msgs and msgs[-1]["Subject"] == "Din bekræftelseskode til Spamfilter"
    r = c.post("/me/2fa/recovery", data={"code": last_code(ANNA_MAIL), "csrf": csrf_of(c)})
    assert r.status_code == 200 and "Dine gamle genoprettelseskoder virker ikke længere" in body(r)
    age_codes(smtp, 61)
    post(c, "/me/2fa/confirm", {"method": "mail", "step": "code"})
    flush()
    r = post(c, "/me/2fa/disable", {"method": "all", "code": last_code(ANNA_MAIL)})
    assert r.get_json()["ok"]
    assert not dashboard.twofa_status("anna")["enabled"]
    assert smtp.conn.execute("SELECT COUNT(*) FROM ui_mail_codes WHERE name='anna'").fetchone()[0] == 0


def test_admin_reset_clears_both_methods(smtp):
    c = client_for(smtp, "anna")
    enroll_app(smtp, c, "anna")
    enroll_mail(smtp, c)
    flush()
    admin = client_for(smtp, "admin")
    html = body(admin.get("/users/anna"))
    assert "App" in html and "Mail" in html
    r = post(admin, "/users/anna/2fa/reset")
    assert r.get_json()["ok"]
    st = dashboard.twofa_status("anna")
    assert not st["enabled"] and not st["totp"] and not st["mail"] and st["recovery_left"] == 0
    assert any(ANNA_MAIL in m["To"] and "nulstillet" in m["Subject"] for m in flush())


# --------------------------------------------------------------------- security notices


def test_security_notice_on_new_password(smtp):
    dashboard.mail().save_routes({"security": {"on": True, "to": "sikkerhed@bynet.example"}})
    dashboard.twofa_mail_enable("anna", ANNA_MAIL, actor="test")
    c = client_for(smtp, "admin")
    r = post(c, "/users/anna/password", {"password": "nyt-kodeord-123456", "password2": "nyt-kodeord-123456"})
    assert r.get_json()["ok"], r.get_json()
    msgs = flush()
    rcpts = sorted(m["To"] for m in msgs)
    assert rcpts == [ANNA_MAIL, "sikkerhed@bynet.example"]
    for m in msgs:
        assert m["Subject"] == "Spamfilter: ny adgangskode"
        assert "nyt-kodeord" not in text_of(m) and "anna" in text_of(m)


def test_no_notice_and_no_error_without_a_mail_server(env):
    c = client_for(env, "anna")
    r = post(c, "/me/password", {"current": PW, "password": "nyt-kodeord-123456", "password2": "nyt-kodeord-123456"})
    assert r.get_json()["ok"]
    assert FakeSMTP.sent == [] and env.conn.execute("SELECT COUNT(*) FROM mail_outbox").fetchone()[0] == 0 \
        if env.conn.execute("SELECT name FROM sqlite_master WHERE name='mail_outbox'").fetchone() else True


# --------------------------------------------------------------------- Indstillinger: Mailserver + Notifikationer


def test_settings_cards_render_without_secrets(smtp):
    c = client_for(smtp, "admin")
    html = body(c.get("/settings"))
    assert 'id="mailserver"' in html and 'id="notifikationer"' in html
    assert "Brug postkassens login" in html and "forslag – bekræftes med testmail" in html
    assert "smtp.gigahost.dk:587" in html and "mail.scannet.dk:587" in html
    assert "Send testmail" in html and "(gemt)" in html
    assert SMTP_SECRET not in html
    for pat, label in INLINE_PATTERNS:
        assert not pat.search(html), label
    for kind in ("Alarmer", "Daglig opsummering", "Ugerapport", "Sikkerhed"):
        assert kind in html


def test_save_smtp_settings(env):
    c = client_for(env, "admin")
    data = {"enabled": "1", "host": "smtp.gigahost.dk", "port": "587", "security": "starttls", "auth": "password",
            "username": "ole@bynet.example", "password": SMTP_SECRET, "from_addr": "", "from_name": "Spamfilter"}
    r = post(c, "/settings/smtp", data)
    assert r.get_json()["ok"], r.get_json()
    pw = env.state / "smtp.password"
    assert pw.read_text().strip() == SMTP_SECRET and stat.S_IMODE(pw.stat().st_mode) == 0o600
    audit = env.audit()[-1]
    assert audit["action"] == "settings_smtp" and SMTP_SECRET not in json.dumps(audit)
    assert "password" in audit["detail"]
    assert SMTP_SECRET not in body(c.get("/settings")) and SMTP_SECRET not in env.config.read_text()
    # Validation errors come back in Danish, nothing changes.
    r = post(c, "/settings/smtp", dict(data, port="0"))
    assert r.status_code == 400 and r.get_json()["message"].startswith("Port:")
    # Changing the server without the password again is refused.
    r = post(c, "/settings/smtp", dict(data, host="mail.scannet.dk", password=""))
    assert r.status_code == 400 and "Adgangskode" in r.get_json()["message"]
    assert dashboard.mail().get_settings()["host"] == "smtp.gigahost.dk"
    # Brug postkassens login
    r = post(c, "/settings/smtp", dict(data, auth="account", account="bynet", password=""))
    assert r.get_json()["ok"]
    assert not pw.exists()
    st = dashboard.mail().get_settings()
    assert st["auth"] == "account" and st["account"] == "bynet"


def test_send_test_mail_from_the_ui(smtp):
    c = client_for(smtp, "admin")
    r = post(c, "/settings/smtp/test", {"to": "ole@bynet.example"})
    assert r.get_json()["ok"] and "o…@bynet.example" in r.get_json()["message"]
    assert FakeSMTP.sent[-1][2]["Subject"] == "Testmail fra Spamfilter"
    FakeSMTP.fail_login = __import__("smtplib").SMTPAuthenticationError(535, b"5.7.8 Error: authentication failed")
    r = post(c, "/settings/smtp/test", {"to": "ole@bynet.example"})
    assert r.status_code == 400
    assert r.get_json()["message"] == "Mailserveren afviste brugernavn eller adgangskode."
    assert "5.7.8" not in r.get_json()["message"]
    r = post(c, "/settings/smtp/test", {"to": "ole@bynet.example\r\nBcc: x@evil.example"})
    assert r.status_code == 400 and "ikke gyldig" in r.get_json()["message"]
    html = body(c.get("/settings"))
    assert "Testmailen fejlede" in html or "Seneste afsendelse fejlede" in html


def test_notification_routes(smtp):
    c = client_for(smtp, "admin")
    r = post(c, "/settings/notifications", {"alert_on": "1", "alert_to": "ole@bynet.example, ops@bynet.example",
                                            "digest_on": "1", "digest_to": "ole@bynet.example",
                                            "security_to": "ole@bynet.example"})
    assert r.get_json()["ok"]
    routes = dashboard.mail().get_routes()
    assert routes["alert"] == {"on": True, "to": ["ole@bynet.example", "ops@bynet.example"]}
    assert routes["security"] == {"on": False, "to": ["ole@bynet.example"]}
    assert routes["weekly"]["on"] is False
    audit = smtp.audit()[-1]
    assert audit["action"] == "settings_notify" and "ole@" not in audit["detail"]
    r = post(c, "/settings/notifications", {"alert_on": "1", "alert_to": "ikke en adresse"})
    assert r.status_code == 400 and r.get_json()["message"].startswith("Alarmer:")
    html = body(c.get("/settings"))
    assert "ops@bynet.example" in html


def test_drift_shows_the_mail_card(smtp):
    c = client_for(smtp, "admin")
    html = body(c.get("/system"))
    assert ">Mail<" in html and "smtp.gigahost.dk" in html and "Ikke testet" in html
    post(c, "/settings/smtp/test", {"to": "ole@bynet.example"})
    html = body(c.get("/system"))
    assert "Virker" in html and SMTP_SECRET not in html


def test_drift_without_a_mail_server(env):
    html = body(client_for(env, "admin").get("/system"))
    assert "Ingen mailserver sat op" in html


# --------------------------------------------------------------------- access policy + CSRF


NEW_ADMIN_POSTS = ["/settings/smtp", "/settings/smtp/test", "/settings/notifications"]


def test_new_routes_are_admin_only_under_the_central_policy(smtp):
    for ep in ("settings_smtp", "settings_smtp_test", "settings_notifications"):
        assert dashboard.route_policy(ep) == "admin"
    before = dashboard.mail().get_settings()
    for who in ("anna", "bo"):
        c = client_for(smtp, who)
        for url in NEW_ADMIN_POSTS:
            r = post(c, url, {"enabled": "1", "host": "evil.example", "port": "25", "to": "x@evil.example",
                              "alert_on": "1", "alert_to": "x@evil.example"})
            assert r.status_code == 403, (who, url)
        assert "Mailserver" not in body(c.get("/me"))
    anon = smtp.app.test_client()
    for url in NEW_ADMIN_POSTS:
        r = post(anon, url, {"to": "x@evil.example"})
        assert r.status_code == 401
    assert dashboard.mail().get_settings() == before
    assert dashboard.mail().get_routes()["alert"]["on"] is False
    assert all("evil" not in str(m[1]) for m in FakeSMTP.sent)


def test_every_new_post_needs_the_csrf_token(smtp):
    c = client_for(smtp, "admin")
    for url in NEW_ADMIN_POSTS:
        r = c.post(url, data={"to": "ole@bynet.example", "host": "x.dk"}, headers={"Accept": "application/json"})
        assert r.status_code == 400, url
    anna = client_for(smtp, "anna")
    r = anna.post("/me/2fa/confirm", data={"method": "mail", "step": "send", "email": ANNA_MAIL})
    assert r.status_code == 400
    assert smtp.conn.execute("SELECT COUNT(*) FROM ui_mail_codes").fetchone()[0] == 0
    # The login code step checks its own token too (like /login).
    dashboard.twofa_mail_enable("anna", ANNA_MAIL, actor="test")
    c = smtp.app.test_client()
    password_step(c, "anna")
    n = smtp.conn.execute("SELECT COUNT(*) FROM ui_mail_codes").fetchone()[0]
    age_codes(smtp, 61)
    r = c.post("/login/2fa", data={"action": "send"})
    assert r.status_code == 400 and "udløbet" in body(r)
    assert smtp.conn.execute("SELECT COUNT(*) FROM ui_mail_codes").fetchone()[0] == n


def test_bruger_sees_only_own_2fa_and_preview_hides_it(smtp):
    dashboard.twofa_mail_enable("anna", ANNA_MAIL, actor="test")
    bo = client_for(smtp, "bo")
    html = body(bo.get("/me"))
    assert "a…@bynet.example" not in html and ANNA_MAIL not in html
    admin = client_for(smtp, "admin")
    html = body(admin.get("/users/anna/preview?p=me"))
    assert "a…@bynet.example" not in html and ANNA_MAIL not in html


def test_mobile_markup_is_server_rendered_and_csp_clean(smtp):
    """No inline JS/CSS on the new pages; the mail login box and the method
    rows use the shared components (rendered at 390 px by app.css)."""
    c = client_for(smtp, "anna")
    pages = [c.get("/me").get_data(as_text=True), c.get("/me/2fa/setup").get_data(as_text=True),
             c.get("/me/2fa/setup?method=mail").get_data(as_text=True)]
    for html in pages:
        for pat, label in INLINE_PATTERNS:
            assert not pat.search(html), label
    css = (dashboard.STATIC_DIR / "app.css").read_text()
    block = css.split("/* 2.3 mailer", 1)[1]
    assert "@media (max-width: 560px)" in block and "/* end 2.3 mailer */" in block
    js = (dashboard.STATIC_DIR / "admin.js").read_text()
    assert "initSmtpForms" in js
