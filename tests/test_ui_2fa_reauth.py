"""2.3 fixer: a logged-in session can only add or swap a second factor
after proving an EXISTING one (TOTP, a code to the current verified
address, or a recovery code). Regression tests for the review finding
"session thief swaps the factor and turns the real one off".

Real dashboard + mailer against the fake SMTP (no network).
"""

from __future__ import annotations

import re
import time

from fakes_ui import csrf_of, post
from fakes_ui_mail import flush, last_code
from test_ui_mail2fa import (ANNA_MAIL, age_codes, body, client_for, code_step, enroll_app,  # noqa: F401
                             enroll_mail, env, password_step, smtp)

import dashboard  # noqa: E402

EVIL = "evil@attacker.example"


def _expire_reauth(c) -> None:
    """The proof from enrolling is only valid for TWOFA_REAUTH_TTL."""
    with c.session_transaction() as s:
        s.pop("reauth_2fa", None)


def test_app_user_session_cannot_enrol_an_attacker_address(smtp):
    c = client_for(smtp, "anna")
    secret = enroll_app(smtp, c, "anna")
    flush()
    _expire_reauth(c)
    # The setup page asks for a code first.
    html = body(c.get("/me/2fa/setup?method=mail"))
    assert "Bekræft, at det er dig" in html and 'name="method" value="reauth"' in html
    assert 'name="email"' not in html
    # Posting directly is refused too: no verification mail to the attacker.
    r = post(c, "/me/2fa/confirm", {"method": "mail", "step": "send", "email": EVIL})
    assert r.status_code == 403 and r.get_json()["ok"] is False
    assert flush() == []
    assert smtp.conn.execute("SELECT COUNT(*) FROM ui_mail_codes").fetchone()[0] == 0
    r = post(c, "/me/2fa/confirm", {"method": "mail", "step": "verify", "code": "123456"})
    assert r.status_code == 403
    st = dashboard.twofa_status("anna")
    assert st["totp"] and not st["mail"]
    # A wrong code does not open the gate.
    r = c.post("/me/2fa/confirm", data={"method": "reauth", "next": "/me/2fa/setup?method=mail",
                                        "code": "000000", "csrf": csrf_of(c)})
    assert r.status_code == 302 and "Bekræft, at det er dig" in body(c.get("/me/2fa/setup?method=mail"))
    # The real app code does; then the address can be added (no new recovery codes).
    r = c.post("/me/2fa/confirm", data={"method": "reauth", "next": "/me/2fa/setup?method=mail",
                                        "code": dashboard.totp(secret, time.time() + 30), "csrf": csrf_of(c)})
    assert r.status_code == 302 and r.headers["Location"].endswith("/me/2fa/setup?method=mail")
    assert 'name="email"' in body(c.get("/me/2fa/setup?method=mail"))
    assert enroll_mail(smtp, c) == []
    assert dashboard.twofa_status("anna")["recovery_left"] == 8
    assert any(a["action"] == "twofa_reauth" and a["result"] == "ok" for a in smtp.audit())


def test_session_thief_cannot_disable_totp_with_a_self_enrolled_address(smtp):
    """The exact attack of the review: enrol evil@, mail a code, disable 'all'."""
    c = client_for(smtp, "anna")
    enroll_app(smtp, c, "anna")
    flush()
    _expire_reauth(c)
    post(c, "/me/2fa/confirm", {"method": "mail", "step": "send", "email": EVIL})
    assert flush() == []
    post(c, "/me/2fa/confirm", {"method": "mail", "step": "code"})  # nothing to send to: mail is off
    r = post(c, "/me/2fa/disable", {"method": "all", "code": "123456"})
    assert r.get_json()["ok"] is False
    st = dashboard.twofa_status("anna")
    assert st["enabled"] and st["totp"] and st["recovery_left"] == 8


def test_mail_user_cannot_swap_the_address_without_a_code_to_the_old_one(smtp):
    c = client_for(smtp, "anna")
    enroll_mail(smtp, c)
    flush()
    _expire_reauth(c)
    html = body(c.get("/me/2fa/setup?method=mail"))
    assert "Bekræft, at det er dig" in html
    # The reauth page offers a code to the CURRENT address and comes back here.
    assert "Send kode til a…@bynet.example" in html and 'name="next" value="/me/2fa/setup?method=mail"' in html
    r = post(c, "/me/2fa/confirm", {"method": "mail", "step": "send", "email": EVIL})
    assert r.status_code == 403 and flush() == []
    assert dashboard.twofa_mail_address("anna") == ANNA_MAIL
    age_codes(smtp, 61)
    r = c.post("/me/2fa/confirm", data={"method": "mail", "step": "code", "next": "/me/2fa/setup?method=mail",
                                        "csrf": csrf_of(c)})
    assert r.status_code == 302 and r.headers["Location"].endswith("/me/2fa/setup?method=mail")
    msgs = flush()
    assert msgs and msgs[-1]["To"] == ANNA_MAIL
    r = c.post("/me/2fa/confirm", data={"method": "reauth", "next": "/me/2fa/setup?method=mail",
                                        "code": last_code(ANNA_MAIL), "csrf": csrf_of(c)})
    assert r.status_code == 302
    age_codes(smtp, 61)
    assert enroll_mail(smtp, c, addr="anna2@bynet.example") == []
    assert dashboard.twofa_mail_address("anna") == "anna2@bynet.example"


def test_mail_user_session_cannot_add_an_attacker_app_then_drop_mail(smtp):
    c = client_for(smtp, "anna")
    enroll_mail(smtp, c)
    flush()
    _expire_reauth(c)
    html = body(c.get("/me/2fa/setup?method=app"))
    assert "Bekræft, at det er dig" in html and "otpauth://" not in html
    assert smtp.conn.execute("SELECT pending_secret FROM ui_twofa WHERE name='anna'").fetchone()[0] is None
    # Even with a pending secret from earlier, the confirm POST is gated.
    secret = dashboard.twofa_pending_secret("anna")
    r = post(c, "/me/2fa/confirm", {"code": dashboard.totp(secret, time.time())})
    assert r.status_code == 403
    st = dashboard.twofa_status("anna")
    assert st["mail"] and not st["totp"]


def test_open_redirect_is_impossible_and_recovery_code_proves_too(smtp):
    c = client_for(smtp, "anna")
    codes = enroll_mail(smtp, c)
    _expire_reauth(c)
    r = c.post("/me/2fa/confirm", data={"method": "reauth", "next": "https://evil.example/",
                                        "code": codes[0], "csrf": csrf_of(c)})
    assert r.status_code == 302 and r.headers["Location"].endswith("/me")
    assert "otpauth://" in body(c.get("/me/2fa/setup?method=app"))  # the recovery code counted
    assert dashboard.twofa_status("anna")["recovery_left"] == 7


def test_a_fresh_two_step_login_counts_as_proof(smtp):
    c = client_for(smtp, "anna")
    secret = enroll_app(smtp, c, "anna")
    c = smtp.app.test_client()
    password_step(c, "anna")
    assert code_step(c, dashboard.totp(secret, time.time() + 30)).status_code == 302
    assert 'name="email"' in body(c.get("/me/2fa/setup?method=mail"))
    # ... but only for TWOFA_REAUTH_TTL.
    with c.session_transaction() as s:
        s["reauth_2fa"] = ["anna", int(time.time()) - dashboard.TWOFA_REAUTH_TTL - 5]
    assert "Bekræft, at det er dig" in body(c.get("/me/2fa/setup?method=mail"))
    # A proof for another user never counts.
    with c.session_transaction() as s:
        s["reauth_2fa"] = ["bo", int(time.time())]
    assert "Bekræft, at det er dig" in body(c.get("/me/2fa/setup?method=mail"))


def test_users_without_two_step_login_are_not_asked(smtp):
    c = client_for(smtp, "bo")
    assert 'name="email"' in body(c.get("/me/2fa/setup?method=mail"))
    assert "otpauth://" in body(c.get("/me/2fa/setup?method=app"))
    assert re.search(r"Vælg metode", body(c.get("/me/2fa/setup")))


# --------------------------------------------------------------------- mail flood (review finding)


def test_own_password_changes_and_their_notices_are_rate_limited(smtp, monkeypatch):
    """A Bruger alternating two passwords cannot flood the 'Sikkerhed'
    recipients or the shared mail budget."""
    from fakes_ui import TEST_PASSWORD
    dashboard.mail().save_routes({"security": {"on": True, "to": "sikkerhed@bynet.example"}})
    monkeypatch.setattr(dashboard, "SECURITY_NOTICE_MAX", 3)
    c = client_for(smtp, "bo")
    pws = [TEST_PASSWORD, "andet-kodeord-12345"]
    codes = []
    for i in range(dashboard.PWCHANGE_MAX_PER_HOUR + 1):
        cur, new = pws[i % 2], pws[(i + 1) % 2]
        r = post(c, "/me/password", {"current": cur, "password": new, "password2": new})
        codes.append(r.status_code)
    assert codes[:dashboard.PWCHANGE_MAX_PER_HOUR] == [200] * dashboard.PWCHANGE_MAX_PER_HOUR
    assert codes[-1] == 429
    msgs = [m for m in flush() if m["To"] == "sikkerhed@bynet.example"]
    assert len(msgs) == 3   # SECURITY_NOTICE_MAX
    assert any(a["action"] == "security_notice" and a["result"] == "skipped" for a in smtp.audit())
