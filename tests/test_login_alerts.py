"""2.6 (B2): login alerts - new-device logins (device cookie + coarse
browser/OS label, history under Min konto, mail kind 'security' + push to
the user's own devices) and repeated failed logins (one alert to the
administrators per username/IP per hour, mail + push). Never a password,
code, cookie or token in any message.
"""

from __future__ import annotations

import json

import pytest

from fakes_push import FakePushService, device
from fakes_ui import TEST_PASSWORD, csrf_of, fast_hash
from fakes_ui_admin import make_admin_env
from fakes_ui_mail import configure_smtp, install

import dashboard  # noqa: E402
import login_alerts  # noqa: E402
import mailer  # noqa: E402
import push  # noqa: E402
import webpush  # noqa: E402

PW = TEST_PASSWORD
IPHONE = ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
          "Version/18.1 Mobile/15E148 Safari/604.1")
WINDOWS = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 "
           "Safari/537.36")
ADMIN_MAIL = "admin@bynet.example"
ANNA_MAIL = "anna@bynet.example"
WRONG = "forkert-hemmelig-kode-77"


@pytest.fixture
def env(tmp_path, monkeypatch):
    e = make_admin_env(tmp_path, monkeypatch)
    h = fast_hash(PW)
    (e.state / "dashboard_users").write_text(f"admin:{h}:admin:0\nanna:{h}:bynet:0\n")
    e.mailer = install(monkeypatch)
    m = dashboard.mail()
    configure_smtp(m)
    assert m.save_routes({"security": {"on": True, "to": ADMIN_MAIL}})["ok"]
    monkeypatch.setattr(dashboard, "twofa_mail_address", lambda n: ANNA_MAIL if n == "anna" else None)
    for name in ("STATE_DIR", "CONFIG_PATH", "DB_PATH", "USERS_FILE", "AUTO_WORKER"):
        monkeypatch.setattr(push, name, getattr(push, name))
    monkeypatch.setattr(push, "AUTO_WORKER", False)
    monkeypatch.setenv("PUSH_VAPID_SUBJECT", "mailto:ole@example.com")   # .example is refused by push services
    push.configure_paths(e.state, e.config, db_path=e.state / "spamfilter.db", users_file=e.state / "dashboard_users")
    push.ensure_schema()
    svc = FakePushService()
    real_send = webpush.send
    monkeypatch.setattr(webpush, "send", lambda *a, **k: real_send(*a, **{**k, "session": svc}))
    e.svc = svc
    yield e
    e.mailer.stop_worker()


def client(env, ua: str = IPHONE, ip: str = "203.0.113.7"):
    c = env.app.test_client()
    c.environ_base["REMOTE_ADDR"] = ip
    c.environ_base["HTTP_USER_AGENT"] = ua
    return c


def pw_login(c, name: str, password: str = PW):
    c.get("/login")
    return c.post("/login", data={"username": name, "password": password, "csrf": csrf_of(c)})


def outbox(env) -> list[dict]:
    return [dict(r) for r in env.conn.execute("SELECT kind, recipient, subject, body_text FROM mail_outbox "
                                              "ORDER BY id").fetchall()]


def queue(env, kind: str | None = None) -> list[dict]:
    rows = env.conn.execute("SELECT user, kind, data FROM push_queue ORDER BY id").fetchall()
    return [dict(r) for r in rows if kind is None or r["kind"] == kind]


def history(env, name: str) -> list[dict]:
    return [dict(r) for r in env.conn.execute("SELECT * FROM ui_login_history WHERE name=? ORDER BY id",
                                              (name,)).fetchall()]


def add_device(env, user: str, prefs: dict | None = None):
    dev = device()
    env.svc.add(dev)
    res = push.subscribe(user, dev.endpoint, dev.p256dh, dev.auth, user_agent="iPhone · app", prefs=prefs,
                         is_admin=user == "admin")
    assert res["ok"], res
    return dev


# --------------------------------------------------------------------- device cookie


def test_login_page_sets_a_device_cookie_once(env):
    c = client(env)
    r = c.get("/login")
    cookies = r.headers.getlist("Set-Cookie")
    dev = [x for x in cookies if x.startswith(login_alerts.DEVICE_COOKIE + "=")]
    assert len(dev) == 1 and "HttpOnly" in dev[0] and "SameSite=Strict" in dev[0] and "Secure" not in dev[0]
    assert "Max-Age=34560000" in dev[0]
    assert not [x for x in c.get("/login").headers.getlist("Set-Cookie")
                if x.startswith(login_alerts.DEVICE_COOKIE + "=")]
    # The session cookie is still the first one a login sets (unchanged).
    r = c.post("/login", data={"username": "anna", "password": PW, "csrf": csrf_of(c)})
    assert r.headers["Set-Cookie"].startswith("spamfilter_session=")
    https = env.app.test_client().get("/login", base_url="https://spam.example.dk")
    assert any("Secure" in x for x in https.headers.getlist("Set-Cookie") if x.startswith("sf_device="))


def test_device_label_is_coarse():
    assert login_alerts.device_label(IPHONE) == "Safari på iPhone"
    assert login_alerts.device_label(WINDOWS) == "Chrome på Windows"
    assert login_alerts.device_label("Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0") == \
        "Firefox på Linux"
    assert login_alerts.device_label("") == "Browser på ukendt enhed"


# --------------------------------------------------------------------- new device


def test_first_device_is_silent_then_a_new_device_alerts(env):
    add_device(env, "anna")
    c = client(env)
    assert pw_login(c, "anna").status_code == 302
    assert outbox(env) == [] and queue(env) == []           # the very first device: no alert flood
    (h1,) = history(env, "anna")
    assert h1["label"] == "Safari på iPhone" and h1["method"] == "password" and h1["new_device"] == 0
    # Same browser again: known device, nothing.
    c.post("/logout", data={"csrf": csrf_of(c)})
    assert pw_login(c, "anna").status_code == 302
    assert outbox(env) == []
    # Another browser: alert.
    dashboard.settings_set("external_url", "https://spam.example.dk")
    d = client(env, WINDOWS, "198.51.100.23")
    assert pw_login(d, "anna").status_code == 302
    mails = outbox(env)
    assert [(m["kind"], m["recipient"]) for m in mails] == [("security", ANNA_MAIL), ("security", ADMIN_MAIL)]
    own = mails[0]["body_text"]
    assert own.startswith("Nyt login på din konto: Chrome på Windows, ")
    assert "IP 198.51.100.23" in own and "Var det ikke dig? Skift adgangskode og log ud overalt." in own
    assert "https://spam.example.dk/me#logins" in own
    assert "anna" in mails[1]["subject"] and "Brugeren anna er logget ind fra en ny enhed" in mails[1]["body_text"]
    for m in mails:
        assert PW not in m["body_text"] and "sf_device" not in m["body_text"]
    (q,) = queue(env, "login")
    assert q["user"] == "anna"
    assert json.loads(q["data"])["logins"][0]["ua"] == "Chrome på Windows"
    payload = push.render("anna", "login", json.loads(q["data"]))
    assert payload["title"] == "Nyt login på din konto" and payload["url"] == "/me#logins"
    assert "Chrome på Windows" in payload["body"] and "198.51.100.23" in payload["body"]
    assert "Var det ikke dig?" in payload["body"]
    rec = [a for a in env.audit() if a["action"] == "login_new_device"][-1]
    assert rec["actor"] == "anna" and rec["detail"] == "Chrome på Windows · adgangskode"
    assert history(env, "anna")[-1]["new_device"] == 1


def test_mail_link_never_follows_the_host_header(env):
    pw_login(client(env), "anna")
    c = client(env, WINDOWS)
    c.get("/login", base_url="http://evil.example")
    c.post("/login", data={"username": "anna", "password": PW, "csrf": csrf_of_at(c, "http://evil.example")},
           base_url="http://evil.example")
    mails = outbox(env)
    assert mails and all("evil.example" not in m["body_text"] for m in mails)
    assert "under Min konto i spamfilteret" in mails[0]["body_text"]


def csrf_of_at(c, base: str) -> str:
    with c.session_transaction(base_url=base) as s:
        return s.get("csrf", "")


def test_push_goes_to_every_device_of_the_user_and_is_delivered(env):
    dev = add_device(env, "anna", prefs={"threat": False, "review": False, "problem": False})
    pw_login(client(env), "anna")
    pw_login(client(env, WINDOWS), "anna")
    stats = push.process_queue()
    assert stats["sent"] == 1
    (call,) = [x for x in env.svc.calls if x["url"] == dev.endpoint]
    assert call["payload"]["title"] == "Nyt login på din konto" and call["payload"]["tag"] == "sf-login"


def test_no_push_without_a_device_and_no_mail_without_smtp(env, monkeypatch):
    pw_login(client(env), "anna")
    monkeypatch.setattr(mailer, "is_configured", lambda *a, **k: False)
    pw_login(client(env, WINDOWS), "anna")
    assert outbox(env) == [] and queue(env) == []
    assert [a for a in env.audit() if a["action"] == "login_new_device"]   # still audited


def test_new_device_notices_are_rate_limited(env, monkeypatch):
    monkeypatch.setattr(login_alerts, "NEW_DEVICE_PER_HOUR", 2)
    pw_login(client(env), "anna")
    for i in range(4):
        pw_login(client(env, ip=f"198.51.100.{i + 1}"), "anna")
    own = [m for m in outbox(env) if m["recipient"] == ANNA_MAIL]
    assert len(own) == 2
    assert [a for a in env.audit() if a["action"] == "login_new_device_notice" and a["result"] == "skipped"]


def test_country_only_through_a_trusted_proxy(env, monkeypatch):
    pw_login(client(env), "anna")
    spoof = client(env, WINDOWS)
    spoof.environ_base["HTTP_CF_IPCOUNTRY"] = "RU"
    pw_login(spoof, "anna")
    assert history(env, "anna")[-1]["country"] == ""
    monkeypatch.setattr(dashboard, "TRUSTED_PROXY_NETS", tuple(dashboard.parse_trusted_proxies("172.30.0.2")[0]))
    tun = client(env, "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15",
                 "172.30.0.2")
    hdrs = {"CF-Connecting-IP": "198.51.100.8", "CF-IPCountry": "DE", "X-Forwarded-Proto": "http"}
    tun.get("/login", headers=hdrs)
    tun.post("/login", data={"username": "anna", "password": PW, "csrf": csrf_of(tun)}, headers=hdrs)
    last = history(env, "anna")[-1]
    assert last["country"] == "DE" and last["ip"] == "198.51.100.8"
    assert "IP 198.51.100.8 (DE)" in outbox(env)[-2]["body_text"]


def test_min_konto_lists_recent_logins(env):
    c = client(env)
    pw_login(c, "anna")
    pw_login(client(env, WINDOWS, "198.51.100.23"), "anna")
    html = c.get("/me").get_data(as_text=True)
    assert 'id="logins"' in html and "Seneste login" in html and "Log ud overalt" in html
    assert "Chrome på Windows" in html and "198.51.100.23" in html and "Ny enhed" in html
    assert "Denne enhed" in html
    assert "sf_device" not in html


def test_history_is_bounded_and_forgotten_with_the_user(env, monkeypatch):
    monkeypatch.setattr(login_alerts, "HISTORY_KEEP", 3)
    c = client(env)
    for _ in range(5):
        pw_login(c, "anna")
    assert len(history(env, "anna")) == 3
    with env.app.test_request_context("/"):
        dashboard.forget_user_meta("anna")
    assert history(env, "anna") == []
    assert env.conn.execute("SELECT COUNT(*) FROM ui_login_devices WHERE name='anna'").fetchone()[0] == 0


def test_alert_failure_never_breaks_the_login(env, monkeypatch):
    monkeypatch.setattr(login_alerts, "_on_login", lambda *a: 1 / 0)
    assert pw_login(client(env), "anna").status_code == 302


# --------------------------------------------------------------------- failed logins


def fail(env, name: str, n: int, ip: str = "203.0.113.50", password: str = WRONG):
    for _ in range(n):
        pw_login(client(env, ip=ip), name, password)


def alert_mails(env) -> list[dict]:
    return [m for m in outbox(env) if m["subject"] == "Spamfilter: gentagne forkerte login-forsøg"]


def test_five_failures_alert_the_admins_once(env):
    add_device(env, "admin")
    add_device(env, "anna")
    fail(env, "anna", 4)
    assert alert_mails(env) == []
    fail(env, "anna", 1)
    (m,) = alert_mails(env)
    assert m["kind"] == "security" and m["recipient"] == ADMIN_MAIL
    body = m["body_text"]
    assert "5 forkerte login-forsøg på 15 minutter for brugeren anna og IP-adressen 203.0.113.50" in body
    assert "sfctl unlock anna" in body and WRONG not in body
    fail(env, "anna", 3)                                  # locked now: no new alerts
    assert len(alert_mails(env)) == 1
    (q,) = queue(env, "login_failed")
    assert q["user"] == "admin"                           # only admins
    payload = push.render("admin", "login_failed", json.loads(q["data"]))
    assert payload["title"] == "Gentagne forkerte login-forsøg" and "brugeren anna" in payload["body"]
    assert push.render("anna", "login_failed", json.loads(q["data"])) is None
    rec = [a for a in env.audit() if a["action"] == "login_alert"][-1]
    assert rec["actor"] == "anna" and WRONG not in json.dumps(rec)


def test_dedup_once_per_hour_per_username_and_ip(env):
    fail(env, "anna", 5)
    assert len(alert_mails(env)) == 1
    env.conn.execute("DELETE FROM login_attempts")       # the lock has run out (15 min later)
    env.conn.commit()
    fail(env, "anna", 5)
    assert len(alert_mails(env)) == 1                     # same username + IP within the hour
    env.conn.execute("DELETE FROM login_attempts")
    env.conn.execute("UPDATE ui_login_alerts SET at=at-?", (login_alerts.ALERT_DEDUP + 1,))
    env.conn.commit()
    fail(env, "anna", 5)
    assert len(alert_mails(env)) == 2


def test_unknown_username_is_never_echoed(env):
    fail(env, "<script>evil</script>", 5, ip="198.51.100.66")
    (m,) = alert_mails(env)
    assert "<script>" not in m["body_text"] and "evil" not in m["body_text"]
    assert "et brugernavn, der ikke findes" in m["body_text"] and "IP-adressen 198.51.100.66" in m["body_text"]
    assert "sfctl unlock --ip 198.51.100.66" in m["body_text"]


def test_spray_from_one_ip_alerts_for_the_ip(env):
    for i in range(5):
        pw_login(client(env, ip="198.51.100.77"), f"spray{i}", WRONG)
    (m,) = alert_mails(env)
    assert "for IP-adressen 198.51.100.77" in m["body_text"] and "spray" not in m["body_text"]


def test_wrong_codes_after_the_right_password(env):
    with env.app.test_request_context("/"):
        secret = dashboard.twofa_pending_secret("anna")
        dashboard.twofa_confirm("anna", dashboard.totp(secret), actor="test")
    c = client(env)
    pw_login(c, "anna")
    for _ in range(5):
        c.post("/login/2fa", data={"code": "000000", "csrf": csrf_of(c)})
    (m,) = alert_mails(env)
    assert "brugeren anna" in m["body_text"] and "Adgangskoden var rigtig" in m["body_text"]
    assert "000000" not in m["body_text"]


def test_global_cap_on_failed_login_alerts(env, monkeypatch):
    monkeypatch.setattr(login_alerts, "ALERTS_PER_HOUR", 2)
    for i in range(4):
        fail(env, f"x{i}", 5, ip=f"198.51.100.{100 + i}")
    assert len(alert_mails(env)) == 2
    assert [a for a in env.audit() if a["action"] == "login_alert" and a["result"] == "skipped"]


def test_no_mail_route_no_admin_mail(env):
    assert dashboard.mail().save_routes({"security": {"on": False, "to": ADMIN_MAIL}})["ok"]
    fail(env, "anna", 5)
    assert alert_mails(env) == []
    assert [a for a in env.audit() if a["action"] == "login_alert"]   # still audited


def test_push_respects_the_admins_problem_switch(env):
    add_device(env, "admin", prefs={"threat": True, "review": False, "problem": False})
    fail(env, "anna", 5)
    assert queue(env, "login_failed") == []
