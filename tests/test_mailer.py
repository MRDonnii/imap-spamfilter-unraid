"""2.3 (B29) mailer.py: SMTP settings, TLS-only delivery, header safety,
outbox + retries + rate limits, the worker, transient one-time codes, the
engine helpers (own-mail skip, downtime notice) and the CLI.

No network: smtplib is replaced by FakeSMTP (mailer.SMTP_CLASS /
SMTP_SSL_CLASS seams), the state dir and config are temp files.
"""

from __future__ import annotations

import email
import email.policy
import json
import logging
import os
import smtplib
import socket
import sqlite3
import ssl
import stat
import sys
import threading
import time
from pathlib import Path

import pytest
import yaml

FILTER_DIR = Path(__file__).resolve().parents[1] / "filter"
sys.path.insert(0, str(Path(__file__).resolve().parent))
if str(FILTER_DIR) not in sys.path:
    sys.path.insert(0, str(FILTER_DIR))

import mailer  # noqa: E402

from fakes_ui_mail import SMTP_SECRET as SECRET  # noqa: E402
from fakes_ui_mail import FakeSMTP, FakeSMTPSSL  # noqa: E402
from fakes_ui_mail import reset as reset_fake  # noqa: E402

IMAP_SECRET = "imap-hemmelig-kode-7"


@pytest.fixture
def env(tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    secrets_dir = state / "imap-secrets"
    secrets_dir.mkdir(mode=0o700)
    (secrets_dir / "bynet").write_text(IMAP_SECRET + "\n")
    cfg = tmp_path / "accounts.yml"
    cfg.write_text(yaml.safe_dump({"accounts": [
        {"name": "bynet", "user": "ole@bynet.example", "imap_host": "imap.gigahost.dk",
         "password_file": str(secrets_dir / "bynet")},
        {"name": "sofie", "user": "sofie@molt.example", "imap_host": "mail.scannet.dk",
         "password_file": str(secrets_dir / "missing")},
    ]}))
    for attr in ("STATE_DIR", "CONFIG_PATH", "DB_PATH", "PASSWORD_FILE", "AUDIT_FILE"):
        monkeypatch.setattr(mailer, attr, getattr(mailer, attr))
    mailer.configure_paths(state, cfg)
    monkeypatch.setattr(mailer, "AUTO_WORKER", False)
    monkeypatch.setattr(mailer, "SMTP_CLASS", FakeSMTP)
    monkeypatch.setattr(mailer, "SMTP_SSL_CLASS", FakeSMTPSSL)
    reset_fake()
    mailer._TRANSIENT.clear()
    while not mailer._WAKEQ.empty():
        mailer._WAKEQ.get_nowait()
    yield state
    mailer.stop_worker()
    reset_fake()


def configure(**over):
    form = {"enabled": True, "host": "smtp.gigahost.dk", "port": "587", "security": "starttls",
            "auth": "password", "username": "ole@bynet.example", "account": "", "from_addr": "",
            "from_name": "Spamfilter Hjemmeserver"}
    form.update(over)
    pw = form.pop("password", SECRET)
    res = mailer.save_settings(form, password=pw)
    assert res["ok"], res
    return res


def outbox(state):
    conn = sqlite3.connect(state / "spamfilter.db")
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM mail_outbox ORDER BY id")]
    finally:
        conn.close()


def audit_lines(state):
    p = state / "admin-audit.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


def body_of(msg) -> str:
    return msg.get_body(preferencelist=("plain",)).get_content()


# --------------------------------------------------------------------- validation


@pytest.mark.parametrize("bad", [
    "ole@bynet.example\r\nBcc: x@evil.example", "ole@bynet.example\nBcc: x@evil.example", "a@b.dk, c@d.dk",
    "Ole <ole@bynet.example>", "", "   ", "ole", "@bynet.example", "ole@", "ole@bynet", "jo hn@bynet.example",
    "ole@bynet.example\x00", "a" * 65 + "@bynet.example", "x@" + "a" * 250 + ".dk", "ole@-bynet.example", "ole@bynet..dk",
    "ole@bynet.example "])
def test_address_validation_rejects_injection_and_junk(bad):
    with pytest.raises(mailer.MailError) as ex:
        mailer.validate_address(bad)
    assert ex.value.code == "invalid_address"


def test_address_validation_accepts_normal_addresses():
    assert mailer.validate_address(" ole@BYnet.EXAMPLE ") == "ole@bynet.example"
    assert mailer.validate_address("info+shop@pinsikbing.example") == "info+shop@pinsikbing.example"
    assert mailer.validate_address("a.b-c@sub.xn--ls8h.dk") == "a.b-c@sub.xn--ls8h.dk"


@pytest.mark.parametrize("bad", ["Hej\r\nBcc: x@y.dk", "Hej\nX", "Hej\rX", "a\x00b"])
def test_header_text_refuses_line_breaks(bad):
    with pytest.raises(mailer.MailError) as ex:
        mailer.clean_header_text(bad, 200)
    assert ex.value.code == "invalid_header"


def test_mask_address():
    assert mailer.mask_address("ole@bynet.example") == "o…@bynet.example"
    assert mailer.mask_address("x") == "…"


# --------------------------------------------------------------------- settings + secret


def test_settings_store_password_only_in_a_0600_file(env):
    configure()
    pw = env / "smtp.password"
    assert pw.read_text().strip() == SECRET
    assert stat.S_IMODE(pw.stat().st_mode) == 0o600
    raw = sqlite3.connect(env / "spamfilter.db").execute("SELECT value FROM settings_kv WHERE key='smtp'").fetchone()[0]
    assert SECRET not in raw and json.loads(raw)["host"] == "smtp.gigahost.dk"
    st = mailer.status()
    assert SECRET not in json.dumps(st, default=str) and st["password_stored"] and st["configured"]


def test_settings_validation_errors_are_danish_and_nothing_is_stored(env):
    res = mailer.save_settings({"enabled": True, "host": "https://smtp.x.dk", "port": "99999", "security": "plain",
                                "auth": "password", "username": "a b", "from_addr": "nope"}, password="x\ny")
    assert not res["ok"]
    assert set(res["errors"]) >= {"host", "port", "security", "username", "from_addr", "password"}
    assert "Porten" in res["errors"]["port"]
    assert not (env / "smtp.password").exists()
    assert mailer.get_settings()["host"] == ""


def test_changed_server_needs_the_password_again(env):
    configure()
    res = mailer.save_settings({"enabled": True, "host": "mail.evil.example", "port": "587", "security": "starttls",
                                "auth": "password", "username": "ole@bynet.example"})
    assert not res["ok"] and "adgangskoden igen" in res["errors"]["password"]
    assert mailer.get_settings()["host"] == "smtp.gigahost.dk"
    # Same server: an empty password field keeps the stored one.
    res = mailer.save_settings({"enabled": True, "host": "smtp.gigahost.dk", "port": "587", "security": "starttls",
                                "auth": "password", "username": "ole@bynet.example", "from_name": "Nyt navn"})
    assert res["ok"] and res["changed"] == ["from_name"]
    assert (env / "smtp.password").read_text().strip() == SECRET


def test_account_login_reads_the_mailbox_secret_at_send_time_never_copies_it(env):
    configure()
    res = mailer.save_settings({"enabled": True, "host": "smtp.gigahost.dk", "port": "587", "security": "starttls",
                                "auth": "account", "account": "bynet"})
    assert res["ok"]
    assert not (env / "smtp.password").exists()  # the unused SMTP secret is gone
    assert mailer.effective_from() == "ole@bynet.example"
    res = mailer.send_test("ole@bynet.example")
    assert res["ok"], res
    conn = FakeSMTP.instances[-1]
    assert "login:ole@bynet.example" in conn.calls and conn.password == IMAP_SECRET
    assert IMAP_SECRET not in (env / "spamfilter.db").read_bytes().decode("latin-1")
    assert not (env / "smtp.password").exists()
    # A mailbox whose secret cannot be read: a clear, permanent error.
    mailer.save_settings({"enabled": True, "host": "mail.scannet.dk", "port": "587", "security": "starttls",
                          "auth": "account", "account": "sofie"})
    res = mailer.send_test("ole@bynet.example")
    assert not res["ok"] and res["code"] == "account_password"


def test_provider_suggestions_are_labelled():
    assert mailer.PROVIDER_NOTE == "forslag – bekræftes med testmail"
    hosts = {p["id"]: (p["host"], p["port"], p["security"]) for p in mailer.PROVIDERS}
    assert hosts["gigahost"] == ("smtp.gigahost.dk", 587, "starttls")
    assert hosts["scannet"] == ("mail.scannet.dk", 587, "starttls")
    assert mailer.provider_for_imap("imap.gigahost.dk")["id"] == "gigahost"


# --------------------------------------------------------------------- TLS + delivery


def test_starttls_then_auth_with_verified_certificate(env):
    configure()
    res = mailer.send_test("ole@bynet.example")
    assert res["ok"] and "o…@bynet.example" in res["text"]
    conn = FakeSMTP.instances[-1]
    assert conn.calls.index("starttls") < conn.calls.index("login:ole@bynet.example") < conn.calls.index("send")
    assert isinstance(conn.context, ssl.SSLContext)
    assert conn.context.verify_mode == ssl.CERT_REQUIRED and conn.context.check_hostname is True
    assert conn.timeout == mailer.SEND_TIMEOUT
    assert conn.password == SECRET


def test_implicit_tls_uses_smtp_ssl_with_verification(env):
    configure(security="ssl", port="465")
    assert mailer.send_test("ole@bynet.example")["ok"]
    conn = FakeSMTP.instances[-1]
    assert isinstance(conn, FakeSMTPSSL) and "starttls" not in conn.calls
    assert conn.context.verify_mode == ssl.CERT_REQUIRED and conn.context.check_hostname


def test_no_starttls_means_no_auth_and_no_mail(env):
    configure()
    FakeSMTP.offer_starttls = False
    res = mailer.send_test("ole@bynet.example")
    assert not res["ok"] and res["code"] == "no_starttls" and "SSL/TLS" in res["text"]
    conn = FakeSMTP.instances[-1]
    assert not any(c.startswith("login") for c in conn.calls) and "send" not in conn.calls
    assert FakeSMTP.sent == []


@pytest.mark.parametrize("exc,code", [
    (ssl.SSLCertVerificationError("bad cert"), "cert"),
    (ssl.SSLError("handshake"), "tls"),
])
def test_tls_failures_never_fall_back_to_plain(env, exc, code):
    configure()
    FakeSMTP.fail_starttls = exc
    res = mailer.send_test("ole@bynet.example")
    assert res["code"] == code
    assert not any(c.startswith("login") for c in FakeSMTP.instances[-1].calls)


@pytest.mark.parametrize("attr,exc,code", [
    ("fail_login", smtplib.SMTPAuthenticationError(535, b"5.7.8 nope"), "auth"),
    ("fail_connect", socket.gaierror("no such host"), "dns"),
    ("fail_connect", ConnectionRefusedError("refused"), "connect"),
    ("fail_connect", socket.timeout("slow"), "timeout"),
    ("fail_send", smtplib.SMTPSenderRefused(553, b"not yours", "x@y"), "sender"),
    ("fail_send", smtplib.SMTPRecipientsRefused({"a@b.dk": (550, b"no")}), "recipient"),
    ("fail_send", smtplib.SMTPDataError(451, b"later"), "server"),
])
def test_errors_are_classified_in_danish_without_server_text(env, attr, exc, code):
    configure()
    setattr(FakeSMTP, attr, exc)
    res = mailer.send_test("ole@bynet.example")
    assert not res["ok"] and res["code"] == code
    assert res["text"] == mailer.ERROR_TEXTS[code]
    assert "nope" not in res["text"] and "not yours" not in res["text"]
    st = mailer.status()
    assert st["last_test"]["ok"] is False and st["last_test"]["code"] == code


def test_message_headers_and_bodies(env):
    configure(from_name="Spamfilter Hjemmeserver")
    res = mailer.notify("alert", "Spamfilter: Konto bynet: login afvist", "Linje 1\n\nLinje <2> & 3",
                        recipients=["ole@bynet.example"])
    assert res["ok"] and res["queued"] == 1
    counts = mailer.process_outbox()
    assert counts["sent"] == 1
    frm, to, msg = FakeSMTP.sent[-1]
    assert frm == "ole@bynet.example" and to == ["ole@bynet.example"]
    assert msg["Auto-Submitted"] == "auto-generated"
    assert msg["X-TH-Spamfilter"] == "notify"
    assert mailer.MSGID_RE.match(msg["Message-ID"])
    assert msg["Subject"] == "Spamfilter: Konto bynet: login afvist"
    assert "Spamfilter Hjemmeserver" in msg["From"] and "<ole@bynet.example>" in msg["From"]
    assert "Linje 1" in body_of(msg)
    html = msg.get_body(preferencelist=("html",)).get_content()
    assert "Linje &lt;2&gt; &amp; 3" in html and "<script" not in html
    row = outbox(env)[-1]
    assert row["status"] == "sent" and row["message_id"] == msg["Message-ID"]
    assert row["body_text"] is None and row["body_html"] is None  # content is not kept after delivery


def test_subject_injection_is_refused_before_anything_is_queued(env):
    configure()
    res = mailer.notify("alert", "Hej\r\nBcc: x@evil.example", "tekst", recipients=["ole@bynet.example"])
    assert not res["ok"] and res["code"] == "invalid_header"
    res = mailer.notify("alert", "Hej", "tekst", recipients=["ole@bynet.example\r\nBcc: x@evil.example"])
    assert not res["ok"] and res["code"] == "invalid_address"
    assert outbox(env) == []
    with pytest.raises(mailer.MailError):
        mailer.build_message(to="a@b.dk", subject="x", text="y", html=None, message_id="<evil@x>",
                             settings=mailer.get_settings())


# --------------------------------------------------------------------- notify + routes


def test_notify_needs_a_configured_server_and_a_route(env):
    assert mailer.notify("alert", "S", "T")["code"] == "not_configured"
    configure()
    assert mailer.notify("alert", "S", "T")["code"] == "off"
    assert mailer.notify("bogus", "S", "T")["code"] == "invalid_kind"
    res = mailer.save_routes({"alert": {"on": True, "to": "ole@bynet.example, sofie@molt.example, ole@bynet.example"},
                              "digest": {"on": False, "to": ""}})
    assert res["ok"] and res["routes"]["alert"]["to"] == ["ole@bynet.example", "sofie@molt.example"]
    assert mailer.recipients_for("alert") == ["ole@bynet.example", "sofie@molt.example"]
    assert mailer.recipients_for("digest") == []
    res = mailer.notify("alert", "S", "T")
    assert res["ok"] and res["queued"] == 2
    assert mailer.process_outbox()["sent"] == 2
    mailer.set_enabled(False)
    assert mailer.notify("alert", "S", "T")["code"] == "disabled"


def test_routes_validation(env):
    res = mailer.save_routes({"alert": {"on": True, "to": "ok@x.dk, ikke-en-adresse"}})
    assert not res["ok"] and "ikke-en-adresse" in res["errors"]["alert"]
    res = mailer.save_routes({"weekly": {"on": True, "to": ""}})
    assert not res["ok"] and "mindst én" in res["errors"]["weekly"]
    res = mailer.save_routes({"security": {"on": True, "to": ", ".join(f"a{i}@x.dk" for i in range(11))}})
    assert not res["ok"]


# --------------------------------------------------------------------- outbox, retries, rate limits


def test_retry_with_backoff_then_failure(env):
    configure()
    FakeSMTP.fail_connect = ConnectionRefusedError("down")
    res = mailer.notify("alert", "S", "T", recipients=["ole@bynet.example"])
    t0 = int(time.time())
    c = mailer.process_outbox(now=t0)
    assert c["retry"] == 1
    row = outbox(env)[-1]
    assert row["status"] == "queued" and row["attempts"] == 1 and row["next_attempt_at"] == t0 + mailer.BACKOFF[0]
    assert row["last_error"] == "connect"
    assert mailer.process_outbox(now=t0 + 10)["retry"] == 0  # not due yet
    t = t0
    for i in range(1, mailer.MAX_ATTEMPTS):
        t += mailer.BACKOFF[i - 1]
        mailer.process_outbox(now=t)
    row = outbox(env)[-1]
    assert row["status"] == "failed" and row["attempts"] == mailer.MAX_ATTEMPTS
    assert row["body_text"] is None
    assert [a["action"] for a in audit_lines(env)][-1] == "mail_failed"
    assert res["ids"] == [row["id"]]


def test_recovery_after_a_temporary_failure(env):
    configure()
    FakeSMTP.fail_connect = ConnectionRefusedError("down")
    mailer.notify("alert", "S", "T", recipients=["ole@bynet.example"])
    t0 = int(time.time())
    mailer.process_outbox(now=t0)
    FakeSMTP.fail_connect = None
    assert mailer.process_outbox(now=t0 + mailer.BACKOFF[0])["sent"] == 1
    st = mailer.status()
    assert st["ok"] is True and st["sent_24h"] == 1


def test_permanent_errors_fail_at_once(env):
    configure()
    FakeSMTP.fail_login = smtplib.SMTPAuthenticationError(535, b"nope")
    mailer.notify("alert", "S", "T", recipients=["ole@bynet.example"])
    assert mailer.process_outbox()["failed"] == 1
    assert outbox(env)[-1]["status"] == "failed" and outbox(env)[-1]["last_error"] == "auth"
    st = mailer.status()
    assert st["last_error"]["code"] == "auth" and st["ok"] is False


def test_per_recipient_and_global_rate_limits(env, monkeypatch):
    configure()
    monkeypatch.setattr(mailer, "PER_RECIPIENT_PER_HOUR", 2)
    monkeypatch.setattr(mailer, "GLOBAL_PER_HOUR", 3)
    for _ in range(3):
        mailer.notify("alert", "S", "T", recipients=["ole@bynet.example"])
    c = mailer.process_outbox()
    assert c["sent"] == 2 and c["deferred"] == 1
    deferred = [r for r in outbox(env) if r["status"] == "queued"]
    assert len(deferred) == 1 and deferred[0]["attempts"] == 0 and deferred[0]["last_error"] == "rate"
    mailer.notify("alert", "S", "T", recipients=["sofie@molt.example"])
    mailer.notify("alert", "S", "T", recipients=["anden@molt.example"])
    c = mailer.process_outbox()
    assert c["sent"] == 1  # the global limit (3/hour) stops the last one
    assert mailer.send_test("ny@molt.example")["code"] == "rate"


def test_outbox_is_bounded(env, monkeypatch):
    configure()
    monkeypatch.setattr(mailer, "OUTBOX_MAX_QUEUED", 2)
    assert mailer.notify("alert", "S", "T", recipients=["a@x.dk", "b@x.dk"])["ok"]
    res = mailer.notify("alert", "S", "T", recipients=["c@x.dk"])
    assert not res["ok"] and res["code"] == "queue_full"


def test_disabled_server_drops_queued_mail(env):
    configure()
    mailer.notify("alert", "S", "T", recipients=["ole@bynet.example"])
    mailer.set_enabled(False)
    assert mailer.process_outbox()["dropped"] == 1
    assert FakeSMTP.sent == []


def test_two_processes_never_send_the_same_row(env):
    configure()
    mailer.notify("alert", "S", "T", recipients=["ole@bynet.example"])
    row_id = outbox(env)[-1]["id"]
    conn = sqlite3.connect(env / "spamfilter.db")
    conn.execute("UPDATE mail_outbox SET status='sending', claimed_at=? WHERE id=?", (int(time.time()), row_id))
    conn.commit()
    conn.close()
    assert mailer.process_outbox()["sent"] == 0
    # A claim of a crashed process is retried after STALE_CLAIM.
    assert mailer.process_outbox(now=int(time.time()) + mailer.STALE_CLAIM + 5)["sent"] == 1


def test_process_outbox_never_raises(env, monkeypatch):
    configure()
    mailer.notify("alert", "S", "T", recipients=["ole@bynet.example"])
    FakeSMTP.fail_send = RuntimeError("library bug")
    assert mailer.process_outbox()["retry"] == 1
    monkeypatch.setattr(mailer, "build_message", lambda **k: (_ for _ in ()).throw(KeyError("boom")))
    assert isinstance(mailer.process_outbox(now=int(time.time()) + 3600), dict)
    monkeypatch.setattr(mailer, "DB_PATH", env / "nope" / "x" / "db")
    monkeypatch.setattr(mailer, "_SCHEMA_READY", set())
    (env / "nope").write_text("a file, not a dir")
    assert mailer.process_outbox() == {"sent": 0, "failed": 0, "retry": 0, "deferred": 0, "expired": 0,
                                       "dropped": 0}
    assert mailer.notify("alert", "S", "T", recipients=["ole@bynet.example"])["ok"] is False


def test_worker_is_idempotent_survives_errors_and_delivers(env, monkeypatch):
    configure()
    monkeypatch.setattr(mailer, "WORKER_POLL", 0.05)
    calls = {"n": 0}
    real = mailer.process_outbox

    def flaky(**kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("first run explodes")
        return real(**kw)

    monkeypatch.setattr(mailer, "process_outbox", flaky)
    assert mailer.ensure_worker() and mailer.ensure_worker()
    workers = [t for t in threading.enumerate() if t.name == "mailer"]
    assert len(workers) == 1
    mailer.notify("alert", "S", "T", recipients=["ole@bynet.example"])
    mailer._kick()
    deadline = time.time() + 5
    while time.time() < deadline and not FakeSMTP.sent:
        time.sleep(0.05)
    assert FakeSMTP.sent and mailer.worker_alive()
    mailer.stop_worker()
    assert not mailer.worker_alive()


def test_notify_starts_the_worker_when_allowed(env, monkeypatch):
    configure()
    monkeypatch.setattr(mailer, "AUTO_WORKER", True)
    monkeypatch.setattr(mailer, "WORKER_POLL", 0.05)
    mailer.notify("alert", "S", "T", recipients=["ole@bynet.example"])
    deadline = time.time() + 5
    while time.time() < deadline and not FakeSMTP.sent:
        time.sleep(0.05)
    assert FakeSMTP.sent


# --------------------------------------------------------------------- one-time codes (transient)


def test_code_mail_never_stores_the_code(env):
    configure()
    res = mailer.send_code("ole@bynet.example", "123456", purpose="login", name="anna")
    assert res["ok"]
    row = outbox(env)[-1]
    assert row["kind"] == "code" and row["transient"] == 1 and row["body_text"] is None
    assert row["expires_at"] - row["created_at"] == mailer.CODE_TTL
    assert b"123456" not in (env / "spamfilter.db").read_bytes()
    assert mailer.process_outbox()["sent"] == 1
    msg = FakeSMTP.sent[-1][2]
    assert "123 456" in body_of(msg) and "123 456" in msg.get_body(preferencelist=("html",)).get_content()
    assert "123456" not in msg["Subject"]
    for line in audit_lines(env):
        assert "123456" not in json.dumps(line) and "ole@bynet.example" not in json.dumps(line)
    assert mailer.send_code("ole@bynet.example", "12345")["code"] == "invalid_text"


def test_codes_of_another_process_are_never_sent_and_expire(env, monkeypatch):
    configure()
    mailer.send_code("ole@bynet.example", "654321", name="anna")
    monkeypatch.setattr(mailer, "PROCESS_TOKEN", "another-process")
    assert mailer.process_outbox()["sent"] == 0
    assert outbox(env)[-1]["status"] == "queued"
    c = mailer.process_outbox(now=int(time.time()) + mailer.CODE_TTL + 1)
    assert c["expired"] == 1 and outbox(env)[-1]["status"] == "expired"
    assert FakeSMTP.sent == []


# --------------------------------------------------------------------- engine helpers


def test_is_own_notification(env):
    configure()
    mailer.notify("alert", "S", "T", recipients=["ole@bynet.example"])
    mailer.process_outbox()
    msg = FakeSMTP.sent[-1][2]
    raw = msg.as_bytes()
    mid = msg["Message-ID"]
    assert mailer.is_own_notification(mid, raw)
    assert mailer.is_own_notification(mid)  # without headers: the recorded ID alone
    forged = raw.replace(b"X-TH-Spamfilter: notify", b"X-TH-Spamfilter: other")
    assert not mailer.is_own_notification(mid, forged)
    assert not mailer.is_own_notification("<notify." + "0" * 32 + "@hjemmeserver.spamfilter>", raw)
    assert not mailer.is_own_notification("<x@hjemmeserver.spamfilter>", raw)
    assert not mailer.is_own_notification(None)


def test_downtime_notice_from_the_old_heartbeat(env):
    configure()
    mailer.save_routes({"alert": {"on": True, "to": "ole@bynet.example"}})
    hb = env / "heartbeat"
    now = int(time.time())
    hb.write_text(f"{now - 120} boot\n")
    assert mailer.check_heartbeat_gap(hb, now=now) is False
    hb.write_text(f"{now - 3 * 3600} boot\n")
    assert mailer.check_heartbeat_gap(hb, now=now) is True
    mailer.process_outbox()
    msg = FakeSMTP.sent[-1][2]
    assert "Spamfilteret har været stoppet fra" in body_of(msg) and "til" in body_of(msg)
    assert mailer.check_heartbeat_gap(env / "missing", now=now) is False
    hb.write_text("garbage")
    assert mailer.check_heartbeat_gap(hb, now=now) is False


def test_prune_keeps_recent_and_queued_rows(env):
    configure()
    mailer.notify("alert", "S", "T", recipients=["ole@bynet.example"])
    mailer.process_outbox()
    assert mailer.prune(now=int(time.time()) + 31 * 86400) == 1
    assert outbox(env) == []


# --------------------------------------------------------------------- privacy + CLI


def test_logs_and_audit_never_carry_full_addresses_or_secrets(env, caplog):
    configure()
    caplog.set_level(logging.DEBUG, logger="mailer")
    FakeSMTP.fail_connect = ConnectionRefusedError("down")
    mailer.notify("alert", "S", "T", recipients=["kontakt@kunde.example"])
    mailer.process_outbox()
    FakeSMTP.fail_connect = None
    FakeSMTP.fail_login = smtplib.SMTPAuthenticationError(535, b"x")
    mailer.process_outbox(now=int(time.time()) + 4000)
    mailer.send_test("kontakt@kunde.example")
    text = caplog.text + json.dumps(audit_lines(env))
    assert "kontakt@kunde.example" not in text and SECRET not in text
    assert "k…@kunde.example" in text


def test_cli(env, capsys):
    assert mailer.main(["notify", "--kind", "alert", "--subject", "S", "--text", "T"]) == mailer.EXIT_OFF
    configure()
    mailer.save_routes({"alert": {"on": True, "to": "ole@bynet.example"}})
    assert mailer.main(["notify", "--kind", "alert", "--subject", "Spamfilter: OK igen", "--text", "Løst"]) == 0
    assert "Sendt: 1" in capsys.readouterr().out
    assert FakeSMTP.sent[-1][2]["Subject"] == "Spamfilter: OK igen"
    assert mailer.main(["test", "ole@bynet.example"]) == 0
    assert mailer.main(["status"]) == 0
    st = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert st["configured"] is True and SECRET not in json.dumps(st)
    assert mailer.main(["notify", "--kind", "nope", "--subject", "S"]) == 2
    FakeSMTP.fail_login = smtplib.SMTPAuthenticationError(535, b"x")
    assert mailer.main(["notify", "--kind", "alert", "--subject", "S", "--text", "T"]) == 1


def test_cli_runs_as_a_script_without_network(env, tmp_path):
    """`python3 /app/mailer.py notify ...` (the host-monitor path) with no
    mail server set up: exit 3, nothing sent, no traceback."""
    import subprocess

    out = subprocess.run([sys.executable, "-s", str(FILTER_DIR / "mailer.py"), "notify", "--kind", "alert",
                          "--subject", "S", "--text", "T"],
                         env=dict(os.environ, STATE_DIR=str(env), CONFIG_PATH=str(tmp_path / "accounts.yml")),
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 3, out.stderr
    assert "Traceback" not in out.stderr
