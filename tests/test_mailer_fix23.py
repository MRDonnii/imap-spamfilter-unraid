"""2.3 fixer: mail budget reserved for login codes and alerts, and
'Brug postkassens login' bound to the mailbox's own provider (or a host an
admin confirmed with the mailbox password). No network (FakeSMTP)."""

from __future__ import annotations

import json

import pytest
from test_mailer import IMAP_SECRET, configure, env, outbox  # noqa: F401  (sets sys.path)

import mailer  # noqa: E402
from fakes_ui_mail import FakeSMTP  # noqa: E402


def test_notices_cannot_use_the_budget_reserved_for_codes_and_alerts(env, monkeypatch):
    configure()
    monkeypatch.setattr(mailer, "GLOBAL_PER_HOUR", 6)
    monkeypatch.setattr(mailer, "PRIORITY_RESERVE", 2)
    for i in range(8):  # a Bruger triggering security notices to many addresses
        assert mailer.notify("security", "S", "T", recipients=[f"x{i}@evil.example"])["ok"]
    c = mailer.process_outbox(limit=50)
    assert c["sent"] == 4 and c["deferred"] == 4   # stops PRIORITY_RESERVE short
    assert mailer.send_code("bo@bynet.example", "123456", name="bo")["ok"]
    assert mailer.notify("alert", "A", "T", recipients=["ole@bynet.example"])["ok"]
    c = mailer.process_outbox(limit=50)
    assert c["sent"] == 2   # the code and the alert still go out
    kinds = [r["kind"] for r in outbox(env) if r["status"] == "sent"]
    assert "code" in kinds and "alert" in kinds


def test_priority_per_recipient_limit_ignores_notice_floods(env, monkeypatch):
    configure()
    monkeypatch.setattr(mailer, "PER_RECIPIENT_PER_HOUR", 2)
    for _ in range(3):
        mailer.notify("security", "S", "T", recipients=["admin@bynet.example"])
    mailer.process_outbox(limit=50)
    # The admin's own login code to the flooded address is not rate-limited.
    assert mailer.send_code("admin@bynet.example", "654321", name="admin")["ok"]
    assert mailer.process_outbox(limit=50)["sent"] == 1


def test_security_notices_are_bounded_by_the_outbox_cap(env, monkeypatch):
    configure()
    monkeypatch.setattr(mailer, "OUTBOX_MAX_QUEUED", 2)
    assert mailer.notify("security", "S", "T", recipients=["a@x.dk", "b@x.dk"])["ok"]
    res = mailer.notify("security", "S", "T", recipients=["c@x.dk"])
    assert not res["ok"] and res["code"] == "queue_full"
    # One-time codes are bounded elsewhere (memory + per-user limit) and still queue.
    assert mailer.send_code("bo@bynet.example", "111111", name="bo")["ok"]


def test_mailbox_password_never_goes_to_an_unconfirmed_host(env):
    configure()
    res = mailer.save_settings({"enabled": True, "host": "mail.evil.example", "port": "465", "security": "ssl",
                                "auth": "account", "account": "bynet"})
    assert not res["ok"] and "account_password" in res["errors"]
    assert mailer.get_settings()["host"] == "smtp.gigahost.dk"
    # A wrong mailbox password does not confirm it either.
    res = mailer.save_settings({"enabled": True, "host": "mail.evil.example", "port": "465", "security": "ssl",
                                "auth": "account", "account": "bynet"}, account_password="gæt")
    assert not res["ok"] and res["errors"]["account_password"] == "Adgangskoden passer ikke til postkassen."


def test_switch_from_password_to_account_with_a_new_host_needs_the_mailbox_password(env):
    configure(host="smtp.example.dk")
    res = mailer.save_settings({"enabled": True, "host": "smtp.example.dk", "port": "587", "security": "starttls",
                                "auth": "account", "account": "bynet"})
    assert not res["ok"] and "account_password" in res["errors"]
    res = mailer.save_settings({"enabled": True, "host": "smtp.example.dk", "port": "587", "security": "starttls",
                                "auth": "account", "account": "bynet"}, account_password=IMAP_SECRET)
    assert res["ok"], res
    s = mailer.get_settings()
    assert s["account_bound"] == "smtp.example.dk:587:bynet" and IMAP_SECRET not in str(s)
    assert mailer.send_test("ole@bynet.example")["ok"]
    assert FakeSMTP.instances[-1].password == IMAP_SECRET
    # Saving again unchanged keeps the confirmation; a new port asks again.
    assert mailer.save_settings({"enabled": True, "host": "smtp.example.dk", "port": "587",
                                 "security": "starttls", "auth": "account", "account": "bynet"})["ok"]
    res = mailer.save_settings({"enabled": True, "host": "smtp.example.dk", "port": "2525",
                                "security": "starttls", "auth": "account", "account": "bynet"})
    assert not res["ok"] and "account_password" in res["errors"]


def test_own_provider_needs_no_confirmation(env):
    res = mailer.save_settings({"enabled": True, "host": "SMTP.gigahost.dk", "port": "465", "security": "ssl",
                                "auth": "account", "account": "bynet"})
    assert res["ok"] and mailer.get_settings()["account_bound"] == ""
    assert mailer.is_configured()


@pytest.mark.parametrize("host", ["mail.evil.example", "smtp.gigahost.dk.evil.example"])
def test_send_time_check_refuses_a_tampered_setting(env, host):
    """Even a settings row written behind save_settings' back (direct DB
    edit) never makes the mailer send the mailbox password elsewhere."""
    mailer.save_settings({"enabled": True, "host": "smtp.gigahost.dk", "port": "587", "security": "starttls",
                          "auth": "account", "account": "bynet"})
    s = mailer.get_settings()
    s["host"] = host
    mailer._kv_set(mailer.SETTINGS_KEY, json.dumps(s))
    assert not mailer.is_configured()
    FakeSMTP.instances.clear()
    res = mailer.send_test("ole@bynet.example")
    assert not res["ok"]
    assert all(getattr(i, "password", None) != IMAP_SECRET for i in FakeSMTP.instances)
    with pytest.raises(mailer.MailError) as ex:
        mailer._credentials(s)
    assert ex.value.code == "account_host"
