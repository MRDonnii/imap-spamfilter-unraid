"""Fake SMTP for the 2.3 mail tests (mailer.py, two-step login by mail,
Mailserver/Notifikationer pages). No network: install() swaps the seams
mailer.SMTP_CLASS / SMTP_SSL_CLASS; every delivered message is kept in
FakeSMTP.sent so a test can read the one-time code from it.
"""

from __future__ import annotations

import email.message
import re
import sys
from pathlib import Path
from typing import Any

FILTER_DIR = Path(__file__).resolve().parent.parent / "filter"
if str(FILTER_DIR) not in sys.path:
    sys.path.insert(0, str(FILTER_DIR))

SMTP_SECRET = "smtp-hemmelig-kode-42"


class FakeSMTP:
    """Records the SMTP conversation. Behaviour knobs are class attributes
    (reset()); SMTP_SSL is the subclass FakeSMTPSSL."""

    instances: list["FakeSMTP"] = []
    sent: list[tuple[str, list[str], email.message.EmailMessage]] = []
    offer_starttls = True
    fail_connect: BaseException | None = None
    fail_starttls: BaseException | None = None
    fail_login: BaseException | None = None
    fail_send: BaseException | None = None
    refuse: dict = {}

    def __init__(self, host, port, timeout=None, context=None, **kw):
        self.host, self.port, self.timeout, self.context = host, port, timeout, context
        self.calls: list[str] = []
        self.ssl = context is not None  # SMTP_SSL gets the context at connect time
        FakeSMTP.instances.append(self)
        if FakeSMTP.fail_connect is not None:
            raise FakeSMTP.fail_connect
        self.calls.append("connect")

    def ehlo(self, name=""):
        self.calls.append("ehlo")
        return 250, b"ok"

    def has_extn(self, opt):
        return opt.lower() == "starttls" and FakeSMTP.offer_starttls and not self.ssl

    def starttls(self, context=None):
        self.calls.append("starttls")
        self.context = context
        if FakeSMTP.fail_starttls is not None:
            raise FakeSMTP.fail_starttls
        self.ssl = True
        return 220, b"go ahead"

    def login(self, user, password):
        assert self.ssl, "AUTH before TLS"
        self.calls.append(f"login:{user}")
        self.password = password
        if FakeSMTP.fail_login is not None:
            raise FakeSMTP.fail_login
        return 235, b"ok"

    def send_message(self, msg, from_addr=None, to_addrs=None):
        self.calls.append("send")
        if FakeSMTP.fail_send is not None:
            raise FakeSMTP.fail_send
        FakeSMTP.sent.append((from_addr, list(to_addrs or []), msg))
        return dict(FakeSMTP.refuse)

    def quit(self):
        self.calls.append("quit")

    def close(self):
        self.calls.append("close")


class FakeSMTPSSL(FakeSMTP):
    pass


def reset() -> None:
    FakeSMTP.instances = []
    FakeSMTP.sent = []
    FakeSMTP.offer_starttls = True
    FakeSMTP.fail_connect = FakeSMTP.fail_starttls = FakeSMTP.fail_login = FakeSMTP.fail_send = None
    FakeSMTP.refuse = {}


def install(monkeypatch: Any) -> Any:
    """Fake SMTP + no background worker (tests deliver with flush())."""
    import mailer

    monkeypatch.setattr(mailer, "SMTP_CLASS", FakeSMTP)
    monkeypatch.setattr(mailer, "SMTP_SSL_CLASS", FakeSMTPSSL)
    monkeypatch.setattr(mailer, "AUTO_WORKER", False)
    for attr in ("STATE_DIR", "CONFIG_PATH", "DB_PATH", "PASSWORD_FILE", "AUDIT_FILE"):
        monkeypatch.setattr(mailer, attr, getattr(mailer, attr))
    reset()
    mailer._TRANSIENT.clear()
    while not mailer._WAKEQ.empty():
        mailer._WAKEQ.get_nowait()
    return mailer


def configure_smtp(mailer: Any, **over: Any) -> dict:
    form = {"enabled": True, "host": "smtp.gigahost.dk", "port": "587", "security": "starttls",
            "auth": "password", "username": "ole@bynet.example", "account": "", "from_addr": "",
            "from_name": "Spamfilter Hjemmeserver"}
    form.update(over)
    pw = form.pop("password", SMTP_SECRET)
    res = mailer.save_settings(form, password=pw)
    assert res["ok"], res
    return res


def flush() -> list:
    """Deliver what is queued; returns the messages sent by this call."""
    import mailer

    before = len(FakeSMTP.sent)
    mailer.process_outbox(limit=100)
    return [m for _f, _t, m in FakeSMTP.sent[before:]]


def text_of(msg: email.message.EmailMessage) -> str:
    return msg.get_body(preferencelist=("plain",)).get_content()


def last_code(to: str | None = None) -> str:
    """The 6-digit code of the newest code mail (optionally to `to`)."""
    for _f, rcpts, msg in reversed(FakeSMTP.sent):
        if to is not None and to not in rcpts:
            continue
        m = re.search(r"Din kode: (\d{3}) (\d{3})", text_of(msg))
        if m:
            return m.group(1) + m.group(2)
    raise AssertionError("no code mail sent")
