"""End-to-end smoke test without network (INTEGRATOR).

Runs the REAL filter.py engine + mailctx + services + dashboard/ui_mail
against the RFC-accurate FakeIMAP (tests/fakes_engine.py) and a fake rspamd
HTTP endpoint (requests.post/get monkeypatched):

  new spam arrives -> scored with the mailctx sender context (IP/From/
  Deliver-To sent to rspamd) -> pending_move -> moved after the grace period
  (UIDPLUS emulation on Gigahost-like caps, MOVE on Scannet-like caps) ->
  listed on /spam -> released via POST /mail/action -> back in INBOX with
  user_verdict 'ham' -> the next loops do NOT move it back.

Plus: shadow mode performs zero IMAP mutations.
"""

from __future__ import annotations

import datetime as dt
import importlib
import json
import logging
import re
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from fakes_engine import GIGAHOST_CAPS, SCANNET_CAPS, FakeIMAP, FakeRspamd, setup_engine
from fakes_ui import TEST_PASSWORD, login, post, write_users

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "headers"
LOG = logging.getLogger("e2e")

PROFILES = {
    # name: (caps, imap host, fixture, expected external IP, expected envelope sender)
    "gigahost": (GIGAHOST_CAPS, "imap.gigahost.dk", "gigahost_inbound.eml", "54.240.39.204",
                 "010001a1593c2a73-814d6018-9d39-4658-8176-fa3f74999361-000000@envelope.ollama.com"),
    "scannet": (SCANNET_CAPS, "mail.scannet.dk", "scannet_inbound.eml", "52.17.18.180",
                "bounce+4-user=example-b.dk@news.ajax.systems"),
}


class E2ERspamd(FakeRspamd):
    """FakeRspamd whose GET replies also carry .json() like requests does
    (services.bayes_stats/rspamd_health parse the controller's JSON)."""

    def get(self, url, timeout=None, headers=None):  # noqa: D401
        super().get(url, timeout=timeout)
        if url.endswith("/stat"):
            payload = {"statfiles": [{"symbol": "BAYES_SPAM", "revision": 250, "users": 1},
                                     {"symbol": "BAYES_HAM", "revision": 300, "users": 1}]}
            return SimpleNamespace(status_code=200, text=json.dumps(payload), json=lambda: payload)
        return SimpleNamespace(status_code=200, text="pong", json=lambda: (_ for _ in ()).throw(ValueError()))


def mail_from_fixture(fixture: str, msgid: str, subject: str) -> bytes:
    raw = (FIXTURES / fixture).read_bytes().replace(b"\r\n", b"\n")
    raw = re.sub(rb"(?m)^Message-ID: .*$", f"Message-ID: <{msgid}>".encode(), raw, count=1)
    raw = re.sub(rb"(?m)^Subject: .*$", f"Subject: {subject}".encode(), raw, count=1)
    return raw.replace(b"\n", b"\r\n")


def session_view(main: FakeIMAP) -> FakeIMAP:
    """A second IMAP connection to the same mailbox (own selected folder,
    own write log, shared folders) - what services.mail_action opens."""
    other = FakeIMAP(capabilities=main.caps, folders=())
    other.folders = main.folders
    other.writes = main.writes  # one combined mutation log per mailbox
    return other


@pytest.fixture
def world(tmp_path, monkeypatch):
    """Real engine + services + dashboard sharing one temp state dir."""
    mailctx = importlib.import_module("mailctx")
    eng = setup_engine(tmp_path, monkeypatch, mailctx=mailctx)
    services = importlib.import_module("services")
    import dashboard
    import ui_mail  # noqa: F401 - registers /spam, /mail/action

    clock = SimpleNamespace(t=time.time())
    monkeypatch.setattr(eng, "_now", lambda: clock.t)
    rspamd = E2ERspamd(eng.requests).install(monkeypatch, eng)

    for name, value in {
        "STATE_DIR": tmp_path, "CONFIG_PATH": eng.CONFIG_PATH, "DB_PATH": eng.DB_PATH,
        "USERS_FILE": tmp_path / "dashboard_users", "SECRET_PATH": tmp_path / "dashboard_secret",
        "AUDIT_FILE": tmp_path / "admin-audit.jsonl", "RELOAD_FILE": tmp_path / "reload_requested",
    }.items():
        monkeypatch.setattr(dashboard, name, value)
    monkeypatch.setattr(dashboard, "engine", eng)
    monkeypatch.setattr(dashboard, "services", services)
    dashboard.init_ui_db()
    write_users(tmp_path, [("admin", TEST_PASSWORD, "admin")])
    dashboard.app.config["TESTING"] = True

    mailboxes: dict[str, FakeIMAP] = {}

    def fake_connect(acc, password=None, *, timeout=None):
        assert password == "imap-secret", "services must read the secret file"
        client = session_view(mailboxes[acc.name])
        client.login(acc.user, password)
        return client

    monkeypatch.setattr(eng, "connect", fake_connect)
    return SimpleNamespace(eng=eng, services=services, dashboard=dashboard, rspamd=rspamd,
                           clock=clock, mailboxes=mailboxes, tmp=tmp_path)


def configure(world, profile: str, *, mode: str) -> SimpleNamespace:
    """Write accounts.yml + secret, connect the engine to a fresh mailbox and
    initialise the bookmark. Returns an account handle."""
    caps, host, fixture, ip, env_from = PROFILES[profile]
    secret = world.tmp / f"secret-{profile}"
    secret.write_text("imap-secret\n")
    secret.chmod(0o600)
    cfg = {"defaults": {"bayes_user": "hjemmeserver", "junk_retention_days": 0, "trained_retention_days": 0},
           "accounts": [{"name": profile, "user": "user@example-a.dk", "imap_host": host,
                         "password_file": str(secret), "mode": mode, "threshold": 8.0,
                         "junk": "Spamfilter", "move_grace_seconds": 60}]}
    world.eng.CONFIG_PATH.write_text(json.dumps(cfg))  # JSON is valid YAML
    acc = world.eng.load_account_configs(world.eng.CONFIG_PATH)[0]
    assert acc.junk == "Spamfilter" and acc.junk_explicit

    # Provider's own Junk exists (and on Scannet carries \Junk); our
    # Spamfilter folder does not exist yet.
    client = FakeIMAP(capabilities=caps, folders=("INBOX", "Junk", "Trash"),
                      special_use={"Junk": "\\Junk"} if profile == "scannet" else None)
    world.mailboxes[profile] = client
    client.login(acc.user, "imap-secret")
    db = world.eng.Db(acc.name)
    state = world.eng.AccountState()
    world.eng._on_connected(client, db, LOG, acc, state)
    h = SimpleNamespace(acc=acc, client=client, db=db, state=state, fixture=fixture, ip=ip,
                        env_from=env_from, profile=profile)
    loop(world, h)  # first pass sets the bookmark
    return h


def loop(world, h) -> None:
    world.eng._loop_once(h.client, h.db, LOG, h.acc, h.state)


def deliver(world, h, msgid: str, subject: str, score: float) -> None:
    world.rspamd.scores[msgid] = score
    # A fresh delivery (2.2 B7: mail older than 6 h is scanned in aged mode).
    when = dt.datetime.fromtimestamp(world.clock.t, dt.timezone.utc)
    h.client.add("INBOX", mail_from_fixture(h.fixture, msgid, subject), internaldate=when)


def row(world, h, msgid: str):
    return h.db.conn.execute("SELECT * FROM messages WHERE account=? AND message_id=?",
                             (h.acc.name, msgid)).fetchone()


@pytest.mark.parametrize("profile,expect_writes", [
    ("gigahost", {"copy", "add_flags", "uid_expunge"}),
    ("scannet", {"move"}),
])
def test_spam_is_moved_listed_released_and_stays_released(world, profile, expect_writes):
    h = configure(world, profile, mode="move")
    c = h.client
    # move mode creates + subscribes the dedicated Spamfilter folder once
    assert "Spamfilter" in c.folders and c.folders["Spamfilter"].subscribed
    assert {w[0] for w in c.writes} == {"create_folder", "subscribe_folder"}
    c.writes.clear()

    deliver(world, h, "ham1@e2e.test", "Mødeindkaldelse", 0.5)
    deliver(world, h, "spam1@e2e.test", "Vind en iPhone nu", 12.0)
    loop(world, h)

    # 1) Scored with the sender context from mailctx (not the IMAP host).
    scans = {s["msgid"]: s["headers"] for s in world.rspamd.scan_calls}
    hdr = scans["spam1@e2e.test"]
    assert hdr["IP"] == h.ip
    assert hdr["From"] == h.env_from
    assert hdr["Deliver-To"] == "hjemmeserver"
    assert hdr["Rcpt"] == "user@example-a.dk"
    assert "User" not in hdr

    # 2) Decision: spam -> pending_move (grace), ham -> none.
    r = row(world, h, "spam1@e2e.test")
    assert r["our_action"] == "pending_move" and r["our_score"] >= 12.0
    assert r["score_version"] == world.eng.SCORE_VERSION == 2
    assert r["sender_ip"] == h.ip
    assert row(world, h, "ham1@e2e.test")["our_action"] == "none"
    assert c.writes == []  # nothing touched during the grace period

    # 3) After the grace period the move happens with the right method.
    world.clock.t += 61
    loop(world, h)
    assert c.msgids("Spamfilter") == ["spam1@e2e.test"]
    assert c.msgids("INBOX") == ["ham1@e2e.test"]
    assert {w[0] for w in c.writes} == expect_writes
    assert "expunge" not in [w[0] for w in c.writes]  # never a plain EXPUNGE
    assert row(world, h, "spam1@e2e.test")["our_action"] == "moved_to_junk"
    status = h.db.conn.execute("SELECT move_method, state FROM account_status WHERE account=?",
                               (h.acc.name,)).fetchone()
    assert status["move_method"] == ("UIDPLUS" if profile == "gigahost" else "MOVE")

    # 4) The caught spam shows up on /spam.
    web = world.dashboard.app.test_client()
    assert login(web).status_code in (302, 303)
    page = web.get("/spam")
    assert page.status_code == 200
    html = page.get_data(as_text=True)
    assert "Vind en iPhone nu" in html and "Mødeindkaldelse" not in html

    # 5) Release through the UI -> real services.mail_action over IMAP.
    import ui_kit as kit

    item = f"{h.acc.name}:{kit.token_for('spam1@e2e.test')}"
    reply = post(web, "/mail/action", {"action": "release", "view": "spam", "items": [item],
                                       "nonce": f"e2e-{profile}"})
    data = reply.get_json()
    assert reply.status_code == 200 and data["ok"] is True, data
    assert [x["code"] for x in data["results"]] in (["ok"], ["learn_rate_limited"])
    assert sorted(c.msgids("INBOX")) == ["ham1@e2e.test", "spam1@e2e.test"]
    assert c.msgids("Spamfilter") == []
    r = row(world, h, "spam1@e2e.test")
    assert r["user_verdict"] == "ham" and r["our_action"] == "manual_release"
    assert any("/learnham" in call["url"] for call in world.rspamd.learn_calls)
    assert web.get("/spam").get_data(as_text=True).count("Vind en iPhone nu") == 0

    # 6) The released copy is a NEW UID in INBOX; the following loops must
    #    honour the sticky verdict and never move it back.
    writes_before = len(c.writes)
    for _ in range(3):
        loop(world, h)
        world.clock.t += 120
    loop(world, h)
    assert "spam1@e2e.test" in c.msgids("INBOX")
    assert c.writes[writes_before:] == []
    r = row(world, h, "spam1@e2e.test")
    assert r["user_verdict"] == "ham" and r["our_action"] == "manual_release"
    pend = h.db.conn.execute("SELECT COUNT(*) FROM pending_move WHERE account=?", (h.acc.name,)).fetchone()[0]
    assert pend == 0


@pytest.mark.parametrize("profile", ["gigahost", "scannet"])
def test_shadow_mode_never_mutates_imap(world, profile):
    h = configure(world, profile, mode="shadow")
    c = h.client
    deliver(world, h, "spam2@e2e.test", "Billig medicin", 14.0)
    deliver(world, h, "ham2@e2e.test", "Faktura oktober", 0.2)
    for _ in range(4):
        loop(world, h)
        world.clock.t += 400  # past grace and the junk-poll interval
    assert c.writes == []
    assert "Spamfilter" not in c.folders  # shadow never creates folders
    assert sorted(c.msgids("INBOX")) == ["ham2@e2e.test", "spam2@e2e.test"]
    assert row(world, h, "spam2@e2e.test")["our_action"] == "shadow_spam"
    assert row(world, h, "ham2@e2e.test")["our_action"] == "none"
    # no learning from shadow either
    assert world.rspamd.learn_calls == []
    # The Overvåg source tab on /spam lists it as "would have been moved".
    web = world.dashboard.app.test_client()
    login(web)
    html = web.get("/spam?source=shadow").get_data(as_text=True)
    assert "Billig medicin" in html
