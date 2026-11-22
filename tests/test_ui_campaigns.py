"""UI 2.6: the Oversigt items for A3 (block suggestions with 'Bloker for
alle' / 'Ignorer') and A6 (spam piling up in a protected inbox), the
'Samme spam som i <postkasse>' timeline text (A2) and the permission
matrix of the new route. Block suggestions run the real services function
against the test database (fakes_ui EngineShim)."""

from __future__ import annotations

import json
import time

import pytest

from fakes_ui import insert_message, post

import campaigns  # noqa: E402
import services as real_services  # noqa: E402
import ui_campaigns  # noqa: E402,F401
from test_ui_23 import audits, body, client_for, csp_clean, detail_url, env  # noqa: F401,E402 - env = fixture

NOW = int(time.time())
TITLE = "Forslag: bloker @bad-shop.example for alle postkasser (2 spam-mails fra 2 postkasser)"


@pytest.fixture
def cenv(env, monkeypatch):  # noqa: F811
    svc = env.services
    shim = svc.engine_shim()
    monkeypatch.setattr(svc, "block_suggestions",
                        lambda **kw: real_services.block_suggestions(engine=shim, **kw), raising=False)
    monkeypatch.setattr(svc, "dismiss_block_suggestion",
                        lambda *a, **kw: real_services.dismiss_block_suggestion(*a, engine=shim), raising=False)
    monkeypatch.setattr(svc, "protected_watch", lambda **kw: [], raising=False)
    c = env.conn
    for acc, mid, sender in (("bynet", "bs1@x", "Tilbud <tilbud@bad-shop.example>"),
                             ("molt", "bs2@x", "nyhed@mail.bad-shop.example"),
                             ("bynet", "own1@x", "ole@bynet.example"), ("molt", "own2@x", "ole@bynet.example"),
                             ("bynet", "fm1@x", "a@gmail.com"), ("molt", "fm2@x", "b@gmail.com")):
        dom = sender.rpartition("@")[2].rstrip(">")
        insert_message(c, acc, mid, sender=sender, subject="Kæmpe udsalg", current_folder="Spamfilter",
                       our_action="user_junked", user_verdict="spam", verdict_at=NOW - 3600,
                       sender_auth=json.dumps({"dkim": [dom]}))
        campaigns.ensure_schema(c)
        c.execute("INSERT INTO campaign_source(account, message_id, campaign_key, actor, at) VALUES(?,?,?,?,?)",
                  (acc, mid, "k", "user:move", NOW - 3600))
    c.commit()
    return env


def _overview(c) -> str:
    return body(c.get("/"))


def test_admin_sees_block_suggestion_with_both_buttons(cenv):
    html = _overview(client_for(cenv, "admin"))
    assert TITLE in html
    item = html.split(TITLE)[1].split("</li>")[0]
    assert "Bloker for alle" in item and "Afvis" in item
    assert 'action="/rules/add"' in item and 'name="account" value="*"' in item
    assert 'name="pattern" value="@bad-shop.example"' in item and 'name="scope" value="domain"' in item
    assert 'action="/rules/suggestions/dismiss"' in item
    # Never the owner's own domain or a freemail domain.
    assert "@bynet.example for alle" not in html and "@gmail.com for alle" not in html
    csp_clean(html, "/")


def test_block_for_all_uses_the_rule_route_and_audit(cenv):
    admin = client_for(cenv, "admin")
    r = post(admin, "/rules/add", {"kind": "block", "account": "*", "pattern": "@bad-shop.example",
                                   "scope": "domain", "next": "/", "note": "Forslag: 2 spam-mails fra 2 postkasser"})
    assert r.get_json()["ok"], r.get_json()
    row = cenv.conn.execute("SELECT * FROM sender_rules WHERE pattern='@bad-shop.example'").fetchone()
    assert row["account"] == "*" and row["kind"] == "block" and row["created_by"] == "admin"
    assert [a["detail"] for a in audits(cenv, "rule_add")] == ["block @bad-shop.example"]
    assert TITLE not in _overview(admin)


def test_block_for_all_still_refuses_the_shop(cenv):
    admin = client_for(cenv, "admin")
    r = post(admin, "/rules/add", {"kind": "block", "account": "*", "pattern": "@vexar.example", "scope": "domain"})
    assert not r.get_json()["ok"]
    assert cenv.conn.execute("SELECT COUNT(*) FROM sender_rules WHERE pattern='@vexar.example'").fetchone()[0] == 0


def test_ignore_persists_and_is_audited(cenv):
    admin = client_for(cenv, "admin")
    r = post(admin, "/rules/suggestions/dismiss", {"domain": "bad-shop.example", "next": "/"})
    assert r.get_json()["ok"], r.get_json()
    assert cenv.conn.execute("SELECT dismissed_by FROM block_suggestion_dismissed WHERE domain='bad-shop.example'"
                             ).fetchone()[0] == "admin"
    assert [a["detail"] for a in audits(cenv, "block_suggestion_dismiss")] == ["bad-shop.example"]
    assert TITLE not in _overview(admin)


@pytest.mark.parametrize("who", ["anna", "bo", None])
def test_dismiss_route_is_admin_only(cenv, who):
    c = client_for(cenv, who)
    r = post(c, "/rules/suggestions/dismiss", {"domain": "bad-shop.example"})
    assert r.status_code in (302, 401, 403)
    assert cenv.conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='block_suggestion_dismissed'"
                             ).fetchone()[0] in (0, 1)
    n = cenv.conn.execute("SELECT COUNT(*) FROM block_suggestion_dismissed").fetchone()[0] \
        if cenv.conn.execute("SELECT 1 FROM sqlite_master WHERE name='block_suggestion_dismissed'").fetchone() else 0
    assert n == 0


def test_user_never_sees_suggestions(cenv):
    html = _overview(client_for(cenv, "anna"))
    assert "Forslag: bloker" not in html


def test_protected_inbox_item(cenv, monkeypatch):
    monkeypatch.setattr(cenv.services, "protected_watch",
                        lambda **kw: [{"account": "bynet", "n": 4, "threshold": 6.0, "protected_threshold": 7.0}],
                        raising=False)
    html = _overview(client_for(cenv, "admin"))
    assert "Spam samler sig i en beskyttet indbakke (bynet)" in html
    assert "4 mails over grænsen – overvej at sænke grænsen for beskyttede adresser" in html
    assert 'href="/accounts/bynet"' in html
    assert "Spam samler sig" not in _overview(client_for(cenv, "anna"))


def test_services_failure_never_breaks_oversigt(cenv, monkeypatch):
    def boom(**kw):
        raise RuntimeError("db exploded")
    monkeypatch.setattr(cenv.services, "block_suggestions", boom, raising=False)
    monkeypatch.setattr(cenv.services, "protected_watch", boom, raising=False)
    r = client_for(cenv, "admin").get("/")
    assert r.status_code == 200 and "Forslag: bloker" not in body(r)


def test_timeline_shows_the_source_mailbox(cenv):
    c = cenv.conn
    insert_message(c, "molt", "cp@x", sender="nyhed@mail.bad-shop.example", subject="Kæmpe udsalg",
                   our_action="moved_to_junk", current_folder="Spamfilter")
    c.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES('molt', ?, 'cp@x', 'campaign_move', "
              "'Samme spam som i bynet: samme afsenderdomæne og emne (kilde bs1@x)')", (NOW - 60,))
    c.commit()
    html = body(client_for(cenv, "admin").get(detail_url("molt", "cp@x")))
    assert "Samme spam som i en anden postkasse" in html
    assert "Samme spam som i bynet: samme afsenderdomæne og emne (kilde bs1@x)" in html
