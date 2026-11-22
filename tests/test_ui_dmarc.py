"""2.6 (C2): the admin page /dmarc (ui_dmarc.py): per domain totals, % pass,
top sources with reverse DNS marked godkendt / fejler, the recommendation,
the settings form (rua address, per mailbox, extra domains, audited) and
the DNS hints. Admin only; report content is escaped."""

from __future__ import annotations

import json
import time

from fakes_ui import csrf_of
from test_ui_admin import admin, env, sofie, text  # noqa: F401 - fixtures

import dmarc  # noqa: E402
from test_dmarc import feedback  # noqa: E402

import pytest  # noqa: E402

NOW = int(time.time())
DAY = 86400
EVIL = '<script>alert(1)</script>'
PTR_CALLS: list[str] = []


@pytest.fixture(autouse=True)
def _no_dns(monkeypatch):
    PTR_CALLS.clear()

    def lookup(ip, **kw):
        PTR_CALLS.append(ip)
        return None

    monkeypatch.setattr(dmarc, "ptr_lookup", lookup)


def _seed(conn, domain="bynet.example", days=20, good=990, bad=10, org="google.com"):
    dmarc.ensure_schema(conn)
    for i in range(days):
        b = NOW - (i + 1) * DAY
        rep = dmarc.parse_report_bytes(feedback(domain=domain, org=org, rid=f"{domain}-{i}", begin=b,
                                                records=[("209.85.220.41", good, "pass", "pass"),
                                                         ("192.0.2.66", bad, "fail", "fail")]))
        dmarc.store(conn, "bynet", f"m{i}@x", rep, now=NOW)
    conn.execute("INSERT OR REPLACE INTO dmarc_ptr VALUES('209.85.220.41', 'mail-sor-f41.google.com', ?)", (NOW,))
    conn.commit()


def test_page_shows_domains_sources_and_advice(env, admin):  # noqa: F811
    _seed(env.conn)
    html = text(admin.get("/dmarc"))
    assert "bynet.example" in html and "Består DMARC" in html and "99 %" in html
    assert "mail-sor-f41.google.com" in html and "209.85.220.41" in html
    assert "godkendt" in html and "fejler" in html
    assert "Klar til p=quarantine" in html
    assert 'href="/dmarc"' in html  # in the admin navigation
    assert "rua=mailto:ole@bynet.example" in html  # DNS hint with the default rua address


def test_empty_page_explains_what_to_do(env, admin):  # noqa: F811
    html = text(admin.get("/dmarc"))
    assert "Ingen DMARC-rapporter endnu" in html and "_dmarc." in html


def test_hostile_report_content_is_escaped(env, admin):  # noqa: F811
    dmarc.ensure_schema(env.conn)
    rep = dmarc.parse_report_bytes(feedback(org="evil&lt;script&gt;", rid="x1"))
    dmarc.store(env.conn, "bynet", "e@x", rep, now=NOW)
    env.conn.execute("INSERT OR REPLACE INTO dmarc_ptr VALUES('192.0.2.66', ?, ?)", (EVIL, NOW))
    env.conn.commit()
    html = text(admin.get("/dmarc"))
    assert EVIL not in html and "<script>alert" not in html


def test_bruger_cannot_see_or_change_dmarc(env, sofie):  # noqa: F811
    assert sofie.get("/dmarc").status_code == 403
    r = sofie.post("/dmarc/settings", data={"rua": "x@y.dk"})
    assert r.status_code in (400, 403)


def test_settings_save_validate_and_audit(env, admin):  # noqa: F811
    admin.get("/dmarc")
    token = csrf_of(admin)
    r = admin.post("/dmarc/settings", data={"csrf": token, "rua": "dmarc@molt.example", "acc:bynet": "off",
                                            "acc:molt": "on", "domains": "example.org\nEXAMPLE.org, gravisk.example"},
                   headers={"Accept": "application/json"})
    assert r.status_code == 200, r.get_data(as_text=True)
    row = env.conn.execute("SELECT value FROM settings_kv WHERE key='dmarc'").fetchone()
    saved = json.loads(row[0])
    assert saved == {"rua": "dmarc@molt.example", "accounts": {"bynet": "off", "molt": "on"},
                     "domains": ["example.org", "gravisk.example"]}
    assert any(a["action"] == "dmarc_settings" and "rua=dmarc@molt.example" in a.get("detail", "") for a in env.audit())
    html = text(admin.get("/dmarc"))
    assert "example.org._report._dmarc.molt.example" in html  # RFC 7489 7.1 permission record
    bad = admin.post("/dmarc/settings", data={"csrf": token, "rua": "not-an-address"},
                     headers={"Accept": "application/json"})
    assert bad.status_code == 400
    bad = admin.post("/dmarc/settings", data={"csrf": token, "rua": "a@b.dk", "domains": "evil domain!"},
                     headers={"Accept": "application/json"})
    assert bad.status_code == 400
    assert json.loads(env.conn.execute("SELECT value FROM settings_kv WHERE key='dmarc'").fetchone()[0])["rua"] == \
        "dmarc@molt.example"


def test_reverse_dns_is_looked_up_lazily_on_the_page_and_cached(env, admin):  # noqa: F811
    _seed(env.conn)
    admin.get("/dmarc")
    assert PTR_CALLS == ["192.0.2.66"]  # the cached name is not looked up again
    admin.get("/dmarc")
    assert PTR_CALLS == ["192.0.2.66"]  # "no name" is cached too
