"""2.7 Mailsikkerhed: the admin page /mailcheck (ui_mailcheck.py), sfctl
mailcheck / doctor, the HA payload. Stored runs only - opening the page
never touches the network; "Tjek nu" is CSRF-protected and admin-only."""

from __future__ import annotations

import json
import time

from fakes_ui import csrf_of
from test_ui_admin import admin, env, sofie, text  # noqa: F401 - fixtures

import mailcheck as mc  # noqa: E402

NOW = int(time.time())
EVIL = '<script>alert(1)</script>'


def _results(*, dkim="bad", extra_text="", finished=NOW, listed=False):
    anna = [mc.item("bynet.example:spf", "SPF", "ok", "SPF-posten findes og slutter med -all.", domain="bynet.example"),
          mc.item("bynet.example:dkim", "DKIM", dkim, "Ingen af de 5 mails var DKIM-signeret." + extra_text,
                  "Slå DKIM til hos Gigahost", domain="bynet.example")]
    res = {"version": 1, "started_at": finished - 30, "finished_at": finished, "reason": "schedule",
           "domains": [{"domain": "bynet.example", "provider": "Gigahost", "dns_host": "Gigahost", "sources": ["postkasse"],
                        "no_mail": False, "checks": anna, "status": mc.worst(c["status"] for c in anna)},
                       {"domain": "example.org", "provider": "Cloudflare", "sources": ["tilføjet"], "no_mail": True,
                        "checks": [mc.item("example.org:dmarc", "DMARC", "ok", "p=reject", domain="example.org")],
                        "status": "ok"}],
           "servers": [mc.item("srv:mx:mx1.gigahost.dk:25", "mx1.gigahost.dk:25", "unknown",
                               "Kunne ikke testes (port 25 blokeret).", role="mx", host="mx1.gigahost.dk", port=25,
                               **{"for": ["bynet.example"]})],
           "blacklists": [mc.item("bl:198.51.100.7", "198.51.100.7", "bad" if listed else "ok",
                                  "Står på SpamCop." if listed else "Ikke på nogen af de 4 lister.", ip="198.51.100.7",
                                  ptr=EVIL, why=["sender mail for bynet.example"])]}
    res["counts"] = mc.counts(res)
    res["status"] = mc.overall(res)
    return res


def test_empty_page_and_navigation(env, admin):  # noqa: F811
    html = text(admin.get("/mailcheck"))
    assert "Ikke tjekket endnu" in html and "Tjek nu" in html
    assert 'href="/mailcheck"' in html and "Mailsikkerhed" in html
    assert "Intern tilstand" in html and 'href="/system"' in html
    assert "bynet.example" in html and "molt.example" in html   # derived domains in the settings hint


def test_page_shows_results_diff_history_and_escapes(env, admin):  # noqa: F811
    mc.store_run(env.conn, _results(dkim="ok", finished=NOW - 86400))
    mc.store_run(env.conn, _results(extra_text=EVIL, listed=True))
    html = text(admin.get("/mailcheck"))
    assert "Slå DKIM til hos Gigahost" in html and "Fejl" in html and "sender ikke mail" in html
    assert "port 25 blokeret" in html and "Ikke testet" in html
    assert "Siden sidst" in html and "Værre" in html
    assert "Historik" in html and "?run=" in html
    assert EVIL not in html and "<script>alert" not in html
    old = mc.list_runs(env.conn)[-1]["id"]
    html = text(admin.get(f"/mailcheck?run={old}"))
    assert "ældre tjek" in html


def test_bruger_cannot_see_or_trigger(env, sofie):  # noqa: F811
    assert sofie.get("/mailcheck").status_code == 403
    assert sofie.post("/mailcheck/run", data={}).status_code in (400, 403)
    assert sofie.post("/mailcheck/settings", data={"domains": "x.dk"}).status_code in (400, 403)


def test_tjek_nu_needs_csrf_and_sets_the_request(env, admin):  # noqa: F811
    admin.get("/mailcheck")
    r = admin.post("/mailcheck/run", data={}, headers={"Accept": "application/json"})
    assert r.status_code == 400
    assert mc.state_get(env.conn, "request") is None
    r = admin.post("/mailcheck/run", data={"csrf": csrf_of(admin)}, headers={"Accept": "application/json"})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert mc.state_get(env.conn, "request")
    assert any(a["action"] == "mailcheck_run" for a in env.audit())
    assert "Tjekket er bestilt" in text(admin.get("/mailcheck"))


def test_settings_save_validate_and_audit(env, admin):  # noqa: F811
    admin.get("/mailcheck")
    token = csrf_of(admin)
    r = admin.post("/mailcheck/settings", data={"csrf": token, "domains": "example.org\nEKSTRA.dk",
                                                "no_mail": "example.org", "skip": "vexar.example",
                                                "selectors": "bynet.example gh2024\nmolt.example sc1"},
                   headers={"Accept": "application/json"})
    assert r.status_code == 200, r.get_data(as_text=True)
    saved = json.loads(env.conn.execute("SELECT value FROM settings_kv WHERE key='mailcheck'").fetchone()[0])
    assert saved == {"domains": ["example.org", "ekstra.dk"], "no_mail": ["example.org"], "skip": ["vexar.example"],
                     "selectors": {"bynet.example": ["gh2024"], "molt.example": ["sc1"]}}
    assert any(a["action"] == "mailcheck_settings" for a in env.audit())
    for bad in ({"domains": "ikke et domæne!"}, {"selectors": "kun-et-ord"}):
        r = admin.post("/mailcheck/settings", data={"csrf": token, **bad}, headers={"Accept": "application/json"})
        assert r.status_code == 400
    assert "gh2024" in text(admin.get("/mailcheck"))


def test_internal_state_reuses_health_and_backup(env, admin, monkeypatch):  # noqa: F811
    import aio_health

    monkeypatch.setattr(aio_health, "read_status", lambda *a, **k: {
        "ts": NOW - 20, "parts": {"filter": {"ok": True}, "rspamd": {"ok": True}, "redis": {"ok": True},
                                  "unbound": {"ok": False, "detail": "timeout"}, "clamd": {"ok": True}}})
    html = text(admin.get("/mailcheck"))
    assert "ClamAV" in html and "Unbound (DNS)" in html and "fejler: timeout" in html
    assert "Krypteret backup" in html and "DMARC-rapporter" in html and "Livstegn" in html



def test_kendt_ignorer_acknowledges_a_finding(env, admin):  # noqa: F811
    mc.store_run(env.conn, _results())
    html = text(admin.get("/mailcheck"))
    assert "Kendt – ignorér" in html
    run = mc.load_run(env.conn)
    dkim = next(i for i in mc.all_items(run) if i["key"] == "bynet.example:dkim")
    token = csrf_of(admin)
    r = admin.post("/mailcheck/ack", data={"key": "bynet.example:dkim", "fp": "stale"},
                   headers={"Accept": "application/json"})
    assert r.status_code == 400                                       # no CSRF
    r = admin.post("/mailcheck/ack", data={"csrf": token, "key": "bynet.example:dkim", "fp": "stale"},
                   headers={"Accept": "application/json"})
    assert r.status_code == 400 and mc.load_acks(env.conn) == {}     # changed since: refused
    r = admin.post("/mailcheck/ack", data={"csrf": token, "key": "bynet.example:dkim", "fp": mc.fingerprint(dkim)},
                   headers={"Accept": "application/json"})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert "bynet.example:dkim" in mc.load_acks(env.conn)
    assert any(a["action"] == "mailcheck_ack" for a in env.audit())
    html = text(admin.get("/mailcheck"))
    assert "Kendt – ignoreret" in html and "Ikke længere kendt" in html and "markeret som kendt" in html
    assert mc.last_summary(env.conn)["errors"] == 0
    r = admin.post("/mailcheck/unack", data={"csrf": token, "key": "bynet.example:dkim"},
                   headers={"Accept": "application/json"})
    assert r.status_code == 200 and mc.load_acks(env.conn) == {}
    assert mc.last_summary(env.conn)["errors"] == 1


def test_bruger_cannot_acknowledge(env, sofie):  # noqa: F811
    assert sofie.post("/mailcheck/ack", data={"key": "x", "fp": "y"}).status_code in (400, 403)


def test_degraded_run_shows_a_warning(env, admin):  # noqa: F811
    res = _results()
    mc._degrade(res, "DNS svarede ikke.")
    res["counts"], res["status"] = mc.counts(res), mc.overall(res)
    mc.store_run(env.conn, res)
    html = text(admin.get("/mailcheck"))
    assert "kunne ikke gennemføres ordentligt" in html and "DNS svarede ikke." in html
    assert "Kendt – ignorér" not in html                              # nothing to acknowledge
