"""UI (B22): Indstillinger -> Beskyttede domæner, the Oversigt attention
item for new registrations, the threat badge + 'Ikke en efterligning' on
the message detail page, and the permission matrix of every new route
(admin only; a Bruger never sees protected domains or the watch).

The real services functions run against the test database (fakes_ui
EngineShim), so the pages render what production returns."""

from __future__ import annotations

import json
import time

import pytest

from fakes_ui import insert_message, post

import dashboard  # noqa: E402
import ui_kit as kit  # noqa: E402
import ui_lookalike  # noqa: E402
from test_ui_23 import audits, body, client_for, csp_clean, detail_url, env  # noqa: F401,E402 - env = fixture

NOW = int(time.time())
LOOK_SYMS = [{"n": "TH_LOOKALIKE_DOMAIN", "s": 6.0, "o": ["pinslkbing.example", "pinsikbing.example", "from"]},
             {"n": "BAYES_SPAM", "s": 1.0, "o": ["90%"]}]
URL_SYMS = [{"n": "TH_LOOKALIKE_URL", "s": 4.0, "o": ["gravlsk.example", "gravisk.example", "url"]}]
EVIL = 'xn--pnsikbing-v9h.example"><script>alert(1)</script>'


@pytest.fixture
def lenv(env):  # noqa: F811
    c = env.conn
    import lookalike as lk

    lk.ensure_schema(c)
    rows = [
        # (domain, protected, kind, mx, a, new_at, acked)
        ("pinslkbing.example", "pinsikbing.example", "homoglyph", ["10 mx.evil.example"], [], NOW - 3600, None),
        ("pinsikbing.com", "pinsikbing.example", "tld", [], ["192.0.2.1"], None, None),
        ("rnolt.example", "molt.example", "homoglyph", ["5 mx.x"], ["192.0.2.2"], NOW - 40 * 86400, None),
    ]
    for d, p, k, mx, a, new_at, acked in rows:
        c.execute("INSERT INTO lookalike_watch(domain, protected, kind, created_at, checked_at, ns, mx, a, registered, "
                  "first_registered_at, new_at, new_what, acked_at) VALUES(?,?,?,?,?,?,?,?,1,?,?,?,?)",
                  (d, p, k, NOW - 30 * 86400, NOW - 3600, json.dumps(["ns.x"]), json.dumps(mx), json.dumps(a),
                   NOW - 7 * 86400, new_at, "mx" if new_at else None, acked))
    c.execute("INSERT INTO lookalike_watch(domain, protected, kind, created_at, checked_at, ns, mx, a, registered) "
              "VALUES('pinsikbin.example', 'pinsikbing.example', 'omission', ?, ?, '[]', '[]', '[]', 0)", (NOW, NOW))
    c.execute("INSERT INTO engine_state(key, value, updated_at) VALUES('lookalike_watch_last', ?, ?)",
              (json.dumps({"started_at": NOW - 4000, "finished_at": NOW - 3600, "checked": 323, "new": 1,
                           "capped": False, "error": None}), NOW))
    insert_message(c, "bynet", "look1@x", our_action="moved_to_junk", our_score=7.0, current_folder="Spamfilter",
                   sender="Pinsikbing <ordre@pinslkbing.example>", subject="Ordrebekræftelse", threat="lookalike",
                   threat_detail="pinslkbing.example ligner pinsikbing.example", symbols=LOOK_SYMS)
    insert_message(c, "bynet", "look2@x", our_score=5.0, sender="nyhed@shop.example", subject="Tilbud",
                   symbols=URL_SYMS)
    insert_message(c, "bynet", "look3@x", our_action="moved_to_junk", our_score=7.0, current_folder="Spamfilter",
                   sender="x@evil.example", subject="Evil", threat="lookalike",
                   threat_detail=EVIL + " ligner pinsikbing.example",
                   symbols=[{"n": "TH_LOOKALIKE_DOMAIN", "s": 6.0, "o": [EVIL, "pinsikbing.example", "from"]}])
    c.commit()
    return env


def _settings(c) -> str:
    return body(c.get("/settings"))


def test_settings_card_renders_everything(lenv):
    html = _settings(client_for(lenv, "admin"))
    card = html.split('id="beskyttede-domaener"')[1]
    assert "Beskyttede domæner" in card
    for d in ("bynet.example", "molt.example", "pinsikbing.example", "gravisk.example", "vexar.example"):
        assert d in card, d
    assert "Seneste kontrol" in card and "323 domæner slået op" in card and "Kør kontrol nu" in card
    assert "1 nyt domæne ligner jeres" in card and "Markér alle som set" in card
    assert "pinslkbing.example" in card and "Mailserver" in card and "Hjemmeside" in card and "Nyt" in card
    assert "Mails fra lignende domæner" in card and "gravlsk.example" in card
    assert "Ikke en efterligning" in card and "Redigér listen" in card
    assert "pinsikbin.example" not in card                       # NXDOMAIN rows are not findings
    csp_clean(html, "/settings")
    # A lookalike is text, never a link; attacker text is escaped.
    assert 'href="https://pinslkbing' not in html and 'href="http://pinslkbing' not in html
    assert "<script>alert(1)" not in html


def test_settings_card_first_run_text(env):  # noqa: F811
    card = _settings(client_for(env, "admin")).split('id="beskyttede-domaener"')[1]
    assert "Ikke kørt endnu" in card and "Registrerede lignende domæner" not in card


def test_edit_protected_domains(lenv):
    admin = client_for(lenv, "admin")
    r = post(admin, "/settings/lookalike", {"domains": "bank.dk\nhttps://www.e-conomic.dk/login, Bank.dk"})
    assert r.get_json()["ok"], r.get_json()
    assert lenv.raw_config()["defaults"]["protected_domains"] == ["bank.dk", "e-conomic.dk"]
    assert audits(lenv, "protected_domains")
    r = post(admin, "/settings/lookalike", {"domains": "bank.dk ikke-et-domæne!"})
    assert not r.get_json()["ok"] and "Ugyldige domæner" in r.get_json()["message"]
    assert lenv.raw_config()["defaults"]["protected_domains"] == ["bank.dk", "e-conomic.dk"]
    r = post(admin, "/settings/lookalike", {"domains": "bank.dk e-conomic.dk"})
    assert r.get_json()["ok"] and "uændret" in r.get_json()["message"]
    r = post(admin, "/settings/lookalike", {"reset": "1"})
    assert r.get_json()["ok"] and "protected_domains" not in lenv.raw_config()["defaults"]
    # An explicit empty list keeps only the mailbox domains.
    r = post(admin, "/settings/lookalike", {"domains": ""})
    assert r.get_json()["ok"] and lenv.raw_config()["defaults"]["protected_domains"] == []


def test_not_a_lookalike_flow(lenv):
    admin = client_for(lenv, "admin")
    r = post(admin, "/settings/lookalike/allow", {"domain": "pinsikbing.com", "protected": "pinsikbing.example"})
    assert r.get_json()["ok"]
    c = lenv.conn
    assert c.execute("SELECT created_by FROM lookalike_allow WHERE domain='pinsikbing.com'").fetchone()[0] == "admin"
    assert [a["detail"] for a in audits(lenv, "lookalike_allow")] == ["pinsikbing.com ligner pinsikbing.example"]
    assert c.execute("SELECT COUNT(*) FROM events WHERE event='lookalike_allowed'").fetchone()[0] == 1
    r = post(admin, "/settings/lookalike/allow", {"domain": "pinsikbing.com"})
    assert r.get_json()["ok"] and "allerede" in r.get_json()["message"]
    assert len(audits(lenv, "lookalike_allow")) == 1          # nothing new to audit
    # own domains can never be marked
    r = post(admin, "/settings/lookalike/allow", {"domain": "shop.pinsikbing.example"})
    assert not r.get_json()["ok"] and "egne" in r.get_json()["message"]
    r = post(admin, "/settings/lookalike/allow", {"domain": "ikke et domæne"})
    assert not r.get_json()["ok"]
    card = _settings(admin).split('id="beskyttede-domaener"')[1]
    assert "Fjern" in card
    r = post(admin, "/settings/lookalike/unallow", {"domain": "pinsikbing.com"})
    assert r.get_json()["ok"] and audits(lenv, "lookalike_unallow")
    assert c.execute("SELECT COUNT(*) FROM lookalike_allow").fetchone()[0] == 0


def test_allow_returns_to_the_message(lenv):
    admin = client_for(lenv, "admin")
    here = detail_url("bynet", "look1@x")
    r = post(admin, "/settings/lookalike/allow", {"domain": "pinslkbing.example", "next": here}, json_reply=False)
    assert r.status_code == 302 and r.headers["Location"].endswith(here)
    r = post(admin, "/settings/lookalike/allow", {"domain": "x.dk", "next": "//evil.example/"}, json_reply=False)
    assert r.headers["Location"].endswith("/settings#beskyttede-domaener")


def test_overview_attention_admin_only_and_ack(lenv):
    admin = client_for(lenv, "admin")
    html = body(admin.get("/"))
    assert "Nyt domæne ligner pinsikbing.example" in html and "pinslkbing[.]example" in html
    assert "rnolt" not in html                               # older than 14 days
    for who in ("anna", "bo"):
        assert "Nyt domæne ligner" not in body(client_for(lenv, who).get("/")), who
    r = post(admin, "/settings/lookalike/ack", {"domain": "pinslkbing.example"})
    assert r.get_json()["ok"] and audits(lenv, "lookalike_ack")
    assert "Nyt domæne ligner" not in body(admin.get("/"))
    # the findings list keeps it (no longer 'Nyt')
    assert "pinslkbing.example" in _settings(admin).split('id="beskyttede-domaener"')[1]


def test_allowed_domain_leaves_the_attention_list(lenv):
    admin = client_for(lenv, "admin")
    post(admin, "/settings/lookalike/allow", {"domain": "pinslkbing.example"})
    assert "Nyt domæne ligner" not in body(admin.get("/"))


def test_run_request(lenv):
    admin = client_for(lenv, "admin")
    r = post(admin, "/settings/lookalike/run", {})
    assert r.get_json()["ok"] and audits(lenv, "lookalike_run")
    c = lenv.conn
    assert c.execute("SELECT value FROM engine_state WHERE key='lookalike_watch_request'").fetchone()[0]
    r = post(admin, "/settings/lookalike/run", {})
    assert r.get_json()["ok"] and "allerede bestilt" in r.get_json()["message"]
    assert "Kontrollen er bestilt" in _settings(admin)
    c.execute("DELETE FROM engine_state WHERE key='lookalike_watch_request'")
    c.execute("INSERT OR REPLACE INTO engine_state(key, value, updated_at) VALUES('lookalike_watch_attempt_at', ?, ?)",
              (str(int(time.time()) - 60), NOW))   # real time: NOW is fixed at import, and the
    c.commit()                                    # full suite can outlast the 15-min window
    r = post(admin, "/settings/lookalike/run", {})
    assert not r.get_json()["ok"] and "lige kørt" in r.get_json()["message"]


def test_detail_badge_and_admin_button(lenv):
    admin = body(client_for(lenv, "admin").get(detail_url("bynet", "look1@x")))
    assert "Efterligner jeres domæne: pinslkbing.example ligner pinsikbing.example" in admin
    assert "Ikke en efterligning: pinslkbing.example" in admin
    assert "Efterligner jeres domæne: pinslkbing.example ligner pinsikbing.example (afsenderen)" in admin   # symbol row
    csp_clean(admin, "detail")
    anna = body(client_for(lenv, "anna").get(detail_url("bynet", "look1@x")))
    assert "Efterligner jeres domæne" in anna and "Ikke en efterligning" not in anna
    url = body(client_for(lenv, "admin").get(detail_url("bynet", "look2@x")))
    assert "Link til gravlsk.example, der ligner jeres domæne gravisk.example" in url and "Ikke en efterligning" in url
    evil = body(client_for(lenv, "admin").get(detail_url("bynet", "look3@x")))
    assert "<script>alert(1)" not in evil
    csp_clean(evil, "evil detail")


def test_list_badge_is_compact(lenv):
    html = body(client_for(lenv, "admin").get("/spam"))
    assert "Efterligner jeres domæne" in html


def test_release_needs_admin(lenv):
    anna = client_for(lenv, "anna")
    r = post(anna, "/mail/action", {"key": f"bynet:{kit.token_for('look1@x')}", "action": "release"})
    data = r.get_json()
    assert not data.get("ok")
    row = lenv.conn.execute("SELECT our_action FROM messages WHERE message_id='look1@x'").fetchone()
    assert row[0] == "moved_to_junk"


# ===================================================================== permission matrix

POSTS = [("/settings/lookalike", {"domains": "evil.dk"}),
         ("/settings/lookalike/allow", {"domain": "pinslkbing.example"}),
         ("/settings/lookalike/unallow", {"domain": "pinslkbing.example"}),
         ("/settings/lookalike/ack", {}),
         ("/settings/lookalike/run", {})]


def test_every_new_route_has_the_admin_policy():
    for rule in dashboard.app.url_map.iter_rules():
        if rule.rule.startswith("/settings/lookalike"):
            assert dashboard.route_policy(rule.endpoint) == dashboard.POLICY_ADMIN, rule.rule


@pytest.mark.parametrize("who", ["anna", "bo", "cille", None])
def test_post_matrix(lenv, who):
    c = client_for(lenv, who)
    cfg = lenv.config.read_text()
    for url, data in POSTS:
        r = post(c, url, data)
        assert r.status_code == (401 if who is None else 403), f"{who} {url}: {r.status_code}"
    assert lenv.config.read_text() == cfg
    db = lenv.conn
    assert db.execute("SELECT COUNT(*) FROM lookalike_allow").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM lookalike_watch WHERE acked_at IS NOT NULL").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM engine_state WHERE key='lookalike_watch_request'").fetchone()[0] == 0


@pytest.mark.parametrize("who", ["anna", "bo", "cille"])
def test_bruger_never_sees_the_card(lenv, who):
    c = client_for(lenv, who)
    assert c.get("/settings").status_code == 403
    assert "beskyttede-domaener" not in body(c.get("/"))


def test_csrf_required(lenv):
    admin = client_for(lenv, "admin")
    for url, data in POSTS:
        assert admin.post(url, data=data).status_code == 400, url


def test_card_survives_a_failing_service(lenv, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("x")

    monkeypatch.setattr(lenv.services, "lookalike_overview", boom)
    html = _settings(client_for(lenv, "admin"))
    assert 'id="beskyttede-domaener"' in html and "Ikke kørt endnu" in html


def test_symbol_texts():
    for n in ("TH_LOOKALIKE_DOMAIN", "TH_LOOKALIKE_URL", "TH_LOOKALIKE_ALLOWED"):
        assert n in kit.SYMBOL_TEXT and "_" not in kit.SYMBOL_TEXT[n]
    assert kit.explain_symbol_detail(LOOK_SYMS[0]) == \
        "Efterligner jeres domæne: pinslkbing.example ligner pinsikbing.example (afsenderen)"
    allowed = {"n": "TH_LOOKALIKE_ALLOWED", "s": 0.0, "o": ["pinslkbing.example", "pinsikbing.example", "ham_history"]}
    assert kit.explain_symbol_detail(allowed) == "pinslkbing.example ligner pinsikbing.example, men tæller ikke (kendt afsender)"
    assert kit.plain_reason("TH_LOOKALIKE_DOMAIN") == "Afsenderens domæne efterligner et af jeres egne"


def test_event_and_audit_labels():
    import ui_admin
    import ui_mail

    for ev in ("lookalike_registered", "lookalike_watch_done", "lookalike_watch_failed", "lookalike_allowed",
               "lookalike_unallowed", "lookalike_acked", "lookalike_watch_requested"):
        assert ev in ui_admin.EVENT_LABELS and ev in ui_mail.EVENT_INFO, ev
        assert "_" not in ui_admin.EVENT_LABELS[ev][0] and "_" not in ui_mail.EVENT_INFO[ev][0]
    for a in ("protected_domains", "lookalike_allow", "lookalike_unallow", "lookalike_ack", "lookalike_run"):
        assert a in ui_admin.AUDIT_LABELS, a


def test_attention_items_need_admin(lenv):
    with lenv.app.test_request_context("/"):
        assert ui_lookalike.attention_items() == []          # nobody logged in


# ----- 2.3.6 review fixes ---------------------------------------------------------------------


def _last_run(c, **summary) -> None:
    base = {"started_at": NOW - 4000, "finished_at": NOW - 3600, "checked": 0, "new": 0, "capped": False,
            "error": None, "errors": 0}
    base.update(summary)
    c.execute("INSERT OR REPLACE INTO engine_state(key, value, updated_at) VALUES('lookalike_watch_last', ?, ?)",
              (json.dumps(base), NOW))
    c.commit()


@pytest.mark.parametrize("summary,why", [
    ({"error": "resolver unreachable"}, "navneserveren kunne ikke nås"),
    ({"error": "dns errors", "errors": 20}, "20 opslag fejlede hos navneserveren"),
])
def test_failed_run_text_names_the_real_retry_window(lenv, summary, why):
    """The retry only happens in the 03-05 window: never promise 'om en time'."""
    _last_run(lenv.conn, **summary)
    card = _settings(client_for(lenv, "admin")).split('id="beskyttede-domaener"')[1]
    assert why in card
    assert "prøver igen mellem kl. 3 og 5 om natten" in card and "om en time" not in card


def test_attention_lists_several_protected_domains_in_danish(lenv):
    c = lenv.conn
    c.execute("INSERT INTO lookalike_watch(domain, protected, kind, created_at, checked_at, mx, a, registered, "
              "new_at, new_what) VALUES('gravlsk.example', 'gravisk.example', 'homoglyph', ?, ?, '[\"1 mx\"]', '[]', 1, ?, 'mx')",
              (NOW - 86400, NOW - 3600, NOW - 1800))
    c.commit()
    html = body(client_for(lenv, "admin").get("/"))
    assert "2 nye domæner ligner jeres" in html
    assert "Domænerne ligner gravisk.example og pinsikbing.example." in html
    assert "gravisk.example, pinsikbing.example og har" not in html
    card = _settings(client_for(lenv, "admin")).split('id="beskyttede-domaener"')[1]
    assert "2 nye domæner ligner jeres" in card and "De har lige fået en mailserver" in card


def test_provider_exemption_text():
    sym = {"n": "TH_LOOKALIKE_ALLOWED", "s": 0.0, "o": ["bynetexample.onmicrosoft.com", "bynet.example", "provider"]}
    assert kit.explain_symbol_detail(sym) == \
        "bynetexample.onmicrosoft.com ligner bynet.example, men tæller ikke (jeres egen mail via mailudbyderen)"
