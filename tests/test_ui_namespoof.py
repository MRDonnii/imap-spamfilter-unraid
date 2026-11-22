"""UI (2.7, Falske afsendernavne): Indstillinger -> Beskyttede navne (Fra /
Prøv / Til, the name list editor, "Hent navne fra Sendt post", the hit
list with "Tillad adressen"), the Oversigt item after a week of Prøv, the
symbol text and admin button on the message detail page, and the
permission matrix (admin only).

The real services functions run against the test database (fakes_ui
EngineShim), so the pages render what production returns."""

from __future__ import annotations

import json
import time

import pytest

from fakes_ui import insert_message, post

import dashboard  # noqa: E402
import namespoof as ns  # noqa: E402
import ui_kit as kit  # noqa: E402
from test_ui_23 import audits, body, client_for, csp_clean, detail_url, env  # noqa: F401,E402 - env = fixture

NOW = int(time.time())
TRIAL = [{"n": "TH_NAME_SPOOF_TRIAL", "s": 0.0, "o": ["Ole Storm", "c…@outlook.com", "svar-til"]},
         {"n": "BAYES_SPAM", "s": 1.0, "o": ["90%"]}]
ON = [{"n": "TH_NAME_SPOOF", "s": 7.0, "o": ["Ole Storm", "c…@outlook.com", "emne"]}]
EVIL = 'Sofie"><script>alert(1)</script>'


@pytest.fixture
def nenv(env):  # noqa: F811
    import contacts

    c = env.conn
    contacts.ensure_schema(c)
    ns.ensure_schema(c)
    ns.save_name(c, name="Ole Storm", allow=["ole@bynet.example", "ole@molt.example"], actor="admin", now=NOW)
    ns.save_name(c, name="Inge", allow=[], enabled=False, actor="admin", now=NOW)
    insert_message(c, "bynet", "ns1@x", our_score=1.0, sender="Ole Storm <ceo.office@outlook.com>",
                   subject="Er du ved din computer?", symbols=TRIAL)
    insert_message(c, "molt", "ns2@x", our_action="moved_to_junk", our_score=8.0, current_folder="Spamfilter",
                   sender="Ole Storm <ceo.office@outlook.com>", subject="Betaling", symbols=ON)
    insert_message(c, "bynet", "ns3@x", our_score=1.0, sender=f"{EVIL} <x@evil.example>",
                   symbols=[{"n": "TH_NAME_SPOOF_TRIAL", "s": 0.0, "o": [EVIL, "x…@evil.example", "navn"]}])
    c.commit()
    return env


def _card(c) -> str:
    html = body(c.get("/settings"))
    return html.split('id="beskyttede-navne"')[1]


def test_settings_card_renders_names_mode_and_hits(nenv):
    html = body(client_for(nenv, "admin").get("/settings"))
    card = html.split('id="beskyttede-navne"')[1]
    assert "Beskyttede navne" in card and "1 navn – falske afsendernavne" in card
    assert "Ole Storm" in card and "ole@bynet.example" in card and "ole@molt.example" in card
    assert "Inge" in card and "Slået fra" in card and "Kun præcis navn" in card
    assert 'value="shadow" checked' in card and "Prøv i 0 dage" in card
    assert "Mails med jeres navne fra andre adresser" in card and "ceo.office@outlook.com" in card
    assert "Prøv: ville give +5" in card and "Tillad adressen" in card and "Hent navne fra Sendt post" in card
    assert "<script>alert(1)" not in html
    csp_clean(html, "/settings")


def test_mode_switch_is_audited(nenv):
    admin = client_for(nenv, "admin")
    r = post(admin, "/settings/namespoof/mode", {"mode": "on"})
    assert r.get_json()["ok"] and "Til" in r.get_json()["message"]
    assert ns.get_mode(nenv.conn)["mode"] == "on"
    assert [a["detail"] for a in audits(nenv, "namespoof_mode")] == ["mode=on"]
    assert 'value="on" checked' in _card(admin)
    r = post(admin, "/settings/namespoof/mode", {"mode": "on"})
    assert r.get_json()["ok"] and "Uændret" in r.get_json()["message"]
    r = post(admin, "/settings/namespoof/mode", {"mode": "måske"})
    assert not r.get_json()["ok"]
    assert len(audits(nenv, "namespoof_mode")) == 1


def test_add_edit_and_remove_a_name(nenv):
    admin = client_for(nenv, "admin")
    r = post(admin, "/settings/namespoof/save", {"name": "Sofie  Hansen", "allow": "sofie@molt.example\n@shop.example",
                                                 "enabled": "1"})
    assert r.get_json()["ok"], r.get_json()
    e = next(x for x in ns.list_names(nenv.conn) if x["name"] == "Sofie Hansen")
    assert e["allow"] == ["sofie@molt.example", "@shop.example"] and e["enabled"] and e["source"] == "manual"
    assert audits(nenv, "namespoof_name")
    r = post(admin, "/settings/namespoof/save", {"name": "Sofie Hansen", "allow": "gmail.com"})
    assert not r.get_json()["ok"] and "gratis-maildomæne" in r.get_json()["message"]
    r = post(admin, "/settings/namespoof/save", {"id": str(e["id"]), "name": "Sofie Hansen", "allow": ""})
    assert r.get_json()["ok"] and ns.get_name(nenv.conn, e["id"])["enabled"] is False   # switch unchecked
    r = post(admin, "/settings/namespoof/delete", {"id": str(e["id"])})
    assert r.get_json()["ok"] and ns.get_name(nenv.conn, e["id"]) is None and audits(nenv, "namespoof_name_remove")
    r = post(admin, "/settings/namespoof/delete", {"id": str(e["id"])})
    assert not r.get_json()["ok"]


def test_allow_address_from_a_hit(nenv):
    admin = client_for(nenv, "admin")
    e = next(x for x in ns.list_names(nenv.conn) if x["name"] == "Ole Storm")
    r = post(admin, "/settings/namespoof/allow", {"id": str(e["id"]), "address": "ceo.office@outlook.com"})
    assert r.get_json()["ok"] and "c…@outlook.com må nu bruge navnet Ole Storm" in r.get_json()["message"]
    assert "ceo.office@outlook.com" in ns.get_name(nenv.conn, e["id"])["allow"]
    assert [a["detail"] for a in audits(nenv, "namespoof_allow")] == [f"id={e['id']} c…@outlook.com"]
    assert "Tilladt" in _card(admin)


def test_seed_button(nenv):
    c = nenv.conn
    c.execute("INSERT INTO own_identities(account, display_name, addr, n, last_at) "
              "VALUES('molt-sofie', 'Sofie Hansen', 'sofie@molt.example', 7, 1)")
    c.commit()
    admin = client_for(nenv, "admin")
    r = post(admin, "/settings/namespoof/seed", {})
    assert r.get_json()["ok"] and "1 nyt navn" in r.get_json()["message"] and audits(nenv, "namespoof_seed")
    assert "Sofie Hansen" in _card(admin) and "Fra Sendt post" in _card(admin)
    r = post(admin, "/settings/namespoof/seed", {})
    assert r.get_json()["ok"] and "Intet nyt" in r.get_json()["message"]


def test_overview_item_after_a_week_of_default_trial(nenv):
    c = nenv.conn
    c.execute("INSERT OR REPLACE INTO engine_state(key, value, updated_at) VALUES('namespoof_mode', ?, ?)",
              (json.dumps({"mode": "shadow", "at": NOW - 8 * 86400, "by": ""}), NOW))
    c.commit()
    admin = client_for(nenv, "admin")
    html = body(admin.get("/"))
    assert "Beskyttede navne: klar til at slå til?" in html and "Prøv i 8 dage" in html
    for who in ("anna", "bo"):
        assert "Beskyttede navne" not in body(client_for(nenv, who).get("/")), who
    card = _card(admin)
    assert "Prøv har kørt i 8 dage" in card and "Slå til" in card and "Bliv i Prøv" in card
    r = post(admin, "/settings/namespoof/mode", {"mode": "shadow"})          # Bliv i Prøv
    assert r.get_json()["ok"]
    assert "Beskyttede navne: klar til at slå til?" not in body(admin.get("/"))


def test_detail_text_and_admin_button(nenv):
    admin = body(client_for(nenv, "admin").get(detail_url("molt", "ns2@x")))
    assert ("Afsendernavnet er en af jeres egne (Ole Storm), men adressen er ikke hans/hendes rigtige – og "
            "emnet ligner direktørsvindel") in admin
    assert "Tillad adressen for Ole Storm" in admin
    csp_clean(admin, "detail")
    anna = body(client_for(nenv, "anna").get(detail_url("molt", "ns2@x")))
    assert "Tillad adressen" not in anna
    trial = body(client_for(nenv, "admin").get(detail_url("bynet", "ns1@x")))
    assert "Prøv: afsendernavnet er en af jeres egne (Ole Storm)" in trial
    evil = body(client_for(nenv, "admin").get(detail_url("bynet", "ns3@x")))
    assert "<script>alert(1)" not in evil


def test_symbol_texts():
    assert kit.plain_reason("TH_NAME_SPOOF")
    assert "hans/hendes" in kit.explain_symbol("TH_NAME_SPOOF")
    assert kit.explain_symbol_detail({"n": "TH_NAME_SPOOF", "o": ["Ole Storm", "x…@y.dk", "navn"]}) == \
        "Afsendernavnet er en af jeres egne (Ole Storm), men adressen er ikke hans/hendes rigtige"


# ===================================================================== permission matrix

POSTS = [("/settings/namespoof/mode", {"mode": "off"}),
         ("/settings/namespoof/save", {"name": "Evil Name", "allow": ""}),
         ("/settings/namespoof/delete", {"id": "1"}),
         ("/settings/namespoof/allow", {"id": "1", "address": "evil@x.example"}),
         ("/settings/namespoof/seed", {})]


def test_every_new_route_has_the_admin_policy():
    rules = [r for r in dashboard.app.url_map.iter_rules() if r.rule.startswith("/settings/namespoof")]
    assert len(rules) == 5
    for rule in rules:
        assert dashboard.route_policy(rule.endpoint) == dashboard.POLICY_ADMIN, rule.rule


@pytest.mark.parametrize("who", ["anna", "bo", "cille", None])
def test_post_matrix(nenv, who):
    c = client_for(nenv, who)
    before = json.dumps(ns.list_names(nenv.conn)), ns.get_mode(nenv.conn)
    for url, data in POSTS:
        r = post(c, url, data)
        assert r.status_code == (401 if who is None else 403), f"{who} {url}: {r.status_code}"
    assert (json.dumps(ns.list_names(nenv.conn)), ns.get_mode(nenv.conn)) == before


# ===================================================================== 2.7 fix: AI reason for admins only

def test_ai_reason_is_shown_to_admins_only(nenv):
    sym = {"n": "TH_AI_SPAM", "s": 3.0, "o": ["spam", "0.95", "Hemmelig modelbegrundelse", "qwen2.5:7b"]}
    insert_message(nenv.conn, "bynet", "ai1@x", our_action="moved_to_junk", our_score=9.0,
                   current_folder="Spamfilter", sender="X <x@evil.example>", subject="Tilbud", symbols=[sym])
    nenv.conn.commit()
    admin = body(client_for(nenv, "admin").get(detail_url("bynet", "ai1@x")))
    assert "Hemmelig modelbegrundelse" in admin
    anna = body(client_for(nenv, "anna").get(detail_url("bynet", "ai1@x")))
    assert "Hemmelig modelbegrundelse" not in anna
    assert "Den lokale AI-vurdering mente, at mailen var spam" in anna
