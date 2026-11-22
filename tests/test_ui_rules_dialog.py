"""2.3 rules dialog: one Bloker/Tillad flow everywhere.

Every Bloker/Tillad button posts `choose=1`; the server answers with the
dialog "Kun denne adresse / Hele domænet" (JSON for app.js, a small confirm
page without JavaScript). The dialog and the Regler form post
`scope=address|domain` and the server builds the pattern itself, refusing
whole freemail domains, the owner's own domains / webshop / mailbox
addresses and 'Altid igennem' senders, and showing an existing rule with a
one-click switch instead of creating a duplicate.
"""

from __future__ import annotations

import json
import re
import time

import pytest

from fakes_ui import (DEFAULT_ACCOUNTS, FakeAccount, TEST_PASSWORD, csrf_of, insert_message, login, make_env,
                      post, set_status)

import dashboard  # noqa: E402
import ui_kit as kit  # noqa: E402
import ui_mail  # noqa: E402

PW = TEST_PASSWORD
INLINE = [
    (re.compile(r'\sstyle\s*='), "inline style attribute"),
    (re.compile(r"<style\b"), "<style> block"),
    (re.compile(r"<script(?![^>]*\bsrc=)[^>]*>"), "inline script"),
    (re.compile(r'\son[a-z]+\s*=\s*"', re.I), "inline event handler"),
    (re.compile(r'(src|href)="(https?:)?//'), "external resource"),
]
XSS_NAME = "<img src=x onerror=alert(1)><script>alert(2)</script>"
XSS_ADDR = "a'b&c@evil.example"


def key(account, mid):
    return f"{account}:{kit.token_for(mid)}"


@pytest.fixture
def env(tmp_path, monkeypatch):
    accounts = [FakeAccount(**a.__dict__) for a in DEFAULT_ACCOUNTS]
    accounts[0].owner_platform_domains = ["platform.example"]
    accounts[0].webshop_domains = ["minbutik.example", "platform.example"]
    e = make_env(tmp_path, monkeypatch, accounts=accounts,
                 users=[("admin", PW, "admin"), ("sofie", PW, "sofie"), ("inge", PW, "bynet"),
                        ("bo", PW, "bynet"), ("lise", PW, "bynet")])
    with e.app.test_request_context("/"):
        dashboard.set_user_perms("inge", ["release", "rules", "see_messages"], "test")
        dashboard.set_user_perms("bo", ["release", "see_messages"], "test")      # no 'rules'
        dashboard.set_user_perms("lise", ["rules", "see_messages"], "test")      # no 'release'
    c = e.conn
    set_status(c, "bynet", "idle", junk_exists=1)
    set_status(c, "molt", "idle", junk_exists=1)
    set_status(c, "sofie", "paused")
    junk = {"our_action": "moved_to_junk", "our_score": 14.0, "current_folder": "Spamfilter"}
    insert_message(c, "bynet", "<spam1@x>", sender="Tilbud <tilbud@firma.dk>", subject="Kæmpe udsalg", **junk)
    insert_message(c, "bynet", "<gm@x>", sender="Ukendt <someone@gmail.com>", subject="Hej", **junk)
    insert_message(c, "bynet", "<fm@x>", sender="Spam <x@smaa-tjeneste.example>", subject="Freemail-symbol",
                   symbols=[{"n": "FREEMAIL_FROM", "s": 0.0}], **junk)
    insert_message(c, "bynet", "<xss@x>", sender=f'"{XSS_NAME}" <{XSS_ADDR}>', subject="XSS", **junk)
    insert_message(c, "bynet", "<ham1@x>", sender="Mor <mor@familie.dk>", subject="Søndag?")
    insert_message(c, "bynet", "<virus@x>", sender="Bad <bad@virus.example>", subject="Faktura",
                   threat="phish", **junk)
    insert_message(c, "molt", "<m1@x>", sender="Hemmelig <skjult@molt-afsender.example>", subject="MOLT", **junk)
    insert_message(c, "sofie", "<t1@x>", sender="spam@sofie.example", subject="Sofies", **junk)
    c.commit()
    return e


def client(env, name="admin"):
    cl = env.app.test_client()
    assert login(cl, name, PW).status_code == 302, name
    return cl


@pytest.fixture
def admin(env):
    return client(env)


def rules(env):
    return {tuple(r) for r in env.conn.execute("SELECT account, pattern, kind FROM sender_rules")}


def dialog(cl, data):
    r = post(cl, "/rules/add", {"choose": "1", "view": "spam", "next": "/spam", **data})
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    d = r.get_json()
    assert d["ok"] and d["dialog"]["html"]
    return d["dialog"]


def radio(html, scope):
    m = re.search(r'<input type="radio" class="rd-radio" name="scope" value="' + scope + r'"[^>]*>', html)
    assert m, scope
    return m.group(0)


def choice(html, scope):
    """The whole <label> card of one choice."""
    i = html.index(radio(html, scope))
    start = html.rindex("<label", 0, i)
    return html[start:html.index("</label>", i)]


def csp_clean(html, where):
    for rx, what in INLINE:
        m = rx.search(html)
        assert m is None, f"{what} on {where}: {html[max(0, m.start() - 60):m.end() + 60]}"


# --------------------------------------------------------------------- the dialog itself


def test_block_dialog_shows_both_choices_with_plain_descriptions(env, admin):
    d = dialog(admin, {"kind": "block", "pattern": "tilbud@firma.dk", "account": "bynet",
                       "item": key("bynet", "<spam1@x>")})
    html = d["html"]
    assert d["title"] == "Bloker afsender" and 'id="sf-rule-title"' in html
    addr, dom = choice(html, "address"), choice(html, "domain")
    assert "Kun denne adresse" in addr and "tilbud@firma.dk" in addr
    assert ("Kun mails fra præcis denne afsender flyttes til spam. Andre fra firma.dk kommer stadig igennem."
            in addr)
    assert "Hele domænet" in dom and ">firma.dk<" in dom
    assert "Alle mails fra firma.dk og underdomæner (fx nyhed.firma.dk) flyttes til spam." in dom
    # The safe choice is pre-selected; both are enabled.
    assert "checked" in radio(html, "address") and "disabled" not in radio(html, "address")
    assert "checked" not in radio(html, "domain") and "disabled" not in radio(html, "domain")
    assert 'action="/rules/add"' in html and 'name="csrf"' in html and "data-ajax" in html
    assert 'name="pattern" value="tilbud@firma.dk"' in html and 'name="kind" value="block"' in html
    assert ">Bloker<" in html and ">Annullér<" in html and "Fra</span> <b>Tilbud</b>" in html
    assert rules(env) == set()  # asking changes nothing
    csp_clean(html, "block dialog")


def test_allow_dialog_has_the_mirrored_texts(env, admin):
    html = dialog(admin, {"kind": "allow", "pattern": "tilbud@firma.dk", "account": "bynet"})["html"]
    # A normal Tillad is not 'Altid igennem': the texts never use that phrase.
    assert ("Mails fra præcis denne afsender flyttes ikke til spam. Andre fra firma.dk vurderes som normalt."
            in choice(html, "address"))
    assert ("Alle mails fra firma.dk og underdomæner (fx nyhed.firma.dk) flyttes ikke til spam."
            in choice(html, "domain"))
    assert "kommer altid igennem" not in html
    assert ">Tillad<" in html and "Hvad vil du tillade?" in html and "forfalsket" in html


def test_choose_address_or_domain_creates_the_right_rule(env, admin):
    k = key("bynet", "<spam1@x>")
    data = post(admin, "/rules/add", {"kind": "block", "pattern": "tilbud@firma.dk", "account": "bynet",
                                      "scope": "address", "view": "spam", "next": "/spam", "sync": [k]}).get_json()
    assert data["ok"] and data["message"] == "tilbud@firma.dk er nu blokeret på bynet"
    assert "Blokeret" in data["rows"][k] and data["undo"]["url"].endswith("/delete")
    data = post(admin, "/rules/add", {"kind": "block", "pattern": "tilbud@firma.dk", "account": "bynet",
                                      "scope": "domain", "view": "spam", "next": "/spam"}).get_json()
    assert data["ok"] and data["message"] == "Hele domænet firma.dk er nu blokeret på bynet"
    assert rules(env) == {("bynet", "tilbud@firma.dk", "block"), ("bynet", "@firma.dk", "block")}
    audit = [a for a in env.audit() if a["action"] == "rule_add"]
    assert [a["detail"] for a in audit] == ["block tilbud@firma.dk", "block @firma.dk"]


def test_dialog_echoes_sync_rows_so_the_list_updates(env, admin):
    k1 = key("bynet", "<spam1@x>")
    html = post(admin, "/rules/add", {"kind": "block", "pattern": "tilbud@firma.dk", "account": "bynet",
                                      "choose": "1", "view": "spam", "next": "/spam",
                                      "sync": [k1]}).get_json()["dialog"]["html"]
    assert f'name="sync" value="{k1}"' in html


def test_bad_input_and_bad_scope_are_refused_in_danish(env, admin):
    r = post(admin, "/rules/add", {"kind": "block", "pattern": "ikke en adresse", "account": "bynet", "choose": "1"})
    assert r.status_code == 400 and "Ugyldig adresse eller domæne" in r.get_json()["message"]
    r = post(admin, "/rules/add", {"kind": "block", "pattern": "firma.dk", "account": "bynet", "scope": "address"})
    assert r.status_code == 400 and "Du har skrevet et domæne" in r.get_json()["message"]
    r = post(admin, "/rules/add", {"kind": "block", "pattern": "a@firma.dk", "account": "bynet", "scope": "alt"})
    assert r.status_code == 400 and "Kun denne adresse eller Hele domænet" in r.get_json()["message"]
    assert rules(env) == set()
    # A bare domain pasted in the Regler form + Hele domænet works ("@" is not needed).
    data = post(admin, "/rules/add", {"kind": "block", "pattern": "Firma.DK", "account": "bynet",
                                      "scope": "domain"}).get_json()
    assert data["ok"] and ("bynet", "@firma.dk", "block") in rules(env)


# --------------------------------------------------------------------- safety


@pytest.mark.parametrize("addr", ["someone@gmail.com", "a@hotmail.co.uk", "b@outlook.dk", "c@live.com",
                                  "d@yahoo.com", "e@icloud.com", "f@me.com", "g@mail.dk", "h@jubii.dk"])
def test_whole_freemail_domain_is_disabled(env, admin, addr):
    for kind in ("block", "allow"):
        html = dialog(admin, {"kind": kind, "pattern": addr, "account": "bynet"})["html"]
        dom = choice(html, "domain")
        assert "disabled" in radio(html, "domain") and "is-disabled" in dom
        assert "stor mailtjeneste" in dom and "vælg kun adressen" in dom
        assert "checked" in radio(html, "address") and "disabled" not in radio(html, "address")
        r = post(admin, "/rules/add", {"kind": kind, "pattern": addr, "account": "bynet", "scope": "domain"})
        assert r.status_code == 400 and "stor mailtjeneste" in r.get_json()["message"]
    assert rules(env) == set()
    assert post(admin, "/rules/add", {"kind": "block", "pattern": addr, "account": "bynet",
                                      "scope": "address"}).get_json()["ok"]


def test_freemail_detection_is_not_too_greedy():
    assert ui_mail._is_freemail("hotmail.com") and ui_mail._is_freemail("yahoo.com.au")
    assert ui_mail._is_freemail("@GMAIL.com.") and ui_mail._is_freemail("gmx.at")
    assert not ui_mail._is_freemail("live.nation.example") and not ui_mail._is_freemail("firma.dk")
    assert not ui_mail._is_freemail("outlook-partner.example")


def test_freemail_symbol_of_the_mail_also_disables_the_domain(env, admin):
    html = dialog(admin, {"kind": "block", "pattern": "x@smaa-tjeneste.example", "account": "bynet",
                          "item": key("bynet", "<fm@x>")})["html"]
    assert "disabled" in radio(html, "domain")
    # A forged item from another mailbox is ignored (no leak, no hint).
    html = dialog(admin, {"kind": "block", "pattern": "x@smaa-tjeneste.example", "account": "molt",
                          "item": key("bynet", "<fm@x>")})["html"]
    assert "disabled" not in radio(html, "domain")


@pytest.mark.parametrize("pattern,scope,why", [
    ("ole@bynet.example", "address", "en af jeres egne postkasser"),
    ("ole@bynet.example", "domain", "jeres eget domæne"),
    ("ny@molt.example", "domain", "jeres eget domæne"),
    ("x@nyhed.bynet.example", "domain", "jeres eget domæne"),
    ("ordre@minbutik.example", "address", "webshop eller platform"),
    ("ordre@minbutik.example", "domain", "webshop eller platform"),
    ("info@mail.platform.example", "domain", "webshop eller platform"),
])
def test_blocking_own_domains_is_refused(env, admin, pattern, scope, why):
    r = post(admin, "/rules/add", {"kind": "block", "pattern": pattern, "account": "bynet", "scope": scope})
    data = r.get_json()
    assert r.status_code == 400 and data["ok"] is False and why in data["message"]
    assert rules(env) == set()
    html = dialog(admin, {"kind": "block", "pattern": pattern, "account": "bynet"})["html"]
    assert "disabled" in radio(html, scope)
    # The reason is on the card - or, when both cards share it, shown once
    # (on the first) and referenced by aria-describedby.
    ref = re.search(r'aria-describedby="([^"]+)"', radio(html, scope)).group(1)
    assert why in html[html.index(f'id="{ref}"'):][:400]
    assert html.count(why) == 1 or why in choice(html, scope)


def test_own_mailbox_dialog_has_nothing_to_choose(env, admin):
    html = dialog(admin, {"kind": "block", "pattern": "ordre@minbutik.example", "account": "bynet"})["html"]
    assert "data-blocked" in html and "rd-submit" not in html and ">Annullér<" in html
    # No dead end: the hint says what to do instead (both cards share one reason, shown once).
    assert "Mails fra jeres webshop skal altid igennem" in html and "Lær som spam" in html
    assert "ret reglen under Regler" not in html
    assert html.count("hører til jeres egen webshop") == 1
    # Allowing your own shop is fine (nothing is refused).
    html = dialog(admin, {"kind": "allow", "pattern": "ordre@minbutik.example", "account": "bynet"})["html"]
    assert "data-blocked" not in html and "disabled" not in radio(html, "domain")


def test_other_addresses_on_the_own_domain_can_still_be_blocked(env, admin):
    data = post(admin, "/rules/add", {"kind": "block", "pattern": "falsk@bynet.example", "account": "bynet",
                                      "scope": "address"}).get_json()
    assert data["ok"] and ("bynet", "falsk@bynet.example", "block") in rules(env)


def test_altid_igennem_sender_cannot_be_blocked_from_the_dialog(env, admin):
    env.engine.add_sender_rule(env.conn, "*", "@trygshop.example", "allow", None, "admin", force=True)
    env.conn.commit()
    html = dialog(admin, {"kind": "block", "pattern": "kunde@trygshop.example", "account": "bynet"})["html"]
    assert "disabled" in radio(html, "address") and "disabled" in radio(html, "domain")
    assert "Altid igennem" in html
    r = post(admin, "/rules/add", {"kind": "block", "pattern": "kunde@trygshop.example", "account": "bynet",
                                   "scope": "address"})
    assert r.status_code == 400 and "Altid igennem" in r.get_json()["message"]
    inge = client(env, "inge")
    r = post(inge, "/rules/add", {"kind": "block", "pattern": "kunde@trygshop.example", "account": "bynet",
                                   "scope": "domain"})
    assert r.status_code == 403 and "Altid igennem" in r.get_json()["message"]
    assert rules(env) == {("*", "@trygshop.example", "allow")}


# --------------------------------------------------------------------- existing rules


def test_existing_rule_is_shown_with_a_one_click_switch(env, admin):
    rid = env.engine.add_sender_rule(env.conn, "bynet", "tilbud@firma.dk", "allow", "Kunde", "admin")
    env.conn.commit()
    k = key("bynet", "<spam1@x>")
    html = post(admin, "/rules/add", {"kind": "block", "pattern": "tilbud@firma.dk", "account": "bynet",
                                      "choose": "1", "view": "spam", "next": "/spam",
                                      "sync": [k]}).get_json()["dialog"]["html"]
    assert "Der findes allerede en regel" in html and "tilbud@firma.dk er tilladt for bynet" in html
    m = re.search(r'<form method="post" action="/rules/%d/kind"[^>]*>(.*?)</form>' % rid, html, re.S)
    assert m and 'name="kind" value="block"' in m.group(1) and 'name="guard" value="1"' in m.group(1)
    assert "Skift til Bloker" in m.group(1) and f'name="sync" value="{k}"' in m.group(1)
    data = post(admin, f"/rules/{rid}/kind", {"kind": "block", "guard": "1", "view": "spam", "next": "/spam",
                                              "sync": [k]}).get_json()
    assert data["ok"] and "Blokeret" in data["rows"][k]
    assert rules(env) == {("bynet", "tilbud@firma.dk", "block")}  # switched, no duplicate
    row = env.conn.execute("SELECT note FROM sender_rules WHERE id=?", (rid,)).fetchone()
    assert row[0] == "Kunde"


def test_same_rule_is_not_offered_twice(env, admin):
    env.engine.add_sender_rule(env.conn, "bynet", "tilbud@firma.dk", "block", None, "admin")
    env.engine.add_sender_rule(env.conn, "*", "@firma.dk", "block", None, "admin")
    env.conn.commit()
    html = dialog(admin, {"kind": "block", "pattern": "tilbud@firma.dk", "account": "bynet"})["html"]
    assert "disabled" in radio(html, "address") and "Findes allerede" in choice(html, "address")
    assert "disabled" in radio(html, "domain") and "alle postkasser" in choice(html, "domain")
    assert "data-blocked" in html and "Skift til" not in html


def test_global_rule_switch_is_admin_only(env, admin):
    env.engine.add_sender_rule(env.conn, "*", "@firma.dk", "allow", None, "admin")
    env.conn.commit()
    inge = client(env, "inge")
    html = dialog(inge, {"kind": "block", "pattern": "tilbud@firma.dk", "account": "bynet"})["html"]
    assert "Der findes allerede en regel" in html and "Kun en administrator kan ændre den" in html
    assert "/kind" not in html
    assert "disabled" not in radio(html, "domain")  # an own-mailbox rule beats the global one
    html = dialog(admin, {"kind": "block", "pattern": "tilbud@firma.dk", "account": "bynet"})["html"]
    assert "Skift til Bloker" in html


def test_guarded_switch_refuses_own_domain(env, admin):
    rid = env.engine.add_sender_rule(env.conn, "bynet", "@bynet.example", "allow", None, "admin")
    env.conn.commit()
    html = dialog(admin, {"kind": "block", "pattern": "x@bynet.example", "account": "bynet"})["html"]
    assert "Der findes allerede en regel" in html and f"/rules/{rid}/kind" not in html
    r = post(admin, f"/rules/{rid}/kind", {"kind": "block", "guard": "1"})
    assert r.status_code == 400 and "jeres eget domæne" in r.get_json()["message"]
    assert rules(env) == {("bynet", "@bynet.example", "allow")}


# --------------------------------------------------------------------- Frigiv og tillad (spam lists, Tjek disse)


def test_release_allow_dialog_then_domain(env, admin):
    k = key("bynet", "<spam1@x>")
    r = post(admin, "/mail/action", {"action": "release_allow", "items": [k], "choose": "1", "view": "spam",
                                     "next": "/spam", "nonce": "n1"})
    d = r.get_json()
    assert r.status_code == 200 and d["dialog"]["title"] == "Frigiv og tillad afsender"
    html = d["dialog"]["html"]
    assert 'action="/mail/action"' in html and 'name="action" value="release_allow"' in html
    assert f'name="items" value="{k}"' in html and 'name="nonce"' in html and ">Frigiv og tillad<" in html
    assert "Mailen flyttes tilbage til indbakken" in html
    assert "flyttes ikke til spam" in choice(html, "domain")
    assert env.services.calls == [] and rules(env) == set()  # nothing happened yet
    data = post(admin, "/mail/action", {"action": "release_allow", "items": [k], "scope": "domain",
                                        "view": "spam", "next": "/spam", "nonce": "n2"}).get_json()
    assert data["ok"] and data["message"] == "1 besked frigivet – afsenderen er tilladt"
    assert rules(env) == {("bynet", "@firma.dk", "allow")}
    assert data["undo"]["fields"]["restore_rule"]


def test_release_allow_refuses_freemail_domain_but_releases(env, admin):
    k = key("bynet", "<gm@x>")
    data = post(admin, "/mail/action", {"action": "release_allow", "items": [k], "scope": "domain",
                                        "view": "spam", "nonce": "n3"}).get_json()
    assert data["ok"] and "ikke tilladt" in data["results"][0]["text"] and rules(env) == set()


def test_release_allow_dialog_refused_for_threats_and_foreign_mail(env, admin):
    r = post(admin, "/mail/action", {"action": "release_allow", "items": [key("bynet", "<virus@x>")],
                                     "choose": "1", "view": "spam"})
    assert r.status_code == 403 and "farlig" in r.get_json()["message"]
    inge = client(env, "inge")
    r = post(inge, "/mail/action", {"action": "release_allow", "items": [key("molt", "<m1@x>")],
                                     "choose": "1", "view": "spam"})
    assert r.status_code == 404 and "MOLT" not in r.get_data(as_text=True)
    assert "skjult@molt-afsender.example" not in r.get_data(as_text=True)


def test_review_rows_offer_tillad_with_the_dialog(env, admin):
    insert_message(env.conn, "bynet", "<near@x>", our_action="moved_to_junk", our_score=8.4,
                   current_folder="Spamfilter", sender="Lars <lars@nielsen-vvs.example>", subject="Tilbud på fyr")
    env.conn.commit()
    html = admin.get("/spam").get_data(as_text=True)
    if 'id="tjek"' not in html:
        pytest.skip("no Tjek disse items in this fixture")
    section = html[html.index('id="tjek"'):]
    section = section[:section.index("</section>")]
    row = section[section.index(f'data-row="review:{key("bynet", "<near@x>")}"'):]
    row = row[row.index('class="review-actions"'):]
    row = row[:row.index("</div></li>")]
    assert 'value="release_allow"' in row and 'name="choose" value="1"' in row and "Tillad afsender" in row


# --------------------------------------------------------------------- buttons everywhere use the dialog


def test_rows_and_detail_buttons_post_choose(env, admin):
    html = admin.get("/spam").get_data(as_text=True)
    row = html[html.index(f'data-row="{key("bynet", "<spam1@x>")}"'):]
    row = row[:row.index("</li>")]
    assert row.count('name="choose" value="1"') == 2  # Tillad (release_allow) + Bloker
    assert 'aria-haspopup="dialog"' in row and "data-confirm" not in row.split("Bloker afsender")[0][-400:]
    det = admin.get(f"/messages/bynet/{kit.token_for('<spam1@x>')}").get_data(as_text=True)
    sender = det[det.index("<h3>Afsender</h3>"):]
    sender = sender[:sender.index("</section>")]
    assert sender.count('name="choose" value="1"') == 2
    assert f'name="item" value="{key("bynet", "<spam1@x>")}"' in sender
    assert "Tillad domæne" not in sender and "Bloker domæne" not in sender
    # A dangerous mail: Bloker only.
    det = admin.get(f"/messages/bynet/{kit.token_for('<virus@x>')}").get_data(as_text=True)
    sender = det[det.index("<h3>Afsender</h3>"):]
    sender = sender[:sender.index("</section>")]
    assert "Bloker afsender" in sender and "Tillad afsender" not in sender


# --------------------------------------------------------------------- no JavaScript


def test_without_js_the_dialog_is_a_small_confirm_page(env, admin):
    form = {"kind": "block", "pattern": "tilbud@firma.dk", "account": "bynet", "choose": "1", "view": "spam",
            "next": "/spam?source=filter", "item": key("bynet", "<spam1@x>"), "csrf": csrf_of(admin)}
    r = admin.post("/rules/add", data=form)
    html = r.get_data(as_text=True)
    assert r.status_code == 200 and "<title>" in html and "Bloker afsender" in html
    assert "Kun denne adresse" in html and "Hele domænet" in html and 'class="rd-page"' in html
    m = re.search(r'<form method="post" action="/rules/add" class="rd-form"([^>]*)>', html)
    assert m and "data-ajax" not in m.group(1)
    assert 'href="/spam?source=filter" data-rd-cancel' in html
    csp_clean(html, "no-JS dialog page")
    assert rules(env) == set()
    # Submitting the page: redirect back with a flash.
    r = admin.post("/rules/add", data={"kind": "block", "pattern": "tilbud@firma.dk", "account": "bynet",
                                       "scope": "domain", "view": "spam", "next": "/spam?source=filter",
                                       "csrf": csrf_of(admin)})
    assert r.status_code == 302 and r.headers["Location"] == "/spam?source=filter"
    assert "Hele domænet firma.dk er nu blokeret" in admin.get("/spam?source=filter").get_data(as_text=True)
    # An unsafe next is ignored.
    r = admin.post("/rules/add", data={**form, "next": "//evil.example"})
    assert 'href="//evil.example"' not in r.get_data(as_text=True)


def test_without_js_release_allow_page(env, admin):
    k = key("bynet", "<spam1@x>")
    r = admin.post("/mail/action", data={"action": "release_allow", "items": [k], "choose": "1", "view": "spam",
                                         "next": "/spam", "csrf": csrf_of(admin)})
    html = r.get_data(as_text=True)
    assert r.status_code == 200 and "Frigiv og tillad afsender" in html and 'value="release_allow"' in html
    assert env.services.calls == []


def test_without_js_existing_switch_is_a_plain_form(env, admin):
    rid = env.engine.add_sender_rule(env.conn, "bynet", "tilbud@firma.dk", "allow", None, "admin")
    env.conn.commit()
    r = admin.post("/rules/add", data={"kind": "block", "pattern": "tilbud@firma.dk", "account": "bynet",
                                       "choose": "1", "next": "/spam", "csrf": csrf_of(admin)})
    m = re.search(r'<form method="post" action="/rules/%d/kind"([^>]*)>' % rid, r.get_data(as_text=True))
    assert m and "data-ajax" not in m.group(1)


# --------------------------------------------------------------------- CSRF + permissions


def test_csrf_is_required(env, admin):
    for url, data in (("/rules/add", {"kind": "block", "pattern": "a@firma.dk", "account": "bynet", "choose": "1"}),
                      ("/rules/add", {"kind": "block", "pattern": "a@firma.dk", "account": "bynet", "scope": "domain"}),
                      ("/mail/action", {"action": "release_allow", "items": [key("bynet", "<spam1@x>")],
                                        "choose": "1"})):
        r = admin.post(url, data=data, headers={"Accept": "application/json", "X-Requested-With": "fetch"})
        assert r.status_code == 400, url
    assert rules(env) == set() and env.services.calls == []


def test_permission_matrix(env):
    anna = key("bynet", "<spam1@x>")
    block = {"kind": "block", "pattern": "tilbud@firma.dk", "choose": "1"}
    ra = {"action": "release_allow", "items": [anna], "choose": "1"}
    cases = [
        # (user, url, data, expected status)
        ("admin", "/rules/add", {**block, "account": "bynet"}, 200),
        ("admin", "/rules/add", {**block, "account": "*"}, 200),
        ("admin", "/mail/action", ra, 200),
        ("inge", "/rules/add", {**block, "account": "bynet"}, 200),
        ("inge", "/rules/add", {**block, "account": "molt"}, 404),
        ("inge", "/rules/add", {**block, "account": "*"}, 403),
        ("inge", "/rules/add", {**block, "account": "bynet", "kind": "allow", "force": "1"}, 403),
        ("inge", "/mail/action", ra, 200),
        ("inge", "/mail/action", {**ra, "items": [key("sofie", "<t1@x>")]}, 404),
        ("bo", "/rules/add", {**block, "account": "bynet"}, 403),          # no 'rules'
        ("bo", "/mail/action", ra, 403),
        ("lise", "/rules/add", {**block, "account": "bynet"}, 200),        # rules without release
        ("lise", "/mail/action", ra, 403),
        ("sofie", "/rules/add", {**block, "account": "bynet"}, 404),
        ("sofie", "/rules/add", {**block, "account": "sofie", "pattern": "spam@sofie.example"}, 200),
    ]
    clients = {}
    for user, url, data, status in cases:
        cl = clients.setdefault(user, client(env, user))
        r = post(cl, url, data)
        assert r.status_code == status, (user, url, data, r.status_code, r.get_data(as_text=True)[:200])
        if status != 200:
            assert "dialog" not in (r.get_json() or {}), (user, url)
    # Same for the scoped submit.
    inge = clients["inge"]
    assert post(inge, "/rules/add", {"kind": "block", "pattern": "x@firma.dk", "account": "molt",
                                      "scope": "domain"}).status_code == 404
    assert post(inge, "/rules/add", {"kind": "block", "pattern": "x@firma.dk", "account": "*",
                                      "scope": "domain"}).status_code == 403
    assert post(inge, "/rules/add", {"kind": "allow", "pattern": "x@firma.dk", "account": "bynet",
                                      "scope": "domain", "force": "1"}).status_code == 403
    assert rules(env) == set() and env.services.calls == []


def test_no_new_routes_and_policies_unchanged(env):
    eps = {r.endpoint for r in env.app.url_map.iter_rules()}
    assert not any("dialog" in ep for ep in eps)
    for ep, policy in (("rules_add", "rules"), ("rules_preview", "rules"), ("rules_kind", "rules"),
                       ("mail_action", "release"), ("rules_page", "rules")):
        assert dashboard.route_policy(ep) == policy, ep


def test_bruger_buttons_follow_permissions(env):
    html = client(env, "bo").get("/spam").get_data(as_text=True)
    assert 'name="choose"' not in html  # no 'rules' permission: no Tillad/Bloker
    html = client(env, "inge").get("/spam").get_data(as_text=True)
    assert 'name="choose" value="1"' in html and "skjult@molt-afsender.example" not in html


# --------------------------------------------------------------------- XSS


def test_attacker_controlled_sender_is_escaped(env, admin):
    k = key("bynet", "<xss@x>")
    pattern = ui_mail.ui.engine.normalize_rule_pattern(XSS_ADDR)
    for data in ({"kind": "block", "pattern": pattern, "account": "bynet", "item": k},
                 {"kind": "allow", "pattern": pattern, "account": "bynet", "item": k}):
        html = dialog(admin, data)["html"]
        assert "<img" not in html and "<script" not in html and "&lt;img src=x onerror=alert(1)&gt;" in html
        assert "a&#39;b&amp;c@evil.example" in html and "a'b&c" not in html
        csp_clean(html, "xss dialog")
    r = post(admin, "/mail/action", {"action": "release_allow", "items": [k], "choose": "1", "view": "spam"})
    html = r.get_json()["dialog"]["html"]
    assert "<img" not in html and "<script" not in html and "&lt;img" in html
    page = admin.post("/rules/add", data={"kind": "block", "pattern": pattern, "account": "bynet", "choose": "1",
                                          "item": k, "next": "/spam", "csrf": csrf_of(admin)}).get_data(as_text=True)
    assert "<img src=x" not in page and "<script>alert" not in page
    csp_clean(page, "xss page")
    # A pattern typed into the Regler form never reaches HTML unescaped either.
    p = admin.get("/rules/preview?" + "form=1&kind=block&account=bynet&pattern="
                  + "%22%3E%3Cimg%20src%3Dx%3E@x.example").get_json()
    assert p["tone"] == "bad" and "choices_html" not in p


# --------------------------------------------------------------------- Regler: paste an address


def test_rules_page_form_has_the_two_choices(env, admin):
    html = admin.get("/rules").get_data(as_text=True)
    form = html[html.index('class="rule-add-form"'):]
    form = form[:form.index("</form>")]
    assert 'name="scope" value="address"' in form and 'name="scope" value="domain"' in form
    assert "Kun denne adresse" in form and "Hele domænet" in form
    assert 'data-rule-choices="rule-choices"' in form and 'id="rule-existing"' in html
    assert "Indsæt bare hele afsenderens adresse" in form
    csp_clean(html, "/rules")


def test_rules_preview_returns_the_choices_for_a_pasted_address(env, admin):
    p = admin.get("/rules/preview?form=1&kind=block&account=bynet&pattern=tilbud%40firma.dk").get_json()
    assert p["tone"] == "ok" and p["scope"] == "address" and p["blocked"] is False
    assert "Kun denne adresse: <b" in p["choices_html"] and "tilbud@firma.dk" in p["choices_html"]
    assert "Andre fra firma.dk kommer stadig igennem" in p["choices_html"]
    assert p["existing_html"] == ""
    p = admin.get("/rules/preview?form=1&kind=block&account=bynet&pattern=tilbud%40firma.dk&scope=domain").get_json()
    assert p["scope"] == "domain" and "@firma.dk" in p["text"] and "underdomæner" in p["text"]
    # A bare domain: only "Hele domænet" can be chosen.
    p = admin.get("/rules/preview?form=1&kind=block&account=bynet&pattern=firma.dk&scope=address").get_json()
    assert p["scope"] == "domain" and re.search(r'value="address"[^>]*disabled', p["choices_html"])
    # Freemail: only the address.
    p = admin.get("/rules/preview?form=1&kind=allow&account=bynet&pattern=a%40gmail.com&scope=domain").get_json()
    assert p["scope"] == "address" and re.search(r'value="domain"[^>]*disabled', p["choices_html"])
    # Own domain typed as a domain: nothing to choose.
    p = admin.get("/rules/preview?form=1&kind=block&account=bynet&pattern=bynet.example").get_json()
    assert p["blocked"] is True and p["tone"] == "warn" and "data-blocked" in p["choices_html"]
    # Existing rule: shown with the switch.
    rid = env.engine.add_sender_rule(env.conn, "bynet", "@firma.dk", "allow", None, "admin")
    env.conn.commit()
    p = admin.get("/rules/preview?form=1&kind=block&account=bynet&pattern=x%40firma.dk&next=/rules%3Fkind%3Dallow").get_json()
    assert f'action="/rules/{rid}/kind"' in p["existing_html"] and "Skift til Bloker" in p["existing_html"]
    assert 'name="next" value="/rules?kind=allow"' in p["existing_html"]
    # Someone else's mailbox: 404 (unchanged).
    assert client(env, "inge").get("/rules/preview?form=1&kind=block&account=molt&pattern=a%40b.dk").status_code == 404


def test_rules_form_submit_with_scope(env, admin):
    data = post(admin, "/rules/add", {"kind": "block", "pattern": "  Tilbud@Firma.dk ", "account": "*",
                                      "scope": "domain", "note": "Udsalg", "view": "rules"}).get_json()
    assert data["ok"] and data["message"] == "Hele domænet firma.dk er nu blokeret"
    row = env.conn.execute("SELECT account, pattern, kind, note FROM sender_rules").fetchone()
    assert tuple(row) == ("*", "@firma.dk", "block", "Udsalg")
    data = post(admin, "/rules/add", {"kind": "allow", "pattern": "kunde@shop.example", "account": "bynet",
                                      "scope": "address", "force": "1"}).get_json()
    assert data["ok"] and "Altid igennem" in data["message"]
    assert env.conn.execute("SELECT force FROM sender_rules WHERE pattern='kunde@shop.example'").fetchone()[0] == 1


def test_legacy_single_pattern_api_is_unchanged(env, admin):
    """Fortryd / import / old cached pages post a pattern without scope or
    choose: no dialog and no dialog-only refusals (freemail, Altid igennem
    overlap) - but the owner's shop and own addresses/domains are protected
    on every path (2.3 follow-up)."""
    data = post(admin, "/rules/add", {"kind": "block", "pattern": "x@firma.example", "account": "bynet"}).get_json()
    assert data["ok"] and "dialog" not in data
    data = post(admin, "/rules/add", {"kind": "block", "pattern": "@gmail.com", "account": "bynet"}).get_json()
    assert data["ok"] and "dialog" not in data
    r = post(admin, "/rules/add", {"kind": "block", "pattern": "x@minbutik.example", "account": "bynet"})
    assert r.status_code == 400 and r.get_json()["code"] == "own_shop"
    data = post(admin, "/rules/add", {"kind": "allow", "pattern": "a@b.example", "account": "bynet",
                                      "choose": "1", "undo": "1"}).get_json()
    assert data["ok"] and "dialog" not in data


# --------------------------------------------------------------------- follow-up (2.3 round 2)


@pytest.mark.parametrize("pattern,scope", [
    ("ordre@vexar.example", "address"), ("x@vexar.example", "domain"), ("info@mail.vexar.example", "domain"),
    ("salg@gravisk.example", "domain"), ("salg@pinsikbing.example", "address"),
])
def test_owner_platform_is_protected_even_without_config_lists(env, admin, pattern, scope):
    """molt has empty owner_platform_domains / webshop_domains: vexar.example
    and the default webshops are still never blocked from the UI."""
    r = post(admin, "/rules/add", {"kind": "block", "pattern": pattern, "account": "molt", "scope": scope})
    assert r.status_code == 400 and "webshop eller platform" in r.get_json()["message"]
    assert rules(env) == set()
    html = dialog(admin, {"kind": "block", "pattern": pattern, "account": "molt"})["html"]
    assert "disabled" in radio(html, scope)
    # Allowing them is fine.
    assert post(admin, "/rules/add", {"kind": "allow", "pattern": pattern, "account": "molt",
                                      "scope": scope}).get_json()["ok"]


def test_parent_domain_rule_is_shown_with_a_switch(env, admin):
    rid = env.engine.add_sender_rule(env.conn, "bynet", "@firma.dk", "allow", None, "admin")
    env.conn.commit()
    html = dialog(admin, {"kind": "block", "pattern": "nyhed@kampagne.firma.dk", "account": "bynet"})["html"]
    assert "Der findes allerede en regel" in html and "hele domænet firma.dk er tilladt for bynet" in html
    assert f'action="/rules/{rid}/kind"' in html and "Skift til Bloker" in html
    # The narrower choices are still offered (they would beat the parent rule).
    assert "disabled" not in radio(html, "address") and "disabled" not in radio(html, "domain")
    # A sibling domain is not a parent.
    html = dialog(admin, {"kind": "block", "pattern": "a@andetfirma.dk", "account": "bynet"})["html"]
    assert "Der findes allerede en regel" not in html


def test_freemail_symbol_is_enforced_on_submit(env, admin):
    """The dialog disables Hele domænet for a mail rspamd marked
    FREEMAIL_FROM; a hand-made POST is refused the same way."""
    k = key("bynet", "<fm@x>")
    r = post(admin, "/rules/add", {"kind": "block", "pattern": "x@smaa-tjeneste.example", "account": "bynet",
                                   "scope": "domain", "item": k})
    assert r.status_code == 400 and "stor mailtjeneste" in r.get_json()["message"] and rules(env) == set()
    # Without the mail (Regler page) the domain is not known as freemail.
    assert post(admin, "/rules/add", {"kind": "block", "pattern": "x@smaa-tjeneste.example", "account": "bynet",
                                      "scope": "address", "item": k}).get_json()["ok"]
    data = post(admin, "/mail/action", {"action": "release_allow", "items": [k], "scope": "domain",
                                        "view": "spam", "nonce": "fm1"}).get_json()
    assert "ikke tilladt" in data["results"][0]["text"]
    assert ("bynet", "@smaa-tjeneste.example", "allow") not in rules(env)


def test_opposite_rule_is_switched_not_overwritten(env, admin):
    env.engine.add_sender_rule(env.conn, "bynet", "tilbud@firma.dk", "allow", "Kunde", "admin")
    env.conn.commit()
    html = dialog(admin, {"kind": "block", "pattern": "tilbud@firma.dk", "account": "bynet"})["html"]
    assert "disabled" in radio(html, "address") and "Skift til Bloker" in choice(html, "address")
    # The other choice is still possible, but NOT pre-selected: one tap on
    # Bloker must never block the whole domain by surprise.
    assert "disabled" not in radio(html, "domain") and "checked" not in radio(html, "domain")
    assert 'name="dialog" value="1"' in html
    # The switch of the sender's own rule is the primary (red) action.
    sw = html[html.index('action="/rules/'):]
    assert "btn-danger" in sw[:sw.index("</form>")]
    # Submitting without a choice is refused, never guessed.
    r = post(admin, "/rules/add", {"kind": "block", "pattern": "tilbud@firma.dk", "account": "bynet",
                                   "dialog": "1", "view": "spam", "next": "/spam"})
    assert r.status_code == 400 and "Vælg Kun denne adresse eller Hele domænet" in r.get_json()["message"]
    assert ("bynet", "tilbud@firma.dk", "allow") in rules(env) and ("bynet", "@firma.dk", "block") not in rules(env)
    # Frigiv og tillad (release dialog) keeps the address selectable: the
    # release replaces a block rule and Fortryd restores it.
    env.engine.add_sender_rule(env.conn, "bynet", "tilbud@firma.dk", "block", None, "admin")
    env.conn.commit()
    d = post(admin, "/mail/action", {"action": "release_allow", "items": [key("bynet", "<spam1@x>")],
                                     "choose": "1", "view": "spam", "nonce": "sw1"}).get_json()
    assert "disabled" not in radio(d["dialog"]["html"], "address")


# --------------------------------------------------------------------- follow-up (2.3 review round 3)


@pytest.mark.parametrize("pattern", ["@vexar.example", "ordre@vexar.example", "@mail.vexar.example", "@gravisk.example",
                                     "ole@bynet.example", "@bynet.example", "@minbutik.example"])
def test_protected_block_is_refused_without_scope_for_a_bruger(env, pattern):
    """The protection of the owner's shop and own addresses/domains is not
    advisory: the same POST without scope (old cached page, hand-made
    request) and with undo=1 is refused too."""
    inge = client(env, "inge")
    for extra in ({}, {"undo": "1"}):
        r = post(inge, "/rules/add", {"kind": "block", "pattern": pattern, "account": "bynet", **extra})
        data = r.get_json()
        assert r.status_code == 400 and data["ok"] is False, (pattern, extra)
        assert data["code"] in ("own_shop", "own_mailbox", "own_domain")
    assert rules(env) == set()


def test_import_field_skips_protected_lines(env, admin):
    r = post(admin, "/rules/add", {"kind": "block", "account": "*",
                                   "patterns": "@vexar.example\n@gravisk.example\nspam@ok.example\n@bynet.example"})
    data = r.get_json()
    assert data["ok"] and data["message"].startswith("1 regel tilføjet")
    assert "3 sprunget over (jeres egne adresser, domæner eller webshop kan ikke blokeres)" in data["message"]
    assert rules(env) == {("*", "spam@ok.example", "block")}
    # Allowing them in bulk is fine.
    assert post(admin, "/rules/add", {"kind": "allow", "account": "*",
                                      "patterns": "@vexar.example\n@gravisk.example"}).get_json()["ok"]


def test_kind_switch_to_block_is_refused_without_guard_and_for_undo(env):
    inge = client(env, "inge")
    assert post(inge, "/rules/add", {"kind": "allow", "pattern": "@vexar.example", "account": "bynet",
                                      "scope": "domain"}).get_json()["ok"]
    rid = env.conn.execute("SELECT id FROM sender_rules WHERE pattern='@vexar.example'").fetchone()[0]
    for extra in ({"guard": "1"}, {}, {"undo": "1"}):
        r = post(inge, f"/rules/{rid}/kind", {"kind": "block", **extra})
        assert r.status_code == 400 and r.get_json()["code"] == "own_shop", extra
    assert rules(env) == {("bynet", "@vexar.example", "allow")}
    # Other senders still switch without the guard (legacy path unchanged).
    assert post(inge, "/rules/add", {"kind": "allow", "pattern": "x@firma.example", "account": "bynet",
                                      "scope": "address"}).get_json()["ok"]
    rid2 = env.conn.execute("SELECT id FROM sender_rules WHERE pattern='x@firma.example'").fetchone()[0]
    assert post(inge, f"/rules/{rid2}/kind", {"kind": "block"}).get_json()["ok"]


def test_own_domain_dialog_points_to_learn_as_spam(env, admin):
    html = dialog(admin, {"kind": "block", "pattern": "ole@bynet.example", "account": "bynet"})["html"]
    assert "data-blocked" in html and "rd-submit" not in html
    assert "udgiver sig for at komme fra jer" in html and "Lær som spam" in html
    assert "ret reglen under Regler" not in html


def test_existing_rule_still_points_to_regler(env, admin):
    env.engine.add_sender_rule(env.conn, "bynet", "tilbud@firma.dk", "block", None, "admin")
    env.engine.add_sender_rule(env.conn, "bynet", "@firma.dk", "block", None, "admin")
    env.conn.commit()
    html = dialog(admin, {"kind": "block", "pattern": "tilbud@firma.dk", "account": "bynet"})["html"]
    assert "data-blocked" in html and "ret reglen under Regler" in html


def test_success_messages_use_the_mailbox_display_name(env, admin, monkeypatch):
    monkeypatch.setattr(dashboard, "account_display_names", lambda: {"bynet": "Ole"})
    data = post(admin, "/rules/add", {"kind": "block", "pattern": "tilbud@firma.dk", "account": "bynet",
                                      "scope": "address"}).get_json()
    assert data["message"] == "tilbud@firma.dk er nu blokeret på Ole"
    rid = env.conn.execute("SELECT id FROM sender_rules WHERE pattern='tilbud@firma.dk'").fetchone()[0]
    assert post(admin, f"/rules/{rid}/kind", {"kind": "allow"}).get_json()["message"] == \
        "tilbud@firma.dk er nu tilladt på Ole"
    data = post(admin, f"/rules/{rid}/force", {"force": "1"}).get_json()
    assert data["message"] == "tilbud@firma.dk er nu Altid igennem på Ole"
    assert "bynet" not in data["message"]
