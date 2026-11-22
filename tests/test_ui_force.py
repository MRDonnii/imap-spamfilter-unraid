"""UI 2.0.3: 'Altid igennem' (force) allow rules on Regler and the detail page."""

from __future__ import annotations

import re

from fakes_ui import csrf_of, insert_message, post

import ui_kit as kit  # noqa: E402
from test_ui_core import INLINE_PATTERNS  # noqa: E402
from test_ui_mail import admin, env, forms_in, key, sofie, row_of  # noqa: E402,F401 - fixtures

FORCE_TEXT = "Afsenderen er markeret Altid igennem, så beskeden flyttes aldrig."


def force_of(env, rid):
    return env.conn.execute("SELECT force FROM sender_rules WHERE id=?", (rid,)).fetchone()[0]


def test_allow_rule_row_has_force_toggle_with_plain_danish_confirm(env, admin):
    rid = env.engine.add_sender_rule(env.conn, "*", "@vexar.example", "allow", "Webshop")
    bid = env.engine.add_sender_rule(env.conn, "*", "@lotto.example", "block")
    env.conn.commit()
    html = admin.get("/rules").get_data(as_text=True)
    row = row_of(html, f"rule:{rid}")
    assert "Altid igennem</span>" not in row.split("rule-actions")[0]  # no badge on a normal rule
    toggle = [b for url, b in forms_in(row) if url == f"/rules/{rid}/force"]
    assert len(toggle) == 1 and 'name="force" value="1"' in toggle[0] and "Gør til Altid igennem" in toggle[0]
    assert "data-confirm=" in toggle[0] and "altid i indbakken" in toggle[0] and "100 %" in toggle[0]
    assert "falske mails i afsenderens navn også kommer igennem" in toggle[0]
    assert "webshop-platform" in toggle[0] and 'name="csrf"' in toggle[0]
    # Block rules have no force toggle.
    assert "/force" not in row_of(html, f"rule:{bid}")


def test_toggle_force_on_and_off_with_undo(env, admin):
    rid = env.engine.add_sender_rule(env.conn, "*", "@vexar.example", "allow", "Webshop")
    env.conn.commit()
    data = post(admin, f"/rules/{rid}/force", {"force": "1", "view": "rules", "next": "/rules"}).get_json()
    assert data["ok"] and data["message"] == "@vexar.example er nu Altid igennem"
    assert force_of(env, rid) == 1
    row = data["rows"][f"rule:{rid}"]
    assert row.startswith("<tr") and "Altid igennem" in row and "Normal tilladelse" in row
    assert 'name="force" value="0"' in row and "badge tone-brand" in row
    assert env.audit()[-1]["action"] == "rule_force" and env.audit()[-1]["detail"] == "on @vexar.example"
    assert data["undo"]["url"] == f"/rules/{rid}/force" and data["undo"]["fields"]["force"] == "0"
    html = admin.get("/rules").get_data(as_text=True)
    assert "Altid igennem" in row_of(html, f"rule:{rid}")
    # Same state again: no change, no audit.
    n = len(env.audit())
    again = post(admin, f"/rules/{rid}/force", {"force": "1", "view": "rules"}).get_json()
    assert again["ok"] and "var allerede" in again["message"] and len(env.audit()) == n and "undo" not in again
    # Fortryd -> normal again.
    back = post(admin, f"/rules/{rid}/force", data["undo"]["fields"]).get_json()
    assert back["ok"] and back["message"].startswith("Fortrudt") and force_of(env, rid) == 0
    assert env.audit()[-1]["detail"] == "off @vexar.example"


def test_force_endpoint_validation(env, admin):
    rid = env.engine.add_sender_rule(env.conn, "*", "@vexar.example", "allow")
    bid = env.engine.add_sender_rule(env.conn, "*", "@lotto.example", "block")
    env.conn.commit()
    assert post(admin, f"/rules/{rid}/force", {"force": "ja"}).get_json()["ok"] is False
    r = post(admin, f"/rules/{bid}/force", {"force": "1"})
    assert r.get_json()["ok"] is False and force_of(env, bid) == 0
    assert post(admin, "/rules/99999/force", {"force": "1"}).status_code == 404


def test_force_scope_and_csrf(env, admin, sofie):
    gid = env.engine.add_sender_rule(env.conn, "*", "@vexar.example", "allow")
    own = env.engine.add_sender_rule(env.conn, "sofie", "@shop.example", "allow")
    other = env.engine.add_sender_rule(env.conn, "bynet", "@anna.example", "allow")
    env.conn.commit()
    # Global rules are admin-only; other accounts' rules are not visible/editable.
    assert post(sofie, f"/rules/{gid}/force", {"force": "1"}).status_code == 403
    assert post(sofie, f"/rules/{other}/force", {"force": "1"}).status_code == 403
    assert force_of(env, gid) == 0 and force_of(env, other) == 0
    html = sofie.get("/rules").get_data(as_text=True)
    # 'Altid igennem' is admin-only (2.1): no toggle, not even on own rules.
    assert f"/rules/{gid}/force" not in html and f"/rules/{own}/force" not in html
    assert 'name="force"' not in html
    assert post(sofie, f"/rules/{own}/force", {"force": "1"}).status_code == 403 and force_of(env, own) == 0
    r = post(sofie, "/rules/add", {"kind": "allow", "pattern": "@y.example", "account": "sofie", "force": "1"})
    assert r.status_code == 403
    # A scoped user cannot create a global force rule through the form either.
    r = post(sofie, "/rules/add", {"kind": "allow", "pattern": "@x.example", "account": "*", "force": "1"})
    assert r.status_code == 403
    # CSRF: no token -> refused, nothing changes.
    r = admin.post(f"/rules/{gid}/force", data={"force": "1"})
    assert r.status_code == 400 and force_of(env, gid) == 0


def test_force_toggle_without_js_redirects_with_flash(env, admin):
    rid = env.engine.add_sender_rule(env.conn, "*", "@vexar.example", "allow")
    env.conn.commit()
    r = admin.post(f"/rules/{rid}/force", data={"force": "1", "next": "/rules?kind=allow", "view": "rules",
                                                "csrf": csrf_of(admin)})
    assert r.status_code == 302 and r.headers["Location"] == "/rules?kind=allow"
    html = admin.get("/rules?kind=allow").get_data(as_text=True)
    assert "@vexar.example er nu Altid igennem" in html and force_of(env, rid) == 1


def test_add_form_has_force_checkbox_for_allow_rules(env, admin):
    html = admin.get("/rules").get_data(as_text=True)
    form = html[html.index('<div class="form-grid">'):html.index("Tilføj regel")]
    assert 'class="field field-switch force-field"' in form
    assert 'type="checkbox" role="switch" name="force" value="1"' in form and "Altid igennem" in form
    assert "100 %" in form and "checked" not in form.split('name="force"')[1].split(">")[0]
    data = post(admin, "/rules/add", {"kind": "allow", "pattern": "@vexar.example", "account": "*",
                                      "note": "Webshop", "force": "1"}).get_json()
    assert data["ok"] and data["message"] == "@vexar.example er nu tilladt (Altid igennem)"
    rid = env.conn.execute("SELECT id FROM sender_rules WHERE pattern='@vexar.example'").fetchone()[0]
    assert force_of(env, rid) == 1
    assert env.audit()[-1]["action"] == "rule_add" and env.audit()[-1]["detail"] == "allow @vexar.example force"
    # force is ignored for block rules.
    post(admin, "/rules/add", {"kind": "block", "pattern": "@lotto.example", "account": "*", "force": "1"})
    assert env.conn.execute("SELECT force FROM sender_rules WHERE pattern='@lotto.example'").fetchone()[0] == 0
    # Upgrading an existing normal rule via the form can be undone back to normal.
    nid = env.engine.add_sender_rule(env.conn, "bynet", "@shop.example", "allow")
    env.conn.commit()
    data = post(admin, "/rules/add", {"kind": "allow", "pattern": "@shop.example", "account": "bynet",
                                      "force": "1"}).get_json()
    assert force_of(env, nid) == 1 and data["undo"]["url"] == f"/rules/{nid}/force"
    post(admin, data["undo"]["url"], data["undo"]["fields"])
    assert force_of(env, nid) == 0
    # The preview tells that an existing rule is Altid igennem.
    p = admin.get("/rules/preview?pattern=@vexar.example&account=*").get_json()
    assert "Altid igennem" in p["text"]


def test_one_click_allow_buttons_create_normal_rules_and_never_downgrade(env, admin):
    html = admin.get("/spam").get_data(as_text=True)
    assert 'name="force"' not in row_of(html, key("bynet", "<spam1@x>"))
    post(admin, "/mail/action", {"action": "release_allow", "view": "spam", "items": [key("bynet", "<spam1@x>")]})
    rid = env.conn.execute("SELECT id FROM sender_rules WHERE pattern='win@lotto.example'").fetchone()[0]
    assert force_of(env, rid) == 0
    post(admin, "/rules/add", {"kind": "allow", "pattern": "mor@familie.dk", "account": "bynet", "view": "messages"})
    assert env.conn.execute("SELECT force FROM sender_rules WHERE pattern='mor@familie.dk'").fetchone()[0] == 0
    # Re-adding an existing 'Altid igennem' rule without the box keeps it.
    gid = env.engine.add_sender_rule(env.conn, "*", "@vexar.example", "allow", force=True)
    env.conn.commit()
    post(admin, "/rules/add", {"kind": "allow", "pattern": "@vexar.example", "account": "*"})
    assert force_of(env, gid) == 1


def test_kind_switch_and_delete_undo_keep_force(env, admin):
    # vexar.example itself can never be switched to Bloker (2.3.0 follow-up):
    shop = env.engine.add_sender_rule(env.conn, "*", "@vexar.example", "allow", "Webshop", force=True)
    env.conn.commit()
    data = post(admin, f"/rules/{shop}/kind", {"kind": "block", "view": "rules"}).get_json()
    assert not data["ok"] and data.get("code") == "own_shop" and force_of(env, shop) == 1
    rid = env.engine.add_sender_rule(env.conn, "*", "@forhandler.example", "allow", "Webshop", force=True)
    env.conn.commit()
    data = post(admin, f"/rules/{rid}/kind", {"kind": "block", "view": "rules"}).get_json()
    assert force_of(env, rid) == 0 and data["undo"]["fields"]["force"] == "1"
    post(admin, data["undo"]["url"], data["undo"]["fields"])
    assert force_of(env, rid) == 1
    data = post(admin, f"/rules/{rid}/delete", {"view": "rules"}).get_json()
    assert data["undo"]["fields"]["force"] == "1"
    post(admin, data["undo"]["url"], data["undo"]["fields"])
    row = env.conn.execute("SELECT kind, note, force FROM sender_rules WHERE pattern='@forhandler.example'").fetchone()
    assert tuple(row) == ("allow", "Webshop", 1)


def _detail(admin, account, mid):
    return admin.get(f"/messages/{account}/{kit.token_for(mid)}").get_data(as_text=True)


def test_detail_page_explains_force(env, admin):
    fid = env.engine.add_sender_rule(env.conn, "*", "@vexar.example", "allow", force=True)
    nid = env.engine.add_sender_rule(env.conn, "*", "@normal.example", "allow")
    insert_message(env.conn, "bynet", "<order@x>", our_action="allowlisted", our_score=14.0,
                   sender="Vexar <support@vexar.example>", rule_hit=f"allow:{fid}",
                   symbols=[{"n": "DMARC_POLICY_REJECT", "s": 2.0, "o": []}])
    insert_message(env.conn, "bynet", "<nl@x>", our_action="allowlisted", our_score=12.0,
                   sender="nyt@normal.example", rule_hit=f"allow:{nid}")
    env.conn.commit()
    html = _detail(admin, "bynet", "<order@x>")
    assert FORCE_TEXT in html and "Altid igennem: flyttes aldrig" in html
    html = _detail(admin, "bynet", "<nl@x>")
    assert FORCE_TEXT not in html and "afsenderen er tilladt af en regel" in html


def test_force_markup_is_csp_clean(env, admin):
    fid = env.engine.add_sender_rule(env.conn, "*", "@vexar.example", "allow", force=True)
    env.engine.add_sender_rule(env.conn, "bynet", "@normal.example", "allow")
    insert_message(env.conn, "bynet", "<order@x>", our_action="allowlisted", our_score=14.0,
                   sender="support@vexar.example", rule_hit=f"allow:{fid}")
    env.conn.commit()
    for path in ("/rules", "/rules?kind=allow", f"/messages/bynet/{kit.token_for('<order@x>')}"):
        html = admin.get(path).get_data(as_text=True)
        for rx, what in INLINE_PATTERNS:
            m = rx.search(html)
            assert m is None, f"{what} on {path}: {html[max(0, m.start() - 80):m.end() + 80]}"
    data = post(admin, f"/rules/{fid}/force", {"force": "0", "view": "rules"}).get_json()
    for rx, what in INLINE_PATTERNS:
        assert not rx.search(data["rows"][f"rule:{fid}"]), what
    assert re.search(r'<tr data-row="rule:\d+">', data["rows"][f"rule:{fid}"])
