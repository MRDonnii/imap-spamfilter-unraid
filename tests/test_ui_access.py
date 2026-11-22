"""2.1 access control (AUTH-1): roles, per-user permissions, the central
route policy, remember-me sessions, the Brugere pages and migration of
pre-2.1 users.

The permission MATRIX introspects every route registered on the Flask app
(mail + admin pages), so a new route without an access policy - or with a
policy that lets a limited user through - fails here.
"""

from __future__ import annotations

import json
import re
import time
from email.utils import parsedate_to_datetime

import pytest

from fakes_ui import TEST_PASSWORD, fast_hash, csrf_of, insert_message, login, post, set_status
from fakes_ui_admin import make_admin_env

import dashboard  # noqa: E402
import ui_kit as kit  # noqa: E402
from test_ui_core import INLINE_PATTERNS  # noqa: E402

PW = TEST_PASSWORD

# What each user may see. Strings from the OTHER mailboxes must never reach
# a limited user (addresses, senders, subjects, account names).
LEAKS_FOR_BYNET_USER = ["ole@molt.example", "sofie@molt.example", "skjult@molt-afsender.example", "MOLT-HEMMELIGT",
                        "skjult@sofie-afsender.example", "SOFIE-HEMMELIGT", "acct-molt", "acct-sofie",
                        "account=molt", "account=sofie", '"molt"', '"sofie"', ">molt<", ">sofie<"]
LEAKS_FOR_NOBODY = LEAKS_FOR_BYNET_USER + ["ole@bynet.example", "skjult@bynet-afsender.example", "BYNET-EMNE",
                                           "acct-bynet", "account=bynet", ">bynet<"]


def write_users(env, lines: list[str]) -> None:
    (env.state / "dashboard_users").write_text("\n".join(lines) + "\n")


@pytest.fixture
def env(tmp_path, monkeypatch):
    e = make_admin_env(tmp_path, monkeypatch)
    h = fast_hash(PW)
    write_users(e, [f"admin:{h}:admin:0",
                    f"anna:{h}:bynet:0",       # Bruger, bynet, all permissions (no ui_users row = 2.0 default)
                    f"bo:{h}:bynet:0",         # Bruger, bynet, no permissions
                    f"cille:{h}:~none:0"])     # Bruger without mailboxes
    with e.app.test_request_context("/"):
        dashboard.set_user_perms("bo", [], "test")
    c = e.conn
    for acc, state in (("bynet", "idle"), ("molt", "auth_failed"), ("sofie", "paused")):
        set_status(c, acc, state, detail=f"detalje for {acc}", junk_exists=1)
    insert_message(c, "bynet", "<j1@x>", our_action="moved_to_junk", our_score=14.0, current_folder="Spamfilter",
                   sender="Spam <skjult@bynet-afsender.example>", subject="BYNET-EMNE")
    insert_message(c, "bynet", "<j2@x>", our_action="none", our_score=1.0,
                   sender="Ven <ven@familie.example>", subject="Hej fra bynet")
    insert_message(c, "molt", "<m1@x>", our_action="moved_to_junk", our_score=12.0, current_folder="Spamfilter",
                   sender="Skjult <skjult@molt-afsender.example>", subject="MOLT-HEMMELIGT")
    insert_message(c, "molt", "<m2@x>", our_action="move_failed", our_score=12.0,
                   sender="skjult@molt-afsender.example", subject="MOLT-HEMMELIGT 2")
    insert_message(c, "sofie", "<t1@x>", our_action="shadow_spam", our_score=9.0,
                   sender="skjult@sofie-afsender.example", subject="SOFIE-HEMMELIGT")
    for acc in ("bynet", "molt", "sofie"):
        c.execute("INSERT INTO stats_daily(account, day, metric, n) VALUES(?,?,?,?)", (acc, kit.today_str(), "scanned", 7))
    c.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES('molt', ?, '<m1@x>', 'moved_to_junk', '')",
              (int(time.time()),))
    c.execute("INSERT INTO sender_rules(account, pattern, kind, created_at) VALUES('molt', '@molt-regel.example', 'block', 1)")
    c.execute("INSERT INTO train_jobs(account, folder, kind, max_messages, created_at) VALUES('molt','Junk','spam',10,1)")
    c.commit()
    # Undo job 1 belongs to bynet (Fortryd flytninger).
    e.services.undo_jobs = {1: {"id": 1, "account": "bynet", "since_ts": 1, "until_ts": 2, "learn": 0, "status": "done",
                                "total": 1, "processed": 1, "moved": 1, "not_found": 0, "skipped": 0, "failed": 0,
                                "learned": 0, "error": "", "created_by": "admin", "created_at": 1, "started_at": 1,
                                "finished_at": 2, "percent": 100, "remaining": 0, "text": "Færdig."}}
    return e


def client_for(env, name: str | None):
    c = env.app.test_client()
    if name:
        r = login(c, name, PW)
        assert r.status_code == 302, name
    return c


def body(r) -> str:
    return r.get_data().decode("utf-8", "replace")


# --------------------------------------------------------------------- route policies


EXPECTED_POLICY = {
    "healthz": "public", "api_health": "public", "favicon": "public", "login": "public",
    "logout": "public", "logout_get": "public",
    "overview": "login", "bayes_fragment": "login", "spam_page": "login", "api_status": "login",
    "messages_page": "see_messages", "message_detail": "see_messages",
    "mail_action": "release",
    "rules_page": "rules", "rules_preview": "rules", "rules_add": "rules", "rules_delete": "rules",
    "rules_kind": "rules", "rules_force": "admin",
    # 2.1 (AUTH-2): code step of the login, PWA files, the user's own account page.
    "login_2fa": "public", "manifest": "public", "service_worker": "public", "offline": "public",
    "apple_touch_icon": "public",
    "me_page": "login", "me_2fa_setup": "login", "me_2fa_confirm": "login", "me_2fa_recovery": "login",
    "me_2fa_disable": "login", "me_logout_all": "login",
    # 2.1 (UI-FEATURES): own password, welcome card, "gennemset", Find en
    # mail (search: everybody, move: release), Fortryd flytninger, Hjælp.
    "me_password": "login", "welcome_dismiss": "login", "spam_mark_seen": "login",
    "find_page": "login", "find_search": "login", "find_move": "release",
    "undo_page": "release", "undo_run": "release", "undo_job_page": "release", "undo_job_json": "release",
    "undo_job_cancel": "release", "help_page": "login",
    # 2.3 (B13): Regler → Kendte kontakter. Seeing the own mailboxes' contacts
    # and "Opdater nu": logged in (object check: require_account); remove /
    # restore / the on-off switch: the 'rules' permission on that mailbox.
    "contacts_page": "login", "contacts_sync": "login", "contacts_status": "rules", "contacts_enabled": "rules",
    # 2.3.6 (B26): the Home Assistant API (home network + bearer token, no
    # session: 404 for everybody else - tests/test_ha.py) and the family
    # guide PDF under Hjælp.
    "api_ha": "ha_token", "help_familieguide": "login",
    # 2.9.0: Kontrolrum single sign-on - server to server, public (peer IP +
    # signature, tests/test_ui_kontrolrum_sso.py); every method but POST is 404.
    "login_kontrolrum": "public",
    # 2.5.0: Min konto -> Beskeder på denne enhed (push). Every route acts
    # only on the logged-in user's own devices (tests/test_push_ui.py).
    "me_push_key": "login", "me_push_subscribe": "login", "me_push_prefs": "login", "me_push_test": "login",
    "me_push_unsubscribe": "login", "me_push_remove": "login",
    # 2.6 (B1): passkeys - the login ceremony is public (CSRF + throttle +
    # login scope, tests/test_passkeys.py); Min konto acts only on the
    # logged-in user's own passkeys and needs a fresh re-auth.
    "login_passkey_options": "public", "login_passkey": "public",
    "me_passkeys_confirm_page": "login", "me_passkeys_confirm": "login", "me_passkeys_options": "login",
    "me_passkeys_register": "login", "me_passkeys_remove": "login",
    # 2.6 (A4): Nyhedsbreve - the page needs the mailbox (require_account);
    # "Tilbage til indbakken" / "Fjern" need 'release' on that mailbox.
    "newsletters_page": "login", "newsletters_back": "release", "newsletters_unkeep": "release",
}
# Admin-only 2.1 routes that must stay admin-only.
EXPECTED_ADMIN = {"user_preview", "account_auto_allow", "settings_digest", "account_threshold_suggestion",
                  "account_resume_moves", "account_fast_move", "account_protected", "account_forwarders",
                  "account_receipt", "account_receipt_test", "account_folder_sizes", "account_display_name",
                  # 2.2 (UI-2.2a): Reparér Bayes, lærelister, rebalancering, ugerapport
                  "training_repair_learn", "training_learn_list_page", "training_learn_list_cancel",
                  "training_learn_list_retry", "training_rebalance_page", "training_rebalance",
                  "settings_weekly", "settings_weekly_preview", "settings_weekly_preview_html", "settings_weekly_send",
                  # 2.3 (B17): blocked attachment types + per-sender exceptions
                  "settings_attachments", "attachments_page", "attachments_add", "attachments_delete",
                  # 2.3 follow-up: Byg Bayes op på ny + the Straks-advarsel switch
                  "training_rebuild_page", "training_rebuild_start", "training_rebuild_restore",
                  "training_rebuild_status", "account_threat_notice",
                  # 2.6 (A4): the Nyhedsbreve setting (Fra / Prøv / Til)
                  "account_newsletters"}
# Routes that act on the logged-in user's OWN login (2FA, log out everywhere):
# allowed for everybody who is logged in, covered by tests/test_ui_auth2.py.
SELF_SERVICE = {"me_2fa_confirm", "me_2fa_recovery", "me_2fa_disable", "me_logout_all",
                # the user's own UI state / password (tests: test_ui_features.py)
                "welcome_dismiss", "spam_mark_seen", "me_password",
                # 2.5.0 push devices (tests: test_push_ui.py)
                "me_push_subscribe", "me_push_prefs", "me_push_test", "me_push_unsubscribe", "me_push_remove",
                # 2.6 passkeys (tests: test_passkeys.py)
                "me_passkeys_confirm", "me_passkeys_options", "me_passkeys_register", "me_passkeys_remove"}


def all_endpoints(app):
    return sorted({r.endpoint for r in app.url_map.iter_rules() if r.endpoint != "static"})


def test_every_route_declares_a_policy(env):
    valid = {"public", "login", "admin", dashboard.POLICY_HA, *dashboard.PERMISSIONS}
    for ep in all_endpoints(env.app):
        policy = dashboard.route_policy(ep)
        assert policy in valid, f"{ep} has no/unknown access policy: {policy!r}"
        view = env.app.view_functions[ep]
        if view.__module__ == "ui_admin":
            assert policy == "admin", f"admin page {ep} is not admin-only"
        if ep in EXPECTED_POLICY:
            assert policy == EXPECTED_POLICY[ep], ep
        if ep in EXPECTED_ADMIN:
            assert policy == "admin", ep
    assert EXPECTED_ADMIN <= set(all_endpoints(env.app))
    # Every non-admin route is listed above: adding one forces a review here.
    unlisted = [ep for ep in all_endpoints(env.app)
                if dashboard.route_policy(ep) != "admin" and ep not in EXPECTED_POLICY]
    assert unlisted == []


def test_route_without_policy_fails_closed(env, monkeypatch):
    def naked():
        return "secret"
    monkeypatch.setitem(env.app.view_functions, "healthz", naked)
    r = env.app.test_client().get("/healthz")
    assert r.status_code == 404 and "secret" not in body(r)


def _url_for_rule(env, rule, *, account: str, user: str) -> str | None:
    tokens = {"bynet": kit.token_for("<j1@x>"), "molt": kit.token_for("<m1@x>"), "sofie": kit.token_for("<t1@x>")}
    values = {}
    for arg in rule.arguments:
        if arg == "account":
            values[arg] = account
        elif arg == "token":
            values[arg] = tokens[account]
        elif arg == "name":
            values[arg] = user if rule.rule.startswith("/users/") else account
        elif arg in ("job_id", "rule_id", "undo_id"):
            values[arg] = 1
        else:
            return None
    path = rule.rule
    for k, v in values.items():
        path = re.sub(r"<(?:[a-z]+:)?%s>" % k, str(v), path)
    return path


GET_EXTRA = ["/?account=bynet", "/spam?account=bynet&q=skjult", "/messages?q=skjult", "/messages?q=MOLT",
             "/rules/preview?pattern=@molt-afsender.example", "/rules?q=regel", "/api/status", "/fragments/bayes"]


def _get_rules(env):
    return [r for r in env.app.url_map.iter_rules() if "GET" in r.methods and r.endpoint != "static"]


PROFILES = {
    # name: (is_admin, visible accounts, perms)
    "admin": (True, {"bynet", "molt", "sofie"}, set(dashboard.PERMISSIONS)),
    "anna": (False, {"bynet"}, set(dashboard.PERMISSIONS)),
    "bo": (False, {"bynet"}, set()),
    "cille": (False, set(), set(dashboard.PERMISSIONS)),
}


def _expected_get(policy: str, profile, account_arg: str | None) -> set[int]:
    is_admin, visible, perms = profile
    if policy == "public":
        return {200, 302}
    if policy == dashboard.POLICY_HA:
        return {404}  # a session never opens the token API
    if is_admin:
        return {200, 404}  # 404 only for objects that do not exist (job 1 for /training/jobs/1 exists)
    if policy == "admin":
        return {403}
    if policy in dashboard.PERMISSIONS and policy not in perms:
        return {403}
    if account_arg is not None and account_arg not in visible:
        return {404}
    return {200}


@pytest.mark.parametrize("who", ["admin", "anna", "bo", "cille", None])
def test_permission_matrix_get(env, who):
    c = client_for(env, who)
    profile = PROFILES.get(who)
    leaks = {"anna": LEAKS_FOR_BYNET_USER, "bo": LEAKS_FOR_BYNET_USER, "cille": LEAKS_FOR_NOBODY}.get(who, [])
    seen = 0
    for rule in _get_rules(env):
        policy = dashboard.route_policy(rule.endpoint)
        for account in (["bynet", "molt", "sofie"] if ("account" in rule.arguments or "name" in rule.arguments
                                                       and not rule.rule.startswith("/users/")) else [None]):
            url = _url_for_rule(env, rule, account=account or "bynet", user="anna")
            if url is None:
                continue
            r = c.get(url, headers={"Accept": "text/html"})
            seen += 1
            if rule.endpoint == "login_kontrolrum":  # POST only (server to server): GET is a plain 404 for all
                assert r.status_code == 404, url
                continue
            if who is None:
                if policy == "public":
                    assert r.status_code < 400, url
                elif policy == dashboard.POLICY_HA:
                    assert r.status_code == 404, url
                else:
                    assert r.status_code == 302 and "/login" in r.headers["Location"], url
                continue
            acc_arg = account if "account" in rule.arguments else ("bynet" if "undo_id" in rule.arguments else None)
            want = _expected_get(policy, profile, acc_arg)
            assert r.status_code in want, f"{who} GET {url}: {r.status_code}, want {want}"
            if r.status_code == 200 and policy != "public":  # /api/health lists states by name (A8 monitor)
                text = body(r)
                for s in leaks:
                    assert s not in text, f"{who} GET {url} leaks {s!r}"
    assert seen >= 25
    for url in GET_EXTRA:
        r = c.get(url, headers={"Accept": "text/html"})
        if who is None:
            assert r.status_code in (302, 401), url
            continue
        assert r.status_code in (200, 403, 404), url
        if r.status_code == 200:
            for s in leaks:
                assert s not in body(r), f"{who} GET {url} leaks {s!r}"


@pytest.mark.parametrize("who", ["anna", "bo", "cille", None])
def test_permission_matrix_post_denials(env, who):
    """Every state-changing route refuses users without the policy's role
    or permission (and anonymous clients) before any work is done."""
    c = client_for(env, who)
    profile = PROFILES.get(who)
    users_before = (env.state / "dashboard_users").read_text()
    cfg_before = env.config.read_text()
    checked = 0
    for rule in env.app.url_map.iter_rules():
        if "POST" not in rule.methods:
            continue
        policy = dashboard.route_policy(rule.endpoint)
        if policy == "public" or rule.endpoint in SELF_SERVICE:
            continue
        if policy == "ha_token":
            # Read-only HA API: every method is routed to it and answers
            # 404 without the token (tests/test_ha.py covers the matrix).
            assert post(c, rule.rule, {}).status_code == 404
            continue
        url = _url_for_rule(env, rule, account="molt", user="anna")
        if url is None:
            continue
        r = post(c, url, {"confirm": "FJERN", "role": "admin", "password": "x" * 14, "password2": "x" * 14,
                          "kind": "allow", "pattern": "a@b.example", "account": "*", "force": "1",
                          "action": "release", "items": [f"molt:{kit.token_for('<m1@x>')}"]})
        checked += 1
        if who is None:
            assert r.status_code == 401, url
            continue
        is_admin, _visible, perms = profile
        if policy == "admin" or (policy in dashboard.PERMISSIONS and policy not in perms):
            assert r.status_code == 403, f"{who} POST {url}: {r.status_code}"
        else:
            # Allowed route, but every object here belongs to molt / is global.
            assert r.status_code in (400, 403, 404), f"{who} POST {url}: {r.status_code}"
    assert checked >= 20
    assert (env.state / "dashboard_users").read_text() == users_before
    assert env.config.read_text() == cfg_before
    assert env.services.calls == []
    rules = env.conn.execute("SELECT account, pattern, kind FROM sender_rules").fetchall()
    assert [tuple(r) for r in rules] == [("molt", "@molt-regel.example", "block")]


# --------------------------------------------------------------------- what a limited user sees


def test_no_permission_user_sees_only_overview_and_spam(env):
    bo = client_for(env, "bo")
    html = body(bo.get("/spam"))
    assert "BYNET-EMNE" in html
    assert 'action="/mail/action"' not in html and 'action="/rules/add"' not in html
    assert 'name="items"' not in html and "data-select-all" not in html
    assert f'href="/messages/bynet/' not in html  # rows are not links without see_messages
    assert 'href="/messages"' not in html and 'href="/rules"' not in html  # nav (sidebar + tab bar)
    assert 'href="/accounts"' not in html and 'href="/users"' not in html
    assert bo.get("/messages").status_code == 403
    assert bo.get(f"/messages/bynet/{kit.token_for('<j1@x>')}").status_code == 403
    assert bo.get("/rules").status_code == 403
    r = post(bo, "/mail/action", {"action": "release", "items": [f"bynet:{kit.token_for('<j1@x>')}"]})
    assert r.status_code == 403 and env.services.calls == []
    overview = body(bo.get("/"))
    # Simple home: own spam, no scores, no KPIs, no action buttons, no Find (no release).
    assert "BYNET-EMNE" in overview and "Nøgletal" not in overview and 'class="score' not in overview
    assert 'action="/mail/action"' not in overview and 'href="/find' not in overview
    assert "/messages?account" not in overview and "Hvorfor?" in overview


def test_full_permission_user(env):
    anna = client_for(env, "anna")
    html = body(anna.get("/spam"))
    # Simple rows with big buttons (no bulk checkboxes, no score numbers).
    assert 'value="release"' in html and 'value="release_allow"' in html and "data-select-all" not in html
    assert 'class="score' not in html and 'action="/rules/add"' in html
    assert f'href="/messages/bynet/{kit.token_for("<j1@x>")}"' in html
    assert anna.get("/messages").status_code == 200
    rules = body(anna.get("/rules"))
    assert 'value="*"' not in rules and 'name="force"' not in rules  # no global, no Altid igennem
    # Someone else's mail: 404, nothing called.
    r = post(anna, "/mail/action", {"action": "release", "items": [f"molt:{kit.token_for('<m1@x>')}"]})
    assert r.status_code == 404 and env.services.calls == []
    r = post(anna, "/mail/action", {"action": "release", "view": "spam",
                                    "items": [f"molt:{kit.token_for('<m1@x>')}", f"bynet:{kit.token_for('<j1@x>')}"]})
    data = r.get_json()
    assert [c[0] for c in env.services.calls] == ["bynet"]
    assert "MOLT" not in json.dumps(data) and "m1@x" not in json.dumps(data)
    assert anna.get("/spam?account=molt").status_code == 404
    assert anna.get("/rules/preview?pattern=a@b.example&account=molt").status_code == 404


def test_user_without_mailboxes(env):
    cille = client_for(env, "cille")
    assert "Du har ikke adgang til nogen postkasser" in body(cille.get("/"))
    data = cille.get("/api/status").get_json()
    assert data["accounts"] == [] and data["kpis"]["24h"]["scanned"] == 0 and data["nav"]["spam"] == 0
    html = body(cille.get("/spam"))
    assert 'class="mail-row' not in html and "Ingen postkasse endnu" in html


def test_config_error_text_is_admin_only(env):
    env.engine.config_error = "account molt: bad port for ole@molt.example"
    anna = client_for(env, "anna")
    assert "ole@molt.example" not in body(anna.get("/"))
    assert "ole@molt.example" not in json.dumps(anna.get("/api/status").get_json())
    admin = client_for(env, "admin")
    assert "ole@molt.example" in body(admin.get("/"))


def test_permissions_are_reread_on_every_request(env):
    anna = client_for(env, "anna")
    assert anna.get("/rules").status_code == 200
    admin = client_for(env, "admin")
    r = post(admin, "/users/anna", {"role": "user", "acct:bynet": "1", "perm:release": "1"})
    assert r.get_json()["ok"]
    assert anna.get("/rules").status_code == 403          # same session, new rights
    assert anna.get("/messages").status_code == 403
    assert anna.get("/spam").status_code == 200
    post(admin, "/users/anna", {"role": "user", "perm:release": "1"})  # no mailboxes any more
    assert "BYNET-EMNE" not in body(anna.get("/spam"))
    assert anna.get("/spam?account=bynet").status_code == 404


def test_bruger_cannot_override_altid_igennem(env):
    """A global 'Altid igennem' rule (vexar.example) must not be undermined by a
    Bruger's own-mailbox rule (an account rule beats a global one)."""
    env.engine.add_sender_rule(env.conn, "*", "@vexar.example", "allow", None, "admin", force=True)
    env.conn.commit()
    anna = client_for(env, "anna")
    for kind, pattern in (("block", "@vexar.example"), ("block", "support@vexar.example"), ("allow", "mailbot@vexar.example"),
                          ("block", "@x.vexar.example")):
        r = post(anna, "/rules/add", {"kind": kind, "pattern": pattern, "account": "bynet"})
        assert r.status_code == 403 and r.get_json()["ok"] is False, pattern
        assert "Altid igennem" in r.get_json()["message"]
    assert post(anna, "/rules/add", {"kind": "block", "pattern": "@vexar.example.evil.example",
                                     "account": "bynet"}).get_json()["ok"]
    rows = {tuple(r) for r in env.conn.execute("SELECT account, pattern FROM sender_rules")}
    assert ("bynet", "@vexar.example") not in rows and ("bynet", "support@vexar.example") not in rows
    # 2.3 follow-up: vexar.example is never blocked from the UI - not even by an
    # administrator and not without the dialog's scope (owner rule).
    admin = client_for(env, "admin")
    r = post(admin, "/rules/add", {"kind": "block", "pattern": "x@vexar.example", "account": "bynet"})
    assert r.status_code == 400 and r.get_json()["code"] == "own_shop"
    # A legacy admin rule (made before 2.3): the Bruger cannot flip it either.
    env.engine.add_sender_rule(env.conn, "bynet", "x@vexar.example", "block", None, "admin")
    env.conn.commit()
    rid = env.conn.execute("SELECT id FROM sender_rules WHERE pattern='x@vexar.example'").fetchone()[0]
    assert post(anna, f"/rules/{rid}/kind", {"kind": "allow"}).status_code == 403
    insert_message(env.conn, "bynet", "<shop@x>", our_action="allowlisted", our_score=11.0,
                   sender="Vexar <support@vexar.example>", subject="Ordre 1001")
    env.conn.commit()
    html = body(anna.get("/messages"))
    row = html[html.index(f'data-row="bynet:{kit.token_for("<shop@x>")}"'):]
    row = row[:row.index("</li>")]
    assert "Ordre 1001" in row
    assert "Bloker afsender" not in row and "Fjern tilladelse" not in row and "/rules/add" not in row


# --------------------------------------------------------------------- remember me


def _cookie_expiry(resp) -> float:
    cookie = resp.headers.get("Set-Cookie", "")
    m = re.search(r"Expires=([^;]+)", cookie)
    assert m, cookie
    return parsedate_to_datetime(m.group(1)).timestamp() - time.time()


def test_login_page_autocomplete_and_remember_box(env):
    html = body(env.app.test_client().get("/login"))
    assert 'autocomplete="username"' in html and 'autocomplete="current-password"' in html
    assert 'name="remember"' in html and "Husk mig på denne enhed i 30 dage" in html
    for rx, what in INLINE_PATTERNS:
        assert rx.search(html) is None, what


def test_normal_session_lifetimes(env):
    c = env.app.test_client()
    c.get("/login")
    r = c.post("/login", data={"username": "anna", "password": PW, "csrf": csrf_of(c)})
    assert abs(_cookie_expiry(r) - dashboard.SESSION_LIFETIME) < 120
    with c.session_transaction() as s:
        assert not s.get("rm")
        s["ts"] = int(time.time()) - dashboard.SESSION_IDLE - 5
    assert c.get("/").status_code == 302


def test_remember_me_lifetimes(env):
    c = env.app.test_client()
    c.get("/login")
    r = c.post("/login", data={"username": "anna", "password": PW, "remember": "1", "csrf": csrf_of(c)})
    assert r.status_code == 302
    assert abs(_cookie_expiry(r) - dashboard.REMEMBER_LIFETIME) < 120
    assert dashboard.REMEMBER_LIFETIME == 30 * 86400 and dashboard.REMEMBER_IDLE == 7 * 86400
    # 3 days without use: still logged in (a normal session would be gone after 2 h).
    with c.session_transaction() as s:
        assert s["rm"] == 1
        s["ts"] = int(time.time()) - 3 * 86400
        s["t0"] = int(time.time()) - 20 * 86400
    assert c.get("/").status_code == 200
    # 8 days idle: out.
    with c.session_transaction() as s:
        s["ts"] = int(time.time()) - 8 * 86400
    assert c.get("/").status_code == 302
    # 31 days absolute: out, even if used yesterday.
    login_remember(c, "anna")
    with c.session_transaction() as s:
        s["t0"] = int(time.time()) - 31 * 86400
        s["ts"] = int(time.time()) - 3600
    assert c.get("/").status_code == 302
    assert [x for x in env.audit() if x["action"] == "login"][-1]["detail"] == "husk mig"


def login_remember(c, name):
    c.get("/login")
    return c.post("/login", data={"username": name, "password": PW, "remember": "1", "csrf": csrf_of(c)})


@pytest.mark.parametrize("revoke", ["logout_all", "password", "remove"])
def test_remembered_sessions_are_revoked(env, revoke):
    phone = env.app.test_client()
    assert login_remember(phone, "anna").status_code == 302
    assert phone.get("/").status_code == 200
    admin = client_for(env, "admin")
    if revoke == "logout_all":
        assert post(admin, "/users/anna/logout-all", {}).get_json()["ok"]
    elif revoke == "password":
        assert post(admin, "/users/anna/password", {"password": "ny-kode-til-anna-1", "password2": "ny-kode-til-anna-1"}).get_json()["ok"]
    else:
        assert post(admin, "/users/anna/remove", {"confirm": "anna"}).get_json()["ok"]
    assert phone.get("/").status_code == 302


# --------------------------------------------------------------------- Brugere UI


def test_users_page_cards(env):
    admin = client_for(env, "admin")
    login(env.app.test_client(), "anna", PW)
    html = body(admin.get("/users"))
    for name in ("admin", "anna", "bo", "cille"):
        assert f'data-row="user:{name}"' in html
    card = html[html.index('data-row="user:anna"'):]
    card = card[:card.index("</article>")]
    assert "Kan se bynet · Må frigive post, tillade og blokere afsendere og se alle beskeder" in card
    assert "ole@bynet.example" in card and "Ikke slået til" in card and "Sidst logget ind" in card
    assert 'href="/users/anna"' in card and 'href="/users/anna#kode"' in card
    assert 'action="/users/anna/logout-all"' in card and 'data-confirm-typed="anna"' in card
    bo = html[html.index('data-row="user:bo"'):]
    assert "Må kun se fanget spam" in bo[:bo.index("</article>")]
    cil = html[html.index('data-row="user:cille"'):]
    assert "Kan ikke se nogen postkasser endnu" in cil[:cil.index("</article>")]
    me = html[html.index('data-row="user:admin"'):]
    assert "/users/admin/remove" not in me[:me.index("</article>")]  # never delete yourself / the last admin


def test_new_user_form(env):
    admin = client_for(env, "admin")
    html = body(admin.get("/users/new"))
    assert html.count('autocomplete="new-password"') == 2 and 'name="name"' in html
    assert re.search(r'name="name"[^>]*autocomplete="off"', html)
    assert "data-pw-generate" in html and "Generér stærk kode" in html and 'minlength="12"' in html
    for acc, addr in (("bynet", "ole@bynet.example"), ("molt", "ole@molt.example"), ("sofie", "sofie@molt.example")):
        assert f'name="acct:{acc}"' in html and addr in html
    for p in dashboard.PERMISSIONS:
        assert f'name="perm:{p}"' in html
    assert "data-access-summary" in html and "Kan se alle postkasser" in html
    pre = body(admin.get("/users/new?mailbox=molt"))
    assert 'name="acct:molt" value="1" data-acct-name="molt" data-acct-label="molt" checked' in pre
    assert 'name="role" value="user" checked' in pre and "Kan se molt · Må frigive post" in pre


def test_konti_card_offers_user_for_mailbox(env):
    admin = client_for(env, "admin")
    html = body(admin.get("/accounts"))
    assert 'href="/users/new?mailbox=bynet"' in html and "Opret bruger til denne postkasse" in html


def test_edit_page_password_form_autocomplete(env):
    admin = client_for(env, "admin")
    html = body(admin.get("/users/anna"))
    form = html[html.index('action="/users/anna/password"'):]
    form = form[:form.index("</form>")]
    assert 'autocomplete="username"' in form and 'value="anna"' in form
    assert form.count('autocomplete="new-password"') == 2
    assert "Ikke slået til" in html and 'id="kode"' in html


def test_create_bruger_without_mailboxes_and_permissions(env):
    admin = client_for(env, "admin")
    r = post(admin, "/users/new", {"name": "gaest", "password": "gaest-kode-12345", "password2": "gaest-kode-12345",
                                   "role": "user"})
    assert r.get_json()["ok"]
    line = next(x for x in (env.state / "dashboard_users").read_text().splitlines() if x.startswith("gaest:"))
    assert line.split(":")[2] == dashboard.NO_ACCOUNTS
    g = env.app.test_client()
    assert login(g, "gaest", "gaest-kode-12345").status_code == 302
    assert g.get("/messages").status_code == 403 and g.get("/rules").status_code == 403
    assert "BYNET-EMNE" not in body(g.get("/spam"))


def test_self_demotion_needs_confirmation(env):
    admin = client_for(env, "admin")
    assert post(admin, "/users/anna", {"role": "admin"}).get_json()["ok"]  # second admin
    html = body(admin.get("/users/admin"))
    assert 'name="self_demote"' in html and "data-self-demote" in html
    r = post(admin, "/users/admin", {"role": "user", "acct:bynet": "1", "perm:release": "1"})
    assert r.status_code == 400 and "egen administratoradgang" in r.get_json()["message"]
    r = post(admin, "/users/admin", {"role": "user", "acct:bynet": "1", "perm:release": "1", "self_demote": "1"})
    assert r.get_json()["ok"] and r.get_json()["redirect"] == "/"
    assert admin.get("/users").status_code == 403 and admin.get("/spam").status_code == 200


def test_only_admin_cannot_be_demoted(env):
    admin = client_for(env, "admin")
    r = post(admin, "/users/admin", {"role": "user", "self_demote": "1"})
    assert r.status_code == 400 and "mindst én administrator" in r.get_json()["message"]
    html = body(admin.get("/users/admin"))
    assert "Den sidste administrator kan ikke gøres til Bruger" in html


def test_access_change_is_audited_and_stored_outside_the_users_file(env):
    admin = client_for(env, "admin")
    before = (env.state / "dashboard_users").read_text()
    r = post(admin, "/users/anna", {"role": "user", "acct:bynet": "1", "perm:see_messages": "1"})
    assert r.get_json()["ok"]
    assert (env.state / "dashboard_users").read_text() == before  # same mailboxes: users file untouched
    row = env.conn.execute("SELECT perms, updated_by FROM ui_users WHERE name='anna'").fetchone()
    assert json.loads(row[0]) == {"release": False, "rules": False, "see_messages": True} and row[1] == "admin"
    rec = [x for x in env.audit() if x["action"] == "user_access"][-1]
    assert rec["detail"] == "anna bynet perms=see_messages"
    assert post(admin, "/users/anna", {"role": "user", "acct:bynet": "1", "perm:see_messages": "1"}).get_json()["message"] == "Adgangen er uændret."


def test_last_login_is_recorded(env):
    login(env.app.test_client(), "bo", PW)
    row = env.conn.execute("SELECT last_login_at, perms FROM ui_users WHERE name='bo'").fetchone()
    assert row[0] and abs(row[0] - time.time()) < 60
    assert json.loads(row[1]) == {"release": False, "rules": False, "see_messages": False}  # perms untouched


# --------------------------------------------------------------------- migration / rollback compatibility


def old_parse_user_line(raw: str):
    """dashboard.parse_user_line of 2.0.3 (the version a rollback runs)."""
    parts = raw.strip().split(":")
    if len(parts) < 2:
        return None
    name, verifier = parts[0].strip(), parts[1].strip()
    scope = parts[2].strip() if len(parts) >= 3 and parts[2].strip() else "admin"
    try:
        gen = int(parts[3]) if len(parts) >= 4 and parts[3].strip() else 0
    except ValueError:
        gen = 0
    admin = scope.lower() == "admin"
    accounts = frozenset() if admin else frozenset(a.strip() for a in re.split(r"[|,]", scope) if a.strip())
    return name, verifier, admin, accounts, gen


def test_pre_21_users_keep_their_rights(env):
    """1.x/2.0 lines (no ui_users row) load unchanged; scoped users get all
    three Bruger permissions = exactly the 2.0 behaviour."""
    h = fast_hash(PW)
    write_users(env, [f"admin:{h}", f"gammel:{h}:bynet", f"to:{h}:bynet|molt:4"])
    env.conn.execute("DELETE FROM ui_users")
    env.conn.commit()
    users = dashboard.load_users()
    assert users["admin"].admin and users["admin"].gen == 0
    assert users["gammel"].accounts == frozenset({"bynet"}) and not users["gammel"].admin
    assert users["to"].accounts == frozenset({"bynet", "molt"}) and users["to"].gen == 4
    g = client_for(env, "gammel")
    assert g.get("/messages").status_code == 200 and g.get("/rules").status_code == 200
    assert 'value="release"' in body(g.get("/spam"))
    with env.app.test_request_context("/"):
        assert dashboard.user_perms("gammel") == frozenset(dashboard.PERMISSIONS)


def test_users_file_written_by_21_is_readable_by_old_code(env):
    admin = client_for(env, "admin")
    post(admin, "/users/new", {"name": "ny", "password": "ny-bruger-kode-1", "password2": "ny-bruger-kode-1",
                               "role": "user", "acct:molt": "1", "perm:release": "1"})
    post(admin, "/users/new", {"name": "tom", "password": "tom-bruger-kode-1", "password2": "tom-bruger-kode-1",
                               "role": "user"})
    post(admin, "/users/anna", {"role": "user", "perm:rules": "1"})  # anna loses all mailboxes
    lines = [x for x in (env.state / "dashboard_users").read_text().splitlines() if x and not x.startswith("#")]
    old = {p[0]: p for p in map(old_parse_user_line, lines)}
    assert old["ny"][2] is False and old["ny"][3] == frozenset({"molt"})
    # No mailboxes is NEVER an empty scope (which old code reads as admin).
    for name in ("tom", "anna", "cille"):
        assert old[name][2] is False and old[name][3] == frozenset({dashboard.NO_ACCOUNTS}), name
        assert not any(acc.name in old[name][3] for acc in env.engine.load_account_configs(env.config))
    assert old["admin"][2] is True
    for line in lines:
        assert len(line.split(":")) == 4  # name:verifier:scope:gen


def test_ui_users_table_is_additive(env):
    cols = {r[1] for r in env.conn.execute("PRAGMA table_info(ui_users)")}
    assert cols == {"name", "perms", "last_login_at", "last_login_ip", "updated_at", "updated_by"}
    # Older code never touches it; dropping it (as if never migrated) falls back to 2.0 rights.
    env.conn.execute("DROP TABLE ui_users")
    env.conn.commit()
    dashboard._UI_DB_READY.discard(str(dashboard.DB_PATH))
    anna = client_for(env, "anna")
    assert anna.get("/rules").status_code == 200


def test_garbled_perms_fall_back_to_defaults_not_admin():
    assert dashboard._parse_perms("{oops") == frozenset(dashboard.PERMISSIONS)
    assert dashboard._parse_perms(json.dumps({"rules": False})) == frozenset({"release", "see_messages"})
    assert dashboard._parse_perms("[]") == frozenset(dashboard.PERMISSIONS)


def test_access_summary_wording():
    s = dashboard.access_summary
    assert s(True, [], []) == "Kan se alle postkasser · Må alt – også konti, brugere og indstillinger"
    assert s(False, ["molt", "bynet"], ["release"]) == "Kan se bynet og molt · Må frigive post"
    assert s(False, [], []) == "Kan ikke se nogen postkasser endnu · Må kun se fanget spam"


def test_users_pages_are_csp_clean(env):
    admin = client_for(env, "admin")
    for url in ("/users", "/users/new", "/users/anna", "/settings"):
        html = body(admin.get(url))
        for rx, what in INLINE_PATTERNS:
            m = rx.search(html)
            assert m is None, f"{what} on {url}"
