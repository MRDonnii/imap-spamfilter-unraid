"""2.5.0 push notifications - Min konto -> 'Beskeder på denne enhed'.

Routes under /me/push/ (central policy 'login', CSRF on every POST, a
user only ever sees and changes their OWN devices), the card (CSP strict,
Danish, no endpoint in the HTML), user removal, and the client side:
sw.js 'push' / 'notificationclick' (same-origin paths only, caching
untouched) and app.js initPush (permission only from the button).
Every HTTP request goes to the fake push service.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fakes_push import FakePushService, device  # noqa: E402
from fakes_ui import TEST_PASSWORD, csrf_of, fast_hash, login, post  # noqa: E402
from fakes_ui_admin import make_admin_env  # noqa: E402

import dashboard  # noqa: E402
import push  # noqa: E402
import ui_admin  # noqa: E402
import webpush  # noqa: E402
from test_ui_core import INLINE_PATTERNS  # noqa: E402

STATIC = Path(__file__).resolve().parents[1] / "filter" / "static"
IPHONE_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
             "Version/18.1 Mobile/15E148 Safari/604.1")


@pytest.fixture
def env(tmp_path, monkeypatch):
    e = make_admin_env(tmp_path, monkeypatch)
    h = fast_hash(TEST_PASSWORD)
    (e.state / "dashboard_users").write_text(
        f"admin:{h}:admin:0\nanna:{h}:bynet:0\nbo:{h}:molt:0\n")
    with e.app.test_request_context("/"):
        dashboard.set_user_perms("bo", [], "test")
    for name in ("STATE_DIR", "CONFIG_PATH", "DB_PATH", "USERS_FILE", "AUTO_WORKER"):
        monkeypatch.setattr(push, name, getattr(push, name))
    monkeypatch.setattr(push, "AUTO_WORKER", False)
    monkeypatch.setenv("PUSH_VAPID_SUBJECT", "mailto:ole@example.com")
    push.configure_paths(e.state, e.config, db_path=e.state / "spamfilter.db")
    push.ensure_schema()
    svc = FakePushService()
    real_send = webpush.send
    monkeypatch.setattr(webpush, "send", lambda *a, **k: real_send(*a, **{**k, "session": svc}))
    e.svc = svc
    return e


def client(env, name):
    c = env.app.test_client()
    assert login(c, name, TEST_PASSWORD).status_code == 302
    return c


def body(r) -> str:
    return r.get_data().decode("utf-8", "replace")


def subscribe(env, c, dev=None, **extra):
    dev = dev or device()
    data = {"endpoint": dev.endpoint, "p256dh": dev.p256dh, "auth": dev.auth, "app": "1", **extra}
    r = post(c, "/me/push/subscribe", data, headers={"User-Agent": IPHONE_UA})
    env.svc.add(dev)
    return r, dev


def rows(env, user=None):
    sql = "SELECT * FROM push_subscriptions" + (" WHERE user=?" if user else "") + " ORDER BY id"
    return [dict(r) for r in env.conn.execute(sql, (user,) if user else ()).fetchall()]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def test_routes_need_login(env):
    c = env.app.test_client()
    r = c.get("/me/push/key", headers={"Accept": "application/json"})
    assert r.status_code == 401
    for url in ("/me/push/subscribe", "/me/push/prefs", "/me/push/test", "/me/push/unsubscribe", "/me/push/remove"):
        assert post(c, url, {}).status_code == 401, url
    assert rows(env) == []


def test_key_endpoint_returns_the_public_vapid_key(env):
    c = client(env, "anna")
    r = c.get("/me/push/key")
    data = r.get_json()
    assert r.status_code == 200 and data["ok"] is True
    assert len(webpush.b64u_decode(data["key"])) == 65 and "PRIVATE" not in body(r)
    assert c.get("/me/push/key").get_json()["key"] == data["key"]        # generated once
    key_file = env.state / "vapid_private.pem"
    assert key_file.stat().st_mode & 0o777 == 0o600
    assert r.headers["Cache-Control"] == "no-store"


def test_subscribe_lists_the_device_and_audits(env):
    c = client(env, "anna")
    r, dev = subscribe(env, c)
    assert r.status_code == 200 and r.get_json()["ok"] and r.get_json()["refresh"] is True
    [row] = rows(env, "anna")
    assert row["endpoint"] == dev.endpoint and row["user_agent_short"] == "iPhone · app på hjemmeskærmen"
    assert json.loads(row["prefs"]) == {"threat": True, "review": False, "problem": False}   # a Bruger
    html = body(c.get("/me"))
    assert "iPhone · app på hjemmeskærmen" in html and f'data-push-hash="{push.endpoint_hash(dev.endpoint)}"' in html
    assert dev.endpoint not in html and dev.auth not in html and dev.p256dh not in html
    assert [a for a in env.audit() if a["action"] == "push_subscribe"]


def test_subscribe_needs_csrf(env):
    c = client(env, "anna")
    dev = device()
    r = c.post("/me/push/subscribe", data={"endpoint": dev.endpoint, "p256dh": dev.p256dh, "auth": dev.auth},
               headers={"Accept": "application/json"})
    assert r.status_code == 400 and rows(env) == []
    r = post(c, "/me/push/subscribe", {"endpoint": dev.endpoint, "p256dh": dev.p256dh, "auth": dev.auth},
             headers={"X-CSRF-Token": "forkert"})
    assert r.status_code == 400 and rows(env) == []


@pytest.mark.parametrize("endpoint", ["https://192.168.1.10:18080/x", "https://127.0.0.1/x", "http://web.push.apple.com/x",
                                      "https://web.push.apple.com.evil.example/x"])
def test_subscribe_refuses_ssrf_endpoints(env, endpoint):
    c = client(env, "anna")
    dev = device()
    r = post(c, "/me/push/subscribe", {"endpoint": endpoint, "p256dh": dev.p256dh, "auth": dev.auth})
    assert r.status_code == 400 and not r.get_json()["ok"] and rows(env) == []


def test_prefs_only_own_device_and_bruger_never_problems(env):
    anna, admin = client(env, "anna"), client(env, "admin")
    _, dev_a = subscribe(env, anna)
    _, dev_admin = subscribe(env, admin)
    ida = rows(env, "anna")[0]["id"]
    idadmin = rows(env, "admin")[0]["id"]
    r = post(anna, "/me/push/prefs", {"id": str(ida), "threat": "1", "review": "1", "problem": "1"})
    assert r.status_code == 200 and r.get_json()["ok"]
    assert json.loads(rows(env, "anna")[0]["prefs"]) == {"threat": True, "review": True, "problem": False}
    # Someone else's device: 404 and unchanged.
    r = post(anna, "/me/push/prefs", {"id": str(idadmin)})
    assert r.status_code == 404
    assert json.loads(rows(env, "admin")[0]["prefs"])["threat"] is True
    r = post(anna, "/me/push/prefs", {"id": "abc"})
    assert r.status_code == 400
    # Only switches that exist for the role are rendered.
    html_a = body(anna.get("/me"))
    html_admin = body(admin.get("/me"))
    assert 'name="review"' in html_a and 'name="problem"' not in html_a
    assert 'name="problem"' in html_admin and "Problemer med filteret" in html_admin
    # Unchecked switch = off.
    assert post(admin, "/me/push/prefs", {"id": str(idadmin), "threat": "1"}).status_code == 200
    assert json.loads(rows(env, "admin")[0]["prefs"]) == {"threat": True, "review": False, "problem": False}


def test_a_bruger_sees_only_own_devices(env):
    anna, admin = client(env, "anna"), client(env, "admin")
    subscribe(env, admin)
    html = body(anna.get("/me"))
    assert "data-push-hash" not in html and "Dine enheder" not in html
    assert "Beskeder på denne enhed" in html


def test_send_test_to_this_device(env):
    anna = client(env, "anna")
    _, dev = subscribe(env, anna)
    _, dev2 = subscribe(env, anna)
    r = post(anna, "/me/push/test", {"endpoint": dev.endpoint})
    assert r.status_code == 200 and r.get_json()["message"] == "Testbeskeden er sendt."
    assert env.svc.payloads(dev) == [{"title": "Testbesked", "body": "Beskeder virker på denne enhed.", "url": "/me",
                                      "tag": "sf-test"}]
    assert env.svc.payloads(dev2) == []
    r = post(anna, "/me/push/test", {})                   # no endpoint: all of hers
    assert r.get_json()["message"] == "Testbeskeden er sendt til 2 enheder."
    for _ in range(3):
        post(anna, "/me/push/test", {})
    r = post(anna, "/me/push/test", {})
    assert r.status_code == 429 and "Vent" in r.get_json()["message"]
    assert [a for a in env.audit() if a["action"] == "push_test"]


def test_test_message_never_goes_to_someone_elses_device(env):
    anna, admin = client(env, "anna"), client(env, "admin")
    _, dev_admin = subscribe(env, admin)
    r = post(anna, "/me/push/test", {"endpoint": dev_admin.endpoint})
    assert r.status_code == 400 and env.svc.calls == []


def test_unsubscribe_and_remove_only_own(env):
    anna, admin = client(env, "anna"), client(env, "admin")
    _, dev_a = subscribe(env, anna)
    _, dev_admin = subscribe(env, admin)
    idadmin = rows(env, "admin")[0]["id"]
    # anna cannot remove the admin's device, by endpoint or by id.
    post(anna, "/me/push/unsubscribe", {"endpoint": dev_admin.endpoint})
    assert post(anna, "/me/push/remove", {"id": str(idadmin)}).status_code == 404
    assert len(rows(env, "admin")) == 1
    r = post(anna, "/me/push/unsubscribe", {"endpoint": dev_a.endpoint})
    assert r.status_code == 200 and rows(env, "anna") == []
    r = post(admin, "/me/push/remove", {"id": str(idadmin)})
    assert r.status_code == 200 and r.get_json()["rows"] == {f"push:{idadmin}": None}
    assert rows(env) == []
    actions = [a["action"] for a in env.audit()]
    assert "push_unsubscribe" in actions and "push_remove" in actions


def test_removing_a_user_deletes_their_devices(env):
    anna, admin = client(env, "anna"), client(env, "admin")
    subscribe(env, anna)
    subscribe(env, anna)
    subscribe(env, admin)
    r = post(admin, "/users/anna/remove", {"confirm": "anna"})
    assert r.status_code == 200 and r.get_json()["ok"]
    assert rows(env, "anna") == [] and len(rows(env, "admin")) == 1


def test_no_js_form_post_redirects_back(env):
    anna = client(env, "anna")
    _, dev = subscribe(env, anna)
    sid = rows(env, "anna")[0]["id"]
    r = anna.post("/me/push/prefs", data={"id": str(sid), "threat": "1", "csrf": csrf_of(anna)})
    assert r.status_code == 302 and r.headers["Location"].endswith("/me")


# ---------------------------------------------------------------------------
# The card
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("who", ["admin", "anna", "bo"])
def test_card_is_csp_clean_and_danish(env, who):
    c = client(env, who)
    subscribe(env, c)
    html = body(c.get("/me"))
    for rx, what in INLINE_PATTERNS:
        m = rx.search(html)
        assert m is None, f"{what}: {html[max(0, m.start() - 80):m.end() + 80]}"
    for text in ("Beskeder på denne enhed", "Slå beskeder til", "Send testbesked", "Slå fra på denne enhed",
                 "Dine enheder", "Farlige mails stoppet", "Nye mails under Tjek disse", "iOS 16.4",
                 "Føj til hjemmeskærm", "aldrig afsender eller emne", "Fjern"):
        assert text in html, text
    for state in ("insecure", "ios", "unsupported", "denied"):
        assert re.search(rf'data-push-why="{state}" hidden', html), state
    assert re.search(r"<div class=\"push-panel\" data-push-off hidden>", html)
    assert re.search(r"<div class=\"push-panel\" data-push-on hidden>", html)
    assert 'data-push-key-url="/me/push/key"' in html and 'data-push-this hidden' in html
    assert ("Problemer med filteret" in html) is (who == "admin")


def test_card_mentions_the_external_address(env):
    with env.app.test_request_context("/"):
        dashboard.settings_set("external_url", "https://spamfilter.example.org")
    html = body(client(env, "anna").get("/me"))
    assert 'href="https://spamfilter.example.org"' in html
    assert "lokale adresse" not in html                                   # family users: no LAN talk
    assert "lokale adresse" in body(client(env, "admin").get("/me"))


def test_ios_explanation_is_correct_danish_for_every_role(env):
    """2.5.0: the Bruger fallback (no external address) keeps the relative
    clause closed before the next clause ('..., du plejer at bruge, tryk')."""
    def ios_text(who):
        html = body(client(env, who).get("/me"))
        m = re.search(r'data-push-why="ios" hidden>(.*?)</div>\s*</div>', html, re.S)
        assert m, who
        return re.sub(r"<[^>]+>", "", m.group(1))

    anna = ios_text("anna")
    assert "Åbn spamfilteret i Safari fra den adresse, du plejer at bruge, tryk på Del" in anna
    assert "telefonen i Safari" not in anna
    assert "Åbn den eksterne https-adresse i Safari, tryk på Del" in ios_text("admin")
    with env.app.test_request_context("/"):
        dashboard.settings_set("external_url", "https://spamfilter.example.org")
    assert "Åbn spamfilter.example.org i Safari, tryk på Del" in ios_text("anna")


def test_preview_of_my_account_mentions_push_without_data(env):
    admin = client(env, "admin")
    subscribe(env, client(env, "anna"))
    html = body(admin.get("/users/anna/preview?p=me"))
    assert "Beskeder på telefonen" in html and "data-push-hash" not in html


def test_icons_and_audit_labels_exist():
    sprite = (STATIC / "icons.svg").read_text()
    assert 'id="i-bell"' in sprite and 'id="i-bell-off"' in sprite
    for action in ("push_subscribe", "push_unsubscribe", "push_remove", "push_test", "push_reset"):
        assert action in ui_admin.AUDIT_LABELS and "_" not in ui_admin.AUDIT_LABELS[action]


def test_push_routes_are_in_the_central_policy(env):
    for ep in ("me_push_key", "me_push_subscribe", "me_push_prefs", "me_push_test", "me_push_unsubscribe",
               "me_push_remove"):
        assert dashboard.route_policy(ep) == "login", ep
    rules = {r.endpoint: r for r in env.app.url_map.iter_rules() if r.endpoint.startswith("me_push_")}
    assert rules["me_push_key"].methods >= {"GET"} and "POST" not in rules["me_push_key"].methods
    assert all("POST" in rules[e].methods for e in rules if e != "me_push_key")


def test_admin_who_must_set_up_2fa_cannot_use_push_first(env):
    with env.app.test_request_context("/"):
        dashboard.twofa_set_required("anna", True, "admin")
    c = client(env, "anna")
    r = c.get("/me/push/key", headers={"Accept": "application/json"})
    assert r.status_code == 403 and r.get_json()["code"] == "twofa_setup_required"


# ---------------------------------------------------------------------------
# Service worker + app.js
# ---------------------------------------------------------------------------


def test_service_worker_route_has_push_handlers_and_keeps_caching(env):
    r = env.app.test_client().get("/sw.js")
    src = body(r)
    assert r.status_code == 200 and "__SF_" not in src
    # Caching logic unchanged.
    for s in ('addEventListener("install"', 'addEventListener("activate"', 'addEventListener("fetch"',
              "function isStaticAsset", 'caches.match(OFFLINE)', 'if (req.method !== "GET") return;'):
        assert s in src, s
    # Push.
    assert 'self.addEventListener("push"' in src and "self.registration.showNotification(title" in src
    assert "event.data.json()" in src and "event.waitUntil(" in src
    for key in ("body:", "tag:", "icon: ICON", "badge: ICON", "data: { url: safePath(d.url) }"):
        assert key in src, key
    assert 'self.addEventListener("notificationclick"' in src
    assert "event.notification.close()" in src and "clients.matchAll" in src and "openWindow(target)" in src
    assert "safePath(event.notification.data && event.notification.data.url)" in src
    assert "u.origin !== self.location.origin" in src
    assert "importScripts" not in src and "eval(" not in src


NODE = shutil.which("node")


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_service_worker_handlers_behave(tmp_path):
    """Run sw.js in node with a minimal service-worker stub: the payload
    becomes the notification, a click opens ONLY same-origin paths."""
    sw = (STATIC / "sw.js").read_text().replace("__SF_VERSION__", '"t"').replace(
        "__SF_ASSETS__", '["/static/app.css?v=t", "/static/icon-192.png?v=t"]')
    harness = r"""
const handlers = {};
const shown = [];
const opened = [];
const self = {
  location: { origin: "https://spamfilter.example.org" },
  addEventListener: (n, f) => { handlers[n] = f; },
  registration: { showNotification: (t, o) => { shown.push([t, o]); return Promise.resolve(); } },
  clients: { matchAll: () => Promise.resolve([]), openWindow: (u) => { opened.push(u); return Promise.resolve(null); } },
  skipWaiting: () => Promise.resolve(),
};
global.self = self;
global.caches = {};
SWSRC
function fire(name, ev) { const waits = []; ev.waitUntil = (p) => waits.push(p); handlers[name](ev); return Promise.all(waits); }
(async () => {
  await fire("push", { data: { json: () => ({ title: "2 farlige mails stoppet", body: "I Inge", url: "/spam?account=molt-inge", tag: "sf-threat" }) } });
  await fire("push", { data: { json: () => { throw new Error("bad"); } } });
  await fire("push", { data: { json: () => ({ title: 5, url: "https://evil.example/x", tag: "<b>" }) } });
  const urls = ["/spam?account=molt-inge", "https://evil.example/", "//evil.example/x", "/\\evil.example",
                "javascript:alert(1)", "/\t/evil.example", null, "/me#x"];
  for (const u of urls) {
    await fire("notificationclick", { notification: { close: () => {}, data: { url: u } } });
  }
  console.log(JSON.stringify({ shown, opened }));
})();
""".replace("SWSRC", sw)
    script = tmp_path / "sw-test.js"
    script.write_text(harness)
    out = subprocess.run([NODE, str(script)], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    data = json.loads(out.stdout)
    (t1, o1), (t2, o2), (t3, o3) = data["shown"]
    assert t1 == "2 farlige mails stoppet" and o1["body"] == "I Inge" and o1["tag"] == "sf-threat"
    assert o1["data"]["url"] == "/spam?account=molt-inge" and o1["icon"] == "/static/icon-192.png?v=t"
    assert t2 == "Spamfilter" and o2["data"]["url"] == "/"              # unreadable payload: still a notification
    assert t3 == "Spamfilter" and o3["data"]["url"] == "/" and o3["tag"] == "sf"
    base = "https://spamfilter.example.org"
    assert data["opened"] == [base + "/spam?account=molt-inge", base + "/", base + "/", base + "/", base + "/",
                              base + "/", base + "/", base + "/me#x"]


def test_app_js_push_flow_structure():
    js = (STATIC / "app.js").read_text()
    start = js.index("function initPush()")
    end = js.index("function initPwa()")
    code = js[start:end]
    assert "initPush();" in js[js.index('document.addEventListener("DOMContentLoaded"'):]
    # Permission ONLY from the button (user gesture), and before any await.
    click = code[code.index("[data-push-enable]"):]
    assert click.index("Notification.requestPermission()") < click.index("fetch(")
    assert "requestPermission" not in js[:start] + js[end:]      # never on page load
    assert "userVisibleOnly: true" in code and "applicationServerKey: keyBytes" in code
    assert 'postForm("/me/push/subscribe"' in code and 'postForm("/me/push/unsubscribe"' in code
    assert '"X-CSRF-Token": csrf()' in js[js.index("function postForm"):start]
    support = js[js.index("function pushSupport()"):start]
    assert "window.isSecureContext" in support and '"PushManager" in window' in support
    assert 'platform() === "ios" && !standalone()' in support and 'Notification.permission === "denied"' in support
    assert "innerHTML" not in code and ".style." not in code and "eval(" not in code
    assert "old.unsubscribe()" in code          # a rotated VAPID key re-subscribes cleanly


def test_app_css_has_push_rules():
    css = (STATIC / "app.css").read_text()
    for sel in (".push-devices", ".push-device", ".push-prefs", "@media (max-width: 420px)"):
        assert sel in css
