"""UI-CORE: dashboard.py security/auth/helpers and the ui_kit contract."""

from __future__ import annotations

import inspect
import json
import re
import time

import pytest

from fakes_ui import TEST_PASSWORD, csrf_of, login, make_env, post

import dashboard  # noqa: E402  (fakes_ui puts filter/ on sys.path)
import ui_kit as kit  # noqa: E402

CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
       "manifest-src 'self'; worker-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


@pytest.fixture
def env(tmp_path, monkeypatch):
    return make_env(tmp_path, monkeypatch)


@pytest.fixture
def client(env):
    return env.app.test_client()


@pytest.fixture
def admin(client):
    assert login(client).status_code == 302
    return client


# --------------------------------------------------------------------- health


def test_healthz_needs_no_auth(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.get_json() == {"ok": True, "version": "2.19.3"}


def test_api_health_only_states(env, client):
    conn = env.conn
    conn.execute("INSERT INTO account_status(account, updated_at, state, detail, last_error) "
                 "VALUES('bynet', 1, 'idle', 'ole@bynet.example forbundet', 'secret error text')")
    conn.execute("INSERT INTO account_status(account, updated_at, state) VALUES('molt', 1, 'auth_failed')")
    conn.commit()
    r = client.get("/api/health")
    data = r.get_json()
    assert r.status_code == 200
    assert set(data) == {"ok", "version", "accounts"}
    assert data["accounts"] == {"bynet": "idle", "molt": "auth_failed"}
    assert data["ok"] is True
    assert "@" not in r.get_data(as_text=True) and "secret" not in r.get_data(as_text=True)
    conn.execute("INSERT INTO account_status(account, updated_at, state) VALUES('*', 1, 'config_error')")
    conn.commit()
    assert client.get("/api/health").get_json()["ok"] is False


# --------------------------------------------------------------------- headers / cookies


def test_security_headers_and_cookie(client):
    r = client.get("/login")
    assert r.headers["Content-Security-Policy"] == CSP
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert r.headers["Cache-Control"] == "no-store"
    r = login(client)
    cookie = r.headers.get("Set-Cookie", "")
    assert cookie.startswith("spamfilter_session=")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    assert "Secure" not in cookie  # only with DASHBOARD_COOKIE_SECURE=1
    page = client.get("/")
    assert page.status_code == 200
    assert page.headers["Cache-Control"] == "no-store"


def test_static_assets_cache_busted(admin):
    html = admin.get("/").get_data(as_text=True)
    m = re.search(r'href="(/static/app\.css\?v=[^"]+)"', html)
    assert m and "2.19.3-" in m.group(1)
    assert re.search(r'<script src="/static/app\.js\?v=[^"]+"></script>', html)
    r = admin.get(m.group(1))
    assert r.status_code == 200
    assert "immutable" in r.headers["Cache-Control"]
    for name in ("app.js", "icons.svg", "logo.png"):
        assert admin.get(f"/static/{name}").status_code == 200
    assert admin.get("/favicon.png").status_code == 200


def test_logo_is_small():
    assert (dashboard.STATIC_DIR / "logo.png").stat().st_size < 40_000


def test_icon_sprite_covers_every_icon_used():
    sprite = (dashboard.STATIC_DIR / "icons.svg").read_text()
    have = set(re.findall(r'id="i-([a-z0-9-]+)"', sprite))
    assert len(have) >= 30
    src = "".join(p.read_text() for p in dashboard.STATIC_DIR.parent.glob("ui_*.py"))
    src += (dashboard.STATIC_DIR.parent / "dashboard.py").read_text()
    used = set(re.findall(r'icon\(\s*"([a-z0-9-]+)"', src)) | set(re.findall(r'icon="([a-z0-9-]+)"', src))
    used |= set(re.findall(r'"icon": "([a-z0-9-]+)"', src))
    assert used - have == set()


# --------------------------------------------------------------------- login / sessions


def test_redirects_to_login(client):
    r = client.get("/spam?q=x")
    assert r.status_code == 302
    assert r.headers["Location"].startswith("/login?next=/spam")
    r = client.get("/api/status", headers={"Accept": "application/json"})
    assert r.status_code == 401 and r.get_json()["ok"] is False


def test_login_success_and_audit(env, client):
    r = login(client)
    assert r.status_code == 302 and r.headers["Location"] == "/"
    assert client.get("/").status_code == 200
    recs = env.audit()
    assert recs[-1]["action"] == "login" and recs[-1]["result"] == "ok" and recs[-1]["actor"] == "admin"


def test_login_next_is_same_site_only(client):
    client.get("/login")
    r = client.post("/login?next=//evil.example/x",
                    data={"username": "admin", "password": TEST_PASSWORD, "csrf": csrf_of(client)})
    assert r.headers["Location"] == "/"


@pytest.mark.parametrize("target", ["/\t/evil.example", "/\n/evil.example", "/ /evil.example",
                                    "/\x7f/evil.example", "https://evil.example", "/x\\evil"])
def test_safe_next_rejects_control_chars_and_absolute(target):
    import dashboard

    assert dashboard.safe_next(target) == "/"
    assert dashboard.safe_next("/spam?view=all") == "/spam?view=all"


def test_login_next_with_encoded_tab_is_not_an_open_redirect(client):
    client.get("/login")
    r = client.post("/login?next=/%09/evil.example/relogin",
                    data={"username": "admin", "password": TEST_PASSWORD, "csrf": csrf_of(client)})
    assert r.status_code == 302 and r.headers["Location"] == "/"
    r = client.get("/login?next=/%09/evil.example")
    assert "evil.example" not in r.headers.get("Location", "")


def test_login_failure_is_throttled(env, client):
    for _ in range(5):
        r = login(client, "admin", "forkert")
        assert r.status_code == 401
        assert "Forkert brugernavn eller adgangskode" in r.get_data(as_text=True)
    r = login(client, "admin", TEST_PASSWORD)  # correct password, but locked now
    assert r.status_code == 429
    assert "For mange forsøg" in r.get_data(as_text=True)
    results = [x["result"] for x in env.audit() if x["action"] == "login"]
    assert results.count("failed") == 5 and results[-1] == "locked"


def test_login_requires_csrf(client):
    client.get("/login")
    r = client.post("/login", data={"username": "admin", "password": TEST_PASSWORD})
    assert r.status_code == 400
    assert "udløbet" in r.get_data(as_text=True)


def test_post_without_csrf_rejected(admin):
    r = admin.post("/logout")
    assert r.status_code == 400
    assert "Sikkerhedstokenet" in r.get_data(as_text=True)
    r = admin.post("/rules/add", data={"kind": "allow", "pattern": "a@b.dk"},
                   headers={"Accept": "application/json", "X-Requested-With": "fetch"})
    assert r.status_code == 400 and r.get_json()["ok"] is False


def test_cross_origin_post_rejected(admin):
    r = post(admin, "/rules/add", {"kind": "allow", "pattern": "a@b.dk", "account": "*"},
             headers={"Origin": "http://evil.example"})
    assert r.status_code == 400
    r = post(admin, "/rules/add", {"kind": "allow", "pattern": "a@b.dk", "account": "*"},
             headers={"Origin": "http://localhost"})
    assert r.status_code == 200


def test_logout_is_post_only(admin):
    assert admin.get("/logout").status_code == 302
    assert admin.get("/").status_code == 200  # GET did not log out
    r = admin.post("/logout", data={"csrf": csrf_of(admin)})
    assert r.status_code == 302 and r.headers["Location"] == "/login"
    assert admin.get("/").status_code == 302


def test_session_generation_bump_logs_out(env, admin):
    assert admin.get("/").status_code == 200
    dashboard.bump_generation("admin")
    assert admin.get("/").status_code == 302
    line = (env.state / "dashboard_users").read_text().splitlines()[0]
    assert line.endswith(":admin:1")


def test_idle_and_absolute_timeouts(admin):
    with admin.session_transaction() as s:
        s["ts"] = int(time.time()) - dashboard.SESSION_IDLE - 5
    assert admin.get("/").status_code == 302
    login(admin)
    with admin.session_transaction() as s:
        s["t0"] = int(time.time()) - dashboard.SESSION_LIFETIME - 5
    assert admin.get("/").status_code == 302


def test_removed_user_is_logged_out(env, admin):
    (env.state / "dashboard_users").write_text("")
    assert admin.get("/").status_code == 302


def test_user_file_format_roundtrip():
    u = dashboard.parse_user_line("anna:pbkdf2$1$aa$bb:bynet|molt:3")
    assert u.name == "anna" and not u.admin and u.accounts == frozenset({"bynet", "molt"}) and u.gen == 3
    assert dashboard.format_user_line(u) == "anna:pbkdf2$1$aa$bb:bynet|molt:3"
    legacy = dashboard.parse_user_line("bo:pbkdf2$1$aa$bb")  # 1.x line: admin, gen 0
    assert legacy.admin and legacy.gen == 0
    assert dashboard.verify_password(dashboard.hash_password("x" * 12), "x" * 12)


# --------------------------------------------------------------------- scopes / helpers


def test_admin_required_rejects_scoped_user(env, monkeypatch):
    view = dashboard.admin_required(lambda: "ok")
    with env.app.test_request_context("/x"):
        monkeypatch.setattr(dashboard, "current_user",
                            lambda: {"name": "sofie", "is_admin": False, "accounts": frozenset({"sofie"})})
        with pytest.raises(Exception) as ei:
            view()
        assert getattr(ei.value, "code", None) == 403
    with env.app.test_request_context("/x"):
        monkeypatch.setattr(dashboard, "current_user",
                            lambda: {"name": "admin", "is_admin": True, "accounts": None})
        assert view() == "ok"


def test_scope_sql_and_visible_accounts(env, client):
    login(client, "sofie")
    with client.application.test_request_context("/"):
        from flask import session
        with client.session_transaction() as s:
            session.update(s)
        assert dashboard.current_user()["accounts"] == frozenset({"sofie"})
        assert dashboard.scope_sql() == (" AND account IN (?)", ["sofie"])
        assert [a.name for a in dashboard.visible_accounts()] == ["sofie"]
        assert dashboard.can_access("sofie") and not dashboard.can_access("bynet")


def test_json_helpers(env):
    with env.app.test_request_context("/"):
        r = dashboard.json_ok("Gemt", extra=1)
        assert r.get_json() == {"ok": True, "message": "Gemt", "results": [], "reload": False, "extra": 1}
        resp, status = dashboard.json_err("Nej", 409)
        assert status == 409 and resp.get_json()["ok"] is False


def test_effective_accounts_reports_config_error(env, admin):
    env.engine.config_error = "accounts[0]: missing user"
    html = admin.get("/").get_data(as_text=True)
    assert "Konfigurationen kan ikke indlæses" in html
    assert "missing user" in html


# --------------------------------------------------------------------- config writes + A6


def test_save_config_writes_atomically_and_audits(env):
    with env.app.test_request_context("/"):
        dashboard.save_config(lambda raw: raw["accounts"].append({"name": "ny", "user": "ny@x.dk"}),
                              "admin", "account_add", account="ny")
    text = env.config.read_text()
    assert "ny@x.dk" in text
    assert (env.config.stat().st_mode & 0o777) == 0o600
    assert (env.state / "reload_requested").exists()
    rec = env.audit()[-1]
    assert rec["action"] == "account_add" and rec["result"] == "ok"
    # The UI's own write must not be reported as an external change.
    assert dashboard.check_external_config_change() is False


def test_save_config_rejects_invalid(env):
    before = env.config.read_text()

    def bad_loader(path=None):
        raise ValueError("threshold must be a number")

    env.engine.load_account_configs = bad_loader
    with env.app.test_request_context("/"):
        with pytest.raises(ValueError):
            dashboard.save_config(lambda raw: raw.update(defaults={"threshold": "x"}), "admin", "settings")
    assert env.config.read_text() == before
    assert env.audit()[-1]["result"] == "rejected"


def test_external_config_change_is_audited(env):
    assert dashboard.check_external_config_change() is False  # first sight: remember hash
    assert dashboard.check_external_config_change() is False
    env.config.write_text("defaults: {threshold: 9}\naccounts: []\n")
    assert dashboard.check_external_config_change() is True
    rec = env.audit()[-1]
    assert rec["action"] == "config_changed_externally" and rec["actor"] == "system"
    assert dashboard.check_external_config_change() is False


# --------------------------------------------------------------------- error pages + CSP-safe markup


def test_danish_error_pages(client, admin):
    r = admin.get("/findes-ikke")
    html = r.get_data(as_text=True)
    assert r.status_code == 404
    assert "Siden findes ikke" in html and 'class="sidebar"' in html
    r = admin.get("/messages/bynet/@@@")
    assert r.status_code == 404
    r = admin.delete("/healthz")
    assert r.status_code in (400, 405)


def test_error_page_logged_out_has_no_layout(client):
    r = client.get("/findes-ikke")
    html = r.get_data(as_text=True)
    assert r.status_code == 404 and "Siden findes ikke" in html and 'class="sidebar"' not in html


INLINE_PATTERNS = [
    (re.compile(r'\sstyle\s*='), "inline style attribute"),
    (re.compile(r"<style\b"), "<style> block"),
    (re.compile(r"<script(?![^>]*\bsrc=)[^>]*>"), "inline script"),
    (re.compile(r'\son[a-z]+\s*=\s*"', re.I), "inline event handler"),
    (re.compile(r'(src|href)="(https?:)?//'), "external resource"),
]


@pytest.mark.parametrize("path", ["/", "/?period=7d", "/spam", "/messages", "/rules", "/login", "/nope"])
def test_pages_are_csp_clean(env, admin, path):
    from fakes_ui import insert_message
    insert_message(env.conn, "bynet", "<a@x>", our_action="moved_to_junk", our_score=12.0,
                   current_folder="Spamfilter", subject="Tilbud",
                   symbols=[{"n": "BAYES_SPAM", "s": 5.1, "o": ["99%"]}])
    env.conn.commit()
    html = admin.get(path).get_data(as_text=True)
    for rx, what in INLINE_PATTERNS:
        m = rx.search(html)
        assert m is None, f"{what} on {path}: {html[max(0, m.start() - 80):m.end() + 80]}"


# --------------------------------------------------------------------- ui_kit contract


KIT_API = {
    "render_page": ["title", "body_html", "active", "subtitle", "actions_html", "breadcrumbs"],
    "h": ["text"], "icon": ["name", "cls"],
    "card": ["body", "title", "subtitle", "actions", "cls"],
    "kpi": ["label", "value", "sub", "trend", "tone"],
    "badge": ["text", "tone"], "chip": ["text", "tone"], "status_dot": ["state"],
    "score_badge": ["score", "threshold"],
    "button": ["label", "href", "kind", "icon", "attrs"],
    "table": ["headers", "rows", "empty"],
    "empty_state": ["title", "text", "icon", "action_html"],
    "form_field": ["label", "input_html", "hint", "error"],
    "input_": ["name", "value", "type", "attrs"],
    "select": ["name", "options", "selected", "attrs"],
    "switch": ["name", "checked", "label"], "segmented": ["name", "options", "selected"],
    "progress": ["value", "maximum", "tone", "label"], "ring": ["value", "maximum", "label"],
    "modal": ["id", "title", "body", "actions"], "bar_chart": ["series", "labels"],
    "fmt_ts": ["ts"], "ago": ["ts"], "fmt_score": ["s"], "mode_label": ["mode"],
    "state_label": ["state"], "explain_symbol": ["name"],
}
DASH_API = ["app", "init_ui_db", "db", "current_user", "login_required", "admin_required",
            "csrf_token", "check_csrf", "audit", "json_ok", "json_err", "flash", "wants_json",
            "effective_accounts", "save_config", "services"]


def test_kit_and_dashboard_api_exist():
    for name, params in KIT_API.items():
        fn = getattr(kit, name)
        sig = inspect.signature(fn).parameters
        for p in params:
            assert p in sig, f"ui_kit.{name} lacks parameter {p}"
    assert kit.MODE_LABELS == {"shadow": "Overvåg", "flag": "Markér", "move": "Filtrér"}
    for name in DASH_API:
        assert hasattr(dashboard, name), name
    sig = inspect.signature(dashboard.audit).parameters
    assert list(sig)[:5] == ["action", "account", "result", "detail", "message_id"]


def test_kit_formatting():
    assert kit.h('<b a="1">') == "&lt;b a=&#34;1&#34;&gt;"
    assert kit.fmt_score(8.25) == "8,2" or kit.fmt_score(8.25) == "8,3"
    assert kit.fmt_score(-1.5) == "−1,5"
    assert kit.fmt_score(None) == "–"
    assert kit.fmt_int(12345) == "12.345"
    assert kit.ago(int(time.time())) == "lige nu"
    assert kit.ago(int(time.time()) - 7200) == "for 2 t. siden"
    assert kit.ago(None) == "aldrig"
    assert kit.mode_label("move") == "Filtrér" and kit.state_label("auth_failed") == "Login fejler"
    assert kit.sensitivity_label(5.5) == "Streng" and kit.sensitivity_label(8) == "Normal"
    assert kit.sensitivity_label(10) == "Lempelig"
    mid = "<CAF+x/y=z@mail.example.com>"
    assert kit.msgid_from_token(kit.token_for(mid)) == mid
    assert kit.msgid_from_token("../etc") is None


def test_symbol_texts():
    assert len(kit.SYMBOL_TEXT) >= 60
    assert kit.explain_symbol("BAYES_SPAM") != kit.explain_symbol("UNKNOWN_THING_X")
    assert "TH_PROVIDER_SPAM" in kit.SYMBOL_TEXT
    assert kit.explain_symbol("RBL_SOMETHING_NEW")  # prefix fallback
    assert kit.explain_symbol("ZZZ") == "Teknisk kontrol i spam-motoren (ingen nærmere forklaring)"


def test_kit_components_render_safely():
    html = kit.score_badge(9.5, 8)
    assert "tone-bad" in html and "9,5" in html
    assert "tone-warn" in kit.score_badge(6, 8) and "tone-ok" in kit.score_badge(-2, 8)
    chart = kit.bar_chart([{"label": "Legitim", "values": [1, 2], "tone": "brand"},
                           {"label": "Spam", "values": [0, 3], "tone": "bad"}], ["1/10", "2/10"])
    assert "<svg" in chart and "style=" not in chart
    t = kit.table(["A", ("B", "num")], [["<x>", "1"]])
    assert 'data-label="A"' in t and "<x>" in t  # cells are caller-escaped HTML
    assert "Intet" in kit.table(["A"], [], empty="Intet her")
    assert 'class="progress-fill p-50"' in kit.progress(5, 10)
    assert "<dialog" in kit.modal("m1", "Titel", "<p>x</p>", kit.button("OK"))
    assert 'role="switch"' in kit.switch("x", True, "Aktiv")
    assert "checked" in kit.segmented("mode", [("shadow", "Overvåg"), ("move", "Filtrér")], "move")
    assert "<script" not in kit.h("<script>")


def test_render_page_layout(env, admin):
    html = admin.get("/").get_data(as_text=True)
    assert '<html lang="da"' in html
    assert 'class="sidebar"' in html and 'class="tabbar"' in html
    assert "Konti" in html  # admin nav
    assert 'name="csrf-token"' in html


def test_scoped_user_has_no_admin_nav(env, client):
    login(client, "sofie")
    html = client.get("/").get_data(as_text=True)
    assert 'href="/accounts"' not in html and 'href="/settings"' not in html
    assert "<small>Bruger</small>" in html


def test_flash_shows_on_next_page(env, admin):
    r = admin.post("/rules/add", data={"kind": "allow", "pattern": "ven@example.dk", "account": "*",
                                       "csrf": csrf_of(admin)})
    assert r.status_code == 302
    html = admin.get(r.headers["Location"]).get_data(as_text=True)
    assert "ven@example.dk er nu tilladt" in html and "data-flash" in html


def test_register_pages_tolerates_missing_ui_admin(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "ui_admin":
            err = ModuleNotFoundError("No module named 'ui_admin'")
            err.name = "ui_admin"
            raise err
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    dashboard.register_pages()  # must not raise


def test_audit_file_is_private_jsonl(env):
    with env.app.test_request_context("/"):
        dashboard.audit("test", "bynet", detail="x", message_id="<m@x>", actor="admin")
    p = env.state / "admin-audit.jsonl"
    assert (p.stat().st_mode & 0o777) == 0o600
    rec = json.loads(p.read_text().splitlines()[-1])
    assert rec["action"] == "test" and rec["message_id"] == "<m@x>" and rec["actor"] == "admin"


def test_rules_seen_in_live_mail_have_danish_texts():
    """Rules that showed up in the owner's mail (2026-10-22) must never fall
    back to the generic text."""
    seen = ("R_SUSPICIOUS_IMAGES", "MV_CASE", "BAD_REP_POLICIES", "VIOLATED_DIRECT_SPF", "SPAM_FLAG",
            "SUSPICIOUS_URL_IN_SUSPICIOUS_MESSAGE", "CTYPE_MIXED_BOGUS", "HIDDEN_TEXT", "EXT_CSS",
            "FAKE_REPLY", "PHISH_EMOTION", "URL_MULTIPLE_AT_SIGNS", "ABUSE_SURBL", "DWL_DNSWL_LOW",
            "PDF_JAVASCRIPT", "OOXML_REMOTE_TEMPLATE", "HAS_X_SOURCE", "XLSX_SUSPICIOUS")
    generic = kit.explain_symbol("ZZZ")
    for name in seen:
        text = kit.explain_symbol(name)
        assert text != generic and name not in text, name


def test_pull_to_refresh_only_in_the_installed_app():
    """Owner 2026-10-23: 'træk ned for at opdatere' in the home-screen app.
    Only in standalone mode, passive touch listeners, CSP-safe styling."""
    import pathlib
    static = pathlib.Path(__file__).resolve().parent.parent / "filter" / "static"
    js = (static / "app.js").read_text()
    css = (static / "app.css").read_text()
    body = js.split("function initPullToRefresh()", 1)[1].split("\n  }\n", 1)[0]
    assert "if (!standalone()" in body and "window.scrollY > 0" in body
    assert body.count("{ passive: true }") == 4 and "preventDefault" not in body
    assert "location.reload()" in body and 'dialog[open]' in body
    assert "initPullToRefresh();" in js.split('document.addEventListener("DOMContentLoaded"', 1)[1]
    assert ".ptr {" in css and "var(--ptr-y" in css and "prefers-reduced-motion" in css
    assert "setAttribute(\"style\"" not in body and ".style.cssText" not in body


def test_sidebar_can_fold(env, admin):
    """2.8.4: the sidebar has a fold button; links keep a title (tooltip in the icon rail)."""
    html = admin.get("/").get_data(as_text=True)
    assert 'data-nav-toggle' in html and 'aria-label="Klap menuen sammen"' in html
    assert 'class="nav-link is-active" href="/" title="Oversigt"' in html


def _sidebar_of(html: str) -> str:
    return html.split('<aside class="sidebar"', 1)[1].split("</aside>", 1)[0]


def test_sidebar_collapse_toggle_markup(env, admin):
    """Shared rule 2026-11-21 (sammenklappelig menu): the last row of the side
    menu is a chevron button with Danish text, aria-expanded/-controls and a
    tooltip; it controls the menu (#sidebar-nav)."""
    side = _sidebar_of(admin.get("/").get_data(as_text=True))
    foot = side.split('<div class="sidebar-foot">', 1)[1]
    btn = re.search(r"<button[^>]*data-nav-toggle[^>]*>.*?</button>", foot, re.S)
    assert btn, "fold button missing in the sidebar foot"
    b = btn.group(0)
    assert 'type="button"' in b and 'class="nav-toggle"' in b
    assert 'aria-expanded="true"' in b and 'aria-controls="sidebar-nav"' in b
    assert 'aria-label="Klap menuen sammen"' in b and 'title="Klap menuen sammen (Ctrl+B)"' in b
    assert "chevron-left" in b
    assert '<span class="nav-toggle-text">Klap menuen sammen</span>' in b
    assert foot.endswith(b + "</div>")  # the very last thing in the sidebar
    assert '<nav class="nav" id="sidebar-nav" aria-label="Hovedmenu">' in side
    # The logo keeps a name when only the icon shows.
    assert '<a class="brand" href="/" aria-label="Spamfilter" title="Spamfilter ' in side
    assert '<small class="sidebar-version">Version ' in side.split('<div class="sidebar-head">', 1)[1]


def test_sidebar_links_have_tooltip_and_aria_label(env, admin, monkeypatch):
    """Icon rail: every menu item has title + aria-label; a count also gets a
    short form for the small number on the icon (at most "99+")."""
    monkeypatch.setattr(dashboard, "nav_counts", lambda: {"spam": 1234, "undo": 7})
    side = _sidebar_of(admin.get("/").get_data(as_text=True))
    links = re.findall(r'<a class="nav-link[^"]*"[^>]*>', side)
    assert len(links) >= 10
    for a in links:
        title = re.search(r'title="([^"]+)"', a).group(1)
        assert re.search(r'aria-label="' + re.escape(title) + r'( \([0-9.]+\))?"', a), a
    assert 'title="Oversigt" aria-label="Oversigt" aria-current="page"' in side
    assert 'aria-label="Fanget spam (1.234)"' in side
    assert '<span class="nav-count" data-mini="99+">1.234</span>' in side
    assert '<span class="nav-count" data-mini="7">7</span>' in side
    assert kit._mini_count(99) == "99" and kit._mini_count(100) == "99+" and kit._mini_count(None) == ""


def test_sidebar_collapse_simple_menu():
    """A Bruger's simple menu has the same menu id and labelled links."""
    nav = kit._nav("overview", False, {"spam": 3}, {"name": "u", "is_admin": False, "accounts": frozenset()})
    assert '<nav class="nav nav-simple" id="sidebar-nav"' in nav
    links = re.findall(r'<a class="nav-link[^>]*>', nav)
    assert links and all("aria-label=" in a and "title=" in a for a in links)


def test_sidebar_collapse_css_and_js_hooks():
    """CSS: 64 px rail under html.nav-mini on desktop only, 150-200 ms width
    transition, none with reduced motion. JS: shared localStorage key,
    applied before paint, Ctrl/Cmd+B outside text fields."""
    import pathlib
    static = pathlib.Path(__file__).resolve().parent.parent / "filter" / "static"
    css = (static / "app.css").read_text()
    js = (static / "app.js").read_text()
    rail = css.split("/* 2.8.1: the side menu folded", 1)[1].split("@media (max-width: 759px) { .nav-toggle", 1)[0]
    assert "@media (min-width: 760px)" in rail and ".nav-mini { --sidebar-w: 64px; }" in rail
    assert "transition: width .18s" in rail and "transition: padding-left .18s" in rail
    assert "prefers-reduced-motion: reduce" in rail and "transition: none" in rail
    for hook in (".nav-mini .nav-label", ".nav-mini .brand-text", ".nav-mini .nav-toggle-text",
                 ".nav-mini .nav-toggle .icon { transform: rotate(180deg); }", "content: attr(data-mini)"):
        assert hook in rail, hook
    assert "@media (max-width: 759px) { .nav-toggle { display: none; } }" in css  # phone unchanged
    # Before paint: the class is set at the top level of app.js (blocking script in <head>).
    pre = js.split("function initNavToggle()", 1)[0]
    assert 'NAV_KEY = "spamfilter.nav.collapsed"' in pre and 'root.classList.add("nav-mini")' in pre
    body = js.split("function initNavToggle()", 1)[1].split("\n  }\n", 1)[0]
    assert '"Fold menuen ud" : "Klap menuen sammen"' in body
    assert "aria-expanded" in body and "localStorage.setItem(NAV_KEY" in body
    assert "e.ctrlKey || e.metaKey" in body and 'e.key !== "b"' in body
    assert "INPUT|TEXTAREA|SELECT" in body and "isContentEditable" in body
    assert "initNavToggle();" in js.split('document.addEventListener("DOMContentLoaded"', 1)[1]


def test_head_loads_app_js_blocking(env, admin):
    """No flash of the wide menu: app.js (which sets html.nav-mini) is a plain
    blocking script in <head>, and the page has no inline script (CSP script-src 'self')."""
    html = admin.get("/").get_data(as_text=True)
    head = html.split("</head>", 1)[0]
    tag = re.search(r'<script src="[^"]*app\.js[^"]*"></script>', head)
    assert tag and "defer" not in tag.group(0) and "async" not in tag.group(0)
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html)


def test_fleetdeck_shell_and_look_choices(env, admin):
    """2.10 (Fleetdeck-design): top bar with search, both menu placements in
    the page (CSS picks one), and Udseende (style, theme, menu) on Min konto."""
    html = admin.get("/").get_data(as_text=True)
    assert 'data-skin="command" data-nav="side"' in html  # default = forslag A
    assert '<form class="fd-search" id="fd-search" role="search" method="get" action="/find">' in html
    assert '<nav class="topnav"' in html and "Konti og adgang" in html.split('<nav class="topnav"', 1)[1].split("</nav>", 1)[0]
    for attr in ('data-skin-set="command"', 'data-skin-set="aurora"', 'data-navpos-set="top"', 'data-theme-set="system"'):
        assert attr in html
    me = admin.get("/me").get_data(as_text=True)
    assert 'id="udseende"' in me and 'data-navpos-set="side"' in me
    assert "style=" not in html.split("<body", 1)[1]  # CSP: no inline styles


def test_search_in_top_bar_finds_every_menu_page(env, admin):
    """2.10.x: the search field also shows with the menu at the top (Fleetdeck),
    finds every page in the menu, and the phone gets a search button."""
    import pathlib

    ui_kit = kit
    static = pathlib.Path(__file__).resolve().parent.parent / "filter" / "static"
    html = admin.get("/").get_data(as_text=True)
    form = html.split('<form class="fd-search"', 1)[1].split("</form>", 1)[0]
    hrefs = set(re.findall(r'<a class="menu-item" role="option" href="([^"]+)"', form))
    assert {href for _k, href, _l, _i in ui_kit.nav_admin_items()} <= hrefs
    assert "/me" in hrefs and "Find mails med" in form and 'aria-controls="fd-search-list"' in form
    assert 'class="look-btn topbar-search-btn" href="/find"' in html and "data-search-open" in html
    css = (static / "app.css").read_text(encoding="utf-8")
    assert '\n[data-nav="top"] .fd-search { display: none; }' not in css
    assert '[data-nav="top"] .fd-search { flex: 0 1 300px;' in css
    js = (static / "app.js").read_text(encoding="utf-8")
    assert "function initSearch()" in js and "initSearch();" in js.split('document.addEventListener("DOMContentLoaded"', 1)[1]


def test_search_in_top_bar_only_lists_a_users_own_pages():
    """A Bruger only finds the pages in their own (simple) menu."""
    user = {"name": "sofie", "is_admin": False, "perms": frozenset({"release"})}
    out = kit._search_pages(False, user)
    hrefs = set(re.findall(r'role="option" href="([^"]+)"', out))
    assert hrefs == {href for _k, href, _l, _i in kit.user_nav(user)} | {"/me"}
    assert "/users" not in hrefs and "/settings" not in hrefs
    # every admin page has words to search on, and they are escaped attributes
    assert all(k in kit.SEARCH_WORDS for k, *_ in kit.nav_admin_items())
    assert 'data-search-words="' in kit._search_pages(True, {"name": "admin", "is_admin": True})