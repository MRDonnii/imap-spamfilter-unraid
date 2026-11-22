"""2.5.0: swipe on mail rows (Fanget spam, Tjek disse, Beskeder).

Right = Frigiv, left = Det er spam. The server renders, per row, only the
swipes the current user may do (data-swipe-right / data-swipe-left) and
the form to post (form[data-swipe-form], the button's own form or a hidden
one with the same fields + CSRF); app.js never decides a permission.
Covers the rendered hooks per permission (admin, Bruger with/without
release, B16 threat gate), the posted actions (Fortryd reused), the JS/CSS
structure (passive listeners, direction lock, threshold, no inline style)
and a headless Chrome run with real touch events (skipped without
playwright/Chrome).
"""

from __future__ import annotations

import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

from fakes_ui import TEST_PASSWORD, csrf_of, fast_hash, insert_message, login, post, set_status
from fakes_ui_admin import make_admin_env

import dashboard  # noqa: E402
import ui_admin  # noqa: E402,F401 - registers the admin routes at collection time
import ui_kit as kit  # noqa: E402
import ui_mail  # noqa: E402
from test_ui_core import INLINE_PATTERNS  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
APP_JS = (ROOT / "filter" / "static" / "app.js").read_text(encoding="utf-8")
APP_CSS = (ROOT / "filter" / "static" / "app.css").read_text(encoding="utf-8")
PW = TEST_PASSWORD
KC = [{"n": "TH_KNOWN_CONTACT", "s": -2.0, "o": ["k…@kunde.example", "sendt=3"]}]


@pytest.fixture
def env(tmp_path, monkeypatch):
    e = make_admin_env(tmp_path, monkeypatch)
    hp = fast_hash(PW)
    (e.state / "dashboard_users").write_text("\n".join([
        f"admin:{hp}:admin:0",
        f"anna:{hp}:bynet:0",     # Bruger, bynet, all permissions
        f"bo:{hp}:bynet:0",       # Bruger, bynet, no permissions
        f"dora:{hp}:bynet:0",     # Bruger, bynet, release only (no rules)
    ]) + "\n")
    with e.app.test_request_context("/"):
        dashboard.set_user_perms("bo", [], "test")
        dashboard.set_user_perms("dora", ["release"], "test")
    c = e.conn
    for acc in ("bynet", "molt", "sofie"):
        set_status(c, acc, "idle", junk_exists=1)
    junk = {"our_action": "moved_to_junk", "current_folder": "Spamfilter", "our_score": 14.0}
    insert_message(c, "bynet", "plain1@x.example", sender="spam@lotto.example", subject="Almindelig spam", **junk)
    insert_message(c, "bynet", "virus1@x.example", sender="Billing <billing@x.example>", subject="Faktura",
                   threat="virus", threat_detail="Win.Trojan.Agent-12345",
                   symbols=[{"n": "CLAM_VIRUS", "s": 20.0, "o": ["Win.Trojan.Agent-12345"]}], **junk)
    insert_message(c, "bynet", "conf1@x.example", sender="spam@pharma.example", subject="Bekræftet",
                   user_verdict="spam", **junk)
    insert_message(c, "bynet", "kc1@kunde.example", sender="Kunde <kunde@kunde.example>", subject="Re: ordre",
                   symbols=KC, **junk)  # 'Tjek disse': a known contact in spam
    insert_message(c, "bynet", "gone1@x.example", sender="weg@x.example", our_action="moved_to_junk",
                   current_folder="gone", our_score=12.0)
    insert_message(c, "bynet", "shadow1@x.example", sender="maybe@shadow.example", our_action="shadow_spam",
                   our_score=11.0)
    insert_message(c, "bynet", "ham1@x.example", sender="Mor <mor@familie.dk>", subject="Søndag")
    insert_message(c, "bynet", "rel1@x.example", sender="ok@frigivet.example", our_action="manual_release",
                   user_verdict="ham", our_score=11.0)
    insert_message(c, "molt", "m1@x.example", sender="skjult@molt-kunde.example", subject="MOLT-HEMMELIGT", **junk)
    c.commit()
    return e


def client_for(env, name):
    c = env.app.test_client()
    assert login(c, name, PW).status_code == 302, name
    return c


def body(r) -> str:
    return r.get_data().decode("utf-8", "replace")


def key_of(account: str, mid: str) -> str:
    return f"{account}:{kit.token_for(mid)}"


def row(html: str, data_row: str) -> str:
    """The whole <li> of one row (rows hold nested <li> in 'Hvorfor?' and
    the review reasons, so the closing tag is found by depth)."""
    i = html.find(f'data-row="{data_row}"')
    assert i > -1, f"row {data_row} not on the page"
    start = html.rfind("<li", 0, i)
    depth = 0
    for m in re.finditer(r"<li\b|</li>", html[start:]):
        depth += 1 if m.group(0) != "</li>" else -1
        if depth == 0:
            return html[start:start + m.end()]
    raise AssertionError("unclosed row")


def open_tag(fragment: str) -> str:
    return fragment[:fragment.index(">") + 1]


def swipes(fragment: str) -> dict[str, str]:
    tag = open_tag(fragment)
    return {d: m.group(1) for d in ("right", "left") if (m := re.search(rf'data-swipe-{d}="([^"]*)"', tag))}


def swipe_form(fragment: str, d: str) -> str:
    m = re.search(rf'<form[^>]*data-swipe-form="{d}"[^>]*>(.*?)</form>', fragment, re.S)
    return m.group(0) if m else ""


def fields(form_html: str) -> dict[str, str]:
    return dict(re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]*)"', form_html))


def csp_clean(html: str, where: str) -> None:
    for rx, what in INLINE_PATTERNS:
        m = rx.search(html)
        assert m is None, f"{what} on {where}: {html[max(0, m.start() - 80):m.end() + 80]}"


# ===================================================================== rendered hooks per permission


def test_admin_spam_rows_swipe_both_ways(env):
    html = body(client_for(env, "admin").get("/spam"))
    r = row(html, key_of("bynet", "plain1@x.example"))
    assert swipes(r) == {"right": "Frigiv", "left": "Det er spam"}
    # Right = the visible Frigiv button's own form (no duplicate).
    right = swipe_form(r, "right")
    assert right and fields(right)["action"] == "release" and "Frigiv" in right
    assert fields(right)["items"] == key_of("bynet", "plain1@x.example") and 'name="csrf"' in right
    assert "data-ajax" in right and "data-sync" in right and " hidden" not in open_tag(right)
    # Left = learn_spam ("Bekræft som spam" of the bulk bar): a hidden form, same fields + CSRF.
    left = swipe_form(r, "left")
    f = fields(left)
    assert f["action"] == "learn_spam" and f["items"] == key_of("bynet", "plain1@x.example")
    assert f["view"] == "spam" and f["nonce"] and f["next"].startswith("/spam") and 'name="csrf"' in left
    assert 'class="swipe-form"' in left and " hidden" in open_tag(left) and "<button" not in left
    # The hidden form sits outside .mail-actions (its :empty layout rule must keep working).
    actions = r[r.index('<div class="mail-actions">'):]
    assert actions.index("</div>") < actions.index('class="swipe-form"')
    # An Overvåg row (still in the inbox) on the spam list: Frigiv + learn as spam, nothing moves.
    s = row(html, key_of("bynet", "shadow1@x.example"))
    assert swipes(s) == {"right": "Frigiv", "left": "Det er spam"}
    assert fields(swipe_form(s, "left"))["action"] == "learn_spam"
    # Already confirmed spam: nothing to say "Det er spam" about.
    assert swipes(row(html, key_of("bynet", "conf1@x.example"))) == {"right": "Frigiv"}
    csp_clean(html, "/spam admin")


def test_admin_threat_row_keeps_frigiv_swipe_for_the_confirm_dialog(env):
    html = body(client_for(env, "admin").get("/spam"))
    r = row(html, key_of("bynet", "virus1@x.example"))
    assert swipes(r) == {"right": "Frigiv", "left": "Det er spam"}
    f = fields(swipe_form(r, "right"))
    assert f["action"] == "release" and "confirm_threat" not in f  # the server asks first


def test_bruger_threat_row_has_no_frigiv_swipe(env):
    html = body(client_for(env, "anna").get("/spam"))
    r = row(html, key_of("bynet", "virus1@x.example"))
    assert "data-swipe-right" not in open_tag(r) and swipe_form(r, "right") == ""
    assert 'value="release"' not in r and "Kontakt administrator" in r
    assert swipes(r) == {"left": "Det er spam"}
    assert fields(swipe_form(r, "left"))["action"] == "learn_spam"
    p = row(html, key_of("bynet", "plain1@x.example"))
    assert swipes(p) == {"right": "Frigiv", "left": "Det er spam"}
    # Never another mailbox's rows.
    assert "MOLT-HEMMELIGT" not in html and key_of("molt", "m1@x.example") not in html
    csp_clean(html, "/spam anna")


def test_bruger_without_release_gets_no_swipe(env):
    for path in ("/spam", "/"):
        html = body(client_for(env, "bo").get(path))
        assert "data-swipe-" not in html and "swipe-form" not in html, path


def test_bruger_with_release_only(env):
    html = body(client_for(env, "dora").get("/spam"))
    r = row(html, key_of("bynet", "plain1@x.example"))
    assert swipes(r) == {"right": "Frigiv", "left": "Det er spam"}
    assert 'value="release_allow"' not in r  # no rules permission: no Tillad
    assert swipes(row(html, key_of("bynet", "virus1@x.example"))) == {"left": "Det er spam"}


def test_bruger_home_fanget_spam_card_swipes(env):
    html = body(client_for(env, "anna").get("/"))
    assert swipes(row(html, key_of("bynet", "plain1@x.example"))) == {"right": "Frigiv", "left": "Det er spam"}
    csp_clean(html, "/ anna")


def test_admin_overview_has_no_swipe(env):
    html = body(client_for(env, "admin").get("/"))
    assert key_of("bynet", "plain1@x.example") in html  # listed under "Seneste fanget spam"
    assert "data-swipe-" not in html


def test_messages_rows_swipe_matches_where_the_mail_is(env):
    html = body(client_for(env, "admin").get("/messages"))
    inbox = row(html, key_of("bynet", "ham1@x.example"))
    assert swipes(inbox) == {"left": "Det er spam"}
    left = swipe_form(inbox, "left")
    assert fields(left)["action"] == "mark_spam" and "Flyt til spam" in left and " hidden" not in open_tag(left)
    assert 'class="swipe-form"' not in inbox  # the visible button is the swipe form
    junk = row(html, key_of("bynet", "plain1@x.example"))
    assert swipes(junk) == {"right": "Frigiv", "left": "Det er spam"}
    assert fields(swipe_form(junk, "left"))["action"] == "learn_spam"
    assert swipes(row(html, key_of("bynet", "conf1@x.example"))) == {"right": "Frigiv"}
    released = row(html, key_of("bynet", "rel1@x.example"))
    assert swipes(released) == {"left": "Det er spam"}  # already in the inbox: no Frigiv
    gone = row(html, key_of("bynet", "gone1@x.example"))
    assert swipes(gone) == {} and "<form" not in gone
    csp_clean(html, "/messages admin")


def test_review_rows_swipe_with_their_own_buttons(env):
    for who in ("admin", "anna"):
        html = body(client_for(env, who).get("/spam"))
        r = row(html, "review:" + key_of("bynet", "kc1@kunde.example"))
        assert swipes(r) == {"right": "Frigiv", "left": "Det er spam"}, who
        assert fields(swipe_form(r, "right"))["action"] == "release"
        left = swipe_form(r, "left")
        assert fields(left)["action"] == "learn_spam" and "Det er spam" in left
        assert fields(left)["view"] == "review" and 'class="swipe-form"' not in r


def test_swipe_plan_fails_closed(env):
    with env.app.test_request_context("/"):
        assert ui_mail.swipe_plan(account="bynet", loc="junk", view="spam", verdict=None, threat=None) == {}
        assert ui_mail.swipe_attrs({}) == ""
        assert ui_mail.swipe_forms({}, key="k", view="spam", next_url="/spam", rendered="") == ""
    assert ui_mail.SWIPE_LABELS == {"right": "Frigiv", "left": "Det er spam"}
    assert set(ui_mail.SWIPE_VIEWS) == {"spam", "messages", "review"}


# ===================================================================== the posted actions


def test_swipe_forms_post_the_existing_actions_with_undo(env):
    admin = client_for(env, "admin")
    html = body(admin.get("/spam"))
    k = key_of("bynet", "plain1@x.example")
    f = fields(swipe_form(row(html, k), "right"))
    data = post(admin, "/mail/action", {**f, "nonce": "sw-1"}).get_json()
    assert data["ok"] and data["rows"][k] is None                      # leaves the spam list
    assert data["undo"]["fields"]["action"] == "mark_spam"              # existing Fortryd
    # Left on Beskeder: Flyt til spam, Fortryd = Frigiv; the row stays, now in spam.
    html = body(admin.get("/messages"))
    h1 = key_of("bynet", "ham1@x.example")
    f = fields(swipe_form(row(html, h1), "left"))
    data = post(admin, "/mail/action", {**f, "nonce": "sw-2"}).get_json()
    assert data["ok"] and data["undo"]["fields"]["action"] == "release"
    assert swipes(data["rows"][h1]) == {"right": "Frigiv"}
    # learn_spam has no undo: result toast only; the re-rendered row lost its left swipe.
    html = body(admin.get("/spam"))
    s1 = key_of("bynet", "shadow1@x.example")
    f = fields(swipe_form(row(html, s1), "left"))
    data = post(admin, "/mail/action", {**f, "nonce": "sw-3"}).get_json()
    assert data["ok"] and "undo" not in data and swipes(data["rows"][s1]) == {"right": "Frigiv"}
    assert env.services.calls[-1][2] == "learn_spam"


def test_bruger_threat_release_by_forged_swipe_is_refused(env):
    anna = client_for(env, "anna")
    data = post(anna, "/mail/action", {"action": "release", "items": [key_of("bynet", "virus1@x.example")],
                                       "view": "spam", "nonce": "sw-f1"}).get_json()
    assert not data["ok"] and data["results"][0]["code"] == "threat_admin"
    r = post(anna, "/mail/action", {"action": "learn_spam", "items": [key_of("molt", "m1@x.example")],
                                    "view": "spam", "nonce": "sw-f2"})
    assert r.status_code == 404 and r.get_json()["message"] == "Beskeden findes ikke."


def test_swipe_post_needs_csrf(env):
    admin = client_for(env, "admin")
    r = admin.post("/mail/action", data={"action": "learn_spam", "items": [key_of("bynet", "plain1@x.example")],
                                         "view": "spam", "nonce": "sw-c"},
                   headers={"Accept": "application/json", "X-Requested-With": "fetch"})
    assert r.status_code in (400, 403)
    assert env.services.calls == []
    assert csrf_of(admin)


# ===================================================================== JS / CSS structure


def _swipe_js() -> str:
    start = APP_JS.index("// ---------------------------------------------------------------- swipe on mail rows")
    return APP_JS[start:APP_JS.index("function initPwa()", start)]


def test_js_swipe_listeners_are_passive_and_never_block_scrolling():
    js = _swipe_js()
    calls = [m.start() for m in re.finditer(r"addEventListener\(", js)] + [len(js)]
    seen = []
    for a, b in zip(calls, calls[1:]):
        m = re.match(r'addEventListener\("(touch\w+)"', js[a:])
        if m:
            seen.append(m.group(1))
            assert "{ passive: true, capture: true }" in js[a:b], m.group(1)
    assert sorted(seen) == ["touchcancel", "touchend", "touchmove", "touchstart"]
    assert "preventDefault" not in js.split('addEventListener("click"')[0]  # only the post-swipe click guard
    assert re.search(r'addEventListener\("click", function \(e\) \{\s*if \(Date\.now\(\) < noClickUntil\)', js)


def test_js_direction_lock_threshold_and_fling():
    js = _swipe_js()
    assert re.search(r"var LOCK = 10;", js) and re.search(r"var COMMIT = 0\.4;", js)
    assert "Math.abs(dx) < LOCK && Math.abs(dy) < LOCK" in js
    assert 'if (Math.abs(dy) >= Math.abs(dx)) { swipePhase = "y"; g = null; return; }' in js
    assert "FLING_V" in js and "far || fling" in js
    assert "snapBack(s)" in js and "is-armed" in js
    # Permissions only from the server: the row attribute and its form.
    assert 'hasAttribute("data-swipe-" + dir)' in js and "form[data-swipe-form=" in js
    assert "SF.submit(form, null)" in js


def test_js_no_inline_style_and_reduced_motion():
    assert 'setAttribute("style"' not in APP_JS and ".style.cssText" not in APP_JS
    assert not re.search(r"\.style\.[a-zA-Z]+\s*=", _swipe_js())
    assert "style.setProperty(\"--sw-x\"" in _swipe_js()
    assert "prefers-reduced-motion: reduce" in APP_JS and "reducedMotion()" in _swipe_js()
    assert "innerHTML" not in _swipe_js()  # labels come from attributes via textContent


def test_js_pull_to_refresh_yields_to_a_swipe():
    ptr = APP_JS[APP_JS.index("function initPullToRefresh()"):APP_JS.index("// ------", APP_JS.index("function initPullToRefresh()"))]
    assert 'if (swipePhase === "x") { if (dist) reset(); else startY = null; return; }' in ptr
    assert 'if (swipePhase === "pending") return;' in ptr
    assert 'dist >= THRESHOLD && swipePhase !== "x"' in ptr
    # The swipe listeners run in the capture phase, before pull to refresh's.
    assert _swipe_js().count("capture: true") == 4
    boot = APP_JS[APP_JS.index('document.addEventListener("DOMContentLoaded"'):]
    assert boot.index("initPullToRefresh();") < boot.index("initSwipe();")


def test_js_first_use_hint():
    js = _swipe_js()
    assert '"Tip: stryg en mail til højre for Frigiv eller til venstre for Det er spam"' in js
    assert 'var SWIPE_HINT_KEY = "sf-swipe-hint";' in js
    assert "localStorage.getItem(SWIPE_HINT_KEY)" in js and "localStorage.setItem(SWIPE_HINT_KEY" in js
    assert 'setAttribute("aria-label", "Skjul tip")' in js


def test_js_rerender_under_the_finger_drops_the_gesture():
    """2.5.0: applyRows tells the swipe code before it replaces/removes a
    row, so a gesture on a detached node (whose touchend never reaches the
    document) cannot leave a backdrop behind or keep swipePhase stuck."""
    apply = APP_JS[APP_JS.index("function applyRows(rows)"):APP_JS.index("function maybeEmpty()")]
    assert apply.index("swipeRelease(target") < apply.index("target.replaceWith(fresh)")
    drop = APP_JS[APP_JS.index("swipeDrop = function (row, removing)"):]
    drop = drop[:drop.index("};")]
    assert "g.row === row" in drop and 'swipePhase = "idle"' in drop and "g = null" in drop
    assert "g.bg.remove()" in drop and "__sfSwipeBg.remove()" in drop


def test_js_and_css_label_never_cut_off():
    assert 'el("span", "swipe-act-text"' in APP_JS and '"--sw-reveal"' in APP_JS
    assert 'classList.toggle("is-full"' in APP_JS
    assert ".swipe-bg.is-full .swipe-act-text { opacity: 1; }" in APP_CSS
    assert "var(--sw-reveal, 0px)" in APP_CSS


def test_css_clips_the_list_while_a_row_is_out_of_place():
    assert (".mail-list.has-swipe:has(> .swipe-bg), .review-list.has-swipe:has(> .swipe-bg) "
            "{ overflow: hidden; overflow: clip; }") in APP_CSS


def test_css_swipe_rules():
    assert re.search(r"\[data-swipe-right\], \[data-swipe-left\] \{ touch-action: pan-y pinch-zoom; \}", APP_CSS)
    assert ".swipe-form { display: none !important; }" in APP_CSS
    assert "var(--sw-x, 0px)" in APP_CSS and ".swipe-bg.go-right" in APP_CSS and ".swipe-bg.go-left" in APP_CSS
    block = APP_CSS[APP_CSS.index("/* 2.5.0: swipe on mail rows"):APP_CSS.index("/* end 2.5.0 swipe */")]
    assert "@media (prefers-reduced-motion: reduce)" in block


# ===================================================================== headless Chrome (real touch events)


PW_PY = Path("/tmp/pwvenv/bin/python")
CHROME = Path("/usr/bin/google-chrome")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.skipif(not (PW_PY.exists() and CHROME.exists()), reason="playwright venv / Chrome not installed")
def test_swipe_in_headless_chrome(tmp_path):
    if subprocess.run([str(PW_PY), "-c", "import playwright.sync_api"], capture_output=True).returncode:
        pytest.skip("playwright not importable")
    port, state = _free_port(), tmp_path / "dev"
    srv = subprocess.Popen([sys.executable, str(ROOT / "tests" / "dev_server.py"), "--port", str(port),
                            "--state", str(state)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        base = f"http://127.0.0.1:{port}"
        for _ in range(120):
            try:
                urllib.request.urlopen(base + "/healthz", timeout=1)
                break
            except OSError:
                time.sleep(0.25)
        else:
            pytest.fail("dev server did not start")
        # A dangerous mail for the administrator's confirm-before-release path.
        now = int(time.time())
        c = sqlite3.connect(state / "spamfilter.db")
        row_ = {"account": "bynet", "message_id": "<virus-swipe@x.example>", "first_seen": now, "last_seen": now,
                "current_folder": "Spamfilter", "our_score": 19.6, "our_action": "moved_to_junk",
                "sender": "Billing <billing@x.example>", "subject": "Faktura", "received_at": now - 60,
                "scanned_at": now, "origin": "inbox_scan", "score_version": 2, "threat": "virus",
                "threat_detail": "Win.Trojan.Agent-12345",
                "symbols": json.dumps([{"n": "CLAM_VIRUS", "s": 20.0, "o": ["Win.Trojan.Agent-12345"]}])}
        c.execute(f"INSERT INTO messages({','.join(row_)}) VALUES({','.join('?' * len(row_))})", list(row_.values()))
        # Two ordinary spam mails from one sender domain (data-sync pair).
        for i, who in enumerate(("Tilbud <tilbud@samme-afsender.example>", "Nyhed <nyhed@samme-afsender.example>")):
            pair = {**row_, "message_id": f"<pair-{i}@samme-afsender.example>", "sender": who,
                    "subject": f"Kampagne {i}", "our_score": 14.0 + i, "received_at": now - 30 - i,
                    "threat": None, "threat_detail": None,
                    "symbols": json.dumps([{"n": "BAYES_SPAM", "s": 5.0}])}
            c.execute(f"INSERT INTO messages({','.join(pair)}) VALUES({','.join('?' * len(pair))})", list(pair.values()))
        c.commit()
        c.close()
        res = subprocess.run([str(PW_PY), str(ROOT / "tests" / "swipe_browser_check.py"), base, PW],
                             capture_output=True, text=True, timeout=240, env={**os.environ, "PYTHONPATH": ""})
        assert res.stdout.strip(), res.stderr[-2000:]
        out = json.loads(res.stdout.strip().splitlines()[-1])
        assert out["ok"], out
        for k in ("follows_finger", "short_snaps_back", "vertical_not_hijacked", "armed_right", "release_toast",
                  "row_removed", "armed_left", "learn_spam_posted", "ptr_quiet_during_swipe", "swipe_owns_gesture",
                  "threat_needs_confirm", "threat_row_snapped_back", "mark_spam_undo", "hint_remembered",
                  # 2.5.0 review fixes
                  "label_icon_only_when_short", "label_full_right", "label_full_left", "review_drag_no_overflow",
                  "same_sender_pair", "pending_commit_no_overflow", "page_not_panned", "b_armed", "b_rerendered",
                  "rerender_no_post_for_b", "rerender_no_orphan_backdrop", "b_swipes_afterwards",
                  "review_commit_posted"):
            assert out["checks"].get(k) is True, (k, out["checks"])
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=10)
        except subprocess.TimeoutExpired:
            srv.kill()


def test_review_rows_can_be_ticked_and_judged_together(env):
    """2.8.2: Tjek disse has checkboxes + a bulk bar (Frigiv / Det er spam), so several
    mails are judged in one go instead of one 'Det er spam' click per row."""
    admin = client_for(env, "admin")
    html = body(admin.get("/spam"))
    k = key_of("bynet", "kc1@kunde.example")
    r = row(html, "review:" + k)
    assert f'value="{k}" form="bulk-review"' in r and "has-check" in open_tag(r)
    assert 'id="bulk-review"' in html and 'data-select-all="bulk-review"' in html
    form = html[html.index('<form id="bulk-review"'):]
    form = form[:form.index("</form>")]
    assert 'value="release"' in form and 'value="learn_spam"' in form and "Det er spam" in form
    f = fields(form)
    data = post(admin, "/mail/action", {**f, "action": "learn_spam", "items": k, "nonce": "rv-bulk-1"}).get_json()
    assert data["ok"] and data["rows"]["review:" + k] is None
