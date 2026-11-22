"""Headless Chrome check of the 2.5.0 swipe on mail rows (touch via CDP).

    /tmp/pwvenv/bin/python tests/swipe_browser_check.py http://127.0.0.1:8099 [--shots DIR]

Runs against tests/dev_server.py (fake engine/services, throw-away state):
logs in as admin on a 390x844 touch phone, then drives real touch events
through the Chrome DevTools protocol (Input.dispatchTouchEvent):

  * the one-time tip is shown, a short sideways drag snaps back (no POST),
    a vertical drag is never taken over (no swipe class, no POST);
  * a long swipe to the right posts Frigiv: toast with "Fortryd", the row
    collapses away and the tip is remembered in localStorage;
  * a swipe to the left posts "Det er spam" (learn_spam) and the row is
    re-rendered without a left swipe;
  * a dangerous mail (if the caller seeded one): the server's confirmation
    dialog opens and the row snaps back until it is confirmed;
  * Beskeder: an inbox mail swiped left is moved to spam (with Fortryd);
  * pull to refresh (installed app emulated) stays quiet during a swipe;
  * 2.5.0: the label behind the row is never a cut-off fragment (icon at
    the moving edge, text once it fits); the page never gets wider than the
    screen while a Tjek disse row is dragged or waits for the server; a row
    re-rendered under the finger (same sender, another swipe's answer)
    drops that gesture and leaves no coloured backdrop behind;
  * no console errors / CSP violations.

Prints one JSON object; exit status 0 = all checks passed. Used by
tests/test_ui_swipe.py (skipped when playwright/Chrome are missing).
"""

from __future__ import annotations

import json
import sys
import time

from playwright.sync_api import sync_playwright

CHROME = "/usr/bin/google-chrome"
PASSWORD = "korrekt-hest-batteri-42"  # tests/fakes_ui.TEST_PASSWORD (dev server only)


# Where the label behind the swiped row is: "icon" = only the icon shows,
# next to the row's moving edge; "full" = the whole label is visible and
# not covered by the row; anything else = a cut-off / covered label.
LABEL_JS = """dir => { const bg = document.querySelector('.swipe-bg'); const row = document.querySelector('li.is-swiping');
  if (!bg || !row) return 'none';
  const a = bg.querySelector('.swipe-act-' + dir), r = a.getBoundingClientRect(), rr = row.getBoundingClientRect();
  const ic = a.querySelector('.icon').getBoundingClientRect();
  const txt = parseFloat(getComputedStyle(a.querySelector('.swipe-act-text')).opacity);
  const free = dir === 'right' ? [0, rr.left] : [rr.right, innerWidth];
  const inside = (x0, x1) => x0 >= free[0] - 1 && x1 <= free[1] + 1;
  if (txt > 0.99 && inside(r.left, r.right)) return 'full';
  if (txt < 0.01 && inside(ic.left, ic.right)) return 'icon';
  return 'cut:' + [Math.round(r.left), Math.round(r.right), Math.round(rr.left), Math.round(rr.right), txt].join(','); }"""
# A fixed 390: with mobile emulation the layout viewport (innerWidth) grows
# with overflowing content, so it cannot be the yardstick.
WIDTH_JS = "() => document.documentElement.scrollWidth <= 390 && document.body.scrollWidth <= 390"


def main() -> int:
    base = sys.argv[1].rstrip("/")
    password = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else PASSWORD
    shots = sys.argv[sys.argv.index("--shots") + 1] if "--shots" in sys.argv else ""
    out: dict = {"checks": {}, "errors": []}
    checks = out["checks"]
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=CHROME, headless=True, args=["--no-sandbox"])
        ctx = browser.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2,
                                  is_mobile=True, has_touch=True, locale="da-DK")
        # The installed app (display-mode: standalone) turns on pull to refresh.
        ctx.add_init_script("""(() => { const mm = window.matchMedia.bind(window);
          window.matchMedia = q => /display-mode:\\s*standalone/.test(q)
            ? {matches: true, media: q, addEventListener() {}, removeEventListener() {}} : mm(q); })();""")
        page = ctx.new_page()
        page.on("console", lambda m: out["errors"].append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: out["errors"].append(str(e)))
        posts: list[str] = []
        page.on("request", lambda r: posts.append(r.post_data or "") if r.method == "POST"
                and r.url.endswith("/mail/action") else None)

        page.goto(base + "/login")
        page.fill('input[name="username"]', "admin")
        page.fill('input[name="password"]', password)
        page.click('button[type="submit"]')
        page.wait_for_load_state("networkidle")
        page.goto(base + "/spam")
        page.wait_for_load_state("networkidle")
        cdp = ctx.new_cdp_session(page)

        def touch(kind: str, x: float | None = None, y: float | None = None) -> None:
            pts = [] if x is None else [{"x": x, "y": y, "id": 1}]
            cdp.send("Input.dispatchTouchEvent", {"type": kind, "touchPoints": pts})

        def drag(x0: float, y0: float, x1: float, y1: float, steps: int = 12, *, end: bool = True,
                 pause: float = 0.012) -> None:
            touch("touchStart", x0, y0)
            for i in range(1, steps + 1):
                touch("touchMove", x0 + (x1 - x0) * i / steps, y0 + (y1 - y0) * i / steps)
                time.sleep(pause)
            if end:
                touch("touchEnd")

        def row_box(sel: str) -> dict:
            page.eval_on_selector(sel, "n => n.scrollIntoView({block: 'center'})")
            time.sleep(0.15)
            return page.eval_on_selector(sel, "n => { const r = n.querySelector('.mail-main').getBoundingClientRect();"
                                              " const w = n.getBoundingClientRect();"
                                              " return {x: r.left + 8, y: r.top + r.height / 2, w: w.width}; }")

        # 0. Pull to refresh vs. swipe at the top of the page (installed app).
        checks["standalone"] = page.evaluate("() => document.documentElement.classList.contains('is-standalone')")
        page.evaluate("() => { window.scrollTo(0, 0); window.__sfMarker = 1; }")
        rv = "li.review-row[data-swipe-right]"
        def rv_box() -> dict:
            return page.eval_on_selector(rv, "n => { const r = n.querySelector('.review-main').getBoundingClientRect();"
                                             " return {x: r.left + 8, y: r.top + 10}; }")
        b = rv_box()
        drag(b["x"], b["y"], b["x"] + 3, b["y"] + 200, end=False)          # straight down: the app's pull
        checks["ptr_control_armed"] = page.evaluate("() => !!document.querySelector('.ptr.is-armed')")
        for i in range(1, 9):                                               # back up: no refresh
            touch("touchMove", b["x"] + 3, b["y"] + 200 - 25 * i)
        touch("touchEnd")
        time.sleep(0.4)
        checks["ptr_control_no_reload"] = page.evaluate("() => window.__sfMarker === 1")
        # Moving the finger back up scrolled the page (momentum): back to the
        # very top, where pull to refresh is live, and measure again.
        time.sleep(0.6)
        page.evaluate("() => window.scrollTo(0, 0)")
        time.sleep(0.3)
        checks["at_top"] = page.evaluate("() => window.scrollY === 0")
        b = rv_box()
        touch("touchStart", b["x"], b["y"])
        # Sideways first (beyond Chrome's ~15 px touch slop, which swallows
        # smaller moves): a swipe ...
        touch("touchMove", b["x"] + 24, b["y"] + 2)
        for i in range(1, 11):
            touch("touchMove", b["x"] + 24 + 4 * i, b["y"] + 2 + 20 * i)      # ... then mostly down
            time.sleep(0.012)
        checks["ptr_quiet_during_swipe"] = page.evaluate(
            "() => !document.querySelector('.ptr.is-armed') && document.querySelector('.ptr').classList.contains('is-dragging') === false")
        checks["swipe_owns_gesture"] = page.evaluate(
            "() => !!document.querySelector('li.review-row.is-swiping[data-swipe-right]')")
        touch("touchEnd")
        time.sleep(0.6)
        checks["no_reload_after_swipe"] = page.evaluate("() => window.__sfMarker === 1")
        checks["diagonal_snaps_back"] = not posts and page.locator(".swipe-bg").count() == 0

        checks["hint_shown"] = page.locator(".swipe-hint").count() == 1 and "stryg en mail til højre for Frigiv" in (
            page.locator(".swipe-hint").inner_text())
        sel = "li.mail-row[data-swipe-right][data-swipe-left]:not(.is-gone):not(:has(.threat-badge))"
        checks["swipe_rows"] = page.locator(sel).count()
        first_key = page.eval_on_selector(sel, "n => n.getAttribute('data-row')")
        row_sel = f'li[data-row="{first_key}"]'
        if shots:
            page.screenshot(path=f"{shots}/swipe-0-hint.png")

        # 1. Short sideways drag (20 %): follows the finger, then snaps back, nothing posted.
        b = row_box(row_sel)
        drag(b["x"], b["y"], b["x"] + b["w"] * 0.2, b["y"] + 2, end=False)
        checks["follows_finger"] = page.eval_on_selector(
            row_sel, "n => n.classList.contains('is-swiping') && parseFloat(getComputedStyle(n).getPropertyValue('--sw-x')) > 20")
        checks["not_armed_short"] = not page.eval_on_selector(row_sel, "n => n.classList.contains('is-armed')")
        time.sleep(0.2)
        checks["label_icon_only_when_short"] = page.evaluate(LABEL_JS, "right") == "icon"
        touch("touchEnd")
        time.sleep(0.5)
        checks["short_snaps_back"] = (page.locator(row_sel).count() == 1 and not page.eval_on_selector(
            row_sel, "n => n.classList.contains('is-swiping')") and page.locator(".swipe-bg").count() == 0)
        checks["short_no_post"] = not posts

        # 2. Vertical drag with a little sideways jitter: never a swipe.
        b = row_box(row_sel)
        drag(b["x"], b["y"], b["x"] + 6, b["y"] - 120, end=False)
        checks["vertical_not_hijacked"] = not page.eval_on_selector(row_sel, "n => n.classList.contains('is-swiping')")
        touch("touchEnd")
        time.sleep(0.3)
        checks["vertical_no_post"] = not posts

        # 3. Long swipe right: armed, Frigiv posted, toast with Fortryd, row collapses away.
        b = row_box(row_sel)
        drag(b["x"], b["y"], b["x"] + b["w"] * 0.6, b["y"] + 3, end=False)
        checks["armed_right"] = page.evaluate(
            "() => !!document.querySelector('.swipe-bg.go-right.is-armed')")
        time.sleep(0.2)
        checks["label_full_right"] = page.evaluate(LABEL_JS, "right") == "full"
        if shots:
            page.screenshot(path=f"{shots}/swipe-1-armed-right.png")
        with page.expect_response(lambda r: r.url.endswith("/mail/action")) as resp:
            touch("touchEnd")
        checks["release_posted"] = "action=release" in (posts[-1] if posts else "") or "release" in (posts[-1] if posts else "")
        checks["release_status"] = resp.value.status
        page.wait_for_selector(".toast", timeout=3000)
        toast = page.locator(".toast").last.inner_text()
        checks["release_toast"] = "frigivet" in toast and "Fortryd" in toast
        time.sleep(0.8)
        checks["row_removed"] = page.locator(row_sel).count() == 0 and page.locator(".swipe-bg").count() == 0
        checks["hint_remembered"] = (page.evaluate("() => localStorage.getItem('sf-swipe-hint')") == "1"
                                     and page.locator(".swipe-hint").count() == 0)
        if shots:
            page.screenshot(path=f"{shots}/swipe-2-released.png")

        # 4. Swipe left on the next row: "Det er spam" = learn_spam; the row stays, without a left swipe.
        key2 = page.eval_on_selector(sel, "n => n.getAttribute('data-row')")
        row2 = f'li[data-row="{key2}"]'
        b = row_box(row2)
        x0 = min(b["x"] + b["w"] * 0.7, 390 - 30)
        drag(x0, b["y"], x0 - b["w"] * 0.6, b["y"] + 2, end=False)
        checks["armed_left"] = page.evaluate("() => !!document.querySelector('.swipe-bg.go-left.is-armed')")
        time.sleep(0.2)
        checks["label_full_left"] = page.evaluate(LABEL_JS, "left") == "full"
        if shots:
            page.screenshot(path=f"{shots}/swipe-3-armed-left.png")
        n_posts = len(posts)
        with page.expect_response(lambda r: r.url.endswith("/mail/action")):
            touch("touchEnd")
        checks["learn_spam_posted"] = len(posts) == n_posts + 1 and "learn_spam" in posts[-1]
        time.sleep(0.8)
        checks["left_row_rerendered"] = page.locator(row2).count() == 1 and not page.eval_on_selector(
            row2, "n => n.hasAttribute('data-swipe-left')") and page.locator(".swipe-bg").count() == 0

        # 5. Reload: the tip stays hidden.
        page.reload()
        page.wait_for_load_state("networkidle")
        checks["hint_stays_hidden"] = page.locator(".swipe-hint").count() == 0

        # 5b. No sideways page overflow: a Tjek disse row mid-drag, and a row
        #     waiting for a slow server (responses delayed on the client).
        page.evaluate("""() => { const f = window.fetch; window.__sfDelay = 0;
          window.fetch = function () { const p = f.apply(this, arguments); const d = window.__sfDelay;
            return d ? p.then(r => new Promise(res => setTimeout(() => res(r), d))) : p; }; }""")
        rvs = "li.review-row[data-swipe-right]"
        if page.locator(rvs).count():
            page.eval_on_selector(rvs, "n => n.scrollIntoView({block: 'center'})")
            time.sleep(0.15)
            b = page.eval_on_selector(rvs, "n => { const r = n.querySelector('.review-main').getBoundingClientRect();"
                                           " return {x: r.left + 8, y: r.top + 10, w: n.getBoundingClientRect().width}; }")
            n_posts = len(posts)
            drag(b["x"], b["y"], b["x"] + b["w"] * 0.32, b["y"] + 2, end=False)
            checks["review_drag_no_overflow"] = page.evaluate(WIDTH_JS) and page.evaluate(
                "() => !!document.querySelector('li.review-row.is-swiping')")
            touch("touchEnd")
            time.sleep(0.5)
            checks["review_drag_no_post"] = len(posts) == n_posts
            # Committed, and the server is slow: the row waits off to the side.
            page.evaluate("() => { window.__sfDelay = 1500; }")
            rkey = page.eval_on_selector(rvs, "n => n.getAttribute('data-row')")
            b = page.eval_on_selector(rvs, "n => { const r = n.querySelector('.review-main').getBoundingClientRect();"
                                           " return {x: r.left + 8, y: r.top + 10, w: n.getBoundingClientRect().width}; }")
            drag(b["x"], b["y"], b["x"] + b["w"] * 0.6, b["y"] + 2)
            time.sleep(0.35)
            checks["pending_commit_no_overflow"] = page.evaluate(WIDTH_JS) and page.evaluate(
                "k => [...document.querySelectorAll('li.review-row.is-swiping')].some(n => n.getAttribute('data-row') === k)",
                rkey)
            # A sideways drag elsewhere on the page (the card head) must not pan it.
            hb = page.eval_on_selector(".review-card .card-head, .review-head, .review-card h2",
                                       "n => { const r = n.getBoundingClientRect();"
                                       " return {x: r.left + r.width / 2, y: r.top + Math.min(12, r.height / 2)}; }")
            drag(min(hb["x"] + 80, 340), hb["y"], max(hb["x"] - 120, 40), hb["y"] + 1)
            time.sleep(0.2)
            checks["page_not_panned"] = page.evaluate(
                "() => window.scrollX === 0 && (!window.visualViewport || window.visualViewport.offsetLeft < 1)")
            time.sleep(1.8)
            page.evaluate("() => { window.__sfDelay = 0; }")
            checks["review_commit_posted"] = len(posts) == n_posts + 1

        # 5c. Two rows from the same sender: A is swiped (Frigiv) and waits for
        #     the server; meanwhile B is dragged past the commit point. A's
        #     answer re-renders B (data-sync): B's gesture is dropped, nothing
        #     is posted for B and no backdrop is left over another row.
        pair = page.evaluate("""() => { const by = {};
          for (const n of document.querySelectorAll('li.mail-row[data-swipe-right][data-swipe-left][data-sync-key]')) {
            if (n.querySelector('.threat-badge')) continue;
            const k = n.getAttribute('data-sync-key'); (by[k] = by[k] || []).push(n.getAttribute('data-row')); }
          for (const k in by) if (by[k].length >= 2) return by[k].slice(0, 2); return null; }""")
        checks["same_sender_pair"] = bool(pair)
        if pair:
            ra, rb = (f'li[data-row="{k}"]' for k in pair)
            page.evaluate("() => { window.__sfDelay = 1500; }")
            b = row_box(ra)
            n_posts = len(posts)
            drag(b["x"], b["y"], b["x"] + b["w"] * 0.6, b["y"] + 3)          # A: commit, slides out, waits
            time.sleep(0.35)
            bb = row_box(rb)
            x0 = min(bb["x"] + bb["w"] * 0.7, 390 - 30)
            drag(x0, bb["y"], x0 - bb["w"] * 0.6, bb["y"] + 2, end=False)      # B: armed, finger still down
            checks["b_armed"] = page.evaluate("() => !!document.querySelector('.swipe-bg.go-left.is-armed')")
            time.sleep(1.8)                                                    # A's answer re-renders B
            checks["b_rerendered"] = page.eval_on_selector(rb, "n => !n.classList.contains('is-swiping')")
            touch("touchEnd")
            time.sleep(0.9)
            checks["rerender_no_post_for_b"] = len(posts) == n_posts + 1 and "learn_spam" not in posts[-1]
            checks["rerender_no_orphan_backdrop"] = page.locator(".swipe-bg").count() == 0
            checks["rerender_a_gone"] = page.locator(ra).count() == 0
            page.evaluate("() => { window.__sfDelay = 0; }")
            if shots:
                page.screenshot(path=f"{shots}/swipe-6-rerender.png")
            # B still swipes normally afterwards.
            bb = row_box(rb)
            x0 = min(bb["x"] + bb["w"] * 0.7, 390 - 30)
            drag(x0, bb["y"], x0 - bb["w"] * 0.6, bb["y"] + 2, end=False)
            with page.expect_response(lambda r: r.url.endswith("/mail/action")):
                touch("touchEnd")
            checks["b_swipes_afterwards"] = "learn_spam" in posts[-1]
            time.sleep(0.8)

        # 6. Dangerous mail (seeded by the caller): an administrator's swipe asks
        #    first (server confirm dialog); the row snaps back, "Frigiv alligevel" releases it.
        tsel = "li.mail-row[data-swipe-right]:has(.threat-badge)"
        if page.locator(tsel).count():
            tkey = page.eval_on_selector(tsel, "n => n.getAttribute('data-row')")
            trow = f'li[data-row="{tkey}"]'
            b = row_box(trow)
            drag(b["x"], b["y"], b["x"] + b["w"] * 0.6, b["y"] + 2, end=False)
            with page.expect_response(lambda r: r.url.endswith("/mail/action")) as resp:
                touch("touchEnd")
            checks["threat_needs_confirm"] = resp.value.status == 409
            page.wait_for_selector("#sf-confirm[open]", timeout=3000)
            checks["threat_dialog"] = "farlig" in page.locator("#sf-confirm").inner_text().lower()
            time.sleep(0.5)
            checks["threat_row_snapped_back"] = page.locator(trow).count() == 1 and not page.eval_on_selector(
                trow, "n => n.classList.contains('is-swiping')") and page.locator(".swipe-bg").count() == 0
            if shots:
                page.screenshot(path=f"{shots}/swipe-4-threat-confirm.png")
            page.click("#sf-confirm .btn-danger")
            page.wait_for_timeout(900)
            checks["threat_released_after_ok"] = page.locator(trow).count() == 0

        # 7. Beskeder: an inbox mail swiped left = "Flyt til spam" (mark_spam) with Fortryd;
        #    it stays in the list, now in spam (Frigiv swipe, no left swipe).
        page.goto(base + "/messages")
        page.wait_for_load_state("networkidle")
        msel = "li.mail-row[data-swipe-left]:not([data-swipe-right])"
        checks["messages_inbox_rows"] = page.locator(msel).count()
        if checks["messages_inbox_rows"]:
            mkey = page.eval_on_selector(msel, "n => n.getAttribute('data-row')")
            mrow = f'li[data-row="{mkey}"]'
            b = row_box(mrow)
            x0 = min(b["x"] + b["w"] * 0.7, 390 - 30)
            n_posts = len(posts)
            drag(x0, b["y"], x0 - b["w"] * 0.6, b["y"] + 2, end=False)
            with page.expect_response(lambda r: r.url.endswith("/mail/action")):
                touch("touchEnd")
            checks["mark_spam_posted"] = len(posts) == n_posts + 1 and "mark_spam" in posts[-1]
            page.wait_for_selector(".toast", timeout=3000)
            checks["mark_spam_undo"] = "Fortryd" in page.locator(".toast").last.inner_text()
            time.sleep(0.8)
            checks["mark_spam_rerendered"] = page.locator(mrow).count() == 1 and page.eval_on_selector(
                mrow, "n => n.hasAttribute('data-swipe-right') && !n.hasAttribute('data-swipe-left')")
            if shots:
                page.screenshot(path=f"{shots}/swipe-5-messages.png")
        browser.close()
    # The 409 of a dangerous mail's release is the server asking to confirm (expected).
    out["errors"] = [e for e in out["errors"] if "favicon" not in e and "status of 409" not in e]
    want_true = [k for k, v in checks.items() if v is False]
    ok = not want_true and not out["errors"] and checks.get("swipe_rows", 0) >= 2 and checks.get("release_status") == 200
    out["ok"] = ok
    out["failed"] = want_true
    print(json.dumps(out, ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
