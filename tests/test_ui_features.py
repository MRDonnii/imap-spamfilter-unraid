"""2.1 UI-FEATURES: simple Bruger profile (U8), 'Se som bruger' preview,
navigation, Find en mail (U1), Tjek disse / Ny (U2), Fortryd flytninger
(U3), konto settings (U4), daily digest (U5), Hjælp + welcome (U7) and the
own-password form on Min konto.

Uses the access-matrix fixture of tests/test_ui_access.py: admin (all),
anna (Bruger, bynet, all permissions), bo (Bruger, bynet, no permissions),
cille (Bruger, no mailboxes). Other mailboxes' strings must never leak.
"""

from __future__ import annotations

import json
import re
import time

import pytest

from fakes_ui import post
from test_ui_access import LEAKS_FOR_BYNET_USER, PW, body, client_for, env  # noqa: F401 - fixture
from test_ui_core import INLINE_PATTERNS

import dashboard
import ui_kit as kit
import ui_mail


def audit(env) -> list[dict]:
    path = env.state / "admin-audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


def no_leaks(html: str) -> None:
    for s in LEAKS_FOR_BYNET_USER:
        assert s not in html, f"leaks {s!r}"


def csp_clean(html: str, where: str) -> None:
    for rx, what in INLINE_PATTERNS:
        m = rx.search(html)
        assert m is None, f"{what} on {where}: {html[max(0, m.start() - 60):m.end() + 60]}"


# --------------------------------------------------------------------- navigation


def _sidebar(html: str) -> str:
    """2.10: the navigation = the top bar (menu at the top, account switcher,
    avatar menu with name and role) + the side menu."""
    return html[html.index('<header class="topbar">'):html.index("</aside>")]


def test_admin_nav_is_grouped_by_task(env):
    """2.10 (owner: "Menuen skal inddeles mere pænt og intuitivt"): Oversigt,
    then Post / Filtrering / Sikkerhed / Konti og adgang / System, each with a
    heading, in the side menu, the top menu and the phone's Mere sheet.
    Every admin page is reachable; Hjælp is the (?) in the sidebar foot."""
    admin = client_for(env, "admin")
    html = body(admin.get("/system"))
    side = html[html.index('<nav class="nav"'):html.index("</aside>")]
    groups = re.findall(r'<div class="nav-group" data-nav-group="([a-z]+)">(.*?)</div>(?=<div class="nav-group"|</nav>)',
                        side)
    got = {k: re.findall(r'<a [^>]*href="([^"]+)"', g) for k, g in groups}
    assert got == {"start": ["/"], "post": ["/spam", "/messages", "/find", "/undo"],
                   "filter": ["/rules", "/training", "/ai"], "security": ["/mailcheck", "/dmarc"],
                   "access": ["/accounts", "/users", "/access"], "system": ["/system", "/updates", "/settings"]}
    labels = re.findall(r'<div class="nav-label">([^<]+)</div>', side)
    assert labels == ["Post", "Filtrering", "Sikkerhed", "Konti og adgang", "System"]
    assert "nav-adv" not in html and "Avanceret" not in side  # no hidden group any more
    assert re.search(r'class="nav-link is-active" href="/system"[^>]*aria-current="page"', side)
    assert 'class="icon-btn nav-help" href="/help"' in side  # Hjælp in the foot
    # top menu: Oversigt + one drop-down per group + Hjælp, the active group lit
    top = html[html.index('<nav class="topnav"'):html.index("</nav>", html.index('<nav class="topnav"'))]
    assert re.findall(r'<summary class="fd-top( is-active)?">([^<]+)', top) == [
        ("", "Post"), ("", "Filtrering"), ("", "Sikkerhed"), ("", "Konti og adgang"), (" is-active", "System")]
    assert 'href="/updates"' in top and 'href="/help"' in top
    # phone: four tabs, the rest grouped in the Mere sheet (incl. Hjælp under Konto)
    sheet = html[html.index('<div class="sheet"'):]
    assert re.findall(r'<div class="sheet-group">([^<]+)</div>', sheet) == [
        "Post", "Filtrering", "Sikkerhed", "Konti og adgang", "System", "Konto"]
    for href in ("/undo", "/rules", "/training", "/ai", "/mailcheck", "/dmarc", "/accounts", "/users",
                 "/system", "/updates", "/settings", "/help", "/me"):
        assert f'href="{href}"' in sheet, href
    # Hjælp page lights the (?) button
    side = _sidebar(body(admin.get("/help")))
    assert 'class="icon-btn nav-help is-active"' in side


def test_bruger_nav_only_shows_what_was_given(env):
    anna = _sidebar(body(client_for(env, "anna").get("/")))
    for label in ("Min spam", "Find en mail", "Beskeder", "Regler", "Hjælp", "Min konto"):
        assert label in anna
    assert "Oversigt" not in anna and "Fanget spam" not in anna and "Konti og adgang" not in anna and "Opdateringer" not in anna
    for href in ('href="/accounts"', 'href="/users"', 'href="/training"', 'href="/settings"', 'href="/system"'):
        assert href not in anna
    bo = _sidebar(body(client_for(env, "bo").get("/")))
    assert "Min spam" in bo and "Hjælp" in bo and "Min konto" in bo
    assert 'href="/find"' not in bo and 'href="/messages"' not in bo and 'href="/rules"' not in bo
    # a single mailbox: nothing to switch between, no admin vocabulary
    assert 'class="switcher"' not in bo and "Filtrér" not in bo


def test_bruger_tabbar_is_simple(env):
    html = body(client_for(env, "anna").get("/"))
    bar = html[html.index('<nav class="tabbar"'):]
    assert "Min spam" in bar and "Mere" in bar and 'href="/accounts"' not in bar


# --------------------------------------------------------------------- U8: the simple Bruger home


def test_bruger_home_is_a_short_summary_and_the_list(env):
    html = body(client_for(env, "anna").get("/"))
    assert "ole@bynet.example" in html and "1 mail fanget de sidste 7 dage" in html
    assert "BYNET-EMNE" in html and "Hvorfor?" in html
    assert "Nøgletal" not in html and "kpi" not in html and 'class="score' not in html
    assert "Post de seneste 14 dage" not in html and "Filterets hukommelse" not in html
    # big buttons per permission (Frigiv / Tillad / Bloker), no bulk checkboxes
    assert 'value="release"' in html and 'value="release_allow"' in html and 'value="block"' in html
    assert 'name="items" value="bynet:' in html and "data-select-all" not in html
    assert 'class="btn btn-secondary btn-sm btn-tone' not in html  # normal size, not small
    no_leaks(html)
    csp_clean(html, "/ (anna)")


def test_bruger_without_release_sees_no_buttons(env):
    html = body(client_for(env, "bo").get("/spam"))
    assert "BYNET-EMNE" in html and 'action="/mail/action"' not in html and 'action="/rules/add"' not in html
    no_leaks(html)


def test_bruger_why_reasons_are_plain_without_numbers(env):
    env.conn.execute("UPDATE messages SET symbols=? WHERE message_id='<j1@x>'",
                     (json.dumps([{"n": "RBL_SPAMHAUS_SBL", "s": 4.0}, {"n": "BAYES_SPAM", "s": 5.1}]),))
    env.conn.commit()
    html = body(client_for(env, "anna").get("/"))
    why = html[html.index('class="why-list"'):]
    why = why[:why.index("</ul>")]
    import html as htmlmod
    plain = htmlmod.unescape(why)
    assert "Sendt fra en server, der er kendt for spam" in plain and "Ligner spam, som filteret har set før" in plain
    assert not re.search(r"\d", plain)
    # No technical jargon for a Bruger.
    assert not re.search(r"Bayes|SPF|DKIM|DMARC|URIBL|Spamhaus|Message-ID|\bIP\b", plain)


def test_bruger_why_reasons_group_technical_symbols(env):
    env.conn.execute("UPDATE messages SET symbols=? WHERE message_id='<j1@x>'",
                     (json.dumps([{"n": "R_SPF_SOFTFAIL", "s": 3.0}, {"n": "DMARC_POLICY_REJECT", "s": 2.0},
                                  {"n": "URIBL_BLACK", "s": 4.0}, {"n": "MID_RHS_NOT_FQDN", "s": 1.0},
                                  {"n": "HFILTER_HOSTNAME_UNKNOWN", "s": 1.5}, {"n": "SUBJ_ALL_CAPS", "s": 1.0}]),))
    env.conn.commit()
    html = body(client_for(env, "anna").get("/"))
    why = html[html.index('class="why-list"'):]
    import html as htmlmod
    plain = htmlmod.unescape(why[:why.index("</ul>")])
    assert plain.count("Afsenderen kunne ikke bevise, at mailen er ægte") == 1   # de-duplicated
    assert "Indeholder links til kendte spam- eller svindelsider" in plain
    assert "Emnet råber med store bogstaver" in plain
    assert not re.search(r"Bayes|SPF|DKIM|DMARC|URIBL|Message-ID|HELO|\bIP\b", plain)


# --------------------------------------------------------------------- U8: Se som bruger


def test_preview_renders_exactly_the_users_view_read_only(env):
    admin = client_for(env, "admin")
    seen_before = dashboard.settings_get("spam_seen:anna")
    r = admin.get("/users/anna/preview")
    assert r.status_code == 200 and r.headers["Cache-Control"] == "no-store"
    html = body(r)
    assert "Forhåndsvisning som anna – ingen handlinger mulige" in html
    assert "BYNET-EMNE" in html and "Min spam" in html and "Beskeder" in html
    no_leaks(html)  # only anna's mailboxes
    side = _sidebar(html)
    assert "Konti og adgang" not in side and "anna" in side and "Bruger" in side
    # nothing can be done: no CSRF token anywhere, every control disabled,
    # every form inert, no live polling with the admin's session
    assert 'name="csrf-token"' not in html and 'name="csrf"' not in html
    for tag in re.findall(r"<button\b[^>]*>", html):
        assert " disabled" in tag, tag
    for tag in re.findall(r"<form\b[^>]*>", html):
        assert " inert" in tag and 'method="get"' in tag and 'action="#"' in tag, tag
        assert "data-ajax" not in tag
    for tag in re.findall(r"<input\b[^>]*>", html):
        assert 'type="hidden"' in tag or " disabled" in tag, tag
    assert "data-live=" not in html and "data-fragment=" not in html
    # links stay inside the preview
    assert 'href="/users/anna/preview?p=find"' in html and 'href="/users/anna/preview?p=help"' in html
    assert 'href="/accounts"' not in html
    csp_clean(html, "preview")
    # read-only: no visit stored for anna, audited, admin session untouched
    assert dashboard.settings_get("spam_seen:anna") == seen_before
    rec = [a for a in audit(env) if a["action"] == "user_preview"]
    assert rec and rec[-1]["actor"] == "admin" and rec[-1]["detail"].startswith("anna")
    after = body(admin.get("/users"))
    assert "Konti og adgang" in _sidebar(after) and "Forhåndsvisning" not in after


def test_preview_cannot_perform_actions(env):
    admin = client_for(env, "admin")
    html = body(admin.get("/users/anna/preview?p=spam"))
    assert 'action="/mail/action"' not in html and 'action="/rules/add"' not in html
    # The route itself only reads.
    assert post(admin, "/users/anna/preview", {}).status_code == 405
    assert env.services.calls == [] and getattr(env.services, "tool_calls", []) == []
    rules = env.conn.execute("SELECT COUNT(*) FROM sender_rules").fetchone()[0]
    assert rules == 1


def test_preview_respects_the_users_permissions(env):
    admin = client_for(env, "admin")
    html = body(admin.get("/users/bo/preview?p=messages"))
    assert "Ikke tilgængelig for bo" in html and "BYNET-EMNE" not in html
    html = body(admin.get("/users/bo/preview"))
    assert 'href="/users/bo/preview?p=find"' not in html and "BYNET-EMNE" in html
    html = body(admin.get("/users/anna/preview?p=spam&account=molt"))
    assert "Ikke tilgængelig for anna" in html and "MOLT" not in html
    html = body(admin.get("/users/anna/preview?p=me"))
    assert "Brugerens egne login-indstillinger vises ikke" in html and "/me/2fa/setup" not in html
    html = body(admin.get("/users/cille/preview"))
    assert "ikke adgang til nogen postkasser" in html and "BYNET-EMNE" not in html


def test_preview_is_admin_only_and_never_of_an_admin(env):
    admin = client_for(env, "admin")
    assert admin.get("/users/admin/preview").status_code == 403
    assert admin.get("/users/findes-ikke/preview").status_code == 404
    assert admin.get("/users/anna/preview?p=accounts").status_code == 404
    for who in ("anna", "bo"):
        assert client_for(env, who).get("/users/anna/preview").status_code == 403
    assert env.app.test_client().get("/users/anna/preview").status_code == 302


def test_users_page_offers_preview_only_for_brugere(env):
    html = body(client_for(env, "admin").get("/users"))
    assert 'href="/users/anna/preview"' in html and 'href="/users/admin/preview"' not in html
    assert "Se som bruger" in body(client_for(env, "admin").get("/users/anna"))


# --------------------------------------------------------------------- U1: Find en mail


LIVE = [{"name": "Spamfilter", "label": "Spamfilter", "kind": "filter_junk", "can_move": True, "truncated": False,
         "explanation": "Filterets egen mappe.",
         "hits": [{"uid": 7, "message_id": "<live1@x>", "subject": "Fundet i mappen", "sender": "pakke@post.example",
                   "sender_name": "Pakke", "received_at": int(time.time()), "seen": False, "deleted": False,
                   "known": False, "our_score": 11.0, "can_move": True}]},
        {"name": "INBOX", "label": "Indbakken", "kind": "inbox", "can_move": False, "truncated": False,
         "explanation": "Ligger i indbakken.",
         "hits": [{"uid": 9, "message_id": "<live2@x>", "subject": "Fundet i indbakken", "sender": "pakke@post.example",
                   "sender_name": "Pakke", "received_at": int(time.time()), "seen": True, "deleted": False,
                   "known": False, "our_score": None, "can_move": False}]}]


def test_find_db_first_then_mailbox(env):
    env.services.live_folders = LIVE
    anna = client_for(env, "anna")
    html = body(anna.get("/find?q=BYNET"))
    assert "I filterets historik" in html and "BYNET-EMNE" in html and "Søg også i postkassen" in html
    assert 'class="score' not in html  # no numbers for a Bruger
    no_leaks(html)
    r = post(anna, "/find/search", {"account": "bynet", "q": "Fundet", "days": "30"}, json_reply=False)
    html = body(r)
    assert r.status_code == 200 and "Fundet i mappen" in html and "Flyt til indbakken" in html
    assert "Fundet i indbakken" in html  # anna may see all mail (see_messages)
    assert any(a["action"] == "find_mail" and a["account"] == "bynet" for a in audit(env))
    admin_html = body(client_for(env, "admin").get("/find?q=BYNET&account=bynet"))
    assert 'class="score' in admin_html


def _csrf(client) -> str:
    with client.session_transaction() as s:
        return s.get("csrf", "")


def test_find_nothing_found_gives_hints(env):
    env.services.live_folders = []
    anna = client_for(env, "anna")
    html = body(post(anna, "/find/search", {"account": "bynet", "q": "intet her", "days": "30"}, json_reply=False))
    assert "Ingen mails matcher i postkassen" in html and "Hvor kan den ellers være?" in html
    assert "Prøv en længere periode" in html


def test_find_without_see_messages_hides_the_inbox(env):
    env.services.live_folders = LIVE
    dashboard_perms = ["release"]
    with env.app.test_request_context("/"):
        dashboard.set_user_perms("bo", dashboard_perms, "test")
    bo = client_for(env, "bo")
    html = body(post(bo, "/find/search", {"account": "bynet", "q": "Fundet", "days": "30"}, json_reply=False))
    assert "Fundet i mappen" in html and "Fundet i indbakken" not in html


TRASH = {"name": "Trash", "label": "Papirkurv", "kind": "trash", "can_move": True, "truncated": False,
         "explanation": "Slettet post.",
         "hits": [{"uid": 3, "message_id": "<trash1@x>", "subject": "Fundet Lønseddel TRASH-PRIVAT",
                   "sender": "hr@firma.example", "sender_name": "HR", "received_at": int(time.time()),
                   "seen": True, "deleted": False, "known": False, "our_score": None, "can_move": True}]}


def test_find_without_see_messages_hides_the_trash_too(env):
    env.services.live_folders = LIVE + [TRASH]
    with env.app.test_request_context("/"):
        dashboard.set_user_perms("bo", ["release"], "test")
    bo = client_for(env, "bo")
    html = body(post(bo, "/find/search", {"account": "bynet", "q": "Fundet", "days": "30"}, json_reply=False))
    assert "Fundet i mappen" in html
    assert "TRASH-PRIVAT" not in html and "hr@firma.example" not in html and "Fundet i indbakken" not in html
    anna_html = body(post(client_for(env, "anna"), "/find/search",
                          {"account": "bynet", "q": "Fundet", "days": "30"}, json_reply=False))
    assert "TRASH-PRIVAT" in anna_html          # see_messages: everything


def test_find_live_search_needs_release_or_see_messages(env):
    env.services.live_folders = LIVE + [TRASH]
    bo = client_for(env, "bo")                   # no permissions at all
    n = len(getattr(env.services, "tool_calls", []))
    r = post(bo, "/find/search", {"account": "bynet", "q": "Fundet", "days": "30"}, json_reply=False)
    assert r.status_code == 403 and "TRASH-PRIVAT" not in body(r)
    assert not any(c[0] == "find_mail" and c[-1] for c in getattr(env.services, "tool_calls", [])[n:])
    assert "Søg også i postkassen" not in body(bo.get("/find?q=BYNET"))


def test_find_move_needs_release_and_own_mailbox(env):
    anna = client_for(env, "anna")
    r = post(anna, "/find/move", {"account": "bynet", "folder": "Spamfilter", "message_id": "<live1@x>", "q": "x"})
    assert r.status_code == 200 and r.get_json()["ok"]
    assert ("move_found_to_inbox", "bynet", "Spamfilter", "<live1@x>", "anna") in env.services.tool_calls
    assert any(a["action"] == "find_move" and a["account"] == "bynet" for a in audit(env))
    n = len(env.services.tool_calls)
    assert post(anna, "/find/move", {"account": "molt", "folder": "Junk", "message_id": "<m1@x>"}).status_code == 404
    assert post(client_for(env, "bo"), "/find/move", {"account": "bynet", "folder": "Junk",
                                                     "message_id": "<j1@x>"}).status_code == 403
    assert len(env.services.tool_calls) == n
    assert client_for(env, "anna").get("/find?account=molt&q=MOLT").status_code == 404


def test_find_hints_mention_spamexperts_only_while_it_is_in_front(env):
    import ui_tools

    class Acc:
        imap_host = "mail.scannet.dk"

    class Giga:
        imap_host = "imap.gigahost.dk"
    texts = " ".join(t for _i, t in ui_tools._hints(Acc(), True))
    assert "SpamExperts" in texts and "karantæne" in texts
    # 2.11.1: SpamExperts cancelled (MX no longer there) -> no tip.
    assert "SpamExperts" not in " ".join(t for _i, t in ui_tools._hints(Acc()))
    assert "SpamExperts" not in " ".join(t for _i, t in ui_tools._hints(Acc(), False))
    assert "SpamExperts" not in " ".join(t for _i, t in ui_tools._hints(Giga(), True))


# --------------------------------------------------------------------- U2: Tjek disse, Ny, gennemset


def test_tjek_disse_and_new_chips(env):
    now = int(time.time())
    for i in range(3):
        env.conn.execute("INSERT INTO messages(account, message_id, first_seen, last_seen, current_folder, our_score, "
                         "our_action, sender, subject, received_at, scanned_at, origin, score_version, symbols) "
                         "VALUES('bynet', ?, ?, ?, 'Spamfilter', 8.5, 'moved_to_junk', 'Ven <ven@familie.example>', ?,"
                         " ?, ?, 'inbox_scan', 2, '[]')", (f"<b{i}@x>", now, now, f"Grænse {i}", now, now))
    env.conn.commit()
    admin = client_for(env, "admin")
    html = body(admin.get("/spam"))
    assert "Tjek disse" in html and "Lige over grænsen: 8,5" in html and "Det er spam" in html
    assert "chip-new" in html and "Markér alle som gennemset" in html
    # 'Ny' badge in the nav until the next visit; the visit itself is stored
    assert dashboard.settings_get("spam_seen:admin") is not None
    r = post(admin, "/spam/seen", {"next": "/spam"})
    assert r.status_code == 200
    anna_html = body(client_for(env, "anna").get("/"))
    assert "Tjek disse" in anna_html and "Tæt på grænsen – kig en ekstra gang" in anna_html
    assert "kan godt være en rigtig mail" not in anna_html
    assert "8,5" not in anna_html


def test_tjek_disse_count_on_admin_overview(env):
    html = body(client_for(env, "admin").get("/"))
    assert "Spam fanget" in html and "Sluppet igennem" in html and "Frigivet" in html and "Tjek disse" in html


# --------------------------------------------------------------------- U3: Fortryd flytninger


def test_undo_preview_and_run(env):
    env.conn.execute("UPDATE messages SET moved_to_junk_at=? WHERE message_id='<j1@x>'", (int(time.time()) - 60,))
    env.conn.commit()
    anna = client_for(env, "anna")
    html = body(anna.get("/undo?period=today"))
    assert "Flyt 1 mail tilbage til indbakken" in html and "BYNET-EMNE" in html
    assert 'name="learn"' in html and "checked" not in html[html.index('name="learn"') - 200:html.index('name="learn"') + 50]
    no_leaks(html)
    since, until = re.search(r'name="since" value="(\d+)"', html).group(1), re.search(r'name="until" value="(\d+)"', html).group(1)
    r = post(anna, "/undo/run", {"account": "bynet", "since": since, "until": until})
    data = r.get_json()
    assert data["ok"] and data["redirect"].startswith("/undo/jobs/")
    call = [c for c in env.services.tool_calls if c[0] == "undo_moves"][-1]
    assert call[1] == "bynet" and call[4] == "anna" and call[5] is False  # no learning by default
    job = anna.get(data["redirect"] + ".json").get_json()["job"]
    assert job["percent"] == 50 and job["active"]
    page = body(anna.get(data["redirect"]))
    assert "data-undo-poll" in page and "tools.js" in page
    assert any(a["action"] == "undo_moves" for a in audit(env))
    assert post(anna, "/undo/run", {"account": "molt", "since": since, "until": until}).status_code == 404
    assert client_for(env, "bo").get("/undo").status_code == 403


def test_undo_window_periods():
    import ui_tools

    since, until, label = ui_tools.undo_window("hour", now=10_000)
    assert (since, until, label) == (6_400, 10_000, "den seneste time")
    assert ui_tools.undo_window("custom", "2026-01-02T00:00", "2026-01-01T00:00") == "Slut skal ligge efter start."
    assert "92 dage" in ui_tools.undo_window("custom", "2026-01-01T00:00", "2026-06-01T00:00")


# --------------------------------------------------------------------- U4: konto


def test_account_page_learning_card_and_auto_allow_switch(env):
    admin = client_for(env, "admin")
    html = body(admin.get("/accounts/bynet"))
    assert "Flytter man en mail ud af Spamfilter i mailprogrammet, bliver afsenderen automatisk tilladt" in html
    assert 'action="/accounts/bynet/auto-allow"' in html and 'name="auto_allow_on_rescue"' in html
    r = post(admin, "/accounts/bynet/auto-allow", {})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert env.entry("bynet")["auto_allow_on_rescue"] is False
    assert any(a["action"] == "account_auto_allow" for a in audit(env))
    assert post(client_for(env, "anna"), "/accounts/bynet/auto-allow", {"auto_allow_on_rescue": "1"}).status_code == 403


def test_account_page_threshold_suggestion(env):
    env.services.suggestions = {"bynet": {
        "ok": True, "account": "bynet", "days": 14, "mode": "move", "current": 8.0, "recommended": 9.0,
        "change": "raise", "confidence": "high", "text": "Hæv grænsen til 9,0.", "reasons": ["released_over_current"],
        "counts": {"scored": 100, "released": 2}, "histogram": [], "grid": []}}
    html = body(client_for(env, "admin").get("/accounts/bynet"))
    assert "Forslag til følsomhed" in html and "Brug forslaget" in html and "Hæv grænsen til 9,0." in html


def test_threshold_suggestion_can_be_dismissed_until_it_changes(env):
    """2.8.4: 'Afvis' hides the suggestion on Oversigt and the account page; a
    different suggestion shows again; a stale one is refused."""
    sug = {"ok": True, "account": "bynet", "days": 14, "mode": "move", "current": 8.0, "recommended": 9.0,
           "change": "raise", "confidence": "high", "text": "Hæv grænsen til 9,0.", "reasons": [],
           "counts": {"scored": 100}, "histogram": [], "grid": []}
    env.services.suggestions = {"bynet": dict(sug)}
    admin = client_for(env, "admin")
    html = body(admin.get("/accounts/bynet"))
    assert 'action="/accounts/bynet/threshold-suggestion/dismiss"' in html and "Afvis" in html
    assert post(admin, "/accounts/bynet/threshold-suggestion/dismiss", {"sig": "raise|8.0|8.5"}).status_code == 400
    r = post(admin, "/accounts/bynet/threshold-suggestion/dismiss", {"sig": "raise|8.0|9.0"})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert "Forslag til følsomhed" not in body(admin.get("/accounts/bynet"))
    import ui_mail
    ui_mail._SUGGEST_CACHE.clear()
    assert "Forslag til følsomhed for" not in body(admin.get("/"))
    env.services.suggestions = {"bynet": {**sug, "recommended": 9.5, "text": "Hæv grænsen til 9,5."}}
    assert "Hæv grænsen til 9,5." in body(admin.get("/accounts/bynet"))
    assert post(client_for(env, "anna"), "/accounts/bynet/threshold-suggestion/dismiss",
                {"sig": "raise|8.0|9.5"}).status_code == 403


# --------------------------------------------------------------------- U5: Indstillinger


def test_digest_setting(env):
    admin = client_for(env, "admin")
    html = body(admin.get("/settings"))
    assert "Daglig opsummering" in html and "Settings → Notification Settings" in html
    assert re.search(r'name="digest_enabled"[^>]*checked', html)  # missing = on
    assert post(admin, "/settings/digest", {}).status_code == 200
    assert dashboard.settings_get("digest_enabled") == "0"
    assert post(admin, "/settings/digest", {"digest_enabled": "1"}).status_code == 200
    assert dashboard.settings_get("digest_enabled") == "1"
    assert [a["detail"] for a in audit(env) if a["action"] == "settings_digest"] == ["on=0", "on=1"]
    assert post(client_for(env, "anna"), "/settings/digest", {}).status_code == 403


# --------------------------------------------------------------------- U7: Hjælp + welcome


def test_help_explains_the_folder_moves_simply(env):
    html = body(client_for(env, "anna").get("/help"))
    for s in ("Spamfilter-mappen", "Træk mailen over i mappen Spamfilter", "afsenderen bliver automatisk tilladt",
              "Intet bliver slettet", "Find en mail", "Frigiv (kun denne mail)", "Tillad (også fremover)"):
        assert s in html, s
    # A Bruger: no scores, no admin-only button, no 'webadministrationen'.
    for s in ("score", "Altid igennem", "webadministrationen"):
        assert s not in html, s
    assert 'id="folsomhed"' not in html and "Del vejledningen" not in html
    admin_html = body(client_for(env, "admin").get("/help"))
    assert 'id="folsomhed"' in admin_html and "Del vejledningen" in admin_html
    assert "Altid igennem" in admin_html and "score" in admin_html
    csp_clean(html, "/help")


def test_welcome_card_once_per_user(env):
    anna = client_for(env, "anna")
    assert "Velkommen, anna" in body(anna.get("/"))
    assert post(anna, "/welcome/dismiss", {}).status_code == 200
    assert "Velkommen, anna" not in body(anna.get("/"))
    assert "Velkommen, bo" in body(client_for(env, "bo").get("/"))


# --------------------------------------------------------------------- Min konto: own password


def test_own_password_change(env):
    anna = client_for(env, "anna")
    other = client_for(env, "anna")
    html = body(anna.get("/me"))
    assert 'action="/me/password"' in html and "Skift adgangskode" in html
    new = "en-helt-ny-adgangskode-1"
    r = post(anna, "/me/password", {"current": "forkert", "password": new, "password2": new})
    assert r.status_code == 403
    assert post(anna, "/me/password", {"current": PW, "password": new, "password2": new + "x"}).status_code == 400
    assert post(anna, "/me/password", {"current": PW, "password": "kort", "password2": "kort"}).status_code == 400
    r = post(anna, "/me/password", {"current": PW, "password": new, "password2": new})
    assert r.status_code == 200 and r.get_json()["ok"]
    assert anna.get("/").status_code == 200  # this session stays
    assert other.get("/").status_code == 302  # every other one is logged out
    assert dashboard.check_login("anna", new) is not None
    assert any(a["action"] == "me_password" and a["result"] == "rejected" for a in audit(env))


# --------------------------------------------------------------------- CSP


@pytest.mark.parametrize("who,urls", [
    ("admin", ["/", "/spam", "/find", "/find?q=BYNET", "/undo", "/undo?period=today", "/undo/jobs/1", "/help",
               "/accounts/bynet", "/settings", "/users/anna/preview", "/users/anna/preview?p=find", "/me"]),
    ("anna", ["/", "/spam", "/find", "/find?q=BYNET", "/undo?period=today", "/help", "/me"]),
])
def test_new_pages_are_csp_clean(env, who, urls):
    c = client_for(env, who)
    for url in urls:
        r = c.get(url)
        assert r.status_code == 200, url
        csp_clean(body(r), url)


def test_tools_js_exists_and_is_served(env):
    r = client_for(env, "anna").get("/static/tools.js")
    assert r.status_code == 200 and b"data-undo-poll" in r.get_data()
    html = body(client_for(env, "anna").get("/undo?period=today"))
    assert kit.h("tools.js") in html


# --------------------------------------------------------------------- 2.1 review fixes


def test_bruger_rules_page_is_simple(env):
    env.conn.execute("INSERT INTO sender_rules(account, pattern, kind, created_at, force) "
                     "VALUES('*', '@platform.example', 'allow', 1, 1)")
    env.conn.execute("INSERT INTO sender_rules(account, pattern, kind, created_at) "
                     "VALUES('bynet', 'egen@regel.example', 'block', 1)")
    env.conn.commit()
    html = body(client_for(env, "anna").get("/rules"))
    assert "Tilladte afsendere flyttes ikke til spam. Blokerede afsendere flyttes altid." in html
    for s in ("vælg Altid igennem", "Importér flere", "Træffere", 'name="force"'):
        assert s not in html, s
    # one mailbox: no 'Gælder for' picker, the account goes along hidden
    assert 'name="account" value="bynet"' in html and "Gælder for</" not in html
    # own rules in the table, the administrator's global rules collapsed and read-only
    table, _sep, rest = html.partition("Regler fra administratoren")
    assert "egen@regel.example" in table and "@platform.example" not in table
    assert _sep and "@platform.example" in rest and 'action="/rules/' not in rest.split("</details>")[0]
    no_leaks(html)
    csp_clean(html, "/rules (anna)")
    admin_html = body(client_for(env, "admin").get("/rules"))
    assert "Importér flere" in admin_html and "Træffere" in admin_html and "vælg Altid igennem" in admin_html


def test_row_rerender_keeps_the_single_mailbox_layout(env):
    anna = client_for(env, "anna")
    anna.get("/spam")                                    # starts a visit ('Ny' cut-off)
    k = f"bynet:{kit.token_for('<j1@x>')}"
    data = post(anna, "/mail/action", {"action": "learn_spam", "view": "review", "items": [k]}).get_json()
    row = data["rows"][k]
    assert row and "BYNET-EMNE" in row
    assert 'chip tone-neutral">bynet<' not in row and ">bynet<" not in row


def test_welcome_and_help_tie_auto_allow_to_dragging(env):
    anna = client_for(env, "anna")
    html = body(anna.get("/"))
    assert "Tryk Frigiv for at lægge den tilbage – eller Tillad" in html
    assert "Trækker du den selv tilbage til Indbakken i mailprogrammet, bliver afsenderen tilladt automatisk." in html
    assert "Filteret lærer af det, og afsenderen bliver tilladt." not in html
    # The admin turns auto-allow off for bynet: no promise any more.
    assert post(client_for(env, "admin"), "/accounts/bynet/auto-allow", {}).status_code == 200
    html = body(client_for(env, "anna").get("/"))
    assert "tilladt automatisk" not in html and "Velkommen, anna" in html
    help_html = body(client_for(env, "anna").get("/help"))
    assert "afsenderen bliver automatisk tilladt" not in help_html


def test_auto_allow_events_have_danish_labels():
    import ui_admin
    import ui_mail

    for ev in ("rule_auto_allow", "rule_auto_allow_removed", "rule_auto_allow_skipped"):
        assert ev in ui_admin.EVENT_LABELS and ev in ui_mail.EVENT_INFO
        assert "_" not in ui_admin.EVENT_LABELS[ev][0] and "_" not in ui_mail.EVENT_INFO[ev][0]


def test_user_form_texts_and_labels(env):
    admin = client_for(env, "admin")
    html = body(admin.get("/users/anna"))
    assert "Uden den ser brugeren kun sin fangede spam." in html and "Oversigt og Fanget spam" not in html
    assert "Giver også adgang til Find en mail og Fortryd flytninger." in html
    import dashboard as d
    assert d.access_summary(False, ["molt", "bynet"], ["release"], {"bynet": "Ole · BYnet", "molt": "Molt"}.get) \
        == "Kan se Molt og Ole · BYnet · Må frigive post"


def test_single_mailbox_undo_page_wording(env):
    html = body(client_for(env, "anna").get("/undo"))
    assert "1. Vælg periode" in html and "Vælg postkasse og periode" not in html
    assert "følsomheden" not in html
    assert "følsomheden" in body(client_for(env, "admin").get("/undo"))


def test_bruger_explanation_does_not_rewrite_history_using_a_new_block_rule():
    row = dict(our_action='moved_to_junk', rule_hit=None, symbols='[]')
    reasons = ui_mail.why_reasons(row, dict(id=42, kind='block'))
    assert not any('blokeret' in r.lower() for r in reasons)


def test_bruger_explanation_keeps_a_recorded_block_after_the_rule_is_removed():
    row = dict(our_action='moved_to_junk', rule_hit='block:42', symbols='[]')
    reasons = ui_mail.why_reasons(row)
    assert any('blokeret' in r.lower() for r in reasons)


def test_bruger_explanation_never_claims_an_unrecorded_score_threshold():
    reasons = ui_mail.why_reasons(dict(our_action='none', rule_hit=None, symbols='[]'))
    assert not any('over grænsen' in r for r in reasons)
    assert any('ikke markeret' in r for r in reasons)
