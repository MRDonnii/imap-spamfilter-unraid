"""UI-CORE: mail pages (Oversigt, Fanget spam, Beskeder, detalje, Regler)."""

from __future__ import annotations

import time

import pytest

from fakes_ui import bump, csrf_of, insert_message, login, make_env, post, set_status

import ui_kit as kit  # noqa: E402

SPAM_SYMBOLS = [{"n": "BAYES_SPAM", "s": 5.1, "o": ["99.9%"]},
                {"n": "RBL_SPAMHAUS_ZEN", "s": 3.0, "o": []},
                {"n": "DMARC_POLICY_ALLOW", "s": -0.5, "o": []}]


@pytest.fixture
def env(tmp_path, monkeypatch):
    e = make_env(tmp_path, monkeypatch)
    c = e.conn
    now = int(time.time())
    set_status(c, "bynet", "idle", junk_exists=1, move_method="UIDPLUS")
    set_status(c, "molt", "idle", junk_exists=0)
    set_status(c, "sofie", "paused")
    insert_message(c, "bynet", "<spam1@x>", our_action="moved_to_junk", our_score=14.2,
                   current_folder="Spamfilter", sender="Lotto <win@lotto.example>",
                   subject="Du har vundet", symbols=SPAM_SYMBOLS, rspamd_score=10.2)
    insert_message(c, "bynet", "<spam2@x>", our_action="provider_junk", our_score=None,
                   current_folder="Spamfilter", sender="noreply@pharma.example", subject="Billig medicin",
                   origin="junk_poll")
    insert_message(c, "molt", "<shadow1@x>", our_action="shadow_spam", our_score=7.5,
                   sender="Nyhed <news@shop.example>", subject="Kun i dag", symbols=SPAM_SYMBOLS)
    insert_message(c, "bynet", "<ham1@x>", our_action="none", our_score=-1.2,
                   sender="Mor <mor@familie.dk>", subject="Søndag?")
    insert_message(c, "bynet", "<released@x>", our_action="manual_release", our_score=9.0,
                   user_verdict="ham", sender="bank@bank.example", subject="Kontoudtog")
    insert_message(c, "bynet", "<gone@x>", our_action="moved_to_junk", our_score=11.0,
                   current_folder="gone", subject="Væk")
    insert_message(c, "sofie", "<sofie1@x>", our_action="moved_to_junk", our_score=12.0,
                   current_folder="Spamfilter", sender="spam@sofie.example", subject="Sofies spam")
    insert_message(c, "bynet", "<xss@x>", our_action="moved_to_junk", our_score=20.0,
                   current_folder="Spamfilter", sender='"<img src=x>" <evil@x.example>',
                   subject="<script>alert(1)</script>")
    c.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES('bynet', ?, '<spam1@x>', "
              "'moved_to_junk', 'score=14.2')", (now,))
    for d in range(14):
        bump(c, "bynet", kit.today_str(d), "scanned", 40 + d)
        bump(c, "bynet", kit.today_str(d), "spam_detected", 5 + d % 4)
    bump(c, "bynet", kit.today_str(), "skipped_seen", 2)
    c.commit()
    return e


@pytest.fixture
def admin(env):
    client = env.app.test_client()
    assert login(client).status_code == 302
    return client


@pytest.fixture
def sofie(env):
    client = env.app.test_client()
    assert login(client, "sofie").status_code == 302
    return client


def key(account, mid):
    return f"{account}:{kit.token_for(mid)}"


# --------------------------------------------------------------------- Oversigt


def test_overview_admin(admin):
    html = admin.get("/").get_data(as_text=True)
    assert "Nøgletal" in html and "Spam fanget" in html and "Frigivet" in html
    assert "chart-svg" in html  # 14-day chart from stats_daily
    for name in ("bynet", "molt", "sofie"):
        assert f'id="acct-{name}"' in html
    assert "På pause" in html
    assert "Sprunget over i dag: 2 allerede læst" in html
    # molt is in shadow with no Spamfilter folder yet: expected, not an attention item.
    assert "Spamfilter-mappen findes ikke endnu" not in html and "Spamfilter-mappen mangler" not in html
    # bynet filters, molt only monitors: no "all protected" claim, a way to switch.
    assert "1 af 2 postkasser filtreres" in html and "er beskyttet" not in html
    assert "Aktivér filtrering" in html
    assert "Du har vundet" in html  # recent spam list
    assert 'data-fragment="/fragments/bayes"' in html
    assert "1 filtrerer" in html and "1 overvåger" in html


def test_overview_hero_problem_states(env, admin):
    set_status(env.conn, "bynet", "auth_failed", detail="Mailserveren afviser adgangskoden")
    env.conn.commit()
    html = admin.get("/").get_data(as_text=True)
    assert "1 postkasse kræver opmærksomhed" in html
    assert "Login fejler for bynet" in html
    assert "Opdater adgangskoden" in html


def test_overview_all_protected(env, admin):
    for a in env.engine.accounts:
        a.mode, a.enabled = "move", True
    set_status(env.conn, "molt", "idle", junk_exists=1)
    set_status(env.conn, "sofie", "idle", junk_exists=1)
    env.conn.commit()
    html = admin.get("/").get_data(as_text=True)
    assert "Alle 3 postkasser er beskyttet" in html


def test_overview_stale_account(env, admin):
    set_status(env.conn, "molt", "idle", last_loop_at=int(time.time()) - 3 * 3600,
               updated_at=int(time.time()) - 3 * 3600)
    env.conn.commit()
    assert "Svarer ikke" in admin.get("/").get_data(as_text=True)


def test_overview_scoped_user_sees_only_own(sofie):
    # A Bruger's home is the simple "Min spam" page: own mailbox only, no KPIs.
    html = sofie.get("/").get_data(as_text=True)
    assert "Min spam" in html and 'class="home-summary"' in html
    assert "acct-bynet" not in html and "ole@bynet.example" not in html and "Nøgletal" not in html
    assert "Du har vundet" not in html and "Sofies spam" in html


def test_overview_account_filter_and_period(admin):
    html = admin.get("/?account=molt&period=7d").get_data(as_text=True)
    assert 'id="acct-molt"' in html and 'id="acct-bynet"' not in html
    assert "De seneste 7 dage" in html


def test_bayes_fragment(env, admin):
    html = admin.get("/fragments/bayes").get_data(as_text=True)
    assert "Spam lært" in html and "Legitim lært" in html and "200" in html
    env.services.bayes = {"ok": False}
    assert "rspamd svarer ikke" in admin.get("/fragments/bayes").get_data(as_text=True)


def test_api_status(admin, sofie):
    data = admin.get("/api/status").get_json()
    names = [a["name"] for a in data["accounts"]]
    assert names == ["bynet", "molt", "sofie"]
    anna = data["accounts"][0]
    assert anna["state"] == "idle" and anna["mode_label"] == "Filtrér" and anna["today"]["scanned"] == 40
    assert data["live"]["acct-bynet-dot"]["tone"] == "ok"
    assert data["live"]["acct-sofie-state"]["text"] == "På pause"
    assert "24h" in data["kpis"]
    scoped = sofie.get("/api/status").get_json()
    assert [a["name"] for a in scoped["accounts"]] == ["sofie"]


# --------------------------------------------------------------------- Fanget spam


def test_spam_page_lists_caught_mail(admin):
    html = admin.get("/spam").get_data(as_text=True)
    assert "Du har vundet" in html            # our move
    assert "Billig medicin" in html           # provider junk
    assert "Kun i dag" in html                # shadow
    assert "Søndag?" not in html              # legit
    assert "Kontoudtog" not in html           # released (ham verdict)
    assert ">Væk<" not in html                # gone from mailbox
    assert "Lært af filteret" in html or "Bayes" in html  # humanized reasons
    assert 'data-bulkbar="bulk-spam"' in html
    assert "Frigiv og tillad afsender" in html


def test_spam_page_escapes_mail_content(admin):
    html = admin.get("/spam").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=x>" not in html


def test_spam_filters(admin):
    html = admin.get("/spam?source=provider").get_data(as_text=True)
    assert "Billig medicin" in html and "Du har vundet" not in html
    html = admin.get("/spam?source=shadow").get_data(as_text=True)
    assert "Kun i dag" in html and "Billig medicin" not in html
    html = admin.get("/spam?q=lotto").get_data(as_text=True)
    assert "Du har vundet" in html and "Billig medicin" not in html
    html = admin.get("/spam?account=molt").get_data(as_text=True)
    assert "Kun i dag" in html and "Du har vundet" not in html
    html = admin.get("/spam?q=%25").get_data(as_text=True)  # LIKE wildcard is literal
    assert "Ingen spam matcher" in html


def test_spam_scoped(sofie):
    html = sofie.get("/spam").get_data(as_text=True)
    assert "Sofies spam" in html and "Du har vundet" not in html
    html = sofie.get("/spam?account=bynet").get_data(as_text=True)  # not allowed: ignored
    assert "Du har vundet" not in html


def test_spam_empty_state(env, admin):
    env.conn.execute("DELETE FROM messages")
    env.conn.commit()
    html = admin.get("/spam?period=all").get_data(as_text=True)
    assert "Ingen spam her" in html


# --------------------------------------------------------------------- Beskeder


def test_messages_pagination_without_cap(env, admin):
    c = env.conn
    base = int(time.time()) - 10_000
    for i in range(120):
        insert_message(c, "molt", f"<bulk{i}@x>", subject=f"Bulk {i:03d}", scanned_at=base + i,
                       received_at=base + i, our_score=float(i % 12))
    c.commit()
    html = admin.get("/messages?account=molt").get_data(as_text=True)
    assert html.count('class="mail-row') == 50
    assert "121 beskeder" in html and "side 1 af 3" in html
    html = admin.get("/messages?account=molt&page=3").get_data(as_text=True)
    assert html.count('class="mail-row') == 21
    assert "Bulk 000" in html


def test_messages_band_relative_to_threshold(admin):
    # molt threshold 6.0 -> 7.5 is over; bynet threshold 8.0 -> 9.0 (released) is over too.
    html = admin.get("/messages?band=over").get_data(as_text=True)
    assert "Kun i dag" in html and "Søndag?" not in html
    html = admin.get("/messages?band=neg").get_data(as_text=True)
    assert "Søndag?" in html and "Kun i dag" not in html
    html = admin.get("/messages?result=legit").get_data(as_text=True)
    assert "Søndag?" in html and "Du har vundet" not in html


def test_messages_search_by_message_id(admin):
    html = admin.get("/messages?q=ham1").get_data(as_text=True)
    assert "Søndag?" in html and "Du har vundet" not in html


# --------------------------------------------------------------------- Besked-detalje


def test_detail_page_junk_mail(admin):
    r = admin.get(f"/messages/bynet/{kit.token_for('<spam1@x>')}")
    html = r.get_data(as_text=True)
    assert r.status_code == 200
    assert "Du har vundet" in html
    assert "Lært af filteret" in html or kit.explain_symbol("BAYES_SPAM") in html
    assert "BAYES_SPAM" in html and "99.9%" in html
    assert "Flyttet til Spamfilter-mappen" in html  # timeline event
    assert "gauge" in html
    assert ">Frigiv<" in html and "Flyt til spam" not in html
    # 2.3: one Tillad / one Bloker; the dialog asks "Kun denne adresse" or "Hele domænet".
    assert "Tillad afsender" in html and "Bloker afsender" in html and "Bloker domæne" not in html
    assert "win@lotto.example" in html and "hele domænet lotto.example" in html


def test_detail_page_inbox_mail_actions(admin):
    html = admin.get(f"/messages/bynet/{kit.token_for('<ham1@x>')}").get_data(as_text=True)
    assert "Flyt til spam" in html and "Lær som legitim" in html
    assert ">Frigiv<" not in html


def test_detail_old_scoring_is_greyed(env, admin):
    insert_message(env.conn, "bynet", "<old@x>", our_score=5.0, score_version=None, subject="Gammel")
    env.conn.commit()
    html = admin.get(f"/messages/bynet/{kit.token_for('<old@x>')}").get_data(as_text=True)
    assert "gammel scoring" in html and "is-greyed" in html


def test_detail_scope_and_bad_tokens(admin, sofie):
    assert sofie.get(f"/messages/bynet/{kit.token_for('<spam1@x>')}").status_code == 404
    assert sofie.get(f"/messages/sofie/{kit.token_for('<sofie1@x>')}").status_code == 200
    assert admin.get("/messages/bynet/!!!").status_code == 404
    assert admin.get(f"/messages/bynet/{kit.token_for('<nope@x>')}").status_code == 404


# --------------------------------------------------------------------- mail actions


def test_bulk_release_groups_per_account(env, admin):
    items = [key("bynet", "<spam1@x>"), key("molt", "<shadow1@x>"), key("bynet", "<spam2@x>")]
    r = post(admin, "/mail/action", {"action": "release", "view": "spam", "items": items, "nonce": "n1"})
    data = r.get_json()
    assert r.status_code == 200 and data["ok"] is True
    assert data["message"] == "3 beskeder frigivet"
    calls = sorted((a, tuple(ids), act) for a, ids, act, _ in env.services.calls)
    assert calls == [("bynet", ("<spam1@x>", "<spam2@x>"), "release"), ("molt", ("<shadow1@x>",), "release")]
    assert all(actor == "admin" for *_, actor in env.services.calls)
    assert data["rows"] == {k: None for k in items}  # removed from the spam list
    row = env.conn.execute("SELECT our_action, user_verdict FROM messages WHERE message_id='<spam1@x>'").fetchone()
    assert tuple(row) == ("manual_release", "ham")
    audits = [a for a in env.audit() if a["action"] == "mail_release"]
    assert len(audits) == 3 and audits[0]["message_id"]


def test_partial_failure_reports_per_item(env, admin):
    env.services.fail_ids = {"<spam2@x>"}
    items = [key("bynet", "<spam1@x>"), key("bynet", "<spam2@x>")]
    data = post(admin, "/mail/action", {"action": "release", "view": "spam", "items": items}).get_json()
    assert data["ok"] is True and data["message"] == "1 af 2 beskeder frigivet"
    failed = [x for x in data["results"] if not x["ok"]]
    assert failed[0]["code"] == "not_found" and "findes ikke længere" in failed[0]["text"]
    assert "formentlig slettet" in failed[0]["text"]
    # The vanished mail is marked gone and leaves the spam list too.
    assert data["rows"] == {items[0]: None, items[1]: None}
    cf = env.conn.execute("SELECT current_folder FROM messages WHERE message_id='<spam2@x>'").fetchone()[0]
    assert cf == "gone"


def test_mail_action_respects_scope(env, sofie):
    items = [key("bynet", "<spam1@x>"), key("sofie", "<sofie1@x>")]
    data = post(sofie, "/mail/action", {"action": "release", "view": "spam", "items": items}).get_json()
    assert [c[0] for c in env.services.calls] == ["sofie"]
    # Another mailbox's mail is reported exactly like a mail that does not exist.
    hidden = [x for x in data["results"] if x["code"] == "not_found"]
    assert len(hidden) == 1 and hidden[0]["message_id"] == "" and "spam1" not in str(data)


def test_mail_action_is_idempotent(env, admin):
    form = {"action": "learn_spam", "view": "spam", "items": [key("bynet", "<spam1@x>")], "nonce": "same-nonce"}
    first = post(admin, "/mail/action", form).get_json()
    second = post(admin, "/mail/action", form).get_json()
    assert len(env.services.calls) == 1
    assert first["ok"] and second["ok"] and "allerede" in second["message"]


def test_mail_action_hides_exception_text(env, admin):
    env.services.raise_on_action = True
    r = post(admin, "/mail/action", {"action": "release", "view": "spam", "items": [key("bynet", "<spam1@x>")]})
    body = r.get_data(as_text=True)
    assert r.get_json()["ok"] is False
    assert "secret-detail" not in body and "exploded" not in body


def test_release_and_allow_adds_rule(env, admin):
    data = post(admin, "/mail/action", {"action": "release_allow", "view": "spam",
                                        "items": [key("bynet", "<spam1@x>")]}).get_json()
    assert data["ok"] and "tilladt" in data["message"]
    rule = env.conn.execute("SELECT account, pattern, kind FROM sender_rules").fetchone()
    assert tuple(rule) == ("bynet", "win@lotto.example", "allow")


def test_learn_spam_rerenders_row(env, admin):
    k = key("molt", "<shadow1@x>")
    data = post(admin, "/mail/action", {"action": "learn_spam", "view": "spam", "items": [k]}).get_json()
    assert "Bekræftet spam" in data["rows"][k]


def test_mail_action_validation(admin):
    assert post(admin, "/mail/action", {"action": "delete", "items": ["x"]}).get_json()["ok"] is False
    assert "Vælg mindst" in post(admin, "/mail/action", {"action": "release"}).get_json()["message"]
    many = [key("bynet", f"<m{i}@x>") for i in range(201)]
    assert "Højst 200" in post(admin, "/mail/action", {"action": "release", "items": many}).get_json()["message"]


def test_mail_action_without_js_redirects_with_flash(env, admin):
    r = admin.post("/mail/action", data={"action": "release", "view": "spam", "next": "/spam",
                                         "items": [key("bynet", "<spam1@x>")], "csrf": csrf_of(admin)})
    assert r.status_code == 302 and r.headers["Location"] == "/spam"
    assert "1 besked frigivet" in admin.get("/spam").get_data(as_text=True)


# --------------------------------------------------------------------- Regler


def test_rules_add_preview_delete(env, admin):
    p = admin.get("/rules/preview?pattern=FIRMA.dk&account=*").get_json()
    assert p["tone"] == "ok" and "@firma.dk" in p["text"] and "underdomæner" in p["text"]
    bad = admin.get("/rules/preview?pattern=ikke%20gyldig").get_json()
    assert bad["tone"] == "bad"
    hits = admin.get("/rules/preview?pattern=@lotto.example&account=bynet").get_json()
    assert hits["matches"] == 1
    r = post(admin, "/rules/add", {"kind": "block", "pattern": "@lotto.example", "account": "*", "note": "Lotteri"})
    assert r.get_json()["ok"] and r.get_json()["refresh"]
    html = admin.get("/rules").get_data(as_text=True)
    assert "@lotto.example" in html and "Lotteri" in html and "Alle konti" in html
    rid = env.conn.execute("SELECT id FROM sender_rules").fetchone()[0]
    again = admin.get("/rules/preview?pattern=@lotto.example&account=*").get_json()
    assert "erstatter" in again["text"]
    d = post(admin, f"/rules/{rid}/delete").get_json()
    assert d["ok"] and d["rows"] == {f"rule:{rid}": None}
    assert env.conn.execute("SELECT COUNT(*) FROM sender_rules").fetchone()[0] == 0
    assert [a["action"] for a in env.audit()][-2:] == ["rule_add", "rule_delete"]


def test_rules_import_multiple_lines(env, admin):
    text = "# kommentar\n@a.example\nb@b.example\nikke gyldig\n\n"
    data = post(admin, "/rules/add", {"kind": "block", "patterns": text, "account": "bynet"}).get_json()
    assert data["ok"] and data["message"] == "2 regler tilføjet, 1 ugyldige linjer sprunget over"
    pats = {r[0] for r in env.conn.execute("SELECT pattern FROM sender_rules WHERE account='bynet'")}
    assert pats == {"@a.example", "b@b.example"}


def test_rules_scope_for_account_user(env, sofie):
    r = post(sofie, "/rules/add", {"kind": "allow", "pattern": "x@y.dk", "account": "*"})
    assert r.status_code == 403
    r = post(sofie, "/rules/add", {"kind": "allow", "pattern": "x@y.dk", "account": "bynet"})
    assert r.status_code == 404  # someone else's mailbox: not revealed
    assert post(sofie, "/rules/add", {"kind": "allow", "pattern": "x@y.dk", "account": "sofie"}).get_json()["ok"]
    env.engine.add_sender_rule(env.conn, "*", "@global.example", "block")
    env.engine.add_sender_rule(env.conn, "bynet", "@other.example", "block")
    env.conn.commit()
    html = sofie.get("/rules").get_data(as_text=True)
    assert "@global.example" in html and "@other.example" not in html and "x@y.dk" in html
    gid = env.conn.execute("SELECT id FROM sender_rules WHERE account='*'").fetchone()[0]
    assert post(sofie, f"/rules/{gid}/delete").status_code == 403
    assert 'value="*"' not in html  # no "Alle konti" option for scoped users


def test_rules_empty_state(admin):
    assert "Ingen regler endnu" in admin.get("/rules").get_data(as_text=True)


def test_timeline_details_are_humanised():
    """Engine event details are technical English; the timeline shows Danish
    and hides bare IMAP UIDs (INTEGRATOR)."""
    import ui_mail

    assert ui_mail._human_detail("score=17.50") == "Score 17,5"
    assert ui_mail._human_detail("uid=5 -> Spamfilter") == "Til Spamfilter"
    assert ui_mail._human_detail("uid=4") == ""
    assert ui_mail._human_detail("metode=UIDPLUS") == "Metode UIDPLUS"
    assert ui_mail._human_detail("bootstrap job=3") == "Træningsjob #3"
    assert ui_mail._human_detail("confirmed by junk poll") == "Bekræftet ved kontrol af Spamfilter-mappen"


def test_detail_location_names_the_provider_folder(env, admin):
    """A 'Fanget af udbyder' mail lies in the provider's Junk, not in the
    Spamfilter folder: Placering says so (review fix)."""
    insert_message(env.conn, "bynet", "<prov@x>", our_action="provider_junk", our_score=None,
                   current_folder="Junk", origin="junk_poll", subject="Udbyder")
    env.conn.commit()
    html = admin.get(f"/messages/bynet/{kit.token_for('<prov@x>')}").get_data(as_text=True)
    assert "Udbyderens spam-mappe (Junk)" in html and ">Frigiv<" in html
    html = admin.get(f"/messages/bynet/{kit.token_for('<spam1@x>')}").get_data(as_text=True)
    assert "Spamfilter-mappen (Spamfilter)" in html


def test_replayed_nonce_of_a_failed_action_reports_the_failure(env, admin):
    env.services.fail_ids = {"<spam1@x>"}
    form = {"action": "release", "view": "spam", "items": [key("bynet", "<spam1@x>")], "nonce": "fail-nonce"}
    first = post(admin, "/mail/action", form).get_json()
    second = post(admin, "/mail/action", form).get_json()
    assert first["ok"] is False
    assert second["ok"] is False and "allerede udført" not in second["message"]


def test_block_domain_not_offered_for_freemail(env, admin):
    insert_message(env.conn, "bynet", "<gm@x>", our_action="moved_to_junk", our_score=12.0,
                   current_folder="Spamfilter", sender="Spammer <someone@gmail.com>", subject="Hej")
    env.conn.commit()
    html = admin.get(f"/messages/bynet/{kit.token_for('<gm@x>')}").get_data(as_text=True)
    assert "Bloker afsender" in html and "Bloker domæne" not in html
    assert "gmail.com er en stor mailtjeneste, så reglen gælder kun adressen." in html
    assert "hele domænet gmail.com" not in html
    # The dialog behind the button offers only the address (2.3).
    d = post(admin, "/rules/add", {"kind": "block", "pattern": "someone@gmail.com", "account": "bynet",
                                   "choose": "1", "view": "detail", "item": key("bynet", "<gm@x>")}).get_json()
    dlg = d["dialog"]["html"]
    assert re.search(r'value="domain"[^>]*disabled', dlg) and "stor mailtjeneste" in dlg


# --------------------------------------------------------------------- one-click row buttons (Tillad / Bloker / Fjern)

import re  # noqa: E402


def row_of(html, k):
    """The <li> (mail list) or <tr> (rules) whose data-row is k."""
    m = re.search(r'<(li|tr)[^>]*data-row="' + re.escape(k) + r'"', html)
    assert m, f"row {k} not found"
    tag = m.group(1)
    return html[m.start():html.index(f"</{tag}>", m.start())]


def forms_in(fragment):
    return re.findall(r'<form method="post" action="([^"]+)"[^>]*>(.*?)</form>', fragment, re.S)


def test_spam_rows_have_release_allow_and_block_buttons(admin):
    html = admin.get("/spam").get_data(as_text=True)
    row = row_of(html, key("bynet", "<spam1@x>"))
    acts = forms_in(row)
    mail = [body for url, body in acts if url == "/mail/action"]
    assert any('name="action" value="release"' in b and "data-confirm" not in b for b in mail)
    allow = [b for b in mail if 'value="release_allow"' in b]
    assert allow and "Tillad afsender" in allow[0] and "data-confirm" not in allow[0]
    assert 'name="choose" value="1"' in allow[0]  # 2.3: asks address or domain first
    block = [b for url, b in acts if url == "/rules/add"]
    assert len(block) == 1 and 'name="kind" value="block"' in block[0]
    assert 'name="pattern" value="win@lotto.example"' in block[0] and 'name="account" value="bynet"' in block[0]
    assert 'name="choose" value="1"' in block[0] and "Bloker afsender" in block[0]
    assert "data-confirm=" not in block[0]  # the dialog replaces the plain confirm
    assert 'name="csrf"' in row and 'data-sync-key="lotto.example"' in row
    # The bulk bar stays for power users.
    assert 'data-bulkbar="bulk-spam"' in html and "Frigiv og tillad afsender" in html


def test_existing_rule_shows_chip_and_remove_button(env, admin):
    rid = env.engine.add_sender_rule(env.conn, "bynet", "win@lotto.example", "allow", "Kendt", "admin")
    env.engine.add_sender_rule(env.conn, "*", "@pharma.example", "block")
    env.conn.commit()
    html = admin.get("/spam").get_data(as_text=True)
    row = row_of(html, key("bynet", "<spam1@x>"))
    assert 'class="chip rule-chip tone-ok"' in row and "Tilladt" in row
    assert f'action="/rules/{rid}/delete"' in row and "Fjern tilladelse" in row
    assert 'value="release_allow"' not in row  # replaced by "Fjern tilladelse"
    assert "Bloker afsender" in row  # an account block would still override
    prow = row_of(html, key("bynet", "<spam2@x>"))
    assert "rule-chip tone-bad" in prow and "Blokeret" in prow and "Fjern blokering" in prow
    assert "Bloker afsender" not in prow


def test_global_rule_is_not_removable_by_scoped_user(env, admin, sofie):
    gid = env.engine.add_sender_rule(env.conn, "*", "@sofie.example", "block")
    env.conn.commit()
    row = row_of(sofie.get("/spam").get_data(as_text=True), key("sofie", "<sofie1@x>"))
    assert "Blokeret" in row and f"/rules/{gid}/delete" not in row
    assert "Fjern blokering" not in row and "Bloker afsender" not in row
    row = row_of(admin.get("/spam").get_data(as_text=True), key("sofie", "<sofie1@x>"))
    assert f"/rules/{gid}/delete" in row


def test_messages_rows_offer_what_fits_and_hide_gone(admin):
    html = admin.get("/messages").get_data(as_text=True)
    inbox = row_of(html, key("bynet", "<ham1@x>"))
    assert 'value="mark_spam"' in inbox and "Flyt til spam" in inbox
    # Phones show the short label: "Til spam" reads as an action, a bare "Spam" as a status.
    assert '<span class="lbl-short">Til spam</span>' in inbox
    assert 'value="release"' not in inbox
    assert '"/rules/add"' in inbox and 'value="allow"' in inbox and 'value="block"' in inbox
    junk = row_of(html, key("bynet", "<spam1@x>"))
    assert 'value="release"' in junk and 'value="mark_spam"' not in junk
    assert 'value="release_allow"' in junk  # Tillad on a spam-folder row also releases it
    gone = row_of(html, key("bynet", "<gone@x>"))
    assert "Slettet" in gone and "chip-gone" in gone and "<form" not in gone


def test_overview_rows_have_release_and_allow(admin):
    html = admin.get("/").get_data(as_text=True)
    row = row_of(html, key("bynet", "<spam1@x>"))
    assert 'value="release"' in row and 'value="release_allow"' in row
    assert "Bloker afsender" not in row


def test_block_from_row_rerenders_same_sender_rows(env, admin):
    insert_message(env.conn, "bynet", "<spam3@x>", our_action="moved_to_junk", our_score=13.0,
                   current_folder="Spamfilter", sender="Lotto <win@lotto.example>", subject="Igen")
    env.conn.commit()
    k1, k3 = key("bynet", "<spam1@x>"), key("bynet", "<spam3@x>")
    data = post(admin, "/rules/add", {"kind": "block", "pattern": "win@lotto.example", "account": "bynet",
                                      "view": "spam", "next": "/spam", "sync": [k1, k3]}).get_json()
    assert data["ok"] and data["message"] == "win@lotto.example er nu blokeret på bynet"
    assert not data.get("refresh")
    assert set(data["rows"]) == {k1, k3}
    assert all("Blokeret" in data["rows"][k] and "Fjern blokering" in data["rows"][k] for k in (k1, k3))
    rid = env.conn.execute("SELECT id FROM sender_rules WHERE pattern='win@lotto.example'").fetchone()[0]
    assert data["undo"]["url"] == f"/rules/{rid}/delete" and data["undo"]["fields"]["undo"] == "1"
    # Fortryd removes the new rule again and reloads the list.
    u = post(admin, data["undo"]["url"], data["undo"]["fields"]).get_json()
    assert u["ok"] and u["refresh"] and u["message"].startswith("Fortrudt")
    assert env.conn.execute("SELECT COUNT(*) FROM sender_rules").fetchone()[0] == 0
    assert "undo" not in u


def test_allow_over_existing_block_undo_restores_block(env, admin):
    rid = env.engine.add_sender_rule(env.conn, "bynet", "mor@familie.dk", "block", "Ups")
    env.conn.commit()
    data = post(admin, "/rules/add", {"kind": "allow", "pattern": "mor@familie.dk", "account": "bynet",
                                      "view": "messages", "next": "/messages",
                                      "sync": [key("bynet", "<ham1@x>")]}).get_json()
    assert data["ok"] and "Tilladt" in data["rows"][key("bynet", "<ham1@x>")]
    assert data["undo"]["url"] == f"/rules/{rid}/kind" and data["undo"]["fields"]["kind"] == "block"
    post(admin, data["undo"]["url"], data["undo"]["fields"])
    row = env.conn.execute("SELECT kind, note FROM sender_rules WHERE id=?", (rid,)).fetchone()
    assert tuple(row) == ("block", "Ups")


def test_rule_buttons_respect_scope_and_csrf(env, sofie):
    r = post(sofie, "/rules/add", {"kind": "allow", "pattern": "win@lotto.example", "account": "bynet",
                                   "view": "spam"})
    assert r.status_code == 404
    # Rows outside the user's accounts are never rendered back.
    data = post(sofie, "/rules/add", {"kind": "block", "pattern": "spam@sofie.example", "account": "sofie",
                                      "view": "spam", "sync": [key("bynet", "<spam1@x>"),
                                                               key("sofie", "<sofie1@x>")]}).get_json()
    assert data["ok"] and list(data["rows"]) == [key("sofie", "<sofie1@x>")]
    r = sofie.post("/rules/add", data={"kind": "block", "pattern": "x@y.dk", "account": "sofie"})
    assert r.status_code == 400  # no CSRF token
    rid = env.conn.execute("SELECT id FROM sender_rules").fetchone()[0]
    assert sofie.post(f"/rules/{rid}/kind", data={"kind": "allow"}).status_code == 400


def test_rule_kind_switch(env, admin, sofie):
    rid = env.engine.add_sender_rule(env.conn, "bynet", "@lotto.example", "allow", "Lotteri")
    gid = env.engine.add_sender_rule(env.conn, "*", "@global.example", "allow")
    env.conn.commit()
    html = admin.get("/rules").get_data(as_text=True)
    row = row_of(html, f"rule:{rid}")
    assert f'action="/rules/{rid}/kind"' in row and "Skift til Bloker" in row and "Fjern" in row
    data = post(admin, f"/rules/{rid}/kind", {"kind": "block", "view": "rules", "next": "/rules"}).get_json()
    assert data["ok"] and data["message"] == "@lotto.example er nu blokeret på bynet"
    r = env.conn.execute("SELECT kind, note FROM sender_rules WHERE id=?", (rid,)).fetchone()
    assert tuple(r) == ("block", "Lotteri")  # the note survives
    assert "Skift til Tillad" in data["rows"][f"rule:{rid}"] and data["rows"][f"rule:{rid}"].startswith("<tr")
    assert data["undo"]["fields"]["kind"] == "allow"
    assert env.audit()[-1]["action"] == "rule_kind" and env.audit()[-1]["detail"] == "allow->block @lotto.example"
    # On the "Tilladt" tab the switched rule leaves the list.
    data = post(admin, f"/rules/{rid}/kind", {"kind": "allow", "view": "rules", "filter_kind": "block"}).get_json()
    assert data["rows"][f"rule:{rid}"] is None
    # Scoped users cannot touch global rules; bad kinds are refused.
    assert post(sofie, f"/rules/{gid}/kind", {"kind": "block"}).status_code == 403
    assert post(admin, f"/rules/{rid}/kind", {"kind": "delete"}).get_json()["ok"] is False
    assert post(admin, "/rules/99999/kind", {"kind": "block"}).status_code == 404
    # Without JS: redirect back with a flash.
    r = admin.post(f"/rules/{rid}/kind", data={"kind": "block", "next": "/rules?kind=allow",
                                               "csrf": csrf_of(admin)})
    assert r.status_code == 302 and r.headers["Location"] == "/rules?kind=allow"
    assert "er nu blokeret" in admin.get("/rules").get_data(as_text=True)


def test_remove_rule_from_row_with_undo(env, admin):
    rid = env.engine.add_sender_rule(env.conn, "bynet", "win@lotto.example", "allow", "Kendt")
    env.conn.commit()
    k = key("bynet", "<spam1@x>")
    data = post(admin, f"/rules/{rid}/delete", {"view": "spam", "next": "/spam", "sync": [k]}).get_json()
    assert data["ok"] and data["message"] == "Tilladelsen af win@lotto.example er fjernet"
    assert "Tilladt" not in data["rows"][k] and 'value="release_allow"' in data["rows"][k]
    assert data["undo"]["url"] == "/rules/add"
    back = post(admin, "/rules/add", data["undo"]["fields"]).get_json()
    assert back["ok"] and back["refresh"]
    r = env.conn.execute("SELECT account, kind, note FROM sender_rules WHERE pattern='win@lotto.example'").fetchone()
    assert tuple(r) == ("bynet", "allow", "Kendt")


def test_rule_buttons_without_js_redirect_with_flash(env, admin):
    r = admin.post("/rules/add", data={"kind": "allow", "pattern": "win@lotto.example", "account": "bynet",
                                       "view": "spam", "next": "/spam?source=filter", "csrf": csrf_of(admin)})
    assert r.status_code == 302 and r.headers["Location"] == "/spam?source=filter"
    html = admin.get("/spam?source=filter").get_data(as_text=True)
    assert "win@lotto.example er nu tilladt på bynet" in html
    rid = env.conn.execute("SELECT id FROM sender_rules").fetchone()[0]
    r = admin.post(f"/rules/{rid}/delete", data={"view": "spam", "next": "/spam", "csrf": csrf_of(admin)})
    assert r.status_code == 302 and r.headers["Location"] == "/spam"
    r = admin.post(f"/rules/{rid}/delete", data={"next": "//evil.example", "csrf": csrf_of(admin)})
    assert r.headers["Location"] == "/rules"


def test_release_offers_undo_only_when_it_is_a_true_undo(env, admin):
    k = key("bynet", "<spam1@x>")
    data = post(admin, "/mail/action", {"action": "release", "view": "spam", "items": [k], "nonce": "u1"}).get_json()
    assert data["undo"]["fields"]["action"] == "mark_spam" and data["undo"]["fields"]["items"] == [k]
    u = post(admin, "/mail/action", {**data["undo"]["fields"], "nonce": "u2"}).get_json()
    assert u["ok"] and u["refresh"] and u["message"].startswith("Fortrudt") and "undo" not in u
    assert env.services.calls[-1][2] == "mark_spam"
    # A shadow mail never left the inbox: moving it to spam would not be an undo.
    data = post(admin, "/mail/action", {"action": "release", "view": "spam",
                                        "items": [key("molt", "<shadow1@x>")]}).get_json()
    assert data["ok"] and "undo" not in data
    # Flyt til spam from the inbox can be undone with Frigiv.
    data = post(admin, "/mail/action", {"action": "mark_spam", "view": "messages",
                                        "items": [key("bynet", "<ham1@x>")]}).get_json()
    assert data["undo"]["fields"]["action"] == "release"


def test_release_allow_undo_restores_the_rule(env, admin):
    k = key("bynet", "<spam1@x>")
    data = post(admin, "/mail/action", {"action": "release_allow", "view": "spam", "items": [k]}).get_json()
    assert data["message"] == "1 besked frigivet – afsenderen er tilladt"
    rid = env.conn.execute("SELECT id FROM sender_rules WHERE pattern='win@lotto.example'").fetchone()[0]
    assert data["undo"]["fields"]["restore_rule"] == [f"{rid}:none"]
    post(admin, "/mail/action", {**data["undo"]["fields"], "nonce": "x"})
    assert env.conn.execute("SELECT COUNT(*) FROM sender_rules").fetchone()[0] == 0
    assert [a["action"] for a in env.audit()][-1] == "rule_restore"


def test_restore_rule_respects_scope(env, sofie):
    gid = env.engine.add_sender_rule(env.conn, "*", "@x.example", "allow")
    env.conn.commit()
    post(sofie, "/mail/action", {"action": "mark_spam", "view": "spam", "undo": "1",
                                 "items": [key("sofie", "<sofie1@x>")], "restore_rule": [f"{gid}:none"]})
    assert env.conn.execute("SELECT COUNT(*) FROM sender_rules WHERE id=?", (gid,)).fetchone()[0] == 1


def test_vanished_mail_is_marked_gone(env, admin):
    env.services.fail_ids = {"<ham1@x>"}
    k = key("bynet", "<ham1@x>")
    r = post(admin, "/mail/action", {"action": "learn_spam", "view": "messages", "items": [k]})
    data = r.get_json()
    assert r.status_code == 422 and data["ok"] is False
    assert data["message"] == "Mailen findes ikke længere i postkassen – den er formentlig slettet."
    assert "Slettet" in data["rows"][k] and "<form" not in data["rows"][k]
    cf = env.conn.execute("SELECT current_folder FROM messages WHERE message_id='<ham1@x>'").fetchone()[0]
    assert cf == "gone"
    html = admin.get(f"/messages/bynet/{kit.token_for('<ham1@x>')}").get_data(as_text=True)
    assert "Ikke længere i postkassen" in html and "formentlig slettet" in html
    assert 'value="mark_spam"' not in html and 'value="learn_spam"' not in html
    assert "Tillad afsender" in html  # the sender can still be allowed/blocked
    # From the detail page the page reloads to show the new state.
    env.services.fail_ids = {"<spam1@x>"}
    d = post(admin, "/mail/action", {"action": "release", "view": "detail",
                                     "items": [key("bynet", "<spam1@x>")]}).get_json()
    assert d["refresh"] is True


def test_detail_button_groups(env, admin):
    html = admin.get(f"/messages/bynet/{kit.token_for('<spam1@x>')}").get_data(as_text=True)
    for label in ("Frigiv", "Lær som spam", "Tillad afsender", "Bloker afsender"):
        assert f">{label}<" in html, label
    assert ">Tillad domæne<" not in html and ">Bloker domæne<" not in html  # 2.3: chosen in the dialog
    assert 'value="win@lotto.example"' in html and 'name="choose" value="1"' in html
    rid = env.engine.add_sender_rule(env.conn, "bynet", "@lotto.example", "allow")
    env.conn.commit()
    html = admin.get(f"/messages/bynet/{kit.token_for('<spam1@x>')}").get_data(as_text=True)
    assert "Tilladt af reglen @lotto.example (bynet)" in html
    assert f'action="/rules/{rid}/delete"' in html and ">Fjern tilladelse<" in html
    assert ">Tillad afsender<" not in html and ">Bloker afsender<" in html
    html = admin.get(f"/messages/bynet/{kit.token_for('<ham1@x>')}").get_data(as_text=True)
    for label in ("Flyt til spam", "Lær som legitim", "Lær som spam"):
        assert f">{label}<" in html, label


def test_detail_page_is_csp_clean(admin):
    html = admin.get(f"/messages/bynet/{kit.token_for('<spam1@x>')}").get_data(as_text=True)
    assert not re.search(r'\sstyle\s*=', html) and "<style" not in html
    assert not re.search(r'\son[a-z]+\s*=\s*"', html, re.I)
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html)


def test_kit_button_tone_and_short_label():
    b = kit.button("Tillad afsender", kind="secondary", size="sm", tone="ok", short="Tillad", icon="check")
    assert 'class="btn btn-secondary btn-sm btn-tone tone-ok"' in b
    assert '<span class="lbl-full">Tillad afsender</span><span class="lbl-short">Tillad</span>' in b
    assert "lbl-short" not in kit.button("Frigiv")
    assert "tone-neutral" in kit.button("x", tone="<evil>")


def test_account_card_spam_counts_unique_mails_in_the_filter_folder(env, admin):
    """Owner 2026-10-22: 'Spam' on a mailbox card = every mail that landed in
    Spamfilter today, each counted ONCE: filter moves (incl. a second
    'confirmed by junk poll' event) plus mails the users moved there; 'Det er
    spam' on a mail the filter already caught is not counted again."""
    import sqlite3
    now = int(time.time())
    c = sqlite3.connect(env.state / "spamfilter.db")
    ev = [("bynet", "<spam1@x>", "moved_to_junk"),      # fixture already has one; a duplicate
          ("bynet", "<spam1@x>", "manual_mark_spam"),   # marked after the filter caught it
          ("bynet", "<drag1@x>", "user_junked"), ("bynet", "<drag2@x>", "user_junked"),
          ("bynet", "<old@x>", "moved_to_junk")]
    for acc, mid, e in ev:
        c.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,'')",
                  (acc, now - 60 if mid != "<old@x>" else now - 3 * 86400, mid, e))
    c.commit()
    c.close()
    html = admin.get("/").get_data(as_text=True)
    card = html.split('id="acct-bynet"', 1)[1].split("</article>", 1)[0]
    assert 'data-live="acct-bynet-spam">3<' in card          # spam1 + drag1 + drag2
    assert "heraf 2 af jer" in card
    assert 'href="/spam?account=bynet"' in card
    sofie_card = html.split('id="acct-sofie"', 1)[1].split("</article>", 1)[0]
    assert 'data-live="acct-sofie-spam">0<' in sofie_card
    assert 'data-live="acct-sofie-spamuser"></small>' in sofie_card


def test_account_card_shows_the_providers_own_spam_folder(env, admin):
    """2.7.2: mail the provider put in its own spam folder (Scannet/SpamExperts -> Junk) is not
    the filter's catch, but the owner wants to see it: a separate line on the card, counted once."""
    import sqlite3
    now = int(time.time())
    c = sqlite3.connect(env.state / "spamfilter.db")
    for mid in ("<p1@x>", "<p2@x>", "<p2@x>", "<p3@x>"):
        c.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES('sofie',?,?,'provider_junk','uid=1')",
                  (now - 60, mid))
    c.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES('sofie',?,?,'provider_junk','uid=9')",
              (now - 3 * 86400, "<old@x>"))
    c.commit()
    c.close()
    html = admin.get("/").get_data(as_text=True)
    sofie_card = html.split('id="acct-sofie"', 1)[1].split("</article>", 1)[0]
    assert "+ 3 i udbyderens spam-mappe" in sofie_card
    assert 'data-live="acct-sofie-spam">0<' in sofie_card       # still not the filter's own catch
