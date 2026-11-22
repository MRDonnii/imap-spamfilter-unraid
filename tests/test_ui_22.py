"""UI-2.2a: Danish texts for the 2.2 rules, Reparér Bayes / lærelister /
rebalancering on Træning, the weekly report under Indstillinger and the
"scannet sent" note on the message detail."""

from __future__ import annotations

import json
import re
import time

import pytest

from fakes_ui import insert_message, login, post, set_status
from fakes_ui_admin import FOLDERS, make_admin_env

import dashboard  # noqa: E402
import ui_admin  # noqa: E402
import ui_kit as kit  # noqa: E402
import ui_mail  # noqa: E402
from test_ui_core import INLINE_PATTERNS  # noqa: E402

SPOOF_SYMS = [{"n": "TH_BRAND_SPOOF", "s": 5.0, "o": []},
              {"n": "TH_FROM_BRAND_NAME", "s": 0.0, "o": ["PostNord"]},
              {"n": "TH_LURE_SUBJECT", "s": 1.5, "o": ["Din pakke venter"]},
              {"n": "TH_LURE_COMBO", "s": 4.0, "o": []},
              {"n": "BAYES_HAM", "s": -3.0, "o": ["99%"]}]
SPOOF_SENDER = "PostNord <noreply@goteamup.com>"
SPOOF_TEXT = "Afsendernavnet udgiver sig for at være PostNord, men mailen kommer fra goteamup.com"


@pytest.fixture
def env(tmp_path, monkeypatch):
    e = make_admin_env(tmp_path, monkeypatch)
    c = e.conn
    set_status(c, "bynet", "idle", junk_exists=1, move_method="UIDPLUS", folders=json.dumps(FOLDERS))
    set_status(c, "molt", "idle", junk_exists=0, move_method="MOVE", folders=json.dumps(FOLDERS))
    set_status(c, "sofie", "paused")
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


def text(resp) -> str:
    return resp.get_data(as_text=True)


def csp_clean(html: str, where: str) -> None:
    for rx, what in INLINE_PATTERNS:
        m = rx.search(html)
        assert m is None, f"{what} on {where}: {html[max(0, m.start() - 80):m.end() + 80]}"


def audits(env, action: str) -> list[dict]:
    return [r for r in env.audit() if r["action"] == action]


# ===================================================================== (1) symbol texts

NEW_SYMBOLS = ["TH_BRAND_SPOOF", "TH_FROM_BRAND_NAME", "TH_FROM_BRAND_DOMAIN", "TH_FROM_NAME_HOMOGLYPH",
               "TH_LURE_SUBJECT", "TH_LURE_COMBO", "TH_FROM_ABUSED_TLD", "TH_FROM_TLD_CN_RU", "TH_OWN_PLATFORM_URIBL",
               "TH_AGED_SCAN", "TH_PROVIDER_AUTH_PASS", "TH_PROVIDER_AUTH_FAIL", "PHISHED_OPENPHISH",
               "PHISHED_PHISHTANK", "PHISHED_EXCLUDED", "RSPAMD_URIBL"]


@pytest.mark.parametrize("name", NEW_SYMBOLS)
def test_every_new_symbol_has_its_own_danish_text(name):
    assert name in kit.SYMBOL_TEXT
    text_ = kit.explain_symbol(name)
    assert text_ != "Spamfilterets egen vurdering" and not text_.startswith("Teknisk regel")
    assert not re.search(r"\b(the|from|with|score)\b", text_, re.I)  # Danish, not English


def test_texts_match_the_engine_wording():
    import filter as engine
    assert kit.SYMBOL_TEXT["TH_OWN_PLATFORM_URIBL"] == engine.OWN_PLATFORM_TEXT
    assert kit.explain_symbol("TH_PROVIDER_AUTH_PASS") == "Udbyderen bekræftede afsenderen ved modtagelsen"
    assert "(DMARC)" in kit.explain_symbol("TH_PROVIDER_AUTH_FAIL")
    assert ui_mail.HAM_GUARD_TEXT == engine.HAM_GUARD_TEXT


def test_brand_spoof_names_brand_and_domain():
    spoof = SPOOF_SYMS[0]
    assert kit.explain_symbol_detail(spoof, symbols=SPOOF_SYMS, sender=SPOOF_SENDER) == SPOOF_TEXT
    # No TH_FROM_BRAND_NAME option: the display name of the From header is used.
    assert kit.explain_symbol_detail(spoof, symbols=[spoof], sender='"MobilePay Kundeservice" <x@mp-hjaelp.top>') == (
        "Afsendernavnet udgiver sig for at være MobilePay Kundeservice, men mailen kommer fra mp-hjaelp.top")
    # Nothing to name: the generic text.
    assert kit.explain_symbol_detail(spoof, symbols=[spoof], sender="x@y.example") == kit.SYMBOL_TEXT["TH_BRAND_SPOOF"]
    # Long names are shortened; quotes never leak into the sentence.
    long = kit.explain_symbol_detail(spoof, symbols=[{"n": "TH_FROM_BRAND_NAME", "s": 0, "o": ['"' + "A" * 80 + '"']}],
                                     sender="a@b.dk")
    assert "…" in long and '"' not in long


def test_detail_texts_for_homoglyph_tld_platform_and_age():
    hom = kit.explain_symbol_detail({"n": "TH_FROM_NAME_HOMOGLYPH", "s": 5, "o": ["ΕasyΡark"]})
    assert hom.startswith("Afsendernavnet “ΕasyΡark” bruger forvekslelige bogstaver")
    tld = kit.explain_symbol_detail({"n": "TH_FROM_ABUSED_TLD", "s": 5, "o": ["lastchance.guru"]})
    assert tld == "Afsenderdomænet lastchance.guru bruger topdomænet .guru, som spammere ofte misbruger"
    cn = kit.explain_symbol_detail({"n": "TH_FROM_TLD_CN_RU", "s": 2, "o": []}, sender="Shop <a@fabrik.cn>")
    assert cn == "Afsenderdomænet fabrik.cn ender på .cn"
    own = kit.explain_symbol_detail({"n": "TH_OWN_PLATFORM_URIBL", "s": -4.5, "o": ["vexar.example"]})
    assert own == "Jeres egen webshop-platform (vexar.example) står fejlagtigt på en domæneliste – udlignet"
    assert "(9 timer efter modtagelsen)" in kit.explain_symbol_detail({"n": "TH_AGED_SCAN", "s": 0, "o": ["alder=9t"]})
    assert "(3 dage efter modtagelsen)" in kit.explain_symbol_detail({"n": "TH_AGED_SCAN", "s": 0, "o": ["alder=75t"]})
    assert kit.explain_symbol_detail({"n": "R_SPF_FAIL", "s": 1, "o": []}) == kit.explain_symbol("R_SPF_FAIL")


def test_plain_bruger_wording():
    assert kit.plain_reason_detail(SPOOF_SYMS[0], symbols=SPOOF_SYMS, sender=SPOOF_SENDER) == (
        "Afsenderen udgiver sig for at være PostNord, men er det ikke")
    assert kit.plain_reason("TH_BRAND_SPOOF") == kit.PLAIN_BRAND
    assert kit.plain_reason("TH_FROM_NAME_HOMOGLYPH") == kit.PLAIN_HOMOGLYPH
    assert kit.plain_reason("TH_LURE_SUBJECT") == kit.PLAIN_LURE
    assert kit.plain_reason("TH_LURE_COMBO") == kit.PLAIN_LURE_COMBO
    assert kit.plain_reason("TH_FROM_ABUSED_TLD") == kit.plain_reason("TH_FROM_TLD_CN_RU") == kit.PLAIN_TLD
    assert kit.plain_reason("PHISHED_OPENPHISH") == kit.PLAIN_PHISH
    assert kit.plain_reason("TH_PROVIDER_AUTH_FAIL") == kit.PLAIN_AUTH
    # Corrections / information are never a "why it is spam" reason.
    for n in ("PHISHED_EXCLUDED", "TH_PROVIDER_AUTH_PASS", "TH_AGED_SCAN", "TH_OWN_PLATFORM_URIBL",
              "TH_FROM_BRAND_NAME", "TH_FROM_BRAND_DOMAIN"):
        assert kit.plain_reason(n) is None, n
    for t in (kit.PLAIN_BRAND, kit.PLAIN_HOMOGLYPH, kit.PLAIN_LURE, kit.PLAIN_LURE_COMBO, kit.PLAIN_TLD, kit.PLAIN_PHISH):
        assert not re.search(r"[A-Z]{2,}_|TH_|rspamd|DMARC|Bayes", t)


def test_why_reasons_for_a_bruger_name_the_brand():
    row = {"our_action": "moved_to_junk", "symbols": json.dumps(SPOOF_SYMS), "sender": SPOOF_SENDER}
    reasons = ui_mail.why_reasons(row)
    assert reasons[0] == "Afsenderen udgiver sig for at være PostNord, men er det ikke"
    assert kit.PLAIN_LURE_COMBO in reasons


def test_spam_list_shows_the_brand_text(env, admin, sofie):
    insert_message(env.conn, "bynet", "<pn@goteamup.com>", our_action="moved_to_junk", our_score=14.5,
                   current_folder="Spamfilter", sender=SPOOF_SENDER, subject="Din pakke venter", symbols=SPOOF_SYMS)
    insert_message(env.conn, "sofie", "<pn2@goteamup.com>", our_action="moved_to_junk", our_score=14.5,
                   current_folder="Spamfilter", sender=SPOOF_SENDER, subject="Din pakke venter", symbols=SPOOF_SYMS)
    env.conn.commit()
    assert SPOOF_TEXT in text(admin.get("/spam?account=bynet"))
    html = text(sofie.get("/spam"))
    assert "Afsenderen udgiver sig for at være PostNord, men er det ikke" in html
    assert "TH_BRAND_SPOOF" not in html and "goteamup.com, men" not in html


# ===================================================================== (4) message detail

def _detail(client, account: str, mid: str):
    return client.get(f"/messages/{account}/{kit.token_for(mid)}")


@pytest.mark.parametrize("auth,expect", [
    ("TH_PROVIDER_AUTH_PASS", "Udbyderen bekræftede afsenderen ved modtagelsen – det tæller lidt til fordel"),
    ("TH_PROVIDER_AUTH_FAIL", "Udbyderen kunne ikke bekræfte afsenderen ved modtagelsen (DMARC) – det tæller imod"),
    (None, "Udbyderen havde ingen godkendelse at give videre"),
])
def test_aged_message_says_provider_auth_was_used(env, admin, auth, expect):
    syms = [{"n": "TH_AGED_SCAN", "s": 0.0, "o": ["alder=26t"]}, {"n": "BAYES_SPAM", "s": 3.0, "o": []}]
    if auth:
        syms.append({"n": auth, "s": -1.0 if auth.endswith("PASS") else 2.0, "o": ["spamexperts"]})
    insert_message(env.conn, "bynet", "<aged@x>", our_action="none", our_score=2.0, rspamd_score=3.0, aged=1,
                   symbols=syms)
    env.conn.commit()
    html = text(_detail(admin, "bynet", "<aged@x>"))
    assert "Scannet sent – udbyderens godkendelse brugt" in html
    assert "(26 timer efter modtagelsen)" in html and expect in html
    csp_clean(html, "aged detail")


def test_fresh_message_has_no_aged_note(env, admin):
    insert_message(env.conn, "bynet", "<fresh@x>", our_action="none", our_score=1.0, aged=0,
                   symbols=[{"n": "R_SPF_ALLOW", "s": -0.2, "o": []}])
    insert_message(env.conn, "bynet", "<old21@x>", our_action="none", our_score=1.0, aged=None, symbols=[])
    env.conn.commit()
    for mid in ("<fresh@x>", "<old21@x>"):
        html = text(_detail(admin, "bynet", mid))
        assert "Scannet sent" not in html and "aged-note" not in html


def test_aged_from_symbol_only_and_is_aged_helper():
    assert ui_mail.is_aged({"aged": 1}, [])
    assert ui_mail.is_aged({"aged": None}, [{"n": "TH_AGED_SCAN", "s": 0, "o": []}])
    assert not ui_mail.is_aged({"aged": 0}, [{"n": "R_SPF_FAIL", "s": 1, "o": []}])


def test_detail_shows_own_corrections_and_brand_text(env, admin):
    syms = [*SPOOF_SYMS, {"n": "RSPAMD_URIBL", "s": 4.5, "o": ["vexar.example:url"]},
            {"n": "TH_OWN_PLATFORM_URIBL", "s": -4.5, "o": ["vexar.example"]}]
    insert_message(env.conn, "bynet", "<own@x>", our_action="moved_to_junk", our_score=12.0, rspamd_score=16.5,
                   current_folder="Spamfilter", sender=SPOOF_SENDER, symbols=syms)
    env.conn.commit()
    html = text(_detail(admin, "bynet", "<own@x>"))
    assert SPOOF_TEXT in html
    assert "Jeres egen webshop-platform (vexar.example) står fejlagtigt på en domæneliste – udlignet" in html
    assert "breakdown breakdown-4" in html and "Egne justeringer" in html
    assert re.search(r"<b>[−-]4,5</b><span>Egne justeringer</span>", html)
    # Without own corrections the breakdown keeps its three columns.
    insert_message(env.conn, "bynet", "<plain@x>", our_action="none", our_score=1.0, rspamd_score=1.0, symbols=[])
    env.conn.commit()
    html = text(_detail(admin, "bynet", "<plain@x>"))
    assert "Egne justeringer" not in html and 'class="breakdown"' in html


def test_ham_guard_event_in_timeline_and_drift(env, admin):
    insert_message(env.conn, "bynet", "<hg@x>", our_action="none", our_score=1.0, symbols=[])
    env.conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES('bynet', ?, '<hg@x>', "
                     "'ham_guard', 'autolearn phishing: TH_BRAND_SPOOF')", (int(time.time()),))
    env.conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES('*', ?, NULL, "
                     "'weekly_report_sent', 'weekly week=2026-W42 full')", (int(time.time()),))
    env.conn.commit()
    html = text(_detail(admin, "bynet", "<hg@x>"))
    assert "Ikke lært som legitim – læringsvagten stoppede det" in html
    assert "Automatisk læring: phishing- eller trusselsregel ramte (TH_BRAND_SPOOF)" in html
    assert ui_mail._human_detail("job=7 blind_score: 6.2") == (
        "Træningsjob #7: scoren uden Bayes og udbyder er 5 eller mere (6.2)")
    drift = text(admin.get("/system"))
    assert "Ugerapport lagt i indbakken" in drift or "Ikke lært som legitim (læringsvagt)" in drift
    for ev in ("own_domain_uribl", "ham_guard", "learn_list_queued", "learn_list_done", "weekly_report_sent",
               "weekly_report_failed"):
        assert ev in ui_admin.EVENT_LABELS
    for a in ("bayes_repair_learn", "bayes_rebalance", "learn_list_cancel", "learn_list_retry", "settings_weekly",
              "weekly_send"):
        assert a in ui_admin.AUDIT_LABELS


# ===================================================================== (2) Træning: Reparér Bayes

def _cand(account: str, mid: str, reasons: list[str], *, learned_as: str | None = "ham", symbols=None,
          subject: str = "Din pakke venter") -> dict:
    return {"account": account, "message_id": mid, "sender": SPOOF_SENDER, "subject": subject, "received_at": 1,
            "folder": "INBOX", "score": 3.4, "learned_as": learned_as, "learned_at": 1, "reasons": reasons,
            "symbols": symbols if symbols is not None else (["TH_BRAND_SPOOF"] if "phishing_rule" in reasons else []),
            "text": "; ".join(reasons), "suggested_kind": "spam"}


@pytest.fixture
def cands(env):
    env.services.repair_items = [
        _cand("bynet", "<phish@x>", ["phishing_rule", "provider_spam"]),
        _cand("molt", "<marked@x>", ["user_marked_spam"], subject="Gratis gave fra Harald Nyborg"),
        _cand("bynet", "<prov@x>", ["provider_spam"], subject="Nyhedsbrev uge 42"),
        _cand("molt", "<never@x>", ["phishing_rule"], learned_as=None, subject="Aldrig lært"),
    ]
    return env.services.repair_items


def _boxes(html: str) -> dict[str, bool]:
    out = {}
    for m in re.finditer(r'<input type="checkbox" class="check" name="pick" value="([^"]+)"[^>]*>', html):
        acc, _s, tok = m.group(1).partition(":")
        out[f"{acc}:{kit.msgid_from_token(tok)}"] = " checked" in m.group(0)
    return out


def test_repair_card_lists_candidates_and_prechecks_only_strong_reasons(env, admin, cands):
    html = text(admin.get("/training"))
    assert "Reparér Bayes" in html and 'id="reparer"' in html
    boxes = _boxes(html)
    assert boxes == {"bynet:<phish@x>": True, "molt:<marked@x>": True, "bynet:<prov@x>": False}
    assert "Phishing-regel: falsk brand" in html
    assert ui_admin._rule_short("PHISHED_OPENPHISH") == "kendt phishing-link"
    assert "Udbyderen: spam" in html and "Markeret som spam" in html
    assert 'data-check-count>2</span> af 3 valgt' in html
    assert "Lær de valgte som spam" in html and 'data-confirm' in html
    assert 'href="/training/rebalance"' in html and "Rebalancér fra spam-mapper" in html
    assert 'data-fragment="/training/bayes?part=ratio"' in html
    csp_clean(html, "/training")


def test_repair_scope_and_account_filter(env, admin, cands):
    html = text(admin.get("/training?repair_scope=all&repair_account=molt"))
    assert set(_boxes(html)) == {"molt:<marked@x>", "molt:<never@x>"}
    assert ("bayes_repair_candidates", "molt", "all", ui_admin.REPAIR_SHOW) in env.services.svc22_calls
    # An unknown account filter is ignored, not an error.
    assert admin.get("/training?repair_account=nope").status_code == 200


def test_repair_empty_state_suggests_a_calibration(env, admin):
    html = text(admin.get("/training"))
    assert "Ingen kandidater lige nu" in html and "Kør en kalibrering af Indbakken" in html
    assert 'href="#kalibrering"' in html and 'id="kalibrering"' in html


def test_repair_learn_queues_only_current_candidates_and_audits(env, admin, cands):
    picks = [f"bynet:{kit.token_for('<phish@x>')}", f"molt:{kit.token_for('<marked@x>')}",
             f"molt:{kit.token_for('<forged@x>')}", f"bynet:{kit.token_for('<phish@x>')}"]
    r = post(admin, "/training/repair/learn", {"pick": picks})
    data = r.get_json()
    assert r.status_code == 200 and data["ok"], data
    assert "1 mail var ikke længere kandidater" in data["message"]
    call = next(c for c in env.services.svc22_calls if c[0] == "queue_learn_list")
    items, actor, kind, note = call[1:]
    assert actor == "admin" and kind == "spam" and note == "Reparér Bayes"
    assert [(i["account"], i["message_id"], i["kind"]) for i in items] == [
        ("bynet", "<phish@x>", "spam"), ("molt", "<marked@x>", "spam")]
    assert items[0]["reason"] == "phishing_rule; provider_spam"
    rec = audits(env, "bayes_repair_learn")[-1]
    assert rec["result"] == "ok" and "learn_list job=1 n=2" in rec["detail"] and "stale=1" in rec["detail"]


def test_repair_learn_refuses_empty_and_stale_selections(env, admin, cands):
    r = post(admin, "/training/repair/learn", {})
    assert r.status_code == 400 and "Vælg mindst én mail" in r.get_json()["message"]
    r = post(admin, "/training/repair/learn", {"pick": [f"bynet:{kit.token_for('<gone@x>')}", "garbage"]})
    assert r.status_code == 400 and "ikke længere kandidater" in r.get_json()["message"]
    assert not any(c[0] == "queue_learn_list" for c in env.services.svc22_calls)
    # Never-learned mail is only accepted in the "all" scope it was shown in.
    never = f"molt:{kit.token_for('<never@x>')}"
    assert post(admin, "/training/repair/learn", {"pick": [never]}).status_code == 400
    r = post(admin, "/training/repair/learn", {"pick": [never], "repair_scope": "all"})
    assert r.status_code == 200 and r.get_json()["ok"]


def test_repair_learn_without_js_redirects_with_flash(env, admin, cands):
    r = post(admin, "/training/repair/learn", {"pick": [f"bynet:{kit.token_for('<phish@x>')}"]}, json_reply=False)
    assert r.status_code == 302 and r.headers["Location"].endswith("/training#laerelister")


def test_bayes_ratio_fragment(env, admin):
    env.services.bayes = {"ok": True, "spam_learned": 256, "ham_learned": 1448, "min_learns": 200, "users": 1}
    html = text(admin.get("/training/bayes?part=ratio"))
    assert "1 spam pr. 5,7 legitime" in html and "tone-bad" in html and "Mål: mindst 1 spam pr. 2 legitime" in html
    assert "bayes-rings" not in html
    env.services.bayes = {"ok": True, "spam_learned": 800, "ham_learned": 1448, "min_learns": 200, "users": 1}
    assert "tone-ok" in text(admin.get("/training/bayes?part=ratio"))
    full = text(admin.get("/training/bayes"))
    assert "bayes-rings" in full and "bayes-ratio" not in full  # the ratio lives on Reparér Bayes
    assert 'href="/training#reparer"' not in full  # 1:1,8 is not skewed
    env.services.bayes = {"ok": True, "spam_learned": 256, "ham_learned": 1448, "min_learns": 200, "users": 1}
    assert 'href="/training#reparer"' in text(admin.get("/training/bayes"))  # skewed: the warning links to it
    env.services.bayes = {"ok": False}
    assert "Forholdet kan ikke hentes" in text(admin.get("/training/bayes?part=ratio"))


@pytest.mark.parametrize("spam,ham,head,tone", [
    (0, 0, "Intet lært endnu", "neutral"), (10, 0, "Ingen legitime lært endnu", "neutral"),
    (0, 50, "Ingen spam lært", "bad"), (100, 300, "1 spam pr. 3,0 legitime", "warn"),
    (300, 200, "1,5 spam pr. legitim", "ok")])
def test_ratio_wording(spam, ham, head, tone):
    html = ui_admin.bayes_ratio_html({"ok": True, "spam_learned": spam, "ham_learned": ham})
    assert f"<b>{head}</b>" in html and f"tone-{tone}" in html


# ===================================================================== lærelister

def _seed_lists(env):
    env.services.learn_lists = {
        1: {"id": 1, "status": "done", "total": 3, "processed": 3, "learned": 1, "already": 0, "not_found": 1,
            "skipped": 0, "failed": 1, "note": "Reparér Bayes", "error": None, "created_by": "admin",
            "created_at": int(time.time()) - 600, "percent": 100, "remaining": 0, "text": "Færdig."},
        2: {"id": 2, "status": "running", "total": 10, "processed": 4, "learned": 4, "already": 0, "not_found": 0,
            "skipped": 0, "failed": 0, "note": "Reparér Bayes", "error": None, "created_by": "admin",
            "created_at": int(time.time()) - 60, "percent": 40, "remaining": 6, "text": "Lærer mails …"}}
    env.services.learn_items = {1: [
        {"job_id": 1, "account": "bynet", "message_id": "<a@x>", "kind": "spam", "status": "learned", "folder": "INBOX",
         "previous": "ham", "reason": "Phishing-regel ramte (TH_BRAND_SPOOF)", "sender": SPOOF_SENDER,
         "subject": "Din pakke venter", "status_text": "Lært"},
        {"job_id": 1, "account": "molt", "message_id": "<b@x>", "kind": "spam", "status": "not_found", "folder": None,
         "previous": None, "reason": "", "sender": None, "subject": None, "status_text": "Mailen findes ikke længere"},
        {"job_id": 1, "account": "molt", "message_id": "<c@x>", "kind": "spam", "status": "failed", "folder": "Junk",
         "previous": None, "reason": "", "sender": "x@y.dk", "subject": "Fejlet", "status_text": "Fejlede"}]}


def test_learn_lists_in_jobs_card_and_live_json(env, admin):
    _seed_lists(env)
    html = text(admin.get("/training"))
    assert 'id="laerelister"' in html and 'data-row="ll:2" data-job-active="1"' in html and 'data-row="ll:1"' in html
    assert "/training/learn-lists/1/retry" in html  # one failed item
    assert "/training/learn-lists/2/cancel" in html and "/training/learn-lists/1/cancel" not in html
    data = admin.get("/training/jobs.json").get_json()
    assert data["active"] is True and {"ll:1", "ll:2"} <= set(data["rows"])
    assert data["rows"]["ll:2"].startswith("<tr") and "4 / 10" in data["rows"]["ll:2"]


def test_learn_list_detail_page(env, admin):
    _seed_lists(env)
    html = text(admin.get("/training/learn-lists/1"))
    assert "Læreliste #1" in html and "Din pakke venter" in html and "Mailen findes ikke længere" in html
    assert "Indbakken" in html  # folder label
    html = text(admin.get("/training/learn-lists/1?status=failed"))
    assert "Fejlet" in html and "Din pakke venter" not in html
    assert admin.get("/training/learn-lists/99").status_code == 404
    csp_clean(text(admin.get("/training/learn-lists/1")), "/training/learn-lists/1")


def test_learn_list_cancel_and_retry(env, admin):
    _seed_lists(env)
    r = post(admin, "/training/learn-lists/2/cancel")
    assert r.status_code == 200 and "stoppes" in r.get_json()["message"] and "ll:2" in r.get_json()["rows"]
    assert env.services.learn_lists[2]["status"] == "cancel_requested"
    assert post(admin, "/training/learn-lists/1/cancel").status_code == 400
    r = post(admin, "/training/learn-lists/1/retry")
    assert r.status_code == 200 and r.get_json()["ok"]
    call = [c for c in env.services.svc22_calls if c[0] == "queue_learn_list"][-1]
    assert [i["message_id"] for i in call[1]] == ["<c@x>"] and call[4] == "genforsøg af job 1"
    assert [a["action"] for a in env.audit()][-2:] == ["learn_list_cancel", "learn_list_retry"]
    env.services.learn_items[3] = []
    env.services.learn_lists[3] = dict(env.services.learn_lists[1], id=3)
    r = post(admin, "/training/learn-lists/3/retry")
    assert r.status_code == 400 and "ingen mails at prøve igen" in r.get_json()["message"]
    assert post(admin, "/training/learn-lists/99/retry").status_code == 404


def test_train_job_row_shows_stop_ratio(env, admin):
    env.conn.execute("ALTER TABLE train_jobs ADD COLUMN stop_ratio REAL") if "stop_ratio" not in {
        r[1] for r in env.conn.execute("PRAGMA table_info(train_jobs)")} else None
    env.conn.execute("INSERT INTO train_jobs(account, folder, kind, max_messages, status, created_at, stop_ratio) "
                     "VALUES('molt','Junk','spam',189,'queued',?,0.5)", (int(time.time()),))
    env.conn.commit()
    assert "Stopper ved 1 spam pr. 2,0 legitime (rebalancering)" in text(admin.get("/training"))


# ===================================================================== rebalancering

def test_rebalance_plan_page_is_a_dry_run(env, admin):
    html = text(admin.get("/training/rebalance"))
    assert ("queue_bayes_rebalance", "admin", False, True) in env.services.svc22_calls
    assert "Plan for rebalancering" in html and "1 spam pr. 5,7 legitime" in html
    assert "Spamfilter-mappen" in html and "Udbyderens spam" in html and "189" in html
    assert "Start 2 job" in html and 'action="/training/rebalance"' in html and "data-confirm" in html
    assert not audits(env, "bayes_rebalance")
    csp_clean(html, "/training/rebalance")
    admin.get("/training/rebalance?trash=1")
    assert ("queue_bayes_rebalance", "admin", True, True) in env.services.svc22_calls


def test_rebalance_start_queues_and_audits(env, admin):
    r = post(admin, "/training/rebalance", {"trash": "1"})
    assert r.status_code == 200 and r.get_json()["ok"] and r.get_json()["refresh"]
    assert ("queue_bayes_rebalance", "admin", True, False) in env.services.svc22_calls
    rec = audits(env, "bayes_rebalance")[-1]
    assert rec["result"] == "ok" and rec["detail"] == "bayes_rebalance jobs=2 needed=468 ratio=0.5"


@pytest.mark.parametrize("code,tone", [("balanced", "ok"), ("rspamd", "bad"), ("nothing", "info")])
def test_rebalance_without_plan_has_no_start_button(env, admin, code, tone):
    env.services.rebalance = {"ok": code != "rspamd", "code": code, "text": f"Kode {code}.", "jobs": [], "errors": [
        {"account": "molt", "code": "auth", "text": "Login fejlede."}],
        "bayes": {"spam": 900, "ham": 1000} if code == "balanced" else None}
    html = text(admin.get("/training/rebalance"))
    assert f"Kode {code}." in html and "Start " not in html and "Login fejlede." in html
    assert f"alert tone-{tone}" in html or f"tone-{tone}" in html


# ===================================================================== (3) Indstillinger: ugerapport

def test_weekly_card_on_settings(env, admin):
    html = text(admin.get("/settings"))
    assert 'id="ugerapport"' in html and "Ugerapport" in html and "Slået fra" in html
    assert 'name="weekly_enabled"' in html and 'name="weekly_users"' in html and 'name="weekly_admin_account"' in html
    assert "Automatisk (Ole · BYnet)" in html or "Automatisk (bynet)" in html
    assert 'action="/settings/weekly/preview"' in html and "Forhåndsvis" in html
    assert 'action="/settings/weekly/send"' in html and "Send nu til" in html
    assert "overvåges, får ingen rapport" in html  # molt is in shadow mode
    csp_clean(html, "/settings")


def test_weekly_settings_saved_and_audited(env, admin):
    r = post(admin, "/settings/weekly", {"weekly_enabled": "1", "weekly_admin_account": "molt"})
    assert r.status_code == 200 and "første kommer mandag morgen" in r.get_json()["message"]
    with env.app.test_request_context("/"):
        assert dashboard.settings_get("weekly_enabled") == "1"
        assert dashboard.settings_get("weekly_users") is None  # unchanged '0' is not written
        assert dashboard.settings_get("weekly_admin_account") == "molt"
    rec = audits(env, "settings_weekly")[-1]
    assert rec["detail"] == "enabled=1 admin_account=molt"
    r = post(admin, "/settings/weekly", {"weekly_enabled": "1", "weekly_admin_account": "molt"})
    assert r.get_json()["message"] == "Uændret."
    r = post(admin, "/settings/weekly", {"weekly_enabled": "1", "weekly_users": "1", "weekly_admin_account": ""})
    assert r.get_json()["message"] == "Gemt."
    with env.app.test_request_context("/"):
        assert dashboard.settings_get("weekly_users") == "1" and dashboard.settings_get("weekly_admin_account") == ""
    assert "Slået til" in text(admin.get("/settings"))
    r = post(admin, "/settings/weekly", {"weekly_admin_account": "sofie"})  # disabled mailbox
    assert r.status_code == 400 and "Ukendt postkasse" in r.get_json()["message"]
    r = post(admin, "/settings/weekly", {})
    assert "slået fra" in r.get_json()["message"]


def test_weekly_preview_page(env, admin):
    html = text(admin.get("/settings/weekly/preview?account=bynet"))
    assert "[Prøve] Spamfilter: ugerapport for uge 42" in html and "Fuld rapport (alle konti)" in html
    assert "Webshop-post: 12 mails fra pinsikbing.example/gravisk.example/vexar.example – 0 flyttet" in html
    assert '<pre class="weekly-text">' in html and "Forrige uge" in html
    assert 'href="/settings/weekly/preview.html?account=bynet&amp;week=2026-W42"' in html
    assert 'action="/settings/weekly/send"' in html and 'name="week" value="2026-W42"' in html
    csp_clean(html, "/settings/weekly/preview")
    html = text(admin.get("/settings/weekly/preview?account=molt&week=2026-w40"))
    assert "Kort version (kun egen postkasse)" in html and "uge 40" in html
    assert ("weekly_preview", "molt", "2026-W40") in env.services.svc22_calls
    assert "Næste uge" in html  # an older week can step forward
    admin.get("/settings/weekly/preview?week=bad")
    assert ("weekly_preview", None, None) in env.services.svc22_calls  # malformed week -> default week
    assert admin.get("/settings/weekly/preview?account=nope").status_code == 404
    assert admin.get("/settings/weekly/preview?account=sofie").status_code == 404  # paused mailbox


def test_weekly_html_preview_is_sandboxed(env, admin):
    r = admin.get("/settings/weekly/preview.html?account=bynet&week=2026-W42")
    assert r.status_code == 200 and r.mimetype == "text/html"
    csp = r.headers["Content-Security-Policy"]
    assert "sandbox" in csp and "script-src" not in csp and "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp and r.headers["X-Frame-Options"] == "DENY"
    assert "Webshop-post" in text(r) and r.headers["Cache-Control"] == "no-store"
    # The relaxed policy is per response: the next page has the app CSP again.
    assert admin.get("/settings").headers["Content-Security-Policy"] == dashboard.CSP


def test_weekly_send_now(env, admin):
    r = post(admin, "/settings/weekly/send", {"account": "bynet", "week": "2026-W41"})
    assert r.status_code == 200 and r.get_json()["ok"]
    assert ("send_weekly_now", "bynet", True, "2026-W41", "admin") in env.services.svc22_calls
    rec = audits(env, "weekly_send")[-1]
    assert rec["account"] == "bynet" and rec["result"] == "ok" and "preview" in rec["detail"]
    r = post(admin, "/settings/weekly/send", {"account": "nope"})
    assert r.status_code == 400 and "Vælg en postkasse" in r.get_json()["message"]


def test_weekly_send_failure_is_audited(env, admin, monkeypatch):
    def fail(*_a, **_k):
        return {"ok": False, "code": "auth", "text": "Mailserveren afviste login."}
    monkeypatch.setattr(env.services, "send_weekly_now", fail)
    r = post(admin, "/settings/weekly/send", {"account": "bynet"})
    assert r.status_code == 400 and r.get_json()["message"] == "Mailserveren afviste login."
    assert audits(env, "weekly_send")[-1]["result"] == "failed"


# ===================================================================== access + CSP

NEW_ROUTES_GET = ["/training/learn-lists/1", "/training/rebalance", "/settings/weekly/preview",
                  "/settings/weekly/preview.html"]
NEW_ROUTES_POST = ["/training/repair/learn", "/training/learn-lists/1/cancel", "/training/learn-lists/1/retry",
                   "/training/rebalance", "/settings/weekly", "/settings/weekly/send"]


def test_new_routes_are_admin_only(env, sofie, cands):
    _seed_lists(env)
    for url in NEW_ROUTES_GET:
        assert sofie.get(url).status_code == 403, url
    for url in NEW_ROUTES_POST:
        assert post(sofie, url, {"account": "bynet", "pick": [f"bynet:{kit.token_for('<phish@x>')}"]}).status_code == 403
    assert not any(c[0] in ("queue_learn_list", "queue_bayes_rebalance", "send_weekly_now", "cancel_learn_list_job")
                   for c in env.services.svc22_calls)
    with env.app.test_request_context("/"):
        assert dashboard.settings_get("weekly_enabled") is None
    anon = env.app.test_client()
    for url in NEW_ROUTES_GET:
        r = anon.get(url)
        assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_new_posts_need_csrf(env, admin, cands):
    for url in NEW_ROUTES_POST:
        r = admin.post(url, data={"account": "bynet"}, headers={"Accept": "application/json"})
        assert r.status_code in (400, 403), url
    assert not any(c[0] in ("queue_learn_list", "queue_bayes_rebalance", "send_weekly_now")
                   for c in env.services.svc22_calls)


def test_learn_list_retry_button_only_when_something_is_retryable(env, admin):
    _seed_lists(env)
    # Job 4: only an ambiguous mail ('skipped') - retry_learn_list would answer 'empty'.
    env.services.learn_lists[4] = dict(env.services.learn_lists[1], id=4, failed=0, skipped=1)
    env.services.learn_items[4] = [dict(env.services.learn_items[1][1], job_id=4, status="ambiguous")]
    # Job 5: stopped before it ran - its pending items can be resumed.
    env.services.learn_lists[5] = dict(env.services.learn_lists[1], id=5, status="cancelled", failed=0)
    env.services.learn_items[5] = [dict(env.services.learn_items[1][1], job_id=5, status="pending")]
    html = text(admin.get("/training"))
    assert "/training/learn-lists/4/retry" not in html
    assert "/training/learn-lists/5/retry" in html and "/training/learn-lists/1/retry" in html
    assert ui_admin._ll_retryable({"status": "done", "skipped": 3, "failed": 0}) is False
    assert ui_admin._ll_retryable({"status": "done", "skipped": 3, "failed": 0, "retryable": 2}) is True
    assert ui_admin._ll_retryable({"status": "running", "retryable": 2}) is False
    r = post(admin, "/training/learn-lists/5/retry")
    assert r.status_code == 200 and r.get_json()["ok"]


def test_new_aged_distrust_symbols_have_danish_texts():
    for sym in ("TH_PROVIDER_AUTH_SPOOF", "TH_AGED_UNVERIFIED"):
        assert kit.SYMBOL_TEXT[sym]
        assert kit.plain_reason(sym)
    assert kit.plain_reason("PHISHED_EXCLUDED") is None and kit.plain_reason("PHISHED_GENERIC_SERVICE") is None
    assert kit.plain_reason("PHISHED_OPENPHISH")
