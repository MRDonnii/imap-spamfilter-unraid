"""UI 2.3 follow-up (UI-2): 'Byg Bayes op på ny' on Træning, the per-mailbox
'Straks-advarsel ved farlige mails' switch on Konti, the red Oversigt card
'Farlige mails stoppet i dag: N' (+ the Fanget spam filter it links to),
the active Bayes pool on both Bayes cards, the new labels and the
permission matrix of every new route.

The rebuild services are faked with the exact documented return shapes
(fakes_ui_admin.FakeAdminServices); threats_today is the REAL services
function on the test database (fakes_ui EngineShim); the threat-notice
preview is built by the REAL filter.build_threat_notice.
"""

from __future__ import annotations

import json
import re
import time

import pytest
import yaml

from fakes_ui import TEST_PASSWORD, fast_hash, insert_message, login, post, set_status
from fakes_ui_admin import make_admin_env

import dashboard  # noqa: E402
import services  # noqa: E402
import ui_admin  # noqa: E402 - registers the admin routes
import ui_kit as kit  # noqa: E402
import ui_mail  # noqa: E402
from test_ui_core import INLINE_PATTERNS  # noqa: E402

PW = TEST_PASSWORD
NEW_ROUTES = {"training_rebuild_page", "training_rebuild_start", "training_rebuild_restore",
              "training_rebuild_status", "account_threat_notice"}


def write_users(env, lines: list[str]) -> None:
    (env.state / "dashboard_users").write_text("\n".join(lines) + "\n")


def midnight() -> int:
    return services._local_midnight_ts(services._local_today())


def today_ts() -> int:
    """'Now', but never before today's local midnight (no midnight flake)."""
    return max(int(time.time()) - 60, midnight() + 1)


@pytest.fixture
def env(tmp_path, monkeypatch):
    e = make_admin_env(tmp_path, monkeypatch)
    hp = fast_hash(PW)
    write_users(e, [f"admin:{hp}:admin:0",
                    f"anna:{hp}:bynet:0",        # Bruger, bynet, all permissions
                    f"bo:{hp}:bynet:0",          # Bruger, bynet, no permissions
                    f"cille:{hp}:~none:0"])      # Bruger without mailboxes
    with e.app.test_request_context("/"):
        dashboard.set_user_perms("bo", [], "test")
    for acc in ("bynet", "molt", "sofie"):
        set_status(e.conn, acc, "idle", junk_exists=1)
    e.conn.commit()
    return e


def client_for(env, name: str | None):
    c = env.app.test_client()
    if name:
        r = login(c, name, PW)
        assert r.status_code == 302, name
    return c


def body(r) -> str:
    return r.get_data().decode("utf-8", "replace")


def csp_clean(html: str, where: str) -> None:
    for rx, what in INLINE_PATTERNS:
        m = rx.search(html)
        assert m is None, f"{what} on {where}: {html[max(0, m.start() - 80):m.end() + 80]}"


def audits(env, action: str) -> list[dict]:
    return [r for r in env.audit() if r["action"] == action]


def svc_calls(env, name: str) -> list[tuple]:
    return [c for c in getattr(env.services, "svc22_calls", []) if c[0] == name]


def seed_threats(env) -> None:
    c, t = env.conn, today_ts()
    insert_message(c, "bynet", "virus1@x.example", our_action="moved_to_junk", our_score=19.6, scanned_at=t,
                   current_folder="Spamfilter", sender="Billing <billing@x.example>", subject="Faktura vedhæftet",
                   threat="virus", threat_detail="Win.Trojan.Agent-12345")
    insert_message(c, "molt", "phish1@x.example", our_action="moved_to_junk", our_score=14.0, scanned_at=t,
                   current_folder="Spamfilter", sender="Bank <sikkerhed@bank-login.example>",
                   subject="MOLT-HEMMELIGT", threat="phish")
    # Not counted: a DKIM-verified Altid igennem pass and yesterday's catch.
    insert_message(c, "bynet", "pass1@x.example", our_action="allowlisted", our_score=-5.0, scanned_at=t,
                   threat="phish")
    insert_message(c, "bynet", "old1@x.example", our_action="moved_to_junk", our_score=18.0,
                   scanned_at=midnight() - 3600, current_folder="Spamfilter", subject="Gammel trussel",
                   threat="virus")
    insert_message(c, "bynet", "plain1@x.example", our_action="moved_to_junk", our_score=12.0, scanned_at=t,
                   current_folder="Spamfilter", sender="spam@x.example", subject="Almindelig spam")
    c.commit()


# ===================================================================== Træning: Byg Bayes op på ny


def test_training_page_has_rebuild_card(env):
    html = body(client_for(env, "admin").get("/training"))
    assert 'id="genopbyg"' in html and "Byg Bayes op på ny" in html
    assert "lærte det hele indbakker som legitim post" in html
    assert 'data-rebuild-live="/training/rebuild/status"' in html and 'href="/training/rebuild"' in html
    # Placed before the older "Reparér Bayes" card.
    assert html.index('id="genopbyg"') < html.index('id="reparer"')
    csp_clean(html, "/training")


def test_rebuild_status_fragment_without_rebuild(env):
    html = body(client_for(env, "admin").get("/training/rebuild/status"))
    assert "Aktiv Bayes-pulje" in html and "hjemmeserver" in html and "Se planen" in html
    assert "data-rebuild-active" not in html and "Gendan tidligere Bayes" not in html
    j = client_for(env, "admin").get("/training/rebuild/status", headers={"Accept": "application/json"}).get_json()
    assert j["active"] is False and j["code"] == "none" and "Se planen" in j["html"]


def test_rebuild_plan_page_shows_the_dry_run(env):
    cfg_before = env.config.read_text()
    html = body(client_for(env, "admin").get("/training/rebuild"))
    # Why, in plain Danish, and what happens.
    assert "Hvorfor bygge op på ny?" in html and "lærte det hele indbakker som legitim post" in html
    assert "indtil den nye har lært mindst 200 spam og 200 legitime" in html
    assert "urørt som backup (puljen hjemmeserver)" in html
    assert "aldrig fra Indbakken, Sendt, Kladder eller Papirkurven" in html
    # Sources, expected numbers, the new pool.
    for s in ("Spamfilter-mappen", "Udbyderens spam", "Anden spam-mappe", "Enkeltmails", "Uønsket e-mail",
              "ca. 661", "ca. 1.322", "hjemmeserver-r1", ">700<", ">622<", "Archive", "Arkiv"):
        assert s in html, s
    assert "Archive.2019" not in html and ">2019<" not in html   # planned 0 -> not shown
    # The typed confirmation (works without JS: a visible field).
    assert 'data-typed-confirm="BYG OP"' in html and "Skriv BYG OP for at bekræfte" in html
    assert 'action="/training/rebuild"' in html and "data-typed-target" in html
    assert re.search(r'<input type="hidden" name="ratio" value="2">', html)
    csp_clean(html, "/training/rebuild")
    # A dry run only: no start, no config change.
    assert svc_calls(env, "bayes_rebuild_plan") and not svc_calls(env, "bayes_rebuild_start")
    assert env.config.read_text() == cfg_before


@pytest.mark.parametrize("arg,want", [("3", 3.0), ("1.5", 1.5), ("99", 2.0), ("x", 2.0), ("", 2.0)])
def test_rebuild_plan_ratio_is_whitelisted(env, arg, want):
    client_for(env, "admin").get(f"/training/rebuild?ratio={arg}")
    assert svc_calls(env, "bayes_rebuild_plan")[-1][2] == want


@pytest.mark.parametrize("typed", ["", "byg", "BYG", "OP BYG", "FJERN"])
def test_rebuild_start_needs_the_typed_word(env, typed):
    admin = client_for(env, "admin")
    admin.get("/training/rebuild")
    cfg_before = env.config.read_text()
    r = post(admin, "/training/rebuild", {"confirm": typed, "ratio": "2"})
    assert r.status_code == 400 and "Skriv BYG OP for at bekræfte" in r.get_json()["message"]
    assert not svc_calls(env, "bayes_rebuild_start")
    assert env.config.read_text() == cfg_before


def test_rebuild_start_switches_pool_and_shows_progress(env):
    admin = client_for(env, "admin")
    r = post(admin, "/training/rebuild", {"confirm": "  byg   op ", "ratio": "1.5"})
    j = r.get_json()
    assert r.status_code == 200 and j["ok"] and j["reload"] is True and j["location"] == "/training#genopbyg"
    assert "hjemmeserver-r1" in j["message"]
    call = svc_calls(env, "bayes_rebuild_start")[-1]
    assert call[1] == "admin" and call[2] is True and call[3] == 1.5 and call[4] is dashboard.save_config
    assert env.raw_config()["defaults"]["bayes_user"] == "hjemmeserver-r1"
    recs = audits(env, "bayes_rebuild")
    assert len(recs) == 1 and recs[0]["result"] == "ok"            # written once, by save_config
    # Live status: progress, numbers, the 200-gate and the restore button.
    st = body(admin.get("/training/rebuild/status"))
    assert "data-rebuild-active" in st and "Genopbygning i gang" in st
    # Progress counts mails (148 + 96 of ca. 1.983), not jobs, and the bar has an accessible label.
    assert 'aria-valuenow="12"' in st and 'aria-label="Genopbygning"' in st and ">12 %<" in st
    assert "færdige" not in st and "148" in st and "af ca. 661" in st and "af ca. 1.322" in st
    assert "Bayes er slået fra, indtil begge har 200" in st
    assert 'action="/training/rebuild/restore"' in st and "Gendan tidligere Bayes" in st
    assert "Byg op på ny igen" not in st
    j = admin.get("/training/rebuild/status", headers={"Accept": "application/json"}).get_json()
    assert j["active"] is True and j["code"] == "running"
    # While it runs the plan page shows the status, not a second start form.
    page = body(admin.get("/training/rebuild"))
    assert "Genopbygning i gang" in page and 'action="/training/rebuild"' not in page
    assert len(svc_calls(env, "bayes_rebuild_plan")) == 1   # only the start re-planned
    csp_clean(page, "/training/rebuild (running)")


def test_rebuild_restore(env):
    admin = client_for(env, "admin")
    post(admin, "/training/rebuild", {"confirm": "BYG OP"})
    r = post(admin, "/training/rebuild/restore", {})
    j = r.get_json()
    assert r.status_code == 200 and j["ok"] and j["reload"] is True and "hjemmeserver" in j["message"]
    assert svc_calls(env, "bayes_restore_previous")[-1][2] is True
    assert svc_calls(env, "bayes_restore_previous")[-1][3] is dashboard.save_config
    assert env.raw_config()["defaults"]["bayes_user"] == "hjemmeserver"
    assert [a["result"] for a in audits(env, "bayes_restore")] == ["ok"]
    st = body(admin.get("/training/rebuild/status"))
    assert "Den tidligere Bayes er gendannet" in st and "Gendan tidligere Bayes" not in st
    assert "Byg op på ny igen" in st
    # Nothing left to restore: a clear refusal, audited, config untouched.
    cfg = env.config.read_text()
    r2 = post(admin, "/training/rebuild/restore", {})
    assert r2.status_code == 400 and "Der er ingen tidligere Bayes" in r2.get_json()["message"]
    assert env.config.read_text() == cfg
    assert [a["result"] for a in audits(env, "bayes_restore")] == ["ok", "rejected"]


def test_rebuild_done_with_warning_and_unknown_pool_counts(env):
    env.services._rebuild_state()["status_override"] = {
        "ok": True, "code": "done", "rebuild_id": 2, "pool": "hjemmeserver-r2", "pool_old": "hjemmeserver",
        "pool_new": "hjemmeserver-r2", "created_at": int(time.time()) - 7200, "created_by": "admin",
        "expected_spam": 400, "expected_ham": 800, "learned_spam": 0, "learned_ham": 410, "percent": 100,
        "jobs": {"done": 5}, "bayes": {"ok": True, "spam": 0, "ham": 410, "active": False,
                                       "counts_source": "all_pools"},
        "min_learns": 200, "can_restore": True,
        "warnings": ["Genopbygningen lærte ingen spam, fordi rspamd svarede »allerede lært« (380 gange). "
                     "Filteret kører nu uden Bayes. Tryk »Gendan tidligere Bayes« for at gå tilbage til den gamle."],
        "text": "Genopbygningen er færdig: 0 spam og 410 legitime er lært i puljen hjemmeserver-r2."}
    html = body(client_for(env, "admin").get("/training/rebuild/status"))
    assert "Genopbygningen er færdig" in html and "data-rebuild-active" not in html
    assert "rspamd svarede »allerede lært«" in html and "Tryk »Gendan tidligere Bayes«" in html
    # With a warning, going back is the primary action.
    restore = html[html.index('action="/training/rebuild/restore"'):]
    assert "btn-primary" in restore[:600]
    assert "summen af alle Bayes-puljer" in html
    assert "Gendan tidligere Bayes" in html and "Byg op på ny igen" in html
    assert "hjemmeserver-r2" in html


def test_rebuild_plan_that_cannot_start(env):
    env.services._rebuild_state()["plan"] = dict(env.services.REBUILD_PLAN, expected_spam=0, spam_sources=[],
                                                 warnings=["Der er kun ca. 0 spam at lære."])
    html = body(client_for(env, "admin").get("/training/rebuild"))
    assert "Kan ikke startes lige nu" in html and "Der er ingen spam at lære fra." in html
    assert 'name="confirm"' not in html and "Ingen spam-mapper med mails fundet." in html
    env.services._rebuild_state()["plan"] = {"ok": False, "code": "config", "text": "Konfigurationen kunne ikke "
                                             "indlæses.", "warnings": [], "spam_sources": [], "ham_sources": []}
    html = body(client_for(env, "admin").get("/training/rebuild"))
    assert "Konfigurationen kunne ikke indlæses." in html and 'name="confirm"' not in html


@pytest.mark.parametrize("res,code,text", [
    ({"ok": False, "code": "running", "text": "En genopbygning er allerede i gang."}, 409, "allerede i gang"),
    ({"ok": False, "code": "rejected", "text": "Ændringen blev afvist: x"}, 400, "afvist"),
    (RuntimeError("redis password=hemmelig"), 400, "den gamle Bayes bruges stadig"),
])
def test_rebuild_start_refusals(env, monkeypatch, res, code, text):
    def fake(*a, **kw):
        if isinstance(res, Exception):
            raise res
        return res
    monkeypatch.setattr(env.services, "bayes_rebuild_start", fake)
    r = post(client_for(env, "admin"), "/training/rebuild", {"confirm": "BYG OP"})
    j = r.get_json()
    assert r.status_code == code and text in j["message"] and "hemmelig" not in json.dumps(j)
    assert audits(env, "bayes_rebuild")[-1]["result"] in ("rejected", "failed")


def test_rebuild_refused_while_config_is_broken(env, monkeypatch):
    monkeypatch.setattr(dashboard, "config_error", lambda: "broken")
    r = post(client_for(env, "admin"), "/training/rebuild", {"confirm": "BYG OP"})
    assert r.status_code == 400 and "accounts.yml kan ikke indlæses" in r.get_json()["message"]
    assert not svc_calls(env, "bayes_rebuild_start")
    r = post(client_for(env, "admin"), "/training/rebuild/restore", {})
    assert r.status_code == 400 and not svc_calls(env, "bayes_restore_previous")


def test_rebuild_without_js(env):
    """No JS: plain form posts redirect with a flash message."""
    admin = client_for(env, "admin")
    r = post(admin, "/training/rebuild", {"confirm": "BYG OP"}, json_reply=False)
    assert r.status_code == 302 and r.headers["Location"].endswith("/training#genopbyg")
    assert env.raw_config()["defaults"]["bayes_user"] == "hjemmeserver-r1"
    page = body(admin.get("/training/rebuild/status", headers={"Sec-Fetch-Mode": "navigate"}))
    assert "<html" in page and "Genopbygning i gang" in page


# ===================================================================== Bayes cards: the active pool


def test_bayes_cards_show_the_pool_and_services_text(env):
    env.services.bayes = {"ok": True, "spam_learned": 150, "ham_learned": 90, "min_learns": 200, "users": 2,
                          "pool": "hjemmeserver-r1", "counts_source": "all_pools",
                          "text": "Bayes er ikke aktiv endnu: 150 spam og 90 legitime er lært (alle Bayes-puljer "
                                  "tilsammen – tallet for den aktive pulje kendes ikke). rspamd bruger først Bayes, "
                                  "når der er lært mindst 200 af hver slags."}
    admin = client_for(env, "admin")
    tr = body(admin.get("/training/bayes"))
    assert "Aktiv pulje: " in tr and "hjemmeserver-r1" in tr and "rspamd bruger først Bayes" in tr
    assert "Tallet for den aktive pulje kendes ikke" in tr
    ov = body(admin.get("/fragments/bayes"))
    assert "hjemmeserver-r1" in ov and "summen af alle Bayes-puljer" in ov
    # A Bruger never sees the pool name.
    assert "hjemmeserver-r1" not in body(client_for(env, "anna").get("/fragments/bayes"))


def test_bayes_card_without_pool_is_unchanged(env):
    tr = body(client_for(env, "admin").get("/training/bayes"))
    assert "Aktiv pulje" not in tr and "Bayes tæller først med ved 200 af hver" in tr


# ===================================================================== Konti: Straks-advarsel


def test_account_page_threat_notice_switch_and_preview(env):
    html = body(client_for(env, "admin").get("/accounts/bynet"))
    assert "Straks-advarsel ved farlige mails" in html
    assert re.search(r'name="threat_notice" value="1" checked', html)
    assert "lægges en kort advarsel straks i postkassens indbakke" in html
    assert 'action="/accounts/bynet/threat-notice"' in html
    # The preview is the engine's own text for an invented phishing mail.
    pre = re.search(r'<pre class="notice-text">(.*?)</pre>', html, re.S).group(1)
    assert "Spamfilteret har stoppet en farlig mail" in html
    assert "Phishing-link" in pre and "Mailen ligger i mappen Spamfilter" in pre
    assert "postnord․example" in pre and "postnord.example" not in pre   # host made non-clickable
    assert "http" not in pre
    assert "Sendes kun, når kontoen kører i Filtrér" not in html             # bynet is in Filtrér
    csp_clean(html, "/accounts/bynet")
    molt = body(client_for(env, "admin").get("/accounts/molt"))
    assert "Sendes kun, når kontoen kører i Filtrér" in molt                 # molt is in Overvåg


def test_threat_notice_toggle_writes_config(env):
    admin = client_for(env, "admin")
    r = post(admin, "/accounts/bynet/threat-notice", {"next": "/accounts/bynet"})
    j = r.get_json()
    assert r.status_code == 200 and j["ok"] and "slået fra" in j["message"] and j["reload"] is True
    assert env.entry("bynet")["threat_notice"] is False
    assert "threat_notice" not in env.entry("molt")
    rec = audits(env, "account_threat_notice")[-1]
    assert rec["account"] == "bynet" and "on=0" in rec["detail"]
    html = body(admin.get("/accounts/bynet"))
    assert re.search(r'name="threat_notice" value="1">', html) and "Fra" in html
    assert post(admin, "/accounts/bynet/threat-notice", {}).get_json()["message"] == "Uændret."
    r = post(admin, "/accounts/bynet/threat-notice", {"threat_notice": "1"})
    assert r.get_json()["ok"] and env.entry("bynet")["threat_notice"] is True


def test_threat_notice_config_is_valid_for_the_real_engine(env, tmp_path):
    """The key the switch writes is the one filter.py reads (bool)."""
    import filter as engine
    post(client_for(env, "admin"), "/accounts/bynet/threat-notice", {})
    raw = env.raw_config()
    p = tmp_path / "real.yml"
    p.write_text(yaml.safe_dump(raw))
    accs = {a.name: a for a in engine.load_account_configs(p)}
    assert accs["bynet"].threat_notice is False and accs["molt"].threat_notice is True


def test_threat_notice_preview_never_breaks_the_page(env, monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("x")
    monkeypatch.setattr(env.engine, "build_threat_notice", boom, raising=False)
    html = body(client_for(env, "admin").get("/accounts/bynet"))
    assert "Straks-advarsel ved farlige mails" in html and "notice-text" not in html


# ===================================================================== Oversigt: Farlige mails stoppet i dag


def test_overview_has_no_threat_card_without_threats(env):
    html = body(client_for(env, "admin").get("/"))
    assert "threat-today" not in html
    # The Nøgletal strip says 0 with the same words as the card.
    assert 'Farlige mails stoppet i dag:</span> <b class="num">0</b>' in html and "Trusler stoppet" not in html


def test_threat_count_is_shown_once_with_the_card(env):
    seed_threats(env)
    html = body(client_for(env, "admin").get("/"))
    assert html.count("Farlige mails stoppet i dag") == 1          # only the red card, not the strip too
    week = body(client_for(env, "admin").get("/?period=7d"))
    assert re.search(r'Farlige mails stoppet de seneste 7 dage:</span> <b class="num">3</b>', week)


def test_threat_card_singular_and_mail_still_in_the_inbox(env):
    c, t = env.conn, today_ts()
    insert_message(c, "bynet", "v1@x.example", our_action="moved_to_junk", our_score=19.0, scanned_at=t,
                   current_folder="Spamfilter", subject="Virus", threat="virus")
    insert_message(c, "bynet", "p1@x.example", our_action="shadow_spam", our_score=14.0, scanned_at=t,
                   current_folder="INBOX", subject="Phish i Overvåg", threat="phish")
    c.commit()
    card = re.search(r'<section class="threat-today".*?</section>', body(client_for(env, "admin").get("/")),
                     re.S).group(0)
    assert 'stoppet i dag: <span class="num">1</span>' in card            # the shadow mail is not "stoppet"
    assert "Mailen ligger i Spamfilter-mappen – åbn den ikke" in card and "Mailene" not in card
    assert "1 farlig mail ligger stadig i indbakken – slet den uden at åbne den." in card
    assert "Phishing" not in card
    csp_clean(card, "threat card")


def test_threat_card_when_nothing_was_stopped_but_one_is_in_the_inbox(env):
    insert_message(env.conn, "bynet", "f1@x.example", our_action="flagged", our_score=14.0, scanned_at=today_ts(),
                   current_folder="INBOX", subject="Markeret", threat="phish")
    insert_message(env.conn, "bynet", "f2@x.example", our_action="move_failed", our_score=14.0,
                   scanned_at=today_ts(), current_folder="INBOX", subject="Fejlet", threat="virus")
    env.conn.commit()
    html = body(client_for(env, "admin").get("/"))
    card = re.search(r'<section class="threat-today".*?</section>', html, re.S).group(0)
    assert "stoppet" not in card and 'Farlige mails i indbakken i dag: <span class="num">2</span>' in card
    assert "2 farlige mails ligger stadig i indbakken – slet dem uden at åbne dem." in card
    assert "Spamfilter-mappen" not in card and "Se dem" not in card


def test_overview_threat_card_for_admin(env):
    seed_threats(env)
    html = body(client_for(env, "admin").get("/"))
    m = re.search(r'<section class="threat-today".*?</section>', html, re.S)
    assert m, "card missing"
    card = m.group(0)
    assert 'Farlige mails stoppet i dag: <span class="num">2</span>' in card
    assert "Virus 1" in card and "Phishing-link 1" in card
    assert 'href="/spam?threat=today"' in card and "Se dem" in card
    # Full width between the hero and Nøgletal - outside the overview grid.
    assert html.index("hero tone-") < html.index("threat-today") < html.index("Nøgletal") < html.index("ov-grid")
    assert html.count('class="grid grid-main ov-grid"') == 1
    csp_clean(html, "/")
    one = body(client_for(env, "admin").get("/?account=bynet"))
    assert 'stoppet i dag: <span class="num">1</span>' in one and "Phishing-link" not in \
        re.search(r'<section class="threat-today".*?</section>', one, re.S).group(0)
    assert 'href="/spam?threat=today&amp;account=bynet"' in one


def test_overview_threat_card_mentions_notices(env):
    seed_threats(env)
    env.conn.execute("INSERT INTO stats_daily(account, day, metric, n) VALUES('bynet', ?, 'threat_notice_sent', 1)",
                     (services._local_today().isoformat(),))
    env.conn.commit()
    html = body(client_for(env, "admin").get("/"))
    assert "1 straks-advarsel er lagt i indbakken" in html


def test_bruger_sees_only_own_threats(env):
    seed_threats(env)
    html = body(client_for(env, "anna").get("/"))
    card = re.search(r'<section class="threat-today".*?</section>', html, re.S).group(0)
    assert 'stoppet i dag: <span class="num">1</span>' in card and "Virus 1" in card
    assert "Phishing" not in card and "MOLT" not in html
    calls = [c for c in env.services.calls23 if c[0] == "threats_today"]
    assert calls[-1] == ("threats_today", ["bynet"])
    csp_clean(html, "/ (Bruger)")


def test_bruger_without_mailboxes_gets_no_card(env):
    seed_threats(env)
    html = body(client_for(env, "cille").get("/"))
    assert "threat-today" not in html
    assert not [c for c in env.services.calls23 if c[0] == "threats_today" and c[1] is None]


def test_threat_card_survives_a_services_failure(env, monkeypatch):
    seed_threats(env)

    def boom(*a, **kw):
        raise RuntimeError("db gone")
    monkeypatch.setattr(env.services, "threats_today", boom)
    r = client_for(env, "admin").get("/")
    assert r.status_code == 200 and "threat-today" not in body(r)


def test_spam_list_filtered_on_todays_threats(env):
    seed_threats(env)
    admin = client_for(env, "admin")
    html = body(admin.get("/spam?threat=today"))
    assert "Viser kun farlige mails, der er stoppet i dag." in html and 'href="/spam"' in html
    assert "Faktura vedhæftet" in html and "MOLT-HEMMELIGT" in html
    assert "Almindelig spam" not in html and "Gammel trussel" not in html
    assert 'name="threat" value="today"' in html and 'name="period"' not in html
    csp_clean(html, "/spam?threat=today")
    both = body(admin.get("/spam?threat=today&account=bynet"))
    assert "Faktura vedhæftet" in both and "MOLT-HEMMELIGT" not in both
    assert 'href="/spam?account=bynet"' in both
    # Without the filter everything is back.
    allspam = body(admin.get("/spam?period=all"))
    assert "Almindelig spam" in allspam and "Viser kun farlige mails" not in allspam


def test_bruger_spam_list_filtered_on_threats(env):
    seed_threats(env)
    anna = client_for(env, "anna")
    html = body(anna.get("/spam?threat=today"))
    assert "Viser kun farlige mails" in html and "Faktura vedhæftet" in html
    assert "Almindelig spam" not in html and "MOLT-HEMMELIGT" not in html
    home = body(anna.get("/?threat=today"))
    assert "Viser kun farlige mails" in home and "threat-today" not in home  # no card on the filtered list


# ===================================================================== labels


def test_labels_for_new_events_audits_and_stats():
    import filter as engine
    for ev in ("threat_notice_sent", "threat_notice_failed", "threat_alert_mailed", "bayes_rebuild_started",
               "bayes_rebuild_done", "bayes_restored"):
        assert ev in ui_admin.EVENT_LABELS and ev in ui_mail.EVENT_INFO, ev
        assert "_" not in ui_admin.EVENT_LABELS[ev][0] and "_" not in ui_mail.EVENT_INFO[ev][0]
    for a in ("bayes_rebuild", "bayes_restore", "account_threat_notice"):
        assert a in ui_admin.AUDIT_LABELS and "_" not in ui_admin.AUDIT_LABELS[a], a
    assert "threat_notice_sent" in engine.STAT_METRICS and "threat_notice_sent" in ui_admin.STAT_LABELS


def test_engine_emits_exactly_the_labelled_events():
    """Every new event name the backend writes has a label (grep of the sources)."""
    from pathlib import Path
    src = "".join((Path(__file__).resolve().parent.parent / "filter" / f).read_text()
                  for f in ("filter.py", "services.py", "trainer.py"))
    for ev in ("threat_notice_sent", "threat_notice_failed", "threat_alert_mailed", "bayes_rebuild_started",
               "bayes_rebuild_done", "bayes_restored"):
        assert f'"{ev}"' in src or f"'{ev}'" in src, ev


# ===================================================================== permissions


def test_new_routes_are_admin_only_by_the_central_policy(env):
    eps = {r.endpoint for r in env.app.url_map.iter_rules()}
    assert NEW_ROUTES <= eps
    for ep in NEW_ROUTES:
        assert dashboard.route_policy(ep) == "admin", ep


@pytest.mark.parametrize("who", ["anna", "bo", "cille"])
def test_brugere_are_refused_on_every_new_route(env, who):
    c = client_for(env, who)
    cfg = env.config.read_text()
    for url in ("/training/rebuild", "/training/rebuild/status"):
        assert c.get(url, headers={"Accept": "text/html"}).status_code == 403, url
    for url, data in (("/training/rebuild", {"confirm": "BYG OP"}), ("/training/rebuild/restore", {}),
                      ("/accounts/bynet/threat-notice", {"threat_notice": ""})):
        assert post(c, url, data).status_code == 403, url
    assert env.config.read_text() == cfg
    assert not svc_calls(env, "bayes_rebuild_start") and not svc_calls(env, "bayes_restore_previous")
    assert not svc_calls(env, "bayes_rebuild_plan")


def test_anonymous_is_sent_to_login(env):
    c = env.app.test_client()
    for url in ("/training/rebuild", "/training/rebuild/status"):
        r = c.get(url)
        assert r.status_code == 302 and "/login" in r.headers["Location"]
    for url in ("/training/rebuild", "/training/rebuild/restore", "/accounts/bynet/threat-notice"):
        assert c.post(url, data={"confirm": "BYG OP"}, headers={"Accept": "application/json",
                                                                "X-Requested-With": "fetch"}).status_code == 401


def test_csrf_is_required(env):
    admin = client_for(env, "admin")
    r = admin.post("/training/rebuild", data={"confirm": "BYG OP"},
                   headers={"Accept": "application/json", "X-Requested-With": "fetch"})
    assert r.status_code == 400 and not svc_calls(env, "bayes_rebuild_start")


def test_static_hooks_exist():
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent / "filter" / "static"
    js = (root / "admin.js").read_text()
    assert "data-typed-confirm" in js and "data-rebuild-live" in js and "initRebuildLive()" in js
    css = (root / "app.css").read_text()
    for cls in (".threat-today", ".threat-filter", ".rebuild-state", ".notice-text", ".bayes-pool"):
        assert cls in css, cls
    assert kit is not None
