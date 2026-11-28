"""2.6 A4 UI: the Nyhedsbreve setting (Fra / Prøv / Til) on Konti, the
Oversigt mailbox card line, the /newsletters list (shadow + moved + kept
senders) and 'Tilbage til indbakken' (page, mail list and detail page)."""

from __future__ import annotations

import re
import time

import pytest
import yaml

from fakes_ui import TEST_PASSWORD, fast_hash, insert_message, login, post, set_status
from fakes_ui_admin import make_admin_env

import dashboard  # noqa: E402
import newsletters as nl  # noqa: E402
import ui_admin  # noqa: E402,F401 - registers the admin routes
import ui_kit as kit  # noqa: E402
from test_ui_core import INLINE_PATTERNS  # noqa: E402

PW = TEST_PASSWORD


@pytest.fixture
def env(tmp_path, monkeypatch):
    e = make_admin_env(tmp_path, monkeypatch)
    hp = fast_hash(PW)
    (e.state / "dashboard_users").write_text("\n".join([f"admin:{hp}:admin:0", f"anna:{hp}:bynet:0",
                                                        f"bo:{hp}:bynet:0"]) + "\n")
    with e.app.test_request_context("/"):
        dashboard.set_user_perms("bo", [], "test")
    for acc in ("bynet", "molt", "sofie"):
        set_status(e.conn, acc, "idle", junk_exists=1)
    e.conn.commit()
    return e


def client_for(env, name):
    c = env.app.test_client()
    assert login(c, name, PW).status_code == 302
    return c


def body(r) -> str:
    return r.get_data().decode("utf-8", "replace")


def csp_clean(html: str) -> None:
    for rx, what in INLINE_PATTERNS:
        assert rx.search(html) is None, what


def event(env, account, mid, ev, detail="newsletter signals=list-unsubscribe,esp:sendgrid.net", ts=None):
    env.conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                     (account, ts or int(time.time()) - 60, mid, ev, detail))


def seed(env):
    insert_message(env.conn, "bynet", "s1@x", sender="Plantorama <klub@plantorama.example>",
                   subject="Plantorama klub: <b>Ugens</b> tilbud")
    event(env, "bynet", "s1@x", nl.EVENT_SHADOW)
    insert_message(env.conn, "bynet", "old@x", subject="Gammel")
    event(env, "bynet", "old@x", nl.EVENT_SHADOW, ts=int(time.time()) - 9 * 86400)
    insert_message(env.conn, "bynet", "m1@x", sender="AMD <news@amd.example>", subject="AMD Ryzen nyheder",
                   our_action=nl.ACTION_MOVED, current_folder="Nyhedsbreve")
    event(env, "bynet", "m1@x", nl.EVENT_MOVE, detail="uid=3 -> Nyhedsbreve")
    insert_message(env.conn, "molt", "molt1@x", subject="MOLT-HEMMELIGT")
    event(env, "molt", "molt1@x", nl.EVENT_SHADOW)
    env.conn.execute("INSERT INTO newsletter_keep(account, sender, created_at, created_by) VALUES(?,?,?,?)",
                     ("bynet", "news@perfectjeans.example", int(time.time()), "user:move"))
    env.conn.commit()


# ----- Konti: setting -----------------------------------------------------------


def test_account_page_has_newsletter_selector(env):
    seed(env)
    html = body(client_for(env, "admin").get("/accounts/bynet"))
    assert 'id="nyhedsbreve"' in html and 'action="/accounts/bynet/newsletters"' in html
    assert re.search(r'name="newsletters" value="shadow" checked', html)
    for label in ("Fra", "Prøv", "Til"):
        assert f"<span>{label}</span>" in html
    assert "vexar.example bliver altid i indbakken" in html and "læres aldrig som spam" in html
    assert "1 ville være flyttet" in html and 'href="/newsletters?account=bynet"' in html
    csp_clean(html)


def test_setting_writes_config_valid_for_the_real_engine(env, tmp_path):
    admin = client_for(env, "admin")
    r = post(admin, "/accounts/bynet/newsletters", {"newsletters": "on"})
    j = r.get_json()
    assert r.status_code == 200 and j["ok"] and "flyttes nu" in j["message"]
    assert env.entry("bynet")["newsletters"] == "on"
    assert "newsletters" not in env.entry("molt")
    assert "newsletters: 'on'" in env.config.read_text()  # quoted: YAML 1.1 would read a bool
    assert [a for a in env.audit() if a["action"] == "account_newsletters"][-1]["detail"] == "newsletters=on"
    assert post(admin, "/accounts/bynet/newsletters", {"newsletters": "on"}).get_json()["message"] == "Uændret."
    assert post(admin, "/accounts/bynet/newsletters", {"newsletters": "x"}).get_json()["ok"] is False
    import filter as engine
    p = tmp_path / "real.yml"
    p.write_text(yaml.safe_dump(env.raw_config()))
    accs = {a.name: a for a in engine.load_account_configs(p)}
    assert accs["bynet"].newsletters == "on" and accs["molt"].newsletters == "shadow"


def test_setting_is_admin_only(env):
    r = post(client_for(env, "anna"), "/accounts/bynet/newsletters", {"newsletters": "off"})
    assert r.status_code == 403 and "newsletters" not in env.entry("bynet")


# ----- Oversigt card + list page --------------------------------------------------


def test_overview_card_shows_shadow_count_with_link(env):
    seed(env)
    html = body(client_for(env, "admin").get("/"))
    assert "1 nyhedsbrev ville være flyttet de seneste 7 dage" in html
    assert 'href="/newsletters?account=bynet"' in html
    csp_clean(html)


def test_list_page_shadow_moved_and_kept(env):
    seed(env)
    html = body(client_for(env, "admin").get("/newsletters?account=bynet"))
    assert "Ville være flyttet" in html and "Plantorama" in html
    assert "&lt;b&gt;Ugens&lt;/b&gt;" in html and "<b>Ugens</b>" not in html   # escaped
    assert "Afmeldingslink" in html and "Sendt via sendgrid.net" in html
    assert "Gammel" not in html                                                # older than 7 days
    assert "AMD Ryzen nyheder" in html and 'action="/newsletters/back"' in html
    assert "news@perfectjeans.example" in html and 'action="/newsletters/unkeep"' in html
    assert "MOLT-HEMMELIGT" not in html
    csp_clean(html)


def test_list_page_scoping(env):
    seed(env)
    anna = client_for(env, "anna")
    assert anna.get("/newsletters?account=molt").status_code == 404
    html = body(anna.get("/newsletters"))
    assert "AMD Ryzen nyheder" in html and "MOLT-HEMMELIGT" not in html
    bo = body(client_for(env, "bo").get("/newsletters?account=bynet"))
    assert "AMD Ryzen nyheder" in bo and 'action="/newsletters/back"' not in bo   # no 'release' permission


def test_back_action_calls_the_service(env, monkeypatch):
    seed(env)
    calls = []

    def fake(account, mid, actor, **kw):
        calls.append((account, mid, actor))
        return {"ok": True, "code": "ok", "text": "Flyttet tilbage til indbakken.", "sender_kept": "news@amd.example"}

    monkeypatch.setattr(env.services, "newsletter_to_inbox", fake, raising=False)
    r = post(client_for(env, "admin"), "/newsletters/back", {"account": "bynet", "message_id": "m1@x"})
    assert r.status_code == 200 and r.get_json()["ok"] and calls == [("bynet", "m1@x", "admin")]
    rec = [a for a in env.audit() if a["action"] == "newsletter_back"][-1]
    assert rec["account"] == "bynet" and rec["message_id"] == "m1@x"
    # Other mailboxes / no permission: refused before the service runs.
    assert post(client_for(env, "anna"), "/newsletters/back", {"account": "molt", "message_id": "x"}).status_code \
        == 404
    assert post(client_for(env, "bo"), "/newsletters/back", {"account": "bynet", "message_id": "x"}).status_code \
        == 403
    assert len(calls) == 1


def test_unkeep_action(env, monkeypatch):
    calls = []
    monkeypatch.setattr(env.services, "newsletter_unkeep",
                        lambda a, s, actor, **kw: calls.append((a, s)) or {"ok": True, "code": "ok", "text": "ok"},
                        raising=False)
    r = post(client_for(env, "admin"), "/newsletters/unkeep", {"account": "bynet", "sender": "a@b.example"})
    assert r.get_json()["ok"] and calls == [("bynet", "a@b.example")]


def test_mail_list_and_detail_offer_back_to_inbox(env):
    seed(env)
    admin = client_for(env, "admin")
    lst = body(admin.get("/messages?account=bynet&result=newsletters"))
    assert "AMD Ryzen nyheder" in lst and "Flyttet til nyhedsbreve" in lst
    assert "Plantorama" not in lst
    assert 'action="/newsletters/back"' in lst
    html = body(admin.get(f"/messages/bynet/{kit.token_for('m1@x')}"))
    assert "Tilbage til indbakken" in html and "Nyhedsbreve (Nyhedsbreve)" in html
    assert "Ligger i nyhedsbreve-mappen" in html
    csp_clean(html)


# ----- 2.21: Black Friday setting -------------------------------------------------


def test_account_page_has_black_friday_selector(env):
    html = body(client_for(env, "admin").get("/accounts/bynet"))
    assert 'id="black-friday"' in html and 'action="/accounts/bynet/black-friday"' in html
    assert re.search(r'name="black_friday" value="shadow" checked', html)
    assert "Cyber Monday" in html and "“Black Friday”" in html
    csp_clean(html)


def test_black_friday_setting_writes_config_valid_for_the_real_engine(env, tmp_path):
    admin = client_for(env, "admin")
    r = post(admin, "/accounts/bynet/black-friday", {"black_friday": "on"})
    j = r.get_json()
    assert r.status_code == 200 and j["ok"] and "flyttes nu til “Black Friday”" in j["message"]
    assert env.entry("bynet")["black_friday"] == "on" and "black_friday" not in env.entry("molt")
    assert [a for a in env.audit() if a["action"] == "account_black_friday"][-1]["detail"] == "black_friday=on"
    assert post(admin, "/accounts/bynet/black-friday", {"black_friday": "on"}).get_json()["message"] == "Uændret."
    assert post(admin, "/accounts/bynet/black-friday", {"black_friday": "x"}).get_json()["ok"] is False
    assert post(client_for(env, "anna"), "/accounts/bynet/black-friday", {"black_friday": "off"}).status_code == 403
    import filter as engine
    p = tmp_path / "real.yml"
    p.write_text(yaml.safe_dump(env.raw_config()))
    accs = {a.name: a for a in engine.load_account_configs(p)}
    assert accs["bynet"].black_friday == "on" and accs["molt"].black_friday == "shadow"
