"""2.7: the admin page /ai (ui_ai.py): settings (Fra/Prøv/Til, LAN-only
Ollama address, model, band, hourly cap, time-out; validated and audited),
"Test forbindelse" against a fake Ollama, the evaluation table with escaped
attacker-influenced text, admin only, and the navigation entry."""

from __future__ import annotations

import json
import time

from fakes_ui import csrf_of
from test_ui_admin import admin, env, sofie, text  # noqa: F401 - fixtures

import ai_verdict as ai  # noqa: E402

import pytest  # noqa: E402

NOW = int(time.time())
EVIL = '<script>alert(1)</script>'
JSON = {"Accept": "application/json"}


class FakeOllama:
    def __init__(self):
        self.models = [{"name": "qwen2.5:7b"}, {"name": "qwen3:8b"}, {"name": "gemma3:4b"}]
        self.fail = None
        self.urls: list[str] = []

    def get_json(self, url, timeout):
        self.urls.append(url)
        if self.fail:
            raise self.fail
        return {"models": self.models}

    def post_json(self, url, body, timeout):  # pragma: no cover - the page never chats
        raise AssertionError("the UI never sends mail to the model")


@pytest.fixture(autouse=True)
def ollama(monkeypatch):
    fake = FakeOllama()
    monkeypatch.setattr(ai, "TRANSPORT", fake)
    return fake


def _saved(env):  # noqa: F811
    row = env.conn.execute("SELECT value FROM settings_kv WHERE key='ai'").fetchone()
    return json.loads(row[0]) if row else None


FORM = {"mode": "on", "url": "http://192.168.1.10:11434", "model": "qwen3:8b", "band_low": "3,5", "band_high": "",
        "max_per_hour": "60", "timeout": "20"}


def test_page_renders_defaults_and_nav(env, admin):  # noqa: F811
    html = text(admin.get("/ai"))
    assert "AI-vurdering" in html and 'href="/ai"' in html
    # 2.7 fix: no default address - nothing is sent until an admin saves one.
    assert 'name="url" value=""' in html and 'placeholder="http://192.168.1.10:11434"' in html
    assert "Ikke sat op – angiv Ollama-adressen" in html and 'value="qwen2.5:7b"' in html
    assert "Test forbindelse" in html and "Ingen AI-vurderinger endnu" in html
    assert '<option value="shadow" selected' in html


def test_bruger_cannot_see_or_change(env, sofie):  # noqa: F811
    assert sofie.get("/ai").status_code == 403
    assert sofie.post("/ai/settings", data=FORM).status_code in (400, 403)
    assert sofie.post("/ai/test", data={}).status_code in (400, 403)


def test_settings_save_validate_and_audit(env, admin):  # noqa: F811
    admin.get("/ai")
    token = csrf_of(admin)
    r = admin.post("/ai/settings", data={"csrf": token, **FORM}, headers=JSON)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _saved(env) == {"mode": "on", "url": "http://192.168.1.10:11434", "model": "qwen3:8b", "band_low": 3.5,
                           "band_high": None, "max_per_hour": 60, "timeout": 20}
    assert any(a["action"] == "ai_settings" and "mode=on" in a.get("detail", "") for a in env.audit())
    html = text(admin.get("/ai"))
    assert '<option value="on" selected' in html and 'value="3,5"' in html
    for key, value in (("url", "https://api.openai.com"), ("url", "http://8.8.8.8:11434"),
                       ("url", "http://ollama.example.com"), ("mode", "always"), ("band_low", "abc"),
                       ("band_high", "2"), ("timeout", "900"), ("model", "<x>")):
        bad = admin.post("/ai/settings", data={"csrf": token, **FORM, key: value}, headers=JSON)
        assert bad.status_code == 400, (key, value)
    assert _saved(env)["url"] == "http://192.168.1.10:11434"  # unchanged


def test_test_connection_lists_models(env, admin, ollama):  # noqa: F811
    admin.get("/ai")
    token = csrf_of(admin)
    r = admin.post("/ai/test", data={"csrf": token}, headers=JSON)
    assert r.status_code == 400 and not ollama.urls  # no address saved yet
    assert admin.post("/ai/settings", data={"csrf": token, **FORM}, headers=JSON).status_code == 200
    r = admin.post("/ai/test", data={"csrf": token}, headers=JSON)
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "qwen2.5:7b" in body and "gemma3:4b" in body
    assert ollama.urls == ["http://192.168.1.10:11434/api/tags"]
    ollama.models = [{"name": "llama3:8b"}]
    r = admin.post("/ai/test", data={"csrf": token}, headers=JSON)
    assert r.status_code == 400 and "ikke installeret" in r.get_data(as_text=True)
    ollama.fail = ai.OllamaError("ingen forbindelse (ConnectionError)")
    r = admin.post("/ai/test", data={"csrf": token}, headers=JSON)
    assert r.status_code == 400 and "Ingen forbindelse til Ollama" in r.get_data(as_text=True)
    r = admin.post("/ai/test", data={"csrf": token, "url": "http://1.1.1.1:11434"}, headers=JSON)
    assert r.status_code == 400 and len(ollama.urls) == 3  # a public address is never contacted
    assert any(a["action"] == "ai_test" for a in env.audit())


def test_evaluation_table_is_escaped(env, admin):  # noqa: F811
    ai.ensure_schema(env.conn)
    env.conn.execute("INSERT INTO ai_verdicts(account, message_id, score_before, threshold, mode, status, verdict, "
                     "confidence, reason, model, latency_ms, points, late, applied, created_at) "
                     "VALUES('bynet','e@x',6.5,10,'shadow','ok','phishing',0.9,?,'qwen2.5:7b',800,3.0,0,'record',?)",
                     (EVIL, NOW))
    env.conn.execute("INSERT OR REPLACE INTO messages(account, message_id, first_seen, last_seen, current_folder, "
                     "our_action, sender, subject) VALUES('bynet','e@x',1,1,'INBOX','none',?,?)",
                     ("evil@x.dk", EVIL))
    env.conn.commit()
    html = text(admin.get("/ai"))
    assert EVIL not in html and "&lt;script&gt;" in html
    assert "phishing 90 %" in html and "Blev i indbakken" in html and "+3 point" in html
    assert "Vurderet" in html and "Falske positiver" in html
