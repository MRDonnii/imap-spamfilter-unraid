"""2.7: sfctl doctor reports the local AI (Ollama) as a warning only - it
reads the state the engine's worker recorded and never calls Ollama."""

from __future__ import annotations

import json
import time

from test_sfctl import env, run  # noqa: F401 - fixtures

import ai_verdict as ai  # noqa: E402
import filter as engine  # noqa: E402


def _beat(env):  # noqa: F811
    (env.state / "heartbeat").write_text(f"{int(time.time())} boot\n")
    (env.state / "admin-audit.jsonl").touch(mode=0o600)


def _status(**st):
    conn = engine._open_conn()
    try:
        conn.execute("INSERT OR REPLACE INTO engine_state(key, value, updated_at) VALUES(?,?,?)",
                     (ai.STATUS_KEY, json.dumps(st), int(time.time())))
    finally:
        conn.close()


def _settings(**kw):
    conn = engine._open_conn()
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS settings_kv (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute("INSERT OR REPLACE INTO settings_kv(key, value) VALUES('ai', ?)", (json.dumps(kw),))
    finally:
        conn.close()


class NoNetwork:
    def post_json(self, *a, **k):
        raise AssertionError("doctor must not call Ollama")

    get_json = post_json


def test_doctor_ai_states(env, capsys, monkeypatch):  # noqa: F811
    monkeypatch.setattr(ai, "TRANSPORT", NoNetwork())
    _beat(env)
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert code == 0 and "AI-vurdering (Prøv): ikke sat op – ingen Ollama-adresse gemt" in o
    _settings(mode="shadow", url="http://192.168.1.10:11434")
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert code == 0 and "AI-vurdering (Prøv): ingen vurderinger endnu" in o
    now = int(time.time())
    _status(last_ok_at=now - 120, errors=0)
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert code == 0 and "AI-vurdering (Prøv): Ollama svarede for" in o
    _status(last_ok_at=now - 3600, last_error_at=now - 60, last_error="ingen forbindelse (ConnectionError)",
            errors=4, backoff_until=now + 400)
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert code == 0, o  # a warning, never an error: mail is decided without AI
    assert "[FEJL]" not in o and "Ollama svarer ikke" in o and "4 fejl i træk" in o
    assert "http://192.168.1.10:11434" in o
