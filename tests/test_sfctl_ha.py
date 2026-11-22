"""sfctl ha-token create|revoke|status (2.3.6, B26; since 2.11.0 an alias
for the API key "Home Assistant") and sfctl api-key list|create|delete
(2.11.0) against the real schema (the env fixture of test_sfctl)."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3

import dashboard  # noqa: E402
from test_sfctl import audit_records, env, last_audit, run  # noqa: F401,E402 - env = fixture


def _keys(e) -> list[tuple]:
    conn = sqlite3.connect(e.db)
    try:
        return conn.execute("SELECT id, name, scope, sha256, hint, lan_only, expires_at FROM ui_api_keys "
                            "ORDER BY id").fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


def test_status_without_token(env, capsys, monkeypatch):
    code, o, _ = run(capsys, monkeypatch, "ha-token", "status")
    assert code == 0 and "ingen" in o and "/api/v1/ha" in o


def test_create_shows_token_once_and_stores_hash(env, capsys, monkeypatch):
    code, o, _ = run(capsys, monkeypatch, "ha-token", "create")
    assert code == 0
    tok = re.search(r"(sf_[A-Za-z0-9_-]{43})", o).group(1)
    assert f'spamfilter_auth: "Bearer {tok}"' in o
    (kid, name, scope, sha, hint, lan, exp), = _keys(env)
    assert (name, scope, lan, exp, hint) == ("Home Assistant", "read", 1, None, tok[-4:])
    assert sha == hashlib.sha256(tok.encode()).hexdigest()
    rec = last_audit(env)
    assert (rec["action"], rec["actor"], rec["ip"]) == ("ha_token_create", "cli", "local")
    assert tok not in json.dumps(audit_records(env))
    code, o, _ = run(capsys, monkeypatch, "ha-token", "status")
    assert code == 0 and "aktiv" in o and "aldrig" in o and tok not in o
    assert dashboard.ha_token_matches(tok)


def test_replace_asks_first(env, capsys, monkeypatch):
    run(capsys, monkeypatch, "ha-token", "create")
    first = _keys(env)
    code, _, e = run(capsys, monkeypatch, "ha-token", "create", answers=["nej"])
    assert code == 1 and "intet er ændret" in e and _keys(env) == first
    code, o, _ = run(capsys, monkeypatch, "ha-token", "create", answers=["ja"])
    assert code == 0 and _keys(env) != first and len(_keys(env)) == 1
    assert "erstattede" in last_audit(env)["detail"]
    code, _, _ = run(capsys, monkeypatch, "ha-token", "create", "--yes")
    assert code == 0


def test_revoke(env, capsys, monkeypatch):
    run(capsys, monkeypatch, "ha-token", "create")
    code, o, _ = run(capsys, monkeypatch, "ha-token", "revoke")
    assert code == 0 and "tilbagekaldt" in o and _keys(env) == []
    assert last_audit(env)["action"] == "ha_token_revoke"
    n = len(audit_records(env))
    code, o, _ = run(capsys, monkeypatch, "ha-token", "revoke")
    assert code == 0 and "ingen" in o and len(audit_records(env)) == n


def test_ha_token_revoke_leaves_other_keys(env, capsys, monkeypatch):
    run(capsys, monkeypatch, "api-key", "create", "--name", "Kontrolrum")
    run(capsys, monkeypatch, "ha-token", "create")
    run(capsys, monkeypatch, "ha-token", "revoke")
    assert [k[1] for k in _keys(env)] == ["Kontrolrum"]


# ---- sfctl api-key (2.11.0)


def test_api_key_list_create_delete(env, capsys, monkeypatch):
    code, o, _ = run(capsys, monkeypatch, "api-key", "list")
    assert code == 0 and "ingen" in o
    code, o, _ = run(capsys, monkeypatch, "api-key", "create", "--name", "Backup-script", "--scope", "control",
                     "--anywhere", "--expires", "30")
    assert code == 0
    tok = re.search(r"(sf_[A-Za-z0-9_-]{43})", o).group(1)
    assert f"Authorization: Bearer {tok}" in o
    (kid, name, scope, sha, hint, lan, exp), = _keys(env)
    assert (name, scope, lan, hint) == ("Backup-script", "control", 0, tok[-4:]) and exp
    rec = last_audit(env)
    assert rec["action"] == "api_key_create" and "Backup-script" in rec["detail"] and tok not in json.dumps(rec)
    code, o, _ = run(capsys, monkeypatch, "api-key", "list")
    assert code == 0 and "Backup-script" in o and f"sf_…{tok[-4:]}" in o and "Læse og styre" in o
    assert tok not in o and sha not in o and "også udefra" in o
    # Same name twice is refused.
    code, _, e = run(capsys, monkeypatch, "api-key", "create", "--name", "backup-script")
    assert code != 0 and "allerede" in e
    # Delete asks first, then the key is gone.
    code, _, e = run(capsys, monkeypatch, "api-key", "delete", str(kid), answers=["nej"])
    assert code == 1 and len(_keys(env)) == 1
    code, o, _ = run(capsys, monkeypatch, "api-key", "revoke", str(kid), "--yes")
    assert code == 0 and "slettet" in o and _keys(env) == []
    assert last_audit(env)["action"] == "api_key_delete"
    code, _, e = run(capsys, monkeypatch, "api-key", "delete", str(kid), "--yes")
    assert code != 0 and "ingen nøgle" in e


def test_api_key_create_needs_a_name(env, capsys, monkeypatch):
    code, _, e = run(capsys, monkeypatch, "api-key", "create")
    assert code != 0 and "navn" in e and _keys(env) == []


def test_bad_action_is_usage_error(env, capsys, monkeypatch):
    assert run(capsys, monkeypatch, "ha-token", "show")[0] == 2
    assert run(capsys, monkeypatch, "ha-token")[0] == 2


def test_unlock_ip_clears_home_assistant_lock(env, capsys, monkeypatch):
    conn = sqlite3.connect(env.db)
    conn.execute("INSERT INTO login_attempts(key, failures, first_at, locked_until) VALUES('ha:192.168.1.20', 5, 1, ?)",
                 (2_000_000_000,))
    conn.commit()
    conn.close()
    code, o, _ = run(capsys, monkeypatch, "users")
    assert code == 0 and "192.168.1.20" in o
    code, o, _ = run(capsys, monkeypatch, "unlock", "--ip", "192.168.1.20")
    assert code == 0 and "ophævet" in o
    conn = sqlite3.connect(env.db)
    assert conn.execute("SELECT COUNT(*) FROM login_attempts").fetchone()[0] == 0
    conn.close()
