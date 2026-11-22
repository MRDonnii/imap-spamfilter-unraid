"""sfctl - the break-glass admin CLI (`docker exec -it spamfilter sfctl ...`).

Every command runs against a temp STATE_DIR / CONFIG_PATH with the REAL
schema (filter.init_db + dashboard.init_ui_db) and the real dashboard /
ui_admin / filter helpers - no fakes.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
FILTER_DIR = ROOT / "filter"
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fakes_ui import fast_hash  # noqa: E402  (also puts filter/ on sys.path)

import dashboard  # noqa: E402
import filter as engine  # noqa: E402
import mailer  # noqa: E402
import sfctl  # noqa: E402
from fakes_ui_mail import FakeSMTP, configure_smtp, flush, install  # noqa: E402

PW = "korrekt-hest-batteri-42"
NEW_PW = "nyt-sikkert-kodeord-2026"


class Env:
    def __init__(self, tmp_path: Path) -> None:
        self.state = tmp_path / "state"
        self.cfgdir = tmp_path / "config"
        self.config = self.cfgdir / "accounts.yml"
        self.users = self.state / "dashboard_users"
        self.audit = self.state / "admin-audit.jsonl"
        self.db = self.state / "spamfilter.db"


@pytest.fixture
def env(tmp_path, monkeypatch, capsys):
    e = Env(tmp_path)
    e.state.mkdir(mode=0o700)
    e.cfgdir.mkdir(mode=0o700)
    secrets_dir = e.state / "imap-secrets"
    secrets_dir.mkdir(mode=0o700)
    for name in ("bynet", "molt", "sofie"):
        (secrets_dir / name).write_text("imap-secret\n")
        (secrets_dir / name).chmod(0o600)
    cfg = {"defaults": {"bayes_user": "hjemmeserver", "mode": "flag"},
           "accounts": [
               {"name": "bynet", "user": "ole@bynet.example", "imap_host": "imap.gigahost.dk",
                "password_file": str(secrets_dir / "bynet"), "mode": "move", "junk": "Spamfilter"},
               {"name": "molt", "user": "ole@molt.example", "imap_host": "mail.scannet.dk",
                "password_file": str(secrets_dir / "molt"), "threshold": 6.0},
               {"name": "sofie", "user": "sofie@molt.example", "imap_host": "mail.scannet.dk",
                "password_file": str(secrets_dir / "sofie"), "mode": "shadow"},
           ]}
    e.config.write_text(yaml.safe_dump(cfg, sort_keys=False))
    e.config.chmod(0o600)

    monkeypatch.setenv("STATE_DIR", str(e.state))
    monkeypatch.setenv("CONFIG_PATH", str(e.config))
    monkeypatch.delenv("TRUSTED_PROXIES", raising=False)
    monkeypatch.delenv("TRUSTED_PROXY", raising=False)
    monkeypatch.delenv("DASHBOARD_USERS", raising=False)
    monkeypatch.delenv("DASHBOARD_USER", raising=False)
    # Record originals so the global writes of sfctl.configure() are undone.
    for attr in ("STATE_DIR", "CONFIG_PATH", "DB_PATH", "USERS_FILE", "SECRET_PATH", "AUDIT_FILE",
                 "RELOAD_FILE", "AUDIT_IP_NO_REQUEST", "TRUSTED_PROXY_NETS", "TRUSTED_PROXIES_SPEC"):
        monkeypatch.setattr(dashboard, attr, getattr(dashboard, attr))
    for attr in ("STATE_DIR", "DB_PATH", "CONFIG_PATH", "HEARTBEAT_PATH", "RELOAD_PATH"):
        monkeypatch.setattr(engine, attr, getattr(engine, attr))
    monkeypatch.setattr(dashboard, "engine", engine)
    monkeypatch.setattr(dashboard, "PBKDF2_ITERATIONS", 1000)
    monkeypatch.setattr(engine, "_rspamd_alive", lambda: True)
    monkeypatch.setattr(sfctl, "_euid", lambda: 10099)
    monkeypatch.setattr(sfctl, "OWNER_UID", os.getuid())
    for attr in ("STATE_DIR", "CONFIG_PATH", "DB_PATH", "PASSWORD_FILE", "AUDIT_FILE", "AUTO_WORKER"):
        monkeypatch.setattr(mailer, attr, getattr(mailer, attr))
    sfctl.configure()
    engine.init_db()
    dashboard.init_ui_db()
    e.users.write_text(f"admin:{fast_hash(PW)}:admin:3\nanna:{fast_hash(PW)}:bynet:1\n")
    e.users.chmod(0o600)
    dashboard.set_user_perms("anna", ["release"], "admin")
    capsys.readouterr()
    return e


def run(capsys, monkeypatch, *argv, answers=(), passwords=()):
    """sfctl.main(argv) -> (exit code, stdout, stderr)."""
    a, p = list(answers), list(passwords)
    monkeypatch.setattr(sfctl, "_input", lambda prompt: a.pop(0) if a else "")
    monkeypatch.setattr(sfctl, "_getpass", lambda prompt: p.pop(0))
    code = sfctl.main(list(argv))
    o = capsys.readouterr()
    return code, o.out, o.err


def audit_records(e: Env) -> list[dict]:
    if not e.audit.exists():
        return []
    return [json.loads(line) for line in e.audit.read_text().splitlines() if line.strip()]


def last_audit(e: Env) -> dict:
    return audit_records(e)[-1]


def gen_of(name: str) -> int:
    return dashboard.load_users()[name].gen


def raw_entry(e: Env, name: str) -> dict:
    return next(a for a in yaml.safe_load(e.config.read_text())["accounts"] if a["name"] == name)


def lock(keys):
    for _ in range(dashboard.LOGIN_MAX_FAILURES):
        dashboard._throttle_begin(keys)


def enroll_2fa(name: str) -> None:
    secret = dashboard.twofa_pending_secret(name)
    assert dashboard.twofa_confirm(name, dashboard.totp(secret), actor=name)
    assert dashboard.twofa_status(name)["enabled"]


# ---------------------------------------------------------------------------
# Read-only commands
# ---------------------------------------------------------------------------


def test_status(env, capsys, monkeypatch):
    (env.state / "heartbeat").write_text(f"{int(__import__('time').time()) - 5} boot\n")
    dashboard.settings_set("external_url", "https://spam.example.dk")
    conn = engine._open_conn()
    engine.update_account_status(conn, "bynet", state="idle", last_error="LOGIN failed", last_error_at=1)
    engine.open_circuit(conn, "bynet", "for mange flytninger")
    conn.close()
    enroll_2fa("admin")
    code, o, _ = run(capsys, monkeypatch, "status")
    assert code == 0
    assert f"Spamfilter {engine.VERSION}" in o
    for text in ("bynet", "ole@bynet.example", "Filtrér (move)", "Markér (flag)", "Overvåg (shadow)", "6",
                 "LOGIN failed", "STOPPET af sikkerhedsbremsen", "sfctl resume-moves bynet", "sek. siden",
                 "Brugere: 2 (1 administrator(er)), to-trins-login slået til for 1",
                 "Betroede proxyer: (ingen)", "Ekstern adresse:  https://spam.example.dk"):
        assert text in o, text
    assert audit_records(env) == []  # read-only


def test_status_survives_broken_config(env, capsys, monkeypatch):
    env.config.write_text("accounts: [")
    code, o, _ = run(capsys, monkeypatch, "status")
    assert code == 0 and "FEJL: accounts.yml kan ikke indlæses" in o


def test_users_lists_roles_permissions_2fa_and_locks(env, capsys, monkeypatch):
    enroll_2fa("admin")
    dashboard.twofa_set_required("anna", True, "admin")
    dashboard.record_login("admin", "192.168.1.7")
    lock(["user:anna", "ip:203.0.113.9"])
    code, o, _ = run(capsys, monkeypatch, "users")
    assert code == 0
    admin_block, anna_block = o.split("\nanna")[0], o.split("\nanna")[1]
    assert "Administrator" in admin_block and "postkasser:  alle" in admin_block
    assert "2-trin:      slået til" in admin_block and "fra 192.168.1.7" in admin_block
    assert "spærret:     nej" in admin_block
    assert "Bruger" in anna_block and "postkasser:  bynet" in anna_block
    assert "Frigive og flytte post" in anna_block and "Se alle beskeder" not in anna_block
    assert "slået fra, påkrævet" in anna_block and "SPÆRRET" in anna_block
    assert "Spærrede IP-adresser: 203.0.113.9" in o


def test_audit_tail_and_sanitising(env, capsys, monkeypatch):
    for i in range(5):
        dashboard.audit("login", result="failed", actor=f"evil\x1b[2J{i}")
    code, o, _ = run(capsys, monkeypatch, "audit", "--tail", "3")
    assert code == 0
    lines = o.strip().splitlines()
    assert len(lines) == 3 and "\x1b" not in o
    assert lines[0].split()[2].startswith("evil?[2J2") and lines[-1].split()[2].endswith("4")
    assert run(capsys, monkeypatch, "audit", "--tail", "0")[0] == 2


# ---------------------------------------------------------------------------
# Passwords, sessions, users
# ---------------------------------------------------------------------------


def test_reset_password_prompt(env, capsys, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    lock(["user:anna"])
    before = gen_of("anna")
    code, o, e = run(capsys, monkeypatch, "reset-password", "anna", passwords=[NEW_PW, NEW_PW])
    assert code == 0, e
    assert dashboard.check_login("anna", NEW_PW) is not None
    assert dashboard.check_login("anna", PW) is None
    assert gen_of("anna") == before + 1  # logged out everywhere
    assert not sfctl._locked_keys()
    rec = last_audit(env)
    assert rec["action"] == "user_password" and rec["actor"] == "cli" and rec["ip"] == "local"
    assert NEW_PW not in o + e + env.audit.read_text() + caplog.text
    assert oct(env.users.stat().st_mode & 0o777) == "0o600"
    # comments + other users untouched; scope of anna kept
    assert dashboard.load_users()["anna"].accounts == frozenset({"bynet"})


def test_reset_password_rejects_short_and_mismatch(env, capsys, monkeypatch):
    before = env.users.read_text()
    code, _, e = run(capsys, monkeypatch, "reset-password", "anna", passwords=["kort"])
    assert code == 1 and "mindst 12 tegn" in e
    code, _, e = run(capsys, monkeypatch, "reset-password", "anna", passwords=[NEW_PW, NEW_PW + "x"])
    assert code == 1 and "ikke ens" in e
    assert env.users.read_text() == before and audit_records(env) == []
    assert run(capsys, monkeypatch, "reset-password", "nobody", "--generate")[0] == 1


def test_reset_password_generate_prints_once(env, capsys, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    code, o, e = run(capsys, monkeypatch, "reset-password", "admin", "--generate")
    assert code == 0
    found = re.findall(r"^\s{4}(\S+)$", o, re.M)
    assert len(found) == 1
    pw = found[0]
    assert len(pw.replace("-", "")) == 24 and o.count(pw) == 1
    assert dashboard.check_login("admin", pw) is not None
    assert pw not in e + env.audit.read_text() + caplog.text
    assert "genereret" in last_audit(env)["detail"]


def test_env_user_is_read_only(env, capsys, monkeypatch):
    monkeypatch.setenv("DASHBOARD_USERS", f"envadmin:{fast_hash(PW)}:admin")
    code, _, e = run(capsys, monkeypatch, "reset-password", "envadmin", "--generate")
    assert code == 1 and "miljøvariabel" in e


def test_disable_2fa_clears_secret_codes_and_requirement(env, capsys, monkeypatch):
    enroll_2fa("anna")
    dashboard.twofa_set_required("anna", True, "admin")
    # declined confirmation: nothing changes
    code, _, e = run(capsys, monkeypatch, "disable-2fa", "anna", answers=["nej"])
    assert code == 1 and "Afbrudt" in e and dashboard.twofa_status("anna")["enabled"]
    code, o, _ = run(capsys, monkeypatch, "disable-2fa", "anna", answers=["ja"])
    assert code == 0
    row = dashboard._twofa_row("anna")
    assert row["secret"] is None and row["recovery"] is None and row["required"] == 0
    rec = last_audit(env)
    assert (rec["action"], rec["actor"], rec["ip"]) == ("twofa_reset", "cli", "local")
    assert "krav fjernet" in rec["detail"]


def test_disable_2fa_keep_required(env, capsys, monkeypatch):
    enroll_2fa("admin")  # also works for the last admin
    dashboard.twofa_set_required("admin", True, "admin")
    code, o, _ = run(capsys, monkeypatch, "disable-2fa", "admin", "--keep-required", "--yes")
    assert code == 0 and "sættes op igen" in o
    st = dashboard.twofa_status("admin")
    assert not st["enabled"] and st["required"]
    code, o, _ = run(capsys, monkeypatch, "disable-2fa", "anna", "--yes")
    assert code == 0 and "har ikke to-trins-login" in o
    assert run(capsys, monkeypatch, "disable-2fa", "nobody", "--yes")[0] == 1


def test_unlock_user_ip_all(env, capsys, monkeypatch):
    lock(["user:anna", "2fa:anna", "ip:203.0.113.9", "2faip:203.0.113.9", "user:bo"])
    assert run(capsys, monkeypatch, "unlock")[0] == 2
    assert run(capsys, monkeypatch, "unlock", "anna", "--all")[0] == 2
    assert run(capsys, monkeypatch, "unlock", "--ip", "not-an-ip")[0] == 2
    code, o, _ = run(capsys, monkeypatch, "unlock", "Anna")
    assert code == 0 and "ophævet" in o
    assert set(sfctl._locked_keys()) == {"ip:203.0.113.9", "2faip:203.0.113.9", "user:bo"}
    code, _, _ = run(capsys, monkeypatch, "unlock", "--ip", "203.0.113.9")
    assert set(sfctl._locked_keys()) == {"user:bo"}
    assert last_audit(env)["action"] == "login_unlock" and last_audit(env)["actor"] == "cli"
    code, o, _ = run(capsys, monkeypatch, "unlock", "--all")
    assert code == 0 and not sfctl._lock_rows()
    code, o, _ = run(capsys, monkeypatch, "unlock", "anna")
    assert code == 0 and "ingen spærring" in o


def test_logout_all(env, capsys, monkeypatch):
    g_admin, g_anna = gen_of("admin"), gen_of("anna")
    code, o, _ = run(capsys, monkeypatch, "logout-all", "anna")
    assert code == 0 and gen_of("anna") == g_anna + 1 and gen_of("admin") == g_admin
    code, _, e = run(capsys, monkeypatch, "logout-all")  # needs confirmation
    assert code == 1 and gen_of("admin") == g_admin
    code, o, _ = run(capsys, monkeypatch, "logout-all", "--yes")
    assert code == 0 and gen_of("admin") == g_admin + 1 and gen_of("anna") == g_anna + 2
    assert last_audit(env)["detail"].startswith("alle")
    assert run(capsys, monkeypatch, "logout-all", "nobody")[0] == 1


def test_create_admin(env, capsys, monkeypatch):
    code, o, _ = run(capsys, monkeypatch, "create-admin", "nød", "--generate")
    assert code == 1  # invalid name
    code, o, e = run(capsys, monkeypatch, "create-admin", "anna", "--generate")
    assert code == 1 and "findes allerede" in e
    code, o, _ = run(capsys, monkeypatch, "create-admin", "nod.admin", passwords=[NEW_PW, NEW_PW])
    assert code == 0
    u = dashboard.load_users()["nod.admin"]
    assert u.admin and u.gen > 0 and dashboard.check_login("nod.admin", NEW_PW)
    assert dashboard.user_meta("nod.admin")["stored"]
    rec = last_audit(env)
    assert (rec["action"], rec["actor"], rec["ip"]) == ("user_add", "cli", "local")
    assert NEW_PW not in o + env.audit.read_text()


def test_set_role_last_admin_guard(env, capsys, monkeypatch):
    before = env.users.read_text()
    code, _, e = run(capsys, monkeypatch, "set-role", "admin", "user", "--yes")
    assert code == 1 and "sidste administrator" in e and env.users.read_text() == before
    assert run(capsys, monkeypatch, "set-role", "admin", "boss")[0] == 2
    code, o, _ = run(capsys, monkeypatch, "set-role", "anna", "admin")
    assert code == 0 and dashboard.load_users()["anna"].admin
    assert dashboard.load_users()["anna"].accounts == frozenset()
    # demote needs confirmation
    code, _, e = run(capsys, monkeypatch, "set-role", "admin", "user", answers=["nej"])
    assert code == 1 and dashboard.load_users()["admin"].admin
    code, o, _ = run(capsys, monkeypatch, "set-role", "admin", "user", answers=["ja"])
    assert code == 0
    u = dashboard.load_users()["admin"]
    assert not u.admin and u.scope == dashboard.NO_ACCOUNTS
    assert dashboard.user_meta("admin")["stored"]
    rec = last_audit(env)
    assert rec["action"] == "user_access" and rec["actor"] == "cli"
    code, o, _ = run(capsys, monkeypatch, "set-role", "anna", "admin")
    assert code == 0 and "allerede" in o


# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------


def test_pause_resume_round_trip(env, capsys, monkeypatch):
    original = yaml.safe_load(env.config.read_text())
    # --all asks first
    code, _, e = run(capsys, monkeypatch, "pause", "--all", answers=["nej"])
    assert code == 1 and yaml.safe_load(env.config.read_text()) == original
    code, o, e = run(capsys, monkeypatch, "pause", "--all", answers=["ja"])
    assert code == 0, e
    accs = {a.name: a.mode for a in engine.load_account_configs(env.config)}
    assert accs == {"bynet": "shadow", "molt": "shadow", "sofie": "shadow"}
    assert "sofie kører allerede i Overvåg" in o
    assert (env.state / "reload_requested").exists()
    memo = json.loads(dashboard.settings_get("sfctl_pause:bynet"))
    assert memo["mode"] == "move" and memo["explicit"] is True
    assert json.loads(dashboard.settings_get("sfctl_pause:molt"))["explicit"] is False
    assert dashboard.settings_get("sfctl_pause:sofie") is None
    rec = last_audit(env)
    assert (rec["action"], rec["actor"], rec["ip"], rec["result"]) == ("account_mode", "cli", "local", "ok")
    assert "bynet move->shadow" in rec["detail"] and "molt flag->shadow" in rec["detail"]
    assert dashboard.config_sha256() == dashboard.settings_get("config_sha256")
    assert oct(env.config.stat().st_mode & 0o777) == "0o600"
    # a second pause does not overwrite the memory with 'shadow'
    code, o, _ = run(capsys, monkeypatch, "pause", "bynet")
    assert code == 0 and json.loads(dashboard.settings_get("sfctl_pause:bynet"))["mode"] == "move"
    # sofie was never paused by sfctl: refused without --mode
    code, _, e = run(capsys, monkeypatch, "resume", "sofie")
    assert code == 1 and "ingen husket tilstand" in e
    code, o, e = run(capsys, monkeypatch, "resume", "--all")
    assert code == 0, e
    assert yaml.safe_load(env.config.read_text()) == original  # exactly restored (molt inherits again)
    assert "mode" not in raw_entry(env, "molt")
    assert dashboard.settings_get("sfctl_pause:bynet") is None
    assert dashboard.settings_get("sfctl_pause:molt") is None
    code, o, _ = run(capsys, monkeypatch, "resume", "--all")
    assert code == 0 and "intet at genoptage" in o


def test_resume_with_mode_and_move_guard(env, capsys, monkeypatch):
    assert run(capsys, monkeypatch, "resume", "--all", "--mode", "flag")[0] == 2
    assert run(capsys, monkeypatch, "resume")[0] == 2
    assert run(capsys, monkeypatch, "resume", "nope")[0] == 1
    code, o, e = run(capsys, monkeypatch, "resume", "sofie", "--mode", "move")
    assert code == 1 and "Spamfilter-mappen" in e and raw_entry(env, "sofie")["mode"] == "shadow"
    code, o, e = run(capsys, monkeypatch, "resume", "sofie", "--mode", "flag")
    assert code == 0, e
    assert raw_entry(env, "sofie")["mode"] == "flag"


def test_pause_single_and_changed_meanwhile(env, capsys, monkeypatch):
    code, o, _ = run(capsys, monkeypatch, "pause", "bynet")  # single account: no confirmation
    assert code == 0 and raw_entry(env, "bynet")["mode"] == "shadow"
    assert last_audit(env)["account"] == "bynet"
    # someone switches it in the UI meanwhile -> resume does not touch it
    dashboard.save_config(lambda raw: raw["accounts"][0].__setitem__("mode", "flag"), "admin", "account_mode")
    code, o, _ = run(capsys, monkeypatch, "resume", "bynet")
    assert code == 0 and "ændret i mellemtiden" in o and raw_entry(env, "bynet")["mode"] == "flag"
    assert dashboard.settings_get("sfctl_pause:bynet") is None


def test_pause_rejected_config_keeps_no_memory(env, capsys, monkeypatch):
    env.config.write_text(env.config.read_text().replace("imap_host: imap.gigahost.dk", "imap_port: nope\n  imap_host: x"))
    code, _, e = run(capsys, monkeypatch, "pause", "--all", "--yes")
    assert code == 1 and "accounts.yml" in e
    assert dashboard.settings_get("sfctl_pause:bynet") is None


def test_resume_moves(env, capsys, monkeypatch):
    conn = engine._open_conn()
    engine.open_circuit(conn, "bynet", "for mange")
    conn.close()
    code, o, _ = run(capsys, monkeypatch, "resume-moves", "bynet")
    assert code == 0 and "genoptaget" in o
    conn = engine._open_conn()
    assert not engine.circuit_open(conn, "bynet")
    assert engine.circuit_status(conn, "bynet")["resumed_by"] == "cli"
    conn.close()
    rec = last_audit(env)
    assert (rec["action"], rec["account"], rec["result"], rec["actor"]) == ("account_resume_moves", "bynet", "ok", "cli")
    code, o, _ = run(capsys, monkeypatch, "resume-moves", "bynet")
    assert code == 0 and "ikke stoppet" in o and last_audit(env)["result"] == "noop"
    assert run(capsys, monkeypatch, "resume-moves", "ukendt")[0] == 1


def test_external_url(env, capsys, monkeypatch):
    code, o, _ = run(capsys, monkeypatch, "external-url")
    assert code == 0 and "(ingen)" in o
    code, o, _ = run(capsys, monkeypatch, "external-url", "spam.example.dk")
    assert code == 0 and dashboard.settings_get("external_url") == "https://spam.example.dk"
    assert last_audit(env)["action"] == "settings_external_url"
    code, _, e = run(capsys, monkeypatch, "external-url", "https://x.dk/sti")
    assert code == 1 and "uden sti" in e
    assert run(capsys, monkeypatch, "external-url", "--clear", "x.dk")[0] == 2
    code, o, _ = run(capsys, monkeypatch, "external-url", "--clear")
    assert code == 0 and dashboard.settings_get("external_url") == ""
    assert "fjernet" in o


def test_reload(env, capsys, monkeypatch):
    code, o, _ = run(capsys, monkeypatch, "reload")
    assert code == 0 and (env.state / "reload_requested").exists()
    rec = last_audit(env)
    assert (rec["action"], rec["actor"], rec["ip"]) == ("filter_restart", "cli", "local")


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


def test_doctor_healthy(env, capsys, monkeypatch):
    (env.state / "heartbeat").write_text(f"{int(__import__('time').time())} boot\n")
    (env.state / "admin-audit.jsonl").touch(mode=0o600)
    code, o, e = run(capsys, monkeypatch, "doctor")
    assert code == 0, o
    assert "[FEJL]" not in o
    for text in ("accounts.yml er gyldig (3 konti)", "integritetstjekket", "rspamd svarer",
                 "brugerfilen kan læses (2 brugere)", "1 administrator(er)"):
        assert text in o, text
    assert "administratorer uden to-trins-login: admin" in o  # a warning, not an error


def test_doctor_finds_problems_and_offers_fixes(env, capsys, monkeypatch):
    env.users.write_text(f"anna:{fast_hash(PW)}:bynet:0\ngarbage-line\n")
    env.users.chmod(0o644)
    env.state.chmod(0o755)
    env.config.write_text("accounts: [")
    monkeypatch.setattr(engine, "_rspamd_alive", lambda: False)
    monkeypatch.setattr(sfctl, "OWNER_UID", os.getuid() + 1)
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert code == 1
    assert "der er ingen administrator" in o
    assert "sfctl create-admin <navn> --generate" in o
    assert "accounts.yml kan ikke indlæses" in o
    assert "rspamd svarer ikke" in o
    assert "1 linje(r) i brugerfilen" in o
    assert "[FEJL] følsomme filer kan læses af andre" in o and "chmod 0600" in o
    assert "chown -R" in o


def test_doctor_accepts_root_written_host_status_files():
    assert sfctl._owner_ok("backup-status.json", 0)
    assert sfctl._owner_ok("host-status.json", 0)
    assert sfctl._owner_ok("spamfilter.db", sfctl.OWNER_UID)
    assert not sfctl._owner_ok("spamfilter.db", 0)
    assert not sfctl._owner_ok("backup-status.json", 1234)


def test_doctor_reports_corrupt_db(env, capsys, monkeypatch):
    env.db.write_bytes(b"not a database at all" * 100)
    for suffix in ("-wal", "-shm"):
        Path(str(env.db) + suffix).unlink(missing_ok=True)
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert code == 1 and "databasen" in o


# ---------------------------------------------------------------------------
# Safety: root refusal, usage, no threads/servers, image install
# ---------------------------------------------------------------------------


def test_refuses_root_without_allow_root(env, capsys, monkeypatch):
    monkeypatch.setattr(sfctl, "_euid", lambda: 0)
    before = env.users.read_text()
    code, o, e = run(capsys, monkeypatch, "logout-all", "anna")
    assert code == 1 and "root" in e and env.users.read_text() == before
    assert audit_records(env) == []
    code, o, e = run(capsys, monkeypatch, "--allow-root", "status")
    assert code == 0
    code, o, e = run(capsys, monkeypatch, "logout-all", "anna", "--allow-root")
    assert code == 0 and env.users.read_text() != before


def test_usage_errors_exit_2(env, capsys, monkeypatch):
    assert run(capsys, monkeypatch)[0] == 2
    assert run(capsys, monkeypatch, "frobnicate")[0] == 2
    assert run(capsys, monkeypatch, "reset-password")[0] == 2
    assert run(capsys, monkeypatch, "pause")[0] == 2
    assert run(capsys, monkeypatch, "pause", "bynet", "--all")[0] == 2


def test_help_is_danish_and_lists_commands():
    help_text = sfctl.build_parser().format_help()
    for cmd in ("status", "users", "reset-password", "disable-2fa", "unlock", "logout-all", "create-admin",
                "set-role", "pause", "resume", "resume-moves", "external-url", "audit", "reload", "doctor"):
        assert cmd in help_text
    assert "docker exec -it spamfilter sfctl" in help_text and "Exitkoder" in help_text


def test_import_starts_no_threads_or_server(tmp_path):
    code = ("import threading, sys; before = threading.active_count(); import sfctl, dashboard, filter; "
            "assert threading.active_count() == before, threading.enumerate(); "
            "assert 'waitress' not in sys.modules; print('ok')")
    res = subprocess.run([sys.executable, "-c", code], cwd=FILTER_DIR, capture_output=True, text=True,
                         env={**os.environ, "STATE_DIR": str(tmp_path), "CONFIG_PATH": str(tmp_path / "a.yml")},
                         timeout=60)
    assert res.returncode == 0 and "ok" in res.stdout, res.stderr


def test_dockerfile_installs_sfctl():
    text = (FILTER_DIR / "Dockerfile.unraid").read_text()
    assert "COPY sfctl /usr/local/bin/sfctl" in text
    assert "chown root:root /usr/local/bin/sfctl" in text
    assert "chmod 0755 /usr/local/bin/sfctl" in text
    # installed before the image drops to the runtime user
    assert text.index("/usr/local/bin/sfctl") < text.index("USER 10099:10099")
    wrapper = FILTER_DIR / "sfctl"
    assert os.access(wrapper, os.X_OK)
    body = wrapper.read_text()
    assert body.startswith("#!/bin/sh") and 'exec python -s -E /app/sfctl.py "$@"' in body
    ignore = (FILTER_DIR / "Dockerfile.unraid.dockerignore").read_text().split()
    assert "sfctl" not in ignore and "sfctl.py" not in ignore
    assert (FILTER_DIR / "sfctl.py").exists()  # COPY *.py /app/ picks it up


# ---------------------------------------------------------------------------
# Review fixes: stale pause memory, damaged files, read-only status, root,
# invisible characters, Danish usage
# ---------------------------------------------------------------------------


def test_pause_again_after_ui_change_remembers_the_current_mode(env, capsys, monkeypatch):
    # pause (move) -> owner picks Markér in the WebUI -> pause again -> resume
    # must bring back Markér, never the stale (and unchecked) Filtrér.
    assert run(capsys, monkeypatch, "pause", "bynet")[0] == 0
    dashboard.save_config(lambda raw: raw["accounts"][0].__setitem__("mode", "flag"), "admin", "account_mode")
    assert run(capsys, monkeypatch, "pause", "bynet")[0] == 0
    assert json.loads(dashboard.settings_get("sfctl_pause:bynet"))["mode"] == "flag"
    code, o, e = run(capsys, monkeypatch, "resume", "bynet")
    assert code == 0, e
    assert raw_entry(env, "bynet")["mode"] == "flag" and "Markér" in o


def test_pause_keeps_memory_when_the_config_was_already_written(env, capsys, monkeypatch):
    # save_config can fail AFTER accounts.yml was replaced (locked DB while
    # storing the hash): the accounts ARE in Overvåg, so resume must still work.
    real = dashboard.settings_set

    def flaky(key, value):
        if key == "config_sha256":
            raise sqlite3.OperationalError("database is locked")
        return real(key, value)

    monkeypatch.setattr(dashboard, "settings_set", flaky)
    code, _, e = run(capsys, monkeypatch, "pause", "bynet")
    assert code == 1 and "kunne ikke gemmes" in e
    assert raw_entry(env, "bynet")["mode"] == "shadow"
    assert json.loads(dashboard.settings_get("sfctl_pause:bynet"))["mode"] == "move"
    monkeypatch.setattr(dashboard, "settings_set", real)
    assert run(capsys, monkeypatch, "resume", "bynet")[0] == 0
    assert raw_entry(env, "bynet")["mode"] == "move"


def test_pause_failure_restores_an_older_memory(env, capsys, monkeypatch):
    dashboard.settings_set("sfctl_pause:molt", json.dumps({"mode": "move", "explicit": True, "at": 1}))
    env.config.write_text(env.config.read_text().replace("threshold: 6.0", "threshold: nope"))
    code, _, _ = run(capsys, monkeypatch, "pause", "molt")
    assert code == 1
    assert json.loads(dashboard.settings_get("sfctl_pause:molt"))["at"] == 1


def _break_db(e: Env) -> None:
    e.db.write_bytes(b"not a database at all" * 100)
    for suffix in ("-wal", "-shm"):
        Path(str(e.db) + suffix).unlink(missing_ok=True)


def test_doctor_runs_to_the_end_on_a_corrupt_db_and_says_restore(env, capsys, monkeypatch):
    _break_db(env)
    code, o, e = run(capsys, monkeypatch, "doctor")
    assert code == 1 and e == ""
    assert "databasen er beskadiget" in o and "BACKUP.md" in o
    assert "WebUI-tabellerne" not in o
    assert "administratorer uden to-trins-login" not in o  # unknown, not "off"
    assert "1 administrator(er)" in o and "fejl og" in o   # reached the summary


def test_status_on_a_corrupt_db_still_shows_accounts(env, capsys, monkeypatch):
    _break_db(env)
    code, o, e = run(capsys, monkeypatch, "status")
    assert code == 0, e
    assert "ole@bynet.example" in o and "kør sfctl doctor" in o and "Betroede proxyer" in o


def test_status_never_creates_the_database(env, capsys, monkeypatch):
    _break_db(env)
    env.db.unlink()
    monkeypatch.setattr(dashboard, "_UI_DB_READY", set())
    code, o, e = run(capsys, monkeypatch, "status")
    assert code == 0, e
    assert "findes ikke" in o and not env.db.exists()


def test_damaged_users_file_doctor_explains_and_writers_refuse(env, capsys, monkeypatch):
    env.users.write_bytes(b"admin:\xff\xfe:admin:1\n")
    before = env.users.read_bytes()
    code, o, e = run(capsys, monkeypatch, "doctor")
    assert code == 1 and e == ""
    assert "brugerfilen" in o and "beskadiget" in o and "dashboard_users.beskadiget" in o
    assert "create-admin" in o and "der er ingen administrator" not in o
    code, o, _ = run(capsys, monkeypatch, "status")
    assert code == 0 and "brugerfilen er beskadiget" in o
    for argv in (("create-admin", "nyadmin", "--generate"), ("reset-password", "admin", "--generate"),
                 ("logout-all", "--yes"), ("set-role", "anna", "admin")):
        code, o, e = run(capsys, monkeypatch, *argv)
        assert code == 1 and "beskadiget" in e and "Traceback" not in e, argv
        assert "    " not in o  # no generated password shown for a write that never happened
    assert env.users.read_bytes() == before
    code, _, e = run(capsys, monkeypatch, "users")
    assert code == 1 and "kør sfctl doctor" in e


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any file")
def test_unreadable_users_file_is_never_overwritten(env, capsys, monkeypatch):
    env.users.chmod(0)
    try:
        code, o, _ = run(capsys, monkeypatch, "doctor")
        assert code == 1 and "kan ikke læses af filteret" in o and "chown" in o
        assert "der er ingen administrator" not in o and "brugerfilen kan læses" not in o
        code, _, e = run(capsys, monkeypatch, "create-admin", "nyadmin", "--generate")
        assert code == 1 and "chown" in e
    finally:
        env.users.chmod(0o600)
    assert "nyadmin" not in env.users.read_text() and "admin:" in env.users.read_text()


def test_users_file_write_backs_up_lines_it_cannot_parse(env, capsys, monkeypatch):
    env.users.write_text(env.users.read_text() + "bent-uden-hash\n")
    code, o, e = run(capsys, monkeypatch, "reset-password", "anna", "--generate")
    assert code == 0, e
    backups = list(env.state.glob("dashboard_users.backup-*"))
    assert len(backups) == 1 and "bent-uden-hash" in backups[0].read_text()
    assert oct(backups[0].stat().st_mode & 0o777) == "0o600"
    assert str(backups[0]) in o and "bent-uden-hash" not in env.users.read_text()


def test_reset_password_mentions_active_2fa_and_never_prints_secrets(env, capsys, monkeypatch):
    enroll_2fa("anna")
    secret = dashboard._twofa_row("anna")["secret"]
    code, o, e = run(capsys, monkeypatch, "reset-password", "anna", "--generate")
    assert code == 0 and "sfctl disable-2fa anna" in o
    code, o2, e2 = run(capsys, monkeypatch, "disable-2fa", "anna", "--yes")
    assert code == 0
    for text in (o, e, o2, e2, env.audit.read_text()):
        assert secret not in text


def test_root_read_only_command_still_hands_files_back(env, capsys, monkeypatch):
    calls = []
    monkeypatch.setattr(sfctl, "_euid", lambda: 0)
    monkeypatch.setattr(sfctl, "_fix_ownership", lambda: calls.append(1))
    assert run(capsys, monkeypatch, "--allow-root", "status")[0] == 0
    assert run(capsys, monkeypatch, "--allow-root", "doctor")[0] in (0, 1)
    assert len(calls) == 2


def test_output_strips_bidi_and_invisible_characters(env, capsys, monkeypatch):
    dashboard.audit("login", result="failed", actor="adm‮nimda​")
    code, o, _ = run(capsys, monkeypatch, "audit")
    assert code == 0 and "‮" not in o and "​" not in o and "adm?nimda?" in o
    assert sfctl.clean("Søren Ærø – ok") == "Søren Ærø – ok"


def test_usage_and_help_are_danish(env, capsys, monkeypatch):
    help_text = sfctl.build_parser().format_help()
    assert help_text.startswith("brug: sfctl") and "options:" not in help_text
    assert "Glemt adgangskode" in help_text and "Mistet telefon" in help_text
    code, _, e = run(capsys, monkeypatch, "reset-password")
    assert code == 2 and "mangler: BRUGER" in e and "required" not in e
    code, _, e = run(capsys, monkeypatch, "set-role", "anna", "boss")
    assert code == 2 and "ugyldigt valg" in e
    sub = sfctl.build_parser()._subparsers._group_actions[0].choices["resume"].format_help()
    assert sub.count("valgmuligheder:") == 1 and "Filtrér" in sub


def test_allow_root_refuses_symlinks_planted_in_state(env, capsys, monkeypatch, tmp_path):
    target = tmp_path / "elsewhere"
    target.write_text("")
    env.audit.unlink(missing_ok=True)
    env.audit.symlink_to(target)
    monkeypatch.setattr(sfctl, "_euid", lambda: 0)
    monkeypatch.setattr(sfctl, "_fix_ownership", lambda: None)
    before = env.users.read_text()
    code, _, e = run(capsys, monkeypatch, "--allow-root", "logout-all", "anna")
    assert code == 1 and "symbolske links" in e and str(env.audit) in e
    assert target.read_text() == "" and env.users.read_text() == before


def test_fix_ownership_never_follows_symlinks(env, monkeypatch):
    calls = []
    real_lstat = os.lstat

    def fake_lstat(p, *a, **kw):
        st = real_lstat(p, *a, **kw)
        return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, 0, 0, st.st_size,
                               int(st.st_atime), int(st.st_mtime), int(st.st_ctime)))

    monkeypatch.setattr(sfctl, "_euid", lambda: 0)
    monkeypatch.setattr(sfctl.os, "lstat", fake_lstat)
    monkeypatch.setattr(sfctl.os, "chown", lambda p, u, g, **kw: calls.append((str(p), u, g, kw)))
    sfctl._fix_ownership()
    assert calls and all(kw == {"follow_symlinks": False} for *_, kw in calls)
    assert {c[1] for c in calls} == {sfctl.OWNER_UID}


def test_wrapper_runs_python_isolated(tmp_path):
    body = (FILTER_DIR / "sfctl").read_text().replace("/app/sfctl.py", str(FILTER_DIR / "sfctl.py"))
    body = body.replace("exec python ", f"exec {sys.executable} ")
    wrapper = tmp_path / "sfctl"
    wrapper.write_text(body)
    res = subprocess.run(["sh", str(wrapper), "--help"], capture_output=True, text=True, timeout=60,
                         env={**os.environ, "STATE_DIR": str(tmp_path), "CONFIG_PATH": str(tmp_path / "a.yml"),
                              "PYTHONSTARTUP": "/nonexistent"},
                         cwd=tmp_path)
    assert res.returncode == 0 and "brug: sfctl" in res.stdout, res.stderr


# ---------------------------------------------------------------------------
# 2.3 (B29): mail server break-glass + two-step login by mail
# ---------------------------------------------------------------------------


@pytest.fixture
def mail_env(env, monkeypatch):
    install(monkeypatch)
    sfctl.configure()  # mailer -> this state dir
    return env


def test_help_lists_the_mail_commands():
    help_text = sfctl.build_parser().format_help()
    for cmd in ("smtp-status", "smtp-disable", "smtp-test"):
        assert cmd in help_text
    assert "både app og kode på mail" in help_text
    sub = sfctl.build_parser()._subparsers._group_actions[0].choices["disable-2fa"].format_help()
    assert "både app og kode på mail" in sub


def test_disable_2fa_clears_both_methods(mail_env, capsys, monkeypatch):
    enroll_2fa("anna")
    dashboard.twofa_mail_enable("anna", "anna@bynet.example", actor="anna")
    dashboard.mail_code_issue("anna", "anna@bynet.example", "login")
    st = dashboard.twofa_status("anna")
    assert st["totp"] and st["mail"]
    code, o, _ = run(capsys, monkeypatch, "disable-2fa", "anna", answers=["ja"])
    assert code == 0 and "både app og kode på mail" in o
    st = dashboard.twofa_status("anna")
    assert not st["enabled"] and not st["totp"] and not st["mail"] and st["recovery_left"] == 0
    assert dashboard.twofa_mail_address("anna") is None
    conn = sqlite3.connect(mail_env.db)
    assert conn.execute("SELECT COUNT(*) FROM ui_mail_codes WHERE name='anna'").fetchone()[0] == 0
    conn.close()
    assert last_audit(mail_env)["action"] == "twofa_reset"


def test_disable_2fa_mail_only_user(mail_env, capsys, monkeypatch):
    dashboard.twofa_mail_enable("anna", "anna@bynet.example", actor="anna")
    code, o, _ = run(capsys, monkeypatch, "users")
    assert "slået til (kode på mail a…@bynet.example)" in o and "anna@bynet.example" not in o
    code, o, _ = run(capsys, monkeypatch, "disable-2fa", "anna", "--yes")
    assert code == 0 and not dashboard.twofa_status("anna")["enabled"]


def test_disable_2fa_queues_a_security_notice_when_mail_works(mail_env, capsys, monkeypatch):
    configure_smtp(mailer)
    dashboard.twofa_mail_enable("anna", "anna@bynet.example", actor="anna")
    code, _, _ = run(capsys, monkeypatch, "disable-2fa", "anna", "--yes")
    assert code == 0
    assert FakeSMTP.sent == []  # sfctl only queues; the filter's own worker sends
    msgs = flush()
    assert [m["To"] for m in msgs] == ["anna@bynet.example"] and "nulstillet" in msgs[0]["Subject"]


def test_smtp_status_and_test_and_disable(mail_env, capsys, monkeypatch):
    code, o, _ = run(capsys, monkeypatch, "smtp-status")
    assert code == 0 and "ikke sat op" in o
    assert run(capsys, monkeypatch, "smtp-disable")[1].startswith("Der er ingen mailserver")
    configure_smtp(mailer)
    mailer.save_routes({"alert": {"on": True, "to": "ole@bynet.example"}})
    code, o, _ = run(capsys, monkeypatch, "smtp-status")
    assert code == 0 and "slået til" in o and "smtp.gigahost.dk:587 (STARTTLS" in o
    assert "gemt adgangskode" in o and "smtp-hemmelig" not in o
    assert "Alarmer" in o and "til (1 modtager)" in o
    code, o, _ = run(capsys, monkeypatch, "smtp-test", "ole@bynet.example")
    assert code == 0 and "Testmailen er sendt til o…@bynet.example" in o
    assert FakeSMTP.sent[-1][2]["Subject"] == "Testmail fra Spamfilter"
    FakeSMTP.fail_login = __import__("smtplib").SMTPAuthenticationError(535, b"nope")
    code, _, e = run(capsys, monkeypatch, "smtp-test", "ole@bynet.example")
    assert code == 1 and "afviste brugernavn eller adgangskode" in e
    assert run(capsys, monkeypatch, "smtp-test", "ikke-en-adresse")[0] == 2
    dashboard.twofa_mail_enable("anna", "anna@bynet.example", actor="anna")
    code, o, _ = run(capsys, monkeypatch, "smtp-disable")
    assert code == 0 and "slået fra" in o and "anna" in o and "genoprettelseskode" in o
    assert mailer.get_settings()["enabled"] is False and mailer.get_settings()["host"] == "smtp.gigahost.dk"
    assert last_audit(mail_env)["action"] == "smtp_disable"
    assert "allerede slået fra" in run(capsys, monkeypatch, "smtp-disable")[1]
    assert run(capsys, monkeypatch, "smtp-test", "ole@bynet.example")[0] == 1


def test_doctor_reports_smtp(mail_env, capsys, monkeypatch):
    (mail_env.state / "heartbeat").write_text(f"{int(__import__('time').time())} boot\n")
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert "mailserver: ikke sat op" in o
    assert "administratorer uden to-trins-login: admin (hverken app eller kode på mail)" in o
    dashboard.twofa_mail_enable("anna", "anna@bynet.example", actor="anna")
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert "har kode på mail, men der er ingen mailserver: anna" in o
    configure_smtp(mailer)
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert "er ikke testet endnu" in o and "sfctl smtp-test" in o
    mailer.send_test("ole@bynet.example")
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert "mailserver smtp.gigahost.dk:587 virker" in o
    FakeSMTP.fail_connect = ConnectionRefusedError("down")
    mailer.send_test("ole@bynet.example")
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert "seneste mail fejlede" in o
    (mail_env.state / "smtp.password").chmod(0o644)
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert "smtp.password" in o and "chmod 0600" in o
    mailer.set_enabled(False)
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert "mailserver: slået fra – brugere med kode på mail" in o
    # admins with ANY method count as protected
    dashboard.twofa_mail_enable("admin", "admin@bynet.example", actor="admin")
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert "alle administratorer har to-trins-login" in o


# --------------------------------------------------------------------- 2.3 login scope (owner request)


def test_login_scope_set_show_and_audit(env, capsys, monkeypatch):
    code, o, _ = run(capsys, monkeypatch, "users")
    assert code == 0 and "login:       overalt" in o
    code, o, _ = run(capsys, monkeypatch, "login-scope", "anna", "lokalt")
    assert code == 0 and "kun logge ind fra hjemmenetværket" in o
    assert dashboard.login_scope("anna") == "local"
    rec = last_audit(env)
    assert rec["action"] == "user_login_scope" and rec["actor"] == "cli" and rec["detail"] == "anna local (sfctl)"
    code, o, _ = run(capsys, monkeypatch, "users")
    anna_block = o.split("\nanna")[1]
    assert "login:       kun lokalt (hjemmenetværket)" in anna_block
    code, o, _ = run(capsys, monkeypatch, "login-scope", "anna", "lokalt")
    assert code == 0 and "allerede" in o
    code, o, _ = run(capsys, monkeypatch, "login-scope", "anna", "overalt")
    assert code == 0 and dashboard.login_scope("anna") == "everywhere"


def test_login_scope_warns_when_every_admin_is_local(env, capsys, monkeypatch):
    code, o, _ = run(capsys, monkeypatch, "login-scope", "admin", "lokalt")
    assert code == 0 and "alle administratorer må nu kun logge ind lokalt" in o
    code, o, _ = run(capsys, monkeypatch, "users")
    assert "alle administratorer må kun logge ind lokalt" in o


def test_login_scope_usage_and_unknown_user(env, capsys, monkeypatch):
    assert run(capsys, monkeypatch, "login-scope", "anna", "måske")[0] == 2
    assert run(capsys, monkeypatch, "login-scope", "anna")[0] == 2
    code, _o, e = run(capsys, monkeypatch, "login-scope", "findes-ikke", "lokalt")
    assert code == 1 and "Ukendt bruger" in e
    assert "login-scope" in sfctl.build_parser().format_help()
    assert "sfctl login-scope NAVN overalt" in sfctl.EPILOG


# ----- Bayes: byg op på ny / gendan / status ----------------------------------

_PLAN = {"ok": True, "code": "plan", "pool_now": "hjemmeserver", "pool_new": "hjemmeserver-r2", "ratio": 2.0,
         "spam_sources": [{"account": "bynet", "folder": "INBOX.Spamfilter", "label": "INBOX.Spamfilter",
                           "kind": "filter_junk", "messages": 120, "planned": 120},
                          {"account": "bynet", "folder": None, "label": "x", "kind": "learn_list",
                           "messages": 7, "planned": 7}],
         "ham_sources": [{"account": "bynet", "folder": "INBOX.Arkiv", "label": "INBOX.Arkiv",
                          "messages": 4000, "planned": 254},
                         {"account": "molt", "folder": "Kunder", "label": "Kunder", "messages": 9, "planned": 0}],
         "expected_spam": 127, "expected_ham": 254, "warnings": ["Der er kun ca. 127 spam at lære."],
         "running": None, "text": "Ny Bayes-pulje: hjemmeserver-r2."}


@pytest.fixture
def fake_rebuild(monkeypatch):
    import services

    calls = []

    def plan(actor, ratio=2.0, **kw):
        calls.append(("plan", actor, ratio))
        return dict(_PLAN, ratio=ratio)

    def start(actor, confirm=True, ratio=2.0, save_config=None, **kw):
        calls.append(("start", actor, confirm, ratio, save_config))
        return {"ok": True, "code": "started", "text": "Bayes bygges op på ny i puljen hjemmeserver-r2."}

    status = {"ok": True, "code": "running", "rebuild_id": 1, "pool": "hjemmeserver-r2", "pool_old": "hjemmeserver",
              "pool_new": "hjemmeserver-r2", "created_at": 1_790_000_000, "expected_spam": 127, "expected_ham": 254,
              "learned_spam": 50, "learned_ham": 20, "jobs": {"done": 1, "queued": 2}, "can_restore": True,
              "text": "Genopbygning i gang (33 %)."}

    def restore(actor, confirm=True, save_config=None, **kw):
        calls.append(("restore", actor, confirm, save_config))
        return {"ok": True, "code": "restored", "text": "Den tidligere Bayes (hjemmeserver) er gendannet."}

    monkeypatch.setattr(services, "bayes_rebuild_plan", plan)
    monkeypatch.setattr(services, "bayes_rebuild_start", start)
    monkeypatch.setattr(services, "bayes_rebuild_status", lambda **kw: dict(status))
    monkeypatch.setattr(services, "bayes_restore_previous", restore)
    monkeypatch.setattr(services, "bayes_stats", lambda **kw: {
        "ok": True, "pool": "hjemmeserver-r2", "spam_learned": 50, "ham_learned": 20, "min_learns": 200,
        "active": False, "counts_source": "pool"})
    return calls, status


def test_bayes_rebuild_dry_run_shows_the_plan_and_changes_nothing(env, capsys, monkeypatch, fake_rebuild):
    calls, _ = fake_rebuild
    code, o, _e = run(capsys, monkeypatch, "bayes-rebuild", "--dry-run")
    assert code == 0
    assert [c[0] for c in calls] == ["plan"] and calls[0][1] == "cli"
    assert "hjemmeserver  →  ny pulje: hjemmeserver-r2" in o
    assert "INBOX.Spamfilter" in o and "lærer 120" in o and "enkeltmails lært som spam" in o
    assert "INBOX.Arkiv" in o and "lærer 254" in o and "Kunder" not in o  # planned 0 is not listed
    assert "Bruges aldrig som legitime: Indbakke, Sendt" in o and "Bemærk: Der er kun" in o
    assert "Prøvekørsel – intet er ændret." in o


def test_bayes_rebuild_asks_before_it_starts(env, capsys, monkeypatch, fake_rebuild):
    calls, _ = fake_rebuild
    code, o, e = run(capsys, monkeypatch, "bayes-rebuild", answers=["nej"])
    assert code == 1 and "Afbrudt – intet er ændret" in e
    assert [c[0] for c in calls] == ["plan"]
    code, o, _e = run(capsys, monkeypatch, "bayes-rebuild", "--ratio", "1.5", answers=["ja"])
    assert code == 0 and "gemmes urørt og kan gendannes med sfctl bayes-restore" in o
    start = [c for c in calls if c[0] == "start"][0]
    assert start[1:4] == ("cli", True, 1.5) and start[4] is dashboard.save_config
    assert "Følg med: sfctl bayes-status" in o


def test_bayes_rebuild_refuses_while_running(env, capsys, monkeypatch, fake_rebuild):
    import services

    monkeypatch.setattr(services, "bayes_rebuild_plan", lambda actor, ratio=2.0, **kw: dict(_PLAN, running=3))
    code, _o, e = run(capsys, monkeypatch, "bayes-rebuild", "--yes")
    assert code == 1 and "allerede i gang" in e


def test_bayes_status_and_restore(env, capsys, monkeypatch, fake_rebuild):
    calls, status = fake_rebuild
    code, o, _e = run(capsys, monkeypatch, "bayes-status")
    assert code == 0 and "Aktiv Bayes-pulje: hjemmeserver-r2" in o
    assert "50 spam · 20 legitime (fra genopbygningens optælling)" in o and "aktiv:         nej" in o
    assert "hjemmeserver → hjemmeserver-r2, i gang" in o and "50 af ca. 127 spam" in o
    code, o, _e = run(capsys, monkeypatch, "bayes-restore", "--yes")
    assert code == 0 and "er gendannet" in o
    assert calls[-1][:3] == ("restore", "cli", True) and calls[-1][3] is dashboard.save_config
    status["can_restore"] = False
    code, _o, e = run(capsys, monkeypatch, "bayes-restore", "--yes")
    assert code == 1 and "ingen tidligere Bayes at gendanne" in e


def test_bayes_rebuild_with_real_services_and_no_mailserver(env, capsys, monkeypatch):
    # No network in tests: every mailbox is unreachable, so there is nothing to learn.
    import requests
    import services

    monkeypatch.setattr(engine, "connect", lambda *a, **k: (_ for _ in ()).throw(OSError("offline")))
    monkeypatch.setattr(services.requests, "get",
                        lambda *a, **k: (_ for _ in ()).throw(requests.ConnectionError("offline")))
    code, o, e = run(capsys, monkeypatch, "bayes-rebuild", "--yes")
    assert code == 1 and "ingen spam at lære" in e
    assert "kunne ikke læses" in o
    assert yaml.safe_load(env.config.read_text())["defaults"]["bayes_user"] == "hjemmeserver"
    code, o, _e = run(capsys, monkeypatch, "bayes-status")
    assert code == 0 and "Aktiv Bayes-pulje: hjemmeserver" in o and "ikke bygget op på ny" in o
    assert "rspamd svarer ikke" in o


def test_help_lists_the_bayes_commands():
    help_text = sfctl.build_parser().format_help()
    for cmd in ("bayes-rebuild", "bayes-restore", "bayes-status"):
        assert cmd in help_text
    assert "sfctl bayes-rebuild --dry-run" in sfctl.EPILOG
