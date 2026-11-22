"""2.6 (B3): sfctl backup-now / backup-list / backup-verify / backup-restore /
backup-key and the doctor lines (real sfctl.main against the temp state of
test_sfctl's env fixture)."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from test_sfctl import env, last_audit, run  # noqa: F401 - env is a fixture

import backup  # noqa: E402


@pytest.fixture
def benv(env, tmp_path, monkeypatch):  # noqa: F811
    dest = tmp_path / "backup"
    dest.mkdir()
    monkeypatch.setattr(backup, "BACKUP_DIR", dest)
    monkeypatch.setattr(backup, "REQUIRE_MOUNT", False)
    monkeypatch.setattr(backup, "APPDATA", tmp_path / "no-appdata")

    def fake_rdb(path):
        Path(path).write_bytes(b"REDIS0011fake")
        return True, ""

    monkeypatch.setattr(backup, "redis_dump", fake_rdb)
    env.dest = dest
    return env


def test_backup_key_show_once_then_refuse(benv, capsys, monkeypatch):
    code, o, _ = run(capsys, monkeypatch, "backup-key", "status")
    assert code == 0 and "ingen endnu" in o
    code, o, _ = run(capsys, monkeypatch, "backup-key", "show")
    assert code == 0 and "VIGTIGT" in o and "kode-manager" in o
    key = (benv.state / "backup.key").read_text().strip()
    assert key in o
    assert last_audit(benv)["action"] == "backup_key_show" and key not in json.dumps(last_audit(benv))
    code, o, e = run(capsys, monkeypatch, "backup-key", "show")
    assert code == 1 and key not in o + e and "allerede vist" in e
    code, o, _ = run(capsys, monkeypatch, "backup-key", "show", "--again", answers=["nej"])
    assert code == 1 and key not in o
    code, o, _ = run(capsys, monkeypatch, "backup-key", "show", "--again", "--yes")
    assert code == 0 and key in o
    code, o, _ = run(capsys, monkeypatch, "backup-key", "status")
    assert "nøgle-id" in o and key not in o


def test_backup_now_list_verify_restore(benv, capsys, monkeypatch, tmp_path):
    code, o, e = run(capsys, monkeypatch, "backup-now")
    assert code == 0, o + e
    assert "Færdig" in o and last_audit(benv)["action"] == "backup_now"
    name = next(benv.dest.glob("*.sfbak")).name
    code, o, _ = run(capsys, monkeypatch, "backup-list")
    assert code == 0 and name in o and "anden nøgle" not in o
    code, o, _ = run(capsys, monkeypatch, "backup-verify", name)
    assert code == 0 and "OK:" in o and "Bayes-data (Redis): med" in o
    key = (benv.state / "backup.key").read_text().strip()
    code, o, _ = run(capsys, monkeypatch, "backup-verify", name, "--ask-key", passwords=[key])
    assert code == 0 and key not in o
    code, o, e = run(capsys, monkeypatch, "backup-verify", name, "--ask-key",
                     passwords=[backup.format_key(b"\x01" * 32)])
    assert code == 1 and "Forkert nøgle" in e
    # Restore: only into a new directory, never the live state.
    code, o, e = run(capsys, monkeypatch, "backup-restore", name, "--to", str(benv.state / "x"))
    assert code == 1 and "kørende installation" in e
    link = tmp_path / "ser-uskyldig-ud"
    link.symlink_to(benv.state)
    code, o, e = run(capsys, monkeypatch, "backup-restore", name, "--to", str(link / "x"))
    assert code == 1 and "kørende installation" in e and not (benv.state / "x").exists()
    out = tmp_path / "gendan"
    code, o, e = run(capsys, monkeypatch, "backup-restore", name, "--to", str(out))
    assert code == 0, e
    assert (out / "state" / "spamfilter.db").is_file() and (out / "config" / "accounts.yml").is_file()
    assert "IKKE ændret" in o and last_audit(benv)["action"] == "backup_restore"


def test_backup_restore_help_suggests_tmp_not_the_backup_share():
    import sfctl

    p = sfctl.build_parser()
    sub = next(a for a in p._actions if a.__class__.__name__ == "_SubParsersAction")
    to = next(a for a in sub.choices["backup-restore"]._actions if "--to" in a.option_strings)
    assert "/tmp/" in to.help and "fx /backup/" not in to.help


def test_backup_now_if_older_skips_a_fresh_backup(benv, capsys, monkeypatch):
    assert run(capsys, monkeypatch, "backup-now")[0] == 0
    code, o, _ = run(capsys, monkeypatch, "backup-now", "--if-older", "20")
    assert code == 0 and "ingen ny nu" in o
    assert len(list(benv.dest.glob("*.sfbak"))) == 1


def test_backup_now_without_mount_fails_clearly(benv, capsys, monkeypatch):
    monkeypatch.setattr(backup, "REQUIRE_MOUNT", True)
    monkeypatch.setattr(backup, "backup_mounted", lambda path=None: False)
    code, o, e = run(capsys, monkeypatch, "backup-now")
    assert code == 1 and "ikke monteret" in e
    assert list(benv.dest.iterdir()) == []


def test_doctor_reports_backup_and_offsite(benv, capsys, monkeypatch):
    (benv.state / "heartbeat").write_text(f"{int(time.time())} boot\n")
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert "krypteret backup: ingen endnu" in o
    assert run(capsys, monkeypatch, "backup-now")[0] == 0
    (benv.state / "offsite-status.json").write_text(json.dumps(
        {"ok": False, "ts": int(time.time()), "remote": "offsite:Backup/Spamfilter", "error": "rclone exit 7"}))
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert "krypteret backup for" in o
    assert "backupnøglen er aldrig vist" in o
    assert "[FEJL] kopi ud af huset fejlede: rclone exit 7" in o


def test_doctor_alerts_after_48h(benv, capsys, monkeypatch):
    backup.configure(benv.state)
    backup.write_status({"ts": int(time.time()), "ok": False, "error": "disk fuld",
                         "since": int(time.time()) - 72 * 3600, "last_ok_ts": None})
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert code == 1 and "[FEJL] krypteret backup fejlede: disk fuld" in o and "48 timer" in o
