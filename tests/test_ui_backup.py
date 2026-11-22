"""2.6 (B3): Drift -> "Krypteret backup" card (ui_backup.py): last run, last
success, no /backup mount, the 48 h alarm, the key that was never shown
and the off-site copy. Admin only (the /system page); never a secret."""

from __future__ import annotations

import json
import time

import pytest

from test_ui_admin import admin, env, sofie, text  # noqa: F401 - fixtures

import backup  # noqa: E402


@pytest.fixture
def benv(env, tmp_path, monkeypatch):  # noqa: F811
    dest = tmp_path / "backup-dest"
    dest.mkdir()
    monkeypatch.setattr(backup, "BACKUP_DIR", dest)
    monkeypatch.setattr(backup, "REQUIRE_MOUNT", False)
    backup.configure(env.state)
    env.dest = dest
    return env


def test_card_without_mount(benv, admin, monkeypatch):  # noqa: F811
    monkeypatch.setattr(backup, "REQUIRE_MOUNT", True)
    html = text(admin.get("/system"))
    assert "Krypteret backup" in html and "Ingen backup-placering" in html
    assert "/mnt/user/backup/spamfilter" in html


def test_card_after_success_with_offsite_failure(benv, admin):  # noqa: F811
    t = int(time.time())
    name = f"spamfilter-{backup._stamp(t)}.sfbak"
    (benv.dest / name).write_bytes(b"SFBACKUP")
    backup.write_status({"ts": t, "ok": True, "archive": name, "size": 123456, "since": t - 86400,
                         "last_ok_ts": t, "last_ok_archive": name, "warnings": []})
    key = backup.load_key(create=True)
    (benv.state / "offsite-status.json").write_text(json.dumps(
        {"ok": False, "ts": t, "remote": "offsite:Backup/Spamfilter", "error": "rclone copy fejlede (exit 5)"}))
    html = text(admin.get("/system"))
    assert "Seneste krypterede backup lykkedes" in html and name in html
    assert "1 i " in html and "14 dage + 8 uger" in html
    assert "fejlede: rclone copy fejlede (exit 5)" in html
    assert "aldrig vist" in html and "sfctl backup-key show" in html
    assert backup.format_key(key) not in html


def test_alarm_after_48h(benv, admin):  # noqa: F811
    t = int(time.time())
    backup.write_status({"ts": t, "ok": False, "error": "For lidt fri plads på /backup", "since": t - 72 * 3600,
                         "last_ok_ts": None})
    html = text(admin.get("/system"))
    assert "Backup mangler" in html and "For lidt fri plads" in html


def test_bruger_never_sees_drift(benv, sofie):  # noqa: F811
    assert sofie.get("/system").status_code in (302, 403, 404)
