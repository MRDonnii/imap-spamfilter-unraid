"""2.6 (B3): the encrypted nightly backup (filter/backup.py).

Round trip (encrypt -> verify -> restore), tamper detection (header, chunk,
truncation, trailing data, wrong key), retention (14 daily + 8 weekly),
the missing /backup mount, the schedule and the 48 h alert. Redis is
replaced by a fake `redis-cli --rdb` (backup.redis_dump)."""

from __future__ import annotations

import json
import os
import sqlite3
import struct
import sys
import time
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "filter"))
import backup  # noqa: E402

RDB = b"REDIS0011" + os.urandom(3000) + b"\xff" + b"\x00" * 8


@pytest.fixture
def bk(tmp_path, monkeypatch):
    app = tmp_path / "appdata"
    state, config, dest = app / "state", app / "config", tmp_path / "backup"
    for d in (state / "imap-secrets", config, app / "rspamd" / "local.d", app / "redis-config", dest):
        d.mkdir(parents=True)
    db = sqlite3.connect(state / "spamfilter.db")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY, subject TEXT)")
    db.executemany("INSERT INTO messages(subject) VALUES(?)", [(f"emne {i}" * 20,) for i in range(3000)])
    db.commit()
    db.close()
    for name, data in (("dashboard_users", "admin:hash:admin:0\n"), ("dashboard_secret", "s" * 64),
                       ("contacts.key", "k" * 32), ("vapid_private.pem", "-----BEGIN-----\n"),
                       ("redis.password", "pw\n"), ("admin-audit.jsonl", '{"a":1}\n'),
                       ("heartbeat", "1 boot\n"), ("spamfilter.db-wal-x.tmp", "temp")):
        (state / name).write_text(data)
        os.chmod(state / name, 0o600)
    (state / "imap-secrets" / "bynet").write_text("imap-pw\n")
    (state / ".hidden-temp").write_text("x")
    (config / "accounts.yml").write_text("accounts: []\n")
    (app / "rspamd" / "local.d" / "options.inc").write_text("dns {}\n")
    (app / "unbound.conf").write_text("server:\n")
    unreadable = app / "redis-config" / "redis.conf"
    unreadable.write_text("requirepass x\n")
    os.chmod(unreadable, 0)
    backup.configure(state, config / "accounts.yml", appdata=app, backup_dir=dest, version="2.6.0-test")
    monkeypatch.setattr(backup, "REQUIRE_MOUNT", False)

    def fake_rdb(path):
        Path(path).write_bytes(RDB)
        return True, ""

    monkeypatch.setattr(backup, "redis_dump", fake_rdb)

    class B:
        pass
    b = B()
    b.app, b.state, b.config, b.dest = app, state, config, dest
    yield b
    os.chmod(unreadable, 0o600)


def _only(dest: Path) -> Path:
    files = sorted(dest.glob("*.sfbak"))
    assert len(files) == 1, files
    return files[0]


# ---------------------------------------------------------------- round trip

def test_round_trip_encrypt_verify_restore(bk, tmp_path):
    st = backup.run_backup(reason="test")
    assert st["ok"] is True, st
    arc = _only(bk.dest)
    assert arc.name == st["archive"] and oct(arc.stat().st_mode & 0o777) == "0o600"
    raw = arc.read_bytes()
    # Encrypted: no plaintext of the secrets or the DB in the archive.
    for needle in (b"imap-pw", b"admin:hash", b"emne 1", b"SQLite format 3", b"REDIS0011", b"accounts:"):
        assert needle not in raw
    key = (bk.state / "backup.key").read_text()
    assert key.startswith("SFBK1-") and oct((bk.state / "backup.key").stat().st_mode & 0o777) == "0o600"
    assert key.strip().encode() not in raw

    v = backup.verify(arc)
    assert v["ok"] and v["redis"] and v["version"] == "2.6.0-test"
    assert {"name": "appdata/redis-config/redis.conf", "why": "ingen adgang"} in v["skipped"] or os.geteuid() == 0

    out = tmp_path / "restored"
    r = backup.restore(arc, out)
    assert r["files"] == v["files"]
    names = {p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()}
    assert {"state/spamfilter.db", "state/dashboard_users", "state/contacts.key", "state/vapid_private.pem",
            "state/imap-secrets/bynet", "state/admin-audit.jsonl", "config/accounts.yml",
            "appdata/rspamd/local.d/options.inc", "appdata/unbound.conf", "redis/dump.rdb"} <= names
    # Never: the key, transient files, temp files.
    assert not {"state/backup.key", "state/heartbeat", "state/.hidden-temp", "state/spamfilter.db-wal-x.tmp"} & names
    assert not any(n.endswith(("-wal", "-shm")) for n in names)
    assert (out / "redis" / "dump.rdb").read_bytes() == RDB
    assert (out / "state" / "imap-secrets" / "bynet").read_text() == "imap-pw\n"
    db = sqlite3.connect(out / "state" / "spamfilter.db")
    assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert db.execute("SELECT count(*) FROM messages").fetchone()[0] == 3000
    db.close()
    for p in out.rglob("*"):
        assert (p.stat().st_mode & 0o777) == (0o700 if p.is_dir() else 0o600), p


def test_large_file_spans_many_chunks(bk, monkeypatch, tmp_path):
    monkeypatch.setattr(backup, "CHUNK", 4096)
    (bk.state / "big.bin").write_bytes(os.urandom(4096 * 5 + 17))
    assert backup.run_backup()["ok"]
    out = tmp_path / "r"
    backup.restore(_only(bk.dest), out)
    assert (out / "state" / "big.bin").read_bytes() == (bk.state / "big.bin").read_bytes()


def test_exact_chunk_multiple_round_trips(tmp_path):
    key = os.urandom(32)
    f = tmp_path / "f"
    f.write_bytes(b"a" * backup.CHUNK)
    e = backup.Entry(name="state/f", path=f)
    backup._hash(e)
    man = {"format": 1, "created": 5, "files": [{"name": e.name, "size": e.size, "sha256": e.sha256}]}
    # Manifest prefix shifts the stream; test also a stream that ends exactly on a chunk.
    out = tmp_path / "spamfilter-20260101T000000Z.sfbak"
    backup.encrypt_archive(out, key, [e], man, created=5)
    assert backup.verify(out, key)["files"] == 1


def test_wrong_key_and_key_from_password_manager(bk, tmp_path):
    assert backup.run_backup()["ok"]
    arc = _only(bk.dest)
    with pytest.raises(backup.BackupError, match="Forkert nøgle"):
        backup.verify(arc, os.urandom(32))
    typed = (bk.state / "backup.key").read_text().strip().lower().replace("-", " ")
    assert backup.verify(arc, backup.parse_key(typed))["ok"]
    with pytest.raises(backup.BackupError, match="format"):
        backup.parse_key("SFBK1-not-a-key!")


# ---------------------------------------------------------------- tampering

def _archive(bk) -> tuple[Path, bytes]:
    assert backup.run_backup()["ok"]
    arc = _only(bk.dest)
    return arc, arc.read_bytes()


def test_tampered_header_is_detected(bk):
    arc, raw = _archive(bk)
    hl = struct.unpack(">I", raw[9:13])[0]
    header = json.loads(raw[13:13 + hl])
    header["created"] = header["created"] + 1
    hb = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    arc.write_bytes(raw[:9] + struct.pack(">I", len(hb)) + hb + raw[13 + hl:])
    with pytest.raises(backup.BackupError, match="header er ændret"):
        backup.verify(arc)


def test_flipped_bit_in_a_chunk_is_detected(bk):
    arc, raw = _archive(bk)
    b = bytearray(raw)
    b[len(b) // 2] ^= 0x01
    arc.write_bytes(bytes(b))
    with pytest.raises(backup.BackupError, match="ændret eller beskadiget"):
        backup.verify(arc)


def test_truncation_and_trailing_data_are_detected(bk, monkeypatch):
    monkeypatch.setattr(backup, "CHUNK", 8192)
    arc, raw = _archive(bk)
    # Cut exactly at a chunk boundary: the new last chunk lacks the last flag.
    hl = struct.unpack(">I", raw[9:13])[0]
    off = 13 + hl + backup.WRAPPED_LEN
    first_len = struct.unpack(">I", raw[off:off + 4])[0]
    arc.write_bytes(raw[:off + 4 + first_len])
    with pytest.raises(backup.BackupError):
        backup.verify(arc)
    arc.write_bytes(raw[:-10])
    with pytest.raises(backup.BackupError):
        backup.verify(arc)
    arc.write_bytes(raw + raw[off:off + 4 + first_len])
    with pytest.raises(backup.BackupError):
        backup.verify(arc)


def test_not_an_archive(bk, tmp_path):
    p = tmp_path / "x.sfbak"
    p.write_bytes(b"PK\x03\x04 not ours")
    with pytest.raises(backup.BackupError, match="ikke en spamfilter-backup"):
        backup.verify(p)


def test_manifest_with_path_traversal_is_refused(tmp_path):
    key = os.urandom(32)
    f = tmp_path / "f"
    f.write_bytes(b"evil")
    e = backup.Entry(name="state/f", path=f)
    backup._hash(e)
    man = {"format": 1, "created": 7, "files": [{"name": "state/../../etc/passwd", "size": 4, "sha256": e.sha256}]}
    out = tmp_path / "spamfilter-20260101T000000Z.sfbak"
    backup.encrypt_archive(out, key, [e], man, created=7)
    dest = tmp_path / "restore"
    with pytest.raises(backup.BackupError, match="ugyldigt filnavn"):
        backup.restore(out, dest, key)
    assert not dest.exists()


# ---------------------------------------------------------------- restore safety

def test_restore_never_overwrites_live_state_or_a_full_dir(bk, tmp_path):
    arc, _raw = _archive(bk)
    for target in (bk.state, bk.state / "sub", bk.app, bk.config):
        with pytest.raises(backup.BackupError, match="kørende installation"):
            backup.restore(arc, target)
    full = tmp_path / "full"
    full.mkdir()
    (full / "x").write_text("keep")
    with pytest.raises(backup.BackupError, match="ikke tom"):
        backup.restore(arc, full)
    assert (full / "x").read_text() == "keep"


def test_restore_resolves_symlinks_and_dotdot_before_the_live_check(bk, tmp_path):
    arc, _raw = _archive(bk)
    link = tmp_path / "harmless-looking"
    link.symlink_to(bk.state)
    sneaky = tmp_path / "other" / ".." / "appdata" / "state" / "gendan"
    for target in (link, link / "gendan", sneaky, tmp_path, Path("/")):
        with pytest.raises(backup.BackupError, match="kørende installation"):
            backup.restore(arc, target)
    assert not (bk.state / "gendan").exists() and not (bk.state / "state").exists()
    # The live dirs reached through a symlink are compared by their real path too.
    live_link = tmp_path / "live-link"
    live_link.symlink_to(bk.app)
    backup.configure(live_link / "state", live_link / "config" / "accounts.yml", appdata=live_link)
    with pytest.raises(backup.BackupError, match="kørende installation"):
        backup.restore(arc, bk.state / "x")
    assert not (bk.state / "x").exists()
    # --to as a symlink to an empty dir elsewhere is refused (restore into a real, new dir).
    empty = tmp_path / "empty"
    empty.mkdir()
    (tmp_path / "to-empty").symlink_to(empty)
    with pytest.raises(backup.BackupError, match="ikke en mappe"):
        backup.restore(arc, tmp_path / "to-empty")
    assert list(empty.iterdir()) == []
    r = backup.restore(arc, tmp_path / "gendan-ok")
    assert r["ok"] and r["to"] == str((tmp_path / "gendan-ok").resolve())


def test_corrupt_archive_restore_removes_partial_output(bk, tmp_path):
    arc, raw = _archive(bk)
    b = bytearray(raw)
    b[-40] ^= 0xFF
    arc.write_bytes(bytes(b))
    dest = tmp_path / "r"
    with pytest.raises(backup.BackupError):
        backup.restore(arc, dest)
    assert not dest.exists()


# ---------------------------------------------------------------- missing mount / failures

def test_missing_mount_writes_nothing(bk, monkeypatch):
    monkeypatch.setattr(backup, "REQUIRE_MOUNT", True)
    monkeypatch.setattr(backup, "backup_mounted", lambda path=None: False)
    before = sorted(p.name for p in bk.state.iterdir())
    st = backup.run_backup()
    assert st["ok"] is False and st["skipped"] == "no_mount" and "ikke monteret" in st["error"]
    assert list(bk.dest.iterdir()) == []
    after = sorted(p.name for p in bk.state.iterdir())
    assert set(after) - set(before) == {backup.STATUS_FILE}  # no key, no staging, no archive
    s = backup.summary()
    assert s["state"] == "no_mount" and s["tone"] == "warn" and not s["alert"]


def test_mountinfo_check(tmp_path, monkeypatch):
    monkeypatch.setattr(backup, "REQUIRE_MOUNT", True)
    assert backup.backup_mounted(tmp_path / "nowhere") is False
    assert backup.backup_mounted(Path("/proc")) is True


def test_redis_failure_keeps_archive_but_is_not_a_success(bk, monkeypatch):
    monkeypatch.setattr(backup, "redis_dump", lambda p: (False, "Redis svarede ikke i tide"))
    st = backup.run_backup()
    assert st["ok"] is False and st["archive"] and "Bayes" in st["error"]
    assert st["last_ok_ts"] is None
    v = backup.verify(_only(bk.dest))
    assert v["ok"] and not v["redis"]


def test_secrets_never_in_status_or_log(bk, caplog):
    caplog.set_level("DEBUG")
    st = backup.run_backup()
    key = (bk.state / "backup.key").read_text().strip()
    blob = json.dumps(st) + (bk.state / backup.STATUS_FILE).read_text() + caplog.text
    for secret in (key, "imap-pw", "admin:hash", "pw\n"):
        assert secret not in blob
    assert oct((bk.state / backup.STATUS_FILE).stat().st_mode & 0o777) == "0o600"


def test_lock_prevents_parallel_runs(bk):
    with backup._lock():
        st = backup.run_backup()
    assert st["ok"] is False and "kører allerede" in st["error"]


def test_stale_work_dir_is_cleaned(bk):
    stale = bk.state / (backup.WORK_PREFIX + "old")
    stale.mkdir()
    (stale / "secret").write_text("x")
    assert backup.run_backup()["ok"]
    assert not stale.exists()
    assert not [p for p in bk.state.iterdir() if p.name.startswith(backup.WORK_PREFIX)]


# ---------------------------------------------------------------- retention

def _ts(y, mo, d, h=3):
    return int(datetime(y, mo, d, h, 0, tzinfo=backup._TZ).timestamp())


def test_retention_keeps_14_daily_and_8_weekly(tmp_path):
    archives = []
    start = _ts(2026, 6, 1)
    for i in range(120):            # 120 days, two runs on every 10th day
        for extra in ((0, 3600) if i % 10 == 0 else (0,)):
            ts = start + i * 86400 + extra
            archives.append({"name": f"spamfilter-{backup._stamp(ts)}.sfbak", "ts": ts})
    keep = backup.retention_keep(archives)
    newest = sorted(archives, key=lambda a: a["ts"], reverse=True)
    per_day: dict = {}
    per_week: dict = {}
    for a in newest:
        per_day.setdefault(backup._local(a["ts"]).date(), a["name"])
        per_week.setdefault(backup._local(a["ts"]).isocalendar()[:2], a["name"])
    want = set(list(per_day.values())[:14]) | set(list(per_week.values())[:8])
    assert keep == want
    assert len({backup._local(a["ts"]).isocalendar()[:2] for a in archives if a["name"] in keep}) == 8
    assert 14 <= len(keep) <= 22


def test_prune_deletes_only_our_old_archives(bk):
    now = time.time()
    names = []
    for i in range(40):
        ts = now - i * 86400
        p = bk.dest / f"spamfilter-{backup._stamp(ts)}.sfbak"
        p.write_bytes(b"x")
        names.append(p.name)
    other = bk.dest / "notes.txt"
    other.write_text("keep me")
    foreign = bk.dest / "spamfilter-2020.tar.gz"
    foreign.write_text("keep")
    old_part = bk.dest / f"spamfilter-{backup._stamp(now - 7200)}.sfbak.part"
    old_part.write_bytes(b"x")
    os.utime(old_part, (now - 7200, now - 7200))
    gone = backup.prune(bk.dest, now=now)
    left = {p.name for p in bk.dest.iterdir()}
    assert other.name in left and foreign.name in left and old_part.name not in left
    kept = [n for n in names if n in left]
    assert 14 <= len(kept) <= 22 and len(gone) == 40 - len(kept)
    assert names[0] in left  # newest always


def test_successful_run_prunes(bk):
    now = time.time()
    for i in range(1, 60):
        (bk.dest / f"spamfilter-{backup._stamp(now - i * 86400)}.sfbak").write_bytes(b"x")
    st = backup.run_backup(now=now)
    assert st["ok"] and st["pruned"]
    assert st["archive"] in {p.name for p in bk.dest.iterdir()}
    assert len(list(bk.dest.glob("*.sfbak"))) <= 22


def test_failed_run_never_prunes(bk, monkeypatch):
    now = time.time()
    for i in range(1, 60):
        (bk.dest / f"spamfilter-{backup._stamp(now - i * 86400)}.sfbak").write_bytes(b"x")
    monkeypatch.setattr(backup, "encrypt_archive", lambda *a, **k: (_ for _ in ()).throw(OSError("disk")))
    st = backup.run_backup(now=now)
    assert st["ok"] is False
    assert len(list(bk.dest.glob("*.sfbak"))) == 59


# ---------------------------------------------------------------- schedule + alert

def test_due_nightly_with_catch_up_and_retries():
    night = _ts(2026, 11, 2, 2) + 31 * 60          # 02:31 local
    assert backup.due(night - 3600, {}) is False    # 01:31
    assert backup.due(night, {}) is True
    day = backup._local(night).date().isoformat()
    ok = {"attempt_day": day, "ok": True, "ts": night, "attempts_today": 1}
    assert backup.due(night + 5 * 3600, ok) is False
    failed = {"attempt_day": day, "ok": False, "ts": night, "attempts_today": 1}
    assert backup.due(night + 600, failed) is False
    assert backup.due(night + 3700, failed) is True
    assert backup.due(night + 9 * 3600, dict(failed, attempts_today=4)) is False
    yesterday = {"attempt_day": "2026-11-01", "ok": True, "ts": night - 86400}
    assert backup.due(night + 8 * 3600, yesterday) is True  # container was down at 02:30


class _Eng:
    def __init__(self):
        self.sent, self.cleared = [], []

    def alert_once(self, conn, key, episode, subject, text):
        self.sent.append((key, episode, subject, text))
        return True

    def alert_clear(self, conn, key):
        self.cleared.append(key)


def test_alert_after_48h_without_success(bk):
    eng = _Eng()
    t = time.time()
    backup.write_status({"ts": int(t - 3600), "ok": False, "error": "x", "since": int(t - 50 * 3600),
                         "last_ok_ts": None})
    assert backup.check_alert(eng, None, now=t) is True
    key, episode, subject, text = eng.sent[0]
    assert key == "backup" and episode == "never" and "48 timer" in subject and "sfctl doctor" in text
    backup.write_status({"ts": int(t), "ok": True, "since": int(t - 50 * 3600), "last_ok_ts": int(t - 3 * 86400)})
    eng2 = _Eng()
    backup.check_alert(eng2, None, now=t)
    assert eng2.sent and eng2.sent[0][1] == str(int(t - 3 * 86400))
    backup.write_status({"ts": int(t), "ok": True, "since": int(t - 50 * 3600), "last_ok_ts": int(t - 3600)})
    eng3 = _Eng()
    assert backup.check_alert(eng3, None, now=t) is False and eng3.cleared == ["backup"]


def test_no_alert_within_48h_of_the_first_attempt(bk):
    eng = _Eng()
    t = time.time()
    backup.write_status({"ts": int(t), "ok": False, "skipped": "no_mount", "since": int(t - 3600)})
    assert backup.check_alert(eng, None, now=t) is False and not eng.sent


def test_key_status_and_shown_marker(bk):
    assert backup.key_status()["exists"] is False
    key = backup.load_key(create=True)
    st = backup.key_status()
    assert st["exists"] and st["key_id"] == backup.key_id(key) and st["shown_at"] is None
    backup.mark_key_shown(123)
    assert backup.key_status()["shown_at"] == 123
    assert "SFBK1" not in json.dumps(backup.key_status())


def test_summary_offsite_status(bk):
    (bk.state / backup.OFFSITE_STATUS_FILE).write_text(json.dumps(
        {"ok": False, "ts": int(time.time()) - 60, "remote": "offsite:Backup/Spamfilter", "error": "rclone exit 5"}))
    s = backup.summary()
    assert s["offsite"]["ok"] is False and s["offsite"]["error"] == "rclone exit 5" and s["offsite"]["age_s"] >= 60


def test_scheduler_loop_runs_a_due_backup_and_clears_the_alert(bk, monkeypatch):
    class Once:
        n = 0

        def wait(self, _t):
            self.n += 1
            return self.n > 1

    eng = _Eng()
    eng.SHUTDOWN = Once()
    eng._open_conn = lambda: sqlite3.connect(":memory:")
    monkeypatch.setattr(backup, "due", lambda now, st=None: True)
    monkeypatch.setattr(backup, "run_nightly", backup.run_backup)
    backup._loop(eng)
    assert backup.read_status()["ok"] is True and eng.cleared == ["backup"]


def test_scheduler_only_in_the_aio_container(monkeypatch):
    monkeypatch.delenv("SPAMFILTER_AIO", raising=False)
    monkeypatch.delenv("SF_BACKUP_DIR", raising=False)
    assert backup.enabled() is False and backup.start(object()) is False
    monkeypatch.setenv("SPAMFILTER_AIO", "1")
    assert backup.enabled() is True


# ---------------------------------------------------------------- 2.7.4: never in the engine
def _wal_after_other_process_closes(db: Path) -> bool:
    import subprocess  # noqa: PLC0415

    subprocess.run([sys.executable, "-c", "import sqlite3, sys; c = sqlite3.connect(sys.argv[1]); "
                    "c.execute('SELECT count(*) FROM messages').fetchone(); c.close()", str(db)], check=True)
    return Path(f"{db}-wal").exists()


def _engine_conn(db: Path) -> sqlite3.Connection:
    """Like an account thread: an open WAL connection with a pending WAL."""
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("INSERT INTO messages(subject) VALUES('ny')")
    conn.commit()
    assert Path(f"{db}-wal").exists()
    return conn


def test_why_the_engine_never_snapshots_itself(bk):
    """The 3 Nov 2026 cause: the header sniff's close() drops the engine's
    lock, so another process deletes the WAL under the open connection."""
    db = bk.state / "spamfilter.db"
    conn = _engine_conn(db)
    try:
        assert _wal_after_other_process_closes(db) is True
        assert backup._is_sqlite(db) is True
        assert _wal_after_other_process_closes(db) is False
    finally:
        conn.close()


def test_isolated_backup_keeps_the_engine_locks(bk):
    db = bk.state / "spamfilter.db"
    conn = _engine_conn(db)
    try:
        backup.configure(backup_dir=bk.dest)
        st = backup.run_backup_isolated(reason="test")
        assert st["reason"] == "test" and st["archive"] and (bk.dest / st["archive"]).is_file()
        assert _wal_after_other_process_closes(db) is True
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        conn.close()


def test_the_nightly_job_uses_the_child_process():
    assert backup.run_nightly is backup.run_backup_isolated


def test_local_fuzzy_redis_inventory_is_authenticated_and_custom_backend_not_full(bk, tmp_path):
    worker = bk.app / 'rspamd/local.d/worker-fuzzy.inc'
    worker.write_text('backend = "redis";\n')
    result = backup.run_backup(now=1700000000)
    assert result['ok']
    archive = _only(bk.dest)
    verified = backup.verify(archive)
    assert verified['learning_stores']['local_fuzzy']['snapshot'] == 'redis/dump.rdb'
    assert verified['learning_stores']['local_fuzzy']['backend'] == 'redis'
    restored = tmp_path / 'restored-fuzzy'
    backup.restore(archive, restored)
    assert (restored / 'redis/dump.rdb').read_bytes() == RDB
    assert (restored / 'appdata/rspamd/local.d/worker-fuzzy.inc').read_bytes() == worker.read_bytes()
    worker.write_text('backend = "sqlite";\n')
    result = backup.run_backup(now=1700003600)
    assert not result['ok'] and result['archive']
    assert result['last_ok_ts'] == 1700000000
    assert any('fuzzy' in warning for warning in result['warnings'])


def test_old_archive_inventory_remains_unknown(bk):
    result = backup.run_backup()
    assert result['learning_stores']['local_fuzzy']['backend'] == 'unknown'
    assert result['learning_stores']['local_fuzzy']['snapshot'] is None
    assert any('fuzzy' in w for w in result['warnings'])
