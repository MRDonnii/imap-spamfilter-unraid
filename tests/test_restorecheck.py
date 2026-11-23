"""Actual isolated Redis + HTTP startup on an encrypted restored fixture."""
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import time
import pytest
from test_backup import bk, _only
import backup
import restorecheck
from fakes_engine import setup_engine


def test_database_corruption_is_not_an_archive_success(tmp_path):
    root = tmp_path / 'copy'
    (root / 'state').mkdir(parents=True)
    (root / 'state' / 'spamfilter.db').write_bytes(b'not sqlite')
    with pytest.raises(restorecheck.DrillError):
        restorecheck.inspect_databases(root)


def test_missing_database_is_refused(tmp_path):
    (tmp_path / 'state').mkdir()
    with pytest.raises(restorecheck.DrillError, match='mangler'):
        restorecheck.inspect_databases(tmp_path)


def test_actual_restore_starts_app_and_loads_bayes(bk, tmp_path, monkeypatch):
    redis = shutil.which('redis-server')
    if redis is None:
        pytest.skip('redis-server unavailable; container smoke runs this check with the pinned Redis')
    # Replace ONLY this test fixture's old example DB with a real engine DB.
    conn = sqlite3.connect(bk.state / 'spamfilter.db')
    conn.execute('DROP TABLE messages')
    conn.commit()
    conn.close()
    setup_engine(bk.state, monkeypatch)
    rdir = tmp_path / 'seed'
    rdir.mkdir()
    sock = rdir / 'r.sock'
    proc = subprocess.Popen([redis, '--port', '0', '--unixsocket', str(sock), '--dir', str(rdir),
                             '--save', '', '--appendonly', 'no'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 10
        while not sock.exists():
            assert proc.poll() is None and time.monotonic() < deadline
            time.sleep(.02)
        assert restorecheck._redis(sock, b'SET neutral-bayes-key 42').startswith(b'+OK')
        assert restorecheck._redis(sock, b'SAVE').startswith(b'+OK')
    finally:
        proc.terminate()
        proc.wait(timeout=5)
    def dump(dest):
        shutil.copyfile(rdir / 'dump.rdb', dest)
        return True, ''
    monkeypatch.setattr(backup, 'redis_dump', dump)
    result = backup.run_backup(reason='test')
    assert result['ok'], result
    original = (bk.state / 'spamfilter.db').read_bytes()
    result = restorecheck.run(_only(bk.dest))
    assert result['ok'] and result['app_started'] and result['redis_keys'] == 1
    assert (bk.state / 'spamfilter.db').read_bytes() == original
    with pytest.raises(backup.BackupError):
        restorecheck.run(_only(bk.dest), key=b'x' * 32)
    # A valid encrypted archive with invalid Bayes data must fail startup.
    monkeypatch.setattr(backup, 'redis_dump', lambda dest: (Path(dest).write_bytes(b'bad rdb') and True, ''))
    assert backup.run_backup(reason='test', now=time.time() + 100)['ok']
    newest = max(bk.dest.glob('*.sfbak'), key=lambda p: p.name)
    with pytest.raises(restorecheck.DrillError, match='Redis'):
        restorecheck.run(newest)
