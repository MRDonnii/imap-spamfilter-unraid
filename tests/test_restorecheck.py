"""Actual isolated Redis + HTTP startup on an encrypted restored fixture."""
import os
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import time
import sys
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
    assert result['child_limits']['memory_mib_max'] == 1024
    assert (bk.state / 'spamfilter.db').read_bytes() == original
    with pytest.raises(backup.BackupError):
        restorecheck.run(_only(bk.dest), key=b'x' * 32)
    # A valid encrypted archive with invalid Bayes data must fail startup.
    monkeypatch.setattr(backup, 'redis_dump', lambda dest: (Path(dest).write_bytes(b'bad rdb') and True, ''))
    assert backup.run_backup(reason='test', now=time.time() + 100)['ok']
    newest = max(bk.dest.glob('*.sfbak'), key=lambda p: p.name)
    with pytest.raises(restorecheck.DrillError, match='Redis'):
        restorecheck.run(newest)


def test_actual_child_has_kernel_resource_limits_and_cannot_allocate_over_budget():
    code = '''import json,resource,sys
print(json.dumps({str(k): resource.getrlimit(k) for k in
 (resource.RLIMIT_AS, resource.RLIMIT_CPU, resource.RLIMIT_NOFILE, resource.RLIMIT_CORE)}), flush=True)
try:
    data = bytearray(256 * 1024 * 1024)
except MemoryError:
    print('allocation blocked', flush=True)
    sys.exit(0)
sys.exit(2)
'''
    proc = restorecheck._start_bounded([sys.executable, '-c', code], memory_mib=128,
                                      stdout=subprocess.PIPE)
    try:
        output, _ = proc.communicate(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
    assert proc.returncode == 0
    rows = output.decode().splitlines()
    limits = json.loads(rows[0])
    import resource
    assert limits[str(resource.RLIMIT_AS)][0] <= 128 * 1024 * 1024
    assert limits[str(resource.RLIMIT_CPU)][0] <= 30
    assert limits[str(resource.RLIMIT_NOFILE)][0] <= 128
    assert limits[str(resource.RLIMIT_CORE)] == [0, 0]
    assert rows[1] == 'allocation blocked'


@pytest.mark.parametrize('limit', [0, 127, 4097, True])
def test_invalid_budget_is_refused_before_restoring_anything(tmp_path, limit):
    with pytest.raises(restorecheck.DrillError, match='Hukommelsesgrænsen'):
        restorecheck.run(tmp_path / 'not-opened.sfbak', memory_mib=limit)
