"""Encrypted archive -> harmless runtime copy with restored backend keys."""
import json
from pathlib import Path
import sqlite3

import pytest
import yaml

from test_backup import bk, _only
from test_aio import _bundle, render
import backup
import stackrestore


@pytest.fixture
def archive(bk):
    (bk.state / 'controller.password').write_text('controller-neutral-0123456789\n')
    (bk.state / 'redis.password').write_text('redis-neutral-"quoted\\key\n')
    (bk.state / 'smtp.password').write_text('PRIVATE SMTP')
    (bk.config / 'accounts.yml').write_text('accounts:\n- name: private-account\n  password: PRIVATE LOGIN\n')
    with sqlite3.connect(bk.state / 'spamfilter.db') as conn:
        conn.executescript("CREATE TABLE settings_kv(key TEXT PRIMARY KEY,value TEXT);"
                          "CREATE TABLE mail_outbox(body TEXT);"
                          "CREATE TABLE train_jobs(status TEXT);")
        conn.execute("INSERT INTO settings_kv VALUES('smtp','PRIVATE SMTP SETTINGS')")
        conn.execute("INSERT INTO mail_outbox VALUES('PRIVATE OUTBOX')")
        conn.execute("INSERT INTO train_jobs VALUES('queued')")
    result = backup.run_backup(reason='test')
    assert result['ok'], result
    return _only(bk.dest), backup.load_key()


def fake_seed(path, **kwargs):
    assert (path / 'dump.rdb').is_file()
    return dict(key='neutral-canary-key', value='neutral-canary-value')


def test_prepares_only_a_new_copy_preserving_keys_and_cancelling_active_jobs(bk, archive, tmp_path):
    path, key = archive
    original = path.read_bytes(), (bk.state / 'spamfilter.db').read_bytes()
    output = tmp_path / 'prepared'
    result = stackrestore.prepare(path, key, output, bundle=_bundle(tmp_path), renderer=render, seed=fake_seed)
    assert result['ok'] and result['accounts_enabled'] == 0
    assert yaml.safe_load((output / 'config/accounts.yml').read_text()) == {'accounts': []}
    assert not (output / 'state/smtp.password').exists()
    assert not list((output / 'state/imap-secrets').iterdir())
    assert not (output / 'state/vapid_private.pem').exists()
    with sqlite3.connect(output / 'state/spamfilter.db') as conn:
        assert not conn.execute('SELECT * FROM mail_outbox').fetchall()
        assert not conn.execute('SELECT * FROM settings_kv').fetchall()
        assert conn.execute('SELECT status FROM train_jobs').fetchone()[0] == 'cancelled'
        assert conn.execute('SELECT COUNT(*) FROM messages').fetchone()[0] == 3000
    redis_pw = (bk.state / 'redis.password').read_text().strip()
    assert 'requirepass ' + json.dumps(redis_pw) in (output / 'redis-config/redis.conf').read_text()
    assert 'password = ' + json.dumps(redis_pw) in (output / 'rspamd/local.d/redis.conf').read_text()
    assert 'appendonly no' in (output / 'redis-config/redis.conf').read_text()
    assert (output / 'state/controller.password').read_bytes() == (bk.state / 'controller.password').read_bytes()
    assert (path.read_bytes(), (bk.state / 'spamfilter.db').read_bytes()) == original
    assert 'PRIVATE' not in json.dumps(result)
    assert (output / 'operations/restore-proof.json').stat().st_mode & 0o777 == 0o600


def test_refuses_existing_output_and_bad_key_without_touching_source(bk, archive, tmp_path):
    path, key = archive
    output = tmp_path / 'existing'
    output.mkdir()
    (output / 'keep').write_text('preserve')
    with pytest.raises(stackrestore.PrepareError, match='ny'):
        stackrestore.prepare(path, key, output, bundle=_bundle(tmp_path), renderer=render, seed=fake_seed)
    assert (output / 'keep').read_text() == 'preserve'
    missing = tmp_path / 'not-created'
    with pytest.raises(backup.BackupError):
        stackrestore.prepare(path, b'x'*32, missing, bundle=_bundle(tmp_path), renderer=render, seed=fake_seed)
    assert not missing.exists()


def test_refuses_live_path_and_removes_its_own_failed_copy(bk, archive, tmp_path):
    path, key = archive
    with pytest.raises(stackrestore.PrepareError, match='aktive'):
        stackrestore.prepare(path, key, bk.app / 'new', bundle=_bundle(tmp_path), renderer=render, seed=fake_seed)
    def bad_seed(*args, **kw):
        raise stackrestore.PrepareError('synthetic seed error')
    output = tmp_path / 'failed-copy'
    with pytest.raises(stackrestore.PrepareError, match='seed'):
        stackrestore.prepare(path, key, output, bundle=_bundle(tmp_path), renderer=render, seed=bad_seed)
    assert not output.exists()


@pytest.mark.parametrize('unsafe', ['network', 'port', 'mount', 'memory'])
def test_driver_refuses_daemon_isolation_changes_before_start(tmp_path, unsafe):
    """A daemon-applied mismatch must never reach docker start (real jq gate)."""
    import os
    import shutil
    import subprocess
    if not shutil.which('jq'):
        pytest.skip('jq required for deployment validation')
    binaries = tmp_path / 'bin'
    binaries.mkdir()
    docker = binaries / 'docker'
    docker.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['CALLS'], 'a') as f: f.write(json.dumps(args)+'\\n')
if args[:2] == ['image', 'inspect']:
    print(json.dumps([{'Config':{'Labels':{'spamfilter.layout':'aio'}}}]))
elif args[0] == 'create':
    print('owned-container-id')
elif args[0] == 'inspect':
    mounts=[]
    calls=[json.loads(s) for s in Path(os.environ['CALLS']).read_text().splitlines()]
    create=next(c for c in calls if c[0]=='create')
    for i,v in enumerate(create):
        if v=='--mount':
            fields=create[i+1].split(',')
            kv=dict(x.split('=',1) for x in fields if '=' in x)
            mounts.append(dict(Type='bind',Source=kv['src'],Destination=kv['dst'],RW='readonly' not in fields))
    h=dict(NetworkMode='none',PortBindings={},Memory=2048,NanoCpus=1000,PidsLimit=64,ReadonlyRootfs=True)
    which=os.environ['UNSAFE']
    if which=='network': h['NetworkMode']='bridge'
    if which=='port': h['PortBindings']={'8080/tcp':[{'HostPort':'9999'}]}
    if which=='memory': h['Memory']=0
    if which=='mount': mounts.append(dict(Type='bind',Source='/live/state',Destination='/state',RW=True))
    print(json.dumps([dict(HostConfig=h,Mounts=mounts)]))
''')
    docker.chmod(0o755)
    # This test runs without root; no service processes or ownership changes.
    for name, body in [('id', '#!/bin/sh\necho 0\n'), ('chown', '#!/bin/sh\nexit 0\n')]:
        p = binaries / name
        p.write_text(body)
        p.chmod(0o755)
    source = tmp_path / 'original.sfbak'
    key = tmp_path / 'original.key'
    source.write_bytes(b'encrypted synthetic archive')
    key.write_text('neutral key')
    calls = tmp_path / 'calls.jsonl'
    root = Path(__file__).resolve().parents[1]
    app = tmp_path / 'app'
    live = app / 'state'
    live.mkdir(parents=True)
    sentinel = live / 'keep'
    sentinel.write_text('live data')
    result = subprocess.run(['bash', str(root / 'deploy/aio/restore-stack-drill.sh'),
        '--archive', str(source), '--key-file', str(key), '--image', 'neutral-test-image'],
        env=dict(os.environ, PATH=str(binaries)+':'+os.environ['PATH'], SPAMFILTER_APP=str(app),
                 CALLS=str(calls), UNSAFE=unsafe), capture_output=True, text=True)
    assert result.returncode != 0
    assert 'isolation verification failed' in result.stderr
    actions = [json.loads(line) for line in calls.read_text().splitlines()]
    assert not any(row[0] == 'start' for row in actions)
    assert ['rm', '--force', '--volumes', 'owned-container-id'] in actions
    assert not list((app / 'operations/restore-drills').iterdir())
    assert source.read_bytes() == b'encrypted synthetic archive'
    assert key.read_text() == 'neutral key'
    assert sentinel.read_text() == 'live data'


def test_real_redis_canary_survives_rdb_reload(tmp_path):
    import shutil
    if not shutil.which('redis-server'):
        pytest.skip('Redis unavailable; pinned image CI executes the full drill')
    data = tmp_path / 'redis'
    data.mkdir()
    first = stackrestore.seed_canary(data)
    second = stackrestore.seed_canary(data)
    # Confirm the seed loads old data, rather than replacing the RDB.
    import subprocess
    import tempfile
    import time
    import restorecheck
    with tempfile.TemporaryDirectory(prefix='sf-proof-') as tmp:
        sock = Path(tmp) / 'r.sock'
        proc = restorecheck._start_bounded([shutil.which('redis-server'), '--port', '0',
            '--unixsocket', str(sock), '--dir', str(data), '--save', '', '--appendonly', 'no'])
        try:
            until = time.monotonic() + 10
            while not sock.exists() and proc.poll() is None and time.monotonic() < until:
                time.sleep(.02)
            for marker in (first, second):
                assert marker['value'].encode() in restorecheck._redis(sock, ('GET '+marker['key']).encode())
        finally:
            proc.terminate()
            proc.wait(timeout=5)
