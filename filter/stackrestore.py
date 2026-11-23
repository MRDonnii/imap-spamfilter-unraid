"""Prepare an accountless restore copy for an OFFLINE, separate AIO container.

Never start this module as a live installation. Transport configuration comes
from the selected image's templates with the restored backend secrets. Original
archive/key files are read-only; no secret values are returned or logged.
"""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

import backup
import restorecheck


class PrepareError(ValueError):
    pass


def _secret(path):
    with path.open('rb') as f:
        value = f.read(4097)
    if len(value) > 4096:
        raise PrepareError('En backendnøgle har et ugyldigt format.')
    value = value.decode('utf-8').strip()
    if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise PrepareError('En backendnøgle har et ugyldigt format.')
    return value


def _template(bundle, name, variable, secret):
    text = (bundle / name).read_text()
    placeholder = re.escape('${' + variable + '}')
    pattern = '"' + placeholder + '"|' + placeholder
    text, count = re.subn(pattern, lambda _: json.dumps(secret, ensure_ascii=False), text)
    if not count:
        raise PrepareError('Billedets backend-skabelon kunne ikke anvendes.')
    return text


def seed_canary(redis_dir, *, memory_mib=1024):
    redis = shutil.which('redis-server')
    if not redis:
        raise PrepareError('Billedet mangler Redis.')
    key, value = 'sf-restore-drill-' + secrets.token_hex(12), secrets.token_hex(16)
    with tempfile.TemporaryDirectory(prefix='sf-seed-') as tmp:
        sock = Path(tmp) / 'r.sock'
        proc = restorecheck._start_bounded([redis, '--port', '0', '--unixsocket', str(sock),
            '--unixsocketperm', '600', '--dir', str(redis_dir), '--dbfilename', 'dump.rdb',
            '--save', '', '--appendonly', 'no', '--daemonize', 'no'], memory_mib=memory_mib)
        try:
            deadline = time.monotonic() + 30
            while True:
                if proc.poll() is not None or time.monotonic() >= deadline:
                    raise PrepareError('Den gendannede Redis-kopi kunne ikke indlæses inden for budgettet.')
                try:
                    if restorecheck._redis(sock, b'PING').startswith(b'+PONG'):
                        break
                except OSError:
                    pass
                time.sleep(.05)
            if not restorecheck._redis(sock, f'SET {key} {value}'.encode()).startswith(b'+OK'):
                raise PrepareError('Redis-prøvemarkøren kunne ikke gemmes.')
            if not restorecheck._redis(sock, b'SAVE').startswith(b'+OK'):
                raise PrepareError('Den gendannede Redis-kopi kunne ikke skrives.')
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
    return dict(key=key, value=value)


def prepare(archive, key, output, *, bundle, renderer=None, seed=seed_canary, memory_mib=1024):
    output, bundle = Path(output), Path(bundle)
    if isinstance(memory_mib, bool) or not isinstance(memory_mib, int) or not 128 <= memory_mib <= 4096:
        raise PrepareError('Hukommelsesbudgettet skal være 128–4096 MiB.')
    if output.exists() or output.is_symlink():
        raise PrepareError('Destinationsmappen skal være ny og må ikke være et symbolsk link.')
    for live in (backup.STATE_DIR, backup.CONFIG_PATH.parent, backup.APPDATA):
        a, b = output.resolve(), Path(live).resolve()
        if a == b or backup._inside(a, b) or backup._inside(b, a):
            raise PrepareError('Destinationsmappen må ikke overlappe den aktive installation.')
    with backup.Archive(Path(archive), key) as source:
        try:
            sizes = [int(row['size']) for row in source.manifest['files']]
        except (ValueError, TypeError, KeyError):
            raise PrepareError('Backupfilens indholdsliste er ugyldig.') from None
        if any(size < 0 for size in sizes):
            raise PrepareError('Backupfilens indholdsliste er ugyldig.')
        if shutil.disk_usage(output.parent).free < 2 * sum(sizes) + 256 * 1024 * 1024:
            raise PrepareError('Der er ikke fri plads til den private gendannelseskopi.')
    if renderer is None:
        sys.path.insert(0, '/usr/local/lib/spamfilter-aio')
        import aio_render as renderer
    created = False
    try:
        with tempfile.TemporaryDirectory(prefix='.sf-restore-', dir=output.parent) as tmp:
            restored = Path(tmp) / 'restored'
            info = backup.restore(Path(archive), restored, key)
            databases = restorecheck.inspect_databases(restored)
            if not (restored / 'redis' / 'dump.rdb').is_file():
                raise PrepareError('Backup mangler Redis/Bayes.')
            redis_pw = _secret(restored / 'state' / 'redis.password')
            controller_pw = _secret(restored / 'state' / 'controller.password')
            output.mkdir(mode=0o700)
            created = True
            if not renderer.init_appdata(output, bundle, chown=False):
                raise PrepareError('Billedets friske runtime-kopi kunne ikke oprettes.')
            shutil.copytree(restored / 'state', output / 'state', dirs_exist_ok=True)
            shutil.copytree(restored / 'config', output / 'config', dirs_exist_ok=True)
            shutil.copyfile(restored / 'redis' / 'dump.rdb', output / 'redis' / 'dump.rdb')
            extra = restored / 'appdata'
            if (extra / 'rspamd/local.d').is_dir():
                shutil.copytree(extra / 'rspamd/local.d', output / 'rspamd/local.d', dirs_exist_ok=True)
            for name in ('unbound.conf', 'unbound-forward-records.conf'):
                if (extra / name).is_file():
                    shutil.copyfile(extra / name, output / name)
            # Regenerate transport files, retaining the restored secrets;
            # ordinary backups may lack other service UIDs' private configs.
            source_conf = extra / 'redis-config/redis.conf'
            conf = (source_conf.read_text() if source_conf.is_file() else
                    _template(bundle, 'redis.conf.template', 'REDIS_PASSWORD', redis_pw))
            conf = re.sub(r'^\s*appendonly\s+.*$', 'appendonly no', conf, flags=re.M)
            (output / 'redis-config' / 'redis.conf').write_text(conf)
            for name, variable, value in (('redis.conf', 'REDIS_PASSWORD', redis_pw),
                                          ('worker-controller.inc', 'RSPAMD_PASSWORD', controller_pw)):
                if not (extra / 'rspamd/local.d' / name).is_file():
                    (output / 'rspamd/local.d' / name).write_text(
                        _template(bundle, 'rspamd/' + name + '.template', variable, value))
            (output / 'config' / 'accounts.yml').write_text('accounts: []\n')
            # Old credentials/jobs cannot be used, even before network isolation.
            for name in ('imap-secrets', 'removed-secrets'):
                path = output / 'state' / name
                if path.is_dir():
                    shutil.rmtree(path)
                path.mkdir(mode=0o700)
            for name in ('smtp.password', 'vapid_private.pem'):
                (output / 'state' / name).unlink(missing_ok=True)
            conn = sqlite3.connect(output / 'state' / 'spamfilter.db')
            try:
                tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if 'settings_kv' in tables:
                    conn.execute("DELETE FROM settings_kv WHERE key IN ('smtp','smtp_state','mail_notify','ai')")
                for table in ('mail_outbox', 'push_subscriptions', 'push_queue', 'account_status'):
                    if table in tables:
                        conn.execute(f'DELETE FROM {table}')
                for table in ('undo_jobs', 'train_jobs', 'learn_list_jobs'):
                    if table in tables:
                        conn.execute(f"UPDATE {table} SET status='cancelled' WHERE status IN "
                                     "('queued','running','cancel_requested')")
                conn.commit()
            finally:
                conn.close()
            canary = seed(output / 'redis', memory_mib=memory_mib)
            result = dict(ok=True, files=info['files'], databases=len(databases), canary=canary,
                        accounts_enabled=0, runtime_config='readable_restored_overrides_with_image_fallbacks',
                        scope='Offline application/Rspamd/Redis/Unbound copy; ClamAV and provider logins excluded')
            proof = output / 'operations' / 'restore-proof.json'
            proof.write_text(json.dumps(result))
            proof.chmod(0o600)
            return result
    except BaseException:
        if created:
            shutil.rmtree(output)
        raise


def check_runtime(app=Path('/appdata')):
    import requests
    proof = json.loads((app / 'operations' / 'restore-proof.json').read_text())
    if (app / 'config' / 'accounts.yml').read_text().strip() != 'accounts: []':
        raise PrepareError('Prøven har aktive kontooplysninger.')
    health = requests.get('http://127.0.0.1:8080/healthz', timeout=10)
    health.raise_for_status()
    login = requests.get('http://127.0.0.1:8080/login', timeout=10, allow_redirects=False)
    if login.status_code != 200:
        raise PrepareError('Den gendannede login-side kunne ikke åbnes.')
    raw = (b'From: restore@sample.invalid\r\nTo: neutral@sample.invalid\r\n'
           b'Subject: Neutral restore check\r\nMessage-ID: <restore-check@sample.invalid>\r\n\r\n'
           b'This is a neutral offline restoration test. No mail is sent.')
    scan = requests.post('http://127.0.0.1:11333/checkv2', data=raw, timeout=30)
    scan.raise_for_status()
    if not isinstance(scan.json(), dict) or 'score' not in scan.json():
        raise PrepareError('Rspamd kunne ikke scanne en neutral prøve.')
    env = dict(os.environ, REDISCLI_AUTH=_secret(app / 'state' / 'redis.password'))
    cli = shutil.which('redis-cli')
    if not cli:
        raise PrepareError('Billedet mangler Redis-klienten.')
    def redis(*args):
        proc = subprocess.run([cli, '--raw', *args], env=env, capture_output=True, timeout=10, text=True)
        if proc.returncode:
            raise PrepareError('Den gendannede Redis kunne ikke læses med backupens legitimationsoplysninger.')
        return proc.stdout.strip()
    if redis('GET', proof['canary']['key']) != proof['canary']['value']:
        raise PrepareError('Redis indlæste ikke den gendannede RDB-kopi.')
    redis('DEL', proof['canary']['key'])
    return dict(ok=True, http=True, rspamd_scan=True, redis_canary_verified=True,
                redis_keys=int(redis('DBSIZE')), accounts_enabled=0,
                app_version=health.json().get('version'), clamav='not_started_offline',
                scope=proof['scope'], runtime_config=proof['runtime_config'])


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('prepare')
    p.add_argument('--archive', required=True)
    p.add_argument('--key-file', required=True)
    p.add_argument('--to', required=True)
    p.add_argument('--bundle', default='/usr/local/share/spamfilter-aio')
    p.add_argument('--memory-mib', type=int, default=1024)
    commands.add_parser('check')
    args = parser.parse_args()
    try:
        if args.command == 'check':
            result = check_runtime()
        else:
            keyfile = Path(args.key_file)
            if keyfile.is_symlink():
                raise PrepareError('Backupnøglen må ikke være et symbolsk link.')
            key = backup.parse_key(keyfile.read_text())
            result = prepare(args.archive, key, args.to, bundle=args.bundle, memory_mib=args.memory_mib)
            result.pop('canary', None)
    except (PrepareError, backup.BackupError, OSError, sqlite3.Error, ValueError) as ex:
        detail = str(ex) if isinstance(ex, PrepareError) else type(ex).__name__
        print('Gendannelseskopien kunne ikke forberedes: ' + detail, file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
