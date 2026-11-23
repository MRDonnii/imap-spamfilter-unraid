"""Restore startup drill: private temporary copy, SQLite + app + Redis/Bayes.

Never starts account, trainer, SMTP or push workers. The actual HTTP server
listens on a private Unix socket; Redis has port=0 and a private Unix socket.
The original archive and installation are read-only. Rspamd/ClamAV and live
provider access remain separate container/installation acceptance checks.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time


class DrillError(ValueError):
    pass


def _redis(sockpath, command):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(2)
        sock.connect(str(sockpath))
        sock.sendall(command + b'\r\n')
        return sock.recv(4096)


def inspect_databases(root):
    databases = []
    for path in (root / 'state').glob('*.db'):
        conn = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)
        try:
            if conn.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                raise DrillError('En gendannet database består ikke integritetskontrollen.')
            databases.append(path.name)
        except sqlite3.DatabaseError:
            raise DrillError('En gendannet database kunne ikke læses.') from None
        finally:
            conn.close()
    if 'spamfilter.db' not in databases:
        raise DrillError('Backup mangler spamfilter.db.')
    return databases


# Deliberately not dashboard.start()/filter.main(): those start live workers.
BOOTSTRAP = r'''
import socket
# This child may bind its private Unix socket, but never connect to IP hosts.
original_connect = socket.socket.connect
def local_only(self, address):
    if self.family != socket.AF_UNIX:
        raise RuntimeError('restore drill forbids network connections')
    return original_connect(self, address)
socket.socket.connect = local_only
import filter as engine
engine.init_db()
import dashboard as ui
import mailer
mailer.AUTO_WORKER = False
import push
push.AUTO_WORKER = False
ui.init_ui_db()
ui.app.secret_key = ui._load_secret()
ui.register_pages()
from waitress import create_server
server = create_server(ui.app, unix_socket=__import__('os').environ['DRILL_HTTP_SOCKET'],
                       unix_socket_perms='600', threads=2)
server.run()
'''


def run(archive, key=None, *, timeout=30):
    import backup
    redis = shutil.which('redis-server')
    if not redis:
        raise DrillError('redis-server mangler; kør øvelsen i all-in-one-containeren.')
    # Short directory name: Unix socket paths have a platform length limit.
    with tempfile.TemporaryDirectory(prefix='sf-drill-') as tmp:
        work = Path(tmp)
        restored = work / 'copy'
        backup.restore(Path(archive), restored, key)
        databases = inspect_databases(restored)
        if not (restored / 'redis' / 'dump.rdb').is_file():
            raise DrillError('Backup mangler Redis/Bayes; øvelsen kan ikke godkendes.')
        # No secrets/account settings are loaded as runtime config. The copy
        # still contains the restored originals for the integrity checks.
        safe = work / 'config'
        safe.mkdir(mode=0o700)
        (safe / 'accounts.yml').write_text('accounts: []\n')
        (safe / 'site.yml').write_text('setup_done: false\n')
        rsock, hsock = work / 'redis.sock', work / 'http.sock'
        env = dict(os.environ, STATE_DIR=str(restored / 'state'),
                   CONFIG_PATH=str(safe / 'accounts.yml'), SITE_CONFIG_PATH=str(safe / 'site.yml'),
                   SF_RDAP='0', DRILL_HTTP_SOCKET=str(hsock), PYTHONDONTWRITEBYTECODE='1')
        processes = []
        try:
            processes.append(subprocess.Popen([redis, '--port', '0', '--bind', '127.0.0.1',
                '--unixsocket', str(rsock), '--unixsocketperm', '600', '--dir', str(restored / 'redis'),
                '--dbfilename', 'dump.rdb', '--save', '', '--appendonly', 'no', '--daemonize', 'no'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            deadline = time.monotonic() + timeout
            while True:
                if processes[0].poll() is not None:
                    raise DrillError('Redis kunne ikke indlæse den gendannede Bayes-database.')
                try:
                    if _redis(rsock, b'PING').startswith(b'+PONG'):
                        break
                except OSError:
                    pass
                if time.monotonic() >= deadline:
                    raise DrillError('Redis-start tog for lang tid.')
                time.sleep(.05)
            response = _redis(rsock, b'DBSIZE')
            if not response.startswith(b':'):
                raise DrillError('Redis/Bayes kunne ikke læses.')
            keys = int(response[1:].strip())
            processes.append(subprocess.Popen([sys.executable, '-c', BOOTSTRAP], env=env,
                cwd=str(Path(__file__).parent), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            while True:
                if processes[1].poll() is not None:
                    raise DrillError('Applikationen kunne ikke starte med den gendannede database.')
                try:
                    with socket.socket(socket.AF_UNIX) as sock:
                        sock.settimeout(2)
                        sock.connect(str(hsock))
                        sock.sendall(b'GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n')
                        reply = sock.recv(4096)
                    if b' 200 ' in reply.split(b'\r\n', 1)[0]:
                        break
                except OSError:
                    pass
                if time.monotonic() >= deadline:
                    raise DrillError('Applikationsstart tog for lang tid.')
                time.sleep(.05)
            return dict(ok=True, checked_at=int(time.time()), databases=len(databases),
                        redis_keys=keys, app_started=True, network='unix_sockets_only',
                        scope='SQLite, web application startup and Redis/Bayes; no mail workers, Rspamd or ClamAV')
        finally:
            for proc in reversed(processes):
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
