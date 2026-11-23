"""Local, content-bound reservations against future Bayes/fuzzy learning.

Reservations cover matching content across mailboxes and Bayes pools. They do
not undo past learning or prove an independent test set. The registry contains
hashes and neutral sample IDs, never mail bodies. All app-controlled learning
POSTs and reservation commits share a bounded process lock.
"""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import re
import sqlite3
import time

import mailidentity

SCHEMA = '''CREATE TABLE IF NOT EXISTS quality_holdout (
 fingerprint TEXT PRIMARY KEY, sample_id TEXT NOT NULL UNIQUE,
 created_at INTEGER NOT NULL)'''


class HoldoutError(Exception):
    pass


@contextmanager
def _lock(path, timeout=5):
    fd = os.open(Path(path).with_name('.quality-learning.lock'),
                 os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    acquired = False
    try:
        deadline = time.monotonic() + timeout
        while not acquired:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise HoldoutError('Læring er optaget; prøv igen senere.') from None
                time.sleep(.025)
        yield
    finally:
        if acquired:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _table(conn, name):
    return conn.execute('SELECT 1 FROM sqlite_master WHERE type=\'table\' AND name=?', (name,)).fetchone()


def reserved(conn, raw):
    if not _table(conn, 'quality_holdout'):
        return False  # additive migration: an older database has no reservations
    return conn.execute('SELECT 1 FROM quality_holdout WHERE fingerprint=?',
                        (mailidentity.fingerprint(raw),)).fetchone() is not None


@contextmanager
def learning_guard(db_path, raw):
    """Keep a reservation from committing between the check and learning POST.

    A missing DB cannot hold a reservation (standalone legacy helpers/tests).
    Existing but unreadable/corrupt registries raise; callers must skip learning.
    """
    if db_path is None or not Path(db_path).exists():
        yield True
        return
    with _lock(db_path):
        conn = sqlite3.connect(Path(db_path).resolve().as_uri() + '?mode=ro', uri=True, timeout=2)
        try:
            allowed = not reserved(conn, raw)
        finally:
            conn.close()
        yield allowed


def reserve(db_path, raw, sample_id, *, now=None):
    """Reserve an owner's local .eml for future learning, without training it.

    BEGIN IMMEDIATE never waits while holding the learning lock: a caller may
    already own a DB transaction before attempting to learn. Refusing busy
    registration avoids a lock-order deadlock and leaves the registry unchanged.
    """
    if not isinstance(sample_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,79}', sample_id):
        raise HoldoutError('Brug et neutralt sample-ID på 1–80 bogstaver, tal, punktum, bindestreg eller underscore.')
    if not raw or len(raw) > 10 * 1024 * 1024:
        raise HoldoutError('Mailfilen skal indeholde mellem 1 byte og 10 MiB.')
    digest = mailidentity.fingerprint(raw)
    try:
        with _lock(db_path):
            conn = sqlite3.connect(Path(db_path).resolve().as_uri() + '?mode=rw', uri=True,
                                   timeout=0, isolation_level=None)
            try:
                conn.execute('BEGIN IMMEDIATE')
                conn.execute(SCHEMA)
                existing = conn.execute('SELECT fingerprint, sample_id FROM quality_holdout '
                                        'WHERE fingerprint=? OR sample_id=?', (digest, sample_id)).fetchall()
                if existing and existing != [(digest, sample_id)]:
                    raise HoldoutError('Sample-ID eller indhold er allerede reserveret under en anden identitet.')
                # Refuse known historical Bayes training, including another
                # account. Absence of a local record cannot prove no past learn.
                if _table(conn, 'mail_identity') and _table(conn, 'messages'):
                    learned = conn.execute("SELECT 1 FROM mail_identity i JOIN messages m "
                                           "ON m.account=i.account AND m.message_id=i.message_key "
                                           "WHERE i.fingerprint=? AND m.learned_as IN ('spam','ham') LIMIT 1",
                                           (digest,)).fetchone()
                    if _table(conn, 'learn_ledger'):
                        learned = learned or conn.execute('SELECT 1 FROM mail_identity i JOIN learn_ledger l '
                                                         'ON l.account=i.account AND l.message_id=i.message_key '
                                                         'WHERE i.fingerprint=? LIMIT 1', (digest,)).fetchone()
                    if _table(conn, 'bayes_pool_archive'):
                        learned = learned or conn.execute('SELECT 1 FROM mail_identity i JOIN bayes_pool_archive b '
                                                         'ON b.account=i.account AND b.message_id=i.message_key '
                                                         "WHERE i.fingerprint=? AND b.kind IN ('spam','ham') LIMIT 1",
                                                         (digest,)).fetchone()
                    if learned:
                        raise HoldoutError('Dette indhold er allerede registreret som lært. Vælg andet prøvemateriale.')
                conn.execute('INSERT OR IGNORE INTO quality_holdout VALUES(?,?,?)',
                             (digest, sample_id, int(time.time() if now is None else now)))
                conn.commit()
            finally:
                conn.close()
    except (OSError, sqlite3.Error) as ex:
        raise HoldoutError('Reservation afvist; registeret er optaget eller utilgængeligt ('
                           + type(ex).__name__ + ').') from None
    return dict(sample_id=sample_id, reserved=True, already_reserved=bool(existing),
                scope='matching_content_all_accounts',
                warning='Kun fremtidig læring gennem denne app blokeres. Tidligere træning er ikke '
                        'tilbageført eller bevist fraværende. Hold mail og facit lokalt.')
