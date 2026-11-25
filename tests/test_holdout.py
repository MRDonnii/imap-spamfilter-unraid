"""Future training exclusion across accounts, direct import and fuzzy POSTs."""
import sqlite3
import threading
import time
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import setup_engine, make_account, make_message
import campaigns
import holdout
import mailidentity
import trainer

RAW = make_message('holdout@sample.example', body='Neutral human-reviewed sample')


@pytest.fixture
def eng(tmp_path, monkeypatch):
    return setup_engine(tmp_path, monkeypatch)


def test_reservation_is_idempotent_metadata_only_and_transport_stable(eng):
    original = holdout.reserve(eng.DB_PATH, RAW, 'sample-001', now=10)
    again = holdout.reserve(eng.DB_PATH, b'Received: by relay\r\n' + RAW, 'sample-001', now=20)
    assert original['reserved'] and not original['already_reserved']
    assert again['already_reserved']
    with sqlite3.connect(eng.DB_PATH) as conn:
        assert conn.execute('SELECT * FROM quality_holdout').fetchall() == [
            (mailidentity.fingerprint(RAW), 'sample-001', 10)]
        assert holdout.reserved(conn, RAW)
        assert not holdout.reserved(conn, make_message('different@sample.example', body='different'))
    assert 'Neutral human' not in str(original)


@pytest.mark.parametrize('sample,raw', [('bad@email.example', RAW), ('', RAW), ('x', b''),
                                    ('x', b'x' * (10 * 1024 * 1024 + 1))])
def test_invalid_input_never_reserves(eng, sample, raw):
    with pytest.raises(holdout.HoldoutError):
        holdout.reserve(eng.DB_PATH, raw, sample)
    with sqlite3.connect(eng.DB_PATH) as conn:
        assert conn.execute('SELECT COUNT(*) FROM quality_holdout').fetchone()[0] == 0


def test_conflicting_sample_identity_is_refused(eng):
    holdout.reserve(eng.DB_PATH, RAW, 'sample-001')
    with pytest.raises(holdout.HoldoutError, match='identitet'):
        holdout.reserve(eng.DB_PATH, RAW, 'other-id')
    with pytest.raises(holdout.HoldoutError, match='identitet'):
        holdout.reserve(eng.DB_PATH, b'Subject: other\r\n\r\nother', 'sample-001')


@pytest.mark.parametrize('source', ['messages', 'ledger', 'archive'])
def test_known_learning_in_another_account_prevents_clean_holdout_claim(eng, source):
    db = eng.Db('other-account')
    try:
        with db.tx():
            mid = mailidentity.bind(db.conn, db.account, 'holdout@sample.example', RAW)
            db.upsert_message(mid, 'INBOX', 'sender@sample.example', 'neutral')
            if source == 'ledger':
                eng._ledger_record(db.conn, db.account, mid, 'ham', 1, 'test')
            elif source == 'archive':
                db.conn.execute("INSERT INTO bayes_pool_archive(pool, src, account, message_id, kind, archived_at) "
                                "VALUES('old-pool','messages',?,?,'ham',1)", (db.account, mid))
            else:
                db.update_message(mid, learned_as='ham')
        with pytest.raises(holdout.HoldoutError, match='allerede'):
            holdout.reserve(eng.DB_PATH, RAW, 'sample-001')
    finally:
        db.conn.close()


def test_no_bayes_learning_in_any_pool_and_no_fake_bookkeeping(eng, monkeypatch):
    holdout.reserve(eng.DB_PATH, RAW, 'sample-001')
    monkeypatch.setattr(eng.requests, 'post', lambda *a, **k: pytest.fail('reserved content must never train'))
    acc = make_account(eng, name='another-account')
    db = eng.Db(acc.name)
    try:
        with db.tx():
            db.upsert_message('local-key', 'INBOX', None, None)
            db.update_message('local-key', pending_learn='spam', pending_learn_at=1)
        for kind in ('spam', 'ham'):
            assert eng.rspamd_learn(RAW, kind, 'any-pool') == 'held_out'
            assert eng.learn_message(db, acc, RAW, kind, 'local-key', bypass_rate=True,
                                     bypass_cooldown=True, allow_threat=True) == 'held_out'
        row = db.get_message('local-key')
        assert row['learned_as'] is None and row['pending_learn'] is None
        assert not db.conn.execute('SELECT 1 FROM learn_ledger').fetchone()
        assert not db.conn.execute("SELECT 1 FROM events WHERE event IN ('learn_spam','learn_ham')").fetchone()
    finally:
        db.conn.close()


def test_import_without_message_id_and_fuzzy_add_obey_reservation(eng, monkeypatch):
    raw = b'Subject: neutral sample\r\n\r\nNo message-ID present'
    holdout.reserve(eng.DB_PATH, raw, 'sample-002')
    calls = []
    monkeypatch.setattr(eng.requests, 'post', lambda url, **kw: calls.append(url) or SimpleNamespace(status_code=200))
    acc = make_account(eng)
    db = eng.Db(acc.name)
    try:
        outcome = trainer._learn_one(eng, db, acc, dict(kind='spam', created_by='admin', id=1), raw,
                                    SimpleNamespace(message_id=None), {})
        assert outcome == 'held_out'
        assert campaigns.fuzzy_add(eng, raw) == 'held_out'
        assert not calls
        assert campaigns.fuzzy_add(eng, raw, op='fuzzydel') == 'added'
        assert len(calls) == 1 and calls[0].endswith('/fuzzydel')
    finally:
        db.conn.close()


def test_reservation_waits_for_inflight_learning_then_blocks_the_next_post(eng):
    done = threading.Event()
    errors = []
    def register():
        try:
            holdout.reserve(eng.DB_PATH, RAW, 'sample-001')
        except Exception as ex:
            errors.append(ex)
        finally:
            done.set()
    with holdout.learning_guard(eng.DB_PATH, RAW) as allowed:
        assert allowed
        worker = threading.Thread(target=register)
        worker.start()
        assert not done.wait(.1)
    worker.join(3)
    assert done.is_set() and not errors
    with holdout.learning_guard(eng.DB_PATH, RAW) as allowed:
        assert not allowed


def test_busy_database_does_not_deadlock_a_learning_transaction(eng):
    with sqlite3.connect(eng.DB_PATH) as conn:
        conn.execute('BEGIN IMMEDIATE')
        started = time.monotonic()
        with pytest.raises(holdout.HoldoutError, match='optaget'):
            holdout.reserve(eng.DB_PATH, RAW, 'sample-001')
        assert time.monotonic() - started < 1
        with holdout.learning_guard(eng.DB_PATH, RAW) as allowed:
            assert allowed


def test_unreadable_registry_blocks_learning_instead_of_ignoring_reservations(eng, monkeypatch):
    monkeypatch.setattr(eng, 'DB_PATH', eng.DB_PATH.parent / 'broken.db')
    eng.DB_PATH.write_bytes(b'not a sqlite database')
    monkeypatch.setattr(eng.requests, 'post', lambda *a, **kw: pytest.fail('must fail without learning'))
    assert eng.rspamd_learn(RAW, 'spam') == 'error'
    assert campaigns.fuzzy_add(eng, RAW) == 'error'


def test_reservation_arriving_after_high_level_check_is_not_booked_as_learning(eng, monkeypatch):
    acc = make_account(eng)
    db = eng.Db(acc.name)
    try:
        with db.tx():
            db.upsert_message('local-key', 'INBOX', None, None)
        def race(*args, **kw):
            holdout.reserve(eng.DB_PATH, RAW, 'sample-001')
            return 'held_out'
        monkeypatch.setattr(eng, 'rspamd_learn', race)
        assert eng.learn_message(db, acc, RAW, 'spam', 'local-key') == 'held_out'
        assert db.get_message('local-key')['learned_as'] is None
        assert not db.conn.execute('SELECT 1 FROM learn_ledger').fetchone()
    finally:
        db.conn.close()


def test_missing_database_cannot_accept_a_reservation(tmp_path):
    missing = tmp_path / 'missing.db'
    with pytest.raises(holdout.HoldoutError, match='utilgængeligt'):
        holdout.reserve(missing, RAW, 'sample-001')
    assert not missing.exists()
