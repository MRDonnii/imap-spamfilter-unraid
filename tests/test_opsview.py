"""Operational views must never mistake stale/missing measurements for green."""
import sqlite3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "filter"))
from types import SimpleNamespace

import pytest

import opsview
import ai_verdict


@pytest.mark.parametrize('health', [None, {}, {'ts': 0}, {'ts': 9999},
    {'ts': 1, 'parts': {'clamav': {'state': 'ok'}}},
    {'ts': True, 'parts': {'clamav': {'state': 'ok'}}},
    {'ts': 999, 'parts': {'clamav': {'state': 'invented'}}}])
def test_stale_malformed_and_future_health_are_unknown(health):
    assert opsview.antivirus(health, now=1000)['state'] == 'unknown'


def test_signature_age_advances_from_measurement_and_off_requires_explicit_setting():
    facts = opsview.antivirus({'ts': 900, 'parts': {'clamav': {'state': 'ok', 'db_age_s': 3600}}}, now=1000)
    assert facts['signatures_age_s'] == 3700 and facts['observed_age_s'] == 100
    for reason, intentional in [('SF_CLAMAV=0', True), ('cannot create directory', False)]:
        facts = opsview.antivirus({'ts': 1000, 'parts': {'clamav': {'state': 'off', 'reason': reason}}}, now=1000)
        assert facts['intentionally_off'] is intentional


def test_queue_counts_are_account_scoped_read_only_and_ignore_finished_jobs():
    conn = sqlite3.connect(':memory:')
    conn.executescript('''CREATE TABLE pending_move(account TEXT,flag_at INTEGER);
        CREATE TABLE train_jobs(account TEXT,created_at INTEGER,status TEXT);
        CREATE TABLE undo_jobs(account TEXT,created_at INTEGER,status TEXT);
        INSERT INTO pending_move VALUES('a',100),('a',200),('removed',1);
        INSERT INTO train_jobs VALUES('a',300,'queued'),('a',1,'done');
        INSERT INTO undo_jobs VALUES('removed',1,'running');''')
    before = list(conn.iterdump())
    conn.execute('PRAGMA query_only=ON')
    data = opsview.queues(conn, ['a'], now=1000)
    assert data['moves'] == dict(available=True, count=2, oldest_age_s=900)
    assert data['training'] == dict(available=True, count=1, oldest_age_s=700)
    assert data['undo'] == dict(available=True, count=0, oldest_age_s=None)
    assert list(conn.iterdump()) == before
    assert opsview.queues(conn, [], now=1000)['moves']['count'] == 0


def test_missing_queue_and_invalid_timestamp_are_unknown_not_zero_age():
    conn = sqlite3.connect(':memory:')
    conn.executescript("CREATE TABLE pending_move(account TEXT,flag_at INTEGER);"
                       "INSERT INTO pending_move VALUES('a',100),('a',2000);")
    data = opsview.queues(conn, ['a'], now=1000)
    assert data['moves'] == dict(available=True, count=2, oldest_age_s=None)
    assert data['training'] == dict(available=False, count=None, oldest_age_s=None)


def test_ai_queue_reports_only_waiting_metadata_without_consuming_jobs(monkeypatch):
    import queue
    jobs = queue.Queue()
    jobs.put(SimpleNamespace(queued_at=100, raw='PRIVATE BODY', account='PRIVATE ACCOUNT'))
    jobs.put(SimpleNamespace(queued_at=400, raw='PRIVATE BODY 2', account='PRIVATE ACCOUNT 2'))
    monkeypatch.setattr(ai_verdict, '_QUEUE', jobs)
    data = ai_verdict.queue_status(now=1000)
    assert data == dict(count=2, oldest_age_s=900)
    assert 'PRIVATE' not in str(data)
    assert jobs.qsize() == 2
