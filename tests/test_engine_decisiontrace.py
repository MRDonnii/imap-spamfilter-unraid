"""Actual scan/pending-rule decisions keep reproducible local core evidence."""
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import setup_engine
from test_engine_scan import Harness
import decisiontrace


@pytest.fixture
def eng(tmp_path, monkeypatch):
    return setup_engine(tmp_path, monkeypatch)


def test_real_scan_has_a_reproducible_snapshot_without_mail_body(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode='move')
    h.deliver('sample@x', score=12, subject='PRIVATE SUBJECT', body='PRIVATE BODY')
    h.scan()
    row = h.db.conn.execute("SELECT snapshot FROM decision_traces WHERE account=? AND stage='scan'",
                            (h.acc.name,)).fetchone()
    data = json.loads(row[0])
    assert data['result']['spam'] and data['result']['reason'] == 'score'
    assert 'PRIVATE' not in row[0]
    assert decisiontrace.replay(row[0]) == data['result']
    preview = decisiontrace.preview(h.db.conn, h.acc.name, threshold=15)
    assert preview['changed'] == 1
    assert h.row('sample@x')['our_action'] == 'pending_move'


def test_rule_added_during_grace_is_a_separate_recorded_recheck(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode='move')
    h.deliver('sample@x', score=12, sender='sender@sample.example')
    h.scan()
    eng.add_sender_rule(h.db.conn, h.acc.name, 'sender@sample.example', 'allow')
    h.advance(61)
    h.moves()
    row = h.db.conn.execute("SELECT snapshot FROM decision_traces WHERE account=? AND stage='pending_allow_recheck'",
                            (h.acc.name,)).fetchone()
    assert row is not None
    data = json.loads(row[0])
    assert data['result']['reason'] == 'sender_allow' and not data['result']['spam']
    assert h.row('sample@x')['our_action'] == 'allowlisted'
    assert decisiontrace.replay(row[0]) == data['result']


def test_pruning_removes_orphan_traces_only_in_the_current_mailbox(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode='shadow')
    h.deliver('old@x', score=12)
    h.scan()
    other = eng.Db('other-account')
    try:
        with other.tx():
            other.upsert_message('other-key', 'INBOX', None, None)
            other.conn.execute("INSERT INTO decision_traces(account,message_key,stage,created_at,digest,snapshot) "
                               "SELECT 'other-account','other-key',stage,created_at,digest,snapshot "
                               "FROM decision_traces WHERE account=?", (h.acc.name,))
        with h.db.tx():
            h.db.conn.execute('UPDATE messages SET last_seen=0 WHERE account=?', (h.acc.name,))
            h.db.prune_messages(older_than_s=1)
        assert not h.db.conn.execute('SELECT 1 FROM decision_traces WHERE account=?', (h.acc.name,)).fetchone()
        assert other.conn.execute('SELECT COUNT(*) FROM decision_traces WHERE account=?',
                                  (other.account,)).fetchone()[0] == 1
    finally:
        other.close()


def test_trace_capture_failure_does_not_change_mail_decisions(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode='move')
    def broken(*args, **kwargs):
        raise ValueError('synthetic metadata failure')
    monkeypatch.setattr(decisiontrace, 'inputs', broken)
    h.deliver('sample@x', score=12)
    h.scan()
    assert h.row('sample@x')['our_action'] == 'pending_move'
    assert not h.db.conn.execute('SELECT 1 FROM decision_traces').fetchone()
