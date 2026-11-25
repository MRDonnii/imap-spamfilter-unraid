"""Reproduce core decisions from bounded, account-scoped local evidence."""
import json
from pathlib import Path
import sqlite3
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'filter'))
import decisionpolicy
import decisiontrace


@pytest.fixture
def conn():
    conn = sqlite3.connect(':memory:')
    conn.executescript(decisiontrace.SCHEMA)
    yield conn
    conn.close()


def decision(score=10, *, rule=None, names=frozenset(), threat=None):
    inputs = decisiontrace.inputs(None, rule, score, names, threshold=8, threat=threat)
    result = decisionpolicy.decide(**dict(inputs, names=frozenset(inputs['names'])))
    result.policy_input = inputs
    return result


def test_identical_snapshots_deduplicate_per_mailbox_and_stage(conn):
    first = decisiontrace.record(conn, 'a', 'private-mail-id', 'scan', decision(), 1)
    assert decisiontrace.record(conn, 'a', 'private-mail-id', 'scan', decision(), 2) == first
    second = decisiontrace.record(conn, 'b', 'private-mail-id', 'scan', decision(), 3)
    assert second != first
    assert conn.execute('SELECT COUNT(*) FROM decision_traces').fetchone()[0] == 2
    preview = decisiontrace.preview(conn, 'a', threshold=12)
    assert preview['sampled'] == preview['changed'] == 1
    assert preview['items'][0]['baseline_matches_current_policy']
    assert not preview['items'][0]['candidate_spam']
    assert 'private-mail-id' not in json.dumps(preview)
    assert not preview['automatic_activation']


def test_threshold_preview_keeps_threat_and_block_priorities(conn):
    decisiontrace.record(conn, 'a', 'virus', 'scan', decision(threat='virus'), 1)
    decisiontrace.record(conn, 'a', 'blocked', 'scan', decision(rule=dict(id=1, kind='block', pattern='@x', force=0)), 2)
    result = decisiontrace.preview(conn, 'a', threshold=100)
    assert result['changed'] == 0
    assert all(r['candidate_spam'] for r in result['items'])


def test_complete_evidence_beyond_ui_symbols_replays_distrusted_allow(conn):
    names = frozenset([f'EXAMPLE_{n}' for n in range(100)] + ['R_SPF_FAIL'])
    result = decision(rule=dict(id=1, kind='allow', pattern='@sender.example', force=0), names=names)
    decisiontrace.record(conn, 'a', 'one', 'scan', result, 1)
    snapshot = conn.execute('SELECT snapshot FROM decision_traces').fetchone()[0]
    assert len(json.loads(snapshot)['inputs']['names']) == 101
    assert decisiontrace.replay(snapshot)['reason'] == 'allow_distrusted'


def test_recorded_inputs_are_detached_and_exclude_unconsumed_fields():
    prior = dict(user_verdict='ham', our_action='manual_release', subject='PRIVATE SUBJECT')
    auth = dict(dkim=['sender.example'])
    inputs = decisiontrace.inputs(prior, None, 1, frozenset(), threshold=8, auth=auth)
    prior['user_verdict'] = 'spam'
    auth['dkim'].append('other.example')
    assert inputs['prior']['user_verdict'] == 'ham'
    assert inputs['auth']['dkim'] == ['sender.example']
    assert 'PRIVATE SUBJECT' not in json.dumps(inputs)


def test_preview_uses_latest_scan_per_message_and_reports_corrupt_evidence(conn):
    decisiontrace.record(conn, 'a', 'one', 'scan', decision(10), 1)
    newest = decisiontrace.record(conn, 'a', 'one', 'scan', decision(1), 2)
    decisiontrace.record(conn, 'a', 'one', 'pending_move', decision(12), 3)
    decisiontrace.record(conn, 'b', 'secret', 'scan', decision(20), 4)
    assert decisiontrace.preview(conn, 'a')['sampled'] == 1
    assert decisiontrace.preview(conn, 'a')['items'][0]['trace_id'] == newest
    conn.execute('UPDATE decision_traces SET snapshot=? WHERE id=?', ('not JSON', newest))
    assert decisiontrace.preview(conn, 'a')['invalid'] == 1


@pytest.mark.parametrize('options', [dict(threshold=float('nan')), dict(threshold=True),
                                   dict(threshold=0), dict(limit=201), dict(limit=False)])
def test_preview_rejects_invalid_parameters(conn, options):
    with pytest.raises(ValueError):
        decisiontrace.preview(conn, 'a', **options)
