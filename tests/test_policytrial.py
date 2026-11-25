"""A shadow candidate must never change the active decision or IMAP actions."""
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import setup_engine, stub_mailctx
from test_engine_scan import Harness
import policytrial


@pytest.fixture
def eng(tmp_path, monkeypatch):
    return setup_engine(tmp_path, monkeypatch)


def test_shadow_more_restrictive_candidate_does_not_move_or_learn(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode='move')
    trial_id = policytrial.start(h.db.conn, h.acc.name, 1, int(h.t))
    assert policytrial.start(h.db.conn, h.acc.name, 1, int(h.t)) == trial_id
    h.deliver('candidate-only@x', score=4)
    h.scan()
    original_score = h.row('candidate-only@x')['our_score']
    h.advance(100)
    h.moves()
    assert h.row('candidate-only@x')['our_action'] == 'none'
    assert h.row('candidate-only@x')['our_score'] == original_score
    assert not h.rspamd.learn_calls
    assert not h.client.msgids('Junk')
    report = policytrial.status(h.db.conn, h.acc.name)
    assert report['trial']['observed'] == report['trial']['more_restrictive'] == 1
    assert not report['automatic_activation']
    assert 'candidate-only@x' not in json.dumps(report)
    assert policytrial.status(h.db.conn, 'other-account')['trial'] is None


def test_candidate_cannot_relax_virus_or_explicit_block(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode='shadow')
    policytrial.start(h.db.conn, h.acc.name, 100, int(h.t))
    eng.add_sender_rule(h.db.conn, h.acc.name, 'blocked@sample.example', 'block')
    h.deliver('blocked@x', score=1, sender='blocked@sample.example')
    h.deliver('virus@x', score=0)
    h.rspamd.symbols['virus@x'] = {'CLAM_VIRUS': {'name': 'CLAM_VIRUS', 'score': 0, 'options': ['Neutral.Test']}}
    h.scan()
    report = policytrial.status(h.db.conn, h.acc.name)['trial']
    assert report['observed'] == report['unchanged'] == 2
    assert h.row('virus@x')['threat'] == 'virus'
    assert h.row('blocked@x')['our_action'] == 'shadow_spam'


def test_candidate_preserves_the_protected_recipient_floor(eng, monkeypatch):
    monkeypatch.setattr(eng, '_mailctx', lambda: stub_mailctx(recipients=['orders@sample.example']))
    h = Harness(eng, monkeypatch, mode='move', protected_recipients=['orders@sample.example'], protected_threshold=18)
    policytrial.start(h.db.conn, h.acc.name, 1, int(h.t))
    h.deliver('order@x', score=12)
    h.scan()
    row = h.db.conn.execute('SELECT candidate_threshold,candidate_spam FROM policy_trial_results').fetchone()
    assert row['candidate_threshold'] == 18 and not row['candidate_spam']
    assert h.row('order@x')['our_action'] == 'none'


def test_start_change_stop_keeps_histories_separate(eng, monkeypatch):
    h = Harness(eng, monkeypatch)
    first = policytrial.start(h.db.conn, h.acc.name, 1, int(h.t))
    second = policytrial.start(h.db.conn, h.acc.name, 12, int(h.t)+1)
    assert second != first
    assert h.db.conn.execute('SELECT status FROM policy_trials WHERE id=?', (first,)).fetchone()[0] == 'stopped'
    assert policytrial.stop(h.db.conn, h.acc.name, int(h.t)+2) == 1
    h.deliver('not-observed@x', score=4)
    h.scan()
    assert policytrial.status(h.db.conn, h.acc.name)['trial']['observed'] == 0
    assert policytrial.status(h.db.conn, h.acc.name)['trial']['status'] == 'stopped'


def test_trial_recording_failure_cannot_change_the_active_mail_decision(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode='move')
    policytrial.start(h.db.conn, h.acc.name, 1, int(h.t))
    def broken(*args, **kw):
        raise ValueError('synthetic trial metadata failure')
    monkeypatch.setattr(policytrial, 'observe', broken)
    h.deliver('kept@x', score=4)
    h.scan()
    assert h.row('kept@x')['our_action'] == 'none'
    assert policytrial.status(h.db.conn, h.acc.name)['trial']['observed'] == 0


@pytest.mark.parametrize('threshold', [0, -1, 101, True, float('nan'), float('inf')])
def test_invalid_candidate_is_refused_before_changing_a_trial(eng, threshold):
    db = eng.Db('sample')
    try:
        with pytest.raises(ValueError):
            policytrial.start(db.conn, 'sample', threshold, 1)
        assert policytrial.status(db.conn, 'sample')['trial'] is None
    finally:
        db.close()
