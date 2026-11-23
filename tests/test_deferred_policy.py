"""Deferred policy phases are pure, ordered and replayable without I/O."""
import json
import sqlite3

import pytest

from test_decisionpolicy import policy
import decisiontrace

AI = dict(mode='on', account_mode='move', late=False, present=True, user_verdict=None,
          action='none', threat=None, folder_matches=True, contact=False,
          namespoof=False, has_ai=False, final=9.0, threshold=8.0, original_threshold=8.0)
CONTEXT = dict(present=True, source_active=True, user_verdict=None, sticky_ham=False,
               action='none', mode='move', folder_matches=True, old=False,
               trusted=False, allowed=False, own_sender=False, protected_allow=False)
SCORE = dict(score=6.5, threshold=8.0, margin=2.0, consensus=False,
             mode='move', hourly_used=0, hourly_limit=50)
LIVE = dict(matches=1, where='indbakken', flagged=False, deleted=False, seen=False, old=False, mode='move')


@pytest.mark.parametrize('changes,action', [
    ({}, 'pending_move'), ({'threshold': 12}, 'points'),
    ({'original_threshold': 12}, 'points'),
    ({'mode': 'shadow', 'present': False}, 'skipped:off'),
    ({'account_mode': 'shadow', 'late': True}, 'skipped:account_mode'),
    ({'late': True, 'present': False}, 'skipped:late'),
    ({'present': False}, 'skipped:gone'), ({'user_verdict': 'ham', 'threat': 'virus'}, 'skipped:decided'),
    ({'action': 'manual_release'}, 'skipped:decided'), ({'threat': 'virus'}, 'skipped:threat'),
    ({'folder_matches': False}, 'skipped:moved'), ({'contact': True, 'namespoof': True}, 'skipped:contact'),
    ({'namespoof': True, 'has_ai': True}, 'skipped:namespoof'), ({'has_ai': True}, 'skipped:done'),
])
def test_ai_precedence_and_original_floor(changes, action):
    decision = policy.decide_deferred('ai', dict(AI, **changes))
    assert decision.action == action
    assert decision.spam == (action == 'pending_move')


@pytest.mark.parametrize('changes,reason', [
    ({'present': False, 'source_active': False}, 'campaign_unknown'),
    ({'source_active': False, 'user_verdict': 'ham'}, 'campaign_source'),
    ({'user_verdict': 'spam', 'action': 'moved_to_junk'}, 'campaign_user'),
    ({'sticky_ham': True}, 'campaign_user'),
    ({'action': 'manual_release', 'folder_matches': False}, 'campaign_changed'),
    ({'folder_matches': False, 'old': True}, 'campaign_folder'),
    ({'old': True, 'trusted': True}, 'campaign_old'),
    ({'trusted': True, 'allowed': True}, 'campaign_contact'),
    ({'allowed': True, 'own_sender': True}, 'campaign_allow'),
    ({'own_sender': True, 'protected_allow': True}, 'campaign_own'),
    ({'protected_allow': True}, 'campaign_protected'),
])
def test_campaign_context_guards_precede_score_consensus(changes, reason):
    decision = policy.decide_deferred('campaign_context', dict(CONTEXT, **changes))
    assert not decision.spam and decision.reason == reason


@pytest.mark.parametrize('changes,action', [
    ({}, 'eligible'), ({'score': 6}, 'eligible'), ({'score': 5.9}, 'skipped'),
    ({'score': None}, 'skipped'), ({'score': 0, 'consensus': True}, 'eligible'),
    ({'threshold': 15}, 'skipped'), ({'hourly_used': 50}, 'deferred'),
    ({'hourly_used': 50, 'mode': 'shadow'}, 'eligible'),
    ({'score': 0, 'hourly_used': 50}, 'skipped'),
])
def test_campaign_floor_consensus_and_rate(changes, action):
    assert policy.decide_deferred('campaign_score', dict(SCORE, **changes)).action == action


@pytest.mark.parametrize('changes,action,reason', [
    ({}, 'move', 'campaign_live_move'), ({'mode': 'flag'}, 'flag', 'campaign_live_flag'),
    ({'mode': 'shadow'}, 'shadow', 'campaign_live_shadow'),
    ({'matches': 0, 'seen': True}, 'skipped', 'campaign_missing'),
    ({'matches': 2}, 'skipped', 'campaign_ambiguous'),
    ({'flagged': True, 'seen': True}, 'skipped', 'campaign_flagged'),
    ({'deleted': True, 'seen': True}, 'skipped', 'campaign_deleted'),
    ({'seen': True}, 'skipped', 'campaign_read'), ({'old': True}, 'skipped', 'campaign_old'),
])
def test_live_mailbox_safety_always_wins(changes, action, reason):
    decision = policy.decide_deferred('campaign_live', dict(LIVE, **changes))
    assert (decision.action, decision.reason) == (action, reason)


@pytest.mark.parametrize('profile,facts', [('ai', AI), ('campaign_context', CONTEXT),
                                           ('campaign_score', SCORE), ('campaign_live', LIVE)])
def test_deferred_trace_round_trip_is_scoped_and_cannot_activate_or_guess_a_new_threshold(profile, facts):
    conn = sqlite3.connect(':memory:')
    conn.executescript(decisiontrace.SCHEMA)
    decision = policy.decide_deferred(profile, facts)
    ident = decisiontrace.record(conn, 'a', 'private-key', profile, decision, 1000)
    snapshot = conn.execute('SELECT snapshot FROM decision_traces WHERE id=? AND account=?', (ident, 'a')).fetchone()[0]
    assert json.loads(snapshot)['schema_version'] == 2
    assert decisiontrace.replay(snapshot) == json.loads(snapshot)['result']
    assert not conn.execute('SELECT 1 FROM decision_traces WHERE account=?', ('b',)).fetchone()
    with pytest.raises(ValueError, match='ny grænse'):
        decisiontrace.replay(snapshot, threshold=99)
