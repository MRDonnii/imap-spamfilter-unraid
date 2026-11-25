"""Policy boundaries without a database, scanner, mail server or AI."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'filter'))
import decisionpolicy as policy


ALLOW = dict(id=7, kind='allow', pattern='@sender.example', force=0)
FORCE = dict(ALLOW, force=1)
BLOCK = dict(ALLOW, kind='block')
DKIM = dict(dkim=['sender.example'])
HOST = dict(host='mail.sender.example')
SPOOF = frozenset({'R_SPF_FAIL'})


@pytest.mark.parametrize('prior,rule,score,names,options,spam,reason', [
    (None, None, 7.9, frozenset(), {}, False, 'score'),
    (None, None, 8, frozenset(), {}, True, 'score'),
    (None, BLOCK, 0, frozenset(), {}, True, 'sender_block'),
    (None, ALLOW, 30, frozenset(), {}, False, 'sender_allow'),
    (None, ALLOW, 30, SPOOF, {}, True, 'allow_distrusted'),
    (None, ALLOW, 1, SPOOF, {}, False, 'allow_distrusted'),
    (None, ALLOW, 30, frozenset(), {'aged_unverified': True}, True, 'allow_distrusted'),
    (None, FORCE, 30, SPOOF, {'auth': DKIM}, False, 'verified_force_allow'),
    (None, FORCE, 30, SPOOF, {'auth': HOST}, False, 'verified_force_allow'),
    (None, FORCE, 30, SPOOF, {'auth': DKIM, 'from_header': False}, True, 'allow_distrusted'),
    (None, FORCE, 30, SPOOF, {}, True, 'allow_distrusted'),
    (None, FORCE, 30, frozenset(), {}, False, 'sender_allow'),
    (None, FORCE, 0, frozenset(), {'threat': 'virus', 'auth': DKIM}, True, 'virus'),
    (None, ALLOW, 0, frozenset(), {'threat': 'phish'}, True, 'threat'),
    (None, FORCE, 0, frozenset(), {'threat': 'phish', 'auth': HOST}, True, 'threat'),
    (None, FORCE, 30, SPOOF, {'threat': 'phish', 'auth': DKIM}, False, 'verified_threat_exception'),
    (None, BLOCK, 0, frozenset(), {'threat': 'phish', 'auth': DKIM}, True, 'sender_block'),
    (dict(user_verdict='spam', our_action='none'), None, 0, frozenset(), {}, True, 'user_spam'),
    (dict(user_verdict='spam', our_action='none'), ALLOW, 30, frozenset(), {}, False, 'sender_allow'),
    # Explicit releases already precede threat handling in 2.15.0. Refactoring
    # must not silently change that established owner/admin decision.
    (dict(user_verdict='ham', our_action='manual_release'), BLOCK, 30, SPOOF,
     {'threat': 'virus'}, False, 'sticky_ham'),
])
def test_policy_precedence(prior, rule, score, names, options, spam, reason):
    result = policy.decide(prior, rule, score, names, threshold=8, **options)
    assert result.spam is spam
    assert result.reason == reason
    assert result.policy_version == 1


def test_unverified_force_and_aged_evidence_are_retained_without_mutating_inputs():
    names = frozenset({'R_SPF_FAIL'})
    rule = dict(FORCE)
    result = policy.decide(None, rule, 30, names, threshold=8, aged_unverified=True)
    assert {s['n'] for s in result.symbols} == {'TH_FORCE_UNVERIFIED', 'TH_AGED_UNVERIFIED'}
    assert result.events == [('force_unverified', 'rule=7 @sender.example')]
    assert names == frozenset({'R_SPF_FAIL'}) and rule == FORCE


def test_decisions_do_not_share_mutable_evidence():
    first = policy.decide(None, None, 0, frozenset(), threshold=8)
    second = policy.decide(None, None, 0, frozenset(), threshold=8)
    first.symbols.append({'n': 'example'})
    assert not second.symbols
