"""Local snapshots of the pure policy, without raw mail or learning I/O.

Replaying a snapshot reuses its captured sender rule and evidence. It does not
rescan content or reconstruct all surrounding IMAP, AI, campaign or ZAP guards.
"""
from dataclasses import asdict
import hashlib
import json
import math

import decisionpolicy

STAGES = ('scan', 'ai_policy', 'campaign_context', 'campaign_score', 'campaign_live')

SCHEMA = '''CREATE TABLE IF NOT EXISTS decision_traces (
 id INTEGER PRIMARY KEY, account TEXT NOT NULL, message_key TEXT NOT NULL,
 stage TEXT NOT NULL, created_at INTEGER NOT NULL, digest TEXT NOT NULL,
 snapshot TEXT NOT NULL, UNIQUE(account, message_key, stage, digest));
 CREATE INDEX IF NOT EXISTS idx_decision_traces_account ON decision_traces(account, stage, id);'''


def _get(row, key, default=None):
    try:
        return row[key] if row is not None else default
    except (KeyError, IndexError):
        return default


def inputs(prior, rule, score, names, *, threshold, from_header=True, auth=None,
           aged_unverified=False, threat=None):
    """Capture only fields consumed by the pure policy; detach mutable input."""
    return dict(prior=({k: _get(prior, k) for k in ('user_verdict', 'our_action')}
                       if prior is not None else None),
                rule=({k: _get(rule, k) for k in ('id', 'kind', 'pattern', 'force')}
                      if rule is not None else None),
                final=score, names=sorted(names), threshold=threshold,
                from_header=bool(from_header), auth=decisionpolicy.parse_sender_auth(auth),
                aged_unverified=bool(aged_unverified), threat=threat)


def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False)


def _result(decision):
    result = asdict(decision)
    result.pop('policy_input', None)
    return json.loads(_json(result))


def record(conn, account, key, stage, decision, now):
    evidence = getattr(decision, 'policy_input', None)
    if evidence is None:
        return None
    snapshot = _json(dict(schema_version=2 if 'profile' in evidence else 1,
                          inputs=evidence, result=_result(decision)))
    digest = hashlib.sha256(snapshot.encode()).hexdigest()
    conn.execute('INSERT OR IGNORE INTO decision_traces(account,message_key,stage,created_at,digest,snapshot) '
                 'VALUES(?,?,?,?,?,?)', (account, key, stage, int(now), digest, snapshot))
    return conn.execute('SELECT id FROM decision_traces WHERE account=? AND message_key=? AND stage=? AND digest=?',
                        (account, key, stage, digest)).fetchone()[0]


def replay(snapshot, *, threshold=None):
    data = json.loads(snapshot) if isinstance(snapshot, str) else snapshot
    if type(data.get('schema_version')) is not int or data['schema_version'] not in (1, 2):
        raise ValueError('Ukendt format for beslutningsspor.')
    evidence = dict(data['inputs'])
    if data['schema_version'] == 2:
        if threshold is not None:
            raise ValueError('Forsinkede spor kan gengives, men ikke afprøves med en ny grænse.')
        return _result(decisionpolicy.decide_deferred(evidence['profile'], evidence['facts']))
    if threshold is not None:
        evidence['threshold'] = threshold
    for name in ('final', 'threshold'):
        value = evidence[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError('Beslutningssporet indeholder ugyldige scorer.')
    evidence['names'] = frozenset(evidence['names'])
    return _result(decisionpolicy.decide(**evidence))


def preview(conn, account, *, threshold=None, limit=100, stage='scan'):
    if stage not in STAGES:
        raise ValueError('Ukendt beslutningsfase.')
    if stage != 'scan' and threshold is not None:
        raise ValueError('Forsinkede spor kan gengives, men ikke afprøves med en ny grænse.')
    if threshold is not None and (isinstance(threshold, bool) or not isinstance(threshold, (int, float))
                                  or not math.isfinite(threshold) or not 0 < threshold <= 100):
        raise ValueError('Prøvegrænsen skal være et endeligt tal over 0 og højst 100.')
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
        raise ValueError('Antal skal være mellem 1 og 200.')
    rows = conn.execute("SELECT id,created_at,snapshot,digest FROM decision_traces WHERE account=? AND stage=? "
                        "AND id IN (SELECT MAX(id) FROM decision_traces WHERE account=? AND stage=? "
                        'GROUP BY message_key) ORDER BY id DESC LIMIT ?', (account, stage, account, stage, limit)).fetchall()
    items = []
    for trace_id, created_at, snapshot, digest in rows:
        try:
            if hashlib.sha256(snapshot.encode()).hexdigest() != digest:
                raise ValueError('Beslutningssporet stemmer ikke med det gemte fingerprint.')
            original = json.loads(snapshot)['result']
            baseline = replay(snapshot)
            candidate = replay(snapshot, threshold=threshold)
            items.append(dict(trace_id=trace_id, created_at=created_at, valid=True,
                              baseline_matches_current_policy=baseline == original,
                              original_spam=original['spam'], candidate_spam=candidate['spam'],
                              original_reason=original['reason'], candidate_reason=candidate['reason'],
                              original_policy_version=original['policy_version'],
                              candidate_policy_version=candidate['policy_version'],
                              changed=any(original.get(k) != candidate.get(k)
                                          for k in ('spam', 'action', 'rule_hit', 'rule_id'))))
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
            items.append(dict(trace_id=trace_id, created_at=created_at, valid=False))
    return dict(account=account, stage=stage, scope='recorded_policy_inputs', threshold_override=threshold,
                sampled=len(items), changed=sum(bool(r.get('changed')) for r in items),
                invalid=sum(not r['valid'] for r in items), items=items, automatic_activation=False,
                warning=('Kun gemte første-scannings-input og deres daværende regler. ' if stage == 'scan' else
                         'Kun gemte input for den valgte beslutningsfase. ') +
                        'Ingen ny scanning, mailflytning eller træning. '
                        'Ikke samlet træfsikkerhed eller prøve på levende trafik.')
