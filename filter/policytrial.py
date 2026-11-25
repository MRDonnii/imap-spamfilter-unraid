"""Per-account shadow thresholds over the SAME pre-AI policy evidence.

Records logical differences only. No IMAP, learning, notifications, live rule
changes or activation path. A trial must never mutate the active decision.
"""
from contextlib import contextmanager
import math

import decisionpolicy

SCHEMA = '''CREATE TABLE IF NOT EXISTS policy_trials (
 id INTEGER PRIMARY KEY, account TEXT NOT NULL, candidate_threshold REAL NOT NULL,
 status TEXT NOT NULL, created_at INTEGER NOT NULL, closed_at INTEGER);
 CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_trial_active ON policy_trials(account) WHERE status='shadow';
 CREATE TABLE IF NOT EXISTS policy_trial_results (
 trial_id INTEGER NOT NULL, account TEXT NOT NULL, message_key TEXT NOT NULL,
 baseline_spam INTEGER NOT NULL, candidate_spam INTEGER NOT NULL,
 baseline_reason TEXT NOT NULL, candidate_reason TEXT NOT NULL,
 score REAL NOT NULL, baseline_threshold REAL NOT NULL, candidate_threshold REAL NOT NULL,
 filter_version TEXT NOT NULL, policy_version INTEGER NOT NULL, created_at INTEGER NOT NULL,
 PRIMARY KEY(trial_id,account,message_key));'''


@contextmanager
def _edit(conn):
    conn.execute('SAVEPOINT policy_trial_edit')
    try:
        yield
        conn.execute('RELEASE policy_trial_edit')
    except BaseException:
        conn.execute('ROLLBACK TO policy_trial_edit')
        conn.execute('RELEASE policy_trial_edit')
        raise


def start(conn, account, threshold, now):
    if (isinstance(threshold, bool) or not isinstance(threshold, (int, float))
            or not math.isfinite(threshold) or not 0 < threshold <= 100):
        raise ValueError('Kandidatgrænsen skal være et endeligt tal over 0 og højst 100.')
    with _edit(conn):
        active = conn.execute("SELECT id,candidate_threshold FROM policy_trials WHERE account=? AND status='shadow'",
                              (account,)).fetchone()
        if active and active[1] == threshold:
            return active[0]
        conn.execute("UPDATE policy_trials SET status='stopped',closed_at=? WHERE account=? AND status='shadow'",
                     (int(now), account))
        cur = conn.execute('INSERT INTO policy_trials(account,candidate_threshold,status,created_at) '
                           "VALUES(?,?,'shadow',?)", (account, threshold, int(now)))
        return cur.lastrowid


def stop(conn, account, now):
    with _edit(conn):
        return conn.execute("UPDATE policy_trials SET status='stopped',closed_at=? WHERE account=? AND status='shadow'",
                            (int(now), account)).rowcount


def observe(conn, account, key, decision, *, protected_threshold, version, now):
    evidence = getattr(decision, 'policy_input', None)
    if evidence is None:
        return False
    trial = conn.execute("SELECT id,candidate_threshold FROM policy_trials WHERE account=? AND status='shadow'",
                         (account,)).fetchone()
    if trial is None:
        return False
    inputs = dict(evidence)
    inputs['names'] = frozenset(inputs['names'])
    threshold = float(trial[1])
    if 'TH_PROTECTED_RCPT' in inputs['names']:
        threshold = max(threshold, float(protected_threshold))
    inputs['threshold'] = threshold
    candidate = decisionpolicy.decide(**inputs)
    conn.execute('INSERT OR IGNORE INTO policy_trial_results VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                 (trial[0], account, key, int(decision.spam), int(candidate.spam),
                  decision.reason, candidate.reason, inputs['final'], evidence['threshold'], threshold,
                  version, decision.policy_version, int(now)))
    return True


def status(conn, account):
    trial = conn.execute('SELECT id,candidate_threshold,status,created_at,closed_at FROM policy_trials '
                         'WHERE account=? ORDER BY id DESC LIMIT 1', (account,)).fetchone()
    result = dict(account=account, trial=None, automatic_activation=False,
                  warning='Kun beholdte første-scanningsobservationer før AI. Ingen menneskelig facitkontrol '
                          'eller samlet træfsikkerhed. Prøven ændrer ingen mail eller aktive regler.')
    if trial is None:
        return result
    total, more, less = conn.execute('SELECT COUNT(*),COALESCE(SUM(candidate_spam=1 AND baseline_spam=0),0),'
                                     'COALESCE(SUM(candidate_spam=0 AND baseline_spam=1),0) '
                                     'FROM policy_trial_results WHERE trial_id=? AND account=?',
                                     (trial[0], account)).fetchone()
    versions = [dict(filter_version=v, policy_version=p, observed=n) for v, p, n in conn.execute(
        'SELECT filter_version,policy_version,COUNT(*) FROM policy_trial_results WHERE trial_id=? AND account=? '
        'GROUP BY filter_version,policy_version ORDER BY filter_version,policy_version', (trial[0], account))]
    result['trial'] = dict(id=trial[0], candidate_threshold=trial[1], status=trial[2], created_at=trial[3],
                           closed_at=trial[4], observed=total, more_restrictive=more, less_restrictive=less,
                           unchanged=total-more-less, versions=versions)
    return result
