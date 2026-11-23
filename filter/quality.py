"""Read-only coverage and holdout evaluation. Never trains or contacts IMAP.

Coverage is event counts, not a percentage of all delivered mail: read mail,
provider junk and rescans do not share a reliable delivery denominator.
Evaluation reports ONLY the supplied, human-labelled sample, per mailbox.
"""
import hashlib
import json
import math
from collections import defaultdict

METRICS = {'scanned': 'Scannet', 'skipped_seen': 'Læst før første kontrol',
           'skipped_oversize': 'For stor', 'scan_failed': 'Fejlede scanningsforsøg',
           'scan_giveup': 'Scanning opgivet',
           'junk_identity_unverified': 'Mappeindhold ikke bekræftet'}
SCHEMA = '''CREATE TABLE IF NOT EXISTS scan_observations (
 account TEXT NOT NULL, message_key TEXT NOT NULL, score REAL NOT NULL,
 threshold REAL NOT NULL, prediction TEXT NOT NULL, version TEXT NOT NULL,
 scanned_at INTEGER NOT NULL, PRIMARY KEY(account, message_key));'''


def observe(conn, account, key, score, threshold, spam, version, now):
    conn.execute('INSERT OR IGNORE INTO scan_observations VALUES(?,?,?,?,?,?,?)',
                 (account, key, score, threshold, 'spam' if spam else 'ham', version, now))


def coverage(conn, accounts, since):
    """Explicit account allowlist and inclusive local calendar day; no total %."""
    result = []
    for account in sorted(set(accounts)):
        counts = {m: 0 for m in METRICS}
        for metric, n in conn.execute('SELECT metric, SUM(n) FROM stats_daily WHERE account=? '
                                     'AND day>=? GROUP BY metric', (account, since)):
            if metric in counts:
                counts[metric] = int(n or 0)
        result.append({'account': account, 'since': since, 'counts': counts,
                       'has_observations': bool(sum(counts.values()))})
    return result


def export_sample(conn, accounts):
    """Metadata only; labels are explicit user judgements, never auto-learns.

    A convenience sample with selection bias, not an unbiased accuracy claim.
    Export remains local: Message-IDs/account IDs can identify people.
    """
    for account in sorted(set(accounts)):
        rows = conn.execute('SELECT o.*, m.user_verdict FROM scan_observations o '
                            'JOIN messages m ON m.account=o.account AND m.message_id=o.message_key '
                            "WHERE o.account=? AND m.user_verdict IN ('spam','ham')", (account,))
        for r in rows:
            yield dict(account=account, id=r['message_key'], split='holdout',
                       label=r['user_verdict'], prediction=r['prediction'], score=r['score'],
                       threshold=r['threshold'], version=r['version'],
                       basis='first_scan_before_ai', selection='explicit_user_judgements')


def evaluate(rows):
    groups = defaultdict(lambda: {'tp': 0, 'tn': 0, 'fp': 0, 'fn': 0, 'versions': set()})
    seen = set()
    holdout = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('Hver linje skal være et JSON-objekt.')
        account, mid = row.get('account'), row.get('id')
        if not isinstance(account, str) or not account or not isinstance(mid, str) or not mid:
            raise ValueError('account og id skal være udfyldt.')
        identity = (account, mid)
        if identity in seen:
            raise ValueError('Samme mail forekommer flere gange; træning og holdout må ikke overlappe.')
        seen.add(identity)
        if row.get('split') not in ('train', 'holdout') or row.get('label') not in ('ham', 'spam'):
            raise ValueError('Angiv split=train|holdout og label=ham|spam.')
        if row['split'] == 'train':
            continue
        score, threshold = row.get('score'), row.get('threshold')
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v)
               for v in (score, threshold)):
            raise ValueError('score og threshold skal være endelige tal.')
        prediction = row.get('prediction', 'spam' if score >= threshold else 'ham')
        if prediction not in ('ham', 'spam'):
            raise ValueError('prediction skal være ham eller spam.')
        holdout.append((account, row, prediction))
    for account, row, prediction in holdout:
        g = groups[account]
        g['versions'].add(str(row.get('version') or 'ukendt'))
        g[('tp' if row['label'] == 'spam' else 'fp') if prediction == 'spam'
          else ('fn' if row['label'] == 'spam' else 'tn')] += 1
    result = []
    for account, g in sorted(groups.items()):
        tp, tn, fp, fn = (g[k] for k in ('tp', 'tn', 'fp', 'fn'))
        result.append(dict(account=account, sample_size=tp+tn+fp+fn, tp=tp, tn=tn, fp=fp, fn=fn,
                           precision=tp/(tp+fp) if tp+fp else None,
                           recall=tp/(tp+fn) if tp+fn else None,
                           false_positive_rate=fp/(fp+tn) if fp+tn else None,
                           false_negative_rate=fn/(fn+tp) if fn+tp else None,
                           versions=sorted(g['versions']),
                           warning='Menneskeligt mærket prøveudvalg; ikke dokumenteret samlet træfsikkerhed.'))
    return {'basis': 'holdout_only', 'accounts': result, 'holdout_size': len(holdout),
            'warning': 'Ingen træning udført. AI-confidence er ikke målt korrekthed.'}


def read_dataset(path):
    if path.stat().st_size > 10 * 1024 * 1024:
        raise ValueError('Datasættet må højst være 10 MiB.')
    with path.open() as f:
        return [json.loads(line) for line in f if line.strip()]


def _digest(rows):
    """Stable evidence identifier; never include mail IDs in a comparison report."""
    return hashlib.sha256(json.dumps(rows, sort_keys=True, ensure_ascii=True,
                                     separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def compare(baseline, candidate, *, false_positive_cost=10, min_per_class=20):
    """Compare paired, human-labelled predictions. No training or activation.

    A gate is descriptive of this sample only, never deployment approval.
    The minimum is a configurable operational floor, not statistical power.
    Unknown training provenance and correction bias remain explicit limitations.
    """
    if (isinstance(false_positive_cost, bool) or not isinstance(false_positive_cost, int)
            or not 1 <= false_positive_cost <= 1_000_000):
        raise ValueError('Prisen for en falsk positiv skal være et heltal fra 1 til 1000000.')
    if (isinstance(min_per_class, bool) or not isinstance(min_per_class, int)
            or not 1 <= min_per_class <= 1_000_000):
        raise ValueError('Mindste antal pr. klasse skal være et heltal fra 1 til 1000000.')
    baseline, candidate = list(baseline), list(candidate)
    # Reuse all input checks, including duplicate train/holdout identities.
    before, after = evaluate(baseline), evaluate(candidate)
    left = {(r['account'], r['id']): r for r in baseline}
    right = {(r['account'], r['id']): r for r in candidate}
    if left.keys() != right.keys():
        raise ValueError('Baseline og kandidat skal indeholde præcis de samme konto/ID-par.')
    cohort, evidence = [], [[], []]
    transitions = defaultdict(lambda: dict(new_false_positives=0, fixed_false_positives=0,
                                          new_false_negatives=0, fixed_false_negatives=0))
    for key in sorted(left):
        a, b = left[key], right[key]
        for field in ('label', 'split', 'basis', 'selection'):
            if a.get(field) != b.get(field):
                raise ValueError(f'Baseline og kandidat har forskelligt {field}; sammenligningen afvises.')
        if a['split'] == 'train':
            continue
        cohort.append([*key, a['label'], a.get('basis'), a.get('selection')])
        predictions = []
        for index, r in enumerate((a, b)):
            prediction = r.get('prediction', 'spam' if r['score'] >= r['threshold'] else 'ham')
            predictions.append(prediction)
            evidence[index].append([*key, prediction, float(r['score']), float(r['threshold']),
                                    str(r.get('version') or 'ukendt')])
        previous, current = predictions
        t = transitions[key[0]]
        if previous != current:
            if a['label'] == 'ham':
                t['new_false_positives' if current == 'spam' else 'fixed_false_positives'] += 1
            else:
                t['new_false_negatives' if current == 'ham' else 'fixed_false_negatives'] += 1
    before_accounts = {g['account']: g for g in before['accounts']}
    accounts = []
    for current in after['accounts']:
        account = current['account']
        previous, t = before_accounts[account], transitions[account]
        ham, spam = current['tn'] + current['fp'], current['tp'] + current['fn']
        enough = ham >= min_per_class and spam >= min_per_class
        regression = bool(t['new_false_positives'] or current['fn'] > previous['fn'])
        old_cost = previous['fp'] * false_positive_cost + previous['fn']
        new_cost = current['fp'] * false_positive_cost + current['fn']
        accounts.append(dict(account=account, baseline=previous, candidate=current,
                             changes=t, ham_size=ham, spam_size=spam,
                             sufficient_sample=enough, baseline_cost=old_cost,
                             candidate_cost=new_cost, cost_delta=new_cost-old_cost,
                             status=('regression_in_sample' if regression else
                                     'no_regression_in_sample' if enough else 'insufficient_sample')))
    statuses = {g['status'] for g in accounts}
    status = ('regression_in_sample' if 'regression_in_sample' in statuses else
              'insufficient_sample' if not accounts or 'insufficient_sample' in statuses else
              'no_regression_in_sample')
    return dict(schema_version=1, basis='paired_holdout_only', status=status,
                holdout_size=len(cohort), cohort_sha256=_digest(cohort),
                baseline_sha256=_digest(evidence[0]), candidate_sha256=_digest(evidence[1]),
                false_positive_cost=false_positive_cost, false_negative_cost=1,
                min_per_class=min_per_class, accounts=accounts, automatic_activation=False,
                warning='Kun det leverede prøveudvalg. Ingen dokumentation for samlet træfsikkerhed, '
                        'uafhængigt holdout eller fravær af træningslækage. Ingen træning eller aktivering.')
