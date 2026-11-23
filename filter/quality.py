"""Read-only coverage and holdout evaluation. Never trains or contacts IMAP.

Coverage is event counts, not a percentage of all delivered mail: read mail,
provider junk and rescans do not share a reliable delivery denominator.
Evaluation reports ONLY the supplied, human-labelled sample, per mailbox.
"""
import json
import math
from collections import defaultdict

METRICS = {'scanned': 'Scannet', 'skipped_seen': 'Læst før første kontrol',
           'skipped_oversize': 'For stor', 'scan_failed': 'Fejlede scanningsforsøg',
           'scan_giveup': 'Scanning opgivet'}
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
