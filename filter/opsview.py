"""Read-only operational facts for administrators; no probes or mail actions."""
import math
import sqlite3

HEALTH_MAX_AGE = 600


def _number(value):
    try:
        return (not isinstance(value, bool) and isinstance(value, (int, float))
                and math.isfinite(value))
    except (ValueError, OverflowError):
        return False


def antivirus(health, *, now):
    unknown = dict(state='unknown', signatures_age_s=None, observed_age_s=None)
    if not isinstance(health, dict) or not _number(health.get('ts')):
        return unknown
    elapsed = now - health['ts']
    if not 0 <= elapsed <= HEALTH_MAX_AGE:
        return unknown
    parts = health.get('parts')
    info = parts.get('clamav') if isinstance(parts, dict) else None
    if not isinstance(info, dict) or info.get('state') not in ('ok', 'off', 'waiting', 'down', 'stale'):
        return unknown
    age = info.get('db_age_s')
    age = age + elapsed if _number(age) and age >= 0 else None
    return dict(state=info['state'], signatures_age_s=age, observed_age_s=elapsed,
                intentionally_off=info['state'] == 'off' and info.get('reason') == 'SF_CLAMAV=0')


def queues(conn, accounts, *, now):
    """Counts/oldest age, scoped to configured accounts. Waiting is not failure.

    Oldest means time since enqueue, including intentional grace/pause. Never
    infer successful processing or signal an alert from queue length alone.
    Missing tables/invalid times stay unknown instead of looking like zero.
    """
    accounts = tuple(sorted(set(accounts)))
    out = {}
    for kind, table, stamp, condition in (
        ('moves', 'pending_move', 'flag_at', '1=1'),
        ('training', 'train_jobs', 'created_at', "status IN ('queued','running','cancel_requested')"),
        ('undo', 'undo_jobs', 'created_at', "status IN ('queued','running','cancel_requested')"),
    ):
        item = dict(available=False, count=None, oldest_age_s=None)
        try:
            # Exclude orphan/removed account data without exposing account IDs.
            marks = ','.join('?' for _ in accounts) or 'NULL'
            row = conn.execute(f'SELECT COUNT(*), MIN({stamp}), '
                               f'SUM(CASE WHEN {stamp} IS NULL OR {stamp}<=0 OR {stamp}>? THEN 1 ELSE 0 END) '
                               f'FROM {table} WHERE {condition} AND account IN ({marks})',
                               (now, *accounts)).fetchone()
            count, first, invalid = row
            item = dict(available=True, count=int(count), oldest_age_s=None)
            if count and not invalid and _number(first) and 0 < first <= now:
                item['oldest_age_s'] = now - first
        except (sqlite3.Error, AttributeError, TypeError, ValueError):
            pass
        out[kind] = item
    return out
