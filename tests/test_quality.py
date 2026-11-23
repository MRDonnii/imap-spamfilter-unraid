import json
import sqlite3
from pathlib import Path
import pytest
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "filter"))
import quality


def row(mid, label, score, **kw):
    return dict(account='mailbox-a', id=mid, split='holdout', label=label, score=score, threshold=8, **kw)


def test_confusion_matrix_and_train_exclusion():
    rows = [row('tp', 'spam', 10), row('fp', 'ham', 10), row('tn', 'ham', 2), row('fn', 'spam', 2)]
    rows += [dict(row('train', 'spam', 10), split='train')]
    result = quality.evaluate(rows)
    g = result['accounts'][0]
    assert result['holdout_size'] == 4
    assert (g['tp'], g['tn'], g['fp'], g['fn']) == (1, 1, 1, 1)
    assert g['precision'] == g['recall'] == g['false_positive_rate'] == .5
    assert quality.evaluate(list(reversed(rows))) == result


def test_separate_accounts_and_no_imaginary_denominators():
    rows = [row('one', 'ham', 1), dict(row('two', 'spam', 10), account='mailbox-b')]
    results = quality.evaluate(rows)['accounts']
    assert results[0]['recall'] is None and results[1]['false_positive_rate'] is None
    assert all(r['sample_size'] == 1 for r in results)


@pytest.mark.parametrize('mutate', [lambda r: dict(r, score=float('nan')), lambda r: dict(r, threshold=float('inf')),
                                   lambda r: dict(r, label='unsure'), lambda r: dict(r, score=True)])
def test_invalid_samples_refused(mutate):
    with pytest.raises(ValueError):
        quality.evaluate([mutate(row('one', 'ham', 1))])


def test_holdout_overlap_refused():
    with pytest.raises(ValueError, match='overlappe'):
        quality.evaluate([row('same', 'ham', 1), dict(row('same', 'ham', 1), split='train')])


def test_prediction_includes_rules_and_is_not_replaced_by_raw_score():
    result = quality.evaluate([row('allowed', 'ham', 20, prediction='ham')])
    assert result['accounts'][0]['tn'] == 1


def test_coverage_account_scope_and_period():
    conn = sqlite3.connect(':memory:')
    try:
        conn.execute('CREATE TABLE stats_daily(account TEXT, day TEXT, metric TEXT, n INTEGER)')
        conn.executemany('INSERT INTO stats_daily VALUES(?,?,?,?)', [('a','2026-11-23','scanned',3),
           ('b','2026-11-23','scanned',999), ('a','2026-01-01','scanned',999), ('a','2026-11-23','scan_failed',2)])
        r = quality.coverage(conn, ['a'], '2026-11-10')
        assert len(r) == 1 and r[0]['counts']['scanned'] == 3
        assert r[0]['counts']['scan_failed'] == 2
        assert 'percent' not in r[0]
    finally:
        conn.close()


def test_export_is_scoped_metadata_and_preserves_first_observation():
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(quality.SCHEMA)
        conn.execute('CREATE TABLE messages(account TEXT, message_id TEXT, user_verdict TEXT, subject TEXT)')
        conn.executemany('INSERT INTO messages VALUES(?,?,?,?)',
                         [('a', 'one', 'ham', 'PRIVATE SUBJECT'), ('b', 'two', 'spam', 'SECRET')])
        quality.observe(conn, 'a', 'one', 10, 8, True, 'original', 1)
        quality.observe(conn, 'a', 'one', 1, 8, False, 'later-ai', 2)
        quality.observe(conn, 'b', 'two', 10, 8, True, 'original', 1)
        rows = list(quality.export_sample(conn, ['a']))
        assert len(rows) == 1 and rows[0]['account'] == 'a'
        assert rows[0]['score'] == 10 and rows[0]['version'] == 'original'
        assert rows[0]['label'] == 'ham' and rows[0]['prediction'] == 'spam'
        assert 'subject' not in rows[0] and 'PRIVATE' not in json.dumps(rows)
        assert quality.evaluate(rows)['accounts'][0]['fp'] == 1
    finally:
        conn.close()
