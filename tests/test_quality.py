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


def test_paired_comparison_keeps_mailboxes_separate_and_detects_new_false_positive():
    baseline = [row('private-id-a', 'ham', 1), row('spam-a', 'spam', 10),
                dict(row('ham-b', 'ham', 10), account='mailbox-b'),
                dict(row('spam-b', 'spam', 1), account='mailbox-b')]
    candidate = [dict(r, score=10) if r['id'] == 'private-id-a' else
                 dict(r, score=1) if r['id'] == 'ham-b' else
                 dict(r, score=10) if r['id'] == 'spam-b' else dict(r) for r in baseline]
    result = quality.compare(baseline, candidate, min_per_class=1)
    a, b = result['accounts']
    assert result['status'] == a['status'] == 'regression_in_sample'
    assert b['status'] == 'no_regression_in_sample'
    assert a['cost_delta'] == 10 and b['cost_delta'] == -11
    assert a['changes']['new_false_positives'] == 1
    assert b['changes']['fixed_false_positives'] == b['changes']['fixed_false_negatives'] == 1
    assert result['automatic_activation'] is False
    assert 'private-id-a' not in json.dumps(result)
    assert quality.compare(baseline[::-1], candidate[::-1], min_per_class=1) == result


def test_same_error_count_cannot_hide_a_new_false_positive():
    baseline = [row('old-fp', 'ham', 10), row('new-fp', 'ham', 1)]
    candidate = [dict(baseline[0], score=1), dict(baseline[1], score=10)]
    result = quality.compare(baseline, candidate, min_per_class=1)
    account = result['accounts'][0]
    assert account['cost_delta'] == 0
    assert account['changes']['new_false_positives'] == 1
    assert result['status'] == 'regression_in_sample'


def test_comparison_exposes_more_missed_spam_and_keeps_explicit_rule_decisions():
    baseline = [row('spam', 'spam', 10), row('allowed', 'ham', 20, prediction='ham')]
    candidate = [dict(baseline[0], prediction='ham'), baseline[1]]
    result = quality.compare(baseline, candidate, min_per_class=1)
    account = result['accounts'][0]
    assert account['changes']['new_false_negatives'] == 1
    assert account['candidate']['fp'] == 0
    assert account['candidate_cost'] == 1
    assert result['status'] == 'regression_in_sample'


@pytest.mark.parametrize('field,value', [('label', 'spam'), ('split', 'train'),
                                      ('basis', 'after_ai'), ('selection', 'different')])
def test_comparison_rejects_changed_ground_truth_or_measurement_basis(field, value):
    baseline = [row('one', 'ham', 1)]
    with pytest.raises(ValueError, match=field):
        quality.compare(baseline, [dict(baseline[0], **{field: value})])


def test_comparison_rejects_missing_or_duplicate_mail_without_printing_ids():
    baseline = [row('sensitive-id', 'ham', 1)]
    with pytest.raises(ValueError, match='samme konto/ID') as ex:
        quality.compare(baseline, [])
    assert 'sensitive-id' not in str(ex.value)
    with pytest.raises(ValueError, match='overlappe'):
        quality.compare(baseline, baseline * 2)


def test_sample_floor_empty_input_and_provenance_are_explicit():
    sample = [row('h', 'ham', 1), row('s', 'spam', 10)]
    result = quality.compare(sample, sample)
    assert result['status'] == 'insufficient_sample'
    assert not result['accounts'][0]['sufficient_sample']
    assert quality.compare([], [])['status'] == 'insufficient_sample'
    assert 'træningslækage' in result['warning']
    assert quality.compare(sample, sample, min_per_class=1)['status'] == 'no_regression_in_sample'


def test_comparison_hashes_distinguish_cohort_and_predictions_excluding_train():
    sample = [row('h', 'ham', 1), row('s', 'spam', 10),
              dict(row('train', 'spam', 10), split='train')]
    changed = [dict(sample[0], score=2, version='candidate'), sample[1],
               dict(sample[2], score=30)]
    result = quality.compare(sample, changed)
    assert result['holdout_size'] == 2
    assert len(result['cohort_sha256']) == 64
    assert result['baseline_sha256'] != result['candidate_sha256']
    assert result['cohort_sha256'] == quality.compare(sample[:2], changed[:2])['cohort_sha256']


@pytest.mark.parametrize('options', [{'false_positive_cost': True}, {'false_positive_cost': 0},
                                   {'false_positive_cost': 1.5}, {'min_per_class': 0},
                                   {'min_per_class': False}, {'min_per_class': 1_000_001}])
def test_comparison_rejects_invalid_cost_or_floor(options):
    with pytest.raises(ValueError):
        quality.compare([], [], **options)
