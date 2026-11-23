"""No live mail: reasons, bounded samples, privacy, latest verdict and UI scope."""
import json
import sqlite3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "filter"))

import pytest
import correctionfollowup as followup
import decisiontrace
import quality
import services


@pytest.fixture
def conn():
    c = sqlite3.connect(':memory:')
    c.row_factory = sqlite3.Row
    c.executescript(quality.SCHEMA + decisiontrace.SCHEMA + '''CREATE TABLE messages(
        account TEXT,message_id TEXT,sender TEXT,symbols TEXT,verdict_at INTEGER,
        verdict_by TEXT,user_verdict TEXT,subject TEXT,PRIMARY KEY(account,message_id));''')
    yield c
    c.close()


def put(c, key, *, account='a', reason='score', spam=False, verdict='spam', at=100, sender='one@sample.invalid'):
    c.execute('INSERT INTO messages VALUES(?,?,?,?,?,?,?,?)',
        (account,key,sender,'[]',at,'admin',verdict,'PRIVATE SUBJECT'))
    if reason is not None:
        trace = json.dumps(dict(schema_version=1, result=dict(spam=spam,reason=reason)))
        c.execute("INSERT INTO decision_traces(account,message_key,stage,created_at,digest,snapshot) VALUES(?,?,'scan',?,?,?)",
                  (account,key,1,key,trace))


def test_scoped_latest_verdict_period_no_bodies_or_ids_and_no_mutation(conn):
    put(conn,'SECRET-ID',reason='sender_allow')
    put(conn,'spam-first',spam=True)
    put(conn,'unknown',reason=None)
    put(conn,'rescued',verdict='ham')
    put(conn,'old',at=2)
    put(conn,'PRIVATE-OTHER',account='b')
    conn.commit()
    before=conn.total_changes
    a, = followup.summarize(conn,['a'],50,200,authenticated=lambda *args: False)
    assert a['sample_size']==3 and a['unverified']==3
    assert {r['code']:r['n'] for r in a['reasons']}==dict(allow=1, first_scan_spam=1, unknown=1)
    assert conn.total_changes==before
    output=json.dumps(a)
    assert all(s not in output for s in ('PRIVATE','SECRET-ID','one@sample.invalid'))


def test_first_trace_wins_later_ai_not_used_unknown_and_truncation_explicit(conn):
    for i in range(4): put(conn,str(i),sender=f'{i}@sample.invalid')
    conn.execute("INSERT INTO decision_traces(account,message_key,stage,created_at,digest,snapshot) "
                 "VALUES('a','3','scan',150,'later',?)",(json.dumps(dict(schema_version=1,result=dict(spam=True,reason='score'))),))
    a, = followup.summarize(conn,['a'],50,200,limit=3)
    assert a['sample_size']==3 and a['truncated']
    assert a['rotating_domains']==1 and a['unverified'] is None
    assert a['reasons'][0]['code']=='below_threshold'
    with pytest.raises(ValueError): followup.summarize(conn,['a'],0,200,limit=501)


def test_unknown_malformed_trace_and_unattributed_verdict(conn):
    put(conn,'one')
    conn.execute("UPDATE decision_traces SET snapshot='broken'")
    put(conn,'automatic')
    conn.execute("UPDATE messages SET verdict_by=NULL WHERE message_id='automatic'")
    a,=followup.summarize(conn,['a'],0,200)
    assert a['sample_size']==1 and a['reasons'][0]['code']=='unknown'


def test_weekly_plain_and_html_use_same_safe_aggregate(conn):
    put(conn,'one',reason='sender_allow')
    item,=followup.summarize(conn,['a'],0,200)
    result=services.render_weekly(dict(week='2026-W47',accounts=[dict(account='a',name='<mailbox>',scanned=1,moved=0,
        released=0,missed=1,prev={})],correction_followup=[item]),full=False)
    assert 'Opfølgning på spamrettelser: <mailbox>' in result['text']
    assert '&lt;mailbox&gt;' in result['html'] and '<mailbox>' not in result['html']
    assert 'tilladelsesregel' in result['text'] and 'Ingen regler' in result['text']
