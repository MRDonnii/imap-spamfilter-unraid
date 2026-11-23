"""Security regressions from the independent review; no real mailbox access."""
import pytest
from fakes_engine import setup_engine, GIGAHOST_CAPS, SCANNET_CAPS, make_message
from test_engine_scan import Harness

@pytest.fixture
def eng(tmp_path, monkeypatch):
    return setup_engine(tmp_path, monkeypatch)

@pytest.mark.parametrize('caps', [GIGAHOST_CAPS, SCANNET_CAPS])
def test_no_message_id_is_scanned_and_moved(eng, monkeypatch, caps):
    h = Harness(eng, monkeypatch, caps=caps)
    h.rspamd.default = 20
    h.client.add('INBOX', make_message(None, body='malicious body'))
    h.scan()
    assert len(h.rspamd.scan_calls) == 1
    assert h.db.count_pending_moves() == 1
    h.advance(100)
    h.moves()
    assert not h.client.uids('INBOX') and len(h.client.uids('Junk')) == 1

@pytest.mark.parametrize('change', ['sender', 'body'])
def test_reused_id_does_not_inherit_release(eng, monkeypatch, change):
    h = Harness(eng, monkeypatch)
    h.deliver('released@x', score=1)
    h.scan()
    with h.db.tx():
        h.db.update_message('released@x', user_verdict='ham', our_action='manual_release')
    h.advance(60)
    h.deliver('released@x', score=20, **({'sender': 'other@evil.example'} if change == 'sender' else {'body': 'different payload'}))
    h.scan()
    assert len(h.rspamd.scan_calls) == 2
    assert h.db.count_pending_moves() == 1
    assert h.row('released@x')['user_verdict'] == 'ham'

@pytest.mark.parametrize('caps', [GIGAHOST_CAPS, SCANNET_CAPS])
def test_normal_allow_during_grace_cancels_move(eng, monkeypatch, caps):
    h = Harness(eng, monkeypatch, caps=caps)
    h.deliver('pending@x', score=12, sender='real@vendor.example')
    h.scan()
    eng.add_sender_rule(h.db.conn, h.acc.name, 'real@vendor.example', 'allow', actor='test')
    h.advance(100)
    h.moves()
    assert h.client.msgids('INBOX') == ['pending@x']
    assert not h.client.uids('Junk') and h.db.count_pending_moves() == 0


def test_no_id_rescue_and_learning_keep_the_same_identity(eng, monkeypatch):
    h = Harness(eng, monkeypatch)
    h.rspamd.default = 20
    uid = h.client.add('INBOX', make_message(None, body='first body'))
    h.scan()
    key = h.db.conn.execute('SELECT message_id FROM messages').fetchone()[0]
    h.advance(100)
    h.moves()
    h.poll()
    source = h.client.folders['Junk']
    msg = source.msgs.pop(next(iter(source.msgs)))
    h.client.add('INBOX', msg.raw, internaldate=msg.internaldate)
    h.scan()
    assert h.row(key)['user_verdict'] == 'ham'
    assert h.row(key)['our_action'] == 'user_rescued'
    assert len(h.rspamd.scan_calls) == 1
    assert h.db.count_pending_moves() == 0


def test_distinct_no_id_messages_and_restarts(eng, monkeypatch):
    h = Harness(eng, monkeypatch)
    h.client.add('INBOX', make_message(None, body='one'))
    h.client.add('INBOX', make_message(None, body='two'))
    h.scan()
    rows = h.db.conn.execute('SELECT message_id FROM messages').fetchall()
    assert len(rows) == 2 and rows[0][0] != rows[1][0]
    h.state = eng.AccountState()
    h.scan()
    assert len(h.rspamd.scan_calls) == 2


def test_collision_lookup_cannot_release_other_content(eng, monkeypatch):
    h = Harness(eng, monkeypatch)
    original = h.deliver('same@x', score=1)
    h.scan()
    other = h.deliver('same@x', score=20, body='different')
    h.scan()
    keys = [r[0] for r in h.db.conn.execute('SELECT message_id FROM messages')]
    local = next(k for k in keys if k != 'same@x')
    assert eng.find_uids_by_message_id(h.client, 'same@x') == [original]
    assert eng.find_uids_by_message_id(h.client, local) == [other]


@pytest.mark.parametrize('symbol', ['CLAM_VIRUS', 'R_SPF_FAIL'])
def test_allow_during_grace_does_not_save_virus_or_spoof(eng, monkeypatch, symbol):
    h = Harness(eng, monkeypatch)
    h.rspamd.symbols['danger@x'] = {symbol: {'name': symbol, 'score': 10, 'options': ['Win.Trojan']}}
    h.deliver('danger@x', score=20, sender='real@vendor.example')
    h.scan()
    eng.add_sender_rule(h.db.conn, h.acc.name, 'real@vendor.example', 'allow', actor='test')
    h.advance(100)
    h.moves()
    assert h.client.msgids('Junk') == ['danger@x']


def test_release_of_same_fingerprinted_mail_stays_sticky(eng, monkeypatch):
    h = Harness(eng, monkeypatch)
    h.deliver('kept@x', score=20)
    h.scan()
    with h.db.tx():
        h.db.update_message('kept@x', user_verdict='ham', our_action='manual_release')
        h.db.drop_pending_moves_for('kept@x')
    h.user_moves('kept@x', 'INBOX', 'Trash')
    h.user_moves('kept@x', 'Trash', 'INBOX')
    h.scan()
    assert len(h.rspamd.scan_calls) == 1
    assert h.row('kept@x')['user_verdict'] == 'ham'


def test_reserved_local_key_header_does_not_impersonate_no_id_mail(eng, monkeypatch):
    h = Harness(eng, monkeypatch)
    h.client.add('INBOX', make_message(None, body='original'))
    h.scan()
    key = h.db.conn.execute('SELECT message_id FROM messages').fetchone()[0]
    with h.db.tx():
        h.db.update_message(key, user_verdict='ham', our_action='manual_release')
    h.deliver(key, score=20, body='forged')
    h.scan()
    assert len(h.rspamd.scan_calls) == 2 and h.db.count_pending_moves() == 1


def test_raised_threshold_rechecked_before_move(eng, monkeypatch):
    h = Harness(eng, monkeypatch)
    h.deliver('threshold@x', score=12)
    h.scan()
    h.acc.threshold = 15
    h.advance(100)
    h.moves()
    assert h.client.msgids('INBOX') == ['threshold@x']
    assert h.db.count_pending_moves() == 0


def test_truncated_display_symbols_cannot_hide_spoof_at_move(eng, monkeypatch):
    h = Harness(eng, monkeypatch)
    h.rspamd.symbols['spoof@x'] = {'R_SPF_FAIL': {'name': 'R_SPF_FAIL', 'score': 10, 'options': []}}
    h.deliver('spoof@x', score=20, sender='allowed@vendor.example')
    h.scan()
    # UI explanations are not the complete decision evidence.
    with h.db.tx():
        h.db.update_message('spoof@x', symbols='[]')
    eng.add_sender_rule(h.db.conn, h.acc.name, 'allowed@vendor.example', 'allow')
    h.advance(100)
    h.moves()
    assert h.client.msgids('Junk') == ['spoof@x']


@pytest.mark.parametrize('caps', [GIGAHOST_CAPS, SCANNET_CAPS])
@pytest.mark.parametrize('unavailable', ['oversize', 'missing_body'])
def test_unverified_junk_collision_cannot_change_existing_release(eng, monkeypatch, caps, unavailable):
    h = Harness(eng, monkeypatch, caps=caps)
    h.deliver('released-size@x', score=1)
    h.scan()
    with h.db.tx():
        h.db.update_message('released-size@x', user_verdict='ham', our_action='manual_release')
    h.poll()
    h.client.add('Junk', make_message('released-size@x', body='different oversize payload'),
                 size=eng.MAX_FETCH_BYTES + 1 if unavailable == 'oversize' else None)
    if unavailable == 'missing_body':
        fetch = h.client.fetch
        def without_body(uids, parts):
            if h.client.selected == 'Junk' and b'BODY.PEEK[]' in parts:
                return {u: {} for u in uids}
            return fetch(uids, parts)
        monkeypatch.setattr(h.client, 'fetch', without_body)
    h.poll()
    assert h.row('released-size@x')['user_verdict'] == 'ham'
    assert h.row('released-size@x')['our_action'] == 'manual_release'
    assert h.rspamd.learn_calls == []
    assert h.events('junk_identity_unverified')
