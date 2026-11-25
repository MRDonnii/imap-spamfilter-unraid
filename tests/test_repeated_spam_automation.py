"""Owner-approved automation uses fresh, explicit, authenticated feedback only."""
import logging
import pytest
from fakes_engine import setup_engine
import junkrules
import services
from test_v212_rules import _harness, _junk_one, _rules, SENDER, AUTHED

LOG = logging.getLogger('test-repeat-automation')

@pytest.fixture
def eng(tmp_path, monkeypatch):
    return setup_engine(tmp_path, monkeypatch)


def test_default_automation_blocks_only_after_three_new_authenticated_corrections(eng, monkeypatch):
    h = _harness(eng, monkeypatch)
    for i in range(2):
        _junk_one(h, f'fresh-{i}@x')
    assert not _rules(h)
    _junk_one(h, 'fresh-2@x')
    assert [(r['account'],r['pattern'],r['kind'],r['created_by']) for r in _rules(h)] == [
        (h.acc.name,SENDER,'block','auto:junk')]
    assert h.events('junk_auto_block')


def test_old_suggestion_does_not_become_an_automatic_block_on_upgrade(eng, monkeypatch):
    h = _harness(eng, monkeypatch)
    for i in range(3):
        junkrules.on_user_junk(h.db.conn,h.acc.name,SENDER,f'old-{i}@x',now=int(h.t))
    assert not _rules(h)
    _junk_one(h,'new-after-upgrade@x')
    assert not _rules(h)
    _junk_one(h,'new-after-upgrade-2@x')
    assert not _rules(h)
    _junk_one(h,'new-after-upgrade-3@x')
    assert len(_rules(h)) == 1


def _webui_spam(h, mid):
    h.rspamd.symbols[mid] = dict(AUTHED)
    h.deliver(mid,score=2,sender=SENDER)
    h.scan()
    fmap=services._folder_map(h.acc,services._list_folders(h.client))
    return services._do_mark_spam(h.eng,h.db,h.acc,services._Session(h.client),fmap,
                                 services._caps_for_engine(services._caps(h.client)),mid,'admin')


def test_webui_and_mail_client_corrections_share_one_counter_without_double_counting(eng,monkeypatch):
    h=_harness(eng,monkeypatch)
    assert _webui_spam(h,'ui-one@x')['ok']
    h.poll()  # engine sees the same manually moved mail: not another correction
    assert not _rules(h)
    _junk_one(h,'app-two@x')
    assert not _rules(h)
    assert _webui_spam(h,'ui-three@x')['ok']
    assert len(_rules(h)) == 1


@pytest.mark.parametrize('webui',[False,True])
def test_rescue_cancels_automatic_block_even_without_automatic_allow(eng,monkeypatch,webui):
    h=_harness(eng,monkeypatch)
    h.acc.auto_allow_on_rescue=False
    for i in range(3):_junk_one(h,f'rescue-{i}@x')
    assert len(_rules(h)) == 1
    if webui:
        from test_engine_autoallow import _release_via_services
        assert _release_via_services(eng,h,'rescue-2@x',scan_between=False,monkeypatch=monkeypatch)['ok']
    else:
        h.user_moves('rescue-2@x','Spamfilter','INBOX')
        h.scan()
    assert not _rules(h)
    assert h.events('junk_auto_block_removed')


def test_switch_off_keeps_suggestions_without_automatic_rules(eng,monkeypatch):
    h=_harness(eng,monkeypatch)
    h.acc.auto_block_repeated_spam=False
    for i in range(3):_junk_one(h,f'off-{i}@x')
    assert not _rules(h) and h.events('junk_block_suggested')


def test_automatic_evidence_expires_after_30_days(eng,monkeypatch):
    h=_harness(eng,monkeypatch)
    _junk_one(h,'early-1@x')
    _junk_one(h,'early-2@x')
    h.advance(31*86400)
    _junk_one(h,'late-1@x')
    assert not _rules(h)
    assert h.db.conn.execute('SELECT COUNT(*) FROM junk_auto_evidence').fetchone()[0] == 1
    _junk_one(h,'late-2@x')
    assert not _rules(h)
    _junk_one(h,'late-3@x')
    assert len(_rules(h)) == 1


def test_rescue_before_third_correction_resets_the_evidence(eng,monkeypatch):
    h=_harness(eng,monkeypatch)
    h.acc.auto_allow_on_rescue=False
    _junk_one(h,'reset-1@x')
    _junk_one(h,'reset-2@x')
    h.user_moves('reset-2@x','Spamfilter','INBOX')
    h.scan()
    _junk_one(h,'reset-3@x')
    assert not _rules(h)
    assert h.db.conn.execute('SELECT COUNT(*) FROM junk_auto_evidence').fetchone()[0] == 1


def test_daily_automatic_rule_budget_leaves_a_suggestion(eng,monkeypatch):
    h=_harness(eng,monkeypatch)
    _junk_one(h,'budget-1@x')
    _junk_one(h,'budget-2@x')
    for i in range(junkrules.MAX_AUTO_BLOCKS_PER_DAY):
        h.db.log_event('junk_auto_block',f'other-{i}@x',detail='earlier automatic rule')
    _junk_one(h,'budget-3@x')
    assert not _rules(h)
    assert junkrules.get(h.db.conn,h.acc.name,SENDER,'suggest')['status'] == 'open'


def test_repeated_clicks_on_one_webui_mail_never_make_three_corrections(eng,monkeypatch):
    h=_harness(eng,monkeypatch)
    assert _webui_spam(h,'clicks@x')['ok']
    fmap=services._folder_map(h.acc,services._list_folders(h.client))
    for i in range(4):
        assert services._do_mark_spam(eng,h.db,h.acc,services._Session(h.client),fmap,
                  services._caps_for_engine(services._caps(h.client)),'clicks@x','admin')['ok']
    assert not _rules(h)
    assert h.db.conn.execute('SELECT COUNT(*) FROM junk_auto_evidence').fetchone()[0] == 1


def test_automatic_block_does_not_affect_another_mailbox(eng,monkeypatch):
    from test_engine_scan import Harness
    h=_harness(eng,monkeypatch)
    for i in range(3):_junk_one(h,f'personal-{i}@x')
    other=Harness(eng,monkeypatch,name='other',user='other@other-mail.example',mode='move')
    other.deliver('other-inbox@x',score=2,sender=SENDER)
    other.scan()
    assert other.row('other-inbox@x')['our_action'] == 'none'
    assert other.row('other-inbox@x')['rule_hit'] is None


def test_ham_does_not_delete_a_rule_the_admin_has_replaced(eng,monkeypatch):
    h=_harness(eng,monkeypatch)
    h.acc.auto_allow_on_rescue=False
    for i in range(3):_junk_one(h,f'admin-{i}@x')
    rid=_rules(h)[0]['id']
    h.db.conn.execute("UPDATE sender_rules SET created_by='admin',note='explicit choice' WHERE id=?",(rid,))
    h.user_moves('admin-2@x','Spamfilter','INBOX')
    h.scan()
    assert [(r['id'],r['created_by']) for r in _rules(h)] == [(rid,'admin')]


def test_undo_automatic_rule_also_cancels_a_pending_move_that_only_depended_on_it(eng,monkeypatch):
    h=_harness(eng,monkeypatch)
    h.acc.auto_allow_on_rescue=False
    for i in range(3):_junk_one(h,f'pending-base-{i}@x')
    h.deliver('waiting-low@x',score=2,sender=SENDER)
    h.deliver('waiting-high@x',score=14,sender=SENDER)
    h.scan()
    assert h.row('waiting-low@x')['our_action']=='pending_move'
    h.user_moves('pending-base-2@x','Spamfilter','INBOX')
    h.scan()
    assert not _rules(h)
    h.advance(61)
    h.moves()
    assert 'waiting-low@x' in h.client.msgids('INBOX')
    assert 'waiting-high@x' in h.client.msgids('Spamfilter')


def test_pending_automatic_rule_undo_during_fetch_is_respected(eng,monkeypatch):
    h=_harness(eng,monkeypatch)
    for i in range(3):_junk_one(h,f'fetch-base-{i}@x')
    h.deliver('fetch-waiting@x',score=2,sender=SENDER)
    h.scan()
    h.advance(61)
    fetch=h.client.fetch
    changed=[]
    def fetch_then_undo(*args,**kwargs):
        data=fetch(*args,**kwargs)
        if not changed:
            changed.append(True)
            with h.db.tx():
                eng._junk_rules_after_user_ham(h.db,LOG,h.acc,'fetch-base-2@x',SENDER)
        return data
    monkeypatch.setattr(h.client,'fetch',fetch_then_undo)
    h.moves()
    assert changed
    assert 'fetch-waiting@x' in h.client.msgids('INBOX')
    assert not _rules(h)


@pytest.mark.parametrize('set_undone',[False,True])
def test_remove_automatic_block_button_is_respected_for_waiting_mail(eng,monkeypatch,set_undone):
    h=_harness(eng,monkeypatch)
    for i in range(3):_junk_one(h,f'button-base-{i}@x')
    h.deliver('button-low@x',score=2,sender=SENDER)
    h.deliver('button-high@x',score=14,sender=SENDER)
    h.scan()
    rid=_rules(h)[0]['id']
    with h.db.tx():
        eng.delete_sender_rule(h.db.conn,rid)
        if set_undone:
            junkrules.decide(h.db.conn,h.acc.name,SENDER,'suggest','undone','admin',now=int(h.t))
    h.advance(61)
    h.moves()
    assert 'button-low@x' in h.client.msgids('INBOX')
    assert 'button-high@x' in h.client.msgids('Spamfilter')
