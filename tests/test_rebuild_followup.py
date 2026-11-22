"""'Byg Bayes op på ny' – follow-up fixes (2.3.0 review):

1. After the pool switch, autolearn never feeds the new pool inbox mail an
   earlier pool already learned (and never a ham autolearn an admin
   reverted); no ham autolearn while a rebuild runs; reverted ham
   autolearns go on the rebuild's spam learn list and are never ham.
2. A failure while queueing the rebuild's jobs leaves the old pool's
   learned state exactly as it was (switch + queue are one transaction).
3. A restore whose state switch failed can be retried ('restoring').
4. Status: progress counts mails, and the »allerede lært« warning tells
   the owner to restore."""

from __future__ import annotations

import logging
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "filter"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import services  # noqa: E402
import trainer  # noqa: E402
from fakes_engine import setup_engine  # noqa: E402
from test_engine_scan import Harness  # noqa: E402
from test_services import live  # noqa: E402,F401
from test_services_rebuild import (  # noqa: E402,F401
    Saver, _old_pool_history, config, db, fast_trainer, learns, mailbox, only_filter_spam, run_trainer,
)

LOG = logging.getLogger("t")
DAY = 86400


@pytest.fixture
def eng(tmp_path, monkeypatch):
    return setup_engine(tmp_path, monkeypatch)


def _seen_inbox(h):
    for m in h.client.folders["INBOX"].msgs.values():
        m.flags.add("\\Seen")


def _switch(eng, h, src="hjemmeserver", dst="hjemmeserver-r2"):
    c = sqlite3.connect(eng.DB_PATH, isolation_level=None)
    c.row_factory = sqlite3.Row
    try:
        services.bayes_pool_switch(c, {h.acc.name: (src, dst)})
    finally:
        c.close()
    h.acc.bayes_user = dst


# ---------------------------------------------------------------------------
# 1. autolearn after the pool switch
# ---------------------------------------------------------------------------


def test_reverted_ham_autolearn_is_never_relearned_as_ham_in_the_new_pool(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("ham@x", score=-0.5)
    h.scan()
    _seen_inbox(h)
    h.advance(7 * DAY + 1)
    assert eng.autolearn_pass(h.client, h.db, LOG, h.acc, h.acc.folder_map)["ham"] == 1
    entry = eng.autolearn_entries(h.db.conn)[0]
    h.advance(eng.FLIP_FLOP_COOLDOWN_S + 1)
    assert eng.revert_autolearn(h.db.conn, entry["id"], "admin")   # the admin: NOT legitimate
    eng.process_pending_learns(h.client, h.db, LOG, h.acc, h.acc.folder_map)
    assert h.row("ham@x")["learned_as"] == "spam"
    # The rebuild puts it on its spam learn list.
    c = sqlite3.connect(eng.DB_PATH)
    c.row_factory = sqlite3.Row
    assert (h.acc.name, "ham@x") in services._old_spam_learn_list(
        c, {h.acc.name}, {}, eng)
    c.close()
    _switch(eng, h)
    with sqlite3.connect(eng.DB_PATH) as c:
        # The autolearn record survives the switch (it is not per pool).
        assert c.execute("SELECT COUNT(*) FROM autolearn_log WHERE message_id='ham@x'").fetchone()[0] == 1
    n0 = len(h.rspamd.learn_calls)
    h.advance(DAY + 1)
    res = eng.autolearn_pass(h.client, h.db, LOG, h.acc, h.acc.folder_map)
    assert res["ham"] == 0
    assert not [x for x in h.rspamd.learn_calls[n0:] if x["url"].endswith("/learnham")]


def test_inbox_mail_an_earlier_pool_learned_is_no_ham_candidate_but_new_mail_is(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("old@x", score=-1.0)
    h.scan()
    with sqlite3.connect(eng.DB_PATH) as c:   # e.g. the 2.0 bootstrap learned the inbox as ham
        c.execute("UPDATE messages SET learned_as='ham', learned_at=? WHERE message_id='old@x'", (1,))
    _switch(eng, h)
    assert h.row("old@x")["learned_as"] is None   # reset for the new pool ...
    h.deliver("new@x", score=-1.0)
    h.scan()
    _seen_inbox(h)
    h.advance(7 * DAY + 1)
    cands = {r["message_id"] for r in eng.autolearn_candidates(h.db, h.acc, h.acc.folder_map)["ham"]}
    assert cands == {"new@x"}                     # ... but never ham again via autolearn


def test_no_ham_autolearn_while_a_rebuild_runs(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("ham@x", score=-0.5)
    h.scan()
    _seen_inbox(h)
    h.advance(7 * DAY + 1)
    with sqlite3.connect(eng.DB_PATH) as c:
        c.execute("INSERT INTO bayes_rebuilds(status, pool_old, pool_new, ratio, created_at) "
                  "VALUES('running', 'hjemmeserver', 'hjemmeserver-r2', 2.0, 1)")
    assert eng.autolearn_candidates(h.db, h.acc, h.acc.folder_map)["ham"] == []
    with sqlite3.connect(eng.DB_PATH) as c:
        c.execute("UPDATE bayes_rebuilds SET status='done'")
    assert [r["message_id"] for r in eng.autolearn_candidates(h.db, h.acc, h.acc.folder_map)["ham"]] == ["ham@x"]


def test_rebuild_never_learns_a_reverted_ham_autolearn_as_ham(live):
    h = mailbox(live, archive=(1, 0, 0))
    only_filter_spam(h)
    from test_services_rebuild import add
    add(live, h, "INBOX.Arkiv", "reverted@x")
    with db(live) as conn:
        now = int(live.clock.t) - 10
        conn.execute("INSERT INTO messages(account, message_id, first_seen, last_seen, current_folder) "
                     "VALUES('anna', 'reverted@x', ?, ?, 'INBOX.Arkiv')", (now, now))
        conn.execute("INSERT INTO autolearn_log(account, message_id, kind, score, outcome, created_at, "
                     "reverted_at, reverted_by) VALUES('anna', 'reverted@x', 'ham', -1, 'learned', ?, ?, 'admin')",
                     (now - 100, now))
    assert services.bayes_rebuild_start("admin", engine=live.eng, save_config=Saver(live.eng))["ok"]
    run_trainer(live)
    assert ("learnham", "hjemmeserver-r2", "reverted@x") not in learns(live)


# ---------------------------------------------------------------------------
# 2. a queueing failure after the switch
# ---------------------------------------------------------------------------


def test_queue_failure_leaves_the_old_pool_state_untouched(live, monkeypatch):
    h = mailbox(live)
    _old_pool_history(live, h)
    with db(live) as conn:
        before = sorted(tuple(r) for r in conn.execute(
            "SELECT message_id, learned_as FROM messages WHERE learned_as IS NOT NULL"))
        ledger = conn.execute("SELECT COUNT(*) FROM learn_ledger").fetchone()[0]
    saver = Saver(live.eng)
    real = services._queue_rebuild_jobs

    def boom(*a, **k):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(services, "_queue_rebuild_jobs", boom)
    res = services.bayes_rebuild_start("admin", engine=live.eng, save_config=saver)
    assert res["code"] == "db" and "den gamle Bayes bruges stadig" in res["text"]
    assert config(live)["defaults"]["bayes_user"] == "hjemmeserver"
    with db(live) as conn:
        after = sorted(tuple(r) for r in conn.execute(
            "SELECT message_id, learned_as FROM messages WHERE learned_as IS NOT NULL"))
        assert after == before and len(after) == 4
        assert conn.execute("SELECT COUNT(*) FROM learn_ledger").fetchone()[0] == ledger
        assert conn.execute("SELECT COUNT(*) FROM bayes_pool_archive").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM train_jobs").fetchone()[0] == 0
        assert tuple(conn.execute("SELECT status, archived FROM bayes_rebuilds").fetchone()) == ("failed", None)
    st = services.bayes_rebuild_status(engine=live.eng)
    assert st["code"] == "failed" and "den tidligere Bayes bruges stadig" in st["text"]
    # A new start works afterwards.
    monkeypatch.setattr(services, "_queue_rebuild_jobs", real)
    assert services.bayes_rebuild_start("admin", engine=live.eng, save_config=saver)["ok"]


def test_a_failure_marking_running_rolls_the_queue_back_too(live, monkeypatch):
    mailbox(live)
    saver = Saver(live.eng)
    real = services._queue_rebuild_jobs

    def queue_then_fail(*a, **k):
        real(*a, **k)
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(services, "_queue_rebuild_jobs", queue_then_fail)
    assert services.bayes_rebuild_start("admin", engine=live.eng, save_config=saver)["code"] == "db"
    with db(live) as conn:
        assert conn.execute("SELECT COUNT(*) FROM train_jobs").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM learn_list_jobs").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM bayes_rebuild_jobs").fetchone()[0] == 0


# ---------------------------------------------------------------------------
# 3. a restore whose state switch failed can be retried
# ---------------------------------------------------------------------------


def test_failed_restore_can_be_retried_and_finishes_the_state_switch(live, monkeypatch):
    h = mailbox(live)
    _old_pool_history(live, h)
    saver = Saver(live.eng)
    assert services.bayes_rebuild_start("admin", engine=live.eng, save_config=saver)["ok"]
    run_trainer(live)
    real = services.bayes_pool_switch

    def boom(*a, **k):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(services, "bayes_pool_switch", boom)
    res = services.bayes_restore_previous("admin", engine=live.eng, save_config=saver)
    assert res["code"] == "db" and "Gendan tidligere Bayes« igen" in res["text"]
    assert config(live)["defaults"]["bayes_user"] == "hjemmeserver"          # config already back
    st = services.bayes_rebuild_status(engine=live.eng)
    assert st["code"] == "restoring" and st["can_restore"] and "igen" in st["text"]
    # No new rebuild may start on top of a half restore.
    again = services.bayes_rebuild_start("admin", engine=live.eng, save_config=saver)
    assert again["code"] == "running" and "Gendan tidligere Bayes" in again["text"]
    monkeypatch.setattr(services, "bayes_pool_switch", real)
    n_saves = len(saver.calls)
    res2 = services.bayes_restore_previous("admin", engine=live.eng, save_config=saver)
    assert res2["ok"] and res2["code"] == "restored", res2
    assert len(saver.calls) == n_saves          # the config was already back: not written twice
    with db(live) as conn:
        rows = {r["message_id"]: r["learned_as"] for r in conn.execute(
            "SELECT message_id, learned_as FROM messages WHERE learned_as IS NOT NULL")}
        assert rows == {"sf0@spam": "spam", "inboxarkiv0@ham": "ham", "inboxarkivkunder0@ham": "unlearnable",
                        "dragged@spam": "spam"}
        assert conn.execute("SELECT status FROM bayes_rebuilds").fetchone()[0] == "restored"
    assert services.bayes_rebuild_status(engine=live.eng)["code"] == "restored"


def test_restore_rejected_by_the_config_puts_the_status_back(live):
    mailbox(live)
    saver = Saver(live.eng)
    assert services.bayes_rebuild_start("admin", engine=live.eng, save_config=saver)["ok"]
    run_trainer(live)
    saver.reject = "ugyldig"
    res = services.bayes_restore_previous("admin", engine=live.eng, save_config=saver)
    assert res["code"] == "rejected"
    st = services.bayes_rebuild_status(engine=live.eng)
    assert st["code"] == "done" and st["can_restore"]
    saver.reject = None
    assert services.bayes_restore_previous("admin", engine=live.eng, save_config=saver)["ok"]


# ---------------------------------------------------------------------------
# 4. status: percent in mails, the »allerede lært« advice
# ---------------------------------------------------------------------------


def test_percent_counts_mails_not_jobs():
    prog = {"spam": {"learned": 148, "skipped": 0, "failed": 0, "planned": 661},
            "ham": {"learned": 96, "skipped": 0, "failed": 0, "planned": 1322},
            "jobs": {"done": 2, "running": 1, "queued": 3}, "active": 4, "total_jobs": 6}
    assert services._rebuild_percent(prog, 661, 1322) == 12
    prog["spam"].update(learned=661)
    prog["ham"].update(learned=1322)
    assert services._rebuild_percent(prog, 661, 1322) == 99      # never 100 while a job is active
    prog["active"] = 0
    assert services._rebuild_percent(prog, 661, 1322) == 100


def test_already_learned_warning_says_restore(live):
    h = mailbox(live, spam=22, provider_spam=0, archive=(5, 0, 0))
    only_filter_spam(h)
    services.bayes_rebuild_start("admin", engine=live.eng, save_config=Saver(live.eng))
    live.rspamd.learn_status = 208
    run_trainer(live)
    st = services.bayes_rebuild_status(engine=live.eng)
    assert st["code"] == "done"
    w = st["warnings"][0]
    assert "rspamd svarede »allerede lært«" in w and "Gendan tidligere Bayes" in w
    assert "før du venter" not in w and "uden Bayes" in w
