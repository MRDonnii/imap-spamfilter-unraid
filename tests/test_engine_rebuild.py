"""ENGINE side of 'Byg Bayes op på ny': learn_message's bypass_cooldown
(Bayes rebuild jobs only), the identity a learn is POSTed to after a pool
switch, and the additive rebuild tables in init_db."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import make_message, setup_engine  # noqa: E402
from test_engine_scan import Harness  # noqa: E402


@pytest.fixture
def eng(tmp_path, monkeypatch):
    return setup_engine(tmp_path, monkeypatch)


def _row(h, mid):
    h.db.conn.execute("INSERT OR IGNORE INTO messages(account, message_id, first_seen, last_seen, current_folder) "
                      "VALUES(?, ?, 0, 0, 'INBOX')", (h.acc.name, mid))


def test_flip_flop_cooldown_holds_unless_bypassed(eng, monkeypatch):
    h = Harness(eng, monkeypatch)
    _row(h, "m@x")
    raw = make_message("m@x")
    assert eng.learn_message(h.db, h.acc, raw, "ham", "m@x", bypass_rate=True) == "learned"
    assert eng.learn_message(h.db, h.acc, raw, "spam", "m@x", bypass_rate=True) == "rate_limited"
    assert eng.learn_message(h.db, h.acc, raw, "spam", "m@x", bypass_rate=True,
                             bypass_cooldown=True) == "learned"
    assert h.db.get_message("m@x")["learned_as"] == "spam"
    assert [c["url"].rsplit("/", 1)[-1] for c in h.rspamd.learn_calls] == ["learnham", "learnspam"]
    # 'already' still short-circuits with the bypass (no POST).
    assert eng.learn_message(h.db, h.acc, raw, "spam", "m@x", bypass_cooldown=True,
                             bypass_rate=True) == "already"
    assert len(h.rspamd.learn_calls) == 2


def test_a_reset_row_is_posted_to_the_new_pool(eng, monkeypatch):
    h = Harness(eng, monkeypatch)
    _row(h, "m@x")
    raw = make_message("m@x")
    assert eng.learn_message(h.db, h.acc, raw, "spam", "m@x", bypass_rate=True) == "learned"
    # A pool switch (services.bayes_pool_switch) resets the per-pool state ...
    h.db.conn.execute("UPDATE messages SET learned_as=NULL, learned_at=NULL")
    h.acc.bayes_user = "hjemmeserver-r2"
    assert eng.learn_message(h.db, h.acc, raw, "spam", "m@x", bypass_rate=True) == "learned"
    idents = [c["headers"].get("Deliver-To") for c in h.rspamd.learn_calls]
    assert idents == ["hjemmeserver", "hjemmeserver-r2"]
    assert h.rspamd.learn_calls[-1]["data"].startswith(b"Delivered-To: hjemmeserver-r2\r\n")


def test_rebuild_tables_are_created_additively(eng):
    eng.init_db()
    eng.init_db()  # idempotent
    conn = sqlite3.connect(eng.DB_PATH)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"bayes_rebuilds", "bayes_rebuild_jobs", "bayes_pool_archive", "threat_notices"} <= tables
    assert "threat_notice_sent" in eng.STAT_METRICS
