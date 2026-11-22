"""ENGINE: schema, additive migration, sender rules, stats, status rows (SPEC 3, A4, A5, A7)."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import setup_engine  # noqa: E402

# The 1.x schema as shipped before 2.0 (only the tables 2.0 alters).
SCHEMA_1X = """
CREATE TABLE messages (
    account TEXT NOT NULL, message_id TEXT NOT NULL, first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL, current_folder TEXT NOT NULL, moved_to_junk_at INTEGER,
    our_score REAL, our_action TEXT, learned_as TEXT, learned_at INTEGER,
    pending_learn TEXT, pending_learn_at INTEGER, sender TEXT, subject TEXT,
    received_at INTEGER, PRIMARY KEY (account, message_id));
CREATE TABLE pending_move (
    account TEXT NOT NULL, uidvalidity INTEGER NOT NULL, uid INTEGER NOT NULL,
    message_id TEXT NOT NULL, flag_at INTEGER NOT NULL, PRIMARY KEY (account, uidvalidity, uid));
CREATE TABLE scan_bookmark (account TEXT NOT NULL, folder TEXT NOT NULL,
    uidvalidity INTEGER NOT NULL, max_uid INTEGER NOT NULL, PRIMARY KEY (account, folder, uidvalidity));
"""

TABLES_2 = {"messages", "uidvalidity", "pending_move", "scan_bookmark", "events", "rate_limit",
            "safe_mode", "account_status", "sender_rules", "stats_daily", "train_jobs",
            "calibration_results", "scan_retry", "junk_bookmark"}
NEW_MESSAGE_COLS = {"rspamd_score", "symbols", "rspamd_action", "sender_ip", "envelope_from",
                    "provider_score", "provider_flag", "user_verdict", "verdict_at", "verdict_by",
                    "rule_hit", "size", "scanned_at", "origin", "score_version"}


@pytest.fixture
def eng(tmp_path, monkeypatch):
    return setup_engine(tmp_path, monkeypatch)


def cols(conn, table):
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def test_init_db_creates_everything_and_is_idempotent(eng):
    eng.init_db()
    eng.init_db()
    conn = sqlite3.connect(eng.DB_PATH)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert TABLES_2 <= tables
    assert NEW_MESSAGE_COLS <= cols(conn, "messages")
    assert "folder" in cols(conn, "pending_move")
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert {"account", "updated_at", "state", "detail", "connected_since", "last_loop_at",
            "last_scan_at", "last_error", "last_error_at", "error_count", "capabilities",
            "move_method", "idle_supported", "folders", "folder_map", "junk_exists", "mode",
            "threshold", "bookmark_lag", "pending_moves",
            # 2.1 (additive)
            "alive_at", "moves_today", "move_state", "move_state_reason", "move_state_at",
            "login_state", "retry_at"} == cols(conn, "account_status")


def test_migration_from_1x_is_additive_and_keeps_data(tmp_path, monkeypatch):
    db_path = tmp_path / "spamfilter.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA_1X)
    conn.execute("INSERT INTO messages(account, message_id, first_seen, last_seen, current_folder, "
                 "our_score, our_action) VALUES('a','m1',1,2,'INBOX',9.5,'shadow')")
    conn.execute("INSERT INTO pending_move VALUES('a', 7, 3, 'm1', 5)")
    conn.commit()
    before = [r[1] for r in conn.execute("PRAGMA table_info(messages)")]
    conn.close()

    eng = setup_engine(tmp_path, monkeypatch)  # runs init_db -> _migrate
    conn = sqlite3.connect(db_path)
    after = [r[1] for r in conn.execute("PRAGMA table_info(messages)")]
    assert after[:len(before)] == before  # nothing renamed/dropped/reordered
    assert NEW_MESSAGE_COLS <= set(after)
    row = conn.execute("SELECT our_score, our_action, score_version FROM messages").fetchone()
    assert row == (9.5, "shadow", None)  # old rows keep their values; not v2
    assert conn.execute("SELECT folder FROM pending_move").fetchone() == (None,)
    eng.init_db()  # second run is a no-op


def test_train_jobs_check_allows_calibrate(eng):
    conn = sqlite3.connect(eng.DB_PATH)
    for kind in ("spam", "ham", "calibrate"):
        conn.execute("INSERT INTO train_jobs(account, folder, kind, max_messages, created_at) "
                     "VALUES('a','Junk',?,10,1)", (kind,))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO train_jobs(account, folder, kind, max_messages, created_at) "
                     "VALUES('a','Junk','bogus',10,1)")
    row = conn.execute("SELECT status, provider_filter, processed FROM train_jobs LIMIT 1").fetchone()
    assert row == ("queued", "any", 0)
    conn.execute("INSERT INTO calibration_results(job_id, account, folder, message_id, final_score) "
                 "VALUES(1,'a','INBOX','m',3.5)")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO calibration_results(job_id, account, folder, message_id) "
                     "VALUES(1,'a','INBOX','m')")


def test_bump_stat_uses_copenhagen_day(eng, monkeypatch):
    conn = sqlite3.connect(eng.DB_PATH)
    # 2026-10-20 22:30 UTC = 2026-10-21 00:30 in Copenhagen (CEST).
    monkeypatch.setattr(eng, "_now", lambda: 1792535400.0)
    eng.bump_stat(conn, "a", "scanned")
    eng.bump_stat(conn, "a", "scanned", 2)
    eng.bump_stat(conn, "a", "moved", 0)  # no-op
    rows = conn.execute("SELECT day, metric, n FROM stats_daily").fetchall()
    assert rows == [("2026-10-21", "scanned", 3)]


def test_stats_day_dst_fallback(eng, monkeypatch):
    monkeypatch.setattr(eng, "_CPH", None)
    assert eng.stats_day(1792535400.0) == "2026-10-21"   # CEST, +2
    assert eng.stats_day(1795127400.0) == "2026-11-19"   # 22:30 UTC = 23:30 CET (+1)
    assert eng.stats_day(1795131000.0) == "2026-11-20"   # 23:30 UTC = 00:30 CET


def test_update_account_status_upserts_json(eng):
    conn = sqlite3.connect(eng.DB_PATH)
    eng.update_account_status(conn, "a", state="idle", capabilities=["IMAP4REV1", "UIDPLUS"],
                              junk_exists=True, folders=[{"name": "INBOX", "flags": [], "messages": 2}])
    eng.update_account_status(conn, "a", detail="hej")
    row = conn.execute("SELECT state, detail, capabilities, junk_exists, folders FROM account_status").fetchone()
    assert row[0] == "idle" and row[1] == "hej" and row[3] == 1
    assert json.loads(row[2]) == ["IMAP4REV1", "UIDPLUS"]
    assert json.loads(row[4])[0]["messages"] == 2
    with pytest.raises(ValueError):
        eng.update_account_status(conn, "a", bogus=1)


# ----- sender rules ---------------------------------------------------------


@pytest.mark.parametrize("text, expected", [
    ("Bob@Example.COM", "bob@example.com"),
    ("example.com", "@example.com"),
    ("@Example.com", "@example.com"),
    ("*@example.com", "@example.com"),
    ("*.example.com", "@example.com"),
    ("<bob@example.com>", "bob@example.com"),
    ("mailto:bob@example.com", "bob@example.com"),
    ("bob@bücher.de", "bob@xn--bcher-kva.de"),
])
def test_normalize_rule_pattern(eng, text, expected):
    assert eng.normalize_rule_pattern(text) == expected


@pytest.mark.parametrize("text", ["", "   ", "a@b@c.dk", "bob@", "bob @x.dk", "@nodot", "a\n@x.dk",
                                  "@-bad-.dk"])
def test_normalize_rule_pattern_rejects(eng, text):
    with pytest.raises(ValueError):
        eng.normalize_rule_pattern(text)


def test_match_sender_rule_precedence(eng):
    conn = sqlite3.connect(eng.DB_PATH)
    conn.row_factory = sqlite3.Row
    g_dom_allow = eng.add_sender_rule(conn, "*", "example.com", "allow", "global", "admin")
    g_dom_block = eng.add_sender_rule(conn, "*", "@bad.example.com", "block", None, "admin")
    assert eng.match_sender_rule(conn, "a", "x@example.com")["id"] == g_dom_allow
    # Subdomain matches the parent domain rule; the longer domain wins.
    assert eng.match_sender_rule(conn, "a", "x@mail.example.com")["id"] == g_dom_allow
    assert eng.match_sender_rule(conn, "a", "x@bad.example.com")["id"] == g_dom_block
    # Exact address beats domain.
    exact = eng.add_sender_rule(conn, "*", "boss@bad.example.com", "allow", None, "admin")
    assert eng.match_sender_rule(conn, "a", "Boss@Bad.Example.com")["id"] == exact
    # Account-specific beats global even if less specific.
    acc_rule = eng.add_sender_rule(conn, "a", "@example.com", "block", None, "admin")
    assert eng.match_sender_rule(conn, "a", "boss@bad.example.com")["id"] == acc_rule
    assert eng.match_sender_rule(conn, "b", "boss@bad.example.com")["id"] == exact
    # Block beats allow at equal specificity (different accounts scope '*').
    conn.execute("DELETE FROM sender_rules")
    allow = eng.add_sender_rule(conn, "*", "@x.dk", "allow")
    assert eng.match_sender_rule(conn, "a", "q@x.dk")["kind"] == "allow"
    eng.add_sender_rule(conn, "*", "@x.dk", "block")  # same pattern: updates kind
    r = eng.match_sender_rule(conn, "a", "q@x.dk")
    assert r["id"] == allow and r["kind"] == "block"
    assert eng.match_sender_rule(conn, "a", None) is None
    assert eng.match_sender_rule(conn, "a", "not-an-address") is None
    assert eng.delete_sender_rule(conn, allow) is True
    assert eng.match_sender_rule(conn, "a", "q@x.dk") is None
    with pytest.raises(ValueError):
        eng.add_sender_rule(conn, "*", "@x.dk", "maybe")


def test_account_rule_beats_identical_global_rule(eng):
    conn = sqlite3.connect(eng.DB_PATH)
    conn.row_factory = sqlite3.Row
    eng.add_sender_rule(conn, "*", "@ab.dk", "block")
    eng.add_sender_rule(conn, "a", "@ab.dk", "allow")
    assert eng.match_sender_rule(conn, "a", "x@ab.dk")["kind"] == "allow"
    assert eng.match_sender_rule(conn, "b", "x@ab.dk")["kind"] == "block"


# The 2.0.2 sender_rules table (before the 2.0.3 'Altid igennem' column).
SENDER_RULES_202 = """
CREATE TABLE sender_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT, account TEXT NOT NULL DEFAULT '*', pattern TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('allow','block')), note TEXT, created_by TEXT,
    created_at INTEGER NOT NULL, hits INTEGER NOT NULL DEFAULT 0, last_hit_at INTEGER,
    UNIQUE(account, pattern));
"""


def test_force_column_migration_is_additive_and_rollback_safe(tmp_path, monkeypatch):
    db_path = tmp_path / "spamfilter.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(SENDER_RULES_202)
    conn.execute("INSERT INTO sender_rules(account, pattern, kind, note, created_by, created_at, hits) "
                 "VALUES('*', '@vexar.example', 'allow', 'Webshop', 'admin', 1, 7)")
    conn.commit()
    before = cols(conn, "sender_rules")
    order_before = [r[1] for r in conn.execute("PRAGMA table_info(sender_rules)")]
    conn.close()

    eng = setup_engine(tmp_path, monkeypatch)  # runs init_db -> _migrate
    eng.init_db()  # idempotent
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    order_after = [r[1] for r in conn.execute("PRAGMA table_info(sender_rules)")]
    assert order_after[:len(order_before)] == order_before and cols(conn, "sender_rules") == before | {"force"}
    r = conn.execute("SELECT * FROM sender_rules").fetchone()
    assert (r["pattern"], r["kind"], r["note"], r["hits"], r["force"]) == ("@vexar.example", "allow", "Webshop", 7, 0)
    assert not eng.rule_is_force(eng.match_sender_rule(conn, "a", "support@vexar.example"))
    # A rolled-back 2.0.2 writes rules without naming the column: they are normal rules.
    conn.execute("INSERT INTO sender_rules(account, pattern, kind, note, created_by, created_at) "
                 "VALUES('*', '@old.example', 'block', NULL, NULL, 2)")
    conn.execute("INSERT INTO sender_rules(account, pattern, kind, note, created_by, created_at) "
                 "VALUES('*', '@vexar.example', 'allow', NULL, 'x', 3) ON CONFLICT(account, pattern) "
                 "DO UPDATE SET kind=excluded.kind")
    assert conn.execute("SELECT force FROM sender_rules WHERE pattern='@old.example'").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM sender_rules").fetchone()[0] == 2
