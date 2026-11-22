"""Rollback guarantee for the 2.3 threat class (B16), attachment policy
(B17) and rescans (B19): the 2.2.0 engine (from git) runs on a database
migrated by 2.3 - threat columns, rescan_queue, attach_rules and zap rows
in pending_move included - and 2.3 rolls forward again."""

from __future__ import annotations

import importlib.util
import json
import logging
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import setup_engine  # noqa: E402
from test_engine_history import _v22_source  # noqa: E402
from test_engine_scan import Harness  # noqa: E402
from test_engine_threat import mail_with_attachments  # noqa: E402

LOG = logging.getLogger("test-rollback23")


def test_rollback_22_engine_on_a_23_threat_and_zap_database(tmp_path, monkeypatch):
    src = _v22_source()
    if src is None:
        pytest.skip("2.2 source not available (no git history)")
    eng = setup_engine(tmp_path, monkeypatch)
    h = Harness(eng, monkeypatch, threshold=10.0)
    # A virus, an attachment threat, a zap candidate and an exception rule.
    h.rspamd.symbols["v@x"] = {"CLAM_VIRUS": {"name": "CLAM_VIRUS", "score": 0.0, "options": ["Eicar"]}}
    h.deliver("v@x", score=1.0)
    import datetime as dt

    h.client.add("INBOX", mail_with_attachments("a@x", [("x.pdf.exe", b"MZ")]),
                 internaldate=dt.datetime.fromtimestamp(h.t, dt.timezone.utc))
    h.deliver("z@x", score=5.0)
    h.scan()
    eng.add_attach_rule(h.db.conn, "*", "@leverandor.dk", actor="admin")
    h.advance(46 * 60)
    h.rspamd.scores["z@x"] = 13.0
    h.rspamd.symbols["z@x"] = {"DBL_SPAM": {"name": "DBL_SPAM", "score": 6.5}}
    eng.zap_pass(h.client, h.db, LOG, h.acc, h.acc.folder_map, h.state)
    assert h.db.conn.execute("SELECT origin FROM pending_move WHERE message_id='z@x'").fetchone()[0] == "zap"
    h.deliver("q@x", score=5.0)
    h.scan()  # stays queued in rescan_queue
    h.advance(eng.ZAP_GRACE_S + 1)
    assert h.row("v@x")["threat"] == "virus" and h.row("a@x")["threat"] == "attachment"
    h.db.close()
    eng.init_db()  # idempotent

    old_dir = tmp_path / "v22"
    old_dir.mkdir()
    (old_dir / "filter_v22b.py").write_text(src)
    spec = importlib.util.spec_from_file_location("filter_v22b", old_dir / "filter_v22b.py")
    old = importlib.util.module_from_spec(spec)
    sys.modules["filter_v22b"] = old
    try:
        spec.loader.exec_module(old)
        assert old.VERSION.startswith("2.2") and old.SCORE_VERSION == eng.SCORE_VERSION
        monkeypatch.setattr(old, "STATE_DIR", tmp_path)
        monkeypatch.setattr(old, "DB_PATH", eng.DB_PATH)
        monkeypatch.setattr(old, "_now", lambda: h.t)
        old.init_db()
        db = old.Db("acct")
        v = db.get_message("v@x")
        assert v["our_action"] == "pending_move" and v["score_version"] == old.SCORE_VERSION
        # 2.2's ham guard still refuses the threat symbols.
        assert old.ham_guard_reason(db.conn, "acct", symbols=v["symbols"], final=v["our_score"],
                                    rspamd_score=v["rspamd_score"])[0] == "phishing"
        a = db.get_message("a@x")
        assert "TH_ATTACH_BLOCK" in {s["n"] for s in json.loads(a["symbols"])}
        # 2.2 reads and executes the pending moves (zap row included).
        uv = h.client.folders["INBOX"].uidvalidity
        due = db.due_pending_moves(uv, 60, folder="INBOX")
        assert {r["message_id"] for r in due} >= {"v@x", "a@x", "z@x"}
        h.client.selected = None
        old_acc = old.Account(**{k: getattr(h.acc, k) for k in (
            "name", "user", "password", "imap_host", "imap_port", "ssl", "inbox", "junk", "trash",
            "spam_train", "trained_spam", "ham_train", "trained_ham", "mode", "threshold",
            "min_threshold_allowed", "reject_score_above", "move_grace_seconds", "learn_grace_seconds",
            "idle_timeout", "poll_interval", "junk_poll_interval", "retention_check_interval",
            "max_moves_per_hour", "max_learns_per_hour", "max_train_per_run", "safe_mode_unseen_cap",
            "junk_retention_days", "trained_retention_days", "learn_from_moves", "auto_special_folders")})
        old_acc.folder_map = old.build_folder_map(old_acc, ".")
        old.execute_due_moves(h.client, db, LOG, old_acc, old_acc.folder_map, old.AccountState())
        assert set(h.client.msgids("Junk")) >= {"v@x", "a@x", "z@x"}
        with db.tx():
            db.upsert_message("new22@x", "INBOX", "a@b.dk", "Hej")
            db.update_message("new22@x", our_score=2.0, our_action="none", score_version=old.SCORE_VERSION)
        old.autolearn_candidates(db, old_acc, old_acc.folder_map)
        old.health_snapshot(db.conn)
        # 2.2 never touches the 2.3 tables; its rules are unaffected by attach_rules.
        assert old.match_sender_rule(db.conn, "acct", "x@leverandor.dk") is None
        # A 2.3 accounts.yml (zap, attachment_block) still loads in 2.2.
        cfg = tmp_path / "accounts23.yml"
        cfg.write_text("defaults:\n  mode: move\n  zap: true\n  attachment_block: [exe, js]\n"
                       "accounts:\n  - name: bynet\n    user: ole@bynet.example\n    imap_host: imap.example.net\n"
                       "    password: x\n    zap: false\n    attachment_block: []\n")
        assert [a.name for a in old.load_account_configs(cfg)] == ["bynet"]
        assert eng.load_account_configs(cfg)[0].zap is False
        db.close()
    finally:
        sys.modules.pop("filter_v22b", None)
    # Rolling forward keeps everything.
    eng.init_db()
    conn = sqlite3.connect(eng.DB_PATH)
    assert conn.execute("SELECT COUNT(*) FROM attach_rules").fetchone()[0] == 1
    assert conn.execute("SELECT message_id FROM rescan_queue").fetchall() == [("q@x",)]
    assert conn.execute("SELECT threat FROM messages WHERE message_id='v@x'").fetchone()[0] == "virus"
    assert conn.execute("SELECT threat FROM messages WHERE message_id='new22@x'").fetchone()[0] is None
    conn.close()
