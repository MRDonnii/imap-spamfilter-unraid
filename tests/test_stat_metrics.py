"""2.11.1: every daily counter the code bumps is registered in
filter.STAT_METRICS - dmarc_reports and dmarc_moved were not, and the log
said "bump_stat: unknown metric"."""
from __future__ import annotations

import logging
import re
import sqlite3
from pathlib import Path

import fakes_engine

FILTER = Path(__file__).resolve().parents[1] / "filter"
# db.bump("x"), bump_stat(conn, acc, "x"), eng.bump_stat(conn, name, "x")
BUMP_RE = re.compile(r'\bbump(?:_stat)?\(\s*(?:[^,()"]+,\s*[^,()"]+,\s*)?"([a-z0-9_]+)"')


def test_dmarc_metrics_are_registered(tmp_path, monkeypatch):
    eng = fakes_engine.setup_engine(tmp_path, monkeypatch)
    assert {"dmarc_reports", "dmarc_moved"} <= eng.STAT_METRICS


def test_every_bumped_metric_literal_is_registered(tmp_path, monkeypatch):
    eng = fakes_engine.setup_engine(tmp_path, monkeypatch)
    found: dict[str, str] = {}
    for path in sorted(FILTER.glob("*.py")):
        for m in BUMP_RE.finditer(path.read_text(encoding="utf-8")):
            found.setdefault(m.group(1), path.name)
    assert {"dmarc_reports", "dmarc_moved", "moved", "user_junked"} <= set(found)  # the scan works
    missing = {k: v for k, v in found.items() if k not in eng.STAT_METRICS}
    assert missing == {}


def test_bump_stat_counts_dmarc_metrics_without_a_warning(tmp_path, monkeypatch, caplog):
    eng = fakes_engine.setup_engine(tmp_path, monkeypatch)
    monkeypatch.setattr(eng, "_UNKNOWN_METRICS_WARNED", set())
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.execute("CREATE TABLE stats_daily(account TEXT, day TEXT, metric TEXT, n INTEGER, "
                 "PRIMARY KEY(account, day, metric))")
    with caplog.at_level(logging.WARNING, logger="filter"):
        eng.bump_stat(conn, "anna", "dmarc_reports")
        eng.bump_stat(conn, "anna", "dmarc_moved", 2)
    assert "unknown metric" not in caplog.text
    got = dict(conn.execute("SELECT metric, n FROM stats_daily").fetchall())
    assert got == {"dmarc_reports": 1, "dmarc_moved": 2}
