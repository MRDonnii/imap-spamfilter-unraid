"""SERVICES (B22): the lookalike API the WebUI calls (overview, protected
list editor, 'Ikke en efterligning', 'Set', 'Kør kontrol nu', Oversigt
items) and the weekly report line. Runs against the duck-typed engine
(fakes_services.FakeEngine) - filter.py itself is never imported."""

from __future__ import annotations

import datetime as dt
import json
import sys
import time
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "filter"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import services  # noqa: E402
from fakes_services import FakeEngine, make_account  # noqa: E402
from test_services import _weekly_env  # noqa: E402

import lookalike as lk  # noqa: E402

NOW = int(time.time())


@pytest.fixture
def eng(tmp_path):
    e = FakeEngine(tmp_path, accounts=[make_account(name="bynet", user="ole@bynet.example"),
                                       make_account(name="sofie", user="sofie@molt.example")])
    e.CONFIG_PATH.write_text(yaml.safe_dump({"defaults": {"mode": "move"}, "accounts": [
        {"name": "bynet", "user": "ole@bynet.example", "imap_host": "x"},
        {"name": "sofie", "user": "sofie@molt.example", "imap_host": "x", "protected_domains": ["x.dk"]}]}))
    with e.db() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS engine_state (key TEXT PRIMARY KEY, value TEXT, updated_at INTEGER)")
        lk.ensure_schema(conn)
    return e


def _watch(conn, domain, protected, *, mx=(), a=(), new_at=None, registered=1, acked=None):
    conn.execute("INSERT INTO lookalike_watch(domain, protected, kind, created_at, checked_at, ns, mx, a, registered, "
                 "new_at, new_what, acked_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                 (domain, protected, "homoglyph", NOW - 99, NOW - 50, "[]", json.dumps(list(mx)), json.dumps(list(a)),
                  registered, new_at, "mx" if new_at else None, acked))


def test_settings_defaults_and_per_account(eng):
    st = services.lookalike_settings(engine=eng)
    assert st["configured"] == ["pinsikbing.example", "gravisk.example", "vexar.example"] and not st["custom"]
    assert st["mailbox"] == ["bynet.example", "molt.example"]
    assert st["effective"] == ["pinsikbing.example", "gravisk.example", "vexar.example", "bynet.example", "molt.example"]
    assert st["per_account"] == {"sofie": ["x.dk"]}


def test_set_protected_domains_with_injected_save_config(eng):
    seen = {}

    def save_config(mutator, actor, action, *, account="", detail=""):
        raw = yaml.safe_load(eng.CONFIG_PATH.read_text())
        mutator(raw)
        eng.CONFIG_PATH.write_text(yaml.safe_dump(raw))
        seen.update(actor=actor, action=action, detail=detail)

    r = services.set_protected_domains("bank.dk e-conomic.dk", "admin", engine=eng, save_config=save_config)
    assert r["ok"] and r["code"] == "ok" and r["domains"] == ["bank.dk", "e-conomic.dk"]
    assert seen == {"actor": "admin", "action": "protected_domains",
                    "detail": "n=2 +bank.dk,e-conomic.dk -gravisk.example,pinsikbing.example,vexar.example"}
    assert services.lookalike_settings(engine=eng)["custom"]
    r = services.set_protected_domains(["bank.dk", "e-conomic.dk"], "admin", engine=eng, save_config=save_config)
    assert r["code"] == "unchanged"
    r = services.set_protected_domains([f"d{i}.dk" for i in range(51)], "admin", engine=eng, save_config=save_config)
    assert not r["ok"] and "Højst 50" in r["text"]

    def reject(mutator, actor, action, **kw):
        raise ValueError("ugyldig")

    r = services.set_protected_domains("ny.dk", "admin", engine=eng, save_config=reject)
    assert r["code"] == "rejected" and "ugyldig" in r["text"]
    r = services.set_protected_domains("", "admin", reset=True, engine=eng, save_config=save_config)
    assert r["ok"] and "protected_domains" not in yaml.safe_load(eng.CONFIG_PATH.read_text())["defaults"]


def test_overview_findings_mail_and_allowed(eng):
    with eng.db() as conn:
        _watch(conn, "pinslkbing.example", "pinsikbing.example", mx=["10 mx"], new_at=NOW - 60)
        _watch(conn, "pinsikbing.com", "pinsikbing.example", a=["192.0.2.1"])
        _watch(conn, "pinsikbin.example", "pinsikbing.example", registered=0)
        conn.execute("INSERT INTO lookalike_allow(domain, protected, created_by, created_at) "
                     "VALUES('pinsikbing.com', 'pinsikbing.example', 'admin', ?)", (NOW,))
        for i, syms in enumerate([[{"n": "TH_LOOKALIKE_DOMAIN", "s": 6.0, "o": ["pinslkbing.example", "pinsikbing.example", "from"]}],
                                  [{"n": "TH_LOOKALIKE_URL", "s": 4.0, "o": ["pinslkbing.example", "pinsikbing.example", "url"]}],
                                  [{"n": "TH_LOOKALIKE_URL", "s": 4.0, "o": ["gravlsk.example", "gravisk.example", "url"]}]]):
            conn.execute("INSERT INTO messages(account, message_id, first_seen, last_seen, scanned_at, symbols, "
                         "current_folder) VALUES('bynet', ?, ?, ?, ?, ?, 'INBOX')", (f"m{i}@x", NOW - i, NOW - i, NOW - i, json.dumps(syms)))
        conn.execute("INSERT INTO engine_state VALUES('lookalike_watch_last', ?, ?)",
                     (json.dumps({"finished_at": NOW, "checked": 9, "new": 1}), NOW))
    ov = services.lookalike_overview(engine=eng)
    assert ov["ok"] and ov["last_run"]["checked"] == 9 and ov["candidates"] == 3 and ov["registered"] == 2
    f = {x["domain"]: x for x in ov["findings"]}
    assert set(f) == {"pinslkbing.example", "pinsikbing.com"}
    assert f["pinslkbing.example"]["new"] and f["pinslkbing.example"]["mx"] and not f["pinslkbing.example"]["a"]
    assert f["pinsikbing.com"]["allowed"] and f["pinsikbing.com"]["a"]
    assert ov["findings"][0]["domain"] == "pinslkbing.example"                       # new first
    m = {x["domain"]: x for x in ov["mail"]}
    assert m["pinslkbing.example"]["n"] == 2 and m["pinslkbing.example"]["sender"] and m["pinslkbing.example"]["link"]
    assert m["gravlsk.example"]["link"] and not m["gravlsk.example"]["sender"]
    assert [a["domain"] for a in ov["allowed"]] == ["pinsikbing.com"]


def test_overview_on_a_database_without_the_tables(tmp_path):
    e = FakeEngine(tmp_path, accounts=[make_account(name="bynet", user="ole@bynet.example")])
    e.CONFIG_PATH.write_text(yaml.safe_dump({"accounts": [{"name": "bynet", "user": "ole@bynet.example",
                                                           "imap_host": "x"}]}))
    ov = services.lookalike_overview(engine=e)
    assert ov["findings"] == [] and ov["last_run"] is None
    assert services.lookalike_attention(engine=e) == []


def test_attention_ack_allow(eng):
    with eng.db() as conn:
        _watch(conn, "pinslkbing.example", "pinsikbing.example", mx=["10 mx"], new_at=NOW - 60)
        _watch(conn, "rnolt.example", "molt.example", mx=["10 mx"], new_at=NOW - 30 * 86400)        # too old
        _watch(conn, "m0lt.example", "molt.example", a=["192.0.2.3"], new_at=NOW - 120)
    items = services.lookalike_attention(engine=eng)
    assert [i["domain"] for i in items] == ["pinslkbing.example", "m0lt.example"]
    assert items[0]["text"] == "pinslkbing[.]example (ligner pinsikbing.example) har fået en mailserver"
    assert services.lookalike_ack("admin", domain="m0lt.example", engine=eng)["n"] == 1
    assert services.lookalike_allow("pinslkbing.example", "admin", protected="pinsikbing.example", engine=eng)["code"] == "ok"
    assert services.lookalike_attention(engine=eng) == []
    assert services.lookalike_ack("admin", engine=eng)["n"] == 1            # the old rnolt.example
    assert services.lookalike_ack("admin", engine=eng)["code"] == "unchanged"
    assert services.lookalike_allow("molt.example", "admin", engine=eng)["code"] == "own"
    assert services.lookalike_allow("bynet.example.", "admin", engine=eng)["code"] == "own"
    assert services.lookalike_unallow("nope.dk", "admin", engine=eng)["code"] == "not_found"
    with eng.db() as conn:
        evs = [r[0] for r in conn.execute("SELECT event FROM events WHERE account='*' ORDER BY id")]
    assert evs == ["lookalike_acked", "lookalike_allowed", "lookalike_acked"]


def test_request_run(eng):
    assert services.lookalike_request_run("admin", engine=eng)["code"] == "ok"
    assert services.lookalike_request_run("admin", engine=eng)["code"] == "pending"
    with eng.db() as conn:
        conn.execute("DELETE FROM engine_state")
        # The real clock, not NOW (set at import): in a long full-suite run NOW is many minutes old
        # and "30 s ago" would no longer be too soon.
        now = int(time.time())
        conn.execute("INSERT INTO engine_state VALUES('lookalike_watch_attempt_at', ?, ?)", (str(now - 30), now))
    assert services.lookalike_request_run("admin", engine=eng)["code"] == "too_soon"


def test_weekly_report_lists_new_registrations(tmp_path, monkeypatch):
    eng = _weekly_env(tmp_path)
    monkeypatch.setattr(services, "bayes_stats", lambda engine=None: {"ok": False})
    ts = int(dt.datetime(2026, 10, 21, 4, 10, tzinfo=dt.timezone.utc).timestamp())
    with eng.db() as conn:
        lk.ensure_schema(conn)
        _watch(conn, "pinslkbing.example", "pinsikbing.example", mx=["10 mx"], new_at=ts)
        _watch(conn, "old.dk", "pinsikbing.example", mx=["10 mx"], new_at=ts - 30 * 86400)
    d = services.weekly_data("2026-W43", engine=eng)
    assert d["lookalike"] == [{"domain": "pinslkbing.example", "protected": "pinsikbing.example", "what": "mx"}]
    r = services.render_weekly(d)
    assert "Nye domæner, der ligner jeres:\n- pinslkbing[.]example (ligner pinsikbing.example) har fået en mailserver" in r["text"]
    assert "pinslkbing[.]example" in r["html"] and "pinslkbing.example" not in r["text"]
    short = services.weekly_data("2026-W43", account="bynet", engine=eng)
    assert short["lookalike"] == []
    assert "Nye domæner" not in services.render_weekly(short, full=False)["text"]


def test_weekly_report_without_the_table(tmp_path, monkeypatch):
    eng = _weekly_env(tmp_path)
    monkeypatch.setattr(services, "bayes_stats", lambda engine=None: {"ok": False})
    assert services.weekly_data("2026-W43", engine=eng)["lookalike"] == []
