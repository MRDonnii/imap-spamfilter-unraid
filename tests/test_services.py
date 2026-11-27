"""services: mail actions, connection test, folders, jobs, status helpers.

Runs against tests/fakes_services.FakeEngine (a stand-in for the `filter`
module over a real SQLite file) - filter.py itself is never imported.
"""

import datetime as dt
import json
import socket
import ssl
import sqlite3
import sys
import time
from pathlib import Path

import pytest
from imapclient.exceptions import IMAPClientError, LoginError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "filter"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import services  # noqa: E402
from fakes_services import (  # noqa: E402
    SCANNET_CAPS, FakeEngine, FakeIMAP, FakeIMAPFactory, make_account,
    make_message,
)

PW = "Sup3r-secret-PW"


@pytest.fixture
def imap():
    return FakeIMAP()


@pytest.fixture
def eng(tmp_path, imap):
    return FakeEngine(tmp_path, imap=imap)


def row(eng, mid, account="acc"):
    with eng.db() as conn:
        return conn.execute("SELECT * FROM messages WHERE account=? AND message_id=?",
                            (account, mid)).fetchone()


def events(eng, name=None):
    with eng.db() as conn:
        rows = conn.execute("SELECT * FROM events ORDER BY id").fetchall()
    return [r for r in rows if name is None or r["event"] == name]


# ---------------------------------------------------------------------------
# test_connection
# ---------------------------------------------------------------------------


def _test_conn(factory, **kw):
    args = dict(host="imap.gigahost.dk", port=993, user="user@example-a.dk", password=PW)
    args.update(kw)
    return services.test_connection(**args, engine=type("E", (), {"IMAPClient": factory})())


def test_connection_ok_gigahost_is_read_only():
    client = FakeIMAP(folders=("INBOX", "Junk", "Trash", "Sent"), password=PW)
    client.add("INBOX", make_message("a@x"))
    client.add("Junk", make_message("b@x"))
    client.add("Junk", make_message("c@x"))
    res = _test_conn(FakeIMAPFactory(client))
    assert res["ok"] is True and res["code"] == "ok"
    assert res["move_method"] == "UIDPLUS"  # Gigahost: no MOVE capability
    assert res["idle"] is True
    assert "UIDPLUS" in res["capabilities"]
    folders = {f["name"]: f for f in res["folders"]}
    assert folders["INBOX"]["messages"] == 1 and folders["Junk"]["messages"] == 2
    assert folders["Sent"]["messages"] is None  # STATUS only for inbox/junk/trash
    assert res["suggested"] == {"junk": "Junk", "trash": "Trash"}
    assert res["folders"][0]["name"] == "INBOX"
    assert client.writes == [] and client.selects == []
    assert client.logged_out


def test_connection_scannet_special_use_and_move():
    client = FakeIMAP(capabilities=SCANNET_CAPS, folders=("INBOX", "Uønsket", "Papirkurv"),
                      special_use={"Uønsket": "\\Junk", "Papirkurv": "\\Trash"})
    res = _test_conn(FakeIMAPFactory(client), host="mail.scannet.dk")
    assert res["move_method"] == "MOVE"
    assert res["suggested"] == {"junk": "Uønsket", "trash": "Papirkurv"}


@pytest.mark.parametrize("exc,code", [
    (socket.gaierror(-2, "Name or service not known"), "dns"),
    (TimeoutError("timed out"), "timeout"),
    (ssl.SSLCertVerificationError(1, "certificate verify failed"), "tls"),
    (ConnectionRefusedError(111, "refused"), "network"),
    (RuntimeError("weird"), "other"),
])
def test_connection_error_codes(exc, code):
    res = _test_conn(FakeIMAPFactory(connect_error=exc))
    assert res["ok"] is False and res["code"] == code
    assert res["text"] == services._CONNECT_TEXT[code]


def test_connection_auth_failure_never_leaks_password_or_server_text():
    client = FakeIMAP(fail_on={"login": LoginError(f"LOGIN user {PW} rejected: NO [AUTH] secret")})
    res = _test_conn(FakeIMAPFactory(client))
    assert res["code"] == "auth" and res["ok"] is False
    dump = json.dumps(res)
    assert PW not in dump and "secret" not in dump and "NO [AUTH]" not in dump
    assert client.logged_out


def test_connection_validates_input_without_connecting():
    f = FakeIMAPFactory()
    assert _test_conn(f, host="bad host;rm")["ok"] is False
    assert _test_conn(f, port=70000)["ok"] is False
    assert _test_conn(f, password="")["code"] == "auth"
    assert f.calls == []


def test_connection_port_143_requires_starttls():
    client = FakeIMAP()
    f = FakeIMAPFactory(client)
    assert _test_conn(f, port=143)["ok"] is True
    assert f.calls[0]["ssl"] is False and client.starttls_done
    client2 = FakeIMAP(fail_on={"starttls": OSError("no starttls")})
    res = _test_conn(FakeIMAPFactory(client2), port=143)
    assert res["code"] == "tls" and client2.logins == 0


def test_connection_list_failure_keeps_ok():
    client = FakeIMAP(fail_on={"list_folders": IMAPClientError(f"boom {PW}")})
    res = _test_conn(FakeIMAPFactory(client))
    assert res["ok"] is True and res["folders"] == []
    assert PW not in json.dumps(res)


# ---------------------------------------------------------------------------
# mail_action
# ---------------------------------------------------------------------------


def test_release_moves_exact_match_learns_ham_and_records(eng, imap):
    imap.add("Junk", make_message("spam-1@x.example"))
    uid = imap.add("Junk", make_message("abc@x.example", subject="Faktura"))
    imap.add("Junk", make_message("xabc@x.example.org"))  # substring decoy (A3)
    with eng.db() as conn:
        conn.execute("INSERT INTO pending_move VALUES('acc', 1, 9, 'abc@x.example', 0, 'INBOX')")
    [res] = services.mail_action("acc", ["<abc@x.example>"], "release", "admin", engine=eng)
    assert res["ok"] is True and res["code"] == "ok"
    assert res["message_id"] == "<abc@x.example>"
    assert "Frigivet" in res["text"]
    assert eng.move_calls == [{"uids": [uid], "dest": "INBOX", "method": "UIDPLUS"}]
    assert len(imap.folders["Junk"]) == 2 and len(imap.folders["INBOX"]) == 1
    [call] = eng.learn_calls
    assert call["kind"] == "ham" and call["message_id"] == "abc@x.example"
    assert call["actor"] == "admin" and call["reason"] == "manual_release"
    r = row(eng, "abc@x.example")
    assert r["user_verdict"] == "ham" and r["our_action"] == "manual_release"
    assert r["current_folder"] == "INBOX" and r["verdict_by"] == "admin"
    assert r["learned_as"] == "ham" and r["pending_learn"] is None
    assert r["subject"] == "Faktura" and r["origin"] is not None
    assert eng.stat("acc", "released") == 1
    assert events(eng, "manual_release")
    with eng.db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM pending_move").fetchone()[0] == 0
    assert imap.logged_out and eng.connects == 1


def test_release_ambiguous_and_not_found_change_nothing(eng, imap):
    # Two DIFFERENT messages (other INTERNALDATE) with the same Message-ID.
    imap.add("Junk", make_message("dup@x"))
    imap.add("Junk", make_message("dup@x"), internaldate=dt.datetime(2026, 10, 19, 8, 0, tzinfo=dt.timezone.utc))
    res = services.mail_action("acc", ["dup@x", "missing@x"], "release", "a", engine=eng)
    assert [r["code"] for r in res] == ["ambiguous", "not_found"]
    assert all(r["ok"] is False and r["text"] for r in res)
    assert eng.move_calls == [] and eng.learn_calls == []
    assert imap.writes == []


def test_release_of_mail_already_in_inbox_does_not_write_unless_flagged(eng, imap):
    imap.add("INBOX", make_message("in@x"))
    uid2 = imap.add("INBOX", make_message("flagged@x"), flags=("$Junk",))
    res = services.mail_action("acc", ["in@x", "flagged@x"], "release", "a", engine=eng)
    assert all(r["ok"] for r in res)
    assert eng.move_calls == []
    assert imap.writes == [("remove_flags", [uid2], ["$Junk"]),
                           ("add_flags", [uid2], ["$NotJunk"])]
    assert row(eng, "in@x")["user_verdict"] == "ham"


def test_mark_spam_creates_missing_junk_and_learns_spam(tmp_path):
    imap = FakeIMAP(capabilities=SCANNET_CAPS, folders=("INBOX", "Trash"))
    eng = FakeEngine(tmp_path, imap=imap,
                     accounts=[make_account(junk="Spamfilter", junk_explicit=True)])
    uid = imap.add("INBOX", make_message("bad@x"))
    [res] = services.mail_action("acc", ["bad@x"], "mark_spam", "bob", engine=eng)
    assert res["ok"] is True
    assert ("create_folder", "Spamfilter") in imap.writes
    assert ("subscribe_folder", "Spamfilter") in imap.writes
    assert eng.move_calls == [{"uids": [uid], "dest": "Spamfilter", "method": "MOVE"}]
    assert eng.learn_calls[0]["kind"] == "spam"
    r = row(eng, "bad@x")
    assert r["user_verdict"] == "spam" and r["our_action"] == "manual_mark_spam"
    assert r["current_folder"] == "Spamfilter" and r["moved_to_junk_at"]
    assert eng.stat("acc", "marked_spam") == 1
    assert events(eng, "folder_created")


def test_mark_spam_declined_by_rspamd_reads_as_already_known(tmp_path):
    """Owner 2026-10-22: 'Det er spam' showed 'rspamd ville ikke lære den (for
    lidt indhold)' when Bayes already knew the mail as spam (rspamd's learn
    condition, HTTP 204). It is a success with an honest text."""
    imap = FakeIMAP(capabilities=SCANNET_CAPS, folders=("INBOX", "Spamfilter"))
    eng = FakeEngine(tmp_path, imap=imap, learn_outcome="declined",
                     accounts=[make_account(junk="Spamfilter", junk_explicit=True)])
    imap.add("Spamfilter", make_message("known@x"))
    [res] = services.mail_action("acc", ["known@x"], "mark_spam", "bob", engine=eng)
    assert res["ok"] is True and res["code"] == "ok"
    assert "genkender den allerede som spam" in res["text"] and "for lidt indhold" not in res["text"]
    assert row(eng, "known@x")["user_verdict"] == "spam"
    imap.add("INBOX", make_message("good@x"))
    [res] = services.mail_action("acc", ["good@x"], "learn_ham", "bob", engine=eng)
    assert res["ok"] is True and "som legitim post" in res["text"]


def test_explicit_junk_wins_over_special_use(tmp_path):
    imap = FakeIMAP(capabilities=SCANNET_CAPS, folders=("INBOX", "Junk", "Spamfilter"),
                    special_use={"Junk": "\\Junk"})
    eng = FakeEngine(tmp_path, imap=imap,
                     accounts=[make_account(junk="Spamfilter", junk_explicit=True)])
    imap.add("INBOX", make_message("m@x"))
    services.mail_action("acc", ["m@x"], "mark_spam", "a", engine=eng)
    assert eng.move_calls[0]["dest"] == "Spamfilter"


def test_learn_actions_are_read_only(eng, imap):
    imap.add("Junk", make_message("j@x"))
    imap.add("INBOX", make_message("i@x"))
    res = services.mail_action("acc", ["j@x", "i@x"], "learn_ham", "a", engine=eng)
    assert [r["ok"] for r in res] == [True, True]
    assert imap.writes == [] and eng.move_calls == []
    assert all(ro for _f, ro in imap.selects)
    assert [c["kind"] for c in eng.learn_calls] == ["ham", "ham"]
    assert row(eng, "j@x")["current_folder"] == "Junk"
    assert row(eng, "j@x")["user_verdict"] == "ham"


def test_rate_limited_learn_stays_pending(tmp_path, imap):
    eng = FakeEngine(tmp_path, imap=imap, learn_outcome="rate_limited")
    imap.add("Junk", make_message("r@x"))
    [res] = services.mail_action("acc", ["r@x"], "release", "a", engine=eng)
    assert res["ok"] is True and res["code"] == "learn_rate_limited"
    r = row(eng, "r@x")
    assert r["pending_learn"] == "ham" and r["learned_as"] is None


def test_oversize_message_is_moved_but_not_learned(eng, imap):
    eng.MAX_FETCH_BYTES = 100
    imap.add("Junk", make_message("big@x", size_pad=500))
    [res] = services.mail_action("acc", ["big@x"], "release", "a", engine=eng)
    assert res["ok"] is True and res["code"] == "learn_too_large"
    assert eng.move_calls and eng.learn_calls == []


def test_input_validation_dedupe_and_limit(eng, imap):
    assert services.mail_action("acc", ["a@x"], "delete", "a", engine=eng)[0]["code"] == "invalid_action"
    imap.add("Junk", make_message("a@x"))
    res = services.mail_action("acc", ["a@x", "<a@x>", "bad id\r\nX", 'q"@x'], "release", "a",
                               engine=eng)
    assert [r["code"] for r in res] == ["ok", "ok", "invalid_id", "invalid_id"]
    assert res[1]["message_id"] == "<a@x>"
    assert len(eng.move_calls) == 1
    many = [f"m{i}@x" for i in range(205)]
    res = services.mail_action("acc", many, "learn_ham", "a", engine=eng)
    assert len(res) == 205 and [r["code"] for r in res[200:]] == ["limit"] * 5
    assert services.mail_action("acc", "a@x", "learn_ham", "a", engine=eng)[0]["message_id"] == "a@x"


def test_connect_and_config_errors_are_mapped(tmp_path, imap):
    eng = FakeEngine(tmp_path, imap=imap, connect_error=LoginError(f"bad {PW}"))
    [res] = services.mail_action("acc", ["a@x"], "release", "a", engine=eng)
    assert res["code"] == "auth" and PW not in json.dumps(res)
    eng = FakeEngine(tmp_path, imap=imap, connect_error=OSError(f"x {PW}"))
    assert services.mail_action("acc", ["a@x"], "release", "a", engine=eng)[0]["code"] == "connect"
    eng = FakeEngine(tmp_path, imap=imap, secret=None)
    assert services.mail_action("acc", ["a@x"], "release", "a", engine=eng)[0]["code"] == "no_secret"
    eng = FakeEngine(tmp_path, imap=imap)
    assert services.mail_action("nope", ["a@x"], "release", "a", engine=eng)[0]["code"] == "no_account"
    eng.config_error = ValueError("broken yaml")
    assert services.mail_action("acc", ["a@x"], "release", "a", engine=eng)[0]["code"] == "config"


def test_imap_error_during_action_is_contained(eng, imap):
    imap.add("Junk", make_message("a@x"))
    imap.fail_on["move"] = IMAPClientError(f"NO move failed {PW}")
    imap.add("Junk", make_message("b@x"))
    res = services.mail_action("acc", ["a@x", "b@x"], "release", "a", engine=eng)
    assert [r["code"] for r in res] == ["move_failed", "move_failed"]
    assert PW not in json.dumps(res)
    assert eng.learn_calls == [] and row(eng, "a@x") is None
    imap.fail_on = {"search": IMAPClientError("server gone")}
    res = services.mail_action("acc", ["a@x"], "release", "a", engine=eng)
    assert res[0]["code"] == "imap_error" and "server gone" not in res[0]["text"]


# ---------------------------------------------------------------------------
# Folders
# ---------------------------------------------------------------------------


def test_account_folders_reads_status_without_imap(eng):
    assert services.account_folders("acc", engine=eng) == []
    with eng.db() as conn:
        conn.execute("INSERT INTO account_status(account, updated_at, state, folders) "
                     "VALUES('acc', 1, 'idle', ?)",
                     (json.dumps([{"name": "INBOX", "flags": [], "messages": 3}, "junk"]),))
    assert services.account_folders("acc", engine=eng) == [
        {"name": "INBOX", "flags": [], "messages": 3}]
    assert eng.connects == 0


def test_refresh_folders_updates_status_read_only(eng, imap):
    imap.add("Junk", make_message("a@x"))
    out = services.refresh_folders("acc", engine=eng)
    assert {f["name"]: f["messages"] for f in out} == {"INBOX": 0, "Junk": 1, "Trash": None}
    assert imap.writes == [] and imap.selects == []
    with eng.db() as conn:
        st = conn.execute("SELECT * FROM account_status WHERE account='acc'").fetchone()
    assert st["move_method"] == "UIDPLUS" and st["junk_exists"] == 1
    assert json.loads(st["folder_map"])["junk"] == "Junk"
    assert json.loads(st["folders"]) == out


def test_refresh_folders_errors_are_service_errors(tmp_path, imap):
    eng = FakeEngine(tmp_path, imap=imap, connect_error=LoginError(PW))
    with pytest.raises(services.ServiceError) as ei:
        services.refresh_folders("acc", engine=eng)
    assert ei.value.code == "auth" and PW not in ei.value.text
    with pytest.raises(services.ServiceError):
        services.refresh_folders("nope", engine=FakeEngine(tmp_path, imap=imap))


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------


def test_queue_list_and_cancel_jobs(eng):
    j1 = services.queue_train_job("acc", "Junk", "spam", 100, actor="admin", engine=eng)
    j2 = services.queue_train_job("acc", "INBOX", "ham", 50, min_age_days=30, seen_only=True,
                                  provider_filter="provider_clean", engine=eng)
    j3 = services.queue_calibration("acc", "INBOX", engine=eng)
    jobs = {j["id"]: j for j in services.list_train_jobs(engine=eng)}
    assert jobs[j1]["status"] == "queued" and jobs[j1]["created_by"] == "admin"
    assert jobs[j2]["seen_only"] == 1 and jobs[j2]["min_age_days"] == 30
    assert jobs[j3]["kind"] == "calibrate" and jobs[j3]["max_messages"] == 300
    assert [j["id"] for j in services.list_train_jobs(engine=eng)] == [j3, j2, j1]

    assert services.cancel_train_job(j1, engine=eng) is True
    with eng.db() as conn:
        conn.execute("UPDATE train_jobs SET status='running', total=10, processed=5 WHERE id=?", (j2,))
    assert services.cancel_train_job(j2, engine=eng) is True
    jobs = {j["id"]: j for j in services.list_train_jobs(engine=eng)}
    assert jobs[j1]["status"] == "cancelled" and jobs[j1]["finished_at"]
    assert jobs[j2]["status"] == "cancel_requested" and jobs[j2]["percent"] == 50
    assert services.cancel_train_job(j1, engine=eng) is False  # already final


@pytest.mark.parametrize("kw", [
    dict(account="nope"), dict(kind="eggs"), dict(max_messages=0),
    dict(max_messages=99999), dict(folder=""), dict(folder="a\r\nb"),
    dict(min_age_days=-1), dict(provider_filter="x"), dict(max_messages="many"),
])
def test_queue_train_job_validation(eng, kw):
    args = dict(account="acc", folder="Junk", kind="spam", max_messages=10)
    args.update(kw)
    with pytest.raises(ValueError):
        services.queue_train_job(**args, engine=eng)


def test_calibration_results_and_summary(eng):
    j = services.queue_calibration("acc", "INBOX", max_messages=10, engine=eng)
    with eng.db() as conn:
        for i, s in enumerate((1.0, 5.5, 9.0, 12.5)):
            conn.execute("INSERT INTO calibration_results(job_id, account, folder, message_id, "
                         "final_score, symbols) VALUES(?,?,?,?,?,?)",
                         (j, "acc", "INBOX", f"m{i}", s, json.dumps([{"n": "X", "s": s}])))
    rows = services.calibration_results(j, engine=eng)
    assert [r["final_score"] for r in rows] == [12.5, 9.0, 5.5, 1.0]
    assert rows[0]["symbols"][0]["n"] == "X"
    summ = services.calibration_summary(j, thresholds=[5.0, 8.0, 10.0], engine=eng)
    assert summ["count"] == 4 and summ["median"] == pytest.approx(7.25)
    assert [c["n"] for c in summ["caught_at"]] == [3, 2, 1]
    assert sum(b["n"] for b in summ["histogram"]) == 4


# ---------------------------------------------------------------------------
# rspamd / misc
# ---------------------------------------------------------------------------


class _Resp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload
        self.text = payload if isinstance(payload, str) else json.dumps(payload)

    def json(self):
        if isinstance(self._payload, str):
            raise ValueError("not json")
        return self._payload


def test_bayes_stats_parses_stat(monkeypatch, eng):
    (eng.STATE_DIR / "controller.password").write_text("ctrl-pw\n")
    seen = {}

    def fake_get(url, headers=None, timeout=None):
        seen.update(url=url, headers=headers)
        return _Resp(200, {"statfiles": [
            {"symbol": "BAYES_SPAM", "revision": 240, "users": 1},
            {"symbol": "BAYES_HAM", "revision": 150, "users": 1}]})

    monkeypatch.setattr(services.requests, "get", fake_get)
    st = services.bayes_stats(engine=eng)
    assert {k: st[k] for k in ("ok", "spam_learned", "ham_learned", "min_learns", "users")} == {
        "ok": True, "spam_learned": 240, "ham_learned": 150, "min_learns": 200, "users": 1}
    # 2.3 round 2: the active pool and where the numbers come from (no rebuild yet = rspamd's totals).
    assert st["pool"] == "hjemmeserver" and st["pools"] == ["hjemmeserver"] and st["counts_source"] == "rspamd"
    assert (st["all_pools_spam"], st["all_pools_ham"]) == (240, 150)
    assert st["active"] is False and "ikke aktiv endnu" in st["text"] and "200" in st["text"]
    assert seen["url"].endswith("/stat") and seen["headers"]["Password"] == "ctrl-pw"


def test_bayes_stats_and_health_when_rspamd_down(monkeypatch, eng):
    def boom(*a, **k):
        raise services.requests.ConnectionError("down")

    monkeypatch.setattr(services.requests, "get", boom)
    assert services.bayes_stats(engine=eng)["ok"] is False
    h = services.rspamd_health(engine=eng)
    assert h["ok"] is False and h["text"]


def test_rspamd_health_ok(monkeypatch, eng):
    urls = []

    def fake_get(url, headers=None, timeout=None):
        urls.append(url)
        return _Resp(200, "pong\r\n")

    monkeypatch.setattr(services.requests, "get", fake_get)
    h = services.rspamd_health(engine=eng)
    assert h["ok"] and h["controller_ms"] is not None and h["scanner_ms"] is not None
    assert urls == ["http://rspamd.test:11334/ping", "http://rspamd.test:11333/ping"]


def test_request_reload_touches_flag_and_logs(eng):
    assert services.request_reload("mode changed", "admin", engine=eng) is True
    assert eng.reloads == 1 and (eng.STATE_DIR / "reload_requested").exists()
    ev = events(eng, "reload_requested")
    assert ev and "admin" in ev[0]["detail"]


def test_known_providers_and_suggestions():
    kp = services.known_providers()
    assert kp["molt.example"]["imap_host"] == "mail.scannet.dk" and kp["molt.example"]["imap_port"] == 993
    assert kp["bynet.example"]["imap_host"] == "imap.gigahost.dk"
    assert services.suggest_imap("x@bynet.example")["guess"] is False
    g = services.suggest_imap("x@firma.dk")
    assert g["imap_host"] == "imap.firma.dk" and g["guess"] is True
    assert services.suggest_imap("garbage")["imap_host"] == ""


def test_host_status_missing_fresh_and_stale(eng):
    assert services.host_status(engine=eng) == {"available": False, "stale": True, "age_s": None}
    p = eng.STATE_DIR / "host-status.json"
    p.write_text(json.dumps({"ts": int(time.time()) - 30, "containers": {}}))
    st = services.host_status(engine=eng)
    assert st["available"] and not st["stale"] and st["containers"] == {}
    p.write_text(json.dumps({"ts": int(time.time()) - 3600}))
    assert services.host_status(engine=eng)["stale"] is True
    p.write_text("{not json")
    assert services.host_status(engine=eng)["available"] is False


def test_backup_status(eng):
    assert services.backup_status(engine=eng) == {"available": False}
    (eng.STATE_DIR / "backup-status.json").write_text(
        json.dumps({"ok": True, "ts": int(time.time()) - 60, "size": 10}))
    st = services.backup_status(engine=eng)
    assert st["available"] and st["ok"] and 50 <= st["age_s"] <= 120


def test_normalize_message_id():
    assert services.normalize_message_id("<a@b>") == "a@b"
    assert services.normalize_message_id(" a@b ") == "a@b"
    for bad in ("", "a b@c", "a\r\n@b", 'a"@b', "æ@b", None, "x" * 600):
        assert services.normalize_message_id(bad) is None


def test_queue_train_job_refuses_inbox_as_spam(eng):
    for folder in ("INBOX", "Inbox"):
        with pytest.raises(ValueError, match="Indbakken"):
            services.queue_train_job("acc", folder, "spam", 300, engine=eng)
    assert services.queue_train_job("acc", "INBOX", "ham", 300, engine=eng)
    assert services.queue_train_job("acc", "INBOX", "spam", 10, allow_inbox_spam=True, engine=eng)


# ---------------------------------------------------------------------------
# Review fixes: provider's own spam folder, \Deleted copies
# ---------------------------------------------------------------------------


def _spamfilter_engine(tmp_path, **imap_kw):
    imap = FakeIMAP(capabilities=SCANNET_CAPS, folders=("INBOX", "Junk", "Spamfilter", "Trash"),
                    special_use={"Junk": "\\Junk"}, **imap_kw)
    eng = FakeEngine(tmp_path, imap=imap, accounts=[make_account(junk="Spamfilter", junk_explicit=True)])
    return imap, eng


def test_release_from_provider_junk(tmp_path):
    """'Fanget af udbyder' rows: the mail sits in the provider's Junk, not
    in Spamfilter - Frigiv must find and release it there."""
    imap, eng = _spamfilter_engine(tmp_path)
    uid = imap.add("Junk", make_message("prov@x"))
    [res] = services.mail_action("acc", ["prov@x"], "release", "admin", engine=eng)
    assert res["ok"] is True, res
    assert eng.move_calls == [{"uids": [uid], "dest": "INBOX", "method": "MOVE"}]
    assert not imap.folders["Junk"] and len(imap.folders["INBOX"]) == 1
    r = row(eng, "prov@x")
    assert r["our_action"] == "manual_release" and r["user_verdict"] == "ham"
    assert r["current_folder"] == "INBOX"


def test_mark_spam_and_learn_find_mail_in_provider_junk(tmp_path):
    imap, eng = _spamfilter_engine(tmp_path)
    imap.add("Junk", make_message("p1@x"))
    imap.add("Junk", make_message("p2@x"))
    [res] = services.mail_action("acc", ["p1@x"], "mark_spam", "admin", engine=eng)
    assert res["ok"] is True and "udbyderens spam-mappe" in res["text"]
    assert eng.move_calls == [] and row(eng, "p1@x")["current_folder"] == "Junk"
    [res] = services.mail_action("acc", ["p2@x"], "learn_spam", "admin", engine=eng)
    assert res["ok"] is True, res


def test_release_of_deleted_flagged_copy_clears_deleted_first(tmp_path):
    """A mark-as-deleted client left \\Deleted on the Spamfilter copy: the
    released copy must not arrive in the inbox already deleted."""
    imap, eng = _spamfilter_engine(tmp_path)
    uid = imap.add("Spamfilter", make_message("fp@x"), flags=("\\Seen", "\\Deleted"))
    [res] = services.mail_action("acc", ["fp@x"], "release", "admin", engine=eng)
    assert res["ok"] is True
    assert ("remove_flags", [uid], ["\\Deleted"]) in imap.writes
    [m] = imap.folders["INBOX"].values()
    assert "\\Deleted" not in m.flags and "\\Seen" in m.flags


# ===========================================================================
# 2.1 SERVICES: find_mail / move_found_to_inbox
# ===========================================================================

UTC = dt.timezone.utc
RECENT = dt.datetime.now(UTC) - dt.timedelta(days=2)
FIND_FOLDERS = ("INBOX", "Spamfilter", "Junk", "Uønsket e-mail", "Trash", "Sent", "Arkiv")


@pytest.fixture(autouse=True)
def _reset_service_caches(monkeypatch):
    monkeypatch.setattr(services, "UNDO_PER_SECOND", 1e9)  # limiter tested separately
    services._find_last.clear()
    services._sizes_cache.clear()
    services._undo_threads.clear()
    services._undo_schema_ok.clear()
    yield


def find_env(tmp_path, *, caps=SCANNET_CAPS, folders=FIND_FOLDERS, **acc):
    client = FakeIMAP(capabilities=caps, folders=folders, special_use={"Junk": "\\Junk"}
                      if "Junk" in folders else {})
    acct = make_account(junk="Spamfilter", junk_explicit=True, mode="move", threshold=10.0, **acc)
    return FakeEngine(tmp_path, imap=client, accounts=[acct]), client


def seed(eng, mid, **cols):
    now = int(time.time())
    base = dict(account="acc", message_id=mid, first_seen=now, last_seen=now,
                current_folder="INBOX")
    base.update(cols)
    with eng.db() as conn:
        conn.execute(f"INSERT INTO messages({','.join(base)}) VALUES({','.join('?' * len(base))})",
                     tuple(base.values()))


def test_find_mail_searches_spam_like_and_trash_read_only(tmp_path):
    eng, imap = find_env(tmp_path)
    shop = "Vexar Shop <support@vexar.example>"
    imap.add("Uønsket e-mail", make_message("o1@vexar.example", sender=shop, subject="Ny ordre #1234"),
             internaldate=RECENT)
    imap.add("Trash", make_message("o2@vexar.example", sender=shop, subject="Faktura"), internaldate=RECENT)
    imap.add("Spamfilter", make_message("o3@vexar.example", sender=shop, subject="Kontaktformular"),
             internaldate=RECENT, flags=("\\Seen",))
    imap.add("Sent", make_message("s1@x", sender=shop, subject="sent"), internaldate=RECENT)
    imap.add("Arkiv", make_message("a1@x", sender=shop, subject="arkiv"), internaldate=RECENT)
    imap.add("Junk", make_message("old@x", sender=shop),
             internaldate=dt.datetime.now(UTC) - dt.timedelta(days=60))
    imap.add("INBOX", make_message("other@x", sender="x@y.dk", subject="Andet"), internaldate=RECENT)

    res = services.find_mail("acc", "vexar.example", since_days=30, actor="admin", engine=eng)

    assert res["ok"] is True and res["code"] == "ok"
    kinds = {g["name"]: g["kind"] for g in res["folders"]}
    assert kinds == {"INBOX": "inbox", "Spamfilter": "filter_junk", "Junk": "provider_junk",
                     "Uønsket e-mail": "spam_like", "Trash": "trash"}
    assert "Sent" not in res["searched"] and "Arkiv" not in res["searched"]
    groups = {g["name"]: g for g in res["folders"]}
    assert groups["Uønsket e-mail"]["explanation"] == \
        "Ligger i Uønsket e-mail – dit mailprogram har flyttet den."
    assert "spamfilteret" in groups["Spamfilter"]["explanation"]
    assert "papirkurv" in groups["Trash"]["explanation"] or "slettet" in groups["Trash"]["explanation"]
    hit = groups["Uønsket e-mail"]["hits"][0]
    assert hit["message_id"] == "o1@vexar.example" and hit["subject"] == "Ny ordre #1234"
    assert hit["sender"] == "support@vexar.example" and hit["sender_name"] == "Vexar Shop"
    assert hit["can_move"] is True and hit["received_at"] and hit["date"]
    assert groups["Spamfilter"]["hits"][0]["seen"] is True
    assert groups["Junk"]["hits"] == []  # older than the window
    assert res["total"] == 3
    # Groups with hits first.
    assert [g["name"] for g in res["folders"]][:3] == ["Spamfilter", "Uønsket e-mail", "Trash"]
    # Strictly read-only: EXAMINE everywhere, no writes, header-light fetches.
    assert imap.writes == [] and all(ro for _f, ro in imap.selects)
    assert {f for f, _ro in imap.selects} == set(kinds)
    for _uids, items in imap.fetches:
        assert set(items) <= {b"ENVELOPE", b"INTERNALDATE", b"FLAGS"}
    crit = imap.searches[0]
    assert crit[0] == "SINCE" and crit[2:] == ["OR", "FROM", "vexar.example", "SUBJECT", "vexar.example"]
    assert set(imap.search_charsets) == {"UTF-8"}
    assert imap.logged_out and eng.connect_kwargs[-1] == {"timeout": services.FIND_TIMEOUT_S}
    assert "q='vexar.example'" in res["audit_detail"] and "hits=3" in res["audit_detail"]


def test_find_mail_decodes_utf7_folder_names_and_matches_utf8_subjects(tmp_path):
    eng, imap = find_env(tmp_path, folders=("INBOX", "Spamfilter", "U&APg-nsket e-mail", "Papirkurv"))
    imap.add("U&APg-nsket e-mail", make_message("u@x", subject="=?utf-8?q?R=C3=B8dgr=C3=B8d?="),
             internaldate=RECENT)
    imap.add("Papirkurv", make_message("p@x", subject="Rødgrød med fløde"), internaldate=RECENT)
    res = services.find_mail("acc", "Rødgrød", engine=eng)
    groups = {g["name"]: g for g in res["folders"]}
    assert groups["U&APg-nsket e-mail"]["label"] == "Uønsket e-mail"
    assert groups["U&APg-nsket e-mail"]["kind"] == "spam_like"
    assert groups["U&APg-nsket e-mail"]["explanation"].startswith("Ligger i Uønsket e-mail")
    assert groups["U&APg-nsket e-mail"]["hits"][0]["subject"] == "Rødgrød"
    assert groups["Papirkurv"]["kind"] == "trash" and groups["Papirkurv"]["hits"]
    assert ("U&APg-nsket e-mail", True) in imap.selects  # selected by its raw name


def test_find_mail_limits_hits_per_folder_newest_first(tmp_path):
    eng, imap = find_env(tmp_path)
    uids = [imap.add("Spamfilter", make_message(f"n{i}@x", subject=f"Nyhedsbrev {i}"),
                     internaldate=RECENT) for i in range(25)]
    res = services.find_mail("acc", "Nyhedsbrev", engine=eng)
    g = next(g for g in res["folders"] if g["name"] == "Spamfilter")
    assert g["count"] == 25 and g["truncated"] is True and len(g["hits"]) == 20
    assert [h["uid"] for h in g["hits"]] == list(reversed(uids))[:20]


def test_find_mail_throttles_live_search_per_account(tmp_path, monkeypatch):
    eng, imap = find_env(tmp_path)
    now = [1000.0]
    monkeypatch.setattr(services, "_clock", lambda: now[0])
    assert services.find_mail("acc", "abc", engine=eng)["ok"] is True
    now[0] += 4
    res = services.find_mail("acc", "abc", engine=eng)
    assert res["ok"] is False and res["code"] == "throttled" and res["retry_after"] == 6.0
    assert "Vent 6 sekunder" in res["text"] and eng.connects == 1
    # DB-only lookups are never throttled.
    assert services.find_mail("acc", "abc", live=False, engine=eng)["ok"] is True
    now[0] += 6
    assert services.find_mail("acc", "abc", engine=eng)["ok"] is True and eng.connects == 2


def test_find_mail_db_lookup_without_imap_escapes_like(tmp_path):
    eng, imap = find_env(tmp_path)
    now = int(time.time())
    seed(eng, "d1@x", sender="kunde@gravisk.example", subject="Spørgsmål", received_at=now - 3600,
         our_action="moved_to_junk", our_score=12.5, current_folder="Spamfilter")
    seed(eng, "d2@x", sender="a@b.dk", subject="100% gratis", received_at=now - 3600)
    seed(eng, "d3@x", sender="kunde@gravisk.example", subject="Gammel", received_at=now - 90 * 86400)
    res = services.find_mail("acc", "gravisk", since_days=30, live=False, engine=eng)
    assert res["ok"] and [r["message_id"] for r in res["db"]] == ["d1@x"]
    assert res["db"][0]["our_action"] == "moved_to_junk" and res["folders"] == []
    assert eng.connects == 0 and "1 besked fundet" in res["text"]
    assert [r["message_id"] for r in services.find_mail("acc", "0%", live=False, engine=eng)["db"]] == ["d2@x"]
    assert services.find_mail("acc", "_", live=False, engine=eng)["code"] == "invalid"


def _mailcheck_run(eng, domain, mx_hosts):
    import mailcheck

    results = {"domains": [{"domain": domain, "checks": [
        mailcheck.item(f"{domain}:mx", "MX", "ok", "Mail modtages", hosts=list(mx_hosts))]}]}
    with sqlite3.connect(eng.DB_PATH) as conn:
        mailcheck.ensure_schema(conn)
        conn.execute("INSERT INTO mailcheck_runs(started_at, finished_at, reason, status, results) "
                     "VALUES(1, 2, 'test', 'ok', ?)", (json.dumps(results),))


def test_find_mail_hints_when_nothing_is_found(tmp_path, monkeypatch):
    monkeypatch.setattr(services, "_find_last", {})
    eng, imap = find_env(tmp_path, imap_host="mail.scannet.dk")
    # 2.11.1: the SpamExperts tip only while the domain's MX points there.
    _mailcheck_run(eng, "example-a.dk", ["mx.spamexperts.com", "fallbackmx.spamexperts.eu"])
    res = services.find_mail("acc", "ingen-match", since_days=30, engine=eng)
    assert res["ok"] and res["total"] == 0 and res["spamexperts"] is True
    text = " ".join(res["hints"])
    assert "ældre end 30 dage" in text and "SpamExperts" in text and "karantænen hos Scannet" in text
    # SpamExperts gone (the newest run sees Scannet's own MX): no tip.
    _mailcheck_run(eng, "example-a.dk", ["mx1.scannet.dk", "mx2.scannet.dk"])
    monkeypatch.setattr(services, "_find_last", {})
    res = services.find_mail("acc", "ingen-match", since_days=30, engine=eng)
    assert res["hints"] and res["spamexperts"] is False
    assert not any("SpamExperts" in x for x in res["hints"])
    # A hit: no hints. A Gigahost account: no SpamExperts hint.
    imap.add("INBOX", make_message("h@x", subject="ingen-match her"))
    monkeypatch.setattr(services, "_find_last", {})
    assert services.find_mail("acc", "ingen-match", engine=eng)["hints"] == []
    eng2, _imap2 = find_env(tmp_path / "g", imap_host="imap.gigahost.dk")
    monkeypatch.setattr(services, "_find_last", {})
    res = services.find_mail("acc", "ingen-match", since_days=365, engine=eng2)
    assert res["code"] == "ok"
    assert res["hints"] and not any("SpamExperts" in x or "ældre end" in x for x in res["hints"])
    # DB-only lookups and errors carry the key too (always a list).
    assert services.find_mail("acc", "x", engine=eng)["hints"] == []


@pytest.mark.parametrize("text", ["", "a", " a ", "x" * 101, "ab\x00c", "ab\x7fc", None])
def test_find_mail_rejects_bad_queries(tmp_path, text):
    eng, imap = find_env(tmp_path)
    res = services.find_mail("acc", text, engine=eng)
    assert res["ok"] is False and res["code"] == "invalid" and eng.connects == 0


def test_find_mail_errors_are_mapped_and_safe(tmp_path):
    eng, imap = find_env(tmp_path)
    eng.connect_error = LoginError(f"LOGIN user {PW} failed")
    res = services.find_mail("acc", "abc", engine=eng)
    assert res["code"] == "auth" and PW not in json.dumps(res)
    eng.connect_error = None
    imap.fail_on["search"] = IMAPClientError(f"weird {PW}")
    services._find_last.clear()
    res = services.find_mail("acc", "abcd", since_days=7, engine=eng)
    assert res["ok"] is True and res["code"] == "partial" and res["errors"]
    assert PW not in json.dumps(res, ensure_ascii=False)
    assert services.find_mail("nope", "abc", engine=eng)["code"] == "no_account"


def test_find_mail_ascii_falls_back_without_charset(tmp_path):
    eng, imap = find_env(tmp_path)
    imap.reject_charset = True
    imap.add("INBOX", make_message("i@x", subject="Ordre"), internaldate=RECENT)
    res = services.find_mail("acc", "Ordre", engine=eng)
    assert res["ok"] and res["total"] == 1 and None in imap.search_charsets
    services._find_last.clear()
    assert services.find_mail("acc", "Ødelagt", engine=eng)["code"] == "partial"


def test_find_mail_folders_param_only_narrows(tmp_path):
    eng, imap = find_env(tmp_path)
    res = services.find_mail("acc", "abc", folders=["Trash", "Sent"], engine=eng)
    assert [g["name"] for g in res["folders"]] == ["Trash"]  # Sent is never searchable


def test_find_mail_marks_known_rows(tmp_path):
    eng, imap = find_env(tmp_path)
    imap.add("Spamfilter", make_message("k@x", subject="Kendt"), internaldate=RECENT)
    seed(eng, "k@x", our_action="moved_to_junk", our_score=14.0, current_folder="Spamfilter")
    res = services.find_mail("acc", "Kendt", engine=eng)
    hit = res["folders"][0]["hits"][0]
    assert hit["known"] is True and hit["our_action"] == "moved_to_junk" and hit["our_score"] == 14.0


def test_move_found_to_inbox_moves_exactly_one_without_learning(tmp_path):
    eng, imap = find_env(tmp_path)
    imap.add("Uønsket e-mail", make_message("o1@vexar.example", subject="Ordre"), internaldate=RECENT)
    imap.add("Uønsket e-mail", make_message("o10@vexar.example", subject="Ordre 10"), internaldate=RECENT)
    seed(eng, "o1@vexar.example", current_folder="Uønsket e-mail", pending_learn="spam",
         our_action="user_junked", user_verdict="spam")
    res = services.move_found_to_inbox("acc", "Uønsket e-mail", "<o1@vexar.example>", "admin", engine=eng)
    assert res["ok"] is True and res["code"] == "ok" and res["learned"] is None
    assert res["text"] == "Flyttet fra Uønsket e-mail til indbakken."
    assert [m["dest"] for m in eng.move_calls] == ["INBOX"]
    assert len(imap.folders["Uønsket e-mail"]) == 1  # the substring match stays
    assert eng.learn_calls == []
    r = row(eng, "o1@vexar.example")
    assert r["user_verdict"] == "ham" and r["our_action"] == "manual_release"
    assert r["current_folder"] == "INBOX" and r["pending_learn"] is None and r["verdict_by"] == "admin"
    assert events(eng, "found_to_inbox")
    assert eng.stat("acc", "released") == 0  # not a filter false positive
    assert not any(w[0] in ("expunge", "delete_messages") for w in imap.writes)


def test_move_found_to_inbox_learn_and_unknown_row(tmp_path):
    eng, imap = find_env(tmp_path)
    imap.add("Spamfilter", make_message("f@x", subject="Faktura"), internaldate=RECENT)
    res = services.move_found_to_inbox("acc", "Spamfilter", "f@x", "admin", learn=True, engine=eng)
    assert res["ok"] and res["learned"] == "learned" and "lært som legitim" in res["text"]
    assert eng.learn_calls[0]["kind"] == "ham"
    r = row(eng, "f@x")
    assert r["subject"] == "Faktura" and r["learned_as"] == "ham" and r["origin"] == "manual"
    assert eng.stat("acc", "released") == 1  # out of the filter's own folder


@pytest.mark.parametrize("folder", ["INBOX", "Sent", "Arkiv", "Nope"])
def test_move_found_to_inbox_refuses_other_folders(tmp_path, folder):
    eng, imap = find_env(tmp_path)
    imap.folders.setdefault(folder, {})
    imap.add(folder, make_message("z@x"))
    res = services.move_found_to_inbox("acc", folder, "z@x", "admin", engine=eng)
    assert res["ok"] is False and res["code"] == "folder_not_allowed"
    assert imap.writes == [] and eng.move_calls == []


def test_move_found_to_inbox_ambiguous_not_found_and_duplicates(tmp_path):
    eng, imap = find_env(tmp_path)
    imap.add("Junk", make_message("d@x"), internaldate=RECENT)
    imap.add("Junk", make_message("d@x"), internaldate=RECENT - dt.timedelta(hours=1))
    assert services.move_found_to_inbox("acc", "Junk", "d@x", "a", engine=eng)["code"] == "ambiguous"
    assert services.move_found_to_inbox("acc", "Junk", "missing@x", "a", engine=eng)["code"] == "not_found"
    assert services.move_found_to_inbox("acc", "Junk", "bad id", "a", engine=eng)["code"] == "invalid_id"
    assert eng.move_calls == []
    # Identical copies in the filter's folder (interrupted UIDPLUS move): newest wins.
    imap.add("Spamfilter", make_message("c@x"), internaldate=RECENT)
    newest = imap.add("Spamfilter", make_message("c@x"), internaldate=RECENT)
    res = services.move_found_to_inbox("acc", "Spamfilter", "c@x", "a", engine=eng)
    assert res["ok"] and eng.move_calls[-1]["uids"] == [newest]
    assert len(imap.folders["Spamfilter"]) == 1


def test_move_found_to_inbox_premarks_and_restores_on_failure(tmp_path):
    eng, imap = find_env(tmp_path, caps=(b"IMAP4REV1", b"UIDPLUS"))
    imap.add("Trash", make_message("t@x"), internaldate=RECENT, flags=("\\Deleted",))
    seed(eng, "t@x", current_folder="Trash", our_action="none")
    seen_during_move = {}
    original = eng.imap_move

    def failing_move(client, uids, dest, *, capabilities):
        seen_during_move.update(dict(row(eng, "t@x")))
        raise IMAPClientError("COPY failed")

    eng.imap_move = failing_move
    res = services.move_found_to_inbox("acc", "Trash", "t@x", "a", engine=eng)
    assert res["code"] == "move_failed" and res["ok"] is False
    # The engine saw a sticky release while the move ran ...
    assert seen_during_move["our_action"] == "manual_release"
    assert seen_during_move["current_folder"] == "INBOX"
    # ... and the row is back to what it was after the failure.
    r = row(eng, "t@x")
    assert r["our_action"] == "none" and r["current_folder"] == "Trash" and r["user_verdict"] is None
    eng.imap_move = original
    res = services.move_found_to_inbox("acc", "Trash", "t@x", "a", engine=eng)
    assert res["ok"] and eng.move_calls[-1]["method"] == "UIDPLUS"
    assert ("remove_flags", [1], ["\\Deleted"]) in imap.writes  # never arrives deleted
    msg = next(iter(imap.folders["INBOX"].values()))
    assert "\\Deleted" not in msg.flags


# ===========================================================================
# 2.1 SERVICES: bulk undo
# ===========================================================================


def undo_env(tmp_path, n=5, *, caps=SCANNET_CAPS):
    eng, imap = find_env(tmp_path, caps=caps)
    base = int(time.time()) - 3600
    for i in range(n):
        imap.add("Spamfilter", make_message(f"u{i}@x", subject=f"U{i}"), internaldate=RECENT)
        seed(eng, f"u{i}@x", current_folder="Spamfilter", our_action="moved_to_junk",
             moved_to_junk_at=base + i * 60, our_score=11.0, score_version=2)
    return eng, imap, base


def undo_job_row(eng, jid):
    with eng.db() as conn:
        return conn.execute("SELECT * FROM undo_jobs WHERE id=?", (jid,)).fetchone()


def test_preview_undo_counts_window_and_skips_gone(tmp_path):
    eng, imap, base = undo_env(tmp_path, 4)
    with eng.db() as conn:
        conn.execute("UPDATE messages SET current_folder='gone' WHERE message_id='u3@x'")
    p = services.preview_undo("acc", base, base + 150, engine=eng)
    assert p["ok"] and p["count"] == 3 and p["gone"] == 0
    assert [i["message_id"] for i in p["items"]] == ["u0@x", "u1@x", "u2@x"]
    p = services.preview_undo("acc", base, base + 3600, engine=eng)
    assert p["count"] == 3 and p["gone"] == 1 and "allerede væk" in p["text"]
    assert services.preview_undo("acc", base + 10, base, engine=eng)["ok"] is False
    assert services.preview_undo("acc", 0, 200 * 86400, engine=eng)["ok"] is False
    assert eng.connects == 0


def test_undo_moves_puts_mail_back_without_learning(tmp_path):
    eng, imap, base = undo_env(tmp_path, 5)
    seed(eng, "released@x", current_folder="INBOX", our_action="manual_release",
         moved_to_junk_at=base + 30, user_verdict="ham")
    imap.add("Spamfilter", make_message("outside@x"), internaldate=RECENT)
    seed(eng, "outside@x", current_folder="Spamfilter", our_action="moved_to_junk",
         moved_to_junk_at=base - 7200)
    res = services.undo_moves("acc", base, base + 3600, "admin", engine=eng)
    assert res["ok"] and res["status"] == "done" and res["code"] == "ok"
    assert (res["total"], res["moved"], res["not_found"], res["failed"]) == (5, 5, 0, 0)
    assert "5 af 5 flyttet tilbage" in res["text"] and f"job={res['job_id']}" in res["audit_detail"]
    assert sorted(m["dest"] for m in eng.move_calls) == ["INBOX"] * 5
    assert eng.learn_calls == []
    for i in range(5):
        r = row(eng, f"u{i}@x")
        assert r["our_action"] == "manual_release" and r["current_folder"] == "INBOX"
        assert r["user_verdict"] is None and r["verdict_by"] == "undo:admin"
    assert row(eng, "outside@x")["our_action"] == "moved_to_junk"
    assert list(m.raw for m in imap.folders["Spamfilter"].values()) == [make_message("outside@x")]
    assert len(events(eng, "undo_release")) == 5 and events(eng, "undo_job_done")
    assert eng.stat("acc", "released") == 0
    assert not any(w[0] in ("expunge", "delete_messages") for w in imap.writes)


def test_undo_moves_with_learning_sets_verdict(tmp_path):
    eng, imap, base = undo_env(tmp_path, 3)
    res = services.undo_moves("acc", base, base + 3600, "admin", learn=True, engine=eng)
    assert res["moved"] == 3 and res["learned"] == 3
    assert [c["kind"] for c in eng.learn_calls] == ["ham"] * 3
    assert all(row(eng, f"u{i}@x")["user_verdict"] == "ham" for i in range(3))
    assert eng.stat("acc", "released") == 3


def test_undo_skips_changed_and_counts_missing(tmp_path):
    eng, imap, base = undo_env(tmp_path, 3)
    del imap.folders["Spamfilter"][2]  # u1 deleted by the user meanwhile
    jid_res = services.undo_moves("acc", base, base + 3600, "a", engine=eng)
    assert (jid_res["moved"], jid_res["not_found"]) == (2, 1)
    with eng.db() as conn:
        codes = dict(conn.execute("SELECT message_id, code FROM undo_items").fetchall())
    assert codes["u1@x"] == "not_found"


def test_undo_is_chunked_resumable_and_continues_in_background(tmp_path, monkeypatch):
    eng, imap, base = undo_env(tmp_path, 5)
    monkeypatch.setattr(services, "UNDO_CHUNK", 2)
    monkeypatch.setattr(services, "_spawn_undo_thread", lambda e, j: None)
    res = services.undo_moves("acc", base, base + 3600, "a", wait_s=0, engine=eng)
    assert res["status"] == "queued" and res["moved"] == 2 and res["remaining"] == 3
    assert services.undo_moves("acc", base, base + 3600, "a", engine=eng)["code"] == "busy"
    # The trainer thread (or a restart) continues where it stopped.
    assert services.run_pending_undo_once(engine=eng) == res["job_id"]
    job = services.undo_job(res["job_id"], engine=eng)
    assert job["status"] == "done" and job["moved"] == 5 and job["percent"] == 100
    assert len(eng.move_calls) == 5  # nothing moved twice
    assert services.run_pending_undo_once(engine=eng) is None


def test_undo_background_thread_finishes(tmp_path, monkeypatch):
    eng, imap, base = undo_env(tmp_path, 4)
    monkeypatch.setattr(services, "UNDO_CHUNK", 1)
    res = services.undo_moves("acc", base, base + 3600, "a", wait_s=0, engine=eng)
    t = services._undo_threads[res["job_id"]]
    t.join(5)
    assert services.undo_job(res["job_id"], engine=eng)["status"] == "done"
    assert len(eng.move_calls) == 4


def test_undo_connection_loss_fails_then_resumes(tmp_path, monkeypatch):
    eng, imap, base = undo_env(tmp_path, 4)
    original = eng.imap_move
    calls = {"n": 0}

    def flaky(client, uids, dest, *, capabilities):
        calls["n"] += 1
        if calls["n"] == 3:
            raise ConnectionResetError("socket closed")
        return original(client, uids, dest, capabilities=capabilities)

    eng.imap_move = flaky
    res = services.undo_moves("acc", base, base + 3600, "a", engine=eng)
    assert res["status"] == "failed" and res["ok"] is False and res["moved"] == 2
    assert "afbrudt" in res["text"]
    assert row(eng, "u2@x")["our_action"] == "moved_to_junk"  # restored
    eng.imap_move = original
    job = services.resume_undo_job(res["job_id"], engine=eng)
    assert job["status"] == "done" and job["moved"] == 4
    assert len(imap.folders["INBOX"]) == 4 and imap.folders["Spamfilter"] == {}


def test_undo_cancel_and_recover(tmp_path, monkeypatch):
    eng, imap, base = undo_env(tmp_path, 3)
    monkeypatch.setattr(services, "UNDO_CHUNK", 1)
    monkeypatch.setattr(services, "_spawn_undo_thread", lambda e, j: None)
    res = services.undo_moves("acc", base, base + 3600, "a", wait_s=0, engine=eng)
    assert services.cancel_undo_job(res["job_id"], engine=eng) is True
    assert undo_job_row(eng, res["job_id"])["status"] == "cancelled"
    assert services.run_pending_undo_once(engine=eng) is None
    # A job left 'running' by a crash is resumed after restart.
    with eng.db() as conn:
        conn.execute("UPDATE undo_jobs SET status='running' WHERE id=?", (res["job_id"],))
    services.recover_undo_jobs(engine=eng)
    assert undo_job_row(eng, res["job_id"])["status"] == "queued"
    assert services.list_undo_jobs("acc", engine=eng)[0]["id"] == res["job_id"]


def test_undo_paces_moves_for_the_isp(tmp_path, monkeypatch):
    eng, imap, base = undo_env(tmp_path, 3)
    monkeypatch.setattr(services, "UNDO_PER_SECOND", 10.0)
    monkeypatch.setattr(services, "UNDO_CHUNK", 1)
    monkeypatch.setattr(services, "_spawn_undo_thread", lambda e, j: None)
    res = services.undo_moves("acc", base, base + 3600, "a", wait_s=0, engine=eng)
    assert res["status"] == "queued" and res["moved"] == 1
    slept = []
    assert services.run_undo_job(res["job_id"], engine=eng, sleep=slept.append) == "done"
    assert len(slept) == 2 and all(0 < x <= 0.1 for x in slept)


def test_undo_nothing_and_validation(tmp_path):
    eng, imap, base = undo_env(tmp_path, 0)
    res = services.undo_moves("acc", base, base + 60, "a", engine=eng)
    assert res["ok"] and res["code"] == "nothing" and res["job_id"] is None and eng.connects == 0
    assert services.undo_moves("acc", base + 60, base, "a", engine=eng)["code"] == "invalid"
    assert services.undo_moves("nope", base, base + 60, "a", engine=eng)["code"] == "no_account"


# ===========================================================================
# 2.1 SERVICES: threshold suggestion
# ===========================================================================


def scored(eng, scores, *, verdict=None, action="none", version=2, rule=None, prefix="s",
           symbols=None):
    now = int(time.time())
    syms = json.dumps(symbols, separators=(",", ":")) if symbols is not None else None
    with eng.db() as conn:
        conn.executemany(
            "INSERT INTO messages(account, message_id, first_seen, last_seen, current_folder, "
            "our_score, our_action, user_verdict, score_version, scanned_at, rule_hit, symbols) "
            "VALUES('acc', ?, ?, ?, 'INBOX', ?, ?, ?, ?, ?, ?, ?)",
            [(f"{prefix}{i}-{s}@x", now, now, s, action, verdict, version, now - 3600, rule, syms)
             for i, s in enumerate(scores)])


def sugg_env(tmp_path, threshold=10.0):
    acct = make_account(mode="move", threshold=threshold, junk="Spamfilter", junk_explicit=True)
    return FakeEngine(tmp_path, accounts=[acct])


def test_threshold_suggestion_raises_above_released_mail(tmp_path):
    eng = sugg_env(tmp_path)
    scored(eng, [1.0] * 30 + [12.0] * 10, prefix="bg")
    scored(eng, [11.2, 10.4], verdict="ham", action="manual_release", prefix="fp")
    s = services.threshold_suggestion("acc", engine=eng)
    assert s["ok"] and s["change"] == "raise" and s["recommended"] == 12.0
    assert s["recommended"] > s["max_released_score"] == 11.2
    assert "Hæv grænsen fra 10 til 12" in s["text"] and "11,2" in s["text"]
    assert s["counts"]["released_over_current"] == 2
    g = {x["threshold"]: x for x in s["grid"]}
    assert g[12.0]["released_hit"] == 0 and g[11.0]["released_hit"] == 1


def test_threshold_suggestion_lowers_for_missed_spam(tmp_path):
    eng = sugg_env(tmp_path)
    scored(eng, [0.5] * 40, prefix="bg")
    scored(eng, [8.6, 9.1, 9.4], verdict="spam", action="user_junked", prefix="miss")
    scored(eng, [4.0], verdict="ham", action="manual_release", prefix="fp")
    s = services.threshold_suggestion("acc", engine=eng)
    assert s["change"] == "lower" and s["recommended"] == 8.5
    assert "Sænk grænsen fra 10 til 8,5" in s["text"]
    assert s["counts"]["missed_below_current"] == 3 and s["counts"]["extra_at_recommended"] == 0


def test_threshold_suggestion_never_lowers_onto_released_mail(tmp_path):
    eng = sugg_env(tmp_path)
    scored(eng, [0.5] * 40, prefix="bg")
    scored(eng, [8.6, 9.1, 9.4], verdict="spam", action="manual_mark_spam", prefix="miss")
    scored(eng, [9.0], verdict="ham", action="user_rescued", prefix="fp")
    s = services.threshold_suggestion("acc", engine=eng)
    assert s["recommended"] is not None and s["recommended"] > 9.0
    assert s["recommended"] == 10.0 and s["change"] == "keep"


def test_threshold_suggestion_keep_low_data_and_impossible(tmp_path):
    eng = sugg_env(tmp_path)
    scored(eng, [1.0] * 5)
    s = services.threshold_suggestion("acc", engine=eng)
    assert s["change"] == "none" and s["recommended"] is None and "For få data" in s["text"]
    scored(eng, [1.0] * 30 + [14.0] * 5, prefix="more")
    s = services.threshold_suggestion("acc", engine=eng)
    assert s["change"] == "keep" and s["recommended"] == 10.0 and s["confidence"] == "medium"
    scored(eng, [16.0], verdict="ham", action="manual_release", prefix="hi")
    s = services.threshold_suggestion("acc", engine=eng)
    assert s["recommended"] is None and "tilladelsesregel" in s["text"]


def test_threshold_suggestion_ignores_old_scores_and_rule_hits(tmp_path):
    eng = sugg_env(tmp_path)
    scored(eng, [1.0] * 30, prefix="bg")
    scored(eng, [13.0], verdict="ham", action="manual_release", version=1, prefix="v1")
    scored(eng, [13.0], verdict="ham", action="manual_release", rule="allow:3", prefix="rule")
    s = services.threshold_suggestion("acc", engine=eng)
    assert s["max_released_score"] is None and s["change"] == "keep"


def test_threshold_suggestion_ignores_protected_recipient_mail(tmp_path):
    # Engine E9: mail to info@gravisk.example / info@pinsikbing.example is decided by
    # protected_threshold (18), not by the account threshold. A released
    # shop order at 16 must not block (or push up) the suggestion, and a
    # protected miss must not pull it down.
    eng = sugg_env(tmp_path)
    prot = [{"n": "TH_PROTECTED_RCPT", "s": 0.0, "o": ["info@gravisk.example", "grænse=18"]},
            {"n": "R_SPF_SOFTFAIL", "s": 3.0}]
    scored(eng, [1.0] * 30 + [14.0] * 5, prefix="bg",
           symbols=[{"n": "BAYES_HAM", "s": -3.0}])
    scored(eng, [16.0], verdict="ham", action="manual_release", prefix="shop", symbols=prot)
    scored(eng, [6.5, 7.0, 7.5], verdict="spam", action="user_junked", prefix="pmiss", symbols=prot)
    s = services.threshold_suggestion("acc", engine=eng)
    assert s["max_released_score"] is None and s["change"] == "keep" and s["recommended"] == 10.0
    assert s["counts"]["protected_excluded"] == 4
    assert s["counts"]["scored"] == 35 and s["counts"]["missed"] == 0
    # The same released mail WITHOUT the protected marker does count.
    scored(eng, [16.0], verdict="ham", action="manual_release", prefix="plain")
    s = services.threshold_suggestion("acc", engine=eng)
    assert s["recommended"] is None and s["max_released_score"] == 16.0


def test_threshold_suggestion_property_never_hits_released(tmp_path):
    import random
    for seed_n in range(25):
        rnd = random.Random(seed_n)
        eng = sugg_env(tmp_path / str(seed_n), threshold=rnd.choice([6.0, 8.0, 10.0, 12.5]))
        scored(eng, [round(rnd.uniform(-5, 25), 1) for _ in range(rnd.randint(0, 80))], prefix="bg")
        ham = [round(rnd.uniform(0, 16), 1) for _ in range(rnd.randint(0, 4))]
        scored(eng, ham, verdict="ham", action="manual_release", prefix="fp")
        scored(eng, [round(rnd.uniform(4, 12), 1) for _ in range(rnd.randint(0, 6))],
               verdict="spam", action="user_junked", prefix="miss")
        s = services.threshold_suggestion("acc", engine=eng)
        if s["recommended"] is not None:
            assert 6.0 <= s["recommended"] <= 15.0 and (s["recommended"] * 2) % 1 == 0
            assert all(h < s["recommended"] for h in ham), (seed_n, s)


# ===========================================================================
# 2.1 SERVICES: digest data, folder sizes, calibration blind score
# ===========================================================================


def test_digest_data_counts_per_mailbox(tmp_path):
    accts = [make_account(name="bynet", mode="move", threshold=10.0),
             make_account(name="molt", mode="move", display_name="Molt (Ole)"),
             make_account(name="molt-sofie", enabled=False, mode="shadow")]
    eng = FakeEngine(tmp_path, accounts=accts)
    with eng.db() as conn:
        for acc, metric, n in [("bynet", "moved", 4), ("bynet", "released", 1),
                               ("bynet", "marked_spam", 1), ("bynet", "user_junked", 2),
                               ("molt", "scanned", 12), ("bynet", "moved", 99)]:
            day = "2026-10-20" if n != 99 else "2026-10-19"
            conn.execute("INSERT INTO stats_daily VALUES(?,?,?,?)", (acc, day, metric, n))
    d = services.digest_data("2026-10-20", engine=eng)
    by = {a["account"]: a for a in d["accounts"]}
    assert set(by) == {"bynet", "molt"}  # paused account without activity left out
    assert (by["bynet"]["moved"], by["bynet"]["released"], by["bynet"]["marked"]) == (4, 1, 3)
    assert by["molt"]["name"] == "Molt (Ole)" and by["molt"]["moved"] == 0
    assert d["totals"]["moved"] == 4 and d["empty"] is False and "suggestions" not in d
    d = services.digest_data("2026-10-18", suggestions=True, engine=eng)
    assert d["empty"] is True and {s["account"] for s in d["suggestions"]} == {"bynet", "molt"}
    json.dumps(d)
    with pytest.raises(ValueError):
        services.digest_data("yesterday", engine=eng)


def test_folder_sizes_status_only_and_cached(tmp_path, monkeypatch):
    eng, imap = find_env(tmp_path)
    imap.add("INBOX", make_message("a@x"), flags=("\\Seen",))
    imap.add("INBOX", make_message("b@x"))
    imap.add("Spamfilter", make_message("c@x"))
    now = [5000.0]
    monkeypatch.setattr(services, "_clock", lambda: now[0])
    res = services.folder_sizes("acc", engine=eng)
    assert res["ok"] and res["cached"] is False
    f = {x["kind"]: x for x in res["folders"]}
    assert (f["inbox"]["messages"], f["inbox"]["unseen"]) == (2, 1)
    assert (f["filter_junk"]["name"], f["filter_junk"]["messages"]) == ("Spamfilter", 1)
    assert f["provider_junk"]["name"] == "Junk" and f["provider_junk"]["messages"] == 0
    assert imap.selects == [] and imap.writes == []
    now[0] += 300
    assert services.folder_sizes("acc", engine=eng)["cached"] is True and eng.connects == 1
    now[0] += 301
    assert services.folder_sizes("acc", engine=eng)["cached"] is False and eng.connects == 2
    # Errors are cached briefly and never leak.
    eng.connect_error = LoginError(PW)
    services._sizes_cache.clear()
    err = services.folder_sizes("acc", engine=eng)
    assert err["ok"] is False and err["code"] == "auth" and PW not in json.dumps(err)
    now[0] += 30
    assert services.folder_sizes("acc", engine=eng)["cached"] is True
    now[0] += 31
    assert services.folder_sizes("acc", engine=eng)["cached"] is False


def test_folder_sizes_missing_spamfilter_folder(tmp_path):
    eng, imap = find_env(tmp_path, folders=("INBOX", "Junk"))
    f = {x["kind"]: x for x in services.folder_sizes("acc", engine=eng)["folders"]}
    assert f["filter_junk"]["exists"] is False and f["filter_junk"]["messages"] is None


def test_calibration_summary_reports_blind_score_from_symbols(eng):
    syms = [{"n": "BAYES_SPAM", "s": 5.0}, {"n": "TH_PROVIDER_SPAM", "s": 4.0},
            {"n": "SPAM_FLAG", "s": 1.0}, {"n": "RBL_X", "s": 3.0}]
    with eng.db() as conn:
        for i, final in enumerate([13.0, 2.0]):
            conn.execute(
                "INSERT INTO calibration_results(job_id, account, folder, message_id, final_score, "
                "rspamd_score, symbols) VALUES(7, 'acc', 'Junk', ?, ?, ?, ?)",
                (f"c{i}@x", final, final, json.dumps(syms if i == 0 else [])))
    s = services.calibration_summary(7, [3.0, 10.0], engine=eng)
    assert [c["n"] for c in s["caught_at"]] == [1, 1]
    assert s["blind"]["max"] == 3.0 and [c["n"] for c in s["blind"]["caught_at"]] == [1, 0]
    assert s["blind_from_symbols"] is True and "Bayes" in s["blind_note"]
    rows = services.calibration_results(7, engine=eng)
    assert rows[0]["blind_score"] == 3.0


class _CopiedMoveError(IMAPClientError):
    copied = True


def test_move_to_inbox_keeps_bookkeeping_when_copy_landed(tmp_path):
    eng, imap = find_env(tmp_path, caps=(b"IMAP4REV1", b"UIDPLUS"))
    imap.add("Spamfilter", make_message("cp@x"), internaldate=RECENT)
    seed(eng, "cp@x", current_folder="Spamfilter", our_action="moved_to_junk",
         moved_to_junk_at=int(time.time()) - 60)

    def copy_then_fail(client, uids, dest, *, capabilities):
        client.copy(uids, dest)
        raise _CopiedMoveError("expunge after copy failed")

    eng.imap_move = copy_then_fail
    res = services.move_found_to_inbox("acc", "Spamfilter", "cp@x", "a", engine=eng)
    assert res["ok"] is True and res["code"] == "copied" and "originalen" in res["text"]
    r = row(eng, "cp@x")
    # The inbox copy must look like a release to the engine, not like a rescue.
    assert r["current_folder"] == "INBOX" and r["our_action"] == "manual_release"
    assert len(imap.folders["INBOX"]) == 1 and len(imap.folders["Spamfilter"]) == 1
    assert "source_kept" in events(eng, "found_to_inbox")[0]["detail"]


def test_release_picks_newest_of_identical_copies_in_filter_folder(eng, imap):
    imap.add("Junk", make_message("twin@x"))
    newest = imap.add("Junk", make_message("twin@x"))
    [res] = services.mail_action("acc", ["twin@x"], "release", "a", engine=eng)
    assert res["ok"] is True and eng.move_calls[0]["uids"] == [newest]
    assert len(imap.folders["Junk"]) == 1 and len(imap.folders["INBOX"]) == 1


# ===========================================================================
# 2.1 SERVICES against the REAL engine (filter.py) - find / move back / undo
# ===========================================================================
#
# The unit tests above use FakeEngine. These run the real filter.py loop on
# the RFC-accurate EngineMailbox (fakes_engine semantics) next to the real
# services, for Gigahost (UIDPLUS, no MOVE) and Scannet (MOVE) capabilities,
# and prove what the live system depends on: mail put back by undo_moves /
# move_found_to_inbox stays in the inbox through later engine loops (junk
# polls, reconciliation, autolearn window), is never learned unless the user
# asked, and nothing but the exact message is ever touched.

import logging  # noqa: E402
from types import SimpleNamespace  # noqa: E402

LIVE_LOG = logging.getLogger("services-live")
GIGA = (b"IMAP4REV1", b"IDLE", b"UIDPLUS", b"NAMESPACE", b"CHILDREN")  # no MOVE
SCAN = (b"IMAP4REV1", b"IDLE", b"MOVE", b"SPECIAL-USE", b"UIDPLUS", b"NAMESPACE")


@pytest.fixture
def live(tmp_path, monkeypatch):
    import fakes_engine
    from fakes_services import EngineMailbox

    eng = fakes_engine.setup_engine(tmp_path, monkeypatch)
    clock = SimpleNamespace(t=float(int(time.time())))
    monkeypatch.setattr(eng, "_now", lambda: clock.t)
    rspamd = fakes_engine.FakeRspamd(eng.requests).install(monkeypatch, eng)
    monkeypatch.setattr(services, "_find_last", {})
    monkeypatch.setattr(services, "_sizes_cache", {})
    boxes: dict[str, EngineMailbox] = {}
    connects: list[str] = []

    def fake_connect(acc, password=None, *, timeout=None):
        assert password == "imap-secret"
        connects.append(acc.name)
        client = boxes[acc.name].session()
        client.login(acc.user, password)
        return client

    monkeypatch.setattr(eng, "connect", fake_connect)
    return SimpleNamespace(eng=eng, clock=clock, rspamd=rspamd, boxes=boxes, tmp=tmp_path,
                           connects=connects, Mailbox=EngineMailbox)


def live_account(live, caps, *, extra_folders=(), **account_keys):
    secret = live.tmp / "secret"
    secret.write_text("imap-secret\n")
    secret.chmod(0o600)
    cfg = {"defaults": {"bayes_user": "hjemmeserver", "junk_retention_days": 0,
                        "trained_retention_days": 0},
           "accounts": [{"name": "anna", "user": "ole@example-a.dk", "imap_host": "imap.example.net",
                         "password_file": str(secret), "mode": "move", "threshold": 10.0,
                         "junk": "Spamfilter", "move_grace_seconds": 60, **account_keys}]}
    live.eng.CONFIG_PATH.write_text(json.dumps(cfg))
    acc = live.eng.load_account_configs(live.eng.CONFIG_PATH)[0]
    special = {"Junk": "\\Junk"} if b"SPECIAL-USE" in caps else None
    box = live.Mailbox(capabilities=caps, folders=("INBOX", "Junk", "Trash", *extra_folders),
                       special_use=special)
    live.boxes[acc.name] = box
    box.login(acc.user, "imap-secret")
    h = SimpleNamespace(acc=acc, box=box, db=live.eng.Db(acc.name), state=live.eng.AccountState())
    live.eng._on_connected(box, h.db, LIVE_LOG, acc, h.state)
    live_loop(live, h)  # first pass: bookmark only
    return h


def live_loop(live, h, n=1, step=0.0, *, reconcile=False):
    """n engine loops. The engine schedules junk polls / reconciliation on
    time.monotonic(), so they are forced here: every loop polls the junk
    folders, reconcile=True also runs the 6-hourly reconciliation."""
    for _ in range(n):
        h.state.last_junk_poll = float("-inf")
        if reconcile:
            h.state.last_junk_reconcile = float("-inf")
        live.eng._loop_once(h.box, h.db, LIVE_LOG, h.acc, h.state)
        live.clock.t += step


def live_mail(live, h, folder, msgid, *, subject="Hej", sender="a@example.org", score=None):
    if score is not None:
        live.rspamd.scores[msgid] = score
    when = dt.datetime.fromtimestamp(live.clock.t, dt.timezone.utc)
    return h.box.add(folder, make_message(msgid, subject=subject, sender=sender), internaldate=when)


def live_row(h, msgid):
    return h.db.conn.execute("SELECT * FROM messages WHERE account=? AND message_id=?",
                             (h.acc.name, msgid)).fetchone()


def learned_ids(live):
    out = []
    for call in live.rspamd.learn_calls:
        m = re.search(rb"Message-ID: <([^>]+)>", call["data"])
        out.append((call["url"].rsplit("/", 1)[-1], m.group(1).decode() if m else None))
    return out


def catch_spam(live, h, ids):
    """Deliver spam, let the real engine score and move it to Spamfilter."""
    for mid in ids:
        live_mail(live, h, "INBOX", mid, subject=f"Vind {mid}", score=13.0)
    live_loop(live, h)
    live.clock.t += 61
    live_loop(live, h)
    assert sorted(h.box.msgids("Spamfilter")) == sorted(ids)
    for mid in ids:
        assert live_row(h, mid)["our_action"] == "moved_to_junk"


import re  # noqa: E402


@pytest.mark.parametrize("caps", [GIGA, SCAN], ids=["gigahost", "scannet"])
def test_live_undo_puts_mail_back_and_the_engine_leaves_it_alone(live, caps):
    h = live_account(live, caps)
    live_mail(live, h, "INBOX", "ham@x", score=0.5)
    catch_spam(live, h, ["s1@x", "s2@x", "old@x"])
    # 'old@x' was moved before the chosen window.
    h.db.conn.execute("UPDATE messages SET moved_to_junk_at=? WHERE message_id='old@x'",
                      (int(live.clock.t) - 7200,))
    since, until = int(live.clock.t) - 3600, int(live.clock.t) + 60
    prev = services.preview_undo("anna", since, until, engine=live.eng)
    assert prev["ok"] and prev["count"] == 2
    assert {i["message_id"] for i in prev["items"]} == {"s1@x", "s2@x"}
    h.box.writes.clear()
    learns_before = list(live.rspamd.learn_calls)

    res = services.undo_moves("anna", since, until, "admin", engine=live.eng)
    assert res["ok"] and res["code"] == "ok" and (res["moved"], res["total"]) == (2, 2)
    assert sorted(h.box.msgids("INBOX")) == ["ham@x", "s1@x", "s2@x"]
    assert h.box.msgids("Spamfilter") == ["old@x"]
    names = h.box.write_names()
    assert "expunge" not in names  # never a plain EXPUNGE
    if caps is GIGA:
        assert set(names) == {"copy", "add_flags", "uid_expunge"}
        # \Deleted + UID EXPUNGE only ever on the two Spamfilter copies.
        for w in h.box.writes:
            if w[0] in ("add_flags", "uid_expunge"):
                assert w[1] == "Spamfilter" and len(w[2]) == 1
    else:
        assert set(names) == {"move"}
    assert live.rspamd.learn_calls == learns_before  # learn=False: nothing learned
    for mid in ("s1@x", "s2@x"):
        r = live_row(h, mid)
        assert r["our_action"] == "manual_release" and r["user_verdict"] is None
        assert r["pending_learn"] is None and r["current_folder"] == "INBOX"

    # Junk polls, a reconciliation and the 3-day autolearn window later:
    h.box.writes.clear()
    live_loop(live, h, n=4, step=400)
    live.clock.t += 7 * 3600
    live_loop(live, h, reconcile=True)
    live.clock.t += 4 * 86400
    live_loop(live, h, n=2, step=61)
    assert sorted(m for m in h.box.msgids("INBOX")) == ["ham@x", "s1@x", "s2@x"]
    moved_back = [w for w in h.box.writes if w[0] in ("move", "copy", "uid_expunge")
                  and w[1] == "INBOX"]
    assert moved_back == []
    assert not [x for x in learned_ids(live) if x[1] in ("s1@x", "s2@x")]
    for mid in ("s1@x", "s2@x"):
        r = live_row(h, mid)
        assert r["our_action"] == "manual_release" and r["learned_as"] is None
        assert r["pending_learn"] is None
    assert h.db.conn.execute("SELECT COUNT(*) FROM pending_move").fetchone()[0] == 0
    # The job is done and re-running the same window finds nothing left.
    again = services.undo_moves("anna", since, until, "admin", engine=live.eng)
    assert again["code"] == "nothing"


@pytest.mark.parametrize("caps", [GIGA, SCAN], ids=["gigahost", "scannet"])
def test_live_undo_with_learning_learns_ham_exactly_once(live, caps):
    h = live_account(live, caps)
    catch_spam(live, h, ["n1@x"])
    since, until = int(live.clock.t) - 3600, int(live.clock.t) + 60
    res = services.undo_moves("anna", since, until, "admin", learn=True, engine=live.eng)
    assert res["moved"] == 1 and res["learned"] == 1
    assert [x for x in learned_ids(live) if x[1] == "n1@x"] == [("learnham", "n1@x")]
    live_loop(live, h, n=4, step=400)
    assert [x for x in learned_ids(live) if x[1] == "n1@x"] == [("learnham", "n1@x")]
    r = live_row(h, "n1@x")
    assert r["user_verdict"] == "ham" and r["learned_as"] == "ham"
    assert "n1@x" in h.box.msgids("INBOX")


@pytest.mark.parametrize("caps", [GIGA, SCAN], ids=["gigahost", "scannet"])
def test_live_find_mail_is_read_only_and_move_back_sticks(live, caps):
    h = live_account(live, caps, extra_folders=("Uønsket e-mail", "Sent"))
    live_mail(live, h, "INBOX", "order@x", subject="Ordre 1001", sender="support@vexar.example", score=13)
    live_loop(live, h)
    live.clock.t += 61
    live_loop(live, h)
    # The provider sorted one into its Junk (engine records provider_junk),
    # the mail program put one into "Uønsket e-mail", one sits in Trash, and
    # a match in Sent must never be searched.
    live_mail(live, h, "Junk", "kontakt@x", subject="Kontaktformular gravisk.example",
              sender="mailbot@vexar.example")
    live_mail(live, h, "Uønsket e-mail", "faktura@x", subject="Faktura fra vexar.example",
              sender="support@vexar.example")
    live_mail(live, h, "Trash", "trash@x", subject="vexar.example nyhedsbrev", sender="news@vexar.example")
    live_mail(live, h, "Sent", "sent@x", subject="Re: vexar.example", sender="ole@example-a.dk")
    live.clock.t += 400
    live_loop(live, h)  # junk poll sees the provider's Junk
    assert live_row(h, "kontakt@x")["our_action"] == "provider_junk"
    h.db.conn.execute("UPDATE messages SET subject='Ordre vexar.example' WHERE message_id='order@x'")
    h.box.writes.clear()
    # 2.3: the engine's own contact sync EXAMINEs Sent (known contacts);
    # only the calls find_mail makes count here.
    calls_before = len(h.box.calls)

    res = services.find_mail("anna", "vexar.example", since_days=7, engine=live.eng)
    assert res["ok"] and res["code"] == "ok", res
    assert h.box.writes == []  # EXAMINE + SEARCH + FETCH only
    selects = [c for c in h.box.calls[calls_before:] if c[0] == "select_folder" and c[1] != "INBOX"]
    groups = {g["name"]: g for g in res["folders"]}
    assert "Sent" not in groups and "Sent" not in [c[1] for c in selects]
    hits = {g["name"]: [x["message_id"] for x in g["hits"]] for g in res["folders"]}
    assert hits["Spamfilter"] == ["order@x"] and hits["Junk"] == ["kontakt@x"]
    assert hits["Uønsket e-mail"] == ["faktura@x"] and hits["Trash"] == ["trash@x"]
    assert groups["Uønsket e-mail"]["kind"] == "spam_like"
    assert "dit mailprogram har flyttet den" in groups["Uønsket e-mail"]["explanation"]
    assert groups["Junk"]["kind"] == "provider_junk" and groups["Spamfilter"]["kind"] == "filter_junk"
    assert [r["message_id"] for r in res["db"]] and "order@x" in [r["message_id"] for r in res["db"]]

    learns_before = list(live.rspamd.learn_calls)
    for folder, mid in (("Spamfilter", "order@x"), ("Junk", "kontakt@x"),
                        ("Uønsket e-mail", "faktura@x"), ("Trash", "trash@x")):
        out = services.move_found_to_inbox("anna", folder, mid, "admin", engine=live.eng)
        assert out["ok"] and out["code"] == "ok" and out["learned"] is None, out
        assert mid in h.box.msgids("INBOX") and mid not in h.box.msgids(folder)
        r = live_row(h, mid)
        assert r["user_verdict"] == "ham" and r["our_action"] == "manual_release"
    assert live.rspamd.learn_calls == learns_before
    assert "expunge" not in h.box.write_names()
    # A folder find_mail never searches is refused, and nothing moves.
    n = len(h.box.writes)
    out = services.move_found_to_inbox("anna", "Sent", "sent@x", "admin", engine=live.eng)
    assert out["code"] == "folder_not_allowed" and len(h.box.writes) == n

    # Later engine loops: no move back, no rescue learning (learn_from_moves
    # is on - the explicit "don't learn" must win).
    h.box.writes.clear()
    live_loop(live, h, n=4, step=400)
    live.clock.t += 7 * 3600
    live_loop(live, h, n=2, step=61, reconcile=True)
    inbox = h.box.msgids("INBOX")
    for mid in ("order@x", "kontakt@x", "faktura@x", "trash@x"):
        assert mid in inbox
        assert live_row(h, mid)["pending_learn"] is None
    assert [w for w in h.box.writes if w[1] == "INBOX" and w[0] in ("move", "copy", "uid_expunge")] == []
    assert live.rspamd.learn_calls == learns_before


def _near_midnight(minutes: int = 20) -> bool:
    """The digest part of the next test mixes the fake engine clock with
    real timestamps: within a few minutes of midnight (local or UTC) the
    two land on different days (seen on CI at 23:59 UTC)."""
    import datetime as _dt
    from zoneinfo import ZoneInfo
    # The filter's days are Copenhagen days; CI runners are on UTC (Copenhagen midnight = 23:00 UTC).
    for now in (_dt.datetime.now(), _dt.datetime.now(_dt.timezone.utc), _dt.datetime.now(ZoneInfo("Europe/Copenhagen"))):
        secs = now.hour * 3600 + now.minute * 60 + now.second
        if secs < minutes * 60 or secs > 86400 - minutes * 60:
            return True
    return False


def test_live_folder_sizes_and_threshold_suggestion_on_real_schema(live):
    if _near_midnight():
        pytest.skip("day boundary: digest dates would straddle midnight")
    h = live_account(live, GIGA)
    catch_spam(live, h, ["z1@x", "z2@x"])
    live_mail(live, h, "INBOX", "u@x", score=0.2)
    sizes = services.folder_sizes("anna", engine=live.eng)
    f = {x["kind"]: x for x in sizes["folders"]}
    assert sizes["ok"] and (f["filter_junk"]["messages"], f["filter_junk"]["unseen"]) == (2, 2)
    assert f["inbox"]["messages"] == 1 and f["provider_junk"]["name"] == "Junk"
    assert h.box.writes == [] or "expunge" not in h.box.write_names()
    # threshold_suggestion / digest_data read the real schema read-only.
    s = services.threshold_suggestion("anna", engine=live.eng)
    assert s["ok"] and s["current"] == 10.0 and s["counts"]["scored"] >= 2
    # The digest's days are Copenhagen days; the runner's local zone (UTC on CI) is a different
    # date for an hour every night.
    from zoneinfo import ZoneInfo
    day = dt.datetime.fromtimestamp(live.clock.t, ZoneInfo("Europe/Copenhagen")).date().isoformat()
    d = services.digest_data(day, suggestions=True, engine=live.eng)
    assert d["accounts"][0]["account"] == "anna" and d["accounts"][0]["moved"] == 2
    json.dumps(d)


@pytest.mark.parametrize("caps", [GIGA, SCAN], ids=["gigahost", "scannet"])
def test_live_duplicates_identical_copies_vs_different_deliveries(live, caps):
    h = live_account(live, caps, extra_folders=("Junk E-mail",))
    when = dt.datetime.fromtimestamp(live.clock.t - 600, dt.timezone.utc)
    raw = make_message("dup@x", subject="Ordre vexar.example", sender="support@vexar.example")
    # An interrupted COPY-based move left two identical copies behind.
    h.box.add("Spamfilter", raw, internaldate=when)
    h.box.add("Spamfilter", raw, internaldate=when)
    # Two different deliveries with the same Message-ID (alias + forward).
    h.box.add("Junk E-mail", make_message("two@x", subject="vexar.example"), internaldate=when)
    h.box.add("Junk E-mail", make_message("two@x", subject="vexar.example", body="other\r\n"),
              internaldate=when + dt.timedelta(minutes=3))
    h.box.writes.clear()
    out = services.move_found_to_inbox("anna", "Spamfilter", "dup@x", "admin", engine=live.eng)
    assert out["ok"], out
    assert h.box.msgids("INBOX").count("dup@x") == 1
    assert h.box.msgids("Spamfilter").count("dup@x") == 1  # the other copy is left alone
    n = len(h.box.writes)
    out = services.move_found_to_inbox("anna", "Junk E-mail", "two@x", "admin", engine=live.eng)
    assert out["ok"] is False and out["code"] == "ambiguous"
    assert len(h.box.writes) == n and h.box.msgids("Junk E-mail") == ["two@x", "two@x"]
    assert live_row(h, "two@x") is None  # nothing recorded for a refused move


def test_live_protected_recipient_mail_is_left_out_of_the_suggestion(live, monkeypatch):
    import fakes_engine

    h = live_account(live, GIGA, protected_recipients=["info@gravisk.example"])
    monkeypatch.setattr(live.eng, "_mailctx",
                        lambda: fakes_engine.stub_mailctx(recipients=["info@gravisk.example"]))
    live_mail(live, h, "INBOX", "shop@x", subject="Ny ordre", score=16.0)
    live_loop(live, h)
    r = live_row(h, "shop@x")
    assert r["our_action"] == "none"  # 16 < protected_threshold 18: never moved
    assert '"TH_PROTECTED_RCPT"' in r["symbols"]
    h.db.conn.execute("UPDATE messages SET user_verdict='ham' WHERE message_id='shop@x'")
    s = services.threshold_suggestion("anna", engine=live.eng)
    assert s["counts"]["protected_excluded"] == 1 and s["max_released_score"] is None


# ===========================================================================
# 2.2 SERVICES (B6): learn lists, Bayes repair candidates, rebalancing
# ===========================================================================


def test_queue_learn_list_validates_and_dedupes(tmp_path):
    eng = FakeEngine(tmp_path, accounts=[make_account(), make_account(name="b")])
    res = services.queue_learn_list(
        [{"account": "acc", "message_id": "<a@x>", "reason": "TH_BRAND_SPOOF"}, ("acc", "a@x"),
         ("b", "b@x", "ham"), ("nope", "c@x"), ("acc", "bad id"), {"account": "acc", "message_id": "d@x",
                                                                    "kind": "weird"}, "garbage"],
        "owner", engine=eng)
    assert res["ok"] and res["code"] == "queued" and res["total"] == 2
    assert res["by_account"] == {"acc": 1, "b": 1}
    assert sorted(r["code"] for r in res["rejected"]) == ["invalid_id", "invalid_kind", "no_account",
                                                         "no_account"]
    assert "spam/legitim" in res["text"] and "ingen mails flyttes" in res["text"]
    assert res["audit_detail"].startswith(f"learn_list job={res['job_id']}")
    items = services.learn_list_items(res["job_id"], engine=eng)
    assert [(i["account"], i["message_id"], i["kind"], i["status"]) for i in items] == [
        ("acc", "a@x", "spam", "pending"), ("b", "b@x", "ham", "pending")]
    assert items[0]["status_text"] == "Venter"
    job = services.learn_list_job(res["job_id"], engine=eng)
    assert job["status"] == "queued" and job["total"] == 2 and job["remaining"] == 2
    assert [j["id"] for j in services.list_learn_list_jobs(engine=eng)] == [res["job_id"]]
    assert events(eng, "learn_list_queued")
    assert services.queue_learn_list([], engine=eng)["code"] == "empty"
    assert services.queue_learn_list([("acc", "a@x")], kind="x", engine=eng)["ok"] is False
    assert services.learn_list_job(999, engine=eng) is None
    assert services.cancel_learn_list_job(999, engine=eng) is False


def test_queue_learn_list_limits(tmp_path, monkeypatch):
    eng = FakeEngine(tmp_path)
    monkeypatch.setattr(services, "LEARN_LIST_MAX_ITEMS", 2)
    assert services.queue_learn_list([("acc", f"{i}@x") for i in range(3)], engine=eng)["code"] == "too_many"
    eng.config_error = ValueError("broken")
    assert services.queue_learn_list([("acc", "a@x")], engine=eng)["code"] == "config"


def _learned_ham(eng, mid, *, account="acc", via="events", ts=None):
    ts = ts or int(time.time()) - 3600
    with eng.db() as conn:
        if via == "events":
            conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                         (account, ts, mid, "learn_ham", "bootstrap job=22"))
        else:
            conn.execute("CREATE TABLE IF NOT EXISTS learn_ledger (account TEXT, message_id TEXT, kind TEXT, "
                         "learned_at INTEGER, source TEXT, PRIMARY KEY(account, message_id))")
            conn.execute("INSERT OR REPLACE INTO learn_ledger VALUES(?,?,?,?,?)",
                         (account, mid, via, ts, "x"))


def _calib(eng, mid, symbols, *, job=40, provider_flag=None, account="acc"):
    with eng.db() as conn:
        conn.execute("INSERT INTO calibration_results(job_id, account, folder, message_id, final_score, "
                     "rspamd_score, symbols, sender, subject, received_at, seen, provider_flag) "
                     "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                     (job, account, "INBOX", mid, 9.1, 9.1, json.dumps(symbols), "x@goteamup.example",
                      "Dit betalingskort er udløbet", 1792500000, 1, provider_flag))


def test_bayes_repair_candidates(tmp_path):
    eng = FakeEngine(tmp_path)
    # Learned as ham (bootstrap job), later calibrated with the 2.2 phishing rules.
    _learned_ham(eng, "phish@x")
    _calib(eng, "phish@x", [{"n": "TH_BRAND_SPOOF", "s": 5.0}, {"n": "TH_LURE_COMBO", "s": 4.0},
                            {"n": "BAYES_HAM", "s": -3.0}])
    # An older calibration row without the rules does not hide the newer one.
    _calib(eng, "phish@x", [{"n": "BAYES_HAM", "s": -3.0}], job=10)
    # Learned as ham, the user later dragged it to spam.
    _learned_ham(eng, "dragged@x")
    scored(eng, [], prefix="x")
    now = int(time.time())
    with eng.db() as conn:
        conn.execute("INSERT INTO messages(account, message_id, first_seen, last_seen, current_folder, "
                     "our_action, user_verdict, sender, subject, provider_flag, learned_as, learned_at) "
                     "VALUES('acc','dragged@x',?,?,'Junk','user_junked','spam','a@b.example','Hej',1,'ham',?)",
                     (now, now, now))
        # Released by the user: never a candidate, even with evidence.
        conn.execute("INSERT INTO messages(account, message_id, first_seen, last_seen, current_folder, "
                     "user_verdict, provider_flag, learned_as, learned_at) "
                     "VALUES('acc','released@x',?,?,'INBOX','ham',1,'ham',?)", (now, now, now))
        # Allow-rule mail is the owner's decision.
        conn.execute("INSERT INTO messages(account, message_id, first_seen, last_seen, current_folder, "
                     "provider_flag, learned_as, learned_at, rule_hit) "
                     "VALUES('acc','allowed@x',?,?,'INBOX',1,'ham',?,'allow:3')", (now, now, now))
    # Provider-flagged, learned as ham (events) - and one already flipped to spam (ledger).
    _learned_ham(eng, "prov@x")
    _calib(eng, "prov@x", [{"n": "TH_PROVIDER_SPAM", "s": 4.0}])
    _learned_ham(eng, "flipped@x")
    _calib(eng, "flipped@x", [{"n": "DBL_PHISH", "s": 7.5}])
    _learned_ham(eng, "flipped@x", via="spam", ts=now)
    # Never learned: only with scope='all'.
    _calib(eng, "fresh@x", [{"n": "PHISHED_OPENPHISH", "s": 7.0}])
    # Learned as ham without any evidence.
    _learned_ham(eng, "clean@x")
    _calib(eng, "clean@x", [{"n": "BAYES_HAM", "s": -3.0}])

    res = services.bayes_repair_candidates(engine=eng)
    assert res["ok"] and res["scope"] == "learned_ham"
    by = {i["message_id"]: i for i in res["items"]}
    assert set(by) == {"phish@x", "dragged@x", "prov@x"}
    assert by["phish@x"]["reasons"] == ["phishing_rule"]
    assert by["phish@x"]["symbols"] == ["TH_BRAND_SPOOF", "TH_LURE_COMBO"]
    assert by["phish@x"]["text"] == "Phishing-regel ramte (TH_BRAND_SPOOF, TH_LURE_COMBO)"
    assert by["phish@x"]["subject"] == "Dit betalingskort er udløbet" and by["phish@x"]["learned_as"] == "ham"
    assert by["dragged@x"]["reasons"] == ["user_marked_spam", "provider_spam"]
    assert res["items"][0]["message_id"] == "dragged@x"          # most evidence first
    assert by["prov@x"]["reasons"] == ["provider_spam"] and by["prov@x"]["suggested_kind"] == "spam"
    assert res["counts"]["by_reason"] == {"phishing_rule": 1, "user_marked_spam": 1, "provider_spam": 2}
    assert res["counts"]["by_account"] == {"acc": 3}
    assert res["counts"]["learned_ham"] == 6     # flipped@x is spam now (ledger)
    res_all = services.bayes_repair_candidates(scope="all", engine=eng)
    assert {i["message_id"] for i in res_all["items"]} == {"phish@x", "dragged@x", "prov@x", "fresh@x"}
    assert services.bayes_repair_candidates("other", engine=eng)["total"] == 0
    assert services.bayes_repair_candidates(limit=1, engine=eng)["truncated"] is True
    # The suggestions feed a learn list directly.
    q = services.queue_learn_list(res["items"], "owner", engine=eng)
    assert q["ok"] and q["total"] == 3
    assert {i["reason"] for i in services.learn_list_items(q["job_id"], engine=eng)} == {None}
    json.dumps(res)


def _rebalance_env(tmp_path, monkeypatch, spam=256, ham=1448):
    imap = FakeIMAP(folders=("INBOX", "Junk", "Spamfilter", "Trash"), special_use={"Junk": "\\Junk"})
    eng = FakeEngine(tmp_path, imap=imap, accounts=[make_account(junk="Spamfilter", junk_explicit=True)])
    for i in range(30):
        imap.add("Junk", make_message(f"j{i}@x"))
    for i in range(5):
        imap.add("Spamfilter", make_message(f"s{i}@x"))
    imap.add("INBOX", make_message("in@x"))
    monkeypatch.setattr(services, "bayes_stats", lambda engine=None: {
        "ok": True, "spam_learned": spam, "ham_learned": ham})
    return eng, imap


def test_bayes_rebalance_plan_and_queue(tmp_path, monkeypatch):
    eng, imap = _rebalance_env(tmp_path, monkeypatch)
    plan = services.queue_bayes_rebalance("owner", dry_run=True, engine=eng)
    assert plan["ok"] and plan["code"] == "plan" and plan["needed"] == 724 - 256
    assert plan["bayes"] == {"spam": 256, "ham": 1448, "ratio": 0.177}
    assert [(j["folder"], j["kind"], j["messages"], j["job_id"]) for j in plan["jobs"]] == [
        ("Junk", "provider_junk", 30, None), ("Spamfilter", "filter_junk", 5, None)]
    assert services.list_train_jobs(engine=eng) == []
    assert imap.writes == []
    res = services.queue_bayes_rebalance("owner", min_age_days=3, max_per_folder=20, engine=eng)
    assert res["ok"] and res["code"] == "queued" and "stopper af sig selv" in res["text"]
    jobs = {j["folder"]: j for j in services.list_train_jobs(engine=eng)}
    assert set(jobs) == {"Junk", "Spamfilter"}                     # never INBOX
    assert all(j["kind"] == "spam" and j["stop_ratio"] == 0.5 and j["min_age_days"] == 3
               for j in jobs.values())
    assert jobs["Junk"]["max_messages"] == 20 and jobs["Junk"]["created_by"] == "owner"
    assert res["audit_detail"].startswith("bayes_rebalance jobs=2")


def test_bayes_rebalance_balanced_trash_and_errors(tmp_path, monkeypatch):
    eng, imap = _rebalance_env(tmp_path, monkeypatch, spam=800, ham=1448)
    assert services.queue_bayes_rebalance(engine=eng)["code"] == "balanced"
    eng, imap = _rebalance_env(tmp_path / "2", monkeypatch)
    imap.add("Trash", make_message("t@x"))
    res = services.queue_bayes_rebalance(include_trash=True, dry_run=True, engine=eng)
    trash = [j for j in res["jobs"] if j["kind"] == "trash"]
    assert trash and trash[0]["provider_filter"] == "provider_spam"
    monkeypatch.setattr(services, "bayes_stats", lambda engine=None: {"ok": False})
    assert services.queue_bayes_rebalance(engine=eng)["code"] == "rspamd"
    assert services.queue_bayes_rebalance(ratio=0, engine=eng)["code"] == "invalid"
    eng3 = FakeEngine(tmp_path / "3", connect_error=OSError("down"))
    monkeypatch.setattr(services, "bayes_stats", lambda engine=None: {"ok": True, "spam_learned": 1,
                                                                       "ham_learned": 100})
    res = services.queue_bayes_rebalance(engine=eng3)
    assert res["code"] == "nothing" and res["errors"][0]["code"] == "connect"


def test_threshold_suggestion_leaves_aged_scans_out(tmp_path):
    eng = sugg_env(tmp_path)
    with eng.db() as conn:
        conn.execute("ALTER TABLE messages ADD COLUMN aged INTEGER")
    scored(eng, [1.0] * 30, prefix="bg")
    scored(eng, [13.0], verdict="ham", action="manual_release", prefix="old")
    with eng.db() as conn:
        conn.execute("UPDATE messages SET aged=1 WHERE message_id LIKE 'old%'")
    s = services.threshold_suggestion("acc", engine=eng)
    assert s["max_released_score"] is None and s["counts"]["aged_excluded"] == 1
    s = services.threshold_suggestion("acc", include_aged=True, engine=eng)
    assert s["max_released_score"] == 13.0 and s["counts"]["aged_excluded"] == 0


# ===========================================================================
# 2.2 SERVICES (B21): weekly report
# ===========================================================================


def _weekly_env(tmp_path):
    accts = [make_account(name="bynet", mode="move", threshold=10.0, display_name="Ole",
                          webshop_domains=["pinsikbing.example", "gravisk.example", "vexar.example"]),
             make_account(name="molt", mode="move", threshold=10.0)]
    eng = FakeEngine(tmp_path, accounts=accts)
    with eng.db() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS settings_kv (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute("INSERT INTO settings_kv VALUES('external_url','https://spamfilter.example')")
        # ISO week 2026-W43 = 19.-25. October; W42 = 12.-18.
        for acc, day, metric, n in [("bynet", "2026-10-20", "moved", 4), ("bynet", "2026-10-21", "moved", 3),
                                    ("bynet", "2026-10-20", "scanned", 50), ("bynet", "2026-10-20", "released", 1),
                                    ("bynet", "2026-10-22", "user_junked", 2), ("bynet", "2026-10-13", "moved", 9),
                                    ("molt", "2026-10-25", "scanned", 7), ("molt", "2026-10-26", "moved", 99)]:
            conn.execute("INSERT INTO stats_daily VALUES(?,?,?,?)", (acc, day, metric, n))
        ts = int(dt.datetime(2026, 10, 21, 12, 0, tzinfo=dt.timezone.utc).timestamp())
        rows = [("o1@x", "ordre@vexar.example", None, "none", None, "inbox_scan"),
                ("o2@x", "Kunde <kunde@gmail.example>", "SRS0=ab=cd=gravisk.example=info@gravisk.example", "none", None,
                 "inbox_scan"),
                ("o3@x", "info@pinsikbing.example", None, "manual_release", ts, "inbox_scan"),
                ("b1@x", "x@spam.example", None, "moved_to_junk", ts, "inbox_scan"),
                ("b2@x", "y@spam.example", None, "moved_to_junk", ts, "inbox_scan"),
                ("j1@x", "ordre@vexar.example", None, "provider_junk", None, "junk_poll")]
        for mid, sender, env, action, moved, origin in rows:
            conn.execute("INSERT INTO messages(account, message_id, first_seen, last_seen, current_folder, "
                         "sender, envelope_from, our_action, moved_to_junk_at, scanned_at, origin, rule_hit, "
                         "subject) VALUES('bynet',?,?,?,'INBOX',?,?,?,?,?,?,?,?)",
                         (mid, ts, ts, sender, env, action, moved, ts, origin,
                          "block:4" if mid.startswith("b") else None, f"Emne {mid}"))
        conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES('bynet',?,NULL,"
                     "'circuit_open','rate')", (ts,))
    return eng


def test_weekly_data(tmp_path, monkeypatch):
    eng = _weekly_env(tmp_path)
    monkeypatch.setattr(services, "bayes_stats", lambda engine=None: {"ok": True, "spam_learned": 300,
                                                                       "ham_learned": 1400})
    d = services.weekly_data("2026-W43", engine=eng)
    assert d["week"] == "2026-W43" and d["prev_week"] == "2026-W42" and d["span"] == "19.–25. oktober 2026"
    by = {a["account"]: a for a in d["accounts"]}
    assert (by["bynet"]["moved"], by["bynet"]["released"], by["bynet"]["missed"]) == (7, 1, 2)
    assert by["bynet"]["prev"]["moved"] == 9 and by["molt"]["moved"] == 0 and by["molt"]["scanned"] == 7
    assert d["top_blocked"] == [{"domain": "spam.example", "n": 2}]
    assert d["threats"] is None
    shop = d["webshop"]
    assert shop["total"] == 3 and shop["moved"] == 1
    assert shop["line"] == "Webshop-post: 3 mails fra pinsikbing.example/gravisk.example/vexar.example – 1 flyttet"
    [moved] = shop["moved_items"]
    assert moved["message_id"] == "o3@x" and moved["released"] is True
    assert moved["link"].startswith("https://spamfilter.example/messages/bynet/")
    assert d["drift"]["bayes"] == {"ok": True, "spam": 300, "ham": 1400}
    assert d["drift"]["circuit_stops"] == [{"account": "bynet", "n": 1}]
    assert {t["account"] for t in d["thresholds"]} == {"bynet", "molt"}
    json.dumps(d)
    # Short version: one mailbox, no Bayes/backup lookups.
    short = services.weekly_data("2026-W43", account="molt", engine=eng)
    assert [a["account"] for a in short["accounts"]] == ["molt"] and short["webshop"]["line"] == ""
    with pytest.raises(ValueError):
        services.weekly_data("2026-43", engine=eng)
    assert services.parse_week(None, today=dt.date(2026, 10, 21)) == dt.date(2026, 10, 12)
    assert services.parse_week(None, today=dt.date(2026, 10, 26)) == dt.date(2026, 10, 19)


def test_render_weekly_full_and_short(tmp_path, monkeypatch):
    eng = _weekly_env(tmp_path)
    monkeypatch.setattr(services, "bayes_stats", lambda engine=None: {"ok": False})
    d = services.weekly_data("2026-W43", engine=eng)
    r = services.render_weekly(d)
    assert r["subject"] == "Spamfilter: ugerapport for uge 43"
    assert "Webshop-post: 3 mails fra pinsikbing.example/gravisk.example/vexar.example – 1 flyttet" in r["text"]
    assert "- Ole: 50 scannet, 7 flyttet til Spamfilter (ugen før 9), 1 frigivet, 2 spam slap igennem" in r["text"]
    assert "spam.example: 2" in r["text"] and "Sikkerhedsbremse: bynet (1)" in r["text"]
    assert "<table" in r["html"] and "&lt;" not in r["subject"]
    d["webshop"]["moved_items"][0]["released"] = False
    r = services.render_weekly(d, preview=True)
    assert r["subject"].startswith("[Prøve] ") and "Frigiv: https://spamfilter.example/messages/bynet/" in r["text"]
    s = services.render_weekly(services.weekly_data("2026-W43", account="bynet", engine=eng), full=False)
    assert "Filteret flyttede 7 mails til Spamfilter-mappen. 1 blev frigivet igen." in s["text"]
    assert "Postkasser" not in s["text"]


def test_weekly_settings_preview_and_send_now(tmp_path, monkeypatch):
    eng = _weekly_env(tmp_path)
    monkeypatch.setattr(services, "bayes_stats", lambda engine=None: {"ok": False})
    st = services.weekly_settings(engine=eng)
    assert st == {"enabled": False, "admin_account": None, "admin_account_effective": "bynet",
                  "users": False, "external_url": "https://spamfilter.example"}
    with eng.db() as conn:
        conn.execute("INSERT INTO settings_kv VALUES('weekly_enabled','1'),('weekly_admin_account','molt'),"
                     "('weekly_users','1')")
    st = services.weekly_settings(engine=eng)
    assert st["enabled"] and st["users"] and st["admin_account_effective"] == "molt"
    p = services.weekly_preview(engine=eng, week="2026-W43")
    assert p["ok"] and p["full"] is True and p["subject"].startswith("[Prøve]") and p["data"]["week"] == "2026-W43"
    p = services.weekly_preview("bynet", week="2026-W43", engine=eng)
    assert p["full"] is False and "Filteret flyttede" in p["body_text"]
    assert services.weekly_preview(week="bad", engine=eng)["code"] == "invalid"
    assert services.send_weekly_now("bynet", engine=eng)["code"] == "config"   # FakeEngine: no sender
    calls = []
    eng.send_weekly_report = lambda account, **kw: calls.append((account, kw)) or {
        "ok": True, "code": "sent", "week": "2026-W43"}
    res = services.send_weekly_now("bynet", preview=False, actor="admin", engine=eng)
    assert res["ok"] and res["audit_detail"] == "weekly_report bynet week=2026-W43 sent"
    assert calls == [("bynet", {"preview": False, "week": None, "full": None, "actor": "admin"})]


# ----- 2.2 review fixes: PHISHED_EXCLUDED is informational -------------------------


def test_phished_excluded_is_never_repair_evidence(tmp_path):
    import filter as engine_module

    assert services.REPAIR_INFO_SYMBOLS == engine_module.PHISHED_INFO
    assert services._repair_hits({"PHISHED_EXCLUDED", "PHISHED_GENERIC_SERVICE", "R_DKIM_ALLOW"}) == []
    assert services._repair_hits({"PHISHED_EXCLUDED", "PHISHED_OPENPHISH"}) == ["PHISHED_OPENPHISH"]
    eng = FakeEngine(tmp_path)
    # A ham-learned webshop mail that links to the owner's own shop (B5 exclusion list).
    _learned_ham(eng, "shop@x")
    _calib(eng, "shop@x", [{"n": "PHISHED_EXCLUDED", "s": 0.0}, {"n": "R_DKIM_ALLOW", "s": -0.2}])
    res = services.bayes_repair_candidates(scope="all", engine=eng)
    assert "shop@x" not in {i["message_id"] for i in res["items"]}


def test_spamexperts_tip_needs_scannet_and_a_spamexperts_mx(tmp_path, monkeypatch):
    """2.11.1: no Mailsikkerhed run, another domain's MX, or a non-Scannet
    mailbox -> no SpamExperts tip; older runs only count when the newer ones
    did not read the domain's MX."""
    import mailcheck

    eng, _imap = find_env(tmp_path, imap_host="mail.scannet.dk")
    acc = eng.load_account_configs(eng.CONFIG_PATH)[0]
    assert services._spamexperts_in_front(eng, acc) is False             # no run yet
    _mailcheck_run(eng, "example-a.dk", ["mx.antispamcloud.com"])
    assert services._spamexperts_in_front(eng, acc) is True
    _mailcheck_run(eng, "other.dk", ["mx1.scannet.dk"])                  # newer run, MX not read for us
    assert services._spamexperts_in_front(eng, acc) is True
    _mailcheck_run(eng, "example-a.dk", ["mx1.scannet.dk."])
    assert services._spamexperts_in_front(eng, acc) is False
    eng2, _ = find_env(tmp_path / "g", imap_host="imap.gigahost.dk")
    _mailcheck_run(eng2, "example-a.dk", ["mx.spamexperts.com"])
    assert services._spamexperts_in_front(eng2, eng2.load_account_configs(eng2.CONFIG_PATH)[0]) is False
    assert mailcheck.spamexperts_in_front(None, "example-a.dk") is False
    assert mailcheck.spamexperts_in_front(sqlite3.connect(":memory:"), "example-a.dk") is False  # no table
    assert not mailcheck.spamexperts_in_front(sqlite3.connect(":memory:"), "not a domain")
    assert services._find_hints(acc, 30) == services._find_hints(acc, 30, spamexperts=False)
    assert any("SpamExperts" in x for x in services._find_hints(acc, 30, spamexperts=True))


@pytest.mark.parametrize("caps", [GIGA, SCAN], ids=["gigahost", "scannet"])
@pytest.mark.parametrize("wire", [None, "reused@x"], ids=["missing-id", "collision"])
def test_live_find_and_release_uses_content_identity(live, caps, wire):
    h = live_account(live, caps)
    if wire:
        live_mail(live, h, "INBOX", wire, subject="Original", score=0)
        live_loop(live, h)
    live_mail(live, h, "Trash", wire, subject="Find marker.example", sender="sender@marker.example")
    res = services.find_mail("anna", "marker.example", since_days=7, engine=live.eng)
    assert res["ok"]
    hit = next(g for g in res["folders"] if g["name"] == "Trash")["hits"][0]
    key = hit["message_id"]
    assert key.startswith("sf-local:") and hit["can_move"]
    out = services.move_found_to_inbox("anna", "Trash", key, "admin", engine=live.eng)
    assert out["ok"], out
    assert live_row(h, key)["user_verdict"] == "ham"
    scans = len(live.rspamd.scan_calls)
    live_loop(live, h, n=3, step=400)
    assert len(live.rspamd.scan_calls) == scans
    assert live.rspamd.learn_calls == []


def test_legacy_threat_cannot_be_released_via_a_new_search_identity(live):
    h = live_account(live, SCAN)
    catch_spam(live, h, ['danger@x'])
    with h.db.tx():
        h.db.update_message('danger@x', threat='virus', threat_detail='Legacy.Test')
        h.db.conn.execute('DELETE FROM mail_identity WHERE account=?', (h.acc.name,))
    res = services.find_mail('anna', 'danger', since_days=7, engine=live.eng)
    hit = next(g for g in res['folders'] if g['name'] == 'Spamfilter')['hits'][0]
    assert hit['message_id'].startswith('sf-local:')
    with h.db.tx():
        h.db.upsert_message(hit['message_id'], 'Spamfilter', 'sender@example.org', 'rechecked')
        h.db.update_message(hit['message_id'], scanned_at=int(live.clock.t), our_score=0)
    # A new score alone cannot disprove an old virus finding whose content
    # was never fingerprinted (the current AV may be unavailable).
    h.box.writes.clear()
    out = services.move_found_to_inbox('anna', 'Spamfilter', hit['message_id'], 'user', engine=live.eng)
    assert out['code'] == 'threat_admin', out
    assert h.box.writes == []
    assert not live.rspamd.learn_calls
    out = services.move_found_to_inbox('anna', 'Spamfilter', hit['message_id'], 'admin',
                                      engine=live.eng, is_admin=True)
    assert out['code'] == 'threat_confirm' and h.box.writes == []
    out = services.move_found_to_inbox('anna', 'Spamfilter', hit['message_id'], 'admin', learn=True,
                                      engine=live.eng, is_admin=True, confirm_threat=True)
    assert out['ok'] and out['learned'] is None, out
    assert not live.rspamd.learn_calls
    assert live_row(h, hit['message_id'])['threat'] == 'virus'


def test_different_fingerprinted_payload_uses_its_own_threat_classification(live):
    h = live_account(live, SCAN)
    with h.db.tx():
        identity = live.eng.mailidentity
        identity.bind(h.db.conn, h.acc.name, 'different@x', make_message('different@x', subject='old'))
        key = identity.bind(h.db.conn, h.acc.name, 'different@x', make_message('different@x', subject='new'))
        h.db.upsert_message('different@x', 'Spamfilter', 'sender@example.org', 'old')
        h.db.update_message('different@x', threat='virus')
        h.db.upsert_message(key, 'Spamfilter', 'sender@example.org', 'new')
        h.db.update_message(key, scanned_at=int(live.clock.t), threat=None)
    assert services._threat_of(h.db.conn, h.acc.name, key) == (None, None)


@pytest.mark.parametrize("action", ["learn_spam", "mark_spam"])
def test_spam_on_a_known_mail_that_cannot_be_found_still_records_the_verdict(eng, imap, action):
    # 2.20.1: a mail rewritten by the person's mail client (or deleted) kept
    # coming back in 'Tjek disse' because 'Det er spam' failed as not_found.
    now = int(time.time())
    with eng.db() as conn:
        conn.execute("INSERT INTO messages(account, message_id, first_seen, last_seen, current_folder, "
                     "our_action, sender, subject) VALUES('acc','rewritten@x',?,?,'Junk','moved_to_junk',"
                     "'a@b.example','Hej')", (now, now))
    res = services.mail_action("acc", ["rewritten@x", "unknown@x"], action, "anna", engine=eng)
    assert [(r["ok"], r["code"]) for r in res] == [(True, "verdict_only"), (False, "not_found")]
    r = row(eng, "rewritten@x")
    assert r["user_verdict"] == "spam" and r["verdict_by"] == "anna" and r["current_folder"] == "Junk"
    assert row(eng, "unknown@x") is None
    assert eng.move_calls == [] and eng.learn_calls == [] and imap.writes == []
    assert events(eng, "verdict_only_spam")


def test_release_of_a_known_mail_that_cannot_be_found_records_nothing(eng, imap):
    now = int(time.time())
    with eng.db() as conn:
        conn.execute("INSERT INTO messages(account, message_id, first_seen, last_seen, current_folder, "
                     "our_action, sender) VALUES('acc','rewritten@x',?,?,'Junk','moved_to_junk','a@b.example')",
                     (now, now))
    res = services.mail_action("acc", ["rewritten@x"], "release", "anna", engine=eng)
    assert res[0]["code"] == "not_found" and row(eng, "rewritten@x")["user_verdict"] is None
