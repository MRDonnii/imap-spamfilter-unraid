"""2.5.0 push notifications - subscriptions, routing, rate limits, the
queue and the engine hooks (filter/push.py + the filter.py wiring).

Users: Bjarke (admin), inge (Bruger, molt-inge), anna (Bruger, bynet).
A Bruger never gets anything about a mailbox they cannot see, problems go
to administrators only, payloads hold counts and mailbox names only.
Every HTTP request goes to the fake push service (fakes_push.py).
"""

from __future__ import annotations

import json
import sqlite3
import sys
import time
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fakes_push import FakePushService, device  # noqa: E402
from fakes_ui import fast_hash  # noqa: E402  (also puts filter/ on sys.path)

import push  # noqa: E402
import webpush  # noqa: E402

PW = "korrekt-hest-batteri-42"
NOW = 1_800_000_000


@pytest.fixture
def penv(tmp_path, monkeypatch):
    import filter as engine

    state = tmp_path / "state"
    state.mkdir()
    cfg = tmp_path / "accounts.yml"
    cfg.write_text(yaml.safe_dump({"accounts": [
        {"name": "bynet", "user": "ole@example.com", "display_name": "BYnet"},
        {"name": "molt-inge", "user": "inge@example.net", "display_name": "Inge"},
        {"name": "molt", "user": "ole@example.net"},
    ]}))
    (state / "dashboard_users").write_text(
        f"Bjarke:{fast_hash(PW)}:admin:0\ninge:{fast_hash(PW)}:molt-inge:0\nanna:{fast_hash(PW)}:bynet:0\n")
    monkeypatch.setattr(engine, "DB_PATH", state / "spamfilter.db")
    engine.init_db()
    for name in ("STATE_DIR", "CONFIG_PATH", "DB_PATH", "USERS_FILE", "AUTO_WORKER"):
        monkeypatch.setattr(push, name, getattr(push, name))
    push.configure_paths(state, cfg)
    monkeypatch.setattr(push, "AUTO_WORKER", False)
    for var in ("DASHBOARD_USERS", "DASHBOARD_USER", "PUSH_VAPID_SUBJECT"):
        monkeypatch.delenv(var, raising=False)
    push.ensure_schema()
    svc = FakePushService()
    conn = sqlite3.connect(state / "spamfilter.db", isolation_level=None)
    conn.row_factory = sqlite3.Row

    class E:
        pass

    e = E()
    e.state, e.cfg, e.svc, e.conn, e.engine = state, cfg, svc, conn, engine

    def sub(user, *, host="web.push.apple.com", prefs=None):
        dev = device(host)
        res = push.subscribe(user, dev.endpoint, dev.p256dh, dev.auth, user_agent="iPhone · app på hjemmeskærmen",
                             prefs=prefs, now=NOW)
        assert res["ok"], res
        dev.id = res["id"]
        svc.add(dev)
        return dev

    def run(now=NOW):
        return push.process_queue(now=now, session=svc)

    def queue():
        return [dict(r) for r in conn.execute("SELECT * FROM push_queue ORDER BY id")]

    e.sub, e.run, e.queue = sub, run, queue
    yield e
    conn.close()


def threat_rows(e, account, ids, *, queued_at=NOW, subject="HEMMELIGT-EMNE", sender="Svindler <angriber@evil.example>"):
    for mid in ids:
        e.conn.execute("INSERT INTO messages(account, message_id, first_seen, last_seen, current_folder, our_action, "
                       "sender, subject, threat, scanned_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                       (account, mid, queued_at, queued_at, "Spamfilter", "moved_to_junk", sender, subject, "phish",
                        queued_at))
        e.conn.execute("INSERT INTO threat_notices(account, message_id, threat, sender_name, created_at, queued_at) "
                       "VALUES(?,?,?,?,?,?)", (account, mid, "phish", "Svindler", queued_at, queued_at))


# ---------------------------------------------------------------------------
# Subscriptions
# ---------------------------------------------------------------------------


def test_subscribe_update_list_and_remove(penv):
    dev = device()
    res = push.subscribe("inge", dev.endpoint, dev.p256dh, dev.auth, user_agent="iPhone · Safari", now=NOW)
    assert res == {"ok": True, "code": "ok", "text": push.TEXTS["ok"], "id": res["id"]}
    again = push.subscribe("inge", dev.endpoint, dev.p256dh, dev.auth, user_agent="iPhone · app på hjemmeskærmen")
    assert again["code"] == "updated" and again["id"] == res["id"]
    [d] = push.devices("inge", is_admin=False)
    assert d["ua"] == "iPhone · app på hjemmeskærmen" and d["host"] == "web.push.apple.com"
    assert d["hash"] == push.endpoint_hash(dev.endpoint) and "endpoint" not in d
    assert d["prefs"] == {"threat": True, "review": False, "problem": False}   # Bruger: never problems
    assert push.devices("Bjarke") == [] and push.devices("anna") == []
    assert push.remove("anna", res["id"]) is False                # not hers
    assert push.remove_endpoint("anna", dev.endpoint) is False
    assert push.owns_endpoint("anna", dev.endpoint) is None
    assert push.owns_endpoint("inge", dev.endpoint) == res["id"]
    assert push.remove("inge", res["id"]) is True
    assert push.devices("inge") == []


def test_admin_defaults_and_prefs_are_scoped(penv):
    a = penv.sub("Bjarke")
    f = penv.sub("inge")
    assert push.devices("Bjarke")[0]["prefs"] == {"threat": True, "review": False, "problem": True}
    dev = device()
    sid = push.subscribe("anna", dev.endpoint, dev.p256dh, dev.auth, is_admin=False)["id"]
    stored = penv.conn.execute("SELECT prefs FROM push_subscriptions WHERE id=?", (sid,)).fetchone()[0]
    assert json.loads(stored) == {"threat": True, "review": False, "problem": False}
    assert push.set_prefs("inge", a.id, {"threat": False}, is_admin=False) is False   # someone else's device
    assert push.devices("Bjarke")[0]["prefs"]["threat"] is True
    assert push.set_prefs("inge", f.id, {"threat": True, "review": True, "problem": True}, is_admin=False)
    assert push.devices("inge", is_admin=False)[0]["prefs"] == {"threat": True, "review": True, "problem": False}
    stored = penv.conn.execute("SELECT prefs FROM push_subscriptions WHERE id=?", (f.id,)).fetchone()[0]
    assert json.loads(stored)["problem"] is False


def test_endpoint_of_another_user_moves_only_with_the_same_keys(penv):
    dev = penv.sub("anna")
    other = device()
    res = push.subscribe("inge", dev.endpoint, other.p256dh, other.auth)
    assert res["code"] == "taken" and not res["ok"]
    assert push.devices("anna")
    res = push.subscribe("inge", dev.endpoint, dev.p256dh, dev.auth)   # the same browser, now inge's
    assert res["ok"] and push.devices("anna") == [] and len(push.devices("inge")) == 1


def test_at_most_10_devices_per_user(penv):
    for _ in range(push.MAX_PER_USER):
        penv.sub("anna")
    dev = device()
    res = push.subscribe("anna", dev.endpoint, dev.p256dh, dev.auth)
    assert res["code"] == "too_many" and "10 enheder" in res["text"]
    assert len(push.devices("anna")) == 10
    assert penv.sub("inge")    # per user


@pytest.mark.parametrize("endpoint,code", [
    ("https://192.168.1.10/push", "endpoint_not_allowed"), ("http://fcm.googleapis.com/fcm/send/x", "invalid_endpoint"),
    ("https://fcm.googleapis.com.evil.example/x", "endpoint_not_allowed"), ("javascript:alert(1)", "invalid_endpoint"),
])
def test_ssrf_subscriptions_are_refused(penv, endpoint, code):
    dev = device()
    res = push.subscribe("anna", endpoint, dev.p256dh, dev.auth)
    assert res["code"] == code and not res["ok"]
    assert penv.conn.execute("SELECT COUNT(*) FROM push_subscriptions").fetchone()[0] == 0


def test_bad_keys_are_refused(penv):
    dev = device()
    for p, a in ((dev.p256dh[:20], dev.auth), (dev.p256dh, "AAAA"), ("", ""), (dev.p256dh, dev.auth + "x" * 200)):
        assert push.subscribe("anna", dev.endpoint, p, a)["code"] == "invalid_keys"


def test_delete_user_removes_devices_and_queue(penv):
    penv.sub("inge")
    penv.sub("inge", host="fcm.googleapis.com")
    push.enqueue(None, "inge", "threat", {"counts": {"molt-inge": 1}}, now=NOW)
    assert push.delete_user("inge") == 2
    assert push.devices("inge") == []
    assert [q for q in penv.queue() if q["status"] == "queued"] == []


def test_short_user_agent():
    ios = ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
           "Version/18.1 Mobile/15E148 Safari/604.1")
    assert push.short_user_agent(ios) == "iPhone · Safari"
    assert push.short_user_agent(ios, app=True) == "iPhone · app på hjemmeskærmen"
    assert push.short_user_agent("Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 Chrome/130.0 Mobile Safari/537.36"
                                 ) == "Android · Chrome"
    assert push.short_user_agent("Mozilla/5.0 (Windows NT 10.0) Chrome/130.0 Safari/537.36 Edg/130.0") == "Windows · Edge"
    assert push.short_user_agent("") == "Enhed · browser"
    assert len(push.short_user_agent("x" * 500)) <= push.UA_MAX


# ---------------------------------------------------------------------------
# Routing + payloads
# ---------------------------------------------------------------------------


def test_threat_goes_only_to_users_who_can_see_the_mailbox(penv):
    admin, inge, anna = penv.sub("Bjarke"), penv.sub("inge"), penv.sub("anna")
    threat_rows(penv, "molt-inge", ["<t1@x>", "<t2@x>"])
    assert push.on_threats(penv.conn, "molt-inge", now=NOW) == 2       # Bjarke + inge
    stats = penv.run()
    assert stats["sent"] == 2
    [pf] = penv.svc.payloads(inge)
    assert pf == {"title": "2 farlige mails stoppet",
                  "body": "2 farlige mails i Inge er lagt i Spamfilter-mappen. Åbn dem ikke.",
                  "url": "/spam?account=molt-inge", "tag": "sf-threat"}
    assert penv.svc.payloads(admin) == [pf]
    assert penv.svc.payloads(anna) == []                                  # bynet only: nothing about Inge
    # Never content: no subject, no sender, no address, no Message-ID.
    raw = json.dumps([c["payload"] for c in penv.svc.calls], ensure_ascii=False)
    for secret in ("HEMMELIGT", "angriber", "evil.example", "Svindler", "<t1@x>", "inge@example.net"):
        assert secret not in raw
    # Urgent + short-lived, topic for coalescing at the push service.
    h = penv.svc.calls[0]["headers"]
    assert h["Urgency"] == "high" and h["TTL"] == str(push.TTL["threat"]) and h["Topic"] == "sf-threat"


def test_threat_is_counted_once(penv):
    penv.sub("inge")
    threat_rows(penv, "molt-inge", ["<t1@x>"])
    assert push.on_threats(penv.conn, "molt-inge", now=NOW) == 1
    assert push.on_threats(penv.conn, "molt-inge", now=NOW + 5) == 0
    threat_rows(penv, "molt-inge", ["<t2@x>"], queued_at=NOW + 10)
    assert push.on_threats(penv.conn, "molt-inge", now=NOW + 10) == 1
    [row] = penv.queue()                                 # merged into the one queued row
    assert json.loads(row["data"]) == {"counts": {"molt-inge": 2}}


def test_old_threats_are_not_pushed_after_an_outage(penv):
    penv.sub("inge")
    threat_rows(penv, "molt-inge", ["<old@x>"], queued_at=NOW - push.LOOKBACK - 60)
    assert push.on_threats(penv.conn, "molt-inge", now=NOW) == 0


def test_nobody_subscribed_means_no_queue(penv):
    threat_rows(penv, "bynet", ["<t1@x>"])
    assert push.on_threats(penv.conn, "bynet", now=NOW) == 0
    assert penv.queue() == []


def test_foreign_mailbox_never_reaches_a_bruger_even_if_queued(penv):
    """Defence in depth: access is checked again when the message is rendered
    (a forged row, or access narrowed after the event was queued)."""
    inge = penv.sub("inge")
    push.enqueue(None, "inge", "threat", {"counts": {"bynet": 3}}, now=NOW)
    push.enqueue(None, "inge", "problem", {"problems": [["auth", "bynet"]]}, now=NOW)
    penv.run()
    assert penv.svc.payloads(inge) == []
    assert {q["last_error"] for q in penv.queue()} == {"not_visible"}


def test_mixed_counts_render_only_visible_mailboxes(penv):
    inge = penv.sub("inge")
    push.enqueue(None, "inge", "threat", {"counts": {"bynet": 5, "molt-inge": 1}}, now=NOW)
    penv.run()
    [p] = penv.svc.payloads(inge)
    assert p["title"] == "Farlig mail stoppet" and "Inge" in p["body"] and "BYnet" not in p["body"]


def test_admin_with_several_mailboxes_gets_one_summary(penv):
    admin = penv.sub("Bjarke")
    push.enqueue(None, "Bjarke", "threat", {"counts": {"bynet": 2}}, now=NOW)
    push.enqueue(None, "Bjarke", "threat", {"counts": {"molt-inge": 1}}, now=NOW)
    penv.run()
    [p] = penv.svc.payloads(admin)
    assert p["title"] == "3 farlige mails stoppet"
    assert p["body"] == "Lagt i Spamfilter-mappen: BYnet (2), Inge (1). Åbn dem ikke."
    assert p["url"] == "/spam"


def test_problems_go_to_admins_only(penv):
    admin = penv.sub("Bjarke")
    inge = penv.sub("inge", prefs={"threat": True, "review": True, "problem": True})  # forced on: ignored
    assert push.on_problem(penv.conn, "auth", "bynet", now=NOW) == 1
    assert push.on_problem(penv.conn, "nonsense", "bynet", now=NOW) == 0
    penv.run()
    [p] = penv.svc.payloads(admin)
    assert p == {"title": "Login afvist", "body": "Mailserveren afviser login for BYnet. Tjek adgangskoden under Konti.",
                 "url": "/accounts", "tag": "sf-problem"}
    assert penv.svc.payloads(inge) == []


def test_problem_pref_off_means_no_push(penv):
    admin = penv.sub("Bjarke", prefs={"threat": True, "review": False, "problem": False})
    assert push.on_problem(penv.conn, "circuit", "bynet", now=NOW) == 0
    penv.run()
    assert penv.svc.payloads(admin) == []


def test_several_problems_are_merged(penv):
    admin = penv.sub("Bjarke")
    push.on_problem(None, "auth", "bynet", now=NOW)
    push.on_problem(None, "safe", "molt", now=NOW)
    push.on_problem(None, "auth", "bynet", now=NOW)      # duplicate
    penv.run()
    [p] = penv.svc.payloads(admin)
    assert p["title"] == "2 problemer med filteret" and p["url"] == "/system"
    assert "Login afvist (BYnet)" in p["body"] and "Sikkerhedstilstand (molt)" in p["body"]


def test_downtime_push_after_a_long_stop(penv):
    admin = penv.sub("Bjarke")
    hb = penv.state / "heartbeat"
    hb.write_text(f"{NOW - 300} boot\n")
    assert push.check_heartbeat_gap(hb, now=NOW) is False                # 5 min: no
    hb.write_text(f"{NOW - 3600} boot\n")
    assert push.check_heartbeat_gap(hb, now=NOW) is True
    penv.run()
    assert penv.svc.payloads(admin)[0]["title"] == "Filteret kører igen"
    assert push.check_heartbeat_gap(penv.state / "missing", now=NOW) is False


def test_payload_is_small_and_has_exactly_four_keys(penv):
    users = push.load_users()
    for kind, data in (("threat", {"counts": {"bynet": 999, "molt-inge": 2, "molt": 1}}),
                       ("review", {"counts": {"bynet": 1}}), ("problem", {"problems": [["safe", "molt"]]}),
                       ("test", {})):
        p = push.render("Bjarke", kind, data, users)
        assert set(p) == {"title", "body", "url", "tag"}
        assert len(json.dumps(p, ensure_ascii=False).encode()) < 400
        assert p["url"].startswith("/") and not p["url"].startswith("//")


# ---------------------------------------------------------------------------
# Rate limits, retries, cleanup
# ---------------------------------------------------------------------------


def test_one_push_per_tag_per_10_minutes_later_events_are_merged(penv):
    inge = penv.sub("inge", prefs={"threat": True, "review": True, "problem": False})
    push.enqueue(None, "inge", "threat", {"counts": {"molt-inge": 1}}, now=NOW)
    assert penv.run(NOW)["sent"] == 1
    push.enqueue(None, "inge", "threat", {"counts": {"molt-inge": 1}}, now=NOW + 60)
    assert penv.run(NOW + 60) == {"sent": 0, "deferred": 1, "dropped": 0, "failed": 0, "retry": 0}
    push.enqueue(None, "inge", "threat", {"counts": {"molt-inge": 2}}, now=NOW + 120)   # merged
    assert penv.run(NOW + 300)["sent"] == 0                          # still inside the 10 min
    push.enqueue(None, "inge", "review", {"counts": {"molt-inge": 1}}, now=NOW + 300)  # other tag: not held
    assert penv.run(NOW + 300)["sent"] == 1
    assert penv.run(NOW + push.TAG_INTERVAL)["sent"] == 1
    titles = [p["title"] for p in penv.svc.payloads(inge)]
    assert titles == ["Farlig mail stoppet", "Tjek disse", "3 farlige mails stoppet"]


def test_daily_cap_of_20(penv):
    inge = penv.sub("inge")
    t = NOW
    for _ in range(push.DAILY_MAX):
        push.enqueue(None, "inge", "threat", {"counts": {"molt-inge": 1}}, now=t)
        assert penv.run(t)["sent"] == 1
        t += push.TAG_INTERVAL
    push.enqueue(None, "inge", "threat", {"counts": {"molt-inge": 1}}, now=t)
    assert penv.run(t)["dropped"] == 1
    assert penv.queue()[-1]["last_error"] == "daily_limit"
    assert len(penv.svc.payloads(inge)) == 20
    # A test message is never counted against (or stopped by) the cap.
    assert push.send_test("inge", now=t, session=penv.svc)["ok"]
    # A day later it flows again.
    push.enqueue(None, "inge", "threat", {"counts": {"molt-inge": 1}}, now=t + 86400)
    assert penv.run(t + 86400)["sent"] == 1


@pytest.mark.parametrize("status", [404, 410])
def test_gone_subscriptions_are_deleted(penv, status):
    a, b = penv.sub("inge"), penv.sub("inge", host="fcm.googleapis.com")
    penv.svc.status_for[a.endpoint] = status
    push.enqueue(None, "inge", "threat", {"counts": {"molt-inge": 1}}, now=NOW)
    assert penv.run()["sent"] == 1
    assert [d["id"] for d in push.devices("inge")] == [b.id]


def test_429_and_5xx_back_off_and_retry_only_the_failed_device(penv):
    a, b = penv.sub("inge"), penv.sub("inge", host="updates.push.services.mozilla.com")
    penv.svc.status_for[a.endpoint] = 503
    push.enqueue(None, "inge", "threat", {"counts": {"molt-inge": 1}}, now=NOW)
    assert penv.run(NOW)["retry"] == 1
    [row] = penv.queue()
    assert row["status"] == "queued" and row["attempts"] == 1 and json.loads(row["targets"]) == [a.id]
    assert row["next_at"] == NOW + max(push.BACKOFF[0], 30) and row["sent_at"] == NOW   # b got it
    assert penv.run(NOW + 10)["retry"] == 0 and len(penv.svc.calls) == 2              # not due yet
    penv.svc.status_for[a.endpoint] = 201
    assert penv.run(row["next_at"])["sent"] == 1
    assert len(penv.svc.payloads(a)) == 2 and len(penv.svc.payloads(b)) == 1           # b never twice
    assert push.devices("inge")[0]["last_error"] is None


def test_retries_give_up_after_max_attempts(penv):
    a = penv.sub("inge")
    penv.svc.status_for[a.endpoint] = 429
    push.enqueue(None, "inge", "threat", {"counts": {"molt-inge": 1}}, now=NOW)
    t = NOW
    for _ in range(push.MAX_ATTEMPTS):
        penv.run(t)
        t += 4000
    [row] = penv.queue()
    assert row["status"] == "failed" and row["attempts"] == push.MAX_ATTEMPTS
    assert push.devices("inge")   # a busy service never deletes the device


def test_rejected_three_times_deletes_the_device(penv):
    a = penv.sub("inge")
    penv.svc.status_for[a.endpoint] = 400
    penv.svc.reason_for[a.endpoint] = "BadDeviceToken"      # the service says: this device is bad
    t = NOW
    for i in range(push.REJECT_DELETE):
        push.enqueue(None, "inge", "threat", {"counts": {"molt-inge": 1}}, now=t)
        penv.run(t)
        t += push.TAG_INTERVAL
        if i < push.REJECT_DELETE - 1:
            assert push.devices("inge")[0]["last_error"] == "400 BadDeviceToken"
    assert push.devices("inge") == []


@pytest.mark.parametrize("status,reason", [(403, "BadJwtToken"), (400, "BadExpirationDate"), (401, None),
                                           (413, None)])
def test_server_wide_refusal_never_deletes_a_device(penv, status, reason):
    """A JWT/clock/'sub' problem hits every device alike: keep them all,
    record it for sfctl doctor, and clear it once that service accepts us."""
    a, b = penv.sub("inge"), penv.sub("Bjarke")
    for d in (a, b):
        penv.svc.status_for[d.endpoint] = status
        if reason:
            penv.svc.reason_for[d.endpoint] = reason
    t = NOW
    for _ in range(push.REJECT_DELETE + 2):
        push.enqueue(None, "inge", "threat", {"counts": {"molt-inge": 1}}, now=t)
        push.enqueue(None, "Bjarke", "threat", {"counts": {"bynet": 1}}, now=t)
        penv.run(t)
        assert push.send_test("inge", now=t, session=penv.svc)["code"] == "refused"
        t += push.TAG_INTERVAL
    assert len(penv.svc.payloads(a)) == push.REJECT_DELETE + 2 + push.REJECT_DELETE + 2
    devs = push.devices("inge") + push.devices("Bjarke")
    assert len(devs) == 2
    assert all(d["last_error"] == f"{status} {reason or ''}".strip() for d in devs)
    st = push.status(now=t)
    assert st["refused"]["status"] == status and st["refused"]["host"] == "web.push.apple.com"
    assert st["refused"]["detail"] == (reason or "")
    assert all(dev["fail_count"] == 0 for dev in st["devices"])
    assert "endpoint" not in json.dumps(st["refused"]) and a.endpoint not in json.dumps(st)
    # The cause is fixed (clock, sub): the next delivery clears it.
    penv.svc.status_for[a.endpoint] = 201
    assert push.send_test("inge", now=t + push.TEST_WINDOW + 1, session=penv.svc)["ok"]
    assert push.status()["refused"] is None and push.devices("inge")[0]["last_error"] is None


def test_refusal_on_another_host_is_not_cleared_by_a_good_host(penv):
    a, b = penv.sub("inge"), penv.sub("inge", host="fcm.googleapis.com")
    penv.svc.status_for[a.endpoint] = 403
    res = push.send_test("inge", now=NOW, session=penv.svc)
    assert res["ok"] and res["sent"] == 1
    assert push.status()["refused"]["host"] == "web.push.apple.com"
    assert len(push.devices("inge")) == 2


def test_refused_test_message_text_per_role(penv):
    a = penv.sub("inge")
    penv.svc.status_for[a.endpoint] = 403
    res = push.send_test("inge", now=NOW, session=penv.svc)
    assert res["code"] == "refused" and "administratoren" in res["text"] and "sfctl" not in res["text"]
    d = penv.sub("Bjarke")
    penv.svc.status_for[d.endpoint] = 403
    res = push.send_test("Bjarke", now=NOW, is_admin=True, session=penv.svc)
    assert res["code"] == "refused" and "sfctl doctor" in res["text"]


def test_expired_rows_are_dropped(penv):
    penv.sub("inge")
    push.enqueue(None, "inge", "threat", {"counts": {"molt-inge": 1}}, now=NOW)
    assert penv.run(NOW + push.TTL["threat"] + 1)["dropped"] == 1
    assert penv.svc.calls == []


def test_queue_without_devices_is_dropped(penv):
    push.enqueue(None, "inge", "threat", {"counts": {"molt-inge": 1}}, now=NOW)
    assert penv.run()["dropped"] == 1 and penv.queue()[0]["last_error"] == "no_devices"


def test_device_with_the_kind_turned_off_gets_nothing(penv):
    a = penv.sub("inge")
    b = penv.sub("inge", prefs={"threat": False, "review": True, "problem": False})
    push.enqueue(None, "inge", "threat", {"counts": {"molt-inge": 1}}, now=NOW)
    penv.run()
    assert len(penv.svc.payloads(a)) == 1 and penv.svc.payloads(b) == []


def test_events_never_send_synchronously(penv, monkeypatch):
    penv.sub("Bjarke")
    monkeypatch.setattr(webpush, "send", lambda *a, **k: pytest.fail("the engine hook must not send"))
    assert push.on_problem(penv.conn, "auth", "bynet", now=NOW) == 1
    assert penv.queue()[0]["status"] == "queued"


def test_worker_thread_sends_in_the_background(penv, monkeypatch):
    sent = []

    def fake_send(endpoint, p256dh, auth, payload, **kw):
        sent.append(json.loads(payload))
        return webpush.SendResult(201, "ok")

    monkeypatch.setattr(webpush, "send", fake_send)
    monkeypatch.setattr(push, "WORKER_POLL", 0.2)
    penv.sub("Bjarke")
    push.enqueue(None, "Bjarke", "problem", {"problems": [["downtime", ""]]})
    try:
        assert push.ensure_worker() is True and push.ensure_worker() is True
        deadline = time.time() + 10
        while not sent and time.time() < deadline:
            time.sleep(0.05)
    finally:
        push.stop_worker()
    assert sent and sent[0]["title"] == "Filteret kører igen"
    assert not push.worker_alive()


# ---------------------------------------------------------------------------
# Test message
# ---------------------------------------------------------------------------


def test_send_test_to_this_device_or_all_and_rate_limit(penv):
    a, b = penv.sub("anna"), penv.sub("anna", host="fcm.googleapis.com")
    res = push.send_test("anna", endpoint=a.endpoint, now=NOW, session=penv.svc)
    assert res["ok"] and res["sent"] == 1 and penv.svc.payloads(a)[0]["title"] == "Testbesked"
    assert penv.svc.payloads(b) == []
    assert push.send_test("anna", now=NOW, session=penv.svc)["sent"] == 2
    other = device()
    res = push.send_test("anna", endpoint=other.endpoint, now=NOW, session=penv.svc)
    assert res["code"] == "no_devices"                       # not hers: never sent
    for _ in range(3):
        push.send_test("anna", now=NOW + 1, session=penv.svc)
    assert push.send_test("anna", now=NOW + 2, session=penv.svc)["code"] == "rate"
    assert push.send_test("anna", now=NOW + push.TEST_WINDOW + 5, session=penv.svc)["ok"]
    assert push.send_test("inge", now=NOW, session=penv.svc)["code"] == "no_devices"


def test_send_test_reports_rejection_and_busy(penv):
    a = penv.sub("anna")
    penv.svc.status_for[a.endpoint] = 503
    assert push.send_test("anna", now=NOW, session=penv.svc)["code"] == "retry"
    penv.svc.status_for[a.endpoint] = 400
    penv.svc.reason_for[a.endpoint] = "BadDeviceToken"
    assert push.send_test("anna", now=NOW, session=penv.svc)["code"] == "rejected"


def test_send_test_limit_holds_for_parallel_requests(penv):
    """The slot is reserved before the (slow) delivery: 12 simultaneous
    'Send testbesked' taps send at most TEST_MAX."""
    import threading

    penv.sub("anna")
    penv.svc.delay = 0.3
    results: list[dict] = []
    lock = threading.Lock()
    start = threading.Barrier(12)

    def tap():
        start.wait()
        r = push.send_test("anna", now=NOW, session=penv.svc)
        with lock:
            results.append(r)

    threads = [threading.Thread(target=tap) for _ in range(12)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(30)
    codes = sorted(r["code"] for r in results)
    assert codes.count("sent") == push.TEST_MAX and codes.count("rate") == 12 - push.TEST_MAX
    assert len(penv.svc.calls) == push.TEST_MAX
    rows = penv.queue()
    assert [r["status"] for r in rows] == ["sent"] * push.TEST_MAX     # no row left 'sending'
    assert penv.run()["sent"] == 0                                      # the worker never picks them up


# ---------------------------------------------------------------------------
# VAPID subject + key
# ---------------------------------------------------------------------------


def test_vapid_subject_fallbacks(penv, monkeypatch):
    assert push.vapid_subject() == "mailto:ole@example.com"                 # first mailbox
    penv.conn.execute("INSERT INTO settings_kv(key, value) VALUES('smtp', ?)",
                      (json.dumps({"from_addr": "spamfilter@example.org"}),))
    assert push.vapid_subject() == "mailto:spamfilter@example.org"          # SMTP sender
    monkeypatch.setenv("PUSH_VAPID_SUBJECT", "https://spamfilter.example.org")
    assert push.vapid_subject() == "https://spamfilter.example.org"
    monkeypatch.setenv("PUSH_VAPID_SUBJECT", "mailto:x@hjemmeserver.invalid")  # Apple would refuse it
    assert push.vapid_subject() == "mailto:spamfilter@example.org"
    penv.cfg.write_text("accounts: []\n")
    penv.conn.execute("DELETE FROM settings_kv")
    monkeypatch.delenv("PUSH_VAPID_SUBJECT")
    assert push.vapid_subject() is None


def test_key_is_reused_and_reset_rotates_and_deletes_everything(penv):
    k1 = push.public_key()
    assert push.public_key() == k1
    assert (penv.state / "vapid_private.pem").stat().st_mode & 0o777 == 0o600
    penv.sub("anna")
    penv.sub("Bjarke")
    push.enqueue(None, "anna", "threat", {"counts": {"bynet": 1}}, now=NOW)
    res = push.reset_all()
    assert res["subscriptions"] == 2 and len(res["fingerprint"]) == 12
    assert push.public_key() != k1
    assert penv.conn.execute("SELECT COUNT(*) FROM push_subscriptions").fetchone()[0] == 0
    assert [q for q in penv.queue() if q["status"] == "queued"] == []


def test_status_never_shows_endpoints_or_keys(penv):
    a = penv.sub("anna")
    push.public_key()
    st = push.status(now=NOW)
    assert st["available"] and st["key"] and st["key_mode"] == 0o600 and st["subject_ok"]
    assert st["devices"][0]["host"] == "web.push.apple.com" and st["devices"][0]["user"] == "anna"
    text = json.dumps(st, default=str)
    assert a.endpoint not in text and a.p256dh not in text and a.auth not in text
    assert "PRIVATE" not in text


# ---------------------------------------------------------------------------
# Tjek disse (review)
# ---------------------------------------------------------------------------


class Acc:
    def __init__(self, name="bynet", user="ole@example.com", threshold=8.0):
        self.name, self.user, self.threshold = name, user, threshold


def msg(e, mid, *, account="bynet", score=20.0, sender="Spam <spam@spam.example>", symbols=(), action="moved_to_junk",
        ts=NOW, verdict=None, threat=None, folder="Spamfilter", subject="HEMMELIGT"):
    e.conn.execute("INSERT INTO messages(account, message_id, first_seen, last_seen, current_folder, our_score, "
                   "our_action, sender, subject, symbols, scanned_at, user_verdict, threat) "
                   "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (account, mid, ts, ts, folder, score, action, sender, subject,
                    json.dumps([{"n": s, "s": 1.0} for s in symbols]), ts, verdict, threat))


def test_review_counts_only_maybe_legit_mail_and_batches_per_30_min(penv):
    inge = penv.sub("inge", prefs={"threat": True, "review": True, "problem": False})
    anna = penv.sub("anna", prefs={"threat": True, "review": True, "problem": False})
    acc = Acc()
    msg(penv, "<near@x>", score=9.0)                                       # just over 8.0
    msg(penv, "<contact@x>", score=30.0, symbols=["TH_KNOWN_CONTACT"])
    msg(penv, "<own@x>", score=30.0, sender="Kollega <k@example.com>")
    msg(penv, "<spam@x>", score=30.0)                                      # clear spam: no
    msg(penv, "<threat@x>", score=9.0, threat="phish")                     # dangerous: never "Tjek disse"
    msg(penv, "<judged@x>", score=9.0, verdict="spam", sender="Anden <a@andet.example>")
    msg(penv, "<inbox@x>", score=2.0, action="none", folder="INBOX", sender="Ven <ven@familie.example>")
    assert push.on_review(penv.conn, acc, now=NOW) == 1                    # anna (bynet) only
    penv.run(NOW)
    assert penv.svc.payloads(anna) == [{"title": "Tjek disse", "body": "3 nye mails i BYnet er måske ikke spam.",
                                        "url": "/spam?account=bynet", "tag": "sf-review"}]
    assert penv.svc.payloads(inge) == []
    # Inside the 30 min batch: held back, and the engine is told when to wake.
    msg(penv, "<near2@x>", score=8.5, ts=NOW + 60)
    assert push.on_review(penv.conn, acc, now=NOW + 60) == 0
    assert push.review_due_in(penv.conn, acc, now=NOW + 60) == pytest.approx(push.REVIEW_BATCH - 60)
    assert push.on_review(penv.conn, acc, now=NOW + push.REVIEW_BATCH) == 1
    penv.run(NOW + push.REVIEW_BATCH)
    assert penv.svc.payloads(anna)[-1]["body"] == "En ny mail i BYnet er måske ikke spam."
    assert push.review_due_in(penv.conn, acc, now=NOW + push.REVIEW_BATCH + 1) is None


def test_review_known_sender_counts(penv):
    anna = penv.sub("anna", prefs={"threat": False, "review": True, "problem": False})
    msg(penv, "<old-ham@x>", score=1.0, action="none", folder="INBOX", sender="Ven <ven@familie.example>",
        ts=NOW - 86400 * 30)
    msg(penv, "<caught@x>", score=25.0, sender="Ven <ven@familie.example>")
    assert push.on_review(penv.conn, Acc(), now=NOW) == 1
    penv.run()
    assert penv.svc.payloads(anna)[0]["body"] == "En ny mail i BYnet er måske ikke spam."


def test_review_without_subscribers_never_floods_later(penv):
    acc = Acc()
    msg(penv, "<a@x>", score=9.0, ts=NOW - 600)
    assert push.on_review(penv.conn, acc, now=NOW) == 0
    anna = penv.sub("anna", prefs={"threat": True, "review": True, "problem": False})
    assert push.on_review(penv.conn, acc, now=NOW + 30) == 0               # older than the floor
    msg(penv, "<b@x>", score=9.0, ts=NOW + 40)
    assert push.on_review(penv.conn, acc, now=NOW + 50) == 1
    penv.run(NOW + 50)
    assert penv.svc.payloads(anna)[0]["body"] == "En ny mail i BYnet er måske ikke spam."


def test_review_rule_matches_the_tjek_disse_page(penv):
    """push.review_qualifies() must agree with ui_mail.review_reasons()."""
    import dashboard
    import ui_mail

    rows = []
    cases = [
        dict(score=9.0), dict(score=10.9), dict(score=11.0), dict(score=30.0),
        dict(score=30.0, symbols=["TH_KNOWN_CONTACT"]), dict(score=30.0, symbols=["TH_REPLY"]),
        dict(score=30.0, symbols=["TH_PROTECTED_RCPT"]), dict(score=30.0, symbols=["TH_FORCE_UNVERIFIED"]),
        dict(score=30.0, sender="x@example.com"), dict(score=30.0, sender="X <x@mail.bynet.example>"),
        dict(score=30.0, sender="x@notbynet.example"), dict(score=None),
    ]
    for i, kw in enumerate(cases):
        msg(penv, f"<p{i}@x>", **kw)
    rows = penv.conn.execute("SELECT * FROM messages WHERE account='bynet' ORDER BY message_id").fetchall()
    acc = Acc()
    with dashboard.app.test_request_context("/"):
        for r in rows:
            for known in (0, 2):
                ui_side = bool(ui_mail.review_reasons(r, acc, acc.threshold, {"x@example.com": 0} if not known else
                                                      {ui_mail._addr_of(r["sender"]): known}))
                assert push.review_qualifies(r, user=acc.user, threshold=acc.threshold, known=known) is ui_side, \
                    (dict(r), known)


# ---------------------------------------------------------------------------
# Engine wiring (filter.py)
# ---------------------------------------------------------------------------


def test_engine_alert_once_pushes_a_problem_without_smtp(penv, monkeypatch):
    engine = penv.engine
    monkeypatch.setattr(engine, "STATE_DIR", penv.state)
    monkeypatch.setattr(engine, "CONFIG_PATH", penv.cfg)
    monkeypatch.setattr(engine, "_mailer", lambda: None)            # no SMTP at all
    admin = penv.sub("Bjarke")
    conn = engine._open_conn()
    try:
        assert engine.alert_once(conn, "auth:bynet", "1", "Spamfilter: Konto bynet: login afvist", "x") is False
        assert engine.alert_once(conn, "auth:bynet", "1", "Spamfilter: Konto bynet: login afvist", "x") is False
    finally:
        conn.close()
    push.configure_paths(penv.state, penv.cfg)
    rows = penv.queue()
    assert len(rows) == 1 and json.loads(rows[0]["data"]) == {"problems": [["auth", "bynet"]]}   # once per episode
    penv.run(int(time.time()))
    assert penv.svc.payloads(admin)[0]["title"] == "Login afvist"


def test_engine_push_startup_queues_downtime(penv, monkeypatch):
    engine = penv.engine
    monkeypatch.setattr(engine, "STATE_DIR", penv.state)
    monkeypatch.setattr(engine, "CONFIG_PATH", penv.cfg)
    monkeypatch.setattr(push, "ensure_worker", lambda: True)
    penv.sub("Bjarke")
    (penv.state / "heartbeat").write_text(f"{int(time.time()) - 7200} boot\n")
    import logging

    engine._push_startup(logging.getLogger("t"))
    assert json.loads(penv.queue()[0]["data"]) == {"problems": [["downtime", ""]]}


def test_engine_loop_pushes_a_moved_threat_and_review_mail(tmp_path, monkeypatch):
    """The real account loop (move mode, FakeIMAP): a phishing mail moved to
    the filter's folder queues one 'Farlig mail stoppet' push for the
    mailbox's Bruger at the Straks-advarsel moment; a borderline catch
    queues 'Tjek disse'. Nobody else gets anything."""
    from fakes_engine import setup_engine
    from test_engine_scan import Harness
    from test_engine_threatnotice import PHISH, threat_mail

    eng = setup_engine(tmp_path, monkeypatch)
    monkeypatch.setattr(eng, "_mailer", lambda: None)
    for name in ("STATE_DIR", "CONFIG_PATH", "DB_PATH", "USERS_FILE", "AUTO_WORKER"):
        monkeypatch.setattr(push, name, getattr(push, name))
    monkeypatch.setattr(push, "AUTO_WORKER", False)
    monkeypatch.setenv("PUSH_VAPID_SUBJECT", "mailto:ole@example.com")   # no accounts.yml in this harness
    (tmp_path / "dashboard_users").write_text(f"bea:{fast_hash(PW)}:acct:0\nanna:{fast_hash(PW)}:bynet:0\n")
    h = Harness(eng, monkeypatch, threshold=10.0)
    push.configure_paths(tmp_path, tmp_path / "accounts.yml")
    push.ensure_schema()
    svc = FakePushService()
    devs = {}
    for user in ("bea", "anna"):
        dev = device()
        assert push.subscribe(user, dev.endpoint, dev.p256dh, dev.auth,
                              prefs={"threat": True, "review": True, "problem": False})["ok"]
        svc.add(dev)
        devs[user] = dev
    threat_mail(h, "ph1@x", PHISH)
    h.deliver("near@x", score=11.0)          # caught, just over 10: "Tjek disse"
    h.loop()
    h.advance(120)
    h.loop()
    conn = sqlite3.connect(tmp_path / "spamfilter.db")
    rows = conn.execute("SELECT user, kind, data FROM push_queue ORDER BY id").fetchall()
    conn.close()
    assert {(u, k) for u, k, _ in rows} == {("bea", "threat"), ("bea", "review")}
    assert json.loads(next(d for u, k, d in rows if k == "threat")) == {"counts": {"acct": 1}}
    push.process_queue(now=int(h.t), session=svc)
    titles = sorted(p["title"] for p in svc.payloads(devs["bea"]))
    assert titles == ["Farlig mail stoppet", "Tjek disse"]
    assert svc.payloads(devs["anna"]) == []


# ---------------------------------------------------------------------------
# Suite guard (tests/conftest.py): never a real push service from the tests
# ---------------------------------------------------------------------------


def test_suite_never_reaches_a_real_push_service(penv):
    import requests

    assert push.AUTO_WORKER is False
    with pytest.raises(requests.ConnectionError):
        requests.Session().post("https://web.push.apple.com/x", data=b"", timeout=1)
    with pytest.raises(requests.ConnectionError):
        requests.Session().post("https://wns2-db5p.notify.windows.com/w/?token=x", data=b"", timeout=1)
    # webpush.send with its own (default) session: a 'retry', nothing sent.
    dev = device()
    res = webpush.send(dev.endpoint, dev.p256dh, dev.auth, b"{}", key=push.vapid_key(), subject="mailto:a@b.dk")
    assert res.outcome == "retry" and res.status == 0


def test_review_skips_borderline_mail_from_a_sender_already_called_spam(penv):
    """2.19.1 (judged.py): no phone ping for the next zoo-friends mail once a
    person has called the sender spam; a known contact still counts."""
    penv.sub("anna", prefs={"threat": False, "review": True, "problem": False})
    msg(penv, "<old@x>", score=9.0, verdict="spam", sender="Zoo <abc@zoo-friends.example>", ts=NOW - 86400)
    msg(penv, "<new@x>", score=9.0, sender="Zoo <xyz@zoo-friends.example>")
    assert push.on_review(penv.conn, Acc(), now=NOW) == 0
    msg(penv, "<new2@x>", score=9.0, sender="Zoo <q@zoo-friends.example>", symbols=["TH_KNOWN_CONTACT"], ts=NOW + 10)
    assert push.on_review(penv.conn, Acc(), now=NOW + push.REVIEW_BATCH) == 1
