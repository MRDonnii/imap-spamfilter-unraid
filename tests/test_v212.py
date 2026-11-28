"""2.12: quality and operations (plan #7, #11, #13, #14, #16, #20, #21,
#24, #25, #26).

- #7  CI: pip-audit + Trivy, Dependabot, pinned digests, ClamAV minimum, no
      pip (and its vendored urllib3/certifi) in the image
- #11 off-site copy age (> 48 h) and the monthly restore drill
- #13 provider junk is scored read-only and is a learning source
- #14 the Home Assistant package knows when it must be fetched again
- #16 update packages are checked against a release signature
- #20 the provider's SPAM_FLAG counts ~+2 for a trusted sender
- #21 mails scanned while ClamAV was starting are scanned again once it is ready
- #24 a new mailbox's old mail does not count as moves to Junk
- #25 housekeeping, container log on update, docker.img >= 85 %, task_timeout
- #26 login lock per IP + username, admin API keys LAN-only with their own rate
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "filter"))

from fakes_deploy import write_state  # noqa: E402
from fakes_engine import make_message, setup_engine  # noqa: E402
from test_engine_scan import Harness  # noqa: E402

LOG = logging.getLogger("test-212")
DAY = 86400


@pytest.fixture
def eng(tmp_path, monkeypatch):
    e = setup_engine(tmp_path, monkeypatch)
    import contacts

    contacts.forget_cached_keys()
    yield e
    contacts.forget_cached_keys()


def _versions() -> dict[str, str]:
    out = {}
    for line in (DEPLOY / "versions.env").read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            k, _, v = line.partition("=")
            out[k] = v
    return out


# ---------------------------------------------------------------- #7 supply chain

def test_ci_runs_pip_audit_and_a_pinned_trivy():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "pip-audit --strict -r filter/requirements.txt" in ci
    assert "pip-audit --no-deps --disable-pip -r" in ci            # the frozen image
    assert "/trivy\" image" in ci and "--severity HIGH,CRITICAL" in ci and "--exit-code 1" in ci
    assert re.search(r"TRIVY_SHA256: [0-9a-f]{64}", ci) and "sha256sum -c" in ci
    assert "aquasecurity/trivy-action" not in ci                   # no third-party action
    assert (ROOT / ".trivyignore").exists()


def test_dependabot_covers_pip_docker_and_actions():
    text = (ROOT / ".github" / "dependabot.yml").read_text()
    for eco in ("pip", "docker", "github-actions"):
        assert re.search(rf"package-ecosystem: {eco}\b", text), eco
    assert text.count("interval: monthly") == 3


def test_pins_and_clamav_minimum():
    v = _versions()
    assert v["VERSION"] == "2.21.0" and v["AIO_IMAGE"].endswith(":2.21.0")
    assert v["REDIS_AIO_TAG"] == "8.10.3-trixie" and v["AIO_REDIS_VERSION"] == "8.10.3"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", v["REDIS_AIO_DIGEST"])
    assert v["AIO_CLAMAV_MIN"] == "1.4.6"
    docker = (DEPLOY / "aio" / "Dockerfile").read_text()
    assert "ARG EXPECT_CLAMAV_MIN=1.4.6" in docker and 'EXPECT_CLAMAV_MIN="$EXPECT_CLAMAV_MIN"' in docker
    assert f"ARG RSPAMD_IMAGE={v['RSPAMD_IMAGE']}" in docker
    check = (DEPLOY / "aio" / "build-check.sh").read_text()
    assert "EXPECT_CLAMAV_MIN" in check and "sort -V" in check and "is older than" in check
    assert '"EXPECT_CLAMAV_MIN=$AIO_CLAMAV_MIN"' in (DEPLOY / "aio" / "lib-aio.sh").read_text()


def test_pip_and_its_vendored_copies_are_removed_from_the_image():
    docker = (DEPLOY / "aio" / "Dockerfile").read_text()
    assert "python -m pip uninstall -y --disable-pip-version-check pip" in docker
    assert "ensurepip/_bundled" in docker and "! python -c 'import pip'" in docker
    check = (DEPLOY / "aio" / "build-check.sh").read_text()
    assert "import pip" in check and "pip is still installed" in check


def test_build_check_clamav_minimum_logic():
    """The version comparison of build-check.sh, run on its own."""
    snippet = ('cv="${v#ClamAV }"; cv="${cv%%/*}"\n'
               '[[ "$(printf \'%s\\n%s\\n\' "$EXPECT_CLAMAV_MIN" "$cv" | sort -V | head -n 1)" == "$EXPECT_CLAMAV_MIN" ]]')
    for v, ok in (("ClamAV 1.4.6/27830/Fri Nov 20", True), ("ClamAV 1.4.7", True), ("ClamAV 1.5.5/1", True),
                  ("ClamAV 1.4.3/27800", False), ("ClamAV 1.0.9", False)):
        r = subprocess.run(["bash", "-c", snippet], env={"v": v, "EXPECT_CLAMAV_MIN": "1.4.6", "PATH": os.environ["PATH"]})
        assert (r.returncode == 0) is ok, v


# ---------------------------------------------------------------- #25 rspamd task timeout

def test_rspamd_task_timeout_is_25s_below_the_filter_http_timeout():
    text = (ROOT / "rspamd" / "local.d" / "options.inc").read_text()
    m = re.search(r"^task_timeout = (\d+)s;$", text, re.M)
    assert m and int(m.group(1)) == 25
    eng_text = (ROOT / "filter" / "filter.py").read_text()
    http = int(re.search(r"^HTTP_TIMEOUT = (\d+)", eng_text, re.M).group(1))
    assert int(m.group(1)) < http


# ---------------------------------------------------------------- #13 provider junk scoring

def test_provider_junk_is_scored_read_only(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.client.writes.clear()
    h.deliver("pj@x", folder="Junk", score=3.0, sender="a@b.dk")
    h.poll()
    r = h.row("pj@x")
    assert r["our_action"] == "provider_junk" and r["current_folder"] == "Junk"
    assert r["our_score"] == pytest.approx(3.0) and r["scanned_at"] is not None
    assert r["pending_learn"] is None and r["user_verdict"] is None
    assert h.client.writes == []                                   # never flagged or moved
    assert all(c[2] is True for c in h.client.calls if c[0] == "select_folder" and c[1] == "Junk")
    assert any(e[1] == "pj@x" for e in h.events("provider_junk_scored"))
    # Scored once: the next poll does not fetch it again.
    h.client.calls.clear()
    h.state.last_junk_reconcile = 1e12
    h.poll()
    assert not any(c[0] == "fetch" for c in h.client.calls)


def test_provider_spam_is_scored_but_never_learned(eng, monkeypatch):
    # Review 2.12: the score contains the provider's own verdict - learning
    # from it would feed the provider's false positives into the shared pool.
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("big@x", folder="Junk", score=20.0)
    h.deliver("mid@x", folder="Junk", score=9.0)
    h.poll()
    assert h.row("big@x")["our_score"] == pytest.approx(20.0)
    assert h.row("big@x")["pending_learn"] is None and h.row("mid@x")["pending_learn"] is None
    h.advance(h.acc.learn_grace_seconds + 1)
    h.state.last_junk_reconcile = 1e12
    h.poll()
    assert h.row("big@x")["learned_as"] is None and h.row("big@x")["current_folder"] == "Junk"
    assert h.rspamd.learn_calls == []
    assert h.client.writes == [] or all("Junk" not in str(w) for w in h.client.writes if w[0] == "move")


def test_provider_junk_scoring_does_not_dilute_the_circuit_breaker(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", circuit_min_moves=2, circuit_max_ratio=0.5)
    for i in range(5):
        h.deliver(f"pj{i}@x", folder="Junk", score=2.0)
    h.poll()
    assert all(h.row(f"pj{i}@x")["scanned_at"] is not None for i in range(5))
    scanned = h.db.conn.execute(
        "SELECT COUNT(*) FROM messages WHERE account=? AND scanned_at IS NOT NULL", (h.acc.name,)).fetchone()[0]
    assert scanned == 5
    # 2 moves against 0 scanned inbox mails trips; the 5 scored junk rows do not count.
    allowed, why = eng.circuit_trip_reason(h.db.conn, h.acc, 2)
    assert allowed == 0 and why and "2 af 0 scannede" in why


def test_provider_spam_learn_needs_learn_from_moves(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", learn_from_moves=False)
    h.deliver("big@x", folder="Junk", score=20.0)
    h.poll()
    assert h.row("big@x")["our_score"] == pytest.approx(20.0) and h.row("big@x")["pending_learn"] is None


def test_provider_junk_scoring_is_bounded_and_skips_old_mail(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    old = dt.datetime.fromtimestamp(h.t - 20 * DAY, dt.timezone.utc)
    h.deliver("old@x", folder="Junk", score=2.0, internaldate=old)
    for i in range(12):
        h.deliver(f"n{i}@x", folder="Junk", score=2.0)
    h.poll()
    scored = [m for m in [f"n{i}@x" for i in range(12)] if h.row(m)["our_score"] is not None]
    assert len(scored) == eng.PROVIDER_JUNK_SCORE_PER_RUN == 10
    h.state.last_junk_reconcile = 1e12
    h.poll()
    assert all(h.row(f"n{i}@x")["our_score"] is not None for i in range(12))
    assert h.row("old@x")["our_score"] is None                     # older than 14 days: never fetched


def test_provider_junk_scoring_stops_on_an_rspamd_outage(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    h.deliver("pj@x", folder="Junk", score=3.0)
    h.rspamd.outage = True
    h.poll()                                                       # the header pass still works
    r = h.row("pj@x")
    assert r["our_action"] == "provider_junk" and r["scanned_at"] is None
    h.rspamd.outage = False
    h.state.last_junk_reconcile = 1e12
    h.poll()
    assert h.row("pj@x")["our_score"] == pytest.approx(3.0)


def test_provider_review_reasons_only_low_score_from_known_sender():
    import ui_mail

    known = ["Du har fået 3 normale mails fra denne afsender før"]
    row = {"our_score": 2.0}
    out = ui_mail.provider_review_reasons(row, 7.0, known)
    assert out[0].startswith("Udbyderen lagde den i sin spam-mappe") and out[1:] == known
    assert ui_mail.provider_review_reasons({"our_score": 9.0}, 7.0, known) == []      # the filter agrees
    assert ui_mail.provider_review_reasons({"our_score": 2.0}, 7.0, ["Tæt på grænsen"]) == []  # unknown sender
    assert ui_mail.provider_review_reasons({"our_score": None}, 7.0, known) == []     # never scored


# ---------------------------------------------------------------- #20 SPAM_FLAG for trusted senders

FLAG = [{"n": "SPAM_FLAG", "s": 5.0, "o": []}]


def test_provider_flag_offset_rules(eng):
    off = eng.provider_flag_offset(FLAG, {"SPAM_FLAG", "TH_ESTABLISHED"}, None)
    assert off["n"] == "TH_PROVIDER_FLAG_TRUSTED" and off["s"] == pytest.approx(-3.0)
    assert eng.provider_flag_offset(FLAG, {"SPAM_FLAG", "TH_KNOWN_CONTACT"}, None)["s"] == pytest.approx(-3.0)
    assert eng.provider_flag_offset(FLAG, {"SPAM_FLAG"}, None) is None                  # unknown sender
    assert eng.provider_flag_offset(FLAG, {"SPAM_FLAG", "TH_ESTABLISHED"}, "phishing") is None
    assert eng.provider_flag_offset([], {"TH_ESTABLISHED"}, None) is None               # no flag
    assert eng.provider_flag_offset([{"n": "SPAM_FLAG", "s": 1.5}], {"TH_REPLY"}, None) is None


@pytest.mark.parametrize("name,final,released", [
    # The known releases (bynet, threshold 7): the shelly mail (8.6) now passes;
    # boerkopcykler (13.3) is still over the threshold - other rules carry it.
    ("shelly", 8.6, True),
    ("boerkopcykler", 13.3, False),
])
def test_known_releases_with_spam_flag(eng, name, final, released):
    off = eng.provider_flag_offset(FLAG, {"SPAM_FLAG", "TH_ESTABLISHED"}, None)
    assert (final + off["s"] < 7.0) is released, name


def test_spam_flag_offset_in_the_live_score(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", threshold=7.0)
    h.rspamd.scores["f@x"] = 8.6
    h.rspamd.symbols["f@x"] = {"SPAM_FLAG": {"name": "SPAM_FLAG", "score": 5.0, "options": []}}
    trust = SimpleNamespace(symbols=[{"n": "TH_ESTABLISHED", "s": 0.0, "o": []}], delta=0.0, unmatched=False)
    monkeypatch.setattr(eng, "_contact_trust", lambda *a, **k: trust)
    raw = make_message("f@x", sender="noreply@shelly.cloud")
    sc = eng._score_message(h.db, h.acc, raw, msgid="f@x", prior=None, flags=set(), received_at=h.t)
    assert "TH_PROVIDER_FLAG_TRUSTED" in sc.names and sc.final == pytest.approx(5.6)
    assert not sc.decision.spam
    monkeypatch.setattr(eng, "_contact_trust", lambda *a, **k: None)
    sc = eng._score_message(h.db, h.acc, raw, msgid="f@x", prior=None, flags=set(), received_at=h.t)
    assert "TH_PROVIDER_FLAG_TRUSTED" not in sc.names and sc.final == pytest.approx(8.6) and sc.decision.spam


# ---------------------------------------------------------------- #21 ClamAV ready

FAIL = {"CLAM_VIRUS_FAIL": {"name": "CLAM_VIRUS_FAIL", "score": 0.0, "options": ["failed to scan"]}}


def _av_setup(eng, monkeypatch, ready):
    from test_engine_avrescan import deliver

    h = Harness(eng, monkeypatch, threshold=6.0, zap=False)
    deliver(h, "t@x", attach=False)                               # text only (2.12)
    import aio_health

    state = {"ok": ready}
    monkeypatch.setenv("SPAMFILTER_AIO", "1")
    monkeypatch.setattr(eng, "_AV_READY", {"at": 0.0, "ok": None})
    monkeypatch.setattr(aio_health, "probe_clamav_ready",
                        lambda *a, **k: aio_health.Result(state["ok"], "test"))
    return h, state


def _avq(h):
    return {r["message_id"]: dict(r) for r in h.db.conn.execute("SELECT * FROM av_rescan_queue")}


def _av(eng, h):
    return eng.av_rescan_pass(h.client, h.db, LOG, h.acc, h.acc.folder_map, h.state)


def test_clamav_ready_is_unknown_outside_the_aio(eng, monkeypatch):
    monkeypatch.delenv("SPAMFILTER_AIO", raising=False)
    assert eng.clamav_ready() is None


def test_rescan_waits_while_clamav_starts_and_runs_once_it_is_ready(eng, monkeypatch):
    h, state = _av_setup(eng, monkeypatch, ready=False)
    assert set(_avq(h)) == {"t@x"}
    h.advance(15 * 60)                                             # first attempt due, but ClamAV is not ready
    assert _av(eng, h) == 0
    assert _avq(h)["t@x"]["attempt"] == 0                          # no attempt used up
    state["ok"] = True
    monkeypatch.setattr(eng, "_AV_READY", {"at": 0.0, "ok": None})
    h.rspamd.symbols["t@x"] = {}                                   # ClamAV answers: clean
    assert _av(eng, h) == 1
    assert "t@x" not in _avq(h)
    assert any(e[1] == "t@x" for e in h.events("av_rescan_clean"))


def test_ready_clamav_rescans_before_the_10_minutes(eng, monkeypatch):
    h, _state = _av_setup(eng, monkeypatch, ready=True)
    h.rspamd.symbols["t@x"] = {}
    assert _av(eng, h) == 0                                        # just queued: not yet (60 s)
    h.advance(90)
    assert _av(eng, h) == 1 and "t@x" not in _avq(h)


# ---------------------------------------------------------------- #24 old mail of a new mailbox

def test_old_mail_moved_to_junk_is_not_a_move_to_junk(eng, monkeypatch):
    # A new mailbox with a separate filter folder: the inbox mail that was
    # there before the first scan (skipped by the bookmark) is tidied into the
    # filter's folder - not a move to Junk. A new mail the filter scanned is.
    h = Harness(eng, monkeypatch, mode="move", preexisting=1, folders=("INBOX", "Junk", "Trash"),
                junk="Spamfilter", junk_explicit=True)
    old = dt.datetime.fromtimestamp(h.t - 30 * DAY, dt.timezone.utc)
    h.client.folders["INBOX"].msgs[min(h.client.folders["INBOX"].msgs)].internaldate = old
    h.poll()                                                       # first sight of the spam folders
    h.deliver("new@x", score=1.0)
    h.scan()
    h.advance(600)
    h.user_moves("old0@x", "INBOX", "Spamfilter")
    h.user_moves("new@x", "INBOX", "Spamfilter")
    h.poll()
    o, n = h.row("old0@x"), h.row("new@x")
    assert o["current_folder"] == "Spamfilter" and o["our_action"] == "provider_junk"
    assert o["user_verdict"] is None and o["pending_learn"] is None
    assert any(e[1] == "old0@x" for e in h.events("junk_preexisting"))
    assert n["our_action"] == "user_junked" and n["pending_learn"] == "spam"
    got = h.db.conn.execute("SELECT n FROM stats_daily WHERE account=? AND day=? AND metric='user_junked'",
                            (h.acc.name, eng.stats_day(h.t))).fetchone()
    assert got[0] == 1


def test_fix_preexisting_junk_counts_corrects_the_first_day_once(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move")
    started = eng.account_started(h.db)
    db, acc = h.db, h.acc.name
    with db.tx():
        for i, rec in enumerate((started - 40 * DAY, started - 5 * DAY, started + 3600)):
            mid = f"m{i}@x"
            db.upsert_message(mid, "Junk", "a@b.dk", "s", rec)
            db.update_message(mid, our_action="user_junked", user_verdict="spam", verdict_at=started + 7200,
                              verdict_by="user:move", pending_learn="spam", pending_learn_at=started + 7200)
            db.log_event("user_junked", mid, detail="uid=1")
        day = eng.stats_day(started + 7200)
        db.conn.execute("INSERT INTO stats_daily(account, day, metric, n) VALUES(?,?,?,?)", (acc, day, "user_junked", 3))
    assert eng.fix_preexisting_junk_counts(db, LOG) == 2
    n = db.conn.execute("SELECT n FROM stats_daily WHERE account=? AND day=? AND metric='user_junked'",
                        (acc, day)).fetchone()[0]
    assert n == 1
    for mid in ("m0@x", "m1@x"):
        r = db.get_message(mid)
        assert r["our_action"] == "provider_junk" and r["user_verdict"] is None and r["pending_learn"] is None
    assert db.get_message("m2@x")["our_action"] == "user_junked"   # arrived after the start: a real move
    ev = {r[0] for r in db.conn.execute("SELECT event FROM events WHERE message_id IN ('m0@x','m1@x')")}
    assert ev == {"junk_preexisting"}
    assert eng.fix_preexisting_junk_counts(db, LOG) == 0          # once


def test_dmarc_metrics_are_registered(eng):
    assert {"dmarc_reports", "dmarc_moved"} <= eng.STAT_METRICS


# ---------------------------------------------------------------- #14 Home Assistant package

def test_ha_package_flags_a_missing_mailbox(monkeypatch):
    import ui_ha

    text = ui_ha.ha_package_yaml("http://x:1", ["bynet", "molt", "molt-sofie"])
    assert "# Sensorer for 3 postkasser: bynet, molt, molt-sofie." in text
    assert "unique_id: spamfilter_pakken_skal_hentes_igen" in text
    assert "(value_json.account_ids | sort) != ['bynet', 'molt', 'molt-sofie']" in text
    for n in ("bynet", "molt", "molt_sofie"):
        assert f"unique_id: spamfilter_{n}_status" in text
    import yaml

    yaml.safe_load(text.replace("!secret", "secret"))
    md = (ROOT / "HOME-ASSISTANT.md").read_text()
    assert "Ny postkasse? Hent pakken igen." in md and "spamfilter_pakken_skal_hentes_igen" in md


# ---------------------------------------------------------------- #26 login lock + admin keys

@pytest.fixture
def uenv(tmp_path, monkeypatch):
    from fakes_ui import TEST_PASSWORD, fast_hash
    from fakes_ui_admin import make_admin_env

    import dashboard

    e = make_admin_env(tmp_path, monkeypatch)
    hp = fast_hash(TEST_PASSWORD)
    (e.state / "dashboard_users").write_text(f"admin:{hp}:admin:0\nanna:{hp}:bynet:0\n")
    e.pw = TEST_PASSWORD
    e.ui = dashboard
    return e


def _login(env, ip, name, password):
    from fakes_ui import csrf_of

    c = env.app.test_client()
    c.environ_base["REMOTE_ADDR"] = ip
    c.get("/login")
    return c.post("/login", data={"username": name, "password": password, "csrf": csrf_of(c)})


def _lock_keys(ui):
    conn = ui._connect()
    try:
        return {str(r["key"]) for r in conn.execute("SELECT key FROM login_attempts WHERE locked_until IS NOT NULL")}
    finally:
        conn.close()


def test_login_lock_is_per_ip_and_username(uenv):
    ui = uenv.ui
    for _ in range(ui.LOGIN_MAX_FAILURES):
        _login(uenv, "203.0.113.9", "admin", "forkert")
    assert _login(uenv, "203.0.113.9", "admin", uenv.pw).status_code == 429     # that address is locked
    locked = _lock_keys(ui)
    assert "user:admin@203.0.113.9" in locked and "user:admin" not in locked
    # Guesses from outside never lock the owner out elsewhere (home or another address).
    assert _login(uenv, "192.168.1.20", "admin", uenv.pw).status_code == 302
    assert _login(uenv, "198.51.100.4", "admin", uenv.pw).status_code == 302


def test_guesses_from_many_ips_still_lock_the_username_from_outside(uenv, monkeypatch):
    # Review 2.12 (#26): a guessing attack spread over many IPs is slowed by
    # one counter per username for requests from outside - home stays open.
    ui = uenv.ui
    monkeypatch.setattr(ui, "LOGIN_MAX_FAILURES_USER_EXTERNAL", 6)
    for i in range(6):
        _login(uenv, f"198.51.100.{10 + i}", "admin", "forkert")
    assert "userx:admin" in _lock_keys(ui)
    assert _login(uenv, "203.0.113.77", "admin", uenv.pw).status_code == 429       # a fresh outside IP
    assert _login(uenv, "192.168.1.20", "admin", uenv.pw).status_code == 302          # home is never locked
    assert "userx:admin" in _lock_keys(ui)                                          # not refilled by that login


def test_good_logins_from_outside_never_add_up_to_a_lock(uenv, monkeypatch):
    ui = uenv.ui
    monkeypatch.setattr(ui, "LOGIN_MAX_FAILURES_USER_EXTERNAL", 3)
    for i in range(5):
        assert _login(uenv, f"198.51.100.{30 + i}", "admin", uenv.pw).status_code == 302
    assert "userx:admin" not in _lock_keys(ui)


def test_admin_keys_are_lan_only_with_their_own_rate(uenv):
    ui = uenv.ui
    with uenv.app.test_request_context("/"):
        with pytest.raises(ValueError, match="hjemmenetværket"):
            ui.api_key_create("Admin udefra", "admin", "admin", lan_only=False)
        tok, row = ui.api_key_create("Admin hjemme", "admin", "admin", lan_only=True)
    assert row["scope"] == "admin" and tok.startswith(ui.API_KEY_PREFIX)
    assert ui.API_KEY_RATE["admin"] < ui.API_KEY_RATE["control"]
    sha = ui.api_key_hash(tok)
    waits = [ui._api_rate_wait(sha, "admin") for _ in range(ui.API_KEY_RATE["admin"] + 1)]
    assert waits[:-1] == [0] * ui.API_KEY_RATE["admin"] and waits[-1] > 0


def test_old_admin_key_made_for_anywhere_is_refused_from_outside(uenv):
    ui = uenv.ui
    with uenv.app.test_request_context("/"):
        tok, row = ui.api_key_create("Gammel", "admin", "admin", lan_only=True)
    conn = ui._connect()
    conn.execute("UPDATE ui_api_keys SET lan_only=0 WHERE id=?", (row["id"],))   # made before 2.12
    conn.commit()
    conn.close()
    assert ui._api_keys_remote_allowed() is False
    src = (ROOT / "filter" / "dashboard.py").read_text()
    assert '(row["lan_only"] or str(row["scope"]) == "admin") and not local' in src


def test_sfctl_unlock_finds_the_per_ip_user_locks():
    text = (ROOT / "filter" / "sfctl.py").read_text()
    assert 'startswith(f"user:{low}@")' in text and 'f"userx:{low}"' in text
    assert "ui.login_user_key(username, ip)" in (ROOT / "filter" / "login_alerts.py").read_text()
    assert "ui.login_user_ext_key(username)" in (ROOT / "filter" / "login_alerts.py").read_text()
    assert "ui.login_user_keys(user.name)" in (ROOT / "filter" / "passkeys.py").read_text()


# ---------------------------------------------------------------- #11 off-site age + restore drill

from test_deploy_scripts import DRILL_OK, _all_up, _container, _monitor, _offsite, host, lib_bash, offsite  # noqa: E402,F401

DRILL_RCLONE = r'''#!/bin/bash
printf '%s\n' "$*" >>"$FAKE_RCLONE_LOG"
case "$1" in
  lsf) printf 'spamfilter-20261101T013000Z.sfbak\nspamfilter-20261102T013000Z.sfbak\n' ;;
  copyto) [[ "${FAKE_DRILL_BAD:-0}" == 1 ]] && printf 'garbage' >"$3" || printf 'SFBACKUP\x01remote' >"$3" ;;
esac
exit 0
'''
VERIFY_OK = "OK: spamfilter-20261102T013000Z.sfbak er hel – 12 filer, 1.234 byte, lavet 2. nov. 02:30 (version 2.12.0)."


def _drill_env(offsite, **extra):
    rc = offsite.tmp / "rclone-drill"
    rc.write_text(DRILL_RCLONE)
    rc.chmod(0o755)
    return {"SF_RCLONE_BIN": str(rc), "SF_RESTORE_DRILL_DAYS": "30", **extra}


def _drill(offsite):
    return json.loads((offsite.app / "state" / "restore-drill.json").read_text())


def test_restore_drill_fetches_the_newest_remote_archive_and_verifies_it(offsite):
    write_state(offsite.state_file, {"spamfilter": _container("imap-spamfilter-unraid:2.21.0")})
    proc = _offsite(offsite, **_drill_env(offsite, FAKE_DOCKER_EXEC=json.dumps(
        {"spamfilter sfctl backup-verify": VERIFY_OK, "spamfilter sfctl backup-drill": json.dumps({"ok": True, "app_started": True, "network": "unix_sockets_only"})})))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    calls = (offsite.tmp / "rclone.log").read_text().splitlines()
    cp = next(c for c in calls if c.startswith("copyto "))
    assert cp.startswith("copyto offsite:Backup/Spamfilter/spamfilter-20261102T013000Z.sfbak "
                         + str(offsite.dest) + "/.restore-drill.")
    dr = _drill(offsite)
    assert dr["ok"] is True and dr["archive"] == "spamfilter-20261102T013000Z.sfbak" and dr["error"] is None
    assert dr["detail"].startswith("OK: ") and dr["every_days"] == 30
    assert oct((offsite.app / "state" / "restore-drill.json").stat().st_mode & 0o777) == "0o644"
    assert not list(offsite.dest.glob(".restore-drill.*"))         # the temp copy is gone
    assert "/backup/.restore-drill." in Path(offsite.env["FAKE_DOCKER_CALLS"]).read_text()
    # Not due again for 30 days.
    (offsite.tmp / "rclone.log").unlink()
    _offsite(offsite, **_drill_env(offsite))
    assert not any(c.startswith("copyto ") for c in (offsite.tmp / "rclone.log").read_text().splitlines())


def test_failed_restore_drill_notifies_and_is_retried(offsite):
    proc = _offsite(offsite, **_drill_env(offsite, FAKE_DRILL_BAD="1"))
    assert proc.returncode == 0, proc.stdout + proc.stderr       # the copy itself is done
    dr = _drill(offsite)
    assert dr["ok"] is False and "ikke en krypteret backup" in dr["error"]
    assert "gendannelsesøvelsen fejlede" in Path(offsite.env["FAKE_NOTIFY_LOG"]).read_text()
    assert json.loads((offsite.app / "state" / "offsite-status.json").read_text())["ok"] is True
    assert not list(offsite.dest.glob(".restore-drill.*"))
    # sfctl backup-verify fails (no exec answer) -> also a failed drill; due again the next day
    proc = _offsite(offsite, **_drill_env(offsite))
    assert _drill(offsite)["ok"] is False and "backup-verify" in _drill(offsite)["error"]


def test_restore_drill_off_and_dry_run(offsite):
    _offsite(offsite, **_drill_env(offsite, SF_RESTORE_DRILL_DAYS="0"))
    assert not (offsite.app / "state" / "restore-drill.json").exists()
    proc = _offsite(offsite, "--dry-run", **_drill_env(offsite))
    assert "restore drill due" in proc.stdout and not (offsite.app / "state" / "restore-drill.json").exists()


def _fake_df(host, pct):
    df = host.tmp / "bin-df"
    df.mkdir(exist_ok=True)
    (df / "df").write_text(f'#!/bin/bash\necho "Filesystem 1-blocks Used Available Capacity Mounted"\n'
                           f'echo "/dev/x 1000 {pct * 10} {1000 - pct * 10} {pct}% /x"\n')
    (df / "df").chmod(0o755)
    return {"PATH": f"{df}:{host.env['PATH']}"}


def _monitor_alerts(host, **extra):
    write_state(host.state_file, _all_up())
    (host.app / "state" / "heartbeat").write_text(f"{int(time.time()) - 10} boot\n")
    (host.app / "state" / "backup-status.json").write_text(json.dumps(
        {"ok": True, "ts": int(time.time()) - 3600, "archive": "/x", "size": 1, "error": None}))
    _monitor(host, FAKE_CURL_BODY=json.dumps({"ok": True, "version": "2.21.0", "accounts": {"bynet": "idle"}}),
             FAKE_DOCKER_EXEC=json.dumps({"spamfilter-unbound drill": DRILL_OK, "spamfilter-rspamd rspamc": "ok"}),
             **extra)
    st = json.loads((host.app / "state" / "host-status.json").read_text())
    return st, {a["key"]: a for a in st["alerts"]}


def test_monitor_offsite_age_and_drill(host):
    now = int(time.time())
    off = host.app / "state" / "offsite-status.json"
    drill = host.app / "state" / "restore-drill.json"
    off.write_text(json.dumps({"ok": True, "ts": now - 3600, "remote": "R:x", "skipped": None, "error": None}))
    drill.write_text(json.dumps({"ok": True, "ts": now - 86400, "archive": "a.sfbak", "every_days": 30}))
    st, al = _monitor_alerts(host, **_fake_df(host, 50))
    assert "offsite" not in al and "restore-drill" not in al
    assert st["backup"]["offsite"]["ok"] is True and st["backup"]["drill"]["ok"] is True
    off.write_text(json.dumps({"ok": True, "ts": now - 49 * 3600, "remote": "R:x", "skipped": None}))
    drill.write_text(json.dumps({"ok": False, "ts": now - 3600, "error": "hentning fejlede", "every_days": 30}))
    _st, al = _monitor_alerts(host, **_fake_df(host, 50))
    assert "ældre end 48 timer" in al["offsite"]["text"] and "hentning fejlede" in al["restore-drill"]["text"]
    off.write_text(json.dumps({"ok": False, "ts": now, "error": "rclone exit 5"}))
    drill.write_text(json.dumps({"ok": True, "ts": now - 40 * 86400, "every_days": 30}))
    _st, al = _monitor_alerts(host, **_fake_df(host, 50))
    assert "fejlede: rclone exit 5" in al["offsite"]["text"] and "over 35 dage" in al["restore-drill"]["text"]
    # Off-site turned off on purpose: no alert.
    off.write_text(json.dumps({"ok": True, "ts": now - 10 * 86400, "skipped": "SF_OFFSITE_REMOTE er tom"}))
    drill.unlink()
    _st, al = _monitor_alerts(host, **_fake_df(host, 50))
    assert "offsite" not in al and "restore-drill" not in al


@pytest.mark.parametrize("pct,alert", [(84, False), (85, True), (92, True)])
def test_monitor_docker_img_warns_from_85_percent(host, pct, alert):
    _st, al = _monitor_alerts(host, **_fake_df(host, pct))
    assert ("disk:docker_img" in al) is alert
    assert ("disk:appdata" in al) is (pct >= 90)


def test_backup_summary_and_ui_show_offsite_age_and_drill(tmp_path, monkeypatch):
    import backup as bk

    monkeypatch.setattr(bk, "STATE_DIR", tmp_path)
    now = time.time()
    (tmp_path / "offsite-status.json").write_text(json.dumps({"ok": True, "ts": now - 50 * 3600, "remote": "R:x"}))
    (tmp_path / "restore-drill.json").write_text(json.dumps(
        {"ok": True, "ts": now - 3 * 86400, "archive": "a.sfbak", "every_days": 30}))
    s = bk.summary(now)
    assert s["offsite"]["stale"] is True
    assert s["drill"]["ok"] is True and s["drill"]["overdue"] is False and s["drill"]["archive"] == "a.sfbak"
    (tmp_path / "restore-drill.json").write_text(json.dumps({"ok": True, "ts": now - 40 * 86400}))
    assert bk.summary(now)["drill"]["overdue"] is True
    import sfctl

    assert "restore-drill.json" in sfctl.HOST_WRITTEN


# ---------------------------------------------------------------- #25 housekeeping + container log

def test_housekeeping_keeps_3_source_trees_and_30_days_of_our_logs(host):
    app, ops = host.app, host.app / "operations"
    now = time.time()
    for i in range(5):
        d = app / f"source.prev-2026110{i}T000000Z"
        d.mkdir()
        os.utime(d, (now - (10 - i) * 86400, now - (10 - i) * 86400))
    (app / "source.bak").mkdir()
    os.utime(app / "source.bak", (now - 30 * 86400, now - 30 * 86400))
    (app / "source").mkdir(exist_ok=True)
    (app / "state" / "keep.db").write_text("x")
    for name, age in (("aio-update-old.log", 40), ("aio-update-new.log", 2), ("update-runner-old.log", 31),
                      ("failed-spamfilter-old.log", 45), ("dashboard.initial-password", 60), ("other.log", 60)):
        f = ops / name
        f.write_text("x")
        os.utime(f, (now - age * 86400, now - age * 86400))
    lib_bash(host, "sf_housekeeping")
    left = sorted(p.name for p in app.iterdir() if p.name.startswith("source"))
    assert left == ["source", "source.prev-20261102T000000Z", "source.prev-20261103T000000Z",
                    "source.prev-20261104T000000Z"]
    assert sorted(p.name for p in ops.iterdir()) == ["aio-update-new.log", "dashboard.initial-password", "other.log"]
    assert (app / "state" / "keep.db").exists()


def test_previous_container_log_is_kept_before_it_is_removed(host):
    write_state(host.state_file, {"spamfilter-rollback": _container("imap-spamfilter-unraid:2.11.2", running=False)})
    lib_bash(host, "SF_STAMP=20261121T000000Z; sf_drop_rollback spamfilter",
             FAKE_DOCKER_LOGS=json.dumps({"spamfilter-rollback": "[filter] 12:00 scanned 3"}))
    logf = host.app / "operations" / "container-log-spamfilter-20261121T000000Z.log"
    assert "scanned 3" in logf.read_text() and oct(logf.stat().st_mode & 0o777) == "0o600"
    calls = Path(host.env["FAKE_DOCKER_CALLS"]).read_text()
    assert "logs --since 72h spamfilter-rollback" in calls and "rm spamfilter-rollback" in calls
    assert "sf_housekeeping" in (DEPLOY / "aio" / "update.sh").read_text()


# ---------------------------------------------------------------- #16 signed releases

from test_update_runner import Host as URHost  # noqa: E402
import updates  # noqa: E402

needs_ssh = pytest.mark.skipif(not shutil.which("ssh-keygen") or not shutil.which("jq"), reason="ssh-keygen/jq")


def _keypair(tmp: Path, name: str) -> Path:
    key = tmp / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(key)], check=True)
    return key


def _sign(key: Path, path: Path) -> Path:
    subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-f", str(key), "-n", "spamfilter-release", str(path)], check=True)
    return Path(str(path) + ".sig")


@pytest.fixture
def sh(tmp_path):
    h = URHost(tmp_path)
    h.key = _keypair(tmp_path, "release")
    pub = (tmp_path / "release.pub").read_text().split()
    (h.app / "source" / "deploy" / "release-signers").write_text(
        f'# test\nspamfilter-release namespaces="spamfilter-release" {pub[0]} {pub[1]}\n')
    (h.app / "source" / "deploy" / "release-signing.env").write_text(
        "RELEASE_SIGN_ID=spamfilter-release\nRELEASE_SIGN_NAMESPACE=spamfilter-release\nRELEASE_SIGNED_SINCE=2.11.0\n")
    return h


def _with_sig(h, version, key):
    rel = h.tmp / f"release-{version}.json"
    data = json.loads(rel.read_text())
    sha = h.tmp / f"pkg-{version}.sha256"
    sig = _sign(key, sha)
    data["assets"].append({"id": 13, "name": updates.source_asset(version) + ".sha256.sig"})
    rel.write_text(json.dumps(data))
    h.routes[f"https://api.test/repos/ejer/spamfilter/releases/assets/13"] = str(sig)


@needs_ssh
def test_signed_release_installs(sh):
    sh.release("2.12.0")
    _with_sig(sh, "2.12.0", sh.key)
    sh.request("v2.12.0")
    r = sh.run()
    assert r.returncode == 0, r.stdout + r.stderr
    assert sh.installed() == "VERSION=2.12.0" and "signature ok" in r.stdout + r.stderr


@needs_ssh
def test_wrong_signature_is_refused(sh):
    sh.release("2.12.0")
    _with_sig(sh, "2.12.0", _keypair(sh.tmp, "attacker"))
    sh.request("v2.12.0")
    r = sh.run()
    assert r.returncode != 0 and sh.installed() == "VERSION=2.10.1"
    assert "signaturen passer ikke" in sh.status()["message"]


@needs_ssh
def test_missing_signature_refused_from_signed_since_but_not_before(sh):
    sh.release("2.12.0")
    sh.request("v2.12.0")
    r = sh.run()
    assert r.returncode != 0 and "ikke signeret" in sh.status()["message"]
    assert sh.installed() == "VERSION=2.10.1"
    # An older release (below RELEASE_SIGNED_SINCE) stays installable unsigned.
    sh.release("2.10.9")
    sh.request("v2.10.9")
    r = sh.run()
    assert r.returncode == 0, r.stdout + r.stderr
    assert sh.installed() == "VERSION=2.10.9" and "has no signature - accepted" in r.stdout + r.stderr


@needs_ssh
def test_no_signing_key_installed_means_no_check(tmp_path):
    h = URHost(tmp_path)
    h.release("2.12.0")
    h.request("v2.12.0")
    r = h.run()
    assert r.returncode == 0 and "signature not checked" in r.stdout + r.stderr


def test_repo_ships_the_public_key_and_release_signs():
    signers = (DEPLOY / "release-signers").read_text()
    assert re.search(r'^spamfilter-release namespaces="spamfilter-release" ssh-ed25519 \S+$', signers, re.M)
    assert "PRIVATE KEY" not in signers
    rel = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    assert "secrets.SF_RELEASE_SIGNING_KEY" in rel and "ssh-keygen -Y sign" in rel
    assert "ssh-keygen -Y verify -f deploy/release-signers" in rel and "${{ env.pkg }}.sha256.sig" in rel
    env = (DEPLOY / "release-signing.env").read_text()
    assert "RELEASE_SIGNED_SINCE=2.12.1" in env
    assert os.access(DEPLOY / "sign-release.sh", os.X_OK)


# ---------------------------------------------------------------- #13 Tjek disse in the UI

import test_ui_rules_dialog as _rd  # noqa: E402


@pytest.fixture
def rd_env(tmp_path, monkeypatch):
    return _rd.env.__wrapped__(tmp_path, monkeypatch)


@pytest.fixture
def rd_admin(rd_env):
    return _rd.admin.__wrapped__(rd_env)


def test_low_scored_provider_junk_from_a_known_sender_is_under_tjek_disse(rd_env, rd_admin):
    from fakes_ui import insert_message

    c = rd_env.conn
    insert_message(c, "bynet", "<old-ham@x>", sender="Lars <lars@nielsen-vvs.example>", subject="Tak for sidst")
    insert_message(c, "bynet", "<pj-known@x>", our_action="provider_junk", our_score=2.0, current_folder="Junk",
                   sender="Lars <lars@nielsen-vvs.example>", subject="Faktura fra Lars")
    insert_message(c, "bynet", "<pj-unknown@x>", our_action="provider_junk", our_score=2.0, current_folder="Junk",
                   sender="X <x@ukendt.example>", subject="Ukendt")
    insert_message(c, "bynet", "<pj-high@x>", our_action="provider_junk", our_score=14.0, current_folder="Junk",
                   sender="Lars <lars@nielsen-vvs.example>", subject="Høj score")
    c.commit()
    html = rd_admin.get("/spam").get_data(as_text=True)
    assert 'id="tjek"' in html
    section = html[html.index('id="tjek"'):]
    section = section[:section.index("</section>")]
    assert "Faktura fra Lars" in section and "Udbyderen lagde den i sin spam-mappe" in section
    assert "Ukendt" not in section and "Høj score" not in section
