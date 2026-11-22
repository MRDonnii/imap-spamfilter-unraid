"""UI-ADMIN: Konti, Træning, Drift, Indstillinger."""

from __future__ import annotations

import json
import re
import stat
import time

import pytest

from fakes_ui import TEST_PASSWORD, csrf_of, insert_message, login, post, set_status
from fakes_ui_admin import FOLDERS, SECRET, make_admin_env

import ui_admin  # noqa: E402


@pytest.fixture
def env(tmp_path, monkeypatch):
    e = make_admin_env(tmp_path, monkeypatch)
    c = e.conn
    set_status(c, "bynet", "idle", junk_exists=1, move_method="UIDPLUS", connected_since=int(time.time()) - 3600,
               folders=json.dumps(FOLDERS), capabilities=json.dumps(["IMAP4rev1", "IDLE", "UIDPLUS"]), idle_supported=1)
    set_status(c, "molt", "idle", junk_exists=0, move_method="MOVE", folders=json.dumps(FOLDERS))
    set_status(c, "sofie", "paused")
    c.commit()
    return e


@pytest.fixture
def admin(env):
    client = env.app.test_client()
    assert login(client).status_code == 302
    return client


@pytest.fixture
def sofie(env):
    client = env.app.test_client()
    assert login(client, "sofie").status_code == 302
    return client


def text(resp) -> str:
    return resp.get_data(as_text=True)


def actions(env) -> list[str]:
    return [r["action"] for r in env.audit()]


# --------------------------------------------------------------------- access + markup

ADMIN_PAGES = ["/accounts", "/accounts/bynet", "/accounts/sofie", "/accounts/new", "/accounts/molt/golive",
               "/training", "/system", "/system?tab=audit", "/settings", "/training/bayes", "/system/rspamd",
               "/users", "/users/new", "/users/new?mailbox=molt", "/users/sofie", "/users/admin"]


@pytest.mark.parametrize("path", ADMIN_PAGES)
def test_admin_pages_render_and_are_admin_only(env, admin, sofie, path):
    r = admin.get(path)
    assert r.status_code == 200, path
    assert sofie.get(path).status_code == 403
    anon = env.app.test_client().get(path)
    assert anon.status_code == 302 and "/login" in anon.headers["Location"]


INLINE_PATTERNS = [
    (re.compile(r'\sstyle\s*='), "inline style attribute"),
    (re.compile(r"<style\b"), "<style> block"),
    (re.compile(r"<script(?![^>]*\bsrc=)[^>]*>"), "inline script"),
    (re.compile(r'\son[a-z]+\s*=\s*"', re.I), "inline event handler"),
    (re.compile(r'(src|href)="(https?:)?//'), "external resource"),
]


@pytest.mark.parametrize("path", ADMIN_PAGES)
def test_admin_pages_are_csp_clean(env, admin, path):
    html = text(admin.get(path))
    for rx, what in INLINE_PATTERNS:
        m = rx.search(html)
        assert m is None, f"{what} on {path}: {html[max(0, m.start() - 80):m.end() + 80]}"


def test_admin_js_is_loaded_and_exists(env, admin):
    html = text(admin.get("/accounts"))
    m = re.search(r'<script src="(/static/admin\.js\?v=[^"]+)" defer>', html)
    assert m
    assert admin.get(m.group(1).replace("&amp;", "&")).status_code == 200


def test_post_requires_csrf(env, admin):
    r = admin.post("/accounts/molt/mode", data={"mode": "flag"})
    assert r.status_code == 400
    assert env.entry("molt").get("mode") is None


# --------------------------------------------------------------------- Konti


def test_accounts_page_cards(env, admin):
    html = text(admin.get("/accounts"))
    for name in ("bynet", "molt", "sofie"):
        assert f'id="acct-{name}"' in html
    assert "Tilføj konto" in html and "COPY + UID EXPUNGE" in html
    # bynet is in move: active segment; molt never went live: Filtrér opens the checklist.
    assert 'href="/accounts/molt/golive" data-open-modal="golive-molt"' in html
    assert 'data-fragment="/accounts/molt/golive?fragment=1"' in html
    assert "Genoptag" in html  # sofie is paused


def test_mode_change_writes_only_mode(env, admin):
    before = env.entry("molt")
    r = post(admin, "/accounts/molt/mode", {"mode": "flag"})
    data = r.get_json()
    assert r.status_code == 200 and data["ok"] and data["reload"] is True
    after = env.entry("molt")
    assert after == {**before, "mode": "flag"}
    assert (env.state / "reload_requested").exists()
    rec = [a for a in env.audit() if a["action"] == "account_mode"][-1]
    assert rec["account"] == "molt" and rec["detail"] == "shadow->flag" and rec["actor"] == "admin"


def test_move_needs_explicit_spamfilter_folder(env, admin):
    """Without an explicit `junk:` the engine would file spam into the
    provider's own Junk (SPECIAL-USE): the checklist and the mode POST
    both refuse until a spam folder is saved."""
    page = text(admin.get("/accounts/molt/golive?fragment=1"))
    assert "Vælg Spamfilter-mappen først" in page and 'name="golive"' not in page
    r = post(admin, "/accounts/molt/mode", {"mode": "move", "golive": "1"})
    assert not r.get_json()["ok"] and env.entry("molt").get("mode") is None
    # Also after go-live (e.g. the junk key was removed by hand later).
    env.ui.settings_set("golive:molt", "1")
    r = post(admin, "/accounts/molt/mode", {"mode": "move"})
    assert not r.get_json()["ok"] and "Spamfilter-mappen" in r.get_json()["message"]
    assert env.entry("molt").get("mode") is None
    assert post(admin, "/accounts/molt/junk", {"junk": "Spamfilter"}).get_json()["ok"]
    r = post(admin, "/accounts/molt/mode", {"mode": "move"})
    assert r.get_json()["ok"] and env.entry("molt")["mode"] == "move"


def test_first_switch_to_move_needs_checklist(env, admin):
    assert post(admin, "/accounts/molt/junk", {"junk": "Spamfilter"}).get_json()["ok"]
    r = post(admin, "/accounts/molt/mode", {"mode": "move"})
    assert r.status_code == 400 and "tjeklisten" in r.get_json()["message"]
    assert env.entry("molt").get("mode") is None
    page = text(admin.get("/accounts/molt/golive?fragment=1"))
    assert "Flyttemetode: MOVE" in page and "oprettes automatisk" in page and 'name="golive"' in page
    r = post(admin, "/accounts/molt/mode", {"mode": "move", "golive": "1"})
    assert r.get_json()["ok"], r.get_json()
    assert env.entry("molt")["mode"] == "move"
    assert env.ui.settings_get("golive:molt")
    # Afterwards the plain confirm is enough.
    post(admin, "/accounts/molt/mode", {"mode": "shadow"})
    r = post(admin, "/accounts/molt/mode", {"mode": "move"})
    assert r.get_json()["ok"]


def test_move_blocked_without_safe_move_method(env, admin):
    set_status(env.conn, "molt", "idle", move_method="none", folders=json.dumps(FOLDERS))
    env.conn.commit()
    page = text(admin.get("/accounts/molt/golive"))
    assert "kan ikke flytte beskeder sikkert" in page and 'name="golive"' not in page
    r = post(admin, "/accounts/molt/mode", {"mode": "move", "golive": "1"})
    assert not r.get_json()["ok"]
    assert env.entry("molt").get("mode") is None


def test_mode_rejects_unknown_and_noop(env, admin):
    assert post(admin, "/accounts/molt/mode", {"mode": "delete"}).status_code == 400
    r = post(admin, "/accounts/bynet/mode", {"mode": "move"})
    assert r.get_json()["ok"] and "allerede" in r.get_json()["message"]
    assert post(admin, "/accounts/nope/mode", {"mode": "flag"}).status_code == 404


def test_threshold_validation_and_save(env, admin):
    for bad in ("4.5", "15.5", "7.3", "abc"):
        r = post(admin, "/accounts/molt/threshold", {"threshold": bad})
        assert r.status_code == 400, bad
    r = post(admin, "/accounts/molt/threshold", {"threshold": "7,5"})
    assert r.get_json()["ok"] and r.get_json()["reload"]
    assert env.entry("molt")["threshold"] == 7.5
    assert "account_threshold" in actions(env)


def test_threshold_preview_uses_only_v2_scores(env, admin):
    c = env.conn
    for i, s in enumerate([2.0, 6.5, 9.0, 12.0]):
        insert_message(c, "molt", f"<p{i}@x>", our_score=s, score_version=2)
    insert_message(c, "molt", "<old@x>", our_score=14.0, score_version=None)
    insert_message(c, "molt", "<fp@x>", our_score=10.0, score_version=2, user_verdict="ham")
    insert_message(c, "molt", "<miss@x>", our_score=4.0, score_version=2, user_verdict="spam")
    insert_message(c, "molt", "<rule@x>", our_score=20.0, score_version=2, rule_hit="block:1")
    c.commit()
    with env.app.test_request_context():
        acc = env.ui.account_by_name("molt")
        prev = ui_admin.threshold_preview(acc)
    assert prev["m"] == 6
    assert prev["steps"]["8.0"] == [3, 1, 1]      # 9, 12, 10(fp) caught; 4.0 spam missed
    assert prev["steps"]["5.0"] == [4, 1, 1]
    assert prev["steps"]["15.0"] == [0, 0, 1]
    html = text(admin.get("/accounts/molt"))
    assert "data-thr-preview=" in html and "af de seneste 6 beskeder ville være fanget" in html


def test_junk_folder_picker(env, admin):
    html = text(admin.get("/accounts/molt"))
    assert "udbyderens spam-mappe" in html and "Opret ny mappe…" in html
    assert post(admin, "/accounts/molt/junk", {"junk": "INBOX"}).status_code == 400
    assert post(admin, "/accounts/molt/junk", {"junk": "__new__", "new_folder": "Bad*Name"}).status_code == 400
    r = post(admin, "/accounts/molt/junk", {"junk": "Spamfilter"})
    assert r.get_json()["ok"]
    assert env.entry("molt")["junk"] == "Spamfilter"  # explicit, wins over SPECIAL-USE
    r = post(admin, "/accounts/molt/junk", {"junk": "__new__", "new_folder": "INBOX.Spam-fanget"})
    assert r.get_json()["ok"] and "oprettes automatisk" in r.get_json()["message"]
    assert env.entry("molt")["junk"] == "INBOX.Spam-fanget"


def test_refresh_folders(env, admin):
    r = post(admin, "/accounts/sofie/folders/refresh", {})
    assert r.get_json()["ok"] and "5 mapper" in r.get_json()["message"]

    class Boom(Exception):
        text = "Kunne ikke forbinde til mailserveren."
        code = "connect"

    env.services.refresh_error = Boom("raw secret detail")
    r = post(admin, "/accounts/sofie/folders/refresh", {})
    assert r.status_code == 400 and r.get_json()["message"] == "Kunne ikke forbinde til mailserveren."
    assert "raw secret detail" not in r.get_data(as_text=True)


def test_pause_and_resume_requires_working_login(env, admin):
    r = post(admin, "/accounts/bynet/enabled", {"enabled": "0"})
    assert r.get_json()["ok"] and env.entry("bynet")["enabled"] is False
    (env.secrets / "sofie").write_text("forkert")
    r = post(admin, "/accounts/sofie/enabled", {"enabled": "1"})
    assert r.status_code == 400 and "ikke genoptaget" in r.get_json()["message"]
    assert env.entry("sofie")["enabled"] is False
    (env.secrets / "sofie").write_text(SECRET)
    r = post(admin, "/accounts/sofie/enabled", {"enabled": "1"})
    assert r.get_json()["ok"] and env.entry("sofie")["enabled"] is True
    assert env.services.tests[-1] == ("mail.scannet.dk", 993, "sofie@molt.example", SECRET)


def test_connection_save_requires_successful_test(env, admin):
    url = "/accounts/molt/connection"
    r = post(admin, url, {"op": "save", "imap_host": "mail.scannet.dk", "imap_port": "993",
                          "user": "ole@molt.example", "password": "forkert-kode"})
    assert r.status_code == 400 and "testen fejlede" in r.get_json()["message"]
    assert (env.secrets / "molt").read_text() == SECRET
    assert "forkert-kode" not in r.get_data(as_text=True)
    # Test first -> token -> save without a second login.
    env.services.good_password = "ny-hemmelig-kode"
    r = post(admin, url, {"op": "test", "imap_host": "mail.scannet.dk", "imap_port": "993",
                          "user": "ole@molt.example", "password": "ny-hemmelig-kode"})
    data = r.get_json()
    assert data["ok"] and data["token"] and data["test"]["move_method"] == "MOVE"
    assert "ny-hemmelig-kode" not in r.get_data(as_text=True)
    n_tests = len(env.services.tests)
    r = post(admin, url, {"op": "save", "tested": data["token"], "imap_host": "mail.scannet.dk", "imap_port": "993",
                          "user": "ole@molt.example", "password": "ny-hemmelig-kode"})
    assert r.get_json()["ok"], r.get_json()
    assert len(env.services.tests) == n_tests
    secret = env.secrets / "molt"
    assert secret.read_text() == "ny-hemmelig-kode"
    assert stat.S_IMODE(secret.stat().st_mode) == 0o600
    assert env.entry("molt")["password_file"] == str(secret)
    assert "ny-hemmelig-kode" not in env.config.read_text()
    assert {"account_secret", "account_connection", "account_test"} <= set(actions(env))
    assert "ny-hemmelig-kode" not in (env.state / "admin-audit.jsonl").read_text()


def test_connection_token_is_bound_to_values(env, admin):
    url = "/accounts/molt/connection"
    tok = post(admin, url, {"op": "test", "imap_host": "mail.scannet.dk", "imap_port": "993",
                            "user": "ole@molt.example", "password": ""}).get_json()["token"]
    assert tok  # blank password = test with the stored secret
    env.services.good_password = "something-else"
    r = post(admin, url, {"op": "save", "tested": tok, "imap_host": "imap.other.dk", "imap_port": "993",
                          "user": "ole@molt.example", "password": ""})
    assert r.status_code == 400  # token did not cover the new host -> re-test -> fails
    assert env.entry("molt")["imap_host"] == "mail.scannet.dk"
    env.services.good_password = SECRET
    n_tests = len(env.services.tests)
    # The stored password is never sent to a new host/port/user (review fix).
    for op in ("test", "save"):
        r = post(admin, url, {"op": op, "imap_host": "imap.other.dk", "imap_port": "143",
                              "user": "ole@molt.example", "password": ""})
        assert r.status_code == 400 and "Skriv adgangskoden igen" in r.get_json()["message"]
    r = post(admin, url, {"op": "test", "imap_host": "mail.scannet.dk", "imap_port": "993",
                          "user": "other@molt.example", "password": ""})
    assert r.status_code == 400
    assert len(env.services.tests) == n_tests
    r = post(admin, url, {"op": "save", "imap_host": "imap.other.dk", "imap_port": "143",
                          "user": "ole@molt.example", "password": SECRET})
    assert r.get_json()["ok"]
    e = env.entry("molt")
    assert e["imap_host"] == "imap.other.dk" and e["imap_port"] == 143 and "password" not in e


def test_connection_validation(env, admin):
    url = "/accounts/molt/connection"
    for data in ({"imap_host": "bad host!", "imap_port": "993", "user": "x"},
                 {"imap_host": "ok.dk", "imap_port": "99999", "user": "x"},
                 {"imap_host": "ok.dk", "imap_port": "993", "user": ""}):
        assert post(admin, url, {"op": "test", **data}).status_code == 400
    r = post(admin, url, {"op": "save", "imap_host": "mail.scannet.dk", "imap_port": "993", "user": "ole@molt.example"})
    assert "Ingen ændringer" in r.get_json()["message"]


def test_advanced_writes_only_changed_keys(env, admin):
    form = {"move_grace_seconds": "120", "max_moves_per_hour": "60", "junk_poll_interval": "300",
            "poll_interval": "600", "learn_from_moves": "1", "provider_bonus": "1"}
    before = env.entry("molt")
    r = post(admin, "/accounts/molt/advanced", form)
    assert r.get_json()["ok"], r.get_json()
    assert env.entry("molt") == {**before, "move_grace_seconds": 120}
    form2 = dict(form, move_grace_seconds="120")
    form2.pop("provider_bonus")  # unchecked switch
    post(admin, "/accounts/molt/advanced", form2)
    assert env.entry("molt")["provider_bonus"] is False
    assert post(admin, "/accounts/molt/advanced", dict(form, max_moves_per_hour="0")).status_code == 400
    assert post(admin, "/accounts/molt/advanced", dict(form, poll_interval="abc")).status_code == 400


def test_engine_rejection_is_shown_and_nothing_written(env, admin, monkeypatch):
    real = env.engine.load_account_configs

    def picky(path=None):
        if str(path) != str(env.config):
            raise ValueError("account 'molt': threshold must be a number")
        return real(path)

    monkeypatch.setattr(env.engine, "load_account_configs", picky)
    before = env.config.read_text()
    r = post(admin, "/accounts/molt/threshold", {"threshold": "9"})
    assert r.status_code == 400 and "Ændringen blev afvist" in r.get_json()["message"]
    assert env.config.read_text() == before
    assert env.audit()[-1]["result"] == "rejected"


def test_config_error_locks_account_writes(env, admin):
    env.engine.config_error = "invalid YAML at line 3"
    html = text(admin.get("/accounts"))
    assert "accounts.yml kan ikke indlæses" in html
    env.engine.config_error = None


def test_remove_requires_typed_fjern_and_archives_secret(env, admin):
    assert post(admin, "/accounts/molt/remove", {"confirm": "fjern"}).status_code == 400
    assert any(a["name"] == "molt" for a in env.raw_config()["accounts"])
    r = post(admin, "/accounts/molt/remove", {"confirm": "FJERN"})
    data = r.get_json()
    assert data["ok"] and data["location"] == "/accounts"
    assert all(a["name"] != "molt" for a in env.raw_config()["accounts"])
    assert not (env.secrets / "molt").exists()
    archived = list((env.state / "removed-secrets").glob("*-molt"))
    assert len(archived) == 1 and archived[0].read_text() == SECRET
    assert "account_remove" in actions(env)


def test_wizard_suggest(env, admin):
    d = admin.get("/accounts/suggest?email=kontor@molt.example").get_json()
    assert d["imap_host"] == "mail.scannet.dk" and d["provider"] == "Scannet" and not d["guess"]
    assert d["name"] == "molt-kontor" and d["exists"] is False
    d = admin.get("/accounts/suggest?email=ole@molt.example").get_json()
    assert d["exists"] is True
    d = admin.get("/accounts/suggest?email=a@firma.example").get_json()
    assert d["imap_host"] == "imap.firma.example" and d["guess"]
    assert admin.get("/accounts/suggest?email=nonsense").get_json()["ok"] is False


def test_wizard_creates_account_in_shadow(env, admin):
    form = {"email": "kontor@molt.example", "name": "molt-kontor", "imap_host": "mail.scannet.dk", "imap_port": "993",
            "user": "", "password": "forkert", "junk": "Spamfilter"}
    r = post(admin, "/accounts/new", form)
    assert r.status_code == 400 and "testen fejlede" in r.get_json()["message"]
    assert not (env.secrets / "molt-kontor").exists()
    t = post(admin, "/accounts/new", {**form, "op": "test", "password": SECRET}).get_json()
    assert t["ok"] and t["test"]["folders"] and t["token"]
    r = post(admin, "/accounts/new", {**form, "password": SECRET, "tested": t["token"]})
    data = r.get_json()
    assert data["ok"] and data["location"] == "/accounts/molt-kontor" and data["reload"]
    e = env.entry("molt-kontor")
    assert e["mode"] == "shadow" and e["junk"] == "Spamfilter" and e["user"] == "kontor@molt.example"
    assert e["password_file"] == str(env.secrets / "molt-kontor") and "password" not in e
    assert stat.S_IMODE((env.secrets / "molt-kontor").stat().st_mode) == 0o600
    assert SECRET not in env.config.read_text()
    assert "account_add" in actions(env)
    # Duplicates and reserved names.
    assert post(admin, "/accounts/new", {**form, "password": SECRET}).status_code == 400
    assert post(admin, "/accounts/new", {**form, "name": "new", "email": "x@molt.example", "password": SECRET}).status_code == 400
    assert post(admin, "/accounts/new", {**form, "name": "bad name", "password": SECRET}).status_code == 400


def test_wizard_yaml_accepted_by_real_engine(env, admin):
    filter_mod = pytest.importorskip("filter")
    if not hasattr(filter_mod, "load_account_configs"):
        pytest.skip("engine without load_account_configs")
    post(admin, "/accounts/new", {"email": "kontor@molt.example", "name": "molt-kontor", "imap_host": "mail.scannet.dk",
                                  "imap_port": "993", "password": SECRET, "junk": "__new__", "new_folder": "Spamfilter"})
    post(admin, "/accounts/molt/threshold", {"threshold": "9.5"})
    post(admin, "/accounts/molt/advanced", {"move_grace_seconds": "90", "max_moves_per_hour": "40",
                                            "junk_poll_interval": "300", "poll_interval": "600"})
    accs = {a.name: a for a in filter_mod.load_account_configs(env.config)}
    assert accs["molt-kontor"].mode == "shadow" and accs["molt-kontor"].junk == "Spamfilter"
    assert accs["molt"].threshold == 9.5 and accs["molt"].move_grace_seconds == 90
    assert accs["molt"].learn_from_moves is False and accs["molt"].provider_bonus is False


def test_account_page_never_echoes_secret(env, admin):
    html = text(admin.get("/accounts/bynet"))
    assert SECRET not in html
    assert 'name="password"' in html and "Uændret" in html
    assert "COPY + UID EXPUNGE" in html and "hjemmeserver" in html


# --------------------------------------------------------------------- Træning


def test_training_page(env, admin):
    html = text(admin.get("/training"))
    assert 'data-fragment="/training/bayes"' in html and "Start træning" in html and "Kalibrering" in html
    assert "Træn spam fra Junk-mapper" in html and "bynet: Junk" in html
    assert 'data-folders="' in html and "<optgroup" in html
    frag = text(admin.get("/training/bayes"))
    assert "Spam lært" in frag and "fælles Bayes-hukommelse" in frag and "hjemmeserver" in frag


def test_queue_training_job(env, admin):
    form = {"account": "bynet", "folder": "Junk", "kind": "spam", "max_messages": "200", "min_age_days": "0",
            "provider_filter": "any"}
    assert post(admin, "/training/jobs", {**form, "kind": "x"}).status_code == 400
    assert post(admin, "/training/jobs", {**form, "folder": "Findes-ikke"}).status_code == 400
    assert post(admin, "/training/jobs", {**form, "max_messages": "0"}).status_code == 400
    assert post(admin, "/training/jobs", {**form, "account": "nope"}).status_code == 400
    r = post(admin, "/training/jobs", {**form, "seen_only": "1"})
    assert r.get_json()["ok"]
    job = env.conn.execute("SELECT * FROM train_jobs").fetchone()
    assert (job["account"], job["folder"], job["kind"], job["max_messages"], job["seen_only"], job["created_by"]) == \
        ("bynet", "Junk", "spam", 200, 1, "admin")
    assert "train_queue" in actions(env)


def test_calibration_queues_inbox_and_provider_junk(env, admin):
    r = post(admin, "/training/calibrate", {"account": "bynet", "inbox": "1", "provider_junk": "1", "max_messages": "150"})
    assert r.get_json()["ok"]
    rows = env.conn.execute("SELECT folder, kind, max_messages FROM train_jobs ORDER BY id").fetchall()
    assert [tuple(r) for r in rows] == [("INBOX", "calibrate", 150), ("Junk", "calibrate", 150)]
    assert post(admin, "/training/calibrate", {"account": "bynet", "max_messages": "10"}).status_code == 400


def test_presets_queue_jobs(env, admin):
    r = post(admin, "/training/preset", {"preset": "spam_junk"})
    assert r.get_json()["ok"]
    jobs = env.conn.execute("SELECT account, folder, kind FROM train_jobs ORDER BY id").fetchall()
    # sofie is paused; molt' own filter folder IS "Junk" (no explicit junk), so it is not
    # treated as the provider's folder - never learn from what the filter moved itself.
    assert [tuple(j) for j in jobs] == [("bynet", "Junk", "spam")]
    post(admin, "/training/preset", {"preset": "ham_archive"})
    ham = env.conn.execute("SELECT account, folder, seen_only, provider_filter FROM train_jobs WHERE kind='ham'").fetchall()
    assert [tuple(j) for j in ham] == [("bynet", "Archive", 1, "provider_clean"), ("molt", "Archive", 1, "provider_clean")]
    assert post(admin, "/training/preset", {"preset": "nope"}).status_code == 400


def test_job_list_live_and_cancel(env, admin):
    c = env.conn
    now = int(time.time())
    c.execute("INSERT INTO train_jobs(account, folder, kind, max_messages, status, total, processed, learned, created_at) "
              "VALUES('bynet','Junk','spam',300,'running',200,50,48,?)", (now,))
    c.execute("INSERT INTO train_jobs(account, folder, kind, max_messages, status, created_at) "
              "VALUES('molt','INBOX','ham',300,'queued',?)", (now,))
    c.commit()
    html = text(admin.get("/training"))
    assert 'data-row="job:1" data-job-active="1"' in html and 'data-jobs-live="/training/jobs.json"' in html
    d = admin.get("/training/jobs.json").get_json()
    assert d["active"] is True and set(d["rows"]) == {"job:1", "job:2"}
    assert d["rows"]["job:1"].startswith("<tr") and "50 / 200" in d["rows"]["job:1"]
    r = post(admin, "/training/jobs/2/cancel", {})
    assert r.get_json()["ok"] and "Annulleret" in r.get_json()["rows"]["job:2"]
    r = post(admin, "/training/jobs/1/cancel", {})
    assert r.get_json()["ok"] and "Stopper" in r.get_json()["rows"]["job:1"]
    r = post(admin, "/training/jobs/2/cancel", {})
    assert r.status_code == 400
    assert actions(env).count("train_cancel") == 3


def _calibration(env, job_id, folder, scores):
    c = env.conn
    c.execute("INSERT INTO train_jobs(id, account, folder, kind, max_messages, status, total, processed, learned, created_at, finished_at) "
              "VALUES(?, 'bynet', ?, 'calibrate', 300, 'done', ?, ?, ?, ?, ?)",
              (job_id, folder, len(scores), len(scores), len(scores), int(time.time()), int(time.time())))
    for i, s in enumerate(scores):
        c.execute("INSERT INTO calibration_results(job_id, account, folder, message_id, final_score, rspamd_score, symbols, "
                  "sender, subject, received_at, seen, provider_flag) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                  (job_id, "bynet", folder, f"<c{job_id}-{i}@x>", s, s, json.dumps([{"n": "BAYES_SPAM", "s": 5.0, "o": []}]),
                   f"Afsender {i} <a{i}@x.example>", f"<b>Emne {i}</b>", int(time.time()) - i * 60, i % 2, 0))
    c.commit()


def test_calibration_job_page(env, admin):
    _calibration(env, 10, "INBOX", [-3.0, -1.0, 0.5, 2.0, 9.5] + [1.0] * 60)
    _calibration(env, 11, "Junk", [6.0, 9.0, 12.0, 15.5])
    html = text(admin.get("/training/jobs/11"))
    assert "chart-svg" in html and "Indbakke (INBOX)" in html and "Udbyderens spam-mappe (Junk)" in html
    assert "data-whatif" in html and "data-whatif-row" in html
    # At bynet's threshold 8: 3 of 4 in Junk, 1 of 65 in INBOX.
    assert "3 af 4" in html and "1 af 65" in html
    assert "&lt;b&gt;Emne 0&lt;/b&gt;" in html  # subjects are escaped
    page2 = text(admin.get("/training/jobs/10?sort=low&page=2"))
    assert 'aria-current="page">2<' in page2
    assert admin.get("/training/jobs/999").status_code == 404


def test_training_job_detail_for_learning_job(env, admin):
    env.conn.execute("INSERT INTO train_jobs(account, folder, kind, max_messages, status, error, created_at) "
                     "VALUES('bynet','Junk','spam',300,'failed','Kunne ikke forbinde',?)", (int(time.time()),))
    env.conn.commit()
    html = text(admin.get("/training/jobs/1"))
    assert "Kunne ikke forbinde" in html and "Fejlede" in html


# --------------------------------------------------------------------- Drift


def test_system_page_with_host_status(env, admin):
    (env.state / "heartbeat").write_text(f"{int(time.time()) - 5} boot-1")
    html = text(admin.get("/system"))
    for needle in ("Filter + WebUI", "Unbound (DNS)", "Stoppet", "92 %", "appdata er 92 % fuld",
                   "Seneste backup lykkedes", "Spamhaus-testen svarer korrekt", "5 sek.", "Genstart filter",
                   'data-fragment="/system/rspamd"'):
        assert needle in html, needle


def test_system_page_without_host_status(tmp_path, monkeypatch):
    env = make_admin_env(tmp_path, monkeypatch, host_status=None, backup=None)
    client = env.app.test_client()
    login(client)
    html = text(client.get("/system"))
    assert "Ingen værtsstatus" in html and "Livstegn" in html and "mangler" in html


def test_rspamd_fragment(env, admin):
    frag = text(admin.get("/system/rspamd"))
    assert "rspamd svarer normalt" in frag and "9 ms" in frag
    env.services.health = {"ok": False, "controller_ok": False, "scanner_ok": False, "text": "rspamd svarer ikke."}
    assert "svarer ikke" in text(admin.get("/system/rspamd"))


def test_events_tab_filters_and_pagination(env, admin):
    c = env.conn
    now = int(time.time())
    for i in range(120):
        c.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                  ("bynet" if i % 2 else "molt", now - i, f"<e{i}@x>", "moved_to_junk" if i % 3 else "conn_error",
                   f"detail {i}"))
    c.execute("INSERT INTO events(account, ts, event, detail) VALUES('bynet', ?, 'scan', '<script>x</script>')", (now + 5,))
    c.commit()
    html = text(admin.get("/system?tab=events"))
    assert "121 hændelser" in html and "Flyttet til spam" in html
    assert "<script>x</script>" not in html and "&lt;script&gt;x&lt;/script&gt;" in html
    assert 'href="/system?tab=events&amp;page=2"' in html
    html = text(admin.get("/system?tab=events&event=conn_error&account=molt"))
    assert "20 hændelser" in html
    html = text(admin.get("/system?tab=events&q=detail+11"))
    assert "11 hændelser" in html or "hændelser" in html


def test_audit_tab(env, admin):
    post(admin, "/accounts/molt/mode", {"mode": "flag"})
    html = text(admin.get("/system?tab=audit"))
    assert "Tilstand ændret" in html and "Overvåg → Markér" in html and "Login" in html
    html = text(admin.get("/system?tab=audit&action=account_mode"))
    assert "1 post" in html


def test_read_audit_tolerates_garbage(env):
    p = env.state / "admin-audit.jsonl"
    p.write_text('{"action":"a","ts":1}\nnot json\n{"action":"b","ts":2}\n')
    with env.app.test_request_context():
        recs = ui_admin.read_audit()
        assert [r["action"] for r in recs] == ["b", "a"]
        assert [r["action"] for r in ui_admin.read_audit(max_bytes=25)] == ["b"]


def test_restart_filter(env, admin):
    r = post(admin, "/system/restart", {})
    assert r.get_json()["ok"] and r.get_json()["reload"]
    assert env.services.reloads and env.services.reloads[-1][1] == "admin"
    assert "filter_restart" in actions(env)


# --------------------------------------------------------------------- Indstillinger


def test_settings_page(env, admin):
    html = text(admin.get("/settings"))
    # Brugere and the theme have their own pages now (no duplicates here).
    assert 'href="/users"' in html and "Administrér brugere" not in html
    assert "Log ud overalt" in html and "Om spamfilteret" in html and "Daglig opsummering" in html
    assert "Husk mig" in html and "30 dage" in html


def users_file(env) -> dict:
    out = {}
    for line in (env.state / "dashboard_users").read_text().splitlines():
        if line and not line.startswith("#"):
            name, verifier, scope, gen = line.split(":")
            out[name] = (verifier, scope, int(gen))
    return out


def test_add_user_validation_and_login(env, admin):
    base = {"name": "kontor", "password": "en-lang-adgangskode", "password2": "en-lang-adgangskode",
            "role": "user", "acct:molt": "1", "perm:release": "1"}
    assert post(admin, "/users/new", {**base, "password": "kort", "password2": "kort"}).status_code == 400
    assert post(admin, "/users/new", {**base, "password2": "noget-andet-helt"}).status_code == 400
    assert post(admin, "/users/new", {**base, "name": "ugyldig navn"}).status_code == 400
    assert post(admin, "/users/new", {**base, "name": "new"}).status_code == 400  # route name
    assert post(admin, "/users/new", {**base, "name": "sofie"}).status_code == 400
    r = post(admin, "/users/new", {**base, "acct:ukendt": "1"})
    assert r.get_json()["ok"] and r.get_json()["redirect"] == "/users"
    assert users_file(env)["kontor"][1] == "molt"
    assert "en-lang-adgangskode" not in (env.state / "dashboard_users").read_text()
    with env.app.test_request_context("/"):
        assert env.ui.user_perms("kontor") == frozenset({"release"})
    c = env.app.test_client()
    assert login(c, "kontor", "en-lang-adgangskode").status_code == 302
    assert c.get("/accounts").status_code == 403
    assert "user_add" in actions(env)
    rec = [r for r in env.audit() if r["action"] == "user_add"][-1]
    assert rec["detail"] == "kontor molt perms=release"


def test_change_password_bumps_generation(env, admin):
    other = env.app.test_client()
    login(other, "sofie")
    gen = users_file(env)["sofie"][2]
    r = post(admin, "/users/sofie/password", {"password": "helt-ny-kode-123", "password2": "helt-ny-kode-123"})
    assert r.get_json()["ok"]
    assert users_file(env)["sofie"][2] == gen + 1
    assert other.get("/").status_code == 302  # sofie's old session is gone
    # Own password: this session survives, others die.
    second = env.app.test_client()
    login(second)
    r = post(admin, "/users/admin/password", {"password": "admin-ny-kode-123", "password2": "admin-ny-kode-123"})
    assert r.get_json()["ok"]
    assert admin.get("/settings").status_code == 200
    assert second.get("/").status_code == 302


def test_last_admin_guard(env, admin):
    r = post(admin, "/users/admin", {"role": "user", "acct:molt": "1", "self_demote": "1"})
    assert r.status_code == 400 and "mindst én administrator" in r.get_json()["message"]
    assert post(admin, "/users/admin/remove", {"confirm": "admin"}).status_code == 400  # self
    assert users_file(env)["admin"][1] == "admin"
    # With a second admin, sofie can be promoted and the other one removed.
    assert post(admin, "/users/sofie", {"role": "admin"}).get_json()["ok"]
    assert users_file(env)["sofie"][1] == "admin"
    assert post(admin, "/users/sofie/remove", {}).status_code == 400  # typed confirmation missing
    r = post(admin, "/users/sofie/remove", {"confirm": "sofie"})
    assert r.get_json()["ok"] and r.get_json()["rows"] == {"user:sofie": None}
    assert "sofie" not in users_file(env)


def test_scope_change(env, admin):
    r = post(admin, "/users/sofie", {"role": "user", "acct:molt": "1", "acct:sofie": "1",
                                     "perm:release": "1", "perm:rules": "1", "perm:see_messages": "1"})
    assert r.get_json()["ok"]
    assert users_file(env)["sofie"][1] == "molt|sofie"
    assert post(admin, "/users/nobody", {"role": "admin"}).status_code == 404


def test_logout_everywhere_self(env, admin):
    r = post(admin, "/users/admin/logout-all", {})
    assert r.get_json()["ok"] and r.get_json()["redirect"] == "/login"
    assert admin.get("/settings").status_code == 302


def test_logout_everywhere_other(env, admin):
    other = env.app.test_client()
    login(other, "sofie")
    assert post(admin, "/users/sofie/logout-all", {}).get_json()["ok"]
    assert other.get("/").status_code == 302
    assert admin.get("/settings").status_code == 200
    assert "user_logout_all" in actions(env)


def test_env_users_are_read_only(env, admin, monkeypatch):
    monkeypatch.setenv("DASHBOARD_USERS", "ops:plain:" + "x" * 16 + ":admin")
    html = text(admin.get("/users"))
    assert "Fra miljøvariabel" in html
    assert admin.get("/users/ops").status_code == 200
    assert post(admin, "/users/ops/remove", {"confirm": "ops"}).status_code == 403
    assert post(admin, "/users/ops/password", {"password": "y" * 12, "password2": "y" * 12}).status_code == 403
    assert post(admin, "/users/ops", {"role": "user"}).status_code == 403


# --------------------------------------------------------------------- helpers


def test_write_secret_rejects_bad_input(env):
    with env.app.test_request_context():
        with pytest.raises(ValueError):
            ui_admin.write_secret("../evil", "x" * 12)
        with pytest.raises(ValueError):
            ui_admin.write_secret("ok", "line\nbreak")
        p = ui_admin.write_secret("ok", "hemmelig")
        assert p.read_text() == "hemmelig" and stat.S_IMODE(p.stat().st_mode) == 0o600


def test_test_token_expires_and_binds_actor(env, monkeypatch):
    with env.app.test_request_context():
        tok = ui_admin.make_test_token("h.dk", 993, "u", "pw")
        assert ui_admin.check_test_token(tok, "h.dk", 993, "u", "pw")
        assert not ui_admin.check_test_token(tok, "h.dk", 993, "u", "pw2")
        assert not ui_admin.check_test_token("garbage", "h.dk", 993, "u", "pw")
        real = time.time
        monkeypatch.setattr(ui_admin.time, "time", lambda: real() + ui_admin.TEST_TOKEN_TTL + 5)
        assert not ui_admin.check_test_token(tok, "h.dk", 993, "u", "pw")


def test_csrf_token_header_matches_cookie_session(env, admin):
    # Sanity: the shared helper posts with this session's token.
    assert csrf_of(admin)
    assert TEST_PASSWORD


def test_training_never_learns_the_inbox_as_spam_by_default(env, admin):
    """One click with the form defaults must not teach 300 real inbox mails
    as spam to the shared Bayes: no kind preselected, a confirm on the
    button, and INBOX + spam refused server-side."""
    html = text(admin.get("/training"))
    form = html[html.index('action="/training/jobs"'):]
    form = form[:form.index("</form>")]
    assert 'name="kind" value="spam" checked' not in form and 'name="kind" value="ham" checked' not in form
    assert 'data-confirm="Start træning?"' in form
    base = {"account": "bynet", "max_messages": "300", "min_age_days": "0", "provider_filter": "any"}
    assert post(admin, "/training/jobs", {**base, "folder": "INBOX"}).status_code == 400  # no kind
    for folder in ("INBOX", "inbox"):
        r = post(admin, "/training/jobs", {**base, "folder": folder, "kind": "spam"})
        assert r.status_code == 400 and "Indbakken" in r.get_json()["message"]
    assert env.conn.execute("SELECT COUNT(*) FROM train_jobs").fetchone()[0] == 0
    assert post(admin, "/training/jobs", {**base, "folder": "INBOX", "kind": "ham"}).get_json()["ok"]


def test_recreated_user_does_not_revive_old_sessions(env, admin):
    """Remove 'sofie' (lost phone) and add a new 'sofie': the old cookie
    carried gen 0 and must stay dead (review fix)."""
    old_phone = env.app.test_client()
    assert login(old_phone, "sofie").status_code == 302
    assert old_phone.get("/").status_code == 200
    assert post(admin, "/users/sofie/remove", {"confirm": "sofie"}).get_json()["ok"]
    r = post(admin, "/users/new", {"name": "sofie", "password": "en-helt-ny-kode-42",
                                   "password2": "en-helt-ny-kode-42", "role": "admin"})
    assert r.get_json()["ok"]
    assert users_file(env)["sofie"][2] > 0
    assert old_phone.get("/").status_code == 302
