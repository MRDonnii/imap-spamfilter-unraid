"""2.10 Opdateringer (updates.py + ui_updates.py): the release check against
GitHub (ETag cache, errors, channels), the encrypted optional token, the
signed request the host helper picks up (only a published, installable,
newer tag; never two at once), the status shown, release notes escaped,
and the page: admin only, CSRF, audited, CSP clean, in the new menu."""

from __future__ import annotations

import json
import re
import time

from fakes_ui import csrf_of, post
from test_ui_admin import admin, env, sofie, text  # noqa: F401 - fixtures
from test_ui_core import INLINE_PATTERNS  # noqa: E402

import updates  # noqa: E402
import pytest  # noqa: E402

# The newer release in these tests is 2.99.0, so they keep working when VERSION moves on.
NOW = 1_800_000_000
EVIL = "<script>alert(1)</script>"


def _rel(version, *, pre=False, installable=True, body="- **Ny:** noget", draft=False):
    assets = []
    if installable:
        n = updates.source_asset(version)
        assets = [{"name": n, "digest": "sha256:" + "a" * 64}, {"name": n + ".sha256"}]
    return {"tag_name": f"v{version}", "name": f"Spamfilter {version}", "prerelease": pre, "draft": draft,
            "published_at": "2026-11-20T10:00:00Z", "body": body, "html_url": "https://github.com/o/r/releases",
            "assets": assets}


class Resp:
    def __init__(self, code, data=None, headers=None):
        self.status_code, self._data, self.headers = code, data, headers or {}

    def json(self):
        if isinstance(self._data, Exception):
            raise self._data
        return self._data


class Session:
    def __init__(self, *replies):
        self.replies, self.calls = list(replies), []

    def get(self, url, **kw):
        self.calls.append((url, kw))
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


# --------------------------------------------------------------- versions + channels


def test_parse_version_and_tags():
    assert updates.parse_version("2.10.0") == (2, 10, 0) == updates.parse_version("v2.10.0")
    assert updates.parse_version("2.10.0-hjemmeserver") == (2, 10, 0)
    for bad in ("", "2.10", "v2.10.0; rm -rf /", "02.1.0", None):
        assert updates.parse_version(bad) is None
    assert updates.TAG_RE.match("v2.11.0") and not updates.TAG_RE.match("v2.11.0-rc1")
    assert not updates.TAG_RE.match("v2.11.0\n")


def test_repo_from_env_validates():
    assert updates.repo_from_env({"SF_UPDATE_REPO": "ejer/spamfilter"}) == "ejer/spamfilter"
    for bad in ("", "ejer", "ejer/../x", "https://github.com/a/b", "a/b c", "-a/b"):
        assert updates.repo_from_env({"SF_UPDATE_REPO": bad}) == ""


def test_channels_and_newer():
    rels = [t for t in (updates._trim_release(r) for r in
                        (_rel("2.9.0"), _rel("2.10.0"), _rel("2.11.0", pre=True), _rel("2.12.0", draft=True))) if t]
    assert [r["version"] for r in rels] == ["2.9.0", "2.10.0", "2.11.0"]  # drafts never shown
    assert updates.newer_releases(rels, "stable", "2.10.0") == []
    assert [r["version"] for r in updates.newer_releases(rels, "beta", "2.9.0")] == ["2.11.0", "2.10.0"]
    assert updates.latest(rels, "stable")["version"] == "2.10.0"
    assert updates.latest(rels, "beta")["version"] == "2.11.0"
    assert rels[0]["installable"] and rels[0]["digest"] == "sha256:" + "a" * 64
    assert rels[0]["published_ts"] == 1795168800
    assert not updates._trim_release(_rel("2.99.0", installable=False))["installable"]


# --------------------------------------------------------------- GitHub check


def test_check_uses_etag_cache_and_token(tmp_path):
    s = Session(Resp(200, [_rel("2.11.0")], {"ETag": 'W/"abc"'}))
    out = updates.check_releases(tmp_path, "o/r", "ghp_" + "x" * 36, session=s, now=NOW)
    assert not out["error"] and out["releases"][0]["tag"] == "v2.11.0"
    url, kw = s.calls[0]
    assert url == "https://api.github.com/repos/o/r/releases" and kw["timeout"] <= 10
    assert kw["headers"]["Authorization"].startswith("Bearer ") and not kw["allow_redirects"]
    cache = json.loads((tmp_path / updates.CACHE_FILE).read_text())
    assert "ghp_" not in json.dumps(cache) and cache["etag"] == 'W/"abc"'
    # fresh cache: no call at all
    assert updates.check_releases(tmp_path, "o/r", "ghp_" + "x" * 36, session=Session(), now=NOW + 60)["releases"]
    # stale: conditional request; 304 keeps the list
    s2 = Session(Resp(304))
    out = updates.check_releases(tmp_path, "o/r", "ghp_" + "x" * 36, session=s2, now=NOW + updates.CHECK_EVERY + 1)
    assert s2.calls[0][1]["headers"]["If-None-Match"] == 'W/"abc"' and out["releases"][0]["tag"] == "v2.11.0"
    # another token = other answer: no stale ETag sent
    s3 = Session(Resp(200, []))
    updates.check_releases(tmp_path, "o/r", None, session=s3, now=NOW, force=True)
    assert "If-None-Match" not in s3.calls[0][1]["headers"] and "Authorization" not in s3.calls[0][1]["headers"]


@pytest.mark.parametrize("reply,code", [
    (Resp(404), "not_found"), (Resp(401), "auth"), (Resp(403, headers={"x-ratelimit-remaining": "0"}), "rate_limited"),
    (Resp(500), "bad_reply"), (Resp(200, {"message": "x"}), "bad_reply"), (Resp(200, ValueError("bad json")), "bad_reply"),
    (OSError("down"), "network")])
def test_check_errors_keep_the_old_list(tmp_path, reply, code):
    updates.check_releases(tmp_path, "o/r", None, session=Session(Resp(200, [_rel("2.11.0")])), now=NOW)
    out = updates.check_releases(tmp_path, "o/r", None, session=Session(reply), now=NOW, force=True)
    assert out["error"] == code and out["releases"][0]["tag"] == "v2.11.0"


def test_check_not_configured(tmp_path):
    assert updates.check_releases(tmp_path, "", None, session=Session(), now=NOW)["error"] == "not_configured"


# --------------------------------------------------------------- token


def test_token_is_sealed_and_bound_to_the_key():
    tok = "github_pat_" + "A1" * 20
    blob = updates.seal_token(tok, b"key-1")
    assert tok not in blob and updates.unseal_token(blob, b"key-1") == tok
    assert updates.unseal_token(blob, b"key-2") is None and updates.unseal_token("garbage", b"key-1") is None
    assert updates.clean_token(" " + tok + " ") == tok
    for bad in ("", "kort", "ghp_x y" * 5, "a" * 300, tok + "\n#"):
        assert updates.clean_token(bad) is None


# --------------------------------------------------------------- request + status


def _releases():
    return [updates._trim_release(_rel("2.11.0")), updates._trim_release(_rel("2.12.0", installable=False))]


def test_request_is_signed_and_verifiable(tmp_path):
    req = updates.write_request(tmp_path, "v2.11.0", "Do nnii<x>", releases=_releases(), current="2.10.0", now=NOW)
    on_disk = json.loads((tmp_path / updates.REQUEST_FILE).read_text())
    assert on_disk == req and set(req) == {"v", "tag", "requested_by", "ts", "nonce", "sig"}
    assert req["requested_by"] == "Do_nnii_x_"  # only safe characters reach the host
    assert (tmp_path / updates.REQUEST_FILE).stat().st_mode & 0o077 == 0
    key = updates.request_key(tmp_path)
    assert (tmp_path / updates.KEY_FILE).stat().st_mode & 0o077 == 0
    assert updates.verify_request(req, key, now=NOW) == "v2.11.0"
    assert updates.verify_request({**req, "tag": "v2.12.0"}, key, now=NOW) is None
    assert updates.verify_request({**req, "extra": 1}, key, now=NOW) is None
    assert updates.verify_request(req, key, now=NOW + 7200) is None
    assert updates.verify_request(req, b"0" * 64, now=NOW) is None
    st = updates.read_status(tmp_path, now=NOW)
    assert st["state"] == "venter" and st["tag"] == "v2.11.0"
    with pytest.raises(updates.UpdateRefused, match="allerede"):
        updates.write_request(tmp_path, "v2.11.0", "a", releases=_releases(), current="2.10.0", now=NOW)
    assert updates.cancel_request(tmp_path) and updates.read_status(tmp_path)["state"] == "idle"


@pytest.mark.parametrize("tag,current,msg", [
    ("v2.11.0; reboot", "2.10.0", "Ukendt"), ("2.11.0", "2.10.0", "Ukendt"), ("v9.9.9", "2.10.0", "findes ikke"),
    ("v2.11.0", "2.11.0", "ikke nyere"), ("v2.11.0", "2.12.0", "ikke nyere"), ("v2.12.0", "2.10.0", "kildepakke")])
def test_request_refused(tmp_path, tag, current, msg):
    with pytest.raises(updates.UpdateRefused, match=msg):
        updates.write_request(tmp_path, tag, "admin", releases=_releases(), current=current, now=NOW)
    assert not (tmp_path / updates.REQUEST_FILE).exists()


def test_request_refused_while_the_host_runs(tmp_path):
    (tmp_path / updates.STATUS_FILE).write_text(json.dumps({"state": "koerer", "tag": "v2.11.0", "started_at": NOW}))
    with pytest.raises(updates.UpdateRefused):
        updates.write_request(tmp_path, "v2.11.0", "a", releases=_releases(), current="2.10.0", now=NOW)


def test_status_is_cleaned(tmp_path):
    (tmp_path / updates.STATUS_FILE).write_text(json.dumps({
        "state": "fejlet", "tag": "v2.11.0; x", "message": "nede\x1b[31m", "log": ["a\x00b", "ok"] * 50,
        "started_at": NOW, "finished_at": NOW + 5}))
    st = updates.read_status(tmp_path, now=NOW)
    assert st["state"] == "fejlet" and st["tag"] == "" and st["message"] == "nede[31m"
    assert len(st["log"]) == 60 and st["log"][-2] == "ab"
    (tmp_path / updates.STATUS_FILE).write_text(json.dumps({"state": "rm -rf", "log": "x"}))
    assert updates.read_status(tmp_path)["state"] == "idle"
    (tmp_path / updates.STATUS_FILE).write_text(json.dumps({"state": "koerer", "started_at": NOW}))
    assert updates.read_status(tmp_path, now=NOW + updates.STATUS_STALE + 1)["stale"]


def test_notes_are_escaped():
    html = updates.notes_html(f"## Nyt\n- **Fed** og `kode` {EVIL}\n\nTekst [link](javascript:x)", updates_escape)
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "<b>Fed</b>" in html and "<code>kode</code>" in html and "<ul" in html and "href" not in html


def updates_escape(s):
    import ui_kit

    return ui_kit.h(s)


# --------------------------------------------------------------- the page


@pytest.fixture
def gh(env, monkeypatch):
    """GitHub answers from a list (no network); SF_UPDATE_REPO set."""
    monkeypatch.setenv("SF_UPDATE_REPO", "ejer/spamfilter")
    data = {"releases": [_rel("2.99.0", pre=True, body=f"- **Menu** ny {EVIL}"), _rel("2.10.0")], "calls": 0}

    def fake(update_dir, repo, token, *, session=None, force=False, now=None):
        data["calls"] += 1
        data["token"] = token
        rels = [t for t in (updates._trim_release(r) for r in data["releases"]) if t]
        return {"repo": repo, "releases": rels, "checked_at": int(time.time()), "error": data.get("error", "")}

    monkeypatch.setattr(updates, "check_releases", fake)
    return data


def _upd(env):
    return env.state / "update"


def test_page_shows_versions_notes_and_button(env, admin, gh):  # noqa: F811
    import ui_updates

    admin.post("/updates/settings", data={"channel": "beta", "csrf": csrf_of(admin)})
    html = text(admin.get("/updates"))
    assert "Kører nu" in html and "2.99.0" in html and "Opdatér nu" in html
    assert EVIL not in html and "&lt;script&gt;" in html and "<b>Menu</b>" in html
    assert 'action="/updates/request"' in html and 'value="v2.99.0"' in html and "data-confirm" in html
    assert ui_updates.ERROR_TEXT  # error texts exist
    # stable channel: 2.99.0 is a pre-release -> not offered
    admin.post("/updates/settings", data={"channel": "stable", "csrf": csrf_of(admin)})
    html = text(admin.get("/updates"))
    assert "nyeste version" in html and 'action="/updates/request"' not in html


def test_page_is_csp_clean_and_in_the_menu(env, admin, gh):  # noqa: F811
    gh["releases"][0]["prerelease"] = False
    _upd(env).mkdir(parents=True, exist_ok=True)
    (_upd(env) / "status.json").write_text(json.dumps({"state": "fejlet", "tag": "v2.99.0", "message": "x",
                                                        "log": ["linje 1", EVIL], "started_at": 1, "finished_at": 2}))
    html = text(admin.get("/updates"))
    for rx, what in INLINE_PATTERNS:
        m = rx.search(html)
        assert m is None, f"{what}: {html[max(0, m.start() - 60):m.end() + 60]}"
    assert EVIL not in html and "Fejlet" in html
    side = html[html.index('<nav class="nav"'):html.index("</aside>")]
    assert re.search(r'<a class="nav-link is-active" href="/updates"[^>]*aria-current="page"', side)


def test_bruger_cannot_see_or_use_updates(env, sofie, gh):  # noqa: F811
    assert sofie.get("/updates").status_code == 403
    for url in ("/updates/request", "/updates/check", "/updates/settings", "/updates/cancel"):
        assert post(sofie, url, {"tag": "v2.99.0"}).status_code in (400, 403)
    assert not (_upd(env) / "request.json").exists()
    assert "/updates" not in text(sofie.get("/"))


def test_request_needs_csrf(env, admin, gh):  # noqa: F811
    r = admin.post("/updates/request", data={"tag": "v2.99.0"})
    assert r.status_code in (400, 403) and not (_upd(env) / "request.json").exists()


def test_request_cancel_and_audit(env, admin, gh):  # noqa: F811
    gh["releases"][0]["prerelease"] = False
    r = post(admin, "/updates/request", {"tag": "v2.99.0"})
    assert r.status_code == 200 and r.get_json()["ok"]
    req = json.loads((_upd(env) / "request.json").read_text())
    assert req["tag"] == "v2.99.0" and req["requested_by"] == "admin"
    assert updates.verify_request(req, updates.request_key(_upd(env))) == "v2.99.0"
    html = text(admin.get("/updates"))
    assert "Venter" in html and 'action="/updates/cancel"' in html and 'action="/updates/request"' not in html
    assert 'data-reload-after="15"' in html  # the page follows the host's progress
    assert not post(admin, "/updates/request", {"tag": "v2.99.0"}).get_json()["ok"]  # one at a time
    assert post(admin, "/updates/cancel").get_json()["ok"] and not (_upd(env) / "request.json").exists()
    assert not post(admin, "/updates/cancel").get_json()["ok"]
    acts = [(a["action"], a.get("result"), a.get("detail", "")) for a in env.audit()]
    assert ("update_request", "ok", "tag=v2.99.0") in acts and ("update_cancel", "ok", "") in acts
    assert any(a == "update_request" and res == "afvist" for a, res, _ in acts)


def test_request_refuses_free_text_and_unknown_tags(env, admin, gh):  # noqa: F811
    gh["releases"][0]["prerelease"] = False
    for tag in ("v2.99.0 && reboot", "../../x", "v9.9.9", "v2.10.0", ""):
        assert not post(admin, "/updates/request", {"tag": tag}).get_json()["ok"], tag
    assert not (_upd(env) / "request.json").exists()


def test_token_saved_encrypted_never_shown_and_removed(env, admin, gh):  # noqa: F811
    tok = "github_pat_" + "B2" * 20
    assert not post(admin, "/updates/settings", {"channel": "stable", "token": "ikke en token"}).get_json()["ok"]
    assert post(admin, "/updates/settings", {"channel": "stable", "token": tok}).get_json()["ok"]
    html = text(admin.get("/updates"))
    assert tok not in html and "gemt krypteret" in html and gh["token"] == tok
    assert tok not in (env.state / "admin-audit.jsonl").read_text()
    assert post(admin, "/updates/settings", {"clear_token": "1"}).get_json()["ok"]
    admin.get("/updates")
    assert gh["token"] is None


def test_errors_are_explained(env, admin, gh):  # noqa: F811
    gh["error"] = "not_found"
    assert "Repoet blev ikke fundet" in text(admin.get("/updates"))
    r = post(admin, "/updates/check")
    assert not r.get_json()["ok"] and any(a["action"] == "update_check" for a in env.audit())


def test_runner_heartbeat_shown(env, admin, gh):  # noqa: F811
    assert "Ikke set" in text(admin.get("/updates"))
    _upd(env).mkdir(parents=True, exist_ok=True)
    (_upd(env) / "runner.json").write_text(json.dumps({"seen_at": int(time.time()) - 30, "v": 1}))
    assert "Aktiv" in text(admin.get("/updates"))


# --------------------------------------------------------------- 2.11.2: token hand-over to the host

TOK = "github_pat_" + "C3" * 20


def test_token_formats_are_strict():
    for good in (TOK, "ghp_" + "a1B2" * 9, "ghs_" + "x" * 36):
        assert updates.clean_token(good) == good
    for bad in ("A" * 40, "github_pat_kort", "ghx_" + "a" * 36, "ghp_" + "a_b" * 12, TOK + "\nX", "ghp_" + "a" * 300):
        assert updates.clean_token(bad) is None, bad


def test_request_hands_over_the_token_bound_to_its_nonce(tmp_path):
    req = updates.write_request(tmp_path, "v2.11.0", "admin", releases=_releases(), current="2.10.0", now=NOW,
                                token=TOK)
    path = tmp_path / updates.TOKEN_FILE
    data = json.loads(path.read_text())
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert set(data) == {"v", "nonce", "token", "sig"} and data["nonce"] == req["nonce"] and data["token"] == TOK
    key = updates.request_key(tmp_path)
    assert data["sig"] == updates.sign_token(key, req["nonce"], TOK) != updates.sign_token(key, "ab" * 16, TOK)
    assert TOK not in (tmp_path / updates.REQUEST_FILE).read_text()
    # cancelling deletes the hand-over with the request
    assert updates.cancel_request(tmp_path) and not path.exists()
    # a request without a token removes an old hand-over; a bad token is never handed over
    path.write_text("{}")
    updates.write_request(tmp_path, "v2.11.0", "admin", releases=_releases(), current="2.10.0", now=NOW)
    assert not path.exists()
    updates.cancel_request(tmp_path)
    updates.write_request(tmp_path, "v2.11.0", "admin", releases=_releases(), current="2.10.0", now=NOW,
                          token="A" * 40)
    assert not path.exists()


def test_failed_request_write_leaves_no_token(tmp_path, monkeypatch):
    real = updates._write_atomic

    def boom(path, data, mode=0o600):
        if path.name == updates.REQUEST_FILE:
            raise OSError("disk full")
        return real(path, data, mode)

    monkeypatch.setattr(updates, "_write_atomic", boom)
    with pytest.raises(OSError):
        updates.write_request(tmp_path, "v2.11.0", "admin", releases=_releases(), current="2.10.0", now=NOW,
                              token=TOK)
    assert not (tmp_path / updates.TOKEN_FILE).exists()


def test_handover_is_never_in_a_backup():
    import backup
    from pathlib import PurePosixPath

    assert backup._skip_state(PurePosixPath("update/request.token"))
    assert backup._skip_state(PurePosixPath("update/.request.token.abc123"))  # the temp file while writing
    assert not backup._skip_state(PurePosixPath("update/status.json"))


def test_read_runner_and_status_error(tmp_path):
    assert updates.read_runner(tmp_path) == {"seen_at": 0, "token_file": False, "token_handoff": False}
    (tmp_path / "runner.json").write_text(json.dumps({"seen_at": 5, "v": 2, "token_file": "yes",
                                                     "token_handoff": True}))
    assert updates.read_runner(tmp_path) == {"seen_at": 5, "token_file": False, "token_handoff": True}
    (tmp_path / "status.json").write_text(json.dumps({"state": "fejlet", "error": "github_access", "message": "m"}))
    assert updates.read_status(tmp_path)["error"] == "github_access"
    (tmp_path / "status.json").write_text(json.dumps({"state": "fejlet", "error": EVIL}))
    assert updates.read_status(tmp_path)["error"] == ""


def _runner_json(env, **kw):
    _upd(env).mkdir(parents=True, exist_ok=True)
    (_upd(env) / "runner.json").write_text(json.dumps({"seen_at": int(time.time()) - 20, "v": 2, **kw}))


@pytest.mark.parametrize("runner,handed", [
    ({"token_file": False, "token_handoff": True}, True),     # 2.11.2 helper without its own token
    ({"token_file": True, "token_handoff": True}, False),     # the host's own token file wins
    ({}, False),                                              # 2.11.0/2.11.1 helper: does not know the field
])
def test_ui_hands_the_token_to_the_host_only_when_needed(env, admin, gh, runner, handed):  # noqa: F811
    gh["releases"][0]["prerelease"] = False
    assert post(admin, "/updates/settings", {"channel": "stable", "token": TOK}).get_json()["ok"]
    _runner_json(env, **runner)
    assert post(admin, "/updates/request", {"tag": "v2.99.0"}).get_json()["ok"]
    path = _upd(env) / updates.TOKEN_FILE
    assert path.exists() is handed
    req = json.loads((_upd(env) / "request.json").read_text())
    if handed:
        assert json.loads(path.read_text())["nonce"] == req["nonce"]
    audit = (env.state / "admin-audit.jsonl").read_text()
    assert TOK not in audit and TOK not in text(admin.get("/updates"))
    assert ("token=id " in audit) is handed
    # "Fjern token" also removes a copy still waiting for the host
    assert post(admin, "/updates/settings", {"clear_token": "1"}).get_json()["ok"] and not path.exists()


def test_ui_never_hands_the_token_to_a_helper_not_seen(env, admin, gh):  # noqa: F811
    """2.11.2 review: with the helper not seen lately (User Scripts off), the
    token would stay in clear text in state/update - refuse instead."""
    gh["releases"][0]["prerelease"] = False
    assert post(admin, "/updates/settings", {"channel": "stable", "token": TOK}).get_json()["ok"]
    _upd(env).mkdir(parents=True, exist_ok=True)
    (_upd(env) / "runner.json").write_text(json.dumps({"seen_at": int(time.time()) - 3600, "v": 2,
                                                       "token_handoff": True}))
    r = post(admin, "/updates/request", {"tag": "v2.99.0"}).get_json()
    assert not r["ok"] and "ikke set" in json.dumps(r, ensure_ascii=False)
    assert not (_upd(env) / updates.TOKEN_FILE).exists() and not (_upd(env) / "request.json").exists()
    _runner_json(env, token_handoff=True)  # seen again
    assert post(admin, "/updates/request", {"tag": "v2.99.0"}).get_json()["ok"]
    assert (_upd(env) / updates.TOKEN_FILE).exists()


def test_helper_access_is_shown(env, admin, gh):  # noqa: F811
    _runner_json(env, token_file=False, token_handoff=True)
    assert "virker kun med et offentligt repo" in text(admin.get("/updates"))
    post(admin, "/updates/settings", {"channel": "beta", "token": TOK})
    html = text(admin.get("/updates"))
    i = html.find("GitHub-adgang")
    assert "ens token</span>" in html and "slettes bagefter" in html, html[i:i + 400]
    _runner_json(env, token_file=True, token_handoff=True)
    assert "Værtens token" in text(admin.get("/updates"))
    _runner_json(env)  # old helper
    html = text(admin.get("/updates"))
    assert "Gammel hjælper" in html and "2.11.2" in html


def test_access_errors_name_the_permission(env, admin, gh, monkeypatch):  # noqa: F811
    monkeypatch.setenv("SF_UPDATE_REPO", "ejer/imap-spamfilter-unraid")
    want = "Tokenen har ikke adgang til repoet – den skal have Contents: read på imap-spamfilter-unraid"
    gh["error"] = "not_found"
    html = text(admin.get("/updates"))
    assert "Repoet blev ikke fundet" in html and "Contents: read på imap-spamfilter-unraid" in html
    post(admin, "/updates/settings", {"channel": "beta", "token": TOK})
    for code in ("not_found", "auth"):
        gh["error"] = code
        assert want in text(admin.get("/updates")), code
        r = post(admin, "/updates/check").get_json()
        assert not r["ok"] and want in json.dumps(r, ensure_ascii=False), code


def test_status_shows_the_helpers_github_refusal(env, admin, gh):  # noqa: F811
    _upd(env).mkdir(parents=True, exist_ok=True)
    msg = "GitHub svarede 404: tokenen har ikke adgang til repoet – den skal have Contents: read på spamfilter."
    (_upd(env) / "status.json").write_text(json.dumps({"state": "fejlet", "tag": "v2.99.0", "message": msg,
                                                        "error": "github_access", "started_at": 1, "finished_at": 2}))
    _runner_json(env, token_handoff=True)
    html = text(admin.get("/updates"))
    assert "GitHub afviste hjælperen" in html and "Contents: read på spamfilter" in html and "Afvist" in html


def test_old_result_hidden_once_newer_version_runs(tmp_path):
    """2.14.1: "Fejlet v2.11.1" must not linger after 2.14.0 was installed another way."""
    import ui_updates
    (tmp_path / updates.STATUS_FILE).write_text(json.dumps(
        {"state": "fejlet", "tag": "v2.11.1", "finished_at": NOW, "message": "Opdateringen fejlede under: release (exit 22)."}))
    st = updates.read_status(tmp_path)
    assert ui_updates._status_card(st, "2.14.0") == ""
    assert ui_updates._status_card(st, "2.11.1") == ""
    assert "Fejlet" in ui_updates._status_card(st, "2.11.0")
    (tmp_path / updates.STATUS_FILE).write_text(json.dumps({"state": "faerdig", "tag": "v2.14.0", "finished_at": NOW}))
    st = updates.read_status(tmp_path)
    assert "Færdig" in ui_updates._status_card(st, "2.14.0")
    assert ui_updates._status_card(st, "2.14.1") == ""
