"""2.10 Opdateringer, host side: deploy/update-runner.sh (User Script
"Spamfilter-update", every minute). Runs the real script against a temp
app dir with a fake curl (GitHub) and a source package whose
deploy/aio/update.sh only records that it ran. Checks: a valid signed
request installs exactly that tag (backup, source/ swapped, update.sh
--build from the verified tree, status færdig); everything else is refused
without installing: bad signature, replay, old request, wrong checksum,
not newer, unsafe paths, a planted symlink; a failed update.sh puts the
previous source/ back; --dry-run consumes nothing."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "deploy" / "update-runner.sh"
sys.path.insert(0, str(ROOT / "filter"))

import updates  # noqa: E402

needs = [c for c in ("jq", "openssl", "sha256sum", "flock", "timeout", "tar") if not shutil.which(c)]
pytestmark = pytest.mark.skipif(bool(needs), reason=f"missing {needs}")

API = "https://api.test"
REPO = "ejer/spamfilter"

FAKE_CURL = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_CURL_CALLS"], "a") as fh:
    fh.write(" ".join(args) + "\n")
# 2.11.2: which Authorization header (from -H @file) went to which URL.
auth = [open(args[i + 1][1:]).read().strip() for i, a in enumerate(args[:-1])
        if a == "-H" and args[i + 1].startswith("@")]
with open(os.environ["FAKE_CURL_AUTH"], "a") as fh:
    fh.write(args[-1] + " " + (auth[0] if auth else "-") + "\n")
routes = json.load(open(os.environ["FAKE_CURL_ROUTES"]))
url, out = args[-1], None
if "-o" in args:
    out = args[args.index("-o") + 1]
route = routes.get(url)
if not isinstance(route, dict):
    route = {"path": route, "code": 200 if route else 404}
need = route.get("auth")
if need and not any(a == "Authorization: Bearer " + need for a in auth):
    route = {"code": 404}
code, path = route["code"], route.get("path")
if "-D" in args:
    with open(args[args.index("-D") + 1], "w") as fh:
        fh.write("HTTP/2 %d\r\n" % code + "".join("%s: %s\r\n" % kv for kv in route.get("headers", {}).items()))
if code >= 400 and ("-f" in args or "-fsS" in args):
    sys.stderr.write("curl: (22) The requested URL returned error: %d\n" % code)
    sys.exit(22)
data = open(path, "rb").read() if path else b'{"message": "Not Found"}'
if out:
    open(out, "wb").write(data)
else:
    sys.stdout.buffer.write(data)
if "-w" in args:  # "effective": where a redirect (-L) ended up
    w = args[args.index("-w") + 1]
    sys.stdout.write(w.replace("%{http_code}", str(code)).replace("%{url_effective}", route.get("effective", url)))
'''

UPDATE_SH = """#!/bin/bash
set -euo pipefail
echo "update.sh $* app=$SPAMFILTER_APP from=$(dirname "$0")" >>"$SPAMFILTER_APP/ran"
echo "gate ok"
exit "${FAKE_UPDATE_RC:-0}"
"""


def _package(path: Path, version: str, *, top: str | None = None, extra: dict | None = None,
             file_version: str | None = None) -> None:
    top = top or f"spamfilter-{version}"
    files = {"deploy/versions.env": f"VERSION={file_version or version}\n", "deploy/aio/update.sh": UPDATE_SH,
             "filter/filter.py": f'VERSION = "{version}"\n', **(extra or {})}
    with tarfile.open(path, "w:gz") as tf:
        for name, body in files.items():
            data = body.encode()
            ti = tarfile.TarInfo(name if name.startswith(("/", "..")) else f"{top}/{name}")
            ti.size, ti.mode = len(data), 0o755 if name.endswith(".sh") else 0o644
            tf.addfile(ti, io.BytesIO(data))


class Host:
    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.app = tmp / "app"
        self.upd = self.app / "state" / "update"
        self.upd.mkdir(parents=True)
        (self.app / "operations").mkdir()
        (self.app / "source" / "deploy").mkdir(parents=True)
        (self.app / "source" / "deploy" / "versions.env").write_text("VERSION=2.10.1\n")
        (self.app / "source" / "OLD").write_text("old tree\n")
        self.bin = tmp / "bin"
        self.bin.mkdir()
        (self.bin / "curl").write_text(FAKE_CURL)
        (self.bin / "curl").chmod(0o755)
        (self.bin / "notify").write_text('#!/bin/bash\necho "$*" >>"$FAKE_NOTIFY_LOG"\n')
        (self.bin / "notify").chmod(0o755)
        self.routes: dict[str, str] = {}
        self.calls = tmp / "curl-calls"
        self.calls.touch()

    def release(self, version: str, *, digest: str | None = None, sha: str | None = None, assets: bool = True,
                **pkg) -> None:
        pkg_path = self.tmp / f"pkg-{version}.tar.gz"
        _package(pkg_path, version, **pkg)
        real = hashlib.sha256(pkg_path.read_bytes()).hexdigest()
        sha_path = self.tmp / f"pkg-{version}.sha256"
        sha_path.write_text(f"{sha or real}  spamfilter-{version}-source.tar.gz\n")
        name = updates.source_asset(version)
        rel = {"tag_name": f"v{version}", "draft": False, "prerelease": True,
               "assets": [{"id": 11, "name": name, "digest": digest if digest is not None else f"sha256:{real}"},
                          {"id": 12, "name": name + ".sha256"}] if assets else []}
        rel_path = self.tmp / f"release-{version}.json"
        rel_path.write_text(json.dumps(rel))
        self.routes.update({f"{API}/repos/{REPO}/releases/tags/v{version}": str(rel_path),
                            f"{API}/repos/{REPO}/releases/assets/11": str(pkg_path),
                            f"{API}/repos/{REPO}/releases/assets/12": str(sha_path)})

    def request(self, tag: str, *, ts: int | None = None, actor: str = "admin", token: str | None = None,
                **override) -> dict:
        key = updates.request_key(self.upd)
        ts = int(time.time()) if ts is None else ts
        nonce = override.pop("nonce", os.urandom(16).hex())
        req = {"v": 1, "tag": tag, "requested_by": actor, "ts": ts, "nonce": nonce,
               "sig": updates.sign(key, tag, actor, ts, nonce), **override}
        if token:
            self.handover(token, nonce)
        (self.upd / "request.json").write_text(json.dumps(req))
        return req

    def handover(self, token: str, nonce: str, **override) -> None:
        """state/update/request.token as the WebUI writes it (2.11.2)."""
        key = updates.request_key(self.upd)
        data = {"v": 1, "nonce": nonce, "token": token, "sig": updates.sign_token(key, nonce, token), **override}
        (self.upd / "request.token").write_text(json.dumps(data))
        (self.upd / "request.token").chmod(0o600)

    def require_token(self, token: str) -> None:
        """GitHub answers 404 (private repo) unless this token is sent."""
        self.routes = {u: {"path": p, "code": 200, "auth": token} for u, p in self.routes.items()}

    def auth_sent(self) -> list[str]:
        p = self.tmp / "curl-auth"
        return p.read_text().splitlines() if p.exists() else []

    def files_containing(self, needle: str) -> list[str]:
        """Every file below the app dir and the test dir holding `needle`,
        except the fake GitHub's own files (its routes and the headers it got)."""
        hits = []
        for p in self.tmp.rglob("*"):
            if p.name in ("curl-auth", "routes.json") or p.is_symlink() or not p.is_file():
                continue
            if needle.encode() in p.read_bytes():
                hits.append(str(p.relative_to(self.tmp)))
        return hits

    def run(self, *args: str, **env_extra: str) -> subprocess.CompletedProcess:
        routes = self.tmp / "routes.json"
        routes.write_text(json.dumps(self.routes))
        env = {"PATH": f"{self.bin}:{os.environ['PATH']}", "SPAMFILTER_APP": str(self.app),
               "SF_UPDATE_REPO": REPO, "SF_UPDATE_API": API, "SF_UPDATE_LOCK": str(self.tmp / "runner.lock"),
               "SF_LOCK_FILE": str(self.tmp / "deploy.lock"), "SF_NOTIFY_BIN": str(self.bin / "notify"),
               "SF_UPDATE_TOKEN_FILE": str(self.tmp / "no-token"),
               "FAKE_CURL_ROUTES": str(routes), "FAKE_CURL_CALLS": str(self.calls),
               "FAKE_CURL_AUTH": str(self.tmp / "curl-auth"),
               "FAKE_NOTIFY_LOG": str(self.tmp / "notify.log"), "HOME": str(self.tmp), **env_extra}
        return subprocess.run(["bash", str(RUNNER), *args], env=env, capture_output=True, text=True, timeout=120)

    def status(self) -> dict:
        return json.loads((self.upd / "status.json").read_text())

    def installed(self) -> str:
        return (self.app / "source" / "deploy" / "versions.env").read_text().strip()

    def ran(self) -> str:
        p = self.app / "ran"
        return p.read_text() if p.exists() else ""


@pytest.fixture
def host(tmp_path):
    return Host(tmp_path)


def test_no_request_only_heartbeat(host):
    r = host.run()
    assert r.returncode == 0, r.stderr
    assert json.loads((host.upd / "runner.json").read_text())["seen_at"] > 0
    assert not (host.upd / "status.json").exists() and host.calls.read_text() == ""


def test_valid_request_installs_exactly_that_tag(host):
    host.release("2.11.0")
    host.request("v2.11.0")
    r = host.run()
    assert r.returncode == 0, r.stdout + r.stderr
    assert host.installed() == "VERSION=2.11.0" and not (host.app / "source" / "OLD").exists()
    ran = host.ran()
    assert "update.sh --build" in ran and f"app={host.app}" in ran
    assert str(host.app / "source") not in ran.split("from=")[1]  # runs from the root-only verified copy
    st = host.status()
    assert st["state"] == "faerdig" and st["tag"] == "v2.11.0" and "gate ok" in st["log"]
    assert st["requested_by"] == "admin" and st["finished_at"] >= st["started_at"] > 0
    assert oct((host.upd / "status.json").stat().st_mode & 0o777) == "0o644"
    assert not (host.upd / "request.json").exists()
    backups = list((host.app / "operations" / "source-backups").glob("source-*.tar.gz"))
    assert len(backups) == 1 and not list(host.app.glob("source.prev-*"))
    assert not list((host.app / "operations").glob(".update-work.*"))  # cleaned up
    assert list((host.app / "operations").glob("update-runner-*.log"))
    calls = host.calls.read_text()
    assert f"{API}/repos/{REPO}/releases/assets/11" in calls and "--proto =https" in calls


def test_failed_update_restores_the_previous_source(host):
    host.release("2.11.0")
    host.request("v2.11.0")
    r = host.run(FAKE_UPDATE_RC="3")
    assert r.returncode == 1
    assert host.installed() == "VERSION=2.10.1" and (host.app / "source" / "OLD").exists()
    st = host.status()
    assert st["state"] == "fejlet" and "exit 3" in st["message"] and "gate ok" in st["log"]
    assert "fejlede" in (host.tmp / "notify.log").read_text()


@pytest.mark.parametrize("case,expect", [
    ("bad_sig", "signaturen"), ("old", "for gammel"), ("extra_key", "format"), ("free_text", "ugyldig version"),
    ("actor", "brugernavn"), ("not_newer", "ikke nyere"), ("no_assets", "kildepakke"), ("sha_file", ".sha256"),
    ("digest", "GitHubs"), ("dotdot", "ugyldige stier"), ("other_top", "ugyldige stier"),
    ("wrong_version", "ikke version"), ("unknown_release", "GitHub svarede 404"),
    ("no_repo", "SF_UPDATE_REPO")])
def test_refused_requests_install_nothing(host, case, expect):
    env = {}
    tag = "v2.11.0"
    if case == "no_assets":
        host.release("2.11.0", assets=False)
    elif case == "sha_file":
        host.release("2.11.0", sha="0" * 64)
    elif case == "digest":
        host.release("2.11.0", digest="sha256:" + "1" * 64)
    elif case == "dotdot":
        host.release("2.11.0", extra={"../evil.sh": "x"})
    elif case == "other_top":
        host.release("2.11.0", top="andet")
    elif case == "wrong_version":
        host.release("2.11.0", file_version="2.12.0")
    elif case != "unknown_release":
        host.release("2.11.0")
    if case == "bad_sig":
        host.request(tag, sig="0" * 64)
    elif case == "old":
        host.request(tag, ts=int(time.time()) - 7200)
    elif case == "extra_key":
        host.request(tag, cmd="reboot")
    elif case == "free_text":
        host.request("v2.11.0; reboot")
    elif case == "actor":
        host.request(tag, actor="a b$(id)")
    elif case == "not_newer":
        host.release("2.10.1")
        host.request("v2.10.1")
    elif case == "no_repo":
        env["SF_UPDATE_REPO"] = "../../etc"
        host.request(tag)
    else:
        host.request(tag)
    r = host.run(**env)
    assert r.returncode != 0
    st = host.status()
    assert st["state"] == "fejlet" and expect in st["message"], st
    assert host.installed() == "VERSION=2.10.1" and host.ran() == ""
    assert not (host.upd / "request.json").exists()  # consumed: not retried every minute
    assert not (host.tmp / "evil.sh").exists() and not (host.app / "evil.sh").exists()


def test_replayed_request_is_refused(host):
    host.release("2.11.0")
    req = host.request("v2.11.0")
    assert host.run().returncode == 0
    (host.app / "source" / "deploy" / "versions.env").write_text("VERSION=2.10.1\n")
    (host.app / "ran").unlink()
    (host.upd / "request.json").write_text(json.dumps(req))
    assert host.run().returncode == 1
    assert "brugt før" in host.status()["message"] and host.ran() == ""


def test_symlinked_request_is_refused(host):
    host.release("2.11.0")
    secret = host.tmp / "secret"
    secret.write_text("root only\n")
    (host.upd / "request.json").symlink_to(secret)
    assert host.run().returncode == 1
    assert "almindelig fil" in host.status()["message"] and secret.read_text() == "root only\n"


def test_planted_status_symlink_is_replaced_not_followed(host):
    target = host.tmp / "target"
    target.write_text("keep\n")
    (host.upd / "status.json").symlink_to(target)
    host.release("2.11.0")
    host.request("v2.11.0")
    assert host.run().returncode == 0
    assert target.read_text() == "keep\n" and not (host.upd / "status.json").is_symlink()


def test_dry_run_consumes_and_installs_nothing(host):
    host.release("2.11.0")
    host.request("v2.11.0")
    r = host.run("--dry-run")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "[DRY RUN] v2.11.0 verified" in r.stdout
    assert (host.upd / "request.json").exists() and host.installed() == "VERSION=2.10.1" and host.ran() == ""
    assert not (host.upd / "status.json").exists()


def test_waits_while_another_deploy_runs(host):
    host.release("2.11.0")
    host.request("v2.11.0")
    lock = host.tmp / "deploy.lock"
    holder = subprocess.Popen(["flock", str(lock), "sleep", "5"])
    try:
        time.sleep(0.3)
        assert host.run().returncode == 0
        assert (host.upd / "request.json").exists() and host.ran() == ""
    finally:
        holder.terminate()
        holder.wait()


def test_python_and_bash_sign_the_same_message(host):
    """The host's openssl HMAC equals updates.sign (same key, same fields)."""
    key = updates.request_key(host.upd)
    msg = updates.request_message("v2.11.0", "admin", 1800000000, "ab" * 16)
    out = subprocess.run(["openssl", "dgst", "-sha256", "-mac", "HMAC", "-macopt", f"key:{key.decode()}"],
                         input=msg, capture_output=True, check=True).stdout.decode().split()[-1]
    assert out == updates.sign(key, "v2.11.0", "admin", 1800000000, "ab" * 16)


# ================================================================ 2.11.2: token from the WebUI

WEB_TOKEN = "github_pat_" + "W3b" * 20
HOST_TOKEN = "ghp_" + "H0st" * 9


def test_runner_reports_handoff_support(host):
    host.run()
    data = json.loads((host.upd / "runner.json").read_text())
    assert data["token_handoff"] is True and data["token_file"] is False and data["v"] == 2
    (host.tmp / "host-token").write_text(HOST_TOKEN + "\n")
    host.run(SF_UPDATE_TOKEN_FILE=str(host.tmp / "host-token"))
    assert json.loads((host.upd / "runner.json").read_text())["token_file"] is True
    assert HOST_TOKEN not in (host.upd / "runner.json").read_text()


def test_webui_token_is_used_for_the_repo_and_deleted(host):
    host.release("2.11.0")
    host.require_token(WEB_TOKEN)
    host.request("v2.11.0", token=WEB_TOKEN)
    r = host.run()
    assert r.returncode == 0, r.stdout + r.stderr
    assert host.installed() == "VERSION=2.11.0"
    sent = host.auth_sent()
    assert sent and all(line.endswith(f"Authorization: Bearer {WEB_TOKEN}") for line in sent)
    assert all(line.startswith(f"{API}/repos/{REPO}/") for line in sent)
    assert not (host.upd / "request.token").exists()          # moved away at once ...
    assert not list((host.app / "operations").glob(".update-work.*"))  # ... and deleted with the work dir
    # never logged, never in status/notify/nonces/curl's argv
    assert WEB_TOKEN not in r.stdout + r.stderr and host.files_containing(WEB_TOKEN) == []
    assert "GitHub token: webui" in r.stdout and host.status()["state"] == "faerdig"


def test_host_token_file_wins_and_the_handover_is_deleted_unread(host):
    host.release("2.11.0")
    host.require_token(HOST_TOKEN)
    (host.tmp / "host-token").write_text(HOST_TOKEN + "\n")
    host.request("v2.11.0", token=WEB_TOKEN)
    r = host.run(SF_UPDATE_TOKEN_FILE=str(host.tmp / "host-token"))
    assert r.returncode == 0, r.stdout + r.stderr
    sent = host.auth_sent()
    assert sent and all(line.endswith(f"Bearer {HOST_TOKEN}") for line in sent)
    assert WEB_TOKEN not in "\n".join(sent) and "GitHub token: host" in r.stdout
    assert not (host.upd / "request.token").exists() and host.files_containing(WEB_TOKEN) == []
    assert host.files_containing(HOST_TOKEN) == ["host-token"]


def test_symlinked_host_token_file_is_ignored(host):
    host.release("2.11.0")
    real = host.tmp / "real-token"
    real.write_text(HOST_TOKEN + "\n")
    (host.tmp / "host-token").symlink_to(real)
    host.request("v2.11.0", token=WEB_TOKEN)
    r = host.run(SF_UPDATE_TOKEN_FILE=str(host.tmp / "host-token"))
    assert r.returncode == 0, r.stdout + r.stderr
    assert all(line.endswith(f"Bearer {WEB_TOKEN}") for line in host.auth_sent())


@pytest.mark.parametrize("case,expect", [
    ("other_nonce", "hører ikke til"), ("bad_sig", "signatur"), ("format", "ligner ikke"),
    ("extra_key", "rigtige format"), ("symlink", "almindelig fil"), ("old_style", "ligner ikke")])
def test_bad_handover_is_refused_and_deleted(host, case, expect):
    host.release("2.11.0")
    req = host.request("v2.11.0")
    nonce = req["nonce"]
    if case == "other_nonce":
        host.handover(WEB_TOKEN, "ab" * 16)
    elif case == "bad_sig":
        host.handover(WEB_TOKEN, nonce, sig="0" * 64)
    elif case == "format":
        host.handover("github_pat_x\nAuthorization: evil", nonce)
    elif case == "old_style":
        host.handover("A" * 40, nonce)  # 2.10's loose format is no longer accepted
    elif case == "extra_key":
        host.handover(WEB_TOKEN, nonce, url="https://evil.example")
    elif case == "symlink":
        target = host.tmp / "elsewhere"
        target.write_text("{}")
        (host.upd / "request.token").symlink_to(target)
    r = host.run()
    assert r.returncode == 1
    st = host.status()
    assert st["state"] == "fejlet" and expect in st["message"], st
    assert host.installed() == "VERSION=2.10.1" and host.ran() == "" and host.auth_sent() == []
    assert not (host.upd / "request.token").exists() and not (host.upd / "request.token").is_symlink()
    assert WEB_TOKEN not in r.stdout + r.stderr + json.dumps(st)
    if case == "symlink":
        assert (host.tmp / "elsewhere").read_text() == "{}"


def test_refused_request_deletes_its_token_too(host):
    host.release("2.11.0")
    host.request("v2.11.0", token=WEB_TOKEN, sig="0" * 64)
    assert host.run().returncode == 1 and "signaturen" in host.status()["message"]
    assert not (host.upd / "request.token").exists() and host.files_containing(WEB_TOKEN) == []


@pytest.mark.parametrize("with_token", [True, False])
def test_github_denied_gives_a_clear_danish_message(host, with_token):
    host.release("2.11.0")
    host.require_token("ghp_" + "Other" * 8)   # the repo wants another token: 404 like a private repo
    host.request("v2.11.0", token=WEB_TOKEN if with_token else None)
    r = host.run()
    assert r.returncode == 1
    st = host.status()
    assert st["state"] == "fejlet" and st["error"] == "github_access" and "GitHub svarede 404" in st["message"]
    if with_token:
        assert "tokenen har ikke adgang til repoet – den skal have Contents: read på spamfilter" in st["message"]
    else:
        assert "hjælperen har ingen token" in st["message"] and "Contents: read på spamfilter" in st["message"]
    assert host.installed() == "VERSION=2.10.1" and host.ran() == ""
    assert host.files_containing(WEB_TOKEN) == [] and WEB_TOKEN not in r.stdout + r.stderr
    assert "opdatering fejlede" in (host.tmp / "notify.log").read_text()


def test_deleted_release_is_not_called_an_access_problem(host):
    """2.11.2 review: a 404 for the tag while the repo is visible means the
    release is gone (or a draft) - not "the token has no access"."""
    host.require_token(WEB_TOKEN)
    host.routes[f"{API}/repos/{REPO}"] = {"path": str(host.tmp / "repo.json"), "code": 200, "auth": WEB_TOKEN}
    (host.tmp / "repo.json").write_text('{"full_name": "ejer/spamfilter"}')
    host.request("v2.11.0", token=WEB_TOKEN)
    assert host.run().returncode == 1
    st = host.status()
    assert "udgivelsen v2.11.0 findes ikke" in st["message"] and st["error"] != "github_access", st
    assert f"{API}/repos/{REPO} Authorization: Bearer {WEB_TOKEN}" in host.auth_sent()  # the probe used it too
    assert host.files_containing(WEB_TOKEN) == []


def test_download_host_refusal_is_not_called_an_access_problem(host):
    """A 403 from the download host after the redirect (e.g. an expired
    signed URL) is a download failure, not a token problem."""
    host.release("2.11.0")
    host.routes[f"{API}/repos/{REPO}/releases/assets/11"] = {"code": 403,
                                                           "effective": "https://objects.test/signed?x=1"}
    host.request("v2.11.0")
    assert host.run().returncode == 1
    st = host.status()
    assert st["error"] == "" and "under: download" in st["message"], st
    assert host.installed() == "VERSION=2.10.1" and host.ran() == ""


def test_stale_work_dirs_are_removed(host):
    """A run killed with -9 (or a power loss) can leave a work dir with
    auth.hdr behind: removed after 4 hours by the next run."""
    ops = host.app / "operations"
    old_dir, new_dir = ops / ".update-work.AAAAAA", ops / ".update-work.BBBBBB"
    for d in (old_dir, new_dir):
        d.mkdir()
        (d / "auth.hdr").write_text("Authorization: Bearer " + WEB_TOKEN + "\n")
    old = time.time() - 5 * 3600
    os.utime(old_dir, (old, old))
    host.run("--dry-run")
    assert old_dir.exists()
    assert host.run().returncode == 0
    assert not old_dir.exists() and new_dir.exists()


def test_rate_limit_is_not_called_an_access_problem(host):
    host.release("2.11.0")
    url = f"{API}/repos/{REPO}/releases/tags/v2.11.0"
    host.routes[url] = {"code": 403, "headers": {"x-ratelimit-remaining": "0"}}
    host.request("v2.11.0")
    assert host.run().returncode == 1
    st = host.status()
    assert st["error"] == "github_rate" and "beder os vente" in st["message"]


def test_orphan_handover_is_deleted_after_ten_minutes(host):
    host.handover(WEB_TOKEN, "ab" * 16)
    host.run()
    assert (host.upd / "request.token").exists()   # the WebUI may be writing request.json right now
    old = time.time() - 900
    os.utime(host.upd / "request.token", (old, old))
    host.run("--dry-run")
    assert (host.upd / "request.token").exists()   # --dry-run deletes nothing
    host.run()
    assert not (host.upd / "request.token").exists()


def test_dry_run_checks_the_handover_without_consuming_it(host):
    host.release("2.11.0")
    host.require_token(WEB_TOKEN)
    host.request("v2.11.0", token=WEB_TOKEN)
    r = host.run("--dry-run")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "[DRY RUN] v2.11.0 verified" in r.stdout and (host.upd / "request.token").exists()
    assert WEB_TOKEN not in r.stdout + r.stderr
    assert not list((host.app / "operations").glob(".update-work.*"))


def test_python_and_bash_sign_the_same_token_message(host):
    key = updates.request_key(host.upd)
    msg = updates.token_message("ab" * 16, WEB_TOKEN)
    out = subprocess.run(["openssl", "dgst", "-sha256", "-mac", "HMAC", "-macopt", f"key:{key.decode()}"],
                         input=msg, capture_output=True, check=True).stdout.decode().split()[-1]
    assert out == updates.sign_token(key, "ab" * 16, WEB_TOKEN)


def test_runner_and_python_accept_the_same_token_formats():
    text = RUNNER.read_text()
    bash_re = text.split("TOKEN_RE='", 1)[1].split("'", 1)[0]
    for tok in (WEB_TOKEN, HOST_TOKEN, "A" * 40, "ghp_short", "github_pat_" + "x" * 300, "gho_" + "a_b" * 12):
        ok = subprocess.run(["bash", "-c", f'[[ "$1" =~ {bash_re} ]]', "_", tok]).returncode == 0
        assert ok == bool(updates.clean_token(tok)), tok
