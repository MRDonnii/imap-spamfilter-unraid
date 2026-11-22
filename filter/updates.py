"""Opdateringer (2.10, owner: "der skal laves en update-fane, så det kan
opdateres også igennem WebUI").

The container cannot build or replace itself, so an update is a REQUEST:

1. The WebUI (admin only, CSRF, audited) asks GitHub which releases exist
   (one call to the releases API, conditional with the cached ETag, so a
   check that finds nothing new costs no rate limit). No key is needed for
   a public repository; a read-only token can be saved for a private one -
   stored encrypted (AES-GCM, key derived from the session secret) and
   never shown again.
2. "Opdatér nu" writes state/update/request.json: ONLY a version tag (vX.Y.Z
   that is a published release newer than the running version), who asked,
   when, a random nonce and an HMAC-SHA256 over exactly those fields with
   the key in state/update/request.key. No free text.
3. The host helper deploy/update-runner.sh (Unraid User Script
   "Spamfilter-update", every minute, installed by
   deploy/install-user-scripts.sh) takes the request, checks it field by
   field, fetches the release's source package from GitHub for the
   repository set on the HOST (SF_UPDATE_REPO in operations/site.env -
   never one chosen by the container), checks its sha256 against both
   GitHub's asset digest and the release's .sha256 file, and runs the new
   tree's deploy/aio/update.sh --build (backup, gate, automatic rollback).
   It writes state/update/status.json (venter/kører/færdig/fejlet + the
   last log lines), which the page shows.
4. Token hand-over (2.11.2, owner: "Vi skal kunne sætte token ind fra
   GitHub i GUI'en og køre opdateringen den vej fremover"): when the
   helper reports (runner.json) that it understands it and has no token
   file of its own, "Opdatér nu" also writes state/update/request.token
   {v, nonce, token, sig} (0600) BEFORE request.json; sig = HMAC-SHA256
   with request.key over "tok1|<nonce of that request>|<token>", so it is
   bound to exactly one request. The helper moves it into its root-only
   work dir together with the request, uses it only as the Authorization
   header to the host-configured repo's API and deletes it after the
   download. The container backup skips it (backup.STATE_SKIP_PATHS);
   cancelling deletes it; the helper deletes one left without a request.

Everything here is pure (paths, HTTP session and clock are parameters) so
it is tested without a network.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import tempfile
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("updates")

API = "https://api.github.com"
USER_AGENT = "spamfilter-update-check"
TIMEOUT = 8
CHECK_EVERY = 6 * 3600          # automatic check on page view at most this often
MAX_RELEASES = 30
MAX_BODY = 20000                # characters of release notes kept per release
REQUEST_MAX_AGE = 3600          # the host ignores older requests
STATUS_STALE = 3 * 3600         # "kører" for longer than this = probably dead

REQUEST_FILE = "request.json"
STATUS_FILE = "status.json"
CACHE_FILE = "releases.json"
KEY_FILE = "request.key"
TOKEN_FILE = "request.token"         # the hand-over (2.11.2), next to request.json
RUNNER_FILE = "runner.json"

TAG_RE = re.compile(r"^v(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\Z")
VERSION_RE = re.compile(r"^v?(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})(?:[-+].*)?\Z")
REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}\Z")
ACTOR_RE = re.compile(r"[^A-Za-z0-9._@-]")
# GitHub token formats: fine-grained (github_pat_...) and the classic/app
# prefixes ghp_/gho_/ghu_/ghs_/ghr_. The host helper uses the same pattern.
TOKEN_RE = re.compile(r"^(?:github_pat_[A-Za-z0-9_]{22,240}|gh[pousr]_[A-Za-z0-9]{30,250})\Z")
NONCE_RE = re.compile(r"^[0-9a-f]{32}\Z")
SIG_RE = re.compile(r"^[0-9a-f]{64}\Z")
STATES = ("venter", "koerer", "faerdig", "fejlet")
STATUS_ERRORS = ("github_access", "github_rate")   # status.json "error" from the helper (2.11.2)
CHANNELS = ("stable", "beta")
TOKEN_CONTEXT = b"spamfilter update-token v1"


def source_asset(version: str) -> str:
    """Name of the release's source package (attached by release.yml)."""
    return f"spamfilter-{version}-source.tar.gz"


# --------------------------------------------------------------- versions


def parse_version(v: Any) -> tuple[int, int, int] | None:
    m = VERSION_RE.match(str(v or "").strip())
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def tag_version(tag: str) -> str:
    return tag[1:] if tag.startswith("v") else tag


def repo_from_env(environ: Any = None) -> str:
    """The repository to check: SF_UPDATE_REPO (operations/site.env on the
    host, passed to the container by update.sh). Empty when unset/invalid."""
    val = str((environ if environ is not None else os.environ).get("SF_UPDATE_REPO") or "").strip()
    return val if REPO_RE.match(val) and ".." not in val else ""


# ------------------------------------------------------------ token (AES-GCM)


def _aes(key_material: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415 - only for this feature

    return AESGCM(hmac.new(key_material, TOKEN_CONTEXT, hashlib.sha256).digest())


def clean_token(token: str) -> str | None:
    t = str(token or "").strip()
    return t if TOKEN_RE.match(t) else None


def seal_token(token: str, key_material: bytes) -> str:
    nonce = secrets.token_bytes(12)
    enc = _aes(key_material).encrypt(nonce, token.encode("utf-8"), TOKEN_CONTEXT)
    return base64.b64encode(nonce + enc).decode("ascii")


def unseal_token(blob: str, key_material: bytes) -> str | None:
    """The token, or None when missing or the key changed (then it must be
    saved again)."""
    try:
        raw = base64.b64decode(str(blob or ""), validate=True)
        return _aes(key_material).decrypt(raw[:12], raw[12:], TOKEN_CONTEXT).decode("utf-8")
    except Exception:  # noqa: BLE001 - wrong key / garbage: treat as no token
        return None


def token_fingerprint(token: str | None) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12] if token else ""


# ------------------------------------------------------------ small files


def _write_atomic(path: Path, data: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_json(path: Path, limit: int = 2_000_000) -> dict | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


# ------------------------------------------------------------ GitHub releases


def _trim_release(r: dict) -> dict | None:
    tag = str(r.get("tag_name") or "")
    if r.get("draft") or not TAG_RE.match(tag):
        return None
    version = tag_version(tag)
    assets = {str(a.get("name") or ""): a for a in (r.get("assets") or []) if isinstance(a, dict)}
    src = assets.get(source_asset(version))
    digest = str((src or {}).get("digest") or "")
    return {
        "tag": tag, "version": version, "name": str(r.get("name") or tag)[:200],
        "prerelease": bool(r.get("prerelease")), "published_ts": _iso_ts(r.get("published_at")),
        "body": str(r.get("body") or "")[:MAX_BODY], "url": str(r.get("html_url") or "")[:300],
        "installable": bool(src) and (source_asset(version) + ".sha256") in assets,
        "digest": digest if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) else "",
    }


def _iso_ts(v: Any) -> int:
    from datetime import datetime  # noqa: PLC0415

    try:
        return int(datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp())
    except (TypeError, ValueError):
        return 0


def load_cache(update_dir: Path) -> dict:
    return _read_json(update_dir / CACHE_FILE) or {}


def check_releases(update_dir: Path, repo: str, token: str | None, *, session: Any = None,
                   force: bool = False, now: float | None = None) -> dict:
    """The cached release list, refreshed from GitHub when stale (or force).
    Conditional request with the cached ETag (304 = nothing new, free of the
    rate limit). Returns {"releases", "checked_at", "error", "repo"}; the
    error is a short code (not_configured, not_found, auth, rate_limited,
    network, bad_reply) and the old list is kept when a check fails."""
    now = time.time() if now is None else now
    cache = load_cache(update_dir)
    fp = token_fingerprint(token)
    if cache.get("repo") != repo or cache.get("token_fp") != fp:
        cache = {}  # another repo or token: other answer, other ETag
    out = {"repo": repo, "releases": cache.get("releases") or [], "checked_at": cache.get("checked_at") or 0,
           "error": cache.get("error") or ""}
    if not repo:
        return {**out, "releases": [], "error": "not_configured"}
    if not force and now - float(out["checked_at"] or 0) < CHECK_EVERY:
        return out
    if session is None:
        import requests  # noqa: PLC0415

        session = requests.Session()
        session.trust_env = False  # no proxy from the environment, no ~/.netrc
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
               "User-Agent": USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if cache.get("etag") and out["releases"]:
        headers["If-None-Match"] = str(cache["etag"])
    error, releases, etag = "", out["releases"], cache.get("etag") or ""
    try:
        resp = session.get(f"{API}/repos/{repo}/releases", params={"per_page": MAX_RELEASES},
                           headers=headers, timeout=TIMEOUT, allow_redirects=False)
        code = int(resp.status_code)
        if code == 304:
            pass
        elif code == 200:
            data = resp.json()
            if not isinstance(data, list):
                raise ValueError("not a list")
            releases = [t for t in (_trim_release(r) for r in data if isinstance(r, dict)) if t]
            etag = str(resp.headers.get("ETag") or "")[:200]
        elif code == 404:
            error = "not_found"
        elif code == 401:
            error = "auth"
        elif code in (403, 429):
            error = "rate_limited" if str(resp.headers.get("x-ratelimit-remaining", "")) == "0" or code == 429 else "auth"
        else:
            error = "bad_reply"
    except ValueError:
        error = "bad_reply"
    except Exception as ex:  # noqa: BLE001 - network trouble must not break the page
        log.info("release check failed: %s", type(ex).__name__)
        error = "network"
    new = {"repo": repo, "token_fp": fp, "etag": etag if not error else cache.get("etag") or "",
           "releases": releases, "checked_at": now, "error": error}
    try:
        _write_atomic(update_dir / CACHE_FILE, json.dumps(new), 0o600)
    except OSError as ex:
        log.warning("release cache not written: %s", type(ex).__name__)
    return {"repo": repo, "releases": releases, "checked_at": now, "error": error}


def newer_releases(releases: list[dict], channel: str, current: str) -> list[dict]:
    """Releases in the channel newer than `current`, newest first. Stabil =
    only full releases; Beta = also pre-releases."""
    cur = parse_version(current) or (0, 0, 0)
    out = []
    for r in releases:
        v = parse_version(r.get("version"))
        if v is None or v <= cur:
            continue
        if channel != "beta" and r.get("prerelease"):
            continue
        out.append(r)
    return sorted(out, key=lambda r: parse_version(r["version"]) or (0, 0, 0), reverse=True)


def latest(releases: list[dict], channel: str) -> dict | None:
    pool = [r for r in releases if channel == "beta" or not r.get("prerelease")]
    return max(pool, key=lambda r: parse_version(r.get("version")) or (0, 0, 0), default=None)


# ------------------------------------------------------------ the request


def request_key(update_dir: Path) -> bytes:
    """The HMAC key of requests (made on first use, 0600). The host helper
    reads the same file."""
    path = update_dir / KEY_FILE
    try:
        if not path.is_symlink() and path.is_file():
            key = path.read_text(encoding="ascii").strip()
            if re.fullmatch(r"[0-9a-f]{64}", key):
                return key.encode("ascii")
    except OSError:
        pass
    key = secrets.token_hex(32)
    _write_atomic(path, key + "\n", 0o600)
    return key.encode("ascii")


def clean_actor(name: str) -> str:
    return (ACTOR_RE.sub("_", str(name or "")) or "ukendt")[:64]


def request_message(tag: str, actor: str, ts: int, nonce: str) -> bytes:
    """Exactly what is signed - the host helper builds the same string."""
    return f"v1|{tag}|{actor}|{ts}|{nonce}".encode("ascii")


def sign(key: bytes, tag: str, actor: str, ts: int, nonce: str) -> str:
    return hmac.new(key, request_message(tag, actor, ts, nonce), hashlib.sha256).hexdigest()


def token_message(nonce: str, token: str) -> bytes:
    """What the token hand-over signs - the host builds the same string."""
    return f"tok1|{nonce}|{token}".encode("ascii")


def sign_token(key: bytes, nonce: str, token: str) -> str:
    return hmac.new(key, token_message(nonce, token), hashlib.sha256).hexdigest()


def read_runner(update_dir: Path) -> dict:
    """runner.json from the host helper: {"seen_at", "token_file" (it has
    its own token, which wins), "token_handoff" (it understands
    request.token, 2.11.2 and later)}."""
    raw = _read_json(update_dir / RUNNER_FILE, limit=4096) or {}
    return {"seen_at": _num(raw.get("seen_at")), "token_file": raw.get("token_file") is True,
            "token_handoff": raw.get("token_handoff") is True}


def remove_token_handover(update_dir: Path) -> None:
    try:
        (update_dir / TOKEN_FILE).unlink()
    except FileNotFoundError:
        pass


def verify_request(data: Any, key: bytes, *, now: float | None = None) -> str | None:
    """The tag of a valid request, else None (the same checks as the host)."""
    now = time.time() if now is None else now
    if not isinstance(data, dict) or set(data) != {"v", "tag", "requested_by", "ts", "nonce", "sig"}:
        return None
    tag, actor, ts, nonce, sig = (data.get(k) for k in ("tag", "requested_by", "ts", "nonce", "sig"))
    if data.get("v") != 1 or not isinstance(tag, str) or not TAG_RE.match(tag):
        return None
    if not isinstance(actor, str) or actor != clean_actor(actor) or not isinstance(ts, int) or isinstance(ts, bool):
        return None
    if not isinstance(nonce, str) or not NONCE_RE.match(nonce) or not isinstance(sig, str) or not SIG_RE.match(sig):
        return None
    if abs(now - ts) > REQUEST_MAX_AGE:
        return None
    return tag if hmac.compare_digest(sign(key, tag, actor, ts, nonce), sig) else None


class UpdateRefused(ValueError):
    """Shown to the admin as is (Danish)."""


def write_request(update_dir: Path, tag: str, actor: str, *, releases: list[dict], current: str,
                  now: float | None = None, token: str | None = None) -> dict:
    """Ask the host to install `tag`. Only a published, installable release
    newer than the running version; never while another update waits/runs.
    `token` (the WebUI's GitHub token, only when the helper has none of its
    own) is handed over in request.token, written first and bound to this
    request's nonce."""
    now = int(time.time() if now is None else now)
    if not isinstance(tag, str) or not TAG_RE.match(tag):
        raise UpdateRefused("Ukendt version.")
    rel = next((r for r in releases if r.get("tag") == tag), None)
    if rel is None:
        raise UpdateRefused("Versionen findes ikke blandt udgivelserne på GitHub. Tjek igen.")
    cur = parse_version(current) or (0, 0, 0)
    if (parse_version(tag) or (0, 0, 0)) <= cur:
        raise UpdateRefused("Versionen er ikke nyere end den, der kører.")
    if not rel.get("installable"):
        raise UpdateRefused("Udgivelsen har ingen kildepakke med kontrolsum og kan kun installeres manuelt.")
    st = read_status(update_dir, now=now)
    if st["state"] in ("venter", "koerer"):
        raise UpdateRefused("Der er allerede en opdatering i gang.")
    key = request_key(update_dir)
    actor = clean_actor(actor)
    nonce = secrets.token_hex(16)
    req = {"v": 1, "tag": tag, "requested_by": actor, "ts": now, "nonce": nonce,
           "sig": sign(key, tag, actor, now, nonce)}
    tok = clean_token(token) if token else None
    if tok:
        handover = {"v": 1, "nonce": nonce, "token": tok, "sig": sign_token(key, nonce, tok)}
        _write_atomic(update_dir / TOKEN_FILE, json.dumps(handover, separators=(",", ":")) + "\n", 0o600)
    else:
        remove_token_handover(update_dir)
    try:
        _write_atomic(update_dir / REQUEST_FILE, json.dumps(req, separators=(",", ":")) + "\n", 0o600)
    except BaseException:
        remove_token_handover(update_dir)
        raise
    return req


def cancel_request(update_dir: Path) -> bool:
    """'Annullér' while the request still waits (the host has not taken it)."""
    path = update_dir / REQUEST_FILE
    try:
        remove_token_handover(update_dir)
    except OSError:
        pass
    try:
        if path.is_symlink() or path.is_file():
            path.unlink()
            return True
    except OSError:
        pass
    return False


def _clean_line(s: Any) -> str:
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", str(s))[:300]


def read_status(update_dir: Path, *, now: float | None = None) -> dict:
    """{"state": idle|venter|koerer|faerdig|fejlet, "tag", "message",
    "log": [lines], "started_at", "finished_at", "stale"}."""
    now = time.time() if now is None else now
    raw = _read_json(update_dir / STATUS_FILE, limit=200_000) or {}
    st = {"state": str(raw.get("state") or ""), "tag": str(raw.get("tag") or ""),
          "message": _clean_line(raw.get("message") or ""), "requested_by": clean_actor(raw.get("requested_by") or "")
          if raw.get("requested_by") else "",
          "log": [_clean_line(x) for x in (raw.get("log") or []) if isinstance(raw.get("log"), list)][-60:],
          "started_at": _num(raw.get("started_at")), "finished_at": _num(raw.get("finished_at")), "stale": False,
          "error": str(raw.get("error") or "") if raw.get("error") in STATUS_ERRORS else ""}
    if st["state"] not in STATES:
        st["state"] = "idle"
    if not TAG_RE.match(st["tag"]):
        st["tag"] = ""
    req_path = update_dir / REQUEST_FILE
    if not req_path.is_symlink() and req_path.is_file():
        req = _read_json(req_path, limit=4096) or {}
        tag = str(req.get("tag") or "")
        if TAG_RE.match(tag) and st["state"] != "koerer":
            st.update(state="venter", tag=tag, message="Venter på, at værten henter opdateringen (inden for et minut).",
                      log=[], started_at=_num(req.get("ts")), finished_at=0, error="",
                      requested_by=clean_actor(req.get("requested_by") or ""))
    if st["state"] == "koerer" and st["started_at"] and now - st["started_at"] > STATUS_STALE:
        st["stale"] = True
    return st


def _num(v: Any) -> int:
    try:
        return int(v) if not isinstance(v, bool) else 0
    except (TypeError, ValueError):
        return 0


# ------------------------------------------------------------ release notes


def notes_html(body: str, esc: Any) -> str:
    """Release notes (GitHub markdown) as safe, simple HTML: everything is
    escaped first; then bullets, headings, **bold** and `code`. Links stay
    plain text."""
    out: list[str] = []
    in_list = False

    def inline(s: str) -> str:
        s = esc(s)
        s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
        return re.sub(r"`([^`]+)`", r"<code>\1</code>", s)

    for line in str(body or "").replace("\r\n", "\n").split("\n"):
        s = line.strip()
        m = re.match(r"^[-*]\s+(.*)$", s)
        if m:
            if not in_list:
                out.append('<ul class="notes-list">')
                in_list = True
            out.append(f"<li>{inline(m.group(1))}</li>")
            continue
        if in_list:
            out.append("</ul>")
            in_list = False
        if not s:
            continue
        h = re.match(r"^#{1,6}\s+(.*)$", s)
        out.append(f'<p class="notes-head">{inline(h.group(1))}</p>' if h else f"<p>{inline(s)}</p>")
    if in_list:
        out.append("</ul>")
    return "".join(out)
