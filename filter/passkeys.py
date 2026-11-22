"""Passkeys (WebAuthn) for the WebUI (2.6, B1).

A user can register one or more passkeys (Face ID, fingerprint, the PIN
of a security key) under Min konto and log in with one instead of the
password AND the code: a discoverable credential with user verification
counts as both factors. Verification is webauthn.py (attestation "none",
ES256/RS256); this module owns storage, challenges, routes and the UI.

Where it works (WebAuthn needs a secure context and a domain as RP ID):
the external https address (settings_kv 'external_url', RP ID = its
hostname, origin = that https origin) and http(s)://localhost. On a plain
http LAN address the button is hidden with a short hint; the server
refuses every ceremony there as well (rp_for_request() is None).

Tables (dashboard.UI_SCHEMA, additive - older versions ignore them):
  ui_passkeys             one row per credential: name, cred_id (b64url,
                          UNIQUE), user_handle, rp_id, COSE public key,
                          alg, sign_count, label, flags, created/last used
  ui_passkey_handles      one random 32-byte WebAuthn user.id per user
                          (never the user name)
  ui_webauthn_challenges  sha256 of each outstanding challenge, purpose,
                          user, rp_id + origin, 5 min expiry; taken
                          (deleted) atomically on first use = single use;
                          at most CHALLENGE_MAX rows - when full, the
                          oldest login challenges make room (login
                          options are also limited per IP / IPv6 /64)

Routes (central policy + CSRF via dashboard._before for every POST):
  POST /login/passkey/options   public   challenge for a discoverable login
  POST /login/passkey           public   verify -> full session (mfa)
  GET  /me/passkeys/confirm     login    "Bekræft, at det er dig"
  POST /me/passkeys/confirm     login    password proof (users without 2FA)
  POST /me/passkeys/options     login    registration options (re-auth)
  POST /me/passkeys/register    login    verify + store (re-auth)
  POST /me/passkeys/remove      login    remove one of your own (re-auth)

A passkey login obeys the same rules as a password login: the IP and the
user throttle (5 failures / 15 min), the login scope ('Kun lokalt' from
outside gets the generic error), a fresh session (new CSRF token, the
session generation), "Husk mig", the login history and alerts (B2).
Adding or removing a passkey needs a fresh proof (10 min): a code from
the existing two-step login - or, without 2FA, the password - or a login
with a code/passkey within the last 10 minutes.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import re
import secrets
import sqlite3
import threading
import time
from collections import OrderedDict
from typing import Any
from urllib.parse import urlsplit

from flask import Response, jsonify, redirect, request, session

import dashboard as ui
import ui_kit as kit
import webauthn as wa
from ui_kit import h

log = logging.getLogger("passkeys")
app = ui.app

RP_NAME = "Spamfilter"
MAX_PER_USER = 10
LABEL_MAX = 40
CHALLENGE_TTL = 5 * 60
CHALLENGE_MAX = 500                 # outstanding challenges in total (memory bound, public endpoint)
OPTIONS_PER_IP = 20                 # login challenges per IP bucket (IPv4 address / IPv6 /64) ...
OPTIONS_WINDOW = 5 * 60             # ... per this window
OPTIONS_BUCKETS_MAX = 4096          # IP buckets tracked at once (least recently used dropped first)
TIMEOUT_MS = 120_000
REAUTH_TTL = ui.TWOFA_REAUTH_TTL
CONFIRM_URL = "/me/passkeys/confirm"
TRANSPORTS = ("usb", "nfc", "ble", "internal", "hybrid", "smart-card")
_CTRL_RE = re.compile("[\\x00-\\x1f\\x7f-\\x9f\\u200b-\\u200f\\u202a-\\u202e\\u2066-\\u2069]")

GENERIC_FAIL = "Passkeyen kunne ikke bruges. Prøv igen – eller log ind med adgangskode."
ERRORS = {
    "attestation_format": "Denne nøgle sender en attestation, spamfilteret ikke bruger. Prøv en anden passkey.",
    "user_verified": "Nøglen bekræftede ikke, at det var dig (Face ID, fingeraftryk eller PIN). Prøv igen.",
    "alg": "Denne nøgle bruger en type, spamfilteret ikke understøtter.",
}


# ---------------------------------------------------------------------------
# Where passkeys work
# ---------------------------------------------------------------------------


def rp_for_request() -> tuple[str, str] | None:
    """(rp_id, origin) for THIS request, or None (plain-http LAN address,
    unknown host). Only the configured external https address and
    localhost are relying parties."""
    try:
        host = (urlsplit(f"{request.scheme}://{request.host}").hostname or "").lower()
    except ValueError:
        return None
    ext = ui.external_url()
    if ext.startswith("https://"):
        ep = urlsplit(ext)
        ext_host = (ep.hostname or "").lower()
        if ext_host and host == ext_host:
            return ext_host, "https://" + ui._origin_key("https", ep.netloc)
    if host == "localhost":
        return "localhost", f"{request.scheme}://" + ui._origin_key(request.scheme, request.host)
    return None


def external_host() -> str:
    ext = ui.external_url()
    return (urlsplit(ext).hostname or "") if ext.startswith("https://") else ""


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


def _conn() -> sqlite3.Connection:
    ui._ensure_ui_db()
    return ui._connect()


def user_handle(name: str, *, create: bool = True) -> str | None:
    """The user's WebAuthn user.id (b64url of 32 random bytes)."""
    conn = _conn()
    try:
        row = conn.execute("SELECT handle FROM ui_passkey_handles WHERE name=?", (name,)).fetchone()
        if row is not None or not create:
            return str(row["handle"]) if row else None
        conn.execute("INSERT OR IGNORE INTO ui_passkey_handles(name, handle, created_at) VALUES(?,?,?)",
                     (name, wa.b64url_encode(secrets.token_bytes(32)), int(time.time())))
        conn.commit()
        return str(conn.execute("SELECT handle FROM ui_passkey_handles WHERE name=?", (name,)).fetchone()["handle"])
    finally:
        conn.close()


def list_passkeys(name: str) -> list[dict]:
    """The user's passkeys for display (no keys, no credential ids)."""
    try:
        conn = _conn()
        try:
            rows = conn.execute("SELECT id, label, rp_id, alg, backup_eligible, backed_up, created_at, last_used_at, "
                                "last_used_ip FROM ui_passkeys WHERE name=? ORDER BY created_at, id", (name,)).fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return []
    return [dict(r) for r in rows]


def _cred_ids(name: str, rp_id: str) -> list[str]:
    conn = _conn()
    try:
        return [str(r[0]) for r in conn.execute("SELECT cred_id FROM ui_passkeys WHERE name=? AND rp_id=?",
                                                (name, rp_id)).fetchall()]
    finally:
        conn.close()


def remove_passkey(name: str, pk_id: int) -> dict | None:
    """Delete one of `name`'s passkeys; the removed row (label) or None."""
    conn = _conn()
    try:
        row = conn.execute("SELECT id, label FROM ui_passkeys WHERE id=? AND name=?", (int(pk_id), name)).fetchone()
        if row is None:
            return None
        conn.execute("DELETE FROM ui_passkeys WHERE id=? AND name=?", (int(pk_id), name))
        conn.commit()
        return dict(row)
    finally:
        conn.close()


class _Busy(Exception):
    pass


def ip_bucket(ip: str | None) -> str:
    """Rate-limit bucket for a client address: the IPv4 address (also when
    IPv4-mapped) or the /64 of an IPv6 address - one host easily owns a
    whole /64, so per-address counting would not limit it."""
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return (ip or "unknown")[:64]
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        return str(ipaddress.IPv6Network((addr, 64), strict=False))
    return str(addr)


_OPT_LOCK = threading.Lock()
_OPT_HITS: OrderedDict[str, list[float]] = OrderedDict()


def _options_allowed(bucket: str) -> bool:
    """Rolling per-bucket counter for login challenges (OPTIONS_PER_IP per
    OPTIONS_WINDOW). At most OPTIONS_BUCKETS_MAX buckets are kept, so
    requests from ever new addresses cannot grow memory without bound."""
    now = time.time()
    key = f"{ui.DB_PATH}|{bucket}"  # one state dir = one set of counters (tests, dev)
    with _OPT_LOCK:
        hits = [t for t in _OPT_HITS.pop(key, []) if now - t < OPTIONS_WINDOW]
        ok = len(hits) < OPTIONS_PER_IP
        if ok:
            hits.append(now)
        _OPT_HITS[key] = hits  # most recently used last
        while len(_OPT_HITS) > OPTIONS_BUCKETS_MAX:
            _OPT_HITS.popitem(last=False)
        return ok


def _challenge_new(purpose: str, name: str | None, rp_id: str, origin: str) -> bytes:
    raw = secrets.token_bytes(wa.CHALLENGE_BYTES)
    now = int(time.time())
    conn = _conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM ui_webauthn_challenges WHERE expires_at<?", (now,))
        if name:  # one outstanding registration per user
            conn.execute("DELETE FROM ui_webauthn_challenges WHERE purpose=? AND name=?", (purpose, name))
        n = int(conn.execute("SELECT COUNT(*) FROM ui_webauthn_challenges").fetchone()[0])
        if n >= CHALLENGE_MAX:
            # Full - e.g. one actor asking from many addresses. Make room by
            # dropping the OLDEST unauthenticated login challenges, so a real
            # login (or registration) still gets one instead of everybody
            # being locked out. Registration challenges (one per signed-in
            # user) are never evicted; the table stays at CHALLENGE_MAX rows.
            conn.execute("DELETE FROM ui_webauthn_challenges WHERE rowid IN (SELECT rowid FROM ui_webauthn_challenges "
                         "WHERE purpose='login' AND name IS NULL ORDER BY created_at, rowid LIMIT ?)",
                         (n - CHALLENGE_MAX + 1,))
            n = int(conn.execute("SELECT COUNT(*) FROM ui_webauthn_challenges").fetchone()[0])
        if n >= CHALLENGE_MAX:
            conn.execute("COMMIT")
            raise _Busy()
        conn.execute("INSERT INTO ui_webauthn_challenges(id, purpose, name, rp_id, origin, created_at, expires_at) "
                     "VALUES(?,?,?,?,?,?,?)", (hashlib.sha256(raw).hexdigest(), purpose, name, rp_id, origin, now,
                                               now + CHALLENGE_TTL))
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.close()
    return raw


def _challenge_take(raw: bytes, purpose: str) -> dict | None:
    """Consume a challenge (single use): its row while unexpired, else None."""
    cid = hashlib.sha256(raw).hexdigest()
    conn = _conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM ui_webauthn_challenges WHERE id=? AND purpose=?", (cid, purpose)).fetchone()
        conn.execute("DELETE FROM ui_webauthn_challenges WHERE id=?", (cid,))
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.close()
    if row is None or int(row["expires_at"]) < time.time():
        return None
    return dict(row)


def _session_challenge(key: str) -> bytes | None:
    """Pop this session's challenge for `key` (it is single use either way)."""
    val = session.pop(key, None)
    try:
        return wa.b64url_decode(val, limit=64) if val else None
    except wa.WebAuthnError:
        return None


# ---------------------------------------------------------------------------
# Re-authentication for adding/removing passkeys
# ---------------------------------------------------------------------------


def _fresh(val: Any, name: str) -> bool:
    if not isinstance(val, list) or len(val) != 2 or val[0] != name:
        return False
    try:
        return 0 <= time.time() - int(val[1]) <= REAUTH_TTL
    except (TypeError, ValueError):
        return False


def reauth_ok(name: str) -> bool:
    """A fresh proof in THIS session: a code from the user's two-step login
    (or a code/passkey login) - or, for a user without two-step login, the
    password - within REAUTH_TTL."""
    if _fresh(session.get("reauth_2fa"), name):
        return True
    return not ui.twofa_status(name)["enabled"] and _fresh(session.get("reauth_pw"), name)


def mark_password_proof(name: str) -> None:
    session["reauth_pw"] = [name, int(time.time())]


def _clean_label(text: Any, default: str) -> str:
    s = " ".join(_CTRL_RE.sub("", str(text or "")).split())[:LABEL_MAX]
    return s or default[:LABEL_MAX]


def _json() -> dict:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _b64(data: dict, key: str, limit: int) -> bytes:
    return wa.b64url_decode(data.get(key), limit=limit)


def _bytes_or_none(x: Any, limit: int) -> bytes | None:
    try:
        return wa.b64url_decode(x, limit=limit)
    except wa.WebAuthnError:
        return None


# ---------------------------------------------------------------------------
# Login with a passkey
# ---------------------------------------------------------------------------


@app.post("/login/passkey/options")
@ui.public
def login_passkey_options():
    rp = rp_for_request()
    if rp is None:
        return ui.json_err("Passkeys virker kun via spamfilterets https-adresse.", 404)
    if not _options_allowed(ip_bucket(request.remote_addr)):
        return ui.json_err("For mange forsøg. Vent et par minutter, og prøv igen.", 429)
    try:
        raw = _challenge_new("login", None, *rp)
    except _Busy:
        return ui.json_err("Spamfilteret har travlt. Prøv igen om lidt.", 503)
    session["pk_login"] = wa.b64url_encode(raw)
    return jsonify({"ok": True, "publicKey": {
        "challenge": wa.b64url_encode(raw), "rpId": rp[0], "timeout": TIMEOUT_MS,
        "userVerification": "required", "allowCredentials": []}})


def _login_fail(message: str = GENERIC_FAIL, status: int = 401, **extra: Any):
    return ui.json_err(message, status, **extra)


@app.post("/login/passkey")
@ui.public
def login_passkey():
    """Finish a passkey login: verify -> full session (password + 2FA)."""
    nxt = ui.safe_next(request.args.get("next"))
    if ui.current_user() is not None:
        return jsonify({"ok": True, "redirect": nxt})
    raw_challenge = _session_challenge("pk_login")
    data = _json()
    remember = data.get("remember") in (True, 1, "1", "on", "true")
    ip_key = f"ip:{request.remote_addr or 'unknown'}"
    wait = ui._throttle_begin([ip_key])
    if wait:
        ui.audit("login", result="locked", actor="", detail="passkey")
        return _login_fail(f"For mange forsøg. Prøv igen om {max(1, (wait + 59) // 60)} min.", 429)
    ch = _challenge_take(raw_challenge, "login") if raw_challenge else None
    rp = rp_for_request()
    if ch is None or rp is None or (ch["rp_id"], ch["origin"]) != rp:
        ui.audit("login", result="failed", actor="", detail="passkey · udløbet")
        return _login_fail("Siden var udløbet. Prøv igen.", 400)
    resp = data.get("response") if isinstance(data.get("response"), dict) else {}
    cred_id = data.get("rawId") if isinstance(data.get("rawId"), str) else ""
    if data.get("type") != "public-key" or not cred_id or data.get("id") != cred_id \
            or _bytes_or_none(cred_id, wa.MAX_CRED_ID) is None:
        ui.audit("login", result="failed", actor="", detail="passkey · format")
        ui.login_failed("", "passkey")
        return _login_fail()
    conn = _conn()
    try:
        row = conn.execute("SELECT * FROM ui_passkeys WHERE cred_id=? AND rp_id=?", (cred_id, ch["rp_id"])).fetchone()
    finally:
        conn.close()
    user = ui.load_users().get(str(row["name"])) if row is not None else None
    if row is None or user is None:
        ui.audit("login", result="failed", actor="", detail="passkey · ukendt")
        ui.login_failed("", "passkey")
        return _login_fail("Spamfilteret kender ikke denne passkey (måske er den fjernet). Log ind med adgangskode.",
                           401, code="unknown", credential=cred_id, rp=ch["rp_id"])
    user_keys = ui.login_user_keys(user.name)   # 2.12 (#26): per IP + username (+ all IPs from outside)
    wait = ui._throttle_begin(user_keys)
    if wait:
        ui.audit("login", result="locked", actor=user.name, detail="passkey")
        return _login_fail(f"For mange forsøg. Prøv igen om {max(1, (wait + 59) // 60)} min.", 429)
    if not ui.login_allowed_here(user.name):
        # Same reply as any other failure: no oracle for 'Kun lokalt'.
        ui._blocked_external(user.name, "passkey")
        ui.login_failed(user.name, "passkey")
        return _login_fail()
    try:
        handle = _bytes_or_none(resp.get("userHandle"), 64)
        if handle is None or not hmac.compare_digest(wa.b64url_encode(handle), str(row["user_handle"])):
            raise wa.WebAuthnError("user_handle")
        result = wa.verify_assertion(
            public_key=wa.b64url_decode(row["public_key"]), client_data_json=_b64(resp, "clientDataJSON", 8192),
            authenticator_data=_b64(resp, "authenticatorData", 4096), signature=_b64(resp, "signature", 1024),
            challenge=raw_challenge, origin=ch["origin"], rp_id=ch["rp_id"],
            stored_sign_count=int(row["sign_count"] or 0))
    except wa.WebAuthnError as ex:
        ui.audit("login", result="failed", actor=user.name, detail=f"passkey · {ex.code}")
        ui.login_failed(user.name, "passkey")
        return _login_fail(ERRORS.get(ex.code, GENERIC_FAIL))
    now = int(time.time())
    conn = _conn()
    try:
        n = conn.execute("UPDATE ui_passkeys SET sign_count=?, backed_up=?, last_used_at=?, last_used_ip=? "
                         "WHERE id=? AND sign_count=?",
                         (result.sign_count, 1 if result.backed_up else 0, now, (request.remote_addr or "")[:64],
                          row["id"], row["sign_count"])).rowcount
        conn.commit()
    finally:
        conn.close()
    if n != 1:  # a parallel login with the same counter value: replay
        ui.audit("login", result="failed", actor=user.name, detail="passkey · counter")
        return _login_fail()
    ui._throttle_success([ip_key, *user_keys])
    ui.start_session(user, remember=remember, mfa=True)
    ui._mark_reauth(user.name)
    ui.record_login(user.name, request.remote_addr)
    ui.login_succeeded(user.name, "passkey")
    ui.audit("login", result="ok", actor=user.name, detail="passkey" + (" · husk mig" if remember else ""))
    return jsonify({"ok": True, "redirect": nxt})


def login_section(nxt: str) -> str:
    """'Log ind med passkey' under the login form (passkeys.js), or a short
    hint where passkeys cannot work (plain-http LAN address)."""
    if rp_for_request() is None:
        host = external_host()
        if not host:
            return ""
        return (f'<p class="login-passkey-hint faint small">{kit.icon("key")}<span>Log ind med passkey virker via '
                f"{h(host)}. Her på hjemmenetværket bruger du adgangskoden.</span></p>")
    return (f'<div class="login-passkey" data-passkey-login-box data-next="{h(nxt)}" hidden>'
            '<div class="login-or"><span>eller</span></div>'
            + kit.button("Log ind med passkey", kind="secondary", icon="key", cls="btn-block", size="lg",
                         attrs='type="button" data-passkey-login')
            + '<p class="faint small login-passkey-note">Face ID, fingeraftryk eller skærmlås – uden adgangskode '
              "og kode.</p></div>"
            '<p class="login-passkey-hint faint small" data-passkey-unsupported hidden>'
            f'{kit.icon("key")}<span>Denne browser kan ikke bruge passkeys. Log ind med adgangskode.</span></p>'
            + script_tag())


def script_tag() -> str:
    return f'<script src="{h(ui.static_url("passkeys.js"))}" defer></script>'


# ---------------------------------------------------------------------------
# Min konto: confirm, register, remove
# ---------------------------------------------------------------------------


def _confirm_page(name: str, *, error: str = "", status: int = 200) -> Response:
    tf = ui.twofa_status(name)
    if tf["enabled"]:
        form = kit.post_form(
            "/me/2fa/confirm",
            kit.hidden("method", "reauth") + kit.hidden("next", CONFIRM_URL)
            + kit.form_field(ui._code_label(tf), kit.otp_input("code", id="pk-reauth-code", autofocus=True),
                             error=error)
            + '<div class="form-actions">' + kit.button("Bekræft", kind="primary", icon="shield-check") + "</div>",
            ajax=False, cls="twofa-form")
        sendcode = ui._send_code_form(tf, next_url=CONFIRM_URL)
        if sendcode:
            sendcode = (f'<div class="twofa-sendcode-sect mt-1"><p class="muted small">Få koden på mail:</p>'
                        f"{sendcode}</div>")
        lead = "skal du bekræfte med en kode fra dit to-trins-login"
    else:
        user_hint = (f'<input type="text" name="username" value="{h(name)}" autocomplete="username" '
                     'class="sr-only" tabindex="-1" aria-hidden="true" readonly>')
        form = kit.post_form(
            CONFIRM_URL,
            user_hint + kit.form_field("Din adgangskode", kit.input_(
                "password", "", type="password",
                attrs='id="pk-reauth-pw" autocomplete="current-password" required maxlength="256" autofocus'),
                error=error)
            + '<div class="form-actions">' + kit.button("Bekræft", kind="primary", icon="shield-check") + "</div>",
            ajax=False, cls="twofa-form")
        sendcode = ""
        lead = "skal du skrive din adgangskode"
    card = kit.card(f'<p class="muted mb-1">Før du tilføjer eller fjerner en passkey, {lead}. Så kan ingen, der har '
                    "fået fat i en åben session, give sig selv adgang.</p>" + form + sendcode,
                    title="Bekræft, at det er dig")
    html = kit.render_page("Bekræft, at det er dig", f'<div class="narrow-wrap">{card}</div>', active="me",
                           subtitle="Ændringer af passkeys kræver en bekræftelse.",
                           breadcrumbs=[("Min konto", "/me"), ("Passkeys", None)])
    return Response(html, status=status, mimetype="text/html")


@app.get(CONFIRM_URL)
@ui.login_required
def me_passkeys_confirm_page():
    name = ui._me_name()
    if reauth_ok(name):
        card = kit.card(kit.alert(f"Du har bekræftet, at det er dig. De næste {REAUTH_TTL // 60} minutter kan du "
                                  "tilføje og fjerne passkeys.", "ok")
                        + '<div class="form-actions">'
                        + kit.button("Til passkeys", href="/me#passkeys", kind="primary", icon="arrow-right")
                        + "</div>", title="Bekræftet")
        return Response(kit.render_page("Bekræft, at det er dig", f'<div class="narrow-wrap">{card}</div>',
                                        active="me", breadcrumbs=[("Min konto", "/me"), ("Passkeys", None)]),
                        mimetype="text/html")
    return _confirm_page(name)


@app.post(CONFIRM_URL)
@ui.login_required
def me_passkeys_confirm():
    """Password proof for users WITHOUT two-step login (with 2FA the code
    goes through /me/2fa/confirm method=reauth, which marks reauth_2fa)."""
    name = ui._me_name()
    if ui.twofa_status(name)["enabled"]:
        return _confirm_page(name, error="Bekræft med en kode fra dit to-trins-login.", status=400)
    keys = [f"reauth:{name.lower()}"]
    wait = ui._throttle_begin(keys)
    if wait:
        ui.audit("passkey_reauth", result="locked")
        return _confirm_page(name, error=f"For mange forsøg. Prøv igen om {max(1, (wait + 59) // 60)} min.",
                             status=429)
    u = ui.load_users().get(name)
    if u is None or not ui.verify_password(u.verifier, request.form.get("password") or ""):
        ui.audit("passkey_reauth", result="failed")
        return _confirm_page(name, error="Adgangskoden er forkert.", status=403)
    ui._throttle_reset(keys)
    mark_password_proof(name)
    ui.audit("passkey_reauth")
    return redirect("/me#passkeys")


def _gate(name: str):
    if reauth_ok(name):
        return None
    ui.audit("passkey_reauth", result="required")
    return ui.json_err("Bekræft først, at det er dig.", 403, redirect=CONFIRM_URL)


@app.post("/me/passkeys/options")
@ui.login_required
def me_passkeys_options():
    name = ui._me_name()
    rp = rp_for_request()
    if rp is None:
        return ui.json_err("Passkeys kan kun tilføjes, når spamfilteret er åbnet fra https-adressen.", 400)
    gate = _gate(name)
    if gate is not None:
        return gate
    if len(list_passkeys(name)) >= MAX_PER_USER:
        return ui.json_err(f"Du har allerede {MAX_PER_USER} passkeys. Fjern en af dem først.", 409)
    try:
        raw = _challenge_new("register", name, *rp)
    except _Busy:
        return ui.json_err("Spamfilteret har travlt. Prøv igen om lidt.", 503)
    session["pk_reg"] = wa.b64url_encode(raw)
    return jsonify({"ok": True, "publicKey": {
        "rp": {"id": rp[0], "name": RP_NAME},
        "user": {"id": user_handle(name), "name": name, "displayName": name},
        "challenge": wa.b64url_encode(raw),
        "pubKeyCredParams": [{"type": "public-key", "alg": wa.ALG_ES256},
                             {"type": "public-key", "alg": wa.ALG_RS256}],
        "timeout": TIMEOUT_MS,
        "attestation": "none",
        "authenticatorSelection": {"residentKey": "required", "requireResidentKey": True,
                                   "userVerification": "required"},
        "excludeCredentials": [{"type": "public-key", "id": c} for c in _cred_ids(name, rp[0])]}})


@app.post("/me/passkeys/register")
@ui.login_required
def me_passkeys_register():
    name = ui._me_name()
    raw_challenge = _session_challenge("pk_reg")
    gate = _gate(name)
    if gate is not None:
        return gate
    ch = _challenge_take(raw_challenge, "register") if raw_challenge else None
    rp = rp_for_request()
    if ch is None or rp is None or ch["name"] != name or (ch["rp_id"], ch["origin"]) != rp:
        return ui.json_err("Det tog for lang tid. Prøv igen.", 400)
    data = _json()
    resp = data.get("response") if isinstance(data.get("response"), dict) else {}
    try:
        reg = wa.verify_registration(client_data_json=_b64(resp, "clientDataJSON", 8192),
                                     attestation_object=_b64(resp, "attestationObject", wa.MAX_ATTESTATION),
                                     challenge=raw_challenge, origin=ch["origin"], rp_id=ch["rp_id"])
        cred_id = wa.b64url_encode(reg.credential_id)
        if data.get("type") != "public-key" or data.get("rawId") != cred_id or data.get("id") != cred_id:
            raise wa.WebAuthnError("credential_id")
    except wa.WebAuthnError as ex:
        ui.audit("passkey_add", result="failed", detail=ex.code)
        return ui.json_err(ERRORS.get(ex.code, "Passkeyen kunne ikke gemmes. Prøv igen."), 400)
    import login_alerts  # noqa: PLC0415 - the coarse browser/OS label

    label = _clean_label(data.get("label"), login_alerts.device_label(request.headers.get("User-Agent", "")))
    transports = ",".join(t for t in (resp.get("transports") or []) if isinstance(t, str) and t in TRANSPORTS)[:80]
    conn = _conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        n = conn.execute("SELECT COUNT(*) FROM ui_passkeys WHERE name=?", (name,)).fetchone()[0]
        if int(n) >= MAX_PER_USER:
            conn.execute("ROLLBACK")
            return ui.json_err(f"Du har allerede {MAX_PER_USER} passkeys. Fjern en af dem først.", 409)
        conn.execute("INSERT INTO ui_passkeys(name, cred_id, user_handle, rp_id, public_key, alg, sign_count, label, "
                     "aaguid, transports, backup_eligible, backed_up, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (name, cred_id, user_handle(name), ch["rp_id"], wa.b64url_encode(reg.public_key), reg.alg,
                      reg.sign_count, label, reg.aaguid, transports, 1 if reg.backup_eligible else 0,
                      1 if reg.backed_up else 0, int(time.time())))
        conn.execute("COMMIT")
    except sqlite3.IntegrityError:
        conn.rollback()
        return ui.json_err("Den passkey er allerede gemt.", 409)
    finally:
        conn.close()
    ui.audit("passkey_add", detail=f"{label} · {wa.ALG_NAMES.get(reg.alg, reg.alg)}")
    ui.security_notice(name, "ny passkey",
                       f"En passkey ({label}) er tilføjet til dit login. Med den kan man logge ind uden adgangskode "
                       "og kode.")
    return ui.json_ok(f"Passkeyen “{label}” er gemt. Næste gang kan du logge ind med den.", redirect="/me#passkeys")


@app.post("/me/passkeys/remove")
@ui.login_required
def me_passkeys_remove():
    name = ui._me_name()
    if not reauth_ok(name):
        ui.audit("passkey_reauth", result="required")
        return ui.respond("Bekræft først, at det er dig.", ok=False, status=403, next_url=CONFIRM_URL,
                          redirect=CONFIRM_URL)
    try:
        pk_id = int((request.form.get("id") or "").strip()[:12])
    except ValueError:
        return ui.respond("Ugyldig passkey.", ok=False, next_url="/me")
    gone = remove_passkey(name, pk_id)
    if gone is None:  # not found and not yours look the same
        return ui.respond("Passkeyen findes ikke.", ok=False, status=404, next_url="/me")
    ui.audit("passkey_remove", detail=str(gone["label"]))
    ui.security_notice(name, "passkey fjernet", f"Passkeyen “{gone['label']}” er fjernet fra dit login.")
    return ui.respond(f"Passkeyen “{gone['label']}” er fjernet.", next_url="/me#passkeys",
                      rows={f"passkey:{pk_id}": None})


def passkeys_card(name: str) -> str:
    """Min konto -> Passkeys."""
    items = list_passkeys(name)
    rp = rp_for_request()
    fresh = reauth_ok(name)
    rows = []
    for p in items:
        chips = kit.chip("Synkroniseres", "brand") if p.get("backup_eligible") else ""
        if rp is not None and p.get("rp_id") != rp[0]:
            chips += kit.chip(f"Kun {p.get('rp_id')}", "warn")
        used = (f"brugt {kit.ago(p['last_used_at'])}" if p.get("last_used_at") else "ikke brugt endnu")
        remove = ""
        if fresh:
            remove = kit.post_form("/me/passkeys/remove", kit.hidden("id", p["id"]) + kit.button(
                "Fjern", kind="ghost", size="sm", icon="trash",
                attrs=kit.confirm_attrs("Fjern passkeyen?", "Den kan ikke længere bruges til at logge ind. Slet den "
                                        "også på enheden bagefter.", confirm="Fjern", tone="danger")))
        rows.append(f'<li class="twofa-method" data-row="passkey:{int(p["id"])}">{kit.icon("key", "twofa-method-icon")}'
                    f'<div class="twofa-method-text"><div class="row-tight"><b>{h(p["label"])}</b>{chips}</div>'
                    f'<span>Tilføjet {h(kit.fmt_date(p["created_at"]))} · {h(used)}</span></div>'
                    + (f'<div class="twofa-method-actions">{remove}</div>' if remove else "") + "</li>")
    listing = f'<ul class="twofa-methods">{"".join(rows)}</ul>' if rows else ""
    intro = ('<p class="muted">Log ind med Face ID, fingeraftryk eller telefonens skærmlås i stedet for adgangskode og '
             "kode. En passkey kan ikke phishes, og den virker kun på spamfilterets egen adresse.</p>")
    if rp is None:
        host = external_host()
        where = f"https://{h(host)}" if host else "en https-adresse (Ekstern adresse under Indstillinger)"
        action = (f'<p class="faint small">Passkeys kan kun tilføjes og bruges via {where} – ikke fra den lokale '
                  "adresse på hjemmenetværket.</p>")
    elif len(items) >= MAX_PER_USER:
        action = f'<p class="faint small">Du har {MAX_PER_USER} passkeys – det er det højeste antal.</p>'
    elif not fresh:
        action = ('<div class="form-actions">'
                  + kit.button("Tilføj passkey", href=CONFIRM_URL, kind="secondary", icon="plus")
                  + (kit.button("Administrér", href=CONFIRM_URL, kind="ghost", icon="sliders") if items else "")
                  + "</div><p class=\"faint small\">Du bliver bedt om at bekræfte, at det er dig.</p>")
    else:
        action = ('<div class="passkey-add" data-passkey-add hidden>'
                  + kit.form_field("Navn på passkeyen", kit.input_(
                      "label", "", attrs=f'id="pk-label" maxlength="{LABEL_MAX}" placeholder="fx Annas iPhone" '
                                         'autocomplete="off"'), hint="Så du kan kende den igen.")
                  + '<div class="form-actions">'
                  + kit.button("Tilføj passkey", kind="primary", icon="plus", attrs='type="button" data-passkey-create')
                  + "</div></div>"
                  '<p class="faint small" data-passkey-unsupported hidden>Denne browser kan ikke lave passkeys.</p>'
                  + script_tag())
    # The anchor lets "/me#passkeys" land on this card (kit.card takes no id).
    return kit.card('<span id="passkeys" class="anchor"></span>' + intro + listing + action, title="Passkeys",
                    subtitle="Log ind uden adgangskode.", cls="passkey-card")
