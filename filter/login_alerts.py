"""Login alerts (2.6, B2): new-device logins and repeated failed logins.

New device
    Every browser gets a random device cookie (`sf_device`, 256 bit,
    HttpOnly, SameSite=Strict, Secure over https, 400 days) when the
    login page is shown. A device = sha256(cookie + coarse browser/OS
    label), stored per user in `ui_login_devices` - no fingerprinting
    beyond "Safari på iPhone". After a successful login (password, code
    or passkey) from a device the user has not used before, the user gets
    a security mail (their verified 2FA address) and a push on their own
    devices; the 'Sikkerhed' mail recipients (administrators) get a copy.
    A user's very first device after the update is recorded silently (no
    alert flood on rollout). Every successful login is kept in
    `ui_login_history` (newest 20 per user, 90 days) and shown under
    Min konto next to "Log ud overalt". Links in the mails use only the
    configured external address, never the request's Host header.

Repeated failures
    The login throttle (dashboard.login_attempts) counts every attempt per
    username and per IP. When one of them reaches LOGIN_MAX_FAILURES (5)
    within LOGIN_WINDOW (15 min) the administrators get ONE alert (mail kind
    'security' + push to admins whose devices want 'Problemer med
    filteret'), at most once per hour per username/IP (`ui_login_alerts`)
    and at most ALERTS_PER_HOUR in total. An unknown username is never
    echoed (attacker-chosen text); passwords, codes, tokens and cookies
    are never part of any message, log line or audit record.

Never raises into the login: every hook swallows and logs its errors.
"""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
import sqlite3
import time
from typing import Any

from flask import after_this_request, has_request_context, request

import dashboard as ui
import ui_kit as kit
from ui_kit import h

log = logging.getLogger("login_alerts")

DEVICE_COOKIE = "sf_device"
DEVICE_COOKIE_AGE = 400 * 86400          # browsers cap cookies at 400 days
_DEVICE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
HISTORY_KEEP = 20                        # per user
HISTORY_DAYS = 90
DEVICES_KEEP = 30                        # per user (oldest are forgotten)
ALERT_DEDUP = 3600                       # one failed-login alert per username/IP per hour
ALERTS_PER_HOUR = 10                     # ... and at most this many in total
NEW_DEVICE_PER_HOUR = 5                  # new-device notices per user per hour
_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")

METHOD_TEXT = {"password": "adgangskode", "2fa": "to-trins-login", "recovery": "genoprettelseskode",
               "mail": "kode på mail", "passkey": "passkey", "kontrolrum": "Kontrolrum"}
STEP_TEXT = {"login": "adgangskode", "2fa": "kode efter rigtig adgangskode", "passkey": "passkey"}
STEP_KEYS = {"login": ("user", "ip"), "passkey": ("user", "ip"), "2fa": ("2fa", "2faip")}


# ---------------------------------------------------------------------------
# Device cookie + labels
# ---------------------------------------------------------------------------


def device_label(ua: Any) -> str:
    """'Safari på iPhone', 'Chrome på Windows' - never the full user agent."""
    s = str(ua or "")
    if "iPhone" in s:
        os_name = "iPhone"
    elif "iPad" in s:
        os_name = "iPad"
    elif "Android" in s:
        os_name = "Android"
    elif "Macintosh" in s or "Mac OS X" in s:
        os_name = "Mac"
    elif "Windows" in s:
        os_name = "Windows"
    elif "CrOS" in s:
        os_name = "ChromeOS"
    elif "Linux" in s or "X11" in s:
        os_name = "Linux"
    else:
        os_name = "ukendt enhed"
    if "Edg/" in s or "EdgA/" in s or "EdgiOS/" in s:
        browser = "Edge"
    elif "Firefox/" in s or "FxiOS/" in s:
        browser = "Firefox"
    elif "Chrome/" in s or "CriOS/" in s:
        browser = "Chrome"
    elif "Safari/" in s or "AppleWebKit/" in s:
        browser = "Safari"
    else:
        browser = "Browser"
    return f"{browser} på {os_name}"


def _cookie_value() -> str | None:
    v = request.cookies.get(DEVICE_COOKIE) or ""
    return v if _DEVICE_RE.fullmatch(v) else None


def _set_cookie(resp: Any, value: str) -> Any:
    secure = bool(ui.app.config.get("SESSION_COOKIE_SECURE")) or request.is_secure
    resp.set_cookie(DEVICE_COOKIE, value, max_age=DEVICE_COOKIE_AGE, path="/", secure=secure, httponly=True,
                    samesite="Strict")
    return resp


def with_device_cookie(resp: Any) -> Any:
    """The login page: give this browser its device id if it has none."""
    try:
        if has_request_context() and _cookie_value() is None:
            _set_cookie(resp, secrets.token_urlsafe(32))
    except Exception as ex:  # noqa: BLE001 - the login page always renders
        log.warning("device cookie not set: %s", type(ex).__name__)
    return resp


def _device_key(value: str, label: str) -> str:
    return hashlib.sha256(f"sf-device:{value}:{label}".encode()).hexdigest()[:32]


def current_device_key() -> str | None:
    value = _cookie_value() if has_request_context() else None
    return _device_key(value, device_label(request.headers.get("User-Agent", ""))) if value else None


def request_country() -> str:
    """Cloudflare's CF-IPCountry - only when the request came through a
    trusted proxy (never from a client header)."""
    if not has_request_context() or not request.environ.get("sf.proxied"):
        return ""
    cc = str(request.environ.get("HTTP_CF_IPCOUNTRY") or "").strip().upper()
    return cc if _COUNTRY_RE.fullmatch(cc) and cc not in ("XX", "T1") else ""


def _conn() -> sqlite3.Connection:
    ui._ensure_ui_db()
    return ui._connect()


# ---------------------------------------------------------------------------
# Successful logins
# ---------------------------------------------------------------------------


def on_login(name: str, method: str, *, device: str | None = None, label: str | None = None) -> bool:
    """Record a successful login; alert on a new device. Returns True when
    the device was new (and an alert was due). Never raises. `device` (with
    `label`) is a fixed device id instead of the browser's device cookie -
    2.9.0 Kontrolrum SSO: "kontrolrum:<ip>", so each Kontrolrum is one
    device and only its first login alerts."""
    try:
        return _on_login(name, method, device=device, label=label)
    except Exception as ex:  # noqa: BLE001 - a login must never fail on its alert
        log.warning("login alert failed: %s", type(ex).__name__)
        return False


def _on_login(name: str, method: str, *, device: str | None = None, label: str | None = None) -> bool:
    now = int(time.time())
    if device is not None:
        label = str(label or device)[:60]
        device = _device_key(str(device), label)
    else:
        label = device_label(request.headers.get("User-Agent", ""))
        value = _cookie_value()
        if value is None:
            value = secrets.token_urlsafe(32)

            @after_this_request
            def _give_cookie(resp):  # noqa: ANN001
                return _set_cookie(resp, value)

        device = _device_key(value, label)
    ip = (request.remote_addr or "")[:64]
    country = request_country()
    conn = _conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        known = conn.execute("SELECT 1 FROM ui_login_devices WHERE name=? AND device=?", (name, device)).fetchone()
        others = conn.execute("SELECT COUNT(*) FROM ui_login_devices WHERE name=?", (name,)).fetchone()[0]
        new = known is None
        if new:
            conn.execute("INSERT INTO ui_login_devices(name, device, label, first_at, last_at, last_ip, logins) "
                         "VALUES(?,?,?,?,?,?,1)", (name, device, label, now, now, ip))
            conn.execute("DELETE FROM ui_login_devices WHERE name=? AND device NOT IN (SELECT device FROM "
                         "ui_login_devices WHERE name=? ORDER BY last_at DESC LIMIT ?)", (name, name, DEVICES_KEEP))
        else:
            conn.execute("UPDATE ui_login_devices SET last_at=?, last_ip=?, logins=logins+1, label=? "
                         "WHERE name=? AND device=?", (now, ip, label, name, device))
        alert = new and int(others) > 0
        conn.execute("INSERT INTO ui_login_history(name, at, ip, country, label, method, device, new_device) "
                     "VALUES(?,?,?,?,?,?,?,?)", (name, now, ip, country, label, method, device, 1 if alert else 0))
        conn.execute("DELETE FROM ui_login_history WHERE name=? AND (at<? OR id NOT IN (SELECT id FROM "
                     "ui_login_history WHERE name=? ORDER BY at DESC, id DESC LIMIT ?))",
                     (name, now - HISTORY_DAYS * 86400, name, HISTORY_KEEP))
        conn.execute("COMMIT")
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()
    if alert:
        ui.audit("login_new_device", actor=name, detail=f"{label} · {METHOD_TEXT.get(method, method)}")
        _notify_new_device(name, label, now, ip, country)
    return alert


def _me_link() -> str:
    """Only the configured external address - never this request's Host
    header (the person logging in controls it)."""
    base = ui.external_url()
    return f"{base}/me#logins" if base else ""


def _where(ip: str, country: str) -> str:
    if not ip:
        return ""
    return f"IP {ip}" + (f" ({country})" if country else "")


def new_device_text(label: str, at: int, ip: str, country: str) -> str:
    when = time.strftime("%d.%m.%Y kl. %H:%M", time.localtime(at))
    parts = [label, when] + ([_where(ip, country)] if ip else [])
    return (f"Nyt login på din konto: {', '.join(parts)}. Var det ikke dig? Skift adgangskode og log ud "
            "overalt.")


def _notify_new_device(name: str, label: str, at: int, ip: str, country: str) -> None:
    if not ui._recent_hit(f"newdevice:{name.lower()}", NEW_DEVICE_PER_HOUR, 3600):
        ui.audit("login_new_device_notice", result="skipped", actor=name, detail="for mange på en time")
        return
    text = new_device_text(label, at, ip, country)
    link = _me_link()
    # Mail: the user's own verified address + the 'Sikkerhed' recipients.
    try:
        m = ui.mail()
        if m.is_configured():
            own = ui.twofa_mail_address(name)
            where = f"under Min konto:\n{link}" if link else "under Min konto i spamfilteret."
            if own:
                m.notify("security", "Spamfilter: nyt login på din konto",
                         f"{text}\n\nDine seneste login og knappen “Log ud overalt” finder du {where}",
                         recipients=[own])
            admins = [r for r in m.recipients_for("security") if not own or r.lower() != own.lower()]
            if admins:
                m.notify("security", f"Spamfilter: nyt login for {name}",
                         f"Brugeren {name} er logget ind fra en ny enhed.\n\n{text}\n\nDe seneste login står {where}",
                         recipients=admins)
    except Exception as ex:  # noqa: BLE001
        log.warning("new-device mail not sent: %s", type(ex).__name__)
    # Push: every device the user turned notifications on for.
    try:
        import ui_push  # noqa: PLC0415

        ui_push._push().notify_login(None, name, {"ua": label, "at": at, "ip": ip, "cc": country})
    except Exception as ex:  # noqa: BLE001
        log.warning("new-device push not queued: %s", type(ex).__name__)


# ---------------------------------------------------------------------------
# Failed logins
# ---------------------------------------------------------------------------


def on_failed(username: str, step: str = "login") -> bool:
    """After a failed attempt (wrong password, blocked scope, wrong code,
    bad passkey): alert the administrators once the throttle counter of
    the username or the IP has reached the limit. Never raises."""
    try:
        return _on_failed(str(username or "")[:64], step)
    except Exception as ex:  # noqa: BLE001
        log.warning("failed-login alert failed: %s", type(ex).__name__)
        return False


def _on_failed(username: str, step: str) -> bool:
    ukind, ikind = STEP_KEYS.get(step, STEP_KEYS["login"])
    ip = request.remote_addr or "unknown"
    now = int(time.time())
    keys = []
    if username:
        # 2.12 (#26): the password/passkey lock counts per IP + username.
        tkey = ui.login_user_key(username, ip) if ukind == "user" else f"{ukind}:{username.lower()}"
        keys.append(("user", tkey, f"user:{username.lower()}"))
        if ukind == "user" and not ui.request_is_local():
            # The global per-username counter from outside (many IPs).
            keys.append(("user", ui.login_user_ext_key(username), f"userx:{username.lower()}"))
    keys.append(("ip", f"{ikind}:{ip}", f"ip:{ip}"))
    due: list[tuple[str, int]] = []
    conn = _conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        for what, throttle_key, dedup_key in keys:
            row = conn.execute("SELECT failures, first_at FROM login_attempts WHERE key=?", (throttle_key,)).fetchone()
            if row is None or int(row["failures"] or 0) < ui.login_limit(throttle_key) \
                    or int(row["first_at"] or 0) < now - ui.LOGIN_WINDOW:
                continue
            last = conn.execute("SELECT at FROM ui_login_alerts WHERE key=?", (dedup_key,)).fetchone()
            if last is not None and now - int(last["at"]) < ALERT_DEDUP:
                continue
            conn.execute("INSERT INTO ui_login_alerts(key, at) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET at=excluded.at",
                         (dedup_key, now))
            due.append((what, int(row["failures"])))
        conn.execute("DELETE FROM ui_login_alerts WHERE at<?", (now - 7 * 86400,))
        conn.execute("COMMIT")
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()
    if not due:
        return False
    if not ui._recent_hit("loginfail-alerts", ALERTS_PER_HOUR, 3600):
        ui.audit("login_alert", result="skipped", actor=username, detail="for mange advarsler på en time")
        return False
    known = username in ui.load_users() if username else False
    who_user = (f"brugeren {username}" if known else "et brugernavn, der ikke findes") if username else ""
    parts = []
    n = max(c for _w, c in due)
    for what, _count in due:
        parts.append(who_user if what == "user" else f"IP-adressen {ip}")
    who = " og ".join(p for p in parts if p)
    ui.audit("login_alert", actor=username if known else "", detail=f"{n} fejl · {' + '.join(w for w, _ in due)} · "
                                                                   f"{STEP_TEXT.get(step, step)}")
    _notify_failed(who, n, ip, step, username if known else "")
    return True


def failed_text(who: str, n: int, step: str) -> str:
    mins = ui.LOGIN_WINDOW // 60
    text = (f"{n} forkerte login-forsøg på {mins} minutter for {who}. Login er spærret i {mins} minutter.")
    if step == "2fa":
        text += " Adgangskoden var rigtig – kun koden passede ikke. Adgangskoden kan være kendt af andre."
    return text


def _notify_failed(who: str, n: int, ip: str, step: str, user: str) -> None:
    text = failed_text(who, n, step)
    when = time.strftime("%d.%m.%Y kl. %H:%M", time.localtime())
    try:
        m = ui.mail()
        rcpts = m.recipients_for("security") if m.is_configured() else []
        if rcpts:
            unlock = f"sfctl unlock {user}" if user else f"sfctl unlock --ip {ip}"
            m.notify("security", "Spamfilter: gentagne forkerte login-forsøg",
                     f"{text}\n\nTidspunkt: {when}\nFra IP-adresse: {ip}\nTrin: {STEP_TEXT.get(step, step)}\n\n"
                     "Kender du ikke forsøgene? Bed brugeren om at skifte adgangskode og slå to-trins-login eller "
                     f"en passkey til. Spærringen ophører af sig selv – eller ophæv den med:\n    {unlock}",
                     recipients=rcpts)
    except Exception as ex:  # noqa: BLE001
        log.warning("failed-login mail not sent: %s", type(ex).__name__)
    try:
        import ui_push  # noqa: PLC0415

        ui_push._push().notify_login_failed(None, {"who": who, "n": n, "step": step})
    except Exception as ex:  # noqa: BLE001
        log.warning("failed-login push not queued: %s", type(ex).__name__)


# ---------------------------------------------------------------------------
# Min konto: recent logins + devices
# ---------------------------------------------------------------------------


def recent_logins(name: str, limit: int = 8) -> list[dict]:
    try:
        conn = _conn()
        try:
            rows = conn.execute("SELECT * FROM ui_login_history WHERE name=? ORDER BY at DESC, id DESC LIMIT ?",
                                (name, int(limit))).fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return []
    return [dict(r) for r in rows]


def known_devices(name: str) -> list[dict]:
    try:
        conn = _conn()
        try:
            rows = conn.execute("SELECT * FROM ui_login_devices WHERE name=? ORDER BY last_at DESC", (name,)).fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return []
    return [dict(r) for r in rows]


def logins_html(name: str) -> str:
    """'Seneste login' list for the Logget ind card (no secrets: device
    label, time, IP, method)."""
    rows = recent_logins(name)
    if not rows:
        return ""
    this = current_device_key()
    items = []
    for r in rows:
        chips = ""
        if this and r.get("device") == this:
            chips += kit.chip("Denne enhed", "brand")
        if r.get("new_device"):
            chips += kit.chip("Ny enhed", "warn")
        where = _where(str(r.get("ip") or ""), str(r.get("country") or ""))
        meta = " · ".join(x for x in (kit.fmt_ts(r["at"]), where, METHOD_TEXT.get(str(r.get("method")), "")) if x)
        items.append(f'<li>{kit.icon("smartphone")}<div><b>{h(r.get("label") or "Ukendt enhed")}</b> {chips}'
                     f'<span>{h(meta)}</span></div></li>')
    n_dev = len(known_devices(name))
    return ('<div class="logins" id="logins"><h3 class="push-h">Seneste login</h3>'
            f'<ul class="simple-list login-list">{"".join(items)}</ul>'
            f'<p class="faint small">Kendte enheder: {n_dev}. Får du besked om et login, du ikke kender, så skift '
            "adgangskode og log ud overalt.</p></div>")

