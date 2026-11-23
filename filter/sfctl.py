"""sfctl - nødadgang (break-glass) til spamfilteret fra kommandolinjen.

Kun for den, der har root på værten:

    docker exec -it spamfilter sfctl <kommando>

Der er ingen netværksport og ingen WebUI-rute: kommandoerne kører som
containerens bruger (uid 10099) direkte mod /state og /config og bruger
PRÆCIS de samme funktioner som WebUI'en (dashboard.*, ui_admin.*,
filter.*): brugerfilen skrives atomisk med mode 0600, rettigheder og
to-trins-login ligger i ui_users/ui_twofa/ui_twofa_mail, tilstande skrives med
dashboard.save_config (validering + atomisk skrivning + genindlæsning), og
hver ændring revisionslogges med actor 'cli' og ip 'local'.

Importen starter hverken webserver eller tråde (dashboard.start() og
filter.main() kaldes aldrig). Mail (2.3): smtp-status, smtp-disable og
smtp-test bruger mailer.py; mails, sfctl lægger i udbakken (fx
sikkerhedsbeskeder), sendes af filterets egen afsender-tråd.

Exitkoder: 0 = ok, 1 = fejl/afvist, 2 = forkert brug.
"""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import logging
import os
import re
import secrets
import sqlite3
import stat
import sys
import time
import unicodedata
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

sys.dont_write_bytecode = True  # /app is read-only for the runtime user

import dashboard as ui  # noqa: E402
import filter as engine  # noqa: E402
import mailer  # noqa: E402

log = logging.getLogger("sfctl")

ACTOR = "cli"
AUDIT_IP = "local"
OWNER_UID = 10099
OWNER_GID = 10099
MIN_PASSWORD = 12
MAX_PASSWORD = 256
DEFAULT_STATE_DIR = "/state"
DEFAULT_CONFIG_PATH = "/config/accounts.yml"
PAUSE_KEY = "sfctl_pause:{}"
HEARTBEAT_STALE = 120
EXIT_OK, EXIT_ERR, EXIT_USAGE = 0, 1, 2
# 2.4 all-in-one container (deploy/aio): rspamd, Redis and Unbound run in
# the same container as the filter; root there has no CAP_DAC_OVERRIDE, so
# ownership is fixed on the Unraid host instead.
AIO = os.environ.get("SPAMFILTER_AIO") == "1"
AIO_APPDATA_HOST = os.environ.get("SPAMFILTER_APP_HOST") or "<app-mappen>"   # the app dir on the host
FIX_OWNER = (f"chown -R {OWNER_UID}:{OWNER_GID} {AIO_APPDATA_HOST}/state {AIO_APPDATA_HOST}/config"
             "  (som root på Unraid-værten)" if AIO else
             f"docker exec -u 0 spamfilter chown -R {OWNER_UID}:{OWNER_GID} /state /config")
# Status files the host scripts (root) write world-readable on purpose.
HOST_WRITTEN = frozenset({"backup-status.json", "host-status.json", "offsite-status.json", "restore-drill.json"})


def _owner_ok(name: str, uid: int) -> bool:
    """Files must belong to the filter user; the host status files may be root's."""
    return uid == OWNER_UID or (uid == 0 and name in HOST_WRITTEN)


class CliError(Exception):
    """Afvist/fejlet handling: Dansk tekst, exitkode 1."""


class UsageError(Exception):
    """Forkert brug: Dansk tekst, exitkode 2."""


# ---------------------------------------------------------------------------
# Setup + small helpers
# ---------------------------------------------------------------------------


def configure(state_dir: str | Path | None = None, config_path: str | Path | None = None) -> None:
    """Point dashboard + engine at the same state dir and config."""
    sd = Path(state_dir or os.environ.get("STATE_DIR") or DEFAULT_STATE_DIR)
    cp = Path(config_path or os.environ.get("CONFIG_PATH") or DEFAULT_CONFIG_PATH)
    ui.configure_paths(sd, cp)
    engine.STATE_DIR = sd
    engine.DB_PATH = sd / "spamfilter.db"
    engine.CONFIG_PATH = cp
    engine.HEARTBEAT_PATH = sd / "heartbeat"
    engine.RELOAD_PATH = sd / "reload_requested"
    ui.AUDIT_IP_NO_REQUEST = AUDIT_IP
    ui.mail()  # mailer -> same state dir, DB and audit file
    mailer.AUTO_WORKER = False  # one-shot process: the filter's worker sends what we queue
    try:
        import push  # noqa: PLC0415 - 2.5.0 push notifications

        push.configure_paths(sd, cp, db_path=sd / "spamfilter.db", users_file=sd / "dashboard_users")
        push.AUTO_WORKER = False  # queued pushes are sent by the filter's own worker
    except Exception:  # noqa: BLE001 - push-* commands report it themselves
        pass


def _euid() -> int:
    return os.geteuid()


def _input(prompt: str) -> str:
    return input(prompt)


def _getpass(prompt: str) -> str:
    return getpass.getpass(prompt)


def out(text: str = "") -> None:
    print(text, flush=True)


def err(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_HIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


def clean(value: Any, limit: int = 200) -> str:
    """Printable text only (audit actors/details can be attacker-chosen,
    e.g. a failed login name - never pass terminal escapes through, nor
    invisible/bidi characters such as U+202E that make a line lie)."""
    text = _CTRL_RE.sub("?", str("" if value is None else value))
    return "".join("?" if unicodedata.category(c) in _HIDDEN_CATEGORIES else c for c in text)[:limit]


def fmt_ts(ts: Any) -> str:
    try:
        return datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError, OverflowError):
        return "–"


def fmt_age(seconds: float | int | None) -> str:
    if seconds is None:
        return "ukendt"
    s = max(0, int(seconds))
    if s < 90:
        return f"{s} sek."
    if s < 90 * 60:
        return f"{s // 60} min."
    if s < 48 * 3600:
        return f"{s // 3600} t. {s % 3600 // 60} min."
    return f"{s // 86400} dage"


def confirm(args: argparse.Namespace, question: str) -> None:
    """Interactive yes for destructive actions (skipped with --yes)."""
    if getattr(args, "yes", False):
        return
    out(question)
    try:
        answer = _input("Skriv ja for at fortsætte: ")
    except (EOFError, OSError, KeyboardInterrupt):
        answer = ""
    if answer.strip().lower() not in ("ja", "j", "yes", "y"):
        raise CliError("Afbrudt – intet er ændret. (Brug --yes for at springe spørgsmålet over.)")


def audit(action: str, account: str = "", result: str = "ok", detail: str = "") -> None:
    ui.audit(action, account, result, detail, actor=ACTOR)


def _db() -> sqlite3.Connection:
    ui.init_ui_db()
    return ui._connect()


def _engine_conn() -> sqlite3.Connection:
    return engine._open_conn()


def settings_delete(key: str) -> None:
    conn = _db()
    try:
        conn.execute("DELETE FROM settings_kv WHERE key=?", (key,))
        conn.commit()
    finally:
        conn.close()


def _admin_mod():
    """ui_admin (route module) for its validators/helpers; importing it
    only registers routes on the Flask app, nothing is served."""
    import ui_admin
    return ui_admin


def _file_user(name: str) -> ui.User:
    u = ui.load_users().get(name)
    if u is None:
        raise CliError(f"Ukendt bruger: {name}")
    if u.source != "file":
        raise CliError(f"{name} er sat op med en miljøvariabel (DASHBOARD_USERS/DASHBOARD_USER) og kan ikke "
                       "ændres herfra. Ret containerens miljø i stedet.")
    return u


MOVE_ASIDE = "docker exec spamfilter mv {f} {f}.beskadiget"


def _bad_user_lines(text: str) -> int:
    return sum(1 for line in text.splitlines()
               if line.strip() and not line.strip().startswith("#") and ui.parse_user_line(line.strip()) is None)


def _guard_users_file() -> None:
    """Before any users-file command: a file the filter cannot read or
    decode must never be silently replaced (load_users() would see 0 users
    and the rewrite would wipe everybody) - stop with the exact fix.
    Lines the parser drops (a hand edit gone wrong) would vanish on the
    rewrite: keep a 0600 copy of the old file first."""
    f = Path(ui.USERS_FILE)
    if not f.exists():
        return
    try:
        text = f.read_bytes().decode("utf-8")
    except OSError:
        raise CliError(f"Brugerfilen {f} kan ikke læses af filteret. Ret ejeren først: {FIX_OWNER}") from None
    except UnicodeDecodeError:
        raise CliError(f"Brugerfilen {f} er beskadiget (ikke gyldig tekst). Flyt den til side med\n"
                       f"    {MOVE_ASIDE.format(f=f)}\n"
                       "og opret derefter en ny administrator med: "
                       "docker exec -it spamfilter sfctl create-admin <navn> --generate") from None
    bad = _bad_user_lines(text)
    if not bad:
        return
    backup = f.with_name(f"{f.name}.backup-{time.strftime('%Y%m%d-%H%M%S')}")
    fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    out(f"Bemærk: {bad} linje(r) i brugerfilen kan ikke læses og forsvinder ved denne ændring. "
        f"Den gamle fil er gemt som {backup}.")


def _admins(users: dict) -> int:
    """Admins in exactly this dict (ui.admin_count({}) re-reads the file)."""
    return sum(1 for u in users.values() if u.admin)


def _valid_password(pw: str) -> str | None:
    if len(pw) < MIN_PASSWORD:
        return f"Adgangskoden skal være mindst {MIN_PASSWORD} tegn."
    if len(pw) > MAX_PASSWORD or any(c in pw for c in "\r\n\x00"):
        return "Adgangskoden er for lang eller indeholder ugyldige tegn."
    return None


def generate_password() -> str:
    """24 tegn fra et alfabet uden forvekslelige tegn (0/O, 1/l/I)."""
    alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    raw = "".join(secrets.choice(alphabet) for _ in range(24))
    return "-".join(raw[i:i + 6] for i in range(0, 24, 6))


def ask_password(generate: bool) -> tuple[str, bool]:
    if generate:
        return generate_password(), True
    pw1 = _getpass(f"Ny adgangskode (mindst {MIN_PASSWORD} tegn): ")
    if problem := _valid_password(pw1):
        raise CliError(problem)
    pw2 = _getpass("Gentag adgangskoden: ")
    if pw1 != pw2:
        raise CliError("De to adgangskoder er ikke ens. Intet er ændret.")
    return pw1, False


def show_generated(name: str, password: str) -> None:
    out("")
    out(f"Ny adgangskode til {name} (vises kun denne ene gang – skriv den ned nu):")
    out("")
    out(f"    {password}")
    out("")


def _accounts() -> list:
    """All accounts from accounts.yml; CliError (Danish) if it is broken."""
    try:
        return list(engine.load_account_configs(ui.CONFIG_PATH))
    except FileNotFoundError:
        raise CliError(f"{ui.CONFIG_PATH} blev ikke fundet.") from None
    except ValueError as ex:
        raise CliError(f"accounts.yml kan ikke indlæses: {clean(ex, 300)}") from None


def _status_rows() -> dict[str, dict]:
    try:
        conn = _engine_conn()
    except sqlite3.Error:
        return {}
    try:
        rows = conn.execute("SELECT * FROM account_status").fetchall()
        return {str(r["account"]): {k: r[k] for k in r.keys()} for r in rows}
    except sqlite3.Error:
        return {}
    finally:
        conn.close()


def _lock_rows() -> list[sqlite3.Row]:
    conn = _db()
    try:
        return conn.execute("SELECT * FROM login_attempts").fetchall()
    finally:
        conn.close()


def _locked_keys(now: int | None = None) -> dict[str, int]:
    now = int(time.time()) if now is None else now
    return {str(r["key"]): int(r["locked_until"]) for r in _lock_rows()
            if r["locked_until"] and int(r["locked_until"]) > now}


def _user_keys(name: str) -> list[str]:
    """The throttle keys of one user: 2.12 (#26) also every per-IP lock
    'user:<name>@<ip>' (the old plain 'user:<name>' too, from before) and
    the global per-username lock from outside 'userx:<name>'."""
    low = name.lower()
    try:
        per_ip = sorted(str(r["key"]) for r in _lock_rows() if str(r["key"]).startswith(f"user:{low}@"))
    except Exception:  # noqa: BLE001 - no table yet
        per_ip = []
    return [f"user:{low}", *per_ip, f"userx:{low}", f"2fa:{low}", f"pwchange:{name}"]


def _ip_keys(ip: str) -> list[str]:
    # ha: = failed Home Assistant API calls (2.3.6, B26)
    return [f"ip:{ip}", f"2faip:{ip}", f"ha:{ip}"]


def _fix_ownership() -> None:
    """--allow-root: files we (root) created/replaced go back to 10099."""
    if _euid() != 0:
        return
    paths = [ui.STATE_DIR, ui.CONFIG_PATH]
    try:
        paths += [p for p in Path(ui.STATE_DIR).iterdir() if p.is_file()]
    except OSError:
        pass
    for p in paths:
        try:
            st = os.lstat(p)
            if st.st_uid == 0 and not stat.S_ISLNK(st.st_mode):
                # lchown: a symlink swapped in after the lstat (by a
                # compromised uid-10099 process) must not hand a root file
                # such as /app/*.py or /usr/local/bin/sfctl to 10099.
                os.chown(p, OWNER_UID, OWNER_GID, follow_symlinks=False)
        except OSError:
            continue


def _root_symlinks() -> list[str]:
    """--allow-root: files root would write through. /state belongs to the
    (less trusted) runtime user, so a symlink there could make root append
    to or create a file anywhere in the container. Refuse instead."""
    paths = [ui.STATE_DIR, ui.USERS_FILE, ui.AUDIT_FILE, ui.DB_PATH, ui.RELOAD_FILE, ui.SECRET_PATH,
             ui.CONFIG_PATH, Path(ui.CONFIG_PATH).parent]
    paths += [Path(f"{ui.DB_PATH}{s}") for s in ("-wal", "-shm", "-journal")]
    return [str(p) for p in paths if Path(p).is_symlink()]


# ---------------------------------------------------------------------------
# Read-only commands
# ---------------------------------------------------------------------------


def heartbeat_age() -> int | None:
    try:
        ts = int((Path(ui.STATE_DIR) / "heartbeat").read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return None
    return int(time.time()) - ts


def cmd_status(args: argparse.Namespace) -> int:
    out(f"Spamfilter {engine.VERSION}")
    out(f"  Tilstandsmappe: {ui.STATE_DIR}")
    out(f"  Konfiguration:  {ui.CONFIG_PATH}")
    age = heartbeat_age()
    hb = "mangler (filteret kører ikke, eller starter op)" if age is None else (
        f"{fmt_age(age)} siden" + ("" if age <= HEARTBEAT_STALE else "  << GAMMEL – filteret hænger måske"))
    out(f"  Hjerteslag:     {hb}")
    out("")
    out("Konti:")
    try:
        accs = _accounts()
    except CliError as ex:
        accs = []
        out(f"  FEJL: {ex}")
    # Read-only: never create the database from here (the filter owns it),
    # and a broken one must not hide the rest of the overview.
    db_ok = Path(ui.DB_PATH).exists()
    status = _status_rows() if db_ok else {}
    snap: dict = {}
    if db_ok:
        try:
            conn = _engine_conn()
            try:
                snap = engine.health_snapshot(conn).get("details", {})
            finally:
                conn.close()
        except Exception as ex:  # noqa: BLE001 - old/broken DB: still show the rest
            log.debug("health_snapshot failed: %s", type(ex).__name__)
    paused = set(_paused_accounts()) if db_ok else set()
    labels = ui.account_display_names()
    if not accs and status.get("*", {}).get("state") == "config_error":
        out("  Filteret melder konfigurationsfejl.")
    for a in accs:
        st = status.get(a.name, {})
        det = snap.get(a.name, {})
        state = "på pause (slået fra)" if not a.enabled else (det.get("state") or st.get("state") or "starter")
        label = labels.get(a.name)
        out(f"  {a.name}" + (f" ({clean(label)})" if label else ""))
        out(f"    adresse:   {clean(a.user)}")
        out(f"    aktiv:     {'ja' if a.enabled else 'nej'}")
        out(f"    tilstand:  {ui.kit.mode_label(a.mode)} ({a.mode})" + (
            "  – sat på pause med sfctl" if a.name in paused else ""))
        out(f"    grænse:    {a.threshold:g}")
        out(f"    status:    {ui.kit.state_label(state)} ({state})")
        if st.get("detail"):
            out(f"    detalje:   {clean(st.get('detail'))}")
        if st.get("last_error"):
            out(f"    sidste fejl: {clean(st.get('last_error'))} ({fmt_ts(st.get('last_error_at'))})")
        circ = det.get("circuit") or "closed"
        out("    flytning:  " + ("STOPPET af sikkerhedsbremsen – " + clean(det.get("circuit_reason") or "")
                                 + f"  (genoptag: sfctl resume-moves {a.name})" if circ == "open" else "kører"))
    out("")
    if not db_ok:
        out(f"Databasen {ui.DB_PATH} findes ikke (filteret har ikke kørt endnu). Kør sfctl doctor.")
    try:
        users = ui.load_users()
    except ValueError:  # UnicodeDecodeError: damaged users file
        users = None
        out("Brugere: brugerfilen er beskadiget – kør sfctl doctor.")
    try:
        if users is not None:
            tf = ui.all_twofa_status() if db_ok else {}
            out(f"Brugere: {len(users)} ({_admins(users)} administrator(er)), "
                f"to-trins-login slået til for {sum(1 for n in users if tf.get(n, {}).get('enabled'))}")
        locked = _locked_keys() if db_ok else {}
        if locked:
            out(f"Spærrede logins: {len(locked)} (se sfctl users / sfctl unlock)")
        ext = ui.settings_get("external_url") if db_ok else None
    except sqlite3.Error as ex:
        out(f"Databasen kan ikke læses ({type(ex).__name__}) – kør sfctl doctor.")
        ext = None
    ui.configure_proxies()
    out(f"Betroede proxyer: {ui.TRUSTED_PROXIES_SPEC or '(ingen)'}")
    out(f"Ekstern adresse:  {ext or '(ingen)'}")
    return EXIT_OK


def cmd_users(args: argparse.Namespace) -> int:
    users = ui.load_users()
    if not users:
        out("Der er ingen brugere. Opret en administrator med: sfctl create-admin <navn> --generate")
        return EXIT_OK
    meta = ui.all_user_meta()
    tf = ui.all_twofa_status()
    scopes = ui.all_login_scopes()
    locked = _locked_keys()
    for name in sorted(users, key=str.lower):
        u = users[name]
        m = meta.get(name) or {"perms": frozenset(ui.PERMISSIONS), "last_login_at": None, "last_login_ip": None}
        t = tf.get(name, {})
        role = "Administrator" if u.admin else "Bruger"
        out(clean(name, 64) + ("  (miljøvariabel, kan ikke ændres her)" if u.source != "file" else ""))
        out(f"  rolle:       {role}")
        out("  postkasser:  " + ("alle" if u.admin else (clean(", ".join(sorted(u.accounts))) or "ingen")))
        out("  rettigheder: " + ("alle" if u.admin else (
            ", ".join(ui.PERMISSION_TEXT[p][0] for p in ui.PERMISSIONS if p in m["perms"]) or "kun se fanget spam")))
        methods = [w for k, w in (("totp", "app"), ("mail", "kode på mail " + str(t.get("mail_masked") or "")))
                   if t.get(k)]
        twofa = ("slået til (" + ", ".join(m.strip() for m in methods) + ")") if t.get("enabled") else "slået fra"
        if t.get("required"):
            twofa += ", påkrævet"
        out(f"  2-trin:      {twofa}")
        out("  login:       " + ("kun lokalt (hjemmenetværket)" if scopes.get(name) == "local" else "overalt"))
        last = (f"{fmt_ts(m['last_login_at'])} fra {clean(m.get('last_login_ip') or '?', 64)}"
                if m.get("last_login_at") else "aldrig (eller før 2.1)")
        out(f"  sidst inde:  {last}")
        mine = [k for k in _user_keys(name) if k in locked]
        if mine:
            until = max(locked[k] for k in mine)
            out(f"  SPÆRRET til {fmt_ts(until)}  (sfctl unlock {clean(name, 64)})")
        else:
            out("  spærret:     nej")
    if ui.admins_all_local(users, scopes):
        out("")
        out("Bemærk: alle administratorer må kun logge ind lokalt – ingen kan administrere filteret udefra.")
    ips = sorted({k.split(":", 1)[1] for k in locked if k.startswith(("ip:", "2faip:", "ha:"))})
    if ips:
        out("")
        out("Spærrede IP-adresser: " + ", ".join(clean(i, 64) for i in ips) + "  (sfctl unlock --ip <IP>)")
    return EXIT_OK


def cmd_audit(args: argparse.Namespace) -> int:
    n = args.tail
    if n < 1 or n > 10000:
        raise UsageError("--tail skal være mellem 1 og 10000.")
    records = _admin_mod().read_audit()[:n]
    if not records:
        out("Revisionsloggen er tom.")
        return EXIT_OK
    for r in reversed(records):
        parts = [fmt_ts(r.get("ts")), clean(r.get("actor") or "-", 64), clean(r.get("ip") or "-", 64),
                 clean(r.get("action"), 64), clean(r.get("result"), 32)]
        if r.get("account"):
            parts.append(f"konto={clean(r.get('account'), 64)}")
        line = "  ".join(parts)
        if r.get("detail"):
            line += f"  – {clean(r.get('detail'), 300)}"
        out(line)
    return EXIT_OK


# ---------------------------------------------------------------------------
# Users, passwords, sessions, 2FA, throttles
# ---------------------------------------------------------------------------


def cmd_reset_password(args: argparse.Namespace) -> int:
    name = args.user
    _guard_users_file()
    _file_user(name)
    password, generated = ask_password(args.generate)
    with ui._USERS_LOCK:
        users = ui.load_users()
        u = users.get(name)
        if u is None or u.source != "file":
            raise CliError(f"Ukendt bruger: {name}")
        users[name] = replace(u, verifier=ui.hash_password(password), gen=u.gen + 1)
        ui.write_users(users.values())
    ui._throttle_reset(_user_keys(name))
    audit("user_password", detail=f"{name} (sfctl{', genereret' if generated else ''})")
    # A reset is for a lost or leaked login: a passkey would still let the
    # old holder in without the new password.
    n_pk = ui.remove_all_passkeys(name)
    if n_pk:
        audit("passkey_reset", detail=f"{name} ({n_pk})")
    if generated:
        show_generated(name, password)
    out(f"Adgangskoden for {name} er skiftet. {name} er logget ud på alle enheder, og spærringen af "
        "brugernavnet er ophævet.")
    if n_pk:
        out(f"{n_pk} passkey(s) for {name} er fjernet. Slet dem også på enhederne (de virker ikke længere).")
    ui.security_notice(name, "ny adgangskode" + (" og passkeys fjernet" if n_pk else ""),
                       "Adgangskoden er skiftet fra serverens nødadgang (sfctl)."
                       + (" " + ui.passkeys_removed_text(n_pk) if n_pk else ""))
    if ui.twofa_status(name)["enabled"]:
        out(f"To-trins-login er stadig slået til. Er telefonen eller mailen også væk: sfctl disable-2fa {name}")
    return EXIT_OK


def cmd_disable_2fa(args: argparse.Namespace) -> int:
    name = args.user
    if name not in ui.load_users():
        raise CliError(f"Ukendt bruger: {name}")
    st = ui.twofa_status(name)
    clear_required = st["required"] and not args.keep_required
    if not st["enabled"] and not clear_required:
        out(f"{name} har ikke to-trins-login slået til." + (
            " Det er stadig påkrævet, så det skal sættes op ved næste login." if st["required"] else ""))
        return EXIT_OK
    what = []
    if st["enabled"]:
        methods = " og ".join(w for k, w in (("totp", "appen"), ("mail", "kode på mail")) if st.get(k))
        what.append(f"slår to-trins-login fra ({methods}) og sletter hemmeligheden, mailadressen og "
                    "genoprettelseskoderne")
    if clear_required:
        what.append("fjerner kravet om to-trins-login")
    confirm(args, f"Dette {' og '.join(what)} for {name}.")
    old_addr = ui.twofa_mail_address(name)
    if st["enabled"]:
        ui.twofa_disable(name, ACTOR)  # BOTH methods (app + mail) and the recovery codes
    if clear_required:
        ui.twofa_set_required(name, False, ACTOR)
    detail = name + (" krav fjernet" if clear_required else (" krav bevaret" if st["required"] else ""))
    audit("twofa_reset", detail=detail.strip())
    if st["enabled"]:
        ui.security_notice(name, "to-trins-login er nulstillet",
                           "To-trins-login er nulstillet fra serverens nødadgang (sfctl).", also=[old_addr])
    msg = f"To-trins-login for {name} er slået fra (både app og kode på mail); {name} kan logge ind med adgangskoden."
    if st["required"] and not clear_required:
        msg += " Kravet er bevaret, så to-trins-login skal sættes op igen ved næste login."
    out(msg)
    return EXIT_OK


def cmd_unlock(args: argparse.Namespace) -> int:
    if not (args.user or args.ip or args.all):
        raise UsageError("Angiv en bruger, --ip IP eller --all.")
    if args.all and (args.user or args.ip):
        raise UsageError("--all kan ikke kombineres med en bruger eller --ip.")
    existing = {str(r["key"]) for r in _lock_rows()}
    if args.all:
        conn = _db()
        try:
            n = conn.execute("DELETE FROM login_attempts").rowcount
            conn.commit()
        finally:
            conn.close()
        audit("login_unlock", detail=f"alle ({n})")
        out(f"Alle login-spærringer er ophævet ({n} registreringer slettet).")
        return EXIT_OK
    keys: list[str] = []
    what: list[str] = []
    if args.user:
        keys += _user_keys(args.user)
        what.append(f"bruger {args.user}")
    if args.ip:
        ip = args.ip.strip()
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            if ip != "unknown":
                raise UsageError(f"Ugyldig IP-adresse: {clean(ip, 64)}") from None
        keys += _ip_keys(ip)
        what.append(f"IP {ip}")
    hit = [k for k in keys if k in existing]
    ui._throttle_reset(keys)
    audit("login_unlock", detail=", ".join(what) + f" ({len(hit)})")
    if hit:
        out(f"Login-spærringen for {' og '.join(what)} er ophævet.")
    else:
        out(f"Der var ingen spærring for {' og '.join(what)}.")
    return EXIT_OK


def cmd_logout_all(args: argparse.Namespace) -> int:
    _guard_users_file()
    if args.user:
        _file_user(args.user)
        ui.bump_generation(args.user)
        audit("user_logout_all", detail=args.user)
        out(f"{args.user} er logget ud på alle enheder.")
        if n_pk := len(_passkey_rows(args.user)):
            out(f"{args.user} har stadig {n_pk} passkey(s), der kan logge ind. Fjern dem (fx mistet telefon): "
                f"sfctl passkeys-reset {args.user}")
        return EXIT_OK
    users = [u for u in ui.load_users().values() if u.source == "file"]
    if not users:
        raise CliError("Der er ingen brugere i brugerfilen.")
    confirm(args, f"Dette logger ALLE {len(users)} brugere ud på alle enheder.")
    with ui._USERS_LOCK:
        current = ui.load_users()
        bumped = {n: replace(u, gen=u.gen + 1) if u.source == "file" else u for n, u in current.items()}
        ui.write_users(bumped.values())
    audit("user_logout_all", detail="alle (sfctl)")
    skipped = [n for n, u in current.items() if u.source != "file"]
    out(f"Alle {len(users)} brugere er logget ud på alle enheder.")
    if skipped:
        out("Brugere fra miljøvariabler kan ikke logges ud herfra: " + ", ".join(skipped))
    return EXIT_OK


def cmd_create_admin(args: argparse.Namespace) -> int:
    _guard_users_file()
    name = args.name.strip()
    adm = _admin_mod()
    if not adm.USER_NAME_RE.fullmatch(name) or name.lower() in adm.RESERVED_USER_NAMES:
        raise CliError("Brugernavnet må kun indeholde bogstaver, tal, punktum, - og _ (1-64 tegn), og ikke være "
                       "“new”.")
    if name in ui.load_users():
        raise CliError(f"Brugeren {name} findes allerede. Brug sfctl reset-password eller sfctl set-role.")
    password, generated = ask_password(args.generate)
    with ui._USERS_LOCK:
        users = ui.load_users()
        if name in users:
            raise CliError(f"Brugeren {name} findes allerede.")
        # Same order as the UI: limits first, then the user line. Never
        # generation 0 (an old cookie of a removed namesake must not revive).
        ui.set_user_perms(name, ui.PERMISSIONS, ACTOR)
        users[name] = ui.User(name, ui.hash_password(password), True, frozenset(), int(time.time()), "file")
        ui.write_users(users.values())
    audit("user_add", detail=f"{name} admin (sfctl)")
    if generated:
        show_generated(name, password)
    out(f"Administratoren {name} er oprettet. Log ind i WebUI'en og slå to-trins-login til under Min konto.")
    return EXIT_OK


LOGIN_SCOPE_ARGS = {"overalt": "everywhere", "lokalt": "local"}


def cmd_login_scope(args: argparse.Namespace) -> int:
    """Where a user may log in: overalt | lokalt (only the home network;
    never through Cloudflare Tunnel or another proxy)."""
    name = args.user
    if name not in ui.load_users():
        raise CliError(f"Ukendt bruger: {name}")
    scope = LOGIN_SCOPE_ARGS[args.scope]
    if not ui.set_login_scope(name, scope, ACTOR):
        out(f"{name} må allerede logge ind {args.scope}.")
        return EXIT_OK
    audit("user_login_scope", detail=f"{name} {scope} (sfctl)")
    if scope == "local":
        out(f"{name} må nu kun logge ind fra hjemmenetværket. Sessioner udefra (også “Husk mig”) er logget ud "
            "ved næste klik.")
    else:
        out(f"{name} må nu logge ind overalt – også udefra via Cloudflare Tunnel.")
    if ui.admins_all_local():
        out("Bemærk: alle administratorer må nu kun logge ind lokalt – ingen kan administrere filteret udefra.")
    return EXIT_OK


def cmd_set_role(args: argparse.Namespace) -> int:
    _guard_users_file()
    name, role = args.user, args.role
    adm = _admin_mod()
    with ui._USERS_LOCK:
        u = _file_user(name)
        make_admin = role == "admin"
        if u.admin == make_admin:
            out(f"{name} er allerede {'Administrator' if make_admin else 'Bruger'}.")
            return EXIT_OK
        users = ui.load_users()
        new = replace(u, admin=make_admin, accounts=frozenset())
        users[name] = new
        if _admins(users) < 1:
            raise CliError(f"{name} er den sidste administrator og kan ikke gøres til Bruger. "
                           "Opret først en anden administrator (sfctl create-admin <navn>).")
        if not make_admin:
            confirm(args, f"{name} mister administratoradgangen og bliver Bruger uden postkasser.")
            perms = ui.user_perms(name)
        else:
            perms = frozenset(ui.PERMISSIONS)
        ui.set_user_perms(name, perms, ACTOR)
        ui.write_users(users.values())
    audit("user_access", detail=f"{name} {adm._access_audit(make_admin, frozenset(), perms)} (sfctl)")
    if make_admin:
        out(f"{name} er nu Administrator.")
    else:
        out(f"{name} er nu Bruger uden postkasser. Vælg postkasser under Brugere i WebUI'en.")
    return EXIT_OK


# ---------------------------------------------------------------------------
# Accounts: pause / resume / resume-moves / external-url / reload
# ---------------------------------------------------------------------------


def _save_modes(changes: dict[str, str | None], detail: str, account: str = "") -> None:
    """Write mode per account through dashboard.save_config (validation,
    atomic replace, reload flag, audit). None = remove the account's own
    `mode` key (it then inherits defaults.mode again)."""
    adm = _admin_mod()

    def mutate(raw: dict) -> None:
        for name, mode in changes.items():
            entry = adm._entry(raw, name)
            if mode is None:
                entry.pop("mode", None)
            else:
                entry["mode"] = mode

    try:
        ui.save_config(mutate, ACTOR, "account_mode", account=account, detail=detail)
    except adm.UserError as ex:
        raise CliError(str(ex)) from None
    except ValueError as ex:
        raise CliError(f"Ændringen blev afvist: {clean(ex, 220)}") from None
    except (OSError, sqlite3.Error) as ex:
        raise CliError(f"Konfigurationen kunne ikke gemmes ({type(ex).__name__}).") from None


def _targets(args: argparse.Namespace, accs: list) -> list:
    if args.all and args.account:
        raise UsageError("Angiv enten en konto eller --all.")
    if not args.all and not args.account:
        raise UsageError("Angiv en konto eller --all.")
    if args.all:
        return accs
    acc = next((a for a in accs if a.name == args.account), None)
    if acc is None:
        raise CliError(f"Ukendt konto: {args.account}")
    return [acc]


def _raw_entry(raw: dict, name: str) -> dict:
    return next((a for a in raw.get("accounts") or [] if isinstance(a, dict) and str(a.get("name")) == name), {})


def cmd_pause(args: argparse.Namespace) -> int:
    accs = _accounts()
    targets = _targets(args, accs)
    raw = ui.load_raw_config()
    plan: dict[str, dict] = {}
    for a in targets:
        if a.mode == "shadow":
            out(f"{a.name} kører allerede i Overvåg – springes over.")
            continue
        entry = _raw_entry(raw, a.name)
        plan[a.name] = {"mode": a.mode, "explicit": "mode" in entry, "at": int(time.time())}
    if not plan:
        out("Intet at sætte på pause.")
        return EXIT_OK
    if args.all:
        confirm(args, "Nødstop: " + ", ".join(f"{n} ({ui.kit.mode_label(p['mode'])})" for n, p in plan.items())
                + " skifter til Overvåg. Filteret rører ikke post, før du kører sfctl resume.")
    # Remember first (so resume always works). Every planned account runs a
    # real mode now, so that mode is the truth: an older memory (paused,
    # then switched in the WebUI, then paused again) is replaced - resume
    # must never bring back a stale, possibly stricter mode.
    previous: dict[str, str | None] = {}
    for name, p in plan.items():
        key = PAUSE_KEY.format(name)
        previous[name] = ui.settings_get(key)
        ui.settings_set(key, json.dumps(p, sort_keys=True))
    detail = "sfctl pause: " + ", ".join(f"{n} {p['mode']}->shadow" for n, p in plan.items())
    try:
        _save_modes({n: "shadow" for n in plan}, detail, account=next(iter(plan)) if len(plan) == 1 else "")
    except CliError:
        # Undo the memory only where the config did NOT change (save_config
        # can fail after accounts.yml was replaced, e.g. a locked DB).
        now = {a.name: a.mode for a in _accounts_or_empty()}
        for name, old in previous.items():
            if now.get(name) == "shadow":
                continue
            if old is None:
                settings_delete(PAUSE_KEY.format(name))
            else:
                ui.settings_set(PAUSE_KEY.format(name), old)
        raise
    for name, p in plan.items():
        out(f"{name}: {ui.kit.mode_label(p['mode'])} -> Overvåg")
    out("Filteret genindlæser konfigurationen. Genoptag med: sfctl resume "
        + ("--all" if args.all else next(iter(plan))))
    return EXIT_OK


def _default_mode(raw: dict) -> str | None:
    """Mode an account inherits without its own `mode` key (engine merge:
    built-ins, defaults, env overrides)."""
    try:
        defaults = raw.get("defaults") if isinstance(raw.get("defaults"), dict) else {}
        merged = engine._apply_env_overrides(engine._deep_merge(engine.BUILTIN_DEFAULTS, defaults or {}))
        return str(merged.get("mode"))
    except Exception:  # noqa: BLE001 - unknown: keep the explicit key
        return None


def _move_blocker(acc: Any) -> str | None:
    """Same safety rules as the UI's switch to Filtrér."""
    if not getattr(acc, "junk_explicit", False):
        return "Spamfilter-mappen er ikke valgt for kontoen"
    if (_status_rows().get(acc.name) or {}).get("move_method") == "none":
        return "mailserveren kan ikke flytte beskeder sikkert"
    if ui.settings_get(f"golive:{acc.name}") is None:
        return "kontoen har aldrig været i Filtrér – brug tjeklisten i WebUI'en"
    return None


def cmd_resume(args: argparse.Namespace) -> int:
    accs = _accounts()
    if args.mode and args.all:
        raise UsageError("--mode kan kun bruges med én konto.")
    targets = _targets(args, accs)
    raw = ui.load_raw_config()
    changes: dict[str, str | None] = {}
    targets_done: dict[str, str] = {}
    report: list[str] = []
    forget: list[str] = []
    problems = 0
    for a in targets:
        key = PAUSE_KEY.format(a.name)
        stored = ui.settings_get(key)
        memo: dict | None = None
        if stored:
            try:
                memo = json.loads(stored)
                if not isinstance(memo, dict) or memo.get("mode") not in ("flag", "move"):
                    memo = None
            except ValueError:
                memo = None
        if memo is None and not args.mode:
            if args.all:
                continue
            raise CliError(f"Der er ingen husket tilstand for {a.name}. Brug sfctl resume {a.name} --mode move|flag.")
        if a.mode != "shadow":
            out(f"{a.name} kører allerede i {ui.kit.mode_label(a.mode)} (ændret i mellemtiden) – røres ikke.")
            if memo:
                forget.append(key)
            continue
        if args.mode:
            target, explicit = args.mode, True
        else:
            target, explicit = memo["mode"], bool(memo.get("explicit", True))
        if target == "move" and (memo or {}).get("mode") != "move":
            if blocker := _move_blocker(a):
                err(f"{a.name}: kan ikke skifte til Filtrér: {blocker}.")
                problems += 1
                continue
        # The mode was inherited from `defaults` before the pause: drop the
        # account's own key again, if the defaults still give that mode.
        changes[a.name] = None if (not explicit and _default_mode(raw) == target) else target
        targets_done[a.name] = target
        report.append(f"{a.name}: Overvåg -> {ui.kit.mode_label(target)}")
        if memo:
            forget.append(key)
    if changes:
        detail = "sfctl resume: " + ", ".join(f"{n} shadow->{t}" for n, t in targets_done.items())
        _save_modes(changes, detail, account=next(iter(changes)) if len(changes) == 1 else "")
    for key in forget:
        settings_delete(key)
    for line in report:
        out(line)
    if not changes and not problems:
        out("Der var intet at genoptage.")
    elif changes:
        out("Filteret genindlæser konfigurationen.")
    return EXIT_ERR if problems else EXIT_OK


def cmd_resume_moves(args: argparse.Namespace) -> int:
    name = args.account
    known = {a.name for a in _accounts_or_empty()} | set(_status_rows())
    if name not in known:
        raise CliError(f"Ukendt konto: {name}")
    conn = _engine_conn()
    try:
        ok = bool(engine.resume_moves(conn, name, ACTOR))
    except sqlite3.Error as ex:
        raise CliError(f"Flytningen kunne ikke genoptages ({type(ex).__name__}).") from None
    finally:
        conn.close()
    audit("account_resume_moves", name, "ok" if ok else "noop")
    out(f"Flytning er genoptaget for {name}; ventende flytninger kører nu." if ok
        else f"Flytning var ikke stoppet af sikkerhedsbremsen for {name}.")
    return EXIT_OK


def _accounts_or_empty() -> list:
    try:
        return _accounts()
    except CliError:
        return []


def cmd_external_url(args: argparse.Namespace) -> int:
    old = ui.settings_get("external_url") or ""
    if not args.clear and args.url is None:
        out(f"Ekstern adresse: {old or '(ingen)'}")
        return EXIT_OK
    if args.clear and args.url is not None:
        raise UsageError("Angiv enten en adresse eller --clear.")
    try:
        value = "" if args.clear else ui.normalize_external_url(args.url)
    except ValueError as ex:
        raise CliError(str(ex)) from None
    if args.url is not None and not value:
        raise UsageError("Adressen er tom – brug --clear for at fjerne den.")
    if value == old:
        out("Adressen er uændret.")
        return EXIT_OK
    ui.settings_set("external_url", value)
    audit("settings_external_url", detail=f"{old or '-'} -> {value or '-'} (sfctl)")
    out(f"Den eksterne adresse er nu {value}." if value else "Den eksterne adresse er fjernet.")
    return EXIT_OK


def cmd_reload(args: argparse.Namespace) -> int:
    try:
        import services
        ok = bool(services.request_reload("Genstart fra sfctl", ACTOR))
    except Exception as ex:  # noqa: BLE001
        log.debug("services.request_reload failed: %s", type(ex).__name__)
        ok = False
    if not ok:
        ui.request_reload()
    if not (Path(ui.STATE_DIR) / "reload_requested").exists():
        raise CliError("Genstarten kunne ikke bestilles (kan ikke skrive i tilstandsmappen).")
    audit("filter_restart", detail="sfctl")
    out("Filteret genstarter om få sekunder.")
    return EXIT_OK


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


class Report:
    def __init__(self) -> None:
        self.errors = 0
        self.warnings = 0

    def ok(self, text: str) -> None:
        out(f"[ OK ] {text}")

    def warn(self, text: str, fix: str = "") -> None:
        self.warnings += 1
        out(f"[ADV.] {text}")
        if fix:
            out(f"       Ret: {fix}")

    def bad(self, text: str, fix: str = "") -> None:
        self.errors += 1
        out(f"[FEJL] {text}")
        if fix:
            out(f"       Ret: {fix}")


SENSITIVE = ("dashboard_users", "dashboard_secret", "admin-audit.jsonl", "spamfilter.db", "controller.password",
             "smtp.password", "vapid_private.pem", "backup.key")


def _check_files(rep: Report) -> None:
    state = Path(ui.STATE_DIR)
    cfg = Path(ui.CONFIG_PATH)
    for d, label in ((state, "tilstandsmappen"), (cfg.parent, "konfigurationsmappen")):
        try:
            st = d.stat()
        except OSError:
            rep.bad(f"{label} {d} findes ikke eller kan ikke læses")
            continue
        if st.st_uid != OWNER_UID:
            rep.bad(f"{label} {d} ejes af uid {st.st_uid}, ikke {OWNER_UID}", FIX_OWNER)
        elif not os.access(d, os.W_OK):
            rep.bad(f"{label} {d} kan ikke skrives af filteret", FIX_OWNER)
        else:
            rep.ok(f"{label} {d} ejes af {OWNER_UID}")
        if st.st_mode & 0o077 and d == state:
            rep.warn(f"{d} kan læses af andre (mode {stat.S_IMODE(st.st_mode):04o})",
                     f"docker exec -u 0 spamfilter chmod 0700 {d}")
    wrong_owner: list[str] = []
    too_open: list[str] = []
    candidates: list[Path] = []
    try:
        candidates += [p for p in state.iterdir() if not p.is_symlink()]
    except OSError:
        pass
    secrets_dir = state / "imap-secrets"
    if secrets_dir.is_dir():
        try:
            candidates += [p for p in secrets_dir.iterdir() if not p.is_symlink()]
        except OSError:
            rep.bad(f"{secrets_dir} kan ikke læses", FIX_OWNER)
    if cfg.exists():
        candidates.append(cfg)
    for p in candidates:
        try:
            st = p.lstat()
        except OSError:
            continue
        if not _owner_ok(p.name, st.st_uid):
            wrong_owner.append(str(p))
        sensitive = (p.name in SENSITIVE or p.parent == secrets_dir
                     or p.name.startswith(("spamfilter.db-", "dashboard_users.")))
        if sensitive and stat.S_ISREG(st.st_mode) and st.st_mode & 0o077:
            too_open.append(f"{p} ({stat.S_IMODE(st.st_mode):04o})")
    if wrong_owner:
        rep.bad(f"{len(wrong_owner)} fil(er) ejes ikke af {OWNER_UID}: " + ", ".join(wrong_owner[:6])
                + (" …" if len(wrong_owner) > 6 else ""), FIX_OWNER)
    else:
        rep.ok(f"alle filer i {state} og {cfg} ejes af {OWNER_UID}")
    if too_open:
        # Behind a 0700 state dir nobody else can reach them (SQLite makes
        # -wal/-shm with the umask): a warning. An open dir makes it an error.
        try:
            dir_open = bool(state.stat().st_mode & 0o077)
        except OSError:
            dir_open = True
        fix = ("docker exec -u 0 spamfilter sh -c 'chmod 0600 " + " ".join(t.split(" (")[0] for t in too_open[:6])
               + "'")
        (rep.bad if dir_open else rep.warn)("følsomme filer kan læses af andre: " + ", ".join(too_open[:6]), fix)
    else:
        rep.ok("følsomme filer har mode 0600")


def cmd_doctor(args: argparse.Namespace) -> int:
    rep = Report()
    out(f"Spamfilter {engine.VERSION} – sundhedstjek")
    _check_files(rep)
    # config
    try:
        accs = _accounts()
        rep.ok(f"accounts.yml er gyldig ({len(accs)} konti)")
    except CliError as ex:
        rep.bad(str(ex), f"ret {ui.CONFIG_PATH} – eller rul tilbage til en backup")
    # database
    db_path = Path(ui.DB_PATH)
    db_ok = False  # exists AND readable AND intact: only then touch the UI tables
    restore = "stop filteret og gendan databasen fra backup (se BACKUP.md)"
    if not db_path.exists():
        rep.bad(f"databasen {db_path} findes ikke", "start filteret (det opretter databasen)")
    elif not os.access(db_path, os.R_OK | os.W_OK):
        rep.bad(f"databasen {db_path} kan ikke læses/skrives af filteret", FIX_OWNER)
    else:
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10)
            try:
                res = [r[0] for r in conn.execute("PRAGMA integrity_check").fetchall()]
            finally:
                conn.close()
            if res == ["ok"]:
                rep.ok("databasen består integritetstjekket")
                db_ok = True
            else:
                rep.bad("databasen er beskadiget: " + clean("; ".join(map(str, res[:3])), 300), restore)
        except sqlite3.OperationalError as ex:
            # locked / unable to open (owner, mode, a root-owned -wal/-shm)
            rep.bad(f"databasen kan ikke åbnes ({clean(ex, 120)})", FIX_OWNER)
        except sqlite3.Error as ex:
            # DatabaseError: 'file is not a database' / malformed = damaged
            rep.bad(f"databasen er beskadiget ({clean(ex, 120)})", restore)
    # heartbeat
    age = heartbeat_age()
    if age is None:
        rep.warn("intet hjerteslag (filteret kører ikke, eller starter op)")
    elif age > HEARTBEAT_STALE:
        rep.warn(f"hjerteslaget er {fmt_age(age)} gammelt", "sfctl reload")
    else:
        rep.ok(f"hjerteslag for {fmt_age(age)} siden")
    # rspamd
    try:
        alive = bool(engine._rspamd_alive())
    except Exception:  # noqa: BLE001
        alive = False
    if alive:
        rep.ok("rspamd svarer")
    elif _aio_mode():
        rep.bad(f"rspamd svarer ikke ({engine.RSPAMD_PING_URL})", "docker exec spamfilter supervisorctl restart rspamd")
    else:
        rep.bad(f"rspamd svarer ikke ({engine.RSPAMD_PING_URL})", "docker restart spamfilter-rspamd")
    if _aio_mode():
        _doctor_aio(rep)
    # users file (never via load_users() before it is known to be readable)
    users_file = Path(ui.USERS_FILE)
    bad_lines = 0
    users_readable = True
    if users_file.exists():
        try:
            bad_lines = _bad_user_lines(users_file.read_bytes().decode("utf-8"))
        except OSError:
            users_readable = False
            rep.bad(f"brugerfilen {users_file} kan ikke læses af filteret (ingen kan logge ind)", FIX_OWNER)
        except UnicodeDecodeError:
            users_readable = False
            rep.bad(f"brugerfilen {users_file} er beskadiget (ikke gyldig tekst) – ingen kan logge ind",
                    f"{MOVE_ASIDE.format(f=users_file)}  og derefter  "
                    "docker exec -it spamfilter sfctl create-admin <navn> --generate")
    users = ui.load_users() if users_readable else {}
    if bad_lines:
        rep.bad(f"{bad_lines} linje(r) i brugerfilen kan ikke læses og ignoreres",
                f"ret {users_file} (format navn:hash:adgang:generation)")
    elif users_readable:
        rep.ok(f"brugerfilen kan læses ({len(users)} brugere)")
    admins = _admins(users)
    if not users_readable:
        pass  # the admin count is unknown until the file can be read
    elif admins < 1:
        rep.bad("der er ingen administrator", "docker exec -it spamfilter sfctl create-admin <navn> --generate")
    else:
        rep.ok(f"{admins} administrator(er)")
        tf = ui.all_twofa_status() if db_ok else {}
        without = sorted(n for n, u in users.items() if u.admin and not tf.get(n, {}).get("enabled"))
        if without and db_ok:
            rep.warn("administratorer uden to-trins-login: " + ", ".join(without)
                     + " (hverken app eller kode på mail)",
                     "log ind som dem og slå det til under Min konto – eller kræv det under Brugere")
        elif db_ok:
            rep.ok("alle administratorer har to-trins-login")
    if db_ok:
        try:
            conn = _db()
            conn.close()
            rep.ok("WebUI-tabellerne findes")
        except sqlite3.Error as ex:
            rep.bad(f"WebUI-tabellerne kan ikke oprettes ({clean(ex, 120)})", FIX_OWNER)
    paused = _paused_accounts() if db_ok else []
    if paused:
        rep.warn("sat på pause med sfctl: " + ", ".join(paused), "sfctl resume --all")
    if db_ok:
        _doctor_smtp(rep, users)
        _doctor_push(rep, users)
        _doctor_passkeys(rep, users)
        _doctor_ai(rep)
    _doctor_backup(rep)
    if db_ok:
        _doctor_mailcheck(rep)
    out("")
    if rep.errors:
        out(f"{rep.errors} fejl og {rep.warnings} advarsel(er).")
        return EXIT_ERR
    out("Alt ser fint ud." if not rep.warnings else f"Ingen fejl, {rep.warnings} advarsel(er).")
    return EXIT_OK


def _aio_mode() -> bool:
    return os.environ.get("SPAMFILTER_AIO") == "1"


AIO_PART_NAMES = {"filter": "filteret", "rspamd": "rspamd", "redis": "Redis", "unbound": "Unbound"}
AIO_STATUS_MAX_AGE = 180


def _doctor_aio(rep: Report, now: float | None = None) -> None:
    """2.4 all-in-one container: Redis and Unbound answer (unprivileged
    probes), plus every part of the last full health check (Docker runs it
    as root every 30 s, with the Redis password) from health.json."""
    import aio_health as aio

    restart = "docker exec spamfilter supervisorctl restart {}"
    r = aio.probe_redis_alive()
    if r.ok:
        rep.ok("Redis svarer (127.0.0.1:6379, i containeren)")
    else:
        rep.bad(f"Redis svarer ikke (127.0.0.1:6379): {r.detail}", restart.format("redis"))
    u = aio.probe_unbound()
    if u.ok:
        rep.ok(f"Unbound svarer (127.0.0.1:{aio.UNBOUND_PORT}, i containeren)")
    else:
        rep.bad(f"Unbound svarer ikke (127.0.0.1:{aio.UNBOUND_PORT}): {u.detail}", restart.format("unbound"))
    st = aio.read_status()
    if st is None:
        rep.warn("intet samlet sundhedstjek endnu (Docker kører det hvert 30. sekund)",
                 "vent et minut, eller kør: docker exec spamfilter sf-health check")
        return
    age = int((time.time() if now is None else now) - int(st.get("ts") or 0))
    parts = st.get("parts") or {}
    bad = [(name, parts.get(name) or {}) for name in aio.PARTS if not (parts.get(name) or {}).get("ok")]
    for name, info in bad:
        detail = clean(info.get("detail") or "ingen data", 120)
        fix = "docker restart spamfilter" if name == "filter" else restart.format(name)
        rep.bad(f"samlet sundhedstjek for {fmt_age(max(age, 0))} siden: {AIO_PART_NAMES[name]} fejler ({detail})", fix)
    if not bad:
        rep.ok(f"samlet sundhedstjek for {fmt_age(max(age, 0))} siden: filter, rspamd, Redis (med adgangskode) "
               "og Unbound er ok")
    _doctor_clamav(rep, parts.get("clamav"))
    if age > AIO_STATUS_MAX_AGE:
        rep.warn(f"det samlede sundhedstjek er {fmt_age(age)} gammelt", "docker exec spamfilter sf-health check")


def _doctor_clamav(rep: Report, info: dict | None) -> None:
    """2.7: ClamAV from the last full health check. Only warnings - the
    filter keeps scanning without it (rspamd adds CLAM_VIRUS_FAIL)."""
    if not isinstance(info, dict):
        return  # health.json of an image without ClamAV
    state = str(info.get("state") or "")
    age = info.get("db_age_s")
    sig_age = f"signaturerne er {fmt_age(age)} gamle" if isinstance(age, (int, float)) else "signaturernes alder ukendt"
    logs = "docker logs spamfilter 2>&1 | grep -E '\\[(clamd|freshclam)\\]' | tail -n 30"
    if state == "off":
        reason = clean(info.get("reason") or "", 120)
        if reason == "SF_CLAMAV=0":
            rep.ok("antivirus (ClamAV): slået fra med SF_CLAMAV=0 – mails virusscannes ikke")
        else:
            rep.warn(f"antivirus (ClamAV) er slået fra: {reason or 'ukendt årsag'} – mails virusscannes ikke",
                     "se [init]-linjerne i docker logs spamfilter, ret årsagen og genstart containeren")
    elif state == "ok":
        daily = info.get("daily")
        rep.ok(f"antivirus (ClamAV) svarer, {sig_age}" + (f" (daily {int(daily)})" if daily else ""))
    elif state == "waiting":
        rep.warn("antivirus (ClamAV) henter sine første virussignaturer (~300 MB, nogle minutter) – "
                 "indtil da scannes mails uden antivirus", logs)
    elif state == "stale":
        rep.warn(f"antivirus (ClamAV): {sig_age} – freshclam opdaterer ikke",
                 f"{logs}; docker exec spamfilter supervisorctl restart freshclam")
    else:
        rep.warn(f"antivirus (ClamAV) svarer ikke ({clean(info.get('detail') or 'ingen data', 120)}) – "
                 "mails scannes uden antivirus", "docker exec spamfilter supervisorctl restart clamd")


def _mail_users(users: dict) -> list[str]:
    tf = ui.all_twofa_status()
    return sorted(n for n in users if tf.get(n, {}).get("mail"))


def _doctor_smtp(rep: Report, users: dict) -> None:
    try:
        st = mailer.status()
    except Exception as ex:  # noqa: BLE001
        rep.warn(f"mailserverens status kan ikke læses ({type(ex).__name__})")
        return
    mail_users = _mail_users(users) if users else []
    if not st.get("host"):
        rep.ok("mailserver: ikke sat op (valgfri – kun Unraid-notifikationer og to-trins-login med app)")
        if mail_users:
            rep.warn("disse brugere har kode på mail, men der er ingen mailserver: " + ", ".join(mail_users),
                     "sæt mailserveren op under Indstillinger – eller sfctl disable-2fa NAVN")
        return
    if not st.get("enabled"):
        (rep.warn if mail_users else rep.ok)(
            "mailserver: slået fra" + (" – brugere med kode på mail kan kun logge ind med en genoprettelseskode: "
                                      + ", ".join(mail_users) if mail_users else ""),
            "slå den til igen under Indstillinger → Mailserver – eller sfctl disable-2fa NAVN" if mail_users else "")
        return
    if not st.get("configured"):
        rep.warn("mailserver: slået til, men indstillingerne er ufuldstændige (login, adgangskode eller afsender)",
                 "ret dem under Indstillinger → Mailserver")
        return
    pw = Path(mailer.PASSWORD_FILE)
    if st.get("auth") == "password" and pw.exists():
        try:
            mode = stat.S_IMODE(pw.stat().st_mode)
        except OSError:
            mode = 0
        if mode & 0o077:
            rep.warn(f"{pw} kan læses af andre (mode {mode:04o})",
                     f"docker exec -u 0 spamfilter chmod 0600 {pw}")
    err = st.get("last_error") or {}
    if err and float(err.get("at") or 0) > float(st.get("last_ok_at") or 0):
        rep.warn(f"mailserver: seneste mail fejlede ({clean(err.get('text'), 160)}, {fmt_ts(err.get('at'))})",
                 "sfctl smtp-test DIN@ADRESSE – eller sfctl smtp-disable")
    elif st.get("last_ok_at"):
        rep.ok(f"mailserver {clean(st['host'])}:{st['port']} virker (seneste mail {fmt_ts(st['last_ok_at'])})")
    else:
        rep.warn(f"mailserver {clean(st['host'])}:{st['port']} er ikke testet endnu", "sfctl smtp-test DIN@ADRESSE")
    if int(st.get("queued") or 0) > 20:
        rep.warn(f"{st['queued']} mails venter i udbakken", "sfctl smtp-status")


# ---------------------------------------------------------------------------
# Mail (2.3): status, nødstop og test
# ---------------------------------------------------------------------------

SECURITY_DA = {"starttls": "STARTTLS", "ssl": "SSL/TLS"}


def cmd_smtp_status(args: argparse.Namespace) -> int:
    st = mailer.status()
    if not st.get("host"):
        out("Mailserver: ikke sat op.")
        out("  Sæt den op i WebUI'en under Indstillinger → Mailserver.")
        return EXIT_OK
    state = ("slået til" if st["enabled"] else "SLÅET FRA") + ("" if st["configured"] or not st["enabled"]
                                                            else " (men ufuldstændig)")
    out(f"Mailserver: {state}")
    out(f"  server:        {clean(st['host'])}:{st['port']} ({SECURITY_DA.get(st['security'], st['security'])}, "
        "certifikat tjekkes)")
    if st["auth"] == "account":
        out(f"  login:         postkassens login ({clean(st['account'])}) – adgangskoden læses fra postkassen")
    else:
        out(f"  login:         {clean(st['username']) or '(intet brugernavn)'} + "
            + ("gemt adgangskode (0600-fil)" if st["password_stored"] else "INGEN gemt adgangskode"))
    out(f"  afsender:      {clean(st.get('from_addr')) or '(mangler)'}")
    out(f"  seneste ok:    {fmt_ts(st['last_ok_at']) if st.get('last_ok_at') else 'aldrig'}")
    err = st.get("last_error") or {}
    out(f"  seneste fejl:  " + (f"{clean(err.get('text'), 160)} ({fmt_ts(err.get('at'))})" if err else "ingen"))
    test = st.get("last_test") or {}
    if test:
        out("  seneste test:  " + ("ok" if test.get("ok") else f"fejlede – {clean(test.get('text'), 160)}")
            + f" ({fmt_ts(test.get('at'))})")
    out(f"  udbakke:       {st['queued']} i kø · {st['sent_24h']} sendt og {st['failed_24h']} fejlet det seneste døgn")
    out("Notifikationer:")
    for kind, r in (st.get("routes") or {}).items():
        n = len(r.get("to") or [])
        out(f"  {mailer.KIND_LABELS.get(kind, kind):<20} " + (f"til ({n} modtager{'e' if n != 1 else ''})"
                                                              if r.get("on") else "fra"))
    users = ui.load_users()
    mu = _mail_users(users)
    out(f"Kode på mail: {', '.join(mu) if mu else 'ingen brugere'}")
    return EXIT_OK


def cmd_smtp_disable(args: argparse.Namespace) -> int:
    st = mailer.status()
    if not st.get("host"):
        out("Der er ingen mailserver sat op – intet at slå fra.")
        return EXIT_OK
    if not st.get("enabled"):
        out("Afsendelse af mail er allerede slået fra.")
        return EXIT_OK
    mailer.set_enabled(False)
    audit("smtp_disable", detail="sfctl")
    out("Afsendelse af mail er slået fra. Indstillingerne er gemt; slå den til igen under Indstillinger → Mailserver.")
    out("Mails i udbakken sendes ikke. Unraid-notifikationerne kommer stadig.")
    mu = _mail_users(ui.load_users())
    if mu:
        out("Disse brugere har kode på mail og kan nu kun logge ind med en genoprettelseskode: " + ", ".join(mu))
        out("Nulstil dem om nødvendigt med: sfctl disable-2fa NAVN")
    return EXIT_OK


def cmd_smtp_test(args: argparse.Namespace) -> int:
    try:
        to = mailer.validate_address(args.to)
    except mailer.MailError:
        raise UsageError("Skriv en gyldig mailadresse, fx sfctl smtp-test navn@domæne.dk") from None
    out(f"Sender en testmail til {mailer.mask_address(to)} …")
    res = mailer.send_test(to, actor=ACTOR)
    if not res["ok"]:
        raise CliError(res["text"])
    out(res["text"])
    return EXIT_OK


# ---------------------------------------------------------------------------
# Beskeder på telefonen (2.5.0, web push)
# ---------------------------------------------------------------------------

PUSH_KIND_DA = {"threat": "farlige mails", "review": "Tjek disse", "problem": "problemer"}


def _push_mod():
    try:
        import push  # noqa: PLC0415
    except Exception as ex:  # noqa: BLE001
        raise CliError(f"push-modulet kan ikke indlæses ({type(ex).__name__})") from None
    if not push.available():
        raise CliError("Beskeder er ikke tilgængelige: Python-pakken 'cryptography' mangler i imaget.")
    return push


def _doctor_push(rep: Report, users: dict) -> None:
    try:
        import push  # noqa: PLC0415
    except Exception as ex:  # noqa: BLE001
        rep.warn(f"beskeder (push): modulet kan ikke indlæses ({type(ex).__name__})")
        return
    if not push.available():
        rep.warn("beskeder (push): Python-pakken 'cryptography' mangler – beskeder virker ikke",
                 "byg imaget igen (filter/requirements.txt)")
        return
    try:
        st = push.status()
    except Exception as ex:  # noqa: BLE001
        rep.warn(f"beskeder (push): status kan ikke læses ({type(ex).__name__})")
        return
    key = Path(push.STATE_DIR) / "vapid_private.pem"
    if st.get("key") is None:
        if key.exists():
            rep.bad(f"{key} kan ikke læses (beskeder virker ikke)", "sfctl push-reset (nye nøgler; enhederne skal "
                    "slå beskeder til igen)")
        else:
            rep.ok("beskeder (push): ingen nøgle endnu (laves, når den første enhed slår beskeder til)")
    elif st.get("key_mode") and st["key_mode"] & 0o077:
        rep.warn(f"{key} kan læses af andre (mode {st['key_mode']:04o})", f"docker exec -u 0 spamfilter chmod 0600 {key}")
    devs = st.get("devices") or []
    if not devs:
        if st.get("key") is not None:
            rep.ok("beskeder (push): ingen enheder tilmeldt")
        return
    unknown = sorted({d["user"] for d in devs if d["user"] not in users})
    if unknown:
        rep.warn("enheder med beskeder hører til slettede brugere: " + ", ".join(clean(u) for u in unknown),
                 "sfctl push-reset – eller slet dem under Min konto")
    if not st.get("subject_ok"):
        rep.bad("beskeder (push): ingen afsenderadresse (VAPID 'sub') – push-tjenesterne afviser beskederne",
                "sæt en mailadresse på en postkasse i accounts.yml, en afsender under Mailserver, eller "
                "PUSH_VAPID_SUBJECT=mailto:DIN@ADRESSE")
    ref = st.get("refused")
    if ref:
        rep.bad(f"beskeder (push): {clean(ref.get('host'), 60)} afviser filterets afsender-nøgle "
                f"({clean(str(ref.get('status')), 4)} {clean(ref.get('detail'), 40)}, {fmt_ts(ref.get('at'))}) – "
                "enhederne er beholdt, men får ingen beskeder",
                "tjek uret på Unraid (NTP) og afsenderadressen (PUSH_VAPID_SUBJECT); prøv sfctl push-test NAVN")
    failing = [d for d in devs if d.get("last_error")]
    msg = f"beskeder (push): {len(devs)} enhed(er) hos {len({d['user'] for d in devs})} bruger(e)"
    if failing:
        rep.warn(msg + f", {len(failing)} med fejl ved seneste besked", "sfctl push-status")
    else:
        rep.ok(msg)
    if int(st.get("queued") or 0) > 50:
        rep.warn(f"{st['queued']} beskeder venter i køen", "sfctl push-status")


def cmd_push_status(args: argparse.Namespace) -> int:
    push = _push_mod()
    st = push.status()
    if st.get("key"):
        mode = st.get("key_mode")
        out(f"Nøgle (VAPID):  {st['key']} (fingeraftryk; fil {Path(push.STATE_DIR) / 'vapid_private.pem'}"
            + (f", mode {mode:04o}" if mode is not None else "") + ")")
    else:
        out("Nøgle (VAPID):  ingen endnu (laves, når den første enhed slår beskeder til)")
    out(f"Afsender (sub): {'ok' if st.get('subject_ok') else 'MANGLER – sæt PUSH_VAPID_SUBJECT eller en mailadresse'}")
    devs = st.get("devices") or []
    out(f"Enheder:        {len(devs)}")
    for d in devs:
        kinds = ", ".join(PUSH_KIND_DA[k] for k, on in d["prefs"].items() if on) or "intet valgt"
        last = fmt_ts(d["last_ok_at"]) if d.get("last_ok_at") else "aldrig"
        err_txt = f" · fejl: {clean(d['last_error'], 60)}" if d.get("last_error") else ""
        out(f"  #{d['id']:<4} {clean(d['user'], 30):<14} {clean(d['ua'], 40):<28} {clean(d['host'], 40)}"
            f" · seneste ok {last}{err_txt} · {kinds}")
    ref = st.get("refused")
    if ref:
        out(f"Afvist:         {clean(ref.get('host'), 60)} afviste filterets afsender-nøgle "
            f"({clean(str(ref.get('status')), 4)} {clean(ref.get('detail'), 40)}) {fmt_ts(ref.get('at'))} – "
            "enhederne er beholdt; tjek uret og PUSH_VAPID_SUBJECT")
    out(f"Kø:             {st['queued']} venter · {st['sent_24h']} sendt, {st['failed_24h']} fejlet og "
        f"{st['dropped_24h']} sprunget over det seneste døgn")
    return EXIT_OK


def cmd_push_test(args: argparse.Namespace) -> int:
    push = _push_mod()
    users = ui.load_users()
    u = users.get(args.user)
    if u is None:
        raise CliError(f"Brugeren {clean(args.user, 64)} findes ikke (se sfctl users).")
    out(f"Sender en testbesked til {clean(args.user, 64)}s enheder …")
    res = push.send_test(args.user, is_admin=u.admin)
    if not res["ok"] and res.get("code") == "refused":
        raise CliError("Beskedtjenesten afviste filterets afsender-nøgle. Enhederne er beholdt; "
                       "kør sfctl doctor (tjek uret på serveren og afsenderadressen).")
    if not res["ok"]:
        raise CliError(res["text"])
    out(res["text"])
    return EXIT_OK


def cmd_push_reset(args: argparse.Namespace) -> int:
    push = _push_mod()
    confirm(args, "Alle enheder mister beskeder og skal slå dem til igen under Min konto, og nøglen (VAPID) "
                  "skiftes ud.")
    res = push.reset_all()
    audit("push_reset", detail=f"{res['subscriptions']} enhed(er)")
    out(f"{res['subscriptions']} enhed(er) er fjernet, og der er lavet en ny nøgle ({res['fingerprint']}).")
    out("Slå beskeder til igen under Min konto på hver telefon.")
    return EXIT_OK


# ---------------------------------------------------------------------------
# Passkeys (2.6, B1)
# ---------------------------------------------------------------------------


# Direct SQL on the UI tables (dashboard.UI_SCHEMA) - the same rows
# passkeys.py reads and writes; sfctl never imports the route module.


def _passkey_rows(name: str | None = None) -> list[dict]:
    conn = _db()
    try:
        sql = ("SELECT id, name, label, rp_id, alg, backup_eligible, created_at, last_used_at, last_used_ip "
               "FROM ui_passkeys" + (" WHERE name=?" if name is not None else "") + " ORDER BY name, created_at, id")
        return [dict(r) for r in conn.execute(sql, (name,) if name is not None else ()).fetchall()]
    finally:
        conn.close()


def _external_host() -> str:
    ext = ui.external_url()
    return (urlsplit(ext).hostname or "").lower() if ext.startswith("https://") else ""


def cmd_passkeys(args: argparse.Namespace) -> int:
    """List a user's passkeys (never credential ids or keys)."""
    name = args.user
    if name not in ui.load_users():
        raise CliError(f"Ukendt bruger: {clean(name, 64)}")
    items = _passkey_rows(name)
    if not items:
        out(f"{clean(name, 64)} har ingen passkeys.")
        return EXIT_OK
    out(f"Passkeys for {clean(name, 64)} ({len(items)}):")
    for p in items:
        used = (f"senest brugt {fmt_ts(p['last_used_at'])} fra {clean(p.get('last_used_ip'), 64)}"
                if p.get("last_used_at") else "ikke brugt endnu")
        sync = " · synkroniseres" if p.get("backup_eligible") else ""
        out(f"  #{p['id']:<4} {clean(p['label'], 40):<28} {clean(p['rp_id'], 80)} · oprettet "
            f"{fmt_ts(p['created_at'])} · {used}{sync}")
    out(f"Fjern dem alle (fx mistet telefon): sfctl passkeys-reset {clean(name, 64)}")
    return EXIT_OK


def cmd_passkeys_reset(args: argparse.Namespace) -> int:
    name = args.user
    if name not in ui.load_users():
        raise CliError(f"Ukendt bruger: {clean(name, 64)}")
    n = len(_passkey_rows(name))
    confirm(args, f"Dette fjerner alle {n} passkey(s) for {clean(name, 64)}. Brugeren logger ind med adgangskode "
                  "(og to-trins-login) og kan lave nye under Min konto.")
    removed = ui.remove_all_passkeys(name)
    audit("passkey_reset", detail=f"{name} ({removed})")
    if removed:
        ui.security_notice(name, "passkeys fjernet",
                           "Alle passkeys er fjernet fra dit login fra serverens nødadgang (sfctl).")
    out(f"{removed} passkey(s) for {clean(name, 64)} er fjernet. Slet dem også på enhederne (de virker ikke længere).")
    return EXIT_OK


def _doctor_passkeys(rep: Report, users: dict) -> None:
    try:
        items = _passkey_rows()
    except sqlite3.Error as ex:
        rep.warn(f"passkeys: kan ikke læses ({type(ex).__name__})")
        return
    if not items:
        rep.ok("passkeys: ingen oprettet")
        return
    orphans = sorted({p["name"] for p in items if p["name"] not in users})
    if orphans:
        rep.warn("passkeys hører til slettede brugere: " + ", ".join(clean(n, 64) for n in orphans),
                 f"sfctl passkeys-reset {clean(orphans[0], 64)}")
    host = _external_host()
    other = sorted({p["rp_id"] for p in items if p["rp_id"] not in (host, "localhost")})
    if other:
        rep.warn(f"{sum(1 for p in items if p['rp_id'] in other)} passkey(s) er lavet til "
                 + ", ".join(clean(o, 80) for o in other)
                 + (f", men den eksterne adresse er nu {host}" if host else ", men der er ingen ekstern https-adresse")
                 + " – de virker ikke", "sfctl external-url https://" + clean(other[0], 80)
                 + "  (eller fjern dem: sfctl passkeys-reset NAVN)")
    if not orphans and not other:
        rep.ok(f"passkeys: {len(items)} hos {len({p['name'] for p in items})} bruger(e)")


# ---------------------------------------------------------------------------
# Home Assistant-nøgle (2.3.6, B26). 2.11.0: alias for API-nøglen "Home
# Assistant" (Kun læse, kun hjemmenet); create erstatter nøglen med det navn.
# ---------------------------------------------------------------------------

HA_SECRET_HINT = 'spamfilter_auth: "Bearer {token}"'


def cmd_ha_token(args: argparse.Namespace) -> int:
    """create: ny nøgle (vises én gang; kun sha256 gemmes), revoke:
    tilbagekald, status: findes den, hvornår og hvorfra den sidst blev brugt."""
    st = ui.ha_token_status()
    if args.action == "status":
        if not st["exists"]:
            out("Home Assistant-nøgle: ingen (opret med sfctl ha-token create).")
        else:
            out("Home Assistant-nøgle: aktiv")
            out(f"  oprettet:      {fmt_ts(st['created_at'])}" + (f" af {clean(st['created_by'], 80)}"
                                                                    if st["created_by"] else ""))
            out("  senest brugt:  " + (f"{fmt_ts(st['last_used_at'])} fra {clean(st['last_used_ip'], 64)}"
                                       if st["last_used_at"] else "aldrig"))
        if st["rejected_at"]:
            out(f"  seneste afvisning: {fmt_ts(st['rejected_at'])} fra {clean(st['rejected_ip'], 64)}")
        out("  adresse:       GET /api/v1/ha (kun fra hjemmenetværket, med Authorization: Bearer <nøgle>)")
        return EXIT_OK
    if args.action == "revoke":
        if not st["exists"]:
            out("Der er ingen Home Assistant-nøgle – intet at tilbagekalde.")
            return EXIT_OK
        ui.ha_token_revoke(ACTOR)
        audit("ha_token_revoke", detail="sfctl")
        out("Nøglen er tilbagekaldt. Home Assistant får ikke flere tal, før der laves en ny.")
        return EXIT_OK
    # create
    if st["exists"]:
        confirm(args, "Der findes allerede en nøgle. En ny nøgle gør den gamle ugyldig med det samme.")
    token = ui.ha_token_create(ACTOR)
    audit("ha_token_create", detail="sfctl" + (" (erstattede den gamle)" if st["exists"] else ""))
    out("Ny Home Assistant-nøgle (vises KUN nu – kopiér den):")
    out(f"  {token}")
    out("Linje til Home Assistants secrets.yaml:")
    out("  " + HA_SECRET_HINT.format(token=token))
    out("Pakken med sensorerne: WebUI → Adgang for programmer → Home Assistant (eller HOME-ASSISTANT.md).")
    return EXIT_OK


# ---------------------------------------------------------------------------
# API-nøgler til programmer (2.11.0) - `ha-token` er et alias for nøglen
# "Home Assistant"
# ---------------------------------------------------------------------------


def _key_line(k: dict) -> str:
    used = (f"{fmt_ts(k['last_used_at'])} fra {clean(k['last_used_ip'], 64)}" if k["last_used_at"] else "aldrig")
    flags = [k["scope_label"], "kun hjemmenet" if k["lan_only"] else "også udefra"]
    if k["expires_at"]:
        flags.append(("udløbet " if k["expired"] else "udløber ") + fmt_ts(k["expires_at"]))
    if k["migrated"]:
        flags.append("flyttet")
    return (f"  #{k['id']:<3} {clean(k['name'], 60):<24} {ui.api_key_label(k):<12} {', '.join(flags)}\n"
            f"       oprettet {fmt_ts(k['created_at'])}" + (f" af {clean(k['created_by'], 80)}" if k["created_by"] else "")
            + f" · senest brugt {used}")


def cmd_api_key(args: argparse.Namespace) -> int:
    """list: alle nøgler (aldrig selve nøglen), create: ny nøgle (vises én
    gang; kun sha256 + de sidste 4 tegn gemmes), delete: slet én nøgle (de
    andre virker videre)."""
    if args.action == "list":
        keys = ui.api_keys_list()
        if not keys:
            out("API-nøgler: ingen (lav en med sfctl api-key create --name NAVN).")
        else:
            out(f"API-nøgler: {len(keys)}")
            for k in keys:
                out(_key_line(k))
        rej = ui.api_key_rejected()
        if rej:
            out(f"Seneste afvisning: {fmt_ts(rej['at'])} fra {clean(rej['ip'], 64)} ({rej['reason_text']})")
        out("Brug: Authorization: Bearer <nøgle> (aldrig i adressen). GET /api/v1/ha kræver Kun læse.")
        return EXIT_OK
    if args.action == "create":
        if not args.name:
            raise CliError("Giv nøglen et navn: sfctl api-key create --name \"Home Assistant\"")
        try:
            token, k = ui.api_key_create(args.name, args.scope, ACTOR, lan_only=not args.anywhere,
                                         expires_days=args.expires or 0)
        except ValueError as ex:
            raise CliError(str(ex)) from None
        audit("api_key_create", detail=f"sfctl: {k['name']} (#{k['id']}, {k['scope']}, "
                                       f"{'hjemmenet' if k['lan_only'] else 'også udefra'}, …{k['hint']})")
        out(f"Ny API-nøgle \"{k['name']}\" ({k['scope_label']}) – vises KUN nu, kopiér den:")
        out(f"  {token}")
        out(f"Send den som:  Authorization: Bearer {token}")
        out("Til Home Assistants secrets.yaml:")
        out("  " + HA_SECRET_HINT.format(token=token))
        return EXIT_OK
    # delete
    if args.id is None:
        raise CliError("Skriv nøglens nummer: sfctl api-key delete ID (se sfctl api-key list).")
    k = ui.api_key_get(args.id)
    if k is None:
        raise CliError(f"Der er ingen nøgle med nummer {args.id} (se sfctl api-key list).")
    confirm(args, f"Slet nøglen \"{k['name']}\"? Programmer, der bruger den, får ikke flere svar. "
                  "De andre nøgler virker som før.")
    ui.api_key_delete(k["id"])
    audit("api_key_delete", detail=f"sfctl: {k['name']} (#{k['id']}, {k['scope']}, {ui.api_key_label(k)})")
    out(f"Nøglen \"{k['name']}\" er slettet. De andre nøgler virker som før.")
    return EXIT_OK


# ---------------------------------------------------------------------------
# Krypteret backup (2.6, B3)
# ---------------------------------------------------------------------------

KEY_WARNING = """\
!!! VIGTIGT – LÆS DETTE !!!
Dette er nøglen til de krypterede backups. Uden den kan INGEN backup gendannes,
heller ikke af os. Gem den NU i din kode-manager (fx som "Spamfilter backupnøgle").
Den vises kun denne ene gang. Del den aldrig i chat, mail eller skærmbilleder.
Nøglen ligger også i containeren (state/backup.key), men den er IKKE med i
backupperne – mister du app-mappen, er kode-manageren det eneste sted, den findes."""


def _backup_mod():
    import backup  # noqa: PLC0415

    backup.configure(ui.STATE_DIR, ui.CONFIG_PATH, version=engine.VERSION)
    return backup


def _ask_key(args: argparse.Namespace, bk: Any) -> bytes | None:
    if not getattr(args, "ask_key", False):
        return None
    try:
        text = _getpass("Backupnøgle (SFBK1-…): ")
    except (EOFError, KeyboardInterrupt):
        raise CliError("Afbrudt – ingen nøgle.") from None
    try:
        return bk.parse_key(text)
    except bk.BackupError as ex:
        raise CliError(str(ex)) from None


def _archive_path(bk: Any, name: str) -> Path:
    p = Path(name)
    if not p.exists() and not p.is_absolute() and "/" not in name:
        p = bk.BACKUP_DIR / name
    if not p.is_file():
        raise CliError(f"{name} findes ikke (se sfctl backup-list).")
    return p


def cmd_backup_now(args: argparse.Namespace) -> int:
    """Lav en krypteret backup nu (samme som natten)."""
    bk = _backup_mod()
    if args.if_older is not None:
        st = bk.read_status()
        last = st.get("last_ok_ts")
        if isinstance(last, (int, float)) and time.time() - float(last) < args.if_older * 3600:
            out(f"Seneste backup er {fmt_age(time.time() - float(last))} gammel – ingen ny nu.")
            return EXIT_OK
    out("Laver en krypteret backup … (det kan tage et par minutter)")
    st = bk.run_backup(reason="sfctl")
    if st.get("ok"):
        audit("backup_now", detail=f"{st.get('archive')} ({st.get('files')} filer)")
        out(f"Færdig: {bk.BACKUP_DIR / str(st.get('archive'))} ({st.get('files')} filer, {_n(st.get('size'))} byte).")
        for w in st.get("warnings") or []:
            out(f"  Advarsel: {clean(w, 200)}")
        if st.get("pruned"):
            out(f"  Ryddet op: {len(st['pruned'])} ældre backup(s) uden for 14 dage + 8 uger.")
        return EXIT_OK
    audit("backup_now", result="failed", detail=clean(st.get("error") or "", 200))
    if st.get("archive"):
        out(f"Backuppen {st['archive']} er skrevet, men ufuldstændig.")
    err(f"Backup fejlede: {clean(st.get('error') or 'ukendt fejl', 300)}")
    return EXIT_ERR


def cmd_backup_list(args: argparse.Namespace) -> int:
    """Vis de krypterede backups i /backup (nyeste først)."""
    bk = _backup_mod()
    s = bk.summary()
    if not s["mounted"]:
        out(f"{bk.BACKUP_DIR} er ikke monteret – der er ingen backup-placering.")
        return EXIT_ERR
    kid = (s.get("key") or {}).get("key_id")
    items = bk.list_archives()
    if not items:
        out(f"Ingen krypterede backups i {bk.BACKUP_DIR} endnu (lav en med sfctl backup-now).")
        return EXIT_OK
    out(f"Krypterede backups i {bk.BACKUP_DIR} (beholdes: 14 dage + 8 uger):")
    for a in items:
        try:
            other = bk.peek(a["path"]).get("key_id") != kid
        except bk.BackupError:
            other = True
        out(f"  {a['name']}  {fmt_ts(a['ts'])}  {_n(a['size'])} byte" + ("  (anden nøgle)" if other else ""))
    return EXIT_OK


def cmd_backup_verify(args: argparse.Namespace) -> int:
    """Dekrypter en backup og tjek alle kontrolsummer (skriver intet)."""
    bk = _backup_mod()
    path = _archive_path(bk, args.file)
    key = _ask_key(args, bk)
    try:
        r = bk.verify(path, key)
    except bk.BackupError as ex:
        audit("backup_verify", result="failed", detail=f"{path.name}: {clean(ex, 160)}")
        raise CliError(str(ex)) from None
    audit("backup_verify", detail=path.name)
    out(f"OK: {path.name} er hel – {r['files']} filer, {_n(r['bytes'])} byte, lavet {fmt_ts(r['created'])}"
        f" (version {clean(r.get('version') or '?', 20)}).")
    out("  Bayes-data (Redis): " + ("med" if r["redis"] else "MANGLER"))
    if "site_config" in r:
        out("  Lokal opsætning (config/site.yml): " + ("med" if r["site_config"] else "MANGLER"))
    for sk in r["skipped"]:
        out(f"  Ikke med: {clean(sk.get('name'), 120)} ({clean(sk.get('why'), 40)})")
    for w in r["warnings"]:
        out(f"  Advarsel: {clean(w, 200)}")
    return EXIT_OK


def cmd_backup_restore(args: argparse.Namespace) -> int:
    """Gendan en backup til en NY mappe (aldrig oven i den kørende)."""
    bk = _backup_mod()
    path = _archive_path(bk, args.file)
    key = _ask_key(args, bk)
    try:
        r = bk.restore(path, Path(args.to), key)
    except bk.BackupError as ex:
        audit("backup_restore", result="failed", detail=f"{path.name}: {clean(ex, 160)}")
        raise CliError(str(ex)) from None
    audit("backup_restore", detail=f"{path.name} -> {clean(r['to'], 120)}")
    out(f"Gendannet til {r['to']}: {r['files']} filer, alle kontrolsummer passer.")
    out("Den kørende installation er IKKE ændret. Næste skridt (se BACKUP.md, 'Gendan fra krypteret backup'):")
    out("  1. Stop containeren:  docker stop -t 90 spamfilter")
    out("  2. Gem de nuværende state/ og config/ til side, og kopiér de gendannede filer ind")
    out("     med ejer 10099:10099 (mode 0600, mapper 0700). redis/dump.rdb: se BACKUP.md.")
    out("  3. Start igen:  docker start spamfilter   og kør  sfctl doctor")
    out("Mappen indeholder alle hemmeligheder i klar tekst – slet den, når du er færdig.")
    return EXIT_OK


def cmd_backup_drill(args):
    import restorecheck
    bk = _backup_mod()
    path, key = _archive_path(bk, args.file), _ask_key(args, bk)
    try:
        result = restorecheck.run(path, key)
    except (restorecheck.DrillError, bk.BackupError) as ex:
        audit("backup_startup_drill", result="failed", detail=type(ex).__name__)
        raise CliError(str(ex)) from None
    audit("backup_startup_drill", detail="app and Redis started on isolated restored copy")
    out(json.dumps(result, ensure_ascii=False))
    return EXIT_OK


def cmd_quality_evaluate(args):
    import quality
    try:
        result = quality.evaluate(quality.read_dataset(Path(args.file)))
    except (ValueError, OSError) as ex:
        raise CliError("Evaluering afvist: " + str(ex)) from None
    out(json.dumps(result, ensure_ascii=False, indent=2))
    return EXIT_OK


def cmd_quality_compare(args):
    import quality
    try:
        result = quality.compare(quality.read_dataset(Path(args.baseline)),
                                 quality.read_dataset(Path(args.candidate)),
                                 false_positive_cost=args.false_positive_cost,
                                 min_per_class=args.min_per_class)
    except (ValueError, OSError) as ex:
        raise CliError("Sammenligning afvist: " + str(ex)) from None
    out(json.dumps(result, ensure_ascii=False, indent=2))
    # Success means valid evaluation, not an installation/activation decision.
    return EXIT_OK


def cmd_policy_preview(args):
    import decisiontrace
    try:
        conn = sqlite3.connect(Path(ui.DB_PATH).resolve().as_uri() + '?mode=ro', uri=True)
        try:
            result = decisiontrace.preview(conn, args.account, threshold=args.threshold, limit=args.limit)
        finally:
            conn.close()
    except ValueError as ex:
        raise CliError('Prøve afvist: ' + str(ex)) from None
    out(json.dumps(result, ensure_ascii=False, indent=2))
    return EXIT_OK


def cmd_quality_reserve(args):
    import holdout
    try:
        with Path(args.file).open('rb') as f:
            raw = f.read(10 * 1024 * 1024 + 1)
        result = holdout.reserve(ui.DB_PATH, raw, args.sample_id)
    except (holdout.HoldoutError, OSError) as ex:
        raise CliError('Reservation afvist: ' + (str(ex) if isinstance(ex, holdout.HoldoutError)
                                               else type(ex).__name__)) from None
    audit('quality_reserve', detail=args.sample_id)
    out(json.dumps(result, ensure_ascii=False, indent=2))
    return EXIT_OK


def cmd_quality_export(args):
    import quality
    with sqlite3.connect(ui.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        accounts = [r[0] for r in conn.execute("SELECT DISTINCT account FROM scan_observations")]
        rows = list(quality.export_sample(conn, accounts))
    # Never overwrite a file or print message IDs to the terminal.
    fd = os.open(args.to, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    out(f"{len(rows)} mærkede observationer eksporteret lokalt. Udvalget har selektionsbias; del ikke filen på GitHub.")
    return EXIT_OK


def cmd_backup_key(args: argparse.Namespace) -> int:
    """show: vis nøglen (kun én gang), status: findes den, id og hvornår den blev vist."""
    bk = _backup_mod()
    st = bk.key_status()
    if args.action == "status":
        if not st["exists"]:
            out("Backupnøgle: ingen endnu (laves ved første backup eller med sfctl backup-key show).")
            return EXIT_OK
        out("Backupnøgle: findes")
        out(f"  nøgle-id:  {st['key_id']}  (står også i hver backupfil)")
        out(f"  oprettet:  {fmt_ts(st['created_at'])}")
        out("  vist:      " + (fmt_ts(st["shown_at"]) if st["shown_at"] else "aldrig – kør sfctl backup-key show og gem den"))
        return EXIT_OK
    if st["shown_at"] and not args.again:
        raise CliError(f"Nøglen blev allerede vist {fmt_ts(st['shown_at'])}. Den skal ligge i din kode-manager. "
                       "Har du mistet den: sfctl backup-key show --again")
    if st["shown_at"]:
        confirm(args, "Nøglen er vist før. Vis den igen (kun hvis den er væk fra kode-manageren)?")
    key = bk.load_key(create=True)
    out(KEY_WARNING)
    out("")
    out(f"  {bk.format_key(key)}")
    out("")
    out(f"Nøgle-id (til kontrol): {bk.key_id(key)}")
    bk.mark_key_shown()
    audit("backup_key_show", detail=f"id {bk.key_id(key)}" + (" (igen)" if st["shown_at"] else ""))
    return EXIT_OK


def _doctor_ai(rep: Report) -> None:
    """2.7: the local AI second opinion (Ollama on the LAN). Only a warning:
    without it the mail is decided exactly as before. Reads the state the
    engine's worker recorded - doctor itself never calls Ollama."""
    try:
        import ai_verdict  # noqa: PLC0415

        conn = _engine_conn()
        try:
            hl = ai_verdict.health(conn)
            settings = ai_verdict.load_settings(conn)
        finally:
            conn.close()
    except Exception as ex:  # noqa: BLE001
        rep.warn(f"AI-vurdering: status kan ikke læses ({type(ex).__name__})")
        return
    label = ai_verdict.MODE_TEXT.get(hl["mode"], hl["mode"])
    if hl["state"] == "off":
        rep.ok("AI-vurdering: Fra")
    elif not hl["url_ok"]:
        rep.ok(f"AI-vurdering ({label}): ikke sat op – ingen Ollama-adresse gemt, intet sendes "
               "(angiv den under Filtrering → AI-vurdering)")
    elif hl["state"] == "down":
        rep.warn(f"AI-vurdering ({label}): Ollama svarer ikke ({clean(hl.get('last_error') or '', 80)}, "
                 f"{hl['errors']} fejl i træk) – mailen vurderes som uden AI",
                 f"tjek Ollama på {settings['url']} (Filtrering → AI-vurdering → Test forbindelse)")
    elif hl["state"] == "ok":
        age = time.time() - float(hl["last_ok_at"] or 0)
        rep.ok(f"AI-vurdering ({label}): Ollama svarede for {fmt_age(age)} siden ({clean(settings['model'], 40)})")
    else:
        rep.ok(f"AI-vurdering ({label}): ingen vurderinger endnu")


def _doctor_backup(rep: Report) -> None:
    """2.6 (B3): the nightly encrypted backup and the off-site copy."""
    try:
        bk = _backup_mod()
        s = bk.summary()
    except Exception as ex:  # noqa: BLE001
        rep.warn(f"krypteret backup: status kan ikke læses ({type(ex).__name__})")
        return
    if not s["mounted"]:
        (rep.bad if s["alert"] else rep.warn)(
            f"krypteret backup: {bk.BACKUP_DIR} er ikke monteret – der laves ingen backup ud af app-mappen",
            "deploy/aio/update.sh (tilføjer /backup -> /mnt/user/backup/spamfilter), eller tilføj stien i Unraid-skabelonen")
    elif s["state"] == "ok":
        rep.ok(f"krypteret backup for {fmt_age(s['age_s'])} siden ({s['archives']} i {bk.BACKUP_DIR})")
        for w in s["warnings"]:
            rep.warn(f"krypteret backup: {clean(w, 160)}")
    elif s["state"] == "never":
        (rep.bad if s["alert"] else rep.warn)("krypteret backup: ingen endnu (kører hver nat fra kl. 02:30)",
                                              "sfctl backup-now")
    else:
        (rep.bad if s["alert"] else rep.warn)(
            f"krypteret backup fejlede: {clean(s.get('error') or '', 200)}"
            + (" – ingen vellykket backup i over 48 timer" if s["alert"] else ""),
            "sfctl backup-now  (og se Drift → Krypteret backup)")
    key = s.get("key") or {}
    if key.get("exists") and not key.get("shown_at"):
        rep.warn("backupnøglen er aldrig vist – uden den kan en backup ikke gendannes andre steder",
                 "sfctl backup-key show  (gem den i din kode-manager)")
    off = s.get("offsite")
    if off:
        if off.get("skipped"):
            rep.warn(f"kopi ud af huset: slået fra ({clean(off.get('skipped'), 80)})")
        elif off.get("ok"):
            rep.ok(f"kopi ud af huset ({clean(off.get('remote'), 80)}) for {fmt_age(off.get('age_s'))} siden")
        else:
            rep.bad(f"kopi ud af huset fejlede: {clean(off.get('error') or '', 160)}",
                    "se User Scripts → Spamfilter-offsite (log) på Unraid")


# ---------------------------------------------------------------------------
# Mailsikkerhed (2.7)
# ---------------------------------------------------------------------------

def _mailcheck_mod():
    import mailcheck  # noqa: PLC0415

    return mailcheck


def _doctor_mailcheck(rep: Report) -> None:
    """One line from the newest stored check (no network). Problems in the
    domains' DNS are the owner's DNS, not this installation: a warning."""
    try:
        mc = _mailcheck_mod()
        conn = _engine_conn()
        try:
            s = mc.last_summary(conn)
        finally:
            conn.close()
    except Exception as ex:  # noqa: BLE001
        rep.warn(f"mailsikkerhed: status kan ikke læses ({type(ex).__name__})")
        return
    if s is None:
        out("[INFO] mailsikkerhed: ikke tjekket endnu (kører hver nat; nu: sfctl mailcheck)")
        return
    when = f"for {fmt_age(s['age_s'])} siden"
    if s.get("degraded"):
        rep.warn(f"mailsikkerhed: tjekket {when} kunne ikke gennemføres (DNS/forbindelse) – intet testet",
                 "tjek Unbound og internetforbindelsen, og kør sfctl mailcheck")
    elif s["errors"] or s["warnings"]:
        top = ("; ".join(clean(t, 80) for t in s["top"])) if s["top"] else ""
        rep.warn(f"mailsikkerhed: {s['errors']} fejl og {s['warnings']} advarsel(er) i tjekket {when}"
                 + (f" – {top}" if top else ""), "se Sikkerhed → Mailsikkerhed i WebUI'en, eller kør sfctl mailcheck")
    else:
        rep.ok(f"mailsikkerhed: alt OK i tjekket {when}")
    if s["age_s"] > 3 * 86400:
        rep.warn(f"mailsikkerhed: seneste tjek er {fmt_age(s['age_s'])} gammelt (kører hver nat)", "sfctl mailcheck")


def cmd_mailcheck(args: argparse.Namespace) -> int:
    mc = _mailcheck_mod()
    conn = _engine_conn()
    try:
        mc.ensure_schema(conn)
        if args.last:
            res = mc.load_run(conn)
            if res is None:
                out("Ingen tjek endnu. Kør: sfctl mailcheck")
                return EXIT_OK
        else:
            out("Mailsikkerhed: tjekker domæner, mailservere og blokeringslister (1–2 minutter) …")
            try:
                smtp = mailer.get_settings()
            except Exception:  # noqa: BLE001
                smtp = None
            res = mc.run_and_record(engine, conn, _accounts_or_empty(), reason="cli", smtp=smtp)
            if res is None:
                raise CliError("tjekket blev afbrudt")
            audit("mailcheck_run", detail=f"fejl={res['counts'].get('bad', 0)} advarsler={res['counts'].get('warn', 0)}")
        res = mc.effective(res, mc.load_acks(conn))   # "Kendt – ignorér" findings count as info
    finally:
        conn.close()
    out(f"Tjek {fmt_ts(res.get('finished_at'))}")
    for line in mc.summary_lines(res, verbose=not args.problems):
        out(clean(line, 700))
    c = res.get("counts") or mc.counts(res)
    out("")
    out(f"I alt: {c.get('bad', 0)} fejl, {c.get('warn', 0)} advarsel(er), {c.get('ok', 0)} OK, "
        f"{c.get('unknown', 0)} ikke testet.")
    return EXIT_ERR if c.get("bad") else EXIT_OK


# ---------------------------------------------------------------------------
# Bayes: byg op på ny / gendan / status
# ---------------------------------------------------------------------------

def _services():
    import services  # noqa: PLC0415 - same image; services imports the engine lazily

    return services


def _n(value: Any) -> str:
    try:
        return f"{int(value):,}".replace(",", ".")
    except (TypeError, ValueError):
        return "–"


def _print_plan(plan: dict) -> None:
    out(f"Bayes-pulje nu: {clean(plan.get('pool_now'))}  →  ny pulje: {clean(plan.get('pool_new'))}")
    out(f"Spam (ca. {_n(plan.get('expected_spam'))}):")
    for src in plan.get("spam_sources") or []:
        where = clean(src.get("label"), 60) if src.get("kind") != "learn_list" else "enkeltmails lært som spam"
        out(f"  {clean(src.get('account'), 20):<20} {where:<34} {_n(src.get('messages')):>7} mails, "
            f"lærer {_n(src.get('planned'))}")
    if not plan.get("spam_sources"):
        out("  (ingen)")
    ratio = plan.get("ratio") or 2
    out(f"Legitime fra arkivmapper (ca. {_n(plan.get('expected_ham'))}, højst {ratio:g} pr. spam, nyeste først):")
    shown = [h for h in plan.get("ham_sources") or [] if int(h.get("planned") or 0) > 0]
    for h in shown:
        out(f"  {clean(h.get('account'), 20):<20} {clean(h.get('label'), 34):<34} {_n(h.get('messages')):>7} mails, "
            f"lærer {_n(h.get('planned'))}")
    if not shown:
        out("  (ingen)")
    out("Bruges aldrig som legitime: Indbakke, Sendt, Uønsket/Junk, Papirkurv, Kladder, Udbakke, RSS, "
        "Spamfilter-mappen og udbyderens spam-mappe.")
    for w in plan.get("warnings") or []:
        out(f"Bemærk: {clean(w, 300)}")
    out(clean(plan.get("text"), 1200))


def cmd_bayes_rebuild(args: argparse.Namespace) -> int:
    svc = _services()
    out("Læser mapperne i postkasserne (kun læsning) …")
    plan = svc.bayes_rebuild_plan(ACTOR, ratio=args.ratio)
    if not plan.get("ok"):
        raise CliError(clean(plan.get("text"), 300) or "Planen kunne ikke laves.")
    _print_plan(plan)
    if args.dry_run:
        out("Prøvekørsel – intet er ændret.")
        return EXIT_OK
    if plan.get("running"):
        raise CliError("En genopbygning er allerede i gang – se sfctl bayes-status.")
    if int(plan.get("expected_spam") or 0) <= 0:
        raise CliError("Der er ingen spam at lære fra – intet er ændret.")
    confirm(args, f"Byg Bayes op på ny i puljen {clean(plan.get('pool_new'))}? Den nuværende pulje "
                  f"({clean(plan.get('pool_now'))}) gemmes urørt og kan gendannes med sfctl bayes-restore.")
    res = svc.bayes_rebuild_start(ACTOR, confirm=True, ratio=args.ratio, save_config=ui.save_config)
    if not res.get("ok"):
        raise CliError(clean(res.get("text"), 300) or "Genopbygningen kunne ikke startes.")
    out(clean(res.get("text"), 600))
    out("Følg med: sfctl bayes-status   ·   Fortryd: sfctl bayes-restore")
    return EXIT_OK


def cmd_bayes_restore(args: argparse.Namespace) -> int:
    svc = _services()
    st = svc.bayes_rebuild_status()
    if not st.get("can_restore"):
        raise CliError("Der er ingen tidligere Bayes at gendanne."
                       + (f" {clean(st.get('text'), 400)}" if st.get("rebuild_id") else ""))
    confirm(args, f"Gendan den tidligere Bayes ({clean(st.get('pool_old'))})? Genopbygningens job stoppes, og "
                  f"puljen {clean(st.get('pool_new'))} lades urørt.")
    res = svc.bayes_restore_previous(ACTOR, confirm=True, save_config=ui.save_config)
    if not res.get("ok"):
        raise CliError(clean(res.get("text"), 300) or "Den tidligere Bayes kunne ikke gendannes.")
    out(clean(res.get("text"), 600))
    return EXIT_OK


def cmd_bayes_status(args: argparse.Namespace) -> int:
    svc = _services()
    st = svc.bayes_rebuild_status()
    stats = svc.bayes_stats()
    out(f"Aktiv Bayes-pulje: {clean(stats.get('pool')) or 'ukendt'}")
    if stats.get("ok"):
        src = "fra genopbygningens optælling" if stats.get("counts_source") == "pool" else "fra rspamd"
        out(f"  lært:          {_n(stats.get('spam_learned'))} spam · {_n(stats.get('ham_learned'))} legitime ({src})")
        out(f"  aktiv:         {'ja' if stats.get('active') else 'nej'} (kræver mindst {_n(stats.get('min_learns'))} "
            "af hver slags)")
    else:
        out("  rspamd svarer ikke – tallene kunne ikke hentes.")
    if st.get("rebuild_id"):
        out(f"Seneste genopbygning #{st['rebuild_id']}: {clean(st.get('pool_old'))} → {clean(st.get('pool_new'))}, "
            f"{svc._REBUILD_STATUS_TEXT.get(st.get('code'), clean(st.get('code')))}, startet {fmt_ts(st.get('created_at'))}")
        out(f"  lært:          {_n(st.get('learned_spam'))} af ca. {_n(st.get('expected_spam'))} spam · "
            f"{_n(st.get('learned_ham'))} af ca. {_n(st.get('expected_ham'))} legitime")
        jobs = st.get("jobs") or {}
        if jobs:
            out("  job:           " + ", ".join(f"{clean(k)} {v}" for k, v in sorted(jobs.items())))
    out(clean(st.get("text"), 800))
    return EXIT_OK


def _paused_accounts() -> list[str]:
    try:
        conn = _db()
        try:
            rows = conn.execute("SELECT key FROM settings_kv WHERE key LIKE 'sfctl_pause:%'").fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return []
    return sorted(str(r[0]).split(":", 1)[1] for r in rows)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

EPILOG = """\
Hjælp i en nødsituation (skriv det hele efter docker exec -it spamfilter):
  Glemt adgangskode:             sfctl reset-password NAVN --generate
  Mistet telefon/mail (to-trins): sfctl disable-2fa NAVN   (slår både app og kode på mail fra)
  Mailserveren driller:          sfctl smtp-status  /  sfctl smtp-disable  /  sfctl smtp-test ADRESSE
  Bayes lærer forkert:           sfctl bayes-rebuild --dry-run  (fortryd: sfctl bayes-restore)
  Spærret ude efter for mange forsøg:  sfctl unlock NAVN
  Kan ikke logge ind udefra:     sfctl login-scope NAVN overalt
  Der er ingen administrator:    sfctl create-admin NAVN --generate
  Filteret flytter forkert post: sfctl pause --all   (senere: sfctl resume --all)
  Home Assistant-nøgle lækket:   sfctl ha-token revoke   (ny: sfctl ha-token create)
  Beskeder på telefonen driller: sfctl push-status  /  sfctl push-test NAVN  /  sfctl push-reset
  Krypteret backup:              sfctl backup-now  /  sfctl backup-list  /  sfctl backup-key show
  Mistet telefon med passkey:    sfctl passkeys NAVN  /  sfctl passkeys-reset NAVN
  Domæner og mailservere:        sfctl mailcheck   (kun problemer: --problems, seneste: --last)
  Noget virker ikke:             sfctl doctor
Se navne med sfctl users og sfctl status. Hjælp til én kommando: sfctl <kommando> --help

Bruges kun fra værten som root:  docker exec -it spamfilter sfctl <kommando>
Alle ændringer skrives i revisionsloggen som 'cli' (ip 'local').
Exitkoder: 0 = ok, 1 = fejl eller afvist, 2 = forkert brug."""

# argparse's own (English) words -> Danish, for a non-technical owner.
_ARGPARSE_DA = (
    ("the following arguments are required:", "mangler:"),
    ("invalid choice:", "ugyldigt valg:"),
    ("choose from", "vælg mellem"),
    ("unrecognized arguments:", "ukendte argumenter:"),
    ("expected one argument", "kræver en værdi"),
    ("invalid int value:", "ikke et tal:"),
    ("not allowed with argument", "kan ikke bruges sammen med"),
    ("argument ", ""),
)


class _DanishHelp(argparse.RawDescriptionHelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):  # noqa: ANN001 - argparse signature
        return super().add_usage(usage, actions, groups, "brug: " if prefix is None else prefix)


class _Parser(argparse.ArgumentParser):
    def __init__(self, *a: Any, **kw: Any) -> None:
        kw.setdefault("formatter_class", _DanishHelp)
        parents = kw.pop("parents", [])
        super().__init__(*a, **kw)
        self._positionals.title = "argumenter"
        self._optionals.title = "valgmuligheder"
        # Parents only after the Danish titles, so their options land in the
        # same section (argparse matches groups by title).
        for parent in parents:
            self._add_container_actions(parent)
            self._defaults.update(getattr(parent, "_defaults", {}))

    def error(self, message: str):  # noqa: D401 - Danish usage errors, exit 2
        for en, da in _ARGPARSE_DA:
            message = message.replace(en, da)
        self.print_usage(sys.stderr)
        err(f"sfctl: fejl: {message}")
        err("Se sfctl --help (eller sfctl <kommando> --help).")
        raise SystemExit(EXIT_USAGE)


def build_parser() -> argparse.ArgumentParser:
    def common(suppress: bool) -> argparse.ArgumentParser:
        p = _Parser(add_help=False)
        p.add_argument("-h", "--help", action="help", default=argparse.SUPPRESS, help="vis denne hjælp")
        d = argparse.SUPPRESS if suppress else False
        p.add_argument("--yes", "-y", action="store_true", default=d,
                       help="spring bekræftelsen over ved farlige handlinger")
        p.add_argument("--allow-root", action="store_true", default=d,
                       help="tillad kørsel som root (filer gives tilbage til uid 10099)")
        return p

    parser = _Parser(prog="sfctl", parents=[common(False)], add_help=False,
                     description="Nødadgang til spamfilteret: nulstil adgang, stop filteret og tjek installationen.",
                     epilog=EPILOG)
    sub = parser.add_subparsers(dest="command", metavar="<kommando>", parser_class=_Parser, title="kommandoer")
    sub.required = True
    c = [common(True)]

    def add(name: str, helptext: str, fn: Callable[[argparse.Namespace], int]) -> argparse.ArgumentParser:
        p = sub.add_parser(name, parents=c, help=helptext, description=helptext, add_help=False)
        p.set_defaults(func=fn)
        return p

    add("status", "vis version, konti, hjerteslag, brugere og adgang udefra", cmd_status)
    add("users", "vis brugere med rolle, postkasser, rettigheder, 2-trin, sidste login og spærring", cmd_users)
    p = add("reset-password", "sæt en ny adgangskode (logger brugeren ud overalt og fjerner passkeys)",
            cmd_reset_password)
    p.add_argument("user", metavar="BRUGER", help="brugernavnet (se sfctl users)")
    p.add_argument("--generate", action="store_true", help="lav en stærk kode og vis den én gang")
    p = add("disable-2fa", "slå to-trins-login fra – både app og kode på mail (mistet telefon/mail)",
            cmd_disable_2fa)
    p.add_argument("user", metavar="BRUGER", help="brugernavnet (se sfctl users)")
    p.add_argument("--keep-required", action="store_true",
                   help="bevar kravet, så brugeren skal sætte to-trins-login op igen ved næste login")
    p = add("unlock", "ophæv login-spærringer for en bruger og/eller en IP", cmd_unlock)
    p.add_argument("user", metavar="BRUGER", nargs="?", help="brugernavnet (se sfctl users)")
    p.add_argument("--ip", metavar="IP", help="ophæv spærringen af denne IP-adresse (se sfctl users)")
    p.add_argument("--all", action="store_true", help="ophæv alle spærringer")
    p = add("logout-all", "log en bruger (eller alle) ud på alle enheder", cmd_logout_all)
    p.add_argument("user", metavar="BRUGER", nargs="?", help="brugernavnet; uden navn logges ALLE ud")
    p = add("create-admin", "opret en ny administrator", cmd_create_admin)
    p.add_argument("name", metavar="NAVN", help="det nye brugernavn (bogstaver, tal, punktum, - og _)")
    p.add_argument("--generate", action="store_true", help="lav en stærk kode og vis den én gang")
    p = add("set-role", "gør en bruger til administrator eller Bruger", cmd_set_role)
    p.add_argument("user", metavar="BRUGER", help="brugernavnet (se sfctl users)")
    p.add_argument("role", choices=("admin", "user"), metavar="admin|user",
                   help="admin = Administrator, user = Bruger")
    p = add("login-scope", "bestem, hvor en bruger må logge ind: overalt eller kun lokalt (hjemmenetværket)",
            cmd_login_scope)
    p.add_argument("user", metavar="BRUGER", help="brugernavnet (se sfctl users)")
    p.add_argument("scope", choices=tuple(LOGIN_SCOPE_ARGS), metavar="overalt|lokalt",
                   help="overalt = også udefra (Cloudflare Tunnel), lokalt = kun fra hjemmenetværket")
    p = add("pause", "nødstop: skift konto(er) til Overvåg og husk den gamle tilstand", cmd_pause)
    p.add_argument("account", metavar="KONTO", nargs="?", help="kontonavnet fra accounts.yml (se sfctl status)")
    p.add_argument("--all", action="store_true", help="alle konti")
    p = add("resume", "genskab den tilstand, pause huskede", cmd_resume)
    p.add_argument("account", metavar="KONTO", nargs="?", help="kontonavnet fra accounts.yml (se sfctl status)")
    p.add_argument("--all", action="store_true", help="alle konti, pause har husket")
    p.add_argument("--mode", choices=("move", "flag"), metavar="move|flag",
                   help="kun hvis intet er husket: move = Filtrér (flytter spam), flag = Markér")
    p = add("resume-moves", "genoptag flytning efter sikkerhedsbremsen", cmd_resume_moves)
    p.add_argument("account", metavar="KONTO", help="kontonavnet fra accounts.yml (se sfctl status)")
    p = add("external-url", "vis, sæt eller fjern den eksterne adresse", cmd_external_url)
    p.add_argument("url", metavar="URL", nargs="?", help="fx https://spam.eksempel.dk (uden URL: vis den)")
    p.add_argument("--clear", action="store_true", help="fjern adressen")
    p = add("audit", "vis de seneste linjer i revisionsloggen", cmd_audit)
    p.add_argument("--tail", type=int, default=30, metavar="N", help="antal linjer (standard 30)")
    add("smtp-status", "vis mailserver, seneste fejl, udbakke og notifikationer", cmd_smtp_status)
    add("smtp-disable", "nødstop: slå afsendelse af mail fra (indstillingerne bevares)", cmd_smtp_disable)
    p = add("smtp-test", "send en testmail nu med de gemte indstillinger", cmd_smtp_test)
    p.add_argument("to", metavar="ADRESSE", help="modtageren, fx din egen mailadresse")
    p = add("bayes-rebuild", "byg Bayes op på ny i en ny pulje (den gamle gemmes og kan gendannes)",
            cmd_bayes_rebuild)
    p.add_argument("--dry-run", action="store_true", help="vis kun planen – ændrer intet")
    p.add_argument("--ratio", type=float, default=2.0, metavar="N",
                   help="højst N legitime pr. spam (standard 2 = 1:2)")
    add("bayes-restore", "gendan den tidligere Bayes-pulje (stopper genopbygningen)", cmd_bayes_restore)
    add("bayes-status", "vis aktiv Bayes-pulje, lærte mails og genopbygningens fremskridt", cmd_bayes_status)
    p = add("ha-token", "alias: API-nøglen \"Home Assistant\" – opret (vises én gang), tilbagekald, status",
            cmd_ha_token)
    p.add_argument("action", choices=("create", "revoke", "status"), metavar="create|revoke|status",
                   help="create = ny nøgle (erstatter den gamle), revoke = tilbagekald, status = vis brug")
    p = add("api-key", "API-nøgler til programmer: vis, lav (vises én gang) eller slet én nøgle", cmd_api_key)
    p.add_argument("action", choices=("list", "create", "delete", "revoke"), metavar="list|create|delete",
                   help="list = vis alle, create = ny nøgle, delete ID = slet én (revoke er et alias)")
    p.add_argument("id", nargs="?", type=int, default=None, metavar="ID", help="nøglens nummer (til delete)")
    p.add_argument("--name", default="", metavar="NAVN", help="programmets navn, fx \"Kontrolrum\" (til create)")
    p.add_argument("--scope", default="read", choices=("read", "control", "admin"),
                   help="read = kun læse (standard), control = læse og styre, admin = administrator")
    p.add_argument("--anywhere", action="store_true",
                   help="må også bruges udefra (standard: kun fra hjemmenetværket)")
    p.add_argument("--expires", type=int, default=0, metavar="DAGE", help="udløber om DAGE dage (standard aldrig)")
    add("push-status", "vis enheder med beskeder (push), nøgle, kø og seneste fejl", cmd_push_status)
    p = add("push-test", "send en testbesked nu til alle en brugers enheder", cmd_push_test)
    p.add_argument("user", metavar="BRUGER", help="brugernavnet (se sfctl users)")
    add("push-reset", "nødstop: fjern alle enheder med beskeder og lav en ny nøgle (VAPID)", cmd_push_reset)
    p = add("policy-preview", "afprøv gemte policy-input lokalt uden mailhandlinger", cmd_policy_preview)
    p.add_argument("account", help="postkassens interne navn")
    p.add_argument("--threshold", type=float, default=None, help="prøv en anden scoregrænse; gemmes ikke")
    p.add_argument("--limit", type=int, default=100, help="seneste antal mails, 1–200 (standard 100)")
    p = add("quality-evaluate", "evaluér et lokalt mærket holdout-sæt uden træning", cmd_quality_evaluate)
    p.add_argument("file", help="lokal JSONL-fil; se CONFIGURATION.md")
    p = add("quality-reserve", "reservér lokal .eml mod fremtidig Bayes/fuzzy-læring", cmd_quality_reserve)
    p.add_argument("file", help="lokal mailfil, højst 10 MiB; indholdet gemmes ikke i registret")
    p.add_argument("--sample-id", required=True, help="neutralt ID, fx sample-001; ingen adresser eller emner")
    p = add("quality-compare", "sammenlign baseline/kandidat på samme lokale prøveudvalg", cmd_quality_compare)
    p.add_argument("baseline", help="lokal JSONL-fil med oprindelige afgørelser")
    p.add_argument("candidate", help="lokal JSONL-fil med kandidatens afgørelser på samme mails")
    p.add_argument("--false-positive-cost", type=int, default=10,
                   help="pris for fanget rigtig post relativt til overset spam (standard 10)")
    p.add_argument("--min-per-class", type=int, default=20,
                   help="mindst så mange ham og spam pr. postkasse (standard 20; ingen statistisk garanti)")
    p = add("quality-export", "eksportér eksplicitte brugerafgørelser lokalt (metadata, ingen mailtekst)", cmd_quality_export)
    p.add_argument("--to", required=True, help="ny fil; oprettes med mode 0600")
    p = add("backup-now", "lav en krypteret backup nu (ellers hver nat fra kl. 02:30)", cmd_backup_now)
    p.add_argument("--if-older", type=float, default=None, metavar="TIMER",
                   help="kun hvis den seneste vellykkede backup er ældre end TIMER timer")
    add("backup-list", "vis de krypterede backups i /backup", cmd_backup_list)
    p = add("backup-drill", "gendan midlertidigt og start app + Bayes isoleret uden mailarbejdere", cmd_backup_drill)
    p.add_argument("file", metavar="FIL")
    p.add_argument("--ask-key", action="store_true")
    p = add("backup-verify", "dekrypter en backup og tjek alle kontrolsummer (skriver intet)", cmd_backup_verify)
    p.add_argument("file", metavar="FIL", help="filnavnet fra sfctl backup-list (eller en sti)")
    p.add_argument("--ask-key", action="store_true", help="spørg efter nøglen (fra kode-manageren)")
    p = add("backup-restore", "gendan en backup til en NY mappe – den kørende installation røres ikke",
            cmd_backup_restore)
    p.add_argument("file", metavar="FIL", help="filnavnet fra sfctl backup-list (eller en sti)")
    p.add_argument("--to", required=True, metavar="MAPPE",
                   help="ny, tom mappe uden for installationen, fx /tmp/gendan-2026-11-02 "
                        "(ikke under /backup: de gendannede filer ligger i klar tekst)")
    p.add_argument("--ask-key", action="store_true", help="spørg efter nøglen (fra kode-manageren)")
    p = add("backup-key", "backupnøglen: vis den (kun én gang) eller vis status", cmd_backup_key)
    p.add_argument("action", choices=("show", "status"), metavar="show|status",
                   help="show = vis nøglen til din kode-manager, status = findes den, og er den vist")
    p.add_argument("--again", action="store_true", help="vis nøglen igen (kun hvis den er mistet)")
    p = add("passkeys", "vis en brugers passkeys (navn, adresse, oprettet, senest brugt)", cmd_passkeys)
    p.add_argument("user", metavar="BRUGER", help="brugernavnet (se sfctl users)")
    p = add("passkeys-reset", "nødstop: fjern alle en brugers passkeys (mistet telefon/nøgle)", cmd_passkeys_reset)
    p.add_argument("user", metavar="BRUGER", help="brugernavnet (se sfctl users)")
    p = add("mailcheck", "tjek jeres domæner (MX, SPF, DKIM, DMARC, DNSSEC), mailservere og blokeringslister",
            cmd_mailcheck)
    p.add_argument("--last", action="store_true", help="vis kun det seneste gemte tjek (intet netværk)")
    p.add_argument("--problems", action="store_true", help="vis kun fejl, advarsler og det, der ikke kunne testes")
    add("reload", "bed filteret om at genstarte pænt", cmd_reload)
    add("doctor", "tjek filer, rettigheder, konfiguration, database, rspamd, brugere, mailserver og beskeder",
        cmd_doctor)
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as ex:
        return int(ex.code) if isinstance(ex.code, int) else EXIT_USAGE
    if _euid() == 0 and not args.allow_root:
        err("sfctl kører ikke som root: filer i /state og /config skal blive ejet af uid 10099.\n"
            "Brug: docker exec -it spamfilter sfctl ...  (uden -u 0)\n"
            "Kun hvis containerbrugeren ikke virker: tilføj --allow-root.")
        return EXIT_ERR
    configure()
    if _euid() == 0 and (links := _root_symlinks()):
        err("sfctl --allow-root nægter at skrive gennem symbolske links: " + ", ".join(links)
            + "\nFjern dem (eller kør uden -u 0) og prøv igen.")
        return EXIT_ERR
    try:
        return int(args.func(args))
    except UsageError as ex:
        err(f"sfctl: {ex}")
        return EXIT_USAGE
    except CliError as ex:
        err(f"Fejl: {ex}")
        return EXIT_ERR
    except KeyboardInterrupt:
        err("Afbrudt.")
        return EXIT_ERR
    except UnicodeDecodeError:
        err("Fejl: en fil i /state eller /config er beskadiget (ikke gyldig tekst) – kør sfctl doctor.")
        return EXIT_ERR
    except (sqlite3.Error, OSError) as ex:
        err(f"Fejl: {type(ex).__name__} – kør sfctl doctor.")
        return EXIT_ERR
    finally:
        # Also after read-only commands: opening the DB as root can create
        # spamfilter.db / -wal / -shm, which the filter (10099) must own.
        _fix_ownership()


if __name__ == "__main__":
    sys.exit(main())
