"""Local site configuration (/config/site.yml).

Everything that belongs to ONE installation - the server's name, the
owner's own mail domains and webshops, the platform whose mail must always
get through, trusted forwarders, the admin address, the LAN address, the DNS
forwarder - lives here, on the server, next to accounts.yml. Nothing of it
is in the program, the image or the repository.

  * A fresh all-in-one install gets an empty (neutral) copy from the first
    start (aio_render.py init) with `setup_done: false`; the WebUI then asks
    for what is needed (Indstillinger -> Lokal opsætning).
  * The file is only ever written by an admin's save in the WebUI
    (save(): validation, atomic replace, 0600, unknown keys kept). An update
    or a restart never writes it, never merges defaults over it.
  * Missing on an existing install (an update installed before the
    migration script ran): the filter keeps running with empty values, the
    WebUI shows "Lokal opsætning mangler" - nothing crashes.
  * Unreadable / invalid YAML: the same, with "Lokal opsætning kan ikke
    læses".

The rspamd maps that need these values (own domains in the URL blocklist
whitelist, brand domains, phishing-feed exclusions) are generated from this
file at every container start (aio_render.py site + rspamd).

Stdlib + PyYAML. Never logs values, only key names and counts.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Any

log = logging.getLogger("siteconfig")

FILE_NAME = "site.yml"
MAX_ITEMS = 50
DEFAULT_MSGID_DOMAIN = "spamfilter.invalid"
DEFAULT_RECEIPT_FROM = f"Spamfilter <noreply@{DEFAULT_MSGID_DOMAIN}>"
DEFAULT_CONTACTS_KEY_LABEL = "spamfilter-contacts-key:"

# key -> (kind, label shown in the WebUI). Order = order in the file/UI.
FIELDS: dict[str, tuple[str, str]] = {
    "server_name": ("text", "Serverens navn"),
    "admin_email": ("email", "Administratorens mailadresse"),
    "mail_domains": ("domains", "Egne maildomæner"),
    "webshop_domains": ("domains", "Egne webshops og hjemmesider"),
    "platform_domains": ("domains", "Platforme, hvis mail altid skal igennem"),
    "protected_domains": ("domains", "Beskyttede domæner (standard)"),
    "trusted_forwarders": ("hosts", "Betroede videresendere"),
    "mailcheck_domains": ("domains", "Ekstra domæner til Mailsikkerhed"),
    "mailcheck_no_mail": ("domains", "Domæner der ikke sender mail"),
    "domain_providers": ("providers", "Udbyder pr. domæne"),
    "imap_presets": ("presets", "Mailserver pr. domæne"),
    "lan_url": ("url", "Filterets adresse på hjemmenetværket"),
    "dns_forwarders": ("ips", "Navneserver på hjemmenetværket"),
    "msgid_domain": ("hostname", "Domæne i filterets egne Message-ID'er"),
    "receipt_from": ("text", "Afsender på kvitteringer"),
    "contacts_key_label": ("text", "Nøgle-mærke for kendte kontakter"),
    "setup_done": ("bool", "Opsætningen er gennemgået"),
}
LIST_KINDS = ("domains", "hosts", "ips")
MAP_KINDS = ("providers", "presets")
# Technical keys a migrated install carries so it keeps working exactly as
# before; not shown as ordinary fields (only under "Avanceret").
COMPAT_KEYS = ("msgid_domain", "receipt_from", "contacts_key_label")

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")
HOST_RE = DOMAIN_RE
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                      r"[a-z][a-z0-9-]{0,62}$")
URL_RE = re.compile(r"^https?://[A-Za-z0-9.\-\[\]:]+(?::\d{1,5})?/?$")
TEXT_MAX = 120
CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


def site_path() -> Path:
    env = os.environ.get("SITE_CONFIG_PATH")
    if env:
        return Path(env)
    return Path(os.environ.get("CONFIG_PATH", "/config/accounts.yml")).parent / FILE_NAME


def empty() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, (kind, _label) in FIELDS.items():
        out[key] = [] if kind in LIST_KINDS else {} if kind in MAP_KINDS else False if kind == "bool" else ""
    return out


# --------------------------------------------------------------- validation
def _ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _check_item(kind: str, v: str) -> bool:
    if kind == "domains":
        return bool(DOMAIN_RE.match(v))
    if kind == "hosts":
        return bool(HOST_RE.match(v)) or _ip(v)
    if kind == "ips":
        return _ip(v)
    return False


def clean_list(kind: str, raw: Any) -> tuple[list[str], list[str]]:
    """'a.dk, b.dk\\nc.dk' or a list -> (clean unique values, invalid)."""
    if raw is None:
        return [], []
    items = re.split(r"[\s,;]+", raw) if isinstance(raw, str) else list(raw) if isinstance(raw, (list, tuple)) else [raw]
    out: list[str] = []
    bad: list[str] = []
    for item in items:
        v = str(item or "").strip().lower().rstrip(".")
        if not v:
            continue
        if kind == "domains" and v.startswith("@"):
            v = v[1:]
        if not _check_item(kind, v):
            bad.append(str(item)[:80])
        elif v not in out:
            out.append(v)
    if len(out) > MAX_ITEMS:
        bad.append(f"højst {MAX_ITEMS}")
        out = out[:MAX_ITEMS]
    return out, bad


def clean_value(key: str, raw: Any) -> tuple[Any, list[str]]:
    """One field -> (clean value, problems). Unknown keys are refused."""
    if key not in FIELDS:
        return None, [f"ukendt felt {key}"]
    kind, label = FIELDS[key]
    if kind in LIST_KINDS:
        val, bad = clean_list(kind, raw)
        return val, [f"{label}: ugyldig værdi {b!r}" for b in bad]
    if kind == "bool":
        return bool(raw) if not isinstance(raw, str) else raw.strip().lower() in ("1", "true", "yes", "ja", "on"), []
    if kind == "providers":
        if raw in (None, ""):
            return {}, []
        if not isinstance(raw, dict):
            return {}, [f"{label}: skal være domæne: udbyder"]
        out: dict[str, str] = {}
        bad: list[str] = []
        for d, p in raw.items():
            dd, pp = str(d or "").strip().lower(), str(p or "").strip()
            if not DOMAIN_RE.match(dd) or not pp or len(pp) > 60 or CTRL_RE.search(pp):
                bad.append(f"{label}: ugyldig linje {dd!r}")
            else:
                out[dd] = pp
        return out, bad
    if kind == "presets":
        if raw in (None, ""):
            return {}, []
        if not isinstance(raw, dict):
            return {}, [f"{label}: skal være domæne: server"]
        out2: dict[str, dict[str, Any]] = {}
        bad = []
        for d, spec in raw.items():
            dd = str(d or "").strip().lower()
            spec = spec if isinstance(spec, dict) else {"imap_host": spec}
            host = str(spec.get("imap_host") or "").strip().lower()
            try:
                port = int(spec.get("imap_port") or 993)
            except (TypeError, ValueError):
                port = -1
            prov = str(spec.get("provider") or "").strip()
            if not DOMAIN_RE.match(dd) or not HOST_RE.match(host) or not 0 < port < 65536 \
                    or len(prov) > 60 or CTRL_RE.search(prov):
                bad.append(f"{label}: ugyldig linje {dd!r}")
                continue
            item: dict[str, Any] = {"imap_host": host, "imap_port": port}
            if prov:
                item["provider"] = prov
            out2[dd] = item
        return out2, bad
    v = "" if raw is None else str(raw).strip()
    if not v:
        return "", []
    if CTRL_RE.search(v) or len(v) > (200 if key == "receipt_from" else TEXT_MAX):
        return "", [f"{label}: for lang eller ugyldige tegn"]
    if kind == "email":
        v = v.lower()
        return (v, []) if EMAIL_RE.match(v) else ("", [f"{label}: ikke en gyldig mailadresse"])
    if kind == "url":
        v = v.rstrip("/")
        return (v, []) if URL_RE.match(v + "/") else ("", [f"{label}: skriv fx http://192.168.1.10:18080"])
    if kind == "hostname":
        v = v.lower()
        return (v, []) if DOMAIN_RE.match(v) else ("", [f"{label}: ikke et gyldigt domænenavn"])
    return v, []


def validate(data: Any) -> tuple[dict[str, Any], list[str]]:
    """A loaded/posted mapping -> (clean values for every known key,
    problems). Unknown keys are ignored here (save() keeps them)."""
    out = empty()
    problems: list[str] = []
    if data is None:
        return out, problems
    if not isinstance(data, dict):
        return out, ["filen er ikke en liste af nøgler og værdier"]
    for key in FIELDS:
        if key in data:
            val, bad = clean_value(key, data[key])
            out[key] = val
            problems.extend(bad)
    return out, problems


# --------------------------------------------------------------- loading
class Site:
    """The loaded configuration: values (always every key) + status."""

    def __init__(self, values: dict[str, Any], status: str, problems: list[str] | None = None,
                 path: Path | None = None) -> None:
        self.values = values
        self.status = status          # ok | missing | invalid
        self.problems = list(problems or [])
        self.path = path

    def get(self, key: str) -> Any:
        return self.values.get(key, empty().get(key))

    def list(self, key: str) -> list[str]:
        return list(self.values.get(key) or [])


def load(path: Path | None = None) -> Site:
    p = Path(path) if path is not None else site_path()
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return Site(empty(), "missing", path=p)
    except OSError as ex:
        log.warning("site config %s unreadable: %s", p.name, type(ex).__name__)
        return Site(empty(), "invalid", [f"filen kan ikke læses ({type(ex).__name__})"], path=p)
    try:
        import yaml  # noqa: PLC0415 - aio_render imports this module without the app's path

        data = yaml.safe_load(text)
    except Exception as ex:  # noqa: BLE001 - any YAML error = invalid, never a crash
        log.warning("site config %s is not valid YAML: %s", p.name, type(ex).__name__)
        return Site(empty(), "invalid", ["filen er ikke gyldig YAML"], path=p)
    values, problems = validate(data if data is not None else {})
    if problems:
        log.warning("site config %s: %d invalid value(s) ignored", p.name, len(problems))
    if not isinstance(data, (dict, type(None))):
        return Site(empty(), "invalid", problems, path=p)
    return Site(values, "ok", problems, path=p)


CURRENT = load()


def reload() -> Site:
    global CURRENT
    CURRENT = load()
    return CURRENT


def get(key: str) -> Any:
    return CURRENT.get(key)


def get_list(key: str) -> list[str]:
    return CURRENT.list(key)


def status() -> str:
    return CURRENT.status


# --------------------------------------------------------------- effective values
def server_name() -> str:
    return str(CURRENT.get("server_name") or "")


def brand(sep: str = " · ") -> str:
    """'Spamfilter · <server>' or plain 'Spamfilter'."""
    name = server_name()
    return f"Spamfilter{sep}{name}" if name else "Spamfilter"


def signature() -> str:
    name = server_name()
    return f"– Spamfilteret på {name}" if name else "– Spamfilteret"


def msgid_domain() -> str:
    return str(CURRENT.get("msgid_domain") or DEFAULT_MSGID_DOMAIN)


def receipt_from() -> str:
    return str(CURRENT.get("receipt_from") or DEFAULT_RECEIPT_FROM)


def contacts_key_label() -> bytes:
    return str(CURRENT.get("contacts_key_label") or DEFAULT_CONTACTS_KEY_LABEL).encode("utf-8")


def own_domains() -> list[str]:
    """Mail domains + webshops (without the multi-tenant platforms)."""
    plat = set(get_list("platform_domains"))
    out: list[str] = []
    for d in (*get_list("mail_domains"), *get_list("webshop_domains")):
        if d not in plat and d not in out:
            out.append(d)
    return out


def rspamd_values(site: Site | None = None) -> dict[str, list[str]]:
    """What the rspamd maps need (aio_render.py site): plain lists."""
    s = site or CURRENT
    mail, shops, plat = s.list("mail_domains"), s.list("webshop_domains"), s.list("platform_domains")
    surbl = [d for d in dict.fromkeys([*mail, *shops]) if d not in set(plat)]
    feed = list(dict.fromkeys([*shops, *[p for p in plat if p not in shops]]))
    return {
        "brand_domains": list(mail),
        "surbl_whitelist": surbl,
        "phishing_feed_exclusion": feed,
        "phisharmy_exclusion": list(dict.fromkeys([*feed, *mail])),
        "dns_forwarders": s.list("dns_forwarders"),
    }


# --------------------------------------------------------------- saving
HEADER = ("# Lokal opsætning af spamfilteret (kun på denne server - aldrig i programmet).\n"
          "# Rettes i WebUI'en under Indstillinger -> Lokal opsætning. En opdatering\n"
          "# ændrer eller nulstiller aldrig denne fil.\n")


def _yaml_dump(data: dict[str, Any]) -> str:
    import yaml  # noqa: PLC0415

    return HEADER + yaml.safe_dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False)


def render_new(values: dict[str, Any] | None = None) -> str:
    """Text of a NEW site.yml (fresh install seed / migration)."""
    data = empty()
    if values:
        clean, _bad = validate(values)
        data.update({k: v for k, v in clean.items() if k in values})
    return _yaml_dump(data)


def save(changes: dict[str, Any], path: Path | None = None) -> tuple[bool, list[str]]:
    """Validate CHANGES (only the keys given), merge them into the file's
    current content (other and unknown keys kept as they are) and replace
    the file atomically (0600). Returns (saved, problems)."""
    p = Path(path) if path is not None else site_path()
    problems: list[str] = []
    clean: dict[str, Any] = {}
    for key, raw in changes.items():
        val, bad = clean_value(key, raw)
        problems.extend(bad)
        clean[key] = val
    if problems:
        return False, problems
    current: dict[str, Any] = {}
    if p.is_file():
        import yaml  # noqa: PLC0415

        try:
            loaded = yaml.safe_load(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return False, ["den gemte fil kan ikke læses – ret den på serveren først"]
        if isinstance(loaded, dict):
            current = loaded
        elif loaded is not None:
            return False, ["den gemte fil kan ikke læses – ret den på serveren først"]
    else:
        current = empty()
    current.update(clean)
    text = _yaml_dump(current)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".site-", suffix=".yml", dir=str(p.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)
    finally:
        tmp.unlink(missing_ok=True)
    log.info("site config saved: %s", ", ".join(sorted(clean)) or "-")
    return True, []
