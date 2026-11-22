"""Mailsikkerhed (2.7) - an MXToolbox-like check of the owner's own domains
and mail servers - spamfilter.

Which domains: every mailbox address's domain, the owner/shop platform
domains of accounts.yml, the DMARC page's domains (dmarc settings) and an
admin-edited list (settings_kv 'mailcheck'); a domain can be skipped or
marked "sender ikke mail" (then SPF should be "v=spf1 -all" and DMARC
p=reject, and no DKIM is needed).

Per domain (each result: ok / info / warn / bad / unknown = could not be
tested, a plain Danish explanation and a concrete fix naming the provider
where it is known):

  * MX present (or deliberately none), the MX hosts resolve, PTR/forward
    of the MX addresses;
  * SPF: exactly one record, syntax, "-all", at most 10 DNS lookups
    (every include/a/mx/ptr/exists/redirect occurrence counts, also a
    repeated include; a loop is only a reference back to a domain on the
    current path) and at most 2 void lookups, the deprecated spf2.0/pra
    record (info);
  * DKIM: selectors of PASSING signatures in real delivered mail (rspamd
    R_DKIM_ALLOW options "domain:s=selector" in messages.symbols, DMARC
    report rows with dkim=pass), remembered across runs and forgotten
    after 60 days unseen, plus admin selectors (kept); the key exists and
    is >= 1024 bit (2048 recommended). A sending domain whose own mail of
    the last 30 days carried no aligned signature is an error;
  * DMARC: present, syntax, policy (p=none = warning with the DMARC page's
    advice), rua, the RFC 7489 7.1 permission record for an external rua
    domain; MTA-STS / TLS-RPT (info, optional), DNSSEC (the AD flag of the
    stack's validating Unbound; a control query shows whether it
    validates at all; SERVFAIL counts as broken DNSSEC only when the same
    query with CD - checking disabled - answers), a wildcard that answers
    _dmarc/_domainkey/_mta-sts (info).

Mail servers (every MX, the SMTP submission host of the mailer settings,
the accounts' IMAP hosts): TCP connect, STARTTLS/TLS, certificate valid
for the host name, days to expiry (warn < 21, bad < 7), TLS >= 1.2. Names
are resolved through the same Unbound, only global addresses are probed
(SSRF), each probe has a 20 s deadline. "Kunne ikke testes", not an error:
port 25 blocked by the ISP, a server refusing the test connection (554
banner, rejected EHLO, reset - normal from a home IP), an internal
address, and connect errors when no server answers at all (offline).

Blacklists: the providers' OUTBOUND relays actually seen - sending IPs of
the owner's own delivered mail that passed SPF for the domain and that the
domain's SPF authorises (never an authenticated submission's client, never
a DKIM-only sender) and the DMARC reports' SPF-passing sources - plus the
MX addresses, against a small set of DNSBLs via the same Unbound,
rate-limited, with their own share of the query budget. Spamhaus
127.255.255.x answers (public resolver / too many queries) are "kunne ikke
slås op"; PBL (127.0.0.10/11, dynamic ranges) is info.

DNS goes through dnspython (filter/requirements.txt) to
$MAILCHECK_DNS_SERVER:$MAILCHECK_DNS_PORT, else the lookalike resolver
($LOOKALIKE_DNS_SERVER/_PORT; the all-in-one image: 127.0.0.1:5353), with
a short timeout and a per-run query budget. dnspython is imported lazily:
everything but DnsPythonResolver works (and is tested) without it.

Each run is stored as JSON (mailcheck_runs, the last RUN_KEEP runs). A run
alerts through the engine's alert_once (mail + 'problem' push) only on a
regression against the last KNOWN level of a check (ok -> warn/bad, warn
-> bad) that was also seen in the previous tested run (two in a row), and
at once on a real listing of a provider's sending address and on a
certificate with < 7 days left; mailcheck_alerted de-duplicates (a problem
is mailed again only after it was fixed in between, or when it gets
worse), and a problem alerted within 7 days is not alerted again when it
flaps back. A finding counts as told only after a successful send.
"Could not test" never counts as fixed or as broken; an offline/degraded
run (control queries fail, or most DNS queries fail) is "unknown" as a
whole and changes no alert state. Findings marked "Kendt – ignorér" (by
fingerprint) are info and never alert until they change. The first run is
the baseline. One run has a 10-minute deadline.

The engine runs it nightly (RUN_HOURS, Copenhagen) in its own thread and
within a minute of "Tjek nu" (request flag in mailcheck_state; only a
scheduled run moves the nightly schedule, and a running_since left by a
crashed run is cleared at start-up / ignored after the deadline); sfctl
`mailcheck` runs it in the foreground. The WebUI page (ui_mailcheck.py)
only reads stored runs: opening it never touches the network.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import socket
import sqlite3
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from email.utils import parseaddr
from typing import Any, Callable, Iterable, Sequence

import siteconfig

log = logging.getLogger("mailcheck")

SETTINGS_KEY = "mailcheck"
RESULTS_VERSION = 1
RUN_KEEP = 60                      # stored runs
HISTORY = 30                       # runs shown on the page
WINDOW_DAYS = 30                   # own mail / DMARC reports looked at
MAX_DOMAINS = 30
MAX_SELECTORS = 6                  # per domain
MAX_EXTRA = 50                     # admin list entries
DNS_TIMEOUT_S = 2.0
TCP_TIMEOUT_S = 8.0
PROBE_DEADLINE_S = 20.0            # one TLS probe in total (connect, dialogue, both handshakes)
RUN_DEADLINE_S = 600.0             # one whole run; also when running_since counts as stale
MAX_DNS_QUERIES = 800              # per run (SPF expansion included) - at least
RUN_BASE_QUERIES = 100             # per-run budget: base + per domain (+ the blacklist step's reserve)
RUN_DOMAIN_QUERIES = 150
SPF_MAX_LOOKUPS = 10               # RFC 7208 4.6.4
SPF_MAX_VOID = 2
SPF_MAX_DEPTH = 10
SPF_EXPAND_CAP = 40                # stop expanding a tree that is far over the limit anyway
DKIM_MIN_BITS = 1024
DKIM_GOOD_BITS = 2048
DKIM_PARTIAL_MIN = 3               # unsigned own mails before "only some are signed"
SELECTOR_FORGET_DAYS = 60          # a learned selector not seen this long is forgotten
SELECTOR_FRESH_DAYS = 14           # a missing key of a selector seen this recently is an error
CERT_WARN_DAYS = 21
CERT_BAD_DAYS = 7
SERVER_WORKERS = 4
MAX_SERVERS = 24
DNSBL_ZONES = (("zen.spamhaus.org", "Spamhaus ZEN"), ("bl.spamcop.net", "SpamCop"),
               ("b.barracudacentral.org", "Barracuda"), ("psbl.surriel.com", "PSBL"))
DNSBL_MAX_IPS = 16
DNSBL_RATE_S = 0.25                # pause before every DNSBL query
RUN_HOURS = (5,)                   # nightly, Copenhagen time (backup 02:30, lookalike 03-04)
POLL_S = 60
RETRY_S = 3600                     # after a failed/aborted run
MIN_GAP_S = 20 * 3600              # a scheduled run at most once per night
REQUEST_STALE_S = 15 * 60          # a request no engine picked up is shown as stale
ALERT_KEY = "mailcheck"            # filter.alert_once key -> push.PROBLEMS['mailcheck']
FLAP_S = 7 * 86400                 # a problem alerted this recently is not alerted again after a fix
ALERT_MAX_RETRIES = 3              # failed sends retried on this many runs, then given up
DNS_SERVER_ENV = "MAILCHECK_DNS_SERVER"
DNS_PORT_ENV = "MAILCHECK_DNS_PORT"
HELO_ENV = "MAILCHECK_HELO"
HELO_NAME = "mailcheck.invalid"    # last resort only (no external address, no FQDN)
# Offline / degraded run: both control queries fail, or this share of the
# domain checks' DNS queries failed.
CONTROL_QUERIES = (("dk", "SOA"), ("com", "SOA"))
DEGRADED_RATIO = 0.5
DEGRADED_MIN_QUERIES = 8

# Extra domains to check and domains that send no mail ("sender ikke mail"
# until the admin changes it) - defaults from the local site config.
DEFAULT_DOMAINS = tuple(siteconfig.get_list("mailcheck_domains"))
DEFAULT_NO_MAIL = tuple(siteconfig.get_list("mailcheck_no_mail"))
# Known mail providers of the owner's domains (fix texts name them) - from
# the local site config (domain: provider).
KNOWN_PROVIDERS: dict[str, str] = dict(siteconfig.get("domain_providers") or {})
# host / SPF include suffix -> provider name
PROVIDER_SUFFIXES = (
    ("gigahost.dk", "Gigahost"), ("scannet.dk", "Scannet"), ("scannet.net", "Scannet"),
    ("antispamcloud.com", "Scannet (SpamExperts)"), ("spamexperts.com", "Scannet (SpamExperts)"),
    ("cloudflare.com", "Cloudflare"), ("cloudflare.net", "Cloudflare"),
    ("google.com", "Google Workspace"), ("googlemail.com", "Google Workspace"),
    ("outlook.com", "Microsoft 365"), ("office365.us", "Microsoft 365"),
    ("one.com", "One.com"), ("simply.com", "Simply.com"), ("unoeuro.com", "Simply.com"),
    ("dandomain.dk", "DanDomain"), ("zoho.com", "Zoho"), ("zoho.eu", "Zoho"), ("sendgrid.net", "SendGrid"),
    ("mailgun.org", "Mailgun"), ("amazonses.com", "Amazon SES"), ("mcsv.net", "Mailchimp"),
)

OK, INFO, WARN, BAD, UNKNOWN = "ok", "info", "warn", "bad", "unknown"
STATUSES = (OK, INFO, WARN, BAD, UNKNOWN)
LEVEL = {OK: 0, INFO: 0, WARN: 1, BAD: 2}           # UNKNOWN has no level
LABEL = {OK: "OK", INFO: "Info", WARN: "Advarsel", BAD: "Fejl", UNKNOWN: "Ikke testet"}
TONE = {OK: "ok", INFO: "info", WARN: "warn", BAD: "bad", UNKNOWN: "neutral"}
SOURCE_TEXT = {"postkasse": "postkasse", "platform": "platform", "webshop": "webshop",
               "dmarc": "DMARC-siden", "tilføjet": "tilføjet her"}
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
_SELECTOR_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,62})$")
_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)*"
                      r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


# ---------------------------------------------------------------- helpers
def clean_domain(value: Any) -> str | None:
    d = str(value or "").strip().strip(".").lower()
    if not d or len(d) > 253:
        return None
    if not d.isascii():
        try:
            d = d.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            return None
    return d if _DOMAIN_RE.match(d) else None


def clean_selector(value: Any) -> str | None:
    s = str(value or "").strip()
    return s if _SELECTOR_RE.match(s) else None


def under(host: str | None, domain: str | None) -> bool:
    """host is domain or a subdomain of it (relaxed alignment)."""
    h, d = str(host or "").lower().rstrip("."), str(domain or "").lower().rstrip(".")
    return bool(h and d) and (h == d or h.endswith("." + d))


def item(key: str, area: str, status: str, text: str, fix: str = "", **extra: Any) -> dict[str, Any]:
    out = {"key": key, "area": area, "status": status if status in STATUSES else UNKNOWN,
           "text": str(text)[:600], "fix": str(fix or "")[:600]}
    out.update(extra)
    return out


def worst(statuses: Iterable[str]) -> str:
    best, rank = OK, -1
    for s in statuses:
        r = {OK: 0, INFO: 1, UNKNOWN: 2, WARN: 3, BAD: 4}.get(s, 2)
        if r > rank:
            best, rank = s, r
    return best


def provider_of(*hosts: Any) -> str | None:
    for host in hosts:
        h = str(host or "").lower().rstrip(".")
        for suffix, name in PROVIDER_SUFFIXES:
            if under(h, suffix):
                return name
    return None


def _hos(name: str | None, fallback: str) -> str:
    return f"hos {name}" if name else fallback


def _n(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


# ---------------------------------------------------------------- settings
def normalize_settings(raw: Any) -> dict[str, Any]:
    """{domains[], no_mail[], skip[], selectors{domain: [sel]}}. Missing
    keys (never saved) = the defaults."""
    raw = raw if isinstance(raw, dict) else {}

    def domains(key: str, default: Sequence[str]) -> list[str]:
        vals = raw.get(key) if isinstance(raw.get(key), list) else (list(default) if key not in raw else [])
        out: list[str] = []
        for v in vals:
            cd = clean_domain(v)
            if cd and cd not in out:
                out.append(cd)
        return out[:MAX_EXTRA]

    sels: dict[str, list[str]] = {}
    src = raw.get("selectors") if isinstance(raw.get("selectors"), dict) else {}
    for d, lst in list(src.items())[:MAX_EXTRA]:
        cd = clean_domain(d)
        if not cd or not isinstance(lst, list):
            continue
        clean = [s for s in (clean_selector(x) for x in lst) if s]
        if clean:
            sels[cd] = list(dict.fromkeys(clean))[:MAX_SELECTORS]
    return {"domains": domains("domains", DEFAULT_DOMAINS), "no_mail": domains("no_mail", DEFAULT_NO_MAIL),
            "skip": domains("skip", ()), "selectors": sels}


def load_settings(conn: sqlite3.Connection | None) -> dict[str, Any]:
    raw: Any = None
    if conn is not None:
        try:
            row = conn.execute("SELECT value FROM settings_kv WHERE key=?", (SETTINGS_KEY,)).fetchone()
            raw = json.loads(row[0]) if row and row[0] else None
        except (sqlite3.Error, ValueError, TypeError):
            raw = None
    return normalize_settings(raw)


def _dmarc_mod() -> Any:
    import dmarc  # noqa: PLC0415 - stdlib only; DMARC settings + report tables

    return dmarc


def domain_targets(accounts: Iterable[Any], settings: dict[str, Any],
                   dmarc_cfg: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """The domains to check: [{domain, sources[], no_mail}] in a stable
    order (mailboxes first)."""
    skip = set(settings.get("skip") or [])
    no_mail = set(settings.get("no_mail") or [])
    out: dict[str, dict[str, Any]] = {}

    def add(value: Any, source: str) -> None:
        d = clean_domain(value)
        if not d or d in skip:
            return
        e = out.setdefault(d, {"domain": d, "sources": [], "no_mail": d in no_mail})
        if source not in e["sources"]:
            e["sources"].append(source)

    accounts = list(accounts or ())
    for a in accounts:
        add(str(getattr(a, "user", "") or "").rpartition("@")[2], "postkasse")
    for a in accounts:
        for d in getattr(a, "owner_platform_domains", None) or []:
            add(d, "platform")
        for d in getattr(a, "webshop_domains", None) or []:
            add(d, "webshop")
    if dmarc_cfg:
        for d in dmarc_cfg.get("domains") or []:
            add(d, "dmarc")
        add(str(dmarc_cfg.get("rua") or "").rpartition("@")[2], "dmarc")
    for d in settings.get("domains") or []:
        add(d, "tilføjet")
    return list(out.values())[:MAX_DOMAINS]


# ---------------------------------------------------------------- DNS
@dataclass
class Answer:
    status: str                          # ok | nodata | nxdomain | error
    records: list[str] = field(default_factory=list)
    ad: bool = False                     # validated by the resolver (DNSSEC)
    cnames: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def failed(self) -> bool:
        return self.status == "error"


LIMIT_ERRORS = frozenset({"limit", "deadline"})    # not asked at all (budget / run deadline)


class Resolver:
    """Per-run cache + query budget + optional deadline in front of `_ask`
    (subclasses / tests). Never raises: a failure is Answer('error').
    `failures` counts answered-with-error queries, `limited` the ones not
    asked because of the budget or the deadline."""

    def __init__(self, *, max_queries: int = MAX_DNS_QUERIES) -> None:
        self.max_queries = int(max_queries)
        self.queries = 0
        self.failures = 0
        self.limited = 0
        self.deadline: float | None = None          # time.monotonic() value
        self._cache: dict[tuple[str, str, bool], Answer] = {}
        self._lock = threading.Lock()

    def _ask(self, name: str, rdtype: str) -> Answer:  # pragma: no cover - overridden
        raise NotImplementedError

    def _ask_cd(self, name: str, rdtype: str) -> Answer:
        """The same query with CD (checking disabled); resolvers that cannot
        do it answer 'unsupported' (= could not be tested)."""
        return Answer("error", error="unsupported")

    def query(self, name: str, rdtype: str, *, cd: bool = False) -> Answer:
        key = (str(name).lower().rstrip("."), str(rdtype).upper(), bool(cd))
        with self._lock:
            if key in self._cache:
                return self._cache[key]
            if self.deadline is not None and time.monotonic() > self.deadline:
                self.limited += 1
                return Answer("error", error="deadline")
            if self.queries >= self.max_queries:
                self.limited += 1
                return Answer("error", error="limit")
            self.queries += 1
        try:
            ans = (self._ask_cd if cd else self._ask)(key[0] + ".", key[1])
        except Exception as ex:  # noqa: BLE001 - a lookup never breaks a run
            ans = Answer("error", error=type(ex).__name__)
        with self._lock:
            self._cache[key] = ans
            if ans.failed:
                self.failures += 1
        return ans


def default_dns_server() -> str:
    raw = (os.environ.get(DNS_SERVER_ENV) or "").strip()
    if raw:
        return raw
    try:
        import lookalike  # noqa: PLC0415

        return lookalike.default_server()
    except Exception:  # noqa: BLE001
        return "127.0.0.1"


def default_dns_port() -> int:
    raw = (os.environ.get(DNS_PORT_ENV) or "").strip()
    if raw:
        try:
            p = int(raw)
            if 0 < p < 65536:
                return p
        except ValueError:
            pass
    try:
        import lookalike  # noqa: PLC0415

        return int(lookalike.default_port())
    except Exception:  # noqa: BLE001
        return 53


class DnsPythonResolver(Resolver):
    """dnspython against ONE recursive resolver (the stack's own Unbound).
    Asks with DO + AD so a validating resolver reports the AD flag.
    `transport(query, server, port, timeout, tcp)` replaces the network in
    tests."""

    def __init__(self, server: str | None = None, port: int | None = None, *, timeout: float = DNS_TIMEOUT_S,
                 transport: Callable[..., Any] | None = None, max_queries: int = MAX_DNS_QUERIES) -> None:
        super().__init__(max_queries=max_queries)
        self.server = server or default_dns_server()
        self.port = int(port if port is not None else default_dns_port())
        self.timeout = float(timeout)
        self.transport = transport
        self._addr: str | None = None

    def _server_addr(self) -> str:
        if self._addr is None:
            try:
                ipaddress.ip_address(self.server)
                self._addr = self.server
            except ValueError:  # 4-container layout: the container name
                self._addr = socket.getaddrinfo(self.server, self.port, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
        return self._addr

    def _send(self, q: Any, tcp: bool) -> Any:
        if self.transport is not None:
            return self.transport(q, self._server_addr(), self.port, self.timeout, tcp)
        import dns.query  # noqa: PLC0415

        fn = dns.query.tcp if tcp else dns.query.udp
        return fn(q, self._server_addr(), timeout=self.timeout, port=self.port)

    def _ask_cd(self, name: str, rdtype: str) -> Answer:
        return self._ask(name, rdtype, cd=True)

    def _ask(self, name: str, rdtype: str, cd: bool = False) -> Answer:
        import dns.exception  # noqa: PLC0415
        import dns.flags  # noqa: PLC0415
        import dns.message  # noqa: PLC0415
        import dns.rcode  # noqa: PLC0415
        import dns.rdatatype  # noqa: PLC0415

        want = dns.rdatatype.from_text(rdtype)
        q = dns.message.make_query(name, want, want_dnssec=True)
        q.flags |= dns.flags.AD
        if cd:
            q.flags |= dns.flags.CD
        try:
            r = self._send(q, False)
            if r.flags & dns.flags.TC:
                r = self._send(q, True)
        except dns.exception.Timeout:
            return Answer("error", error="timeout")
        except (OSError, dns.exception.DNSException) as ex:
            return Answer("error", error=type(ex).__name__)
        return answer_from_message(r, want)


def answer_from_message(r: Any, want: Any) -> Answer:
    """dnspython response -> Answer (records of the wanted type as text,
    CNAME targets followed, the AD flag)."""
    import dns.flags  # noqa: PLC0415
    import dns.rcode  # noqa: PLC0415
    import dns.rdatatype  # noqa: PLC0415

    ad = bool(r.flags & dns.flags.AD)
    rc = r.rcode()
    if rc == dns.rcode.NXDOMAIN:
        return Answer("nxdomain", ad=ad)
    if rc != dns.rcode.NOERROR:
        return Answer("error", ad=ad, error=dns.rcode.to_text(rc))
    records: list[str] = []
    cnames: list[str] = []
    for rrset in r.answer:
        if rrset.rdtype == dns.rdatatype.CNAME and want != dns.rdatatype.CNAME:
            cnames += [rd.target.to_text(omit_final_dot=True).lower() for rd in rrset]
            continue
        if rrset.rdtype != want:
            continue
        for rd in rrset:
            records.append(_rdata_text(rd, want))
    return Answer("ok" if records else "nodata", records=records, ad=ad, cnames=cnames)


def _rdata_text(rd: Any, rdtype: Any) -> str:
    import dns.rdatatype  # noqa: PLC0415

    if rdtype == dns.rdatatype.TXT:
        return b"".join(rd.strings).decode("utf-8", "replace")
    if rdtype == dns.rdatatype.MX:
        return f"{rd.preference} {rd.exchange.to_text(omit_final_dot=True).lower()}"
    if rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
        return str(rd.address)
    if rdtype in (dns.rdatatype.PTR, dns.rdatatype.NS, dns.rdatatype.CNAME):
        return rd.target.to_text(omit_final_dot=True).lower()
    return rd.to_text()


def make_resolver(server: str | None = None, port: int | None = None) -> Resolver:
    return DnsPythonResolver(server, port)


def txt(resolver: Resolver, name: str) -> Answer:
    return resolver.query(name, "TXT")


def addresses(resolver: Resolver, host: str, *, v6: bool = True) -> tuple[list[str], bool]:
    """(IPs of host, lookup failed). Failed = no IP found while the A or
    the AAAA lookup errored (a timeout is not proof of "no address")."""
    a = resolver.query(host, "A")
    ips = list(a.records)
    failed = a.failed
    if v6:
        b = resolver.query(host, "AAAA")
        ips += b.records
        failed = failed or b.failed
    return ips, failed and not ips


def reverse_name(ip: str) -> str:
    return ipaddress.ip_address(ip).reverse_pointer


# ---------------------------------------------------------------- SPF
SPF_MECHS = ("all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists")
SPF_LOOKUP_MECHS = frozenset({"include", "a", "mx", "ptr", "exists"})
_SPF_TERM_RE = re.compile(r"^([+\-~?]?)([A-Za-z][A-Za-z0-9_.-]*)(?:([:/=])(.*))?$")
_DOMAIN_SPEC_RE = re.compile(r"^[A-Za-z0-9_.%{}+=-]{1,253}$")
SPF_ALL_TEXT = {"-": "-all", "~": "~all", "?": "?all", "+": "+all"}


@dataclass
class Spf:
    terms: list[tuple[str, str, str]] = field(default_factory=list)   # (qualifier, mechanism, value)
    redirect: str | None = None
    exp: str | None = None
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def all_qualifier(self) -> str | None:
        for q, mech, _v in self.terms:
            if mech == "all":
                return q
        return None


def is_spf(text: str) -> bool:
    return bool(re.match(r"(?i)^v=spf1(\s|$)", str(text or "").strip()))


def is_senderid(text: str) -> bool:
    return bool(re.match(r"(?i)^spf2\.0/", str(text or "").strip()))


def _domain_spec(value: str) -> str:
    v = value.split("/", 1)[0]
    return v if _DOMAIN_SPEC_RE.match(v) else ""


def parse_spf(text: str) -> Spf:
    """RFC 7208 record -> Spf (syntax errors as Danish texts)."""
    spf = Spf()
    parts = str(text or "").split()
    if not parts or parts[0].lower() != "v=spf1":
        spf.errors.append("posten begynder ikke med v=spf1")
        return spf
    seen_all = False
    for p in parts[1:]:
        m = _SPF_TERM_RE.match(p)
        if not m:
            spf.errors.append(f"ukendt led “{p[:60]}”")
            continue
        q, name, sep, val = m.group(1), m.group(2).lower(), m.group(3), m.group(4) or ""
        if sep == "=":
            if q:
                spf.errors.append(f"“{p[:60]}” er ikke gyldigt")
            elif name in ("redirect", "exp"):
                if getattr(spf, name) is not None:
                    spf.errors.append(f"{name}= står mere end én gang")
                elif not _domain_spec(val):
                    spf.errors.append(f"{name}= mangler et gyldigt domæne")
                else:
                    setattr(spf, name, val.lower())
            continue  # unknown modifiers are ignored (RFC 7208 6)
        if name not in SPF_MECHS:
            spf.errors.append(f"ukendt mekanisme “{name[:40]}”")
            continue
        value = val if sep == ":" else (f"/{val}" if sep == "/" else "")
        if name == "all":
            if value:
                spf.errors.append("“all” må ikke have en værdi")
                continue
        elif name in ("ip4", "ip6"):
            try:
                net = (ipaddress.IPv4Network if name == "ip4" else ipaddress.IPv6Network)(value, strict=False)
                value = str(net)
            except ValueError:
                spf.errors.append(f"{name}:{value[:60]} er ikke en gyldig adresse")
                continue
        elif name in ("include", "exists"):
            if not _domain_spec(value):
                spf.errors.append(f"{name}: mangler et gyldigt domæne")
                continue
            value = value.lower()
        elif sep == ":" and not _domain_spec(value):
            spf.errors.append(f"{name}:{value[:60]} er ikke gyldigt")
            continue
        if seen_all:
            spf.notes.append(f"“{p[:40]}” står efter all og bliver aldrig brugt")
        if name == "ptr":
            spf.notes.append("ptr er forældet og langsomt (RFC 7208 5.5)")
        if name == "all":
            seen_all = True
        spf.terms.append((q or "+", name, value))
    return spf


def _void(ans: Answer) -> bool:
    """RFC 7208 4.6.4: a "void lookup" answers NXDOMAIN or no records."""
    return ans.status in ("nxdomain", "nodata")


def spf_lookups(domain: str, resolver: Resolver, *, _depth: int = 0, _path: frozenset[str] | None = None,
                _total: list[int] | None = None) -> dict[str, Any]:
    """Count the DNS lookups an SPF check of `domain` costs, the way a
    receiver evaluates it: every include, a, mx, ptr, exists and redirect
    term counts, also when the same include appears twice in the tree
    (RFC 7208 4.6.4, limit 10); void lookups (NXDOMAIN / no records for an
    include, redirect, a, mx or exists target; limit 2). A loop is only an
    include/redirect back to a domain on the CURRENT path - two branches
    that both include _spf.google.com are fine.
    -> {lookups, void, errors[], unknown, missing, multiple, record,
        includes[], nets[], nets_complete, truncated}
    nets: the ip4/ip6 networks and a/mx addresses the tree authorises
    (nets_complete False when a macro, ptr or an unanswered lookup leaves
    part of it unknown)."""
    path = (_path or frozenset()) | {domain.lower()}
    total = _total if _total is not None else [0]
    out: dict[str, Any] = {"domain": domain, "lookups": 0, "void": 0, "errors": [], "unknown": False,
                           "missing": False, "multiple": False, "record": None, "includes": [], "nets": [],
                           "nets_complete": True, "truncated": False, "void_self": False}
    ans = txt(resolver, domain)
    if ans.failed:
        out["unknown"] = True
        out["nets_complete"] = False
        return out
    recs = [r for r in ans.records if is_spf(r)]
    if not recs:
        out["missing"] = True
        out["void_self"] = _void(ans)
        return out
    if len(recs) > 1:
        out["multiple"] = True
    out["record"] = recs[0]
    spf = parse_spf(recs[0])
    out["errors"] += spf.errors

    def add_err(e: str) -> None:
        if e not in out["errors"]:
            out["errors"].append(e)

    def follow(target: str, how: str) -> None:
        if "%" in target:  # a macro: can only be expanded per message
            out["nets_complete"] = False
            return
        t = target.lower()
        if t in path:
            add_err(f"{how}:{target} giver en løkke (henviser tilbage til {domain})")
            return
        if _depth + 1 > SPF_MAX_DEPTH:
            add_err(f"{how}:{target} er for dybt indlejret")
            return
        if total[0] > SPF_EXPAND_CAP:  # far over the limit already: the exact count no longer matters
            out["truncated"] = True
            out["nets_complete"] = False
            return
        child = spf_lookups(t, resolver, _depth=_depth + 1, _path=path, _total=total)
        out["includes"].append(t)
        out["lookups"] += child["lookups"]
        out["void"] += child["void"] + (1 if child["void_self"] else 0)
        out["unknown"] = out["unknown"] or child["unknown"]
        out["truncated"] = out["truncated"] or child["truncated"]
        out["nets_complete"] = out["nets_complete"] and child["nets_complete"]
        out["nets"] += [n for n in child["nets"] if n not in out["nets"]]
        if child["missing"]:
            add_err(f"{how}:{target} har ingen SPF-post (modtagere giver permerror)")
        if child["multiple"]:
            add_err(f"{how}:{target} har flere SPF-poster")
        for e in child["errors"]:
            add_err(e)

    def host_of(val: str) -> str | None:
        h = (val.split("/", 1)[0] if val and not val.startswith("/") else "") or domain
        if "%" in h:
            out["nets_complete"] = False
            return None
        return h

    def add_ips(ips: Iterable[str], val: str = "") -> None:
        cidr = val.split("/", 1)[1].split("/", 1)[0] if "/" in val else ""
        for ip in ips:
            try:
                v4 = ipaddress.ip_address(ip).version == 4 if "/" not in ip else False
                n = str(ipaddress.ip_network(f"{ip}/{cidr}" if cidr and v4 else ip, strict=False))
            except ValueError:
                continue
            if n not in out["nets"]:
                out["nets"].append(n)

    for q, mech, val in spf.terms:
        if mech in SPF_LOOKUP_MECHS:
            out["lookups"] += 1
            total[0] += 1
        if mech in ("ip4", "ip6") and q in ("+", ""):
            add_ips([val])
        elif mech == "include":
            follow(val, "include")
        elif mech == "a":
            host = host_of(val)
            if host:
                a4, a6 = resolver.query(host, "A"), resolver.query(host, "AAAA")
                if a4.failed or a6.failed:
                    out["nets_complete"] = False
                if _void(a4) and _void(a6):
                    out["void"] += 1
                if q == "+":
                    add_ips(a4.records, val)
                    add_ips(a6.records)
        elif mech == "mx":
            host = host_of(val)
            if host:
                m = resolver.query(host, "MX")
                if m.failed:
                    out["nets_complete"] = False
                elif _void(m):
                    out["void"] += 1
                for _p, mxh in parse_mx(m.records)[:10]:
                    ips, failed = addresses(resolver, mxh, v6=False)
                    if failed:
                        out["nets_complete"] = False
                    if q == "+":
                        add_ips(ips, val)
        elif mech == "exists":
            if "%" in val:
                out["nets_complete"] = False
            elif _void(resolver.query(val, "A")):
                out["void"] += 1
        elif mech == "ptr":
            out["nets_complete"] = False
    if spf.redirect and spf.all_qualifier is None:
        out["lookups"] += 1
        total[0] += 1
        follow(spf.redirect, "redirect")
    return out


def ip_in_nets(ip: str, nets: Iterable[str]) -> bool:
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    for n in nets:
        try:
            if a in ipaddress.ip_network(n, strict=False):
                return True
        except (ValueError, TypeError):
            continue
    return False


def spf_includes(record: str | None) -> list[str]:
    if not record:
        return []
    spf = parse_spf(record)
    return [v for _q, m, v in spf.terms if m == "include"] + ([spf.redirect] if spf.redirect else [])


def check_spf(domain: str, no_mail: bool, resolver: Resolver, provider: str | None,
              dns_host: str | None, info: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """-> items. `info` (optional) receives the networks the SPF tree
    authorises (nets, nets_complete) for the blacklist step."""
    key = f"{domain}:spf"
    where = _hos(dns_host, "hos jeres DNS-udbyder")
    ans = txt(resolver, domain)
    if ans.failed:
        return [item(key, "SPF", UNKNOWN, "SPF kunne ikke slås op (DNS svarede ikke).")]
    recs = [r for r in ans.records if is_spf(r)]
    out: list[dict[str, Any]] = []
    sid = [r for r in ans.records if is_senderid(r)]
    if sid:
        out.append(item(f"{domain}:spf_senderid", "Sender ID (forældet)", INFO,
                        "Der ligger også en forældet Sender ID-post (spf2.0). Ingen modtagere bruger den længere.",
                        f"Kan slettes {where} – den gør ingen skade.", record=sid[0][:300]))
    if not recs:
        if no_mail:
            out.insert(0, item(key, "SPF", WARN, "Ingen SPF-post. Domænet sender ikke mail, så SPF bør sige, at "
                               "ingen servere må sende som det.", f'Opret TXT-posten {domain} "v=spf1 -all" {where}.'))
        else:
            out.insert(0, item(key, "SPF", BAD, "Ingen SPF-post. Modtagerne kan ikke se, hvilke servere der må "
                               "sende mail som domænet, så jeres mail kan ende som spam.",
                               f"Opret en SPF-post (TXT på {domain}) {where} med de servere, der sender for jer"
                               + (f" – spørg {provider} om den præcise post" if provider else "") + ", og slut med -all."))
        return out
    if len(recs) > 1:
        out.insert(0, item(key, "SPF", BAD, f"Der er {len(recs)} SPF-poster. Så giver SPF-tjekket fejl (permerror) "
                           "hos alle modtagere.", f"Slå dem sammen til én post {where}.", record=" | ".join(recs)[:300]))
        return out
    rec = recs[0]
    spf = parse_spf(rec)
    if spf.errors:
        out.insert(0, item(key, "SPF", BAD, "SPF-posten har en fejl: " + "; ".join(spf.errors[:3])
                           + ". Modtagerne ignorerer den (permerror).", f"Ret posten {where}.", record=rec[:300]))
        return out
    q = spf.all_qualifier
    if no_mail:
        if [t for t in spf.terms if t[1] != "all"] or spf.redirect or q != "-":
            out.insert(0, item(key, "SPF", WARN, "Domænet sender ikke mail, men SPF-posten tillader alligevel "
                               "nogle servere.", f'Skift posten til præcis "v=spf1 -all" {where}.', record=rec[:300]))
        else:
            out.insert(0, item(key, "SPF", OK, "v=spf1 -all: ingen servere må sende mail som domænet.", record=rec[:300]))
        return out
    notes = " ".join(spf.notes[:2])
    if q == "-":
        st, text, fix = OK, "SPF-posten findes og slutter med -all, så andre servere afvises.", ""
    elif q == "~":
        st, text = WARN, ("SPF slutter med ~all (softfail): mail fra fremmede servere markeres kun, den "
                          "afvises ikke.")
        fix = f"Skift ~all til -all {where}, når alle jeres afsendere (webshop, nyhedsbreve) er med i posten."
    elif q in ("?", "+"):
        st, text = BAD, f"SPF slutter med {SPF_ALL_TEXT[q]}, så alle servere i verden må sende som domænet."
        fix = f"Skift til -all {where}."
    elif spf.redirect:
        st, text, fix = OK, f"SPF-posten henviser til {spf.redirect} (redirect).", ""
    else:
        st, text = WARN, "SPF-posten slutter ikke med -all, så andre servere bliver ikke afvist."
        fix = f"Tilføj -all sidst i posten {where}."
    out.insert(0, item(key, "SPF", st, (text + (" " + notes if notes else "")).strip(), fix, record=rec[:300]))
    # lookup count (RFC 7208 4.6.4)
    lk = spf_lookups(domain, resolver)
    if info is not None:
        info.update(nets=list(lk["nets"]), nets_complete=bool(lk["nets_complete"] and not lk["unknown"]))
    lkey = f"{domain}:spf_lookups"
    if lk["errors"]:
        out.append(item(lkey, "SPF-opslag", BAD, "SPF henviser til noget, der ikke virker: " + "; ".join(lk["errors"][:3])
                        + ".", f"Ret eller fjern henvisningen {where}.", lookups=lk["lookups"]))
    elif lk["unknown"] and lk["lookups"] <= SPF_MAX_LOOKUPS:
        out.append(item(lkey, "SPF-opslag", UNKNOWN, f"Mindst {lk['lookups']} af højst {SPF_MAX_LOOKUPS} DNS-opslag; "
                        "en del af posten kunne ikke slås op.", lookups=lk["lookups"]))
    elif lk["lookups"] > SPF_MAX_LOOKUPS:
        out.append(item(lkey, "SPF-opslag", BAD, f"SPF kræver {'mindst ' if lk['truncated'] else ''}"
                        f"{lk['lookups']} DNS-opslag – højst {SPF_MAX_LOOKUPS} er "
                        "tilladt, så modtagerne giver fejl (permerror), og jeres mail kan blive afvist.",
                        f"Fjern include:-led, I ikke bruger, eller erstat dem med ip4:-adresser {where}.",
                        lookups=lk["lookups"]))
    elif lk["void"] > SPF_MAX_VOID:
        out.append(item(lkey, "SPF-opslag", WARN, f"{lk['void']} henvisninger i SPF giver tomme svar (højst "
                        f"{SPF_MAX_VOID} tilladt).", f"Fjern de døde henvisninger {where}.", lookups=lk["lookups"]))
    else:
        out.append(item(lkey, "SPF-opslag", OK, f"{lk['lookups']} af højst {SPF_MAX_LOOKUPS} DNS-opslag.",
                        lookups=lk["lookups"]))
    return out


# ---------------------------------------------------------------- DKIM
def parse_tags(text: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in str(text or "").split(";"):
        k, sep, v = part.strip().partition("=")
        if sep and k.strip():
            tags.setdefault(k.strip().lower(), re.sub(r"\s+", "", v) if k.strip().lower() == "p" else v.strip())
    return tags


def _der_len(data: bytes, off: int) -> tuple[int, int]:
    n = data[off]
    off += 1
    if n < 0x80:
        return n, off
    k = n & 0x7F
    if not 1 <= k <= 4:
        raise ValueError("bad length")
    return int.from_bytes(data[off:off + k], "big"), off + k


def _der_tlv(data: bytes, off: int, tag: int) -> tuple[int, int]:
    """-> (content start, content end) of the TLV at off (must be tag)."""
    if off >= len(data) or data[off] != tag:
        raise ValueError("unexpected tag")
    ln, start = _der_len(data, off + 1)
    if start + ln > len(data):
        raise ValueError("truncated")
    return start, start + ln


def rsa_bits(der: bytes) -> int:
    """Modulus size of an RSA public key (SubjectPublicKeyInfo or PKCS#1
    RSAPublicKey, both are seen in DKIM records). ValueError if neither."""
    s, e = _der_tlv(der, 0, 0x30)
    if der[s:s + 1] == b"\x30":          # SPKI: SEQUENCE { AlgorithmIdentifier, BIT STRING }
        _a, a_end = _der_tlv(der, s, 0x30)
        b_s, _b_e = _der_tlv(der, a_end, 0x03)
        return rsa_bits(der[b_s + 1:])  # skip the unused-bits byte
    m_s, m_e = _der_tlv(der, s, 0x02)    # RSAPublicKey: SEQUENCE { INTEGER n, INTEGER e }
    modulus = der[m_s:m_e].lstrip(b"\x00")
    if not modulus:
        raise ValueError("empty modulus")
    return int.from_bytes(modulus, "big").bit_length()


def dkim_key(text: str) -> dict[str, Any] | None:
    """A DKIM key record -> {k, bits, revoked} (None if it is not one)."""
    tags = parse_tags(text)
    if "p" not in tags or ("v" in tags and tags["v"] != "DKIM1"):
        return None
    k = (tags.get("k") or "rsa").lower()
    p = tags["p"]
    if not p:
        return {"k": k, "bits": None, "revoked": True}
    if k == "ed25519":
        return {"k": k, "bits": 256, "revoked": False}
    try:
        der = base64.b64decode(p + "=" * (-len(p) % 4), validate=False)
        bits = rsa_bits(der)
    except (ValueError, IndexError, TypeError):
        bits = None
    return {"k": k, "bits": bits, "revoked": False}


_SEL_OPT_RE = re.compile(r"^([A-Za-z0-9._-]{1,253}):(?:s=)?([A-Za-z0-9_][A-Za-z0-9_.-]{0,62})$")
DKIM_SYMBOLS = ("R_DKIM_ALLOW", "R_DKIM_REJECT", "R_DKIM_TEMPFAIL", "R_DKIM_PERMFAIL")


def selectors_from_symbols(symbols: Any) -> list[tuple[str, str, str]]:
    """messages.symbols ([{"n","s","o"}], JSON or list) -> [(signing
    domain, selector, symbol)] from rspamd's "domain:s=selector" options."""
    if isinstance(symbols, (str, bytes)):
        try:
            symbols = json.loads(symbols)
        except (TypeError, ValueError):
            return []
    out: list[tuple[str, str, str]] = []
    for s in symbols if isinstance(symbols, list) else []:
        if not isinstance(s, dict) or s.get("n") not in DKIM_SYMBOLS:
            continue
        for opt in s.get("o") or []:
            m = _SEL_OPT_RE.match(str(opt).strip())
            if m:
                d = clean_domain(m.group(1))
                if d:
                    out.append((d, m.group(2), str(s["n"])))
    return out


def _symbol_names(symbols: Any) -> set[str]:
    if isinstance(symbols, (str, bytes)):
        try:
            symbols = json.loads(symbols)
        except (TypeError, ValueError):
            return set()
    return {str(s.get("n")) for s in symbols if isinstance(s, dict)} if isinstance(symbols, list) else set()


def _dkim_domains(symbols: Any, sender_auth: Any) -> set[str]:
    out = {d for d, _s, n in selectors_from_symbols(symbols) if n == "R_DKIM_ALLOW"}
    try:
        auth = json.loads(sender_auth) if isinstance(sender_auth, str) else (sender_auth or {})
        out |= {clean_domain(d) or "" for d in auth.get("dkim") or []} - {""}
    except (TypeError, ValueError, AttributeError):
        pass
    if isinstance(symbols, (str, bytes)):
        try:
            symbols = json.loads(symbols)
        except (TypeError, ValueError):
            symbols = []
    for s in symbols if isinstance(symbols, list) else []:
        if isinstance(s, dict) and s.get("n") == "R_DKIM_ALLOW":
            for opt in s.get("o") or []:
                d = clean_domain(str(opt).split(":", 1)[0])
                if d:
                    out.add(d)
    return out


SPAM_ACTIONS = frozenset({"moved_to_junk", "pending_move", "flagged", "flag", "shadow_spam", "move_failed"})


def _cols(conn: sqlite3.Connection, table: str) -> set[str]:
    try:
        return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    except sqlite3.Error:
        return set()


def mail_evidence(conn: sqlite3.Connection | None, domain: str, *, now: int, days: int = WINDOW_DAYS,
                  limit: int = 5000) -> dict[str, Any]:
    """What the owner's own delivered mail from `domain` (last `days`)
    shows: verified own mails (SPF or DKIM passed, not spam), how many
    carried an aligned DKIM signature, unaligned signers, selectors of
    PASSING signatures (selectors / selector_seen = newest unix time),
    sending IPs - plus the DMARC reports' dkim results.

    ips (the blacklist step's candidates) only holds addresses whose mail
    passed SPF (R_SPF_ALLOW) with an envelope domain of `domain` (when the
    envelope is known), and only when the matched SPF mechanism covers the
    address: never the client of an authenticated submission (rspamd
    skips SPF for those) and never a DKIM-only sender. run_check further
    keeps only addresses the domain's own SPF tree authorises.
    dmarc_ips: report rows whose SPF passed for an aligned domain."""
    ev: dict[str, Any] = {"mails": 0, "dkim": 0, "other_signers": [], "selectors": {}, "selector_seen": {},
                          "ips": {}, "dmarc_msgs": 0, "dmarc_dkim": 0, "dmarc_ips": {}}
    if conn is None:
        return ev
    since = int(now) - days * 86400
    cols = _cols(conn, "messages")
    if {"sender", "symbols"} <= cols:
        auth_col = "sender_auth" if "sender_auth" in cols else "NULL"
        ip_col = "sender_ip" if "sender_ip" in cols else "NULL"
        env_col = "envelope_from" if "envelope_from" in cols else "NULL"
        esc = domain.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        try:
            rows = conn.execute(
                f"SELECT sender, symbols, {auth_col}, {ip_col}, our_action, user_verdict, {env_col}, "
                "COALESCE(received_at, first_seen) FROM messages "
                "WHERE COALESCE(received_at, first_seen) >= ? AND (sender LIKE ? ESCAPE '\\' OR sender LIKE ? ESCAPE '\\' "
                "OR sender LIKE ? ESCAPE '\\') "
                "ORDER BY COALESCE(received_at, first_seen) DESC LIMIT ?",
                (since, f"%@{esc}", f"%.{esc}", f"%{esc}>", int(limit))).fetchall()
        except sqlite3.Error:
            rows = []
        other: dict[str, int] = {}
        for sender, symbols, auth, ip, action, verdict, envelope, ts in rows:
            addr = parseaddr(str(sender or ""))[1].lower()
            if not under(addr.rpartition("@")[2], domain):
                continue
            if str(action or "") in SPAM_ACTIONS or str(verdict or "") == "spam":
                continue
            names = _symbol_names(symbols)
            signers = _dkim_domains(symbols, auth)
            aligned = any(under(s, domain) or under(domain, s) for s in signers)
            if not (aligned or "R_SPF_ALLOW" in names or "DMARC_POLICY_ALLOW" in names):
                continue  # unverified (a spoof would fail SPF and DKIM)
            ev["mails"] += 1
            if aligned:
                ev["dkim"] += 1
            elif ip:
                # 2.7.1: which server sent the unsigned mail (a website/WordPress host, a newsletter
                # service ...) - the fix is at that sender, not necessarily the mail provider.
                ev.setdefault("unsigned_ips", {})
                ev["unsigned_ips"][str(ip)] = ev["unsigned_ips"].get(str(ip), 0) + 1
            for s in signers:
                if not (under(s, domain) or under(domain, s)):
                    other[s] = other.get(s, 0) + 1
            for d, sel, n in selectors_from_symbols(symbols):
                if n == "R_DKIM_ALLOW" and under(d, domain):   # only passing signatures teach a selector
                    _seen_selector(ev, f"{d}|{sel}", 1, ts)
            if ip and _spf_sender_ip(str(ip), symbols, envelope, domain):
                ev["ips"][str(ip)] = ev["ips"].get(str(ip), 0) + 1
        ev["other_signers"] = sorted(other, key=lambda k: -other[k])[:5]
    dcols = _cols(conn, "dmarc_records")
    if dcols:
        sel_col = "dkim_selector" if "dkim_selector" in dcols else "NULL"
        spf_cols = ("spf_domain, spf_result" if {"spf_domain", "spf_result"} <= dcols else "NULL, NULL")
        try:
            for dk_dom, dk_res, sel, ip, cnt, _passed, spf_dom, spf_res, ts in conn.execute(
                    f"SELECT dkim_domain, dkim_result, {sel_col}, source_ip, count, dmarc_pass, {spf_cols}, date_end "
                    "FROM dmarc_records WHERE domain=? AND date_end >= ?", (domain, since)):
                cnt = int(cnt or 0)
                ev["dmarc_msgs"] += cnt
                dk_pass = dk_res == "pass" and under(dk_dom, domain)
                if dk_pass:
                    ev["dmarc_dkim"] += cnt
                if dk_pass and sel and clean_selector(sel):
                    _seen_selector(ev, f"{str(dk_dom).lower()}|{sel}", cnt, ts)
                if ip and spf_res == "pass" and spf_dom and _same_org(str(spf_dom).lower(), domain):
                    ev["dmarc_ips"][str(ip)] = ev["dmarc_ips"].get(str(ip), 0) + cnt
        except sqlite3.Error:
            pass
    return ev


def _seen_selector(ev: dict[str, Any], key: str, n: int, ts: Any) -> None:
    ev["selectors"][key] = ev["selectors"].get(key, 0) + int(n)
    try:
        t = int(ts or 0)
    except (TypeError, ValueError):
        t = 0
    ev["selector_seen"][key] = max(int(ev["selector_seen"].get(key, 0)), t)


_SPF_OPT_NET_RE = re.compile(r"^[+?~-]?(ip4|ip6):(\S+)$", re.I)


def _spf_sender_ip(ip: str, symbols: Any, envelope: Any, domain: str) -> bool:
    """A sending address of the domain's own outbound relay: the mail
    passed SPF (rspamd evaluates the envelope domain; it skips SPF for
    authenticated submissions), the envelope domain (when stored) is the
    domain, and the matched ip4/ip6 mechanism (R_SPF_ALLOW option) covers
    the address."""
    if isinstance(symbols, (str, bytes)):
        try:
            symbols = json.loads(symbols)
        except (TypeError, ValueError):
            return False
    spf = next((s for s in symbols if isinstance(s, dict) and s.get("n") == "R_SPF_ALLOW"), None) \
        if isinstance(symbols, list) else None
    if spf is None:
        return False
    env = parseaddr(str(envelope or ""))[1].lower()
    if env and "@" in env and not _same_org(env.rpartition("@")[2], domain):
        return False  # SPF passed for someone else's bounce domain (ESP, forwarder)
    for opt in spf.get("o") or []:
        m = _SPF_OPT_NET_RE.match(str(opt).strip())
        if m and not ip_in_nets(ip, [m.group(2)]):
            return False
    return True


def _unsigned_senders(ev: dict[str, Any], resolver: Resolver, limit: int = 3) -> list[str]:
    """2.7.1: 'host (ip)' of the servers that sent the domain's unsigned mail, most frequent first."""
    out: list[str] = []
    ips = ev.get("unsigned_ips") or {}
    for ip in sorted(ips, key=lambda k: -ips[k])[:limit]:
        name = ""
        try:
            ans = resolver.query(reverse_name(ip), "PTR")
            if ans.ok and ans.records:
                name = str(ans.records[0]).rstrip(".")
        except Exception:  # noqa: BLE001 - a missing PTR only shortens the text
            name = ""
        out.append(f"{name} ({ip})" if name else ip)
    return out


def check_dkim(domain: str, no_mail: bool, resolver: Resolver, ev: dict[str, Any], admin_selectors: Sequence[str],
               provider: str | None, dns_host: str | None, *, now: int = 0) -> list[dict[str, Any]]:
    key = f"{domain}:dkim"
    if no_mail:
        return [item(key, "DKIM", INFO, "Domænet sender ikke mail, så det behøver ingen DKIM-nøgle.")]
    who = _hos(provider, "hos den udbyder, der sender jeres mail")
    where = _hos(dns_host, "hos jeres DNS-udbyder")
    learned: list[tuple[str, str]] = []
    for k in sorted(ev.get("selectors") or {}, key=lambda k: -ev["selectors"][k]):
        d, _sep, sel = k.partition("|")
        learned.append((d, sel))
    pairs: list[tuple[str, str, bool]] = [(d, s, True) for d, s in learned]
    for s in admin_selectors:
        if (domain, s) not in [(d, x) for d, x, _l in pairs]:
            pairs.append((domain, s, False))
    out: list[dict[str, Any]] = []
    mails, signed = int(ev.get("mails") or 0), int(ev.get("dkim") or 0)
    dm, dmk = int(ev.get("dmarc_msgs") or 0), int(ev.get("dmarc_dkim") or 0)
    sel_text = ", ".join(s for _d, s, _l in pairs[:3])
    senders = _unsigned_senders(ev, resolver)
    # The provider's own relays (PTR names the provider) -> "slå DKIM til hos <udbyder>" as before;
    # another server (a website host, a newsletter service) is named so the fix goes to the right place.
    prov = re.sub(r"[^a-z0-9]", "", (provider or "").lower())
    # Only a server whose reverse DNS names someone else counts as foreign (no PTR = can't tell).
    foreign = [x for x in senders if " (" in x and not (prov and prov in re.sub(r"[^a-z0-9]", "", x.lower()))]
    via = f" De usignerede mails kom fra {', '.join(senders)}." if foreign else ""
    senders = foreign
    if mails and not signed and not dmk:
        other = ev.get("other_signers") or []
        extra = (f" Nogle var signeret af {', '.join(other[:2])}, men DMARC kræver en signatur med jeres eget "
                 "domæne." if other else "")
        out.append(item(key, "DKIM", BAD, f"Ingen af de {mails} mails fra {domain}, filteret har set de seneste "
                        f"{WINDOW_DAYS} dage, var DKIM-signeret med domænet. Uden DKIM kan modtagerne ikke se, at "
                        f"mailen virkelig er fra jer, og DMARC hviler kun på SPF.{extra}{via}",
                        (f"Slå DKIM til hos den tjeneste, der sender fra {senders[0]} (fx hjemmesidens webhost "
                         f"eller et nyhedsbrevssystem), eller lad den sende via {provider or 'jeres mailudbyder'}. "
                         f"Nøglen lægges i DNS {where} som <selector>._domainkey.{domain}."
                         if senders else
                         f"Slå DKIM til {who}, og læg den viste nøgle (<selector>._domainkey.{domain}) "
                         f"i DNS {where}."), mails=mails, signed=signed))
    elif dm and not dmk and not signed:
        out.append(item(key, "DKIM", BAD, f"DMARC-rapporterne viser {dm} mails fra {domain} de seneste {WINDOW_DAYS} "
                        "dage, og ingen havde en gyldig DKIM-signatur med domænet.",
                        f"Slå DKIM til {who}.", mails=mails, signed=signed))
    elif mails and mails - signed >= DKIM_PARTIAL_MIN and signed / mails < 0.9:
        out.append(item(key, "DKIM", WARN, f"Kun {signed} af {mails} mails fra {domain} de seneste {WINDOW_DAYS} dage "
                        f"var DKIM-signeret. Nogle af jeres afsendere (fx webshop eller nyhedsbreve) signerer ikke.{via}",
                        f"Slå DKIM til for alle tjenester, der sender som {domain}.", mails=mails, signed=signed))
    elif signed or dmk:
        n_txt = f"{signed} af {mails} mails" if mails else f"{dmk} mails i DMARC-rapporterne"
        out.append(item(key, "DKIM", OK, f"Jeres mail er DKIM-signeret ({n_txt} de seneste {WINDOW_DAYS} dage"
                        + (f", selector {sel_text}" if sel_text else "") + ").", mails=mails, signed=signed))
    else:
        out.append(item(key, "DKIM", INFO, f"Filteret har ikke set mail fra {domain} de seneste {WINDOW_DAYS} dage, så "
                        "det kan ikke ses, om den bliver DKIM-signeret."
                        + ("" if pairs else " Kender I jeres selector, kan den tilføjes nedenfor, så nøglen bliver tjekket."),
                        mails=0, signed=0))
    seen = ev.get("selector_seen") or {}
    for d, sel, was_learned in pairs[:MAX_SELECTORS]:
        age = None
        if was_learned and now and seen.get(f"{d}|{sel}"):
            age = max(0, int((now - int(seen[f"{d}|{sel}"])) // 86400))
        out.append(_check_selector(domain, d, sel, was_learned, resolver, who, where, age_days=age))
    return out


def _check_selector(domain: str, sig_domain: str, sel: str, learned: bool, resolver: Resolver, who: str,
                    where: str, *, age_days: int | None = None) -> dict[str, Any]:
    name = f"{sel}._domainkey.{sig_domain}"
    key = f"{domain}:dkim:{sig_domain}:{sel}"
    area = f"DKIM-nøgle ({sel})"
    ans = txt(resolver, name)
    if ans.failed:
        return item(key, area, UNKNOWN, f"{name} kunne ikke slås op.", selector=sel)
    keys = [k for k in (dkim_key(r) for r in ans.records) if k]
    if not keys:
        if learned and age_days is not None and age_days > SELECTOR_FRESH_DAYS:
            return item(key, area, INFO, f"Selectoren “{sel}” er ikke set i jeres mail i {age_days} dage, og nøglen "
                        f"{name} findes ikke længere – udbyderen har sikkert skiftet nøgle.",
                        "Intet at gøre, hvis jeres mail stadig er DKIM-signeret (se DKIM ovenfor).", selector=sel)
        if learned:
            return item(key, area, BAD, f"Selectoren “{sel}” bruges i jeres mail, men nøglen {name} findes ikke i "
                        "DNS. Modtagerne kan ikke tjekke signaturen.", f"Udgiv nøglen {where} – find den {who}.",
                        selector=sel)
        return item(key, area, WARN, f"Der er ingen DKIM-nøgle på {name}.",
                    "Tjek stavningen af selectoren, eller fjern den fra listen nedenfor.", selector=sel)
    k = keys[0]
    if k["revoked"]:
        return item(key, area, WARN if learned else INFO, f"Nøglen på {name} er trukket tilbage (tom p=).",
                    "Signerer jeres udbyder stadig med den, skal den nye nøgle udgives." if learned else "",
                    selector=sel)
    bits = k["bits"]
    if bits is None:
        return item(key, area, WARN, f"Nøglen på {name} kan ikke læses (ugyldig base64 eller ukendt format).",
                    f"Kopiér nøglen igen fra udbyderen {where}.", selector=sel)
    if k["k"] == "ed25519":
        return item(key, area, OK, f"Ed25519-nøgle på {name}.", selector=sel, bits=bits)
    if bits < DKIM_MIN_BITS:
        return item(key, area, BAD, f"Nøglen på {name} er kun {bits} bit. Den er for svag, og mange modtagere "
                    "afviser den.", f"Lav en ny 2048-bit nøgle {who}.", selector=sel, bits=bits)
    if bits < DKIM_GOOD_BITS:
        return item(key, area, WARN, f"Nøglen på {name} er {bits} bit. 2048 bit anbefales.",
                    f"Skift til en 2048-bit nøgle {who}, når det passer.", selector=sel, bits=bits)
    return item(key, area, OK, f"{bits}-bit nøgle på {name}.", selector=sel, bits=bits)


# ---------------------------------------------------------------- DMARC
def is_dmarc(text: str) -> bool:
    return bool(re.match(r"(?i)^v\s*=\s*DMARC1\s*(;|$)", str(text or "").strip()))


def parse_dmarc(text: str) -> tuple[dict[str, str], list[str]]:
    """RFC 7489 record -> (tags, errors in Danish)."""
    errors: list[str] = []
    tags: dict[str, str] = {}
    parts = [p.strip() for p in str(text or "").split(";") if p.strip()]
    for i, p in enumerate(parts):
        k, sep, v = p.partition("=")
        k, v = k.strip().lower(), v.strip()
        if not sep:
            errors.append(f"“{p[:40]}” er ikke et gyldigt led")
            continue
        if i == 0 and (k != "v" or v != "DMARC1"):
            errors.append("posten skal begynde med v=DMARC1")
        if k in tags:
            errors.append(f"{k}= står mere end én gang")
            continue
        tags[k] = v
    for k in ("p", "sp"):
        if k in tags and tags[k].lower() not in ("none", "quarantine", "reject"):
            errors.append(f"{k}={tags[k][:30]} er ikke none, quarantine eller reject")
        elif k in tags:
            tags[k] = tags[k].lower()
    if "p" not in tags:
        errors.append("p= mangler")
    if "pct" in tags:
        try:
            if not 0 <= int(tags["pct"]) <= 100:
                raise ValueError
        except ValueError:
            errors.append("pct= skal være et tal fra 0 til 100")
    for k in ("adkim", "aspf"):
        if k in tags and tags[k].lower() not in ("r", "s"):
            errors.append(f"{k}= skal være r eller s")
    for k in ("rua", "ruf"):
        for uri in [u.strip() for u in tags.get(k, "").split(",") if u.strip()]:
            if not re.match(r"(?i)^mailto:[^@\s]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(!\d+[kmgt]?)?$", uri) \
                    and not uri.lower().startswith("https:"):
                errors.append(f"{k}={uri[:60]} er ikke en gyldig mailto:-adresse")
    return tags, errors


def report_addresses(tags: dict[str, str], key: str = "rua") -> list[str]:
    out = []
    for uri in [u.strip() for u in tags.get(key, "").split(",") if u.strip()]:
        if uri.lower().startswith("mailto:"):
            addr = uri[7:].split("!", 1)[0].strip().lower()
            if "@" in addr and addr not in out:
                out.append(addr)
    return out


def _same_org(a: str, b: str) -> bool:
    """Crude organisational-domain test (no public suffix list): one is the
    other or a subdomain of it."""
    return under(a, b) or under(b, a)


def check_dmarc(domain: str, no_mail: bool, resolver: Resolver, *, rua_default: str, advice: str | None,
                dns_host: str | None) -> list[dict[str, Any]]:
    key = f"{domain}:dmarc"
    where = _hos(dns_host, "hos jeres DNS-udbyder")
    ans = txt(resolver, f"_dmarc.{domain}")
    if ans.failed:
        return [item(key, "DMARC", UNKNOWN, "DMARC kunne ikke slås op (DNS svarede ikke).")]
    recs = [r for r in ans.records if is_dmarc(r)]
    if not recs:
        if no_mail:
            return [item(key, "DMARC", BAD, "Ingen DMARC-post. Domænet sender ikke mail, så modtagerne bør få "
                         "besked på at afvise alt, der udgiver sig for at være fra det.",
                         f'Opret TXT-posten _dmarc.{domain} "v=DMARC1; p=reject; rua=mailto:{rua_default}" {where}.')]
        return [item(key, "DMARC", BAD, "Ingen DMARC-post. Modtagerne ved ikke, hvad de skal gøre med falske mails "
                     "fra domænet, og I får ingen rapporter om, hvem der sender som jer.",
                     f'Opret TXT-posten _dmarc.{domain} "v=DMARC1; p=none; rua=mailto:{rua_default}" {where}. '
                     "Siden DMARC fortæller, hvornår I kan stramme den.")]
    if len(recs) > 1:
        return [item(key, "DMARC", BAD, f"Der er {len(recs)} DMARC-poster på _dmarc.{domain}. Så ignorerer "
                     "modtagerne dem alle.", f"Slet alle på nær én {where}.")]
    rec = recs[0]
    tags, errors = parse_dmarc(rec)
    out: list[dict[str, Any]] = []
    if errors:
        out.append(item(key, "DMARC", BAD, "DMARC-posten har en fejl: " + "; ".join(errors[:3]) + ".",
                        f"Ret posten _dmarc.{domain} {where}.", record=rec[:300]))
    else:
        p = tags.get("p", "none")
        pct = int(tags.get("pct", "100") or 100)
        if no_mail:
            if p == "reject" and pct == 100:
                out.append(item(key, "DMARC", OK, "p=reject: alt, der udgiver sig for at være fra domænet, afvises.",
                                record=rec[:300], policy=p))
            else:
                out.append(item(key, "DMARC", WARN, f"Domænet sender ikke mail, men DMARC står på p={p}"
                                + (f" og pct={pct}" if pct != 100 else "") + ". Falske mails afvises ikke.",
                                f"Skift til p=reject {where} – det er sikkert, når domænet ikke sender mail.",
                                record=rec[:300], policy=p))
        elif p == "none":
            out.append(item(key, "DMARC", WARN, "p=none: I får rapporter, men falske mails fra domænet afvises ikke."
                            + (f" DMARC-siden siger: {advice}" if advice else ""),
                            "Følg anbefalingen på siden DMARC, og skift til p=quarantine og senere p=reject, når alle "
                            "jeres afsendere består.", record=rec[:300], policy=p))
        elif pct < 100:
            out.append(item(key, "DMARC", WARN, f"p={p}, men kun for {pct} % af mailene.",
                            f"Hæv pct til 100 {where}, når siden DMARC viser, at alt består.", record=rec[:300], policy=p))
        else:
            out.append(item(key, "DMARC", OK, f"p={p}: falske mails fra domænet "
                            + ("afvises." if p == "reject" else "lægges i spam hos modtagerne."), record=rec[:300],
                            policy=p))
    # rua + the RFC 7489 7.1 permission records of external report domains
    rua = report_addresses(tags)
    rkey = f"{domain}:dmarc_rua"
    if not rua:
        out.append(item(rkey, "DMARC-rapporter (rua)", INFO if no_mail else WARN,
                        "DMARC-posten har ingen rua=, så I får ingen rapporter om, hvem der sender som domænet.",
                        f"Tilføj rua=mailto:{rua_default} til _dmarc.{domain} {where}."))
        return out
    missing, unknown, external = [], [], []
    for addr in rua[:5]:
        rdom = clean_domain(addr.rpartition("@")[2])
        if not rdom or _same_org(rdom, domain):
            continue
        external.append(rdom)
        a = txt(resolver, f"{domain}._report._dmarc.{rdom}")
        if a.failed:
            unknown.append(rdom)
        elif not any(is_dmarc(r) for r in a.records):
            missing.append(rdom)
    if missing:
        out.append(item(rkey, "DMARC-rapporter (rua)", BAD, f"Rapporterne skal til {', '.join(rua[:3])}, men "
                        f"{', '.join(missing)} har ikke givet lov til at modtage rapporter for {domain}. Så sender "
                        "Google, Microsoft m.fl. dem ikke.",
                        " ".join(f'Opret TXT-posten {domain}._report._dmarc.{m} "v=DMARC1" i DNS for {m}.'
                                 for m in missing[:2]), rua=rua))
    elif unknown:
        out.append(item(rkey, "DMARC-rapporter (rua)", UNKNOWN, "Tilladelsen til at sende rapporterne til "
                        f"{', '.join(unknown)} kunne ikke slås op.", rua=rua))
    else:
        out.append(item(rkey, "DMARC-rapporter (rua)", OK, f"Rapporterne sendes til {', '.join(rua[:3])}"
                        + (f" ({', '.join(external)} har givet lov)." if external else "."), rua=rua))
    return out


# ---------------------------------------------------------------- MTA-STS, TLS-RPT, DNSSEC, wildcard
def check_optional(domain: str, no_mail: bool, resolver: Resolver) -> list[dict[str, Any]]:
    if no_mail:
        return []
    out = []
    a = txt(resolver, f"_mta-sts.{domain}")
    sts = [r for r in a.records if re.match(r"(?i)^v=STSv1\s*;", r.strip())]
    if a.failed:
        out.append(item(f"{domain}:mta_sts", "MTA-STS", UNKNOWN, "MTA-STS kunne ikke slås op."))
    elif sts:
        out.append(item(f"{domain}:mta_sts", "MTA-STS", INFO, "MTA-STS er slået til: afsendere skal bruge "
                        "kryptering til jeres mailserver."))
    else:
        out.append(item(f"{domain}:mta_sts", "MTA-STS", INFO, "MTA-STS er ikke sat op (valgfrit). Det tvinger "
                        "afsendere til at kryptere mail til jer."))
    b = txt(resolver, f"_smtp._tls.{domain}")
    rpt = [r for r in b.records if re.match(r"(?i)^v=TLSRPTv1\s*;", r.strip())]
    if b.failed:
        out.append(item(f"{domain}:tls_rpt", "TLS-rapporter (TLS-RPT)", UNKNOWN, "TLS-RPT kunne ikke slås op."))
    else:
        out.append(item(f"{domain}:tls_rpt", "TLS-rapporter (TLS-RPT)", INFO,
                        "TLS-RPT er slået til." if rpt else "TLS-RPT er ikke sat op (valgfrit). Det giver rapporter "
                        "om fejl i krypteringen til jeres mailserver."))
    return out


def check_dnssec(domain: str, resolver: Resolver, dns_host: str | None) -> dict[str, Any]:
    """AD flag of the validating local resolver. A control query for the
    TLD tells whether the resolver validates at all. SERVFAIL alone is not
    proof of broken DNSSEC (a lame or unreachable name server gives it
    too): only when the same query with CD (checking disabled) answers is
    the validation the cause."""
    key = f"{domain}:dnssec"
    ans = resolver.query(domain, "SOA")
    if ans.failed:
        if ans.error == "SERVFAIL":
            cd = resolver.query(domain, "SOA", cd=True)
            if cd.status in ("ok", "nodata", "nxdomain"):
                return item(key, "DNSSEC", BAD, "Domænet giver SERVFAIL hos en validerende resolver, men svarer, når "
                            "valideringen slås fra – DNSSEC-signaturen er ødelagt. Så kan mange slet ikke slå "
                            "domænet op.", f"Kontakt {dns_host or 'jeres DNS-udbyder'} med det samme (DS-posten passer "
                            "ikke til nøglerne).")
            return item(key, "DNSSEC", UNKNOWN, "DNSSEC kunne ikke tjekkes: domænet kunne ikke slås op (SERVFAIL, "
                        "også uden validering – typisk en navneserver, der ikke svarer).")
        return item(key, "DNSSEC", UNKNOWN, "DNSSEC kunne ikke tjekkes (DNS svarede ikke).")
    if ans.ad:
        return item(key, "DNSSEC", OK, "DNSSEC er slået til, og svarene er gyldigt signeret.")
    tld = domain.rpartition(".")[2]
    ctl = resolver.query(tld, "SOA")
    if not ctl.ad:
        return item(key, "DNSSEC", UNKNOWN, "Kunne ikke afgøres: den lokale resolver validerer ikke DNSSEC "
                    f"(heller ikke for .{tld}).")
    return item(key, "DNSSEC", WARN, "DNSSEC er ikke slået til. Uden det kan svarene om jeres domæne – også "
                "MX og SPF – forfalskes undervejs.", f"Slå DNSSEC til {_hos(dns_host, 'hos jeres DNS-udbyder')} "
                "(udbyderen signerer zonen og sender DS-posten til registret).")


def check_wildcard(domain: str, resolver: Resolver, *, token: str | None = None) -> dict[str, Any] | None:
    """A wildcard (*.domain) also answers _dmarc, x._domainkey and
    _mta-sts when those do not exist: info, so the other results are read
    with that in mind. None = no wildcard."""
    tok = token or "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(10))
    probe = resolver.query(f"_sf-{tok}.{domain}", "A")
    if probe.failed or probe.status != "ok" and not probe.cnames:
        return None
    target = ", ".join(probe.cnames[:1]) or ", ".join(probe.records[:2])
    shadowed = []
    for label, name in (("_dmarc", f"_dmarc.{domain}"), ("_domainkey", f"_sf-{tok}._domainkey.{domain}"),
                        ("_mta-sts", f"_mta-sts.{domain}")):
        a = txt(resolver, name)
        if probe.cnames and a.cnames[:1] == probe.cnames[:1] or (not probe.cnames and a.status == "ok"
                                                                 and label == "_domainkey"):
            shadowed.append(label)
    text = (f"*.{domain} svarer for alle navne, der ikke findes ({'CNAME til ' if probe.cnames else ''}{target}).")
    if shadowed:
        text += (" Det gælder også " + ", ".join(shadowed) + ", så opslag dér får svar fra jokertegnet i stedet "
                 "for et tomt svar. Tjekkene ovenfor tager højde for det.")
    return item(f"{domain}:wildcard", "Jokertegn (*)", INFO, text, "Ikke en fejl. Vil I undgå det, så opret de "
                "konkrete poster, eller begræns jokertegnet.", shadowed=shadowed)


# ---------------------------------------------------------------- MX
def parse_mx(records: Iterable[str]) -> list[tuple[int, str]]:
    out = []
    for r in records:
        pref, _sp, host = str(r).strip().partition(" ")
        try:
            out.append((int(pref), host.strip().rstrip(".").lower()))
        except ValueError:
            continue
    return sorted(out)


def check_mx(domain: str, no_mail: bool, resolver: Resolver, provider: str | None, dns_host: str | None,
             *, ptr_hosts: int = 4) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """-> (items, [{host, pref, ips}])."""
    key = f"{domain}:mx"
    where = _hos(dns_host, "hos jeres DNS-udbyder")
    ans = resolver.query(domain, "MX")
    if ans.failed:
        return [item(key, "MX", UNKNOWN, "MX kunne ikke slås op (DNS svarede ikke).")], []
    if ans.status == "nxdomain":
        return [item(key, "MX", BAD, f"Domænet {domain} findes ikke i DNS.",
                     "Tjek stavningen, eller fjern domænet fra listen.")], []
    mx = parse_mx(ans.records)
    null = [h for _p, h in mx if h in ("", ".")]
    real = [(p, h) for p, h in mx if h not in ("", ".")]
    if no_mail:
        if not real:
            return [item(key, "MX", OK, "Ingen MX" + (" (null-MX)" if null else "") + " – passer til et domæne, der "
                         "ikke bruger mail.")], []
        st, text = INFO, (f"Domænet modtager mail via {', '.join(h for _p, h in real[:3])}, selv om det er markeret "
                          "som “sender ikke mail”. Det er fint, hvis I bruger det til at modtage mail.")
    elif not real:
        return [item(key, "MX", BAD if not null else WARN, "Ingen MX-post: domænet kan ikke modtage mail – heller "
                     "ikke svar og fejlmeldinger på det, I sender." if not null else "Null-MX: domænet siger, at det "
                     "ikke modtager mail, men det er markeret som et domæne, der sender mail.",
                     f"Opret MX-posten {where}" + (f" (spørg {provider})." if provider else "."))], []
    else:
        st, text = OK, f"Mail modtages af {', '.join(h for _p, h in real[:4])}" + (f" ({provider})." if provider else ".")
    out = [item(key, "MX", st, text, hosts=[h for _p, h in real])]
    hosts: list[dict[str, Any]] = []
    missing = []
    unknown = False
    for pref, host in real[:8]:
        ips, failed = addresses(resolver, host)
        if failed:
            unknown = True
        elif not ips:
            missing.append(host)
        hosts.append({"host": host, "pref": pref, "ips": ips})
    if missing:
        out.append(item(f"{domain}:mx_resolve", "MX-adresser", BAD, f"MX-serveren {', '.join(missing[:3])} har ingen "
                        "IP-adresse, så mail til den kan ikke leveres.", f"Ret MX-posten {where}."))
    elif unknown:
        out.append(item(f"{domain}:mx_resolve", "MX-adresser", UNKNOWN, "Adresserne på MX-serverne kunne ikke slås op."))
    else:
        out.append(item(f"{domain}:mx_resolve", "MX-adresser", OK, "Alle MX-servere har en IP-adresse."))
    # PTR/forward (cheap: the first IPv4 address of a few hosts)
    bad, checked = [], 0
    for hh in hosts[:ptr_hosts]:
        ip = next((i for i in hh["ips"] if ":" not in i), None)
        if not ip:
            continue
        p = resolver.query(reverse_name(ip), "PTR")
        if p.failed:
            continue
        checked += 1
        names = p.records[:2]
        if not names or not any(ip in addresses(resolver, n, v6=False)[0] for n in names):
            bad.append(f"{ip} ({hh['host']})")
    if checked:
        out.append(item(f"{domain}:mx_ptr", "Omvendt DNS (PTR)", INFO if bad else OK,
                        ("Omvendt DNS passer ikke for " + ", ".join(bad[:3]) + ". Det betyder mest for servere, der "
                         "sender mail.") if bad else "Omvendt DNS (PTR) passer til MX-serverne."))
    return out, hosts


def check_ns(domain: str, resolver: Resolver) -> str | None:
    """The DNS host by its name servers."""
    a = resolver.query(domain, "NS")
    return provider_of(*a.records) if a.ok else None


# ---------------------------------------------------------------- TLS servers
@dataclass
class Probe:
    host: str
    port: int
    mode: str                       # smtp (STARTTLS) | imap (STARTTLS) | tls (implicit)
    ok: bool = False                # TLS handshake completed
    error: str = ""                 # timeout | refused | unreachable | dns | starttls | protocol | handshake
    #                                 | rejected (server refused the test) | internal (not a global address)
    #                                 | dns_fail (name lookup errored) | v6 (IPv6 only, no IPv6 route)
    detail: str = ""
    tls_version: str = ""
    verified: bool = False          # chain + host name verified
    verify_error: str = ""          # expired | hostname | untrusted | other
    not_after: int | None = None
    names: list[str] = field(default_factory=list)


CONNECT_ERRORS = frozenset({"timeout", "refused", "unreachable", "dns"})
OFFLINE_ERRORS = frozenset({"timeout", "unreachable", "dns_fail", "v6"})   # what "no internet" looks like
UNTESTABLE_ERRORS = frozenset({"rejected", "internal", "dns_fail", "v6"})
ERROR_TEXT = {"timeout": "ingen svar", "refused": "forbindelsen blev afvist", "unreachable": "kan ikke nås",
              "dns": "navnet findes ikke"}
OLD_TLS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})


def cert_info(der: bytes) -> tuple[int | None, list[str]]:
    """DER certificate -> (not_after unix, DNS names)."""
    try:
        from cryptography import x509  # noqa: PLC0415 - pinned (push notifications)

        c = x509.load_der_x509_certificate(der)
        na = getattr(c, "not_valid_after_utc", None) or c.not_valid_after
        names: list[str] = []
        try:
            san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            names = [str(n) for n in san.get_values_for_type(x509.DNSName)][:20]
        except x509.ExtensionNotFound:
            pass
        if na.tzinfo is None:
            na = na.replace(tzinfo=datetime.timezone.utc)
        return int(na.timestamp()), names
    except Exception:  # noqa: BLE001 - no details is not a failure
        return None, []


def _verify_kind(ex: ssl.SSLCertVerificationError) -> str:
    code = getattr(ex, "verify_code", None)
    msg = str(getattr(ex, "verify_message", "") or ex).lower()
    if code == 10 or "expired" in msg:
        return "expired"
    if code == 62 or "hostname" in msg or "ip address mismatch" in msg:
        return "hostname"
    if code in (2, 18, 19, 20, 21) or "self" in msg or "issuer" in msg:
        return "untrusted"
    return "other"


def public_ip(ip: str) -> bool:
    """A globally routable unicast address: never private, loopback,
    link-local, CGNAT (100.64/10), multicast, reserved or unspecified."""
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped is not None:
        a = a.ipv4_mapped
    return bool(a.is_global and not a.is_multicast and not a.is_reserved and not a.is_unspecified
                and a not in _CGNAT)


_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def helo_name(conn: sqlite3.Connection | None = None) -> str:
    """The EHLO name of the probes: $MAILCHECK_HELO, else the host of the
    external address (settings_kv 'external_url'), else the machine's
    FQDN when it is a real one, else mailcheck.invalid."""
    raw = (os.environ.get(HELO_ENV) or "").strip().lower().rstrip(".")
    if raw and _HOST_RE.match(raw) and "." in raw:
        return raw
    if conn is not None:
        try:
            row = conn.execute("SELECT value FROM settings_kv WHERE key='external_url'").fetchone()
            url = str(row[0] or "") if row else ""
        except sqlite3.Error:
            url = ""
        host = url.split("://", 1)[-1].split("/", 1)[0].rsplit(":", 1)[0].strip().lower() if url else ""
        if host and "." in host and _HOST_RE.match(host):
            return host
    try:
        fq = socket.getfqdn().strip().lower().rstrip(".")
    except OSError:
        fq = ""
    if fq and "." in fq and _HOST_RE.match(fq) and not fq.endswith((".local", ".localdomain", ".lan", ".home",
                                                                     ".internal", ".arpa", "localhost")):
        return fq
    return HELO_NAME


class _Rejected(Exception):
    """The server turned the test connection down (banner, EHLO, reset)."""


class _Lines:
    """Line reader on a raw socket bounded by the probe's deadline (a
    server that drips bytes cannot stretch a probe)."""

    def __init__(self, sock: socket.socket, end: float, per_op: float) -> None:
        self.sock, self.end, self.per_op = sock, end, per_op
        self.buf = b""

    def readline(self, limit: int = 2048) -> bytes:
        while True:
            i = self.buf.find(b"\n")
            if 0 <= i < limit or len(self.buf) >= limit:
                cut = i + 1 if 0 <= i < limit else limit
                line, self.buf = self.buf[:cut], self.buf[cut:]
                return line
            rem = self.end - time.monotonic()
            if rem <= 0:
                raise socket.timeout("deadline")
            self.sock.settimeout(min(self.per_op, rem))
            chunk = self.sock.recv(4096)
            if not chunk:
                line, self.buf = self.buf, b""
                return line
            self.buf += chunk


class TlsProber:
    """One TCP + (STARTTLS) + TLS handshake per call; the network in
    production, replaced by a fake in tests.

    SSRF hardening: the host name is resolved through `resolver` (the
    stack's own Unbound - the same answers the checks saw), only global
    unicast addresses are connected to ("intern adresse" otherwise), the
    connection goes to the resolved address and the certificate is
    verified against the NAME (SNI). Everything - connect, dialogue, both
    handshakes - shares one monotonic deadline (`deadline_s`); a watchdog
    shuts the socket down when it passes."""

    def __init__(self, timeout: float = TCP_TIMEOUT_S, helo: str | None = None, *, resolver: Resolver | None = None,
                 deadline_s: float = PROBE_DEADLINE_S, allow_private: bool = False) -> None:
        self.timeout = float(timeout)
        self.helo = helo or HELO_NAME
        self.resolver = resolver
        self.deadline_s = float(deadline_s)
        self.allow_private = bool(allow_private)

    @staticmethod
    def _smtp_reply(f: Any) -> int:
        code = 0
        for _ in range(64):
            line = f.readline(2048)
            if not line:
                return 0
            try:
                code = int(line[:3])
            except ValueError:
                return 0
            if line[3:4] != b"-":
                return code
        return 0

    def _starttls(self, sock: socket.socket, mode: str, f: _Lines) -> str:
        """'' when TLS can start, 'no_starttls'; raises _Rejected."""
        if mode == "smtp":
            code = self._smtp_reply(f)
            if code != 220:
                raise _Rejected(f"svarede {code}" if code else "lukkede forbindelsen")
            sock.sendall(f"EHLO {self.helo}\r\n".encode())
            lines: list[bytes] = []
            for _ in range(64):
                line = f.readline(2048)
                if not line:
                    break
                lines.append(line)
                if line[3:4] != b"-":
                    break
            if not lines:
                raise _Rejected("lukkede forbindelsen efter EHLO")
            if lines[-1][:3] != b"250":
                raise _Rejected(f"EHLO blev afvist ({lines[-1][:3].decode('ascii', 'replace')})")
            if not any(ln[4:].upper().startswith(b"STARTTLS") for ln in lines):
                return "no_starttls"
            sock.sendall(b"STARTTLS\r\n")
            code = self._smtp_reply(f)
            if code == 220:
                return ""
            if code == 0 or 400 <= code < 500:
                raise _Rejected(f"STARTTLS svarede {code}" if code else "lukkede forbindelsen")
            return "no_starttls"
        greeting = f.readline(4096)
        if not greeting:
            raise _Rejected("lukkede forbindelsen")
        if not greeting.startswith(b"* OK"):
            raise _Rejected("ingen IMAP-hilsen")
        sock.sendall(b"a1 STARTTLS\r\n")
        for _ in range(64):
            line = f.readline(4096)
            if not line:
                raise _Rejected("lukkede forbindelsen")
            if line.upper().startswith(b"A1 "):
                return "" if line.upper().startswith(b"A1 OK") else "no_starttls"
        return "no_starttls"

    def _addresses(self, host: str) -> tuple[list[str], str, str]:
        """-> (addresses to try, error, detail)."""
        try:
            ipaddress.ip_address(host)
            ips = [host]
        except ValueError:
            if self.resolver is not None:
                a, b = self.resolver.query(host, "A"), self.resolver.query(host, "AAAA")
                ips = list(a.records) + list(b.records)
                if not ips:
                    return [], ("dns_fail" if (a.failed or b.failed) else "dns"), ""
            else:
                try:
                    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
                except socket.gaierror:
                    return [], "dns", ""
                ips = list(dict.fromkeys(str(i[4][0]) for i in infos))
                ips.sort(key=lambda x: ":" in x)
        allowed = [ip for ip in ips if self.allow_private or public_ip(ip)]
        if not allowed:
            return [], "internal", ips[0] if ips else ""
        return allowed[:3], "", ""

    def __call__(self, host: str, port: int, mode: str) -> Probe:
        p = Probe(host, int(port), mode)
        end = time.monotonic() + self.deadline_s
        ips, err, detail = self._addresses(host)
        if err:
            p.error, p.detail = err, detail
            return p
        for verify in (True, False):
            sock, err = self._connect(ips, int(port), end)
            if sock is None:
                p.error = err
                return p
            watchdog = threading.Timer(max(0.0, end - time.monotonic()), _shutdown, args=(sock,))
            watchdog.daemon = True
            watchdog.start()
            try:
                if mode in ("smtp", "imap"):
                    why = self._starttls(sock, mode, _Lines(sock, end, self.timeout))
                    if why:
                        p.error, p.detail = "starttls", why
                        return p
                if verify:
                    ctx = ssl.create_default_context()
                else:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                rem = end - time.monotonic()
                if rem <= 0:
                    raise socket.timeout("deadline")
                sock.settimeout(min(self.timeout, rem))
                try:
                    ss = ctx.wrap_socket(sock, server_hostname=host)   # SNI + name check against the NAME
                except ssl.SSLCertVerificationError as ex:
                    p.verify_error = _verify_kind(ex)
                    continue  # once more without verification, to read the certificate
                except ssl.SSLError as ex:
                    if time.monotonic() >= end:
                        raise socket.timeout("deadline") from None
                    reason = str(getattr(ex, "reason", "") or ex)
                    old = any(w in reason.upper() for w in ("PROTOCOL", "VERSION"))
                    p.error, p.detail = ("protocol" if old else "handshake"), reason[:120]
                    return p
                with ss:
                    p.ok, p.verified = True, verify
                    p.tls_version = ss.version() or ""
                    der = ss.getpeercert(binary_form=True)
                    if der:
                        p.not_after, p.names = cert_info(der)
                    try:
                        ss.sendall(b"QUIT\r\n" if mode == "smtp" else b"a2 LOGOUT\r\n" if mode == "imap" else b"")
                    except OSError:
                        pass
                return p
            except _Rejected as ex:
                # the watchdog's shutdown also looks like "closed the connection"
                p.error, p.detail = ("timeout", "") if time.monotonic() >= end else ("rejected", str(ex)[:120])
                return p
            except socket.timeout:
                p.error = "timeout"
                return p
            except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                p.error, p.detail = ("timeout", "") if time.monotonic() >= end else ("rejected", "forbindelsen blev nulstillet")
                return p
            except OSError as ex:
                p.error, p.detail = ("timeout", "") if time.monotonic() >= end else ("unreachable", type(ex).__name__)
                return p
            finally:
                watchdog.cancel()
                try:
                    sock.close()
                except OSError:
                    pass
        return p

    def _connect(self, ips: Sequence[str], port: int, end: float) -> tuple[socket.socket | None, str]:
        last = "unreachable"
        for ip in ips:
            rem = end - time.monotonic()
            if rem <= 0:
                return None, "timeout"
            try:
                return socket.create_connection((ip, port), timeout=min(self.timeout, rem)), ""
            except socket.timeout:
                last = "timeout"
            except ConnectionRefusedError:
                last = "refused"
            except OSError:
                last = "unreachable"
        if last == "unreachable" and ips and all(":" in ip for ip in ips):
            return None, "v6"
        return None, last


def _shutdown(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


ROLE_TEXT = {"mx": "Modtager mail (MX)", "smtp": "Afsender (SMTP)", "imap": "Postkasse (IMAP)"}


def server_targets(domains: Sequence[dict[str, Any]], accounts: Iterable[Any],
                   smtp: dict[str, Any] | None) -> list[dict[str, Any]]:
    """MX hosts (port 25, STARTTLS), the SMTP submission host, the IMAP
    hosts - de-duplicated by (host, port)."""
    out: dict[tuple[str, int], dict[str, Any]] = {}

    def add(host: Any, port: int, mode: str, role: str, why: str) -> None:
        h = str(host or "").strip().rstrip(".").lower()
        if not h or not _HOST_RE.match(h):
            return
        e = out.setdefault((h, int(port)), {"host": h, "port": int(port), "mode": mode, "role": role, "for": []})
        if why and why not in e["for"]:
            e["for"].append(why)

    for d in domains:
        for hh in d.get("mx_hosts") or []:
            add(hh["host"], 25, "smtp", "mx", d["domain"])
    if smtp and smtp.get("host"):
        sec = str(smtp.get("security") or "starttls")
        add(smtp["host"], int(smtp.get("port") or (465 if sec == "ssl" else 587)),
            "tls" if sec == "ssl" else "smtp", "smtp", "filterets egne beskeder")
    for a in accounts or ():
        host = getattr(a, "imap_host", "")
        port = int(getattr(a, "imap_port", 993) or 993)
        use_ssl = bool(getattr(a, "ssl", port == 993))
        add(host, port, "tls" if use_ssl else "imap", "imap", str(getattr(a, "name", "") or ""))
    return list(out.values())[:MAX_SERVERS]


def evaluate_server(t: dict[str, Any], p: Probe, *, now: int, port25_blocked: bool,
                    provider: str | None = None, offline: bool = False) -> dict[str, Any]:
    """Probe -> one result item (pure; the tests feed fake probes).
    offline: no server answered at all (or DNS is down) - a connect error
    is then "could not be tested", never an error."""
    role, host, port = t["role"], t["host"], int(t["port"])
    key = f"srv:{role}:{host}:{port}"
    area = f"{host}:{port}"
    base = {"role": role, "host": host, "port": port, "for": list(t.get("for") or []), "tls": p.tls_version,
            "days": None, "verified": p.verified}
    who = f"Kontakt {provider}" if provider else "Kontakt udbyderen af serveren"
    if p.error == "skipped":
        return item(key, area, UNKNOWN, f"Ikke testet ({p.detail or 'sprunget over'}).", skipped=True, **base)
    if p.error == "rejected":
        return item(key, area, UNKNOWN, "Kunne ikke testes: serveren afviste testforbindelsen"
                    + (f" ({p.detail})" if p.detail else "") + " – normalt fra en hjemme-IP.", **base)
    if p.error == "internal":
        return item(key, area, UNKNOWN, "Intern adresse" + (f" ({p.detail})" if p.detail else "") + " – ikke testet.",
                    **base)
    if p.error == "dns_fail":
        return item(key, area, UNKNOWN, "Kunne ikke testes: navnet kunne ikke slås op.", **base)
    if p.error == "v6":
        return item(key, area, UNKNOWN, "Kunne ikke testes: serveren har kun IPv6-adresser, og denne maskine har "
                    "ingen IPv6-forbindelse.", **base)
    if offline and p.error in OFFLINE_ERRORS:
        return item(key, area, UNKNOWN, f"Kunne ikke testes ({ERROR_TEXT.get(p.error, p.error)}): ingen af "
                    "serverne svarede – er internetforbindelsen nede?", **base)
    if p.error in CONNECT_ERRORS:
        if role == "mx" and port == 25 and port25_blocked:
            return item(key, area, UNKNOWN, "Kunne ikke testes (port 25 blokeret). Internetudbydere blokerer "
                        "typisk udgående port 25 fra private forbindelser, så MX-serverne kan ikke testes herfra.",
                        **base)
        if role == "mx":
            return item(key, area, WARN, f"MX-serveren svarer ikke på port 25 ({ERROR_TEXT[p.error]}), selv om andre "
                        "MX-servere gør.", f"{who}, hvis det varer ved.", **base)
        fix = ("Tjek servernavn og port under Indstillinger → Mail." if role == "smtp"
               else "Tjek servernavn og port under Konti.")
        return item(key, area, BAD, f"Serveren svarer ikke ({ERROR_TEXT[p.error]}).", fix, **base)
    if p.error == "starttls":
        text = ("Serveren tilbyder ikke kryptering (STARTTLS), så mail og adgangskoder sendes i klar tekst."
                if p.detail == "no_starttls" else f"Kunne ikke starte kryptering ({p.detail}).")
        return item(key, area, BAD, text, f"{who}.", **base)
    if p.error == "protocol":
        return item(key, area, BAD, f"Serveren understøtter ikke TLS 1.2 eller nyere ({p.detail}).",
                    f"{who} – TLS 1.0 og 1.1 er forældede og usikre.", **base)
    if p.error or not p.ok:
        return item(key, area, BAD, f"Krypteringen (TLS) kunne ikke forhandles ({p.detail or p.error or 'ukendt'}).",
                    f"{who}.", **base)
    problems: list[tuple[str, str, str]] = []
    if p.tls_version in OLD_TLS:
        problems.append((BAD, f"Forbindelsen bruger kun {p.tls_version}.", f"{who} – kræv TLS 1.2 eller nyere."))
    names = ", ".join(p.names[:3])
    if p.verify_error == "expired":
        problems.append((BAD, "Certifikatet er udløbet.", f"{who} – certifikatet skal fornyes."))
    elif p.verify_error == "hostname":
        problems.append((WARN if role == "mx" else BAD, f"Certifikatet passer ikke til navnet {host}"
                         + (f" (det gælder for {names})" if names else "") + ".",
                         f"Brug det navn, certifikatet gælder for, eller {who.lower()}."))
    elif p.verify_error == "untrusted":
        problems.append((WARN if role == "mx" else BAD, "Certifikatet er ikke udstedt af en betroet udsteder "
                         "(selvsigneret eller mangler mellemcertifikat).", f"{who}."))
    elif p.verify_error:
        problems.append((WARN, "Certifikatet kunne ikke godkendes.", f"{who}."))
    days = None
    if p.not_after is not None:
        days = int((p.not_after - now) // 86400)
        base["days"] = days
        if days < 0 and p.verify_error != "expired":
            problems.append((BAD, "Certifikatet er udløbet.", f"{who} – certifikatet skal fornyes."))
        elif 0 <= days < CERT_BAD_DAYS:
            problems.append((BAD, f"Certifikatet udløber om {_n(days, 'dag', 'dage')}.",
                             f"{who} med det samme – certifikatet skal fornyes."))
        elif CERT_BAD_DAYS <= days < CERT_WARN_DAYS:
            problems.append((WARN, f"Certifikatet udløber om {days} dage.",
                             "Fornyes det ikke automatisk inden for en uge, så " + who.lower() + "."))
    tail = f"TLS {p.tls_version.replace('TLSv', '')}" if p.tls_version else "TLS"
    if days is not None and days >= 0:
        tail += f", certifikatet gælder {days} dage endnu"
    if not problems:
        return item(key, area, OK, f"Krypteret forbindelse ({tail}).", **base)
    st = worst(s for s, _t, _f in problems)
    return item(key, area, st, " ".join(t for _s, t, _f in problems) + f" ({tail}).",
                " ".join(dict.fromkeys(f for s, _t, f in problems if s == st)), **base)


def check_servers(targets: Sequence[dict[str, Any]], prober: Callable[[str, int, str], Probe], *, now: int,
                  providers: dict[str, str | None] | None = None, workers: int = SERVER_WORKERS,
                  offline: bool = False) -> list[dict[str, Any]]:
    if not targets:
        return []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets)))) as ex:
        probes = list(ex.map(lambda t: _safe_probe(prober, t), targets))
    mx25 = [p for t, p in zip(targets, probes) if t["role"] == "mx" and int(t["port"]) == 25]
    blocked = bool(mx25) and all(p.error in CONNECT_ERRORS | OFFLINE_ERRORS for p in mx25)
    # Not one server answered (port 25 aside, which ISPs block): the
    # connection is down, not every mail server at once.
    rest = [p for t, p in zip(targets, probes) if not (t["role"] == "mx" and int(t["port"]) == 25)]
    offline = offline or (bool(rest) and all(p.error in OFFLINE_ERRORS for p in rest))
    providers = providers or {}
    return [evaluate_server(t, p, now=now, port25_blocked=blocked,
                            provider=providers.get(t["host"]) or provider_of(t["host"]), offline=offline)
            for t, p in zip(targets, probes)]


def _safe_probe(prober: Callable[[str, int, str], Probe], t: dict[str, Any]) -> Probe:
    try:
        return prober(t["host"], int(t["port"]), t["mode"])
    except Exception as ex:  # noqa: BLE001 - a probe never breaks a run
        return Probe(t["host"], int(t["port"]), t["mode"], error="handshake", detail=type(ex).__name__)


# ---------------------------------------------------------------- blacklists
SPAMHAUS_REFUSED = {"127.255.255.252": "forkert forespørgsel", "127.255.255.254": "offentlig eller åben resolver",
                    "127.255.255.255": "for mange opslag"}
SPAMHAUS_LISTS = {2: "SBL", 3: "CSS", 4: "XBL", 5: "XBL", 6: "XBL", 7: "XBL", 9: "DROP", 10: "PBL", 11: "PBL"}
SPAMHAUS_PBL = frozenset({10, 11})        # policy list of dynamic/end-user ranges: info, not a listing


def dnsbl_name(ip: str, zone: str) -> str:
    return ".".join(reversed(ip.split("."))) + "." + zone


def interpret_dnsbl(zone: str, ans: Answer) -> tuple[str, str]:
    """-> (listed | pbl | clean | unknown, Danish detail). pbl = only on
    Spamhaus PBL (127.0.0.10/11: a dynamic / end-user address range - the
    normal state of a home connection, not a listing for spam)."""
    if ans.status in ("nxdomain", "nodata"):
        return "clean", ""
    if ans.failed:
        if ans.error in LIMIT_ERRORS:
            return "unknown", "ikke testet (grænse nået)"
        return "unknown", "kunne ikke slås op" + (f" ({ans.error})" if ans.error else "")
    codes = []
    for r in ans.records:
        try:
            ip = ipaddress.ip_address(r)
        except ValueError:
            return "unknown", "uventet svar"
        if ip.version != 4 or not ip.is_loopback:
            return "unknown", f"uventet svar {r} (omskriver resolveren svarene?)"
        codes.append(str(ip))
    if zone.endswith("spamhaus.org"):
        refused = [c for c in codes if c.startswith("127.255.255.")]
        if refused:
            why = SPAMHAUS_REFUSED.get(refused[0], "afvist")
            return "unknown", f"kunne ikke slås op – Spamhaus afviste opslaget ({refused[0]}: {why})"
        real = [c for c in codes if int(c.rsplit(".", 1)[1]) not in SPAMHAUS_PBL]
        if not real:
            return "pbl", "PBL"
        lists = sorted({SPAMHAUS_LISTS.get(int(c.rsplit(".", 1)[1]), c) for c in real})
        return "listed", ", ".join(lists)
    return "listed", ", ".join(codes)


def blacklist_ips(evidence: dict[str, dict[str, Any]], domains: Sequence[dict[str, Any]],
                  limit: int = DNSBL_MAX_IPS) -> list[dict[str, Any]]:
    """[{ip, why[], sender}]: the providers' outbound relays - sending IPs
    of the owner's own mail that passed SPF for the domain (mail_evidence)
    and the DMARC reports' SPF-passing sources, kept only when the
    domain's own SPF tree authorises them (d["spf_nets"], when it could be
    expanded completely) - then the MX addresses (public IPv4)."""
    out: dict[str, dict[str, Any]] = {}
    spf = {d["domain"]: d for d in domains}

    def add(ip: str, why: str, sender: bool) -> None:
        try:
            a = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return
        if a.version != 4 or not public_ip(str(a)):
            return
        e = out.setdefault(str(a), {"ip": str(a), "why": [], "sender": False})
        if why not in e["why"]:
            e["why"].append(why)
        e["sender"] = e["sender"] or sender

    def authorised(dom: str, ip: str) -> bool:
        d = spf.get(dom) or {}
        if not d.get("spf_complete"):
            return True       # macros / unanswered parts: the mail's own SPF pass has to do
        return ip_in_nets(ip, d.get("spf_nets") or [])

    for dom, ev in evidence.items():
        for ip in sorted(ev.get("ips") or {}, key=lambda k: -ev["ips"][k])[:4]:
            if authorised(dom, ip):
                add(ip, f"sender mail for {dom}", True)
        for ip in sorted(ev.get("dmarc_ips") or {}, key=lambda k: -ev["dmarc_ips"][k])[:3]:
            if authorised(dom, ip):
                add(ip, f"sender mail for {dom} (DMARC-rapport)", True)
    for d in domains:
        for hh in d.get("mx_hosts") or []:
            for ip in hh.get("ips") or []:
                add(ip, f"MX for {d['domain']}", False)
    return list(out.values())[:limit]


def check_blacklists(ips: Sequence[dict[str, Any]], resolver: Resolver, *, zones: Sequence[tuple[str, str]] = DNSBL_ZONES,
                     pause: Callable[[float], Any] | None = None, rate_s: float = DNSBL_RATE_S,
                     stop: threading.Event | None = None) -> list[dict[str, Any]]:
    out = []
    for e in ips:
        ip = e["ip"]
        listed, unknown, pbl, results = [], [], [], {}
        ptr = resolver.query(reverse_name(ip), "PTR")
        name = ptr.records[0] if ptr.ok else ""
        for zone, label in zones:
            if stop is not None and stop.is_set():
                return out
            if pause is not None and rate_s > 0:
                pause(rate_s)
            state, detail = interpret_dnsbl(zone, resolver.query(dnsbl_name(ip, zone), "A"))
            results[zone] = {"state": state, "detail": detail}
            if state == "listed":
                listed.append(f"{label}" + (f" ({detail})" if detail else ""))
            elif state == "pbl":
                pbl.append(label)
            elif state == "unknown":
                unknown.append(f"{label}: {detail}")
        key = f"bl:{ip}"
        area = ip + (f" ({name})" if name else "")
        prov = provider_of(name)
        extra = {"ip": ip, "ptr": name, "why": e["why"], "zones": results, "sender": bool(e.get("sender"))}
        pbl_text = ("Spamhaus PBL: dynamisk IP – normalt (adressen står som en almindelig "
                    "internetforbindelse, ikke som spam). " if pbl else "")
        if listed:
            out.append(item(key, area, BAD, f"Står på {', '.join(listed)}. Mail fra adressen kan blive afvist eller "
                            "lagt i spam.", (f"Det er {prov}s server. Kontakt {prov}" if prov else "Kontakt ejeren af "
                            "serveren") + " og bed dem få adressen fjernet fra listen.", **extra))
        elif unknown and len(unknown) == len(zones):
            out.append(item(key, area, UNKNOWN, "Kunne ikke slås op: " + "; ".join(unknown[:2]) + ".", **extra))
        elif pbl:
            ok_n = len(zones) - len(unknown) - len(pbl)
            out.append(item(key, area, INFO, pbl_text + f"Ikke på nogen af de {ok_n} andre lister"
                            + (f" (kunne ikke slås op: {'; '.join(unknown[:2])})" if unknown else "") + ".", **extra))
        else:
            ok_n = len(zones) - len(unknown)
            out.append(item(key, area, OK, f"Ikke på nogen af de {ok_n} lister"
                            + (f" (kunne ikke slås op: {'; '.join(unknown[:2])})" if unknown else "") + ".", **extra))
    return out


# ---------------------------------------------------------------- one run
def _dmarc_context(conn: sqlite3.Connection | None) -> tuple[dict[str, Any], Callable[[str], str | None]]:
    try:
        dm = _dmarc_mod()
        cfg = dm.load_settings(conn)
    except Exception:  # noqa: BLE001
        return {"rua": "", "domains": []}, lambda _d: None

    def advice(domain: str) -> str | None:
        if conn is None:
            return None
        try:
            for s in dm.summaries(conn, domains=[domain]):
                if s.get("domain") == domain and s.get("reports"):
                    return (s.get("advice") or {}).get("text")
        except Exception:  # noqa: BLE001 - the advice is a courtesy
            return None
        return None

    return cfg, advice


CONTROL_QUERIES_AFTER = (("se", "SOA"), ("net", "SOA"))   # other names: the first ones are cached


def _real_failure(a: Answer) -> bool:
    return a.failed and a.error not in LIMIT_ERRORS


def _skipped_domain(d: dict[str, Any], text: str) -> None:
    dom = d["domain"]
    d.update(provider=KNOWN_PROVIDERS.get(dom), dns_host=None, mx_hosts=[], mails=0, status=UNKNOWN,
             checks=[item(f"{dom}:skipped", "Tjek", UNKNOWN, text, domain=dom)])


def _degrade(results: dict[str, Any], why: str) -> None:
    """An offline / degraded run: every warning and error becomes "could
    not be tested" (the original status stays in degraded_from)."""
    for it in all_items(results):
        if it.get("status") in (WARN, BAD):
            it["degraded_from"] = it["status"]
            it["status"] = UNKNOWN
            it["text"] = ("Usikkert – DNS svarede ikke ordentligt under tjekket: " + str(it.get("text") or ""))[:600]
    for d in results.get("domains") or []:
        d["status"] = worst(c["status"] for c in d.get("checks") or []) if d.get("checks") else UNKNOWN
    results["degraded"] = why


def run_check(*, accounts: Iterable[Any], conn: sqlite3.Connection | None, settings: dict[str, Any] | None = None,
              smtp: dict[str, Any] | None = None, resolver: Resolver | None = None,
              prober: Callable[[str, int, str], Probe] | None = None, now: float | None = None, reason: str = "manual",
              pause: Callable[[float], Any] | None = None, stop: threading.Event | None = None,
              wildcard_token: str | None = None, deadline_s: float = RUN_DEADLINE_S,
              max_queries: int | None = None, helo: str | None = None) -> dict[str, Any] | None:
    """Run every check -> the results dict (not stored). None when `stop`
    was set before the end. One monotonic deadline (`deadline_s`) bounds
    the run: what is left when it passes is "ikke testet". The DNS budget
    scales with the number of domains, and the blacklist step gets its own
    reserve so it is never silently skipped."""
    t0 = int(time.time() if now is None else now)
    run_end = time.monotonic() + float(deadline_s)
    accounts = list(accounts or ())
    settings = settings if settings is not None else load_settings(conn)
    resolver = resolver or make_resolver()
    resolver.deadline = run_end
    pause = pause if pause is not None else (lambda s: (stop.wait(s) if stop is not None else time.sleep(s)))
    dmarc_cfg, advice_for = _dmarc_context(conn)
    rua_default = dmarc_cfg.get("rua") or siteconfig.get("admin_email") or ""
    domains = domain_targets(accounts, settings, dmarc_cfg)
    resolver.max_queries = (int(max_queries) if max_queries is not None else
                            max(resolver.max_queries, RUN_BASE_QUERIES + RUN_DOMAIN_QUERIES * len(domains)))
    prober = prober or TlsProber(resolver=resolver, helo=helo or helo_name(conn))

    def late() -> bool:
        return time.monotonic() > run_end

    # Offline / broken resolver: both control queries fail -> nothing is tested.
    dns_down = all(_real_failure(resolver.query(n, t)) for n, t in CONTROL_QUERIES)
    memory = load_selector_memory(conn)
    evidence: dict[str, dict[str, Any]] = {}
    providers: dict[str, str | None] = {}
    q0, f0 = resolver.queries, resolver.failures
    timed_out = False
    for d in domains:
        if stop is not None and stop.is_set():
            return None
        dom, no_mail = d["domain"], d["no_mail"]
        if dns_down:
            _skipped_domain(d, "Ikke testet: DNS svarede ikke (heller ikke på kontrolopslag).")
            continue
        if late():
            timed_out = True
            _skipped_domain(d, "Ikke testet: tidsgrænsen for tjekket blev nået.")
            continue
        ev = mail_evidence(conn, dom, now=t0) if not no_mail else mail_evidence(None, dom, now=t0)
        if not no_mail:
            _merge_memory(ev, memory.get(dom), t0)
        evidence[dom] = ev
        dns_host = check_ns(dom, resolver)
        spf_rec = next((r for r in txt(resolver, dom).records if is_spf(r)), None)
        mx_ans = resolver.query(dom, "MX")
        mx_names = [h for _p, h in parse_mx(mx_ans.records)]
        provider = (KNOWN_PROVIDERS.get(dom) or provider_of(*spf_includes(spf_rec)) or provider_of(*mx_names))
        d["provider"], d["dns_host"] = provider, dns_host or (provider if dom in KNOWN_PROVIDERS else None)
        checks: list[dict[str, Any]] = []
        mx_items, mx_hosts = check_mx(dom, no_mail, resolver, provider, d["dns_host"])
        checks += mx_items
        d["mx_hosts"] = mx_hosts
        for hh in mx_hosts:
            providers.setdefault(hh["host"], provider_of(hh["host"]) or provider)
        spf_info: dict[str, Any] = {}
        checks += check_spf(dom, no_mail, resolver, provider, d["dns_host"], info=spf_info)
        d["spf_nets"] = list(spf_info.get("nets") or [])[:200]
        d["spf_complete"] = bool(spf_info.get("nets_complete"))
        checks += check_dkim(dom, no_mail, resolver, ev, (settings.get("selectors") or {}).get(dom, []), provider,
                             d["dns_host"], now=t0)
        checks += check_dmarc(dom, no_mail, resolver, rua_default=rua_default, advice=advice_for(dom),
                              dns_host=d["dns_host"])
        checks += check_optional(dom, no_mail, resolver)
        checks.append(check_dnssec(dom, resolver, d["dns_host"]))
        wc = check_wildcard(dom, resolver, token=wildcard_token)
        if wc:
            checks.append(wc)
        for c in checks:
            c["domain"] = dom
        d["checks"] = checks
        d["status"] = worst(c["status"] for c in checks)
        d["mails"] = ev.get("mails", 0)
    dq, df = resolver.queries - q0, resolver.failures - f0
    if stop is not None and stop.is_set():
        return None
    targets = server_targets(domains, accounts, smtp)
    if dns_down or late():
        timed_out = timed_out or not dns_down
        why = "DNS svarede ikke" if dns_down else "tidsgrænsen for tjekket blev nået"
        servers = [evaluate_server(t, Probe(t["host"], int(t["port"]), t["mode"], error="skipped", detail=why),
                                   now=t0, port25_blocked=False) for t in targets]
    else:
        def bounded(host: str, port: int, mode: str) -> Probe:
            if late():
                return Probe(host, port, mode, error="skipped", detail="tidsgrænsen for tjekket blev nået")
            return prober(host, port, mode)

        servers = check_servers(targets, bounded, now=t0, providers=providers)
        timed_out = timed_out or any(s.get("skipped") for s in servers)
    if stop is not None and stop.is_set():
        return None
    ips = blacklist_ips(evidence, domains)
    need = len(ips) * (len(DNSBL_ZONES) + 1) + len(CONTROL_QUERIES_AFTER)
    if resolver.max_queries - resolver.queries < need:   # the blacklist step's own reserve
        resolver.max_queries = resolver.queries + need
    blacklists = check_blacklists(ips, resolver, pause=pause, rate_s=DNSBL_RATE_S, stop=stop)
    if stop is not None and stop.is_set():
        return None
    degraded = None
    if dns_down:
        degraded = "DNS svarede ikke (heller ikke på kontrolopslag) – er internetforbindelsen eller Unbound nede?"
    elif dq >= DEGRADED_MIN_QUERIES and df / dq >= DEGRADED_RATIO:
        degraded = f"{df} af {dq} DNS-opslag fejlede – forbindelsen eller Unbound virkede ikke ordentligt."
    elif all(_real_failure(resolver.query(n, t)) for n, t in CONTROL_QUERIES_AFTER):
        degraded = "DNS holdt op med at svare undervejs (kontrolopslag fejlede)."
    results = {"version": RESULTS_VERSION, "started_at": t0, "finished_at": int(time.time() if now is None else now),
               "reason": reason, "domains": domains, "servers": servers, "blacklists": blacklists,
               "dns_queries": resolver.queries, "dns_failed": resolver.failures, "dns_limited": resolver.limited,
               "timed_out": bool(timed_out or late())}
    if degraded:
        _degrade(results, degraded)
    results["counts"] = counts(results)
    results["status"] = overall(results)
    results["_selector_memory"] = _new_memory(memory, evidence, t0)
    return results


def all_items(results: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not results:
        return []
    out = []
    for d in results.get("domains") or []:
        out += list(d.get("checks") or [])
    return out + list(results.get("servers") or []) + list(results.get("blacklists") or [])


def counts(results: dict[str, Any]) -> dict[str, int]:
    c = {s: 0 for s in STATUSES}
    for it in all_items(results):
        c[it.get("status", UNKNOWN)] = c.get(it.get("status", UNKNOWN), 0) + 1
    return c


def overall(results: dict[str, Any]) -> str:
    """bad / warn / ok - unknown for a degraded (offline) run."""
    if results.get("degraded"):
        return UNKNOWN
    c = results.get("counts") or counts(results)
    return BAD if c.get(BAD) else WARN if c.get(WARN) else OK


# ---------------------------------------------------------------- storage
SCHEMA = """
CREATE TABLE IF NOT EXISTS mailcheck_runs (
    id          INTEGER PRIMARY KEY,
    started_at  INTEGER NOT NULL,
    finished_at INTEGER NOT NULL,
    reason      TEXT,
    status      TEXT NOT NULL,
    errors      INTEGER NOT NULL DEFAULT 0,
    warnings    INTEGER NOT NULL DEFAULT 0,
    results     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS mailcheck_runs_finished ON mailcheck_runs(finished_at);
CREATE TABLE IF NOT EXISTS mailcheck_state (
    key        TEXT PRIMARY KEY,
    value      TEXT,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS mailcheck_alerted (
    key        TEXT PRIMARY KEY,
    level      INTEGER NOT NULL,
    alerted_at INTEGER NOT NULL
)
"""


def ensure_schema(conn: sqlite3.Connection) -> None:
    for stmt in (s.strip() for s in SCHEMA.split(";")):
        if stmt:
            conn.execute(stmt)


def state_get(conn: sqlite3.Connection, key: str) -> str | None:
    try:
        row = conn.execute("SELECT value FROM mailcheck_state WHERE key=?", (key,)).fetchone()
    except sqlite3.Error:
        return None
    return None if row is None else row[0]


def state_set(conn: sqlite3.Connection, key: str, value: str | None, now: float | None = None) -> None:
    ensure_schema(conn)
    if value is None:
        conn.execute("DELETE FROM mailcheck_state WHERE key=?", (key,))
    else:
        conn.execute("INSERT INTO mailcheck_state(key, value, updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE "
                     "SET value=excluded.value, updated_at=excluded.updated_at",
                     (key, str(value), int(time.time() if now is None else now)))


def _commit(conn: sqlite3.Connection) -> None:
    if conn.in_transaction:
        conn.commit()


def store_run(conn: sqlite3.Connection, results: dict[str, Any], *, keep: int = RUN_KEEP) -> int:
    ensure_schema(conn)
    c = results.get("counts") or counts(results)
    cur = conn.execute(
        "INSERT INTO mailcheck_runs(started_at, finished_at, reason, status, errors, warnings, results) "
        "VALUES(?,?,?,?,?,?,?)",
        (int(results.get("started_at") or 0), int(results.get("finished_at") or 0), str(results.get("reason") or "")[:20],
         str(results.get("status") or overall(results)), int(c.get(BAD, 0)), int(c.get(WARN, 0)),
         json.dumps(results, ensure_ascii=False, separators=(",", ":"))))
    rid = int(cur.lastrowid)
    conn.execute("DELETE FROM mailcheck_runs WHERE id NOT IN (SELECT id FROM mailcheck_runs ORDER BY id DESC LIMIT ?)",
                 (int(keep),))
    _commit(conn)
    return rid


def list_runs(conn: sqlite3.Connection, limit: int = HISTORY) -> list[dict[str, Any]]:
    try:
        ensure_schema(conn)
        rows = conn.execute("SELECT id, started_at, finished_at, reason, status, errors, warnings FROM mailcheck_runs "
                            "ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
    except sqlite3.Error:
        return []
    return [dict(id=r[0], started_at=r[1], finished_at=r[2], reason=r[3], status=r[4], errors=r[5], warnings=r[6])
            for r in rows]


def load_run(conn: sqlite3.Connection, run_id: int | None = None) -> dict[str, Any] | None:
    """One stored run (the newest without an id) with its id."""
    try:
        ensure_schema(conn)
        if run_id is None:
            row = conn.execute("SELECT id, results FROM mailcheck_runs ORDER BY id DESC LIMIT 1").fetchone()
        else:
            row = conn.execute("SELECT id, results FROM mailcheck_runs WHERE id=?", (int(run_id),)).fetchone()
    except sqlite3.Error:
        return None
    if row is None:
        return None
    try:
        data = json.loads(row[1])
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    data["id"] = int(row[0])
    return data


# 2.11.1: SpamExperts (a front filter Scannet can put before a domain's
# mailboxes) is "in front" of a domain only while its MX points there.
SPAMEXPERTS_MX = ("antispamcloud.com", "spamexperts.com", "spamexperts.eu", "spamexperts.net", "spamfilter.io")


def mx_hosts(results: dict[str, Any] | None, domain: str) -> list[str] | None:
    """The MX hosts a run read for `domain`; None when it did not read them."""
    for d in (results or {}).get("domains") or []:
        if d.get("domain") != domain:
            continue
        for c in d.get("checks") or []:
            if c.get("key") == f"{domain}:mx" and isinstance(c.get("hosts"), list):
                return [str(x) for x in c["hosts"]]
    return None


def spamexperts_in_front(conn: sqlite3.Connection | None, domain: Any, *, runs: int = 5) -> bool:
    """True only when the newest stored run (of the last `runs`) that read
    the domain's MX found a SpamExperts host. No run, no MX read or a
    database error -> False (the tip is then not shown). Read-only."""
    dom = clean_domain(domain)
    if conn is None or not dom:
        return False
    try:
        rows = conn.execute("SELECT results FROM mailcheck_runs ORDER BY id DESC LIMIT ?", (int(runs),)).fetchall()
    except sqlite3.Error:
        return False
    for row in rows:
        try:
            data = json.loads(row[0])
        except (TypeError, ValueError):
            continue
        hosts = mx_hosts(data if isinstance(data, dict) else None, dom)
        if hosts is not None:
            return any(under(h.lower().rstrip("."), suffix) for h in hosts for suffix in SPAMEXPERTS_MX)
    return False


def previous_run(conn: sqlite3.Connection, run_id: int) -> dict[str, Any] | None:
    """The run before `run_id` that was not degraded (an offline run says
    nothing about what changed)."""
    try:
        row = conn.execute("SELECT id FROM mailcheck_runs WHERE id < ? AND status != ? ORDER BY id DESC LIMIT 1",
                           (int(run_id), UNKNOWN)).fetchone()
    except sqlite3.Error:
        return None
    return load_run(conn, int(row[0])) if row else None


def diff_runs(prev: dict[str, Any] | None, cur: dict[str, Any] | None) -> list[dict[str, Any]]:
    """'Siden sidst': checks whose status changed, worse first."""
    if not prev or not cur or cur.get("degraded"):
        return []
    before = {it["key"]: it for it in all_items(prev)}
    after = {it["key"]: it for it in all_items(cur)}
    out = []
    for k, it in after.items():
        old = before.get(k)
        if old is None:
            if it["status"] in (WARN, BAD):
                out.append({"key": k, "item": it, "before": None, "after": it["status"], "direction": "new"})
            continue
        if old["status"] == it["status"]:
            continue
        lo, ln = LEVEL.get(old["status"]), LEVEL.get(it["status"])
        direction = ("worse" if lo is not None and ln is not None and ln > lo else
                     "better" if lo is not None and ln is not None and ln < lo else "changed")
        out.append({"key": k, "item": it, "before": old["status"], "after": it["status"], "direction": direction})
    for k, old in before.items():
        if k not in after and old["status"] in (WARN, BAD):
            out.append({"key": k, "item": old, "before": old["status"], "after": None, "direction": "gone"})
    order = {"worse": 0, "new": 1, "changed": 2, "better": 3, "gone": 4}
    return sorted(out, key=lambda x: (order[x["direction"]], x["key"]))


# ---------------------------------------------------------------- "Kendt – ignorér" (acknowledged findings)
def fingerprint(it: dict[str, Any]) -> str:
    """What an acknowledgement is bound to: the check, its status and its
    wording with the numbers left out (days left, counts) - a different
    status or a different problem text is a change."""
    text = re.sub(r"\d+", "#", str(it.get("text") or ""))
    raw = f"{it.get('key')}|{it.get('status')}|{text}"
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:20]


def load_acks(conn: sqlite3.Connection | None) -> dict[str, dict[str, Any]]:
    if conn is None:
        return {}
    try:
        data = json.loads(state_get(conn, "acks") or "{}")
    except (TypeError, ValueError):
        return {}
    return {str(k): v for k, v in data.items() if isinstance(v, dict) and v.get("fp")} if isinstance(data, dict) else {}


def _save_acks(conn: sqlite3.Connection, acks: dict[str, dict[str, Any]]) -> None:
    state_set(conn, "acks", json.dumps(acks, ensure_ascii=False, separators=(",", ":")) if acks else None)
    _commit(conn)


def acknowledge(conn: sqlite3.Connection, results: dict[str, Any] | None, key: str, fp: str, actor: str = "",
                now: float | None = None) -> bool:
    """Mark a warning/error of the newest run as known. False when the
    finding is not (or no longer) there with that fingerprint."""
    it = next((x for x in all_items(results) if x.get("key") == key), None)
    if it is None or it.get("status") not in (WARN, BAD) or fingerprint(it) != fp:
        return False
    acks = load_acks(conn)
    acks[key] = {"fp": fp, "at": int(time.time() if now is None else now), "by": str(actor or "")[:80],
                 "status": it["status"]}
    _save_acks(conn, acks)
    return True


def unacknowledge(conn: sqlite3.Connection, key: str) -> bool:
    acks = load_acks(conn)
    if key not in acks:
        return False
    del acks[key]
    _save_acks(conn, acks)
    return True


def acked_keys(results: dict[str, Any] | None, acks: dict[str, dict[str, Any]]) -> set[str]:
    return {it["key"] for it in all_items(results)
            if it.get("key") in acks and it.get("status") in (WARN, BAD) and fingerprint(it) == acks[it["key"]].get("fp")}


def effective(results: dict[str, Any] | None, acks: dict[str, dict[str, Any]] | None) -> dict[str, Any] | None:
    """A copy of a run with the acknowledged findings shown as info
    (acked=True, acked_status = the real status) and counts/status
    recomputed - what the page's figures, HA and sfctl doctor use."""
    if not results:
        return results
    keys = acked_keys(results, acks or {})
    out = json.loads(json.dumps(results, ensure_ascii=False))
    if not keys:
        return out
    for it in all_items(out):
        if it.get("key") in keys:
            it["acked"], it["acked_status"], it["status"] = True, it["status"], INFO
    for d in out.get("domains") or []:
        if d.get("checks"):
            d["status"] = worst(c["status"] for c in d["checks"])
    out["counts"] = counts(out)
    out["status"] = overall(out)
    out["acked"] = len(keys)
    return out


def prune_acks(conn: sqlite3.Connection, results: dict[str, Any], acks: dict[str, dict[str, Any]] | None = None
               ) -> dict[str, dict[str, Any]]:
    """After a (not degraded) run: an acknowledgement whose finding changed
    or went away is dropped - it then counts (and alerts) normally again.
    Untested findings keep theirs."""
    acks = load_acks(conn) if acks is None else acks
    by_key = {it["key"]: it for it in all_items(results)}
    keep = {}
    for k, a in acks.items():
        it = by_key.get(k)
        if it is not None and (it.get("status") == UNKNOWN or fingerprint(it) == a.get("fp")):
            keep[k] = a
    if keep != acks:
        _save_acks(conn, keep)
    return keep


def last_summary(conn: sqlite3.Connection | None, now: float | None = None) -> dict[str, Any] | None:
    """The newest stored run in a few numbers (sfctl doctor, HA, Drift),
    with the acknowledged findings counted as info."""
    if conn is None:
        return None
    runs = list_runs(conn, 1)
    if not runs:
        return None
    r = runs[0]
    data = effective(load_run(conn, r["id"]) or {}, load_acks(conn)) or {}
    c = counts(data) if data else {}
    status = overall(data) if data else r["status"]
    top = [f"{it.get('domain') or it.get('area')}: {it['area']}" if it.get("domain") else it["area"]
           for it in all_items(data) if it.get("status") == BAD][:3]
    t = time.time() if now is None else now
    return {"id": r["id"], "status": status, "errors": int(c.get(BAD, r["errors"])),
            "warnings": int(c.get(WARN, r["warnings"])), "finished_at": int(r["finished_at"]),
            "age_s": max(0, int(t - int(r["finished_at"]))), "top": top, "acked": int(data.get("acked") or 0),
            "degraded": data.get("degraded")}


# ---------------------------------------------------------------- learned DKIM selectors
def load_selector_memory(conn: sqlite3.Connection | None) -> dict[str, dict[str, int]]:
    """{domain: {"signing domain|selector": last seen unix}} - selectors of
    passing signatures, remembered across runs."""
    if conn is None:
        return {}
    try:
        data = json.loads(state_get(conn, "selectors") or "{}")
    except (TypeError, ValueError):
        return {}
    out: dict[str, dict[str, int]] = {}
    for dom, m in (data.items() if isinstance(data, dict) else []):
        if isinstance(m, dict):
            out[str(dom)] = {str(k): int(v) for k, v in m.items() if isinstance(v, int)}
    return out


def _merge_memory(ev: dict[str, Any], mem: dict[str, int] | None, now: int) -> None:
    for k, ts in (mem or {}).items():
        if now - int(ts) <= SELECTOR_FORGET_DAYS * 86400:
            ev["selectors"].setdefault(k, 0)
            ev["selector_seen"][k] = max(int(ev["selector_seen"].get(k, 0)), int(ts))


def _new_memory(old: dict[str, dict[str, int]], evidence: dict[str, dict[str, Any]], now: int
                ) -> dict[str, dict[str, int]]:
    limit = SELECTOR_FORGET_DAYS * 86400
    out = {d: {k: ts for k, ts in m.items() if now - ts <= limit} for d, m in old.items()}
    for dom, ev in evidence.items():
        out[dom] = {k: int(ts) for k, ts in (ev.get("selector_seen") or {}).items() if ts and now - int(ts) <= limit}
    return {d: m for d, m in out.items() if m}


def save_selector_memory(conn: sqlite3.Connection, memory: dict[str, dict[str, int]]) -> None:
    state_set(conn, "selectors", json.dumps(memory, separators=(",", ":")) if memory else None)


# ---------------------------------------------------------------- regressions + alerts
def signals(results: dict[str, Any]) -> tuple[list[tuple[str, int, bool, dict[str, Any]]], set[str]]:
    """-> ([(signal key, level, urgent, item)], keys of items that could not
    be tested). Urgent (alerted at once, without waiting for a second
    run): a real listing (not PBL) of a provider's SENDING address and a
    certificate with < 7 days left."""
    out: list[tuple[str, int, bool, dict[str, Any]]] = []
    untested: set[str] = set()
    for it in all_items(results):
        st = it.get("status")
        if st not in LEVEL:
            untested.add(it["key"])
            continue
        out.append((it["key"], LEVEL[st], False, it))
        if it["key"].startswith("bl:"):
            for zone, z in (it.get("zones") or {}).items():
                if z.get("state") == "listed":
                    out.append((f"{it['key']}|{zone}", 2, bool(it.get("sender")), it))
        days = it.get("days")
        if it["key"].startswith("srv:") and isinstance(days, int) and days < CERT_BAD_DAYS:
            out.append((f"{it['key']}|cert7", 2, True, it))
    return out, untested


@dataclass
class AlertPlan:
    alerts: list[dict[str, Any]]
    known: dict[str, int]            # last confirmed level per signal (the baseline)
    alerted: dict[str, int]          # level already told about (until it is fixed)
    last: dict[str, int]             # level seen in the previous tested run
    recent: dict[str, list[int]]     # [level, unix] of alerts of the last FLAP_S


def plan_alerts(results: dict[str, Any], known: dict[str, int], alerted: dict[str, int], *,
                last: dict[str, int] | None = None, recent: dict[str, list[int]] | None = None, now: int = 0,
                acked: Iterable[str] = ()) -> AlertPlan:
    """Which findings to alert about. A regression is a level above the
    last confirmed level that was ALSO seen in the previous tested run (a
    one-night blip never alerts); urgent signals alert at once. A problem
    alerted within FLAP_S is not alerted again when it comes back
    (ok -> bad -> ok -> bad). Untested and acknowledged findings keep
    their state untouched. The first sight of a check is its baseline."""
    sigs, untested = signals(results)
    acked = set(acked)
    untested |= acked
    sigs = [s for s in sigs if s[3]["key"] not in acked]
    last = last or {}
    recent = recent or {}
    new_known: dict[str, int] = {}
    new_alerted: dict[str, int] = {}
    new_last: dict[str, int] = {}
    new_recent = {k: v for k, v in recent.items() if isinstance(v, list) and len(v) == 2 and now - v[1] < FLAP_S}
    alerts: dict[str, dict[str, Any]] = {}

    def kept(k: str) -> bool:
        return k.split("|", 1)[0] in untested

    for src, dst in ((known, new_known), (alerted, new_alerted), (last, new_last)):
        for k, v in src.items():
            if kept(k):
                dst[k] = v
    for key, level, urgent, it in sigs:
        prev = known.get(key)
        new_last[key] = level
        if level == 0:
            new_known[key] = 0
            continue  # fixed: a new episode may alert again (FLAP_S aside)
        if alerted.get(key, 0) >= level:
            new_alerted[key] = alerted[key]
            new_known[key] = level
            continue
        if not urgent and (prev is None or level <= prev):
            new_known[key] = level      # baseline, or not worse than before
            if key in alerted:
                new_alerted[key] = alerted[key]
            continue
        if not urgent and last.get(key, -1) < level:
            new_known[key] = prev if prev is not None else level   # seen once: wait for the next run
            if key in alerted:
                new_alerted[key] = alerted[key]
            continue
        new_known[key] = level
        new_alerted[key] = level
        rec = new_recent.get(key)
        if rec and rec[0] >= level:
            continue  # flapping: told about this within the week
        alerts[it["key"]] = it
        new_recent[key] = [level, int(now)]
    for key, level, _u, it in sigs:   # one message per finding: its other signals are told too
        if it["key"] in alerts and level > 0:
            new_alerted[key] = max(level, new_alerted.get(key, 0))
            new_known[key] = level
            new_recent[key] = [max(level, (new_recent.get(key) or [0])[0]), int(now)]
    return AlertPlan(list(alerts.values()), new_known, new_alerted, new_last, new_recent)


def _load_map(conn: sqlite3.Connection, key: str) -> dict[str, Any]:
    try:
        data = json.loads(state_get(conn, key) or "{}")
    except (TypeError, ValueError):
        return {}
    return {str(k): v for k, v in data.items() if isinstance(v, (int, list))} if isinstance(data, dict) else {}


def _alerted_map(conn: sqlite3.Connection) -> dict[str, int]:
    try:
        return {r[0]: int(r[1]) for r in conn.execute("SELECT key, level FROM mailcheck_alerted")}
    except sqlite3.Error:
        return {}


def alert_text(items: Sequence[dict[str, Any]]) -> tuple[str, str]:
    first = items[0]
    where = first.get("domain") or first.get("area")
    subject = (f"Spamfilter: Mailsikkerhed – {LABEL.get(first['status'], '').lower()} for {where}: {first['area']}"
               if len(items) == 1 else f"Spamfilter: Mailsikkerhed – {len(items)} nye problemer")
    lines = ["Tjekket af jeres domæner og mailservere har fundet noget nyt, der bør ses på:", ""]
    for it in items[:15]:
        head = f"{it.get('domain')} – {it['area']}" if it.get("domain") else it["area"]
        lines.append(f"- {LABEL.get(it['status'], it['status'])}: {head}")
        lines.append(f"  {it['text']}")
        if it.get("fix"):
            lines.append(f"  Sådan retter du: {it['fix']}")
    if len(items) > 15:
        lines.append(f"- ... og {len(items) - 15} mere")
    lines += ["", "Er det kendt og i orden, så tryk “Kendt – ignorér” ved punktet – så kommer der ikke flere beskeder "
              "om det, før det ændrer sig.", "Se det hele under Sikkerhed -> Mailsikkerhed i spamfilteret."]
    return subject[:200], "\n".join(lines)


def _delivered(engine: Any, ret: Any) -> bool:
    """alert_once's answer -> was the owner told? False from alert_once
    means "not mailed": with no mailer configured at all the push it sent
    is all there is (= told); otherwise the mail failed (= retry)."""
    if ret is None or ret is True:
        return True
    try:
        return hasattr(engine, "_mailer") and engine._mailer() is None
    except Exception:  # noqa: BLE001
        return False


def process_alerts(engine: Any, conn: sqlite3.Connection, results: dict[str, Any],
                   now: float | None = None, acks: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Regressions of this run -> one alert (engine.alert_once: mail + push).
    Without an engine nothing is alerted AND nothing is remembered, so the
    next run with an engine still sees the regression; a degraded run
    changes nothing either. A finding counts as told only once the send
    succeeded (else it is retried on the next runs, at most
    ALERT_MAX_RETRIES times)."""
    if engine is None or not hasattr(engine, "alert_once") or results.get("degraded"):
        return []
    ensure_schema(conn)
    t = int(time.time() if now is None else now)
    known = {k: v for k, v in _load_map(conn, "levels").items() if isinstance(v, int)}
    last = {k: v for k, v in _load_map(conn, "last_levels").items() if isinstance(v, int)}
    recent = {k: v for k, v in _load_map(conn, "recent_alerts").items() if isinstance(v, list)}
    alerted = _alerted_map(conn)
    acks = load_acks(conn) if acks is None else acks
    plan = plan_alerts(results, known, alerted, last=last, recent=recent, now=t, acked=acked_keys(results, acks))
    sent = True
    if plan.alerts:
        subject, text = alert_text(plan.alerts)
        episode = hashlib.sha256("\n".join(sorted(f"{i['key']}={i['status']}" for i in plan.alerts)).encode()
                                 ).hexdigest()[:24]
        try:
            ret = engine.alert_once(conn, ALERT_KEY, f"{t}:{episode}", subject, text)
        except Exception as ex:  # noqa: BLE001 - an alert never breaks a run
            log.warning("mailcheck alert failed: %s", type(ex).__name__)
            ret = False
        sent = _delivered(engine, ret)
        tries = int(state_get(conn, "alert_retries") or 0) + (0 if sent else 1)
        if not sent and tries >= ALERT_MAX_RETRIES:
            log.warning("mailcheck alert could not be sent %d times - given up", tries)
            sent, tries = True, 0
        state_set(conn, "alert_retries", str(tries) if not sent else None, now=t)
        if not sent:   # not told: forget the regression's new state so the next run alerts again
            keys = {i["key"] for i in plan.alerts}
            for key, _lvl, _u, it in signals(results)[0]:
                if it["key"] not in keys:
                    continue
                for old, new in ((known, plan.known), (alerted, plan.alerted), (recent, plan.recent)):
                    if key in old:
                        new[key] = old[key]
                    else:
                        new.pop(key, None)
    state_set(conn, "levels", json.dumps(plan.known, separators=(",", ":")), now=t)
    state_set(conn, "last_levels", json.dumps(plan.last, separators=(",", ":")), now=t)
    state_set(conn, "recent_alerts", json.dumps(plan.recent, separators=(",", ":")), now=t)
    conn.execute("DELETE FROM mailcheck_alerted")
    conn.executemany("INSERT INTO mailcheck_alerted(key, level, alerted_at) VALUES(?,?,?)",
                     [(k, v, t) for k, v in plan.alerted.items()])
    _commit(conn)
    return plan.alerts if sent else []


def _event(conn: sqlite3.Connection, event: str, detail: str) -> None:
    try:
        conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES('*',?,NULL,?,?)",
                     (int(time.time()), event, detail[:300]))
        _commit(conn)
    except sqlite3.Error:
        pass


def run_and_record(engine: Any, conn: sqlite3.Connection, accounts: Iterable[Any], *, reason: str = "manual",
                   smtp: dict[str, Any] | None = None, **kw: Any) -> dict[str, Any] | None:
    """One complete run: checks, stored run, alerts, an event; the state
    keys the scheduler and the page read. Returns the results (with id).
    Only a scheduled run moves the nightly schedule (schedule_attempt_at /
    schedule_complete_at): "Tjek nu" or sfctl in the daytime never makes
    the next night skip its run."""
    ensure_schema(conn)
    t = int(time.time() if kw.get("now") is None else kw["now"])
    state_set(conn, "attempt_at", str(t), now=t)
    if reason == "schedule":
        state_set(conn, "schedule_attempt_at", str(t), now=t)
    state_set(conn, "running_since", str(t), now=t)
    if reason == "request" or state_get(conn, "request"):
        state_set(conn, "request", None)
    _commit(conn)
    try:
        results = run_check(accounts=accounts, conn=conn, smtp=smtp, reason=reason, **kw)
        if results is None:
            return None
        memory = results.pop("_selector_memory", None)
        if memory is not None:
            save_selector_memory(conn, memory)
        results["id"] = store_run(conn, results)
        acks = prune_acks(conn, results) if not results.get("degraded") else load_acks(conn)
        alerted = process_alerts(engine, conn, results, now=kw.get("now"), acks=acks)
        state_set(conn, "complete_at", str(results["finished_at"]))
        if reason == "schedule" and not results.get("degraded"):
            state_set(conn, "schedule_complete_at", str(results["finished_at"]))
        c = results["counts"]
        _event(conn, "mailcheck_done", f"fejl={c.get(BAD, 0)} advarsler={c.get(WARN, 0)} ok={c.get(OK, 0)} "
                                       f"ikke_testet={c.get(UNKNOWN, 0)} alarmer={len(alerted)} ({reason})"
                                       + (" offline" if results.get("degraded") else ""))
        log.info("mailcheck: %d errors, %d warnings, %d alerts (%s)%s", c.get(BAD, 0), c.get(WARN, 0), len(alerted),
                 reason, " - degraded run" if results.get("degraded") else "")
        return results
    finally:
        try:
            state_set(conn, "running_since", None)
            _commit(conn)
        except sqlite3.Error:
            pass


# ---------------------------------------------------------------- scheduling
RUNNING_STALE_S = int(RUN_DEADLINE_S) + 300     # a running_since older than this is a crashed run


def request_run(conn: sqlite3.Connection, actor: str = "", now: float | None = None) -> dict[str, Any]:
    """'Tjek nu': the engine starts within a minute."""
    t = int(time.time() if now is None else now)
    ensure_schema(conn)
    pend = pending(conn, now=t)
    if pend["running"]:
        return {"ok": True, "code": "running", "text": "Et tjek kører allerede. Resultatet vises her, når det er færdigt."}
    if pend["requested"] and not pend["stale"]:
        return {"ok": True, "code": "pending", "text": "Tjekket er allerede bestilt og starter inden for et minut."}
    state_set(conn, "request", str(t), now=t)
    _commit(conn)
    _event(conn, "mailcheck_requested", f"af {actor}" if actor else "")
    return {"ok": True, "code": "ok", "text": "Tjekket starter inden for et minut og tager typisk 1–2 minutter. "
                                             "Genindlæs siden bagefter."}


def pending(conn: sqlite3.Connection, now: float | None = None) -> dict[str, Any]:
    """{requested, running, stale}. A running_since older than the run
    deadline (+ margin) is a crashed run, not a running one."""
    t = time.time() if now is None else now
    req = state_get(conn, "request")
    run = state_get(conn, "running_since")
    out = {"requested": None, "running": None, "stale": False}
    try:
        out["requested"] = int(float(req)) if req else None
        out["running"] = int(float(run)) if run else None
    except ValueError:
        pass
    if out["running"] and t - out["running"] > RUNNING_STALE_S:
        out["running"] = None
    if out["requested"] and t - out["requested"] > REQUEST_STALE_S and not out["running"]:
        out["stale"] = True
    return out


def due(conn: sqlite3.Connection, now: float, hour: int) -> str | None:
    """'request' | 'schedule' | None. `hour` is the local (Copenhagen) hour.
    Only scheduled runs count against the nightly schedule."""
    if state_get(conn, "request"):
        return "request"
    try:
        attempt = int(float(state_get(conn, "schedule_attempt_at") or 0))
        done = int(float(state_get(conn, "schedule_complete_at") or 0))
    except ValueError:
        attempt = done = 0
    if now - attempt < RETRY_S:
        return None
    if done and now - done < MIN_GAP_S:
        return None
    return "schedule" if hour in RUN_HOURS else None


def clear_stale(conn: sqlite3.Connection) -> None:
    """Engine start: a running_since left by a crashed/killed run must not
    block "Tjek nu"."""
    try:
        ensure_schema(conn)
        if state_get(conn, "running_since") is not None:
            state_set(conn, "running_since", None)
        _commit(conn)
    except sqlite3.Error:
        pass


def _smtp_settings(engine: Any) -> dict[str, Any] | None:
    try:
        m = engine._mailer() if hasattr(engine, "_mailer") else None
        return m.get_settings() if m is not None else None
    except Exception:  # noqa: BLE001
        return None


def _loop(engine: Any, configs: list[Any]) -> None:
    lg = logging.getLogger("mailcheck")
    try:
        conn = engine._open_conn()
        try:
            clear_stale(conn)
        finally:
            conn.close()
    except Exception as ex:  # noqa: BLE001
        lg.warning("mailcheck start-up cleanup failed: %s", type(ex).__name__)
    while not engine.SHUTDOWN.wait(POLL_S):
        try:
            conn = engine._open_conn()
            try:
                ensure_schema(conn)
                now = engine._now()
                why = due(conn, now, engine._local_dt(now).hour)
                if why:
                    lg.info("mailcheck starting (%s)", why)
                    run_and_record(engine, conn, configs, reason=why, smtp=_smtp_settings(engine),
                                   stop=engine.SHUTDOWN)
            finally:
                conn.close()
        except Exception as ex:  # noqa: BLE001 - the check never takes the engine down
            lg.warning("mailcheck failed: %s", type(ex).__name__)


def start(engine: Any, configs: Iterable[Any]) -> bool:
    """Start the nightly / on-demand thread (the engine's main())."""
    if (os.environ.get("MAILCHECK_DISABLED") or "").strip() == "1":
        return False
    threading.Thread(target=_loop, args=(engine, list(configs or ())), name="mailcheck", daemon=True).start()
    return True


# ---------------------------------------------------------------- text output (sfctl)
CLI_TAG = {OK: "[ OK ]", INFO: "[INFO]", WARN: "[ADV.]", BAD: "[FEJL]", UNKNOWN: "[ -- ]"}


def summary_lines(results: dict[str, Any], *, verbose: bool = True) -> list[str]:
    lines = []
    if results.get("degraded"):
        lines.append(f"[ -- ] Tjekket kunne ikke gennemføres ordentligt: {results['degraded']} "
                     "Alt står som ikke testet, og der er ikke sendt beskeder.")
    if results.get("dns_limited"):
        lines.append(f"[ -- ] {results['dns_limited']} DNS-opslag blev ikke lavet (grænse nået) – de berørte punkter "
                     "står som ikke testet.")
    for d in results.get("domains") or []:
        head = d["domain"] + (f" ({d['provider']})" if d.get("provider") else "")
        if d.get("no_mail"):
            head += " – sender ikke mail"
        lines.append(head)
        for it in d.get("checks") or []:
            if not verbose and it["status"] in (OK, INFO):
                continue
            lines.append(f"  {CLI_TAG[it['status']]} {it['area']}{' (kendt – ignoreret)' if it.get('acked') else ''}: "
                         f"{it['text']}")
            if it.get("fix") and it["status"] in (WARN, BAD):
                lines.append(f"         Ret: {it['fix']}")
    for title, key in (("Mailservere", "servers"), ("Blokeringslister", "blacklists")):
        rows = results.get(key) or []
        if not rows:
            continue
        lines.append(title)
        for it in rows:
            if not verbose and it["status"] in (OK, INFO):
                continue
            lines.append(f"  {CLI_TAG[it['status']]} {it['area']}{' (kendt – ignoreret)' if it.get('acked') else ''}: "
                         f"{it['text']}")
            if it.get("fix") and it["status"] in (WARN, BAD):
                lines.append(f"         Ret: {it['fix']}")
    return lines
