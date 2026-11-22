"""DMARC aggregate reports (2.6, C2) - spamfilter.

The owner publishes `_dmarc.<domain> TXT "v=DMARC1; p=...; rua=mailto:<rua>"`
with <rua> one of the filtered mailboxes (default: the admin address of the local site config, setting
`dmarc` -> rua). Google, Microsoft, Yahoo & co. then mail one aggregate
report (RFC 7489 appendix C XML; .xml, .xml.gz or .zip) per day and domain.

In the engine's inbox scan (`take`, called AFTER the normal scan, before
the engine acts - rspamd and ClamAV always see a report candidate):

  * only a mail the scan found clean (below the threshold, no threat
    class, no virus) is a candidate; then a cheap header check (subject
    "Report domain: ... Submitter: ...", or a dmarc sender);
  * the From domain must carry a valid DKIM signature aligned with it
    (rspamd R_DKIM_ALLOW) and be a known reporter (KNOWN_REPORTERS) or the
    report's own report_metadata email / org_name domain;
  * every attachment is decoded SAFELY: at most MAX_ATTACH bytes per
    attachment, gzip/zip decompressed to at most MAX_XML bytes (zip: max
    MAX_ZIP_ENTRIES entries, no encrypted entries, the declared AND the
    real size checked), XML parsed with expat with a DOCTYPE/ENTITY ban (no
    DTD, no entity expansion, no external resources), a depth and element
    limit and MAX_RECORDS rows;
  * only a report that parses AND belongs to us (the reported domain is one
    of ours, or the mail went to the rua address) is stored (dmarc_reports
    / dmarc_records) and, in move mode, moved to the folder
    "DMARC-rapporter" with the engine's journalled move (repair_moves
    finishes an interrupted COPY). A moved report is never learned and
    never counted as spam;
  * anything else - spam, an unsigned or forged sender, broken XML, a zip
    bomb - and any report that is NOT moved (shadow/flag mode, the hourly
    cap, no MOVE/UIDPLUS, an IMAP error) goes through the normal decision
    path, so this path can never hide spam.

Per account (setting `dmarc` -> accounts{name: on|off}); the default is
"on" only for the mailbox whose address is the rua address. A report the
user moves back to the inbox (dmarc_mail: same Message-ID AND the same
SHA-256 of the raw mail) is left there; a Message-ID alone proves nothing.

The admin page (ui_dmarc.py) uses `summaries()`: per domain the last 30
days, % passing DMARC, the top sending sources (IP + reverse DNS via the
stack's own Unbound, looked up lazily when the page is opened and cached) and a plain-language recommendation.
"""

from __future__ import annotations

import email
import email.policy
import gzip
import hashlib
import io
import ipaddress
import json
import logging
import random
import re
import socket
import sqlite3
import struct
import time
import zipfile
from dataclasses import dataclass, field
from email.utils import getaddresses, parseaddr
from typing import Any, Iterable

import siteconfig
from xml.etree import ElementTree as ET
from xml.parsers import expat

log = logging.getLogger("dmarc")

FOLDER = "DMARC-rapporter"
SETTINGS_KEY = "dmarc"
DEFAULT_RUA = siteconfig.get("admin_email") or ""   # local site config (admin address)
MAX_ATTACH = 10 * 1024 * 1024        # one encoded attachment
MAX_XML = 20 * 1024 * 1024           # decompressed XML
MAX_ZIP_ENTRIES = 10
MAX_PARTS = 8                        # candidate attachments per mail
MAX_DEPTH = 24
MAX_ELEMENTS = 400_000
MAX_RECORDS = 20_000
MAX_TEXT = 255
MAX_MOVES_PER_HOUR = 60
KEEP_DAYS = 400
WINDOW_DAYS = 30
READY_DAYS = 14
READY_PCT = 98.0
LOW_VOLUME_DAYS = 30                 # 2.12 (#6): "Klar (lav volumen)" after 30 days
PTR_PER_PASS = 10
PTR_TIMEOUT_S = 1.0
PTR_RECHECK_S = 14 * 86400

# Aggregate report senders accepted with a DKIM signature aligned with the
# From domain (subdomains included). Any other sender is accepted only when
# its From domain is also the report's own report_metadata email / org_name
# domain (small providers, self-hosted reporters).
KNOWN_REPORTERS = (
    "google.com",                       # noreply-dmarc-support@google.com
    "microsoft.com", "outlook.com",     # dmarcreport@microsoft.com, protection.outlook.com
    "yahoo.com", "yahooinc.com",        # dmarchelp@yahooinc.com
    "mail.ru",
    "comcast.net",
    "zoho.com",
    "fastmail.com", "messagingengine.com",
    "gmx.net", "gmx.de", "web.de",      # 1&1 / United Internet
    "one.com",
    "gigahost.dk",
    "amazonses.com",
)
# Reporters that never DKIM-sign their reports (2.8.3). Accepted only when
# rspamd's DMARC check passed for the From organisation (DMARC_POLICY_ALLOW,
# which then rests on SPF aligned with the From domain) and SPF passed.
SPF_REPORTERS = (
    "iphmx.com",                        # Cisco Secure Email (MAILER-DAEMON@esaN.hcNNN-NN.eu.iphmx.com)
)
SUBJECT_RE = re.compile(r"report\s+domain\s*:\s*\S+.*?submitter\s*:\s*\S+", re.I | re.S)
_DTD_RE = re.compile(rb"<!\s*(DOCTYPE|ENTITY|ELEMENT|ATTLIST|NOTATION)", re.I)
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
_RESULT_RE = re.compile(r"^[a-z_]{1,20}$")
REPORT_TYPES = frozenset({"application/zip", "application/x-zip-compressed", "application/x-zip",
                          "application/gzip", "application/x-gzip", "application/x-gunzip",
                          "text/xml", "application/xml", "application/octet-stream"})
REPORT_EXTS = (".xml", ".xml.gz", ".gz", ".zip")


class DmarcError(ValueError):
    """Not a usable report (unsafe, too big, malformed). Short English text
    for the event log - never content of the mail."""


# ---------------------------------------------------------------- schema
SCHEMA = """
CREATE TABLE IF NOT EXISTS dmarc_reports (
    id          INTEGER PRIMARY KEY,
    account     TEXT NOT NULL,
    message_id  TEXT,
    org_name    TEXT NOT NULL,
    report_id   TEXT NOT NULL,
    domain      TEXT NOT NULL,
    date_begin  INTEGER NOT NULL,
    date_end    INTEGER NOT NULL,
    policy_p    TEXT,
    policy_sp   TEXT,
    policy_pct  INTEGER,
    adkim       TEXT,
    aspf        TEXT,
    records     INTEGER NOT NULL DEFAULT 0,
    messages    INTEGER NOT NULL DEFAULT 0,
    received_at INTEGER NOT NULL,
    UNIQUE(org_name, report_id, domain)
);
CREATE TABLE IF NOT EXISTS dmarc_records (
    report        INTEGER NOT NULL,
    domain        TEXT NOT NULL,
    source_ip     TEXT NOT NULL,
    count         INTEGER NOT NULL,
    disposition   TEXT,
    dkim          TEXT,
    spf           TEXT,
    dmarc_pass    INTEGER NOT NULL,
    header_from   TEXT,
    envelope_from TEXT,
    dkim_domain   TEXT,
    dkim_result   TEXT,
    spf_domain    TEXT,
    spf_result    TEXT,
    dkim_selector TEXT,
    date_begin    INTEGER NOT NULL,
    date_end      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS dmarc_records_domain ON dmarc_records(domain, date_end);
CREATE INDEX IF NOT EXISTS dmarc_records_report ON dmarc_records(report);
CREATE TABLE IF NOT EXISTS dmarc_mail (
    account    TEXT NOT NULL,
    message_id TEXT NOT NULL,
    seen_at    INTEGER NOT NULL,
    reports    INTEGER NOT NULL DEFAULT 0,
    moved      INTEGER NOT NULL DEFAULT 0,
    raw_sha256 TEXT,
    PRIMARY KEY(account, message_id)
);
CREATE TABLE IF NOT EXISTS dmarc_ptr (
    ip         TEXT PRIMARY KEY,
    name       TEXT,
    checked_at INTEGER NOT NULL
);
"""


def ensure_schema(conn: sqlite3.Connection) -> None:
    for stmt in (s.strip() for s in SCHEMA.split(";")):
        if stmt:
            conn.execute(stmt)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(dmarc_mail)")}
    if "raw_sha256" not in cols:  # 2.6 review: a Message-ID alone proves nothing
        conn.execute("ALTER TABLE dmarc_mail ADD COLUMN raw_sha256 TEXT")
    if "dkim_selector" not in {r[1] for r in conn.execute("PRAGMA table_info(dmarc_records)")}:
        conn.execute("ALTER TABLE dmarc_records ADD COLUMN dkim_selector TEXT")  # 2.7 (Mailsikkerhed)


# ---------------------------------------------------------------- settings
def _clean_addr(value: Any) -> str:
    a = parseaddr(str(value or ""))[1].strip().lower()
    return a if re.fullmatch(r"[^@\s]{1,64}@[a-z0-9.-]{1,253}", a) and "." in a.rpartition("@")[2] else ""


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


def load_settings(conn: sqlite3.Connection | None) -> dict[str, Any]:
    """{rua, accounts{name: on|off}, domains[]} from settings_kv (missing
    table/key = the defaults)."""
    raw: Any = None
    if conn is not None:
        try:
            row = conn.execute("SELECT value FROM settings_kv WHERE key=?", (SETTINGS_KEY,)).fetchone()
            raw = json.loads(row[0]) if row and row[0] else None
        except (sqlite3.Error, ValueError, TypeError):
            raw = None
    return normalize_settings(raw if isinstance(raw, dict) else {})


def normalize_settings(raw: dict[str, Any]) -> dict[str, Any]:
    rua = _clean_addr(raw.get("rua")) if raw.get("rua") is not None else DEFAULT_RUA
    accounts = {}
    for k, v in (raw.get("accounts") or {}).items() if isinstance(raw.get("accounts"), dict) else ():
        if str(v) in ("on", "off"):
            accounts[str(k)[:64]] = str(v)
    domains = []
    for d in raw.get("domains") or [] if isinstance(raw.get("domains"), list) else []:
        cd = clean_domain(d)
        if cd and cd not in domains:
            domains.append(cd)
    return {"rua": rua, "accounts": accounts, "domains": domains[:50]}


def account_mode(settings: dict[str, Any], acc: Any) -> str:
    """'on' | 'off' for this mailbox; default on only for the rua mailbox."""
    explicit = (settings.get("accounts") or {}).get(getattr(acc, "name", ""))
    if explicit in ("on", "off"):
        return explicit
    return "on" if settings.get("rua") and str(getattr(acc, "user", "")).lower() == settings["rua"] else "off"


def own_domains(acc: Any, settings: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for d in [str(getattr(acc, "user", "")).rpartition("@")[2], str(settings.get("rua") or "").rpartition("@")[2],
              *(getattr(acc, "protected_domains", None) or []), *(getattr(acc, "webshop_domains", None) or []),
              *(settings.get("domains") or [])]:
        cd = clean_domain(d)
        if cd:
            out.add(cd)
    return out


def _is_own(domain: str, own: set[str]) -> bool:
    return any(domain == d or domain.endswith("." + d) for d in own)


# ---------------------------------------------------------------- detection + decoding
def _header_text(msg: Any, name: str) -> str:
    try:
        return str(msg.get(name, "") or "")
    except Exception:  # noqa: BLE001 - a broken header is just no match
        return ""


def quick_check(raw: bytes) -> bool:
    """Header-only pre-check (cheap; most mail stops here)."""
    head = raw.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0][:65536]
    try:
        msg = email.message_from_bytes(head + b"\r\n\r\n", policy=email.policy.default)
    except Exception:  # noqa: BLE001
        return False
    subject = _header_text(msg, "Subject")
    sender = parseaddr(_header_text(msg, "From"))[1].lower()
    ctype = _header_text(msg, "Content-Type").lower()
    if SUBJECT_RE.search(subject):
        return True
    return "dmarc" in sender and ("multipart" in ctype or "zip" in ctype or "xml" in ctype)


def _limited_gunzip(data: bytes) -> bytes:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:
            out = g.read(MAX_XML + 1)
    except (OSError, EOFError, ValueError) as ex:
        raise DmarcError(f"bad gzip ({type(ex).__name__})") from None
    if len(out) > MAX_XML:
        raise DmarcError("gzip expands beyond the limit")
    return out


def _limited_unzip(data: bytes) -> bytes:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError, ValueError) as ex:
        raise DmarcError(f"bad zip ({type(ex).__name__})") from None
    with zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if not infos or len(zf.infolist()) > MAX_ZIP_ENTRIES:
            raise DmarcError("zip: no file or too many entries")
        xmls = [i for i in infos if i.filename.lower().endswith(".xml")] or infos[:1]
        zi = xmls[0]
        if zi.flag_bits & 0x1:
            raise DmarcError("zip: encrypted entry")
        if zi.file_size > MAX_XML:
            raise DmarcError("zip entry too big")
        try:
            with zf.open(zi) as fh:
                out = fh.read(MAX_XML + 1)
        except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, NotImplementedError, EOFError) as ex:
            raise DmarcError(f"bad zip entry ({type(ex).__name__})") from None
    if len(out) > MAX_XML:
        raise DmarcError("zip expands beyond the limit")
    return out


def decode_attachment(data: bytes) -> bytes:
    """gzip / zip / plain XML (by content, not by name) -> XML bytes."""
    if len(data) > MAX_ATTACH:
        raise DmarcError("attachment too big")
    if data[:2] == b"\x1f\x8b":
        data = _limited_gunzip(data)
    elif data[:4] == b"PK\x03\x04":
        data = _limited_unzip(data)
    if len(data) > MAX_XML:
        raise DmarcError("xml too big")
    if not data.lstrip(b"\xef\xbb\xbf \t\r\n")[:1] == b"<":
        raise DmarcError("not xml")
    return data


def _local(tag: str) -> str:
    return tag.rpartition(":")[2].rpartition("}")[2]


def safe_parse(data: bytes) -> ET.Element:
    """XML -> Element with expat: no DTD at all (so no entity expansion and
    no external entities), depth/element limits."""
    if len(data) > MAX_XML:
        raise DmarcError("xml too big")
    if _DTD_RE.search(data):
        raise DmarcError("xml with DOCTYPE/ENTITY refused")
    parser = expat.ParserCreate()
    tb = ET.TreeBuilder()
    state = {"depth": 0, "n": 0}

    def start(tag: str, _attrs: Any) -> None:
        state["depth"] += 1
        state["n"] += 1
        if state["depth"] > MAX_DEPTH or state["n"] > MAX_ELEMENTS:
            raise DmarcError("xml too deep or too large")
        tb.start(_local(tag), {})

    def end(tag: str) -> None:
        state["depth"] -= 1
        tb.end(_local(tag))

    def refuse(*_a: Any) -> None:
        raise DmarcError("xml with DOCTYPE/ENTITY refused")

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = tb.data
    parser.StartDoctypeDeclHandler = refuse
    parser.EntityDeclHandler = refuse
    parser.UnparsedEntityDeclHandler = refuse
    parser.NotationDeclHandler = refuse
    parser.ExternalEntityRefHandler = refuse
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        parser.Parse(data, True)
        return tb.close()
    except expat.ExpatError:
        raise DmarcError("malformed xml") from None
    except (AssertionError, IndexError):
        raise DmarcError("malformed xml") from None


@dataclass
class Record:
    source_ip: str
    count: int
    disposition: str | None
    dkim: str | None
    spf: str | None
    header_from: str | None
    envelope_from: str | None
    dkim_domain: str | None
    dkim_result: str | None
    spf_domain: str | None
    spf_result: str | None
    dkim_selector: str | None = None   # 2.7: Mailsikkerhed learns selectors from it

    @property
    def dmarc_pass(self) -> bool:
        return self.dkim == "pass" or self.spf == "pass"


@dataclass
class Report:
    org_name: str
    report_id: str
    domain: str
    date_begin: int
    date_end: int
    policy_p: str | None = None
    policy_sp: str | None = None
    policy_pct: int | None = None
    adkim: str | None = None
    aspf: str | None = None
    org_email: str | None = None
    records: list[Record] = field(default_factory=list)

    @property
    def org_email_domain(self) -> str | None:
        return clean_domain((self.org_email or "").rpartition("@")[2]) if self.org_email else None

    @property
    def messages(self) -> int:
        return sum(r.count for r in self.records)


def _text(el: ET.Element | None, *path: str) -> str | None:
    for p in path:
        if el is None:
            return None
        el = el.find(p)
    if el is None or el.text is None:
        return None
    t = re.sub(r"[\x00-\x1f\x7f]", "", el.text).strip()
    return t[:MAX_TEXT] or None


def _result(v: str | None) -> str | None:
    v = (v or "").strip().lower()
    return v if _RESULT_RE.match(v) else None


def _int(v: str | None, lo: int, hi: int) -> int | None:
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        return None
    return n if lo <= n <= hi else None


def _ip(v: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address(str(v or "").strip()))
    except ValueError:
        return None


def _selector(v: str | None) -> str | None:
    v = (v or "").strip()
    return v if re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}", v) else None


def parse_feedback(root: ET.Element) -> Report:
    """RFC 7489 appendix C -> Report (validated, bounded)."""
    if root.tag != "feedback":
        raise DmarcError("not a dmarc feedback document")
    meta = root.find("report_metadata")
    org = _text(meta, "org_name") or _text(meta, "email")
    rid = _text(meta, "report_id")
    begin = _int(_text(meta, "date_range", "begin"), 1, 2**33)
    end = _int(_text(meta, "date_range", "end"), 1, 2**33)
    pp = root.find("policy_published")
    domain = clean_domain(_text(pp, "domain"))
    if not (org and rid and domain and begin and end) or end < begin or end - begin > 32 * 86400:
        raise DmarcError("report metadata missing or invalid")
    rep = Report(org_name=org, report_id=rid, domain=domain, date_begin=begin, date_end=end,
                 policy_p=_result(_text(pp, "p")), policy_sp=_result(_text(pp, "sp")),
                 policy_pct=_int(_text(pp, "pct"), 0, 100), adkim=_result(_text(pp, "adkim")),
                 aspf=_result(_text(pp, "aspf")), org_email=_clean_addr(_text(meta, "email")) or None)
    recs = root.findall("record")
    if len(recs) > MAX_RECORDS:
        raise DmarcError("too many records")
    for rec in recs:
        row = rec.find("row")
        ip = _ip(_text(row, "source_ip"))
        count = _int(_text(row, "count"), 0, 10**9)
        if ip is None or count is None:
            continue
        pe = row.find("policy_evaluated") if row is not None else None
        auth = rec.find("auth_results")
        dk = auth.findall("dkim") if auth is not None else []
        # The signature that passed (if any) tells the most about the source.
        dk_best = next((d for d in dk if _result(_text(d, "result")) == "pass"), dk[0] if dk else None)
        sp = auth.find("spf") if auth is not None else None
        rep.records.append(Record(
            source_ip=ip, count=count, disposition=_result(_text(pe, "disposition")),
            dkim=_result(_text(pe, "dkim")), spf=_result(_text(pe, "spf")),
            header_from=clean_domain(_text(rec, "identifiers", "header_from")),
            envelope_from=clean_domain(_text(rec, "identifiers", "envelope_from")),
            dkim_domain=clean_domain(_text(dk_best, "domain")), dkim_result=_result(_text(dk_best, "result")),
            spf_domain=clean_domain(_text(sp, "domain")), spf_result=_result(_text(sp, "result")),
            dkim_selector=_selector(_text(dk_best, "selector"))))
    return rep


def parse_report_bytes(data: bytes) -> Report:
    return parse_feedback(safe_parse(decode_attachment(data)))


def _candidates(msg: Any) -> Iterable[bytes]:
    n = 0
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = (part.get_content_type() or "").lower()
        fname = str(part.get_filename() or "").lower()
        if not (ctype in REPORT_TYPES or fname.endswith(REPORT_EXTS)):
            continue
        if ctype == "application/octet-stream" and not fname.endswith(REPORT_EXTS):
            continue
        n += 1
        if n > MAX_PARTS:
            return
        try:
            payload = part.get_payload(decode=True)
        except Exception:  # noqa: BLE001
            continue
        if isinstance(payload, bytes) and payload:
            yield payload


def extract_reports(raw: bytes) -> tuple[list[Report], list[str]]:
    """(reports, errors) from one mail. errors are short English texts."""
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
    except Exception as ex:  # noqa: BLE001
        return [], [f"unparsable mail ({type(ex).__name__})"]
    reports: list[Report] = []
    errors: list[str] = []
    for payload in _candidates(msg):
        try:
            reports.append(parse_report_bytes(payload))
        except DmarcError as ex:
            errors.append(str(ex))
        except Exception as ex:  # noqa: BLE001 - hostile input must never crash the scan
            errors.append(f"unexpected {type(ex).__name__}")
    return reports, errors


def addressed_to(raw: bytes, address: str) -> bool:
    if not address:
        return False
    head = raw.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0][:65536]
    try:
        msg = email.message_from_bytes(head + b"\r\n\r\n", policy=email.policy.default)
        vals = [_header_text(msg, h) for h in ("To", "Cc", "Delivered-To", "X-Original-To", "Envelope-To")]
    except Exception:  # noqa: BLE001
        return False
    return any(a.lower() == address for _n, a in getaddresses(vals))


# ---------------------------------------------------------------- storage
def store(conn: sqlite3.Connection, account: str, message_id: str | None, rep: Report,
          now: int | None = None) -> tuple[int, bool]:
    """(report row id, new). A report already stored (same org, report id
    and domain - e.g. sent to two mailboxes) is not counted twice."""
    t = int(time.time() if now is None else now)
    ensure_schema(conn)
    cur = conn.execute(
        "INSERT OR IGNORE INTO dmarc_reports(account, message_id, org_name, report_id, domain, date_begin, date_end,"
        " policy_p, policy_sp, policy_pct, adkim, aspf, records, messages, received_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (account, message_id, rep.org_name, rep.report_id, rep.domain, rep.date_begin, rep.date_end, rep.policy_p,
         rep.policy_sp, rep.policy_pct, rep.adkim, rep.aspf, len(rep.records), rep.messages, t))
    if not cur.rowcount:
        row = conn.execute("SELECT id FROM dmarc_reports WHERE org_name=? AND report_id=? AND domain=?",
                           (rep.org_name, rep.report_id, rep.domain)).fetchone()
        return int(row[0]), False
    rid = int(cur.lastrowid)
    conn.executemany(
        "INSERT INTO dmarc_records(report, domain, source_ip, count, disposition, dkim, spf, dmarc_pass,"
        " header_from, envelope_from, dkim_domain, dkim_result, spf_domain, spf_result, dkim_selector,"
        " date_begin, date_end) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [(rid, rep.domain, r.source_ip, r.count, r.disposition, r.dkim, r.spf, int(r.dmarc_pass), r.header_from,
          r.envelope_from, r.dkim_domain, r.dkim_result, r.spf_domain, r.spf_result, r.dkim_selector,
          rep.date_begin, rep.date_end)
         for r in rep.records])
    return rid, True


def prune(conn: sqlite3.Connection, now: int | None = None, keep_days: int = KEEP_DAYS) -> int:
    t = int(time.time() if now is None else now)
    cut = t - keep_days * 86400
    ensure_schema(conn)
    old = [r[0] for r in conn.execute("SELECT id FROM dmarc_reports WHERE date_end < ?", (cut,))]
    for i in range(0, len(old), 500):
        chunk = old[i:i + 500]
        q = ",".join("?" * len(chunk))
        conn.execute(f"DELETE FROM dmarc_records WHERE report IN ({q})", chunk)
        conn.execute(f"DELETE FROM dmarc_reports WHERE id IN ({q})", chunk)
    conn.execute("DELETE FROM dmarc_mail WHERE seen_at < ?", (cut,))
    return len(old)


# ---------------------------------------------------------------- reverse DNS (cached)
def _ptr_name(ip: str) -> str:
    return ipaddress.ip_address(ip).reverse_pointer


def ptr_lookup(ip: str, *, server: str | None = None, port: int | None = None,
               timeout: float = PTR_TIMEOUT_S) -> str | None:
    """One PTR query against the stack's own Unbound (LOOKALIKE_DNS_SERVER
    / _PORT). None = no name; raises OSError on timeout/unreachable."""
    import lookalike as lk  # noqa: PLC0415 - the DNS helpers live there

    srv = server or lk.default_server()
    prt = int(port if port is not None else lk.default_port())
    name = _ptr_name(ip)
    qid = random.SystemRandom().randrange(0, 65536)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".")) + b"\x00"
    packet = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 12, 1)
    addr = socket.getaddrinfo(srv, prt, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.connect((addr, prt))
        s.send(packet)
        data = s.recv(4096)
    if len(data) < 12:
        return None
    rid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    if rid != qid or not flags & 0x8000 or flags & 0x000F:
        return None
    try:
        off = 12
        for _ in range(qd):
            _q, off = lk._read_name(data, off)
            off += 4
        for _ in range(an):
            _r, off = lk._read_name(data, off)
            rtype, _c, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            if rtype == 12:
                host = lk._read_name(data, off)[0]
                return clean_domain(host)
            off += rdlen
    except (lk.DnsError, struct.error):
        return None
    return None


def resolve_pending(conn: sqlite3.Connection, ips: Iterable[str], *, limit: int = PTR_PER_PASS,
                    now: int | None = None, lookup: Any = None) -> int:
    """Look up at most `limit` uncached IPs; stops at the first timeout so a
    dead resolver never stalls the scan. Never inside a transaction (each
    result is one autocommit write). Returns lookups done."""
    t = int(time.time() if now is None else now)
    fn = lookup or ptr_lookup
    ensure_schema(conn)
    done = 0
    for ip in dict.fromkeys(ips):
        if done >= limit:
            break
        row = conn.execute("SELECT checked_at FROM dmarc_ptr WHERE ip=?", (ip,)).fetchone()
        if row is not None and t - int(row[0]) < PTR_RECHECK_S:
            continue
        try:
            name = fn(ip)
        except (OSError, ValueError, UnicodeError):
            break
        done += 1
        conn.execute("INSERT INTO dmarc_ptr(ip, name, checked_at) VALUES(?,?,?) "
                     "ON CONFLICT(ip) DO UPDATE SET name=excluded.name, checked_at=excluded.checked_at",
                     (ip, name, t))
    return done


# ---------------------------------------------------------------- engine hook
def _folder_name(fmap: dict[str, str], delim: str) -> str:
    """Next to the filter's junk folder: top level, or below INBOX on
    servers that keep everything there (INBOX.Spamfilter)."""
    junk = str(fmap.get("junk") or "")
    for prefix in ("INBOX" + delim, "Inbox" + delim):
        if delim and junk.startswith(prefix):
            return prefix + FOLDER
    return FOLDER


def _from_domain(raw: bytes) -> str | None:
    head = raw.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0][:65536]
    try:
        msg = email.message_from_bytes(head + b"\r\n\r\n", policy=email.policy.default)
        addrs = getaddresses([_header_text(msg, "From")])
    except Exception:  # noqa: BLE001
        return None
    if len(addrs) != 1:
        return None  # no From, or several: never a trusted reporter
    return clean_domain(addrs[0][1].rpartition("@")[2])


def _under(host: str | None, domain: str) -> bool:
    return bool(host) and (host == domain or host.endswith("." + domain))


def trusted_reporter(engine: Any, scored: Any, raw: bytes, reports: list[Report]) -> str | None:
    """None when the From domain may send us aggregate reports, else a short
    English reason. Needs a valid DKIM signature aligned with the From
    domain (rspamd R_DKIM_ALLOW, engine._dkim_aligned) AND either a known
    reporter (KNOWN_REPORTERS) or a report whose report_metadata email /
    org_name domain is the From domain itself. SPF_REPORTERS (never sign)
    pass with an SPF-based DMARC pass for their own domain instead."""
    dom = _from_domain(raw)
    if not dom:
        return "no single From domain"
    if not engine._dkim_aligned(dom, scored.auth, scored.names):
        return None if _spf_reporter(dom, scored) else f"From {dom} not DKIM-aligned"
    if any(_under(dom, k) for k in KNOWN_REPORTERS):
        return None
    for rep in reports:
        for cand in (rep.org_email_domain, clean_domain(rep.org_name)):
            if cand and (_under(dom, cand) or _under(cand, dom)):
                return None
    return f"unknown reporter {dom}"


def _spf_reporter(dom: str, scored: Any) -> bool:
    """An SPF_REPORTERS sender whose mail passed DMARC (aligned SPF) for that
    reporter's own domain."""
    names = getattr(scored, "names", frozenset()) or frozenset()
    if "DMARC_POLICY_ALLOW" not in names or "R_SPF_ALLOW" not in names:
        return False
    opts = (getattr(getattr(scored, "res", None), "options", None) or {}).get("DMARC_POLICY_ALLOW") or []
    org = clean_domain(opts[0]) if opts else None
    return any(_under(dom, k) and org is not None and _under(org, k) for k in SPF_REPORTERS)


def not_spam(scored: Any) -> bool:
    """The normal scan found nothing: below the threshold, no spam decision,
    no threat class (B16), no virus. A report candidate is only ever taken
    AFTER rspamd and ClamAV saw it."""
    names = getattr(scored, "names", frozenset()) or frozenset()
    return (not scored.decision.spam and not scored.threat and float(scored.final) < float(scored.thr)
            and not any(str(n).startswith(("CLAM_VIRUS", "CLAM_PHISH")) and not str(n).endswith("_FAIL")
                        for n in names))


def take(engine: Any, client: Any, db: Any, log_: logging.Logger, acc: Any, fmap: dict[str, str], uv: int,
         meta: Any, raw: bytes, *, readonly: bool, settings: dict[str, Any], scored: Any) -> bool:
    """Called by the engine AFTER the normal scan (`scored`), before it acts.
    True = the mail is a DMARC report of ours from a trusted reporter and
    was stored AND moved to the DMARC folder; the caller stops there.
    False = anything else (not a report, spam, untrusted, not ours, or not
    moved: shadow/flag mode, read-only, the hourly cap, no MOVE, an IMAP
    error, or a report the user moved back): the normal decision path goes
    on. A usable report from a trusted reporter is stored even when the
    mail is not moved."""
    if not quick_check(raw) or not not_spam(scored):
        return False
    msgid = meta.msgid
    conn = db.conn
    ensure_schema(conn)
    reports, errors = extract_reports(raw)
    own = own_domains(acc, settings)
    to_rua = addressed_to(raw, str(settings.get("rua") or ""))
    ours = [r for r in reports if to_rua or _is_own(r.domain, own)]
    why = ("; ".join(errors) or "domain is not ours") if not ours else trusted_reporter(engine, scored, raw, ours)
    if why is not None:
        if errors or reports:
            with db.tx():
                db.log_event("dmarc_not_taken", msgid, detail=why[:200])
        return False
    digest = hashlib.sha256(raw).hexdigest()
    seen = conn.execute("SELECT moved, raw_sha256 FROM dmarc_mail WHERE account=? AND message_id=?",
                        (db.account, msgid)).fetchone()
    if seen is not None and seen[1] == digest and int(seen[0] or 0):
        # The very same report mail (same bytes) is back in the inbox: the
        # user moved it there. It stays; the normal path decides the rest.
        with db.tx():
            db.log_event("dmarc_report_kept", msgid, detail="moved back by the user - left in the inbox")
        return False
    now = int(engine._now())
    new = 0
    with db.tx():
        for rep in ours:
            _rid, is_new = store(conn, db.account, msgid, rep, now=now)
            new += int(is_new)
        conn.execute("INSERT INTO dmarc_mail(account, message_id, seen_at, reports, moved, raw_sha256) "
                     "VALUES(?,?,?,?,0,?) ON CONFLICT(account, message_id) DO UPDATE SET seen_at=excluded.seen_at, "
                     "reports=excluded.reports, moved=0, raw_sha256=excluded.raw_sha256",
                     (db.account, msgid, now, len(ours), digest))
        db.log_event("dmarc_report", msgid,
                     detail=f"{ours[0].org_name[:60]} {','.join(sorted({r.domain for r in ours}))[:80]} "
                            f"rows={sum(len(r.records) for r in ours)} new={new} score={float(scored.final):.2f}")
        db.bump("dmarc_reports")
        if random.random() < 0.05:
            prune(conn, now)
    moved = False
    if acc.mode == "move" and not readonly:
        moved = _move(engine, client, db, log_, acc, fmap, uv, meta, msgid)
    log_.info("dmarc report %s stored (%d report(s), %s)", msgid[:60], len(ours),
              "moved" if moved else "left to the normal path")
    if moved:
        with db.tx():
            db.clear_scan_retry(uv, meta.uid)
            db.bump("scanned")
            db.log_event("scan", msgid, detail=f"score={float(scored.final):.2f} action=dmarc_report mode={acc.mode}")
    return moved


def folder_of(acc: Any, fmap: dict[str, str]) -> str:
    return _folder_name(fmap, getattr(acc, "delimiter", "/") or "/")


def _move(engine: Any, client: Any, db: Any, log_: logging.Logger, acc: Any, fmap: dict[str, str], uv: int,
          meta: Any, msgid: str) -> bool:
    """Move one report to the DMARC folder with the engine's journalled move
    (move_journal, repaired by repair_moves after an interruption)."""
    if db.rate_count("dmarc_move", 3600) >= MAX_MOVES_PER_HOUR:
        with db.tx():
            db.log_event("dmarc_move_skipped", msgid, detail="hourly limit")
        return False
    if engine._journal_has(db, msgid):
        return False  # an interrupted move of this Message-ID awaits repair
    dest = folder_of(acc, fmap)
    inbox = fmap["inbox"]
    caps = engine.client_capabilities(client)
    on_stage = engine._journal_writer(db, inbox, uv, dest, {meta.uid: msgid},
                                      {meta.uid: getattr(meta, "received_at", None)})

    def drop_journal() -> None:
        db.conn.execute("DELETE FROM move_journal WHERE account=? AND folder=? AND uidvalidity=? AND uid=?",
                        (db.account, inbox, uv, meta.uid))

    for attempt in (1, 2):
        try:
            engine.imap_move(client, [meta.uid], dest, capabilities=caps, on_stage=on_stage)
            break
        except engine._CONN_ERRORS:
            raise
        except engine.MoveUnsupported:
            with db.tx():
                drop_journal()
            return False
        except engine.IMAPClientError as ex:
            copied = bool(getattr(ex, "copied", False))
            if not copied:
                with db.tx():
                    drop_journal()
                if attempt == 1 and engine._create_folder(client, db, log_, dest):
                    continue  # folder created: once more
            # copied: a copy may sit in the folder - the journal row stays
            # and repair_moves finishes (or undoes) the move.
            with db.tx():
                db.log_event("dmarc_move_failed", msgid, detail=f"{type(ex).__name__}{' copied' if copied else ''}")
            return False
    with db.tx():
        drop_journal()
        db.record_rate("dmarc_move")
        db.conn.execute("UPDATE dmarc_mail SET moved=1 WHERE account=? AND message_id=?", (db.account, msgid))
        db.log_event("dmarc_report_moved", msgid, detail=dest)
        db.bump("dmarc_moved")
    return True


def repair_moves(engine: Any, client: Any, db: Any, log_: logging.Logger, acc: Any, fmap: dict[str, str],
                 state: Any) -> int:
    """Finish report moves interrupted between COPY, STORE \\Deleted and UID
    EXPUNGE with the engine's own repair (filter._repair_one) against the
    DMARC folder. Returns the number of rows resolved."""
    if acc.mode != "move":
        return 0
    inbox, dest = fmap["inbox"], folder_of(acc, fmap)
    jrows = [r for r in engine._journal_rows(db, inbox) if r["dest"] == dest]
    if not jrows:
        return 0
    inbox_uv = engine.select_with_uidvalidity_check(client, db, inbox, log_)
    fm = dict(fmap, junk=dest)
    resolved = 0
    for r in jrows:
        msgid = r["message_id"]
        try:
            outcome = engine._repair_one(client, db, log_, acc, fm, state, msgid=msgid, stage=r["stage"],
                                         idate=r["internaldate"], predeleted=bool(r["predeleted"]),
                                         inbox_uv=inbox_uv, journal_uv=int(r["uidvalidity"]),
                                         journal_uid=int(r["uid"]))
        except engine._CONN_ERRORS:
            raise
        except engine.IMAPClientError as ex:
            outcome = "error"
            log_.warning("dmarc move repair of %s failed: %s", msgid, engine._short_err(ex))
            try:
                engine.select_with_uidvalidity_check(client, db, inbox, log_)
            except engine.IMAPClientError:
                pass
        with db.tx():
            if outcome in ("completed", "moved"):
                db.conn.execute("UPDATE dmarc_mail SET moved=1 WHERE account=? AND message_id=?",
                                (db.account, msgid))
                db.log_event("dmarc_report_moved", msgid, detail=f"repair stage={r['stage']} {outcome}")
                if outcome == "completed":
                    db.record_rate("dmarc_move")
            elif outcome != "error":
                db.log_event("dmarc_repair_kept", msgid, detail=f"stage={r['stage']} {outcome}")
            if outcome == "error" and int(r["attempts"]) + 1 < engine.MOVE_REPAIR_MAX_ATTEMPTS:
                db.conn.execute("UPDATE move_journal SET attempts=attempts+1, updated_at=? WHERE account=? "
                                "AND folder=? AND uidvalidity=? AND uid=?",
                                (int(engine._now()), db.account, r["folder"], r["uidvalidity"], r["uid"]))
            else:
                db.conn.execute("DELETE FROM move_journal WHERE account=? AND folder=? AND uidvalidity=? "
                                "AND uid=?", (db.account, r["folder"], r["uidvalidity"], r["uid"]))
        if outcome in ("completed", "moved", "kept"):
            resolved += 1
    return resolved


def resolve_for_page(conn: sqlite3.Connection, *, now: int | None = None, days: int = WINDOW_DAYS,
                     limit: int = PTR_PER_PASS, lookup: Any = None) -> int:
    """Lazy reverse DNS for the admin page: the busiest source IPs of the
    window that have no fresh cached name, at most `limit` lookups per
    page view (stops at the first timeout). Never on the scan path."""
    t = int(time.time() if now is None else now)
    ensure_schema(conn)
    ips = [r[0] for r in conn.execute(
        "SELECT r.source_ip FROM dmarc_records r LEFT JOIN dmarc_ptr p ON p.ip = r.source_ip "
        "WHERE r.date_end >= ? AND (p.ip IS NULL OR p.checked_at < ?) "
        "GROUP BY r.source_ip ORDER BY SUM(r.count) DESC LIMIT ?",
        (t - days * 86400, t - PTR_RECHECK_S, int(limit)))]
    return resolve_pending(conn, ips, limit=limit, now=t, lookup=lookup) if ips else 0


# ---------------------------------------------------------------- summaries (UI)
def _source_status(total: int, passed: int) -> tuple[str, str]:
    if total and passed >= total:
        return "godkendt", "ok"
    return ("fejler", "bad") if passed == 0 else (f"fejler ({total - passed} af {total})", "warn")


def summaries(conn: sqlite3.Connection, *, now: int | None = None, days: int = WINDOW_DAYS,
              domains: Iterable[str] = (), top: int = 10) -> list[dict[str, Any]]:
    """Per domain (with data in the window, plus `domains`): totals, % pass,
    top sources, policy and the recommendation."""
    t = int(time.time() if now is None else now)
    since = t - days * 86400
    ready_since = t - READY_DAYS * 86400
    ensure_schema(conn)
    names = [r[0] for r in conn.execute(
        "SELECT DISTINCT domain FROM dmarc_records WHERE date_end >= ? ORDER BY domain", (since,))]
    for d in domains:
        if d not in names:
            names.append(d)
    out = []
    for dom in names:
        tot, ok = conn.execute(
            "SELECT COALESCE(SUM(count),0), COALESCE(SUM(CASE WHEN dmarc_pass THEN count ELSE 0 END),0) "
            "FROM dmarc_records WHERE domain=? AND date_end >= ?", (dom, since)).fetchone()
        tot14, ok14 = conn.execute(
            "SELECT COALESCE(SUM(count),0), COALESCE(SUM(CASE WHEN dmarc_pass THEN count ELSE 0 END),0) "
            "FROM dmarc_records WHERE domain=? AND date_end >= ?", (dom, ready_since)).fetchone()
        rep = conn.execute(
            "SELECT COUNT(*), MIN(date_begin), COUNT(DISTINCT org_name) FROM dmarc_reports WHERE domain=?",
            (dom,)).fetchone()
        n30 = conn.execute("SELECT COUNT(*) FROM dmarc_reports WHERE domain=? AND date_end >= ?",
                           (dom, since)).fetchone()[0]
        latest = conn.execute(
            "SELECT policy_p, policy_pct, date_end FROM dmarc_reports WHERE domain=? ORDER BY date_end DESC LIMIT 1",
            (dom,)).fetchone()
        days14 = conn.execute(
            "SELECT COUNT(DISTINCT date_end / 86400) FROM dmarc_reports WHERE domain=? AND date_end >= ?",
            (dom, ready_since)).fetchone()[0]
        srcs = []
        for ip, total, passed, dk, sp, hf in conn.execute(
                "SELECT source_ip, SUM(count), SUM(CASE WHEN dmarc_pass THEN count ELSE 0 END), "
                "MAX(dkim_domain), MAX(spf_domain), MAX(header_from) FROM dmarc_records "
                "WHERE domain=? AND date_end >= ? GROUP BY source_ip ORDER BY SUM(count) DESC LIMIT ?",
                (dom, since, int(top))):
            ptr = conn.execute("SELECT name FROM dmarc_ptr WHERE ip=?", (ip,)).fetchone()
            label, tone = _source_status(int(total or 0), int(passed or 0))
            srcs.append({"ip": ip, "ptr": ptr[0] if ptr else None, "total": int(total or 0),
                         "passed": int(passed or 0), "status": label, "tone": tone,
                         "dkim_domain": dk, "spf_domain": sp, "header_from": hf})
        # Possibly our own, misconfigured senders: failing DMARC in the last
        # 14 days although SPF or DKIM passed for SOME domain (a newsletter
        # service, a shop platform) - spoofers rarely pass either.
        unknown = [dict(ip=r[0], total=int(r[1] or 0)) for r in conn.execute(
            "SELECT source_ip, SUM(count) FROM dmarc_records WHERE domain=? AND date_end >= ? AND dmarc_pass=0 "
            "AND (dkim_result='pass' OR spf_result='pass') GROUP BY source_ip HAVING SUM(count) >= 3 "
            "ORDER BY SUM(count) DESC LIMIT 20", (dom, ready_since))]
        d = {"domain": dom, "total": int(tot), "passed": int(ok),
             "pct": round(100.0 * ok / tot, 1) if tot else None,
             "total14": int(tot14), "pct14": round(100.0 * ok14 / tot14, 1) if tot14 else None,
             "reports": int(rep[0] or 0), "reports30": int(n30 or 0), "orgs": int(rep[2] or 0),
             "first_ts": rep[1], "days14": int(days14 or 0),
             "policy": latest[0] if latest else None, "policy_pct": latest[1] if latest else None,
             "last_ts": latest[2] if latest else None, "sources": srcs, "unknown": unknown}
        d["advice"] = recommendation(d, now=t)
        out.append(d)
    return out


def recommendation(d: dict[str, Any], *, now: int | None = None) -> dict[str, str]:
    """{code, tone, text} in plain Danish."""
    t = int(time.time() if now is None else now)
    dom, policy = d["domain"], (d.get("policy") or "none")
    if not d.get("reports"):
        return {"code": "no_data", "tone": "neutral",
                "text": f"Ingen rapporter for {dom} endnu. De kommer typisk 1–2 døgn efter, at DMARC-posten med "
                        "rua=mailto: er udgivet."}
    if d.get("total") and not d.get("passed"):
        return {"code": "spoofed_only", "tone": "warn",
                "text": f"Ingen af de {d['total']} mails, der bruger {dom} som afsender, består DMARC. Sender I slet "
                        "ikke mail fra domænet, kan det gå direkte til p=reject."}
    have_days = (t - int(d.get("first_ts") or t)) // 86400
    if have_days < READY_DAYS:
        left = READY_DAYS - have_days
        return {"code": "collect", "tone": "neutral",
                "text": f"Saml data i {left} {'dag' if left == 1 else 'dage'} mere, før I strammer politikken "
                        f"(nu p={policy})."}
    if d.get("unknown"):
        ips = ", ".join(u["ip"] for u in d["unknown"][:3])
        return {"code": "check_sources", "tone": "warn",
                "text": f"Tjek kilderne, der fejler, men har SPF eller DKIM for et andet domæne ({ips}). Er de "
                        f"jeres egne (nyhedsbrev, webshop, fakturasystem), skal de have DKIM for {dom}, før I strammer."}
    pct = d.get("pct14")
    if pct is None or d.get("days14", 0) < 7:
        low = _low_volume_ready(d, have_days, policy)
        if low is not None:
            return low
        return {"code": "collect", "tone": "neutral",
                "text": f"For få rapporter de seneste 14 dage til at anbefale noget for {dom}."}
    if pct < READY_PCT:
        return {"code": "low_pass", "tone": "warn",
                "text": f"Kun {_pct_da(pct)} % består DMARC de seneste 14 dage (målet er {_pct_da(READY_PCT)} %). "
                        "Find og ret de kilder, der fejler, før I strammer."}
    if policy == "none":
        return {"code": "ready_quarantine", "tone": "ok",
                "text": f"Klar til p=quarantine: {_pct_da(pct)} % består de seneste 14 dage, og der er ingen "
                        "ukendte kilder."}
    if policy == "quarantine":
        if d.get("policy_pct") not in (None, 100):
            return {"code": "raise_pct", "tone": "ok",
                    "text": f"Karantæne virker ({_pct_da(pct)} % består). Hæv pct til 100, og gå derefter til p=reject."}
        return {"code": "ready_reject", "tone": "ok",
                "text": f"Klar til p=reject: {_pct_da(pct)} % består de seneste 14 dage under karantæne, og der er "
                        "ingen ukendte kilder."}
    return {"code": "done", "tone": "ok",
            "text": f"Fuld beskyttelse (p=reject), og {_pct_da(pct)} % består. Hold øje med nye kilder, der fejler."}


LOW_VOLUME_LABEL = "Klar (lav volumen)"


def low_volume_ok(d: dict[str, Any], have_days: int) -> bool:
    """2.12 (#6): a small domain never gets 7 report days in 14. After
    LOW_VOLUME_DAYS of data it counts as ready when every source reported
    in the last 30 days is known and passes DMARC: at least one mail, all
    of them DMARC pass (no failing source at all, spoofers included) and
    no source that fails while passing SPF/DKIM for another domain."""
    total, passed = int(d.get("total") or 0), int(d.get("passed") or 0)
    return (have_days >= LOW_VOLUME_DAYS and total > 0 and passed >= total and not d.get("unknown")
            and int(d.get("reports30") or 0) > 0)


def _low_volume_ready(d: dict[str, Any], have_days: int, policy: str) -> dict[str, str] | None:
    if policy not in ("none", "quarantine") or not low_volume_ok(d, have_days):
        return None
    dom, total = d["domain"], int(d.get("total") or 0)
    n_src = len(d.get("sources") or [])
    basis = (f"alle {total} {'mail' if total == 1 else 'mails'}"
             + (f" fra {n_src} {'kilde' if n_src == 1 else 'kilder'}" if n_src else "")
             + f" de seneste {WINDOW_DAYS} dage består DMARC, og der er ingen ukendte eller fejlende kilder. "
             "Der er for få rapporter til det normale 14-dages-kriterium, så vurderingen bygger på 30 dage")
    if policy == "none":
        return {"code": "ready_quarantine_low", "tone": "ok", "label": LOW_VOLUME_LABEL,
                "text": f"{LOW_VOLUME_LABEL}: {dom} kan gå til p=quarantine – {basis}."}
    if d.get("policy_pct") not in (None, 100):
        return {"code": "raise_pct_low", "tone": "ok", "label": LOW_VOLUME_LABEL,
                "text": f"{LOW_VOLUME_LABEL}: hæv pct til 100 for {dom} – {basis}."}
    return {"code": "ready_reject_low", "tone": "ok", "label": LOW_VOLUME_LABEL,
            "text": f"{LOW_VOLUME_LABEL}: {dom} kan gå til p=reject – {basis}."}


def _pct_da(v: float) -> str:
    return (f"{v:.1f}".rstrip("0").rstrip(".")).replace(".", ",")


def dns_hint(domain: str, rua: str) -> list[str]:
    """The DNS records the owner must publish (shown on the page). No
    report address set (fresh install): the domain's postmaster."""
    rua = rua or f"postmaster@{domain}"
    lines = [f'_dmarc.{domain}  TXT  "v=DMARC1; p=none; rua=mailto:{rua}"']
    rdom = rua.rpartition("@")[2]
    if rdom and rdom != domain and not domain.endswith("." + rdom):
        # RFC 7489 7.1: a report address in another domain must allow it.
        lines.append(f'{domain}._report._dmarc.{rdom}  TXT  "v=DMARC1"')
    return lines
