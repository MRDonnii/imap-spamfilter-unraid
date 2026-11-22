"""Lookalike domains and a weekly registration watch (spamfilter,
backlog B22 "Lignende domæner og ugentlig kontrol af nyregistreringer").

What this module does (pure Python; nothing here imports filter.py, the
engine and services inject the database connection and the resolver):

  * `permutations(domain)` - an EXPLICIT set of lookalike variants of one
    protected domain (never an edit distance: 'vexar' would match 'vexaro'):
      - omission, repetition, adjacent transposition and QWERTY / Danish
        neighbour keys (æøå) - only for labels of at least 5 characters;
      - homoglyphs (0/o, 1/l/i, rn/m, vv/w, cl/d, Cyrillic look-alikes as
        IDN), hyphen insertion / removal;
      - TLD swaps (.com .net .shop .eu .co .info .online .store .site),
        '<label>.dk.com' and '<label>-dk.com'.
  * `Matcher` - decides whether a host imitates a protected domain: the
    explicit variants above, plus a UTS #39 style skeleton (confusable
    characters folded, hyphens removed) for homoglyph / IDN tricks, plus
    subdomain embedding ('pinsikbing.example.evil.com'). A protected domain
    itself and its own subdomains never match.
  * `evaluate()` - the pseudo-symbols for one mail: TH_LOOKALIKE_DOMAIN
    (+6, From / Reply-To / envelope sender / DKIM d=; the engine turns it
    into threat class 'lookalike') and TH_LOOKALIKE_URL (+4, link hosts in
    the text and HTML parts; score only). Exempt: domains with ham history
    (>= 3 kept mails in sender_history), known contacts, the admin's
    "Ikke en efterligning" list (lookalike_allow) and mail verifiably
    signed (DKIM) by the imitated domain itself. Options carry
    [lookalike, protected domain, field].
  * `run_watch()` - the registration watch: NS, then MX and A, of every
    generated variant through the stack's resolver (spamfilter-unbound, 2.4 AIO: 127.0.0.1)
    with a hard rate limit (<= 5 lookups/s) and a cap per run. Results go
    to lookalike_watch. The first successful check of a domain is its
    baseline (never an alert); afterwards only an MX or A record set that
    APPEARS (none before, some now) is reported as new. DNS errors never
    overwrite known data (a SERVFAIL week must not cause an alert later).
  * A minimal stdlib DNS client (A, NS, MX over UDP, TCP on truncation):
    dnspython is not in the image and the Dockerfile installs nothing
    (the base image is pinned), so a new dependency would change the
    build; the client is ~150 lines and fully tested with canned packets.

Schema: additive only (two new tables, created idempotently by
`ensure_schema`). Older images ignore them, so a rollback keeps working.
SCORE_VERSION is not changed.
"""

from __future__ import annotations

import email
import email.policy
import html as _html
import json
import logging
import os
import random
import re
import socket
import sqlite3
import struct
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from email.utils import getaddresses
from typing import Any, Callable, Iterable, Sequence

import siteconfig

log = logging.getLogger("lookalike")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SYMBOL_DOMAIN = "TH_LOOKALIKE_DOMAIN"
SYMBOL_URL = "TH_LOOKALIKE_URL"
SYMBOL_ALLOWED = "TH_LOOKALIKE_ALLOWED"     # informational (0): a hit that was exempt
SYMBOLS = (SYMBOL_DOMAIN, SYMBOL_URL, SYMBOL_ALLOWED)
SCORE_DOMAIN = 6.0
SCORE_URL = 4.0

# Config default (accounts.yml defaults.protected_domains); every mailbox
# domain is always added on top.
DEFAULT_PROTECTED = siteconfig.get_list("protected_domains")  # local site config (config/site.yml)
PROTECTED_MAX = 50

TLD_SWAPS = ("com", "net", "shop", "eu", "co", "info", "online", "store", "site")
# TLDs whose registries accept non-Latin IDN labels (Cyrillic variants are
# only generated for the watch under these; .dk only takes Latin letters).
_IDN_TLDS = frozenset({"com", "net", "shop", "eu", "info", "online", "store", "site"})
MIN_EDIT_LABEL = 6          # shorter labels (bynet, vexar, molt): only homoglyph, hyphen and TLD variants
HAM_HISTORY_MIN_KEPT = 3

# Fields a hit came from (third option of the symbol).
FIELD_FROM, FIELD_REPLY_TO, FIELD_ENVELOPE, FIELD_DKIM, FIELD_URL = "from", "reply_to", "envelope", "dkim", "url"
FIELD_TEXT = {FIELD_FROM: "afsender", FIELD_REPLY_TO: "svar-til-adresse", FIELD_ENVELOPE: "konvolut-afsender",
              FIELD_DKIM: "DKIM-signatur", FIELD_URL: "link"}

KIND_OMISSION, KIND_REPETITION, KIND_TRANSPOSITION = "omission", "repetition", "transposition"
KIND_KEYBOARD, KIND_HOMOGLYPH, KIND_HYPHEN = "keyboard", "homoglyph", "hyphen"
KIND_TLD, KIND_EMBED = "tld", "embed"
KIND_TEXT = {
    KIND_OMISSION: "udeladt bogstav", KIND_REPETITION: "dobbelt bogstav",
    KIND_TRANSPOSITION: "byttede bogstaver", KIND_KEYBOARD: "nabotast",
    KIND_HOMOGLYPH: "forvekslelige tegn", KIND_HYPHEN: "bindestreg",
    KIND_TLD: "andet topdomæne", KIND_EMBED: "jeres domæne gemt i et andet",
}

# Two-level public suffixes (same idea as contacts.regdom) + CentralNic's
# dk.com, where anybody can register '<name>.dk.com'.
_MULTI_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "com.au", "net.au",
    "org.au", "co.nz", "org.nz", "com.br", "co.jp", "ne.jp", "com.cn", "com.tr", "co.za", "com.mx",
    "co.in", "com.sg", "com.hk", "co.kr", "com.tw", "com.ar", "com.pl", "co.il", "com.ua", "co.id",
    "com.ru", "com.es", "com.pt", "com.co", "com.de", "co.at", "or.at", "com.gr",
    "dk.com", "uk.com", "us.com", "eu.com", "de.com", "se.net", "dk.net",
})

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")

# ---------------------------------------------------------------------------
# Keyboard neighbours (Danish QWERTY: the æøå keys sit next to p/l)
# ---------------------------------------------------------------------------

_ROWS = ("1234567890", "qwertyuiopå", "asdfghjklæø", "zxcvbnm")


def _neighbours() -> dict[str, str]:
    out: dict[str, set[str]] = {}
    for r, row in enumerate(_ROWS):
        for i, ch in enumerate(row):
            s = out.setdefault(ch, set())
            for j in (i - 1, i + 1):
                if 0 <= j < len(row):
                    s.add(row[j])
            if r > 0:                       # the row above: keys i and i+1
                up = _ROWS[r - 1]
                for j in (i, i + 1):
                    if 0 <= j < len(up):
                        s.add(up[j])
            if r + 1 < len(_ROWS):          # the row below: keys i-1 and i
                down = _ROWS[r + 1]
                for j in (i - 1, i):
                    if 0 <= j < len(down):
                        s.add(down[j])
    return {k: "".join(sorted(v)) for k, v in out.items()}


KEYBOARD = _neighbours()

# ---------------------------------------------------------------------------
# Confusables (UTS #39 style skeleton, reduced to what matters for domains)
# ---------------------------------------------------------------------------

# Characters that look like a Latin letter (Cyrillic, Greek, Latin variants).
_CONFUSABLE_CHARS = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ӏ": "l", "һ": "h", "ԛ": "q", "ԝ": "w",
    "к": "k", "м": "m", "н": "h", "т": "t", "ь": "b", "п": "n", "г": "r", "з": "3", "ɡ": "g",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t",
    "υ": "u", "χ": "x", "ω": "w", "η": "n", "γ": "y",
    # Latin variants without a canonical decomposition
    "ı": "i", "ł": "l", "ø": "o", "đ": "d", "ħ": "h", "ŀ": "l", "ǀ": "l", "ɩ": "i", "ɑ": "a",
    "æ": "ae", "œ": "oe", "ß": "ss",
}
# After folding to Latin: digits and letters that look alike in most fonts.
_FOLD_CHARS = {"0": "o", "1": "l", "i": "l", "|": "l", "5": "s", "$": "s"}
# Multi-letter look-alikes (applied after the single characters).
_FOLD_SEQS = (("rn", "m"), ("vv", "w"), ("cl", "d"))

# Explicit ASCII homoglyph substitutions for the watch (one site at a time).
_ASCII_HOMOGLYPHS = (("o", "0"), ("l", "1"), ("i", "1"), ("i", "l"), ("l", "i"), ("m", "rn"),
                     ("w", "vv"), ("d", "cl"), ("rn", "m"), ("vv", "w"), ("cl", "d"))
# Cyrillic letters that are pixel-identical to Latin ones (IDN variants).
_CYRILLIC = {"a": "а", "c": "с", "e": "е", "i": "і", "o": "о", "p": "р", "x": "х", "y": "у", "j": "ј",
             "s": "ѕ"}


def skeleton(label: str) -> str:
    """The confusable skeleton of one label (unicode or punycode):
    lower-case, diacritics removed, look-alike characters folded, hyphens
    removed. 'pіnsіkbіng' (Cyrillic і), 'p1nsikbing' and 'pin-sikbing' all
    have the skeleton of 'pinsikbing'."""
    s = to_unicode(label).lower()
    s = "".join(_CONFUSABLE_CHARS.get(c, c) for c in s)
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    s = "".join(_CONFUSABLE_CHARS.get(c, c) for c in s)
    s = "".join(_FOLD_CHARS.get(c, c) for c in s)
    for a, b in _FOLD_SEQS:
        s = s.replace(a, b)
    return s.replace("-", "").replace("_", "")


# ---------------------------------------------------------------------------
# Domain helpers
# ---------------------------------------------------------------------------


def to_unicode(label: str) -> str:
    """Punycode labels ('xn--…') decoded; anything else unchanged."""
    out = []
    for part in str(label or "").split("."):
        if part.lower().startswith("xn--"):
            try:
                part = part.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        out.append(part)
    return ".".join(out)


def to_ascii(domain: Any) -> str | None:
    """Lower-case ASCII (IDNA/punycode) form of a host name, or None."""
    d = str(domain or "").strip().strip(".").lower()
    if not d or len(d) > 253 or any(c.isspace() for c in d):
        return None
    if not d.isascii():
        try:
            d = d.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            return None
    return d if _DOMAIN_RE.match(d) else None


def under(host: str | None, domain: str | None) -> bool:
    h = (host or "").strip().lower().rstrip(".")
    d = (domain or "").strip().lower().rstrip(".")
    return bool(h) and bool(d) and (h == d or h.endswith("." + d))


def registrable(domain: Any) -> str | None:
    """'mail.example.co.uk' -> 'example.co.uk', 'a.pinsikbing.example' -> 'pinsikbing.example'."""
    d = to_ascii(domain)
    if d is None:
        return None
    labels = d.split(".")
    if len(labels) <= 2:
        return d
    if ".".join(labels[-2:]) in _MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def split_domain(domain: str) -> tuple[str, str] | None:
    """(label, suffix) of a registrable domain: 'pinsikbing.example' ->
    ('pinsikbing', 'example'), 'x.co.uk' -> ('x', 'co.uk')."""
    reg = registrable(domain)
    if reg is None or "." not in reg:
        return None
    label, _sep, suffix = reg.partition(".")
    return label, suffix


def normalize_protected(items: Iterable[Any]) -> list[str]:
    """Registrable ASCII domains, de-duplicated, order kept."""
    out: list[str] = []
    for item in items or ():
        d = registrable(str(item or "").strip().lstrip("*").lstrip(".").lstrip("@"))
        if d and "." in d and d not in out:
            out.append(d)
    return out


def protected_domains(configured: Iterable[Any] | None, mailbox_addresses: Iterable[Any] = (),
                      mailbox_domains: Iterable[Any] = ()) -> list[str]:
    """The effective protected list: the configured list (None = the
    default) + the domain of every mailbox."""
    base = DEFAULT_PROTECTED if configured is None else list(configured)
    doms = [str(a or "").rpartition("@")[2] for a in mailbox_addresses or () if "@" in str(a or "")]
    return normalize_protected([*base, *doms, *(mailbox_domains or ())])


def defang(domain: Any) -> str:
    """'pinslkbing[.]example' - never auto-linked by a mail client."""
    return str(domain or "").replace(".", "[.]")


# ---------------------------------------------------------------------------
# Permutations (explicit set)
# ---------------------------------------------------------------------------


def _label_ok(label: str) -> bool:
    if label.isascii():
        # 'ab--c' (hyphens in positions 3-4) is reserved for IDNA ('xn--').
        return bool(_LABEL_RE.match(label)) and "--" not in label[2:4]
    try:
        a = label.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return False
    return bool(_LABEL_RE.match(a))


def edit_variants(label: str) -> dict[str, str]:
    """Omission, repetition, transposition and neighbour-key variants of
    one label ({variant: kind}); empty for labels shorter than 5."""
    out: dict[str, str] = {}
    if len(label) < MIN_EDIT_LABEL:
        return out

    def add(v: str, kind: str) -> None:
        if v != label and v not in out and _label_ok(v):
            out[v] = kind

    for i in range(len(label)):
        add(label[:i] + label[i + 1:], KIND_OMISSION)
    for i in range(len(label)):
        if label[i] != "-":
            add(label[:i + 1] + label[i] + label[i + 1:], KIND_REPETITION)
    for i in range(len(label) - 1):
        if label[i] != label[i + 1]:
            add(label[:i] + label[i + 1] + label[i] + label[i + 2:], KIND_TRANSPOSITION)
    for i, ch in enumerate(label):
        for n in KEYBOARD.get(ch, ""):
            add(label[:i] + n + label[i + 1:], KIND_KEYBOARD)
    return out


def hyphen_variants(label: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for i in range(1, len(label)):
        if label[i - 1] != "-" and label[i] != "-":
            v = label[:i] + "-" + label[i:]
            if _label_ok(v):
                out.setdefault(v, KIND_HYPHEN)
    if "-" in label:
        for i, ch in enumerate(label):
            if ch == "-":
                v = label[:i] + label[i + 1:]
                if _label_ok(v):
                    out.setdefault(v, KIND_HYPHEN)
    return out


def homoglyph_variants(label: str, *, idn: bool = False) -> dict[str, str]:
    """Single-site ASCII homoglyph substitutions (+ Cyrillic IDN ones)."""
    out: dict[str, str] = {}
    for a, b in _ASCII_HOMOGLYPHS:
        start = label.find(a)
        while start != -1:
            v = label[:start] + b + label[start + len(a):]
            if v != label and _label_ok(v):
                out.setdefault(v, KIND_HOMOGLYPH)
            start = label.find(a, start + 1)
    if idn:
        for i, ch in enumerate(label):
            cy = _CYRILLIC.get(ch)
            if cy:
                v = label[:i] + cy + label[i + 1:]
                if _label_ok(v):
                    out.setdefault(v, KIND_HOMOGLYPH)
    return out


def permutations(domain: str, *, exclude: Iterable[str] = ()) -> list[tuple[str, str]]:
    """[(variant domain in ASCII/punycode, kind)] for one protected domain:
    the explicit set the watch looks up. Never the domain itself, never a
    subdomain of it and never one of `exclude` (the other protected
    domains)."""
    parts = split_domain(domain)
    if parts is None:
        return []
    label, suffix = parts
    own = f"{label}.{suffix}"
    excl = [e for e in (to_ascii(x) for x in exclude) if e]
    found: dict[str, str] = {}

    def add(lab: str, suf: str, kind: str) -> None:
        d = to_ascii(f"{lab}.{suf}")
        if not d or d == own or under(d, own) or any(under(d, e) for e in excl):
            return
        found.setdefault(d, kind)

    for v, kind in edit_variants(label).items():
        add(v, suffix, kind)
    for v, kind in homoglyph_variants(label, idn=suffix in _IDN_TLDS).items():
        add(v, suffix, kind)
    for v, kind in hyphen_variants(label).items():
        add(v, suffix, kind)
    for tld in TLD_SWAPS:
        if tld != suffix:
            add(label, tld, KIND_TLD)
    flat = suffix.replace(".", "-")
    add(f"{label}-{flat}", "com", KIND_TLD)
    if suffix == "dk":
        add(label, "dk.com", KIND_TLD)
    return sorted(found.items())


# ---------------------------------------------------------------------------
# Matcher
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Hit:
    lookalike: str          # the imitation (ASCII), e.g. 'pinslkbing.example'
    protected: str          # the protected domain it imitates
    kind: str               # KIND_*
    host: str = ""          # the full host it was found in


@dataclass
class _Target:
    domain: str
    label: str
    suffix: str
    canon: str
    canon_joined: str
    edits: dict[str, str]
    canon_edits: frozenset
    labels: tuple


class Matcher:
    """Lookalike test against a fixed list of protected domains."""

    def __init__(self, protected: Iterable[str]) -> None:
        self.protected = normalize_protected(protected)
        self._targets: list[_Target] = []
        for d in self.protected:
            parts = split_domain(d)
            if parts is None:
                continue
            label, suffix = parts
            ulabel = to_unicode(label)
            edits = edit_variants(ulabel)
            self._targets.append(_Target(
                domain=d, label=ulabel, suffix=suffix, canon=skeleton(ulabel),
                canon_joined=skeleton(ulabel + suffix.replace(".", "")), edits=edits,
                canon_edits=frozenset(skeleton(v) for v in edits), labels=tuple(d.split("."))))

    def is_protected(self, host: str | None) -> bool:
        return any(under(host, d) for d in self.protected)

    def match(self, host: Any) -> Hit | None:
        """The protected domain `host` imitates, or None."""
        h = to_ascii(host)
        if h is None or not self._targets:
            return None
        if self.is_protected(h):
            return None  # the real domain and its own subdomains never match
        labels = h.split(".")
        for t in self._targets:
            hit = self._match_suffix(h, labels, t)
            if hit is not None:
                return hit
        for t in self._targets:
            hit = self._match_embed(h, labels, t)
            if hit is not None:
                return hit
        return None

    def _match_suffix(self, h: str, labels: list[str], t: _Target) -> Hit | None:
        suffixes = [t.suffix, *[s for s in TLD_SWAPS if s != t.suffix]]
        if t.suffix == "dk":
            suffixes.append("dk.com")
        for suf in suffixes:
            n = suf.count(".") + 1
            if len(labels) <= n or ".".join(labels[-n:]) != suf:
                continue
            x = labels[-n - 1]
            xu = to_unicode(x).lower()
            key = f"{x}.{suf}"
            if suf == t.suffix:
                if xu == t.label:
                    continue
                kind = t.edits.get(xu)
                if kind is None:
                    cx = skeleton(xu)
                    if cx == t.canon:
                        kind = KIND_HYPHEN if xu.replace("-", "") == t.label.replace("-", "") else KIND_HOMOGLYPH
                    elif cx in t.canon_edits:
                        kind = KIND_HOMOGLYPH
                if kind is not None:
                    return Hit(key, t.domain, kind, h)
            else:
                cx = skeleton(xu)
                if xu == t.label or cx == t.canon:
                    return Hit(key, t.domain, KIND_TLD, h)
                if suf == "com" and cx == t.canon_joined:
                    return Hit(key, t.domain, KIND_TLD, h)   # pinsikbing-example.com, pinsikbingexample.com
        return None

    def _match_embed(self, h: str, labels: list[str], t: _Target) -> Hit | None:
        n = len(t.labels)
        # 'pinsikbing.example.evil.com': the whole protected domain followed by
        # at least one more label that is not the protected domain's own.
        for i in range(0, len(labels) - n):
            if tuple(labels[i:i + n]) == t.labels:
                rest = ".".join(labels[i + n:])
                if rest and not self.is_protected(rest):
                    return Hit(h[:120], t.domain, KIND_EMBED, h)
        # 'pinsikbing-example.evil.com' (label form, not the registrable label).
        for lab in labels[:-2]:
            if skeleton(lab) == t.canon_joined:
                return Hit(h[:120], t.domain, KIND_EMBED, h)
        return None


_MATCHER_CACHE: dict[tuple, Matcher] = {}
_MATCHER_LOCK = threading.Lock()


def matcher_for(protected: Sequence[str]) -> Matcher:
    key = tuple(sorted(normalize_protected(protected)))
    with _MATCHER_LOCK:
        m = _MATCHER_CACHE.get(key)
        if m is None:
            if len(_MATCHER_CACHE) > 16:
                _MATCHER_CACHE.clear()
            m = _MATCHER_CACHE[key] = Matcher(key)
        return m


# ---------------------------------------------------------------------------
# Mail parsing: sender fields and link hosts
# ---------------------------------------------------------------------------

_DKIM_D_RE = re.compile(r"(?:^|;)\s*d\s*=\s*([A-Za-z0-9._-]{1,253})", re.I)
_URL_RE = re.compile(r"(?i)(?:\b(?:https?|ftp)://|\b(?=www\d{0,3}\.))([^\s/?#\"'<>()\[\]{}\\,;|^`]+)")
# Every whitespace run is bounded and the two runs around the optional
# quote can never compete for the same characters: a long 'href=' + blank
# run without '//' must stay linear (2.3.6 review: the unbounded form
# backtracked quadratically - one crafted mail pinned a scan thread).
_HREF_RE = re.compile(r"(?i)\b(?:href|src|action)[ \t\r\n]{0,20}=[ \t\r\n]{0,20}(?:[\"'][ \t\r\n]{0,20})?"
                      r"(?:https?:)?//([^\s/?#\"'<>]+)")
MAX_TEXT_BYTES = 1024 * 1024
MAX_HOSTS = 200


def _domain_of(addr: Any) -> str | None:
    a = str(addr or "").strip().strip("<>").strip()
    if "@" not in a:
        return None
    return to_ascii(a.rpartition("@")[2])


def _clean_host(raw_host: str) -> str | None:
    hst = _html.unescape(str(raw_host or "")[:2048]).strip()
    hst = hst.rpartition("@")[2]                 # userinfo: 'pinsikbing.example@evil.com' -> evil.com
    if hst.startswith("["):
        return None                              # IPv6 literal
    hst = hst.split(":", 1)[0].strip().rstrip(".")
    hst = re.sub(r"[。．｡]", ".", hst)
    if not hst or "." not in hst or re.fullmatch(r"[0-9.]+", hst):
        return None
    return to_ascii(hst)


def mail_fields(raw: bytes) -> dict[str, list[str]]:
    """{'from': [...], 'reply_to': [...], 'dkim': [...]} domains from the
    headers (ASCII). Never raises."""
    out: dict[str, list[str]] = {FIELD_FROM: [], FIELD_REPLY_TO: [], FIELD_DKIM: []}
    try:
        msg = email.message_from_bytes(raw[:262144] if raw else b"", policy=email.policy.compat32)
        for fld, hdr in ((FIELD_FROM, "From"), (FIELD_REPLY_TO, "Reply-To")):
            vals = [str(v) for v in (msg.get_all(hdr) or [])][:5]
            for _name, addr in getaddresses(vals)[:10]:
                d = _domain_of(addr)
                if d and d not in out[fld]:
                    out[fld].append(d)
        for sig in (msg.get_all("DKIM-Signature") or [])[:5]:
            m = _DKIM_D_RE.search(re.sub(r"\s+", " ", str(sig)))
            if m:
                d = to_ascii(m.group(1))
                if d and d not in out[FIELD_DKIM]:
                    out[FIELD_DKIM].append(d)
    except Exception as ex:  # noqa: BLE001 - a parsing problem never blocks a scan
        log.debug("header parsing failed: %s", type(ex).__name__)
    return out


def url_hosts(raw: bytes, limit: int = MAX_HOSTS) -> list[str]:
    """Host names of the links in the text/plain and text/html parts
    (quoted-printable / base64 decoded, HTML entities resolved, userinfo
    and ports removed). At most `limit`; never raises."""
    hosts: list[str] = []
    try:
        msg = email.message_from_bytes(raw or b"", policy=email.policy.compat32)
        budget = MAX_TEXT_BYTES
        for part in msg.walk():
            if part.is_multipart() or part.get_content_maintype() != "text":
                continue
            if str(part.get("Content-Disposition", "")).lower().startswith("attachment"):
                continue
            payload = part.get_payload(decode=True) or b""
            payload = payload[:budget]
            budget -= len(payload)
            charset = part.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except LookupError:
                text = payload.decode("utf-8", errors="replace")
            if part.get_content_subtype() == "html":
                text = _html.unescape(text)
            for rx in (_HREF_RE, _URL_RE):
                for m in rx.finditer(text):
                    hst = _clean_host(m.group(1))
                    if hst and hst not in hosts:
                        hosts.append(hst)
                        if len(hosts) >= limit:
                            return hosts
            if budget <= 0:
                break
    except Exception as ex:  # noqa: BLE001
        log.debug("url parsing failed: %s", type(ex).__name__)
    return hosts


# ---------------------------------------------------------------------------
# Exemptions + evaluation
# ---------------------------------------------------------------------------

SCHEMA = """
-- B22: lookalikes of the protected domains and their DNS state (weekly
-- watch). ns/mx/a: JSON lists, NULL = not known yet (or the last lookup
-- failed). registered: 1 = the name exists, 0 = NXDOMAIN.
CREATE TABLE IF NOT EXISTS lookalike_watch (
    domain       TEXT PRIMARY KEY,
    protected    TEXT NOT NULL,
    kind         TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    checked_at   INTEGER,
    ns           TEXT,
    mx           TEXT,
    a            TEXT,
    registered   INTEGER,
    first_registered_at INTEGER,
    new_at       INTEGER,
    new_what     TEXT,
    alerted_at   INTEGER,
    acked_at     INTEGER,
    errors       INTEGER NOT NULL DEFAULT 0,
    last_error   TEXT
);
CREATE INDEX IF NOT EXISTS idx_lookalike_watch_protected ON lookalike_watch(protected);
CREATE INDEX IF NOT EXISTS idx_lookalike_watch_checked ON lookalike_watch(checked_at);

-- B22: "Ikke en efterligning" (admin): never a lookalike hit for the
-- domain or its subdomains, never an alert from the watch.
CREATE TABLE IF NOT EXISTS lookalike_allow (
    domain     TEXT PRIMARY KEY,
    protected  TEXT,
    note       TEXT,
    created_by TEXT,
    created_at INTEGER NOT NULL
);
"""


def _statements(script: str) -> list[str]:
    out = []
    for part in script.split(";"):
        body = "\n".join(line for line in part.splitlines() if not line.strip().startswith("--")).strip()
        if body:
            out.append(body)
    return out


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the tables (idempotent, additive; never COMMITs a caller's
    open transaction)."""
    for stmt in _statements(SCHEMA):
        conn.execute(stmt)


def allowed_domain(conn: sqlite3.Connection, domain: str) -> str | None:
    """The 'Ikke en efterligning' entry covering `domain`, or None."""
    d = to_ascii(domain)
    if not d:
        return None
    parts = d.split(".")
    cands = [".".join(parts[i:]) for i in range(len(parts) - 1)]
    try:
        q = ",".join("?" * len(cands))
        row = conn.execute(f"SELECT domain FROM lookalike_allow WHERE domain IN ({q}) LIMIT 1", cands).fetchone()
    except sqlite3.Error:
        return None
    return str(row[0]) if row else None


def ham_history(conn: sqlite3.Connection, domain: str, *, exact: bool = False) -> int:
    """Mails kept (not spam) from senders of this registrable domain, all
    mailboxes (contacts.sender_history; 0 when the table is missing).
    exact=True: only `domain` itself (sender_history stores registrable
    domains, so a tenant host on a shared platform never matches)."""
    reg = domain if exact else (registrable(domain) or domain)
    try:
        row = conn.execute("SELECT COALESCE(SUM(n_kept), 0) FROM sender_history WHERE regdom IN (?, ?)",
                           (reg, domain)).fetchone()
    except sqlite3.Error:
        return 0
    return int(row[0] or 0) if row else 0


def known_contact(conn: sqlite3.Connection, domain: str, *, exact: bool = False) -> bool:
    """Someone at this domain is an active known contact (any mailbox).
    exact=True: `domain` and its own subdomains only, never the whole
    registrable domain."""
    reg = domain if exact else (registrable(domain) or domain)
    try:
        row = conn.execute("SELECT 1 FROM known_contacts WHERE status='active' AND (domain=? OR domain LIKE ?) "
                           "LIMIT 1", (reg, "%." + reg)).fetchone()
    except sqlite3.Error:
        return False
    return row is not None


def shared_platform(hit: Hit) -> bool:
    """True when the lookalike is a name ON someone else's registrable
    domain ('pinsikbingexample.onmicrosoft.com', 'pinsikbing-example.sharepoint.com',
    'pinsikbing.example.evil.com') rather than a registrable domain of its own.
    Anybody can create such a tenant/subdomain, so history or contacts at
    the platform say nothing about it."""
    return hit.kind == KIND_EMBED or (registrable(hit.lookalike) or hit.lookalike) != hit.lookalike


def exemption(conn: sqlite3.Connection | None, hit: Hit, *, dkim_verified: Iterable[str] = (),
              origin_host: str | None = None, field_name: str | None = None,
              from_domains: Iterable[str] = ()) -> str | None:
    """Why a hit does not count ('allowed'|'ham_history'|'contact'|
    'signed'|'provider'), or None."""
    for d in dkim_verified or ():
        if under(d, hit.protected):
            return "signed"            # the imitated domain itself signed the mail
    if origin_host and under(origin_host, hit.protected):
        return "signed"
    # Own mail sent through a provider WITHOUT a custom DKIM key: Google
    # Workspace signs d=pinsikbing-example.<date>.gappssmtp.com, Microsoft 365
    # d=<tenant>.onmicrosoft.com. A provider signature of the label form
    # ('embed') on mail whose From is the imitated domain itself is the
    # owner's own mail, not an imitation (2.3.6 review). Verified or not:
    # a forger gains nothing from adding such a signature (it is never
    # aligned with the From) and could simply leave it out, while a
    # forward that breaks the signature must not turn own mail into a
    # threat. Typo/TLD signatures (d=pinslkbing.example) still count.
    if (field_name == FIELD_DKIM and hit.kind == KIND_EMBED
            and any(under(f, hit.protected) for f in from_domains or ())):
        return "provider"
    if conn is None:
        return None
    if allowed_domain(conn, hit.lookalike) or (hit.host and allowed_domain(conn, hit.host)):
        return "allowed"
    # A tenant on a shared platform: only history/contacts of that exact
    # name count, never the platform's registrable domain (2.3.6 review).
    exact = shared_platform(hit)
    name = (hit.host or hit.lookalike) if exact else hit.lookalike
    if ham_history(conn, name, exact=exact) >= HAM_HISTORY_MIN_KEPT:
        return "ham_history"
    if known_contact(conn, name, exact=exact):
        return "contact"
    return None


EXEMPT_TEXT = {"allowed": "Ikke en efterligning", "ham_history": "kendt afsender",
               "contact": "kendt kontakt", "signed": "underskrevet af jeres eget domæne",
               "provider": "jeres egen mail via mailudbyderen"}


@dataclass
class Evaluation:
    symbols: list[dict] = field(default_factory=list)
    hits: list[tuple[Hit, str]] = field(default_factory=list)       # (hit, field) that count
    exempt: list[tuple[Hit, str, str]] = field(default_factory=list)  # (hit, field, reason)


def evaluate(conn: sqlite3.Connection | None, matcher: Matcher, *, raw: bytes, sender: str | None = None,
             envelope_from: str | None = None, dkim_verified: Iterable[str] = (),
             origin_host: str | None = None, urls: Iterable[str] | None = None) -> Evaluation:
    """The lookalike pseudo-symbols for one mail (see module doc)."""
    ev = Evaluation()
    if not matcher.protected:
        return ev
    fields = mail_fields(raw)
    sources: list[tuple[str, str]] = []
    if sender:
        d = _domain_of(sender)
        if d:
            sources.append((FIELD_FROM, d))
    sources += [(FIELD_FROM, d) for d in fields[FIELD_FROM]]
    sources += [(FIELD_REPLY_TO, d) for d in fields[FIELD_REPLY_TO]]
    env = _domain_of(envelope_from)
    if env:
        sources.append((FIELD_ENVELOPE, env))
    verified = [d for d in (to_ascii(x) for x in dkim_verified or ()) if d]
    from_doms = [d for f, d in sources if f == FIELD_FROM]
    sources += [(FIELD_DKIM, d) for d in [*verified, *fields[FIELD_DKIM]]]
    seen: set[str] = set()
    sender_hits: list[tuple[Hit, str]] = []
    for fld, dom in sources:
        if dom in seen:
            continue
        seen.add(dom)
        hit = matcher.match(dom)
        if hit is None:
            continue
        why = exemption(conn, hit, dkim_verified=verified, origin_host=origin_host, field_name=fld,
                        from_domains=from_doms)
        if why:
            ev.exempt.append((hit, fld, why))
        else:
            sender_hits.append((hit, fld))
    url_hits: list[tuple[Hit, str]] = []
    for hst in (url_hosts(raw) if urls is None else urls):
        hst = to_ascii(hst) or ""
        if not hst or hst in seen:
            continue
        seen.add(hst)
        hit = matcher.match(hst)
        if hit is None:
            continue
        why = exemption(conn, hit, dkim_verified=verified, origin_host=origin_host)
        if why:
            ev.exempt.append((hit, FIELD_URL, why))
        else:
            url_hits.append((hit, FIELD_URL))
        if len(url_hits) >= 5:
            break
    if sender_hits:
        hit, fld = sender_hits[0]
        ev.symbols.append({"n": SYMBOL_DOMAIN, "s": SCORE_DOMAIN, "o": [hit.lookalike[:120], hit.protected, fld]})
    if url_hits:
        hit, fld = url_hits[0]
        ev.symbols.append({"n": SYMBOL_URL, "s": SCORE_URL, "o": [hit.lookalike[:120], hit.protected, fld]})
    if ev.exempt and not sender_hits:
        hit, fld, why = ev.exempt[0]
        ev.symbols.append({"n": SYMBOL_ALLOWED, "s": 0.0, "o": [hit.lookalike[:120], hit.protected, why]})
    ev.hits = sender_hits + url_hits
    return ev


def threat_detail(symbols: Iterable[dict]) -> str | None:
    """'pinslkbing.example ligner pinsikbing.example' from a TH_LOOKALIKE_DOMAIN symbol."""
    for s in symbols or ():
        if isinstance(s, dict) and s.get("n") == SYMBOL_DOMAIN:
            o = [str(x) for x in (s.get("o") or [])]
            if len(o) >= 2:
                return f"{o[0]} ligner {o[1]}"[:160]
            if o:
                return o[0][:160]
    return None


# ---------------------------------------------------------------------------
# Minimal DNS client (stdlib)
# ---------------------------------------------------------------------------

QTYPE_A, QTYPE_NS, QTYPE_MX = 1, 2, 15
QTYPES = {"A": QTYPE_A, "NS": QTYPE_NS, "MX": QTYPE_MX}
RCODE_NOERROR, RCODE_NXDOMAIN = 0, 3
DEFAULT_SERVER = "spamfilter-unbound"
# 2.4: the all-in-one container runs Unbound on 127.0.0.1; the 4-container
# layout keeps the container name. LOOKALIKE_DNS_SERVER (empty = unset)
# overrides the default for every resolver built without an explicit server.
DNS_SERVER_ENV = "LOOKALIKE_DNS_SERVER"
# 2.4: the AIO's Unbound listens on 127.0.0.1:5353 (LOOKALIKE_DNS_PORT).
DNS_PORT_ENV = "LOOKALIKE_DNS_PORT"


def default_server() -> str:
    """The resolver the registration watch asks: $LOOKALIKE_DNS_SERVER, or
    the 4-container default 'spamfilter-unbound'. Read at call time."""
    return (os.environ.get(DNS_SERVER_ENV) or "").strip() or DEFAULT_SERVER


def default_port() -> int:
    """$LOOKALIKE_DNS_PORT (1-65535), else 53. Read at call time."""
    raw = (os.environ.get(DNS_PORT_ENV) or "").strip()
    try:
        port = int(raw)
    except ValueError:
        return 53
    return port if 0 < port < 65536 else 53


class DnsError(Exception):
    """A lookup without a usable answer (timeout, SERVFAIL, REFUSED,
    malformed). The caller keeps what it knew before."""


@dataclass
class DnsAnswer:
    rcode: int
    records: list[str]

    @property
    def nxdomain(self) -> bool:
        return self.rcode == RCODE_NXDOMAIN


def encode_name(name: str) -> bytes:
    d = to_ascii(name)
    if d is None:
        raise DnsError("invalid name")
    out = b""
    for label in d.split("."):
        if not 0 < len(label) <= 63:
            raise DnsError("invalid name")
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def build_query(name: str, qtype: int, qid: int) -> bytes:
    return struct.pack(">HHHHHH", qid & 0xFFFF, 0x0100, 1, 0, 0, 0) + encode_name(name) + struct.pack(">HH", qtype, 1)


def _read_name(data: bytes, off: int) -> tuple[str, int]:
    labels: list[str] = []
    jumps = 0
    end: int | None = None
    while True:
        if off >= len(data):
            raise DnsError("malformed")
        ln = data[off]
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                raise DnsError("malformed")
            ptr = ((ln & 0x3F) << 8) | data[off + 1]
            if end is None:
                end = off + 2
            jumps += 1
            if jumps > 32 or ptr >= len(data):
                raise DnsError("malformed")
            off = ptr
            continue
        if ln & 0xC0:
            raise DnsError("malformed")
        off += 1
        if ln == 0:
            break
        if off + ln > len(data):
            raise DnsError("malformed")
        labels.append(data[off:off + ln].decode("ascii", errors="replace").lower())
        off += ln
        if len(labels) > 127:
            raise DnsError("malformed")
    return ".".join(labels), (end if end is not None else off)


def parse_response(data: bytes, qid: int, name: str, qtype: int) -> tuple[DnsAnswer, bool]:
    """(answer, truncated). Raises DnsError for a reply that does not
    belong to the query or cannot be parsed."""
    if len(data) < 12:
        raise DnsError("malformed")
    rid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    if rid != (qid & 0xFFFF) or not flags & 0x8000:
        raise DnsError("mismatch")
    truncated = bool(flags & 0x0200)
    rcode = flags & 0x000F
    off = 12
    want = (to_ascii(name) or "").lower()
    for _ in range(qd):
        qname, off = _read_name(data, off)
        if off + 4 > len(data):
            raise DnsError("malformed")
        qt, _qc = struct.unpack(">HH", data[off:off + 4])
        off += 4
        if qname != want or qt != qtype:
            raise DnsError("mismatch")
    records: list[str] = []
    for _ in range(an):
        _rname, off = _read_name(data, off)
        if off + 10 > len(data):
            raise DnsError("malformed")
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        if off + rdlen > len(data):
            raise DnsError("malformed")
        if rtype == qtype:
            if rtype == QTYPE_A and rdlen == 4:
                records.append(socket.inet_ntoa(data[off:off + 4]))
            elif rtype == QTYPE_NS:
                records.append(_read_name(data, off)[0])
            elif rtype == QTYPE_MX and rdlen >= 3:
                pref = struct.unpack(">H", data[off:off + 2])[0]
                records.append(f"{pref} {_read_name(data, off + 2)[0]}")
        off += rdlen
    if rcode not in (RCODE_NOERROR, RCODE_NXDOMAIN):
        raise DnsError({1: "formerr", 2: "servfail", 4: "notimp", 5: "refused"}.get(rcode, f"rcode{rcode}"))
    return DnsAnswer(rcode, sorted(set(records))), truncated


class DnsResolver:
    """A, NS and MX over UDP (TCP when truncated) against one resolver -
    the stack's own Unbound: spamfilter-unbound (container name, resolved
    through Docker's embedded DNS on spamnet) or, in the all-in-one
    container, 127.0.0.1 via $LOOKALIKE_DNS_SERVER (see default_server)."""

    def __init__(self, server: str | None = None, port: int | None = None, timeout: float = 3.0,
                 retries: int = 1) -> None:
        self.server = server or default_server()
        self.port = int(port) if port is not None else default_port()
        self.timeout, self.retries = float(timeout), int(retries)
        self._addr: str | None = None

    def address(self) -> str:
        if self._addr is None:
            try:
                info = socket.getaddrinfo(self.server, self.port, socket.AF_INET, socket.SOCK_DGRAM)
            except OSError as ex:
                raise DnsError("resolver unreachable") from ex
            if not info:
                raise DnsError("resolver unreachable")
            self._addr = str(info[0][4][0])
        return self._addr

    def query(self, name: str, qtype: str) -> DnsAnswer:
        qt = QTYPES[qtype]
        last: Exception | None = None
        for _attempt in range(self.retries + 1):
            qid = random.SystemRandom().randrange(0, 65536)
            packet = build_query(name, qt, qid)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(self.timeout)
                    s.connect((self.address(), self.port))
                    s.send(packet)
                    data = s.recv(4096)
                ans, truncated = parse_response(data, qid, name, qt)
                if truncated:
                    ans = self._tcp(packet, qid, name, qt)
                return ans
            except DnsError as ex:
                if str(ex) == "resolver unreachable":
                    raise
                last = ex
                if str(ex) not in ("mismatch", "servfail"):
                    break
            except OSError as ex:
                last = ex
        raise DnsError(str(last) if isinstance(last, DnsError) else "timeout")

    def _tcp(self, packet: bytes, qid: int, name: str, qt: int) -> DnsAnswer:
        with socket.create_connection((self.address(), self.port), timeout=self.timeout) as s:
            s.sendall(struct.pack(">H", len(packet)) + packet)
            head = _recv_exact(s, 2)
            data = _recv_exact(s, struct.unpack(">H", head)[0])
        return parse_response(data, qid, name, qt)[0]


def _recv_exact(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise DnsError("malformed")
        buf += chunk
    return buf


# ---------------------------------------------------------------------------
# Registration watch
# ---------------------------------------------------------------------------

WATCH_RATE = 5.0                 # lookups per second (hard limit)
WATCH_MAX_LOOKUPS = 1500         # per run; the rest waits for the next run
# A run whose lookups mostly fail is a failed run (retried), not a quiet
# "nothing new" week: abort after this many failed names in a row, and
# fail the run when at least half of the names it tried failed.
WATCH_MAX_CONSECUTIVE_ERRORS = 20
WATCH_ERROR_DNS = "dns errors"
WATCH_RECHECK_S = 6 * 86400      # a domain checked within this is skipped


class RateLimiter:
    """At most `rate` calls per second (spacing, not bursts)."""

    def __init__(self, rate: float = WATCH_RATE, *, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], Any] = time.sleep) -> None:
        self.interval = 1.0 / max(0.1, min(float(rate), WATCH_RATE))
        self.clock, self.sleep = clock, sleep
        self._next = 0.0

    def wait(self) -> None:
        now = self.clock()
        if now < self._next:
            self.sleep(self._next - now)
            now = self._next
        self._next = now + self.interval


def sync_candidates(conn: sqlite3.Connection, protected: Sequence[str], now: int) -> int:
    """Create a lookalike_watch row for every permutation of every protected
    domain; drop rows whose protected domain is gone. Returns the count."""
    prot = normalize_protected(protected)
    wanted: dict[str, tuple[str, str]] = {}
    for p in prot:
        for dom, kind in permutations(p, exclude=[x for x in prot if x != p]):
            wanted.setdefault(dom, (p, kind))
    have = {r[0] for r in conn.execute("SELECT domain FROM lookalike_watch")}
    for dom in have - set(wanted):
        conn.execute("DELETE FROM lookalike_watch WHERE domain=?", (dom,))
    for dom, (p, kind) in wanted.items():
        if dom not in have:
            conn.execute("INSERT OR IGNORE INTO lookalike_watch(domain, protected, kind, created_at) "
                         "VALUES(?,?,?,?)", (dom, p, kind, int(now)))
    return len(wanted)


def _jl(v: Any) -> list[str] | None:
    if v is None:
        return None
    try:
        out = json.loads(v)
    except (TypeError, ValueError):
        return None
    return [str(x) for x in out] if isinstance(out, list) else None


@dataclass
class WatchResult:
    started_at: int
    finished_at: int = 0
    candidates: int = 0
    checked: int = 0
    lookups: int = 0
    errors: int = 0
    baseline: int = 0
    capped: bool = False
    stopped: bool = False
    error: str | None = None
    new: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"started_at": self.started_at, "finished_at": self.finished_at, "candidates": self.candidates,
                "checked": self.checked, "lookups": self.lookups, "errors": self.errors,
                "baseline": self.baseline, "capped": self.capped, "stopped": self.stopped,
                "error": self.error, "new": len(self.new)}


def run_watch(conn: sqlite3.Connection, protected: Sequence[str], resolver: Any, *, now: int,
              max_lookups: int = WATCH_MAX_LOOKUPS, limiter: RateLimiter | None = None,
              stop: threading.Event | None = None, recheck_s: int = WATCH_RECHECK_S,
              clock: Callable[[], float] = time.time) -> WatchResult:
    """One watch run (see module doc). `resolver.query(name, 'NS'|'MX'|'A')
    -> DnsAnswer` (raises DnsError). Commits after every domain."""
    ensure_schema(conn)
    res = WatchResult(started_at=int(now))
    limiter = limiter or RateLimiter()
    res.candidates = sync_candidates(conn, protected, now)
    conn.commit()
    rows = conn.execute(
        "SELECT * FROM lookalike_watch WHERE checked_at IS NULL OR checked_at <= ? "
        "ORDER BY checked_at IS NOT NULL, checked_at, domain", (int(now) - int(recheck_s),)).fetchall()
    allowed = {r[0] for r in conn.execute("SELECT domain FROM lookalike_allow")}
    cap = max(0, int(max_lookups))

    def ask(dom: str, qtype: str) -> DnsAnswer:
        limiter.wait()
        res.lookups += 1
        return resolver.query(dom, qtype)

    in_a_row = 0

    for row in rows:
        if stop is not None and stop.is_set():
            res.stopped = True
            break
        if res.lookups + 3 > cap:
            res.capped = True
            break
        dom = str(row["domain"])
        try:
            ns = ask(dom, "NS")
            if ns.nxdomain:
                mx, a, registered = DnsAnswer(RCODE_NXDOMAIN, []), DnsAnswer(RCODE_NXDOMAIN, []), 0
            else:
                mx, a = ask(dom, "MX"), ask(dom, "A")
                registered = 0 if (mx.nxdomain and a.nxdomain and not ns.records) else 1
        except DnsError as ex:
            res.errors += 1
            conn.execute("UPDATE lookalike_watch SET errors=errors+1, last_error=? WHERE domain=?",
                         (str(ex)[:80], dom))
            conn.commit()
            if str(ex) == "resolver unreachable":
                res.error = "resolver unreachable"
                break
            in_a_row += 1
            if in_a_row >= WATCH_MAX_CONSECUTIVE_ERRORS:
                res.error = WATCH_ERROR_DNS
                break
            continue
        in_a_row = 0
        ts = int(clock())
        prev_checked = row["checked_at"]
        prev_mx, prev_a = _jl(row["mx"]), _jl(row["a"])
        new_what = []
        if prev_checked is not None:
            if prev_mx is not None and not prev_mx and mx.records:
                new_what.append("mx")
            if prev_a is not None and not prev_a and a.records:
                new_what.append("a")
        else:
            res.baseline += 1
        fields: dict[str, Any] = {
            "checked_at": ts, "ns": json.dumps(ns.records[:10]), "mx": json.dumps(mx.records[:10]),
            "a": json.dumps(a.records[:10]), "registered": registered, "last_error": None}
        if registered and row["first_registered_at"] is None:
            fields["first_registered_at"] = ts
        if new_what and not any(under(dom, d) for d in allowed):
            fields.update(new_at=ts, new_what=",".join(new_what), alerted_at=None, acked_at=None)
            res.new.append({"domain": dom, "protected": str(row["protected"]), "kind": str(row["kind"]),
                            "what": new_what, "mx": mx.records[:5], "a": a.records[:5]})
        sets = ", ".join(f"{k}=?" for k in fields)
        conn.execute(f"UPDATE lookalike_watch SET {sets} WHERE domain=?", (*fields.values(), dom))
        conn.commit()
        res.checked += 1
    if res.error is None and res.errors and res.errors >= res.checked:
        res.error = WATCH_ERROR_DNS        # mostly failed: not a complete run
    res.finished_at = int(clock())
    return res


def new_text(item: dict) -> str:
    """'pinslkbing[.]example (ligner pinsikbing.example) har fået en mailserver'."""
    what = item.get("what") or []
    if isinstance(what, str):
        what = [w for w in what.split(",") if w]
    if "mx" in what and "a" in what:
        got = "har fået en mailserver og en hjemmeside"
    elif "mx" in what:
        got = "har fået en mailserver"
    else:
        got = "har fået en hjemmeside (A-post)"
    return f"{defang(item.get('domain'))} (ligner {item.get('protected')}) {got}"
