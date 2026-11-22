"""Sender context for post-delivery rspamd scans.

The filter scans mail AFTER the provider delivered it, so rspamd would
otherwise judge the provider's last internal hop instead of the real
sender. This module walks the Received chain top-down, trusting only hops
written by the provider (built-in profiles + per-account extras), finds the
first external hop and turns it into the rspamd HTTP headers (IP, Helo,
Hostname, From, Rcpt, User) that an MTA would have passed at SMTP time.

Everything here is pure (no I/O) and must never raise: a garbage message
degrades to a context with only `Rcpt`.

Scannet can relay a domain's mail through SpamExperts (nodeN.spamfilter.io)
first. A SpamExperts node is trusted only when a trusted Scannet host (or
another trusted node) reports it by its verified rDNS or a known node IP;
the hop the node wrote is then the external sender, and SpamExperts' own
X-Spamfilter.io-Class (appended at the END of the header block) replaces
Scannet's score, which carries a -99/-100 SSO_SPAMEXPERTS whitelist.

Forwarded mail (the envelope is still a third-party SRS address after the
provider's own SRS layer is undone, e.g. Outlook.com "x+SRS=..@hotmail.com")
is scanned without the envelope sender: SPF of the forwarder path says
nothing about the original sender.

Provider spam verdicts (X-Spam-*) are only trusted where the provider
itself wrote them:
  * above the external hop (Scannet's amavis prepends its headers there);
  * for providers whose rspamd milter APPENDS headers (Gigahost - verified
    on real mail: X-Spam-Level/X-Spam sit at the very end of the header
    block), the trailing run of spam headers, and only with a consistent
    score. Anything else below the external hop is sender-controlled.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Iterable

# Bounds so a hostile message cannot make header parsing expensive.
MAX_HEADER_CHARS = 256 * 1024
MAX_HEADER_FIELDS = 1000
MAX_HOPS = 60
MAX_HEADER_VALUE = 255

PROVIDER_SPAM_BONUS = 4.0
PROVIDER_SCORE_BONUS = 2.0
PROVIDER_SCORE_MIN = 5.0

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class ProviderProfile:
    name: str
    # Only the provider's MAIL infrastructure. Its address blocks and
    # domain also hold shared web hosting and customer servers (e.g.
    # web1..web27.gigahost.dk in 46.183.139.0/24), which are senders like
    # any other and must stay external.
    networks: tuple[IPNetwork, ...]
    hosts: re.Pattern[str]          # full-match on a lower-case FQDN
    # Domains whose SRS rewrites are the provider's own (exact match).
    srs_domains: tuple[str, ...] = ()
    # True when the provider's spam scanner appends its headers at the end
    # of the header block (Postfix milter add_header) instead of prepending.
    appends_spam_headers: bool = False

    def host_match(self, host: str | None) -> bool:
        return bool(host) and self.hosts.fullmatch(host.lower().rstrip(".")) is not None


def _nets(*cidrs: str) -> tuple[IPNetwork, ...]:
    return tuple(ipaddress.ip_network(c) for c in cidrs)


PROFILES: tuple[ProviderProfile, ...] = (
    ProviderProfile(
        "gigahost",
        # mx1-3, mailstore6, cph1.mailout; smtp (submission), mailout, mx1.
        _nets("46.183.139.11/32", "46.183.139.12/32", "46.183.139.13/32",
              "46.183.139.166/32", "46.183.139.171/32", "89.186.169.107/32",
              "89.186.169.109/32", "89.186.169.112/32", "89.186.169.167/32"),
        re.compile(r"(?:mx\d+|mailstore\d+|smtp|mailout|cph\d+\.mailout)\.gigahost\.dk"),
        srs_domains=("gigahost.dk",),
        appends_spam_headers=True,
    ),
    ProviderProfile(
        "scannet",
        _nets("10.2.85.0/24"),
        # The amavis/mail-filter cluster (scanN/boxN.mf.scannet.dk).
        re.compile(r"(?:[a-z0-9-]+\.)*mf\.scannet\.dk"),
        srs_domains=("scannet.dk", "mf.scannet.dk"),
    ),
)

# SpamExperts (spamfilter.io) front relays seen in Scannet chains. NOT in
# PROFILES: a node is trusted only when a trusted Scannet host (or an
# already trusted node) reports it, never on its own.
SPAMEXPERTS = ProviderProfile(
    "spamexperts",
    _nets("94.231.106.10/32", "94.231.106.12/32", "89.188.78.64/32", "89.188.78.65/32",
          "89.188.78.66/32", "46.36.212.34/32", "46.36.212.36/32", "46.36.212.37/32",
          "46.36.212.38/32"),
    re.compile(r"node\d+\.spamfilter\.io"),
)
# Providers whose trusted hosts may hand mail over from SpamExperts.
SPAMEXPERTS_FRONTED = frozenset({"scannet"})
# Headers SpamExperts appends at the end of the header block.
_SE_TRAILING_NAMES = frozenset({
    "received-spf", "authentication-results", "x-recommended-action",
    "x-filter-id", "x-filter-label",
})
SE_CLASSES = frozenset({"ham", "unsure", "spam"})

# Loopback/private/link-local only. Deliberately not ipaddress.is_private,
# which also covers documentation/benchmark ranges that are not internal.
INTERNAL_NETWORKS: tuple[IPNetwork, ...] = tuple(ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10",
))

SPAM_HEADER_NAMES = frozenset({
    "x-spam-flag", "x-spam", "x-spam-status", "x-spam-score",
    "x-spam-level", "x-spamd-bar", "x-spamd-result", "x-rspamd-score",
})
# Headers a provider milter may append next to its spam headers; the
# trailing provider block is the run of these at the end of the header.
_APPENDED_NAMES = SPAM_HEADER_NAMES | frozenset({
    "x-rspamd-queue-id", "x-rspamd-server", "x-rspamd-action",
    "x-rspamd-pre-result", "x-virus-scanned",
})

_CLAUSE_KEYWORDS = frozenset({"from", "by", "via", "with", "id", "for"})
_HEADER_NAME_RE = re.compile(r"^[!-9;-~]+$")  # RFC 5322 ftext
_BRACKET_IP_RE = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]", re.IGNORECASE)
_ENVELOPE_FROM_RE = re.compile(r"\(envelope-from\s+<([^<>\s]*)>", re.IGNORECASE)
_HELO_RE = re.compile(r"\bhelo=([^\s()]+)", re.IGNORECASE)
_CLIENT_ARG_RE = re.compile(r"\b(?:helo|ident)=[^\s()]*", re.IGNORECASE)
_AUTH_PROTO_RE = re.compile(r"(?:UTF8)?(?:E?SMTP|LMTP)S?A")
_SRS_RE = re.compile(r"^SRS([01])[=+-](.*)$", re.IGNORECASE)
# Strict SRS shapes used to decide "this mail was forwarded" (srs_reverse
# itself stays lenient for display). hash = base64 chars, TT = 2 chars.
_DOMAIN = r"(?=[A-Za-z0-9.-]{3,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+"
_STRICT_SRS0_RE = re.compile(r"^SRS0[=+-][A-Za-z0-9+/]{1,16}=[A-Za-z0-9]{2}=([^=@]+)=(.+)$", re.IGNORECASE)
_STRICT_SRS1_RE = re.compile(r"^SRS1[=+-][A-Za-z0-9+/]{1,16}=([^=@]+)=[=+-]?[A-Za-z0-9+/]{1,16}=[A-Za-z0-9]{2}=([^=@]+)=(.+)$",
                             re.IGNORECASE)
# Outlook.com/Exchange Online forwarding: "local+SRS=hash=TT=domain=orig@fwd".
_OUTLOOK_SRS_RE = re.compile(r"^[^+=@]+\+SRS=([A-Za-z0-9+/]{1,16})=([A-Za-z0-9]{2})=([^=@]+)=(.+)$")
_SE_AR_IPREV_RE = re.compile(
    r"^\s*([^;\s]+)\s*;.*?\biprev=(\w+)\s*\(([^()\s]+)\)\s*smtp\.remote-ip=([0-9A-Fa-f:.]+)",
    re.IGNORECASE)
_SSO_SE_RE = re.compile(r"\bSSO_SPAMEXPERTS=", re.IGNORECASE)
_PAREN_FLOAT_RE = re.compile(r"\(\s*([-+]?\d+(?:\.\d+)?)\s*\)")
_FLOAT_RE = re.compile(r"[-+]?\d+(?:\.\d+)?")


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------


def parse_headers(raw: bytes | str | None) -> list[tuple[str, str]]:
    """Return the header fields as an ordered list of (lower-name, value),
    with folded lines unfolded. Stops at the first blank line. Never raises."""
    try:
        if raw is None:
            return []
        if isinstance(raw, (bytes, bytearray, memoryview)):
            text = bytes(raw[: MAX_HEADER_CHARS * 2]).decode("utf-8", "replace")
        else:
            text = str(raw)
        text = text[:MAX_HEADER_CHARS]
        fields: list[tuple[str, str]] = []
        for line in re.split(r"\r\n|\n|\r", text):
            if line == "" or line.strip() == "":
                if fields:
                    break  # end of header block
                continue
            if line[0] in " \t":
                if fields:
                    name, value = fields[-1]
                    fields[-1] = (name, f"{value} {line.strip()}".strip())
                continue
            name, sep, value = line.partition(":")
            name = name.strip()
            if not sep or not name or not _HEADER_NAME_RE.match(name):
                continue  # mbox "From " line or garbage
            if len(fields) >= MAX_HEADER_FIELDS:
                break
            fields.append((name.lower(), value.strip()))
        return fields
    except Exception:
        return []


def _tokens(text: str) -> list[str]:
    """Split a Received value into whitespace tokens, keeping balanced
    (comments) as single tokens and ';' as its own token."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == "(":
            depth, j = 0, i
            while j < n:
                if text[j] == "(":
                    depth += 1
                elif text[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            out.append(text[i : j + 1])
            i = j + 1
        elif c == ";":
            out.append(";")
            i += 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in "(;":
                j += 1
            out.append(text[i:j])
            i = j
    return out


def _parse_ip(text: str | None) -> IPAddress | None:
    if not text:
        return None
    s = text.strip()
    # Exim with port logging: "[a.b.c.d]:port" / "[v6]:port".
    m = re.fullmatch(r"\[([^\[\]]+)\]:\d+", s)
    if m:
        s = m.group(1)
    s = s.strip("[]")
    if s.lower().startswith("ipv6:"):
        s = s[5:]
    # "a.b.c.d:port" (ecelerity style) - drop the port.
    m = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3}):\d+", s)
    if m:
        s = m.group(1)
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _clean_host(name: str | None) -> str | None:
    if not name:
        return None
    s = name.strip().strip("<>").rstrip(".").lower()
    return s or None


def parse_received(value: str) -> dict[str, Any]:
    """Parse one Received header value into its from/by/with parts."""
    hop: dict[str, Any] = {
        "from_helo": None, "from_rdns": None, "from_ip": None,
        "by": None, "by_aliases": [], "by_ip": None, "proto": None,
        "envelope_from": None, "from_token": None, "for": None,
    }
    clauses: dict[str, list[str]] = {}
    current: str | None = None
    for tok in _tokens(value):
        if tok == ";":
            break
        low = tok.lower()
        if low in _CLAUSE_KEYWORDS and not tok.startswith("("):
            current = low if low not in clauses else None
            if current:
                clauses[current] = []
            continue
        if current is not None:
            clauses[current].append(tok)

    frm = clauses.get("from")
    if frm is not None:
        plain = [t for t in frm if not t.startswith("(")]
        comments = [t[1:-1].strip() for t in frm if t.startswith("(")]
        helo = plain[0] if plain else None
        hop["from_helo"] = helo
        hop["from_token"] = helo
        ip: IPAddress | None = None
        for c in comments:
            # Exim "(... helo=X ident=Y)": X/Y are client-controlled, so a
            # HELO literal "[127.0.0.1]" must never be taken as the IP.
            m = _BRACKET_IP_RE.search(_CLIENT_ARG_RE.sub(" ", c))
            if m and ip is None:
                ip = _parse_ip(m.group(1))
                if ip is not None:
                    before = _CLIENT_ARG_RE.sub(" ", c)[: m.start()].strip()
                    if before and not before.startswith("["):
                        hop["from_rdns"] = before.split()[0]
            h = _HELO_RE.search(c)
            if h:
                # Exim style "(... helo=x)": the leading token is the rDNS.
                hop["from_helo"] = h.group(1)
                if helo and not helo.startswith("[") and not hop["from_rdns"]:
                    hop["from_rdns"] = helo
        if ip is None:
            # ZoneMTA style "from name [ip]" or a bare "[ip]" HELO literal.
            for t in plain[1:] + plain[:1]:
                if t.startswith("["):
                    ip = _parse_ip(t)
                    if ip is not None:
                        break
        hop["from_ip"] = ip

    by = clauses.get("by")
    if by:
        plain = [t for t in by if not t.startswith("(")]
        if plain:
            if plain[0].startswith("["):
                hop["by_ip"] = _parse_ip(plain[0])
            else:
                hop["by"] = _clean_host(plain[0])
        for t in by:
            if not t.startswith("("):
                continue
            inner = t[1:-1].strip()
            m = _BRACKET_IP_RE.search(inner)
            if m:
                alias = inner[: m.start()].strip()
                if alias:
                    hop["by_aliases"].append(_clean_host(alias.split()[0]))
                if hop["by_ip"] is None:
                    hop["by_ip"] = _parse_ip(m.group(1))

    with_ = clauses.get("with")
    if with_:
        plain = [t for t in with_ if not t.startswith("(")]
        if plain:
            hop["proto"] = plain[0].strip(";").upper()

    for_ = clauses.get("for")
    if for_:
        plain = [t for t in for_ if not t.startswith("(")]
        if plain:
            hop["for"] = _addr_from_path(plain[0].strip(";"))

    m = _ENVELOPE_FROM_RE.search(value)
    if m:
        hop["envelope_from"] = m.group(1)
    return hop


# ---------------------------------------------------------------------------
# Trust
# ---------------------------------------------------------------------------


class _Trust:
    def __init__(self, acc: Any) -> None:
        nets: list[IPNetwork] = []
        suffixes: list[str] = []
        for p in PROFILES:
            nets.extend(p.networks)
        for cidr in _as_list(getattr(acc, "trusted_relays", None)):
            try:
                nets.append(ipaddress.ip_network(str(cidr).strip(), strict=False))
            except ValueError:
                continue
        for dom in _as_list(getattr(acc, "trusted_relay_domains", None)):
            d = _clean_host(str(dom).lstrip("*").lstrip("."))
            if d:
                suffixes.append(d)
        self.networks = tuple(nets)
        self.suffixes = tuple(dict.fromkeys(suffixes))
        # Trusted forwarders (2.1): the owner's own MX that forwards shop
        # mailboxes with SRS. Walked past like a provider hop.
        fwd_nets: list[IPNetwork] = []
        fwd_hosts: list[str] = []
        fwd_suffixes: list[str] = []
        for entry in _as_list(getattr(acc, "trusted_forwarders", None)):
            e = str(entry).strip().lower()
            if not e:
                continue
            try:
                fwd_nets.append(ipaddress.ip_network(e, strict=False))
                continue
            except ValueError:
                pass
            if e.startswith("*."):
                d = _clean_host(e[2:])
                if d:
                    fwd_suffixes.append(d)
            else:
                d = _clean_host(e)
                if d:
                    fwd_hosts.append(d)
        self.fwd_networks = tuple(fwd_nets)
        self.fwd_hosts = frozenset(fwd_hosts)
        self.fwd_suffixes = tuple(dict.fromkeys(fwd_suffixes))

    def forwarder_host(self, host: str | None) -> bool:
        h = _clean_host(host)
        if not h:
            return False
        return h in self.fwd_hosts or any(h.endswith("." + s) for s in self.fwd_suffixes)

    def forwarder_hop(self, hop: dict[str, Any]) -> bool:
        """The hop's client is a trusted forwarder (IP listed, or the
        verified rDNS the trusted writer reported matches)."""
        ip = hop["from_ip"]
        if ip is not None and any(ip.version == n.version and ip in n for n in self.fwd_networks):
            return True
        return self.forwarder_host(hop["from_rdns"])

    @staticmethod
    def _suffix_match(host: str | None, suffixes: Iterable[str]) -> bool:
        if not host:
            return False
        host = host.lower().rstrip(".")
        return any(host == s or host.endswith("." + s) for s in suffixes)

    def host_trusted(self, host: str | None) -> bool:
        """A provider mail host (exact patterns) or a per-account trusted
        relay domain (suffix)."""
        return (any(p.host_match(host) for p in PROFILES)
                or self._suffix_match(host, self.suffixes))

    def srs_domain_trusted(self, domain: str | None) -> bool:
        d = (domain or "").lower().rstrip(".")
        return (any(d in p.srs_domains for p in PROFILES)
                or self._suffix_match(domain, self.suffixes))

    def ip_listed(self, ip: IPAddress | None) -> bool:
        return ip is not None and any(
            ip.version == n.version and ip in n for n in self.networks)

    def ip_trusted(self, ip: IPAddress | None) -> bool:
        if ip is None:
            return False
        if any(ip.version == n.version and ip in n for n in INTERNAL_NETWORKS):
            return True
        return self.ip_listed(ip)

    def writer_trusted(self, hop: dict[str, Any]) -> bool:
        if self.host_trusted(hop["by"]) or self.ip_listed(hop["by_ip"]):
            return True
        return any(self.host_trusted(a) for a in hop["by_aliases"])


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    if isinstance(value, str):
        return [v for v in re.split(r"[\s,]+", value) if v]
    return []


def _profile_for(hop: dict[str, Any]) -> ProviderProfile | None:
    names = [hop["by"], *hop["by_aliases"]]
    for p in PROFILES:
        if any(p.host_match(n) for n in names if n):
            return p
        ip = hop["by_ip"]
        if ip is not None and any(ip.version == n.version and ip in n for n in p.networks):
            return p
    return None


# ---------------------------------------------------------------------------
# Envelope sender / SRS
# ---------------------------------------------------------------------------


def _addr_from_path(value: str | None) -> str | None:
    """'<a@b>' -> 'a@b'; '<>' or garbage -> None."""
    if not value:
        return None
    m = re.search(r"<([^<>]*)>", value)
    addr = (m.group(1) if m else value).strip()
    if not addr or "@" not in addr or any(c.isspace() for c in addr):
        return None
    return addr


def srs_reverse(addr: str) -> str | None:
    """Undo ONE SRS layer. SRS0=H=TT=domain=local@fwd -> local@domain;
    SRS1=H=fwd1==H2=TT=domain=local@fwd2 -> SRS0=H2=TT=domain=local@fwd1;
    Outlook.com x+SRS=H=TT=domain=local@fwd -> local@domain.
    Returns None when `addr` is not a well-formed SRS address."""
    local, at, _domain = addr.rpartition("@")
    if not at:
        return None
    m = _SRS_RE.match(local)
    if not m:
        o = _OUTLOOK_SRS_RE.match(local)
        if o and re.fullmatch(_DOMAIN, o.group(3)):
            return f"{o.group(4)}@{o.group(3)}"
        return None
    kind, rest = m.group(1), m.group(2)
    if kind == "0":
        parts = rest.split("=", 3)  # hash, timestamp, domain, local(may contain '=')
        if len(parts) != 4 or not parts[2] or not parts[3]:
            return None
        return f"{parts[3]}@{parts[2]}"
    parts = rest.split("=", 2)  # hash, first forwarder, '=' + SRS0 opaque part
    if len(parts) != 3 or not parts[1] or not parts[2]:
        return None
    opaque = parts[2][1:] if parts[2][:1] in "=+-" else parts[2]
    if not opaque:
        return None
    return f"SRS0={opaque}@{parts[1]}"


def srs_decode_all(addr: str | None, max_layers: int = 4) -> str | None:
    """Fully decode nested SRS (for display: the original sender)."""
    cur = addr
    for _ in range(max_layers):
        if not cur:
            return cur
        nxt = srs_reverse(cur)
        if nxt is None:
            return cur
        cur = nxt
    return cur


def _provider_srs_decode(addr: str | None, trust: _Trust, *, forwarders: bool = False) -> str | None:
    """Undo only the SRS layers added by trusted provider hosts (Gigahost
    rewrites after receiving), so the result is the MAIL FROM that the
    external hop actually presented - which is what SPF must check. A
    third-party forwarder's own SRS (e.g. Scannet mail via a forwarder) is
    kept because that forwarder IS the external hop. `forwarders` (2.1):
    the chain was walked past a trusted forwarder, so its SRS layer is
    undone too (the hop below it is the external one)."""
    cur = addr
    for _ in range(6):
        if not cur:
            return cur
        domain = cur.rpartition("@")[2]
        if not (trust.srs_domain_trusted(domain) or (forwarders and trust.forwarder_host(domain))):
            return cur
        nxt = srs_reverse(cur)
        if nxt is None:
            return cur
        cur = nxt
    return cur


def forwarder_srs(addr: str | None) -> bool:
    """True when `addr` (the envelope AFTER the provider's own SRS layer is
    undone) is unambiguously a third-party forwarder's SRS address:
      * classic SRS0=hash=TT=domain=local@fwd / SRS1=hash=fwd1=[=]hash=TT=domain=local@fwd;
      * Outlook.com x+SRS=hash=TT=domain=local@fwd.
    hash must be 1-16 base64 chars, TT exactly 2 alphanumerics, the encoded
    domain a valid multi-label domain that differs from the forwarder's
    domain. Anything looser ("news+SRS=weekly@shop", VERP/BATV "prvs=",
    "msprvs1=") is NOT forwarded mail: the From/SPF context is kept."""
    try:
        if not addr:
            return False
        local, at, fwd = addr.rpartition("@")
        if not at or not local or not re.fullmatch(_DOMAIN, fwd):
            return False
        fwd = fwd.lower().rstrip(".")
        for rx, dom_group in ((_STRICT_SRS0_RE, 1), (_STRICT_SRS1_RE, 2), (_OUTLOOK_SRS_RE, 3)):
            m = rx.match(local)
            if m:
                dom = m.group(dom_group)
                if rx is _STRICT_SRS1_RE and not re.fullmatch(_DOMAIN, m.group(1)):
                    return False
                return bool(re.fullmatch(_DOMAIN, dom)) and dom.lower().rstrip(".") != fwd
        return False
    except Exception:
        return False


# Split To/Cc into address-like tokens (linear; a findall with an
# unanchored "[...]+@" pattern is quadratic on a long sender-made value).
_ADDR_SPLIT_RE = re.compile(r"[\s,;:<>()\[\]\"]+")


def _addressed_to(fields: list[tuple[str, str]], user: Any) -> bool:
    """Is the account address in To/Cc (case-insensitive)?"""
    u = str(user or "").strip().lower()
    if not u:
        return False
    for name, value in fields:
        if name not in ("to", "cc") or u not in value.lower():
            continue
        if any(a.lower().rstrip(".") == u for a in _ADDR_SPLIT_RE.split(value)):
            return True
    return False


# ---------------------------------------------------------------------------
# Provider verdict
# ---------------------------------------------------------------------------


def _first_float(text: str) -> float | None:
    m = _FLOAT_RE.search(text or "")
    if not m:
        return None
    try:
        return float(m.group(0))
    except ValueError:
        return None


def _yes_no(text: str) -> bool | None:
    t = (text or "").strip().lower()
    if t.startswith(("yes", "true")):
        return True
    if t.startswith(("no", "false")):
        return False
    return None


def _verdict(fields: list[tuple[str, str]], *, last_wins: bool) -> tuple[bool | None, float | None, bool]:
    """(flag, score, found_any) from spam headers. `last_wins` picks the
    last occurrence of each header (appended block), else the first
    (prepended block: the topmost one is the provider's)."""
    picked: dict[str, str] = {}
    for name, value in fields:
        if name not in SPAM_HEADER_NAMES:
            continue
        if last_wins or name not in picked:
            picked[name] = value
    if not picked:
        return None, None, False

    flag: bool | None = None
    for key in ("x-spam-flag", "x-spam-status", "x-spam"):
        if key in picked:
            flag = _yes_no(picked[key])
            if flag is not None:
                break

    score: float | None = None
    if "x-spam-score" in picked:
        score = _first_float(picked["x-spam-score"])
    if score is None and "x-spam-status" in picked:
        m = re.search(r"score=([-+]?\d+(?:\.\d+)?)", picked["x-spam-status"])
        if m:
            score = float(m.group(1))
    if score is None and "x-rspamd-score" in picked:
        score = _first_float(picked["x-rspamd-score"])
    if score is None and "x-spamd-result" in picked:
        m = re.search(r"\[\s*([-+]?\d+(?:\.\d+)?)\s*/", picked["x-spamd-result"])
        if m:
            score = float(m.group(1))
    if score is None and "x-spam-level" in picked:
        score = float(picked["x-spam-level"].count("*"))
    if score is None and "x-spamd-bar" in picked:
        bar = picked["x-spamd-bar"]
        score = float(bar.count("+") - bar.count("-"))
    return flag, score, True


def _trailing_block(fields: list[tuple[str, str]], start: int) -> list[tuple[str, str]]:
    i = len(fields)
    while i > start and fields[i - 1][0] in _APPENDED_NAMES:
        i -= 1
    return fields[i:]


def _se_name(name: str) -> bool:
    return name in _SE_TRAILING_NAMES or name.startswith("x-spamfilter.io-")


def _se_block(fields: list[tuple[str, str]], start: int) -> list[tuple[str, str]]:
    """SpamExperts' appended block: the trailing run of its header names
    below the external hop. It always ends its block with X-Filter-ID (plus
    optional X-Spamfilter.io-Original-*), so without one there is no block.
    The run may also swallow sender headers with the same names (e.g. a
    Microsoft Authentication-Results right above it), so callers pick the
    LAST class and match Authentication-Results by authserv-id."""
    i = len(fields)
    while i > start and _se_name(fields[i - 1][0]):
        i -= 1
    block = fields[i:]
    return block if any(n == "x-filter-id" for n, _ in block) else []


def _se_verdict(block: list[tuple[str, str]]) -> tuple[str | None, float | None]:
    cls: str | None = None
    evidence: float | None = None
    for name, value in block:
        if name == "x-spamfilter.io-class":
            v = value.strip().lower()
            cls = v if v in SE_CLASSES else None
            evidence = None
        elif name == "x-spamfilter.io-evidence":
            m = _PAREN_FLOAT_RE.search(value)
            evidence = float(m.group(1)) if m else None
    return cls, evidence


def _se_iprev(block: list[tuple[str, str]], node: str | None, ip: Any) -> tuple[str | None, str | None]:
    """(result, host) of the node's own iprev check for `ip`, from an
    Authentication-Results whose authserv-id is that node. The LAST match
    wins: the trailing run can start with sender headers, SpamExperts'
    own line comes after them."""
    found: tuple[str | None, str | None] = (None, None)
    if not node or ip is None:
        return found
    for name, value in block:
        if name != "authentication-results":
            continue
        m = _SE_AR_IPREV_RE.match(value)
        if not m or _clean_host(m.group(1)) != node or _parse_ip(m.group(4)) != ip:
            continue
        found = (m.group(2).lower(), _clean_host(m.group(3)))
    return found


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _safe_header_value(value: Any) -> str | None:
    """rspamd HTTP header values must be printable ASCII without CR/LF;
    drop (rather than mangle) anything else."""
    if value is None:
        return None
    s = str(value).strip()
    if not s or len(s) > MAX_HEADER_VALUE:
        return None
    if any(ord(c) < 0x21 or ord(c) > 0x7E for c in s):
        return None
    return s


def _base_context(acc: Any) -> dict[str, Any]:
    headers: dict[str, str] = {}
    rcpt = _safe_header_value(getattr(acc, "user", None))
    if rcpt:
        headers["Rcpt"] = rcpt
    return {
        "headers": headers, "external_ip": None, "helo": None,
        "hostname": None, "envelope_from": None, "original_sender": None,
        "authenticated": False, "provider": None, "provider_score": None,
        "provider_flag": None, "provider_source": None, "trusted_chain": False,
        "provider_class": None, "provider_evidence": None, "forwarded": False,
        "via_forwarder": None, "forwarders": [], "origin_host": None, "recipients": [],
        "hops": [], "provider_auth": None,
    }


def scan_context(raw: bytes | str | None, acc: Any) -> dict[str, Any]:
    """Build the rspamd scan context for a delivered message (full message
    or header block). Never raises; see module docstring for the rules."""
    ctx = _base_context(acc)
    try:
        _fill_context(ctx, raw, acc)
    except Exception:
        # A parser bug must never cost a scan: fall back to Rcpt only.
        return _base_context(acc)
    return ctx


def _fill_context(ctx: dict[str, Any], raw: bytes | str | None, acc: Any) -> None:
    fields = parse_headers(raw)
    trust = _Trust(acc)

    hops: list[dict[str, Any]] = []
    for idx, (name, value) in enumerate(fields):
        if name == "received" and len(hops) < MAX_HOPS:
            hop = parse_received(value)
            hop["index"] = idx
            hop["exim"] = "(exim" in value.lower()
            hops.append(hop)

    external: dict[str, Any] | None = None
    profile: ProviderProfile | None = None
    last_trusted: dict[str, Any] | None = None
    roles: list[str] = []
    continuity = False
    via_se = False  # a SpamExperts node was trusted further up
    forwarder_hops: list[dict[str, Any]] = []
    for hop in hops:
        if external is not None or (roles and roles[-1] == "untrusted"):
            roles.append("unchecked")
            continue
        # A node's own Received (by nodeN) is trusted without continuity only
        # right below that node's local re-injection (quarantine release:
        # "from www-data by nodeN with local"); anywhere else a by-name match
        # is forgeable.
        se_writer = via_se and SPAMEXPERTS.host_match(hop["by"])
        if se_writer and not continuity:
            se_writer = (last_trusted is not None
                         and SPAMEXPERTS.host_match(last_trusted["by"])
                         and last_trusted["from_ip"] is None
                         and last_trusted["proto"] == "LOCAL")
        if not (continuity or trust.writer_trusted(hop) or se_writer):
            roles.append("untrusted")
            continue
        if profile is None and last_trusted is None:
            profile = _profile_for(hop)
        last_trusted = hop
        if hop["from_ip"] is None:
            # "by X (from userid N)" local pickup or a from without an IP:
            # nothing to judge; the next hop must earn trust by its writer.
            roles.append("internal")
            continuity = False
            continue
        if trust.ip_trusted(hop["from_ip"]) or trust.host_trusted(hop["from_rdns"]):
            # The rDNS shown by a trusted Postfix is forward-confirmed, so
            # e.g. smtp.gigahost.dk [89.186.169.109] is provider-internal.
            roles.append("internal")
            continuity = True
            continue
        if trust.forwarder_hop(hop):
            # A trusted forwarder (the owner's own MX): the hop IT wrote is
            # the real external hop.
            roles.append("forwarder")
            continuity = True
            forwarder_hops.append(hop)
            continue
        writer = _profile_for(hop)
        if ((se_writer or (writer is not None and writer.name in SPAMEXPERTS_FRONTED))
                and (SPAMEXPERTS.host_match(hop["from_rdns"])
                     or any(hop["from_ip"].version == n.version and hop["from_ip"] in n
                            for n in SPAMEXPERTS.networks))):
            # Scannet (Postfix, verified rDNS) received it from a SpamExperts
            # node: the hop that node wrote is the real external hop.
            roles.append("internal")
            continuity = True
            via_se = True
            continue
        roles.append("external")
        external = hop

    ctx["hops"] = [
        {
            "from_helo": h["from_helo"], "from_rdns": h["from_rdns"],
            "from_ip": str(h["from_ip"]) if h["from_ip"] is not None else None,
            "by": h["by"], "proto": h["proto"], "role": role,
        }
        for h, role in zip(hops, roles)
    ]
    trusted_chain = last_trusted is not None
    ctx["trusted_chain"] = trusted_chain
    ctx["provider"] = profile.name if profile else None
    if via_se:
        ctx["provider"] = f"{profile.name}+spamexperts" if profile else "spamexperts"
    se_block = _se_block(fields, external["index"] + 1) if (via_se and external is not None) else []

    # Envelope sender: Return-Path (written at final delivery), falling
    # back to the "(envelope-from <x>)" note of the topmost trusted hop.
    return_path = next((v for n, v in fields if n == "return-path"), None)
    envelope = _addr_from_path(return_path)
    if envelope is None and return_path is None and hops and roles and roles[0] != "untrusted":
        envelope = _addr_from_path(f"<{hops[0]['envelope_from']}>") if hops[0]["envelope_from"] else None
    envelope = _provider_srs_decode(envelope, trust, forwarders=bool(forwarder_hops))
    ctx["envelope_from"] = envelope
    ctx["original_sender"] = srs_decode_all(envelope)
    forwarded = forwarder_srs(envelope)
    ctx["forwarded"] = forwarded
    fwd_names = [_hop_name(h) or str(h["from_ip"]) for h in forwarder_hops]
    ctx["via_forwarder"] = fwd_names[-1] if fwd_names else None
    ctx["forwarders"] = fwd_names
    # E8: the host the mail verifiably came from (as reported by a trusted
    # writer); when it originated on a trusted forwarder itself, that host.
    # Never a third-party forwarder (SRS envelope left): it relays anyone's
    # mail, spam included, so its name proves nothing about the sender.
    origin = None
    if forwarded:
        origin = None
    elif external is not None:
        origin = _hop_name(external)
    elif forwarder_hops:
        origin = _hop_name(forwarder_hops[-1])
    ctx["origin_host"] = origin
    # E9: recipients - header recipients plus the "for <x>" of hops written
    # by trusted hosts (incl. the forwarder's own hop = original RCPT TO).
    rcpts: list[str] = []
    for name, value in fields:
        if name in ("to", "cc", "delivered-to", "x-original-to"):
            rcpts.extend(a for a in _ADDR_SPLIT_RE.split(value) if "@" in a)
    for hop, role in zip(hops, roles):
        if role in ("internal", "forwarder", "external") and hop.get("for"):
            rcpts.append(hop["for"])
    ctx["recipients"] = list(dict.fromkeys(
        a.lower().strip(".") for a in rcpts if len(a) <= 254))[:50]
    # The sending host rspamd judges: the external hop, or - for mail that
    # originated inside a trusted forwarder (its own notifications, or a
    # wildcard entry covering the platform's senders) - the deepest
    # forwarder hop, so SPF/RBL still see a real IP instead of none.
    sender_hop = external if external is not None else (forwarder_hops[-1] if forwarder_hops else None)
    original_rcpt = sender_hop.get("for") if (sender_hop is not None and forwarder_hops) else None

    headers: dict[str, str] = ctx["headers"]
    if sender_hop is not None:
        ip = str(sender_hop["from_ip"])
        helo = sender_hop["from_helo"]
        rdns = sender_hop["from_rdns"]
        hostname = None if not rdns or rdns.lower() == "unknown" else rdns.rstrip(".")
        if via_se and SPAMEXPERTS.host_match(sender_hop["by"]):
            hostname = _se_hostname(sender_hop, se_block, hostname)
        ctx["external_ip"] = ip
        ctx["helo"] = helo
        ctx["hostname"] = hostname
        ctx["authenticated"] = bool(
            sender_hop["proto"] and _AUTH_PROTO_RE.fullmatch(sender_hop["proto"]))
        for key, val in (("IP", ip), ("Helo", helo), ("Hostname", hostname)):
            safe = _safe_header_value(val)
            if safe:
                headers[key] = safe
    if (forwarded or forwarder_hops) and not _addressed_to(fields, getattr(acc, "user", None)):
        # Forwarded to this account from another mailbox: the SMTP RCPT is
        # not in To/Cc, which rspamd would score as FORGED_RECIPIENTS.
        # Via a trusted forwarder the original RCPT TO is known.
        headers.pop("Rcpt", None)
        safe_rcpt = _safe_header_value(original_rcpt)
        if safe_rcpt:
            headers["Rcpt"] = safe_rcpt
    if trusted_chain:
        if forwarded:
            # A forwarder's SPF says nothing about the original sender, and
            # omitting From makes rspamd fall back to the MIME From (SPF fail
            # from the forwarder's IP). A null sender makes rspamd check the
            # forwarder's HELO instead (RFC 7208 2.4); DMARC still runs on
            # DKIM alignment. Verified on live forwarded mail (a shop platform,
            # Outlook.com): -4.5 points of false SPF penalties removed.
            headers["From"] = "<>"
        else:
            safe_from = _safe_header_value(envelope)
            if safe_from:
                headers["From"] = safe_from
        if ctx["authenticated"]:
            user = _safe_header_value(envelope) or _safe_header_value(getattr(acc, "user", None))
            if user:
                headers["User"] = user

    # 2.2 (B7): the provider's own authentication verdict at delivery time,
    # only from Authentication-Results a trusted host wrote.
    if trusted_chain:
        ctx["provider_auth"] = _provider_auth(fields, trust, hops, roles, external,
                                              last_trusted, via_se, se_block)

    # Provider verdict (C2): only from headers the provider wrote.
    if not trusted_chain:
        return
    if via_se:
        # Scannet's score includes SSO_SPAMEXPERTS=-99/-100 (whitelisting
        # everything SpamExperts relays) and SPF/RBL results against the
        # node, so it is ignored; SpamExperts' own class is the verdict.
        cls, evidence = _se_verdict(se_block)
        if cls is not None:
            ctx["provider_class"] = cls
            ctx["provider_evidence"] = evidence
            ctx["provider_flag"] = {"spam": True, "ham": False}.get(cls)
            ctx["provider_source"] = "trailing"
        return
    boundary = external["index"] if external is not None else last_trusted["index"]
    flag, score, found = _verdict(fields[:boundary], last_wins=False)
    source = "above" if found else None
    if not found and profile is not None and profile.appends_spam_headers:
        tail = _trailing_block(fields, boundary + 1)
        flag, score, found = _verdict(tail, last_wins=True)
        if found:
            source = "trailing"
            # A trailing "X-Spam: Yes" may come from an upstream forwarder;
            # Gigahost always writes a matching X-Spam-Level, so require it.
            if flag is True and (score is None or score < PROVIDER_SCORE_MIN):
                flag = None
    if found:
        ctx["provider_flag"] = flag
        ctx["provider_score"] = score
        ctx["provider_source"] = source


def _hop_name(hop: dict[str, Any]) -> str | None:
    """Verified client name of a hop as its (trusted) writer reported it:
    Postfix's rDNS ("unknown" = none) or Exim's leading verified name."""
    rd = hop.get("from_rdns")
    if rd and rd.lower() != "unknown":
        return _clean_host(rd)
    lead = hop.get("from_token")
    if hop.get("exim") and lead and not lead.startswith("[") and _parse_ip(lead) is None:
        return _clean_host(lead)
    return None


def _se_hostname(hop: dict[str, Any], block: list[tuple[str, str]], rdns: str | None) -> str | None:
    """Hostname for the external hop written by a SpamExperts node (Exim).
    Exim's "from NAME ([ip] helo=X)" / "from NAME ([ip])" starts with the
    VERIFIED host name (an unverified host is written "from [ip] (helo=X)");
    on all real samples the node's own Authentication-Results iprev host is
    identical. Order: Exim's name; else the node's iprev=pass host (only an
    A-R whose authserv-id is that node and whose remote-ip is the hop IP,
    in SpamExperts' appended block). A non-pass iprev drops the name."""
    result, host = _se_iprev(block, hop["by"], hop["from_ip"])
    if result is not None and result != "pass":
        return None
    name = rdns
    lead = hop.get("from_token")  # Exim: verified name, or "[ip]" when none
    if not name and hop.get("exim") and lead and not lead.startswith("[") and _parse_ip(lead) is None:
        name = _clean_host(lead)
    if name:
        return name
    return host if result == "pass" else None


def provider_bonus(ctx: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Pseudo-symbols for the provider's own verdict (C3). Pure; never raises."""
    try:
        if not ctx:
            return []
        flag = ctx.get("provider_flag")
        score = ctx.get("provider_score")
        name = str(ctx.get("provider") or "udbyder")
        opts = [name]
        if isinstance(score, (int, float)):
            opts.append(f"score={score:g}")
        if flag is True:
            return [{"n": "TH_PROVIDER_SPAM", "s": PROVIDER_SPAM_BONUS, "o": opts[:3]}]
        if ctx.get("provider_class") == "unsure":
            ev = ctx.get("provider_evidence")
            opts = [name, "class=unsure"]
            if isinstance(ev, (int, float)) and not isinstance(ev, bool):
                opts.append(f"evidence={ev:g}")
            return [{"n": "TH_PROVIDER_SCORE", "s": PROVIDER_SCORE_BONUS, "o": opts}]
        if isinstance(score, (int, float)) and score >= PROVIDER_SCORE_MIN:
            return [{"n": "TH_PROVIDER_SCORE", "s": PROVIDER_SCORE_BONUS, "o": opts[:3]}]
    except Exception:
        pass
    return []


# rspamd's own SPAM_FLAG rule already scores a provider "spam" header
# (X-Spam-Flag: YES / X-Spam: Yes, +5). The provider bonus must not count
# the same verdict twice, so it only tops up whatever SPAM_FLAG left.
OVERLAPPING_SYMBOLS = frozenset({"SPAM_FLAG"})


def effective_bonus(bonus: list[dict[str, Any]] | None,
                    rspamd_symbols: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Provider-bonus pseudo-symbols reduced by rspamd symbols that already
    score the provider's verdict. Pure; never raises."""
    try:
        covered = sum(max(0.0, float(s.get("s") or 0)) for s in rspamd_symbols or []
                      if s.get("n") in OVERLAPPING_SYMBOLS)
        out = []
        for b in bonus or []:
            score = float(b.get("s") or 0)
            left = max(0.0, score - covered)
            covered = max(0.0, covered - score)
            if left > 0:
                out.append({**b, "s": left})
        return out
    except Exception:
        return list(bonus or [])


def provider_verdict(ctx: dict[str, Any] | None) -> str:
    """'spam' | 'clean' | 'unknown' - used by the trainer's provider_filter.
    A provider whose chain we trust but that wrote no spam verdict (Gigahost
    only marks spam) counts as 'clean'."""
    try:
        if not ctx:
            return "unknown"
        if ctx.get("provider_flag") is True:
            return "spam"
        if not ctx.get("trusted_chain") or not ctx.get("provider"):
            return "unknown"
        if ctx.get("provider_class") == "unsure":
            return "unknown"  # SpamExperts "unsure": neither class
        score = ctx.get("provider_score")
        if isinstance(score, (int, float)) and score >= PROVIDER_SCORE_MIN:
            return "unknown"  # suspicious but not flagged: neither class
        return "clean"
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# 2.1 helpers: newsletters (E10)
# ---------------------------------------------------------------------------

# Hosts/domains of well-known bulk mail providers (ESPs). Matched as a
# suffix against the verified sending host, the envelope domain and the
# DKIM signing domains.
ESP_SUFFIXES: tuple[str, ...] = (
    "amazonses.com", "sendgrid.net", "mcsv.net", "mcdlv.net", "rsgsv.net",
    "mailchimpapp.net", "mandrillapp.com", "sparkpostmail.com", "sparkpostmail1.com",
    "mailgun.org", "mailgun.net", "mailjet.com", "sendinblue.com", "brevo.com",
    "klaviyomail.com", "hubspotemail.net", "createsend.com", "cmail19.com", "cmail20.com",
    "exacttarget.com", "ccsend.com", "constantcontact.com", "postmarkapp.com", "mtasv.net",
    "emarsys.net", "heyloyalty.com", "ubivox.com", "mailerlite.com", "mlsend.com",
)
_ESP_RE = re.compile(r"(?:^|\.)(?:sendib[a-z0-9]*\.com|cmail\d+\.com|bnc\d*\.mailjet\.com)$")


def _esp_name(host: str | None) -> str | None:
    h = _clean_host(host)
    if not h:
        return None
    for suf in ESP_SUFFIXES:
        if h == suf or h.endswith("." + suf):
            return suf
    if _ESP_RE.search(h):
        return h.rsplit(".", 2)[-2] + "." + h.rsplit(".", 1)[-1]
    return None


def known_esp(ctx: dict[str, Any] | None, dkim_domains: Iterable[str] = ()) -> str | None:
    """Name of the bulk mail provider that sent the mail, or None. Pure."""
    try:
        ctx = ctx or {}
        env = str(ctx.get("envelope_from") or "")
        for cand in (ctx.get("origin_host") or ctx.get("hostname"),
                     env.rpartition("@")[2] if "@" in env else None, *dkim_domains):
            name = _esp_name(cand)
            if name:
                return name
    except Exception:
        pass
    return None


def has_list_unsubscribe(raw: bytes | str | None) -> bool:
    """RFC 2369 List-Unsubscribe with a mailto: or https: target."""
    try:
        for name, value in parse_headers(raw):
            if name == "list-unsubscribe" and re.search(r"<\s*(?:mailto:|https?://)", value, re.I):
                return True
    except Exception:
        pass
    return False


def header_from_domain(raw: bytes | str | None) -> str | None:
    """Domain of the (first) From address, lower-case; None if unusable."""
    try:
        for name, value in parse_headers(raw):
            if name == "from":
                m = re.search(r"<([^<>@\s]+@([^<>@\s]+))>", value) or \
                    re.search(r"([^\s<>@\",;]+@([^\s<>@\",;]+))", value)
                return _clean_host(m.group(2)) if m else None
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# 2.2 (B7): the provider's authentication verdict at delivery time
# ---------------------------------------------------------------------------
#
# A mail scanned hours after delivery fails DKIM (expired signatures) and
# SPF (the sender's IPs changed) although it passed both when it arrived.
# The engine then turns rspamd's SPF/DMARC checks off for that scan and
# uses what the provider recorded at delivery instead - but only from an
# Authentication-Results header a trusted host wrote:
#
#   * SpamExperts (Scannet chains): the LAST A-R in SpamExperts' appended
#     block whose authserv-id is the node that received the mail (a sender
#     can put look-alike lines above it, never below), plus a later
#     "spamfilter.io" A-R of the same block;
#   * a provider host above the external hop (Scannet's amavis prepends
#     "scanN.mf.scannet.dk (amavis); dkim=pass ..."): the topmost one;
#   * a trusted forwarder (the owner's own MX): the first A-R with its
#     authserv-id directly below the Received it wrote, before the next
#     Received (it writes one for every mail it accepts).
#
# Anything else (e.g. Microsoft's A-R inside a third-party forward) is
# sender-controlled and ignored.

PROVIDER_AUTH_PASS_SCORE = -1.0
PROVIDER_AUTH_FAIL_SCORE = 2.0
# Distrust-only (0 points): the provider saw spf=fail/softfail without an
# aligned DKIM pass, or dmarc=fail for a p=none domain. In a fresh scan
# rspamd's own R_SPF_FAIL/SOFTFAIL makes an allow rule be ignored; an aged
# scan has SPF off, so this keeps that signal (filter.ALLOW_DISTRUST_SYMBOLS).
PROVIDER_AUTH_SPOOF_SCORE = 0.0
_AR_METHOD_RE = re.compile(r"^\s*(dkim|dmarc|spf|arc|iprev)\s*=\s*([A-Za-z]+)", re.IGNORECASE)
_AR_PROP_RE = re.compile(
    r"\b(header\.d|header\.i|header\.from|policy\.published-domain-policy|policy|p|action)"
    r"\s*=\s*\"?([^\s;()\"]+)", re.IGNORECASE)
_DMARC_POLICY_MAP = {"reject": "reject", "oreject": "reject", "quarantine": "quarantine",
                     "oquarantine": "quarantine", "none": "none"}


def _split_ar(value: str) -> list[str]:
    """Split an Authentication-Results value on ';' outside (comments) and
    "quoted strings"."""
    out: list[str] = []
    buf: list[str] = []
    depth = 0
    quoted = False
    for c in value or "":
        if quoted:
            buf.append(c)
            if c == '"':
                quoted = False
            continue
        if c == '"':
            quoted = True
        elif c == "(":
            depth += 1
        elif c == ")" and depth:
            depth -= 1
        elif c == ";" and depth == 0:
            out.append("".join(buf))
            buf = []
            continue
        buf.append(c)
    out.append("".join(buf))
    return [p for p in (s.strip() for s in out) if p]


def parse_auth_results(value: Any) -> dict[str, Any] | None:
    """{"authserv_id", "results": [(method, result, {prop: value})]} of one
    Authentication-Results value (RFC 8601, lenient). Pure; never raises."""
    try:
        parts = _split_ar(str(value or ""))
        if not parts:
            return None
        head = re.sub(r"\([^()]*\)", " ", parts[0]).split()
        authserv = _clean_host(head[0]) if head else None
        if authserv and "=" in authserv:
            authserv = None  # "dkim=pass" without an authserv-id
        results: list[tuple[str, str, dict[str, str]]] = []
        for seg in parts[1:] if authserv else parts:
            m = _AR_METHOD_RE.match(seg)
            if not m:
                continue
            props = {k.lower(): v.strip().lower() for k, v in _AR_PROP_RE.findall(seg)}
            results.append((m.group(1).lower(), m.group(2).lower(), props))
        return {"authserv_id": authserv, "results": results}
    except Exception:
        return None


def _from_domain(fields: list[tuple[str, str]]) -> str | None:
    for name, value in fields:
        if name == "from":
            m = re.search(r"<([^<>@\s]+@([^<>@\s]+))>", value) or \
                re.search(r"([^\s<>@\",;]+@([^\s<>@\",;]+))", value)
            return _clean_host(m.group(2)) if m else None
    return None


def _summarize_auth(lines: list[dict[str, Any]], source: str | None,
                    from_domain: str | None) -> dict[str, Any] | None:
    if not lines:
        return None
    dkim_pass: list[str] = []
    dkim_seen = dkim_bad = dkim_ok = False
    dmarc: str | None = None
    policy: str | None = None
    spf: str | None = None
    for line in lines:
        for method, result, props in line.get("results") or []:
            if method == "spf":
                if spf is None:
                    spf = result
            elif method == "dkim":
                dkim_seen = True
                if result == "pass":
                    dkim_ok = True
                    d = props.get("header.d") or (props.get("header.i") or "").rpartition("@")[2]
                    d = _clean_host(d)
                    if d and d not in dkim_pass:
                        dkim_pass.append(d)
                elif result in ("fail", "permerror", "policy"):
                    dkim_bad = True
            elif method == "dmarc" and dmarc is None:
                dmarc = result
                pol = (props.get("policy.published-domain-policy") or props.get("policy")
                       or props.get("p") or props.get("action"))
                policy = _DMARC_POLICY_MAP.get(pol or "")
    if not dkim_seen and dmarc is None and spf is None:
        return None
    return {
        "source": source,
        "dkim": "pass" if dkim_ok else ("fail" if dkim_bad else ("none" if dkim_seen else None)),
        "dkim_domains": dkim_pass[:10],
        "dmarc": dmarc,
        "dmarc_policy": policy,
        "spf": spf,
        "header_from": from_domain,
    }


def _provider_auth(fields: list[tuple[str, str]], trust: "_Trust", hops: list[dict[str, Any]],
                   roles: list[str], external: dict[str, Any] | None,
                   last_trusted: dict[str, Any] | None, via_se: bool,
                   se_block: list[tuple[str, str]]) -> dict[str, Any] | None:
    try:
        lines: list[dict[str, Any]] = []
        source: str | None = None
        if via_se:
            # The node that received the mail from outside (or from a
            # trusted forwarder): the deepest checked hop a node wrote.
            node = None
            for hop, role in zip(hops, roles):
                if role in ("internal", "forwarder", "external") and SPAMEXPERTS.host_match(hop.get("by")):
                    node = _clean_host(hop.get("by"))
            parsed = [parse_auth_results(v) for n, v in se_block if n == "authentication-results"]
            node_at = None
            for i, ar in enumerate(parsed):
                if ar and node and ar["authserv_id"] == node:
                    node_at = i
            if node_at is not None:
                lines.append(parsed[node_at])
                tail = [ar for ar in parsed[node_at + 1:] if ar and ar["authserv_id"] == "spamfilter.io"]
                if tail:
                    lines.append(tail[-1])
                source = node
        if last_trusted is not None or external is not None:
            boundary = external["index"] if external is not None else last_trusted["index"]
            for name, value in fields[:boundary]:
                if name != "authentication-results":
                    continue
                ar = parse_auth_results(value)
                if ar and ar["authserv_id"] and trust.host_trusted(ar["authserv_id"]):
                    lines.append(ar)
                    source = source or ar["authserv_id"]
                    break
        if external is not None and trust.forwarder_host(external.get("by")):
            fwd = _clean_host(external.get("by"))
            nxt = next((h["index"] for h in hops if h["index"] > external["index"]), len(fields))
            for name, value in fields[external["index"] + 1: nxt]:
                if name != "authentication-results":
                    continue
                ar = parse_auth_results(value)
                if ar and ar["authserv_id"] == fwd:
                    lines.append(ar)
                    source = source or fwd
                    break
        return _summarize_auth(lines, source, _from_domain(fields))
    except Exception:
        return None


def _auth_aligned(from_domain: str | None, dkim_domain: str | None) -> bool:
    f = _clean_host(from_domain)
    d = _clean_host(dkim_domain)
    if not f or not d:
        return False
    return f == d or f.endswith("." + d) or d.endswith("." + f)


def provider_auth_symbols(ctx: dict[str, Any] | None) -> list[dict[str, Any]]:
    """B7 pseudo-symbols from ctx["provider_auth"] (used for aged scans):
    TH_PROVIDER_AUTH_FAIL (+2) when the provider recorded dmarc=fail for a
    domain whose policy is not 'none' (or unknown); TH_PROVIDER_AUTH_SPOOF
    (0, distrust only) for dmarc=fail with p=none; else
    TH_PROVIDER_AUTH_PASS (-1) when DKIM passed and either DMARC passed or
    a passing signature is aligned with the From domain; else
    TH_PROVIDER_AUTH_SPOOF when the provider recorded spf=fail/softfail.
    Pure; never raises."""
    try:
        a = (ctx or {}).get("provider_auth")
        if not isinstance(a, dict):
            return []
        src = str(a.get("source") or "udbyder")[:120]
        if a.get("dmarc") == "fail":
            pol = a.get("dmarc_policy")
            if pol == "none":
                return [{"n": "TH_PROVIDER_AUTH_SPOOF", "s": PROVIDER_AUTH_SPOOF_SCORE,
                         "o": [src, "dmarc=fail", "p=none"]}]
            opts = [src, "dmarc=fail"] + ([f"p={pol}"] if pol else [])
            return [{"n": "TH_PROVIDER_AUTH_FAIL", "s": PROVIDER_AUTH_FAIL_SCORE, "o": opts}]
        if a.get("dkim") == "pass":
            doms = list(a.get("dkim_domains") or [])
            aligned = next((d for d in doms if _auth_aligned(a.get("header_from"), d)), None)
            if a.get("dmarc") == "pass" or aligned:
                how = "dmarc=pass" if a.get("dmarc") == "pass" else f"dkim={aligned}"
                return [{"n": "TH_PROVIDER_AUTH_PASS", "s": PROVIDER_AUTH_PASS_SCORE,
                         "o": [src, "dkim=pass", how]}]
        spf = a.get("spf")
        if spf in ("fail", "softfail") and a.get("dmarc") != "pass":
            return [{"n": "TH_PROVIDER_AUTH_SPOOF", "s": PROVIDER_AUTH_SPOOF_SCORE,
                     "o": [src, f"spf={spf}"]}]
    except Exception:
        pass
    return []


def provider_auth_known(ctx: dict[str, Any] | None) -> bool:
    """True when a trusted provider A-R recorded an SPF or DMARC result at
    delivery (pass or fail) - the aged-scan replacement for rspamd's own
    SPF/DMARC check. Pure; never raises."""
    try:
        a = (ctx or {}).get("provider_auth")
        return isinstance(a, dict) and (a.get("spf") is not None or a.get("dmarc") is not None)
    except Exception:
        return False
