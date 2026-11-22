"""B22 lookalike.py (pure parts): the explicit permutation set, the matcher
(homoglyph / IDN skeleton, TLD swaps, subdomain embedding), the mail
parsers, the minimal DNS client (canned packets + a loopback fake server)
and the registration watch (baseline vs. new records, errors, cap, rate
limit) against a fake resolver. No network: the only socket test talks to
a UDP/TCP server on 127.0.0.1 inside the test."""

from __future__ import annotations

import base64
import json
import socket
import sqlite3
import struct
import sys
import threading
from email.message import EmailMessage
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "filter"))
import lookalike as lk  # noqa: E402

PROTECTED = ["pinsikbing.dk", "gravisk.dk", "vexar.shop", "bynet.dk", "molt.dk"]


@pytest.fixture
def m():
    return lk.Matcher(PROTECTED)


# ----- permutations -------------------------------------------------------------------


def test_permutations_cover_every_required_kind():
    perms = dict(lk.permutations("pinsikbing.dk"))
    assert perms["pinsikbin.dk"] == lk.KIND_OMISSION
    assert perms["pinssikbing.dk"] == lk.KIND_REPETITION
    assert perms["pinsikibng.dk"] == lk.KIND_TRANSPOSITION
    assert perms["pinsukbing.dk"] == lk.KIND_KEYBOARD          # i -> u (neighbour)
    assert perms["p1nsikbing.dk"] == lk.KIND_HOMOGLYPH
    assert perms["pinsikb1ng.dk"] == lk.KIND_HOMOGLYPH
    assert perms["pin-sikbing.dk"] == lk.KIND_HYPHEN
    for tld in ("com", "net", "shop", "eu", "co", "info", "online", "store", "site"):
        assert perms[f"pinsikbing.{tld}"] == lk.KIND_TLD
    assert perms["pinsikbing.dk.com"] == lk.KIND_TLD
    assert perms["pinsikbing-dk.com"] == lk.KIND_TLD
    assert "pinsikbing.dk" not in perms
    assert all(not d.endswith(".pinsikbing.dk") for d in perms)


def test_permutations_danish_keyboard_neighbours():
    # p sits next to å, l next to æ and ø on a Danish keyboard.
    assert "å" in lk.KEYBOARD["p"] and "æ" in lk.KEYBOARD["l"] and "ø" in lk.KEYBOARD["æ"]
    perms = dict(lk.permutations("bynet.dk"))
    assert all(d.isascii() for d in perms)                     # IDN variants are punycode
    assert perms["bynet.com"] == lk.KIND_TLD


def test_short_labels_only_get_homoglyph_hyphen_and_tld_variants():
    perms = lk.permutations("molt.dk")
    kinds = {k for _d, k in perms}
    assert kinds <= {lk.KIND_HOMOGLYPH, lk.KIND_HYPHEN, lk.KIND_TLD}
    doms = {d for d, _k in perms}
    assert {"m0lt.dk", "mo1t.dk", "rnolt.dk", "mo-lt.dk", "molt.com", "molt.dk.com", "molt-dk.com"} <= doms
    assert "mol.dk" not in doms and "motl.dk" not in doms and "moolt.dk" not in doms


def test_permutations_never_hit_other_protected_domains():
    perms = lk.permutations("vexar.shop", exclude=["deal.shop"])
    assert "deal.shop" not in dict(perms)


def test_cyrillic_variants_only_where_the_registry_allows_them():
    # .dk allows æ, ø, å and some accents (keyboard neighbours of p), never Cyrillic
    assert not any("\u0400" <= c <= "\u04ff" for d, _k in lk.permutations("pinsikbing.dk")
                   for c in lk.to_unicode(d))
    idn = [d for d, _k in lk.permutations("vexar.shop") if d.startswith("xn--")]
    assert idn and all(lk.to_unicode(d).endswith(".shop") for d in idn)


def test_watch_candidate_count_is_bounded():
    total = sum(len(lk.permutations(p, exclude=[x for x in PROTECTED if x != p])) for p in PROTECTED)
    # ~300 names: three lookups each at most, 5/s -> a few minutes a week.
    assert 150 < total < 600


# ----- matcher ------------------------------------------------------------------------


@pytest.mark.parametrize("host,protected,kind", [
    ("pinslkbing.dk", "pinsikbing.dk", lk.KIND_HOMOGLYPH),
    ("mail.pinslkbing.dk", "pinsikbing.dk", lk.KIND_HOMOGLYPH),
    ("pinsikbng.dk", "pinsikbing.dk", lk.KIND_OMISSION),
    ("pinsikkbing.dk", "pinsikbing.dk", lk.KIND_REPETITION),
    ("pinsikibng.dk", "pinsikbing.dk", lk.KIND_TRANSPOSITION),
    ("pinsukbing.dk", "pinsikbing.dk", lk.KIND_KEYBOARD),
    ("pin-sikbing.dk", "pinsikbing.dk", lk.KIND_HYPHEN),
    ("pinsikbing.com", "pinsikbing.dk", lk.KIND_TLD),
    ("pinsikbing.dk.com", "pinsikbing.dk", lk.KIND_TLD),
    ("pinsikbing-dk.com", "pinsikbing.dk", lk.KIND_TLD),
    ("pinsikbingdk.com", "pinsikbing.dk", lk.KIND_TLD),
    ("pinsikbing.dk.evil.com", "pinsikbing.dk", lk.KIND_EMBED),
    ("login.pinsikbing-dk.evil.net", "pinsikbing.dk", lk.KIND_EMBED),
    ("grvaisk.dk", "gravisk.dk", lk.KIND_TRANSPOSITION),
    ("by-net.dk", "bynet.dk", lk.KIND_HYPHEN),
    ("bynet.com", "bynet.dk", lk.KIND_TLD),
    ("bynet-dk.com", "bynet.dk", lk.KIND_TLD),
    ("rnolt.dk", "molt.dk", lk.KIND_HOMOGLYPH),
    ("m0lt.dk", "molt.dk", lk.KIND_HOMOGLYPH),
    ("molt.online", "molt.dk", lk.KIND_TLD),
    ("vехar.shop", "vexar.shop", lk.KIND_HOMOGLYPH),   # Cyrillic е and х
])
def test_matcher_hits(m, host, protected, kind):
    hit = m.match(host)
    assert hit is not None and hit.protected == protected and hit.kind == kind


@pytest.mark.parametrize("host", [
    # 'vexar' vs 'vexaro' is one edit: an edit-distance matcher would flag it.
    "ikea.com", "ikea.dk", "ikea.shop", "vexaro.de", "vexars.de", "vexare.it",
    "moltkevej.dk", "molt.de", "mobil.dk", "dronning.dk", "sikring.dk", "dinbolig.dk", "jet.dk", "telenet.dk",
    "gmail.com", "example.org", "bynet.de",
])
def test_matcher_no_false_positives(m, host):
    assert m.match(host) is None


@pytest.mark.parametrize("host", [
    "pinsikbing.dk", "PINSIKBING.DK", "shop.pinsikbing.dk", "a.b.pinsikbing.dk", "mail.vexar.shop",
    "vexar.shop", "pinsikbing.vexar.shop", "pinsikbing.dk.vexar.shop", "bynet.dk", "smtp.bynet.dk", "molt.dk",
    "pinsikbing.dk.", "bounce.gravisk.dk",
])
def test_own_domains_and_subdomains_never_match(m, host):
    assert m.match(host) is None


def test_idn_homoglyphs_cyrillic_and_greek(m):
    cyr = "pіnsikbing.dk"                     # Cyrillic і
    hit = m.match(cyr)
    assert hit is not None and hit.kind == lk.KIND_HOMOGLYPH and hit.lookalike.startswith("xn--")
    assert m.match(lk.to_ascii(cyr)).lookalike == hit.lookalike      # punycode in, same answer
    assert m.match("grαvisk.dk").protected == "gravisk.dk"     # Greek omicron
    assert m.match("bynеt.dk").protected == "bynet.dk"          # Cyrillic е
    assert m.match("pinsikbíng.dk").kind == lk.KIND_HOMOGLYPH        # diacritic
    assert m.match("mølt.dk").protected == "molt.dk"            # ø looks like o


def test_skeleton_folds_confusables():
    assert lk.skeleton("pinsikbing") == lk.skeleton("p1nsikb1ng") == lk.skeleton("pin-sikbing")
    assert lk.skeleton("modern") == lk.skeleton("modem")             # rn -> m
    assert lk.skeleton("vvine") == lk.skeleton("wine")
    assert lk.skeleton("vexar") != lk.skeleton("vexaro")


def test_matcher_without_protected_domains_matches_nothing():
    assert lk.Matcher([]).match("pinslkbing.dk") is None


def test_protected_domains_defaults_and_mailboxes(monkeypatch):
    monkeypatch.setattr(lk, "DEFAULT_PROTECTED", ["pinsikbing.dk", "gravisk.dk", "vexar.shop"])  # site config
    assert lk.protected_domains(None, ["ole@bynet.dk", "inge@molt.dk"]) == \
        ["pinsikbing.dk", "gravisk.dk", "vexar.shop", "bynet.dk", "molt.dk"]
    assert lk.protected_domains([], ["ole@bynet.dk"]) == ["bynet.dk"]
    assert lk.protected_domains(["www.Bank.dk", "bank.dk"], [], ["molt.dk"]) == ["bank.dk", "molt.dk"]


def test_matcher_cache_returns_same_object():
    assert lk.matcher_for(["pinsikbing.dk", "molt.dk"]) is lk.matcher_for(["molt.dk", "pinsikbing.dk"][::-1][::-1])


# ----- mail parsing --------------------------------------------------------------------


def _mail(*, sender="kunde@pinslkbing.dk", reply_to=None, dkim=None, text=None, html=None, html_b64=False) -> bytes:
    msg = EmailMessage()
    msg["From"] = f"Pinsikbing <{sender}>"
    msg["To"] = "ole@bynet.dk"
    msg["Subject"] = "Ordre"
    msg["Message-ID"] = "<x@y>"
    if reply_to:
        msg["Reply-To"] = reply_to
    if dkim:
        msg["DKIM-Signature"] = f"v=1; a=rsa-sha256; d={dkim}; s=s1; b=abc"
    msg.set_content(text or "Hej")
    if html is not None:
        msg.add_alternative(html, subtype="html", cte="base64" if html_b64 else None)
    return msg.as_bytes()


def test_mail_fields_from_reply_to_dkim():
    f = lk.mail_fields(_mail(reply_to="Svar <betaling@gravlsk.dk>", dkim="Pinslkbing.DK"))
    assert f["from"] == ["pinslkbing.dk"] and f["reply_to"] == ["gravlsk.dk"] and f["dkim"] == ["pinslkbing.dk"]


def test_url_hosts_text_html_entities_userinfo_and_encodings():
    html = ('<a href="https://www.pinslkbing.dk/login">Log ind</a> <a href="http://pinsikbing.dk@evil.example:8080/x">'
            'x</a> <img src="//cdn.example.net/a.png"> <a href="https://pinsikbing&#46;dk&#46;evil&#46;com/">y</a>'
            '<a href="mailto:a@b.dk">mail</a> https://192.168.1.1/x')
    raw = _mail(text="Se www.gravlsk.dk eller https://xn--pnsikbing-v9h.dk/a?b=1", html=html, html_b64=True)
    hosts = lk.url_hosts(raw)
    assert "www.pinslkbing.dk" in hosts
    assert "evil.example" in hosts and "pinsikbing.dk" not in hosts   # userinfo is not the host
    assert "cdn.example.net" in hosts and "pinsikbing.dk.evil.com" in hosts
    assert "www.gravlsk.dk" in hosts and "xn--pnsikbing-v9h.dk" in hosts
    assert "192.168.1.1" not in hosts and "b.dk" not in hosts


def test_url_hosts_quoted_printable_and_limit():
    body = "".join(f"https://h{i}.example.dk/ " for i in range(300))
    msg = EmailMessage()
    msg["From"] = "a@b.dk"
    msg.set_content(body, cte="quoted-printable")
    assert len(lk.url_hosts(msg.as_bytes())) == lk.MAX_HOSTS
    assert lk.url_hosts(b"\x00\xff garbage") == []


def test_url_hosts_skip_attachments():
    msg = EmailMessage()
    msg["From"] = "a@b.dk"
    msg.set_content("Hej")
    msg.add_attachment("https://pinslkbing.dk/x", subtype="plain", filename="noter.txt")
    assert lk.url_hosts(msg.as_bytes()) == []


# ----- evaluate + exemptions ----------------------------------------------------------------


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    lk.ensure_schema(conn)
    conn.execute("CREATE TABLE sender_history (account TEXT, h TEXT, regdom TEXT, n_kept INTEGER, PRIMARY KEY(account, h))")
    conn.execute("CREATE TABLE known_contacts (account TEXT, h TEXT, domain TEXT, status TEXT, PRIMARY KEY(account, h))")
    return conn


def _names(ev):
    return {s["n"]: s for s in ev.symbols}


def test_evaluate_sender_fields(m):
    conn = _db()
    for kw, fld in ((dict(raw=_mail()), "from"),
                    (dict(raw=_mail(sender="a@ok.example", reply_to="b@pinsikbing-dk.com")), "reply_to"),
                    (dict(raw=_mail(sender="a@ok.example"), envelope_from="bounce@by-net.dk"), "envelope"),
                    (dict(raw=_mail(sender="a@ok.example", dkim="gravlsk.dk")), "dkim"),
                    (dict(raw=_mail(sender="a@ok.example"), dkim_verified=["mail.gravlsk.dk"]), "dkim")):
        ev = lk.evaluate(conn, m, **kw)
        sym = _names(ev)[lk.SYMBOL_DOMAIN]
        assert sym["s"] == lk.SCORE_DOMAIN and sym["o"][2] == fld, kw
        assert lk.SYMBOL_URL not in _names(ev)


def test_evaluate_url_only_is_score_only(m):
    ev = lk.evaluate(_db(), m, raw=_mail(sender="nyhed@shop.example", text="Klik https://pinslkbing.dk/konto"))
    syms = _names(ev)
    assert lk.SYMBOL_DOMAIN not in syms
    assert syms[lk.SYMBOL_URL]["s"] == lk.SCORE_URL and syms[lk.SYMBOL_URL]["o"] == ["pinslkbing.dk", "pinsikbing.dk", "url"]


def test_evaluate_clean_and_own_mail(m):
    assert lk.evaluate(_db(), m, raw=_mail(sender="ordre@pinsikbing.dk", text="https://pinsikbing.dk/ordre/1")).symbols == []
    assert lk.evaluate(_db(), m, raw=_mail(sender="a@ikea.com", text="https://ikea.com")).symbols == []


def test_exemptions(m):
    conn = _db()
    # ham history: 3 kept mails from the domain (any mailbox)
    conn.execute("INSERT INTO sender_history VALUES('bynet','h1','pinslkbing.dk',2)")
    conn.execute("INSERT INTO sender_history VALUES('molt','h2','pinslkbing.dk',1)")
    ev = lk.evaluate(conn, m, raw=_mail())
    assert [s["n"] for s in ev.symbols] == [lk.SYMBOL_ALLOWED] and ev.symbols[0]["o"][2] == "ham_history"
    assert ev.symbols[0]["s"] == 0.0
    # two kept mails are not enough
    conn.execute("DELETE FROM sender_history WHERE h='h2'")
    assert lk.SYMBOL_DOMAIN in _names(lk.evaluate(conn, m, raw=_mail()))
    # a known contact at the domain
    conn.execute("INSERT INTO known_contacts VALUES('bynet','k','salg.pinslkbing.dk','active')")
    assert _names(lk.evaluate(conn, m, raw=_mail()))[lk.SYMBOL_ALLOWED]["o"][2] == "contact"
    conn.execute("UPDATE known_contacts SET status='removed'")
    assert lk.SYMBOL_DOMAIN in _names(lk.evaluate(conn, m, raw=_mail()))
    # 'Ikke en efterligning' covers the domain and its subdomains
    conn.execute("INSERT INTO lookalike_allow(domain, created_at) VALUES('pinslkbing.dk', 1)")
    ev = lk.evaluate(conn, m, raw=_mail(sender="x@mail.pinslkbing.dk", text="https://www.pinslkbing.dk"))
    assert {s["n"] for s in ev.symbols} == {lk.SYMBOL_ALLOWED} and ev.symbols[0]["o"][2] == "allowed"


def test_exemption_signed_by_the_imitated_domain_only(m):
    conn = _db()
    # vexar.shop itself signs a mail from vexarshop.com -> the platform, not an imitation
    ev = lk.evaluate(conn, m, raw=_mail(sender="noreply@vexarshop.com"), dkim_verified=["vexar.shop"])
    assert lk.SYMBOL_DOMAIN not in _names(ev)
    # ... but an vexar.shop signature does not excuse a pinsikbing.dk lookalike (multi-tenant platform)
    ev = lk.evaluate(conn, m, raw=_mail(sender="ordre@pinslkbing.dk"), dkim_verified=["vexar.shop"])
    assert lk.SYMBOL_DOMAIN in _names(ev)
    # the verified path host (E8) of the imitated domain also counts
    ev = lk.evaluate(conn, m, raw=_mail(sender="a@pinsikbing.com"), origin_host="mx.pinsikbing.dk")
    assert lk.SYMBOL_DOMAIN not in _names(ev)


def test_threat_detail_text():
    syms = [{"n": "TH_LOOKALIKE_DOMAIN", "s": 6.0, "o": ["pinslkbing.dk", "pinsikbing.dk", "from"]}]
    assert lk.threat_detail(syms) == "pinslkbing.dk ligner pinsikbing.dk"
    assert lk.threat_detail([]) is None


def test_evaluate_without_db_and_without_protected():
    assert lk.evaluate(None, lk.Matcher(PROTECTED), raw=_mail()).symbols[0]["n"] == lk.SYMBOL_DOMAIN
    assert lk.evaluate(None, lk.Matcher([]), raw=_mail()).symbols == []


# ----- DNS client -------------------------------------------------------------------------


def _name(n: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\x00"


def _reply(qid, name, qtype, *, rcode=0, answers=(), tc=False, qname=None):
    flags = 0x8180 | rcode | (0x0200 if tc else 0)
    head = struct.pack(">HHHHHH", qid, flags, 1, len(answers), 0, 0)
    q = _name(qname or name) + struct.pack(">HH", qtype, 1)
    body = b""
    for rtype, rdata in answers:
        body += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 300, len(rdata)) + rdata
    return head + q + body


def test_build_and_parse_a_mx_ns():
    q = lk.build_query("pinslkbing.dk", lk.QTYPE_A, 0x1234)
    assert q[:2] == b"\x12\x34" and q[12:] == _name("pinslkbing.dk") + b"\x00\x01\x00\x01"
    a, tc = lk.parse_response(_reply(7, "x.dk", 1, answers=[(1, bytes([192, 0, 2, 7])), (5, _name("y.dk"))]),
                              7, "x.dk", 1)
    assert a.records == ["192.0.2.7"] and not tc and not a.nxdomain
    mx, _ = lk.parse_response(_reply(8, "x.dk", 15, answers=[(15, b"\x00\x0a" + _name("mx.x.dk"))]), 8, "x.dk", 15)
    assert mx.records == ["10 mx.x.dk"]
    # compression pointer inside rdata (to the question name)
    ns, _ = lk.parse_response(_reply(9, "x.dk", 2, answers=[(2, b"\x02ns\xc0\x0c")]), 9, "x.dk", 2)
    assert ns.records == ["ns.x.dk"]
    nx, _ = lk.parse_response(_reply(10, "x.dk", 2, rcode=3), 10, "x.dk", 2)
    assert nx.nxdomain and nx.records == []


@pytest.mark.parametrize("data,why", [
    (b"\x00\x01", "malformed"),
    (_reply(1, "x.dk", 1), "mismatch"),                        # wrong id (expect 2)
    (_reply(2, "x.dk", 1, qname="evil.dk"), "mismatch"),         # wrong question
    (_reply(2, "x.dk", 1, rcode=2), "servfail"),
    (_reply(2, "x.dk", 1, rcode=5), "refused"),
    (_reply(2, "x.dk", 1)[:-3], "malformed"),
])
def test_parse_rejects_bad_replies(data, why):
    with pytest.raises(lk.DnsError, match=why):
        lk.parse_response(data, 2, "x.dk", 1)


def test_parse_pointer_loop_is_malformed():
    data = struct.pack(">HHHHHH", 3, 0x8180, 0, 1, 0, 0) + b"\xc0\x0c" + b"\x00" * 10
    with pytest.raises(lk.DnsError):
        lk.parse_response(data, 3, "x.dk", 1)


def test_encode_name_rejects_invalid():
    with pytest.raises(lk.DnsError):
        lk.encode_name("bad name.dk")


class _FakeDnsServer:
    """UDP + TCP DNS stub on 127.0.0.1 (no network)."""

    def __init__(self, table):
        self.table = table          # (name, qtype) -> (rcode, answers, tc)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.port = self.udp.getsockname()[1]
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind(("127.0.0.1", self.port))
        self.tcp.listen(4)
        self.stop = False
        self.queries = []
        threading.Thread(target=self._udp_loop, daemon=True).start()
        threading.Thread(target=self._tcp_loop, daemon=True).start()

    def answer(self, data, *, tcp):
        qid = struct.unpack(">H", data[:2])[0]
        off, labels = 12, []
        while data[off]:
            ln = data[off]
            labels.append(data[off + 1:off + 1 + ln].decode())
            off += ln + 1
        qtype = struct.unpack(">H", data[off + 1:off + 3])[0]
        name = ".".join(labels)
        self.queries.append((name, qtype, tcp))
        rcode, answers, tc = self.table.get((name, qtype), (3, [], False))
        return _reply(qid, name, qtype, rcode=rcode, answers=answers, tc=tc and not tcp)

    def _udp_loop(self):
        while not self.stop:
            try:
                data, addr = self.udp.recvfrom(4096)
            except OSError:
                return
            self.udp.sendto(self.answer(data, tcp=False), addr)

    def _tcp_loop(self):
        while not self.stop:
            try:
                c, _ = self.tcp.accept()
            except OSError:
                return
            with c:
                n = struct.unpack(">H", c.recv(2))[0]
                data = c.recv(n)
                out = self.answer(data, tcp=True)
                c.sendall(struct.pack(">H", len(out)) + out)

    def close(self):
        self.stop = True
        self.udp.close()
        self.tcp.close()


def test_resolver_udp_tcp_fallback_and_nxdomain():
    srv = _FakeDnsServer({
        ("pinslkbing.dk", 2): (0, [(2, _name("ns1.host.example"))], False),
        ("pinslkbing.dk", 15): (0, [(15, b"\x00\x05" + _name("mx.host.example"))], True),   # truncated -> TCP
        ("pinslkbing.dk", 1): (0, [(1, bytes([198, 51, 100, 9]))], False),
        ("broken.dk", 1): (2, [], False),
    })
    try:
        r = lk.DnsResolver("127.0.0.1", port=srv.port, timeout=2.0, retries=0)
        assert r.query("pinslkbing.dk", "NS").records == ["ns1.host.example"]
        assert r.query("pinslkbing.dk", "MX").records == ["5 mx.host.example"]
        assert ("pinslkbing.dk", 15, True) in srv.queries
        assert r.query("pinslkbing.dk", "A").records == ["198.51.100.9"]
        assert r.query("ledigt.dk", "NS").nxdomain
        with pytest.raises(lk.DnsError, match="servfail"):
            r.query("broken.dk", "A")
    finally:
        srv.close()


def test_resolver_unreachable_name(monkeypatch):
    def boom(*a, **k):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(lk.socket, "getaddrinfo", boom)
    with pytest.raises(lk.DnsError, match="resolver unreachable"):
        lk.DnsResolver("spamfilter-unbound").query("x.dk", "A")


def test_resolver_timeout(monkeypatch):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))         # never answers
    try:
        r = lk.DnsResolver("127.0.0.1", port=s.getsockname()[1], timeout=0.2, retries=1)
        with pytest.raises(lk.DnsError, match="timeout"):
            r.query("x.dk", "A")
    finally:
        s.close()


# ----- rate limit + watch ----------------------------------------------------------------------


class Clock:
    def __init__(self):
        self.t = 1000.0
        self.slept = []

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.slept.append(s)
        self.t += s


def test_rate_limiter_never_exceeds_5_per_second():
    c = Clock()
    lim = lk.RateLimiter(50.0, clock=c, sleep=c.sleep)     # asked for 50/s: capped at 5/s
    stamps = []
    for _ in range(11):
        lim.wait()
        stamps.append(c.t)
    assert stamps[-1] - stamps[0] >= 2.0 - 1e-9
    assert all(b - a >= 0.2 - 1e-9 for a, b in zip(stamps, stamps[1:]))


class FakeResolver:
    def __init__(self, zones=None, errors=None):
        self.zones = zones or {}       # domain -> {"NS": [...], "MX": [...], "A": [...]}
        self.errors = errors or {}     # (domain, qtype) -> message
        self.calls = []

    def query(self, name, qtype):
        self.calls.append((name, qtype))
        if (name, qtype) in self.errors:
            raise lk.DnsError(self.errors[(name, qtype)])
        z = self.zones.get(name)
        if z is None:
            return lk.DnsAnswer(lk.RCODE_NXDOMAIN, [])
        return lk.DnsAnswer(0, list(z.get(qtype, [])))


def _watch_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    lk.ensure_schema(conn)
    return conn


def _run(conn, res, now, **kw):
    c = Clock()
    kw.setdefault("limiter", lk.RateLimiter(5.0, clock=c, sleep=c.sleep))
    return lk.run_watch(conn, ["pinsikbing.dk"], res, now=now, clock=lambda: now, **kw)


DAY = 86400


def test_watch_baseline_then_only_new_mx_or_a_alerts():
    conn = _watch_db()
    res = FakeResolver({"pinsikbing.com": {"NS": ["ns.x"], "A": ["192.0.2.1"]},
                        "pinslkbing.dk": {"NS": ["ns.x"]}})
    r1 = _run(conn, res, 1_000_000)
    assert r1.candidates > 50 and r1.checked == r1.candidates and r1.baseline == r1.candidates
    assert r1.new == []                                       # first run = baseline, even for registered ones
    # Unregistered names cost one lookup (NS -> NXDOMAIN).
    assert res.calls.count(("pinsikbing.org", "NS")) == 0
    assert len(res.calls) == r1.candidates + 2 * 2
    row = conn.execute("SELECT * FROM lookalike_watch WHERE domain='pinsikbing.com'").fetchone()
    assert row["registered"] == 1 and json.loads(row["a"]) == ["192.0.2.1"] and row["first_registered_at"]
    # A week later: pinslkbing.dk gets an MX, pinsikbing.com changes its A (no alert), p1nsikbing.dk appears.
    res.zones["pinslkbing.dk"]["MX"] = ["10 mx.evil.example"]
    res.zones["pinsikbing.com"]["A"] = ["192.0.2.99"]
    res.zones["p1nsikbing.dk"] = {"NS": ["ns.y"], "A": ["203.0.113.5"], "MX": ["0 mx.y"]}
    r2 = _run(conn, res, 1_000_000 + 7 * DAY)
    got = {n["domain"]: n["what"] for n in r2.new}
    assert got == {"pinslkbing.dk": ["mx"], "p1nsikbing.dk": ["mx", "a"]}
    assert r2.baseline == 0
    row = conn.execute("SELECT * FROM lookalike_watch WHERE domain='pinslkbing.dk'").fetchone()
    assert row["new_at"] == 1_000_000 + 7 * DAY and row["new_what"] == "mx" and row["alerted_at"] is None
    # Third run: nothing new (same records).
    assert _run(conn, res, 1_000_000 + 14 * DAY).new == []


def test_watch_skips_recently_checked_and_resumes_after_cap():
    conn = _watch_db()
    res = FakeResolver()
    r1 = _run(conn, res, 2_000_000, max_lookups=30)
    assert r1.capped and r1.checked == 28                     # 30 - 3 headroom, one NS lookup each
    r2 = _run(conn, res, 2_000_000 + 60, max_lookups=10_000)
    assert r2.checked == r1.candidates - r1.checked           # only the rest
    assert _run(conn, res, 2_000_000 + 120).checked == 0      # everything checked within 6 days


def test_watch_dns_errors_never_overwrite_or_alert():
    conn = _watch_db()
    res = FakeResolver({"pinslkbing.dk": {"NS": ["ns.x"], "MX": [], "A": []}})
    _run(conn, res, 3_000_000)
    res.errors[("pinslkbing.dk", "NS")] = "servfail"
    res.zones["pinslkbing.dk"]["MX"] = ["10 mx.evil"]
    r = _run(conn, res, 3_000_000 + 7 * DAY)
    assert r.errors == 1 and r.new == []
    row = conn.execute("SELECT * FROM lookalike_watch WHERE domain='pinslkbing.dk'").fetchone()
    assert json.loads(row["mx"]) == [] and row["errors"] == 1 and row["last_error"] == "servfail"
    assert row["checked_at"] == 3_000_000                      # retried next time
    del res.errors[("pinslkbing.dk", "NS")]
    r = _run(conn, res, 3_000_000 + 7 * DAY + 3600)
    assert [n["domain"] for n in r.new] == ["pinslkbing.dk"]


def test_watch_unknown_previous_state_is_not_new():
    conn = _watch_db()
    res = FakeResolver({"pinslkbing.dk": {"NS": ["ns.x"], "A": ["192.0.2.1"]}},
                       errors={("pinslkbing.dk", "MX"): "timeout"})
    _run(conn, res, 4_000_000)
    row = conn.execute("SELECT * FROM lookalike_watch WHERE domain='pinslkbing.dk'").fetchone()
    assert row["checked_at"] is None and row["mx"] is None    # MX failed: the whole domain retries


def test_watch_resolver_unreachable_stops_the_run():
    conn = _watch_db()

    class Down:
        def query(self, name, qtype):
            raise lk.DnsError("resolver unreachable")

    r = _run(conn, Down(), 5_000_000)
    assert r.error == "resolver unreachable" and r.checked == 0 and r.lookups == 1


def test_watch_allowed_domains_do_not_alert_and_stop_event():
    conn = _watch_db()
    res = FakeResolver({"pinslkbing.dk": {"NS": ["ns"]}})
    _run(conn, res, 6_000_000)
    conn.execute("INSERT INTO lookalike_allow(domain, created_at) VALUES('pinslkbing.dk', 1)")
    res.zones["pinslkbing.dk"]["MX"] = ["1 mx"]
    assert _run(conn, res, 6_000_000 + 7 * DAY).new == []
    ev = threading.Event()
    ev.set()
    r = _run(conn, res, 6_000_000 + 14 * DAY, stop=ev)
    assert r.stopped and r.checked == 0


def test_watch_rate_limit_is_applied_per_lookup():
    conn = _watch_db()
    c = Clock()
    res = FakeResolver()
    r = lk.run_watch(conn, ["molt.dk"], res, now=1, limiter=lk.RateLimiter(5.0, clock=c, sleep=c.sleep))
    assert r.lookups == len(res.calls) == r.candidates
    assert c.t - 1000.0 >= (r.lookups - 1) * 0.2 - 1e-6


def test_sync_candidates_prunes_removed_protected_domains():
    conn = _watch_db()
    lk.sync_candidates(conn, ["pinsikbing.dk", "molt.dk"], 1)
    assert conn.execute("SELECT COUNT(*) FROM lookalike_watch WHERE protected='molt.dk'").fetchone()[0] > 0
    lk.sync_candidates(conn, ["pinsikbing.dk"], 2)
    assert conn.execute("SELECT COUNT(*) FROM lookalike_watch WHERE protected='molt.dk'").fetchone()[0] == 0


def test_new_text_is_defanged():
    t = lk.new_text({"domain": "pinslkbing.dk", "protected": "pinsikbing.dk", "what": "mx,a"})
    assert t == "pinslkbing[.]dk (ligner pinsikbing.dk) har fået en mailserver og en hjemmeside"
    assert "fået en mailserver" in lk.new_text({"domain": "a.dk", "protected": "b.dk", "what": ["mx"]})


def test_ensure_schema_is_idempotent_inside_a_transaction():
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.execute("BEGIN")
    lk.ensure_schema(conn)
    lk.ensure_schema(conn)
    assert conn.in_transaction
    conn.execute("ROLLBACK")


def test_base64_import_is_used_for_fixtures():
    # (keeps the html_b64 fixture honest: the part really is base64 encoded)
    raw = _mail(html="<a href='https://pinslkbing.dk'>x</a>", html_b64=True).decode()
    assert base64.b64encode(b"<a href='https://pinslkbing.dk'>x</a>").decode()[:20] in raw


# ----- 2.3.6 review fixes -----------------------------------------------------------------


@pytest.mark.parametrize("body", [
    b"href=" + b" " * 200_000,
    b"href=\"" + b" " * 200_000,
    b"src =  '" + b"\t" * 200_000,
    b"href" + b" " * 200_000,
    b"href= " * 40_000,
])
@pytest.mark.parametrize("ctype", ["text/plain", "text/html"])
def test_url_hosts_is_linear_on_crafted_whitespace(body, ctype):
    """A long 'href=' + blank run without '//' used to backtrack
    quadratically (one mail pinned a scan thread for hours)."""
    import time as _t
    raw = b"From: a@b.example\r\nContent-Type: " + ctype.encode() + b"\r\n\r\n" + body
    t0 = _t.perf_counter()
    assert lk.url_hosts(raw) == []
    assert _t.perf_counter() - t0 < 0.5
    t0 = _t.perf_counter()
    lk.evaluate(_db(), lk.Matcher(PROTECTED), raw=raw)
    assert _t.perf_counter() - t0 < 1.0


def test_url_hosts_still_reads_spaced_href_forms():
    html = ('<a href = " https://pinslkbing.dk/a">x</a> <a HREF=\n\'//gravlsk.dk/b\'>y</a> '
            '<form action=  "http://by-net.dk/login">')
    hosts = lk.url_hosts(_mail(sender="a@ok.example", html=html))
    assert {"pinslkbing.dk", "gravlsk.dk", "by-net.dk"} <= set(hosts)


def test_shared_platform_history_and_contacts_do_not_exempt_a_tenant(m):
    """A free tenant 'pinsikbingdk.onmicrosoft.com' is not excused by
    history or contacts at OTHER tenants of the same platform."""
    conn = _db()
    raw = _mail(sender="ordre@pinsikbingdk.onmicrosoft.com")
    assert _names(lk.evaluate(conn, m, raw=raw))[lk.SYMBOL_DOMAIN]["o"][:2] == \
        ["pinsikbingdk.onmicrosoft.com", "pinsikbing.dk"]
    conn.execute("INSERT INTO sender_history VALUES('bynet','h1','onmicrosoft.com',3)")
    conn.execute("INSERT INTO known_contacts VALUES('bynet','k1','contoso.onmicrosoft.com','active')")
    ev = lk.evaluate(conn, m, raw=raw)
    assert lk.SYMBOL_DOMAIN in _names(ev) and lk.SYMBOL_ALLOWED not in _names(ev)
    # A link to a SharePoint tenant named after the shop, contact at another tenant.
    conn.execute("INSERT INTO known_contacts VALUES('molt','k2','firma.sharepoint.com','active')")
    ev = lk.evaluate(conn, m, raw=_mail(sender="nyhed@shop.example", text="https://pinsikbing-dk.sharepoint.com/x"))
    assert _names(ev)[lk.SYMBOL_URL]["o"][0] == "pinsikbing-dk.sharepoint.com"
    # A contact at exactly that tenant still counts (the owner chose to write to it).
    conn.execute("INSERT INTO known_contacts VALUES('molt','k3','pinsikbingdk.onmicrosoft.com','active')")
    assert _names(lk.evaluate(conn, m, raw=raw))[lk.SYMBOL_ALLOWED]["o"][2] == "contact"
    # A normal registrable lookalike keeps the registrable-domain rule.
    conn.execute("INSERT INTO known_contacts VALUES('molt','k4','salg.pinslkbing.dk','active')")
    assert _names(lk.evaluate(conn, m, raw=_mail()))[lk.SYMBOL_ALLOWED]["o"][2] == "contact"


def test_shared_platform_helper():
    mm = lk.Matcher(PROTECTED)
    assert lk.shared_platform(mm.match("pinsikbingdk.onmicrosoft.com"))
    assert lk.shared_platform(mm.match("pinsikbing.dk.evil.com"))
    assert not lk.shared_platform(mm.match("pinslkbing.dk"))
    assert not lk.shared_platform(mm.match("mail.pinslkbing.dk"))
    assert not lk.shared_platform(mm.match("pinsikbing.dk.com"))


@pytest.mark.parametrize("sender,dkim", [
    ("ole@bynet.dk", "bynetdk.onmicrosoft.com"),                       # M365 without custom DKIM
    ("info@pinsikbing.dk", "pinsikbing-dk.20230601.gappssmtp.com"),     # Google Workspace default
    ("inge@molt.dk", "molt-dk.20210112.gappssmtp.com"),
    ("ordre@shop.gravisk.dk", "graviskdk.onmicrosoft.com"),
])
@pytest.mark.parametrize("verified", [True, False])
def test_own_mail_with_provider_default_dkim_is_not_a_lookalike(m, sender, dkim, verified):
    kw = dict(dkim_verified=[dkim]) if verified else {}
    raw = _mail(sender=sender, dkim=None if verified else dkim)
    ev = lk.evaluate(_db(), m, raw=raw, origin_host="mail-x.outbound.protection.outlook.com", **kw)
    syms = _names(ev)
    assert lk.SYMBOL_DOMAIN not in syms
    assert syms[lk.SYMBOL_ALLOWED]["o"][2] == "provider" and syms[lk.SYMBOL_ALLOWED]["s"] == 0.0


def test_provider_exemption_needs_the_imitated_from_and_the_label_form(m):
    conn = _db()
    # A stranger's mail signed by a tenant named after the shop: still a lookalike.
    ev = lk.evaluate(conn, m, raw=_mail(sender="a@ok.example"), dkim_verified=["pinsikbingdk.onmicrosoft.com"])
    assert _names(ev)[lk.SYMBOL_DOMAIN]["o"][2] == "dkim"
    # From bynet.dk does not excuse a tenant imitating ANOTHER protected domain.
    ev = lk.evaluate(conn, m, raw=_mail(sender="ole@bynet.dk"), dkim_verified=["pinsikbingdk.onmicrosoft.com"])
    assert lk.SYMBOL_DOMAIN in _names(ev)
    # A typo-domain signature on own From is not a provider default: still counts.
    ev = lk.evaluate(conn, m, raw=_mail(sender="info@pinsikbing.dk"), dkim_verified=["pinslkbing.dk"])
    assert _names(ev)[lk.SYMBOL_DOMAIN]["o"][:3] == ["pinslkbing.dk", "pinsikbing.dk", "dkim"]


@pytest.mark.parametrize("host", ["bymet.dk", "ynet.dk", "bnet.dk", "byent.dk", "vexa.shop", "deal.shop",
                                  "vexr.shop", "vexxar.shop", "mol.dk"])
def test_short_labels_get_no_edit_variants(m, host):
    """bynet and vexar (5 letters) only get homoglyph, hyphen and TLD
    variants: ordinary Danish names one edit away are not flagged."""
    assert m.match(host) is None


def test_short_label_permutations():
    for dom in ("bynet.dk", "vexar.shop"):
        kinds = {k for _d, k in lk.permutations(dom)}
        assert kinds <= {lk.KIND_HOMOGLYPH, lk.KIND_HYPHEN, lk.KIND_TLD}, dom
    assert lk.MIN_EDIT_LABEL == 6
    assert dict(lk.permutations("gravisk.dk"))["gravsk.dk"] == lk.KIND_OMISSION   # 7 letters: full set


class _AllFail:
    def __init__(self, msg="timeout"):
        self.msg = msg
        self.calls = 0

    def query(self, name, qtype):
        self.calls += 1
        raise lk.DnsError(self.msg)


def test_watch_where_every_lookup_fails_is_a_failed_run():
    conn = _watch_db()
    res = _AllFail()
    r = _run(conn, res, 7_000_000)
    assert r.error == lk.WATCH_ERROR_DNS and r.checked == 0
    # Aborted after a run of failures instead of grinding through every name.
    assert r.errors == lk.WATCH_MAX_CONSECUTIVE_ERRORS and res.calls == lk.WATCH_MAX_CONSECUTIVE_ERRORS
    assert conn.execute("SELECT COUNT(*) FROM lookalike_watch WHERE checked_at IS NOT NULL").fetchone()[0] == 0


def test_watch_mostly_failing_run_is_failed_but_a_few_errors_are_not():
    conn = _watch_db()
    res = FakeResolver()
    lk.sync_candidates(conn, ["pinsikbing.dk"], 8_000_000)
    names = [r[0] for r in conn.execute("SELECT domain FROM lookalike_watch ORDER BY domain")]
    # Every second name fails (never 20 in a row): errors >= checked -> failed.
    for d in names[::2]:
        res.errors[(d, "NS")] = "servfail"
    r = _run(conn, res, 8_000_000)
    assert r.error == lk.WATCH_ERROR_DNS and r.checked == len(names) // 2
    # One lame name in a full run is a normal, complete run.
    conn2 = _watch_db()
    res2 = FakeResolver(errors={(names[0], "NS"): "servfail"})
    r2 = _run(conn2, res2, 8_000_000)
    assert r2.error is None and r2.errors == 1 and r2.checked == r2.candidates - 1
