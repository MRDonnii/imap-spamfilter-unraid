"""2.7 Mailsikkerhed (mailcheck.py): SPF parsing + lookup counting, DMARC
parsing incl. the external rua permission record, DKIM selectors learned
from rspamd symbols / DMARC reports and key sizes, DNSSEC (AD flag + the
control query), wildcards, blacklist answers (Spamhaus refusal codes),
TLS/certificate evaluation, a full run with fakes, regression detection
and alert de-duplication, scheduling. No real network: FakeDns and
FakeProber stand in for Unbound and the mail servers."""

from __future__ import annotations

import base64
import json
import sqlite3
import time
from types import SimpleNamespace

import pytest

import fakes_ui  # noqa: F401 - puts filter/ on sys.path

import mailcheck as mc  # noqa: E402

NOW = 1_793_000_000
DAY = 86400


class FakeDns(mc.Resolver):
    """{(name, TYPE): Answer | list[str]} - anything else is NXDOMAIN.
    ad=True marks every answer as DNSSEC-validated; cd={...} answers the
    same query with CD (checking disabled); fail_all=True: every query
    times out (offline)."""

    def __init__(self, zone=None, *, ad=False, fail=(), cd=None, fail_all=False):
        super().__init__()
        self.zone = {(k[0].lower().rstrip("."), k[1].upper()): v for k, v in (zone or {}).items()}
        self.cd_zone = {(k[0].lower().rstrip("."), k[1].upper()): v for k, v in (cd or {}).items()}
        self.ad = ad
        self.fail = set(fail)
        self.fail_all = fail_all
        self.asked: list[tuple[str, str]] = []

    def _ask_cd(self, name, rdtype):
        key = (name.lower().rstrip("."), rdtype)
        if key in self.cd_zone:
            v = self.cd_zone[key]
            return v if isinstance(v, mc.Answer) else mc.Answer("ok" if v else "nodata", records=list(v))
        return mc.Answer("error", error="SERVFAIL")

    def _ask(self, name, rdtype):
        key = (name.lower().rstrip("."), rdtype)
        self.asked.append(key)
        if self.fail_all or key[0] in self.fail:
            return mc.Answer("error", error="timeout")
        v = self.zone.get(key)
        if v is None:
            return mc.Answer("nxdomain", ad=self.ad)
        if isinstance(v, mc.Answer):
            return v
        return mc.Answer("ok" if v else "nodata", records=list(v), ad=self.ad)


def rsa_p(bits: int) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    k = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    der = k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


@pytest.fixture(scope="module")
def p2048():
    return rsa_p(2048)


@pytest.fixture(scope="module")
def p1024():
    return rsa_p(1024)


# ---------------------------------------------------------------- SPF
def test_parse_spf_terms_and_errors():
    s = mc.parse_spf("v=spf1 ip4:192.0.2.0/24 include:_spf.gigahost.dk mx a:mail.x.dk/28 ~all")
    assert not s.errors and s.all_qualifier == "~"
    assert ("+", "include", "_spf.gigahost.dk") in s.terms and ("+", "ip4", "192.0.2.0/24") in s.terms
    assert mc.parse_spf("v=spf1 ip4:999.1.1.1 -all").errors
    assert "ukendt mekanisme" in mc.parse_spf("v=spf1 includes:x.dk -all").errors[0]
    assert mc.parse_spf("v=spf1 redirect=a.dk redirect=b.dk").errors
    assert mc.parse_spf("v=spf1 -all exp=explain.x.dk").exp == "explain.x.dk"
    assert any("efter all" in n for n in mc.parse_spf("v=spf1 -all mx").notes)
    assert mc.is_spf("V=SPF1 -all") and not mc.is_spf("v=spf10 -all") and mc.is_senderid("spf2.0/pra -all")


def test_spf_lookup_count_expands_includes_recursively():
    zone = {("x.dk", "TXT"): ["v=spf1 include:a.x.dk include:b.x.dk mx -all"],
            ("a.x.dk", "TXT"): ["v=spf1 include:c.x.dk a ptr -all"],
            ("b.x.dk", "TXT"): ["v=spf1 exists:%{i}.e.x.dk ip4:192.0.2.1 -all"],
            ("c.x.dk", "TXT"): ["v=spf1 a mx -all"]}
    r = mc.spf_lookups("x.dk", FakeDns(zone))
    # x: 2 includes + mx = 3; a: include + a + ptr = 3; b: exists = 1; c: a + mx = 2
    assert r["lookups"] == 9 and not r["errors"]
    zone[("c.x.dk", "TXT")] = ["v=spf1 a mx a:1.x.dk a:2.x.dk -all"]
    assert mc.spf_lookups("x.dk", FakeDns(zone))["lookups"] == 11


def test_spf_include_without_record_loop_and_redirect():
    r = mc.spf_lookups("x.dk", FakeDns({("x.dk", "TXT"): ["v=spf1 include:gone.example -all"]}))
    assert r["lookups"] == 1 and any("har ingen SPF-post" in e for e in r["errors"]) and r["void"] == 1
    loop = {("x.dk", "TXT"): ["v=spf1 include:y.dk -all"], ("y.dk", "TXT"): ["v=spf1 include:x.dk -all"]}
    assert any("løkke" in e for e in mc.spf_lookups("x.dk", FakeDns(loop))["errors"])
    red = {("x.dk", "TXT"): ["v=spf1 redirect=_spf.p.dk"], ("_spf.p.dk", "TXT"): ["v=spf1 mx -all"]}
    assert mc.spf_lookups("x.dk", FakeDns(red))["lookups"] == 2
    deep = {("x.dk", "TXT"): ["v=spf1 include:a.x.dk -all"], ("a.x.dk", "TXT"): ["v=spf1 include:x.dk -all"]}
    errs = mc.spf_lookups("x.dk", FakeDns(deep))["errors"]
    assert len([e for e in errs if "løkke" in e]) == 1


def test_spf_shared_include_is_no_loop_and_counts_every_occurrence():
    """Two branches both including _spf.google.com (common: the provider's
    own record and a newsletter service's) are fine - and both count."""
    zone = {("x.dk", "TXT"): ["v=spf1 include:_spf.gigahost.dk include:mail.shop.example -all"],
            ("_spf.gigahost.dk", "TXT"): ["v=spf1 ip4:192.0.2.0/24 include:_spf.google.com -all"],
            ("mail.shop.example", "TXT"): ["v=spf1 include:_spf.google.com ~all"],
            ("_spf.google.com", "TXT"): ["v=spf1 include:_netblocks.google.com include:_netblocks2.google.com ~all"],
            ("_netblocks.google.com", "TXT"): ["v=spf1 ip4:198.51.100.0/24 ~all"],
            ("_netblocks2.google.com", "TXT"): ["v=spf1 ip6:2001:db8::/32 ~all"]}
    r = mc.spf_lookups("x.dk", FakeDns(zone))
    assert not r["errors"], r["errors"]
    # x: 2 includes; gigahost: 1 + google's 2; shop: 1 + google's 2 = 2 + 3 + 3
    assert r["lookups"] == 8 and r["void"] == 0
    assert r["nets_complete"] and "192.0.2.0/24" in r["nets"] and "198.51.100.0/24" in r["nets"]
    items = _by_key(mc.check_spf("x.dk", False, FakeDns(zone), None, None))
    assert items["x.dk:spf_lookups"]["status"] == "ok" and "8 af højst 10" in items["x.dk:spf_lookups"]["text"]
    # one more shared include tips it over the limit (each occurrence counts)
    zone[("x.dk", "TXT")] = ["v=spf1 include:_spf.gigahost.dk include:mail.shop.example include:_spf.google.com -all"]
    assert mc.spf_lookups("x.dk", FakeDns(zone))["lookups"] == 11
    assert _by_key(mc.check_spf("x.dk", False, FakeDns(zone), None, None))["x.dk:spf_lookups"]["status"] == "bad"


def test_spf_void_lookups():
    zone = {("x.dk", "TXT"): ["v=spf1 a:gone1.x.dk mx:gone2.x.dk include:gone3.x.dk -all"],
            ("gone2.x.dk", "MX"): []}
    r = mc.spf_lookups("x.dk", FakeDns(zone))
    assert r["lookups"] == 3 and r["void"] == 3
    items = _by_key(mc.check_spf("x.dk", False, FakeDns(zone), None, None))
    assert items["x.dk:spf_lookups"]["status"] == "bad"           # include without a record: permerror
    two = {("x.dk", "TXT"): ["v=spf1 a:gone1.x.dk a:gone2.x.dk a:mail.x.dk -all"], ("mail.x.dk", "A"): ["192.0.2.9"]}
    r = mc.spf_lookups("x.dk", FakeDns(two))
    assert r["void"] == 2 and "192.0.2.9/32" in r["nets"]
    assert _by_key(mc.check_spf("x.dk", False, FakeDns(two), None, None))["x.dk:spf_lookups"]["status"] == "ok"
    two[("x.dk", "TXT")] = ["v=spf1 a:gone1.x.dk a:gone2.x.dk exists:gone3.x.dk -all"]
    assert _by_key(mc.check_spf("x.dk", False, FakeDns(two), None, None))["x.dk:spf_lookups"]["status"] == "warn"
    # a timeout is not a void lookup
    t = mc.spf_lookups("x.dk", FakeDns({("x.dk", "TXT"): ["v=spf1 a:slow.x.dk -all"]}, fail={"slow.x.dk"}))
    assert t["void"] == 0 and not t["nets_complete"]


def _by_key(items):
    return {i["key"]: i for i in items}


def test_check_spf_statuses():
    def run(rec, no_mail=False, extra=None):
        zone = {("x.dk", "TXT"): rec if isinstance(rec, list) else [rec]}
        zone.update(extra or {})
        return _by_key(mc.check_spf("x.dk", no_mail, FakeDns(zone), "Gigahost", "Gigahost"))

    assert run("v=spf1 ip4:192.0.2.1 -all")["x.dk:spf"]["status"] == "ok"
    soft = run("v=spf1 ip4:192.0.2.1 ~all")["x.dk:spf"]
    assert soft["status"] == "warn" and "-all" in soft["fix"]
    assert run("v=spf1 +all")["x.dk:spf"]["status"] == "bad"
    two = run(["v=spf1 -all", "v=spf1 mx -all"])["x.dk:spf"]
    assert two["status"] == "bad" and "2 SPF-poster" in two["text"]
    missing = run(["google-site-verification=abc"])["x.dk:spf"]
    assert missing["status"] == "bad" and "Gigahost" in missing["fix"]
    sid = run(["v=spf1 mx -all", "spf2.0/pra mx -all"])
    assert sid["x.dk:spf_senderid"]["status"] == "info"
    many = run("v=spf1 " + " ".join(f"a:h{i}.x.dk" for i in range(11)) + " -all")["x.dk:spf_lookups"]
    assert many["status"] == "bad" and "11 DNS-opslag" in many["text"]
    # a domain that sends no mail: exactly v=spf1 -all
    assert run("v=spf1 -all", no_mail=True)["x.dk:spf"]["status"] == "ok"
    nm = run("v=spf1 mx -all", no_mail=True)["x.dk:spf"]
    assert nm["status"] == "warn" and "v=spf1 -all" in nm["fix"]
    assert mc.check_spf("x.dk", False, FakeDns(fail={"x.dk"}), None, None)[0]["status"] == "unknown"


# ---------------------------------------------------------------- DMARC
def test_parse_dmarc():
    tags, errors = mc.parse_dmarc("v=DMARC1; p=quarantine; pct=50; rua=mailto:a@x.dk,mailto:b@rep.example!10m")
    assert not errors and tags["p"] == "quarantine"
    assert mc.report_addresses(tags) == ["a@x.dk", "b@rep.example"]
    assert mc.parse_dmarc("v=DMARC1; p=maybe")[1]
    assert mc.parse_dmarc("v=DMARC1; rua=mailto:a@x.dk")[1] == ["p= mangler"]
    assert mc.parse_dmarc("p=none; v=DMARC1")[1]
    assert mc.parse_dmarc("v=DMARC1; p=none; pct=200")[1]


def test_check_dmarc_policy_rua_and_external_authorization():
    def run(rec, no_mail=False, extra=None, advice=None):
        zone = {("_dmarc.x.dk", "TXT"): [rec]} if rec else {}
        zone.update(extra or {})
        return _by_key(mc.check_dmarc("x.dk", no_mail, FakeDns(zone), rua_default="ole@bynet.example", advice=advice,
                                      dns_host="Gigahost"))

    r = run("v=DMARC1; p=none; rua=mailto:dmarc@x.dk", advice="Klar til p=quarantine")
    assert r["x.dk:dmarc"]["status"] == "warn" and "Klar til p=quarantine" in r["x.dk:dmarc"]["text"]
    assert "siden DMARC" in r["x.dk:dmarc"]["fix"] and r["x.dk:dmarc_rua"]["status"] == "ok"
    ext = run("v=DMARC1; p=reject; rua=mailto:ole@bynet.example")
    assert ext["x.dk:dmarc"]["status"] == "ok"
    assert ext["x.dk:dmarc_rua"]["status"] == "bad"
    assert "x.dk._report._dmarc.bynet.example" in ext["x.dk:dmarc_rua"]["fix"]
    ok = run("v=DMARC1; p=reject; rua=mailto:ole@bynet.example",
             extra={("x.dk._report._dmarc.bynet.example", "TXT"): ["v=DMARC1"]})
    assert ok["x.dk:dmarc_rua"]["status"] == "ok" and "har givet lov" in ok["x.dk:dmarc_rua"]["text"]
    sub = run("v=DMARC1; p=reject; rua=mailto:dmarc@reports.x.dk")   # same organisation: no record needed
    assert sub["x.dk:dmarc_rua"]["status"] == "ok"
    assert run("v=DMARC1; p=quarantine")["x.dk:dmarc_rua"]["status"] == "warn"
    none = run(None)["x.dk:dmarc"]
    assert none["status"] == "bad" and "rua=mailto:ole@bynet.example" in none["fix"]
    assert run("v=DMARC1; p=none", no_mail=True)["x.dk:dmarc"]["status"] == "warn"
    assert run("v=DMARC1; p=reject", no_mail=True)["x.dk:dmarc"]["status"] == "ok"
    assert "p=reject" in run(None, no_mail=True)["x.dk:dmarc"]["fix"]
    assert run("v=DMARC1; p=bogus")["x.dk:dmarc"]["status"] == "bad"


# ---------------------------------------------------------------- DKIM
def test_selectors_from_symbols():
    syms = json.dumps([{"n": "R_DKIM_ALLOW", "s": -0.2, "o": ["bynet.example:s=gh2024", "vexar.example:s=default"]},
                       {"n": "R_DKIM_REJECT", "s": 1.0, "o": ["molt.example:s=old"]},
                       {"n": "DKIM_TRACE", "s": 0, "o": ["bynet.example:+"]}, {"n": "R_SPF_ALLOW", "s": -0.2}])
    assert mc.selectors_from_symbols(syms) == [("bynet.example", "gh2024", "R_DKIM_ALLOW"),
                                                ("vexar.example", "default", "R_DKIM_ALLOW"),
                                                ("molt.example", "old", "R_DKIM_REJECT")]
    assert mc.selectors_from_symbols("not json") == []


def test_dkim_key_sizes(p1024, p2048):
    assert mc.dkim_key(f"v=DKIM1; k=rsa; p={p2048}")["bits"] == 2048
    # long keys are split into several TXT strings with spaces/newlines inside p=
    spaced = p1024[:100] + " " + p1024[100:]
    assert mc.dkim_key(f"v=DKIM1; p={spaced}")["bits"] == 1024
    assert mc.dkim_key("v=DKIM1; p=")["revoked"]
    assert mc.dkim_key("v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=")["bits"] == 256
    assert mc.dkim_key("google-site-verification=x") is None
    assert mc.dkim_key("v=DKIM1; p=!!!notbase64")["bits"] is None


def _messages_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE messages (account TEXT, message_id TEXT, first_seen INTEGER, received_at INTEGER, "
                 "sender TEXT, symbols TEXT, sender_auth TEXT, sender_ip TEXT, our_action TEXT, user_verdict TEXT)")
    return conn


def _msg(conn, i, sender, syms, *, ip="203.0.113.10", action="none", verdict=None, auth=None, age_days=1):
    conn.execute("INSERT INTO messages VALUES(?,?,?,?,?,?,?,?,?,?)",
                 ("molt", f"m{i}", NOW - age_days * DAY, NOW - age_days * DAY, sender, json.dumps(syms),
                  json.dumps(auth or {"dkim": []}), ip, action, verdict))


SPF_OK = {"n": "R_SPF_ALLOW", "s": -0.2, "o": ["+ip4:203.0.113.10"]}


def test_unsigned_own_mail_is_an_error_naming_the_provider(p2048):
    conn = _messages_db()
    for i in range(5):  # bynet.example via Gigahost: SPF passes, no signature
        _msg(conn, i, "ole@bynet.example", [SPF_OK])
    _msg(conn, 9, "ole@bynet.example", [], ip="198.51.100.66")                       # a spoof: neither SPF nor DKIM
    _msg(conn, 10, "ole@bynet.example", [SPF_OK], action="moved_to_junk")            # spam is never "own mail"
    _msg(conn, 11, "ole@bynet.example", [SPF_OK], age_days=40)                       # outside the window
    ev = mc.mail_evidence(conn, "bynet.example", now=NOW)
    assert ev["mails"] == 5 and ev["dkim"] == 0 and ev["ips"] == {"203.0.113.10": 5}
    items = _by_key(mc.check_dkim("bynet.example", False, FakeDns(), ev, [], "Gigahost", "Gigahost"))
    assert items["bynet.example:dkim"]["status"] == "bad"
    assert "Slå DKIM til hos Gigahost" in items["bynet.example:dkim"]["fix"]


def test_learned_selector_is_checked_and_missing_key_is_an_error(p2048):
    conn = _messages_db()
    syms = [SPF_OK, {"n": "R_DKIM_ALLOW", "s": -0.2, "o": ["molt.example:s=sc1"]}]
    for i in range(4):
        _msg(conn, i, "ole@molt.example", syms)
    _msg(conn, 5, "Inge <inge@molt.example>", [{"n": "R_DKIM_ALLOW", "s": -0.2, "o": ["molt.example:s=sc2"]}])
    ev = mc.mail_evidence(conn, "molt.example", now=NOW)
    assert ev["mails"] == 5 and ev["dkim"] == 5 and set(ev["selectors"]) == {"molt.example|sc1", "molt.example|sc2"}
    dns = FakeDns({("sc1._domainkey.molt.example", "TXT"): [f"v=DKIM1; k=rsa; p={p2048}"]})
    items = _by_key(mc.check_dkim("molt.example", False, dns, ev, ["extra"], "Scannet", None))
    assert items["molt.example:dkim"]["status"] == "ok" and "5 af 5" in items["molt.example:dkim"]["text"]
    assert items["molt.example:dkim:molt.example:sc1"]["status"] == "ok" and items["molt.example:dkim:molt.example:sc1"]["bits"] == 2048
    assert items["molt.example:dkim:molt.example:sc2"]["status"] == "bad"            # used in real mail, key missing
    assert items["molt.example:dkim:molt.example:extra"]["status"] == "warn"         # admin-added, not found


def test_weak_key_and_unaligned_signer(p1024):
    conn = _messages_db()
    for i in range(3):
        _msg(conn, i, "shop@gravisk.example", [SPF_OK, {"n": "R_DKIM_ALLOW", "s": -0.2, "o": ["vexar.example:s=default"]}],
             auth={"dkim": ["vexar.example"]})
    ev = mc.mail_evidence(conn, "gravisk.example", now=NOW)
    items = _by_key(mc.check_dkim("gravisk.example", False, FakeDns(), ev, [], "vexar.example", None))
    assert items["gravisk.example:dkim"]["status"] == "bad" and "vexar.example" in items["gravisk.example:dkim"]["text"]
    dns = FakeDns({("k1._domainkey.x.dk", "TXT"): [f"v=DKIM1; p={p1024}"]})
    weak = _by_key(mc.check_dkim("x.dk", False, dns, {"selectors": {"x.dk|k1": 1}}, [], None, None))
    assert weak["x.dk:dkim:x.dk:k1"]["status"] == "warn" and "2048" in weak["x.dk:dkim:x.dk:k1"]["text"]
    assert weak["x.dk:dkim"]["status"] == "info"                            # no mail seen: cannot tell


def test_dkim_from_dmarc_reports_and_no_mail_domain():
    conn = _messages_db()
    import dmarc
    from test_dmarc import feedback

    rep = dmarc.parse_report_bytes(feedback(domain="x.dk", begin=NOW - 2 * DAY,
                                            records=[("209.85.220.41", 40, "pass", "pass")]))
    assert rep.records[0].dkim_selector == "s1"
    dmarc.store(conn, "bynet", "r@x", rep, now=NOW)
    ev = mc.mail_evidence(conn, "x.dk", now=NOW)
    assert ev["dmarc_dkim"] == 40 and "x.dk|s1" in ev["selectors"] and ev["dmarc_ips"] == {"209.85.220.41": 40}
    assert _by_key(mc.check_dkim("x.dk", False, FakeDns(), ev, [], None, None))["x.dk:dkim"]["status"] == "ok"
    assert mc.check_dkim("example.org", True, FakeDns(), ev, [], None, None)[0]["status"] == "info"


# ---------------------------------------------------------------- DNSSEC, wildcard, MX
def test_dnssec_ad_flag_and_control_query():
    signed = FakeDns({("x.dk", "SOA"): ["ns. host. 1 2 3 4 5"], ("dk", "SOA"): ["a"]}, ad=True)
    assert mc.check_dnssec("x.dk", signed, "Gigahost")["status"] == "ok"
    zone = {("x.dk", "SOA"): mc.Answer("ok", ["soa"], ad=False), ("dk", "SOA"): mc.Answer("ok", ["soa"], ad=True)}
    unsigned = mc.check_dnssec("x.dk", FakeDns(zone), "Gigahost")
    assert unsigned["status"] == "warn" and "hos Gigahost" in unsigned["fix"]
    zone[("dk", "SOA")] = mc.Answer("ok", ["soa"], ad=False)                # resolver does not validate
    assert mc.check_dnssec("x.dk", FakeDns(zone), None)["status"] == "unknown"
    # SERVFAIL that goes away with CD (checking disabled): the signatures are broken
    bogus = FakeDns({("x.dk", "SOA"): mc.Answer("error", error="SERVFAIL")}, cd={("x.dk", "SOA"): ["soa"]})
    assert mc.check_dnssec("x.dk", bogus, None)["status"] == "bad"
    # SERVFAIL also with CD (a lame / unreachable name server): could not be tested
    lame = FakeDns({("x.dk", "SOA"): mc.Answer("error", error="SERVFAIL")})
    res = mc.check_dnssec("x.dk", lame, None)
    assert res["status"] == "unknown" and "kunne ikke slås op" in res["text"]


def test_wildcard_shadowing_is_info():
    cname = mc.Answer("nodata", cnames=["bynet.example"])
    zone = {("_sf-tok.bynet.example", "A"): mc.Answer("ok", ["192.0.2.80"], cnames=["bynet.example"]),
            ("_dmarc.bynet.example", "TXT"): cname, ("_sf-tok._domainkey.bynet.example", "TXT"): cname,
            ("_mta-sts.bynet.example", "TXT"): cname}
    wc = mc.check_wildcard("bynet.example", FakeDns(zone), token="tok")
    assert wc["status"] == "info" and set(wc["shadowed"]) == {"_dmarc", "_domainkey", "_mta-sts"}
    assert mc.check_wildcard("x.dk", FakeDns(), token="tok") is None


def test_mx_checks():
    zone = {("x.dk", "MX"): ["10 mx1.gigahost.dk", "20 mx2.gigahost.dk"], ("mx1.gigahost.dk", "A"): ["192.0.2.25"],
            ("25.2.0.192.in-addr.arpa", "PTR"): ["mx1.gigahost.dk"]}
    items, hosts = mc.check_mx("x.dk", False, FakeDns(zone), "Gigahost", None)
    k = _by_key(items)
    assert k["x.dk:mx"]["status"] == "ok" and k["x.dk:mx_resolve"]["status"] == "bad"
    assert "mx2.gigahost.dk" in k["x.dk:mx_resolve"]["text"] and k["x.dk:mx_ptr"]["status"] == "ok"
    assert [h["host"] for h in hosts] == ["mx1.gigahost.dk", "mx2.gigahost.dk"]
    assert mc.check_mx("x.dk", False, FakeDns({("x.dk", "MX"): []}), None, None)[0][0]["status"] == "bad"
    # A answered "no records", AAAA timed out: not proof of "no address"
    zone2 = {("x.dk", "MX"): ["10 mx1.gigahost.dk"], ("mx1.gigahost.dk", "A"): [],
             ("mx1.gigahost.dk", "AAAA"): mc.Answer("error", error="timeout")}
    k2 = _by_key(mc.check_mx("x.dk", False, FakeDns(zone2), "Gigahost", None)[0])
    assert k2["x.dk:mx_resolve"]["status"] == "unknown"
    assert mc.check_mx("example.org", True, FakeDns({("example.org", "MX"): ["0 ."]}), None, None)[0][0]["status"] == "ok"


# ---------------------------------------------------------------- blacklists
def test_blacklist_answer_interpretation():
    nx = mc.Answer("nxdomain")
    assert mc.interpret_dnsbl("zen.spamhaus.org", nx) == ("clean", "")
    st, d = mc.interpret_dnsbl("zen.spamhaus.org", mc.Answer("ok", ["127.0.0.2", "127.0.0.4"]))
    assert st == "listed" and d == "SBL, XBL"
    for code, why in (("127.255.255.254", "offentlig"), ("127.255.255.255", "for mange"),
                      ("127.255.255.252", "forkert")):
        st, d = mc.interpret_dnsbl("zen.spamhaus.org", mc.Answer("ok", [code]))
        assert st == "unknown" and "kunne ikke slås op" in d and why in d
    assert mc.interpret_dnsbl("bl.spamcop.net", mc.Answer("ok", ["127.0.0.2"]))[0] == "listed"
    assert mc.interpret_dnsbl("bl.spamcop.net", mc.Answer("ok", ["192.0.2.1"]))[0] == "unknown"  # NXDOMAIN hijack
    assert mc.interpret_dnsbl("bl.spamcop.net", mc.Answer("error", error="timeout"))[0] == "unknown"
    assert mc.dnsbl_name("192.0.2.25", "psbl.surriel.com") == "25.2.0.192.psbl.surriel.com"


def test_check_blacklists_rate_limited_and_listed():
    zone = {("10.113.0.203.zen.spamhaus.org", "A"): ["127.0.0.3"],
            ("11.113.0.203.zen.spamhaus.org", "A"): ["127.255.255.254"],
            ("10.113.0.203.in-addr.arpa", "PTR"): ["smtp.gigahost.dk"]}
    pauses: list[float] = []
    out = _by_key(mc.check_blacklists([{"ip": "203.0.113.10", "why": ["sender mail for bynet.example"]},
                                       {"ip": "203.0.113.11", "why": ["MX for x.dk"]}],
                                      FakeDns(zone), pause=pauses.append))
    assert len(pauses) == 2 * len(mc.DNSBL_ZONES) and all(p == mc.DNSBL_RATE_S for p in pauses)
    bad = out["bl:203.0.113.10"]
    assert bad["status"] == "bad" and "Spamhaus ZEN (CSS)" in bad["text"] and "Gigahost" in bad["fix"]
    assert out["bl:203.0.113.11"]["status"] == "ok" and "kunne ikke slås op" in out["bl:203.0.113.11"]["text"]


def test_blacklist_ips_only_public_ipv4():
    ev = {"bynet.example": {"ips": {"203.0.113.10": 3, "192.168.1.5": 9, "2001:db8::1": 1}, "dmarc_ips": {"8.8.4.4": 2}}}
    doms = [{"domain": "bynet.example", "mx_hosts": [{"host": "mx", "ips": ["1.1.1.1", "8.8.4.4"]}]}]
    ips = mc.blacklist_ips(ev, doms)
    # 203.0.113.0/24 is documentation space: not global
    assert [i["ip"] for i in ips] == ["8.8.4.4", "1.1.1.1"]
    assert ips[0]["sender"] and not ips[1]["sender"]
    assert ips[0]["why"] == ["sender mail for bynet.example (DMARC-rapport)", "MX for bynet.example"]


def test_blacklist_candidates_are_only_spf_passing_relays_of_the_domain():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE messages (account TEXT, message_id TEXT, first_seen INTEGER, received_at INTEGER, "
                 "sender TEXT, symbols TEXT, sender_auth TEXT, sender_ip TEXT, our_action TEXT, user_verdict TEXT, "
                 "envelope_from TEXT)")

    def m(i, ip, syms, env="ole@bynet.example"):
        conn.execute("INSERT INTO messages VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                     ("bynet", f"m{i}", NOW - DAY, NOW - DAY, "ole@bynet.example", json.dumps(syms),
                      json.dumps({"dkim": ["bynet.example"]}), ip, "none", None, env))

    dkim = {"n": "R_DKIM_ALLOW", "s": -0.2, "o": ["bynet.example:s=gh1"]}
    m(1, "46.183.139.10", [{"n": "R_SPF_ALLOW", "s": -0.2, "o": ["+ip4:46.183.139.0/24"]}, dkim])  # the relay
    m(2, "87.54.1.2", [dkim])                         # authenticated submission from home: SPF skipped, DKIM only
    m(3, "149.72.1.1", [{"n": "R_SPF_ALLOW", "s": -0.2, "o": ["+ip4:149.72.0.0/16"]}, dkim],
      env="bounces+123@em.sendgrid.net")              # SPF passed for the ESP's bounce domain
    m(4, "46.183.139.99", [{"n": "R_SPF_ALLOW", "s": -0.2, "o": ["+ip4:46.183.139.10"]}, dkim])  # option mismatch
    ev = mc.mail_evidence(conn, "bynet.example", now=NOW)
    assert ev["mails"] == 4 and ev["ips"] == {"46.183.139.10": 1}
    # the domain's own SPF tree must authorise it too (when fully expanded)
    doms = [{"domain": "bynet.example", "spf_nets": ["46.183.139.0/24"], "spf_complete": True, "mx_hosts": []}]
    assert [i["ip"] for i in mc.blacklist_ips({"bynet.example": ev}, doms)] == ["46.183.139.10"]
    assert mc.blacklist_ips({"bynet.example": ev}, doms)[0]["sender"] is True
    doms[0]["spf_nets"] = ["192.0.2.0/24"]
    assert mc.blacklist_ips({"bynet.example": ev}, doms) == []


def test_dmarc_report_sources_need_an_aligned_spf_pass():
    conn = _messages_db()
    import dmarc

    dmarc.ensure_schema(conn)
    rows = [("209.85.220.41", "pass", "x.dk", "pass", "x.dk"),        # SPF pass, aligned: the relay
            ("198.51.100.5", "fail", "x.dk", "pass", "x.dk"),         # DKIM only (e.g. forwarded)
            ("149.72.1.1", "pass", "em.sendgrid.net", "pass", "x.dk")]
    for ip, spf_res, spf_dom, dk_res, dk_dom in rows:
        conn.execute("INSERT INTO dmarc_records(report, domain, source_ip, count, dkim, spf, dmarc_pass, header_from, "
                     "dkim_domain, dkim_result, spf_domain, spf_result, dkim_selector, date_begin, date_end) "
                     "VALUES(1,'x.dk',?,5,'pass',?,1,'x.dk',?,?,?,?,'s1',?,?)",
                     (ip, spf_res, dk_dom, dk_res, spf_dom, spf_res, NOW - 2 * DAY, NOW - DAY))
    ev = mc.mail_evidence(conn, "x.dk", now=NOW)
    assert ev["dmarc_ips"] == {"209.85.220.41": 5}


def test_selectors_are_learned_only_from_passing_signatures_and_forgotten(p2048):
    conn = _messages_db()
    _msg(conn, 1, "ole@molt.example", [SPF_OK, {"n": "R_DKIM_ALLOW", "s": -0.2, "o": ["molt.example:s=good"]},
                                   {"n": "R_DKIM_REJECT", "s": 1, "o": ["molt.example:s=forged"]}])
    import dmarc

    dmarc.ensure_schema(conn)
    for sel, res in (("rep1", "pass"), ("repfail", "fail")):
        conn.execute("INSERT INTO dmarc_records(report, domain, source_ip, count, dmarc_pass, dkim_domain, "
                     "dkim_result, dkim_selector, date_begin, date_end) VALUES(1,'molt.example','192.0.2.1',3,1,'molt.example',"
                     "?,?,?,?)", (res, sel, NOW - 3 * DAY, NOW - 2 * DAY))
    ev = mc.mail_evidence(conn, "molt.example", now=NOW)
    assert set(ev["selectors"]) == {"molt.example|good", "molt.example|rep1"}
    assert ev["selector_seen"]["molt.example|good"] == NOW - DAY
    # remembered across runs, forgotten after 60 days
    mem = mc._new_memory({"molt.example": {"molt.example|old": NOW - 70 * DAY, "molt.example|older": NOW - 30 * DAY}},
                         {"molt.example": ev}, NOW)
    assert set(mem["molt.example"]) == {"molt.example|good", "molt.example|rep1"}          # this run's evidence wins
    ev2 = mc.mail_evidence(None, "molt.example", now=NOW)
    mc._merge_memory(ev2, {"molt.example|old": NOW - 70 * DAY, "molt.example|older": NOW - 30 * DAY}, NOW)
    assert set(ev2["selectors"]) == {"molt.example|older"}
    # a learned selector not seen for 30 days whose key is gone: rotated out, info
    items = _by_key(mc.check_dkim("molt.example", False, FakeDns(), ev2, [], "Scannet", None, now=NOW))
    assert items["molt.example:dkim:molt.example:older"]["status"] == "info"
    fresh = mc.mail_evidence(None, "molt.example", now=NOW)
    mc._merge_memory(fresh, {"molt.example|recent": NOW - 2 * DAY}, NOW)
    items = _by_key(mc.check_dkim("molt.example", False, FakeDns(), fresh, [], "Scannet", None, now=NOW))
    assert items["molt.example:dkim:molt.example:recent"]["status"] == "bad"


def test_selector_memory_persists_and_admin_selectors_stay(p2048):
    conn = _db()
    msgs = ("CREATE TABLE messages (account TEXT, message_id TEXT, first_seen INTEGER, received_at INTEGER, "
            "sender TEXT, symbols TEXT, sender_auth TEXT, sender_ip TEXT, our_action TEXT, user_verdict TEXT)")
    conn.execute(msgs)
    _msg(conn, 1, "ole@bynet.example", [SPF_OK, {"n": "R_DKIM_ALLOW", "s": -0.2, "o": ["bynet.example:s=gh1"]}], age_days=20)
    run(conn, full_zone(p2048))
    assert "bynet.example|gh1" in mc.load_selector_memory(conn)["bynet.example"]
    conn.execute("DELETE FROM messages")
    res = run(conn, full_zone(p2048), now=NOW + 35 * DAY)          # outside the 30-day window, still remembered
    keys = {c["key"] for c in res["domains"][0]["checks"]}
    assert "bynet.example:dkim:bynet.example:gh1" in keys
    res = run(conn, full_zone(p2048), now=NOW + 70 * DAY, selectors=("adm1",))   # forgotten; admin one stays
    keys = {c["key"] for c in res["domains"][0]["checks"]}
    assert "bynet.example:dkim:bynet.example:gh1" not in keys and "bynet.example:dkim:bynet.example:adm1" in keys
    assert "bynet.example" not in mc.load_selector_memory(conn)


def test_spamhaus_pbl_is_info_not_a_listing():
    st, d = mc.interpret_dnsbl("zen.spamhaus.org", mc.Answer("ok", ["127.0.0.10"]))
    assert st == "pbl"
    st, d = mc.interpret_dnsbl("zen.spamhaus.org", mc.Answer("ok", ["127.0.0.11", "127.0.0.2"]))
    assert st == "listed" and d == "SBL"
    zone = {("10.113.0.203.zen.spamhaus.org", "A"): ["127.0.0.11"]}
    out = mc.check_blacklists([{"ip": "203.0.113.10", "why": ["sender mail for bynet.example"], "sender": True}],
                              FakeDns(zone))
    assert out[0]["status"] == "info" and "dynamisk IP – normalt" in out[0]["text"]
    assert mc.interpret_dnsbl("bl.spamcop.net", mc.Answer("error", error="limit")) == ("unknown",
                                                                                      "ikke testet (grænse nået)")


def test_query_budget_scales_and_the_blacklist_step_keeps_its_reserve(p2048):
    conn = _db()
    _messages = ("CREATE TABLE messages (account TEXT, message_id TEXT, first_seen INTEGER, received_at INTEGER, "
                 "sender TEXT, symbols TEXT, sender_auth TEXT, sender_ip TEXT, our_action TEXT, user_verdict TEXT)")
    conn.execute(_messages)
    zone = full_zone(p2048)
    zone[("bynet.example", "TXT")] = ["v=spf1 include:_spf.gigahost.dk -all"]
    zone[("_spf.gigahost.dk", "TXT")] = ["v=spf1 ip4:8.8.4.0/24 -all"]
    _msg(conn, 1, "ole@bynet.example", [{"n": "R_SPF_ALLOW", "s": -0.2, "o": ["+ip4:8.8.4.0/24"]}], ip="8.8.4.4")
    dns = FakeDns(zone)
    res = mc.run_check(accounts=ACCS, conn=conn, resolver=dns, prober=good_prober, now=NOW, pause=lambda s: None,
                       wildcard_token="tok", max_queries=12)
    assert res["dns_limited"] > 0
    bl = _by_key(res["blacklists"])["bl:8.8.4.4"]
    assert bl["status"] == "ok" and all(z["state"] == "clean" for z in bl["zones"].values())
    assert any("grænse nået" in ln for ln in mc.summary_lines(res))
    big = mc.run_check(accounts=ACCS, conn=conn, resolver=FakeDns(zone), prober=good_prober, now=NOW,
                       pause=lambda s: None, wildcard_token="tok")
    assert big["dns_limited"] == 0
    assert FakeDns().max_queries == mc.MAX_DNS_QUERIES


def test_run_deadline_marks_the_rest_untested(p2048):
    res = mc.run_check(accounts=ACCS, conn=_db(), resolver=FakeDns(full_zone(p2048)), prober=good_prober, now=NOW,
                       pause=lambda s: None, wildcard_token="tok", deadline_s=0,
                       smtp={"host": "smtp.gigahost.dk", "port": 587, "security": "starttls"})
    assert res["timed_out"] and all(d["status"] == "unknown" for d in res["domains"])
    assert all(s["status"] == "unknown" and "tidsgrænsen" in s["text"] for s in res["servers"])


# ---------------------------------------------------------------- TLS servers
T_SMTP = {"role": "smtp", "host": "smtp.gigahost.dk", "port": 587, "mode": "smtp"}
T_MX = {"role": "mx", "host": "mx1.gigahost.dk", "port": 25, "mode": "smtp"}


def probe(**kw):
    base = dict(host="h", port=587, mode="smtp", ok=True, tls_version="TLSv1.3", verified=True,
                not_after=NOW + 60 * DAY)
    base.update(kw)
    return mc.Probe(**base)


def test_cert_expiry_and_tls_evaluation():
    ev = lambda p, t=T_SMTP, blocked=False: mc.evaluate_server(t, p, now=NOW, port25_blocked=blocked,  # noqa: E731
                                                                provider="Gigahost")
    good = ev(probe())
    assert good["status"] == "ok" and good["days"] == 60 and "TLS 1.3" in good["text"]
    assert ev(probe(not_after=NOW + 15 * DAY))["status"] == "warn"
    soon = ev(probe(not_after=NOW + 3 * DAY))
    assert soon["status"] == "bad" and "3 dage" in soon["text"] and "Gigahost" in soon["fix"]
    assert ev(probe(not_after=NOW - DAY, verified=False, verify_error="expired"))["status"] == "bad"
    assert ev(probe(tls_version="TLSv1.1"))["status"] == "bad"
    assert ev(probe(ok=False, error="protocol", detail="UNSUPPORTED_PROTOCOL"))["status"] == "bad"
    name = probe(verified=False, verify_error="hostname", names=["*.other.dk"])
    assert ev(name)["status"] == "bad" and ev(name, T_MX)["status"] == "warn"   # MX names are often generic
    assert ev(probe(ok=False, error="starttls", detail="no_starttls"))["status"] == "bad"
    assert ev(probe(ok=False, error="refused"))["status"] == "bad"


def test_port_25_blocked_is_not_an_error():
    targets = [T_MX, {"role": "mx", "host": "mx2.gigahost.dk", "port": 25, "mode": "smtp"}, T_SMTP]

    def prober(host, port, mode):
        return mc.Probe(host, port, mode, error="timeout") if port == 25 else probe(host=host, port=port)

    out = _by_key(mc.check_servers(targets, prober, now=NOW))
    mx = out["srv:mx:mx1.gigahost.dk:25"]
    assert mx["status"] == "unknown" and "port 25 blokeret" in mx["text"]
    assert out["srv:smtp:smtp.gigahost.dk:587"]["status"] == "ok"

    def one_down(host, port, mode):
        return mc.Probe(host, port, mode, error="timeout") if host == "mx2.gigahost.dk" else probe(host=host, port=port)

    out = _by_key(mc.check_servers(targets, one_down, now=NOW))
    assert out["srv:mx:mx2.gigahost.dk:25"]["status"] == "warn"


def test_server_targets_dedup_and_modes():
    accs = [SimpleNamespace(name="bynet", imap_host="imap.gigahost.dk", imap_port=993, ssl=True),
            SimpleNamespace(name="molt", imap_host="mail.scannet.dk", imap_port=993),
            SimpleNamespace(name="sofie", imap_host="mail.scannet.dk", imap_port=993)]
    doms = [{"domain": "molt.example", "mx_hosts": [{"host": "mail.scannet.dk", "ips": []}]}]
    t = mc.server_targets(doms, accs, {"host": "smtp.gigahost.dk", "port": 465, "security": "ssl"})
    keys = {(x["role"], x["host"], x["port"], x["mode"]) for x in t}
    assert keys == {("mx", "mail.scannet.dk", 25, "smtp"), ("smtp", "smtp.gigahost.dk", 465, "tls"),
                    ("imap", "imap.gigahost.dk", 993, "tls"), ("imap", "mail.scannet.dk", 993, "tls")}
    assert next(x for x in t if x["role"] == "imap" and x["host"] == "mail.scannet.dk")["for"] == ["molt", "sofie"]


def test_dnspython_adapter_reads_records_and_ad_flag():
    dns = pytest.importorskip("dns.message")
    import dns.flags
    import dns.rcode
    import dns.rrset

    seen = []

    def transport(q, server, port, timeout, tcp):
        seen.append((server, port, bool(q.flags & dns.flags.AD), q.ednsflags & dns.flags.DO))
        r = dns.message.make_response(q)
        name = q.question[0].name.to_text()
        if name.startswith("gone."):
            r.set_rcode(dns.rcode.NXDOMAIN)
            return r
        r.flags |= dns.flags.AD
        r.answer.append(dns.rrset.from_text(name, 300, "IN", "CNAME", "target.x.dk."))
        r.answer.append(dns.rrset.from_text("target.x.dk.", 300, "IN", "TXT", '"v=spf1 " "-all"'))
        return r

    res = mc.DnsPythonResolver("127.0.0.1", 5353, transport=transport)
    a = res.query("x.dk", "TXT")
    assert a.status == "ok" and a.records == ["v=spf1 -all"] and a.ad and a.cnames == ["target.x.dk"]
    assert res.query("gone.x.dk", "TXT").status == "nxdomain"
    assert res.query("x.dk", "TXT") is a and res.queries == 2      # cached
    assert seen[0][:3] == ("127.0.0.1", 5353, True) and seen[0][3]


def test_resolver_address_is_configurable(monkeypatch):
    monkeypatch.setenv("MAILCHECK_DNS_SERVER", "192.0.2.53")
    monkeypatch.setenv("MAILCHECK_DNS_PORT", "5300")
    r = mc.DnsPythonResolver()
    assert (r.server, r.port) == ("192.0.2.53", 5300)
    monkeypatch.delenv("MAILCHECK_DNS_SERVER")
    monkeypatch.delenv("MAILCHECK_DNS_PORT")
    monkeypatch.setenv("LOOKALIKE_DNS_SERVER", "127.0.0.1")
    monkeypatch.setenv("LOOKALIKE_DNS_PORT", "5353")
    r = mc.DnsPythonResolver()
    assert (r.server, r.port) == ("127.0.0.1", 5353)


def test_query_budget():
    r = FakeDns(zone={})
    r.max_queries = 2
    r.query("a.dk", "A")
    r.query("b.dk", "A")
    assert r.query("c.dk", "A").error == "limit"


# ---------------------------------------------------------------- settings + domains
def test_settings_and_domain_targets():
    s = mc.normalize_settings(None)
    assert s["domains"] == ["example.org"] and s["no_mail"] == ["example.org"]
    s = mc.normalize_settings({"domains": ["Ekstra.DK", "bad domain"], "no_mail": [], "skip": ["vexar.example"],
                               "selectors": {"bynet.example": ["gh1", "bad sel"], "x": ["y"]}})
    assert s == {"domains": ["ekstra.dk"], "no_mail": [], "skip": ["vexar.example"], "selectors": {"bynet.example": ["gh1"]}}
    accs = [SimpleNamespace(user="ole@bynet.example", owner_platform_domains=["vexar.example"],
                            webshop_domains=["gravisk.example", "pinsikbing.example"]),
            SimpleNamespace(user="ole@molt.example", owner_platform_domains=[], webshop_domains=[])]
    t = mc.domain_targets(accs, mc.normalize_settings({"skip": ["vexar.example"]}),
                          {"rua": "ole@bynet.example", "domains": ["example.org"]})
    assert [d["domain"] for d in t] == ["bynet.example", "molt.example", "gravisk.example", "pinsikbing.example", "example.org"]
    assert next(d for d in t if d["domain"] == "example.org")["no_mail"]
    assert next(d for d in t if d["domain"] == "bynet.example")["sources"] == ["postkasse", "dmarc"]


# ---------------------------------------------------------------- full run + regressions
def full_zone(p2048, *, dkim=True, spf_all="-all"):
    return {
        ("bynet.example", "MX"): ["10 mx1.gigahost.dk"], ("mx1.gigahost.dk", "A"): ["192.0.2.25"],
        ("bynet.example", "NS"): ["ns1.gigahost.dk"],
        ("bynet.example", "TXT"): [f"v=spf1 include:_spf.gigahost.dk {spf_all}"],
        ("_spf.gigahost.dk", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
        ("_dmarc.bynet.example", "TXT"): ["v=DMARC1; p=quarantine; rua=mailto:ole@bynet.example"],
        ("bynet.example", "SOA"): mc.Answer("ok", ["soa"], ad=True),
        **({("gh1._domainkey.bynet.example", "TXT"): [f"v=DKIM1; p={p2048}"]} if dkim else {}),
        ("example.org", "TXT"): ["v=spf1 -all"], ("_dmarc.example.org", "TXT"): ["v=DMARC1; p=reject"],
        ("example.org", "MX"): [],
        ("example.org", "NS"): ["kai.ns.cloudflare.com"], ("example.org", "SOA"): mc.Answer("ok", ["soa"], ad=True),
    }


ACCS = [SimpleNamespace(name="bynet", user="ole@bynet.example", imap_host="imap.gigahost.dk", imap_port=993,
                        owner_platform_domains=[], webshop_domains=[])]


def good_prober(host, port, mode):
    return probe(host=host, port=port, mode=mode)


class FakeEngine:
    def __init__(self):
        self.alerts = []

    def alert_once(self, conn, key, episode, subject, text):
        self.alerts.append((key, episode, subject, text))
        return True


def _db():
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.execute("CREATE TABLE settings_kv (key TEXT PRIMARY KEY, value TEXT)")
    conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, account TEXT, ts INTEGER, message_id TEXT, "
                 "event TEXT, detail TEXT)")
    return conn


def run(conn, zone, *, eng=None, prober=good_prober, now=NOW, selectors=("gh1",)):
    conn.execute("INSERT OR REPLACE INTO settings_kv VALUES('mailcheck', ?)",
                 (json.dumps({"selectors": {"bynet.example": list(selectors)}}),))
    return mc.run_and_record(eng, conn, ACCS, reason="schedule", resolver=FakeDns(zone), prober=prober, now=now,
                             pause=lambda s: None, wildcard_token="tok",
                             smtp={"host": "smtp.gigahost.dk", "port": 587, "security": "starttls"})


def test_full_run_is_stored_and_summarised(p2048):
    conn = _db()
    res = run(conn, full_zone(p2048))
    assert [d["domain"] for d in res["domains"]] == ["bynet.example", "example.org"]
    anna = res["domains"][0]
    assert anna["provider"] == "Gigahost" and anna["dns_host"] == "Gigahost"
    statuses = {c["key"]: c["status"] for c in anna["checks"]}
    assert statuses["bynet.example:spf"] == "ok" and statuses["bynet.example:dmarc"] == "ok"
    assert statuses["bynet.example:dkim:bynet.example:gh1"] == "ok" and statuses["bynet.example:dnssec"] == "ok"
    nm = {c["key"]: c["status"] for c in res["domains"][1]["checks"]}
    assert nm["example.org:spf"] == "ok" and nm["example.org:dmarc"] == "ok" and nm["example.org:mx"] == "ok"
    assert {s["key"] for s in res["servers"]} == {"srv:mx:mx1.gigahost.dk:25", "srv:smtp:smtp.gigahost.dk:587",
                                                  "srv:imap:imap.gigahost.dk:993"}
    stored = mc.load_run(conn)
    assert stored["id"] == res["id"] and stored["counts"] == res["counts"]
    assert mc.list_runs(conn)[0]["status"] == res["status"]
    s = mc.last_summary(conn, now=NOW + 60)
    assert s["age_s"] == 60 and s["errors"] == res["counts"]["bad"]
    assert conn.execute("SELECT event FROM events").fetchone()[0] == "mailcheck_done"
    assert any("bynet.example" in ln for ln in mc.summary_lines(res))


def test_regression_alerts_after_two_runs_once_and_not_on_flapping(p2048):
    conn, eng = _db(), FakeEngine()
    first = run(conn, full_zone(p2048, spf_all="~all"), eng=eng)       # baseline: ~all is a warning, no alert
    assert eng.alerts == [] and first["counts"]["warn"] >= 1
    run(conn, full_zone(p2048, spf_all="~all"), eng=eng, now=NOW + DAY)
    assert eng.alerts == []
    broken = full_zone(p2048, dkim=False, spf_all="~all")                 # key disappeared ...
    run(conn, broken, eng=eng, now=NOW + 2 * DAY)
    assert eng.alerts == []                                               # ... seen once: no alert yet
    run(conn, broken, eng=eng, now=NOW + 3 * DAY)                         # ... seen twice: alert
    assert len(eng.alerts) == 1
    key, _ep, subject, text = eng.alerts[0]
    assert key == "mailcheck" and "DKIM-nøgle (gh1)" in subject and "Sådan retter du" in text
    run(conn, broken, eng=eng, now=NOW + 4 * DAY)                         # still broken: de-duplicated
    assert len(eng.alerts) == 1
    run(conn, full_zone(p2048, spf_all="~all"), eng=eng, now=NOW + 5 * DAY)   # fixed
    run(conn, broken, eng=eng, now=NOW + 6 * DAY)                             # broken again ...
    run(conn, broken, eng=eng, now=NOW + 7 * DAY)
    assert len(eng.alerts) == 1                                           # ... flapping within a week: quiet
    prev = mc.previous_run(conn, mc.load_run(conn)["id"])
    run(conn, full_zone(p2048, spf_all="~all"), eng=eng, now=NOW + 8 * DAY)   # fixed
    run(conn, broken, eng=eng, now=NOW + 12 * DAY)
    run(conn, broken, eng=eng, now=NOW + 13 * DAY)                            # a week after the last alert
    assert len(eng.alerts) == 2
    assert prev is not None
    cur = mc.load_run(conn)
    diff = mc.diff_runs(mc.previous_run(conn, mc.load_run(conn, cur["id"] - 1)["id"]), mc.load_run(conn, cur["id"] - 1))
    assert diff[0]["direction"] == "worse" and diff[0]["key"] == "bynet.example:dkim:bynet.example:gh1"


def test_one_night_blip_never_alerts(p2048):
    conn, eng = _db(), FakeEngine()
    run(conn, full_zone(p2048), eng=eng)
    run(conn, full_zone(p2048, dkim=False), eng=eng, now=NOW + DAY)       # gone for one night
    run(conn, full_zone(p2048), eng=eng, now=NOW + 2 * DAY)
    run(conn, full_zone(p2048, dkim=False), eng=eng, now=NOW + 3 * DAY)
    run(conn, full_zone(p2048), eng=eng, now=NOW + 4 * DAY)
    assert eng.alerts == []


def test_unknown_between_two_bad_runs_still_confirms():
    def res(status):
        return {"servers": [mc.item("srv:imap:h:993", "h:993", status, "x")]}

    plan = mc.plan_alerts(res("ok"), {}, {}, now=NOW)
    plan = mc.plan_alerts(res("bad"), plan.known, plan.alerted, last=plan.last, recent=plan.recent, now=NOW + DAY)
    assert plan.alerts == []
    plan = mc.plan_alerts(res("unknown"), plan.known, plan.alerted, last=plan.last, recent=plan.recent,
                          now=NOW + 2 * DAY)
    plan = mc.plan_alerts(res("bad"), plan.known, plan.alerted, last=plan.last, recent=plan.recent, now=NOW + 3 * DAY)
    assert [i["key"] for i in plan.alerts] == ["srv:imap:h:993"]


def test_untested_never_counts_as_fixed(p2048):
    known = {"srv:mx:h:25": 2}
    alerted = {"srv:mx:h:25": 2}
    res = {"servers": [mc.item("srv:mx:h:25", "h:25", "unknown", "port 25 blokeret")]}
    plan = mc.plan_alerts(res, known, alerted)
    assert plan.alerts == [] and plan.known == known and plan.alerted == alerted
    res = {"servers": [mc.item("srv:mx:h:25", "h:25", "bad", "x")]}
    assert mc.plan_alerts(res, plan.known, plan.alerted).alerts == []          # still the same episode


def test_urgent_signals_alert_on_the_first_run():
    bl = mc.item("bl:198.51.100.7", "198.51.100.7", "bad", "Står på SpamCop", sender=True,
                 zones={"bl.spamcop.net": {"state": "listed", "detail": ""}})
    cert = mc.item("srv:imap:h:993", "h:993", "bad", "udløber om 3 dage", days=3)
    warn_cfg = mc.item("x.dk:spf", "SPF", "warn", "~all", domain="x.dk")
    mx_only = mc.item("bl:198.51.100.8", "198.51.100.8", "bad", "Står på PSBL", sender=False,
                      zones={"psbl.surriel.com": {"state": "listed", "detail": ""}})
    plan = mc.plan_alerts({"blacklists": [bl, mx_only], "servers": [cert], "domains": [{"checks": [warn_cfg]}]},
                          {}, {}, now=NOW)
    # config warnings: baseline; a listed MX-only address waits like any other finding
    assert {i["key"] for i in plan.alerts} == {"bl:198.51.100.7", "srv:imap:h:993"}
    # a NEW listing on another list while already listed alerts again
    bl2 = dict(bl, zones={"bl.spamcop.net": {"state": "listed"}, "psbl.surriel.com": {"state": "listed"}})
    p2 = mc.plan_alerts({"blacklists": [bl2]}, plan.known, plan.alerted, last=plan.last, now=NOW + DAY)
    assert [i["key"] for i in p2.alerts] == ["bl:198.51.100.7"]
    assert mc.plan_alerts({"blacklists": [bl2]}, p2.known, p2.alerted, last=p2.last, now=NOW + 2 * DAY).alerts == []
    # PBL only (dynamic range) is info, never a listing signal
    pbl = mc.item("bl:198.51.100.9", "198.51.100.9", "info", "PBL", sender=True,
                  zones={"zen.spamhaus.org": {"state": "pbl", "detail": "PBL"}})
    assert mc.plan_alerts({"blacklists": [pbl]}, {}, {}, now=NOW).alerts == []


class FailingEngine(FakeEngine):
    def __init__(self):
        super().__init__()
        self.fail = True

    def _mailer(self):
        return object()          # a mailer is configured ...

    def alert_once(self, conn, key, episode, subject, text):
        super().alert_once(conn, key, episode, subject, text)
        return not self.fail     # ... but the send failed


def test_alert_is_marked_only_after_a_successful_send(p2048):
    conn, eng = _db(), FailingEngine()
    run(conn, full_zone(p2048), eng=eng)
    broken = full_zone(p2048, dkim=False)
    run(conn, broken, eng=eng, now=NOW + DAY)
    run(conn, broken, eng=eng, now=NOW + 2 * DAY)
    assert len(eng.alerts) == 1                    # tried, failed
    run(conn, broken, eng=eng, now=NOW + 3 * DAY)
    assert len(eng.alerts) == 2                    # retried
    eng.fail = False
    run(conn, broken, eng=eng, now=NOW + 4 * DAY)
    assert len(eng.alerts) == 3                    # sent
    run(conn, broken, eng=eng, now=NOW + 5 * DAY)
    assert len(eng.alerts) == 3                    # told: de-duplicated


def test_failed_sends_are_given_up_after_the_retries(p2048):
    conn, eng = _db(), FailingEngine()
    run(conn, full_zone(p2048), eng=eng)
    broken = full_zone(p2048, dkim=False)
    for d in range(1, 8):
        run(conn, broken, eng=eng, now=NOW + d * DAY)
    assert len(eng.alerts) == mc.ALERT_MAX_RETRIES


def test_degraded_offline_run_is_unknown_and_never_alerts(p2048):
    conn, eng = _db(), FakeEngine()
    run(conn, full_zone(p2048), eng=eng)
    broken = full_zone(p2048, dkim=False)
    run(conn, broken, eng=eng, now=NOW + DAY)                       # seen once
    conn.execute("INSERT OR REPLACE INTO settings_kv VALUES('mailcheck', ?)",
                 (json.dumps({"selectors": {"bynet.example": ["gh1"]}}),))

    def offline_prober(host, port, mode):
        return mc.Probe(host, port, mode, error="timeout")

    res = mc.run_and_record(eng, conn, ACCS, reason="schedule", resolver=FakeDns(fail_all=True),
                            prober=offline_prober, now=NOW + 2 * DAY, pause=lambda s: None, wildcard_token="tok",
                            smtp={"host": "smtp.gigahost.dk", "port": 587, "security": "starttls"})
    assert res["degraded"] and res["status"] == "unknown" and res["counts"]["bad"] == 0
    assert res["counts"]["warn"] == 0 and eng.alerts == []
    assert all(s["status"] == "unknown" for s in res["servers"])
    assert mc.last_summary(conn, now=NOW + 2 * DAY)["status"] == "unknown"
    assert mc.diff_runs(mc.previous_run(conn, res["id"]), res) == []
    # the degraded run is not "the run before" for Siden sidst
    assert mc.previous_run(conn, res["id"] + 1)["id"] == res["id"] - 1
    # ... and changed no state: the next bad run is the second sighting
    run(conn, broken, eng=eng, now=NOW + 3 * DAY)
    assert len(eng.alerts) == 1


def test_mostly_failing_dns_degrades_the_run(p2048):
    zone = full_zone(p2048)
    dns = FakeDns(zone, fail={n for n, _t in zone} | {"_sf-tok.bynet.example", "_mta-sts.bynet.example", "_smtp._tls.bynet.example"})
    conn = _db()
    res = mc.run_and_record(None, conn, ACCS, reason="schedule", resolver=dns, prober=good_prober, now=NOW,
                            pause=lambda s: None, wildcard_token="tok")
    assert res["degraded"] and "DNS-opslag fejlede" in res["degraded"] and res["status"] == "unknown"


def test_offline_connect_errors_are_unknown_not_errors():
    targets = [{"role": "imap", "host": "imap.gigahost.dk", "port": 993, "mode": "tls"},
               {"role": "smtp", "host": "smtp.gigahost.dk", "port": 587, "mode": "smtp"},
               {"role": "mx", "host": "mx1.gigahost.dk", "port": 25, "mode": "smtp"}]
    out = mc.check_servers(targets, lambda h, p, m: mc.Probe(h, p, m, error="timeout"), now=NOW)
    assert {s["status"] for s in out} == {"unknown"}
    assert "internetforbindelsen" in out[0]["text"]
    # one server down while the others answer: a real error
    def one(h, p, m):
        return mc.Probe(h, p, m, error="refused") if h == "imap.gigahost.dk" else probe(host=h, port=p, mode=m)
    out = _by_key(mc.check_servers(targets, one, now=NOW))
    assert out["srv:imap:imap.gigahost.dk:993"]["status"] == "bad"


def test_without_engine_nothing_is_remembered(p2048):
    conn = _db()
    run(conn, full_zone(p2048))
    assert mc.state_get(conn, "levels") is None


def test_scheduling_and_request(p2048):
    conn = _db()
    mc.ensure_schema(conn)
    assert mc.due(conn, NOW, 5) == "schedule" and mc.due(conn, NOW, 14) is None
    assert mc.request_run(conn, "admin", now=NOW)["code"] == "ok"
    assert mc.request_run(conn, "admin", now=NOW)["code"] == "pending"
    assert mc.due(conn, NOW, 14) == "request" and mc.pending(conn, now=NOW)["requested"] == NOW
    assert mc.pending(conn, now=NOW + 3600)["stale"]
    run(conn, full_zone(p2048), now=NOW)
    assert mc.state_get(conn, "request") is None and mc.state_get(conn, "running_since") is None
    assert mc.due(conn, NOW + 3600, 5) is None                 # done tonight
    assert mc.due(conn, NOW + DAY, 5) == "schedule"


def test_manual_daytime_run_does_not_suppress_the_night(p2048):
    conn = _db()
    mc.ensure_schema(conn)
    res = mc.run_and_record(None, conn, ACCS, reason="request", resolver=FakeDns(full_zone(p2048)), prober=good_prober,
                            now=NOW, pause=lambda s: None, wildcard_token="tok")
    assert res is not None
    assert mc.due(conn, NOW + 15 * 3600, 5) == "schedule"          # 15 h later, at 05: the night still runs
    mc.run_and_record(None, conn, ACCS, reason="cli", resolver=FakeDns(full_zone(p2048)), prober=good_prober,
                      now=NOW + 15 * 3600 - 600, pause=lambda s: None, wildcard_token="tok")
    assert mc.due(conn, NOW + 15 * 3600, 5) == "schedule"          # also right after an sfctl run


def test_stale_running_since_never_blocks_tjek_nu():
    conn = _db()
    mc.ensure_schema(conn)
    mc.state_set(conn, "running_since", str(NOW - 2 * 3600), now=NOW)   # a run that crashed two hours ago
    assert mc.pending(conn, now=NOW)["running"] is None
    assert mc.request_run(conn, "admin", now=NOW)["code"] == "ok"
    mc.state_set(conn, "request", None)
    mc.state_set(conn, "running_since", str(NOW - 60), now=NOW)          # a live one
    assert mc.request_run(conn, "admin", now=NOW)["code"] == "running"
    mc.clear_stale(conn)                                                   # engine start-up
    assert mc.state_get(conn, "running_since") is None


def test_acknowledged_findings_are_info_do_not_alert_until_they_change(p2048):
    conn, eng = _db(), FakeEngine()
    run(conn, full_zone(p2048), eng=eng)
    broken = full_zone(p2048, dkim=False)
    res = run(conn, broken, eng=eng, now=NOW + DAY)
    it = next(i for i in mc.all_items(res) if i["key"] == "bynet.example:dkim:bynet.example:gh1")
    assert it["status"] == "warn"
    assert not mc.acknowledge(conn, res, it["key"], "wrong", "admin")
    assert mc.acknowledge(conn, res, it["key"], mc.fingerprint(it), "admin", now=NOW + DAY)
    eff = mc.effective(mc.load_run(conn), mc.load_acks(conn))
    e_it = next(i for i in mc.all_items(eff) if i["key"] == it["key"])
    assert e_it["status"] == "info" and e_it["acked"] and e_it["acked_status"] == "warn"
    assert eff["counts"]["warn"] == res["counts"]["warn"] - 1
    assert mc.last_summary(conn, now=NOW + DAY)["acked"] == 1
    run(conn, broken, eng=eng, now=NOW + 2 * DAY)
    run(conn, broken, eng=eng, now=NOW + 3 * DAY)
    assert eng.alerts == []                                   # acknowledged: never alerted
    assert it["key"] in mc.load_acks(conn)
    run(conn, full_zone(p2048), eng=eng, now=NOW + 4 * DAY)   # fixed: the acknowledgement is gone
    assert it["key"] not in mc.load_acks(conn)
    assert not mc.unacknowledge(conn, it["key"])
    # nothing is acknowledged automatically
    assert mc.load_acks(_db()) == {}


def test_fingerprint_ignores_numbers_but_not_status_or_wording():
    a = mc.item("srv:imap:h:993", "h:993", "warn", "Certifikatet udløber om 15 dage.")
    assert mc.fingerprint(a) == mc.fingerprint(dict(a, text="Certifikatet udløber om 14 dage."))
    assert mc.fingerprint(a) != mc.fingerprint(dict(a, status="bad"))
    assert mc.fingerprint(a) != mc.fingerprint(dict(a, text="Certifikatet er udløbet."))


def test_stop_aborts_without_storing(p2048):
    import threading

    conn = _db()
    stop = threading.Event()
    stop.set()
    assert mc.run_and_record(None, conn, ACCS, resolver=FakeDns(full_zone(p2048)), prober=good_prober,
                             stop=stop, now=NOW) is None
    assert mc.list_runs(conn) == [] and mc.state_get(conn, "running_since") is None


def test_runs_are_pruned(p2048):
    conn = _db()
    res = {"started_at": NOW, "finished_at": NOW, "domains": [], "servers": [], "blacklists": []}
    for _ in range(5):
        mc.store_run(conn, dict(res), keep=3)
    assert len(mc.list_runs(conn)) == 3


def test_tls_prober_against_a_closed_local_port():
    """The real prober on loopback only: nothing listens -> refused."""
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    p = mc.TlsProber(timeout=1, allow_private=True)("127.0.0.1", port, "smtp")
    assert p.error in ("refused", "unreachable") and not p.ok


def test_tls_prober_refuses_internal_addresses():
    """SSRF: never connect to loopback / private / link-local / CGNAT /
    multicast - also when a public-looking NAME resolves there."""
    for ip in ("127.0.0.1", "192.168.1.10", "192.168.1.2", "169.254.1.1", "100.64.0.1", "224.0.0.1", "::1",
               "fe80::1", "::ffff:192.168.1.1"):
        assert not mc.public_ip(ip), ip
    assert mc.public_ip("8.8.8.8") and mc.public_ip("2a00:1450::1")
    p = mc.TlsProber(timeout=1)("127.0.0.1", 25, "smtp")
    assert p.error == "internal" and not p.ok
    dns = FakeDns({("mail.evil.example", "A"): ["192.168.1.10"]})
    p = mc.TlsProber(timeout=1, resolver=dns)("mail.evil.example", 993, "tls")
    assert p.error == "internal" and p.detail == "192.168.1.10"
    assert ("mail.evil.example", "A") in dns.asked                  # resolved through OUR resolver
    t = {"role": "imap", "host": "mail.evil.example", "port": 993}
    item = mc.evaluate_server(t, p, now=NOW, port25_blocked=False)
    assert item["status"] == "unknown" and "intern adresse" in item["text"].lower()
    p = mc.TlsProber(timeout=1, resolver=FakeDns(fail={"slow.example"}))("slow.example", 993, "tls")
    assert p.error == "dns_fail"
    assert mc.evaluate_server(t, p, now=NOW, port25_blocked=False)["status"] == "unknown"


def _local_server(handler):
    import socket
    import threading

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)

    def serve():
        while True:
            try:
                c, _a = srv.accept()
            except OSError:
                return
            with c:
                try:
                    handler(c)
                except OSError:
                    pass

    threading.Thread(target=serve, daemon=True).start()
    return srv, srv.getsockname()[1]


def test_mx_rejecting_the_probe_is_unknown():
    srv, port = _local_server(lambda c: c.sendall(b"554 5.7.1 Your IP is listed (PBL)\r\n"))
    try:
        p = mc.TlsProber(timeout=2, allow_private=True)("127.0.0.1", port, "smtp")
    finally:
        srv.close()
    assert p.error == "rejected" and "554" in p.detail
    it = mc.evaluate_server(T_MX, p, now=NOW, port25_blocked=False)
    assert it["status"] == "unknown" and "afviste testforbindelsen" in it["text"] and "hjemme-IP" in it["text"]

    def ehlo_no(c):
        c.sendall(b"220 mx ESMTP\r\n")
        c.recv(200)
        c.sendall(b"550 go away\r\n")

    srv, port = _local_server(ehlo_no)
    try:
        p = mc.TlsProber(timeout=2, allow_private=True, helo="spam.bynet.example")("127.0.0.1", port, "smtp")
    finally:
        srv.close()
    assert p.error == "rejected" and "EHLO" in p.detail

    srv, port = _local_server(lambda c: c.close())        # connection closed / reset at once
    try:
        p = mc.TlsProber(timeout=2, allow_private=True)("127.0.0.1", port, "smtp")
    finally:
        srv.close()
    assert p.error == "rejected"
    assert mc.evaluate_server(T_MX, p, now=NOW, port25_blocked=False)["status"] == "unknown"


def test_probe_deadline_bounds_a_silent_or_dripping_server():
    import time as _t

    def drip(c):
        for _ in range(40):
            c.sendall(b"2")
            _t.sleep(0.1)

    for handler in (lambda c: _t.sleep(5), drip):
        srv, port = _local_server(handler)
        try:
            t0 = _t.monotonic()
            p = mc.TlsProber(timeout=10, allow_private=True, deadline_s=1.0)("127.0.0.1", port, "smtp")
            took = _t.monotonic() - t0
        finally:
            srv.close()
        assert p.error == "timeout" and took < 3, (p, took)


def test_helo_name(monkeypatch):
    conn = _db()
    monkeypatch.delenv("MAILCHECK_HELO", raising=False)
    monkeypatch.setattr(mc.socket, "getfqdn", lambda: "pc.local")
    assert mc.helo_name(conn) == mc.HELO_NAME
    monkeypatch.setattr(mc.socket, "getfqdn", lambda: "beast.bynet.example")
    assert mc.helo_name(conn) == "beast.bynet.example"
    conn.execute("INSERT INTO settings_kv VALUES('external_url', 'https://spam.bynet.example:8443')")
    assert mc.helo_name(conn) == "spam.bynet.example"
    monkeypatch.setenv("MAILCHECK_HELO", "mx-test.bynet.example")
    assert mc.helo_name(conn) == "mx-test.bynet.example"


def test_tls_prober_starttls_handshake_with_a_local_fake_server(tmp_path):
    """A loopback SMTP server with a self-signed certificate: STARTTLS
    works, the certificate is read (unverified retry), the name fails."""
    import datetime
    import socket
    import threading

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mx.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=5))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("mx.test")]), False).sign(key, hashes.SHA256()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
    ctx = __import__("ssl").SSLContext(__import__("ssl").PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]

    def serve():
        for _ in range(2):
            try:
                c, _a = srv.accept()
            except OSError:
                return
            with c:
                f = c.makefile("rb")
                c.sendall(b"220 mx.test ESMTP\r\n")
                f.readline()
                c.sendall(b"250-mx.test\r\n250 STARTTLS\r\n")
                f.readline()
                c.sendall(b"220 go ahead\r\n")
                try:
                    with ctx.wrap_socket(c, server_side=True) as t:
                        t.recv(100)
                except Exception:  # noqa: BLE001 - the verifying client aborts the first handshake
                    pass

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    # the NAME is resolved through our resolver, the connection goes to the
    # address, and the certificate is checked against the name (SNI)
    dns = FakeDns({("mx.test", "A"): ["127.0.0.1"]})
    p = mc.TlsProber(timeout=3, resolver=dns, allow_private=True)("mx.test", port, "smtp")
    srv.close()
    assert p.ok and not p.verified and p.verify_error == "untrusted"     # self-signed, but the name matches
    assert p.names == ["mx.test"] and p.tls_version.startswith("TLSv1.")
    item = mc.evaluate_server({"role": "mx", "host": "mx.test", "port": port}, p, now=int(time.time()),
                              port25_blocked=False)
    assert item["status"] == "bad" and item["days"] in (4, 5)   # < 7 days left wins over the MX name warning


def test_unsigned_mail_from_a_website_host_is_named():
    """2.7.1: molt.example's own mail is signed by Scannet, but the WordPress site sends as
    wordpress@molt.example through its web host unsigned - name that host, don't blame Scannet."""
    ev = {"mails": 1, "dkim": 0, "unsigned_ips": {"93.191.155.217": 1}}
    dns = FakeDns({("217.155.191.93.in-addr.arpa", "PTR"): ["smtp10.zitcom.dk."]})
    it = _by_key(mc.check_dkim("molt.example", False, dns, ev, [], "Scannet", None))["molt.example:dkim"]
    assert it["status"] == "bad"
    assert "smtp10.zitcom.dk (93.191.155.217)" in it["text"]
    assert "smtp10.zitcom.dk" in it["fix"] and "hos Scannet" not in it["fix"]
    # The provider's own relay keeps the old advice.
    ev2 = {"mails": 3, "dkim": 0, "unsigned_ips": {"46.183.139.177": 3}}
    dns2 = FakeDns({("177.139.183.46.in-addr.arpa", "PTR"): ["cph7.mailout.gigahost.dk."]})
    it2 = _by_key(mc.check_dkim("bynet.example", False, dns2, ev2, [], "Gigahost", "Gigahost"))["bynet.example:dkim"]
    assert "Slå DKIM til hos Gigahost" in it2["fix"] and "kom fra" not in it2["text"]
