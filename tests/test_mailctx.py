"""mailctx: Received-chain trust, rspamd scan headers, provider verdicts.

Fixtures in tests/fixtures/headers are anonymised copies of real Gigahost
and Scannet deliveries (plus a few synthetic variants on the same layout).
"""

import ipaddress
import random
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "filter"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import mailctx  # noqa: E402
from fakes_services import fixture, make_account  # noqa: E402

ACC = make_account(user="user@example-a.dk")


def ctx_of(name, acc=ACC):
    return mailctx.scan_context(fixture(name), acc)


def bonus_names(ctx):
    return [b["n"] for b in mailctx.provider_bonus(ctx)]


# ---------------------------------------------------------------------------
# Gigahost
# ---------------------------------------------------------------------------


def test_gigahost_normal_inbound():
    ctx = ctx_of("gigahost_inbound.eml")
    assert ctx["headers"] == {
        "Rcpt": "user@example-a.dk",
        "IP": "54.240.39.204",
        "Helo": "a39-204.smtp-out.amazonses.com",
        "Hostname": "a39-204.smtp-out.amazonses.com",
        # Gigahost's own SRS0 layer is undone: this is the real MAIL FROM.
        "From": "010001a1593c2a73-814d6018-9d39-4658-8176-fa3f74999361-000000@envelope.ollama.com",
    }
    assert ctx["authenticated"] is False
    assert ctx["provider"] == "gigahost"
    assert [h["role"] for h in ctx["hops"]] == ["internal", "external"]
    # Gigahost's milter appends X-Spam-Level at the END of the header block.
    assert ctx["provider_score"] == 1.0
    assert ctx["provider_flag"] is None
    assert ctx["provider_source"] == "trailing"
    assert mailctx.provider_bonus(ctx) == []
    assert mailctx.provider_verdict(ctx) == "clean"


def test_srs0_with_equals_in_local_part_and_esmtpsa_below_hop_ignored():
    ctx = ctx_of("gigahost_inbound_sparkpost.eml")
    assert ctx["envelope_from"] == "msprvs1=20752hMlC8P0H=bounces-7356@eu.sparkpostmail1.com"
    assert ctx["external_ip"] == "147.253.222.184"
    # The sender's own ESMTPSA hop sits below the external hop: not ours.
    assert ctx["authenticated"] is False
    assert "User" not in ctx["headers"]
    assert [h["role"] for h in ctx["hops"]] == ["internal", "external", "unchecked"]


def test_gigahost_authenticated_submission_chain():
    ctx = ctx_of("gigahost_submission.eml")
    roles = [h["role"] for h in ctx["hops"]]
    # mx3 <- cph1.mailout <- mailout [10.x] <- smtp.gigahost.dk (trusted by
    # its verified rDNS) <- local pickup <- ESMTPSA from a residential IP.
    assert roles == ["internal"] * 5 + ["external"]
    assert ctx["external_ip"] == "198.51.100.243"
    assert ctx["helo"] == "smtpclient.apple"
    assert ctx["hostname"] == "dsl-198-51-100-243.isp.example"
    assert ctx["authenticated"] is True
    assert ctx["headers"]["User"] == "user@example-c.dk"
    assert ctx["headers"]["From"] == "user@example-c.dk"
    assert ctx["headers"]["IP"] == "198.51.100.243"


def test_gigahost_junk_flag_and_unknown_rdns():
    ctx = ctx_of("gigahost_junk.eml")
    assert ctx["headers"]["IP"] == "160.119.66.35"
    assert "Hostname" not in ctx["headers"]  # Postfix said "unknown"
    assert ctx["hostname"] is None
    assert ctx["provider_flag"] is True
    assert ctx["provider_score"] == 10.0
    assert mailctx.provider_bonus(ctx) == [
        {"n": "TH_PROVIDER_SPAM", "s": 4.0, "o": ["gigahost", "score=10"]}]
    assert mailctx.provider_verdict(ctx) == "spam"


def test_srs1_forward_undoes_gigahost_layer_and_drops_envelope():
    ctx = ctx_of("gigahost_junk_srs1.eml")
    # Gigahost's SRS1 layer is undone -> the forwarder's SRS0 address, which
    # is what mail.vexar.example presented. That is a third-party forward, so
    # the envelope (and the Rcpt that is not in To/Cc) is not sent.
    assert ctx["envelope_from"] == "SRS0=6UXA=IF=lastchance.guru=user@mail.vexar.example"
    assert ctx["original_sender"] == "user@lastchance.guru"
    assert ctx["forwarded"] is True
    assert ctx["headers"]["From"] == "<>" and "Rcpt" not in ctx["headers"]
    assert ctx["external_ip"] == "203.0.113.109"
    assert ctx["authenticated"] is False  # ESMTPA hop is below the external hop
    assert ctx["provider_flag"] is True and ctx["provider_score"] == 12.0


def test_literal_helo_unknown_rdns_and_qmail_hop():
    ctx = ctx_of("gigahost_unknown_rdns.eml")
    assert ctx["headers"]["Helo"] == "[163.128.8.17]"
    assert ctx["headers"]["IP"] == "163.128.8.58"
    assert "Hostname" not in ctx["headers"]
    assert ctx["envelope_from"] == "user@example-a.dk"
    assert "TH_PROVIDER_SPAM" in bonus_names(ctx)


def test_gigahost_forged_spam_headers_below_external_hop_are_ignored():
    ctx = ctx_of("gigahost_forged_below.eml")
    assert ctx["external_ip"] == "203.0.113.25"
    assert ctx["provider_flag"] is None
    assert ctx["provider_score"] is None
    assert mailctx.provider_bonus(ctx) == []


def test_ipv6_external_hop():
    ctx = ctx_of("gigahost_ipv6.eml")
    assert ctx["headers"]["IP"] == "2a00:1450:4864:20::62f"
    assert ctx["headers"]["Hostname"] == "mail-ej1-x62f.google.com"


def test_gigahost_trailing_yes_without_matching_level_is_not_trusted():
    raw = fixture("gigahost_inbound.eml").replace(b"X-Spam-Level: *\n", b"X-Spam: Yes\n")
    ctx = mailctx.scan_context(raw, ACC)
    # An upstream forwarder can leave "X-Spam: Yes" at the end; Gigahost
    # itself always writes X-Spam-Level with it, so this one is ignored.
    assert ctx["provider_flag"] is None
    assert mailctx.provider_bonus(ctx) == []


# ---------------------------------------------------------------------------
# Scannet
# ---------------------------------------------------------------------------


def test_scannet_normal_inbound_with_amavis_hops():
    ctx = ctx_of("scannet_inbound.eml")
    assert [h["role"] for h in ctx["hops"]] == ["internal", "internal", "internal", "external"]
    assert ctx["headers"] == {
        "Rcpt": "user@example-a.dk",
        "IP": "52.17.18.180",
        "Helo": "m21.esputnik.com",
        "Hostname": "m21.esputnik.com",
        "From": "bounce+4-user=example-b.dk@news.ajax.systems",
    }
    assert ctx["provider"] == "scannet"
    assert ctx["provider_flag"] is False
    assert ctx["provider_score"] == pytest.approx(-0.101)
    assert ctx["provider_source"] == "above"
    assert mailctx.provider_verdict(ctx) == "clean"


def test_scannet_score_above_five_gives_score_bonus():
    ctx = ctx_of("scannet_provider_score.eml")
    assert ctx["external_ip"] == "62.173.146.164"
    assert ctx["authenticated"] is False  # spammer's ESMTPA below the hop
    assert mailctx.provider_bonus(ctx) == [
        {"n": "TH_PROVIDER_SCORE", "s": 2.0, "o": ["scannet", "score=6.338"]}]
    assert mailctx.provider_verdict(ctx) == "unknown"


def test_scannet_junk_flag_yes_and_private_ips_below_hop_ignored():
    ctx = ctx_of("scannet_junk.eml")
    assert ctx["external_ip"] == "150.242.228.48"
    assert ctx["provider_flag"] is True
    assert ctx["provider_score"] == pytest.approx(8.007)
    assert bonus_names(ctx) == ["TH_PROVIDER_SPAM"]
    assert ctx["hops"][4]["role"] == "unchecked"  # 172.16.x below the hop


def test_scannet_forwarder_spam_headers_below_hop_ignored():
    ctx = ctx_of("scannet_forwarded_forged.eml")
    # The forwarder's own "X-Spam: Yes" (appended below the external hop)
    # must not count; Scannet's verdict above the hop says NO / 4.85.
    assert ctx["provider_flag"] is False
    assert ctx["provider_score"] == pytest.approx(4.85)
    assert mailctx.provider_bonus(ctx) == []
    # A third-party forwarder's SRS is NOT undone (it is the external hop),
    # but it marks the mail as forwarded: no envelope sender for rspamd.
    assert ctx["envelope_from"] == "SRS0=N7BF=IH=gazeta.ie=user@mail.vexar.example"
    assert ctx["forwarded"] is True and ctx["headers"]["From"] == "<>"
    assert ctx["original_sender"] == "user@gazeta.ie"
    assert ctx["headers"]["IP"] == "203.0.113.109"


def test_scannet_forged_spam_headers_below_hop_ignored():
    ctx = ctx_of("scannet_forged_below.eml")
    assert ctx["external_ip"] == "203.0.113.80"
    assert ctx["provider_flag"] is None and ctx["provider_score"] is None
    assert mailctx.provider_bonus(ctx) == []


# ---------------------------------------------------------------------------
# Degenerate input
# ---------------------------------------------------------------------------


def test_missing_received_falls_back_to_rcpt_only():
    ctx = ctx_of("missing_received.eml")
    assert ctx["headers"] == {"Rcpt": "user@example-a.dk"}
    assert ctx["trusted_chain"] is False
    # Spam headers without any provider hop are not trusted either.
    assert ctx["provider_flag"] is None
    assert mailctx.provider_bonus(ctx) == []
    assert mailctx.provider_verdict(ctx) == "unknown"


def test_untrusted_top_hop_trusts_nothing():
    raw = (b"Return-Path: <x@spam.example>\n"
           b"Received: from evil (evil [198.51.100.9]) by mx.attacker.example with ESMTPSA;"
           b" Tue, 20 Oct 2026 10:00:00 +0000\n"
           b"X-Spam-Flag: YES\nSubject: x\n\nbody\n")
    ctx = mailctx.scan_context(raw, ACC)
    assert ctx["headers"] == {"Rcpt": "user@example-a.dk"}
    assert ctx["authenticated"] is False
    assert ctx["hops"][0]["role"] == "untrusted"


@pytest.mark.parametrize("name", sorted(p.name for p in
                                        (Path(__file__).parent / "fixtures" / "headers").glob("*.eml")))
def test_crlf_and_header_only_input_give_same_context(name):
    raw = fixture(name)
    base = mailctx.scan_context(raw, ACC)
    crlf = mailctx.scan_context(raw.replace(b"\n", b"\r\n"), ACC)
    header_only = mailctx.scan_context(raw.split(b"\n\n", 1)[0] + b"\n\n", ACC)
    assert crlf == base
    assert header_only == base
    if not base["forwarded"]:
        assert base["headers"]["Rcpt"] == "user@example-a.dk"


@pytest.mark.parametrize("raw", [
    None, b"", b"\n\n\n", "a string: value\n", b"\x00\xff" * 4000,
    b"Received: (((((((\n", b"Received: from\n", b"Received: by\n",
    b"Received: from [999.1.1.1] (unknown [::ffff:zz]) by mx1.gigahost.dk\n",
    b"Return-Path: <SRS0=>\nReceived: from x ([1.2.3.4]) by mx1.gigahost.dk with ESMTPSA\n",
    b"Received: " + b"(" * 5000 + b"\n",
    b"X-Spam-Status: Yes, score=abc\nX-Spam-Score: nan-ish\n",
])
def test_garbage_never_raises_and_keeps_rcpt(raw):
    ctx = mailctx.scan_context(raw, ACC)
    assert ctx["headers"]["Rcpt"] == "user@example-a.dk"
    assert isinstance(mailctx.provider_bonus(ctx), list)


def test_random_bytes_fuzz_never_raises():
    rnd = random.Random(1234)
    base = fixture("scannet_inbound.eml")
    for _ in range(300):
        buf = bytearray(base)
        for _ in range(rnd.randint(1, 40)):
            buf[rnd.randrange(len(buf))] = rnd.randrange(256)
        ctx = mailctx.scan_context(bytes(buf), ACC)
        assert "Rcpt" in ctx["headers"]


def test_header_value_sanitising_blocks_injection():
    acc = make_account(user="user@example-a.dk\r\nX-Evil: 1")
    raw = fixture("gigahost_inbound.eml").replace(
        b"from a39-204.smtp-out.amazonses.com (", "from hélo.example (".encode(), 1)
    ctx = mailctx.scan_context(raw, acc)
    assert "Rcpt" not in ctx["headers"]          # unsafe value dropped, not mangled
    assert "Helo" not in ctx["headers"]          # non-ASCII HELO dropped
    assert ctx["headers"]["IP"] == "54.240.39.204"


def test_account_without_new_fields_works():
    acc = SimpleNamespace(user="user@example-b.dk")  # pre-2.0 Account shape
    ctx = mailctx.scan_context(fixture("scannet_junk.eml"), acc)
    assert ctx["headers"]["Rcpt"] == "user@example-b.dk"
    assert ctx["external_ip"] == "150.242.228.48"


def test_per_account_trusted_relays_and_domains():
    raw = (b"Return-Path: <a@sender.example>\n"
           b"Received: from relay.home.example (relay.home.example [198.51.100.7]) "
           b"by mx1.gigahost.dk (Postfix) with ESMTPS id 1; Tue, 20 Oct 2026 10:00:02 +0000\n"
           b"Received: from gw.office.example (gw.office.example [192.0.2.44]) "
           b"by relay.home.example (Postfix) with ESMTPS id 2; Tue, 20 Oct 2026 10:00:01 +0000\n"
           b"Received: from out.sender.example (out.sender.example [203.0.113.99]) "
           b"by gw.office.example (Postfix) with ESMTPS id 3; Tue, 20 Oct 2026 10:00:00 +0000\n"
           b"Subject: x\n\nbody\n")
    plain = mailctx.scan_context(raw, ACC)
    assert plain["external_ip"] == "198.51.100.7"
    acc = make_account(trusted_relays=["198.51.100.0/24", "not-a-cidr"],
                       trusted_relay_domains=["office.example"])
    ctx = mailctx.scan_context(raw, acc)
    # relay by CIDR, gw.office.example by its (verified) rDNS suffix.
    assert ctx["external_ip"] == "203.0.113.99"
    assert ctx["helo"] == "out.sender.example"


def test_documentation_ranges_are_not_internal():
    raw = (b"Received: from x (x.example [192.0.2.1]) by mx2.gigahost.dk with ESMTP;"
           b" Tue, 20 Oct 2026 10:00:00 +0000\n\n")
    assert mailctx.scan_context(raw, ACC)["external_ip"] == "192.0.2.1"


def test_envelope_from_falls_back_to_lmtp_note_and_bounce_is_omitted():
    raw = fixture("scannet_junk.eml")
    no_rp = mailctx.scan_context(raw.replace(b"Return-Path: <user@elekworld.cn>\n", b""), ACC)
    assert no_rp["envelope_from"] == "user@elekworld.cn"
    bounce = mailctx.scan_context(
        raw.replace(b"Return-Path: <user@elekworld.cn>", b"Return-Path: <>"), ACC)
    assert bounce["envelope_from"] is None
    assert "From" not in bounce["headers"]


# ---------------------------------------------------------------------------
# SRS / bonus helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("addr,expected", [
    ("SRS0=ElL/=IJ=eu.example.com=a=b=c@fwd.example", "a=b=c@eu.example.com"),
    ("SRS0=+pym=G4=x.example=kontakt@fwd.example", "kontakt@x.example"),
    ("srs0=AbCd=ZZ=x.example=u@fwd.example", "u@x.example"),
    ("SRS1=Fbun=first.example==6UXA=IF=orig.example=u@last.example",
     "SRS0=6UXA=IF=orig.example=u@first.example"),
    ("plain@example.org", None),
    ("SRS0=only=two@fwd.example", None),
    ("SRS1=x@fwd.example", None),
    ("SRS0=", None),
])
def test_srs_reverse(addr, expected):
    assert mailctx.srs_reverse(addr) == expected


def test_srs_decode_all_handles_nesting():
    assert mailctx.srs_decode_all(
        "SRS1=Fbun=first.example==6UXA=IF=orig.example=u@last.example") == "u@orig.example"
    assert mailctx.srs_decode_all(None) is None


@pytest.mark.parametrize("ctx,expected", [
    (None, []),
    ({}, []),
    ({"provider_flag": True, "provider_score": None}, ["TH_PROVIDER_SPAM"]),
    ({"provider_flag": False, "provider_score": 5.0}, ["TH_PROVIDER_SCORE"]),
    ({"provider_flag": None, "provider_score": 4.99}, []),
    ({"provider_flag": "garbage", "provider_score": "x"}, []),
])
def test_provider_bonus_rules(ctx, expected):
    assert [b["n"] for b in mailctx.provider_bonus(ctx)] == expected


def test_bonus_symbols_match_messages_symbols_format():
    (sym,) = mailctx.provider_bonus({"provider_flag": True, "provider_score": 12.0,
                                     "provider": "gigahost"})
    assert set(sym) == {"n", "s", "o"} and sym["s"] == 4.0
    assert len(sym["o"]) <= 3 and all(isinstance(o, str) for o in sym["o"])


def test_parse_received_shapes():
    hop = mailctx.parse_received(
        "from mailout.gigahost.dk [10.103.105.10] by cph1.mailout.gigahost.dk (ZoneMTA) "
        "with ESMTP id 1a15; Mon, 19 Oct 2026 14:32:50 +0000")
    assert str(hop["from_ip"]) == "10.103.105.10" and hop["by"] == "cph1.mailout.gigahost.dk"
    hop = mailctx.parse_received(
        "from [20.240.223.52] ([20.240.223.52:62037] helo=ppj-vm-producti) by sp.example "
        "(envelope-from <a@b.example>) (ecelerity 5.3 r(msys:tags/5.3)) with ESMTPSA id 88")
    assert str(hop["from_ip"]) == "20.240.223.52"
    assert hop["from_helo"] == "ppj-vm-producti"
    assert hop["proto"] == "ESMTPSA" and hop["envelope_from"] == "a@b.example"
    hop = mailctx.parse_received(
        "from scan2.mf.scannet.dk ([127.0.0.1]) by localhost (scan2.mf.scannet.dk [127.0.0.1]) "
        "(amavis, port 10024) with ESMTP id x for <u@example-b.dk>; Tue, 20 Oct 2026")
    assert hop["by"] == "localhost" and "scan2.mf.scannet.dk" in hop["by_aliases"]


# ---------------------------------------------------------------------------
# Review fix: only the provider's MAIL hosts are trusted, not its whole
# address block or domain (shared web hosting / customer servers live there)
# ---------------------------------------------------------------------------

_GH_TOP = (b"Return-Path: <SRS0=abcd=IJ=evil.example=x@gigahost.dk>\n"
           b"Received: from mx1.gigahost.dk (mx1.gigahost.dk [46.183.139.11])\n"
           b"\tby mailstore4.gigahost.dk (Postfix) with ESMTPS id A1 for <ole@bynet.example>;"
           b" Mon, 19 Oct 2026 10:00:00 +0200\n")


def _gh(hop: bytes, extra: bytes = b"") -> bytes:
    return (_GH_TOP + hop + extra
            + b"From: x@evil.example\nSubject: hi\n\nbody\n")


def test_gigahost_shared_web_host_is_external():
    raw = _gh(b"Received: from web5.gigahost.dk (web5.gigahost.dk [46.183.139.205])\n"
              b"\tby mx1.gigahost.dk (Postfix) with ESMTPS id B2; Mon, 19 Oct 2026 10:00:00 +0200\n",
              b"Received: by web5.gigahost.dk (Postfix, from userid 1001) id D4;"
              b" Mon, 19 Oct 2026 10:00:00 +0200\n")
    ctx = mailctx.scan_context(raw, ACC)
    assert ctx["external_ip"] == "46.183.139.205" and ctx["hostname"] == "web5.gigahost.dk"
    assert [h["role"] for h in ctx["hops"]] == ["internal", "external", "unchecked"]
    assert ctx["provider"] == "gigahost" and ctx["envelope_from"] == "x@evil.example"


@pytest.mark.parametrize("host,ip", [("internal.lightbooth.io", "46.183.139.20"),
                                     ("web5.gigahost.dk", "46.183.139.205")])
def test_forged_esmtpsa_hop_below_customer_host_is_not_trusted(host, ip):
    raw = _gh(f"Received: from srv ({host} [{ip}])\n"
              "\tby mx1.gigahost.dk (Postfix) with ESMTPS id B2; Mon, 19 Oct 2026 10:00:00 +0200\n".encode(),
              b"Received: from x (good.example [209.85.208.46]) by smtp.gigahost.dk (Postfix)"
              b" with ESMTPSA id E5; Mon, 19 Oct 2026 10:00:00 +0200\n")
    ctx = mailctx.scan_context(raw, ACC)
    assert ctx["external_ip"] == ip
    assert ctx["authenticated"] is False and "User" not in ctx["headers"]
    assert ctx["headers"]["IP"] == ip


def test_provider_host_patterns_are_exact():
    gh = next(p for p in mailctx.PROFILES if p.name == "gigahost")
    sn = next(p for p in mailctx.PROFILES if p.name == "scannet")
    for ok in ("mx1.gigahost.dk", "MX3.gigahost.dk.", "mailstore4.gigahost.dk", "smtp.gigahost.dk",
               "mailout.gigahost.dk", "cph1.mailout.gigahost.dk"):
        assert gh.host_match(ok), ok
    for bad in ("web5.gigahost.dk", "gigahost.dk", "api.gigahost.dk", "mx1.gigahost.dk.evil.example",
                "evilmx1.gigahost.dk"):
        assert not gh.host_match(bad), bad
    assert sn.host_match("scan2.mf.scannet.dk") and sn.host_match("box11.mf.scannet.dk")
    assert not sn.host_match("www.scannet.dk") and not sn.host_match("customer.scannet.dk")
    assert not any(ipaddress.ip_address("46.183.139.205") in n for n in gh.networks)


def test_effective_bonus_does_not_double_count_spam_flag():
    """rspamd's SPAM_FLAG (+5) already scores X-Spam: Yes; the provider bonus
    must not add the same verdict again (calibration found +9 for one flag)."""
    spam = [{"n": "TH_PROVIDER_SPAM", "s": 4.0, "o": ["gigahost"]}]
    score = [{"n": "TH_PROVIDER_SCORE", "s": 2.0, "o": ["scannet"]}]
    flagged = [{"n": "SPAM_FLAG", "s": 5.0, "o": []}, {"n": "BAYES_HAM", "s": -3.0}]
    assert mailctx.effective_bonus(spam, flagged) == []
    assert mailctx.effective_bonus(score, flagged) == []
    assert mailctx.effective_bonus(spam, [{"n": "SPAM_FLAG", "s": 1.5}]) == [
        {"n": "TH_PROVIDER_SPAM", "s": 2.5, "o": ["gigahost"]}]
    assert mailctx.effective_bonus(spam, [{"n": "BAYES_SPAM", "s": 5.0}]) == spam
    assert mailctx.effective_bonus(spam, None) == spam
    assert mailctx.effective_bonus(None, flagged) == []


# ---------------------------------------------------------------------------
# SpamExperts (spamfilter.io) in front of Scannet
# ---------------------------------------------------------------------------


def test_spamexperts_ham_external_is_the_hop_the_node_wrote():
    ctx = ctx_of("scannet_spamexperts_ham.eml")
    assert [h["role"] for h in ctx["hops"]] == [
        "internal", "internal", "internal", "internal", "external", "unchecked"]
    assert ctx["headers"] == {
        "Rcpt": "user@example-a.dk",
        "IP": "159.183.232.146",
        "Helo": "o6.ptr9305.em.invoice.example",
        "Hostname": "o6.ptr9305.em.invoice.example",
        "From": "bounces+123-abcd-user=example-a.dk@email.invoice.example",
    }
    assert ctx["provider"] == "scannet+spamexperts"
    assert ctx["forwarded"] is False
    # Scannet's -95 (SSO_SPAMEXPERTS=-100) is ignored; SpamExperts says ham.
    assert ctx["provider_score"] is None
    assert ctx["provider_class"] == "ham"
    assert ctx["provider_evidence"] == pytest.approx(0.00977954808814)
    assert ctx["provider_flag"] is False
    assert ctx["provider_source"] == "trailing"
    assert mailctx.provider_bonus(ctx) == []
    assert mailctx.provider_verdict(ctx) == "clean"


def test_spamexperts_unsure_last_class_and_own_iprev_win():
    ctx = ctx_of("scannet_spamexperts_unsure.eml")
    assert ctx["external_ip"] == "45.145.226.54"
    assert ctx["helo"] == "mail.shop.example"
    # Exim "from NAME ([ip] helo=X)": NAME is Exim's verified rDNS; the
    # sender's forged "iprev=pass (forged.bank.example)" is not used.
    assert ctx["hostname"] == "mail-out.shop.example"
    # A sender-written "X-Spamfilter.io-Class: ham" above SpamExperts' own
    # block: the last class (SpamExperts') wins.
    assert ctx["provider_class"] == "unsure"
    assert ctx["provider_flag"] is None and ctx["provider_score"] is None
    assert mailctx.provider_bonus(ctx) == [{
        "n": "TH_PROVIDER_SCORE", "s": 2.0,
        "o": ["scannet+spamexperts", "class=unsure", "evidence=0.56"]}]
    assert mailctx.provider_verdict(ctx) == "unknown"


def test_spamexperts_spam_class_after_quarantine_release_hop():
    ctx = ctx_of("scannet_spamexperts_spam.eml")
    # backup-mx <- node1 (trusted) <- "from www-data by node1 with local"
    # <- node2 wrote the real reception hop -> external.
    assert [h["role"] for h in ctx["hops"]] == [
        "internal", "internal", "internal", "internal", "internal", "external", "unchecked"]
    assert ctx["external_ip"] == "203.0.113.77"
    assert ctx["helo"] == "promo.example"
    # Exim wrote "[ip]" (no verified name): the node's own iprev=pass host.
    assert ctx["hostname"] == "mx.promo.example"
    assert ctx["authenticated"] is False  # the ESMTPSA hop is below
    assert ctx["provider_flag"] is True and ctx["provider_class"] == "spam"
    assert ctx["provider_score"] is None  # Scannet's -76 is ignored
    assert mailctx.provider_bonus(ctx) == [{
        "n": "TH_PROVIDER_SPAM", "s": 4.0, "o": ["scannet+spamexperts"]}]
    assert mailctx.provider_verdict(ctx) == "spam"


def test_spamexperts_iprev_only_from_the_writing_node_and_matching_ip():
    raw = fixture("scannet_spamexperts_spam.eml")
    own = (b"Authentication-Results: node2.spamfilter.io;\n"
           b"\tiprev=pass (mx.promo.example) smtp.remote-ip=203.0.113.77;\n")
    assert own in raw
    for forged in (b"Authentication-Results: node9.spamfilter.io;\n"
                   b"\tiprev=pass (mx.promo.example) smtp.remote-ip=203.0.113.77;\n",
                   b"Authentication-Results: node2.spamfilter.io;\n"
                   b"\tiprev=pass (mx.promo.example) smtp.remote-ip=203.0.113.78;\n"):
        ctx = mailctx.scan_context(raw.replace(own, forged), ACC)
        assert ctx["external_ip"] == "203.0.113.77"
        assert ctx["hostname"] is None and "Hostname" not in ctx["headers"]
    # A matching line in the sender's own headers (not SpamExperts' trailing
    # block) does not count either.
    moved = raw.replace(own, b"").replace(b"Subject: Fixture", own + b"Subject: Fixture")
    assert mailctx.scan_context(moved, ACC)["hostname"] is None
    # iprev other than pass drops even Exim's name.
    unsure = fixture("scannet_spamexperts_unsure.eml").replace(
        b"iprev=pass (mail-out.shop.example)", b"iprev=fail (mail-out.shop.example)")
    assert mailctx.scan_context(unsure, ACC)["hostname"] is None


def test_spamexperts_class_ignored_without_block_or_below_external_only():
    raw = fixture("scannet_spamexperts_ham.eml")
    # No X-Filter-ID -> no SpamExperts block; Scannet's score stays ignored.
    no_id = mailctx.scan_context(raw.replace(b"X-Filter-ID:", b"X-Other-ID:"), ACC)
    assert no_id["provider_class"] is None and no_id["provider_flag"] is None
    assert no_id["provider_score"] is None
    assert mailctx.provider_bonus(no_id) == []
    assert mailctx.provider_verdict(no_id) == "clean"


def test_spamexperts_node_not_trusted_unless_reported_by_scannet():
    # The same node hop delivered to Gigahost: a SpamExperts customer's
    # outbound relay, i.e. the external sender itself.
    raw = (b"Return-Path: <SRS0=abcd=IJ=shop.example=x@gigahost.dk>\n"
           b"Received: from mx1.gigahost.dk (mx1.gigahost.dk [46.183.139.11])\n"
           b"\tby mailstore4.gigahost.dk (Postfix) with ESMTPS id A1; Tue, 20 Oct 2026 10:00:02 +0000\n"
           b"Received: from node4.spamfilter.io (node4.spamfilter.io [46.36.212.34])\n"
           b"\tby mx1.gigahost.dk (Postfix) with ESMTPS id B2; Tue, 20 Oct 2026 10:00:01 +0000\n"
           b"Received: from evil.example ([203.0.113.5]) by node4.spamfilter.io with esmtps"
           b" (Exim 4.94.2) id 1; Tue, 20 Oct 2026 10:00:00 +0000\n"
           b"Subject: x\nX-Spamfilter.io-Class: ham\nX-Filter-ID: x\n\nbody\n")
    ctx = mailctx.scan_context(raw, ACC)
    assert ctx["external_ip"] == "46.36.212.34"
    assert ctx["provider"] == "gigahost" and ctx["provider_class"] is None
    # Scannet hop from a host that is neither a node name nor a node IP.
    raw2 = fixture("scannet_spamexperts_ham.eml").replace(
        b"from node4.spamfilter.io (node4.spamfilter.io [46.36.212.34])",
        b"from node4.spamfilter.io (node4.spamfilter.io.evil.example [198.51.100.34])")
    ctx2 = mailctx.scan_context(raw2, ACC)
    assert ctx2["external_ip"] == "198.51.100.34"
    assert ctx2["provider"] == "scannet" and ctx2["provider_class"] is None


def test_spamexperts_known_ip_trusted_even_with_unknown_rdns():
    raw = fixture("scannet_spamexperts_ham.eml").replace(
        b"from node4.spamfilter.io (node4.spamfilter.io [46.36.212.34])",
        b"from node4.spamfilter.io (unknown [46.36.212.34])")
    ctx = mailctx.scan_context(raw, ACC)
    assert ctx["external_ip"] == "159.183.232.146"
    assert ctx["provider_class"] == "ham"


def test_spamexperts_profile_patterns():
    se = mailctx.SPAMEXPERTS
    for ok in ("node1.spamfilter.io", "NODE10.spamfilter.io."):
        assert se.host_match(ok), ok
    for bad in ("spamfilter.io", "nodex.spamfilter.io", "node4.spamfilter.io.evil.example",
                "evilnode4.spamfilter.io", "mx.spamfilter.io"):
        assert not se.host_match(bad), bad
    assert se not in mailctx.PROFILES  # never trusted on its own


# ---------------------------------------------------------------------------
# Forwarded mail
# ---------------------------------------------------------------------------


def test_outlook_forward_to_gigahost_drops_envelope_and_rcpt():
    ctx = ctx_of("gigahost_outlook_forward.eml")
    assert ctx["forwarded"] is True
    # Gigahost's own SRS0 layer undone; Outlook's "+SRS=" layer is kept as
    # the envelope (display) and decoded for original_sender.
    assert ctx["envelope_from"] == "user+SRS=g1gbi=GF=shop.example=order@hotmail.com"
    assert ctx["original_sender"] == "order@shop.example"
    # The forwarder hop stays the external hop (RBL/rDNS on Outlook infra).
    assert ctx["headers"] == {
        "IP": "40.93.65.12",
        "Helo": "AM0PR83CU005.outbound.protection.outlook.com",
        "Hostname": "mail-westeuropeazlp17010012.outbound.protection.outlook.com",
        "From": "<>",  # null sender: rspamd checks the forwarder's HELO, not SPF of the original
    }
    assert ctx["provider"] == "gigahost" and mailctx.provider_verdict(ctx) == "clean"


def test_classic_srs0_forward_keeps_rcpt_when_addressed_to_account():
    ctx = ctx_of("gigahost_srs0_forward.eml")
    assert ctx["envelope_from"] == "SRS0=6UXA=IF=orig.example=info@mail.fwd-example-net.dk"
    assert ctx["original_sender"] == "info@orig.example"
    assert ctx["forwarded"] is True
    assert ctx["headers"] == {
        "Rcpt": "user@example-a.dk",  # To: contains the account address
        "IP": "198.51.100.25",
        "Helo": "mail.fwd-example-net.dk",
        "Hostname": "mail.fwd-example-net.dk",
        "From": "<>",
    }


@pytest.mark.parametrize("return_path,forwarded,sent_from", [
    # Gigahost's own SRS0 around a plain sender: not forwarded.
    ("SRS0=abcd=IJ=shop.example=news@gigahost.dk", False, "news@shop.example"),
    # SRS-looking local parts that are not a complete SRS address.
    ("SRS0=abcd=IJ=shop.example=news+SRS=weekly@gigahost.dk", False, "news+SRS=weekly@shop.example"),
    ("news+SRS=weekly@shop.example", False, "news+SRS=weekly@shop.example"),
    ("bounce+SRS=abc=XY=nodot=u@shop.example", False, "bounce+SRS=abc=XY=nodot=u@shop.example"),
    ("SRS0=abc=XYZ=other.example=u@shop.example", False, "SRS0=abc=XYZ=other.example=u@shop.example"),
    ("prvs=1234abcd=u@shop.example", False, "prvs=1234abcd=u@shop.example"),
    # Self-referential SRS (encoded domain == forwarder): ambiguous, kept.
    ("SRS0=abc=XY=shop.example=u@shop.example", False, "SRS0=abc=XY=shop.example=u@shop.example"),
    # Real forwards.
    ("SRS0=abc=XY=other.example=u@shop.example", True, "<>"),
    ("SRS1=Fbun=fwd1.example==6UXA=IF=orig.example=u@shop.example", True, "<>"),
    ("x+SRS=P/L9D=H5=other.example=order@hotmail.com", True, "<>"),
])
def test_forward_detection_rule(return_path, forwarded, sent_from):
    raw = (f"Return-Path: <{return_path}>\n".encode()
           + b"Received: from mx1.gigahost.dk (mx1.gigahost.dk [46.183.139.11])\n"
           b"\tby mailstore4.gigahost.dk (Postfix) with ESMTPS id A1; Tue, 20 Oct 2026 10:00:02 +0000\n"
           b"Received: from out.shop.example (out.shop.example [203.0.113.40])\n"
           b"\tby mx1.gigahost.dk (Postfix) with ESMTPS id B2; Tue, 20 Oct 2026 10:00:01 +0000\n"
           b"To: someone@elsewhere.example\nSubject: x\n\nbody\n")
    ctx = mailctx.scan_context(raw, ACC)
    assert ctx["forwarded"] is forwarded
    assert ctx["headers"].get("From") == sent_from
    # Rcpt is only dropped for forwarded mail not addressed to the account.
    assert ("Rcpt" in ctx["headers"]) is (not forwarded)
    assert ctx["external_ip"] == "203.0.113.40"


@pytest.mark.parametrize("addr,expected", [
    ("user+SRS=g1gbi=GF=shop.example=order@hotmail.com", "order@shop.example"),
    ("user+SRS=g1gbi=GF=nodot=order@hotmail.com", None),
])
def test_srs_reverse_outlook_style(addr, expected):
    assert mailctx.srs_reverse(addr) == expected


def test_forwarder_srs_never_raises():
    for v in (None, "", "@", "SRS0=@", "a+SRS=@b", "x" * 5000 + "@y.example", 12):
        assert mailctx.forwarder_srs(v) in (True, False)


# ---------------------------------------------------------------------------
# Review regressions: client-controlled Exim fields, port logging, by-name
# node trust, quadratic To/Cc scan.
# ---------------------------------------------------------------------------

_SE_UNSURE_HOP = b"Received: from mail-out.shop.example ([45.145.226.54] helo=mail.shop.example)"
_SE_FORGED_BELOW = (b"Received: from webmail.shop.example (localhost [127.0.0.1])\n"
                    b"\tby mail.shop.example",
                    b"Received: from good.example (good.example [8.8.8.8])\n"
                    b"\tby node10.spamfilter.io")


@pytest.mark.parametrize("hop", [
    # HELO literals are client-controlled: never the hop IP.
    b"Received: from [6.6.6.6] (helo=[127.0.0.1])",
    b"Received: from [6.6.6.6] (helo=[89.188.78.66])",
    b"Received: from [6.6.6.6] (helo=[IPv6:::1] ident=[192.168.1.1])",
    # Exim with port logging.
    b"Received: from [6.6.6.6]:4444 (helo=x.example)",
    b"Received: from [6.6.6.6] (port=4444 helo=[127.0.0.1])",
])
def test_spamexperts_hop_ip_cannot_be_spoofed_via_helo_or_port(hop):
    raw = fixture("scannet_spamexperts_unsure.eml").replace(_SE_UNSURE_HOP, hop)
    raw = raw.replace(*_SE_FORGED_BELOW)
    ctx = mailctx.scan_context(raw, ACC)
    assert ctx["external_ip"] == "6.6.6.6"
    assert ctx["hostname"] is None
    assert [h["role"] for h in ctx["hops"]][-2:] == ["external", "unchecked"]


def test_parse_received_ignores_helo_literal_and_handles_port():
    hop = mailctx.parse_received("from [6.6.6.6] (helo=[127.0.0.1]) by node1.spamfilter.io")
    assert str(hop["from_ip"]) == "6.6.6.6" and hop["from_rdns"] is None
    assert hop["from_helo"] == "[127.0.0.1]"
    hop = mailctx.parse_received("from h.example ([6.6.6.6]:25 helo=x) by n")
    assert str(hop["from_ip"]) == "6.6.6.6" and hop["from_rdns"] == "h.example"
    assert str(mailctx._parse_ip("[2001:db8::1]:25")) == "2001:db8::1"


def test_node_by_name_trusted_only_below_node_local_reinjection():
    # A node hop without a parseable IP that is NOT a local re-injection
    # must not let a forged "by nodeN" header below it be trusted.
    raw = fixture("scannet_spamexperts_unsure.eml").replace(
        _SE_UNSURE_HOP, b"Received: from somewhere by node10.spamfilter.io with esmtp")
    raw = raw.replace(*_SE_FORGED_BELOW)
    ctx = mailctx.scan_context(raw, ACC)
    assert ctx["external_ip"] is None
    assert "8.8.8.8" not in ctx["headers"].values()
    # The real quarantine release (with local) still works.
    assert ctx_of("scannet_spamexperts_spam.eml")["external_ip"] == "203.0.113.77"


def test_addressed_to_is_linear_on_long_to_header():
    import time
    raw = (b"Return-Path: <SRS0=abcd=AB=bank.example=x@fwd.example>\n"
           b"Received: from a (a.example [203.0.113.9]) by mx1.gigahost.dk (Postfix) with ESMTP id 1\n"
           b"To: " + b"a" * 200000 + b"\n\nbody\n")
    t = time.monotonic()
    ctx = mailctx.scan_context(raw, ACC)
    assert time.monotonic() - t < 2.0
    assert ctx["forwarded"] is True and "Rcpt" not in ctx["headers"]
    assert mailctx._addressed_to([("to", "Name <USER@example-a.dk>, x@y.example")], "user@example-a.dk")
    assert not mailctx._addressed_to([("to", "xuser@example-a.dk")], "user@example-a.dk")


# ---------------------------------------------------------------------------
# 2.1 E7: trusted forwarders (the owner's own MX, mail.vexar.example)
# ---------------------------------------------------------------------------

FWD = ["mail.vexar.example", "203.0.113.109"]
ACC_FWD_A = make_account(user="user@example-a.dk", trusted_forwarders=FWD)
ACC_FWD_B = make_account(user="user@example-b.dk", trusted_forwarders=FWD)


def test_forwarder_walked_past_on_gigahost_platform_order():
    ctx = ctx_of("gigahost_vexar_shop_order.eml", ACC_FWD_A)
    assert [h["role"] for h in ctx["hops"]] == ["internal", "forwarder", "external"]
    assert ctx["external_ip"] == "203.0.113.33"
    assert ctx["hostname"] == "mail-sender-3.vexar.example"
    # Gigahost's SRS1 and the forwarder's SRS0 are both undone: the real sender.
    assert ctx["envelope_from"] == "mailbot@vexar.example"
    assert ctx["forwarded"] is False and ctx["via_forwarder"] == "mail.vexar.example"
    assert ctx["origin_host"] == "mail-sender-3.vexar.example"
    assert ctx["headers"]["From"] == "mailbot@vexar.example"
    assert ctx["headers"]["IP"] == "203.0.113.33"
    # The original RCPT TO (the shop mailbox) instead of the account address.
    assert ctx["headers"]["Rcpt"] == "info@shop-a.example"
    assert "info@shop-a.example" in ctx["recipients"]


def test_without_the_forwarder_the_same_mail_is_a_plain_forward():
    ctx = ctx_of("gigahost_vexar_shop_order.eml")
    assert ctx["external_ip"] == "203.0.113.109" and ctx["forwarded"] is True
    assert ctx["headers"]["From"] == "<>"
    # A third-party forwarder relays anyone's mail: never path proof (E8).
    assert ctx["origin_host"] is None


def test_spam_via_the_forwarder_is_judged_by_the_real_sender():
    ctx = ctx_of("gigahost_vexar_shop_spam.eml", ACC_FWD_A)
    assert [h["role"] for h in ctx["hops"]] == ["internal", "forwarder", "external", "unchecked"]
    assert ctx["external_ip"] == "62.173.146.164"
    assert ctx["envelope_from"] == "ephiydk@lastchance.example"
    assert ctx["origin_host"] == "mail.gadgetoutlet.example"   # NOT under vexar.example
    assert ctx["headers"]["From"] == "ephiydk@lastchance.example"
    # The ESMTPA hop below the external one is the spammer's own.
    assert ctx["authenticated"] is False and "User" not in ctx["headers"]
    assert ctx["provider_flag"] is True


def test_scannet_direct_via_forwarder():
    ctx = ctx_of("scannet_vexar_shop_spam.eml", ACC_FWD_B)
    assert [h["role"] for h in ctx["hops"]][-2:] == ["forwarder", "external"]
    assert ctx["external_ip"] == "34.162.54.97"
    assert ctx["envelope_from"] == "support@gazeta.example"
    assert ctx["forwarded"] is False
    assert ctx["headers"]["Rcpt"] == "info@shop-a.example"
    # Scannet's amavis verdict above the hops is still the provider verdict.
    assert ctx["provider_score"] == 5.85 and ctx["provider_source"] == "above"


def test_spamexperts_quarantine_release_via_forwarder():
    ctx = ctx_of("scannet_spamexperts_vexar_shop_release.eml", ACC_FWD_B)
    roles = [h["role"] for h in ctx["hops"]]
    assert roles[-2:] == ["forwarder", "external"]
    assert ctx["provider"] == "scannet+spamexperts"
    assert ctx["external_ip"] == "203.0.113.35"
    assert ctx["origin_host"] == "mail-sender-5.vexar.example"
    assert ctx["via_forwarder"] == "mail.vexar.example"   # Exim's verified name
    assert ctx["envelope_from"] == "support@vexar.example"
    assert ctx["headers"]["Rcpt"] == "info@shop-b.example"


def test_forwarder_trust_needs_a_trusted_writer():
    """A spammer's own Received claiming 'from mail.vexar.example' below the
    external hop never makes the forwarder trusted."""
    raw = (b"Return-Path: <x@spam.example>\r\n"
           b"Received: from mx2.gigahost.dk (mx2.gigahost.dk [46.183.139.12])\r\n"
           b"\tby mailstore4.gigahost.dk (Postfix) with ESMTPS id 1\r\n"
           b"Received: from bad.example (bad.example [198.51.100.9])\r\n"
           b"\tby mx2.gigahost.dk (Postfix) with ESMTPS id 2\r\n"
           b"Received: from mail.vexar.example (mail.vexar.example [203.0.113.109])\r\n"
           b"\tby bad.example (Postfix) with ESMTP id 3\r\n"
           b"From: support@vexar.example\r\nMessage-ID: <f@x>\r\n\r\nx\r\n")
    ctx = mailctx.scan_context(raw, ACC_FWD_A)
    assert ctx["external_ip"] == "198.51.100.9" and ctx["origin_host"] == "bad.example"
    assert [h["role"] for h in ctx["hops"]] == ["internal", "external", "unchecked"]


def test_forwarder_wildcard_and_ip_entries():
    # A wildcard trusts every host of the platform, so the mail "originates"
    # inside the trusted chain: no external hop, origin = the last of them.
    acc = make_account(user="user@example-a.dk", trusted_forwarders=["*.vexar.example"])
    ctx = ctx_of("gigahost_vexar_shop_order.eml", acc)
    assert [h["role"] for h in ctx["hops"]] == ["internal", "forwarder", "forwarder"]
    assert ctx["forwarders"] == ["mail.vexar.example", "mail-sender-3.vexar.example"]
    assert ctx["origin_host"] == "mail-sender-3.vexar.example"
    assert ctx["envelope_from"] == "mailbot@vexar.example"
    # rspamd still judges the deepest trusted sending host (not "no IP").
    assert ctx["external_ip"] == "203.0.113.33" and ctx["headers"]["IP"] == "203.0.113.33"
    assert ctx["headers"]["Hostname"] == "mail-sender-3.vexar.example"
    assert ctx["headers"]["Rcpt"] == "info@shop-a.example"
    acc = make_account(user="user@example-a.dk", trusted_forwarders="203.0.113.96/27")
    assert ctx_of("gigahost_vexar_shop_order.eml", acc)["external_ip"] == "203.0.113.33"


def test_mail_originating_on_the_forwarder_itself():
    """A notification written by the owner's MX itself (local pickup): the
    forwarder hop is the sending host rspamd judges."""
    raw = (b"Return-Path: <SRS1=Ab12=mail.vexar.example==Cd34=IJ=mail.vexar.example=postmaster@gigahost.dk>\r\n"
           b"Received: from mx2.gigahost.dk (mx2.gigahost.dk [46.183.139.12])\r\n"
           b"\tby mailstore4.gigahost.dk (Postfix) with ESMTPS id 1\r\n"
           b"\tfor <user@example-a.dk>; Tue, 20 Oct 2026 09:14:03 +0000 (UTC)\r\n"
           b"Received: from mail.vexar.example (mail.vexar.example [203.0.113.109])\r\n"
           b"\tby mx2.gigahost.dk (Postfix) with ESMTPS id 2\r\n"
           b"\tfor <user@example-a.dk>; Tue, 20 Oct 2026 09:14:02 +0000 (UTC)\r\n"
           b"Received: by mail.vexar.example (Postfix, from userid 0) id 3; Tue, 20 Oct 2026 11:14:01 +0200\r\n"
           b"From: postmaster@mail.vexar.example\r\nTo: info@shop-a.example\r\nMessage-ID: <n@x>\r\n\r\nx\r\n")
    ctx = mailctx.scan_context(raw, ACC_FWD_A)
    assert [h["role"] for h in ctx["hops"]] == ["internal", "forwarder", "internal"]
    assert ctx["external_ip"] == "203.0.113.109" and ctx["headers"]["IP"] == "203.0.113.109"
    assert ctx["origin_host"] == "mail.vexar.example"
    assert ctx["envelope_from"] == "postmaster@mail.vexar.example"


def test_recipients_only_from_trusted_hops():
    raw = fixture("gigahost_vexar_shop_spam.eml").replace(
        b"Received: from mail.gadgetoutlet.example (labe",
        b"Received: from x (y [192.0.2.1]) by z for <ceo@protected.example>;\r\n"
        b"Received: from mail.gadgetoutlet.example (labe")
    ctx = mailctx.scan_context(raw, ACC_FWD_A)
    assert "ceo@protected.example" not in ctx["recipients"]
    assert "info@shop-a.example" in ctx["recipients"]


# ---------------------------------------------------------------------------
# 2.1 E10: newsletter helpers
# ---------------------------------------------------------------------------


def test_newsletter_helpers():
    raw = (b"From: Shop News <news@shop.example>\r\n"
           b"List-Unsubscribe: <https://shop.example/u/1>, <mailto:u@shop.example>\r\n\r\nx")
    assert mailctx.has_list_unsubscribe(raw)
    assert not mailctx.has_list_unsubscribe(b"List-Unsubscribe: nope\r\n\r\n")
    assert mailctx.header_from_domain(raw) == "shop.example"
    assert mailctx.header_from_domain(b"From: plain@Sub.Shop.Example\r\n\r\n") == "sub.shop.example"
    assert mailctx.known_esp({"origin_host": "o1.ptr.sendgrid.net"}) == "sendgrid.net"
    assert mailctx.known_esp({"envelope_from": "bounce@mcsv.net"}) == "mcsv.net"
    assert mailctx.known_esp({}, ["x.sendibt3.com"]) == "sendibt3.com"
    assert mailctx.known_esp({"origin_host": "mail.shop.example"}) is None
    assert mailctx.known_esp(None) is None


# ---------------------------------------------------------------------------
# 2.2 B7: the provider's authentication verdict at delivery (aged scans)
# ---------------------------------------------------------------------------


def auth_names(ctx):
    return [(s["n"], s["s"]) for s in mailctx.provider_auth_symbols(ctx)]


def test_parse_auth_results():
    ar = mailctx.parse_auth_results(
        'node2.spamfilter.io; iprev=pass (mail.x) smtp.remote-ip=1.2.3.4;\r\n dkim=pass header.d=Shop.Example '
        'header.s=s1; dmarc=fail reason="No valid SPF; nor DKIM" header.from=shop.example (policy=reject)')
    assert ar["authserv_id"] == "node2.spamfilter.io"
    assert [(m, r) for m, r, _p in ar["results"]] == [("iprev", "pass"), ("dkim", "pass"), ("dmarc", "fail")]
    assert ar["results"][1][2]["header.d"] == "shop.example"
    assert ar["results"][2][2]["policy"] == "reject"
    assert mailctx.parse_auth_results("scan2.mf.scannet.dk (amavis); dkim=pass")["authserv_id"] == \
        "scan2.mf.scannet.dk"
    assert mailctx.parse_auth_results("dkim=pass header.d=x.example")["authserv_id"] is None
    assert mailctx.parse_auth_results("") is None


def test_spamexperts_node_auth_is_trusted():
    ctx = ctx_of("scannet_spamexperts_ham.eml")
    a = ctx["provider_auth"]
    assert a["source"] == "node4.spamfilter.io" and a["dkim"] == "pass"
    assert a["dkim_domains"] == ["invoice.example"] and a["header_from"] == "invoice.example"
    assert auth_names(ctx) == [("TH_PROVIDER_AUTH_PASS", -1.0)]


def test_scannet_amavis_auth_above_external_hop_is_trusted():
    ctx = ctx_of("scannet_inbound.eml")
    assert ctx["provider_auth"]["source"] == "scan2.mf.scannet.dk"
    assert auth_names(ctx) == [("TH_PROVIDER_AUTH_PASS", -1.0)]   # aligned dkim, no dmarc line


def test_forwarder_auth_directly_below_its_hop():
    ctx = mailctx.scan_context(fixture("gigahost_vexar_shop_order.eml"), ACC_FWD_A)
    assert ctx["provider_auth"]["source"] == "mail.vexar.example"
    assert ctx["provider_auth"]["dmarc"] == "pass"
    assert auth_names(ctx) == [("TH_PROVIDER_AUTH_PASS", -1.0)]


def test_dmarc_fail_with_policy_none_is_distrust_only():
    # No points (p=none is the domain owner's choice), but an allow rule for
    # the From must not be trusted (fresh scans had R_SPF_FAIL for that).
    ctx = mailctx.scan_context(fixture("scannet_vexar_shop_spam.eml"), ACC_FWD_B)
    assert ctx["provider_auth"]["dmarc"] == "fail" and ctx["provider_auth"]["dmarc_policy"] == "none"
    assert auth_names(ctx) == [("TH_PROVIDER_AUTH_SPOOF", 0.0)]
    assert mailctx.provider_auth_symbols(ctx)[0]["o"][1:] == ["dmarc=fail", "p=none"]


def test_dmarc_fail_with_enforcing_or_unknown_policy_is_a_penalty():
    raw = fixture("scannet_vexar_shop_spam.eml").replace(b"(policy=none)", b"(policy=reject)")
    ctx = mailctx.scan_context(raw, ACC_FWD_B)
    assert auth_names(ctx) == [("TH_PROVIDER_AUTH_FAIL", 2.0)]
    assert mailctx.provider_auth_symbols(ctx)[0]["o"] == ["mail.vexar.example", "dmarc=fail", "p=reject"]
    raw = fixture("scannet_vexar_shop_spam.eml").replace(b" (policy=none)", b"")
    assert auth_names(mailctx.scan_context(raw, ACC_FWD_B)) == [("TH_PROVIDER_AUTH_FAIL", 2.0)]


def test_dkim_fail_or_dmarc_without_dkim_gives_no_pass():
    assert auth_names(mailctx.scan_context(fixture("scannet_spamexperts_vexar_shop_release.eml"), ACC_FWD_B)) == []
    assert auth_names(ctx_of("scannet_spamexperts_unsure.eml")) == []    # dmarc=pass, no dkim


def test_sender_written_auth_results_are_ignored():
    # A spammer's own "Authentication-Results: mx2.gigahost.dk; dkim=pass; dmarc=pass" BELOW the
    # external hop (sender-controlled area) must not count.
    raw = fixture("gigahost_inbound.eml").replace(
        b"From: Ollama", b"Authentication-Results: mx2.gigahost.dk; dkim=pass header.d=ollama.com; "
                        b"dmarc=pass header.from=ollama.com\r\nFrom: Ollama")
    ctx = mailctx.scan_context(raw, ACC)
    assert ctx["provider_auth"] is None and auth_names(ctx) == []
    # Microsoft's A-R inside a third-party forward is not ours either.
    assert ctx_of("gigahost_outlook_forward.eml")["provider_auth"] is None


def test_spamexperts_forged_node_line_above_the_real_one_loses():
    raw = fixture("scannet_spamexperts_ham.eml").replace(
        b"Authentication-Results: node4.spamfilter.io;",
        b"Authentication-Results: node4.spamfilter.io; dkim=pass header.d=bank.example; dmarc=pass\r\n"
        b"Authentication-Results: node4.spamfilter.io;", 1)
    a = mailctx.scan_context(raw, ACC)["provider_auth"]
    assert a["dkim_domains"] == ["invoice.example"] and a["dmarc"] is None


def test_provider_auth_needs_a_trusted_chain_and_never_raises():
    assert mailctx.scan_context(fixture("missing_received.eml"), ACC)["provider_auth"] is None
    assert mailctx.provider_auth_symbols(None) == []
    assert mailctx.provider_auth_symbols({"provider_auth": "garbage"}) == []
    assert mailctx.provider_auth_symbols({"provider_auth": {"dkim": "pass", "dkim_domains": ["a.example"],
                                                             "header_from": "b.example"}}) == []


# 2.2 review fix: the provider's SPF result keeps the allow-rule spoof guard
# alive in aged scans (rspamd's own SPF check is off there).


def _auth(**kw):
    base = {"source": "node4.spamfilter.io", "dkim": None, "dkim_domains": [], "dmarc": None,
            "dmarc_policy": None, "spf": None, "header_from": "partner.example"}
    return {"provider_auth": {**base, **kw}}


def test_summarize_auth_records_spf():
    ar = mailctx.parse_auth_results("node4.spamfilter.io; spf=fail smtp.mailfrom=partner.example; dkim=none")
    a = mailctx._summarize_auth([ar], "node4.spamfilter.io", "partner.example")
    assert a["spf"] == "fail" and a["dkim"] == "none"
    only_spf = mailctx.parse_auth_results("node4.spamfilter.io; spf=softfail smtp.mailfrom=x.example")
    assert mailctx._summarize_auth([only_spf], "node4.spamfilter.io", "x.example")["spf"] == "softfail"
    assert mailctx._summarize_auth([mailctx.parse_auth_results("node4.spamfilter.io; iprev=pass")],
                                   "n", "x.example") is None


@pytest.mark.parametrize("spf", ["fail", "softfail"])
def test_provider_spf_fail_is_a_distrust_only_signal(spf):
    syms = mailctx.provider_auth_symbols(_auth(spf=spf, dkim="none"))
    assert [(s["n"], s["s"]) for s in syms] == [("TH_PROVIDER_AUTH_SPOOF", 0.0)]
    assert syms[0]["o"] == ["node4.spamfilter.io", f"spf={spf}"]
    # A non-aligned DKIM pass does not vouch for the From either.
    assert auth_names(_auth(spf=spf, dkim="pass", dkim_domains=["esp.example"])) == [
        ("TH_PROVIDER_AUTH_SPOOF", 0.0)]


def test_provider_spf_fail_with_aligned_dkim_or_dmarc_pass_is_a_pass():
    # Forwarded mail breaks SPF; an aligned signature / DMARC pass still proves the From.
    assert auth_names(_auth(spf="fail", dkim="pass", dkim_domains=["partner.example"])) == [
        ("TH_PROVIDER_AUTH_PASS", -1.0)]
    assert auth_names(_auth(spf="fail", dkim="pass", dkim_domains=["esp.example"], dmarc="pass")) == [
        ("TH_PROVIDER_AUTH_PASS", -1.0)]
    assert auth_names(_auth(spf="fail", dmarc="pass")) == []
    assert auth_names(_auth(spf="pass")) == [] and auth_names(_auth(spf="neutral")) == []


def test_provider_auth_known():
    assert mailctx.provider_auth_known(_auth(spf="pass")) is True
    assert mailctx.provider_auth_known(_auth(dmarc="none")) is True
    assert mailctx.provider_auth_known(_auth(dkim="pass", dkim_domains=["x.example"])) is False
    assert mailctx.provider_auth_known({"provider_auth": None}) is False
    assert mailctx.provider_auth_known(None) is False
