"""2.7 namespoof.py (pure parts): name normalisation (æøå, order variants,
spacing, titles, homoglyphs), the matcher, the exceptions, Reply-To and
lure combinations, Prøv vs Til, the entry editor and the seed from the
Sent identities. Real SQLite in memory; filter.py is never imported."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "filter"))
import contacts  # noqa: E402
import namespoof as ns  # noqa: E402

OWN = ["bynet.example", "molt.example", "vexar.example"]
DISTRUST = {"DMARC_POLICY_REJECT", "DMARC_POLICY_QUARANTINE", "R_SPF_FAIL", "R_SPF_SOFTFAIL", "TH_PROVIDER_SPAM"}


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:", isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("CREATE TABLE engine_state (key TEXT PRIMARY KEY, value TEXT, updated_at INTEGER)")
    c.execute("CREATE TABLE messages (account TEXT, message_id TEXT, sender TEXT, symbols TEXT, scanned_at INTEGER, "
              "first_seen INTEGER)")
    contacts.ensure_schema(c)
    ns.ensure_schema(c)
    return c


def add(conn, name, allow=(), enabled=True):
    res = ns.save_name(conn, name=name, allow=list(allow), enabled=enabled, actor="admin", now=1000)
    assert res["ok"], res
    return res["entry"]


def raw(display, addr, *, subject="Hej", reply_to=None, extra=""):
    frm = f'"{display}" <{addr}>' if display else f"<{addr}>"
    lines = [f"From: {frm}", "To: inge@molt.example", f"Subject: {subject}", "Message-ID: <m@x>"]
    if reply_to:
        lines.append(f"Reply-To: {reply_to}")
    if extra:
        lines.append(extra)
    return ("\r\n".join(lines) + "\r\n\r\nTekst\r\n").encode()


def ev(conn, display, addr, *, mode="on", names=(), dkim=(), **kw):
    return ns.evaluate(conn, raw=raw(display, addr, **kw), names=names, dkim_domains=dkim, own_domains=OWN,
                       distrust=DISTRUST, mode=mode)


# ----- normalisation ------------------------------------------------------------------------


@pytest.mark.parametrize("a,b", [
    ("Søren Østergård", "Soren Ostergard"),
    ("Søren Østergård", "Soeren Oestergaard"),
    ("Åse Ærø", "Aase Aero"),
    ("Sofie   Hansen", "sofie hansen"),
    ("RASMUS-JENSEN", "Rasmus Jensen"),
    ("Ole Storm", "0le St0rm"),                        # digits
    ("Ole Storm", "Оle Stоrm"),                        # Cyrillic О and о
    ("Ole Storm", "Ole Stοrm"),                        # Greek omicron
    ("Ole Storm", "Ole Storrn"),                         # rn / m
    ("Inge", "Dr. Inge"),                              # titles ignored
    ("Ole Storm", "Ole Storm, CEO"),
    ("José Müller", "Jose Muller"),                      # diacritics
])
def test_names_normalise_to_the_same_key(a, b):
    assert ns.name_key(a) == ns.name_key(b)


@pytest.mark.parametrize("a,b", [("Ole Storm", "Ole Stormgaard"), ("Sofie", "Sofie Hansen"),
                                 ("Rasmus Jensen", "Rasmus Jessen")])
def test_different_names_stay_different(a, b):
    assert ns.name_key(a) != ns.name_key(b)


def test_invisible_characters_and_addresses_never_count():
    assert ns.tokens("O\u200ble St\u202eorm") == ns.tokens("Ole Storm")
    assert ns.name_key(ns._clean_display("O\u200ble Storm")) == ns.name_key("Ole Storm")
    assert ns.tokens("Ole Storm <evil@x.example>") == ns.tokens("Ole Storm")


# ----- matcher --------------------------------------------------------------------------------


def _m(*entries):
    return ns.Matcher([{"id": i, "name": n, "key": ns.name_key(n), "allow": list(a), "enabled": True}
                       for i, (n, a) in enumerate(entries, 1)])


@pytest.mark.parametrize("display", ["Ole Storm", "Storm, Ole", "STORM OLE", "Ole  Storm", "OleStorm",
                                     "Ole E. Storm", "Ole Storm (CEO)", "Ole Storm via Mobil",
                                     "Direktør Ole Storm", "Оle Stоrm"])
def test_full_name_and_order_variants_match(display):
    hit = _m(("Ole Storm", ["ole@bynet.example"])).match(display)
    assert hit is not None and hit.entry["name"] == "Ole Storm" and hit.how == "name"


@pytest.mark.parametrize("display", ["Ole", "Ole Smith", "Olav Storm", "Ole Stormgaard", "Storm", "O. Storm",
                                     "Ole Peter Hansen Storm", ""])
def test_unrelated_people_do_not_match(display):
    assert _m(("Ole Storm", [])).match(display) is None


def test_middle_names_in_the_entry():
    m = _m(("Ole Erik Storm", []))
    for d in ("Ole Erik Storm", "Ole Storm", "Storm, Ole Erik", "Storm Ole"):
        assert m.match(d) is not None, d
    assert m.match("Erik Storm") is None


def test_one_word_entry_needs_the_exact_display_name():
    m = _m(("Inge", []))
    assert m.match("Inge") is not None and m.match("inge") is not None and m.match("Hr. Inge") is not None
    for d in ("Inge Hansen", "Inge's Pizza", "Ingemar", "Anne Inge"):
        assert m.match(d) is None, d


def test_address_in_the_display_name():
    m = _m(("Ole Storm", ["ole@bynet.example"]))
    hit = m.match("ole@bynet.example")
    assert hit is not None and hit.how == "address"
    assert m.match("someone@else.example") is None


def test_disabled_entries_never_match():
    m = ns.Matcher([{"id": 1, "name": "Ole Storm", "key": "ole storm", "allow": [], "enabled": False}])
    assert m.match("Ole Storm") is None


# ----- evaluation: exceptions, combos, modes -------------------------------------------------


def test_hit_from_a_foreign_address(conn):
    add(conn, "Ole Storm", ["ole@bynet.example", "ole@molt.example"])
    r = ev(conn, "Ole Storm", "ceo.office@outlook.com")
    assert r.symbols == [{"n": "TH_NAME_SPOOF", "s": 5.0, "o": ["Ole Storm", "c…@outlook.com", "navn"]}]
    assert r.events == [("namespoof_hit", "Ole Storm: c…@outlook.com +5 navn")]


def test_real_addresses_and_own_domains_are_exempt(conn):
    add(conn, "Ole Storm", ["ole@bynet.example", "ole.storm@gmail.com", "@shopplatform.example"])
    assert ev(conn, "Ole Storm", "ole@bynet.example").exempt == "address"
    assert ev(conn, "Ole Storm", "info@molt.example").exempt == "own"            # the owner's own domain
    assert ev(conn, "Ole Storm", "noreply@mail.shopplatform.example").exempt == "domain"
    # A listed freemail address only with a DKIM signature of its domain.
    assert ev(conn, "Ole Storm", "ole.storm@gmail.com", dkim=["gmail.com"]).exempt == "address"
    r = ev(conn, "Ole Storm", "ole.storm@gmail.com")
    assert r.exempt is None and r.symbols[0]["n"] == "TH_NAME_SPOOF"


def test_forged_from_voids_an_exception(conn):
    add(conn, "Ole Storm", ["ole@bynet.example"])
    r = ev(conn, "Ole Storm", "ole@bynet.example", names={"DMARC_POLICY_REJECT"})
    assert r.exempt is None and r.symbols and r.symbols[0]["s"] == 5.0
    # ... but a valid aligned signature still proves it.
    assert ev(conn, "Ole Storm", "ole@bynet.example", names={"R_SPF_SOFTFAIL"}, dkim=["bynet.example"]).exempt == "address"


def test_address_in_display_needs_the_exact_address(conn):
    add(conn, "Ole Storm", ["ole@bynet.example", "@shopplatform.example"])
    r = ev(conn, "ole@bynet.example", "x@shopplatform.example")
    assert r.symbols and r.symbols[0]["o"][2] == "adresse-i-navnet"
    assert ev(conn, "ole@bynet.example", "ole@bynet.example").exempt == "address"


def test_reply_to_elsewhere_adds_two(conn):
    add(conn, "Sofie Hansen", ["sofie@molt.example"])
    r = ev(conn, "Sofie Hansen", "sofie.hansen@gmail.com", reply_to="pay@evil.example")
    assert r.symbols[0]["s"] == 7.0 and r.symbols[0]["o"][2] == "svar-til"
    # Reply-To to the same address or to an own domain is no combo.
    assert ev(conn, "Sofie Hansen", "m@gmail.com", reply_to="m@gmail.com").symbols[0]["s"] == 5.0
    assert ev(conn, "Sofie Hansen", "m@gmail.com", reply_to="sofie@molt.example").symbols[0]["s"] == 5.0


@pytest.mark.parametrize("subject", ["Er du ved din computer?", "Hurtig overførsel – haster", "Betaling haster",
                                     "Gavekort til kunder", "Urgent wire transfer", "Har du et øjeblik?",
                                     "Lille tjeneste", "Fortroligt: betaling i dag", "Are you available?",
                                     "Bankoverførsel straks"])
def test_lure_subject_adds_two(conn, subject):
    add(conn, "Rasmus Jensen", ["rasmus@bynet.example"])
    r = ev(conn, "Rasmus Jensen", "rasmusj@gmail.com", subject=subject)
    assert r.symbols[0]["s"] == 7.0 and "emne" in r.symbols[0]["o"][2]


@pytest.mark.parametrize("subject", ["Faktura 2026-118", "Din regning fra TDC", "Betaling modtaget", "Invoice 42",
                                     "Payment received", "Hurtig levering", "Overførsel af billeder",
                                     "Fwd: Din regning er klar", "Er du på kontoret i morgen?",
                                     "Har du tid til kaffe?", "Haster: mødet flyttes"])
def test_ordinary_billing_words_are_no_lure(conn, subject):
    add(conn, "Rasmus Jensen", ["rasmus@bynet.example"])
    r = ev(conn, "Rasmus Jensen", "rasmusj@gmail.com", subject=subject)
    assert r.symbols[0]["s"] == 5.0 and r.symbols[0]["o"][2] == "navn"


def test_rspamd_lure_symbols_and_combos_are_not_cumulative(conn):
    add(conn, "Rasmus Jensen", [])
    # rspamd's own lure symbols score themselves; they are no name-spoof combo.
    r = ev(conn, "Rasmus Jensen", "m@gmail.com", subject="Hej", names={"TH_LURE_SUBJECT"})
    assert r.symbols[0]["s"] == 5.0
    r = ev(conn, "Rasmus Jensen", "m@gmail.com", subject="Gavekort", reply_to="x@evil.example")
    assert r.symbols[0]["s"] == 7.0 and r.symbols[0]["o"][2] == "svar-til+emne"
    assert ev(conn, "Rasmus Jensen", "m@gmail.com", subject="Billeder fra i weekenden").symbols[0]["s"] == 5.0


def test_reply_to_same_domain_or_the_persons_domain_is_no_combo(conn):
    add(conn, "Molt Handel", ["info@molt.example", "ole@bynet.example"])
    # Another address in the From's own (non-freemail) domain: no combo.
    r = ev(conn, "Molt Handel", "no-reply@e-conomic.com", reply_to="support@e-conomic.com")
    assert r.symbols[0]["s"] == 5.0
    # Reply-To one of the person's domains (from an address listed for it).
    r = ev(conn, "Molt Handel", "no-reply@shop.example", reply_to="kontor@bynet.example")
    assert r.symbols[0]["s"] == 5.0
    # A freemail From: any other address counts, even on the same freemail domain.
    r = ev(conn, "Molt Handel", "molt.ms@gmail.com", reply_to="molt.pay@gmail.com")
    assert r.symbols[0]["s"] == 7.0 and r.symbols[0]["o"][2] == "svar-til"


# ----- 2.7 fix: the review's false positives (each must stay below 6) -----------------------


def _fp(conn):
    add(conn, "Molt Handel", ["info@molt.example"])
    add(conn, "Ole Storm", ["ole@bynet.example"])


@pytest.mark.parametrize("display,addr,subject,reply_to,dkim,score,flag", [
    # e-conomic sends the company's invoices in its name, replies go to the company.
    ("Molt Handel", "no-reply@e-conomic.com", "Faktura 1042 fra Molt Handel", "info@molt.example",
     ["e-conomic.com"], 5.0, "signeret"),
    ("Molt Handel", "no-reply@e-conomic.com", "Faktura 1042 fra Molt Handel", "info@molt.example",
     [], 5.0, "navn"),
    # A share notification from Google Docs, signed by google.com.
    ("Ole Storm (via Google Docs)", "drive-shares-dm-noreply@google.com", "Dokument: Faktura 2026", None,
     ["google.com"], 2.0, "platform"),
    # Ole's own iCloud address, which nobody listed yet.
    ("Ole Storm", "olestorm@icloud.com", "Fwd: Din regning fra TDC", None, ["icloud.com"], 5.0, "navn"),
    # MobilePay's receipt in the shop's name.
    ("Molt Handel via MobilePay", "noreply@mobilepay.dk", "Betaling modtaget", None, ["mobilepay.dk"],
     2.0, "platform"),
])
def test_review_false_positives_stay_below_six(conn, display, addr, subject, reply_to, dkim, score, flag):
    _fp(conn)
    r = ev(conn, display, addr, subject=subject, reply_to=reply_to, dkim=dkim)
    assert r.symbols[0]["s"] == score < 6 and r.symbols[0]["o"][2] == flag
    shadow = ev(conn, display, addr, mode="shadow", subject=subject, reply_to=reply_to, dkim=dkim)
    assert ns.score_of(shadow.symbols[0]) == score


def test_signed_platform_is_capped_even_with_reply_to_elsewhere(conn):
    _fp(conn)
    r = ev(conn, "Molt Handel", "no-reply@e-conomic.com", subject="Gavekort", reply_to="x@evil.example",
           dkim=["e-conomic.com"])
    assert r.symbols[0]["s"] == 5.0 and r.symbols[0]["o"][2] == "svar-til+emne+signeret"
    # A freemail signature caps nothing: anybody can sign with gmail.com.
    r = ev(conn, "Ole Storm", "ceo.ole@gmail.com", subject="Gavekort", dkim=["gmail.com"])
    assert r.symbols[0]["s"] == 7.0
    # "via" without the platform's own signature is an ordinary hit.
    r = ev(conn, "Ole Storm via Mobil", "x@evil.example", subject="Gavekort")
    assert r.symbols[0]["s"] == 7.0


def test_classic_ceo_fraud_still_reaches_seven(conn):
    _fp(conn)
    r = ev(conn, "Ole Storm", "ceo.ole@gmail.com", subject="Er du ved din computer? Jeg skal bruge gavekort")
    assert r.symbols[0]["s"] == 7.0 and r.symbols[0]["o"][2] == "emne"
    r = ev(conn, "Ole Storm", "ceo.ole@gmail.com", subject="Er du ved din computer? Jeg skal bruge gavekort",
           dkim=["gmail.com"])
    assert r.symbols[0]["s"] == 7.0


def test_platform_domains_need_the_exact_address(conn):
    add(conn, "Molt Handel", ["ordre@vexar.example", "@vexar.example", "info@molt.example"])
    kw = dict(own_domains=OWN, distrust=DISTRUST, mode="on", platform_domains=["vexar.example"])
    # OWN contains vexar.example, but a platform is never an own domain ...
    r = ns.evaluate(conn, raw=raw("Molt Handel", "noreply@vexar.example"), **kw)
    assert r.exempt is None and r.symbols[0]["n"] == "TH_NAME_SPOOF"
    # ... nor does a domain entry on it count: only the person's exact address.
    assert ns.evaluate(conn, raw=raw("Molt Handel", "ordre@vexar.example"), **kw).exempt == "address"
    assert ns.evaluate(conn, raw=raw("Molt Handel", "info@molt.example"), **kw).exempt == "address"
    assert ns.evaluate(conn, raw=raw("Molt Handel", "kontor@molt.example"), **kw).exempt == "own"
    # Without platform_domains the domain entry counts as before.
    assert ev(conn, "Molt Handel", "noreply@vexar.example").exempt == "domain"


def test_long_display_names_are_cut_before_matching(conn):
    add(conn, "Ole Storm")
    assert ev(conn, "Ole Storm " + "x" * 5000, "a@evil.example").hit is not None
    assert ev(conn, "x " * 200 + "Ole Storm", "a@evil.example").hit is None


# ----- 2.7 fix: odd From headers -------------------------------------------------------------


def _odd(conn, from_lines, **kw):
    hdr = "".join(f"From: {f}\r\n" for f in from_lines)
    return ns.evaluate(conn, raw=(hdr + "Subject: Hej\r\n\r\nx\r\n").encode(), own_domains=OWN,
                       distrust=DISTRUST, mode="on", **kw)


@pytest.mark.parametrize("froms", [
    ["Ole Storm <x@evil.example>,"],                               # trailing comma
    ["Ole Storm <x@evil.example>, garbage"],                       # garbage after a comma
    ["Ole Storm <a@x.example>, B <b@y.example>"],                  # two addresses
    ["Ole Storm <ole@bynet.example>", "Anyone <x@evil.example>"],      # two From headers
    ["Ole Storm ole@bynet.example <x@evil.example>"],                  # the real address in the name, unquoted
    ['"Ole Storm" <"ole@bynet.example"@evil.example>'],                # quoted local part
    ["Ole Storm <ole@bynet.example@evil.example>"],                    # two @
    ['<"ole@bynet.example"@evil.example>'],                             # the address in a quoted local part
    ["<ole@bynet.example@evil.example>"],
])
def test_odd_from_headers_are_a_strong_hit(conn, froms):
    add(conn, "Ole Storm", ["ole@bynet.example"])
    r = _odd(conn, froms, dkim_domains=["bynet.example"])
    assert r.exempt is None and r.symbols and r.symbols[0]["s"] == 7.0, r.symbols
    assert "ugyldig-afsender" in r.symbols[0]["o"][2]


def test_odd_from_without_a_protected_name_is_nothing(conn):
    add(conn, "Ole Storm", ["ole@bynet.example"])
    assert _odd(conn, ["Anna Jensen <a@x.example>, B <b@y.example>"]).hit is None
    assert _odd(conn, []).hit is None


def test_unambiguous_odd_from_needs_dkim_for_an_exception(conn):
    add(conn, "Ole Storm", ["ole@bynet.example"])
    # "[Molt]" is not valid RFC 5322 without quotes, but there is only one address.
    assert _odd(conn, ["Ole Storm [Molt] <ole@bynet.example>"], dkim_domains=["bynet.example"]).exempt == "address"
    r = _odd(conn, ["Ole Storm [Molt] <ole@bynet.example>"])
    assert r.exempt is None and r.symbols[0]["s"] == 7.0
    # Ordinary but unusual forms still parse strictly.
    for f in ("Ole Storm (Molt) <ole@bynet.example>", '"Storm, Ole" <ole@bynet.example>', "ole@bynet.example (Ole Storm)"):
        assert _odd(conn, [f]).exempt == "address", f


def test_shadow_records_without_score_and_off_does_nothing(conn):
    add(conn, "Ole Storm", ["ole@bynet.example"])
    r = ev(conn, "Ole Storm", "x@outlook.com", mode="shadow", reply_to="y@evil.example")
    assert r.symbols == [{"n": "TH_NAME_SPOOF_TRIAL", "s": 0.0, "o": ["Ole Storm", "x…@outlook.com", "svar-til"]}]
    assert r.events[0][0] == "namespoof_trial" and r.score == 7.0
    assert ns.score_of(r.symbols[0]) == 7.0
    off = ev(conn, "Ole Storm", "x@outlook.com", mode="off")
    assert off.symbols == [] and off.hit is None


def test_mode_defaults_to_shadow_and_is_stored(conn):
    assert ns.get_mode(conn) == {"mode": "shadow", "at": None, "by": "", "explicit": False}
    ns.touch_default(conn, 1000)
    assert ns.get_mode(conn)["at"] == 1000 and not ns.get_mode(conn)["explicit"]
    ns.touch_default(conn, 2000)
    assert ns.get_mode(conn)["at"] == 1000
    ns.set_mode(conn, "on", "admin", 3000)
    assert ns.get_mode(conn) == {"mode": "on", "at": 3000, "by": "admin", "explicit": True}
    with pytest.raises(ValueError):
        ns.set_mode(conn, "maybe", "admin", 1)
    add(conn, "Ole Storm")
    assert ns.evaluate(conn, raw=raw("Ole Storm", "x@outlook.com"))  .symbols[0]["n"] == "TH_NAME_SPOOF"


def test_no_display_name(conn):
    add(conn, "Ole Storm")
    assert ev(conn, "", "x@outlook.com").hit is None


def test_raw_utf8_and_encoded_comma(conn):
    add(conn, "Ole Storm")
    r = ns.evaluate(conn, raw=b"From: =?utf-8?q?Storm=2C_Ole?= <x@evil.example>\r\n\r\n", mode="on")
    assert r.hit is not None
    add(conn, "Søren Østergård")
    r = ns.evaluate(conn, raw="From: Søren Østergård <s@evil.example>\r\nSubject: Har du et øjeblik?\r\n\r\n"
                    .encode(), mode="on")
    assert r.symbols[0]["s"] == 7.0


def test_encoded_display_name(conn):
    add(conn, "Søren Østergård")
    r = ns.evaluate(conn, raw=b"From: =?utf-8?q?S=C3=B8ren_=C3=98sterg=C3=A5rd?= <s@evil.example>\r\n"
                              b"Subject: =?utf-8?q?Overf=C3=B8rsel_haster?=\r\n\r\n", mode="on")
    assert r.symbols[0]["s"] == 7.0 and r.symbols[0]["o"][0] == "Søren Østergård"


# ----- entry editor ---------------------------------------------------------------------------


def test_save_name_validation(conn):
    assert ns.save_name(conn, name="  ", allow="")["code"] == "invalid"
    bad = ns.save_name(conn, name="Ole Storm", allow="gmail.com nope@ @@x")
    assert bad["code"] == "invalid" and "gmail.com" in bad["invalid"]
    ok = ns.save_name(conn, name="Ole  Storm", allow="Ole@BYnet.example, @shop.example\nole.storm@gmail.com")
    assert ok["ok"] and ok["entry"]["name"] == "Ole Storm"
    assert ok["entry"]["allow"] == ["ole@bynet.example", "@shop.example", "ole.storm@gmail.com"]
    assert ns.save_name(conn, name="Ölé Storm", allow="")["code"] == "exists"
    eid = ok["entry"]["id"]
    assert ns.save_name(conn, entry_id=eid, name="Ole Storm", allow=ok["entry"]["allow"])["code"] == "unchanged"
    upd = ns.save_name(conn, entry_id=eid, name="Ole Storm", allow="", enabled=False)
    assert upd["ok"] and upd["entry"]["allow"] == [] and upd["entry"]["enabled"] is False
    assert ns.save_name(conn, entry_id=999, name="Xx Yy", allow="")["code"] == "not_found"


def test_allow_address_and_delete(conn):
    e = add(conn, "Ole Storm", ["ole@bynet.example"])
    res = ns.allow_address(conn, e["id"], "Ole.Privat@Gmail.com")
    assert res["code"] == "ok" and "ole.privat@gmail.com" in res["entry"]["allow"]
    assert ns.allow_address(conn, e["id"], "ole.privat@gmail.com")["code"] == "exists"
    assert ns.allow_address(conn, e["id"], "not an address")["code"] == "invalid"
    assert ns.delete_name(conn, e["id"])["name"] == "Ole Storm"
    assert ns.delete_name(conn, e["id"]) is None
    assert ns.allow_address(conn, e["id"], "a@b.dk")["code"] == "not_found"


# ----- seed from Sent ---------------------------------------------------------------------------


def _ident(conn, account, display, addr, n):
    conn.execute("INSERT INTO own_identities(account, display_name, addr, n, last_at) VALUES(?,?,?,?,?)",
                 (account, display, addr, n, 1))


def test_seed_from_own_identities(conn):
    _ident(conn, "bynet", "Ole Storm", "ole@bynet.example", 40)
    _ident(conn, "molt", "Ole Storm", "ole@molt.example", 12)
    _ident(conn, "molt-inge", "Inge", "inge@molt.example", 9)
    _ident(conn, "molt-sofie", "Sofie Hansen", "sofie@molt.example", 5)
    _ident(conn, "bynet", "Rasmus Jensen", "rasmus@bynet.example", 2)          # used too rarely
    _ident(conn, "bynet", "ole@bynet.example", "ole@bynet.example", 30)            # an address is no name
    _ident(conn, "bynet", "", "ole@bynet.example", 30)
    assert ns.seed(conn, 5000) == {"added": 3, "extended": 0}
    got = {e["name"]: e for e in ns.list_names(conn)}
    assert set(got) == {"Ole Storm", "Inge", "Sofie Hansen"}
    assert sorted(got["Ole Storm"]["allow"]) == ["ole@bynet.example", "ole@molt.example"]
    assert got["Ole Storm"]["source"] == "seed" and got["Ole Storm"]["enabled"]
    assert got["Inge"]["enabled"] is False and got["Inge"]["one_word"]   # one word: off until switched on
    # Idempotent; a new address of a known name is added once.
    assert ns.seed(conn, 5001) == {"added": 0, "extended": 0}
    _ident(conn, "bynet", "Ole Storm", "ole.storm@gmail.com", 3)
    assert ns.seed(conn, 5002) == {"added": 0, "extended": 1}
    assert "ole.storm@gmail.com" in ns.get_name(conn, got["Ole Storm"]["id"])["allow"]


def test_seed_never_brings_back_what_the_admin_removed(conn):
    _ident(conn, "molt-sofie", "Sofie Hansen", "sofie@molt.example", 5)
    ns.seed(conn, 1)
    e = ns.list_names(conn)[0]
    ns.save_name(conn, entry_id=e["id"], name=e["name"], allow="")          # admin removed the address
    ns.seed(conn, 2)
    assert ns.get_name(conn, e["id"])["allow"] == []
    ns.delete_name(conn, e["id"])
    ns.seed(conn, 3)
    assert ns.list_names(conn) == []
    _ident(conn, "molt", "Sofie Hansen", "sofie.h@molt.example", 4)              # even with a new address
    ns.seed(conn, 4)
    assert ns.list_names(conn) == []


def test_seed_extends_a_manual_entry_and_maybe_seed_is_hourly(conn):
    add(conn, "Rasmus Jensen", ["rasmus@bynet.example"])
    _ident(conn, "bynet", "Rasmus Jensen", "rasmus.j@bynet.example", 3)
    assert ns.maybe_seed(conn, 10_000) == {"added": 0, "extended": 1}
    assert ns.maybe_seed(conn, 10_100) is None
    assert ns.maybe_seed(conn, 10_000 + 3600) == {"added": 0, "extended": 0}
    assert ns.get_mode(conn)["at"] == 10_000                                 # the trial started with the first run


def test_seed_without_contact_tables_is_harmless():
    c = sqlite3.connect(":memory:", isolation_level=None)
    ns.ensure_schema(c)
    assert ns.seed(c, 1) == {"added": 0, "extended": 0}


# ----- admin hit list -------------------------------------------------------------------------


def test_hits_grouped_per_name_and_sender(conn):
    e = add(conn, "Ole Storm", ["ole@bynet.example"])
    trial = {"n": "TH_NAME_SPOOF_TRIAL", "s": 0.0, "o": ["Ole Storm", "c…@outlook.com", "svar-til"]}
    on = {"n": "TH_NAME_SPOOF", "s": 5.0, "o": ["Ole Storm", "c…@outlook.com", "navn"]}
    for i, (acc, sym) in enumerate([("bynet", trial), ("molt", trial), ("molt", on)]):
        conn.execute("INSERT INTO messages VALUES(?,?,?,?,?,?)",
                     (acc, f"m{i}@x", "Ole Storm <ceo@outlook.com>", json.dumps([sym]), 100 + i, 100))
    conn.execute("INSERT INTO messages VALUES('bynet','old@x','x@y.example',?,1,1)", (json.dumps([on]),))
    got = ns.hits(conn, 50)
    assert len(got) == 1
    g = got[0]
    assert g["sender"] == "ceo@outlook.com" and g["n"] == 3 and g["trial"] == 2 and g["on"] == 1
    assert sorted(g["accounts"]) == ["bynet", "molt"] and g["flags"] == ["svar-til"] and g["score"] == 7.0
    assert g["entry_id"] == e["id"] and g["allowed"] is False
    ns.allow_address(conn, e["id"], "ceo@outlook.com")
    assert ns.hits(conn, 50)[0]["allowed"] is True


def test_own_domains_never_include_freemail():
    assert ns.own_domains_of(["bynet.example", "gmail.com", "user@molt.example", "", "MOLT.EXAMPLE", "hotmail.com"]) == \
        ["bynet.example", "molt.example"]


def test_parse_allow():
    items, bad = ns.parse_allow(["@Shop.Example", "*.shop.example", "a@b.dk", "outlook.com", "x"])
    assert items == ["@shop.example", "a@b.dk"] and bad == ["outlook.com", "x"]
