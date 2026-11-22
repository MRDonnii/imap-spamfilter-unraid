"""ENGINE (2.7, Falske afsendernavne): TH_NAME_SPOOF in a live scan.

Prøv (the default) records TH_NAME_SPOOF_TRIAL (0) and the event
namespoof_trial without changing the score; Til adds +5 (+7 with a
Reply-To elsewhere or a lure subject), blocks every contact trust bonus
and is never a threat class. The person's real addresses and the owner's
own domains are exempt. The contact sync seeds the protected names from
the From identities in Sent."""

from __future__ import annotations

import datetime as dt
import json
import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import setup_engine  # noqa: E402
from test_engine_contacts import DMARC_OK, dkim, run_sync, sent_mail, sym, synced  # noqa: E402
from test_engine_scan import Harness  # noqa: E402

import namespoof as ns  # noqa: E402

LOG = logging.getLogger("test-namespoof")


@pytest.fixture
def eng(tmp_path, monkeypatch):
    import contacts

    contacts.forget_cached_keys()
    e = setup_engine(tmp_path, monkeypatch)
    monkeypatch.setattr(e, "LOOKALIKE_MAILBOX_DOMAINS", frozenset({"bynet.example", "molt.example"}))
    yield e
    contacts.forget_cached_keys()


def _h(eng, monkeypatch, **kw):
    kw.setdefault("threshold", 6.0)
    kw.setdefault("user", "inge@molt.example")
    return Harness(eng, monkeypatch, **kw)


def protect(h, name="Ole Storm", allow=("ole@bynet.example", "ole@molt.example"), mode=None):
    res = ns.save_name(h.db.conn, name=name, allow=list(allow), actor="admin", now=int(h.t))
    assert res["ok"], res
    if mode:
        ns.set_mode(h.db.conn, mode, "admin", int(h.t))
    return res["entry"]


def mail(h, msgid, display, addr, *, score=0.5, symbols=None, subject="Hej", extra=""):
    h.rspamd.scores[msgid] = score
    h.rspamd.symbols[msgid] = symbols or {}
    lines = ["Received: from mx1.example.net (mx1.example.net [192.0.2.10]) by mail.example.net",
             f'From: "{display}" <{addr}>', "To: inge@molt.example", f"Subject: {subject}", f"Message-ID: <{msgid}>",
             "Date: Tue, 20 Oct 2026 10:00:00 +0200"]
    if extra:
        lines.append(extra)
    h.client.add("INBOX", ("\r\n".join(lines) + "\r\n\r\nHej\r\n").encode(),
                 internaldate=dt.datetime.fromtimestamp(h.t, dt.timezone.utc))
    h.scan()
    return h.row(msgid)


def syms_of(row):
    return {s["n"]: s for s in json.loads(row["symbols"])}


def events(h, name):
    return [r for r in h.events() if r[0] == name]


def test_default_is_shadow_records_without_score(eng, monkeypatch):
    h = _h(eng, monkeypatch)
    protect(h)
    r = mail(h, "t1@x", "Ole Storm", "ceo.office@outlook.com", extra="Reply-To: <pay@evil.example>")
    s = syms_of(r)
    assert "TH_NAME_SPOOF" not in s
    assert s["TH_NAME_SPOOF_TRIAL"] == {"n": "TH_NAME_SPOOF_TRIAL", "s": 0.0,
                                        "o": ["Ole Storm", "c…@outlook.com", "svar-til"]}
    assert r["our_score"] == pytest.approx(0.5) and r["our_action"] == "none"
    ev = events(h, "namespoof_trial")
    assert len(ev) == 1 and "ceo.office" not in ev[0][2] and "+7" in ev[0][2]


def test_on_scores_and_moves_with_a_combo(eng, monkeypatch):
    h = _h(eng, monkeypatch)
    protect(h, mode="on")
    r = mail(h, "o1@x", "Ole Storm", "ceo.office@outlook.com", subject="Er du ved din computer?")
    s = syms_of(r)["TH_NAME_SPOOF"]
    assert s["s"] == 7.0 and s["o"] == ["Ole Storm", "c…@outlook.com", "emne"]
    assert r["our_score"] == pytest.approx(7.5) and r["our_action"] == "pending_move"
    assert r["threat"] is None                          # score only, never a threat class
    assert events(h, "namespoof_hit")
    # The name alone (+5) on a clean mail stays below the threshold.
    r = mail(h, "o2@x", "Ole Storm", "ole.newaddress@outlook.com")
    assert syms_of(r)["TH_NAME_SPOOF"]["s"] == 5.0 and r["our_action"] == "none"


def test_rspamd_lure_symbol_is_no_combo(eng, monkeypatch):
    # 2.7 fix: TH_LURE_SUBJECT scores on its own; it no longer raises the name hit.
    h = _h(eng, monkeypatch)
    protect(h, mode="on")
    r = mail(h, "l1@x", "Ole Storm", "x@outlook.com", symbols=sym("TH_LURE_SUBJECT", 1.5))
    assert syms_of(r)["TH_NAME_SPOOF"]["s"] == 5.0


def test_billing_mail_in_a_protected_name_is_not_moved(eng, monkeypatch):
    # 2.7 fix (review): e-conomic invoice in the company's name, replies to the company.
    h = _h(eng, monkeypatch)
    protect(h, name="Molt Handel", allow=("info@molt.example",), mode="on")
    r = mail(h, "b1@x", "Molt Handel", "no-reply@e-conomic.com", score=0.5, symbols=dkim("e-conomic.com"),
             subject="Faktura 1042 fra Molt Handel", extra="Reply-To: info@molt.example")
    s = syms_of(r)["TH_NAME_SPOOF"]
    assert s["s"] == 5.0 and s["o"][2] == "signeret" and r["our_action"] == "none"


def test_platform_domain_needs_the_exact_address(eng, monkeypatch):
    # vexar.example (owner_platform_domains / webshop_domains) is multi-tenant: no own-domain exception.
    h = _h(eng, monkeypatch)
    protect(h, name="Molt Handel", allow=("ordre@vexar.example",), mode="on")
    assert "vexar.example" in eng.namespoof_platform_domains(h.acc)
    assert "vexar.example" not in eng.namespoof_own_domains(h.acc)
    assert "molt.example" in eng.namespoof_own_domains(h.acc)
    r = mail(h, "p1@x", "Molt Handel", "noreply@vexar.example", symbols=dkim("vexar.example"))
    assert syms_of(r)["TH_NAME_SPOOF"]["s"] == 5.0
    r = mail(h, "p2@x", "Molt Handel", "ordre@vexar.example", symbols=dkim("vexar.example"))
    assert "TH_NAME_SPOOF" not in syms_of(r)


def test_calibration_blocks_trust_like_the_live_scan(tmp_path, monkeypatch):
    # 2.7 fix (L6): trainer.scan_scored runs the name-spoof check and passes
    # TH_NAME_SPOOF on, so a fraudster the user answered gets no trust there either.
    import contacts
    import trainer

    contacts.forget_cached_keys()
    e = setup_engine(tmp_path, monkeypatch)
    monkeypatch.setattr(e, "LOOKALIKE_MAILBOX_DOMAINS", frozenset({"bynet.example", "molt.example"}))
    h = synced(e, monkeypatch, [sent_mail("s1@x", "ceo.office@outlook.com", sender="inge@molt.example"),
                                sent_mail("s2@x", "ceo.office@outlook.com", sender="inge@molt.example")],
               user="inge@molt.example", threshold=6.0)
    protect(h, mode="on")
    raw = ('From: "Ole Storm" <ceo.office@outlook.com>\r\nTo: inge@molt.example\r\nSubject: Gavekort\r\n'
           "Message-ID: <cal1@x>\r\nDate: Tue, 20 Oct 2026 10:00:00 +0200\r\n\r\nHej\r\n").encode()
    h.rspamd.scores["cal1@x"] = 1.0
    h.rspamd.symbols["cal1@x"] = DMARC_OK
    _res, all_syms, final, _aged = trainer.scan_scored(e, h.acc, raw, {}, None, h.db.conn)
    names = {s["n"]: s for s in all_syms}
    assert names["TH_NAME_SPOOF"]["s"] == 7.0 and "TH_KNOWN_CONTACT" not in names
    assert final == pytest.approx(8.0)
    contacts.forget_cached_keys()


def test_real_address_own_domain_and_unrelated_names(eng, monkeypatch):
    h = _h(eng, monkeypatch)
    protect(h, mode="on")
    for i, (display, addr) in enumerate([("Ole Storm", "ole@bynet.example"), ("Ole Storm", "ordre@molt.example"),
                                         ("Ole Smith", "ole@outlook.com"), ("Ole", "ole@outlook.com"),
                                         ("Olav Stormgaard", "os@outlook.com")]):
        r = mail(h, f"x{i}@x", display, addr, symbols=dkim("bynet.example") if "bynet" in addr else None)
        assert not {"TH_NAME_SPOOF", "TH_NAME_SPOOF_TRIAL"} & set(syms_of(r)), (display, addr)


def test_forged_own_address_is_not_exempt(eng, monkeypatch):
    h = _h(eng, monkeypatch)
    protect(h, mode="on")
    r = mail(h, "f1@x", "Ole Storm", "ole@bynet.example", symbols=sym("DMARC_POLICY_QUARANTINE", 1.5))
    assert syms_of(r)["TH_NAME_SPOOF"]["s"] == 5.0


def test_off_does_nothing(eng, monkeypatch):
    h = _h(eng, monkeypatch)
    protect(h, mode="off")
    r = mail(h, "n1@x", "Ole Storm", "x@outlook.com")
    assert not {"TH_NAME_SPOOF", "TH_NAME_SPOOF_TRIAL"} & set(syms_of(r))


def test_on_blocks_contact_trust_shadow_does_not(eng, monkeypatch):
    # The user answered the fraudster twice: a known contact now.
    h = synced(eng, monkeypatch, [sent_mail("s1@x", "ceo.office@outlook.com", sender="inge@molt.example"),
                                  sent_mail("s2@x", "ceo.office@outlook.com", sender="inge@molt.example")],
               user="inge@molt.example", threshold=6.0)
    protect(h)
    r = mail(h, "c1@x", "Ole Storm", "ceo.office@outlook.com", score=1.0, symbols=DMARC_OK)
    assert "TH_KNOWN_CONTACT" in syms_of(r) and "TH_NAME_SPOOF_TRIAL" in syms_of(r)
    ns.set_mode(h.db.conn, "on", "admin", int(h.t))
    r = mail(h, "c2@x", "Ole Storm", "ceo.office@outlook.com", score=1.0, symbols=DMARC_OK,
             subject="Betaling haster")
    s = syms_of(r)
    assert "TH_KNOWN_CONTACT" not in s and s["TH_NAME_SPOOF"]["s"] == 7.0
    assert r["our_score"] == pytest.approx(8.0) and r["our_action"] == "pending_move"


def test_name_spoof_is_never_learned_as_ham(eng):
    assert "TH_NAME_SPOOF" in eng.HAM_GUARD_SYMBOLS and "TH_NAME_SPOOF_TRIAL" not in eng.HAM_GUARD_SYMBOLS


def test_contact_sync_seeds_the_names(eng, monkeypatch):
    sent = [sent_mail(f"s{i}@x", "kunde@firma.example", sender="ole@bynet.example", name="Ole Storm")
            for i in range(3)]
    h = synced(eng, monkeypatch, sent, user="ole@bynet.example", threshold=6.0)
    names = ns.list_names(h.db.conn)
    assert [(e["name"], e["allow"], e["source"]) for e in names] == [("Ole Storm", ["ole@bynet.example"], "seed")]
    assert events(h, "namespoof_seeded")
    assert ns.get_mode(h.db.conn)["mode"] == "shadow" and ns.get_mode(h.db.conn)["at"]
    # Hourly: a second sync slice does not seed again.
    h.client.add("Sent", sent_mail("s9@x", "a@b.example", sender="ole@bynet.example", name="Ole Storm"))
    run_sync(h)
    assert len(events(h, "namespoof_seeded")) == 1


def test_scan_survives_a_broken_namespoof_module(eng, monkeypatch):
    h = _h(eng, monkeypatch)

    class Broken:
        def evaluate(self, *a, **k):
            raise RuntimeError("boom")

    monkeypatch.setattr(eng, "_namespoof", lambda: Broken())
    r = mail(h, "b1@x", "Ole Storm", "x@outlook.com")
    assert r["our_score"] == pytest.approx(0.5)
