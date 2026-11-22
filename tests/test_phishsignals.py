"""2.13 phishing signals (filter/phishsignals.py): mixed scripts in the
subject, newly registered domains (RDAP) and payment/account phishing."""

from __future__ import annotations

import sqlite3
import sys
import time
from email.message import EmailMessage
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "filter"))

import filter as eng  # noqa: E402
import phishsignals as ps  # noqa: E402
import trialmode  # noqa: E402

ACC = SimpleNamespace(name="bynet", user="ole@bynet.example", protected_recipients=["info@gravisk.example"])
DAY = 86400


def mail(subject: str, sender: str = "Service <support@example.com>", reply_to: str = "") -> bytes:
    m = EmailMessage()
    m["From"] = sender
    m["To"] = "ole@bynet.example"
    m["Subject"] = subject
    if reply_to:
        m["Reply-To"] = reply_to
    m.set_content("Hej")
    return m.as_bytes()


@pytest.fixture
def conn(tmp_path, monkeypatch):
    monkeypatch.setattr(eng, "STATE_DIR", tmp_path)
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE engine_state(key TEXT PRIMARY KEY, value TEXT, updated_at INTEGER)")
    return c


def by_name(syms):
    return {s["n"]: s for s in syms}


# ------------------------------------------------------------------ mixed scripts

@pytest.mark.parametrize("subject,hit", [
    ("Haster: Dоmænеnаvnеt tservice.dk еr blеvеt blоkеrеt.", True),     # Cyrillic о, е, а
    ("Оpmærksomhed: Domænenavnet ordskilte.dk er blevet blokeret", True),  # Cyrillic О first
    ("Pаypal: konto låst", True),                                          # one Cyrillic а
    ("Привет, как дела?", False),                                          # all Cyrillic
    ("Καλημέρα", False),                                                   # all Greek
    ("Mødet på fredag – 10 % rabat", False),
    ("Søren's café naïve façade", False),                                  # Latin with diacritics
])
def test_mixed_words(subject, hit):
    assert bool(ps.mixed_words(subject)) is hit


def test_mixed_script_scores_in_til_and_only_registers_in_prove(conn):
    raw = mail("Haster: Dоmænеnаvnеt er blokeret")
    syms, events = ps.judge(conn, ACC, raw, set())
    assert by_name(syms)["TH_SUBJECT_MIXED_SCRIPT"]["s"] == ps.MIXED_SCORE
    assert ("mixscript_hit" in {e for e, _ in events})
    trialmode.set_mode(conn, "mixscript", "shadow", "test")
    syms, events = ps.judge(conn, ACC, raw, set())
    s = by_name(syms)["TH_SUBJECT_MIXED_SCRIPT_TRIAL"]
    assert s["s"] == 0.0 and s["o"][0] == "+5"
    assert {e for e, _ in events} >= {"mixscript_trial"}
    for f in ("mixscript", "domainage", "payphish"):
        trialmode.set_mode(conn, f, "off", "test")
    assert ps.judge(conn, ACC, raw, set()) == ([], [])


def test_new_features_default_to_til(conn):
    for f in ("mixscript", "domainage", "payphish"):
        assert trialmode.get(conn, f)["mode"] == "on"
    assert trialmode.get(conn, "qr")["mode"] == "shadow"     # 2.8 features unchanged


# ------------------------------------------------------------------ payment phishing

MISSED = [
    "Påmindelse: Opdater dine betalingsoplysninger",
    "Please Verify Your Contact Information for Continued Payment",
    "Dit opsagte domænenavn er ikke længere aktivt.",
    "Din GLS-forsendelse er klar – Betaling kræves for levering",
    "Your Premium Access is Ending Soon",
    "Your Prime membership is Renewing on Sun, March 01, 2026",
    "Domænenavnet molt.example er suspenderet.",
    "Din Konto MitID",
    "Ny notifikation vedrørende din udbetaling",
    "Meddelelse om Gennemgang af Intellektuel Ejendomsret og Brug",
    "Dit abonnement afbrydes snart",
    "Spotify : Action Required !",
    "Your Spotify Premium payment needs attention",
]
NOT_LURES = [
    "Din ordre er afsendt", "Faktura 2291 – service på fyr", "Re: Billeder fra sommerhuset",
    "Nyhedsbrev november", "Black Friday: 50 % på alt", "Mødeindkaldelse tirsdag",
    "Din pakke er på vej", "Kvittering for dit køb",
]


@pytest.mark.parametrize("subject", MISSED)
def test_missed_phishing_subjects_are_lures(subject):
    assert ps.pay_lure(subject, set())


@pytest.mark.parametrize("subject", NOT_LURES)
def test_everyday_subjects_are_not_lures(subject):
    assert not ps.pay_lure(subject, set())


def test_pay_phish_needs_a_risk_sign(conn):
    # A real service: DMARC pass, its own domain, no Reply-To elsewhere -> nothing.
    raw = mail("Your Spotify Premium payment needs attention", "Spotify <no-reply@spotify.com>")
    syms, _ = ps.judge(conn, ACC, raw, {"DMARC_POLICY_ALLOW", "R_DKIM_ALLOW"})
    assert "TH_PAY_PHISH" not in by_name(syms)
    # The same subject from a freemail sender without DMARC: two risk signs -> +5.
    raw = mail("Your Spotify Premium payment needs attention", "Spotify <kontakt123@gmail.com>")
    syms, events = ps.judge(conn, ACC, raw, {"FREEMAIL_FROM"})
    s = by_name(syms)["TH_PAY_PHISH"]
    assert s["s"] == 5.0 and "gratis mailadresse" in s["o"] and "ingen DMARC-godkendelse" in s["o"]
    assert any(e == "payphish_hit" for e, _ in events)


def test_late_scan_provider_auth_counts_as_dmarc(conn):
    raw = mail("Dit abonnement afbrydes snart", "Service <info@example.com>")
    assert "TH_PAY_PHISH" not in by_name(ps.judge(conn, ACC, raw, {"TH_PROVIDER_AUTH_PASS"})[0])
    assert "TH_PAY_PHISH" in by_name(ps.judge(conn, ACC, raw, set())[0])


def test_pay_phish_counts_reply_to_elsewhere_and_caps_at_six(conn):
    raw = mail("Opdater dine betalingsoplysninger", "Netflix <info@netf1ix-billing.store>",
               reply_to="svar@andet-domaene.example")
    syms, _ = ps.judge(conn, ACC, raw, {"TH_FROM_ABUSED_TLD", "TH_FROM_NAME_HOMOGLYPH"})
    s = by_name(syms)["TH_PAY_PHISH"]
    assert s["s"] == 6.0 and len(s["o"]) == 3


def test_strong_lure_symbol_counts_as_a_lure(conn):
    syms, _ = ps.judge(conn, ACC, mail("Hej"), {"TH_LURE_SUBJECT_STRONG", "FREEMAIL_FROM", "DMARC_POLICY_ALLOW"})
    assert by_name(syms)["TH_PAY_PHISH"]["s"] == 4.0


# ------------------------------------------------------------------ domain age

def test_new_domain_points(conn, monkeypatch):
    now = time.time()
    created = {"fresh.com": now - 3 * DAY, "month.com": now - 20 * DAY, "old.com": now - 900 * DAY}
    monkeypatch.setattr(ps, "domain_created", lambda d, now=None: created.get(d))
    s = by_name(ps.judge(conn, ACC, mail("Hej", "a@mail.fresh.com"), set())[0])["TH_NEW_DOMAIN"]
    assert s["s"] == 4.5 and s["o"] == ["fresh.com", "3 dage"]
    assert by_name(ps.judge(conn, ACC, mail("Hej", "a@month.com"), set())[0])["TH_NEW_DOMAIN"]["s"] == 3.0
    assert ps.judge(conn, ACC, mail("Hej", "a@old.com"), set())[0] == []
    # a new domain is also a payment-phishing risk sign
    syms, _ = ps.judge(conn, ACC, mail("Dit abonnement afbrydes snart", "a@month.com"), {"DMARC_POLICY_ALLOW"})
    assert "domæne 20 dage gammelt" in by_name(syms)["TH_PAY_PHISH"]["o"]


def test_freemail_and_own_domains_are_never_looked_up(conn, monkeypatch):
    asked = []
    monkeypatch.setattr(ps, "domain_created", lambda d, now=None: asked.append(d))
    for sender in ("x@gmail.com", "y@hotmail.dk", "ole@bynet.example", "z@gravisk.example"):
        ps.judge(conn, ACC, mail("Hej", sender), set())
    assert asked == []


class FakeResp:
    def __init__(self, status, data=None):
        self.status_code, self._data = status, data
        self.ok = 200 <= status < 300

    def json(self):
        return self._data

    def raise_for_status(self):
        if not self.ok:
            raise RuntimeError(self.status_code)


def test_rdap_lookup_bootstrap_cache_and_rate_limit(conn, monkeypatch, tmp_path):
    import requests

    calls = []
    boot = {"services": [[["com"], ["https://rdap.example/com/v1/"]], [["store"], ["http://insecure/"]]]}

    def get(url, timeout=None, headers=None):
        calls.append(url)
        if url == ps.RDAP_BOOTSTRAP_URL:
            return FakeResp(200, boot)
        if url.endswith("/domain/new.com"):
            return FakeResp(200, {"events": [{"eventAction": "registration", "eventDate": "2026-11-20T10:00:00Z"}]})
        return FakeResp(404)

    monkeypatch.setattr(requests, "get", get)
    monkeypatch.setattr(ps, "_RDAP_DISABLED", False)
    monkeypatch.setattr(ps, "_bootstrap", {})
    monkeypatch.setattr(ps, "_lookups", ps.deque())
    now = 1795000000.0  # 2026-11-17
    from datetime import datetime, timezone

    want = int(datetime(2026, 11, 20, 10, tzinfo=timezone.utc).timestamp())
    assert ps.domain_created("new.com", now) == want
    n = len(calls)
    assert ps.domain_created("new.com", now + 60) is not None and len(calls) == n      # cached
    assert ps.domain_created("gone.com", now) is None                                 # 404
    assert ps.domain_created("x.store", now) is None                                  # no https server
    assert ps.domain_created("x.dk", now) is None                                     # no RDAP
    assert (tmp_path / "rdap-cache.db").exists() and (tmp_path / "rdap-dns.json").exists()
    st = dict(sqlite3.connect(tmp_path / "rdap-cache.db").execute("SELECT domain, status FROM domain_age"))
    assert st["gone.com"] == "not_found" and st["x.dk"] == "no_rdap" and st["new.com"] == "ok"
    # rate limit: no more lookups once the window is full, and that is "unknown"
    monkeypatch.setattr(ps, "_lookups", ps.deque([now] * ps.RDAP_MAX_LOOKUPS))
    before = len(calls)
    assert ps.domain_created("other.com", now) is None and len(calls) == before


def test_judge_never_raises(conn, monkeypatch):
    monkeypatch.setattr(ps, "_subject", lambda raw: 1 / 0)
    assert ps.judge(conn, ACC, b"garbage", set()) == ([], [])


def test_trial_symbols_include_the_new_signals(conn):
    res = SimpleNamespace(symbols=[], options={}, names=frozenset())
    syms, events = eng.trial_symbols(conn, ACC, mail("Dоmænеnаvnеt er blokeret"), res, set())
    assert "TH_SUBJECT_MIXED_SCRIPT" in by_name(syms)


# ------------------------------------------------------------------ WebUI (2.13)

def test_explanations_name_what_the_rule_saw():
    import ui_kit as kit

    t = kit.explain_symbol_detail({"n": "TH_SUBJECT_MIXED_SCRIPT", "o": ["Dоmænеnаvnеt"]})
    assert "“Dоmænеnаvnеt”" in t and "(а, е, о)" in t and "russiske" in t
    t = kit.explain_symbol_detail({"n": "TH_SUBJECT_MIXED_SCRIPT_TRIAL", "o": ["+5", "Dоmæne"]})
    assert t.startswith("Prøv (ville give 5 point): ")
    assert kit.explain_symbol_detail({"n": "TH_NEW_DOMAIN", "o": ["fresh.com", "3 dage"]}) == \
        "Afsenderdomænet fresh.com blev registreret for 3 dage siden (ifølge domæneregistret)"
    t = kit.explain_symbol_detail({"n": "TH_PAY_PHISH_TRIAL", "o": ["+4.5", "gratis mailadresse"]})
    assert t.startswith("Prøv (ville give 4,5 point): ") and t.endswith("faretegn: gratis mailadresse")
    for n in ("TH_SUBJECT_MIXED_SCRIPT", "TH_NEW_DOMAIN", "TH_PAY_PHISH"):
        assert not kit.explain_symbol(n).startswith("Teknisk regel")
        assert not kit.explain_symbol(n + "_TRIAL").startswith("Teknisk regel")


def test_protections_card_lists_the_newest_finds(tmp_path, monkeypatch):
    from fakes_ui import insert_message, login
    from fakes_ui_admin import make_admin_env

    e = make_admin_env(tmp_path, monkeypatch)
    now = int(time.time())
    insert_message(e.conn, "bynet", "<pp1@x>", sender="Spotify <kontakt@gmail.com>",
                   subject="Your Spotify <b>payment</b> needs attention", our_action="moved_to_junk")
    e.conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES('bynet', ?, '<pp1@x>', "
                   "'payphish_hit', 'TH_PAY_PHISH 5 gratis mailadresse')", (now - 60,))
    e.conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES('bynet', ?, '<pp1@x>', "
                   "'payphish_hit', 'TH_PAY_PHISH 5 again')", (now - 30,))   # one row per mail
    e.conn.commit()
    client = e.app.test_client()
    assert login(client).status_code == 302
    html = client.get("/settings").get_data(as_text=True)
    i = html.index("Betalings- og kontophishing")
    card = html[i:i + 3000]
    assert "Seneste fund (1)" in card and "Your Spotify &lt;b&gt;payment&lt;/b&gt; needs attention" in card
    assert "kontakt@gmail.com" in card and "point" in card and "Sidste 7 dage: 1 mail med point" in card
    assert "Snydetegn i emnet" in html and "Nyregistrerede domæner" in html
    assert "Ingen fund de sidste 30 dage." in html
