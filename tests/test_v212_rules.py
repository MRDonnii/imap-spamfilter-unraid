"""Spamfilter 2.12, part 2: DMARC "Klar (lav volumen)" (#6), rules versus the
user's own moves to Junk (#8 conflicts, #9 per-mailbox block after three
moves), legitimate newsletters are never learned as spam (#9) and Kontrolrum
SSO with the real person (#10)."""

from __future__ import annotations

import json
import logging
import time

import pytest

from fakes_engine import setup_engine  # noqa: E402
from test_engine_scan import Harness  # noqa: E402

import dmarc  # noqa: E402
import junkrules  # noqa: E402

LOG = logging.getLogger("test-212-rules")
DAY = 86400
NOW = 1_800_000_000


@pytest.fixture
def eng(tmp_path, monkeypatch):
    e = setup_engine(tmp_path, monkeypatch)
    import contacts

    contacts.forget_cached_keys()
    yield e
    contacts.forget_cached_keys()


# ---------------------------------------------------------------- #6 DMARC low volume

def _dom(**over):
    d = {"domain": "bynet.example", "reports": 4, "reports30": 4, "total": 6, "passed": 6, "pct": 100.0,
         "total14": 2, "pct14": 100.0, "days14": 2, "first_ts": NOW - 31 * DAY, "policy": "none",
         "policy_pct": 100, "unknown": [], "sources": [{"ip": ip, "total": 3, "passed": 3, "status": "godkendt", "tone": "ok"}
                                for ip in ("192.0.2.1", "192.0.2.2")]}
    d.update(over)
    return d


def test_low_volume_ready_after_30_days_with_only_known_passing_sources():
    adv = dmarc.recommendation(_dom(), now=NOW)
    assert adv["code"] == "ready_quarantine_low" and adv["tone"] == "ok"
    assert adv["label"] == "Klar (lav volumen)" and adv["text"].startswith("Klar (lav volumen): bynet.example")
    assert "p=quarantine" in adv["text"] and "alle 6 mails fra 2 kilder" in adv["text"]


@pytest.mark.parametrize("over", [
    {"first_ts": NOW - 29 * DAY},                       # under 30 days of data
    {"passed": 5},                                      # one failing source (also a spoofer counts)
    {"total": 0, "passed": 0, "pct": None},            # nothing reported in 30 days
    {"reports30": 0},
])
def test_low_volume_needs_30_days_and_every_source_passing(over):
    assert dmarc.recommendation(_dom(**over), now=NOW)["code"] in ("collect", "spoofed_only")


def test_low_volume_never_hides_unknown_sources():
    adv = dmarc.recommendation(_dom(unknown=[{"ip": "198.51.100.9", "total": 3}]), now=NOW)
    assert adv["code"] == "check_sources"


def test_low_volume_next_steps_under_quarantine():
    assert dmarc.recommendation(_dom(policy="quarantine"), now=NOW)["code"] == "ready_reject_low"
    assert dmarc.recommendation(_dom(policy="quarantine", policy_pct=25), now=NOW)["code"] == "raise_pct_low"
    assert dmarc.recommendation(_dom(policy="reject"), now=NOW)["code"] == "collect"


def test_normal_criterion_is_unchanged():
    adv = dmarc.recommendation(_dom(days14=8), now=NOW)
    assert adv["code"] == "ready_quarantine" and "label" not in adv


def test_low_volume_from_the_database():
    import sqlite3

    conn = sqlite3.connect(":memory:")
    dmarc.ensure_schema(conn)
    for i, day in enumerate((40, 20, 3)):
        rep = dmarc.Report(org_name="google.com", org_email="noreply@google.com", report_id=f"r{i}",
                           date_begin=NOW - day * DAY - DAY, date_end=NOW - day * DAY, domain="bynet.example",
                           policy_p="none", policy_pct=100)
        rep.records.append(dmarc.Record(source_ip="192.0.2.1", count=2, disposition="none", dkim="pass",
                                        spf="pass", header_from="bynet.example", envelope_from="bynet.example",
                                        dkim_domain="bynet.example", dkim_result="pass", spf_domain="bynet.example",
                                        spf_result="pass"))
        dmarc.store(conn, "bynet", f"m{i}@x", rep, now=NOW)
    d = [s for s in dmarc.summaries(conn, now=NOW) if s["domain"] == "bynet.example"][0]
    assert d["days14"] == 1 and d["advice"]["code"] == "ready_quarantine_low", d["advice"]


def test_dmarc_page_shows_the_low_volume_badge(monkeypatch):
    import ui_dmarc

    d = _dom()
    d.update(advice=dmarc.recommendation(d, now=NOW), last_ts=NOW, orgs=1)
    import dashboard

    with dashboard.app.test_request_context("/"):
        html = ui_dmarc._domain_card(d)
    assert "Anbefaling: Klar (lav volumen)" in html and html.count("Klar (lav volumen)") >= 2


# ---------------------------------------------------------------- #8 / #9 engine

SENDER = "nyhed@perfectjeans.example"


def _harness(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="move", folders=("INBOX", "Junk", "Trash"),
                junk="Spamfilter", junk_explicit=True)
    h.poll()                                                       # first sight of the spam folders
    return h


AUTHED = {"DMARC_POLICY_ALLOW": {"name": "DMARC_POLICY_ALLOW", "score": -0.5, "options": []}}


def _junk_one(h, mid, sender=SENDER, symbols=None, **kw):
    h.rspamd.symbols.setdefault(mid, dict(AUTHED if symbols is None else symbols))
    h.deliver(mid, score=2.0, sender=sender, **kw)
    h.scan()
    h.advance(600)
    h.user_moves(mid, "INBOX", "Spamfilter")
    h.poll()


def _rules(h):
    return [dict(r) for r in h.db.conn.execute("SELECT * FROM sender_rules ORDER BY id")]


def test_third_move_to_junk_is_a_suggestion_when_automation_is_disabled(eng, monkeypatch):
    # Disabling the owner-approved 2.18 automation keeps the earlier suggestion workflow.
    assert junkrules.AUTO_BLOCK is False
    h = _harness(eng, monkeypatch)
    h.acc.auto_block_repeated_spam = False
    for i in range(3):
        _junk_one(h, f"q{i}@x")
    assert _rules(h) == [] and not h.events("junk_auto_block") and h.events("junk_block_suggested")
    note = junkrules.get(h.db.conn, h.acc.name, SENDER, "suggest")
    assert note["status"] == "open" and note["n_junk"] == 3


def test_third_move_to_junk_blocks_the_sender_for_that_mailbox_only(eng, monkeypatch):
    monkeypatch.setattr(junkrules, "AUTO_BLOCK", True)            # only when the owner turns it on
    h = _harness(eng, monkeypatch)
    _junk_one(h, "p1@x")
    _junk_one(h, "p2@x")
    assert _rules(h) == [] and not h.events("junk_auto_block")
    _junk_one(h, "p3@x")
    rules = _rules(h)
    assert len(rules) == 1
    r = rules[0]
    assert (r["account"], r["pattern"], r["kind"], r["created_by"]) == (h.acc.name, SENDER, "block", "auto:junk")
    note = junkrules.get(h.db.conn, h.acc.name, SENDER, "suggest")
    assert note["status"] == "auto_blocked" and note["block_rule_id"] == r["id"] and note["n_junk"] == 3
    assert h.events("junk_auto_block")
    # Nothing already in the mailbox is touched: the three mails stay where the user put them.
    assert {h.row(m)["current_folder"] for m in ("p1@x", "p2@x", "p3@x")} == {"Spamfilter"}
    # A new mail from the sender: the rule acts (moved to the spam folder later, never deleted).
    h.deliver("p4@x", score=2.0, sender=SENDER)
    h.scan()
    assert h.row("p4@x")["rule_hit"] == f"block:{r['id']}" and h.row("p4@x")["our_action"] == "pending_move"


@pytest.mark.parametrize("symbols", [
    {},                                                                       # nothing proves the From
    {"R_DKIM_ALLOW": {"name": "R_DKIM_ALLOW", "score": -0.2, "options": ["other-esp.example:s=k1"]}},
    {"DMARC_POLICY_ALLOW": {"name": "DMARC_POLICY_ALLOW", "score": -0.5},
     "R_SPF_SOFTFAIL": {"name": "R_SPF_SOFTFAIL", "score": 0.5}},           # a spoof sign wins
    {"TH_PROVIDER_AUTH_SPOOF": {"name": "TH_PROVIDER_AUTH_SPOOF", "score": 0.0}},
])
def test_moves_of_an_unproven_from_do_not_count(eng, monkeypatch, symbols):
    # Review 2.12: phishing with a forged From must not make the real
    # sender a block suggestion.
    monkeypatch.setattr(junkrules, "AUTO_BLOCK", True)
    h = _harness(eng, monkeypatch)
    for i in range(3):
        _junk_one(h, f"f{i}@x", symbols=symbols)
    assert _rules(h) == [] and junkrules.get(h.db.conn, h.acc.name, SENDER, "suggest") is None
    assert junkrules.count_moves(h.db.conn, h.acc.name, SENDER, now=int(h.t)) == 0


def test_aligned_dkim_counts(eng):
    syms = json.dumps([{"n": "R_DKIM_ALLOW", "s": -0.2, "o": ["mail.perfectjeans.example:s=k1"]}])
    assert eng.from_authenticated(syms, SENDER)
    assert not eng.from_authenticated(syms, "x@other.example")
    assert eng.from_authenticated(json.dumps([{"n": "TH_PROVIDER_AUTH_PASS", "s": -1}]), SENDER)
    assert not eng.from_authenticated(None, SENDER) and not eng.from_authenticated("[]", SENDER)


def test_moves_do_not_count_without_learn_from_moves(eng, monkeypatch):
    monkeypatch.setattr(junkrules, "AUTO_BLOCK", True)
    h = Harness(eng, monkeypatch, mode="move", folders=("INBOX", "Junk", "Trash"),
                junk="Spamfilter", junk_explicit=True, learn_from_moves=False)
    h.poll()
    for i in range(3):
        _junk_one(h, f"l{i}@x")
    assert _rules(h) == [] and junkrules.get(h.db.conn, h.acc.name, SENDER, "suggest") is None


def test_the_same_mail_seen_twice_counts_once(eng, monkeypatch):
    h = _harness(eng, monkeypatch)
    conn = h.db.conn
    for _ in range(3):
        junkrules.on_user_junk(conn, h.acc.name, SENDER, "same@x", now=NOW, add_rule=eng.add_sender_rule)
    assert junkrules.count_moves(conn, h.acc.name, SENDER, now=NOW) == 1 and _rules(h) == []


def test_moves_count_per_mailbox(eng, monkeypatch):
    h = _harness(eng, monkeypatch)
    conn = h.db.conn
    for i, acc in enumerate(("a", "b", "a", "b")):
        junkrules.on_user_junk(conn, acc, SENDER, f"m{i}@x", now=NOW, add_rule=eng.add_sender_rule,
                               auto_block=True)
    assert _rules(h) == []
    junkrules.on_user_junk(conn, "a", SENDER, "m9@x", now=NOW, add_rule=eng.add_sender_rule, auto_block=True)
    assert [(r["account"], r["kind"]) for r in _rules(h)] == [("a", "block")]


def test_admin_release_rule_becomes_a_conflict_not_a_block(eng, monkeypatch):
    h = _harness(eng, monkeypatch)
    rid = eng.add_sender_rule(h.db.conn, h.acc.name, SENDER, "allow", "Frigivet fra Fanget spam", "admin")
    h.db.conn.commit()
    for i in range(3):
        h.rspamd.symbols[f"c{i}@x"] = dict(AUTHED)
        h.deliver(f"c{i}@x", score=2.0, sender=SENDER)
        h.scan()
        h.advance(600)
        h.user_moves(f"c{i}@x", "INBOX", "Spamfilter")
        h.poll()
    rules = _rules(h)
    assert [(r["id"], r["kind"]) for r in rules] == [(rid, "allow")]     # the admin's rule is kept
    note = junkrules.get(h.db.conn, h.acc.name, SENDER, "conflict")
    assert note["status"] == "open" and note["rule_id"] == rid and note["rule_by"] == "admin" and note["n_junk"] == 3
    assert junkrules.get(h.db.conn, h.acc.name, SENDER, "suggest") is None
    assert h.events("junk_rule_conflict")


def test_domain_allow_rule_is_a_conflict_too(eng, monkeypatch):
    h = _harness(eng, monkeypatch)
    rid = eng.add_sender_rule(h.db.conn, h.acc.name, "@perfectjeans.example", "allow", None, "admin")
    res = junkrules.on_user_junk(h.db.conn, h.acc.name, SENDER, "d1@x", now=NOW, add_rule=eng.add_sender_rule)
    assert res["conflict"] == rid


@pytest.mark.parametrize("account,force,by", [("*", False, "admin"), ("acct", True, "admin"),
                                              ("acct", False, "auto:flytning")])
def test_policy_and_automatic_rules_are_no_conflict(eng, monkeypatch, account, force, by):
    h = _harness(eng, monkeypatch)
    conn = h.db.conn
    eng.add_sender_rule(conn, account if account == "*" else h.acc.name, SENDER, "allow", None, by, force=force)
    for i in range(3):
        res = junkrules.on_user_junk(conn, h.acc.name, SENDER, f"x{i}@x", now=NOW, add_rule=eng.add_sender_rule,
                                     auto_block=True)
    assert res["conflict"] is None and res["blocked"] is None
    assert [r["kind"] for r in _rules(h)] == ["allow"]


@pytest.mark.parametrize("sender", ["ordre@vexar.example", "info@mail.vexar.example", "kollega@example-a.dk",
                                    "salg@gravisk.example"])
def test_owner_domains_are_never_blocked_automatically(eng, monkeypatch, sender):
    monkeypatch.setattr(junkrules, "AUTO_BLOCK", True)
    h = _harness(eng, monkeypatch)
    for i in range(3):
        _junk_one(h, f"o{i}@x", sender=sender)
    assert _rules(h) == [] and junkrules.get(h.db.conn, h.acc.name, sender, "suggest") is None


OTHER_ACCOUNTS = """
defaults:
  mode: move
accounts:
  - name: bynet
    user: owner@anden-net.example
    imap_host: imap.example.net
    password: x
    owner_platform_domains: []
    webshop_domains: []
  - name: molt
    user: inge@molt.example
    imap_host: imap.example.net
    password: x
    contact_group: "moltgruppe.example"
    owner_platform_domains: []
    webshop_domains: []
"""


@pytest.mark.parametrize("sender", ["anden@anden-net.example", "owner@anden-net.example", "inge@molt.example",
                                    "x@moltgruppe.example", "salg@pinsikbing.example", "y@sub.gravisk.example"])
def test_every_mailbox_domain_and_address_is_protected(eng, monkeypatch, tmp_path, sender):
    # Review 2.12: the same protection as the WebUI (junkrules.owner_protection
    # over EVERY mailbox): moves in one mailbox never block another mailbox's
    # domain or address, nor pinsikbing.example/gravisk.example even with an own list.
    monkeypatch.setattr(junkrules, "AUTO_BLOCK", True)
    cfg = tmp_path / "accounts.yml"
    cfg.write_text(OTHER_ACCOUNTS)
    monkeypatch.setattr(eng, "CONFIG_PATH", cfg)
    monkeypatch.setattr(eng, "_OWNER_PROTECTION_CACHE", {})
    h = _harness(eng, monkeypatch)
    for i in range(3):
        _junk_one(h, f"w{i}@x", sender=sender)
    assert _rules(h) == [] and junkrules.get(h.db.conn, h.acc.name, sender, "suggest") is None


def test_owner_protection_matches_the_webui_refusals():
    accs = [type("A", (), {"user": "owner@anden-net.example", "contact_group": "", "owner_platform_domains": [],
                           "webshop_domains": ["butik.example"]})()]
    prot = junkrules.owner_protection(accs)
    assert junkrules.block_refusal("owner@anden-net.example", prot) == ("own_mailbox", "owner@anden-net.example")
    assert junkrules.block_refusal("@anden-net.example", prot) == ("own_domain", "anden-net.example")
    assert junkrules.block_refusal("a@butik.example", prot) == ("own_shop", "butik.example")
    assert junkrules.block_refusal("a@gravisk.example", prot) == ("own_shop", "gravisk.example")
    assert junkrules.block_refusal("kollega@anden-net.example", prot) is None          # the WebUI allows one address
    assert junkrules.owner_sender("kollega@anden-net.example", prot)                  # the engine never does
    assert not junkrules.owner_sender("nyhed@perfectjeans.example", prot)


def test_force_rule_for_the_sender_is_never_overridden(eng, monkeypatch):
    monkeypatch.setattr(junkrules, "AUTO_BLOCK", True)
    h = _harness(eng, monkeypatch)
    eng.add_sender_rule(h.db.conn, "*", "@perfectjeans.example", "allow", None, "admin", force=True)
    h.db.conn.commit()
    for i in range(3):
        _junk_one(h, f"fo{i}@x")
    assert [(r["kind"], r["force"]) for r in _rules(h)] == [("allow", 1)]
    assert junkrules.get(h.db.conn, h.acc.name, SENDER, "suggest") is None


def test_a_dismissed_suggestion_is_not_blocked_later(eng, monkeypatch):
    h = _harness(eng, monkeypatch)
    conn = h.db.conn
    for i in range(3):
        junkrules.on_user_junk(conn, h.acc.name, SENDER, f"s{i}@x", now=NOW, auto_block=False,
                               add_rule=eng.add_sender_rule)
    assert junkrules.get(conn, h.acc.name, SENDER, "suggest")["status"] == "open" and _rules(h) == []
    junkrules.decide(conn, h.acc.name, SENDER, "suggest", "dismissed", "admin")
    junkrules.on_user_junk(conn, h.acc.name, SENDER, "s9@x", now=NOW, add_rule=eng.add_sender_rule)
    assert _rules(h) == [] and junkrules.get(conn, h.acc.name, SENDER, "suggest")["status"] == "dismissed"


def test_junk_rule_trouble_never_breaks_the_junk_poll(eng, monkeypatch):
    h = _harness(eng, monkeypatch)
    import junkrules as jr

    monkeypatch.setattr(jr, "on_user_junk", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    _junk_one(h, "b1@x")
    assert h.row("b1@x")["our_action"] == "user_junked"


# ---------------------------------------------------------------- #9 newsletters are not learned as spam

NL_HEADERS = "List-Unsubscribe: <https://esp.example/u/1>, <mailto:u@esp.example>"


NL_SYMS = [{"n": "TH_NEWSLETTER", "s": -1.5, "o": ["esp.example"]}, {"n": "TH_ESTABLISHED", "s": -2.0},
           {"n": "HAS_LIST_UNSUB", "s": -0.01}]


def _nl_row(**over):
    row = {"scanned_at": NOW, "our_score": 3.0, "threat": None, "sender": SENDER, "message_id": "nl@x",
           "symbols": json.dumps(NL_SYMS)}
    row.update(over)
    return row


def _nl_raw(headers=NL_HEADERS):
    from fakes_engine import make_message

    return make_message("nl@x", sender=SENDER, extra_headers=headers)


def test_legit_newsletter_rules(eng):
    assert eng.legit_newsletter(_nl_raw(), _nl_row(), 8.0)
    assert not eng.legit_newsletter(_nl_raw(""), _nl_row(), 8.0)                       # no List-Unsubscribe
    assert not eng.legit_newsletter(_nl_raw(), _nl_row(our_score=8.5), 8.0)            # over the threshold
    assert not eng.legit_newsletter(_nl_raw(), _nl_row(threat="phishing"), 8.0)
    assert not eng.legit_newsletter(_nl_raw(), _nl_row(scanned_at=None), 8.0)          # never scanned
    assert not eng.legit_newsletter(_nl_raw(), _nl_row(symbols="[]"), 8.0)             # no valid signature
    # Review 2.12: any valid DKIM signature is not enough - fresh spam domains sign too.
    dkim_only = json.dumps([{"n": "R_DKIM_ALLOW", "s": -0.2}, {"n": "TH_ESTABLISHED", "s": -2.0}])
    assert not eng.legit_newsletter(_nl_raw(), _nl_row(symbols=dkim_only), 8.0)
    # TH_NEWSLETTER needs a sender history: TH_ESTABLISHED or earlier ham in the pool.
    nl_only = json.dumps([{"n": "TH_NEWSLETTER", "s": -1.5}])
    assert not eng.legit_newsletter(_nl_raw(), _nl_row(symbols=nl_only), 8.0)
    for sign in ("PHISHED_OPENPHISH", "FUZZY_DENIED_X", "RBL_SPAMHAUS_SBL", "TH_LOOKALIKE_DOMAIN",
                 "DMARC_POLICY_QUARANTINE", "TH_PROVIDER_SPAM", "TH_BRAND_SPOOF"):
        syms = json.dumps([*NL_SYMS, {"n": sign, "s": 1.0}])
        assert not eng.legit_newsletter(_nl_raw(), _nl_row(symbols=syms), 8.0), sign
    syms = json.dumps([*NL_SYMS, {"n": "PHISHED_EXCLUDED", "s": 0}])
    assert eng.legit_newsletter(_nl_raw(), _nl_row(symbols=syms), 8.0)               # informational only


def test_newsletter_sender_history_from_earlier_ham(eng, monkeypatch):
    h = _harness(eng, monkeypatch)
    conn = h.db.conn
    nl_only = json.dumps([{"n": "TH_NEWSLETTER", "s": -1.5}])
    assert not eng.legit_newsletter(_nl_raw(), _nl_row(symbols=nl_only), 8.0, conn)
    h.db.upsert_message("old@x", "INBOX", SENDER.upper(), "Tidligere", NOW - 86400)
    h.db.update_message("old@x", user_verdict="ham")
    conn.commit()
    assert eng.legit_newsletter(_nl_raw(), _nl_row(symbols=nl_only), 8.0, conn)
    assert not eng.legit_newsletter(_nl_raw(), _nl_row(symbols=nl_only, message_id="old@x"), 8.0, conn)


def _as_newsletter(h, mid):
    h.db.conn.execute("UPDATE messages SET symbols=? WHERE account=? AND message_id=?",
                      (json.dumps(NL_SYMS), h.acc.name, mid))
    h.db.conn.commit()


def _learn_due(h):
    h.advance(h.acc.learn_grace_seconds + 60)
    h.eng.process_pending_learns(h.client, h.db, LOG, h.acc, h.acc.folder_map)


def test_user_move_of_a_newsletter_is_not_learned_as_spam(eng, monkeypatch):
    h = _harness(eng, monkeypatch)
    _junk_one(h, "nl1@x", extra_headers=NL_HEADERS)
    assert h.row("nl1@x")["pending_learn"] == "spam"
    _as_newsletter(h, "nl1@x")
    _learn_due(h)
    r = h.row("nl1@x")
    assert r["pending_learn"] is None and r["learned_as"] is None and r["user_verdict"] == "spam"
    assert h.rspamd.learn_calls == [] and h.events("learn_skip_newsletter")


def test_dkim_signed_spam_from_a_new_sender_is_still_learned(eng, monkeypatch):
    # Review 2.12: List-Unsubscribe + any valid DKIM + a low score is most
    # spam from fresh domains - it is learned (and the campaign sweep runs).
    h = _harness(eng, monkeypatch)
    _junk_one(h, "ns1@x", extra_headers=NL_HEADERS,
              symbols={"R_DKIM_ALLOW": {"name": "R_DKIM_ALLOW", "score": -0.2, "options": ["fresh.example:s=a"]}})
    _learn_due(h)
    assert h.row("ns1@x")["learned_as"] == "spam" and len(h.rspamd.learn_calls) == 1
    assert not h.events("learn_skip_newsletter")


def test_user_move_of_ordinary_spam_is_still_learned(eng, monkeypatch):
    h = _harness(eng, monkeypatch)
    _junk_one(h, "sp1@x")                                          # no List-Unsubscribe
    _learn_due(h)
    assert h.row("sp1@x")["learned_as"] == "spam" and len(h.rspamd.learn_calls) == 1
    assert not h.events("learn_skip_newsletter")


def test_webui_move_to_spam_of_a_newsletter_skips_learning(eng, monkeypatch):
    import services

    h = _harness(eng, monkeypatch)
    h.deliver("nl2@x", score=2.0, sender=SENDER, extra_headers=NL_HEADERS)
    h.scan()
    _as_newsletter(h, "nl2@x")
    raw = _nl_raw()
    assert services._legit_newsletter(eng, h.db, h.acc, "nl2@x", raw)
    assert any(e[1] == "nl2@x" for e in h.events("learn_skip_newsletter"))
    assert not services._legit_newsletter(eng, h.db, h.acc, "nl2@x", _nl_raw(""))
    assert services._LEARN_NOTE["newsletter"].startswith(" – ikke lært som spam")


# ---------------------------------------------------------------- #8 / #9 admin page

@pytest.fixture
def jenv(tmp_path, monkeypatch):
    import fakes_ui_admin
    from fakes_ui import fast_hash

    e = fakes_ui_admin.make_admin_env(tmp_path, monkeypatch)
    hp = fast_hash("pw-test-1234567")
    (e.state / "dashboard_users").write_text(f"admin:{hp}:admin:0\nanna:{hp}:bynet:0\n")
    e.pw = "pw-test-1234567"
    import ui_mail  # noqa: F401 - registers /spam and ui_junkrules

    c = e.conn
    junkrules.ensure_schema(c)
    e.rid = e.engine.add_sender_rule(c, "bynet", SENDER, "allow", "Frigivet fra Fanget spam", "admin")
    junkrules.on_user_junk(c, "bynet", SENDER, "k1@x", now=int(time.time()))
    for i in range(3):
        junkrules.on_user_junk(c, "molt", "spam@shop.example", f"s{i}@x", now=int(time.time()),
                               add_rule=e.engine.add_sender_rule, auto_block=True)   # the opt-in mode
    c.commit()
    return e


def _client(env, name):
    from fakes_ui import login

    cl = env.app.test_client()
    assert login(cl, name, env.pw).status_code == 302
    return cl


def _audits(env, action):
    return [r for r in env.audit() if r["action"] == action]


def test_admin_sees_conflicts_and_automatic_blocks_under_tjek_disse(jenv):
    html = _client(jenv, "admin").get("/spam").get_data(as_text=True)
    assert "Tjek disse: regler og flytninger til Junk" in html
    assert f"{SENDER} er tilladt i" in html and "Fjern reglen" in html and "Bloker for kontoen" in html
    assert "spam@shop.example er flyttet til Junk 3 gange" in html and "Fjern blokeringen" in html
    assert 'action="/spam/junk-notes"' in html


def test_a_user_never_sees_the_admin_card(jenv):
    cl = _client(jenv, "anna")
    assert "regler og flytninger til Junk" not in cl.get("/spam").get_data(as_text=True)
    from fakes_ui import post

    r = post(cl, "/spam/junk-notes", {"account": "bynet", "sender": SENDER, "kind": "conflict",
                                      "action": "remove_rule"})
    assert r.status_code in (403, 404)
    assert jenv.conn.execute("SELECT COUNT(*) FROM sender_rules WHERE id=?", (jenv.rid,)).fetchone()[0] == 1


def test_remove_rule_deletes_only_that_rule(jenv):
    from fakes_ui import post

    r = post(_client(jenv, "admin"), "/spam/junk-notes",
             {"account": "bynet", "sender": SENDER, "kind": "conflict", "action": "remove_rule"})
    assert r.get_json()["ok"], r.get_json()
    assert jenv.conn.execute("SELECT COUNT(*) FROM sender_rules WHERE id=?", (jenv.rid,)).fetchone()[0] == 0
    assert junkrules.get(jenv.conn, "bynet", SENDER, "conflict")["status"] == "rule_removed"
    assert [a["detail"] for a in _audits(jenv, "junk_note_remove_rule")] == [f"allow {SENDER}"]


def test_block_for_the_mailbox_switches_the_exact_rule(jenv):
    from fakes_ui import post

    r = post(_client(jenv, "admin"), "/spam/junk-notes",
             {"account": "bynet", "sender": SENDER, "kind": "conflict", "action": "block"})
    assert r.get_json()["ok"], r.get_json()
    rows = [tuple(x) for x in jenv.conn.execute("SELECT account, pattern, kind FROM sender_rules "
                                                "WHERE pattern=?", (SENDER,))]
    assert rows == [("bynet", SENDER, "block")]
    assert junkrules.get(jenv.conn, "bynet", SENDER, "conflict")["status"] == "blocked"


def test_undo_an_automatic_block(jenv):
    from fakes_ui import post

    r = post(_client(jenv, "admin"), "/spam/junk-notes",
             {"account": "molt", "sender": "spam@shop.example", "kind": "suggest", "action": "undo"})
    assert r.get_json()["ok"], r.get_json()
    assert jenv.conn.execute("SELECT COUNT(*) FROM sender_rules WHERE pattern='spam@shop.example'").fetchone()[0] == 0
    assert junkrules.get(jenv.conn, "molt", "spam@shop.example", "suggest")["status"] == "undone"


def test_block_refuses_vexar_shop(jenv):
    from fakes_ui import post

    c = jenv.conn
    for i in range(3):
        junkrules.on_user_junk(c, "bynet", "ordre@vexar.example", f"i{i}@x", now=int(time.time()), auto_block=False)
    # protected: never even a suggestion
    assert junkrules.get(c, "bynet", "ordre@vexar.example", "suggest") is None
    c.execute("INSERT INTO junk_sender_notes(account, sender, kind, n_junk, first_at, last_at, status) "
              "VALUES('bynet','ordre@vexar.example','suggest',3,1,1,'open')")
    c.commit()
    r = post(_client(jenv, "admin"), "/spam/junk-notes",
             {"account": "bynet", "sender": "ordre@vexar.example", "kind": "suggest", "action": "block"})
    assert not r.get_json()["ok"]
    assert c.execute("SELECT COUNT(*) FROM sender_rules WHERE pattern='ordre@vexar.example'").fetchone()[0] == 0


# ---------------------------------------------------------------- #10 Kontrolrum SSO with the real person

from test_ui_kontrolrum_sso import assertion, client, env as kr_env, sso  # noqa: E402,F401


def test_sso_logs_in_the_real_person_and_the_audit_log_shows_them(kr_env):
    import dashboard

    with kr_env.app.test_request_context("/"):
        dashboard.set_kr_sso_allowed("anna", True, "test")
    c = client(kr_env)
    r = sso(c, assertion(kr_env.key, sub="anna"))
    assert r.status_code == 200 and r.get_json() == {"ok": True, "user": "anna"}
    rec = [a for a in kr_env.audit() if a["action"] == "login_kontrolrum"][-1]
    assert rec["actor"] == "anna" and rec["via"] == "kontrolrum" and rec["result"] == "ok"
    from fakes_ui import post

    post(c, "/logout", json_reply=False)
    out = [a for a in kr_env.audit() if a["action"] == "logout"][-1]
    assert out["actor"] == "anna" and out["via"] == "kontrolrum"


def test_sso_person_without_the_checkbox_is_refused_and_settings_are_unchanged(kr_env):
    import dashboard

    with kr_env.app.test_request_context("/"):
        before = dashboard.all_kr_sso_allowed()
    r = sso(client(kr_env), assertion(kr_env.key, sub="anna"))
    assert r.status_code == 401 and r.get_json() == {"error": "unknown_user"}
    with kr_env.app.test_request_context("/"):
        assert dashboard.all_kr_sso_allowed() == before == {"kontrolrum"}


def test_sso_long_kontrolrum_link_is_an_unknown_user_not_a_bad_request(kr_env):
    r = sso(client(kr_env), assertion(kr_env.key, sub="x" * 100))
    assert r.status_code == 401 and r.get_json() == {"error": "unknown_user"}
    r = sso(client(kr_env), assertion(kr_env.key, sub="x" * 129))
    assert r.status_code == 400


def test_password_login_is_not_marked_as_kontrolrum(kr_env):
    from fakes_ui import login

    c = kr_env.app.test_client()
    c.environ_base["REMOTE_ADDR"] = "192.168.1.42"
    login(c, "admin", "x")  # wrong password: a failed audit line without 'via'
    recs = [a for a in kr_env.audit() if a["action"] == "login"]
    assert recs and all("via" not in a for a in recs)


def test_audit_page_shows_via_kontrolrum():
    import ui_admin

    assert "via Kontrolrum" in ui_admin._audit_origin({"ip": "172.17.0.1", "via": "kontrolrum"})
    assert "Kontrolrum" not in ui_admin._audit_origin({"ip": "192.168.1.42"})
