"""2.3 established senders and first contact (B12), the interplay with
autolearn, user verdicts and rescues (B14), and the rollback guarantee: a
database migrated by 2.3 still works with the 2.2.0 engine."""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import make_message, setup_engine, stub_mailctx  # noqa: E402
from test_engine_contacts import (  # noqa: E402,F401
    DMARC_OK, LOG, C, dkim, eng, harness, inbound, run_sync, sent_mail, sym, syms_of,
)

ROOT = Path(__file__).resolve().parents[1]
DAY = 86400


def env_mailctx():
    """stub_mailctx whose envelope sender is the mail's Return-Path."""
    import email

    base = stub_mailctx()
    orig = base.scan_context

    def scan_context(raw, acc):
        ctx = orig(raw, acc)
        rp = email.message_from_bytes(raw).get("Return-Path")
        ctx["envelope_from"] = rp.strip("<> ") if rp else None
        return ctx

    base.scan_context = scan_context
    return base


def archived(h, folder, sender, *, days_ago, mid, dkim_d=None, return_path=None):
    extra = f"DKIM-Signature: v=1; a=rsa-sha256; d={dkim_d}; s=mandrill; b=abc" if dkim_d else ""
    when = dt.datetime.fromtimestamp(h.t - days_ago * DAY, dt.timezone.utc)
    h.client.add(folder, make_message(mid, sender=sender, extra_headers=extra, return_path=return_path),
                 flags=("\\Seen",), internaldate=when)


def datamail(eng, monkeypatch, *, n=3, span_days=80, junk=False):
    h = harness(eng, monkeypatch, folders=("INBOX", "Junk", "Trash", "Sent", "Arkiv", "Kladder"))
    for i in range(n):
        archived(h, "Arkiv", "faktura@datamail.example", days_ago=10 + span_days * (n - 1 - i) / max(1, n - 1),
                 mid=f"f{i}@datamail.example", dkim_d="datamail.example", return_path="bounce@mandrillapp.com")
    archived(h, "Kladder", "faktura@datamail.example", days_ago=1, mid="draft@x")  # drafts never count
    run_sync(h)
    return h


# ----- bootstrap ------------------------------------------------------------------


def test_bootstrap_counts_inbox_and_archives_only(eng, monkeypatch, C):
    h = harness(eng, monkeypatch, folders=("INBOX", "Junk", "Trash", "Sent", "Arkiv", "Kladder"))
    archived(h, "Arkiv", "klub@klubben.dk", days_ago=40, mid="h1@x")
    archived(h, "Arkiv", "klub@klubben.dk", days_ago=20, mid="h2@x", dkim_d="klubben.dk")
    archived(h, "Junk", "spam@spam.example", days_ago=5, mid="j1@x")
    archived(h, "Kladder", "me@x.dk", days_ago=5, mid="k1@x")
    h.client.add("INBOX", make_message("i1@x", sender="ven@gmail.com"))
    h.client.add("INBOX", make_message("h1@x", sender="klub@klubben.dk"))  # same Message-ID: once
    h.scan()  # the bookmark now covers the two inbox mails
    run_sync(h)
    key = eng._contacts_key(h.db)
    rows = {r["h"]: r for r in h.db.conn.execute("SELECT * FROM sender_history")}
    hold = rows[C.hash_address(key, "klub@klubben.dk")]
    assert (hold["n_kept"], hold["n_seen"], hold["n_junk"], hold["regdom"]) == (2, 2, 0, "klubben.dk")
    assert json.loads(hold["fp"])["dkim"] == ["klubben.dk"]
    assert C.hash_address(key, "ven@gmail.com") in rows
    assert C.hash_address(key, "spam@spam.example") not in rows and C.hash_address(key, "me@x.dk") not in rows
    assert h.client.writes == []


# ----- TH_ESTABLISHED -----------------------------------------------------------------


def test_established_with_the_same_dkim_domain(eng, monkeypatch, C):
    h = datamail(eng, monkeypatch)
    r = inbound(h, "e1@x", "faktura@datamail.example", score=9.0, symbols=dkim("datamail.example"))
    est = syms_of(h, "e1@x")["TH_ESTABLISHED"]
    assert est["s"] == -2.0 and est["o"][0] == "n=3" and est["o"][1].startswith("siden=")
    assert r["our_score"] == pytest.approx(7.0) and r["our_action"] == "none"
    assert h.stat("established") == 1
    # A spoof from another network: no signature -> nothing.
    inbound(h, "e2@x", "faktura@datamail.example", symbols={})
    assert "TH_ESTABLISHED" not in syms_of(h, "e2@x")


@pytest.mark.parametrize("n, span", [(2, 80), (4, 10)], ids=["two_mails", "ten_days"])
def test_established_needs_three_kept_mails_over_thirty_days(eng, monkeypatch, C, n, span):
    h = datamail(eng, monkeypatch, n=n, span_days=span)
    inbound(h, "e3@x", "faktura@datamail.example", symbols=dkim("datamail.example"))
    assert "TH_ESTABLISHED" not in syms_of(h, "e3@x")


def test_established_by_envelope_and_asn_and_spoof_from_another_network(tmp_path, monkeypatch, C):
    eng = setup_engine(tmp_path, monkeypatch, mailctx=env_mailctx())
    C.forget_cached_keys()
    h = datamail(eng, monkeypatch)
    asn = lambda n: sym("ASN", 0.0, [f"asn:{n}", "ipnet:192.0.2.0/24", "country:US"])  # noqa: E731
    # A kept mail with DKIM records the sending network (env domain + ASN).
    h.rspamd.scores["n1@x"] = 2.0
    h.rspamd.symbols["n1@x"] = {**dkim("datamail.example"), **asn(14618)}
    h.deliver("n1@x", sender="faktura@datamail.example", return_path="bounce@mandrillapp.com")
    h.scan()
    # Same network, DKIM broken (e.g. released from quarantine): still established.
    h.rspamd.scores["n2@x"] = 2.0
    h.rspamd.symbols["n2@x"] = asn(14618)
    h.deliver("n2@x", sender="faktura@datamail.example", return_path="bounce@mandrillapp.com")
    h.scan()
    assert "TH_ESTABLISHED" in syms_of(h, "n2@x")
    # A forger without DKIM cannot teach us his network.
    h.rspamd.scores["n2b@x"] = 2.0
    h.rspamd.symbols["n2b@x"] = asn(777)
    h.deliver("n2b@x", sender="faktura@datamail.example", return_path="bounce@mandrillapp.com")
    h.scan()
    key = eng._contacts_key(h.db)
    fp = json.loads(h.db.conn.execute("SELECT fp FROM sender_history WHERE h=?",
                                      (C.hash_address(key, "faktura@datamail.example"),)).fetchone()[0])
    assert fp["asn"] == ["14618"] and fp["env"] == ["mandrillapp.com"]
    # Same envelope domain, another network: a forgery - nothing.
    h.rspamd.scores["n3@x"] = 2.0
    h.rspamd.symbols["n3@x"] = asn(666)
    h.deliver("n3@x", sender="faktura@datamail.example", return_path="bounce@mandrillapp.com")
    h.scan()
    assert "TH_ESTABLISHED" not in syms_of(h, "n3@x")


def test_established_dies_with_one_junk_verdict(eng, monkeypatch, C):
    h = datamail(eng, monkeypatch)
    inbound(h, "e5@x", "faktura@datamail.example", score=2.0, symbols=dkim("datamail.example"))
    assert "TH_ESTABLISHED" in syms_of(h, "e5@x")
    h.user_moves("e5@x", "INBOX", "Junk")
    h.poll()
    key = eng._contacts_key(h.db)
    hist = h.db.conn.execute("SELECT n_junk, n_kept FROM sender_history WHERE h=?",
                             (C.hash_address(key, "faktura@datamail.example"),)).fetchone()
    assert hist["n_junk"] == 1 and hist["n_kept"] == 3  # 3 archived + e5 kept, minus the junked one
    ev = h.events("contact_demoted")
    assert len(ev) == 1 and "ikke længere fast afsender" in ev[0][2] and "faktura@" not in ev[0][2]
    inbound(h, "e6@x", "faktura@datamail.example", symbols=dkim("datamail.example"))
    assert "TH_ESTABLISHED" not in syms_of(h, "e6@x")


# ----- TH_FIRST_CONTACT ----------------------------------------------------------------


def test_first_contact_once_and_never_more_than_one_point(eng, monkeypatch, C):
    h = harness(eng, monkeypatch, sent=[sent_mail("s1@x", "alice@kunde.dk")])
    run_sync(h)
    r = inbound(h, "fc1@x", "ny@ukendt.example", score=7.5)
    fc = syms_of(h, "fc1@x")["TH_FIRST_CONTACT"]
    assert fc["s"] == 1.0 and fc["o"] == ["ukendt.example"]
    assert r["our_score"] == pytest.approx(8.5) and r["our_action"] == "pending_move"  # +1 only, no holding
    assert h.stat("first_contact") == 1
    inbound(h, "fc2@x", "ny@ukendt.example")   # seen before now
    inbound(h, "fc3@x", "anden@ukendt.example")  # domain seen before
    assert "TH_FIRST_CONTACT" not in syms_of(h, "fc2@x") and "TH_FIRST_CONTACT" not in syms_of(h, "fc3@x")
    inbound(h, "fc4@x", "kollega@example-a.dk")  # own domain
    inbound(h, "fc5@x", "alice@kunde.dk")        # a contact (domain known)
    assert "TH_FIRST_CONTACT" not in syms_of(h, "fc4@x") and "TH_FIRST_CONTACT" not in syms_of(h, "fc5@x")


def test_first_contact_respects_allow_rules_and_older_messages(eng, monkeypatch, C):
    h = harness(eng, monkeypatch)
    run_sync(h)
    eng.add_sender_rule(h.db.conn, "acct", "@tilladt.example", "allow", "", "test")
    inbound(h, "a1@x", "x@tilladt.example")
    assert "TH_FIRST_CONTACT" not in syms_of(h, "a1@x")
    with h.db.tx():
        h.db.upsert_message("old@x", "Junk", "noget@set-foer.example", "x")
    inbound(h, "a2@x", "andet@set-foer.example")
    assert "TH_FIRST_CONTACT" not in syms_of(h, "a2@x")


def test_rescue_counts_as_kept_and_ends_first_contact(eng, monkeypatch, C):
    h = harness(eng, monkeypatch)
    run_sync(h)
    inbound(h, "r1@x", "ny@butik.example", score=8.0)
    assert "TH_FIRST_CONTACT" in syms_of(h, "r1@x") and h.row("r1@x")["our_action"] == "pending_move"
    h.advance(61)
    h.moves()
    assert h.row("r1@x")["our_action"] == "moved_to_junk"
    key = eng._contacts_key(h.db)
    hh = C.hash_address(key, "ny@butik.example")
    assert tuple(h.db.conn.execute("SELECT n_kept, n_junk FROM sender_history WHERE h=?", (hh,)).fetchone()) == (0, 1)
    h.user_moves("r1@x", "Junk", "INBOX")
    h.scan()
    assert h.row("r1@x")["our_action"] == "user_rescued"
    assert tuple(h.db.conn.execute("SELECT n_kept, n_junk FROM sender_history WHERE h=?", (hh,)).fetchone()) == (1, 0)
    inbound(h, "r2@x", "ny@butik.example")
    assert "TH_FIRST_CONTACT" not in syms_of(h, "r2@x")


# ----- B14: demotion, autolearn ---------------------------------------------------------


def test_user_spam_verdict_demotes_a_known_contact(eng, monkeypatch, C):
    h = harness(eng, monkeypatch, sent=[sent_mail("s1@x", "alice@kunde.dk")])
    run_sync(h)
    inbound(h, "d1@x", "alice@kunde.dk", score=1.0, symbols=DMARC_OK)
    assert "TH_KNOWN_CONTACT" in syms_of(h, "d1@x")
    h.user_moves("d1@x", "INBOX", "Junk")
    h.poll()
    row = h.db.conn.execute("SELECT status, status_by FROM known_contacts").fetchone()
    assert tuple(row) == ("demoted", "user:move")
    ev = h.events("contact_demoted")
    assert len(ev) == 1 and ev[0][1] == "d1@x" and "a…@kunde.dk fjernet fra kendte kontakter" in ev[0][2]
    inbound(h, "d2@x", "alice@kunde.dk", score=1.0, symbols=DMARC_OK)
    assert "TH_KNOWN_CONTACT" not in syms_of(h, "d2@x")
    # Gendan (services/UI): active again and n_junk cleared.
    key = eng._contacts_key(h.db)
    with h.db.tx():
        assert C.set_status(h.db.conn, "acct", C.hash_address(key, "alice@kunde.dk"), "active", "admin") == "demoted"
    assert h.db.conn.execute("SELECT n_junk FROM sender_history").fetchone()[0] == 0
    inbound(h, "d3@x", "alice@kunde.dk", score=1.0, symbols=DMARC_OK)
    assert "TH_KNOWN_CONTACT" in syms_of(h, "d3@x")


def test_spam_verdict_on_a_colleague_contact_only_blocks_it_here(eng, monkeypatch, C):
    h = harness(eng, monkeypatch, contact_group="molt.example")
    run_sync(h)
    key = eng._contacts_key(h.db)
    hh = C.hash_address(key, "kunde@kunde.dk")
    h.db.conn.execute("INSERT INTO contacts_sync(account, folder, kind, complete, grp) VALUES('molt', '*', 'account', 1, "
                      "'molt.example')")
    h.db.conn.execute("INSERT INTO known_contacts(account, h, domain, mask, sent_count, last_sent_at) "
                      "VALUES('molt', ?, 'kunde.dk', 'k…@kunde.dk', 3, ?)", (hh, int(eng._now())))
    inbound(h, "g1@x", "kunde@kunde.dk", symbols=DMARC_OK)
    assert syms_of(h, "g1@x")["TH_KNOWN_CONTACT"]["o"][-1] == "gruppe"
    h.user_moves("g1@x", "INBOX", "Junk")
    h.poll()
    rows = {r["account"]: r["status"] for r in h.db.conn.execute("SELECT account, status FROM known_contacts")}
    assert rows == {"molt": "active", "acct": "demoted"}
    inbound(h, "g2@x", "kunde@kunde.dk", symbols=DMARC_OK)
    assert "TH_KNOWN_CONTACT" not in syms_of(h, "g2@x")


def test_trust_bonuses_never_make_mail_learnable_as_ham(eng, monkeypatch, C):
    g = eng.ham_guard_reason
    for name, score in (("TH_KNOWN_CONTACT", -4.0), ("TH_REPLY", -5.0), ("TH_REPLY_THREAD", -2.0),
                        ("TH_ESTABLISHED", -2.0), ("TH_KNOWN_DOMAIN", -1.0)):
        syms = [{"n": name, "s": score}, {"n": "X", "s": 3.0}]
        res = g(None, "a", symbols=syms, final=3.0 + score, rspamd_score=3.0,
                trust_limit=eng.AUTOLEARN_HAM_MAX_SCORE)
        assert res is not None and res[0] == "trust_only", name
    # The live path: a known contact's mail kept under 0 only by the bonus.
    h = harness(eng, monkeypatch, sent=[sent_mail("s1@x", "alice@kunde.dk")])
    run_sync(h)
    uid = h.deliver("al@x", sender="alice@kunde.dk")
    h.rspamd.scores["al@x"] = 2.5
    h.rspamd.symbols["al@x"] = DMARC_OK
    h.scan()
    assert h.row("al@x")["our_score"] < 0 and "TH_KNOWN_CONTACT" in syms_of(h, "al@x")
    h.client.folders["INBOX"].msgs[uid].flags.add("\\Seen")
    h.advance(7 * DAY + 1)
    assert h.eng.autolearn_pass(h.client, h.db, LOG, h.acc, h.acc.folder_map)["ham"] == 0
    assert "trust_only" in h.events("ham_guard")[0][2]
    assert not [c for c in h.rspamd.learn_calls if "learnham" in c["url"]]


# ----- rollback: 2.2.0 on a 2.3-migrated database -------------------------------------


def _v22_source() -> str | None:
    for ref in ("v2.2", "origin/v2.2"):
        try:
            out = subprocess.run(["git", "-C", str(ROOT), "show", f"{ref}:filter/filter.py"],
                                 capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return None
        if out.returncode == 0 and 'VERSION = "2.2' in out.stdout:
            return out.stdout
    return None


def test_rollback_22_engine_works_on_a_23_migrated_database(tmp_path, monkeypatch, C):
    src = _v22_source()
    if src is None:
        pytest.skip("2.2 source not available (no git history)")
    eng = setup_engine(tmp_path, monkeypatch)
    C.forget_cached_keys()
    h = harness(eng, monkeypatch, sent=[sent_mail("s1@x", "alice@kunde.dk")])
    run_sync(h)
    inbound(h, "kc@x", "alice@kunde.dk", score=1.0, symbols=DMARC_OK)
    inbound(h, "fc@x", "ny@ukendt.example", score=1.0)
    h.db.close()
    eng.init_db()  # idempotent second migration
    # Import the 2.2.0 engine from git (under another name) against this DB.
    old_dir = tmp_path / "v22"
    old_dir.mkdir()
    (old_dir / "filter_v22.py").write_text(src)
    spec = importlib.util.spec_from_file_location("filter_v22", old_dir / "filter_v22.py")
    old = importlib.util.module_from_spec(spec)
    sys.modules["filter_v22"] = old
    try:
        spec.loader.exec_module(old)
        assert old.VERSION.startswith("2.2") and old.SCORE_VERSION == eng.SCORE_VERSION
        monkeypatch.setattr(old, "STATE_DIR", tmp_path)
        monkeypatch.setattr(old, "DB_PATH", eng.DB_PATH)
        old.init_db()  # 2.2's schema reader / migration on the 2.3 database
        db = old.Db("acct")
        row = db.get_message("kc@x")
        assert row["our_action"] == "none" and row["score_version"] == old.SCORE_VERSION
        names = {s["n"] for s in json.loads(row["symbols"])}
        assert "TH_KNOWN_CONTACT" in names
        with db.tx():
            db.upsert_message("new22@x", "INBOX", "a@b.dk", "Hej")
            db.update_message("new22@x", our_score=2.0, our_action="none", score_version=old.SCORE_VERSION)
            db.log_event("scan", "new22@x", detail="score=2.00 by 2.2")
            db.bump("scanned")
        assert db.get_message("new22@x")["our_score"] == 2.0
        # 2.2's ham guard still treats the 2.3 trust symbols as trust bonuses.
        assert old.ham_guard_reason(db.conn, "acct", symbols=row["symbols"], final=row["our_score"],
                                    rspamd_score=row["rspamd_score"],
                                    trust_limit=old.AUTOLEARN_HAM_MAX_SCORE)[0] == "trust_only"
        old.autolearn_candidates(db, h.acc, h.acc.folder_map)
        old.health_snapshot(db.conn)
        db.close()
    finally:
        sys.modules.pop("filter_v22", None)
    # ... and rolling forward again keeps the contact data.
    eng.init_db()
    conn = sqlite3.connect(eng.DB_PATH)
    assert conn.execute("SELECT COUNT(*) FROM known_contacts").fetchone()[0] == 1
    assert conn.execute("SELECT complete FROM contacts_sync WHERE folder='*'").fetchone()[0] == 1
