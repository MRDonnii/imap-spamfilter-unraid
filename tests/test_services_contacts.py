"""2.3 services API for 'Kendte kontakter' (B13 needs, B14): overview,
list (people/organisations, full address only for inbound senders), lookup
via the hash, remove/restore (audited, events with masks only), 'Opdater
nu', the on/off switch via save_config, trust labels for the message
detail, today's counter, mail_action demotion, digest/weekly/S3/S4 and the
trainer's calibration scan - against the REAL engine schema."""

from __future__ import annotations

import datetime as dt
import json
import logging
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "filter"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import services  # noqa: E402
from fakes_engine import make_message, setup_engine  # noqa: E402
from test_engine_contacts import DMARC_OK, harness, run_sync, sent_mail  # noqa: E402
from test_services import (  # noqa: E402,F401
    GIGA, LIVE_LOG, live, live_account, live_loop, live_mail, live_row,
)

CFG = """
defaults:
  mode: move
  threshold: 8
accounts:
  - name: acct
    user: user@example-a.dk
    imap_host: imap.example.net
    password: x
{extra}
  - name: other
    user: other@example-b.dk
    imap_host: imap.example.net
    password: x
"""


@pytest.fixture
def eng(tmp_path, monkeypatch):
    e = setup_engine(tmp_path, monkeypatch)
    import contacts

    contacts.forget_cached_keys()
    Path(e.CONFIG_PATH).write_text(CFG.format(extra=""))
    yield e
    contacts.forget_cached_keys()


@pytest.fixture
def C():
    import contacts

    return contacts


def synced(eng, monkeypatch, sent=None):
    h = harness(eng, monkeypatch, sent=sent if sent is not None else [
        sent_mail("s1@x", "alice@kunde.dk"), sent_mail("s2@x", "alice@kunde.dk", cc="bob@firma.dk"),
        sent_mail("s3@x", ["carl@firma.dk", "ven@gmail.com"])])
    run_sync(h)
    return h


def events(h, name):
    return [tuple(r) for r in h.db.conn.execute("SELECT event, message_id, detail FROM events WHERE event=?",
                                                 (name,))]


# ----- overview --------------------------------------------------------------------


def test_overview_before_during_and_after_the_first_sync(eng, monkeypatch, C):
    o = services.contacts_overview("acct", engine=eng)
    assert o["ok"] and not o["complete"] and o["enabled"]
    assert o["text"] == "Den første gennemgang af dine sendte mails er ikke startet endnu."
    assert o["help"] == "Vi læser kun modtager-adresser og Message-ID fra dine sendte mails – aldrig indholdet."
    monkeypatch.setattr(C, "FETCH_CHUNK", 1)
    h = harness(eng, monkeypatch, sent=[sent_mail(f"s{i}@x", f"p{i}@kunde.dk") for i in range(4)])
    C.sync_step(h.client, h.db, logging.getLogger("t"), h.acc, h.acc.folder_map, h.state,
                key=eng._contacts_key(h.db), now=int(time.time()), budget_s=0.0)
    o = services.contacts_overview("acct", engine=eng)
    assert not o["complete"] and o["progress"]["total"] == 4 and o["progress"]["percent"] == 25
    assert o["text"].startswith("Lærer fra dine sendte mails … 25 %")
    run_sync(h)
    o = services.contacts_overview("acct", engine=eng)
    assert o["complete"] and o["contacts"] == 4 and o["sent_mails"] == 4 and o["progress"]["percent"] == 100
    assert o["text"].startswith("Lært fra dine sendte mails: 4 kontakter · 4 sendte mails · opdateret ")
    assert o["last_sync_text"] in o["text"] and o["last_sync_at"]
    assert services.contacts_overview("nope", engine=eng)["code"] == "no_account"


def test_overview_when_disabled(eng):
    Path(eng.CONFIG_PATH).write_text(CFG.format(extra="    known_contacts: false"))
    o = services.contacts_overview("acct", engine=eng)
    assert not o["enabled"] and o["text"] == "Kendte kontakter er slået fra for denne postkasse."


# ----- list / lookup ---------------------------------------------------------------


def test_list_people_masks_unless_the_address_wrote_to_you(eng, monkeypatch, C):
    h = synced(eng, monkeypatch)
    with h.db.tx():
        h.db.upsert_message("in@x", "INBOX", "Alice@Kunde.dk", "Hej")
    res = services.contacts_list("acct", engine=eng)
    assert res["ok"] and res["total"] == 4 and res["pages"] == 1
    by = {i["display"]: i for i in res["items"]}
    assert by["alice@kunde.dk"]["masked"] is False and by["alice@kunde.dk"]["sent_count"] == 2
    assert by["b…@firma.dk"]["masked"] is True and by["b…@firma.dk"]["address"] is None
    assert by["alice@kunde.dk"]["last_sent_text"] == "oktober 2026"
    assert res["items"][0]["status_text"] == "Kendt kontakt" and res["items"][0]["can_remove"]
    assert services.contacts_list("acct", q="firma", engine=eng)["total"] == 2
    page = services.contacts_list("acct", per_page=3, page=2, engine=eng)
    assert page["pages"] == 2 and len(page["items"]) == 1
    orgs = services.contacts_list("acct", group="orgs", engine=eng)
    assert [(o["domain"], o["contacts"]) for o in orgs["items"]] == [("firma.dk", 2), ("kunde.dk", 1)]
    look = services.contacts_list("acct", q="bob@firma.dk", engine=eng)["lookup"]
    assert look["found"] and look["text"] == "Ja, du har skrevet til bob@firma.dk 1 gang, senest oktober 2026."
    assert services.contacts_list("other", engine=eng)["total"] == 0  # scoped per mailbox


def test_lookup_texts(eng, monkeypatch, C):
    assert services.contact_lookup("acct", "alice@kunde.dk", engine=eng)["code"] == "not_ready"
    synced(eng, monkeypatch)
    r = services.contact_lookup("acct", "Alice@Kunde.DK", engine=eng)
    assert r["code"] == "found" and r["sent_count"] == 2 and r["mask"] == "a…@kunde.dk"
    assert r["text"] == "Ja, du har skrevet til alice@kunde.dk 2 gange, senest oktober 2026."
    r = services.contact_lookup("acct", "ukendt@kunde.dk", engine=eng)
    assert r["code"] == "not_found" and r["text"] == "Nej, du har ikke skrevet til ukendt@kunde.dk fra denne postkasse."
    assert services.contact_lookup("acct", "ikke en adresse", engine=eng)["code"] == "invalid"
    assert services.contact_lookup("nope", "a@b.dk", engine=eng)["code"] == "no_account"


# ----- writes ---------------------------------------------------------------------------


def test_remove_and_restore_are_logged_with_masks_only(eng, monkeypatch, C):
    h = synced(eng, monkeypatch)
    hh = C.hash_address(eng._contacts_key(h.db), "alice@kunde.dk")
    r = services.set_contact_status("acct", hh, "removed", "admin", engine=eng)
    assert r["ok"] and r["code"] == "ok" and r["previous"] == "active"
    assert r["text"] == "Afsenderen er fjernet fra Kendte kontakter."
    assert r["audit_detail"] == "a…@kunde.dk active->removed" and "alice@" not in r["audit_detail"]
    ev = events(h, "contact_removed")
    assert len(ev) == 1 and "a…@kunde.dk" in ev[0][2] and "alice@" not in ev[0][2]
    assert services.set_contact_status("acct", hh, "removed", "admin", engine=eng)["code"] == "unchanged"
    lst = services.contacts_list("acct", status="removed", engine=eng)
    assert lst["total"] == 1 and lst["items"][0]["can_restore"] and lst["items"][0]["status_text"] == "Fjernet"
    r = services.restore_contact("acct", hh, "admin", engine=eng)
    assert r["ok"] and r["text"] == "Afsenderen er gendannet som kendt kontakt."
    assert len(events(h, "contact_restored")) == 1
    assert services.set_contact_status("acct", "zz", "removed", "admin", engine=eng)["code"] == "invalid"
    assert services.set_contact_status("acct", hh, "bogus", "admin", engine=eng)["code"] == "invalid"
    assert services.set_contact_status("acct", "0" * 32, "active", "admin", engine=eng)["code"] == "invalid"


def test_request_sync_wakes_the_account_thread(eng, monkeypatch, C):
    h = synced(eng, monkeypatch)
    wake0 = eng.engine_state_get(h.db.conn, "wake:acct")
    r = services.request_contacts_sync("acct", "admin", engine=eng)
    assert r["ok"] and r["code"] == "queued" and r["audit_detail"] == "contacts_sync"
    assert eng.engine_state_get(h.db.conn, C.REQUEST_STATE + "acct")
    assert eng.engine_state_get(h.db.conn, "wake:acct") != wake0
    assert len(events(h, "contacts_sync_requested")) == 1
    h.db.conn.execute("UPDATE contacts_sync SET synced_at=1 WHERE folder='*'")  # synced before the request
    assert services.contacts_overview("acct", engine=eng)["requested"] is True
    h.client.add("Sent", sent_mail("s9@x", "ny@kunde.dk"))
    eng.contacts_sync(h.client, h.db, logging.getLogger("t"), h.acc, h.state)
    assert services.contact_lookup("acct", "ny@kunde.dk", engine=eng)["found"]
    Path(eng.CONFIG_PATH).write_text(CFG.format(extra="    known_contacts: false"))
    assert services.request_contacts_sync("acct", "admin", engine=eng)["code"] == "disabled"


def test_switch_uses_save_config(eng):
    calls = []

    def fake_save(mutator, actor, action, *, account="", detail=""):
        raw = {"accounts": [{"name": "acct"}, {"name": "other"}]}
        mutator(raw)
        calls.append((raw, actor, action, account, detail))

    r = services.set_known_contacts_enabled("acct", False, "admin", engine=eng, save_config=fake_save)
    assert r["ok"] and r["text"].startswith("Kendte kontakter er slået fra.")
    raw, actor, action, account, detail = calls[0]
    assert raw["accounts"][0]["known_contacts"] is False and "known_contacts" not in raw["accounts"][1]
    assert (actor, action, account, detail) == ("admin", "known_contacts", "acct", "known_contacts=off")

    def rejecting(mutator, *a, **k):
        raise ValueError("nej")

    assert services.set_known_contacts_enabled("acct", True, "a", engine=eng, save_config=rejecting)["code"] == "rejected"
    assert services.set_known_contacts_enabled("nope", True, "a", engine=eng, save_config=fake_save)["code"] == "no_account"


# ----- labels / counters -----------------------------------------------------------------


def test_trust_labels_exact_texts():
    today = dt.date(2026, 10, 21)
    syms = [{"n": "TH_KNOWN_CONTACT", "s": -4, "o": ["a…@b.dk", "sendt=7", "senest=2026-03"]},
            {"n": "TH_REPLY", "s": -5, "o": ["a…@b.dk", "sendt=2026-10-12"]},
            {"n": "TH_ESTABLISHED", "s": -2, "o": ["n=14", "siden=2021"]},
            {"n": "TH_FIRST_CONTACT", "s": 1, "o": ["b.dk"]},
            {"n": "TH_REPLY_UNVERIFIED", "s": 0, "o": []}]
    labels = services.trust_labels(json.dumps(syms), today=today)
    assert [(lb["kind"], lb["tone"], lb["text"]) for lb in labels] == [
        ("known_contact", "green", "Kendt kontakt – du har skrevet til afsenderen 7 gange"),
        ("reply", "green", "Svar på din mail fra 12. okt."),
        ("established", "blue", "Fast afsender – 14 mails siden 2021"),
        ("first_contact", "amber", "Første mail fra denne afsender"),
        ("reply_unverified", "grey", "Ligner et svar, men afsenderen kunne ikke bekræftes"),
    ]
    plain = [lb["text"] for lb in services.trust_labels(syms, numbers=False, today=today)]
    assert plain[:3] == ["Kendt kontakt", "Svar på din mail", "Fast afsender"]
    # Group contacts never show a count (also not from rows stored before the fix).
    assert services.trust_labels([{"n": "TH_KNOWN_CONTACT", "o": ["x", "sendt=37", "gruppe"]}])[0]["text"] == \
        "Kendt kontakt – en kollega har skrevet til afsenderen"
    assert services.trust_labels([{"n": "TH_KNOWN_CONTACT", "o": ["x", "gruppe"]}], numbers=False)[0]["text"] == \
        "Kendt kontakt"
    assert services.trust_labels([{"n": "TH_REPLY", "o": ["x", "sendt=2025-01-03"]}], today=today)[0]["text"] == \
        "Svar på din mail fra 3. jan. 2025"
    assert services.trust_labels("not json") == [] and services.TRUST_LABEL_KINDS[0] == "known_contact"


def test_message_trust_labels_and_today_counter(eng, monkeypatch, C):
    h = synced(eng, monkeypatch)
    h.rspamd.scores["kc@x"] = 2.0
    h.rspamd.symbols["kc@x"] = DMARC_OK
    h.deliver("kc@x", sender="alice@kunde.dk")
    h.scan()
    labels = services.message_trust_labels("acct", "<kc@x>", engine=eng)
    assert labels[0]["text"] == "Kendt kontakt – du har skrevet til afsenderen 2 gange"
    assert services.message_trust_labels("other", "kc@x", engine=eng) == []
    day = eng.stats_day()
    t = services.trust_counts_today(["acct", "other"], day=day, engine=eng)
    assert t["total"] == 1 and t["by_account"] == {"acct": 1}
    assert t["text"] == "Beskyttet af kendte kontakter i dag: 1"
    assert services.trust_counts_today([], day=day, engine=eng)["total"] == 0
    assert services.trust_counts_today(["other"], day=day, engine=eng)["total"] == 0


# ----- B14: mail_action demotion (real engine + services) -------------------------------


def test_mark_spam_demotes_a_known_contact_unless_declined(live, C):
    C.forget_cached_keys()
    h = live_account(live, GIGA, extra_folders=("Sent",))
    for i, who in enumerate(("alice@kunde.dk", "bob@kunde.dk")):
        h.box.add("Sent", sent_mail(f"s{i}@x", who, sender="ole@example-a.dk"))
    h.state.contacts_next_status = 0.0  # the first sync already ran (empty Sent): next STATUS
    for _ in range(10):
        live.eng.contacts_sync(h.box, h.db, LIVE_LOG, h.acc, h.state)
        if not h.state.contacts_busy:
            break
    for mid, who in (("kc1@x", "alice@kunde.dk"), ("kc2@x", "bob@kunde.dk")):
        live.rspamd.symbols[mid] = DMARC_OK
        live_mail(live, h, "INBOX", mid, sender=who, score=2.0)
    live_loop(live, h)
    assert any(s["n"] == "TH_KNOWN_CONTACT" for s in json.loads(live_row(h, "kc1@x")["symbols"]))
    [res] = services.mail_action("anna", ["kc1@x"], "mark_spam", "admin", engine=live.eng)
    assert res["ok"] and res["contact"] == {"mask": "a…@kunde.dk", "demoted": True, "h": res["contact"]["h"]}
    [res2] = services.mail_action("anna", ["kc2@x"], "mark_spam", "admin", engine=live.eng, demote_contact=False)
    assert res2["ok"] and res2["contact"]["demoted"] is False
    st = {r["mask"]: (r["status"], r["status_by"]) for r in h.db.conn.execute("SELECT * FROM known_contacts")}
    assert st == {"a…@kunde.dk": ("demoted", "admin"), "b…@kunde.dk": ("active", None)}
    key = C.load_key(live.eng.STATE_DIR, None, create=False)
    nj = h.db.conn.execute("SELECT n_junk FROM sender_history WHERE h=?",
                           (C.hash_address(key, "bob@kunde.dk"),)).fetchone()[0]
    assert nj == 1  # the sender still lost 'established'
    # Frigiv counts as kept.
    [rel] = services.mail_action("anna", ["kc2@x"], "release", "admin", engine=live.eng)
    assert rel["ok"]
    row = h.db.conn.execute("SELECT n_kept, n_junk FROM sender_history WHERE h=?",
                            (C.hash_address(key, "bob@kunde.dk"),)).fetchone()
    assert tuple(row) == (1, 0)  # the spam verdict is taken back


# ----- digest / weekly / S3 / S4 / trainer ------------------------------------------------


def test_digest_weekly_and_threshold_text_count_contacts(eng, monkeypatch, C):
    h = synced(eng, monkeypatch)
    day = "2026-10-20"
    for metric, n in (("known_contact", 4), ("reply_detected", 2), ("first_contact", 3), ("scanned", 9)):
        h.db.conn.execute("INSERT INTO stats_daily VALUES('acct', ?, ?, ?)", (day, metric, n))
    d = services.digest_data(day, engine=eng)
    a = {x["account"]: x for x in d["accounts"]}["acct"]
    assert (a["known_contact"], a["reply_detected"], a["first_contact"]) == (4, 2, 3)
    assert d["totals"]["known_contact"] == 4
    w = services.weekly_data("2026-W43", engine=eng)
    assert w["totals"]["reply_detected"] == 2
    text = services.render_weekly(w)["text"]
    assert "Kendte kontakter: 4 mails fra kendte kontakter, 2 svar på jeres mails genkendt, 3 første mails" in text
    s = services.threshold_suggestion("acct", engine=eng)
    assert s["contacts_included"] and s["text"].endswith("Kendte kontakter er regnet med.")
    assert services.threshold_suggestion("other", engine=eng)["contacts_included"] is False


def test_calibration_summary_split_with_and_without_trust(eng, monkeypatch):
    conn = eng.Db("acct").conn
    for i, (score, syms) in enumerate(((2.0, [{"n": "TH_KNOWN_CONTACT", "s": -4}]), (12.0, []), (9.0, []),
                                       (1.0, [{"n": "TH_REPLY", "s": -5}]))):
        conn.execute("INSERT INTO calibration_results(job_id, account, folder, message_id, final_score, symbols) "
                     "VALUES(5, 'acct', 'INBOX', ?, ?, ?)", (f"m{i}", score, json.dumps(syms)))
    s = services.calibration_summary(5, thresholds=[8.0], engine=eng)
    t = s["trust"]
    assert (t["with_count"], t["without_count"]) == (2, 2)
    assert "Kendte kontakter" in t["note"]


def test_trainer_calibration_scan_includes_trust_signals(eng, monkeypatch, C):
    import trainer

    h = synced(eng, monkeypatch)
    raw = make_message("cal@x", sender="alice@kunde.dk")
    h.rspamd.scores["cal@x"] = 3.0
    h.rspamd.symbols["cal@x"] = DMARC_OK
    ctx = {"headers": {}, "envelope_from": None}
    monkeypatch.setattr(trainer.mailctx, "provider_bonus", lambda ctx: [])
    _res, syms, final, _aged = trainer.scan_scored(eng, h.acc, raw, ctx, None, h.db.conn)
    assert "TH_KNOWN_CONTACT" in {s["n"] for s in syms} and final == pytest.approx(-1.0)
    _res, syms, final, _aged = trainer.scan_scored(eng, h.acc, raw, ctx, None)
    assert "TH_KNOWN_CONTACT" not in {s["n"] for s in syms} and final == pytest.approx(3.0)
