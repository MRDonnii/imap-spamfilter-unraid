"""2.3 SERVICES for the threat class (B16), rescans (B19) and the
attachment policy (B17), against the REAL engine (filter.py) and the
RFC-accurate mailbox fake.

Every path that can put mail back or learn ham refuses a threat for
non-admins ('Kontakt administrator'), asks an admin for an explicit
confirmation, and a confirmed release never learns ham: mail_action
(release / learn_ham, also in bulk), move_found_to_inbox, undo_moves and
learn lists. Message dicts carry threat + a Danish threat_text."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "filter"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import services  # noqa: E402
from test_services import (  # noqa: E402,F401
    GIGA, SCAN, learned_ids, live, live_account, live_loop, live_mail, live_row,
)

VIRUS = {"CLAM_VIRUS": {"name": "CLAM_VIRUS", "score": 0.0, "options": ["Eicar-Test-Signature"]}}
PHISH = {"DBL_PHISH": {"name": "DBL_PHISH", "score": 7.5, "options": ["bank-login.example:url"]}}


def catch_threat(live, h, mid, symbols, *, score=2.0):
    live.rspamd.symbols[mid] = symbols
    live_mail(live, h, "INBOX", mid, subject=f"Faktura {mid}", score=score)
    live_loop(live, h)
    live.clock.t += 61
    live_loop(live, h)
    assert mid in h.box.msgids("Spamfilter")
    assert live_row(h, mid)["threat"]


def catch_more(live, h, ids):
    """Like test_services.catch_spam, with other mail already in Spamfilter."""
    for mid in ids:
        live_mail(live, h, "INBOX", mid, subject=f"Vind {mid}", score=13.0)
    live_loop(live, h)
    live.clock.t += 61
    live_loop(live, h)
    for mid in ids:
        assert mid in h.box.msgids("Spamfilter") and live_row(h, mid)["our_action"] == "moved_to_junk"


def user_mail(h, folder):
    """Message-IDs in a folder without the filter's own notices: a threat
    moved to Spamfilter now also gives a Straks-advarsel in the INBOX."""
    return [m for m in h.box.msgids(folder) if not m.endswith("@hjemmeserver.spamfilter")]


def events(h, name):
    return [tuple(r) for r in h.db.conn.execute("SELECT event, message_id, detail FROM events WHERE event=?",
                                                 (name,))]


@pytest.fixture(params=[GIGA, SCAN], ids=["gigahost", "scannet"])
def caps(request):
    return request.param


# ----- mail_action ----------------------------------------------------------------------


def test_release_of_threat_needs_admin_and_confirmation(live, caps):
    h = live_account(live, caps)
    catch_threat(live, h, "v@x", VIRUS)
    catch_more(live, h, ["n@x"])
    # A Bruger (fail closed: no is_admin) gets 'Kontakt administrator'.
    res = services.mail_action("anna", ["v@x"], "release", "bruger", engine=live.eng)[0]
    assert res["ok"] is False and res["code"] == "threat_admin"
    assert "Kontakt administrator" in res["text"] and res["threat_text"] == "Virus: Eicar-Test-Signature"
    assert "v@x" in h.box.msgids("Spamfilter")
    # An admin must confirm.
    res = services.mail_action("anna", ["v@x"], "release", "admin", engine=live.eng, is_admin=True)[0]
    assert res["code"] == "threat_confirm"
    assert res["confirm_text"] == "Denne mail indeholder virus: Eicar-Test-Signature."
    assert "v@x" in h.box.msgids("Spamfilter")
    assert [e[1] for e in events(h, "threat_release_refused")] == ["v@x", "v@x"]
    # Confirmed: released, never learned as ham.
    res = services.mail_action("anna", ["v@x"], "release", "admin", engine=live.eng, is_admin=True,
                               confirm_threat=True)[0]
    assert res["ok"] and res["code"] == "ok" and "ikke lært som legitim" in res["text"]
    assert res["threat"] == "virus"
    assert "v@x" in h.box.msgids("INBOX") and "v@x" not in h.box.msgids("Spamfilter")
    assert all(mid != "v@x" for _k, mid in learned_ids(live))
    r = live_row(h, "v@x")
    assert r["user_verdict"] == "ham" and r["our_action"] == "manual_release" and r["learned_as"] is None
    assert [e[1] for e in events(h, "threat_release")] == ["v@x"]
    # The engine leaves it alone afterwards and never learns it.
    live_loop(live, h, 3, step=600)
    assert "v@x" in h.box.msgids("INBOX")
    assert all(mid != "v@x" for _k, mid in learned_ids(live))
    # Ordinary spam: unchanged behaviour for a Bruger.
    res = services.mail_action("anna", ["n@x"], "release", "bruger", engine=live.eng)[0]
    assert res["ok"] and ("learnham", "n@x") in learned_ids(live)


def test_bulk_release_mixes_threats_and_normal_mail(live):
    h = live_account(live, SCAN)
    catch_threat(live, h, "p@x", PHISH)
    catch_more(live, h, ["a@x", "b@x"])
    res = services.mail_action("anna", ["a@x", "p@x", "b@x"], "release", "bruger", engine=live.eng)
    assert [r["code"] for r in res] == ["ok", "threat_admin", "ok"]
    assert res[1]["threat_text"] == "Phishing-link"
    assert sorted(user_mail(h, "INBOX")) == ["a@x", "b@x"] and h.box.msgids("Spamfilter") == ["p@x"]
    assert len(h.box.msgids("INBOX")) == 3  # + the Straks-advarsel about p@x


def test_learn_ham_of_threat(live):
    h = live_account(live, SCAN)
    catch_threat(live, h, "p@x", PHISH)
    res = services.mail_action("anna", ["p@x"], "learn_ham", "bruger", engine=live.eng)[0]
    assert res["code"] == "threat_admin"
    assert services.mail_action("anna", ["p@x"], "learn_ham", "admin", engine=live.eng,
                                is_admin=True)[0]["code"] == "threat_confirm"
    res = services.mail_action("anna", ["p@x"], "learn_ham", "admin", engine=live.eng, is_admin=True,
                               confirm_threat=True)[0]
    assert res["ok"] and ("learnham", "p@x") in learned_ids(live)  # the admin's explicit choice
    # mark_spam / learn_spam of a threat are always fine.
    res = services.mail_action("anna", ["p@x"], "learn_spam", "bruger", engine=live.eng)[0]
    assert res["code"] in ("ok", "learn_rate_limited") and res["threat"] == "phish"


def test_threat_release_does_not_count_as_kept_for_contacts(live, monkeypatch):
    h = live_account(live, SCAN)
    catch_threat(live, h, "v@x", VIRUS)
    calls = []
    monkeypatch.setattr(services, "_contact_verdict", lambda *a, **k: calls.append(a[4]))
    services.mail_action("anna", ["v@x"], "release", "admin", engine=live.eng, is_admin=True, confirm_threat=True)
    assert calls == []


# ----- move_found_to_inbox, undo, learn lists ---------------------------------------------


def test_move_found_to_inbox_refuses_threat_for_brugere(live):
    h = live_account(live, SCAN)
    catch_threat(live, h, "v@x", VIRUS)
    res = services.move_found_to_inbox("anna", "Spamfilter", "v@x", "bruger", learn=True, engine=live.eng)
    assert res["ok"] is False and res["code"] == "threat_admin" and res["threat"] == "virus"
    assert "v@x" in h.box.msgids("Spamfilter")
    res = services.move_found_to_inbox("anna", "Spamfilter", "v@x", "admin", learn=True, engine=live.eng,
                                       is_admin=True)
    assert res["code"] == "threat_confirm"
    res = services.move_found_to_inbox("anna", "Spamfilter", "v@x", "admin", learn=True, engine=live.eng,
                                       is_admin=True, confirm_threat=True)
    assert res["ok"] and res["learned"] is None and res["threat_text"] == "Virus: Eicar-Test-Signature"
    assert "v@x" in h.box.msgids("INBOX")
    assert all(mid != "v@x" for _k, mid in learned_ids(live))


def test_undo_moves_skips_threats(live):
    h = live_account(live, SCAN)
    since = int(live.clock.t) - 10
    catch_threat(live, h, "v@x", VIRUS)
    catch_more(live, h, ["a@x", "b@x"])
    until = int(live.clock.t) + 10
    p = services.preview_undo("anna", since, until, engine=live.eng)
    assert p["count"] == 2 and p["threats"] == 1 and "farlig mail" in p["text"]
    res = services.undo_moves("anna", since, until, "admin", engine=live.eng, wait_s=30)
    assert res["moved"] == 2
    assert h.box.msgids("Spamfilter") == ["v@x"] and sorted(user_mail(h, "INBOX")) == ["a@x", "b@x"]


def test_learn_list_rejects_ham_for_threats(live):
    h = live_account(live, SCAN)
    catch_threat(live, h, "v@x", VIRUS)
    catch_more(live, h, ["a@x"])
    res = services.queue_learn_list([("anna", "v@x", "ham"), ("anna", "a@x", "ham")], "admin", engine=live.eng)
    assert res["ok"] and res["total"] == 1
    assert {"account": "anna", "message_id": "v@x", "code": "threat"} in res["rejected"]
    res = services.queue_learn_list([("anna", "v@x", "spam")], "admin", engine=live.eng)
    assert res["ok"] and res["total"] == 1


def test_find_mail_rows_carry_the_threat(live):
    h = live_account(live, SCAN)
    catch_threat(live, h, "v@x", VIRUS)
    res = services.find_mail("anna", "Faktura", live=False, engine=live.eng)
    row = next(r for r in res["db"] if r["message_id"] == "v@x")
    assert row["threat"] == "virus" and row["threat_text"] == "Virus: Eicar-Test-Signature"
    res = services.find_mail("anna", "Faktura", engine=live.eng)
    hit = next(x for g in res["folders"] for x in g["hits"] if x["message_id"] == "v@x")
    assert hit["threat"] == "virus" and hit["threat_text"].startswith("Virus")


# ----- message info: threat + rescans -------------------------------------------------------


def test_message_threat_info_and_zap_timeline(live):
    h = live_account(live, SCAN)
    catch_threat(live, h, "p@x", PHISH)
    info = services.message_threat_info("anna", "p@x", engine=live.eng)
    assert info["ok"] and info["threat"] == "phish" and info["threat_text"] == "Phishing-link"
    assert info["tone"] == "red" and info["user_release"] is False
    assert info["admin_text"] == "Kontakt administrator, hvis mailen skal frigives."
    assert info["confirm_text"] == "Denne mail indeholder et phishing-link."
    assert info["zapped"] is False and info["zap_label"] == ""
    # A mail a rescan moved.
    live_mail(live, h, "INBOX", "z@x", score=5.0)
    live_loop(live, h)
    live.clock.t += 3 * 3600 + 600
    live.rspamd.scores["z@x"] = 13.0
    live.rspamd.symbols["z@x"] = {"DBL_SPAM": {"name": "DBL_SPAM", "score": 6.5}}
    live_loop(live, h)
    live.clock.t += 20
    live_loop(live, h)
    assert "z@x" in h.box.msgids("Spamfilter")
    info = services.message_threat_info("anna", "z@x", engine=live.eng)
    assert info["zapped"] and info["zap_label"] == "Fanget ved genscanning"
    assert info["timeline"][-1]["text"] == "Ny viden: DBL_SPAM kom til efter 3 t"
    assert services.message_threat_info("anna", "nope@x", engine=live.eng)["code"] == "not_found"


def test_zap_timeline_texts():
    t = services.zap_timeline_text
    assert t("ny=DBL_SPAM efter=3 t score=4.00->13.00") == "Ny viden: DBL_SPAM kom til efter 3 t"
    assert t("læst ny=DBL_SPAM,ABUSE_SURBL efter=45 min") == "Ny viden: DBL_SPAM og ABUSE_SURBL kom til efter 45 min"
    assert t("ny=- efter=4 t score=5.00->5.00") == "Genscannet efter 4 t – intet nyt"


def test_weekly_and_digest_texts(live):
    h = live_account(live, SCAN)
    data = services.weekly_data(engine=live.eng)
    data["threats"] = {"phish": 2, "virus": 1}
    for a in data["accounts"]:
        a["zapped"] = 3
    out = services.render_weekly(data, full=True)
    assert "Trusler stoppet: Virus 1, Phishing-link 2" in out["text"]
    assert "Flyttet efterfølgende (genscanning): 3" in out["text"]
    assert "Trusler stoppet" in out["html"]
    live.eng.bump_stat(h.db.conn, "anna", "threat_detected", 2)
    live.eng.bump_stat(h.db.conn, "anna", "zapped", 1)
    d = services.digest_data(live.eng.stats_day(live.clock.t), engine=live.eng)
    assert d["totals"]["threats"] == 2 and d["totals"]["zapped"] == 1


# ----- B17: attachment policy API --------------------------------------------------------


def _save_config(eng):
    calls = []

    def save_config(mutator, actor, action, *, account="", detail=""):
        raw = yaml.safe_load(Path(eng.CONFIG_PATH).read_text()) or {}
        result = mutator(raw)
        tmp = Path(eng.CONFIG_PATH).with_suffix(".tmp")
        tmp.write_text(yaml.safe_dump(raw))
        eng.load_account_configs(tmp)  # validation like dashboard.save_config
        tmp.replace(eng.CONFIG_PATH)
        calls.append((actor, action, detail))
        return result

    save_config.calls = calls
    return save_config


def test_attachment_policy_list_editor(live):
    live_account(live, SCAN)
    p = services.attachment_policy(engine=live.eng)
    assert p["ok"] and p["extensions"] == live.eng.DEFAULT_ATTACHMENT_BLOCK and p["custom"] is False
    assert "zip" in p["help"]
    sc = _save_config(live.eng)
    res = services.set_attachment_block("exe, .JS *.iso exe", "admin", engine=live.eng, save_config=sc)
    assert res["ok"] and res["extensions"] == ["exe", "js", "iso"]
    assert sc.calls[-1][1] == "attachment_block" and "scr" in sc.calls[-1][2].split(" -", 1)[1]
    assert live.eng.load_account_configs(live.eng.CONFIG_PATH)[0].attachment_block == ["exe", "js", "iso"]
    p = services.attachment_policy(engine=live.eng)
    assert p["custom"] and p["extensions"] == ["exe", "js", "iso"]
    assert services.set_attachment_block(["exe", "js", "iso"], "admin", engine=live.eng,
                                         save_config=sc)["code"] == "unchanged"
    bad = services.set_attachment_block("exe, ../x, e x", "admin", engine=live.eng, save_config=sc)
    assert bad["ok"] is False and bad["code"] == "invalid" and "../x" in bad["text"]
    many = services.set_attachment_block([f"e{i}" for i in range(101)], "admin", engine=live.eng, save_config=sc)
    assert many["code"] == "invalid"
    res = services.set_attachment_block(None, "admin", reset=True, engine=live.eng, save_config=sc)
    assert res["ok"] and services.attachment_policy(engine=live.eng)["custom"] is False


def test_attachment_exceptions_admin_only_and_masked(live):
    h = live_account(live, SCAN)
    res = services.add_attachment_exception("anna", "it@leverandor.dk", "bruger", engine=live.eng)
    assert res["code"] == "admin_only" and res["ok"] is False
    res = services.add_attachment_exception("anna", "IT@Leverandor.dk", "admin", is_admin=True, engine=live.eng,
                                            note="ISO-drivere")
    assert res["ok"] and res["pattern"] == "it@leverandor.dk"
    assert "it@leverandor.dk" not in res["audit_detail"] and "i…@leverandor.dk" in res["audit_detail"]
    assert services.add_attachment_exception("nope", "@x.dk", "admin", is_admin=True,
                                             engine=live.eng)["code"] == "no_account"
    assert services.add_attachment_exception("*", "not an address", "admin", is_admin=True,
                                             engine=live.eng)["code"] == "invalid"
    g = services.add_attachment_exception("*", "@leverandor.dk", "admin", is_admin=True, engine=live.eng)
    items = services.attachment_exceptions("anna", engine=live.eng)["items"]
    assert {i["pattern"] for i in items} == {"it@leverandor.dk", "@leverandor.dk"}
    assert {i["scope_text"] for i in items} == {"anna", "Alle postkasser"}
    for _e, _m, detail in events(h, "attach_exception_added"):
        assert "it@leverandor.dk" not in detail
    # The engine honours it (with DKIM of the domain).
    from test_engine_threat import mail_with_attachments

    import datetime as dt

    live.rspamd.symbols["iso@x"] = {"R_DKIM_ALLOW": {"name": "R_DKIM_ALLOW", "score": -0.2,
                                                     "options": ["leverandor.dk:s=sel"]}}
    live.rspamd.scores["iso@x"] = 1.0
    h.box.add("INBOX", mail_with_attachments("iso@x", [("driver.iso", b"x")], sender="it@leverandor.dk"),
              internaldate=dt.datetime.fromtimestamp(live.clock.t, dt.timezone.utc))
    live_loop(live, h)
    assert live_row(h, "iso@x")["threat"] is None
    assert services.remove_attachment_exception(res["id"], "bruger", engine=live.eng)["code"] == "admin_only"
    assert services.remove_attachment_exception(res["id"], "admin", is_admin=True, engine=live.eng)["ok"]
    assert services.remove_attachment_exception(res["id"], "admin", is_admin=True,
                                                engine=live.eng)["code"] == "not_found"
    assert services.remove_attachment_exception(g["id"], "admin", is_admin=True, engine=live.eng)["ok"]
    assert services.attachment_exceptions(engine=live.eng)["items"] == []


def test_threat_helpers_tolerate_a_pre_23_database(tmp_path):
    import sqlite3

    conn = sqlite3.connect(tmp_path / "x.db")
    conn.execute("CREATE TABLE messages (account TEXT, message_id TEXT)")
    assert services._threat_of(conn, "a", "m") == (None, None)
    assert services.threat_gate(None, None, is_admin=False, confirm_threat=False) is None
    assert services.threat_gate("virus", "X", is_admin=True, confirm_threat=True) is None
    assert json.dumps(services.threat_gate("attachment", "a.exe", is_admin=False, confirm_threat=False))
    assert time.time() > 0


# ----- Straks-advarsel: Oversigt card -----------------------------------------


def test_threats_today_counts_per_class_and_only_the_users_mailboxes(live):
    h = live_account(live, GIGA)
    catch_threat(live, h, "p@x", PHISH)
    catch_threat(live, h, "v@x", VIRUS)
    # A DKIM-verified pass-through (not stopped) is not counted.
    h.db.conn.execute("UPDATE messages SET our_action='allowlisted' WHERE message_id='v@x'")
    out = services.threats_today(["anna"], engine=live.eng)
    assert out["total"] == 1 and out["by_class"] == {"phish": 1} and out["by_account"] == {"anna": 1}
    assert out["items"] == [{"threat": "phish", "label": "Phishing-link", "n": 1}]
    assert out["text"] == "Farlige mails stoppet i dag: 1 (1 phishing-link)"
    assert out["notices"] >= 1  # the Straks-advarsel went into the INBOX
    assert services.threats_today(None, engine=live.eng)["total"] == 1
    assert services.threats_today([], engine=live.eng)["total"] == 0  # a user without mailboxes
    assert services.threats_today(["molt"], engine=live.eng)["total"] == 0
    assert services.threats_today(["anna"], day="2001-01-01", engine=live.eng)["total"] == 0
    assert services.threats_today(["anna"], day="ikke-en-dato", engine=live.eng)["total"] == 0
    # The notice itself is the filter's own mail: it never reaches the learn path.
    notice = [m for m in h.box.msgids("INBOX") if m.endswith("@hjemmeserver.spamfilter")]
    assert len(notice) == 1 and live.eng.is_own_registered(h.db.conn, "anna", notice[0])


def test_threats_today_counts_only_mail_really_out_of_the_inbox(live):
    h = live_account(live, GIGA)
    catch_threat(live, h, "p@x", PHISH)
    catch_threat(live, h, "v@x", VIRUS)
    catch_threat(live, h, "s@x", PHISH)
    h.db.conn.execute("UPDATE messages SET our_action='shadow_spam' WHERE message_id='v@x'")
    h.db.conn.execute("UPDATE messages SET our_action='move_failed' WHERE message_id='s@x'")
    out = services.threats_today(["anna"], engine=live.eng)
    assert out["total"] == 1 and out["by_class"] == {"phish": 1}
    assert out["in_inbox"] == 2 and out["in_inbox_by_account"] == {"anna": 2}
    assert "2 farlige mails ligger stadig i indbakken" in out["text"]
    week = services.threats_today(["anna"], days=7, engine=live.eng)
    assert week["days"] == 7 and week["total"] == 1 and week["text"].startswith("Farlige mails stoppet de seneste 7")
