"""2.19.1 'Tjek disse' leaves out borderline mail from senders a person
already called spam (filter/judged.py)."""

from __future__ import annotations

import time

from fakes_ui import csrf_of, insert_message, login, post
from fakes_ui_admin import make_admin_env

import judged
import ui_mail

NOW = int(time.time())
CAUGHT = {"our_score": 9.0, "our_action": "moved_to_junk", "current_folder": "Spamfilter"}   # threshold 8.0


def test_sender_key_domain_or_freemail_address():
    assert judged.sender_key("Zoo <ylsizvx@mail.zoo-friends.help>") == "dom:zoo-friends.help"
    assert judged.sender_key("X <Kontakt7781@Gmail.com>") == "addr:kontakt7781@gmail.com"
    assert judged.sender_key("nobody") is None and judged.sender_key(None) is None


def test_judged_spam_needs_a_spam_verdict_and_no_release(tmp_path, monkeypatch):
    e = make_admin_env(tmp_path, monkeypatch)
    insert_message(e.conn, "bynet", "<s1@x>", sender="a@zoo.example", user_verdict="spam")
    insert_message(e.conn, "molt", "<s2@x>", sender="b@both.example", user_verdict="spam")
    insert_message(e.conn, "bynet", "<h1@x>", sender="c@both.example", our_action="manual_release")
    old = NOW - 400 * 86400
    insert_message(e.conn, "bynet", "<old@x>", sender="d@old.example", user_verdict="spam",
                   scanned_at=old, first_seen=old, received_at=old)
    e.conn.commit()
    assert judged.judged_spam(e.conn, NOW) == {"dom:zoo.example"}


def _env(tmp_path, monkeypatch):
    e = make_admin_env(tmp_path, monkeypatch)
    insert_message(e.conn, "bynet", "<judged@x>", sender="Zoo <abc@zoo-friends.example>", user_verdict="spam",
                   scanned_at=NOW - 3600, **CAUGHT)
    for i in range(3):
        insert_message(e.conn, "bynet", f"<zoo{i}@x>", sender=f"Zoo <x{i}@zoo-friends.example>",
                       subject=f"Glem toilettet {i}", **CAUGHT)
    insert_message(e.conn, "bynet", "<other@x>", sender="Ny <n@nyafsender.example>", subject="Andet emne", **CAUGHT)
    insert_message(e.conn, "bynet", "<prot@x>", sender="Zoo <x9@zoo-friends.example>", subject="Beskyttet",
                   symbols=[{"n": "TH_PROTECTED_RCPT", "s": 0.0, "o": ["info@firma.example"]}], **CAUGHT)
    e.conn.commit()
    c = e.app.test_client()
    assert login(c).status_code == 302
    return e, c


def _review(html: str) -> str:
    part = html[html.index('id="tjek"'):]
    return part[:part.index("</section>")]


def test_review_hides_judged_senders_and_offers_show_all(tmp_path, monkeypatch):
    e, c = _env(tmp_path, monkeypatch)
    review = _review(c.get("/spam").get_data(as_text=True))
    assert "Glem toilettet" not in review                       # zoo-friends: already called spam
    assert "Andet emne" in review                               # new sender: still offered
    assert "Beskyttet" in review                                # protected address: always offered
    assert "3 mails vises ikke" in review and "tjek=alle" in review
    review = _review(c.get("/spam?tjek=alle").get_data(as_text=True))
    assert "Glem toilettet 0" in review and "Skjul dem igen" in review


def test_det_er_spam_removes_the_other_rows_from_the_same_sender(tmp_path, monkeypatch):
    e, c = _env(tmp_path, monkeypatch)
    insert_message(e.conn, "bynet", "<other2@x>", sender="Ny <m@nyafsender.example>", subject="Andet emne 2",
                   **CAUGHT)
    e.conn.commit()
    c.get("/spam")
    key = ui_mail._key("bynet", "<other@x>")
    r = post(c, "/mail/action", {"action": "learn_spam", "view": "review", "items": key, "nonce": "rj-1",
                                 "csrf": csrf_of(c)}).get_json()
    assert r["ok"], r
    assert r["rows"].get("review:" + key, "x") is None
    assert r["rows"].get("review:" + ui_mail._key("bynet", "<other2@x>"), "x") is None


def test_all_hidden_shows_a_slim_card(tmp_path, monkeypatch):
    e = make_admin_env(tmp_path, monkeypatch)
    insert_message(e.conn, "bynet", "<j@x>", sender="a@zoo.example", user_verdict="spam", **CAUGHT)
    insert_message(e.conn, "bynet", "<n@x>", sender="b@zoo.example", **CAUGHT)
    e.conn.commit()
    c = e.app.test_client()
    login(c)
    html = c.get("/spam").get_data(as_text=True)
    assert "review-card-empty" in html and "1 mail vises ikke, fordi den næsten sikkert er spam" in html
    assert "Vis den alligevel" in html


def test_obvious_spam_rules():
    assert judged.obvious_spam(set(), True) == "ai"
    assert judged.obvious_spam({"TH_FIRST_CONTACT"}, False) == "first_contact"                 # no DMARC
    assert judged.obvious_spam({"TH_FIRST_CONTACT", "DMARC_POLICY_ALLOW"}, False) == ""          # a new, real sender
    assert judged.obvious_spam({"TH_FIRST_CONTACT", "DMARC_POLICY_ALLOW", "TH_LURE_SUBJECT"}, False) == "first_contact"
    assert judged.obvious_spam({"DMARC_POLICY_ALLOW", "TH_LURE_SUBJECT"}, False) == ""          # sender seen before


def test_review_hides_first_contact_and_ai_sure_spam(tmp_path, monkeypatch):
    e = make_admin_env(tmp_path, monkeypatch)
    insert_message(e.conn, "bynet", "<fc@x>", sender="a@ny.example", subject="Ukendt uden DMARC",
                   symbols=[{"n": "TH_FIRST_CONTACT", "s": 1.0}], **CAUGHT)
    insert_message(e.conn, "bynet", "<fcd@x>", sender="b@ny2.example", subject="Ny butik med DMARC",
                   symbols=[{"n": "TH_FIRST_CONTACT", "s": 1.0}, {"n": "DMARC_POLICY_ALLOW", "s": -0.5}], **CAUGHT)
    insert_message(e.conn, "bynet", "<ai@x>", sender="c@kendt.example", subject="AI er sikker", **CAUGHT)
    insert_message(e.conn, "bynet", "<shop@x>", sender="d@butik.example", subject="Black Friday fra butikken", **CAUGHT)
    e.conn.execute("CREATE TABLE IF NOT EXISTS ai_verdicts(account TEXT, message_id TEXT, verdict TEXT, "
                   "confidence REAL, created_at INTEGER)")
    e.conn.execute("INSERT INTO ai_verdicts(account, message_id, mode, status, verdict, confidence, created_at) "
                   "VALUES('bynet', '<ai@x>', 'on', 'ok', 'phishing', 0.9, ?)", (NOW,))
    e.conn.commit()
    c = e.app.test_client()
    login(c)
    review = _review(c.get("/spam").get_data(as_text=True))
    assert "Ukendt uden DMARC" not in review and "AI er sikker" not in review
    assert "Ny butik med DMARC" in review and "Black Friday fra butikken" in review
    assert "2 mails vises ikke" in review
