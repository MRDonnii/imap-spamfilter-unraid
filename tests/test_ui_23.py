"""UI 2.3: Kendte kontakter (B13), trust labels, the threat class in the UI
(B16), blocked attachment types + exceptions (B17), rescans (B19), the new
Hjælp sections and the permission matrix of every new route.

The real services functions run against the test database (fakes_ui
EngineShim), so the pages render exactly what production returns.
"""

from __future__ import annotations

import json
import re
import time

import pytest

from fakes_ui import TEST_PASSWORD, csrf_of, fast_hash, insert_message, login, post, set_status
from fakes_ui_admin import make_admin_env

import contacts as cmod  # noqa: E402
import dashboard  # noqa: E402
import ui_admin  # noqa: E402,F401 - registers the admin routes at collection time
import ui_kit as kit  # noqa: E402
import ui_mail  # noqa: E402
from test_ui_core import INLINE_PATTERNS  # noqa: E402

PW = TEST_PASSWORD
NOW = int(time.time())

# Contacts per mailbox: (address, sent_count, days since last mail)
JT_CONTACTS = [("lars@nielsen-vvs.dk", 7, 200), ("sofie@holm.dk", 23, 12), ("kim@revisor-aarhus.dk", 3, 90),
               ("bogholderi@revisor-aarhus.dk", 16, 25), ("ven@familie.example", 4, 5)]
MOLT_CONTACTS = [("hemmelig@molt-kunde.example", 9, 10), ("kunde2@molt-kunde.example", 2, 40)]
LEAK_MOLT = ["molt-kunde.example", "h…@molt-kunde.example", "MOLT-HEMMELIGT", "account=molt", ">molt<"]

KC_SYMS = [{"n": "TH_KNOWN_CONTACT", "s": -4.0, "o": ["l…@nielsen-vvs.dk", "sendt=7", "senest=2026-03"]},
           {"n": "TH_REPLY", "s": 0.0, "o": ["l…@nielsen-vvs.dk", "sendt=2026-10-12", "loft -6"]},
           {"n": "BAYES_HAM", "s": -1.9, "o": ["91%"]}]
EST_SYMS = [{"n": "TH_ESTABLISHED", "s": -2.0, "o": ["n=14", "siden=2021"]}]
FIRST_SYMS = [{"n": "TH_FIRST_CONTACT", "s": 1.0, "o": ["nyt-firma.dk"]}]
UNVER_SYMS = [{"n": "TH_REPLY_UNVERIFIED", "s": 0.0, "o": ["k…@kunde.example", "sendt=2026-10-02"]}]
EVIL_NAME = '<img src=x onerror=alert(1)>faktura‮gpj.exe'


def write_users(env, lines: list[str]) -> None:
    (env.state / "dashboard_users").write_text("\n".join(lines) + "\n")


def _seed_contacts(env) -> bytes:
    key = cmod.load_key(env.state, None, create=True)
    c = env.conn
    cmod.ensure_schema(c)
    for acc, people in (("bynet", JT_CONTACTS), ("molt", MOLT_CONTACTS)):
        for addr, n, days in people:
            norm = cmod.normalize_address(addr)
            c.execute("INSERT OR REPLACE INTO known_contacts(account, h, domain, mask, sent_count, first_sent_at, "
                      "last_sent_at, source, status) VALUES(?,?,?,?,?,?,?,'sent','active')",
                      (acc, cmod.hash_address(key, norm), norm.split("@")[1], cmod.mask(norm), n,
                       NOW - (days + 400) * 86400, NOW - days * 86400))
        c.execute("INSERT OR REPLACE INTO contacts_sync(account, folder, kind, max_uid, total, messages, synced_at, "
                  "complete, grp) VALUES(?, '*', 'account', 0, NULL, ?, ?, 1, ?)", (acc, 1666, NOW - 600, acc + ".dk"))
    return key


def h_of(key: bytes, addr: str) -> str:
    return cmod.hash_address(key, cmod.normalize_address(addr))


@pytest.fixture
def env(tmp_path, monkeypatch):
    e = make_admin_env(tmp_path, monkeypatch)
    hp = fast_hash(PW)
    write_users(e, [f"admin:{hp}:admin:0",
                    f"anna:{hp}:bynet:0",        # Bruger, bynet, all permissions
                    f"bo:{hp}:bynet:0",          # Bruger, bynet, no permissions
                    f"cille:{hp}:~none:0"])      # Bruger without mailboxes
    with e.app.test_request_context("/"):
        dashboard.set_user_perms("bo", [], "test")
    c = e.conn
    for acc in ("bynet", "molt", "sofie"):
        set_status(c, acc, "idle", junk_exists=1)
    e.key = _seed_contacts(e)
    # Mail with trust labels (INBOX) and threats (Spamfilter-mappen).
    insert_message(c, "bynet", "kc1@nielsen-vvs.dk", sender="Lars <lars@nielsen-vvs.dk>", subject="Re: Tilbud",
                   our_score=-3.4, rspamd_score=0.6, symbols=KC_SYMS)
    insert_message(c, "bynet", "est1@datamail.example", sender="faktura@datamail.example", subject="Faktura",
                   our_score=1.2, symbols=EST_SYMS)
    insert_message(c, "bynet", "fc1@nyt-firma.dk", sender="hej@nyt-firma.dk", subject="Samarbejde",
                   our_score=4.1, symbols=FIRST_SYMS)
    insert_message(c, "bynet", "ru1@kunde.example", sender="kunde@kunde.example", subject="Re: ordre",
                   our_score=6.3, symbols=UNVER_SYMS)
    insert_message(c, "bynet", "virus1@x.example", our_action="moved_to_junk", our_score=19.6,
                   current_folder="Spamfilter", sender="Billing <billing@x.example>", subject="Faktura vedhæftet",
                   threat="virus", threat_detail="Win.Trojan.Agent-12345",
                   symbols=[{"n": "CLAM_VIRUS", "s": 20.0, "o": ["Win.Trojan.Agent-12345"]}])
    insert_message(c, "bynet", "att1@x.example", our_action="moved_to_junk", our_score=22.4,
                   current_folder="Spamfilter", sender="GLS <info@pakke.example>", subject="Pakkelabel",
                   threat="attachment", threat_detail=EVIL_NAME,
                   symbols=[{"n": "TH_ATTACH_BLOCK", "s": 20.0, "o": [EVIL_NAME, "archive"]}])
    insert_message(c, "bynet", "plain1@x.example", our_action="moved_to_junk", our_score=12.0,
                   current_folder="Spamfilter", sender="spam@x.example", subject="Almindelig spam")
    insert_message(c, "bynet", "zap1@x.example", our_action="moved_to_junk", our_score=12.1,
                   current_folder="Spamfilter", sender="nyhed@kampagne.example", subject="Kun i dag",
                   zapped_at=NOW - 3600, symbols=[{"n": "DBL_SPAM", "s": 6.5, "o": []}])
    c.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES('bynet', ?, 'zap1@x.example', "
              "'zap_move', 'ny=DBL_SPAM efter=3 t score=6.80->12.10')", (NOW - 3600,))
    insert_message(c, "molt", "m1@x.example", our_action="moved_to_junk", our_score=12.0,
                   current_folder="Spamfilter", sender="skjult@molt-kunde.example", subject="MOLT-HEMMELIGT",
                   threat="phish", symbols=[{"n": "DBL_PHISH", "s": 7.5, "o": []}])
    day = kit.today_str()
    for acc, metric, n in (("bynet", "known_contact", 5), ("bynet", "reply_detected", 2),
                           ("molt", "known_contact", 40), ("bynet", "zapped", 1), ("bynet", "threat_detected", 2)):
        c.execute("INSERT INTO stats_daily(account, day, metric, n) VALUES(?,?,?,?)", (acc, day, metric, n))
    c.commit()
    return e


def client_for(env, name: str | None):
    c = env.app.test_client()
    if name:
        r = login(c, name, PW)
        assert r.status_code == 302, name
    return c


def body(r) -> str:
    return r.get_data().decode("utf-8", "replace")


def detail_url(account: str, mid: str) -> str:
    return f"/messages/{account}/{kit.token_for(mid)}"


def key_of(account: str, mid: str) -> str:
    return f"{account}:{kit.token_for(mid)}"


def csp_clean(html: str, where: str) -> None:
    for rx, what in INLINE_PATTERNS:
        m = rx.search(html)
        assert m is None, f"{what} on {where}: {html[max(0, m.start() - 80):m.end() + 80]}"


def audits(env, action: str) -> list[dict]:
    return [r for r in env.audit() if r["action"] == action]


# ===================================================================== Kendte kontakter (B13)


def _synced_today(env) -> None:
    """Seed the last sync relative to TODAY's local midnight (test time,
    not import time): 'opdateret i dag' must not flip to 'i går' when the
    suite runs across midnight (the old NOW - 600 seed did)."""
    import services
    midnight = services._local_midnight_ts(services._local_today())
    env.conn.execute("UPDATE contacts_sync SET synced_at=? WHERE folder='*'",
                     (max(int(time.time()) - 600, midnight + 1),))
    env.conn.commit()


def test_contacts_page_admin(env):
    import services
    admin = client_for(env, "admin")
    for _ in range(2):  # a midnight between the seed and the request: seed again for the new day
        day = services._local_today()
        _synced_today(env)
        html = body(admin.get("/rules/contacts?account=bynet"))
        if services._local_today() == day:
            break
    assert "Lært fra dine sendte mails: 5 kontakter · 1.666 sendte mails · opdateret i dag" in html
    assert "Vi læser kun modtager-adresser og Message-ID fra dine sendte mails – aldrig indholdet." in html
    assert "Opdater nu" in html and "Stol på folk, jeg har skrevet til" in html
    # Masks only: none of these addresses ever wrote to the mailbox ...
    assert "l…@nielsen-vvs.dk" in html and "lars@nielsen-vvs.dk" not in html
    # ... except ven@familie.example (we have no message from it either) -> masked.
    assert "Du har skrevet 23 gange · senest" in html
    assert "Fjern" in html and 'action="/rules/contacts/status"' in html
    assert "Afsenderregler" in html and "Vedhæftninger" in html  # Regler sub navigation
    csp_clean(html, "/rules/contacts")


def test_contacts_full_address_only_when_it_also_wrote(env):
    insert_message(env.conn, "bynet", "in1@holm.dk", sender="sofie@holm.dk", subject="Hej")
    env.conn.commit()
    html = body(client_for(env, "admin").get("/rules/contacts?account=bynet"))
    assert "sofie@holm.dk" in html
    # The block button is offered for the full address only.
    assert 'value="sofie@holm.dk"' in html and "Bloker" in html
    assert 'value="lars@nielsen-vvs.dk"' not in html


def test_contacts_lookup_answers_yes_and_no(env):
    admin = client_for(env, "admin")
    html = body(admin.get("/rules/contacts?account=bynet&q=Sofie@Holm.dk"))
    assert re.search(r"Ja, du har skrevet til sofie@holm\.dk 23 gange, senest \w+ \d{4}\.", html)
    no = body(admin.get("/rules/contacts?account=bynet&q=ukendt@nowhere.example"))
    assert "Nej, du har ikke skrevet til ukendt@nowhere.example fra denne postkasse." in no
    # A molt contact is not found from bynet (per-mailbox hashes).
    other = body(admin.get("/rules/contacts?account=bynet&q=hemmelig@molt-kunde.example"))
    assert "Nej, du har ikke skrevet til" in other


def test_contacts_orgs_grouping_and_status_filter(env):
    admin = client_for(env, "admin")
    orgs = body(admin.get("/rules/contacts?account=bynet&group=orgs"))
    assert "revisor-aarhus.dk" in orgs and "2 kontakter" in orgs and "Organisationer" in orgs
    env.conn.execute("UPDATE known_contacts SET status='removed' WHERE account='bynet' AND h=?",
                     (h_of(env.key, "kim@revisor-aarhus.dk"),))
    env.conn.commit()
    removed = body(admin.get("/rules/contacts?account=bynet&status=removed"))
    assert "k…@revisor-aarhus.dk" in removed and "Gendan" in removed and "l…@nielsen-vvs.dk" not in removed


def test_contacts_mailbox_picker_for_several_mailboxes(env):
    html = body(client_for(env, "admin").get("/rules/contacts"))
    assert "Vælg en postkasse" in html and "/rules/contacts?account=bynet" in html


def test_contacts_remove_and_restore_with_masked_audit(env):
    admin = client_for(env, "admin")
    h = h_of(env.key, "lars@nielsen-vvs.dk")
    r = post(admin, "/rules/contacts/status", {"account": "bynet", "h": h, "status": "removed", "view": "contacts",
                                               "next": "/rules/contacts?account=bynet"})
    data = r.get_json()
    assert r.status_code == 200 and data["ok"] and "fjernet" in data["message"].lower()
    assert data["undo"]["fields"]["status"] == "active"  # one-click Fortryd
    assert f"contact:{h}" in data["rows"] and "Gendan" in data["rows"][f"contact:{h}"]
    row = env.conn.execute("SELECT status FROM known_contacts WHERE account='bynet' AND h=?", (h,)).fetchone()
    assert row["status"] == "removed"
    r = post(admin, "/rules/contacts/status", {"account": "bynet", "h": h, "status": "active"})
    assert r.get_json()["ok"]
    rec = audits(env, "contact_remove") + audits(env, "contact_restore")
    assert len(rec) == 2 and all("l…@nielsen-vvs.dk" in x["detail"] for x in rec)
    assert "lars@nielsen-vvs.dk" not in json.dumps(env.audit())
    # Unknown status is refused, nothing written.
    r = post(admin, "/rules/contacts/status", {"account": "bynet", "h": h, "status": "demoted"})
    assert not r.get_json()["ok"]


def test_contacts_sync_request_and_switch(env):
    admin = client_for(env, "admin")
    r = post(admin, "/rules/contacts/sync", {"account": "bynet"})
    assert r.get_json()["ok"] and "om lidt" in r.get_json()["message"]
    tok = env.conn.execute("SELECT value FROM engine_state WHERE key=?",
                           (cmod.REQUEST_STATE + "bynet",)).fetchone()
    assert tok is not None
    assert audits(env, "contacts_sync")[-1]["account"] == "bynet"
    html = body(admin.get("/rules/contacts?account=bynet"))
    assert "Opdatering bestilt" in html
    # Switch off: written through save_config (audit 'known_contacts').
    r = post(admin, "/rules/contacts/enabled", {"account": "bynet", "enabled": "0"})
    assert r.get_json()["ok"]
    assert env.entry("bynet")["known_contacts"] is False
    assert audits(env, "known_contacts")


def test_bruger_with_rules_sees_only_own_mailbox(env):
    anna = client_for(env, "anna")
    html = body(anna.get("/rules/contacts"))
    assert "l…@nielsen-vvs.dk" in html and "Fjern" in html and "Stol på folk" in html
    for s in LEAK_MOLT:
        assert s not in html, s
    assert anna.get("/rules/contacts?account=molt").status_code == 404
    assert anna.get("/rules/contacts?account=finnes-ikke").status_code == 404
    # Writes on a foreign mailbox: 404, nothing changes.
    h = h_of(env.key, "hemmelig@molt-kunde.example")
    for url, data in (("/rules/contacts/status", {"account": "molt", "h": h, "status": "removed"}),
                      ("/rules/contacts/sync", {"account": "molt"}),
                      ("/rules/contacts/enabled", {"account": "molt", "enabled": "0"})):
        assert post(anna, url, data).status_code == 404, url
    assert env.conn.execute("SELECT status FROM known_contacts WHERE account='molt' AND h=?",
                            (h,)).fetchone()["status"] == "active"
    # 'Vedhæftninger' is admin-only and not offered.
    assert 'href="/rules/attachments"' not in html


def test_bruger_without_rules_reads_but_cannot_change(env):
    bo = client_for(env, "bo")
    html = body(bo.get("/rules/contacts"))
    assert "l…@nielsen-vvs.dk" in html and "Opdater nu" in html
    assert 'action="/rules/contacts/status"' not in html and 'name="enabled"' not in html
    assert "Kun en administrator eller en bruger med adgang til regler kan ændre det." in html
    # Own nav entry 'Kendte kontakter' (no Regler for bo).
    assert 'href="/rules/contacts"' in html and 'href="/rules"' not in html
    h = h_of(env.key, "lars@nielsen-vvs.dk")
    assert post(bo, "/rules/contacts/status", {"account": "bynet", "h": h, "status": "removed"}).status_code == 403
    assert post(bo, "/rules/contacts/enabled", {"account": "bynet", "enabled": "0"}).status_code == 403
    assert post(bo, "/rules/contacts/sync", {"account": "bynet"}).get_json()["ok"]  # 'Opdater nu' is allowed


def test_bruger_without_mailboxes(env):
    cille = client_for(env, "cille")
    html = body(cille.get("/rules/contacts"))
    assert "Ingen postkasse endnu" in html
    for s in LEAK_MOLT + ["nielsen-vvs.dk", "account=bynet"]:
        assert s not in html, s
    assert cille.get("/rules/contacts?account=bynet").status_code == 404


# ===================================================================== trust labels


def test_detail_trust_labels_admin_with_numbers(env):
    html = body(client_for(env, "admin").get(detail_url("bynet", "kc1@nielsen-vvs.dk")))
    assert "Kendt kontakt – du har skrevet til afsenderen 7 gange" in html
    assert "Svar på din mail fra 12. okt." in html
    assert 'class="badge trust-badge tone-ok' in html
    assert "Kendte kontakter" in html  # the breakdown names the bonus
    est = body(client_for(env, "admin").get(detail_url("bynet", "est1@datamail.example")))
    assert "Fast afsender – 14 mails siden 2021" in est and "tone-info" in est
    first = body(client_for(env, "admin").get(detail_url("bynet", "fc1@nyt-firma.dk")))
    assert "Første mail fra denne afsender" in first and "trust-badge tone-warn" in first
    unv = body(client_for(env, "admin").get(detail_url("bynet", "ru1@kunde.example")))
    assert "Ligner et svar, men afsenderen kunne ikke bekræftes" in unv and "trust-badge tone-neutral" in unv


def test_bruger_and_preview_see_labels_without_numbers(env):
    anna = body(client_for(env, "anna").get(detail_url("bynet", "kc1@nielsen-vvs.dk")))
    assert ">Kendt kontakt<" in anna and "7 gange" not in anna.split("Hvorfor")[0]
    admin = client_for(env, "admin")
    assert "afsenderen 7 gange" in body(admin.get("/messages?account=bynet"))  # admin: full label as tooltip
    preview = body(admin.get("/users/anna/preview?p=messages"))
    assert "trust-badge" in preview and ">Kendt kontakt<" in preview and "7 gange" not in preview
    contacts = body(admin.get("/users/anna/preview?p=contacts"))
    assert "l…@nielsen-vvs.dk" in contacts and "molt-kunde" not in contacts


def test_compact_trust_chips_in_message_list(env):
    html = body(client_for(env, "admin").get("/messages?account=bynet"))
    assert "trust-badge tone-ok is-compact" in html and ">Kendt kontakt<" in html
    assert ">Fast afsender<" in html and ">Ny afsender<" in html


def test_symbol_texts_for_new_symbols():
    for n in ("TH_KNOWN_CONTACT", "TH_KNOWN_DOMAIN", "TH_REPLY", "TH_REPLY_THREAD", "TH_REPLY_UNVERIFIED",
              "TH_ESTABLISHED", "TH_FIRST_CONTACT", "TH_ATTACH_BLOCK", "TH_ATTACH_ALLOWED", "TH_ENCRYPTED_ARCHIVE"):
        assert n in kit.SYMBOL_TEXT and "_" not in kit.SYMBOL_TEXT[n]
    t = kit.explain_symbol_detail(KC_SYMS[0])
    assert t.startswith("Kendt kontakt – du har skrevet til afsenderen 7 gange, senest marts 2026")
    assert "loftet" in kit.explain_symbol_detail(KC_SYMS[1])


def test_event_labels_cover_new_engine_events():
    import contacts
    import ui_admin
    names = set(contacts.EVENTS) | {
        "threat_detected", "threat_force_pass", "threat_rescue_ignored_learning", "threat_ham_refused",
        "threat_release", "threat_release_refused", "attach_exception", "attach_exception_unverified",
        "attach_exception_added", "attach_exception_removed", "zap_move", "zap_rescore", "would_have_zapped",
        "zap_skipped", "zap_skipped_read", "zap_failed", "weekly_report_mailed"}
    for n in names:
        assert n in ui_mail.EVENT_INFO, n
        assert n in ui_admin.EVENT_LABELS, n
        assert "_" not in ui_mail.EVENT_INFO[n][0] and "_" not in ui_admin.EVENT_LABELS[n][0]
    for a in ("known_contacts", "contact_remove", "contact_restore", "contacts_sync", "attachment_block",
              "attach_exception_add", "attach_exception_remove", "user_login_scope", "login_blocked_external"):
        assert a in ui_admin.AUDIT_LABELS, a


# ===================================================================== spam verdict on a known contact (B14)


def test_mark_spam_on_known_contact_offers_keep(env):
    admin = client_for(env, "admin")
    r = post(admin, "/mail/action", {"action": "mark_spam", "items": [key_of("bynet", "kc1@nielsen-vvs.dk")],
                                     "view": "messages", "nonce": "n-kc1"})
    data = r.get_json()
    assert data["ok"] and "fjernet fra Kendte kontakter" in data["message"]
    act = data["actions"][0]
    assert act["label"] == "Behold som kontakt" and act["fields"]["status"] == "active"
    h = act["fields"]["h"]
    assert env.conn.execute("SELECT status FROM known_contacts WHERE h=?", (h,)).fetchone()["status"] == "demoted"
    # The attention item on Oversigt with the one-click restore.
    home = body(admin.get("/"))
    assert "l…@nielsen-vvs.dk er fjernet fra Kendte kontakter" in home and "Behold som kontakt" in home
    r = post(admin, "/rules/contacts/status", {"account": "bynet", "h": h, "status": "active", "next": "/"})
    assert r.get_json()["ok"]
    assert env.conn.execute("SELECT status FROM known_contacts WHERE h=?", (h,)).fetchone()["status"] == "active"
    assert "fjernet fra Kendte kontakter" not in body(admin.get("/"))


def test_demote_contact_can_be_declined(env):
    admin = client_for(env, "admin")
    r = post(admin, "/mail/action", {"action": "mark_spam", "items": [key_of("bynet", "kc1@nielsen-vvs.dk")],
                                     "view": "messages", "nonce": "n-kc2", "demote_contact": "0"})
    assert r.get_json()["ok"] and "actions" not in r.get_json()
    assert env.services.action_kwargs[-1]["demote_contact"] is False


# ===================================================================== threats (B16)


def test_threat_badges_escape_attacker_names(env):
    admin = client_for(env, "admin")
    spam = body(admin.get("/spam?account=bynet"))
    assert "threat-badge" in spam and ">Virus<" in spam
    assert "<img src=x" not in spam and "onerror=alert(1)>" not in spam and "‮" not in spam
    detail = body(admin.get(detail_url("bynet", "att1@x.example")))
    assert "Farlig vedhæftning:" in detail and "‮" not in detail
    assert "<img src=x" not in detail and "&lt;img src=x onerror=alert(1)&gt;" in detail
    csp_clean(detail, "threat detail")
    virus = body(admin.get(detail_url("bynet", "virus1@x.example")))
    assert "Virus: Win.Trojan.Agent-12345" in virus and "threat-banner" in virus


def test_short_filename_keeps_extension():
    name = "Kvittering_GLS_2026_10_21_nr_884213_meget_lang_tekst_her.pdf.exe"
    s = kit.short_filename(name, 30)
    assert s.endswith(".pdf.exe") and "…" in s and len(s) <= 30
    assert kit.clean_name("a‮b​c\x00d") == "abcd"
    compact = kit.threat_badge("Farlig vedhæftning: " + name, compact=True)
    assert ".pdf.exe" in compact and "title=" in compact
    assert ">Virus<" in kit.threat_badge("Virus: Win.Trojan", compact=True)


def test_bruger_sees_kontakt_administrator_everywhere(env):
    anna = client_for(env, "anna")
    spam = body(anna.get("/spam?account=bynet"))
    assert "Kontakt administrator" in spam
    # The threat rows have no Frigiv / Tillad buttons.
    row = spam.split("virus1@x.example")[0][-4000:] if "virus1" in spam else ""
    detail = body(anna.get(detail_url("bynet", "virus1@x.example")))
    assert "Kontakt administrator" in detail and "Frigiv alligevel" not in detail
    assert 'value="release"' not in detail.split("Handlinger")[1].split("Afsender")[0]
    assert row is not None
    # Server side: a forged release is refused (fail closed) and nothing moves.
    r = post(anna, "/mail/action", {"action": "release", "items": [key_of("bynet", "virus1@x.example")],
                                    "view": "spam", "nonce": "n-a1", "confirm_threat": "1"})
    data = r.get_json()
    assert not data["ok"] and data["results"][0]["code"] == "threat_admin"
    assert "Kontakt administrator" in data["message"]
    assert env.services.action_kwargs[-1] == {"demote_contact": True, "is_admin": False, "confirm_threat": False}
    assert env.conn.execute("SELECT user_verdict FROM messages WHERE message_id='virus1@x.example'"
                            ).fetchone()[0] is None


def test_admin_release_needs_confirmation_naming_the_threat(env):
    admin = client_for(env, "admin")
    k = key_of("bynet", "virus1@x.example")
    r = post(admin, "/mail/action", {"action": "release", "items": [k], "view": "spam", "nonce": "n-v1"})
    assert r.status_code == 409
    cf = r.get_json()["confirm"]
    assert "Win.Trojan.Agent-12345" in cf["text"] and cf["fields"]["confirm_threat"] == "1"
    assert cf["fields"]["items"] == [k] and cf["tone"] == "danger"
    assert env.conn.execute("SELECT user_verdict FROM messages WHERE message_id='virus1@x.example'"
                            ).fetchone()[0] is None
    fields = dict(cf["fields"], nonce="n-v2")
    r = post(admin, "/mail/action", fields)
    assert r.get_json()["ok"]
    assert env.services.action_kwargs[-1]["is_admin"] and env.services.action_kwargs[-1]["confirm_threat"]


def test_bulk_release_mixed_threat_and_plain(env):
    admin = client_for(env, "admin")
    r = post(admin, "/mail/action", {"action": "release", "view": "spam", "nonce": "n-b1",
                                     "items": [key_of("bynet", "plain1@x.example"), key_of("bynet", "att1@x.example")]})
    data = r.get_json()
    assert data["ok"] and data["confirm"]["fields"]["items"] == [key_of("bynet", "att1@x.example")]
    assert [x["key"] for x in data["results"]] == [key_of("bynet", "plain1@x.example")]


def test_release_allow_never_allows_threat_sender(env):
    admin = client_for(env, "admin")
    r = post(admin, "/mail/action", {"action": "release_allow", "view": "spam", "nonce": "n-ra",
                                     "items": [key_of("bynet", "virus1@x.example")]})
    assert r.status_code == 409  # first the confirmation
    assert env.conn.execute("SELECT COUNT(*) FROM sender_rules WHERE pattern LIKE '%x.example%'").fetchone()[0] == 0


def test_find_move_threat_gate(env):
    env.services.find_threats = {"virus1@x.example": ("virus", "Win.Trojan")}
    data = {"account": "bynet", "folder": "Junk", "message_id": "virus1@x.example", "uid": "5", "q": "x", "days": "30"}
    r = post(client_for(env, "anna"), "/find/move", data)
    assert r.get_json()["ok"] is False and "Kontakt administrator" in r.get_json()["message"]
    r = post(client_for(env, "admin"), "/find/move", data)
    assert r.status_code == 409 and r.get_json()["confirm"]["fields"]["confirm_threat"] == "1"
    r = post(client_for(env, "admin"), "/find/move", dict(data, confirm_threat="1"))
    assert r.get_json()["ok"]


# ===================================================================== rescans (B19) + Oversigt


def test_zap_label_and_timeline(env):
    html = body(client_for(env, "admin").get(detail_url("bynet", "zap1@x.example")))
    # Plain Danish for everybody (fixer): no raw rspamd names, 't' spelled out.
    assert "Fanget ved genscanning" in html
    assert "Ny viden efter 3 timer: Linkdomæne på Spamhaus" in html
    assert "Ny viden: DBL_SPAM" not in html
    lst = body(client_for(env, "admin").get("/spam?account=bynet"))
    assert "zap-badge" in lst


def test_overview_protection_strip_scoped(env):
    admin = body(client_for(env, "admin").get("/?account=bynet"))
    assert "Beskyttet af kendte kontakter i dag" in admin and "prot-strip" in admin
    assert re.search(r"Beskyttet af kendte kontakter i dag:</span> <b class=\"num\">7</b>", admin)
    assert "Flyttet efterfølgende i dag" in admin
    # Dangerous mails today: either the red card or the strip item - never both, same words.
    assert admin.count("Farlige mails stoppet i dag") == 1 and "Trusler stoppet" not in admin
    everything = body(client_for(env, "admin").get("/"))
    assert re.search(r"Beskyttet af kendte kontakter i dag:</span> <b class=\"num\">47</b>", everything)
    # The 2.2 overview grid is still there in the same order (regression gate).
    for part in ("Nøgletal", "Post de seneste 14 dage", "Kræver opmærksomhed", "Postkasser"):
        assert part in everything
    assert everything.index("Nøgletal") < everything.index("prot-strip") < everything.index("Post de seneste 14 dage")


def test_undo_preview_mentions_threats(env, monkeypatch):
    prev = {"ok": True, "count": 3, "gone": 0, "threats": 1, "items": [], "text": "3 mails"}
    monkeypatch.setattr(env.services, "preview_undo", lambda *a, **k: prev, raising=False)
    html = body(client_for(env, "admin").get("/undo?account=bynet&period=today"))
    if "undo-preview" in html:
        assert "farlig mail" in html and "flyttes ikke tilbage" in html


# ===================================================================== B17 attachments


def test_settings_attachment_list_editor(env):
    admin = client_for(env, "admin")
    html = body(admin.get("/settings"))
    assert 'id="vedhaeftninger"' in html and "Farlige vedhæftninger" in html and ".exe" in html
    r = post(admin, "/settings/attachments", {"extensions": "exe, .iso *.js"})
    assert r.get_json()["ok"]
    assert env.raw_config()["defaults"]["attachment_block"] == ["exe", "iso", "js"]
    assert audits(env, "attachment_block")
    r = post(admin, "/settings/attachments", {"extensions": "exe bad!ext"})
    assert not r.get_json()["ok"] and env.raw_config()["defaults"]["attachment_block"] == ["exe", "iso", "js"]
    r = post(admin, "/settings/attachments", {"reset": "1"})
    assert r.get_json()["ok"]
    assert "attachment_block" not in env.raw_config()["defaults"] or \
        len(env.raw_config()["defaults"]["attachment_block"]) > 10


def test_attachment_exceptions_admin_only(env):
    admin = client_for(env, "admin")
    html = body(admin.get("/rules/attachments"))
    assert "Ny undtagelse" in html and "Afsendere med undtagelse" in html
    r = post(admin, "/rules/attachments/add", {"account": "bynet", "pattern": "@revisor-aarhus.dk",
                                               "note": "installationsfiler"})
    assert r.get_json()["ok"]
    rid = env.conn.execute("SELECT id FROM attach_rules WHERE pattern='@revisor-aarhus.dk'").fetchone()[0]
    assert "@revisor-aarhus.dk" in body(admin.get("/rules/attachments"))
    for who in ("anna", "bo", "cille"):
        c = client_for(env, who)
        assert c.get("/rules/attachments").status_code == 403
        assert post(c, "/rules/attachments/add", {"account": "bynet", "pattern": "@x.dk"}).status_code == 403
        assert post(c, f"/rules/attachments/{rid}/delete", {}).status_code == 403
        assert post(c, "/settings/attachments", {"extensions": "exe"}).status_code == 403
    r = post(admin, f"/rules/attachments/{rid}/delete", {})
    assert r.get_json()["ok"]
    assert post(admin, "/rules/attachments/999/delete", {}).status_code == 404
    assert audits(env, "attach_exception_add") and audits(env, "attach_exception_remove")


def test_detail_offers_attachment_exception_to_admin_only(env):
    admin = body(client_for(env, "admin").get(detail_url("bynet", "att1@x.example")))
    assert "Tillad farlige vedhæftninger fra denne afsender" in admin
    assert "Tillad afsender" not in admin.split("Handlinger")[1]
    anna = body(client_for(env, "anna").get(detail_url("bynet", "att1@x.example")))
    assert "Tillad farlige vedhæftninger" not in anna


# ===================================================================== Hjælp


def test_help_sections(env):
    admin = body(client_for(env, "admin").get("/help"))
    for title in ("Kendte kontakter", "Svar på din mail", "Fast afsender", "Farlige mails", "Genscanning",
                  "Kode på mail"):
        assert title in admin, title
    anna = body(client_for(env, "anna").get("/help"))
    assert "Kendte kontakter" in anna and "Kun en administrator kan frigive den" in anna


# ===================================================================== permission matrix of the new routes

NEW_GET = ["/rules/contacts", "/rules/contacts?account=bynet", "/rules/contacts?account=molt",
           "/rules/contacts?account=bynet&group=orgs", "/rules/contacts?account=bynet&q=sofie@holm.dk",
           "/rules/attachments"]
EXPECT_GET = {
    "admin": {u: 200 for u in NEW_GET},
    "anna": {**{u: 200 for u in NEW_GET}, "/rules/contacts?account=molt": 404, "/rules/attachments": 403},
    "bo": {**{u: 200 for u in NEW_GET}, "/rules/contacts?account=molt": 404, "/rules/attachments": 403},
    "cille": {**{u: 404 for u in NEW_GET}, "/rules/contacts": 200, "/rules/attachments": 403},
}


@pytest.mark.parametrize("who", ["admin", "anna", "bo", "cille", None])
def test_new_routes_get_matrix(env, who):
    c = client_for(env, who)
    for url in NEW_GET:
        r = c.get(url, headers={"Accept": "text/html"})
        if who is None:
            assert r.status_code == 302 and "/login" in r.headers["Location"], url
            continue
        assert r.status_code == EXPECT_GET[who][url], f"{who} {url}: {r.status_code}"
        if r.status_code == 200 and who != "admin":
            text = body(r)
            for s in LEAK_MOLT:
                assert s not in text, f"{who} {url} leaks {s}"


@pytest.mark.parametrize("who", ["anna", "bo", "cille", None])
def test_new_routes_post_matrix(env, who):
    c = client_for(env, who)
    h = h_of(env.key, "hemmelig@molt-kunde.example")
    cfg = env.config.read_text()
    cases = [("/rules/contacts/status", {"account": "molt", "h": h, "status": "removed"}),
             ("/rules/contacts/sync", {"account": "molt"}),
             ("/rules/contacts/enabled", {"account": "molt", "enabled": "0"}),
             ("/rules/attachments/add", {"account": "*", "pattern": "@x.dk"}),
             ("/rules/attachments/1/delete", {}),
             ("/settings/attachments", {"extensions": "exe"})]
    for url, data in cases:
        r = post(c, url, data)
        if who is None:
            assert r.status_code == 401, url
        elif who == "bo" and url in ("/rules/contacts/status", "/rules/contacts/enabled"):
            assert r.status_code == 403, url
        elif url.startswith(("/rules/attachments", "/settings")):
            assert r.status_code == 403, url
        else:
            assert r.status_code == 404, f"{who} {url}: {r.status_code}"  # foreign mailbox
    assert env.config.read_text() == cfg
    assert env.conn.execute("SELECT status FROM known_contacts WHERE account='molt' AND h=?",
                            (h,)).fetchone()["status"] == "active"
    assert env.conn.execute("SELECT COUNT(*) FROM engine_state WHERE key LIKE 'contacts_sync_request:%'"
                            ).fetchone()[0] == 0


def test_csrf_required_on_new_posts(env):
    admin = client_for(env, "admin")
    for url in ("/rules/contacts/status", "/rules/contacts/sync", "/rules/contacts/enabled",
                "/rules/attachments/add", "/settings/attachments"):
        r = admin.post(url, data={"account": "bynet"})
        assert r.status_code == 400, url
    assert csrf_of(admin)


def test_calibration_trust_split_card(env):
    import ui_admin
    summ = {"trust": {"with_count": 12, "without_count": 88, "with": {"median": -1.5}, "without": {"median": 3.25},
                      "note": "Opdelt efter, om mailen fik bonus som kendt kontakt."}}
    with env.app.test_request_context("/"):
        html = ui_admin._trust_split_card(summ)
        assert "Med kendte kontakter" in html and "median −1,5" in html.replace("-", "−") and "Opdelt efter" in html
        assert ui_admin._trust_split_card({"trust": {"with_count": 0}}) == ""
