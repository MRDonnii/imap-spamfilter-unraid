"""2.3 fixer: UI regressions from the review (privacy + ux lenses)."""

from __future__ import annotations

import re

from fakes_ui import insert_message
from test_ui_23 import NOW, body, client_for, detail_url, env, post  # noqa: F401

import ui_contacts  # noqa: E402,F401
import ui_kit as kit  # noqa: E402
import ui_mail  # noqa: E402

GROUP_SYMS = [{"n": "TH_KNOWN_CONTACT", "s": -3.0, "o": ["k…@kunde.example", "sendt=37", "gruppe"]},
              {"n": "TH_ESTABLISHED", "s": -2.0, "o": ["n=58", "siden=2019"]}]


def _grp(env):
    insert_message(env.conn, "bynet", "grp1@kunde.example", sender="kunde@kunde.example", subject="Hej",
                   our_score=-1.0, symbols=GROUP_SYMS)
    env.conn.commit()


def test_bruger_never_sees_colleague_counts_or_trust_numbers(env):
    _grp(env)
    for who in ("anna", "bo"):
        html = body(client_for(env, who).get(detail_url("bynet", "grp1@kunde.example")))
        if who == "anna":  # with the symbol table: the plain text, no options
            assert "<b>Kendt kontakt – du har skrevet til afsenderen</b><code>TH_KNOWN_CONTACT</code>" in html
        for leak in ("sendt=37", "37 gange", "n=58", "58 mails", "siden=2019", "k…@kunde.example, "):
            assert leak not in html, (who, leak)
    admin = body(client_for(env, "admin").get(detail_url("bynet", "grp1@kunde.example")))
    # Even an administrator gets no colleague count for a group contact (old rows included).
    assert "37 gange" not in admin and "en kollega har skrevet til afsenderen" in admin
    assert "Fast afsender – 58 mails siden 2019" in admin


def test_spam_verdict_turns_green_trust_labels_grey(env):
    env.conn.execute("UPDATE messages SET user_verdict='spam', our_action='manual_mark_spam', "
                     "current_folder='Spamfilter' WHERE message_id='kc1@nielsen-vvs.dk'")
    env.conn.commit()
    html = body(client_for(env, "admin").get(detail_url("bynet", "kc1@nielsen-vvs.dk")))
    assert "Var kendt kontakt – du har markeret mailen som spam" in html
    # The badges no longer say "trusted" (the 'Hvorfor' table keeps the scan-time record).
    badges = " ".join(re.findall(r'<span class="badge trust-badge[^"]*"[^>]*>.*?</span></span>', html, re.S))
    assert "Kendt kontakt – du har skrevet" not in badges and "Svar på din mail" not in badges
    assert "tone-neutral" in badges
    labels = ui_mail.after_spam_verdict([{"kind": "first_contact", "tone": "amber", "text": "x"}], "spam")
    assert labels[0]["kind"] == "first_contact"   # nothing trusting -> unchanged


def test_settings_notifications_follow_the_mail_server_and_name_the_channel(env):
    html = body(client_for(env, "admin").get("/settings"))
    i_smtp, i_notify = html.index('id="mailserver"'), html.index('id="notifikationer"')
    assert i_smtp < i_notify < html.index("Daglig opsummering") < html.index('id="vedhaeftninger"')
    for label in ("Alarmer på mail", "Daglig opsummering på mail", "Ugerapport på mail", "Sikkerhed på mail"):
        assert label in html
    assert "samme indhold som ugerapporten" not in html
    assert "Slå “Ugerapport på mail” til under" in html
    assert "nødbremse" not in html.lower() and "forslag – bekræftes med testmail" in html
    assert "Tom = samme adresse som brugernavnet" in html


def test_locked_release_is_a_visible_note_not_a_dead_button(env):
    html = body(client_for(env, "anna").get("/spam?account=bynet"))
    m = re.search(r'<span class="act-locked[^"]*" role="note">.*?</span></span>', html, re.S)
    assert m and "Farlig mail." in m.group(0) and "Kontakt administrator, hvis den skal frigives." in m.group(0)
    assert "title=" not in m.group(0)
    detail = body(client_for(env, "anna").get(detail_url("bynet", "virus1@x.example")))
    assert detail.count("Kontakt administrator, hvis mailen skal frigives.") == 0
    assert "Kun en administrator kan frigive den" in detail


def test_threat_detail_does_not_repeat_itself(env):
    html = body(client_for(env, "admin").get(detail_url("bynet", "virus1@x.example")))
    assert html.count("uanset score, regler og kendte kontakter") == 1
    assert "Farlig mail – flyttet uanset score." in html
    assert "Jeg forstår: " not in html
    assert "Jeg forstår, at mailen indeholder virus (Win.Trojan.Agent-12345). Den lægges i indbakken" in html
    assert "Ligger i Spamfilter-mappen" in html


def test_zap_text_is_plain_danish():
    assert ui_mail.zap_plain_text("ny=DBL_SPAM efter=3 t score=6.80->12.10") == \
        "Ny viden efter 3 timer: Linkdomæne på Spamhaus' spamliste"
    assert ui_mail.zap_plain_text("ny=- efter=45 min") == "Genscannet efter 45 minutter – intet nyt"
    assert ui_mail.zap_plain_text("ny=DBL_SPAM efter=1 t").startswith("Ny viden efter 1 time:")


def test_contacts_progress_reads_mails_not_percent(env, monkeypatch):
    ov = {"ok": True, "code": "ok", "account": "bynet", "enabled": True, "complete": False, "contacts": 0,
          "removed": 0, "demoted": 0, "sent_mails": 0, "senders": 0, "last_sync_at": None,
          "last_sync_text": "aldrig", "progress": {"done": 980, "total": 2400, "percent": 40},
          "requested": False, "group": None, "text": "Lærer fra dine sendte mails … 40 %", "help": "x"}
    monkeypatch.setattr(env.services, "contacts_overview", lambda *a, **k: ov, raising=False)
    html = body(client_for(env, "admin").get("/rules/contacts?account=bynet"))
    assert "Sendte mails gennemgået" in html and "980 / 2.400" in html
    assert "40 / 100" not in html


def test_contacts_list_subtitle_matches_the_status_card(env):
    from test_ui_23 import h_of
    import contacts as cmod
    with env.app.test_request_context("/"):
        cmod.set_status(env.conn, "bynet", h_of(env.key, "kim@revisor-aarhus.dk"), "removed", "admin")
    env.conn.commit()
    html = body(client_for(env, "admin").get("/rules/contacts?account=bynet"))
    assert "5 adresser · 4 kendte · 1 fjernet" in html


def test_protection_strip_follows_the_period(env):
    week = body(client_for(env, "admin").get("/?period=7d"))
    assert "Beskyttet af kendte kontakter de seneste 7 dage" in week and "kendte kontakter i dag" not in week
    day = body(client_for(env, "admin").get("/"))
    assert "Beskyttet af kendte kontakter i dag" in day


def test_two_step_texts(env):
    html = body(client_for(env, "admin").get("/me"))
    assert "den virker også, hvis nogen" not in html


def test_chart_labels_hidden_on_tablets_too():
    from pathlib import Path
    css = (Path(kit.__file__).parent / "static" / "app.css").read_text()
    block = css[css.index("@media (max-width: 960px) {"):]
    assert ".chart-x span.is-alt { visibility: hidden; }" in block[:400]
