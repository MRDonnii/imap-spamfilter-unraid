"""2.6 A4: newsletter folder "Nyhedsbreve" - classification, config,
shadow vs on, spam priority, no Bayes learning and the keep-in-inbox
memory (newsletters.py + the engine hooks in filter.py)."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "filter"))

import newsletters as nl  # noqa: E402
from fakes_engine import make_message, setup_engine  # noqa: E402
from test_engine_scan import Harness  # noqa: E402

LOG = logging.getLogger("test")
UNSUB = "List-Unsubscribe: <https://click.example.com/u/abc>, <mailto:u@example.com>"
ONECLICK = UNSUB + "\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click"


def raw(subject: str, sender: str = "news@brand.example", extra: str = UNSUB, body: str = "Hej\r\n") -> bytes:
    return make_message("m@x", subject=subject, sender=sender, extra_headers=extra, body=body)


def verdict(subject: str, sender: str = "news@brand.example", extra: str = UNSUB, **kw) -> nl.Verdict:
    kw.setdefault("final", 1.0)
    kw.setdefault("threshold", 6.0)
    return nl.classify(raw(subject, sender, extra), subject=subject, sender=sender, **kw)


# ----- classification: should move -----------------------------------------


@pytest.mark.parametrize("subject,sender,extra", [
    ("Call of Duty: Black Ops 7 er her – forudbestil nu", "news@activision.example", ONECLICK),
    ("AMD Ryzen: nye processorer til din næste gaming-pc", "amd@email.amd.example", UNSUB),
    ("Lenovo Black Friday: op til 40 % på ThinkPad", "lenovo@news.lenovo.example",
     "Precedence: bulk\r\nX-SFMC-Stack: 7"),
    ("Nye styles fra Perfect Jeans – gratis levering i weekenden", "info@perfectjeans.example", UNSUB),
    ("Plantorama klub: Ugens tilbud til dig", "klub@plantorama.example", UNSUB + "\r\nX-Mailer: Klaviyo"),
    ("Get ready for the trade fair", "events@fair.example", "Precedence: list"),
    ("Brug rabatkoden SOMMER20 og spar 20 %", "shop@brand.example", UNSUB),
])
def test_marketing_mail_is_a_newsletter(subject, sender, extra):
    v = verdict(subject, sender, extra)
    assert v.newsletter, v
    assert v.reason == "newsletter" and v.signals


def test_rspamd_symbol_alone_is_a_strong_signal():
    v = verdict("Ugens nyheder", extra="", names={"HAS_LIST_UNSUB"})
    assert v.newsletter and "HAS_LIST_UNSUB" in v.signals


# ----- classification: stays in the inbox ----------------------------------


@pytest.mark.parametrize("subject,sender", [
    ("[Alert] Tunnel health changed", "noreply@notify.cloudflare.example"),
    ("Du er inviteret til: Holdfoto", "noreply@klubben.example"),
    ("Ordrebekræftelse #12345", "shop@brand.example"),
    ("Din ordre er afsendt", "shop@brand.example"),
    ("Your order has shipped", "shop@brand.example"),
    ("Faktura 2026-118 fra Brand", "shop@brand.example"),
    ("Kvittering for dit køb", "shop@brand.example"),
    ("Din pakke er på vej", "shop@brand.example"),
    ("Nulstil din adgangskode", "account@brand.example"),
    ("Din kode: 482913", "account@brand.example"),
    ("Your verification code", "account@brand.example"),
    ("Bekræft din e-mailadresse", "account@brand.example"),
    ("Ny enhed loggede ind på din konto", "account@brand.example"),
    ("Din konto på webshoppen Brand er blevet oprettet", "post@brand.example"),
    ("Your account has been created", "hello@brand.example"),
    ("Booking bekræftet: bord til 4", "booking@restaurant.example"),
    ("Månedens nyheder", "faktura@brand.example"),   # transactional sender name
])
def test_transactional_mail_stays(subject, sender):
    v = verdict(subject, sender)
    assert not v.newsletter
    assert v.reason == "transactional", v


def test_calendar_part_and_auto_submitted_stay():
    cal = raw("Holdfoto lørdag", extra=UNSUB + "\r\nContent-Type: text/calendar; method=REQUEST")
    assert nl.classify(cal, subject="Holdfoto lørdag", sender="a@b.example", final=0, threshold=6).reason \
        == "transactional"
    auto = raw("Status for din tjeneste", extra=UNSUB + "\r\nAuto-Submitted: auto-generated")
    assert nl.classify(auto, subject="Status for din tjeneste", sender="a@b.example", final=0,
                       threshold=6).reason == "transactional"


def test_esp_signal_alone_is_not_enough():
    # Receipts and password resets go through the same ESPs - without an
    # unsubscribe header they are never newsletters.
    v = verdict("Tak for din tilmelding", extra="X-SG-EID: abc\r\nFeedback-ID: 1:2:sendgrid")
    assert not v.newsletter and v.reason == "no_bulk"
    assert any(s.startswith("esp:") for s in v.signals)


def test_over_threshold_is_spam_not_newsletter():
    assert verdict("Ugens tilbud", final=6.0, threshold=6.0).reason == "spam"
    assert verdict("Ugens tilbud", spam=True).reason == "spam"
    assert verdict("Ugens tilbud", threat="phish").reason == "spam"


@pytest.mark.parametrize("kw,reason", [
    ({"names": {"TH_KNOWN_CONTACT"}}, "contact"),
    ({"names": {"TH_REPLY"}}, "contact"),
    ({"names": {"TH_REPLY_THREAD"}}, "contact"),
    ({"names": {"TH_KNOWN_DOMAIN"}}, "contact"),
    ({"names": {"TH_PROTECTED_RCPT"}}, "protected"),
    ({"allow_rule": True}, "allow_rule"),
    ({"kept": True}, "keep"),
    ({"flags": {"\\Flagged"}}, "flagged"),
])
def test_exclusions(kw, reason):
    v = verdict("Ugens tilbud", **kw)
    assert not v.newsletter and v.reason == reason


def test_established_sender_alone_is_still_a_newsletter():
    assert verdict("Ugens tilbud", names={"TH_ESTABLISHED"}).newsletter


def test_owner_domains_and_vexar_shop_always_stay():
    assert verdict("Nyt i shoppen", sender="noreply@vexar.example").reason == "own_domain"
    assert verdict("Nyt i shoppen", sender="shop@kunde.example",
                   auth={"dkim": ["mail.vexar.example"], "host": None}).reason == "own_domain"
    assert verdict("Nyt i shoppen", sender="shop@kunde.example",
                   ctx={"origin_host": "mail-sender-3.vexar.example"}).reason == "own_domain"
    assert verdict("Nyt", sender="info@pinsikbing.example", owner_domains=["pinsikbing.example"]).reason == "own_domain"


def test_parse_mode_accepts_yaml_booleans():
    assert nl.parse_mode(True) == "on" and nl.parse_mode(False) == "off"
    assert nl.parse_mode("Shadow") == "shadow"
    with pytest.raises(ValueError):
        nl.parse_mode("maybe")


# ----- config ---------------------------------------------------------------


@pytest.fixture
def eng(tmp_path, monkeypatch):
    return setup_engine(tmp_path, monkeypatch)


def _write(tmp_path, text):
    p = tmp_path / "cfg.yml"
    p.write_text(text)
    return p


BASE = """
accounts:
  - name: a
    user: a@example.dk
    imap_host: imap.example.net
    password: x
"""


def test_config_defaults_to_shadow(eng, tmp_path):
    acc = eng.load_account_configs(_write(tmp_path, BASE))[0]
    assert acc.newsletters == "shadow" and acc.newsletter_folder == "Nyhedsbreve"


@pytest.mark.parametrize("value,expected", [("on", "on"), ("off", "off"), ("'on'", "on"), ("shadow", "shadow"),
                                            ("true", "on")])
def test_config_values(eng, tmp_path, value, expected):
    acc = eng.load_account_configs(_write(tmp_path, BASE + f"    newsletters: {value}\n"))[0]
    assert acc.newsletters == expected


@pytest.mark.parametrize("extra", ["    newsletters: sometimes\n", "    newsletter_folder: Junk\n",
                                   "    newsletter_folder: inbox\n", "    newsletter_folder: ''\n"])
def test_config_rejects_bad_values(eng, tmp_path, extra):
    with pytest.raises(eng.ConfigError):
        eng.load_account_configs(_write(tmp_path, BASE + extra))


def test_defaults_block_sets_all_accounts(eng, tmp_path):
    text = "defaults:\n  newsletters: off\n  newsletter_folder: Reklamer\n" + BASE
    acc = eng.load_account_configs(_write(tmp_path, text))[0]
    assert acc.newsletters == "off" and acc.newsletter_folder == "Reklamer"


# ----- engine: shadow vs on --------------------------------------------------


def deliver_news(h, msgid, *, score=1.0, subject="Ugens tilbud til dig", sender="news@brand.example",
                 extra=UNSUB, flags=()):
    return h.deliver(msgid, score=score, subject=subject, sender=sender, extra_headers=extra, flags=flags)


def test_shadow_records_only(eng, monkeypatch):
    h = Harness(eng, monkeypatch, newsletters="shadow")
    deliver_news(h, "n1@x")
    h.scan()
    h.advance(3600)
    h.moves()
    eng.newsletter_moves(h.client, h.db, LOG, h.acc, h.acc.folder_map, h.state)
    assert h.client.msgids("INBOX") == ["n1@x"]
    assert "Nyhedsbreve" not in h.client.folders
    assert h.row("n1@x")["our_action"] == "none"
    assert [e[1] for e in h.events("newsletter_shadow")] == ["n1@x"]
    assert h.stat("newsletter_shadow") == 1
    assert nl.shadow_count(h.db.conn, h.acc.name, now=h.t) == 1
    items = nl.recent(h.db.conn, h.acc.name, now=h.t)
    assert items[0]["subject"] == "Ugens tilbud til dig" and "list-unsubscribe" in items[0]["signals"]


def test_on_moves_to_newsletter_folder_after_grace(eng, monkeypatch):
    h = Harness(eng, monkeypatch, newsletters="on")
    deliver_news(h, "n1@x")
    h.deliver("plain@x", score=1.0)
    h.scan()
    assert h.row("n1@x")["our_action"] == nl.ACTION_PENDING
    eng.newsletter_moves(h.client, h.db, LOG, h.acc, h.acc.folder_map, h.state)
    assert h.client.msgids("INBOX") == ["n1@x", "plain@x"]  # grace not over
    h.advance(61)
    h.loop()
    assert h.client.msgids("INBOX") == ["plain@x"]
    assert h.client.msgids("Nyhedsbreve") == ["n1@x"]
    row = h.row("n1@x")
    assert row["our_action"] == nl.ACTION_MOVED and row["current_folder"] == "Nyhedsbreve"
    assert row["moved_to_junk_at"] is None and row["learned_as"] is None and row["pending_learn"] is None
    assert [e[1] for e in h.events("newsletter_move")] == ["n1@x"]
    assert h.stat("newsletter_moved") == 1 and h.stat("moved") == 0
    assert h.client.msgids("Junk") == []
    assert h.db.conn.execute("SELECT COUNT(*) FROM move_journal").fetchone()[0] == 0


def test_on_requires_move_mode(eng, monkeypatch):
    h = Harness(eng, monkeypatch, newsletters="on", mode="flag")
    deliver_news(h, "n1@x")
    h.scan()
    h.advance(3600)
    h.loop()
    assert h.client.msgids("INBOX") == ["n1@x"]
    assert [e[1] for e in h.events("newsletter_shadow")] == ["n1@x"]


def test_off_does_nothing(eng, monkeypatch):
    h = Harness(eng, monkeypatch, newsletters="off")
    deliver_news(h, "n1@x")
    h.scan()
    assert not [e for e in h.events() if e[0].startswith("newsletter")]


def test_spam_over_threshold_goes_to_junk_not_newsletters(eng, monkeypatch):
    h = Harness(eng, monkeypatch, newsletters="on")
    deliver_news(h, "spam@x", score=12.0)
    h.scan()
    h.advance(3600)
    h.loop()
    assert h.client.msgids("Junk") == ["spam@x"]
    assert "Nyhedsbreve" not in h.client.folders
    assert not h.events("newsletter_queued") and not h.events("newsletter_move")


def test_newsletter_move_never_learns_and_junk_poll_ignores_the_folder(eng, monkeypatch):
    h = Harness(eng, monkeypatch, newsletters="on")
    deliver_news(h, "n1@x")
    h.scan()
    h.advance(61)
    h.loop()
    h.advance(8 * 86400)
    h.loop()
    h.poll()
    eng.autolearn_pass(h.client, h.db, LOG, h.acc, h.acc.folder_map)
    eng.process_pending_learns(h.client, h.db, LOG, h.acc, h.acc.folder_map)
    assert h.rspamd.learn_calls == []
    assert h.row("n1@x")["learned_as"] is None
    assert h.row("n1@x")["our_action"] == nl.ACTION_MOVED


def test_read_during_grace_stays(eng, monkeypatch):
    h = Harness(eng, monkeypatch, newsletters="on")
    uid = deliver_news(h, "n1@x")
    h.scan()
    h.client.folders["INBOX"].msgs[uid].flags.add("\\Seen")
    h.advance(61)
    h.loop()
    assert h.client.msgids("INBOX") == ["n1@x"]
    assert h.row("n1@x")["our_action"] == "none"
    assert h.events("newsletter_skipped_read")


def test_transactional_and_contact_mail_stays_in_engine(eng, monkeypatch):
    h = Harness(eng, monkeypatch, newsletters="on")
    deliver_news(h, "alert@x", subject="[Alert] Tunnel health changed", sender="noreply@notify.cloudflare.example")
    deliver_news(h, "hold@x", subject="Du er inviteret til: Holdfoto", sender="noreply@klubben.example")
    deliver_news(h, "c@x", sender="friend@brand.example")
    h.rspamd.symbols["c@x"] = {"TH_KNOWN_CONTACT": {"name": "TH_KNOWN_CONTACT", "score": -4.0}}
    h.scan()
    h.advance(3600)
    h.loop()
    assert sorted(h.client.msgids("INBOX")) == ["alert@x", "c@x", "hold@x"]
    reasons = {e[1]: e[2].split(" ")[0] for e in h.events("newsletter_excluded")}
    assert reasons == {"alert@x": "transactional", "hold@x": "transactional", "c@x": "contact"}


def test_allow_rule_keeps_mail_in_inbox(eng, monkeypatch):
    h = Harness(eng, monkeypatch, newsletters="on")
    eng.add_sender_rule(h.db.conn, h.acc.name, "@brand.example", "allow", "test", "admin")
    deliver_news(h, "n1@x")
    h.scan()
    h.advance(61)
    h.loop()
    assert h.client.msgids("INBOX") == ["n1@x"]
    assert not h.events("newsletter_queued")


def test_switching_off_cancels_pending(eng, monkeypatch):
    h = Harness(eng, monkeypatch, newsletters="on")
    deliver_news(h, "n1@x")
    h.scan()
    h.acc.newsletters = "shadow"
    h.advance(61)
    h.loop()
    assert h.client.msgids("INBOX") == ["n1@x"]
    assert h.row("n1@x")["our_action"] == "none"
    assert h.db.conn.execute("SELECT COUNT(*) FROM newsletter_pending").fetchone()[0] == 0


# ----- keep in inbox -----------------------------------------------------------


def test_drag_back_keeps_sender_forever(eng, monkeypatch):
    h = Harness(eng, monkeypatch, newsletters="on")
    deliver_news(h, "n1@x")
    h.scan()
    h.advance(61)
    h.loop()
    assert h.client.msgids("Nyhedsbreve") == ["n1@x"]
    h.user_moves("n1@x", "Nyhedsbreve", "INBOX", flags=["\\Seen"])
    h.scan()
    row = h.row("n1@x")
    assert row["our_action"] == nl.ACTION_KEPT and row["current_folder"] == "INBOX"
    assert row["user_verdict"] is None  # not a spam/ham verdict
    assert nl.is_kept(h.db.conn, h.acc.name, "News@Brand.example")
    assert h.stat("newsletter_kept") == 1 and h.events("newsletter_kept")
    # The next issue from the same sender stays in the inbox.
    h.advance(10)
    deliver_news(h, "n2@x", subject="Ugens nye tilbud")
    h.scan()
    h.advance(3600)
    h.loop()
    assert sorted(h.client.msgids("INBOX")) == ["n1@x", "n2@x"]
    assert [e[2].split(" ")[0] for e in h.events("newsletter_excluded")] == ["keep"]
    assert h.rspamd.learn_calls == []
    # Another scan never moves the kept copy again.
    h.loop()
    assert "n1@x" in h.client.msgids("INBOX")


def test_kept_message_id_alone_never_skips_scoring(eng, monkeypatch):
    """A later mail that reuses a kept newsletter's Message-ID (a new
    delivery: another INTERNALDATE) is scored like new mail."""
    h = Harness(eng, monkeypatch, newsletters="on")
    deliver_news(h, "n1@x")
    h.scan()
    h.advance(61)
    h.loop()
    h.user_moves("n1@x", "Nyhedsbreve", "INBOX", flags=["\\Seen"])
    h.scan()
    assert h.row("n1@x")["our_action"] == nl.ACTION_KEPT
    calls = len(h.rspamd.scan_calls)
    h.advance(3600)
    deliver_news(h, "n1@x", score=20.0, subject="Din konto er spærret")
    h.scan()
    assert len(h.rspamd.scan_calls) == calls + 1
    assert h.row("n1@x")["our_action"] == nl.ACTION_KEPT
    assert h.db.conn.execute("SELECT COUNT(*) FROM messages WHERE message_id LIKE 'sf-local:%' "
                             "AND our_action='pending_move'").fetchone()[0] == 1


def test_interrupted_copy_is_repaired(eng, monkeypatch):
    from fakes_engine import IMAPClientError
    h = Harness(eng, monkeypatch, newsletters="on")  # Gigahost: COPY + STORE + UID EXPUNGE
    deliver_news(h, "n1@x")
    h.scan()
    h.advance(61)
    eng.newsletter_moves(h.client, h.db, LOG, h.acc, h.acc.folder_map, h.state)  # creates the folder
    assert h.client.msgids("Nyhedsbreve") == ["n1@x"]
    deliver_news(h, "n2@x", subject="Nyt fra os")
    h.scan()
    h.advance(61)
    h.client.fail_on["uid_expunge"] = IMAPClientError("NO expunge failed")
    eng.newsletter_moves(h.client, h.db, LOG, h.acc, h.acc.folder_map, h.state)
    assert h.row("n2@x")["our_action"] == nl.ACTION_FAILED
    assert h.db.conn.execute("SELECT COUNT(*) FROM move_journal").fetchone()[0] == 1
    eng.newsletter_moves(h.client, h.db, LOG, h.acc, h.acc.folder_map, h.state)
    assert h.client.msgids("INBOX") == []
    assert sorted(h.client.msgids("Nyhedsbreve")) == ["n1@x", "n2@x"]
    assert h.row("n2@x")["our_action"] == nl.ACTION_MOVED
    assert h.db.conn.execute("SELECT COUNT(*) FROM move_journal").fetchone()[0] == 0


def test_circuit_breaker_and_safe_mode_pause_newsletter_moves(eng, monkeypatch):
    h = Harness(eng, monkeypatch, newsletters="on")
    deliver_news(h, "n1@x")
    h.scan()
    h.advance(61)
    eng.open_circuit(h.db.conn, h.acc.name, "test")
    eng.newsletter_moves(h.client, h.db, LOG, h.acc, h.acc.folder_map, h.state)
    assert h.client.msgids("INBOX") == ["n1@x"]
    eng.resume_moves(h.db.conn, h.acc.name, "admin")
    eng.newsletter_moves(h.client, h.db, LOG, h.acc, h.acc.folder_map, h.state)
    assert h.client.msgids("Nyhedsbreve") == ["n1@x"]
