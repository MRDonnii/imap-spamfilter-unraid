"""ENGINE: Straks-advarsel (threat notices) and the admin threat alert.

When a mail with a threat class is MOVED to the filter's folder, the
mailbox gets one Danish notice in its own INBOX (APPEND, no SMTP needed),
at most one per 30 minutes per mailbox, listing at most 10 mails. The
notice is registered like a receipt, so the scanner, the junk poll and
every learn path skip it - a forged look-alike is still scanned. It never
carries a URL, attachment or HTML of the dangerous mail. Virus, dangerous
attachments and phishing/malware links also give an admin alert mail
(mailer.notify kind 'alert') when SMTP is set up: each mail once, at most
one per mailbox per 30 minutes."""

from __future__ import annotations

import email
import email.policy
import logging
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import make_message, setup_engine  # noqa: E402
from test_engine_contacts import sym  # noqa: E402
from test_engine_scan import Harness  # noqa: E402
from test_engine_threat import mail_with_attachments  # noqa: E402

LOG = logging.getLogger("test-threatnotice")

VIRUS = sym("CLAM_VIRUS", 0.0, ["Win.Trojan.Agent-123"])
PHISH = sym("DBL_PHISH", 7.5, ["evil.example:url"])
ATTACH_EXT = "exe"


@pytest.fixture
def eng(tmp_path, monkeypatch):
    e = setup_engine(tmp_path, monkeypatch)
    import contacts

    contacts.forget_cached_keys()
    monkeypatch.setattr(e, "_mailer", lambda: None)  # no SMTP unless a test installs one
    yield e
    contacts.forget_cached_keys()


def threat_mail(h, msgid, symbols, *, sender="angriber@evil.example", subject="Din konto er lukket",
                name="PayPal Support", raw=None):
    import datetime as dt

    h.rspamd.scores[msgid] = 3.0
    h.rspamd.symbols[msgid] = symbols
    if raw is None:
        raw = make_message(msgid, sender=sender, subject=subject).replace(
            f"From: Sender <{sender}>".encode(), f"From: {name} <{sender}>".encode())
    h.client.add("INBOX", raw, internaldate=dt.datetime.fromtimestamp(h.t, dt.timezone.utc))


def catch(h):
    """Scan, let the short grace pass, move, then run the notice step."""
    h.scan()
    h.advance(10)
    h.moves()
    return h.eng.maybe_send_threat_notice(h.client, h.db, LOG, h.acc, h.acc.folder_map)


def notices(h):
    out = []
    for uid in h.client.uids("INBOX"):
        raw = h.client.folders["INBOX"].msgs[uid].raw
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        if str(msg.get("X-TH-Spamfilter-Kind", "")) == "threat-notice":
            out.append(msg)
    return out


def body_text(msg):
    return msg.get_body(("plain",)).get_content()


def body_html(msg):
    return msg.get_body(("html",)).get_content()


# ----------------------------------------------------------------- notice

def test_threat_moved_gives_one_notice_in_the_inbox(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=10.0)
    threat_mail(h, "ph1@x", PHISH)
    assert catch(h) is True
    assert "ph1@x" in h.client.msgids("Junk")
    [n] = notices(h)
    assert str(n["Subject"]) == "⚠️ Spamfilteret har stoppet en farlig mail"
    assert str(n["X-TH-Spamfilter"]) == "report" and str(n["Auto-Submitted"]) == "auto-generated"
    text = body_text(n)
    assert text.startswith("⚠️ Spamfilteret har stoppet en farlig mail")
    assert "Afsender: PayPal Support <angriber@evil.example>" in text
    assert "Emne: Din konto er lukket" in text
    assert "Type: Phishing-link – linket fører til en falsk side" in text
    assert "Modtaget: " in text and " kl. " in text
    assert ("Mailen ligger i mappen Junk. Åbn den ikke, og klik ikke på links. "
            "Ventede du mailen, så kontakt administratoren.") in text
    # Registered like a receipt and counted.
    mid = str(n["Message-ID"]).strip("<>")
    assert mid.endswith("@hjemmeserver.spamfilter")
    row = h.db.conn.execute("SELECT kind, items FROM daily_receipts WHERE message_id=?", (mid,)).fetchone()
    assert tuple(row) == ("threat", 1)
    assert h.stat("threat_notice_sent") == 1
    ev = h.events("threat_notice_sent")
    assert ev == [("threat_notice_sent", mid, "items=1")]
    t = h.db.conn.execute("SELECT notice_id, sent_at, sender_name FROM threat_notices WHERE message_id='ph1@x'"
                          ).fetchone()
    assert t[0] == mid and t[1] and t[2] == "PayPal Support"
    # Nothing new: no second notice.
    assert eng.maybe_send_threat_notice(h.client, h.db, LOG, h.acc, h.acc.folder_map) is False


def test_virus_and_attachment_type_texts(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=10.0)
    threat_mail(h, "v1@x", VIRUS, subject="Faktura")
    import datetime as dt

    h.rspamd.scores["a1@x"] = 1.0
    h.client.add("INBOX", mail_with_attachments("a1@x", [("faktura.pdf.exe", b"MZ")]),
                 internaldate=dt.datetime.fromtimestamp(h.t, dt.timezone.utc))
    assert catch(h)
    [n] = notices(h)
    assert str(n["Subject"]) == "⚠️ Spamfilteret har stoppet 2 farlige mails"
    text = body_text(n)
    assert "Type: Virus" in text and "Win.Trojan" not in text
    assert "Type: Farlig vedhæftning: faktura․pdf․exe" in text
    assert "1. Afsender:" in text and "2. Afsender:" in text
    assert ("Mailene ligger i mappen Junk. Åbn dem ikke, og klik ikke på links. "
            "Ventede du en af mailene, så kontakt administratoren.") in text


def test_at_most_one_notice_per_30_minutes_batches_the_rest(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=10.0, circuit_max_ratio=1.0, circuit_max_moves_per_hour=200)
    threat_mail(h, "b0@x", PHISH)
    assert catch(h)
    for i in range(1, 13):
        threat_mail(h, f"b{i}@x", PHISH, subject=f"Mail nummer {i}")
    assert catch(h) is False            # inside the 30 min window: waits
    assert len(notices(h)) == 1
    due = eng.threat_notice_due_in(h.db.conn, h.acc, h.t)
    assert 0 < due <= eng.THREAT_NOTICE_INTERVAL_S
    assert eng._next_wake_in(h.db, h.acc, h.state) <= due + 1
    h.advance(eng.THREAT_NOTICE_INTERVAL_S)
    assert eng.maybe_send_threat_notice(h.client, h.db, LOG, h.acc, h.acc.folder_map) is True
    ns = notices(h)
    assert len(ns) == 2
    text = body_text(ns[1])
    assert str(ns[1]["Subject"]) == "⚠️ Spamfilteret har stoppet 12 farlige mails"
    assert text.count("Afsender:") == 10 and "… og 2 mere." in text
    assert "Mail nummer 1\r\n" in text and "Mail nummer 10" in text      # in the order they were caught
    assert "Mail nummer 11" not in text and "Mail nummer 12" not in text
    assert h.db.conn.execute("SELECT COUNT(*) FROM threat_notices WHERE sent_at IS NULL").fetchone()[0] == 0
    assert h.stat("threat_notice_sent") == 2


def test_notice_never_contains_a_url_or_control_characters(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=10.0)
    subject = "Klik http://evil.example/login?x=1 eller www.evil-bank.com nu ‮gnp.exe <script>x</script>"
    threat_mail(h, "u1@x", PHISH, subject=subject, name="Bank​ Support www.bank.dk",
                sender="sikkerhed@evil.example")
    assert catch(h)
    [n] = notices(h)
    for part in (body_text(n), body_html(n)):
        assert "http" not in part and "www." not in part and "evil.example/" not in part
        assert "evil-bank.com" not in part and "bank.dk" not in part
        assert "‮" not in part and "​" not in part
    assert "<script>" not in body_html(n)  # escaped in HTML; plain text is never rendered
    assert "[link fjernet]" in body_text(n)
    assert "&lt;script&gt;" in body_html(n)
    html = body_html(n)
    assert "<a " not in html and "<img" not in html and "href" not in html and "src=" not in html
    # The raw notice has no attachment part.
    assert not [p for p in n.walk() if p.get_content_disposition() == "attachment"]


def test_notice_safe_text_units(eng):
    assert eng.notice_safe_text("faktura.zip") == "faktura․zip"
    # Ideographic / full-width dots count as dots in IDNA: defanged too.
    for dot in ("\u3002", "\uff0e", "\uff61"):
        assert eng.notice_safe_text(f"paypal{dot}com login") == "paypal\u2024com login"
        assert eng.notice_safe_text(f"se www{dot}paypal{dot}com") == "se [link fjernet]"
    assert eng.notice_safe_text("se javascript:alert(1)") == "se [link fjernet]"
    assert eng.notice_safe_text("hxxp data:text/html,abc") == "hxxp [link fjernet]"
    assert eng.notice_safe_text("x" * 300, 50).endswith("…") and len(eng.notice_safe_text("x" * 300, 50)) == 50
    assert eng.notice_safe_text("Hej. Faktura") == "Hej. Faktura"   # a sentence stays readable
    assert eng.notice_safe_text("skriv til a@b.example") == "skriv til a@b\u2024example"
    assert eng.notice_safe_address("ok@kunde.dk") == "ok@kunde.dk"
    assert "www." not in eng.notice_safe_address("www.paypal.com@evil.example")
    assert eng.notice_type_text("attachment", "ukendt fil") == "Farlig vedhæftning"
    assert eng.notice_type_text("malware_url") == "Farligt link – linket fører til skadelig software"


def test_scanner_junk_poll_and_learning_skip_our_notice(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=10.0)
    threat_mail(h, "s1@x", PHISH)
    assert catch(h)
    [n] = notices(h)
    mid = str(n["Message-ID"]).strip("<>")
    before = list(h.scanned_ids())
    h.scan()
    assert mid not in h.scanned_ids()[len(before):] and h.row(mid) is None
    # Dragged into the spam folder: not a user verdict, never learned.
    h.user_moves(mid, "INBOX", "Junk")
    h.poll()
    assert h.row(mid) is None
    raw = h.client.folders["Junk"].msgs[h.client.uids("Junk")[-1]].raw
    learns = len(h.rspamd.learn_calls)
    assert eng.learn_message(h.db, h.acc, raw, "spam", mid, reason="test") == "declined"
    assert eng.learn_message(h.db, h.acc, raw, "ham", mid, reason="test") == "declined"
    assert len(h.rspamd.learn_calls) == learns
    assert eng.is_own_registered(h.db.conn, "acct", mid) and eng.is_own_registered(h.db.conn, "acct", f"<{mid}>")
    assert not eng.is_own_registered(h.db.conn, "other", mid)


def test_forged_notice_is_still_scanned_and_learnable(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=10.0)
    forged = "threat-acct-1-deadbeef@hjemmeserver.spamfilter"
    raw = make_message(forged, subject="⚠️ Spamfilteret har stoppet en farlig mail",
                       extra_headers="X-TH-Spamfilter: report\r\nX-TH-Spamfilter-Kind: threat-notice")
    h.rspamd.scores[forged] = 2.0
    import datetime as dt

    h.client.add("INBOX", raw, internaldate=dt.datetime.fromtimestamp(h.t, dt.timezone.utc))
    h.scan()
    assert forged in h.scanned_ids() and h.row(forged) is not None
    assert not eng.is_own_registered(h.db.conn, "acct", forged)
    assert eng.learn_message(h.db, h.acc, raw, "spam", forged, reason="test") == "learned"


def test_threat_notice_off_sends_nothing_but_clears_the_queue(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=10.0, threat_notice=False)
    threat_mail(h, "off1@x", VIRUS)
    assert catch(h) is False
    assert notices(h) == [] and "off1@x" in h.client.msgids("Junk")
    row = h.db.conn.execute("SELECT queued_at, sent_at, notice_id FROM threat_notices").fetchone()
    assert row[0] and row[1] and row[2] is None
    assert eng.threat_notice_due_in(h.db.conn, h.acc) is None


def test_no_notice_without_a_move(eng, monkeypatch):
    # Flag mode flags, shadow mode only records: nothing was moved, no notice.
    for mode in ("flag", "shadow"):
        h = Harness(eng, monkeypatch, threshold=10.0, mode=mode, name=f"acct-{mode}")
        threat_mail(h, f"{mode}@x", PHISH)
        h.scan()
        h.advance(10)
        h.loop()
        assert notices(h) == []
        assert h.db.conn.execute("SELECT queued_at FROM threat_notices WHERE account=?",
                                 (h.acc.name,)).fetchone()[0] is None


def test_loop_sends_the_notice_in_move_mode(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=10.0)
    threat_mail(h, "loop1@x", VIRUS)
    h.loop()
    h.advance(10)
    h.loop()
    assert len(notices(h)) == 1


def test_failed_append_is_retried_later(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=10.0)
    threat_mail(h, "f1@x", VIRUS)
    h.scan()
    h.advance(10)
    h.moves()
    from imapclient.exceptions import IMAPClientError

    real = h.client.append

    def broken(*a, **k):
        raise IMAPClientError("APPEND failed: NO quota")

    monkeypatch.setattr(h.client, "append", broken)
    assert eng.maybe_send_threat_notice(h.client, h.db, LOG, h.acc, h.acc.folder_map) is False
    assert h.db.conn.execute("SELECT COUNT(*) FROM daily_receipts").fetchone()[0] == 0
    assert h.events("threat_notice_failed")
    assert eng.threat_notice_due_in(h.db.conn, h.acc, h.t) > 0
    monkeypatch.setattr(h.client, "append", real)
    h.advance(eng.THREAT_NOTICE_RETRY_S + 1)
    assert eng.maybe_send_threat_notice(h.client, h.db, LOG, h.acc, h.acc.folder_map) is True


def test_prune_threat_notices(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=10.0)
    threat_mail(h, "pr1@x", VIRUS)
    assert catch(h)
    h.db.conn.execute("INSERT INTO threat_notices(account, message_id, threat, created_at) VALUES(?,?,?,?)",
                      ("acct", "never-moved@x", "phish", int(h.t)))
    h.db.conn.commit()
    assert eng.prune_threat_notices(h.db.conn, "acct", h.t + 3 * 86400) == 1
    assert eng.prune_threat_notices(h.db.conn, "acct", h.t + 31 * 86400) == 1


# ----------------------------------------------------------------- config

def test_threat_notice_config_default_and_validation(eng, tmp_path):
    assert eng.BUILTIN_DEFAULTS["threat_notice"] is True
    assert "threat_notice_sent" in eng.STAT_METRICS
    cfg = tmp_path / "a.yml"
    base = ("accounts:\n  - name: a\n    user: a@b.dk\n    imap_host: imap.b.dk\n    password: x\n")
    cfg.write_text(base)
    assert eng.load_account_configs(cfg)[0].threat_notice is True
    cfg.write_text(base + "    threat_notice: false\n")
    assert eng.load_account_configs(cfg)[0].threat_notice is False
    cfg.write_text(base + "    threat_notice: måske\n")
    with pytest.raises(eng.ConfigError):
        eng.load_account_configs(cfg)


# ----------------------------------------------------------------- admin alert

class FakeMailer:
    def __init__(self, configured=True, code="queued"):
        self.configured = configured
        self.code = code
        self.calls = []

    def is_configured(self):
        return self.configured

    @staticmethod
    def mask_address(value):
        local, _at, domain = str(value).rpartition("@")
        return f"{local[0]}…@{domain}" if local else "…"

    def notify(self, kind, subject, text, html=None, recipients=None):
        self.calls.append(SimpleNamespace(kind=kind, subject=subject, text=text))
        ok = self.code == "queued"
        return {"ok": ok, "code": self.code, "queued": 1 if ok else 0}


def test_admin_alert_once_per_mail_and_rate_limited(eng, monkeypatch):
    m = FakeMailer()
    monkeypatch.setattr(eng, "_mailer", lambda: m)
    h = Harness(eng, monkeypatch, threshold=10.0)
    threat_mail(h, "al1@x", VIRUS, subject="Se http://evil.example/x")
    assert catch(h)
    assert len(m.calls) == 1
    c = m.calls[0]
    assert c.kind == "alert" and c.subject == "Spamfilter: Konto acct: farlig mail stoppet"
    assert "Virus fra a…@evil\u2024example" in c.text
    assert "http" not in c.text and "evil.example" not in c.text and "Se http" not in c.text
    assert h.events("threat_alert_mailed") == [("threat_alert_mailed", None, "items=1")]
    # Same mail again: never a second alert.
    eng._threat_admin_alert(h.db, h.acc, now=h.t + 3600)
    assert len(m.calls) == 1
    # A new one within 30 minutes waits, then comes alone.
    h.advance(60)
    threat_mail(h, "al2@x", PHISH)
    catch(h)
    assert len(m.calls) == 1
    h.advance(eng.THREAT_ALERT_INTERVAL_S)
    eng._threat_admin_alert(h.db, h.acc)
    assert len(m.calls) == 2 and "Phishing-link fra" in m.calls[1].text and "Virus" not in m.calls[1].text


def test_admin_alert_global_hourly_cap(eng, monkeypatch):
    m = FakeMailer()
    monkeypatch.setattr(eng, "_mailer", lambda: m)
    h = Harness(eng, monkeypatch, threshold=10.0)
    for _ in range(eng.THREAT_ALERT_MAX_PER_HOUR):
        h.db.log_event("threat_alert_mailed", detail="items=1")
    h.db.conn.commit()
    threat_mail(h, "cap1@x", VIRUS)
    catch(h)
    assert m.calls == []
    assert h.db.conn.execute("SELECT alerted_at FROM threat_notices").fetchone()[0] is None


def test_admin_alert_without_smtp_marks_and_never_floods_later(eng, monkeypatch):
    m = FakeMailer(configured=False)
    monkeypatch.setattr(eng, "_mailer", lambda: m)
    h = Harness(eng, monkeypatch, threshold=10.0)
    threat_mail(h, "ns1@x", VIRUS)
    assert catch(h)              # the INBOX notice works without SMTP
    assert m.calls == []
    assert h.db.conn.execute("SELECT alerted_at FROM threat_notices").fetchone()[0] is not None
    m.configured = True
    eng._threat_admin_alert(h.db, h.acc, now=h.t + 7200)
    assert m.calls == []


def test_admin_alert_not_for_impersonation_classes(eng, monkeypatch):
    m = FakeMailer()
    monkeypatch.setattr(eng, "_mailer", lambda: m)
    h = Harness(eng, monkeypatch, threshold=10.0)
    h.db.conn.execute("INSERT INTO threat_notices(account, message_id, threat, created_at, queued_at) "
                      "VALUES('acct', 'imp@x', 'impersonation', ?, ?)", (int(h.t), int(h.t)))
    h.db.conn.commit()
    assert eng._threat_admin_alert(h.db, h.acc) is False and m.calls == []
