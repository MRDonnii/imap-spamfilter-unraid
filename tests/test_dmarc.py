"""2.6 (C2): DMARC aggregate reports (filter/dmarc.py + the engine hook).

Sample reports in the style of Google (zip) and Microsoft (gzip, XML
namespaces), plain XML, the engine path (stored, moved to DMARC-rapporter,
never scored or learned; shadow mode only stores; a report the user moved
back stays), and hostile input (DOCTYPE/entities, XXE, gzip and zip bombs,
deep nesting, forged subjects, foreign domains)."""

from __future__ import annotations

import datetime as dt
import gzip
import io
import json
import logging
import sys
import time
import zipfile
from email.message import EmailMessage
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import FakeIMAP, FakeRspamd, SCANNET_CAPS, make_account, setup_engine  # noqa: E402

import dmarc  # noqa: E402

LOG = logging.getLogger("test")
NOW = int(time.time())
DAY = 86400


def feedback(domain="bynet.example", org="google.com", rid="1234567890", begin=None, end=None, p="none",
             records=(("209.85.220.41", 12, "pass", "pass"), ("192.0.2.66", 3, "fail", "fail")),
             ns="", extra=""):
    begin = NOW - DAY if begin is None else begin
    end = begin + DAY - 1 if end is None else end
    recs = "".join(f"""
  <record>
    <row><source_ip>{ip}</source_ip><count>{n}</count>
      <policy_evaluated><disposition>none</disposition><dkim>{dk}</dkim><spf>{sp}</spf></policy_evaluated>
    </row>
    <identifiers><header_from>{domain}</header_from></identifiers>
    <auth_results><dkim><domain>{domain if dk == 'pass' else 'sendgrid.net'}</domain><result>{'pass' if dk == 'pass' else 'fail'}</result><selector>s1</selector></dkim>
      <spf><domain>{domain}</domain><result>{sp}</result></spf></auth_results>
  </record>""" for ip, n, dk, sp in records)
    return f"""<?xml version="1.0" encoding="UTF-8" ?>
<feedback{ns}>
  <version>1.0</version>
  <report_metadata><org_name>{org}</org_name><email>noreply-dmarc-support@google.com</email>
    <report_id>{rid}</report_id><date_range><begin>{begin}</begin><end>{end}</end></date_range></report_metadata>
  <policy_published><domain>{domain}</domain><adkim>r</adkim><aspf>r</aspf><p>{p}</p><sp>{p}</sp><pct>100</pct></policy_published>{recs}{extra}
</feedback>""".encode()


def zipped(xml: bytes, name="google.com!bynet.example!1!2.xml") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(name, xml)
    return buf.getvalue()


def report_mail(attachment: bytes, *, msgid="r1@google.com", subject="Report domain: bynet.example Submitter: google.com "
                "Report-ID: 1234567890", sender="noreply-dmarc-support@google.com", to="ole@bynet.example",
                filename="google.com!bynet.example!1!2.zip", ctype=("application", "zip")) -> bytes:
    m = EmailMessage()
    m["From"] = sender
    m["To"] = to
    m["Subject"] = subject
    m["Message-ID"] = f"<{msgid}>"
    m["Date"] = "Mon, 02 Nov 2026 01:00:00 +0000"
    m.set_content("This is an aggregate report from google.com.")
    m.add_attachment(attachment, maintype=ctype[0], subtype=ctype[1], filename=filename)
    return m.as_bytes()


def google_zip(**kw) -> bytes:
    return report_mail(zipped(feedback(**kw)))


def microsoft_gz(**kw) -> bytes:
    xml = feedback(org="Enterprise Outlook", rid="ms-77",
                   ns=' xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"',
                   **kw)
    return report_mail(gzip.compress(xml), msgid="ms1@microsoft.com", sender="dmarcreport@microsoft.com",
                       subject="Report Domain: bynet.example Submitter: protection.outlook.com Report-ID: <ms-77>",
                       filename="protection.outlook.com!bynet.example!1!2.xml.gz", ctype=("application", "gzip"))


# ---------------------------------------------------------------- parsing

def test_google_zip_and_microsoft_gzip_parse():
    reps, errs = dmarc.extract_reports(google_zip())
    assert errs == [] and len(reps) == 1
    r = reps[0]
    assert (r.org_name, r.report_id, r.domain, r.policy_p, r.policy_pct) == ("google.com", "1234567890", "bynet.example",
                                                                             "none", 100)
    assert [(x.source_ip, x.count, x.dmarc_pass) for x in r.records] == [("209.85.220.41", 12, True),
                                                                         ("192.0.2.66", 3, False)]
    assert r.records[1].dkim_domain == "sendgrid.net" and r.records[1].dkim_result == "fail"
    reps, errs = dmarc.extract_reports(microsoft_gz())
    assert errs == [] and reps[0].org_name == "Enterprise Outlook" and reps[0].messages == 15


def test_namespaced_and_plain_xml():
    xml = feedback(ns=' xmlns="urn:ietf:params:xml:ns:dmarc-2.0"').replace(b"<feedback", b"<dmarc:feedback", 1) \
        .replace(b"</feedback>", b"</dmarc:feedback>")
    xml = xml.replace(b'xmlns="urn', b'xmlns:dmarc="urn')
    assert dmarc.parse_report_bytes(xml).domain == "bynet.example"
    mail = report_mail(feedback(), filename="report.xml", ctype=("text", "xml"))
    assert dmarc.extract_reports(mail)[0][0].messages == 15


def test_quick_check():
    assert dmarc.quick_check(google_zip()) and dmarc.quick_check(microsoft_gz())
    plain = b"From: a@b.dk\r\nSubject: Hej\r\nMessage-ID: <x@y>\r\n\r\nhej"
    assert not dmarc.quick_check(plain)


@pytest.mark.parametrize("xml,why", [
    (b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]>'
     b"<feedback>&lol2;</feedback>", "DOCTYPE"),
    (b'<?xml version="1.0"?><!DOCTYPE f [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><feedback>&xxe;</feedback>',
     "DOCTYPE"),
    (b"<feedback>" + b"<a>" * 100 + b"</a>" * 100 + b"</feedback>", "deep"),
    (b"<feedback><report_metadata>", "malformed"),
    (b"<html><body>hi</body></html>", "not a dmarc"),
    (b"not xml at all", "not xml"),
    (feedback().replace(b"<domain>bynet.example</domain><adkim>", b"<domain>../../etc</domain><adkim>"), "metadata"),
])
def test_hostile_or_broken_xml_is_refused(xml, why):
    with pytest.raises(dmarc.DmarcError, match=why):
        dmarc.parse_report_bytes(xml)


def test_entity_reference_without_dtd_is_refused():
    with pytest.raises(dmarc.DmarcError):
        dmarc.parse_report_bytes(b"<feedback>&undefined;</feedback>")


def test_gzip_bomb_is_refused(monkeypatch):
    monkeypatch.setattr(dmarc, "MAX_XML", 1024 * 1024)
    bomb = gzip.compress(b"<feedback>" + b" " * (5 * 1024 * 1024) + b"</feedback>")
    assert len(bomb) < 64 * 1024
    with pytest.raises(dmarc.DmarcError, match="gzip expands"):
        dmarc.parse_report_bytes(bomb)


def test_zip_bombs_and_odd_zips_are_refused(monkeypatch):
    monkeypatch.setattr(dmarc, "MAX_XML", 1024 * 1024)
    big = zipped(b"<feedback>" + b" " * (3 * 1024 * 1024) + b"</feedback>")
    with pytest.raises(dmarc.DmarcError, match="too big"):
        dmarc.parse_report_bytes(big)
    # A lying central directory (declared small) is still capped while reading.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("r.xml", b"<feedback>" + b" " * (3 * 1024 * 1024) + b"</feedback>")
    raw = bytearray(buf.getvalue())
    cd = raw.rfind(b"PK\x01\x02")
    raw[cd + 24:cd + 28] = (100).to_bytes(4, "little")  # uncompressed size in the central directory
    with pytest.raises(dmarc.DmarcError):
        dmarc.parse_report_bytes(bytes(raw))
    many = io.BytesIO()
    with zipfile.ZipFile(many, "w") as z:
        for i in range(dmarc.MAX_ZIP_ENTRIES + 1):
            z.writestr(f"{i}.xml", b"<feedback/>")
    with pytest.raises(dmarc.DmarcError, match="too many"):
        dmarc.parse_report_bytes(many.getvalue())
    with pytest.raises(dmarc.DmarcError, match="bad zip"):
        dmarc.parse_report_bytes(b"PK\x03\x04garbage")


def test_too_many_records(monkeypatch):
    monkeypatch.setattr(dmarc, "MAX_RECORDS", 5)
    xml = feedback(records=[(f"192.0.2.{i}", 1, "pass", "pass") for i in range(6)])
    with pytest.raises(dmarc.DmarcError, match="too many records"):
        dmarc.parse_report_bytes(xml)


def test_invalid_rows_are_skipped_and_text_is_bounded():
    xml = feedback(records=[("not-an-ip", 1, "pass", "pass"), ("192.0.2.9", 2, "pass<x>", "pass")])
    xml = xml.replace(b"pass<x>", b"pass&lt;x&gt;")
    r = dmarc.parse_report_bytes(xml)
    assert [x.source_ip for x in r.records] == ["192.0.2.9"] and r.records[0].dkim is None


# ---------------------------------------------------------------- settings

class Acc:
    def __init__(self, name="bynet", user="ole@bynet.example", mode="move"):
        self.name, self.user, self.mode = name, user, mode
        self.protected_domains = ["pinsikbing.example"]
        self.webshop_domains = ["gravisk.example"]
        self.delimiter = "."


def test_account_default_follows_the_rua_address():
    s = dmarc.normalize_settings({})
    assert s["rua"] == "ole@bynet.example"
    assert dmarc.account_mode(s, Acc()) == "on"
    assert dmarc.account_mode(s, Acc("molt", "ole@molt.example")) == "off"
    s = dmarc.normalize_settings({"rua": "dmarc@molt.example", "accounts": {"bynet": "on", "x": "maybe"},
                                  "domains": ["example.org", "bad domain", "EXAMPLE.org"]})
    assert dmarc.account_mode(s, Acc("molt", "dmarc@molt.example")) == "on" and s["accounts"] == {"bynet": "on"}
    assert s["domains"] == ["example.org"]
    assert dmarc.normalize_settings({"rua": "nonsense"})["rua"] == ""


# ---------------------------------------------------------------- engine path

class H:
    def __init__(self, eng, monkeypatch, *, mode="move", user="ole@bynet.example", caps=SCANNET_CAPS):
        self.eng = eng
        self.t = float(NOW)
        monkeypatch.setattr(eng, "_now", lambda: self.t)
        self.rspamd = FakeRspamd(eng.requests).install(monkeypatch, eng)
        self.client = FakeIMAP(capabilities=caps, folders=("INBOX", "Junk", "Trash"))
        self.acc = make_account(eng, name="bynet", user=user, mode=mode)
        self.db = eng.Db(self.acc.name)
        self.state = eng.AccountState()
        eng._on_connected(self.client, self.db, LOG, self.acc, self.state)
        self.scan()
        dmarc.ensure_schema(self.db.conn)
        monkeypatch.setattr(dmarc, "ptr_lookup", lambda ip, **kw: (_ for _ in ()).throw(
            AssertionError("no reverse DNS on the scan path")))

    def sign(self, msgid, domain, *, score=None):
        """rspamd result for a report: a valid DKIM signature for `domain`."""
        self.rspamd.symbols[msgid] = {"R_DKIM_ALLOW": {"name": "R_DKIM_ALLOW", "score": -0.2,
                                                       "options": [f"{domain}:s=1"]}}
        if score is not None:
            self.rspamd.scores[msgid] = score

    def scan(self):
        self.eng.scan_inbox(self.client, self.db, LOG, self.acc, self.acc.folder_map, self.state)

    def deliver(self, raw, folder="INBOX"):
        return self.client.add(folder, raw, internaldate=dt.datetime.fromtimestamp(self.t, dt.timezone.utc))

    def events(self, name):
        return [tuple(r) for r in self.db.conn.execute(
            "SELECT event, message_id, detail FROM events WHERE event=? ORDER BY id", (name,))]


@pytest.fixture
def eng(tmp_path, monkeypatch):
    return setup_engine(tmp_path, monkeypatch)


def test_report_is_scanned_first_then_stored_and_moved(eng, monkeypatch):
    h = H(eng, monkeypatch)
    h.sign("r1@google.com", "google.com")
    h.sign("ms1@microsoft.com", "microsoft.com")
    h.deliver(google_zip())
    h.deliver(microsoft_gz())
    h.scan()
    # rspamd (and ClamAV through it) always sees a report candidate
    assert sorted(c["msgid"] for c in h.rspamd.scan_calls) == ["ms1@microsoft.com", "r1@google.com"]
    assert h.rspamd.learn_calls == []
    assert sorted(h.client.msgids(dmarc.FOLDER)) == ["ms1@microsoft.com", "r1@google.com"]
    assert h.client.msgids("INBOX") == []
    assert h.db.get_message("r1@google.com") is None  # never in messages: no spam stats, no learning
    n = h.db.conn.execute("SELECT COUNT(*), SUM(count) FROM dmarc_records").fetchone()
    assert tuple(n) == (4, 30)
    assert len(h.events("dmarc_report_moved")) == 2
    assert h.db.conn.execute("SELECT COUNT(*) FROM dmarc_ptr").fetchone()[0] == 0  # lazy: the admin page
    assert h.db.conn.execute("SELECT COUNT(*) FROM move_journal").fetchone()[0] == 0


def test_folder_is_created_below_inbox_when_the_server_keeps_folders_there(eng, monkeypatch):
    h = H(eng, monkeypatch)
    h.acc.folder_map["junk"] = "INBOX.Spamfilter"
    h.client.add_folder("INBOX.Spamfilter")
    h.sign("r1@google.com", "google.com")
    h.deliver(google_zip())
    h.scan()
    assert h.client.msgids("INBOX." + dmarc.FOLDER) == ["r1@google.com"]


def test_shadow_mode_stores_and_goes_through_the_normal_path(eng, monkeypatch):
    h = H(eng, monkeypatch, mode="shadow")
    h.sign("r1@google.com", "google.com")
    h.deliver(google_zip())
    h.scan()
    assert h.client.msgids("INBOX") == ["r1@google.com"] and dmarc.FOLDER not in h.client.folders
    assert h.db.conn.execute("SELECT COUNT(*) FROM dmarc_reports").fetchone()[0] == 1
    assert h.rspamd.scan_calls
    assert h.db.get_message("r1@google.com")["our_action"] == "none"  # normal decision recorded


@pytest.mark.parametrize("score,symbols", [
    (9.0, None),                                                         # spam by score
    (1.0, {"CLAM_VIRUS": {"name": "CLAM_VIRUS", "score": 8.0, "options": ["Eicar"]}}),
])
def test_spam_or_virus_report_candidate_is_never_taken(eng, monkeypatch, score, symbols):
    h = H(eng, monkeypatch)
    h.sign("r1@google.com", "google.com", score=score)
    if symbols:
        h.rspamd.symbols["r1@google.com"].update(symbols)
    h.deliver(google_zip())
    h.scan()
    assert dmarc.FOLDER not in h.client.folders
    assert h.db.conn.execute("SELECT COUNT(*) FROM dmarc_reports").fetchone()[0] == 0
    assert h.db.get_message("r1@google.com") is not None  # decided by the normal path


def test_report_without_aligned_dkim_or_from_an_unknown_reporter_is_not_taken(eng, monkeypatch):
    h = H(eng, monkeypatch)
    # unsigned
    h.deliver(google_zip())
    # signed, but by another domain than the From domain
    h.deliver(report_mail(zipped(feedback(rid="2")), msgid="r2@google.com"))
    h.sign("r2@google.com", "evil.example")
    # aligned, but an unknown reporter whose report names another org
    h.deliver(report_mail(zipped(feedback(rid="3")), msgid="r3@spoof.example",
                          sender="dmarc@spoof.example"))
    h.sign("r3@spoof.example", "spoof.example")
    h.scan()
    assert dmarc.FOLDER not in h.client.folders
    assert h.db.conn.execute("SELECT COUNT(*) FROM dmarc_reports").fetchone()[0] == 0
    details = " ".join(d for _e, _m, d in h.events("dmarc_not_taken"))
    assert "not DKIM-aligned" in details and "unknown reporter spoof.example" in details


def test_unknown_reporter_is_taken_when_the_report_names_its_own_domain(eng, monkeypatch):
    h = H(eng, monkeypatch)
    xml = feedback(org="smallmail.example", rid="s1").replace(b"noreply-dmarc-support@google.com",
                                                              b"dmarc@smallmail.example")
    h.deliver(report_mail(zipped(xml), msgid="s1@smallmail.example", sender="dmarc@reports.smallmail.example"))
    h.sign("s1@smallmail.example", "smallmail.example")
    h.scan()
    assert h.client.msgids(dmarc.FOLDER) == ["s1@smallmail.example"]


def test_report_moved_back_by_the_user_stays(eng, monkeypatch):
    h = H(eng, monkeypatch)
    h.sign("r1@google.com", "google.com")
    h.deliver(google_zip())
    h.scan()
    raw = h.client.folders[dmarc.FOLDER].msgs
    (uid, msg), = raw.items()
    del raw[uid]
    h.client.add("INBOX", msg.raw, internaldate=msg.internaldate)
    h.scan()
    assert h.client.msgids("INBOX") == ["r1@google.com"]
    assert len(h.rspamd.scan_calls) == 2  # scanned again, not trusted by its Message-ID
    assert h.events("dmarc_report_kept")
    assert h.db.get_message("r1@google.com") is not None


def test_a_later_mail_reusing_a_report_message_id_is_scored_normally(eng, monkeypatch):
    h = H(eng, monkeypatch)
    h.sign("r1@google.com", "google.com")
    h.deliver(google_zip())
    h.scan()
    # Same Message-ID, other content (spam): scored, never skipped.
    h.rspamd.scores["r1@google.com"] = 12.0
    h.rspamd.symbols.pop("r1@google.com")
    h.deliver(report_mail(b"MZ evil", msgid="r1@google.com", filename="invoice.zip"))
    h.scan()
    assert len(h.rspamd.scan_calls) == 2
    assert h.db.conn.execute("SELECT COUNT(*) FROM messages m JOIN mail_identity i "
                             "ON m.account=i.account AND m.message_id=i.message_key "
                             "WHERE i.wire_id=? AND m.our_action IN ('pending_move', 'moved_to_junk')",
                             ("r1@google.com",)).fetchone()[0] == 1
    assert not h.events("dmarc_report_kept")


def test_interrupted_copy_is_journalled_and_repaired(eng, monkeypatch):
    h = H(eng, monkeypatch, caps=tuple(c for c in SCANNET_CAPS if c != b"MOVE"))
    h.client.add_folder(dmarc.FOLDER)
    h.sign("r1@google.com", "google.com")
    h.deliver(google_zip())
    real = h.client.uid_expunge

    def broken(uids):
        raise eng.IMAPClientError("connection hiccup")

    h.client.uid_expunge = broken
    h.scan()
    assert h.client.msgids(dmarc.FOLDER) == ["r1@google.com"]  # the copy
    assert h.client.msgids("INBOX") == ["r1@google.com"]       # the original (flag rolled back)
    row = h.db.conn.execute("SELECT dest, stage FROM move_journal").fetchone()
    assert tuple(row) == (dmarc.FOLDER, "copied")
    h.client.uid_expunge = real
    h.deliver(report_mail(b"hello", msgid="other@x", filename="a.txt", ctype=("text", "plain")))
    h.scan()  # the next scan with new mail repairs the move first
    assert h.client.msgids(dmarc.FOLDER) == ["r1@google.com"]
    assert "r1@google.com" not in h.client.msgids("INBOX")
    assert h.db.conn.execute("SELECT COUNT(*) FROM move_journal").fetchone()[0] == 0


def test_not_moved_report_goes_through_the_normal_path(eng, monkeypatch):
    h = H(eng, monkeypatch)
    monkeypatch.setattr(dmarc, "MAX_MOVES_PER_HOUR", 0)
    h.sign("r1@google.com", "google.com")
    h.deliver(google_zip())
    h.scan()
    assert h.client.msgids("INBOX") == ["r1@google.com"]
    assert h.db.get_message("r1@google.com")["our_action"] == "none"
    assert h.db.conn.execute("SELECT COUNT(*) FROM dmarc_reports").fetchone()[0] == 1


def test_duplicate_report_is_counted_once(eng, monkeypatch):
    h = H(eng, monkeypatch)
    h.sign("r1@google.com", "google.com")
    h.sign("r1-copy@google.com", "google.com")
    h.deliver(google_zip())
    h.deliver(report_mail(zipped(feedback()), msgid="r1-copy@google.com"))
    h.scan()
    assert h.db.conn.execute("SELECT COUNT(*) FROM dmarc_reports").fetchone()[0] == 1
    assert h.db.conn.execute("SELECT SUM(count) FROM dmarc_records").fetchone()[0] == 15


def test_forged_or_foreign_reports_are_scanned_normally(eng, monkeypatch):
    h = H(eng, monkeypatch)
    for mid in ("evil@x", "foreign@x", "bomb@x"):
        h.sign(mid, "google.com")
    # forged subject, attachment is not a report -> normal scan (rspamd decides)
    h.deliver(report_mail(b"MZ\x90\x00 evil", msgid="evil@x", filename="invoice.zip"))
    # a valid report for somebody else's domain, not addressed to the rua address
    h.deliver(report_mail(zipped(feedback(domain="example.org")), msgid="foreign@x", to="someone@example.org"))
    # a DOCTYPE bomb
    h.deliver(report_mail(b'<!DOCTYPE x [<!ENTITY a "a">]><feedback>&a;</feedback>', msgid="bomb@x",
                          filename="r.xml", ctype=("text", "xml")))
    h.scan()
    assert sorted(h.rspamd.scan_calls[i]["msgid"] for i in range(3)) == ["bomb@x", "evil@x", "foreign@x"]
    assert dmarc.FOLDER not in h.client.folders
    assert h.db.conn.execute("SELECT COUNT(*) FROM dmarc_reports").fetchone()[0] == 0
    details = " ".join(d for _e, _m, d in h.events("dmarc_not_taken"))
    assert "DOCTYPE" in details and "domain is not ours" in details


def test_mailbox_without_dmarc_setting_scans_reports_normally(eng, monkeypatch):
    h = H(eng, monkeypatch, user="ole@molt.example")
    h.sign("r1@google.com", "google.com")
    h.deliver(google_zip())
    h.scan()
    assert h.rspamd.scan_calls and h.client.msgids("INBOX") == ["r1@google.com"]


def test_explicit_setting_turns_it_on_for_another_mailbox(eng, monkeypatch):
    h = H(eng, monkeypatch, user="ole@molt.example")
    h.db.conn.execute("CREATE TABLE IF NOT EXISTS settings_kv (key TEXT PRIMARY KEY, value TEXT)")
    h.db.conn.execute("INSERT INTO settings_kv VALUES('dmarc', ?)", (json.dumps({"accounts": {"bynet": "on"}}),))
    h.sign("r1@google.com", "google.com")
    h.deliver(google_zip())
    h.scan()
    assert h.client.msgids(dmarc.FOLDER) == ["r1@google.com"]


def test_hostile_report_never_breaks_the_scan(eng, monkeypatch):
    h = H(eng, monkeypatch)
    monkeypatch.setattr(dmarc, "extract_reports", lambda raw: (_ for _ in ()).throw(MemoryError()))
    h.sign("r1@google.com", "google.com")
    h.deliver(google_zip())
    h.scan()
    assert h.rspamd.scan_calls and h.client.msgids("INBOX") == ["r1@google.com"]
    assert h.db.get_message("r1@google.com") is not None


def test_old_dmarc_mail_table_gets_the_hash_column(tmp_path):
    import sqlite3

    conn = sqlite3.connect(tmp_path / "x.db", isolation_level=None)
    conn.execute("CREATE TABLE dmarc_mail (account TEXT NOT NULL, message_id TEXT NOT NULL, seen_at INTEGER NOT NULL,"
                 " reports INTEGER NOT NULL DEFAULT 0, moved INTEGER NOT NULL DEFAULT 0,"
                 " PRIMARY KEY(account, message_id))")
    dmarc.ensure_schema(conn)
    assert "raw_sha256" in {r[1] for r in conn.execute("PRAGMA table_info(dmarc_mail)")}


def test_page_reverse_dns_is_bounded_and_cached(tmp_path):
    import sqlite3

    conn = sqlite3.connect(tmp_path / "x.db", isolation_level=None)
    rep = dmarc.parse_report_bytes(feedback(records=[(f"192.0.2.{i}", 100 - i, "pass", "pass") for i in range(20)]))
    dmarc.store(conn, "bynet", "m@x", rep, now=NOW)
    calls = []
    assert dmarc.resolve_for_page(conn, now=NOW, lookup=lambda ip: calls.append(ip)) == dmarc.PTR_PER_PASS
    assert calls[0] == "192.0.2.0"  # busiest first
    calls.clear()
    dmarc.resolve_for_page(conn, now=NOW, lookup=lambda ip: calls.append(ip))
    assert len(calls) == 10 and "192.0.2.0" not in calls


def test_dead_resolver_stops_after_the_first_timeout(tmp_path):
    import sqlite3

    conn = sqlite3.connect(tmp_path / "x.db", isolation_level=None)
    calls = []

    def boom(ip):
        calls.append(ip)
        raise TimeoutError("timed out")

    assert dmarc.resolve_pending(conn, ["192.0.2.1", "192.0.2.2", "192.0.2.3"], lookup=boom) == 0
    assert calls == ["192.0.2.1"]


# ---------------------------------------------------------------- summaries + advice

def _seed(conn, domain="bynet.example", days=20, good=98, bad=2, p="none", unknown=False, start=NOW):
    for i in range(days):
        b = start - (i + 1) * DAY
        recs = [("209.85.220.41", good, "pass", "pass"), ("192.0.2.66", bad, "fail", "fail")]
        rep = dmarc.parse_report_bytes(feedback(domain=domain, rid=f"{domain}-{i}", begin=b, p=p, records=recs))
        if unknown:
            rep.records.append(dmarc.Record("198.51.100.7", 5, "none", "fail", "fail", domain, None,
                                            "mailchimp.com", "pass", "mcsv.net", "pass"))
        dmarc.store(conn, "bynet", f"m{i}@{domain}", rep, now=NOW)


@pytest.fixture
def conn(tmp_path):
    import sqlite3

    c = sqlite3.connect(tmp_path / "d.db", isolation_level=None)
    c.execute("PRAGMA synchronous=OFF")
    dmarc.ensure_schema(c)
    return c


def test_summary_ready_for_quarantine(conn):
    _seed(conn, good=990, bad=10)
    conn.execute("INSERT INTO dmarc_ptr VALUES('209.85.220.41', 'mail-sor-f41.google.com', ?)", (NOW,))
    (s,) = dmarc.summaries(conn, now=NOW)
    assert s["domain"] == "bynet.example" and s["pct"] == 99.0 and s["reports"] == 20
    assert s["sources"][0] == {**s["sources"][0], "ip": "209.85.220.41", "ptr": "mail-sor-f41.google.com",
                               "status": "godkendt"}
    assert s["sources"][1]["status"] == "fejler"
    assert s["advice"]["code"] == "ready_quarantine" and "Klar til p=quarantine" in s["advice"]["text"]


def test_summary_advice_variants(conn):
    _seed(conn, domain="molt.example", days=5)
    _seed(conn, domain="gravisk.example", good=80, bad=20)
    _seed(conn, domain="pinsikbing.example", unknown=True, good=990, bad=1)
    _seed(conn, domain="example.org", good=0, bad=40)
    _seed(conn, domain="vexar.example", p="quarantine", good=1000, bad=0)
    got = {s["domain"]: s["advice"]["code"] for s in dmarc.summaries(conn, now=NOW, domains=["nyt.dk"])}
    assert got == {"molt.example": "collect", "gravisk.example": "low_pass", "pinsikbing.example": "check_sources",
                   "example.org": "spoofed_only", "vexar.example": "ready_reject", "nyt.dk": "no_data"}
    adv = {s["domain"]: s["advice"]["text"] for s in dmarc.summaries(conn, now=NOW)}
    assert "198.51.100.7" in adv["pinsikbing.example"] and "80 %" in adv["gravisk.example"]


def test_prune_and_dns_hint(conn):
    _seed(conn, days=3, start=NOW - 500 * DAY)
    _seed(conn, domain="molt.example", days=2)
    assert dmarc.prune(conn, now=NOW) == 3
    assert conn.execute("SELECT COUNT(*) FROM dmarc_reports").fetchone()[0] == 2
    assert dmarc.dns_hint("bynet.example", "ole@bynet.example") == ['_dmarc.bynet.example  TXT  "v=DMARC1; p=none; '
                                                            'rua=mailto:ole@bynet.example"']
    hint = dmarc.dns_hint("molt.example", "ole@bynet.example")
    assert hint[1] == 'molt.example._report._dmarc.bynet.example  TXT  "v=DMARC1"'


def _cisco(h, msgid, *, org="iphmx.com", spf=True):
    sym = {"DMARC_POLICY_ALLOW": {"name": "DMARC_POLICY_ALLOW", "score": -0.5, "options": [org, "none"]}}
    if spf:
        sym["R_SPF_ALLOW"] = {"name": "R_SPF_ALLOW", "score": -0.2, "options": ["+ip4:23.90.118.74"]}
    h.rspamd.symbols[msgid] = sym


def test_cisco_reports_without_dkim_are_taken_on_an_spf_dmarc_pass(eng, monkeypatch):
    """2.8.3: Cisco Secure Email never DKIM-signs its reports; DMARC passes on
    aligned SPF. Such a report is taken; the same mail without that pass is not."""
    h = H(eng, monkeypatch)
    sender = "MAILER-DAEMON@esa1.hc999-46.eu.iphmx.com"
    subj = "Report Domain: bynet.example Submitter: esa1.hc999-46.eu.iphmx.com Report-ID: <c1>"
    h.deliver(report_mail(zipped(feedback(rid="c1")), msgid="c1@iphmx.com", sender=sender, subject=subj))
    _cisco(h, "c1@iphmx.com")
    h.deliver(report_mail(zipped(feedback(rid="c2")), msgid="c2@iphmx.com", sender=sender, subject=subj))
    _cisco(h, "c2@iphmx.com", spf=False)                     # no SPF pass
    h.deliver(report_mail(zipped(feedback(rid="c3")), msgid="c3@iphmx.com", sender=sender, subject=subj))
    _cisco(h, "c3@iphmx.com", org="evil.example")            # DMARC passed for another domain
    h.deliver(report_mail(zipped(feedback(rid="c4")), msgid="c4@other.example",
                          sender="dmarc@other.example", subject=subj))
    _cisco(h, "c4@other.example", org="other.example")       # not an SPF reporter
    h.scan()
    assert h.client.msgids(dmarc.FOLDER) == ["c1@iphmx.com"]
    details = " ".join(d for _e, _m, d in h.events("dmarc_not_taken"))
    assert details.count("not DKIM-aligned") == 3
