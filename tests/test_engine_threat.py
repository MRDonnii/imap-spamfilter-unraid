"""ENGINE 2.3: threat class (B16) and attachment policy (B17).

Virus always goes to Spamfilter (allow / 'Altid igennem' rules, known
contacts and protected recipients cannot help); phishing and malware links
and dangerous attachments override normal allow rules and protected
recipients, only a DKIM-verified 'Altid igennem' still passes (logged).
A threat dragged out of Spamfilter is never learned as ham and never
allows the sender. Attachment file names are normalised against the usual
tricks, zip archives are inspected, encrypted archives cost +4."""

from __future__ import annotations

import io
import json
import logging
import sys
import zipfile
from email.message import EmailMessage
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import make_message, setup_engine, stub_mailctx  # noqa: E402
from test_engine_contacts import DMARC_OK, dkim, inbound, run_sync, sent_mail, sym, syms_of  # noqa: E402
from test_engine_scan import Harness  # noqa: E402

LOG = logging.getLogger("test-threat")


@pytest.fixture
def eng(tmp_path, monkeypatch):
    e = setup_engine(tmp_path, monkeypatch)
    import contacts

    contacts.forget_cached_keys()
    yield e
    contacts.forget_cached_keys()


def syms(*parts):
    out = {}
    for p in parts:
        out.update(p)
    return out


def scored(h, msgid, *, score=1.0, symbols=None, sender="a@example.org", raw=None, flags=()):
    h.rspamd.scores[msgid] = score
    h.rspamd.symbols[msgid] = symbols if symbols is not None else {}
    if raw is None:
        h.deliver(msgid, sender=sender, flags=flags)
    else:
        import datetime as dt

        h.client.add("INBOX", raw, flags=flags,
                     internaldate=dt.datetime.fromtimestamp(h.t, dt.timezone.utc))
    h.scan()
    return h.row(msgid)


def mail_with_attachments(msgid, files, *, sender="a@example.org", body="Se vedhæftet."):
    msg = EmailMessage()
    msg["From"] = f"Afsender <{sender}>"
    msg["To"] = "user@example-a.dk"
    msg["Subject"] = "Faktura"
    msg["Message-ID"] = f"<{msgid}>"
    msg["Date"] = "Tue, 20 Oct 2026 10:00:00 +0200"
    msg.set_content(body)
    for name, data in files:
        msg.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
    return msg.as_bytes()


def zip_bytes(entries, *, encrypt=False):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries:
            zf.writestr(name, data)
    raw = bytearray(buf.getvalue())
    if encrypt:
        # Set the "encrypted" general purpose bit in the local and central
        # headers (zipfile cannot write encrypted archives).
        i = 0
        while True:
            j = raw.find(b"PK\x03\x04", i)
            if j < 0:
                break
            raw[j + 6] |= 0x01
            i = j + 4
        i = 0
        while True:
            j = raw.find(b"PK\x01\x02", i)
            if j < 0:
                break
            raw[j + 8] |= 0x01
            i = j + 4
    return bytes(raw)


# ----- config -------------------------------------------------------------------------

BASE_YML = """
defaults:
  mode: move
  threshold: 10
accounts:
  - name: bynet
    user: ole@bynet.example
    imap_host: imap.example.net
    password: x
{extra}
"""


def test_config_defaults_and_validation(eng):
    Path(eng.CONFIG_PATH).write_text(BASE_YML.format(extra=""))
    acc = eng.load_account_configs(eng.CONFIG_PATH)[0]
    assert acc.zap is True
    assert acc.attachment_block == eng.DEFAULT_ATTACHMENT_BLOCK
    for ext in ("exe", "scr", "js", "iso", "lnk", "img", "vhdx", "xll", "chm", "reg", "msix", "appx"):
        assert ext in acc.attachment_block
    Path(eng.CONFIG_PATH).write_text(BASE_YML.format(extra="    attachment_block: ['.EXE', '*.js', iso]\n"
                                                           "    zap: false\n"))
    acc = eng.load_account_configs(eng.CONFIG_PATH)[0]
    assert acc.attachment_block == ["exe", "js", "iso"] and acc.zap is False
    Path(eng.CONFIG_PATH).write_text(BASE_YML.format(extra="    attachment_block: []\n"))
    assert eng.load_account_configs(eng.CONFIG_PATH)[0].attachment_block == []
    for bad in ("['ex e']", "['../x']", "[" + ",".join(f"e{i}" for i in range(101)) + "]"):
        Path(eng.CONFIG_PATH).write_text(BASE_YML.format(extra=f"    attachment_block: {bad}\n"))
        with pytest.raises(eng.ConfigError):
            eng.load_account_configs(eng.CONFIG_PATH)
    Path(eng.CONFIG_PATH).write_text(BASE_YML.format(extra="    zap: maybe\n"))
    with pytest.raises(eng.ConfigError):
        eng.load_account_configs(eng.CONFIG_PATH)


def test_stats_and_score_version_unchanged(eng):
    assert {"threat_detected", "zapped", "would_have_zapped"} <= eng.STAT_METRICS
    assert eng.SCORE_VERSION == 2


# ----- classification -----------------------------------------------------------------


@pytest.mark.parametrize("names, want", [
    ({"CLAM_VIRUS"}, "virus"),
    ({"CLAM_VIRUS", "DBL_PHISH"}, "virus"),
    ({"DBL_PHISH"}, "phish"), ({"PH_SURBL_MULTI"}, "phish"), ({"PHISHED_OPENPHISH"}, "phish"),
    ({"PHISHED_PHISHTANK"}, "phish"), ({"CLAM_PHISH"}, "phish"),
    ({"URLHAUS_MALWARE_URL"}, "malware_url"), ({"DBL_MALWARE"}, "malware_url"),
    ({"TH_ATTACH_BLOCK"}, "attachment"),
    # rspamd heuristics are ordinary score symbols, never a threat.
    ({"PHISHING"}, None), ({"REDIRECTOR_URL"}, None), ({"SUSPICIOUS_URL_IN_SUSPICIOUS_MESSAGE"}, None),
    ({"PHISHED_EXCLUDED"}, None), ({"PHISHED_GENERIC_SERVICE"}, None), ({"CLAM_VIRUS_FAIL"}, None),
    ({"DBL_SPAM", "URIBL_BLACK", "ABUSE_SURBL"}, None),
])
def test_threat_classes_are_exact(eng, names, want):
    assert eng.classify_threat(names)[0] == want


def test_threat_texts(eng):
    assert eng.classify_threat({"CLAM_VIRUS"}, [{"n": "CLAM_VIRUS", "s": 20, "o": ["Eicar-Test-Signature"]}]) \
        == ("virus", "Eicar-Test-Signature")
    assert eng.threat_text("virus", "Eicar-Test-Signature") == "Virus: Eicar-Test-Signature"
    assert eng.threat_text("phish", "DBL_PHISH evil.example") == "Phishing-link"
    assert eng.threat_text("malware_url", "x") == "Malware-link"
    assert eng.threat_text("attachment", "faktura.pdf.exe") == "Farlig vedhæftning: faktura.pdf.exe"
    assert eng.threat_text(None) == ""
    assert eng.threat_confirm_text("virus", "Eicar") == "Denne mail indeholder virus: Eicar."
    import services

    for t in eng.THREAT_CLASSES:
        assert services.threat_text(t, "d") == eng.threat_text(t, "d")
        assert services.threat_confirm_text(t, "d") == eng.threat_confirm_text(t, "d")
    assert services.THREAT_LABELS == eng.THREAT_LABELS


# ----- decision ---------------------------------------------------------------------------

VIRUS = sym("CLAM_VIRUS", 0.0, ["Win.Trojan.Agent-123"])
PHISH = sym("DBL_PHISH", 7.5, ["evil.example:url"])


def test_virus_beats_force_rule_allow_rule_and_threshold(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=10.0)
    eng.add_sender_rule(h.db.conn, "*", "@vexar.example", "allow", None, "admin", force=True)
    r = scored(h, "v1@x", score=-2.0, symbols=syms(VIRUS, dkim("vexar.example")), sender="ordre@vexar.example")
    assert r["our_action"] == "pending_move" and r["threat"] == "virus"
    assert r["threat_detail"] == "Win.Trojan.Agent-123"
    eng.add_sender_rule(h.db.conn, "acct", "ven@kunde.dk", "allow")
    r = scored(h, "v2@x", score=0.0, symbols=VIRUS, sender="ven@kunde.dk")
    assert r["our_action"] == "pending_move"
    assert h.stat("threat_detected") == 2
    ev = [e for e in h.events("threat_detected") if e[1] == "v1@x"]
    assert ev and ev[0][2].startswith("virus: Win.Trojan")
    # Clear spam: the short grace, then moved even though the force rule matches.
    h.advance(5)
    h.moves()
    assert "v1@x" in h.client.msgids("Junk") and "v2@x" in h.client.msgids("Junk")


def test_virus_beats_protected_recipient(eng, monkeypatch):
    stub = stub_mailctx(recipients=["chef@example-a.dk"])
    monkeypatch.setattr(eng, "_mailctx", lambda: stub)
    h = Harness(eng, monkeypatch, threshold=8.0, protected_recipients=["chef@example-a.dk"],
                protected_threshold=18.0)
    assert scored(h, "p1@x", score=12.0)["our_action"] == "none"  # protected: 18
    r = scored(h, "p2@x", score=1.0, symbols=VIRUS)
    assert r["our_action"] == "pending_move" and r["threat"] == "virus"
    r = scored(h, "p3@x", score=1.0, symbols=PHISH)
    assert r["our_action"] == "pending_move" and r["threat"] == "phish"


def test_phish_overrides_allow_rule_but_dkim_force_passes_logged(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=10.0)
    eng.add_sender_rule(h.db.conn, "acct", "@kunde.dk", "allow")
    r = scored(h, "ph1@x", score=2.0, symbols=PHISH, sender="ven@kunde.dk")
    assert r["our_action"] == "pending_move" and r["threat"] == "phish"
    assert any("allow rule" in (e[2] or "") for e in h.events("scan") if e[1] == "ph1@x")
    fid = eng.add_sender_rule(h.db.conn, "*", "@vexar.example", "allow", None, "admin", force=True)
    r = scored(h, "ph2@x", score=2.0, symbols=syms(PHISH, dkim("vexar.example")), sender="ordre@vexar.example")
    assert r["our_action"] == "allowlisted" and r["threat"] == "phish"
    ev = [e for e in h.events("threat_force_pass") if e[1] == "ph2@x"]
    assert ev and f"rule={fid}" in ev[0][2] and "dkim:vexar.example" in ev[0][2]
    # Without DKIM (forged From of the shop) the force rule does not help.
    r = scored(h, "ph3@x", score=2.0, symbols=PHISH, sender="ordre@vexar.example")
    assert r["our_action"] == "pending_move"


def test_phish_host_verified_force_does_not_pass(eng, monkeypatch):
    stub = stub_mailctx(origin_host="mail-sender-1.vexar.example")
    monkeypatch.setattr(eng, "_mailctx", lambda: stub)
    h = Harness(eng, monkeypatch, threshold=10.0)
    eng.add_sender_rule(h.db.conn, "*", "@vexar.example", "allow", None, "admin", force=True)
    assert scored(h, "ok@x", score=12.0, sender="ordre@vexar.example")["our_action"] == "allowlisted"
    r = scored(h, "mw@x", score=1.0, symbols=sym("URLHAUS_MALWARE_URL", 8.0, ["bad.example"]),
               sender="ordre@vexar.example")
    assert r["our_action"] == "pending_move" and r["threat"] == "malware_url"


def test_force_rule_added_during_grace_never_saves_a_virus(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=10.0, move_grace_seconds_high=60)
    scored(h, "v@x", score=1.0, symbols=syms(VIRUS, dkim("vexar.example")), sender="ordre@vexar.example")
    scored(h, "p@x", score=1.0, symbols=syms(PHISH, dkim("vexar.example")), sender="ordre@vexar.example")
    eng.add_sender_rule(h.db.conn, "*", "@vexar.example", "allow", None, "admin", force=True)
    h.advance(61)
    h.moves()
    assert h.client.msgids("Junk") == ["v@x"]
    assert h.row("p@x")["our_action"] == "allowlisted"  # DKIM-verified force rule: like the scan


def test_threat_gets_no_known_contact_bonus(eng, monkeypatch):
    h = Harness(eng, monkeypatch, folders=("INBOX", "Junk", "Trash", "Sent"), threshold=10.0)
    h.client.add("Sent", sent_mail("s1@x", "alice@kunde.dk"))
    run_sync(h)
    r = inbound(h, "kc@x", "alice@kunde.dk", score=9.0, symbols=DMARC_OK)
    assert "TH_KNOWN_CONTACT" in syms_of(h, "kc@x") and r["our_action"] == "none"
    r = inbound(h, "kcp@x", "alice@kunde.dk", score=3.0, symbols=syms(DMARC_OK, sym("PHISHED_OPENPHISH", 7.0)))
    assert "TH_KNOWN_CONTACT" not in syms_of(h, "kcp@x")
    assert r["our_action"] == "pending_move" and r["threat"] == "phish"
    import contacts

    assert contacts.trust_blocked([], threat="attachment") == "threat:attachment"


def test_flag_mode_sets_junk_and_phishing_keywords(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="flag", threshold=10.0)
    scored(h, "f1@x", score=12.0)
    scored(h, "f2@x", score=1.0, symbols=PHISH)
    uid1 = h.client.uids("INBOX")[0]
    uid2 = h.client.uids("INBOX")[1]
    assert "$Junk" in h.client.flags_of("INBOX", uid1) and "$Phishing" not in h.client.flags_of("INBOX", uid1)
    assert {"$Junk", "$Phishing"} <= h.client.flags_of("INBOX", uid2)
    assert "\\Flagged" not in h.client.flags_of("INBOX", uid2)
    assert h.row("f2@x")["our_action"] == "flagged"


def test_shadow_mode_records_the_threat_without_writes(eng, monkeypatch):
    h = Harness(eng, monkeypatch, mode="shadow", threshold=10.0)
    r = scored(h, "s@x", score=1.0, symbols=VIRUS)
    assert r["our_action"] == "shadow_spam" and r["threat"] == "virus"
    assert h.client.write_names() == []


# ----- rescue of a threat --------------------------------------------------------------


def test_rescue_of_threat_never_learns_or_allows(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=10.0, learn_grace_seconds=0)
    scored(h, "t@x", score=1.0, symbols=PHISH, sender="svindel@bank.example")
    scored(h, "n@x", score=14.0, sender="spam@normal.example")
    h.advance(61)
    h.moves()
    assert sorted(h.client.msgids("Junk")) == ["n@x", "t@x"]
    h.user_moves("t@x", "Junk", "INBOX")
    h.user_moves("n@x", "Junk", "INBOX")
    h.scan()
    t, n = h.row("t@x"), h.row("n@x")
    assert t["user_verdict"] == "ham" and t["our_action"] == "user_rescued"
    assert t["pending_learn"] is None and n["pending_learn"] == "ham"
    assert [e[1] for e in h.events("threat_rescue_ignored_learning")] == ["t@x"]
    rules = {r["pattern"] for r in h.db.conn.execute("SELECT pattern FROM sender_rules")}
    assert "svindel@bank.example" not in rules and "spam@normal.example" in rules
    # The rescued threat stays in the inbox (the user's decision) ...
    h.advance(600)
    h.loop()
    assert "t@x" in h.client.msgids("INBOX")
    # ... and nothing learns it as ham, not even an explicit engine call.
    learned = [c for c in h.rspamd.learn_calls if b"t@x" in c["data"]]
    assert learned == []
    acc = h.acc
    assert eng.learn_message(h.db, acc, b"x", "ham", "t@x", reason="test") == "declined"
    assert h.events("threat_ham_refused")
    assert eng.learn_message(h.db, acc, make_message("t@x"), "spam", "t@x", reason="test") == "learned"


def test_learn_message_allow_threat_is_explicit(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=10.0)
    scored(h, "t@x", score=1.0, symbols=VIRUS)
    with h.db.tx():
        h.db.update_message("t@x", pending_learn="ham", pending_learn_at=1)
    assert eng.learn_message(h.db, h.acc, make_message("t@x"), "ham", "t@x") == "declined"
    assert h.row("t@x")["pending_learn"] is None
    assert eng.learn_message(h.db, h.acc, make_message("t@x"), "ham", "t@x", allow_threat=True) == "learned"


def test_autolearn_ham_guard_covers_threat_symbols(eng):
    for name in ("TH_ATTACH_BLOCK", "CLAM_VIRUS", "DBL_PHISH", "URLHAUS_MALWARE_URL"):
        assert eng.ham_guard_reason(None, "acct", symbols=[{"n": name, "s": 1.0}], final=-5.0,
                                    rspamd_score=-5.0)[0] == "phishing"


# ----- B17: file names --------------------------------------------------------------------


@pytest.mark.parametrize("name, ext", [
    ("faktura.pdf.exe", "exe"),
    ("FAKTURA.PDF.EXE", "exe"),
    ("faktura\u202efdp.exe", "exe"),              # RTLO: shows as "fakturaexe.pdf"
    ("faktura.pdf\u202e", "pdf"),
    ("x.e\u200bx\u200ce", "exe"),                 # zero-width space / non-joiner
    ("virus.exe.", "exe"), ("virus.exe . . ", "exe"),  # Windows drops trailing dots/spaces
    ("ｖｉｒｕｓ．ｅｘｅ", "exe"),                    # full-width forms (NFKC)
    ("c:\\temp\\run.bat", "bat"), ("dir/inner/run.JS", "js"),
    ("noext", ""), ("archive.tar.gz", "gz"),
])
def test_filename_normalisation_defeats_tricks(eng, name, ext):
    assert eng.filename_ext(name) == ext


def test_mail_attachments_lists_zip_members_and_links(eng):
    inner = zip_bytes([("deep.lnk", b"x")])
    raw = mail_with_attachments("m@x", [("faktura.zip", zip_bytes([("a.pdf", b"x"), ("inner.zip", inner)])),
                                        ("billede.jpg", b"jpg")], body="Se https://example.org/x")
    info = eng.mail_attachments(raw)
    names = [n for n, _w in info.names]
    assert "faktura.zip" in names and "a.pdf" in names and "deep.lnk" in names and "billede.jpg" in names
    assert info.has_links and info.has_attachments and info.encrypted == []
    assert eng.mail_attachments(make_message("p@x")).has_attachments is False
    assert eng.mail_attachments(b"\x00garbage").names == []


def test_blocked_attachment_top_level(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=10.0)
    r = scored(h, "a1@x", score=0.5, raw=mail_with_attachments("a1@x", [("faktura.pdf.exe", b"MZ")]))
    s = syms_of(h, "a1@x")["TH_ATTACH_BLOCK"]
    assert s["s"] == 20.0 and s["o"] == ["faktura.pdf.exe", "extension"]
    assert r["threat"] == "attachment" and r["threat_detail"] == "faktura.pdf.exe"
    assert r["our_score"] == pytest.approx(20.5) and r["our_action"] == "pending_move"
    assert eng.threat_text(r["threat"], r["threat_detail"]) == "Farlig vedhæftning: faktura.pdf.exe"


@pytest.mark.parametrize("name", ["faktura\u202efdp.exe", "invoice.js.", "SETUP.ISO", "x.ex\u200be"])
def test_blocked_attachment_tricks(eng, monkeypatch, name):
    h = Harness(eng, monkeypatch, threshold=10.0)
    r = scored(h, "t@x", raw=mail_with_attachments("t@x", [(name, b"x")]))
    assert r["threat"] == "attachment" and "\u202e" not in (r["threat_detail"] or "")


def test_blocked_attachment_inside_zip_and_nested_zip(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=10.0)
    r = scored(h, "z1@x", raw=mail_with_attachments("z1@x", [("bilag.zip", zip_bytes([("bilag.pdf", b"x"),
                                                                                      ("run.vbs", b"x")]))]))
    assert r["threat"] == "attachment" and r["threat_detail"] == "run.vbs"
    assert syms_of(h, "z1@x")["TH_ATTACH_BLOCK"]["o"][1] == "archive"
    nested = zip_bytes([("inner.zip", zip_bytes([("evil.hta", b"x")]))])
    r = scored(h, "z2@x", raw=mail_with_attachments("z2@x", [("pakke.zip", nested)]))
    assert r["threat"] == "attachment" and r["threat_detail"] == "evil.hta"
    r = scored(h, "z3@x", raw=mail_with_attachments("z3@x", [("ok.zip", zip_bytes([("a.pdf", b"x")]))]))
    assert r["threat"] is None and r["our_action"] == "none"


@pytest.mark.parametrize("symbols, detail", [
    (sym("MIME_BAD_EXTENSION", 1.0, ["exe"]), ".exe"),               # e.g. inside a rar
    (sym("MIME_BAD_EXTENSION", 1.0, ["scr:bilag.scr"]), "bilag.scr"),
    (sym("MIME_DOUBLE_BAD_EXTENSION", 3.0, [".pdf.exe"]), ".pdf.exe"),
    (sym("MIME_EXE_IN_GEN_SPLIT_RAR", 5.0, ["exe"]), ".exe"),
])
def test_rspamd_mime_symbols_trigger_the_block(eng, monkeypatch, symbols, detail):
    h = Harness(eng, monkeypatch, threshold=10.0)
    r = scored(h, "r@x", score=1.0, symbols=symbols)
    assert r["threat"] == "attachment" and r["threat_detail"] == detail


def test_rspamd_bad_extension_not_in_our_list_is_score_only(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=10.0)
    r = scored(h, "r@x", score=1.0, symbols=sym("MIME_BAD_EXTENSION", 1.0, ["ace"]))
    assert r["threat"] is None and r["our_action"] == "none"


def test_custom_and_empty_block_list(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=10.0, attachment_block=["pdf"])
    assert scored(h, "c1@x", raw=mail_with_attachments("c1@x", [("x.pdf", b"x")]))["threat"] == "attachment"
    assert scored(h, "c2@x", raw=mail_with_attachments("c2@x", [("x.exe", b"x")]))["threat"] is None
    h2 = Harness(eng, monkeypatch, threshold=10.0, attachment_block=[], name="other")
    r = scored(h2, "c3@x", raw=mail_with_attachments("c3@x", [("x.exe", b"x")]))
    assert r["threat"] is None


def test_encrypted_archive_costs_four_unless_known_contact(eng, monkeypatch):
    h = Harness(eng, monkeypatch, folders=("INBOX", "Junk", "Trash", "Sent"), threshold=10.0)
    h.client.add("Sent", sent_mail("s1@x", "revisor@kunde.dk"))
    run_sync(h)
    enc = zip_bytes([("regnskab.pdf", b"x")], encrypt=True)
    r = scored(h, "e1@x", score=1.0, raw=mail_with_attachments("e1@x", [("regnskab.zip", enc)],
                                                                 sender="ukendt@firma.example"))
    s = syms_of(h, "e1@x")["TH_ENCRYPTED_ARCHIVE"]
    assert s["s"] == 4.0 and s["o"] == ["regnskab.zip"]
    # 1 + 4 + TH_FIRST_CONTACT 1: scored, not blocked.
    assert r["our_score"] == pytest.approx(6.0) and r["threat"] is None and r["our_action"] == "none"
    h.rspamd.symbols["e2@x"] = DMARC_OK
    h.rspamd.scores["e2@x"] = 1.0
    import datetime as dt

    h.client.add("INBOX", mail_with_attachments("e2@x", [("regnskab.zip", enc)], sender="revisor@kunde.dk"),
                 internaldate=dt.datetime.fromtimestamp(h.t, dt.timezone.utc))
    h.scan()
    names = syms_of(h, "e2@x")
    assert "TH_ENCRYPTED_ARCHIVE" not in names and "TH_KNOWN_CONTACT" in names
    # rspamd's own MIME_ENCRYPTED_ARCHIVE (rar/7z) counts too.
    scored(h, "e3@x", score=1.0, symbols=sym("MIME_ENCRYPTED_ARCHIVE", 0.0, ["pakke.rar"]))
    assert syms_of(h, "e3@x")["TH_ENCRYPTED_ARCHIVE"]["o"] == ["pakke.rar"]


def test_attachment_exception_needs_dkim_verification(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=10.0)
    rid = eng.add_attach_rule(h.db.conn, "acct", "@leverandor.dk", note="ISO-filer", actor="admin")
    raw = mail_with_attachments("x1@x", [("driver.iso", b"x")], sender="it@leverandor.dk")
    r = scored(h, "x1@x", score=1.0, symbols=dkim("leverandor.dk"), raw=raw)
    names = syms_of(h, "x1@x")
    assert "TH_ATTACH_BLOCK" not in names and names["TH_ATTACH_ALLOWED"]["o"] == ["driver.iso", "@leverandor.dk"]
    assert r["threat"] is None and r["our_action"] == "none"
    assert h.db.conn.execute("SELECT hits FROM attach_rules WHERE id=?", (rid,)).fetchone()[0] == 1
    # A forged From (no DKIM of the domain) gets no exception.
    raw = mail_with_attachments("x2@x", [("driver.iso", b"x")], sender="it@leverandor.dk")
    r = scored(h, "x2@x", score=1.0, symbols=dkim("evil.example"), raw=raw)
    assert r["threat"] == "attachment"
    assert [e[1] for e in h.events("attach_exception_unverified")] == ["x2@x"]
    # A virus is never excepted.
    raw = mail_with_attachments("x3@x", [("driver.iso", b"x")], sender="it@leverandor.dk")
    r = scored(h, "x3@x", score=1.0, symbols=syms(dkim("leverandor.dk"), VIRUS), raw=raw)
    assert r["threat"] == "virus" and r["our_action"] == "pending_move"
    assert eng.delete_attach_rule(h.db.conn, rid) is True


def test_attach_rules_never_touch_sender_rules(eng, monkeypatch):
    """sender_rules.kind has CHECK(allow|block): the exception lives in its
    own table, so 2.2.0 (which ranks every rule by kind) never sees it."""
    h = Harness(eng, monkeypatch)
    eng.add_attach_rule(h.db.conn, "*", "a@b.dk")
    assert h.db.conn.execute("SELECT COUNT(*) FROM sender_rules").fetchone()[0] == 0
    import sqlite3

    with pytest.raises(sqlite3.IntegrityError):
        h.db.conn.execute("INSERT INTO sender_rules(account, pattern, kind, created_at) "
                          "VALUES('*', 'x@y.dk', 'attach_ok', 1)")


def test_privacy_threat_events_carry_no_sender_address(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=10.0)
    scored(h, "pv@x", score=1.0, symbols=PHISH, sender="hemmelig.person@privat.example")
    for ev, _mid, detail in h.events():
        if ev.startswith(("threat", "attach")):
            assert "hemmelig.person" not in (detail or "")


def test_rescan_symbols_json_keeps_threat_options(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=10.0)
    scored(h, "o@x", score=1.0, symbols=sym("CLAM_VIRUS", 0.0, [f"Sig{i}" for i in range(10)]))
    res = h.db.conn.execute("SELECT symbols FROM messages WHERE message_id='o@x'").fetchone()[0]
    assert any(s["n"] == "CLAM_VIRUS" for s in json.loads(res))


# ----- 2.7 fix: heuristic / third-party ClamAV signatures ---------------------------------


@pytest.mark.parametrize("sig,heuristic", [
    ("Heuristics.Phishing.Email.SpoofedDomain", True),
    ("Heuristics.Limits.Exceeded.MaxFileSize", True),
    ("PUA.Doc.Tool.LibreOffice_Macro-1", True),
    ("Html.Phishing.Bank-123", True),
    ("Email.Phishing.Pdf-7", True),
    ("Sanesecurity.Jurlbl.Auto.1a2b.UNOFFICIAL", True),
    ("SecuriteInfo.com.PDF.Phishing.Gen.1", True),
    ("winnow.phish.123.UNOFFICIAL", True),
    ("MiscreantPunch.Spam.EML.1", True),
    ("foxhole.Zip_fs223", True),
    ("Porcupine.Malware.1", True),
    ("Something.Else.UNOFFICIAL", True),
    ("Win.Trojan.Agent-123", False),
    ("Doc.Dropper.Agent-6338946-0", False),
    ("Eicar-Signature", False),
])
def test_clam_signature_classes(eng, sig, heuristic):
    assert eng.clam_is_heuristic(sig) is heuristic
    names = {"CLAM_VIRUS"}
    syms_ = [{"n": "CLAM_VIRUS", "s": 0.0, "o": [sig]}]
    assert eng.classify_threat(names, syms_)[0] == (None if heuristic else "virus")


def test_clam_mixed_or_unnamed_signatures_stay_virus(eng):
    mixed = [{"n": "CLAM_VIRUS", "s": 0.0, "o": ["Heuristics.Phishing.Email", "Win.Trojan.Agent-1"]}]
    assert eng.classify_threat({"CLAM_VIRUS"}, mixed) == ("virus", "Heuristics.Phishing.Email")
    assert eng.classify_threat({"CLAM_VIRUS"}, [{"n": "CLAM_VIRUS", "s": 0.0, "o": []}])[0] == "virus"
    # The heuristic hit still lets another threat class through.
    heur = [{"n": "CLAM_VIRUS", "s": 0.0, "o": ["Sanesecurity.Phish.1"]}]
    assert eng.classify_threat({"CLAM_VIRUS", "DBL_PHISH"}, heur)[0] == "phish"


HEUR = sym("CLAM_VIRUS", 0.0, ["Heuristics.Phishing.Email.SpoofedDomain"])
# 2.8 (A1): third-party (Sanesecurity) hits are TH_CLAM_3P (Fra/Prøv/Til), not TH_CLAM_HEURISTIC.
THIRD = sym("CLAM_VIRUS", 0.0, ["Sanesecurity.Foxhole.Zip_fs223.UNOFFICIAL"])
THIRD_PHISH = sym("CLAM_VIRUS", 0.0, ["Sanesecurity.Phishing.Fake.21.UNOFFICIAL"])


def test_clam_heuristic_scores_four_and_is_no_threat(eng, monkeypatch):
    h = Harness(eng, monkeypatch, threshold=6.0)
    r = scored(h, "h1@x", score=1.0, symbols=HEUR)
    s = {x["n"]: x for x in json.loads(r["symbols"])}
    assert r["threat"] is None and r["our_action"] == "none" and r["our_score"] == pytest.approx(5.0)
    assert s["TH_CLAM_HEURISTIC"]["s"] == 4.0
    assert s["TH_CLAM_HEURISTIC"]["o"] == ["Heuristics.Phishing.Email.SpoofedDomain"]
    r = scored(h, "h2@x", score=2.5, symbols=HEUR)
    assert r["our_action"] == "pending_move" and r["threat"] is None   # a Bruger can release it
    # 'Altid igennem' (DKIM-verified) still wins - unlike a real virus.
    eng.add_sender_rule(h.db.conn, "*", "@vexar.example", "allow", None, "admin", force=True)
    r = scored(h, "h3@x", score=5.0, symbols=syms(HEUR, dkim("vexar.example")), sender="ordre@vexar.example")
    assert r["our_action"] == "allowlisted" and r["threat"] is None
    r = scored(h, "v3@x", score=0.0, symbols=syms(VIRUS, dkim("vexar.example")), sender="ordre@vexar.example")
    assert r["threat"] == "virus" and r["our_action"] == "pending_move"


def test_clam_heuristic_keeps_the_known_contact_bonus(eng, monkeypatch):
    h = Harness(eng, monkeypatch, folders=("INBOX", "Junk", "Trash", "Sent"), threshold=10.0)
    h.client.add("Sent", sent_mail("s1@x", "alice@kunde.dk"))
    run_sync(h)
    inbound(h, "kh@x", "alice@kunde.dk", score=3.0, symbols=syms(DMARC_OK, HEUR))
    names = syms_of(h, "kh@x")
    assert "TH_KNOWN_CONTACT" in names and "TH_CLAM_HEURISTIC" in names
    inbound(h, "kv@x", "alice@kunde.dk", score=3.0, symbols=syms(DMARC_OK, VIRUS))
    assert "TH_KNOWN_CONTACT" not in syms_of(h, "kv@x")


def test_clam_heuristic_text():
    import ui_kit as kit

    heur = {"n": "TH_CLAM_HEURISTIC", "s": 4.0, "o": ["Heuristics.Phishing.Email.SpoofedDomain"]}
    assert "ikke en sikker virus" in kit.explain_symbol_detail(heur)
    clam = {"n": "CLAM_VIRUS", "s": 0.0, "o": ["Heuristics.Phishing.Email.SpoofedDomain"]}
    assert "ikke en sikker virus" in kit.explain_symbol_detail(clam, symbols=[clam, heur])
    assert kit.explain_symbol_detail({"n": "CLAM_VIRUS", "s": 0.0, "o": ["Win.Trojan.A"]}) == \
        kit.SYMBOL_TEXT["CLAM_VIRUS"]
    assert kit.plain_reason("TH_CLAM_HEURISTIC")


# ---------------------------------------------------------------- 2.8 (A1): Sanesecurity
def test_third_party_hit_is_a_trial_by_default_and_never_a_virus(eng, monkeypatch):
    import trialmode
    trialmode._CACHE.clear()
    h = Harness(eng, monkeypatch, threshold=6.0)
    r = scored(h, "t1@x", score=1.0, symbols=THIRD_PHISH)
    s = {x["n"]: x for x in json.loads(r["symbols"])}
    assert r["threat"] is None and r["our_score"] == pytest.approx(1.0)
    assert "TH_CLAM_HEURISTIC" not in s and s["TH_CLAM_3P_TRIAL"]["s"] == 0.0
    assert s["TH_CLAM_3P_TRIAL"]["o"][0] == "+6"
    ev = h.db.conn.execute("SELECT detail FROM events WHERE event='clam3p_trial'").fetchone()
    assert ev and ev[0].startswith("+6 Sanesecurity.Phishing.Fake.21")


def test_third_party_hit_scores_when_on(eng, monkeypatch):
    import trialmode
    h = Harness(eng, monkeypatch, threshold=6.0)
    with h.db.conn:
        trialmode.set_mode(h.db.conn, "clam3p", "on", "test")
    r = scored(h, "t2@x", score=1.0, symbols=THIRD_PHISH)
    assert r["our_score"] == pytest.approx(7.0) and r["our_action"] == "pending_move" and r["threat"] is None
    r = scored(h, "t3@x", score=1.0, symbols=THIRD)
    s = {x["n"]: x for x in json.loads(r["symbols"])}
    assert s["TH_CLAM_3P"]["s"] == 4.0 and r["our_score"] == pytest.approx(5.0)
    with h.db.conn:
        trialmode.set_mode(h.db.conn, "clam3p", "off", "test")
    r = scored(h, "t4@x", score=1.0, symbols=THIRD_PHISH)
    assert r["our_score"] == pytest.approx(1.0) and "TH_CLAM_3P" not in r["symbols"]
    trialmode._CACHE.clear()


def test_third_party_signature_classes(eng):
    assert eng.clam_is_third_party("Sanesecurity.Phishing.Fake.1.UNOFFICIAL")
    assert eng.clam_is_third_party("Porcupine.Malware.1.UNOFFICIAL")
    assert not eng.clam_is_third_party("Heuristics.Phishing.Email.SpoofedDomain")
    assert not eng.clam_is_third_party("Win.Trojan.Agent-1")
    # A real virus next to a third-party hit stays the threat 'virus' and gets no TH_CLAM_3P.
    res = type("R", (), {"names": {"CLAM_VIRUS"}, "symbols": [{"n": "CLAM_VIRUS", "s": 0.0, "o": [
        "Sanesecurity.Phishing.Fake.1.UNOFFICIAL", "Win.Trojan.Agent-1"]}], "options": {}})()
    assert eng.clam_3p_symbols(res, "on") == ([], [])


def test_heuristic_clam_hit_does_not_block_ham_learning(eng):
    third = [{"n": "CLAM_VIRUS", "s": 0.0, "o": ["Sanesecurity.Phishing.Fake.1.UNOFFICIAL"]}]
    assert eng.ham_guard_reason(None, "a", symbols=third, final=1.0, rspamd_score=1.0) is None
    real = [{"n": "CLAM_VIRUS", "s": 0.0, "o": ["Win.Trojan.Agent-1"]}]
    assert eng.ham_guard_reason(None, "a", symbols=real, final=1.0, rspamd_score=1.0)[0] == "phishing"
