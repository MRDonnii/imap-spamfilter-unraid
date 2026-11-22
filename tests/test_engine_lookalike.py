"""ENGINE (B22): lookalike domains in a live scan and the weekly
registration watch.

TH_LOOKALIKE_DOMAIN (+6) on From / Reply-To / envelope sender / DKIM d=
makes the mail threat class 'lookalike' (always moved, admin-only release,
Straks-advarsel); TH_LOOKALIKE_URL (+4) on a link is score only. Ham
history, known contacts, 'Ikke en efterligning' and a signature of the
imitated domain itself exempt a hit. The watch: baseline first, then only
an MX or A record that appears raises an alert (event, mail, Oversigt)."""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import logging
import sqlite3
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import make_message, setup_engine, stub_mailctx  # noqa: E402
from test_engine_contacts import dkim, sym  # noqa: E402
from test_engine_scan import Harness  # noqa: E402
from test_lookalike import FakeResolver  # noqa: E402

import lookalike as lk  # noqa: E402

LOG = logging.getLogger("test-lookalike")
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def eng(tmp_path, monkeypatch):
    e = setup_engine(tmp_path, monkeypatch)
    monkeypatch.setattr(e, "LOOKALIKE_MAILBOX_DOMAINS", frozenset())
    return e


def _h(eng, monkeypatch, **kw):
    kw.setdefault("threshold", 10.0)
    kw.setdefault("user", "ole@bynet.example")
    return Harness(eng, monkeypatch, **kw)


def mail(h, msgid, *, sender="ordre@pinslkbing.example", score=1.0, symbols=None, extra_headers="", body="Hej.\r\n"):
    h.rspamd.scores[msgid] = score
    h.rspamd.symbols[msgid] = symbols or {}
    h.client.add("INBOX", make_message(msgid, sender=sender, extra_headers=extra_headers, body=body),
                 internaldate=dt.datetime.fromtimestamp(h.t, dt.timezone.utc))
    h.scan()
    return h.row(msgid)


def syms_of(row):
    return {s["n"]: s for s in json.loads(row["symbols"])}


# ----- config ------------------------------------------------------------------------------

YML = """
defaults:
  mode: move
{defaults}
accounts:
  - name: bynet
    user: ole@bynet.example
    imap_host: imap.example.net
    password: x
{extra}
"""


def test_config_protected_domains(eng):
    p = Path(eng.CONFIG_PATH)
    p.write_text(YML.format(defaults="", extra=""))
    assert eng.load_account_configs(p)[0].protected_domains == ["pinsikbing.example", "gravisk.example", "vexar.example"]
    p.write_text(YML.format(defaults="  protected_domains: [Bank.DK, '*.e-conomic.dk']", extra=""))
    assert eng.load_account_configs(p)[0].protected_domains == ["bank.dk", "e-conomic.dk"]
    p.write_text(YML.format(defaults="  protected_domains: null", extra=""))
    assert eng.load_account_configs(p)[0].protected_domains == []
    p.write_text(YML.format(defaults="  protected_domains: ['ikke et domæne!']", extra=""))
    with pytest.raises(ValueError):
        eng.load_account_configs(p)
    many = "[" + ", ".join(f"d{i}.dk" for i in range(51)) + "]"
    p.write_text(YML.format(defaults=f"  protected_domains: {many}", extra=""))
    with pytest.raises(ValueError, match="protected_domains"):
        eng.load_account_configs(p)


def test_protected_list_includes_every_mailbox(eng, monkeypatch):
    acc = SimpleNamespace(user="inge@molt.example", protected_domains=["pinsikbing.example"])
    assert eng.lookalike_protected(acc) == ["pinsikbing.example", "molt.example"]
    eng.set_lookalike_mailboxes([SimpleNamespace(user="ole@bynet.example"), SimpleNamespace(user="inge@molt.example")])
    assert eng.lookalike_protected(acc) == ["pinsikbing.example", "molt.example", "bynet.example"]
    assert eng.lookalike_watch_protected([SimpleNamespace(user="ole@bynet.example", protected_domains=None)]) == \
        ["pinsikbing.example", "gravisk.example", "vexar.example", "bynet.example"]


# ----- scan: sender fields ---------------------------------------------------------------------


def test_from_lookalike_is_a_threat_and_moved(eng, monkeypatch):
    h = _h(eng, monkeypatch)
    r = mail(h, "f@x")
    s = syms_of(r)["TH_LOOKALIKE_DOMAIN"]
    assert s["s"] == 6.0 and s["o"] == ["pinslkbing.example", "pinsikbing.example", "from"]
    assert r["our_score"] == pytest.approx(7.0)                     # below the threshold ...
    assert r["threat"] == "lookalike" and r["threat_detail"] == "pinslkbing.example ligner pinsikbing.example"
    assert r["our_action"] == "pending_move"                        # ... and still moved
    assert eng.threat_text(r["threat"], r["threat_detail"]) == \
        "Efterligner jeres domæne: pinslkbing.example ligner pinsikbing.example"
    assert any(e[0] == "threat_detected" and "lookalike" in e[2] for e in h.events())
    h.advance(10)
    h.moves()
    assert h.row("f@x")["our_action"] == "moved_to_junk" and "f@x" in h.client.msgids("Junk")
    # Straks-advarsel: the notice row is queued like every other threat.
    t = h.db.conn.execute("SELECT threat, queued_at FROM threat_notices WHERE message_id='f@x'").fetchone()
    assert t["threat"] == "lookalike" and t["queued_at"]


@pytest.mark.parametrize("field,kw", [
    ("reply_to", dict(sender="kunde@ok.example", extra_headers="Reply-To: Betaling <betaling@gravlsk.example>")),
    ("dkim", dict(sender="kunde@ok.example", symbols=dkim("mail.pinsikblng.example"))),
    ("dkim", dict(sender="kunde@ok.example",
                  extra_headers="DKIM-Signature: v=1; a=rsa-sha256; d=pinsikbing-example.com; s=x; b=abc")),
])
def test_other_sender_fields(eng, monkeypatch, field, kw):
    h = _h(eng, monkeypatch)
    r = mail(h, "o@x", **kw)
    assert syms_of(r)["TH_LOOKALIKE_DOMAIN"]["o"][2] == field
    assert r["threat"] == "lookalike"


def test_envelope_sender(eng, monkeypatch):
    stub = stub_mailctx()
    base = stub.scan_context

    def ctx(raw, acc):
        c = base(raw, acc)
        c["envelope_from"] = "bounce@p1nsikbing.example"
        return c

    stub.scan_context = ctx
    monkeypatch.setattr(eng, "_mailctx", lambda: stub)
    h = _h(eng, monkeypatch)
    r = mail(h, "e@x", sender="kunde@ok.example")
    assert syms_of(r)["TH_LOOKALIKE_DOMAIN"]["o"] == ["p1nsikbing.example", "pinsikbing.example", "envelope"]


def test_url_lookalike_scores_only(eng, monkeypatch):
    h = _h(eng, monkeypatch)
    r = mail(h, "u@x", sender="nyhed@shop.example", body="Log ind: https://www.pinslkbing.example/konto\r\n")
    s = syms_of(r)
    assert "TH_LOOKALIKE_DOMAIN" not in s and s["TH_LOOKALIKE_URL"]["s"] == 4.0
    assert r["our_score"] == pytest.approx(5.0) and r["threat"] is None and r["our_action"] == "none"


def test_url_plus_high_score_is_spam_but_no_threat(eng, monkeypatch):
    h = _h(eng, monkeypatch)
    r = mail(h, "u2@x", sender="nyhed@shop.example", score=7.0, body="https://pinsikbing.example.evil.example/x\r\n")
    assert r["our_score"] == pytest.approx(11.0) and r["our_action"] == "pending_move" and r["threat"] is None


def test_own_mail_and_clean_mail_untouched(eng, monkeypatch):
    h = _h(eng, monkeypatch)
    r = mail(h, "own@x", sender="ordre@pinsikbing.example", body="https://pinsikbing.example/ordre\r\n")
    assert not any(n.startswith("TH_LOOKALIKE") for n in syms_of(r)) and r["threat"] is None
    r = mail(h, "ikea@x", sender="nyhed@ikea.com", body="https://www.ikea.com\r\n")
    assert not any(n.startswith("TH_LOOKALIKE") for n in syms_of(r))
    r = mail(h, "mb@x", sender="kollega@bynet.example")
    assert r["threat"] is None


def test_mailbox_domain_of_another_account_is_protected(eng, monkeypatch):
    monkeypatch.setattr(eng, "LOOKALIKE_MAILBOX_DOMAINS", frozenset({"molt.example"}))
    h = _h(eng, monkeypatch)
    r = mail(h, "m@x", sender="inge@rnolt.example")
    assert syms_of(r)["TH_LOOKALIKE_DOMAIN"]["o"][:2] == ["rnolt.example", "molt.example"]


# ----- exemptions ----------------------------------------------------------------------------------


def _history(h, regdom, kept):
    import contacts

    contacts.ensure_schema(h.db.conn)
    h.db.conn.execute("INSERT INTO sender_history(account, h, regdom, n_kept, n_seen, n_junk) VALUES(?,?,?,?,?,0)",
                      ("other", "hh" + regdom, regdom, kept, kept))


def test_ham_history_exempts(eng, monkeypatch):
    h = _h(eng, monkeypatch)
    _history(h, "pinslkbing.example", 3)
    r = mail(h, "hh@x")
    s = syms_of(r)
    assert "TH_LOOKALIKE_DOMAIN" not in s and s["TH_LOOKALIKE_ALLOWED"]["o"][2] == "ham_history"
    assert r["threat"] is None and r["our_action"] == "none"


def test_known_contact_exempts(eng, monkeypatch):
    h = _h(eng, monkeypatch)
    import contacts

    contacts.ensure_schema(h.db.conn)
    h.db.conn.execute("INSERT INTO known_contacts(account, h, domain, mask, status) "
                      "VALUES('acct', 'k1', 'pinslkbing.example', 'o…@pinslkbing.example', 'active')")
    assert mail(h, "kc@x")["threat"] is None


def test_not_a_lookalike_list_exempts(eng, monkeypatch):
    h = _h(eng, monkeypatch)
    h.db.conn.execute("INSERT INTO lookalike_allow(domain, created_at) VALUES('pinslkbing.example', 1)")
    r = mail(h, "al@x", sender="ordre@post.pinslkbing.example")
    assert r["threat"] is None and syms_of(r)["TH_LOOKALIKE_ALLOWED"]["o"][2] == "allowed"


def test_signature_of_the_imitated_domain_exempts(eng, monkeypatch):
    h = _h(eng, monkeypatch)
    r = mail(h, "sig@x", sender="noreply@vexarexample.com", symbols=dkim("vexar.example"))
    assert r["threat"] is None
    r = mail(h, "sig2@x", sender="ordre@pinslkbing.example", symbols=dkim("vexar.example"))
    assert r["threat"] == "lookalike"        # the shop platform's key does not vouch for another shop's name


@pytest.mark.parametrize("sender,signer", [
    ("ole@bynet.example", "bynetexample.onmicrosoft.com"),
    ("info@pinsikbing.example", "pinsikbing-example.20230601.gappssmtp.com"),
])
def test_own_mail_signed_by_the_providers_default_key_is_not_a_threat(eng, monkeypatch, sender, signer):
    """2.3.6 review: Google Workspace / Microsoft 365 without a custom DKIM
    key sign own mail with a provider name that embeds the domain."""
    h = _h(eng, monkeypatch)
    r = mail(h, "own@x", sender=sender, symbols=dkim(signer))
    s = syms_of(r)
    assert r["threat"] is None and r["our_action"] == "none"
    assert "TH_LOOKALIKE_DOMAIN" not in s and s["TH_LOOKALIKE_ALLOWED"]["o"][2] == "provider"
    # The same tenant signing a stranger's mail is still an imitation.
    r = mail(h, "own2@x", sender="kunde@ok.example", symbols=dkim(signer))
    assert r["threat"] == "lookalike"


def test_shared_platform_history_does_not_exempt_a_tenant(eng, monkeypatch):
    h = _h(eng, monkeypatch)
    _history(h, "onmicrosoft.com", 5)            # kept mail from some unrelated M365 tenant
    r = mail(h, "tn@x", sender="ordre@pinsikbingexample.onmicrosoft.com")
    assert r["threat"] == "lookalike"
    assert syms_of(r)["TH_LOOKALIKE_DOMAIN"]["o"][:2] == ["pinsikbingexample.onmicrosoft.com", "pinsikbing.example"]


def test_threat_overrides_allow_rule_and_is_never_learned_as_ham(eng, monkeypatch):
    h = _h(eng, monkeypatch)
    eng.add_sender_rule(h.db.conn, "*", "@pinslkbing.example", "allow", "", "admin")
    r = mail(h, "ar@x")
    assert r["our_action"] == "pending_move" and r["threat"] == "lookalike"
    out = eng.learn_message(h.db, h.acc, make_message("ar@x", sender="ordre@pinslkbing.example"), "ham", "ar@x")
    assert out == "declined"


def test_release_needs_admin_confirmation():
    import services

    gate = services.threat_gate("lookalike", "pinslkbing.example ligner pinsikbing.example", is_admin=False,
                                confirm_threat=False)
    assert gate["code"] == "threat_admin" and "Efterligner jeres domæne" in gate["text"]
    gate = services.threat_gate("lookalike", "pinslkbing.example ligner pinsikbing.example", is_admin=True,
                                confirm_threat=False)
    assert gate["code"] == "threat_confirm" and "efterligner jeres eget (pinslkbing.example ligner pinsikbing.example)" \
        in gate["confirm_text"]
    assert services.threat_gate("lookalike", None, is_admin=True, confirm_threat=True) is None


def test_services_and_engine_threat_texts_agree(eng):
    import services

    assert services.THREAT_LABELS == eng.THREAT_LABELS
    for d in (None, "pinslkbing.example ligner pinsikbing.example"):
        assert services.threat_text("lookalike", d) == eng.threat_text("lookalike", d)
        assert services.threat_confirm_text("lookalike", d) == eng.threat_confirm_text("lookalike", d)


def test_classify_threat_order_and_detail(eng):
    names = {"TH_LOOKALIKE_DOMAIN"}
    syms = [{"n": "TH_LOOKALIKE_DOMAIN", "s": 6.0, "o": ["pinslkbing.example", "pinsikbing.example", "from"]}]
    assert eng.classify_threat(names, syms) == ("lookalike", "pinslkbing.example ligner pinsikbing.example")
    assert eng.classify_threat(names | {"DBL_PHISH"}, syms)[0] == "phish"     # more severe wins
    assert eng.classify_threat({"TH_LOOKALIKE_URL"}, [])[0] is None


def test_scan_survives_a_broken_lookalike_module(eng, monkeypatch):
    h = _h(eng, monkeypatch)

    class Broken:
        def __getattr__(self, name):
            raise RuntimeError("boom")

    monkeypatch.setattr(eng, "_lookalike", lambda: Broken())
    r = mail(h, "b@x")
    assert r["our_action"] == "none" and r["threat"] is None


# ----- weekly registration watch ----------------------------------------------------------------


class FakeMailer:
    def __init__(self, ok=True):
        self.ok = ok
        self.calls = []

    def notify(self, kind, subject, text, html=None, recipients=None):
        self.calls.append(SimpleNamespace(kind=kind, subject=subject, text=text))
        return {"ok": self.ok, "code": "queued" if self.ok else "not_configured"}


class NoWait:
    def wait(self):
        pass


CONFIGS = [SimpleNamespace(user="ole@bynet.example", protected_domains=["pinsikbing.example"])]


def _events(conn, name=None):
    return [tuple(r) for r in conn.execute("SELECT account, event, detail FROM events ORDER BY id")
            if name is None or r[1] == name]


def test_watch_once_baseline_then_alert(eng, monkeypatch):
    m = FakeMailer()
    monkeypatch.setattr(eng, "_mailer", lambda: m)
    t0 = 1_800_000_000
    monkeypatch.setattr(eng, "_now", lambda: t0)
    conn = eng._open_conn()
    res = FakeResolver({"pinslkbing.example": {"NS": ["ns.x"]}})
    s1 = eng.lookalike_watch_once(CONFIGS, conn=conn, resolver=res, limiter=NoWait())
    assert s1["complete"] and s1["new"] == 0 and s1["baseline"] == s1["checked"] > 0
    assert set(s1["protected"]) == {"pinsikbing.example", "bynet.example"}
    assert m.calls == [] and _events(conn, "lookalike_registered") == []
    assert _events(conn, "lookalike_watch_done")[0][0] == "*"
    assert eng.engine_state_get(conn, eng.LOOKALIKE_STATE_COMPLETE) == str(t0)
    # A week later pinslkbing.example gets a mail server.
    res.zones["pinslkbing.example"]["MX"] = ["10 mx.evil.example"]
    monkeypatch.setattr(eng, "_now", lambda: t0 + 7 * 86400)
    s2 = eng.lookalike_watch_once(CONFIGS, conn=conn, resolver=res, limiter=NoWait())
    assert s2["new"] == 1
    ev = _events(conn, "lookalike_registered")
    assert ev == [("*", "lookalike_registered", "pinslkbing.example ligner pinsikbing.example: mx")]
    assert len(m.calls) == 1 and m.calls[0].kind == "alert"
    assert m.calls[0].subject == "Spamfilter: nyt domæne ligner pinsikbing.example"
    assert "pinslkbing[.]example (ligner pinsikbing.example) har fået en mailserver" in m.calls[0].text
    assert "pinslkbing.example" not in m.calls[0].text                    # defanged: never a link
    row = conn.execute("SELECT alerted_at, new_at FROM lookalike_watch WHERE domain='pinslkbing.example'").fetchone()
    assert row["alerted_at"] == t0 + 7 * 86400 and row["new_at"] == t0 + 7 * 86400
    conn.close()


def test_watch_without_smtp_still_records(eng, monkeypatch):
    m = FakeMailer(ok=False)
    monkeypatch.setattr(eng, "_mailer", lambda: m)
    conn = eng._open_conn()
    res = FakeResolver({"pinslkbing.example": {"NS": ["ns.x"]}})
    monkeypatch.setattr(eng, "_now", lambda: 1_800_000_000)
    eng.lookalike_watch_once(CONFIGS, conn=conn, resolver=res, limiter=NoWait())
    res.zones["pinslkbing.example"]["A"] = ["192.0.2.1"]
    monkeypatch.setattr(eng, "_now", lambda: 1_800_000_000 + 7 * 86400)
    eng.lookalike_watch_once(CONFIGS, conn=conn, resolver=res, limiter=NoWait())
    row = conn.execute("SELECT alerted_at, new_what FROM lookalike_watch WHERE domain='pinslkbing.example'").fetchone()
    assert row["alerted_at"] is None and row["new_what"] == "a"
    assert len(m.calls) == 1                                         # tried once, mailer said no
    conn.close()


def test_watch_failure_is_incomplete_and_retried(eng, monkeypatch):
    class Down:
        def query(self, name, qtype):
            raise lk.DnsError("resolver unreachable")

    conn = eng._open_conn()
    monkeypatch.setattr(eng, "_now", lambda: 1_800_000_000)
    s = eng.lookalike_watch_once(CONFIGS, conn=conn, resolver=Down(), limiter=NoWait())
    assert not s["complete"] and s["error"] == "resolver unreachable"
    assert eng.engine_state_get(conn, eng.LOOKALIKE_STATE_COMPLETE) is None
    assert _events(conn, "lookalike_watch_failed")
    conn.close()


def test_watch_where_every_lookup_times_out_is_failed_and_retried(eng, monkeypatch):
    """2.3.6 review: a resolver that answers nothing but timeouts used to
    give a 'complete', 'done' run that was not retried for a week."""
    class Timeouts:
        calls = 0

        def query(self, name, qtype):
            Timeouts.calls += 1
            raise lk.DnsError("timeout")

    conn = eng._open_conn()
    t0 = _at_local(3)
    monkeypatch.setattr(eng, "_now", lambda: t0)
    s = eng.lookalike_watch_once(CONFIGS, conn=conn, resolver=Timeouts(), limiter=NoWait())
    assert not s["complete"] and s["error"] == lk.WATCH_ERROR_DNS and s["checked"] == 0
    assert Timeouts.calls == lk.WATCH_MAX_CONSECUTIVE_ERRORS            # gave up early
    assert eng.engine_state_get(conn, eng.LOOKALIKE_STATE_COMPLETE) is None
    assert _events(conn, "lookalike_watch_failed") and not _events(conn, "lookalike_watch_done")
    assert "fejl=dns errors" in _events(conn, "lookalike_watch_failed")[0][2]
    assert eng.lookalike_watch_due(conn, t0 + 600) is None             # not straight away ...
    assert eng.lookalike_watch_due(conn, t0 + 3700) == "schedule"      # ... but within the hour window
    conn.close()


def _at_local(hour):
    import zoneinfo

    return dt.datetime(2026, 10, 25, hour, 30, tzinfo=zoneinfo.ZoneInfo("Europe/Copenhagen")).timestamp()


def test_watch_due_logic(eng):
    conn = eng._open_conn()
    night, day = _at_local(3), _at_local(14)
    assert eng.lookalike_watch_due(conn, night) == "schedule"          # never ran: first quiet hour
    assert eng.lookalike_watch_due(conn, day) is None
    eng.engine_state_set(conn, eng.LOOKALIKE_STATE_REQUEST, "1")
    assert eng.lookalike_watch_due(conn, day) == "request"           # 'Kør kontrol nu'
    eng.engine_state_set(conn, eng.LOOKALIKE_STATE_REQUEST, None)
    eng.engine_state_set(conn, eng.LOOKALIKE_STATE_COMPLETE, str(int(night - 2 * 86400)))
    assert eng.lookalike_watch_due(conn, night) is None              # done two days ago
    eng.engine_state_set(conn, eng.LOOKALIKE_STATE_COMPLETE, str(int(night - 7 * 86400)))
    assert eng.lookalike_watch_due(conn, night) == "schedule"
    eng.engine_state_set(conn, eng.LOOKALIKE_STATE_ATTEMPT, str(int(night - 600)))
    assert eng.lookalike_watch_due(conn, night) is None              # an attempt 10 min ago
    conn.close()


def test_watch_request_is_cleared(eng, monkeypatch):
    conn = eng._open_conn()
    eng.engine_state_set(conn, eng.LOOKALIKE_STATE_REQUEST, "123")
    eng.lookalike_watch_once(CONFIGS, conn=conn, resolver=FakeResolver(), limiter=NoWait(), reason="request",
                             max_lookups=5)
    assert eng.engine_state_get(conn, eng.LOOKALIKE_STATE_REQUEST) is None
    last = json.loads(eng.engine_state_get(conn, eng.LOOKALIKE_STATE_LAST))
    assert last["capped"] and not last["complete"] and last["reason"] == "request"
    conn.close()


def test_init_db_creates_the_tables(eng):
    conn = sqlite3.connect(eng.DB_PATH)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"lookalike_watch", "lookalike_allow"} <= names
    conn.close()


# ----- rollback ------------------------------------------------------------------------------------


def _head_source() -> str | None:
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "show", "HEAD:filter/filter.py"], capture_output=True,
                             text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout if out.returncode == 0 and 'VERSION = "2.3' in out.stdout else None


def test_rollback_head_engine_on_a_lookalike_database(tmp_path, monkeypatch):
    src = _head_source()
    if src is None:
        pytest.skip("HEAD source not available (no git history)")
    if "THREAT_LOOKALIKE" in src:
        pytest.skip("HEAD already contains B22")
    eng = setup_engine(tmp_path, monkeypatch)
    monkeypatch.setattr(eng, "LOOKALIKE_MAILBOX_DOMAINS", frozenset())
    h = _h(eng, monkeypatch)
    mail(h, "rb@x")
    h.db.conn.execute("INSERT INTO lookalike_allow(domain, created_at) VALUES('x.dk', 1)")
    eng.lookalike_watch_once(CONFIGS, resolver=FakeResolver(), limiter=NoWait(), max_lookups=12)
    h.db.close()
    old_dir = tmp_path / "head"
    old_dir.mkdir()
    (old_dir / "filter_head.py").write_text(src)
    spec = importlib.util.spec_from_file_location("filter_head", old_dir / "filter_head.py")
    old = importlib.util.module_from_spec(spec)
    sys.modules["filter_head"] = old
    try:
        spec.loader.exec_module(old)
        assert old.SCORE_VERSION == eng.SCORE_VERSION
        monkeypatch.setattr(old, "STATE_DIR", tmp_path)
        monkeypatch.setattr(old, "DB_PATH", eng.DB_PATH)
        monkeypatch.setattr(old, "_now", lambda: h.t + 60)
        old.init_db()
        db = old.Db("acct")
        r = db.get_message("rb@x")
        assert r["threat"] == "lookalike" and r["our_action"] == "pending_move"
        assert old.threat_text(r["threat"], r["threat_detail"])          # 2.3.5 shows a label
        uv = h.client.folders["INBOX"].uidvalidity
        assert {x["message_id"] for x in db.due_pending_moves(uv, 60, folder="INBOX")} >= {"rb@x"}
        cfg = tmp_path / "accounts236.yml"
        cfg.write_text("defaults:\n  mode: move\n  protected_domains: [bank.dk]\n"
                       "accounts:\n  - name: bynet\n    user: ole@bynet.example\n    imap_host: imap.example.net\n"
                       "    password: x\n    protected_domains: []\n")
        assert [a.name for a in old.load_account_configs(cfg)] == ["bynet"]
        assert eng.load_account_configs(cfg)[0].protected_domains == []
        db.close()
    finally:
        sys.modules.pop("filter_head", None)
    eng.init_db()
    conn = sqlite3.connect(eng.DB_PATH)
    assert conn.execute("SELECT COUNT(*) FROM lookalike_allow").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM lookalike_watch").fetchone()[0] > 0
    conn.close()
