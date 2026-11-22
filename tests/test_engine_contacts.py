"""2.3 known contacts (B10): hashing/normalisation, the key, the sync in the
account thread (Sent detection, chunks, bookmarks, time budget, UIDVALIDITY,
STATUS every 15 min, skip rules), TH_KNOWN_CONTACT / TH_KNOWN_DOMAIN with
the auth requirement, forwarded mail, own domains, hard exceptions, the cap,
the inactive-before-sync rule and config validation."""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import sqlite3
import stat
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import make_message, setup_engine, stub_mailctx  # noqa: E402
from test_engine_scan import Harness  # noqa: E402

LOG = logging.getLogger("test-contacts")
DAY = 86400
USER = "user@example-a.dk"


@pytest.fixture
def eng(tmp_path, monkeypatch):
    e = setup_engine(tmp_path, monkeypatch)
    import contacts

    contacts.forget_cached_keys()
    yield e
    contacts.forget_cached_keys()


@pytest.fixture
def C():
    import contacts

    return contacts


# ----- helpers (also used by test_engine_reply / test_engine_history) --------


def sent_mail(mid: str, to: str | list[str], *, cc: str | None = None, bcc: str | None = None,
              irt: str | None = None, sender: str = USER, date: str = "Tue, 20 Oct 2026 10:00:00 +0200",
              name: str = "Ole") -> bytes:
    to = [to] if isinstance(to, str) else to
    lines = [f"From: {name} <{sender}>", f"To: {', '.join(to)}", "Subject: Hej", f"Date: {date}"]
    if cc:
        lines.append(f"Cc: {cc}")
    if bcc:
        lines.append(f"Bcc: {bcc}")
    if mid:
        lines.append(f"Message-ID: <{mid}>")
    if irt:
        lines.append(f"In-Reply-To: <{irt}>")
    return ("\r\n".join(lines) + "\r\n\r\nTekst\r\n").encode()


def rfc_date(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")


def sym(name, score=0.0, options=()):
    return {name: {"name": name, "score": score, "options": list(options)}}


def dkim(domain):
    return sym("R_DKIM_ALLOW", -0.2, [f"{domain}:s=sel"])


DMARC_OK = sym("DMARC_POLICY_ALLOW", -0.5, ["example"])


def run_sync(h, n=50, **kw):
    """Run contact sync slices until the first sync is complete."""
    for _ in range(n):
        h.eng.contacts_sync(h.client, h.db, LOG, h.acc, h.state)
        if not h.state.contacts_busy:
            break
    return h


def harness(eng, monkeypatch, *, folders=("INBOX", "Junk", "Trash", "Sent"), sent=(), **acc):
    """Harness with mail in Sent (list of raw bytes) synced."""
    h = Harness(eng, monkeypatch, folders=folders, **acc)
    for raw in sent:
        h.client.add("Sent", raw)
    return h


def syms_of(h, msgid):
    return {s["n"]: s for s in json.loads(h.row(msgid)["symbols"])}


def inbound(h, msgid, sender, *, score=3.0, symbols=None, extra=""):
    h.rspamd.scores[msgid] = score
    h.rspamd.symbols[msgid] = symbols if symbols is not None else {}
    h.deliver(msgid, sender=sender, extra_headers=extra)
    h.scan()
    return h.row(msgid)


# ----- normalisation, hashing, key -------------------------------------------


def test_normalize_mask_regdom(C):
    assert C.normalize_address("Alice@Kunde.DK") == "alice@kunde.dk"
    assert C.normalize_address("<bob+tilbud@firma.dk>") == "bob+tilbud@firma.dk"  # +tags kept
    puny = "æøå.dk".encode("idna").decode()
    assert puny.startswith("xn--") and C.normalize_address("jens@æøå.dk") == f"jens@{puny}"
    assert C.normalize_address("no-at-sign") is None
    assert C.normalize_address("a b@c.dk") is None
    assert C.mask("alice@kunde.dk") == "a…@kunde.dk"
    assert C.mask(f"jens@{puny}") == "j…@æøå.dk"
    assert C.regdom("mail.send.example.co.uk") == "example.co.uk"
    assert C.regdom("smtp.datamail.example") == "datamail.example"
    assert C.regdom("dk") is None and C.regdom("kunde.dk") == "kunde.dk"
    assert C.normalize_mid(" <abc@x> ") == "abc@x"


def test_hashes_are_keyed_and_domain_separated(C):
    k1, k2 = b"a" * 32, b"b" * 32
    h = C.hash_address(k1, "Alice@Kunde.dk")
    assert h == C.hash_address(k1, "alice@kunde.dk") and len(h) == 32
    assert h != C.hash_address(k2, "alice@kunde.dk")
    assert C.hash_mid(k1, "<x@y>") == C.hash_mid(k1, "x@y") != C.hash_address(k1, "x@y")
    assert C.hash_domain(k1, "kunde.dk") != C.hash_address(k1, "kunde.dk@kunde.dk")


def test_key_created_0600_and_regeneration_wipes_everything(eng, C, tmp_path):
    conn = sqlite3.connect(eng.DB_PATH, isolation_level=None)
    key = C.load_key(tmp_path, conn)
    path = tmp_path / "contacts.key"
    assert len(key) == 32 and path.read_bytes() == key
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert C.load_key(tmp_path, conn) == key  # stable
    conn.execute("INSERT INTO known_contacts(account, h, sent_count) VALUES('a', 'x', 1)")
    conn.execute("INSERT INTO sender_history(account, h, n_seen) VALUES('a', 'x', 1)")
    # Lost key (restart without the file): a new key and a full resync.
    path.unlink()
    C.forget_cached_keys()
    assert C.load_key(tmp_path, None, create=False) is None
    key2 = C.load_key(tmp_path, conn)
    assert key2 != key and stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert conn.execute("SELECT COUNT(*) FROM known_contacts").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM sender_history").fetchone()[0] == 0
    ev = conn.execute("SELECT detail FROM events WHERE event='contacts_key_regenerated'").fetchall()
    assert len(ev) == 1 and "@" not in ev[0][0]
    # A corrupt key file counts as lost.
    path.write_bytes(b"short")
    C.forget_cached_keys()
    assert C.load_key(tmp_path, None, create=False) is None
    assert len(C.load_key(tmp_path, conn)) == 32


def test_key_deleted_while_running_is_written_back(eng, C, tmp_path):
    conn = sqlite3.connect(eng.DB_PATH, isolation_level=None)
    key = C.load_key(tmp_path, conn)
    (tmp_path / "contacts.key").unlink()
    assert C.load_key(tmp_path, conn) == key
    assert (tmp_path / "contacts.key").read_bytes() == key


def test_schema_is_idempotent_and_safe_inside_a_transaction(eng, C):
    eng.init_db()
    eng.init_db()
    conn = sqlite3.connect(eng.DB_PATH, isolation_level=None)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"known_contacts", "contacts_sync", "own_identities", "sent_threads", "sender_history",
            "contacts_seen", "contact_recheck"} <= names
    conn.execute("BEGIN")
    conn.execute("INSERT INTO events(account, ts, event) VALUES('a', 1, 'x')")
    C.ensure_schema(conn)
    assert conn.in_transaction  # executescript would have committed it
    conn.execute("ROLLBACK")
    assert conn.execute("SELECT COUNT(*) FROM events WHERE event='x'").fetchone()[0] == 0


# ----- config -------------------------------------------------------------------


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
    assert acc.known_contacts is True and acc.known_contact_score == -4.0
    assert acc.sent_folders == [] and acc.contact_group is None
    assert eng.BUILTIN_DEFAULTS["known_contacts"] is True
    Path(eng.CONFIG_PATH).write_text(BASE_YML.format(
        extra="    known_contacts: false\n    known_contact_score: -3\n    sent_folders: [Sendt, 'INBOX/Sendte']\n"
              "    contact_group: Molt.example\n"))
    acc = eng.load_account_configs(eng.CONFIG_PATH)[0]
    assert (acc.known_contacts, acc.known_contact_score, acc.sent_folders, acc.contact_group) == (
        False, -3.0, ["Sendt", "INBOX/Sendte"], "molt.example")
    for bad in ("    known_contact_score: -8\n", "    known_contact_score: 1\n",
                "    known_contacts: maybe\n", "    contact_group: 'a b'\n", "    sent_folders: {a: 1}\n"):
        Path(eng.CONFIG_PATH).write_text(BASE_YML.format(extra=bad))
        with pytest.raises(eng.ConfigError):
            eng.load_account_configs(eng.CONFIG_PATH)


def test_stats_and_trust_symbol_sets(eng, C):
    assert set(C.METRICS) <= eng.STAT_METRICS
    assert C.CONTACT_SYMBOLS <= eng.TRUST_SYMBOLS
    assert "TH_FIRST_CONTACT" not in eng.TRUST_SYMBOLS


# ----- folder plan ----------------------------------------------------------------


def test_sent_detection_special_use_names_and_override(eng, monkeypatch, C):
    h = Harness(eng, monkeypatch, folders=("INBOX", "Junk", "Trash", "Elementer sendt", "INBOX.Sendt",
                                           "Kladder", "Drafts", "INBOX.Klubben", "Spamfilter",
                                           "Arkiv", "Sent Messages"))
    h.client.folders["Elementer sendt"].flags = ("\\HasNoChildren", "\\Sent")
    eng._on_connected(h.client, h.db, LOG, h.acc, h.state)
    plan = C.plan_folders(h.client, h.acc, h.acc.folder_map, h.state)
    assert plan.sent == ["Elementer sendt", "INBOX.Sendt", "Sent Messages"]
    assert plan.history[0] == "INBOX"
    assert set(plan.history) == {"INBOX", "INBOX.Klubben", "Arkiv"}  # no Junk/Trash/Drafts/Spamfilter
    h.acc.sent_folders = ["INBOX/Sendt"]
    plan = C.plan_folders(h.client, h.acc, h.acc.folder_map, h.state)
    assert plan.sent == ["INBOX.Sendt"]
    assert "Elementer sendt" not in plan.history and "Sent Messages" not in plan.history


# ----- sync ------------------------------------------------------------------------


def test_sent_sync_builds_contacts_threads_and_identities(eng, monkeypatch, C):
    h = harness(eng, monkeypatch, sent=[
        sent_mail("s1@example-a.dk", "Alice <alice@kunde.dk>"),
        sent_mail("s2@example-a.dk", ["alice@kunde.dk", "noreply@shop.dk"], cc="bob@firma.dk"),
        sent_mail("s3@example-a.dk", USER),                      # to myself
        sent_mail("s4@example-a.dk", "x@us1.list-manage.com", bcc="news-unsubscribe@firma.dk"),
    ])
    writes_before = list(h.client.writes)
    run_sync(h)
    assert h.client.writes == writes_before  # strictly read-only
    rows = {r["mask"]: r for r in h.db.conn.execute("SELECT * FROM known_contacts")}
    assert set(rows) == {"a…@kunde.dk", "b…@firma.dk"}
    assert rows["a…@kunde.dk"]["sent_count"] == 2 and rows["b…@firma.dk"]["sent_count"] == 1
    assert all(r["status"] == "active" and r["source"] == "sent" for r in rows.values())
    assert h.db.conn.execute("SELECT COUNT(*) FROM sent_threads").fetchone()[0] == 4
    ident = h.db.conn.execute("SELECT addr, display_name, n FROM own_identities").fetchall()
    assert [tuple(r) for r in ident] == [(USER, "Ole", 4)]
    assert C.sync_complete(h.db.conn, "acct")
    ev = h.events("contacts_sync_complete")
    assert len(ev) == 1 and "kontakter=2" in ev[0][2] and "@" not in ev[0][2]
    # Fetches were header-only (BODY.PEEK[HEADER.FIELDS ...]) and EXAMINE only.
    for call in h.client.calls:
        if call[0] == "select_folder" and call[1] == "Sent":
            assert call[2] is True
        if call[0] == "fetch":
            assert all(b"BODY[]" not in it and b"BODY.PEEK[]" not in it for it in call[2])


def test_chunks_bookmarks_and_time_budget(eng, monkeypatch, C):
    monkeypatch.setattr(C, "FETCH_CHUNK", 2)
    h = harness(eng, monkeypatch, sent=[sent_mail(f"s{i}@x", f"p{i}@kunde.dk") for i in range(5)])
    for i in range(3):
        h.client.add("INBOX", make_message(f"old{i}@x", sender=f"o{i}@old.dk"))
    h.scan()  # inbox bookmark now covers the 3 mails (bootstrap target)
    calls = []
    real = C.sync_step

    def step(*a, **kw):
        kw["budget_s"] = 0.0  # exactly one chunk per slice
        calls.append(1)
        return real(*a, **kw)

    monkeypatch.setattr(C, "sync_step", step)
    eng.contacts_sync(h.client, h.db, LOG, h.acc, h.state)
    assert h.state.contacts_busy
    row = h.db.conn.execute("SELECT max_uid, complete FROM contacts_sync WHERE folder='Sent'").fetchone()
    assert tuple(row) == (2, 0)  # resumable bookmark after the first chunk
    assert eng._next_wake_in(h.db, h.acc, h.state) == eng.MIN_LOOP_WAIT_S  # back after one IDLE slice
    assert not C.sync_complete(h.db.conn, "acct")
    run_sync(h)
    assert C.sync_complete(h.db.conn, "acct") and not h.state.contacts_busy
    assert len(calls) == 6  # 3 Sent chunks + 2 INBOX chunks + the final slice
    assert h.db.conn.execute("SELECT COUNT(*) FROM known_contacts").fetchone()[0] == 5
    assert h.db.conn.execute("SELECT SUM(n_kept) FROM sender_history").fetchone()[0] == 3


def test_time_budget_stops_between_chunks(eng, monkeypatch, C):
    monkeypatch.setattr(C, "FETCH_CHUNK", 1)
    h = harness(eng, monkeypatch, sent=[sent_mail(f"s{i}@x", f"p{i}@kunde.dk") for i in range(4)])
    clock = {"t": 0.0}

    def mono():
        clock["t"] += 1.0
        return clock["t"]

    monkeypatch.setattr(C, "_mono", mono)
    eng.contacts_sync(h.client, h.db, LOG, h.acc, h.state)
    done = h.db.conn.execute("SELECT max_uid FROM contacts_sync WHERE folder='Sent'").fetchone()[0]
    assert 1 <= done < 4 and h.state.contacts_busy


def test_uidvalidity_change_resyncs_the_folder_without_double_counting(eng, monkeypatch, C):
    h = harness(eng, monkeypatch, sent=[sent_mail("s1@x", "alice@kunde.dk")])
    run_sync(h)
    h.client.folders["Sent"].uidvalidity = 77777
    h.client.add("Sent", sent_mail("s2@x", "alice@kunde.dk"))
    h.state.contacts_next_status = 0.0
    eng.contacts_sync(h.client, h.db, LOG, h.acc, h.state)
    assert h.events("contacts_uidvalidity")
    r = h.db.conn.execute("SELECT sent_count FROM known_contacts").fetchone()
    assert r[0] == 2  # s1 again is a duplicate (sent_threads), s2 is new
    assert h.db.conn.execute("SELECT uidvalidity FROM contacts_sync WHERE folder='Sent'").fetchone()[0] == 77777


def test_incremental_status_every_15_minutes_and_on_request(eng, monkeypatch, C):
    h = harness(eng, monkeypatch, sent=[sent_mail("s1@x", "alice@kunde.dk")])
    run_sync(h)
    h.client.add("Sent", sent_mail("s2@x", "carl@ny.dk"))
    n_status = sum(1 for c in h.client.calls if c[0] == "folder_status" and c[1] == "Sent")
    eng.contacts_sync(h.client, h.db, LOG, h.acc, h.state)  # within 15 min: nothing
    assert sum(1 for c in h.client.calls if c[0] == "folder_status" and c[1] == "Sent") == n_status
    assert h.db.conn.execute("SELECT COUNT(*) FROM known_contacts").fetchone()[0] == 1
    wait = eng._next_wake_in(h.db, h.acc, h.state)
    assert eng.MIN_LOOP_WAIT_S <= wait <= C.STATUS_INTERVAL_S + 1
    # 'Opdater nu' (services) sets a token; the next slice runs STATUS at once.
    eng.engine_state_set(h.db.conn, C.REQUEST_STATE + "acct", "123:abc")
    eng.contacts_sync(h.client, h.db, LOG, h.acc, h.state)
    assert h.db.conn.execute("SELECT COUNT(*) FROM known_contacts").fetchone()[0] == 2
    h.client.add("Sent", sent_mail("s3@x", "dora@ny.dk"))
    eng.contacts_sync(h.client, h.db, LOG, h.acc, h.state)  # same token: not again
    assert h.db.conn.execute("SELECT COUNT(*) FROM known_contacts").fetchone()[0] == 2
    h.state.contacts_next_status = 0.0  # 15 min later
    eng.contacts_sync(h.client, h.db, LOG, h.acc, h.state)
    assert h.db.conn.execute("SELECT COUNT(*) FROM known_contacts").fetchone()[0] == 3


def test_skip_rules_reply_to_spam_and_own_identities(eng, monkeypatch, C):
    h = harness(eng, monkeypatch, sent=[
        sent_mail("s1@x", "spammer@bad.example", irt="spam1@bad.example"),
        *[sent_mail(f"a{i}@x", "kunde@kunde.dk", sender="ole@bynet.example") for i in range(3)],
        sent_mail("s5@x", "ole@bynet.example"),  # an own alias (identity used 3 times)
        sent_mail("s6@x", "bounces+123@mailer.example"),
    ])
    h.db.upsert_message("spam1@bad.example", "Junk", "spammer@bad.example", "x")
    h.db.update_message("spam1@bad.example", our_action="moved_to_junk")
    run_sync(h)
    masks = {r[0] for r in h.db.conn.execute("SELECT mask FROM known_contacts")}
    assert masks == {"k…@kunde.dk"}
    key = eng._contacts_key(h.db)
    assert h.db.conn.execute("SELECT 1 FROM sent_threads WHERE mid_h=?",
                             (C.hash_mid(key, "s1@x"),)).fetchone() is None


def test_sync_runs_in_shadow_mode_without_writes(eng, monkeypatch, C):
    h = harness(eng, monkeypatch, mode="shadow", sent=[sent_mail("s1@x", "alice@kunde.dk")])
    run_sync(h)
    assert C.sync_complete(h.db.conn, "acct") and h.client.writes == []


def test_disabled_account_never_syncs(eng, monkeypatch, C):
    h = harness(eng, monkeypatch, known_contacts=False, sent=[sent_mail("s1@x", "alice@kunde.dk")])
    run_sync(h)
    assert not any(c[0] == "select_folder" and c[1] == "Sent" for c in h.client.calls)
    assert not (Path(eng.STATE_DIR) / "contacts.key").exists()


def test_loop_once_runs_the_sync(eng, monkeypatch, C):
    h = harness(eng, monkeypatch, sent=[sent_mail("s1@x", "alice@kunde.dk")])
    h.loop()
    assert C.sync_complete(h.db.conn, "acct")


def test_sync_error_never_breaks_the_loop(eng, monkeypatch, C):
    h = harness(eng, monkeypatch, sent=[sent_mail("s1@x", "alice@kunde.dk")])

    def boom(*a, **k):
        raise ValueError("bug")

    monkeypatch.setattr(C, "sync_step", boom)
    h.loop()  # no exception
    assert not h.state.contacts_busy
    # ... and no tight retry loop: the next attempt follows the STATUS rhythm.
    assert h.state.contacts_next_status > time.monotonic() + 60
    assert eng._next_wake_in(h.db, h.acc, h.state) > eng.MIN_LOOP_WAIT_S


def test_busy_database_retries_within_a_minute(eng, monkeypatch, C):
    """A locked database (another writer at start-up) is transient: retry in
    about a minute instead of waiting for the 15-minute STATUS rhythm."""
    import sqlite3
    h = harness(eng, monkeypatch, sent=[sent_mail("s1@x", "alice@kunde.dk")])

    def busy(*a, **k):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(C, "sync_step", busy)
    t0 = time.monotonic()
    h.loop()
    assert not h.state.contacts_busy
    assert t0 + 30 < h.state.contacts_next_status <= time.monotonic() + eng.CONTACTS_BUSY_RETRY_S + 1
    assert eng._next_wake_in(h.db, h.acc, h.state) <= eng.CONTACTS_BUSY_RETRY_S + 1


def test_db_transactions_take_the_write_lock_up_front(eng):
    """BEGIN IMMEDIATE: a read-then-write transaction waits for busy_timeout
    instead of failing at once with 'database is locked' (WAL snapshot)."""
    import inspect
    assert 'BEGIN IMMEDIATE' in inspect.getsource(eng.Db.tx)


# ----- TH_KNOWN_CONTACT -------------------------------------------------------------


def synced(eng, monkeypatch, sent, **acc):
    h = harness(eng, monkeypatch, sent=sent, **acc)
    run_sync(h)
    return h


def test_known_contact_bonus_with_dmarc_or_aligned_dkim(eng, monkeypatch, C):
    h = synced(eng, monkeypatch, [sent_mail("s1@x", "alice@kunde.dk"), sent_mail("s2@x", "alice@kunde.dk")])
    r = inbound(h, "in1@x", "alice@kunde.dk", score=9.0, symbols=DMARC_OK)
    kc = syms_of(h, "in1@x")["TH_KNOWN_CONTACT"]
    assert kc["s"] == -4.0 and kc["o"][:2] == ["a…@kunde.dk", "sendt=2"] and kc["o"][2].startswith("senest=")
    assert r["our_score"] == pytest.approx(5.0) and r["our_action"] == "none"
    assert h.stat("known_contact") == 1
    inbound(h, "in2@x", "alice@kunde.dk", symbols=dkim("kunde.dk"))
    assert "TH_KNOWN_CONTACT" in syms_of(h, "in2@x")
    # No authentication: a forged From of a contact gets nothing.
    r = inbound(h, "in3@x", "alice@kunde.dk", score=9.0, symbols={})
    assert "TH_KNOWN_CONTACT" not in syms_of(h, "in3@x") and r["our_action"] == "pending_move"
    # DKIM of another domain is not aligned.
    inbound(h, "in4@x", "alice@kunde.dk", symbols=dkim("mailer.example"))
    assert "TH_KNOWN_CONTACT" not in syms_of(h, "in4@x")
    # Only exactly one From address.
    inbound(h, "in5@x", "alice@kunde.dk", symbols=DMARC_OK)
    assert h.stat("known_contact") == 3


def test_known_contact_score_by_age_and_list_mail(eng, monkeypatch, C):
    now = eng._now()
    h = synced(eng, monkeypatch, [
        sent_mail("s1@x", "recent@kunde.dk", date=rfc_date(now - 30 * DAY)),
        sent_mail("s2@x", "three@kunde.dk", date=rfc_date(now - 3 * 365 * DAY)),
        sent_mail("s3@x", "old@kunde.dk", date=rfc_date(now - 6 * 365 * DAY)),
    ])
    for mid, who, want in (("a@x", "recent@kunde.dk", -4.0), ("b@x", "three@kunde.dk", -3.0),
                           ("c@x", "old@kunde.dk", -2.0)):
        inbound(h, mid, who, symbols=DMARC_OK)
        assert syms_of(h, mid)["TH_KNOWN_CONTACT"]["s"] == want
    inbound(h, "d@x", "recent@kunde.dk", symbols=DMARC_OK, extra="List-Id: <liste.kunde.dk>")
    assert syms_of(h, "d@x")["TH_KNOWN_CONTACT"]["s"] == -2.0
    h.acc.known_contact_score = -5.0
    inbound(h, "e@x", "recent@kunde.dk", symbols=DMARC_OK)
    assert syms_of(h, "e@x")["TH_KNOWN_CONTACT"]["s"] == -5.0


def forwarded_mailctx():
    base = stub_mailctx()
    orig = base.scan_context

    def scan_context(raw, acc):
        ctx = orig(raw, acc)
        ctx["forwarded"] = True
        return ctx

    base.scan_context = scan_context
    return base


def test_forwarded_mail_needs_aligned_dkim(tmp_path, monkeypatch, C):
    eng = setup_engine(tmp_path, monkeypatch, mailctx=forwarded_mailctx())
    C.forget_cached_keys()
    h = synced(eng, monkeypatch, [sent_mail("s1@x", "alice@kunde.dk")])
    inbound(h, "f1@x", "alice@kunde.dk", symbols=DMARC_OK)
    assert "TH_KNOWN_CONTACT" not in syms_of(h, "f1@x")
    inbound(h, "f2@x", "alice@kunde.dk", symbols={**DMARC_OK, **dkim("kunde.dk")})
    assert "TH_KNOWN_CONTACT" in syms_of(h, "f2@x")


def test_own_domain_needs_aligned_dkim(eng, monkeypatch, C):
    h = synced(eng, monkeypatch, [sent_mail("s1@x", "kollega@example-a.dk")])
    inbound(h, "o1@x", "kollega@example-a.dk", symbols=DMARC_OK)
    assert "TH_KNOWN_CONTACT" not in syms_of(h, "o1@x")
    inbound(h, "o2@x", "kollega@example-a.dk", symbols=dkim("example-a.dk"))
    assert "TH_KNOWN_CONTACT" in syms_of(h, "o2@x")


@pytest.mark.parametrize("hard", ["TH_BRAND_SPOOF", "TH_FROM_NAME_HOMOGLYPH", "DBL_PHISH", "DBL_SPAM",
                                  "DBL_MALWARE", "URIBL_BLACK", "PHISHED_OPENPHISH", "CLAM_VIRUS",
                                  "MIME_BAD_EXTENSION", "MIME_DOUBLE_BAD_EXTENSION", "FUZZY_DENIED",
                                  "R_SPF_FAIL", "DMARC_POLICY_QUARANTINE", "TH_PROVIDER_AUTH_FAIL"])
def test_hard_exceptions_never_get_a_bonus(eng, monkeypatch, C, hard):
    h = synced(eng, monkeypatch, [sent_mail("s1@x", "alice@kunde.dk")])
    inbound(h, "h@x", "alice@kunde.dk", symbols={**dkim("kunde.dk"), **sym(hard, 3.0)})
    assert "TH_KNOWN_CONTACT" not in syms_of(h, "h@x")


def test_provider_spam_flag_is_a_hard_exception(tmp_path, monkeypatch, C):
    eng = setup_engine(tmp_path, monkeypatch, mailctx=stub_mailctx(provider_flag=True))
    C.forget_cached_keys()
    h = synced(eng, monkeypatch, [sent_mail("s1@x", "alice@kunde.dk")])
    inbound(h, "p@x", "alice@kunde.dk", symbols=dkim("kunde.dk"))
    assert "TH_KNOWN_CONTACT" not in syms_of(h, "p@x")


def test_trust_blocked_helper(C):
    assert C.trust_blocked({"PHISHED_EXCLUDED", "CLAM_VIRUS_FAIL", "BAYES_HAM"}) is None
    assert C.trust_blocked({"PHISHED_PHISHTANK"}) == "PHISHED_PHISHTANK"
    assert C.trust_blocked(set(), threat="phish") == "threat:phish"
    assert C.trust_blocked({"R_SPF_SOFTFAIL"}, distrust={"R_SPF_SOFTFAIL"}) == "R_SPF_SOFTFAIL"


def test_block_rule_always_wins(eng, monkeypatch, C):
    h = synced(eng, monkeypatch, [sent_mail("s1@x", "alice@kunde.dk")])
    eng.add_sender_rule(h.db.conn, "acct", "alice@kunde.dk", "block", "", "test")
    r = inbound(h, "b@x", "alice@kunde.dk", score=1.0, symbols=DMARC_OK)
    assert "TH_KNOWN_CONTACT" not in syms_of(h, "b@x") and r["our_action"] == "pending_move"


def test_inactive_until_the_first_sync_is_complete(eng, monkeypatch, C):
    h = harness(eng, monkeypatch, sent=[sent_mail("s1@x", "alice@kunde.dk")])
    key = eng._contacts_key(h.db)
    h.db.conn.execute("INSERT INTO known_contacts(account, h, domain, mask, sent_count, last_sent_at) "
                      "VALUES('acct', ?, 'kunde.dk', 'a…@kunde.dk', 5, ?)",
                      (C.hash_address(key, "alice@kunde.dk"), int(eng._now())))
    inbound(h, "i1@x", "alice@kunde.dk", symbols=DMARC_OK)
    names = set(syms_of(h, "i1@x"))
    assert not names & {"TH_KNOWN_CONTACT", "TH_FIRST_CONTACT", "TH_ESTABLISHED"}
    run_sync(h)
    inbound(h, "i2@x", "alice@kunde.dk", symbols=DMARC_OK)
    assert "TH_KNOWN_CONTACT" in syms_of(h, "i2@x")


def test_removed_contact_gets_nothing_and_survives_resync(eng, monkeypatch, C):
    h = synced(eng, monkeypatch, [sent_mail("s1@x", "alice@kunde.dk")])
    key = eng._contacts_key(h.db)
    hh = C.hash_address(key, "alice@kunde.dk")
    with h.db.tx():
        C.set_status(h.db.conn, "acct", hh, "removed", "admin")
    h.client.add("Sent", sent_mail("s2@x", "alice@kunde.dk"))
    h.state.contacts_next_status = 0.0
    eng.contacts_sync(h.client, h.db, LOG, h.acc, h.state)
    row = h.db.conn.execute("SELECT status, sent_count FROM known_contacts WHERE h=?", (hh,)).fetchone()
    assert tuple(row) == ("removed", 2)
    inbound(h, "r@x", "alice@kunde.dk", symbols=DMARC_OK)
    assert "TH_KNOWN_CONTACT" not in syms_of(h, "r@x")


def test_known_domain_bonus(eng, monkeypatch, C):
    h = synced(eng, monkeypatch, [sent_mail("s1@x", "a@firma.dk"), sent_mail("s2@x", "b@firma.dk"),
                                  sent_mail("s3@x", "a@gmail.com"), sent_mail("s4@x", "b@gmail.com")])
    inbound(h, "d1@x", "c@firma.dk", symbols=dkim("firma.dk"))
    kd = syms_of(h, "d1@x")["TH_KNOWN_DOMAIN"]
    assert kd["s"] == -1.0 and kd["o"] == ["firma.dk", "kendte=2"]
    inbound(h, "d2@x", "c@firma.dk", symbols=DMARC_OK)  # needs aligned DKIM
    assert "TH_KNOWN_DOMAIN" not in syms_of(h, "d2@x")
    inbound(h, "d3@x", "c@gmail.com", symbols=dkim("gmail.com"))  # freemail
    assert "TH_KNOWN_DOMAIN" not in syms_of(h, "d3@x")
    inbound(h, "d4@x", "a@firma.dk", symbols=dkim("firma.dk"))  # a contact: KC wins
    assert set(syms_of(h, "d4@x")) & {"TH_KNOWN_DOMAIN", "TH_KNOWN_CONTACT"} == {"TH_KNOWN_CONTACT"}


def test_contact_of_a_colleague_mailbox_in_the_same_group(eng, monkeypatch, C):
    h = synced(eng, monkeypatch, [sent_mail("s1@x", "noget@andet.dk")], contact_group="molt.example")
    key = eng._contacts_key(h.db)
    hh = C.hash_address(key, "kunde@kunde.dk")
    for acc, grp in (("molt", "molt.example"), ("bynet", "bynet.example")):
        h.db.conn.execute("INSERT INTO contacts_sync(account, folder, kind, complete, grp) "
                          "VALUES(?, '*', 'account', 1, ?)", (acc, grp))
    h.db.conn.execute("INSERT INTO known_contacts(account, h, domain, mask, sent_count, last_sent_at) "
                      "VALUES('molt', ?, 'kunde.dk', 'k…@kunde.dk', 4, ?)", (hh, int(eng._now())))
    inbound(h, "g1@x", "kunde@kunde.dk", symbols=DMARC_OK)
    kc = syms_of(h, "g1@x")["TH_KNOWN_CONTACT"]
    # No colleague count in the options (review: Brugere must not learn how often
    # other mailboxes in the group wrote to the sender).
    assert kc["s"] == -3.0 and kc["o"] == ["k…@kunde.dk", "gruppe"]
    h.acc.contact_group = "andet"
    inbound(h, "g2@x", "kunde@kunde.dk", symbols=DMARC_OK)
    assert "TH_KNOWN_CONTACT" not in syms_of(h, "g2@x")


def test_cap_minus_six_with_newsletter(eng, monkeypatch, C):
    h = synced(eng, monkeypatch, [sent_mail("s1@x", "alice@kunde.dk")])
    key = eng._contacts_key(h.db)
    h.db.conn.execute("UPDATE known_contacts SET sent_count=3")
    raw = make_message("cap@x", sender="alice@kunde.dk")
    h.acc.known_contact_score = -6.0
    t = C.evaluate(h.db.conn, h.acc, key, raw=raw, ctx={}, names={"DMARC_POLICY_ALLOW", "TH_NEWSLETTER"},
                   dkim_domains=[], final=5.0, threshold=8.0, newsletter=-1.5, now=int(eng._now()))
    kc = [s for s in t.symbols if s["n"] == "TH_KNOWN_CONTACT"][0]
    assert kc["s"] == -4.5 and "loft -6" in kc["o"] and t.delta == -4.5
    t = C.evaluate(h.db.conn, h.acc, key, raw=raw, ctx={}, names={"DMARC_POLICY_ALLOW"},
                   dkim_domains=[], final=5.0, threshold=8.0, newsletter=0.0, now=int(eng._now()))
    assert t.delta == -6.0


def test_contact_trust_symbols_for_calibration_is_read_only(eng, monkeypatch, C):
    h = synced(eng, monkeypatch, [sent_mail("s1@x", "alice@kunde.dk")])
    raw = make_message("cal@x", sender="alice@kunde.dk")
    res = eng.ScanResult(score=3.0, action=None, symbols=[], names=frozenset({"DMARC_POLICY_ALLOW"}))
    before = h.db.conn.execute("SELECT COUNT(*) FROM sender_history").fetchone()[0]
    syms = eng.contact_trust_symbols(h.db.conn, h.acc, raw, {}, res, 3.0)
    assert [s["n"] for s in syms] == ["TH_KNOWN_CONTACT"]
    assert h.db.conn.execute("SELECT COUNT(*) FROM sender_history").fetchone()[0] == before
    h.acc.known_contacts = False
    assert eng.contact_trust_symbols(h.db.conn, h.acc, raw, {}, res, 3.0) == []


def test_no_full_contact_address_in_logs_or_events(eng, monkeypatch, C, caplog):
    caplog.set_level(logging.DEBUG)
    h = synced(eng, monkeypatch, [sent_mail("s1@x", "alice.hemmelig@kunde.dk")])
    inbound(h, "l@x", "alice.hemmelig@kunde.dk", symbols=DMARC_OK)
    assert "alice.hemmelig@kunde.dk" not in caplog.text
    for ev in h.db.conn.execute("SELECT detail FROM events WHERE event LIKE 'contact%'"):
        assert "alice.hemmelig" not in (ev[0] or "")
    sy = h.row("l@x")["symbols"]
    assert "alice.hemmelig" not in sy and "a…@kunde.dk" in sy
