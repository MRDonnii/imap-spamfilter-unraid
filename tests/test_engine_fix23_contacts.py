"""2.3 fixer: contact-signal regressions from the review.

- 'Fjern' (removed) / a spam verdict (demoted) takes away every trust
  bonus for the sender (also TH_ESTABLISHED and TH_KNOWN_DOMAIN);
- calibration trust honours the pseudo-symbol hard exceptions like the
  live scan (TH_PROVIDER_SPAM blocks TH_KNOWN_CONTACT);
- a UIDVALIDITY change found by the freshness sync aborts the scan
  instead of continuing on stale UIDs.
"""

from __future__ import annotations

import json

import pytest
from fakes_engine import make_message, setup_engine, stub_mailctx
from test_engine_contacts import C, DAY, DMARC_OK, dkim, eng, inbound, sent_mail, synced, syms_of  # noqa: F401
from test_engine_reply import irt


def _established(h, hh, *, dom="kunde.dk"):
    with h.db.tx():
        h.db.conn.execute(
            "INSERT OR REPLACE INTO sender_history(account,h,regdom,first_seen,last_seen,n_kept,n_seen,n_junk,fp) "
            "VALUES('acct',?,?,?,?,3,3,0,?)",
            (hh, dom, int(h.t) - 40 * DAY, int(h.t) - DAY, json.dumps({"env": [], "dkim": [dom], "asn": []})))


@pytest.mark.parametrize("status", ["removed", "demoted"])
def test_removed_contact_loses_every_trust_bonus(eng, monkeypatch, C, status):  # noqa: F811
    h = synced(eng, monkeypatch, [sent_mail("s1@x", "alice@kunde.dk"), sent_mail("s2@x", "bob@kunde.dk"),
                                  sent_mail("s3@x", "carl@kunde.dk")])
    key = eng._contacts_key(h.db)
    hh = C.hash_address(key, "alice@kunde.dk")
    _established(h, hh)
    inbound(h, "a1@x", "alice@kunde.dk", score=9.0, symbols=dkim("kunde.dk"))
    assert "TH_KNOWN_CONTACT" in syms_of(h, "a1@x")
    with h.db.tx():
        C.set_status(h.db.conn, "acct", hh, status, "admin")
    inbound(h, "a2@x", "alice@kunde.dk", score=9.0, symbols=dkim("kunde.dk"))
    after = set(syms_of(h, "a2@x"))
    assert not after & {"TH_ESTABLISHED", "TH_KNOWN_DOMAIN", "TH_KNOWN_CONTACT", "TH_FIRST_CONTACT"}
    # 'Gendan' brings the contact back.
    with h.db.tx():
        C.set_status(h.db.conn, "acct", hh, "active", "admin")
    inbound(h, "a3@x", "alice@kunde.dk", score=9.0, symbols=dkim("kunde.dk"))
    assert "TH_KNOWN_CONTACT" in syms_of(h, "a3@x")


def test_calibration_trust_honours_provider_spam(tmp_path, monkeypatch):
    import contacts
    import trainer
    contacts.forget_cached_keys()
    mc = stub_mailctx(provider_flag=True)
    eng2 = setup_engine(tmp_path, monkeypatch, mailctx=mc)
    h = synced(eng2, monkeypatch, [sent_mail("s1@x", "alice@kunde.dk")])
    inbound(h, "p@x", "alice@kunde.dk", symbols=dkim("kunde.dk"))
    live = syms_of(h, "p@x")
    assert "TH_KNOWN_CONTACT" not in live and "TH_PROVIDER_SPAM" in live
    raw = make_message("p2@x", sender="alice@kunde.dk")
    ctx = mc.scan_context(raw, h.acc)
    h.rspamd.symbols["p2@x"] = dkim("kunde.dk")
    h.rspamd.scores["p2@x"] = 3.0
    _result, all_syms, _final, _aged = trainer.scan_scored(eng2, h.acc, raw, ctx, None, h.db.conn)
    names = [s["n"] for s in all_syms]
    assert "TH_PROVIDER_SPAM" in names and "TH_KNOWN_CONTACT" not in names


def test_calibration_trust_still_works_without_exceptions(tmp_path, monkeypatch):
    import contacts
    import trainer
    contacts.forget_cached_keys()
    mc = stub_mailctx(provider_flag=False)
    eng2 = setup_engine(tmp_path, monkeypatch, mailctx=mc)
    h = synced(eng2, monkeypatch, [sent_mail("s1@x", "alice@kunde.dk")])
    raw = make_message("p3@x", sender="alice@kunde.dk")
    ctx = mc.scan_context(raw, h.acc)
    h.rspamd.symbols["p3@x"] = dkim("kunde.dk")
    h.rspamd.scores["p3@x"] = 3.0
    _result, all_syms, _final, _aged = trainer.scan_scored(eng2, h.acc, raw, ctx, None, h.db.conn)
    assert "TH_KNOWN_CONTACT" in [s["n"] for s in all_syms]


def test_uidvalidity_change_in_the_freshness_sync_aborts_the_scan(eng, monkeypatch, C):  # noqa: F811
    h = synced(eng, monkeypatch, [sent_mail("old@example-a.dk", "a@b.dk")], mode="flag")
    h.client.add("Sent", sent_mail("offer@example-a.dk", "ny.kunde@kunde.dk"))
    h.rspamd.scores["re6@x"] = 12.0
    h.rspamd.symbols["re6@x"] = DMARC_OK
    h.deliver("re6@x", sender="ny.kunde@kunde.dk", extra_headers=irt("offer@example-a.dk"))
    h.deliver("spam@x", score=12.0, sender="x@spam.example")
    real = eng.select_with_uidvalidity_check
    flag = {"on": False}
    real_inc = C.incremental_sent

    def inc(*a, **k):
        flag["on"] = True
        return real_inc(*a, **k)

    def changed(client, db, folder, log, readonly=False):
        uv = real(client, db, folder, log, readonly=readonly)
        return uv + 1 if folder == "INBOX" and flag["on"] else uv

    monkeypatch.setattr(C, "incremental_sent", inc)
    monkeypatch.setattr(eng, "select_with_uidvalidity_check", changed)
    with pytest.raises(eng.IMAPClientAbortError):
        h.scan()
    # Nothing was flagged on a UID of the old UIDVALIDITY.
    assert not [w for w in h.client.writes if w[0] == "add_flags"]
