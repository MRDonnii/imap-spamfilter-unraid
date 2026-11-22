"""Owner request (2.3): for Gigahost mailboxes a provider spam flag alone is
no evidence for a Bayes repair (Gigahost flags real invoices as spam) -
services.bayes_repair_candidates needs another reason there."""

from __future__ import annotations

import time

from test_services import _calib, _learned_ham  # noqa: E402

import services  # noqa: E402
from fakes_services import FakeEngine, make_account  # noqa: E402


def _eng(tmp_path):
    return FakeEngine(tmp_path, accounts=[
        make_account(name="bynet", imap_host="imap.gigahost.dk"),
        make_account(name="molt", imap_host="mail.scannet.dk")])


def test_gigahost_provider_flag_alone_is_not_evidence(tmp_path):
    eng = _eng(tmp_path)
    # Gigahost: a real invoice the provider flagged, learned as ham.
    _learned_ham(eng, "faktura@x", account="bynet")
    _calib(eng, "faktura@x", [{"n": "TH_PROVIDER_SPAM", "s": 4.0}], provider_flag=1, account="bynet")
    # Gigahost with another reason: still a candidate (both reasons listed).
    _learned_ham(eng, "phish@x", account="bynet")
    _calib(eng, "phish@x", [{"n": "TH_PROVIDER_SPAM", "s": 4.0}, {"n": "TH_BRAND_SPOOF", "s": 5.0}],
           provider_flag=1, account="bynet")
    # Scannet: the provider flag alone still counts.
    _learned_ham(eng, "prov@x", account="molt")
    _calib(eng, "prov@x", [{"n": "TH_PROVIDER_SPAM", "s": 4.0}], provider_flag=1, account="molt")
    res = services.bayes_repair_candidates(engine=eng)
    by = {(i["account"], i["message_id"]): i for i in res["items"]}
    assert ("bynet", "faktura@x") not in by
    assert by[("bynet", "phish@x")]["reasons"] == ["phishing_rule", "provider_spam"]
    assert by[("molt", "prov@x")]["reasons"] == ["provider_spam"]
    assert res["counts"]["provider_only_skipped"] == 1
    assert services.bayes_repair_candidates("bynet", engine=eng)["total"] == 1


def test_gigahost_user_verdict_plus_provider_flag_is_evidence(tmp_path):
    eng = _eng(tmp_path)
    now = int(time.time())
    with eng.db() as conn:
        conn.execute("INSERT INTO messages(account, message_id, first_seen, last_seen, current_folder, "
                     "our_action, user_verdict, provider_flag, learned_as, learned_at) "
                     "VALUES('bynet','drag@x',?,?,'Spamfilter','user_junked','spam',1,'ham',?)", (now, now, now))
    res = services.bayes_repair_candidates(engine=eng)
    assert [i["reasons"] for i in res["items"]] == [["user_marked_spam", "provider_spam"]]


def test_unreadable_config_fails_toward_fewer_suggestions(tmp_path):
    eng = _eng(tmp_path)
    _learned_ham(eng, "prov@x", account="molt")
    _calib(eng, "prov@x", [{"n": "TH_PROVIDER_SPAM", "s": 4.0}], provider_flag=1, account="molt")
    eng.config_error = ValueError("broken")
    res = services.bayes_repair_candidates(engine=eng)
    assert res["ok"] and res["total"] == 0 and res["counts"]["provider_only_skipped"] == 1
