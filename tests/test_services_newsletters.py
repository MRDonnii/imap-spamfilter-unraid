"""2.6 A4: 'Tilbage til indbakken' (services.newsletter_to_inbox), the
keep-in-inbox list and 'Flyt til spam' out of the newsletter folder -
against the REAL engine loop on the RFC-accurate EngineMailbox, for
Gigahost (UIDPLUS, no MOVE) and Scannet (MOVE)."""

from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "filter"))

import services  # noqa: E402
from fakes_services import make_message  # noqa: E402
from test_services import GIGA, SCAN, live, live_account, live_loop, live_row  # noqa: E402,F401

UNSUB = "List-Unsubscribe: <https://click.example.com/u/1>"


def news(live, h, msgid, *, sender="news@brand.example", subject="Ugens tilbud", score=1.0):
    live.rspamd.scores[msgid] = score
    when = dt.datetime.fromtimestamp(live.clock.t, dt.timezone.utc)
    return h.box.add("INBOX", make_message(msgid, subject=subject, sender=sender, extra=UNSUB), internaldate=when)


def moved_newsletter(live, h, msgid="n1@x", **kw):
    news(live, h, msgid, **kw)
    live_loop(live, h)
    live.clock.t += 61
    live_loop(live, h)
    assert h.box.msgids("Nyhedsbreve") == [msgid]
    assert live_row(h, msgid)["our_action"] == "newsletter_moved"


@pytest.mark.parametrize("caps", [GIGA, SCAN], ids=["gigahost", "scannet"])
def test_back_to_inbox_keeps_sender_and_engine_leaves_it(live, caps):
    h = live_account(live, caps, newsletters="on")
    moved_newsletter(live, h)
    res = services.newsletter_to_inbox("anna", "<n1@x>", "admin", engine=live.eng)
    assert res["ok"] is True and res["sender_kept"] == "news@brand.example"
    assert "bliver i indbakken fremover" in res["text"]
    assert h.box.msgids("INBOX") == ["n1@x"] and h.box.msgids("Nyhedsbreve") == []
    r = live_row(h, "n1@x")
    assert r["our_action"] == "newsletter_kept" and r["current_folder"] == "INBOX"
    assert r["user_verdict"] is None and r["learned_as"] is None and r["pending_learn"] is None
    for _ in range(3):
        live.clock.t += 120
        live_loop(live, h)
    assert h.box.msgids("INBOX") == ["n1@x"]
    assert live_row(h, "n1@x")["our_action"] == "newsletter_kept"
    # The next issue from the same sender stays in the inbox too.
    news(live, h, "n2@x", subject="Nye tilbud")
    live_loop(live, h)
    live.clock.t += 61
    live_loop(live, h)
    assert sorted(h.box.msgids("INBOX")) == ["n1@x", "n2@x"]
    assert live.rspamd.learn_calls == []


def test_back_to_inbox_refuses_mail_the_filter_did_not_move(live):
    h = live_account(live, SCAN, newsletters="on", extra_folders=("Nyhedsbreve",))
    h.box.add("Nyhedsbreve", make_message("own@x", subject="Selv flyttet"))
    res = services.newsletter_to_inbox("anna", "own@x", "admin", engine=live.eng)
    assert res["ok"] is False and res["code"] == "changed"
    assert h.box.msgids("Nyhedsbreve") == ["own@x"]
    assert services.newsletter_to_inbox("anna", "", "admin", engine=live.eng)["code"] == "invalid_id"


def test_mark_spam_from_newsletter_folder(live):
    h = live_account(live, SCAN, newsletters="on")
    moved_newsletter(live, h)
    [res] = services.mail_action("anna", ["n1@x"], "mark_spam", "admin", engine=live.eng)
    assert res["ok"] is True
    assert h.box.msgids("Spamfilter") == ["n1@x"] and h.box.msgids("Nyhedsbreve") == []
    assert live_row(h, "n1@x")["user_verdict"] == "spam"


def test_unkeep_lets_the_sender_be_moved_again(live):
    h = live_account(live, SCAN, newsletters="on")
    moved_newsletter(live, h)
    assert services.newsletter_to_inbox("anna", "n1@x", "admin", engine=live.eng)["ok"]
    res = services.newsletter_unkeep("anna", "News@Brand.example", "admin", engine=live.eng)
    assert res["ok"] and res["code"] == "ok"
    assert services.newsletter_unkeep("anna", "news@brand.example", "admin", engine=live.eng)["code"] == "nothing"
    news(live, h, "n3@x", subject="Endnu flere tilbud")
    live_loop(live, h)
    live.clock.t += 61
    live_loop(live, h)
    assert h.box.msgids("Nyhedsbreve") == ["n3@x"]
