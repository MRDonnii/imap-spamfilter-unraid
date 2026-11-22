"""2.11.1: "Lær som spam" during the grace period keeps the filter's queued
move. Before, _record_verdict dropped pending_move for every verdict and
_do_learn does not move, so a spam the user confirmed stayed in the inbox
(seen live twice). Learning ham / releasing still cancels the move. Runs
the real engine loop next to the real services (test_services' harness)."""
from __future__ import annotations

import pytest
from test_services import GIGA, SCAN, live, live_account, live_loop, live_mail, live_row  # noqa: F401

import services  # noqa: E402 - test_services puts filter/ on sys.path


def _pending(h, mid):
    return h.db.conn.execute("SELECT COUNT(*) FROM pending_move WHERE account=? AND message_id=?",
                             (h.acc.name, mid)).fetchone()[0]


@pytest.mark.parametrize("caps", [GIGA, SCAN], ids=["gigahost", "scannet"])
def test_learn_spam_keeps_the_pending_move_and_the_engine_moves(live, caps):
    h = live_account(live, caps)
    live_mail(live, h, "INBOX", "spam@x", subject="Vind nu", score=13.0)
    live_loop(live, h)                                   # scored: queued, grace 60 s
    assert _pending(h, "spam@x") == 1 and h.box.msgids("INBOX") == ["spam@x"]

    [res] = services.mail_action("anna", ["spam@x"], "learn_spam", "user:ole", engine=live.eng)
    assert res["ok"] is True
    assert _pending(h, "spam@x") == 1                    # the regression: this was 0
    assert h.box.msgids("INBOX") == ["spam@x"]           # learning itself never moves
    assert live_row(h, "spam@x")["user_verdict"] == "spam"

    live.clock.t += 61
    live_loop(live, h)
    assert h.box.msgids("Spamfilter") == ["spam@x"] and h.box.msgids("INBOX") == []
    row = live_row(h, "spam@x")
    assert row["our_action"] == "moved_to_junk" and row["current_folder"] == "Spamfilter"
    assert _pending(h, "spam@x") == 0
    assert "expunge" not in h.box.write_names()          # moved, never deleted


@pytest.mark.parametrize("action", ["learn_ham", "release"])
def test_ham_verdicts_still_cancel_the_pending_move(live, action):
    h = live_account(live, SCAN)
    live_mail(live, h, "INBOX", "ok@x", subject="Faktura", score=13.0)
    live_loop(live, h)
    assert _pending(h, "ok@x") == 1

    [res] = services.mail_action("anna", ["ok@x"], action, "user:ole", engine=live.eng)
    assert res["ok"] is True, res
    assert _pending(h, "ok@x") == 0
    live.clock.t += 61
    live_loop(live, h, n=2, step=61)
    assert h.box.msgids("INBOX") == ["ok@x"] and h.box.msgids("Spamfilter") == []


@pytest.mark.parametrize("learn", [True, False], ids=["learned-spam", "not-learned"])
def test_read_rescan_move_goes_only_after_the_users_spam_verdict(live, learn):
    """A re-scan/AI move (origin zap/ai) of a mail read during the grace is
    skipped (B19) - unless the user said spam with "Lær som spam"."""
    h = live_account(live, SCAN)
    uid = live_mail(live, h, "INBOX", "re@x", subject="Vind nu", score=13.0)
    live_loop(live, h)
    h.db.conn.execute("UPDATE pending_move SET origin='zap' WHERE message_id='re@x'")
    h.db.conn.commit()
    h.box.folders["INBOX"].msgs[uid].flags.add("\\Seen")
    if learn:
        [res] = services.mail_action("anna", ["re@x"], "learn_spam", "user:ole", engine=live.eng)
        assert res["ok"] is True and _pending(h, "re@x") == 1
    live.clock.t += 61
    live_loop(live, h)
    if learn:
        assert h.box.msgids("Spamfilter") == ["re@x"] and h.box.msgids("INBOX") == []
    else:
        assert h.box.msgids("INBOX") == ["re@x"] and h.box.msgids("Spamfilter") == []
    assert _pending(h, "re@x") == 0


@pytest.mark.parametrize("target", ["Junk", "Spamfilter"], ids=["provider_junk", "junk"])
def test_learn_spam_in_a_junk_folder_still_drops_the_pending_move(live, target):
    """keep_pending_move only holds outside the spam folders: the user moved
    the queued mail into the provider's Junk / the Spamfilter folder before
    the grace ended, then said spam - the queued move is obsolete and the
    mail stays where the user put it."""
    h = live_account(live, SCAN)
    uid = live_mail(live, h, "INBOX", "jk@x", subject="Vind nu", score=13.0)
    live_loop(live, h)
    assert _pending(h, "jk@x") == 1
    if target not in h.box.folders:
        h.box.add_folder(target)
    msg = h.box.folders["INBOX"].msgs.pop(uid)          # the user's own move
    h.box.add(target, msg.raw)

    [res] = services.mail_action("anna", ["jk@x"], "learn_spam", "user:ole", engine=live.eng)
    assert res["ok"] is True, res
    assert _pending(h, "jk@x") == 0
    assert live_row(h, "jk@x")["user_verdict"] == "spam"
    live.clock.t += 61
    live_loop(live, h)
    assert h.box.msgids(target) == ["jk@x"] and h.box.msgids("INBOX") == []
    assert "expunge" not in h.box.write_names()
