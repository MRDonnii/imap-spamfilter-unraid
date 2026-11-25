"""Senders the people have already judged (2.19.1) - TH-Beast spamfilter.

'Tjek disse' (ui_mail.review_items) and its phone notification
(push.on_review) offer caught mail that MAY be legitimate. A mail that is
there only because its score is close to the threshold is left out when the
same sender has already been called spam by a person ("Det er spam",
"Lær som spam", a move to Junk) and nobody has ever released or rescued mail
from it: the person has answered that question. Mail with a real reason
(known contact, reply, protected address, own domain, 'Altid igennem' that
could not be verified) is always offered.

The sender is its registrable domain (zoo-friends.help); for freemail
(gmail.com, hotmail.dk ...) only the exact address, since anyone can have
one. Verdicts from every mailbox count: a campaign that one person called
spam is the same campaign in the next mailbox. Nothing is moved or learned
here; hidden mail stays in the Spamfilter folder and in the spam list.
"""

from __future__ import annotations

import sqlite3
from email.utils import parseaddr
from typing import Any, Iterable

JUDGED_DAYS = 180
HAM_ACTIONS = ("manual_release", "user_rescued")


def sender_key(sender: Any) -> str | None:
    """'dom:zoo-friends.help' / 'addr:x@gmail.com' / None."""
    addr = (parseaddr(str(sender or ""))[1] or "").strip().lower()
    if "@" not in addr:
        return None
    dom = addr.rpartition("@")[2].strip(".")
    if not dom or "." not in dom:
        return None
    try:
        import contacts  # noqa: PLC0415

        if contacts.is_freemail(dom):
            return f"addr:{addr}"
    except Exception:  # noqa: BLE001 - without the freemail list: address only (strict)
        return f"addr:{addr}"
    try:
        import lookalike  # noqa: PLC0415

        reg = lookalike.registrable(dom) or dom
    except Exception:  # noqa: BLE001
        reg = dom
    return f"dom:{reg}"


def judged_spam(conn: sqlite3.Connection, now: int, *, days: int = JUDGED_DAYS) -> set[str]:
    """Sender keys a person called spam in the last `days` and never released
    or rescued (in any mailbox, also earlier than `days`). Never raises."""
    spam: set[str] = set()
    ham: set[str] = set()
    q = ",".join("?" * len(HAM_ACTIONS))
    try:
        for sender, verdict, action, ts in conn.execute(
                f"SELECT sender, user_verdict, our_action, COALESCE(scanned_at, received_at, first_seen) "
                f"FROM messages WHERE user_verdict IN ('spam', 'ham') OR our_action IN ({q})", HAM_ACTIONS):
            key = sender_key(sender)
            if key is None:
                continue
            if verdict == "ham" or action in HAM_ACTIONS:
                ham.add(key)
            elif verdict == "spam" and ts is not None and int(ts) >= now - days * 86400:
                spam.add(key)
    except (sqlite3.Error, TypeError, ValueError):
        return set()
    return spam - ham


def already_judged(sender: Any, judged: Iterable[str]) -> bool:
    key = sender_key(sender)
    return key is not None and key in judged


# ---------------------------------------------------------------------------
# 2.19.2: obvious spam left out of 'Tjek disse'. Measured on 3 weeks of live
# mail (69 borderline mails): these rules hid 49 of 59 spam and none of the
# 10 mails people released - all 10 came from senders seen before.

AI_SURE = 0.8
FIRST_CONTACT_SIGNS = frozenset({
    "TH_PAY_PHISH", "TH_SUBJECT_MIXED_SCRIPT", "TH_NEW_DOMAIN", "TH_FROM_ABUSED_TLD", "TH_LURE_SUBJECT",
    "TH_LURE_SUBJECT_STRONG", "FUZZY_DENIED", "FUZZY_LOCAL_SPAM", "TH_FROM_NAME_HOMOGLYPH", "TH_BRAND_SPOOF",
    "TH_SUBJECT_BRAND"})
DMARC_PASS = frozenset({"DMARC_POLICY_ALLOW", "TH_PROVIDER_AUTH_PASS"})


def ai_sure_spam(conn: sqlite3.Connection, now: int, *, days: int = 31) -> set[tuple[str, str]]:
    """(account, message_id) the local AI called spam or phishing with
    confidence >= AI_SURE. Never raises."""
    try:
        return {(str(a), str(m)) for a, m in conn.execute(
            "SELECT account, message_id FROM ai_verdicts WHERE verdict IN ('spam', 'phishing') "
            "AND confidence >= ? AND created_at >= ?", (AI_SURE, now - days * 86400))}
    except (sqlite3.Error, TypeError, ValueError):
        return set()


def obvious_spam(names: Iterable[str], ai_sure: bool) -> str:
    """Why a borderline-only mail is obvious spam ('' = offer it): the AI is
    sure, or it is the first mail from an unknown sender without a DMARC
    pass or with a spam sign."""
    names = set(names or ())
    if ai_sure:
        return "ai"
    if "TH_FIRST_CONTACT" in names and (not names & DMARC_PASS or names & FIRST_CONTACT_SIGNS):
        return "first_contact"
    return ""
