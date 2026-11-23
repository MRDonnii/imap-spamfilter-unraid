"""Pure sender/threat/score policy. No database, mail, network or learning I/O.

The engine resolves account-scoped sender rules and content-bound prior verdicts
before calling decide(). Version 1 preserves the 2.15.0 ordering, including
explicit sticky releases before threat handling. New reason codes are metadata.
This is the shared initial-scan/pending-move core, not every later AI/ZAP action.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

POLICY_VERSION = 1

STICKY_HAM_ACTIONS = frozenset({"manual_release", "user_rescued"})
DMARC_SPOOF_SYMBOLS = frozenset({"DMARC_POLICY_REJECT", "DMARC_POLICY_QUARANTINE"})
# An allow rule matches the (forgeable) header From. Besides a DMARC
# reject/quarantine verdict these also mean "do not trust this From" - most
# domains (the owner's own included) publish DMARC p=none, so spoofed
# "from yourself" extortion spam never gets a DMARC policy symbol.
ALLOW_DISTRUST_SYMBOLS = DMARC_SPOOF_SYMBOLS | frozenset({
    "R_SPF_FAIL", "R_SPF_SOFTFAIL", "TH_PROVIDER_SPAM",
    # 2.2 (B7): an aged scan turns rspamd's DMARC/SPF off; the provider's
    # own verdict at delivery keeps distrusting the From: dmarc=fail
    # (TH_PROVIDER_AUTH_FAIL; p=none -> TH_PROVIDER_AUTH_SPOOF) and
    # spf=fail/softfail without an aligned DKIM pass (TH_PROVIDER_AUTH_SPOOF).
    # TH_AGED_UNVERIFIED: aged scan with no provider SPF/DMARC verdict and no
    # aligned DKIM signature - nothing proves the From (see _decide).
    "TH_PROVIDER_AUTH_FAIL", "TH_PROVIDER_AUTH_SPOOF", "TH_AGED_UNVERIFIED"})
THREAT_FORCE_PASSABLE = frozenset({"phish", "malware_url", "attachment", "impersonation", "lookalike"})


@dataclass
class Decision:
    spam: bool                  # act on it (how depends on the mode)
    action: str | None          # our_action when not acting
    rule_hit: str | None = None
    rule_id: int | None = None
    note: str = ""
    verdict: str | None = None  # user verdict implied by the mail (e.g. $NotJunk)
    symbols: list = field(default_factory=list)   # 2.1: pseudo-symbols to store (score 0)
    events: list = field(default_factory=list)    # 2.1: (event, detail) to log
    reason: str = "score"
    policy_version: int = POLICY_VERSION
    policy_input: dict | None = field(default=None, repr=False, compare=False)


def sticky_ham(row: Any) -> bool:
    return row is not None and (row["user_verdict"] == "ham" or row["our_action"] in STICKY_HAM_ACTIONS)


def rule_is_force(rule: Any) -> bool:
    """True for an allow rule marked 'Altid igennem' (never moved, not even
    when the From looks forged)."""
    if rule is None:
        return False
    try:
        return rule["kind"] == "allow" and bool(rule["force"])
    except (IndexError, KeyError):  # row from before the column existed
        return False


def _rule_domain(rule: Any) -> str:
    return str(rule["pattern"] or "").partition("@")[2].lower()


def _domain_under(host: str | None, domain: str) -> bool:
    h = (host or "").strip().lower().rstrip(".")
    return bool(h) and bool(domain) and (h == domain or h.endswith("." + domain))


def parse_sender_auth(value: Any) -> dict[str, Any]:
    """messages.sender_auth JSON -> {"dkim": [domains], "host": str|None}."""
    if isinstance(value, dict):
        data = value
    else:
        try:
            data = json.loads(value) if value else {}
        except (TypeError, ValueError):
            data = {}
    if not isinstance(data, dict):
        data = {}
    dkim = [str(d).lower() for d in (data.get("dkim") or []) if d][:20]
    host = data.get("host")
    return {"dkim": dkim, "host": str(host).lower() if host else None}


def force_verification(rule: Any, auth: dict[str, Any] | None) -> str | None:
    """E8: how an 'Altid igennem' rule's domain is verified for this mail:
    'dkim:<d>' (R_DKIM_ALLOW for the domain or a subdomain), 'host:<h>'
    (the verified sending host lies under the domain, e.g. a shop
    platform's mail-sender-N host behind its own forwarder), else None."""
    if rule is None:
        return None
    dom = _rule_domain(rule)
    a = parse_sender_auth(auth)
    for d in a["dkim"]:
        if _domain_under(d, dom):
            return f"dkim:{d}"
    if _domain_under(a["host"], dom):
        return f"host:{a['host']}"
    return None


def decide(prior: Any, rule: Any, final: float, names: frozenset, *, threshold: float,
           from_header: bool = True, auth: dict[str, Any] | None = None,
           aged_unverified: bool = False, threat: str | None = None) -> Decision:
    """Apply the established policy to already-resolved evidence without I/O."""
    over = final >= threshold
    if sticky_ham(prior):
        return Decision(False, prior["our_action"] or "none", reason="sticky_ham", note="sticky ham verdict")
    if threat == "virus":
        return Decision(True, None, reason="virus", note="threat virus")
    if rule is not None and rule["kind"] == "block":
        return Decision(True, None, rule_hit=f"block:{rule['id']}", rule_id=int(rule["id"]),
                        reason="sender_block", note="block rule")
    if threat:
        if (rule is not None and threat in THREAT_FORCE_PASSABLE and rule_is_force(rule) and from_header):
            how = force_verification(rule, auth)
            if how is not None and how.startswith("dkim:"):
                return Decision(False, "allowlisted", rule_hit=f"allow:{rule['id']}", rule_id=int(rule["id"]),
                                reason="verified_threat_exception", note=f"force allow rule ({how}) despite threat {threat}",
                                events=[("threat_force_pass", f"{threat} rule={rule['id']} {how}")])
        ignored = f" (allow rule {rule['id']} ignored)" if rule is not None and rule["kind"] == "allow" else ""
        return Decision(True, None, reason="threat", note=f"threat {threat}{ignored}")
    extra_syms: list[dict] = []
    extra_events: list[tuple[str, str]] = []
    unverified_note = ""
    if rule is not None and rule["kind"] == "allow":
        distrust = names & ALLOW_DISTRUST_SYMBOLS
        if aged_unverified and "TH_AGED_UNVERIFIED" not in distrust:
            distrust = distrust | {"TH_AGED_UNVERIFIED"}
        if rule_is_force(rule) and from_header:
            how = force_verification(rule, auth)
            if how is not None:
                # 'Altid igennem': the owner vouches for this sender (e.g. their
                # own webshop platform, forwarded with SRS and sometimes released
                # from the provider's quarantine with a broken DKIM signature)
                # and the mail verifiably comes from that domain. Never flagged
                # or moved - not by score, not by spoof symbols.
                return Decision(False, "allowlisted", rule_hit=f"allow:{rule['id']}", rule_id=int(rule["id"]),
                                reason="verified_force_allow", note=f"force allow rule ({how})" + (f" (ignored {','.join(sorted(distrust))})"
                                                                    if distrust else ""))
            # Spoof guard (E8): the From claims the domain, but neither DKIM
            # nor the sending path proves it - a normal allow rule.
            extra_syms.append({"n": "TH_FORCE_UNVERIFIED", "s": 0.0, "o": [str(rule["pattern"])[:120]]})
            extra_events.append(("force_unverified", f"rule={rule['id']} {rule['pattern']}"))
            unverified_note = "force_unverified; "
        if distrust:
            # A forged From of an allowed sender must not bypass the filter:
            # decide by score like any other mail.
            if "TH_AGED_UNVERIFIED" in distrust and "TH_AGED_UNVERIFIED" not in names:
                extra_syms.append({"n": "TH_AGED_UNVERIFIED", "s": 0.0,
                                   "o": ["ingen udbyder-godkendelse", "ingen DKIM-signatur"]})
            return Decision(over, None if over else "none",
                            reason="allow_distrusted", note=f"{unverified_note}allow rule ignored: {','.join(sorted(distrust))}",
                            symbols=extra_syms, events=extra_events)
        return Decision(False, "allowlisted" if over else "none",
                        rule_hit=f"allow:{rule['id']}", rule_id=int(rule["id"]),
                        reason="sender_allow", note=f"{unverified_note}allow rule", symbols=extra_syms, events=extra_events)
    if prior is not None and prior["user_verdict"] == "spam":
        return Decision(True, None, reason="user_spam", note="user verdict spam")
    return Decision(over, None if over else "none")
