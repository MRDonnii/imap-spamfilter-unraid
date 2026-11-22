"""Phishing signals of 2.13 (spamfilter), each with Fra/Prøv/Til
(trialmode.py); default Til:

  mixscript  TH_SUBJECT_MIXED_SCRIPT (+5): a word in the subject mixes Latin
             letters with Cyrillic or Greek look-alikes ("Dоmænеnаvnеt").
             A whole Cyrillic/Greek subject is not mixed and gives nothing.
  domainage  TH_NEW_DOMAIN (+4.5 under 7 days, +3 under 30 days): the From
             domain was registered recently (RDAP, the public registry
             protocol; IANA bootstrap). Freemail and the mailbox's own domain
             are never looked up; TLDs without RDAP (.dk, .de, .eu ...) give
             nothing. Answers are cached in STATE_DIR/rdap-cache.db (never the
             live spamfilter.db), lookups are rate limited, and a slow or
             failing registry only means "no evidence".
  payphish   TH_PAY_PHISH (+4, +5 with two risk signs, +6 with three or
             more): a subject about payment, account, subscription, domain,
             MitID or copyright AND at least one risk sign on the sender -
             freemail, an abused TLD, a look-alike display name, mixed
             scripts, a domain under 60 days, no DMARC pass, or a Reply-To
             in another domain. A real service signing for its own old domain
             has no risk sign and gets nothing; known contacts keep their
             trust (applied after this, contacts.py).

In Prøv a 0-point *_TRIAL symbol and a '<feature>_trial' event; in Til the
points and a '<feature>_hit' event. judge() never raises.
"""

from __future__ import annotations

import email
import json
import os
import logging
import re
import sqlite3
import threading
import time
import unicodedata
from collections import deque
from email.header import decode_header, make_header
from email.utils import getaddresses
from pathlib import Path
from typing import Any, Iterable

log = logging.getLogger("filter.phishsignals")

MIXED_SCORE = 5.0
NEW_DOMAIN_SCORES = ((7, 4.5), (30, 3.0))     # (younger than N days, points)
NEW_DOMAIN_RISK_DAYS = 60                     # a risk sign for TH_PAY_PHISH
PAY_SCORES = (4.0, 5.0, 6.0)                  # 1, 2, 3+ risk signs

RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
RDAP_BOOTSTRAP_MAX_AGE_S = 7 * 86400
RDAP_TIMEOUT_S = 4.0
RDAP_MAX_LOOKUPS = 30                         # per RDAP_WINDOW_S, per process
RDAP_WINDOW_S = 600
CACHE_OK_S = 90 * 86400                       # a known registration date
CACHE_RETRY_S = 86400                         # not found / error / no RDAP
_RDAP_DISABLED = os.environ.get("SF_RDAP", "1") == "0"   # tests: SF_RDAP=0 (conftest)

# Subjects about money, accounts, subscriptions, domains, identity or
# copyright (Danish + English). Only counts together with a risk sign.
PAY_LURES = [re.compile(p, re.I) for p in (
    r"\bdom(?:æ|ae)ne(?:navn)?(?:et)?\b.{0,40}\b(?:blokeret|suspenderet|spærret|udløb\w*|lukket|deaktiveret|"
    r"ikke\s+længere\s+aktiv\w*|opsagt)",
    r"\bdomain\b.{0,40}\b(?:suspended|blocked|expir\w*|deactivat\w*|terminat\w*)",
    r"\bbetaling\s+kræves\b|\bkræver\s+betaling\b",
    r"\b(?:premium|prime|netflix|spotify|abonnement\w*|subscription|membership|medlemskab\w*)\b.{0,40}"
    r"\b(?:udløber|afbrydes|stoppes|ending|expir\w*|renew\w*|fornyes|suspend\w*|on\s+hold|på\s+hold|payment)",
    r"\bverify\s+your\s+(?:contact|account|payment|billing|identity)",
    r"\b(?:bekræft|verificer|opdater)\s+(?:din|dine)\s+(?:konto|oplysninger|betalings\w*|kort\w*|identitet)",
    r"\bmitid\b",
    r"\b(?:intellektuel\s+ejendomsret|ophavsret|copyright|varemærke\w*|trademark)\b",
    r"\b(?:udbetaling|refusion|tilbagebetaling|refund)\b.{0,30}\b(?:notifikation|afventer|venter|klar|godkendt|"
    r"pending|notification)|\b(?:notifikation|meddelelse|besked|notification)\b.{0,40}"
    r"\b(?:udbetaling|refusion|tilbagebetaling|refund|payout)",
    r"\baction\s+required\b|\bhandling\s+påkrævet\b",
    r"\b(?:din|your)\s+(?:konto|account)\b.{0,30}\b(?:lukket|blokeret|spærret|suspend\w*|locked|on\s+hold|"
    r"på\s+hold|begrænset|limited|deaktiveret)",
    r"\bpayment\b.{0,30}\b(?:failed|declined|attention|update|required|problem)",
    r"\bbetaling\w*\b.{0,30}\b(?:fejlet|afvist|kunne\s+ikke|mislykkedes)",
)]
LURE_SYMBOLS = frozenset({"TH_LURE_SUBJECT_STRONG"})
# DMARC passed: rspamd's own check, or (late scan, filter.py aged mode) the
# provider's Authentication-Results.
DMARC_PASS_SYMBOLS = frozenset({"DMARC_POLICY_ALLOW", "TH_PROVIDER_AUTH_PASS"})
RISK_SYMBOLS = {"FREEMAIL_FROM": "gratis mailadresse", "TH_FROM_ABUSED_TLD": "misbrugt topdomæne",
                "TH_FROM_NAME_HOMOGLYPH": "falske tegn i afsendernavnet"}

_WORD = re.compile(r"[^\W\d_]+", re.UNICODE)
_lock = threading.Lock()
_lookups: deque[float] = deque()
_bootstrap: dict[str, str] = {}
_bootstrap_at = 0.0


# --------------------------------------------------------------------- helpers

def _subject(raw: bytes) -> str:
    try:
        msg = email.message_from_bytes(raw[:65536])
        return str(make_header(decode_header(msg.get("Subject", "") or "")))[:400]
    except Exception:  # noqa: BLE001 - a broken header is just no subject
        return ""


def _addr_domain(value: str) -> str:
    try:
        addrs = getaddresses([value or ""])
    except Exception:  # noqa: BLE001
        return ""
    for _name, addr in addrs:
        if "@" in addr:
            return addr.rpartition("@")[2].strip().strip(">").lower().rstrip(".")
    return ""


def _headers(raw: bytes) -> tuple[str, str]:
    try:
        msg = email.message_from_bytes(raw[:65536])
        return _addr_domain(str(msg.get("From", ""))), _addr_domain(str(msg.get("Reply-To", "")))
    except Exception:  # noqa: BLE001
        return "", ""


def _script(ch: str) -> str:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return ""
    for s in ("LATIN", "CYRILLIC", "GREEK"):
        if name.startswith(s):
            return s
    return ""


def mixed_words(text: str) -> list[str]:
    """Words that mix Latin with Cyrillic or Greek letters."""
    out = []
    for w in _WORD.findall(text or ""):
        scripts = {_script(c) for c in w} - {""}
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
            out.append(w)
    return out


def pay_lure(subject: str, names: Iterable[str]) -> bool:
    return bool(set(names) & LURE_SYMBOLS) or any(p.search(subject or "") for p in PAY_LURES)


def _registrable(domain: str) -> str | None:
    try:
        import lookalike  # noqa: PLC0415

        return lookalike.registrable(domain)
    except Exception:  # noqa: BLE001
        return None


def _is_freemail(domain: str) -> bool:
    try:
        import contacts  # noqa: PLC0415

        return bool(contacts.is_freemail(domain))
    except Exception:  # noqa: BLE001
        return False


# --------------------------------------------------------------------- RDAP

def _state_dir() -> Path:
    import filter as eng  # noqa: PLC0415

    return Path(eng.STATE_DIR)


def _cache_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_state_dir() / "rdap-cache.db"), timeout=5)
    conn.execute("CREATE TABLE IF NOT EXISTS domain_age(domain TEXT PRIMARY KEY, created INTEGER, "
                 "status TEXT NOT NULL, checked_at INTEGER NOT NULL)")
    return conn


def _rate_ok(now: float) -> bool:
    while _lookups and now - _lookups[0] > RDAP_WINDOW_S:
        _lookups.popleft()
    if len(_lookups) >= RDAP_MAX_LOOKUPS:
        return False
    _lookups.append(now)
    return True


def _rdap_base(tld: str) -> str | None:
    """The RDAP server of a TLD (IANA bootstrap, cached on disk for a week)."""
    global _bootstrap, _bootstrap_at
    now = time.time()
    if not _bootstrap or now - _bootstrap_at > RDAP_BOOTSTRAP_MAX_AGE_S:
        path = _state_dir() / "rdap-dns.json"
        data = None
        try:
            if path.exists() and now - path.stat().st_mtime < RDAP_BOOTSTRAP_MAX_AGE_S:
                data = json.loads(path.read_text())
        except (OSError, ValueError):
            data = None
        if data is None:
            try:
                import requests  # noqa: PLC0415

                r = requests.get(RDAP_BOOTSTRAP_URL, timeout=RDAP_TIMEOUT_S)
                r.raise_for_status()
                data = r.json()
                tmp = path.with_suffix(".tmp")
                tmp.write_text(json.dumps(data))
                tmp.replace(path)
            except Exception as ex:  # noqa: BLE001
                log.info("rdap bootstrap unavailable: %s", type(ex).__name__)
                try:
                    data = json.loads(path.read_text()) if path.exists() else None
                except (OSError, ValueError):
                    data = None
        if not isinstance(data, dict):
            _bootstrap_at = now  # do not hammer IANA; retry after the max age
            return None
        table: dict[str, str] = {}
        for entry in data.get("services") or []:
            try:
                tlds, urls = entry
            except (TypeError, ValueError):
                continue
            url = next((u for u in urls if str(u).startswith("https://")), None)
            for t in tlds:
                if url:
                    table[str(t).lower()] = str(url).rstrip("/") + "/"
        _bootstrap, _bootstrap_at = table, now
    return _bootstrap.get(tld)


def _parse_created(data: Any) -> int | None:
    if not isinstance(data, dict):
        return None
    for ev in data.get("events") or []:
        if isinstance(ev, dict) and ev.get("eventAction") == "registration":
            try:
                from datetime import datetime  # noqa: PLC0415

                return int(datetime.fromisoformat(str(ev.get("eventDate")).replace("Z", "+00:00")).timestamp())
            except (TypeError, ValueError):
                return None
    return None


def _cache_get(domain: str) -> tuple[int | None, str, int] | None:
    with _lock:
        conn = _cache_conn()
        try:
            return conn.execute("SELECT created, status, checked_at FROM domain_age WHERE domain=?",
                                (domain,)).fetchone()
        finally:
            conn.close()


def _cache_put(domain: str, created: int | None, status: str, now: float) -> None:
    with _lock:
        conn = _cache_conn()
        try:
            with conn:
                conn.execute("INSERT INTO domain_age(domain, created, status, checked_at) VALUES(?,?,?,?) "
                             "ON CONFLICT(domain) DO UPDATE SET created=excluded.created, "
                             "status=excluded.status, checked_at=excluded.checked_at",
                             (domain, created, status, int(now)))
        finally:
            conn.close()


def domain_created(domain: str, now: float | None = None) -> int | None:
    """Registration time (epoch) of a registrable domain, or None (unknown,
    no RDAP for the TLD, rate limited, network error). Never raises. The
    lock only guards the cache and the rate counter, never the network."""
    if _RDAP_DISABLED or not domain or "." not in domain:
        return None
    now = time.time() if now is None else now
    try:
        row = _cache_get(domain)
        if row is not None:
            created, status, checked = row
            if now - checked < (CACHE_OK_S if status == "ok" else CACHE_RETRY_S):
                return int(created) if created is not None else None
        with _lock:
            base = _rdap_base(domain.rsplit(".", 1)[1])
            allowed = base is not None and _rate_ok(now)
        if base is None:
            status, created = "no_rdap", None
        elif not allowed:
            return None
        else:
            import requests  # noqa: PLC0415

            try:
                r = requests.get(f"{base}domain/{domain}", timeout=RDAP_TIMEOUT_S,
                                 headers={"Accept": "application/rdap+json"})
                if r.status_code == 404:
                    status, created = "not_found", None
                elif r.ok:
                    created = _parse_created(r.json())
                    status = "ok" if created is not None else "no_date"
                else:
                    status, created = f"http_{r.status_code}", None
            except Exception as ex:  # noqa: BLE001
                status, created = f"error_{type(ex).__name__}"[:40], None
        _cache_put(domain, created, status, now)
        return created
    except Exception as ex:  # noqa: BLE001 - evidence only
        log.warning("rdap lookup failed: %s", type(ex).__name__)
        return None


def _own_domains(acc: Any) -> set[str]:
    out = set()
    for v in [getattr(acc, "user", "")] + list(getattr(acc, "protected_recipients", None) or []):
        d = _registrable(str(v).rpartition("@")[2]) if "@" in str(v) else None
        if d:
            out.add(d)
    return out


def sender_age_days(acc: Any, from_domain: str, now: float | None = None) -> int | None:
    reg = _registrable(from_domain) if from_domain else None
    if not reg or _is_freemail(reg) or reg in _own_domains(acc):
        return None
    created = domain_created(reg, now)
    if created is None:
        return None
    now = time.time() if now is None else now
    return max(0, int((now - created) // 86400))


# --------------------------------------------------------------------- judge

def _emit(feature: str, mode: str, name: str, score: float, opts: list[str],
          syms: list[dict], events: list[tuple[str, str]]) -> None:
    if mode == "on":
        syms.append({"n": name, "s": score, "o": opts})
        events.append((f"{feature}_hit", f"{name} {score:g} {' '.join(opts)}"[:200]))
    elif mode == "shadow":
        syms.append({"n": f"{name}_TRIAL", "s": 0.0, "o": [f"+{score:g}", *opts]})
        events.append((f"{feature}_trial", f"{name} {score:g} {' '.join(opts)}"[:200]))


def judge(conn: Any, acc: Any, raw: bytes, names: Iterable[str]) -> tuple[list[dict], list[tuple[str, str]]]:
    syms: list[dict] = []
    events: list[tuple[str, str]] = []
    try:
        import trialmode  # noqa: PLC0415

        names = set(names or ())
        modes = {f: trialmode.mode(conn, f) for f in ("mixscript", "domainage", "payphish")}
        if all(m == "off" for m in modes.values()):
            return syms, events
        subject = _subject(raw)
        from_dom, reply_dom = _headers(raw)
        mixed = mixed_words(subject)
        if mixed and modes["mixscript"] != "off":
            _emit("mixscript", modes["mixscript"], "TH_SUBJECT_MIXED_SCRIPT", MIXED_SCORE,
                  [mixed[0][:40]], syms, events)
        lure = pay_lure(subject, names)
        age = None
        if modes["domainage"] != "off" or (lure and modes["payphish"] != "off"):
            age = sender_age_days(acc, from_dom)
        if age is not None and modes["domainage"] != "off":
            pts = next((p for days, p in NEW_DOMAIN_SCORES if age < days), 0.0)
            if pts:
                _emit("domainage", modes["domainage"], "TH_NEW_DOMAIN", pts,
                      [_registrable(from_dom) or from_dom, f"{age} dage"], syms, events)
        if lure and modes["payphish"] != "off":
            risks = [label for sym, label in RISK_SYMBOLS.items() if sym in names]
            if mixed:
                risks.append("blandede tegn i emnet")
            if age is not None and age < NEW_DOMAIN_RISK_DAYS:
                risks.append(f"domæne {age} dage gammelt")
            if not names & DMARC_PASS_SYMBOLS:
                risks.append("ingen DMARC-godkendelse")
            if reply_dom and from_dom and _registrable(reply_dom) != _registrable(from_dom):
                risks.append("svar går til et andet domæne")
            if risks:
                pts = PAY_SCORES[min(len(risks), len(PAY_SCORES)) - 1]
                _emit("payphish", modes["payphish"], "TH_PAY_PHISH", pts, risks[:3], syms, events)
    except Exception as ex:  # noqa: BLE001 - optional evidence, never blocks a scan
        log.warning("phish signals failed: %s", type(ex).__name__)
    return syms, events
