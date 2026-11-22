"""Fra / Prøv / Til for the 2.8 protections (spamfilter).

One engine_state row per feature ('<feature>_mode', JSON {mode, at, by}):

  qr      QR-code phishing (qrscan.py)
  clam3p  ClamAV's third-party signatures (Sanesecurity, deploy/aio/sf-sigs)

off (Fra) | shadow (Prøv: only a 0-point trial symbol and an event, the
default; 2.13: DEFAULTS) | on (Til: the points count). The WebUI card (ui_trials.py) and
`sfctl trial` change it; every change is audited by the caller.
"""

from __future__ import annotations

import json
import sqlite3
import time
from typing import Any

MODES = ("off", "shadow", "on")
DEFAULT_MODE = "shadow"
FEATURES: dict[str, dict[str, str]] = {
    "qr": {"title": "QR-kode-phishing",
           "text": "Læser QR-koder i billeder og PDF'er og tjekker linket i dem."},
    "clam3p": {"title": "Ekstra virus- og phishinglister (Sanesecurity)",
               "text": "ClamAV-fund fra Sanesecurity's lister over phishing, svindel og farlige filer."},
    # 2.13 (phishsignals.py): default Til (DEFAULTS).
    "mixscript": {"title": "Snydetegn i emnet",
                  "text": "Russiske eller græske bogstaver gemt i danske og engelske ord, fx \"Dоmænеnаvnеt\"."},
    "domainage": {"title": "Nyregistrerede domæner",
                  "text": "Afsenderdomænet er under 30 dage gammelt (slås op i det offentlige domæneregister)."},
    "payphish": {"title": "Betalings- og kontophishing",
                 "text": "Emne om betaling, konto, abonnement, domæne eller MitID fra en afsender med faretegn."},
}
DEFAULTS = {"mixscript": "on", "domainage": "on", "payphish": "on"}
MODE_TEXT = {"off": "Fra", "shadow": "Prøv", "on": "Til"}
_CACHE: dict[str, tuple[float, str]] = {}
CACHE_S = 30.0


def _key(feature: str) -> str:
    if feature not in FEATURES:
        raise ValueError(f"unknown feature {feature!r}")
    return f"{feature}_mode"


def get(conn: sqlite3.Connection | None, feature: str) -> dict[str, Any]:
    """{mode, at, by} (mode falls back to DEFAULT_MODE)."""
    key = _key(feature)
    out: dict[str, Any] = {"mode": DEFAULTS.get(feature, DEFAULT_MODE), "at": None, "by": None}
    if conn is None:
        return out
    try:
        row = conn.execute("SELECT value FROM engine_state WHERE key=?", (key,)).fetchone()
        if row and row[0]:
            d = json.loads(row[0])
            if isinstance(d, dict) and d.get("mode") in MODES:
                out.update({"mode": d["mode"], "at": d.get("at"), "by": d.get("by")})
    except (sqlite3.Error, ValueError, TypeError):
        pass
    return out


def mode(conn: sqlite3.Connection | None, feature: str) -> str:
    """The mode, cached CACHE_S seconds per feature (read on every scan)."""
    now = time.monotonic()
    hit = _CACHE.get(feature)
    if hit is not None and now - hit[0] < CACHE_S:
        return hit[1]
    m = get(conn, feature)["mode"]
    _CACHE[feature] = (now, m)
    return m


def set_mode(conn: sqlite3.Connection, feature: str, value: str, actor: str, now: int | None = None) -> bool:
    """True when the mode changed. Caller handles the transaction + audit."""
    if value not in MODES:
        raise ValueError("Vælg Fra, Prøv eller Til.")
    if get(conn, feature)["mode"] == value:
        return False
    ts = int(now if now is not None else time.time())
    conn.execute("INSERT INTO engine_state(key, value, updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE "
                 "SET value=excluded.value, updated_at=excluded.updated_at",
                 (_key(feature), json.dumps({"mode": value, "at": ts, "by": str(actor or "")[:80]}), ts))
    _CACHE.pop(feature, None)
    return True
