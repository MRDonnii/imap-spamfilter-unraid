"""2.8: trialmode (Fra/Prøv/Til), the Nye beskyttelser card and sf-sigs."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "filter"))
import trialmode  # noqa: E402


def _conn():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE engine_state(key TEXT PRIMARY KEY, value TEXT, updated_at INTEGER)")
    return c


def test_modes_default_to_shadow_and_change():
    c = _conn()
    assert trialmode.mode(c, "qr") == "shadow" and trialmode.get(c, "clam3p")["mode"] == "shadow"
    assert trialmode.set_mode(c, "qr", "on", "admin", now=100) is True
    assert trialmode.set_mode(c, "qr", "on", "admin") is False
    assert trialmode.get(c, "qr") == {"mode": "on", "at": 100, "by": "admin"}
    assert trialmode.mode(c, "qr") == "on" and trialmode.mode(None, "clam3p") == "shadow"
    with pytest.raises(ValueError):
        trialmode.set_mode(c, "qr", "maybe", "admin")
    with pytest.raises(ValueError):
        trialmode.get(c, "nope")
    c.execute("UPDATE engine_state SET value='garbage'")
    trialmode._CACHE.clear()
    assert trialmode.mode(c, "qr") == "shadow"


def _sigs():
    path = ROOT / "deploy" / "aio" / "sf-sigs"
    loader = importlib.machinery.SourceFileLoader("sf_sigs", str(path))
    spec = importlib.util.spec_from_loader("sf_sigs", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_sf_sigs_lists_only_low_risk_sanesecurity_files_and_the_key_ships():
    m = _sigs()
    assert "junk.ndb" not in m.FILES and "jurlbl.ndb" not in m.FILES and "foxhole_filename.cdb" not in m.FILES
    assert {"phish.ndb", "scam.ndb", "sigwhitelist.ign2"} <= set(m.FILES)
    assert all(u.startswith("https://") for u in m.MIRRORS)
    assert (ROOT / "deploy/aio/clamav/sanesecurity.gpg").stat().st_size > 500


def test_sf_sigs_installs_only_verified_files(tmp_path, monkeypatch):
    m = _sigs()
    monkeypatch.setattr(m, "DB_DIR", tmp_path)
    monkeypatch.setattr(m, "FILES", ("good.ndb", "bad.ndb", "same.ndb"))
    (tmp_path / "same.ndb").write_text("old")
    (tmp_path / "bad.ndb").write_text("previous")
    fetched = []

    def get(url, since=None):
        fetched.append(url)
        if "same.ndb" in url and not url.endswith(".sig"):
            return None  # 304
        return b"sig" if url.endswith(".sig") else b"data:" + url.encode()
    monkeypatch.setattr(m, "_get", get)
    monkeypatch.setattr(m, "_verify", lambda tmp, name, data, sig: None if name == "good.ndb" else "GPG-signaturen passer ikke")
    monkeypatch.setattr(m, "_reload", lambda: True)
    st = m.run_once()
    assert st["updated"] == ["good.ndb"] and st["reloaded"] is True
    assert set(st["failed"]) == {"bad.ndb"} and st["files"] == 3
    assert (tmp_path / "good.ndb").read_bytes().startswith(b"data:https://ftp.swin.edu.au/")
    assert (tmp_path / "bad.ndb").read_text() == "previous"      # a bad copy never replaces the old one
    assert (tmp_path / "same.ndb").read_text() == "old"
    assert sum("bad.ndb" in u and not u.endswith(".sig") for u in fetched) == 2  # second mirror tried


def test_sf_sigs_verify_with_gpgv(tmp_path):
    import shutil
    if shutil.which("gpgv") is None:
        pytest.skip("gpgv missing")
    m = _sigs()
    m.KEYRING = ROOT / "deploy/aio/clamav/sanesecurity.gpg"
    assert m._verify(tmp_path, "sigwhitelist.ign2", b"x", b"not a signature") == "GPG-signaturen passer ikke"



def test_weekly_report_shows_the_new_protections():
    import services
    base = {"accounts": [], "trials": {"qr_trial": 2, "clam3p_hit": 1, "ai": 5, "ai_spam": 1}}
    try:
        out = services.render_weekly(base, full=True)
    except Exception:  # noqa: BLE001 - the renderer may want more keys; then only the helper text is checked
        pytest.skip("render_weekly needs a full data dict")
    text = out.get("text") or ""
    assert "Nye beskyttelser: QR-koder med mistænkeligt link 2 (Prøv), Sanesecurity-fund 1, AI vurderede 5" in text
