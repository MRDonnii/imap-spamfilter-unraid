"""2.7 Mailsikkerhed: the compact status in the Home Assistant payload."""

from __future__ import annotations

from test_ha import _json, env, henv  # noqa: F401 - fixtures

import mailcheck as mc  # noqa: E402
from test_ui_mailcheck import _results  # noqa: E402


def test_ha_payload_has_compact_mailcheck_status(henv):  # noqa: F811
    d = _json(henv)
    assert d["mailcheck"] == {"status": None, "errors": None, "warnings": None, "last_run": None}
    mc.store_run(henv.conn, _results())
    d = _json(henv)
    assert d["mailcheck"]["status"] == "bad" and d["mailcheck"]["errors"] == 1 and d["mailcheck"]["last_run"]


def test_ha_status_leaves_out_acknowledged_findings_and_degraded_runs(henv):  # noqa: F811
    res = _results()
    mc.store_run(henv.conn, res)
    dkim = next(i for i in mc.all_items(res) if i["key"] == "bynet.example:dkim")
    assert mc.acknowledge(henv.conn, mc.load_run(henv.conn), dkim["key"], mc.fingerprint(dkim), "admin")
    d = _json(henv)
    assert d["mailcheck"]["status"] == "ok" and d["mailcheck"]["errors"] == 0
    off = _results()
    mc._degrade(off, "DNS svarede ikke.")
    off["counts"], off["status"] = mc.counts(off), mc.overall(off)
    mc.store_run(henv.conn, off)
    assert _json(henv)["mailcheck"]["status"] == "unknown"
