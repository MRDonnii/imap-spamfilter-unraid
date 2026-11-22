"""2.7 Mailsikkerhed: sfctl mailcheck (run + Danish summary, --last,
--problems), the one-line summary in sfctl doctor, the compact status in
push text and the dnspython pin. Fakes only:
no DNS server or mail server is ever contacted."""

from __future__ import annotations

import re
from pathlib import Path

from test_sfctl import env, last_audit, run  # noqa: F401 - env is a fixture

import mailcheck as mc  # noqa: E402
from test_mailcheck import FakeDns, full_zone, good_prober, rsa_p  # noqa: E402
from test_ui_mailcheck import _results  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def test_sfctl_mailcheck_last_run_and_doctor(env, capsys, monkeypatch):  # noqa: F811
    code, o, _ = run(capsys, monkeypatch, "mailcheck", "--last")
    assert code == 0 and "Ingen tjek endnu" in o
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert "[INFO] mailsikkerhed: ikke tjekket endnu" in o
    zone = full_zone(rsa_p(2048), dkim=False)
    monkeypatch.setattr(mc, "make_resolver", lambda *a, **k: FakeDns(zone))
    monkeypatch.setattr(mc, "TlsProber", lambda *a, **k: good_prober)
    monkeypatch.setattr(mc, "DNSBL_RATE_S", 0)
    monkeypatch.setenv("MAILCHECK_HELO", "spam.bynet.example")      # no getfqdn() lookup in tests
    code, o, _ = run(capsys, monkeypatch, "mailcheck")
    assert "bynet.example (Gigahost)" in o and "I alt:" in o and "Ret:" in o
    assert code == (1 if "[FEJL]" in o else 0)
    assert last_audit(env)["action"] == "mailcheck_run"
    code2, o2, _ = run(capsys, monkeypatch, "mailcheck", "--last", "--problems")
    assert code2 == code and "[ OK ]" not in o2 and "I alt:" in o2
    code, o, _ = run(capsys, monkeypatch, "doctor")
    line = next(ln for ln in o.splitlines() if "mailsikkerhed:" in ln)
    assert line.startswith("[ADV.]") and "i tjekket for" in line   # DNS problems are warnings in doctor


def test_push_problem_text_exists():
    import push

    title, body, url = push.PROBLEMS["mailcheck"]
    assert url == "/mailcheck" and "Mailsikkerhed" in title + body


def test_dnspython_is_pinned_installed_and_import_checked():
    req = (ROOT / "filter" / "requirements.txt").read_text()
    assert re.search(r"^dnspython==\d+\.\d+\.\d+$", req, re.M)
    for path in (ROOT / "filter" / "Dockerfile.unraid", ROOT / "deploy" / "aio" / "Dockerfile"):
        text = path.read_text()
        assert "grep -E '^dnspython==' /tmp/requirements.txt" in text
        assert "-r /tmp/requirements-dns.txt" in text and "import dns.message" in text
    bc = (ROOT / "deploy" / "aio" / "build-check.sh").read_text()
    assert re.search(r"import filter, dashboard, .*\bmailcheck, ui_mailcheck\b", bc)
    assert "dnspython works" in bc


def test_doctor_reports_a_degraded_run(env, capsys, monkeypatch):  # noqa: F811
    import sfctl

    code, o, _ = run(capsys, monkeypatch, "doctor")      # configures sfctl's paths
    res = _results()
    mc._degrade(res, "DNS svarede ikke.")
    res["counts"], res["status"] = mc.counts(res), mc.overall(res)
    conn = sfctl._engine_conn()
    try:
        mc.store_run(conn, res)
    finally:
        conn.close()
    code, o, _ = run(capsys, monkeypatch, "doctor")
    line = next(ln for ln in o.splitlines() if "mailsikkerhed:" in ln)
    assert line.startswith("[ADV.]") and "kunne ikke gennemføres" in line
