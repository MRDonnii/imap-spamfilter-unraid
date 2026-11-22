"""2.5.0 push notifications - operations: sfctl push-status / push-test /
push-reset and doctor, the pinned 'cryptography' in the images, the AIO
build check, the build context, the nightly backup (VAPID key) and the
smoke-test copy (no phone ever gets a push from it)."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fakes_push import FakePushService, device  # noqa: E402
from test_deploy_scripts import _archive_members, _run_backup, backup_host  # noqa: E402,F401
from test_sfctl import audit_records, env, run  # noqa: E402,F401

import push  # noqa: E402
import webpush  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
AIO = ROOT / "deploy" / "aio"


@pytest.fixture
def saved_push(monkeypatch):
    for name in ("STATE_DIR", "CONFIG_PATH", "DB_PATH", "USERS_FILE", "AUTO_WORKER"):
        monkeypatch.setattr(push, name, getattr(push, name))


@pytest.fixture
def senv(saved_push, env, monkeypatch):
    svc = FakePushService()
    real_send = webpush.send
    monkeypatch.setattr(webpush, "send", lambda *a, **k: real_send(*a, **{**k, "session": svc}))
    # The env's mailboxes use the reserved .example TLD, which push services
    # refuse as a VAPID contact - name a usable one explicitly.
    monkeypatch.setenv("PUSH_VAPID_SUBJECT", "mailto:admin@example.com")
    env.svc = svc
    return env


def add_device(e, user, **kw):
    dev = device(**kw)
    res = push.subscribe(user, dev.endpoint, dev.p256dh, dev.auth, user_agent="iPhone · app på hjemmeskærmen")
    assert res["ok"], res
    e.svc.add(dev)
    return dev


def test_sfctl_configures_push_for_a_one_shot_process(senv):
    assert push.STATE_DIR == senv.state and push.DB_PATH == senv.state / "spamfilter.db"
    assert push.AUTO_WORKER is False


def test_push_status_lists_devices_without_endpoints(senv, capsys, monkeypatch):
    code, o, _ = run(capsys, monkeypatch, "push-status")
    assert code == 0 and "Enheder:        0" in o and "ingen endnu" in o
    dev = add_device(senv, "anna", host="fcm.googleapis.com")
    push.public_key()
    code, o, _ = run(capsys, monkeypatch, "push-status")
    assert code == 0
    assert "Enheder:        1" in o and "anna" in o and "fcm.googleapis.com" in o and "mode 0600" in o
    assert "farlige mails" in o and "Afsender (sub): ok" in o
    assert dev.endpoint not in o and dev.auth not in o and dev.p256dh not in o and "PRIVATE" not in o


def test_push_test_sends_to_the_users_devices(senv, capsys, monkeypatch):
    dev = add_device(senv, "anna")
    code, o, e = run(capsys, monkeypatch, "push-test", "anna")
    assert code == 0, e
    assert "Testbeskeden er sendt." in o
    assert senv.svc.payloads(dev)[0]["title"] == "Testbesked"
    code, _, e = run(capsys, monkeypatch, "push-test", "admin")
    assert code == 1 and "ingen enhed" in e
    code, _, e = run(capsys, monkeypatch, "push-test", "ukendt")
    assert code == 1 and "findes ikke" in e


def test_push_reset_needs_ja_deletes_devices_and_rotates_the_key(senv, capsys, monkeypatch):
    add_device(senv, "anna")
    add_device(senv, "admin")
    old = push.public_key()
    code, o, e = run(capsys, monkeypatch, "push-reset", answers=["nej"])
    assert code == 1 and len(push.devices("anna")) == 1
    code, o, _ = run(capsys, monkeypatch, "push-reset", answers=["ja"])
    assert code == 0 and "2 enhed(er) er fjernet" in o
    assert push.devices("anna") == [] and push.devices("admin") == []
    assert push.public_key() != old
    assert (senv.state / "vapid_private.pem").stat().st_mode & 0o777 == 0o600
    rec = audit_records(senv)[-1]
    assert rec["action"] == "push_reset" and rec["actor"] == "cli" and "2 enhed" in rec["detail"]


def test_doctor_shows_push_state(senv, capsys, monkeypatch):
    (senv.state / "heartbeat").write_text(f"{int(__import__('time').time())} boot\n")
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert "beskeder (push): ingen nøgle endnu" in o
    add_device(senv, "anna")
    push.public_key()
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert "beskeder (push): 1 enhed(er) hos 1 bruger(e)" in o
    (senv.state / "vapid_private.pem").chmod(0o644)
    add_device(senv, "slettet")
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert "vapid_private.pem kan læses af andre" in o
    assert "enheder med beskeder hører til slettede brugere: slettet" in o
    senv.config.write_text("accounts: []\n")
    monkeypatch.delenv("PUSH_VAPID_SUBJECT", raising=False)
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert "ingen afsenderadresse" in o


def test_doctor_and_push_status_flag_a_server_wide_refusal(senv, capsys, monkeypatch):
    """2.5.0: Apple refusing the filter's JWT (clock skew, bad 'sub') keeps
    every device and is raised as a bad doctor line, not silently deleted."""
    (senv.state / "heartbeat").write_text(f"{int(__import__('time').time())} boot\n")
    dev = add_device(senv, "anna")
    senv.svc.status_for[dev.endpoint] = 403
    code, _, e = run(capsys, monkeypatch, "push-test", "anna")
    assert code == 1 and "afviste filterets afsender-nøgle" in e and "sfctl doctor" in e
    assert len(push.devices("anna")) == 1
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert "web.push.apple.com afviser filterets afsender-nøgle (403 BadJwtToken" in o
    assert "tjek uret på Unraid" in o
    code, o, _ = run(capsys, monkeypatch, "push-status")
    assert code == 0 and "Afvist:" in o and "403 BadJwtToken" in o
    assert dev.endpoint not in o
    senv.svc.status_for[dev.endpoint] = 201
    code, _, _ = run(capsys, monkeypatch, "push-test", "anna")
    code, o, _ = run(capsys, monkeypatch, "doctor")
    assert code is not None and "afviser filterets" not in o
    # push-reset also forgets a refusal (it belonged to the old key).
    senv.svc.status_for[dev.endpoint] = 403
    run(capsys, monkeypatch, "push-test", "anna")
    assert push.status()["refused"] is not None
    code, _, _ = run(capsys, monkeypatch, "push-reset", answers=["ja"])
    assert code == 0 and push.status()["refused"] is None


def test_sfctl_help_lists_the_push_commands(capsys, monkeypatch):
    import sfctl

    text = sfctl.build_parser().format_help()
    for cmd in ("push-status", "push-test", "push-reset"):
        assert cmd in text
    assert "vapid_private.pem" in sfctl.SENSITIVE


# ---------------------------------------------------------------------------
# Images, build check, context
# ---------------------------------------------------------------------------

PIN_RE = re.compile(r"^(cryptography|cffi|pycparser)==(\d+(?:\.\d+)+)$", re.M)


def test_requirements_pin_cryptography_exactly():
    req = (ROOT / "filter" / "requirements.txt").read_text()
    pins = dict(PIN_RE.findall(req))
    assert set(pins) == {"cryptography", "cffi", "pycparser"}
    import cryptography

    assert cryptography.__version__ == pins["cryptography"]      # tests run against the pinned version
    for line in req.splitlines():
        if line and not line.startswith("#"):
            assert re.fullmatch(r"[A-Za-z0-9_.-]+==[0-9][0-9A-Za-z.]*", line), line


@pytest.mark.parametrize("path,copy", [(ROOT / "filter" / "Dockerfile.unraid", "COPY requirements.txt /tmp/requirements.txt"),
                                       (AIO / "Dockerfile", "COPY filter/requirements.txt /tmp/requirements.txt")])
def test_images_install_exactly_the_pinned_wheels(path, copy):
    text = path.read_text()
    assert copy in text
    assert "grep -E '^(cryptography|cffi|pycparser)==' /tmp/requirements.txt" in text
    assert "--no-deps --only-binary=:all:" in text and "--no-cache-dir" in text
    assert "import cryptography.hazmat.primitives.asymmetric.ec" in text


def test_aio_installs_cryptography_before_the_runtime_library_scan():
    text = (AIO / "Dockerfile").read_text()
    filter_stage = text[text.index("AS filter"):text.index("AS redis")]
    assert filter_stage.index("pip install") < filter_stage.index("ldd {} +")


def test_build_check_imports_the_push_modules_and_round_trips():
    text = (AIO / "build-check.sh").read_text()
    assert re.search(r"import filter, dashboard, .*\bpush, webpush, ui_push\b", text)
    assert "webpush.decrypt(body, ua" in text and "push crypto works" in text


def test_build_context_has_requirements(tmp_path):
    ctx = tmp_path / "ctx"
    env = dict(os.environ, SPAMFILTER_APP=str(tmp_path / "noapp"))
    proc = subprocess.run([str(AIO / "build.sh"), "--context-only", str(ctx)], env=env, capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert (ctx / "filter" / "requirements.txt").read_text() == (ROOT / "filter" / "requirements.txt").read_text()
    staged = {p.name for p in (ctx / "filter").glob("*.py")}
    assert {"push.py", "webpush.py", "ui_push.py"} <= staged


def test_smoke_test_copy_has_no_push_devices_or_key():
    text = (AIO / "smoke-test.sh").read_text()
    assert '"DELETE FROM push_subscriptions"' in text and '"DELETE FROM push_queue"' in text
    assert 'rm -f "$test_app/state/smtp.password" "$test_app/state/vapid_private.pem"' in text


# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------


def test_backup_archives_the_vapid_key_0600(backup_host):
    h = backup_host
    key = h.state / "vapid_private.pem"
    key.write_bytes(b"-----BEGIN PRIVATE KEY-----\nvapid-secret\n-----END PRIVATE KEY-----\n")
    key.chmod(0o600)
    proc = _run_backup(h)
    assert proc.returncode == 0, proc.stderr
    st = json.loads((h.state / "backup-status.json").read_text())
    members = _archive_members(Path(st["archive"]))
    mode, data = members["state/vapid_private.pem"]
    assert mode == 0o600 and data == key.read_bytes()
    assert "vapid_private.pem" in members["meta/secrets"][1].decode().split()
    assert "state/vapid_private.pem" in members["meta/secrets-sha256"][1].decode()
    for text in (proc.stdout, proc.stderr, json.dumps(st)):
        assert "vapid-secret" not in text


def test_backup_without_vapid_key_is_fine(backup_host):
    proc = _run_backup(backup_host)
    assert proc.returncode == 0, proc.stderr
