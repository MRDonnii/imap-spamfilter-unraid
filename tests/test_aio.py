"""2.4 all-in-one container (deploy/aio): image, runtime config, health,
Unraid template and the build / smoke-test / migrate / rollback / cleanup /
update scripts.

No docker is used: the scripts run against tests/fakes_deploy.py (fake
docker/curl on PATH, container state in a JSON file) or their functions are
called through lib.sh like tests/test_deploy_scripts.py does.
"""

from __future__ import annotations

import configparser
import json
import os
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
AIO = DEPLOY / "aio"
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(AIO))
from fakes_deploy import base_env, install_fake_bin, read_state, write_state  # noqa: E402

import aio_render as render  # noqa: E402

AIO_SCRIPTS = ["build.sh", "smoke-test.sh", "migrate.sh", "rollback.sh", "cleanup.sh", "update.sh"]
AIO_SHELL = AIO_SCRIPTS + ["restore-stack-drill.sh", "lib-aio.sh", "build-check.sh", "sf-entrypoint", "sf-run", "sf-fatal-listener",
                           "sf-clamav"]
AIO_IMG = "imap-spamfilter-unraid:2.16.0"
AIO_LABELS = {"spamfilter.layout": "aio", "spamfilter.version": "2.16.0"}


def versions() -> dict[str, str]:
    out = {}
    for line in (DEPLOY / "versions.env").read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            k, _, v = line.partition("=")
            out[k] = v
    return out


def dockerfile_args() -> dict[str, str]:
    out = {}
    for m in re.finditer(r"^ARG (\w+)=(\S*)$", (AIO / "Dockerfile").read_text(), re.M):
        out[m.group(1)] = m.group(2)
    return out


# ================================================================ static

@pytest.mark.parametrize("name", AIO_SHELL)
def test_aio_shell_syntax_and_strict_mode(name):
    path = AIO / name
    subprocess.run(["bash", "-n", str(path)], check=True)
    text = path.read_text()
    assert text.startswith("#!/bin/bash\n"), name
    if name not in ("lib-aio.sh", "sf-fatal-listener"):
        assert re.search(r"^set -E?euo pipefail$", text, re.M), name
    assert os.access(path, os.X_OK) or name == "lib-aio.sh", name


@pytest.mark.parametrize("name", AIO_SCRIPTS)
def test_aio_scripts_offer_dry_run_and_help(name):
    text = (AIO / name).read_text()
    assert "--dry-run) export DRY_RUN=1 ;;" in text
    assert '. "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"' in text
    usage = subprocess.run(["bash", str(AIO / name), "--help"], capture_output=True, text=True)
    assert usage.returncode == 0 and "set -euo" not in usage.stdout and usage.stdout.strip()


def test_aio_shellcheck_clean():
    sc = shutil.which("shellcheck")
    if not sc:
        pytest.skip("shellcheck not installed")
    files = [str((AIO / n).relative_to(ROOT)) for n in AIO_SHELL] + ["deploy/aio/sfctl-aio", "deploy/aio/sf-health"]
    subprocess.run([sc, "-x", *files], cwd=ROOT, check=True)


def test_dockerfile_pins_match_versions_env():
    v, a = versions(), dockerfile_args()
    assert a["FILTER_BASE_IMAGE"] == v["FILTER_BASE_IMAGE"]
    # The SAME rspamd digest as the 4-container layout: rspamd stays identical.
    assert a["RSPAMD_IMAGE"] == v["RSPAMD_IMAGE"]
    assert re.search(r"@sha256:[0-9a-f]{64}$", a["RSPAMD_IMAGE"])
    # Redis build image pinned by digest (the release refuses to publish without it)
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", v["REDIS_AIO_DIGEST"])
    assert a["REDIS_IMAGE"] == f"redis:{v['REDIS_AIO_TAG']}@{v['REDIS_AIO_DIGEST']}"
    assert a["AIO_VERSION"] == v["VERSION"] == "2.16.0"
    assert a["EXPECT_RSPAMD"] == v["AIO_RSPAMD_VERSION"] == "4.2.2"
    assert a["EXPECT_REDIS"] == v["AIO_REDIS_VERSION"] == "8.10.3"
    assert a["EXPECT_UNBOUND"] == v["AIO_UNBOUND_SERIES"] == "1.26"
    assert a["EXPECT_PYTHON"] == v["AIO_PYTHON_SERIES"] == "3.14"
    assert a["EXPECT_CLAMAV_MIN"] == v["AIO_CLAMAV_MIN"] == "1.4.6"
    assert v["AIO_IMAGE"] == AIO_IMG


def test_dockerfile_contract():
    text = (AIO / "Dockerfile").read_text()
    froms = re.findall(r"^FROM (\S+)(?: AS (\w+))?$", text, re.M)
    assert froms == [("${FILTER_BASE_IMAGE}", "filter"), ("${REDIS_IMAGE}", "redis"), ("${RSPAMD_IMAGE}", "")]
    # the filter stage is filter/Dockerfile.unraid's app (no tests in /app)
    for needle in ("COPY filter/*.py /app/", "COPY filter/static/ /app/static/", "favicon.png",
                   "familieguide.pdf", "rm -f /app/test_*.py", "chown -R root:root /app"):
        assert needle in text, needle
    # rspamd untouched: nothing under /usr/local before the copy, manifest, held package
    assert "find /usr/local -mindepth 1 -type f" in text and "rspamd.sha256" in text
    assert "apt-mark hold rspamd" in text and "apt-get upgrade" not in text
    for pkg in ("tini", "supervisor", "unbound", "dns-root-data", "ldnsutils", "ca-certificates", "tzdata"):
        assert re.search(rf"\b{pkg}\b", text), pkg
    assert "COPY --from=redis /usr/local/bin/redis-server /usr/local/bin/redis-cli /usr/local/bin/" in text
    assert 'ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/sf-entrypoint"]' in text
    assert 'CMD ["/usr/local/bin/sf-health", "check"]' in text
    assert re.search(r"^HEALTHCHECK --interval=30s --timeout=25s --start-period=180s --retries=3", text, re.M)
    assert re.search(r"^EXPOSE 8080$", text, re.M) and len(re.findall(r"^EXPOSE", text, re.M)) == 1
    assert 'spamfilter.layout="aio"' in text
    assert "build-check.sh" in text and "ENV SPAMFILTER_AIO=1" in text
    for env in ("RSPAMD_SCAN_URL=http://127.0.0.1:11333/checkv2", "RSPAMD_LEARN_URL=http://127.0.0.1:11334",
                "LOOKALIKE_DNS_SERVER=127.0.0.1", "STATE_DIR=/state", "CONFIG_PATH=/config/accounts.yml"):
        assert env in text, env
    # the old container paths are links into /appdata; uids of the 4 containers
    for link in ("ln -s /appdata/state /state", "ln -s /appdata/config /config", "ln -s /appdata/redis /data",
                 "ln -s /appdata/redis-config /usr/local/etc/redis",
                 "ln -s /run/spamfilter/rspamd/local.d /etc/rspamd/local.d"):
        assert link in text, link
    assert "--uid 10099 --gid 10099" in text and "--uid 999 --gid 1000" in text
    # /var/lib/rspamd is the base image's VOLUME: never replaced by a link
    assert not re.search(r"(ln -s\S*|rm -rf)[^\n;]*/var/lib/rspamd", re.sub(r"#.*", "", text))
    # classic builder compatible: no BuildKit-only syntax
    for bk in ("--mount", "--chmod", "--link", "<<EOF", "# syntax="):
        assert bk not in text, bk


def test_build_check_asserts_versions_uids_and_loopback():
    text = (AIO / "build-check.sh").read_text()
    for needle in ('"$(uidgid 10099)" == 10099:10099', '"$(uidgid 11333)" == 11333:11333',
                   '"$(uidgid 999)" == 999:1000', "sha256sum --quiet -c", "dpkg --verify rspamd",
                   "rspamadm configtest", "rspamadm configdump -j", "check-binds", "unbound-checkconf",
                   "not found", "EXPECT_RSPAMD", "EXPECT_REDIS", "EXPECT_UNBOUND", "EXPECT_PYTHON"):
        assert needle in text, needle


def test_supervisord_conf_programs_uids_order_and_logs():
    cp = configparser.RawConfigParser()
    cp.read(AIO / "supervisord.conf")
    progs = {s.split(":", 1)[1]: cp[s] for s in cp.sections() if s.startswith("program:")}
    assert set(progs) == {"redis", "unbound", "rspamd", "filter", "clamd", "freshclam", "sigs"}
    assert {n: p["user"] for n, p in progs.items()} == {"redis": "999", "unbound": "unbound",
                                                         "rspamd": "11333", "filter": "10099",
                                                         "clamd": "3310", "freshclam": "3310", "sigs": "3310"}
    order = sorted(progs, key=lambda n: int(progs[n]["priority"]))
    assert order == ["redis", "unbound", "rspamd", "clamd", "freshclam", "sigs", "filter"]
    for name, p in progs.items():
        assert p["autorestart"] == "true" and p["stopsignal"] == "TERM", name
        assert p["stdout_logfile"] == "/dev/fd/1" and p["redirect_stderr"] == "true", name
        assert p["command"].startswith(f"/usr/local/bin/sf-run {name} "), name
        assert p["killasgroup"] == "true" and p["stopasgroup"] == "false", name
    assert "--wait redis --wait unbound --" in progs["rspamd"]["command"]
    assert "--wait rspamd --wait clamav --" in progs["filter"]["command"]  # 2.7 fix: clamd too (bounded)
    assert int(progs["filter"]["stopwaitsecs"]) >= 30 and int(progs["redis"]["stopwaitsecs"]) >= 20
    assert "--bind 127.0.0.1 -::1 --port 6379" in progs["redis"]["command"]
    assert "/usr/local/etc/redis/redis.conf" in progs["redis"]["command"]
    assert "-c /run/spamfilter/unbound/unbound.conf" in progs["unbound"]["command"]
    # 2.7 ClamAV: started only when the entrypoint says so (SF_CLAMAV), through sf-clamav
    for name in ("clamd", "freshclam"):
        assert progs[name]["autostart"] == "%(ENV_SF_CLAMAV_AUTOSTART)s", name
        assert progs[name]["command"] == f"/usr/local/bin/sf-run {name} -- /usr/local/bin/sf-clamav {name}", name
    # 2.8 (A1): Sanesecurity signatures, only with ClamAV
    assert progs["sigs"]["autostart"] == "%(ENV_SF_CLAMAV_AUTOSTART)s"
    assert progs["sigs"]["command"] == "/usr/local/bin/sf-run sigs -- /usr/local/bin/sf-sigs"
    for name in ("redis", "unbound", "rspamd", "filter"):
        assert progs[name]["autostart"] == "true", name
    assert cp["eventlistener:sf-fatal"]["events"] == "PROCESS_STATE_FATAL"
    assert cp["supervisord"]["nodaemon"] == "true" and cp["unix_http_server"]["chmod"] == "0700"
    # docker stop must outlast the ordered shutdown
    stop_sum = sum(int(p["stopwaitsecs"]) for p in progs.values())
    assert "--stop-timeout 90" in (AIO / "lib-aio.sh").read_text() and stop_sum <= 120


def test_entrypoint_never_rewrites_or_chowns_the_app_dir():
    text = (AIO / "sf-entrypoint").read_text()
    code = re.sub(r"#.*", "", text)
    # The only chowns: (2.7) the NEW ClamAV signature dir it just created,
    # inside rundir(), which refuses anything outside $RUN_DIR (the tmpfs),
    # and (2.6) the EMPTY root-owned /backup top dir, which may never lie
    # inside the app dir: nothing that already exists in the app dir is chowned.
    chowns = re.findall(r"(?:^\s*|[;&|(]\s*)chown\s+(.*)$", code, re.M)
    assert chowns == ['"$CLAMAV_UID:$CLAMAV_UID" "$CLAMAV_DB"; then', '"$1" "$3"', '10099:10099 "$BACKUP"'], chowns
    assert 'CLAMAV_DB="$APPDATA/clamav"' in code and "CLAMAV_UID=3310" in code
    assert re.search(r'elif \[\[ ! -e "\$CLAMAV_DB" \]\]; then\s+#[^\n]*\n\s+if mkdir "\$CLAMAV_DB"', text)
    assert '"$APPDATA"/*) die' in code and '-z "$(ls -A "$BACKUP" 2>/dev/null)"' in code
    assert '[[ "$3" == "$RUN_DIR/"* ]] || die' in code
    assert 'rundir 11333:11333 0750 "$RUN_DIR/rspamd"' in code
    assert 'rundir unbound:unbound 0750 "$RUN_DIR/unbound"' in code
    assert 'mountpoint -q "$APPDATA"' in code and 'same_dir 11333 11333 "$RSPAMD_DB"' in code
    assert "RSPAMD_DB=${SF_AIO_RSPAMD_DB:-/var/lib/rspamd}" in code and "APPDATA=${SF_AIO_APPDATA:-/appdata}" in code
    for need in ('need 10099 10099 -w "$APPDATA/state"', 'need 999 1000 -r "$APPDATA/redis-config/redis.conf"',
                 'need 11333 11333 -r "$APPDATA/rspamd/local.d/redis.conf"'):
        assert need in code, need
    assert 'as 11333 11333 "$PY" -s -E "$LIB/aio_render.py" rspamd' in code
    assert "unbound-checkconf" in code and "rspamadm configtest" in code
    assert code.rstrip().endswith('exec "$SUPERVISORD" -n -c /etc/spamfilter/supervisord.conf')
    # every write goes to the runtime dir; the app dir is only read (or initialised when empty)
    for m in re.finditer(r"--dst \"([^\"]+)\"", code):
        assert m.group(1).startswith("$RUN_DIR/"), m.group(1)


def _entrypoint_env(tmp_path, app):
    """Fake root tools so sf-entrypoint runs unprivileged: setpriv runs what
    follows "--", install ignores -o/-g, id -u says 0; the validators and
    supervisord only record their arguments."""
    bindir = tmp_path / "ebin"
    bindir.mkdir()
    log = tmp_path / "tools.log"
    tools = {
        "setpriv": '#!/bin/bash\nwhile [[ "$1" != -- ]]; do shift; done; shift; exec "$@"\n',
        "chown": "#!/bin/bash\nexit 0\n",
        "install": ('#!/bin/bash\nargs=()\nwhile (( $# )); do case "$1" in -o|-g) shift 2 ;; '
                    '*) args+=("$1"); shift ;; esac; done\nexec /usr/bin/install "${args[@]}"\n'),
        "id": '#!/bin/bash\n[[ "$1" == -u ]] && { echo 0; exit 0; }\nexec /usr/bin/id "$@"\n',
        "mountpoint": '#!/bin/bash\nexit 0\n',
        "unbound-checkconf": f'#!/bin/bash\necho "checkconf $*" >>"{log}"\ngrep -q "interface: 127.0.0.1@5353" "$1"\n',
        "rspamadm": f'#!/bin/bash\necho "rspamadm $*" >>"{log}"\necho "syntax OK"\n',
        "supervisord": f'#!/bin/bash\necho "supervisord $*" >>"{log}"\n',
    }
    for name, body in tools.items():
        (bindir / name).write_text(body)
        (bindir / name).chmod(0o755)
    share = tmp_path / "share"
    (share / "rspamd").mkdir(parents=True)
    shutil.copy(DEPLOY / "unbound.conf", share / "unbound.conf")
    (share / "VERSION").write_text("2.4.0\n")
    key = tmp_path / "root.key"
    key.write_text(". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n")
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", SF_AIO_APPDATA=str(app),
               SF_AIO_RUN_DIR=str(tmp_path / "run"), SF_AIO_LIB=str(AIO), SF_AIO_SHARE=str(share),
               SF_AIO_PY=sys.executable, SF_AIO_RSPAMD_DB=str(app / "rspamd" / "data"),
               SF_AIO_ROOT_KEY=str(key), SF_AIO_SUPERVISORD=str(bindir / "supervisord"))
    return env, log


def _live_appdata(tmp_path) -> Path:
    app = tmp_path / "app"
    for d in ("state", "config", "redis", "redis-config", "rspamd/local.d/maps.d", "rspamd/data", "operations"):
        (app / d).mkdir(parents=True)
    (app / "config" / "accounts.yml").write_text((DEPLOY / "accounts.yml").read_text())
    # the local site configuration a live (migrated) install has
    (app / "config" / "site.yml").write_text((Path(__file__).with_name("site.yml")).read_text())
    (app / "redis-config" / "redis.conf").write_text('dir /data\nrequirepass "S3CRET-redis-pw"\n')
    (app / "state" / "redis.password").write_text("S3CRET-redis-pw\n")
    ld = app / "rspamd" / "local.d"
    (ld / "redis.conf").write_text(LIVE_REDIS)
    (ld / "worker-controller.inc").write_text(LIVE_CTRL)
    for f in ("options.inc", "worker-normal.inc", "actions.conf", "classifier-bayes.conf"):
        shutil.copy(ROOT / "rspamd" / "local.d" / f, ld / f)
    shutil.copy(DEPLOY / "unbound.conf", app / "unbound.conf")
    return app


def test_entrypoint_renders_runtime_config_and_leaves_the_app_dir_untouched(tmp_path):
    app = _live_appdata(tmp_path)
    before = _snapshot(app)
    env, log = _entrypoint_env(tmp_path, app)
    proc = subprocess.run([str(AIO / "sf-entrypoint")], env=env, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _snapshot(app) == before  # nothing in the shared app dir changed
    run = tmp_path / "run"
    assert 'servers = "127.0.0.1:6379";' in (run / "rspamd" / "local.d" / "redis.conf").read_text()
    assert 'nameserver = ["127.0.0.1:5353"];' in (run / "rspamd" / "local.d" / "options.inc").read_text()
    assert "interface: 127.0.0.1@5353" in (run / "unbound" / "unbound.conf").read_text()
    ctrl = (run / "rspamd" / "local.d" / "worker-controller.inc").read_text()
    assert re.findall(r'^\s*secure_ip.*$', ctrl, re.M) == [render.SECURE_IP_LINE]
    assert 'secure_ip = "127.0.0.1"' in (app / "rspamd" / "local.d" / "worker-controller.inc").read_text()
    assert (run / "unbound" / "root.key").exists() and (run / "run").stat().st_mode & 0o1777 == 0o1777
    calls = log.read_text().splitlines()
    assert calls[0].startswith("checkconf ") and calls[1] == "rspamadm configtest"
    assert calls[-1] == "supervisord -n -c /etc/spamfilter/supervisord.conf"
    out = proc.stdout + proc.stderr
    assert "S3CRET" not in out and "[init] Spamfilter all-in-one 2.4.0 starting" in out
    assert "rspamd configtest: syntax OK" in out


@pytest.mark.parametrize("breakage,msg", [
    ("redis-conf", "rspamd Redis client config"),
    ("rspamd-db", "is not"),
    ("configtest", "rspamadm configtest failed"),
])
def test_entrypoint_refuses_to_start_on_a_broken_layout(tmp_path, breakage, msg):
    app = _live_appdata(tmp_path)
    env, log = _entrypoint_env(tmp_path, app)
    if breakage == "redis-conf":
        (app / "rspamd" / "local.d" / "redis.conf").unlink()
    elif breakage == "rspamd-db":
        other = tmp_path / "anon-volume"
        other.mkdir()
        env["SF_AIO_RSPAMD_DB"] = str(other)
    else:
        (Path(env["PATH"].split(":")[0]) / "rspamadm").write_text(
            '#!/bin/bash\necho "line 3: password = \\"S3CRET-x\\" bad"\necho "config error"\nexit 1\n')
    proc = subprocess.run([str(AIO / "sf-entrypoint")], env=env, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 1 and msg in proc.stderr
    assert "S3CRET" not in proc.stdout + proc.stderr
    assert "supervisord" not in (log.read_text() if log.exists() else "")


def test_sfctl_wrapper_drops_root_to_the_filter_uid():
    text = (AIO / "sfctl-aio").read_text()
    assert "exec setpriv --reuid=10099 --regid=10099 --clear-groups -- /usr/local/bin/python -s -E /app/sfctl.py" in text
    assert '[ "$a" = --allow-root ]' in text


# ================================================================ rspamd render

LIVE_REDIS = '''# rspamd Redis client config.
servers = "spamfilter-redis:6379";
timeout = 1s;
password = "S3CRET-redis-pw";
'''
LIVE_CTRL = '''bind_socket = "*:11334";
password = "S3CRET-ctrl";
enable_password = "S3CRET-ctrl";
secure_ip = "127.0.0.1";
'''


@pytest.fixture
def local_d(tmp_path):
    src = tmp_path / "local.d"
    (src / "maps.d").mkdir(parents=True)
    (src / "redis.conf").write_text(LIVE_REDIS)
    (src / "worker-controller.inc").write_text(LIVE_CTRL)
    for name in ("options.inc", "worker-normal.inc", "actions.conf", "classifier-bayes.conf"):
        shutil.copy(ROOT / "rspamd" / "local.d" / name, src / name)
    shutil.copy(ROOT / "rspamd" / "local.d" / "maps.d" / "th_brand_domains.map", src / "maps.d")
    (src / "elsewhere").write_text("outside\n")
    (src / "link.conf").symlink_to(src / "elsewhere")
    for p in src.rglob("*"):
        if p.is_file() and not p.is_symlink():
            p.chmod(0o640)
    return src


def _snapshot(d: Path) -> dict[str, tuple[bytes, int]]:
    return {str(p.relative_to(d)): (p.read_bytes(), p.stat().st_mtime_ns)
            for p in d.rglob("*") if p.is_file() and not p.is_symlink()}


def test_render_rspamd_points_everything_at_loopback_and_leaves_the_source(local_d, tmp_path):
    before = _snapshot(local_d)
    dst = tmp_path / "run" / "local.d"
    changes = render.render_rspamd(local_d, dst)
    assert _snapshot(local_d) == before  # shared file untouched (rollback keeps working)
    redis = (dst / "redis.conf").read_text()
    assert 'servers = "127.0.0.1:6379";' in redis and 'password = "S3CRET-redis-pw";' in redis
    assert 'nameserver = ["127.0.0.1:5353"];' in (dst / "options.inc").read_text()
    assert 'bind_socket = "127.0.0.1:11334";' in (dst / "worker-controller.inc").read_text()
    # one container = one shared loopback: no program may skip the controller password
    ctrl = (dst / "worker-controller.inc").read_text()
    assert 'secure_ip = "192.0.2.1";' in ctrl and "127.0.0.1\";" not in ctrl.split("secure_ip", 1)[1]
    assert 'bind_socket = "127.0.0.1:11333";' in (dst / "worker-normal.inc").read_text()
    assert (dst / "maps.d" / "th_brand_domains.map").read_bytes() == (local_d / "maps.d" / "th_brand_domains.map").read_bytes()
    assert (dst / "classifier-bayes.conf").read_bytes() == (local_d / "classifier-bayes.conf").read_bytes()
    assert not (dst / "link.conf").exists()  # links are never followed out of local.d
    assert {"redis.conf", "options.inc", "worker-controller.inc", "worker-normal.inc"} <= set(changes)
    for p in dst.rglob("*"):
        if p.is_file():
            assert p.stat().st_mode & 0o777 == 0o640
            for host in render.OLD_HOSTS:
                assert host not in p.read_text(errors="replace")


def test_render_rspamd_rerender_replaces_a_stale_copy(local_d, tmp_path):
    dst = tmp_path / "run" / "local.d"
    render.render_rspamd(local_d, dst)
    (dst / "stale.conf").write_text("old\n")
    (local_d / "options.inc").write_text('dns {\n    nameserver = ["spamfilter-unbound"];\n}\n')
    render.render_rspamd(local_d, dst)
    assert not (dst / "stale.conf").exists()
    assert 'nameserver = ["127.0.0.1:5353"];' in (dst / "options.inc").read_text()


def test_render_rspamd_refuses_without_redis_conf(local_d, tmp_path):
    (local_d / "redis.conf").unlink()
    with pytest.raises(render.RenderError, match="redis.conf missing"):
        render.render_rspamd(local_d, tmp_path / "dst")
    (local_d / "redis.conf").write_text('password = "x";\n')
    with pytest.raises(render.RenderError, match="no servers line"):
        render.render_rspamd(local_d, tmp_path / "dst")


def test_render_cli_never_prints_secrets(local_d, tmp_path):
    proc = subprocess.run([sys.executable, str(AIO / "aio_render.py"), "rspamd", "--src", str(local_d),
                           "--dst", str(tmp_path / "dst")], capture_output=True, text=True, check=True)
    out = proc.stdout + proc.stderr
    assert "redis.conf" in out and "S3CRET" not in out
    bad = subprocess.run([sys.executable, str(AIO / "aio_render.py"), "rspamd", "--src", str(tmp_path / "nope"),
                          "--dst", str(tmp_path / "dst2")], capture_output=True, text=True)
    assert bad.returncode == 1 and "ERROR" in bad.stderr


@pytest.mark.parametrize("line,want", [
    ('bind_socket = "*:11334";', 'bind_socket = "127.0.0.1:11334";'),
    ('bind_socket = "0.0.0.0:11333";', 'bind_socket = "127.0.0.1:11333";'),
    ('bind_socket = "*v4:11332";', 'bind_socket = "127.0.0.1:11332";'),
    ('bind_socket = "[::]:11335";', 'bind_socket = "127.0.0.1:11335";'),
    ('bind_socket = "localhost:11333";', 'bind_socket = "localhost:11333";'),
])
def test_render_bind_sockets(line, want):
    assert render.render_rspamd_text("worker-normal.inc", line + "\n")[0] == want + "\n"


def test_harden_override_and_check_binds(tmp_path):
    d = tmp_path / "override.d"
    d.mkdir()
    (d / "worker-controller.inc").write_text('bind_socket = "*:11334";\n')
    (d / "worker-proxy.inc").write_text('bind_socket = "*:11332";\nmilter = yes;\n')
    (d / "logging.inc").write_text('type = "console";\n')
    written = render.harden_override(d)
    assert set(written) == {"worker-controller.inc", "worker-normal.inc", "worker-proxy.inc", "worker-fuzzy.inc"}
    assert (d / "worker-controller.inc").read_text() == ('bind_socket = "127.0.0.1:11334";\n'
                                                         + render.SECURE_IP_LINE + "\n")
    assert (d / "worker-normal.inc").read_text() == 'bind_socket = "127.0.0.1:11333";\n'
    assert (d / "worker-proxy.inc").read_text() == 'bind_socket = "127.0.0.1:11332";\nmilter = yes;\n'
    # The base rspamd.conf also defines proxy and fuzzy storage on "*" (found by the
    # real build check): both are pinned even without an override file of their own.
    assert (d / "worker-fuzzy.inc").read_text() == 'bind_socket = "127.0.0.1:11335";\n'
    assert (d / "logging.inc").read_text() == 'type = "console";\n'
    assert render.harden_override(d) == []  # idempotent
    dump = {"worker": [{"type": "normal", "bind_socket": "127.0.0.1:11333"},
                       {"type": "controller", "bind_socket": ["localhost:11334"]},
                       {"type": "fuzzy", "bind_socket": "*:11335"}]}
    assert render.check_binds(dump) == ["*:11335"]
    assert render.check_binds({"worker": {"x": {"bind_socket": "[::1]:11334"}}}) == []
    assert render.check_binds({}) == ["(no bind_socket found)"]
    f = tmp_path / "dump.json"
    f.write_text(json.dumps(dump))
    proc = subprocess.run([sys.executable, str(AIO / "aio_render.py"), "check-binds", str(f)],
                          capture_output=True, text=True)
    assert proc.returncode == 1 and "*:11335" in proc.stderr


# ================================================================ unbound render

def test_render_unbound_from_the_repo_config(tmp_path):
    run_dir = tmp_path / "unbound"
    key = tmp_path / "root.key"
    key.write_text(". IN DS 20326 8 2 abc\n")
    used = render.render_unbound(DEPLOY / "unbound.conf", tmp_path / "missing.conf", run_dir / "unbound.conf",
                                 run_dir, root_key=key, site={"dns_forwarders": ["192.168.1.1"]})
    assert used == "appdata"
    text = (run_dir / "unbound.conf").read_text()
    assert re.findall(r"^\s*interface:.*$", text, re.M) == ["    interface: 127.0.0.1@5353"]
    assert re.findall(r"^\s*port:.*$", text, re.M) == ["    port: 5353"]
    assert '    chroot: ""' in text and '    username: ""' in text
    assert f'    directory: "{run_dir}"' in text and f'auto-trust-anchor-file: "{run_dir}/root.key"' in text
    code = re.sub(r"#.*", "", text)
    assert 'chroot: "/opt/unbound' not in code and 'username: "_unbound"' not in code
    assert 'directory: "/opt/unbound' not in code
    assert "forward-addr: 192.168.1.1" in text and "log-servfail: yes" in text
    assert "private-address: 127." not in text
    assert (run_dir / "root.key").read_text() == key.read_text()
    # the rest of the config is kept line for line
    src_keys = [ln.strip() for ln in (DEPLOY / "unbound.conf").read_text().splitlines()
                if ln.strip() and not ln.strip().startswith("#")
                and ln.strip().split(":")[0] not in render.REPLACED]
    for ln in src_keys:
        assert ln in text, ln


def test_render_unbound_fallback_and_forward_records(tmp_path):
    base = tmp_path / "image-unbound.conf"
    base.write_text("server:\n    interface: 0.0.0.0@53\n    username: \"_unbound\"\n    verbosity: 1\n")
    fwd = tmp_path / "unbound-forward-records.conf"
    fwd.write_text('forward-zone:\n    name: "."\n    forward-addr: 192.168.1.1\n')
    dst = tmp_path / "run" / "unbound.conf"
    used = render.render_unbound(tmp_path / "absent.conf", base, dst, tmp_path / "run", forward=fwd)
    assert used == "image"
    text = dst.read_text()
    assert "0.0.0.0@53" not in text and "interface: 127.0.0.1@5353" in text and "verbosity: 1" in text
    assert text.count("forward-zone:") == 1 and "forward-addr: 192.168.1.1" in text
    # a config that has its own forward-zone never gets a second one
    text2 = render.render_unbound_text((DEPLOY / "unbound.conf").read_text(), "/r", fwd.read_text())
    assert text2.count("forward-zone:") == 1
    # no server: clause at all -> one is added
    assert render.render_unbound_text("forward-zone:\n    name: \".\"\n", "/r").startswith("server:\n")


# ================================================================ fresh app dir

def _bundle(tmp_path) -> Path:
    b = tmp_path / "bundle"
    if b.exists():
        return b
    (b / "rspamd" / "maps.d").mkdir(parents=True)
    shutil.copy(ROOT / "redis" / "redis.conf.template", b / "redis.conf.template")
    shutil.copy(AIO / "accounts.seed.yml", b / "accounts.seed.yml")
    shutil.copy(AIO / "site.seed.yml", b / "site.seed.yml")
    for f in (ROOT / "rspamd" / "local.d").iterdir():
        if f.is_file() and f.name not in ("redis.conf", "worker-controller.inc"):
            shutil.copy(f, b / "rspamd" / f.name)
    for f in (ROOT / "rspamd" / "local.d" / "maps.d").iterdir():
        shutil.copy(f, b / "rspamd" / "maps.d" / f.name)
    return b


def test_init_creates_the_four_container_layout_with_matching_secrets(tmp_path, capsys):
    app = tmp_path / "app"
    app.mkdir()
    assert render.init_appdata(app, _bundle(tmp_path), chown=False) is True
    redis_pw = (app / "state" / "redis.password").read_text().strip()
    ctrl_pw = (app / "state" / "controller.password").read_text().strip()
    assert re.fullmatch(r"[0-9a-f]{64}", redis_pw) and re.fullmatch(r"[0-9a-f]{64}", ctrl_pw)
    assert f'requirepass "{redis_pw}"' in (app / "redis-config" / "redis.conf").read_text()
    assert f'password = "{redis_pw}";' in (app / "rspamd" / "local.d" / "redis.conf").read_text()
    assert f'password = "{ctrl_pw}";' in (app / "rspamd" / "local.d" / "worker-controller.inc").read_text()
    assert "${" not in (app / "redis-config" / "redis.conf").read_text()
    for f in ("state/redis.password", "state/controller.password", "config/accounts.yml",
              "redis-config/redis.conf", "rspamd/local.d/redis.conf", "rspamd/local.d/worker-controller.inc"):
        assert (app / f).stat().st_mode & 0o777 == 0o600, f
    for d in ("state", "state/imap-secrets", "config", "redis", "redis-config", "operations"):
        assert (app / d).stat().st_mode & 0o777 == 0o700, d
    assert (app / "rspamd" / "local.d" / "actions.conf").exists()
    assert (app / "rspamd" / "local.d" / "maps.d" / "th_brand_domains.map").exists()
    assert "enabled = false;" in (app / "rspamd" / "local.d" / "fuzzy_check.conf").read_text()
    assert "accounts: []" in (app / "config" / "accounts.yml").read_text()
    out = capsys.readouterr()
    assert redis_pw not in out.out + out.err


def test_init_accepts_the_rspamd_data_dir_docker_created(tmp_path):
    app = tmp_path / "app"
    (app / "rspamd" / "data").mkdir(parents=True)  # -v <app>/rspamd/data:/var/lib/rspamd
    assert render.init_appdata(app, _bundle(tmp_path), chown=False) is True
    assert (app / "rspamd" / "local.d" / "redis.conf").is_file()
    assert (app / "rspamd" / "local.d" / "worker-controller.inc").is_file()


def test_init_never_touches_an_existing_or_partial_install(tmp_path):
    app = tmp_path / "app"
    (app / "state").mkdir(parents=True)
    (app / "state" / "keep").write_text("live\n")
    assert render.init_appdata(app, _bundle(tmp_path), chown=False) is False
    assert sorted(p.name for p in app.rglob("*")) == ["keep", "state"]
    partial = tmp_path / "partial"
    (partial / "rspamd" / "local.d").mkdir(parents=True)
    (partial / "rspamd" / "local.d" / "redis.conf").write_text("x\n")
    with pytest.raises(render.RenderError, match="partial install"):
        render.init_appdata(partial, _bundle(tmp_path), chown=False)
    assert not (partial / "state").exists()


def test_init_cli_output_has_no_secret(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    proc = subprocess.run([sys.executable, str(AIO / "aio_render.py"), "init", "--appdata", str(app),
                           "--bundle", str(_bundle(tmp_path)), "--no-chown"], capture_output=True, text=True,
                          check=True)
    pw = (app / "state" / "redis.password").read_text().strip()
    assert "fresh app dir initialised" in proc.stdout and pw not in proc.stdout + proc.stderr
    again = subprocess.run([sys.executable, str(AIO / "aio_render.py"), "init", "--appdata", str(app),
                            "--bundle", str(_bundle(tmp_path)), "--no-chown"], capture_output=True, text=True,
                           check=True)
    assert again.stdout == "" and (app / "state" / "redis.password").read_text().strip() == pw


# ================================================================ sf-run / fatal listener

def test_sf_run_prefixes_lines_backs_off_and_waits(tmp_path):
    state = tmp_path / "run"
    state.mkdir()
    health = tmp_path / "sf-health"
    health.write_text('#!/bin/bash\necho "health $*" >>"' + str(tmp_path / "health.log") + '"\nexit 1\n')
    health.chmod(0o755)
    env = dict(os.environ, SF_RUN_STATE_DIR=str(state), SF_HEALTH=str(health), SF_BACKOFF_MAX="0",
               SF_WAIT_TIMEOUT="7")
    proc = subprocess.run([str(AIO / "sf-run"), "rspamd", "--wait", "redis", "--wait", "unbound", "--",
                           "sh", "-c", "echo one; echo two >&2"], env=env, capture_output=True, text=True,
                          timeout=30)
    assert proc.returncode == 0
    lines = proc.stdout.splitlines()
    assert "[rspamd] one" in lines and "[rspamd] two" in lines
    assert "[rspamd] redis unbound not ready after 7 s - starting anyway" in lines
    assert (tmp_path / "health.log").read_text().strip() == "health wait --timeout 7 redis unbound"
    # a second start within a minute backs off
    proc = subprocess.run([str(AIO / "sf-run"), "rspamd", "--", "true"], env=env, capture_output=True, text=True,
                          timeout=30)
    assert "restarted 1x within a minute" in proc.stdout
    stamp, count = (state / "rspamd").read_text().split()
    assert count == "1" and abs(int(stamp) - time.time()) < 30
    bad = subprocess.run([str(AIO / "sf-run"), "x"], env=env, capture_output=True, text=True)
    assert bad.returncode == 2


def test_sf_fatal_listener_stops_supervisord(tmp_path):
    victim = subprocess.Popen(["sleep", "60"])
    pidfile = tmp_path / "supervisord.pid"
    pidfile.write_text(f"{victim.pid}\n")
    payload = "processname:rspamd groupname:rspamd from_state:BACKOFF"
    header = f"ver:3.0 server:supervisor serial:1 pool:sf-fatal poolserial:1 eventname:PROCESS_STATE_FATAL len:{len(payload)}\n"
    proc = subprocess.run([str(AIO / "sf-fatal-listener")], input=header + payload,
                          env=dict(os.environ, SF_SUPERVISOR_PIDFILE=str(pidfile)),
                          capture_output=True, text=True, timeout=20)
    assert proc.stdout == "READY\nRESULT 2\nOKREADY\n"
    assert "rspamd cannot be started (FATAL)" in proc.stderr
    assert victim.wait(timeout=10) != 0


# ================================================================ deploy-script host

@pytest.fixture
def host(tmp_path):
    app = tmp_path / "app"
    for sub in ("operations", "state", "config", "rspamd/local.d", "rspamd/data", "redis", "redis-config"):
        (app / sub).mkdir(parents=True)
    bindir = tmp_path / "bin"
    install_fake_bin(bindir)
    env = base_env(tmp_path, bindir)
    tpl = tmp_path / "templates-user"
    tpl.mkdir()
    autostart = tmp_path / "unraid-autostart"
    autostart.write_text("spamfilter-redis\nspamfilter-unbound\nspamfilter-rspamd\nspamfilter\nplex\n")
    env.update(SPAMFILTER_APP=str(app), SF_POLL="0", SF_GATE_TIMEOUT="3", SF_AIO_GATE_TIMEOUT="3",
               SF_GATE_MIN_UPTIME="0", SPAMFILTER_URL="http://fake", DOCKERMAN_TEMPLATES=str(tpl),
               SF_AUTOSTART_FILE=str(autostart), SF_DOCKER_ROOT=str(tmp_path), SF_MIN_FREE_MB="1",
               FAKE_CURL_CALLS=str(tmp_path / "curl.log"))
    env.pop("SF_HA_TOKEN", None)
    write_state(Path(env["FAKE_DOCKER_STATE"]), {})

    class Host:
        pass
    h = Host()
    h.tmp, h.app, h.bin, h.env, h.tpl, h.autostart = tmp_path, app, bindir, env, tpl, autostart
    h.state_file = Path(env["FAKE_DOCKER_STATE"])
    h.calls = lambda: Path(env["FAKE_DOCKER_CALLS"]).read_text() if Path(env["FAKE_DOCKER_CALLS"]).exists() else ""
    return h


def lib_bash(host, body: str, *, check=True, **extra_env):
    env = dict(host.env, **extra_env)
    script = f'set -euo pipefail\n. "{DEPLOY}/lib.sh"\nchown() {{ :; }}\n{body}\n'
    proc = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=120)
    if check and proc.returncode != 0:
        raise AssertionError(f"rc={proc.returncode}\nstdout:{proc.stdout}\nstderr:{proc.stderr}")
    return proc


def _ct(image, running=True, health="healthy", **kw):
    return {"image": image, "running": running, "health": health, **kw}


def _four(running=True):
    return {"spamfilter": _ct("imap-spamfilter-unraid:2.3.6", running=running, user="10099:10099"),
            "spamfilter-redis": _ct("redis@sha256:" + "1" * 64, running=running),
            "spamfilter-rspamd": _ct("rspamd/rspamd@sha256:" + "2" * 64, running=running),
            "spamfilter-unbound": _ct("mvance/unbound@sha256:" + "3" * 64, running=running)}


def _write(host, containers, images=(), **extra):
    data = {"containers": containers, "images": list(images),
            "image_labels": {AIO_IMG: AIO_LABELS, "imap-spamfilter-unraid:2.4.1": dict(AIO_LABELS, **{
                "spamfilter.version": "2.4.1"})}, **extra}
    host.state_file.write_text(json.dumps(data))


STAT_BEFORE = ("Results for command: stat (0.003 seconds)\nMessages scanned: 10\n"
               "Statfile: BAYES_SPAM type: redis; length: 0; free blocks: 0; total blocks: 0; free: 0.00%; "
               "learned: 251; users: 2; languages: 0\n"
               "Statfile: BAYES_HAM type: redis; length: 0; free blocks: 0; total blocks: 0; free: 0.00%; "
               "learned: 216; users: 2; languages: 0\nTotal learns: 467\n")
HEALTH_OK = json.dumps({"ts": 1, "ok": True, "parts": {p: {"ok": True, "detail": "ok"}
                                                       for p in ("filter", "rspamd", "redis", "unbound")}})
API_OK = json.dumps({"ok": True, "version": "2.16.0",
                     "accounts": {"bynet": "idle", "molt": "working", "inge": "paused"}})


def stat_to_bayes(stat: str) -> str:
    """`rspamc stat` text -> what `sf-health bayes` prints ("SYMBOL learned")."""
    return "\n".join(f"{m.group(1)} {m.group(2)}"
                     for m in re.finditer(r"^Statfile: (\S+) .*?learned: (\d+)", stat, re.M))


def _exec_map(after_stat=STAT_BEFORE, after_db="1234", health=HEALTH_OK):
    # 4 containers: rspamc inside spamfilter-rspamd (its loopback is exempt);
    # AIO: no exempt client -> sf-health bayes as the filter uid (password).
    return json.dumps({"spamfilter-rspamd rspamc": STAT_BEFORE, "spamfilter-redis sh": "1234",
                       "spamfilter /usr/local/bin/sf-health bayes": stat_to_bayes(after_stat),
                       "spamfilter sh": after_db,
                       "spamfilter /usr/local/bin/sf-health": "ok: all\n" + health})


# ================================================================ run args + template

def run_args(host, *args) -> list[str]:
    a = " ".join(f'"{x}"' for x in args)
    out = lib_bash(host, f'sf_aio_run_args {a}; printf "%s\\n" "${{SF_OPTS[@]}}" "--" "${{SF_IMAGE_CMD[@]}}"').stdout
    return out.splitlines()


def test_aio_run_args_live(host):
    a = run_args(host, "spamfilter")
    j = " ".join(a)
    assert a[a.index("--") + 1:] == [AIO_IMG]
    for need in ("--name spamfilter", "--network bridge", "--restart unless-stopped", "--stop-timeout 90",
                 "--memory 4g", "--pids-limit 512", "--cap-drop ALL", "--cap-add CHOWN", "--cap-add SETUID",
                 "--cap-add SETGID", "--cap-add KILL", "--security-opt no-new-privileges",
                 "-p 192.168.1.10:18080:8080/tcp",
                 f"-v {host.app}:/appdata", f"-v {host.app}/rspamd/data:/var/lib/rspamd",
                 "--label net.unraid.docker.managed=dockerman",
                 "--label net.unraid.docker.webui=http://[IP]:[PORT:8080]/",
                 "--label net.unraid.docker.icon=http://192.168.1.10:18080/static/icon-192.png",
                 "-e TZ=Europe/Copenhagen", "--log-opt max-size=10m"):
        assert need in j, need
    assert "--init" not in a and "--user" not in a and "--privileged" not in a
    assert "--sysctl" not in a  # Unbound uses the unprivileged port 5353
    assert sum(1 for x in a if x == "-p") == 1  # only the WebUI is published
    assert "TRUSTED_PROXIES" not in j


def test_aio_run_args_pass_site_settings(host):
    a = " ".join(run_args(host, "spamfilter").copy())
    assert "TRUSTED_PROXIES" not in a
    # like the 4-container filter: TRUSTED_PROXIES comes from operations/site.env
    (host.app / "operations" / "site.env").write_text("TRUSTED_PROXIES=192.168.1.10\n")
    out = lib_bash(host, 'sf_aio_run_args spamfilter; printf "%s\\n" "${SF_OPTS[@]}"',
                   LOCAL_NETWORKS="192.168.1.0/24", SPAMFILTER_LAN_URL="http://192.168.1.10:18080").stdout
    for kv in ("TRUSTED_PROXIES=192.168.1.10", "LOCAL_NETWORKS=192.168.1.0/24",
               "SPAMFILTER_LAN_URL=http://192.168.1.10:18080"):
        assert kv in out.splitlines()


def test_aio_run_args_test_container(host):
    a = run_args(host, "spamfilter-aio-test", AIO_IMG, str(host.tmp / "copy"), "127.0.0.1", "18090", "test")
    j = " ".join(a)
    assert "-p 127.0.0.1:18090:8080/tcp" in j and "--restart no" in j
    assert f"-v {host.tmp}/copy:/appdata" in j and "net.unraid" not in j


def _template_xml(env_extra=None) -> str:
    env = {"PATH": os.environ["PATH"], "HOME": "/tmp", "WEBUI_BIND": "192.168.1.10", **(env_extra or {})}
    return subprocess.run(["bash", "-c", f'set -euo pipefail; . "{DEPLOY}/lib.sh"; sf_aio_template'],
                          env=env, capture_output=True, text=True, check=True).stdout


def test_committed_template_is_the_generated_one():
    assert (AIO / "unraid-template.xml").read_text() == _template_xml()


def test_template_is_valid_dockerman_xml_with_labels_ports_paths():
    root = ET.fromstring((AIO / "unraid-template.xml").read_text())
    assert root.tag == "Container" and root.get("version") == "2"
    assert root.findtext("Name") == "spamfilter"  # = the container name scripts and sfctl use
    assert root.findtext("Repository") == AIO_IMG
    assert root.findtext("Network") == "bridge"
    assert root.findtext("WebUI") == "http://[IP]:[PORT:8080]/"
    assert root.findtext("Icon") == "http://192.168.1.10:18080/static/icon-192.png"
    assert (ROOT / "filter" / "static" / "icon-192.png").is_file()
    assert root.findtext("Privileged") == "false" and root.findtext("Shell") == "bash"
    assert "rspamd" in root.findtext("Overview") and "Intet bliver slettet" in root.findtext("Overview")
    extra = root.findtext("ExtraParams")
    assert "-p 192.168.1.10:18080:8080/tcp" in extra and "--pids-limit 512" in extra and "--memory 4g" in extra
    assert "--init" not in extra
    cfg = {c.get("Target"): c for c in root.findall("Config")}
    assert cfg["/appdata"].get("Type") == "Path" and cfg["/appdata"].text == "/mnt/user/appdata/spamfilter"
    assert cfg["/var/lib/rspamd"].text == "/mnt/user/appdata/spamfilter/rspamd/data"
    assert cfg["TZ"].text == "Europe/Copenhagen" and cfg["TZ"].get("Type") == "Variable"
    assert {"TRUSTED_PROXIES", "LOCAL_NETWORKS", "SPAMFILTER_LAN_URL"} <= set(cfg)
    # 2.7: ClamAV can be switched off in the template (default on)
    assert cfg["SF_CLAMAV"].get("Type") == "Variable" and cfg["SF_CLAMAV"].get("Default") == "1"
    assert cfg["SF_CLAMAV"].text == "1" and "ClamAV" in root.findtext("Overview")
    assert not [c for c in root.findall("Config") if c.get("Type") == "Port"]  # bound to 192.168.1.10 in ExtraParams


def test_template_extra_params_equal_the_run_args(host):
    root = ET.fromstring(_template_xml())
    extra = root.findtext("ExtraParams").split()
    live = run_args(host, "spamfilter")
    # dockerMan adds name, network, -e, -v and the labels itself; the rest
    # must be exactly the run script's flags in the same order.
    stripped = live[live.index("--log-driver") + 2:live.index("-e")]
    assert extra == stripped


def test_template_install_and_restore(host):
    old = host.tpl / "my-spamfilter.xml"
    old.write_text("<Container><Name>spamfilter</Name><Repository>x:2.3.6</Repository></Container>\n")
    (host.app / "operations" / "site.env").write_text("TRUSTED_PROXIES=192.168.1.10\n")
    lib_bash(host, f'sf_aio_install_template "{AIO_IMG}"')
    root = ET.fromstring(old.read_text())
    assert root.findtext("Repository") == AIO_IMG
    assert {c.get("Target"): c.text for c in root.findall("Config")}["TRUSTED_PROXIES"] == "192.168.1.10"
    assert {c.get("Target"): c.text for c in root.findall("Config")}["/appdata"] == str(host.app)
    backups = list((host.app / "operations" / "config-backups").glob("*/my-spamfilter.xml"))
    assert len(backups) == 1 and "x:2.3.6" in backups[0].read_text()
    lib_bash(host, "sf_aio_restore_template")
    assert "x:2.3.6" in old.read_text()
    # without a pre-migration template the AIO one is removed on rollback
    for b in backups:
        b.unlink()
    old.unlink()
    lib_bash(host, f'sf_aio_install_template "{AIO_IMG}"')
    lib_bash(host, "sf_aio_restore_template")
    assert not old.exists()


# ================================================================ layout guards

def test_layout_detection_and_legacy_scripts_refuse_next_to_an_aio(host):
    _write(host, {"spamfilter": _ct(AIO_IMG, labels=AIO_LABELS)}, images=[AIO_IMG])
    assert lib_bash(host, "sf_layout").stdout.strip() == "aio"
    for script in ("recreate-filter.sh", "recreate-infra.sh", "run-containers.sh", "migrate-2.0.sh"):
        args = [str(DEPLOY / script), "--dry-run"] + (["redis"] if script == "recreate-infra.sh" else [])
        proc = subprocess.run(args, env=host.env, capture_output=True, text=True, timeout=60)
        assert proc.returncode != 0 and "all-in-one container is live" in proc.stderr, script
    _write(host, _four())
    assert lib_bash(host, "sf_layout").stdout.strip() == "legacy"
    _write(host, {})
    assert lib_bash(host, "sf_layout").stdout.strip() == "none"


def test_prune_is_layout_class_aware(host):
    repo = "imap-spamfilter-unraid"
    imgs = [f"{repo}:2.4.1", f"{repo}:2.4.0", f"{repo}:2.4.0-filter", f"{repo}:2.3.6", f"{repo}:2.3.5"]
    labels = {f"{repo}:2.4.1": AIO_LABELS, f"{repo}:2.4.0": AIO_LABELS}
    host.state_file.write_text(json.dumps({"containers": {"spamfilter": _ct(f"{repo}:2.4.1", labels=AIO_LABELS)},
                                           "images": imgs, "image_labels": labels}))
    lib_bash(host, "sf_prune_filter_images")
    # AIO 2.4.1 runs: previous AIO 2.4.0 is kept, filter-only images are not
    # this function's business (cleanup.sh removes them)
    assert set(read_state(host.state_file)["images"]) == set(imgs)
    imgs2 = imgs + [f"{repo}:2.3.9-aio"]
    labels[f"{repo}:2.3.9-aio"] = AIO_LABELS
    host.state_file.write_text(json.dumps({"containers": {"spamfilter": _ct(f"{repo}:2.4.1", labels=AIO_LABELS)},
                                           "images": imgs2, "image_labels": labels}))
    lib_bash(host, "sf_prune_filter_images")
    assert f"{repo}:2.3.9-aio" not in read_state(host.state_file)["images"]
    assert f"{repo}:2.4.0" in read_state(host.state_file)["images"]


# ================================================================ build.sh

def test_build_context_only_stages_runtime_files_and_no_secrets(tmp_path):
    ctx = tmp_path / "ctx"
    env = dict(os.environ, SPAMFILTER_APP=str(tmp_path / "noapp"))
    proc = subprocess.run([str(AIO / "build.sh"), "--context-only", str(ctx)], env=env, capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert (ctx / "Dockerfile").read_text() == (AIO / "Dockerfile").read_text()
    staged_py = {p.name for p in (ctx / "filter").glob("*.py")}
    assert "aio_health.py" in staged_py and "filter.py" in staged_py and "healthcheck.py" in staged_py
    assert not [n for n in staged_py if n.startswith("test_")]
    assert (ctx / "filter" / "static" / "icon-192.png").is_file()
    assert not list(ctx.rglob("__pycache__"))
    rs = {p.name for p in (ctx / "aio" / "share" / "rspamd").iterdir() if p.is_file()}
    assert "redis.conf" not in rs and "worker-controller.inc" not in rs  # rendered secrets never
    assert {"redis.conf.template", "worker-controller.inc.template", "fuzzy_check.conf",
            "fuzzy_check.conf.readonly", "options.inc", "actions.conf"} <= rs
    assert (ctx / "aio" / "share" / "VERSION").read_text() == "2.16.0\n"
    assert (ctx / "aio" / "share" / "unbound.conf").read_text() == (DEPLOY / "unbound.conf").read_text()
    for f in ("sf-entrypoint", "sf-run", "sf-health", "sfctl-aio", "build-check.sh"):
        assert os.access(ctx / "aio" / f, os.X_OK), f
    args = dict(line.split("=", 1) for line in (ctx / "build-args.env").read_text().splitlines())
    v = versions()
    assert args["RSPAMD_IMAGE"] == v["RSPAMD_IMAGE"] and args["FILTER_BASE_IMAGE"] == v["FILTER_BASE_IMAGE"]
    assert args["REDIS_IMAGE"].startswith("redis:8.10.3") and args["AIO_VERSION"] == "2.16.0"
    assert set(args) == set(dockerfile_args())


def test_build_dry_run_resolves_redis_and_builds_with_pinned_args(host):
    proc = subprocess.run([str(AIO / "build.sh"), "--dry-run"], env=host.env, capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 0, proc.stderr
    v = versions()
    # pinned in versions.env: no pull of a moving tag, the digest goes to the build
    assert "docker pull" not in proc.stdout
    line = next(x for x in proc.stdout.splitlines() if "[dry-run] docker build" in x)
    assert f"-t {AIO_IMG}" in line
    assert f"--build-arg REDIS_IMAGE=redis:{v['REDIS_AIO_TAG']}@{v['REDIS_AIO_DIGEST']}" in line
    assert f"--build-arg RSPAMD_IMAGE={v['RSPAMD_IMAGE']}" in line
    assert "--build-arg EXPECT_REDIS=8.10.3" in line
    assert read_state(host.state_file)["images"] == []
    # an install that un-pins it (site.env) resolves the tag once and says so
    (host.app / "operations" / "site.env").write_text("REDIS_AIO_DIGEST=\n")
    proc = subprocess.run([str(AIO / "build.sh"), "--dry-run"], env=host.env, capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "[dry-run] docker pull redis:8.10.3-trixie" in proc.stdout and "not pinned" in proc.stderr


# ================================================================ migrate

def _migrate_env(host, **kw):
    env = dict(FAKE_DOCKER_EXEC=_exec_map(), FAKE_CURL_MAP=json.dumps({"/api/health": API_OK}),
               FAKE_CURL_BODY='{"ok":true}', FAKE_CURL_CODES=json.dumps({"/api/v1/ha": "404"}),
               FAKE_DOCKER_LOGS=json.dumps({"spamfilter": "[filter] main: loaded 4 account(s): a"}),
               FAKE_RUN_HEARTBEAT=str(host.app / "state" / "heartbeat"))
    env.update(kw)
    return env


def test_migrate_dry_run_changes_nothing(host):
    _write(host, _four(), images=[AIO_IMG])
    before = host.state_file.read_text()
    tpl_before = sorted(host.tpl.iterdir())
    auto_before = host.autostart.read_text()
    proc = subprocess.run([str(AIO / "migrate.sh"), "--dry-run"], env=dict(host.env, **_migrate_env(host)),
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout
    order = [x for x in out.splitlines() if "[dry-run] docker stop" in x]
    assert [x.split()[-1] for x in order] == ["spamfilter", "spamfilter-rspamd", "spamfilter-unbound",
                                             "spamfilter-redis"]
    assert "[dry-run] docker rename spamfilter spamfilter-legacy" in out
    run_line = next(x for x in out.splitlines() if "[dry-run] docker run -d" in x)
    assert "net.unraid.docker.managed=dockerman" in run_line and run_line.rstrip().endswith(AIO_IMG)
    assert host.state_file.read_text() == before
    assert sorted(host.tpl.iterdir()) == tpl_before and host.autostart.read_text() == auto_before
    mutating = [ln for ln in host.calls().splitlines() if ln.split()[0] in ("run", "stop", "rename", "rm", "update")]
    assert mutating == []


def test_migrate_success(host):
    _write(host, _four(), images=[AIO_IMG])
    lib_bash(host, f'sf_backup() {{ :; }}\nsf_aio_migrate "{AIO_IMG}" 0', **_migrate_env(host))
    c = read_state(host.state_file)["containers"]
    assert set(c) == {"spamfilter", "spamfilter-legacy", "spamfilter-redis", "spamfilter-rspamd",
                      "spamfilter-unbound"}
    assert c["spamfilter"]["image"] == AIO_IMG and c["spamfilter"]["running"]
    assert c["spamfilter"]["labels"]["spamfilter.layout"] == "aio"  # inherited from the image
    assert c["spamfilter"]["labels"]["net.unraid.docker.managed"] == "dockerman"
    for name in ("spamfilter-legacy", "spamfilter-redis", "spamfilter-rspamd", "spamfilter-unbound"):
        assert not c[name]["running"] and c[name]["restart"] == "no", name  # kept, never started by Docker
    assert c["spamfilter-legacy"]["image"] == "imap-spamfilter-unraid:2.3.6"
    # Unraid will not start the old ones on boot; foreign entries untouched
    assert host.autostart.read_text().split() == ["spamfilter", "plex"]
    assert ET.parse(host.tpl / "my-spamfilter.xml").getroot().findtext("Repository") == AIO_IMG
    ops = host.app / "operations"
    assert json.loads(next(ops.glob("aio-migrate-*.before.json")).read_text())["bayes"] == {
        "BAYES_SPAM": 251, "BAYES_HAM": 216}
    assert json.loads(next(ops.glob("aio-migrate-*.after.json")).read_text())["dbsize"] == 1234
    calls = host.calls()
    assert "exec -u 10099:10099 spamfilter /usr/local/bin/sf-health bayes" in calls
    assert "exec -u 999:1000 spamfilter sh" in calls and "spamfilter rspamc" not in calls
    assert " rm " not in f" {calls} ".replace("\n", " ") or "rm spamfilter" not in calls


BEFORE_SNAPSHOT = {"version": "2.3.6", "accounts": {"bynet": "idle", "molt": "working", "inge": "paused"},
                   "bayes": {"BAYES_SPAM": 251, "BAYES_HAM": 216}, "dbsize": 1234}


@pytest.mark.parametrize("problem,env", [
    ("bayes", {"FAKE_DOCKER_EXEC": _exec_map(after_stat=STAT_BEFORE.replace("learned: 251", "learned: 10"))}),
    ("redis keys", {"FAKE_DOCKER_EXEC": _exec_map(after_db="12")}),
    ("parts", {"FAKE_DOCKER_EXEC": _exec_map(health=json.dumps({"ok": False, "parts": {}}))}),
    ("version", {"FAKE_CURL_MAP": json.dumps({"/api/health": API_OK.replace("2.16.0", "2.3.6")})}),
    ("account", {"FAKE_CURL_MAP": json.dumps({"/api/health": API_OK.replace('"working"', '"auth_failed"')})}),
    ("ha", {"FAKE_CURL_CODES": json.dumps({"/api/v1/ha": "200"})}),
    ("unhealthy", {"FAKE_NEW_HEALTH": "unhealthy"}),
])
def test_migrate_failed_gate_rolls_back_to_the_four(host, problem, env):
    _write(host, _four(), images=[AIO_IMG])
    # The 4-container snapshot is fixed; the AIO answers per the parameter.
    body = ('eval "$(declare -f sf_aio_snapshot | sed \'1s/sf_aio_snapshot/_real_snapshot/\')"\n'
            "sf_aio_snapshot() { if [[ $1 == legacy ]]; then echo '" + json.dumps(BEFORE_SNAPSHOT)
            + "'; else _real_snapshot \"$@\"; fi; }\n"
            f'sf_backup() {{ :; }}\nsf_aio_migrate "{AIO_IMG}" 0')
    proc = lib_bash(host, body, check=False, **dict(_migrate_env(host), **env))
    assert proc.returncode != 0, proc.stdout
    assert "ROLLBACK to the four containers" in proc.stderr and "migration FAILED" in proc.stderr
    c = read_state(host.state_file)["containers"]
    assert set(c) == {"spamfilter", "spamfilter-redis", "spamfilter-rspamd", "spamfilter-unbound"}
    assert c["spamfilter"]["image"] == "imap-spamfilter-unraid:2.3.6"
    assert all(x["running"] for x in c.values())
    assert all(x.get("restart") == "unless-stopped" for x in c.values())
    assert set(host.autostart.read_text().split()) == {"spamfilter", "spamfilter-redis", "spamfilter-unbound",
                                                       "spamfilter-rspamd", "plex"}
    assert not (host.tpl / "my-spamfilter.xml").exists()
    assert list((host.app / "operations").glob("failed-aio-*.log"))


def test_migrate_preflight_refuses(host):
    _write(host, _four(), images=[])
    proc = lib_bash(host, f'sf_backup() {{ :; }}\nsf_aio_migrate "{AIO_IMG}" 0', check=False, **_migrate_env(host))
    assert proc.returncode != 0 and "build it first" in proc.stderr
    four = _four()
    four["spamfilter-legacy"] = _ct("x", running=False)
    _write(host, four, images=[AIO_IMG])
    proc = lib_bash(host, f'sf_backup() {{ :; }}\nsf_aio_migrate "{AIO_IMG}" 0', check=False, **_migrate_env(host))
    assert proc.returncode != 0 and "already exists" in proc.stderr
    _write(host, _four(), images=[AIO_IMG])
    proc = lib_bash(host, f'sf_backup() {{ :; }}\nsf_aio_migrate "{AIO_IMG}" 0', check=False,
                    **_migrate_env(host, FAKE_DOCKER_EXEC="{}"))
    assert proc.returncode != 0 and "cannot read the Bayes statistics" in proc.stderr
    # nothing was stopped by a refused preflight
    assert all(x["running"] for x in read_state(host.state_file)["containers"].values())


def test_migrate_ha_token_goes_to_curl_on_stdin_only(host):
    """The HA check with a token runs INSIDE the container (127.0.0.1): from the
    Unraid host a request comes from the trusted proxy 192.168.1.10 and is
    rightly treated as external (found by the first live migration). The
    token goes in on stdin only."""
    _write(host, _four(), images=[AIO_IMG])
    token = "sfha_" + "Z" * 40
    exec_map = json.loads(_exec_map())
    exec_map["spamfilter python3 -s"] = "200"
    env = _migrate_env(host, SF_HA_TOKEN=token, FAKE_DOCKER_EXEC=json.dumps(exec_map))
    proc = lib_bash(host, f'sf_backup() {{ :; }}\nsf_aio_migrate "{AIO_IMG}" 0', **env)
    assert read_state(host.state_file)["containers"]["spamfilter"]["image"] == AIO_IMG
    assert "exec -i spamfilter python3 -s" in host.calls()
    curl_log = (host.tmp / "curl.log").read_text() if (host.tmp / "curl.log").exists() else ""
    assert token not in curl_log
    assert token not in proc.stdout + proc.stderr + host.calls()
    for log in (host.app / "operations").glob("*"):
        if log.is_file():
            assert token not in log.read_text(errors="replace")


def test_compare_rules(host):
    before = {"version": "2.3.6", "accounts": {"a": "idle", "b": "working", "c": "paused", "d": "error",
                                               "*": "ok"},
              "bayes": {"BAYES_SPAM": 10, "BAYES_HAM": 5}, "dbsize": 100}
    good = {"version": "2.16.0", "accounts": {"a": "working", "b": "idle", "c": "paused", "d": "auth_failed"},
            "bayes": {"BAYES_SPAM": 11, "BAYES_HAM": 5}, "dbsize": 101}
    out = lib_bash(host, f"sf_aio_compare '{json.dumps(before)}' '{json.dumps(good)}'").stdout
    assert out.strip() == ""
    # a user re-learning a mail during the gate: spam -1, ham +1, total equal -> fine
    relearn = dict(good, bayes={"BAYES_SPAM": 9, "BAYES_HAM": 6}, dbsize=95)
    out = lib_bash(host, f"sf_aio_compare '{json.dumps(before)}' '{json.dumps(relearn)}'").stdout
    assert out.strip() == ""
    bad = dict(good, accounts={"a": "connecting", "b": "idle", "c": "idle"}, bayes={"BAYES_SPAM": 4}, dbsize=89)
    out = lib_bash(host, f"sf_aio_compare '{json.dumps(before)}' '{json.dumps(bad)}'").stdout.splitlines()
    assert "account a: connecting (was idle)" in out and "account c: idle (was paused)" in out
    assert "Bayes BAYES_SPAM: 4 learned (was 10)" in out and "Bayes BAYES_HAM: not readable (was 5 learned)" in out
    assert "Bayes total: 4 learned (was 15)" in out
    assert "Redis keys: 89 (was 100)" in out and not any(x.startswith("account d") for x in out)
    big = dict(before, dbsize=100000)
    out = lib_bash(host, f"sf_aio_compare '{json.dumps(big)}' '{json.dumps(dict(good, dbsize=99100))}'").stdout
    assert out.strip() == ""  # 0.9 % fewer keys: short-lived rspamd keys expired
    out = lib_bash(host, f"sf_aio_compare '{json.dumps(big)}' '{json.dumps(dict(good, dbsize=12))}'").stdout
    assert "Redis keys: 12 (was 100000)" in out


# ================================================================ rollback

def _after_migration():
    four = _four(running=False)
    legacy = four.pop("spamfilter")
    for c in four.values():
        c["restart"] = "no"
    return {"spamfilter": _ct(AIO_IMG, labels=dict(AIO_LABELS)), "spamfilter-legacy": dict(legacy, restart="no"),
            **four}


def test_rollback_script_requires_yes(host):
    _write(host, _after_migration(), images=[AIO_IMG])
    proc = subprocess.run([str(AIO / "rollback.sh")], env=host.env, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 2 and "--yes" in proc.stderr
    proc = subprocess.run([str(AIO / "rollback.sh"), "--dry-run"], env=host.env, capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "[dry-run] docker stop -t 90 spamfilter" in proc.stdout
    assert "[dry-run] docker rename spamfilter spamfilter-aio-rolledback" in proc.stdout
    assert read_state(host.state_file)["containers"]["spamfilter"]["image"] == AIO_IMG


def test_manual_rollback_stops_the_aio_before_the_old_redis_starts(host):
    host.autostart.write_text("spamfilter\nplex\n")
    _write(host, _after_migration(), images=[AIO_IMG])
    (host.app / "state" / "heartbeat").write_text(f"{int(time.time()) + 30} boot\n")
    lib_bash(host, "sf_aio_rollback keep", FAKE_CURL_BODY='{"ok":true}')
    c = read_state(host.state_file)["containers"]
    assert c["spamfilter"]["image"] == "imap-spamfilter-unraid:2.3.6" and c["spamfilter"]["running"]
    assert c["spamfilter-aio-rolledback"]["image"] == AIO_IMG and not c["spamfilter-aio-rolledback"]["running"]
    assert c["spamfilter-aio-rolledback"]["restart"] == "no"
    assert all(c[n]["running"] and c[n]["restart"] == "unless-stopped"
               for n in ("spamfilter-redis", "spamfilter-unbound", "spamfilter-rspamd"))
    calls = host.calls().splitlines()
    stop_aio = calls.index("stop -t 90 spamfilter")
    start_redis = calls.index("start spamfilter-redis")
    assert stop_aio < start_redis
    starts = [ln.split()[-1] for ln in calls if ln.startswith("start ")]
    assert starts == ["spamfilter-redis", "spamfilter-unbound", "spamfilter-rspamd", "spamfilter"]
    assert set(host.autostart.read_text().split()) >= {"spamfilter-redis", "spamfilter-rspamd", "plex"}


def test_rollback_refuses_while_an_aio_still_runs(host):
    st = _after_migration()
    st["spamfilter-aio-rolledback"] = _ct(AIO_IMG, labels=dict(AIO_LABELS))  # running!
    _write(host, st, images=[AIO_IMG])
    proc = lib_bash(host, "sf_aio_rollback remove", check=False)
    assert proc.returncode != 0 and "still running" in proc.stderr
    c = read_state(host.state_file)["containers"]
    assert not c["spamfilter-redis"]["running"]  # the old Redis never started


# ================================================================ cleanup

def _cleanup_state():
    st = _after_migration()
    st["plex"] = _ct("plexinc/pms:latest", running=False)
    st["spamfilter-other"] = _ct("someone/else:1", running=False)
    return st


def test_cleanup_refuses_without_yes_and_with_unhealthy_aio(host):
    _write(host, _cleanup_state(), images=[AIO_IMG])
    before = host.state_file.read_text()
    proc = subprocess.run([str(AIO / "cleanup.sh")], env=host.env, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 2 and "--yes" in proc.stderr
    assert host.state_file.read_text() == before
    st = _cleanup_state()
    st["spamfilter"]["health"] = "unhealthy"
    _write(host, st, images=[AIO_IMG])
    proc = lib_bash(host, "sf_aio_cleanup", check=False)
    assert proc.returncode != 0 and "not running and healthy" in proc.stderr
    _write(host, _four(), images=[AIO_IMG])
    proc = lib_bash(host, "sf_aio_cleanup", check=False)
    assert proc.returncode != 0 and "not live" in proc.stderr
    assert set(read_state(host.state_file)["containers"]) == set(_four())


def test_cleanup_removes_only_the_old_setup(host):
    repo = "imap-spamfilter-unraid"
    v = versions()
    images = [AIO_IMG, f"{repo}:2.3.6", f"{repo}:2.3.5", f"{repo}:2.4.0-filter", v["REDIS_IMAGE"],
              v["UNBOUND_IMAGE"], v["RSPAMD_IMAGE"], v["FILTER_BASE_IMAGE"], "redis:8.10.3-trixie",
              "plexinc/pms:latest", "someone/else:1"]
    st = _cleanup_state()
    st["spamfilter-redis"]["image"] = v["REDIS_IMAGE"]
    st["spamfilter-unbound"]["image"] = v["UNBOUND_IMAGE"]
    st["spamfilter-rspamd"]["image"] = v["RSPAMD_IMAGE"]
    st["spamfilter-rspamd"]["running"] = True  # a running one is never removed
    _write(host, st, images=images, networks={"spamnet": ["spamfilter-redis", "spamfilter-unbound",
                                                          "spamfilter-legacy", "spamfilter-rspamd"]})
    host.autostart.write_text("spamfilter\nspamfilter-redis\nplex\n")
    proc = lib_bash(host, "sf_aio_cleanup")
    out = read_state(host.state_file)
    assert set(out["containers"]) == {"spamfilter", "spamfilter-rspamd", "plex", "spamfilter-other"}
    assert "spamfilter-rspamd is running - left alone" in proc.stderr
    assert set(out["images"]) == {AIO_IMG, v["RSPAMD_IMAGE"], v["FILTER_BASE_IMAGE"], "redis:8.10.3-trixie",
                                  "plexinc/pms:latest", "someone/else:1"}
    assert "spamnet" in out["networks"]  # the running spamfilter-rspamd is still attached
    assert host.autostart.read_text().split() == ["spamfilter", "plex"]
    assert "rm -f" not in host.calls() and "image rm -f" not in host.calls()
    # second pass after the operator stopped rspamd: network goes too
    out["containers"]["spamfilter-rspamd"]["running"] = False
    host.state_file.write_text(json.dumps(out))
    lib_bash(host, "sf_aio_cleanup")
    out = read_state(host.state_file)
    assert set(out["containers"]) == {"spamfilter", "plex", "spamfilter-other"}
    assert "spamnet" not in out["networks"]


def test_cleanup_dry_run_changes_nothing(host):
    _write(host, _cleanup_state(), images=[AIO_IMG, "imap-spamfilter-unraid:2.3.6"],
           networks={"spamnet": ["spamfilter-legacy"]})
    before = host.state_file.read_text()
    proc = subprocess.run([str(AIO / "cleanup.sh"), "--dry-run"], env=host.env, capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "[dry-run] docker rm spamfilter-legacy" in proc.stdout
    assert "[dry-run] docker network rm spamnet" in proc.stdout
    assert "[dry-run] docker image rm imap-spamfilter-unraid:2.3.6" in proc.stdout
    assert "plex" not in proc.stdout.replace("plexinc", "")
    assert host.state_file.read_text() == before


# ================================================================ update

def test_update_refuses_on_the_legacy_layout(host):
    _write(host, _four(), images=[AIO_IMG])
    proc = subprocess.run([str(AIO / "update.sh"), "--dry-run"], env=host.env, capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode != 0 and "not live" in proc.stderr


def test_update_success_keeps_previous_image_and_drops_rollback(host):
    new = "imap-spamfilter-unraid:2.4.1"
    _write(host, {"spamfilter": _ct(AIO_IMG, labels=dict(AIO_LABELS)), "plex": _ct("plexinc/pms:latest")},
           images=[new, AIO_IMG, "imap-spamfilter-unraid:2.3.6"])
    lib_bash(host, f'sf_set_state_owner() {{ :; }}\nsf_install_traps\nsf_recreate spamfilter sf_gate_aio "{new}"\n'
                   f'sf_aio_install_template "{new}"\nsf_prune_filter_images',
             SF_LAYOUT="aio", SF_KEEP_ROLLBACK="0", **_migrate_env(host))
    st = read_state(host.state_file)
    assert set(st["containers"]) == {"spamfilter", "plex"}
    assert st["containers"]["spamfilter"]["image"] == new
    assert "net.unraid.docker.managed" in st["containers"]["spamfilter"]["labels"]
    assert set(st["images"]) >= {new, AIO_IMG}
    assert ET.parse(host.tpl / "my-spamfilter.xml").getroot().findtext("Repository") == new
    assert "stop -t 90 spamfilter" in host.calls()


def test_update_failed_gate_restarts_the_previous_aio(host):
    new = "imap-spamfilter-unraid:2.4.1"
    _write(host, {"spamfilter": _ct(AIO_IMG, labels=dict(AIO_LABELS))}, images=[new, AIO_IMG])
    proc = lib_bash(host, f'sf_set_state_owner() {{ :; }}\nsf_install_traps\nsf_recreate spamfilter sf_gate_aio "{new}"',
                    check=False, SF_LAYOUT="aio", SF_KEEP_ROLLBACK="0", **_migrate_env(host, FAKE_NEW_HEALTH="unhealthy"))
    assert proc.returncode != 0 and "rolled back" in proc.stderr
    st = read_state(host.state_file)["containers"]
    assert set(st) == {"spamfilter"} and st["spamfilter"]["image"] == AIO_IMG and st["spamfilter"]["running"]


def test_update_dry_run(host):
    _write(host, {"spamfilter": _ct(AIO_IMG, labels=dict(AIO_LABELS))}, images=[AIO_IMG])
    before = host.state_file.read_text()
    proc = subprocess.run([str(AIO / "update.sh"), "--dry-run", "--no-backup"], env=host.env, capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "[dry-run] docker stop -t 90 spamfilter" in proc.stdout
    run_line = next(x for x in proc.stdout.splitlines() if "[dry-run] docker run -d" in x)
    assert "-p 192.168.1.10:18080:8080/tcp" in run_line and "/appdata" in run_line
    assert host.state_file.read_text() == before


def test_update_reinstalls_the_user_scripts_from_the_new_tree(host):
    """2.11.2: update.sh re-installs the User Scripts (bodies copied inline)
    after the gate, so a new update-runner.sh takes effect - the 2.11.1
    update via the WebUI failed with the old helper. A missing plugin dir
    only warns."""
    _write(host, {"spamfilter": _ct(AIO_IMG, labels=dict(AIO_LABELS))}, images=[AIO_IMG])
    us = host.tmp / "user.scripts"
    us.mkdir()
    env = dict(host.env, USER_SCRIPTS_DIR=str(us), UPDATE_CRON_BIN=str(host.tmp / "none"))
    proc = subprocess.run([str(AIO / "update.sh"), "--dry-run", "--no-backup"], env=env, capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert f"[dry-run] write {us}/scripts/Spamfilter-update/script" in out
    assert out.index("docker run -d") < out.index("User script Spamfilter-update")  # after the new container
    proc = subprocess.run([str(AIO / "update.sh"), "--dry-run", "--no-backup"],
                          env=dict(host.env, USER_SCRIPTS_DIR=str(host.tmp / "missing")), capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0 and "User Scripts plugin" in proc.stderr + proc.stdout
    # A broken schedule.json stops the re-install (own process with errexit,
    # not `( fn ) || warn`), leaves it as it was and only warns.
    (us / "schedule.json").write_text("{broken\n")
    proc = subprocess.run([str(AIO / "update.sh"), "--dry-run", "--no-backup"], env=env, capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "could not update" in proc.stderr and "User Scripts not re-installed" in proc.stderr
    assert "User script Spamfilter-backup" in proc.stdout and "User script Spamfilter-offsite" not in proc.stdout
    assert (us / "schedule.json").read_text() == "{broken\n"


# ================================================================ smoke test

def test_smoke_test_dry_run_plans_a_harmless_copy(host):
    backups = host.app / "operations" / "backups"
    backups.mkdir()
    (backups / "spamfilter-20261022T030000Z.tar.gz").write_bytes(b"x")
    _write(host, _four(), images=[AIO_IMG])
    before = host.state_file.read_text()
    proc = subprocess.run([str(AIO / "smoke-test.sh"), "--dry-run"], env=host.env, capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "spamfilter-20261022T030000Z.tar.gz" in out
    assert "find" in out and "imap-secrets" in out and "smtp.password" in out
    assert 'acc[\\"enabled\\"]\\ =\\ False' in out or "enabled" in out
    run_line = next(x for x in out.splitlines() if "[dry-run] docker run -d" in x)
    assert "--name spamfilter-aio-test" in run_line and "-p 127.0.0.1:18090:8080/tcp" in run_line
    assert "--restart no" in run_line and "net.unraid" not in run_line
    assert f"{host.app}/operations/aio-test/" in run_line and f"-v {host.app}:/appdata" not in run_line
    assert host.state_file.read_text() == before


def test_smoke_test_refuses_the_live_port_and_missing_backup(host):
    proc = subprocess.run([str(AIO / "smoke-test.sh"), "--dry-run", "--port", "18080"], env=host.env,
                          capture_output=True, text=True)
    assert proc.returncode == 2
    _write(host, _four(), images=[AIO_IMG])
    proc = subprocess.run([str(AIO / "smoke-test.sh"), "--dry-run"], env=host.env, capture_output=True, text=True)
    assert proc.returncode != 0 and "no backup archive" in proc.stderr
    proc = subprocess.run([str(AIO / "smoke-test.sh"), "--dry-run", "--fresh"], env=host.env, capture_output=True,
                          text=True)
    assert proc.returncode == 0, proc.stderr


def test_smoke_sanitizer_disables_every_account(tmp_path):
    """The sanitising Python of smoke-test.sh, run here against a real
    accounts.yml + database: no account may stay enabled, mail is off."""
    import sqlite3
    import yaml

    text = (AIO / "smoke-test.sh").read_text()
    code = text.split("  sanitize='", 1)[1].split("\n'\n", 1)[0]
    s, c = tmp_path / "s", tmp_path / "c"
    s.mkdir()
    c.mkdir()
    (c / "accounts.yml").write_text((DEPLOY / "accounts.yml").read_text())
    db = sqlite3.connect(s / "spamfilter.db")
    db.execute("CREATE TABLE settings_kv(key TEXT PRIMARY KEY, value TEXT)")
    db.execute("CREATE TABLE mail_outbox(id INTEGER)")
    db.executemany("INSERT INTO settings_kv VALUES (?, ?)", [("smtp", "{}"), ("mail_notify", "{}"), ("x", "1")])
    db.execute("INSERT INTO mail_outbox VALUES (1)")
    db.commit()
    db.close()
    code = code.replace("/c/", f"{c}/").replace("/s/", f"{s}/")
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    cfg = yaml.safe_load((c / "accounts.yml").read_text())
    assert cfg["accounts"] and all(a["enabled"] is False and a["mode"] == "shadow" for a in cfg["accounts"])
    db = sqlite3.connect(s / "spamfilter.db")
    assert [r[0] for r in db.execute("SELECT key FROM settings_kv")] == ["x"]
    assert db.execute("SELECT count(*) FROM mail_outbox").fetchone()[0] == 0


def _sanitizer_code() -> str:
    text = (AIO / "smoke-test.sh").read_text()
    return text.split("  sanitize='", 1)[1].split("\n'\n", 1)[0]


def test_smoke_copy_cannot_log_in_and_runs_no_snapshot_job(tmp_path, monkeypatch):
    """Review finding: `enabled: false` alone does not stop the trainer
    thread - it resumes queued/running undo, training and learn-list jobs of
    the snapshot for ANY account (load_account_configs returns disabled ones
    too). After the sanitiser no account can log in (inline password,
    password_file anywhere, any host) and no snapshot job is runnable."""
    import sqlite3

    import yaml
    sys.path.insert(0, str(ROOT / "filter"))
    import filter as engine  # noqa: E402
    import services  # noqa: E402
    import trainer  # noqa: E402
    from fakes_services import FakeEngine, FakeIMAP  # noqa: E402

    imap = FakeIMAP()
    eng = FakeEngine(tmp_path / "s", imap=imap)
    cfgdir = tmp_path / "c"
    cfgdir.mkdir()
    (cfgdir / "inline.pass").write_text("x\n")
    (cfgdir / "accounts.yml").write_text(yaml.safe_dump({
        "defaults": {"mode": "move", "imap_port": 993, "ssl": True},
        "accounts": [
            {"name": "acc", "enabled": False, "user": "a@example.dk", "imap_host": "imap.gigahost.dk",
             "password": "INLINE-SECRET"},                                   # inline: survives secret deletion
            {"name": "b", "enabled": False, "user": "b@example.dk", "imap_host": "mail.scannet.dk",
             "password_file": str(cfgdir / "inline.pass")},                  # outside imap-secrets/
            {"name": "c", "enabled": True, "user": "c@example.dk", "imap_host": "imap.gigahost.dk",
             "password_file": "/state/imap-secrets/c"}]}))
    now = int(time.time())
    with sqlite3.connect(eng.DB_PATH) as conn:
        services.ensure_undo_schema(conn)
        trainer.ensure_learn_list_schema(conn)
        trainer.ensure_train_columns(conn)
        conn.executemany("INSERT INTO undo_jobs(account, since_ts, until_ts, status, created_at) "
                         "VALUES('acc', 0, ?, ?, ?)", [(now, "running", now), (now, "queued", now),
                                                       (now, "done", now)])
        conn.execute("INSERT INTO train_jobs(account, folder, kind, max_messages, status, created_at) "
                     "VALUES('b', 'Spamfilter', 'spam', 10, 'queued', ?)", (now,))
        conn.executemany("INSERT INTO learn_list_jobs(status, created_at) VALUES(?, ?)",
                         [("cancel_requested", now), ("running", now)])
    code = _sanitizer_code().replace("/c/", f"{cfgdir}/").replace("/s/", f"{eng.STATE_DIR}/")
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "accounts after sanitising: 3, enabled: 0, able to log in: 0" in proc.stdout
    assert "imap-hosts: imap.gigahost.dk mail.scannet.dk" in proc.stdout
    assert "INLINE-SECRET" not in proc.stdout + proc.stderr + (cfgdir / "accounts.yml").read_text()

    # the filter's own parser: every account is disabled, points at 127.0.0.1:1, has no secret
    accounts = engine.load_account_configs(cfgdir / "accounts.yml")
    assert [a.name for a in accounts] == ["acc", "b", "c"]
    for acc in accounts:
        assert not acc.enabled and acc.imap_host == "127.0.0.1" and acc.imap_port == 1
        with pytest.raises(ValueError):
            engine.read_secret(acc)
    with sqlite3.connect(eng.DB_PATH) as conn:
        for table in ("undo_jobs", "train_jobs", "learn_list_jobs"):
            left = conn.execute(f"SELECT count(*) FROM {table} WHERE status IN "
                                "('queued', 'running', 'cancel_requested')").fetchone()[0]
            assert left == 0, table
        assert conn.execute("SELECT count(*) FROM undo_jobs WHERE status = 'done'").fetchone()[0] == 1

    # what the trainer thread does at start: nothing to resume, no IMAP session
    eng.accounts = accounts
    eng.read_secret = engine.read_secret
    monkeypatch.setattr(services, "_spawn_undo_thread", lambda e, j: None)
    trainer.recover_interrupted(engine=eng)
    assert trainer.run_pending_undo_once(engine=eng) is None
    assert trainer.run_pending_learn_list_once(engine=eng) is None
    assert trainer.run_pending_once(engine=eng) is None
    assert eng.connects == 0 and imap.logins == 0


def test_smoke_sanitizer_fails_when_an_account_could_still_log_in(tmp_path):
    import yaml
    s, c = tmp_path / "s", tmp_path / "c"
    s.mkdir()
    c.mkdir()
    (c / "accounts.yml").write_text(yaml.safe_dump({"accounts": [{"name": "a", "imap_host": "x"}]}))
    code = _sanitizer_code().replace("/c/", f"{c}/").replace("/s/", f"{s}/")
    # sabotage the no-login values after they are applied: the self-check must catch it
    code = code.replace('    acc["mode"] = "shadow"\n', '    acc["mode"] = "shadow"\n    acc["password"] = "p"\n')
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 1 and "able to log in: 1" in proc.stdout


def test_smoke_blocks_the_original_imap_hosts(host):
    out = lib_bash(host, 'SF_OPTS=(--name x); sf_aio_block_hosts imap.gigahost.dk "bad host" "-x" mail.scannet.dk; '
                         'printf "%s\\n" "${SF_OPTS[@]}"').stdout.splitlines()
    assert out == ["--name", "x", "--add-host", "imap.gigahost.dk:127.0.0.1", "--add-host",
                   "mail.scannet.dk:127.0.0.1"]
    text = (AIO / "smoke-test.sh").read_text()
    assert 'sf_aio_block_hosts "${imap_hosts[@]}"' in text
    assert text.index("sf_aio_run_args \"$name\"") < text.index("sf_aio_block_hosts")


# Redis' startup rule (src/server.c loadDataFromDisk): with appendonly yes
# ONLY the AOF is loaded - no appendonlydir means an EMPTY dataset, dump.rdb
# is ignored; with appendonly no the RDB is loaded.
def _redis_keys_at_start(conf: str, datadir: Path) -> int:
    aof = re.search(r'^\s*appendonly\s+"?yes"?\s*$', conf, re.M | re.I) is not None
    if aof:
        d = datadir / "appendonlydir"
        return int((d / "keys").read_text()) if d.is_dir() else 0
    rdb = datadir / "dump.rdb"
    return int(rdb.read_text()) if rdb.is_file() else 0


def test_smoke_copy_loads_the_restored_dump_rdb(host):
    """Review finding: the archive holds only dump.rdb, the live redis.conf
    says appendonly yes -> the copy started with an EMPTY Redis and the smoke
    test always failed on real data."""
    live_conf = (ROOT / "redis" / "redis.conf.template").read_text().replace("${REDIS_PASSWORD}", "pw")
    copy = host.tmp / "copy"
    (copy / "redis").mkdir(parents=True)
    (copy / "redis-config").mkdir()
    (copy / "redis" / "dump.rdb").write_text("41234")  # model: the RDB holds 41234 keys
    conf = copy / "redis-config" / "redis.conf"
    conf.write_text(live_conf)
    assert _redis_keys_at_start(conf.read_text(), copy / "redis") == 0  # the bug
    lib_bash(host, f'sf_redis_conf_rdb_only "{conf}"')
    text = conf.read_text()
    assert _redis_keys_at_start(text, copy / "redis") == 41234
    assert re.findall(r"^appendonly.*$", text, re.M) == ["appendonly no"]
    # everything else of the copy's config is unchanged (password, save points, memory cap)
    assert [ln for ln in text.splitlines() if not ln.startswith("appendonly")] == \
        [ln for ln in live_conf.splitlines() if not ln.startswith("appendonly")]
    # the live redis-config is never changed
    live = host.app / "redis-config" / "redis.conf"
    live.write_text(live_conf)
    proc = lib_bash(host, f'sf_redis_conf_rdb_only "{live}"', check=False)
    assert proc.returncode != 0 and "refusing" in proc.stderr and live.read_text() == live_conf
    # the smoke test does it on its copy, before anything starts
    st = (AIO / "smoke-test.sh").read_text()
    assert st.index('sf_redis_conf_rdb_only "$test_app/redis-config/redis.conf"') < st.index("sf_aio_run_args")


def test_backup_doc_restores_redis_with_aof_off_first():
    text = (ROOT / "BACKUP.md").read_text()
    assert "appendonly no" in text and "CONFIG SET appendonly yes" in text
    assert "aof_rewrite_in_progress:0" in text
    assert "Flyt en nyere AOF til side, ellers overskriver den" not in text  # the old, wrong advice


# ---------------------------------------------------------------- signals / interrupted runs

def _sig_script(host, marker: Path, plain_tee: bool = False) -> str:
    tee = ('exec > >(tee -a "$APP/operations/plain.log") 2>&1' if plain_tee else "sf_aio_tee_log sigtest")
    return f"""set -euo pipefail
. "{DEPLOY}/lib.sh"
{tee}
handler() {{
  local rc=$?
  sf_aio_log_rescue
  for i in 1 2 3; do sleep 0.3; log "rollback step $i"; done
  echo done >"{marker}"
  return "$rc"
}}
trap handler EXIT
trap 'exit 130' INT TERM HUP
log ready
sleep 30
"""


@pytest.mark.parametrize("sig", ["SIGINT", "SIGHUP"])
def test_ctrl_c_or_hangup_still_finishes_the_rollback(host, sig):
    """Review finding: Ctrl-C / a dropped SSH session signals the whole
    process group; the log tee died with it and the next log line of the
    EXIT-trap rollback killed the script with SIGPIPE."""
    import signal

    def run(plain):
        marker = host.tmp / f"marker-{sig}-{plain}"
        # A real Ctrl-C comes from a terminal where these signals are not ignored. CI runners can
        # start the test process with SIGINT ignored, and a non-interactive bash cannot trap a
        # signal that was ignored when it started - so reset them to the default in the child.
        def default_signals():
            for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                signal.signal(s, signal.SIG_DFL)
            signal.pthread_sigmask(signal.SIG_SETMASK, [])

        def sleeping(pgid):
            # bash is in its 'sleep 30' (not still between 'log ready' and the fork): the
            # moment a terminal Ctrl-C would hit it. Polling /proc avoids a timing guess.
            for st in Path("/proc").glob("[0-9]*/stat"):
                try:
                    f = st.read_text().rsplit(")", 1)
                    comm = f[0].split("(", 1)[1]
                    if comm == "sleep" and int(f[1].split()[2]) == pgid:
                        return True
                except (OSError, IndexError, ValueError):
                    continue
            return False

        proc = subprocess.Popen(["bash", "-c", _sig_script(host, marker, plain)], env=host.env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
                                preexec_fn=default_signals)
        deadline = time.time() + 20
        logs = lambda: "".join(f.read_text() for f in (host.app / "operations").glob("*.log"))  # noqa: E731
        while not ("ready" in logs() and sleeping(proc.pid)) and time.time() < deadline:
            time.sleep(0.05)
        os.killpg(proc.pid, getattr(signal, sig))
        out, _ = proc.communicate(timeout=30)
        run.out = out.decode(errors="replace")[-2000:]  # bash's own output, shown if the test fails
        for f in (host.app / "operations").glob("*.log"):
            text = f.read_text()
            f.unlink()
        return proc.returncode, marker.exists(), text

    rc, done, text = run(False)
    assert done and "rollback step 3" in text, (rc, text, run.out)
    assert rc == 130
    if sig == "SIGHUP":  # control: the old plain tee loses the rollback
        rc, done, _ = run(True)
        assert not done and rc != 130


def test_rollback_repairs_an_interrupted_migration(host):
    """migrate.sh killed (-9, power loss) in its stop loop: two of the four
    stopped with restart=no and off autostart, nothing renamed. rollback.sh
    used to refuse ('nothing to roll back')."""
    four = _four()
    for n in ("spamfilter", "spamfilter-rspamd"):
        four[n].update(running=False, restart="no")
    _write(host, four, images=[AIO_IMG])
    host.autostart.write_text("spamfilter-redis\nspamfilter-unbound\nspamfilter\nplex\n")
    assert lib_bash(host, "sf_aio_legacy_needs_repair && echo yes").stdout.strip() == "yes"
    proc = subprocess.run([str(AIO / "rollback.sh"), "--dry-run"], env=host.env, capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "interrupted migration" in proc.stderr and "[dry-run] docker start spamfilter-rspamd" in proc.stdout
    (host.app / "state" / "heartbeat").write_text(f"{int(time.time()) + 30} boot\n")
    lib_bash(host, "sf_aio_rollback keep", FAKE_CURL_BODY='{"ok":true}')
    c = read_state(host.state_file)["containers"]
    assert all(c[n]["running"] and c[n]["restart"] == "unless-stopped" for n in _four())
    assert host.autostart.read_text().split() == ["spamfilter-redis", "spamfilter-unbound", "spamfilter-rspamd",
                                                  "spamfilter", "plex"]
    # the healthy four: nothing to repair, rollback.sh refuses as before
    _write(host, _four(), images=[AIO_IMG])
    assert lib_bash(host, "sf_aio_legacy_needs_repair || echo no").stdout.strip() == "no"
    proc = subprocess.run([str(AIO / "rollback.sh"), "--dry-run"], env=host.env, capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode != 0 and "nothing to roll back" in proc.stderr


def test_rollback_restores_the_autostart_order_and_delays(host):
    host.autostart.write_text("plex 10\nspamfilter-redis 5\nspamfilter-unbound\nspamfilter-rspamd 3\n"
                              "spamfilter\nimmich\n")
    original = host.autostart.read_text()
    _write(host, _four(), images=[AIO_IMG])
    lib_bash(host, f'sf_backup() {{ :; }}\nsf_aio_migrate "{AIO_IMG}" 0', **_migrate_env(host))
    assert host.autostart.read_text() == "plex 10\nspamfilter\nimmich\n"
    (host.app / "state" / "heartbeat").write_text(f"{int(time.time()) + 30} boot\n")
    lib_bash(host, "sf_aio_rollback keep", FAKE_CURL_BODY='{"ok":true}')
    # same order as before the migration (redis first), delay fields kept, no duplicates
    assert host.autostart.read_text() == original
    # a "name <delay>" line counts as present (no duplicate)
    lib_bash(host, "sf_autostart_add spamfilter-redis")
    assert host.autostart.read_text() == original


def test_restore_template_keeps_a_foreign_template(host):
    tpl = host.tpl / "my-spamfilter.xml"
    tpl.write_text("<Container><Name>spamfilter</Name><Repository>x:2.3.6</Repository></Container>\n")
    lib_bash(host, "sf_aio_restore_template")
    assert tpl.exists()  # not ours (no /appdata path): left alone


# ---------------------------------------------------------------- legacy guard (monitor)

def _legacy_running_state(aio_running=True):
    st = _after_migration()
    st["spamfilter"]["running"] = aio_running
    st["spamfilter-redis"]["running"] = True  # someone pressed Start in the Docker tab
    return st


def test_monitor_alerts_and_kills_an_old_redis_next_to_the_aio(host):
    _write(host, _legacy_running_state(), images=[AIO_IMG])
    (host.app / "state" / "heartbeat").write_text(f"{int(time.time())} boot\n")
    _monitor(host, FAKE_DOCKER_EXEC=json.dumps({"spamfilter drill": DRILL_OK}))
    out = json.loads((host.app / "state" / "host-status.json").read_text())
    assert out["legacy_running"] == ["spamfilter-redis"]
    alert = {a["key"]: a for a in out["alerts"]}["legacy-running"]
    assert "spamfilter-redis" in alert["text"] and "stoppet med det samme" in alert["text"]
    assert alert["notified"] is True  # immediate (delay 0)
    assert "kill spamfilter-redis" in host.calls()
    assert not read_state(host.state_file)["containers"]["spamfilter-redis"]["running"]
    assert "Gamle spamfilter-containere" in (host.tmp / "notify.log").read_text()


def test_monitor_never_kills_during_a_deploy_or_without_a_running_aio(host):
    import fcntl
    _write(host, _legacy_running_state(), images=[AIO_IMG])
    with open(host.env["SF_LOCK_FILE"], "w") as fh:  # rollback.sh holds the deploy lock
        fcntl.flock(fh, fcntl.LOCK_EX)
        _monitor(host, FAKE_DOCKER_EXEC=json.dumps({"spamfilter drill": DRILL_OK}))
    assert "kill" not in host.calls()
    out = json.loads((host.app / "state" / "host-status.json").read_text())
    assert "(spamfilter-redis er stoppet" not in {a["key"]: a for a in out["alerts"]}["legacy-running"]["text"]
    _write(host, _legacy_running_state(aio_running=False), images=[AIO_IMG])
    _monitor(host, FAKE_DOCKER_EXEC=json.dumps({"spamfilter drill": DRILL_OK}))
    assert "kill" not in host.calls()
    assert read_state(host.state_file)["containers"]["spamfilter-redis"]["running"]


def test_template_and_migration_warn_against_starting_the_old_containers():
    root = ET.fromstring((AIO / "unraid-template.xml").read_text())
    assert "Start aldrig de gamle" in root.findtext("Overview")
    assert "NEVER start spamfilter-redis" in (AIO / "lib-aio.sh").read_text()
    rb = (ROOT / ".build" / "RELEASE-2.4.0.md").read_text()
    assert "tmux" in rb and "never start" in rb.lower()


# ---------------------------------------------------------------- controller password / unbound port

def test_controller_secure_ip_is_pinned_in_the_aio(tmp_path):
    text = 'bind_socket = "*:11334";\npassword = "p";\nsecure_ip = "127.0.0.1";\nsecure_ip = "::1";\n'
    new, n = render.render_rspamd_text("worker-controller.inc", text)
    assert re.findall(r"^secure_ip.*$", new, re.M) == [render.SECURE_IP_LINE, render.SECURE_IP_LINE]
    assert "127.0.0.1\";" not in new.replace('bind_socket = "127.0.0.1:11334";', "") and n >= 3
    new, _ = render.render_rspamd_text("worker-controller.inc", 'password = "p";\n')
    assert new.endswith(render.SECURE_IP_LINE + "\n")  # appended when absent
    assert render.render_rspamd_text("worker-normal.inc", 'secure_ip = "127.0.0.1";\n')[1] == 0
    bad = {"worker": {"controller": {"secure_ip": ["127.0.0.1", "::1"], "bind_socket": "127.0.0.1:11334"}}}
    assert render.check_secure_ip(bad) == ["127.0.0.1", "::1"]
    good = {"worker": [{"controller": {"secure_ip": "192.0.2.1", "bind_socket": "127.0.0.1:11334"}}]}
    assert render.check_secure_ip(good) == [] and render.check_secure_ip({}) == []
    f = tmp_path / "dump.json"
    f.write_text(json.dumps(bad))
    proc = subprocess.run([sys.executable, str(AIO / "aio_render.py"), "check-binds", str(f)],
                          capture_output=True, text=True)
    assert proc.returncode == 1 and "exempts 127.0.0.1" in proc.stderr
    f.write_text(json.dumps(good))
    proc = subprocess.run([sys.executable, str(AIO / "aio_render.py"), "check-binds", str(f)],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "check-binds" in (AIO / "build-check.sh").read_text()


def test_rspamd_render_points_dns_at_the_unprivileged_unbound_port():
    for src, want in (('nameserver = ["spamfilter-unbound"];', 'nameserver = ["127.0.0.1:5353"];'),
                      ('nameserver = ["spamfilter-unbound:53"];', 'nameserver = ["127.0.0.1:5353"];'),
                      ('nameserver = ["spamfilter-unbound:53:10"];', 'nameserver = ["127.0.0.1:5353:10"];'),
                      ('nameserver = ["192.168.1.1"];', 'nameserver = ["192.168.1.1"];')):
        assert render.render_rspamd_text("options.inc", src + "\n")[0] == want + "\n"
    assert render.render_rspamd_text("redis.conf", 'servers = "spamfilter-redis:6379";\n')[0] == \
        'servers = "127.0.0.1:6379";\n'
    docker = (AIO / "Dockerfile").read_text()
    assert "LOOKALIKE_DNS_PORT=5353" in docker and "LOOKALIKE_DNS_SERVER=127.0.0.1" in docker
    assert "--sysctl" not in (AIO / "lib-aio.sh").read_text() + (AIO / "unraid-template.xml").read_text()


def test_image_records_its_debian_package_versions():
    assert "dpkg-query -W -f '${Package} ${Version}\\n' | sort > /usr/local/share/spamfilter-aio/packages.txt" in \
        (AIO / "Dockerfile").read_text()


# ================================================================ host-monitor / backup in AIO mode

def _monitor(host, *args, **extra):
    env = dict(host.env, SF_DOCKER_ROOT=str(host.tmp), **extra)
    proc = subprocess.run([str(DEPLOY / "host-monitor.sh"), *args], env=env, capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc


DRILL_OK = """;; ->>HEADER<<- opcode: QUERY, rcode: NOERROR, id: 1
2.0.0.127.zen.spamhaus.org.\t60\tIN\tA\t127.0.0.2
;; Query time: 23 msec
"""


def test_monitor_aio_layout(host):
    log = ("[rspamd] x rspamd_task_write_log: id: <a>, (default: F (no action): [1/15] [X(0.00){x.dk:server fail;}])\n"
           "[filter] SERVFAIL is just a word here\n[unbound] info: SERVFAIL <x. A IN>\n")
    health_log = "unhealthy: redis: no PONG\n" + json.dumps({"ok": False, "parts": {
        "filter": {"ok": True}, "rspamd": {"ok": True}, "redis": {"ok": False, "detail": "no PONG"},
        "unbound": {"ok": True}}})
    st = {"spamfilter": _ct(AIO_IMG, labels=dict(AIO_LABELS), health="unhealthy", health_log=health_log)}
    _write(host, st, images=[AIO_IMG])
    (host.app / "state" / "heartbeat").write_text(f"{int(time.time())} boot\n")
    _monitor(host, FAKE_CURL_BODY=json.dumps({"ok": True, "version": "2.4.0", "accounts": {"bynet": "idle"}}),
             FAKE_DOCKER_EXEC=json.dumps({"spamfilter drill": DRILL_OK,
                                          "spamfilter /usr/local/bin/sf-health bayes": "BAYES_SPAM 1",
                                          "spamfilter python": json.dumps({"status": {}, "settings": {}})}),
             FAKE_DOCKER_LOGS=json.dumps({"spamfilter": log}))
    out = json.loads((host.app / "state" / "host-status.json").read_text())
    assert out["layout"] == "aio" and set(out["containers"]) == {"spamfilter"}
    assert out["parts"]["redis"]["ok"] is False and out["parts"]["filter"]["ok"] is True
    assert out["dns"]["ok"] is True and out["rspamd"]["ok"] is True
    assert out["rbl"]["scans"] == 1 and out["rbl"]["scans_with_dns_fail"] == 1
    assert out["rbl"]["unbound_servfail"] == 1  # only the [unbound] line counts
    alert = {a["key"]: a for a in out["alerts"]}["container:spamfilter"]
    assert "usund" in alert["text"] and "fejler: redis" in alert["text"]
    calls = host.calls()
    assert "exec -u 10099:10099 spamfilter /usr/local/bin/sf-health bayes" in calls
    assert "exec -u 10099:10099 spamfilter python" in calls and "rspamc" not in calls
    assert "exec spamfilter drill -p 5353 @127.0.0.1" in calls  # the AIO's Unbound port
    # the old containers are only looked at by the legacy guard, never used
    old = [ln for ln in calls.splitlines() if re.search(r"spamfilter-(rspamd|unbound|redis|legacy)\b", ln)]
    assert old and all(ln.startswith("container inspect -f {{.State.Running}} ") for ln in old), old
    assert out["legacy_running"] == [] and "legacy-running" not in {a["key"] for a in out["alerts"]}


def test_monitor_legacy_layout_unchanged(host):
    four = {n: _ct(n + ":img") for n in ("spamfilter", "spamfilter-rspamd", "spamfilter-redis",
                                         "spamfilter-unbound")}
    _write(host, four)
    _monitor(host, FAKE_DOCKER_EXEC=json.dumps({"spamfilter-unbound drill": DRILL_OK}))
    out = json.loads((host.app / "state" / "host-status.json").read_text())
    assert out["layout"] == "legacy" and out["parts"] is None and len(out["containers"]) == 4
    assert out["dns"]["ok"] is True


_AIO_BACKUP_DOCKER = r'''#!/bin/bash
printf '%s\n' "$*" >>"$FAKE_BACKUP_CALLS"
case "$1 $2" in
  "container inspect")
    case "$4" in
      *spamfilter.layout*) echo aio ;;
      *"range \$k, \$v := .Config.Labels"*) echo "spamfilter.layout=aio spamfilter.version=2.16.0 " ;;
      *Image*) echo "sha256:img-$5" ;;
      *Running*) echo true ;;
    esac ;;
  "exec -u")
    if [[ "$3" == 10099:10099 && "$4" == spamfilter ]]; then
      dest="${*: -1}"
      cp "$SPAMFILTER_APP/state/spamfilter.db" "$SPAMFILTER_APP$dest"
    elif [[ "$3" == 999:1000 && "$4" == spamfilter ]]; then
      :
    else
      echo "unexpected exec $*" >&2; exit 2
    fi ;;
  "run --rm") : ;;
  *) echo "fake docker: unsupported $*" >&2; exit 2 ;;
esac
'''


def test_backup_and_verify_in_the_aio_layout(tmp_path):
    import sqlite3
    import tarfile

    app = tmp_path / "app"
    for sub in ("operations", "state", "config", "rspamd/local.d", "redis", "redis-config"):
        (app / sub).mkdir(parents=True)
    db = sqlite3.connect(app / "state" / "spamfilter.db")
    db.execute("CREATE TABLE messages(id INTEGER)")
    db.commit()
    db.close()
    (app / "config" / "accounts.yml").write_text("accounts: []\n")
    (app / "redis-config" / "redis.conf").write_text('requirepass "r"\n')
    (app / "redis" / "dump.rdb").write_bytes(b"REDIS0011")
    (app / "state" / "redis.password").write_text("r\n")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in (("docker", _AIO_BACKUP_DOCKER),
                       ("id", '#!/bin/bash\n[[ "$1" == -u ]] && { echo 0; exit 0; }\nexec /usr/bin/id "$@"\n')):
        (bindir / name).write_text(body)
        (bindir / name).chmod(0o755)
    calls = tmp_path / "docker.log"
    env = {"PATH": f"{bindir}:{os.environ['PATH']}", "HOME": str(tmp_path), "SPAMFILTER_APP": str(app),
           "SF_BACKUP_LOCK": str(tmp_path / "b.lock"), "SF_NOTIFY_BIN": "/nonexistent",
           "FAKE_BACKUP_CALLS": str(calls), "LC_ALL": "C"}
    proc = subprocess.run(["bash", str(DEPLOY / "backup-and-verify.sh")], env=env, capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "layout: aio" in proc.stdout
    log = calls.read_text()
    assert "exec -u 10099:10099 spamfilter python" in log and "exec -u 999:1000 spamfilter sh" in log
    assert "spamfilter-redis" not in log
    st = json.loads((app / "state" / "backup-status.json").read_text())
    with tarfile.open(st["archive"]) as tf:
        assert tf.extractfile("./meta/layout").read() == b"aio\n"
        assert tf.extractfile("./meta/redis-image-id").read() == tf.extractfile("./meta/filter-image-id").read()


# ================================================================ docs / CI

def test_ci_builds_and_smoke_tests_the_aio_image():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    rel = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    assert "deploy/aio/build.sh --context-only" in ci and "push: false" in ci
    assert "deploy/aio/smoke-test.sh" in ci and "--fresh" in ci and "--learn-test" in ci
    assert "deploy/aio/build.sh --context-only" in rel
    # exactly the smoke-tested image is pushed - no second build
    assert "push: true" not in rel and rel.count("docker/build-push-action") == 1
    assert rel.index("Smoke test before publishing") < rel.index('docker push "$image:$version"')
    assert "REDIS_AIO_DIGEST=sha256:[0-9a-f]{64}" in rel  # no release from an unpinned Redis
    assert "${{ steps.v.outputs.image }}:${{ steps.v.outputs.version }}" in rel
    assert "${{ steps.v.outputs.image }}:beta" in rel
    assert "GITHUB_REPOSITORY,," in rel  # lowercased owner
    assert "filter/Dockerfile.unraid" in ci  # the filter-only image is still built (not pushed)
    assert "file: ./filter/Dockerfile.unraid" not in rel  # ... and no longer published
    # 2.10 Opdateringer: every release carries the source package + .sha256 the host helper installs
    assert 'git archive --format=tar.gz --prefix="spamfilter-$version/"' in rel
    assert "spamfilter-$version-source.tar.gz" in rel and "${{ env.pkg }}.sha256" in rel


def test_runbook_and_docs_exist():
    rb = (ROOT / ".build" / "RELEASE-2.4.0.md").read_text()
    for step in ("deploy/aio/build.sh", "deploy/aio/smoke-test.sh", "deploy/aio/migrate.sh --dry-run",
                 "deploy/aio/rollback.sh", "deploy/aio/cleanup.sh --yes", "install-user-scripts.sh"):
        assert step in rb, step
    inst = (ROOT / "INSTALLATION.md").read_text()
    assert "én container" in inst.lower() or "én container" in inst
    assert "deploy/aio/migrate.sh" in inst and "my-spamfilter.xml" in inst


# ================================================================ 2.6 (B3): /backup mount

def test_backup_mount_only_when_the_host_dir_exists(host):
    share = host.tmp / "user" / "backups"
    dirn = share / "spamfilter"
    a = " ".join(run_args_env(host, SF_AIO_BACKUP=str(dirn)))
    assert ":/backup" not in a  # no dir yet: an existing install keeps running unchanged
    dirn.mkdir(parents=True)
    a = run_args_env(host, SF_AIO_BACKUP=str(dirn))
    assert a[a.index(f"{dirn}:/backup") - 1] == "-v"
    assert ":/backup" not in " ".join(run_args_env(host, SF_AIO_BACKUP=""))
    t = lib_bash(host, 'sf_aio_run_args spamfilter-aio-test "" "$APP" 127.0.0.1 18090 test; printf "%s\\n" "${SF_OPTS[@]}"',
                 SF_AIO_BACKUP=str(dirn)).stdout
    assert ":/backup" not in t  # the smoke-test copy never writes backups


def run_args_env(host, **env):
    out = lib_bash(host, 'sf_aio_run_args spamfilter; printf "%s\\n" "${SF_OPTS[@]}"', **env).stdout
    return out.splitlines()


def test_prepare_backup_creates_the_dir_on_the_share_only(host):
    share = host.tmp / "user" / "backups"
    dirn = share / "spamfilter"
    p = lib_bash(host, "sf_aio_prepare_backup; echo READY=$SF_AIO_BACKUP_READY", SF_AIO_BACKUP=str(dirn))
    assert "READY=0" in p.stdout and "create the Unraid share" in p.stderr and not dirn.exists()
    share.mkdir(parents=True)
    p = lib_bash(host, "sf_aio_prepare_backup; echo READY=$SF_AIO_BACKUP_READY; sf_aio_run_args spamfilter; "
                       'printf "%s\\n" "${SF_OPTS[@]}"', SF_AIO_BACKUP=str(dirn), DRY_RUN="1")
    assert "READY=1" in p.stdout and f"{dirn}:/backup" in p.stdout and not dirn.exists()  # dry run: planned only
    p = lib_bash(host, "sf_aio_prepare_backup; echo READY=$SF_AIO_BACKUP_READY", SF_AIO_BACKUP=str(dirn))
    assert "READY=1" in p.stdout and dirn.is_dir() and (dirn.stat().st_mode & 0o777) == 0o700
    p = lib_bash(host, "sf_aio_prepare_backup; echo B=[$SF_AIO_BACKUP]", SF_AIO_BACKUP=str(host.app / "backups"))
    assert "inside the app dir" in p.stderr and "B=[]" in p.stdout


def test_update_prepares_backup_before_recreate():
    text = (AIO / "update.sh").read_text()
    assert text.index("sf_aio_prepare_backup") < text.index('sf_recreate spamfilter sf_gate_aio "$image"')
    lib = (AIO / "lib-aio.sh").read_text()
    mig = lib[lib.index("sf_aio_migrate() {"):]
    assert mig.index("sf_aio_prepare_backup") < mig.index('sf_aio_run_args spamfilter "$image"')


def test_template_has_the_optional_backup_path():
    root = ET.fromstring((AIO / "unraid-template.xml").read_text())
    cfg = {c.get("Target"): c for c in root.findall("Config")}
    b = cfg["/backup"]
    assert b.get("Type") == "Path" and b.get("Required") == "false" and b.text == "/mnt/user/backup/spamfilter"
    assert "anden disk end app-mappen" in b.get("Description") and "10099" in b.get("Description")
    no = ET.fromstring(_template_xml({"SF_AIO_BACKUP": ""}))
    assert "/backup" not in {c.get("Target") for c in no.findall("Config")}


def test_entrypoint_hands_an_empty_root_backup_dir_to_the_filter(tmp_path):
    app = _live_appdata(tmp_path)
    env, log = _entrypoint_env(tmp_path, app)
    bdir = tmp_path / "backup"
    bdir.mkdir()
    bdir.chmod(0o555)  # not writable for the (fake) uid 10099, like Docker's fresh root dir
    calls = tmp_path / "chown.log"
    (Path(env["PATH"].split(":")[0]) / "chown").write_text(f'#!/bin/bash\necho "chown $*" >>"{calls}"\n')
    env["SF_AIO_BACKUP_DIR"] = str(bdir)
    try:
        proc = subprocess.run([str(AIO / "sf-entrypoint")], env=env, capture_output=True, text=True, timeout=60)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        backup_chowns = [c for c in calls.read_text().splitlines() if "/run/" not in c]
        # (2.7: the new ClamAV signature dir is the only other one)
        assert backup_chowns == [f"chown 3310:3310 {app}/clamav", f"chown 10099:10099 {bdir}"]
        assert (bdir.stat().st_mode & 0o777) == 0o700
        # not empty -> never touched, only a warning
        calls.unlink()
        bdir.chmod(0o755)
        (bdir / "x.sfbak").write_text("x")
        bdir.chmod(0o555)
        proc = subprocess.run([str(AIO / "sf-entrypoint")], env=env, capture_output=True, text=True, timeout=60)
        assert proc.returncode == 0 and "not writable for uid 10099" in proc.stdout
        assert str(bdir) not in calls.read_text()
        # inside the app dir -> refuse to start
        env["SF_AIO_BACKUP_DIR"] = str(app / "backup")
        proc = subprocess.run([str(AIO / "sf-entrypoint")], env=env, capture_output=True, text=True, timeout=60)
        assert proc.returncode == 1 and "another disk" in proc.stderr
    finally:
        bdir.chmod(0o755)


# ---------------------------------------------------------------- 2.6.1: rspamd rules on update

RSPAMD_SRC = ROOT / "rspamd" / "local.d"


def _local_d(host, fuzzy_live: bool = True):
    ld = host.app / "rspamd" / "local.d"
    for f in ("redis.conf", "worker-controller.inc"):
        (ld / f).write_text("secret stand-in\n")
    (ld / "multimap.conf").write_text("old multimap\n")
    (ld / "fuzzy_check.conf").write_text("enabled = true;\n" if fuzzy_live else "enabled = false;\n")
    return ld


def test_update_installs_rspamd_rules_tested_with_the_new_image(host):
    ld = _local_d(host)
    seen = host.tmp / "seen.txt"
    fake = ('docker() { local a v="" img=""; for a in "$@"; do case "$a" in '
            '*:/run/spamfilter/rspamd/local.d:ro) v="${a%%:*}";; imap-spamfilter-unraid:*) img="$a";; esac; done; '
            '{ echo "img=$img"; (cd "$v" && find . -type f | sort); } > "' + str(seen) + '"; echo "syntax OK"; }\n')
    lib_bash(host, fake + 'sf_aio_install_rspamd_config "imap-spamfilter-unraid:9.9.9"')
    staged = seen.read_text().split()
    assert "img=imap-spamfilter-unraid:9.9.9" in staged
    assert "./maps.d/th_subject_brands.re" in staged and "./redis.conf" in staged
    assert (ld / "multimap.conf").read_bytes() == (RSPAMD_SRC / "multimap.conf").read_bytes()
    for p in (RSPAMD_SRC / "maps.d").iterdir():
        assert (ld / "maps.d" / p.name).read_bytes() == p.read_bytes(), p.name
    # Secrets untouched.
    assert (ld / "redis.conf").read_text() == "secret stand-in\n"


def test_update_rule_install_follows_versions_env_fuzzy(host):
    ld = _local_d(host, fuzzy_live=False)
    lib_bash(host, 'docker() { echo "syntax OK"; }\nsf_aio_install_rspamd_config "imap-spamfilter-unraid:9.9.9"')
    want = "fuzzy_check.conf.readonly" if versions().get("ENABLE_FUZZY") == "1" else "fuzzy_check.conf"
    assert (ld / "fuzzy_check.conf").read_bytes() == (RSPAMD_SRC / want).read_bytes()


def test_update_rule_configtest_failure_installs_nothing(host):
    ld = _local_d(host)
    proc = lib_bash(host, 'docker() { echo "bad regexp"; return 1; }\n'
                          'sf_aio_install_rspamd_config "imap-spamfilter-unraid:9.9.9"', check=False)
    assert proc.returncode != 0 and "configtest failed" in proc.stderr
    assert (ld / "multimap.conf").read_text() == "old multimap\n"
    assert not (ld / "maps.d").exists()


def test_update_failed_gate_restores_the_previous_rspamd_rules(host):
    new = "imap-spamfilter-unraid:2.11.2"
    ld = _local_d(host)
    _write(host, {"spamfilter": _ct(AIO_IMG, labels=dict(AIO_LABELS))}, images=[new, AIO_IMG])
    proc = lib_bash(host, 'sf_set_state_owner() { :; }\nsf_rspamd_preflight() { :; }\nsf_install_traps\n'
                          f'sf_aio_install_rspamd_config "{new}"\nsf_recreate spamfilter sf_gate_aio "{new}"',
                    check=False, SF_LAYOUT="aio", SF_KEEP_ROLLBACK="0",
                    **_migrate_env(host, FAKE_NEW_HEALTH="unhealthy"))
    assert proc.returncode != 0 and "rolled back" in proc.stderr
    assert (ld / "multimap.conf").read_text() == "old multimap\n"
    assert not [p for p in (ld / "maps.d").iterdir()]
    assert (ld / "fuzzy_check.conf").read_text() == "enabled = true;\n"


def test_update_installs_rules_before_recreate():
    text = (AIO / "update.sh").read_text()
    assert text.index('sf_aio_install_rspamd_config "$image"') < text.index('sf_recreate spamfilter sf_gate_aio "$image"')
    assert text.index("sf_backup") < text.index('sf_aio_install_rspamd_config "$image"')


# ================================================================ 2.7: ClamAV

CLAMAV = AIO / "clamav"


def _clamav_conf(name: str) -> dict[str, list[str]]:
    """ClamAV config file -> {Option: [values]} (comments and blanks dropped)."""
    out: dict[str, list[str]] = {}
    for line in (CLAMAV / name).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition(" ")
        out.setdefault(key, []).append(value.strip())
    return out


def _size(v: str) -> int:
    m = re.fullmatch(r"(\d+)([KM]?)", v)
    assert m, v
    return int(m.group(1)) * {"": 1, "K": 1024, "M": 1024 * 1024}[m.group(2)]


def test_clamd_conf_unix_socket_only_and_paths_agree_with_rspamd_and_health():
    sys.path.insert(0, str(ROOT / "filter"))
    import aio_health
    c, f = _clamav_conf("clamd.conf"), _clamav_conf("freshclam.conf")
    assert not [k for k in c if k.startswith("TCP")]  # nothing listens on an IP address
    assert "Example" not in c and "Example" not in f
    sock = aio_health.CLAMAV_SOCKET
    assert c["LocalSocket"] == [sock] and sock == "/run/spamfilter/clamav/clamd.sock"
    av = (ROOT / "rspamd" / "local.d" / "antivirus.conf").read_text()
    assert f'servers = "{sock}";' in av
    assert c["LocalSocketMode"] == ["666"]  # the 0750 3310:11333 directory is the access check
    assert c["DatabaseDirectory"] == f["DatabaseDirectory"] == [aio_health.CLAMAV_DB] == ["/appdata/clamav"]
    assert c["Foreground"] == f["Foreground"] == ["yes"]
    assert "User" not in c  # supervisord already runs it as clamav
    assert c["ConcurrentDatabaseReload"] == ["no"] and c["DetectPUA"] == ["no"] and c["PhishingScanURLs"] == ["no"]
    max_size = int(re.search(r"max_size = (\d+);", av).group(1))
    assert _size(c["StreamMaxLength"][0]) >= max_size and _size(c["MaxFileSize"][0]) >= max_size
    assert f["DatabaseMirror"] == ["database.clamav.net"] and 1 <= int(f["Checks"][0]) <= 12
    assert f["NotifyClamd"] == ["/etc/spamfilter/clamav/clamd.conf"] and f["DatabaseOwner"] == ["clamav"]
    assert f["TestDatabases"] == ["yes"]
    # 2.7 fix: clamd stops a slow scan itself, before rspamd's antivirus timeout.
    timeout_ms = float(re.search(r"timeout = ([\d.]+);", av).group(1)) * 1000
    assert 0 < int(c["MaxScanTime"][0]) < timeout_ms
    assert int(c["MaxThreads"][0]) == 8 and c["AlertExceedsMax"] == ["yes"]


def test_dockerfile_installs_clamav_with_a_fixed_uid_before_the_packages():
    text = (AIO / "Dockerfile").read_text()
    code = re.sub(r"#.*", "", text)
    assert re.search(r"\bclamav-daemon clamav-freshclam\b", code)
    # The user exists BEFORE apt-get install: Debian's postinst only adds a missing clamav user.
    assert code.index("groupadd --system --gid 3310 clamav") < code.index("apt-get install")
    assert code.index("useradd --system --uid 3310 --gid 3310") < code.index("apt-get install")
    assert "COPY aio/clamav/ /etc/spamfilter/clamav/" in code
    assert "aio/sf-clamav /usr/local/bin/" in code and "/usr/local/bin/sf-clamav" in code
    assert "SF_CLAMAV=1" in code
    assert len(re.findall(r"^EXPOSE", text, re.M)) == 1  # clamd publishes nothing


def test_build_check_verifies_clamav_offline():
    text = (AIO / "build-check.sh").read_text()
    for needle in ('"$(uidgid 3310)" == 3310:3310', "clamconf -c", "TCP(Socket|Addr)", "clamd.sock",
                   "database.clamav.net", "/usr/sbin/clamd /usr/bin/freshclam", "sf-build-check.hdb",
                   'h.clamd_request(b"INSTREAM"', "--reuid=3310"):
        assert needle in text, needle
    # no EICAR (or any real malware string) in the image or the repo script
    assert "EICAR" not in text.upper().replace("NO EICAR", "")


def test_build_context_stages_the_clamav_files(tmp_path):
    ctx = tmp_path / "ctx"
    env = dict(os.environ, SPAMFILTER_APP=str(tmp_path / "noapp"))
    subprocess.run([str(AIO / "build.sh"), "--context-only", str(ctx)], env=env, check=True,
                   capture_output=True, text=True, timeout=60)
    for f in ("clamd.conf", "freshclam.conf"):
        assert (ctx / "aio" / "clamav" / f).read_bytes() == (CLAMAV / f).read_bytes()
    assert os.access(ctx / "aio" / "sf-clamav", os.X_OK)
    assert os.access(ctx / "aio" / "sf-sigs", os.X_OK)  # 2.8 (A1)
    assert (ctx / "aio" / "clamav" / "sanesecurity.gpg").is_file()
    assert (ctx / "aio" / "share" / "rspamd" / "antivirus.conf").is_file()


def _clamav_entrypoint(tmp_path, **env_extra):
    app = _live_appdata(tmp_path)
    shutil.copy(ROOT / "rspamd" / "local.d" / "antivirus.conf", app / "rspamd" / "local.d" / "antivirus.conf")
    env, log = _entrypoint_env(tmp_path, app)
    sup = Path(env["PATH"].split(":")[0]) / "supervisord"
    sup.write_text(f'#!/bin/bash\necho "supervisord autostart=$SF_CLAMAV_AUTOSTART" >>"{log}"\n')
    env.update(env_extra)
    return app, env, log


def test_entrypoint_clamav_on_creates_the_signature_dir_and_socket_dir(tmp_path):
    app, env, log = _clamav_entrypoint(tmp_path)
    proc = subprocess.run([str(AIO / "sf-entrypoint")], env=env, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    run = tmp_path / "run"
    assert (app / "clamav").is_dir() and (app / "clamav").stat().st_mode & 0o777 == 0o750
    assert (run / "clamav").is_dir() and (run / "clamav").stat().st_mode & 0o777 == 0o750
    assert (run / "clamav.state").read_text() == "on nodb\n"   # 2.7 fix: no signatures yet
    rendered = (run / "rspamd" / "local.d" / "antivirus.conf").read_text()
    assert rendered == (ROOT / "rspamd" / "local.d" / "antivirus.conf").read_text()
    assert log.read_text().splitlines()[-1] == "supervisord autostart=true"
    assert "ClamAV: created" in proc.stdout
    # second start: the dir exists and is writable -> left alone, still on
    before = _snapshot(app)
    proc = subprocess.run([str(AIO / "sf-entrypoint")], env=env, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0 and _snapshot(app) == before and "ClamAV: on" in proc.stdout


def test_entrypoint_sf_clamav_0_skips_clamav_and_disables_rspamd_antivirus(tmp_path):
    app, env, log = _clamav_entrypoint(tmp_path, SF_CLAMAV="0")
    before = _snapshot(app)
    proc = subprocess.run([str(AIO / "sf-entrypoint")], env=env, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _snapshot(app) == before and not (app / "clamav").exists()
    run = tmp_path / "run"
    assert not (run / "clamav").exists()
    assert (run / "clamav.state").read_text() == "off SF_CLAMAV=0\n"
    assert (run / "rspamd" / "local.d" / "antivirus.conf").read_text() == render.ANTIVIRUS_OFF
    # the app dir keeps the real file (a later SF_CLAMAV=1 start needs it)
    assert "clamav {" in (app / "rspamd" / "local.d" / "antivirus.conf").read_text()
    assert log.read_text().splitlines()[-1] == "supervisord autostart=false"
    assert "ClamAV: off (SF_CLAMAV=0)" in proc.stdout and "WARNING" not in proc.stdout


@pytest.mark.parametrize("breakage", ["readonly-app", "symlink"])
def test_entrypoint_clamav_problems_never_block_the_start(tmp_path, breakage):
    app, env, log = _clamav_entrypoint(tmp_path)
    if breakage == "symlink":
        (tmp_path / "elsewhere").mkdir()
        (app / "clamav").symlink_to(tmp_path / "elsewhere")
    else:
        app.chmod(0o555)
    try:
        proc = subprocess.run([str(AIO / "sf-entrypoint")], env=env, capture_output=True, text=True, timeout=60)
    finally:
        app.chmod(0o755)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "WARNING: ClamAV is off for this run" in proc.stdout
    state = (tmp_path / "run" / "clamav.state").read_text()
    assert state.startswith("off ") and ("symlink" in state if breakage == "symlink" else "cannot create" in state)
    assert (tmp_path / "run" / "rspamd" / "local.d" / "antivirus.conf").read_text() == render.ANTIVIRUS_OFF
    assert log.read_text().splitlines()[-1] == "supervisord autostart=false"


def test_render_rspamd_replaces_the_legacy_disabled_antivirus_conf(local_d, tmp_path):
    """2.7 fix: a migrated app dir has the 4-container layout's disabled copy;
    with ClamAV on the image's own antivirus.conf is rendered instead."""
    shutil.copy(ROOT / "rspamd" / "local.d" / "antivirus.conf.legacy", local_d / "antivirus.conf")
    image = tmp_path / "image-antivirus.conf"
    shutil.copy(ROOT / "rspamd" / "local.d" / "antivirus.conf", image)
    ch = render.render_rspamd(local_d, tmp_path / "on", antivirus_src=image)
    assert ch["antivirus.conf"] == 1
    assert (tmp_path / "on" / "antivirus.conf").read_bytes() == image.read_bytes()
    assert (local_d / "antivirus.conf").read_bytes() == (ROOT / "rspamd" / "local.d" / "antivirus.conf.legacy"
                                                          ).read_bytes()  # the app dir is never changed
    # SF_CLAMAV=0 still wins; without a source the copy is kept as it is.
    render.render_rspamd(local_d, tmp_path / "off", antivirus=False, antivirus_src=image)
    assert (tmp_path / "off" / "antivirus.conf").read_text() == render.ANTIVIRUS_OFF
    render.render_rspamd(local_d, tmp_path / "plain")
    assert "enabled = false;" in (tmp_path / "plain" / "antivirus.conf").read_text()


def test_render_rspamd_no_antivirus(local_d, tmp_path):
    shutil.copy(ROOT / "rspamd" / "local.d" / "antivirus.conf", local_d / "antivirus.conf")
    on = render.render_rspamd(local_d, tmp_path / "on")
    assert "antivirus.conf" not in on  # nothing to adjust: a unix socket, no old host
    assert (tmp_path / "on" / "antivirus.conf").read_bytes() == (local_d / "antivirus.conf").read_bytes()
    off = render.render_rspamd(local_d, tmp_path / "off", antivirus=False)
    assert off["antivirus.conf"] == 1
    assert (tmp_path / "off" / "antivirus.conf").read_text() == render.ANTIVIRUS_OFF
    assert re.search(r"^enabled = false;$", render.ANTIVIRUS_OFF, re.M)
    proc = subprocess.run([sys.executable, str(AIO / "aio_render.py"), "rspamd", "--src", str(local_d),
                           "--dst", str(tmp_path / "cli"), "--no-antivirus"], capture_output=True, text=True)
    assert proc.returncode == 0 and "antivirus.conf (1)" in proc.stdout
    # a fresh install gets antivirus.conf like every other non-secret rule file
    assert "antivirus.conf" in render.RSPAMD_FILES


def test_aio_render_rspamd_files_equal_lib_sh():
    m = re.search(r"^SF_RSPAMD_FILES=\(([^)]*)\)", (DEPLOY / "lib.sh").read_text(), re.M)
    assert tuple(m.group(1).split()) == render.RSPAMD_FILES


def _sf_clamav_env(tmp_path):
    bindir = tmp_path / "cbin"
    bindir.mkdir()
    log = tmp_path / "clamav.log"
    for name in ("clamd", "freshclam"):
        (bindir / name).write_text(f'#!/bin/bash\necho "{name} $*" >>"{log}"\n')
        (bindir / name).chmod(0o755)
    db = tmp_path / "db"
    db.mkdir()
    env = dict(os.environ, SF_CLAMAV_DB=str(db), SF_CLAMAV_POLL="1", SF_CLAMD=str(bindir / "clamd"),
               SF_FRESHCLAM=str(bindir / "freshclam"), SF_CLAMAV_CONF_DIR="/etc/spamfilter/clamav")
    return env, db, log


def test_sf_clamav_freshclam_runs_in_daemon_mode(tmp_path):
    env, db, log = _sf_clamav_env(tmp_path)
    subprocess.run([str(AIO / "sf-clamav"), "freshclam"], env=env, check=True, timeout=20)
    assert log.read_text() == "freshclam --config-file=/etc/spamfilter/clamav/freshclam.conf --daemon --foreground\n"
    assert subprocess.run([str(AIO / "sf-clamav"), "bogus"], env=env, capture_output=True).returncode == 2


def test_sf_clamav_clamd_waits_for_a_complete_signature_set(tmp_path):
    env, db, log = _sf_clamav_env(tmp_path)
    (db / "main.cvd").write_bytes(b"x" * 10)
    (db / "daily.cld").write_bytes(b"")  # empty = still incomplete
    proc = subprocess.Popen([str(AIO / "sf-clamav"), "clamd"], env=env, stdout=subprocess.PIPE, text=True)
    try:
        time.sleep(2.5)
        assert proc.poll() is None and not log.exists()  # still waiting, never exited
        (db / "daily.cld").write_bytes(b"y" * 10)
        assert proc.wait(timeout=10) == 0
    finally:
        proc.kill()
    out = proc.stdout.read()
    assert "waiting for the first ClamAV signatures" in out and "starting clamd" in out
    assert log.read_text() == "clamd --config-file=/etc/spamfilter/clamav/clamd.conf --foreground\n"
    # signatures present: straight to clamd
    log.unlink()
    subprocess.run([str(AIO / "sf-clamav"), "clamd"], env=env, check=True, timeout=10)
    assert log.read_text().startswith("clamd ")


@pytest.mark.parametrize("prog", ["clamd", "freshclam"])
def test_sf_fatal_listener_keeps_the_container_for_clamav(tmp_path, prog):
    victim = subprocess.Popen(["sleep", "60"])
    try:
        pidfile = tmp_path / "supervisord.pid"
        pidfile.write_text(f"{victim.pid}\n")
        payload = f"processname:{prog} groupname:{prog} from_state:BACKOFF"
        header = ("ver:3.0 server:supervisor serial:1 pool:sf-fatal poolserial:1 eventname:PROCESS_STATE_FATAL "
                  f"len:{len(payload)}\n")
        proc = subprocess.run([str(AIO / "sf-fatal-listener")], input=header + payload,
                              env=dict(os.environ, SF_SUPERVISOR_PIDFILE=str(pidfile)),
                              capture_output=True, text=True, timeout=20)
        assert proc.stdout == "READY\nRESULT 2\nOKREADY\n"
        assert f"{prog} cannot be started (FATAL)" in proc.stderr and "keeps running" in proc.stderr
        time.sleep(0.3)
        assert victim.poll() is None  # supervisord (the victim) was not stopped
    finally:
        victim.kill()


def test_aio_run_args_pass_sf_clamav(host):
    a = run_args(host, "spamfilter")
    assert not [x for x in a if x.startswith("SF_CLAMAV=")]  # unset: the image default (on)
    out = lib_bash(host, 'sf_aio_run_args spamfilter; printf "%s\\n" "${SF_OPTS[@]}"', SF_CLAMAV="0").stdout
    assert "SF_CLAMAV=0" in out.splitlines()
    root = ET.fromstring(_template_xml({"SF_CLAMAV": "0"}))
    assert {c.get("Target"): c.text for c in root.findall("Config")}["SF_CLAMAV"] == "0"


def test_ci_smoke_tests_run_without_the_clamav_download():
    for wf in ("ci.yml", "release.yml"):
        text = (ROOT / ".github" / "workflows" / wf).read_text()
        smoke = [line for line in text.splitlines() if "SF_AIO_MEMORY=" in line]
        assert smoke and all("SF_CLAMAV=0" in line for line in smoke), wf
    smoke = (AIO / "smoke-test.sh").read_text()
    assert "--clamav-scan) clamscan=1 ;;" in smoke and "sf-health clamav" in smoke
    assert "EICAR" in smoke and "X5O" not in smoke  # the test file only base64-encoded


def test_update_installs_antivirus_conf(host):
    ld = _local_d(host)
    lib_bash(host, 'docker() { echo "syntax OK"; }\nsf_aio_install_rspamd_config "imap-spamfilter-unraid:9.9.9"')
    assert (ld / "antivirus.conf").read_bytes() == (RSPAMD_SRC / "antivirus.conf").read_bytes()
