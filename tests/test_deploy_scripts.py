"""INFRA: deploy scripts, versions.env, Dockerfile, rspamd/unbound configs.

Real docker is never used: tests/fakes_deploy.py puts fake `docker`,
`curl` and `notify` binaries first on PATH and keeps container state in a
JSON file, which is enough to exercise recreate/rollback, the User Scripts
installer, host-monitor.sh and the failure path of backup-and-verify.sh.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_deploy import base_env, install_fake_bin, read_state, write_state  # noqa: E402

SCRIPTS = sorted(DEPLOY.glob("*.sh"))
# Scripts that change host state and must offer --dry-run.
CHANGING = ["backup-and-verify.sh", "backup-offsite.sh", "host-monitor.sh", "init-dashboard-user.sh", "init-host.sh",
            "install-user-scripts.sh", "migrate-2.0.sh", "recreate-filter.sh",
            "recreate-infra.sh", "run-containers.sh", "update-runner.sh"]


def versions() -> dict[str, str]:
    out = {}
    for line in (DEPLOY / "versions.env").read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            k, _, v = line.partition("=")
            out[k] = v
    return out


# ---------------------------------------------------------------- static checks

def test_expected_scripts_exist():
    names = {p.name for p in SCRIPTS}
    for name in CHANGING + ["lib.sh"]:
        assert name in names, name


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_bash_syntax(script):
    subprocess.run(["bash", "-n", str(script)], check=True)


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_strict_mode_and_shebang(script):
    text = script.read_text()
    assert text.startswith("#!/bin/bash\n")
    if script.name != "lib.sh":  # sourced; inherits the caller's options
        assert re.search(r"^set -E?euo pipefail$", text, re.M), script.name


@pytest.mark.parametrize("name", CHANGING)
def test_dry_run_and_app_override(name):
    text = (DEPLOY / name).read_text()
    assert "--dry-run" in text
    sourced = ". \"$(dirname \"${BASH_SOURCE[0]}\")/lib.sh\"" in text
    assert sourced or "SPAMFILTER_APP" in text


def test_shellcheck_clean():
    sc = shutil.which("shellcheck")
    if not sc:
        pytest.skip("shellcheck not installed")
    subprocess.run([sc, "-x", *[str(p.relative_to(ROOT)) for p in SCRIPTS]], cwd=ROOT, check=True)


def test_versions_env_pins():
    v = versions()
    assert v["VERSION"] == "2.16.0"
    # 2.4: AIO_IMAGE is production; FILTER_IMAGE (suffix -filter) is the
    # filter-only image of the 4-container layout (rollback only).
    assert v["AIO_IMAGE"] == "imap-spamfilter-unraid:2.16.0"
    assert v["FILTER_IMAGE"] == "imap-spamfilter-unraid:2.16.0-filter"
    for key in ("REDIS_IMAGE", "RSPAMD_IMAGE", "UNBOUND_IMAGE", "FILTER_BASE_IMAGE"):
        assert re.search(r"@sha256:[0-9a-f]{64}$", v[key]), key
    assert v["ENABLE_FUZZY"] in ("0", "1")
    assert (v["FILTER_UID"], v["FILTER_GID"]) == ("10099", "10099")


def test_dockerfile_contract():
    text = (ROOT / "filter" / "Dockerfile.unraid").read_text()
    from_line = next(line for line in text.splitlines() if line.startswith("FROM "))
    assert from_line.split()[1] == versions()["FILTER_BASE_IMAGE"]
    assert "COPY *.py /app/" in text and "COPY static/ /app/static/" in text
    assert "favicon.png" in text and "rm -f /app/test_*.py" in text
    assert "chown -R root:root /app" in text and "chmod 0644" in text
    assert re.search(r"^ENV HOME=/tmp", text, re.M)
    assert re.search(r"^USER 10099:10099$", text, re.M)
    assert ("HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \\\n"
            '    CMD ["python", "/app/healthcheck.py"]') in text
    assert 'org.opencontainers.image.version="2.16.0-unraid"' in text
    ignore = (ROOT / "filter" / "Dockerfile.unraid.dockerignore").read_text()
    assert "test_*.py" in ignore


def test_rspamd_local_d():
    d = ROOT / "rspamd" / "local.d"
    assert "rbls" not in (d / "rbl.conf").read_text()
    assert re.search(r"^enabled = false;", (d / "greylist.conf").read_text(), re.M)
    actions = (d / "actions.conf").read_text()
    assert "reject = 15;" in actions and "add_header = 6;" in actions
    assert not re.search(r"^greylist = \d", actions, re.M)
    opts = (d / "options.inc").read_text()
    assert "dns_max_requests = 128;" in opts and "spamfilter-unbound" in opts
    bayes = (d / "classifier-bayes.conf").read_text()
    for needle in ('backend = "redis";', "new_schema = true;", "users_enabled = true;",
                   "min_learns = 200;"):
        assert needle in bayes, needle
    # No autolearn: scans (shadow, calibration) must never write to Bayes.
    assert re.search(r"^autolearn = false;$", bayes, re.M)
    assert not re.search(r"^autolearn\s*\{", bayes, re.M)
    assert not re.search(r"^expire", bayes, re.M)
    assert re.search(r"^enabled = false;", (d / "fuzzy_check.conf").read_text(), re.M)
    ro = (d / "fuzzy_check.conf.readonly").read_text()
    assert "enabled = true;" in ro and "read_only = yes;" in ro
    assert re.search(r"^enabled = false;", (d / "neural.conf").read_text(), re.M)


def test_unbound_conf():
    text = (DEPLOY / "unbound.conf").read_text()
    for needle in ("num-threads: 2", "msg-cache-size: 32m", "rrset-cache-size: 64m",
                   "serve-expired: yes", "prefetch: yes", "cache-min-ttl: 60",
                   "log-servfail: yes", "verbosity: 1",
                   'logfile: ""'):
        assert needle in text, needle
    # RBL answers are 127.0.0.x: loopback must never be a private-address.
    assert not re.search(r"private-address: 127\.", text)
    assert "192.168.1.15" not in re.sub(r"#.*", "", text)
    # No LAN resolver in the repository: it comes from the local site config
    # (dns_forwarders) or the app dir's unbound-forward-records.conf.
    assert not re.search(r"^\s*forward-(zone|addr):", text, re.M)


def test_upstream_files_neutralised():
    assert not (ROOT / "unraid").exists()
    assert not (ROOT / "docker-compose.yml").exists()
    assert not (ROOT / "ca_profile.xml").exists()
    up = ROOT / "upstream-unused"
    for name in ("unraid", "docker-compose.yml", "ca_profile.xml", "README.md"):
        assert (up / name).exists(), name
    assert "DO NOT USE" in (up / "README.md").read_text()


# ---------------------------------------------------------------- lib.sh behaviour

@pytest.fixture
def host(tmp_path):
    """Temp app dir + fake docker/curl/notify on PATH."""
    app = tmp_path / "app"
    for sub in ("operations", "state", "config", "rspamd/local.d", "redis", "redis-config"):
        (app / sub).mkdir(parents=True)
    bindir = tmp_path / "bin"
    install_fake_bin(bindir)
    env = base_env(tmp_path, bindir)
    env.update(SPAMFILTER_APP=str(app), SF_POLL="0", SF_GATE_TIMEOUT="3", SF_GATE_MIN_UPTIME="0",
               SPAMFILTER_URL="http://fake")
    write_state(Path(env["FAKE_DOCKER_STATE"]), {})

    class Host:
        pass
    h = Host()
    h.tmp, h.app, h.bin, h.env = tmp_path, app, bindir, env
    h.state_file = Path(env["FAKE_DOCKER_STATE"])
    h.calls = lambda: Path(env["FAKE_DOCKER_CALLS"]).read_text() if Path(env["FAKE_DOCKER_CALLS"]).exists() else ""
    return h


def lib_bash(host, body: str, *, check=True, **extra_env):
    """Run *body* in bash after sourcing lib.sh. chown is stubbed (tests do
    not run as root); everything else is real."""
    env = dict(host.env, **extra_env)
    script = f'set -euo pipefail\n. "{DEPLOY}/lib.sh"\nchown() {{ :; }}\n{body}\n'
    proc = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=60)
    if check and proc.returncode != 0:
        raise AssertionError(f"rc={proc.returncode}\nstdout:{proc.stdout}\nstderr:{proc.stderr}")
    return proc


def run_args(host, name: str) -> list[str]:
    out = lib_bash(host, f'sf_run_args {name}; printf "%s\\n" "${{SF_OPTS[@]}}" "--" "${{SF_IMAGE_CMD[@]}}"').stdout
    return out.splitlines()


def test_run_args_common_flags(host):
    for name in ("spamfilter", "spamfilter-redis", "spamfilter-unbound", "spamfilter-rspamd"):
        a = run_args(host, name)
        joined = " ".join(a)
        assert "--init" in a and "--stop-timeout 30" in joined, name
        assert "-e TZ=Europe/Copenhagen" in joined, name
        assert "--log-opt max-size=10m" in joined, name
        assert "--cap-drop ALL" in joined and "no-new-privileges" in joined, name
        assert "--restart unless-stopped" in joined and "--network spamnet" in joined, name


def test_run_args_filter(host):
    a = run_args(host, "spamfilter")
    joined = " ".join(a)
    assert "--user 10099:10099" in joined
    assert "-p 192.168.1.10:18080:8080" in joined
    assert "net.unraid.docker.webui=http://192.168.1.10:18080/" in a
    assert "net.unraid.docker.icon=http://192.168.1.10:18080/static/logo.png" in a
    assert f"{host.app}/state:/state" in a and f"{host.app}/config:/config" in a
    assert "AUTOMATIC_RETENTION_ENABLED=0" in a
    assert a[a.index("--") + 1] == "imap-spamfilter-unraid:2.16.0-filter"


def test_run_args_infra(host):
    unbound = " ".join(run_args(host, "spamfilter-unbound"))
    assert f"{host.app}/unbound.conf:/opt/unbound/etc/unbound/unbound.conf:ro" in unbound
    assert "--pids-limit 512" in unbound and "--cap-add NET_BIND_SERVICE" in unbound
    rspamd = run_args(host, "spamfilter-rspamd")
    assert f"{host.app}/rspamd/local.d:/etc/rspamd/local.d:ro" in rspamd
    redis = run_args(host, "spamfilter-redis")
    assert redis[redis.index("--") + 1:] == [versions()["REDIS_IMAGE"], "redis-server",
                                              "/usr/local/etc/redis/redis.conf"]


def _container(image, running=True, health="healthy", **kw):
    return {"image": image, "running": running, "health": health, **kw}


def test_recreate_success_keeps_one_rollback(host):
    img = versions()["REDIS_IMAGE"]
    write_state(host.state_file, {
        "spamfilter-redis": _container("redis:old"),
        "spamfilter-redis-rollback": _container("redis:older", running=False),
        "spamfilter-redis-rollback-20261001T000000Z": _container("redis:ancient", running=False),
    }, images=[img])
    lib_bash(host, "sf_install_traps; sf_recreate spamfilter-redis sf_gate_health")
    c = read_state(host.state_file)["containers"]
    assert set(c) == {"spamfilter-redis", "spamfilter-redis-rollback"}
    assert c["spamfilter-redis"]["image"] == img and c["spamfilter-redis"]["running"]
    assert "spamfilter.deploy-hash" in c["spamfilter-redis"]["labels"]
    assert c["spamfilter-redis-rollback"]["image"] == "redis:old"
    assert not c["spamfilter-redis-rollback"]["running"]


def test_recreate_gate_failure_rolls_back_container_and_config(host):
    img = versions()["RSPAMD_IMAGE"]
    local_d = host.app / "rspamd" / "local.d"
    (local_d / "actions.conf").write_text("old actions\n")
    for f in ("redis.conf", "worker-controller.inc"):
        (local_d / f).write_text("secret stand-in\n")
    write_state(host.state_file, {
        "spamfilter-rspamd": _container("rspamd:old"),
        "spamfilter-rspamd-rollback": _container("rspamd:older", running=False),
    }, images=[img])
    proc = lib_bash(host, "sf_rspamd_preflight() { :; }\nsf_install_traps\n"
                          "sf_install_rspamd_config\nsf_recreate spamfilter-rspamd sf_gate_health",
                    check=False, FAKE_NEW_HEALTH="unhealthy")
    assert proc.returncode != 0
    assert "rolled back" in proc.stderr
    c = read_state(host.state_file)["containers"]
    assert set(c) == {"spamfilter-rspamd", "spamfilter-rspamd-rollback"}
    assert c["spamfilter-rspamd"]["image"] == "rspamd:old" and c["spamfilter-rspamd"]["running"]
    assert c["spamfilter-rspamd-rollback"]["image"] == "rspamd:older"
    # Replaced config restored, files new in this run removed, secrets untouched.
    assert (local_d / "actions.conf").read_text() == "old actions\n"
    assert not (local_d / "greylist.conf").exists()
    assert not (local_d / "multimap.conf").exists()
    assert not [p for p in (local_d / "maps.d").iterdir()]
    assert (local_d / "redis.conf").read_text() == "secret stand-in\n"
    assert list((host.app / "operations").glob("failed-spamfilter-rspamd-*.log"))


def test_install_rspamd_config_respects_fuzzy_flag(host):
    local_d = host.app / "rspamd" / "local.d"
    for f in ("redis.conf", "worker-controller.inc"):
        (local_d / f).write_text("secret stand-in\n")
    lib_bash(host, "sf_rspamd_preflight() { :; }\nENABLE_FUZZY=0\nsf_install_rspamd_config")
    assert "enabled = false;" in (local_d / "fuzzy_check.conf").read_text()
    lib_bash(host, "sf_rspamd_preflight() { :; }\nENABLE_FUZZY=1\nsf_install_rspamd_config")
    assert "read_only = yes;" in (local_d / "fuzzy_check.conf").read_text()
    for f in ("actions.conf", "greylist.conf", "options.inc", "classifier-bayes.conf"):
        assert (local_d / f).read_bytes() == (ROOT / "rspamd" / "local.d" / f).read_bytes()
    assert (local_d / "redis.conf").read_text() == "secret stand-in\n"


MAPS_SRC = ROOT / "rspamd" / "local.d" / "maps.d"


def test_install_rspamd_config_installs_new_confs_and_maps(host):
    """2.2 B0: multimap/composites/phishing + every maps.d file reach the host."""
    local_d = host.app / "rspamd" / "local.d"
    for f in ("redis.conf", "worker-controller.inc"):
        (local_d / f).write_text("secret stand-in\n")
    lib_bash(host, "sf_rspamd_preflight() { :; }\nsf_install_rspamd_config")
    for f in ("groups.conf", "multimap.conf", "composites.conf", "phishing.conf"):
        assert (local_d / f).read_bytes() == (ROOT / "rspamd" / "local.d" / f).read_bytes(), f
    src = sorted(MAPS_SRC.iterdir())
    assert {p.name for p in src} >= {"surbl-whitelist.inc.local", "th_brand_names.re",
                                     "th_brand_domains.map", "phishing_feed_exclusion.inc"}
    for p in src:
        dest = local_d / "maps.d" / p.name
        assert dest.read_bytes() == p.read_bytes(), p.name
        assert dest.stat().st_mode & 0o777 == 0o640, p.name
    assert (local_d / "maps.d").stat().st_mode & 0o777 == 0o750
    assert (local_d / "redis.conf").read_text() == "secret stand-in\n"
    # Second run: nothing to do, a map changed by hand is put back.
    (local_d / "maps.d" / "th_brand_domains.map").write_text("edited\n")
    out = lib_bash(host, "sf_rspamd_preflight() { :; }\nsf_install_rspamd_config").stdout
    installs = [line for line in out.splitlines() if "  install    " in line]
    assert installs == [line for line in installs if line.endswith("maps.d/th_brand_domains.map")]
    assert len(installs) == 1
    assert (local_d / "maps.d" / "th_brand_domains.map").read_bytes() == \
        (MAPS_SRC / "th_brand_domains.map").read_bytes()


def test_install_records_new_files_for_a_manual_rollback(host):
    """2.2 review: config-backups/<stamp>/NEW_FILES lists what a run created."""
    local_d = host.app / "rspamd" / "local.d"
    for f in ("redis.conf", "worker-controller.inc"):
        (local_d / f).write_text("secret stand-in\n")
    (local_d / "groups.conf").write_text("2.1 groups\n")      # replaced, not new
    lib_bash(host, "sf_rspamd_preflight() { :; }\nsf_install_rspamd_config")
    stamps = list((host.app / "operations" / "config-backups").iterdir())
    assert len(stamps) == 1
    new = (stamps[0] / "NEW_FILES").read_text().split()
    for f in ("multimap.conf", "composites.conf", "phishing.conf"):
        assert f"rspamd/local.d/{f}" in new, f
    assert "rspamd/local.d/maps.d/th_brand_names.re" in new
    assert "rspamd/local.d/groups.conf" not in new
    assert (stamps[0] / "rspamd" / "local.d" / "groups.conf").read_text() == "2.1 groups\n"
    readme = (ROOT / "deploy" / "README.md").read_text()
    assert "NEW_FILES" in readme and "rm -rf $APP/rspamd/local.d/maps.d" in readme


def test_rspamd_digest_covers_maps(host):
    local_d = host.app / "rspamd" / "local.d"
    (local_d / "actions.conf").write_text("a\n")

    def digest() -> str:
        return lib_bash(host, "sf_rspamd_digest").stdout.strip()

    d0 = digest()
    (local_d / "maps.d").mkdir()
    assert digest() == d0  # an empty/missing maps.d keeps the 2.1 digest
    (local_d / "maps.d" / "th_brand_domains.map").write_text("postnord.com\n")
    d1 = digest()
    assert d1 != d0
    (local_d / "maps.d" / "th_brand_domains.map").write_text("postnord.com\npostnord.dk\n")
    d2 = digest()
    assert d2 not in (d0, d1)
    (local_d / "maps.d" / "th_brand_domains.map").rename(local_d / "maps.d" / "other.map")
    assert digest() not in (d0, d1, d2)  # the name counts, not only the content


def test_rspamd_preflight_stages_maps_and_cleans_up(host):
    local_d = host.app / "rspamd" / "local.d"
    (local_d / "redis.conf").write_text("secret stand-in\n")
    listing = host.tmp / "stage.txt"
    fake = ('docker() { local a v=""; for a in "$@"; do case "$a" in *:/etc/rspamd/local.d:ro) '
            'v="${a%%:*}";; esac; done; (cd "$v" && find . -type f | sort) > "' + str(listing) + '"; '
            'echo "syntax OK"; }\n')
    lib_bash(host, fake + "sf_rspamd_preflight")
    staged = listing.read_text().split()
    assert "./redis.conf" in staged and "./multimap.conf" in staged and "./phishing.conf" in staged
    for p in MAPS_SRC.iterdir():
        assert "./maps.d/" + p.name in staged, p.name
    assert not list((host.app / "operations").glob(".rspamd-stage-*"))
    # Nothing is installed by the preflight itself.
    assert not (local_d / "maps.d").exists()


def test_rspamd_preflight_failure_installs_nothing(host):
    local_d = host.app / "rspamd" / "local.d"
    for f in ("redis.conf", "worker-controller.inc"):
        (local_d / f).write_text("secret stand-in\n")
    proc = lib_bash(host, 'docker() { echo "maps.d/th_lure_subjects.re: bad regexp"; echo "syntax BAD"; '
                          'return 1; }\nsf_install_rspamd_config', check=False)
    assert proc.returncode != 0
    assert "configtest failed" in proc.stderr
    assert not (local_d / "maps.d").exists()
    assert not (local_d / "multimap.conf").exists()


def test_filter_gate_and_rollback_restores_previous_user(host):
    img = versions()["FILTER_IMAGE"]
    write_state(host.state_file, {"spamfilter": _container("imap-spamfilter-unraid:1.0.0-local", user="99:100")},
                images=[img])
    # Gate fails: no heartbeat, curl down -> previous container restored and
    # state ownership handed back to its user (stubbed owner function logs it).
    proc = lib_bash(host, 'sf_set_state_owner() { echo "OWNER $1"; }\nsf_install_traps\n'
                          f'sf_recreate spamfilter sf_gate_filter "{img}"', check=False, SF_GATE_TIMEOUT="1")
    assert proc.returncode != 0
    assert "OWNER 10099:10099" in proc.stdout and "OWNER 99:100" in proc.stdout
    c = read_state(host.state_file)["containers"]
    assert c["spamfilter"]["image"] == "imap-spamfilter-unraid:1.0.0-local" and c["spamfilter"]["running"]
    assert "spamfilter-rollback" not in c


def test_filter_gate_passes(host):
    img = versions()["FILTER_IMAGE"]
    write_state(host.state_file, {"spamfilter": _container("old", user="99:100")}, images=[img])
    # Heartbeat written "by the new container" in the future of its start.
    hb = host.app / "state" / "heartbeat"
    body = ('sf_set_state_owner() { :; }\nsf_install_traps\n'
            f'( sleep 1; echo "$(( $(date +%s) + 5 )) boot" > "{hb}" ) &\n'
            f'sf_recreate spamfilter sf_gate_filter "{img}"')
    proc = lib_bash(host, body, FAKE_CURL_BODY='{"ok":true}',
                    FAKE_DOCKER_LOGS=json.dumps({"spamfilter": "main: loaded 4 account(s): a, b"}),
                    SF_GATE_TIMEOUT="20")
    assert "accounts loaded" in proc.stdout
    c = read_state(host.state_file)["containers"]
    assert c["spamfilter"]["image"] == img
    assert c["spamfilter-rollback"]["image"] == "old"


def test_migrate_dry_run_changes_nothing(host):
    us = host.tmp / "user.scripts"
    (us / "scripts").mkdir(parents=True)
    write_state(host.state_file, {
        "spamfilter": _container("imap-spamfilter-unraid:1.0.0-local", user="99:100"),
        "spamfilter-redis": _container("r"), "spamfilter-rspamd": _container("s"),
        "spamfilter-unbound": _container("u"),
    })
    for f in ("redis.conf", "worker-controller.inc"):
        (host.app / "rspamd" / "local.d" / f).write_text("secret stand-in\n")
    before = host.state_file.read_text()
    env = dict(host.env, USER_SCRIPTS_DIR=str(us), FAKE_ALL_IMAGES="1")
    proc = subprocess.run([str(DEPLOY / "migrate-2.0.sh"), "--dry-run"], env=env,
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[dry-run] docker run -d" in proc.stdout
    assert host.state_file.read_text() == before
    mutating = [line for line in host.calls().splitlines()
                if line.split()[0] in ("run", "stop", "rename", "rm", "build", "update", "restart")]
    assert mutating == []
    assert not any(us.rglob("script"))
    assert not (host.app / "rspamd" / "local.d" / "actions.conf").exists()
    assert not (host.app / "rspamd" / "local.d" / "maps.d").exists()
    assert not (host.app / "unbound.conf").exists()


# ---------------------------------------------------------------- User Scripts

REAL_CRON = """# Generated cron schedule for user.scripts
*/5 * * * * /usr/local/emhttp/plugins/user.scripts/startCustom.php /boot/config/plugins/user.scripts/scripts/Rclone keep alive/script > /dev/null 2>&1

0 3 * * * /usr/local/emhttp/plugins/user.scripts/startCustom.php {us}/scripts/Spamfilter-backup/script > /dev/null 2>&1
"""


def test_install_user_scripts_inline_and_idempotent(host):
    us = host.tmp / "user.scripts"
    (us / "scripts" / "Spamfilter-backup").mkdir(parents=True)
    (us / "scripts" / "Spamfilter-backup" / "script").write_text(
        "#!/bin/bash\nexec /mnt/user/appdata/spamfilter/source/deploy/backup-and-verify.sh\n")
    (us / "customSchedule.cron").write_text(REAL_CRON.format(us=us))
    sched = {f"{us}/scripts/Other/script": {"script": f"{us}/scripts/Other/script", "frequency": "disabled",
                                            "id": "scheduleOther", "custom": ""},
             f"{us}/scripts/Spamfilter-backup/script": {"script": f"{us}/scripts/Spamfilter-backup/script",
                                                        "frequency": "custom", "id": "scheduleSpamfilterbackup",
                                                        "custom": "0 3 * * *"}}
    (us / "schedule.json").write_text(json.dumps(sched, indent=2) + "\n")
    update_cron = host.tmp / "update_cron"
    update_cron.write_text(f"#!/bin/bash\necho ran >> {host.tmp}/update_cron.log\n")
    update_cron.chmod(0o755)
    env = dict(host.env, USER_SCRIPTS_DIR=str(us), UPDATE_CRON_BIN=str(update_cron))
    # --dry-run through the real entry point (no root needed) changes nothing.
    snap0 = {p: p.read_bytes() for p in us.rglob("*") if p.is_file()}
    proc = subprocess.run([str(DEPLOY / "install-user-scripts.sh"), "--dry-run"], env=env,
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[dry-run] write" in proc.stdout
    assert {p: p.read_bytes() for p in us.rglob("*") if p.is_file()} == snap0
    # Real install (the root check lives in the wrapper script).
    lib_bash(host, "sf_install_user_scripts", USER_SCRIPTS_DIR=str(us), UPDATE_CRON_BIN=str(update_cron))

    backup = (us / "scripts" / "Spamfilter-backup" / "script").read_text()
    assert backup.startswith("#!/bin/bash\n") and "exec /mnt" not in backup
    assert "STEP=\"sqlite backup\"" in backup  # full body inline
    assert f'SPAMFILTER_APP="${{SPAMFILTER_APP:-{host.app}}}"' in backup
    monitor = (us / "scripts" / "Spamfilter-monitor" / "script").read_text()
    assert "host-status.json" in monitor
    assert (us / "scripts" / "Spamfilter-monitor" / "name").read_text() == "Spamfilter host monitor\n"
    # 2.10: the update runner, every minute, also inline (never exec from appdata)
    upd = (us / "scripts" / "Spamfilter-update" / "script").read_text()
    assert "request.json" in upd and "update.sh\" --build" in upd and "exec /mnt" not in upd

    cron = (us / "customSchedule.cron").read_text().splitlines()
    mon_line = (f"*/5 * * * * /usr/local/emhttp/plugins/user.scripts/startCustom.php "
                f"{us}/scripts/Spamfilter-monitor/script > /dev/null 2>&1")
    assert cron.count(mon_line) == 1
    assert cron.count(f"* * * * * /usr/local/emhttp/plugins/user.scripts/startCustom.php "
                      f"{us}/scripts/Spamfilter-update/script > /dev/null 2>&1") == 1
    assert sum("Spamfilter-backup/script" in line for line in cron) == 1
    assert cron[:4] == REAL_CRON.format(us=us).splitlines()[:4]  # other lines untouched, in place

    data = json.loads((us / "schedule.json").read_text())
    key = f"{us}/scripts/Spamfilter-monitor/script"
    assert data[key] == {"script": key, "frequency": "custom", "id": "scheduleSpamfiltermonitor",
                         "custom": "*/5 * * * *"}
    assert list(data)[0].endswith("Other/script")
    assert (host.tmp / "update_cron.log").read_text() == "ran\n"
    backups = list((host.app / "operations").glob("user-scripts-backup-*/customSchedule.cron"))
    assert len(backups) == 1

    # Second run: nothing changes, cron not re-activated.
    snap = {p: p.read_bytes() for p in us.rglob("*") if p.is_file()}
    lib_bash(host, "sf_install_user_scripts", USER_SCRIPTS_DIR=str(us), UPDATE_CRON_BIN=str(update_cron))
    assert {p: p.read_bytes() for p in us.rglob("*") if p.is_file()} == snap
    assert (host.tmp / "update_cron.log").read_text() == "ran\n"


def test_install_user_scripts_never_writes_a_broken_or_empty_schedule(host):
    """2.11.2 review: a failing jq must stop the install - never an empty
    schedule.json (it holds the owner's own User Scripts too)."""
    us = host.tmp / "user.scripts"
    (us / "scripts").mkdir(parents=True)
    (us / "customSchedule.cron").write_text(REAL_CRON.format(us=us))
    (us / "schedule.json").write_text("{not json\n")
    proc = lib_bash(host, "sf_install_user_scripts", check=False, USER_SCRIPTS_DIR=str(us),
                    UPDATE_CRON_BIN=str(host.tmp / "none"))
    assert proc.returncode != 0 and "could not update" in proc.stderr
    assert (us / "schedule.json").read_text() == "{not json\n"
    assert "Spamfilter-offsite" not in (us / "customSchedule.cron").read_text()  # stopped at the first script


# ---------------------------------------------------------------- host-monitor

DRILL_OK = """;; ->>HEADER<<- opcode: QUERY, rcode: NOERROR, id: 4711
;; flags: qr rd ra ; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0
;; QUESTION SECTION:
;; 2.0.0.127.zen.spamhaus.org.\tIN\tA

;; ANSWER SECTION:
2.0.0.127.zen.spamhaus.org.\t60\tIN\tA\t127.0.0.2
2.0.0.127.zen.spamhaus.org.\t60\tIN\tA\t127.0.0.10

;; Query time: 23 msec
"""
RSPAMD_LOG = ("x rspamd_task_write_log: id: <a>, (default: F (no action): [1/15] [SEM_URIBL_UNKNOWN_FAIL(0.00){x.dk:server fail;}])\n"
              "x rspamd_task_write_log: id: <b>, (default: F (no action): [1/15] [ARC_NA(0.00){}])\n"
              "x make_dns_request_task_common: stop resolving on reaching 64 requests\n")


def _monitor(host, *args, **extra):
    env = dict(host.env, SF_DOCKER_ROOT=str(host.tmp), **extra)
    proc = subprocess.run([str(DEPLOY / "host-monitor.sh"), *args], env=env,
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc


def _all_up():
    return {n: _container(n + ":img") for n in ("spamfilter", "spamfilter-rspamd",
                                                "spamfilter-redis", "spamfilter-unbound")}


def test_monitor_healthy_status(host):
    write_state(host.state_file, _all_up())
    (host.app / "state" / "heartbeat").write_text(f"{int(time.time()) - 10} boot\n")
    (host.app / "state" / "backup-status.json").write_text(json.dumps(
        {"ok": True, "ts": int(time.time()) - 3600, "archive": "/x.tar.gz", "size": 10, "error": None}))
    _monitor(host, FAKE_CURL_BODY=json.dumps({"ok": True, "version": "2.0.0",
                                              "accounts": {"bynet": "idle", "molt": "idle"}}),
             FAKE_DOCKER_EXEC=json.dumps({"spamfilter-unbound drill": DRILL_OK, "spamfilter-rspamd rspamc": "ok"}),
             FAKE_DOCKER_LOGS=json.dumps({"spamfilter-rspamd": RSPAMD_LOG}))
    out = host.app / "state" / "host-status.json"
    st = json.loads(out.read_text())
    assert oct(out.stat().st_mode & 0o777) == "0o644"
    assert st["containers"]["spamfilter"]["running"] is True
    assert st["containers"]["spamfilter"]["health"] == "healthy"
    assert st["dns"]["ok"] is True and st["dns"]["answers"] == ["127.0.0.2", "127.0.0.10"]
    assert st["dns"]["ms"] == 23 and st["dns"]["rcode"] == "NOERROR"
    assert st["rbl"]["scans"] == 2 and st["rbl"]["scans_with_dns_fail"] == 1
    assert st["rbl"]["fail_rate"] == 0.5 and st["rbl"]["dns_limit_hits"] == 1
    assert st["rspamd"]["ok"] is True
    assert st["accounts"] == {"bynet": "idle", "molt": "idle"} and st["accounts_source"] == "api"
    assert 5 <= st["heartbeat"]["age_s"] <= 60
    assert st["backup"]["ok"] is True and st["backup"]["age_s"] >= 3600
    assert st["disk"]["docker_img"]["pct"] is not None
    assert isinstance(st["ts"], int)
    # Only the RBL rate condition (>= 50 % with >= 5 scans) could fire; 2 scans -> none.
    assert st["alerts"] == [] and st["ok"] is True
    assert not Path(host.env["FAKE_NOTIFY_LOG"]).exists()


def test_monitor_filter_down_dedup_and_recovery(host):
    containers = _all_up()
    containers["spamfilter"]["running"] = False
    write_state(host.state_file, containers)
    exec_ok = json.dumps({"spamfilter-unbound drill": DRILL_OK, "spamfilter-rspamd rspamc": "ok"})
    (host.app / "state" / "backup-status.json").write_text(json.dumps(
        {"ok": True, "ts": int(time.time()), "archive": "/x", "size": 1, "error": None}))

    _monitor(host, FAKE_DOCKER_EXEC=exec_ok)  # curl unset -> /api/health down
    st = json.loads((host.app / "state" / "host-status.json").read_text())
    keys = {a["key"] for a in st["alerts"]}
    assert "container:spamfilter" in keys
    assert st["accounts_source"] == "none" and st["ok"] is False
    notify_log = Path(host.env["FAKE_NOTIFY_LOG"])
    assert not notify_log.exists()  # under the 5 min delay

    # Pretend the problem started 10 minutes ago -> exactly one alert.
    ms = host.app / "operations" / "monitor-state.json"
    data = json.loads(ms.read_text())
    data["conditions"]["container:spamfilter"]["since"] -= 600
    ms.write_text(json.dumps(data))
    _monitor(host, FAKE_DOCKER_EXEC=exec_ok)
    _monitor(host, FAKE_DOCKER_EXEC=exec_ok)
    lines = notify_log.read_text().splitlines()
    assert len(lines) == 1
    assert "-e\tSpamfilter" in lines[0] and "-i\talert" in lines[0]
    assert "spamfilter kører ikke" in lines[0]

    # Recovery -> one "OK igen" notice, condition gone.
    write_state(host.state_file, _all_up())
    (host.app / "state" / "heartbeat").write_text(f"{int(time.time())} boot\n")
    _monitor(host, FAKE_DOCKER_EXEC=exec_ok,
             FAKE_CURL_BODY=json.dumps({"ok": True, "version": "2.0.0", "accounts": {"a": "idle"}}))
    lines = notify_log.read_text().splitlines()
    assert len(lines) == 2 and "OK igen" in lines[1] and "-i\tnormal" in lines[1]
    assert json.loads(ms.read_text())["conditions"] == {}


def test_monitor_dry_run_writes_nothing(host):
    write_state(host.state_file, _all_up())
    proc = _monitor(host, "--dry-run")
    assert json.loads(proc.stdout.split("\n[dry-run]")[0])["version"] == 1
    assert not (host.app / "state" / "host-status.json").exists()
    assert not (host.app / "operations" / "monitor-state.json").exists()


def test_monitor_spamhaus_blocked_and_auth_failed(host):
    write_state(host.state_file, _all_up())
    blocked = DRILL_OK.replace("127.0.0.2", "127.255.255.254").replace("\t127.0.0.10", "\t127.255.255.254")
    (host.app / "state" / "heartbeat").write_text(f"{int(time.time())} boot\n")
    _monitor(host, FAKE_DOCKER_EXEC=json.dumps({"spamfilter-unbound drill": blocked}),
             FAKE_CURL_BODY=json.dumps({"ok": True, "version": "2.0.0", "accounts": {"bynet": "auth_failed"}}))
    st = json.loads((host.app / "state" / "host-status.json").read_text())
    assert st["dns"]["verdict"] == "blocked" and st["dns"]["ok"] is False
    keys = {a["key"]: a for a in st["alerts"]}
    assert "dns" in keys and "account:bynet" in keys
    assert "login afvist" in keys["account:bynet"]["text"]


# ---------------------------------------------------------------- backup

def test_backup_dry_run(host):
    proc = subprocess.run([str(DEPLOY / "backup-and-verify.sh"), "--dry-run"], env=host.env,
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0 and "[dry-run]" in proc.stdout
    assert not (host.app / "state" / "backup-status.json").exists()
    assert not (host.app / "operations" / "backups").exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="relies on the non-root preflight failure")
def test_backup_failure_writes_status_and_notifies(host):
    proc = subprocess.run([str(DEPLOY / "backup-and-verify.sh")], env=host.env,
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode != 0
    st = json.loads((host.app / "state" / "backup-status.json").read_text())
    assert st["ok"] is False and st["archive"] is None and st["size"] is None
    assert "preflight" in st["error"] and isinstance(st["ts"], int)
    note = Path(host.env["FAKE_NOTIFY_LOG"]).read_text()
    assert "-e\tSpamfilter" in note and "-i\talert" in note and "backup fejlede" in note


# ---------------------------------------------------------------- review fixes

LIVE_LIKE_ACCOUNTS = """defaults:
  mode: shadow
  threshold: 8.0
accounts:
  - name: bynet
    enabled: true
    user: ole@bynet.example
    imap_host: imap.gigahost.dk
    password_file: /state/imap-secrets/bynet
  - name: "molt"
    user: ole@molt.example
    junk: Spamfilter
    password_file: /state/imap-secrets/molt
  - user: sofie@molt.example
    name: molt-sofie
    bayes_user: per-account   # an account-level key must not count as the default
"""


def test_accounts_config_preflight_warns_about_missing_owner_decisions(host):
    cfg = host.app / "config" / "accounts.yml"
    cfg.write_text(LIVE_LIKE_ACCOUNTS)
    proc = lib_bash(host, "sf_check_accounts_config")
    assert "defaults.bayes_user is not set" in proc.stderr
    assert "no explicit 'junk:' for: bynet molt-sofie -" in proc.stderr
    cfg.write_text((DEPLOY / "accounts.yml").read_text())   # the seed follows SPEC 9
    proc = lib_bash(host, "sf_check_accounts_config")
    assert "WARNING" not in proc.stderr
    cfg.unlink()
    assert "cannot read" in lib_bash(host, "sf_check_accounts_config").stderr


def test_infra_gate_failure_restarts_rspamd(host):
    img = versions()["UNBOUND_IMAGE"]
    write_state(host.state_file, {
        "spamfilter-unbound": _container("unbound:old"),
        "spamfilter-rspamd": _container("rspamd:cur"),
    }, images=[img])
    (host.app / "unbound.conf").write_text("old\n")
    proc = lib_bash(host, "sf_unbound_preflight() { :; }\nsf_install_traps\n"
                          "sf_install_unbound_config\nsf_recreate spamfilter-unbound sf_gate_health",
                    check=False, FAKE_NEW_HEALTH="unhealthy")
    assert proc.returncode != 0 and "rolled back" in proc.stderr
    assert "restarting spamfilter-rspamd" in proc.stderr
    assert any(line.split()[:2] == ["restart", "-t"] and "spamfilter-rspamd" in line
               for line in host.calls().splitlines())


# ---------------------------------------------------------------- host-monitor 2.1: digest + alerts

import calendar  # noqa: E402


def _utc(y, mo, d, h, mi=0):
    return calendar.timegm((y, mo, d, h, mi, 0))


DIGEST = {"day": "2026-10-24", "empty": False, "totals": {"moved": 5},
          "accounts": [{"account": "bynet", "name": "bynet", "mode": "move", "moved": 4, "released": 1,
                        "marked": 2, "spam_detected": 4, "scanned": 40},
                       {"account": "molt-inge", "name": "Inge", "mode": "move", "moved": 0,
                        "released": 0, "marked": 0, "spam_detected": 0, "scanned": 9},
                       {"account": "molt-sofie", "name": "molt-sofie", "mode": "shadow", "moved": 0,
                        "released": 0, "marked": 0, "spam_detected": 3, "scanned": 9}],
          "suggestions": [{"account": "bynet", "name": "bynet", "current": 10.0, "recommended": 12.0,
                           "change": "raise", "text": "Hæv grænsen fra 10 til 12: 1 mail ..."}]}


def _sfdb(digest=DIGEST, settings=None, status=None):
    return json.dumps({"status": status or {}, "settings": settings or {}, "digest": digest,
                       "digest_source": "services" if digest else None})


def _digest_run(host, now, *, sfdb=None, curl=None, **extra):
    write_state(host.state_file, _all_up())
    (host.app / "state" / "heartbeat").write_text(f"{now - 10} boot\n")
    (host.app / "state" / "backup-status.json").write_text(json.dumps(
        {"ok": True, "ts": now - 3600, "archive": "/x.tar.gz", "size": 10, "error": None}))
    env = dict(SF_NOW=str(now), SF_TZ="Europe/Copenhagen",
               FAKE_DOCKER_EXEC=json.dumps({"spamfilter-unbound drill": DRILL_OK,
                                            "spamfilter python": sfdb if sfdb is not None else _sfdb()}),
               FAKE_CURL_BODY=curl or json.dumps({"ok": True, "version": "2.2.0",
                                                  "accounts": {"bynet": "idle"}}))
    env.update(extra)
    return _monitor(host, **env)


def _notifications(host):
    log = Path(host.env["FAKE_NOTIFY_LOG"])
    return log.read_text().split("\n-e\t")[0:] if log.exists() else []


def _notify_lines(host):
    log = Path(host.env["FAKE_NOTIFY_LOG"])
    return log.read_text() if log.exists() else ""


def _exec_calls(host):
    """Trailing arguments (yesterday, due, monday) of each snippet call."""
    return [" " + part.splitlines()[0].strip() for part in host.calls().split("print(json.dumps(out))")[1:]]


def test_monitor_digest_once_after_seven_local_time_dst_safe(host):
    # 2026-10-25 is the end of DST: 06:30 UTC = 07:30 CET, 05:30 UTC = 06:30 CET.
    _digest_run(host, _utc(2026, 10, 25, 5, 30))
    assert "dagsoversigt" not in _notify_lines(host)
    assert _exec_calls(host)[-1].endswith(" 2026-10-24 0 0")  # not due: no digest asked for
    _digest_run(host, _utc(2026, 10, 25, 6, 5))
    text = _notify_lines(host)
    assert text.count("Spamfilter: dagsoversigt 24.10.2026") == 1
    assert _exec_calls(host)[-1].endswith(" 2026-10-24 1 0")
    assert "I går: 4 mails flyttet til Spamfilter, 1 frigivet, 2 markeret som spam." in text
    assert "Tjek Fanget spam: http://fake/spam" in text
    assert "bynet: 4 flyttet · 1 frigivet · 2 markeret som spam" in text
    assert "Inge: ingen spam" in text and "molt-sofie: 3 fanget (uden flytning)" in text
    assert "-i\tnormal" in text and "-m\tDagsoversigt for 24.10.2026" in text
    assert "Forslag til følsomhed" not in text  # Sunday
    ms = json.loads((host.app / "operations" / "monitor-state.json").read_text())
    assert ms["digest"]["last_day"] == "2026-10-25" and ms["digest"]["for_day"] == "2026-10-24"
    st = json.loads((host.app / "state" / "host-status.json").read_text())
    assert st["digest"]["enabled"] is True and st["digest"]["last_day"] == "2026-10-25"
    # Later runs the same day send nothing more.
    _digest_run(host, _utc(2026, 10, 25, 9, 0))
    _digest_run(host, _utc(2026, 10, 25, 22, 55))  # 23:55 local
    assert _notify_lines(host).count("dagsoversigt") == 1
    # Summer time: 05:05 UTC is already 07:05 CEST.
    _digest_run(host, _utc(2026, 7, 1, 4, 55))
    assert _notify_lines(host).count("dagsoversigt") == 1
    _digest_run(host, _utc(2026, 7, 1, 5, 5))
    assert _notify_lines(host).count("dagsoversigt") == 2


def test_monitor_digest_monday_suggestions_external_url_and_empty(host):
    monday = _utc(2026, 10, 26, 7, 0)  # Monday 08:00 CET
    _digest_run(host, monday, sfdb=_sfdb(settings={"external_url": "https://spam.example.dk/",
                                                   "digest_enabled": "1"}))
    text = _notify_lines(host)
    assert _exec_calls(host)[-1].endswith(" 2026-10-25 1 1")
    assert "Udefra: https://spam.example.dk/spam" in text
    assert "Forslag til følsomhed (seneste 14 dage):\nbynet: Hæv grænsen fra 10 til 12" in text
    empty = dict(DIGEST, accounts=[dict(DIGEST["accounts"][1])], suggestions=[])
    _digest_run(host, _utc(2026, 10, 27, 7, 0),
                sfdb=_sfdb(empty, settings={"external_url": "javascript:alert(1)"}))
    text = _notify_lines(host).split("dagsoversigt 26.10.2026")[1]
    assert "Ingen spam i går. Tjek Fanget spam: http://fake/spam" in text
    assert "Udefra" not in text and "javascript" not in text


def test_monitor_digest_disabled_or_unavailable(host):
    now = _utc(2026, 10, 25, 8, 0)
    _digest_run(host, now, sfdb=_sfdb(None, settings={"digest_enabled": "0"}))
    assert "dagsoversigt" not in _notify_lines(host)
    st = json.loads((host.app / "state" / "host-status.json").read_text())
    assert st["digest"]["enabled"] is False and st["digest"]["due"] is True
    ms = json.loads((host.app / "operations" / "monitor-state.json").read_text())
    assert ms["digest"] == {}
    # Filter not answering: nothing sent, retried on the next run.
    _digest_run(host, now + 300, sfdb="not json")
    assert "dagsoversigt" not in _notify_lines(host)
    _digest_run(host, now + 600)
    assert _notify_lines(host).count("dagsoversigt") == 1


def test_monitor_digest_dry_run_prints_but_keeps_state(host):
    write_state(host.state_file, _all_up())
    env = dict(SF_NOW=str(_utc(2026, 10, 25, 8, 0)),
               FAKE_DOCKER_EXEC=json.dumps({"spamfilter python": _sfdb()}))
    proc = _monitor(host, "--dry-run", **env)
    assert "[dry-run] notify -i normal: Spamfilter: dagsoversigt 24.10.2026" in proc.stdout
    assert not (host.app / "operations" / "monitor-state.json").exists()
    assert not Path(host.env["FAKE_NOTIFY_LOG"]).exists()


def test_monitor_engine_states_circuit_stale_limited(host):
    now = int(time.time())
    health = {"ok": True, "version": "2.2.0",
              "accounts": {"bynet": "paused_moves", "molt": "stale", "molt-inge": "limited",
                           "molt-sofie": "idle"},
              "details": {"bynet": {"circuit": "open", "stale": False},
                          "molt": {"stale": True, "circuit": "closed"},
                          "molt-inge": {"limited": True, "login_state": "limited", "circuit": "closed"},
                          "molt-sofie": {"circuit": "closed", "stale": False, "login_state": "ok"}}}
    _digest_run(host, now, curl=json.dumps(health), sfdb=_sfdb(None))
    st = json.loads((host.app / "state" / "host-status.json").read_text())
    keys = {a["key"]: a for a in st["alerts"]}
    assert set(keys) == {"circuit:bynet", "stale:molt", "limit:molt-inge"}
    assert st["account_details"]["bynet"]["circuit"] == "open"
    lines = _notify_lines(host).splitlines()
    # The circuit breaker is notified at once; stale/limit wait for their delay.
    assert len(lines) == 1 and "sikkerhedsbremsen" in lines[0] and "-i\talert" in lines[0]
    ms = host.app / "operations" / "monitor-state.json"
    data = json.loads(ms.read_text())
    data["conditions"]["stale:molt"]["since"] -= 601
    data["conditions"]["limit:molt-inge"]["since"] -= 1700  # not yet 30 min
    ms.write_text(json.dumps(data))
    _digest_run(host, now, curl=json.dumps(health), sfdb=_sfdb(None))
    lines = _notify_lines(host).splitlines()
    assert len(lines) == 2 and "molt: filteret har ikke tjekket postkassen" in lines[1]
    data = json.loads(ms.read_text())
    data["conditions"]["limit:molt-inge"]["since"] -= 200
    ms.write_text(json.dumps(data))
    _digest_run(host, now, curl=json.dumps(health), sfdb=_sfdb(None))
    lines = _notify_lines(host).splitlines()
    assert len(lines) == 3 and "begrænser" in lines[2] and "-i\twarning" in lines[2]
    # All clear -> one "OK igen" per notified problem.
    ok = {"ok": True, "version": "2.2.0", "accounts": {n: "idle" for n in health["accounts"]},
          "details": {n: {"circuit": "closed", "stale": False, "login_state": "ok"} for n in health["accounts"]}}
    _digest_run(host, now, curl=json.dumps(ok), sfdb=_sfdb(None))
    lines = _notify_lines(host).splitlines()
    assert len(lines) == 6 and all("OK igen" in x for x in lines[3:])


def test_monitor_paused_accounts_never_alert_on_stale_login_state(host):
    # The engine keeps login_state from before a pause (molt-sofie was paused
    # after failed logins): a paused/stopped account must not raise "login
    # afvist", "begrænser" or "hængt" - only a still-open circuit breaker,
    # which needs an admin either way.
    now = int(time.time())
    health = {"ok": True, "version": "2.2.0",
              "accounts": {"molt-sofie": "paused", "molt-inge": "stopped", "bynet": "paused"},
              "details": {"molt-sofie": {"login_state": "auth_failed", "stale": False, "circuit": "closed"},
                          "molt-inge": {"login_state": "limited", "limited": False, "stale": True,
                                         "circuit": "closed"},
                          "bynet": {"login_state": "ok", "circuit": "open"}}}
    status = {"molt-sofie": {"state": "paused", "login_state": "auth_failed", "updated_at": now - 9000},
              "molt-inge": {"state": "stopped", "login_state": "limited", "updated_at": now - 9000},
              "bynet": {"state": "paused", "updated_at": now - 9000, "circuit": "open"}}
    _digest_run(host, now, curl=json.dumps(health), sfdb=_sfdb(None, status=status))
    st = json.loads((host.app / "state" / "host-status.json").read_text())
    assert {a["key"] for a in st["alerts"]} == {"circuit:bynet"}
    # SQLite fallback (API down) behaves the same.
    _digest_run(host, now + 300, curl="not json", sfdb=_sfdb(None, status=status))
    st = json.loads((host.app / "state" / "host-status.json").read_text())
    assert st["accounts_source"] == "sqlite"
    assert {a["key"] for a in st["alerts"]} == {"circuit:bynet"}
    # Resumed but still failing: the auth alert comes back.
    health["accounts"]["molt-sofie"] = "auth_failed"
    _digest_run(host, now + 600, curl=json.dumps(health), sfdb=_sfdb(None))
    st = json.loads((host.app / "state" / "host-status.json").read_text())
    assert "account:molt-sofie" in {a["key"] for a in st["alerts"]}


def test_monitor_stale_is_confirmed_by_the_next_run(host):
    now = int(time.time())
    health = {"ok": True, "version": "2.2.0", "accounts": {"molt": "stale"},
              "details": {"molt": {"stale": True, "circuit": "closed"}}}
    _digest_run(host, now, curl=json.dumps(health), sfdb=_sfdb(None))
    assert "hængt" not in _notify_lines(host)
    _digest_run(host, now + 300, curl=json.dumps(health), sfdb=_sfdb(None))
    assert _notify_lines(host).count("hængt") == 1
    _digest_run(host, now + 600, curl=json.dumps(health), sfdb=_sfdb(None))
    assert _notify_lines(host).count("hængt") == 1  # de-duplicated


def test_monitor_plain_state_strings_and_sqlite_fallback(host):
    now = int(time.time())
    # Old /api/health shape (state strings only).
    _digest_run(host, now, sfdb=_sfdb(None), curl=json.dumps(
        {"ok": True, "version": "2.0.3", "accounts": {"bynet": "circuit_open", "molt": "unavailable"}}))
    keys = {a["key"] for a in json.loads((host.app / "state" / "host-status.json").read_text())["alerts"]}
    assert keys == {"circuit:bynet", "limit:molt"}
    # /api/health down: states, circuit table and a silent thread from SQLite.
    status = {"bynet": {"state": "idle", "alive_at": now - 3000, "last_loop_at": now - 3000,
                        "updated_at": now - 3000},
              "molt": {"state": "idle", "alive_at": now - 30, "circuit": "open"},
              "molt-inge": {"state": "connecting", "login_state": "auth_failed", "updated_at": now}}
    write_state(host.state_file, _all_up())
    (host.app / "state" / "heartbeat").write_text(f"{now - 10} boot\n")
    env = dict(SF_NOW=str(now), FAKE_DOCKER_EXEC=json.dumps(
        {"spamfilter-unbound drill": DRILL_OK, "spamfilter python": _sfdb(None, status=status)}))
    _monitor(host, **env)
    st = json.loads((host.app / "state" / "host-status.json").read_text())
    assert st["accounts_source"] == "sqlite"
    assert st["accounts"] == {"bynet": "idle", "molt": "idle", "molt-inge": "connecting"}
    keys = {a["key"] for a in st["alerts"]}
    assert {"stale:bynet", "circuit:molt", "account:molt-inge"} <= keys
    assert "circuit:bynet" not in keys


# ---------------------------------------------------------------- the in-container snippet, for real

def _snippet() -> str:
    text = (DEPLOY / "host-monitor.sh").read_text()
    m = re.search(r"<<'PYEOF' \|\| true\n(.*?)\nPYEOF\n", text, re.S)
    assert m, "snippet markers"
    return m.group(1)


def _snippet_db(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    cfg = tmp_path / "accounts.yml"
    cfg.write_text("defaults:\n  bayes_user: hjemmeserver\naccounts:\n"
                   "  - name: bynet\n    user: ole@example.dk\n    imap_host: imap.example.dk\n"
                   "    password_file: /run/none\n    mode: move\n    threshold: 10\n    junk: Spamfilter\n"
                   "  - name: molt\n    user: j@example.org\n    imap_host: mail.example.org\n"
                   "    password_file: /run/none\n    mode: shadow\n")
    env = dict(os.environ, STATE_DIR=str(state), CONFIG_PATH=str(cfg), SF_PY_PATH=str(ROOT / "filter"),
               PYTHONPATH=str(ROOT / "filter"))
    subprocess.run([sys.executable, "-c", "import filter; filter.init_db()"], env=env, check=True,
                   cwd=tmp_path, timeout=60)
    import sqlite3
    db = sqlite3.connect(state / "spamfilter.db")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS settings_kv (key TEXT PRIMARY KEY, value TEXT);
        INSERT INTO settings_kv VALUES ('external_url', 'https://x.example');
        INSERT INTO stats_daily(account, day, metric, n) VALUES
            ('bynet', '2026-10-24', 'moved', 3), ('bynet', '2026-10-24', 'user_junked', 1),
            ('molt', '2026-10-24', 'spam_detected', 2);
        INSERT INTO account_status(account, updated_at, state, last_loop_at) VALUES ('bynet', 1, 'idle', 1);
    """)
    db.commit()
    db.close()
    return env, state / "spamfilter.db"


def test_monitor_snippet_reads_db_read_only_via_services(tmp_path):
    env, dbfile = _snippet_db(tmp_path)
    before = dbfile.read_bytes()
    out = subprocess.run([sys.executable, "-c", _snippet(), "2026-10-24", "1", "1"], env=env,
                         capture_output=True, text=True, timeout=60, cwd=tmp_path)
    assert out.returncode == 0, out.stderr
    data = json.loads(out.stdout)
    assert data["digest_source"] == "services"
    assert data["settings"] == {"external_url": "https://x.example"}
    assert data["status"]["bynet"]["state"] == "idle"
    acc = {a["account"]: a for a in data["digest"]["accounts"]}
    assert (acc["bynet"]["moved"], acc["bynet"]["marked"]) == (3, 1)
    assert acc["molt"]["spam_detected"] == 2
    assert [s["account"] for s in data["digest"]["suggestions"]] == ["bynet"]
    assert dbfile.read_bytes() == before
    # Not due -> no digest computed.
    out = subprocess.run([sys.executable, "-c", _snippet(), "2026-10-24", "0", "0"], env=env,
                         capture_output=True, text=True, timeout=60, cwd=tmp_path)
    assert json.loads(out.stdout)["digest"] is None


def test_monitor_snippet_falls_back_to_sql_and_honours_disabled(tmp_path):
    env, dbfile = _snippet_db(tmp_path)
    env = dict(env, SF_PY_PATH=str(tmp_path / "nowhere"))
    env.pop("PYTHONPATH")
    out = subprocess.run([sys.executable, "-c", _snippet(), "2026-10-24", "1", "0"], env=env,
                         capture_output=True, text=True, timeout=60, cwd=tmp_path)
    data = json.loads(out.stdout)
    assert data["digest_source"] == "sqlite"
    acc = {a["account"]: a for a in data["digest"]["accounts"]}
    assert acc["bynet"]["moved"] == 3 and acc["bynet"]["marked"] == 1
    import sqlite3
    db = sqlite3.connect(dbfile)
    db.execute("INSERT INTO settings_kv VALUES ('digest_enabled', 'off')")
    db.commit()
    db.close()
    out = subprocess.run([sys.executable, "-c", _snippet(), "2026-10-24", "1", "0"], env=env,
                         capture_output=True, text=True, timeout=60, cwd=tmp_path)
    data = json.loads(out.stdout)
    assert data["digest"] is None and data["settings"]["digest_enabled"] == "off"
    # Missing database: still valid JSON.
    env["STATE_DIR"] = str(tmp_path / "missing")
    out = subprocess.run([sys.executable, "-c", _snippet(), "2026-10-24", "1", "0"], env=env,
                         capture_output=True, text=True, timeout=60, cwd=tmp_path)
    assert json.loads(out.stdout)["status"] == {}


@pytest.mark.parametrize("now,expected", [
    (_utc(2026, 3, 29, 6, 30), "28.03.2026"),   # first CEST morning (08:30 local)
    (_utc(2027, 1, 1, 7, 0), "31.12.2026"),     # year boundary
    (_utc(2026, 11, 1, 6, 0), "31.10.2026"),    # month boundary, 07:00 CET exactly
])
def test_monitor_digest_reports_previous_local_day(host, now, expected):
    _digest_run(host, now)
    assert f"dagsoversigt {expected}" in _notify_lines(host)


def test_monitor_digest_not_before_seven_or_after_midnight(host):
    _digest_run(host, _utc(2026, 10, 25, 23, 30))  # 00:30 CET on the 26th
    _digest_run(host, _utc(2026, 11, 1, 5, 59))    # 06:59 CET
    assert "dagsoversigt" not in _notify_lines(host)


def test_installed_monitor_script_contains_digest_inline(host):
    us = host.tmp / "user.scripts"
    us.mkdir()
    lib_bash(host, "sf_install_user_scripts", USER_SCRIPTS_DIR=str(us),
             UPDATE_CRON_BIN=str(host.tmp / "missing"))
    body = (us / "scripts" / "Spamfilter-monitor" / "script").read_text()
    assert "sf-monitor-snippet" in body and "digest_data" in body and "exec /mnt" not in body
    assert "opsummering" in (us / "scripts" / "Spamfilter-monitor" / "description").read_text()


def test_site_env_overrides_versions_env(tmp_path):
    """operations/site.env survives source updates and wins over versions.env
    (used for TRUSTED_PROXIES with the host-network cloudflared tunnel)."""
    import subprocess
    app = tmp_path / "app"
    (app / "operations").mkdir(parents=True)
    (app / "operations" / "site.env").write_text("TRUSTED_PROXIES=192.168.1.10\n")
    lib = Path(__file__).resolve().parent.parent / "deploy" / "lib.sh"
    out = subprocess.run(["bash", "-c", f'. "{lib}"; printf "%s" "$TRUSTED_PROXIES"'],
                         env={"SPAMFILTER_APP": str(app), "PATH": "/usr/bin:/bin"},
                         capture_output=True, text=True, check=True)
    assert out.stdout == "192.168.1.10"


# ---------------------------------------------------------------- host-monitor 2.3: mail via the filter's mailer

CIRCUIT_HEALTH = {"ok": True, "version": "2.3.0", "accounts": {"bynet": "paused_moves"},
                  "details": {"bynet": {"circuit": "open", "stale": False}}}


def _mail_calls(host):
    return [line for line in host.calls().splitlines() if "/app/mailer.py" in line]


def test_monitor_mails_alerts_and_ok_again_through_the_filter(host):
    now = int(time.time())
    _digest_run(host, now, curl=json.dumps(CIRCUIT_HEALTH), sfdb=_sfdb(None),
                FAKE_DOCKER_EXEC=json.dumps({"spamfilter-unbound drill": DRILL_OK, "spamfilter python": _sfdb(None),
                                             "spamfilter python3": "Sendt: 1, i kø: 0, fejlet: 0"}))
    calls = _mail_calls(host)
    assert len(calls) == 1
    assert calls[0].startswith("exec spamfilter python3 /app/mailer.py notify --kind alert --subject Spamfilter: "
                               "Konto bynet: sikkerhedsbremsen")
    assert "--text Aktivt siden" in calls[0]
    # Unraid notify is still the always-on path.
    assert len(_notify_lines(host).splitlines()) == 1
    ok = {"ok": True, "version": "2.3.0", "accounts": {"bynet": "idle"},
          "details": {"bynet": {"circuit": "closed", "stale": False}}}
    _digest_run(host, now, curl=json.dumps(ok), sfdb=_sfdb(None))
    calls = _mail_calls(host)
    assert len(calls) == 2 and "--subject Spamfilter: OK igen" in calls[1] and "--kind alert" in calls[1]


def test_monitor_mails_the_digest(host):
    _digest_run(host, _utc(2026, 10, 25, 6, 5))
    calls = [c for c in _mail_calls(host) if "--kind digest" in c]
    assert len(calls) == 1 and "--subject Spamfilter: dagsoversigt 24.10.2026" in calls[0]
    assert "--text Dagsoversigt for 24.10.2026" in calls[0]


def test_monitor_never_mails_while_the_filter_is_down_and_survives_mail_failures(host):
    containers = _all_up()
    containers["spamfilter"]["running"] = False
    write_state(host.state_file, containers)
    (host.app / "state" / "backup-status.json").write_text(json.dumps(
        {"ok": True, "ts": int(time.time()), "archive": "/x", "size": 1, "error": None}))
    exec_ok = json.dumps({"spamfilter-unbound drill": DRILL_OK, "spamfilter-rspamd rspamc": "ok"})
    _monitor(host, FAKE_DOCKER_EXEC=exec_ok)
    ms = host.app / "operations" / "monitor-state.json"
    data = json.loads(ms.read_text())
    data["conditions"]["container:spamfilter"]["since"] -= 600
    ms.write_text(json.dumps(data))
    _monitor(host, FAKE_DOCKER_EXEC=exec_ok)
    assert "spamfilter kører ikke" in _notify_lines(host)  # Unraid only ...
    assert _mail_calls(host) == []                          # ... no mail while the filter is down
    # Filter up again, but the mailer fails (exit 1, no key in the fake): the run still succeeds.
    write_state(host.state_file, _all_up())
    (host.app / "state" / "heartbeat").write_text(f"{int(time.time())} boot\n")
    proc = _monitor(host, FAKE_DOCKER_EXEC=exec_ok,
                    FAKE_CURL_BODY=json.dumps({"ok": True, "version": "2.3.0", "accounts": {"a": "idle"}}))
    assert "OK igen" in _notify_lines(host)
    assert len(_mail_calls(host)) == 1 and "mail (alert)" not in proc.stdout


def test_monitor_dry_run_prints_mail_but_sends_nothing(host):
    write_state(host.state_file, _all_up())
    (host.app / "state" / "heartbeat").write_text(f"{int(time.time())} boot\n")
    proc = _monitor(host, "--dry-run", FAKE_CURL_BODY=json.dumps(CIRCUIT_HEALTH),
                    FAKE_DOCKER_EXEC=json.dumps({"spamfilter-unbound drill": DRILL_OK}))
    assert "[dry-run] mail (alert): Spamfilter: Konto bynet: sikkerhedsbremsen" in proc.stdout
    assert _mail_calls(host) == []


def test_monitor_header_documents_the_mail_path_and_its_limit():
    text = (DEPLOY / "host-monitor.sh").read_text()
    head = text.split("set -euo pipefail", 1)[0]
    flat = " ".join(head.replace("\n# ", " ").split())
    assert "python3 /app/mailer.py notify" in flat
    assert "ONLY Unraid notifications work" in flat and "har været stoppet fra" in flat
    # --help prints exactly the header block
    n = head.count("\n")
    assert f"sed -n '2,{n}p'" in text and n >= 53
    assert "legacy_running" in flat and "deploy lock" in flat  # 2.4 legacy guard documented
    assert 'timeout "$MAIL_TIMEOUT" "${FILTER_EXEC[@]}" python3 /app/mailer.py notify' in text


# ---------------------------------------------------------------- 2.3: rollback + image cleanup

FILTER_REPO = "imap-spamfilter-unraid"


def test_recreate_removes_the_stopped_rollback_after_a_passed_gate(host):
    img = versions()["REDIS_IMAGE"]
    write_state(host.state_file, {
        "spamfilter-redis": _container("redis:old"),
        "spamfilter-redis-rollback": _container("redis:older", running=False),
    }, images=[img])
    proc = lib_bash(host, "sf_install_traps; sf_recreate spamfilter-redis sf_gate_health", SF_KEEP_ROLLBACK="0")
    c = read_state(host.state_file)["containers"]
    assert set(c) == {"spamfilter-redis"}
    assert c["spamfilter-redis"]["image"] == img and c["spamfilter-redis"]["running"]
    assert "the stopped spamfilter-redis-rollback was removed" in proc.stdout
    assert "rm spamfilter-redis-rollback" in host.calls()
    assert "rm -f spamfilter-redis-rollback\n" not in host.calls()  # never forced


def test_failed_gate_keeps_the_previous_container_even_without_keep_rollback(host):
    img = versions()["REDIS_IMAGE"]
    write_state(host.state_file, {"spamfilter-redis": _container("redis:old")}, images=[img])
    proc = lib_bash(host, "sf_install_traps; sf_recreate spamfilter-redis sf_gate_health", check=False,
                    SF_KEEP_ROLLBACK="0", FAKE_NEW_HEALTH="unhealthy")
    assert proc.returncode != 0
    c = read_state(host.state_file)["containers"]
    assert c["spamfilter-redis"]["image"] == "redis:old" and c["spamfilter-redis"]["running"]


def test_drop_rollback_never_removes_a_running_container(host):
    write_state(host.state_file, {"spamfilter-rollback": _container("x", running=True)})
    proc = lib_bash(host, "sf_drop_rollback spamfilter")
    assert "is not stopped - left alone" in proc.stderr
    assert "spamfilter-rollback" in read_state(host.state_file)["containers"]


def _images(*tags):
    return [f"{FILTER_REPO}:{t}" for t in tags]


def test_prune_keeps_running_and_previous_version_only(host):
    imgs = _images("2.3.0", "2.2.0", "2.1.0", "2.0.1", "1.0.0-local", "latest", "2.4.0-rc1")
    write_state(host.state_file, {"spamfilter": _container(f"{FILTER_REPO}:2.3.0"),
                                  "spamfilter-redis": _container("redis@sha256:abc")},
                images=imgs + ["redis@sha256:abc", "other/thing:1.0.0"])
    proc = lib_bash(host, "sf_prune_filter_images")
    left = read_state(host.state_file)["images"]
    assert set(left) == set(_images("2.3.0", "2.2.0", "latest", "2.4.0-rc1")) | {"redis@sha256:abc",
                                                                                  "other/thing:1.0.0"}
    assert "Removing old filter image imap-spamfilter-unraid:2.1.0" in proc.stdout
    assert "rmi -f" not in host.calls() and "image rm -f" not in host.calls()


def test_prune_never_removes_an_image_a_container_uses(host):
    imgs = _images("2.3.0", "2.2.0", "2.1.0")
    write_state(host.state_file, {"spamfilter": _container(f"{FILTER_REPO}:2.3.0"),
                                  "spamfilter-rollback": _container(f"{FILTER_REPO}:2.1.0", running=False)},
                images=imgs)
    lib_bash(host, "sf_prune_filter_images")
    assert set(read_state(host.state_file)["images"]) == set(imgs)


def test_prune_does_nothing_without_a_running_filter_image(host):
    imgs = _images("2.2.0", "2.1.0", "2.0.0")
    write_state(host.state_file, {"spamfilter": _container("ghcr.io/x/other:2.3.0")}, images=imgs)
    proc = lib_bash(host, "sf_prune_filter_images")
    assert set(read_state(host.state_file)["images"]) == set(imgs)
    assert "Image cleanup skipped" in proc.stdout


def test_prune_dry_run_changes_nothing(host):
    imgs = _images("2.3.0", "2.2.0", "2.1.0")
    write_state(host.state_file, {"spamfilter": _container(f"{FILTER_REPO}:2.3.0")}, images=imgs)
    proc = lib_bash(host, "sf_prune_filter_images", DRY_RUN="1")
    assert set(read_state(host.state_file)["images"]) == set(imgs)
    assert "[dry-run] docker image rm imap-spamfilter-unraid:2.1.0" in proc.stdout


def test_filter_deploy_removes_rollback_and_old_images(host):
    img = f"{FILTER_REPO}:2.3.0"
    old = f"{FILTER_REPO}:2.1.0"
    prev = f"{FILTER_REPO}:2.2.0"
    write_state(host.state_file, {"spamfilter": _container(prev, user="10099:10099"),
                                  "spamfilter-rollback": _container(old, running=False)},
                images=[img, prev, old, f"{FILTER_REPO}:2.0.0"])
    hb = host.app / "state" / "heartbeat"
    body = ('sf_set_state_owner() { :; }\nsf_install_traps\n'
            f'( sleep 1; echo "$(( $(date +%s) + 5 )) boot" > "{hb}" ) &\n'
            f'sf_recreate spamfilter sf_gate_filter "{img}"\nsf_prune_filter_images')
    lib_bash(host, body, FAKE_CURL_BODY='{"ok":true}', SF_KEEP_ROLLBACK="0",
             FAKE_DOCKER_LOGS=json.dumps({"spamfilter": "main: loaded 4 account(s): a, b"}), SF_GATE_TIMEOUT="20")
    st = read_state(host.state_file)
    assert set(st["containers"]) == {"spamfilter"} and st["containers"]["spamfilter"]["image"] == img
    assert set(st["images"]) == {img, prev}


@pytest.mark.parametrize("script", ["recreate-filter.sh", "recreate-infra.sh"])
def test_scripts_offer_keep_rollback_and_prune(script):
    text = (DEPLOY / script).read_text()
    assert "--keep-rollback) SF_KEEP_ROLLBACK=1 ;;" in text
    assert "export SF_KEEP_ROLLBACK=0" in text
    assert "\nsf_prune_filter_images\n" in text
    usage = subprocess.run(["bash", str(DEPLOY / script), "--help"], capture_output=True, text=True)
    assert usage.returncode == 0 and "--keep-rollback" in usage.stdout and "set -euo" not in usage.stdout


def test_migrate_still_keeps_rollback_containers():
    # Only recreate-filter/-infra drop the rollback; lib.sh keeps it by default.
    assert 'SF_KEEP_ROLLBACK="${SF_KEEP_ROLLBACK:-1}"' in (DEPLOY / "lib.sh").read_text()
    assert "SF_KEEP_ROLLBACK" not in (DEPLOY / "migrate-2.0.sh").read_text()


# ------------------------------------------------- backup: 2.3 secret files

_BACKUP_DOCKER = r'''#!/bin/bash
# Fake docker for a full backup-and-verify.sh run (tests only).
printf '%s\n' "$*" >>"$FAKE_BACKUP_CALLS"
case "$1 $2" in
  "container inspect")
    case "$4" in
      *Image*) echo "sha256:img-$5" ;;
      *Running*) echo true ;;
    esac ;;
  "exec spamfilter")
    # python -c <online backup> /state/.backup-<stamp>.db
    dest="${*: -1}"
    cp "$SPAMFILTER_APP/state/spamfilter.db" "$SPAMFILTER_APP$dest" ;;
  "exec spamfilter-redis") : ;;
  "run --rm") : ;;
  *) echo "fake docker: unsupported $*" >&2; exit 2 ;;
esac
'''


@pytest.fixture
def backup_host(tmp_path):
    """An app dir the real backup-and-verify.sh can back up end to end:
    fake docker (online backup = copy), fake `id -u` = 0, real tar/sha256sum."""
    import sqlite3

    app = tmp_path / "app"
    for sub in ("operations", "state", "config", "rspamd/local.d", "redis", "redis-config"):
        (app / sub).mkdir(parents=True)
    st = app / "state"
    db = sqlite3.connect(st / "spamfilter.db")
    db.execute("CREATE TABLE messages(id INTEGER)")
    db.commit()
    db.close()
    (app / "config" / "accounts.yml").write_text("accounts: []\n")
    (app / "rspamd" / "local.d" / "x.conf").write_text("x = 1;\n")
    (app / "redis-config" / "redis.conf").write_text('requirepass "r"\n')
    (app / "redis" / "dump.rdb").write_bytes(b"REDIS0011")
    for name, data in (("dashboard_users", b"admin:x:admin:1\n"), ("dashboard_secret", b"s" * 32),
                       ("controller.password", b"ctrl\n"), ("redis.password", b"redis\n"),
                       ("contacts.key", bytes(range(32))), ("smtp.password", b"smtp-secret\n")):
        (st / name).write_bytes(data)
        (st / name).chmod(0o600)
    (st / "imap-secrets").mkdir(mode=0o700)
    (st / "imap-secrets" / "bynet").write_text("imap\n")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in (("docker", _BACKUP_DOCKER),
                       ("id", '#!/bin/bash\n[[ "$1" == -u ]] && { echo 0; exit 0; }\nexec /usr/bin/id "$@"\n'),
                       ("notify", '#!/bin/bash\nprintf "%s\\n" "$*" >>"$FAKE_NOTIFY_LOG"\n')):
        (bindir / name).write_text(body)
        (bindir / name).chmod(0o755)
    env = {"PATH": f"{bindir}:{os.environ.get('PATH', '/usr/bin:/bin')}", "HOME": str(tmp_path),
           "SPAMFILTER_APP": str(app), "SF_BACKUP_LOCK": str(tmp_path / "backup.lock"),
           "SF_NOTIFY_BIN": str(bindir / "notify"), "FAKE_NOTIFY_LOG": str(tmp_path / "notify.log"),
           "FAKE_BACKUP_CALLS": str(tmp_path / "docker.log"), "LC_ALL": "C"}

    class H:
        pass
    h = H()
    h.app, h.state, h.env, h.tmp = app, st, env, tmp_path
    return h


def _run_backup(h):
    return subprocess.run(["bash", str(DEPLOY / "backup-and-verify.sh")], env=h.env,
                          capture_output=True, text=True, timeout=60)


def _archive_members(archive: Path) -> dict[str, tuple[int, bytes | None]]:
    import tarfile

    out = {}
    with tarfile.open(archive) as tf:
        for m in tf.getmembers():
            data = tf.extractfile(m).read() if m.isfile() else None
            out[m.name.lstrip("./")] = (m.mode & 0o777, data)
    return out


def test_backup_archives_and_verifies_the_23_secret_files(backup_host):
    h = backup_host
    (h.state / "smtp.password").chmod(0o644)  # a too-open live file is still 0600 in the archive
    proc = _run_backup(h)
    assert proc.returncode == 0, proc.stderr
    st = json.loads((h.state / "backup-status.json").read_text())
    assert st["ok"] is True and st["error"] is None
    members = _archive_members(Path(st["archive"]))
    for name in ("dashboard_users", "dashboard_secret", "controller.password", "redis.password",
                 "contacts.key", "smtp.password"):
        mode, data = members[f"state/{name}"]
        assert mode == 0o600, name
        assert data == (h.state / name).read_bytes(), name
    listed = members["meta/secrets"][1].decode().split()
    assert {"contacts.key", "smtp.password"} <= set(listed)
    sums = members["meta/secrets-sha256"][1].decode()
    assert "state/contacts.key" in sums and "state/smtp.password" in sums
    # Secret content never reaches the output, the status or the log.
    for text in (proc.stdout, proc.stderr, json.dumps(st)):
        assert "smtp-secret" not in text and "ctrl" not in text
    assert Path(st["archive"]).stat().st_mode & 0o777 == 0o600


def test_backup_without_smtp_password_is_fine(backup_host):
    h = backup_host
    (h.state / "smtp.password").unlink()
    proc = _run_backup(h)
    assert proc.returncode == 0, proc.stderr
    st = json.loads((h.state / "backup-status.json").read_text())
    members = _archive_members(Path(st["archive"]))
    assert "state/smtp.password" not in members and "state/contacts.key" in members
    assert "smtp.password" not in members["meta/secrets"][1].decode().split()


def test_backup_restore_test_rejects_a_damaged_contacts_key(backup_host):
    h = backup_host
    (h.state / "contacts.key").write_bytes(b"short")
    proc = _run_backup(h)
    assert proc.returncode != 0
    st = json.loads((h.state / "backup-status.json").read_text())
    assert st["ok"] is False and "restore test: secrets" in st["error"]
    assert "contacts.key" in proc.stderr and "short" not in proc.stderr
    assert not list((h.app / "operations" / "backups").glob("*.tar.gz"))  # removed on failure
    note = Path(h.env["FAKE_NOTIFY_LOG"]).read_text()
    assert "backup fejlede" in note


def test_backup_never_follows_a_symlinked_secret(backup_host, tmp_path):
    h = backup_host
    outside = tmp_path / "outside-secret"
    outside.write_text("not-ours\n")
    (h.state / "smtp.password").unlink()
    (h.state / "smtp.password").symlink_to(outside)
    proc = _run_backup(h)
    # A link planted in state/ is never followed: not archived, a warning in
    # the log, and the rest of the backup still runs.
    assert proc.returncode == 0, proc.stderr
    assert "smtp.password is a symlink" in proc.stdout and "not-ours" not in proc.stdout
    st = json.loads((h.state / "backup-status.json").read_text())
    members = _archive_members(Path(st["archive"]))
    assert "state/smtp.password" not in members


def test_backup_never_writes_the_status_through_a_planted_symlink(backup_host, tmp_path):
    h = backup_host
    outside = tmp_path / "outside-file"
    outside.write_text("untouched\n")
    outside.chmod(0o600)
    (h.state / "backup-status.json").symlink_to(outside)
    proc = _run_backup(h)
    # The link is neither followed nor chmod'ed; the verified archive stays
    # and the failed status write is reported.
    assert proc.returncode == 1
    assert "backup-status.json is a symlink" in proc.stderr
    assert outside.read_text() == "untouched\n" and outside.stat().st_mode & 0o777 == 0o600
    assert (h.state / "backup-status.json").is_symlink()
    assert len(list((h.app / "operations" / "backups").glob("spamfilter-*.tar.gz"))) == 1
    assert "backup-status kunne ikke skrives" in Path(h.env["FAKE_NOTIFY_LOG"]).read_text()
    assert not list(h.state.glob(".backup-status*")) and not list((h.app / "operations").glob(".backup-status*"))


def test_backup_status_is_a_fresh_regular_file_and_no_temp_is_left(backup_host):
    h = backup_host
    proc = _run_backup(h)
    assert proc.returncode == 0, proc.stderr
    status = h.state / "backup-status.json"
    assert status.is_file() and not status.is_symlink() and status.stat().st_mode & 0o777 == 0o644
    assert not list(h.state.glob(".backup-status*")) and not list((h.app / "operations").glob(".backup-status*"))


@pytest.mark.parametrize("name", ["backup-and-verify.sh", "backup-offsite.sh"])
def test_status_writers_use_no_predictable_temp_name(name):
    body = (DEPLOY / name).read_text()
    fn = body[body.index("write_status() {"):]
    fn = fn[:fn.index("\n}\n")]
    # No "$STATE/.x.$$": a name the filter's uid could pre-plant as a link.
    assert "$$" not in fn
    assert 'mktemp "$tmpdir/.' in fn and "XXXXXX" in fn and 'tmpdir="$APP/operations"' in fn
    assert 'mv -fT "$tmp" "$STATUS"' in fn and '[[ -L "$STATUS" ]]' in fn


# ---------------------------------------------------------------- 2.6 (B3): off-site copy

FAKE_RCLONE = r'''#!/bin/bash
printf '%s\n' "$*" >>"$FAKE_RCLONE_LOG"
if [[ "$1" == copy ]]; then
  while (( $# )); do
    if [[ "$1" == --files-from ]]; then cat "$2" >>"$FAKE_RCLONE_LOG.files"; fi
    shift
  done
  exit "${FAKE_RCLONE_COPY_RC:-0}"
fi
if [[ "$1" == lsf ]]; then printf 'spamfilter-20261101T013000Z.sfbak\nspamfilter-20261102T013000Z.sfbak\n'; fi
exit 0
'''


@pytest.fixture
def offsite(host):
    dest = host.tmp / "backups" / "spamfilter"
    dest.mkdir(parents=True)
    rclone = host.tmp / "rclone"
    rclone.write_text(FAKE_RCLONE)
    rclone.chmod(0o755)
    env = dict(host.env, SF_BACKUP_HOST_DIR=str(dest), SF_RCLONE_BIN=str(rclone), SF_RCLONE_CONFIG="",
               FAKE_RCLONE_LOG=str(host.tmp / "rclone.log"), SF_OFFSITE_LOCK=str(host.tmp / "offsite.lock"),
               SF_RESTORE_DRILL_DAYS="0")   # 2.12 restore drill: tested in test_v212.py
    now = time.time()
    for i, magic in enumerate((b"SFBACKUP", b"SFBACKUP", b"PLAINTXT")):
        p = dest / f"spamfilter-2026110{i + 1}T013000Z.sfbak"
        p.write_bytes(magic + b"\x01payload")
        os.utime(p, (now - (2 - i) * 3600, now - (2 - i) * 3600))
    old = dest / "spamfilter-20261001T013000Z.sfbak"
    old.write_bytes(b"SFBACKUP old")
    os.utime(old, (now - 10 * 86400, now - 10 * 86400))
    (dest / "spamfilter-20261102T013000Z.sfbak.part").write_bytes(b"SFBACKUP part")
    (host.app / "operations" / "backups").mkdir()
    (host.app / "operations" / "backups" / "spamfilter-x.tar.gz").write_bytes(b"plain secrets")
    host.offsite_env, host.dest = env, dest
    return host


def _offsite(host, *args, **extra):
    env = dict(host.offsite_env, **extra)
    return subprocess.run([str(DEPLOY / "backup-offsite.sh"), *args], env=env, capture_output=True, text=True,
                          timeout=60)


def _offsite_status(host):
    return json.loads((host.app / "state" / "offsite-status.json").read_text())


def test_offsite_dry_run_lists_only_encrypted_archives_and_writes_nothing(offsite):
    proc = _offsite(offsite, "--dry-run")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout
    assert "would copy 2 encrypted archive(s) to offsite:Backup/Spamfilter" in out
    assert "spamfilter-20261101T013000Z.sfbak" in out and "spamfilter-20261102T013000Z.sfbak" in out
    assert "20261103T013000Z.sfbak is not an encrypted archive" in out  # wrong magic: never uploaded
    assert "20261001" not in out and ".part" not in out and "tar.gz" not in out
    assert not (offsite.tmp / "rclone.log").exists()
    assert not (offsite.app / "state" / "offsite-status.json").exists()


def test_offsite_copies_prunes_and_records_status(offsite):
    proc = _offsite(offsite)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    calls = (offsite.tmp / "rclone.log").read_text().splitlines()
    copy = next(c for c in calls if c.startswith("copy "))
    assert copy.startswith(f"copy {offsite.dest} offsite:Backup/Spamfilter --files-from ")
    assert "--immutable" in copy and "--no-traverse" in copy and "--timeout 5m" in copy
    assert "/mnt/disks" not in "".join(calls)
    uploaded = (offsite.tmp / "rclone.log.files").read_text().split()
    assert uploaded == ["spamfilter-20261101T013000Z.sfbak", "spamfilter-20261102T013000Z.sfbak"]
    delete = next(c for c in calls if c.startswith("delete "))
    assert delete.startswith("delete offsite:Backup/Spamfilter --min-age 60d --include spamfilter-*.sfbak")
    st = _offsite_status(offsite)
    assert st["ok"] is True and st["uploaded"] == 2 and st["files"] == 2 and st["error"] is None
    assert st["remote"] == "offsite:Backup/Spamfilter"
    assert oct((offsite.app / "state" / "offsite-status.json").stat().st_mode & 0o777) == "0o644"


def test_offsite_failure_notifies_and_records(offsite):
    write_state(offsite.state_file, {"spamfilter": _container("imap-spamfilter-unraid:2.11.2")})
    proc = _offsite(offsite, FAKE_RCLONE_COPY_RC="5")
    assert proc.returncode == 1
    st = _offsite_status(offsite)
    assert st["ok"] is False and "rclone copy" in st["error"] and "exit 5" in st["error"]
    note = Path(offsite.env["FAKE_NOTIFY_LOG"]).read_text()
    assert "kopi ud af huset fejlede" in note and "-i\talert" in note
    assert "mailer.py notify --kind alert" in offsite.calls()  # the filter mails it too


def test_offsite_off_and_bad_remote(offsite):
    proc = _offsite(offsite, SF_OFFSITE_REMOTE="")
    assert proc.returncode == 0 and _offsite_status(offsite)["skipped"]
    assert not (offsite.tmp / "rclone.log").exists()
    for bad in ("/mnt/disks/offsite_rclone/Backup", "offsite"):
        proc = _offsite(offsite, SF_OFFSITE_REMOTE=bad)
        assert proc.returncode == 1 and "rclone-mål" in proc.stderr
    proc = _offsite(offsite, SF_OFFSITE_KEEP_DAYS="3")
    assert proc.returncode == 1 and "mindst 14" in proc.stderr


def test_offsite_asks_the_container_for_a_fresh_backup(offsite):
    for p in offsite.dest.iterdir():
        os.utime(p, (time.time() - 5 * 86400, time.time() - 5 * 86400))
    write_state(offsite.state_file, {"spamfilter": _container("imap-spamfilter-unraid:2.11.2")})
    proc = _offsite(offsite)
    assert proc.returncode == 1 and "kunne ikke lave en ny krypteret backup" in proc.stderr
    assert "exec -u 10099:10099 spamfilter sfctl backup-now --if-older 20" in offsite.calls()
    assert not (offsite.tmp / "rclone.log").exists()


def test_offsite_installed_as_user_script(host):
    us = host.tmp / "user.scripts"
    us.mkdir()
    lib_bash(host, "sf_install_user_scripts", USER_SCRIPTS_DIR=str(us), UPDATE_CRON_BIN=str(host.tmp / "none"))
    body = (us / "scripts" / "Spamfilter-offsite" / "script").read_text()
    assert 'rclone_cmd copy "$DIR" "$REMOTE"' in body and "exec /mnt" not in body
    cron = (us / "customSchedule.cron").read_text()
    assert f"45 3 * * * /usr/local/emhttp/plugins/user.scripts/startCustom.php {us}/scripts/Spamfilter-offsite/script" in cron



def test_offsite_never_writes_the_status_through_a_planted_symlink(offsite):
    status = offsite.app / "state" / "offsite-status.json"
    dangling = offsite.tmp / "outside" / "created-by-root"
    dangling.parent.mkdir()
    status.symlink_to(dangling)
    proc = _offsite(offsite)
    # Neither written through nor chmod'ed: the dangling link target is
    # never created; the refusal is logged and alerted.
    assert proc.returncode == 1
    assert "offsite-status.json is a symlink" in proc.stderr
    assert not dangling.exists() and status.is_symlink()
    assert "kopi ud af huset fejlede" in Path(offsite.env["FAKE_NOTIFY_LOG"]).read_text()
    for d in (offsite.app / "state", offsite.app / "operations"):
        assert not list(d.glob(".offsite-status*")), d


def test_offsite_status_is_a_fresh_regular_file_and_no_temp_is_left(offsite):
    proc = _offsite(offsite)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    status = offsite.app / "state" / "offsite-status.json"
    assert status.is_file() and not status.is_symlink()
    for d in (offsite.app / "state", offsite.app / "operations"):
        assert not list(d.glob(".offsite-status*")), d


def test_legacy_layout_gets_the_disabled_antivirus_conf(host):
    """2.7 fix: the 4-container layout has no clamd - antivirus.conf must not
    point rspamd at a socket that does not exist there."""
    local_d = host.app / "rspamd" / "local.d"
    for f in ("redis.conf", "worker-controller.inc"):
        (local_d / f).write_text("secret stand-in\n")
    lib_bash(host, "sf_rspamd_preflight() { :; }\nsf_install_rspamd_config")
    text = (local_d / "antivirus.conf").read_text()
    assert text == (ROOT / "rspamd" / "local.d" / "antivirus.conf.legacy").read_text()
    assert "enabled = false;" in text and "clamd.sock" not in text.split("enabled")[-1]
    # The all-in-one layout gets the real rule.
    lib_bash(host, "sf_rspamd_preflight() { :; }\nSF_LAYOUT=aio sf_install_rspamd_config")
    assert (local_d / "antivirus.conf").read_bytes() == (ROOT / "rspamd" / "local.d" / "antivirus.conf").read_bytes()


def test_monitor_one_mail_when_several_mailboxes_stall(host):
    """2.8.0: a damaged database stalled every mailbox at once and the owner got one
    'hængt?' mail per mailbox; several stalled mailboxes now give ONE alert."""
    now = int(time.time())
    health = {"ok": True, "version": "2.11.2", "accounts": {"bynet": "stale", "molt": "stale", "molt-sofie": "stale"},
              "details": {n: {"stale": True, "circuit": "closed"} for n in ("bynet", "molt", "molt-sofie")}}
    _digest_run(host, now, curl=json.dumps(health), sfdb=_sfdb(None))
    st = json.loads((host.app / "state" / "host-status.json").read_text())
    keys = {a["key"]: a for a in st["alerts"]}
    assert set(keys) == {"stale:*"}
    assert "3 postkasser" in keys["stale:*"]["text"] and "bynet, molt, molt-sofie" in keys["stale:*"]["text"]
    ms = host.app / "operations" / "monitor-state.json"
    data = json.loads(ms.read_text())
    data["conditions"]["stale:*"]["since"] -= 301
    ms.write_text(json.dumps(data))
    _digest_run(host, now, curl=json.dumps(health), sfdb=_sfdb(None))
    lines = _notify_lines(host).splitlines()
    assert len(lines) == 1 and "3 postkasser" in lines[0]


def test_monitor_damaged_database_is_one_clear_alert(host):
    now = int(time.time())
    health = {"ok": True, "version": "2.11.2", "accounts": {"bynet": "stale", "molt": "stale"},
              "details": {n: {"stale": True, "circuit": "closed"} for n in ("bynet", "molt")}}
    _digest_run(host, now, curl=json.dumps(health), sfdb=_sfdb(None),
                FAKE_DOCKER_EXEC=json.dumps({"spamfilter-unbound drill": DRILL_OK, "spamfilter python": _sfdb(None),
                                             "spamfilter python3 -s": "SFDBCHECK bad database disk image is malformed\n"}))
    st = json.loads((host.app / "state" / "host-status.json").read_text())
    keys = {a["key"]: a for a in st["alerts"]}
    assert set(keys) == {"database"}                      # no stale mails on top
    assert "Databasen er beskadiget (database disk image is malformed)" in keys["database"]["text"]
    lines = _notify_lines(host).splitlines()
    assert len(lines) == 1 and "Databasen er beskadiget" in lines[0] and "-i\talert" in lines[0]
