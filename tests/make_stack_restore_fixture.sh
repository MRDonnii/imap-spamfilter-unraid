#!/bin/bash
# CI only: a NEW accountless, offline AIO creates an encrypted fuzzy fixture.
set -euo pipefail
umask 077
fixture=${1:?new fixture directory required}
image=${2:?local image required}
[[ ! -e "$fixture" && "$fixture" == /* && "$fixture" != *[:,]* ]] || exit 2
SF_SITE_ENV=/dev/null
# shellcheck source=deploy/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/../deploy/lib.sh"
mkdir -m 700 "$fixture"
mkdir -m 700 "$fixture/output"
chown 10099:10099 "$fixture/output"
cid=''
cleanup() {
  local rc=$?
  trap - EXIT
  if [[ -n "$cid" ]]; then docker rm --force --volumes "$cid" >/dev/null || rc=1; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
SF_AIO_MEMORY=2g SF_AIO_CPUS=1 SF_CLAMAV=0
sf_aio_run_args "sf-fuzzy-fixture-${RANDOM}" "$image" "$fixture/appdata" 127.0.0.1 0 test
opts=()
for (( i=0; i<${#SF_OPTS[@]}; i++ )); do
  case "${SF_OPTS[i]}" in
    -p|--publish|--network|--log-driver|--log-opt) (( i+=1 )) ;;
    *) opts+=("${SF_OPTS[i]}") ;;
  esac
done
# Fresh account seed is accounts: []; fuzzy_check only talks to loopback.
cid="$(docker create "${opts[@]}" --network none --log-driver none --read-only \
  --memory-swap 2g --pids-limit 128 --tmpfs /tmp:rw,nosuid,nodev,size=128m,mode=1777 \
  -e SPAMFILTER_ENABLE_FUZZY=1 \
  -v "$fixture/output:/fixture" \
  -v "$PWD/tests/make_stack_restore_fixture.py:/fixture-maker.py:ro" "$image")"
docker inspect "$cid" | jq -e '.[0] | .HostConfig.NetworkMode == "none" and
  ((.HostConfig.PortBindings // {}) | length == 0) and .HostConfig.Memory > 0 and
  .HostConfig.NanoCpus > 0 and .HostConfig.PidsLimit > 0 and .HostConfig.ReadonlyRootfs == true' >/dev/null
docker start "$cid" >/dev/null
deadline=$(( SECONDS + 180 ))
until docker exec "$cid" sf-health check --json 2>/dev/null | jq -e '.ok == true' >/dev/null; do
  (( SECONDS < deadline )) || exit 1
  sleep 2
done
# Disable the public fuzzy rule in the COPY only, then restart Rspamd.
docker exec --user 11333:11333 "$cid" /usr/local/bin/python3 -c '
from pathlib import Path
for p in (Path("/appdata/rspamd/local.d/fuzzy_check.conf"), Path("/run/spamfilter/rspamd/local.d/fuzzy_check.conf")):
    s=p.read_text().replace("rule \"rspamd.com\" {", "rule \"rspamd.com\" {\n    enabled = false;")
    p.write_text(s)
p=Path("/appdata/rspamd/local.d/worker-fuzzy.inc")
p.write_text(p.read_text()+"\nsync = 1s;\n")
p=Path("/run/spamfilter/rspamd/local.d/worker-fuzzy.inc")
p.write_text(p.read_text()+"\nsync = 1s;\n")
# Only the neutral fixture: expose these two NON-secret configs to backup.
Path("/appdata/rspamd").chmod(0o755)
Path("/appdata/rspamd/local.d").chmod(0o755)
for name in ("fuzzy_check.conf", "worker-fuzzy.inc"):
    (Path("/appdata/rspamd/local.d") / name).chmod(0o644)
'
docker exec "$cid" supervisorctl -c /etc/spamfilter/supervisord.conf restart rspamd >/dev/null
sleep 2
timeout 120 docker exec --user 10099:10099 --workdir /app "$cid" \
  /usr/local/bin/python3 /fixture-maker.py
