#!/bin/bash
# Restore an encrypted backup into an accountless, network-isolated AIO copy.
# Usage: restore-stack-drill.sh --archive FILE --key-file FILE [--image IMAGE]
#                              [--memory-mib 2048]
# Requires root/Docker. Never mounts live data in the runtime container.
# ClamAV/provider logins are excluded. All temporary copies are deleted.
set -euo pipefail
umask 077
archive='' keyfile='' image='' memory=2048
check_args=()
while (( $# )); do
  case "$1" in
    --archive) archive="${2:?}"; shift ;;
    --key-file) keyfile="${2:?}"; shift ;;
    --image) image="${2:?}"; shift ;;
    --memory-mib) memory="${2:?}"; shift ;;
    --require-fuzzy) check_args+=(--require-fuzzy) ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) echo 'Unknown argument' >&2; exit 2 ;;
  esac
  shift
done
if [[ ! "$memory" =~ ^[0-9]{3,4}$ ]] || (( memory < 512 || memory > 4096 )); then
  echo 'Memory must be 512–4096 MiB' >&2; exit 2
fi
# Avoid sourcing optional live site settings; only image defaults are needed.
SF_SITE_ENV=/dev/null
# shellcheck source=deploy/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
sf_require_root
sf_require_cmds docker jq timeout realpath find mktemp cp chown chmod grep stat df awk
[[ -f "$archive" && ! -L "$archive" && -f "$keyfile" && ! -L "$keyfile" ]] || die 'Archive and key must be regular files'
archive="$(realpath "$archive")"; keyfile="$(realpath "$keyfile")"
# Docker bind syntax cannot represent these paths safely.
[[ "$archive$keyfile$APP" != *[:,]* ]] || die 'Paths must not contain commas or colons'
image="${image:-$AIO_IMAGE}"
[[ "$(sf_image_layout "$image")" == aio ]] || die 'A local AIO image is required (no image is pulled)'
# mktemp owns this directory exclusively; no shared/predictable container names.
parent="$APP/operations/restore-drills"
[[ ! -L "$parent" ]] || die 'Restore directory must not be a link'
mkdir -p "$parent"
work="$(mktemp -d "$parent/drill.XXXXXXXX")"
prep='' runtime=''
cleanup() {
  local rc=$? stopped=1
  trap - EXIT
  for cid in "$runtime" "$prep"; do
    if [[ -n "$cid" ]]; then docker rm --force --volumes "$cid" >/dev/null 2>&1 || { stopped=0; rc=1; }; fi
  done
  # Only the freshly created tree, never a source archive/key/live directory.
  if (( stopped )) && [[ "$work" == "$parent/"drill.* && -d "$work" && ! -L "$work" ]]; then
    find "$work" -xdev -depth -delete || rc=1
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Reserve space before duplicating encrypted input; prepare() separately checks
# authenticated plaintext sizes before unpacking. Check app disk headroom.
archive_size="$(stat -c %s "$archive")"
key_size="$(stat -c %s "$keyfile")"
free_kib="$(df -Pk "$work" | awk 'NR==2 {print $4}')"
[[ "$archive_size" =~ ^[0-9]+$ && "$key_size" =~ ^[0-9]+$ && "$free_kib" =~ ^[0-9]+$ ]] || die 'Cannot check free space'
(( key_size > 0 && key_size <= 4096 )) || die 'Invalid backup key file size'
(( free_kib * 1024 >= 3 * archive_size + 536870912 )) || die 'Not enough free space for a private restore copy'
mkdir "$work/output" "$work/input"
# Copy input files so arbitrary owner-only backup keys can be read by the
# unprivileged preparer, without changing source permissions or ownership.
cp -- "$archive" "$work/input/archive.sfbak"
cp -- "$keyfile" "$work/input/backup.key"
archive="$work/input/archive.sfbak"; keyfile="$work/input/backup.key"
chmod 0600 "$archive" "$keyfile"
chown 10099:10099 "$work/output" "$archive" "$keyfile"
# Check daemon-applied isolation before *any* process starts. Image volumes
# may add fresh anonymous mounts; only our explicit bind sources are allowed.
verify_isolation() {
  local cid=$1 expected=$2
  docker inspect "$cid" | jq -e --argjson expected "$expected" '
    .[0] | .HostConfig.NetworkMode == "none" and
    ((.HostConfig.PortBindings // {}) | length == 0) and
    .HostConfig.Memory > 0 and .HostConfig.NanoCpus > 0 and
    .HostConfig.PidsLimit > 0 and .HostConfig.ReadonlyRootfs == true and
    ([.Mounts[] | select(.Type == "bind") | {Source,Destination,RW}] | sort_by(.Destination)) ==
      ($expected | sort_by(.Destination))' >/dev/null || die 'Docker isolation verification failed'
}
prep="$(docker create --network none --log-driver none --read-only --restart no \
  --memory "${memory}m" --memory-swap "${memory}m" --cpus 1 --pids-limit 64 \
  --cap-drop ALL --security-opt no-new-privileges --user 10099:10099 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777 \
  --mount "type=bind,src=$archive,dst=/input/archive.sfbak,readonly" \
  --mount "type=bind,src=$keyfile,dst=/input/backup.key,readonly" \
  --mount "type=bind,src=$work/output,dst=/work" \
  --workdir /app --entrypoint /usr/local/bin/python3 "$image" \
  /app/stackrestore.py prepare --archive /input/archive.sfbak --key-file /input/backup.key \
  --to /work/appdata --memory-mib "$memory")"
expected="$(jq -cn --arg a "$archive" --arg k "$keyfile" --arg w "$work/output" \
  '[{Source:$a,Destination:"/input/archive.sfbak",RW:false},{Source:$k,Destination:"/input/backup.key",RW:false},{Source:$w,Destination:"/work",RW:true}]')"
verify_isolation "$prep" "$expected"
timeout 180 docker start --attach "$prep"
[[ "$(docker inspect -f '{{.State.ExitCode}}' "$prep")" == 0 ]] || die 'Restore preparation failed'
copy="$work/output/appdata"
[[ -f "$copy/operations/restore-proof.json" ]] || die 'Missing preparation proof'
# Service ownership applies ONLY to our freshly restored copy.
chmod 0755 "$copy" "$copy/rspamd"
chown -R 10099:10099 "$copy/state" "$copy/config" "$copy/operations"
chown -R 999:1000 "$copy/redis" "$copy/redis-config"
chown -R 11333:11333 "$copy/rspamd"
chmod 0750 "$copy/rspamd/local.d" "$copy/rspamd/data"
for conf in "$copy/unbound.conf" "$copy/unbound-forward-records.conf"; do
  [[ ! -f "$conf" ]] || chmod 0644 "$conf"
done
unset TRUSTED_PROXIES LOCAL_NETWORKS SPAMFILTER_LAN_URL SF_UPDATE_REPO
SF_AIO_MEMORY="${memory}m" SF_AIO_CPUS=1 SF_CLAMAV=0
sf_aio_run_args "sf-restore-${work##*.}" "$image" "$copy" 127.0.0.1 0 test
# Use production capabilities/tmpfs/service mounts, remove published ports
# and replace network/logging; never allow multiple network flags.
opts=()
for (( i=0; i<${#SF_OPTS[@]}; i++ )); do
  case "${SF_OPTS[i]}" in
    -p|--publish|--network|--log-driver|--log-opt) (( i+=1 )) ;;
    *) opts+=("${SF_OPTS[i]}") ;;
  esac
done
runtime="$(docker create "${opts[@]}" --network none --log-driver none --read-only \
  --memory-swap "${memory}m" --tmpfs /tmp:rw,nosuid,nodev,size=128m,mode=1777 "$image")"
expected="$(jq -cn --arg w "$copy" \
  '[{Source:$w,Destination:"/appdata",RW:true},{Source:($w+"/rspamd/data"),Destination:"/var/lib/rspamd",RW:true}]')"
verify_isolation "$runtime" "$expected"
docker start "$runtime" >/dev/null
deadline=$(( SECONDS + 180 ))
while ! docker exec "$runtime" sf-health check --json 2>/dev/null | jq -e '.ok == true' >/dev/null; do
  (( SECONDS < deadline )) || die 'Restored services did not become healthy in 180 seconds'
  [[ "$(docker inspect -f '{{.State.Running}}' "$runtime")" == true ]] || die 'Restored container stopped'
  sleep 2
done
[[ "$(docker exec "$runtime" sf-health clamav)" == 'clamav: off (SF_CLAMAV=0)' ]] || die 'ClamAV must be off in the offline trial'
docker exec --user 11333:11333 "$runtime" cat /run/spamfilter/rspamd/local.d/antivirus.conf | \
  grep -Eq 'enabled[[:space:]]*=[[:space:]]*false' || die 'Antivirus was not disabled'
timeout 60 docker exec --user 10099:10099 --workdir /app "$runtime" \
  /usr/local/bin/python3 /app/stackrestore.py check "${check_args[@]}"
