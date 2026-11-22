#!/bin/bash
# Replace the spamfilter container with FILTER_IMAGE (deploy/versions.env).
#
#   recreate-filter.sh [--dry-run] [--build] [--no-backup] [--keep-rollback] [--image IMAGE]
#
# Order: (build) -> backup-and-verify -> stop old -> rename it to
# spamfilter-rollback -> delete heartbeat -> chown state/config to the
# filter uid -> run new -> gate. Gate (SPEC I4): running >= 40 s with
# RestartCount 0, heartbeat newer than the container start, /healthz 200 on
# the LAN address and the log line "loaded N account(s)". On failure the
# previous container (and its state ownership) is restored automatically.
# After a passed gate the stopped spamfilter-rollback is removed (keep it
# with --keep-rollback) and filter images older than the previous version
# are deleted (the running image and one previous version stay). The image
# is built from the source tree when --build is given or the tag is missing.
#
# Manual rollback later: see deploy/README.md ("Rollback").
set -euo pipefail

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; }

build=0 backup=1 image=""
export SF_KEEP_ROLLBACK=0
while (( $# )); do
  case "$1" in
    --dry-run) export DRY_RUN=1 ;;
    --build) build=1 ;;
    --no-backup) backup=0 ;;
    --keep-rollback) SF_KEEP_ROLLBACK=1 ;;
    --image) image="${2:?--image needs a value}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

# shellcheck source=deploy/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

image="${image:-$FILTER_IMAGE}"
[[ "$DRY_RUN" == 1 ]] || sf_require_root
sf_require_cmds docker jq curl flock awk sha256sum
sf_require_app
# 2.4: never next to a live all-in-one container (two Redis on one data dir).
sf_require_legacy_layout
sf_lock
sf_install_traps

log "recreate-filter: $image (app dir $APP)$([[ "$DRY_RUN" == 1 ]] && echo ' [DRY RUN]')"
if (( build )) || ! docker image inspect "$image" >/dev/null 2>&1; then
  sf_build_filter_image "$image"
fi
if (( backup )); then
  sf_backup
else
  warn "--no-backup: skipping backup-and-verify"
fi

# Dies after an automatic rollback (failed container logs are saved in
# operations/failed-spamfilter-<stamp>.log).
sf_recreate spamfilter sf_gate_filter "$image"
sf_prune_filter_images
sf_summary
log "Done. WebUI: $SF_URL/"
