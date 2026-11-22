#!/bin/bash
# Update the all-in-one container to a new image (2.4 and later) - the AIO
# counterpart of recreate-filter.sh.
#
#   update.sh [--dry-run] [--build] [--image IMAGE] [--no-backup] [--keep-rollback]
#
# Order: (build.sh) -> backup-and-verify -> rspamd rules (2.6.1, configtest
# with the new image) -> /backup dir (2.6, see
# sf_aio_prepare_backup) -> stop spamfilter (90 s) -> rename
# it spamfilter-rollback -> delete the heartbeat -> run IMAGE with the same
# parameters (lib-aio.sh, = the Unraid template) -> gate (Docker healthy,
# filter/rspamd/redis/unbound ok, heartbeat, /healthz, accounts loaded). A
# failed gate removes the new container and starts the previous one again
# (same app dir, nothing chowned). After a passed gate: the template gets
# the new image, the stopped spamfilter-rollback is removed (keep it with
# --keep-rollback) and AIO images older than the previous version are
# deleted (the running and the previous one stay). Then (2.11.2) the Unraid
# User Scripts are re-installed from this tree (install-user-scripts.sh), so
# the host jobs and the update helper always match the running version.
# 2.12: the previous container's last 72 h of log is saved to
# operations/container-log-spamfilter-<stamp>.log before it is removed, and
# housekeeping keeps at most 3 old source trees (source.prev-*/source.bak*)
# and our own operations/*.log files for 30 days (never mail or state).
# IMAGE defaults to AIO_IMAGE (versions.env); --build builds it first.
# Run it inside tmux/screen; Ctrl-C or a dropped SSH session still rolls back.
# Log: operations/aio-update-<stamp>.log.
set -euo pipefail

usage() { sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; }

build=0 backup=1 image=""
export SF_KEEP_ROLLBACK=0 SF_LAYOUT=aio
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
. "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

image="${image:-$AIO_IMAGE}"
[[ "$DRY_RUN" == 1 ]] || sf_require_root
sf_require_cmds docker jq curl flock awk sha256sum
sf_require_app
sf_require_aio_layout
sf_lock
sf_install_traps
sf_aio_tee_log update
log "update: all-in-one -> $image (app dir $APP)$([[ "$DRY_RUN" == 1 ]] && echo ' [DRY RUN]')"

if (( build )); then
  # DRY_RUN is exported, so build.sh plans only under --dry-run as well.
  SF_LOCK_HELD=1 "$SF_AIO_DIR/build.sh" --tag "$image"
fi
if [[ "$DRY_RUN" != 1 ]]; then
  docker image inspect "$image" >/dev/null 2>&1 || die "image $image not found - build it: deploy/aio/update.sh --build"
  [[ "$(sf_image_layout "$image")" == aio ]] || die "$image is not an all-in-one image"
fi
if (( backup )); then
  sf_backup
else
  warn "--no-backup: skipping backup-and-verify"
fi

# 2.6.1: this release's rspamd rules (configtest with the new image first; restored on rollback).
sf_aio_install_rspamd_config "$image"
# 2.6 (B3): /backup (encrypted nightly backups on the array) is added when
# the share exists; without it the new container runs exactly as before.
sf_aio_prepare_backup
# Dies after an automatic rollback (logs: operations/failed-spamfilter-<stamp>.log).
sf_recreate spamfilter sf_gate_aio "$image"
sf_aio_install_template "$image"
# 2.11.2: the host jobs (backup, offsite, monitor and the update helper) run
# as Unraid User Scripts with this release's script bodies copied INLINE, so
# re-install them from this (verified) tree - otherwise a new
# update-runner.sh would never take effect. Never fails the update (the new
# container already passed the gate). Run as its own process (its own
# `set -euo pipefail`; it takes no lock): in `( fn ) || warn` bash turns
# errexit off inside the subshell, so a failing jq/awk would not stop it.
if [[ -d "$USER_SCRIPTS_DIR" ]]; then
  USER_SCRIPTS_DIR="$USER_SCRIPTS_DIR" UPDATE_CRON_BIN="$UPDATE_CRON_BIN" SPAMFILTER_APP="$APP" \
    bash "$SF_DEPLOY_DIR/install-user-scripts.sh" \
    || warn "User Scripts not re-installed - run deploy/install-user-scripts.sh"
else
  warn "User Scripts plugin ($USER_SCRIPTS_DIR) not found - host jobs not (re)installed"
fi
sf_prune_filter_images
sf_housekeeping
sf_summary
log "Done. WebUI: $SF_URL/"
