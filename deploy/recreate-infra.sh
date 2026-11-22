#!/bin/bash
# Recreate the infrastructure containers with the flags from deploy/lib.sh.
#
#   recreate-infra.sh [--dry-run] [--no-backup] [--keep-rollback] <redis|rspamd|unbound|all>
#
# unbound: validates + installs deploy/unbound.conf, then recreates.
# rspamd:  validates (rspamadm configtest) + installs the non-secret
#          rspamd/local.d files (+ fuzzy per ENABLE_FUZZY), then recreates.
#          The rendered redis.conf / worker-controller.inc are never touched.
# redis:   recreates (data in redis/ is kept).
# all:     redis, unbound, rspamd - in that order, so rspamd starts last and
#          resolves the new redis/unbound addresses.
# Each container gets a health gate; on failure the previous container and
# config files are restored. After a passed gate the stopped
# <name>-rollback is removed (--keep-rollback keeps it), and filter images
# older than the previous filter version are deleted.
set -euo pipefail

usage() { sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; }

backup=1 target=""
export SF_KEEP_ROLLBACK=0
while (( $# )); do
  case "$1" in
    --dry-run) export DRY_RUN=1 ;;
    --no-backup) backup=0 ;;
    --keep-rollback) SF_KEEP_ROLLBACK=1 ;;
    redis|rspamd|unbound|all)
      [[ -z "$target" ]] || { echo "only one target allowed" >&2; exit 2; }
      target=$1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done
[[ -n "$target" ]] || { usage >&2; exit 2; }

# shellcheck source=deploy/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ "$DRY_RUN" == 1 ]] || sf_require_root
sf_require_cmds docker jq flock awk sha256sum cmp
sf_require_app
# 2.4: never next to a live all-in-one container (two Redis on one data dir).
sf_require_legacy_layout
sf_lock
sf_install_traps

log "recreate-infra: $target (app dir $APP)$([[ "$DRY_RUN" == 1 ]] && echo ' [DRY RUN]')"
if (( backup )); then
  sf_backup
else
  warn "--no-backup: skipping backup-and-verify"
fi

do_redis() {
  sf_recreate spamfilter-redis sf_gate_health
}
do_unbound() {
  sf_install_unbound_config
  sf_recreate spamfilter-unbound sf_gate_health
}
do_rspamd() {
  sf_install_rspamd_config
  sf_recreate spamfilter-rspamd sf_gate_health
  sf_verify_fuzzy
}

case "$target" in
  redis) do_redis; sf_restart_gated spamfilter-rspamd ;;
  unbound) do_unbound; sf_restart_gated spamfilter-rspamd ;;
  rspamd) do_rspamd ;;
  all) do_redis; do_unbound; do_rspamd ;;
esac
sf_prune_filter_images
sf_summary
log "Done."
