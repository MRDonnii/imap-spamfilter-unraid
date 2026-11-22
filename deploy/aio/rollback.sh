#!/bin/bash
# Manual way back from the all-in-one container to the four containers -
# any time after the migration, as long as cleanup.sh has not removed them.
#
#   rollback.sh [--dry-run] --yes [--no-backup]
#
# 1. backup-and-verify.sh (the AIO layout; --no-backup skips it when the
#    AIO is too broken for a backup - the nightly one stays).
# 2. The AIO container is stopped (90 s, so Redis saves) and kept as
#    spamfilter-aio-rolledback (restart policy no); it is never running
#    while the old Redis starts.
# 3. spamfilter-legacy becomes spamfilter again; restart policies, the Unraid
#    autostart list (in the old start order) and the template are restored;
#    redis, unbound, rspamd and the filter start in that order, each gated.
# Also repairs the state an interrupted migrate.sh can leave behind before
# it renamed anything (the four stopped, restart policy no, off autostart).
# Run it inside tmux/screen: a dropped SSH session must not stop it halfway.
# The app dir was never rewritten by the AIO (same files, same uids), so the
# old containers see everything the AIO did - also Bayes it learned since.
# Log: operations/aio-rollback-<stamp>.log.
set -euo pipefail

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; }

yes=0 backup=1
while (( $# )); do
  case "$1" in
    --dry-run) export DRY_RUN=1 ;;
    --yes) yes=1 ;;
    --no-backup) backup=0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

# shellcheck source=deploy/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

if [[ "$DRY_RUN" != 1 && "$yes" != 1 ]]; then
  echo "rollback.sh changes the running spamfilter: add --yes (or --dry-run to see the plan)" >&2
  exit 2
fi
[[ "$DRY_RUN" == 1 ]] || sf_require_root
sf_require_cmds docker jq curl flock awk
sf_require_app
sf_lock
sf_aio_tee_log rollback
log "rollback: all-in-one -> four containers (app dir $APP)$([[ "$DRY_RUN" == 1 ]] && echo ' [DRY RUN]')"

layout="$(sf_layout)"
if [[ "$layout" != aio ]] && ! sf_exists "$SF_AIO_LEGACY"; then
  # A migrate.sh that died before 'spamfilter' was renamed (kill -9, power
  # loss) leaves the four stopped / restart=no / off autostart: put them back.
  if [[ "$layout" == legacy ]] && sf_aio_legacy_needs_repair; then
    warn "the four containers are not all running with restart unless-stopped - an interrupted migration? restoring them"
  else
    die "the all-in-one container is not live and there is no $SF_AIO_LEGACY - nothing to roll back"
  fi
fi
for name in "${SF_AIO_INFRA[@]}"; do
  sf_exists "$name" || die "$name is missing (removed by cleanup.sh?) - a rollback is no longer possible; restore from BACKUP.md instead"
done
if (( backup )) && [[ "$layout" == aio ]]; then
  if [[ "$DRY_RUN" == 1 ]]; then
    run "$SF_DEPLOY_DIR/backup-and-verify.sh"
  else
    "$SF_DEPLOY_DIR/backup-and-verify.sh" ||
      die "backup failed - nothing was changed (--no-backup rolls back without a fresh backup)"
  fi
fi
sf_aio_rollback keep || die "rollback finished with problems - see above"
sf_summary
log "Back on the four containers. The stopped all-in-one container is kept as $SF_AIO_ROLLEDBACK."
log "The 2.4 monitor and backup User Scripts detect the layout by themselves."
