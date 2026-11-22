#!/bin/bash
# Remove what the 4-container layout left behind - ONLY with --yes, and only
# while the all-in-one container is live and healthy.
#
#   cleanup.sh [--dry-run] [--yes]
#
# Removed (each only if it exists and is STOPPED; never with -f on a
# running one; never anything by pattern):
#   containers  spamfilter-legacy spamfilter-rspamd spamfilter-redis
#               spamfilter-unbound spamfilter-aio-rolledback spamfilter-rollback
#               spamfilter-aio-test
#   network     spamnet, if no container is attached
#   images      REDIS_IMAGE and UNBOUND_IMAGE (versions.env), the
#               filter-only imap-spamfilter-unraid images (2.3.x, *-filter)
#               and all-in-one images older than the previous version. Kept:
#               the running AIO image, the previous AIO version, the rspamd
#               base (RSPAMD_IMAGE), FILTER_BASE_IMAGE and the Redis build
#               image (needed by the next deploy/aio/build.sh). docker image
#               rm is never forced, so an image a container uses stays.
#   autostart   the old names in Unraid's autostart list
# Never touched: any other container, image, network or volume, and the app
# dir (the all-in-one container uses all of it).
# After cleanup.sh a rollback to the four containers is no longer possible
# (restore from a backup instead, BACKUP.md).
# Log: operations/aio-cleanup-<stamp>.log.
set -euo pipefail

usage() { sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; }

yes=0
while (( $# )); do
  case "$1" in
    --dry-run) export DRY_RUN=1 ;;
    --yes) yes=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

# shellcheck source=deploy/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

if [[ "$DRY_RUN" != 1 && "$yes" != 1 ]]; then
  echo "cleanup.sh removes the stopped 4-container setup for good (no rollback afterwards)." >&2
  echo "Would remove (if present and stopped): ${SF_AIO_OLD_CONTAINERS[*]}, network $SF_NETWORK, old images." >&2
  echo "Run with --dry-run to see the exact plan, then with --yes." >&2
  exit 2
fi
[[ "$DRY_RUN" == 1 ]] || sf_require_root
sf_require_cmds docker jq flock awk
sf_require_app
sf_lock
sf_aio_tee_log cleanup
log "cleanup of the 4-container leftovers$([[ "$DRY_RUN" == 1 ]] && echo ' [DRY RUN]')"

sf_aio_cleanup
sf_summary
log "Cleanup done. Kept: spamfilter (all-in-one), its image, the previous all-in-one image and the build bases."
