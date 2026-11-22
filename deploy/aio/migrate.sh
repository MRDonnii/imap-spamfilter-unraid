#!/bin/bash
# Move from the four containers to the all-in-one container (2.4).
#
#   migrate.sh [--dry-run] [--image IMAGE] [--skip-bayes-check]
#
# 1. Preflight: the 4-container layout is live (spamfilter + -rspamd,
#    -redis, -unbound; no spamfilter-legacy), the AIO image exists
#    (deploy/aio/build.sh) and carries spamfilter.layout=aio + VERSION,
#    >= SF_MIN_FREE_MB MiB free on the app dir and Docker, and
#    backup-and-verify.sh passes.
# 2. Snapshot: /api/health (version, account states), Bayes learned counts
#    (rspamc stat) and the Redis key count.
# 3. The four stop (filter first, Redis last - it saves), get restart policy
#    "no", leave the Unraid autostart list, and spamfilter is renamed
#    spamfilter-legacy. Nothing is deleted, nothing is chowned.
# 4. The Unraid template my-spamfilter.xml is installed and the AIO
#    'spamfilter' starts with exactly the template's parameters.
# 5. Gate (SF_AIO_GATE_TIMEOUT s): Docker healthy, filter/rspamd/redis/
#    unbound ok, fresh heartbeat, /healthz, accounts loaded, /api/health
#    version = VERSION, every account that was idle/working is so again,
#    the same Bayes data (lib-aio.sh sf_aio_compare), Home
#    Assistant endpoint answers (200 with SF_HA_TOKEN in the environment,
#    else 404 without a token).
# 6. Any failure, also Ctrl-C -> automatic rollback: the AIO is removed,
#    spamfilter-legacy becomes spamfilter again, restart policies, autostart
#    and template are restored and the four start again (each gated).
# Run it inside tmux/screen (a dropped SSH session is survived - the log
# tee ignores the hangup and the rollback still runs - but tmux keeps the
# output). Never start the stopped old containers by hand afterwards: they
# share the Redis data dir with the AIO (rollback.sh is the way back).
# Log: operations/aio-migrate-<stamp>.log. After a few good days:
# deploy/aio/cleanup.sh --yes. Manual way back meanwhile: rollback.sh.
set -euo pipefail

usage() { sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; }

image="" skip_bayes=0
while (( $# )); do
  case "$1" in
    --dry-run) export DRY_RUN=1 ;;
    --image) image="${2:?--image needs a value}"; shift ;;
    --skip-bayes-check) skip_bayes=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

# shellcheck source=deploy/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

image="${image:-$AIO_IMAGE}"
[[ "$DRY_RUN" == 1 ]] || sf_require_root
sf_require_cmds docker jq curl flock awk df timeout
sf_require_app
sf_lock
sf_aio_tee_log migrate
log "migrate: four containers -> all-in-one $image (app dir $APP)$([[ "$DRY_RUN" == 1 ]] && echo ' [DRY RUN]')"

sf_aio_migrate "$image" "$skip_bayes"
