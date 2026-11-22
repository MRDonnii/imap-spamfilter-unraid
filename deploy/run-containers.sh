#!/bin/bash
# FRESH install only: create the four containers that do not exist yet,
# with the same flags/gates as the recreate scripts (deploy/lib.sh).
# Existing installs: use migrate-2.0.sh / recreate-*.sh instead.
#
#   run-containers.sh [--dry-run]
#
# Order: redis, unbound, rspamd, filter. Requires init-host.sh (dirs,
# rendered secrets, network) and init-dashboard-user.sh afterwards.
set -euo pipefail

while (( $# )); do
  case "$1" in
    --dry-run) export DRY_RUN=1 ;;
    -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

# shellcheck source=deploy/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ "$DRY_RUN" == 1 ]] || sf_require_root
sf_require_cmds docker jq curl flock awk sha256sum cmp
sf_require_app
# 2.4: never next to a live all-in-one container (two Redis on one data dir).
sf_require_legacy_layout
for name in "${SF_ALL[@]}"; do
  if sf_exists "$name"; then
    die "$name already exists - this script is for fresh installs only (use migrate-2.0.sh / recreate-*.sh)"
  fi
done
sf_lock
sf_install_traps

docker image inspect "$FILTER_IMAGE" >/dev/null 2>&1 || sf_build_filter_image "$FILTER_IMAGE"
sf_install_unbound_config
sf_install_rspamd_config
sf_recreate spamfilter-redis sf_gate_health
sf_recreate spamfilter-unbound sf_gate_health
sf_recreate spamfilter-rspamd sf_gate_health
sf_verify_fuzzy
sf_recreate spamfilter sf_gate_filter "$FILTER_IMAGE"
sf_summary
log "Spamfilter containers created. Next: init-dashboard-user.sh, install-user-scripts.sh"
