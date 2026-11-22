#!/bin/bash
# One-time migration of a running 1.x install to spamfilter 2.0.
# Idempotent: re-running skips everything that is already in place.
#
#   migrate-2.0.sh [--dry-run] [--no-backup] [--skip-user-scripts]
#
# Run from the unpacked 2.0 source tree on the Unraid host, normally
# $SPAMFILTER_APP/source/deploy/migrate-2.0.sh. Steps:
#   1. preflight: root, tools, app dir, source tree, deploy lock; warn
#      about accounts.yml without junk: / defaults.bayes_user; lock source/
#   2. build the filter image (FILTER_IMAGE from versions.env)
#   3. validate unbound.conf (unbound-checkconf) and rspamd local.d
#      (rspamadm configtest) in throwaway containers - nothing changed yet
#   4. backup-and-verify.sh (consistent backup + isolated restore test)
#   5. source/: root:root, not group/world-writable
#   6. install unbound.conf + non-secret rspamd local.d files (the rendered
#      redis.conf / worker-controller.inc with passwords are left alone)
#   7. recreate redis, unbound, rspamd (--init, limits, cap-drop, ...)
#      unless already current; verify fuzzy egress (ENABLE_FUZZY=1)
#   8. recreate the filter: stop 1.x, chown state/ + config/ to 10099
#      (dirs 0700, files 0600, heartbeat/status JSON 0644), start 2.0, gate
#   9. install User Scripts Spamfilter-backup (03:00) and
#      Spamfilter-monitor (*/5) with the script bodies inline
#  10. first host-monitor run + summary
# Any failed container gate rolls that container back (incl. ownership of
# state/ for the filter) and stops the migration.
set -euo pipefail

usage() { sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; }

backup=1 user_scripts=1
while (( $# )); do
  case "$1" in
    --dry-run) export DRY_RUN=1 ;;
    --no-backup) backup=0 ;;
    --skip-user-scripts) user_scripts=0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

# shellcheck source=deploy/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

log "=== Spamfilter $VERSION migration (app dir $APP)$([[ "$DRY_RUN" == 1 ]] && echo ' [DRY RUN - nothing is changed]')"

# 1. preflight
[[ "$DRY_RUN" == 1 ]] || sf_require_root
sf_require_cmds docker jq curl flock awk sha256sum cmp install
sf_require_app
# 2.4: never next to a live all-in-one container (two Redis on one data dir).
sf_require_legacy_layout
for f in filter/Dockerfile.unraid filter/filter.py filter/healthcheck.py filter/static \
         deploy/unbound.conf rspamd/local.d/fuzzy_check.conf.readonly; do
  [[ -e "$SF_SRC/$f" ]] || die "source tree incomplete: $SF_SRC/$f missing"
done
docker network inspect "$SF_NETWORK" >/dev/null 2>&1 || die "docker network $SF_NETWORK missing - run init-host.sh first"
sf_lock
sf_install_traps
sf_check_accounts_config
# Lock source/ before anything builds or executes from it (appdata is an SMB
# share; a writable tree would let others change what root runs next).
sf_lock_source

# 2. image
log "--- Step 2: filter image"
sf_build_filter_image "$FILTER_IMAGE"

# 3. validate before touching anything
log "--- Step 3: validate configs"
sf_unbound_preflight
sf_rspamd_preflight

# 4. backup
log "--- Step 4: backup"
if (( backup )); then
  sf_backup
else
  warn "--no-backup: skipping backup-and-verify"
fi

# 5. source tree (locked again: backup-and-verify ran in between)
log "--- Step 5: source/ ownership"
sf_lock_source

# 6 + 7. infra containers (config install is part of each step so a failed
# gate restores exactly the files that step replaced)
log "--- Step 6/7: infra containers"
upstream_changed=0
for name in spamfilter-redis spamfilter-unbound spamfilter-rspamd; do
  case "$name" in
    spamfilter-unbound) sf_install_unbound_config ;;
    spamfilter-rspamd) sf_install_rspamd_config ;;
  esac
  if sf_is_current "$name"; then
    log "$name is already current - not recreated"
    if [[ "$name" == spamfilter-rspamd ]] && (( upstream_changed )); then
      # redis/unbound got new containers (new IPs); rspamd resolves them
      # only at startup.
      sf_restart_gated spamfilter-rspamd
    fi
  else
    sf_recreate "$name" sf_gate_health
    upstream_changed=1
  fi
done
sf_verify_fuzzy

# 8. filter
log "--- Step 8: filter"
if sf_is_current spamfilter "$FILTER_IMAGE"; then
  log "spamfilter already runs $FILTER_IMAGE with the current flags - not recreated"
else
  sf_recreate spamfilter sf_gate_filter "$FILTER_IMAGE"
fi

# 9. user scripts
log "--- Step 9: User Scripts"
if (( user_scripts )); then
  sf_install_user_scripts
else
  warn "--skip-user-scripts: backup/monitor schedules not installed"
fi

# 10. first monitor run + summary
log "--- Step 10: host monitor + summary"
if [[ "$DRY_RUN" == 1 ]]; then
  run "$SF_DEPLOY_DIR/host-monitor.sh"
else
  "$SF_DEPLOY_DIR/host-monitor.sh" >/dev/null || warn "host-monitor.sh failed (non-fatal)"
fi
sf_summary
sf_check_accounts_config
log "Rollback containers kept (stopped): $(docker ps -a --format '{{.Names}}' | grep -E -- '-rollback$' | tr '\n' ' ' || true)"
log "=== Migration to $VERSION complete. WebUI: $SF_URL/"
