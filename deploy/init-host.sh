#!/bin/bash
# FRESH install only: create the app dir layout, render the rspamd/redis
# configs with generated passwords and create the docker network.
# Idempotent: existing passwords, rendered configs and accounts.yml are kept.
# Secrets are written straight to 0600 files and never printed.
#
#   init-host.sh [--dry-run]
#
# Then: run-containers.sh, init-dashboard-user.sh, install-user-scripts.sh.
set -euo pipefail
umask 077

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
sf_require_cmds docker openssl sed install
FU="$FILTER_UID:$FILTER_GID"

log "Preparing $APP"
run install -d -m 755 -o root -g root "$APP"
run install -d -m 700 -o root -g root "$APP/operations" "$APP/source"
run install -d -m 700 -o "$FILTER_UID" -g "$FILTER_GID" "$APP/state" "$APP/state/imap-secrets" "$APP/config"
run install -d -m 700 -o 999 -g 1000 "$APP/redis" "$APP/redis-config"
run install -d -m 750 -o 11333 -g 11333 "$APP/rspamd" "$APP/rspamd/data" "$APP/rspamd/local.d"

for kind in redis controller; do
  file="$APP/state/$kind.password"
  if [[ ! -e "$file" ]]; then
    log "  generating $file"
    [[ "$DRY_RUN" == 1 ]] || openssl rand -hex 32 >"$file"
  fi
  run chown "$FU" "$file"
  run chmod 600 "$file"
done

# render TEMPLATE PLACEHOLDER SECRET_FILE DEST OWNER - only when DEST is
# missing (re-rendering would rotate nothing and risk drift).
render() {
  local tpl=$1 ph=$2 secret=$3 dest=$4 owner=$5
  if [[ -e "$dest" ]]; then
    log "  keeping existing $dest"
    return 0
  fi
  log "  rendering $dest"
  [[ "$DRY_RUN" == 1 ]] && return 0
  # The secret only lives in sed's argument list for a moment; hex has no
  # characters that need escaping for the | delimiter.
  sed "s|\${$ph}|$(cat "$secret")|g" "$tpl" >"$dest"
  chown "$owner" "$dest"
  chmod 600 "$dest"
}
render "$SF_SRC/redis/redis.conf.template" REDIS_PASSWORD "$APP/state/redis.password" \
  "$APP/redis-config/redis.conf" 999:1000
render "$SF_SRC/rspamd/local.d/redis.conf.template" REDIS_PASSWORD "$APP/state/redis.password" \
  "$APP/rspamd/local.d/redis.conf" 11333:11333
render "$SF_SRC/rspamd/local.d/worker-controller.inc.template" RSPAMD_PASSWORD "$APP/state/controller.password" \
  "$APP/rspamd/local.d/worker-controller.inc" 11333:11333

if [[ ! -e "$APP/config/accounts.yml" ]]; then
  run install -m 600 -o "$FILTER_UID" -g "$FILTER_GID" "$SF_SRC/deploy/accounts.yml" "$APP/config/accounts.yml"
fi
if [[ ! -e "$APP/operations/dashboard.initial-password" ]]; then
  log "  generating operations/dashboard.initial-password"
  [[ "$DRY_RUN" == 1 ]] || openssl rand -base64 24 >"$APP/operations/dashboard.initial-password"
fi
if [[ -e "$APP/operations/dashboard.initial-password" ]]; then
  run chown root:root "$APP/operations/dashboard.initial-password"
  run chmod 600 "$APP/operations/dashboard.initial-password"
fi

docker network inspect "$SF_NETWORK" >/dev/null 2>&1 || run docker network create --driver bridge "$SF_NETWORK" >/dev/null
log "Host prepared at $APP (unbound.conf and rspamd local.d are installed by run-containers.sh)"
