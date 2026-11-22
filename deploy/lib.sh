#!/bin/bash
# Shared helpers for the spamfilter deploy scripts. Source it, do not run it:
#   . "$(dirname "$0")/lib.sh"
#
# Everything that creates or replaces the four containers lives here, so
# migrate-2.0.sh, recreate-filter.sh and recreate-infra.sh always use the
# same `docker run` flags, the same health gates and the same rollback.
#
# Conventions: every state-changing command goes through `run` (prints
# instead of executing under --dry-run); nothing here ever prints a secret
# (rendered redis.conf / worker-controller.inc / state/*.password are only
# copied, never read into variables).
#
# Environment overrides (mostly for tests / non-standard installs):
#   SPAMFILTER_APP        app dir (default: the dir above source/, else /mnt/user/appdata/spamfilter)
#   SPAMFILTER_URL        WebUI base URL used by the filter gate
#   SF_GATE_TIMEOUT       seconds a new container gets to pass its gate (180)
#   SF_GATE_MIN_UPTIME    filter must run this long without restarts (40)
#   SF_POLL               gate poll interval in seconds (2)
#   SF_AUTOSTART_FILE     Unraid autostart list (/var/lib/docker/unraid-autostart)
#   SF_LOCK_FILE          deploy lock (/tmp/spamfilter-deploy.lock)
#   USER_SCRIPTS_DIR      User Scripts plugin dir (/boot/config/plugins/user.scripts)
#   UPDATE_CRON_BIN       Unraid cron rebuild helper (/usr/local/sbin/update_cron)
#   SF_KEEP_ROLLBACK      1 = keep the stopped <name>-rollback after a passed gate
#                         (default here; recreate-filter/-infra set 0 unless
#                         --keep-rollback is given)
# shellcheck shell=bash

SF_DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SF_SRC="$(cd "$SF_DEPLOY_DIR/.." && pwd)"
# shellcheck source=deploy/versions.env
. "$SF_DEPLOY_DIR/versions.env"

# The app dir: SPAMFILTER_APP, else the dir this source tree is unpacked in
# (<app dir>/source/deploy/lib.sh) when it looks like one, else Unraid's
# usual appdata path.
sf_default_app() {
  local up
  up="$(cd "$SF_SRC/.." 2>/dev/null && pwd)" || up=""
  if [[ -n "$up" && -d "$up/state" && -d "$up/config" ]]; then
    printf '%s\n' "$up"
  else
    printf '%s\n' /mnt/user/appdata/spamfilter
  fi
}
APP="${SPAMFILTER_APP:-$(sf_default_app)}"
# Site-specific settings that must survive source-tree updates (e.g.
# WEBUI_BIND=192.168.1.10, TRUSTED_PROXIES=192.168.1.10 for a host-network
# cloudflared, ENABLE_FUZZY, SF_UPDATE_REPO).
# root-owned file outside source/; sourced after versions.env so it wins.
SF_SITE_ENV="${SF_SITE_ENV:-$APP/operations/site.env}"
if [[ -f "$SF_SITE_ENV" ]]; then
  # shellcheck source=/dev/null
  . "$SF_SITE_ENV"
fi
# WEBUI_BIND empty (no operations/site.env value): the host's LAN address,
# i.e. the source address of the default route; none found = loopback only.
sf_detect_lan_ip() {
  local ip=""
  if command -v ip >/dev/null 2>&1; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}')" || ip=""
  fi
  [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || ip=127.0.0.1
  printf '%s\n' "$ip"
}
if [[ -z "${WEBUI_BIND:-}" ]]; then
  WEBUI_BIND="$(sf_detect_lan_ip)"
fi
SF_URL="${SPAMFILTER_URL:-http://$WEBUI_BIND:$WEBUI_PORT}"
SF_NETWORK=spamnet
SF_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SF_GATE_TIMEOUT="${SF_GATE_TIMEOUT:-180}"
SF_GATE_MIN_UPTIME="${SF_GATE_MIN_UPTIME:-40}"
SF_POLL="${SF_POLL:-2}"
SF_AUTOSTART_FILE="${SF_AUTOSTART_FILE:-/var/lib/docker/unraid-autostart}"
SF_LOCK_FILE="${SF_LOCK_FILE:-/tmp/spamfilter-deploy.lock}"
USER_SCRIPTS_DIR="${USER_SCRIPTS_DIR:-/boot/config/plugins/user.scripts}"
UPDATE_CRON_BIN="${UPDATE_CRON_BIN:-/usr/local/sbin/update_cron}"
DRY_RUN="${DRY_RUN:-0}"
SF_KEEP_ROLLBACK="${SF_KEEP_ROLLBACK:-1}"
SF_LABEL_HASH=spamfilter.deploy-hash
SF_ALL=(spamfilter-redis spamfilter-unbound spamfilter-rspamd spamfilter)
# Non-secret rspamd files installed from rspamd/local.d. redis.conf and
# worker-controller.inc are rendered with passwords by init-host.sh and are
# never touched here. The map files in rspamd/local.d/maps.d (2.2: brand,
# lure and TLD lists, SURBL whitelist, phishing feed exclusions) are
# installed the same way, see sf_rspamd_maps. 2.7: antivirus.conf (ClamAV in
# the all-in-one container). 2.7 fix: the 4-container layout has no clamd -
# it gets the disabled antivirus.conf.legacy instead (sf_rspamd_source).
SF_RSPAMD_FILES=(actions.conf antivirus.conf classifier-bayes.conf composites.conf greylist.conf groups.conf
                 multimap.conf neural.conf options.inc phishing.conf rbl.conf worker-normal.inc worker-fuzzy.inc
                 url_redirector.conf)

# ---------------------------------------------------------------- output
log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
warn() { printf '[%s] WARNING: %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die()  { printf '[%s] ERROR: %s\n' "$(date +%H:%M:%S)" "$*" >&2; exit 1; }

# Execute a state-changing command, or only show it under --dry-run.
run() {
  if [[ "$DRY_RUN" == 1 ]]; then
    printf '  [dry-run] %s\n' "$(printf '%q ' "$@")"
    return 0
  fi
  "$@"
}

# ---------------------------------------------------------------- preflight
sf_require_root() {
  [[ "$(id -u)" == 0 ]] || die "run as root (on the Unraid host)"
}

sf_require_cmds() {
  local c
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || die "required command not found: $c"
  done
}

sf_require_app() {
  [[ -d "$APP" ]] || die "app dir $APP does not exist (set SPAMFILTER_APP?)"
  [[ -d "$APP/operations" ]] || die "$APP/operations missing - run init-host.sh first"
}

# Warn (never fail) when config/accounts.yml misses the 2.0 owner decisions
# (SPEC 9): an explicit `junk:` per account - otherwise the engine picks the
# provider's own SPECIAL-USE \Junk folder - and defaults.bayes_user (one
# shared Bayes pool). Text scan only; the file holds no secrets.
sf_check_accounts_config() {
  local f="$APP/config/accounts.yml" missing
  if [[ ! -r "$f" ]]; then
    warn "cannot read $f - check junk: Spamfilter / defaults.bayes_user by hand"
    return 0
  fi
  if ! awk '/^defaults:/ {d=1; next} d && /^[^[:space:]#]/ {d=0}
            d && /^[[:space:]]+bayes_user:[[:space:]]*[^[:space:]#]/ {f=1}
            END {exit !f}' "$f"; then
    warn "accounts.yml: defaults.bayes_user is not set - add 'bayes_user: spamfilter' under defaults" \
         "before the first 2.0 scans (otherwise every mailbox learns into its own Bayes pool)"
  fi
  missing="$(awk '
    function flush() { if (n != "" && !j) printf "%s ", n }
    /^accounts:/ {a=1; next}
    a && /^[^[:space:]#]/ {flush(); a=0; n=""}
    a && /^[[:space:]]*-[[:space:]]/ {flush(); n="?"; j=0}
    a && match($0, /^[[:space:]]*-?[[:space:]]*name:[[:space:]]*/) {
      n=substr($0, RLENGTH + 1); gsub(/["\047[:space:]]/, "", n) }
    a && /^[[:space:]]*-?[[:space:]]*junk:[[:space:]]*[^[:space:]#]/ {j=1}
    END {flush()}' "$f")"
  if [[ -n "$missing" ]]; then
    warn "accounts.yml: no explicit 'junk:' for: ${missing% } - add 'junk: Spamfilter' to each" \
         "before switching to Filtrér (otherwise spam goes to the provider's own Junk)"
  fi
  return 0
}

# One deploy operation at a time (fd 9 stays open until the script exits).
sf_lock() {
  # A deploy script calling another one (aio/update.sh -> aio/build.sh)
  # already holds the lock.
  [[ "${SF_LOCK_HELD:-0}" == 1 ]] && return 0
  exec 9>"$SF_LOCK_FILE"
  flock -n 9 || die "another spamfilter deploy script is running ($SF_LOCK_FILE)"
}

# Run the consistent backup first (standalone script, own lock).
sf_backup() {
  log "Backup + isolated restore test (backup-and-verify.sh)"
  if [[ "$DRY_RUN" == 1 ]]; then
    run "$SF_DEPLOY_DIR/backup-and-verify.sh"
  else
    "$SF_DEPLOY_DIR/backup-and-verify.sh" || die "backup failed - nothing was changed"
  fi
}

# ---------------------------------------------------------------- docker
sf_exists() { docker container inspect "$1" >/dev/null 2>&1; }

# sf_inspect NAME JQ_FILTER -> value (fails if the container is missing).
sf_inspect() {
  local json
  json="$(docker container inspect "$1" 2>/dev/null)" || return 1
  jq -r ".[0] | $2" <<<"$json"
}

sf_image_id() {
  local json
  json="$(docker image inspect "$1" 2>/dev/null)" || return 1
  jq -r '.[0].Id' <<<"$json"
}

sf_ensure_image() {
  if docker image inspect "$1" >/dev/null 2>&1; then
    return 0
  fi
  log "Pulling pinned image $1"
  run docker pull "$1" >/dev/null
}

sf_check_dockerfile_base() {
  local from
  from="$(awk 'toupper($1) == "FROM" {print $2; exit}' "$SF_SRC/filter/Dockerfile.unraid")"
  [[ "$from" == "$FILTER_BASE_IMAGE" ]] ||
    die "filter/Dockerfile.unraid FROM ($from) differs from FILTER_BASE_IMAGE in versions.env"
}

sf_build_filter_image() {
  local image=${1:-$FILTER_IMAGE}
  sf_check_dockerfile_base
  [[ -d "$SF_SRC/filter/static" ]] || die "$SF_SRC/filter/static missing - incomplete source tree"
  log "Building $image from $SF_SRC/filter"
  run docker build -t "$image" -f "$SF_SRC/filter/Dockerfile.unraid" "$SF_SRC/filter"
}

# Fill SF_OPTS (docker run options) and SF_IMAGE_CMD (image + command) for
# one container. The label hash is added by sf_recreate.
sf_run_args() {
  local name=$1 image=${2:-}
  # 2.4: with SF_LAYOUT=aio (deploy/aio/update.sh) 'spamfilter' is the
  # all-in-one container (deploy/aio/lib-aio.sh).
  if [[ "${SF_LAYOUT:-legacy}" == aio && "$name" == spamfilter ]]; then
    sf_aio_run_args spamfilter "${image:-$AIO_IMAGE}"
    return 0
  fi
  SF_OPTS=(
    --name "$name" --network "$SF_NETWORK" --restart unless-stopped
    --init --stop-timeout 30
    --log-driver json-file --log-opt max-size=10m --log-opt max-file=3
    -e TZ=Europe/Copenhagen
  )
  # The health commands below must expand inside the container.
  # shellcheck disable=SC2016
  case "$name" in
    spamfilter-redis)
      # Running directly as the image's redis user (999:1000) makes the
      # entrypoint skip its root-only chown/setpriv step, so every
      # capability can go (verified with the pinned image).
      SF_OPTS+=(
        --memory 1536m --cpus 1 --pids-limit 100
        --user 999:1000 --cap-drop ALL --security-opt no-new-privileges
        --health-cmd 'REDISCLI_AUTH=$(grep "^requirepass " /usr/local/etc/redis/redis.conf | cut -d "\"" -f2) redis-cli ping | grep -qx PONG'
        --health-interval 60s --health-timeout 5s --health-retries 3
        --health-start-period 30s --health-start-interval 5s
        -v "$APP/redis:/data" -v "$APP/redis-config:/usr/local/etc/redis:ro"
      )
      SF_IMAGE_CMD=("${image:-$REDIS_IMAGE}" redis-server /usr/local/etc/redis/redis.conf)
      ;;
    spamfilter-unbound)
      # /unbound.sh runs as root: copies /dev/{random,urandom,null} into the
      # chroot (MKNOD), chowns var/ (CHOWN), unbound-anchor writes into the
      # _unbound-owned var/ (DAC_OVERRIDE), then unbound binds :53, chroots
      # and drops to _unbound (NET_BIND_SERVICE, SYS_CHROOT, SETUID/SETGID).
      SF_OPTS+=(
        --memory 512m --cpus 1 --pids-limit 512
        --cap-drop ALL --cap-add NET_BIND_SERVICE --cap-add SETUID --cap-add SETGID
        --cap-add SYS_CHROOT --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add MKNOD
        --security-opt no-new-privileges
        --health-cmd 'drill @127.0.0.1 example.org A | grep -q "rcode: NOERROR"'
        --health-interval 60s --health-timeout 10s --health-retries 3
        --health-start-period 30s --health-start-interval 5s
        -v "$APP/unbound.conf:/opt/unbound/etc/unbound/unbound.conf:ro"
      )
      SF_IMAGE_CMD=("${image:-$UNBOUND_IMAGE}")
      ;;
    spamfilter-rspamd)
      # Unprivileged image user, ports > 1024: no capabilities needed.
      SF_OPTS+=(
        --memory 1536m --cpus 2 --pids-limit 200
        --user 11333:11333 --cap-drop ALL --security-opt no-new-privileges
        --health-cmd 'rspamc -h 127.0.0.1:11334 stat >/dev/null'
        --health-interval 60s --health-timeout 10s --health-retries 3
        --health-start-period 30s --health-start-interval 5s
        -v "$APP/rspamd/local.d:/etc/rspamd/local.d:ro"
        -v "$APP/rspamd/data:/var/lib/rspamd"
      )
      SF_IMAGE_CMD=("${image:-$RSPAMD_IMAGE}")
      ;;
    spamfilter)
      # Healthcheck comes from the image (healthcheck.py).
      SF_OPTS+=(
        --memory 768m --cpus 2 --pids-limit 150
        --user "$FILTER_UID:$FILTER_GID" --cap-drop ALL --security-opt no-new-privileges
        -p "$WEBUI_BIND:$WEBUI_PORT:8080"
        -e HOME=/tmp -e STATE_DIR=/state -e CONFIG_PATH=/config/accounts.yml
        -e RSPAMD_SCAN_URL=http://spamfilter-rspamd:11333/checkv2
        -e RSPAMD_LEARN_URL=http://spamfilter-rspamd:11334
        -e AUTOMATIC_RETENTION_ENABLED=0
        --label "net.unraid.docker.webui=http://$WEBUI_BIND:$WEBUI_PORT/"
        --label "net.unraid.docker.icon=http://$WEBUI_BIND:$WEBUI_PORT/static/logo.png"
        -v "$APP/state:/state" -v "$APP/config:/config"
      )
      # Trusted reverse proxies (versions.env); only passed when set, so the
      # deploy hash of a LAN-only install does not change.
      if [[ -n "${TRUSTED_PROXIES:-}" ]]; then
        SF_OPTS+=(-e "TRUSTED_PROXIES=$TRUSTED_PROXIES")
      fi
      SF_IMAGE_CMD=("${image:-$FILTER_IMAGE}")
      ;;
    *) die "unknown container $name" ;;
  esac
}

# Hash of everything that defines a container: run flags, image id and the
# config files it mounts. Stored as a label so migrate can skip containers
# that are already up to date.
sf_deploy_hash() {
  local name=$1 image_id extra=""
  image_id="$(sf_image_id "${SF_IMAGE_CMD[0]}" 2>/dev/null)" || image_id="${SF_IMAGE_CMD[0]}"
  case "$name" in
    spamfilter-rspamd) extra="$(sf_rspamd_digest)" ;;
    spamfilter-unbound) [[ -f "$APP/unbound.conf" ]] && extra="$(sha256sum <"$APP/unbound.conf")" ;;
  esac
  printf '%s\n' "${SF_OPTS[@]}" "${SF_IMAGE_CMD[@]}" "$image_id" "$extra" | sha256sum | cut -c1-16
}

# Installed rspamd config: the local.d files plus every map in
# local.d/maps.d (name + content), so a changed or new map counts as new
# configuration. Without maps.d (2.1 hosts) the digest is unchanged.
sf_rspamd_digest() {
  local f
  {
    for f in "${SF_RSPAMD_FILES[@]}" fuzzy_check.conf; do
      cat "$APP/rspamd/local.d/$f" 2>/dev/null || true
    done
    for f in "$APP/rspamd/local.d/maps.d/"*; do
      [[ -f "$f" ]] || continue
      printf 'maps.d/%s\n' "${f##*/}"
      cat "$f"
    done
  } | sha256sum
}

# Names of the map files shipped in rspamd/local.d/maps.d (one per line).
sf_rspamd_maps() {
  local f
  for f in "$SF_SRC/rspamd/local.d/maps.d/"*; do
    [[ -f "$f" ]] && printf '%s\n' "${f##*/}"
  done
  return 0
}

# True when NAME runs with exactly the wanted definition and is not failing.
sf_is_current() {
  local name=$1 want have running health
  sf_run_args "$name" "${2:-}"
  want="$(sf_deploy_hash "$name")"
  have="$(sf_inspect "$name" ".Config.Labels[\"$SF_LABEL_HASH\"] // \"\"")" || return 1
  running="$(sf_inspect "$name" '.State.Running')" || return 1
  health="$(sf_inspect "$name" '.State.Health.Status // "none"')" || return 1
  [[ "$have" == "$want" && "$running" == true && "$health" != unhealthy ]]
}

sf_autostart_add() {
  local name=$1
  [[ -f "$SF_AUTOSTART_FILE" ]] || return 0
  # Unraid writes "name" or "name <delay>": match the first field only.
  awk -v n="$name" '$1 == n {found = 1} END {exit !found}' "$SF_AUTOSTART_FILE" && return 0
  log "Adding $name to Unraid autostart"
  if [[ "$DRY_RUN" == 1 ]]; then
    run tee -a "$SF_AUTOSTART_FILE"
  else
    printf '%s\n' "$name" >>"$SF_AUTOSTART_FILE"
  fi
}

# ---------------------------------------------------------------- ownership
# state/ and config/ belong to the filter's runtime uid. Dirs 0700, files
# 0600; files that root cron writes and the UI reads (or vice versa) stay
# world-readable. Root can always write, so no shared group is needed.
sf_set_state_owner() {
  local owner=$1 f
  log "Ownership: state/ and config/ -> $owner (dirs 0700, files 0600)"
  run chown -R "$owner" "$APP/state" "$APP/config"
  run find "$APP/state" "$APP/config" -type d -exec chmod 0700 {} +
  run find "$APP/state" "$APP/config" -type f -exec chmod 0600 {} +
  for f in heartbeat host-status.json backup-status.json; do
    if [[ -e "$APP/state/$f" ]]; then
      run chmod 0644 "$APP/state/$f"
    fi
  done
}

sf_lock_source() {
  [[ -d "$APP/source" ]] || return 0
  log "source/: root:root, not group/world-writable (root runs code from here)"
  run chown -R root:root "$APP/source"
  run chmod -R go-w "$APP/source"
}

# ---------------------------------------------------------------- configs
# Files replaced by this run: dest -> backup copy ("" = did not exist).
declare -gA SF_CFG_PREV=()
SF_CFG_BACKUP="$APP/operations/config-backups/$SF_STAMP"

# sf_install_file SRC DEST OWNER MODE: atomic, only when content differs.
sf_install_file() {
  local src=$1 dest=$2 owner=$3 mode=$4 tmp rel
  [[ -f "$src" ]] || die "missing source file $src"
  if [[ -f "$dest" ]] && cmp -s "$src" "$dest"; then
    log "  unchanged  $dest"
    run chown "$owner" "$dest"
    run chmod "$mode" "$dest"
    return 0
  fi
  log "  install    $dest"
  if [[ "$DRY_RUN" == 1 ]]; then
    run install -m "$mode" "$src" "$dest"
    return 0
  fi
  rel="${dest#"$APP"/}"
  if [[ -f "$dest" ]]; then
    mkdir -p "$(dirname "$SF_CFG_BACKUP/$rel")"
    cp -p "$dest" "$SF_CFG_BACKUP/$rel"
    SF_CFG_PREV["$dest"]="$SF_CFG_BACKUP/$rel"
  else
    SF_CFG_PREV["$dest"]=""
    # New files are not in the backup copy; record them so a manual
    # rollback (README "Rollback") knows what to delete (2.2: multimap,
    # composites, phishing.conf and maps.d/* did not exist in 2.1).
    mkdir -p "$SF_CFG_BACKUP"
    printf '%s\n' "$rel" >>"$SF_CFG_BACKUP/NEW_FILES"
  fi
  tmp="$(mktemp "$dest.new.XXXXXX")"
  cat "$src" >"$tmp"
  chown "$owner" "$tmp"
  chmod "$mode" "$tmp"
  mv -f "$tmp" "$dest"
}

# Put back config files this run replaced under PREFIX (rollback path: the
# rollback container mounts the same paths and must see its old config).
sf_restore_config() {
  local prefix=$1 dest
  for dest in "${!SF_CFG_PREV[@]}"; do
    [[ "$dest" == "$prefix"* ]] || continue
    if [[ -n "${SF_CFG_PREV[$dest]}" ]]; then
      log "  restore    $dest"
      cp -p "${SF_CFG_PREV[$dest]}" "$dest"
    else
      log "  remove     $dest (new in this run)"
      rm -f "$dest"
    fi
    unset 'SF_CFG_PREV[$dest]'
  done
}

# 2.7 fix: the source of one SF_RSPAMD_FILES entry. antivirus.conf is the
# real ClamAV rule only for the all-in-one layout (SF_LAYOUT=aio, or a test
# image of it via sf_aio_install_rspamd_config); the 4-container layout has
# no clamd socket, so it gets the disabled antivirus.conf.legacy (the AIO
# replaces that with its own copy at start, see aio_render.py).
sf_rspamd_source() {
  if [[ "$1" == antivirus.conf && "${SF_LAYOUT:-legacy}" != aio && -z "${SF_RSPAMD_TEST_IMAGE:-}" ]]; then
    echo "$SF_SRC/rspamd/local.d/antivirus.conf.legacy"
  else
    echo "$SF_SRC/rspamd/local.d/$1"
  fi
}

sf_fuzzy_source() {
  if [[ "${ENABLE_FUZZY:-0}" == 1 && "${SF_FUZZY_FORCE_OFF:-0}" != 1 ]]; then
    echo "$SF_SRC/rspamd/local.d/fuzzy_check.conf.readonly"
  else
    echo "$SF_SRC/rspamd/local.d/fuzzy_check.conf"
  fi
}

# Validate the would-be local.d (live rendered secrets + new repo files) in
# a throwaway container before anything is installed.
sf_rspamd_preflight() {
  local stage f rc=0 out
  log "rspamd configtest of the new local.d (throwaway container, no network)"
  if [[ "$DRY_RUN" == 1 ]]; then
    log "  [dry-run] skipped (would run rspamadm configtest in $RSPAMD_IMAGE)"
    return 0
  fi
  stage="$(mktemp -d "$APP/operations/.rspamd-stage-XXXXXX")"
  cp -a "$APP/rspamd/local.d/." "$stage/"
  for f in "${SF_RSPAMD_FILES[@]}"; do
    cp "$(sf_rspamd_source "$f")" "$stage/$f"
  done
  mkdir -p "$stage/maps.d"
  while IFS= read -r f; do
    cp "$SF_SRC/rspamd/local.d/maps.d/$f" "$stage/maps.d/$f"
  done < <(sf_rspamd_maps)
  cp "$(sf_fuzzy_source)" "$stage/fuzzy_check.conf"
  chown -R 11333:11333 "$stage"
  chmod 0750 "$stage"
  if [[ -n "${SF_RSPAMD_TEST_IMAGE:-}" ]]; then
    # 2.6.1: the all-in-one image (no separate rspamd image any more). Its /etc/rspamd/local.d
    # is a symlink to the rendered copy in /run/spamfilter, so the stage is mounted there.
    out="$(docker run --rm --network none --user 11333:11333 --entrypoint rspamadm \
      -v "$stage:/run/spamfilter/rspamd/local.d:ro" "$SF_RSPAMD_TEST_IMAGE" configtest 2>&1)" || rc=$?
  else
    out="$(docker run --rm --network none --user 11333:11333 \
      -v "$stage:/etc/rspamd/local.d:ro" "$RSPAMD_IMAGE" rspamadm configtest 2>&1)" || rc=$?
  fi
  rm -rf "$stage"
  if (( rc != 0 )) || ! grep -q 'syntax OK' <<<"$out"; then
    printf '%s\n' "$out" | tail -n 15 >&2
    die "rspamd configtest failed - live config left unchanged"
  fi
  log "  configtest: syntax OK"
}

sf_unbound_preflight() {
  local stage rc=0 out
  log "unbound-checkconf of deploy/unbound.conf (throwaway container, no network)"
  if [[ "$DRY_RUN" == 1 ]]; then
    log "  [dry-run] skipped (would run unbound-checkconf in $UNBOUND_IMAGE)"
    return 0
  fi
  stage="$(mktemp -d "$APP/operations/.unbound-stage-XXXXXX")"
  cp "$SF_SRC/deploy/unbound.conf" "$stage/unbound.conf"
  chmod 0755 "$stage"
  chmod 0644 "$stage/unbound.conf"
  # checkconf insists on the trust anchor existing; unbound-anchor falls
  # back to its built-in root key without network.
  # shellcheck disable=SC2016
  out="$(docker run --rm --network none --entrypoint sh \
    -v "$stage/unbound.conf:/opt/unbound/etc/unbound/unbound.conf:ro" "$UNBOUND_IMAGE" \
    -c 'mkdir -p /opt/unbound/etc/unbound/var && { /opt/unbound/sbin/unbound-anchor -a /opt/unbound/etc/unbound/var/root.key >/dev/null 2>&1 || true; } && exec /opt/unbound/sbin/unbound-checkconf /opt/unbound/etc/unbound/unbound.conf' 2>&1)" || rc=$?
  rm -rf "$stage"
  if (( rc != 0 )); then
    printf '%s\n' "$out" | tail -n 15 >&2
    die "unbound-checkconf failed - live config left unchanged"
  fi
  log "  checkconf: no errors"
}

sf_install_rspamd_config() {
  local f
  [[ -d "$APP/rspamd/local.d" ]] || die "$APP/rspamd/local.d missing - run init-host.sh first"
  for f in redis.conf worker-controller.inc; do
    [[ -f "$APP/rspamd/local.d/$f" ]] || die "rendered $f missing in rspamd/local.d - run init-host.sh first"
  done
  sf_rspamd_preflight
  log "Installing rspamd local.d (non-secret files only; ENABLE_FUZZY=${ENABLE_FUZZY:-0})"
  for f in "${SF_RSPAMD_FILES[@]}"; do
    sf_install_file "$(sf_rspamd_source "$f")" "$APP/rspamd/local.d/$f" 11333:11333 0640
  done
  if [[ ! -d "$APP/rspamd/local.d/maps.d" ]]; then
    run mkdir -p "$APP/rspamd/local.d/maps.d"
  fi
  run chown 11333:11333 "$APP/rspamd/local.d/maps.d"
  run chmod 0750 "$APP/rspamd/local.d/maps.d"
  while IFS= read -r f; do
    sf_install_file "$SF_SRC/rspamd/local.d/maps.d/$f" "$APP/rspamd/local.d/maps.d/$f" 11333:11333 0640
  done < <(sf_rspamd_maps)
  sf_install_file "$(sf_fuzzy_source)" "$APP/rspamd/local.d/fuzzy_check.conf" 11333:11333 0640
}

# With ENABLE_FUZZY=1: after rspamd is up, prove that the public fuzzy
# storage answers (outbound UDP 11335). If not, fall back to the disabled
# fuzzy_check.conf so every scan does not wait for fuzzy timeouts.
sf_verify_fuzzy() {
  local out
  [[ "${ENABLE_FUZZY:-0}" == 1 && "${SF_FUZZY_FORCE_OFF:-0}" != 1 ]] || return 0
  log "Fuzzy: checking that fuzzy+rspamd.com answers (UDP 11335 egress)"
  if [[ "$DRY_RUN" == 1 ]]; then
    run docker exec spamfilter-rspamd rspamadm fuzzy_ping -n 3 -t 3
    return 0
  fi
  out="$(timeout 60 docker exec spamfilter-rspamd rspamadm fuzzy_ping -n 3 -t 3 2>&1)" || true
  if grep -q 'reply from' <<<"$out"; then
    log "  fuzzy storage reachable"
    return 0
  fi
  printf '%s\n' "$out" | tail -n 5 >&2
  warn "fuzzy storage NOT reachable - installing the disabled fuzzy_check.conf instead (fix egress, then run: recreate-infra.sh rspamd)"
  SF_FUZZY_FORCE_OFF=1
  sf_install_file "$(sf_fuzzy_source)" "$APP/rspamd/local.d/fuzzy_check.conf" 11333:11333 0640
  sf_restart_gated spamfilter-rspamd
}

sf_install_unbound_config() {
  sf_unbound_preflight
  log "Installing unbound.conf"
  sf_install_file "$SF_SRC/deploy/unbound.conf" "$APP/unbound.conf" 0:0 0644
}

# ---------------------------------------------------------------- gates
sf_epoch() { date -d "$1" +%s; }

# Running, never restarted, and Docker health "healthy".
sf_gate_health() {
  local name=$1 deadline line running restarts health
  deadline=$(( $(date +%s) + SF_GATE_TIMEOUT ))
  while :; do
    line="$(sf_inspect "$name" '[.State.Running, .RestartCount, (.State.Health.Status // "none")] | @tsv')" ||
      { warn "$name disappeared"; return 1; }
    IFS=$'\t' read -r running restarts health <<<"$line"
    if [[ "$running" != true || "$restarts" != 0 ]]; then
      warn "$name is not running steadily (running=$running, restarts=$restarts)"
      return 1
    fi
    case "$health" in
      healthy) log "  $name: healthy"; return 0 ;;
      unhealthy) warn "$name reports unhealthy"; return 1 ;;
    esac
    if (( $(date +%s) >= deadline )); then
      warn "$name not healthy after ${SF_GATE_TIMEOUT}s (health=$health)"
      return 1
    fi
    sleep "$SF_POLL"
  done
}

# SPEC I4 filter gate: running >= SF_GATE_MIN_UPTIME s with RestartCount 0,
# heartbeat newer than the container start, /healthz 200 from the LAN
# address, and the engine logged "loaded N account(s)".
sf_gate_filter() {
  local name=spamfilter deadline line running restarts started start_epoch
  local uptime hb hb_ok http_ok log_ok logs health
  deadline=$(( $(date +%s) + SF_GATE_TIMEOUT ))
  while :; do
    line="$(sf_inspect "$name" '[.State.Running, .RestartCount, .State.StartedAt, (.State.Health.Status // "none")] | @tsv')" ||
      { warn "$name disappeared"; return 1; }
    IFS=$'\t' read -r running restarts started health <<<"$line"
    if [[ "$running" != true || "$restarts" != 0 ]]; then
      warn "$name is not running steadily (running=$running, restarts=$restarts)"
      return 1
    fi
    if [[ "$health" == unhealthy ]]; then
      warn "$name reports unhealthy (see: docker inspect $name --format '{{json .State.Health.Log}}')"
      return 1
    fi
    start_epoch="$(sf_epoch "$started")"
    uptime=$(( $(date +%s) - start_epoch ))
    hb_ok=0 http_ok=0 log_ok=0
    hb="$(awk 'NR == 1 {print $1}' "$APP/state/heartbeat" 2>/dev/null || true)"
    hb="${hb%%.*}"
    if [[ "$hb" =~ ^[0-9]+$ ]] && (( hb >= start_epoch - 2 )); then
      hb_ok=1
    fi
    if curl -fsS -o /dev/null --max-time 5 "$SF_URL/healthz" 2>/dev/null; then
      http_ok=1
    fi
    # Capture first: grep -q closing the pipe early would make docker logs
    # die of SIGPIPE and pipefail turn a match into a failure.
    logs="$(docker logs "$name" 2>&1 || true)"
    if grep -Eq 'loaded [0-9]+ account\(s\)' <<<"$logs"; then
      log_ok=1
    fi
    if (( uptime >= SF_GATE_MIN_UPTIME && hb_ok && http_ok && log_ok )); then
      log "  $name: up ${uptime}s, no restarts, fresh heartbeat, /healthz 200, accounts loaded"
      return 0
    fi
    if (( $(date +%s) >= deadline )); then
      warn "$name gate failed after ${SF_GATE_TIMEOUT}s: uptime=${uptime}s heartbeat=$hb_ok healthz=$http_ok accounts_logged=$log_ok"
      return 1
    fi
    sleep "$SF_POLL"
  done
}

# ---------------------------------------------------------------- recreate
# Transaction state for the EXIT-trap rollback (one container at a time).
SF_TX_NAME="" SF_TX_PHASE=0 SF_TX_PREV_USER=""

sf_on_exit() {
  local rc=$?
  sf_aio_log_rescue
  if (( SF_TX_PHASE > 0 )); then
    warn "interrupted while replacing $SF_TX_NAME - rolling back"
    sf_rollback || true
  fi
  return "$rc"
}

sf_install_traps() {
  trap sf_on_exit EXIT
  trap 'exit 130' INT TERM HUP
}

# Undo the phases of the current transaction, newest first.
#   1: old rollback renamed to <name>-rollback-old
#   2: current container stopped      3: renamed to <name>-rollback
#   4: new container created
sf_rollback() {
  local name=$SF_TX_NAME rb="$SF_TX_NAME-rollback" old="$SF_TX_NAME-rollback-old" logf
  local phase=$SF_TX_PHASE
  SF_TX_PHASE=0
  [[ -n "$name" ]] || return 0
  warn "ROLLBACK of $name"
  if (( phase >= 4 )) && sf_exists "$name"; then
    logf="$APP/operations/failed-$name-$SF_STAMP.log"
    docker logs --tail 200 "$name" >"$logf" 2>&1 || true
    chmod 600 "$logf" 2>/dev/null || true
    warn "logs of the failed $name saved to $logf (last lines below)"
    tail -n 15 "$logf" >&2 || true
    docker rm -f "$name" >/dev/null 2>&1 || true
  fi
  case "$name" in
    spamfilter-rspamd) sf_restore_config "$APP/rspamd/local.d/" ;;
    spamfilter-unbound) sf_restore_config "$APP/unbound.conf" ;;
    spamfilter)
      # 2.6.1: the all-in-one update installs rspamd local.d first - the previous container
      # gets the previous rules back (no-op when nothing was installed).
      sf_restore_config "$APP/rspamd/local.d/"
      if [[ -n "$SF_TX_PREV_USER" && "$SF_TX_PREV_USER" != "$FILTER_UID:$FILTER_GID" ]]; then
        sf_set_state_owner "$SF_TX_PREV_USER"
      fi
      ;;
  esac
  if (( phase >= 3 )) && sf_exists "$rb"; then
    docker rename "$rb" "$name"
    docker update --restart unless-stopped "$name" >/dev/null
  fi
  if (( phase >= 2 )) && sf_exists "$name"; then
    docker start "$name" >/dev/null || warn "could not start the previous $name"
  fi
  if (( phase >= 1 )) && sf_exists "$old" && ! sf_exists "$rb"; then
    docker rename "$old" "$rb"
  fi
  warn "previous $name restored"
}

# Remove 1.x style timestamped rollback containers (spamfilter-rollback-<ts>).
sf_remove_legacy_rollbacks() {
  local name=$1 c
  while IFS= read -r c; do
    [[ -n "$c" ]] || continue
    log "Removing legacy rollback container $c"
    run docker rm -f "$c" >/dev/null
  done < <(docker ps -a --format '{{.Names}}' | grep -E "^${name}-rollback-[0-9]{8}T[0-9]{6}Z$" || true)
}

# sf_recreate NAME GATE_FN [IMAGE]: replace NAME, keep exactly one stopped
# rollback container (<name>-rollback); if the gate fails, roll back and die.
# Never call it in a condition (`if`/`||`): bash would disable errexit for
# the whole function and a failed rename could cascade.
sf_recreate() {
  local name=$1 gate=$2 image=${3:-} rb="$1-rollback" old="$1-rollback-old" hash have_current=0 stop_t=30
  # The all-in-one container stops four programs in order (filter 40 s).
  [[ "${SF_LAYOUT:-legacy}" == aio && "$name" == spamfilter ]] && stop_t=90
  sf_run_args "$name" "$image"
  sf_ensure_image "${SF_IMAGE_CMD[0]}"
  hash="$(sf_deploy_hash "$name")"
  log "Recreating $name (${SF_IMAGE_CMD[0]})"

  # Leftovers of an interrupted run: keep the newest rollback only.
  if sf_exists "$old"; then
    if sf_exists "$rb"; then
      run docker rm -f "$old" >/dev/null
    else
      run docker rename "$old" "$rb"
    fi
  fi
  sf_remove_legacy_rollbacks "$name"
  sf_exists "$name" && have_current=1

  if [[ "$DRY_RUN" == 1 ]]; then
    if (( have_current )); then
      sf_exists "$rb" && run docker rename "$rb" "$old"
      run docker stop -t "$stop_t" "$name"
      run docker rename "$name" "$rb"
      run docker update --restart no "$rb"
    fi
    [[ "$name" == spamfilter ]] && run rm -f "$APP/state/heartbeat"
    [[ "$name" == spamfilter ]] && sf_set_state_owner "$FILTER_UID:$FILTER_GID"
    run docker run -d "${SF_OPTS[@]}" --label "$SF_LABEL_HASH=$hash" "${SF_IMAGE_CMD[@]}"
    if [[ "$SF_KEEP_ROLLBACK" == 1 ]]; then
      log "  [dry-run] gate: $gate; on success remove $old"
    else
      log "  [dry-run] gate: $gate; on success remove $old and the stopped $rb"
    fi
    return 0
  fi

  SF_TX_NAME=$name SF_TX_PREV_USER=""
  if (( have_current )); then
    SF_TX_PREV_USER="$(sf_inspect "$name" '.Config.User // ""')" || SF_TX_PREV_USER=""
    if sf_exists "$rb"; then
      docker rename "$rb" "$old"
      SF_TX_PHASE=1
    fi
    # Phase first: an interrupted/failed stop must still restart the old one.
    SF_TX_PHASE=2
    docker stop -t "$stop_t" "$name" >/dev/null
    docker rename "$name" "$rb"
    SF_TX_PHASE=3
    docker update --restart no "$rb" >/dev/null
  fi
  if [[ "$name" == spamfilter ]]; then
    rm -f "$APP/state/heartbeat"
    sf_set_state_owner "$FILTER_UID:$FILTER_GID"
  fi
  SF_TX_PHASE=4
  docker run -d "${SF_OPTS[@]}" --label "$SF_LABEL_HASH=$hash" "${SF_IMAGE_CMD[@]}" >/dev/null

  if "$gate" "$name"; then
    SF_TX_PHASE=0
    if sf_exists "$old"; then
      docker rm -f "$old" >/dev/null
    fi
    sf_autostart_add "$name"
    if (( have_current )) && [[ "$SF_KEEP_ROLLBACK" == 1 ]]; then
      log "  $name replaced; previous container kept stopped as $rb"
    elif (( have_current )); then
      sf_drop_rollback "$name"
    else
      log "  $name created"
    fi
    return 0
  fi
  sf_rollback
  case "$name" in
    spamfilter-redis|spamfilter-unbound)
      # rspamd resolves both names only at startup and the replaced or
      # restored container may have a new IP: without a restart Bayes or
      # DNS stays dead until someone restarts rspamd by hand.
      if sf_exists spamfilter-rspamd; then
        warn "restarting spamfilter-rspamd so it re-resolves $name"
        docker restart -t 30 spamfilter-rspamd >/dev/null 2>&1 ||
          warn "restart failed - run: docker restart spamfilter-rspamd"
      fi
      ;;
  esac
  die "$name failed its gate and was rolled back to the previous container"
}

# After a passed gate: remove the stopped <name>-rollback (the previous
# container). Never a running one, never anything else.
sf_drop_rollback() {
  local name=$1 rb="$1-rollback" running
  sf_exists "$rb" || { log "  $name replaced"; return 0; }
  running="$(sf_inspect "$rb" '.State.Running')" || running=""
  if [[ "$running" != false ]]; then
    warn "$rb is not stopped - left alone"
    return 0
  fi
  # 2.12 (#25): the previous container's log (last 72 h) is kept before the
  # container goes - otherwise every update erased it (0600: it names senders).
  local logf="$APP/operations/container-log-$name-$SF_STAMP.log"
  if [[ -d "$APP/operations" && ! -L "$logf" ]]; then
    docker logs --since 72h "$rb" >"$logf" 2>&1 || true
    chmod 600 "$logf" 2>/dev/null || true
    log "  log of the previous $name (72 h) saved to $logf"
  fi
  docker rm "$rb" >/dev/null
  log "  $name replaced; the stopped $rb was removed (use --keep-rollback to keep it)"
}

# 2.12 (#25) housekeeping after a successful update - never mail, never
# state/, config/ or backups: at most SF_KEEP_SOURCE_PREV (3) old source
# trees (source.prev-* / source.bak*, real directories only) next to
# source/, and our own logs in operations/ older than SF_KEEP_LOG_DAYS (30).
sf_housekeeping() {
  local keep="${SF_KEEP_SOURCE_PREV:-3}" days="${SF_KEEP_LOG_DAYS:-30}" d n=0 f
  [[ "$keep" =~ ^[0-9]+$ && "$days" =~ ^[0-9]+$ ]] || { warn "housekeeping: bad SF_KEEP_* value - skipped"; return 0; }
  while IFS= read -r d; do
    [[ -n "$d" ]] || continue
    n=$((n + 1))
    (( n > keep )) || continue
    if [[ -d "$d" && ! -L "$d" && "$(basename "$d")" =~ ^source\.(prev|bak)[A-Za-z0-9._-]*$ ]]; then
      run rm -rf -- "$d"
      log "  housekeeping: removed old source tree $(basename "$d")"
    fi
  done < <(find "$APP" -mindepth 1 -maxdepth 1 -type d \( -name 'source.prev*' -o -name 'source.bak*' \) \
             -printf '%T@ %p\n' 2>/dev/null | sort -rn | cut -d' ' -f2-)
  [[ -d "$APP/operations" && ! -L "$APP/operations" ]] || return 0
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    run rm -f -- "$f"
    log "  housekeeping: removed old log $(basename "$f")"
  done < <(find "$APP/operations" -mindepth 1 -maxdepth 1 -type f -mtime "+$days" \
             \( -name 'aio-update-*.log' -o -name 'aio-cleanup-*.log' -o -name 'aio-migrate-*.log' \
                -o -name 'update-runner-*.log' -o -name 'failed-*.log' -o -name 'container-log-*.log' \) 2>/dev/null)
  return 0
}

# Version-sort helper: true when $1 sorts before $2 (sort -V).
sf_version_lt() {
  [[ "$1" != "$2" && "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1)" == "$1" ]]
}

# Remove local filter images (repository of FILTER_IMAGE) OLDER than the
# previous version: keeps the image the running spamfilter container uses,
# the newest version below it (for a manual rollback), every newer tag,
# tags that are not versions (latest, dev, ...) and any image a container
# (also a stopped one) still uses. Never forced; a refused rm only warns.
# 2.4: the repository holds two classes of images - all-in-one (label
# spamfilter.layout=aio) and filter-only (2.3.x, *-filter). Only images of the
# running image's class are considered, so an AIO update never counts a
# filter-only image as "the previous version" and vice versa.
sf_prune_filter_images() {
  local repo="${FILTER_IMAGE%:*}" running="" cur="" prev="" ref tag used class
  local -a refs=() keep=() all=()
  running="$(sf_inspect spamfilter '.Config.Image')" || running=""
  if [[ "$running" != "$repo":* ]]; then
    log "Image cleanup skipped: spamfilter does not run a $repo image"
    return 0
  fi
  cur="${running#"$repo":}"
  class="$(sf_image_layout "$running")"
  mapfile -t all < <(docker image ls --format '{{.Repository}}:{{.Tag}}' "$repo" 2>/dev/null |
    grep -E "^${repo//./\\.}:[0-9]+(\.[0-9]+)+([-.+_][A-Za-z0-9._-]+)?$" | sort -t: -k2,2 -V -r || true)
  for ref in "${all[@]}"; do
    if [[ "$ref" == "$running" || "$(sf_image_layout "$ref")" == "$class" ]]; then
      refs+=("$ref")
    fi
  done
  for ref in "${refs[@]}"; do
    tag="${ref#"$repo":}"
    if [[ -z "$prev" ]] && sf_version_lt "$tag" "$cur"; then
      prev="$tag"
    fi
  done
  used="$(docker ps -a --format '{{.Image}}' 2>/dev/null || true)"
  for ref in "${refs[@]}"; do
    tag="${ref#"$repo":}"
    if [[ "$tag" == "$cur" || "$tag" == "$prev" ]] || ! sf_version_lt "$tag" "${prev:-$cur}"; then
      keep+=("$ref")
      continue
    fi
    if grep -qxF -- "$ref" <<<"$used"; then
      keep+=("$ref")
      continue
    fi
    log "Removing old filter image $ref"
    if [[ "$DRY_RUN" == 1 ]]; then
      run docker image rm "$ref"
    else
      docker image rm "$ref" >/dev/null || warn "could not remove $ref (still in use?)"
    fi
  done
  log "Filter images kept: ${keep[*]:-none}"
}

# docker restart + health gate (rspamd after redis/unbound got a new IP:
# it resolves both names only at startup).
sf_restart_gated() {
  local name=$1
  sf_exists "$name" || { warn "$name does not exist - not restarted"; return 0; }
  log "Restarting $name so it re-resolves its upstreams"
  run docker restart -t 30 "$name" >/dev/null
  [[ "$DRY_RUN" == 1 ]] && return 0
  sf_gate_health "$name" || die "$name is not healthy after the restart - check: docker logs $name"
}

# ---------------------------------------------------------------- user scripts
sf_user_script_id() {
  # Mirrors the plugin's ids: "Spamfilter-backup" -> scheduleSpamfilterbackup.
  printf 'schedule%s' "$(printf '%s' "$1" | tr -d ' -' | tr '.' '-')"
}

# Write FILE with CONTENT (stdin) only if it differs. Returns 0 if changed.
sf_write_if_changed() {
  local dest=$1 tmp
  tmp="$(mktemp)"
  cat >"$tmp"
  if [[ -f "$dest" ]] && cmp -s "$tmp" "$dest"; then
    rm -f "$tmp"
    return 1
  fi
  if [[ "$DRY_RUN" == 1 ]]; then
    printf '  [dry-run] write %s\n' "$dest"
    rm -f "$tmp"
    return 0
  fi
  cat "$tmp" >"$dest.new"
  # Keep the existing file's mode/owner (schedule.json is 0666 on Unraid).
  if [[ -f "$dest" ]]; then
    chmod --reference="$dest" "$dest.new" 2>/dev/null || true
    chown --reference="$dest" "$dest.new" 2>/dev/null || true
  fi
  mv -f "$dest.new" "$dest"
  rm -f "$tmp"
  return 0
}

SF_US_BACKED_UP=0
sf_backup_user_script_schedules() {
  (( SF_US_BACKED_UP )) && return 0
  local dest="$APP/operations/user-scripts-backup-$SF_STAMP" f
  log "Backing up User Scripts schedules to $dest"
  run mkdir -p "$dest"
  for f in customSchedule.cron schedule.json; do
    if [[ -f "$USER_SCRIPTS_DIR/$f" ]]; then
      run cp -p "$USER_SCRIPTS_DIR/$f" "$dest/$f"
    fi
  done
  SF_US_BACKED_UP=1
}

# sf_install_user_script NAME CRON TITLE DESCRIPTION SOURCE_SCRIPT
# The full script body is inlined (not exec'd from appdata), so a change in
# appdata can never alter what root runs from cron.
sf_install_user_script() {
  local name=$1 cron=$2 title=$3 desc=$4 src=$5
  local dir="$USER_SCRIPTS_DIR/scripts/$name" path cronf jsonf line id tmp changed=0
  path="$dir/script"
  cronf="$USER_SCRIPTS_DIR/customSchedule.cron"
  jsonf="$USER_SCRIPTS_DIR/schedule.json"
  id="$(sf_user_script_id "$name")"
  line="$cron /usr/local/emhttp/plugins/user.scripts/startCustom.php $path > /dev/null 2>&1"
  [[ -f "$src" ]] || die "missing $src"
  [[ "$(head -n 1 "$src")" == '#!/bin/bash' ]] || die "$src must start with #!/bin/bash"

  log "User script $name ($cron)"
  run mkdir -p "$dir"
  if printf '%s\n' "$title" | sf_write_if_changed "$dir/name"; then changed=1; fi
  if printf '%s\n' "$desc" | sf_write_if_changed "$dir/description"; then changed=1; fi
  if {
    printf '#!/bin/bash\n'
    printf '# Installed by spamfilter deploy %s from deploy/%s.\n' "$VERSION" "$(basename "$src")"
    printf '# Do not edit here: change the source and run deploy/install-user-scripts.sh.\n'
    # shellcheck disable=SC2016 # literal ${...} belongs in the generated script
    printf 'export SPAMFILTER_APP="${SPAMFILTER_APP:-%s}"\n' "$APP"
    tail -n +2 "$src"
  } | sf_write_if_changed "$path"; then changed=1; fi
  # /boot is FAT on Unraid: modes may not stick, which is fine.
  run chmod 0700 "$path" 2>/dev/null || true

  # customSchedule.cron: replace our line in place (or append), keep the
  # rest byte-for-byte.
  tmp="$(mktemp)"
  if [[ -f "$cronf" ]]; then
    awk -v p="startCustom.php $path " -v l="$line" '
      index($0, p) { if (!done) print l; done = 1; next }
      { print }
      END { if (!done) print l }' "$cronf" >"$tmp" || die "could not read $cronf"
  else
    printf '# Generated cron schedule for user.scripts\n%s\n' "$line" >"$tmp"
  fi
  # Never replace the plugin's schedule with an empty file (it holds the
  # owner's own User Scripts too).
  grep -qF "$line" "$tmp" || die "refusing to write $cronf without the $name line"
  if ! cmp -s "$tmp" "$cronf" 2>/dev/null; then
    sf_backup_user_script_schedules
    sf_write_if_changed "$cronf" <"$tmp" || true
    changed=1
  fi
  # schedule.json: same entry shape as the plugin writes.
  if [[ -f "$jsonf" ]]; then
    jq --indent 2 --arg k "$path" --arg id "$id" --arg c "$cron" \
      '.[$k] = {script: $k, frequency: "custom", id: $id, custom: $c}' "$jsonf" >"$tmp" \
      || die "could not update $jsonf (invalid JSON?) - nothing changed"
  else
    jq -n --indent 2 --arg k "$path" --arg id "$id" --arg c "$cron" \
      '{($k): {script: $k, frequency: "custom", id: $id, custom: $c}}' >"$tmp" || die "jq failed"
  fi
  [[ -s "$tmp" ]] || die "refusing to write an empty $jsonf"
  if ! cmp -s "$tmp" "$jsonf" 2>/dev/null; then
    sf_backup_user_script_schedules
    sf_write_if_changed "$jsonf" <"$tmp" || true
    changed=1
  fi
  rm -f "$tmp"
  (( changed )) && SF_US_CHANGED=1
  if (( changed )); then
    log "  installed/updated"
  else
    log "  unchanged"
  fi
}

SF_US_CHANGED=0
sf_install_user_scripts() {
  [[ -d "$USER_SCRIPTS_DIR" ]] || die "User Scripts plugin dir $USER_SCRIPTS_DIR not found"
  run mkdir -p "$USER_SCRIPTS_DIR/scripts"
  sf_install_user_script Spamfilter-backup "0 3 * * *" "Spamfilter consistent backup" \
    "Daglig konsistent backup af spamfilteret (database, Redis, konfiguration og nøglefiler) med isoleret gendannelsestest. Alarm ved fejl." \
    "$SF_DEPLOY_DIR/backup-and-verify.sh"
  sf_install_user_script Spamfilter-offsite "45 3 * * *" "Spamfilter off-site copy" \
    "Kopierer hver nat de krypterede backups (fra containerens /backup) ud af huset med rclone (standard offsite:Backup/Spamfilter, sættes i operations/site.env) og rydder gamle kopier op efter 60 dage. Kun krypterede filer. Alarm ved fejl." \
    "$SF_DEPLOY_DIR/backup-offsite.sh"
  sf_install_user_script Spamfilter-monitor "*/5 * * * *" "Spamfilter host monitor" \
    "Overvåger spamfilterets containere, DNS/RBL, heartbeat, konti og backup hvert 5. minut og skriver status til WebUI'ens Drift-side. Alarm ved problemer og en daglig opsummering kl. 7 – også på mail, når en mailserver er sat op." \
    "$SF_DEPLOY_DIR/host-monitor.sh"
  sf_install_user_script Spamfilter-update "* * * * *" "Spamfilter update runner" \
    "Installerer en ny version, når en administrator har trykket Opdatér nu under Opdateringer i WebUI'en: tjekker den signerede anmodning, henter kildepakken for netop den version fra GitHub, tjekker kontrolsummen og kører deploy/aio/update.sh --build (backup, test og automatisk tilbagerulning). Gør intet, når der ikke er en anmodning." \
    "$SF_DEPLOY_DIR/update-runner.sh"
  if (( SF_US_CHANGED )); then
    if [[ -x "$UPDATE_CRON_BIN" ]]; then
      log "Activating schedules ($UPDATE_CRON_BIN)"
      run "$UPDATE_CRON_BIN"
    else
      warn "$UPDATE_CRON_BIN not found - schedules take effect after the next User Scripts save/reboot"
    fi
  fi
}

# ---------------------------------------------------------------- summary
sf_summary() {
  local name line
  local -a names=("${SF_ALL[@]}")
  if [[ "$(sf_layout)" == aio ]]; then
    names=(spamfilter "$SF_AIO_LEGACY" "${SF_AIO_INFRA[@]}")
  fi
  log "Summary"
  for name in "${names[@]}"; do
    line="$(sf_inspect "$name" '[.State.Status, (.State.Health.Status // "-"), .Config.Image, .Config.User, .RestartCount] | @tsv')" ||
      line="missing"
    printf '  %-20s %s\n' "$name" "$line"
  done
}

# ---------------------------------------------------------------- all-in-one (2.4)
# shellcheck source=deploy/aio/lib-aio.sh
. "$SF_DEPLOY_DIR/aio/lib-aio.sh"
