#!/bin/bash
# All-in-one (2.4) helpers, sourced by deploy/lib.sh (so every deploy script
# knows the layout) - never run directly.
#
# One container 'spamfilter' from AIO_IMAGE replaces spamfilter,
# spamfilter-rspamd, spamfilter-redis and spamfilter-unbound. It reuses the
# app dir UNCHANGED (same files, same uids), so the four containers can be
# started again at any time while they exist (deploy/aio/rollback.sh).
#
# Names while both layouts exist:
#   spamfilter                the live container (AIO after the migration)
#   spamfilter-legacy         the old filter container, stopped
#   spamfilter-{redis,unbound,rspamd}  old infra containers, stopped
#   spamfilter-rollback       previous AIO during/after deploy/aio/update.sh
#   spamfilter-aio-test       throwaway smoke-test container
#
# Env overrides (tests / non-standard installs):
#   SF_AIO_GATE_TIMEOUT   seconds the AIO gets to pass its gate (420)
#   SF_AIO_HTTP_URL       WebUI URL the gate probes (default SF_URL)
#   DOCKERMAN_TEMPLATES   Unraid template dir (/boot/config/plugins/dockerMan/templates-user)
#   SF_AIO_ICON           icon URL (WebUI /static/icon-192.png)
#   SF_MIN_FREE_MB        free space the migration needs on appdata + docker (1024)
#   SF_HA_TOKEN           Home Assistant token for the migration gate (never logged)
#   SF_AIO_CPUS / SF_AIO_MEMORY  container limits (4 / 4g; CI runners have fewer CPUs).
#                         2.7: 4g because ClamAV holds ~1-1.5 GB of signatures
#                         (peak ~2x for a minute while freshclam test-loads an
#                         update); with SF_CLAMAV=0 the 2.6 limit 3g is enough
#   SF_CLAMAV             2.7: 0 = no virus scanning (no clamd/freshclam, for
#                         low-RAM hosts); passed to the container and the
#                         template (default 1 = on). Set it in operations/site.env
#   SF_UPDATE_REPO        2.10: GitHub repo (owner/name) the WebUI page Opdateringer
#                         checks and deploy/update-runner.sh installs from;
#                         passed to the container. Set it in operations/site.env
#   SF_AIO_BACKUP         2.6: host dir mounted as /backup for the encrypted
#                         nightly backups (/mnt/user/backup/spamfilter, the
#                         "backup" share on another disk than the app dir); empty = no /backup mount
# shellcheck shell=bash
# Variables here are used by the scripts that source lib.sh.
# shellcheck disable=SC2034

SF_AIO_DIR="$SF_DEPLOY_DIR/aio"
SF_AIO_NAME=spamfilter
SF_AIO_LEGACY=spamfilter-legacy
SF_AIO_TEST=spamfilter-aio-test
SF_AIO_ROLLEDBACK=spamfilter-aio-rolledback
SF_AIO_INFRA=(spamfilter-redis spamfilter-unbound spamfilter-rspamd)
# Layout label of the image. Read by suffix: any '<name>.layout' label counts,
# so images built before the label was renamed (old prefix) are still known.
SF_LAYOUT_LABEL=spamfilter.layout
SF_LAYOUT_JQ='([.Config.Labels // {} | to_entries[] | select(.key | test("^[a-z0-9-]+[.]layout$")) | .value] | if index("aio") != null then "aio" else (.[0] // "") end)'
SF_VERSION_JQ='([.Config.Labels // {} | to_entries[] | select(.key | test("^[a-z0-9-]+[.]version$")) | .value] | .[0] // "")'
AIO_IMAGE="${AIO_IMAGE:-imap-spamfilter-unraid:$VERSION}"
SF_AIO_GATE_TIMEOUT="${SF_AIO_GATE_TIMEOUT:-420}"
SF_AIO_ICON="${SF_AIO_ICON:-http://$WEBUI_BIND:$WEBUI_PORT/static/icon-192.png}"
DOCKERMAN_TEMPLATES="${DOCKERMAN_TEMPLATES:-/boot/config/plugins/dockerMan/templates-user}"
SF_AIO_TEMPLATE_NAME=my-spamfilter.xml
SF_MIN_FREE_MB="${SF_MIN_FREE_MB:-1024}"
SF_DOCKER_ROOT="${SF_DOCKER_ROOT:-/var/lib/docker}"
SF_AIO_WEBUI_LABEL='http://[IP]:[PORT:8080]/'
SF_LAYOUT="${SF_LAYOUT:-legacy}"
SF_AIO_BACKUP="${SF_AIO_BACKUP-/mnt/user/backup/spamfilter}"
SF_AIO_BACKUP_READY=0
# Redis password from redis.conf, read INSIDE the container by the uid that
# owns it; only the redis-cli answer leaves the container.
# shellcheck disable=SC2016 # expands inside the container
SF_REDIS_AUTH_SH='REDISCLI_AUTH=$(sed -n '"'"'s/^[[:space:]]*requirepass[[:space:]]\{1,\}"\{0,1\}\([^"[:space:]]*\)"\{0,1\}[[:space:]]*$/\1/p'"'"' /usr/local/etc/redis/redis.conf | tail -n 1); export REDISCLI_AUTH;'

# Like run, but the command's own stdout (container ids, names) is
# discarded in a real run; under --dry-run the plan is still printed.
qrun() {
  if [[ "$DRY_RUN" == 1 ]]; then
    run "$@"
  else
    "$@" >/dev/null
  fi
}

# ---------------------------------------------------------------- layout
# aio | legacy | none - by the image label spamfilter.layout=aio (any
# '<name>.layout' label, see SF_LAYOUT_JQ), which every
# AIO container inherits (also when Unraid's dockerMan created it).
sf_layout_of() {
  local lbl
  sf_exists "$1" || { echo none; return 0; }
  lbl="$(sf_inspect "$1" "$SF_LAYOUT_JQ")" || lbl=""
  if [[ "$lbl" == aio ]]; then echo aio; else echo legacy; fi
}

sf_layout() { sf_layout_of "$SF_AIO_NAME"; }

# The 4-container scripts must never run next to a live AIO: a second Redis
# on the same data dir would corrupt the Bayes store.
sf_require_legacy_layout() {
  if [[ "$(sf_layout)" == aio ]]; then
    die "the all-in-one container is live (spamfilter has $SF_LAYOUT_LABEL=aio) - use deploy/aio/update.sh, or deploy/aio/rollback.sh first"
  fi
}

sf_require_aio_layout() {
  [[ "$(sf_layout)" == aio ]] ||
    die "the all-in-one container is not live (no $SF_LAYOUT_LABEL=aio on spamfilter) - migrate first: deploy/aio/migrate.sh"
}

sf_image_layout() {
  local json
  json="$(docker image inspect "$1" 2>/dev/null)" || { echo none; return 0; }
  jq -r ".[0] | $SF_LAYOUT_JQ | if . == \"\" then \"legacy\" else . end" <<<"$json"
}

# ---------------------------------------------------------------- run args
# SF_AIO_EXTRA: everything dockerMan cannot express with its own fields -
# the run scripts AND the template's ExtraParams use exactly this list.
# sf_aio_extra BIND HOSTPORT RESTART
sf_aio_extra() {
  local bind=$1 port=$2 restart=${3:-unless-stopped}
  # shellcheck disable=SC2054 # the commas belong to the --tmpfs options
  SF_AIO_EXTRA=(
    --restart "$restart" --stop-timeout 90
    --log-opt max-size=10m --log-opt max-file=3
    --memory "${SF_AIO_MEMORY:-4g}" --cpus "${SF_AIO_CPUS:-4}" --pids-limit 512
    --cap-drop ALL --cap-add CHOWN --cap-add SETUID --cap-add SETGID --cap-add KILL
    --security-opt no-new-privileges
    --tmpfs /run/spamfilter:rw,nosuid,nodev,noexec,size=16m,mode=0755
    -p "$bind:$port:8080/tcp"
  )
}

# Site settings passed as environment (only when set, like the 4-container
# filter); the template carries them as variables.
sf_aio_env() {
  SF_AIO_ENV=(-e TZ=Europe/Copenhagen)
  local k
  for k in TRUSTED_PROXIES LOCAL_NETWORKS SPAMFILTER_LAN_URL SF_CLAMAV SF_UPDATE_REPO; do
    if [[ -n "${!k:-}" ]]; then
      SF_AIO_ENV+=(-e "$k=${!k}")
    fi
  done
}

# sf_aio_run_args NAME [IMAGE] [APP] [BIND] [PORT] [test]
# Fills SF_OPTS and SF_IMAGE_CMD (same contract as sf_run_args).
sf_aio_run_args() {
  local name=$1 image=${2:-$AIO_IMAGE} app=${3:-$APP} bind=${4:-$WEBUI_BIND} port=${5:-$WEBUI_PORT}
  local mode=${6:-live}
  if [[ "$mode" == test ]]; then
    sf_aio_extra "$bind" "$port" no
  else
    sf_aio_extra "$bind" "$port" unless-stopped
  fi
  sf_aio_env
  SF_OPTS=(--name "$name" --network bridge --log-driver json-file "${SF_AIO_EXTRA[@]}" "${SF_AIO_ENV[@]}"
           -v "$app:/appdata" -v "$app/rspamd/data:/var/lib/rspamd")
  # 2.6 (B3): /backup only when the host dir exists (sf_aio_prepare_backup
  # creates it): an install without it keeps running exactly as before.
  if [[ "$mode" != test ]] && sf_aio_backup_ok; then
    SF_OPTS+=(-v "$SF_AIO_BACKUP:/backup")
  fi
  if [[ "$mode" != test ]]; then
    SF_OPTS+=(--label net.unraid.docker.managed=dockerman
              --label "net.unraid.docker.webui=$SF_AIO_WEBUI_LABEL"
              --label "net.unraid.docker.icon=$SF_AIO_ICON"
              --label net.unraid.docker.shell=bash)
  fi
  SF_IMAGE_CMD=("$image")
}

# 2.6 (B3): the /backup mount can be added (host dir exists, or is planned
# under --dry-run by sf_aio_prepare_backup).
sf_aio_backup_ok() {
  [[ -n "$SF_AIO_BACKUP" ]] && { [[ -d "$SF_AIO_BACKUP" ]] || [[ "$SF_AIO_BACKUP_READY" == 1 ]]; }
}

# Create the host dir of /backup (owner FILTER_UID, 0700) when its parent -
# the Unraid share, which must live on another disk than the app dir - exists. Without the share
# nothing is created and the container runs without /backup (the filter
# then warns on Drift and in sfctl doctor). Never touches an existing dir.
sf_aio_prepare_backup() {
  local dir=$SF_AIO_BACKUP share owner
  if [[ -z "$dir" ]]; then
    log "Encrypted backups: no /backup mount (SF_AIO_BACKUP is empty)"
    return 0
  fi
  [[ "$dir" == /* && "$dir" != *..* ]] || { warn "SF_AIO_BACKUP=$dir is not an absolute path - no /backup mount"; SF_AIO_BACKUP=""; return 0; }
  case "$dir/" in
    "$APP"/*) warn "SF_AIO_BACKUP=$dir is inside the app dir - backups must go to another disk; no /backup mount"
              SF_AIO_BACKUP=""; return 0 ;;
  esac
  if [[ -d "$dir" ]]; then
    owner="$(stat -c %u "$dir" 2>/dev/null || echo '?')"
    if [[ "$owner" != "$FILTER_UID" ]]; then
      warn "$dir belongs to uid $owner - the filter (uid $FILTER_UID) must be able to write there: chown $FILTER_UID:$FILTER_GID $dir"
    fi
    log "Encrypted backups: $dir -> /backup"
    SF_AIO_BACKUP_READY=1
    return 0
  fi
  share="$(dirname "$dir")"
  if [[ ! -d "$share" ]]; then
    warn "$share does not exist - create the Unraid share (on another disk than the app dir) and run update.sh again; until then the container runs without /backup"
    return 0
  fi
  log "Encrypted backups: creating $dir (owner $FILTER_UID, mode 0700) -> /backup"
  run mkdir "$dir"
  run chmod 0700 "$dir"
  run chown "$FILTER_UID:$FILTER_GID" "$dir"
  SF_AIO_BACKUP_READY=1
}

# 2.6.1: install the rspamd rules of this release into the app dir (rspamd/local.d). The
# all-in-one container renders that directory at every start, but nothing copied new or
# changed rule files there after the first install - 2.6.0 shipped new maps and composites
# that never went live. configtest runs first in a throwaway container of the NEW image
# (no network) on the would-be directory: secrets rendered in the app dir + the release's
# files. The rendered secrets (redis.conf, worker-controller.inc) are never touched; the
# previous files are kept in operations/config-backups/<stamp>/ and restored by sf_rollback.
sf_aio_install_rspamd_config() {
  local image=$1
  local f
  [[ -d "$APP/rspamd/local.d" ]] || { warn "no $APP/rspamd/local.d - rspamd rules not installed"; return 0; }
  for f in redis.conf worker-controller.inc; do
    [[ -f "$APP/rspamd/local.d/$f" ]] || { warn "rendered $f missing in rspamd/local.d - rspamd rules not installed"; return 0; }
  done
  # fuzzy_check.conf follows ENABLE_FUZZY from versions.env (the owner's choice, 1 = on).
  SF_RSPAMD_TEST_IMAGE="$image" sf_install_rspamd_config
}

# Smoke test: map each HOST (the original IMAP servers) to 127.0.0.1 inside
# the throwaway container (appends --add-host to SF_OPTS; names that are not
# plain host names are skipped). sf_aio_block_hosts HOST...
sf_aio_block_hosts() {
  local h
  for h in "$@"; do
    if [[ "$h" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]]; then
      SF_OPTS+=(--add-host "$h:127.0.0.1")
    fi
  done
  return 0
}

# ---------------------------------------------------------------- template
sf_xml() { local s=$1; s=${s//&/&amp;}; s=${s//</&lt;}; s=${s//>/&gt;}; s=${s//\"/&quot;}; printf '%s' "$s"; }

# sf_aio_template [IMAGE] [APP]: the dockerMan template on stdout. The
# committed deploy/aio/unraid-template.xml is this output with the defaults
# (tests compare them), the scripts install it with the live values.
sf_aio_template() {
  local image=${1:-$AIO_IMAGE} app=${2:-$APP}
  sf_aio_extra "$WEBUI_BIND" "$WEBUI_PORT" unless-stopped
  local extra="${SF_AIO_EXTRA[*]}"
  cat <<EOF
<?xml version="1.0"?>
<Container version="2">
  <Name>spamfilter</Name>
  <Repository>$(sf_xml "$image")</Repository>
  <Registry/>
  <Network>bridge</Network>
  <MyIP/>
  <Shell>bash</Shell>
  <Privileged>false</Privileged>
  <Support/>
  <Project/>
  <Overview>Spamfilter til familiens og firmaets IMAP-postkasser. Alt kører i denne ene container: filteret og WebUI'en, rspamd (spam-motor), Redis (Bayes-hukommelse), Unbound (DNS til sortlister) og ClamAV (virusscanning). Intet bliver slettet: spam flyttes til mappen Spamfilter i samme postkasse. Kun WebUI'en (port 8080) er åben; rspamd, Redis, Unbound og ClamAV lytter kun inde i containeren. Alle data ligger i app-mappen. Nødadgang: docker exec -it spamfilter sfctl. Opdatering: deploy/aio/update.sh (backup, kontrol og automatisk tilbagerulning). Start aldrig de gamle stoppede containere spamfilter-redis, -rspamd, -unbound eller spamfilter-legacy i hånden, mens denne kører: de bruger de samme Redis-data. Tilbage til fire containere: deploy/aio/rollback.sh.</Overview>
  <Category>Security: Network:Other</Category>
  <WebUI>$(sf_xml "$SF_AIO_WEBUI_LABEL")</WebUI>
  <TemplateURL/>
  <Icon>$(sf_xml "$SF_AIO_ICON")</Icon>
  <ExtraParams>$(sf_xml "$extra")</ExtraParams>
  <PostArgs/>
  <CPUset/>
  <DonateText/>
  <DonateLink/>
  <Requires>Lav ikke om på de avancerede felter: porten er bundet til $(sf_xml "$WEBUI_BIND") under Extra Parameters, og stien rspamd-data skal pege på rspamd/data i app-mappen.</Requires>
  <Config Name="App-mappe" Target="/appdata" Default="$(sf_xml "$app")" Mode="rw" Description="Spamfilterets mappe med alt: konfiguration, database, Redis, rspamd og backups. Ejere og rettigheder bevares som de er." Type="Path" Display="always" Required="true" Mask="false">$(sf_xml "$app")</Config>
  <Config Name="rspamd-data" Target="/var/lib/rspamd" Default="$(sf_xml "$app/rspamd/data")" Mode="rw" Description="rspamd/data i app-mappen (rspamd-billedet har et VOLUME her; uden stien gemmes rspamds data i et anonymt volume)." Type="Path" Display="advanced" Required="true" Mask="false">$(sf_xml "$app/rspamd/data")</Config>$(sf_aio_template_backup)
  <Config Name="Tidszone" Target="TZ" Default="Europe/Copenhagen" Mode="" Description="Tidszone for logs, dagsoversigt og ugerapport." Type="Variable" Display="advanced" Required="true" Mask="false">Europe/Copenhagen</Config>
  <Config Name="Betroede proxyer" Target="TRUSTED_PROXIES" Default="" Mode="" Description="IP-adresser på proxyen foran WebUI'en (fx Cloudflare Tunnel på værtsnetværket: $(sf_xml "$WEBUI_BIND")). Tom = kun hjemmenetværket." Type="Variable" Display="advanced" Required="false" Mask="false">$(sf_xml "${TRUSTED_PROXIES:-}")</Config>
  <Config Name="Hjemmenetværk" Target="LOCAL_NETWORKS" Default="" Mode="" Description="Netværk, der tæller som hjemme (kommasepareret). Tom = standard (private adresser)." Type="Variable" Display="advanced" Required="false" Mask="false">$(sf_xml "${LOCAL_NETWORKS:-}")</Config>
  <Config Name="Antivirus (ClamAV)" Target="SF_CLAMAV" Default="1" Mode="" Description="1 = mails virusscannes med ClamAV (bruger ca. 1-1,5 GB RAM; containeren har 4 GB). 0 = slået fra, fx på en server med lidt RAM. Virussignaturerne gemmes i app-mappen under clamav." Type="Variable" Display="advanced" Required="false" Mask="false">$(sf_xml "${SF_CLAMAV:-1}")</Config>
  <Config Name="LAN-adresse" Target="SPAMFILTER_LAN_URL" Default="" Mode="" Description="Filterets LAN-adresse til Home Assistant-pakken. Tom = http://192.168.1.10:18080." Type="Variable" Display="advanced" Required="false" Mask="false">$(sf_xml "${SPAMFILTER_LAN_URL:-}")</Config>
  <Config Name="Opdateringskilde" Target="SF_UPDATE_REPO" Default="" Mode="" Description="GitHub-repo (ejer/navn), som siden Opdateringer i WebUI'en tjekker for nye versioner. Sættes i operations/site.env på værten; tom = siden viser, hvordan det sættes op." Type="Variable" Display="advanced" Required="false" Mask="false">$(sf_xml "${SF_UPDATE_REPO:-}")</Config>
</Container>
EOF
}

# 2.6 (B3): the /backup path line of the template (none when SF_AIO_BACKUP is empty).
sf_aio_template_backup() {
  [[ -n "$SF_AIO_BACKUP" ]] || return 0
  printf '\n  <Config Name="Backup-placering" Target="/backup" Default="%s" Mode="rw" Description="Krypterede natlige backups (kl. 02:30). Skal ligge på en anden disk end app-mappen (fx sharen backup) og ejes af uid 10099. Uden stien laves der ingen backup ud af app-mappen." Type="Path" Display="always" Required="false" Mask="false">%s</Config>' \
    "$(sf_xml "$SF_AIO_BACKUP")" "$(sf_xml "$SF_AIO_BACKUP")"
}

# Install the template where Unraid's Docker tab finds it (a copy of the
# previous one goes to operations/config-backups/<stamp>/).
sf_aio_install_template() {
  local image=${1:-$AIO_IMAGE} dest="$DOCKERMAN_TEMPLATES/$SF_AIO_TEMPLATE_NAME"
  if [[ ! -d "$DOCKERMAN_TEMPLATES" ]]; then
    warn "$DOCKERMAN_TEMPLATES not found - Unraid template not installed"
    return 0
  fi
  if [[ -f "$dest" ]]; then
    run mkdir -p "$SF_CFG_BACKUP"
    run cp -p "$dest" "$SF_CFG_BACKUP/$SF_AIO_TEMPLATE_NAME"
  fi
  log "Unraid template -> $dest ($image)"
  sf_aio_template "$image" "$APP" | sf_write_if_changed "$dest" || true
}

# Put back the template the migration replaced (a non-AIO one), or remove ours.
sf_aio_restore_template() {
  local dest="$DOCKERMAN_TEMPLATES/$SF_AIO_TEMPLATE_NAME" backup="" f
  [[ -d "$DOCKERMAN_TEMPLATES" ]] || return 0
  for f in "$APP"/operations/config-backups/*/"$SF_AIO_TEMPLATE_NAME"; do
    [[ -f "$f" ]] || continue
    grep -q 'Target="/appdata"' "$f" || backup=$f
  done
  if [[ -n "$backup" ]]; then
    log "Restoring the previous Unraid template from $backup"
    run cp -p "$backup" "$dest"
  elif [[ -f "$dest" ]] && grep -q 'Target="/appdata"' "$dest"; then
    # only OUR template; a 4-container one (never replaced) stays
    log "Removing the all-in-one Unraid template $dest"
    run rm -f "$dest"
  fi
}

# ---------------------------------------------------------------- Unraid autostart
sf_autostart_remove() {
  local name=$1 tmp
  [[ -f "$SF_AUTOSTART_FILE" ]] || return 0
  awk -v n="$name" '$1 == n {found = 1} END {exit !found}' "$SF_AUTOSTART_FILE" || return 0
  log "Removing $name from Unraid autostart"
  if [[ "$DRY_RUN" == 1 ]]; then
    run sed -i "/^$name\( \|$\)/d" "$SF_AUTOSTART_FILE"
    return 0
  fi
  tmp="$(mktemp)"
  awk -v n="$name" '$1 != n' "$SF_AUTOSTART_FILE" >"$tmp"
  cat "$tmp" >"$SF_AUTOSTART_FILE"
  rm -f "$tmp"
}

sf_autostart_backup() {
  [[ -f "$SF_AUTOSTART_FILE" ]] || return 0
  run mkdir -p "$SF_CFG_BACKUP"
  run cp -p "$SF_AUTOSTART_FILE" "$SF_CFG_BACKUP/unraid-autostart"
}

# Rollback: put the given 4-container names back into Unraid's autostart
# list in their start order (redis, unbound, rspamd, spamfilter) at the
# place of the first one still listed (else at the end). Each entry keeps
# its "<delay>" field from the current list or, for the names the migration
# removed, from the copy it saved (newest operations/config-backups/<stamp>/
# unraid-autostart). Every other line stays as it is now.
# sf_autostart_restore_legacy NAME...
sf_autostart_restore_legacy() {
  local saved tmp
  [[ -f "$SF_AUTOSTART_FILE" ]] || return 0
  (( $# )) || return 0
  # config-backups/<UTC stamp>/: the newest stamp is the latest migration
  saved="$(find "$APP/operations/config-backups" -mindepth 2 -maxdepth 2 -name unraid-autostart \
    2>/dev/null | LC_ALL=C sort | tail -n 1 || true)"
  log "Unraid autostart: $* (in this order)"
  if [[ "$DRY_RUN" == 1 ]]; then
    log "  [dry-run] would rewrite $SF_AUTOSTART_FILE (other entries unchanged)"
    return 0
  fi
  tmp="$(mktemp)"
  awk -v names="$*" -v saved="$saved" '
    BEGIN {
      n = split(names, order, " ")
      for (i = 1; i <= n; i++) want[order[i]] = 1
      if (saved != "") {
        while ((getline l < saved) > 0) { split(l, f, " "); if ((f[1] in want) && !(f[1] in old)) old[f[1]] = l }
        close(saved)
      }
    }
    function block(   i) { for (i = 1; i <= n; i++) print ((order[i] in cur) ? cur[order[i]] : ((order[i] in old) ? old[order[i]] : order[i])) }
    { lines[NR] = $0; if (($1 in want) && !($1 in cur)) cur[$1] = $0 }
    END {
      done = 0
      for (i = 1; i <= NR; i++) {
        split(lines[i], f, " ")
        if (f[1] in want) { if (!done) { block(); done = 1 } continue }
        print lines[i]
      }
      if (!done) block()
    }' "$SF_AUTOSTART_FILE" >"$tmp"
  cat "$tmp" >"$SF_AUTOSTART_FILE"
  rm -f "$tmp"
}

# ---------------------------------------------------------------- probes
# sf_exec_prefix LAYOUT PART [CONTAINER]: SF_EXEC = the docker exec prefix for one part.
sf_exec_prefix() {
  local layout=$1 part=$2
  if [[ "$layout" == aio ]]; then
    case "$part" in
      filter) SF_EXEC=(docker exec -u 10099:10099 "${3:-$SF_AIO_NAME}") ;;
      rspamd) SF_EXEC=(docker exec -u 11333:11333 "${3:-$SF_AIO_NAME}") ;;
      redis) SF_EXEC=(docker exec -u 999:1000 "${3:-$SF_AIO_NAME}") ;;
      *) SF_EXEC=(docker exec "${3:-$SF_AIO_NAME}") ;;
    esac
  else
    case "$part" in
      filter) SF_EXEC=(docker exec spamfilter) ;;
      *) SF_EXEC=(docker exec "spamfilter-$part") ;;
    esac
  fi
}

# "BAYES_SPAM 251" lines (empty when unreadable). 4 containers: `rspamc
# stat` inside spamfilter-rspamd (its own loopback is password-exempt).
# AIO: no client is exempt (aio_render.py pins secure_ip), so the filter uid
# asks /stat WITH the controller password (sf-health bayes; the password
# never leaves the container).
sf_bayes_counts() {
  local out
  if [[ "$1" == aio ]]; then
    sf_exec_prefix aio filter "${2:-}"
    timeout 30 "${SF_EXEC[@]}" /usr/local/bin/sf-health bayes 2>/dev/null |
      awk 'NF == 2 && $2 ~ /^[0-9]+$/ {print $1, $2}' || true
    return 0
  fi
  sf_exec_prefix "$1" rspamd "${2:-}"
  out="$(timeout 30 "${SF_EXEC[@]}" rspamc -h 127.0.0.1:11334 stat 2>/dev/null)" || return 0
  awk '/^Statfile: / { if (match($0, /learned: [0-9]+/)) print $2, substr($0, RSTART + 9, RLENGTH - 9) }' <<<"$out"
}

sf_redis_dbsize() {
  local out
  sf_exec_prefix "$1" redis "${2:-}"
  out="$(timeout 30 "${SF_EXEC[@]}" sh -c "$SF_REDIS_AUTH_SH redis-cli DBSIZE" 2>/dev/null)" || return 0
  out="${out//[!0-9]/}"
  printf '%s' "$out"
}

# JSON snapshot for the migration gate: version, account states, Bayes
# learned counts, Redis key count. No addresses, no secrets.
sf_aio_snapshot() {
  local layout=$1 url=${2:-$SF_URL} api bayes db
  api="$(curl -fsS --max-time 5 "$url/api/health" 2>/dev/null)" || api='{}'
  jq -e 'type == "object"' <<<"$api" >/dev/null 2>&1 || api='{}'
  bayes="$(sf_bayes_counts "$layout" | jq -Rnc '[inputs | select(length > 0) | split(" ")
            | {(.[0]): (.[1] | tonumber)}] | add // {}')"
  db="$(sf_redis_dbsize "$layout")"
  jq -nc --argjson api "$api" --argjson bayes "$bayes" --arg db "$db" \
    '{version: ($api.version // null), accounts: ($api.accounts // {}), bayes: $bayes,
      dbsize: ($db | tonumber? // null)}'
}

# Problems of AFTER compared with BEFORE (one per line; none = pass):
# version must be VERSION; accounts that were idle/working must be
# idle/working again, paused ones still paused. Bayes: the total learned
# count must not be lower and no statfile may lose more than
# SF_BAYES_TOLERANCE (5) - a user moving a mail out of Spamfilter during the
# gate re-learns it (spam -1, ham +1); an empty or wrong Bayes store fails.
# Redis keys: at most 1 % (min. 10) fewer - short-lived rspamd keys may
# expire, a store that was not loaded has (almost) none.
sf_aio_compare() {
  jq -rn --argjson b "$1" --argjson a "$2" --arg v "$VERSION" --argjson tol "${SF_BAYES_TOLERANCE:-5}" '
    def st: if type == "object" then (.state // "unknown") else (. // "unknown") end | tostring;
    def good: . == "idle" or . == "working";
    def resting: . == "paused" or . == "stopped";
    (if ($a.version // "") != $v then "version \($a.version // "unknown") (want \($v))" else empty end),
    ($b.accounts // {} | to_entries[] | select(.key != "*") | .key as $n | (.value | st) as $was
      | (($a.accounts // {})[$n] | st) as $now
      | if ($was | good) and ($now | good | not) then "account \($n): \($now) (was \($was))"
        elif ($was | resting) and ($now | resting | not) then "account \($n): \($now) (was \($was))"
        else empty end),
    ($b.bayes // {} | to_entries[] | .key as $k | .value as $was | (($a.bayes // {})[$k]) as $now
      | if $now == null then "Bayes \($k): not readable (was \($was) learned)"
        elif $now < $was - $tol then "Bayes \($k): \($now) learned (was \($was))" else empty end),
    (($b.bayes // {} | [.[]] | add // 0) as $tb | ($a.bayes // {} | [.[]] | add // 0) as $ta
      | if ($b.bayes // {}) != {} and $ta < $tb then "Bayes total: \($ta) learned (was \($tb))" else empty end),
    (if $b.dbsize != null and ($a.dbsize == null
          or $a.dbsize < $b.dbsize - ([10, ($b.dbsize / 100 | floor)] | max))
       then "Redis keys: \($a.dbsize // "unknown") (was \($b.dbsize))" else empty end)'
}

# Home Assistant endpoint: with SF_HA_TOKEN 200, without a token 404 (the
# endpoint hides itself). The token goes in on stdin, never argv/log.
# With a token the request is made INSIDE the container (127.0.0.1): a
# request from the Unraid host arrives from 192.168.1.10, the trusted proxy
# (cloudflared), and is therefore - correctly - treated as external (404).
sf_aio_ha_ok() {
  local url=$SF_URL code
  if [[ -n "${SF_HA_TOKEN:-}" ]]; then
    code="$(printf '%s\n' "$SF_HA_TOKEN" | docker exec -i "${SF_AIO_NAME:-spamfilter}" python3 -s -c '
import sys, urllib.error, urllib.request
req = urllib.request.Request("http://127.0.0.1:8080/api/v1/ha",
                             headers={"Authorization": "Bearer " + sys.stdin.readline().strip()})
try:
    print(urllib.request.urlopen(req, timeout=5).status)
except urllib.error.HTTPError as ex:
    print(ex.code)
except Exception:
    print("000")
' 2>/dev/null)" || code=000
    [[ "$code" == 200 ]] && return 0
    warn "Home Assistant endpoint with token: HTTP $code (want 200)"
    return 1
  fi
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$url/api/v1/ha" 2>/dev/null)" || code=000
  [[ "$code" == 404 ]] && return 0
  warn "Home Assistant endpoint without token: HTTP $code (want 404)"
  return 1
}

# ---------------------------------------------------------------- gates
# AIO gate: running without restarts for SF_GATE_MIN_UPTIME s, Docker health
# healthy, all four parts ok (sf-health check inside), heartbeat newer than
# the start, /healthz 200 and the engine logged "loaded N account(s)".
# sf_gate_aio NAME [URL] [APP]
sf_gate_aio() {
  local name=$1 url=${2:-${SF_AIO_HTTP_URL:-$SF_URL}} app=${3:-$APP}
  local deadline line running restarts started health start_epoch uptime hb parts
  local parts_ok http_ok hb_ok log_ok logs
  deadline=$(( $(date +%s) + SF_AIO_GATE_TIMEOUT ))
  while :; do
    line="$(sf_inspect "$name" '[.State.Running, .RestartCount, .State.StartedAt, (.State.Health.Status // "none")] | @tsv')" ||
      { warn "$name disappeared"; return 1; }
    IFS=$'\t' read -r running restarts started health <<<"$line"
    if [[ "$running" != true || "$restarts" != 0 ]]; then
      warn "$name is not running steadily (running=$running, restarts=$restarts)"
      return 1
    fi
    if [[ "$health" == unhealthy ]]; then
      warn "$name reports unhealthy: $(docker exec "$name" /usr/local/bin/sf-health check 2>/dev/null | head -n 1 || true)"
      return 1
    fi
    start_epoch="$(sf_epoch "$started")"
    uptime=$(( $(date +%s) - start_epoch ))
    parts_ok=0 http_ok=0 hb_ok=0 log_ok=0
    parts="$(docker exec "$name" /usr/local/bin/sf-health check --json 2>/dev/null | tail -n 1 || true)"
    if jq -e '.ok == true' <<<"$parts" >/dev/null 2>&1; then
      parts_ok=1
    fi
    hb="$(awk 'NR == 1 {print $1}' "$app/state/heartbeat" 2>/dev/null || true)"
    hb="${hb%%.*}"
    if [[ "$hb" =~ ^[0-9]+$ ]] && (( hb >= start_epoch - 2 )); then
      hb_ok=1
    fi
    if curl -fsS -o /dev/null --max-time 5 "$url/healthz" 2>/dev/null; then
      http_ok=1
    fi
    logs="$(docker logs "$name" 2>&1 || true)"
    if grep -Eq 'loaded [0-9]+ account\(s\)' <<<"$logs"; then
      log_ok=1
    fi
    if (( uptime >= SF_GATE_MIN_UPTIME && parts_ok && hb_ok && http_ok && log_ok )) && [[ "$health" == healthy ]]; then
      log "  $name: up ${uptime}s, healthy, filter/rspamd/redis/unbound ok, fresh heartbeat, /healthz 200, accounts loaded"
      return 0
    fi
    if (( $(date +%s) >= deadline )); then
      warn "$name gate failed after ${SF_AIO_GATE_TIMEOUT}s: health=$health parts=$(jq -c '.parts // {} | map_values(.ok)' <<<"${parts:-{\}}" 2>/dev/null || echo '?') heartbeat=$hb_ok healthz=$http_ok accounts_logged=$log_ok uptime=${uptime}s"
      return 1
    fi
    sleep "$SF_POLL"
  done
}

# A STARTED (not recreated) 4-container member is healthy again: running,
# no new restarts since the start, Docker health healthy; the filter also
# needs a fresh heartbeat and /healthz 200. sf_wait_started NAME
sf_wait_started() {
  local name=$1 deadline line running restarts started health base start_epoch hb
  base="$(sf_inspect "$name" '.RestartCount')" || base=0
  deadline=$(( $(date +%s) + SF_GATE_TIMEOUT ))
  while :; do
    line="$(sf_inspect "$name" '[.State.Running, .RestartCount, .State.StartedAt, (.State.Health.Status // "none")] | @tsv')" ||
      { warn "$name disappeared"; return 1; }
    IFS=$'\t' read -r running restarts started health <<<"$line"
    if [[ "$running" != true || "$restarts" != "$base" ]]; then
      warn "$name is not running steadily (running=$running, restarts=$restarts)"
      return 1
    fi
    [[ "$health" == unhealthy ]] && { warn "$name reports unhealthy"; return 1; }
    if [[ "$health" == healthy || "$health" == none ]]; then
      if [[ "$name" != spamfilter ]]; then
        log "  $name: healthy"
        return 0
      fi
      start_epoch="$(sf_epoch "$started")"
      hb="$(awk 'NR == 1 {print $1}' "$APP/state/heartbeat" 2>/dev/null || true)"
      hb="${hb%%.*}"
      if [[ "$hb" =~ ^[0-9]+$ ]] && (( hb >= start_epoch - 2 )) &&
         curl -fsS -o /dev/null --max-time 5 "$SF_URL/healthz" 2>/dev/null; then
        log "  $name: healthy, fresh heartbeat, /healthz 200"
        return 0
      fi
    fi
    if (( $(date +%s) >= deadline )); then
      warn "$name not healthy after ${SF_GATE_TIMEOUT}s (health=$health)"
      return 1
    fi
    sleep "$SF_POLL"
  done
}

# ---------------------------------------------------------------- rollback
# True when one of the four 4-container members is stopped or has restart
# policy "no" (what migrate.sh sets) - only meaningful on the legacy layout.
sf_aio_legacy_needs_repair() {
  local name line
  for name in "${SF_ALL[@]}"; do
    line="$(sf_inspect "$name" '[.State.Running, (.HostConfig.RestartPolicy.Name // "")] | @tsv')" || continue
    [[ "$line" == $'true\tunless-stopped' || "$line" == $'true\talways' ]] || return 0
  done
  return 1
}

# Back to the four containers. Idempotent: works from any point of a failed
# migration and any time later while the stopped containers exist.
#   sf_aio_rollback remove|keep
#     remove: the AIO container is deleted (it just failed its gate)
#     keep:   it is stopped and renamed spamfilter-aio-rolledback
# The AIO is always stopped BEFORE the old Redis starts: two Redis servers
# on one data dir would corrupt it.
sf_aio_rollback() {
  local what=${1:-remove} name logf failed=0 moved=0
  warn "ROLLBACK to the four containers (spamfilter-redis, -unbound, -rspamd, spamfilter)"
  if [[ "$(sf_layout_of "$SF_AIO_NAME")" == aio ]]; then
    moved=1
    logf="$APP/operations/failed-aio-$SF_STAMP.log"
    if [[ "$DRY_RUN" != 1 ]]; then
      docker logs --tail 300 "$SF_AIO_NAME" >"$logf" 2>&1 || true
      chmod 600 "$logf" 2>/dev/null || true
      warn "logs of the all-in-one container saved to $logf"
    fi
    qrun docker stop -t 90 "$SF_AIO_NAME" || true
    if [[ "$what" == keep ]]; then
      if sf_exists "$SF_AIO_ROLLEDBACK"; then
        qrun docker rm -f "$SF_AIO_ROLLEDBACK"
      fi
      run docker rename "$SF_AIO_NAME" "$SF_AIO_ROLLEDBACK"
      qrun docker update --restart no "$SF_AIO_ROLLEDBACK"
    else
      qrun docker rm -f "$SF_AIO_NAME"
    fi
  fi
  if [[ "$DRY_RUN" != 1 ]]; then
    for name in "$SF_AIO_NAME" "$SF_AIO_ROLLEDBACK" spamfilter-rollback; do
      if [[ "$(sf_layout_of "$name")" == aio && "$(sf_inspect "$name" '.State.Running')" == true ]]; then
        die "$name (all-in-one) is still running - stop it before the old Redis may start: docker stop -t 90 $name"
      fi
    done
  fi
  if sf_exists "$SF_AIO_LEGACY"; then
    # (under --dry-run the AIO above was only planned away)
    if sf_exists "$SF_AIO_NAME" && ! [[ "$DRY_RUN" == 1 && "$moved" == 1 ]]; then
      die "both $SF_AIO_NAME and $SF_AIO_LEGACY exist - remove the wrong one by hand"
    fi
    run docker rename "$SF_AIO_LEGACY" "$SF_AIO_NAME"
  fi
  local present=()
  for name in "${SF_AIO_INFRA[@]}" spamfilter; do
    sf_exists "$name" || { warn "$name does not exist - cannot restore it"; failed=1; continue; }
    qrun docker update --restart unless-stopped "$name"
    present+=("$name")
  done
  sf_autostart_restore_legacy "${present[@]}"
  sf_aio_restore_template
  for name in "${SF_AIO_INFRA[@]}" spamfilter; do
    sf_exists "$name" || continue
    log "Starting $name"
    qrun docker start "$name" || { warn "could not start $name"; failed=1; continue; }
    [[ "$DRY_RUN" == 1 ]] && continue
    sf_wait_started "$name" || failed=1
  done
  if (( failed )); then
    warn "rollback finished WITH PROBLEMS - check: docker ps -a --filter name=spamfilter"
    return 1
  fi
  log "Rollback done: the four containers run again"
  return 0
}

# ---------------------------------------------------------------- images
# Remove local images of the AIO repository older than the previous AIO
# version (sf_prune_filter_images handles the classes; see lib.sh).
sf_aio_prune_images() {
  sf_prune_filter_images
}

# ---------------------------------------------------------------- preflight
sf_check_free() {
  local avail
  avail="$(df -Pm "$1" 2>/dev/null | awk 'NR == 2 {print $4}')" || avail=""
  if [[ ! "$avail" =~ ^[0-9]+$ ]]; then
    warn "cannot read the free space of $1"
    return 0
  fi
  (( avail >= SF_MIN_FREE_MB )) || die "only ${avail} MiB free on $1 (need ${SF_MIN_FREE_MB} MiB)"
  log "  $1: ${avail} MiB free"
}

# ---------------------------------------------------------------- logging
# Mirror everything this script prints into operations/aio-NAME-<stamp>.log
# (0600). Nothing printed by these scripts contains a secret.
# tee ignores INT/TERM/HUP: Ctrl-C or a dropped SSH session signals the
# whole foreground process group, and a dead tee would kill the script with
# SIGPIPE in the middle of its EXIT-trap rollback. (A hung-up terminal only
# makes tee's terminal writes fail; it keeps writing the log file.)
SF_AIO_TEE_PID="" SF_AIO_LOG_FILE=""
sf_aio_tee_log() {
  local f="$APP/operations/aio-$1-$SF_STAMP.log"
  [[ "$DRY_RUN" == 1 ]] && return 0
  [[ -d "$APP/operations" ]] || return 0
  : >>"$f"
  chmod 600 "$f"
  SF_AIO_LOG_FILE=$f
  # The tee runs in its own session: Ctrl-C / a dropped SSH session signals the whole process
  # group, and bash 5.3 (Unraid 7) lets that kill a tee that only ignores the signals - the
  # next log line of the EXIT-trap rollback then died with EPIPE. setsid keeps it out of reach;
  # it still ends on EOF when the script exits.
  exec > >(trap '' INT TERM HUP; exec setsid tee -a "$f") 2>&1
  SF_AIO_TEE_PID=$!
  log "log: $f"
}

# First thing in every EXIT/rollback handler: never die of SIGPIPE, and if
# the tee is gone anyway (killed with -9), write straight into the log file
# so the rollback still runs to the end.
sf_aio_log_rescue() {
  trap '' PIPE
  if [[ -n "$SF_AIO_TEE_PID" && -n "$SF_AIO_LOG_FILE" ]] && ! kill -0 "$SF_AIO_TEE_PID" 2>/dev/null; then
    exec >>"$SF_AIO_LOG_FILE" 2>&1
    SF_AIO_TEE_PID=""
  fi
  return 0
}

# A COPY of redis.conf (smoke test) that must load dump.rdb: with
# 'appendonly yes' Redis reads ONLY the AOF at startup and ignores
# dump.rdb, so a restored dump.rdb without its appendonlydir starts EMPTY.
# Redis still writes dump.rdb on shutdown (save lines). Never the live file.
sf_redis_conf_rdb_only() {
  local f=$1 sed_expr='s/^([[:space:]]*)appendonly[[:space:]]+"?[Yy][Ee][Ss]"?[[:space:]]*$/\1appendonly no/'
  if [[ "$DRY_RUN" == 1 ]]; then
    run sed -i -E "$sed_expr" "$f"
    return 0
  fi
  [[ "$(realpath -m "$f")" != "$(realpath -m "$APP/redis-config/redis.conf")" ]] ||
    die "refusing to change the live $f"
  sed -i -E "$sed_expr" "$f"
  if grep -Eq '^[[:space:]]*appendonly[[:space:]]+"?[Yy][Ee][Ss]' "$f"; then
    die "$f still has appendonly yes - the copy would start with an empty Redis"
  fi
  log "  copy of redis.conf: appendonly no (loads the restored dump.rdb)"
}

# ---------------------------------------------------------------- build context
# A minimal build context: runtime code only - never tests, never the
# rendered rspamd redis.conf / worker-controller.inc (secrets).
# sf_aio_stage_context DIR
sf_aio_stage_context() {
  local ctx=$1 f base
  mkdir -p "$ctx/filter/static" "$ctx/aio/share/rspamd/maps.d"
  cp "$SF_AIO_DIR/Dockerfile" "$ctx/Dockerfile"
  for f in "$SF_SRC"/filter/*.py; do
    base="${f##*/}"
    case "$base" in test_*.py|*_test.py) continue ;; esac
    cp "$f" "$ctx/filter/$base"
  done
  cp -R "$SF_SRC/filter/static/." "$ctx/filter/static/"
  find "$ctx/filter/static" -name __pycache__ -prune -exec rm -rf {} +
  cp "$SF_SRC/filter/favicon.png" "$SF_SRC/filter/familieguide.pdf" "$SF_SRC/filter/requirements.txt" "$ctx/filter/"
  for f in supervisord.conf sf-entrypoint sf-run sf-fatal-listener sf-health sf-clamav sf-sigs sfctl-aio \
           aio_render.py build-check.sh; do
    cp "$SF_AIO_DIR/$f" "$ctx/aio/$f"
  done
  mkdir -p "$ctx/aio/clamav"
  cp "$SF_AIO_DIR/clamav/clamd.conf" "$SF_AIO_DIR/clamav/freshclam.conf" "$SF_AIO_DIR/clamav/sanesecurity.gpg" \
    "$ctx/aio/clamav/"
  printf '%s\n' "$VERSION" >"$ctx/aio/share/VERSION"
  cp "$SF_SRC/deploy/unbound.conf" "$ctx/aio/share/unbound.conf"
  cp "$SF_AIO_DIR/accounts.seed.yml" "$ctx/aio/share/accounts.seed.yml"
  cp "$SF_AIO_DIR/site.seed.yml" "$ctx/aio/share/site.seed.yml"
  cp "$SF_SRC/redis/redis.conf.template" "$ctx/aio/share/redis.conf.template"
  for f in "${SF_RSPAMD_FILES[@]}" fuzzy_check.conf fuzzy_check.conf.readonly \
           redis.conf.template worker-controller.inc.template; do
    cp "$SF_SRC/rspamd/local.d/$f" "$ctx/aio/share/rspamd/$f"
  done
  while IFS= read -r f; do
    cp "$SF_SRC/rspamd/local.d/maps.d/$f" "$ctx/aio/share/rspamd/maps.d/$f"
  done < <(sf_rspamd_maps)
  find "$ctx" -type d -exec chmod 0755 {} +
  find "$ctx" -type f -exec chmod 0644 {} +
  chmod 0755 "$ctx/aio/sf-entrypoint" "$ctx/aio/sf-run" "$ctx/aio/sf-fatal-listener" \
    "$ctx/aio/sf-health" "$ctx/aio/sf-clamav" "$ctx/aio/sf-sigs" "$ctx/aio/sfctl-aio" "$ctx/aio/build-check.sh"
}

# The Redis image the AIO build copies redis-server/redis-cli from.
sf_aio_redis_ref() {
  if [[ -n "${REDIS_AIO_DIGEST:-}" ]]; then
    printf 'redis:%s@%s' "$REDIS_AIO_TAG" "$REDIS_AIO_DIGEST"
  else
    printf 'redis:%s' "$REDIS_AIO_TAG"
  fi
}

# KEY=VALUE build args (also written to the staged context for CI).
sf_aio_build_args() {
  printf '%s\n' \
    "FILTER_BASE_IMAGE=$FILTER_BASE_IMAGE" \
    "RSPAMD_IMAGE=$RSPAMD_IMAGE" \
    "REDIS_IMAGE=${1:-$(sf_aio_redis_ref)}" \
    "AIO_VERSION=$VERSION" \
    "EXPECT_RSPAMD=$AIO_RSPAMD_VERSION" \
    "EXPECT_REDIS=$AIO_REDIS_VERSION" \
    "EXPECT_UNBOUND=$AIO_UNBOUND_SERIES" \
    "EXPECT_PYTHON=$AIO_PYTHON_SERIES" \
    "EXPECT_CLAMAV_MIN=$AIO_CLAMAV_MIN"
}

# ---------------------------------------------------------------- migration
# Transaction state for the EXIT-trap rollback of sf_aio_migrate.
SF_MIG_PHASE=0
sf_aio_migrate_on_exit() {
  local rc=$?
  sf_aio_log_rescue
  if (( SF_MIG_PHASE > 0 )); then
    SF_MIG_PHASE=0
    warn "migration FAILED - rolling back to the four containers"
    sf_aio_rollback remove || true
  fi
  return "$rc"
}

# sf_aio_migrate IMAGE SKIP_BAYES(0|1): the body of deploy/aio/migrate.sh
# (see there). Dies on failure; the EXIT trap rolls back once the four
# containers have been touched.
sf_aio_migrate() {
  local image=$1 skip_bayes=${2:-0} layout name ver before after problems deadline ha_ok
  trap sf_aio_migrate_on_exit EXIT
  trap 'exit 130' INT TERM HUP

  # ---------------------------------------------------------------- 1. preflight
  log "Preflight"
  layout="$(sf_layout)"
  [[ "$layout" == legacy ]] || die "spamfilter is not the 4-container filter (layout: $layout) - nothing to migrate"
  for name in "${SF_AIO_INFRA[@]}"; do
    sf_exists "$name" || die "$name is missing - the 4-container layout is incomplete"
  done
  if sf_exists "$SF_AIO_LEGACY"; then
    die "$SF_AIO_LEGACY already exists (an earlier migration?) - use deploy/aio/rollback.sh or cleanup.sh first"
  fi
  if sf_exists "$SF_AIO_TEST"; then
    die "the smoke-test container $SF_AIO_TEST still exists - remove it: docker rm -f $SF_AIO_TEST"
  fi
  docker image inspect "$image" >/dev/null 2>&1 || die "image $image not found - build it first: deploy/aio/build.sh"
  [[ "$(sf_image_layout "$image")" == aio ]] || die "$image is not an all-in-one image (no $SF_LAYOUT_LABEL=aio)"
  ver="$(docker image inspect "$image" | jq -r ".[0] | $SF_VERSION_JQ")"
  [[ "$ver" == "$VERSION" ]] || die "$image is version '${ver:-?}', this source tree is $VERSION"
  [[ -d "$APP/rspamd/data" ]] || die "$APP/rspamd/data missing"
  sf_check_free "$APP"
  sf_check_free "$SF_DOCKER_ROOT"
  sf_check_accounts_config
  sf_backup

  # ---------------------------------------------------------------- 2. snapshot
  log "Snapshot of the running four containers"
  before="$(sf_aio_snapshot legacy)"
  log "  version $(jq -r '.version // "?"' <<<"$before"), accounts $(jq -c '.accounts' <<<"$before"), Bayes $(jq -c '.bayes' <<<"$before"), Redis keys $(jq -r '.dbsize // "?"' <<<"$before")"
  if (( ! skip_bayes )) && [[ "$DRY_RUN" != 1 ]] && jq -e '.bayes == {} or .dbsize == null' <<<"$before" >/dev/null; then
    die "cannot read the Bayes statistics / Redis key count from the running containers - are spamfilter-rspamd and spamfilter-redis healthy? (--skip-bayes-check migrates without that comparison)"
  fi
  if (( skip_bayes )); then
    warn "--skip-bayes-check: Bayes counts and Redis keys are not compared"
    before="$(jq -c '.bayes = {} | .dbsize = null' <<<"$before")"
  fi
  if [[ "$DRY_RUN" != 1 ]]; then
    printf '%s\n' "$before" >"$APP/operations/aio-migrate-$SF_STAMP.before.json"
    chmod 600 "$APP/operations/aio-migrate-$SF_STAMP.before.json"
  fi

  # ---------------------------------------------------------------- 3. stop the four
  SF_MIG_PHASE=1
  sf_autostart_backup
  for name in spamfilter spamfilter-rspamd spamfilter-unbound spamfilter-redis; do
    log "Stopping $name (kept, restart policy no)"
    qrun docker stop -t 60 "$name"
    qrun docker update --restart no "$name"
    # 'spamfilter' stays in the autostart list: the AIO takes over the name.
    [[ "$name" == spamfilter ]] || sf_autostart_remove "$name"
  done
  run docker rename spamfilter "$SF_AIO_LEGACY"

  # ---------------------------------------------------------------- 4. start the AIO
  sf_aio_install_template "$image"
  run rm -f "$APP/state/heartbeat"
  sf_aio_prepare_backup
  sf_aio_run_args spamfilter "$image"
  log "Starting the all-in-one container spamfilter ($image)"
  qrun docker run -d "${SF_OPTS[@]}" "${SF_IMAGE_CMD[@]}"
  sf_autostart_add spamfilter
  if [[ "$DRY_RUN" == 1 ]]; then
    log "[dry-run] gate: sf_gate_aio + version/accounts/Bayes/Redis keys/Home Assistant; on failure: rollback to the four containers"
    SF_MIG_PHASE=0
    return 0
  fi

  # ---------------------------------------------------------------- 5. gate
  sf_gate_aio spamfilter || die "the all-in-one container failed its health gate"
  deadline=$(( $(date +%s) + SF_AIO_GATE_TIMEOUT ))
  while :; do
    after="$(sf_aio_snapshot aio)"
    problems="$(sf_aio_compare "$before" "$after")"
    ha_ok=0
    if [[ -z "$problems" ]] && sf_aio_ha_ok; then
      ha_ok=1
      break
    fi
    if (( $(date +%s) >= deadline )); then
      [[ -n "$problems" ]] && printf '%s\n' "$problems" | while IFS= read -r p; do warn "gate: $p"; done
      (( ha_ok )) || warn "gate: Home Assistant endpoint check failed"
      die "the all-in-one container did not match the four containers within ${SF_AIO_GATE_TIMEOUT}s"
    fi
    sleep "$SF_POLL"
  done
  SF_MIG_PHASE=0
  printf '%s\n' "$after" >"$APP/operations/aio-migrate-$SF_STAMP.after.json"
  chmod 600 "$APP/operations/aio-migrate-$SF_STAMP.after.json"
  log "After: version $(jq -r '.version' <<<"$after"), accounts $(jq -c '.accounts' <<<"$after"), Bayes $(jq -c '.bayes' <<<"$after"), Redis keys $(jq -r '.dbsize // "?"' <<<"$after")"
  sf_summary
  log "Migration done: one container 'spamfilter'. The four old containers are kept STOPPED"
  log "(spamfilter-legacy, spamfilter-rspamd, -redis, -unbound) for deploy/aio/rollback.sh."
  warn "NEVER start spamfilter-redis/-rspamd/-unbound/-legacy by hand (Docker tab, 'Start all'): they share the Redis data dir with the running all-in-one container. The 2.4 monitor alerts and kills an old Redis it finds running."
  log "The 2.4 User Scripts (deploy/install-user-scripts.sh, before the migration) handle this layout."
  log "After a few good days: deploy/aio/cleanup.sh --dry-run, then deploy/aio/cleanup.sh --yes"
}

# Remove one image, never forced (Docker refuses while a container uses it).
sf_aio_rm_image() {
  docker image inspect "$1" >/dev/null 2>&1 || return 0
  log "Removing image $1"
  if [[ "$DRY_RUN" == 1 ]]; then
    run docker image rm "$1"
  else
    docker image rm "$1" >/dev/null || warn "could not remove $1 (still in use?)"
  fi
}

# ---------------------------------------------------------------- cleanup
SF_AIO_OLD_CONTAINERS=("$SF_AIO_LEGACY" spamfilter-rspamd spamfilter-redis spamfilter-unbound
                       "$SF_AIO_ROLLEDBACK" spamfilter-rollback "$SF_AIO_TEST")

# The body of deploy/aio/cleanup.sh (see there; the script asks for --yes).
sf_aio_cleanup() {
  local health name attached repo ref
  # Only when the all-in-one container is live AND healthy.
  sf_require_aio_layout
  health="$(sf_inspect spamfilter '[.State.Running, (.State.Health.Status // "none")] | @tsv')" || health=""
  [[ "$health" == $'true\thealthy' ]] ||
    die "spamfilter (all-in-one) is not running and healthy ($health) - nothing is removed while it is not"

  # ---------------------------------------------------------------- containers
  for name in "${SF_AIO_OLD_CONTAINERS[@]}"; do
    sf_exists "$name" || continue
    if [[ "$(sf_inspect "$name" '.State.Running')" != false ]]; then
      warn "$name is running - left alone"
      continue
    fi
    log "Removing the stopped container $name"
    qrun docker rm "$name"
    sf_autostart_remove "$name"
  done

  # ---------------------------------------------------------------- network
  # Only when no container at all (also no stopped one) is attached.
  if docker network inspect "$SF_NETWORK" >/dev/null 2>&1; then
    # (--dry-run: the old containers above count as removed already)
    attached="$(docker ps -a --filter "network=$SF_NETWORK" --format '{{.Names}}' 2>/dev/null |
      { if [[ "$DRY_RUN" == 1 ]]; then grep -vxF -f <(printf '%s\n' "${SF_AIO_OLD_CONTAINERS[@]}"); else cat; fi; } |
      grep -c . || true)"
    if [[ "$attached" == 0 ]]; then
      log "Removing the network $SF_NETWORK"
      qrun docker network rm "$SF_NETWORK" || warn "could not remove $SF_NETWORK"
    else
      warn "network $SF_NETWORK is still used by $attached container(s) - left alone"
    fi
  fi

  # ---------------------------------------------------------------- images
  sf_aio_rm_image "$REDIS_IMAGE"
  sf_aio_rm_image "$UNBOUND_IMAGE"
  repo="${FILTER_IMAGE%:*}"
  while IFS= read -r ref; do
    [[ -n "$ref" && "$ref" != *:"<none>" ]] || continue
    if [[ "$(sf_image_layout "$ref")" != aio ]]; then
      sf_aio_rm_image "$ref"
    fi
  done < <(docker image ls --format '{{.Repository}}:{{.Tag}}' "$repo" 2>/dev/null || true)
  sf_prune_filter_images
}
