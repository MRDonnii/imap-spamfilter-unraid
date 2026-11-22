#!/bin/bash
# Off-site copy of the ENCRYPTED nightly backups (2.6, B3) - host side.
#
#   backup-offsite.sh [--dry-run]
#
# Runs on the Unraid host as the User Script "Spamfilter-offsite" (45 3 * * *,
# installed inline by deploy/install-user-scripts.sh) - after the container's
# own nightly backup (from 02:30) and backup-and-verify.sh (03:00):
#   1. finds the host dir of the container's /backup mount (docker inspect;
#      fallback SF_BACKUP_HOST_DIR, default /mnt/user/backup/spamfilter)
#   2. no encrypted archive younger than 26 h there -> asks the container
#      for one first: docker exec spamfilter sfctl backup-now --if-older 20
#   3. rclone copy of ONLY the encrypted archives (spamfilter-*.sfbak whose
#      first bytes are the SFBACKUP magic, changed within 72 h; never a
#      .part file, never the unencrypted operations/backups/*.tar.gz) to
#      SF_OFFSITE_REMOTE (env or operations/site.env; default
#      offsite:Backup/Spamfilter) - always through the rclone remote, never a
#      FUSE mount (/mnt/disks/<remote>_rclone),
#      so a hung mount cannot fill RAM; bounded by timeouts
#   4. rclone delete of remote archives older than SF_OFFSITE_KEEP_DAYS (60:
#      a bit longer than the local 14 daily + 8 weekly), our names only
#   5. state/offsite-status.json {ok, ts, remote, files, uploaded, error,
#      skipped} (0644; Drift -> Krypteret backup and sfctl doctor show it).
#      A failure -> Unraid notification + an alert mail through the
#      filter's mailer (when it runs). Never a key or password in output.
#   6. 2.12 (#11) restore drill, every SF_RESTORE_DRILL_DAYS (30; 0 = off)
#      and the day after a failed one: the NEWEST archive on the remote is
#      downloaded (rclone copyto) into a temp dir inside the backup dir
#      (/backup/.restore-drill.XXXXXX in the container), checked by the
#      container with `sfctl backup-verify` (decrypts to nowhere, checks
#      every sha256, writes nothing) and the temp dir is removed again.
#      Result: state/restore-drill.json {ok, ts, archive, detail, error}
#      (0644; Drift -> Krypteret backup and host-monitor show it); a failed
#      drill notifies, the copy itself still counts as done.
# SF_OFFSITE_REMOTE="" turns the upload off (status: skipped).
#
# Self-contained on purpose (inlined into the User Script).
# Env: SPAMFILTER_APP, SF_OFFSITE_REMOTE, SF_OFFSITE_KEEP_DAYS (60),
#      SF_BACKUP_HOST_DIR, SF_RCLONE_BIN (/usr/sbin/rclone), SF_RCLONE_CONFIG
#      (default: the Unraid rclone plugin's /boot/config/plugins/rclone/.rclone.conf
#      when it exists, else rclone's own default), SF_OFFSITE_TIMEOUT (3600 s),
#      SF_NOTIFY_BIN, SF_OFFSITE_LOCK, SF_RESTORE_DRILL_DAYS (30).
set -Eeuo pipefail
umask 077

DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    -h|--help) sed -n '2,41p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

APP="${SPAMFILTER_APP:-$(d="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." 2>/dev/null && pwd)"
  if [[ -n "$d" && -d "$d/state" && -d "$d/config" ]]; then echo "$d"; else echo /mnt/user/appdata/spamfilter; fi)}"
STATE="$APP/state"
STATUS="$STATE/offsite-status.json"
DRILL_STATUS="$STATE/restore-drill.json"
DRILL_DAYS="${SF_RESTORE_DRILL_DAYS:-30}"
DRILL_TMP=""
# The rclone target: SF_OFFSITE_REMOTE (env), else the value in
# operations/site.env, else offsite:Backup/Spamfilter (an rclone remote you
# name "offsite"). Empty = off-site copy switched off.
if [[ -z "${SF_OFFSITE_REMOTE+x}" && -f "$APP/operations/site.env" ]] &&
   grep -q '^SF_OFFSITE_REMOTE=' "$APP/operations/site.env" 2>/dev/null; then
  SF_OFFSITE_REMOTE="$(sed -n 's/^SF_OFFSITE_REMOTE=//p' "$APP/operations/site.env" | tail -n 1 | tr -d "\"' ")"
fi
REMOTE="${SF_OFFSITE_REMOTE-offsite:Backup/Spamfilter}"
KEEP_DAYS="${SF_OFFSITE_KEEP_DAYS:-60}"
RCLONE="${SF_RCLONE_BIN:-/usr/sbin/rclone}"
RCLONE_CONFIG_FILE="${SF_RCLONE_CONFIG:-}"
if [[ -z "$RCLONE_CONFIG_FILE" && -f /boot/config/plugins/rclone/.rclone.conf ]]; then
  RCLONE_CONFIG_FILE=/boot/config/plugins/rclone/.rclone.conf
fi
TIMEOUT="${SF_OFFSITE_TIMEOUT:-3600}"
NOTIFY="${SF_NOTIFY_BIN:-/usr/local/emhttp/webGui/scripts/notify}"
LOCK="${SF_OFFSITE_LOCK:-/tmp/spamfilter-offsite.lock}"
FRESH_MIN=$((26 * 60))
UPLOAD_MIN=$((72 * 60))
STEP="start"
LIST=""

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

json_str() {
  local s=$1
  s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/ }; s=${s//$'\r'/ }; s=${s//$'\t'/ }
  printf '"%s"' "$s"
}

# write_status OK FILES UPLOADED ERROR SKIPPED - atomic, 0644 (the filter reads it).
# state/ is writable by the filter's uid, so root never writes through a
# predictable name there: the temp file comes from mktemp (O_EXCL, never
# follows a planted link) in the root-only operations/ dir (same file
# system; state/ only as a fallback), and mv -T renames it over the target
# (a rename replaces a link instead of following it, and never moves into a
# directory). A symlink at the target is refused. Returns 1 when nothing
# was written.
write_status() {
  local ok=$1 files=$2 uploaded=$3 err=$4 skipped=$5 tmp tmpdir="$APP/operations"
  [[ "$DRY_RUN" == 1 ]] && return 0
  [[ -d "$STATE" ]] || return 0
  if [[ -L "$STATUS" ]]; then
    echo "WARNING: $STATUS is a symlink - status not written" >&2
    return 1
  fi
  [[ -d "$tmpdir" && ! -L "$tmpdir" ]] || tmpdir="$STATE"
  tmp="$(mktemp "$tmpdir/.offsite-status.json.XXXXXX")" || return 1
  if ! { chmod 0644 "$tmp" &&
         printf '{"ok": %s, "ts": %s, "remote": %s, "files": %s, "uploaded": %s, "error": %s, "skipped": %s}\n' \
           "$ok" "$(date +%s)" "$(json_str "$REMOTE")" "${files:-null}" "${uploaded:-null}" \
           "$( [[ -n "$err" ]] && json_str "$err" || echo null)" \
           "$( [[ -n "$skipped" ]] && json_str "$skipped" || echo null)" >"$tmp" &&
         mv -fT "$tmp" "$STATUS"; }; then
    rm -f "$tmp"
    return 1
  fi
}

notify() {
  if [[ -x "$NOTIFY" ]]; then
    "$NOTIFY" -e Spamfilter -s "$1" -d "$2" -i alert >/dev/null 2>&1 || true
  fi
  # The filter's mailer decides the recipients; nothing when it is down.
  if [[ "$(docker container inspect -f '{{.State.Running}}' spamfilter 2>/dev/null || true)" == true ]]; then
    timeout 60 docker exec -u 10099:10099 spamfilter python3 /app/mailer.py notify \
      --kind alert --subject "$1" --text "$2" >/dev/null 2>&1 || true
  fi
}

# Only the step goes into the status/notification - never a command line.
fail() {
  local why=$1
  echo "Off-site copy FAILED: $why" >&2
  if [[ "$DRY_RUN" != 1 ]]; then
    write_status false "" "" "$why" "" || true
    notify "Spamfilter: kopi ud af huset fejlede" \
      "Den krypterede backup kunne ikke kopieres til $REMOTE: $why. Den lokale backup på arrayet er urørt."
  fi
  exit 1
}
on_error() {
  local rc=$?
  trap - ERR
  fail "fejl under: $STEP (exit $rc)"
}
trap on_error ERR
trap '[[ -n "$LIST" ]] && rm -f "$LIST"; [[ -n "$DRILL_TMP" ]] && rm -rf "$DRILL_TMP"; true' EXIT

rclone_cmd() { # rclone with the config, timeouts and quiet stats
  local args=(--timeout 5m --contimeout 60s --retries 3 --low-level-retries 10 --stats 0)
  [[ -n "$RCLONE_CONFIG_FILE" ]] && args+=(--config "$RCLONE_CONFIG_FILE")
  timeout "$TIMEOUT" "$RCLONE" "$@" "${args[@]}"
}

# write_drill OK ARCHIVE DETAIL ERROR - restore-drill.json, written like
# write_status (mktemp in operations/, mv -fT, a planted link is refused).
write_drill() {
  local ok=$1 archive=$2 detail=$3 err=$4 tmp tmpdir="$APP/operations"
  [[ -d "$STATE" ]] || return 0
  if [[ -L "$DRILL_STATUS" ]]; then
    echo "WARNING: $DRILL_STATUS is a symlink - drill status not written" >&2
    return 1
  fi
  [[ -d "$tmpdir" && ! -L "$tmpdir" ]] || tmpdir="$STATE"
  tmp="$(mktemp "$tmpdir/.restore-drill.json.XXXXXX")" || return 1
  if ! { chmod 0644 "$tmp" &&
         printf '{"ok": %s, "ts": %s, "archive": %s, "detail": %s, "error": %s, "every_days": %s}\n' \
           "$ok" "$(date +%s)" "$( [[ -n "$archive" ]] && json_str "$archive" || echo null)" \
           "$( [[ -n "$detail" ]] && json_str "$detail" || echo null)" \
           "$( [[ -n "$err" ]] && json_str "$err" || echo null)" "$DRILL_DAYS" >"$tmp" &&
         mv -fT "$tmp" "$DRILL_STATUS"; }; then
    rm -f "$tmp"
    return 1
  fi
}

# drill_due: no drill yet, the last one failed, or it is DRILL_DAYS old.
drill_due() {
  [[ "$DRILL_DAYS" =~ ^[0-9]+$ ]] && (( DRILL_DAYS > 0 )) || return 1
  [[ -f "$DRILL_STATUS" && ! -L "$DRILL_STATUS" ]] || return 0
  grep -q '"ok": true' "$DRILL_STATUS" || return 0
  [[ -z "$(find "$DRILL_STATUS" -mmin "-$((DRILL_DAYS * 1440))" 2>/dev/null)" ]]
}

drill_fail() {
  local archive=$1 why=$2
  log "restore drill FAILED: $why"
  write_drill false "$archive" "" "$why" || true
  notify "Spamfilter: gendannelsesøvelsen fejlede" \
    "Den nyeste krypterede backup på $REMOTE${archive:+ ($archive)} kunne ikke gendannes til prøve: $why. Selve kopien ud af huset er lavet; øvelsen prøves igen i morgen."
  return 0
}

# restore_drill - never fails the off-site job: every step is guarded.
restore_drill() {
  local name out first
  name="$(rclone_cmd lsf "$REMOTE" --include 'spamfilter-*.sfbak' --files-only 2>/dev/null | sort | tail -n 1)" || name=""
  [[ "$name" =~ ^spamfilter-[A-Za-z0-9._-]{1,80}\.sfbak$ ]] || { drill_fail "" "ingen krypteret backup fundet på $REMOTE"; return 0; }
  DRILL_TMP="$(mktemp -d "$DIR/.restore-drill.XXXXXX")" || { drill_fail "$name" "midlertidig mappe kunne ikke laves"; return 0; }
  if ! rclone_cmd copyto "$REMOTE/$name" "$DRILL_TMP/$name"; then
    drill_fail "$name" "hentning fra $REMOTE fejlede"; return 0
  fi
  if [[ ! -f "$DRILL_TMP/$name" || -L "$DRILL_TMP/$name" || "$(head -c 8 "$DRILL_TMP/$name" 2>/dev/null)" != SFBACKUP ]]; then
    drill_fail "$name" "den hentede fil er ikke en krypteret backup"; return 0
  fi
  # The container (uid 10099) must be able to read it; root may hand it over.
  chown -R 10099:10099 "$DRILL_TMP" 2>/dev/null || true
  if out="$(timeout 1800 docker exec -u 10099:10099 spamfilter sfctl backup-verify \
              "/backup/$(basename "$DRILL_TMP")/$name" 2>&1)"; then
    first="$(grep -m1 '^OK: ' <<<"$out" || true)"
    if [[ -n "$first" ]]; then
      write_drill true "$name" "${first:0:240}" "" || true
      log "restore drill ok: $name"
    else
      drill_fail "$name" "sfctl backup-verify gav intet OK"
    fi
  else
    first="$(grep -m1 -v '^[[:space:]]*$' <<<"$out" || true)"
    drill_fail "$name" "sfctl backup-verify fejlede${first:+: ${first:0:160}}"
  fi
  rm -rf "$DRILL_TMP"
  DRILL_TMP=""
  return 0
}

if [[ -z "$REMOTE" ]]; then
  log "SF_OFFSITE_REMOTE is empty - off-site copy is off"
  write_status true "" "" "" "SF_OFFSITE_REMOTE er tom"
  exit 0
fi
case "$REMOTE" in
  /*|*..*) fail "SF_OFFSITE_REMOTE skal være et rclone-mål (fx offsite:Backup/Spamfilter), ikke en sti" ;;
  *:*) ;;
  *) fail "SF_OFFSITE_REMOTE skal være et rclone-mål (fx offsite:Backup/Spamfilter)" ;;
esac
if [[ ! "$KEEP_DAYS" =~ ^[0-9]+$ ]] || (( KEEP_DAYS < 14 )); then
  fail "SF_OFFSITE_KEEP_DAYS skal være mindst 14"
fi

STEP="preflight"
for c in docker flock timeout find head; do
  command -v "$c" >/dev/null || fail "kommandoen $c mangler"
done
[[ -x "$RCLONE" ]] || fail "rclone findes ikke ($RCLONE)"
[[ -d "$STATE" ]] || fail "$APP er ikke en spamfilter-app-mappe"
exec 8>"$LOCK"
flock -n 8 || fail "en anden kopiering kører allerede"

STEP="backup dir"
DIR="$(docker container inspect -f '{{range .Mounts}}{{if eq .Destination "/backup"}}{{.Source}}{{end}}{{end}}' spamfilter 2>/dev/null || true)"
[[ "$DIR" == /* && "$DIR" != *$'\n'* ]] || DIR=""
DIR="${DIR:-${SF_BACKUP_HOST_DIR:-/mnt/user/backup/spamfilter}}"
[[ -d "$DIR" ]] || fail "backup-mappen $DIR findes ikke (er /backup monteret i containeren?)"
log "backup dir: $DIR -> $REMOTE"

newest() { find "$DIR" -maxdepth 1 -type f -name 'spamfilter-*.sfbak' -mmin "-$FRESH_MIN" | sort | tail -n 1; }

STEP="fresh backup"
if [[ -z "$(newest)" ]]; then
  if [[ "$DRY_RUN" == 1 ]]; then
    log "[dry-run] no archive younger than 26 h - would run: docker exec spamfilter sfctl backup-now --if-older 20"
  else
    log "no archive younger than 26 h - asking the container for one"
    timeout 1800 docker exec -u 10099:10099 spamfilter sfctl backup-now --if-older 20 >/dev/null 2>&1 ||
      fail "containeren kunne ikke lave en ny krypteret backup (sfctl backup-now)"
    [[ -n "$(newest)" ]] || fail "der er ingen krypteret backup fra det seneste døgn"
  fi
fi

STEP="file list"
# Only our encrypted archives: the name AND the format magic must match.
LIST="$(mktemp)"
files=0
while IFS= read -r f; do
  if [[ -L "$f" || "$(head -c 8 "$f" 2>/dev/null)" != SFBACKUP ]]; then
    log "WARNING: $(basename "$f") is not an encrypted archive - never uploaded"
    continue
  fi
  basename "$f" >>"$LIST"
  files=$((files + 1))
done < <(find "$DIR" -maxdepth 1 -type f -name 'spamfilter-*.sfbak' -mmin "-$UPLOAD_MIN" | sort)
(( files > 0 )) || [[ "$DRY_RUN" == 1 ]] || fail "ingen krypterede backups fra de seneste 72 timer at kopiere"

STEP="rclone copy"
if [[ "$DRY_RUN" == 1 ]]; then
  log "[dry-run] would copy $files encrypted archive(s) to $REMOTE:"
  sed 's/^/[dry-run]   /' "$LIST"
  log "[dry-run] would delete remote spamfilter-*.sfbak older than $KEEP_DAYS days"
  if drill_due; then log "[dry-run] restore drill due - would fetch the newest remote archive and run sfctl backup-verify"; fi
  exit 0
fi
# --immutable: an archive is never rewritten; a changed file of the same
# name is an error, not an overwrite.
rclone_cmd copy "$DIR" "$REMOTE" --files-from "$LIST" --no-traverse --immutable ||
  fail "rclone copy til $REMOTE fejlede (exit $?)"

STEP="rclone prune"
rclone_cmd delete "$REMOTE" --min-age "${KEEP_DAYS}d" --include 'spamfilter-*.sfbak' ||
  fail "oprydning på $REMOTE fejlede (exit $?)"

STEP="status"
remote_n="$(rclone_cmd lsf "$REMOTE" --include 'spamfilter-*.sfbak' --files-only 2>/dev/null | grep -c . || true)"
write_status true "${remote_n:-null}" "$files" "" ""
log "off-site copy done: $files archive(s) checked/copied, ${remote_n:-?} on $REMOTE"

STEP="restore drill"
if drill_due; then
  log "restore drill: fetching the newest remote archive"
  restore_drill
fi
