#!/bin/bash
# Consistent spamfilter backup + isolated restore test.
#
#   backup-and-verify.sh [--dry-run]
#
# Archive: operations/backups/spamfilter-<UTC stamp>.tar.gz (0600) with
# the SQLite DB (online backup API), a fresh Redis RDB snapshot (BGSAVE),
# config/, the state secrets (dashboard_users, dashboard_secret,
# controller.password, redis.password and - 2.3 - contacts.key and
# smtp.password, - 2.5.0 - vapid_private.pem, each 0600 in the archive),
# admin-audit.jsonl,
# imap-secrets/, removed-secrets/, rspamd/local.d, redis.conf and
# unbound.conf. The archive is then unpacked into a scratch dir and checked
# with throwaway --network none containers (SQLite integrity_check,
# redis-check-rdb) using the image ids of the RUNNING containers, so the
# check always matches what is deployed; the secrets are checked there too
# (sha256, mode 0600, owner, contacts.key = 32 bytes).
# 2.4: works with both layouts. The all-in-one container (image label
# spamfilter.layout=aio) holds filter and Redis in one container 'spamfilter';
# there the snapshot runs as the owning uid (docker exec -u 10099 / -u 999)
# because root in that container has no CAP_DAC_OVERRIDE, and the verify
# containers use the AIO image (it has python and redis-check-rdb).
# Archives older than 14 days are pruned only after a successful run.
# Result: state/backup-status.json {"ok","ts","archive","size","error"}.
# Any failure -> Unraid notification (alert) + ok=false status.
#
# Self-contained on purpose: it is also installed inline as the User
# Script "Spamfilter-backup" (deploy/install-user-scripts.sh).
# Env: SPAMFILTER_APP, SF_BACKUP_KEEP_DAYS (14), SF_NOTIFY_BIN.
set -Eeuo pipefail
umask 077

DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    -h|--help) sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

APP="${SPAMFILTER_APP:-$(d="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." 2>/dev/null && pwd)"
  if [[ -n "$d" && -d "$d/state" && -d "$d/config" ]]; then echo "$d"; else echo /mnt/user/appdata/spamfilter; fi)}"
STATE="$APP/state"
DEST="$APP/operations/backups"
KEEP_DAYS="${SF_BACKUP_KEEP_DAYS:-14}"
NOTIFY="${SF_NOTIFY_BIN:-/usr/local/emhttp/webGui/scripts/notify}"
LOCK="${SF_BACKUP_LOCK:-/tmp/spamfilter-backup.lock}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARCHIVE="$DEST/spamfilter-$STAMP.tar.gz"
STATUS="$STATE/backup-status.json"
STEP="start"
TMP="" VERIFY="" SQLITE_TMP=""

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

# JSON string escaping without jq (jq is present on Unraid, but the status
# must still be written when the failure IS a missing tool).
json_str() {
  local s=$1
  s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/ }; s=${s//$'\r'/ }; s=${s//$'\t'/ }
  printf '"%s"' "$s"
}

# write_status OK(true|false) ARCHIVE SIZE ERROR - atomic, 0644 so the
# filter (uid 10099) can show it on the Drift page. state/ is writable by
# that uid, so root never writes through a predictable name there: the temp
# file comes from mktemp (O_EXCL, never follows a planted link) in the
# root-only operations/ dir (same file system; state/ only as a fallback),
# and mv -T renames it over the target (a rename replaces a link instead of
# following it, and never moves into a directory). A symlink at the target
# is refused. Returns 1 when nothing was written.
write_status() {
  local ok=$1 archive=$2 size=$3 err=$4 tmp tmpdir="$APP/operations"
  [[ -d "$STATE" ]] || return 0
  if [[ -L "$STATUS" ]]; then
    echo "WARNING: $STATUS is a symlink - status not written" >&2
    return 1
  fi
  [[ -d "$tmpdir" && ! -L "$tmpdir" ]] || tmpdir="$STATE"
  tmp="$(mktemp "$tmpdir/.backup-status.json.XXXXXX")" || return 1
  if ! { chmod 0644 "$tmp" &&
         printf '{"ok": %s, "ts": %s, "archive": %s, "size": %s, "error": %s}\n' \
           "$ok" "$(date +%s)" \
           "$( [[ -n "$archive" ]] && json_str "$archive" || echo null)" \
           "${size:-null}" \
           "$( [[ -n "$err" ]] && json_str "$err" || echo null)" >"$tmp" &&
         mv -fT "$tmp" "$STATUS"; }; then
    rm -f "$tmp"
    return 1
  fi
}

notify() {
  local subject=$1 desc=$2 level=$3
  if [[ -x "$NOTIFY" ]]; then
    "$NOTIFY" -e Spamfilter -s "$subject" -d "$desc" -i "$level" >/dev/null 2>&1 || true
  fi
}

cleanup() {
  [[ -n "$TMP" ]] && rm -rf "$TMP"
  [[ -n "$VERIFY" ]] && rm -rf "$VERIFY"
  [[ -n "$SQLITE_TMP" ]] && rm -f "$SQLITE_TMP"
  return 0
}

# Only the step name goes into status/notification - never command lines
# (they could contain paths of secret files; never their content anyway).
on_error() {
  local rc=$?
  trap - ERR
  echo "Backup FAILED during: $STEP (exit $rc)" >&2
  if [[ "$DRY_RUN" != 1 ]]; then
    rm -f "$ARCHIVE"
    write_status false "" "" "backup failed during: $STEP" || true
    notify "Spamfilter: backup fejlede" "Backup af spamfilteret fejlede under: $STEP. Tidligere backups er urørte. Se $APP/operations/backups." alert
  fi
  exit "$rc"
}
trap on_error ERR
trap cleanup EXIT

if [[ "$DRY_RUN" == 1 ]]; then
  log "[dry-run] would back up $APP to $ARCHIVE, verify it in throwaway containers,"
  log "[dry-run] prune archives older than $KEEP_DAYS days and write $STATUS"
  exit 0
fi

STEP="preflight"
[[ "$(id -u)" == 0 ]] || { echo "run as root" >&2; false; }
for c in docker flock tar sha256sum; do
  command -v "$c" >/dev/null || { echo "missing command: $c" >&2; false; }
done
[[ -d "$STATE" && -d "$APP/config" ]] || { echo "$APP is not a spamfilter app dir" >&2; false; }
exec 8>"$LOCK"
flock -n 8 || { echo "another backup is running" >&2; false; }
mkdir -p "$DEST"
chmod 700 "$DEST"

STEP="image ids"
# The verify containers use exactly the images that are deployed.
LAYOUT=legacy
if docker container inspect -f '{{range $k, $v := .Config.Labels}}{{$k}}={{$v}} {{end}}' spamfilter 2>/dev/null | grep -Eq '(^| )[a-z0-9-]+[.]layout=aio( |$)'; then
  LAYOUT=aio
fi
FILTER_IMAGE_ID="$(docker container inspect -f '{{.Image}}' spamfilter)"
filter_running="$(docker container inspect -f '{{.State.Running}}' spamfilter)"
if [[ "$LAYOUT" == aio ]]; then
  REDIS_IMAGE_ID="$FILTER_IMAGE_ID"
  FILTER_EXEC=(docker exec -u 10099:10099 spamfilter)
  REDIS_EXEC=(docker exec -u 999:1000 spamfilter)
  STATE_MOUNT=/appdata/state   # /state is a link to it in the AIO image
else
  REDIS_IMAGE_ID="$(docker container inspect -f '{{.Image}}' spamfilter-redis)"
  FILTER_EXEC=(docker exec spamfilter)
  REDIS_EXEC=(docker exec spamfilter-redis)
  STATE_MOUNT=/state
fi
log "layout: $LAYOUT"

TMP="$(mktemp -d "$APP/operations/.backup-$STAMP-XXXXXX")"
mkdir -p "$TMP"/{config,state,redis,rspamd,meta}

STEP="sqlite backup"
# SQLite's online backup API gives a consistent copy while the filter
# writes WAL records. Written by the filter's own uid into /state, copied
# root-only into the staging dir, then removed.
SQLITE_TMP="$STATE/.backup-$STAMP.db"
# shellcheck disable=SC2016 # python source, not shell
pycode='
import sqlite3, sys
src = sqlite3.connect("/state/spamfilter.db", timeout=30)
dst = sqlite3.connect(sys.argv[1])
src.backup(dst)
dst.close(); src.close()
'
if [[ "$filter_running" == true ]]; then
  "${FILTER_EXEC[@]}" python -c "$pycode" "/state/.backup-$STAMP.db" >/dev/null
else
  # Filter stopped (e.g. during a deploy): same code in a throwaway
  # container of the same image, as the owner of state/.
  docker run --rm --network none --user "$(stat -c %u:%g "$STATE")" --entrypoint python \
    -v "$STATE:$STATE_MOUNT" "$FILTER_IMAGE_ID" -c "$pycode" "/state/.backup-$STAMP.db" >/dev/null
fi
# Written by the filter's uid in state/: never follow a link planted there.
[[ -f "$SQLITE_TMP" && ! -L "$SQLITE_TMP" ]] || { echo "the SQLite copy is not a regular file" >&2; false; }
cp "$SQLITE_TMP" "$TMP/state/spamfilter.db"
rm -f "$SQLITE_TMP"
SQLITE_TMP=""

STEP="redis snapshot"
# RDB is a point-in-time snapshot; never copy a live appendonlydir. The
# password is read inside the container and never leaves it.
# shellcheck disable=SC2016 # expands inside the container
"${REDIS_EXEC[@]}" sh -c '
REDISCLI_AUTH=$(grep "^requirepass " /usr/local/etc/redis/redis.conf | cut -d "\"" -f2)
export REDISCLI_AUTH
before=$(redis-cli LASTSAVE)
redis-cli BGSAVE >/dev/null
for n in $(seq 1 120); do
  if redis-cli INFO persistence | grep -q "^rdb_bgsave_in_progress:0" &&
     [ "$(redis-cli LASTSAVE)" != "$before" ]; then
    break
  fi
  sleep 1
done
redis-cli INFO persistence | grep -q "^rdb_last_bgsave_status:ok"
' >/dev/null
test -s "$APP/redis/dump.rdb"
cp "$APP/redis/dump.rdb" "$TMP/redis/dump.rdb"

STEP="copy config and secrets"
cp -a "$APP/config/." "$TMP/config/"
# Secret files, 0600 in the archive. 2.3: contacts.key is the HMAC key of
# the known-contacts hashes (without it every contact is re-learned from
# Sent and removed contacts come back); smtp.password exists only with
# separate SMTP credentials. 2.5.0: vapid_private.pem is the push key
# (without it every phone must turn notifications on again); it exists
# only after the first device subscribed. Listed in meta/secrets for the
# restore test.
SECRET_FILES=(dashboard_users dashboard_secret controller.password redis.password contacts.key smtp.password
              vapid_private.pem)
: >"$TMP/meta/secrets"
for file in "${SECRET_FILES[@]}"; do
  if [[ -L "$STATE/$file" ]]; then
    # Never follow a link planted in state/ (the filter never makes one).
    log "WARNING: $file is a symlink - not archived"
  elif [[ -f "$STATE/$file" ]]; then
    cp -p "$STATE/$file" "$TMP/state/$file"
    chmod 0600 "$TMP/state/$file"
    printf '%s\n' "$file" >>"$TMP/meta/secrets"
  fi
done
for file in admin-audit.jsonl boot_id; do
  if [[ -f "$STATE/$file" ]]; then
    cp -p "$STATE/$file" "$TMP/state/$file"
  fi
done
for dir in imap-secrets removed-secrets; do
  if [[ -d "$STATE/$dir" ]]; then
    cp -a "$STATE/$dir" "$TMP/state/"
  fi
done
cp -a "$APP/rspamd/local.d" "$TMP/rspamd/"
cp -p "$APP/redis-config/redis.conf" "$TMP/redis/redis.conf"
for file in unbound.conf unbound-forward-records.conf; do
  if [[ -f "$APP/$file" ]]; then
    cp -p "$APP/$file" "$TMP/$file"
  fi
done
if [[ -f "$APP/source/deploy/versions.env" ]]; then
  cp -p "$APP/source/deploy/versions.env" "$TMP/meta/versions.env"
fi
printf '%s\n' "$LAYOUT" >"$TMP/meta/layout"
printf '%s\n' "$FILTER_IMAGE_ID" >"$TMP/meta/filter-image-id"
printf '%s\n' "$REDIS_IMAGE_ID" >"$TMP/meta/redis-image-id"
(cd "$TMP" && sha256sum state/spamfilter.db redis/dump.rdb) >"$TMP/meta/data-sha256"
: >"$TMP/meta/secrets-sha256"
while IFS= read -r file; do
  (cd "$TMP" && sha256sum "state/$file") >>"$TMP/meta/secrets-sha256"
done <"$TMP/meta/secrets"

STEP="write archive"
tar -C "$TMP" -czf "$ARCHIVE.part" .
chmod 600 "$ARCHIVE.part"
mv -f "$ARCHIVE.part" "$ARCHIVE"

STEP="restore test"
# Restore into an isolated directory - never the live state or live Redis.
VERIFY="$(mktemp -d "$APP/operations/.verify-$STAMP-XXXXXX")"
tar -xzf "$ARCHIVE" -C "$VERIFY"
(cd "$VERIFY" && sha256sum -c --quiet meta/data-sha256)
test -s "$VERIFY/config/accounts.yml"
# The local site configuration (own domains, webshops ...) must be in the
# backup whenever the live install has one.
if [[ -f "$APP/config/site.yml" ]]; then
  test -s "$VERIFY/config/site.yml"
fi
docker run --rm --network none --user 0:0 --entrypoint python \
  -v "$VERIFY/state/spamfilter.db:/verify/spamfilter.db:ro" \
  "$FILTER_IMAGE_ID" -c '
import sqlite3
db = sqlite3.connect("file:/verify/spamfilter.db?mode=ro&immutable=1", uri=True)
assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
db.execute("SELECT count(*) FROM messages").fetchone()
' >/dev/null
docker run --rm --network none --entrypoint redis-check-rdb \
  -v "$VERIFY/redis/dump.rdb:/verify/dump.rdb:ro" \
  "$REDIS_IMAGE_ID" /verify/dump.rdb >/dev/null

STEP="restore test: secrets"
# Every secret that was archived comes back intact, 0600 and owned like the
# live file (uid 10099 on the host); contacts.key is exactly 32 bytes.
# Only names and checks are reported - never file content.
if [[ -s "$VERIFY/meta/secrets" ]]; then
  (cd "$VERIFY" && sha256sum -c --quiet meta/secrets-sha256)
fi
while IFS= read -r file; do
  restored="$VERIFY/state/$file"
  [[ -f "$restored" && ! -L "$restored" && -s "$restored" ]] || { echo "secret missing after restore: $file" >&2; false; }
  [[ "$(stat -c %a "$restored")" == 600 ]] || { echo "secret not 0600 after restore: $file" >&2; false; }
  if [[ -f "$STATE/$file" ]]; then
    [[ "$(stat -c %u "$restored")" == "$(stat -c %u "$STATE/$file")" ]] ||
      { echo "secret owner changed after restore: $file" >&2; false; }
  fi
  if [[ "$file" == contacts.key ]]; then
    [[ "$(stat -c %s "$restored")" == 32 ]] || { echo "contacts.key has the wrong size after restore" >&2; false; }
  fi
done <"$VERIFY/meta/secrets"
for file in contacts.key smtp.password vapid_private.pem; do
  if [[ -f "$STATE/$file" && ! -L "$STATE/$file" ]] && ! grep -qxF "$file" "$VERIFY/meta/secrets"; then
    echo "secret not in the archive: $file" >&2
    false
  fi
done

STEP="prune"
find "$DEST" -maxdepth 1 -type f -name 'spamfilter-*.tar.gz' -mtime "+$KEEP_DAYS" -print -delete |
  while IFS= read -r old; do log "pruned $old"; done
find "$DEST" -maxdepth 1 -type f -name 'spamfilter-*.tar.gz.part' -mmin +60 -delete

STEP="status"
size="$(stat -c %s "$ARCHIVE")"
# The archive is made and verified: a status that cannot be written is
# reported, but never removes the archive (on_error would).
if ! write_status true "$ARCHIVE" "$size" ""; then
  notify "Spamfilter: backup-status kunne ikke skrives" "Backuppen $ARCHIVE er lavet og testet, men $STATUS kunne ikke skrives." alert
  exit 1
fi
log "Backup and isolated restore verification passed: $ARCHIVE ($size bytes)"
