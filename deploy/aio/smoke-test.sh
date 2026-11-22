#!/bin/bash
# Throwaway test of the all-in-one image BEFORE the migration - on a COPY,
# never on the live app dir, and never against a real mailbox.
#
#   smoke-test.sh [--dry-run] [--image IMAGE] [--backup ARCHIVE] [--fresh]
#                 [--port 18090] [--learn-test] [--clamav-scan] [--keep]
#
# 1. A copy of the app dir is restored from the newest (or given) backup
#    archive into operations/aio-test/<stamp>/appdata (owners as live:
#    10099 state/config, 999:1000 redis, 11333 rspamd). --fresh instead
#    starts from an EMPTY app dir (the container initialises it; CI).
#    The copy's redis.conf gets 'appendonly no' (the archive holds only
#    dump.rdb: with AOF on and no appendonlydir Redis would start EMPTY).
# 2. The copy is made harmless before anything starts. It cannot log in by
#    construction, wherever its secrets lived: every account (and defaults)
#    gets enabled: false, mode shadow, no inline password, password_file
#    /nonexistent/smoke-test and imap_host 127.0.0.1 port 1; queued or
#    running undo / training / learn-list jobs of the snapshot are
#    cancelled; the IMAP passwords, the SMTP password, removed secrets and
#    the mail outbox are deleted and the mail server settings are switched
#    off (no mail can leave); 2.5.0: the push devices, the push queue and
#    the VAPID key are deleted too (no phone gets a push from the copy). The sanitiser fails the run if any account
#    could still log in.
# 3. Container spamfilter-aio-test (restart no, no Unraid labels) on
#    127.0.0.1:PORT -> 8080 with the copy as /appdata; every IMAP host of
#    the original accounts.yml is also mapped to 127.0.0.1 (--add-host).
# 4. Checks: the gate (Docker healthy, filter/rspamd/redis/unbound ok,
#    heartbeat, /healthz, "loaded 0 account(s)"), Bayes statistics visible
#    through rspamd (learned counts and Redis keys of the copy; compared with
#    the live containers when they answer), the WebUI login page answers
#    200, only port 8080 listens outside loopback, sfctl doctor runs.
#    --learn-test (CI): scan a test mail, learn it as spam, restart the
#    container and check that the learned count survived.
#    2.7 ClamAV: its status is logged (sf-health clamav) but never fails the
#    run by itself - the first signature download takes minutes. With
#    SF_CLAMAV=0 (CI: no ~300 MB download) it must report off and rspamd's
#    runtime antivirus.conf must be 'enabled = false'. --clamav-scan
#    (optional, needs ClamAV on and the download): wait for clamd (at most
#    SF_CLAMAV_WAIT s, 900) and check that an EICAR test attachment scanned
#    through rspamd gets CLAM_VIRUS.
# 5. The test container and the copy are removed (--keep keeps both).
# Log: operations/aio-smoke-<stamp>.log.
set -euo pipefail

usage() { sed -n '2,41p' "$0" | sed 's/^# \{0,1\}//'; }

image="" archive="" fresh=0 port=18090 learn=0 keep=0 clamscan=0
while (( $# )); do
  case "$1" in
    --dry-run) export DRY_RUN=1 ;;
    --image) image="${2:?--image needs a value}"; shift ;;
    --backup) archive="${2:?--backup needs an archive}"; shift ;;
    --fresh) fresh=1 ;;
    --port) port="${2:?--port needs a value}"; shift ;;
    --learn-test) learn=1 ;;
    --clamav-scan) clamscan=1 ;;
    --keep) keep=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done
[[ "$port" =~ ^[0-9]+$ && "$port" != 18080 ]] || { echo "--port must be a number other than 18080" >&2; exit 2; }

# shellcheck source=deploy/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

image="${image:-$AIO_IMAGE}"
name="$SF_AIO_TEST"
imap_hosts=()
url="http://127.0.0.1:$port"
root="$APP/operations/aio-test/$SF_STAMP"
test_app="$root/appdata"
[[ "$DRY_RUN" == 1 ]] || sf_require_root
sf_require_cmds docker jq curl flock tar awk
sf_require_app
sf_lock
sf_aio_tee_log smoke
log "smoke test: $image on $url with a $([[ $fresh == 1 ]] && echo 'fresh' || echo 'backup copy of the') app dir$([[ "$DRY_RUN" == 1 ]] && echo ' [DRY RUN]')"

if [[ "$DRY_RUN" != 1 ]]; then
  docker image inspect "$image" >/dev/null 2>&1 || die "image $image not found - build it first: deploy/aio/build.sh"
  [[ "$(sf_image_layout "$image")" == aio ]] || die "$image is not an all-in-one image"
fi
if sf_exists "$name"; then
  [[ "$(sf_layout_of "$name")" == aio ]] || die "$name exists and is not an all-in-one test container - left alone"
  log "Removing a leftover $name"
  qrun docker rm -f "$name"
fi
if (( ! fresh )); then
  if [[ -z "$archive" ]]; then
    archive="$(find "$APP/operations/backups" -maxdepth 1 -type f -name 'spamfilter-*.tar.gz' -printf '%T@ %p\n' 2>/dev/null |
      sort -n | tail -n 1 | cut -d' ' -f2- || true)"
  fi
  [[ -n "$archive" && -f "$archive" ]] || die "no backup archive found - run deploy/backup-and-verify.sh first (or --backup FILE)"
  log "Backup: $archive"
fi

cleanup() {
  local rc=$?
  sf_aio_log_rescue
  if (( keep )); then
    log "--keep: container $name and $root are kept (remove: docker rm -f $name; rm -rf $root)"
  elif [[ "$DRY_RUN" != 1 ]]; then
    docker rm -f "$name" >/dev/null 2>&1 || true
    [[ -n "$root" && "$root" == "$APP/operations/aio-test/"* ]] && rm -rf "$root"
    log "Removed the test container and the copy"
  fi
  return "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

# ---------------------------------------------------------------- 1. the copy
run mkdir -p "$test_app/operations"
if (( fresh )); then
  log "Fresh app dir: the container initialises it on its first start"
else
  extract="$root/extract"
  run mkdir -p "$extract"
  run tar -xzf "$archive" -C "$extract"
  run mkdir -p "$test_app/state" "$test_app/config" "$test_app/redis" "$test_app/redis-config" \
    "$test_app/rspamd/local.d" "$test_app/rspamd/data"
  run cp -a "$extract/state/." "$test_app/state/"
  run cp -a "$extract/config/." "$test_app/config/"
  run cp -a "$extract/rspamd/local.d/." "$test_app/rspamd/local.d/"
  run cp -p "$extract/redis/dump.rdb" "$test_app/redis/dump.rdb"
  run cp -p "$extract/redis/redis.conf" "$test_app/redis-config/redis.conf"
  # The archive has dump.rdb only (never a live appendonlydir). With
  # 'appendonly yes' Redis reads ONLY the AOF and would start empty, so the
  # COPY loads the RDB (the live redis.conf is never touched). Redis still
  # saves dump.rdb on shutdown (save lines), so --learn-test survives a restart.
  sf_redis_conf_rdb_only "$test_app/redis-config/redis.conf"
  for f in unbound.conf unbound-forward-records.conf; do
    if [[ -f "$extract/$f" ]]; then run cp -p "$extract/$f" "$test_app/$f"; fi
  done
  # 2.7: the live ClamAV signatures (not in the backup; ~300 MB) spare the
  # copy the first download. Without them the copy downloads its own.
  if [[ -d "$APP/clamav" && ! -L "$APP/clamav" ]]; then
    run cp -a "$APP/clamav" "$test_app/clamav"
  fi
  run rm -rf "$extract"

  # ---------------------------------------------------------------- 2. harmless
  log "Making the copy harmless: no account can log in, pending IMAP jobs cancelled, IMAP/SMTP secrets and outbox removed, mail off, no push devices"
  run rm -rf "$test_app/state/removed-secrets"
  if [[ "$DRY_RUN" == 1 || -d "$test_app/state/imap-secrets" ]]; then
    run find "$test_app/state/imap-secrets" -mindepth 1 -delete
  fi
  run rm -f "$test_app/state/smtp.password" "$test_app/state/vapid_private.pem"
  run chown -R "$FILTER_UID:$FILTER_GID" "$test_app/state" "$test_app/config"
  run chmod 0700 "$test_app/state" "$test_app/config"
  run chown -R 999:1000 "$test_app/redis" "$test_app/redis-config"
  run chown -R 11333:11333 "$test_app/rspamd"
  # The image's own Python edits the copy, offline, as the filter uid.
  # shellcheck disable=SC2016 # python source
  sanitize='
import re, sqlite3, sys, yaml
NOLOGIN = {"imap_host": "127.0.0.1", "imap_port": 1, "password_file": "/nonexistent/smoke-test"}
cfg = yaml.safe_load(open("/c/accounts.yml")) or {}
hosts = set()
defaults = cfg.get("defaults")
if isinstance(defaults, dict):
    if defaults.get("imap_host"):
        hosts.add(str(defaults["imap_host"]))
    defaults.pop("password", None)
    defaults.update(NOLOGIN)
accounts = cfg.get("accounts") or []
for acc in accounts:
    if acc.get("imap_host"):
        hosts.add(str(acc["imap_host"]))
    acc.pop("password", None)
    acc.update(NOLOGIN)
    acc["enabled"] = False
    acc["mode"] = "shadow"
with open("/c/accounts.yml", "w") as fh:
    yaml.safe_dump(cfg, fh, sort_keys=False, allow_unicode=True)
db = sqlite3.connect("/s/spamfilter.db")
active = ("cancelled", "queued", "running", "cancel_requested")
for sql, args in (("DELETE FROM settings_kv WHERE key IN (?, ?, ?)", ("smtp", "smtp_state", "mail_notify")),
                  ("DELETE FROM mail_outbox", ()),
                  ("DELETE FROM push_subscriptions", ()),
                  ("DELETE FROM push_queue", ()),
                  ("UPDATE undo_jobs SET status = ? WHERE status IN (?, ?, ?)", active),
                  ("UPDATE train_jobs SET status = ? WHERE status IN (?, ?, ?)", active),
                  ("UPDATE learn_list_jobs SET status = ? WHERE status IN (?, ?, ?)", active)):
    try:
        db.execute(sql, args)
    except sqlite3.Error:
        pass
db.commit()
enabled = sum(1 for a in accounts if a.get("enabled"))
can_login = sum(1 for a in accounts if any(a.get(k) != v for k, v in NOLOGIN.items()) or a.get("password"))
print(f"accounts after sanitising: {len(accounts)}, enabled: {enabled}, able to log in: {can_login}")
print("imap-hosts: " + " ".join(sorted(h for h in hosts if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", h))))
sys.exit(1 if enabled or can_login else 0)
'
  san=(docker run --rm --network none --user "$FILTER_UID:$FILTER_GID" --entrypoint /usr/local/bin/python3
       -v "$test_app/state:/s" -v "$test_app/config:/c" "$image" -c "$sanitize")
  if [[ "$DRY_RUN" == 1 ]]; then
    run "${san[@]}"
  else
    san_out="$("${san[@]}" 2>&1)" || {
      printf '%s\n' "$san_out" | grep -E '^(accounts|Traceback|[A-Za-z]+Error)' | cut -c1-200 >&2 || true
      die "sanitising the copy failed - nothing was started"
    }
    log "  $(grep -m 1 '^accounts after' <<<"$san_out" || echo 'sanitised')"
    read -r -a imap_hosts <<<"$(sed -n 's/^imap-hosts: //p' <<<"$san_out")"
  fi
fi

# ---------------------------------------------------------------- 3. start
sf_aio_run_args "$name" "$image" "$test_app" 127.0.0.1 "$port" test
# Belt and braces: the original IMAP servers resolve to the container itself.
sf_aio_block_hosts "${imap_hosts[@]}"
log "Starting $name"
qrun docker run -d "${SF_OPTS[@]}" "${SF_IMAGE_CMD[@]}"
if [[ "$DRY_RUN" == 1 ]]; then
  log "[dry-run] gate on $url; Bayes, login page, listeners, sfctl doctor; then remove $name and $root"
  exit 0
fi

# ---------------------------------------------------------------- 4. checks
failed=0
check() { if "$@"; then return 0; fi; failed=1; return 0; }
sf_gate_aio "$name" "$url" "$test_app" || die "$name failed its gate (logs: docker logs $name - kept until this script exits)"

bayes="$(sf_bayes_counts aio "$name")"
dbsize="$(sf_redis_dbsize aio "$name")"
log "Bayes in the copy: $(tr '\n' ' ' <<<"${bayes:-none}")| Redis keys: ${dbsize:-?}"
if (( ! fresh )); then
  live_layout="$(sf_layout)"
  if [[ "$live_layout" != none ]]; then
    live="$(sf_bayes_counts "$live_layout")"
    log "Bayes live now:    $(tr '\n' ' ' <<<"${live:-not readable}")(the backup can be a few hours older)"
  fi
  if [[ -z "$bayes" || ! "$dbsize" =~ ^[1-9][0-9]*$ ]]; then
    warn "the copy shows no Bayes statistics / Redis keys - the restored dump.rdb was not loaded"
    failed=1
  fi
fi

code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$url/login" 2>/dev/null)" || code=000
if [[ "$code" == 200 ]]; then log "  WebUI login page: 200"; else warn "WebUI login page: HTTP $code"; failed=1; fi
if out="$(docker exec "$name" /usr/local/bin/sf-health listeners 2>&1)"; then
  log "  $out"
else
  warn "$out"
  failed=1
fi
# 2.7 ClamAV (optional part: reported, a missing clamd alone never fails here)
clamav_on=1
case "${SF_CLAMAV:-1}" in 0|false|no|off) clamav_on=0 ;; esac
av="$(docker exec "$name" /usr/local/bin/sf-health clamav 2>&1 | head -n 1 || true)"
log "  ${av:-clamav: no answer from sf-health}"
av_conf="$(docker exec -u 11333:11333 "$name" cat /run/spamfilter/rspamd/local.d/antivirus.conf 2>/dev/null || true)"
if (( clamav_on )); then
  if ! grep -q 'clamd.sock' <<<"$av_conf"; then
    warn "rspamd's runtime antivirus.conf does not point at clamd's socket"
    failed=1
  fi
else
  if [[ "$av" != "clamav: off (SF_CLAMAV=0)" ]] || ! grep -q '^enabled = false;' <<<"$av_conf"; then
    warn "SF_CLAMAV=0, but ClamAV is not reported off / antivirus.conf is not 'enabled = false'"
    failed=1
  fi
fi
log "sfctl doctor in the test container:"
docker exec "$name" sfctl doctor 2>&1 | sed 's/^/    /' || true

if (( learn )); then
  log "Learn test: scan a test mail, learn it as spam, restart, check the count"
  # shellcheck disable=SC2016 # python source
  learn_py='
import json, sys, urllib.request
mail = ("From: smoke@example.org\r\nTo: test@example.org\r\nSubject: smoke test\r\n"
        "Message-ID: <aio-smoke@example.org>\r\n\r\n"
        + " ".join(f"word{i} cheap pills offer winner{i}" for i in range(40)) + "\r\n").encode()
def post(url, headers=None):
    req = urllib.request.Request(url, data=mail, headers=headers or {}, method="POST")
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read() or b"{}")
scan = post("http://127.0.0.1:11333/checkv2")
print("scan action:", scan.get("action"))
pw = open("/state/controller.password").read().strip()
res = post("http://127.0.0.1:11334/learnspam", {"Password": pw, "Deliver-To": "smoke-test"})
print("learn:", "ok" if res.get("success") else "failed")
sys.exit(0 if res.get("success") else 1)
'
  check docker exec -u "$FILTER_UID:$FILTER_GID" "$name" /usr/local/bin/python3 -c "$learn_py"
  # rspamd refreshes its learned counters a few seconds after a learn: wait
  # for the count to show up before restarting (CI read 0 here, 1 after).
  before_restart=""
  for _ in $(seq 1 30); do
    before_restart="$(sf_bayes_counts aio "$name" | awk '$1 == "BAYES_SPAM" {print $2}')"
    [[ -n "$before_restart" && "$before_restart" != 0 ]] && break
    sleep 1
  done
  log "  BAYES_SPAM learned before the restart: ${before_restart:-?}"
  docker restart -t 90 "$name" >/dev/null
  sleep 2
  sf_gate_aio "$name" "$url" "$test_app" || die "$name failed its gate after the restart"
  after_restart="$(sf_bayes_counts aio "$name" | awk '$1 == "BAYES_SPAM" {print $2}')"
  log "  BAYES_SPAM learned after the restart:  ${after_restart:-?}"
  if [[ -z "$before_restart" || "$before_restart" == 0 || "$after_restart" != "$before_restart" ]]; then
    warn "the learned count did not survive the restart"
    failed=1
  fi
fi

if (( clamscan )); then
  (( clamav_on )) || die "--clamav-scan needs ClamAV on (SF_CLAMAV is 0)"
  wait_s=${SF_CLAMAV_WAIT:-900}
  log "ClamAV test: waiting for clamd (first signature download, at most ${wait_s} s), then an EICAR test mail through rspamd"
  deadline=$(( $(date +%s) + wait_s ))
  until docker exec "$name" /usr/local/bin/sf-health clamav >/dev/null 2>&1; do
    if (( $(date +%s) >= deadline )); then
      warn "clamd not ready after ${wait_s} s: $(docker exec "$name" /usr/local/bin/sf-health clamav 2>&1 | head -n 1 || true)"
      failed=1
      break
    fi
    sleep 10
  done
  if (( failed == 0 )); then
    # shellcheck disable=SC2016 # python source
    eicar_py='
import base64, json, sys, urllib.request
# The EICAR anti-virus test file (harmless by definition), kept encoded so this
# script itself is never flagged.
eicar = base64.b64decode("WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=")
mail = ("From: smoke@example.org\r\nTo: test@example.org\r\nSubject: clamav smoke test\r\n"
        "Message-ID: <aio-smoke-clamav@example.org>\r\nMIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=sfb\r\n\r\n--sfb\r\nContent-Type: text/plain\r\n\r\n"
        "see attachment\r\n--sfb\r\nContent-Type: application/octet-stream; name=test.com\r\n"
        "Content-Disposition: attachment; filename=test.com\r\nContent-Transfer-Encoding: base64\r\n\r\n"
        + base64.b64encode(eicar).decode() + "\r\n--sfb--\r\n").encode()
req = urllib.request.Request("http://127.0.0.1:11333/checkv2", data=mail, method="POST")
with urllib.request.urlopen(req, timeout=30) as r:
    syms = (json.loads(r.read() or b"{}").get("symbols") or {})
hit = syms.get("CLAM_VIRUS") or {}
print("CLAM_VIRUS:", ",".join(hit.get("options") or []) if hit else "missing",
      "| CLAM_VIRUS_FAIL" if "CLAM_VIRUS_FAIL" in syms else "")
sys.exit(0 if hit else 1)
'
    if out="$(docker exec -u "$FILTER_UID:$FILTER_GID" "$name" /usr/local/bin/python3 -c "$eicar_py" 2>&1)"; then
      log "  EICAR through rspamd: $out"
    else
      warn "EICAR through rspamd was not detected: $(tail -n 2 <<<"$out")"
      failed=1
    fi
  fi
fi

(( failed == 0 )) || die "smoke test FAILED (see the warnings above)"
log "Smoke test passed: all four parts healthy on a copy (ClamAV: ${av#clamav: }); no mailbox was touched."
log "Next: deploy/aio/migrate.sh --dry-run, then deploy/aio/migrate.sh"
