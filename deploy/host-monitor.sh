#!/bin/bash
# Spamfilter host monitor (root cron every 5 min as User Script
# "Spamfilter-monitor"; self-contained, installed inline).
#
#   host-monitor.sh [--dry-run]
#
# Writes state/host-status.json atomically (0644, read by the WebUI's
# Drift page) with: containers {name: {exists, running, status, health,
# started_at, restart_count, image, image_id}}, disk (docker.img +
# appdata), rspamd controller check, DNS test of 2.0.0.127.zen.spamhaus.org
# through spamfilter-unbound, RBL/DNS failure rate from the last 15 min of
# rspamd logs, heartbeat age, per-account state (GET /api/health; fallback
# read-only SQLite via docker exec), backup status, active alerts.
#
# Unraid notifications on transitions, de-duplicated through
# operations/monitor-state.json: container down/unhealthy > 5 min, account
# error/auth_failed/config_error > 15 min, backup older than 26 h, (2.12)
# off-site copy older than 48 h or failed, a failed/overdue restore drill,
# heartbeat stale > 5 min, docker.img >= 85 % (2.12) / appdata >= 90 %, Spamhaus test failing > 15 min,
# RBL failure rate >= 50 % - and one "ok again" notice when a notified
# problem clears. Engine 2.1 states: stale account thread (> 10 min, then
# confirmed by the next run), the move circuit breaker (paused_moves /
# circuit_open: at once), provider limit/unavailable (> 30 min),
# auth_failed (> 15 min). Paused/stopped accounts raise no login, limit or
# stale alerts (their stored login_state is from before the pause).
#
# Daily digest (settings_kv digest_enabled, default on): the first run
# after 07:00 Europe/Copenhagen (DST-safe: local wall clock via TZ) sends
# one Unraid notification with yesterday's moved/released/marked counts
# per mailbox, "Tjek Fanget spam: <url>" (LAN + settings_kv external_url)
# and on Mondays the threshold suggestions; "Ingen spam i går" when quiet.
# The data comes from a read-only SQLite/services call inside the filter
# container (docker exec), so a missed day is sent on the next run.
#
# Mail (2.3): while the filter container runs, every notification above
# (alerts, "OK igen", the digest) ALSO goes out as mail through the
# filter's own mailer (docker exec spamfilter python3 /app/mailer.py notify
# --kind alert|digest ...); the filter decides the recipients (Indstillinger
# -> Notifikationer) and does nothing when no mail server is set up. Unraid
# notify stays the always-on path: while the filter container itself is
# down ONLY Unraid notifications work - the filter mails "Spamfilteret har
# været stoppet fra ... til ..." when it starts again.
#
# 2.4 all-in-one layout (container spamfilter with the image label
# spamfilter.layout=aio): only that one container is listed; rspamd, Redis,
# Unbound and the filter are probed inside it (docker exec -u <their uid>),
# their per-part health from the container's own HEALTHCHECK is written as
# "parts" (and named in the unhealthy alert), and the RBL/SERVFAIL counts
# come from the [rspamd] / [unbound] lines of its log. "layout" says which.
# The stopped old containers are watched too ("legacy_running"): one that
# runs next to the AIO is an immediate alert, and the old Redis is killed
# (see "legacy guard" below).
#
# Works when the filter (or docker) is down: every probe is allowed to
# fail. --dry-run prints the JSON and the notifications instead.
# Env: SPAMFILTER_APP, SPAMFILTER_URL (http://<LAN-IP>:18080), SF_NOTIFY_BIN,
# SF_TZ (Europe/Copenhagen), SF_DIGEST_HOUR (7), SF_MAIL_TIMEOUT (60 s),
# SF_LOCK_FILE (deploy lock, /tmp/spamfilter-deploy.lock).
set -euo pipefail
umask 022

DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    -h|--help) sed -n '2,58p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

APP="${SPAMFILTER_APP:-$(d="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." 2>/dev/null && pwd)"
  if [[ -n "$d" && -d "$d/state" && -d "$d/config" ]]; then echo "$d"; else echo /mnt/user/appdata/spamfilter; fi)}"
# The WebUI address: SPAMFILTER_URL, else WEBUI_BIND/WEBUI_PORT from
# operations/site.env, else the host's own LAN address (default route).
URL="${SPAMFILTER_URL:-}"
if [[ -z "$URL" ]]; then
  _sv() { sed -n "s/^$1=//p" "$APP/operations/site.env" 2>/dev/null | tail -n 1 | tr -d "\"' "; }
  _bind="$(_sv WEBUI_BIND)"
  [[ -n "$_bind" ]] || _bind="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}')" || true
  URL="http://${_bind:-127.0.0.1}:$(_sv WEBUI_PORT | grep -E '^[0-9]+$' || echo 18080)"
  unset _bind
fi
NOTIFY="${SF_NOTIFY_BIN:-/usr/local/emhttp/webGui/scripts/notify}"
LOCK="${SF_MONITOR_LOCK:-/tmp/spamfilter-monitor.lock}"
DOCKER_ROOT="${SF_DOCKER_ROOT:-/var/lib/docker}"
STATE="$APP/state"
OUT="$STATE/host-status.json"
MSTATE="$APP/operations/monitor-state.json"
CONTAINERS=(spamfilter spamfilter-rspamd spamfilter-redis spamfilter-unbound)
DNS_TEST=2.0.0.127.zen.spamhaus.org
NOW="${SF_NOW:-$(date +%s)}"
LOCAL_TZ="${SF_TZ:-Europe/Copenhagen}"
DIGEST_HOUR="${SF_DIGEST_HOUR:-7}"
STALE_AFTER_S=2100  # 35 min: IDLE may legitimately sit ~25 min between loops
MAIL_TIMEOUT="${SF_MAIL_TIMEOUT:-60}"

command -v jq >/dev/null || { echo "host-monitor: jq missing" >&2; exit 1; }
[[ -d "$STATE" ]] || { echo "host-monitor: $STATE missing" >&2; exit 1; }
exec 7>"$LOCK"
flock -n 7 || { echo "host-monitor: previous run still active" >&2; exit 0; }

have_docker=0
command -v docker >/dev/null && docker info >/dev/null 2>&1 && have_docker=1

# ---------------------------------------------------------------- layout
LAYOUT=legacy
if (( have_docker )) &&
   docker container inspect -f '{{range $k, $v := .Config.Labels}}{{$k}}={{$v}} {{end}}' spamfilter 2>/dev/null | grep -Eq '(^| )[a-z0-9-]+[.]layout=aio( |$)'; then
  LAYOUT=aio
  CONTAINERS=(spamfilter)
fi
# docker exec prefixes per part (AIO: as the part's own uid).
if [[ "$LAYOUT" == aio ]]; then
  FILTER_EXEC=(docker exec -u 10099:10099 spamfilter)
  # The AIO controller exempts no client from its password: /stat via the
  # filter uid, which owns controller.password (never leaves the container).
  RSPAMD_STAT=("${FILTER_EXEC[@]}" /usr/local/bin/sf-health bayes)
  DNS_EXEC=(docker exec spamfilter)
  DNS_PORT=5353  # the AIO's Unbound: unprivileged loopback port
  RSPAMD_CT=spamfilter
  UNBOUND_CT=spamfilter
else
  FILTER_EXEC=(docker exec spamfilter)
  RSPAMD_EXEC=(docker exec spamfilter-rspamd)
  RSPAMD_STAT=("${RSPAMD_EXEC[@]}" rspamc -h 127.0.0.1:11334 -t 10 stat)
  DNS_EXEC=(docker exec spamfilter-unbound)
  DNS_PORT=53
  RSPAMD_CT=spamfilter-rspamd
  UNBOUND_CT=spamfilter-unbound
fi

# ---------------------------------------------------------------- legacy guard (2.4)
# While the AIO is live, the STOPPED 4-container members (kept for
# deploy/aio/rollback.sh until cleanup.sh) must stay stopped: the old Redis
# would open the same redis/ data dir as the AIO's Redis and corrupt the
# Bayes store (Redis has no data-dir lock). A running one (Start in the
# Docker tab, "Start all", autostart toggled back on) raises an alert at
# once, and the old Redis is killed (SIGKILL: no shutdown save into the
# shared dir) - but only while the AIO runs and no deploy script holds the
# deploy lock (rollback.sh starts the old ones on purpose, after it stopped
# the AIO).
LEGACY_NAMES=(spamfilter-legacy spamfilter-redis spamfilter-rspamd spamfilter-unbound)
DEPLOY_LOCK="${SF_LOCK_FILE:-/tmp/spamfilter-deploy.lock}"
legacy_running='[]'
legacy_killed=false
if [[ "$LAYOUT" == aio ]]; then
  for name in "${LEGACY_NAMES[@]}"; do
    if [[ "$(docker container inspect -f '{{.State.Running}}' "$name" 2>/dev/null || true)" == true ]]; then
      legacy_running="$(jq -c --arg n "$name" '. + [$n]' <<<"$legacy_running")"
    fi
  done
  if jq -e 'index("spamfilter-redis") != null' <<<"$legacy_running" >/dev/null &&
     [[ "$(docker container inspect -f '{{.State.Running}}' spamfilter 2>/dev/null || true)" == true ]]; then
    # fd 8 = the deploy lock, held only while this function runs
    kill_legacy_redis() {
      flock -n 8 || return 0
      if [[ "$DRY_RUN" == 1 ]]; then
        echo "[dry-run] docker kill spamfilter-redis (runs next to the all-in-one container)" >&2
      elif docker kill spamfilter-redis >/dev/null 2>&1; then
        legacy_killed=true
        echo "host-monitor: killed spamfilter-redis - it ran next to the all-in-one container" >&2
      fi
      return 0
    }
    kill_legacy_redis 8>>"$DEPLOY_LOCK" || true
  fi
fi

# ---------------------------------------------------------------- containers
containers='{}'
parts='null'
for name in "${CONTAINERS[@]}"; do
  c='{"exists": false, "running": false, "status": "missing", "health": null,
      "started_at": null, "restart_count": null, "image": null, "image_id": null}'
  if (( have_docker )) && raw="$(docker container inspect "$name" 2>/dev/null)"; then
    c="$(jq -c '.[0] | {exists: true, running: .State.Running, status: .State.Status,
                        health: (.State.Health.Status // null),
                        started_at: .State.StartedAt, restart_count: .RestartCount,
                        image: .Config.Image, image_id: .Image}' <<<"$raw")" || true
  fi
  containers="$(jq -c --arg n "$name" --argjson c "$c" '.[$n] = $c' <<<"$containers")"
  if [[ "$LAYOUT" == aio && -n "${raw:-}" ]]; then
    # Last HEALTHCHECK output of the AIO: its last line is the JSON of
    # filter/aio_health.py ({"ok", "parts": {name: {ok, detail}}}).
    parts="$(jq -c '.[0].State.Health.Log // [] | last | .Output // ""
                    | split("\n") | map(select(startswith("{"))) | last // "null"
                    | fromjson? // null | if type == "object" then .parts else null end' <<<"$raw" 2>/dev/null)" ||
      parts='null'
    [[ -n "$parts" ]] || parts='null'
  fi
done
running() { jq -e --arg n "$1" '.[$n].running == true' <<<"$containers" >/dev/null; }

# Extra mail path (see the header): only when the filter container is up,
# never fatal, bounded by a timeout. $1 = alert|digest, $2 = subject, $3 = text.
mail_notify() {
  if (( ! have_docker )) || ! running spamfilter; then
    return 0
  fi
  if [[ "$DRY_RUN" == 1 ]]; then
    echo "[dry-run] mail ($1): $2"
    return 0
  fi
  if timeout "$MAIL_TIMEOUT" "${FILTER_EXEC[@]}" python3 /app/mailer.py notify \
       --kind "$1" --subject "$2" --text "$3" >/dev/null 2>&1; then
    echo "mail ($1): $2"
  fi
  return 0
}

# ---------------------------------------------------------------- disk
disk_json() { # df of PATH -> {path,size,used,avail,pct}
  local line
  line="$(df -P -B1 "$1" 2>/dev/null | awk 'NR == 2 {gsub("%", "", $5); print $2, $3, $4, $5}')" || line=""
  if [[ -z "$line" ]]; then
    jq -nc --arg p "$1" '{path: $p, size: null, used: null, avail: null, pct: null}'
    return
  fi
  read -r size used avail pct <<<"$line"
  jq -nc --arg p "$1" --argjson s "$size" --argjson u "$used" --argjson a "$avail" --argjson pc "$pct" \
    '{path: $p, size: $s, used: $u, avail: $a, pct: $pc}'
}
app_bytes="$(timeout 30 du -sxb "$APP" 2>/dev/null | awk '{print $1}')" || app_bytes=""
disk="$(jq -nc --argjson d "$(disk_json "$DOCKER_ROOT")" --argjson a "$(disk_json "$APP")" \
  --arg ab "${app_bytes:-}" \
  '{docker_img: $d, appdata: ($a + {spamfilter_bytes: ($ab | tonumber? // null)})}')"

# ---------------------------------------------------------------- rspamd
rspamd='{"ok": false, "ms": null}'
if (( have_docker )) && running "$RSPAMD_CT"; then
  t0="$(date +%s%N)"
  if timeout 15 "${RSPAMD_STAT[@]}" >/dev/null 2>&1; then
    rspamd="$(jq -nc --argjson ms "$(( ($(date +%s%N) - t0) / 1000000 ))" '{ok: true, ms: $ms}')"
  fi
fi

# ---------------------------------------------------------------- DNS
# 2.0.0.127.zen.spamhaus.org is Spamhaus' permanent test entry: a working
# setup answers 127.0.0.x; 127.255.255.x means "refused: public/open
# resolver" (RBL results would be useless), SERVFAIL/timeout = broken path.
dns="$(jq -nc --arg q "$DNS_TEST" '{query: $q, ok: false, verdict: "unavailable", rcode: null, answers: [], ms: null}')"
if (( have_docker )) && running "$UNBOUND_CT"; then
  out="$(timeout 20 "${DNS_EXEC[@]}" drill -p "$DNS_PORT" @127.0.0.1 "$DNS_TEST" A 2>&1)" || true
  rcode="$(awk -F'rcode: ' '/->>HEADER<<-/ {split($2, a, ","); print a[1]; exit}' <<<"$out")"
  answers="$(awk -v q="$DNS_TEST." '$1 == q && $3 == "IN" && $4 == "A" {print $5}' <<<"$out" | jq -Rnc '[inputs | select(length > 0)]')"
  ms="$(awk '/Query time:/ {print $4; exit}' <<<"$out")"
  dns="$(jq -nc --arg q "$DNS_TEST" --arg rc "${rcode:-}" --argjson an "$answers" --arg ms "${ms:-}" '
    ($an | map(select(startswith("127.255.255."))) | length > 0) as $blocked
    | ($an | map(select(test("^127\\.0\\.0\\.[0-9]+$"))) | length > 0) as $listed
    | {query: $q, rcode: (if $rc == "" then null else $rc end), answers: $an,
       ms: ($ms | tonumber? // null),
       verdict: (if $listed then "ok" elif $blocked then "blocked"
                 elif $rc == "" then "timeout" else ($rc | ascii_downcase) end)}
    | .ok = (.verdict == "ok")')"
fi

# ---------------------------------------------------------------- RBL failures
# rspamd logs one rspamd_task_write_log line per scan; RBL/URIBL lookups
# that failed show up as "...:server fail" symbol options in that line.
rbl='{"window_s": 900, "scans": 0, "scans_with_dns_fail": 0, "fail_rate": null, "dns_limit_hits": 0, "unbound_servfail": 0}'
if (( have_docker )) && running "$RSPAMD_CT"; then
  logs="$(timeout 30 docker logs --since 15m "$RSPAMD_CT" 2>&1)" || logs=""
  ulogs=""
  if [[ "$LAYOUT" == aio ]]; then
    # One log for four programs: every line carries its [program] prefix.
    ulogs="$(grep '^\[unbound\] ' <<<"$logs")" || ulogs=""
    logs="$(grep '^\[rspamd\] ' <<<"$logs")" || logs=""
  elif running spamfilter-unbound; then
    ulogs="$(timeout 30 docker logs --since 15m spamfilter-unbound 2>&1)" || ulogs=""
  fi
  scans="$(grep -c 'rspamd_task_write_log' <<<"$logs")" || scans=0
  failed="$(grep 'rspamd_task_write_log' <<<"$logs" | grep -c 'server fail')" || failed=0
  limit="$(grep -c 'stop resolving on reaching' <<<"$logs")" || limit=0
  servfail="$(grep -c 'SERVFAIL' <<<"$ulogs")" || servfail=0
  rbl="$(jq -nc --argjson s "$scans" --argjson f "$failed" --argjson l "$limit" --argjson sf "$servfail" \
    '{window_s: 900, scans: $s, scans_with_dns_fail: $f,
      fail_rate: (if $s > 0 then (($f / $s * 1000 | round) / 1000) else null end),
      dns_limit_hits: $l, unbound_servfail: $sf}')"
fi

# ---------------------------------------------------------------- heartbeat
hb_age=null
if [[ -r "$STATE/heartbeat" ]]; then
  hb="$(awk 'NR == 1 {print $1}' "$STATE/heartbeat" 2>/dev/null)" || hb=""
  hb="${hb%%.*}"
  [[ "$hb" =~ ^[0-9]+$ ]] && hb_age=$(( NOW - hb ))
fi

# ---------------------------------------------------------------- filter DB
# One read-only look into the filter's SQLite (inside the container, as the
# container user): account_status rows (stale/circuit detection and the
# fallback when /api/health is down), the digest settings and - when the
# digest is due and enabled - yesterday's numbers via services.digest_data.
today="$(TZ="$LOCAL_TZ" date -d "@$NOW" +%F)"
local_hour="$(TZ="$LOCAL_TZ" date -d "@$NOW" +%H)"
local_dow="$(TZ="$LOCAL_TZ" date -d "@$NOW" +%u)"
# Pure calendar arithmetic in UTC (no DST). NB: "12:00 -1 day" would parse
# "-1" as a UTC offset plus "+1 day" in GNU date.
yday="$(date -u -d "$today 12:00 UTC -1 day" +%F)"
prev_digest='{}'
if [[ -r "$MSTATE" ]] && jq -e '.digest | type == "object"' "$MSTATE" >/dev/null 2>&1; then
  prev_digest="$(jq -c '.digest' "$MSTATE")"
fi
want_digest=0
if (( 10#$local_hour >= DIGEST_HOUR )) &&
   [[ "$(jq -r '.last_day // ""' <<<"$prev_digest")" != "$today" ]]; then
  want_digest=1
fi
monday=0
[[ "$local_dow" == 1 ]] && monday=1

read -r -d '' SF_PY <<'PYEOF' || true
# sf-monitor-snippet: runs inside the filter container, read-only.
import json, os, sqlite3, sys
day, want, monday = sys.argv[1], sys.argv[2] == "1", sys.argv[3] == "1"
out = {"status": {}, "settings": {}, "digest": None, "digest_source": None}
path = os.path.join(os.environ.get("STATE_DIR", "/state"), "spamfilter.db")
db = None
try:
    db = sqlite3.connect("file:" + path + "?mode=ro", uri=True, timeout=5)
    db.row_factory = sqlite3.Row
    for r in db.execute("SELECT * FROM account_status"):
        d = dict(r)
        out["status"][str(d.get("account"))] = {
            k: d.get(k) for k in ("state", "updated_at", "last_loop_at", "alive_at",
                                  "move_state", "login_state")}
except sqlite3.Error:
    pass
if db is not None:
    try:  # 2.1 move circuit breaker (absent on older versions)
        for r in db.execute("SELECT account, state FROM move_circuit"):
            out["status"].setdefault(str(r[0]), {})["circuit"] = r[1]
    except sqlite3.Error:
        pass
    try:
        for r in db.execute("SELECT key, value FROM settings_kv "
                            "WHERE key IN ('digest_enabled', 'external_url')"):
            out["settings"][str(r[0])] = r[1]
    except sqlite3.Error:
        pass
enabled = str(out["settings"].get("digest_enabled", "1") or "1").strip().lower() \
    not in ("0", "false", "off", "no", "nej")
if want and enabled:
    try:
        sys.path.insert(0, os.environ.get("SF_PY_PATH", "/app"))
        import services
        out["digest"] = services.digest_data(day, suggestions=monday)
        out["digest_source"] = "services"
    except Exception:
        if db is not None:
            try:
                acc = {}
                for r in db.execute("SELECT account, metric, SUM(n) FROM stats_daily "
                                    "WHERE day=? GROUP BY account, metric", (day,)):
                    acc.setdefault(str(r[0]), {})[str(r[1])] = int(r[2] or 0)
                rows = [{"account": a, "name": a, "mode": None, "moved": s.get("moved", 0),
                         "released": s.get("released", 0),
                         "marked": s.get("marked_spam", 0) + s.get("user_junked", 0),
                         "spam_detected": s.get("spam_detected", 0)}
                        for a, s in sorted(acc.items()) if a != "*"]
                out["digest"] = {"day": day, "accounts": rows, "suggestions": [],
                                 "empty": not any(x["moved"] or x["released"] or x["marked"]
                                                  or x["spam_detected"] for x in rows)}
                out["digest_source"] = "sqlite"
            except sqlite3.Error:
                pass
print(json.dumps(out))
PYEOF

sfdb='{}'
if (( have_docker )) && running spamfilter; then
  sfdb="$(timeout 60 "${FILTER_EXEC[@]}" python -c "$SF_PY" "$yday" "$want_digest" "$monday" 2>/dev/null)" || sfdb='{}'
  jq -e 'type == "object"' <<<"$sfdb" >/dev/null 2>&1 || sfdb='{}'
fi
db_status="$(jq -c '.status // {} | if type == "object" then . else {} end' <<<"$sfdb")"

# ---------------------------------------------------------------- accounts
# A8: /api/health exposes only {ok, version, accounts: {name: state}}
# (2.1 may give {name: {state, stale, circuit, ...}} - both are handled).
api='{"ok": false, "version": null}'
accounts='{}'
details='{}'
accounts_source=none
if body="$(curl -fsS --max-time 5 "$URL/api/health" 2>/dev/null)" &&
   jq -e '.accounts | type == "object"' <<<"$body" >/dev/null 2>&1; then
  api="$(jq -c '{ok: (.ok == true), version: .version}' <<<"$body")"
  accounts="$(jq -c '.accounts' <<<"$body")"
  # E11 details: {name: {stale, circuit, login_state, limited, ...}} (no addresses).
  details="$(jq -c '.details // {} | if type == "object" then . else {} end' <<<"$body")"
  accounts_source=api
elif jq -e 'length > 0' <<<"$db_status" >/dev/null 2>&1; then
  # Read-only fallback straight from SQLite inside the filter container.
  accounts="$(jq -c 'map_values(.state // "unknown")' <<<"$db_status")"
  accounts_source=sqlite
fi

# ---------------------------------------------------------------- backup
backup='{"available": false}'
if [[ -r "$STATE/backup-status.json" ]] && jq -e 'type == "object"' "$STATE/backup-status.json" >/dev/null 2>&1; then
  backup="$(jq -c --argjson now "$NOW" '{available: true, ok: (.ok == true), ts: .ts, archive: .archive,
      size: .size, error: .error, age_s: (if (.ts | type) == "number" then $now - .ts else null end)}' \
      "$STATE/backup-status.json")"
fi

# 2.12 (#11): the off-site copy (backup-offsite.sh) and its monthly restore
# drill. No offsite-status.json = the off-site job is not installed: no alert.
offsite='{"available": false}'
if [[ -r "$STATE/offsite-status.json" && ! -L "$STATE/offsite-status.json" ]] &&
   jq -e 'type == "object"' "$STATE/offsite-status.json" >/dev/null 2>&1; then
  offsite="$(jq -c --argjson now "$NOW" '{available: true, ok: (.ok == true), ts: .ts, remote: .remote,
      skipped: .skipped, error: .error, age_s: (if (.ts | type) == "number" then $now - .ts else null end)}' \
      "$STATE/offsite-status.json")"
fi
drill='{"available": false}'
if [[ -r "$STATE/restore-drill.json" && ! -L "$STATE/restore-drill.json" ]] &&
   jq -e 'type == "object"' "$STATE/restore-drill.json" >/dev/null 2>&1; then
  drill="$(jq -c --argjson now "$NOW" '{available: true, ok: (.ok == true), ts: .ts, archive: .archive,
      error: .error, every_days: (.every_days // 30),
      age_s: (if (.ts | type) == "number" then $now - .ts else null end)}' "$STATE/restore-drill.json")"
fi
backup="$(jq -c --argjson o "$offsite" --argjson dr "$drill" '. + {offsite: $o, drill: $dr}' <<<"$backup")"

# ---------------------------------------------------------------- database
# 2.7.3: a quick integrity check of the filter's SQLite database (read-only,
# inside the container as the filter's uid). A damaged database stops the
# whole filter; without this the owner only saw one "hængt?" mail per mailbox.
db_check="unknown"
if (( have_docker == 1 )) && [[ "$(jq -r '.spamfilter.running // false' <<<"$containers" 2>/dev/null)" == true ]]; then
  # shellcheck disable=SC2016 # python code, expands inside the container
  out="$(timeout 60 "${FILTER_EXEC[@]}" python3 -s -c '
import sqlite3
try:
    c = sqlite3.connect("file:/state/spamfilter.db?mode=ro", uri=True, timeout=20)
    r = c.execute("PRAGMA quick_check").fetchone()[0]
    print("SFDBCHECK ok" if r == "ok" else "SFDBCHECK bad " + str(r)[:120])
except sqlite3.DatabaseError as ex:
    print("SFDBCHECK bad " + str(ex)[:120])
except Exception as ex:
    print("SFDBCHECK unknown " + type(ex).__name__)
' 2>/dev/null)" || true
  line="$(grep -m1 '^SFDBCHECK ' <<<"$out" || true)"
  case "$line" in
    "SFDBCHECK ok") db_check="ok" ;;
    "SFDBCHECK bad "*) db_check="bad:${line#SFDBCHECK bad }" ;;
  esac
fi

# ---------------------------------------------------------------- conditions
# Each active problem: key, delay before notifying (s), level, Danish text
# (shown in Unraid notifications and on the Drift page).
conditions="$(jq -nc \
  --argjson c "$containers" --argjson d "$disk" --argjson dns "$dns" --argjson rbl "$rbl" \
  --argjson acc "$accounts" --argjson b "$backup" --argjson hb "$hb_age" \
  --argjson docker "$have_docker" --argjson st "$db_status" --argjson det "$details" --argjson now "$NOW" \
  --argjson stale_after "$STALE_AFTER_S" --arg unb "$UNBOUND_CT" --argjson parts "$parts" \
  --argjson legacy "$legacy_running" --argjson killed "$legacy_killed" --arg dbc "$db_check" '
  def cond(k; delay; level; text): {key: k, delay: delay, level: level, text: text};
  def stv: if type == "object" then (.state // "unknown" | tostring) else (. // "unknown" | tostring) end;
  def flag(f): if type == "object" then (.[f] // null) else null end;
  def circuit_open: . != null and . != false and . != 0 and . != ""
    and ((tostring | ascii_downcase) | test("^(closed|ok|0|false|none|null|active)$") | not);
  # The engine marks a thread stale after 10 min of silence already; one
  # more run (5 min) confirms it before notifying.
  def stale(n): cond("stale:" + n; 300; "alert"; "Konto " + n + ": filteret har ikke tjekket postkassen i over 10 minutter (hængt?)");
  def circuit(n): cond("circuit:" + n; 0; "alert"; "Konto " + n + ": sikkerhedsbremsen har sat flytning på pause - mange mails blev flyttet på kort tid. Tjek Fanget spam og genoptag under Konti");
  def limited(n): cond("limit:" + n; 1800; "warning"; "Konto " + n + ": mailudbyderen begrænser eller afviser forbindelser (over 30 min)");
  # A paused (or stopped) account is not connected: its login_state is
  # whatever it was when it stopped, so never alert on login/limit/stale.
  # The circuit breaker stays: it is a stored state an admin must resolve.
  def inactive(s): s == "paused" or s == "stopped";
  # n = account, s = state string, d = details object (API details or SQLite row).
  def problems(n; s; d):
    (if n == "*" and s == "config_error" then cond("account:*"; 900; "alert"; "Konfigurationen (accounts.yml) kan ikke indlæses")
     elif inactive(s) then empty
     elif s == "auth_failed" or (d.login_state // "") == "auth_failed" then cond("account:" + n; 900; "alert"; "Konto " + n + ": login afvist - tjek adgangskoden")
     elif s == "error" then cond("account:" + n; 900; "warning"; "Konto " + n + ": forbindelsesfejl")
     else empty end),
    (if inactive(s) then empty
     elif (s | test("limit|unavail|inuse|in_use|throttl")) or d.limited == true
        or ((d.login_state // "") | tostring | test("limit|unavail|inuse|in_use|throttl"))
       then limited(n) else empty end),
    (if inactive(s) then empty elif s == "stale" or d.stale == true then stale(n) else empty end),
    (if (s | test("circuit|paused_moves")) or ((d.circuit // null) | circuit_open)
        or ((d.circuit_open // null) | circuit_open) or (d.move_state // "") == "paused"
       then circuit(n) else empty end);
  [ (if $docker == 0 then cond("docker"; 300; "alert"; "Docker svarer ikke på værten") else empty end),
    (if ($legacy | length) > 0
       then cond("legacy-running"; 0; "alert"; "Gamle spamfilter-containere kører ved siden af den samlede container: "
                 + ($legacy | join(", ")) + (if $killed then " (spamfilter-redis er stoppet med det samme)" else "" end)
                 + ". De deler Redis-data - stop dem, og start dem aldrig i hånden (tilbage til fire containere: deploy/aio/rollback.sh)")
       else empty end),
    ($c | to_entries[] | select($docker == 1) |
      if .value.exists | not then cond("container:" + .key; 300; "alert"; "Containeren " + .key + " findes ikke")
      elif .value.running | not then cond("container:" + .key; 300; "alert"; "Containeren " + .key + " kører ikke (" + (.value.status // "?") + ")")
      elif .value.health == "unhealthy" then cond("container:" + .key; 300; "alert"; "Containeren " + .key + " er usund (unhealthy)"
        + (if .key == "spamfilter" and ($parts | type) == "object"
             then ($parts | to_entries | map(select(.value.ok != true) | .key)) as $bad
               | (if ($bad | length) > 0 then " - fejler: " + ($bad | join(", ")) else "" end)
             else "" end))
      else empty end),
    (if ($c.spamfilter.running == true) and ($hb == null or $hb > 180)
       then cond("heartbeat"; 300; "alert";
                 if $hb == null then "Filterets heartbeat mangler" else "Filterets heartbeat er " + ($hb | tostring) + " s gammel" end)
       else empty end),
    ($acc | to_entries[] | .key as $n | (.value | stv) as $s
      | (if (.value | type) == "object" then .value else ($det[$n] // {}) end) as $d
      | problems($n; $s; $d)),
    ($st | to_entries[] | select(.key != "*") | .key as $n | .value as $v |
      ([$v.alive_at, $v.last_loop_at, $v.updated_at] | map(numbers) | max // 0) as $last |
      problems($n; ($v.state // "unknown" | tostring); $v),
      (if (($v.state // "") as $x | $x == "idle" or $x == "working" or $x == "paused_moves")
          and $last > 0 and ($now - $last) > $stale_after
         then stale($n) else empty end)),
    (if ($b.available | not) then cond("backup"; 93600; "warning"; "Ingen backup-status fundet")
     elif ($b.age_s != null and $b.age_s > 93600) then cond("backup"; 0; "warning"; "Seneste backup er ældre end 26 timer")
     elif ($b.ok | not) then cond("backup"; 21600; "warning"; "Seneste backup fejlede")
     else empty end),
    # 2.12 (#11): the copy out of the house - older than 48 h or failed.
    (($b.offsite // {}) as $o |
     if ($o.available | not) or ($o.skipped != null) then empty
     elif ($o.age_s != null and $o.age_s > 172800) then cond("offsite"; 0; "warning"; "Kopien ud af huset er ældre end 48 timer (User Script Spamfilter-offsite)")
     elif ($o.ok | not) then cond("offsite"; 0; "warning"; "Kopien ud af huset fejlede" + (if $o.error then ": " + ($o.error | tostring) else "" end))
     else empty end),
    (($b.drill // {}) as $r |
     if ($r.available | not) then empty
     elif ($r.ok | not) then cond("restore-drill"; 0; "warning"; "Gendannelsesøvelsen fejlede" + (if $r.error then ": " + ($r.error | tostring) else "" end))
     elif ($r.age_s != null and $r.age_s > (($r.every_days // 30) + 5) * 86400) then cond("restore-drill"; 0; "warning"; "Gendannelsesøvelsen er ikke kørt i over " + ((($r.every_days // 30) + 5) | tostring) + " dage")
     else empty end),
    # 2.12 (#25): docker.img warns from 85 % (a full image stops every container), appdata from 90 %.
    ($d | to_entries[] | select((.value.pct // 0) >= (if .key == "docker_img" then 85 else 90 end)) |
      cond("disk:" + .key; 0; "warning"; (if .key == "docker_img" then "docker.img" else "appdata" end) + " er " + (.value.pct | tostring) + " % fuld")),
    (if ($c[$unb].running == true) and ($dns.verdict != "ok")
       then cond("dns"; 900; "warning"; "Spamhaus-test via Unbound fejler (" + $dns.verdict + ") - RBL-opslag virker ikke") else empty end),
    (if ($rbl.scans >= 5) and (($rbl.fail_rate // 0) >= 0.5)
       then cond("rbl"; 0; "warning"; "Over halvdelen af scanningerne havde fejlende DNS/RBL-opslag") else empty end),
    (if ($dbc | startswith("bad:"))
       then cond("database"; 0; "alert"; "Databasen er beskadiget (" + ($dbc | ltrimstr("bad:")) + "). Filteret kan ikke arbejde, "
                 + "men ingen mail går tabt - den ligger hos udbyderen. Gendan fra den seneste backup (BACKUP.md, afsnit Gendan)")
       else empty end)
  ]
  # 2.7.3: several mailboxes stalled at once share one cause (database, network, a hung
  # engine) - one mail for all of them, and none at all while the database itself is damaged.
  | . as $all | [$all[] | select(.key | startswith("stale:"))] as $st
  | if any($all[]; .key == "database") then [$all[] | select(.key | startswith("stale:") | not)]
    elif ($st | length) >= 2
      then [$all[] | select(.key | startswith("stale:") | not)]
           + [cond("stale:*"; 300; "alert"; "Filteret har ikke tjekket " + ($st | length | tostring)
                   + " postkasser i over 10 minutter (" + ($st | map(.key | ltrimstr("stale:")) | join(", "))
                   + ") - formentlig en fælles fejl (fx databasen eller netværket)")]
    else $all end')"

# De-dup: remember when each problem started and whether it was notified.
prev='{}'
if [[ -r "$MSTATE" ]] && jq -e '.conditions | type == "object"' "$MSTATE" >/dev/null 2>&1; then
  prev="$(jq -c '.conditions' "$MSTATE")"
fi
plan="$(jq -nc --argjson now "$NOW" --argjson active "$conditions" --argjson prev "$prev" --arg url "$URL" '
  ($active | map({(.key): .}) | add // {}) as $act
  | ($act | with_entries(
      .value as $a | ($prev[.key] // null) as $p
      | .value = {since: ($p.since // $now), notified: ($p.notified // false),
                  level: $a.level, text: $a.text, delay: $a.delay})) as $cur
  | ($cur | with_entries(select((.value.notified | not) and ($now - .value.since >= .value.delay)))
          | to_entries | map({key, level: .value.level, subject: ("Spamfilter: " + .value.text),
                              text: ("Aktivt siden " + (.value.since | strflocaltime("%d-%m %H:%M"))
                                     + ". Se Drift-siden: " + $url + "/system")})) as $raise
  | ($prev | with_entries(select(.value.notified == true and ($act[.key] == null)))
           | to_entries | map({key, level: "normal", subject: "Spamfilter: OK igen",
                               text: ("Løst: " + (.value.text // .key))})) as $clear
  | {conditions: ($cur | with_entries(.key as $k
      | .value.notified = (.value.notified or (([$raise[].key] | index($k)) != null)))),
     send: ($raise + $clear)}')"

# ---------------------------------------------------------------- digest
digest_enabled="$(jq -c '.settings.digest_enabled // null
  | if . == null then true else ((tostring | ascii_downcase | gsub("^\\s+|\\s+$"; ""))
      | IN("0", "false", "off", "no", "nej") | not) end' <<<"$sfdb")"
ext_url="$(jq -r '.settings.external_url // "" | tostring | gsub("/+$"; "")
  | if test("^https?://[^\\s\"<>]+$") then . else "" end' <<<"$sfdb")"
digest_send='null'
digest_state="$prev_digest"
if [[ "$want_digest" == 1 && "$digest_enabled" == true ]] &&
   jq -e '.digest | type == "object"' <<<"$sfdb" >/dev/null 2>&1; then
  day_dk="$(date -u -d "$yday 12:00 UTC" +%d.%m.%Y)"
  digest_send="$(jq -c --arg lan "$URL" --arg ext "$ext_url" --arg daydk "$day_dk" --argjson monday "$monday" '
    def n(x): (x // 0);
    def plural(k; one; many): (k | tostring) + " " + (if k == 1 then one else many end);
    .digest as $d
    | ($d.accounts // []) as $acc
    | ($acc | map(n(.moved)) | add // 0) as $moved
    | ($acc | map(n(.released)) | add // 0) as $rel
    | ($acc | map(n(.marked)) | add // 0) as $marked
    | ($acc | map(n(.spam_detected)) | add // 0) as $det
    | ("Tjek Fanget spam: " + $lan + "/spam") as $link
    | (($moved + $rel + $marked + $det) == 0) as $empty
    | {subject: ("Spamfilter: dagsoversigt " + $daydk),
       description: ((if $empty then "Ingen spam i går."
                      else "I går: " + plural($moved; "mail flyttet"; "mails flyttet") + " til Spamfilter, "
                           + ($rel | tostring) + " frigivet, " + ($marked | tostring) + " markeret som spam."
                      end) + " " + $link),
       message: ([ "Dagsoversigt for " + $daydk ]
         + ($acc | map(.name as $name
             | [ (if n(.moved) > 0 then (n(.moved) | tostring) + " flyttet"
                  elif n(.spam_detected) > 0 then (n(.spam_detected) | tostring) + " fanget (uden flytning)"
                  else empty end),
                 (if n(.released) > 0 then (n(.released) | tostring) + " frigivet" else empty end),
                 (if n(.marked) > 0 then (n(.marked) | tostring) + " markeret som spam" else empty end) ]
             | ($name // "?") + ": " + (if length == 0 then "ingen spam" else join(" · ") end)))
         + (if $empty then ["Ingen spam i går."] else [] end)
         + [ $link ]
         + (if $ext != "" then ["Udefra: " + $ext + "/spam"] else [] end)
         + (if $monday == 1 and (($d.suggestions // []) | length) > 0
              then ["", "Forslag til følsomhed (seneste 14 dage):"]
                   + ($d.suggestions | map((.name // .account) + ": " + (.text // "")))
              else [] end)
         | join("\n"))}' <<<"$sfdb")" || digest_send='null'
  if [[ "$digest_send" != null ]]; then
    digest_state="$(jq -nc --arg d "$today" --arg y "$yday" --argjson now "$NOW" \
      '{last_day: $d, for_day: $y, sent_at: $now}')"
  fi
fi
digest_info="$(jq -nc --argjson en "$digest_enabled" --argjson st "$digest_state" \
  --argjson due "$want_digest" --arg ext "$ext_url" \
  '{enabled: $en, last_day: ($st.last_day // null), sent_at: ($st.sent_at // null),
    due: ($due == 1), external_url: (if $ext == "" then null else $ext end)}')"

alerts="$(jq -c --argjson now "$NOW" '.conditions | to_entries
  | map({key, level: .value.level, text: .value.text, since: .value.since,
         age_s: ($now - .value.since), notified: .value.notified})' <<<"$plan")"

status="$(jq -n --argjson now "$NOW" --arg iso "$(date -u -d "@$NOW" +%Y-%m-%dT%H:%M:%SZ)" \
  --arg host "$(hostname 2>/dev/null || echo unknown)" \
  --argjson c "$containers" --argjson d "$disk" --argjson r "$rspamd" --argjson dns "$dns" \
  --argjson rbl "$rbl" --argjson hb "$hb_age" --argjson api "$api" --argjson acc "$accounts" \
  --arg accsrc "$accounts_source" --argjson b "$backup" --argjson al "$alerts" \
  --argjson dg "$digest_info" --argjson det "$details" --arg layout "$LAYOUT" --argjson parts "$parts" \
  --argjson legacy "$legacy_running" \
  '{version: 1, ts: $now, generated_at: $iso, host: $host, layout: $layout, parts: $parts,
    legacy_running: $legacy,
    containers: $c, disk: $d,
    rspamd: $r, dns: $dns, rbl: $rbl, heartbeat: {age_s: $hb}, api: $api,
    accounts: $acc, account_details: $det, accounts_source: $accsrc, backup: $b,
    alerts: $al, digest: $dg,
    ok: ($al | length == 0)}')"

if [[ "$DRY_RUN" == 1 ]]; then
  printf '%s\n' "$status"
  jq -r '.send[] | "[dry-run] notify -i \(.level): \(.subject) - \(.text)"' <<<"$plan"
  while IFS=$'\t' read -r level subject text; do
    if [[ -n "$level" ]]; then mail_notify alert "$subject" "$text"; fi
  done < <(jq -r '.send[] | [.level, .subject, .text] | @tsv' <<<"$plan")
  if [[ "$digest_send" != null ]]; then
    jq -r '"[dry-run] notify -i normal: \(.subject) - \(.description)\n\(.message)"' <<<"$digest_send"
    mail_notify digest "$(jq -r '.subject' <<<"$digest_send")" "$(jq -r '.message' <<<"$digest_send")"
  fi
  exit 0
fi

# Atomic replace; root-owned 0644 inside the filter-owned 0700 state dir.
tmp="$STATE/.host-status.json.$$"
printf '%s\n' "$status" >"$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$OUT"

mkdir -p "$(dirname "$MSTATE")"
tmp="$MSTATE.$$"
jq --argjson dg "$digest_state" '{conditions, digest: $dg}' <<<"$plan" >"$tmp"
chmod 0600 "$tmp"
mv -f "$tmp" "$MSTATE"

while IFS=$'\t' read -r level subject text; do
  [[ -n "$level" ]] || continue
  echo "notify ($level): $subject - $text"
  if [[ -x "$NOTIFY" ]]; then
    "$NOTIFY" -e Spamfilter -s "$subject" -d "$text" -i "$level" >/dev/null 2>&1 || true
  fi
  mail_notify alert "$subject" "$text"
done < <(jq -r '.send[] | [.level, .subject, .text] | @tsv' <<<"$plan")

if [[ "$digest_send" != null ]]; then
  subject="$(jq -r '.subject' <<<"$digest_send")"
  desc="$(jq -r '.description' <<<"$digest_send")"
  message="$(jq -r '.message' <<<"$digest_send")"
  echo "notify (digest): $subject - $desc"
  if [[ -x "$NOTIFY" ]]; then
    "$NOTIFY" -e Spamfilter -s "$subject" -d "$desc" -m "$message" -i normal >/dev/null 2>&1 || true
  fi
  mail_notify digest "$subject" "$message"
fi
