#!/bin/bash
# Install an update the WebUI asked for (2.10, Opdateringer) - host side.
#
#   update-runner.sh [--dry-run]
#
# Runs on the Unraid host as the User Script "Spamfilter-update" (every
# minute, installed inline by deploy/install-user-scripts.sh). The container
# cannot build or replace itself; its WebUI only writes the request
# state/update/request.json = {v, tag, requested_by, ts, nonce, sig}: a
# version tag and an HMAC-SHA256 (key state/update/request.key) - no free
# text. Each run:
#   1. writes state/update/runner.json (the page shows the helper is alive)
#   2. no request, or another deploy script holds the deploy lock -> done
#      (a waiting request is picked up next minute)
#   3. moves the request into a root-only work dir and checks every field
#      (exact keys, vX.Y.Z tag, name, age <= 1 h, nonce not used before,
#      signature); anything else is refused, never interpreted
#   4. asks GitHub for that release of SF_UPDATE_REPO (set on the HOST: env
#      or operations/site.env - never taken from the container), with the
#      host's own token file if there is one, else (2.11.2) the WebUI's
#      read-only token handed over with the request (see below); downloads
#      its source package spamfilter-X.Y.Z-source.tar.gz (by asset id, so
#      only from that repo) and checks its sha256 against BOTH the release's
#      .sha256 file and GitHub's own asset digest; (2.12) the .sha256 file's
#      signature (.sha256.sig, ssh-keygen -Y) against deploy/release-signers
#      of the RUNNING source/ - see "STEP=signature"
#   5. refuses a package with absolute or .. paths, another top directory, a
#      deploy/versions.env VERSION other than the tag, or a version that is
#      not newer than the running source/
#   6. backs up source/ (operations/source-backups, newest 3 kept), puts the
#      new tree in source/ and runs ITS deploy/aio/update.sh --build from
#      the root-only copy (backup, gate, automatic rollback); a failure puts
#      the previous source/ back
#   7. state/update/status.json {state: koerer|faerdig|fejlet, tag, message,
#      log (last lines), started_at, finished_at} - 0644, atomic; refused
#      requests and failures also raise an Unraid notification.
# --dry-run: steps 1-5 without consuming the request or installing.
#
# Token hand-over (2.11.2, owner: "sætte token ind fra GitHub i GUI'en"):
# when runner.json says this helper has no token file, "Opdatér nu" also
# writes state/update/request.token = {v, nonce, token, sig} (0600; sig =
# HMAC-SHA256 with request.key over "tok1|<nonce of THIS request>|<token>").
# It is moved into the root-only work dir together with the request (also
# when the request is refused), checked strictly (exact keys, same nonce,
# GitHub token format, signature) and only ever sent as an Authorization
# header to $SF_UPDATE_API/repos/$SF_UPDATE_REPO/... (curl drops it on the
# redirect to the download host). It is deleted right after the download,
# never logged, never in status.json and never in a backup (state/update
# request.token is skipped by the container backup; the host backup does
# not copy state/update). A host token file always wins: the hand-over is
# then deleted unread. The repo and every package check stay host-side.
# Work dirs older than 4 h (left by a killed run) are removed on start.
#
# Self-contained on purpose (inlined into the User Script).
# Env: SPAMFILTER_APP, SF_UPDATE_REPO (owner/name; else read from
#      operations/site.env), SF_UPDATE_TOKEN_FILE (default
#      operations/github-token, owned by the helper's uid = root; only for
#      a private repo; wins over a token from the WebUI),
#      SF_UPDATE_API (https://api.github.com), SF_UPDATE_LOCK,
#      SF_LOCK_FILE (the deploy scripts' lock), SF_UPDATE_TIMEOUT (10800 s),
#      SF_NOTIFY_BIN.
set -Eeuo pipefail
umask 077

DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    -h|--help) sed -n '2,61p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

APP="${SPAMFILTER_APP:-$(d="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." 2>/dev/null && pwd)"
  if [[ -n "$d" && -d "$d/state" && -d "$d/config" ]]; then echo "$d"; else echo /mnt/user/appdata/spamfilter; fi)}"
STATE="$APP/state"
UPD="$STATE/update"
OPS="$APP/operations"
API="${SF_UPDATE_API:-https://api.github.com}"
TOKEN_FILE="${SF_UPDATE_TOKEN_FILE:-$OPS/github-token}"
LOCK="${SF_UPDATE_LOCK:-/tmp/spamfilter-update-runner.lock}"
DEPLOY_LOCK="${SF_LOCK_FILE:-/tmp/spamfilter-deploy.lock}"
TIMEOUT="${SF_UPDATE_TIMEOUT:-10800}"
NOTIFY="${SF_NOTIFY_BIN:-/usr/local/emhttp/webGui/scripts/notify}"
MAX_AGE=3600
TOKEN_RE='^(github_pat_[A-Za-z0-9_]{22,240}|gh[pousr]_[A-Za-z0-9]{30,250})$'
TAG_RE='^v(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$'
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
WORK="" TAG="" ACTOR="" STARTED=0 STEP="start" INSTALLING=0 ERR_CODE="" TOKEN_SRC="" repo=""

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

# write_json NAME (stdin) - atomic, 0644, into state/update/. state/ is
# writable by the filter's uid, so root never writes through a predictable
# name there: mktemp (O_EXCL) in the root-only operations/ dir, then mv -T
# renames it over the target (replaces a planted link, never follows it).
write_json() {
  local name=$1 tmp
  [[ "$DRY_RUN" == 1 ]] && { cat >/dev/null; return 0; }
  [[ -d "$UPD" && ! -L "$UPD" && -d "$OPS" && ! -L "$OPS" ]] || { cat >/dev/null; return 1; }
  tmp="$(mktemp "$OPS/.update-$name.XXXXXX")" || { cat >/dev/null; return 1; }
  if ! { cat >"$tmp" && chmod 0644 "$tmp" && mv -fT "$tmp" "$UPD/$name"; }; then
    rm -f "$tmp"
    return 1
  fi
}

# status STATE MESSAGE [LOGFILE] - the message is always our own fixed text.
status() {
  local st=$1 msg=$2 logf=${3:-} fin=0
  [[ "$st" == koerer ]] || fin="$(date +%s)"
  {
    if [[ -n "$logf" && -f "$logf" ]]; then
      tail -n 60 "$logf" | tr -d '\000-\010\013-\037\177' | cut -c1-300
    fi
  } | jq -Rn --arg s "$st" --arg t "$TAG" --arg m "$msg" --arg a "$ACTOR" --arg e "$ERR_CODE" \
        --argjson st0 "${STARTED:-0}" --argjson fin "$fin" \
        '{state: $s, tag: $t, message: $m, requested_by: $a, started_at: $st0, finished_at: $fin, error: $e,
          log: [inputs]}' |
    write_json status.json || log "WARNING: status not written"
}

notify() {
  if [[ "$DRY_RUN" != 1 && -x "$NOTIFY" ]]; then
    "$NOTIFY" -e Spamfilter -s "$1" -d "$2" -i "${3:-alert}" >/dev/null 2>&1 || true
  fi
}

# refuse MESSAGE - a request that is not installed (never echoes its content).
refuse() {
  log "refused: $1"
  status fejlet "Afvist: $1"
  notify "Spamfilter: opdatering afvist" "$1"
  exit 1
}

on_error() {
  local rc=$?
  trap - ERR
  log "FAILED during: $STEP (exit $rc)"
  if (( INSTALLING )); then
    restore_source
  fi
  status fejlet "Opdateringen fejlede under: $STEP (exit $rc). Den hidtidige version kører videre." "${LOGF:-}"
  notify "Spamfilter: opdatering fejlede" "Fejl under: $STEP (exit $rc). Se operations/ på værten."
  exit 1
}
trap on_error ERR
trap '[[ -n "$WORK" ]] && rm -rf "$WORK"; true' EXIT

restore_source() {
  if [[ -d "$APP/source.prev-$STAMP" ]]; then
    rm -rf "$APP/source"
    mv -T "$APP/source.prev-$STAMP" "$APP/source"
    log "previous source/ restored"
  fi
  INSTALLING=0
}

# host_token - the host's own token (operations/github-token, owned by our
# uid = root, a regular file, GitHub token format), else nothing.
host_token() {
  local tok
  [[ -f "$TOKEN_FILE" && ! -L "$TOKEN_FILE" && "$(stat -c %u "$TOKEN_FILE")" == "$(id -u)" ]] || return 0
  tok="$(head -c 300 "$TOKEN_FILE" | tr -d '\n\r ')"
  [[ "$tok" =~ $TOKEN_RE ]] && printf '%s' "$tok"
  return 0
}

# github_denied CODE - GitHub said 401/403/404/429: a clear Danish message
# (which token was used, what it needs), never the token itself.
github_denied() {
  local code=$1 name=${repo#*/} msg
  if [[ "$code" == 429 ]] || { [[ "$code" == 403 ]] && grep -qi '^x-ratelimit-remaining: *0' "$WORK/resp.hdr" 2>/dev/null; }; then
    ERR_CODE=github_rate
    msg="GitHub beder os vente (for mange opslag den seneste time). Prøv igen senere."
  elif [[ -n "$TOKEN_SRC" ]]; then
    ERR_CODE=github_access
    msg="GitHub svarede $code: tokenen har ikke adgang til repoet – den skal have Contents: read på $name."
    [[ "$TOKEN_SRC" == host ]] && msg="$msg (Tokenen er værtens egen fil operations/github-token, som går forud for WebUI'ens.)"
  else
    ERR_CODE=github_access
    msg="GitHub svarede $code: repoet er privat eller findes ikke, og hjælperen har ingen token. Gem en GitHub-token med Contents: read på $name under Opdateringer → Indstillinger."
  fi
  rm -f "$WORK/auth.hdr"
  log "GitHub refused (HTTP $code, token: ${TOKEN_SRC:-none})"
  status fejlet "$msg"
  notify "Spamfilter: opdatering fejlede" "$msg"
  exit 1
}

# gh_curl URL OUT [ACCEPT] - prints "<http code> <effective URL>". The
# token goes through a header file, never on the command line, and only to
# this repo's API URLs (curl drops it on a redirect to another host).
gh_curl() {
  local args=(-sS --proto '=https' --proto-redir '=https' --max-time 120 --retry 2
              -H "Accept: ${3:-application/vnd.github+json}" -H "X-GitHub-Api-Version: 2022-11-28"
              -H "User-Agent: spamfilter-update-runner" --max-filesize 67108864
              -D "$WORK/resp.hdr" -w '%{http_code} %{url_effective}' -o "$2")
  [[ -s "$WORK/auth.hdr" && ( "$1" == "$API/repos/$repo" || "$1" == "$API/repos/$repo/"* ) ]] &&
    args+=(-H "@$WORK/auth.hdr")
  [[ "${3:-}" == application/octet-stream ]] && args+=(-L)
  curl "${args[@]}" "$1"
}

# GitHub API GET. Only an answer from $API itself is read as an access
# problem: a 403/404 from the download host after the redirect (say an
# expired signed URL) is a plain download failure, and a 404 for the tag
# while the repo itself is visible means the release is gone (or a draft).
gh_get() { # URL OUT [ACCEPT]
  local out code eff
  out="$(gh_curl "$@")" || return
  code="${out%% *}" eff="${out#* }"
  [[ "$code" == 2?? ]] && return 0
  if [[ "$eff" != "$API/"* ]]; then
    log "download host answered HTTP $code"
    return 22
  fi
  case "$code" in
    404)
      if [[ "$1" == "$API/repos/$repo/releases/tags/"* ]]; then
        out="$(gh_curl "$API/repos/$repo" "$WORK/repo.json")" || out=""
        if [[ "${out%% *}" == 200 ]]; then
          rm -f "$WORK/auth.hdr"
          refuse "udgivelsen $TAG findes ikke på GitHub (slettet, eller kun en kladde)"
        fi
      fi
      github_denied 404 ;;
    401|403|429) github_denied "$code" ;;
    *) log "GitHub answered HTTP $code"; return 22 ;;
  esac
}

newer_than() { # A B -> true when version A > B
  [[ "$1" != "$2" && "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n 1)" == "$1" ]]
}

STEP="preflight"
for c in jq curl openssl sha256sum tar flock timeout sort; do
  command -v "$c" >/dev/null || { log "missing command $c"; exit 1; }
done
[[ -d "$STATE" && ! -L "$STATE" && -d "$OPS" && ! -L "$OPS" ]] || exit 0
exec 8>"$LOCK"
flock -n 8 || exit 0   # the previous run is still installing
# Work dirs left by a run that was killed (kill -9, power loss) may hold the
# token (auth.hdr, request.token): no run is active now that we hold lock 8.
[[ "$DRY_RUN" == 1 ]] || find "$OPS" -maxdepth 1 -name '.update-work.*' -type d -mmin +240 \
  -exec rm -rf {} + 2>/dev/null || true
[[ -d "$UPD" && ! -L "$UPD" ]] || exit 0
# token_file: the WebUI hands its token over only when we have none;
# token_handoff: this helper understands request.token (2.11.2).
has_file=false
[[ -n "$(host_token)" ]] && has_file=true
printf '{"seen_at": %s, "v": 2, "token_file": %s, "token_handoff": true}\n' "$(date +%s)" "$has_file" |
  write_json runner.json || true
if [[ ! -e "$UPD/request.json" && ! -L "$UPD/request.json" ]]; then
  # A hand-over left without a request (cancelled, or written by a WebUI
  # just now: give it 10 minutes) is deleted. find -P never follows links.
  [[ "$DRY_RUN" == 1 ]] || find "$UPD" -maxdepth 1 -name request.token -mmin +10 -delete 2>/dev/null || true
  exit 0
fi
if ! flock -n "$DEPLOY_LOCK" true; then
  log "another deploy script is running - the request waits"
  exit 0
fi

STEP="request"
WORK="$(mktemp -d "$OPS/.update-work.XXXXXX")"
if [[ "$DRY_RUN" == 1 ]]; then
  cp -P "$UPD/request.json" "$WORK/request.json"
  if [[ -e "$UPD/request.token" || -L "$UPD/request.token" ]]; then cp -P "$UPD/request.token" "$WORK/request.token"; fi
else
  mv -fT "$UPD/request.json" "$WORK/request.json"
  # The token goes with its request at once - also when the request is refused below.
  if [[ -e "$UPD/request.token" || -L "$UPD/request.token" ]]; then mv -fT "$UPD/request.token" "$WORK/request.token"; fi
fi
REQ="$WORK/request.json"
[[ -f "$REQ" && ! -L "$REQ" ]] || refuse "anmodningen er ikke en almindelig fil"
(( $(stat -c %s "$REQ") <= 2048 )) || refuse "anmodningen er for stor"
jq -e 'type == "object" and (keys == ["nonce", "requested_by", "sig", "tag", "ts", "v"]) and .v == 1
       and (.tag | type) == "string" and (.requested_by | type) == "string" and (.ts | type) == "number"
       and (.nonce | type) == "string" and (.sig | type) == "string"' "$REQ" >/dev/null 2>&1 ||
  refuse "anmodningen har ikke det rigtige format"
tag="$(jq -r .tag "$REQ")" actor="$(jq -r .requested_by "$REQ")" ts="$(jq -r .ts "$REQ")"
nonce="$(jq -r .nonce "$REQ")" sig="$(jq -r .sig "$REQ")"
[[ "$tag" =~ $TAG_RE ]] || refuse "ugyldig version"
[[ "$actor" =~ ^[A-Za-z0-9._@-]{1,64}$ ]] || refuse "ugyldigt brugernavn"
[[ "$ts" =~ ^[0-9]{1,12}$ && "$nonce" =~ ^[0-9a-f]{32}$ && "$sig" =~ ^[0-9a-f]{64}$ ]] || refuse "ugyldig signatur"
TAG="$tag" ACTOR="$actor" STARTED="$(date +%s)"
now="$(date +%s)"
(( ts <= now + 300 && now - ts <= MAX_AGE )) || refuse "anmodningen er for gammel"
KEYF="$UPD/request.key"
[[ -f "$KEYF" && ! -L "$KEYF" ]] || refuse "nøglen mangler"
key="$(head -c 200 "$KEYF" | tr -d '\n')"
[[ "$key" =~ ^[0-9a-f]{64}$ ]] || refuse "nøglen er ugyldig"
want="$(printf 'v1|%s|%s|%s|%s' "$tag" "$actor" "$ts" "$nonce" |
        openssl dgst -sha256 -mac HMAC -macopt "key:$key" | awk '{print $NF}')"
[[ "$want" == "$sig" ]] || refuse "signaturen passer ikke"
NONCES="$OPS/update-nonces"
if [[ -f "$NONCES" ]] && grep -qx "$nonce" "$NONCES"; then
  refuse "anmodningen er brugt før"
fi
if [[ "$DRY_RUN" != 1 ]]; then
  { tail -n 99 "$NONCES" 2>/dev/null || true; echo "$nonce"; } >"$WORK/nonces" && mv -f "$WORK/nonces" "$NONCES"
fi
version="${tag#v}"
log "request: $tag from $actor"
status koerer "Henter $tag fra GitHub …"

STEP="configuration"
repo="${SF_UPDATE_REPO:-}"
if [[ -z "$repo" && -f "$OPS/site.env" ]]; then
  repo="$(sed -n 's/^SF_UPDATE_REPO=//p' "$OPS/site.env" | tail -n 1 | tr -d "\"' ")"
fi
[[ "$repo" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$ && "$repo" != *..* ]] ||
  refuse "SF_UPDATE_REPO er ikke sat op på værten"
STEP="token"
tok="$(host_token)"
if [[ -n "$tok" ]]; then
  TOKEN_SRC=host   # the host's own file always wins; a hand-over is deleted unread
elif [[ -e "$WORK/request.token" || -L "$WORK/request.token" ]]; then
  TOKF="$WORK/request.token"
  [[ -f "$TOKF" && ! -L "$TOKF" ]] || refuse "tokenen fra WebUI'en er ikke en almindelig fil"
  (( $(stat -c %s "$TOKF") <= 1024 )) || refuse "tokenen fra WebUI'en er for stor"
  jq -e 'type == "object" and (keys == ["nonce", "sig", "token", "v"]) and .v == 1
         and (.nonce | type) == "string" and (.sig | type) == "string" and (.token | type) == "string"' \
    "$TOKF" >/dev/null 2>&1 || refuse "tokenen fra WebUI'en har ikke det rigtige format"
  [[ "$(jq -r .nonce "$TOKF")" == "$nonce" ]] || refuse "tokenen fra WebUI'en hører ikke til denne anmodning"
  tok="$(jq -r .token "$TOKF")" tsig="$(jq -r .sig "$TOKF")"
  [[ "$tok" =~ $TOKEN_RE ]] || { tok=""; refuse "tokenen fra WebUI'en ligner ikke en GitHub-token"; }
  [[ "$tsig" =~ ^[0-9a-f]{64}$ && "$(printf 'tok1|%s|%s' "$nonce" "$tok" |
     openssl dgst -sha256 -mac HMAC -macopt "key:$key" | awk '{print $NF}')" == "$tsig" ]] ||
    { tok=""; refuse "tokenens signatur passer ikke"; }
  TOKEN_SRC=webui
fi
rm -f "$WORK/request.token"
if [[ -n "$tok" ]]; then
  printf 'Authorization: Bearer %s\n' "$tok" >"$WORK/auth.hdr"
fi
unset tok tsig
log "GitHub token: ${TOKEN_SRC:-none}"
current="$(sed -n 's/^VERSION=//p' "$APP/source/deploy/versions.env" 2>/dev/null | tail -n 1)"
[[ -n "$current" ]] || refuse "den kørende version kan ikke læses (source/deploy/versions.env)"
newer_than "$version" "$current" || refuse "$tag er ikke nyere end den installerede $current"

STEP="release"
gh_get "$API/repos/$repo/releases/tags/$tag" "$WORK/release.json"
asset="spamfilter-$version-source.tar.gz"
jq -e --arg t "$tag" '.tag_name == $t and (.draft | not)' "$WORK/release.json" >/dev/null ||
  refuse "udgivelsen $tag findes ikke"
pkg_id="$(jq -r --arg n "$asset" '[.assets[] | select(.name == $n)][0].id // ""' "$WORK/release.json")"
sum_id="$(jq -r --arg n "$asset.sha256" '[.assets[] | select(.name == $n)][0].id // ""' "$WORK/release.json")"
digest="$(jq -r --arg n "$asset" '[.assets[] | select(.name == $n)][0].digest // ""' "$WORK/release.json")"
[[ "$pkg_id" =~ ^[0-9]{1,15}$ && "$sum_id" =~ ^[0-9]{1,15}$ ]] || refuse "udgivelsen har ingen kildepakke med kontrolsum"

STEP="download"
gh_get "$API/repos/$repo/releases/assets/$pkg_id" "$WORK/src.tar.gz" application/octet-stream
gh_get "$API/repos/$repo/releases/assets/$sum_id" "$WORK/src.sha256" application/octet-stream
got="$(sha256sum "$WORK/src.tar.gz" | awk '{print $1}')"
listed="$(awk 'NR == 1 {print $1}' "$WORK/src.sha256")"
[[ "$listed" =~ ^[0-9a-f]{64}$ && "$got" == "$listed" ]] || refuse "kontrolsummen passer ikke med .sha256-filen"
if [[ -n "$digest" ]]; then
  [[ "$digest" == "sha256:$got" ]] || refuse "kontrolsummen passer ikke med GitHubs"
fi
log "sha256 ok: $got"

STEP="signature"
# 2.12 (#16): the .sha256 file must be signed by a key in the RUNNING
# source's deploy/release-signers (ssh-keygen -Y). A wrong signature is
# always refused; a missing one only from RELEASE_SIGNED_SINCE on (older
# releases stay installable). No key there = not checked (as before).
SIGNERS="$APP/source/deploy/release-signers"
SIGNENV="$APP/source/deploy/release-signing.env"
sign_cfg() { [[ -f "$SIGNENV" && ! -L "$SIGNENV" ]] || return 0; sed -n "s/^$1=//p" "$SIGNENV" | tail -n 1 | tr -d "\"' "; }
sign_id="$(sign_cfg RELEASE_SIGN_ID)" sign_ns="$(sign_cfg RELEASE_SIGN_NAMESPACE)" signed_since="$(sign_cfg RELEASE_SIGNED_SINCE)"
sign_id="${sign_id:-spamfilter-release}" sign_ns="${sign_ns:-spamfilter-release}" signed_since="${signed_since:-2.12.1}"
sig_id="$(jq -r --arg n "$asset.sha256.sig" '[.assets[] | select(.name == $n)][0].id // ""' "$WORK/release.json")"
if [[ -f "$SIGNERS" && ! -L "$SIGNERS" ]] && grep -Eq '^[^#[:space:]]' "$SIGNERS"; then
  if [[ -n "$sig_id" ]]; then
    [[ "$sig_id" =~ ^[0-9]{1,15}$ ]] || refuse "udgivelsens signatur har et ugyldigt id"
    command -v ssh-keygen >/dev/null || refuse "ssh-keygen mangler på værten - signaturen kan ikke tjekkes"
    gh_get "$API/repos/$repo/releases/assets/$sig_id" "$WORK/src.sha256.sig" application/octet-stream
    (( $(stat -c %s "$WORK/src.sha256.sig") <= 8192 )) || refuse "signaturen er for stor"
    ssh-keygen -Y verify -f "$SIGNERS" -I "$sign_id" -n "$sign_ns" -s "$WORK/src.sha256.sig" \
      <"$WORK/src.sha256" >/dev/null 2>&1 ||
      refuse "signaturen passer ikke - pakken er ikke underskrevet af udgiveren"
    log "signature ok ($sign_id)"
  elif newer_than "$signed_since" "$version"; then
    log "WARNING: $tag has no signature - accepted (older than $signed_since)"
  else
    refuse "udgivelsen $tag er ikke signeret (.sha256.sig mangler) - kør deploy/sign-release.sh $tag"
  fi
else
  log "no release signing key in source/deploy/release-signers - signature not checked"
fi
rm -f "$WORK/auth.hdr"   # the token is not needed after the download

STEP="unpack"
top_re="^spamfilter-${version//./\\.}(/|\$)"
tar -tzf "$WORK/src.tar.gz" >"$WORK/list"
if grep -Eq '(^/|(^|/)\.\.(/|$))' "$WORK/list" || grep -Evq "$top_re" "$WORK/list"; then
  refuse "kildepakken indeholder ugyldige stier"
fi
tar -tvzf "$WORK/src.tar.gz" | cut -c1 >"$WORK/types"   # to a file: grep -q must not cut the pipe short
if grep -vq '[-d]' "$WORK/types"; then
  refuse "kildepakken indeholder links eller specielle filer"
fi
mkdir "$WORK/src"
tar -xzf "$WORK/src.tar.gz" -C "$WORK/src" --strip-components=1 --no-same-owner
[[ "$(sed -n 's/^VERSION=//p' "$WORK/src/deploy/versions.env" | tail -n 1)" == "$version" ]] ||
  refuse "kildepakken er ikke version $version"
[[ -x "$WORK/src/deploy/aio/update.sh" ]] || refuse "kildepakken mangler deploy/aio/update.sh"
if [[ "$DRY_RUN" == 1 ]]; then
  log "[DRY RUN] $tag verified - would back up source/ and run deploy/aio/update.sh --build"
  exit 0
fi

STEP="source backup"
mkdir -p "$OPS/source-backups"
tar -czf "$OPS/source-backups/source-$STAMP.tar.gz" -C "$APP" source
find "$OPS/source-backups" -maxdepth 1 -name 'source-*.tar.gz' -printf '%T@ %p\n' | sort -rn | tail -n +4 |
  cut -d' ' -f2- | while read -r old; do rm -f -- "$old"; done
rm -rf "$APP/source.new"
cp -a "$WORK/src" "$APP/source.new"
chmod 0755 "$APP/source.new"
chmod -R go-w "$APP/source.new"   # root:root (we are root) and go-w, like a manual copy
INSTALLING=1
mv -T "$APP/source" "$APP/source.prev-$STAMP"
mv -T "$APP/source.new" "$APP/source"

STEP="update.sh"
LOGF="$WORK/update.log"
status koerer "Bygger og installerer $tag (backup, test og automatisk tilbagerulning) …"
SPAMFILTER_APP="$APP" timeout "$TIMEOUT" "$WORK/src/deploy/aio/update.sh" --build >"$LOGF" 2>&1 &
pid=$!
while kill -0 "$pid" 2>/dev/null; do
  sleep 10
  status koerer "Bygger og installerer $tag (backup, test og automatisk tilbagerulning) …" "$LOGF"
done
if wait "$pid"; then rc=0; else rc=$?; fi
cp "$LOGF" "$OPS/update-runner-$STAMP.log" 2>/dev/null || true
if (( rc != 0 )); then
  restore_source
  status fejlet "deploy/aio/update.sh fejlede (exit $rc). Den hidtidige version kører videre eller er rullet tilbage automatisk." "$LOGF"
  notify "Spamfilter: opdatering til $tag fejlede" "update.sh exit $rc - den hidtidige version kører. Log: operations/update-runner-$STAMP.log"
  exit 1
fi
INSTALLING=0
rm -rf "$APP/source.prev-$STAMP"
status faerdig "Opdateret til $tag." "$LOGF"
notify "Spamfilter opdateret" "Version $version kører nu." normal
log "Done: $tag installed."
