#!/bin/bash
# Build the all-in-one image locally on Unraid (2.4).
#
#   build.sh [--dry-run] [--tag IMAGE] [--no-cache] [--context-only DIR]
#
# Stages a minimal build context (runtime code, the AIO runtime files and
# the non-secret config bundle - never tests or rendered secrets), then
#   docker build -t AIO_IMAGE (versions.env) with the pinned ARGs:
#   FILTER_BASE_IMAGE and RSPAMD_IMAGE by digest, Redis from
#   redis:REDIS_AIO_TAG@REDIS_AIO_DIGEST (pinned in versions.env). Only if a
#   site.env empties the digest is the tag pulled once and its digest used
#   AND printed (the release workflow refuses an unpinned build).
# The Dockerfile's last RUN is build-check.sh (versions, rspamd files
# unchanged, libraries, uids, sample configs); afterwards this script checks
# the image labels and that the only VOLUME is /var/lib/rspamd.
# --context-only DIR: only stage the context (+ DIR/build-args.env) - CI.
# Log: operations/aio-build-<stamp>.log.
set -euo pipefail

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; }

tag="" ctx_only="" nocache=()
while (( $# )); do
  case "$1" in
    --dry-run) export DRY_RUN=1 ;;
    --tag) tag="${2:?--tag needs a value}"; shift ;;
    --no-cache) nocache=(--no-cache) ;;
    --context-only) ctx_only="${2:?--context-only needs a directory}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

# shellcheck source=deploy/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

image="${tag:-$AIO_IMAGE}"
if [[ -n "$ctx_only" ]]; then
  mkdir -p "$ctx_only"
  sf_aio_stage_context "$ctx_only"
  sf_aio_build_args >"$ctx_only/build-args.env"
  log "Build context staged in $ctx_only (build args: $ctx_only/build-args.env)"
  exit 0
fi

[[ "$DRY_RUN" == 1 ]] || sf_require_root
sf_require_cmds docker jq flock
sf_lock
sf_aio_tee_log build
log "build: $image (version $VERSION)$([[ "$DRY_RUN" == 1 ]] && echo ' [DRY RUN]')"

redis_ref="$(sf_aio_redis_ref)"
if [[ -z "${REDIS_AIO_DIGEST:-}" ]]; then
  warn "REDIS_AIO_DIGEST is not pinned in versions.env - resolving redis:$REDIS_AIO_TAG"
  qrun docker pull "redis:$REDIS_AIO_TAG"
  if [[ "$DRY_RUN" != 1 ]]; then
    digest="$(docker image inspect "redis:$REDIS_AIO_TAG" | jq -r '.[0].RepoDigests[0] // "" | split("@")[1] // ""')"
    [[ "$digest" == sha256:* ]] || die "could not resolve the digest of redis:$REDIS_AIO_TAG"
    redis_ref="redis:$REDIS_AIO_TAG@$digest"
    log "  using $redis_ref - pin it: REDIS_AIO_DIGEST=$digest (deploy/versions.env)"
  fi
fi

ctx="$(mktemp -d "${TMPDIR:-/tmp}/spamfilter-aio-ctx.XXXXXX")"
trap 'rm -rf "$ctx"' EXIT
sf_aio_stage_context "$ctx"
args=()
while IFS= read -r kv; do
  args+=(--build-arg "$kv")
done < <(sf_aio_build_args "$redis_ref")
log "Building $image (rspamd $AIO_RSPAMD_VERSION, Redis $AIO_REDIS_VERSION, Unbound $AIO_UNBOUND_SERIES.x, Python $AIO_PYTHON_SERIES)"
run docker build "${nocache[@]}" -t "$image" "${args[@]}" -f "$ctx/Dockerfile" "$ctx"

if [[ "$DRY_RUN" == 1 ]]; then
  log "[dry-run] would check the labels and volumes of $image"
  exit 0
fi
json="$(docker image inspect "$image")"
[[ "$(jq -r '.[0].Config.Labels["spamfilter.layout"] // ""' <<<"$json")" == aio ]] || die "$image lacks spamfilter.layout=aio"
[[ "$(jq -r '.[0].Config.Labels["spamfilter.version"] // ""' <<<"$json")" == "$VERSION" ]] || die "$image is not version $VERSION"
vols="$(jq -r '.[0].Config.Volumes // {} | keys | join(" ")' <<<"$json")"
if [[ -n "$vols" && "$vols" != /var/lib/rspamd ]]; then
  die "$image declares VOLUMEs '$vols' - only /var/lib/rspamd is mapped (template path rspamd-data); fix the Dockerfile before using it"
fi
log "Image $image ready: $(jq -r '.[0].Id' <<<"$json" | cut -c1-19), $(( $(jq -r '.[0].Size' <<<"$json") / 1048576 )) MiB"
log "Next: deploy/aio/smoke-test.sh (throwaway container, real data copy, mailboxes untouched)"
