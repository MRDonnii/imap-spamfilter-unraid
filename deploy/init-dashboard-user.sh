#!/bin/bash
# Create the first WebUI login "admin" (fresh installs only) from the
# random password init-host.sh put in operations/dashboard.initial-password.
# Never prints the password.
#
#   init-dashboard-user.sh [--dry-run]
set -euo pipefail

DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/versions.env
. "$DEPLOY_DIR/versions.env"
APP="${SPAMFILTER_APP:-$(d="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." 2>/dev/null && pwd)"
  if [[ -n "$d" && -d "$d/state" && -d "$d/config" ]]; then echo "$d"; else echo /mnt/user/appdata/spamfilter; fi)}"

if [[ -e "$APP/state/dashboard_users" ]]; then
  echo "Dashboard user file already exists; leaving it unchanged"
  exit 0
fi
if [[ "$DRY_RUN" == 1 ]]; then
  echo "[dry-run] would create $APP/state/dashboard_users (user admin) with $FILTER_IMAGE"
  exit 0
fi
docker run --rm --network none --user 0:0 --entrypoint python \
  -v "$APP/operations:/ops:ro" -v "$APP/state:/state" \
  "$FILTER_IMAGE" -c '
import hashlib, pathlib, secrets
p = pathlib.Path("/ops/dashboard.initial-password").read_text().strip()
salt = secrets.token_bytes(16)
digest = hashlib.pbkdf2_hmac("sha256", p.encode(), salt, 600000)
pathlib.Path("/state/dashboard_users").write_text(
    f"admin:pbkdf2$600000${salt.hex()}${digest.hex()}:admin\n")
' >/dev/null
chown "$FILTER_UID:$FILTER_GID" "$APP/state/dashboard_users"
chmod 600 "$APP/state/dashboard_users"
echo "Dashboard login created (username admin; initial password in $APP/operations/dashboard.initial-password)"
