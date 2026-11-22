#!/bin/bash
# (Re)install the Unraid User Scripts that run the spamfilter host jobs:
#   Spamfilter-backup   0 3 * * *    body of deploy/backup-and-verify.sh
#   Spamfilter-offsite  45 3 * * *   body of deploy/backup-offsite.sh (2.6: the
#                                    encrypted nightly backups -> rclone remote)
#   Spamfilter-monitor  */5 * * * *  body of deploy/host-monitor.sh (status,
#                                    alerts and the daily 07:00 digest; also
#                                    by mail via the filter's mailer when a
#                                    mail server is set up - 2.3)
#   Spamfilter-update   * * * * *    body of deploy/update-runner.sh (2.10: installs
#                                    the version an admin chose under
#                                    Opdateringer in the WebUI; idle otherwise)
#
#   install-user-scripts.sh [--dry-run]
#
# The script bodies are copied INLINE into /boot/config/plugins/user.scripts
# (never `exec` from appdata), so files on the appdata share cannot change
# what root runs from cron. customSchedule.cron and schedule.json are
# backed up to operations/ before they are changed; entries use exactly
# the plugin's format. Re-run after changing either script.
set -euo pipefail

while (( $# )); do
  case "$1" in
    --dry-run) export DRY_RUN=1 ;;
    -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

# shellcheck source=deploy/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ "$DRY_RUN" == 1 ]] || sf_require_root
sf_require_cmds jq awk cmp
sf_require_app
sf_install_user_scripts
log "Done."
