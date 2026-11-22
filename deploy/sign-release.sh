#!/bin/bash
# Sign a published release by hand (2.12, #16) - on the owner's machine,
# never on GitHub: downloads spamfilter-X.Y.Z-source.tar.gz and its .sha256,
# checks that they match, signs the .sha256 file with ssh-keygen -Y
# (namespace spamfilter-release) and uploads the .sha256.sig to the release.
#
#   sign-release.sh vX.Y.Z [--key FILE] [--repo OWNER/NAME] [--dry-run]
#
# --key: the private key (default ~/.config/spamfilter-unraid/release-signing/
# spamfilter-release); its public half must be in deploy/release-signers.
# Needs gh (logged in with write access to the repo), ssh-keygen, sha256sum.
set -euo pipefail

tag="" key="${SF_RELEASE_SIGNING_KEY_FILE:-$HOME/.config/spamfilter-unraid/release-signing/spamfilter-release}"
repo="" dry=0
while (( $# )); do
  case "$1" in
    --key) key="${2:?--key needs a file}"; shift ;;
    --repo) repo="${2:?--repo needs OWNER/NAME}"; shift ;;
    --dry-run) dry=1 ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    v[0-9]*) tag="$1" ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: sign-release.sh vX.Y.Z [--key FILE]" >&2; exit 2; }
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
signers="$here/release-signers"
for c in gh ssh-keygen sha256sum; do command -v "$c" >/dev/null || { echo "missing command $c" >&2; exit 1; }; done
[[ -f "$key" ]] || { echo "private key $key not found" >&2; exit 1; }
version="${tag#v}" pkg="spamfilter-${tag#v}-source.tar.gz"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
args=()
[[ -n "$repo" ]] && args=(--repo "$repo")
gh release download "$tag" "${args[@]}" --dir "$work" --pattern "$pkg" --pattern "$pkg.sha256"
(cd "$work" && sha256sum -c "$pkg.sha256")
ssh-keygen -Y sign -q -f "$key" -n spamfilter-release "$work/$pkg.sha256"
ssh-keygen -Y verify -f "$signers" -I spamfilter-release -n spamfilter-release \
  -s "$work/$pkg.sha256.sig" <"$work/$pkg.sha256" >/dev/null
echo "signed $pkg.sha256 of $tag (version $version)"
if (( dry )); then
  echo "[dry-run] would upload $pkg.sha256.sig to $tag"
else
  gh release upload "$tag" "${args[@]}" "$work/$pkg.sha256.sig" --clobber
  echo "uploaded $pkg.sha256.sig to $tag"
fi
