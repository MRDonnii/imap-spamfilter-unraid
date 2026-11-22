#!/usr/bin/env bash
# Regenerate filter/familieguide.pdf from FAMILIEGUIDE.md (headless Chrome).
# Usage: .build/make-familieguide.sh [--html /tmp/guide.html]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${ROOT}/.venv/bin/python"
[[ -x "$PY" ]] || PY="$(command -v python3)"
exec "$PY" "${ROOT}/.build/make_familieguide.py" "$@"
