#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$DIR/web_app.py"
if [[ "${1:-}" == "--cli" ]]; then
  shift
  SCRIPT="$DIR/check_proxy.py"
elif [[ "${1:-}" == "--reset-key" || "${1:-}" == "--key-only" ]]; then
  SCRIPT="$DIR/check_proxy.py"
fi
if command -v cygpath >/dev/null 2>&1; then
  SCRIPT="$(cygpath -w "$SCRIPT")"
fi
if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' >/dev/null 2>&1; then
  exec python3 "$SCRIPT" "$@"
elif command -v py >/dev/null 2>&1; then
  exec py -3 "$SCRIPT" "$@"
elif command -v python >/dev/null 2>&1 && python -c 'import sys; sys.exit(sys.version_info < (3, 8))' >/dev/null 2>&1; then
  exec python "$SCRIPT" "$@"
else
  echo 'Python 3.8+ is required: https://www.python.org/downloads/' >&2
  exit 1
fi
