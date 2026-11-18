#!/usr/bin/env bash
set -euo pipefail
# Launch Connectinator on Linux or macOS from the project's virtual environment.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
PYTHON="$ROOT/.venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then
  echo "Project virtual environment not found."
  echo "Run these commands in the project folder first:"
  echo "  python3 -m venv .venv"
  echo "  .venv/bin/python -m pip install -e ."
  exit 1
fi
if [[ "${1:-}" == "compat" ]]; then
  exec "$PYTHON" scripts/linux_compat_runner.py
fi
if [[ "${1:-}" == "debug" ]]; then
  exec "$PYTHON" -m connectinator
fi
exec "$PYTHON" -m connectinator
