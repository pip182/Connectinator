#!/usr/bin/env sh
# Launch Connectinator on Linux or macOS from the project's virtual environment.
cd "$(dirname "$0")" || exit 1
if [ ! -x .venv/bin/python ]; then
    echo "Project virtual environment not found. Run these commands in the project folder first:"
    echo "  python3 -m venv .venv"
    echo "  .venv/bin/python -m pip install -e ."
    exit 1
fi
exec .venv/bin/python -m connectinator "$@"
