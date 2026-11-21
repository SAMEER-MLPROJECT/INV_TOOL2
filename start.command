#!/usr/bin/env bash
# Double-click on macOS (start.command) or run ./start.command on Linux. Add --uno for the UNO Q.
cd "$(dirname "$0")"
PY=$(command -v python3 || command -v python)
if [ -z "$PY" ]; then echo "Python 3.11+ not found: install it from https://www.python.org/downloads/"; read -r _; exit 1; fi
exec "$PY" start.py "$@"
