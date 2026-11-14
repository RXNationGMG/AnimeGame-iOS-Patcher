#!/usr/bin/env sh
# Genshin Impact - iOS RSA Patcher (macOS / Linux launcher)
set -e
cd "$(dirname "$0")"

if command -v python3 >/dev/null 2>&1; then
    PY=python3
elif command -v python >/dev/null 2>&1; then
    PY=python
else
    echo "Python 3.10+ is required: https://www.python.org/downloads/"
    exit 1
fi

if ! "$PY" -c "import numpy, capstone, keystone" >/dev/null 2>&1; then
    echo "Installing the packages this tool needs (one time only)..."
    "$PY" -m pip install --user --disable-pip-version-check -r requirements.txt
fi

exec "$PY" rsa_patch.py "$@"
