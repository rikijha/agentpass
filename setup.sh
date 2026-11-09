#!/usr/bin/env bash
# One-time setup: creates .venv, installs dependencies, runs the tests.
set -euo pipefail
cd "$(dirname "$0")"

pick_python() {
  for cand in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$cand" >/dev/null 2>&1; then
      if "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
        echo "$cand"; return 0
      fi
    fi
  done
  return 1
}

PY="$(pick_python)" || {
  echo "Python 3.10+ is required. Install it with:  brew install python@3.12"
  exit 1
}
echo "Using $($PY --version) at $(command -v "$PY")"

if [ ! -d .venv ]; then
  "$PY" -m venv .venv
fi
.venv/bin/python -m pip install --upgrade pip --quiet
.venv/bin/python -m pip install -r requirements.txt --quiet
.venv/bin/python -m pip install -e . --quiet --no-deps

echo "Running tests..."
.venv/bin/python -m pytest -q

cat <<'EOF'

Setup complete.
  Demo:    ./run.sh demo
  Server:  ./run.sh server   (dashboard at http://127.0.0.1:8000/)
  Tests:   ./run.sh test
EOF
