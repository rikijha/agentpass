#!/usr/bin/env bash
# Usage: ./run.sh [demo|server|test]
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ]; then
  echo "First run ./setup.sh"; exit 1
fi

case "${1:-demo}" in
  demo)   .venv/bin/python examples/demo.py "${@:2}" ;;
  server) .venv/bin/python -m agentpass "${@:2}" ;;
  test)   .venv/bin/python -m pytest -q "${@:2}" ;;
  *)      echo "Usage: ./run.sh [demo|server|test]"; exit 1 ;;
esac
