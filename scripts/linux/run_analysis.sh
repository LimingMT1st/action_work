#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENV_DIR="${VENV_DIR:-$ROOT_DIR/.venv}"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/logs}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

mkdir -p "$LOG_DIR"

if [[ ! -d "$VENV_DIR" ]]; then
  echo "Virtualenv not found at $VENV_DIR" >&2
  exit 1
fi

source "$VENV_DIR/bin/activate"
export PYTHONPATH="${PYTHONPATH:-$ROOT_DIR/src}"

cd "$ROOT_DIR"
exec "$PYTHON_BIN" -m gha_cascade_analyzer.analysis_main >>"$LOG_DIR/analysis.log" 2>&1
