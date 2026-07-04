#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/logs}"
UNIT_NAME="${UNIT_NAME:-gha-cascade-analysis}"
SESSION_NAME="${SESSION_NAME:-gha-cascade-analysis}"
PID_FILE="$LOG_DIR/analysis.pid"

if command -v systemctl >/dev/null 2>&1; then
  systemctl --user stop "$UNIT_NAME" || true
fi

if command -v tmux >/dev/null 2>&1; then
  tmux kill-session -t "$SESSION_NAME" 2>/dev/null || true
fi

if [[ -f "$PID_FILE" ]]; then
  PID="$(cat "$PID_FILE")"
  kill "$PID" 2>/dev/null || true
  rm -f "$PID_FILE"
fi

echo "Stopped analysis backends if they were running"
