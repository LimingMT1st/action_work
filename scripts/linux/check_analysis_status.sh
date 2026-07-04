#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/logs}"
UNIT_NAME="${UNIT_NAME:-gha-cascade-analysis}"
SESSION_NAME="${SESSION_NAME:-gha-cascade-analysis}"
PID_FILE="$LOG_DIR/analysis.pid"
VENV_DIR="${VENV_DIR:-${VIRTUAL_ENV:-$ROOT_DIR/.venv}}"
PYTHON_BIN="${PYTHON_BIN:-$VENV_DIR/bin/python}"

has_systemd_user_session() {
  [[ -n "${XDG_RUNTIME_DIR:-}" ]] && [[ -S "${XDG_RUNTIME_DIR}/systemd/private" ]]
}

echo "== systemd user unit status =="
if command -v systemctl >/dev/null 2>&1 && has_systemd_user_session; then
  systemctl --user status "$UNIT_NAME" --no-pager || true
else
  echo "systemd user session not available"
fi
echo
echo "== tmux session status =="
if command -v tmux >/dev/null 2>&1; then
  tmux has-session -t "$SESSION_NAME" 2>/dev/null && echo "tmux session $SESSION_NAME is running" || echo "tmux session not found"
else
  echo "tmux not available"
fi
echo
echo "== pid file status =="
if [[ -f "$PID_FILE" ]]; then
  PID="$(cat "$PID_FILE")"
  if ps -p "$PID" >/dev/null 2>&1; then
    echo "nohup pid is running: $PID"
  else
    echo "pid file exists but process is not running: $PID"
  fi
else
  echo "no pid file"
fi
echo
echo "== python environment =="
echo "VENV_DIR=$VENV_DIR"
echo "PYTHON_BIN=$PYTHON_BIN"
echo
echo "== matching processes =="
ps -ef | grep -E 'gha_cascade_analyzer.analysis_main|python -m gha_cascade_analyzer.analysis_main' | grep -v grep || true
echo
echo "== status file =="
cat "$LOG_DIR/analysis.status.json" 2>/dev/null || true
echo
echo "== recent log tail =="
tail -n 40 "$LOG_DIR/analysis.log" 2>/dev/null || true
