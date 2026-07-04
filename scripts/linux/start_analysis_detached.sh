#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/logs}"
UNIT_NAME="${UNIT_NAME:-gha-cascade-analysis}"
SESSION_NAME="${SESSION_NAME:-gha-cascade-analysis}"
PID_FILE="$LOG_DIR/analysis.pid"

has_systemd_user_session() {
  [[ -n "${XDG_RUNTIME_DIR:-}" ]] && [[ -S "${XDG_RUNTIME_DIR}/systemd/private" ]]
}

mkdir -p "$LOG_DIR"
cd "$ROOT_DIR"

SELECTED_VENV_DIR="${VENV_DIR:-${VIRTUAL_ENV:-$ROOT_DIR/.venv}}"
RUNNER=(env "VENV_DIR=$SELECTED_VENV_DIR" "LOG_DIR=$LOG_DIR" "$ROOT_DIR/scripts/linux/run_with_status.sh" analysis)

if command -v systemd-run >/dev/null 2>&1 && has_systemd_user_session; then
  systemd-run --user \
    --unit="$UNIT_NAME" \
    --same-dir \
    --collect \
    --property=WorkingDirectory="$ROOT_DIR" \
    "${RUNNER[@]}"
  echo "Started detached analysis with systemd-run: $UNIT_NAME"
elif command -v tmux >/dev/null 2>&1; then
  tmux new-session -d -s "$SESSION_NAME" "${RUNNER[*]}"
  echo "Started detached analysis with tmux session: $SESSION_NAME"
  echo "Attach with: tmux attach -t $SESSION_NAME"
else
  nohup "${RUNNER[@]}" >/dev/null 2>&1 &
  echo $! >"$PID_FILE"
  echo "Started detached analysis with nohup, pid=$(cat "$PID_FILE")"
fi

echo "Follow logs with:"
echo "  tail -f $LOG_DIR/analysis.log"
echo "Check status with:"
echo "  $ROOT_DIR/scripts/linux/check_analysis_status.sh"
