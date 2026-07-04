#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-}"
if [[ "$MODE" != "analysis" && "$MODE" != "collection" ]]; then
  echo "Usage: $0 <analysis|collection>" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/logs}"
STATUS_FILE="$LOG_DIR/${MODE}.status.json"
LOG_FILE="$LOG_DIR/${MODE}.log"
VENV_DIR="${VENV_DIR:-${VIRTUAL_ENV:-$ROOT_DIR/.venv}}"
PYTHON_BIN="${PYTHON_BIN:-$VENV_DIR/bin/python}"

mkdir -p "$LOG_DIR"

if [[ ! -d "$VENV_DIR" ]]; then
  echo "Virtualenv not found at $VENV_DIR" >&2
  exit 1
fi

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "Virtualenv python not found or not executable: $PYTHON_BIN" >&2
  exit 1
fi

if [[ "$MODE" == "analysis" ]]; then
  MODULE="gha_cascade_analyzer.analysis_main"
else
  MODULE="gha_cascade_analyzer.main"
fi

write_status() {
  local state="$1"
  local code="$2"
  local message="$3"
  python3 - <<PY
import json
from pathlib import Path
payload = {
    "mode": "$MODE",
    "state": "$state",
    "exit_code": $code,
    "message": "$message",
}
Path(r"$STATUS_FILE").write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
PY
}

notify_if_configured() {
  local state="$1"
  local message="$2"
  if [[ -n "${GHA_NOTIFY_WEBHOOK_URL:-}" ]] && command -v curl >/dev/null 2>&1; then
    curl -sS -X POST "$GHA_NOTIFY_WEBHOOK_URL" \
      -H "Content-Type: application/json" \
      -d "{\"text\":\"GHA-Cascade-Analyzer ${MODE} ${state}: ${message}\"}" >/dev/null || true
  fi
}

preflight_python_env() {
  export PYTHONPATH="${PYTHONPATH:-$ROOT_DIR/src}"
  "$PYTHON_BIN" - <<'PY'
missing = []
for module_name in ("aiohttp", "pydantic", "dotenv", "yaml"):
    try:
        __import__(module_name)
    except Exception:
        missing.append(module_name)
if missing:
    raise SystemExit(
        "Missing required Python packages: "
        + ", ".join(missing)
        + ". Run: pip install -e ."
    )
PY
}

write_status "running" 0 "started"
notify_if_configured "running" "started"

set +e
PRECHECK_OUTPUT="$(preflight_python_env 2>&1)"
PRECHECK_EXIT=$?
set -e
if [[ $PRECHECK_EXIT -ne 0 ]]; then
  echo "$PRECHECK_OUTPUT" >>"$LOG_FILE"
  write_status "failed" "$PRECHECK_EXIT" "$PRECHECK_OUTPUT"
  notify_if_configured "failed" "$PRECHECK_OUTPUT"
  echo "$PRECHECK_OUTPUT" >&2
  exit "$PRECHECK_EXIT"
fi

set +e
(
  export PYTHONPATH="${PYTHONPATH:-$ROOT_DIR/src}"
  cd "$ROOT_DIR"
  "$PYTHON_BIN" -m "$MODULE"
) >>"$LOG_FILE" 2>&1
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -eq 0 ]]; then
  write_status "completed" 0 "finished successfully"
  notify_if_configured "completed" "finished successfully"
else
  write_status "failed" "$EXIT_CODE" "exited with non-zero status"
  notify_if_configured "failed" "exited with code $EXIT_CODE"
fi

exit "$EXIT_CODE"
