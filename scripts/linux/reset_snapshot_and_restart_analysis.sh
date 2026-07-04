#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DATA_DIR="${DATA_DIR:-$ROOT_DIR/data}"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/logs}"
VENV_DIR="${VENV_DIR:-${VIRTUAL_ENV:-$ROOT_DIR/.venv}}"
PYTHON_BIN="${PYTHON_BIN:-$VENV_DIR/bin/python}"

usage() {
  cat <<'EOF'
Usage: reset_snapshot_and_restart_analysis.sh [--purge-snapshots] [--restart]

Safely reset snapshot-style analysis inputs while preserving time-series data:
  - repositories.jsonl
  - workflows/*.jsonl
  - actions/discovered.jsonl

It preserves:
  - workflow_history/*.jsonl
  - refs/*.jsonl
  - drift_events.jsonl
  - checkpoints.sqlite3

Options:
  --purge-snapshots   Remove snapshot inputs completely instead of de-duplicating them.
  --restart           Restart detached analysis after cleanup.
  --help              Show this message.
EOF
}

PURGE_SNAPSHOTS="false"
RESTART_ANALYSIS="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge-snapshots)
      PURGE_SNAPSHOTS="true"
      shift
      ;;
    --restart)
      RESTART_ANALYSIS="true"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

mkdir -p "$LOG_DIR"

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "Python interpreter not found: $PYTHON_BIN" >&2
  exit 1
fi

stop_existing_analysis() {
  if [[ -x "$ROOT_DIR/scripts/linux/stop_analysis_detached.sh" ]]; then
    "$ROOT_DIR/scripts/linux/stop_analysis_detached.sh" >/dev/null 2>&1 || true
  fi
  pkill -f 'gha_cascade_analyzer.analysis_main' 2>/dev/null || true
}

clear_analysis_logs() {
  : > "$LOG_DIR/analysis.log"
  rm -f "$LOG_DIR/analysis.status.json" "$LOG_DIR/analysis.pid"
}

purge_snapshots() {
  rm -f "$DATA_DIR/repositories.jsonl"
  rm -f "$DATA_DIR/actions/discovered.jsonl"
  if [[ -d "$DATA_DIR/workflows" ]]; then
    find "$DATA_DIR/workflows" -name '*.jsonl' -delete
  fi
}

dedupe_snapshots() {
  export DATA_DIR
  "$PYTHON_BIN" - <<'PY'
import json
from pathlib import Path
import os

data_dir = Path(os.environ["DATA_DIR"])

def load_jsonl(path: Path):
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]

def write_jsonl(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")

repo_path = data_dir / "repositories.jsonl"
repo_rows = load_jsonl(repo_path)
if repo_rows:
    by_repo_id = {}
    for row in repo_rows:
        by_repo_id[row["repo_id"]] = row
    write_jsonl(repo_path, sorted(by_repo_id.values(), key=lambda item: (-int(item.get("stars", 0)), item["full_name"])))
    print(f"repositories.jsonl: {len(repo_rows)} -> {len(by_repo_id)}")
else:
    print("repositories.jsonl: missing or empty")

action_path = data_dir / "actions" / "discovered.jsonl"
action_rows = load_jsonl(action_path)
if action_rows:
    by_action_id = {}
    for row in action_rows:
        by_action_id[row["action_id"]] = row
    write_jsonl(action_path, by_action_id.values())
    print(f"actions/discovered.jsonl: {len(action_rows)} -> {len(by_action_id)}")
else:
    print("actions/discovered.jsonl: missing or empty")

workflow_dir = data_dir / "workflows"
if workflow_dir.exists():
    for path in sorted(workflow_dir.glob("*.jsonl")):
        rows = load_jsonl(path)
        if not rows:
            continue
        deduped = {}
        for row in rows:
            key = (row["repository_full_name"], row["path"], row["sha"])
            deduped[key] = row
        write_jsonl(path, deduped.values())
        print(f"{path.relative_to(data_dir)}: {len(rows)} -> {len(deduped)}")
else:
    print("workflows/: missing")
PY
}

print_snapshot_summary() {
  export DATA_DIR
  "$PYTHON_BIN" - <<'PY'
import json
from pathlib import Path
import os

data_dir = Path(os.environ["DATA_DIR"])

repo_path = data_dir / "repositories.jsonl"
if repo_path.exists():
    rows = [json.loads(line) for line in repo_path.open("r", encoding="utf-8") if line.strip()]
    print(f"repository_rows={len(rows)} unique_repo_ids={len({row['repo_id'] for row in rows})}")
else:
    print("repository_rows=0 unique_repo_ids=0")

workflow_rows = 0
workflow_keys = set()
workflow_sha_keys = set()
workflow_dir = data_dir / "workflows"
if workflow_dir.exists():
    for path in workflow_dir.glob("*.jsonl"):
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                row = json.loads(line)
                workflow_rows += 1
                workflow_keys.add((row["repository_full_name"], row["path"]))
                workflow_sha_keys.add((row["repository_full_name"], row["path"], row["sha"]))
print(
    "workflow_rows="
    f"{workflow_rows} unique_workflow_paths={len(workflow_keys)} unique_workflow_shas={len(workflow_sha_keys)}"
)
PY
}

restart_analysis() {
  if [[ ! -x "$ROOT_DIR/scripts/linux/start_analysis_detached.sh" ]]; then
    echo "Missing start_analysis_detached.sh; cannot restart analysis automatically." >&2
    exit 1
  fi
  "$ROOT_DIR/scripts/linux/start_analysis_detached.sh"
}

echo "Stopping existing analysis processes..."
stop_existing_analysis
echo "Clearing analysis logs..."
clear_analysis_logs

if [[ "$PURGE_SNAPSHOTS" == "true" ]]; then
  echo "Purging snapshot-style inputs..."
  purge_snapshots
else
  echo "De-duplicating snapshot-style inputs..."
  dedupe_snapshots
fi

echo "Snapshot summary after cleanup:"
print_snapshot_summary

if [[ "$RESTART_ANALYSIS" == "true" ]]; then
  echo "Restarting detached analysis..."
  restart_analysis
fi

echo "Done."
