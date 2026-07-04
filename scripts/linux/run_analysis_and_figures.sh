#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENV_DIR="${VENV_DIR:-${VIRTUAL_ENV:-$ROOT_DIR/.venv}}"
PYTHON_BIN="${PYTHON_BIN:-$VENV_DIR/bin/python}"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/logs}"
ANALYSIS_DIR="${ANALYSIS_DIR:-$ROOT_DIR/data/analysis}"
PLOT_SECTION4="${PLOT_SECTION4:-1}"
PLOT_PAPER="${PLOT_PAPER:-1}"

mkdir -p "$LOG_DIR"

if [[ ! -d "$VENV_DIR" ]]; then
  echo "Virtualenv not found at $VENV_DIR" >&2
  exit 1
fi

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "Virtualenv python not found or not executable: $PYTHON_BIN" >&2
  exit 1
fi

export PYTHONPATH="${PYTHONPATH:-$ROOT_DIR/src}"

run_step() {
  local label="$1"
  shift
  echo "== $label =="
  "$@"
  echo
}

cd "$ROOT_DIR"

run_step "Analysis" "$PYTHON_BIN" -m gha_cascade_analyzer.analysis_main

if [[ "$PLOT_SECTION4" == "1" ]]; then
  run_step "Section 4 Figures" "$PYTHON_BIN" scripts/plot_section4_figures.py --analysis-dir "$ANALYSIS_DIR"
fi

if [[ "$PLOT_PAPER" == "1" ]]; then
  run_step "Paper Figures" "$PYTHON_BIN" scripts/plot_paper_figures.py --analysis-dir "$ANALYSIS_DIR"
fi

echo "== Export Check =="
if [[ -f "$ANALYSIS_DIR/export_failures.csv" && -s "$ANALYSIS_DIR/export_failures.csv" ]]; then
  echo "Some artifacts failed to export:"
  cat "$ANALYSIS_DIR/export_failures.csv"
else
  echo "No export_failures.csv issues detected."
fi
echo

echo "== Key Outputs =="
for path in \
  "$ANALYSIS_DIR/report.json" \
  "$ANALYSIS_DIR/ref_risk_summary.csv" \
  "$ANALYSIS_DIR/privilege_risk_summary.csv" \
  "$ANALYSIS_DIR/propagation_risk_summary.csv" \
  "$ANALYSIS_DIR/trust_amplification_summary.csv" \
  "$ANALYSIS_DIR/section4_figures" \
  "$ANALYSIS_DIR/paper_figures"
do
  if [[ -e "$path" ]]; then
    echo "[ok] $path"
  else
    echo "[missing] $path"
  fi
done
