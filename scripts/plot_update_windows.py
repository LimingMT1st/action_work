from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from gha_cascade_analyzer.analyzers.window_plotter import UpdateWindowPlotter
from gha_cascade_analyzer.models import TimeWindowAmplificationMetric, UpdateWindowMetric, UpdateWindowSummaryMetric


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render research-style update-window figures from existing analysis outputs."
    )
    parser.add_argument(
        "--analysis-dir",
        type=Path,
        default=REPO_ROOT / "data" / "analysis",
        help="Directory containing analysis CSV/JSON outputs. Defaults to data/analysis.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Optional figure output directory. Defaults to <analysis-dir>.",
    )
    return parser.parse_args()


def load_models_from_csv(path: Path, model_cls):
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
    return [model_cls.model_validate(row) for row in rows]


def load_models_from_report(report_path: Path, key: str, model_cls):
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    values = payload.get(key, [])
    return [model_cls.model_validate(item) for item in values]


def load_update_window_inputs(
    analysis_dir: Path,
) -> tuple[list[UpdateWindowMetric], list[UpdateWindowSummaryMetric], list[TimeWindowAmplificationMetric]]:
    update_windows_csv = analysis_dir / "update_windows.csv"
    update_window_summary_csv = analysis_dir / "update_window_summary.csv"
    amplification_csv = analysis_dir / "time_window_amplification.csv"
    report_json = analysis_dir / "report.json"

    if update_windows_csv.exists() and update_window_summary_csv.exists() and amplification_csv.exists():
        return (
            load_models_from_csv(update_windows_csv, UpdateWindowMetric),
            load_models_from_csv(update_window_summary_csv, UpdateWindowSummaryMetric),
            load_models_from_csv(amplification_csv, TimeWindowAmplificationMetric),
        )

    if report_json.exists():
        return (
            load_models_from_report(report_json, "update_windows", UpdateWindowMetric),
            load_models_from_report(report_json, "update_window_summary", UpdateWindowSummaryMetric),
            load_models_from_report(report_json, "time_window_amplification", TimeWindowAmplificationMetric),
        )

    raise FileNotFoundError(
        "Could not find update-window analysis inputs. Expected update_windows.csv / update_window_summary.csv / "
        "time_window_amplification.csv or a report.json containing those fields."
    )


def main() -> int:
    args = parse_args()
    analysis_dir = args.analysis_dir.resolve()
    output_dir = (args.output_dir or analysis_dir).resolve()

    if not analysis_dir.exists():
        print(f"[error] analysis directory does not exist: {analysis_dir}")
        return 1

    try:
        update_windows, summaries, amplification = load_update_window_inputs(analysis_dir)
    except FileNotFoundError as exc:
        print(f"[error] {exc}")
        print(
            "[hint] Re-run the updated analysis pipeline first, or point --analysis-dir to a directory that already "
            "contains the new update-window outputs."
        )
        return 1

    if not update_windows and not summaries and not amplification:
        print("[error] Update-window data is present but empty; there is nothing to plot.")
        return 1

    plotter = UpdateWindowPlotter(output_dir)
    plotter.export_all(update_windows, summaries, amplification)

    print("[ok] Figures exported:")
    print(f"  {output_dir / 'figures' / 'update_window_mode_distribution.png'}")
    print(f"  {output_dir / 'figures' / 'update_window_depth_amplification.png'}")
    print(f"  {output_dir / 'figures' / 'update_window_counts_by_depth.png'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
