from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plot propagation-risk analysis outputs.")
    parser.add_argument(
        "--analysis-dir",
        type=Path,
        default=REPO_ROOT / "data" / "analysis",
        help="Directory containing analysis CSV outputs.",
    )
    return parser.parse_args()


def configure_matplotlib():
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update(
        {
            "figure.figsize": (7.4, 4.8),
            "figure.dpi": 220,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": False,
            "savefig.bbox": "tight",
        }
    )
    return plt


def load_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def to_int(value: str | None, default: int = 0) -> int:
    if value in (None, ""):
        return default
    return int(float(value))


def to_bool(value: str | None) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def to_float(value: str | None, default: float = 0.0) -> float:
    if value in (None, ""):
        return default
    return float(value)


def save_figure(figure, path_stem: Path) -> None:
    path_stem.parent.mkdir(parents=True, exist_ok=True)
    figure.tight_layout()
    figure.savefig(path_stem.with_suffix(".png"))
    figure.clf()


def plot_propagation_channel_distribution(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    if not rows:
        return False
    counts = Counter(to_int(row.get("propagation_channel_count")) for row in rows)
    labels = [str(item) for item in sorted(counts.keys())]
    values = [counts[int(label)] for label in labels]
    figure, axis = plt.subplots()
    bars = axis.bar(labels, values, color="#4e79a7", alpha=0.9)
    axis.set_title("Propagation Channel Count Distribution")
    axis.set_xlabel("Propagation Channel Count")
    axis.set_ylabel("Workflow Count")
    axis.grid(True, axis="y", linestyle="--", linewidth=0.6, alpha=0.35)
    for bar, value in zip(bars, values, strict=False):
        axis.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(value), ha="center", va="bottom", fontsize=8)
    save_figure(figure, output_dir / "propagation_channel_distribution")
    return True


def plot_job_dependency_depth_distribution(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    if not rows:
        return False
    counts = Counter(to_int(row.get("max_job_depth")) for row in rows)
    labels = [str(item) for item in sorted(counts.keys())]
    values = [counts[int(label)] for label in labels]
    figure, axis = plt.subplots()
    bars = axis.bar(labels, values, color="#76b7b2", alpha=0.9)
    axis.set_title("Job Dependency Depth Distribution")
    axis.set_xlabel("Maximum Job Depth")
    axis.set_ylabel("Workflow Count")
    axis.grid(True, axis="y", linestyle="--", linewidth=0.6, alpha=0.35)
    for bar, value in zip(bars, values, strict=False):
        axis.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(value), ha="center", va="bottom", fontsize=8)
    save_figure(figure, output_dir / "job_dependency_depth_distribution")
    return True


def plot_artifact_cache_usage_by_depth(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    if not rows:
        return False
    buckets = {"Depth 0": [], "Depth 1": [], "Depth 2+": []}
    for row in rows:
        depth = to_int(row.get("max_job_depth"))
        if depth <= 0:
            bucket = "Depth 0"
        elif depth == 1:
            bucket = "Depth 1"
        else:
            bucket = "Depth 2+"
        buckets[bucket].append(
            1 if (to_bool(row.get("has_artifact_upload")) or to_bool(row.get("has_artifact_download")) or to_bool(row.get("has_cache_save_restore"))) else 0
        )
    labels = list(buckets.keys())
    values = [sum(items) / len(items) if items else 0.0 for items in buckets.values()]
    figure, axis = plt.subplots()
    axis.bar(labels, values, color="#f28e2b", alpha=0.9)
    axis.set_title("Artifact / Cache Channel Rate by Job Dependency Depth")
    axis.set_xlabel("Job Depth Bucket")
    axis.set_ylabel("Rate")
    axis.set_ylim(0, 1.0)
    axis.grid(True, axis="y", linestyle="--", linewidth=0.6, alpha=0.35)
    save_figure(figure, output_dir / "artifact_cache_usage_by_depth")
    return True


def plot_top_privilege_propagation_workflows(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    filtered = [row for row in rows if to_bool(row.get("privilege_propagation_coupling"))]
    if not filtered:
        return False
    ordered = sorted(filtered, key=lambda row: to_float(row.get("propagation_risk_score")), reverse=True)[:15]
    labels = [f"{row.get('repository_full_name')}::{row.get('workflow_path')}" for row in ordered][::-1]
    values = [to_float(row.get("propagation_risk_score")) for row in ordered][::-1]
    figure, axis = plt.subplots(figsize=(9.0, 5.8), dpi=220)
    bars = axis.barh(labels, values, color="#e15759", alpha=0.9)
    axis.set_title("Top High-Privilege Workflows with Propagation Channels")
    axis.set_xlabel("Propagation Risk Score")
    axis.set_ylabel("Workflow")
    axis.grid(True, axis="x", linestyle="--", linewidth=0.6, alpha=0.35)
    for bar, row in zip(bars, ordered[::-1], strict=False):
        axis.text(
            bar.get_width() + 0.15,
            bar.get_y() + bar.get_height() / 2,
            str(row.get("propagation_channel_count", "0")),
            va="center",
            fontsize=8,
        )
    save_figure(figure, output_dir / "top_privilege_propagation_workflows")
    return True


def main() -> int:
    args = parse_args()
    analysis_dir = args.analysis_dir.resolve()
    figures_dir = analysis_dir / "figures"
    rows = load_rows(analysis_dir / "propagation_risk_by_workflow.csv")
    if not rows:
        print("[error] propagation-risk CSV outputs are missing or empty")
        return 1

    plt = configure_matplotlib()
    generated: list[str] = []
    if plot_propagation_channel_distribution(plt, rows, figures_dir):
        generated.append(str(figures_dir / "propagation_channel_distribution.png"))
    if plot_job_dependency_depth_distribution(plt, rows, figures_dir):
        generated.append(str(figures_dir / "job_dependency_depth_distribution.png"))
    if plot_artifact_cache_usage_by_depth(plt, rows, figures_dir):
        generated.append(str(figures_dir / "artifact_cache_usage_by_depth.png"))
    if plot_top_privilege_propagation_workflows(plt, rows, figures_dir):
        generated.append(str(figures_dir / "top_privilege_propagation_workflows.png"))
    if not generated:
        print("[error] No propagation-risk figures were generated")
        return 1
    print("[ok] Generated propagation-risk figures:")
    for item in generated:
        print(f"  {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
