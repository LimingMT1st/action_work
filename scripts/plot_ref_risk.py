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


REF_ORDER = [
    "FULL_SHA",
    "SHORT_SHA",
    "SEMVER_TAG",
    "MAJOR_TAG",
    "BRANCH_MAIN",
    "BRANCH_OTHER",
    "FLOATING_TAG",
    "UNKNOWN_REF",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plot ref-risk analysis outputs.")
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


def to_float(value: str | None, default: float = 0.0) -> float:
    if value in (None, ""):
        return default
    return float(value)


def to_int(value: str | None, default: int = 0) -> int:
    if value in (None, ""):
        return default
    return int(float(value))


def save_figure(figure, path_stem: Path) -> None:
    path_stem.parent.mkdir(parents=True, exist_ok=True)
    figure.tight_layout()
    figure.savefig(path_stem.with_suffix(".png"))
    figure.clf()


def plot_binding_strategy_distribution(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    if not rows:
        return False
    counts = Counter(row.get("ref_category", "UNKNOWN_REF") for row in rows)
    labels = [label for label in REF_ORDER if counts.get(label, 0) > 0]
    values = [counts[label] for label in labels]
    if not values:
        return False

    figure, axis = plt.subplots(figsize=(8.2, 4.8), dpi=220)
    bars = axis.bar(labels, values, color=["#59a14f", "#8cd17d", "#edc948", "#f28e2b", "#4e79a7", "#e15759", "#b07aa1", "#9d7660"][: len(labels)], alpha=0.9)
    axis.set_title("Binding Strategy Distribution by Ref Resolution Category")
    axis.set_xlabel("Ref Category")
    axis.set_ylabel("Action Count")
    axis.grid(True, axis="y", linestyle="--", linewidth=0.6, alpha=0.35)
    axis.tick_params(axis="x", rotation=20)
    for bar, value in zip(bars, values, strict=False):
        axis.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(value), ha="center", va="bottom", fontsize=8)
    save_figure(figure, output_dir / "binding_strategy_distribution")
    return True


def plot_mutable_ref_by_depth(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    if not rows:
        return False
    order = ["level_1", "level_2", "level_3_plus"]
    labels = ["Depth 1", "Depth 2", "Depth 3+"]
    mutable_values = [to_float(next((row.get("mutable_ref_ratio") for row in rows if row.get("depth_bucket") == bucket), "0")) for bucket in order]
    high_risk_values = [to_float(next((row.get("high_risk_ref_ratio") for row in rows if row.get("depth_bucket") == bucket), "0")) for bucket in order]

    figure, axis = plt.subplots()
    positions = list(range(len(order)))
    width = 0.34
    axis.bar([p - width / 2 for p in positions], mutable_values, width, color="#4e79a7", alpha=0.9, label="Mutable ref ratio")
    axis.bar([p + width / 2 for p in positions], high_risk_values, width, color="#e15759", alpha=0.9, label="High-risk ref ratio")
    axis.set_xticks(positions, labels)
    axis.set_ylim(0, 1.0)
    axis.set_title("Mutable and High-Risk References by Cascade Depth")
    axis.set_xlabel("Depth Bucket")
    axis.set_ylabel("Ratio")
    axis.grid(True, axis="y", linestyle="--", linewidth=0.6, alpha=0.35)
    axis.legend(frameon=False)
    save_figure(figure, output_dir / "mutable_ref_by_depth")
    return True


def plot_observed_drift_ref_types(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    filtered = [row for row in rows if str(row.get("observed_drift", "")).lower() == "true"]
    if not filtered:
        return False
    counts = Counter(row.get("ref_category", "UNKNOWN_REF") for row in filtered)
    labels = [label for label in REF_ORDER if counts.get(label, 0) > 0]
    values = [counts[label] for label in labels]

    figure, axis = plt.subplots(figsize=(8.0, 4.8), dpi=220)
    bars = axis.bar(labels, values, color="#f28e2b", alpha=0.9)
    axis.set_title("Observed Drift Across Ref Resolution Categories")
    axis.set_xlabel("Ref Category")
    axis.set_ylabel("Drifted Action Count")
    axis.grid(True, axis="y", linestyle="--", linewidth=0.6, alpha=0.35)
    axis.tick_params(axis="x", rotation=20)
    for bar, value in zip(bars, values, strict=False):
        axis.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(value), ha="center", va="bottom", fontsize=8)
    save_figure(figure, output_dir / "observed_drift_ref_types")
    return True


def plot_top_mutable_actions_by_blast_radius(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    filtered = [row for row in rows if to_float(row.get("mutable_ref_ratio")) > 0.0]
    if not filtered:
        return False
    ordered = sorted(filtered, key=lambda row: to_float(row.get("blast_radius_weighted_mutability_score")), reverse=True)[:15]
    labels = [f"{row.get('full_name')}@{row.get('ref_name')}" for row in ordered][::-1]
    values = [to_float(row.get("blast_radius_weighted_mutability_score")) for row in ordered][::-1]

    figure, axis = plt.subplots(figsize=(9.0, 5.8), dpi=220)
    bars = axis.barh(labels, values, color="#4c78a8", alpha=0.9)
    axis.set_title("Top Mutable References by Blast-Radius-Weighted Risk")
    axis.set_xlabel("Blast-Radius-Weighted Mutability Score")
    axis.set_ylabel("Action Reference")
    axis.grid(True, axis="x", linestyle="--", linewidth=0.6, alpha=0.35)
    for bar, row in zip(bars, ordered[::-1], strict=False):
        axis.text(
            bar.get_width() + 0.5,
            bar.get_y() + bar.get_height() / 2,
            row.get("ref_category", "UNKNOWN_REF"),
            va="center",
            fontsize=8,
        )
    save_figure(figure, output_dir / "top_mutable_actions_by_blast_radius")
    return True


def main() -> int:
    args = parse_args()
    analysis_dir = args.analysis_dir.resolve()
    figures_dir = analysis_dir / "figures"

    action_rows = load_rows(analysis_dir / "ref_risk_by_action.csv")
    depth_rows = load_rows(analysis_dir / "ref_risk_by_depth.csv")
    if not action_rows and not depth_rows:
        print("[error] ref-risk CSV outputs are missing or empty")
        return 1

    plt = configure_matplotlib()
    generated: list[str] = []
    if plot_binding_strategy_distribution(plt, action_rows, figures_dir):
        generated.append(str(figures_dir / "binding_strategy_distribution.png"))
    if plot_mutable_ref_by_depth(plt, depth_rows, figures_dir):
        generated.append(str(figures_dir / "mutable_ref_by_depth.png"))
    if plot_observed_drift_ref_types(plt, action_rows, figures_dir):
        generated.append(str(figures_dir / "observed_drift_ref_types.png"))
    if plot_top_mutable_actions_by_blast_radius(plt, action_rows, figures_dir):
        generated.append(str(figures_dir / "top_mutable_actions_by_blast_radius.png"))

    if not generated:
        print("[error] No ref-risk figures were generated")
        return 1

    print("[ok] Generated ref-risk figures:")
    for item in generated:
        print(f"  {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
