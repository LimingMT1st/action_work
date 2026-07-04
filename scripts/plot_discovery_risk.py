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
    parser = argparse.ArgumentParser(description="Plot discovery-risk analysis outputs.")
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


def save_figure(figure, path_stem: Path) -> None:
    path_stem.parent.mkdir(parents=True, exist_ok=True)
    figure.tight_layout()
    figure.savefig(path_stem.with_suffix(".png"))
    figure.clf()


def plot_top_candidates(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    filtered = [row for row in rows if to_float(row.get("discovery_risk_score")) > 0.0][:20]
    if not filtered:
        return False
    ordered = sorted(filtered, key=lambda row: to_float(row.get("discovery_risk_score")), reverse=True)[:15]
    labels = [row.get("full_name", "") for row in ordered][::-1]
    scores = [to_float(row.get("discovery_risk_score")) for row in ordered][::-1]

    figure, axis = plt.subplots(figsize=(8.6, 5.8), dpi=220)
    bars = axis.barh(labels, scores, color="#d95f02", alpha=0.88)
    axis.set_title("Top Discovery-Risk Candidates")
    axis.set_xlabel("Discovery Risk Score")
    axis.set_ylabel("Action Repository")
    axis.grid(True, axis="x", linestyle="--", linewidth=0.6, alpha=0.35)
    for bar, row in zip(bars, ordered[::-1], strict=False):
        axis.text(
            bar.get_width() + 0.6,
            bar.get_y() + bar.get_height() / 2,
            row.get("candidate_type", "none"),
            va="center",
            fontsize=8,
        )
    save_figure(figure, output_dir / "discovery_risk_top_candidates")
    return True


def plot_type_distribution(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    counts = Counter(row.get("candidate_type", "none") for row in rows if row.get("candidate_type", "none") != "none")
    if not counts:
        return False
    labels = list(counts.keys())
    values = [counts[label] for label in labels]

    figure, axis = plt.subplots()
    bars = axis.bar(labels, values, color=["#4e79a7", "#f28e2b", "#e15759", "#76b7b2"][: len(labels)], alpha=0.88)
    axis.set_title("Discovery-Risk Candidate Type Distribution")
    axis.set_xlabel("Candidate Type")
    axis.set_ylabel("Action Count")
    axis.grid(True, axis="y", linestyle="--", linewidth=0.6, alpha=0.35)
    axis.tick_params(axis="x", rotation=15)
    for bar, value in zip(bars, values, strict=False):
        axis.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(value), ha="center", va="bottom", fontsize=8)
    save_figure(figure, output_dir / "discovery_risk_type_distribution")
    return True


def main() -> int:
    args = parse_args()
    analysis_dir = args.analysis_dir.resolve()
    figures_dir = analysis_dir / "figures"

    rows = load_rows(analysis_dir / "discovery_risk_candidates.csv")
    if not rows:
        print("[error] discovery_risk_candidates.csv is missing or empty")
        return 1

    plt = configure_matplotlib()
    generated = []
    if plot_top_candidates(plt, rows, figures_dir):
        generated.append(str(figures_dir / "discovery_risk_top_candidates.png"))
    if plot_type_distribution(plt, rows, figures_dir):
        generated.append(str(figures_dir / "discovery_risk_type_distribution.png"))

    if not generated:
        print("[error] No discovery-risk figures were generated")
        return 1

    print("[ok] Generated discovery-risk figures:")
    for item in generated:
        print(f"  {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
