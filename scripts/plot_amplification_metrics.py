from __future__ import annotations

import argparse
import csv
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plot amplification-metric outputs.")
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


def to_float(value: str | None, default: float = 0.0) -> float:
    if value in (None, ""):
        return default
    return float(value)


def save_figure(figure, path_stem: Path) -> None:
    path_stem.parent.mkdir(parents=True, exist_ok=True)
    figure.tight_layout()
    figure.savefig(path_stem.with_suffix(".png"))
    figure.clf()


def plot_fanout_distribution_logscale(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    action_rows = [row for row in rows if row.get("node_kind") == "action"]
    if not action_rows:
        return False
    values = sorted(to_int(row.get("reachable_repository_count")) for row in action_rows)
    if not values:
        return False
    figure, axis = plt.subplots()
    axis.hist(values, bins=min(30, max(5, len(set(values)))), color="#4e79a7", alpha=0.9)
    axis.set_yscale("log")
    axis.set_title("Action Fanout Distribution")
    axis.set_xlabel("Reachable Repository Count")
    axis.set_ylabel("Action Count (log scale)")
    axis.grid(True, axis="y", linestyle="--", linewidth=0.6, alpha=0.35)
    save_figure(figure, output_dir / "fanout_distribution_logscale")
    return True


def plot_depth_vs_fanout_scatter(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    action_rows = [row for row in rows if row.get("node_kind") == "action"]
    if not action_rows:
        return False
    x_values = [to_int(row.get("max_downstream_depth")) for row in action_rows]
    y_values = [to_int(row.get("reachable_repository_count")) for row in action_rows]
    figure, axis = plt.subplots()
    axis.scatter(x_values, y_values, color="#e15759", alpha=0.55, s=18)
    axis.set_title("Depth vs. Fanout for Action Nodes")
    axis.set_xlabel("Maximum Downstream Depth")
    axis.set_ylabel("Reachable Repository Count")
    axis.grid(True, linestyle="--", linewidth=0.6, alpha=0.35)
    save_figure(figure, output_dir / "depth_vs_fanout_scatter")
    return True


def plot_top_actions_cascade_radius(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    action_rows = [row for row in rows if row.get("node_kind") == "action"]
    if not action_rows:
        return False
    ordered = sorted(action_rows, key=lambda row: to_int(row.get("cascade_radius")), reverse=True)[:15]
    labels = [row.get("full_name") or row.get("node_id") or "" for row in ordered][::-1]
    values = [to_int(row.get("cascade_radius")) for row in ordered][::-1]
    figure, axis = plt.subplots(figsize=(8.8, 5.8), dpi=220)
    bars = axis.barh(labels, values, color="#76b7b2", alpha=0.9)
    axis.set_title("Top Actions by Cascade Radius")
    axis.set_xlabel("Cascade Radius")
    axis.set_ylabel("Action")
    axis.grid(True, axis="x", linestyle="--", linewidth=0.6, alpha=0.35)
    for bar, row in zip(bars, ordered[::-1], strict=False):
        axis.text(bar.get_width() + 0.15, bar.get_y() + bar.get_height() / 2, str(row.get("reachable_high_star_repository_count", "0")), va="center", fontsize=8)
    save_figure(figure, output_dir / "top_actions_cascade_radius")
    return True


def plot_action_usage_concentration_lorenz(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    action_rows = [row for row in rows if row.get("node_kind") == "action"]
    if not action_rows:
        return False
    values = sorted(to_int(row.get("reachable_repository_count")) for row in action_rows)
    total = sum(values)
    if total <= 0:
        return False
    cum_values = [0.0]
    running = 0
    for value in values:
        running += value
        cum_values.append(running / total)
    x_values = [index / len(values) for index in range(len(values) + 1)]
    figure, axis = plt.subplots()
    axis.plot(x_values, cum_values, color="#f28e2b", linewidth=2.0)
    axis.plot([0, 1], [0, 1], color="#999999", linestyle="--", linewidth=1.0)
    axis.fill_between(x_values, cum_values, color="#f28e2b", alpha=0.15)
    axis.set_title("Lorenz Curve of Action Usage Concentration")
    axis.set_xlabel("Cumulative Share of Actions")
    axis.set_ylabel("Cumulative Share of Reachable Repositories")
    axis.grid(True, linestyle="--", linewidth=0.6, alpha=0.35)
    save_figure(figure, output_dir / "action_usage_concentration_lorenz")
    return True


def main() -> int:
    args = parse_args()
    analysis_dir = args.analysis_dir.resolve()
    figures_dir = analysis_dir / "figures"
    rows = load_rows(analysis_dir / "amplification_by_node.csv")
    if not rows:
        print("[error] amplification CSV outputs are missing or empty")
        return 1
    plt = configure_matplotlib()
    generated: list[str] = []
    if plot_fanout_distribution_logscale(plt, rows, figures_dir):
        generated.append(str(figures_dir / "fanout_distribution_logscale.png"))
    if plot_depth_vs_fanout_scatter(plt, rows, figures_dir):
        generated.append(str(figures_dir / "depth_vs_fanout_scatter.png"))
    if plot_top_actions_cascade_radius(plt, rows, figures_dir):
        generated.append(str(figures_dir / "top_actions_cascade_radius.png"))
    if plot_action_usage_concentration_lorenz(plt, rows, figures_dir):
        generated.append(str(figures_dir / "action_usage_concentration_lorenz.png"))
    if not generated:
        print("[error] No amplification figures were generated")
        return 1
    print("[ok] Generated amplification figures:")
    for item in generated:
        print(f"  {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
