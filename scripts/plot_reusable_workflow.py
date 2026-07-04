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
    parser = argparse.ArgumentParser(description="Plot reusable-workflow analysis outputs.")
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


def save_figure(figure, path_stem: Path) -> None:
    path_stem.parent.mkdir(parents=True, exist_ok=True)
    figure.tight_layout()
    figure.savefig(path_stem.with_suffix(".png"))
    figure.clf()


def plot_reusable_workflow_usage_distribution(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    if not rows:
        return False
    counts = Counter(to_int(row.get("downstream_repo_count")) for row in rows)
    labels = [str(item) for item in sorted(counts.keys())]
    values = [counts[int(label)] for label in labels]
    figure, axis = plt.subplots()
    axis.bar(labels, values, color="#4e79a7", alpha=0.9)
    axis.set_title("Reusable Workflow Usage Distribution")
    axis.set_xlabel("Downstream Repository Count")
    axis.set_ylabel("Callee Count")
    axis.grid(True, axis="y", linestyle="--", linewidth=0.6, alpha=0.35)
    save_figure(figure, output_dir / "reusable_workflow_usage_distribution")
    return True


def plot_top_reusable_workflows_by_downstream(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    if not rows:
        return False
    ordered = sorted(rows, key=lambda row: to_int(row.get("downstream_repo_count")), reverse=True)[:15]
    labels = [row.get("callee_identifier", "") for row in ordered][::-1]
    values = [to_int(row.get("downstream_repo_count")) for row in ordered][::-1]
    figure, axis = plt.subplots(figsize=(9.0, 5.8), dpi=220)
    axis.barh(labels, values, color="#76b7b2", alpha=0.9)
    axis.set_title("Top Reusable Workflows by Downstream Repositories")
    axis.set_xlabel("Downstream Repository Count")
    axis.set_ylabel("Reusable Workflow")
    axis.grid(True, axis="x", linestyle="--", linewidth=0.6, alpha=0.35)
    save_figure(figure, output_dir / "top_reusable_workflows_by_downstream")
    return True


def plot_reusable_workflow_ref_type_distribution(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    if not rows:
        return False
    counts = Counter(row.get("ref_type", "UNKNOWN") for row in rows)
    labels = list(counts.keys())
    values = [counts[label] for label in labels]
    figure, axis = plt.subplots()
    axis.bar(labels, values, color="#f28e2b", alpha=0.9)
    axis.set_title("Reusable Workflow Reference Type Distribution")
    axis.set_xlabel("Reference Type")
    axis.set_ylabel("Edge Count")
    axis.tick_params(axis="x", rotation=20)
    axis.grid(True, axis="y", linestyle="--", linewidth=0.6, alpha=0.35)
    save_figure(figure, output_dir / "reusable_workflow_ref_type_distribution")
    return True


def plot_secrets_inherit_reusable_workflows(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    filtered = [row for row in rows if to_int(row.get("secrets_inherit_count")) > 0]
    if not filtered:
        return False
    ordered = sorted(filtered, key=lambda row: to_int(row.get("secrets_inherit_count")), reverse=True)[:15]
    labels = [row.get("callee_identifier", "") for row in ordered][::-1]
    values = [to_int(row.get("secrets_inherit_count")) for row in ordered][::-1]
    figure, axis = plt.subplots(figsize=(9.0, 5.8), dpi=220)
    axis.barh(labels, values, color="#e15759", alpha=0.9)
    axis.set_title("Reusable Workflows with secrets: inherit")
    axis.set_xlabel("secrets: inherit Edge Count")
    axis.set_ylabel("Reusable Workflow")
    axis.grid(True, axis="x", linestyle="--", linewidth=0.6, alpha=0.35)
    save_figure(figure, output_dir / "secrets_inherit_reusable_workflows")
    return True


def main() -> int:
    args = parse_args()
    analysis_dir = args.analysis_dir.resolve()
    figures_dir = analysis_dir / "figures"
    edge_rows = load_rows(analysis_dir / "reusable_workflow_edges.csv")
    top_rows = load_rows(analysis_dir / "reusable_workflow_top_callees.csv")
    if not edge_rows and not top_rows:
        print("[error] reusable-workflow CSV outputs are missing or empty")
        return 1
    plt = configure_matplotlib()
    generated: list[str] = []
    if plot_reusable_workflow_usage_distribution(plt, top_rows, figures_dir):
        generated.append(str(figures_dir / "reusable_workflow_usage_distribution.png"))
    if plot_top_reusable_workflows_by_downstream(plt, top_rows, figures_dir):
        generated.append(str(figures_dir / "top_reusable_workflows_by_downstream.png"))
    if plot_reusable_workflow_ref_type_distribution(plt, edge_rows, figures_dir):
        generated.append(str(figures_dir / "reusable_workflow_ref_type_distribution.png"))
    if plot_secrets_inherit_reusable_workflows(plt, top_rows, figures_dir):
        generated.append(str(figures_dir / "secrets_inherit_reusable_workflows.png"))
    if not generated:
        print("[error] No reusable-workflow figures were generated")
        return 1
    print("[ok] Generated reusable-workflow figures:")
    for item in generated:
        print(f"  {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
