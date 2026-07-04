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
    parser = argparse.ArgumentParser(description="Plot privilege-risk analysis outputs.")
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


def to_bool(value: str | None) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def save_figure(figure, path_stem: Path) -> None:
    path_stem.parent.mkdir(parents=True, exist_ok=True)
    figure.tight_layout()
    figure.savefig(path_stem.with_suffix(".png"))
    figure.clf()


def plot_permission_type_distribution(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    if not rows:
        return False
    counts = Counter()
    keys = [
        "has_id_token_write",
        "has_contents_write",
        "has_actions_write",
        "has_packages_write",
        "has_deployments_write",
        "has_security_events_write",
        "has_write_all",
    ]
    for key in keys:
        counts[key.replace("has_", "")] = sum(1 for row in rows if to_bool(row.get(key)))
    labels = list(counts.keys())
    values = [counts[label] for label in labels]
    figure, axis = plt.subplots(figsize=(8.6, 4.8), dpi=220)
    bars = axis.bar(labels, values, color="#4e79a7", alpha=0.9)
    axis.set_title("Privilege Signal Distribution Across Workflow Jobs")
    axis.set_xlabel("Permission Signal")
    axis.set_ylabel("Job Count")
    axis.grid(True, axis="y", linestyle="--", linewidth=0.6, alpha=0.35)
    axis.tick_params(axis="x", rotation=20)
    for bar, value in zip(bars, values, strict=False):
        axis.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(value), ha="center", va="bottom", fontsize=8)
    save_figure(figure, output_dir / "permission_type_distribution")
    return True


def plot_privileged_mutable_action_count(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    if not rows:
        return False
    counts = Counter(to_int(row.get("mutable_third_party_action_count")) for row in rows if to_int(row.get("mutable_third_party_action_count")) > 0)
    if not counts:
        return False
    labels = [str(item) for item in sorted(counts.keys())]
    values = [counts[int(label)] for label in labels]
    figure, axis = plt.subplots()
    bars = axis.bar(labels, values, color="#e15759", alpha=0.9)
    axis.set_title("Mutable Third-Party Actions in Privileged Jobs")
    axis.set_xlabel("Mutable Third-Party Action Count")
    axis.set_ylabel("Job Count")
    axis.grid(True, axis="y", linestyle="--", linewidth=0.6, alpha=0.35)
    for bar, value in zip(bars, values, strict=False):
        axis.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(value), ha="center", va="bottom", fontsize=8)
    save_figure(figure, output_dir / "privileged_mutable_action_count")
    return True


def plot_id_token_write_by_depth(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    if not rows:
        return False
    buckets = {"Depth 1": [], "Depth 2": [], "Depth 3+": []}
    for row in rows:
        depth = to_int(row.get("max_depth"))
        if depth <= 1:
            bucket = "Depth 1"
        elif depth == 2:
            bucket = "Depth 2"
        else:
            bucket = "Depth 3+"
        buckets[bucket].append(1 if to_bool(row.get("has_id_token_write")) else 0)
    labels = list(buckets.keys())
    values = [sum(items) / len(items) if items else 0.0 for items in buckets.values()]
    figure, axis = plt.subplots()
    axis.bar(labels, values, color="#76b7b2", alpha=0.9)
    axis.set_title("Workflow Rate of id-token: write by Dependency Depth")
    axis.set_xlabel("Workflow Depth Bucket")
    axis.set_ylabel("Rate")
    axis.set_ylim(0, 1.0)
    axis.grid(True, axis="y", linestyle="--", linewidth=0.6, alpha=0.35)
    save_figure(figure, output_dir / "id_token_write_by_depth")
    return True


def plot_top_privileged_mutable_workflows(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    filtered = [row for row in rows if to_bool(row.get("mutable_third_party_action_with_privilege"))]
    if not filtered:
        return False
    ordered = sorted(filtered, key=lambda row: to_float(row.get("privilege_risk_score")), reverse=True)[:15]
    labels = [f"{row.get('repository_full_name')}::{row.get('workflow_path')}" for row in ordered][::-1]
    values = [to_float(row.get("privilege_risk_score")) for row in ordered][::-1]

    figure, axis = plt.subplots(figsize=(9.0, 5.8), dpi=220)
    bars = axis.barh(labels, values, color="#f28e2b", alpha=0.9)
    axis.set_title("Top Privileged Workflows with Mutable Third-Party Actions")
    axis.set_xlabel("Privilege Risk Score")
    axis.set_ylabel("Workflow")
    axis.grid(True, axis="x", linestyle="--", linewidth=0.6, alpha=0.35)
    for bar, row in zip(bars, ordered[::-1], strict=False):
        axis.text(
            bar.get_width() + 0.15,
            bar.get_y() + bar.get_height() / 2,
            str(row.get("privileged_job_count", "0")),
            va="center",
            fontsize=8,
        )
    save_figure(figure, output_dir / "top_privileged_mutable_workflows")
    return True


def main() -> int:
    args = parse_args()
    analysis_dir = args.analysis_dir.resolve()
    figures_dir = analysis_dir / "figures"

    workflow_rows = load_rows(analysis_dir / "privilege_risk_by_workflow.csv")
    job_rows = load_rows(analysis_dir / "privilege_risk_by_job.csv")
    if not workflow_rows and not job_rows:
        print("[error] privilege-risk CSV outputs are missing or empty")
        return 1

    plt = configure_matplotlib()
    generated: list[str] = []
    if plot_permission_type_distribution(plt, job_rows, figures_dir):
        generated.append(str(figures_dir / "permission_type_distribution.png"))
    if plot_privileged_mutable_action_count(plt, job_rows, figures_dir):
        generated.append(str(figures_dir / "privileged_mutable_action_count.png"))
    if plot_id_token_write_by_depth(plt, workflow_rows, figures_dir):
        generated.append(str(figures_dir / "id_token_write_by_depth.png"))
    if plot_top_privileged_mutable_workflows(plt, workflow_rows, figures_dir):
        generated.append(str(figures_dir / "top_privileged_mutable_workflows.png"))

    if not generated:
        print("[error] No privilege-risk figures were generated")
        return 1

    print("[ok] Generated privilege-risk figures:")
    for item in generated:
        print(f"  {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
