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
    parser = argparse.ArgumentParser(description="Plot isolation-risk analysis outputs.")
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


def plot_mixed_trust_domains_per_job(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    if not rows:
        return False
    counts = Counter()
    for row in rows:
        bucket = str(to_int(row.get("distinct_trust_domains")))
        counts[bucket] += 1
    labels = sorted(counts.keys(), key=lambda item: int(item))
    values = [counts[label] for label in labels]

    figure, axis = plt.subplots()
    bars = axis.bar(labels, values, color="#4e79a7", alpha=0.9)
    axis.set_title("Distinct Trust Domains Per Job")
    axis.set_xlabel("Distinct Trust Domains")
    axis.set_ylabel("Job Count")
    axis.grid(True, axis="y", linestyle="--", linewidth=0.6, alpha=0.35)
    for bar, value in zip(bars, values, strict=False):
        axis.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(value), ha="center", va="bottom", fontsize=8)
    save_figure(figure, output_dir / "mixed_trust_domains_per_job")
    return True


def plot_isolation_signal_distribution(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    if not rows:
        return False
    labels = [
        "mixed_trust_domains",
        "third_party_before_sensitive",
        "env_pollution",
        "output_dependency",
        "filesystem_dependency",
        "shared_workspace",
    ]
    values = [
        sum(1 for row in rows if to_bool(row.get("has_mixed_trust_domains"))),
        sum(1 for row in rows if to_bool(row.get("has_untrusted_action_before_deploy_step"))),
        sum(1 for row in rows if to_bool(row.get("env_pollution_signal"))),
        sum(1 for row in rows if to_bool(row.get("output_dependency_signal"))),
        sum(1 for row in rows if to_bool(row.get("filesystem_dependency_signal"))),
        sum(1 for row in rows if to_bool(row.get("shared_workspace_exposure_signal"))),
    ]
    figure, axis = plt.subplots(figsize=(8.4, 4.8), dpi=220)
    bars = axis.bar(labels, values, color=["#4e79a7", "#e15759", "#76b7b2", "#f28e2b", "#59a14f", "#b07aa1"], alpha=0.9)
    axis.set_title("Weak-Isolation Exposure Signal Distribution")
    axis.set_xlabel("Signal Type")
    axis.set_ylabel("Job Count")
    axis.grid(True, axis="y", linestyle="--", linewidth=0.6, alpha=0.35)
    axis.tick_params(axis="x", rotation=15)
    for bar, value in zip(bars, values, strict=False):
        axis.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(value), ha="center", va="bottom", fontsize=8)
    save_figure(figure, output_dir / "isolation_signal_distribution")
    return True


def plot_third_party_before_sensitive_step_top_examples(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    filtered = [row for row in rows if to_bool(row.get("has_untrusted_action_before_deploy_step"))]
    if not filtered:
        return False
    ordered = sorted(filtered, key=lambda row: to_float(row.get("signal_score")), reverse=True)[:15]
    labels = [f"{row.get('repository_full_name')}::{row.get('job_id')}" for row in ordered][::-1]
    values = [to_float(row.get("signal_score")) for row in ordered][::-1]

    figure, axis = plt.subplots(figsize=(9.0, 5.8), dpi=220)
    bars = axis.barh(labels, values, color="#e15759", alpha=0.9)
    axis.set_title("Top Jobs with Third-Party Actions Before Sensitive Steps")
    axis.set_xlabel("Isolation Signal Score")
    axis.set_ylabel("Workflow Job")
    axis.grid(True, axis="x", linestyle="--", linewidth=0.6, alpha=0.35)
    for bar, row in zip(bars, ordered[::-1], strict=False):
        axis.text(
            bar.get_width() + 0.15,
            bar.get_y() + bar.get_height() / 2,
            str(row.get("third_party_uses_steps_count", "0")),
            va="center",
            fontsize=8,
        )
    save_figure(figure, output_dir / "third_party_before_sensitive_step_top_examples")
    return True


def main() -> int:
    args = parse_args()
    analysis_dir = args.analysis_dir.resolve()
    figures_dir = analysis_dir / "figures"

    by_job_rows = load_rows(analysis_dir / "isolation_risk_by_job.csv")
    example_rows = load_rows(analysis_dir / "isolation_risk_examples.csv")
    if not by_job_rows:
        print("[error] isolation-risk CSV outputs are missing or empty")
        return 1

    plt = configure_matplotlib()
    generated: list[str] = []
    if plot_mixed_trust_domains_per_job(plt, by_job_rows, figures_dir):
        generated.append(str(figures_dir / "mixed_trust_domains_per_job.png"))
    if plot_isolation_signal_distribution(plt, by_job_rows, figures_dir):
        generated.append(str(figures_dir / "isolation_signal_distribution.png"))
    if plot_third_party_before_sensitive_step_top_examples(plt, example_rows or by_job_rows, figures_dir):
        generated.append(str(figures_dir / "third_party_before_sensitive_step_top_examples.png"))

    if not generated:
        print("[error] No isolation-risk figures were generated")
        return 1

    print("[ok] Generated isolation-risk figures:")
    for item in generated:
        print(f"  {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
