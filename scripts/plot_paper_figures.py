from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from gha_cascade_analyzer.analyzers.window_plotter import UpdateWindowPlotter
from gha_cascade_analyzer.models import TimeWindowAmplificationMetric, UpdateWindowMetric, UpdateWindowSummaryMetric


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate publication-style figures from GHA-Cascade-Analyzer outputs."
    )
    parser.add_argument(
        "--analysis-dir",
        type=Path,
        default=REPO_ROOT / "data" / "analysis",
        help="Directory containing analysis CSV outputs. Defaults to data/analysis.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory where figures will be written. Defaults to <analysis-dir>/paper_figures.",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=12,
        help="Top-k actions to show in the blast-radius figure. Defaults to 12.",
    )
    return parser.parse_args()


def configure_matplotlib():
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update(
        {
            "figure.figsize": (7.2, 4.6),
            "figure.dpi": 220,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": False,
            "axes.titlesize": 13,
            "axes.labelsize": 11,
            "xtick.labelsize": 9,
            "ytick.labelsize": 9,
            "legend.fontsize": 9,
            "font.size": 10,
            "savefig.bbox": "tight",
        }
    )
    return plt


def load_csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader)


def to_float(value: str | None, default: float = 0.0) -> float:
    if value in (None, ""):
        return default
    return float(value)


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


def plot_implicit_dependency_ecdf(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    if not rows:
        return False
    values = sorted(to_float(row.get("implicit_dependency_ratio")) for row in rows)
    if not values:
        return False
    y_values = [(index + 1) / len(values) for index in range(len(values))]

    figure, axis = plt.subplots()
    axis.plot(values, y_values, color="#1f77b4", linewidth=2.0)
    axis.fill_between(values, y_values, color="#1f77b4", alpha=0.15)
    axis.set_title("Distribution of Implicit Dependency Ratios")
    axis.set_xlabel("Implicit Dependency Ratio")
    axis.set_ylabel("ECDF")
    axis.grid(True, linestyle="--", linewidth=0.6, alpha=0.35)
    axis.set_xlim(0, max(1.0, max(values)))
    axis.set_ylim(0, 1.02)

    nonzero = sum(1 for value in values if value > 0)
    mean_value = mean(values)
    axis.text(
        0.98,
        0.08,
        f"workflows={len(values)}\nnonzero={nonzero}\nmean={mean_value:.3f}",
        ha="right",
        va="bottom",
        transform=axis.transAxes,
        fontsize=9,
        bbox={"facecolor": "white", "edgecolor": "#cccccc", "alpha": 0.9},
    )
    save_figure(figure, output_dir / "implicit_dependency_ratio_ecdf")
    return True


def plot_depth_distribution(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    if not rows:
        return False
    bucket_counts = Counter()
    token_counts = Counter()
    for row in rows:
        depth = to_int(row.get("max_depth"))
        if depth <= 0:
            bucket = "0"
        elif depth == 1:
            bucket = "1"
        elif depth == 2:
            bucket = "2"
        else:
            bucket = "3+"
        bucket_counts[bucket] += 1
        if to_bool(row.get("has_token_access")):
            token_counts[bucket] += 1

    order = ["0", "1", "2", "3+"]
    counts = [bucket_counts[b] for b in order]
    token_rates = [
        (token_counts[b] / bucket_counts[b] * 100.0) if bucket_counts[b] else 0.0
        for b in order
    ]

    figure, axis = plt.subplots()
    bars = axis.bar(order, counts, color="#4c78a8", alpha=0.85)
    axis.set_title("Cascade Depth Distribution Across Workflows")
    axis.set_xlabel("Maximum Dependency Depth")
    axis.set_ylabel("Workflow Count")
    axis.grid(True, axis="y", linestyle="--", linewidth=0.6, alpha=0.35)
    for bar, count in zip(bars, counts, strict=False):
        axis.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(count), ha="center", va="bottom", fontsize=9)

    axis_right = axis.twinx()
    axis_right.plot(order, token_rates, color="#d62728", marker="o", linewidth=1.8)
    axis_right.set_ylabel("Token-Access Workflow Rate (%)", color="#d62728")
    axis_right.tick_params(axis="y", colors="#d62728")

    save_figure(figure, output_dir / "cascade_depth_distribution")
    return True


def plot_binding_by_depth(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    if not rows:
        return False
    grouped_sha: dict[str, list[float]] = defaultdict(list)
    grouped_tag: dict[str, list[float]] = defaultdict(list)
    grouped_branch: dict[str, list[float]] = defaultdict(list)
    grouped_main: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        depth = to_int(row.get("max_depth"))
        if depth <= 1:
            bucket = "Depth 0-1"
        elif depth == 2:
            bucket = "Depth 2"
        else:
            bucket = "Depth 3+"
        grouped_sha[bucket].append(to_float(row.get("sha_binding_rate")))
        grouped_tag[bucket].append(to_float(row.get("tag_binding_rate")))
        grouped_branch[bucket].append(to_float(row.get("branch_binding_rate")))
        grouped_main[bucket].append(to_float(row.get("main_binding_rate")))

    order = ["Depth 0-1", "Depth 2", "Depth 3+"]
    sha_values = [mean(grouped_sha[bucket]) if grouped_sha[bucket] else 0.0 for bucket in order]
    tag_values = [mean(grouped_tag[bucket]) if grouped_tag[bucket] else 0.0 for bucket in order]
    branch_values = [mean(grouped_branch[bucket]) if grouped_branch[bucket] else 0.0 for bucket in order]
    main_values = [mean(grouped_main[bucket]) if grouped_main[bucket] else 0.0 for bucket in order]

    figure, axis = plt.subplots()
    positions = list(range(len(order)))
    width = 0.2
    axis.bar([position - 1.5 * width for position in positions], sha_values, width, label="SHA", color="#59a14f", alpha=0.85)
    axis.bar([position - 0.5 * width for position in positions], tag_values, width, label="Tag", color="#e15759", alpha=0.85)
    axis.bar([position + 0.5 * width for position in positions], branch_values, width, label="Branch", color="#4e79a7", alpha=0.85)
    axis.bar([position + 1.5 * width for position in positions], main_values, width, label="@main", color="#f28e2b", alpha=0.9)
    axis.set_xticks(positions, order)
    axis.set_ylim(0, 1.0)
    axis.set_title("Binding Strategy Across Dependency Depth")
    axis.set_xlabel("Workflow Depth Bucket")
    axis.set_ylabel("Mean Binding Rate")
    axis.grid(True, axis="y", linestyle="--", linewidth=0.6, alpha=0.35)
    axis.legend(frameon=False)

    save_figure(figure, output_dir / "binding_strategy_by_depth")
    return True


def plot_blast_radius_topk(plt, rows: list[dict[str, str]], output_dir: Path, top_k: int) -> bool:
    if not rows:
        return False
    sorted_rows = sorted(
        rows,
        key=lambda row: (
            to_int(row.get("downstream_high_star_repository_count")),
            to_int(row.get("downstream_high_star_coverage")),
        ),
        reverse=True,
    )[:top_k]
    labels = [f"{row.get('owner')}/{row.get('repo')}" for row in sorted_rows][::-1]
    counts = [to_int(row.get("downstream_high_star_repository_count")) for row in sorted_rows][::-1]
    coverage_m = [to_int(row.get("downstream_high_star_coverage")) / 1_000_000 for row in sorted_rows][::-1]

    figure, axis = plt.subplots(figsize=(8.6, 5.2), dpi=220)
    bars = axis.barh(labels, counts, color="#4c78a8", alpha=0.85)
    axis.set_title(f"Top-{len(sorted_rows)} Blast-Radius Actions")
    axis.set_xlabel("Downstream High-Star Repository Count")
    axis.set_ylabel("Action")
    axis.grid(True, axis="x", linestyle="--", linewidth=0.6, alpha=0.35)
    for bar, coverage in zip(bars, coverage_m, strict=False):
        axis.text(
            bar.get_width() + 0.2,
            bar.get_y() + bar.get_height() / 2,
            f"{coverage:.1f}M stars",
            va="center",
            fontsize=8,
        )

    save_figure(figure, output_dir / "blast_radius_top_actions")
    return True


def maybe_plot_update_windows(analysis_dir: Path, output_dir: Path) -> list[str]:
    update_windows_path = analysis_dir / "update_windows.csv"
    summary_path = analysis_dir / "update_window_summary.csv"
    amplification_path = analysis_dir / "time_window_amplification.csv"
    if not (update_windows_path.exists() and summary_path.exists() and amplification_path.exists()):
        return []
    if any(path.stat().st_size == 0 for path in (update_windows_path, summary_path, amplification_path)):
        return []

    update_windows = load_csv_rows(update_windows_path)
    summaries = load_csv_rows(summary_path)
    amplification = load_csv_rows(amplification_path)
    if not update_windows and not summaries and not amplification:
        return []

    update_window_models = [UpdateWindowMetric.model_validate(_normalize_empty_fields(row)) for row in update_windows]
    summary_models = [UpdateWindowSummaryMetric.model_validate(_normalize_empty_fields(row)) for row in summaries]
    amplification_models = [TimeWindowAmplificationMetric.model_validate(_normalize_empty_fields(row)) for row in amplification]
    plotter = UpdateWindowPlotter(output_dir)
    plotter.export_all(update_window_models, summary_models, amplification_models)
    return [
        str(output_dir / "figures" / "update_window_mode_distribution.png"),
        str(output_dir / "figures" / "update_window_depth_amplification.png"),
        str(output_dir / "figures" / "update_window_counts_by_depth.png"),
    ]


def maybe_plot_discovery_risk(plt, analysis_dir: Path, output_dir: Path) -> list[str]:
    from plot_discovery_risk import plot_top_candidates, plot_type_distribution

    risk_rows = load_csv_rows(analysis_dir / "discovery_risk_candidates.csv")
    if not risk_rows:
        return []

    figures_dir = output_dir / "figures"
    generated: list[str] = []
    if plot_top_candidates(plt, risk_rows, figures_dir):
        generated.append(str(figures_dir / "discovery_risk_top_candidates.png"))
    if plot_type_distribution(plt, risk_rows, figures_dir):
        generated.append(str(figures_dir / "discovery_risk_type_distribution.png"))
    return generated


def _normalize_empty_fields(row: dict[str, str]) -> dict[str, str | None]:
    return {
        key: (None if value == "" else value)
        for key, value in row.items()
    }


def maybe_plot_ref_risk(plt, analysis_dir: Path, output_dir: Path) -> list[str]:
    from plot_ref_risk import (
        plot_binding_strategy_distribution,
        plot_mutable_ref_by_depth,
        plot_observed_drift_ref_types,
        plot_top_mutable_actions_by_blast_radius,
    )

    action_rows = load_csv_rows(analysis_dir / "ref_risk_by_action.csv")
    depth_rows = load_csv_rows(analysis_dir / "ref_risk_by_depth.csv")
    if not action_rows and not depth_rows:
        return []

    figures_dir = output_dir / "figures"
    generated: list[str] = []
    if plot_binding_strategy_distribution(plt, action_rows, figures_dir):
        generated.append(str(figures_dir / "binding_strategy_distribution.png"))
    if plot_mutable_ref_by_depth(plt, depth_rows, figures_dir):
        generated.append(str(figures_dir / "mutable_ref_by_depth.png"))
    if plot_observed_drift_ref_types(plt, action_rows, figures_dir):
        generated.append(str(figures_dir / "observed_drift_ref_types.png"))
    if plot_top_mutable_actions_by_blast_radius(plt, action_rows, figures_dir):
        generated.append(str(figures_dir / "top_mutable_actions_by_blast_radius.png"))
    return generated


def maybe_plot_isolation_risk(plt, analysis_dir: Path, output_dir: Path) -> list[str]:
    from plot_isolation_risk import (
        plot_isolation_signal_distribution,
        plot_mixed_trust_domains_per_job,
        plot_third_party_before_sensitive_step_top_examples,
    )

    by_job_rows = load_csv_rows(analysis_dir / "isolation_risk_by_job.csv")
    example_rows = load_csv_rows(analysis_dir / "isolation_risk_examples.csv")
    if not by_job_rows:
        return []

    figures_dir = output_dir / "figures"
    generated: list[str] = []
    if plot_mixed_trust_domains_per_job(plt, by_job_rows, figures_dir):
        generated.append(str(figures_dir / "mixed_trust_domains_per_job.png"))
    if plot_isolation_signal_distribution(plt, by_job_rows, figures_dir):
        generated.append(str(figures_dir / "isolation_signal_distribution.png"))
    if plot_third_party_before_sensitive_step_top_examples(plt, example_rows or by_job_rows, figures_dir):
        generated.append(str(figures_dir / "third_party_before_sensitive_step_top_examples.png"))
    return generated


def maybe_plot_privilege_risk(plt, analysis_dir: Path, output_dir: Path) -> list[str]:
    from plot_privilege_risk import (
        plot_id_token_write_by_depth,
        plot_permission_type_distribution,
        plot_privileged_mutable_action_count,
        plot_top_privileged_mutable_workflows,
    )

    workflow_rows = load_csv_rows(analysis_dir / "privilege_risk_by_workflow.csv")
    job_rows = load_csv_rows(analysis_dir / "privilege_risk_by_job.csv")
    if not workflow_rows and not job_rows:
        return []

    figures_dir = output_dir / "figures"
    generated: list[str] = []
    if plot_permission_type_distribution(plt, job_rows, figures_dir):
        generated.append(str(figures_dir / "permission_type_distribution.png"))
    if plot_privileged_mutable_action_count(plt, job_rows, figures_dir):
        generated.append(str(figures_dir / "privileged_mutable_action_count.png"))
    if plot_id_token_write_by_depth(plt, workflow_rows, figures_dir):
        generated.append(str(figures_dir / "id_token_write_by_depth.png"))
    if plot_top_privileged_mutable_workflows(plt, workflow_rows, figures_dir):
        generated.append(str(figures_dir / "top_privileged_mutable_workflows.png"))
    return generated


def maybe_plot_propagation_risk(plt, analysis_dir: Path, output_dir: Path) -> list[str]:
    from plot_propagation_risk import (
        plot_artifact_cache_usage_by_depth,
        plot_job_dependency_depth_distribution,
        plot_propagation_channel_distribution,
        plot_top_privilege_propagation_workflows,
    )

    rows = load_csv_rows(analysis_dir / "propagation_risk_by_workflow.csv")
    if not rows:
        return []

    figures_dir = output_dir / "figures"
    generated: list[str] = []
    if plot_propagation_channel_distribution(plt, rows, figures_dir):
        generated.append(str(figures_dir / "propagation_channel_distribution.png"))
    if plot_job_dependency_depth_distribution(plt, rows, figures_dir):
        generated.append(str(figures_dir / "job_dependency_depth_distribution.png"))
    if plot_artifact_cache_usage_by_depth(plt, rows, figures_dir):
        generated.append(str(figures_dir / "artifact_cache_usage_by_depth.png"))
    if plot_top_privilege_propagation_workflows(plt, rows, figures_dir):
        generated.append(str(figures_dir / "top_privilege_propagation_workflows.png"))
    return generated


def maybe_plot_amplification_metrics(plt, analysis_dir: Path, output_dir: Path) -> list[str]:
    from plot_amplification_metrics import (
        plot_action_usage_concentration_lorenz,
        plot_depth_vs_fanout_scatter,
        plot_fanout_distribution_logscale,
        plot_top_actions_cascade_radius,
    )

    rows = load_csv_rows(analysis_dir / "amplification_by_node.csv")
    if not rows:
        return []
    figures_dir = output_dir / "figures"
    generated: list[str] = []
    if plot_fanout_distribution_logscale(plt, rows, figures_dir):
        generated.append(str(figures_dir / "fanout_distribution_logscale.png"))
    if plot_depth_vs_fanout_scatter(plt, rows, figures_dir):
        generated.append(str(figures_dir / "depth_vs_fanout_scatter.png"))
    if plot_top_actions_cascade_radius(plt, rows, figures_dir):
        generated.append(str(figures_dir / "top_actions_cascade_radius.png"))
    if plot_action_usage_concentration_lorenz(plt, rows, figures_dir):
        generated.append(str(figures_dir / "action_usage_concentration_lorenz.png"))
    return generated


def maybe_plot_trust_amplification(plt, analysis_dir: Path, output_dir: Path) -> list[str]:
    from plot_trust_amplification import (
        plot_mutable_ratio_by_trust_entity,
        plot_privilege_coupled_trust_entities,
        plot_top_trust_entities_by_blast_radius,
        plot_trust_entity_usage_concentration,
    )

    rows = load_csv_rows(analysis_dir / "trust_amplification_by_entity.csv")
    if not rows:
        return []
    figures_dir = output_dir / "figures"
    generated: list[str] = []
    if plot_trust_entity_usage_concentration(plt, rows, figures_dir):
        generated.append(str(figures_dir / "trust_entity_usage_concentration.png"))
    if plot_top_trust_entities_by_blast_radius(plt, rows, figures_dir):
        generated.append(str(figures_dir / "top_trust_entities_by_blast_radius.png"))
    if plot_mutable_ratio_by_trust_entity(plt, rows, figures_dir):
        generated.append(str(figures_dir / "mutable_ratio_by_trust_entity.png"))
    if plot_privilege_coupled_trust_entities(plt, rows, figures_dir):
        generated.append(str(figures_dir / "privilege_coupled_trust_entities.png"))
    return generated


def maybe_plot_reusable_workflow(plt, analysis_dir: Path, output_dir: Path) -> list[str]:
    from plot_reusable_workflow import (
        plot_reusable_workflow_ref_type_distribution,
        plot_reusable_workflow_usage_distribution,
        plot_secrets_inherit_reusable_workflows,
        plot_top_reusable_workflows_by_downstream,
    )

    edge_rows = load_csv_rows(analysis_dir / "reusable_workflow_edges.csv")
    top_rows = load_csv_rows(analysis_dir / "reusable_workflow_top_callees.csv")
    if not edge_rows and not top_rows:
        return []
    figures_dir = output_dir / "figures"
    generated: list[str] = []
    if plot_reusable_workflow_usage_distribution(plt, top_rows, figures_dir):
        generated.append(str(figures_dir / "reusable_workflow_usage_distribution.png"))
    if plot_top_reusable_workflows_by_downstream(plt, top_rows, figures_dir):
        generated.append(str(figures_dir / "top_reusable_workflows_by_downstream.png"))
    if plot_reusable_workflow_ref_type_distribution(plt, edge_rows, figures_dir):
        generated.append(str(figures_dir / "reusable_workflow_ref_type_distribution.png"))
    if plot_secrets_inherit_reusable_workflows(plt, top_rows, figures_dir):
        generated.append(str(figures_dir / "secrets_inherit_reusable_workflows.png"))
    return generated


def maybe_plot_privileged_blast_radius(plt, analysis_dir: Path, output_dir: Path) -> list[str]:
    from plot_privileged_blast_radius import (
        plot_blast_radius_vs_privileged_workflow_count,
        plot_top_actions_by_privileged_blast_radius,
    )

    rows = load_csv_rows(analysis_dir / "privileged_blast_radius_by_action.csv")
    if not rows:
        return []
    figures_dir = output_dir / "figures"
    generated: list[str] = []
    if plot_top_actions_by_privileged_blast_radius(rows, figures_dir):
        generated.append(str(figures_dir / "top_actions_by_privileged_blast_radius.png"))
    if plot_blast_radius_vs_privileged_workflow_count(rows, figures_dir):
        generated.append(str(figures_dir / "blast_radius_vs_privileged_workflow_count.png"))
    return generated


def maybe_plot_component_type_comparison(plt, analysis_dir: Path, output_dir: Path) -> list[str]:
    from plot_component_type_comparison import (
        plot_component_type_vs_fanout,
        plot_component_type_vs_mutability,
        plot_component_type_vs_privileged_blast,
    )

    rows = load_csv_rows(analysis_dir / "component_type_comparison.csv")
    if not rows:
        return []
    figures_dir = output_dir / "figures"
    generated: list[str] = []
    if plot_component_type_vs_fanout(rows, figures_dir):
        generated.append(str(figures_dir / "component_type_vs_fanout.png"))
    if plot_component_type_vs_privileged_blast(rows, figures_dir):
        generated.append(str(figures_dir / "component_type_vs_privileged_blast.png"))
    if plot_component_type_vs_mutability(rows, figures_dir):
        generated.append(str(figures_dir / "component_type_vs_mutability.png"))
    return generated


def main() -> int:
    args = parse_args()
    analysis_dir = args.analysis_dir.resolve()
    output_dir = (args.output_dir or (analysis_dir / "paper_figures")).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not analysis_dir.exists():
        print(f"[error] analysis directory does not exist: {analysis_dir}")
        return 1

    plt = configure_matplotlib()
    generated: list[str] = []

    workflow_rows = load_csv_rows(analysis_dir / "workflow_implicit_ratio.csv")
    depth_rows = load_csv_rows(analysis_dir / "cascade_depth_report.csv")
    blast_rows = load_csv_rows(analysis_dir / "blast_radius.csv")

    if plot_implicit_dependency_ecdf(plt, workflow_rows, output_dir):
        generated.append(str(output_dir / "implicit_dependency_ratio_ecdf.png"))
    if plot_depth_distribution(plt, depth_rows, output_dir):
        generated.append(str(output_dir / "cascade_depth_distribution.png"))
    if plot_binding_by_depth(plt, depth_rows, output_dir):
        generated.append(str(output_dir / "binding_strategy_by_depth.png"))
    if plot_blast_radius_topk(plt, blast_rows, output_dir, args.top_k):
        generated.append(str(output_dir / "blast_radius_top_actions.png"))

    generated.extend(maybe_plot_update_windows(analysis_dir, output_dir))
    generated.extend(maybe_plot_discovery_risk(plt, analysis_dir, output_dir))
    generated.extend(maybe_plot_ref_risk(plt, analysis_dir, output_dir))
    generated.extend(maybe_plot_isolation_risk(plt, analysis_dir, output_dir))
    generated.extend(maybe_plot_privilege_risk(plt, analysis_dir, output_dir))
    generated.extend(maybe_plot_propagation_risk(plt, analysis_dir, output_dir))
    generated.extend(maybe_plot_amplification_metrics(plt, analysis_dir, output_dir))
    generated.extend(maybe_plot_trust_amplification(plt, analysis_dir, output_dir))
    generated.extend(maybe_plot_reusable_workflow(plt, analysis_dir, output_dir))
    generated.extend(maybe_plot_privileged_blast_radius(plt, analysis_dir, output_dir))
    generated.extend(maybe_plot_component_type_comparison(plt, analysis_dir, output_dir))

    if not generated:
        print("[error] No plottable analysis outputs were found.")
        return 1

    print("[ok] Generated publication-style figures:")
    for item in generated:
        print(f"  {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
