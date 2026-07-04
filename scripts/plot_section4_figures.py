from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ANALYSIS_DIR = REPO_ROOT / "data" / "analysis"
DEFAULT_OUTPUT_DIR = DEFAULT_ANALYSIS_DIR / "section4_figures"

COLORS = {
    "blue": "#355C7D",
    "teal": "#3C7E74",
    "orange": "#E07A5F",
    "green": "#5B8E7D",
    "gold": "#C89F3D",
    "slate": "#4A5568",
    "light": "#F4F6F8",
    "grid": "#D9DEE5",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate ICSE-style Section IV figures from analysis outputs."
    )
    parser.add_argument(
        "--analysis-dir",
        type=Path,
        default=DEFAULT_ANALYSIS_DIR,
        help="Directory containing analysis outputs.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory where figures will be written.",
    )
    return parser.parse_args()


def configure_style() -> None:
    plt.rcParams.update(
        {
            "figure.dpi": 260,
            "savefig.dpi": 260,
            "font.family": "DejaVu Serif",
            "font.size": 10,
            "axes.titlesize": 12,
            "axes.titleweight": "semibold",
            "axes.labelsize": 10,
            "axes.edgecolor": "#BBC3CC",
            "axes.linewidth": 0.8,
            "xtick.labelsize": 9,
            "ytick.labelsize": 9,
            "legend.fontsize": 8.8,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "savefig.bbox": "tight",
        }
    )


def read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def read_report(analysis_dir: Path) -> dict:
    path = analysis_dir / "report.json"
    if not path.exists() or path.stat().st_size == 0:
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def rows_from_report(report: dict, *keys: str) -> list[dict]:
    for key in keys:
        value = report.get(key)
        if isinstance(value, list) and value:
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict) and value:
            return [value]
    return []


def load_rows(analysis_dir: Path, report: dict, csv_name: str, *report_keys: str) -> list[dict]:
    rows = read_rows(analysis_dir / csv_name)
    if rows:
        return rows
    return rows_from_report(report, *report_keys)


def to_float(value: str | int | float | None, default: float = 0.0) -> float:
    if value in {None, ""}:
        return default
    return float(value)


def to_int(value: str | int | float | None, default: int = 0) -> int:
    if value in {None, ""}:
        return default
    return int(float(value))


def pct(value: float) -> float:
    return value * 100.0


def rate(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0
    return (numerator / denominator) * 100.0


def save_figure(fig: plt.Figure, output_dir: Path, stem: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    fig.tight_layout(pad=1.1)
    fig.savefig(output_dir / f"{stem}.png")
    plt.close(fig)


def add_panel_label(ax: plt.Axes, label: str) -> None:
    ax.text(
        0.01,
        1.01,
        label,
        transform=ax.transAxes,
        fontsize=12,
        fontweight="bold",
        ha="left",
        va="top",
        bbox={"facecolor": "white", "edgecolor": "none", "alpha": 0.9, "pad": 0.1},
    )


def make_figure(panel_count: int) -> tuple[plt.Figure, list[plt.Axes]]:
    width = max(4.5 * panel_count, 6.4)
    fig, axes = plt.subplots(1, panel_count, figsize=(width, 4.4))
    if panel_count == 1:
        return fig, [axes]
    return fig, list(axes)


def grid_y(ax: plt.Axes) -> None:
    ax.grid(True, axis="y", linestyle="--", linewidth=0.6, alpha=0.35, color=COLORS["grid"])


def grid_x(ax: plt.Axes) -> None:
    ax.grid(True, axis="x", linestyle="--", linewidth=0.6, alpha=0.35, color=COLORS["grid"])


def annotate_box(ax: plt.Axes, text: str, loc: tuple[float, float] = (0.98, 0.05)) -> None:
    ax.text(
        loc[0],
        loc[1],
        text,
        transform=ax.transAxes,
        ha="right",
        va="bottom",
        bbox={"facecolor": "white", "edgecolor": "#C8CED6", "alpha": 0.95, "boxstyle": "round,pad=0.25"},
    )


def _lorenz_points(values: list[float]) -> tuple[list[float], list[float]]:
    if not values:
        return [0.0, 1.0], [0.0, 1.0]
    values = sorted(max(value, 0.0) for value in values)
    total = sum(values)
    if total <= 0:
        n = len(values)
        xs = [i / n for i in range(n + 1)]
        return xs, xs
    cumulative = [0.0]
    running = 0.0
    for value in values:
        running += value
        cumulative.append(running / total)
    xs = [i / len(values) for i in range(len(values) + 1)]
    return xs, cumulative


def plot_rq1_hidden_transitive_trust(analysis_dir: Path, output_dir: Path, report: dict) -> bool:
    implicit_rows = load_rows(analysis_dir, report, "workflow_implicit_ratio.csv", "workflow_metrics")
    depth_rows = load_rows(analysis_dir, report, "cascade_depth_report.csv", "cascade_depth_reports")
    if not implicit_rows:
        return False

    fig, axes = make_figure(3)

    values = sorted(to_float(row.get("implicit_dependency_ratio")) for row in implicit_rows)
    y_values = [(idx + 1) / len(values) for idx in range(len(values))]
    axes[0].plot(values, y_values, color=COLORS["blue"], linewidth=2.2)
    axes[0].fill_between(values, y_values, color=COLORS["blue"], alpha=0.18)
    axes[0].set_xlabel("Implicit dependency ratio")
    axes[0].set_ylabel("ECDF")
    axes[0].set_title("Hidden trust beyond visible uses")
    axes[0].set_xlim(0.0, 1.0)
    axes[0].set_ylim(0.0, 1.02)
    nonzero = sum(1 for value in values if value > 0)
    annotate_box(axes[0], f"non-zero workflows = {nonzero}/{len(values)}\n({rate(nonzero, len(values)):.1f}%)")
    grid_y(axes[0])

    buckets = Counter()
    for row in depth_rows:
        depth = to_int(row.get("max_depth"))
        if depth <= 0:
            bucket = "0"
        elif depth == 1:
            bucket = "1"
        elif depth == 2:
            bucket = "2"
        else:
            bucket = "3+"
        buckets[bucket] += 1
    order = ["0", "1", "2", "3+"]
    counts = [buckets[item] for item in order]
    bars = axes[1].bar(order, counts, color=COLORS["teal"], alpha=0.92)
    axes[1].set_xlabel("Maximum cascade depth")
    axes[1].set_ylabel("Workflow count")
    axes[1].set_title("Depth of transitive execution")
    for bar, count in zip(bars, counts, strict=False):
        axes[1].text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(count), ha="center", va="bottom")
    grid_y(axes[1])

    ranked = sorted(
        [row for row in implicit_rows if to_float(row.get("implicit_dependency_ratio")) > 0],
        key=lambda row: to_float(row.get("implicit_dependency_ratio")),
        reverse=True,
    )[:8]
    labels = [row.get("repository_full_name", "") for row in ranked][::-1]
    ratios = [pct(to_float(row.get("implicit_dependency_ratio"))) for row in ranked][::-1]
    axes[2].barh(labels, ratios, color=COLORS["orange"], alpha=0.92)
    axes[2].set_xlabel("Implicit dependency ratio (%)")
    axes[2].set_title("Most transitive-heavy workflows")
    grid_x(axes[2])

    for label, ax in zip(["A", "B", "C"], axes, strict=False):
        add_panel_label(ax, label)
    save_figure(fig, output_dir, "rq1_hidden_transitive_trust")
    return True


def plot_rq2_silent_trust_rebinding(analysis_dir: Path, output_dir: Path, report: dict) -> bool:
    summary_rows = load_rows(analysis_dir, report, "ref_risk_summary.csv", "ref_risk_summary")
    depth_rows = load_rows(analysis_dir, report, "ref_risk_by_depth.csv", "ref_risk_by_depth")
    update_rows = load_rows(analysis_dir, report, "update_window_summary.csv", "update_window_summary")
    exposure_rows = load_rows(analysis_dir, report, "exposure_window_summary.csv", "exposure_window_summary")
    if not summary_rows:
        return False

    row = summary_rows[0]
    fig, axes = make_figure(3)

    labels = ["Full SHA", "Semver", "Major tag", "Branch", "Floating", "Unknown"]
    values = [
        to_int(row.get("full_sha_count")) + to_int(row.get("short_sha_count")),
        to_int(row.get("semver_tag_count")),
        to_int(row.get("major_tag_count")),
        to_int(row.get("branch_ref_count")),
        to_int(row.get("floating_tag_count")),
        to_int(row.get("unknown_ref_count")),
    ]
    colors = [COLORS["blue"], COLORS["green"], COLORS["orange"], "#C65D7B", "#B78BA7", COLORS["slate"]]
    axes[0].bar(labels, values, color=colors, alpha=0.94)
    axes[0].set_ylabel("Reference count")
    axes[0].set_title("Binding strategies remain predominantly mutable")
    axes[0].tick_params(axis="x", rotation=20)
    annotate_box(
        axes[0],
        f"mutable ratio = {pct(to_float(row.get('mutable_ref_ratio'))):.1f}%\n"
        f"observed drifted actions = {to_int(row.get('observed_drift_action_count'))}",
        loc=(0.98, 0.93),
    )
    grid_y(axes[0])

    depth_order = ["level_1", "level_2", "level_3_plus"]
    mutable_rates = []
    drift_counts = []
    present = []
    for bucket in depth_order:
        bucket_row = next((item for item in depth_rows if item.get("depth_bucket") == bucket), None)
        if not bucket_row:
            continue
        present.append(bucket.replace("level_", "L").replace("_plus", "+"))
        mutable_rates.append(pct(to_float(bucket_row.get("mutable_ref_ratio"))))
        drift_counts.append(to_int(bucket_row.get("observed_drift_ref_count")))
    x = np.arange(len(present))
    axes[1].bar(x, mutable_rates, color=COLORS["teal"], alpha=0.92)
    axes[1].set_xticks(x, present)
    axes[1].set_ylabel("Mutable reference ratio (%)")
    axes[1].set_title("Mutable bindings persist across cascade depth")
    ax2 = axes[1].twinx()
    ax2.plot(x, drift_counts, color=COLORS["orange"], marker="o", linewidth=2.0)
    ax2.set_ylabel("Observed drifted refs")
    grid_y(axes[1])

    explicit = {}
    implicit = {}
    for item in update_rows:
        mode = item.get("adoption_mode")
        bucket = item.get("depth_bucket")
        if bucket not in depth_order:
            continue
        label = bucket.replace("level_", "L").replace("_plus", "+")
        value = to_float(item.get("average_lag_hours"))
        if mode == "explicit":
            explicit[label] = value
        elif mode == "implicit":
            implicit[label] = value
    labels = [bucket.replace("level_", "L").replace("_plus", "+") for bucket in depth_order]
    explicit_values = [explicit.get(label, 0.0) for label in labels]
    implicit_values = [implicit.get(label, 0.0) for label in labels]
    x = np.arange(len(labels))
    width = 0.36
    axes[2].bar(x - width / 2, explicit_values, width=width, color=COLORS["orange"], label="Explicit lag")
    axes[2].bar(x + width / 2, implicit_values, width=width, color=COLORS["blue"], label="Implicit lag")
    axes[2].set_xticks(x, labels)
    axes[2].set_ylabel("Average lag (hours)")
    axes[2].set_title("Explicit updates lag while implicit rebinding is immediate")
    axes[2].legend(frameon=False, loc="upper right")
    if exposure_rows:
        exp = exposure_rows[0]
        annotate_box(
            axes[2],
            f"exposure windows = {to_int(exp.get('exposure_count'))}\n"
            f"avg exposure = {to_float(exp.get('average_lag_hours')):.1f}h",
        )
    grid_y(axes[2])

    for label, ax in zip(["A", "B", "C"], axes, strict=False):
        add_panel_label(ax, label)
    save_figure(fig, output_dir, "rq2_silent_trust_rebinding")
    return True


def plot_rq3_shared_runtime_and_privilege(analysis_dir: Path, output_dir: Path, report: dict) -> bool:
    isolation_summary = load_rows(analysis_dir, report, "isolation_risk_summary.csv", "isolation_risk_summary")
    privilege_summary = load_rows(analysis_dir, report, "privilege_risk_summary.csv", "privilege_risk_summary")
    privilege_examples = load_rows(analysis_dir, report, "privilege_risk_examples.csv", "privilege_risk_examples")
    if not isolation_summary or not privilege_summary:
        return False

    iso = isolation_summary[0]
    prv = privilege_summary[0]
    fig, axes = make_figure(3)

    total_jobs = max(to_int(iso.get("total_jobs")), 1)
    labels = ["mixed trust", "3p before sensitive", "env signal", "output signal", "fs signal"]
    values = [
        rate(to_int(iso.get("jobs_with_mixed_trust_domains")), total_jobs),
        rate(to_int(iso.get("jobs_with_third_party_before_sensitive_step")), total_jobs),
        rate(to_int(iso.get("jobs_with_env_pollution_signal")), total_jobs),
        rate(to_int(iso.get("jobs_with_output_dependency_signal")), total_jobs),
        rate(to_int(iso.get("jobs_with_filesystem_signal")), total_jobs),
    ]
    axes[0].bar(labels, values, color=COLORS["teal"], alpha=0.92)
    axes[0].set_ylabel("Jobs (%)")
    axes[0].set_title("Shared-runtime\nco-location is common")
    axes[0].tick_params(axis="x", rotation=22)
    grid_y(axes[0])

    total_workflows = max(to_int(prv.get("total_workflows")), 1)
    labels = ["id-token", "write-all", "pr_target", "mutable+priv", "isolation+priv"]
    values = [
        rate(to_int(prv.get("workflows_with_id_token_write")), total_workflows),
        rate(to_int(prv.get("workflows_with_write_all")), total_workflows),
        rate(to_int(prv.get("workflows_with_pull_request_target")), total_workflows),
        rate(to_int(prv.get("jobs_with_privilege_coupled_mutability")), max(to_int(prv.get("total_jobs")), 1)),
        rate(to_int(prv.get("jobs_with_isolation_privilege_coupling")), max(to_int(prv.get("total_jobs")), 1)),
    ]
    axes[1].bar(labels, values, color=COLORS["orange"], alpha=0.92)
    axes[1].set_ylabel("Workflow / job rate (%)")
    axes[1].set_title("Privileges frequently co-locate\nwith dependency risk")
    axes[1].tick_params(axis="x", rotation=22)
    grid_y(axes[1])

    ranked = sorted(
        privilege_examples,
        key=lambda item: to_float(item.get("privilege_risk_score")),
        reverse=True,
    )[:8]
    labels = [item.get("repository_full_name", "") for item in ranked][::-1]
    values = [to_float(item.get("privilege_risk_score")) for item in ranked][::-1]
    axes[2].barh(labels, values, color=COLORS["blue"], alpha=0.92)
    axes[2].set_xlabel("Privilege risk score")
    axes[2].set_title("Representative high-risk\nprivileged workflows")
    grid_x(axes[2])

    for label, ax in zip(["A", "B", "C"], axes, strict=False):
        add_panel_label(ax, label)
    save_figure(fig, output_dir, "rq3_shared_runtime_and_privilege")
    return True


def plot_rq4_cross_context_propagation(analysis_dir: Path, output_dir: Path, report: dict) -> bool:
    propagation_summary = load_rows(analysis_dir, report, "propagation_risk_summary.csv", "propagation_risk_summary")
    propagation_rows = load_rows(analysis_dir, report, "propagation_risk_by_workflow.csv", "propagation_risk_by_workflow")
    propagation_examples = load_rows(analysis_dir, report, "propagation_risk_examples.csv", "propagation_risk_examples")
    reusable_summary = load_rows(analysis_dir, report, "reusable_workflow_summary.csv", "reusable_workflow_summary")
    if not propagation_summary or not reusable_summary:
        return False

    row = propagation_summary[0]
    reusable = reusable_summary[0]
    fig, axes = make_figure(3)

    total_workflows = max(to_int(row.get("total_workflows")), 1)
    labels = ["artifact up", "artifact down", "cache", "job outputs", "needs outputs", "workflow_call"]
    values = [
        rate(to_int(row.get("workflows_with_artifact_upload")), total_workflows),
        rate(to_int(row.get("workflows_with_artifact_download")), total_workflows),
        rate(to_int(row.get("workflows_with_cache_save_restore")), total_workflows),
        rate(to_int(row.get("workflows_with_job_outputs")), total_workflows),
        rate(to_int(row.get("workflows_with_needs_outputs")), total_workflows),
        rate(to_int(row.get("workflows_with_workflow_call")), total_workflows),
    ]
    axes[0].bar(labels, values, color=COLORS["green"], alpha=0.92)
    axes[0].set_ylabel("Workflows (%)")
    axes[0].set_title("Workflow-native propagation\nchannels are widespread")
    axes[0].tick_params(axis="x", rotation=22)
    annotate_box(
        axes[0],
        f"privilege-propagation coupling = {rate(to_int(row.get('workflows_with_privilege_propagation_coupling')), total_workflows):.1f}%",
        loc=(0.98, 0.93),
    )
    grid_y(axes[0])

    labels = ["remote", "mutable", "cross-org", "inherit", "permissions", "id-token"]
    total_edges = max(to_int(reusable.get("total_edges")), 1)
    values = [
        rate(to_int(reusable.get("remote_edge_count")), total_edges),
        rate(to_int(reusable.get("mutable_ref_edge_count")), total_edges),
        rate(to_int(reusable.get("cross_org_edge_count")), total_edges),
        rate(to_int(reusable.get("secrets_inherit_edge_count")), total_edges),
        rate(to_int(reusable.get("permissions_edge_count")), total_edges),
        rate(to_int(reusable.get("id_token_write_edge_count")), total_edges),
    ]
    axes[1].bar(labels, values, color=COLORS["orange"], alpha=0.92)
    axes[1].set_ylabel("Reusable workflow edges (%)")
    axes[1].set_title("Reusable workflows act as privileged\npropagation boundaries")
    axes[1].tick_params(axis="x", rotation=22)
    grid_y(axes[1])

    channel_buckets = Counter()
    for item in propagation_rows:
        count = to_int(item.get("propagation_channel_count"))
        if count <= 0:
            bucket = "0"
        elif count == 1:
            bucket = "1"
        elif count == 2:
            bucket = "2"
        elif count == 3:
            bucket = "3"
        else:
            bucket = "4+"
        channel_buckets[bucket] += 1
    order = ["0", "1", "2", "3", "4+"]
    counts = [channel_buckets[item] for item in order]
    bars = axes[2].bar(order, counts, color=COLORS["blue"], alpha=0.92)
    axes[2].set_xlabel("Propagation channel count")
    axes[2].set_ylabel("Workflow count")
    axes[2].set_title("Propagation-heavy workflows are\nnot limited to rare outliers")
    for bar, count in zip(bars, counts, strict=False):
        axes[2].text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(count), ha="center", va="bottom")
    if propagation_examples:
        annotate_box(
            axes[2],
            f"top example = {propagation_examples[0].get('repository_full_name', '')}\n"
            f"score = {to_float(propagation_examples[0].get('propagation_risk_score')):.1f}",
            loc=(0.98, 0.93),
        )
    grid_y(axes[2])

    for label, ax in zip(["A", "B", "C"], axes, strict=False):
        add_panel_label(ax, label)
    save_figure(fig, output_dir, "rq4_cross_context_propagation")
    return True


def plot_rq5_systemic_amplification(analysis_dir: Path, output_dir: Path, report: dict) -> bool:
    blast_rows = load_rows(analysis_dir, report, "blast_radius.csv", "blast_radius")
    trust_summary = load_rows(analysis_dir, report, "trust_amplification_summary.csv", "trust_amplification_summary")
    cross_owner_rows = load_rows(analysis_dir, report, "cross_owner_comparison.csv", "cross_owner_comparison")
    if not blast_rows or not trust_summary or not cross_owner_rows:
        return False

    fig, axes = make_figure(3)

    values = [to_float(row.get("downstream_repository_count")) for row in blast_rows]
    xs, ys = _lorenz_points(values)
    axes[0].plot(xs, ys, color=COLORS["blue"], linewidth=2.2, label="Observed")
    axes[0].plot([0, 1], [0, 1], linestyle="--", color="#9BA4AF", linewidth=1.0, label="Uniform")
    axes[0].set_xlabel("Cumulative share of Actions")
    axes[0].set_ylabel("Cumulative share of downstream reach")
    axes[0].set_title("Cascade impact is highly concentrated")
    axes[0].legend(frameon=False, loc="upper left")
    grid_y(axes[0])

    trust = trust_summary[0]
    labels = ["Top 1", "Top 5", "Top 10"]
    coverage = [
        pct(to_float(trust.get("top_1_owner_coverage"))),
        pct(to_float(trust.get("top_5_owner_coverage"))),
        pct(to_float(trust.get("top_10_owner_coverage"))),
    ]
    axes[1].bar(labels, coverage, color=COLORS["orange"], alpha=0.92)
    axes[1].set_ylabel("Owner usage coverage (%)")
    axes[1].set_ylim(0, 100)
    axes[1].set_title("A few owners anchor\nmost runtime trust")
    annotate_box(axes[1], f"Gini = {to_float(trust.get('gini_coefficient_over_owner_usage')):.4f}", loc=(0.98, 0.93))
    grid_y(axes[1])

    same = next((row for row in cross_owner_rows if row.get("ownership_scope") == "same_owner"), None)
    cross = next((row for row in cross_owner_rows if row.get("ownership_scope") == "cross_owner"), None)
    labels = ["Mutable ratio", "Privilege score", "Propagation", "Avg depth"]
    same_values = [
        pct(to_float(same.get("average_mutable_ref_ratio"))),
        to_float(same.get("average_privilege_risk_score")),
        to_float(same.get("average_propagation_channel_count")),
        to_float(same.get("average_max_depth")),
    ]
    cross_values = [
        pct(to_float(cross.get("average_mutable_ref_ratio"))),
        to_float(cross.get("average_privilege_risk_score")),
        to_float(cross.get("average_propagation_channel_count")),
        to_float(cross.get("average_max_depth")),
    ]
    lifts = [(cross_value / same_value) if same_value > 0 else 0.0 for same_value, cross_value in zip(same_values, cross_values, strict=False)]
    bars = axes[2].bar(labels, lifts, color=COLORS["teal"], alpha=0.92)
    axes[2].set_ylabel("Cross-owner lift (x)")
    axes[2].set_title("Cross-owner reuse systematically\nraises exposure")
    axes[2].tick_params(axis="x", rotation=18)
    for bar, value in zip(bars, lifts, strict=False):
        axes[2].text(bar.get_x() + bar.get_width() / 2, bar.get_height(), f"{value:.1f}x", ha="center", va="bottom")
    grid_y(axes[2])

    for label, ax in zip(["A", "B", "C"], axes, strict=False):
        add_panel_label(ax, label)
    save_figure(fig, output_dir, "rq5_systemic_amplification")
    return True


def main() -> int:
    args = parse_args()
    configure_style()
    analysis_dir = args.analysis_dir.resolve()
    output_dir = args.output_dir.resolve()
    report = read_report(analysis_dir)
    generated: list[str] = []

    plotters = [
        ("rq1_hidden_transitive_trust", plot_rq1_hidden_transitive_trust),
        ("rq2_silent_trust_rebinding", plot_rq2_silent_trust_rebinding),
        ("rq3_shared_runtime_and_privilege", plot_rq3_shared_runtime_and_privilege),
        ("rq4_cross_context_propagation", plot_rq4_cross_context_propagation),
        ("rq5_systemic_amplification", plot_rq5_systemic_amplification),
    ]

    for stem, plotter in plotters:
        if plotter(analysis_dir, output_dir, report):
            generated.append(str(output_dir / f"{stem}.png"))

    if not generated:
        print("[error] no Section IV figures were generated")
        return 1

    print("[ok] generated Section IV figures:")
    for item in generated:
        print(item)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
