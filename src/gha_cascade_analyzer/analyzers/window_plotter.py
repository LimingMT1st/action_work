from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from gha_cascade_analyzer.models import TimeWindowAmplificationMetric, UpdateWindowMetric, UpdateWindowSummaryMetric


class UpdateWindowPlotter:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def export_all(
        self,
        update_windows: list[UpdateWindowMetric],
        summaries: list[UpdateWindowSummaryMetric],
        amplification: list[TimeWindowAmplificationMetric],
    ) -> None:
        try:
            import matplotlib

            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except Exception:
            return

        self._plot_mode_distribution(plt, update_windows)
        self._plot_depth_amplification(plt, amplification)
        self._plot_window_counts(plt, summaries)

    def _plot_mode_distribution(self, plt, update_windows: list[UpdateWindowMetric]) -> None:
        explicit = [item.lag_hours for item in update_windows if item.adoption_mode == "explicit"]
        implicit = [item.lag_hours for item in update_windows if item.adoption_mode == "implicit"]

        figure, axis = plt.subplots(figsize=(7.2, 4.4), dpi=200)
        axis.set_title("Downstream Adoption Windows by Mode")
        axis.set_ylabel("Lag Hours")
        axis.grid(True, axis="y", linestyle="--", linewidth=0.6, alpha=0.35)

        data = []
        labels = []
        if explicit:
            data.append(explicit)
            labels.append("Explicit")
        if implicit:
            data.append(implicit)
            labels.append("Implicit")

        if data:
            boxplot = axis.boxplot(data, labels=labels, patch_artist=True, showfliers=False)
            colors = ["#1f77b4", "#d62728"]
            for patch, color in zip(boxplot["boxes"], colors, strict=False):
                patch.set_facecolor(color)
                patch.set_alpha(0.55)
        else:
            axis.text(0.5, 0.5, "No update-window samples available", ha="center", va="center", transform=axis.transAxes)

        self._save_figure(figure, "figures/update_window_mode_distribution")

    def _plot_depth_amplification(self, plt, amplification: list[TimeWindowAmplificationMetric]) -> None:
        order = ["level_1", "level_2", "level_3_plus"]
        labels = ["Level 1", "Level 2", "Level 3+"]
        explicit_values = []
        implicit_values = []
        explicit_counts = []
        implicit_counts = []
        index = {item.depth_bucket: item for item in amplification}
        for bucket in order:
            metric = index.get(bucket)
            explicit_values.append(metric.explicit_median_lag_hours if metric and metric.explicit_median_lag_hours is not None else 0.0)
            implicit_values.append(metric.implicit_median_lag_hours if metric and metric.implicit_median_lag_hours is not None else 0.0)
            explicit_counts.append(metric.explicit_window_count if metric else 0)
            implicit_counts.append(metric.implicit_window_count if metric else 0)

        figure, axis = plt.subplots(figsize=(8.0, 4.6), dpi=200)
        axis.set_title("Time-Window Amplification Across Dependency Depth")
        axis.set_ylabel("Median Lag Hours")
        axis.grid(True, axis="y", linestyle="--", linewidth=0.6, alpha=0.35)

        positions = list(range(len(order)))
        width = 0.34
        explicit_bars = axis.bar([position - width / 2 for position in positions], explicit_values, width, label="Explicit", color="#1f77b4", alpha=0.75)
        implicit_bars = axis.bar([position + width / 2 for position in positions], implicit_values, width, label="Implicit", color="#d62728", alpha=0.75)
        axis.set_xticks(positions, labels)
        axis.legend(frameon=False)

        for bar, count in zip(explicit_bars, explicit_counts, strict=False):
            axis.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), f"n={count}", ha="center", va="bottom", fontsize=8)
        for bar, count in zip(implicit_bars, implicit_counts, strict=False):
            axis.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), f"n={count}", ha="center", va="bottom", fontsize=8)

        self._save_figure(figure, "figures/update_window_depth_amplification")

    def _plot_window_counts(self, plt, summaries: list[UpdateWindowSummaryMetric]) -> None:
        counts: dict[str, dict[str, int]] = defaultdict(lambda: {"explicit": 0, "implicit": 0})
        for item in summaries:
            counts[item.depth_bucket][item.adoption_mode] = item.window_count

        order = ["level_1", "level_2", "level_3_plus"]
        labels = ["Level 1", "Level 2", "Level 3+"]
        explicit_counts = [counts[bucket]["explicit"] for bucket in order]
        implicit_counts = [counts[bucket]["implicit"] for bucket in order]

        figure, axis = plt.subplots(figsize=(8.0, 4.6), dpi=200)
        axis.set_title("Observed Update Windows by Dependency Depth")
        axis.set_ylabel("Workflow Count")
        axis.grid(True, axis="y", linestyle="--", linewidth=0.6, alpha=0.35)
        positions = list(range(len(order)))
        width = 0.34
        axis.bar([position - width / 2 for position in positions], explicit_counts, width, label="Explicit", color="#1f77b4", alpha=0.75)
        axis.bar([position + width / 2 for position in positions], implicit_counts, width, label="Implicit", color="#d62728", alpha=0.75)
        axis.set_xticks(positions, labels)
        axis.legend(frameon=False)
        self._save_figure(figure, "figures/update_window_counts_by_depth")

    def _save_figure(self, figure, relative_stem: str) -> None:
        path = self.root / f"{relative_stem}.png"
        path.parent.mkdir(parents=True, exist_ok=True)
        figure.tight_layout()
        figure.savefig(path, bbox_inches="tight")
        figure.savefig(path.with_suffix(".svg"), bbox_inches="tight")
        figure.clf()
