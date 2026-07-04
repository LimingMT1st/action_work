from __future__ import annotations

import csv
from pathlib import Path

import matplotlib.pyplot as plt


def _to_float(value: str | None) -> float:
    if value in {None, ""}:
        return 0.0
    return float(value)


def _to_int(value: str | None) -> int:
    if value in {None, ""}:
        return 0
    return int(float(value))


def plot_top_actions_by_privileged_blast_radius(rows: list[dict[str, str]], figures_dir: Path) -> bool:
    ranked = sorted(rows, key=lambda row: _to_float(row.get("privileged_blast_radius_score")), reverse=True)[:10]
    if not ranked:
        return False
    labels = [f"{row['full_name']}@{row.get('ref_name') or ''}".strip("@") for row in ranked]
    values = [_to_float(row.get("privileged_blast_radius_score")) for row in ranked]
    plt.figure(figsize=(11, 6))
    plt.barh(labels[::-1], values[::-1], color="#B64E23")
    plt.xlabel("Privileged Blast Radius Score")
    plt.title("Top Actions by Privileged Downstream Blast Radius")
    plt.tight_layout()
    plt.savefig(figures_dir / "top_actions_by_privileged_blast_radius.png", dpi=200)
    plt.close()
    return True


def plot_blast_radius_vs_privileged_workflow_count(rows: list[dict[str, str]], figures_dir: Path) -> bool:
    if not rows:
        return False
    x = [_to_int(row.get("downstream_repository_count")) for row in rows]
    y = [_to_int(row.get("privileged_downstream_workflow_count")) for row in rows]
    colors = [_to_int(row.get("id_token_downstream_workflow_count")) for row in rows]
    plt.figure(figsize=(8, 6))
    scatter = plt.scatter(x, y, c=colors, cmap="OrRd", alpha=0.75, s=26)
    plt.xlabel("Downstream Repository Count")
    plt.ylabel("Privileged Downstream Workflow Count")
    plt.title("Blast Radius vs Privileged Downstream Workflows")
    cbar = plt.colorbar(scatter)
    cbar.set_label("id-token Downstream Workflow Count")
    plt.tight_layout()
    plt.savefig(figures_dir / "blast_radius_vs_privileged_workflow_count.png", dpi=200)
    plt.close()
    return True


def main() -> None:
    analysis_dir = Path("data/analysis")
    figures_dir = analysis_dir / "figures"
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = analysis_dir / "privileged_blast_radius_by_action.csv"
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        return
    plot_top_actions_by_privileged_blast_radius(rows, figures_dir)
    plot_blast_radius_vs_privileged_workflow_count(rows, figures_dir)


if __name__ == "__main__":
    main()
