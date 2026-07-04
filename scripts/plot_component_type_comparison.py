from __future__ import annotations

import csv
from pathlib import Path

import matplotlib.pyplot as plt


ANALYSIS_DIR = Path("data/analysis")
FIGURES_DIR = ANALYSIS_DIR / "figures"
ORDER = ["javascript", "docker", "composite", "reusable_workflow", "unknown"]


def _read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _to_float(value: str | None) -> float:
    if value in {None, ""}:
        return 0.0
    return float(value)


def plot_component_type_vs_fanout(rows: list[dict[str, str]], figures_dir: Path) -> bool:
    rows_by_type = {row["component_type"]: row for row in rows}
    labels = [item for item in ORDER if item in rows_by_type]
    if not labels:
        return False
    values = [_to_float(rows_by_type[item].get("average_transitive_fanout")) for item in labels]
    plt.figure(figsize=(9, 5))
    plt.bar(labels, values, color="#4C78A8")
    plt.ylabel("Average Transitive Fanout")
    plt.title("Component Type vs Transitive Fanout")
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()
    plt.savefig(figures_dir / "component_type_vs_fanout.png", dpi=200)
    plt.close()
    return True


def plot_component_type_vs_privileged_blast(rows: list[dict[str, str]], figures_dir: Path) -> bool:
    rows_by_type = {row["component_type"]: row for row in rows}
    labels = [item for item in ORDER if item in rows_by_type]
    if not labels:
        return False
    values = [_to_float(rows_by_type[item].get("average_privileged_blast_radius_score")) for item in labels]
    plt.figure(figsize=(9, 5))
    plt.bar(labels, values, color="#E45756")
    plt.ylabel("Average Privileged Blast Radius Score")
    plt.title("Component Type vs Privileged Downstream Exposure")
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()
    plt.savefig(figures_dir / "component_type_vs_privileged_blast.png", dpi=200)
    plt.close()
    return True


def plot_component_type_vs_mutability(rows: list[dict[str, str]], figures_dir: Path) -> bool:
    rows_by_type = {row["component_type"]: row for row in rows}
    labels = [item for item in ORDER if item in rows_by_type]
    if not labels:
        return False
    values = [_to_float(rows_by_type[item].get("mutable_ref_ratio_weighted")) for item in labels]
    plt.figure(figsize=(9, 5))
    plt.bar(labels, values, color="#72B7B2")
    plt.ylabel("Weighted Mutable Ref Ratio")
    plt.title("Component Type vs Mutable Reference Exposure")
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()
    plt.savefig(figures_dir / "component_type_vs_mutability.png", dpi=200)
    plt.close()
    return True


def main() -> None:
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    rows = _read_rows(ANALYSIS_DIR / "component_type_comparison.csv")
    if not rows:
        return
    plot_component_type_vs_fanout(rows, FIGURES_DIR)
    plot_component_type_vs_privileged_blast(rows, FIGURES_DIR)
    plot_component_type_vs_mutability(rows, FIGURES_DIR)


if __name__ == "__main__":
    main()
