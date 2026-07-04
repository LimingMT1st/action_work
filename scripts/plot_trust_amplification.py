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
    parser = argparse.ArgumentParser(description="Plot trust-amplification outputs.")
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


def plot_trust_entity_usage_concentration(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    owner_rows = [row for row in rows if row.get("entity_type") == "owner"]
    if not owner_rows:
        return False
    ordered = sorted(owner_rows, key=lambda row: to_int(row.get("total_usage_count")), reverse=True)[:15]
    labels = [row.get("entity_name", "") for row in ordered][::-1]
    values = [to_int(row.get("total_usage_count")) for row in ordered][::-1]
    figure, axis = plt.subplots(figsize=(8.8, 5.8), dpi=220)
    axis.barh(labels, values, color="#4e79a7", alpha=0.9)
    axis.set_title("Top Trust Entities by Action Usage Concentration")
    axis.set_xlabel("Total Usage Count")
    axis.set_ylabel("Trust Entity")
    axis.grid(True, axis="x", linestyle="--", linewidth=0.6, alpha=0.35)
    save_figure(figure, output_dir / "trust_entity_usage_concentration")
    return True


def plot_top_trust_entities_by_blast_radius(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    if not rows:
        return False
    ordered = sorted(rows, key=lambda row: to_float(row.get("blast_radius_sum")), reverse=True)[:15]
    labels = [row.get("entity_name", "") for row in ordered][::-1]
    values = [to_float(row.get("blast_radius_sum")) for row in ordered][::-1]
    figure, axis = plt.subplots(figsize=(8.8, 5.8), dpi=220)
    axis.barh(labels, values, color="#76b7b2", alpha=0.9)
    axis.set_title("Top Trust Entities by Aggregate Blast Radius")
    axis.set_xlabel("Blast Radius Sum")
    axis.set_ylabel("Trust Entity")
    axis.grid(True, axis="x", linestyle="--", linewidth=0.6, alpha=0.35)
    save_figure(figure, output_dir / "top_trust_entities_by_blast_radius")
    return True


def plot_mutable_ratio_by_trust_entity(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    if not rows:
        return False
    ordered = sorted(rows, key=lambda row: to_float(row.get("mutable_ref_ratio")), reverse=True)[:15]
    labels = [row.get("entity_name", "") for row in ordered][::-1]
    values = [to_float(row.get("mutable_ref_ratio")) for row in ordered][::-1]
    figure, axis = plt.subplots(figsize=(8.8, 5.8), dpi=220)
    axis.barh(labels, values, color="#f28e2b", alpha=0.9)
    axis.set_title("Mutable Reference Ratio by Trust Entity")
    axis.set_xlabel("Mutable Reference Ratio")
    axis.set_ylabel("Trust Entity")
    axis.set_xlim(0, 1.0)
    axis.grid(True, axis="x", linestyle="--", linewidth=0.6, alpha=0.35)
    save_figure(figure, output_dir / "mutable_ratio_by_trust_entity")
    return True


def plot_privilege_coupled_trust_entities(plt, rows: list[dict[str, str]], output_dir: Path) -> bool:
    filtered = [row for row in rows if to_int(row.get("privileged_workflow_count")) > 0 or to_int(row.get("id_token_write_workflow_count")) > 0]
    if not filtered:
        return False
    ordered = sorted(filtered, key=lambda row: to_float(row.get("trust_amplification_score")), reverse=True)[:15]
    labels = [row.get("entity_name", "") for row in ordered][::-1]
    values = [to_float(row.get("trust_amplification_score")) for row in ordered][::-1]
    figure, axis = plt.subplots(figsize=(8.8, 5.8), dpi=220)
    axis.barh(labels, values, color="#e15759", alpha=0.9)
    axis.set_title("Privilege-Coupled Trust Entities")
    axis.set_xlabel("Trust Amplification Score")
    axis.set_ylabel("Trust Entity")
    axis.grid(True, axis="x", linestyle="--", linewidth=0.6, alpha=0.35)
    save_figure(figure, output_dir / "privilege_coupled_trust_entities")
    return True


def main() -> int:
    args = parse_args()
    analysis_dir = args.analysis_dir.resolve()
    figures_dir = analysis_dir / "figures"
    rows = load_rows(analysis_dir / "trust_amplification_by_entity.csv")
    if not rows:
        print("[error] trust-amplification CSV outputs are missing or empty")
        return 1
    plt = configure_matplotlib()
    generated: list[str] = []
    if plot_trust_entity_usage_concentration(plt, rows, figures_dir):
        generated.append(str(figures_dir / "trust_entity_usage_concentration.png"))
    if plot_top_trust_entities_by_blast_radius(plt, rows, figures_dir):
        generated.append(str(figures_dir / "top_trust_entities_by_blast_radius.png"))
    if plot_mutable_ratio_by_trust_entity(plt, rows, figures_dir):
        generated.append(str(figures_dir / "mutable_ratio_by_trust_entity.png"))
    if plot_privilege_coupled_trust_entities(plt, rows, figures_dir):
        generated.append(str(figures_dir / "privilege_coupled_trust_entities.png"))
    if not generated:
        print("[error] No trust-amplification figures were generated")
        return 1
    print("[ok] Generated trust-amplification figures:")
    for item in generated:
        print(f"  {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
