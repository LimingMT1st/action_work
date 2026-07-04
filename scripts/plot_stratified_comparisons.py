from __future__ import annotations

import csv
from pathlib import Path

import matplotlib.pyplot as plt


ANALYSIS_DIR = Path("data/analysis")
FIGURES_DIR = ANALYSIS_DIR / "figures"


def _ensure_figures_dir() -> None:
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)


def _read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _to_float(value: str | None) -> float:
    if value in {None, ""}:
        return 0.0
    return float(value)


def plot_ref_type_privilege_coupling() -> None:
    path = ANALYSIS_DIR / "ref_type_risk_comparison.csv"
    rows = _read_rows(path)
    if not rows:
        return
    ordered = [
        "FULL_SHA",
        "SHORT_SHA",
        "SEMVER_TAG",
        "MAJOR_TAG",
        "BRANCH_MAIN",
        "BRANCH_OTHER",
        "FLOATING_TAG",
        "UNKNOWN_REF",
    ]
    rows_by_category = {row["ref_category"]: row for row in rows}
    labels = [category for category in ordered if category in rows_by_category]
    values = [_to_float(rows_by_category[category].get("privilege_coupled_workflow_count")) for category in labels]
    plt.figure(figsize=(10, 5))
    plt.bar(labels, values, color="#C75B12")
    plt.xticks(rotation=30, ha="right")
    plt.ylabel("Workflow Count")
    plt.title("Privilege-Coupled Workflows by Ref Type")
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "ref_type_vs_privilege_coupling.png", dpi=200)
    plt.close()


def plot_cross_owner_risk() -> None:
    path = ANALYSIS_DIR / "cross_owner_comparison.csv"
    rows = _read_rows(path)
    if not rows:
        return
    metrics = ["average_mutable_ref_ratio", "average_high_risk_ref_ratio", "average_privilege_risk_score"]
    display_names = ["Avg Mutable Ratio", "Avg High-Risk Ratio", "Avg Privilege Score"]
    x = range(len(metrics))
    rows_by_scope = {row["ownership_scope"]: row for row in rows}
    same_owner = rows_by_scope.get("same_owner")
    cross_owner = rows_by_scope.get("cross_owner")
    if same_owner is None or cross_owner is None:
        return
    width = 0.35
    same_values = [_to_float(same_owner.get(metric)) for metric in metrics]
    cross_values = [_to_float(cross_owner.get(metric)) for metric in metrics]
    plt.figure(figsize=(9, 5))
    plt.bar([item - width / 2 for item in x], same_values, width=width, label="Same Owner", color="#4C78A8")
    plt.bar([item + width / 2 for item in x], cross_values, width=width, label="Cross Owner", color="#E45756")
    plt.xticks(list(x), display_names, rotation=20, ha="right")
    plt.ylabel("Value")
    plt.title("Same-Owner vs Cross-Owner Workflow Risk")
    plt.legend()
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "same_owner_vs_cross_owner_risk.png", dpi=200)
    plt.close()


def plot_reusable_workflow_profiles() -> None:
    path = ANALYSIS_DIR / "reusable_workflow_risk_profile.csv"
    rows = _read_rows(path)
    if not rows:
        return
    focus_names = ["local", "remote", "remote_cross_org", "remote_third_party"]
    rows_by_profile = {row["profile_name"]: row for row in rows}
    labels = [name for name in focus_names if name in rows_by_profile]
    if not labels:
        return
    mutable_values = [_to_float(rows_by_profile[name].get("mutable_edge_ratio")) for name in labels]
    secrets_values = [_to_float(rows_by_profile[name].get("secrets_inherit_ratio")) for name in labels]
    id_token_values = [_to_float(rows_by_profile[name].get("id_token_write_ratio")) for name in labels]
    plt.figure(figsize=(10, 5))
    plt.bar(labels, mutable_values, color="#72B7B2", label="Mutable Ratio")
    plt.plot(labels, secrets_values, marker="o", color="#B279A2", label="Secrets Inherit Ratio")
    plt.plot(labels, id_token_values, marker="s", color="#F58518", label="id-token: write Ratio")
    plt.ylabel("Ratio")
    plt.title("Reusable Workflow Risk Profile")
    plt.legend()
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "reusable_workflow_risk_profile.png", dpi=200)
    plt.close()


def main() -> None:
    _ensure_figures_dir()
    plot_ref_type_privilege_coupling()
    plot_cross_owner_risk()
    plot_reusable_workflow_profiles()


if __name__ == "__main__":
    main()
