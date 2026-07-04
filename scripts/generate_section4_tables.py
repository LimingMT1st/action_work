from __future__ import annotations

import argparse
import csv
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ANALYSIS_DIR = REPO_ROOT / "data" / "analysis"
DEFAULT_OUTPUT_DIR = DEFAULT_ANALYSIS_DIR / "section4_tables"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate Section IV summary tables.")
    parser.add_argument("--analysis-dir", type=Path, default=DEFAULT_ANALYSIS_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


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


def write_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


def write_markdown(path: Path, header: list[str], rows: list[list[str]]) -> None:
    lines = [
        "| " + " | ".join(header) + " |",
        "| " + " | ".join(["---"] * len(header)) + " |",
    ]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_latex(path: Path, caption: str, label: str, header: list[str], rows: list[list[str]]) -> None:
    body = [
        "\\begin{table}[t]",
        "\\centering",
        f"\\caption{{{caption}}}",
        f"\\label{{{label}}}",
        "\\footnotesize",
        "\\setlength{\\tabcolsep}{4pt}",
        "\\renewcommand{\\arraystretch}{1.1}",
        "\\begin{tabular}{p{0.12\\columnwidth}p{0.45\\columnwidth}p{0.25\\columnwidth}}",
        "\\toprule",
        " \\textbf{" + "} & \\textbf{".join(header) + "} \\\\",
        "\\midrule",
    ]
    for row in rows:
        body.append(" " + " & ".join(row) + " \\\\")
    body.extend(["\\bottomrule", "\\end{tabular}", "\\end{table}"])
    path.write_text("\n".join(body) + "\n", encoding="utf-8")


def headline_metrics_rows(analysis_dir: Path) -> list[list[str]]:
    implicit_rows = read_rows(analysis_dir / "workflow_implicit_ratio.csv")
    ref_rows = read_rows(analysis_dir / "ref_risk_summary.csv")
    iso_rows = read_rows(analysis_dir / "isolation_risk_summary.csv")
    priv_rows = read_rows(analysis_dir / "privilege_risk_summary.csv")
    prop_rows = read_rows(analysis_dir / "propagation_risk_summary.csv")
    trust_rows = read_rows(analysis_dir / "trust_amplification_summary.csv")
    amp_rows = read_rows(analysis_dir / "amplification_summary.csv")

    implicit_nonzero = sum(1 for row in implicit_rows if to_float(row.get("implicit_dependency_ratio")) > 0)
    total_workflows = len(implicit_rows)
    ref = ref_rows[0]
    iso = iso_rows[0]
    prv = priv_rows[0]
    prop = prop_rows[0]
    trust = trust_rows[0]
    amp = amp_rows[0]

    return [
        ["RQ1", f"{implicit_nonzero}/{total_workflows} workflows with non-zero implicit dependency ratio ({rate(implicit_nonzero, total_workflows):.1f}\\%)", "workflow_implicit_ratio.csv"],
        ["RQ2", f"Mutable references account for {pct(to_float(ref.get('mutable_ref_ratio'))):.1f}\\% of observed bindings; {to_int(ref.get('observed_drift_action_count'))} upstream actions drifted", "ref_risk_summary.csv"],
        ["RQ3", f"{rate(to_int(iso.get('jobs_with_mixed_trust_domains')), to_int(iso.get('total_jobs'))):.1f}\\% of jobs mix trust domains; {rate(to_int(prv.get('jobs_with_isolation_privilege_coupling')), to_int(prv.get('total_jobs'))):.1f}\\% show isolation-privilege coupling", "isolation/privilege summaries"],
        ["RQ4", f"{rate(to_int(prop.get('workflows_with_privilege_propagation_coupling')), to_int(prop.get('total_workflows'))):.1f}\\% of workflows show privilege-propagation coupling; reusable workflows expose {to_int(read_rows(analysis_dir / 'reusable_workflow_summary.csv')[0].get('total_edges'))} edges", "propagation/reusable summaries"],
        ["RQ5", f"Top-10 owners cover {pct(to_float(trust.get('top_10_owner_coverage'))):.1f}\\% of owner usage; top-100 actions cover {pct(to_float(amp.get('top_100_action_coverage'))):.1f}\\% of action usage", "trust/amplification summaries"],
    ]


def representative_case_rows(analysis_dir: Path) -> list[list[str]]:
    implicit_rows = sorted(read_rows(analysis_dir / "workflow_implicit_ratio.csv"), key=lambda row: to_float(row.get("implicit_dependency_ratio")), reverse=True)
    privilege_rows = sorted(read_rows(analysis_dir / "privilege_risk_examples.csv"), key=lambda row: to_float(row.get("privilege_risk_score")), reverse=True)
    propagation_rows = sorted(read_rows(analysis_dir / "propagation_risk_examples.csv"), key=lambda row: to_float(row.get("propagation_risk_score")), reverse=True)

    return [
        ["RQ1", implicit_rows[0].get("repository_full_name", ""), implicit_rows[0].get("workflow_path", ""), f"implicit ratio = {pct(to_float(implicit_rows[0].get('implicit_dependency_ratio'))):.1f}\\%"],
        ["RQ3", privilege_rows[0].get("repository_full_name", ""), privilege_rows[0].get("workflow_path", ""), f"privilege risk score = {to_float(privilege_rows[0].get('privilege_risk_score')):.1f}"],
        ["RQ4", propagation_rows[0].get("repository_full_name", ""), propagation_rows[0].get("workflow_path", ""), f"propagation risk score = {to_float(propagation_rows[0].get('propagation_risk_score')):.1f}"],
    ]


def main() -> int:
    args = parse_args()
    analysis_dir = args.analysis_dir.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    headline_header = ["RQ", "Headline metric", "Primary source"]
    headline_rows = headline_metrics_rows(analysis_dir)
    write_csv(output_dir / "section4_headline_metrics.csv", headline_header, headline_rows)
    write_markdown(output_dir / "section4_headline_metrics.md", headline_header, headline_rows)
    write_latex(
        output_dir / "section4_headline_metrics.tex",
        "Headline quantitative findings for Section~IV.",
        "tab:section4-headline-metrics",
        headline_header,
        headline_rows,
    )

    case_header = ["RQ", "Repository", "Workflow", "Representative signal"]
    case_rows = representative_case_rows(analysis_dir)
    write_csv(output_dir / "section4_representative_cases.csv", case_header, case_rows)
    write_markdown(output_dir / "section4_representative_cases.md", case_header, case_rows)

    print("[ok] generated Section IV tables:")
    for path in sorted(output_dir.iterdir()):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
