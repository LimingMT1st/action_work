from __future__ import annotations

import asyncio
import argparse
import csv
from pathlib import Path

from gha_cascade_analyzer.analyzers.action_content_resolver import ActionContentResolver
from gha_cascade_analyzer.analyzers.component_type_comparison import ComponentTypeComparisonAnalyzer
from gha_cascade_analyzer.analyzers.exporter import AnalysisExporter
from gha_cascade_analyzer.collectors.github_client import GitHubClient
from gha_cascade_analyzer.config import Settings
from gha_cascade_analyzer.models import (
    ActionNode,
    AnalysisReport,
    PrivilegedBlastRadiusByActionMetric,
)
from gha_cascade_analyzer.storage.jsonl_reader import JsonlReader


def _load_privileged_blast_rows(path: Path) -> list[PrivilegedBlastRadiusByActionMetric]:
    if not path.exists():
        return []
    rows: list[PrivilegedBlastRadiusByActionMetric] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            rows.append(PrivilegedBlastRadiusByActionMetric.model_validate(row))
    return rows


async def _resolve_action_types(settings: Settings, actions: list[ActionNode]) -> list[ActionNode]:
    if not settings.github.tokens:
        return actions
    async with GitHubClient(settings.github) as client:
        resolver = ActionContentResolver(client, fetch_concurrency=settings.analysis.recursive_fetch_concurrency)

        async def resolve_one(action: ActionNode) -> ActionNode:
            if action.action_type.value != "unknown":
                return action
            if action.subpath and action.subpath.startswith(".github/workflows/"):
                resolved = await resolver.fetch_reusable_workflow(action.owner, action.repo, action.subpath, action.ref)
            else:
                resolved = await resolver.fetch_action_definition(action.owner, action.repo, action.subpath, action.ref)
            if resolved is None:
                return action
            updated = action.model_copy(deep=True)
            updated.action_type = resolved.action_type
            updated.declared_permissions = resolved.declared_permissions
            updated.has_token_access = resolved.has_token_access
            updated.token_access_patterns = resolved.token_access_patterns
            updated.audited_source_files = resolved.audited_source_files
            return updated

        return await asyncio.gather(*(resolve_one(action) for action in actions))


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--top-n", type=int, default=500, help="Only resolve the top-N most impactful actions")
    args = parser.parse_args()

    settings = Settings.from_env()
    reader = JsonlReader(settings.crawl.output_dir)
    analysis_dir = settings.crawl.output_dir / "analysis"
    exporter = AnalysisExporter(analysis_dir)

    report = AnalysisReport.model_validate_json((analysis_dir / "report.json").read_text(encoding="utf-8"))
    actions = reader.read_models("actions/discovered.jsonl", ActionNode)
    privileged_blast_rows = report.privileged_blast_radius_by_action
    if not privileged_blast_rows:
        privileged_blast_rows = _load_privileged_blast_rows(analysis_dir / "privileged_blast_radius_by_action.csv")
    privileged_index = {item.action_id: item for item in privileged_blast_rows}
    ref_index = {item.action_id: item for item in report.ref_risk_by_action}
    ranked_action_ids = [
        item.action_id
        for item in sorted(
            report.ref_risk_by_action,
            key=lambda item: (
                privileged_index.get(item.action_id).privileged_blast_radius_score if privileged_index.get(item.action_id) else 0.0,
                item.usage_count,
                item.downstream_repo_count,
            ),
            reverse=True,
        )
    ]
    action_ids_in_scope = set(ranked_action_ids[: args.top_n])
    deduped: dict[str, ActionNode] = {}
    for action in actions:
        if action.action_id not in action_ids_in_scope:
            continue
        current = deduped.get(action.action_id)
        if current is None or action.discovered_at >= current.discovered_at:
            deduped[action.action_id] = action
    resolved_actions = await _resolve_action_types(settings, list(deduped.values()))
    exporter.export_models_csv("component_type_resolved_actions.csv", resolved_actions)

    comparison_rows = ComponentTypeComparisonAnalyzer().analyze(
        actions=resolved_actions,
        ref_risk_by_action=report.ref_risk_by_action,
        amplification_by_node=report.amplification_by_node,
        privileged_blast_radius_by_action=privileged_blast_rows,
    )
    exporter.export_models_csv("component_type_comparison.csv", comparison_rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
