from __future__ import annotations

from collections import defaultdict

from gha_cascade_analyzer.analyzers.graph_types import CascadeGraph
from gha_cascade_analyzer.models import (
    BlastRadiusMetric,
    PrivilegeRiskByWorkflowMetric,
    PrivilegedBlastRadiusByActionMetric,
    PrivilegedBlastRadiusSummaryMetric,
    RefRiskByActionMetric,
)


class PrivilegedBlastRadiusAnalyzer:
    def analyze(
        self,
        *,
        graph: CascadeGraph,
        blast_radius: list[BlastRadiusMetric],
        privilege_risk_by_workflow: list[PrivilegeRiskByWorkflowMetric],
        ref_risk_by_action: list[RefRiskByActionMetric],
    ) -> tuple[list[PrivilegedBlastRadiusByActionMetric], PrivilegedBlastRadiusSummaryMetric]:
        if not graph.actions:
            return [], PrivilegedBlastRadiusSummaryMetric()

        blast_index = {item.action_id: item for item in blast_radius}
        ref_index = {item.action_id: item for item in ref_risk_by_action}
        privilege_lookup = {
            (item.repository_full_name, item.workflow_path): item
            for item in privilege_risk_by_workflow
        }

        privileged_workflows_by_action: dict[str, set[str]] = defaultdict(set)
        privileged_repositories_by_action: dict[str, set[str]] = defaultdict(set)
        id_token_workflows_by_action: dict[str, set[str]] = defaultdict(set)
        id_token_repositories_by_action: dict[str, set[str]] = defaultdict(set)
        mutable_privileged_workflows_by_action: dict[str, set[str]] = defaultdict(set)
        privilege_coupled_repositories_by_action: dict[str, set[str]] = defaultdict(set)

        for edge in graph.edges:
            if not edge.consumer_repository or not edge.workflow_path:
                continue
            workflow_row = privilege_lookup.get((edge.consumer_repository, edge.workflow_path))
            if workflow_row is None:
                continue
            workflow_id = f"workflow::{edge.consumer_repository}::{edge.workflow_path}"
            if workflow_row.privilege_risk_score > 0:
                privileged_workflows_by_action[edge.dst_node_id].add(workflow_id)
                privileged_repositories_by_action[edge.dst_node_id].add(edge.consumer_repository)
            if workflow_row.has_id_token_write:
                id_token_workflows_by_action[edge.dst_node_id].add(workflow_id)
                id_token_repositories_by_action[edge.dst_node_id].add(edge.consumer_repository)
            if workflow_row.mutable_third_party_action_with_privilege or workflow_row.privilege_coupled_mutability:
                mutable_privileged_workflows_by_action[edge.dst_node_id].add(workflow_id)
                privilege_coupled_repositories_by_action[edge.dst_node_id].add(edge.consumer_repository)

        rows: list[PrivilegedBlastRadiusByActionMetric] = []
        for action_id, action in graph.actions.items():
            blast = blast_index.get(action_id)
            ref = ref_index.get(action_id)
            downstream_repo_count = blast.downstream_repository_count if blast else len(self._collect_downstream_repositories(graph, action_id))
            high_star_repo_count = blast.downstream_high_star_repository_count if blast else 0
            high_star_coverage = blast.downstream_high_star_coverage if blast else 0
            privileged_repo_count = len(privileged_repositories_by_action.get(action_id, set()))
            id_token_repo_count = len(id_token_repositories_by_action.get(action_id, set()))
            mutable_privileged_workflow_count = len(mutable_privileged_workflows_by_action.get(action_id, set()))
            privilege_coupled_repo_count = len(privilege_coupled_repositories_by_action.get(action_id, set()))
            score = (
                privileged_repo_count * 2.0
                + len(id_token_workflows_by_action.get(action_id, set())) * 3.0
                + mutable_privileged_workflow_count * 2.5
                + high_star_repo_count * 1.5
                + high_star_coverage / 1_000_000.0
            )
            rows.append(
                PrivilegedBlastRadiusByActionMetric(
                    action_id=action_id,
                    owner=action.owner,
                    repo=action.repo,
                    full_name=f"{action.owner}/{action.repo}",
                    ref_name=action.ref,
                    ref_category=(ref.ref_category if ref else "UNKNOWN_REF"),
                    downstream_repository_count=downstream_repo_count,
                    downstream_high_star_repository_count=high_star_repo_count,
                    downstream_high_star_coverage=high_star_coverage,
                    privileged_downstream_workflow_count=len(privileged_workflows_by_action.get(action_id, set())),
                    privileged_downstream_repository_count=privileged_repo_count,
                    id_token_downstream_workflow_count=len(id_token_workflows_by_action.get(action_id, set())),
                    id_token_downstream_repository_count=id_token_repo_count,
                    mutable_privileged_workflow_count=mutable_privileged_workflow_count,
                    privilege_coupled_repository_count=privilege_coupled_repo_count,
                    privileged_blast_radius_score=round(score, 4),
                )
            )

        rows.sort(
            key=lambda item: (
                item.privileged_blast_radius_score,
                item.privileged_downstream_repository_count,
                item.id_token_downstream_repository_count,
                item.full_name.lower(),
            ),
            reverse=True,
        )
        summary = self._build_summary(rows)
        return rows, summary

    def _build_summary(self, rows: list[PrivilegedBlastRadiusByActionMetric]) -> PrivilegedBlastRadiusSummaryMetric:
        if not rows:
            return PrivilegedBlastRadiusSummaryMetric()
        privileged_counts = sorted((item.privileged_downstream_repository_count for item in rows), reverse=True)
        total_privileged = sum(privileged_counts) or 1
        return PrivilegedBlastRadiusSummaryMetric(
            total_actions=len(rows),
            actions_with_privileged_downstream=sum(1 for item in rows if item.privileged_downstream_repository_count > 0),
            actions_with_id_token_downstream=sum(1 for item in rows if item.id_token_downstream_repository_count > 0),
            actions_with_mutable_privileged_downstream=sum(1 for item in rows if item.mutable_privileged_workflow_count > 0),
            top_1_privileged_action_coverage=sum(privileged_counts[:1]) / total_privileged,
            top_10_privileged_action_coverage=sum(privileged_counts[:10]) / total_privileged,
            top_100_privileged_action_coverage=sum(privileged_counts[:100]) / total_privileged,
            total_privileged_downstream_repositories=sum(item.privileged_downstream_repository_count for item in rows),
            total_id_token_downstream_repositories=sum(item.id_token_downstream_repository_count for item in rows),
        )

    def _collect_downstream_repositories(self, graph: CascadeGraph, action_id: str) -> set[str]:
        repositories: set[str] = set()
        for edge in graph.edges:
            if edge.dst_node_id == action_id and edge.consumer_repository:
                repositories.add(edge.consumer_repository)
        return repositories
