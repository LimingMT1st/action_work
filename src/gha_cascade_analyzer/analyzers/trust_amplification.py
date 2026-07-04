from __future__ import annotations

from collections import defaultdict

from gha_cascade_analyzer.analyzers.graph_types import CascadeGraph
from gha_cascade_analyzer.models import (
    BlastRadiusMetric,
    MarketplaceActionIdentity,
    PrivilegeRiskByWorkflowMetric,
    RefRiskByActionMetric,
    TrustAmplificationByEntityMetric,
    TrustAmplificationSummaryMetric,
)


class TrustAmplificationAnalyzer:
    def analyze(
        self,
        *,
        graph: CascadeGraph,
        marketplace_identities: list[MarketplaceActionIdentity],
        blast_radius: list[BlastRadiusMetric],
        ref_risk_by_action: list[RefRiskByActionMetric],
        privilege_risk_by_workflow: list[PrivilegeRiskByWorkflowMetric],
    ) -> tuple[
        list[TrustAmplificationByEntityMetric],
        TrustAmplificationSummaryMetric,
        list[TrustAmplificationByEntityMetric],
    ]:
        if not graph.actions:
            return [], TrustAmplificationSummaryMetric(), []

        marketplace_index = {
            (item.owner.lower(), item.repository.lower()): item
            for item in marketplace_identities
            if item.owner and item.repository
        }
        blast_index = {item.action_id: item for item in blast_radius}
        ref_index = {item.action_id: item for item in ref_risk_by_action}
        privileged_workflows_by_action = self._privileged_workflows_by_action(graph, privilege_risk_by_workflow)
        id_token_workflows_by_action = self._id_token_workflows_by_action(graph, privilege_risk_by_workflow)
        downstream_workflows_by_action = self._downstream_workflows_by_action(graph)

        aggregates: dict[tuple[str, str], dict] = {}
        for action_id, action in graph.actions.items():
            owner_key = action.owner.lower()
            repo_key = action.repo.lower()
            marketplace = marketplace_index.get((owner_key, repo_key))
            entity_keys = [(action.owner, "owner")]
            if owner_key in {"actions", "github"}:
                entity_keys.append((action.owner, "github_owned"))
            else:
                entity_keys.append((action.owner, "third_party_owner"))
            if marketplace is not None:
                entity_keys.append((marketplace.title or f"{action.owner}/{action.repo}", "marketplace_publisher"))
                if marketplace.verified_creator:
                    entity_keys.append((marketplace.badge_text or marketplace.title or action.owner, "verified_creator"))

            blast = blast_index.get(action_id)
            ref_risk = ref_index.get(action_id)
            workflow_ids = downstream_workflows_by_action.get(action_id, set())
            privileged_ids = privileged_workflows_by_action.get(action_id, set())
            id_token_ids = id_token_workflows_by_action.get(action_id, set())
            usage_count = ref_risk.usage_count if ref_risk else len(workflow_ids)
            downstream_repo_count = blast.downstream_repository_count if blast else len({wid.split("::", 2)[1] for wid in workflow_ids})
            high_star_repo_count = blast.downstream_high_star_repository_count if blast else 0
            mutable_usage_count = usage_count if ref_risk and ref_risk.mutable_ref_ratio > 0 else 0
            mutable_ratio = ref_risk.mutable_ref_ratio if ref_risk else 0.0
            blast_value = float(blast.downstream_repository_count if blast else downstream_repo_count)

            for entity_name, entity_type in entity_keys:
                key = (entity_name, entity_type)
                aggregate = aggregates.setdefault(
                    key,
                    {
                        "entity_name": entity_name,
                        "entity_type": entity_type,
                        "action_ids": set(),
                        "total_usage_count": 0,
                        "downstream_repositories": set(),
                        "downstream_workflows": set(),
                        "high_star_downstream_repo_count": 0,
                        "mutable_ref_usage_count": 0,
                        "mutable_ref_ratio_weighted": 0.0,
                        "mutable_ref_ratio_weight": 0,
                        "privileged_workflows": set(),
                        "id_token_workflows": set(),
                        "blast_radius_sum": 0.0,
                        "blast_radius_max": 0.0,
                    },
                )
                aggregate["action_ids"].add(action_id)
                aggregate["total_usage_count"] += usage_count
                aggregate["downstream_workflows"].update(workflow_ids)
                aggregate["downstream_repositories"].update({wid.split("::", 2)[1] for wid in workflow_ids})
                aggregate["high_star_downstream_repo_count"] += high_star_repo_count
                aggregate["mutable_ref_usage_count"] += mutable_usage_count
                aggregate["mutable_ref_ratio_weighted"] += mutable_ratio * usage_count
                aggregate["mutable_ref_ratio_weight"] += usage_count
                aggregate["privileged_workflows"].update(privileged_ids)
                aggregate["id_token_workflows"].update(id_token_ids)
                aggregate["blast_radius_sum"] += blast_value
                aggregate["blast_radius_max"] = max(aggregate["blast_radius_max"], blast_value)

        rows: list[TrustAmplificationByEntityMetric] = []
        for aggregate in aggregates.values():
            mutable_ratio = (
                aggregate["mutable_ref_ratio_weighted"] / aggregate["mutable_ref_ratio_weight"]
                if aggregate["mutable_ref_ratio_weight"]
                else 0.0
            )
            score = (
                len(aggregate["downstream_repositories"]) * 1.5
                + mutable_ratio * 25.0
                + len(aggregate["privileged_workflows"]) * 2.0
                + len(aggregate["id_token_workflows"]) * 3.0
                + len(aggregate["action_ids"]) * 1.0
                + aggregate["blast_radius_sum"] * 0.1
            )
            rows.append(
                TrustAmplificationByEntityMetric(
                    entity_name=aggregate["entity_name"],
                    entity_type=aggregate["entity_type"],  # type: ignore[arg-type]
                    action_count=len(aggregate["action_ids"]),
                    total_usage_count=aggregate["total_usage_count"],
                    downstream_repo_count=len(aggregate["downstream_repositories"]),
                    downstream_workflow_count=len(aggregate["downstream_workflows"]),
                    high_star_downstream_repo_count=aggregate["high_star_downstream_repo_count"],
                    mutable_ref_usage_count=aggregate["mutable_ref_usage_count"],
                    mutable_ref_ratio=round(mutable_ratio, 4),
                    privileged_workflow_count=len(aggregate["privileged_workflows"]),
                    id_token_write_workflow_count=len(aggregate["id_token_workflows"]),
                    blast_radius_sum=round(aggregate["blast_radius_sum"], 4),
                    blast_radius_max=round(aggregate["blast_radius_max"], 4),
                    trust_amplification_score=round(score, 4),
                )
            )

        rows.sort(
            key=lambda item: (
                item.trust_amplification_score,
                item.downstream_repo_count,
                item.total_usage_count,
                item.entity_name.lower(),
            ),
            reverse=True,
        )
        summary = self._build_summary(rows)
        top_entities = rows[:100]
        return rows, summary, top_entities

    def _downstream_workflows_by_action(self, graph: CascadeGraph) -> dict[str, set[str]]:
        result: dict[str, set[str]] = defaultdict(set)
        for edge in graph.edges:
            if edge.consumer_repository and edge.workflow_path:
                workflow_id = f"workflow::{edge.consumer_repository}::{edge.workflow_path}"
                result[edge.dst_node_id].add(workflow_id)
        return result

    def _privileged_workflows_by_action(
        self,
        graph: CascadeGraph,
        privilege_rows: list[PrivilegeRiskByWorkflowMetric],
    ) -> dict[str, set[str]]:
        workflow_lookup = {
            (item.repository_full_name, item.workflow_path): item
            for item in privilege_rows
        }
        result: dict[str, set[str]] = defaultdict(set)
        for edge in graph.edges:
            if not edge.consumer_repository or not edge.workflow_path:
                continue
            row = workflow_lookup.get((edge.consumer_repository, edge.workflow_path))
            if row is None or row.privilege_risk_score <= 0:
                continue
            workflow_id = f"workflow::{edge.consumer_repository}::{edge.workflow_path}"
            result[edge.dst_node_id].add(workflow_id)
        return result

    def _id_token_workflows_by_action(
        self,
        graph: CascadeGraph,
        privilege_rows: list[PrivilegeRiskByWorkflowMetric],
    ) -> dict[str, set[str]]:
        workflow_lookup = {
            (item.repository_full_name, item.workflow_path): item
            for item in privilege_rows
        }
        result: dict[str, set[str]] = defaultdict(set)
        for edge in graph.edges:
            if not edge.consumer_repository or not edge.workflow_path:
                continue
            row = workflow_lookup.get((edge.consumer_repository, edge.workflow_path))
            if row is None or not row.has_id_token_write:
                continue
            workflow_id = f"workflow::{edge.consumer_repository}::{edge.workflow_path}"
            result[edge.dst_node_id].add(workflow_id)
        return result

    def _build_summary(self, rows: list[TrustAmplificationByEntityMetric]) -> TrustAmplificationSummaryMetric:
        owner_rows = [item for item in rows if item.entity_type == "owner"]
        if not owner_rows:
            return TrustAmplificationSummaryMetric(total_entities=len(rows))
        usages = sorted((item.total_usage_count for item in owner_rows), reverse=True)
        total_usage = sum(usages) or 1
        shares = [value / total_usage for value in usages]
        return TrustAmplificationSummaryMetric(
            total_entities=len(rows),
            total_owner_entities=len(owner_rows),
            top_1_owner_coverage=sum(usages[:1]) / total_usage,
            top_5_owner_coverage=sum(usages[:5]) / total_usage,
            top_10_owner_coverage=sum(usages[:10]) / total_usage,
            gini_coefficient_over_owner_usage=round(self._gini(sorted(usages)), 4),
            hhi_over_owner_usage=round(sum(share * share for share in shares), 4),
        )

    def _gini(self, values: list[int]) -> float:
        if not values:
            return 0.0
        n = len(values)
        total = sum(values)
        if total == 0:
            return 0.0
        weighted_sum = sum((index + 1) * value for index, value in enumerate(values))
        return (2 * weighted_sum) / (n * total) - (n + 1) / n
