from __future__ import annotations

from statistics import mean

from gha_cascade_analyzer.models import (
    ActionNode,
    AmplificationByNodeMetric,
    ComponentTypeComparisonMetric,
    PrivilegedBlastRadiusByActionMetric,
    RefRiskByActionMetric,
)


COMPONENT_TYPES = ("javascript", "docker", "composite", "reusable_workflow", "unknown")


class ComponentTypeComparisonAnalyzer:
    def analyze(
        self,
        *,
        actions: list[ActionNode],
        ref_risk_by_action: list[RefRiskByActionMetric],
        amplification_by_node: list[AmplificationByNodeMetric],
        privileged_blast_radius_by_action: list[PrivilegedBlastRadiusByActionMetric],
    ) -> list[ComponentTypeComparisonMetric]:
        if not actions:
            return []

        action_index = {item.action_id: item for item in actions}
        ref_index = {item.action_id: item for item in ref_risk_by_action}
        amplification_index = {
            item.node_id: item
            for item in amplification_by_node
            if item.node_kind == "action"
        }
        privileged_index = {item.action_id: item for item in privileged_blast_radius_by_action}

        aggregates: dict[str, dict[str, list[float] | int | float]] = {}
        for component_type in COMPONENT_TYPES:
            aggregates[component_type] = {
                "action_count": 0,
                "total_usage_count": 0,
                "usage_counts": [],
                "downstream_repo_counts": [],
                "fanouts": [],
                "max_depths": [],
                "mutable_weighted_sum": 0.0,
                "mutable_weight": 0,
                "privileged_repo_count": 0,
                "id_token_repo_count": 0,
                "mutable_privileged_workflow_count": 0,
                "privileged_scores": [],
            }

        for action_id, action in action_index.items():
            component_type = action.action_type.value
            if component_type not in aggregates:
                component_type = "unknown"
            aggregate = aggregates[component_type]
            ref = ref_index.get(action_id)
            amplification = amplification_index.get(action_id)
            privileged = privileged_index.get(action_id)
            usage_count = ref.usage_count if ref else 0
            aggregate["action_count"] += 1
            aggregate["total_usage_count"] += usage_count
            if usage_count:
                aggregate["usage_counts"].append(usage_count)
                aggregate["mutable_weighted_sum"] += ref.mutable_ref_ratio * usage_count if ref else 0.0
                aggregate["mutable_weight"] += usage_count
            if ref:
                aggregate["downstream_repo_counts"].append(ref.downstream_repo_count)
            if amplification:
                aggregate["fanouts"].append(amplification.transitive_fanout)
                aggregate["max_depths"].append(amplification.max_downstream_depth)
            if privileged:
                aggregate["privileged_repo_count"] += privileged.privileged_downstream_repository_count
                aggregate["id_token_repo_count"] += privileged.id_token_downstream_repository_count
                aggregate["mutable_privileged_workflow_count"] += privileged.mutable_privileged_workflow_count
                aggregate["privileged_scores"].append(privileged.privileged_blast_radius_score)

        rows: list[ComponentTypeComparisonMetric] = []
        for component_type in COMPONENT_TYPES:
            aggregate = aggregates[component_type]
            weight = int(aggregate["mutable_weight"])
            rows.append(
                ComponentTypeComparisonMetric(
                    component_type=component_type,  # type: ignore[arg-type]
                    action_count=int(aggregate["action_count"]),
                    total_usage_count=int(aggregate["total_usage_count"]),
                    average_usage_count=self._mean_or_none(aggregate["usage_counts"]),
                    average_downstream_repo_count=self._mean_or_none(aggregate["downstream_repo_counts"]),
                    average_transitive_fanout=self._mean_or_none(aggregate["fanouts"]),
                    average_max_downstream_depth=self._mean_or_none(aggregate["max_depths"]),
                    mutable_ref_ratio_weighted=(float(aggregate["mutable_weighted_sum"]) / weight) if weight else 0.0,
                    privileged_downstream_repository_count=int(aggregate["privileged_repo_count"]),
                    id_token_downstream_repository_count=int(aggregate["id_token_repo_count"]),
                    mutable_privileged_workflow_count=int(aggregate["mutable_privileged_workflow_count"]),
                    average_privileged_blast_radius_score=self._mean_or_none(aggregate["privileged_scores"]),
                )
            )
        return rows

    def _mean_or_none(self, values: list[float]) -> float | None:
        if not values:
            return None
        return float(mean(values))
