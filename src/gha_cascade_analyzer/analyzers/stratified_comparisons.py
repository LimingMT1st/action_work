from __future__ import annotations

from statistics import mean

from gha_cascade_analyzer.models import (
    CrossOwnerRiskComparisonMetric,
    PrivilegeRiskByWorkflowMetric,
    PropagationRiskByWorkflowMetric,
    RefRiskByActionMetric,
    RefRiskByWorkflowMetric,
    RefTypeComparisonMetric,
    ReusableWorkflowEdgeMetric,
    ReusableWorkflowRiskProfileMetric,
    TrustDomainBoundaryMetric,
)


class StratifiedComparisonAnalyzer:
    def analyze(
        self,
        *,
        ref_risk_by_action: list[RefRiskByActionMetric],
        ref_risk_by_workflow: list[RefRiskByWorkflowMetric],
        privilege_risk_by_workflow: list[PrivilegeRiskByWorkflowMetric],
        propagation_risk_by_workflow: list[PropagationRiskByWorkflowMetric],
        trust_domain_boundaries: list[TrustDomainBoundaryMetric],
        reusable_workflow_edges: list[ReusableWorkflowEdgeMetric],
    ) -> tuple[
        list[RefTypeComparisonMetric],
        list[CrossOwnerRiskComparisonMetric],
        list[ReusableWorkflowRiskProfileMetric],
    ]:
        return (
            self._build_ref_type_comparison(
                ref_risk_by_action=ref_risk_by_action,
                ref_risk_by_workflow=ref_risk_by_workflow,
                privilege_risk_by_workflow=privilege_risk_by_workflow,
                propagation_risk_by_workflow=propagation_risk_by_workflow,
            ),
            self._build_cross_owner_comparison(
                trust_domain_boundaries=trust_domain_boundaries,
                ref_risk_by_workflow=ref_risk_by_workflow,
                privilege_risk_by_workflow=privilege_risk_by_workflow,
                propagation_risk_by_workflow=propagation_risk_by_workflow,
            ),
            self._build_reusable_workflow_risk_profile(reusable_workflow_edges),
        )

    def _build_ref_type_comparison(
        self,
        *,
        ref_risk_by_action: list[RefRiskByActionMetric],
        ref_risk_by_workflow: list[RefRiskByWorkflowMetric],
        privilege_risk_by_workflow: list[PrivilegeRiskByWorkflowMetric],
        propagation_risk_by_workflow: list[PropagationRiskByWorkflowMetric],
    ) -> list[RefTypeComparisonMetric]:
        categories = [
            "FULL_SHA",
            "SHORT_SHA",
            "SEMVER_TAG",
            "MAJOR_TAG",
            "BRANCH_MAIN",
            "BRANCH_OTHER",
            "FLOATING_TAG",
            "UNKNOWN_REF",
        ]
        workflow_ref_extractors = {
            "FULL_SHA": lambda item: item.full_sha_count,
            "SHORT_SHA": lambda item: item.short_sha_count,
            "SEMVER_TAG": lambda item: item.semver_tag_count,
            "MAJOR_TAG": lambda item: item.major_tag_count,
            "BRANCH_MAIN": lambda item: item.branch_main_count,
            "BRANCH_OTHER": lambda item: item.branch_other_count,
            "FLOATING_TAG": lambda item: item.floating_tag_count,
            "UNKNOWN_REF": lambda item: item.unknown_ref_count,
        }
        privilege_index = {
            (item.repository_full_name, item.workflow_path): item
            for item in privilege_risk_by_workflow
        }
        propagation_index = {
            (item.repository_full_name, item.workflow_path): item
            for item in propagation_risk_by_workflow
        }

        rows: list[RefTypeComparisonMetric] = []
        for category in categories:
            action_rows = [item for item in ref_risk_by_action if item.ref_category == category]
            workflow_rows = [
                item for item in ref_risk_by_workflow
                if workflow_ref_extractors[category](item) > 0
            ]
            privileged_workflow_count = 0
            privilege_coupled_workflow_count = 0
            propagation_coupled_workflow_count = 0
            for workflow_row in workflow_rows:
                privilege_row = privilege_index.get((workflow_row.repository_full_name, workflow_row.workflow_path))
                propagation_row = propagation_index.get((workflow_row.repository_full_name, workflow_row.workflow_path))
                if privilege_row and self._is_privileged_workflow(privilege_row):
                    privileged_workflow_count += 1
                if privilege_row and privilege_row.privilege_coupled_mutability:
                    privilege_coupled_workflow_count += 1
                if propagation_row and propagation_row.privilege_propagation_coupling:
                    propagation_coupled_workflow_count += 1
            rows.append(
                RefTypeComparisonMetric(
                    ref_category=category,
                    action_count=len(action_rows),
                    workflow_count=len(workflow_rows),
                    total_usage_count=sum(item.usage_count for item in action_rows),
                    average_usage_count=self._mean_or_none([item.usage_count for item in action_rows]),
                    average_downstream_repo_count=self._mean_or_none([item.downstream_repo_count for item in action_rows]),
                    observed_drift_action_count=sum(1 for item in action_rows if item.observed_drift),
                    observed_drift_action_ratio=(sum(1 for item in action_rows if item.observed_drift) / len(action_rows)) if action_rows else 0.0,
                    privileged_workflow_count=privileged_workflow_count,
                    privilege_coupled_workflow_count=privilege_coupled_workflow_count,
                    propagation_coupled_workflow_count=propagation_coupled_workflow_count,
                )
            )
        return rows

    def _build_cross_owner_comparison(
        self,
        *,
        trust_domain_boundaries: list[TrustDomainBoundaryMetric],
        ref_risk_by_workflow: list[RefRiskByWorkflowMetric],
        privilege_risk_by_workflow: list[PrivilegeRiskByWorkflowMetric],
        propagation_risk_by_workflow: list[PropagationRiskByWorkflowMetric],
    ) -> list[CrossOwnerRiskComparisonMetric]:
        trust_index = {
            (item.repository_full_name, item.workflow_path): item
            for item in trust_domain_boundaries
        }
        ref_index = {
            (item.repository_full_name, item.workflow_path): item
            for item in ref_risk_by_workflow
        }
        privilege_index = {
            (item.repository_full_name, item.workflow_path): item
            for item in privilege_risk_by_workflow
        }
        propagation_index = {
            (item.repository_full_name, item.workflow_path): item
            for item in propagation_risk_by_workflow
        }

        grouped: dict[str, list[tuple[TrustDomainBoundaryMetric, RefRiskByWorkflowMetric | None, PrivilegeRiskByWorkflowMetric | None, PropagationRiskByWorkflowMetric | None]]] = {
            "same_owner": [],
            "cross_owner": [],
        }
        for key, trust_row in trust_index.items():
            scope = "cross_owner" if trust_row.has_external_owner_dependency else "same_owner"
            grouped[scope].append(
                (
                    trust_row,
                    ref_index.get(key),
                    privilege_index.get(key),
                    propagation_index.get(key),
                )
            )

        rows: list[CrossOwnerRiskComparisonMetric] = []
        for scope, items in grouped.items():
            if not items:
                rows.append(CrossOwnerRiskComparisonMetric(ownership_scope=scope))  # type: ignore[arg-type]
                continue
            rows.append(
                CrossOwnerRiskComparisonMetric(
                    ownership_scope=scope,  # type: ignore[arg-type]
                    workflow_count=len(items),
                    average_max_depth=self._mean_or_none([trust.max_depth for trust, _, _, _ in items]),
                    average_unique_action_owner_count=self._mean_or_none([trust.unique_action_owner_count for trust, _, _, _ in items]),
                    average_mutable_ref_ratio=self._mean_or_none([ref.mutable_ref_ratio for _, ref, _, _ in items if ref is not None]),
                    average_high_risk_ref_ratio=self._mean_or_none([ref.high_risk_ref_ratio for _, ref, _, _ in items if ref is not None]),
                    workflows_with_observed_drift=sum(1 for _, ref, _, _ in items if ref and ref.observed_drift),
                    workflows_with_id_token_write=sum(1 for _, _, privilege, _ in items if privilege and privilege.has_id_token_write),
                    workflows_with_privilege_coupled_mutability=sum(1 for _, _, privilege, _ in items if privilege and privilege.privilege_coupled_mutability),
                    workflows_with_privilege_propagation_coupling=sum(1 for _, _, _, propagation in items if propagation and propagation.privilege_propagation_coupling),
                    workflows_with_multi_owner_cascade=sum(1 for trust, _, _, _ in items if trust.has_multi_owner_cascade),
                    average_propagation_channel_count=self._mean_or_none([propagation.propagation_channel_count for _, _, _, propagation in items if propagation is not None]),
                    average_privilege_risk_score=self._mean_or_none([privilege.privilege_risk_score for _, _, privilege, _ in items if privilege is not None]),
                )
            )
        return rows

    def _build_reusable_workflow_risk_profile(
        self,
        reusable_workflow_edges: list[ReusableWorkflowEdgeMetric],
    ) -> list[ReusableWorkflowRiskProfileMetric]:
        profiles = {
            "local": [item for item in reusable_workflow_edges if not item.is_remote],
            "remote": [item for item in reusable_workflow_edges if item.is_remote],
            "remote_same_org": [item for item in reusable_workflow_edges if item.is_remote and not item.is_cross_org],
            "remote_cross_org": [item for item in reusable_workflow_edges if item.is_remote and item.is_cross_org],
            "remote_third_party": [item for item in reusable_workflow_edges if item.is_remote and item.is_third_party],
        }
        rows: list[ReusableWorkflowRiskProfileMetric] = []
        for profile_name, edges in profiles.items():
            rows.append(self._build_reusable_profile_row(profile_name, edges))
        return rows

    def _build_reusable_profile_row(
        self,
        profile_name: str,
        edges: list[ReusableWorkflowEdgeMetric],
    ) -> ReusableWorkflowRiskProfileMetric:
        edge_count = len(edges)
        mutable_edge_count = sum(1 for item in edges if item.is_mutable_ref)
        secrets_inherit_count = sum(1 for item in edges if item.has_secrets_inherit)
        permissions_count = sum(1 for item in edges if item.has_permissions)
        id_token_write_count = sum(1 for item in edges if item.has_id_token_write)
        return ReusableWorkflowRiskProfileMetric(
            profile_name=profile_name,
            edge_count=edge_count,
            mutable_edge_count=mutable_edge_count,
            mutable_edge_ratio=(mutable_edge_count / edge_count) if edge_count else 0.0,
            secrets_inherit_count=secrets_inherit_count,
            secrets_inherit_ratio=(secrets_inherit_count / edge_count) if edge_count else 0.0,
            permissions_count=permissions_count,
            permissions_ratio=(permissions_count / edge_count) if edge_count else 0.0,
            id_token_write_count=id_token_write_count,
            id_token_write_ratio=(id_token_write_count / edge_count) if edge_count else 0.0,
            average_downstream_repo_count=self._mean_or_none([item.downstream_repo_count for item in edges]),
        )

    def _is_privileged_workflow(self, item: PrivilegeRiskByWorkflowMetric) -> bool:
        return any(
            [
                item.has_id_token_write,
                item.has_contents_write,
                item.has_actions_write,
                item.has_packages_write,
                item.has_deployments_write,
                item.has_security_events_write,
                item.has_write_all,
                item.secrets_in_env,
                item.secrets_in_with,
                item.github_token_explicit,
            ]
        )

    def _mean_or_none(self, values: list[int | float]) -> float | None:
        if not values:
            return None
        return float(mean(values))
