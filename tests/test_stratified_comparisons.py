from __future__ import annotations

import unittest

from gha_cascade_analyzer.analyzers.stratified_comparisons import StratifiedComparisonAnalyzer
from gha_cascade_analyzer.models import (
    PrivilegeRiskByWorkflowMetric,
    PropagationRiskByWorkflowMetric,
    RefRiskByActionMetric,
    RefRiskByWorkflowMetric,
    ReusableWorkflowEdgeMetric,
    TrustDomainBoundaryMetric,
)


class StratifiedComparisonAnalyzerTests(unittest.TestCase):
    def test_builds_ref_owner_and_reusable_comparisons(self) -> None:
        analyzer = StratifiedComparisonAnalyzer()
        ref_type_rows, cross_owner_rows, reusable_rows = analyzer.analyze(
            ref_risk_by_action=[
                RefRiskByActionMetric(
                    action_id="a1",
                    owner="actions",
                    repo="checkout",
                    full_name="actions/checkout",
                    ref_name="main",
                    ref_category="BRANCH_MAIN",
                    usage_count=10,
                    workflow_count=2,
                    downstream_repo_count=5,
                    mutable_ref_count=1,
                    observed_drift=True,
                ),
                RefRiskByActionMetric(
                    action_id="a2",
                    owner="actions",
                    repo="checkout",
                    full_name="actions/checkout",
                    ref_name="x" * 40,
                    ref_category="FULL_SHA",
                    usage_count=3,
                    workflow_count=1,
                    downstream_repo_count=1,
                    immutable_ref_count=1,
                    mutable_ref_ratio=0.0,
                ),
            ],
            ref_risk_by_workflow=[
                RefRiskByWorkflowMetric(
                    workflow_name="CI",
                    repository_full_name="owner/repo",
                    workflow_path=".github/workflows/ci.yml",
                    max_depth=2,
                    total_ref_count=2,
                    full_sha_count=1,
                    branch_main_count=1,
                    mutable_ref_count=1,
                    immutable_ref_count=1,
                    branch_ref_count=1,
                    sha_ref_count=1,
                    mutable_ref_ratio=0.5,
                    high_risk_ref_ratio=0.5,
                    observed_drift=True,
                )
            ],
            privilege_risk_by_workflow=[
                PrivilegeRiskByWorkflowMetric(
                    repository_full_name="owner/repo",
                    workflow_path=".github/workflows/ci.yml",
                    workflow_name="CI",
                    has_id_token_write=True,
                    privilege_coupled_mutability=True,
                    privilege_risk_score=2.0,
                )
            ],
            propagation_risk_by_workflow=[
                PropagationRiskByWorkflowMetric(
                    repository_full_name="owner/repo",
                    workflow_path=".github/workflows/ci.yml",
                    workflow_name="CI",
                    propagation_channel_count=3,
                    privilege_propagation_coupling=True,
                )
            ],
            trust_domain_boundaries=[
                TrustDomainBoundaryMetric(
                    workflow_name="CI",
                    repository_full_name="owner/repo",
                    workflow_path=".github/workflows/ci.yml",
                    max_depth=2,
                    unique_action_owner_count=2,
                    unique_external_owner_count=1,
                    direct_cross_owner_edge_count=1,
                    total_cross_owner_edge_count=1,
                    has_external_owner_dependency=True,
                    has_multi_owner_cascade=True,
                )
            ],
            reusable_workflow_edges=[
                ReusableWorkflowEdgeMetric(
                    caller_repository="owner/repo",
                    caller_workflow_path=".github/workflows/ci.yml",
                    caller_job="build",
                    callee_owner="org",
                    callee_repo="shared",
                    callee_workflow_path=".github/workflows/reuse.yml",
                    callee_ref="main",
                    ref_type="BRANCH_MAIN",
                    is_remote=True,
                    is_mutable_ref=True,
                    is_cross_org=True,
                    is_third_party=True,
                    has_secrets_inherit=True,
                    has_permissions=True,
                    has_id_token_write=True,
                    downstream_repo_count=4,
                )
            ],
        )

        by_ref_type = {item.ref_category: item for item in ref_type_rows}
        self.assertEqual(by_ref_type["BRANCH_MAIN"].action_count, 1)
        self.assertEqual(by_ref_type["BRANCH_MAIN"].privileged_workflow_count, 1)
        self.assertEqual(by_ref_type["FULL_SHA"].action_count, 1)

        by_scope = {item.ownership_scope: item for item in cross_owner_rows}
        self.assertEqual(by_scope["cross_owner"].workflow_count, 1)
        self.assertEqual(by_scope["cross_owner"].workflows_with_id_token_write, 1)
        self.assertEqual(by_scope["cross_owner"].workflows_with_privilege_propagation_coupling, 1)

        by_profile = {item.profile_name: item for item in reusable_rows}
        self.assertEqual(by_profile["remote"].edge_count, 1)
        self.assertEqual(by_profile["remote_cross_org"].mutable_edge_count, 1)
        self.assertEqual(by_profile["remote_third_party"].secrets_inherit_count, 1)


if __name__ == "__main__":
    unittest.main()
