from __future__ import annotations

import unittest
from datetime import datetime, timezone

from gha_cascade_analyzer.analyzers.evidence_strength import EvidenceStrengthAnalyzer
from gha_cascade_analyzer.models import (
    PrivilegeRiskByJobMetric,
    PrivilegeRiskByWorkflowMetric,
    PropagationRiskByWorkflowMetric,
    RefRiskByActionMetric,
    RefRiskByWorkflowMetric,
    TrustAmplificationByEntityMetric,
    TrustDomainBoundaryMetric,
    WorkflowImplicitDependencyMetric,
)


def ts() -> datetime:
    return datetime(2026, 6, 20, tzinfo=timezone.utc)


class EvidenceStrengthAnalyzerTests(unittest.TestCase):
    def test_builds_bootstrap_effect_and_validation_outputs(self) -> None:
        analyzer = EvidenceStrengthAnalyzer(bootstrap_iterations=50, seed=7)
        bootstrap_rows, effect_rows, validation_rows = analyzer.analyze(
            workflow_metrics=[
                WorkflowImplicitDependencyMetric(repository_full_name="a/x", workflow_path="ci.yml", direct_actions=1, transitive_actions=1, total_actions=2, implicit_dependency_ratio=0.5),
                WorkflowImplicitDependencyMetric(repository_full_name="b/y", workflow_path="ci.yml", direct_actions=1, transitive_actions=0, total_actions=1, implicit_dependency_ratio=0.0),
            ],
            ref_risk_by_workflow=[
                RefRiskByWorkflowMetric(workflow_name="CI", repository_full_name="a/x", workflow_path="ci.yml", mutable_ref_ratio=0.8, observed_drift=True),
                RefRiskByWorkflowMetric(workflow_name="CI", repository_full_name="b/y", workflow_path="ci.yml", mutable_ref_ratio=0.2, observed_drift=False),
            ],
            privilege_risk_by_workflow=[
                PrivilegeRiskByWorkflowMetric(repository_full_name="a/x", workflow_path="ci.yml", workflow_name="CI", privileged_job_count=1, has_id_token_write=True, isolation_privilege_coupling=True, privilege_coupled_mutability=True, privilege_risk_score=9.0),
                PrivilegeRiskByWorkflowMetric(repository_full_name="b/y", workflow_path="ci.yml", workflow_name="CI", privilege_risk_score=1.0),
            ],
            privilege_risk_by_job=[
                PrivilegeRiskByJobMetric(repository_full_name="a/x", workflow_path="ci.yml", workflow_name="CI", job_id="build", isolation_privilege_coupling=True, privilege_risk_score=6.0),
                PrivilegeRiskByJobMetric(repository_full_name="b/y", workflow_path="ci.yml", workflow_name="CI", job_id="test", isolation_privilege_coupling=False, privilege_risk_score=1.0),
            ],
            propagation_risk_by_workflow=[
                PropagationRiskByWorkflowMetric(repository_full_name="a/x", workflow_path="ci.yml", workflow_name="CI", propagation_channel_count=4, privilege_propagation_coupling=True, mutable_to_downstream_propagation=True, has_artifact_upload=True, has_artifact_download=True, propagation_risk_score=7.0),
                PropagationRiskByWorkflowMetric(repository_full_name="b/y", workflow_path="ci.yml", workflow_name="CI", propagation_channel_count=1, propagation_risk_score=1.0),
            ],
            trust_domain_boundaries=[
                TrustDomainBoundaryMetric(workflow_name="CI", repository_full_name="a/x", workflow_path="ci.yml", has_external_owner_dependency=True),
                TrustDomainBoundaryMetric(workflow_name="CI", repository_full_name="b/y", workflow_path="ci.yml", has_external_owner_dependency=False),
            ],
            ref_risk_by_action=[
                RefRiskByActionMetric(action_id="a1", owner="o", repo="r", full_name="o/r", ref_name="main", ref_category="BRANCH_MAIN", observed_drift=True),
                RefRiskByActionMetric(action_id="a2", owner="o", repo="s", full_name="o/s", ref_name="v1", ref_category="MAJOR_TAG", observed_drift=False),
            ],
            trust_amplification_by_entity=[
                TrustAmplificationByEntityMetric(entity_name="actions", entity_type="owner", total_usage_count=100),
                TrustAmplificationByEntityMetric(entity_name="docker", entity_type="owner", total_usage_count=40),
            ],
        )

        bootstrap_by_name = {row.indicator_name: row for row in bootstrap_rows}
        self.assertIn("non_zero_implicit_dependency_ratio", bootstrap_by_name)
        self.assertEqual(bootstrap_by_name["observed_drift_ratio_per_action"].sample_count, 2)

        effect_by_name = {row.metric_name: row for row in effect_rows}
        self.assertIn("mutable_ref_ratio", effect_by_name)
        self.assertGreater(effect_by_name["mutable_ref_ratio"].difference_cross_minus_same, 0)

        rq_labels = {row.rq_label for row in validation_rows}
        self.assertEqual(rq_labels, {"RQ3", "RQ4"})


if __name__ == "__main__":
    unittest.main()
