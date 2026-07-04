from __future__ import annotations

import unittest
from datetime import datetime, timezone

from gha_cascade_analyzer.analyzers.graph_types import CascadeGraph
from gha_cascade_analyzer.analyzers.privileged_blast_radius import PrivilegedBlastRadiusAnalyzer
from gha_cascade_analyzer.enums import ActionType, RefType, VerificationStatus
from gha_cascade_analyzer.models import (
    ActionNode,
    BlastRadiusMetric,
    CDGEdge,
    PrivilegeRiskByWorkflowMetric,
    RefRiskByActionMetric,
)


def ts() -> datetime:
    return datetime(2026, 6, 9, tzinfo=timezone.utc)


class PrivilegedBlastRadiusAnalyzerTests(unittest.TestCase):
    def test_computes_privileged_downstream_counts(self) -> None:
        analyzer = PrivilegedBlastRadiusAnalyzer()
        graph = CascadeGraph(
            workflow_nodes={
                "workflow::consumer/a::.github/workflows/ci.yml",
                "workflow::consumer/b::.github/workflows/deploy.yml",
            },
            workflow_names={},
            actions={
                "checkout_v4": ActionNode(
                    action_id="checkout_v4",
                    owner="actions",
                    repo="checkout",
                    action_name="actions/checkout",
                    action_type=ActionType.UNKNOWN,
                    ref="v4",
                    ref_type=RefType.TAG,
                    author_verified=VerificationStatus.VERIFIED,
                    discovered_at=ts(),
                )
            },
            edges=[
                CDGEdge(
                    edge_id="1",
                    src_node_id="workflow::consumer/a::.github/workflows/ci.yml",
                    dst_node_id="checkout_v4",
                    src_kind="workflow",
                    dst_kind="action",
                    edge_type="direct",
                    ref_type=RefType.TAG,
                    ref_string="v4",
                    workflow_path=".github/workflows/ci.yml",
                    consumer_repository="consumer/a",
                    depth=1,
                    discovered_at=ts(),
                ),
                CDGEdge(
                    edge_id="2",
                    src_node_id="workflow::consumer/b::.github/workflows/deploy.yml",
                    dst_node_id="checkout_v4",
                    src_kind="workflow",
                    dst_kind="action",
                    edge_type="direct",
                    ref_type=RefType.TAG,
                    ref_string="v4",
                    workflow_path=".github/workflows/deploy.yml",
                    consumer_repository="consumer/b",
                    depth=1,
                    discovered_at=ts(),
                ),
            ],
            reverse_adjacency={},
        )
        rows, summary = analyzer.analyze(
            graph=graph,
            blast_radius=[
                BlastRadiusMetric(
                    action_id="checkout_v4",
                    owner="actions",
                    repo="checkout",
                    downstream_repository_count=2,
                    downstream_high_star_repository_count=1,
                    downstream_high_star_coverage=1000,
                )
            ],
            privilege_risk_by_workflow=[
                PrivilegeRiskByWorkflowMetric(
                    repository_full_name="consumer/a",
                    workflow_path=".github/workflows/ci.yml",
                    workflow_name="CI",
                    privilege_risk_score=1.0,
                ),
                PrivilegeRiskByWorkflowMetric(
                    repository_full_name="consumer/b",
                    workflow_path=".github/workflows/deploy.yml",
                    workflow_name="Deploy",
                    has_id_token_write=True,
                    privilege_risk_score=2.0,
                    privilege_coupled_mutability=True,
                ),
            ],
            ref_risk_by_action=[
                RefRiskByActionMetric(
                    action_id="checkout_v4",
                    owner="actions",
                    repo="checkout",
                    full_name="actions/checkout",
                    ref_name="v4",
                    ref_category="MAJOR_TAG",
                )
            ],
        )
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row.privileged_downstream_repository_count, 2)
        self.assertEqual(row.id_token_downstream_repository_count, 1)
        self.assertEqual(row.mutable_privileged_workflow_count, 1)
        self.assertGreater(row.privileged_blast_radius_score, 0.0)
        self.assertEqual(summary.actions_with_privileged_downstream, 1)
        self.assertEqual(summary.actions_with_id_token_downstream, 1)


if __name__ == "__main__":
    unittest.main()
