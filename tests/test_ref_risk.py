from __future__ import annotations

import unittest
from datetime import datetime, timezone

from gha_cascade_analyzer.analyzers.graph_types import CascadeGraph
from gha_cascade_analyzer.analyzers.ref_risk import RefRiskAnalyzer, classify_ref_category
from gha_cascade_analyzer.enums import ActionType, RefType, VerificationStatus
from gha_cascade_analyzer.models import ActionNode, BlastRadiusMetric, CDGEdge, DriftEvent


def ts() -> datetime:
    return datetime(2026, 6, 3, tzinfo=timezone.utc)


class RefRiskAnalyzerTests(unittest.TestCase):
    def test_ref_classification_categories(self) -> None:
        self.assertEqual(classify_ref_category("main"), "BRANCH_MAIN")
        self.assertEqual(classify_ref_category("v4"), "MAJOR_TAG")
        self.assertEqual(classify_ref_category("v4.1.7"), "SEMVER_TAG")
        self.assertEqual(classify_ref_category("a" * 40), "FULL_SHA")
        self.assertEqual(classify_ref_category("next"), "BRANCH_OTHER")

    def test_ref_risk_analysis_marks_drifted_mutable_refs(self) -> None:
        analyzer = RefRiskAnalyzer()
        graph = CascadeGraph(
            workflow_nodes={
                "workflow::consumer/repo::.github/workflows/ci.yml",
            },
            workflow_names={
                "workflow::consumer/repo::.github/workflows/ci.yml": "CI",
            },
            actions={
                "checkout_main": ActionNode(
                    action_id="checkout_main",
                    owner="actions",
                    repo="checkout",
                    action_name="actions/checkout",
                    action_type=ActionType.UNKNOWN,
                    ref="main",
                    ref_type=RefType.BRANCH,
                    author_verified=VerificationStatus.VERIFIED,
                    discovered_at=ts(),
                ),
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
                ),
                "checkout_semver": ActionNode(
                    action_id="checkout_semver",
                    owner="actions",
                    repo="checkout",
                    action_name="actions/checkout",
                    action_type=ActionType.UNKNOWN,
                    ref="v4.1.7",
                    ref_type=RefType.TAG,
                    author_verified=VerificationStatus.VERIFIED,
                    discovered_at=ts(),
                ),
                "checkout_sha": ActionNode(
                    action_id="checkout_sha",
                    owner="actions",
                    repo="checkout",
                    action_name="actions/checkout",
                    action_type=ActionType.UNKNOWN,
                    ref="a" * 40,
                    ref_type=RefType.SHA,
                    author_verified=VerificationStatus.VERIFIED,
                    discovered_at=ts(),
                ),
                "owner_next": ActionNode(
                    action_id="owner_next",
                    owner="owner",
                    repo="action",
                    action_name="owner/action",
                    action_type=ActionType.UNKNOWN,
                    ref="next",
                    ref_type=RefType.BRANCH,
                    author_verified=VerificationStatus.UNKNOWN,
                    discovered_at=ts(),
                ),
            },
            edges=[
                CDGEdge(
                    edge_id="1",
                    src_node_id="workflow::consumer/repo::.github/workflows/ci.yml",
                    dst_node_id="checkout_main",
                    src_kind="workflow",
                    dst_kind="action",
                    edge_type="direct",
                    ref_type=RefType.BRANCH,
                    ref_string="main",
                    workflow_path=".github/workflows/ci.yml",
                    consumer_repository="consumer/repo",
                    depth=1,
                    discovered_at=ts(),
                ),
                CDGEdge(
                    edge_id="2",
                    src_node_id="workflow::consumer/repo::.github/workflows/ci.yml",
                    dst_node_id="checkout_v4",
                    src_kind="workflow",
                    dst_kind="action",
                    edge_type="direct",
                    ref_type=RefType.TAG,
                    ref_string="v4",
                    workflow_path=".github/workflows/ci.yml",
                    consumer_repository="consumer/repo",
                    depth=1,
                    discovered_at=ts(),
                ),
                CDGEdge(
                    edge_id="3",
                    src_node_id="workflow::consumer/repo::.github/workflows/ci.yml",
                    dst_node_id="checkout_semver",
                    src_kind="workflow",
                    dst_kind="action",
                    edge_type="direct",
                    ref_type=RefType.TAG,
                    ref_string="v4.1.7",
                    workflow_path=".github/workflows/ci.yml",
                    consumer_repository="consumer/repo",
                    depth=1,
                    discovered_at=ts(),
                ),
                CDGEdge(
                    edge_id="4",
                    src_node_id="workflow::consumer/repo::.github/workflows/ci.yml",
                    dst_node_id="checkout_sha",
                    src_kind="workflow",
                    dst_kind="action",
                    edge_type="direct",
                    ref_type=RefType.SHA,
                    ref_string="a" * 40,
                    workflow_path=".github/workflows/ci.yml",
                    consumer_repository="consumer/repo",
                    depth=1,
                    discovered_at=ts(),
                ),
                CDGEdge(
                    edge_id="5",
                    src_node_id="workflow::consumer/repo::.github/workflows/ci.yml",
                    dst_node_id="owner_next",
                    src_kind="workflow",
                    dst_kind="action",
                    edge_type="direct",
                    ref_type=RefType.BRANCH,
                    ref_string="next",
                    workflow_path=".github/workflows/ci.yml",
                    consumer_repository="consumer/repo",
                    depth=2,
                    discovered_at=ts(),
                ),
            ],
            reverse_adjacency={
                "checkout_main": {"workflow::consumer/repo::.github/workflows/ci.yml"},
                "checkout_v4": {"workflow::consumer/repo::.github/workflows/ci.yml"},
                "checkout_semver": {"workflow::consumer/repo::.github/workflows/ci.yml"},
                "checkout_sha": {"workflow::consumer/repo::.github/workflows/ci.yml"},
                "owner_next": {"workflow::consumer/repo::.github/workflows/ci.yml"},
            },
        )
        blast_radius = [
            BlastRadiusMetric(action_id="checkout_main", owner="actions", repo="checkout", downstream_repository_count=1),
            BlastRadiusMetric(action_id="checkout_v4", owner="actions", repo="checkout", downstream_repository_count=1),
            BlastRadiusMetric(action_id="checkout_semver", owner="actions", repo="checkout", downstream_repository_count=1),
            BlastRadiusMetric(action_id="checkout_sha", owner="actions", repo="checkout", downstream_repository_count=1),
            BlastRadiusMetric(action_id="owner_next", owner="owner", repo="action", downstream_repository_count=1),
        ]
        drift_events = [
            DriftEvent(
                drift_id="d1",
                action_id="checkout_main",
                tag_name="main",
                ref_type=RefType.BRANCH,
                previous_sha="b" * 40,
                new_sha="c" * 40,
                detected_at=ts(),
                source="branch_head_change",
            )
        ]

        workflow_rows, summary, depth_rows, action_rows = analyzer.analyze(
            graph=graph,
            blast_radius=blast_radius,
            drift_events=drift_events,
        )

        self.assertEqual(len(workflow_rows), 1)
        self.assertEqual(summary.total_actions, 5)
        self.assertEqual(summary.branch_main_count, 1)
        self.assertEqual(summary.major_tag_count, 1)
        self.assertEqual(summary.semver_tag_count, 1)
        self.assertEqual(summary.full_sha_count, 1)
        self.assertEqual(summary.branch_other_count, 1)
        self.assertEqual(len(depth_rows), 3)

        by_action = {item.action_id: item for item in action_rows}
        self.assertEqual(by_action["checkout_main"].ref_category, "BRANCH_MAIN")
        self.assertTrue(by_action["checkout_main"].observed_drift)
        self.assertEqual(by_action["checkout_v4"].ref_category, "MAJOR_TAG")
        self.assertEqual(by_action["checkout_semver"].ref_category, "SEMVER_TAG")
        self.assertEqual(by_action["checkout_sha"].ref_category, "FULL_SHA")
        self.assertEqual(by_action["owner_next"].ref_category, "BRANCH_OTHER")
        self.assertEqual(by_action["checkout_sha"].immutable_ref_count, 1)
        self.assertEqual(by_action["checkout_sha"].mutable_ref_count, 0)


if __name__ == "__main__":
    unittest.main()
