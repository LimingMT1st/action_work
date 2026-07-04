from __future__ import annotations

import unittest
from datetime import datetime, timezone

from gha_cascade_analyzer.analyzers.graph_types import CascadeGraph
from gha_cascade_analyzer.analyzers.trust_amplification import TrustAmplificationAnalyzer
from gha_cascade_analyzer.enums import ActionType, RefType, VerificationStatus
from gha_cascade_analyzer.models import ActionNode, BlastRadiusMetric, CDGEdge, RefRiskByActionMetric


def ts() -> datetime:
    return datetime(2026, 6, 4, tzinfo=timezone.utc)


def action(action_id: str, owner: str, repo: str, ref: str = "v1") -> ActionNode:
    return ActionNode(
        action_id=action_id,
        owner=owner,
        repo=repo,
        action_name=f"{owner}/{repo}",
        action_type=ActionType.UNKNOWN,
        ref=ref,
        ref_type=RefType.TAG,
        author_verified=VerificationStatus.UNKNOWN,
        discovered_at=ts(),
    )


class TrustAmplificationAnalyzerTests(unittest.TestCase):
    def test_owner_concentration_and_score_ordering(self) -> None:
        analyzer = TrustAmplificationAnalyzer()
        graph = CascadeGraph(
            actions={
                "a1": action("a1", "ownerA", "one", "main"),
                "a2": action("a2", "ownerA", "two", "v1"),
                "a3": action("a3", "ownerA", "three", "v2"),
                "b1": action("b1", "ownerB", "four", "v1"),
            },
            edges=[
                *[
                    CDGEdge(
                        edge_id=f"a{i}",
                        src_node_id=f"workflow::repo{i}::.github/workflows/ci.yml",
                        dst_node_id="a1",
                        src_kind="workflow",
                        dst_kind="action",
                        edge_type="direct",
                        workflow_path=".github/workflows/ci.yml",
                        consumer_repository=f"repo{i}",
                        discovered_at=ts(),
                    )
                    for i in range(60)
                ],
                *[
                    CDGEdge(
                        edge_id=f"b{i}",
                        src_node_id=f"workflow::repoB{i}::.github/workflows/ci.yml",
                        dst_node_id="b1",
                        src_kind="workflow",
                        dst_kind="action",
                        edge_type="direct",
                        workflow_path=".github/workflows/ci.yml",
                        consumer_repository=f"repoB{i}",
                        discovered_at=ts(),
                    )
                    for i in range(5)
                ],
            ],
        )
        blast_radius = [
            BlastRadiusMetric(action_id="a1", owner="ownerA", repo="one", downstream_repository_count=60),
            BlastRadiusMetric(action_id="a2", owner="ownerA", repo="two", downstream_repository_count=20),
            BlastRadiusMetric(action_id="a3", owner="ownerA", repo="three", downstream_repository_count=20),
            BlastRadiusMetric(action_id="b1", owner="ownerB", repo="four", downstream_repository_count=5),
        ]
        ref_risk = [
            RefRiskByActionMetric(action_id="a1", owner="ownerA", repo="one", full_name="ownerA/one", ref_name="main", usage_count=60, mutable_ref_ratio=1.0),
            RefRiskByActionMetric(action_id="a2", owner="ownerA", repo="two", full_name="ownerA/two", ref_name="v1", usage_count=20, mutable_ref_ratio=0.0),
            RefRiskByActionMetric(action_id="a3", owner="ownerA", repo="three", full_name="ownerA/three", ref_name="v2", usage_count=20, mutable_ref_ratio=0.0),
            RefRiskByActionMetric(action_id="b1", owner="ownerB", repo="four", full_name="ownerB/four", ref_name="v1", usage_count=5, mutable_ref_ratio=0.0),
        ]

        rows, summary, top_rows = analyzer.analyze(
            graph=graph,
            marketplace_identities=[],
            blast_radius=blast_radius,
            ref_risk_by_action=ref_risk,
            privilege_risk_by_workflow=[],
        )

        owner_rows = [row for row in rows if row.entity_type == "owner"]
        self.assertGreaterEqual(len(owner_rows), 2)
        self.assertEqual(owner_rows[0].entity_name, "ownerA")
        self.assertGreater(owner_rows[0].trust_amplification_score, owner_rows[1].trust_amplification_score)
        self.assertGreater(summary.top_1_owner_coverage, 0.5)
        self.assertGreater(summary.gini_coefficient_over_owner_usage, 0.0)
        self.assertGreater(summary.hhi_over_owner_usage, 0.0)
        self.assertGreaterEqual(len(top_rows), 1)


if __name__ == "__main__":
    unittest.main()
