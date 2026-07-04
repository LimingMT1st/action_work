from __future__ import annotations

import unittest
from datetime import datetime, timezone

from gha_cascade_analyzer.analyzers.amplification_metrics import AmplificationMetricsAnalyzer
from gha_cascade_analyzer.analyzers.graph_types import CascadeGraph
from gha_cascade_analyzer.enums import ActionType, RefType, VerificationStatus
from gha_cascade_analyzer.models import ActionNode


def ts() -> datetime:
    return datetime(2026, 6, 4, tzinfo=timezone.utc)


def action(action_id: str) -> ActionNode:
    return ActionNode(
        action_id=action_id,
        owner="owner",
        repo=action_id,
        action_name=f"owner/{action_id}",
        action_type=ActionType.UNKNOWN,
        ref="v1",
        ref_type=RefType.TAG,
        author_verified=VerificationStatus.UNKNOWN,
        discovered_at=ts(),
    )


class AmplificationMetricsAnalyzerTests(unittest.TestCase):
    def test_small_graph_reachability_and_depth(self) -> None:
        analyzer = AmplificationMetricsAnalyzer()
        graph = CascadeGraph(
            actions={
                "A": action("A"),
                "B": action("B"),
                "C": action("C"),
                "D": action("D"),
            },
            adjacency={
                "A": {"B", "C"},
                "B": {"D"},
                "C": set(),
                "D": set(),
            },
            reverse_adjacency={
                "B": {"A"},
                "C": {"A"},
                "D": {"B"},
                "A": set(),
            },
        )

        rows, summary, top_nodes = analyzer.analyze(graph=graph, blast_radius=[])
        by_id = {item.node_id: item for item in rows if item.node_kind == "action"}

        self.assertEqual(by_id["A"].transitive_fanout, 3)
        self.assertEqual(by_id["B"].transitive_fanout, 1)
        self.assertEqual(by_id["A"].out_degree, 2)
        self.assertEqual(by_id["B"].out_degree, 1)
        self.assertEqual(by_id["A"].max_downstream_depth, 2)
        self.assertEqual(by_id["B"].max_downstream_depth, 1)
        self.assertEqual(summary.total_action_nodes, 4)
        self.assertEqual(summary.max_fanout, 3)
        self.assertGreaterEqual(len(top_nodes), 1)


if __name__ == "__main__":
    unittest.main()
