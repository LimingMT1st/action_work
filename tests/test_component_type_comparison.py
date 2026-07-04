from __future__ import annotations

import unittest
from datetime import datetime, timezone

from gha_cascade_analyzer.analyzers.component_type_comparison import ComponentTypeComparisonAnalyzer
from gha_cascade_analyzer.enums import ActionType, RefType, VerificationStatus
from gha_cascade_analyzer.models import (
    ActionNode,
    AmplificationByNodeMetric,
    PrivilegedBlastRadiusByActionMetric,
    RefRiskByActionMetric,
)


def ts() -> datetime:
    return datetime(2026, 6, 9, tzinfo=timezone.utc)


class ComponentTypeComparisonAnalyzerTests(unittest.TestCase):
    def test_groups_actions_by_component_type(self) -> None:
        analyzer = ComponentTypeComparisonAnalyzer()
        rows = analyzer.analyze(
            actions=[
                ActionNode(
                    action_id="a1",
                    owner="org",
                    repo="js-action",
                    action_name="org/js-action",
                    action_type=ActionType.JAVASCRIPT,
                    ref="v1",
                    ref_type=RefType.TAG,
                    author_verified=VerificationStatus.UNKNOWN,
                    discovered_at=ts(),
                ),
                ActionNode(
                    action_id="a2",
                    owner="org",
                    repo="comp-action",
                    action_name="org/comp-action",
                    action_type=ActionType.COMPOSITE,
                    ref="v1",
                    ref_type=RefType.TAG,
                    author_verified=VerificationStatus.UNKNOWN,
                    discovered_at=ts(),
                ),
            ],
            ref_risk_by_action=[
                RefRiskByActionMetric(
                    action_id="a1",
                    owner="org",
                    repo="js-action",
                    full_name="org/js-action",
                    ref_name="v1",
                    ref_category="MAJOR_TAG",
                    usage_count=10,
                    downstream_repo_count=4,
                    mutable_ref_ratio=1.0,
                ),
                RefRiskByActionMetric(
                    action_id="a2",
                    owner="org",
                    repo="comp-action",
                    full_name="org/comp-action",
                    ref_name="v1",
                    ref_category="MAJOR_TAG",
                    usage_count=20,
                    downstream_repo_count=6,
                    mutable_ref_ratio=1.0,
                ),
            ],
            amplification_by_node=[
                AmplificationByNodeMetric(node_id="a1", node_kind="action", transitive_fanout=1, max_downstream_depth=1),
                AmplificationByNodeMetric(node_id="a2", node_kind="action", transitive_fanout=5, max_downstream_depth=3),
            ],
            privileged_blast_radius_by_action=[
                PrivilegedBlastRadiusByActionMetric(
                    action_id="a1",
                    owner="org",
                    repo="js-action",
                    full_name="org/js-action",
                    privileged_downstream_repository_count=2,
                    privileged_blast_radius_score=10.0,
                ),
                PrivilegedBlastRadiusByActionMetric(
                    action_id="a2",
                    owner="org",
                    repo="comp-action",
                    full_name="org/comp-action",
                    privileged_downstream_repository_count=4,
                    mutable_privileged_workflow_count=3,
                    privileged_blast_radius_score=20.0,
                ),
            ],
        )
        by_type = {item.component_type: item for item in rows}
        self.assertEqual(by_type["javascript"].action_count, 1)
        self.assertEqual(by_type["composite"].action_count, 1)
        self.assertEqual(by_type["composite"].privileged_downstream_repository_count, 4)
        self.assertEqual(by_type["composite"].mutable_privileged_workflow_count, 3)
        self.assertGreater(by_type["composite"].average_transitive_fanout, by_type["javascript"].average_transitive_fanout)


if __name__ == "__main__":
    unittest.main()
