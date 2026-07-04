from __future__ import annotations

import unittest
from datetime import datetime, timezone

from gha_cascade_analyzer.analyzers.discovery_risk import DiscoveryRiskAnalyzer
from gha_cascade_analyzer.analyzers.graph_types import CascadeGraph
from gha_cascade_analyzer.enums import ActionType, RefType, VerificationStatus
from gha_cascade_analyzer.models import ActionNode, RepositoryIdentityObservation, WorkflowFile


def ts() -> datetime:
    return datetime(2026, 6, 3, tzinfo=timezone.utc)


class DiscoveryRiskAnalyzerTests(unittest.TestCase):
    def test_expected_candidates_are_flagged_conservatively(self) -> None:
        analyzer = DiscoveryRiskAnalyzer(canonical_top_n=5)
        workflows = [
            WorkflowFile(
                repository_full_name="example/repo",
                path=".github/workflows/ci.yml",
                sha="a" * 40,
                content="\n".join(
                    [
                        "name: ci",
                        "jobs:",
                        "  build:",
                        "    runs-on: ubuntu-latest",
                        "    steps:",
                        "      - uses: actions/checkout@v4",
                        "      - uses: action/checkout@v4",
                        "      - uses: actions/check-out@v4",
                        "      - uses: action/removed@v1",
                    ]
                ),
                discovered_at=ts(),
            )
        ]
        graph = CascadeGraph(
            actions={
                "checkout": ActionNode(
                    action_id="checkout",
                    owner="actions",
                    repo="checkout",
                    action_name="actions/checkout",
                    action_type=ActionType.UNKNOWN,
                    ref="v4",
                    ref_type=RefType.TAG,
                    author_verified=VerificationStatus.VERIFIED,
                    marketplace_published=True,
                    discovered_at=ts(),
                ),
                "action_checkout": ActionNode(
                    action_id="action_checkout",
                    owner="action",
                    repo="checkout",
                    action_name="action/checkout",
                    action_type=ActionType.UNKNOWN,
                    ref="v4",
                    ref_type=RefType.TAG,
                    author_verified=VerificationStatus.UNKNOWN,
                    discovered_at=ts(),
                ),
                "check_out": ActionNode(
                    action_id="check_out",
                    owner="actions",
                    repo="check-out",
                    action_name="actions/check-out",
                    action_type=ActionType.UNKNOWN,
                    ref="v4",
                    ref_type=RefType.TAG,
                    author_verified=VerificationStatus.UNKNOWN,
                    discovered_at=ts(),
                ),
                "removed": ActionNode(
                    action_id="removed",
                    owner="action",
                    repo="removed",
                    action_name="action/removed",
                    action_type=ActionType.UNKNOWN,
                    ref="v1",
                    ref_type=RefType.TAG,
                    author_verified=VerificationStatus.UNKNOWN,
                    discovered_at=ts(),
                ),
            }
        )
        identity_observations = [
            RepositoryIdentityObservation(
                referenced_owner="actions",
                referenced_repo="checkout",
                referenced_full_name="actions/checkout",
                resolved_owner="actions",
                resolved_repo="checkout",
                resolved_full_name="actions/checkout",
                repository_id=1,
                star_count=1000,
                is_archived=False,
                status_code=200,
                identity_status="canonical",
                observed_at=ts(),
            ),
            RepositoryIdentityObservation(
                referenced_owner="action",
                referenced_repo="removed",
                referenced_full_name="action/removed",
                status_code=404,
                identity_status="missing",
                observed_at=ts(),
            ),
        ]

        candidates, summary = analyzer.analyze(
            graph=graph,
            workflows=workflows,
            workflow_changes=[],
            identity_observations=identity_observations,
            marketplace_identities=[],
        )
        by_name = {item.full_name: item for item in candidates}

        self.assertEqual(by_name["actions/checkout"].candidate_type, "none")
        self.assertEqual(by_name["action/checkout"].possible_typosquat_of, "actions/checkout")
        self.assertIn(by_name["action/checkout"].candidate_type, {"potential_typosquat", "potential_brand_confusion"})
        self.assertEqual(by_name["actions/check-out"].possible_typosquat_of, "actions/checkout")
        self.assertEqual(by_name["actions/check-out"].candidate_type, "potential_typosquat")
        self.assertTrue(by_name["action/removed"].is_deleted_or_unresolved)
        self.assertEqual(by_name["action/removed"].candidate_type, "unresolved_candidate")
        self.assertGreaterEqual(summary.typosquat_candidates, 2)
        self.assertGreaterEqual(summary.unresolved_candidates, 1)


if __name__ == "__main__":
    unittest.main()
