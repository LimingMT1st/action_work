from __future__ import annotations

import unittest
from datetime import datetime, timezone

from gha_cascade_analyzer.analyzers.reusable_workflow import ReusableWorkflowAnalyzer
from gha_cascade_analyzer.models import WorkflowFile


def ts() -> datetime:
    return datetime(2026, 6, 4, tzinfo=timezone.utc)


class ReusableWorkflowAnalyzerTests(unittest.TestCase):
    def test_detects_remote_and_local_reusable_workflow_calls(self) -> None:
        analyzer = ReusableWorkflowAnalyzer()
        workflows = [
            WorkflowFile(
                repository_full_name="caller/repo",
                path=".github/workflows/ci.yml",
                sha="a" * 40,
                content="\n".join(
                    [
                        "name: CI",
                        "permissions:",
                        "  contents: read",
                        "jobs:",
                        "  build:",
                        "    uses: org/repo/.github/workflows/build.yml@v1",
                        "    secrets: inherit",
                        "  deploy:",
                        "    permissions:",
                        "      id-token: write",
                        "    uses: org/repo/.github/workflows/deploy.yaml@main",
                        "  local_job:",
                        "    uses: ./.github/workflows/local.yml",
                    ]
                ),
                discovered_at=ts(),
            )
        ]

        edges, summary, top_callees = analyzer.analyze(workflows)
        self.assertEqual(len(edges), 3)
        remote_build = next(item for item in edges if item.callee_workflow_path.endswith("build.yml"))
        remote_deploy = next(item for item in edges if item.callee_workflow_path.endswith("deploy.yaml"))
        local_edge = next(item for item in edges if not item.is_remote)

        self.assertTrue(remote_build.is_remote)
        self.assertEqual(remote_build.ref_type, "MAJOR_TAG")
        self.assertTrue(remote_build.has_secrets_inherit)
        self.assertTrue(remote_deploy.is_remote)
        self.assertEqual(remote_deploy.ref_type, "BRANCH_MAIN")
        self.assertTrue(remote_deploy.is_mutable_ref)
        self.assertTrue(remote_deploy.has_id_token_write)
        self.assertFalse(local_edge.is_remote)
        self.assertEqual(local_edge.ref_type, "LOCAL_PATH")
        self.assertEqual(summary.total_edges, 3)
        self.assertEqual(summary.remote_edge_count, 2)
        self.assertEqual(summary.local_edge_count, 1)
        self.assertGreaterEqual(len(top_callees), 1)


if __name__ == "__main__":
    unittest.main()
