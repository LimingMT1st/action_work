from __future__ import annotations

import unittest
from datetime import datetime, timezone

from gha_cascade_analyzer.analyzers.graph_types import CascadeGraph
from gha_cascade_analyzer.analyzers.privilege_risk import PrivilegeRiskByWorkflowMetric
from gha_cascade_analyzer.analyzers.propagation_risk import PropagationRiskAnalyzer
from gha_cascade_analyzer.models import WorkflowFile


def ts() -> datetime:
    return datetime(2026, 6, 4, tzinfo=timezone.utc)


class PropagationRiskAnalyzerTests(unittest.TestCase):
    def test_detects_cross_job_and_cross_workflow_propagation_signals(self) -> None:
        analyzer = PropagationRiskAnalyzer()
        workflows = [
            WorkflowFile(
                repository_full_name="owner/repo",
                path=".github/workflows/build.yml",
                sha="a" * 40,
                content="\n".join(
                    [
                        "name: build",
                        "on:",
                        "  workflow_run:",
                        "  workflow_call:",
                        "jobs:",
                        "  build:",
                        "    outputs:",
                        "      image: ${{ steps.meta.outputs.image }}",
                        "    steps:",
                        "      - uses: vendor/action@main",
                        "      - uses: actions/upload-artifact@v4",
                        "      - uses: actions/cache@v4",
                        "  deploy:",
                        "    needs: build",
                        "    steps:",
                        "      - uses: actions/download-artifact@v4",
                        "      - run: echo ${{ needs.build.outputs.image }}",
                        "      - uses: owner/repo/.github/workflows/reusable.yml@main",
                    ]
                ),
                discovered_at=ts(),
            )
        ]
        privilege_rows = [
            PrivilegeRiskByWorkflowMetric(
                repository_full_name="owner/repo",
                workflow_path=".github/workflows/build.yml",
                workflow_name="build",
                privilege_risk_score=5.0,
            )
        ]

        rows, summary, examples = analyzer.analyze(
            workflows=workflows,
            graph=CascadeGraph(),
            privilege_rows=privilege_rows,
        )

        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row.job_count, 2)
        self.assertEqual(row.job_dependency_edges, 1)
        self.assertTrue(row.has_artifact_upload)
        self.assertTrue(row.has_artifact_download)
        self.assertTrue(row.has_cache_save_restore)
        self.assertTrue(row.has_job_outputs)
        self.assertTrue(row.has_needs_outputs)
        self.assertTrue(row.has_workflow_run_trigger)
        self.assertTrue(row.has_workflow_call)
        self.assertTrue(row.has_reusable_workflow_call)
        self.assertTrue(row.privilege_propagation_coupling)
        self.assertTrue(row.mutable_to_downstream_propagation)
        self.assertEqual(summary.workflows_with_artifact_upload, 1)
        self.assertEqual(summary.workflows_with_privilege_propagation_coupling, 1)
        self.assertGreaterEqual(len(examples), 1)


if __name__ == "__main__":
    unittest.main()
