from __future__ import annotations

import unittest
from datetime import datetime, timezone

from gha_cascade_analyzer.analyzers.graph_types import CascadeGraph
from gha_cascade_analyzer.analyzers.privilege_risk import PrivilegeRiskAnalyzer
from gha_cascade_analyzer.models import IsolationRiskByJobMetric, WorkflowFile


def ts() -> datetime:
    return datetime(2026, 6, 3, tzinfo=timezone.utc)


class PrivilegeRiskAnalyzerTests(unittest.TestCase):
    def test_detects_permissions_secrets_and_mutable_third_party_coupling(self) -> None:
        analyzer = PrivilegeRiskAnalyzer()
        workflows = [
            WorkflowFile(
                repository_full_name="owner/repo",
                path=".github/workflows/release.yml",
                sha="a" * 40,
                content="\n".join(
                    [
                        "name: release",
                        "on:",
                        "  pull_request_target:",
                        "  workflow_dispatch:",
                        "permissions:",
                        "  contents: write",
                        "jobs:",
                        "  publish:",
                        "    permissions:",
                        "      id-token: write",
                        "      write-all: write",
                        "    env:",
                        "      API_KEY: ${{ secrets.API_KEY }}",
                        "    steps:",
                        "      - uses: vendor/action@main",
                        "        with:",
                        "          token: ${{ secrets.NPM_TOKEN }}",
                        "      - name: deploy",
                        "        env:",
                        "          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
                        "          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}",
                        "        run: aws deploy && echo done",
                    ]
                ),
                discovered_at=ts(),
            )
        ]
        isolation_rows = [
            IsolationRiskByJobMetric(
                repository_full_name="owner/repo",
                workflow_path=".github/workflows/release.yml",
                workflow_name="release",
                job_id="publish",
                has_mixed_trust_domains=True,
            )
        ]

        workflow_rows, job_rows, summary, examples = analyzer.analyze(
            workflows=workflows,
            graph=CascadeGraph(),
            isolation_rows=isolation_rows,
        )

        self.assertEqual(len(workflow_rows), 1)
        self.assertEqual(len(job_rows), 1)
        job = job_rows[0]
        workflow = workflow_rows[0]
        self.assertTrue(job.has_id_token_write)
        self.assertTrue(job.has_contents_write)
        self.assertTrue(job.has_write_all)
        self.assertTrue(job.secrets_in_env)
        self.assertTrue(job.secrets_in_with)
        self.assertTrue(job.mutable_third_party_action_with_privilege)
        self.assertTrue(job.has_pull_request_target)
        self.assertTrue(job.github_token_explicit)
        self.assertTrue(job.cloud_credential_keywords)
        self.assertTrue(job.privilege_coupled_mutability)
        self.assertTrue(job.isolation_privilege_coupling)
        self.assertTrue(workflow.mutable_third_party_action_with_privilege)
        self.assertEqual(summary.workflows_with_id_token_write, 1)
        self.assertEqual(summary.jobs_with_privilege_coupled_mutability, 1)
        self.assertGreaterEqual(len(examples), 1)


if __name__ == "__main__":
    unittest.main()
