from __future__ import annotations

import unittest
from datetime import datetime, timezone

from gha_cascade_analyzer.analyzers.isolation_risk import IsolationRiskAnalyzer
from gha_cascade_analyzer.models import WorkflowFile


def ts() -> datetime:
    return datetime(2026, 6, 3, tzinfo=timezone.utc)


class IsolationRiskAnalyzerTests(unittest.TestCase):
    def test_detects_mixed_trust_domains_and_sensitive_step_predecessors(self) -> None:
        analyzer = IsolationRiskAnalyzer()
        workflows = [
            WorkflowFile(
                repository_full_name="owner/repo",
                path=".github/workflows/release.yml",
                sha="a" * 40,
                content="\n".join(
                    [
                        "name: release",
                        "jobs:",
                        "  publish:",
                        "    runs-on: ubuntu-latest",
                        "    steps:",
                        "      - uses: actions/checkout@v4",
                        "      - uses: vendor/third-party-action@v1",
                        "      - name: prepare env",
                        "        run: echo \"KEY=value\" >> $GITHUB_ENV",
                        "      - name: capture output",
                        "        run: echo \"tag=v1\" >> $GITHUB_OUTPUT",
                        "      - name: deploy release",
                        "        run: docker build . && docker push example/app",
                    ]
                ),
                discovered_at=ts(),
            )
        ]

        by_job, summary, examples = analyzer.analyze(workflows)
        self.assertEqual(len(by_job), 1)
        job = by_job[0]
        self.assertTrue(job.has_mixed_trust_domains)
        self.assertTrue(job.has_action_before_sensitive_run_step)
        self.assertTrue(job.has_untrusted_action_before_deploy_step)
        self.assertTrue(job.env_pollution_signal)
        self.assertTrue(job.output_dependency_signal)
        self.assertTrue(job.filesystem_dependency_signal)
        self.assertEqual(job.third_party_uses_steps_count, 1)
        self.assertEqual(summary.total_jobs, 1)
        self.assertEqual(summary.jobs_with_mixed_trust_domains, 1)
        self.assertEqual(summary.jobs_with_third_party_before_sensitive_step, 1)
        self.assertGreaterEqual(len(examples), 1)


if __name__ == "__main__":
    unittest.main()
