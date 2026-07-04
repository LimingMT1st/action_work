from __future__ import annotations

from dataclasses import dataclass
from statistics import median
import re

import yaml

from gha_cascade_analyzer.models import (
    IsolationRiskByJobMetric,
    IsolationRiskExampleMetric,
    IsolationRiskSummaryMetric,
    WorkflowFile,
)
from gha_cascade_analyzer.utils.parsing import parse_action_reference


SENSITIVE_KEYWORDS = (
    "deploy",
    "release",
    "publish",
    "upload",
    "docker push",
    "npm publish",
    "gh release",
    "kubectl",
    "terraform apply",
    "aws",
    "gcloud",
    "az ",
)
ENV_POLLUTION_PATTERNS = ("GITHUB_ENV", "GITHUB_PATH")
OUTPUT_PATTERNS = ("GITHUB_OUTPUT", "steps.", ".outputs")
FILESYSTEM_PATTERNS = (
    "./",
    "bash ",
    "sh ",
    "python ",
    "npm install",
    "make",
    "pytest",
    "docker build .",
)
ARTIFACT_ACTIONS = {
    "actions/cache",
    "actions/upload-artifact",
    "actions/download-artifact",
}


@dataclass
class _StepContext:
    kind: str
    action_reference: str | None
    trust_domain: str
    owner: str | None
    step_name: str
    run_command: str
    is_sensitive: bool
    env_signal: bool
    output_signal: bool
    filesystem_signal: bool


class IsolationRiskAnalyzer:
    def analyze(
        self,
        workflows: list[WorkflowFile],
    ) -> tuple[list[IsolationRiskByJobMetric], IsolationRiskSummaryMetric, list[IsolationRiskExampleMetric]]:
        if not workflows:
            return [], IsolationRiskSummaryMetric(), []

        by_job: list[IsolationRiskByJobMetric] = []
        for workflow in workflows:
            by_job.extend(self._analyze_workflow(workflow))

        summary = self._build_summary(by_job)
        examples = self._build_examples(by_job)
        return by_job, summary, examples

    def _analyze_workflow(self, workflow: WorkflowFile) -> list[IsolationRiskByJobMetric]:
        try:
            parsed = yaml.safe_load(workflow.content or "") or {}
        except yaml.YAMLError:
            return []
        if not isinstance(parsed, dict):
            return []
        jobs = parsed.get("jobs")
        if not isinstance(jobs, dict):
            return []

        repository_owner = workflow.repository_full_name.split("/", 1)[0].lower()
        workflow_name = str(parsed.get("name") or workflow.path)
        results: list[IsolationRiskByJobMetric] = []
        for job_id, job_value in jobs.items():
            if not isinstance(job_value, dict):
                continue
            steps = job_value.get("steps")
            if not isinstance(steps, list):
                continue
            result = self._analyze_job(
                repository_owner=repository_owner,
                repository_full_name=workflow.repository_full_name,
                workflow_path=workflow.path,
                workflow_name=workflow_name,
                job_id=str(job_id),
                job_value=job_value,
                steps=steps,
            )
            results.append(result)
        return results

    def _analyze_job(
        self,
        *,
        repository_owner: str,
        repository_full_name: str,
        workflow_path: str,
        workflow_name: str,
        job_id: str,
        job_value: dict,
        steps: list,
    ) -> IsolationRiskByJobMetric:
        contexts = [self._parse_step_context(repository_owner, step) for step in steps if isinstance(step, dict)]
        uses_contexts = [item for item in contexts if item.kind == "uses"]
        run_contexts = [item for item in contexts if item.kind == "run"]
        third_party_contexts = [item for item in uses_contexts if item.trust_domain == "third_party"]
        trust_domains = sorted({item.trust_domain for item in uses_contexts if item.trust_domain})
        action_owners = sorted({item.owner for item in uses_contexts if item.owner})
        action_references = [item.action_reference for item in uses_contexts if item.action_reference]
        sensitive_steps = [item.step_name or item.run_command[:80] for item in contexts if item.is_sensitive]

        env_signal = any(item.env_signal for item in contexts) or self._job_level_signal(job_value, ENV_POLLUTION_PATTERNS)
        output_signal = any(item.output_signal for item in contexts) or self._job_level_signal(job_value, OUTPUT_PATTERNS)
        filesystem_signal = any(item.filesystem_signal for item in contexts)
        shared_workspace_signal = filesystem_signal or any(
            item.action_reference and self._full_action_name(item.action_reference) in ARTIFACT_ACTIONS for item in uses_contexts
        )
        has_action_before_sensitive = self._has_action_before_sensitive_step(contexts)
        has_untrusted_before_sensitive = self._has_untrusted_action_before_sensitive_step(contexts)

        signal_score = (
            (2.0 if len(third_party_contexts) >= 2 else 0.0)
            + (1.5 if len(trust_domains) >= 2 else 0.0)
            + (2.5 if has_action_before_sensitive else 0.0)
            + (3.0 if has_untrusted_before_sensitive else 0.0)
            + (1.0 if shared_workspace_signal else 0.0)
            + (1.0 if env_signal else 0.0)
            + (1.0 if output_signal else 0.0)
            + (1.0 if filesystem_signal else 0.0)
        )

        return IsolationRiskByJobMetric(
            repository_full_name=repository_full_name,
            workflow_path=workflow_path,
            workflow_name=workflow_name,
            job_id=job_id,
            job_name=str(job_value.get("name")) if job_value.get("name") is not None else None,
            steps_count=len(contexts),
            uses_steps_count=len(uses_contexts),
            run_steps_count=len(run_contexts),
            third_party_uses_steps_count=len(third_party_contexts),
            distinct_action_owners=len(action_owners),
            distinct_trust_domains=len(trust_domains),
            has_multiple_third_party_actions_same_job=len(third_party_contexts) >= 2,
            has_mixed_trust_domains=len(trust_domains) >= 2,
            has_action_before_sensitive_run_step=has_action_before_sensitive,
            has_untrusted_action_before_deploy_step=has_untrusted_before_sensitive,
            shared_workspace_exposure_signal=shared_workspace_signal,
            env_pollution_signal=env_signal,
            output_dependency_signal=output_signal,
            filesystem_dependency_signal=filesystem_signal,
            trust_domains=trust_domains,
            action_owners=action_owners,
            action_references=action_references,
            sensitive_steps=sensitive_steps,
            signal_score=round(signal_score, 4),
        )

    def _parse_step_context(self, repository_owner: str, step: dict) -> _StepContext:
        step_name = str(step.get("name") or step.get("id") or "").strip()
        run_command = str(step.get("run") or "")
        if "uses" in step and isinstance(step["uses"], str):
            uses_value = step["uses"]
            trust_domain, owner = self._trust_domain(repository_owner, uses_value)
            combined = " ".join(
                [
                    step_name,
                    uses_value,
                    run_command,
                    str(step.get("with") or ""),
                    str(step.get("env") or ""),
                ]
            )
            return _StepContext(
                kind="uses",
                action_reference=uses_value,
                trust_domain=trust_domain,
                owner=owner,
                step_name=step_name,
                run_command=run_command,
                is_sensitive=self._is_sensitive_step(step_name, run_command),
                env_signal=self._contains_any(combined, ENV_POLLUTION_PATTERNS),
                output_signal=self._contains_any(combined, OUTPUT_PATTERNS),
                filesystem_signal=self._contains_any(combined, FILESYSTEM_PATTERNS)
                or self._full_action_name(uses_value) in ARTIFACT_ACTIONS,
            )

        combined = " ".join(
            [
                step_name,
                run_command,
                str(step.get("env") or ""),
            ]
        )
        return _StepContext(
            kind="run",
            action_reference=None,
            trust_domain="unknown",
            owner=None,
            step_name=step_name,
            run_command=run_command,
            is_sensitive=self._is_sensitive_step(step_name, run_command),
            env_signal=self._contains_any(combined, ENV_POLLUTION_PATTERNS),
            output_signal=self._contains_any(combined, OUTPUT_PATTERNS),
            filesystem_signal=self._contains_any(combined, FILESYSTEM_PATTERNS),
        )

    def _trust_domain(self, repository_owner: str, uses_value: str) -> tuple[str, str | None]:
        try:
            owner, repo, _, _ = parse_action_reference(uses_value)
        except ValueError:
            return "unknown", None
        owner_lower = owner.lower()
        full_name = f"{owner}/{repo}".lower()
        if owner_lower in {"actions", "github"}:
            return "github_owned", owner
        if owner_lower == repository_owner:
            return "same_owner", owner
        if re.fullmatch(r"[A-Za-z0-9_.-]+", owner):
            return "third_party", owner
        return "unknown", owner

    def _full_action_name(self, uses_value: str) -> str:
        try:
            owner, repo, _, _ = parse_action_reference(uses_value)
        except ValueError:
            return uses_value.lower()
        return f"{owner}/{repo}".lower()

    def _contains_any(self, content: str, needles: tuple[str, ...]) -> bool:
        lowered = content.lower()
        return any(needle.lower() in lowered for needle in needles)

    def _is_sensitive_step(self, step_name: str, run_command: str) -> bool:
        haystack = f"{step_name} {run_command}".lower()
        return any(keyword in haystack for keyword in SENSITIVE_KEYWORDS)

    def _has_action_before_sensitive_step(self, contexts: list[_StepContext]) -> bool:
        seen_action = False
        for item in contexts:
            if item.kind == "uses":
                seen_action = True
            if item.kind == "run" and item.is_sensitive and seen_action:
                return True
        return False

    def _has_untrusted_action_before_sensitive_step(self, contexts: list[_StepContext]) -> bool:
        seen_untrusted = False
        for item in contexts:
            if item.kind == "uses" and item.trust_domain in {"third_party", "unknown"}:
                seen_untrusted = True
            if item.kind == "run" and item.is_sensitive and seen_untrusted:
                return True
        return False

    def _job_level_signal(self, job_value: dict, needles: tuple[str, ...]) -> bool:
        combined = " ".join(
            [
                str(job_value.get("env") or ""),
                str(job_value.get("permissions") or ""),
                str(job_value.get("outputs") or ""),
            ]
        )
        return self._contains_any(combined, needles)

    def _build_summary(self, rows: list[IsolationRiskByJobMetric]) -> IsolationRiskSummaryMetric:
        if not rows:
            return IsolationRiskSummaryMetric()
        owner_counts = sorted(item.distinct_action_owners for item in rows)
        return IsolationRiskSummaryMetric(
            total_jobs=len(rows),
            jobs_with_multiple_actions=sum(1 for item in rows if item.uses_steps_count >= 2),
            jobs_with_mixed_trust_domains=sum(1 for item in rows if item.has_mixed_trust_domains),
            jobs_with_third_party_before_sensitive_step=sum(1 for item in rows if item.has_untrusted_action_before_deploy_step),
            jobs_with_env_pollution_signal=sum(1 for item in rows if item.env_pollution_signal),
            jobs_with_output_dependency_signal=sum(1 for item in rows if item.output_dependency_signal),
            jobs_with_filesystem_signal=sum(1 for item in rows if item.filesystem_dependency_signal),
            median_distinct_action_owners_per_job=float(median(owner_counts)) if owner_counts else None,
            p95_distinct_action_owners_per_job=self._percentile(owner_counts, 0.95),
        )

    def _build_examples(self, rows: list[IsolationRiskByJobMetric]) -> list[IsolationRiskExampleMetric]:
        candidates = [
            item
            for item in rows
            if item.has_untrusted_action_before_deploy_step
            or item.has_action_before_sensitive_run_step
            or item.has_mixed_trust_domains
        ]
        ordered = sorted(
            candidates,
            key=lambda item: (
                item.signal_score,
                item.third_party_uses_steps_count,
                item.distinct_action_owners,
                item.repository_full_name.lower(),
                item.job_id.lower(),
            ),
            reverse=True,
        )[:50]
        return [
            IsolationRiskExampleMetric(
                repository_full_name=item.repository_full_name,
                workflow_path=item.workflow_path,
                workflow_name=item.workflow_name,
                job_id=item.job_id,
                job_name=item.job_name,
                third_party_uses_steps_count=item.third_party_uses_steps_count,
                distinct_action_owners=item.distinct_action_owners,
                distinct_trust_domains=item.distinct_trust_domains,
                has_action_before_sensitive_run_step=item.has_action_before_sensitive_run_step,
                has_untrusted_action_before_deploy_step=item.has_untrusted_action_before_deploy_step,
                shared_workspace_exposure_signal=item.shared_workspace_exposure_signal,
                env_pollution_signal=item.env_pollution_signal,
                output_dependency_signal=item.output_dependency_signal,
                filesystem_dependency_signal=item.filesystem_dependency_signal,
                action_references=item.action_references,
                sensitive_steps=item.sensitive_steps,
                trust_domains=item.trust_domains,
                signal_score=item.signal_score,
            )
            for item in ordered
        ]

    def _percentile(self, values: list[int], quantile: float) -> float | None:
        if not values:
            return None
        index = max(0, min(len(values) - 1, int(round((len(values) - 1) * quantile))))
        return float(values[index])
