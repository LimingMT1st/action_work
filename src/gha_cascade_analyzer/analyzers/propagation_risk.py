from __future__ import annotations

from collections import defaultdict, deque
from statistics import mean

import yaml

from gha_cascade_analyzer.analyzers.graph_types import CascadeGraph
from gha_cascade_analyzer.analyzers.privilege_risk import PrivilegeRiskByWorkflowMetric
from gha_cascade_analyzer.analyzers.ref_risk import HIGH_RISK_CATEGORIES, classify_ref_category
from gha_cascade_analyzer.models import (
    PropagationRiskByWorkflowMetric,
    PropagationRiskExampleMetric,
    PropagationRiskSummaryMetric,
    WorkflowFile,
)
from gha_cascade_analyzer.utils.parsing import parse_action_reference


ARTIFACT_UPLOAD_ACTIONS = {"actions/upload-artifact"}
ARTIFACT_DOWNLOAD_ACTIONS = {"actions/download-artifact"}
CACHE_ACTIONS = {"actions/cache"}
WORKFLOW_FILE_WRITE_PATTERNS = (".github/workflows", "gh workflow", "/dispatches", "workflow_dispatch", "repository_dispatch")


class PropagationRiskAnalyzer:
    def analyze(
        self,
        *,
        workflows: list[WorkflowFile],
        graph: CascadeGraph,
        privilege_rows: list[PrivilegeRiskByWorkflowMetric],
    ) -> tuple[list[PropagationRiskByWorkflowMetric], PropagationRiskSummaryMetric, list[PropagationRiskExampleMetric]]:
        if not workflows:
            return [], PropagationRiskSummaryMetric(), []

        privilege_index = {
            (item.repository_full_name, item.workflow_path): item
            for item in privilege_rows
        }
        rows: list[PropagationRiskByWorkflowMetric] = []
        for workflow in workflows:
            parsed = self._load_workflow(workflow)
            if parsed is None:
                continue
            row = self._analyze_workflow(
                workflow=workflow,
                parsed=parsed,
                graph=graph,
                privilege_row=privilege_index.get((workflow.repository_full_name, workflow.path)),
            )
            rows.append(row)

        rows.sort(key=lambda item: (item.propagation_risk_score, item.propagation_channel_count, item.repository_full_name.lower()), reverse=True)
        summary = self._build_summary(rows)
        examples = self._build_examples(rows)
        return rows, summary, examples

    def _load_workflow(self, workflow: WorkflowFile) -> dict | None:
        try:
            parsed = yaml.safe_load(workflow.content or "") or {}
        except yaml.YAMLError:
            return None
        if not isinstance(parsed, dict):
            return None
        return parsed

    def _analyze_workflow(
        self,
        *,
        workflow: WorkflowFile,
        parsed: dict,
        graph: CascadeGraph,
        privilege_row: PrivilegeRiskByWorkflowMetric | None,
    ) -> PropagationRiskByWorkflowMetric:
        workflow_name = str(parsed.get("name") or workflow.path)
        on_value = parsed.get("on")
        if on_value is None and True in parsed:
            on_value = parsed.get(True)
        trigger_events = self._extract_triggers(on_value)
        jobs = parsed.get("jobs")
        jobs_dict = jobs if isinstance(jobs, dict) else {}
        job_count = len(jobs_dict)
        job_dependency_edges = 0
        dependency_graph: dict[str, set[str]] = defaultdict(set)
        has_artifact_upload = False
        has_artifact_download = False
        has_cache_save_restore = False
        has_job_outputs = False
        has_needs_outputs = False
        has_reusable_workflow_call = False
        has_workflow_file_write_signal = False
        upstream_job_with_mutable = False
        downstream_depends_on_upstream = False

        job_mutable_flags: dict[str, bool] = {}

        for job_id, job_value in jobs_dict.items():
            if not isinstance(job_value, dict):
                continue
            needs = job_value.get("needs")
            need_list = self._normalize_needs(needs)
            job_dependency_edges += len(need_list)
            for need in need_list:
                dependency_graph[str(need)].add(str(job_id))
            if "outputs" in job_value:
                has_job_outputs = True

            steps = job_value.get("steps")
            steps_list = steps if isinstance(steps, list) else []
            job_mutable_flags[str(job_id)] = self._job_has_mutable_action(steps_list)
            for step in steps_list:
                if not isinstance(step, dict):
                    continue
                uses_value = step.get("uses")
                run_value = str(step.get("run") or "")
                if isinstance(uses_value, str):
                    action_name = self._full_action_name(uses_value)
                    if action_name in ARTIFACT_UPLOAD_ACTIONS:
                        has_artifact_upload = True
                    if action_name in ARTIFACT_DOWNLOAD_ACTIONS:
                        has_artifact_download = True
                    if action_name in CACHE_ACTIONS:
                        has_cache_save_restore = True
                    if action_name.endswith(".github/workflows") or "/.github/workflows/" in uses_value:
                        has_reusable_workflow_call = True
                combined = " ".join([run_value, str(step.get("with") or ""), str(step.get("env") or ""), str(step.get("name") or "")])
                if self._contains_any(combined, ("needs.", ".outputs")):
                    has_needs_outputs = True
                if self._contains_any(combined, WORKFLOW_FILE_WRITE_PATTERNS):
                    has_workflow_file_write_signal = True

        max_job_depth = self._compute_max_depth(jobs_dict.keys(), dependency_graph)
        has_workflow_run_trigger = "workflow_run" in {item.lower() for item in trigger_events}
        has_repository_dispatch = "repository_dispatch" in {item.lower() for item in trigger_events}
        has_workflow_dispatch = "workflow_dispatch" in {item.lower() for item in trigger_events}
        has_workflow_call = "workflow_call" in {item.lower() for item in trigger_events}

        if has_artifact_download or has_needs_outputs or has_cache_save_restore:
            for upstream, downstreams in dependency_graph.items():
                if job_mutable_flags.get(upstream):
                    upstream_job_with_mutable = True
                    if downstreams:
                        downstream_depends_on_upstream = True
                        break

        propagation_channel_count = sum(
            [
                has_artifact_upload,
                has_artifact_download,
                has_cache_save_restore,
                has_job_outputs,
                has_needs_outputs,
                has_workflow_run_trigger,
                has_repository_dispatch,
                has_workflow_dispatch,
                has_workflow_call,
                has_reusable_workflow_call,
                has_workflow_file_write_signal,
            ]
        )
        privilege_propagation_coupling = bool(
            privilege_row and privilege_row.privilege_risk_score > 0 and propagation_channel_count > 0
        )
        mutable_to_downstream_propagation = upstream_job_with_mutable and downstream_depends_on_upstream
        propagation_risk_score = (
            propagation_channel_count * 1.0
            + job_dependency_edges * 0.35
            + max_job_depth * 0.75
            + (2.5 if privilege_propagation_coupling else 0.0)
            + (2.0 if mutable_to_downstream_propagation else 0.0)
            + (1.0 if has_workflow_run_trigger else 0.0)
            + (1.0 if has_repository_dispatch else 0.0)
            + (1.0 if has_workflow_call or has_reusable_workflow_call else 0.0)
        )

        return PropagationRiskByWorkflowMetric(
            repository_full_name=workflow.repository_full_name,
            workflow_path=workflow.path,
            workflow_name=workflow_name,
            trigger_events=trigger_events,
            job_count=job_count,
            job_dependency_edges=job_dependency_edges,
            max_job_depth=max_job_depth,
            has_artifact_upload=has_artifact_upload,
            has_artifact_download=has_artifact_download,
            has_cache_save_restore=has_cache_save_restore,
            has_job_outputs=has_job_outputs,
            has_needs_outputs=has_needs_outputs,
            has_workflow_run_trigger=has_workflow_run_trigger,
            has_repository_dispatch=has_repository_dispatch,
            has_workflow_dispatch=has_workflow_dispatch,
            has_workflow_call=has_workflow_call,
            has_reusable_workflow_call=has_reusable_workflow_call,
            has_workflow_file_write_signal=has_workflow_file_write_signal,
            propagation_channel_count=propagation_channel_count,
            privilege_propagation_coupling=privilege_propagation_coupling,
            mutable_to_downstream_propagation=mutable_to_downstream_propagation,
            propagation_risk_score=round(propagation_risk_score, 4),
        )

    def _extract_triggers(self, on_value) -> list[str]:
        if isinstance(on_value, str):
            return [on_value]
        if isinstance(on_value, list):
            return [str(item) for item in on_value]
        if isinstance(on_value, dict):
            return [str(key) for key in on_value.keys()]
        return []

    def _normalize_needs(self, needs) -> list[str]:
        if isinstance(needs, str):
            return [needs]
        if isinstance(needs, list):
            return [str(item) for item in needs]
        return []

    def _job_has_mutable_action(self, steps: list[dict]) -> bool:
        for step in steps:
            uses_value = step.get("uses")
            if not isinstance(uses_value, str):
                continue
            try:
                _, _, _, ref = parse_action_reference(uses_value)
            except ValueError:
                continue
            if classify_ref_category(ref) in HIGH_RISK_CATEGORIES | {"MAJOR_TAG"}:
                return True
        return False

    def _compute_max_depth(self, job_ids, dependency_graph: dict[str, set[str]]) -> int:
        indegree: dict[str, int] = {str(job_id): 0 for job_id in job_ids}
        for upstream, downstreams in dependency_graph.items():
            indegree.setdefault(upstream, 0)
            for downstream in downstreams:
                indegree[downstream] = indegree.get(downstream, 0) + 1
        queue = deque([job for job, degree in indegree.items() if degree == 0])
        depth = {job: 0 for job in queue}
        max_depth = 0
        while queue:
            job = queue.popleft()
            current_depth = depth.get(job, 0)
            max_depth = max(max_depth, current_depth)
            for downstream in dependency_graph.get(job, set()):
                indegree[downstream] -= 1
                depth[downstream] = max(depth.get(downstream, 0), current_depth + 1)
                if indegree[downstream] == 0:
                    queue.append(downstream)
        return max_depth

    def _full_action_name(self, uses_value: str) -> str:
        try:
            owner, repo, _, _ = parse_action_reference(uses_value)
        except ValueError:
            return uses_value.lower()
        return f"{owner}/{repo}".lower()

    def _contains_any(self, content: str, needles: tuple[str, ...]) -> bool:
        lowered = content.lower()
        return any(needle.lower() in lowered for needle in needles)

    def _build_summary(self, rows: list[PropagationRiskByWorkflowMetric]) -> PropagationRiskSummaryMetric:
        if not rows:
            return PropagationRiskSummaryMetric()
        return PropagationRiskSummaryMetric(
            total_workflows=len(rows),
            workflows_with_artifact_upload=sum(1 for item in rows if item.has_artifact_upload),
            workflows_with_artifact_download=sum(1 for item in rows if item.has_artifact_download),
            workflows_with_cache_save_restore=sum(1 for item in rows if item.has_cache_save_restore),
            workflows_with_job_outputs=sum(1 for item in rows if item.has_job_outputs),
            workflows_with_needs_outputs=sum(1 for item in rows if item.has_needs_outputs),
            workflows_with_workflow_run_trigger=sum(1 for item in rows if item.has_workflow_run_trigger),
            workflows_with_repository_dispatch=sum(1 for item in rows if item.has_repository_dispatch),
            workflows_with_workflow_dispatch=sum(1 for item in rows if item.has_workflow_dispatch),
            workflows_with_workflow_call=sum(1 for item in rows if item.has_workflow_call),
            workflows_with_reusable_workflow_call=sum(1 for item in rows if item.has_reusable_workflow_call),
            workflows_with_privilege_propagation_coupling=sum(1 for item in rows if item.privilege_propagation_coupling),
            workflows_with_mutable_to_downstream_propagation=sum(1 for item in rows if item.mutable_to_downstream_propagation),
            average_job_dependency_edges=mean(item.job_dependency_edges for item in rows) if rows else None,
            max_job_depth=max(item.max_job_depth for item in rows) if rows else 0,
        )

    def _build_examples(self, rows: list[PropagationRiskByWorkflowMetric]) -> list[PropagationRiskExampleMetric]:
        candidates = [item for item in rows if item.propagation_risk_score > 0]
        ordered = sorted(
            candidates,
            key=lambda item: (
                item.propagation_risk_score,
                item.propagation_channel_count,
                item.job_dependency_edges,
                item.repository_full_name.lower(),
            ),
            reverse=True,
        )[:50]
        return [
            PropagationRiskExampleMetric(
                repository_full_name=item.repository_full_name,
                workflow_path=item.workflow_path,
                workflow_name=item.workflow_name,
                trigger_events=item.trigger_events,
                job_count=item.job_count,
                job_dependency_edges=item.job_dependency_edges,
                max_job_depth=item.max_job_depth,
                propagation_channel_count=item.propagation_channel_count,
                privilege_propagation_coupling=item.privilege_propagation_coupling,
                mutable_to_downstream_propagation=item.mutable_to_downstream_propagation,
                has_artifact_upload=item.has_artifact_upload,
                has_artifact_download=item.has_artifact_download,
                has_cache_save_restore=item.has_cache_save_restore,
                has_job_outputs=item.has_job_outputs,
                has_needs_outputs=item.has_needs_outputs,
                has_workflow_run_trigger=item.has_workflow_run_trigger,
                has_repository_dispatch=item.has_repository_dispatch,
                has_workflow_dispatch=item.has_workflow_dispatch,
                has_workflow_call=item.has_workflow_call,
                has_reusable_workflow_call=item.has_reusable_workflow_call,
                propagation_risk_score=item.propagation_risk_score,
            )
            for item in ordered
        ]
