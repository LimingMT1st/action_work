from __future__ import annotations

from collections import defaultdict
import re

import yaml

from gha_cascade_analyzer.analyzers.ref_risk import HIGH_RISK_CATEGORIES, classify_ref_category
from gha_cascade_analyzer.models import (
    ReusableWorkflowEdgeMetric,
    ReusableWorkflowSummaryMetric,
    ReusableWorkflowTopCalleeMetric,
    WorkflowFile,
)
from gha_cascade_analyzer.utils.parsing import classify_ref, parse_action_reference


REMOTE_REUSABLE_PATTERN = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/[^@]+\.(?:yml|yaml)@.+$",
    re.IGNORECASE,
)
LOCAL_REUSABLE_PATTERN = re.compile(
    r"^\./\.github/workflows/[^@]+\.(?:yml|yaml)$",
    re.IGNORECASE,
)


class ReusableWorkflowAnalyzer:
    def analyze(
        self,
        workflows: list[WorkflowFile],
    ) -> tuple[list[ReusableWorkflowEdgeMetric], ReusableWorkflowSummaryMetric, list[ReusableWorkflowTopCalleeMetric]]:
        if not workflows:
            return [], ReusableWorkflowSummaryMetric(), []

        raw_edges: list[ReusableWorkflowEdgeMetric] = []
        callee_aggregate: dict[str, dict] = {}
        for workflow in workflows:
            raw_edges.extend(self._extract_edges(workflow))

        for edge in raw_edges:
            identifier = self._callee_identifier(edge)
            aggregate = callee_aggregate.setdefault(
                identifier,
                {
                    "callee_identifier": identifier,
                    "is_remote": edge.is_remote,
                    "call_count": 0,
                    "downstream_repositories": set(),
                    "mutable_edge_count": 0,
                    "secrets_inherit_count": 0,
                    "permissions_count": 0,
                    "id_token_write_count": 0,
                    "cross_org_count": 0,
                    "third_party_count": 0,
                },
            )
            aggregate["call_count"] += 1
            aggregate["downstream_repositories"].add(edge.caller_repository)
            aggregate["mutable_edge_count"] += int(edge.is_mutable_ref)
            aggregate["secrets_inherit_count"] += int(edge.has_secrets_inherit)
            aggregate["permissions_count"] += int(edge.has_permissions)
            aggregate["id_token_write_count"] += int(edge.has_id_token_write)
            aggregate["cross_org_count"] += int(edge.is_cross_org)
            aggregate["third_party_count"] += int(edge.is_third_party)

        for edge in raw_edges:
            edge.downstream_repo_count = len(callee_aggregate[self._callee_identifier(edge)]["downstream_repositories"])

        top_callees = [
            ReusableWorkflowTopCalleeMetric(
                callee_identifier=item["callee_identifier"],
                is_remote=item["is_remote"],
                call_count=item["call_count"],
                downstream_repo_count=len(item["downstream_repositories"]),
                mutable_edge_count=item["mutable_edge_count"],
                secrets_inherit_count=item["secrets_inherit_count"],
                permissions_count=item["permissions_count"],
                id_token_write_count=item["id_token_write_count"],
                cross_org_count=item["cross_org_count"],
                third_party_count=item["third_party_count"],
            )
            for item in callee_aggregate.values()
        ]
        top_callees.sort(
            key=lambda item: (
                item.downstream_repo_count,
                item.call_count,
                item.mutable_edge_count,
                item.callee_identifier.lower(),
            ),
            reverse=True,
        )
        summary = self._build_summary(raw_edges, top_callees)
        return raw_edges, summary, top_callees

    def _extract_edges(self, workflow: WorkflowFile) -> list[ReusableWorkflowEdgeMetric]:
        try:
            parsed = yaml.safe_load(workflow.content or "") or {}
        except yaml.YAMLError:
            return []
        if not isinstance(parsed, dict):
            return []

        workflow_permissions = self._normalize_permissions(parsed.get("permissions"))
        jobs = parsed.get("jobs")
        if not isinstance(jobs, dict):
            return []
        caller_owner = workflow.repository_full_name.split("/", 1)[0].lower()
        edges: list[ReusableWorkflowEdgeMetric] = []
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            uses_value = job.get("uses")
            if not isinstance(uses_value, str):
                continue
            if not self._is_reusable_workflow_call(uses_value):
                continue
            job_permissions = self._normalize_permissions(job.get("permissions"))
            effective_permissions = dict(workflow_permissions)
            effective_permissions.update({key: value for key, value in job_permissions.items() if value != "default"})
            has_permissions = any(value != "default" for value in effective_permissions.values())
            has_id_token_write = effective_permissions.get("id-token") == "write" or effective_permissions.get("write-all") == "write"
            has_secrets_inherit = str(job.get("secrets") or "").strip().lower() == "inherit"

            if self._is_local_reusable_workflow(uses_value):
                edge = ReusableWorkflowEdgeMetric(
                    caller_repository=workflow.repository_full_name,
                    caller_workflow_path=workflow.path,
                    caller_job=str(job_id),
                    callee_owner=workflow.repository_full_name.split("/", 1)[0],
                    callee_repo=workflow.repository_full_name.split("/", 1)[1],
                    callee_workflow_path=uses_value.removeprefix("./"),
                    callee_ref=None,
                    ref_type="LOCAL_PATH",
                    is_remote=False,
                    is_mutable_ref=False,
                    is_cross_org=False,
                    is_third_party=False,
                    has_secrets_inherit=has_secrets_inherit,
                    has_permissions=has_permissions,
                    has_id_token_write=has_id_token_write,
                )
                edges.append(edge)
                continue

            owner, repo, subpath, ref = parse_action_reference(uses_value)
            ref_category = classify_ref_category(ref)
            is_cross_org = owner.lower() != caller_owner
            is_third_party = owner.lower() not in {"actions", "github", caller_owner}
            edge = ReusableWorkflowEdgeMetric(
                caller_repository=workflow.repository_full_name,
                caller_workflow_path=workflow.path,
                caller_job=str(job_id),
                callee_owner=owner,
                callee_repo=repo,
                callee_workflow_path=subpath or "",
                callee_ref=ref,
                ref_type=ref_category,
                is_remote=True,
                is_mutable_ref=ref_category in HIGH_RISK_CATEGORIES or ref_category == "MAJOR_TAG",
                is_cross_org=is_cross_org,
                is_third_party=is_third_party,
                has_secrets_inherit=has_secrets_inherit,
                has_permissions=has_permissions,
                has_id_token_write=has_id_token_write,
            )
            edges.append(edge)
        return edges

    def _build_summary(
        self,
        edges: list[ReusableWorkflowEdgeMetric],
        top_callees: list[ReusableWorkflowTopCalleeMetric],
    ) -> ReusableWorkflowSummaryMetric:
        return ReusableWorkflowSummaryMetric(
            total_edges=len(edges),
            remote_edge_count=sum(1 for item in edges if item.is_remote),
            local_edge_count=sum(1 for item in edges if not item.is_remote),
            mutable_ref_edge_count=sum(1 for item in edges if item.is_mutable_ref),
            cross_org_edge_count=sum(1 for item in edges if item.is_cross_org),
            third_party_edge_count=sum(1 for item in edges if item.is_third_party),
            secrets_inherit_edge_count=sum(1 for item in edges if item.has_secrets_inherit),
            permissions_edge_count=sum(1 for item in edges if item.has_permissions),
            id_token_write_edge_count=sum(1 for item in edges if item.has_id_token_write),
            unique_callee_count=len({self._callee_identifier(item) for item in edges}),
            unique_remote_callee_count=len({self._callee_identifier(item) for item in edges if item.is_remote}),
        )

    def _normalize_permissions(self, value) -> dict[str, str]:
        if value is None:
            return {}
        if isinstance(value, str):
            return {"__root__": value.strip().lower()}
        if isinstance(value, dict):
            return {str(key): str(item).strip().lower() for key, item in value.items() if isinstance(item, str)}
        return {}

    def _is_reusable_workflow_call(self, uses_value: str) -> bool:
        return self._is_remote_reusable_workflow(uses_value) or self._is_local_reusable_workflow(uses_value)

    def _is_remote_reusable_workflow(self, uses_value: str) -> bool:
        return bool(REMOTE_REUSABLE_PATTERN.match(uses_value))

    def _is_local_reusable_workflow(self, uses_value: str) -> bool:
        return bool(LOCAL_REUSABLE_PATTERN.match(uses_value))

    def _callee_identifier(self, edge: ReusableWorkflowEdgeMetric) -> str:
        if edge.is_remote:
            return f"{edge.callee_owner}/{edge.callee_repo}/{edge.callee_workflow_path}@{edge.callee_ref}"
        return f"{edge.callee_owner}/{edge.callee_repo}/{edge.callee_workflow_path}"
