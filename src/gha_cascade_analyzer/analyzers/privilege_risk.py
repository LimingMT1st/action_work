from __future__ import annotations

from collections import defaultdict
import re

import yaml

from gha_cascade_analyzer.analyzers.graph_types import CascadeGraph
from gha_cascade_analyzer.analyzers.ref_risk import HIGH_RISK_CATEGORIES, classify_ref_category
from gha_cascade_analyzer.models import (
    IsolationRiskByJobMetric,
    PrivilegeRiskByJobMetric,
    PrivilegeRiskByWorkflowMetric,
    PrivilegeRiskExampleMetric,
    PrivilegeRiskSummaryMetric,
    WorkflowFile,
)
from gha_cascade_analyzer.utils.parsing import parse_action_reference


PERMISSION_FIELDS = (
    ("contents", "contents_permission"),
    ("actions", "actions_permission"),
    ("checks", "checks_permission"),
    ("deployments", "deployments_permission"),
    ("id-token", "id_token_permission"),
    ("issues", "issues_permission"),
    ("packages", "packages_permission"),
    ("pull-requests", "pull_requests_permission"),
    ("security-events", "security_events_permission"),
    ("statuses", "statuses_permission"),
)
SECRET_KEYWORDS = (
    "secrets.",
    "GITHUB_TOKEN",
    "API_KEY",
    "TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CREDENTIALS",
    "NPM_TOKEN",
    "PYPI_TOKEN",
    "DOCKERHUB_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
)
CLOUD_CREDENTIAL_KEYWORDS = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CREDENTIALS",
    "aws-actions/configure-aws-credentials",
    "gcloud",
    "az login",
)


class PrivilegeRiskAnalyzer:
    def analyze(
        self,
        *,
        workflows: list[WorkflowFile],
        graph: CascadeGraph,
        isolation_rows: list[IsolationRiskByJobMetric],
    ) -> tuple[
        list[PrivilegeRiskByWorkflowMetric],
        list[PrivilegeRiskByJobMetric],
        PrivilegeRiskSummaryMetric,
        list[PrivilegeRiskExampleMetric],
    ]:
        if not workflows:
            return [], [], PrivilegeRiskSummaryMetric(), []

        depth_index = self._workflow_depth_index(graph)
        isolation_index = {
            (item.repository_full_name, item.workflow_path, item.job_id): item
            for item in isolation_rows
        }
        job_rows: list[PrivilegeRiskByJobMetric] = []
        workflow_job_index: dict[tuple[str, str], list[PrivilegeRiskByJobMetric]] = defaultdict(list)
        workflow_names: dict[tuple[str, str], str] = {}
        workflow_triggers: dict[tuple[str, str], list[str]] = {}

        for workflow in workflows:
            parsed = self._load_workflow(workflow)
            if parsed is None:
                continue
            workflow_name = str(parsed.get("name") or workflow.path)
            on_value = parsed.get("on")
            if on_value is None and True in parsed:
                on_value = parsed.get(True)
            trigger_events = self._extract_triggers(on_value)
            workflow_permissions = self._normalize_permissions(parsed.get("permissions"))
            jobs = parsed.get("jobs")
            if not isinstance(jobs, dict):
                continue
            workflow_key = (workflow.repository_full_name, workflow.path)
            workflow_names[workflow_key] = workflow_name
            workflow_triggers[workflow_key] = trigger_events
            repository_owner = workflow.repository_full_name.split("/", 1)[0].lower()

            for job_id, job_value in jobs.items():
                if not isinstance(job_value, dict):
                    continue
                row = self._analyze_job(
                    repository_owner=repository_owner,
                    repository_full_name=workflow.repository_full_name,
                    workflow_path=workflow.path,
                    workflow_name=workflow_name,
                    trigger_events=trigger_events,
                    job_id=str(job_id),
                    job_value=job_value,
                    workflow_permissions=workflow_permissions,
                    isolation_row=isolation_index.get((workflow.repository_full_name, workflow.path, str(job_id))),
                )
                job_rows.append(row)
                workflow_job_index[workflow_key].append(row)

        workflow_rows: list[PrivilegeRiskByWorkflowMetric] = []
        for workflow_key, rows in workflow_job_index.items():
            repository_full_name, workflow_path = workflow_key
            workflow_rows.append(
                self._build_workflow_row(
                    repository_full_name=repository_full_name,
                    workflow_path=workflow_path,
                    workflow_name=workflow_names.get(workflow_key, workflow_path),
                    trigger_events=workflow_triggers.get(workflow_key, []),
                    max_depth=depth_index.get(workflow_key, 0),
                    job_rows=rows,
                )
            )

        workflow_rows.sort(key=lambda item: (item.privilege_risk_score, item.privileged_job_count, item.repository_full_name.lower()), reverse=True)
        job_rows.sort(key=lambda item: (item.privilege_risk_score, item.mutable_third_party_action_count, item.repository_full_name.lower(), item.job_id.lower()), reverse=True)
        summary = self._build_summary(workflow_rows, job_rows)
        examples = self._build_examples(workflow_rows, job_rows)
        return workflow_rows, job_rows, summary, examples

    def _load_workflow(self, workflow: WorkflowFile) -> dict | None:
        try:
            parsed = yaml.safe_load(workflow.content or "") or {}
        except yaml.YAMLError:
            return None
        if not isinstance(parsed, dict):
            return None
        return parsed

    def _extract_triggers(self, on_value) -> list[str]:
        if isinstance(on_value, str):
            return [on_value]
        if isinstance(on_value, list):
            return [str(item) for item in on_value]
        if isinstance(on_value, dict):
            return [str(key) for key in on_value.keys()]
        return []

    def _normalize_permissions(self, permissions_value) -> dict[str, str]:
        normalized = {key: "default" for key, _ in PERMISSION_FIELDS}
        normalized["write-all"] = "none"
        normalized["read-all"] = "none"
        if permissions_value is None:
            return normalized
        if isinstance(permissions_value, str):
            value = permissions_value.strip().lower()
            if value in {"write-all", "read-all"}:
                normalized[value] = "write"
            return normalized
        if not isinstance(permissions_value, dict):
            return normalized
        for key, raw in permissions_value.items():
            key_text = str(key).strip().lower()
            value_text = str(raw).strip().lower()
            if key_text in {"write-all", "read-all"}:
                normalized[key_text] = "write"
                continue
            normalized[key_text] = self._normalize_permission_level(value_text)
        return normalized

    def _normalize_permission_level(self, value: str) -> str:
        if value in {"write", "read", "none"}:
            return value
        if value == "write-all":
            return "write"
        if value == "read-all":
            return "read"
        return "default"

    def _merge_permissions(self, workflow_permissions: dict[str, str], job_permissions: dict[str, str]) -> dict[str, str]:
        merged = dict(workflow_permissions)
        for key, value in job_permissions.items():
            if value != "default":
                merged[key] = value
        if job_permissions.get("write-all") == "write":
            merged["write-all"] = "write"
        if job_permissions.get("read-all") == "write":
            merged["read-all"] = "write"
        return merged

    def _analyze_job(
        self,
        *,
        repository_owner: str,
        repository_full_name: str,
        workflow_path: str,
        workflow_name: str,
        trigger_events: list[str],
        job_id: str,
        job_value: dict,
        workflow_permissions: dict[str, str],
        isolation_row: IsolationRiskByJobMetric | None,
    ) -> PrivilegeRiskByJobMetric:
        job_permissions = self._normalize_permissions(job_value.get("permissions"))
        effective_permissions = self._merge_permissions(workflow_permissions, job_permissions)
        steps = job_value.get("steps")
        steps_list = steps if isinstance(steps, list) else []

        secrets_in_env = self._contains_keywords(str(job_value.get("env") or ""), SECRET_KEYWORDS)
        secrets_in_with = False
        github_token_explicit = False
        cloud_credential_keywords = self._contains_keywords(str(job_value.get("env") or ""), CLOUD_CREDENTIAL_KEYWORDS)
        third_party_action_count = 0
        mutable_third_party_action_count = 0

        for step in steps_list:
            if not isinstance(step, dict):
                continue
            secrets_in_env = secrets_in_env or self._contains_keywords(str(step.get("env") or ""), SECRET_KEYWORDS)
            secrets_in_with = secrets_in_with or self._contains_keywords(str(step.get("with") or ""), SECRET_KEYWORDS)
            github_token_explicit = github_token_explicit or self._contains_keywords(
                " ".join([str(step.get("env") or ""), str(step.get("with") or ""), str(step.get("run") or "")]),
                ("GITHUB_TOKEN",),
            )
            cloud_credential_keywords = cloud_credential_keywords or self._contains_keywords(
                " ".join([str(step.get("env") or ""), str(step.get("with") or ""), str(step.get("run") or ""), str(step.get("uses") or "")]),
                CLOUD_CREDENTIAL_KEYWORDS,
            )
            uses_value = step.get("uses")
            if not isinstance(uses_value, str):
                continue
            trust_domain = self._trust_domain(repository_owner, uses_value)
            ref_category = self._ref_category(uses_value)
            if trust_domain == "third_party":
                third_party_action_count += 1
                if ref_category in HIGH_RISK_CATEGORIES or ref_category in {"MAJOR_TAG"}:
                    mutable_third_party_action_count += 1

        high_privilege = self._has_high_privilege(effective_permissions)
        has_id_token_write = self._permission_is_write(effective_permissions, "id-token")
        has_contents_write = self._permission_is_write(effective_permissions, "contents")
        has_actions_write = self._permission_is_write(effective_permissions, "actions")
        has_packages_write = self._permission_is_write(effective_permissions, "packages")
        has_deployments_write = self._permission_is_write(effective_permissions, "deployments")
        has_security_events_write = self._permission_is_write(effective_permissions, "security-events")
        has_write_all = effective_permissions.get("write-all") == "write"
        has_read_all = effective_permissions.get("read-all") == "write"
        has_pull_request_target = "pull_request_target" in {item.lower() for item in trigger_events}

        third_party_action_with_privilege = third_party_action_count > 0 and high_privilege
        mutable_third_party_action_with_privilege = mutable_third_party_action_count > 0 and high_privilege
        privilege_coupled_mutability = mutable_third_party_action_with_privilege
        isolation_privilege_coupling = bool(
            isolation_row
            and isolation_row.has_mixed_trust_domains
            and (high_privilege or secrets_in_env or secrets_in_with or github_token_explicit or cloud_credential_keywords)
        )
        has_any_high_privilege_signal = high_privilege or has_pull_request_target or secrets_in_env or secrets_in_with

        risk_score = (
            (6.0 if mutable_third_party_action_with_privilege else 0.0)
            + (4.5 if has_id_token_write else 0.0)
            + (4.0 if has_write_all else 0.0)
            + (3.0 if has_contents_write else 0.0)
            + (2.5 if has_actions_write else 0.0)
            + (2.0 if has_packages_write else 0.0)
            + (2.0 if has_deployments_write else 0.0)
            + (2.0 if has_security_events_write else 0.0)
            + (2.0 if secrets_in_with else 0.0)
            + (1.5 if secrets_in_env else 0.0)
            + (1.5 if github_token_explicit else 0.0)
            + (1.5 if cloud_credential_keywords else 0.0)
            + (2.0 if has_pull_request_target else 0.0)
            + (1.5 if isolation_privilege_coupling else 0.0)
        )

        row_kwargs = {
            "repository_full_name": repository_full_name,
            "workflow_path": workflow_path,
            "workflow_name": workflow_name,
            "job_id": job_id,
            "job_name": str(job_value.get("name")) if job_value.get("name") is not None else None,
            "trigger_events": trigger_events,
            "permission_keys": sorted([key for key, value in effective_permissions.items() if value != "default" and value != "none"]),
            "contents_permission": effective_permissions.get("contents", "default"),
            "actions_permission": effective_permissions.get("actions", "default"),
            "checks_permission": effective_permissions.get("checks", "default"),
            "deployments_permission": effective_permissions.get("deployments", "default"),
            "id_token_permission": effective_permissions.get("id-token", "default"),
            "issues_permission": effective_permissions.get("issues", "default"),
            "packages_permission": effective_permissions.get("packages", "default"),
            "pull_requests_permission": effective_permissions.get("pull-requests", "default"),
            "security_events_permission": effective_permissions.get("security-events", "default"),
            "statuses_permission": effective_permissions.get("statuses", "default"),
            "has_id_token_write": has_id_token_write,
            "has_contents_write": has_contents_write,
            "has_actions_write": has_actions_write,
            "has_packages_write": has_packages_write,
            "has_deployments_write": has_deployments_write,
            "has_security_events_write": has_security_events_write,
            "has_write_all": has_write_all,
            "has_read_all": has_read_all,
            "has_pull_request_target": has_pull_request_target,
            "secrets_in_env": secrets_in_env,
            "secrets_in_with": secrets_in_with,
            "github_token_explicit": github_token_explicit,
            "cloud_credential_keywords": cloud_credential_keywords,
            "third_party_action_with_privilege": third_party_action_with_privilege,
            "mutable_third_party_action_with_privilege": mutable_third_party_action_with_privilege,
            "privilege_coupled_mutability": privilege_coupled_mutability,
            "isolation_privilege_coupling": isolation_privilege_coupling,
            "has_any_high_privilege_signal": has_any_high_privilege_signal,
            "third_party_action_count": third_party_action_count,
            "mutable_third_party_action_count": mutable_third_party_action_count,
            "privilege_risk_score": round(risk_score, 4),
        }
        return PrivilegeRiskByJobMetric(**row_kwargs)

    def _build_workflow_row(
        self,
        *,
        repository_full_name: str,
        workflow_path: str,
        workflow_name: str,
        trigger_events: list[str],
        max_depth: int,
        job_rows: list[PrivilegeRiskByJobMetric],
    ) -> PrivilegeRiskByWorkflowMetric:
        def any_field(name: str) -> bool:
            return any(getattr(item, name) for item in job_rows)

        return PrivilegeRiskByWorkflowMetric(
            repository_full_name=repository_full_name,
            workflow_path=workflow_path,
            workflow_name=workflow_name,
            trigger_events=trigger_events,
            max_depth=max_depth,
            job_count=len(job_rows),
            privileged_job_count=sum(1 for item in job_rows if item.has_any_high_privilege_signal),
            has_id_token_write=any_field("has_id_token_write"),
            has_contents_write=any_field("has_contents_write"),
            has_actions_write=any_field("has_actions_write"),
            has_packages_write=any_field("has_packages_write"),
            has_deployments_write=any_field("has_deployments_write"),
            has_security_events_write=any_field("has_security_events_write"),
            has_write_all=any_field("has_write_all"),
            has_read_all=any_field("has_read_all"),
            has_pull_request_target=any_field("has_pull_request_target"),
            secrets_in_env=any_field("secrets_in_env"),
            secrets_in_with=any_field("secrets_in_with"),
            github_token_explicit=any_field("github_token_explicit"),
            cloud_credential_keywords=any_field("cloud_credential_keywords"),
            third_party_action_with_privilege=any_field("third_party_action_with_privilege"),
            mutable_third_party_action_with_privilege=any_field("mutable_third_party_action_with_privilege"),
            privilege_coupled_mutability=any_field("privilege_coupled_mutability"),
            isolation_privilege_coupling=any_field("isolation_privilege_coupling"),
            privilege_risk_score=round(sum(item.privilege_risk_score for item in job_rows), 4),
        )

    def _build_summary(
        self,
        workflow_rows: list[PrivilegeRiskByWorkflowMetric],
        job_rows: list[PrivilegeRiskByJobMetric],
    ) -> PrivilegeRiskSummaryMetric:
        return PrivilegeRiskSummaryMetric(
            total_workflows=len(workflow_rows),
            total_jobs=len(job_rows),
            workflows_with_id_token_write=sum(1 for item in workflow_rows if item.has_id_token_write),
            workflows_with_write_all=sum(1 for item in workflow_rows if item.has_write_all),
            workflows_with_pull_request_target=sum(1 for item in workflow_rows if item.has_pull_request_target),
            jobs_with_contents_write=sum(1 for item in job_rows if item.has_contents_write),
            jobs_with_actions_write=sum(1 for item in job_rows if item.has_actions_write),
            jobs_with_packages_write=sum(1 for item in job_rows if item.has_packages_write),
            jobs_with_deployments_write=sum(1 for item in job_rows if item.has_deployments_write),
            jobs_with_security_events_write=sum(1 for item in job_rows if item.has_security_events_write),
            jobs_with_secrets_in_env=sum(1 for item in job_rows if item.secrets_in_env),
            jobs_with_secrets_in_with=sum(1 for item in job_rows if item.secrets_in_with),
            jobs_with_github_token_explicit=sum(1 for item in job_rows if item.github_token_explicit),
            jobs_with_cloud_credential_keywords=sum(1 for item in job_rows if item.cloud_credential_keywords),
            jobs_with_privilege_coupled_mutability=sum(1 for item in job_rows if item.privilege_coupled_mutability),
            jobs_with_isolation_privilege_coupling=sum(1 for item in job_rows if item.isolation_privilege_coupling),
            privileged_mutable_job_count=sum(1 for item in job_rows if item.mutable_third_party_action_with_privilege),
        )

    def _build_examples(
        self,
        workflow_rows: list[PrivilegeRiskByWorkflowMetric],
        job_rows: list[PrivilegeRiskByJobMetric],
    ) -> list[PrivilegeRiskExampleMetric]:
        risky_jobs_by_workflow: dict[tuple[str, str], list[PrivilegeRiskByJobMetric]] = defaultdict(list)
        for item in job_rows:
            if item.privilege_risk_score <= 0:
                continue
            risky_jobs_by_workflow[(item.repository_full_name, item.workflow_path)].append(item)

        examples: list[PrivilegeRiskExampleMetric] = []
        for row in workflow_rows:
            key = (row.repository_full_name, row.workflow_path)
            risky_jobs = risky_jobs_by_workflow.get(key, [])
            if row.privilege_risk_score <= 0:
                continue
            examples.append(
                PrivilegeRiskExampleMetric(
                    repository_full_name=row.repository_full_name,
                    workflow_path=row.workflow_path,
                    workflow_name=row.workflow_name,
                    trigger_events=row.trigger_events,
                    max_depth=row.max_depth,
                    privileged_job_count=row.privileged_job_count,
                    has_id_token_write=row.has_id_token_write,
                    has_write_all=row.has_write_all,
                    has_pull_request_target=row.has_pull_request_target,
                    secrets_in_env=row.secrets_in_env,
                    secrets_in_with=row.secrets_in_with,
                    github_token_explicit=row.github_token_explicit,
                    cloud_credential_keywords=row.cloud_credential_keywords,
                    third_party_action_with_privilege=row.third_party_action_with_privilege,
                    mutable_third_party_action_with_privilege=row.mutable_third_party_action_with_privilege,
                    privilege_coupled_mutability=row.privilege_coupled_mutability,
                    isolation_privilege_coupling=row.isolation_privilege_coupling,
                    risky_job_ids=[item.job_id for item in risky_jobs[:10]],
                    privilege_risk_score=row.privilege_risk_score,
                )
            )
        examples.sort(key=lambda item: (item.privilege_risk_score, item.privileged_job_count, item.repository_full_name.lower()), reverse=True)
        return examples[:50]

    def _workflow_depth_index(self, graph: CascadeGraph) -> dict[tuple[str, str], int]:
        depths: dict[tuple[str, str], int] = {}
        for edge in graph.edges:
            if not edge.consumer_repository or not edge.workflow_path:
                continue
            key = (edge.consumer_repository, edge.workflow_path)
            current = depths.get(key, 0)
            if edge.depth > current:
                depths[key] = edge.depth
        return depths

    def _permission_is_write(self, permissions: dict[str, str], key: str) -> bool:
        return permissions.get("write-all") == "write" or permissions.get(key) == "write"

    def _has_high_privilege(self, permissions: dict[str, str]) -> bool:
        return any(
            [
                self._permission_is_write(permissions, "id-token"),
                self._permission_is_write(permissions, "contents"),
                self._permission_is_write(permissions, "actions"),
                self._permission_is_write(permissions, "packages"),
                self._permission_is_write(permissions, "deployments"),
                self._permission_is_write(permissions, "security-events"),
            ]
        )

    def _contains_keywords(self, content: str, keywords: tuple[str, ...]) -> bool:
        lowered = content.lower()
        return any(keyword.lower() in lowered for keyword in keywords)

    def _trust_domain(self, repository_owner: str, uses_value: str) -> str:
        try:
            owner, _, _, _ = parse_action_reference(uses_value)
        except ValueError:
            return "unknown"
        owner_lower = owner.lower()
        if owner_lower in {"actions", "github"}:
            return "github_owned"
        if owner_lower == repository_owner:
            return "same_owner"
        if re.fullmatch(r"[A-Za-z0-9_.-]+", owner):
            return "third_party"
        return "unknown"

    def _ref_category(self, uses_value: str) -> str:
        try:
            _, _, _, ref = parse_action_reference(uses_value)
        except ValueError:
            return "UNKNOWN_REF"
        return classify_ref_category(ref)
