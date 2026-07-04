from __future__ import annotations

from dataclasses import dataclass
import random
from statistics import mean

from gha_cascade_analyzer.models import (
    BootstrapIndicatorMetric,
    CrossOwnerEffectMetric,
    ManualValidationCandidateMetric,
    PrivilegeRiskByJobMetric,
    PrivilegeRiskByWorkflowMetric,
    PropagationRiskByWorkflowMetric,
    RefRiskByActionMetric,
    TrustAmplificationByEntityMetric,
    TrustDomainBoundaryMetric,
    WorkflowImplicitDependencyMetric,
)


@dataclass
class _BootstrapTarget:
    name: str
    population_kind: str
    values: list[float]
    notes: str | None = None


class EvidenceStrengthAnalyzer:
    def __init__(self, *, bootstrap_iterations: int = 500, seed: int = 42) -> None:
        self.bootstrap_iterations = bootstrap_iterations
        self.seed = seed

    def analyze(
        self,
        *,
        workflow_metrics: list[WorkflowImplicitDependencyMetric],
        ref_risk_by_workflow,
        privilege_risk_by_workflow: list[PrivilegeRiskByWorkflowMetric],
        privilege_risk_by_job: list[PrivilegeRiskByJobMetric],
        propagation_risk_by_workflow: list[PropagationRiskByWorkflowMetric],
        trust_domain_boundaries: list[TrustDomainBoundaryMetric],
        ref_risk_by_action: list[RefRiskByActionMetric],
        trust_amplification_by_entity: list[TrustAmplificationByEntityMetric],
    ) -> tuple[
        list[BootstrapIndicatorMetric],
        list[CrossOwnerEffectMetric],
        list[ManualValidationCandidateMetric],
    ]:
        bootstrap_rows = self._build_bootstrap_metrics(
            workflow_metrics=workflow_metrics,
            ref_risk_by_workflow=ref_risk_by_workflow,
            privilege_risk_by_workflow=privilege_risk_by_workflow,
            privilege_risk_by_job=privilege_risk_by_job,
            propagation_risk_by_workflow=propagation_risk_by_workflow,
            trust_domain_boundaries=trust_domain_boundaries,
            ref_risk_by_action=ref_risk_by_action,
            trust_amplification_by_entity=trust_amplification_by_entity,
        )
        cross_owner_effects = self._build_cross_owner_effects(
            trust_domain_boundaries=trust_domain_boundaries,
            ref_risk_by_workflow=ref_risk_by_workflow,
            privilege_risk_by_workflow=privilege_risk_by_workflow,
            propagation_risk_by_workflow=propagation_risk_by_workflow,
        )
        validation_candidates = self._build_manual_validation_candidates(
            privilege_risk_by_workflow=privilege_risk_by_workflow,
            privilege_risk_by_job=privilege_risk_by_job,
            propagation_risk_by_workflow=propagation_risk_by_workflow,
        )
        return bootstrap_rows, cross_owner_effects, validation_candidates

    def _build_bootstrap_metrics(
        self,
        *,
        workflow_metrics: list[WorkflowImplicitDependencyMetric],
        ref_risk_by_workflow,
        privilege_risk_by_workflow: list[PrivilegeRiskByWorkflowMetric],
        privilege_risk_by_job: list[PrivilegeRiskByJobMetric],
        propagation_risk_by_workflow: list[PropagationRiskByWorkflowMetric],
        trust_domain_boundaries: list[TrustDomainBoundaryMetric],
        ref_risk_by_action: list[RefRiskByActionMetric],
        trust_amplification_by_entity: list[TrustAmplificationByEntityMetric],
    ) -> list[BootstrapIndicatorMetric]:
        owner_rows = [item for item in trust_amplification_by_entity if item.entity_type == "owner"]
        targets = [
            _BootstrapTarget(
                name="non_zero_implicit_dependency_ratio",
                population_kind="workflow",
                values=[1.0 if item.transitive_actions > 0 else 0.0 for item in workflow_metrics],
                notes="workflow has non-zero transitive action surface",
            ),
            _BootstrapTarget(
                name="mutable_ref_ratio_per_workflow",
                population_kind="workflow",
                values=[float(item.mutable_ref_ratio) for item in ref_risk_by_workflow],
            ),
            _BootstrapTarget(
                name="isolation_privilege_coupling_ratio_per_job",
                population_kind="job",
                values=[1.0 if item.isolation_privilege_coupling else 0.0 for item in privilege_risk_by_job],
            ),
            _BootstrapTarget(
                name="privilege_propagation_coupling_ratio_per_workflow",
                population_kind="workflow",
                values=[1.0 if item.privilege_propagation_coupling else 0.0 for item in propagation_risk_by_workflow],
            ),
            _BootstrapTarget(
                name="external_owner_dependency_ratio_per_workflow",
                population_kind="workflow",
                values=[1.0 if item.has_external_owner_dependency else 0.0 for item in trust_domain_boundaries],
            ),
            _BootstrapTarget(
                name="observed_drift_ratio_per_action",
                population_kind="action",
                values=[1.0 if item.observed_drift else 0.0 for item in ref_risk_by_action],
            ),
            _BootstrapTarget(
                name="top10_owner_usage_share",
                population_kind="owner",
                values=[float(item.total_usage_count) for item in owner_rows],
                notes="share recomputed from bootstrap owner-usage resamples",
            ),
        ]

        rows: list[BootstrapIndicatorMetric] = []
        for target in targets:
            if not target.values:
                rows.append(
                    BootstrapIndicatorMetric(
                        indicator_name=target.name,
                        population_kind=target.population_kind,  # type: ignore[arg-type]
                        bootstrap_iterations=self.bootstrap_iterations,
                        notes=target.notes,
                    )
                )
                continue
            if target.name == "top10_owner_usage_share":
                point, lower, upper = self._bootstrap_topk_share(target.values, k=10)
            else:
                point = mean(target.values)
                lower, upper = self._bootstrap_mean_ci(target.values)
            rows.append(
                BootstrapIndicatorMetric(
                    indicator_name=target.name,
                    population_kind=target.population_kind,  # type: ignore[arg-type]
                    sample_count=len(target.values),
                    point_estimate=round(point, 6),
                    ci_lower=round(lower, 6) if lower is not None else None,
                    ci_upper=round(upper, 6) if upper is not None else None,
                    bootstrap_iterations=self.bootstrap_iterations,
                    notes=target.notes,
                )
            )
        return rows

    def _build_cross_owner_effects(
        self,
        *,
        trust_domain_boundaries: list[TrustDomainBoundaryMetric],
        ref_risk_by_workflow,
        privilege_risk_by_workflow: list[PrivilegeRiskByWorkflowMetric],
        propagation_risk_by_workflow: list[PropagationRiskByWorkflowMetric],
    ) -> list[CrossOwnerEffectMetric]:
        trust_index = {
            (item.repository_full_name, item.workflow_path): item
            for item in trust_domain_boundaries
        }
        ref_index = {
            (item.repository_full_name, item.workflow_path): item
            for item in ref_risk_by_workflow
        }
        privilege_index = {
            (item.repository_full_name, item.workflow_path): item
            for item in privilege_risk_by_workflow
        }
        propagation_index = {
            (item.repository_full_name, item.workflow_path): item
            for item in propagation_risk_by_workflow
        }

        grouped: dict[str, dict[str, list[float]]] = {
            "same_owner": {"mutable_ref_ratio": [], "privilege_risk_score": [], "propagation_channel_count": []},
            "cross_owner": {"mutable_ref_ratio": [], "privilege_risk_score": [], "propagation_channel_count": []},
        }
        for key, trust_row in trust_index.items():
            scope = "cross_owner" if trust_row.has_external_owner_dependency else "same_owner"
            ref_row = ref_index.get(key)
            privilege_row = privilege_index.get(key)
            propagation_row = propagation_index.get(key)
            if ref_row is not None:
                grouped[scope]["mutable_ref_ratio"].append(float(ref_row.mutable_ref_ratio))
            if privilege_row is not None:
                grouped[scope]["privilege_risk_score"].append(float(privilege_row.privilege_risk_score))
            if propagation_row is not None:
                grouped[scope]["propagation_channel_count"].append(float(propagation_row.propagation_channel_count))

        rows: list[CrossOwnerEffectMetric] = []
        for metric_name in ("mutable_ref_ratio", "privilege_risk_score", "propagation_channel_count"):
            same_values = grouped["same_owner"][metric_name]
            cross_values = grouped["cross_owner"][metric_name]
            point_same = mean(same_values) if same_values else None
            point_cross = mean(cross_values) if cross_values else None
            point_diff = (point_cross - point_same) if point_same is not None and point_cross is not None else None
            ci_lower, ci_upper = self._bootstrap_difference_ci(cross_values, same_values)
            rows.append(
                CrossOwnerEffectMetric(
                    metric_name=metric_name,
                    same_owner_count=len(same_values),
                    cross_owner_count=len(cross_values),
                    same_owner_mean=round(point_same, 6) if point_same is not None else None,
                    cross_owner_mean=round(point_cross, 6) if point_cross is not None else None,
                    difference_cross_minus_same=round(point_diff, 6) if point_diff is not None else None,
                    ci_lower=round(ci_lower, 6) if ci_lower is not None else None,
                    ci_upper=round(ci_upper, 6) if ci_upper is not None else None,
                    bootstrap_iterations=self.bootstrap_iterations,
                )
            )
        return rows

    def _build_manual_validation_candidates(
        self,
        *,
        privilege_risk_by_workflow: list[PrivilegeRiskByWorkflowMetric],
        privilege_risk_by_job: list[PrivilegeRiskByJobMetric],
        propagation_risk_by_workflow: list[PropagationRiskByWorkflowMetric],
    ) -> list[ManualValidationCandidateMetric]:
        workflow_jobs: dict[tuple[str, str], list[PrivilegeRiskByJobMetric]] = {}
        for row in privilege_risk_by_job:
            workflow_jobs.setdefault((row.repository_full_name, row.workflow_path), []).append(row)

        rq3_candidates: list[ManualValidationCandidateMetric] = []
        for workflow in privilege_risk_by_workflow:
            reasons: list[str] = []
            if workflow.isolation_privilege_coupling:
                reasons.append("mixed_trust_with_privilege")
            if workflow.privilege_coupled_mutability:
                reasons.append("mutable_third_party_with_privilege")
            if workflow.has_pull_request_target:
                reasons.append("pull_request_target")
            if workflow.has_id_token_write:
                reasons.append("id_token_write")
            if workflow.secrets_in_env or workflow.secrets_in_with:
                reasons.append("secret_bearing_configuration")
            if not reasons:
                continue
            risky_jobs = sorted(
                workflow_jobs.get((workflow.repository_full_name, workflow.workflow_path), []),
                key=lambda item: item.privilege_risk_score,
                reverse=True,
            )
            top_job = risky_jobs[0] if risky_jobs else None
            rq3_candidates.append(
                ManualValidationCandidateMetric(
                    rq_label="RQ3",
                    candidate_kind="workflow_privilege_isolation_review",
                    repository_full_name=workflow.repository_full_name,
                    workflow_path=workflow.workflow_path,
                    workflow_name=workflow.workflow_name,
                    job_id=top_job.job_id if top_job else None,
                    score=round(workflow.privilege_risk_score, 4),
                    reasons=reasons,
                    key_signals={
                        "privileged_job_count": workflow.privileged_job_count,
                        "has_id_token_write": workflow.has_id_token_write,
                        "has_pull_request_target": workflow.has_pull_request_target,
                        "secrets_in_env": workflow.secrets_in_env,
                        "secrets_in_with": workflow.secrets_in_with,
                        "top_job_score": top_job.privilege_risk_score if top_job else None,
                    },
                )
            )

        rq4_candidates: list[ManualValidationCandidateMetric] = []
        privilege_index = {
            (item.repository_full_name, item.workflow_path): item
            for item in privilege_risk_by_workflow
        }
        for workflow in propagation_risk_by_workflow:
            reasons: list[str] = []
            if workflow.privilege_propagation_coupling:
                reasons.append("privilege_propagation_coupling")
            if workflow.mutable_to_downstream_propagation:
                reasons.append("mutable_to_downstream_propagation")
            if workflow.has_artifact_upload and workflow.has_artifact_download:
                reasons.append("artifact_roundtrip")
            if workflow.has_workflow_run_trigger:
                reasons.append("workflow_run_trigger")
            if workflow.has_workflow_call or workflow.has_reusable_workflow_call:
                reasons.append("workflow_level_reuse")
            if not reasons:
                continue
            privilege_row = privilege_index.get((workflow.repository_full_name, workflow.workflow_path))
            rq4_candidates.append(
                ManualValidationCandidateMetric(
                    rq_label="RQ4",
                    candidate_kind="workflow_propagation_review",
                    repository_full_name=workflow.repository_full_name,
                    workflow_path=workflow.workflow_path,
                    workflow_name=workflow.workflow_name,
                    score=round(workflow.propagation_risk_score, 4),
                    reasons=reasons,
                    key_signals={
                        "propagation_channel_count": workflow.propagation_channel_count,
                        "job_dependency_edges": workflow.job_dependency_edges,
                        "max_job_depth": workflow.max_job_depth,
                        "has_artifact_upload": workflow.has_artifact_upload,
                        "has_artifact_download": workflow.has_artifact_download,
                        "has_workflow_run_trigger": workflow.has_workflow_run_trigger,
                        "privilege_risk_score": privilege_row.privilege_risk_score if privilege_row else None,
                    },
                )
            )

        rq3_candidates.sort(key=lambda item: item.score, reverse=True)
        rq4_candidates.sort(key=lambda item: item.score, reverse=True)
        return rq3_candidates[:50] + rq4_candidates[:50]

    def _bootstrap_mean_ci(self, values: list[float]) -> tuple[float | None, float | None]:
        if not values:
            return None, None
        rng = random.Random(self.seed)
        means = []
        n = len(values)
        for _ in range(self.bootstrap_iterations):
            sample = [values[rng.randrange(n)] for _ in range(n)]
            means.append(mean(sample))
        means.sort()
        return self._percentile(means, 0.025), self._percentile(means, 0.975)

    def _bootstrap_difference_ci(
        self,
        left_values: list[float],
        right_values: list[float],
    ) -> tuple[float | None, float | None]:
        if not left_values or not right_values:
            return None, None
        rng = random.Random(self.seed)
        diffs = []
        n_left = len(left_values)
        n_right = len(right_values)
        for _ in range(self.bootstrap_iterations):
            left_sample = [left_values[rng.randrange(n_left)] for _ in range(n_left)]
            right_sample = [right_values[rng.randrange(n_right)] for _ in range(n_right)]
            diffs.append(mean(left_sample) - mean(right_sample))
        diffs.sort()
        return self._percentile(diffs, 0.025), self._percentile(diffs, 0.975)

    def _bootstrap_topk_share(self, values: list[float], *, k: int) -> tuple[float, float | None, float | None]:
        point = self._topk_share(values, k)
        rng = random.Random(self.seed)
        shares = []
        n = len(values)
        for _ in range(self.bootstrap_iterations):
            sample = [values[rng.randrange(n)] for _ in range(n)]
            shares.append(self._topk_share(sample, k))
        shares.sort()
        return point, self._percentile(shares, 0.025), self._percentile(shares, 0.975)

    def _topk_share(self, values: list[float], k: int) -> float:
        if not values:
            return 0.0
        ordered = sorted(values, reverse=True)
        total = sum(ordered) or 1.0
        return sum(ordered[:k]) / total

    def _percentile(self, values: list[float], quantile: float) -> float | None:
        if not values:
            return None
        index = max(0, min(len(values) - 1, int(round((len(values) - 1) * quantile))))
        return float(values[index])
