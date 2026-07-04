from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, HttpUrl

from gha_cascade_analyzer.enums import ActionType, RefType, VerificationStatus


class Repository(BaseModel):
    repo_id: int
    owner: str
    name: str
    full_name: str
    html_url: HttpUrl
    stars: int = Field(ge=0)
    organization: str | None = None
    default_branch: str
    workflow_paths: list[str] = Field(default_factory=list)
    is_fork: bool = False
    archived: bool = False
    collected_at: datetime


class WorkflowFile(BaseModel):
    repository_full_name: str
    path: str
    sha: str
    download_url: HttpUrl | None = None
    content: str | None = None
    discovered_at: datetime


class ActionNode(BaseModel):
    action_id: str
    owner: str
    repo: str
    subpath: str | None = None
    action_name: str
    action_type: ActionType = ActionType.UNKNOWN
    ref: str
    ref_type: RefType = RefType.UNKNOWN
    resolved_sha: str | None = None
    author_verified: VerificationStatus = VerificationStatus.UNKNOWN
    marketplace_published: bool = False
    marketplace_category: str | None = None
    declared_permissions: dict[str, str] = Field(default_factory=dict)
    has_token_access: bool = False
    token_access_patterns: list[str] = Field(default_factory=list)
    audited_source_files: list[str] = Field(default_factory=list)
    source_repository_id: int | None = None
    discovered_at: datetime


class CDGEdge(BaseModel):
    edge_id: str
    src_node_id: str
    dst_node_id: str
    src_kind: str
    dst_kind: str
    edge_type: str
    ref_type: RefType = RefType.UNKNOWN
    ref_string: str | None = None
    is_dynamic_ref: bool = False
    binding_downgrade: bool = False
    workflow_path: str | None = None
    job_name: str | None = None
    step_name: str | None = None
    depth: int = Field(ge=1, default=1)
    consumer_repository: str | None = None
    discovered_at: datetime


class WorkflowUseChange(BaseModel):
    repository_full_name: str
    workflow_path: str
    commit_sha: str
    committed_at: datetime
    uses_before: list[str] = Field(default_factory=list)
    uses_after: list[str] = Field(default_factory=list)
    introduced: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)


class MarketplaceActionIdentity(BaseModel):
    slug: str
    title: str
    description: str | None = None
    owner: str | None = None
    repository: str | None = None
    category: str | None = None
    verified_creator: bool = False
    badge_text: str | None = None
    marketplace_url: HttpUrl
    collected_at: datetime


class RefObservation(BaseModel):
    action_id: str
    owner: str
    repo: str
    ref_name: str
    ref_type: RefType
    sha: str
    observed_at: datetime
    source: Literal["ls_remote"] = "ls_remote"


class RepositoryIdentityObservation(BaseModel):
    referenced_owner: str
    referenced_repo: str
    referenced_full_name: str
    resolved_owner: str | None = None
    resolved_repo: str | None = None
    resolved_full_name: str | None = None
    repository_id: int | None = None
    star_count: int | None = None
    is_archived: bool | None = None
    is_fork: bool | None = None
    status_code: int
    identity_status: Literal["canonical", "redirected", "missing", "inaccessible"] = "canonical"
    final_url: str | None = None
    observed_at: datetime


class DriftEvent(BaseModel):
    drift_id: str
    action_id: str
    tag_name: str
    ref_type: RefType = RefType.TAG
    previous_sha: str
    new_sha: str
    detected_at: datetime
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    source: Literal["tag_move", "release_repoint", "branch_head_change"]
    notes: str | None = None


class WorkflowImplicitDependencyMetric(BaseModel):
    repository_full_name: str
    workflow_path: str
    direct_actions: int = 0
    transitive_actions: int = 0
    total_actions: int = 0
    implicit_dependency_ratio: float = 0.0


class DriftDistributionMetric(BaseModel):
    action_type: ActionType = ActionType.UNKNOWN
    author_verified: VerificationStatus = VerificationStatus.UNKNOWN
    ref_type: RefType = RefType.UNKNOWN
    source: str = "unknown"
    drift_event_count: int = 0
    unique_action_count: int = 0
    unique_ref_count: int = 0


class BlastRadiusMetric(BaseModel):
    action_id: str
    owner: str
    repo: str
    downstream_repository_count: int = 0
    downstream_high_star_repository_count: int = 0
    downstream_high_star_coverage: int = 0
    influenced_repositories: list[str] = Field(default_factory=list)


class ExposureWindowMetric(BaseModel):
    action_id: str
    owner: str
    repo: str
    patch_commit_sha: str
    downstream_repository: str
    workflow_path: str
    patch_detected_at: datetime
    updated_at: datetime
    lag_hours: float


class UpdateWindowMetric(BaseModel):
    event_id: str
    action_id: str
    owner: str
    repo: str
    ref_name: str
    ref_type: RefType = RefType.UNKNOWN
    repository_full_name: str
    workflow_path: str
    adoption_mode: Literal["explicit", "implicit"]
    dependency_depth: int = 1
    depth_bucket: Literal["level_1", "level_2", "level_3_plus"] = "level_1"
    upstream_changed_at: datetime
    adopted_at: datetime
    lag_hours: float = 0.0
    prior_ref: str | None = None
    adopted_ref: str | None = None
    evidence: str | None = None


class DriftObservationCoverageMetric(BaseModel):
    observed_action_count: int = 0
    observed_repository_count: int = 0
    observed_ref_count: int = 0
    observed_tag_count: int = 0
    observed_branch_count: int = 0
    observation_count: int = 0
    observation_span_hours: float = 0.0
    drift_event_count: int = 0
    drifted_action_count: int = 0
    drifted_ref_count: int = 0


class RepositoryTransferRiskMetric(BaseModel):
    referenced_full_name: str
    resolved_full_name: str | None = None
    latest_repository_id: int | None = None
    risk_type: Literal["redirected", "missing", "repository_id_changed"]
    latest_identity_status: Literal["canonical", "redirected", "missing", "inaccessible"] = "canonical"
    observation_count: int = 0
    first_observed_at: datetime | None = None
    last_observed_at: datetime | None = None
    affected_action_count: int = 0
    affected_repository_count: int = 0
    affected_workflow_count: int = 0
    privileged_workflow_count: int = 0
    sha_reference_count: int = 0
    tag_reference_count: int = 0
    branch_reference_count: int = 0
    main_reference_count: int = 0


class RepositoryTransferRiskSummaryMetric(BaseModel):
    observed_action_repository_count: int = 0
    risky_action_repository_count: int = 0
    redirected_repository_count: int = 0
    missing_repository_count: int = 0
    repository_id_changed_count: int = 0
    affected_action_count: int = 0
    affected_repository_count: int = 0
    affected_workflow_count: int = 0
    privileged_workflow_count: int = 0


class TrustDomainBoundaryMetric(BaseModel):
    workflow_name: str
    repository_full_name: str
    workflow_path: str
    max_depth: int = 0
    unique_action_owner_count: int = 0
    unique_external_owner_count: int = 0
    direct_cross_owner_edge_count: int = 0
    transitive_cross_owner_edge_count: int = 0
    total_cross_owner_edge_count: int = 0
    same_owner_edge_count: int = 0
    privileged_cross_owner_path_count: int = 0
    has_external_owner_dependency: bool = False
    has_transitive_cross_owner_dependency: bool = False
    has_multi_owner_cascade: bool = False


class TrustDomainBoundarySummaryMetric(BaseModel):
    workflow_count: int = 0
    workflows_with_external_owner_dependency: int = 0
    workflows_with_transitive_cross_owner_dependency: int = 0
    workflows_with_multi_owner_cascade: int = 0
    workflows_with_privileged_cross_owner_path: int = 0
    average_unique_action_owner_count: float | None = None
    average_unique_external_owner_count: float | None = None
    max_unique_action_owner_count: int = 0
    max_unique_external_owner_count: int = 0
    total_cross_owner_edge_count: int = 0
    direct_cross_owner_edge_count: int = 0
    transitive_cross_owner_edge_count: int = 0


class DiscoveryRiskCandidateMetric(BaseModel):
    normalized_name: str
    owner: str
    repo: str
    full_name: str
    usage_count: int = 0
    downstream_repo_count: int = 0
    star_count: int | None = None
    marketplace_verified: bool | None = None
    is_archived: bool | None = None
    is_deleted_or_unresolved: bool = False
    possible_typosquat_of: str | None = None
    edit_distance_to_popular_action: int | None = None
    brand_confusion_score: float = 0.0
    redirection_or_transfer_signal: str | None = None
    discovery_risk_score: float = 0.0
    candidate_reasons: list[str] = Field(default_factory=list)
    candidate_type: Literal["none", "potential_typosquat", "potential_brand_confusion", "redirection_candidate", "unresolved_candidate"] = "none"


class DiscoveryRiskSummaryMetric(BaseModel):
    total_actions: int = 0
    typosquat_candidates: int = 0
    redirection_candidates: int = 0
    unresolved_candidates: int = 0
    affected_workflows: int = 0
    affected_repositories: int = 0
    top_20_candidates_by_risk_score: str = ""


class RefRiskByWorkflowMetric(BaseModel):
    workflow_name: str
    repository_full_name: str
    workflow_path: str
    max_depth: int = 0
    total_ref_count: int = 0
    full_sha_count: int = 0
    short_sha_count: int = 0
    branch_main_count: int = 0
    branch_other_count: int = 0
    major_tag_count: int = 0
    semver_tag_count: int = 0
    floating_tag_count: int = 0
    unknown_ref_count: int = 0
    mutable_ref_count: int = 0
    immutable_ref_count: int = 0
    branch_ref_count: int = 0
    tag_ref_count: int = 0
    sha_ref_count: int = 0
    mutable_ref_ratio: float = 0.0
    high_risk_ref_ratio: float = 0.0
    downstream_repo_count: int = 0
    blast_radius_weighted_mutability_score: float = 0.0
    observed_drift: bool = False
    observed_drift_ref_count: int = 0
    affected_downstream_repositories: int = 0
    drift_amplification_score: float = 0.0


class RefRiskSummaryMetric(BaseModel):
    total_workflows: int = 0
    total_actions: int = 0
    total_ref_count: int = 0
    full_sha_count: int = 0
    short_sha_count: int = 0
    branch_main_count: int = 0
    branch_other_count: int = 0
    major_tag_count: int = 0
    semver_tag_count: int = 0
    floating_tag_count: int = 0
    unknown_ref_count: int = 0
    mutable_ref_count: int = 0
    immutable_ref_count: int = 0
    branch_ref_count: int = 0
    tag_ref_count: int = 0
    sha_ref_count: int = 0
    mutable_ref_ratio: float = 0.0
    high_risk_ref_ratio: float = 0.0
    observed_drift_ref_count: int = 0
    observed_drift_action_count: int = 0
    affected_downstream_repositories: int = 0
    blast_radius_weighted_mutability_score: float = 0.0
    drift_amplification_score: float = 0.0


class RefRiskByDepthMetric(BaseModel):
    depth_bucket: Literal["level_1", "level_2", "level_3_plus"]
    workflow_count: int = 0
    total_ref_count: int = 0
    full_sha_count: int = 0
    short_sha_count: int = 0
    branch_main_count: int = 0
    branch_other_count: int = 0
    major_tag_count: int = 0
    semver_tag_count: int = 0
    floating_tag_count: int = 0
    unknown_ref_count: int = 0
    mutable_ref_count: int = 0
    immutable_ref_count: int = 0
    branch_ref_count: int = 0
    tag_ref_count: int = 0
    sha_ref_count: int = 0
    mutable_ref_ratio: float = 0.0
    high_risk_ref_ratio: float = 0.0
    observed_drift_ref_count: int = 0
    affected_downstream_repositories: int = 0
    blast_radius_weighted_mutability_score: float = 0.0
    drift_amplification_score: float = 0.0


class RefRiskByActionMetric(BaseModel):
    action_id: str
    owner: str
    repo: str
    full_name: str
    ref_name: str
    ref_category: Literal[
        "FULL_SHA",
        "SHORT_SHA",
        "BRANCH_MAIN",
        "BRANCH_OTHER",
        "MAJOR_TAG",
        "SEMVER_TAG",
        "FLOATING_TAG",
        "UNKNOWN_REF",
    ] = "UNKNOWN_REF"
    usage_count: int = 0
    workflow_count: int = 0
    downstream_repo_count: int = 0
    mutable_ref_count: int = 0
    immutable_ref_count: int = 0
    branch_ref_count: int = 0
    tag_ref_count: int = 0
    sha_ref_count: int = 0
    mutable_ref_ratio: float = 0.0
    high_risk_ref_ratio: float = 0.0
    observed_drift: bool = False
    observed_drift_event_count: int = 0
    affected_downstream_repositories: int = 0
    blast_radius_weighted_mutability_score: float = 0.0
    drift_amplification_score: float = 0.0


class IsolationRiskByJobMetric(BaseModel):
    repository_full_name: str
    workflow_path: str
    workflow_name: str
    job_id: str
    job_name: str | None = None
    steps_count: int = 0
    uses_steps_count: int = 0
    run_steps_count: int = 0
    third_party_uses_steps_count: int = 0
    distinct_action_owners: int = 0
    distinct_trust_domains: int = 0
    has_multiple_third_party_actions_same_job: bool = False
    has_mixed_trust_domains: bool = False
    has_action_before_sensitive_run_step: bool = False
    has_untrusted_action_before_deploy_step: bool = False
    shared_workspace_exposure_signal: bool = False
    env_pollution_signal: bool = False
    output_dependency_signal: bool = False
    filesystem_dependency_signal: bool = False
    trust_domains: list[str] = Field(default_factory=list)
    action_owners: list[str] = Field(default_factory=list)
    action_references: list[str] = Field(default_factory=list)
    sensitive_steps: list[str] = Field(default_factory=list)
    signal_score: float = 0.0


class IsolationRiskSummaryMetric(BaseModel):
    total_jobs: int = 0
    jobs_with_multiple_actions: int = 0
    jobs_with_mixed_trust_domains: int = 0
    jobs_with_third_party_before_sensitive_step: int = 0
    jobs_with_env_pollution_signal: int = 0
    jobs_with_output_dependency_signal: int = 0
    jobs_with_filesystem_signal: int = 0
    median_distinct_action_owners_per_job: float | None = None
    p95_distinct_action_owners_per_job: float | None = None


class IsolationRiskExampleMetric(BaseModel):
    repository_full_name: str
    workflow_path: str
    workflow_name: str
    job_id: str
    job_name: str | None = None
    third_party_uses_steps_count: int = 0
    distinct_action_owners: int = 0
    distinct_trust_domains: int = 0
    has_action_before_sensitive_run_step: bool = False
    has_untrusted_action_before_deploy_step: bool = False
    shared_workspace_exposure_signal: bool = False
    env_pollution_signal: bool = False
    output_dependency_signal: bool = False
    filesystem_dependency_signal: bool = False
    action_references: list[str] = Field(default_factory=list)
    sensitive_steps: list[str] = Field(default_factory=list)
    trust_domains: list[str] = Field(default_factory=list)
    signal_score: float = 0.0


class PrivilegeRiskByJobMetric(BaseModel):
    repository_full_name: str
    workflow_path: str
    workflow_name: str
    job_id: str
    job_name: str | None = None
    trigger_events: list[str] = Field(default_factory=list)
    permission_keys: list[str] = Field(default_factory=list)
    contents_permission: str = "default"
    actions_permission: str = "default"
    checks_permission: str = "default"
    deployments_permission: str = "default"
    id_token_permission: str = "default"
    issues_permission: str = "default"
    packages_permission: str = "default"
    pull_requests_permission: str = "default"
    security_events_permission: str = "default"
    statuses_permission: str = "default"
    has_id_token_write: bool = False
    has_contents_write: bool = False
    has_actions_write: bool = False
    has_packages_write: bool = False
    has_deployments_write: bool = False
    has_security_events_write: bool = False
    has_write_all: bool = False
    has_read_all: bool = False
    has_pull_request_target: bool = False
    secrets_in_env: bool = False
    secrets_in_with: bool = False
    github_token_explicit: bool = False
    cloud_credential_keywords: bool = False
    third_party_action_with_privilege: bool = False
    mutable_third_party_action_with_privilege: bool = False
    privilege_coupled_mutability: bool = False
    isolation_privilege_coupling: bool = False
    has_any_high_privilege_signal: bool = False
    third_party_action_count: int = 0
    mutable_third_party_action_count: int = 0
    privilege_risk_score: float = 0.0


class PrivilegeRiskByWorkflowMetric(BaseModel):
    repository_full_name: str
    workflow_path: str
    workflow_name: str
    trigger_events: list[str] = Field(default_factory=list)
    max_depth: int = 0
    job_count: int = 0
    privileged_job_count: int = 0
    has_id_token_write: bool = False
    has_contents_write: bool = False
    has_actions_write: bool = False
    has_packages_write: bool = False
    has_deployments_write: bool = False
    has_security_events_write: bool = False
    has_write_all: bool = False
    has_read_all: bool = False
    has_pull_request_target: bool = False
    secrets_in_env: bool = False
    secrets_in_with: bool = False
    github_token_explicit: bool = False
    cloud_credential_keywords: bool = False
    third_party_action_with_privilege: bool = False
    mutable_third_party_action_with_privilege: bool = False
    privilege_coupled_mutability: bool = False
    isolation_privilege_coupling: bool = False
    privilege_risk_score: float = 0.0


class PrivilegeRiskSummaryMetric(BaseModel):
    total_workflows: int = 0
    total_jobs: int = 0
    workflows_with_id_token_write: int = 0
    workflows_with_write_all: int = 0
    workflows_with_pull_request_target: int = 0
    jobs_with_contents_write: int = 0
    jobs_with_actions_write: int = 0
    jobs_with_packages_write: int = 0
    jobs_with_deployments_write: int = 0
    jobs_with_security_events_write: int = 0
    jobs_with_secrets_in_env: int = 0
    jobs_with_secrets_in_with: int = 0
    jobs_with_github_token_explicit: int = 0
    jobs_with_cloud_credential_keywords: int = 0
    jobs_with_privilege_coupled_mutability: int = 0
    jobs_with_isolation_privilege_coupling: int = 0
    privileged_mutable_job_count: int = 0


class PrivilegeRiskExampleMetric(BaseModel):
    repository_full_name: str
    workflow_path: str
    workflow_name: str
    trigger_events: list[str] = Field(default_factory=list)
    max_depth: int = 0
    privileged_job_count: int = 0
    has_id_token_write: bool = False
    has_write_all: bool = False
    has_pull_request_target: bool = False
    secrets_in_env: bool = False
    secrets_in_with: bool = False
    github_token_explicit: bool = False
    cloud_credential_keywords: bool = False
    third_party_action_with_privilege: bool = False
    mutable_third_party_action_with_privilege: bool = False
    privilege_coupled_mutability: bool = False
    isolation_privilege_coupling: bool = False
    risky_job_ids: list[str] = Field(default_factory=list)
    privilege_risk_score: float = 0.0


class PropagationRiskByWorkflowMetric(BaseModel):
    repository_full_name: str
    workflow_path: str
    workflow_name: str
    trigger_events: list[str] = Field(default_factory=list)
    job_count: int = 0
    job_dependency_edges: int = 0
    max_job_depth: int = 0
    has_artifact_upload: bool = False
    has_artifact_download: bool = False
    has_cache_save_restore: bool = False
    has_job_outputs: bool = False
    has_needs_outputs: bool = False
    has_workflow_run_trigger: bool = False
    has_repository_dispatch: bool = False
    has_workflow_dispatch: bool = False
    has_workflow_call: bool = False
    has_reusable_workflow_call: bool = False
    has_workflow_file_write_signal: bool = False
    propagation_channel_count: int = 0
    privilege_propagation_coupling: bool = False
    mutable_to_downstream_propagation: bool = False
    propagation_risk_score: float = 0.0


class PropagationRiskSummaryMetric(BaseModel):
    total_workflows: int = 0
    workflows_with_artifact_upload: int = 0
    workflows_with_artifact_download: int = 0
    workflows_with_cache_save_restore: int = 0
    workflows_with_job_outputs: int = 0
    workflows_with_needs_outputs: int = 0
    workflows_with_workflow_run_trigger: int = 0
    workflows_with_repository_dispatch: int = 0
    workflows_with_workflow_dispatch: int = 0
    workflows_with_workflow_call: int = 0
    workflows_with_reusable_workflow_call: int = 0
    workflows_with_privilege_propagation_coupling: int = 0
    workflows_with_mutable_to_downstream_propagation: int = 0
    average_job_dependency_edges: float | None = None
    max_job_depth: int = 0


class PropagationRiskExampleMetric(BaseModel):
    repository_full_name: str
    workflow_path: str
    workflow_name: str
    trigger_events: list[str] = Field(default_factory=list)
    job_count: int = 0
    job_dependency_edges: int = 0
    max_job_depth: int = 0
    propagation_channel_count: int = 0
    privilege_propagation_coupling: bool = False
    mutable_to_downstream_propagation: bool = False
    has_artifact_upload: bool = False
    has_artifact_download: bool = False
    has_cache_save_restore: bool = False
    has_job_outputs: bool = False
    has_needs_outputs: bool = False
    has_workflow_run_trigger: bool = False
    has_repository_dispatch: bool = False
    has_workflow_dispatch: bool = False
    has_workflow_call: bool = False
    has_reusable_workflow_call: bool = False
    propagation_risk_score: float = 0.0


class AmplificationByNodeMetric(BaseModel):
    node_id: str
    node_kind: str
    owner: str | None = None
    repo: str | None = None
    full_name: str | None = None
    workflow_name: str | None = None
    in_degree: int = 0
    out_degree: int = 0
    transitive_fanout: int = 0
    reachable_workflow_count: int = 0
    reachable_repository_count: int = 0
    reachable_high_star_repository_count: int = 0
    max_downstream_depth: int = 0
    average_downstream_depth: float = 0.0
    betweenness_like_score: float = 0.0
    cascade_radius: int = 0
    cascade_concentration_score: float = 0.0


class AmplificationSummaryMetric(BaseModel):
    total_action_nodes: int = 0
    total_nodes: int = 0
    top_1_action_coverage: float = 0.0
    top_10_action_coverage: float = 0.0
    top_100_action_coverage: float = 0.0
    gini_coefficient_of_action_usage: float = 0.0
    median_fanout: float | None = None
    p95_fanout: float | None = None
    max_fanout: int = 0


class TrustAmplificationByEntityMetric(BaseModel):
    entity_name: str
    entity_type: Literal["owner", "marketplace_publisher", "verified_creator", "github_owned", "third_party_owner"]
    action_count: int = 0
    total_usage_count: int = 0
    downstream_repo_count: int = 0
    downstream_workflow_count: int = 0
    high_star_downstream_repo_count: int = 0
    mutable_ref_usage_count: int = 0
    mutable_ref_ratio: float = 0.0
    privileged_workflow_count: int = 0
    id_token_write_workflow_count: int = 0
    blast_radius_sum: float = 0.0
    blast_radius_max: float = 0.0
    trust_amplification_score: float = 0.0


class TrustAmplificationSummaryMetric(BaseModel):
    total_entities: int = 0
    total_owner_entities: int = 0
    top_1_owner_coverage: float = 0.0
    top_5_owner_coverage: float = 0.0
    top_10_owner_coverage: float = 0.0
    gini_coefficient_over_owner_usage: float = 0.0
    hhi_over_owner_usage: float = 0.0


class ReusableWorkflowEdgeMetric(BaseModel):
    caller_repository: str
    caller_workflow_path: str
    caller_job: str
    callee_owner: str | None = None
    callee_repo: str | None = None
    callee_workflow_path: str
    callee_ref: str | None = None
    ref_type: str = "LOCAL_PATH"
    is_remote: bool = False
    is_mutable_ref: bool = False
    is_cross_org: bool = False
    is_third_party: bool = False
    has_secrets_inherit: bool = False
    has_permissions: bool = False
    has_id_token_write: bool = False
    downstream_repo_count: int = 0


class ReusableWorkflowSummaryMetric(BaseModel):
    total_edges: int = 0
    remote_edge_count: int = 0
    local_edge_count: int = 0
    mutable_ref_edge_count: int = 0
    cross_org_edge_count: int = 0
    third_party_edge_count: int = 0
    secrets_inherit_edge_count: int = 0
    permissions_edge_count: int = 0
    id_token_write_edge_count: int = 0
    unique_callee_count: int = 0
    unique_remote_callee_count: int = 0


class ReusableWorkflowTopCalleeMetric(BaseModel):
    callee_identifier: str
    is_remote: bool = False
    call_count: int = 0
    downstream_repo_count: int = 0
    mutable_edge_count: int = 0
    secrets_inherit_count: int = 0
    permissions_count: int = 0
    id_token_write_count: int = 0
    cross_org_count: int = 0
    third_party_count: int = 0


class RefTypeComparisonMetric(BaseModel):
    ref_category: str
    action_count: int = 0
    workflow_count: int = 0
    total_usage_count: int = 0
    average_usage_count: float | None = None
    average_downstream_repo_count: float | None = None
    observed_drift_action_count: int = 0
    observed_drift_action_ratio: float = 0.0
    privileged_workflow_count: int = 0
    privilege_coupled_workflow_count: int = 0
    propagation_coupled_workflow_count: int = 0


class CrossOwnerRiskComparisonMetric(BaseModel):
    ownership_scope: Literal["same_owner", "cross_owner"]
    workflow_count: int = 0
    average_max_depth: float | None = None
    average_unique_action_owner_count: float | None = None
    average_mutable_ref_ratio: float | None = None
    average_high_risk_ref_ratio: float | None = None
    workflows_with_observed_drift: int = 0
    workflows_with_id_token_write: int = 0
    workflows_with_privilege_coupled_mutability: int = 0
    workflows_with_privilege_propagation_coupling: int = 0
    workflows_with_multi_owner_cascade: int = 0
    average_propagation_channel_count: float | None = None
    average_privilege_risk_score: float | None = None


class ReusableWorkflowRiskProfileMetric(BaseModel):
    profile_name: str
    edge_count: int = 0
    mutable_edge_count: int = 0
    mutable_edge_ratio: float = 0.0
    secrets_inherit_count: int = 0
    secrets_inherit_ratio: float = 0.0
    permissions_count: int = 0
    permissions_ratio: float = 0.0
    id_token_write_count: int = 0
    id_token_write_ratio: float = 0.0
    average_downstream_repo_count: float | None = None


class PrivilegedBlastRadiusByActionMetric(BaseModel):
    action_id: str
    owner: str
    repo: str
    full_name: str
    ref_name: str | None = None
    ref_category: str = "UNKNOWN_REF"
    downstream_repository_count: int = 0
    downstream_high_star_repository_count: int = 0
    downstream_high_star_coverage: int = 0
    privileged_downstream_workflow_count: int = 0
    privileged_downstream_repository_count: int = 0
    id_token_downstream_workflow_count: int = 0
    id_token_downstream_repository_count: int = 0
    mutable_privileged_workflow_count: int = 0
    privilege_coupled_repository_count: int = 0
    privileged_blast_radius_score: float = 0.0


class PrivilegedBlastRadiusSummaryMetric(BaseModel):
    total_actions: int = 0
    actions_with_privileged_downstream: int = 0
    actions_with_id_token_downstream: int = 0
    actions_with_mutable_privileged_downstream: int = 0
    top_1_privileged_action_coverage: float = 0.0
    top_10_privileged_action_coverage: float = 0.0
    top_100_privileged_action_coverage: float = 0.0
    total_privileged_downstream_repositories: int = 0
    total_id_token_downstream_repositories: int = 0


class ComponentTypeComparisonMetric(BaseModel):
    component_type: Literal["javascript", "docker", "composite", "reusable_workflow", "unknown"]
    action_count: int = 0
    total_usage_count: int = 0
    average_usage_count: float | None = None
    average_downstream_repo_count: float | None = None
    average_transitive_fanout: float | None = None
    average_max_downstream_depth: float | None = None
    mutable_ref_ratio_weighted: float = 0.0
    privileged_downstream_repository_count: int = 0
    id_token_downstream_repository_count: int = 0
    mutable_privileged_workflow_count: int = 0
    average_privileged_blast_radius_score: float | None = None


class ExposureWindowSummaryMetric(BaseModel):
    exposure_count: int = 0
    affected_action_count: int = 0
    affected_repository_count: int = 0
    average_lag_hours: float | None = None
    min_lag_hours: float | None = None
    max_lag_hours: float | None = None


class UpdateWindowSummaryMetric(BaseModel):
    adoption_mode: Literal["explicit", "implicit"]
    depth_bucket: Literal["level_1", "level_2", "level_3_plus"]
    window_count: int = 0
    average_lag_hours: float | None = None
    median_lag_hours: float | None = None
    p95_lag_hours: float | None = None
    max_lag_hours: float | None = None


class TimeWindowAmplificationMetric(BaseModel):
    depth_bucket: Literal["level_1", "level_2", "level_3_plus"]
    explicit_window_count: int = 0
    implicit_window_count: int = 0
    explicit_average_lag_hours: float | None = None
    implicit_average_lag_hours: float | None = None
    explicit_median_lag_hours: float | None = None
    implicit_median_lag_hours: float | None = None


class CascadeDepthMetric(BaseModel):
    workflow_name: str
    repository_full_name: str
    workflow_path: str
    max_depth: int = 0
    layer_1_count: int = 0
    layer_2_count: int = 0
    layer_3_plus_count: int = 0
    sha_binding_rate: float = 0.0
    tag_binding_rate: float = 0.0
    branch_binding_rate: float = 0.0
    main_binding_rate: float = 0.0
    has_token_access: bool = False
    binding_downgrade_count: int = 0
    high_risk_path_count: int = 0
    layer_distribution: dict[str, int] = Field(default_factory=dict)


class BootstrapIndicatorMetric(BaseModel):
    indicator_name: str
    population_kind: Literal["workflow", "action", "owner", "job"] = "workflow"
    sample_count: int = 0
    point_estimate: float = 0.0
    ci_lower: float | None = None
    ci_upper: float | None = None
    bootstrap_iterations: int = 0
    notes: str | None = None


class CrossOwnerEffectMetric(BaseModel):
    metric_name: str
    same_owner_count: int = 0
    cross_owner_count: int = 0
    same_owner_mean: float | None = None
    cross_owner_mean: float | None = None
    difference_cross_minus_same: float | None = None
    ci_lower: float | None = None
    ci_upper: float | None = None
    bootstrap_iterations: int = 0


class ManualValidationCandidateMetric(BaseModel):
    rq_label: Literal["RQ3", "RQ4"]
    candidate_kind: str
    repository_full_name: str
    workflow_path: str
    workflow_name: str | None = None
    job_id: str | None = None
    score: float = 0.0
    reasons: list[str] = Field(default_factory=list)
    key_signals: dict[str, object] = Field(default_factory=dict)


class AnalysisReport(BaseModel):
    generated_at: datetime
    workflow_metrics: list[WorkflowImplicitDependencyMetric] = Field(default_factory=list)
    drift_distribution: list[DriftDistributionMetric] = Field(default_factory=list)
    blast_radius: list[BlastRadiusMetric] = Field(default_factory=list)
    exposure_windows: list[ExposureWindowMetric] = Field(default_factory=list)
    update_windows: list[UpdateWindowMetric] = Field(default_factory=list)
    drift_observation_coverage: DriftObservationCoverageMetric = Field(default_factory=DriftObservationCoverageMetric)
    repository_transfer_risks: list[RepositoryTransferRiskMetric] = Field(default_factory=list)
    repository_transfer_summary: RepositoryTransferRiskSummaryMetric = Field(default_factory=RepositoryTransferRiskSummaryMetric)
    trust_domain_boundaries: list[TrustDomainBoundaryMetric] = Field(default_factory=list)
    trust_domain_boundary_summary: TrustDomainBoundarySummaryMetric = Field(default_factory=TrustDomainBoundarySummaryMetric)
    discovery_risk_candidates: list[DiscoveryRiskCandidateMetric] = Field(default_factory=list)
    discovery_risk_summary: DiscoveryRiskSummaryMetric = Field(default_factory=DiscoveryRiskSummaryMetric)
    amplification_by_node: list[AmplificationByNodeMetric] = Field(default_factory=list)
    amplification_summary: AmplificationSummaryMetric = Field(default_factory=AmplificationSummaryMetric)
    ref_risk_by_workflow: list[RefRiskByWorkflowMetric] = Field(default_factory=list)
    ref_risk_summary: RefRiskSummaryMetric = Field(default_factory=RefRiskSummaryMetric)
    ref_risk_by_depth: list[RefRiskByDepthMetric] = Field(default_factory=list)
    ref_risk_by_action: list[RefRiskByActionMetric] = Field(default_factory=list)
    isolation_risk_by_job: list[IsolationRiskByJobMetric] = Field(default_factory=list)
    isolation_risk_summary: IsolationRiskSummaryMetric = Field(default_factory=IsolationRiskSummaryMetric)
    isolation_risk_examples: list[IsolationRiskExampleMetric] = Field(default_factory=list)
    privilege_risk_by_workflow: list[PrivilegeRiskByWorkflowMetric] = Field(default_factory=list)
    privilege_risk_by_job: list[PrivilegeRiskByJobMetric] = Field(default_factory=list)
    privilege_risk_summary: PrivilegeRiskSummaryMetric = Field(default_factory=PrivilegeRiskSummaryMetric)
    privilege_risk_examples: list[PrivilegeRiskExampleMetric] = Field(default_factory=list)
    propagation_risk_by_workflow: list[PropagationRiskByWorkflowMetric] = Field(default_factory=list)
    propagation_risk_summary: PropagationRiskSummaryMetric = Field(default_factory=PropagationRiskSummaryMetric)
    propagation_risk_examples: list[PropagationRiskExampleMetric] = Field(default_factory=list)
    trust_amplification_by_entity: list[TrustAmplificationByEntityMetric] = Field(default_factory=list)
    trust_amplification_summary: TrustAmplificationSummaryMetric = Field(default_factory=TrustAmplificationSummaryMetric)
    reusable_workflow_edges: list[ReusableWorkflowEdgeMetric] = Field(default_factory=list)
    reusable_workflow_summary: ReusableWorkflowSummaryMetric = Field(default_factory=ReusableWorkflowSummaryMetric)
    reusable_workflow_top_callees: list[ReusableWorkflowTopCalleeMetric] = Field(default_factory=list)
    ref_type_comparison: list[RefTypeComparisonMetric] = Field(default_factory=list)
    cross_owner_comparison: list[CrossOwnerRiskComparisonMetric] = Field(default_factory=list)
    reusable_workflow_risk_profile: list[ReusableWorkflowRiskProfileMetric] = Field(default_factory=list)
    privileged_blast_radius_by_action: list[PrivilegedBlastRadiusByActionMetric] = Field(default_factory=list)
    privileged_blast_radius_summary: PrivilegedBlastRadiusSummaryMetric = Field(default_factory=PrivilegedBlastRadiusSummaryMetric)
    component_type_comparison: list[ComponentTypeComparisonMetric] = Field(default_factory=list)
    exposure_window_summary: ExposureWindowSummaryMetric = Field(default_factory=ExposureWindowSummaryMetric)
    update_window_summary: list[UpdateWindowSummaryMetric] = Field(default_factory=list)
    time_window_amplification: list[TimeWindowAmplificationMetric] = Field(default_factory=list)
    cascade_depth_reports: list[CascadeDepthMetric] = Field(default_factory=list)
    bootstrap_indicators: list[BootstrapIndicatorMetric] = Field(default_factory=list)
    cross_owner_effects: list[CrossOwnerEffectMetric] = Field(default_factory=list)
    manual_validation_candidates: list[ManualValidationCandidateMetric] = Field(default_factory=list)
