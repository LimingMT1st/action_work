from __future__ import annotations

from collections import defaultdict, deque
from statistics import mean

from gha_cascade_analyzer.analyzers.graph_types import CascadeGraph
from gha_cascade_analyzer.enums import ActionType, RefType, VerificationStatus
from gha_cascade_analyzer.models import (
    ActionNode,
    BlastRadiusMetric,
    CascadeDepthMetric,
    DriftObservationCoverageMetric,
    DriftDistributionMetric,
    DriftEvent,
    ExposureWindowMetric,
    ExposureWindowSummaryMetric,
    RefObservation,
    RepositoryIdentityObservation,
    RepositoryTransferRiskMetric,
    RepositoryTransferRiskSummaryMetric,
    TimeWindowAmplificationMetric,
    TrustDomainBoundaryMetric,
    TrustDomainBoundarySummaryMetric,
    UpdateWindowMetric,
    UpdateWindowSummaryMetric,
    WorkflowImplicitDependencyMetric,
    WorkflowUseChange,
)
from gha_cascade_analyzer.utils.parsing import parse_action_reference, stable_id


class RQMetricsEngine:
    DEPTH_BUCKETS = ("level_1", "level_2", "level_3_plus")

    def merge_drift_events(
        self,
        observations: list[RefObservation],
        drift_events: list[DriftEvent],
    ) -> list[DriftEvent]:
        merged: dict[str, DriftEvent] = {event.drift_id: event for event in drift_events}
        observations_by_ref: dict[tuple[str, str, RefType], list[RefObservation]] = defaultdict(list)
        for observation in observations:
            observations_by_ref[(observation.action_id, observation.ref_name, observation.ref_type)].append(observation)

        for (action_id, ref_name, ref_type), ref_observations in observations_by_ref.items():
            ordered = sorted(ref_observations, key=lambda item: item.observed_at)
            for previous, current in zip(ordered, ordered[1:], strict=False):
                if previous.sha == current.sha:
                    continue
                drift_event = DriftEvent(
                    drift_id=stable_id(action_id, ref_type.value, ref_name, previous.sha, current.sha, current.observed_at.isoformat()),
                    action_id=action_id,
                    tag_name=ref_name,
                    ref_type=ref_type,
                    previous_sha=previous.sha,
                    new_sha=current.sha,
                    detected_at=current.observed_at,
                    first_seen_at=previous.observed_at,
                    last_seen_at=current.observed_at,
                    source="tag_move" if ref_type == RefType.TAG else "branch_head_change",
                    notes=f"Reconstructed from observation history for {ref_name}",
                )
                merged.setdefault(drift_event.drift_id, drift_event)
        return sorted(merged.values(), key=lambda item: (item.detected_at, item.action_id, item.tag_name))

    def compute_implicit_dependency_ratio(self, graph: CascadeGraph) -> list[WorkflowImplicitDependencyMetric]:
        metrics: list[WorkflowImplicitDependencyMetric] = []
        direct_by_workflow: dict[str, set[str]] = defaultdict(set)
        transitive_by_workflow: dict[str, set[str]] = defaultdict(set)

        for edge in graph.edges:
            if edge.src_kind == "workflow" and edge.dst_kind == "action":
                direct_by_workflow[edge.src_node_id].add(edge.dst_node_id)
            if edge.edge_type == "transitive" and edge.consumer_repository and edge.workflow_path:
                workflow_node_id = f"workflow::{edge.consumer_repository}::{edge.workflow_path}"
                transitive_by_workflow[workflow_node_id].add(edge.dst_node_id)

        for workflow_node_id in sorted(graph.workflow_nodes):
            _, repository_full_name, workflow_path = workflow_node_id.split("::", 2)
            direct_actions = direct_by_workflow.get(workflow_node_id, set())
            transitive_actions = transitive_by_workflow.get(workflow_node_id, set()) - direct_actions
            total = len(direct_actions | transitive_actions)
            ratio = len(transitive_actions) / total if total else 0.0
            metrics.append(
                WorkflowImplicitDependencyMetric(
                    repository_full_name=repository_full_name,
                    workflow_path=workflow_path,
                    direct_actions=len(direct_actions),
                    transitive_actions=len(transitive_actions),
                    total_actions=total,
                    implicit_dependency_ratio=ratio,
                )
            )
        return metrics

    def compute_drift_distribution(self, actions: dict[str, ActionNode], drift_events: list[DriftEvent]) -> list[DriftDistributionMetric]:
        grouped_events: dict[tuple[ActionType, VerificationStatus, RefType, str], list[DriftEvent]] = defaultdict(list)
        for event in drift_events:
            action = actions.get(event.action_id)
            action_type = action.action_type if action else ActionType.UNKNOWN
            author_verified = action.author_verified if action else VerificationStatus.UNKNOWN
            grouped_events[(action_type, author_verified, event.ref_type, event.source)].append(event)
        return [
            DriftDistributionMetric(
                action_type=action_type,
                author_verified=author_verified,
                ref_type=ref_type,
                source=source,
                drift_event_count=len(events),
                unique_action_count=len({event.action_id for event in events}),
                unique_ref_count=len({(event.action_id, event.tag_name, event.ref_type) for event in events}),
            )
            for (action_type, author_verified, ref_type, source), events in sorted(
                grouped_events.items(),
                key=lambda item: (item[0][0].value, item[0][1].value, item[0][2].value, item[0][3]),
            )
        ]

    def compute_blast_radius(self, graph: CascadeGraph) -> list[BlastRadiusMetric]:
        metrics: list[BlastRadiusMetric] = []
        for action_id, action in sorted(graph.actions.items()):
            repositories = self._collect_downstream_repositories(graph, action_id)
            high_star_repositories = [repo for repo in repositories if (graph.repositories.get(repo).stars if graph.repositories.get(repo) else 0) > 50]
            coverage = sum(graph.repositories[repo].stars for repo in high_star_repositories if repo in graph.repositories)
            metrics.append(
                BlastRadiusMetric(
                    action_id=action_id,
                    owner=action.owner,
                    repo=action.repo,
                    downstream_repository_count=len(repositories),
                    downstream_high_star_repository_count=len(high_star_repositories),
                    downstream_high_star_coverage=coverage,
                    influenced_repositories=sorted(repositories),
                )
            )
        metrics.sort(key=lambda item: (item.downstream_high_star_repository_count, item.downstream_high_star_coverage), reverse=True)
        return metrics

    def compute_exposure_windows(self, workflow_changes: list[WorkflowUseChange], drift_events: list[DriftEvent]) -> list[ExposureWindowMetric]:
        workflow_changes = sorted(workflow_changes, key=lambda item: item.committed_at)
        changes_by_repo_and_action: dict[tuple[str, str, str | None, str, str], list[WorkflowUseChange]] = defaultdict(list)
        for change in workflow_changes:
            refs = set(change.uses_before) | set(change.uses_after)
            for uses_value in refs:
                owner, repo, subpath, ref = parse_action_reference(uses_value)
                action_id = stable_id(owner, repo, subpath or "", ref)
                changes_by_repo_and_action[(change.repository_full_name, action_id, change.workflow_path, owner, repo)].append(change)

        metrics: list[ExposureWindowMetric] = []
        for event in drift_events:
            for (repository_full_name, action_id, workflow_path, owner, repo), changes in changes_by_repo_and_action.items():
                if action_id != event.action_id:
                    continue
                update = self._find_first_change_after(event.detected_at, changes)
                if update is None:
                    continue
                lag_hours = (update.committed_at - event.detected_at).total_seconds() / 3600
                metrics.append(
                    ExposureWindowMetric(
                        action_id=event.action_id,
                        owner=owner,
                        repo=repo,
                        patch_commit_sha=event.new_sha,
                        downstream_repository=repository_full_name,
                        workflow_path=workflow_path,
                        patch_detected_at=event.detected_at,
                        updated_at=update.committed_at,
                        lag_hours=lag_hours,
                    )
                )
        return metrics

    def compute_average_exposure_window_hours(self, exposure_windows: list[ExposureWindowMetric]) -> float | None:
        if not exposure_windows:
            return None
        return mean(item.lag_hours for item in exposure_windows)

    def compute_exposure_window_summary(self, exposure_windows: list[ExposureWindowMetric]) -> ExposureWindowSummaryMetric:
        if not exposure_windows:
            return ExposureWindowSummaryMetric()
        lag_hours = [item.lag_hours for item in exposure_windows]
        return ExposureWindowSummaryMetric(
            exposure_count=len(exposure_windows),
            affected_action_count=len({item.action_id for item in exposure_windows}),
            affected_repository_count=len({item.downstream_repository for item in exposure_windows}),
            average_lag_hours=mean(lag_hours),
            min_lag_hours=min(lag_hours),
            max_lag_hours=max(lag_hours),
        )

    def compute_update_windows(
        self,
        graph: CascadeGraph,
        workflow_changes: list[WorkflowUseChange],
        drift_events: list[DriftEvent],
    ) -> list[UpdateWindowMetric]:
        depth_index = self._workflow_action_depth_index(graph)
        changes_by_workflow = self._group_workflow_changes(workflow_changes)
        impacted_workflows = self._collect_impacted_workflows(graph)

        metrics: list[UpdateWindowMetric] = []
        for event in drift_events:
            action = graph.actions.get(event.action_id)
            if action is None:
                continue
            base_key = (action.owner.lower(), action.repo.lower(), (action.subpath or "").lower())

            explicit_metrics = self._build_explicit_windows_for_event(
                event=event,
                base_key=base_key,
                changes_by_workflow=changes_by_workflow,
                depth_index=depth_index,
            )
            metrics.extend(explicit_metrics)

            explicit_workflows = {
                (item.repository_full_name, item.workflow_path)
                for item in explicit_metrics
            }
            for workflow_node_id, depth in impacted_workflows.get(event.action_id, {}).items():
                _, repository_full_name, workflow_path = workflow_node_id.split("::", 2)
                if (repository_full_name, workflow_path) in explicit_workflows:
                    continue
                metrics.append(
                    UpdateWindowMetric(
                        event_id=event.drift_id,
                        action_id=event.action_id,
                        owner=action.owner,
                        repo=action.repo,
                        ref_name=event.tag_name,
                        ref_type=event.ref_type,
                        repository_full_name=repository_full_name,
                        workflow_path=workflow_path,
                        adoption_mode="implicit",
                        dependency_depth=depth,
                        depth_bucket=self._depth_bucket(depth),
                        upstream_changed_at=event.detected_at,
                        adopted_at=event.detected_at,
                        lag_hours=0.0,
                        prior_ref=event.tag_name,
                        adopted_ref=event.tag_name,
                        evidence="mutable_ref_repoint_on_resolved_dependency",
                    )
                )
        metrics.sort(
            key=lambda item: (
                item.upstream_changed_at,
                item.repository_full_name,
                item.workflow_path,
                item.adoption_mode,
                item.action_id,
            )
        )
        return metrics

    def compute_update_window_summary(self, update_windows: list[UpdateWindowMetric]) -> list[UpdateWindowSummaryMetric]:
        grouped: dict[tuple[str, str], list[UpdateWindowMetric]] = defaultdict(list)
        for item in update_windows:
            grouped[(item.adoption_mode, item.depth_bucket)].append(item)

        summaries: list[UpdateWindowSummaryMetric] = []
        for depth_bucket in self.DEPTH_BUCKETS:
            for adoption_mode in ("explicit", "implicit"):
                items = grouped.get((adoption_mode, depth_bucket), [])
                lags = sorted(item.lag_hours for item in items)
                summaries.append(
                    UpdateWindowSummaryMetric(
                        adoption_mode=adoption_mode,
                        depth_bucket=depth_bucket,  # type: ignore[arg-type]
                        window_count=len(items),
                        average_lag_hours=mean(lags) if lags else None,
                        median_lag_hours=self._percentile(lags, 0.5),
                        p95_lag_hours=self._percentile(lags, 0.95),
                        max_lag_hours=max(lags) if lags else None,
                    )
                )
        return summaries

    def compute_time_window_amplification(self, summaries: list[UpdateWindowSummaryMetric]) -> list[TimeWindowAmplificationMetric]:
        index = {(item.adoption_mode, item.depth_bucket): item for item in summaries}
        metrics: list[TimeWindowAmplificationMetric] = []
        for depth_bucket in self.DEPTH_BUCKETS:
            explicit = index.get(("explicit", depth_bucket))
            implicit = index.get(("implicit", depth_bucket))
            metrics.append(
                TimeWindowAmplificationMetric(
                    depth_bucket=depth_bucket,  # type: ignore[arg-type]
                    explicit_window_count=explicit.window_count if explicit else 0,
                    implicit_window_count=implicit.window_count if implicit else 0,
                    explicit_average_lag_hours=explicit.average_lag_hours if explicit else None,
                    implicit_average_lag_hours=implicit.average_lag_hours if implicit else None,
                    explicit_median_lag_hours=explicit.median_lag_hours if explicit else None,
                    implicit_median_lag_hours=implicit.median_lag_hours if implicit else None,
                )
            )
        return metrics

    def compute_drift_observation_coverage(
        self,
        observations: list[RefObservation],
        drift_events: list[DriftEvent],
    ) -> DriftObservationCoverageMetric:
        if not observations:
            return DriftObservationCoverageMetric(drift_event_count=len(drift_events))
        ordered = sorted(observations, key=lambda item: item.observed_at)
        return DriftObservationCoverageMetric(
            observed_action_count=len({item.action_id for item in observations}),
            observed_repository_count=len({(item.owner, item.repo) for item in observations}),
            observed_ref_count=len({(item.action_id, item.ref_name, item.ref_type) for item in observations}),
            observed_tag_count=len({(item.action_id, item.ref_name) for item in observations if item.ref_type == RefType.TAG}),
            observed_branch_count=len({(item.action_id, item.ref_name) for item in observations if item.ref_type == RefType.BRANCH}),
            observation_count=len(observations),
            observation_span_hours=(ordered[-1].observed_at - ordered[0].observed_at).total_seconds() / 3600 if len(ordered) > 1 else 0.0,
            drift_event_count=len(drift_events),
            drifted_action_count=len({item.action_id for item in drift_events}),
            drifted_ref_count=len({(item.action_id, item.tag_name, item.ref_type) for item in drift_events}),
        )

    def compute_repository_transfer_risks(
        self,
        graph: CascadeGraph,
        identity_observations: list[RepositoryIdentityObservation],
    ) -> list[RepositoryTransferRiskMetric]:
        observations_by_repo: dict[str, list[RepositoryIdentityObservation]] = defaultdict(list)
        for observation in identity_observations:
            observations_by_repo[observation.referenced_full_name.lower()].append(observation)

        actions_by_repo: dict[str, list[ActionNode]] = defaultdict(list)
        for action in graph.actions.values():
            actions_by_repo[f"{action.owner}/{action.repo}".lower()].append(action)

        risks: list[RepositoryTransferRiskMetric] = []
        for referenced_full_name, observations in observations_by_repo.items():
            ordered = sorted(observations, key=lambda item: item.observed_at)
            latest = ordered[-1]
            action_nodes = actions_by_repo.get(referenced_full_name, [])
            repo_ids = {item.repository_id for item in ordered if item.repository_id is not None}
            risk_types: list[str] = []

            if latest.identity_status == "redirected":
                risk_types.append("redirected")
            if latest.identity_status == "missing":
                risk_types.append("missing")
            if len(repo_ids) > 1:
                risk_types.append("repository_id_changed")

            if not risk_types:
                continue

            impacted_repositories, impacted_workflows, privileged_workflows = self._collect_action_group_impact(graph, action_nodes)
            sha_reference_count = sum(1 for action in action_nodes if action.ref_type == RefType.SHA)
            tag_reference_count = sum(1 for action in action_nodes if action.ref_type == RefType.TAG)
            branch_reference_count = sum(1 for action in action_nodes if action.ref_type == RefType.BRANCH)
            main_reference_count = sum(1 for action in action_nodes if action.ref_type == RefType.BRANCH and action.ref.lower() == "main")

            for risk_type in risk_types:
                risks.append(
                    RepositoryTransferRiskMetric(
                        referenced_full_name=latest.referenced_full_name,
                        resolved_full_name=latest.resolved_full_name,
                        latest_repository_id=latest.repository_id,
                        risk_type=risk_type,  # type: ignore[arg-type]
                        latest_identity_status=latest.identity_status,
                        observation_count=len(ordered),
                        first_observed_at=ordered[0].observed_at,
                        last_observed_at=latest.observed_at,
                        affected_action_count=len(action_nodes),
                        affected_repository_count=len(impacted_repositories),
                        affected_workflow_count=len(impacted_workflows),
                        privileged_workflow_count=len(privileged_workflows),
                        sha_reference_count=sha_reference_count,
                        tag_reference_count=tag_reference_count,
                        branch_reference_count=branch_reference_count,
                        main_reference_count=main_reference_count,
                    )
                )

        risks.sort(key=lambda item: (item.risk_type, item.privileged_workflow_count, item.affected_workflow_count), reverse=True)
        return risks

    def compute_repository_transfer_summary(
        self,
        graph: CascadeGraph,
        identity_observations: list[RepositoryIdentityObservation],
        risks: list[RepositoryTransferRiskMetric],
    ) -> RepositoryTransferRiskSummaryMetric:
        observed_repositories = {item.referenced_full_name.lower() for item in identity_observations}
        risky_repositories = {item.referenced_full_name.lower() for item in risks}
        risk_types_by_repo: dict[str, set[str]] = defaultdict(set)
        for item in risks:
            risk_types_by_repo[item.referenced_full_name.lower()].add(item.risk_type)

        risky_actions = [
            action
            for action in graph.actions.values()
            if f"{action.owner}/{action.repo}".lower() in risky_repositories
        ]
        impacted_repositories, impacted_workflows, privileged_workflows = self._collect_action_group_impact(graph, risky_actions)

        return RepositoryTransferRiskSummaryMetric(
            observed_action_repository_count=len(observed_repositories),
            risky_action_repository_count=len(risky_repositories),
            redirected_repository_count=sum(1 for item in risk_types_by_repo.values() if "redirected" in item),
            missing_repository_count=sum(1 for item in risk_types_by_repo.values() if "missing" in item),
            repository_id_changed_count=sum(1 for item in risk_types_by_repo.values() if "repository_id_changed" in item),
            affected_action_count=len(risky_actions),
            affected_repository_count=len(impacted_repositories),
            affected_workflow_count=len(impacted_workflows),
            privileged_workflow_count=len(privileged_workflows),
        )

    def compute_trust_domain_boundaries(self, graph: CascadeGraph) -> list[TrustDomainBoundaryMetric]:
        reports: list[TrustDomainBoundaryMetric] = []
        edges_by_workflow: dict[str, list] = defaultdict(list)
        for edge in graph.edges:
            if edge.consumer_repository and edge.workflow_path:
                workflow_node_id = f"workflow::{edge.consumer_repository}::{edge.workflow_path}"
                edges_by_workflow[workflow_node_id].append(edge)

        for workflow_node_id in sorted(graph.workflow_nodes):
            _, repository_full_name, workflow_path = workflow_node_id.split("::", 2)
            workflow_owner = repository_full_name.split("/", 1)[0].lower()
            workflow_edges = edges_by_workflow.get(workflow_node_id, [])
            action_owners: set[str] = set()
            external_owners: set[str] = set()
            direct_cross_owner_edge_count = 0
            transitive_cross_owner_edge_count = 0
            same_owner_edge_count = 0
            privileged_cross_owner_path_count = 0
            max_depth = 0

            for edge in workflow_edges:
                action = graph.actions.get(edge.dst_node_id)
                if action is None:
                    continue
                dst_owner = action.owner.lower()
                action_owners.add(dst_owner)
                if dst_owner != workflow_owner:
                    external_owners.add(dst_owner)
                max_depth = max(max_depth, edge.depth)

                if edge.src_kind == "workflow":
                    src_owner = workflow_owner
                else:
                    src_action = graph.actions.get(edge.src_node_id)
                    src_owner = src_action.owner.lower() if src_action is not None else workflow_owner

                if src_owner == dst_owner:
                    same_owner_edge_count += 1
                else:
                    if edge.edge_type == "direct":
                        direct_cross_owner_edge_count += 1
                    else:
                        transitive_cross_owner_edge_count += 1
                    if (
                        graph.workflow_has_write_permissions.get(workflow_node_id, False)
                        and action.has_token_access
                    ):
                        privileged_cross_owner_path_count += 1

            total_cross_owner_edge_count = direct_cross_owner_edge_count + transitive_cross_owner_edge_count
            reports.append(
                TrustDomainBoundaryMetric(
                    workflow_name=graph.workflow_names.get(workflow_node_id, workflow_path),
                    repository_full_name=repository_full_name,
                    workflow_path=workflow_path,
                    max_depth=max_depth,
                    unique_action_owner_count=len(action_owners),
                    unique_external_owner_count=len(external_owners),
                    direct_cross_owner_edge_count=direct_cross_owner_edge_count,
                    transitive_cross_owner_edge_count=transitive_cross_owner_edge_count,
                    total_cross_owner_edge_count=total_cross_owner_edge_count,
                    same_owner_edge_count=same_owner_edge_count,
                    privileged_cross_owner_path_count=privileged_cross_owner_path_count,
                    has_external_owner_dependency=direct_cross_owner_edge_count > 0,
                    has_transitive_cross_owner_dependency=transitive_cross_owner_edge_count > 0,
                    has_multi_owner_cascade=len(action_owners) >= 2 and total_cross_owner_edge_count > 0,
                )
            )
        return reports

    def compute_trust_domain_boundary_summary(
        self,
        reports: list[TrustDomainBoundaryMetric],
    ) -> TrustDomainBoundarySummaryMetric:
        if not reports:
            return TrustDomainBoundarySummaryMetric()
        unique_action_owner_counts = [item.unique_action_owner_count for item in reports]
        unique_external_owner_counts = [item.unique_external_owner_count for item in reports]
        return TrustDomainBoundarySummaryMetric(
            workflow_count=len(reports),
            workflows_with_external_owner_dependency=sum(1 for item in reports if item.has_external_owner_dependency),
            workflows_with_transitive_cross_owner_dependency=sum(1 for item in reports if item.has_transitive_cross_owner_dependency),
            workflows_with_multi_owner_cascade=sum(1 for item in reports if item.has_multi_owner_cascade),
            workflows_with_privileged_cross_owner_path=sum(1 for item in reports if item.privileged_cross_owner_path_count > 0),
            average_unique_action_owner_count=mean(unique_action_owner_counts),
            average_unique_external_owner_count=mean(unique_external_owner_counts),
            max_unique_action_owner_count=max(unique_action_owner_counts, default=0),
            max_unique_external_owner_count=max(unique_external_owner_counts, default=0),
            total_cross_owner_edge_count=sum(item.total_cross_owner_edge_count for item in reports),
            direct_cross_owner_edge_count=sum(item.direct_cross_owner_edge_count for item in reports),
            transitive_cross_owner_edge_count=sum(item.transitive_cross_owner_edge_count for item in reports),
        )

    def build_drift_event_rows(self, actions: dict[str, ActionNode], drift_events: list[DriftEvent]) -> list[dict]:
        rows: list[dict] = []
        for event in sorted(drift_events, key=lambda item: (item.detected_at, item.action_id, item.tag_name)):
            action = actions.get(event.action_id)
            rows.append(
                {
                    "action_id": event.action_id,
                    "owner": action.owner if action else "",
                    "repo": action.repo if action else "",
                    "action_type": action.action_type.value if action else ActionType.UNKNOWN.value,
                    "author_verified": action.author_verified.value if action else VerificationStatus.UNKNOWN.value,
                    "ref_name": event.tag_name,
                    "ref_type": event.ref_type.value,
                    "previous_sha": event.previous_sha,
                    "new_sha": event.new_sha,
                    "detected_at": event.detected_at.isoformat(),
                    "first_seen_at": event.first_seen_at.isoformat() if event.first_seen_at else "",
                    "last_seen_at": event.last_seen_at.isoformat() if event.last_seen_at else "",
                    "source": event.source,
                    "notes": event.notes or "",
                }
            )
        return rows

    def compute_cascade_depth_reports(self, graph: CascadeGraph) -> list[CascadeDepthMetric]:
        reports: list[CascadeDepthMetric] = []
        edges_by_workflow: dict[str, list] = defaultdict(list)
        for edge in graph.edges:
            if edge.consumer_repository and edge.workflow_path:
                workflow_node_id = f"workflow::{edge.consumer_repository}::{edge.workflow_path}"
                edges_by_workflow[workflow_node_id].append(edge)

        for workflow_node_id in sorted(graph.workflow_nodes):
            _, repository_full_name, workflow_path = workflow_node_id.split("::", 2)
            workflow_edges = edges_by_workflow.get(workflow_node_id, [])
            actions_by_depth: dict[int, set[str]] = defaultdict(set)
            binding_types: list[RefType] = []
            binding_downgrade_count = 0
            high_risk_path_count = 0

            for edge in workflow_edges:
                actions_by_depth[edge.depth].add(edge.dst_node_id)
                binding_types.append(edge.ref_type)
                if edge.binding_downgrade:
                    binding_downgrade_count += 1
                if (
                    edge.depth >= 2
                    and graph.workflow_has_write_permissions.get(workflow_node_id, False)
                    and (action := graph.actions.get(edge.dst_node_id)) is not None
                    and action.has_token_access
                    and not self._is_same_repository(repository_full_name, action)
                ):
                    high_risk_path_count += 1

            total_bindings = len(binding_types)
            sha_binding_rate = (
                sum(1 for binding in binding_types if binding == RefType.SHA) / total_bindings if total_bindings else 0.0
            )
            tag_binding_rate = (
                sum(1 for binding in binding_types if binding == RefType.TAG) / total_bindings if total_bindings else 0.0
            )
            branch_binding_rate = (
                sum(1 for binding in binding_types if binding == RefType.BRANCH) / total_bindings if total_bindings else 0.0
            )
            main_binding_rate = (
                sum(1 for edge in workflow_edges if edge.ref_type == RefType.BRANCH and self._is_main_ref(edge.ref_string)) / total_bindings
                if total_bindings
                else 0.0
            )
            max_depth = max(actions_by_depth.keys(), default=0)
            layer_distribution = {
                f"level_{depth}": len(nodes)
                for depth, nodes in sorted(actions_by_depth.items())
            }
            reports.append(
                CascadeDepthMetric(
                    workflow_name=graph.workflow_names.get(workflow_node_id, workflow_path),
                    repository_full_name=repository_full_name,
                    workflow_path=workflow_path,
                    max_depth=max_depth,
                    layer_1_count=len(actions_by_depth.get(1, set())),
                    layer_2_count=len(actions_by_depth.get(2, set())),
                    layer_3_plus_count=sum(len(nodes) for depth, nodes in actions_by_depth.items() if depth >= 3),
                    sha_binding_rate=sha_binding_rate,
                    tag_binding_rate=tag_binding_rate,
                    branch_binding_rate=branch_binding_rate,
                    main_binding_rate=main_binding_rate,
                    has_token_access=high_risk_path_count > 0,
                    binding_downgrade_count=binding_downgrade_count,
                    high_risk_path_count=high_risk_path_count,
                    layer_distribution=layer_distribution,
                )
            )
        return reports

    def _collect_downstream_repositories(self, graph: CascadeGraph, action_id: str) -> set[str]:
        queue = deque([action_id])
        visited = {action_id}
        repositories: set[str] = set()
        while queue:
            node_id = queue.popleft()
            for predecessor in graph.reverse_adjacency.get(node_id, set()):
                if predecessor in visited:
                    continue
                visited.add(predecessor)
                if predecessor.startswith("workflow::"):
                    _, repository_full_name, _ = predecessor.split("::", 2)
                    repositories.add(repository_full_name)
                else:
                    queue.append(predecessor)
        return repositories

    def _collect_action_group_impact(
        self,
        graph: CascadeGraph,
        action_nodes: list[ActionNode],
    ) -> tuple[set[str], set[str], set[str]]:
        impacted_repositories: set[str] = set()
        impacted_workflows: set[str] = set()
        privileged_workflows: set[str] = set()

        action_ids = {action.action_id for action in action_nodes}
        for edge in graph.edges:
            if edge.dst_node_id not in action_ids or not edge.consumer_repository or not edge.workflow_path:
                continue
            workflow_node_id = f"workflow::{edge.consumer_repository}::{edge.workflow_path}"
            impacted_repositories.add(edge.consumer_repository)
            impacted_workflows.add(workflow_node_id)
            if graph.workflow_has_write_permissions.get(workflow_node_id, False):
                privileged_workflows.add(workflow_node_id)
        return impacted_repositories, impacted_workflows, privileged_workflows

    def _workflow_action_depth_index(self, graph: CascadeGraph) -> dict[tuple[str, str, str], int]:
        index: dict[tuple[str, str, str], int] = {}
        for edge in graph.edges:
            if edge.consumer_repository and edge.workflow_path:
                workflow_node_id = f"workflow::{edge.consumer_repository}::{edge.workflow_path}"
                key = (workflow_node_id, edge.dst_node_id, edge.edge_type)
                current = index.get(key)
                if current is None or edge.depth < current:
                    index[key] = edge.depth
        return index

    def _collect_impacted_workflows(self, graph: CascadeGraph) -> dict[str, dict[str, int]]:
        impacted: dict[str, dict[str, int]] = defaultdict(dict)
        for edge in graph.edges:
            if edge.consumer_repository and edge.workflow_path:
                workflow_node_id = f"workflow::{edge.consumer_repository}::{edge.workflow_path}"
                current = impacted[edge.dst_node_id].get(workflow_node_id)
                if current is None or edge.depth < current:
                    impacted[edge.dst_node_id][workflow_node_id] = edge.depth
        return impacted

    def _group_workflow_changes(self, workflow_changes: list[WorkflowUseChange]) -> dict[tuple[str, str], list[WorkflowUseChange]]:
        grouped: dict[tuple[str, str], list[WorkflowUseChange]] = defaultdict(list)
        for change in workflow_changes:
            grouped[(change.repository_full_name, change.workflow_path)].append(change)
        for items in grouped.values():
            items.sort(key=lambda item: item.committed_at)
        return grouped

    def _build_explicit_windows_for_event(
        self,
        *,
        event: DriftEvent,
        base_key: tuple[str, str, str],
        changes_by_workflow: dict[tuple[str, str], list[WorkflowUseChange]],
        depth_index: dict[tuple[str, str, str], int],
    ) -> list[UpdateWindowMetric]:
        metrics: list[UpdateWindowMetric] = []
        for (repository_full_name, workflow_path), changes in changes_by_workflow.items():
            update = self._find_first_explicit_update_after_event(changes, base_key, event)
            if update is None:
                continue

            action_id = event.action_id
            workflow_node_id = f"workflow::{repository_full_name}::{workflow_path}"
            depth = depth_index.get((workflow_node_id, action_id, "direct"), 1)
            action_owner, action_repo = base_key[0], base_key[1]
            metrics.append(
                UpdateWindowMetric(
                    event_id=event.drift_id,
                    action_id=event.action_id,
                    owner=action_owner,
                    repo=action_repo,
                    ref_name=event.tag_name,
                    ref_type=event.ref_type,
                    repository_full_name=repository_full_name,
                    workflow_path=workflow_path,
                    adoption_mode="explicit",
                    dependency_depth=depth,
                    depth_bucket=self._depth_bucket(depth),
                    upstream_changed_at=event.detected_at,
                    adopted_at=update["committed_at"],
                    lag_hours=(update["committed_at"] - event.detected_at).total_seconds() / 3600,
                    prior_ref=update["prior_ref"],
                    adopted_ref=update["adopted_ref"],
                    evidence=update["evidence"],
                )
            )
        return metrics

    def _find_first_explicit_update_after_event(
        self,
        changes: list[WorkflowUseChange],
        base_key: tuple[str, str, str],
        event: DriftEvent,
    ) -> dict | None:
        for change in changes:
            if change.committed_at <= event.detected_at:
                continue
            transition = self._extract_ref_transition(change, base_key)
            if transition is None:
                continue
            if transition["before_ref"] != event.tag_name:
                continue
            if transition["after_ref"] == event.tag_name:
                continue
            return {
                "committed_at": change.committed_at,
                "prior_ref": transition["before_ref"],
                "adopted_ref": transition["after_ref"],
                "evidence": "workflow_ref_changed_after_upstream_drift",
            }
        return None

    def _extract_ref_transition(
        self,
        change: WorkflowUseChange,
        base_key: tuple[str, str, str],
    ) -> dict | None:
        before_refs = self._refs_for_base_key(change.uses_before, base_key)
        after_refs = self._refs_for_base_key(change.uses_after, base_key)
        if before_refs == after_refs:
            return None
        if not before_refs or not after_refs:
            return None
        return {
            "before_ref": sorted(before_refs)[0],
            "after_ref": sorted(after_refs)[0],
        }

    def _refs_for_base_key(self, uses_values: list[str], base_key: tuple[str, str, str]) -> set[str]:
        refs: set[str] = set()
        for uses_value in uses_values:
            owner, repo, subpath, ref = parse_action_reference(uses_value)
            candidate_key = (owner.lower(), repo.lower(), (subpath or "").lower())
            if candidate_key == base_key:
                refs.add(ref)
        return refs

    def _depth_bucket(self, depth: int) -> str:
        if depth <= 1:
            return "level_1"
        if depth == 2:
            return "level_2"
        return "level_3_plus"

    def _percentile(self, values: list[float], quantile: float) -> float | None:
        if not values:
            return None
        index = max(0, min(len(values) - 1, int(round((len(values) - 1) * quantile))))
        return values[index]

    def _find_first_change_after(self, detected_at, changes: list[WorkflowUseChange]) -> WorkflowUseChange | None:
        for change in changes:
            if change.committed_at > detected_at:
                return change
        return None

    def _is_same_repository(self, repository_full_name: str, action: ActionNode) -> bool:
        return repository_full_name.lower() == f"{action.owner}/{action.repo}".lower()

    def _is_main_ref(self, ref_string: str | None) -> bool:
        if not ref_string:
            return False
        normalized = ref_string.strip().lower()
        return normalized in {"main", "refs/heads/main"}
