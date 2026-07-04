from __future__ import annotations

from collections import Counter
from pathlib import Path

from gha_cascade_analyzer.analyzers.action_content_resolver import ActionContentResolver
from gha_cascade_analyzer.analyzers.amplification_metrics import AmplificationMetricsAnalyzer
from gha_cascade_analyzer.analyzers.cdg_builder import RecursiveCDGBuilder
from gha_cascade_analyzer.analyzers.component_type_comparison import ComponentTypeComparisonAnalyzer
from gha_cascade_analyzer.analyzers.discovery_risk import DiscoveryRiskAnalyzer
from gha_cascade_analyzer.analyzers.evidence_strength import EvidenceStrengthAnalyzer
from gha_cascade_analyzer.analyzers.exporter import AnalysisExporter
from gha_cascade_analyzer.analyzers.isolation_risk import IsolationRiskAnalyzer
from gha_cascade_analyzer.analyzers.privileged_blast_radius import PrivilegedBlastRadiusAnalyzer
from gha_cascade_analyzer.analyzers.propagation_risk import PropagationRiskAnalyzer
from gha_cascade_analyzer.analyzers.privilege_risk import PrivilegeRiskAnalyzer
from gha_cascade_analyzer.analyzers.ref_risk import RefRiskAnalyzer
from gha_cascade_analyzer.analyzers.reusable_workflow import ReusableWorkflowAnalyzer
from gha_cascade_analyzer.analyzers.rq_metrics import RQMetricsEngine
from gha_cascade_analyzer.analyzers.stratified_comparisons import StratifiedComparisonAnalyzer
from gha_cascade_analyzer.analyzers.trust_amplification import TrustAmplificationAnalyzer
from gha_cascade_analyzer.collectors.github_client import GitHubClient
from gha_cascade_analyzer.collectors.repository_identity_tracker import RepositoryIdentityTracker
from gha_cascade_analyzer.config import Settings
from gha_cascade_analyzer.logging import log_event
from gha_cascade_analyzer.models import ActionNode, AnalysisReport, DriftEvent, MarketplaceActionIdentity, RefObservation, Repository, RepositoryIdentityObservation, WorkflowFile, WorkflowUseChange
from gha_cascade_analyzer.storage.jsonl_reader import JsonlReader
from gha_cascade_analyzer.utils.time import utc_now


class SecurityAnalysisEngine:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.reader = JsonlReader(settings.crawl.output_dir)
        self.exporter = AnalysisExporter(settings.crawl.output_dir / "analysis")
        self.metrics = RQMetricsEngine()
        self.component_type_comparison = ComponentTypeComparisonAnalyzer()
        self.amplification_metrics = AmplificationMetricsAnalyzer()
        self.discovery_risk = DiscoveryRiskAnalyzer()
        self.evidence_strength = EvidenceStrengthAnalyzer()
        self.ref_risk = RefRiskAnalyzer()
        self.isolation_risk = IsolationRiskAnalyzer()
        self.privileged_blast_radius = PrivilegedBlastRadiusAnalyzer()
        self.privilege_risk = PrivilegeRiskAnalyzer()
        self.propagation_risk = PropagationRiskAnalyzer()
        self.trust_amplification = TrustAmplificationAnalyzer()
        self.reusable_workflow = ReusableWorkflowAnalyzer()
        self.stratified_comparisons = StratifiedComparisonAnalyzer()

    async def run(self) -> AnalysisReport:
        if self.settings.analysis.require_complete_local_data:
            self._validate_local_inputs()

        raw_repositories = self.reader.read_models("repositories.jsonl", Repository)
        raw_workflows = self.reader.glob_models("workflows/*.jsonl", WorkflowFile)
        raw_workflow_changes = self.reader.glob_models("workflow_history/*.jsonl", WorkflowUseChange)
        raw_actions = self.reader.read_models("actions/discovered.jsonl", ActionNode)
        raw_observed_refs = self.reader.glob_models("refs/*.jsonl", RefObservation)
        raw_identity_observations = self.reader.glob_models("repo_identity/*.jsonl", RepositoryIdentityObservation)
        stored_drift_events = self.reader.read_models("drift_events.jsonl", DriftEvent)
        raw_marketplace = self.reader.read_models("marketplace/actions.jsonl", MarketplaceActionIdentity)

        repositories = self._dedupe_repositories(raw_repositories)
        workflows = self._dedupe_workflows(raw_workflows)
        workflow_changes = self._dedupe_workflow_changes(raw_workflow_changes)
        actions = self._dedupe_actions(raw_actions)
        observed_refs = self._dedupe_ref_observations(raw_observed_refs)
        identity_observations = self._dedupe_repository_identity_observations(raw_identity_observations)
        marketplace = self._dedupe_marketplace(raw_marketplace)
        drift_events = self.metrics.merge_drift_events(observed_refs, stored_drift_events)

        self._log_deduplication_summary(
            raw_repositories=raw_repositories,
            repositories=repositories,
            raw_workflows=raw_workflows,
            workflows=workflows,
            raw_workflow_changes=raw_workflow_changes,
            workflow_changes=workflow_changes,
            raw_actions=raw_actions,
            actions=actions,
            raw_observed_refs=raw_observed_refs,
            observed_refs=observed_refs,
            raw_identity_observations=raw_identity_observations,
            identity_observations=identity_observations,
            raw_marketplace=raw_marketplace,
            marketplace=marketplace,
        )

        log_event(
            f"Starting analysis with repositories={len(repositories)}, workflows={len(workflows)}, "
            f"workflow_changes={len(workflow_changes)}, observed_refs={len(observed_refs)}, "
            f"repo_identity_observations={len(identity_observations)}, "
            f"drift_events={len(drift_events)}, "
            f"marketplace_identities={len(marketplace)}, token_count={len(self.settings.github.tokens)}, "
            f"online_recursive_expand={self.settings.analysis.online_recursive_expand}"
        )

        if self.settings.analysis.online_recursive_expand and self.settings.github.tokens:
            try:
                async with GitHubClient(self.settings.github) as github_client:
                    log_event("Attempting online recursive CDG expansion")
                    graph = await RecursiveCDGBuilder(
                        action_resolver=ActionContentResolver(
                            github_client,
                            fetch_concurrency=self.settings.analysis.recursive_fetch_concurrency,
                        ),
                        marketplace_identities=marketplace,
                        max_depth=self.settings.analysis.recursive_max_depth,
                        progress_report_interval=self.settings.analysis.progress_report_interval,
                    ).build(repositories, workflows)
            except Exception as exc:
                log_event(f"Online recursive CDG expansion failed, falling back to offline analysis: {exc}")
                graph = await RecursiveCDGBuilder(
                    action_resolver=ActionContentResolver(None),
                    marketplace_identities=marketplace,
                    max_depth=self.settings.analysis.recursive_max_depth,
                    progress_report_interval=self.settings.analysis.progress_report_interval,
                ).build(repositories, workflows)
        else:
            log_event("Using offline CDG build from local collected data only")
            graph = await RecursiveCDGBuilder(
                action_resolver=ActionContentResolver(None),
                marketplace_identities=marketplace,
                max_depth=self.settings.analysis.recursive_max_depth,
                progress_report_interval=self.settings.analysis.progress_report_interval,
            ).build(repositories, workflows)

        graph = await self._supplement_action_metadata(graph)
        identity_observations = await self._supplement_identity_observations(
            identity_observations=identity_observations,
            graph=graph,
        )

        workflow_metrics = self.metrics.compute_implicit_dependency_ratio(graph)
        cascade_depth_reports = self.metrics.compute_cascade_depth_reports(graph)
        drift_distribution = self.metrics.compute_drift_distribution(graph.actions, drift_events)
        drift_observation_coverage = self.metrics.compute_drift_observation_coverage(observed_refs, drift_events)
        repository_transfer_risks = self.metrics.compute_repository_transfer_risks(graph, identity_observations)
        repository_transfer_summary = self.metrics.compute_repository_transfer_summary(graph, identity_observations, repository_transfer_risks)
        trust_domain_boundaries = self.metrics.compute_trust_domain_boundaries(graph)
        trust_domain_boundary_summary = self.metrics.compute_trust_domain_boundary_summary(trust_domain_boundaries)
        discovery_risk_candidates, discovery_risk_summary = self._compute_discovery_risk(
            graph=graph,
            workflows=workflows,
            workflow_changes=workflow_changes,
            identity_observations=identity_observations,
            marketplace=marketplace,
        )
        reusable_workflow_edges, reusable_workflow_summary, reusable_workflow_top_callees = self._compute_reusable_workflow(
            workflows=workflows,
        )
        isolation_risk_by_job, isolation_risk_summary, isolation_risk_examples = self._compute_isolation_risk(
            workflows=workflows,
        )
        blast_radius = self.metrics.compute_blast_radius(graph)
        amplification_by_node, amplification_summary, amplification_top_nodes = self._compute_amplification_metrics(
            graph=graph,
            blast_radius=blast_radius,
        )
        ref_risk_by_workflow, ref_risk_summary, ref_risk_by_depth, ref_risk_by_action = self._compute_ref_risk(
            graph=graph,
            blast_radius=blast_radius,
            drift_events=drift_events,
        )
        privilege_risk_by_workflow, privilege_risk_by_job, privilege_risk_summary, privilege_risk_examples = self._compute_privilege_risk(
            workflows=workflows,
            graph=graph,
            isolation_risk_by_job=isolation_risk_by_job,
        )
        propagation_risk_by_workflow, propagation_risk_summary, propagation_risk_examples = self._compute_propagation_risk(
            workflows=workflows,
            graph=graph,
            privilege_risk_by_workflow=privilege_risk_by_workflow,
        )
        trust_amplification_by_entity, trust_amplification_summary, trust_amplification_top_entities = self._compute_trust_amplification(
            graph=graph,
            marketplace=marketplace,
            blast_radius=blast_radius,
            ref_risk_by_action=ref_risk_by_action,
            privilege_risk_by_workflow=privilege_risk_by_workflow,
        )
        privileged_blast_radius_by_action, privileged_blast_radius_summary = self._compute_privileged_blast_radius(
            graph=graph,
            blast_radius=blast_radius,
            privilege_risk_by_workflow=privilege_risk_by_workflow,
            ref_risk_by_action=ref_risk_by_action,
        )
        component_type_comparison = self._compute_component_type_comparison(
            actions=list(graph.actions.values()),
            ref_risk_by_action=ref_risk_by_action,
            amplification_by_node=amplification_by_node,
            privileged_blast_radius_by_action=privileged_blast_radius_by_action,
        )
        ref_type_comparison, cross_owner_comparison, reusable_workflow_risk_profile = self._compute_stratified_comparisons(
            ref_risk_by_action=ref_risk_by_action,
            ref_risk_by_workflow=ref_risk_by_workflow,
            privilege_risk_by_workflow=privilege_risk_by_workflow,
            propagation_risk_by_workflow=propagation_risk_by_workflow,
            trust_domain_boundaries=trust_domain_boundaries,
            reusable_workflow_edges=reusable_workflow_edges,
        )
        bootstrap_indicators, cross_owner_effects, manual_validation_candidates = self._compute_evidence_strength(
            workflow_metrics=workflow_metrics,
            ref_risk_by_workflow=ref_risk_by_workflow,
            privilege_risk_by_workflow=privilege_risk_by_workflow,
            privilege_risk_by_job=privilege_risk_by_job,
            propagation_risk_by_workflow=propagation_risk_by_workflow,
            trust_domain_boundaries=trust_domain_boundaries,
            ref_risk_by_action=ref_risk_by_action,
            trust_amplification_by_entity=trust_amplification_by_entity,
        )
        exposure_windows = self.metrics.compute_exposure_windows(workflow_changes, drift_events)
        exposure_window_summary = self.metrics.compute_exposure_window_summary(exposure_windows)
        update_windows = self.metrics.compute_update_windows(graph, workflow_changes, drift_events)
        update_window_summary = self.metrics.compute_update_window_summary(update_windows)
        time_window_amplification = self.metrics.compute_time_window_amplification(update_window_summary)

        report = AnalysisReport(
            generated_at=utc_now(),
            workflow_metrics=workflow_metrics,
            cascade_depth_reports=cascade_depth_reports,
            drift_distribution=drift_distribution,
            blast_radius=blast_radius,
            amplification_by_node=amplification_by_node,
            amplification_summary=amplification_summary,
            exposure_windows=exposure_windows,
            update_windows=update_windows,
            drift_observation_coverage=drift_observation_coverage,
            repository_transfer_risks=repository_transfer_risks,
            repository_transfer_summary=repository_transfer_summary,
            trust_domain_boundaries=trust_domain_boundaries,
            trust_domain_boundary_summary=trust_domain_boundary_summary,
            discovery_risk_candidates=discovery_risk_candidates,
            discovery_risk_summary=discovery_risk_summary,
            reusable_workflow_edges=reusable_workflow_edges,
            reusable_workflow_summary=reusable_workflow_summary,
            reusable_workflow_top_callees=reusable_workflow_top_callees,
            isolation_risk_by_job=isolation_risk_by_job,
            isolation_risk_summary=isolation_risk_summary,
            isolation_risk_examples=isolation_risk_examples,
            privilege_risk_by_workflow=privilege_risk_by_workflow,
            privilege_risk_by_job=privilege_risk_by_job,
            privilege_risk_summary=privilege_risk_summary,
            privilege_risk_examples=privilege_risk_examples,
            propagation_risk_by_workflow=propagation_risk_by_workflow,
            propagation_risk_summary=propagation_risk_summary,
            propagation_risk_examples=propagation_risk_examples,
            trust_amplification_by_entity=trust_amplification_by_entity,
            trust_amplification_summary=trust_amplification_summary,
            privileged_blast_radius_by_action=privileged_blast_radius_by_action,
            privileged_blast_radius_summary=privileged_blast_radius_summary,
            component_type_comparison=component_type_comparison,
            ref_type_comparison=ref_type_comparison,
            cross_owner_comparison=cross_owner_comparison,
            reusable_workflow_risk_profile=reusable_workflow_risk_profile,
            ref_risk_by_workflow=ref_risk_by_workflow,
            ref_risk_summary=ref_risk_summary,
            ref_risk_by_depth=ref_risk_by_depth,
            ref_risk_by_action=ref_risk_by_action,
            exposure_window_summary=exposure_window_summary,
            update_window_summary=update_window_summary,
            time_window_amplification=time_window_amplification,
            bootstrap_indicators=bootstrap_indicators,
            cross_owner_effects=cross_owner_effects,
            manual_validation_candidates=manual_validation_candidates,
        )
        self._export_report(report, graph, drift_events)
        log_event("Analysis finished and results were exported")
        return report

    def _validate_local_inputs(self) -> None:
        root = self.settings.crawl.output_dir
        missing_items: list[str] = []

        required_files = [
            root / "repositories.jsonl",
        ]
        for path in required_files:
            if not path.exists():
                missing_items.append(str(path))

        required_dirs = [
            root / "workflows",
            root / "workflow_history",
            root / "refs",
        ]
        for path in required_dirs:
            if not path.exists() or not any(path.glob("*.jsonl")):
                missing_items.append(f"{path}/*.jsonl")

        if missing_items:
            joined = ", ".join(missing_items)
            raise RuntimeError(
                "Analysis requires complete local collection outputs before it can run. "
                f"Missing required inputs: {joined}"
            )

    def _export_report(self, report: AnalysisReport, graph, drift_events: list[DriftEvent]) -> None:
        cascade_depth_rows = [
            {
                "workflow_name": item.workflow_name,
                "repository_full_name": item.repository_full_name,
                "workflow_path": item.workflow_path,
                "max_depth": item.max_depth,
                "layer_1_count": item.layer_1_count,
                "layer_2_count": item.layer_2_count,
                "layer_3_plus_count": item.layer_3_plus_count,
                "sha_binding_rate": item.sha_binding_rate,
                "tag_binding_rate": item.tag_binding_rate,
                "branch_binding_rate": item.branch_binding_rate,
                "main_binding_rate": item.main_binding_rate,
                "has_token_access": item.has_token_access,
                "binding_downgrade_count": item.binding_downgrade_count,
                "high_risk_path_count": item.high_risk_path_count,
            }
            for item in report.cascade_depth_reports
        ]
        drift_event_rows = self.metrics.build_drift_event_rows(graph.actions, drift_events)

        export_operations = [
            ("report.json", lambda: self.exporter.export_model_json("report.json", report)),
            ("cdg_edges.json", lambda: self.exporter.export_models_json("cdg_edges.json", graph.edges)),
            ("cdg_edges.csv", lambda: self.exporter.export_models_csv("cdg_edges.csv", graph.edges)),
            ("workflow_implicit_ratio.csv", lambda: self.exporter.export_models_csv("workflow_implicit_ratio.csv", report.workflow_metrics)),
            ("cascade_depth_report.csv", lambda: self.exporter.export_rows_csv("cascade_depth_report.csv", cascade_depth_rows)),
            ("drift_distribution.csv", lambda: self.exporter.export_models_csv("drift_distribution.csv", report.drift_distribution)),
            ("drift_events.csv", lambda: self.exporter.export_models_csv("drift_events.csv", drift_events)),
            ("drift_events_enriched.csv", lambda: self.exporter.export_rows_csv("drift_events_enriched.csv", drift_event_rows)),
            ("drift_observation_coverage.csv", lambda: self.exporter.export_models_csv("drift_observation_coverage.csv", [report.drift_observation_coverage])),
            ("repository_transfer_risks.csv", lambda: self.exporter.export_models_csv("repository_transfer_risks.csv", report.repository_transfer_risks)),
            ("repository_transfer_summary.csv", lambda: self.exporter.export_models_csv("repository_transfer_summary.csv", [report.repository_transfer_summary])),
            ("trust_domain_boundaries.csv", lambda: self.exporter.export_models_csv("trust_domain_boundaries.csv", report.trust_domain_boundaries)),
            ("trust_domain_boundary_summary.csv", lambda: self.exporter.export_models_csv("trust_domain_boundary_summary.csv", [report.trust_domain_boundary_summary])),
            ("discovery_risk_candidates.csv", lambda: self.exporter.export_models_csv("discovery_risk_candidates.csv", report.discovery_risk_candidates)),
            ("discovery_risk_summary.csv", lambda: self.exporter.export_models_csv("discovery_risk_summary.csv", [report.discovery_risk_summary])),
            ("reusable_workflow_edges.csv", lambda: self.exporter.export_models_csv("reusable_workflow_edges.csv", report.reusable_workflow_edges)),
            ("reusable_workflow_summary.csv", lambda: self.exporter.export_models_csv("reusable_workflow_summary.csv", [report.reusable_workflow_summary])),
            ("reusable_workflow_top_callees.csv", lambda: self.exporter.export_models_csv("reusable_workflow_top_callees.csv", report.reusable_workflow_top_callees)),
            ("reusable_workflow_risk_profile.csv", lambda: self.exporter.export_models_csv("reusable_workflow_risk_profile.csv", report.reusable_workflow_risk_profile)),
            ("isolation_risk_by_job.csv", lambda: self.exporter.export_models_csv("isolation_risk_by_job.csv", report.isolation_risk_by_job)),
            ("isolation_risk_summary.csv", lambda: self.exporter.export_models_csv("isolation_risk_summary.csv", [report.isolation_risk_summary])),
            ("isolation_risk_examples.csv", lambda: self.exporter.export_models_csv("isolation_risk_examples.csv", report.isolation_risk_examples)),
            ("privilege_risk_by_workflow.csv", lambda: self.exporter.export_models_csv("privilege_risk_by_workflow.csv", report.privilege_risk_by_workflow)),
            ("privilege_risk_by_job.csv", lambda: self.exporter.export_models_csv("privilege_risk_by_job.csv", report.privilege_risk_by_job)),
            ("privilege_risk_summary.csv", lambda: self.exporter.export_models_csv("privilege_risk_summary.csv", [report.privilege_risk_summary])),
            ("privilege_risk_examples.csv", lambda: self.exporter.export_models_csv("privilege_risk_examples.csv", report.privilege_risk_examples)),
            ("propagation_risk_by_workflow.csv", lambda: self.exporter.export_models_csv("propagation_risk_by_workflow.csv", report.propagation_risk_by_workflow)),
            ("propagation_risk_summary.csv", lambda: self.exporter.export_models_csv("propagation_risk_summary.csv", [report.propagation_risk_summary])),
            ("propagation_risk_examples.csv", lambda: self.exporter.export_models_csv("propagation_risk_examples.csv", report.propagation_risk_examples)),
            ("trust_amplification_by_entity.csv", lambda: self.exporter.export_models_csv("trust_amplification_by_entity.csv", report.trust_amplification_by_entity)),
            ("trust_amplification_summary.csv", lambda: self.exporter.export_models_csv("trust_amplification_summary.csv", [report.trust_amplification_summary])),
            ("trust_amplification_top_entities.csv", lambda: self.exporter.export_models_csv("trust_amplification_top_entities.csv", report.trust_amplification_by_entity[:100])),
            ("privileged_blast_radius_by_action.csv", lambda: self.exporter.export_models_csv("privileged_blast_radius_by_action.csv", report.privileged_blast_radius_by_action)),
            ("privileged_blast_radius_summary.csv", lambda: self.exporter.export_models_csv("privileged_blast_radius_summary.csv", [report.privileged_blast_radius_summary])),
            ("component_type_comparison.csv", lambda: self.exporter.export_models_csv("component_type_comparison.csv", report.component_type_comparison)),
            ("bootstrap_indicators.csv", lambda: self.exporter.export_models_csv("bootstrap_indicators.csv", report.bootstrap_indicators)),
            ("cross_owner_effects.csv", lambda: self.exporter.export_models_csv("cross_owner_effects.csv", report.cross_owner_effects)),
            ("manual_validation_candidates.csv", lambda: self.exporter.export_models_csv("manual_validation_candidates.csv", report.manual_validation_candidates)),
            ("ref_risk_by_workflow.csv", lambda: self.exporter.export_models_csv("ref_risk_by_workflow.csv", report.ref_risk_by_workflow)),
            ("ref_risk_summary.csv", lambda: self.exporter.export_models_csv("ref_risk_summary.csv", [report.ref_risk_summary])),
            ("ref_risk_by_depth.csv", lambda: self.exporter.export_models_csv("ref_risk_by_depth.csv", report.ref_risk_by_depth)),
            ("ref_risk_by_action.csv", lambda: self.exporter.export_models_csv("ref_risk_by_action.csv", report.ref_risk_by_action)),
            ("ref_type_risk_comparison.csv", lambda: self.exporter.export_models_csv("ref_type_risk_comparison.csv", report.ref_type_comparison)),
            ("cross_owner_comparison.csv", lambda: self.exporter.export_models_csv("cross_owner_comparison.csv", report.cross_owner_comparison)),
            ("blast_radius.csv", lambda: self.exporter.export_models_csv("blast_radius.csv", report.blast_radius)),
            ("amplification_by_node.csv", lambda: self.exporter.export_models_csv("amplification_by_node.csv", report.amplification_by_node)),
            ("amplification_summary.csv", lambda: self.exporter.export_models_csv("amplification_summary.csv", [report.amplification_summary])),
            ("amplification_top_nodes.csv", lambda: self.exporter.export_models_csv("amplification_top_nodes.csv", report.amplification_by_node[:100])),
            ("exposure_windows.csv", lambda: self.exporter.export_models_csv("exposure_windows.csv", report.exposure_windows)),
            ("exposure_window_summary.csv", lambda: self.exporter.export_models_csv("exposure_window_summary.csv", [report.exposure_window_summary])),
            ("update_windows.csv", lambda: self.exporter.export_models_csv("update_windows.csv", report.update_windows)),
            ("update_window_summary.csv", lambda: self.exporter.export_models_csv("update_window_summary.csv", report.update_window_summary)),
            ("time_window_amplification.csv", lambda: self.exporter.export_models_csv("time_window_amplification.csv", report.time_window_amplification)),
        ]

        export_failures: list[dict[str, str]] = []
        for artifact_name, export_fn in export_operations:
            try:
                export_fn()
            except Exception as exc:
                export_failures.append({"artifact": artifact_name, "error": repr(exc)})
                log_event(f"Artifact export failed for {artifact_name}: {exc!r}")

        if export_failures:
            self.exporter.export_rows_csv("export_failures.csv", export_failures)
            log_event(
                f"Artifact export completed with {len(export_failures)} failure(s); "
                "see analysis/export_failures.csv for details"
            )
        else:
            log_event("Artifact export completed without failures")

    def _dedupe_repositories(self, repositories: list[Repository]) -> list[Repository]:
        by_repo_id: dict[int, Repository] = {}
        for item in repositories:
            current = by_repo_id.get(item.repo_id)
            if current is None or item.collected_at >= current.collected_at:
                by_repo_id[item.repo_id] = item
        return sorted(by_repo_id.values(), key=lambda item: (-item.stars, item.full_name.lower()))

    def _dedupe_workflows(self, workflows: list[WorkflowFile]) -> list[WorkflowFile]:
        by_key: dict[tuple[str, str, str], WorkflowFile] = {}
        for item in workflows:
            key = (item.repository_full_name, item.path, item.sha)
            current = by_key.get(key)
            if current is None or item.discovered_at >= current.discovered_at:
                by_key[key] = item
        return sorted(by_key.values(), key=lambda item: (item.repository_full_name.lower(), item.path.lower(), item.sha))

    def _dedupe_workflow_changes(self, workflow_changes: list[WorkflowUseChange]) -> list[WorkflowUseChange]:
        by_key: dict[tuple, WorkflowUseChange] = {}
        for item in workflow_changes:
            key = (
                item.repository_full_name,
                item.workflow_path,
                item.commit_sha,
                item.committed_at,
                tuple(item.uses_before),
                tuple(item.uses_after),
            )
            by_key[key] = item
        return sorted(by_key.values(), key=lambda item: (item.repository_full_name.lower(), item.workflow_path.lower(), item.committed_at))

    def _dedupe_actions(self, actions: list[ActionNode]) -> list[ActionNode]:
        by_action_id: dict[str, ActionNode] = {}
        for item in actions:
            current = by_action_id.get(item.action_id)
            if current is None or item.discovered_at >= current.discovered_at:
                by_action_id[item.action_id] = item
        return sorted(by_action_id.values(), key=lambda item: (item.owner.lower(), item.repo.lower(), item.ref.lower(), item.action_id))

    def _dedupe_ref_observations(self, observations: list[RefObservation]) -> list[RefObservation]:
        by_key: dict[tuple, RefObservation] = {}
        for item in observations:
            key = (item.action_id, item.ref_name, item.ref_type, item.sha, item.observed_at)
            by_key[key] = item
        return sorted(by_key.values(), key=lambda item: (item.action_id, item.ref_name, item.observed_at))

    def _dedupe_repository_identity_observations(
        self,
        observations: list[RepositoryIdentityObservation],
    ) -> list[RepositoryIdentityObservation]:
        by_key: dict[tuple, RepositoryIdentityObservation] = {}
        for item in observations:
            key = (
                item.referenced_full_name,
                item.resolved_full_name,
                item.repository_id,
                item.status_code,
                item.identity_status,
                item.observed_at,
            )
            by_key[key] = item
        return sorted(by_key.values(), key=lambda item: (item.referenced_full_name.lower(), item.observed_at))

    def _dedupe_marketplace(self, identities: list[MarketplaceActionIdentity]) -> list[MarketplaceActionIdentity]:
        by_key: dict[tuple[str, str], MarketplaceActionIdentity] = {}
        slug_only: dict[str, MarketplaceActionIdentity] = {}
        for item in identities:
            if item.owner and item.repository:
                by_key[(item.owner.lower(), item.repository.lower())] = item
            else:
                slug_only[item.slug.lower()] = item
        combined = list(by_key.values()) + list(slug_only.values())
        return sorted(combined, key=lambda item: item.slug.lower())

    def _log_deduplication_summary(
        self,
        *,
        raw_repositories: list[Repository],
        repositories: list[Repository],
        raw_workflows: list[WorkflowFile],
        workflows: list[WorkflowFile],
        raw_workflow_changes: list[WorkflowUseChange],
        workflow_changes: list[WorkflowUseChange],
        raw_actions: list[ActionNode],
        actions: list[ActionNode],
        raw_observed_refs: list[RefObservation],
        observed_refs: list[RefObservation],
        raw_identity_observations: list[RepositoryIdentityObservation],
        identity_observations: list[RepositoryIdentityObservation],
        raw_marketplace: list[MarketplaceActionIdentity],
        marketplace: list[MarketplaceActionIdentity],
    ) -> None:
        if (
            len(raw_repositories) != len(repositories)
            or len(raw_workflows) != len(workflows)
            or len(raw_workflow_changes) != len(workflow_changes)
            or len(raw_actions) != len(actions)
            or len(raw_observed_refs) != len(observed_refs)
            or len(raw_identity_observations) != len(identity_observations)
            or len(raw_marketplace) != len(marketplace)
        ):
            log_event(
                "Deduplicated analysis inputs: "
                f"repositories {len(raw_repositories)}->{len(repositories)}, "
                f"workflows {len(raw_workflows)}->{len(workflows)}, "
                f"workflow_changes {len(raw_workflow_changes)}->{len(workflow_changes)}, "
                f"actions {len(raw_actions)}->{len(actions)}, "
                f"observed_refs {len(raw_observed_refs)}->{len(observed_refs)}, "
                f"repo_identity {len(raw_identity_observations)}->{len(identity_observations)}, "
                f"marketplace {len(raw_marketplace)}->{len(marketplace)}"
            )

    def _compute_discovery_risk(
        self,
        *,
        graph,
        workflows: list[WorkflowFile],
        workflow_changes: list[WorkflowUseChange],
        identity_observations: list[RepositoryIdentityObservation],
        marketplace: list[MarketplaceActionIdentity],
    ):
        if not graph.actions:
            log_event("Warning: discovery-risk analysis skipped because no action references were available")
            return [], self.discovery_risk.analyze(graph, [], [], [], [])[1]
        if not workflows and not workflow_changes:
            log_event("Warning: discovery-risk analysis is running without workflow snapshots or workflow history")
        if not identity_observations:
            log_event("Warning: discovery-risk analysis is running without repository identity observations")
        if not marketplace:
            log_event("Warning: discovery-risk analysis is running without marketplace metadata")
        try:
            return self.discovery_risk.analyze(
                graph=graph,
                workflows=workflows,
                workflow_changes=workflow_changes,
                identity_observations=identity_observations,
                marketplace_identities=marketplace,
            )
        except Exception as exc:
            log_event(f"Warning: discovery-risk analysis failed and will be exported as empty: {exc}")
            return [], self.discovery_risk.analyze(graph, [], [], [], [])[1]

    def _compute_reusable_workflow(
        self,
        *,
        workflows: list[WorkflowFile],
    ):
        if not workflows:
            log_event("Warning: reusable-workflow analysis skipped because no workflow snapshots were available")
            return [], self.reusable_workflow.analyze([])[1], []
        try:
            return self.reusable_workflow.analyze(workflows)
        except Exception as exc:
            log_event(f"Warning: reusable-workflow analysis failed and will be exported as empty: {exc}")
            return [], self.reusable_workflow.analyze([])[1], []

    def _compute_ref_risk(
        self,
        *,
        graph,
        blast_radius,
        drift_events: list[DriftEvent],
    ):
        if not graph.actions:
            log_event("Warning: ref-risk analysis skipped because no action references were available")
            return [], self.ref_risk.analyze(graph=graph, blast_radius=[], drift_events=[])[1], [], []
        try:
            return self.ref_risk.analyze(
                graph=graph,
                blast_radius=blast_radius,
                drift_events=drift_events,
            )
        except Exception as exc:
            log_event(f"Warning: ref-risk analysis failed and will be exported as empty: {exc}")
            return [], self.ref_risk.analyze(graph=graph, blast_radius=[], drift_events=[])[1], [], []

    def _compute_amplification_metrics(
        self,
        *,
        graph,
        blast_radius,
    ):
        if not graph.actions and not graph.workflow_nodes:
            log_event("Warning: amplification-metrics analysis skipped because the CDG was empty")
            return [], self.amplification_metrics.analyze(graph=graph, blast_radius=[])[1], []
        try:
            return self.amplification_metrics.analyze(
                graph=graph,
                blast_radius=blast_radius,
            )
        except Exception as exc:
            log_event(f"Warning: amplification-metrics analysis failed and will be exported as empty: {exc}")
            return [], self.amplification_metrics.analyze(graph=graph, blast_radius=[])[1], []

    def _compute_isolation_risk(
        self,
        *,
        workflows: list[WorkflowFile],
    ):
        if not workflows:
            log_event("Warning: isolation-risk analysis skipped because no workflow snapshots were available")
            return [], self.isolation_risk.analyze([])[1], []
        try:
            return self.isolation_risk.analyze(workflows)
        except Exception as exc:
            log_event(f"Warning: isolation-risk analysis failed and will be exported as empty: {exc}")
            return [], self.isolation_risk.analyze([])[1], []

    def _compute_privilege_risk(
        self,
        *,
        workflows: list[WorkflowFile],
        graph,
        isolation_risk_by_job,
    ):
        if not workflows:
            log_event("Warning: privilege-risk analysis skipped because no workflow snapshots were available")
            return [], [], self.privilege_risk.analyze(workflows=[], graph=graph, isolation_rows=[])[2], []
        try:
            return self.privilege_risk.analyze(
                workflows=workflows,
                graph=graph,
                isolation_rows=isolation_risk_by_job,
            )
        except Exception as exc:
            log_event(f"Warning: privilege-risk analysis failed and will be exported as empty: {exc}")
            return [], [], self.privilege_risk.analyze(workflows=[], graph=graph, isolation_rows=[])[2], []

    def _compute_propagation_risk(
        self,
        *,
        workflows: list[WorkflowFile],
        graph,
        privilege_risk_by_workflow,
    ):
        if not workflows:
            log_event("Warning: propagation-risk analysis skipped because no workflow snapshots were available")
            return [], self.propagation_risk.analyze(workflows=[], graph=graph, privilege_rows=[])[1], []
        try:
            return self.propagation_risk.analyze(
                workflows=workflows,
                graph=graph,
                privilege_rows=privilege_risk_by_workflow,
            )
        except Exception as exc:
            log_event(f"Warning: propagation-risk analysis failed and will be exported as empty: {exc}")
            return [], self.propagation_risk.analyze(workflows=[], graph=graph, privilege_rows=[])[1], []

    def _compute_trust_amplification(
        self,
        *,
        graph,
        marketplace,
        blast_radius,
        ref_risk_by_action,
        privilege_risk_by_workflow,
    ):
        if not graph.actions:
            log_event("Warning: trust-amplification analysis skipped because no action references were available")
            return [], self.trust_amplification.analyze(graph=graph, marketplace_identities=[], blast_radius=[], ref_risk_by_action=[], privilege_risk_by_workflow=[])[1], []
        try:
            return self.trust_amplification.analyze(
                graph=graph,
                marketplace_identities=marketplace,
                blast_radius=blast_radius,
                ref_risk_by_action=ref_risk_by_action,
                privilege_risk_by_workflow=privilege_risk_by_workflow,
            )
        except Exception as exc:
            log_event(f"Warning: trust-amplification analysis failed and will be exported as empty: {exc}")
            return [], self.trust_amplification.analyze(graph=graph, marketplace_identities=[], blast_radius=[], ref_risk_by_action=[], privilege_risk_by_workflow=[])[1], []

    def _compute_privileged_blast_radius(
        self,
        *,
        graph,
        blast_radius,
        privilege_risk_by_workflow,
        ref_risk_by_action,
    ):
        try:
            return self.privileged_blast_radius.analyze(
                graph=graph,
                blast_radius=blast_radius,
                privilege_risk_by_workflow=privilege_risk_by_workflow,
                ref_risk_by_action=ref_risk_by_action,
            )
        except Exception as exc:
            log_event(f"Warning: privileged-blast-radius analysis failed and will be exported as empty: {exc}")
            return [], self.privileged_blast_radius.analyze(graph=graph, blast_radius=[], privilege_risk_by_workflow=[], ref_risk_by_action=[])[1]

    def _compute_component_type_comparison(
        self,
        *,
        actions: list[ActionNode],
        ref_risk_by_action,
        amplification_by_node,
        privileged_blast_radius_by_action,
    ):
        if not actions:
            log_event("Warning: component-type comparison skipped because no discovered action metadata were available")
            return []
        try:
            return self.component_type_comparison.analyze(
                actions=actions,
                ref_risk_by_action=ref_risk_by_action,
                amplification_by_node=amplification_by_node,
                privileged_blast_radius_by_action=privileged_blast_radius_by_action,
            )
        except Exception as exc:
            log_event(f"Warning: component-type comparison failed and will be exported as empty: {exc}")
            return []

    async def _supplement_identity_observations(
        self,
        *,
        identity_observations: list[RepositoryIdentityObservation],
        graph,
    ) -> list[RepositoryIdentityObservation]:
        max_repositories = max(0, self.settings.analysis.supplemental_identity_max_repositories)
        if (
            max_repositories == 0
            or not graph.actions
            or not self.settings.github.tokens
        ):
            return identity_observations

        observed_keys = {
            (item.referenced_owner.lower(), item.referenced_repo.lower())
            for item in identity_observations
        }
        reference_counts: Counter[tuple[str, str]] = Counter()
        representative_actions: dict[tuple[str, str], ActionNode] = {}

        for action in graph.actions.values():
            key = (action.owner.lower(), action.repo.lower())
            representative_actions.setdefault(key, action)
            reference_counts.setdefault(key, 0)

        for edge in graph.edges:
            if edge.dst_kind != "action":
                continue
            action = graph.actions.get(edge.dst_node_id)
            if action is None:
                continue
            key = (action.owner.lower(), action.repo.lower())
            representative_actions.setdefault(key, action)
            reference_counts[key] += 1

        missing_keys = [
            key
            for key, _count in reference_counts.most_common()
            if key not in observed_keys and key in representative_actions
        ]
        if not missing_keys:
            return identity_observations

        selected_keys = missing_keys[:max_repositories]
        selected_actions = [representative_actions[key] for key in selected_keys]
        log_event(
            "Supplementing repository identity coverage for analysis: "
            f"missing={len(missing_keys)}, selected={len(selected_actions)}, cap={max_repositories}"
        )
        try:
            async with GitHubClient(self.settings.github) as github_client:
                tracker = RepositoryIdentityTracker(github_client)
                supplemental = await tracker.observe_action_repositories(
                    selected_actions,
                    batch_size=self.settings.analysis.supplemental_identity_concurrency,
                )
        except Exception as exc:
            log_event(f"Warning: supplemental repository identity observation failed: {exc}")
            return identity_observations

        merged = self._dedupe_repository_identity_observations(identity_observations + supplemental)
        log_event(
            "Supplemental repository identity coverage complete: "
            f"{len(identity_observations)} -> {len(merged)} observations"
        )
        return merged

    async def _supplement_action_metadata(self, graph):
        max_actions = max(0, self.settings.analysis.supplemental_action_metadata_max_actions)
        if max_actions == 0 or not graph.actions or not self.settings.github.tokens:
            return graph

        action_usage_counts: Counter[str] = Counter()
        for edge in graph.edges:
            if edge.dst_kind == "action":
                action_usage_counts[edge.dst_node_id] += 1

        unknown_actions = [
            action
            for action in graph.actions.values()
            if action.action_type.value == "unknown"
        ]
        if not unknown_actions:
            return graph

        unknown_actions.sort(
            key=lambda item: (
                action_usage_counts.get(item.action_id, 0),
                item.owner.lower(),
                item.repo.lower(),
                item.ref.lower(),
            ),
            reverse=True,
        )
        selected_actions = unknown_actions[:max_actions]
        log_event(
            "Supplementing action metadata for analysis: "
            f"unknown={len(unknown_actions)}, selected={len(selected_actions)}, cap={max_actions}"
        )

        try:
            async with GitHubClient(self.settings.github) as github_client:
                resolver = ActionContentResolver(
                    github_client,
                    fetch_concurrency=self.settings.analysis.supplemental_action_metadata_concurrency,
                )
                for index, action in enumerate(selected_actions, start=1):
                    resolved = None
                    if action.subpath and action.subpath.startswith(".github/workflows/"):
                        resolved = await resolver.fetch_reusable_workflow(
                            action.owner,
                            action.repo,
                            action.subpath,
                            action.ref,
                        )
                    else:
                        resolved = await resolver.fetch_action_definition(
                            action.owner,
                            action.repo,
                            action.subpath,
                            action.ref,
                        )
                    if resolved is None:
                        continue
                    action.action_type = resolved.action_type
                    action.declared_permissions = resolved.declared_permissions
                    action.has_token_access = resolved.has_token_access
                    action.token_access_patterns = resolved.token_access_patterns
                    action.audited_source_files = resolved.audited_source_files
                    if index <= 3 or index % 100 == 0:
                        log_event(
                            "Supplemental action metadata progress: "
                            f"processed={index}/{len(selected_actions)}, "
                            f"resolved_type={action.action_type.value}, action={action.owner}/{action.repo}@{action.ref}"
                        )
        except Exception as exc:
            log_event(f"Warning: supplemental action metadata enrichment failed: {exc}")
            return graph

        resolved_count = sum(1 for action in selected_actions if action.action_type.value != "unknown")
        log_event(
            "Supplemental action metadata complete: "
            f"resolved={resolved_count}/{len(selected_actions)} selected actions"
        )
        return graph

    def _compute_stratified_comparisons(
        self,
        *,
        ref_risk_by_action,
        ref_risk_by_workflow,
        privilege_risk_by_workflow,
        propagation_risk_by_workflow,
        trust_domain_boundaries,
        reusable_workflow_edges,
    ):
        try:
            return self.stratified_comparisons.analyze(
                ref_risk_by_action=ref_risk_by_action,
                ref_risk_by_workflow=ref_risk_by_workflow,
                privilege_risk_by_workflow=privilege_risk_by_workflow,
                propagation_risk_by_workflow=propagation_risk_by_workflow,
                trust_domain_boundaries=trust_domain_boundaries,
                reusable_workflow_edges=reusable_workflow_edges,
            )
        except Exception as exc:
            log_event(f"Warning: stratified-comparison analysis failed and will be exported as empty: {exc}")
            return [], [], []

    def _compute_evidence_strength(
        self,
        *,
        workflow_metrics,
        ref_risk_by_workflow,
        privilege_risk_by_workflow,
        privilege_risk_by_job,
        propagation_risk_by_workflow,
        trust_domain_boundaries,
        ref_risk_by_action,
        trust_amplification_by_entity,
    ):
        try:
            return self.evidence_strength.analyze(
                workflow_metrics=workflow_metrics,
                ref_risk_by_workflow=ref_risk_by_workflow,
                privilege_risk_by_workflow=privilege_risk_by_workflow,
                privilege_risk_by_job=privilege_risk_by_job,
                propagation_risk_by_workflow=propagation_risk_by_workflow,
                trust_domain_boundaries=trust_domain_boundaries,
                ref_risk_by_action=ref_risk_by_action,
                trust_amplification_by_entity=trust_amplification_by_entity,
            )
        except Exception as exc:
            log_event(f"Warning: evidence-strength analysis failed and will be exported as empty: {exc}")
            return [], [], []
