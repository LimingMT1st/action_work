from __future__ import annotations

from collections import Counter, defaultdict
import re

from gha_cascade_analyzer.analyzers.graph_types import CascadeGraph
from gha_cascade_analyzer.models import (
    BlastRadiusMetric,
    DriftEvent,
    RefRiskByActionMetric,
    RefRiskByDepthMetric,
    RefRiskByWorkflowMetric,
    RefRiskSummaryMetric,
)


FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
SHORT_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,39}$")
SEMVER_TAG_RE = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9_.-]+)?$")
MAJOR_TAG_RE = re.compile(r"^v?\d+$")
FLOATING_TAGS = {"latest", "stable", "release"}
MAIN_BRANCHES = {"main", "master", "refs/heads/main", "refs/heads/master"}
OTHER_BRANCHES = {
    "dev",
    "develop",
    "development",
    "next",
    "beta",
    "nightly",
    "canary",
    "edge",
    "preview",
    "alpha",
    "refs/heads/dev",
    "refs/heads/develop",
    "refs/heads/development",
    "refs/heads/next",
    "refs/heads/beta",
    "refs/heads/nightly",
    "refs/heads/canary",
    "refs/heads/edge",
    "refs/heads/preview",
    "refs/heads/alpha",
}

REF_CATEGORIES = (
    "FULL_SHA",
    "SHORT_SHA",
    "BRANCH_MAIN",
    "BRANCH_OTHER",
    "MAJOR_TAG",
    "SEMVER_TAG",
    "FLOATING_TAG",
    "UNKNOWN_REF",
)
DEPTH_BUCKETS = ("level_1", "level_2", "level_3_plus")
RISK_WEIGHTS = {
    "FULL_SHA": 0.0,
    "SHORT_SHA": 0.2,
    "SEMVER_TAG": 0.45,
    "MAJOR_TAG": 0.7,
    "BRANCH_MAIN": 0.95,
    "BRANCH_OTHER": 1.0,
    "FLOATING_TAG": 1.0,
    "UNKNOWN_REF": 0.85,
}
HIGH_RISK_CATEGORIES = {"BRANCH_MAIN", "BRANCH_OTHER", "FLOATING_TAG", "UNKNOWN_REF"}


def classify_ref_category(ref: str | None) -> str:
    if ref is None:
        return "UNKNOWN_REF"
    normalized = ref.strip()
    lowered = normalized.lower()
    if not normalized:
        return "UNKNOWN_REF"
    if FULL_SHA_RE.fullmatch(normalized):
        return "FULL_SHA"
    if SHORT_SHA_RE.fullmatch(normalized):
        return "SHORT_SHA"
    if lowered in MAIN_BRANCHES:
        return "BRANCH_MAIN"
    if lowered in OTHER_BRANCHES or lowered.startswith("refs/heads/"):
        return "BRANCH_OTHER"
    if lowered in FLOATING_TAGS:
        return "FLOATING_TAG"
    if SEMVER_TAG_RE.fullmatch(normalized):
        return "SEMVER_TAG"
    if MAJOR_TAG_RE.fullmatch(normalized):
        return "MAJOR_TAG"
    return "UNKNOWN_REF"


class RefRiskAnalyzer:
    def analyze(
        self,
        *,
        graph: CascadeGraph,
        blast_radius: list[BlastRadiusMetric],
        drift_events: list[DriftEvent],
    ) -> tuple[
        list[RefRiskByWorkflowMetric],
        RefRiskSummaryMetric,
        list[RefRiskByDepthMetric],
        list[RefRiskByActionMetric],
    ]:
        if not graph.edges:
            return [], RefRiskSummaryMetric(), [], []

        blast_index = {item.action_id: item for item in blast_radius}
        drift_index = self._build_drift_index(drift_events)
        action_rows = self._build_action_rows(graph, blast_index, drift_index)
        workflow_rows = self._build_workflow_rows(graph, blast_index, drift_index)
        depth_rows = self._build_depth_rows(graph, workflow_rows)
        summary = self._build_summary(graph, action_rows, workflow_rows)
        return workflow_rows, summary, depth_rows, action_rows

    def _build_action_rows(
        self,
        graph: CascadeGraph,
        blast_index: dict[str, BlastRadiusMetric],
        drift_index: dict[tuple[str, str], list[DriftEvent]],
    ) -> list[RefRiskByActionMetric]:
        action_usage: Counter[str] = Counter()
        action_workflows: dict[str, set[str]] = defaultdict(set)
        for edge in graph.edges:
            if not edge.consumer_repository or not edge.workflow_path:
                continue
            action_usage[edge.dst_node_id] += 1
            action_workflows[edge.dst_node_id].add(f"{edge.consumer_repository}::{edge.workflow_path}")

        rows: list[RefRiskByActionMetric] = []
        for action_id, action in sorted(graph.actions.items(), key=lambda item: (item[1].owner.lower(), item[1].repo.lower(), item[1].ref.lower())):
            category = classify_ref_category(action.ref)
            downstream_repo_count = len(self._collect_downstream_repositories(graph, action_id))
            blast = blast_index.get(action_id)
            drift_events = drift_index.get((action_id, action.ref.lower()), [])
            risk_weight = RISK_WEIGHTS[category]
            mutable = 0 if category == "FULL_SHA" else 1
            immutable = 1 - mutable
            high_risk = 1 if category in HIGH_RISK_CATEGORIES else 0
            affected_downstream = downstream_repo_count if drift_events else 0
            blast_score = (blast.downstream_repository_count if blast else downstream_repo_count) * risk_weight
            drift_amplification = affected_downstream * risk_weight * max(1, len(drift_events)) if drift_events else 0.0
            rows.append(
                RefRiskByActionMetric(
                    action_id=action_id,
                    owner=action.owner,
                    repo=action.repo,
                    full_name=f"{action.owner}/{action.repo}",
                    ref_name=action.ref,
                    ref_category=category,  # type: ignore[arg-type]
                    usage_count=action_usage.get(action_id, 0),
                    workflow_count=len(action_workflows.get(action_id, set())),
                    downstream_repo_count=downstream_repo_count,
                    mutable_ref_count=mutable,
                    immutable_ref_count=immutable,
                    branch_ref_count=1 if category.startswith("BRANCH_") else 0,
                    tag_ref_count=1 if "TAG" in category else 0,
                    sha_ref_count=1 if "SHA" in category else 0,
                    mutable_ref_ratio=float(mutable),
                    high_risk_ref_ratio=float(high_risk),
                    observed_drift=bool(drift_events),
                    observed_drift_event_count=len(drift_events),
                    affected_downstream_repositories=affected_downstream,
                    blast_radius_weighted_mutability_score=round(blast_score, 4),
                    drift_amplification_score=round(drift_amplification, 4),
                )
            )
        rows.sort(
            key=lambda item: (
                item.blast_radius_weighted_mutability_score,
                item.downstream_repo_count,
                item.usage_count,
                item.full_name.lower(),
            ),
            reverse=True,
        )
        return rows

    def _build_workflow_rows(
        self,
        graph: CascadeGraph,
        blast_index: dict[str, BlastRadiusMetric],
        drift_index: dict[tuple[str, str], list[DriftEvent]],
    ) -> list[RefRiskByWorkflowMetric]:
        rows: list[RefRiskByWorkflowMetric] = []
        edges_by_workflow: dict[str, list] = defaultdict(list)
        for edge in graph.edges:
            if edge.consumer_repository and edge.workflow_path:
                workflow_id = f"workflow::{edge.consumer_repository}::{edge.workflow_path}"
                edges_by_workflow[workflow_id].append(edge)

        for workflow_id in sorted(graph.workflow_nodes):
            _, repository_full_name, workflow_path = workflow_id.split("::", 2)
            edges = edges_by_workflow.get(workflow_id, [])
            category_counts = Counter()
            max_depth = 0
            downstream_repositories: set[str] = set()
            drifted_action_refs: set[tuple[str, str]] = set()
            blast_score = 0.0
            drift_score = 0.0

            for edge in edges:
                action = graph.actions.get(edge.dst_node_id)
                if action is None:
                    continue
                category = classify_ref_category(edge.ref_string or action.ref)
                category_counts[category] += 1
                max_depth = max(max_depth, edge.depth)
                downstream_set = self._collect_downstream_repositories(graph, edge.dst_node_id)
                downstream_repositories.update(downstream_set)
                blast = blast_index.get(edge.dst_node_id)
                risk_weight = RISK_WEIGHTS[category]
                blast_score += (blast.downstream_repository_count if blast else len(downstream_set)) * risk_weight
                if drift_index.get((edge.dst_node_id, (edge.ref_string or action.ref).lower())):
                    drifted_action_refs.add((edge.dst_node_id, (edge.ref_string or action.ref).lower()))
                    drift_score += len(downstream_set) * risk_weight

            total_refs = sum(category_counts.values())
            mutable_count = total_refs - category_counts["FULL_SHA"]
            high_risk_count = sum(category_counts[name] for name in HIGH_RISK_CATEGORIES)
            rows.append(
                RefRiskByWorkflowMetric(
                    workflow_name=graph.workflow_names.get(workflow_id, workflow_path),
                    repository_full_name=repository_full_name,
                    workflow_path=workflow_path,
                    max_depth=max_depth,
                    total_ref_count=total_refs,
                    full_sha_count=category_counts["FULL_SHA"],
                    short_sha_count=category_counts["SHORT_SHA"],
                    branch_main_count=category_counts["BRANCH_MAIN"],
                    branch_other_count=category_counts["BRANCH_OTHER"],
                    major_tag_count=category_counts["MAJOR_TAG"],
                    semver_tag_count=category_counts["SEMVER_TAG"],
                    floating_tag_count=category_counts["FLOATING_TAG"],
                    unknown_ref_count=category_counts["UNKNOWN_REF"],
                    mutable_ref_count=mutable_count,
                    immutable_ref_count=category_counts["FULL_SHA"],
                    branch_ref_count=category_counts["BRANCH_MAIN"] + category_counts["BRANCH_OTHER"],
                    tag_ref_count=category_counts["MAJOR_TAG"] + category_counts["SEMVER_TAG"] + category_counts["FLOATING_TAG"],
                    sha_ref_count=category_counts["FULL_SHA"] + category_counts["SHORT_SHA"],
                    mutable_ref_ratio=(mutable_count / total_refs) if total_refs else 0.0,
                    high_risk_ref_ratio=(high_risk_count / total_refs) if total_refs else 0.0,
                    downstream_repo_count=len(downstream_repositories),
                    blast_radius_weighted_mutability_score=round(blast_score, 4),
                    observed_drift=bool(drifted_action_refs),
                    observed_drift_ref_count=len(drifted_action_refs),
                    affected_downstream_repositories=len(downstream_repositories) if drifted_action_refs else 0,
                    drift_amplification_score=round(drift_score, 4),
                )
            )
        return rows

    def _build_depth_rows(
        self,
        graph: CascadeGraph,
        workflow_rows: list[RefRiskByWorkflowMetric],
    ) -> list[RefRiskByDepthMetric]:
        workflow_count_by_bucket = Counter()
        for item in workflow_rows:
            workflow_count_by_bucket[self._depth_bucket(item.max_depth)] += 1

        aggregates: dict[str, Counter] = {bucket: Counter() for bucket in DEPTH_BUCKETS}
        totals: dict[str, dict[str, float]] = {
            bucket: {
                "blast_score": 0.0,
                "drift_score": 0.0,
                "affected_downstream_repositories": 0.0,
            }
            for bucket in DEPTH_BUCKETS
        }

        for edge in graph.edges:
            if not edge.consumer_repository or not edge.workflow_path:
                continue
            workflow_id = f"workflow::{edge.consumer_repository}::{edge.workflow_path}"
            action = graph.actions.get(edge.dst_node_id)
            if action is None:
                continue
            category = classify_ref_category(edge.ref_string or action.ref)
            bucket = self._depth_bucket(edge.depth)
            aggregates[bucket][category] += 1

        for item in workflow_rows:
            bucket = self._depth_bucket(item.max_depth)
            totals[bucket]["blast_score"] += item.blast_radius_weighted_mutability_score
            totals[bucket]["drift_score"] += item.drift_amplification_score
            totals[bucket]["affected_downstream_repositories"] += item.affected_downstream_repositories

        rows: list[RefRiskByDepthMetric] = []
        for bucket in DEPTH_BUCKETS:
            counts = aggregates[bucket]
            total_refs = sum(counts.values())
            mutable_count = total_refs - counts["FULL_SHA"]
            high_risk_count = sum(counts[name] for name in HIGH_RISK_CATEGORIES)
            rows.append(
                RefRiskByDepthMetric(
                    depth_bucket=bucket,  # type: ignore[arg-type]
                    workflow_count=workflow_count_by_bucket[bucket],
                    total_ref_count=total_refs,
                    full_sha_count=counts["FULL_SHA"],
                    short_sha_count=counts["SHORT_SHA"],
                    branch_main_count=counts["BRANCH_MAIN"],
                    branch_other_count=counts["BRANCH_OTHER"],
                    major_tag_count=counts["MAJOR_TAG"],
                    semver_tag_count=counts["SEMVER_TAG"],
                    floating_tag_count=counts["FLOATING_TAG"],
                    unknown_ref_count=counts["UNKNOWN_REF"],
                    mutable_ref_count=mutable_count,
                    immutable_ref_count=counts["FULL_SHA"],
                    branch_ref_count=counts["BRANCH_MAIN"] + counts["BRANCH_OTHER"],
                    tag_ref_count=counts["MAJOR_TAG"] + counts["SEMVER_TAG"] + counts["FLOATING_TAG"],
                    sha_ref_count=counts["FULL_SHA"] + counts["SHORT_SHA"],
                    mutable_ref_ratio=(mutable_count / total_refs) if total_refs else 0.0,
                    high_risk_ref_ratio=(high_risk_count / total_refs) if total_refs else 0.0,
                    observed_drift_ref_count=sum(item.observed_drift_ref_count for item in workflow_rows if self._depth_bucket(item.max_depth) == bucket),
                    affected_downstream_repositories=int(totals[bucket]["affected_downstream_repositories"]),
                    blast_radius_weighted_mutability_score=round(totals[bucket]["blast_score"], 4),
                    drift_amplification_score=round(totals[bucket]["drift_score"], 4),
                )
            )
        return rows

    def _build_summary(
        self,
        graph: CascadeGraph,
        action_rows: list[RefRiskByActionMetric],
        workflow_rows: list[RefRiskByWorkflowMetric],
    ) -> RefRiskSummaryMetric:
        counts = Counter()
        for item in action_rows:
            counts[item.ref_category] += 1
        total_actions = len(action_rows)
        total_refs = sum(item.total_ref_count for item in workflow_rows)
        mutable_count = sum(item.mutable_ref_count for item in workflow_rows)
        high_risk_count = sum(
            item.branch_main_count + item.branch_other_count + item.floating_tag_count + item.unknown_ref_count
            for item in workflow_rows
        )
        return RefRiskSummaryMetric(
            total_workflows=len(workflow_rows),
            total_actions=total_actions,
            total_ref_count=total_refs,
            full_sha_count=counts["FULL_SHA"],
            short_sha_count=counts["SHORT_SHA"],
            branch_main_count=counts["BRANCH_MAIN"],
            branch_other_count=counts["BRANCH_OTHER"],
            major_tag_count=counts["MAJOR_TAG"],
            semver_tag_count=counts["SEMVER_TAG"],
            floating_tag_count=counts["FLOATING_TAG"],
            unknown_ref_count=counts["UNKNOWN_REF"],
            mutable_ref_count=mutable_count,
            immutable_ref_count=sum(item.immutable_ref_count for item in workflow_rows),
            branch_ref_count=sum(item.branch_ref_count for item in workflow_rows),
            tag_ref_count=sum(item.tag_ref_count for item in workflow_rows),
            sha_ref_count=sum(item.sha_ref_count for item in workflow_rows),
            mutable_ref_ratio=(mutable_count / total_refs) if total_refs else 0.0,
            high_risk_ref_ratio=(high_risk_count / total_refs) if total_refs else 0.0,
            observed_drift_ref_count=sum(item.observed_drift_ref_count for item in workflow_rows),
            observed_drift_action_count=sum(1 for item in action_rows if item.observed_drift),
            affected_downstream_repositories=len(
                {
                    repo_name
                    for action_id in graph.actions
                    for repo_name in self._collect_downstream_repositories(graph, action_id)
                }
            ),
            blast_radius_weighted_mutability_score=round(
                sum(item.blast_radius_weighted_mutability_score for item in action_rows),
                4,
            ),
            drift_amplification_score=round(sum(item.drift_amplification_score for item in action_rows), 4),
        )

    def _build_drift_index(self, drift_events: list[DriftEvent]) -> dict[tuple[str, str], list[DriftEvent]]:
        index: dict[tuple[str, str], list[DriftEvent]] = defaultdict(list)
        for event in drift_events:
            index[(event.action_id, event.tag_name.lower())].append(event)
        return index

    def _collect_downstream_repositories(self, graph: CascadeGraph, action_id: str) -> set[str]:
        repositories: set[str] = set()
        queue = [action_id]
        visited = {action_id}
        while queue:
            node_id = queue.pop(0)
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

    def _depth_bucket(self, depth: int) -> str:
        if depth <= 1:
            return "level_1"
        if depth == 2:
            return "level_2"
        return "level_3_plus"
