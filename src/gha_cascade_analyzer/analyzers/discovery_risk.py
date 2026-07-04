from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field

from gha_cascade_analyzer.analyzers.graph_types import CascadeGraph
from gha_cascade_analyzer.enums import RefType, VerificationStatus
from gha_cascade_analyzer.models import (
    DiscoveryRiskCandidateMetric,
    DiscoveryRiskSummaryMetric,
    MarketplaceActionIdentity,
    RepositoryIdentityObservation,
    WorkflowFile,
    WorkflowUseChange,
)
from gha_cascade_analyzer.utils.parsing import classify_ref, extract_uses_references, parse_action_reference


CANONICAL_ACTION_HINTS = (
    "actions/checkout",
    "actions/setup-node",
    "actions/upload-artifact",
    "actions/download-artifact",
    "actions/cache",
    "actions/setup-python",
    "docker/login-action",
    "github/codeql-action",
)


@dataclass
class _ReferenceAggregate:
    owner: str
    repo: str
    full_name: str
    usage_count: int = 0
    downstream_repositories: set[str] = field(default_factory=set)
    downstream_workflows: set[str] = field(default_factory=set)
    ref_types: list[RefType] = field(default_factory=list)
    verification_states: set[VerificationStatus] = field(default_factory=set)
    marketplace_verified: bool | None = None
    star_count: int | None = None
    is_archived: bool | None = None
    unresolved_signal: str | None = None
    redirection_signal: str | None = None


class DiscoveryRiskAnalyzer:
    def __init__(self, canonical_top_n: int = 20) -> None:
        self.canonical_top_n = canonical_top_n

    def analyze(
        self,
        graph: CascadeGraph,
        workflows: list[WorkflowFile],
        workflow_changes: list[WorkflowUseChange],
        identity_observations: list[RepositoryIdentityObservation],
        marketplace_identities: list[MarketplaceActionIdentity],
    ) -> tuple[list[DiscoveryRiskCandidateMetric], DiscoveryRiskSummaryMetric]:
        aggregates = self._collect_reference_aggregates(graph, workflows, workflow_changes)
        if not aggregates:
            return [], DiscoveryRiskSummaryMetric()

        marketplace_index = {
            (item.owner.lower(), item.repository.lower()): item
            for item in marketplace_identities
            if item.owner and item.repository
        }
        identity_index = self._latest_identity_index(identity_observations)

        for full_name, aggregate in aggregates.items():
            owner_key, repo_key = aggregate.owner.lower(), aggregate.repo.lower()
            identity = identity_index.get(full_name.lower())
            marketplace = marketplace_index.get((owner_key, repo_key))
            if marketplace is not None:
                aggregate.marketplace_verified = bool(marketplace.verified_creator)
            elif aggregate.marketplace_verified is None:
                aggregate.marketplace_verified = None

            if identity is not None:
                if identity.star_count is not None:
                    aggregate.star_count = identity.star_count
                if identity.is_archived is not None:
                    aggregate.is_archived = identity.is_archived
                if identity.identity_status == "redirected" and identity.resolved_full_name:
                    aggregate.redirection_signal = f"redirected_to:{identity.resolved_full_name}"
                elif identity.identity_status == "missing":
                    aggregate.unresolved_signal = "unresolved_or_orphaned_candidate"
                elif identity.identity_status == "inaccessible":
                    aggregate.unresolved_signal = "inaccessible_repository_candidate"

        canonical_actions = self._select_canonical_actions(aggregates)
        candidates = [
            self._build_candidate_metric(aggregate, canonical_actions)
            for aggregate in sorted(aggregates.values(), key=lambda item: item.full_name.lower())
        ]
        candidates.sort(
            key=lambda item: (
                item.discovery_risk_score,
                item.downstream_repo_count,
                item.usage_count,
                item.full_name.lower(),
            ),
            reverse=True,
        )
        summary = self._build_summary(candidates, aggregates)
        return candidates, summary

    def _collect_reference_aggregates(
        self,
        graph: CascadeGraph,
        workflows: list[WorkflowFile],
        workflow_changes: list[WorkflowUseChange],
    ) -> dict[str, _ReferenceAggregate]:
        aggregates: dict[str, _ReferenceAggregate] = {}

        def ensure(owner: str, repo: str) -> _ReferenceAggregate:
            full_name = f"{owner}/{repo}"
            aggregate = aggregates.get(full_name.lower())
            if aggregate is None:
                aggregate = _ReferenceAggregate(owner=owner, repo=repo, full_name=full_name)
                aggregates[full_name.lower()] = aggregate
            return aggregate

        for action in graph.actions.values():
            aggregate = ensure(action.owner, action.repo)
            aggregate.ref_types.append(action.ref_type)
            aggregate.verification_states.add(action.author_verified)
            if action.marketplace_published and aggregate.marketplace_verified is None:
                if action.author_verified == VerificationStatus.VERIFIED:
                    aggregate.marketplace_verified = True
                elif action.author_verified == VerificationStatus.UNVERIFIED:
                    aggregate.marketplace_verified = False

        for workflow in workflows:
            workflow_key = f"{workflow.repository_full_name}::{workflow.path}"
            for uses_value in extract_uses_references(workflow.content or ""):
                owner, repo, _, ref = parse_action_reference(uses_value)
                aggregate = ensure(owner, repo)
                aggregate.usage_count += 1
                aggregate.downstream_repositories.add(workflow.repository_full_name)
                aggregate.downstream_workflows.add(workflow_key)
                aggregate.ref_types.append(classify_ref(ref))

        for change in workflow_changes:
            workflow_key = f"{change.repository_full_name}::{change.workflow_path}"
            references = set(change.uses_before) | set(change.uses_after)
            for uses_value in references:
                owner, repo, _, ref = parse_action_reference(uses_value)
                aggregate = ensure(owner, repo)
                aggregate.usage_count += 1
                aggregate.downstream_repositories.add(change.repository_full_name)
                aggregate.downstream_workflows.add(workflow_key)
                aggregate.ref_types.append(classify_ref(ref))

        for edge in graph.edges:
            if edge.src_kind != "workflow" or edge.consumer_repository is None or edge.workflow_path is None:
                continue
            action = graph.actions.get(edge.dst_node_id)
            if action is None:
                continue
            aggregate = ensure(action.owner, action.repo)
            aggregate.downstream_repositories.add(edge.consumer_repository)
            aggregate.downstream_workflows.add(f"{edge.consumer_repository}::{edge.workflow_path}")
            aggregate.ref_types.append(edge.ref_type)

        return aggregates

    def _latest_identity_index(
        self,
        identity_observations: list[RepositoryIdentityObservation],
    ) -> dict[str, RepositoryIdentityObservation]:
        latest: dict[str, RepositoryIdentityObservation] = {}
        for item in identity_observations:
            key = item.referenced_full_name.lower()
            current = latest.get(key)
            if current is None or item.observed_at >= current.observed_at:
                latest[key] = item
        return latest

    def _select_canonical_actions(
        self,
        aggregates: dict[str, _ReferenceAggregate],
    ) -> list[_ReferenceAggregate]:
        by_score = sorted(
            aggregates.values(),
            key=lambda item: (
                item.usage_count,
                len(item.downstream_repositories),
                item.marketplace_verified is True,
                item.full_name.lower(),
            ),
            reverse=True,
        )
        canonical: dict[str, _ReferenceAggregate] = {}
        for full_name in CANONICAL_ACTION_HINTS:
            aggregate = aggregates.get(full_name.lower())
            if aggregate is not None:
                canonical[aggregate.full_name.lower()] = aggregate
        for aggregate in by_score:
            if (
                aggregate.usage_count <= 1
                and len(aggregate.downstream_repositories) <= 1
                and aggregate.marketplace_verified is not True
            ):
                continue
            canonical.setdefault(aggregate.full_name.lower(), aggregate)
            if len(canonical) >= self.canonical_top_n:
                break
        return list(canonical.values())

    def _build_candidate_metric(
        self,
        aggregate: _ReferenceAggregate,
        canonical_actions: list[_ReferenceAggregate],
    ) -> DiscoveryRiskCandidateMetric:
        normalized_name = self._normalize_name(aggregate.full_name)
        best_match_name: str | None = None
        best_distance: int | None = None
        best_confusion_score = 0.0
        reasons: list[str] = []

        if aggregate.full_name.lower() not in {item.full_name.lower() for item in canonical_actions}:
            best_match_name, best_distance, best_confusion_score, reasons = self._evaluate_confusion_candidate(
                aggregate,
                canonical_actions,
            )

        if aggregate.redirection_signal:
            reasons.append("redirection_or_transfer_signal")
        if aggregate.unresolved_signal:
            reasons.append(aggregate.unresolved_signal)
        if aggregate.is_archived:
            reasons.append("archived_repository_candidate")

        discovery_risk_score = min(
            100.0,
            best_confusion_score * 60.0
            + (35.0 if aggregate.redirection_signal else 0.0)
            + (45.0 if aggregate.unresolved_signal else 0.0)
            + (10.0 if aggregate.is_archived else 0.0)
            + (5.0 if aggregate.marketplace_verified is False else 0.0)
            + min(aggregate.usage_count, 20) * 0.5
            + min(len(aggregate.downstream_repositories), 20) * 0.5,
        )

        candidate_type = "none"
        if aggregate.unresolved_signal:
            candidate_type = "unresolved_candidate"
        elif aggregate.redirection_signal:
            candidate_type = "redirection_candidate"
        elif best_match_name and best_distance is not None and best_distance <= 2:
            candidate_type = "potential_typosquat"
        elif best_match_name and best_confusion_score >= 0.55:
            candidate_type = "potential_brand_confusion"

        return DiscoveryRiskCandidateMetric(
            normalized_name=normalized_name,
            owner=aggregate.owner,
            repo=aggregate.repo,
            full_name=aggregate.full_name,
            usage_count=aggregate.usage_count,
            downstream_repo_count=len(aggregate.downstream_repositories),
            star_count=aggregate.star_count,
            marketplace_verified=aggregate.marketplace_verified,
            is_archived=aggregate.is_archived,
            is_deleted_or_unresolved=aggregate.unresolved_signal is not None,
            possible_typosquat_of=best_match_name,
            edit_distance_to_popular_action=best_distance,
            brand_confusion_score=round(best_confusion_score, 4),
            redirection_or_transfer_signal=aggregate.redirection_signal or aggregate.unresolved_signal,
            discovery_risk_score=round(discovery_risk_score, 4),
            candidate_reasons=sorted(set(reasons)),
            candidate_type=candidate_type,  # type: ignore[arg-type]
        )

    def _evaluate_confusion_candidate(
        self,
        aggregate: _ReferenceAggregate,
        canonical_actions: list[_ReferenceAggregate],
    ) -> tuple[str | None, int | None, float, list[str]]:
        candidate_owner = self._normalize_name(aggregate.owner)
        candidate_repo = self._normalize_name(aggregate.repo)
        candidate_full = self._normalize_name(aggregate.full_name)

        best_name: str | None = None
        best_distance: int | None = None
        best_score = 0.0
        best_reasons: list[str] = []

        for canonical in canonical_actions:
            if canonical.full_name.lower() == aggregate.full_name.lower():
                continue
            canonical_owner = self._normalize_name(canonical.owner)
            canonical_repo = self._normalize_name(canonical.repo)
            canonical_full = self._normalize_name(canonical.full_name)

            owner_distance = self._levenshtein(candidate_owner, canonical_owner)
            repo_distance = self._levenshtein(candidate_repo, canonical_repo)
            full_distance = self._levenshtein(candidate_full, canonical_full)
            score = 0.0
            reasons: list[str] = []

            if aggregate.owner.lower() == canonical.owner.lower() and repo_distance <= 2 and aggregate.repo.lower() != canonical.repo.lower():
                score = max(score, 0.82 - min(repo_distance, 2) * 0.08)
                reasons.append("similar_repo_under_same_owner")
            if aggregate.repo.lower() == canonical.repo.lower() and owner_distance <= 2 and aggregate.owner.lower() != canonical.owner.lower():
                score = max(score, 0.78 - min(owner_distance, 2) * 0.08)
                reasons.append("similar_owner_for_same_repo")
            if candidate_repo == canonical_repo and candidate_owner != canonical_owner and owner_distance <= 1:
                score = max(score, 0.88)
                reasons.append("normalized_repo_match_with_owner_variation")
            if candidate_owner == canonical_owner and candidate_repo == canonical_repo:
                score = max(score, 0.9)
                reasons.append("separator_or_punctuation_variant")
            if self._prefix_confusion(candidate_repo, canonical_repo) and candidate_owner == canonical_owner:
                score = max(score, 0.7)
                reasons.append("repo_prefix_or_suffix_confusion")
            if full_distance <= 2:
                score = max(score, 0.68 - min(full_distance, 2) * 0.06)
                reasons.append("small_full_name_edit_distance")

            if best_distance is None or full_distance < best_distance or (full_distance == best_distance and score > best_score):
                best_name = canonical.full_name
                best_distance = full_distance
                best_score = score
                best_reasons = reasons

        return best_name, best_distance, best_score, best_reasons

    def _build_summary(
        self,
        candidates: list[DiscoveryRiskCandidateMetric],
        aggregates: dict[str, _ReferenceAggregate],
    ) -> DiscoveryRiskSummaryMetric:
        typosquat_candidates = [item for item in candidates if item.candidate_type in {"potential_typosquat", "potential_brand_confusion"}]
        redirection_candidates = [item for item in candidates if item.candidate_type == "redirection_candidate"]
        unresolved_candidates = [item for item in candidates if item.candidate_type == "unresolved_candidate"]
        risky_names = {
            item.full_name.lower()
            for item in candidates
            if item.candidate_type != "none"
        }
        affected_workflows = set()
        affected_repositories = set()
        for full_name in risky_names:
            aggregate = aggregates.get(full_name.lower())
            if aggregate is None:
                continue
            affected_workflows.update(aggregate.downstream_workflows)
            affected_repositories.update(aggregate.downstream_repositories)

        top_candidates = [
            {
                "full_name": item.full_name,
                "score": item.discovery_risk_score,
                "candidate_type": item.candidate_type,
            }
            for item in candidates[:20]
            if item.discovery_risk_score > 0.0 and item.candidate_type != "none"
        ]
        return DiscoveryRiskSummaryMetric(
            total_actions=len(candidates),
            typosquat_candidates=len(typosquat_candidates),
            redirection_candidates=len(redirection_candidates),
            unresolved_candidates=len(unresolved_candidates),
            affected_workflows=len(affected_workflows),
            affected_repositories=len(affected_repositories),
            top_20_candidates_by_risk_score=json.dumps(top_candidates, ensure_ascii=True),
        )

    def _normalize_name(self, value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "", value.lower())

    def _prefix_confusion(self, candidate_repo: str, canonical_repo: str) -> bool:
        return (
            candidate_repo.startswith(canonical_repo)
            or canonical_repo.startswith(candidate_repo)
            or candidate_repo.endswith(canonical_repo)
            or canonical_repo.endswith(candidate_repo)
        )

    def _levenshtein(self, left: str, right: str) -> int:
        if left == right:
            return 0
        if not left:
            return len(right)
        if not right:
            return len(left)

        previous = list(range(len(right) + 1))
        for i, left_char in enumerate(left, start=1):
            current = [i]
            for j, right_char in enumerate(right, start=1):
                insert_cost = current[j - 1] + 1
                delete_cost = previous[j] + 1
                replace_cost = previous[j - 1] + (0 if left_char == right_char else 1)
                current.append(min(insert_cost, delete_cost, replace_cost))
            previous = current
        return previous[-1]
