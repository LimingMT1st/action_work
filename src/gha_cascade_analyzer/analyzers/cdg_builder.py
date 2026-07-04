from __future__ import annotations

from collections import defaultdict

from gha_cascade_analyzer.analyzers.action_content_resolver import ActionContentResolver
from gha_cascade_analyzer.analyzers.composite_parser import ParsedDependencyReference, parse_workflow_definition
from gha_cascade_analyzer.analyzers.graph_types import CascadeGraph
from gha_cascade_analyzer.enums import ActionType, EdgeType, RefType, VerificationStatus
from gha_cascade_analyzer.logging import log_event
from gha_cascade_analyzer.models import ActionNode, CDGEdge, MarketplaceActionIdentity, Repository, WorkflowFile
from gha_cascade_analyzer.utils.parsing import classify_ref, parse_action_reference, stable_id
from gha_cascade_analyzer.utils.time import utc_now


class RecursiveCDGBuilder:
    def __init__(
        self,
        *,
        action_resolver: ActionContentResolver | None = None,
        marketplace_identities: list[MarketplaceActionIdentity] | None = None,
        max_depth: int = 6,
        progress_report_interval: int = 25,
    ) -> None:
        self.action_resolver = action_resolver or ActionContentResolver()
        self.marketplace_index = self._index_marketplace(marketplace_identities or [])
        self.max_depth = max_depth
        self.progress_report_interval = progress_report_interval
        self._expanded_action_cache: dict[str, list[ParsedDependencyReference]] = {}
        self._workflows_processed = 0

    def _index_marketplace(self, identities: list[MarketplaceActionIdentity]) -> dict[tuple[str, str], MarketplaceActionIdentity]:
        index: dict[tuple[str, str], MarketplaceActionIdentity] = {}
        for identity in identities:
            if identity.owner and identity.repository:
                index[(identity.owner.lower(), identity.repository.lower())] = identity
        return index

    async def build(self, repositories: list[Repository], workflows: list[WorkflowFile]) -> CascadeGraph:
        graph = CascadeGraph(repositories={repo.full_name: repo for repo in repositories})
        workflow_groups: dict[str, list[WorkflowFile]] = defaultdict(list)
        for workflow in workflows:
            workflow_groups[workflow.repository_full_name].append(workflow)

        total_workflows = sum(len(workflow_groups.get(repository.full_name, [])) for repository in repositories)
        for repository in repositories:
            for workflow in workflow_groups.get(repository.full_name, []):
                await self._expand_workflow(graph, repository, workflow)
                self._workflows_processed += 1
                if self._workflows_processed <= 3 or self._workflows_processed % self.progress_report_interval == 0:
                    log_event(
                        f"Recursive CDG progress: workflows_processed={self._workflows_processed}/{total_workflows}, "
                        f"unique_actions={len(graph.actions)}, edges={len(graph.edges)}"
                    )
        return graph

    async def _expand_workflow(self, graph: CascadeGraph, repository: Repository, workflow: WorkflowFile) -> None:
        workflow_node_id = f"workflow::{repository.full_name}::{workflow.path}"
        graph.workflow_nodes.add(workflow_node_id)
        workflow_definition = parse_workflow_definition(workflow.content or "")
        graph.workflow_names[workflow_node_id] = workflow_definition.workflow_name or workflow.path
        graph.workflow_permissions[workflow_node_id] = workflow_definition.declared_permissions
        graph.workflow_has_write_permissions[workflow_node_id] = workflow_definition.has_write_permissions
        for dependency in workflow_definition.nested_dependencies:
            action_node = self._make_action_node(dependency.uses_value)
            graph.actions.setdefault(action_node.action_id, action_node)
            self._add_edge(
                graph,
                src_node_id=workflow_node_id,
                dst_node_id=action_node.action_id,
                src_kind="workflow",
                dst_kind="action",
                edge_type=EdgeType.DIRECT.value,
                ref_type=action_node.ref_type,
                ref_string=dependency.ref_string,
                is_dynamic_ref=dependency.is_dynamic_ref,
                binding_downgrade=False,
                workflow_path=workflow.path,
                consumer_repository=repository.full_name,
                depth=1,
            )
            await self._expand_action_dependencies(graph, repository.full_name, action_node, workflow.path, 2, set())

    async def _expand_action_dependencies(
        self,
        graph: CascadeGraph,
        consumer_repository: str,
        action_node: ActionNode,
        workflow_path: str | None,
        depth: int,
        visited: set[str],
    ) -> None:
        if depth > self.max_depth:
            return
        visit_key = f"{action_node.owner}/{action_node.repo}/{action_node.subpath or ''}@{action_node.ref}"
        if visit_key in visited:
            return
        visited = set(visited)
        visited.add(visit_key)

        nested_refs = await self._resolve_nested_dependencies(action_node)
        if not nested_refs:
            return

        for nested_dependency in nested_refs:
            nested_node = self._make_action_node(nested_dependency.uses_value)
            graph.actions.setdefault(nested_node.action_id, nested_node)
            self._add_edge(
                graph,
                src_node_id=action_node.action_id,
                dst_node_id=nested_node.action_id,
                src_kind="action",
                dst_kind="action",
                edge_type=EdgeType.TRANSITIVE.value,
                ref_type=nested_node.ref_type,
                ref_string=nested_dependency.ref_string,
                is_dynamic_ref=nested_dependency.is_dynamic_ref,
                binding_downgrade=action_node.ref_type == RefType.SHA and nested_dependency.ref_type == RefType.TAG,
                workflow_path=workflow_path,
                consumer_repository=consumer_repository,
                depth=depth,
            )
            await self._expand_action_dependencies(
                graph,
                consumer_repository,
                nested_node,
                workflow_path,
                depth + 1,
                visited,
            )

    async def _resolve_nested_dependencies(self, action_node: ActionNode) -> list[ParsedDependencyReference]:
        if action_node.action_id in self._expanded_action_cache:
            return self._expanded_action_cache[action_node.action_id]

        if action_node.subpath and action_node.subpath.startswith(".github/workflows/"):
            resolved = await self.action_resolver.fetch_reusable_workflow(
                action_node.owner,
                action_node.repo,
                action_node.subpath,
                action_node.ref,
            )
            if resolved is None:
                if action_node.action_type == ActionType.UNKNOWN:
                    action_node.action_type = ActionType.REUSABLE_WORKFLOW
                self._expanded_action_cache[action_node.action_id] = []
                return []
            self._apply_resolved_action_metadata(action_node, resolved)
            self._expanded_action_cache[action_node.action_id] = resolved.nested_dependencies
            return resolved.nested_dependencies

        resolved = await self.action_resolver.fetch_action_definition(
            action_node.owner,
            action_node.repo,
            action_node.subpath,
            action_node.ref,
        )
        if resolved is None:
            self._expanded_action_cache[action_node.action_id] = []
            return []
        self._apply_resolved_action_metadata(action_node, resolved)
        if action_node.action_type not in {ActionType.COMPOSITE, ActionType.REUSABLE_WORKFLOW}:
            self._expanded_action_cache[action_node.action_id] = []
            return []
        self._expanded_action_cache[action_node.action_id] = resolved.nested_dependencies
        return resolved.nested_dependencies

    def _apply_resolved_action_metadata(self, action_node: ActionNode, resolved) -> None:
        action_node.action_type = resolved.action_type
        action_node.declared_permissions = resolved.declared_permissions
        action_node.has_token_access = resolved.has_token_access
        action_node.token_access_patterns = resolved.token_access_patterns
        action_node.audited_source_files = resolved.audited_source_files

    def _make_action_node(self, uses_value: str) -> ActionNode:
        owner, repo, subpath, ref = parse_action_reference(uses_value)
        action_id = stable_id(owner, repo, subpath or "", ref)
        marketplace = self.marketplace_index.get((owner.lower(), repo.lower()))
        action_type = ActionType.REUSABLE_WORKFLOW if subpath and subpath.startswith(".github/workflows/") else ActionType.UNKNOWN
        return ActionNode(
            action_id=action_id,
            owner=owner,
            repo=repo,
            subpath=subpath,
            action_name=f"{owner}/{repo}",
            action_type=action_type,
            ref=ref,
            ref_type=classify_ref(ref),
            author_verified=VerificationStatus.VERIFIED if marketplace and marketplace.verified_creator else VerificationStatus.UNVERIFIED if marketplace else VerificationStatus.UNKNOWN,
            marketplace_published=marketplace is not None,
            marketplace_category=marketplace.category if marketplace else None,
            discovered_at=utc_now(),
        )

    def _add_edge(
        self,
        graph: CascadeGraph,
        *,
        src_node_id: str,
        dst_node_id: str,
        src_kind: str,
        dst_kind: str,
        edge_type: str,
        ref_type,
        ref_string: str | None,
        is_dynamic_ref: bool,
        binding_downgrade: bool,
        workflow_path: str | None,
        consumer_repository: str | None,
        depth: int,
    ) -> None:
        edge_id = stable_id(src_node_id, dst_node_id, edge_type, workflow_path or "", consumer_repository or "", str(depth))
        if any(edge.edge_id == edge_id for edge in graph.edges):
            return
        graph.edges.append(
            CDGEdge(
                edge_id=edge_id,
                src_node_id=src_node_id,
                dst_node_id=dst_node_id,
                src_kind=src_kind,
                dst_kind=dst_kind,
                edge_type=edge_type,
                ref_type=ref_type,
                ref_string=ref_string,
                is_dynamic_ref=is_dynamic_ref,
                binding_downgrade=binding_downgrade,
                workflow_path=workflow_path,
                depth=depth,
                consumer_repository=consumer_repository,
                discovered_at=utc_now(),
            )
        )
        graph.adjacency.setdefault(src_node_id, set()).add(dst_node_id)
        graph.reverse_adjacency.setdefault(dst_node_id, set()).add(src_node_id)
