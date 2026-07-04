from __future__ import annotations

from collections import Counter, deque
from statistics import median

from gha_cascade_analyzer.analyzers.graph_types import CascadeGraph
from gha_cascade_analyzer.models import AmplificationByNodeMetric, AmplificationSummaryMetric, BlastRadiusMetric


class AmplificationMetricsAnalyzer:
    def analyze(
        self,
        *,
        graph: CascadeGraph,
        blast_radius: list[BlastRadiusMetric],
    ) -> tuple[list[AmplificationByNodeMetric], AmplificationSummaryMetric, list[AmplificationByNodeMetric]]:
        if not graph.actions and not graph.workflow_nodes:
            return [], AmplificationSummaryMetric(), []

        reachable_cache: dict[str, dict[str, int]] = {}
        metrics: list[AmplificationByNodeMetric] = []
        blast_index = {item.action_id: item for item in blast_radius}

        node_ids = list(graph.actions.keys()) + sorted(graph.workflow_nodes)
        for node_id in node_ids:
            reachable = self._reachable_distances(graph, node_id, reachable_cache)
            metric = self._build_node_metric(
                graph=graph,
                node_id=node_id,
                reachable=reachable,
                blast=blast_index.get(node_id),
            )
            metrics.append(metric)

        action_metrics = [item for item in metrics if item.node_kind == "action"]
        action_metrics.sort(
            key=lambda item: (
                item.cascade_radius,
                item.transitive_fanout,
                item.reachable_high_star_repository_count,
                item.node_id,
            ),
            reverse=True,
        )
        summary = self._build_summary(action_metrics)
        top_nodes = action_metrics[:100]
        return metrics, summary, top_nodes

    def _build_node_metric(
        self,
        *,
        graph: CascadeGraph,
        node_id: str,
        reachable: dict[str, int],
        blast: BlastRadiusMetric | None,
    ) -> AmplificationByNodeMetric:
        in_degree = len(graph.reverse_adjacency.get(node_id, set()))
        out_degree = len(graph.adjacency.get(node_id, set()))
        transitive_fanout = len(reachable)
        reachable_workflows = {item for item in reachable if item.startswith("workflow::")}
        reachable_repositories = {
            workflow_id.split("::", 2)[1]
            for workflow_id in reachable_workflows
        }
        reachable_high_star_repositories = {
            repo_name
            for repo_name in reachable_repositories
            if (graph.repositories.get(repo_name).stars if graph.repositories.get(repo_name) else 0) > 50
        }
        downstream_depths = list(reachable.values())
        max_downstream_depth = max(downstream_depths, default=0)
        average_downstream_depth = (sum(downstream_depths) / len(downstream_depths)) if downstream_depths else 0.0
        cascade_radius = max(
            len(reachable_workflows),
            len(reachable_repositories),
            blast.downstream_repository_count if blast else 0,
        )
        cascade_concentration_score = (
            len(reachable_high_star_repositories) / len(reachable_repositories)
            if reachable_repositories
            else 0.0
        )
        betweenness_like_score = float(in_degree * transitive_fanout)

        if node_id in graph.actions:
            action = graph.actions[node_id]
            return AmplificationByNodeMetric(
                node_id=node_id,
                node_kind="action",
                owner=action.owner,
                repo=action.repo,
                full_name=f"{action.owner}/{action.repo}",
                in_degree=in_degree,
                out_degree=out_degree,
                transitive_fanout=transitive_fanout,
                reachable_workflow_count=len(reachable_workflows),
                reachable_repository_count=len(reachable_repositories),
                reachable_high_star_repository_count=len(reachable_high_star_repositories),
                max_downstream_depth=max_downstream_depth,
                average_downstream_depth=round(average_downstream_depth, 4),
                betweenness_like_score=round(betweenness_like_score, 4),
                cascade_radius=cascade_radius,
                cascade_concentration_score=round(cascade_concentration_score, 4),
            )

        workflow_name = graph.workflow_names.get(node_id, node_id.split("::", 2)[-1] if node_id.startswith("workflow::") else node_id)
        return AmplificationByNodeMetric(
            node_id=node_id,
            node_kind="workflow",
            workflow_name=workflow_name,
            in_degree=in_degree,
            out_degree=out_degree,
            transitive_fanout=transitive_fanout,
            reachable_workflow_count=len(reachable_workflows),
            reachable_repository_count=len(reachable_repositories),
            reachable_high_star_repository_count=len(reachable_high_star_repositories),
            max_downstream_depth=max_downstream_depth,
            average_downstream_depth=round(average_downstream_depth, 4),
            betweenness_like_score=round(betweenness_like_score, 4),
            cascade_radius=cascade_radius,
            cascade_concentration_score=round(cascade_concentration_score, 4),
        )

    def _reachable_distances(
        self,
        graph: CascadeGraph,
        node_id: str,
        cache: dict[str, dict[str, int]],
    ) -> dict[str, int]:
        cached = cache.get(node_id)
        if cached is not None:
            return cached
        distances: dict[str, int] = {}
        queue = deque([(node_id, 0)])
        visited = {node_id}
        while queue:
            current, depth = queue.popleft()
            for downstream in graph.adjacency.get(current, set()):
                if downstream in visited:
                    continue
                visited.add(downstream)
                distances[downstream] = depth + 1
                queue.append((downstream, depth + 1))
        cache[node_id] = distances
        return distances

    def _build_summary(self, action_metrics: list[AmplificationByNodeMetric]) -> AmplificationSummaryMetric:
        if not action_metrics:
            return AmplificationSummaryMetric()
        coverage_counts = [
            item.reachable_repository_count if item.reachable_repository_count > 0 else item.transitive_fanout
            for item in action_metrics
        ]
        fanout_counts = [item.transitive_fanout for item in action_metrics]
        total_coverage = sum(coverage_counts) or 1
        sorted_coverage = sorted(coverage_counts, reverse=True)
        sorted_fanout = sorted(fanout_counts)
        return AmplificationSummaryMetric(
            total_action_nodes=len(action_metrics),
            total_nodes=len(action_metrics),
            top_1_action_coverage=sum(sorted_coverage[:1]) / total_coverage,
            top_10_action_coverage=sum(sorted_coverage[:10]) / total_coverage,
            top_100_action_coverage=sum(sorted_coverage[:100]) / total_coverage,
            gini_coefficient_of_action_usage=round(self._gini(sorted(coverage_counts)), 4),
            median_fanout=float(median(fanout_counts)) if fanout_counts else None,
            p95_fanout=self._percentile(sorted_fanout, 0.95),
            max_fanout=max(fanout_counts, default=0),
        )

    def _gini(self, values: list[int]) -> float:
        if not values:
            return 0.0
        n = len(values)
        total = sum(values)
        if total == 0:
            return 0.0
        weighted_sum = sum((index + 1) * value for index, value in enumerate(values))
        return (2 * weighted_sum) / (n * total) - (n + 1) / n

    def _percentile(self, values: list[int], quantile: float) -> float | None:
        if not values:
            return None
        index = max(0, min(len(values) - 1, int(round((len(values) - 1) * quantile))))
        return float(values[index])
