from __future__ import annotations

from dataclasses import dataclass, field

from gha_cascade_analyzer.models import ActionNode, CDGEdge, Repository


@dataclass
class CascadeGraph:
    repositories: dict[str, Repository] = field(default_factory=dict)
    actions: dict[str, ActionNode] = field(default_factory=dict)
    workflow_nodes: set[str] = field(default_factory=set)
    workflow_names: dict[str, str] = field(default_factory=dict)
    workflow_permissions: dict[str, dict[str, str]] = field(default_factory=dict)
    workflow_has_write_permissions: dict[str, bool] = field(default_factory=dict)
    edges: list[CDGEdge] = field(default_factory=list)
    adjacency: dict[str, set[str]] = field(default_factory=dict)
    reverse_adjacency: dict[str, set[str]] = field(default_factory=dict)
