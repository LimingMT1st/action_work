from __future__ import annotations

import asyncio
from collections.abc import Iterable

from gha_cascade_analyzer.collectors.github_client import GitHubClient
from gha_cascade_analyzer.models import ActionNode, RepositoryIdentityObservation
from gha_cascade_analyzer.utils.time import utc_now


class RepositoryIdentityTracker:
    def __init__(self, github_client: GitHubClient) -> None:
        self.github_client = github_client

    async def observe_action_repositories(
        self,
        action_nodes: Iterable[ActionNode],
        *,
        batch_size: int | None = None,
    ) -> list[RepositoryIdentityObservation]:
        unique_repositories = sorted({(node.owner, node.repo) for node in action_nodes})
        if not unique_repositories:
            return []

        effective_batch_size = max(
            1,
            batch_size or min(25, self.github_client.settings.max_concurrency),
        )
        observations: list[RepositoryIdentityObservation] = []
        for start in range(0, len(unique_repositories), effective_batch_size):
            chunk = unique_repositories[start : start + effective_batch_size]
            results = await asyncio.gather(
                *(self._observe_repository(owner, repo) for owner, repo in chunk),
                return_exceptions=True,
            )
            for (owner, repo), result in zip(chunk, results, strict=True):
                if isinstance(result, Exception):
                    observations.append(self._build_inaccessible_observation(owner, repo))
                    continue
                observations.append(result)
        return observations

    async def _observe_repository(self, owner: str, repo: str) -> RepositoryIdentityObservation:
        observed_at = utc_now()
        result = await self.github_client.get_repository_identity(owner, repo)
        payload = result.get("payload") or {}
        status_code = int(result["status_code"])
        resolved_full_name = payload.get("full_name") if isinstance(payload, dict) else None
        resolved_owner = None
        resolved_repo = None
        if isinstance(resolved_full_name, str) and "/" in resolved_full_name:
            resolved_owner, resolved_repo = resolved_full_name.split("/", 1)

        if status_code in {404, 410}:
            identity_status = "missing"
        elif not resolved_full_name:
            identity_status = "inaccessible"
        elif resolved_full_name.lower() != f"{owner}/{repo}".lower():
            identity_status = "redirected"
        else:
            identity_status = "canonical"

        repository_id = payload.get("id") if isinstance(payload, dict) else None
        star_count = payload.get("stargazers_count") if isinstance(payload, dict) else None
        is_archived = payload.get("archived") if isinstance(payload, dict) else None
        is_fork = payload.get("fork") if isinstance(payload, dict) else None
        return RepositoryIdentityObservation(
            referenced_owner=owner,
            referenced_repo=repo,
            referenced_full_name=f"{owner}/{repo}",
            resolved_owner=resolved_owner,
            resolved_repo=resolved_repo,
            resolved_full_name=resolved_full_name,
            repository_id=int(repository_id) if repository_id is not None else None,
            star_count=int(star_count) if star_count is not None else None,
            is_archived=bool(is_archived) if is_archived is not None else None,
            is_fork=bool(is_fork) if is_fork is not None else None,
            status_code=status_code,
            identity_status=identity_status,
            final_url=result.get("final_url"),
            observed_at=observed_at,
        )

    def _build_inaccessible_observation(self, owner: str, repo: str) -> RepositoryIdentityObservation:
        return RepositoryIdentityObservation(
            referenced_owner=owner,
            referenced_repo=repo,
            referenced_full_name=f"{owner}/{repo}",
            resolved_owner=None,
            resolved_repo=None,
            resolved_full_name=None,
            repository_id=None,
            star_count=None,
            is_archived=None,
            is_fork=None,
            status_code=0,
            identity_status="inaccessible",
            final_url=None,
            observed_at=utc_now(),
        )
