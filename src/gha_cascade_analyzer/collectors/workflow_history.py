from __future__ import annotations

import asyncio
from datetime import datetime

from gha_cascade_analyzer.models import Repository, WorkflowFile, WorkflowUseChange
from gha_cascade_analyzer.utils.parsing import extract_uses_references


class WorkflowHistoryCollector:
    def __init__(
        self,
        github_client: object,
        git_bin: str = "git",
        max_history_commits_per_workflow: int = 50,
        history_fetch_concurrency: int = 5,
    ) -> None:
        self.github_client = github_client
        self.git_bin = git_bin
        self.max_history_commits_per_workflow = max_history_commits_per_workflow
        self.history_fetch_concurrency = history_fetch_concurrency

    async def collect_uses_changes(self, repository: Repository, workflow_file: WorkflowFile) -> list[WorkflowUseChange]:
        commits = await self._fetch_all_commits(repository.full_name, workflow_file.path)
        if not commits:
            return []

        capped_commits = commits[: self.max_history_commits_per_workflow]
        ordered_commits = list(reversed(capped_commits))
        revisions = await self._fetch_revisions_bounded(repository.full_name, workflow_file.path, ordered_commits)

        changes: list[WorkflowUseChange] = []
        previous_uses: list[str] = []
        for commit, content in zip(ordered_commits, revisions, strict=True):
            if isinstance(content, Exception):
                continue
            current_uses = extract_uses_references(content)
            if current_uses == previous_uses:
                continue
            introduced = sorted(set(current_uses) - set(previous_uses))
            removed = sorted(set(previous_uses) - set(current_uses))
            changes.append(
                WorkflowUseChange(
                    repository_full_name=repository.full_name,
                    workflow_path=workflow_file.path,
                    commit_sha=commit["sha"],
                    committed_at=commit["commit"]["committer"]["date"],
                    uses_before=previous_uses,
                    uses_after=current_uses,
                    introduced=introduced,
                    removed=removed,
                )
            )
            previous_uses = current_uses
        return changes

    async def _fetch_revisions_bounded(self, repository_full_name: str, workflow_path: str, commits: list[dict]) -> list[str | Exception]:
        semaphore = asyncio.Semaphore(self.history_fetch_concurrency)

        async def worker(commit: dict) -> str:
            async with semaphore:
                return await self._fetch_revision_content(repository_full_name, workflow_path, commit["sha"])

        return await asyncio.gather(*(worker(commit) for commit in commits), return_exceptions=True)

    async def _fetch_all_commits(self, repository_full_name: str, workflow_path: str) -> list[dict]:
        commits_url = f"https://api.github.com/repos/{repository_full_name}/commits"
        page = 1
        commits: list[dict] = []
        while True:
            payload = await self.github_client.get_json(
                commits_url,
                params={"path": workflow_path, "per_page": 100, "page": page},
            )
            if not payload:
                break
            commits.extend(payload)
            if len(commits) >= self.max_history_commits_per_workflow:
                return commits[: self.max_history_commits_per_workflow]
            if len(payload) < 100:
                break
            page += 1
        return commits

    async def _fetch_revision_content(self, repository_full_name: str, workflow_path: str, commit_sha: str) -> str:
        file_url = f"https://api.github.com/repos/{repository_full_name}/contents/{workflow_path}"
        return await self.github_client.get_text(file_url, params={"ref": commit_sha})
