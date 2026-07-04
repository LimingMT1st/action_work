from __future__ import annotations

import asyncio

from gha_cascade_analyzer.models import Repository, WorkflowFile
from gha_cascade_analyzer.utils.time import utc_now


class WorkflowCollector:
    def __init__(self, github_client: object, max_workflows_per_repository: int = 20) -> None:
        self.github_client = github_client
        self.max_workflows_per_repository = max_workflows_per_repository

    async def collect_repository_workflows(self, repository: Repository) -> list[WorkflowFile]:
        tree_url = f"https://api.github.com/repos/{repository.full_name}/git/trees/{repository.default_branch}"
        tree_payload = await self.github_client.get_json(tree_url, params={"recursive": "1"})
        workflow_entries = [
            entry
            for entry in tree_payload.get("tree", [])
            if entry.get("type") == "blob"
            and entry.get("path", "").startswith(".github/workflows/")
            and entry["path"].endswith((".yml", ".yaml"))
        ]
        workflow_entries = sorted(workflow_entries, key=lambda entry: entry.get("path", ""))[: self.max_workflows_per_repository]

        async def fetch_content(entry: dict) -> WorkflowFile:
            file_url = f"https://api.github.com/repos/{repository.full_name}/contents/{entry['path']}"
            content = await self.github_client.get_text(file_url, params={"ref": repository.default_branch})
            return WorkflowFile(
                repository_full_name=repository.full_name,
                path=entry["path"],
                sha=entry["sha"],
                content=content,
                discovered_at=utc_now(),
            )

        workflows = await asyncio.gather(*(fetch_content(entry) for entry in workflow_entries))
        repository.workflow_paths = [workflow.path for workflow in workflows]
        return workflows
