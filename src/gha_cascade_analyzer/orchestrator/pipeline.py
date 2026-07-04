from __future__ import annotations

import asyncio

from gha_cascade_analyzer.collectors.github_client import GitHubClient
from gha_cascade_analyzer.collectors.repository_identity_tracker import RepositoryIdentityTracker
from gha_cascade_analyzer.collectors.marketplace_crawler import MarketplaceCrawler
from gha_cascade_analyzer.collectors.ref_tracker import GitRefTracker
from gha_cascade_analyzer.collectors.repository_sampler import RepositorySampler
from gha_cascade_analyzer.collectors.workflow_collector import WorkflowCollector
from gha_cascade_analyzer.collectors.workflow_history import WorkflowHistoryCollector
from gha_cascade_analyzer.config import Settings
from gha_cascade_analyzer.enums import RefType
from gha_cascade_analyzer.logging import log_event
from gha_cascade_analyzer.models import ActionNode, MarketplaceActionIdentity, Repository
from gha_cascade_analyzer.storage.checkpoint import CheckpointStore
from gha_cascade_analyzer.storage.jsonl_store import JsonlStore
from gha_cascade_analyzer.utils.parsing import classify_ref, parse_action_reference, stable_id
from gha_cascade_analyzer.utils.time import utc_now


class CollectionPipeline:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.checkpoints = CheckpointStore(settings.crawl.checkpoint_db)
        self.store = JsonlStore(settings.crawl.output_dir)

    async def run(self) -> None:
        self._log_configuration_summary()
        async with GitHubClient(self.settings.github) as github_client:
            sampler = RepositorySampler(
                github_client=github_client,
                minimum_stars=self.settings.crawl.minimum_stars,
                top_limit=self.settings.crawl.top_repository_limit,
            )
            workflow_collector = WorkflowCollector(
                github_client,
                max_workflows_per_repository=self.settings.crawl.max_workflows_per_repository,
            )
            history_collector = WorkflowHistoryCollector(
                github_client,
                git_bin=self.settings.crawl.git_bin,
                max_history_commits_per_workflow=self.settings.crawl.max_history_commits_per_workflow,
                history_fetch_concurrency=self.settings.crawl.history_fetch_concurrency,
            )
            marketplace_crawler = MarketplaceCrawler(github_client, self.settings.github.marketplace_base_url)
            ref_tracker = GitRefTracker(self.checkpoints, git_bin=self.settings.crawl.git_bin)
            repository_identity_tracker = RepositoryIdentityTracker(github_client)

            repositories = await self._resume_or_sample_repositories(sampler)
            log_event(f"Repository sampling ready: {len(repositories)} repositories")
            self.store.append_many("repositories.jsonl", repositories)

            identities = await self._resume_or_collect_marketplace(marketplace_crawler)
            log_event(f"Marketplace identities ready: {len(identities)} entries")
            self.store.append_many("marketplace/actions.jsonl", identities)

            discovered_actions: dict[str, ActionNode] = {}
            await self._collect_all_repositories(
                repositories,
                workflow_collector,
                history_collector,
                discovered_actions,
            )

            log_event(f"Discovered actions: {len(discovered_actions)} unique nodes")
            self.store.append_many("actions/discovered.jsonl", discovered_actions.values())
            identity_observations = await repository_identity_tracker.observe_action_repositories(discovered_actions.values())
            log_event(f"Observed action repository identities: {len(identity_observations)} repositories")
            self.store.append_many("repo_identity/observations.jsonl", identity_observations)
            await self._observe_action_tags(ref_tracker, discovered_actions.values())
            log_event("Collection pipeline finished")

    def _log_configuration_summary(self) -> None:
        token_count = len(self.settings.github.tokens)
        log_event(
            "Starting collection with "
            f"repositories={self.settings.crawl.top_repository_limit}, "
            f"min_stars={self.settings.crawl.minimum_stars}, "
            f"concurrency={self.settings.github.max_concurrency}, "
            f"timeout={self.settings.github.request_timeout_seconds}s, "
            f"skip_marketplace={self.settings.crawl.skip_marketplace}, "
            f"max_workflows_per_repo={self.settings.crawl.max_workflows_per_repository}, "
            f"max_history_commits={self.settings.crawl.max_history_commits_per_workflow}, "
            f"history_fetch_concurrency={self.settings.crawl.history_fetch_concurrency}, "
            f"output_dir={self.settings.crawl.output_dir}, "
            f"token_count={token_count}"
        )

    async def _resume_or_sample_repositories(self, sampler: RepositorySampler):
        sampler_key = f"repositories::{self.settings.crawl.top_repository_limit}::{self.settings.crawl.minimum_stars}"
        cached = self.checkpoints.load("sampler", sampler_key)
        if cached:
            log_event("Using cached repository sample from checkpoint")
            return [Repository.model_validate(item) for item in cached]
        log_event("Sampling repositories from GitHub")
        repositories = await sampler.sample_high_value_repositories()
        self.checkpoints.save("sampler", sampler_key, [repo.model_dump(mode="json") for repo in repositories])
        return repositories

    async def _resume_or_collect_marketplace(self, crawler: MarketplaceCrawler):
        if self.settings.crawl.skip_marketplace:
            log_event("Skipping Marketplace crawl because GHA_SKIP_MARKETPLACE is enabled")
            return []
        cached = self.checkpoints.load("marketplace", "actions")
        if cached:
            log_event("Using cached Marketplace identities from checkpoint")
            return [MarketplaceActionIdentity.model_validate(item) for item in cached]
        log_event("Crawling GitHub Marketplace")
        try:
            identities = await crawler.crawl_all_actions()
        except Exception as exc:
            log_event(f"Marketplace crawl failed, continuing without it: {exc}")
            self._record_error(
                stage="marketplace",
                repository_full_name=None,
                error=exc,
                extra={"operation": "crawl_all_actions"},
            )
            self.checkpoints.save("marketplace", "actions", [])
            return []
        self.checkpoints.save("marketplace", "actions", [item.model_dump(mode="json") for item in identities])
        return identities

    async def _collect_all_repositories(
        self,
        repositories: list[Repository],
        workflow_collector: WorkflowCollector,
        history_collector: WorkflowHistoryCollector,
        discovered_actions: dict[str, ActionNode],
    ) -> None:
        semaphore = asyncio.Semaphore(self.settings.github.max_concurrency)
        action_lock = asyncio.Lock()
        completed = 0
        failed = 0
        progress_lock = asyncio.Lock()

        async def worker(repository: Repository) -> None:
            async with semaphore:
                nonlocal completed, failed
                try:
                    await self._collect_repository_bundle(
                        repository,
                        workflow_collector,
                        history_collector,
                        discovered_actions,
                        action_lock,
                    )
                    async with progress_lock:
                        completed += 1
                        if completed <= 5 or completed % 10 == 0:
                            log_event(f"Repository progress: completed={completed} failed={failed} total={len(repositories)}")
                except Exception as exc:
                    self._record_error(
                        stage="repository_bundle",
                        repository_full_name=repository.full_name,
                        error=exc,
                    )
                    async with progress_lock:
                        failed += 1
                        log_event(f"Repository failed: {repository.full_name} ({failed} failures)")

        await asyncio.gather(*(worker(repository) for repository in repositories))
        log_event(f"Repository collection complete: completed={completed} failed={failed}")

    async def _collect_repository_bundle(
        self,
        repository,
        workflow_collector: WorkflowCollector,
        history_collector: WorkflowHistoryCollector,
        discovered_actions: dict[str, ActionNode],
        action_lock: asyncio.Lock,
    ) -> None:
        repo_checkpoint_key = repository.full_name
        if (
            self.checkpoints.load("repository", repo_checkpoint_key) == "completed"
            and self._repository_snapshot_exists(repository)
        ):
            return
        if self.checkpoints.load("repository", repo_checkpoint_key) == "completed":
            log_event(f"Repository snapshot missing, forcing recollection: {repository.full_name}")
        self.checkpoints.save("repository", repo_checkpoint_key, "running")
        log_event(f"Collecting repository: {repository.full_name}")

        try:
            workflows = await workflow_collector.collect_repository_workflows(repository)
            self.store.append_many(f"workflows/{repository.owner}__{repository.name}.jsonl", workflows)

            for workflow in workflows:
                changes = await history_collector.collect_uses_changes(repository, workflow)
                self.store.append_many(
                    f"workflow_history/{repository.owner}__{repository.name}.jsonl",
                    changes,
                )
                for change in changes:
                    for uses_value in change.uses_after:
                        owner, repo, subpath, ref = parse_action_reference(uses_value)
                        action_id = stable_id(owner, repo, subpath or "", ref)
                        async with action_lock:
                            discovered_actions.setdefault(
                                action_id,
                                ActionNode(
                                    action_id=action_id,
                                    owner=owner,
                                    repo=repo,
                                    subpath=subpath,
                                    action_name=f"{owner}/{repo}",
                                    ref=ref,
                                    ref_type=classify_ref(ref),
                                    discovered_at=utc_now(),
                                ),
                            )
        except Exception:
            self.checkpoints.save("repository", repo_checkpoint_key, "failed")
            raise

        self.checkpoints.save("repository", repo_checkpoint_key, "completed")

    def _repository_snapshot_exists(self, repository: Repository) -> bool:
        workflow_snapshot = self.settings.crawl.output_dir / f"workflows/{repository.owner}__{repository.name}.jsonl"
        return workflow_snapshot.exists()

    async def _observe_action_tags(self, ref_tracker: GitRefTracker, action_nodes) -> None:
        by_repository: dict[tuple[str, str], list[ActionNode]] = {}
        for action_node in action_nodes:
            if action_node.ref_type not in {RefType.TAG, RefType.BRANCH}:
                continue
            by_repository.setdefault((action_node.owner, action_node.repo), []).append(action_node)

        log_event(f"Observing mutable refs for {len(by_repository)} unique action repositories")
        repository_groups = list(by_repository.values())
        tasks = [ref_tracker.observe_action_refs(action_group) for action_group in repository_groups]
        for action_group, result in zip(repository_groups, await asyncio.gather(*tasks, return_exceptions=True), strict=True):
            representative = action_group[0]
            if isinstance(result, Exception):
                self._record_error(
                    stage="ref_observation",
                    repository_full_name=f"{representative.owner}/{representative.repo}",
                    error=result,
                )
                continue
            observations, drift_events = result
            self.store.append_many("refs/ref_observations.jsonl", observations)
            self.store.append_many("drift_events.jsonl", drift_events)
        log_event("Ref observation phase finished")

    def _record_error(
        self,
        *,
        stage: str,
        repository_full_name: str | None,
        error: Exception,
        extra: dict | None = None,
    ) -> None:
        payload = {
            "stage": stage,
            "repository_full_name": repository_full_name,
            "error_type": type(error).__name__,
            "error_message": str(error),
            "recorded_at": utc_now().isoformat(),
        }
        if extra:
            payload["extra"] = extra
        self.store.append_json("errors.jsonl", payload)
