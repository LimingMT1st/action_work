from __future__ import annotations

import shutil
from dataclasses import dataclass, field

from gha_cascade_analyzer.collectors.github_client import GitHubClient
from gha_cascade_analyzer.config import Settings


@dataclass
class PreflightReport:
    passed: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures


class PreflightChecker:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def run(self) -> PreflightReport:
        report = PreflightReport()
        self._check_local_configuration(report)
        await self._check_remote_connectivity(report)
        return report

    def _check_local_configuration(self, report: PreflightReport) -> None:
        settings = self.settings

        if settings.github.tokens:
            report.passed.append(f"Loaded {len(settings.github.tokens)} GitHub token(s)")
        else:
            report.failures.append("No valid GitHub token was loaded from .env or environment variables")

        git_path = shutil.which(settings.crawl.git_bin) if settings.crawl.git_bin else None
        if git_path:
            report.passed.append(f"Git executable found: {git_path}")
        else:
            report.failures.append(f"Git executable not found: {settings.crawl.git_bin}")

        if settings.crawl.minimum_stars < 50:
            report.warnings.append(
                f"GHA_MIN_STARS={settings.crawl.minimum_stars} is lower than the research target of 50 and may broaden the crawl unnecessarily"
            )
        else:
            report.passed.append(f"Minimum stars threshold looks aligned: {settings.crawl.minimum_stars}")

        if settings.crawl.top_repository_limit > 200:
            report.warnings.append(
                f"GHA_TOP_REPOSITORIES={settings.crawl.top_repository_limit} is relatively large for initial validation; consider starting with 20-50"
            )
        else:
            report.passed.append(f"Repository sample size is conservative enough for validation: {settings.crawl.top_repository_limit}")

        if settings.github.max_concurrency > 5:
            report.warnings.append(
                f"GITHUB_MAX_CONCURRENCY={settings.github.max_concurrency} may be too aggressive on unstable networks; 2-5 is safer"
            )
        else:
            report.passed.append(f"Concurrency is conservative: {settings.github.max_concurrency}")

        if settings.github.request_timeout_seconds < 60:
            report.warnings.append(
                f"GITHUB_TIMEOUT_SECONDS={settings.github.request_timeout_seconds} may be too low for large repository trees; 60-90 is safer"
            )
        else:
            report.passed.append(f"Timeout is conservative: {settings.github.request_timeout_seconds}s")

        if not settings.crawl.skip_marketplace:
            report.warnings.append("Marketplace crawling is enabled; if github.com/marketplace is unstable, set GHA_SKIP_MARKETPLACE=true")
        else:
            report.passed.append("Marketplace crawling is disabled")

        if settings.crawl.max_workflows_per_repository > 20:
            report.warnings.append(
                f"GHA_MAX_WORKFLOWS_PER_REPOSITORY={settings.crawl.max_workflows_per_repository} may slow collection on large repositories"
            )
        else:
            report.passed.append(f"Workflow cap per repository is reasonable: {settings.crawl.max_workflows_per_repository}")

        if settings.crawl.max_history_commits_per_workflow > 50:
            report.warnings.append(
                f"GHA_MAX_HISTORY_COMMITS_PER_WORKFLOW={settings.crawl.max_history_commits_per_workflow} may make workflow history collection very heavy"
            )
        else:
            report.passed.append(f"Workflow history cap is reasonable: {settings.crawl.max_history_commits_per_workflow}")

        if settings.crawl.history_fetch_concurrency > 5:
            report.warnings.append(
                f"GHA_HISTORY_FETCH_CONCURRENCY={settings.crawl.history_fetch_concurrency} may overload unstable connections"
            )
        else:
            report.passed.append(f"Workflow history fetch concurrency is conservative: {settings.crawl.history_fetch_concurrency}")

    async def _check_remote_connectivity(self, report: PreflightReport) -> None:
        if not self.settings.github.tokens:
            return

        async with GitHubClient(self.settings.github) as github_client:
            try:
                rate_limit = await github_client.get_json(f"{self.settings.github.api_base_url}/rate_limit")
                core = rate_limit.get("resources", {}).get("core", {})
                remaining = core.get("remaining")
                limit = core.get("limit")
                report.passed.append(f"GitHub API reachable: core rate limit remaining {remaining}/{limit}")
            except Exception as exc:
                report.failures.append(f"Unable to reach GitHub API /rate_limit: {exc}")
                return

            try:
                await github_client.get_json(f"{self.settings.github.api_base_url}/search/repositories", params={"q": "stars:>50 fork:false", "per_page": 1})
                report.passed.append("GitHub repository search endpoint is reachable")
            except Exception as exc:
                report.failures.append(f"Unable to query GitHub repository search endpoint: {exc}")

