from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field
from dotenv import load_dotenv


class GitHubSettings(BaseModel):
    api_base_url: str = "https://api.github.com"
    marketplace_base_url: str = "https://github.com/marketplace"
    tokens: list[str] = Field(default_factory=list)
    max_concurrency: int = 20
    request_timeout_seconds: int = 30
    user_agent: str = "GHA-Cascade-Analyzer/0.1"


class CrawlSettings(BaseModel):
    top_repository_limit: int = 2000
    minimum_stars: int = 50
    output_dir: Path = Path("data")
    checkpoint_db: Path = Path("data/checkpoints.sqlite3")
    state_dir: Path = Path("data/state")
    workflow_history_mode: Literal["api", "git"] = "api"
    git_bin: str = "git"
    skip_marketplace: bool = False
    max_workflows_per_repository: int = 20
    max_history_commits_per_workflow: int = 50
    history_fetch_concurrency: int = 5


class AnalysisSettings(BaseModel):
    online_recursive_expand: bool = False
    require_complete_local_data: bool = True
    recursive_fetch_concurrency: int = 8
    recursive_max_depth: int = 6
    progress_report_interval: int = 25
    supplemental_identity_max_repositories: int = 1000
    supplemental_identity_concurrency: int = 12
    supplemental_action_metadata_max_actions: int = 4000
    supplemental_action_metadata_concurrency: int = 12


class Settings(BaseModel):
    github: GitHubSettings = Field(default_factory=GitHubSettings)
    crawl: CrawlSettings = Field(default_factory=CrawlSettings)
    analysis: AnalysisSettings = Field(default_factory=AnalysisSettings)

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv()
        tokens_env = os.getenv("GITHUB_TOKENS", "").strip()
        tokens = [
            token.strip()
            for token in tokens_env.split(",")
            if token.strip() and "your_token" not in token and "token_2" not in token
        ]
        output_dir = Path(os.getenv("GHA_OUTPUT_DIR", "data"))
        return cls(
            github=GitHubSettings(
                api_base_url=os.getenv("GITHUB_API_BASE_URL", "https://api.github.com"),
                marketplace_base_url=os.getenv("GITHUB_MARKETPLACE_BASE_URL", "https://github.com/marketplace"),
                tokens=tokens,
                max_concurrency=int(os.getenv("GITHUB_MAX_CONCURRENCY", "20")),
                request_timeout_seconds=int(os.getenv("GITHUB_TIMEOUT_SECONDS", "30")),
                user_agent=os.getenv("GITHUB_USER_AGENT", "GHA-Cascade-Analyzer/0.1"),
            ),
            crawl=CrawlSettings(
                top_repository_limit=int(os.getenv("GHA_TOP_REPOSITORIES", "2000")),
                minimum_stars=int(os.getenv("GHA_MIN_STARS", "50")),
                output_dir=output_dir,
                checkpoint_db=Path(os.getenv("GHA_CHECKPOINT_DB", str(output_dir / "checkpoints.sqlite3"))),
                state_dir=Path(os.getenv("GHA_STATE_DIR", str(output_dir / "state"))),
                workflow_history_mode=os.getenv("GHA_WORKFLOW_HISTORY_MODE", "api"),
                git_bin=os.getenv("GHA_GIT_BIN", "git"),
                skip_marketplace=os.getenv("GHA_SKIP_MARKETPLACE", "false").strip().lower() in {"1", "true", "yes", "on"},
                max_workflows_per_repository=int(os.getenv("GHA_MAX_WORKFLOWS_PER_REPOSITORY", "20")),
                max_history_commits_per_workflow=int(os.getenv("GHA_MAX_HISTORY_COMMITS_PER_WORKFLOW", "50")),
                history_fetch_concurrency=int(os.getenv("GHA_HISTORY_FETCH_CONCURRENCY", "5")),
            ),
            analysis=AnalysisSettings(
                online_recursive_expand=os.getenv("GHA_ANALYSIS_ONLINE_RECURSIVE_EXPAND", "false").strip().lower() in {"1", "true", "yes", "on"},
                require_complete_local_data=os.getenv("GHA_ANALYSIS_REQUIRE_COMPLETE_LOCAL_DATA", "true").strip().lower() in {"1", "true", "yes", "on"},
                recursive_fetch_concurrency=int(os.getenv("GHA_ANALYSIS_RECURSIVE_FETCH_CONCURRENCY", "8")),
                recursive_max_depth=int(os.getenv("GHA_ANALYSIS_RECURSIVE_MAX_DEPTH", "6")),
                progress_report_interval=int(os.getenv("GHA_ANALYSIS_PROGRESS_REPORT_INTERVAL", "25")),
                supplemental_identity_max_repositories=int(os.getenv("GHA_ANALYSIS_SUPPLEMENTAL_IDENTITY_MAX_REPOSITORIES", "1000")),
                supplemental_identity_concurrency=int(os.getenv("GHA_ANALYSIS_SUPPLEMENTAL_IDENTITY_CONCURRENCY", "12")),
                supplemental_action_metadata_max_actions=int(os.getenv("GHA_ANALYSIS_SUPPLEMENTAL_ACTION_METADATA_MAX_ACTIONS", "4000")),
                supplemental_action_metadata_concurrency=int(os.getenv("GHA_ANALYSIS_SUPPLEMENTAL_ACTION_METADATA_CONCURRENCY", "12")),
            ),
        )
