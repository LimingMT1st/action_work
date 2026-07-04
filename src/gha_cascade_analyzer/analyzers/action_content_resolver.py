from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from gha_cascade_analyzer.collectors.github_client import GitHubClient
from gha_cascade_analyzer.enums import ActionType
from gha_cascade_analyzer.analyzers.composite_parser import (
    ParsedActionDefinition,
    ParsedDependencyReference,
    ParsedWorkflowDefinition,
    find_token_access_patterns,
    parse_action_definition,
    parse_workflow_definition,
)
from gha_cascade_analyzer.utils.parsing import parse_action_reference


@dataclass
class ResolvedActionContent:
    action_type: ActionType
    nested_dependencies: list[ParsedDependencyReference] = field(default_factory=list)
    declared_permissions: dict[str, str] = field(default_factory=dict)
    has_token_access: bool = False
    token_access_patterns: list[str] = field(default_factory=list)
    audited_source_files: list[str] = field(default_factory=list)


class ActionContentResolver:
    def __init__(self, github_client: GitHubClient | None = None, fetch_concurrency: int = 8) -> None:
        self.github_client = github_client
        self._fetch_semaphore = asyncio.Semaphore(fetch_concurrency)
        self._text_cache: dict[tuple[str, str, str, str], str] = {}
        self._action_cache: dict[tuple[str, str, str | None, str], ResolvedActionContent | None] = {}
        self._workflow_cache: dict[tuple[str, str, str, str], ResolvedActionContent | None] = {}

    async def fetch_action_definition(self, owner: str, repo: str, subpath: str | None, ref: str) -> ResolvedActionContent | None:
        if self.github_client is None:
            return None
        cache_key = (owner.lower(), repo.lower(), subpath, ref)
        if cache_key in self._action_cache:
            return self._action_cache[cache_key]
        base_path = subpath.strip("/") if subpath else ""
        for filename in ("action.yml", "action.yaml"):
            path = f"{base_path}/{filename}" if base_path else filename
            try:
                content = await self._fetch_repo_text(owner, repo, path, ref)
                parsed = parse_action_definition(content)
                resolved = await self._hydrate_action_content(owner, repo, base_path, ref, path, content, parsed)
                self._action_cache[cache_key] = resolved
                return resolved
            except Exception:
                continue
        self._action_cache[cache_key] = None
        return None

    async def fetch_reusable_workflow(self, owner: str, repo: str, subpath: str | None, ref: str) -> ResolvedActionContent | None:
        if self.github_client is None or not subpath:
            return None
        cache_key = (owner.lower(), repo.lower(), subpath, ref)
        if cache_key in self._workflow_cache:
            return self._workflow_cache[cache_key]
        try:
            content = await self._fetch_repo_text(owner, repo, subpath, ref)
            parsed = parse_workflow_definition(content)
            token_patterns = find_token_access_patterns(content)
            resolved = ResolvedActionContent(
                action_type=ActionType.REUSABLE_WORKFLOW,
                nested_dependencies=parsed.nested_dependencies,
                declared_permissions=parsed.declared_permissions,
                has_token_access=bool(token_patterns),
                token_access_patterns=token_patterns,
                audited_source_files=[subpath],
            )
            self._workflow_cache[cache_key] = resolved
            return resolved
        except Exception:
            self._workflow_cache[cache_key] = None
            return None

    async def _hydrate_action_content(
        self,
        owner: str,
        repo: str,
        base_path: str,
        ref: str,
        definition_path: str,
        definition_content: str,
        parsed: ParsedActionDefinition,
    ) -> ResolvedActionContent:
        audited_files = [definition_path]
        token_patterns = set(find_token_access_patterns(definition_content))

        if parsed.action_type == ActionType.JAVASCRIPT and parsed.main_entry:
            main_path = f"{base_path}/{parsed.main_entry}".strip("/") if base_path else parsed.main_entry
            try:
                main_content = await self._fetch_repo_text(owner, repo, main_path, ref)
                audited_files.append(main_path)
                token_patterns.update(find_token_access_patterns(main_content))
            except Exception:
                pass

        if parsed.action_type == ActionType.COMPOSITE:
            for inline_script in parsed.inline_scripts:
                token_patterns.update(find_token_access_patterns(inline_script))
            for script_path in parsed.local_script_paths:
                normalized_path = f"{base_path}/{script_path}".replace("\\", "/") if base_path else script_path
                normalized_path = normalized_path.lstrip("./")
                try:
                    script_content = await self._fetch_repo_text(owner, repo, normalized_path, ref)
                    audited_files.append(normalized_path)
                    token_patterns.update(find_token_access_patterns(script_content))
                except Exception:
                    continue

        return ResolvedActionContent(
            action_type=parsed.action_type,
            nested_dependencies=parsed.nested_dependencies,
            declared_permissions=parsed.declared_permissions,
            has_token_access=bool(token_patterns),
            token_access_patterns=sorted(token_patterns),
            audited_source_files=sorted(set(audited_files)),
        )

    async def _fetch_repo_text(self, owner: str, repo: str, path: str, ref: str) -> str:
        cache_key = (owner.lower(), repo.lower(), path, ref)
        if cache_key in self._text_cache:
            return self._text_cache[cache_key]
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
        async with self._fetch_semaphore:
            text = await self.github_client.get_text(url, params={"ref": ref})
        self._text_cache[cache_key] = text
        return text

    @staticmethod
    def looks_like_reusable_workflow(uses_value: str) -> bool:
        owner, repo, subpath, _ = parse_action_reference(uses_value)
        return bool(subpath and subpath.startswith(".github/workflows/"))
