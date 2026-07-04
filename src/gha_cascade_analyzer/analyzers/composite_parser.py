from __future__ import annotations

import re
from dataclasses import dataclass, field

import yaml

from gha_cascade_analyzer.enums import ActionType, RefType
from gha_cascade_analyzer.utils.parsing import USES_PATTERN, classify_ref, is_dynamic_ref, parse_action_reference

SCRIPT_PATH_PATTERN = re.compile(r"(?<![\w./-])(?:\./)?[\w./-]+\.(?:sh|bash|ps1|cmd|py|js|mjs|cjs|ts)")
GITHUB_TOKEN_PATTERNS = [
    re.compile(r"\bGITHUB_TOKEN\b"),
    re.compile(r"secrets\.GITHUB_TOKEN"),
    re.compile(r"github\.token"),
    re.compile(r"process\.env\.[A-Z0-9_]+"),
    re.compile(r"\$GITHUB_TOKEN\b"),
    re.compile(r"INPUT_[A-Z0-9_]+"),
    re.compile(r"core\.getInput\("),
]


@dataclass
class ParsedDependencyReference:
    uses_value: str
    owner: str
    repo: str
    subpath: str | None
    ref_string: str
    ref_type: RefType
    is_dynamic_ref: bool


@dataclass
class ParsedActionDefinition:
    action_type: ActionType
    nested_dependencies: list[ParsedDependencyReference] = field(default_factory=list)
    main_entry: str | None = None
    local_script_paths: list[str] = field(default_factory=list)
    declared_permissions: dict[str, str] = field(default_factory=dict)
    inline_scripts: list[str] = field(default_factory=list)


@dataclass
class ParsedWorkflowDefinition:
    workflow_name: str | None = None
    nested_dependencies: list[ParsedDependencyReference] = field(default_factory=list)
    declared_permissions: dict[str, str] = field(default_factory=dict)
    has_write_permissions: bool = False


def normalize_permissions(value: object) -> dict[str, str]:
    if isinstance(value, str):
        return {"__root__": value}
    if isinstance(value, dict):
        normalized: dict[str, str] = {}
        for key, item in value.items():
            if isinstance(item, str):
                normalized[str(key)] = item
        return normalized
    return {}


def has_write_permissions(permissions: dict[str, str]) -> bool:
    return any("write" in permission.lower() for permission in permissions.values())


def find_token_access_patterns(text: str) -> list[str]:
    matches: set[str] = set()
    for pattern in GITHUB_TOKEN_PATTERNS:
        for match in pattern.findall(text):
            matches.add(match if isinstance(match, str) else str(match))
    return sorted(matches)


def extract_local_script_paths(run_command: str) -> list[str]:
    return sorted(set(match.group(0) for match in SCRIPT_PATH_PATTERN.finditer(run_command)))


def build_dependency_reference(uses_value: str) -> ParsedDependencyReference:
    owner, repo, subpath, ref = parse_action_reference(uses_value)
    return ParsedDependencyReference(
        uses_value=uses_value,
        owner=owner,
        repo=repo,
        subpath=subpath,
        ref_string=ref,
        ref_type=classify_ref(ref),
        is_dynamic_ref=is_dynamic_ref(ref),
    )


def parse_action_definition(content: str) -> ParsedActionDefinition:
    try:
        parsed = yaml.safe_load(content) or {}
    except yaml.YAMLError:
        return ParsedActionDefinition(action_type=ActionType.UNKNOWN)

    runs = parsed.get("runs", {}) if isinstance(parsed, dict) else {}
    using = runs.get("using") if isinstance(runs, dict) else None
    declared_permissions = normalize_permissions(parsed.get("permissions")) if isinstance(parsed, dict) else {}
    if using == "composite":
        nested: list[ParsedDependencyReference] = []
        local_script_paths: list[str] = []
        inline_scripts: list[str] = []
        for step in runs.get("steps", []) or []:
            if isinstance(step, dict):
                uses_value = step.get("uses")
                if isinstance(uses_value, str) and USES_PATTERN.match(uses_value):
                    nested.append(build_dependency_reference(uses_value))
                run_command = step.get("run")
                if isinstance(run_command, str):
                    inline_scripts.append(run_command)
                    local_script_paths.extend(extract_local_script_paths(run_command))
        return ParsedActionDefinition(
            action_type=ActionType.COMPOSITE,
            nested_dependencies=_dedupe_dependencies(nested),
            local_script_paths=sorted(set(local_script_paths)),
            declared_permissions=declared_permissions,
            inline_scripts=inline_scripts,
        )
    if using == "docker":
        return ParsedActionDefinition(action_type=ActionType.DOCKER, declared_permissions=declared_permissions)
    if using in {"node12", "node16", "node20"}:
        return ParsedActionDefinition(
            action_type=ActionType.JAVASCRIPT,
            main_entry=runs.get("main") if isinstance(runs.get("main"), str) else None,
            declared_permissions=declared_permissions,
        )
    return ParsedActionDefinition(action_type=ActionType.UNKNOWN, declared_permissions=declared_permissions)


def parse_workflow_definition(content: str) -> ParsedWorkflowDefinition:
    try:
        parsed = yaml.safe_load(content) or {}
    except yaml.YAMLError:
        return ParsedWorkflowDefinition()

    nested: list[ParsedDependencyReference] = []
    jobs = parsed.get("jobs", {})
    permissions = normalize_permissions(parsed.get("permissions")) if isinstance(parsed, dict) else {}
    workflow_name = parsed.get("name") if isinstance(parsed, dict) and isinstance(parsed.get("name"), str) else None
    if isinstance(jobs, dict):
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            uses_value = job.get("uses")
            if isinstance(uses_value, str) and USES_PATTERN.match(uses_value):
                nested.append(build_dependency_reference(uses_value))
            job_permissions = normalize_permissions(job.get("permissions"))
            permissions.update(job_permissions)
            for step in job.get("steps", []) or []:
                if isinstance(step, dict):
                    step_uses = step.get("uses")
                    if isinstance(step_uses, str) and USES_PATTERN.match(step_uses):
                        nested.append(build_dependency_reference(step_uses))
    return ParsedWorkflowDefinition(
        workflow_name=workflow_name,
        nested_dependencies=_dedupe_dependencies(nested),
        declared_permissions=permissions,
        has_write_permissions=has_write_permissions(permissions),
    )


def parse_reusable_workflow(content: str) -> list[ParsedDependencyReference]:
    return parse_workflow_definition(content).nested_dependencies


def _dedupe_dependencies(dependencies: list[ParsedDependencyReference]) -> list[ParsedDependencyReference]:
    seen: set[str] = set()
    deduped: list[ParsedDependencyReference] = []
    for dependency in dependencies:
        key = dependency.uses_value
        if key in seen:
            continue
        seen.add(key)
        deduped.append(dependency)
    return deduped
