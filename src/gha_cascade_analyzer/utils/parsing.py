from __future__ import annotations

import re
from hashlib import sha1

import yaml

from gha_cascade_analyzer.enums import RefType

USES_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/.+)?@.+$")
VARIABLE_REF_PATTERN = re.compile(r"\${{\s*[^}]+\s*}}")


def stable_id(*parts: str) -> str:
    joined = "::".join(parts)
    return sha1(joined.encode("utf-8")).hexdigest()


def classify_ref(ref: str) -> RefType:
    if VARIABLE_REF_PATTERN.search(ref):
        return RefType.UNKNOWN
    if re.fullmatch(r"[0-9a-fA-F]{40}", ref):
        return RefType.SHA
    if ref.startswith("refs/heads/"):
        return RefType.BRANCH
    if re.fullmatch(r"v?\d+(\.\d+)*([\-+].+)?", ref):
        return RefType.TAG
    if ref in {"main", "master", "develop"} or "/" in ref:
        return RefType.BRANCH
    return RefType.TAG


def is_dynamic_ref(ref: str) -> bool:
    return bool(VARIABLE_REF_PATTERN.search(ref))


def extract_uses_references(workflow_text: str) -> list[str]:
    try:
        parsed = yaml.safe_load(workflow_text) or {}
    except yaml.YAMLError:
        return []

    uses_values: list[str] = []

    def walk(value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "uses" and isinstance(item, str) and USES_PATTERN.match(item):
                    uses_values.append(item)
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(parsed)
    return sorted(set(uses_values))


def parse_action_reference(uses_value: str) -> tuple[str, str, str | None, str]:
    repo_part, ref = uses_value.split("@", 1)
    pieces = repo_part.split("/")
    owner = pieces[0]
    repo = pieces[1]
    subpath = "/".join(pieces[2:]) if len(pieces) > 2 else None
    return owner, repo, subpath, ref
