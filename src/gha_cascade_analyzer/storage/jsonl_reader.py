from __future__ import annotations

import json
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class JsonlReader:
    def __init__(self, root: Path) -> None:
        self.root = root

    def read_models(self, relative_path: str, model_type: type[T]) -> list[T]:
        path = self.root / relative_path
        if not path.exists():
            return []
        with path.open("r", encoding="utf-8") as handle:
            return [model_type.model_validate(json.loads(line)) for line in handle if line.strip()]

    def glob_models(self, pattern: str, model_type: type[T]) -> list[T]:
        models: list[T] = []
        for path in sorted(self.root.glob(pattern)):
            with path.open("r", encoding="utf-8") as handle:
                models.extend(model_type.model_validate(json.loads(line)) for line in handle if line.strip())
        return models
