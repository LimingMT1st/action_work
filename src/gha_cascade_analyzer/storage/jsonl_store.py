from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from pydantic import BaseModel


class JsonlStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def append_model(self, relative_path: str, model: BaseModel) -> None:
        self.append_json(relative_path, model.model_dump(mode="json"))

    def append_many(self, relative_path: str, models: Iterable[BaseModel]) -> None:
        target = self.root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as handle:
            for model in models:
                handle.write(json.dumps(model.model_dump(mode="json"), ensure_ascii=True) + "\n")

    def append_json(self, relative_path: str, payload: dict) -> None:
        target = self.root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
