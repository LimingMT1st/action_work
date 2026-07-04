from __future__ import annotations

import csv
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Callable, TextIO

from pydantic import BaseModel


class AnalysisExporter:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def export_models_json(self, relative_path: str, models: list[BaseModel]) -> None:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        rows = [model.model_dump(mode="json") for model in models]
        self._write_text_atomically(
            path,
            lambda handle: json.dump(rows, handle, ensure_ascii=True, indent=2),
        )

    def export_model_json(self, relative_path: str, model: BaseModel) -> None:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = model.model_dump(mode="json")
        self._write_text_atomically(
            path,
            lambda handle: json.dump(payload, handle, ensure_ascii=True, indent=2),
        )

    def export_models_csv(self, relative_path: str, models: list[BaseModel]) -> None:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        rows = [model.model_dump(mode="json") for model in models]
        self.export_rows_csv(relative_path, rows)

    def export_rows_csv(self, relative_path: str, rows: list[dict]) -> None:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if not rows:
            self._write_text_atomically(path, lambda handle: handle.write(""), newline="")
            return
        self._write_text_atomically(
            path,
            lambda handle: self._write_csv_rows(handle, rows),
            newline="",
        )

    def _write_csv_rows(self, handle: TextIO, rows: list[dict]) -> None:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    def _write_text_atomically(
        self,
        path: Path,
        write_fn: Callable[[TextIO], None],
        *,
        newline: str | None = None,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._prepare_existing_target(path)
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=str(path.parent),
        )
        temp_path = Path(temp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline=newline) as handle:
                write_fn(handle)
            self._replace_path(temp_path, path)
        except Exception:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    def _prepare_existing_target(self, path: Path) -> None:
        if not path.exists():
            return
        try:
            current_mode = stat.S_IMODE(path.stat().st_mode)
            path.chmod(current_mode | stat.S_IWUSR)
        except OSError:
            pass

    def _replace_path(self, temp_path: Path, target_path: Path) -> None:
        try:
            os.replace(temp_path, target_path)
            return
        except PermissionError:
            self._prepare_existing_target(target_path)
            if target_path.exists():
                try:
                    target_path.unlink()
                except OSError:
                    pass
            os.replace(temp_path, target_path)
