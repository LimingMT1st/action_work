from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


class CheckpointStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS checkpoints (
                    namespace TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (namespace, key)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tag_observations (
                    action_id TEXT NOT NULL,
                    tag_name TEXT NOT NULL,
                    sha TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    PRIMARY KEY (action_id, tag_name)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ref_states (
                    action_id TEXT NOT NULL,
                    ref_name TEXT NOT NULL,
                    ref_type TEXT NOT NULL,
                    sha TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    PRIMARY KEY (action_id, ref_name, ref_type)
                )
                """
            )

    def load(self, namespace: str, key: str, default: Any = None) -> Any:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value_json FROM checkpoints WHERE namespace = ? AND key = ?",
                (namespace, key),
            ).fetchone()
        if not row:
            return default
        return json.loads(row[0])

    def save(self, namespace: str, key: str, value: Any) -> None:
        payload = json.dumps(value, ensure_ascii=True)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO checkpoints(namespace, key, value_json)
                VALUES (?, ?, ?)
                ON CONFLICT(namespace, key)
                DO UPDATE SET value_json = excluded.value_json, updated_at = CURRENT_TIMESTAMP
                """,
                (namespace, key, payload),
            )

    def load_tag_observation(self, action_id: str, tag_name: str) -> tuple[str, str] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT sha, observed_at
                FROM tag_observations
                WHERE action_id = ? AND tag_name = ?
                """,
                (action_id, tag_name),
            ).fetchone()
        if not row:
            return None
        return row[0], row[1]

    def load_ref_state(self, action_id: str, ref_name: str, ref_type: str) -> tuple[str, str] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT sha, observed_at
                FROM ref_states
                WHERE action_id = ? AND ref_name = ? AND ref_type = ?
                """,
                (action_id, ref_name, ref_type),
            ).fetchone()
        if row:
            return row[0], row[1]
        if ref_type == "tag":
            return self.load_tag_observation(action_id, ref_name)
        return None

    def save_tag_observation(self, action_id: str, tag_name: str, sha: str, observed_at: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO tag_observations(action_id, tag_name, sha, observed_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(action_id, tag_name)
                DO UPDATE SET sha = excluded.sha, observed_at = excluded.observed_at
                """,
                (action_id, tag_name, sha, observed_at),
            )

    def save_ref_state(self, action_id: str, ref_name: str, ref_type: str, sha: str, observed_at: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO ref_states(action_id, ref_name, ref_type, sha, observed_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(action_id, ref_name, ref_type)
                DO UPDATE SET sha = excluded.sha, observed_at = excluded.observed_at
                """,
                (action_id, ref_name, ref_type, sha, observed_at),
            )
        if ref_type == "tag":
            self.save_tag_observation(action_id, ref_name, sha, observed_at)
