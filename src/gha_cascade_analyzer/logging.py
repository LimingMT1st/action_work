from __future__ import annotations

from gha_cascade_analyzer.utils.time import utc_now


def log_event(message: str) -> None:
    timestamp = utc_now().isoformat(timespec="seconds")
    print(f"[{timestamp}] {message}", flush=True)
