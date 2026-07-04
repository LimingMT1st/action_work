from __future__ import annotations

import asyncio

from gha_cascade_analyzer.analyzers.engine import SecurityAnalysisEngine
from gha_cascade_analyzer.config import Settings
from gha_cascade_analyzer.logging import log_event


async def amain() -> None:
    settings = Settings.from_env()
    engine = SecurityAnalysisEngine(settings)
    await engine.run()


def main() -> None:
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        log_event("Analysis interrupted by user")
        raise


if __name__ == "__main__":
    main()
