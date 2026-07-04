from __future__ import annotations

import argparse
import asyncio

from gha_cascade_analyzer.config import Settings
from gha_cascade_analyzer.logging import log_event
from gha_cascade_analyzer.orchestrator.pipeline import CollectionPipeline
from gha_cascade_analyzer.preflight import PreflightChecker


async def amain(preflight_only: bool = False) -> int:
    settings = Settings.from_env()
    if preflight_only:
        checker = PreflightChecker(settings)
        report = await checker.run()
        for item in report.passed:
            log_event(f"PASS: {item}")
        for item in report.warnings:
            log_event(f"WARN: {item}")
        for item in report.failures:
            log_event(f"FAIL: {item}")
        if report.ok:
            log_event("Preflight completed successfully")
            return 0
        log_event("Preflight found blocking issues")
        return 1
    pipeline = CollectionPipeline(settings)
    await pipeline.run()
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GHA-Cascade-Analyzer collection entrypoint")
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Validate configuration, token availability, Git presence, and GitHub API reachability without running collection",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        raise SystemExit(asyncio.run(amain(preflight_only=args.preflight)))
    except KeyboardInterrupt:
        log_event("Collection interrupted by user")
        raise


if __name__ == "__main__":
    main()
