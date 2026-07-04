from __future__ import annotations

import asyncio

from gha_cascade_analyzer.config import Settings
from gha_cascade_analyzer.logging import log_event
from gha_cascade_analyzer.preflight import PreflightChecker


async def amain() -> int:
    settings = Settings.from_env()
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


def main() -> None:
    raise SystemExit(asyncio.run(amain()))


if __name__ == "__main__":
    main()
