from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
import time
from typing import Any

import aiohttp

from gha_cascade_analyzer.config import GitHubSettings


class TokenPoolExhaustedError(RuntimeError):
    """Raised when no usable GitHub token remains."""


@dataclass
class TokenState:
    token: str
    remaining: int = 5000
    reset_at: int = 0
    enabled: bool = True


class TokenPool:
    def __init__(self, tokens: list[str]) -> None:
        self._tokens = deque(TokenState(token=token) for token in tokens) or deque([TokenState(token="")])
        self._lock = asyncio.Lock()

    async def acquire(self) -> TokenState:
        while True:
            async with self._lock:
                if not self._tokens:
                    raise TokenPoolExhaustedError("No GitHub tokens are configured")
                enabled_states = [candidate for candidate in self._tokens if candidate.enabled]
                if not enabled_states:
                    raise TokenPoolExhaustedError("All configured GitHub tokens have been disabled or exhausted")
                state = self._tokens[0]
                self._tokens.rotate(-1)
                now = int(time.time())
                if not state.enabled:
                    continue
                if state.remaining > 1 or state.reset_at <= now:
                    return state
            await asyncio.sleep(1)

    async def update_from_headers(self, token: str, headers: aiohttp.typedefs.LooseHeaders) -> None:
        async with self._lock:
            for state in self._tokens:
                if state.token != token:
                    continue
                remaining = headers.get("X-RateLimit-Remaining")
                reset_at = headers.get("X-RateLimit-Reset")
                if remaining is not None:
                    state.remaining = int(remaining)
                if reset_at is not None:
                    state.reset_at = int(reset_at)
                break

    async def disable_token(self, token: str) -> None:
        if not token:
            return
        async with self._lock:
            for state in self._tokens:
                if state.token == token:
                    state.enabled = False
                    break


class GitHubClient:
    def __init__(self, settings: GitHubSettings) -> None:
        self.settings = settings
        self.token_pool = TokenPool(settings.tokens)
        self._session: aiohttp.ClientSession | None = None
        self._semaphore = asyncio.Semaphore(settings.max_concurrency)

    async def __aenter__(self) -> "GitHubClient":
        timeout = aiohttp.ClientTimeout(total=self.settings.request_timeout_seconds)
        self._session = aiohttp.ClientSession(timeout=timeout)
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._session:
            await self._session.close()

    async def get_json(self, url: str, params: dict[str, Any] | None = None, accept: str = "application/vnd.github+json") -> Any:
        last_error: Exception | None = None
        for attempt in range(5):
            response: aiohttp.ClientResponse | None = None
            try:
                response = await self.request("GET", url, params=params, accept=accept)
                payload = await response.json()
                response.release()
                return payload
            except (asyncio.TimeoutError, aiohttp.ClientError, OSError) as exc:
                last_error = exc
                if response is not None:
                    response.close()
                await asyncio.sleep(min(2 ** attempt, 30))
        raise RuntimeError(f"GitHub JSON fetch failed after retries: {url}") from last_error

    async def get_text(self, url: str, params: dict[str, Any] | None = None, accept: str = "application/vnd.github.raw+json") -> str:
        last_error: Exception | None = None
        for attempt in range(5):
            response: aiohttp.ClientResponse | None = None
            try:
                response = await self.request("GET", url, params=params, accept=accept)
                payload = await response.text()
                response.release()
                return payload
            except (asyncio.TimeoutError, aiohttp.ClientError, OSError) as exc:
                last_error = exc
                if response is not None:
                    response.close()
                await asyncio.sleep(min(2 ** attempt, 30))
        raise RuntimeError(f"GitHub text fetch failed after retries: {url}") from last_error

    async def get_repository_identity(self, owner: str, repo: str) -> dict[str, Any]:
        if self._session is None:
            raise RuntimeError("GitHubClient must be used as an async context manager")

        url = f"{self.settings.api_base_url}/repos/{owner}/{repo}"
        async with self._semaphore:
            last_error: Exception | None = None
            for attempt in range(5):
                token_state = await self.token_pool.acquire()
                headers = {
                    "Accept": "application/vnd.github+json",
                    "User-Agent": self.settings.user_agent,
                    "X-GitHub-Api-Version": "2022-11-28",
                }
                if token_state.token:
                    headers["Authorization"] = f"Bearer {token_state.token}"

                response = await self._session.request("GET", url, headers=headers)
                await self.token_pool.update_from_headers(token_state.token, response.headers)

                try:
                    if response.status == 401:
                        await response.read()
                        await self.token_pool.disable_token(token_state.token)
                        await asyncio.sleep(min(2 ** attempt, 10))
                        continue
                    if response.status in {403, 429}:
                        await response.read()
                        retry_after = response.headers.get("Retry-After")
                        wait_seconds = int(retry_after) if retry_after else min(2 ** attempt, 30)
                        await asyncio.sleep(wait_seconds)
                        continue
                    if response.status >= 500:
                        await response.read()
                        await asyncio.sleep(min(2 ** attempt, 30))
                        continue
                    if response.status in {404, 410}:
                        await response.read()
                        return {
                            "status_code": response.status,
                            "payload": None,
                            "final_url": str(response.url),
                        }
                    response.raise_for_status()
                    payload = await response.json()
                    return {
                        "status_code": response.status,
                        "payload": payload,
                        "final_url": str(response.url),
                    }
                except (asyncio.TimeoutError, aiohttp.ClientError, OSError) as exc:
                    last_error = exc
                    await asyncio.sleep(min(2 ** attempt, 30))
                finally:
                    response.release()

        raise RuntimeError(f"GitHub repository identity fetch failed after retries: {owner}/{repo}") from last_error

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        accept: str = "application/vnd.github+json",
    ) -> aiohttp.ClientResponse:
        if self._session is None:
            raise RuntimeError("GitHubClient must be used as an async context manager")

        async with self._semaphore:
            for attempt in range(5):
                token_state = await self.token_pool.acquire()
                headers = {
                    "Accept": accept,
                    "User-Agent": self.settings.user_agent,
                    "X-GitHub-Api-Version": "2022-11-28",
                }
                if token_state.token:
                    headers["Authorization"] = f"Bearer {token_state.token}"

                response = await self._session.request(method, url, params=params, headers=headers)
                await self.token_pool.update_from_headers(token_state.token, response.headers)

                if response.status == 401:
                    await response.read()
                    await self.token_pool.disable_token(token_state.token)
                    await asyncio.sleep(min(2 ** attempt, 10))
                    continue
                if response.status in {403, 429}:
                    await response.read()
                    retry_after = response.headers.get("Retry-After")
                    wait_seconds = int(retry_after) if retry_after else min(2 ** attempt, 30)
                    await asyncio.sleep(wait_seconds)
                    continue
                if response.status >= 500:
                    await response.read()
                    await asyncio.sleep(min(2 ** attempt, 30))
                    continue
                response.raise_for_status()
                return response

        raise RuntimeError(f"GitHub request failed after retries: {method} {url}")
