from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime
from html import unescape

from gha_cascade_analyzer.models import MarketplaceActionIdentity

NEXT_PAGE_PATTERN = re.compile(r'<a[^>]+href="(?P<href>/marketplace(?:\?[^"]*)?)"[^>]*rel="next"')
CARD_PATTERN = re.compile(
    r'<a[^>]+href="(?P<href>/marketplace/actions/[^"]+)"[^>]*>.*?<h3[^>]*>(?P<title>.*?)</h3>.*?(?P<body><p[^>]*>.*?</p>)?',
    re.DOTALL,
)
REPO_PATTERN = re.compile(r'github\.com/(?P<owner>[^/]+)/(?P<repo>[^/"?#]+)')
CATEGORY_PATTERN = re.compile(r'data-testid="marketplace-category">(?P<category>.*?)<')
DESCRIPTION_PATTERN = re.compile(r"<p[^>]*>(?P<description>.*?)</p>", re.DOTALL)
BADGE_PATTERN = re.compile(r"(Verified creator|Partner|Creator verified)", re.IGNORECASE)


class MarketplaceCrawler:
    def __init__(self, github_client: object, marketplace_base_url: str) -> None:
        self.github_client = github_client
        self.marketplace_base_url = marketplace_base_url.rstrip("/")

    async def crawl_all_actions(self) -> list[MarketplaceActionIdentity]:
        identities: dict[str, MarketplaceActionIdentity] = {}
        next_url = f"{self.marketplace_base_url}?type=actions"

        while next_url:
            html = await self._fetch_html(next_url)
            for identity in self._parse_action_cards(html):
                identities[identity.slug] = identity
            next_url = self._next_page_url(html)
        return list(identities.values())

    async def _fetch_html(self, url: str) -> str:
        if self.github_client._session is None:
            raise RuntimeError("Marketplace crawler requires an active GitHubClient session")
        headers = {"User-Agent": self.github_client.settings.user_agent}
        last_error: Exception | None = None
        for attempt in range(5):
            try:
                async with self.github_client._session.get(url, headers=headers) as response:
                    response.raise_for_status()
                    return await response.text()
            except Exception as exc:
                last_error = exc
                await asyncio.sleep(min(2 ** attempt, 20))
        raise RuntimeError(f"Marketplace fetch failed after retries: {url}") from last_error

    def _parse_action_cards(self, html: str) -> list[MarketplaceActionIdentity]:
        identities: list[MarketplaceActionIdentity] = []
        collected_at = datetime.now(UTC)
        for match in CARD_PATTERN.finditer(html):
            href = match.group("href")
            slug = href.rsplit("/", 1)[-1]
            title = self._strip_html(match.group("title"))
            body_html = match.group("body") or ""
            description_match = DESCRIPTION_PATTERN.search(body_html)
            description = self._strip_html(description_match.group("description")) if description_match else None
            category_match = CATEGORY_PATTERN.search(match.group(0))
            category = self._strip_html(category_match.group("category")) if category_match else None
            repo_match = REPO_PATTERN.search(match.group(0))
            owner = repo = None
            if repo_match:
                owner = repo_match.group("owner")
                repo = repo_match.group("repo")
            identities.append(
                MarketplaceActionIdentity(
                    slug=slug,
                    title=title,
                    description=description,
                    owner=owner,
                    repository=repo,
                    category=category,
                    verified_creator=bool(BADGE_PATTERN.search(match.group(0))),
                    badge_text="verified" if BADGE_PATTERN.search(match.group(0)) else None,
                    marketplace_url=f"https://github.com{href}",
                    collected_at=collected_at,
                )
            )
        return identities

    def _next_page_url(self, html: str) -> str | None:
        match = NEXT_PAGE_PATTERN.search(html)
        if not match:
            return None
        return f"https://github.com{match.group('href')}"

    def _strip_html(self, value: str) -> str:
        no_tags = re.sub(r"<[^>]+>", " ", value)
        return " ".join(unescape(no_tags).split())
