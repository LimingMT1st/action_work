from __future__ import annotations

import asyncio

from gha_cascade_analyzer.models import Repository
from gha_cascade_analyzer.utils.time import utc_now


class RepositorySampler:
    def __init__(self, github_client: object, minimum_stars: int, top_limit: int) -> None:
        self.github_client = github_client
        self.minimum_stars = minimum_stars
        self.top_limit = top_limit

    async def sample_high_value_repositories(self) -> list[Repository]:
        """
        GitHub search is capped per query, so we split the star range recursively.
        The strategy stays consumer-first by always sorting by stars desc and
        prioritizing higher star buckets before descending further.
        """
        repositories: list[Repository] = []
        seen_ids: set[int] = set()
        queue: list[tuple[int, int | None]] = [(self.minimum_stars, None)]

        while queue and len(repositories) < self.top_limit:
            min_star, max_star = queue.pop(0)
            params = {
                "q": self._build_query(min_star=min_star, max_star=max_star),
                "sort": "stars",
                "order": "desc",
                "per_page": 100,
                "page": 1,
            }
            first_page = await self.github_client.get_json("https://api.github.com/search/repositories", params=params)
            total_count = int(first_page.get("total_count", 0))

            if total_count > 1000 and max_star is None:
                items = first_page.get("items", [])
                observed_max = max((item.get("stargazers_count", min_star + 1) for item in items), default=min_star + 1)
                split = max(min_star + 1, (observed_max + min_star) // 2)
                queue = [(split, None), (min_star, split - 1)] + queue
                continue

            if total_count > 1000 and max_star is not None and max_star > min_star:
                midpoint = (min_star + max_star) // 2
                queue = [(midpoint + 1, max_star), (min_star, midpoint)] + queue
                continue

            page_count = min((total_count + 99) // 100, 10)
            page_payloads = [first_page]
            if page_count > 1:
                tasks = [
                    self.github_client.get_json(
                        "https://api.github.com/search/repositories",
                        params={**params, "page": page},
                    )
                    for page in range(2, page_count + 1)
                ]
                page_payloads.extend(await asyncio.gather(*tasks))

            for payload in page_payloads:
                for item in payload.get("items", []):
                    if item.get("fork"):
                        continue
                    repo_id = int(item["id"])
                    if repo_id in seen_ids:
                        continue
                    seen_ids.add(repo_id)
                    repositories.append(
                        Repository(
                            repo_id=repo_id,
                            owner=item["owner"]["login"],
                            name=item["name"],
                            full_name=item["full_name"],
                            html_url=item["html_url"],
                            stars=item["stargazers_count"],
                            organization=item["owner"]["login"] if item["owner"]["type"] == "Organization" else None,
                            default_branch=item["default_branch"],
                            workflow_paths=[],
                            is_fork=item["fork"],
                            archived=item["archived"],
                            collected_at=utc_now(),
                        )
                    )
                    if len(repositories) >= self.top_limit:
                        break
                if len(repositories) >= self.top_limit:
                    break

        repositories.sort(key=lambda repo: repo.stars, reverse=True)
        return repositories[: self.top_limit]

    def _build_query(self, *, min_star: int, max_star: int | None) -> str:
        if max_star is None:
            stars = f"stars:>={min_star}"
        else:
            stars = f"stars:{min_star}..{max_star}"
        return f"{stars} fork:false archived:false"
