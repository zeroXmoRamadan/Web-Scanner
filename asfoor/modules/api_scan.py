"""API endpoint and route discovery via wordlist-based HTTP probing.

Each candidate path from the wordlist is requested against the target.
Soft-404 detection (identical to dir_scan) filters out false positives.
Responses are annotated with useful notes (JSON, auth-required, etc.).
"""
from __future__ import annotations

import asyncio
import logging
import random
import string
from pathlib import Path

import httpx

from asfoor.core.models import ApiEndpointResult
from asfoor.utils.http_client import build_client
from asfoor.utils.rate_limiter import RateLimiter
from asfoor.utils.wordlist_utils import concurrency_for_size, load_wordlist, resolve_wordlist_path

logger = logging.getLogger("asfoor.api_scan")

DEFAULT_API_WORDLIST = resolve_wordlist_path("api", "small")


def _annotate(status_code: int, content_type: str | None) -> str | None:
    """Generate a human-readable note for the endpoint response."""
    notes: list[str] = []

    if content_type:
        ct_lower = content_type.lower()
        if "json" in ct_lower:
            notes.append("Returns JSON")
        elif "xml" in ct_lower:
            notes.append("Returns XML")
        elif "html" in ct_lower:
            notes.append("Returns HTML")

    if status_code == 401:
        notes.append("401 — authentication required")
    elif status_code == 403:
        notes.append("403 — forbidden")
    elif status_code == 405:
        notes.append("405 — method not allowed (endpoint exists)")
    elif status_code >= 500:
        notes.append(f"{status_code} — server error")

    return "; ".join(notes) if notes else None


async def _get_baseline_signature(client: httpx.AsyncClient, base_url: str) -> tuple[int, int]:
    """Request a random nonexistent API path to detect soft-404 behaviour."""
    nonce = "".join(random.choices(string.ascii_lowercase, k=20))
    url = f"{base_url}/api/{nonce}-doesnotexist"
    try:
        resp = await client.head(url)
        if resp.status_code in (405, 501):
            resp = await client.get(url)
    except httpx.HTTPError:
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            return 404, 0

    content_length = int(resp.headers.get("Content-Length", 0)) if resp.request.method == "HEAD" else len(resp.content)
    return resp.status_code, content_length


def _is_soft_404(status_code: int, content_length: int, baseline: tuple[int, int]) -> bool:
    base_status, base_len = baseline
    if status_code != base_status:
        return False
    if base_len == 0:
        return False
    return abs(content_length - base_len) / base_len < 0.05


async def _check_endpoint(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    baseline: tuple[int, int],
    rate_limiter: RateLimiter,
    sem: asyncio.Semaphore,
    results: list[ApiEndpointResult],
) -> None:
    """Probe a single API endpoint."""
    async with sem:
        await rate_limiter.wait()
        url = f"{base_url}/{path}"
        try:
            resp = await client.head(url)
            if resp.status_code in (405, 501):
                resp = await client.get(url)
        except httpx.HTTPError:
            try:
                resp = await client.get(url)
            except httpx.HTTPError as e:
                logger.debug("Request failed for %s: %s", url, e)
                return

        if resp.status_code == 404:
            return

        content_length = int(resp.headers.get("Content-Length", 0)) if resp.request.method == "HEAD" else len(resp.content)

        if _is_soft_404(resp.status_code, content_length, baseline):
            return

        content_type = resp.headers.get("Content-Type")
        note = _annotate(resp.status_code, content_type)

        results.append(ApiEndpointResult(
            path=path,
            status_code=resp.status_code,
            content_type=content_type,
            size=content_length,
            note=note,
        ))
        logger.debug("Found API endpoint: /%s -> %d", path, resp.status_code)


async def scan_api_endpoints(
    domain: str,
    config: dict,
    wordlist_size: str = "small",
    wordlist_path: Path | None = None,
) -> list[ApiEndpointResult]:
    """Discover API endpoints on *domain* using a wordlist.

    Parameters
    ----------
    domain:
        The target domain, e.g. ``example.com``.
    config:
        The merged application config dict.
    wordlist_size:
        ``"small"``, ``"medium"``, or ``"large"`` — selects the bundled
        seclists wordlist and auto-scales concurrency.
    wordlist_path:
        Optional explicit path to a custom wordlist.  Overrides
        ``wordlist_size`` when provided.
    """
    api_cfg = config.get("api_scan", {})
    http_cfg = config.get("http", {})

    if wordlist_path is None:
        wordlist_path = resolve_wordlist_path("api", wordlist_size) or DEFAULT_API_WORDLIST
    if wordlist_path is None:
        logger.warning("No API wordlist found; skipping API endpoint scan.")
        return []

    words = load_wordlist(wordlist_path)
    if not words:
        logger.warning("API wordlist is empty; skipping.")
        return []

    base_concurrency = api_cfg.get("concurrency", 20)
    concurrency = concurrency_for_size(wordlist_size, base=base_concurrency)
    rate_limit = api_cfg.get("rate_limit_seconds", 0.0)

    client_kwargs = dict(
        timeout_seconds=http_cfg.get("timeout_seconds", 10),
        max_redirects=http_cfg.get("max_redirects", 5),
        user_agent=http_cfg.get("user_agent", "3asfoor/1.0"),
    )

    results: list[ApiEndpointResult] = []

    async with build_client(**client_kwargs) as client:
        # Determine reachable base URL
        base_url = None
        for scheme in ("https", "http"):
            candidate = f"{scheme}://{domain}"
            try:
                resp = await client.get(candidate)
                base_url = str(resp.url).rstrip("/")
                break
            except httpx.HTTPError:
                continue

        if base_url is None:
            logger.warning("Could not reach %s for API endpoint scanning", domain)
            return []

        baseline = await _get_baseline_signature(client, base_url)
        rate_limiter = RateLimiter(rate_limit)
        sem = asyncio.Semaphore(concurrency)

        tasks = [
            _check_endpoint(client, base_url, path, baseline, rate_limiter, sem, results)
            for path in words
        ]
        await asyncio.gather(*tasks)

    results.sort(key=lambda r: r.path)
    logger.info("API scan complete: %d endpoints found out of %d candidates", len(results), len(words))
    return results
