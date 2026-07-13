"""Directory and sensitive-file discovery via wordlist-based requests.

Handles soft-404s (sites that return HTTP 200 for every path) by first
requesting a random nonexistent path and comparing later responses against
that baseline signature.
"""
from __future__ import annotations

import asyncio
import logging
import random
import string
from pathlib import Path

import httpx

from asfoor.core.models import DirResult
from asfoor.utils.http_client import build_client
from asfoor.utils.rate_limiter import RateLimiter
from asfoor.utils.wordlist_utils import concurrency_for_size, load_wordlist, resolve_wordlist_path

logger = logging.getLogger("asfoor.dir_scan")

DEFAULT_DIRS_WORDLIST = resolve_wordlist_path("dirs", "small")
DEFAULT_SENSITIVE_WORDLIST = resolve_wordlist_path("sensitive", "small")

SENSITIVE_NOTES = {
    ".env": "Environment file — may contain database credentials, API keys, secrets.",
    ".git/HEAD": "Exposed .git directory — full source repo may be reconstructable.",
    ".git/config": "Exposed .git directory — full source repo may be reconstructable.",
    "wp-config.php.bak": "WordPress config backup — likely contains DB credentials in plaintext.",
    "id_rsa": "Private SSH key exposed — critical, allows direct server/account access.",
    "backup.sql": "Database dump exposed — may contain user data and credentials.",
    "credentials.json": "Credentials file exposed.",
    ".aws/credentials": "AWS credentials exposed — critical, allows cloud account access.",
}




async def _get_baseline_signature(client: httpx.AsyncClient, base_url: str) -> tuple[int, int]:
    """Request a random nonexistent path to detect soft-404 behavior.
    Returns (status_code, approx_content_length) of the 'not found' response.
    """
    nonce = "".join(random.choices(string.ascii_lowercase, k=20))
    url = f"{base_url}/{nonce}-doesnotexist"
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
    # Treat as soft-404 if content length is within ~5% of the baseline "not found" page.
    if base_len == 0:
        return False
    return abs(content_length - base_len) / base_len < 0.05


async def _check_path(client: httpx.AsyncClient, base_url: str, path: str,
                       baseline: tuple[int, int], is_sensitive: bool,
                       rate_limiter: RateLimiter, results: list[DirResult]) -> None:
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

    note = SENSITIVE_NOTES.get(path) if is_sensitive else None
    if is_sensitive and note is None:
        note = "Matched known-sensitive path list — review manually."

    results.append(DirResult(
        path=path,
        status_code=resp.status_code,
        content_type=resp.headers.get("Content-Type"),
        size=content_length,
        is_sensitive=is_sensitive,
        note=note,
    ))


async def scan_directories(domain: str, config: dict,
                             dirs_wordlist_path: Path | None = None,
                             sensitive_wordlist_path: Path | None = None,
                             wordlist_size: str = "small") -> list[DirResult]:
    dir_cfg = config.get("dir_scan", {})
    http_cfg = config.get("http", {})

    client_kwargs = dict(
        timeout_seconds=http_cfg.get("timeout_seconds", 10),
        max_redirects=http_cfg.get("max_redirects", 5),
        user_agent=http_cfg.get("user_agent", "3asfoor/1.0"),
    )

    # If an explicit path was provided via --wordlist / --sensitive-wordlist,
    # honour it.  Otherwise pick from seclists based on the chosen size.
    if dirs_wordlist_path is None:
        dirs_wordlist_path = resolve_wordlist_path("dirs", wordlist_size) or DEFAULT_DIRS_WORDLIST
    if sensitive_wordlist_path is None:
        sensitive_wordlist_path = resolve_wordlist_path("sensitive", wordlist_size) or DEFAULT_SENSITIVE_WORDLIST

    dirs_words = load_wordlist(dirs_wordlist_path)
    sensitive_words = load_wordlist(sensitive_wordlist_path)

    rate_limiter = RateLimiter(dir_cfg.get("rate_limit_seconds", 0.0))
    # Auto-scale concurrency unless the user set --concurrency explicitly
    base_concurrency = dir_cfg.get("concurrency", 20)
    concurrency = concurrency_for_size(wordlist_size, base=base_concurrency)

    results: list[DirResult] = []

    async with build_client(**client_kwargs) as client:
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
            logger.warning("Could not reach %s for directory scanning", domain)
            return []

        baseline = await _get_baseline_signature(client, base_url)

        sem = asyncio.Semaphore(concurrency)

        async def bounded_check(path: str, is_sensitive: bool) -> None:
            async with sem:
                await _check_path(client, base_url, path, baseline, is_sensitive, rate_limiter, results)

        tasks = [bounded_check(p, False) for p in dirs_words]
        tasks += [bounded_check(p, True) for p in sensitive_words]
        await asyncio.gather(*tasks)

    results.sort(key=lambda r: (not r.is_sensitive, r.path))
    return results
