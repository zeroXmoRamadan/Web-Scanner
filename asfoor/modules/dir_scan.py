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

logger = logging.getLogger("asfoor.dir_scan")

DEFAULT_DIRS_WORDLIST = Path(__file__).resolve().parents[2] / "data" / "wordlists" / "common_dirs.txt"
DEFAULT_SENSITIVE_WORDLIST = Path(__file__).resolve().parents[2] / "data" / "wordlists" / "sensitive_files.txt"

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


def _load_wordlist(path: Path) -> list[str]:
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


async def _get_baseline_signature(client: httpx.AsyncClient, base_url: str) -> tuple[int, int]:
    """Request a random nonexistent path to detect soft-404 behavior.
    Returns (status_code, approx_content_length) of the 'not found' response.
    """
    nonce = "".join(random.choices(string.ascii_lowercase, k=20))
    try:
        resp = await client.get(f"{base_url}/{nonce}-doesnotexist")
        return resp.status_code, len(resp.content)
    except httpx.HTTPError:
        return 404, 0


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
        resp = await client.get(url)
    except httpx.HTTPError as e:
        logger.debug("Request failed for %s: %s", url, e)
        return

    if resp.status_code == 404:
        return
    if _is_soft_404(resp.status_code, len(resp.content), baseline):
        return

    note = SENSITIVE_NOTES.get(path) if is_sensitive else None
    if is_sensitive and note is None:
        note = "Matched known-sensitive path list — review manually."

    results.append(DirResult(
        path=path,
        status_code=resp.status_code,
        content_type=resp.headers.get("Content-Type"),
        size=len(resp.content),
        is_sensitive=is_sensitive,
        note=note,
    ))


async def scan_directories(domain: str, config: dict,
                            dirs_wordlist_path: Path | None = None,
                            sensitive_wordlist_path: Path | None = None) -> list[DirResult]:
    dir_cfg = config.get("dir_scan", {})
    http_cfg = config.get("http", {})

    client_kwargs = dict(
        timeout_seconds=http_cfg.get("timeout_seconds", 10),
        max_redirects=http_cfg.get("max_redirects", 5),
        user_agent=http_cfg.get("user_agent", "3asfoor/1.0"),
    )

    dirs_words = _load_wordlist(dirs_wordlist_path or DEFAULT_DIRS_WORDLIST)
    sensitive_words = _load_wordlist(sensitive_wordlist_path or DEFAULT_SENSITIVE_WORDLIST)

    rate_limiter = RateLimiter(dir_cfg.get("rate_limit_seconds", 0.1))
    concurrency = dir_cfg.get("concurrency", 20)

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
