"""Subdomain discovery via DNS resolution and optional HTTP probing.

For each candidate word from the wordlist, ``{word}.{domain}`` is resolved
via DNS.  When a subdomain resolves, a lightweight HTTP GET is attempted to
grab the status code and ``<title>`` from the response.
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
from pathlib import Path

import httpx

from asfoor.core.models import SubdomainResult
from asfoor.utils.http_client import build_client
from asfoor.utils.wordlist_utils import concurrency_for_size, load_wordlist, resolve_wordlist_path

logger = logging.getLogger("asfoor.subdomain_scan")

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

DEFAULT_SUBDOMAIN_WORDLIST = resolve_wordlist_path("subdomains", "small")


def _resolve_dns(hostname: str) -> str | None:
    """Resolve *hostname* to an IPv4 address, or return ``None``."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


async def _resolve_dns_async(hostname: str, loop: asyncio.AbstractEventLoop) -> str | None:
    """Run DNS resolution in the default executor so it doesn't block the loop."""
    return await loop.run_in_executor(None, _resolve_dns, hostname)


async def _probe_http(client: httpx.AsyncClient, subdomain: str) -> tuple[int | None, str | None]:
    """Try an HTTP(S) GET and return ``(status_code, page_title)``."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            resp = await client.get(url)
            title = None
            match = _TITLE_RE.search(resp.text[:4096])
            if match:
                title = match.group(1).strip()[:120]
            return resp.status_code, title
        except (httpx.HTTPError, httpx.StreamError):
            continue
    return None, None


async def _check_subdomain(
    domain: str,
    word: str,
    loop: asyncio.AbstractEventLoop,
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    results: list[SubdomainResult],
) -> None:
    """Check a single subdomain candidate."""
    async with sem:
        fqdn = f"{word}.{domain}"
        ip = await _resolve_dns_async(fqdn, loop)
        if ip is None:
            return

        status_code, title = await _probe_http(client, fqdn)
        results.append(SubdomainResult(
            subdomain=fqdn,
            ip=ip,
            status_code=status_code,
            title=title,
        ))
        logger.debug("Found subdomain: %s -> %s (HTTP %s)", fqdn, ip, status_code)


async def scan_subdomains(
    domain: str,
    config: dict,
    wordlist_size: str = "small",
    wordlist_path: Path | None = None,
) -> list[SubdomainResult]:
    """Enumerate subdomains of *domain* using a wordlist.

    Parameters
    ----------
    domain:
        The base domain to enumerate, e.g. ``example.com``.
    config:
        The merged application config dict.
    wordlist_size:
        ``"small"``, ``"medium"``, or ``"large"`` — selects the bundled
        seclists wordlist and auto-scales concurrency.
    wordlist_path:
        Optional explicit path to a custom wordlist.  Overrides
        ``wordlist_size`` when provided.
    """
    sub_cfg = config.get("subdomain_scan", {})
    http_cfg = config.get("http", {})

    if wordlist_path is None:
        wordlist_path = resolve_wordlist_path("subdomains", wordlist_size) or DEFAULT_SUBDOMAIN_WORDLIST
    if wordlist_path is None:
        logger.warning("No subdomain wordlist found; skipping subdomain scan.")
        return []

    words = load_wordlist(wordlist_path)
    if not words:
        logger.warning("Subdomain wordlist is empty; skipping.")
        return []

    base_concurrency = sub_cfg.get("concurrency", 20)
    concurrency = concurrency_for_size(wordlist_size, base=base_concurrency)
    timeout = sub_cfg.get("timeout_seconds", 3)

    results: list[SubdomainResult] = []
    loop = asyncio.get_event_loop()
    sem = asyncio.Semaphore(concurrency)

    client_kwargs = dict(
        timeout_seconds=timeout,
        max_redirects=http_cfg.get("max_redirects", 3),
        user_agent=http_cfg.get("user_agent", "3asfoor/1.0"),
    )

    async with build_client(**client_kwargs) as client:
        tasks = [
            _check_subdomain(domain, word, loop, client, sem, results)
            for word in words
        ]
        await asyncio.gather(*tasks)

    results.sort(key=lambda r: r.subdomain)
    logger.info("Subdomain scan complete: %d found out of %d candidates", len(results), len(words))
    return results
