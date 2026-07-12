"""Technology fingerprinting: detects CMS/frameworks/servers/libraries and
their versions from HTTP headers, cookies, HTML body, and linked assets.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from urllib.parse import urljoin

import httpx

from asfoor.core.models import Technology
from asfoor.utils.http_client import build_client

logger = logging.getLogger("asfoor.fingerprint")

DEFAULT_SIGNATURES_PATH = Path(__file__).resolve().parents[2] / "data" / "signatures" / "technologies.json"

# How many linked script/link assets to actually fetch and inspect for version strings.
MAX_ASSETS_TO_FETCH = 15


def load_signatures(path: Path | None = None) -> dict:
    sig_path = path or DEFAULT_SIGNATURES_PATH
    with open(sig_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _extract_assets(html: str, base_url: str) -> list[str]:
    """Pull absolute URLs for <script src> and <link href> tags out of raw HTML."""
    urls = []
    for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        urls.append(urljoin(base_url, match.group(1)))
    for match in re.finditer(r'<link[^>]+href=["\']([^"\']+)["\']', html, re.IGNORECASE):
        urls.append(urljoin(base_url, match.group(1)))
    return urls[:MAX_ASSETS_TO_FETCH]


def _match_rule(pattern: str, text: str) -> re.Match | None:
    try:
        return re.search(pattern, text, re.IGNORECASE)
    except re.error:
        logger.debug("Invalid regex pattern skipped: %s", pattern)
        return None


async def fingerprint(domain: str, config: dict, signatures: dict | None = None) -> list[Technology]:
    """Fetch the target site and match collected data against signature rules.

    Returns deduplicated, highest-confidence Technology entries.
    """
    signatures = signatures or load_signatures()
    http_cfg = config.get("http", {})

    client_kwargs = dict(
        timeout_seconds=http_cfg.get("timeout_seconds", 10),
        max_redirects=http_cfg.get("max_redirects", 5),
        user_agent=http_cfg.get("user_agent", "3asfoor/1.0"),
    )

    found: dict[str, Technology] = {}

    async with build_client(**client_kwargs) as client:
        response = await _fetch_homepage(client, domain)
        if response is None:
            logger.warning("Could not reach %s over HTTP or HTTPS", domain)
            return []

        base_url = str(response.url)
        html = response.text
        headers = response.headers
        cookies = response.cookies

        meta_generator = ""
        meta_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if meta_match:
            meta_generator = meta_match.group(1)

        # Fetch a handful of linked assets to check filenames/content for version strings.
        asset_urls = _extract_assets(html, base_url)
        asset_texts: dict[str, str] = {}
        for asset_url in asset_urls:
            try:
                asset_resp = await client.get(asset_url)
                # Only keep filename + first chunk of body; full JS bundles aren't needed.
                asset_texts[asset_url] = asset_url + "\n" + asset_resp.text[:2000]
            except httpx.HTTPError:
                continue

        for name, rule in signatures.items():
            match = _evaluate_rule(name, rule, html, headers, cookies, meta_generator, asset_urls, asset_texts)
            if match:
                existing = found.get(name)
                if existing is None or match.confidence > existing.confidence:
                    found[name] = match

    return sorted(found.values(), key=lambda t: (-t.confidence, t.name))


def _evaluate_rule(name: str, rule: dict, html: str, headers: httpx.Headers,
                    cookies: httpx.Cookies, meta_generator: str,
                    asset_urls: list[str], asset_texts: dict[str, str]) -> Technology | None:
    category = rule.get("category", "Other")

    # Header match — highest confidence signal.
    for header_name, pattern in rule.get("headers", {}).items():
        header_value = headers.get(header_name)
        if header_value:
            m = _match_rule(pattern, header_value)
            if m:
                version = m.group(1) if m.groups() else None
                return Technology(name=name, version=version, category=category,
                                   confidence=95, evidence=f"Header {header_name}: {header_value}")

    # Meta generator tag — high confidence.
    for pattern in rule.get("meta", {}).values():
        m = _match_rule(pattern, meta_generator)
        if m:
            version = m.group(1) if m.groups() else None
            return Technology(name=name, version=version, category=category,
                               confidence=90, evidence=f"meta generator: {meta_generator}")

    # Cookie name match — medium-high confidence, no version info typically.
    for cookie_name in rule.get("cookies", []):
        if cookie_name in cookies:
            return Technology(name=name, version=None, category=category,
                               confidence=75, evidence=f"Cookie present: {cookie_name}")

    # Script/asset filename match — can carry version in filename.
    for pattern in rule.get("script", []):
        for asset_url in asset_urls:
            m = _match_rule(pattern, asset_url)
            if m:
                version = m.group(1) if m.groups() else None
                return Technology(name=name, version=version, category=category,
                                   confidence=80, evidence=f"Asset URL: {asset_url}")
        for asset_url, text in asset_texts.items():
            m = _match_rule(pattern, text)
            if m:
                version = m.group(1) if m.groups() else None
                return Technology(name=name, version=version, category=category,
                                   confidence=70, evidence=f"Asset content: {asset_url}")

    # Generic HTML body string match — lowest confidence, no version typically.
    for pattern in rule.get("html", []):
        m = _match_rule(pattern, html)
        if m:
            version = m.group(1) if m.groups() else None
            return Technology(name=name, version=version, category=category,
                               confidence=55, evidence=f"HTML contains pattern: {pattern}")

    return None


async def _fetch_homepage(client: httpx.AsyncClient, domain: str) -> httpx.Response | None:
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            resp = await client.get(url)
            return resp
        except httpx.HTTPError as e:
            logger.debug("Failed to fetch %s: %s", url, e)
            continue
    return None
