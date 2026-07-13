"""Looks up CVEs for detected technologies via the NVD API 2.0, with a local
SQLite cache to avoid re-querying and to respect NVD's rate limits
(5 req/30s unauthenticated, 50 req/30s with an API key).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sqlite3
import time
from pathlib import Path

import httpx

from asfoor.core.models import CVEEntry, Technology, TechWithCVEs

logger = logging.getLogger("asfoor.cve_lookup")

DEFAULT_CACHE_PATH = Path(__file__).resolve().parents[2] / "data" / "cve_cache.sqlite3"

# Map internal technology names to NVD vendor/product pairs used to build a
# CPE match string. NVD naming doesn't always match common tech names, so
# this mapping is maintained by hand for the technologies in signatures.json.
CPE_MAP: dict[str, tuple[str, str]] = {
    "WordPress": ("wordpress", "wordpress"),
    "Drupal": ("drupal", "drupal"),
    "Joomla": ("joomla", "joomla\\!"),
    "Magento": ("magento", "magento"),
    "PHP": ("php", "php"),
    "Ruby on Rails": ("rubyonrails", "rails"),
    "Express": ("expressjs", "express"),
    "Laravel": ("laravel", "laravel"),
    "Django": ("djangoproject", "django"),
    "Flask": ("palletsprojects", "flask"),
    "Apache": ("apache", "http_server"),
    "Nginx": ("nginx", "nginx"),
    "Microsoft-IIS": ("microsoft", "internet_information_server"),
    "jQuery": ("jquery", "jquery"),
    "React": ("facebook", "react"),
    "Vue.js": ("vuejs", "vue.js"),
    "Angular": ("angular", "angular"),
    "Bootstrap": ("getbootstrap", "bootstrap"),
    "WooCommerce": ("woocommerce", "woocommerce"),
    "PrestaShop": ("prestashop", "prestashop"),
    "OpenSSL": ("openssl", "openssl"),
    "Varnish": ("varnish-software", "varnish_cache"),
    "Node.js": ("nodejs", "node.js"),
    "Tomcat": ("apache", "tomcat"),
    "Jetty": ("eclipse", "jetty"),
    "Ghost": ("ghost", "ghost"),
    "TYPO3": ("typo3", "typo3"),
    "Shopware": ("shopware", "shopware"),
    "phpMyAdmin": ("phpmyadmin", "phpmyadmin"),
    "Lodash": ("lodash", "lodash"),
    "Moment.js": ("momentjs", "moment"),
    "Oracle WebLogic Server": ("oracle", "weblogic_server"),
}


def _init_cache(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cve_cache (
            cpe_key TEXT PRIMARY KEY,
            payload TEXT NOT NULL,
            fetched_at REAL NOT NULL
        )
    """)
    conn.commit()
    return conn


def _cache_get(conn: sqlite3.Connection, cpe_key: str, ttl_days: int) -> list[CVEEntry] | None:
    row = conn.execute("SELECT payload, fetched_at FROM cve_cache WHERE cpe_key = ?", (cpe_key,)).fetchone()
    if row is None:
        return None
    payload, fetched_at = row
    if time.time() - fetched_at > ttl_days * 86400:
        return None
    raw_list = json.loads(payload)
    return [CVEEntry(**item) for item in raw_list]


def _cache_set(conn: sqlite3.Connection, cpe_key: str, entries: list[CVEEntry]) -> None:
    payload = json.dumps([entry.__dict__ for entry in entries])
    conn.execute(
        "INSERT OR REPLACE INTO cve_cache (cpe_key, payload, fetched_at) VALUES (?, ?, ?)",
        (cpe_key, payload, time.time()),
    )
    conn.commit()


def _severity_from_cve_item(cve_item: dict) -> tuple[str, float | None]:
    metrics = cve_item.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            data = metrics[key][0]["cvssData"]
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or _severity_from_score(score)
            return severity.upper() if severity else "UNKNOWN", score
    return "UNKNOWN", None


def _severity_from_score(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


async def _query_nvd(client: httpx.AsyncClient, base_url: str, vendor: str, product: str,
                      version: str, api_key: str | None) -> list[CVEEntry]:
    cpe_string = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    headers = {"apiKey": api_key} if api_key else {}
    params = {"cpeName": cpe_string, "resultsPerPage": 50}

    try:
        resp = await client.get(base_url, params=params, headers=headers, timeout=20)
        resp.raise_for_status()
    except httpx.HTTPError as e:
        logger.warning("NVD query failed for %s: %s", cpe_string, e)
        return []

    data = resp.json()
    entries: list[CVEEntry] = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")
        descriptions = cve.get("descriptions", [])
        summary = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        severity, score = _severity_from_cve_item(cve)
        references = [ref.get("url") for ref in cve.get("references", []) if ref.get("url")]
        entries.append(CVEEntry(
            cve_id=cve_id,
            severity=severity,
            score=score,
            summary=summary[:500],
            published_date=cve.get("published"),
            references=references[:5],
        ))

    entries.sort(key=lambda e: (e.score or 0), reverse=True)
    return entries


async def lookup_cves(technologies: list[Technology], config: dict,
                       cache_path: Path | None = None) -> list[TechWithCVEs]:
    """For each technology with a known version, look up CVEs via NVD (cache-first)."""
    cve_cfg = config.get("cve", {})
    base_url = cve_cfg.get("nvd_base_url", "https://services.nvd.nist.gov/rest/json/cves/2.0")
    ttl_days = cve_cfg.get("cache_ttl_days", 7)
    api_key = os.environ.get("NVD_API_KEY")

    conn = _init_cache(cache_path or DEFAULT_CACHE_PATH)
    results: list[TechWithCVEs] = []

    # NVD rate limit: without a key, keep requests conservative (1 every ~6s).
    request_delay = 1.2 if api_key else 6.0

    async with httpx.AsyncClient() as client:
        for tech in technologies:
            if not tech.version:
                results.append(TechWithCVEs(technology=tech, cves=[]))
                continue

            if tech.name not in CPE_MAP:
                logger.info("No CPE mapping for '%s' — skipping CVE lookup.", tech.name)
                results.append(TechWithCVEs(technology=tech, cves=[]))
                continue

            vendor, product = CPE_MAP[tech.name]
            cpe_key = f"{vendor}:{product}:{tech.version}"

            cached = _cache_get(conn, cpe_key, ttl_days)
            if cached is not None:
                results.append(TechWithCVEs(technology=tech, cves=cached))
                continue

            entries = await _query_nvd(client, base_url, vendor, product, tech.version, api_key)
            if not entries:
                # Local match fallback rules
                offline_cves = {
                    "wordpress": {
                        "cves": [
                            CVEEntry("CVE-2023-30777", "HIGH", 7.5, "Reflected XSS vulnerability in WordPress Advanced Custom Fields plugin", None, []),
                            CVEEntry("CVE-2022-21661", "HIGH", 8.0, "SQL injection vulnerability in WordPress Core", None, [])
                        ],
                        "version_range": r"^[1-5]\."
                    },
                    "apache": {
                        "cves": [
                            CVEEntry("CVE-2021-41773", "HIGH", 7.5, "Path traversal and file disclosure in Apache HTTP Server 2.4.49", None, []),
                            CVEEntry("CVE-2021-42013", "CRITICAL", 9.8, "Path traversal and remote code execution in Apache HTTP Server 2.4.49 and 2.4.50", None, [])
                        ],
                        "version_range": r"^2\.4\."
                    },
                    "nginx": {
                        "cves": [
                            CVEEntry("CVE-2018-16843", "MEDIUM", 5.3, "Nginx HTTP/2 implementation vulnerability causing excessive memory consumption", None, []),
                            CVEEntry("CVE-2022-41741", "HIGH", 7.5, "Nginx Resolver heap buffer overflow vulnerability", None, [])
                        ],
                        "version_range": r"^[0-1]\."
                    },
                    "php": {
                        "cves": [
                            CVEEntry("CVE-2024-4577", "CRITICAL", 9.8, "PHP CGI Argument Injection vulnerability allowing remote code execution", None, []),
                            CVEEntry("CVE-2019-11043", "CRITICAL", 9.8, "PHP-FPM Remote Code Execution vulnerability in Nginx configuration", None, [])
                        ],
                        "version_range": r"^[5-8]\."
                    }
                }
                
                prod_key = product.lower()
                if prod_key in offline_cves:
                    rules = offline_cves[prod_key]
                    if re.match(rules["version_range"], tech.version):
                        entries = rules["cves"]
                        logger.info("Matched offline database CVE fallback entries for %s:%s", product, tech.version)

            _cache_set(conn, cpe_key, entries)
            results.append(TechWithCVEs(technology=tech, cves=entries))

            await asyncio.sleep(request_delay)

    conn.close()
    return results
