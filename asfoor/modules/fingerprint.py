"""Technology fingerprinting powered by wappalyzer-next.

Uses the ``wappalyzer`` package (https://github.com/AliasIO/wappalyzer) to
detect CMS/frameworks/servers/libraries and their versions from HTTP headers,
cookies, HTML body, meta tags, script references, DNS, and more.

Scan modes (controlled by ``--deep-fingerprint``):

* **Default (fast)** — HTTP-only analysis.  Fetches the page via a plain HTTP
  request (no browser) and matches headers, HTML, meta tags, and script
  references.  No Chromium/Playwright required.
* **Deep (full)** — JS-aware browser-based analysis via Playwright + headless
  Chromium.  Detects JS-framework technologies that require runtime DOM
  inspection (React, Vue.js, Angular rendered apps, Next.js, etc.).
  **⚠️ Passivity caveat:** this makes a browser-based request to the target
  which may trigger WAF alerts or logging.  Requires Chromium:
  ``python -m playwright install chromium``.
"""
from __future__ import annotations

import logging
import os
import sys
from contextlib import redirect_stderr

from wappalyzer import Wappalyzer as _WappalyzerScanner  # type: ignore[import-untyped]

from asfoor.core.models import Technology

logger = logging.getLogger("asfoor.fingerprint")


def _analyze_silent(scanner: _WappalyzerScanner, url: str) -> dict:
    with open(os.devnull, "w") as devnull:
        with redirect_stderr(devnull):
            return scanner.analyze(url)


async def fingerprint(
    domain: str,
    config: dict,
    deep_fingerprint: bool = False,
) -> list[Technology]:
    """Run wappalyzer-next technology detection against *domain*.

    Returns a list of :class:`Technology` entries sorted by confidence
    (descending, then alphabetically by name).

    Parameters
    ----------
    domain:
        Target domain (e.g. ``example.com``).
    config:
        Application config dict.
    deep_fingerprint:
        If *True*, uses ``scan_type="full"`` (Playwright + Chromium) for
        JS-aware detection.  Otherwise uses ``scan_type="fast"`` (HTTP-only,
        no browser required).
    """
    fp_cfg = config.get("fingerprint", {})
    http_cfg = config.get("http", {})
    timeout = fp_cfg.get("deep_timeout", http_cfg.get("timeout_seconds", 30))

    scan_type = "full" if deep_fingerprint else "fast"

    # Build the target URL — try HTTPS first, fall back to HTTP.
    url = f"https://{domain}"

    try:
        scanner = _WappalyzerScanner(scan_type=scan_type, timeout=timeout)
        results = _analyze_silent(scanner, url)
        scanner.close()
    except Exception as e:
        logger.debug("wappalyzer-next (%s) failed for %s over HTTPS: %s", scan_type, domain, e)
        # Fall back to HTTP.
        url = f"http://{domain}"
        try:
            scanner = _WappalyzerScanner(scan_type=scan_type, timeout=timeout)
            results = _analyze_silent(scanner, url)
            scanner.close()
        except Exception as e2:
            logger.warning("wappalyzer-next (%s) failed for %s: %s", scan_type, domain, e2)
            return []

    technologies: list[Technology] = []

    # results is {url: {tech_name: {version, confidence, categories, groups}}}
    for _result_url, techs in results.items():
        if not isinstance(techs, dict):
            continue
        for name, info in techs.items():
            if not isinstance(info, dict):
                continue
            version = info.get("version") or None
            # version may be an empty string — normalise to None
            if version == "":
                version = None

            confidence = info.get("confidence", 100)
            if not isinstance(confidence, (int, float)):
                confidence = 100

            categories = info.get("categories", [])
            category = categories[0] if categories else "Other"
            if not isinstance(category, str):
                category = str(category)

            evidence = f"wappalyzer-next ({scan_type})"

            technologies.append(Technology(
                name=name,
                version=version,
                category=category,
                confidence=int(confidence),
                evidence=evidence,
            ))

    return sorted(technologies, key=lambda t: (-t.confidence, t.name))
