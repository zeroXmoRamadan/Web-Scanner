"""Technology fingerprinting powered by python-Wappalyzer.

Uses the Wappalyzer engine (community-maintained signature database) to detect
CMS/frameworks/servers/libraries and their versions from HTTP headers, cookies,
HTML body, meta tags, and script references.

python-Wappalyzer is a **hard dependency** — the tool will error if it is not
installed.
"""
from __future__ import annotations

import json
import logging
from importlib.resources import files as pkg_files
from pathlib import Path

import asfoor.utils.wappalyzer_compat  # noqa: F401  — shim pkg_resources for Python 3.12+
import httpx  # type: ignore[import-not-found]

from asfoor.core.models import Technology
from asfoor.utils.http_client import build_client

logger = logging.getLogger("asfoor.fingerprint")

# Resolve the bundled technologies.json shipped with python-Wappalyzer.
# We do this via importlib.resources instead of the deprecated pkg_resources
# that the library itself uses — this keeps us compatible with Python ≥ 3.9.
_WAPPALYZER_TECHNOLOGIES_PATH: Path | None = None
try:
    _pkg_data = pkg_files("Wappalyzer").joinpath("data", "technologies.json")
    _WAPPALYZER_TECHNOLOGIES_PATH = Path(str(_pkg_data))
except Exception:
    # Fallback: derive from the package's __file__
    try:
        import Wappalyzer as _wp_pkg  # type: ignore[import-not-found]
        _WAPPALYZER_TECHNOLOGIES_PATH = (
            Path(_wp_pkg.__file__).parent / "data" / "technologies.json"
        )
    except Exception:
        pass


def _load_wappalyzer(technologies_file: Path | str | None = None):
    """Initialise a Wappalyzer instance.

    Uses the bundled technologies.json by default, bypassing the deprecated
    ``pkg_resources`` call in ``Wappalyzer.latest()``.
    """
    from Wappalyzer import Wappalyzer as _Wappalyzer  # type: ignore[import-not-found]

    tech_path = technologies_file or _WAPPALYZER_TECHNOLOGIES_PATH
    if tech_path is None:
        raise RuntimeError(
            "Could not locate the Wappalyzer technologies.json database. "
            "Make sure python-Wappalyzer is installed: pip install python-Wappalyzer"
        )

    with open(tech_path, "r", encoding="utf-8") as f:
        obj = json.load(f)

    # Inject Oracle WebLogic Server signature to allow fingerprinting WebLogic Server
    # and extracting its version.
    if "Oracle WebLogic Server" not in obj.get("technologies", {}):
        obj.setdefault("technologies", {})["Oracle WebLogic Server"] = {
            "cats": [22],
            "headers": {
                "server": r"WebLogic(?:\s+Server)?(?:\s*\(?([\d.]+)\)?)?\;version:\1",
                "set-cookie": r"ADMINCONSOLESESSION"
            }
        }

    return _Wappalyzer(categories=obj["categories"], technologies=obj["technologies"])


def _make_webpage(url: str, html: str, headers: dict):
    """Construct a Wappalyzer WebPage from already-fetched response data.

    This avoids an extra HTTP request — we feed in the data our httpx client
    already retrieved.
    """
    from Wappalyzer import WebPage  # type: ignore[import-not-found]
    lower_headers = {k.lower(): v for k, v in headers.items()}
    return WebPage(url=url, html=html, headers=lower_headers)


async def fingerprint(
    domain: str,
    config: dict,
    technologies_file: Path | str | None = None,
) -> list[Technology]:
    """Fetch the target site and run Wappalyzer analysis.

    Returns a list of :class:`Technology` entries sorted by confidence
    (descending).
    """
    wappalyzer = _load_wappalyzer(technologies_file)
    http_cfg = config.get("http", {})

    client_kwargs = dict(
        timeout_seconds=http_cfg.get("timeout_seconds", 10),
        max_redirects=http_cfg.get("max_redirects", 5),
        user_agent=http_cfg.get("user_agent", "3asfoor/1.0"),
    )

    async with build_client(**client_kwargs) as client:
        response = await _fetch_homepage(client, domain)
        if response is None:
            logger.warning("Could not reach %s over HTTP or HTTPS", domain)
            return []

        url = str(response.url)
        html = response.text
        headers = dict(response.headers)

    webpage = _make_webpage(url, html, headers)
    results = wappalyzer.analyze_with_versions_and_categories(webpage)

    technologies: list[Technology] = []
    for name, info in results.items():
        versions = info.get("versions", [])
        version = versions[-1] if versions else None  # longest/most specific
        categories = info.get("categories", [])
        category = categories[0] if categories else "Other"

        confidence = wappalyzer.get_confidence(name)
        if not isinstance(confidence, int):
            confidence = 100  # Wappalyzer returns [] when no explicit confidence → default 100

        technologies.append(Technology(
            name=name,
            version=version,
            category=category,
            confidence=confidence,
            evidence="Wappalyzer",
        ))

    return sorted(technologies, key=lambda t: (-t.confidence, t.name))


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
