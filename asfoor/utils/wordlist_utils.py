"""Shared wordlist resolution and concurrency auto-scaling utilities.

Every scan module that needs a wordlist (dir_scan, api_scan, subdomain_scan)
should import from here instead of reimplementing its own resolution logic.
"""
from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger("asfoor.wordlist_utils")

_SECLISTS_ROOT = Path(__file__).resolve().parents[2] / "seclists"

# Mapping of scan category -> seclists subdirectory
SECLISTS_CATEGORY = {
    "dirs": "directory_discovery",
    "sensitive": "sensitive_files_discovery",
    "api": "api_endpoints_discovery",
    "subdomains": "subdomain_discovery",
}

# Preferred fallback order when the requested size is unavailable
_SIZE_FALLBACK = {
    "small": ["small.txt"],
    "medium": ["medium.txt", "small.txt"],
    "large": ["large.txt", "medium.txt", "small.txt"],
}

# Concurrency multipliers keyed by wordlist size
_CONCURRENCY_MULTIPLIER = {
    "small": 1,
    "medium": 2,
    "large": 4,
}


def resolve_wordlist_path(category: str, size: str = "small") -> Path | None:
    """Return the wordlist path for *category* at the given *size*.

    Falls back through smaller sizes when the requested one doesn't exist.
    For categories with only a single file (e.g. sensitive_files_discovery
    which only has ``files.txt``), the lone file is returned regardless of
    the requested size.
    """
    cat_dir = _SECLISTS_ROOT / SECLISTS_CATEGORY.get(category, category)
    if not cat_dir.is_dir():
        return None

    # Try the requested size and its fallbacks
    for candidate in _SIZE_FALLBACK.get(size, [f"{size}.txt"]):
        path = cat_dir / candidate
        if path.is_file():
            return path

    # Last resort: if the directory has exactly one .txt file, use it
    txt_files = list(cat_dir.glob("*.txt"))
    if len(txt_files) == 1:
        return txt_files[0]

    return None


def load_wordlist(path: Path) -> list[str]:
    """Load a wordlist file, stripping blanks and comments."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def concurrency_for_size(size: str, base: int = 20) -> int:
    """Return an auto-scaled concurrency value based on wordlist *size*.

    - ``small``  → ``base`` (default 20)
    - ``medium`` → ``base * 2`` (40)
    - ``large``  → ``base * 4`` (80)
    """
    multiplier = _CONCURRENCY_MULTIPLIER.get(size, 1)
    scaled = base * multiplier
    logger.debug("Auto-scaled concurrency for size=%s: base=%d → %d", size, base, scaled)
    return scaled
