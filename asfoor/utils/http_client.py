"""Shared async HTTP client factory used by fingerprint.py and dir_scan.py."""
from __future__ import annotations

import httpx


def build_client(timeout_seconds: float = 10, max_redirects: int = 5,
                  user_agent: str = "3asfoor/1.0 (+educational use)") -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout_seconds),
        follow_redirects=True,
        max_redirects=max_redirects,
        headers={"User-Agent": user_agent},
        verify=False,  # many recon targets use self-signed/misconfigured certs; note this in README
        limits=httpx.Limits(max_connections=500, max_keepalive_connections=100),
    )
