"""Proactive rate limiter and exponential-backoff retry helper for NVD API.

The NVD API enforces these documented limits:
  - Without API key: 5 requests per 30-second rolling window
  - With NVD_API_KEY:  50 requests per 30-second rolling window

This module provides:
  1. ``NvdTokenBucket`` — a sliding-window token bucket that pre-throttles
     to stay within budget *proactively* (primary strategy).
  2. ``nvd_request_with_retry`` — an async retry wrapper that catches HTTP
     429/403 and applies exponential backoff with jitter as a *fallback* for
     edge cases where the proactive limiter is insufficient.
"""
from __future__ import annotations

import asyncio
import logging
import os
import random
from collections import deque
from typing import Any

import httpx

logger = logging.getLogger("asfoor.nvd_rate_limiter")

# ---------------------------------------------------------------------------
# Sliding-window token bucket
# ---------------------------------------------------------------------------

WINDOW_SECONDS = 30.0


class NvdTokenBucket:
    """Sliding-window rate limiter that stays within NVD's request budget.

    Automatically detects whether an ``NVD_API_KEY`` is set and selects the
    appropriate budget (50 req/30 s with key, 5 req/30 s without).
    """

    def __init__(self, *, has_api_key: bool | None = None) -> None:
        if has_api_key is None:
            has_api_key = bool(os.environ.get("NVD_API_KEY"))
        self._max_tokens = 50 if has_api_key else 5
        self._window = WINDOW_SECONDS
        # Each entry is a timestamp (loop.time()) of a consumed token.
        self._timestamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    @property
    def max_tokens(self) -> int:
        return self._max_tokens

    async def acquire(self) -> None:
        """Wait until a token is available, then consume it."""
        async with self._lock:
            loop = asyncio.get_event_loop()
            now = loop.time()

            # Purge timestamps older than the window.
            while self._timestamps and (now - self._timestamps[0]) >= self._window:
                self._timestamps.popleft()

            if len(self._timestamps) >= self._max_tokens:
                # Must wait until the oldest token expires out of the window.
                wait_until = self._timestamps[0] + self._window
                delay = wait_until - now
                if delay > 0:
                    logger.debug(
                        "NVD rate limiter: budget exhausted, sleeping %.2fs", delay
                    )
                    await asyncio.sleep(delay)

                # Re-read time and purge again after sleeping.
                now = loop.time()
                while self._timestamps and (now - self._timestamps[0]) >= self._window:
                    self._timestamps.popleft()

            self._timestamps.append(loop.time())


# ---------------------------------------------------------------------------
# Retry helper with exponential backoff + jitter
# ---------------------------------------------------------------------------

_RETRYABLE_STATUS_CODES = frozenset({403, 429})


async def nvd_request_with_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 20.0,
    bucket: NvdTokenBucket | None = None,
    max_retries: int = 5,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    jitter: float = 0.5,
) -> httpx.Response | None:
    """Send a GET request to the NVD API with proactive rate limiting and
    exponential backoff on 429/403 responses.

    Returns the :class:`httpx.Response` on success, or ``None`` if all
    retries are exhausted (caller should treat this as a graceful failure).
    """
    for attempt in range(max_retries + 1):
        # Proactive rate limiting.
        if bucket is not None:
            await bucket.acquire()

        try:
            resp = await client.get(
                url, params=params, headers=headers, timeout=timeout
            )
        except httpx.HTTPError as exc:
            logger.warning(
                "NVD request failed (attempt %d/%d): %s",
                attempt + 1,
                max_retries + 1,
                exc,
            )
            if attempt >= max_retries:
                return None
            delay = _compute_delay(attempt, base_delay, max_delay, jitter)
            await asyncio.sleep(delay)
            continue

        if resp.status_code not in _RETRYABLE_STATUS_CODES:
            # Success or a non-retryable error — return as-is.
            return resp

        # Retryable status code — compute backoff.
        if attempt >= max_retries:
            logger.warning(
                "NVD request exhausted retries (HTTP %d) for %s",
                resp.status_code,
                url,
            )
            return None

        # Honour Retry-After if present.
        retry_after = resp.headers.get("Retry-After")
        if retry_after is not None:
            try:
                delay = float(retry_after)
            except ValueError:
                delay = _compute_delay(attempt, base_delay, max_delay, jitter)
        else:
            delay = _compute_delay(attempt, base_delay, max_delay, jitter)

        logger.info(
            "NVD returned HTTP %d (attempt %d/%d) — retrying in %.2fs",
            resp.status_code,
            attempt + 1,
            max_retries + 1,
            delay,
        )
        await asyncio.sleep(delay)

    return None  # pragma: no cover — loop always returns before here


def _compute_delay(
    attempt: int, base_delay: float, max_delay: float, jitter: float
) -> float:
    """Exponential backoff with jitter, capped at *max_delay*."""
    delay = base_delay * (2 ** attempt) + random.uniform(0, jitter)
    return min(delay, max_delay)
