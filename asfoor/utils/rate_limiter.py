"""A tiny asyncio-friendly rate limiter used by the directory scanner."""
from __future__ import annotations

import asyncio


class RateLimiter:
    """Ensures at least `delay_seconds` passes between successive `wait()` calls
    across all concurrent tasks sharing this limiter instance.
    """

    def __init__(self, delay_seconds: float = 0.1):
        self.delay_seconds = delay_seconds
        self._lock = asyncio.Lock()
        self._last_call = 0.0

    async def wait(self) -> None:
        async with self._lock:
            loop = asyncio.get_event_loop()
            now = loop.time()
            elapsed = now - self._last_call
            if elapsed < self.delay_seconds:
                await asyncio.sleep(self.delay_seconds - elapsed)
            self._last_call = loop.time()
