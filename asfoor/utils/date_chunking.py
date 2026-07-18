"""Splits a date range into sequential, non-overlapping chunks for the NVD
API, which rejects date-range queries wider than 120 days.

Default chunk size is 90 days (safely under the 120-day hard limit).
Chunk boundaries are gap-free: each chunk's end equals the next chunk's
start minus one second, matching NVD's inclusive date semantics.
"""
from __future__ import annotations

from datetime import datetime, timedelta


def chunk_date_range(
    start: datetime,
    end: datetime,
    max_days: int = 90,
) -> list[tuple[datetime, datetime]]:
    """Split *[start, end]* into sequential chunks of at most *max_days* days.

    Returns a list of ``(chunk_start, chunk_end)`` tuples where:
      - ``chunk_end`` is at most ``max_days`` after ``chunk_start``
      - Consecutive chunks are contiguous: ``chunk[i].end + 1 second == chunk[i+1].start``
      - The final chunk's end equals *end*
      - If *end - start* ≤ *max_days* days, a single chunk is returned
      - If *start == end*, a single zero-width chunk is returned

    Raises ``ValueError`` if *end < start* or *max_days < 1*.
    """
    if end < start:
        raise ValueError(f"end ({end}) must be >= start ({start})")
    if max_days < 1:
        raise ValueError(f"max_days must be >= 1, got {max_days}")

    delta = timedelta(days=max_days)
    one_second = timedelta(seconds=1)
    chunks: list[tuple[datetime, datetime]] = []

    chunk_start = start
    while chunk_start <= end:
        chunk_end = min(chunk_start + delta, end)
        chunks.append((chunk_start, chunk_end))
        # Next chunk starts one second after this chunk's end.
        chunk_start = chunk_end + one_second

    return chunks
