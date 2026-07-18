"""Local CVE database — the primary data source for scan-time CVE matching.

Schema uses two tables to handle the many-to-many relationship between CVEs
and affected CPE products:

  ``cve_records``       — one row per CVE (cve_id PK)
  ``cve_cpe_matches``   — one row per (CVE, CPE vendor/product) pair

Scan-time queries hit the local DB only and never make live NVD API calls.
The ``cve-sync`` CLI subcommand populates/refreshes this database from the
NVD API using the rate limiter and date-chunking utilities.

**Migration note for existing users**: the old ``cve_cache`` table (from the
ad-hoc caching layer) is incompatible with this schema.  Delete the old
``data/cve_cache.sqlite3`` and re-run ``3asfoor cve-sync --full``.
"""
from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from asfoor.core.models import CVEEntry

logger = logging.getLogger("asfoor.cve_db")

CURRENT_SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# Schema & migration
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS cve_records (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    cvss_score REAL,
    severity TEXT,
    published_date TEXT,
    last_modified_date TEXT,
    source_last_synced TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cve_cpe_matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL REFERENCES cve_records(cve_id) ON DELETE CASCADE,
    cpe_vendor TEXT NOT NULL,
    cpe_product TEXT NOT NULL,
    cpe_version_start TEXT,
    cpe_version_end TEXT
);

CREATE INDEX IF NOT EXISTS idx_cpe_vendor_product
    ON cve_cpe_matches(cpe_vendor, cpe_product);

CREATE INDEX IF NOT EXISTS idx_cpe_matches_cve_id
    ON cve_cpe_matches(cve_id);

CREATE TABLE IF NOT EXISTS sync_state (
    sync_id INTEGER PRIMARY KEY AUTOINCREMENT,
    sync_type TEXT NOT NULL,
    last_completed_chunk_end TEXT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL DEFAULT 'in_progress'
);
"""


def init_cve_db(db_path: Path) -> sqlite3.Connection:
    """Open (or create) the CVE database and ensure the schema is current.

    Idempotent — safe to call on every startup.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    """Create tables if missing, run migrations if version is outdated."""
    conn.executescript(_SCHEMA_SQL)
    conn.execute("DROP TABLE IF EXISTS cve_cache")

    row = conn.execute(
        "SELECT MAX(version) FROM schema_version"
    ).fetchone()
    current = row[0] if row and row[0] is not None else 0

    if current < CURRENT_SCHEMA_VERSION:
        # No incremental migrations yet — just stamp the version.
        conn.execute(
            "INSERT OR REPLACE INTO schema_version (version) VALUES (?)",
            (CURRENT_SCHEMA_VERSION,),
        )
        conn.commit()

    logger.debug("CVE DB schema at version %d", CURRENT_SCHEMA_VERSION)


# ---------------------------------------------------------------------------
# Data operations
# ---------------------------------------------------------------------------

def upsert_cve_records(
    conn: sqlite3.Connection,
    records: list[dict],
    synced_at: str | None = None,
) -> int:
    """Insert or update CVE records and their CPE matches.

    Each item in *records* should have the structure returned by
    ``parse_nvd_cve_item()``.  Returns the number of CVE records upserted.

    This is safe to call repeatedly with the same data — duplicates are
    merged via ``INSERT OR REPLACE``.
    """
    if synced_at is None:
        synced_at = datetime.now(timezone.utc).isoformat()

    count = 0
    for rec in records:
        conn.execute(
            """INSERT OR REPLACE INTO cve_records
               (cve_id, description, cvss_score, severity,
                published_date, last_modified_date, source_last_synced)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                rec["cve_id"],
                rec.get("description", ""),
                rec.get("cvss_score"),
                rec.get("severity", "UNKNOWN"),
                rec.get("published_date"),
                rec.get("last_modified_date"),
                synced_at,
            ),
        )

        # Remove old CPE matches for this CVE, then re-insert.
        conn.execute(
            "DELETE FROM cve_cpe_matches WHERE cve_id = ?", (rec["cve_id"],)
        )
        for match in rec.get("cpe_matches", []):
            conn.execute(
                """INSERT INTO cve_cpe_matches
                   (cve_id, cpe_vendor, cpe_product,
                    cpe_version_start, cpe_version_end)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    rec["cve_id"],
                    match["vendor"],
                    match["product"],
                    match.get("version_start"),
                    match.get("version_end"),
                ),
            )
        count += 1

    conn.commit()
    return count


def query_cves_for_cpe(
    conn: sqlite3.Connection,
    vendor: str,
    product: str,
    version: str | None = None,
) -> list[CVEEntry]:
    """Query the local DB for CVEs matching a CPE vendor/product pair.

    Returns a list of ``CVEEntry`` objects sorted by score (descending).
    """
    rows = conn.execute(
        """SELECT DISTINCT r.cve_id, r.severity, r.cvss_score,
                  r.description, r.published_date
           FROM cve_records r
           JOIN cve_cpe_matches m ON r.cve_id = m.cve_id
           WHERE m.cpe_vendor = ? AND m.cpe_product = ?
           ORDER BY r.cvss_score DESC""",
        (vendor, product),
    ).fetchall()

    entries: list[CVEEntry] = []
    for cve_id, severity, score, desc, pub_date in rows:
        entries.append(
            CVEEntry(
                cve_id=cve_id,
                severity=severity or "UNKNOWN",
                score=score,
                summary=(desc or "")[:500],
                published_date=pub_date,
                references=[],
            )
        )
    return entries


def is_db_populated(conn: sqlite3.Connection) -> bool:
    """Return True if the CVE database has at least one record."""
    row = conn.execute("SELECT COUNT(*) FROM cve_records").fetchone()
    return (row[0] or 0) > 0


def get_last_sync_time(conn: sqlite3.Connection) -> datetime | None:
    """Return the timestamp of the most recent successful sync, or None."""
    row = conn.execute(
        """SELECT completed_at FROM sync_state
           WHERE status = 'completed'
           ORDER BY completed_at DESC LIMIT 1"""
    ).fetchone()
    if row and row[0]:
        try:
            return datetime.fromisoformat(row[0].replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None
    return None


def record_sync_start(
    conn: sqlite3.Connection, sync_type: str
) -> int:
    """Record the start of a sync operation. Returns the sync_id."""
    cursor = conn.execute(
        """INSERT INTO sync_state (sync_type, started_at, status)
           VALUES (?, ?, 'in_progress')""",
        (sync_type, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    return cursor.lastrowid  # type: ignore[return-value]


def update_sync_progress(
    conn: sqlite3.Connection,
    sync_id: int,
    last_chunk_end: str,
) -> None:
    """Update the last completed chunk end for a running sync."""
    conn.execute(
        """UPDATE sync_state
           SET last_completed_chunk_end = ?
           WHERE sync_id = ?""",
        (last_chunk_end, sync_id),
    )
    conn.commit()


def complete_sync(conn: sqlite3.Connection, sync_id: int) -> None:
    """Mark a sync as completed."""
    conn.execute(
        """UPDATE sync_state
           SET status = 'completed',
               completed_at = ?
           WHERE sync_id = ?""",
        (datetime.now(timezone.utc).isoformat(), sync_id),
    )
    conn.commit()


def get_last_full_sync_progress(
    conn: sqlite3.Connection,
) -> str | None:
    """Return the ``last_completed_chunk_end`` of the most recent
    in-progress full sync, for resuming an interrupted backfill.
    """
    row = conn.execute(
        """SELECT last_completed_chunk_end FROM sync_state
           WHERE sync_type = 'full' AND status = 'in_progress'
           ORDER BY sync_id DESC LIMIT 1"""
    ).fetchone()
    return row[0] if row else None


# ---------------------------------------------------------------------------
# NVD response parsing helpers (used by cve-sync)
# ---------------------------------------------------------------------------

def parse_nvd_cve_item(vuln: dict) -> dict:
    """Parse a single NVD API 2.0 vulnerability item into a flat dict
    suitable for ``upsert_cve_records()``.
    """
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")

    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"), ""
    )

    severity, score = _severity_from_cve_item(cve)
    published = cve.get("published")
    last_modified = cve.get("lastModified")

    # Extract CPE matches from configurations.
    cpe_matches = _extract_cpe_matches(cve)

    return {
        "cve_id": cve_id,
        "description": description[:2000],
        "cvss_score": score,
        "severity": severity,
        "published_date": published,
        "last_modified_date": last_modified,
        "cpe_matches": cpe_matches,
    }


def _severity_from_cve_item(cve_item: dict) -> tuple[str, float | None]:
    """Extract severity/score from NVD metrics, preferring CVSS v3.1."""
    metrics = cve_item.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            data = metrics[key][0]["cvssData"]
            score = data.get("baseScore")
            severity = data.get("baseSeverity")
            if not severity and score is not None:
                if score >= 9.0:
                    severity = "CRITICAL"
                elif score >= 7.0:
                    severity = "HIGH"
                elif score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            return (severity.upper() if severity else "UNKNOWN"), score
    return "UNKNOWN", None


def _extract_cpe_matches(cve: dict) -> list[dict]:
    """Extract CPE vendor/product pairs from NVD configurations."""
    matches: list[dict] = []
    seen = set()

    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]
                    key = (vendor, product)
                    if key not in seen:
                        seen.add(key)
                        matches.append({
                            "vendor": vendor,
                            "product": product,
                            "version_start": match.get("versionStartIncluding"),
                            "version_end": match.get("versionEndIncluding"),
                        })

    return matches
