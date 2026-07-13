"""Injection Point Detector module (passive analysis only — no payloads sent).
Parses parameters and inspects crawl responses for database errors, reflected values, and timing outliers.
"""
from __future__ import annotations

import math
import re
from urllib.parse import parse_qsl, urlparse
from typing import Optional

from asfoor.core.models import CrawlResponse, FormDetails, VulnerabilityFinding

DB_ERRORS = {
    "MySQL": [
        r"(?i)SQL syntax.*?MySQL",
        r"(?i)Warning.*?mysql_",
        r"(?i)valid MySQL result",
        r"(?i)MySqlClient\.",
        r"(?i)MySQL Database Error",
    ],
    "PostgreSQL": [
        r"(?i)PostgreSQL.*?ERROR",
        r"(?i)Warning.*?pg_",
        r"(?i)invalid input syntax for",
        r"(?i)pg_query\(\)",
        r"(?i)PostgreSQL query failed",
    ],
    "MSSQL": [
        r"(?i)Driver.*?SQL Server",
        r"(?i)OLE DB Provider.*?SQL Server",
        r"(?i)SqlException",
        r"(?i)Microsoft OLE DB Provider for SQL Server",
        r"(?i)Warning.*?mssql_",
    ],
    "Oracle": [
        r"(?i)ORA-\d{5}",
        r"(?i)Oracle error",
        r"(?i)Oracle.*?Driver",
        r"(?i)Warning.*?oci_",
    ],
    "SQLite": [
        r"(?i)SQLite/JDBC Driver",
        r"(?i)System.Data.SQLite.SQLiteException",
        r"(?i)Warning.*?sqlite_",
        r"(?i)sqlite3_prepare",
    ]
}


def classify_parameter_type(name: str, value: str) -> str:
    """Classifies parameter expected type based on naming patterns and value."""
    name_lower = name.lower()
    if value.isdigit() or any(x in name_lower for x in ("id", "page", "limit", "age", "offset", "port")):
        return "numeric"
    
    # Date formats: YYYY-MM-DD, MM/DD/YYYY, etc.
    date_pattern = r"^\d{4}[-/]\d{2}[-/]\d{2}$|^\d{2}[-/]\d{2}[-/]\d{4}$"
    if re.match(date_pattern, value) or any(x in name_lower for x in ("date", "time", "created", "updated")):
        return "date"
        
    if value.lower() in ("true", "false", "yes", "no", "admin", "user", "active", "inactive"):
        return "enum"
        
    return "string"


def _check_db_errors(body: str) -> tuple[str | None, str | None]:
    """Scans body for database error signatures. Returns (db_type, matched_error_text)."""
    for db_type, patterns in DB_ERRORS.items():
        for pattern in patterns:
            match = re.search(pattern, body)
            if match:
                # Extract surrounding context of the error
                start = max(0, match.start() - 50)
                end = min(len(body), match.end() + 150)
                evidence = body[start:end].strip()
                return db_type, f"... {evidence} ..."
    return None, None


def _calculate_timing_outliers(responses: list[CrawlResponse]) -> dict[str, tuple[float, float]]:
    """Groups responses by endpoint path and computes mean + stddev for response times.
    Returns a dict mapping path -> (mean, stddev).
    """
    path_times: dict[str, list[float]] = {}
    for resp in responses:
        path = urlparse(resp.url).path
        path_times.setdefault(path, []).append(resp.response_time)
        
    stats: dict[str, tuple[float, float]] = {}
    for path, times in path_times.items():
        if len(times) >= 3:
            mean = sum(times) / len(times)
            variance = sum((x - mean) ** 2 for x in times) / len(times)
            stddev = math.sqrt(variance)
            stats[path] = (mean, stddev)
    return stats


async def detect_injection_points(
    crawl_responses: list[CrawlResponse],
    forms: list[FormDetails]
) -> list[VulnerabilityFinding]:
    """Analyzes crawl responses passively for indicators of SQL or command injection."""
    findings: list[VulnerabilityFinding] = []
    
    # Calculate response-time statistics for outlier detection
    timing_stats = _calculate_timing_outliers(crawl_responses)
    
    for resp in crawl_responses:
        parsed_url = urlparse(resp.url)
        path = parsed_url.path
        
        # Get query parameters
        params = parse_qsl(parsed_url.query)
        if not params:
            continue
            
        # Check DB error signatures
        db_type, error_evidence = _check_db_errors(resp.body)
        
        for name, value in params:
            # Skip empty or tiny parameters to avoid false positives on reflections
            if not name or len(value) < 3:
                continue
                
            param_type = classify_parameter_type(name, value)
            
            signals = []
            evidence = ""
            
            # Signal 1: DB error signature present
            if db_type and error_evidence:
                signals.append(f"DB Error Signature ({db_type})")
                evidence = error_evidence
                
            # Signal 2: Verbatim reflection in response body
            # Check if value is reflected unescaped (e.g. not HTML escaped)
            if value in resp.body:
                # Quick verification if it is reflected unescaped:
                # If we look for the value, we also make sure it's not HTML escaped.
                escaped_val = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
                if escaped_val == value or escaped_val not in resp.body:
                    signals.append("Parameter Reflection")
                    if not evidence:
                        start = max(0, resp.body.find(value) - 40)
                        end = min(len(resp.body), resp.body.find(value) + len(value) + 40)
                        evidence = f"... {resp.body[start:end].strip()} ..."
                        
            # Signal 3: Timing outlier check
            is_outlier = False
            if path in timing_stats:
                mean, stddev = timing_stats[path]
                # Outlier threshold: mean + 3 * stddev, with a safety buffer of at least 1.0s
                if stddev > 0 and resp.response_time > (mean + 3 * stddev) and resp.response_time > 1.0:
                    is_outlier = True
                    signals.append("Timing Outlier")
                    
            if not signals:
                continue
                
            # Compute confidence score
            if len(signals) >= 2:
                confidence = "HIGH"
            elif "DB Error Signature (MySQL)" in signals or "DB Error Signature (PostgreSQL)" in signals or "DB Error Signature (MSSQL)" in signals:
                confidence = "HIGH"
            elif "Parameter Reflection" in signals:
                confidence = "MEDIUM"
            else:
                confidence = "LOW"
                
            description = (
                f"Passive analysis observed a potential injection point. "
                f"Parameter '{name}' (inferred type: {param_type}) in {resp.method} request to {path} "
                f"triggered the following indicators: {', '.join(signals)}."
            )
            
            findings.append(VulnerabilityFinding(
                module="injection",
                endpoint=resp.url,
                parameter=name,
                method=resp.method,
                finding_type="SQL/Command Injection (Passive Indicator)" if db_type else "Parameter Input Reflection",
                confidence=confidence,
                evidence=evidence or f"Response time: {resp.response_time:.2f}s (Outlier for {path})",
                description=description
            ))
            
    return findings
