"""Shared data models used across every scanner module.

These dataclasses are the single contract between modules and the
report generator. Modules should only ever return these types.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Technology:
    name: str
    version: Optional[str]
    category: str
    confidence: int  # 0-100
    evidence: str


@dataclass
class CVEEntry:
    cve_id: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    score: Optional[float]
    summary: str
    published_date: Optional[str]
    references: list[str] = field(default_factory=list)


@dataclass
class TechWithCVEs:
    technology: Technology
    cves: list[CVEEntry] = field(default_factory=list)


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None


@dataclass
class DirResult:
    path: str
    status_code: int
    content_type: Optional[str]
    size: Optional[int]
    is_sensitive: bool = False
    note: Optional[str] = None


@dataclass
class LinkFinding:
    """A single item extracted by the passive, FindSomething-style link
    finder: a domain, path, URL, static namespace path, IP, email, or a
    flagged sensitive-information / dynamic-code-analysis snippet pulled out
    of HTML/JS the target already served.

    `category` is one of the top-level buckets defined in
    `asfoor.modules.link_finder.CATEGORY_ORDER` (domain, path,
    incomplete_path, url, static_path, ip, email, sensitive_information,
    dynamic_code_analysis), optionally suffixed with ":<subtype>" for finer
    machine filtering (e.g. "sensitive_information:aws_access_key_id").
    Use `asfoor.modules.link_finder.group_key(category)` to collapse back to
    the top-level bucket for display/grouping.
    """
    category: str
    value: str
    source: str  # "homepage" or the asset URL it was found in


@dataclass
class ScanReport:
    domain: str
    ip: Optional[str]
    scan_start: str
    scan_end: str
    technologies: list[TechWithCVEs] = field(default_factory=list)
    ports: list[PortResult] = field(default_factory=list)
    directories: list[DirResult] = field(default_factory=list)
    link_findings: list[LinkFinding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @staticmethod
    def now_iso() -> str:
        return datetime.utcnow().isoformat() + "Z"
