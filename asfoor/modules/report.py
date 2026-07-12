"""Generates JSON, HTML, and grouped-text reports from a completed ScanReport."""
from __future__ import annotations

import dataclasses
import json
import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from asfoor.core.models import ScanReport
from asfoor.modules.link_finder import CATEGORY_LABELS, CATEGORY_ORDER, format_findings_report, group_key

logger = logging.getLogger("asfoor.report")

TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def _report_to_dict(report: ScanReport) -> dict:
    return dataclasses.asdict(report)


def write_json_report(report: ScanReport, output_dir: Path, filename_stem: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{filename_stem}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(_report_to_dict(report), f, indent=2, default=str)
    logger.info("JSON report written to %s", path)
    return path


def write_findings_text_report(report: ScanReport, output_dir: Path, filename_stem: str) -> Path | None:
    """Write the passive link/secret findings as a grouped plain-text file
    (Domain / PATH / Incomplete Path / URL / Static Path / IP Address /
    Email Address / Sensitive Information / Dynamic Code Analysis sections),
    in the same style as the classic FindSomething browser-extension export.
    Returns None (writes nothing) if there are no link findings.
    """
    if not report.link_findings:
        return None
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{filename_stem}_findings.txt"
    with open(path, "w", encoding="utf-8") as f:
        f.write(format_findings_report(report.link_findings))
    logger.info("Grouped findings report written to %s", path)
    return path


def write_html_report(report: ScanReport, output_dir: Path, filename_stem: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html.j2")

    # Precompute summary counts for the template.
    total_cves = sum(len(t.cves) for t in report.technologies)
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for tech in report.technologies:
        for cve in tech.cves:
            severity_counts[cve.severity if cve.severity in severity_counts else "UNKNOWN"] += 1

    sensitive_findings = [d for d in report.directories if d.is_sensitive]

    # Group passive link findings into the FindSomething-style categories
    # (Domain / PATH / Incomplete Path / URL / Static Path / IP Address /
    # Email Address / Sensitive Information / Dynamic Code Analysis).
    grouped_links: dict[str, list] = {cat: [] for cat in CATEGORY_ORDER}
    for finding in report.link_findings:
        grouped_links.setdefault(group_key(finding.category), []).append(finding)
    grouped_links = {CATEGORY_LABELS[cat]: items for cat, items in grouped_links.items() if items}

    secret_findings = [l for l in report.link_findings if group_key(l.category) == "sensitive_information"]
    dynamic_findings = [l for l in report.link_findings if group_key(l.category) == "dynamic_code_analysis"]

    html = template.render(
        report=report,
        total_cves=total_cves,
        severity_counts=severity_counts,
        sensitive_findings=sensitive_findings,
        secret_findings=secret_findings,
        dynamic_findings=dynamic_findings,
        grouped_links=grouped_links,
        severity_order=SEVERITY_ORDER,
    )

    path = output_dir / f"{filename_stem}.html"
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    logger.info("HTML report written to %s", path)
    return path


def generate_reports(report: ScanReport, output_dir: str, fmt: str = "both") -> list[Path]:
    out_dir = Path(output_dir)
    stem = f"report_{report.domain.replace('.', '_')}_{report.scan_start.replace(':', '-')}"

    paths = []
    if fmt in ("json", "both"):
        paths.append(write_json_report(report, out_dir, stem))
    if fmt in ("html", "both"):
        paths.append(write_html_report(report, out_dir, stem))
    findings_path = write_findings_text_report(report, out_dir, stem)
    if findings_path is not None:
        paths.append(findings_path)
    return paths
