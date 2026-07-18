"""Runs all scan modules and assembles the final ScanReport.

Modules are run as concurrent "phases". Each phase reports its own
start/finish/error via an `on_phase` callback so the CLI can print
human-readable progress ("* Running port scanning...") without the
orchestrator needing to know anything about the terminal/UI layer.
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Callable, Optional

from asfoor.core.models import ScanReport, TechWithCVEs
from asfoor.modules.api_scan import scan_api_endpoints
from asfoor.modules.cve_lookup import lookup_cves, CPE_MAP
from asfoor.modules.cve_db import init_cve_db, query_cves_for_cpe, is_db_populated
from asfoor.modules.crawler import crawl_site
from asfoor.modules.dir_scan import scan_directories
from asfoor.modules.fingerprint import fingerprint
from asfoor.modules.injection_detector import detect_injection_points
from asfoor.modules.xss_detector import detect_xss
from asfoor.modules.info_disclosure import detect_info_disclosure
from asfoor.modules.link_finder import find_links
from asfoor.modules.port_scan import scan_ports
from asfoor.modules.subdomain_scan import scan_subdomains
from asfoor.utils.validators import resolve_ip
from asfoor.core.models import CVEEntry

logger = logging.getLogger("asfoor.orchestrator")

# on_phase(phase_label: str, status: "start" | "done" | "error", detail: str)
PhaseCallback = Callable[[str, str, str], None]


async def _run_phase(label: str, coro, notify: PhaseCallback):
    notify(label, "start", "")
    try:
        result = await coro
    except Exception as e:  # noqa: BLE001 - surfaced to caller via return_exceptions
        notify(label, "error", str(e))
        raise
    notify(label, "done", "")
    return result


def _noop_notify(label: str, status: str, detail: str) -> None:
    return None


async def run_scan(domain: str, config: dict,
                    skip_ports: bool = False, skip_dirs: bool = False, skip_cve: bool = False,
                    skip_links: bool = False, skip_subdomains: bool = False, skip_api: bool = False,
                    skip_crawler: bool = False, ignore_robots: bool = False,
                    port_override: str | None = None, full_ports: bool = False,
                    dirs_wordlist_path: Path | None = None,
                    sensitive_wordlist_path: Path | None = None,
                    subdomains_wordlist_path: Path | None = None,
                    api_wordlist_path: Path | None = None,
                    wordlist_size: str = "small",
                    deep_fingerprint: bool = False,
                    on_phase: Optional[PhaseCallback] = None) -> ScanReport:
    notify = on_phase or _noop_notify

    scan_start = ScanReport.now_iso()
    warnings: list[str] = []

    ip = resolve_ip(domain)
    if ip is None:
        warnings.append(f"Could not resolve IP for {domain}. Port scanning will be skipped.")
        skip_ports = True

    # All phases below are independent of each other and run concurrently.
    tasks = {}
    tasks["fingerprint"] = _run_phase(
        "technology fingerprinting",
        fingerprint(domain, config, deep_fingerprint=deep_fingerprint),
        notify,
    )

    if not skip_crawler:
        tasks["crawler"] = _run_phase("web crawling", crawl_site(domain, config, ignore_robots=ignore_robots), notify)
    if not skip_dirs:
        tasks["dirs"] = _run_phase("active directory & file brute-force", scan_directories(domain, config, dirs_wordlist_path=dirs_wordlist_path, sensitive_wordlist_path=sensitive_wordlist_path, wordlist_size=wordlist_size), notify)
    if not skip_subdomains:
        tasks["subdomains"] = _run_phase("subdomain enumeration", scan_subdomains(domain, config, wordlist_size=wordlist_size, wordlist_path=subdomains_wordlist_path), notify)
    if not skip_api:
        tasks["api"] = _run_phase("API endpoint discovery", scan_api_endpoints(domain, config, wordlist_size=wordlist_size, wordlist_path=api_wordlist_path), notify)
    if not skip_links:
        tasks["links"] = _run_phase("passive link & secret discovery", find_links(domain, config), notify)
    if not skip_ports:
        tasks["ports"] = _run_phase(
            "port scanning",
            scan_ports(ip, config, port_override=port_override, full_ports=full_ports),
            notify,
        )

    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    named_results = dict(zip(tasks.keys(), results))

    technologies = []
    if "fingerprint" in named_results:
        if isinstance(named_results["fingerprint"], Exception):
            warnings.append(f"Fingerprinting failed: {named_results['fingerprint']}")
        else:
            technologies = named_results["fingerprint"]

    directories = []
    if "dirs" in named_results:
        if isinstance(named_results["dirs"], Exception):
            warnings.append(f"Directory scan failed: {named_results['dirs']}")
        else:
            directories = named_results["dirs"]

    subdomains = []
    if "subdomains" in named_results:
        if isinstance(named_results["subdomains"], Exception):
            warnings.append(f"Subdomain scan failed: {named_results['subdomains']}")
        else:
            subdomains = named_results["subdomains"]

    crawled_urls = []
    forms = []
    crawler_apis = []
    external_domains = []
    crawl_responses = []
    if "crawler" in named_results:
        if isinstance(named_results["crawler"], Exception):
            warnings.append(f"Web crawling failed: {named_results['crawler']}")
        else:
            crawled_urls, forms, crawler_apis, external_domains, crawl_responses = named_results["crawler"]

    findings = []

    # Run passive Injection, XSS & Info Disclosure Detectors
    if crawl_responses:
        try:
            injection_findings = await detect_injection_points(crawl_responses, forms)
            findings.extend(injection_findings)
        except Exception as e:
            warnings.append(f"Passive injection detection failed: {e}")

        try:
            xss_findings = await detect_xss(crawl_responses, forms)
            findings.extend(xss_findings)
        except Exception as e:
            warnings.append(f"Passive XSS detection failed: {e}")

        try:
            disclosure_findings = await detect_info_disclosure(crawl_responses)
            findings.extend(disclosure_findings)
        except Exception as e:
            warnings.append(f"Passive info disclosure detection failed: {e}")

    api_endpoints = []
    if "api" in named_results:
        if isinstance(named_results["api"], Exception):
            warnings.append(f"API endpoint scan failed: {named_results['api']}")
        else:
            api_endpoints = named_results["api"]

    # Merge and deduplicate api_endpoints from active scanner and web crawler
    api_map = {ep.path: ep for ep in api_endpoints}
    for ep in crawler_apis:
        if ep.path not in api_map:
            api_map[ep.path] = ep
    api_endpoints = sorted(api_map.values(), key=lambda ep: ep.path)

    link_findings = []
    if "links" in named_results:
        if isinstance(named_results["links"], Exception):
            warnings.append(f"Passive link finding failed: {named_results['links']}")
        else:
            link_findings = named_results["links"]

    ports = []
    if "ports" in named_results:
        if isinstance(named_results["ports"], Exception):
            warnings.append(f"Port scan failed: {named_results['ports']}")
        else:
            ports, port_warnings = named_results["ports"]
            warnings.extend(port_warnings)

    # CVE lookup depends on fingerprint results, so it runs after the phases above.
    # Uses the local CVE database as the primary data source — never calls the
    # live NVD API during a scan run.
    tech_with_cves = []
    if not skip_cve and technologies:
        try:
            cve_cfg = config.get("cve", {})
            db_path_str = cve_cfg.get("db_path")
            if db_path_str:
                from pathlib import Path as _Path
                cve_db_path = _Path(db_path_str)
            else:
                cve_db_path = Path(__file__).resolve().parents[2] / "data" / "cve_cache.sqlite3"

            cve_conn = init_cve_db(cve_db_path)
            db_populated = is_db_populated(cve_conn)

            if not db_populated:
                warnings.append(
                    "CVE database is empty. Run '3asfoor cve-sync --full' to populate it. "
                    "CVE matching is disabled for this scan."
                )
                tech_with_cves = [TechWithCVEs(technology=t, cves=[]) for t in technologies]
            else:
                notify("CVE lookup", "start", "")
                for tech in technologies:
                    if not tech.version or tech.name not in CPE_MAP:
                        tech_with_cves.append(TechWithCVEs(technology=tech, cves=[]))
                        continue
                    vendor, product = CPE_MAP[tech.name]
                    cves = query_cves_for_cpe(cve_conn, vendor, product)
                    tech_with_cves.append(TechWithCVEs(technology=tech, cves=cves))
                notify("CVE lookup", "done", "")

            cve_conn.close()
        except Exception as e:
            warnings.append(f"CVE lookup failed: {e}")
            tech_with_cves = [TechWithCVEs(technology=t, cves=[]) for t in technologies]
    elif technologies:
        tech_with_cves = [TechWithCVEs(technology=t, cves=[]) for t in technologies]

    scan_end = ScanReport.now_iso()

    inferred_os = None
    cleaned_warnings = []
    for w in warnings:
        if w.startswith("OS Fingerprint: "):
            inferred_os = w.split("OS Fingerprint: ")[1]
        else:
            cleaned_warnings.append(w)

    return ScanReport(
        domain=domain,
        ip=ip,
        scan_start=scan_start,
        scan_end=scan_end,
        technologies=tech_with_cves,
        ports=ports,
        directories=directories,
        subdomains=subdomains,
        api_endpoints=api_endpoints,
        link_findings=link_findings,
        warnings=cleaned_warnings,
        os=inferred_os,
        crawled_urls=crawled_urls,
        forms=forms,
        external_domains=external_domains,
        findings=findings,
        crawl_responses=crawl_responses,
    )
