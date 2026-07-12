"""Runs all scan modules and assembles the final ScanReport.

Modules are run as concurrent "phases". Each phase reports its own
start/finish/error via an `on_phase` callback so the CLI can print
human-readable progress ("* Running port scanning...") without the
orchestrator needing to know anything about the terminal/UI layer.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Callable, Optional

from asfoor.core.models import ScanReport, TechWithCVEs
from asfoor.modules.cve_lookup import lookup_cves
from asfoor.modules.dir_scan import scan_directories
from asfoor.modules.fingerprint import fingerprint
from asfoor.modules.link_finder import find_links
from asfoor.modules.port_scan import scan_ports
from asfoor.utils.validators import resolve_ip

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
                    skip_links: bool = False,
                    port_override: str | None = None, full_ports: bool = False,
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
    tasks["fingerprint"] = _run_phase("technology fingerprinting", fingerprint(domain, config), notify)

    if not skip_dirs:
        tasks["dirs"] = _run_phase("active directory & file brute-force", scan_directories(domain, config), notify)
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
    tech_with_cves = []
    if not skip_cve and technologies:
        try:
            tech_with_cves = await _run_phase("CVE lookup", lookup_cves(technologies, config), notify)
        except Exception as e:
            warnings.append(f"CVE lookup failed: {e}")
            tech_with_cves = [TechWithCVEs(technology=t, cves=[]) for t in technologies]
    elif technologies:
        tech_with_cves = [TechWithCVEs(technology=t, cves=[]) for t in technologies]

    scan_end = ScanReport.now_iso()

    return ScanReport(
        domain=domain,
        ip=ip,
        scan_start=scan_start,
        scan_end=scan_end,
        technologies=tech_with_cves,
        ports=ports,
        directories=directories,
        link_findings=link_findings,
        warnings=warnings,
    )
