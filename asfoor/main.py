"""CLI entrypoint for 3asfoor — web recon & vulnerability scanner.

Usage:
    3asfoor scan example.com --i-have-permission
    3asfoor cve-sync          # incremental sync (last 24 days)
    3asfoor cve-sync --full   # full historical backfill
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import typer
from rich import box
from rich.console import Console
from rich.rule import Rule
from rich.table import Table

from asfoor.core.config_loader import load_config, merge_overrides
from asfoor.core.orchestrator import run_scan
from asfoor.modules.link_finder import CATEGORY_LABELS, CATEGORY_ORDER, group_key
from asfoor.modules.report import generate_reports
from asfoor.utils.banner import print_banner
from asfoor.utils.logger import setup_logger
from asfoor.utils.validators import (
    InvalidDomainError,
    PermissionNotGrantedError,
    enforce_permission_gate,
    validate_domain,
)

app = typer.Typer(help="3asfoor — web recon & vulnerability scanner: tech fingerprinting, CVEs, ports, directories, subdomains, API endpoints.")
console = Console()

SEVERITY_COLOR = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green", "UNKNOWN": "grey58"}


def _dashed_table(**kwargs) -> Table:
    """Build a Table with a dashed "-"/"+" border, and a dashed separator
    line between every row so cells read as clearly delimited on the CLI."""
    return Table(box=box.ASCII, show_lines=True, **kwargs)


def _print_custom_help() -> None:
    """Print a highly readable custom help menu with dashed table lines."""
    # Print the ASCII banner
    print_banner(console)

    console.print("[bold cyan]Usage:[/bold cyan] 3asfoor scan [OPTIONS] DOMAIN\n")
    console.print("Run a full scan against DOMAIN: tech fingerprinting, CVE lookup, port scan,\n"
                  "active directory brute-force, subdomain enumeration, API endpoint discovery,\n"
                  "and passive (FindSomething-style) link/secret discovery.\n")

    # Arguments table
    args_table = _dashed_table()
    args_table.add_column("Argument", style="bold green")
    args_table.add_column("Type", style="cyan")
    args_table.add_column("Description", style="white")
    args_table.add_row("DOMAIN", "TEXT", "Target domain to scan (e.g. example.com). [required]")
    console.print("[bold]Arguments:[/bold]")
    console.print(args_table)
    console.print()

    # Options table
    opts_table = _dashed_table()
    opts_table.add_column("Option", style="bold green")
    opts_table.add_column("Type", style="cyan")
    opts_table.add_column("Description", style="white")

    opts_table.add_row("--i-have-permission", "FLAG", "Confirm authorization to scan target (required for non-interactive).")
    opts_table.add_row("--full-ports", "FLAG", "Scan all 65535 TCP ports instead of the default top 1000.")
    opts_table.add_row("--ports", "TEXT", "Specifies custom TCP port specs (e.g. '80,443,8080-8090').")
    opts_table.add_row("--wordlist / --dir-wordlist", "TEXT", "Path to a custom wordlist file for directory brute-forcing. Overrides SecLists.")
    opts_table.add_row("--sensitive-wordlist", "TEXT", "Path to a custom wordlist file for sensitive file discovery. Overrides SecLists.")
    opts_table.add_row("--subdomain-wordlist", "TEXT", "Path to a custom wordlist file for subdomain discovery. Overrides SecLists.")
    opts_table.add_row("--api-wordlist", "TEXT", "Path to a custom wordlist file for API endpoint discovery. Overrides SecLists.")
    opts_table.add_row("--wordlist-size", "TEXT", "Wordlist size for all modules: 'small' (default), 'medium', or 'large'.")
    opts_table.add_row("--concurrency", "INTEGER", "Max concurrent requests during brute-forcing (default: auto-scaled by size).")
    opts_table.add_row("--rate-limit", "FLOAT", "Seconds delay between directory-scan requests (default: 0.01).")
    opts_table.add_row("--skip-ports", "FLAG", "Skip port scanning and service detection.")
    opts_table.add_row("--skip-dirs", "FLAG", "Skip active directory and sensitive file brute-forcing.")
    opts_table.add_row("--skip-subdomains", "FLAG", "Skip subdomain enumeration.")
    opts_table.add_row("--skip-api", "FLAG", "Skip API endpoint discovery.")
    opts_table.add_row("--skip-links", "FLAG", "Skip passive FindSomething-style link/secret finder.")
    opts_table.add_row("--skip-cve", "FLAG", "Skip CVE lookups.")
    opts_table.add_row("--skip-crawler", "FLAG", "Skip the web crawler module.")
    opts_table.add_row("--ignore-robots", "FLAG", "Ignore robots.txt rules when crawling.")
    opts_table.add_row("--cve-db-path", "TEXT", "Path to a custom CVE database file (default: data/cve_cache.sqlite3).")
    opts_table.add_row("--deep-fingerprint", "FLAG", "Run JS-aware fingerprint pass via wappalyzer-next (requires Chromium).")
    opts_table.add_row("--export / --no-export", "FLAG/OPT", "Write report files (.json, .html, findings.txt) to output directory.")
    opts_table.add_row("--format", "TEXT", "Report output format: 'json', 'html', or 'both' (default: both).")
    opts_table.add_row("--output-dir", "TEXT", "Specify custom output directory where reports are saved (default: ./output).")
    opts_table.add_row("--verbose", "FLAG", "Enables verbose logging to standard output/logs.")
    opts_table.add_row("--quiet", "FLAG", "Enables silent execution mode.")

    console.print("[bold]Options:[/bold]")
    console.print(opts_table)


@app.callback()
def _main() -> None:
    """3asfoor — web recon & vulnerability scanner."""
    # Presence of this callback keeps Typer in "command group" mode, so the
    # CLI is invoked as `3asfoor scan <domain>` rather than collapsing the
    # single command to `3asfoor <domain>`.
    return


@app.command()
def scan(
    domain: str = typer.Argument(..., help="Target domain, e.g. example.com"),
    i_have_permission: bool = typer.Option(
        False, "--i-have-permission",
        help="Confirm you are authorized to scan this target. Required for non-interactive runs."
    ),
    full_ports: bool = typer.Option(False, "--full-ports", help="Scan all 65535 ports instead of top 1000."),
    ports: Optional[str] = typer.Option(None, "--ports", help='Custom port spec, e.g. "80,443,8080-8090".'),
    wordlist: Optional[str] = typer.Option(None, "--wordlist", "--dir-wordlist", help="Path to a custom wordlist file for directory brute-forcing (one path per line)."),
    sensitive_wordlist: Optional[str] = typer.Option(None, "--sensitive-wordlist", help="Path to a custom wordlist file for sensitive file discovery (one path per line)."),
    subdomain_wordlist: Optional[str] = typer.Option(None, "--subdomain-wordlist", help="Path to a custom wordlist file for subdomain discovery (one path per line)."),
    api_wordlist: Optional[str] = typer.Option(None, "--api-wordlist", help="Path to a custom wordlist file for API endpoint discovery (one path per line)."),
    wordlist_size: str = typer.Option("small", "--wordlist-size", help='Wordlist size to use from the bundled seclists for all modules (directories, sensitive files, subdomains, API endpoints): "small" (default), "medium", or "large". Ignored when custom --wordlist or --sensitive-wordlist is given.'),
    output_dir: str = typer.Option("./output", "--output-dir", help="Directory reports are written to, if exporting."),
    concurrency: Optional[int] = typer.Option(None, "--concurrency", help="Max number of parallel requests during directory brute-forcing (default: auto-scaled by --wordlist-size)."),
    rate_limit: Optional[float] = typer.Option(None, "--rate-limit", help="Seconds delay between directory-scan requests."),
    skip_ports: bool = typer.Option(False, "--skip-ports", help="Skip the port scan module."),
    skip_dirs: bool = typer.Option(False, "--skip-dirs", help="Skip the active (wordlist brute-force) directory scan module."),
    skip_subdomains: bool = typer.Option(False, "--skip-subdomains", help="Skip subdomain enumeration."),
    skip_api: bool = typer.Option(False, "--skip-api", help="Skip API endpoint discovery."),
    skip_links: bool = typer.Option(False, "--skip-links", help="Skip the passive FindSomething-style link/secret finder."),
    skip_cve: bool = typer.Option(False, "--skip-cve", help="Skip CVE lookups."),
    skip_crawler: bool = typer.Option(False, "--skip-crawler", help="Skip the web crawler module."),
    ignore_robots: bool = typer.Option(False, "--ignore-robots", help="Ignore robots.txt rules when crawling."),
    cve_db_path: Optional[str] = typer.Option(None, "--cve-db-path", help="Path to a custom CVE database file (default: data/cve_cache.sqlite3)."),
    deep_fingerprint: bool = typer.Option(False, "--deep-fingerprint", help="Run an additional JS-aware fingerprint pass via wappalyzer-next (requires Chromium). Makes a browser-based request to the target."),
    export: Optional[bool] = typer.Option(
        None, "--export/--no-export",
        help="Write JSON/HTML/findings.txt report files to --output-dir. If omitted, you'll be "
             "asked after the scan (or skipped automatically with --quiet)."
    ),
    fmt: str = typer.Option("both", "--format", help="json | html | both — which file formats to write when exporting."),
    verbose: bool = typer.Option(False, "--verbose"),
    quiet: bool = typer.Option(False, "--quiet"),
):
    """Run a full scan against DOMAIN: tech fingerprinting, CVE lookup, port scan,
    active directory brute-force, subdomain enumeration, API endpoint discovery,
    and passive (FindSomething-style) link/secret discovery.

    The full report is always printed to the console when the scan finishes. Writing it to
    files (JSON/HTML/findings.txt) is optional — pass --export to always write them, --no-export
    to never write them, or leave it unset to be asked interactively.
    """
    if not quiet:
        print_banner(console)

    logger = setup_logger(output_dir=output_dir, verbose=verbose, quiet=quiet)

    try:
        clean_domain = validate_domain(domain)
    except InvalidDomainError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)

    try:
        enforce_permission_gate(i_have_permission, interactive=True)
    except PermissionNotGrantedError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(code=1)

    config = load_config()
    overrides = {
        "output.dir": output_dir,
        "output.format": fmt,
        "dir_scan.concurrency": concurrency,
        "dir_scan.rate_limit_seconds": rate_limit,
        "cve.db_path": cve_db_path,
    }
    config = merge_overrides(config, overrides)

    console.print(f"[bold cyan]Starting scan of {clean_domain}[/bold cyan]\n")

    def on_phase(label: str, status: str, detail: str) -> None:
        if quiet:
            return
        if status == "start":
            console.print(f"[cyan]*[/cyan] Running {label}...")
        elif status == "done":
            console.print(f"[green]*[/green] {label} complete")
        elif status == "error":
            console.print(f"[yellow]*[/yellow] {label} failed: {detail}")

    dirs_wordlist_path = Path(wordlist) if wordlist else None
    sensitive_wordlist_path = Path(sensitive_wordlist) if sensitive_wordlist else None
    subdomains_wordlist_path = Path(subdomain_wordlist) if subdomain_wordlist else None
    api_wordlist_path = Path(api_wordlist) if api_wordlist else None

    # Validate wordlist_size
    wordlist_size = wordlist_size.lower()
    if wordlist_size not in ("small", "medium", "large"):
        console.print(f"[red]Error:[/red] --wordlist-size must be 'small', 'medium', or 'large', got '{wordlist_size}'")
        raise typer.Exit(code=1)

    report = asyncio.run(run_scan(
        clean_domain, config,
        skip_ports=skip_ports, skip_dirs=skip_dirs, skip_cve=skip_cve, skip_links=skip_links,
        skip_subdomains=skip_subdomains, skip_api=skip_api,
        skip_crawler=skip_crawler, ignore_robots=ignore_robots,
        port_override=ports, full_ports=full_ports,
        dirs_wordlist_path=dirs_wordlist_path, sensitive_wordlist_path=sensitive_wordlist_path,
        subdomains_wordlist_path=subdomains_wordlist_path, api_wordlist_path=api_wordlist_path,
        wordlist_size=wordlist_size,
        deep_fingerprint=deep_fingerprint,
        on_phase=on_phase,
    ))

    console.print()
    _print_report(report)

    # Exporting to files is optional. --export / --no-export decide it
    # explicitly; if neither was passed, ask (unless --quiet, in which case
    # we default to *not* writing anything rather than surprising the user).
    if export is None:
        if quiet:
            export = False
        else:
            console.print()
            export = typer.confirm(
                f"Export report files (JSON/HTML/findings.txt) to '{output_dir}'?", default=False
            )

    if export:
        paths = generate_reports(report, output_dir, fmt)
        console.print("\n[bold green]Reports written:[/bold green]")
        for p in paths:
            console.print(f"  - {p}")
    elif not quiet:
        console.print("\n[dim]No report files written. Re-run with --export to save them.[/dim]")


def _print_report(report) -> None:
    """Render the full scan report to the console in a readable format."""
    console.print(Rule(f"[bold]Scan Report — {report.domain}[/bold]"))
    console.print(f"[bold]IP:[/bold] {report.ip or 'unresolved'}   "
                   f"[bold]OS:[/bold] {report.os or 'Unknown'}   "
                   f"[bold]Started:[/bold] {report.scan_start}   [bold]Finished:[/bold] {report.scan_end}")

    _print_technologies(report)
    _print_ports(report)
    _print_subdomains(report)
    _print_directories(report)
    _print_api_endpoints(report)
    _print_link_findings(report)
    _print_crawler(report)
    _print_findings(report)

    if report.warnings:
        console.print(Rule("[yellow bold]Warnings[/yellow bold]"))
        for w in report.warnings:
            console.print(f"  [yellow]![/yellow] {w}")

    console.print(Rule())


def _print_technologies(report) -> None:
    console.print(Rule("Technologies Detected"))
    if not report.technologies:
        console.print("[dim]None detected.[/dim]")
        return

    tech_table = _dashed_table()
    tech_table.add_column("Name")
    tech_table.add_column("Version")
    tech_table.add_column("Category")
    tech_table.add_column("Confidence")
    tech_table.add_column("CVEs")
    for item in report.technologies:
        cve_summary = str(len(item.cves))
        if item.cves:
            top_severity = min(item.cves, key=lambda c: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(c.severity, 4)).severity
            color = SEVERITY_COLOR.get(top_severity, "white")
            cve_summary = f"[{color}]{len(item.cves)} (worst: {top_severity})[/{color}]"
        tech_table.add_row(
            item.technology.name,
            item.technology.version or "—",
            item.technology.category,
            f"{item.technology.confidence}%",
            cve_summary,
        )
    console.print(tech_table)

    cve_rows = [(item.technology.name, cve) for item in report.technologies for cve in item.cves]
    if cve_rows:
        cve_table = _dashed_table(title="CVE Detail")
        cve_table.add_column("Technology")
        cve_table.add_column("CVE ID")
        cve_table.add_column("Severity")
        cve_table.add_column("Score")
        cve_table.add_column("Summary")
        severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        for tech_name, cve in sorted(cve_rows, key=lambda r: severity_rank.get(r[1].severity, 5)):
            color = SEVERITY_COLOR.get(cve.severity, "white")
            summary = cve.summary if len(cve.summary) <= 90 else cve.summary[:87] + "..."
            cve_table.add_row(tech_name, cve.cve_id, f"[{color}]{cve.severity}[/{color}]",
                               str(cve.score) if cve.score is not None else "—", summary)
        console.print(cve_table)


def _print_ports(report) -> None:
    console.print(Rule("Open Ports"))
    open_ports = [p for p in report.ports if p.state == "open"]
    if not open_ports:
        console.print("[dim]No open ports found (or port scan was skipped).[/dim]")
        return
    port_table = _dashed_table()
    port_table.add_column("Port")
    port_table.add_column("Protocol")
    port_table.add_column("Service")
    port_table.add_column("Version")
    port_table.add_column("Banner")
    for p in sorted(open_ports, key=lambda x: x.port):
        port_table.add_row(str(p.port), p.protocol, p.service or "—", p.version or "—", (p.banner or "—")[:60])
    console.print(port_table)


def _print_subdomains(report) -> None:
    console.print(Rule("Subdomains"))
    if not report.subdomains:
        console.print("[dim]No subdomains found (or subdomain scan was skipped).[/dim]")
        return
    sub_table = _dashed_table()
    sub_table.add_column("Subdomain")
    sub_table.add_column("IP")
    sub_table.add_column("HTTP Status")
    sub_table.add_column("Title")
    for s in report.subdomains:
        sub_table.add_row(
            s.subdomain,
            s.ip or "—",
            str(s.status_code) if s.status_code is not None else "—",
            (s.title or "—")[:80],
        )
    console.print(sub_table)
    console.print(f"[bold cyan]{len(report.subdomains)} subdomain(s) discovered.[/bold cyan]")


def _print_directories(report) -> None:
    console.print(Rule("Directories & Files (active brute-force)"))
    if not report.directories:
        console.print("[dim]None found (or directory scan was skipped).[/dim]")
        return
    dir_table = _dashed_table()
    dir_table.add_column("Path")
    dir_table.add_column("Status")
    dir_table.add_column("Type")
    dir_table.add_column("Size")
    dir_table.add_column("Note")
    for d in sorted(report.directories, key=lambda x: (not x.is_sensitive, x.path)):
        style = "bold red" if d.is_sensitive else None
        row = (d.path, str(d.status_code), d.content_type or "—", str(d.size) if d.size is not None else "—", d.note or "—")
        if style:
            dir_table.add_row(*[f"[{style}]{v}[/{style}]" for v in row])
        else:
            dir_table.add_row(*row)
    console.print(dir_table)
    sensitive_count = sum(1 for d in report.directories if d.is_sensitive)
    if sensitive_count:
        console.print(f"[bold red]{sensitive_count} sensitive finding(s) highlighted above.[/bold red]")


def _print_api_endpoints(report) -> None:
    console.print(Rule("API Endpoints & Routes"))
    if not report.api_endpoints:
        console.print("[dim]No API endpoints found (or API scan was skipped).[/dim]")
        return
    api_table = _dashed_table()
    api_table.add_column("Path")
    api_table.add_column("Status")
    api_table.add_column("Content-Type")
    api_table.add_column("Size")
    api_table.add_column("Note")
    for ep in report.api_endpoints:
        status_style = ""
        if ep.status_code in (401, 403):
            status_style = "yellow"
        elif ep.status_code >= 500:
            status_style = "red"
        status_str = f"[{status_style}]{ep.status_code}[/{status_style}]" if status_style else str(ep.status_code)
        api_table.add_row(
            f"/{ep.path}",
            status_str,
            ep.content_type or "—",
            str(ep.size) if ep.size is not None else "—",
            ep.note or "—",
        )
    console.print(api_table)
    console.print(f"[bold cyan]{len(report.api_endpoints)} API endpoint(s) discovered.[/bold cyan]")


def _print_link_findings(report) -> None:
    console.print(Rule("Passive Link, Path & Secret Discovery (FindSomething-style)"))
    if not report.link_findings:
        console.print("[dim]No links, paths, or secrets found in page source (or module was skipped).[/dim]")
        return

    grouped: dict[str, list] = {cat: [] for cat in CATEGORY_ORDER}
    for finding in report.link_findings:
        grouped.setdefault(group_key(finding.category), []).append(finding)

    for cat in CATEGORY_ORDER:
        items = grouped.get(cat)
        if not items:
            continue
        label = CATEGORY_LABELS[cat]
        highlight = cat in ("sensitive_information", "dynamic_code_analysis")
        table = _dashed_table(title=f"{label} ({len(items)})")
        table.add_column("Value", overflow="fold")
        table.add_column("Source", overflow="fold")
        for f in sorted(items, key=lambda x: x.value):
            if highlight:
                table.add_row(f"[bold red]{f.value}[/bold red]", f.source)
            else:
                table.add_row(f.value, f.source)
        console.print(table)


def _print_crawler(report) -> None:
    console.print(Rule("Web Crawler Results"))
    if not hasattr(report, "crawled_urls") or not report.crawled_urls:
        console.print("[dim]No crawler results found (or crawling was skipped).[/dim]")
        return
    
    # Print sitemap URLs count
    console.print(f"[bold cyan]Crawled URLs ({len(report.crawled_urls)}):[/bold cyan]")
    for url in sorted(report.crawled_urls)[:10]:
        console.print(f"  - {url}")
    if len(report.crawled_urls) > 10:
        console.print(f"  [dim]... and {len(report.crawled_urls) - 10} more URLs.[/dim]")
        
    # Print Forms
    console.print()
    if report.forms:
        console.print(f"[bold cyan]Discovered Forms ({len(report.forms)}):[/bold cyan]")
        form_table = _dashed_table()
        form_table.add_column("Page URL")
        form_table.add_column("Action")
        form_table.add_column("Method")
        form_table.add_column("Inputs (Name:Type:Default)")
        for form in report.forms:
            inputs_str = ", ".join(f"{inp['name']}:{inp['type']}:{inp['value']}" for inp in form.inputs)
            form_table.add_row(form.url, form.action, form.method.upper(), inputs_str or "—")
        console.print(form_table)
    else:
        console.print("[dim]No forms discovered.[/dim]")
        
    # Print External Domains
    console.print()
    if report.external_domains:
        console.print(f"[bold cyan]External Domains Referenced ({len(report.external_domains)}):[/bold cyan]")
        for dom in report.external_domains:
            console.print(f"  - {dom}")
    else:
        console.print("[dim]No external domains referenced.[/dim]")


def _print_findings(report) -> None:
    console.print(Rule("Vulnerability & Weakness Findings"))
    if not hasattr(report, "findings") or not report.findings:
        console.print("[dim]No vulnerability findings detected.[/dim]")
        return

    findings_table = _dashed_table()
    findings_table.add_column("Module")
    findings_table.add_column("Type")
    findings_table.add_column("Endpoint")
    findings_table.add_column("Param")
    findings_table.add_column("Severity")
    findings_table.add_column("Evidence", overflow="fold")
    
    severity_colors = {
        "HIGH": "bold red",
        "MEDIUM": "yellow",
        "LOW": "green"
    }

    for f in sorted(report.findings, key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(x.confidence, 3)):
        color = severity_colors.get(f.confidence, "white")
        findings_table.add_row(
            f.module,
            f.finding_type,
            f.endpoint,
            f.parameter or "—",
            f"[{color}]{f.confidence}[/{color}]",
            f.evidence[:150]
        )
    console.print(findings_table)


# ---------------------------------------------------------------------------
# cve-sync subcommand
# ---------------------------------------------------------------------------


@app.command("cve-sync")
def cve_sync(
    full: bool = typer.Option(False, "--full", help="Run a full historical backfill instead of an incremental sync."),
    cve_db_path: Optional[str] = typer.Option(None, "--cve-db-path", help="Path to a custom CVE database file."),
    verbose: bool = typer.Option(False, "--verbose"),
    quiet: bool = typer.Option(False, "--quiet"),
):
    """Sync the local CVE database from the NVD API.

    Without --full, performs an incremental sync covering the last N days
    (default 24, configurable via config.yaml cve.sync_lookback_days).

    With --full, performs a complete historical backfill.  This can take
    several hours depending on your API key status.  If interrupted, re-running
    ``cve-sync --full`` will resume from the last completed date chunk (note:
    an interrupted chunk is re-fetched from the beginning of that chunk rather
    than resuming mid-pagination — this is a known limitation).
    """
    import os
    import httpx
    from asfoor.modules.cve_db import (
        init_cve_db, upsert_cve_records, parse_nvd_cve_item,
        record_sync_start, update_sync_progress, complete_sync,
        get_last_full_sync_progress, get_last_sync_time,
    )
    from asfoor.utils.nvd_rate_limiter import NvdTokenBucket, nvd_request_with_retry
    from asfoor.utils.date_chunking import chunk_date_range

    if not quiet:
        print_banner(console)
    logger = setup_logger(output_dir="./output", verbose=verbose, quiet=quiet)

    config = load_config()
    cve_cfg = config.get("cve", {})
    base_url = cve_cfg.get("nvd_base_url", "https://services.nvd.nist.gov/rest/json/cves/2.0")
    max_days = cve_cfg.get("chunk_max_days", 90)
    lookback_days = cve_cfg.get("sync_lookback_days", 24)
    db_file = Path(cve_db_path or cve_cfg.get("db_path", "data/cve_cache.sqlite3"))

    api_key = os.environ.get("NVD_API_KEY")
    retry_cfg = {
        "max_retries": cve_cfg.get("retry_max_attempts", 5),
        "base_delay": cve_cfg.get("retry_base_delay", 1.0),
        "max_delay": cve_cfg.get("retry_max_delay", 30.0),
        "jitter": cve_cfg.get("retry_jitter", 0.5),
    }

    conn = init_cve_db(db_file)
    bucket = NvdTokenBucket(has_api_key=bool(api_key))

    from datetime import timezone
    if full:
        sync_type = "full"
        # NVD data starts around 1999; use 2002 as a practical start.
        range_start = datetime(2002, 1, 1)
        range_end = datetime.now(timezone.utc).replace(tzinfo=None)

        # Check for a resumable in-progress sync.
        resume_point = get_last_full_sync_progress(conn)
        if resume_point:
            try:
                range_start = datetime.fromisoformat(resume_point.replace("Z", "+00:00")).replace(tzinfo=None)
                console.print(f"[yellow]Resuming full sync from {range_start.isoformat()}[/yellow]")
            except (ValueError, AttributeError):
                pass
    else:
        sync_type = "incremental"
        last_sync = get_last_sync_time(conn)
        if last_sync:
            range_start = last_sync.replace(tzinfo=None) - timedelta(days=1)  # small overlap for safety
        else:
            range_start = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=lookback_days)
        range_end = datetime.now(timezone.utc).replace(tzinfo=None)

    chunks = chunk_date_range(range_start, range_end, max_days=max_days)
    console.print(
        f"[bold cyan]CVE {sync_type} sync: {len(chunks)} chunk(s), "
        f"{range_start.date()} → {range_end.date()}[/bold cyan]"
    )

    sync_id = record_sync_start(conn, sync_type)
    total_upserted = 0

    async def _do_sync():
        nonlocal total_upserted
        headers = {"apiKey": api_key} if api_key else {}

        async with httpx.AsyncClient() as client:
            for chunk_idx, (chunk_start, chunk_end) in enumerate(chunks, 1):
                start_str = chunk_start.strftime("%Y-%m-%dT%H:%M:%S.000")
                end_str = chunk_end.strftime("%Y-%m-%dT%H:%M:%S.000")

                if not quiet:
                    console.print(
                        f"  [dim]Chunk {chunk_idx}/{len(chunks)}: "
                        f"{chunk_start.date()} → {chunk_end.date()}[/dim]"
                    )

                start_index = 0
                while True:
                    start_param = "pubStartDate" if full else "lastModStartDate"
                    end_param = "pubEndDate" if full else "lastModEndDate"
                    params = {
                        start_param: start_str,
                        end_param: end_str,
                        "resultsPerPage": 2000,
                        "startIndex": start_index,
                    }

                    resp = await nvd_request_with_retry(
                        client, base_url, params=params, headers=headers,
                        bucket=bucket, **retry_cfg,
                    )
                    if resp is None:
                        console.print(
                            f"  [yellow]Warning: failed to fetch chunk "
                            f"{chunk_idx} page at startIndex={start_index} "
                            f"— skipping remainder of this chunk.[/yellow]"
                        )
                        break

                    try:
                        data = resp.json()
                    except Exception:
                        console.print(f"  [yellow]Warning: invalid JSON response for chunk {chunk_idx}[/yellow]")
                        break

                    vulns = data.get("vulnerabilities", [])
                    if not vulns:
                        break

                    records = [parse_nvd_cve_item(v) for v in vulns]
                    upserted = upsert_cve_records(conn, records)
                    total_upserted += upserted

                    total_results = data.get("totalResults", 0)
                    start_index += len(vulns)
                    if start_index >= total_results:
                        break

                update_sync_progress(conn, sync_id, end_str)

    asyncio.run(_do_sync())
    complete_sync(conn, sync_id)
    conn.close()

    console.print(
        f"\n[bold green]CVE sync complete:[/bold green] "
        f"{total_upserted} record(s) upserted into {db_file}"
    )


# Intercept help requests to render our custom dashed-table help output.
import sys
if any(arg in sys.argv for arg in ("--help", "-h")):
    if not any("pytest" in arg or "test" in arg for arg in sys.argv):
        _print_custom_help()
        sys.exit(0)


if __name__ == "__main__":
    app()
