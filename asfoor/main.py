"""CLI entrypoint for 3asfoor — web recon & vulnerability scanner.

Usage:
    3asfoor scan example.com --i-have-permission
"""
from __future__ import annotations

import asyncio
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

app = typer.Typer(help="3asfoor — web recon & vulnerability scanner: tech fingerprinting, CVEs, ports, directories.")
console = Console()

SEVERITY_COLOR = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green", "UNKNOWN": "grey58"}


def _dashed_table(**kwargs) -> Table:
    """Build a Table with a dashed "-"/"+" border, and a dashed separator
    line between every row so cells read as clearly delimited on the CLI."""
    return Table(box=box.ASCII, show_lines=True, **kwargs)


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
    wordlist_size: str = typer.Option("medium", "--wordlist-size", help="small | medium | large (currently uses bundled list regardless of size)."),
    output_dir: str = typer.Option("./output", "--output-dir", help="Directory reports are written to, if exporting."),
    threads: Optional[int] = typer.Option(None, "--threads", help="Override concurrency for directory scanning."),
    rate_limit: Optional[float] = typer.Option(None, "--rate-limit", help="Seconds delay between directory-scan requests."),
    skip_ports: bool = typer.Option(False, "--skip-ports", help="Skip the port scan module."),
    skip_dirs: bool = typer.Option(False, "--skip-dirs", help="Skip the active (wordlist brute-force) directory scan module."),
    skip_links: bool = typer.Option(False, "--skip-links", help="Skip the passive FindSomething-style link/secret finder."),
    skip_cve: bool = typer.Option(False, "--skip-cve", help="Skip CVE lookups."),
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
    active directory brute-force, and passive (FindSomething-style) link/secret discovery.

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
        "dir_scan.concurrency": threads,
        "dir_scan.rate_limit_seconds": rate_limit,
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

    report = asyncio.run(run_scan(
        clean_domain, config,
        skip_ports=skip_ports, skip_dirs=skip_dirs, skip_cve=skip_cve, skip_links=skip_links,
        port_override=ports, full_ports=full_ports,
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
                   f"[bold]Started:[/bold] {report.scan_start}   [bold]Finished:[/bold] {report.scan_end}")

    _print_technologies(report)
    _print_ports(report)
    _print_directories(report)
    _print_link_findings(report)

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


if __name__ == "__main__":
    app()
