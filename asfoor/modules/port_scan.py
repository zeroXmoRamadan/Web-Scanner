"""Port scanning via nmap (preferred, gives service/version detection) with a
fallback to a plain asyncio TCP connect scan if nmap isn't installed.
"""
from __future__ import annotations

import asyncio
import logging
import shutil

from asfoor.core.models import PortResult

logger = logging.getLogger("asfoor.port_scan")

TOP_1000_PORTS = (
    "1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,"
    "99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,"
    "280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,"
    "524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,"
    "711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,"
    "990,992,993,995,999,1000,1001,1002,1010,1023,1024,1025,1026,1027,1028,1029,1030,1080,1099,1100,1200,1201,"
    "1234,1311,1352,1433,1434,1521,1720,1723,1755,1900,2000,2001,2049,2100,2121,2181,2222,2323,2375,2376,3000,"
    "3128,3306,3389,3690,4000,4040,4443,4444,4567,4664,4700,4899,5000,5001,5432,5555,5601,5666,5800,5900,5985,"
    "5986,6000,6001,6379,6666,6667,7000,7001,7070,7077,7443,7777,8000,8008,8009,8080,8081,8088,8089,8090,8091,"
    "8443,8500,8888,8983,9000,9001,9042,9090,9091,9092,9200,9300,9418,9999,10000,11211,15672,20000,27017,27018,"
    "28017,32768,49152,50000"
)


def _severity_note_for_port(port: int, service: str | None) -> str:
    risky = {
        21: "FTP — often allows anonymous or weak auth; check for cleartext credentials.",
        23: "Telnet — unencrypted remote admin protocol, high risk if exposed.",
        3306: "MySQL — should not be internet-facing without strict access control.",
        5432: "PostgreSQL — should not be internet-facing without strict access control.",
        6379: "Redis — frequently misconfigured with no auth; high-value target.",
        9200: "Elasticsearch — commonly exposed without auth; can leak indexed data.",
        27017: "MongoDB — frequently exposed without auth in the wild.",
        2375: "Docker daemon (unencrypted) — remote code execution risk if exposed.",
    }
    return risky.get(port, "")


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def scan_with_nmap(ip: str, ports: str, timing_template: str = "T4") -> list[PortResult]:
    """Run nmap -sV against the target and parse results. Synchronous — call
    via asyncio.to_thread from the orchestrator.
    """
    import nmap  # python-nmap; imported lazily so the module still loads without it installed

    scanner = nmap.PortScanner()
    args = f"-sV -{timing_template}"
    # Deliberately not logged at INFO: we don't want the port list streamed to
    # the console. Full detail (including the port spec) goes to the debug
    # log file only; the CLI shows phase-level progress instead.
    logger.debug("Running nmap %s -p %s against %s", args, ports, ip)
    scanner.scan(hosts=ip, ports=ports, arguments=args)

    results: list[PortResult] = []
    if ip not in scanner.all_hosts():
        return results

    for proto in scanner[ip].all_protocols():
        for port in sorted(scanner[ip][proto].keys()):
            info = scanner[ip][proto][port]
            service = info.get("name")
            version_parts = [info.get("product", ""), info.get("version", "")]
            version = " ".join(p for p in version_parts if p).strip() or None
            results.append(PortResult(
                port=port,
                protocol=proto,
                state=info.get("state", "unknown"),
                service=service,
                version=version,
                banner=info.get("extrainfo") or None,
            ))
    return results


async def _tcp_connect_scan(ip: str, port_list: list[int], timeout: float = 1.5) -> list[PortResult]:
    results: list[PortResult] = []
    semaphore = asyncio.Semaphore(200)

    async def check_port(port: int) -> None:
        async with semaphore:
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=timeout)
                writer.close()
                await writer.wait_closed()
                results.append(PortResult(port=port, protocol="tcp", state="open"))
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                pass  # closed/filtered — not included in results

    await asyncio.gather(*(check_port(p) for p in port_list))
    results.sort(key=lambda r: r.port)
    return results


async def scan_ports(ip: str, config: dict, port_override: str | None = None,
                      full_ports: bool = False) -> tuple[list[PortResult], list[str]]:
    """Returns (results, warnings)."""
    warnings: list[str] = []
    port_cfg = config.get("port_scan", {})

    if port_override:
        ports = port_override
    elif full_ports:
        ports = "1-65535"
    else:
        ports = TOP_1000_PORTS

    if nmap_available():
        try:
            results = await asyncio.to_thread(
                scan_with_nmap, ip, ports, port_cfg.get("timing_template", "T4")
            )
        except Exception as e:
            warnings.append(f"nmap scan failed ({e}); falling back to basic TCP connect scan.")
            results = await _fallback_scan(ip, ports)
    else:
        warnings.append("nmap not found on system PATH — using basic TCP connect scan "
                         "(no service/version detection). Install nmap for full results.")
        results = await _fallback_scan(ip, ports)

    for r in results:
        note = _severity_note_for_port(r.port, r.service)
        if note:
            r.banner = f"{r.banner + ' | ' if r.banner else ''}NOTE: {note}"

    return results, warnings


async def _fallback_scan(ip: str, ports: str) -> list[PortResult]:
    port_list = _expand_port_spec(ports)
    return await _tcp_connect_scan(ip, port_list)


def _expand_port_spec(spec: str) -> list[int]:
    ports: list[int] = []
    for chunk in spec.split(","):
        if "-" in chunk:
            start, end = chunk.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(chunk))
    return ports
