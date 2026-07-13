"""Port scanning via nmap (preferred, gives service/version detection) with a
fallback to a plain asyncio TCP connect scan if nmap isn't installed. Also
performs UDP scanning, banner grabbing, and passive OS fingerprinting.
"""
from __future__ import annotations

import asyncio
import logging
import platform
import re
import shutil
import socket
import ssl
import subprocess
from typing import Optional

from asfoor.core.models import PortResult
from asfoor.utils.rate_limiter import RateLimiter

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

COMMON_UDP_PORTS = (53, 67, 68, 69, 123, 137, 138, 139, 161, 162, 389, 500, 1900, 5353)


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
                confidence=100 if version else 50,
            ))
    return results


async def _tcp_connect_scan(ip: str, port_list: list[int], timeout: float = 1.5) -> list[PortResult]:
    """Basic TCP connect scan. Kept for unit test compatibility."""
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
                pass

    await asyncio.gather(*(check_port(p) for p in port_list))
    results.sort(key=lambda r: r.port)
    return results


async def _grab_banner_and_detect_service(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    port: int,
    timeout: float
) -> tuple[str | None, str | None, str | None, int]:
    """Passive banner grabbing and service identification."""
    service = None
    version = None
    banner = None
    confidence = 50

    try:
        if port in (80, 443, 8080, 8443):
            req = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: 3asfoor/1.0\r\nConnection: close\r\n\r\n"
            writer.write(req.encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            resp_str = resp.decode("utf-8", errors="ignore")
            banner = resp_str.split("\r\n\r\n")[0]
            service = "http" if port not in (443, 8443) else "https"
            confidence = 70

            server_match = re.search(r"(?i)Server:\s*([^\r\n]+)", resp_str)
            if server_match:
                server_val = server_match.group(1).strip()
                parts = server_val.split("/")
                if len(parts) >= 2:
                    service = parts[0]
                    version_match = re.match(r"^([\d.]+[a-zA-Z0-9_-]*)", parts[1])
                    if version_match:
                        version = version_match.group(1)
                        confidence = 90
                else:
                    service = server_val
                    confidence = 80
        elif port == 22:
            resp = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            resp_str = resp.decode("utf-8", errors="ignore").strip()
            banner = resp_str
            service = "ssh"
            confidence = 80
            match = re.search(r"OpenSSH_([\d.]+p\d+|[\d.]+)", resp_str)
            if match:
                version = match.group(1)
                confidence = 95
        elif port == 21:
            resp = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            resp_str = resp.decode("utf-8", errors="ignore").strip()
            banner = resp_str
            service = "ftp"
            confidence = 80
            match = re.search(r"vsFTPd\s+([\d.]+)", resp_str, re.IGNORECASE)
            if match:
                version = match.group(1)
                confidence = 95
        elif port in (25, 587):
            resp = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            resp_str = resp.decode("utf-8", errors="ignore").strip()
            banner = resp_str
            service = "smtp"
            confidence = 80
        elif port == 110:
            resp = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            resp_str = resp.decode("utf-8", errors="ignore").strip()
            banner = resp_str
            service = "pop3"
            confidence = 80
        elif port == 143:
            resp = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            resp_str = resp.decode("utf-8", errors="ignore").strip()
            banner = resp_str
            service = "imap"
            confidence = 80
        elif port == 3306:
            resp = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            if len(resp) > 5:
                resp_str = resp[5:].decode("utf-8", errors="ignore")
                match = re.search(r"([0-9]+\.[0-9]+\.[0-9]+[a-zA-Z0-9_-]*)", resp_str)
                if match:
                    version = match.group(1)
                    service = "mysql"
                    banner = f"MySQL Server {version}"
                    confidence = 95
                else:
                    service = "mysql"
                    confidence = 80
        elif port == 6379:
            writer.write(b"INFO\r\n")
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            resp_str = resp.decode("utf-8", errors="ignore")
            service = "redis"
            banner = "Redis Key-Value Store"
            confidence = 80
            match = re.search(r"redis_version:([\d.]+)", resp_str)
            if match:
                version = match.group(1)
                confidence = 95
        else:
            try:
                resp = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                resp_str = resp.decode("utf-8", errors="ignore").strip()
                if resp_str:
                    banner = resp_str
                    confidence = 60
                    if "ssh" in resp_str.lower():
                        service = "ssh"
                    elif "ftp" in resp_str.lower():
                        service = "ftp"
                    elif "smtp" in resp_str.lower():
                        service = "smtp"
            except asyncio.TimeoutError:
                writer.write(b"GET / HTTP/1.0\r\n\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                resp_str = resp.decode("utf-8", errors="ignore").strip()
                if resp_str:
                    banner = resp_str.split("\r\n\r\n")[0]
                    if "http" in resp_str.lower() or "html" in resp_str.lower():
                        service = "http"
                        confidence = 60
                        server_match = re.search(r"(?i)Server:\s*([^\r\n]+)", resp_str)
                        if server_match:
                            service = server_match.group(1).strip()
    except Exception as e:
        logger.debug("Failed banner grab on port %d: %s", port, e)

    if service:
        service = service.strip()
    if version:
        version = version.strip()
    if banner:
        banner = banner.strip()

    return service, version, banner, confidence


async def _tcp_probe_port(
    ip: str,
    port: int,
    timeout: float,
    rate_limiter: RateLimiter,
    sem: asyncio.Semaphore
) -> PortResult | None:
    """Probes a single TCP port, upgrading to SSL if needed and grabbing banners."""
    async with sem:
        await rate_limiter.wait()
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)

            service = "http" if port in (80, 8080) else None
            version = None
            banner = None
            confidence = 50

            if port in (443, 8443):
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                try:
                    context = ssl._create_unverified_context()
                    conn_ssl = asyncio.open_connection(ip, port, ssl=context)
                    reader_ssl, writer_ssl = await asyncio.wait_for(conn_ssl, timeout=timeout)
                    service, version, banner, confidence = await _grab_banner_and_detect_service(reader_ssl, writer_ssl, port, timeout)
                    writer_ssl.close()
                    try:
                        await writer_ssl.wait_closed()
                    except Exception:
                        pass
                except Exception as ssl_err:
                    service = "https"
                    banner = f"TLS Handshake failed: {ssl_err}"
                    confidence = 60
            else:
                service, version, banner, confidence = await _grab_banner_and_detect_service(reader, writer, port, timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            return PortResult(
                port=port,
                protocol="tcp",
                state="open",
                service=service,
                version=version,
                banner=banner,
                confidence=confidence
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None


def _map_udp_service(port: int) -> str | None:
    mapping = {
        53: "dns",
        67: "dhcps",
        68: "dhcpc",
        69: "tftp",
        123: "ntp",
        135: "msrpc",
        137: "netbios-ns",
        138: "netbios-dgm",
        139: "netbios-ssn",
        161: "snmp",
        162: "snmptrap",
        389: "ldap",
        500: "isakmp",
        514: "syslog",
        520: "route",
        1900: "ssdp",
        4500: "ipsec-nat-t",
        5353: "mdns",
    }
    return mapping.get(port)


async def _udp_probe_port(
    ip: str,
    port: int,
    timeout: float,
    rate_limiter: RateLimiter,
    sem: asyncio.Semaphore
) -> PortResult:
    """Probes a single UDP port using timeout-based response classification."""
    async with sem:
        await rate_limiter.wait()
        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            await loop.sock_connect(sock, (ip, port))
            payload = b""
            if port == 53:
                payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
            elif port == 123:
                payload = b"\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            elif port == 161:
                payload = b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x12\x34\x56\x78\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
            
            if payload:
                await loop.sock_sendall(sock, payload)
            else:
                await loop.sock_sendall(sock, b"")
                
            await asyncio.wait_for(loop.sock_recv(sock, 1024), timeout=timeout)
            service = _map_udp_service(port)
            return PortResult(port=port, protocol="udp", state="open", service=service, confidence=90)
        except asyncio.TimeoutError:
            service = _map_udp_service(port)
            return PortResult(port=port, protocol="udp", state="open|filtered", service=service, confidence=50)
        except (ConnectionRefusedError, ConnectionResetError):
            return PortResult(port=port, protocol="udp", state="closed", confidence=100)
        except OSError:
            service = _map_udp_service(port)
            return PortResult(port=port, protocol="udp", state="filtered", service=service, confidence=50)
        finally:
            sock.close()


async def _custom_tcp_scan(
    ip: str,
    port_list: list[int],
    timeout: float,
    concurrency: int,
    rate_limit: float
) -> list[PortResult]:
    sem = asyncio.Semaphore(concurrency)
    rate_limiter = RateLimiter(rate_limit)
    tasks = [_tcp_probe_port(ip, port, timeout, rate_limiter, sem) for port in port_list]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]


async def _custom_udp_scan(
    ip: str,
    port_list: list[int],
    timeout: float,
    concurrency: int,
    rate_limit: float
) -> list[PortResult]:
    sem = asyncio.Semaphore(concurrency)
    rate_limiter = RateLimiter(rate_limit)
    tasks = [_udp_probe_port(ip, port, timeout, rate_limiter, sem) for port in port_list]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]


async def _get_ttl_via_ping(ip: str) -> int | None:
    """Send a single ICMP echo request to extract target host's TTL."""
    is_windows = platform.system().lower() == "windows"
    cmd = ["ping", "-n", "1", "-w", "1000", ip] if is_windows else ["ping", "-c", "1", "-W", "1", ip]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        stdout_str = stdout.decode("utf-8", errors="ignore")
        match = re.search(r"ttl=(\d+)", stdout_str, re.IGNORECASE)
        if match:
            return int(match.group(1))
    except Exception:
        pass
    return None


async def _fingerprint_os_passive(ip: str, banners: list[str]) -> str:
    """Infer likely OS family from TTL values and service banner clues observed in responses."""
    ttl = await _get_ttl_via_ping(ip)
    os_family = "Unknown"

    if ttl is not None:
        if ttl <= 64:
            os_family = "Linux/Unix (likely Linux or FreeBSD)"
        elif ttl <= 128:
            os_family = "Windows"
        else:
            os_family = "Cisco/Network Device"

    for banner in banners:
        if not banner:
            continue
        banner_lower = banner.lower()
        if any(x in banner_lower for x in ("ubuntu", "debian", "centos", "redhat", "linux")):
            os_family = "Linux/Unix (likely Linux)"
            break
        elif any(x in banner_lower for x in ("windows", "win32", "win64", "iis", "microsoft")):
            os_family = "Windows"
            break
        elif "cisco" in banner_lower:
            os_family = "Cisco/Network Device"
            break

    return os_family


async def _fallback_scan(ip: str, ports: str, config: dict | None = None) -> list[PortResult]:
    """Falls back to custom pure-Python connect scan when Nmap is unavailable."""
    port_list = _expand_port_spec(ports)
    port_cfg = config.get("port_scan", {}) if config else {}
    concurrency = port_cfg.get("concurrency", 100) or 100
    rate_limit = port_cfg.get("rate_limit_seconds", 0.0) or 0.0
    timeout = port_cfg.get("timeout_seconds", 1.5) or 1.5
    
    return await _custom_tcp_scan(ip, port_list, timeout, concurrency, rate_limit)


async def scan_ports(
    ip: str,
    config: dict,
    port_override: str | None = None,
    full_ports: bool = False
) -> tuple[list[PortResult], list[str]]:
    """Returns (results, warnings)."""
    warnings: list[str] = []
    port_cfg = config.get("port_scan", {})

    if port_override:
        ports = port_override
    elif full_ports:
        ports = "1-65535"
    else:
        ports = TOP_1000_PORTS

    concurrency = port_cfg.get("concurrency", 100) or 100
    rate_limit = port_cfg.get("rate_limit_seconds", 0.0) or 0.0
    timeout = port_cfg.get("timeout_seconds", 1.5) or 1.5

    # 1. Run TCP scanning
    if nmap_available():
        try:
            tcp_results = await asyncio.to_thread(
                scan_with_nmap, ip, ports, port_cfg.get("timing_template", "T4")
            )
        except Exception as e:
            warnings.append(f"nmap scan failed ({e}); falling back to custom TCP scan.")
            tcp_results = await _fallback_scan(ip, ports, config)
    else:
        warnings.append("nmap not found on system PATH — using custom TCP connect scan "
                         "(no external service/version detection). Install nmap for full results.")
        tcp_results = await _fallback_scan(ip, ports, config)

    # 2. Run UDP scanning on common UDP ports
    udp_ports = _expand_port_spec(ports) if port_override else COMMON_UDP_PORTS
    # Keep UDP scan concurrency reasonable (max 20 to avoid overwhelming OS ICMP rate limiters)
    udp_concurrency = min(concurrency, 20)
    udp_results = await _custom_udp_scan(ip, list(udp_ports), timeout, udp_concurrency, rate_limit)

    results = tcp_results + udp_results

    # 3. Passive OS fingerprinting
    banners = [r.banner for r in results if r.banner]
    inferred_os = await _fingerprint_os_passive(ip, banners)
    warnings.append(f"OS Fingerprint: {inferred_os}")

    # 4. Apply severity notes
    for r in results:
        note = _severity_note_for_port(r.port, r.service)
        if note:
            r.banner = f"{r.banner + ' | ' if r.banner else ''}NOTE: {note}"

    results.sort(key=lambda r: (r.protocol, r.port))
    return results, warnings


def _expand_port_spec(spec: str) -> list[int]:
    ports: list[int] = []
    for chunk in spec.split(","):
        if "-" in chunk:
            start, end = chunk.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(chunk))
    return ports
