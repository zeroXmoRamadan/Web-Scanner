"""Information Disclosure Scanner module (passive analysis only — no payloads sent).
Scans crawl responses for environment variables, secrets, private keys, database credentials, internal IPs, and stack traces.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse
from typing import Optional

from asfoor.core.models import CrawlResponse, VulnerabilityFinding

SECRETS_PATTERNS = {
    "AWS Access Key ID": r"\b(AKIA[0-9A-Z]{16})\b",
    "Private Key": r"-----BEGIN (RSA|EC|PGP|OPENSSH)? PRIVATE KEY-----",
    "Database Connection String": r"\b(mongodb\+srv:\/\/|postgres:\/\/|mysql:\/\/|jdbc:(mysql|postgresql|oracle|sqlserver):)\S+\b",
    "Generic API Key/Token": r"(?i)(api[-_]?key|secret[-_]?token|auth[-_]?token|db[-_]?pass|database[-_]?password)\s*[:=]\s*[\"']([a-zA-Z0-9_\-\.]{16,})[\"']"
}

STACK_TRACES = {
    "Python/Django Stack Trace": r"Traceback \(most recent call last\)",
    "PHP Fatal Error": r"(?i)(Fatal error:|stack trace:|in /var/www/|Call Stack:)",
    "Java Stack Trace": r"at [a-zA-Z0-9\._]+\([a-zA-Z0-9_\.]+\.java:\d+\)",
    "Node.js Stack Trace": r"(?s)Error: .*?\n\s+at\s+"
}

INTERNAL_IP_PATTERN = r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"

EMAIL_PATTERN = r"\b[a-zA-Z0-9\._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"

SENSITIVE_FILE_EXTENSIONS = (
    ".env", ".git", ".svn", ".bak", ".sql", ".zip", ".tgz", ".tar.gz",
    ".log", ".conf", ".cfg", ".yml", ".yaml", ".json", ".xml"
)


async def detect_info_disclosure(
    crawl_responses: list[CrawlResponse]
) -> list[VulnerabilityFinding]:
    """Passively scans responses for leaked sensitive credentials, system details, and environments."""
    findings: list[VulnerabilityFinding] = []
    
    for resp in crawl_responses:
        parsed_url = urlparse(resp.url)
        path = parsed_url.path.lower()
        
        # 1. Scan for Stack Traces (High Severity)
        for trace_name, pattern in STACK_TRACES.items():
            match = re.search(pattern, resp.body)
            if match:
                start = max(0, match.start() - 30)
                end = min(len(resp.body), match.end() + 250)
                evidence = resp.body[start:end].strip()
                
                findings.append(VulnerabilityFinding(
                    module="info_disclosure",
                    endpoint=resp.url,
                    parameter=None,
                    method=resp.method,
                    finding_type="Information Disclosure (Application Stack Trace)",
                    confidence="HIGH",
                    evidence=f"... {evidence} ...",
                    description=f"Passive analysis detected a {trace_name} in the response body, exposing internal path layouts or database structures."
                ))
                break # Limit to one stack trace finding per page
                
        # 2. Scan for Secrets & API Keys (High Severity)
        for secret_name, pattern in SECRETS_PATTERNS.items():
            matches = re.finditer(pattern, resp.body)
            for m in matches:
                # Mask key/secret for safety
                full_match = m.group(0)
                # Show first 4 characters and last 4 characters, mask middle
                if len(full_match) > 12:
                    masked = full_match[:6] + "..." + full_match[-6:]
                else:
                    masked = "..."
                    
                start = max(0, m.start() - 40)
                end = min(len(resp.body), m.end() + 40)
                evidence = resp.body[start:end].replace(full_match, masked).strip()
                
                findings.append(VulnerabilityFinding(
                    module="info_disclosure",
                    endpoint=resp.url,
                    parameter=None,
                    method=resp.method,
                    finding_type=f"Sensitive Data Exposure ({secret_name})",
                    confidence="HIGH",
                    evidence=f"... {evidence} ...",
                    description=f"Passive analysis detected a potential {secret_name} in the response body."
                ))
                
        # 3. Scan for Private/Internal IPs (Medium Severity)
        ip_matches = re.finditer(INTERNAL_IP_PATTERN, resp.body)
        logged_ips = set()
        for m in ip_matches:
            ip = m.group(0)
            if ip in logged_ips or ip.startswith(("127.", "0.")):
                continue
            logged_ips.add(ip)
            
            start = max(0, m.start() - 30)
            end = min(len(resp.body), m.end() + 30)
            evidence = resp.body[start:end].strip()
            
            findings.append(VulnerabilityFinding(
                module="info_disclosure",
                endpoint=resp.url,
                parameter=None,
                method=resp.method,
                finding_type="Information Disclosure (Internal IP Leak)",
                confidence="MEDIUM",
                evidence=f"... {evidence} ...",
                description=f"Internal RFC 1918 IP address '{ip}' was found leaked in response body."
            ))
            
        # 4. Scan for Configuration or backup files exposure in the URL path (Medium Severity)
        if any(path.endswith(ext) for ext in SENSITIVE_FILE_EXTENSIONS):
            findings.append(VulnerabilityFinding(
                module="info_disclosure",
                endpoint=resp.url,
                parameter=None,
                method=resp.method,
                finding_type="Sensitive Configuration / File Exposure",
                confidence="HIGH" if path.endswith((".env", ".sql", ".git")) else "MEDIUM",
                evidence=f"Exposed URL: {resp.url}",
                description=f"Passively crawled response references a potentially sensitive configuration or backup file path: {parsed_url.path}."
            ))
            
        # 5. Scan for emails, but ONLY in non-HTML configuration or javascript assets to avoid noise
        is_html = "text/html" in resp.headers.get("Content-Type", "").lower() or not path
        if not is_html:
            email_matches = re.finditer(EMAIL_PATTERN, resp.body)
            logged_emails = set()
            for m in email_matches:
                email = m.group(0)
                if email in logged_emails or any(x in email.lower() for x in ("example", "test", "support@", "admin@")):
                    continue
                logged_emails.add(email)
                
                start = max(0, m.start() - 30)
                end = min(len(resp.body), m.end() + 30)
                evidence = resp.body[start:end].strip()
                
                findings.append(VulnerabilityFinding(
                    module="info_disclosure",
                    endpoint=resp.url,
                    parameter=None,
                    method=resp.method,
                    finding_type="Information Disclosure (Developer Email Leak)",
                    confidence="LOW",
                    evidence=f"... {evidence} ...",
                    description=f"Developer email address '{email}' discovered in JS/config asset."
                ))
                
    return findings
