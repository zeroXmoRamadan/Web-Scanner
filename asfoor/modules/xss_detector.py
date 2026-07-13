"""XSS Detector module (passive analysis only — no payloads sent).
Audits missing security headers, scans JavaScript code for DOM XSS flows, and checks reflection contexts.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlparse
from bs4 import BeautifulSoup
from typing import Optional

from asfoor.core.models import CrawlResponse, FormDetails, VulnerabilityFinding

# DOM XSS Sources and Sinks patterns
DOM_SOURCES = [
    r"\bdocument\.(URL|documentURI|URLUnencoded|baseURI|referrer)\b",
    r"\blocation\.(href|search|hash)\b",
    r"\bwindow\.name\b",
]

DOM_SINKS = [
    r"\.innerHTML\b",
    r"\.outerHTML\b",
    r"\bdocument\.write\s*\(",
    r"\bdocument\.writeln\s*\(",
    r"\beval\s*\(",
    r"\bsetTimeout\s*\([^,]+,",
    r"\bsetInterval\s*\([^,]+,",
    r"\bnew\s+Function\s*\(",
    r"\blocation\.(replace|assign)\s*\(",
]


def audit_headers(headers: dict[str, str]) -> list[tuple[str, str, str]]:
    """Audits response headers for security issues.
    Returns list of tuples: (finding_type, confidence, description).
    """
    findings = []
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    # 1. CSP
    csp = headers_lower.get("content-security-policy")
    if not csp:
        findings.append((
            "Missing Security Header: Content-Security-Policy",
            "LOW",
            "The Content-Security-Policy (CSP) header is missing, which is a key defense-in-depth mechanism against XSS."
        ))
    else:
        weaknesses = []
        if "unsafe-inline" in csp:
            weaknesses.append("unsafe-inline")
        if "unsafe-eval" in csp:
            weaknesses.append("unsafe-eval")
        if "*" in csp:
            weaknesses.append("wildcard source (*)")
            
        if weaknesses:
            findings.append((
                "Weak Content-Security-Policy Configuration",
                "MEDIUM",
                f"CSP header was found but contains potentially weak directives: {', '.join(weaknesses)}."
            ))
            
    # 2. X-Content-Type-Options
    x_cto = headers_lower.get("x-content-type-options")
    if not x_cto or "nosniff" not in x_cto.lower():
        findings.append((
            "Missing/Weak Security Header: X-Content-Type-Options",
            "LOW",
            "The X-Content-Type-Options header is missing or not set to 'nosniff', which could allow MIME-sniffing vulnerabilities."
        ))
        
    # 3. Clickjacking (X-Frame-Options or CSP frame-ancestors)
    x_fo = headers_lower.get("x-frame-options")
    has_frame_ancestors = csp and "frame-ancestors" in csp
    if not x_fo and not has_frame_ancestors:
        findings.append((
            "Missing Security Header: X-Frame-Options",
            "LOW",
            "Neither X-Frame-Options nor CSP frame-ancestors is configured. The application might be vulnerable to Clickjacking."
        ))
        
    return findings


def scan_dom_xss_flows(js_code: str) -> list[tuple[str, str]]:
    """Scans JS code for potential DOM XSS source-to-sink flows within a small range of line numbers.
    Returns list of (evidence, description).
    """
    findings = []
    lines = js_code.splitlines()
    
    source_matches = []
    sink_matches = []
    
    for idx, line in enumerate(lines):
        line_num = idx + 1
        # Find sources
        for pat in DOM_SOURCES:
            if re.search(pat, line):
                source_matches.append((line_num, line.strip()))
                break
        # Find sinks
        for pat in DOM_SINKS:
            if re.search(pat, line):
                sink_matches.append((line_num, line.strip()))
                break
                
    # Detect if any source and sink are close (within 15 lines of each other)
    for src_line, src_text in source_matches:
        for sink_line, sink_text in sink_matches:
            if abs(src_line - sink_line) <= 15:
                # Capture block context
                start = max(1, min(src_line, sink_line) - 2)
                end = min(len(lines), max(src_line, sink_line) + 2)
                snippet_lines = [f"{i}: {lines[i-1]}" for i in range(start, end + 1)]
                evidence = "\n".join(snippet_lines)
                
                desc = (
                    f"Possible DOM XSS flow: Source '{src_text}' (line {src_line}) "
                    f"flows into Sink '{sink_text}' (line {sink_line}) in close proximity."
                )
                findings.append((evidence, desc))
                break # Avoid duplicate warnings on same source
                
    return findings


def audit_reflection_context(html: str, value: str) -> tuple[str, str, str] | None:
    """Checks if the reflected value resides inside dangerous HTML contexts.
    Returns (finding_type, confidence, evidence) or None.
    """
    if not value or len(value) < 4:
        return None
        
    soup = BeautifulSoup(html, "html.parser")
    
    # 1. Script tag check
    for script in soup.find_all("script"):
        if script.string and value in script.string:
            # Check context around reflection in script
            idx = script.string.find(value)
            start = max(0, idx - 40)
            end = min(len(script.string), idx + len(value) + 60)
            evidence = f"<script>... {script.string[start:end].strip()} ...</script>"
            return "Cross-Site Scripting (Script Block Reflection)", "HIGH", evidence
            
    # 2. Attribute / Event handler check
    for tag in soup.find_all(True):
        for attr_name, attr_val in tag.attrs.items():
            attr_str = " ".join(attr_val) if isinstance(attr_val, list) else str(attr_val)
            if value in attr_str:
                # Check if it is an event handler
                if attr_name.lower().startswith("on"):
                    evidence = f"<{tag.name} {attr_name}=\"{attr_str}\">"
                    return "Cross-Site Scripting (Event Handler Reflection)", "HIGH", evidence
                # Check if it is a javascript: URL attribute
                if attr_name.lower() in ("src", "href") and attr_str.lower().strip().startswith("javascript:"):
                    evidence = f"<{tag.name} {attr_name}=\"{attr_str}\">"
                    return "Cross-Site Scripting (JavaScript URI Reflection)", "HIGH", evidence
                    
    return None


async def detect_xss(
    crawl_responses: list[CrawlResponse],
    forms: list[FormDetails]
) -> list[VulnerabilityFinding]:
    """Analyzes crawl responses passively for indicators of Cross-Site Scripting (XSS)."""
    findings: list[VulnerabilityFinding] = []
    
    audited_urls = set()
    
    for resp in crawl_responses:
        # 1. Auditing headers once per URL to avoid duplicates
        if resp.url not in audited_urls:
            header_findings = audit_headers(resp.headers)
            for f_type, conf, desc in header_findings:
                findings.append(VulnerabilityFinding(
                    module="xss",
                    endpoint=resp.url,
                    parameter=None,
                    method="GET",
                    finding_type=f_type,
                    confidence=conf,
                    evidence="—",
                    description=desc
                ))
            audited_urls.add(resp.url)
            
        # 2. Audit script responses or script blocks for DOM XSS
        # Check if the url itself is a javascript file or has JS body
        parsed_url = urlparse(resp.url)
        is_js_file = parsed_url.path.lower().endswith(".js") or "javascript" in resp.headers.get("Content-Type", "").lower()
        
        if is_js_file:
            flows = scan_dom_xss_flows(resp.body)
            for evidence, desc in flows:
                findings.append(VulnerabilityFinding(
                    module="xss",
                    endpoint=resp.url,
                    parameter=None,
                    method="GET",
                    finding_type="DOM-based Cross-Site Scripting (JS Flow)",
                    confidence="MEDIUM",
                    evidence=evidence,
                    description=desc
                ))
        else:
            # Parse inline scripts in HTML
            soup = BeautifulSoup(resp.body, "html.parser")
            for idx, script in enumerate(soup.find_all("script")):
                if script.string:
                    flows = scan_dom_xss_flows(script.string)
                    for evidence, desc in flows:
                        findings.append(VulnerabilityFinding(
                            module="xss",
                            endpoint=resp.url,
                            parameter=None,
                            method="GET",
                            finding_type="DOM-based Cross-Site Scripting (Inline Flow)",
                            confidence="MEDIUM",
                            evidence=evidence,
                            description=f"In script block #{idx + 1}: {desc}"
                        ))
                        
            # 3. Context-aware reflection audit
            params = parse_qsl(parsed_url.query)
            for name, value in params:
                reflection = audit_reflection_context(resp.body, value)
                if reflection:
                    f_type, conf, evidence = reflection
                    findings.append(VulnerabilityFinding(
                        module="xss",
                        endpoint=resp.url,
                        parameter=name,
                        method="GET",
                        finding_type=f_type,
                        confidence=conf,
                        evidence=evidence,
                        description=f"Passive scan detected the value of '{name}' ('{value}') reflected in a dangerous execution context."
                    ))
                    
    return findings
