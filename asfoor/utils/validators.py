"""Input validation and the mandatory authorization gate.

This tool is for scanning domains you own or are explicitly authorized to
test. Port scanning and directory brute-forcing without permission is
illegal in most jurisdictions (e.g. the US Computer Fraud and Abuse Act).
The CLI enforces an explicit opt-in before any active scanning occurs.
"""
from __future__ import annotations

import re
import socket

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


class InvalidDomainError(ValueError):
    pass


class PermissionNotGrantedError(RuntimeError):
    pass


def validate_domain(domain: str) -> str:
    """Normalize and validate a domain string. Strips scheme/path if present."""
    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]  # strip a port if the user included one

    if not _DOMAIN_RE.match(domain):
        raise InvalidDomainError(f"'{domain}' does not look like a valid domain name.")

    return domain


def resolve_ip(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def enforce_permission_gate(permission_flag: bool, interactive: bool = True) -> None:
    """Require explicit authorization before any active scanning proceeds.

    Raises PermissionNotGrantedError if permission was not confirmed via the
    --i-have-permission flag and (when interactive) the user declines the
    follow-up confirmation prompt.
    """
    if permission_flag:
        return

    if interactive:
        answer = input(
            "This tool performs active scanning (ports, directories). "
            "Only run it against domains you own or are explicitly authorized "
            "to test. Confirm you have permission to scan this target? [y/N]: "
        ).strip().lower()
        if answer == "y":
            return

    raise PermissionNotGrantedError(
        "Scan aborted: authorization was not confirmed. Re-run with "
        "--i-have-permission if you are authorized to scan this target."
    )
