"""Startup ASCII-art banner for 3asfoor.

The art is a static string (pre-generated) so there is no extra runtime
dependency (e.g. pyfiglet) required just to print a banner.
"""
from __future__ import annotations

from rich.console import Console

BANNER = r"""
 _____  ___   ___________ _____  ___________
|____ |/ _ \ /  ___|  ___|  _  ||  _  | ___ \
    / / /_\ \\ `--.| |_  | | | || | | | |_/ /
    \ \  _  | `--. \  _| | | | || | | |    /
.___/ / | | |/\__/ / |   \ \_/ /\ \_/ / |\ \
\____/\_| |_/\____/\_|    \___/  \___/\_| \_|
"""

TAGLINE = "web recon & vulnerability scanner"


def print_banner(console: Console) -> None:
    console.print(f"[bold magenta]{BANNER}[/bold magenta]")
    console.print(f"[dim]{TAGLINE}[/dim]\n")
