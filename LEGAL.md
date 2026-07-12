# Authorized Use Only

This tool performs **active scanning** against network targets: port scanning,
directory/file brute-forcing, and automated requests to discover technology
and version information. It also includes a **passive** link/secret finder
that only parses content the target already serves (homepage HTML and linked
JS/CSS) — still, running the tool at all against a target implies fetching
its pages, so the same authorization requirement applies to every module.

Running these actions against a system you do not own or do not have
explicit, documented authorization to test may be illegal in your
jurisdiction — for example, under the U.S. Computer Fraud and Abuse Act
(CFAA), the UK Computer Misuse Act, or equivalent laws elsewhere.

**Before running this tool against any target:**
- Only scan domains/systems you own, or
- Have explicit written permission from the system owner (e.g. a signed
  authorization letter, a bug bounty program's defined scope, or a
  university-sanctioned lab environment).

The tool requires you to confirm authorization (`--i-have-permission` flag or
an interactive confirmation prompt) before any active scan runs. This is a
safeguard, not a legal shield — you are responsible for ensuring you have
proper authorization for every target you scan.

This project is provided for educational purposes as part of a graduation
project. The authors are not responsible for misuse.
