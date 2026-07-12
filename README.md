# 3asfoor — Web Recon & Vulnerability Scanner

A CLI tool that, given only a domain, scans it for:

- **Technology fingerprinting** — CMS, frameworks, servers, JS libraries, and their versions
- **Known CVEs** for the detected technologies (via the NVD API)
- **Open ports & services** (via nmap, with a fallback TCP connect scan)
- **Directories & sensitive files** — active wordlist brute-force (config backups, `.env`, `.git`, exposed keys, etc.)
- **Passive link, path & secret discovery** — a **FindSomething-style** pass over the homepage
  HTML and linked JS/CSS/JSON that classifies everything it finds into the same category
  buckets that tool reports. See [Passive Link & Secret Discovery](#passive-link-path--secret-discovery-link_finderpy)
  below for full details.

Built as a part of a graduation project at DEPI. See [`LEGAL.md`](./LEGAL.md) before using this against any target.

## Install

```bash
git clone https://github.com/zeroXmoRamadan/Web-Scanner.git
cd Web-Scanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

**nmap** is required for full port-scan results (service/version detection). Without it, the tool
falls back to a basic open/closed TCP connect scan.

- macOS: `brew install nmap`
- Debian/Ubuntu: `sudo apt install nmap`
- Windows: install from [nmap.org](https://nmap.org/download.html)

## (Optional) How to set up NVD_API_KEY

**Linux/macOS (temporary, current shell session):**

```bash
export NVD_API_KEY="your-key-here"
3asfoor scan example.com --i-have-permission
```

**Linux/macOS (permanent):** add that `export` line to `~/.bashrc` / `~/.zshrc`, then `source` it.

**Windows PowerShell:**

```powershell
$env:NVD_API_KEY="your-key-here"
```

## Usage

```bash
3asfoor scan example.com --i-have-permission
```

You will be prompted for confirmation if `--i-have-permission` is omitted — the tool
will not run active scans (ports/directories) without explicit authorization.

On start, the tool prints an ASCII-art banner, then live phase progress as it works
(e.g. `* Running port scanning...`, `* port scanning complete`). Once the scan finishes,
the **full report is always printed to the console** — technologies with their CVEs, open
ports, discovered directories/files, and every passive link/path/secret finding grouped
into its category (Domain, PATH, Incomplete Path, URL, Static Path, IP Address, Email
Address, Sensitive Information, Dynamic Code Analysis) — as readable, color-coded tables.
No report file is written unless you ask for one.

### Exporting report files

Writing JSON/HTML/`_findings.txt` files to disk is **optional** and separate from viewing
the report:

```bash
3asfoor scan example.com --i-have-permission --export      # always write the files
3asfoor scan example.com --i-have-permission --no-export   # never write the files
3asfoor scan example.com --i-have-permission                # you'll be asked after the scan
3asfoor scan example.com --i-have-permission --quiet         # quiet implies --no-export unless --export is also passed
```

If you don't pass either flag, the tool asks `Export report files (...) to '<output_dir>'? [y/N]`
right after printing the console report. In `--quiet` mode there's no prompt — the default is
not to write files, so nothing is created unless you explicitly pass `--export`.

### Common options

```bash
# Full 65535-port scan instead of top 1000
3asfoor scan example.com --i-have-permission --full-ports

# Custom port range
3asfoor scan example.com --i-have-permission --ports "80,443,8080-8100"

# Skip specific modules
3asfoor scan example.com --i-have-permission --skip-ports
3asfoor scan example.com --i-have-permission --skip-dirs    # skip active wordlist brute-force
3asfoor scan example.com --i-have-permission --skip-links   # skip passive FindSomething-style discovery
3asfoor scan example.com --i-have-permission --skip-cve

# When exporting, choose which file formats to write (default is both)
3asfoor scan example.com --i-have-permission --export --format json

# Custom output directory (only used if exporting)
3asfoor scan example.com --i-have-permission --export --output-dir ./my-reports
```

Run `3asfoor scan --help` for the full option list.

## Output

The console report (always shown) covers, in order: technologies + CVE detail, open ports,
directories/files found, and passive link/path/secret findings grouped by category — with
sensitive-information and dynamic-code-analysis hits highlighted, and a warnings section at
the end if anything went wrong mid-scan.

If you choose to export (`--export`, or answering "yes" to the prompt), the tool additionally
writes to `./output/` by default:

- `report_<domain>_<timestamp>.json` — full structured results (every field, machine-readable)
- `report_<domain>_<timestamp>.html` — the same report as a standalone, shareable HTML file
- `report_<domain>_<timestamp>_findings.txt` — the passive link/secret findings only,
  as a grouped plain-text export (only written when at least one finding exists) — see below
- `scan.log` — run log (always written, independent of `--export`)

## Passive Link, Path & Secret Discovery (`link_finder.py`)

This module is modeled on the **FindSomething** browser extension: rather than guessing
paths by brute-forcing a wordlist against the server (that's what `dir_scan.py` does), it
parses content the target **already serves** — the homepage HTML plus every linked
`<script src>` / `<link href>` asset that looks textual (JS, CSS, JSON, source maps) — and
regex-classifies everything it finds into the same buckets that tool reports. Nothing here
is requested that a normal browser wouldn't already fetch when loading the page; it is
**100% passive**.

### Categories

| Section (report label)   | What it catches | Example |
|---|---|---|
| **Domain** | A root `scheme://host[:port]` reference — nothing meaningful follows the host | `https://www.hcaptcha.com` |
| **PATH** | A real absolute or relative resource path — quoted JS string literals starting with `/`, `./` or `../`, `href`/`src`/`action`/`formaction` attribute values, and framework-specific markers like DevExpress's `/*DX*/` | `/api/v2/internal/status`, `./Default.aspx` |
| **Incomplete Path** | A slash-bearing token that *looks* path-like but isn't a real path or URL — MIME types, `Date`-style format strings, a lone `"://"` separator literal, or a browser-sniffing fragment | `text/javascript`, `MM/dd/yyyy`, `Opera/` |
| **URL** | A full `scheme://host/path...` string (or a bare `host.tld/path` with no scheme) | `https://www.gstatic.com/images/branding/googlelogo` |
| **Static Path** | An XML/XHTML namespace URI pulled from an `xmlns` attribute — a fixed, spec-defined identifier rather than an endpoint the app serves | `http://www.w3.org/1999/xhtml` |
| **IP Address** | A bare IPv4 address in the source | `10.0.0.42` |
| **Email Address** | A bare email address in the source | `support@example.com` |
| **Sensitive Information** | A client-side identifier/JSON key whose name contains a credential-shaped keyword (`password`, `token`, `secret`, `key`, `auth`, `session`, `cookie`, ...), plus classic hard-coded secret shapes (AWS access keys, Google API keys, JWTs, bearer tokens, generic `apiKey: "..."` assignments) | `PreferredPasswordLength = 8`, `AKIA...`, a JWT |
| **Dynamic Code Analysis** | Code shaped like a DOM XSS sink — assignment to `.src` / `.href` / `.innerHTML` / `.outerHTML`, or a call to `eval()` / `document.write()` / `setTimeout()` / `setInterval()` | `dummyScript.src = scriptSrc`, `eval(userInput)` |

A single literal can legitimately appear in more than one section — e.g. a root URL like
`https://www.hcaptcha.com/` is both a valid **Domain** and a valid **URL** — this mirrors
how the original extension behaves and is expected, not a bug.

### Example output

Running the module against a page produces a grouped, deduplicated report like this
(this is the exact `_findings.txt` export format):

```
Domain
======
https://www.hcaptcha.com
https://www.gstatic.com
www.gstatic.com

PATH
====
/DXR.axd?r=1_0-tZwj7
/ScriptResource.axd?d=...&t=...
/WebResource.axd?d=...&t=...
./Default.aspx

Incomplete Path
===============
://
MM/dd/yyyy
M/d/yyyy
application/json
text/javascript
text/css

URL
===
https://www.gstatic.com/images/branding/googlelogo
https://www.hcaptcha.com/
www.gstatic.com/android/

Static Path
===========
http://www.w3.org/1999/xhtml

Sensitive Information
=====================
"PreferredPasswordLength":8
Password = document
token = tokens
_preferredPasswordLength = 0

Dynamic Code Analysis
=====================
dummyScript.src = scriptSrc
xmlRequestFrame.src = callBackFrameUrl
image.src = url
```

Sections with zero findings are omitted; values within a section are deduplicated and
sorted alphabetically. This same grouping is what the HTML report renders (one table per
section) and what `ScanReport.link_findings` holds in the JSON report (as flat
`{category, value, source}` records — see below).

### Data model

Every finding is a `LinkFinding(category, value, source)`:

- **`category`** — one of the nine bucket identifiers (`domain`, `path`, `incomplete_path`,
  `url`, `static_path`, `ip`, `email`, `sensitive_information`, `dynamic_code_analysis`),
  optionally suffixed with `:<subtype>` for finer machine filtering, e.g.
  `sensitive_information:aws_access_key_id` or `dynamic_code_analysis:dangerous_call`.
  Use `asfoor.modules.link_finder.group_key(category)` to collapse a finding back down to
  its top-level bucket for display/grouping — this is what the report generator, the HTML
  template, and the CLI summary all do internally.
- **`value`** — the extracted string itself.
- **`source`** — `"homepage"`, or the absolute URL of the JS/CSS/JSON asset it was found in.

### Programmatic use

```python
from asfoor.modules.link_finder import find_links, format_findings_report

findings = await find_links("example.com", config)   # list[LinkFinding]
print(format_findings_report(findings))               # grouped plain-text export
```

`format_findings_report()` is what powers the `_findings.txt` report file and can be called
directly on any list of `LinkFinding` objects (e.g. in a notebook, a custom script, or a test).

## Project layout

```
3asfoor/
├── asfoor/
│   ├── main.py              # CLI (Typer)
│   ├── core/                # models, orchestrator, config loader
│   ├── modules/              # fingerprint, cve_lookup, port_scan, dir_scan, link_finder, report
│   ├── utils/                # http client, rate limiter, logger, banner, validators
│   └── templates/            # HTML report template
├── data/
│   ├── signatures/           # technology fingerprint rules
│   └── wordlists/            # directory + sensitive-file wordlists (active brute-force)
└── tests/                    # pytest unit tests (mocked HTTP/nmap, no live network)
```

## Running tests

```bash
pytest
```

Tests are fully mocked — no live network calls or actual scans are performed during testing.
`tests/test_link_finder.py` covers every category the passive link finder reports (domain,
path, incomplete path, url, static path, ip, email, sensitive information, dynamic code
analysis), the domain/URL dual-classification behavior, `group_key()`, and the grouped
plain-text export.

## Notes / limitations

- Technology signature database is a curated set of ~50 common technologies, not an
  exhaustive list — extend `data/signatures/technologies.json` to add more.
- CVE matching relies on a hand-maintained CPE vendor/product map (`cve_lookup.py`); add
  entries there for any new technology you add to the signature database.
- Passive link/secret discovery only parses content the target already serves (homepage
  HTML + linked JS/CSS/JSON) — it does not guess or request paths that weren't referenced.
- The "Sensitive Information" and "Dynamic Code Analysis" categories are pattern-based and
  intentionally broad (favoring recall over precision) — treat every hit as something to
  manually verify, not a confirmed vulnerability. A variable named `passwordHint` or a call
  to `eval()` on a hardcoded, non-attacker-controlled string is not itself a bug.
- This tool only detects vulnerabilities — it does not attempt exploitation.
