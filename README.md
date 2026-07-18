# 3asfoor — Web Recon & Vulnerability Scanner

![3asfoor Banner](./3asfoor-banner.jpg)

A CLI tool that, given only a domain, performs comprehensive web reconnaissance:

- **Technology fingerprinting** — powered by [wappalyzer-next](https://pypi.org/project/wappalyzer/) (1400+ technology signatures): CMS, frameworks, servers, JS libraries, and their versions. Default mode is HTTP-only (no browser needed); optional `--deep-fingerprint` adds JS-aware detection via headless Chromium.
- **Known CVEs** for detected technologies — scan-time queries hit a **local SQLite database** only (no live API calls during scans). Populate/update with `3asfoor cve-sync`.
- **Open ports & services** (via nmap, with a fallback TCP connect scan)
- **Directory & sensitive file discovery** — active wordlist brute-force with soft-404 detection (config backups, `.env`, `.git`, exposed keys, etc.)
- **Subdomain enumeration** — DNS resolution + HTTP probing
- **API endpoint & route discovery** — brute-force with soft-404 detection
- **Passive link, path & secret discovery** — a **FindSomething-style** pass over the homepage
  HTML and linked JS/CSS/JSON that classifies everything it finds into the same category
  buckets that tool reports. See [Passive Link & Secret Discovery](#passive-link-path--secret-discovery-link_finderpy)
  below for full details.

See [`LEGAL.md`](./LEGAL.md) before using this against any target.

## Install

```bash
git clone https://github.com/zeroXmoRamadan/Web-Scanner.git
cd Web-Scanner
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate          # Windows PowerShell
pip install -r requirements.txt
pip install -e .
```

**Requirements:** Python 3.11+ (tested on 3.13 and 3.14).

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

## CVE Database Sync

CVE matching during scans uses a **local SQLite database** — no live NVD API calls are made during `scan` runs. You must populate the database before CVE matching will work:

```bash
# Full historical backfill (first time — takes several hours without an API key)
3asfoor cve-sync --full

# Incremental update (run regularly — covers the last 24 days by default)
3asfoor cve-sync
```

**Recommended cron job** (daily at 3 AM):

```bash
0 3 * * * cd /path/to/3asfoor && 3asfoor cve-sync
```

Options:
- `--full` — full historical backfill (from 2002 to now). Automatically partitions queries by publication date (`pubStartDate` / `pubEndDate`) to ensure all historical records are retrieved. If interrupted, re-running `cve-sync --full` resumes from the last completed date chunk. **Known limitation:** an interrupted chunk is re-fetched from the beginning of that chunk rather than resuming mid-pagination.
- Without `--full` (Incremental) — incremental sync covering the last N days (default 24). Automatically partitions queries by modification date (`lastModStartDate` / `lastModEndDate`) to catch all new publications and recent revisions.
- `--cve-db-path <path>` — custom path for the CVE database file (default: `data/cve_cache.sqlite3`)
- `--verbose` / `--quiet` — control output verbosity

> **⚠️ Migration note for existing users:** The new two-table CVE database schema (`cve_records` + `cve_cpe_matches`) is incompatible with the old `cve_cache` table. The obsolete table is dropped automatically during database initialization, but it is recommended to delete any old database file (`data/cve_cache.sqlite3`) before running `3asfoor cve-sync --full` for a clean backfill.

The `cve-sync` command does **not** require `--i-have-permission` since it only contacts the NVD public API, not any scan target.

## Usage

```bash
3asfoor scan example.com --i-have-permission
```

You will be prompted for confirmation if `--i-have-permission` is omitted — the tool
will not run active scans (ports/directories) without explicit authorization.

On start, the tool prints an ASCII-art banner, then live phase progress as it works
(e.g. `* Running port scanning...`, `* port scanning complete`). Once the scan finishes,
the **full report is always printed to the console** — technologies with their CVEs, open
ports, discovered subdomains, directories/files, API endpoints, and every passive
link/path/secret finding grouped into its category — as readable, color-coded tables.
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

## CLI Options & Flags

Below is the complete list of CLI arguments, options, and flags available when running `3asfoor scan`:

### Target Argument

- **`DOMAIN`** (Required)  
  The target domain to scan (e.g., `example.com`).

### Authorizations & Safety

- **`--i-have-permission`** (Flag)  
  Confirm authorization to scan the target. If omitted in non-interactive environments, the tool will abort. In interactive terminals, you will be prompted for confirmation.

### Scope & Target Ports

* **`--full-ports`** (Flag)  
  Scans all 65535 TCP ports instead of the default top 1000 ports.
- **`--ports <spec>`** (Option)  
  Specifies custom TCP port ranges/specifications to scan (e.g., `--ports "80,443,8080-8090"`).

### Wordlists

* **`--wordlist-size <size>`** (Option)  
  Select which bundled SecLists wordlist to use for all modules (directories, sensitive files, subdomains, and API endpoints): `small` (default), `medium`, or `large`. The tool ships with curated wordlists organized by size under the `seclists/` directory. **Concurrency is auto-scaled** based on this setting (1× for small, 2× for medium, 4× for large).

* **`--wordlist <path>`** or **`--dir-wordlist <path>`** (Option)  
  Path to a custom wordlist file for active directory brute-forcing (one path per line). Overrides the bundled SecLists.
* **`--sensitive-wordlist <path>`** (Option)  
  Path to a custom wordlist file for sensitive file discovery (one path per line). Overrides the bundled SecLists.
* **`--subdomain-wordlist <path>`** (Option)  
  Path to a custom wordlist file for subdomain discovery (one path per line). Overrides the bundled SecLists.
* **`--api-wordlist <path>`** (Option)  
  Path to a custom wordlist file for API endpoint discovery (one path per line). Overrides the bundled SecLists.

### Performance Tuning

* **`--concurrency <num>`** (Option)  
  Override the auto-scaled concurrency for HTTP requests during active brute-forcing. By default, concurrency scales automatically with `--wordlist-size` (20 for small, 40 for medium, 80 for large).
- **`--rate-limit <seconds>`** (Option)  
  Minimum delay in seconds between individual directory-scan HTTP requests (supports decimals, e.g., `0.5`). Useful to avoid overwhelming the target server.

### Module Exclusion Flags

- **`--skip-ports`** — Skip port scanning and service detection.
- **`--skip-dirs`** — Skip active wordlist directory and sensitive file brute-forcing.
- **`--skip-subdomains`** — Skip subdomain enumeration.
- **`--skip-api`** — Skip API endpoint discovery.
- **`--skip-links`** — Skip passive FindSomething-style link, path, and secret extraction.
- **`--skip-cve`** — Skip checking technology versions against NVD CVE database.

### CVE & Fingerprinting Options

- **`--cve-db-path <path>`** (Option)  
  Path to a custom CVE database file (default: `data/cve_cache.sqlite3`).
- **`--deep-fingerprint`** (Flag)  
  Run a full JS-aware fingerprint pass using wappalyzer-next's browser engine (Playwright + Chromium). Detects JS-framework technologies (React, Vue.js, Angular, Next.js, etc.) that require runtime DOM inspection. **⚠️ Passivity caveat:** this makes a browser-based request to the target which may trigger WAF alerts or logging. Requires Chromium: `python -m playwright install chromium`.

### Reports & Export Controls

- **`--export / --no-export`** (Option)  
  Explicitly force or prevent saving report outputs (`.json`, `.html`, `_findings.txt`) to disk. If left unspecified, you will be asked interactively after a successful scan.

- **`--format <fmt>`** (Option)  
  Report output format selection: `json | html | both` (default: `both`).
- **`--output-dir <dir>`** (Option)  
  Specify custom output directory where exported report files are saved (default: `./output`).

### Debugging & Output Modes

- **`--verbose`** (Flag)  
  Enables verbose logging to standard output/logs.

- **`--quiet`** (Flag)  
  Enables silent execution mode. Suppresses startup ASCII banners, loading indicators, and interactive prompts (forces `--no-export` unless `--export` is explicitly passed).

---

## Output

The console report (always shown) covers, in order: technologies + CVE detail, open ports,
subdomains, directories/files found, API endpoints, and passive link/path/secret findings
grouped by category — with sensitive-information and dynamic-code-analysis hits highlighted,
and a warnings section at the end if anything went wrong mid-scan.

If you choose to export (`--export`, or answering "yes" to the prompt), the tool additionally
writes to `./output/` by default:

- `report_<domain>_<timestamp>.json` — full structured results (every field, machine-readable)
- `report_<domain>_<timestamp>.html` — the same report as a standalone, shareable HTML file
- `report_<domain>_<timestamp>_findings.txt` — the passive link/secret findings only,
  as a grouped plain-text export (only written when at least one finding exists) — see below
- `scan.log` — run log (always written, independent of `--export`)

## Scan Modules

### Technology Fingerprinting (`fingerprint.py`)

Powered by [wappalyzer-next](https://pypi.org/project/wappalyzer/) — a modern Wappalyzer
engine with **1400+ technology definitions**. Detects CMS platforms, web frameworks,
JavaScript libraries, analytics tools, CDNs, web servers, and more.

Two scan modes are available:

| Mode | Flag | How it works | Browser needed? |
|---|---|---|---|
| **Fast** (default) | _(none)_ | HTTP-only analysis: headers, HTML, meta tags, scripts, DNS, robots.txt | No |
| **Full** | `--deep-fingerprint` | Browser-based JS-aware analysis via Playwright + Chromium | Yes |

The fast mode is sufficient for most scans. The full mode additionally detects JS-framework
technologies that require runtime DOM inspection (React, Vue.js, Angular rendered apps,
Next.js, etc.).

#### Enabling `--deep-fingerprint`

Install Chromium for Playwright:

```bash
python -m playwright install chromium
```

> **⚠️ Passivity caveat:** The `--deep-fingerprint` mode makes a **browser-based request**
> to the target which executes JavaScript. This may trigger WAF alerts, be logged separately,
> or cause side effects not caused by the default HTTP-only scan.

### Subdomain Enumeration (`subdomain_scan.py`)

DNS-resolves candidate subdomains from the bundled SecLists wordlists, then HTTP-probes each
resolved host to capture status codes and page titles. Results include the subdomain, resolved IP,
HTTP status, and `<title>` tag. Concurrency auto-scales with `--wordlist-size`.

### API Endpoint Discovery (`api_scan.py`)

Brute-forces common API paths (`/api/v1/users`, `/graphql`, `/health`, etc.) from the bundled
SecLists, with built-in soft-404 detection to filter false positives. Reports status code,
content type, response size, and a human-readable note. Concurrency auto-scales with `--wordlist-size`.

### Web Crawler & sitemap builder (`crawler.py`)

A dynamic web crawling and API discovery module. It traverses same-origin links to index sitemap paths and logs all page layouts.
* **JS-Aware Crawling**: Uses Playwright's headless browser by default to render client-side scripts, capture dynamic link generation, and catalog form inputs (strictly defensively, without submissions).
* **Page-Level HTTPX Fallback**: If Playwright fails to load a URL (e.g. due to connection closed/reset by a WAF or anti-bot system), the crawler automatically falls back to fetching the page statically via HTTPX and parsing it with BeautifulSoup to ensure maximum coverage.
* **API Interception**: Intercepts fetch/XHR requests at runtime in the browser context and scans script sources (`.js` files) to extract hidden endpoints.

### Directory & Sensitive File Discovery (`dir_scan.py`)

Active wordlist brute-force against the target, scanning for both common directories and
sensitive files (`.env`, `.git/config`, `backup.zip`, exposed keys, etc.). Uses soft-404
detection to filter false positives. Sensitive findings are highlighted in the report.
Concurrency auto-scales with `--wordlist-size`.

### Passive Link, Path & Secret Discovery (`link_finder.py`)

This module is modeled on the **FindSomething** browser extension: rather than guessing
paths by brute-forcing a wordlist against the server (that's what `dir_scan.py` does), it
parses content the target **already serves** — the homepage HTML plus every linked
`<script src>` / `<link href>` asset that looks textual (JS, CSS, JSON, source maps) — and
regex-classifies everything it finds into the same buckets that tool reports. Nothing here
is requested that a normal browser wouldn't already fetch when loading the page; it is
**100% passive**.

#### Categories

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

#### Example output

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

#### Data model

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

#### Programmatic use

```python
from asfoor.modules.link_finder import find_links, format_findings_report

findings = await find_links("example.com", config)   # list[LinkFinding]
print(format_findings_report(findings))               # grouped plain-text export
```

`format_findings_report()` is what powers the `_findings.txt` report file and can be called
directly on any list of `LinkFinding` objects (e.g. in a notebook, a custom script, or a test).

## Wordlists

The tool uses curated wordlists from the bundled `seclists/` directory, organized by scan type and size:

```
seclists/
├── directory_discovery/       # paths for active dir brute-force
│   ├── small.txt
│   ├── medium.txt
│   └── large.txt
├── subdomain_discovery/       # candidate subdomains
│   ├── small.txt
│   ├── medium.txt
│   └── large.txt
├── api_endpoints_discovery/   # common API routes
│   └── small.txt
└── sensitive_files_discovery/ # .env, .git, backups, etc.
    ├── small.txt
    ├── medium.txt
    └── large.txt
```

**Default is `small`** for all modules — use `--wordlist-size medium` or `--wordlist-size large` for broader coverage. Concurrency automatically scales with `--wordlist-size` based on a base of 100:

| Size | Concurrency Multiplier | Example (base 100) |
|---|---|---|
| `small` | 1× | 100 threads |
| `medium` | 2× | 200 threads |
| `large` | 4× | 400 threads |

You can override any wordlist with `--wordlist <path>` (or `--dir-wordlist <path>`), `--sensitive-wordlist <path>`, `--subdomain-wordlist <path>`, and `--api-wordlist <path>` for custom path files.

## Project Layout

```
3asfoor/
├── asfoor/
│   ├── main.py               # CLI (Typer)
│   ├── core/                  # models, orchestrator, config loader
│   ├── modules/               # fingerprint, cve_lookup, port_scan, dir_scan,
│   │                          #   subdomain_scan, api_scan, link_finder, report
│   ├── utils/                 # http client, rate limiter, logger, banner,
│   │                          #   validators, wordlist utils
│   └── templates/             # HTML report template
├── config/                    # YAML config (defaults.yaml)
├── data/                      # runtime cache (cve_cache.sqlite3)
├── seclists/                  # bundled wordlists (dirs, subdomains, API, sensitive files)
└── output/                    # scan reports (JSON, HTML, findings.txt, scan.log)
```

## Dependencies

| Package | Purpose |
|---|---|
| `httpx` | Async HTTP client |
| `typer` + `rich` | CLI framework + colored tables |
| `wappalyzer` | Technology fingerprinting engine — wappalyzer-next (1400+ signatures) |
| `pyyaml` | Config file parsing |
| `jinja2` | HTML report templating |
| `python-nmap` | nmap integration for port scanning |

## Notes / Limitations

- Technology detection is powered by wappalyzer-next's 1400+ signature database — no manual
  signature maintenance needed.
- CVE matching relies on a hand-maintained CPE vendor/product map (`cve_lookup.py`); add
  entries there for any new technology not covered.
- Passive link/secret discovery only parses content the target already serves (homepage
  HTML + linked JS/CSS/JSON) — it does not guess or request paths that weren't referenced.
- The "Sensitive Information" and "Dynamic Code Analysis" categories are pattern-based and
  intentionally broad (favoring recall over precision) — treat every hit as something to
  manually verify, not a confirmed vulnerability. A variable named `passwordHint` or a call
  to `eval()` on a hardcoded, non-attacker-controlled string is not itself a bug.
- This tool only detects vulnerabilities — it does not attempt exploitation.
