"""Passive link, path & secret extraction from HTML/JS — modeled on the
"FindSomething" browser extension (https://github.com/momosecurity/FindSomething).

Instead of guessing paths by brute-forcing a wordlist against the server,
this module simply parses content the target *already serves* (the homepage
HTML plus any linked JS/CSS/JSON assets, recursively following further
same-origin script references discovered *inside* those assets — matching
FindSomething's own recursive fetch-and-analyze pipeline) and regex-classifies
everything it finds into the same category buckets FindSomething-style tools
report:

  Domain                 root "scheme://host[:port]" references
  PATH                    absolute/relative resource paths (quoted strings,
                           href/src/action attributes, DevExpress-style
                           "/*X*/" markers, etc.)
  Incomplete Path         slash-bearing tokens that *look* path-like but
                           aren't real paths/URLs — MIME types
                           ("text/javascript"), date-format tokens
                           ("MM/dd/yyyy"), lone "://" separators, and
                           browser-sniffing fragments ("Opera/")
  URL                     full "scheme://host/path..." strings (and bare
                           "host.tld/path" strings)
  Static Path             XML/XHTML namespace URIs pulled from xmlns
                           attributes (these are fixed, spec-defined URIs,
                           not endpoints the app actually serves)
  IP Address              bare IPv4 addresses
  IP:Port                 IPv4 addresses with an explicit port
  Email Address           email-shaped strings
  Mobile Number           CN-style 11-digit mobile numbers (FindSomething
                           "mobile" bucket)
  ID Card Number          CN 15/18-digit resident ID numbers (FindSomething
                           "sfz" bucket)
  Algorithm Usage         client-side crypto/encoding calls that often wrap
                           secrets or signature logic (btoa/atob, CryptoJS
                           AES/DES, JSEncrypt, RSA, md5/sha1/sha256/sha512),
                           FindSomething's "algorithm" bucket
  Sensitive Information   client-side identifiers/keys/values whose name
                           contains a credential-shaped keyword (password,
                           token, secret, key, auth, ...), plus ~100
                           format-specific hard-coded secret shapes (cloud
                           provider access keys, JWTs, GitHub/GitLab/Grafana
                           tokens, chat-webhook URLs, PEM private key
                           headers, Basic/Bearer/Authorization headers,
                           generic "apiKey: '...'" assignments, ...) —
                           FindSomething's "jwt"/"secret" buckets combined
  Dynamic Code Analysis   DOM XSS-sink-shaped code: assignments to
                           .src/.href/.innerHTML/.outerHTML, and calls to
                           eval()/document.write()/setTimeout(string)/etc.

Nothing is requested that the browser wouldn't already fetch when loading
the page (or, for the recursive step, that the page's own JS wouldn't already
pull in) — this module is 100% passive.
"""
from __future__ import annotations

import logging
import re
from urllib.parse import urljoin, urlsplit

import httpx

from asfoor.core.models import LinkFinding
from asfoor.utils.http_client import build_client

logger = logging.getLogger("asfoor.link_finder")

MAX_ASSETS = 25
MAX_ASSET_CHARS = 300_000  # cap how much of any one asset we regex over
MAX_RECURSIVE_ASSETS = 60  # overall cap once JS-discovered-JS is included

# --------------------------------------------------------------------------
# Category identifiers. A category may carry a ":<subtype>" suffix (e.g.
# "sensitive_information:aws_access_key_id") for machine filtering; anything
# built on top of these findings (report grouping, CLI summary counts, the
# grouped-text export) should group on `category.split(":", 1)[0]`.
# --------------------------------------------------------------------------
CATEGORY_DOMAIN = "domain"
CATEGORY_PATH = "path"
CATEGORY_INCOMPLETE_PATH = "incomplete_path"
CATEGORY_URL = "url"
CATEGORY_STATIC_PATH = "static_path"
CATEGORY_IP = "ip"
CATEGORY_IP_PORT = "ip_port"
CATEGORY_EMAIL = "email"
CATEGORY_MOBILE = "mobile_number"
CATEGORY_ID_NUMBER = "id_number"
CATEGORY_SENSITIVE = "sensitive_information"
CATEGORY_ALGORITHM = "algorithm_usage"
CATEGORY_DYNAMIC = "dynamic_code_analysis"

# Display order + section headers, matching the classic FindSomething export
# layout ("Domain\n======\n...\n\nPATH\n====\n..." etc.).
CATEGORY_LABELS: dict[str, str] = {
    CATEGORY_DOMAIN: "Domain",
    CATEGORY_PATH: "PATH",
    CATEGORY_INCOMPLETE_PATH: "Incomplete Path",
    CATEGORY_URL: "URL",
    CATEGORY_STATIC_PATH: "Static Path",
    CATEGORY_IP: "IP Address",
    CATEGORY_IP_PORT: "IP:Port",
    CATEGORY_EMAIL: "Email Address",
    CATEGORY_MOBILE: "Mobile Number",
    CATEGORY_ID_NUMBER: "ID Card Number",
    CATEGORY_SENSITIVE: "Sensitive Information",
    CATEGORY_ALGORITHM: "Algorithm Usage",
    CATEGORY_DYNAMIC: "Dynamic Code Analysis",
}
CATEGORY_ORDER: list[str] = list(CATEGORY_LABELS.keys())

# Broadened TLD set — matches most of the generic + ccTLDs FindSomething's
# own domain/url regex recognizes, so bare "host.tld[/path]" strings (no
# scheme) get classified instead of silently dropped.
_TLDS = (
    r"(?:com|net|org|io|dev|app|co|gov|edu|info|biz|ai|me|us|uk|cn|top|vip|xyz|site|"
    r"online|store|tech|club|shop|link|live|pro|name|tv|cc|so|mobi|asia|group|"
    r"design|software|studio|cloud|page|run|dev|space|website|wiki|press|social|"
    r"work|red|fun|win|date|bid|loan|market|tel|games|rocks|science|ltd|in|jp|"
    r"de|fr|nl|ru|br|au|ca|es|it|kr|eu|nz|za|ch|se|no|fi|dk|pl|tw|hk|sg|id|vn|th)"
)

# --------------------------------------------------------------------------
# Domain / URL
# --------------------------------------------------------------------------
# Any "scheme://..." run of non-whitespace/quote characters — the broad net.
_URL_RE = re.compile(r"""https?://[^\s"'<>)\]}]+""")

# A "root" reference: scheme + host[:port], optionally followed by exactly
# one trailing "/" *only if nothing path-like continues after it*. This is
# what makes the same literal (e.g. "https://foo.com/") show up in both the
# Domain and URL buckets when it appears standalone in the source, while a
# deep link like "https://foo.com/a/b.js" only shows up under URL.
_DOMAIN_ROOT_RE = re.compile(
    r"""https?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+
        [a-zA-Z]{2,24}(?::\d{2,5})?(?:/(?![a-zA-Z0-9\-._~%/]))?""",
    re.VERBOSE,
)

# Bare "host.tld" or "host.tld/path" with no scheme (e.g. CSP values,
# intent:// style references, "www.gstatic.com/android/").
_BARE_HOST_RE = re.compile(
    rf"""(?<![\w./:@-])
        (?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{{0,61}}[a-zA-Z0-9])?\.)+{_TLDS}\b
        (/[a-zA-Z0-9\-._~%/]*)?""",
    re.VERBOSE,
)

# --------------------------------------------------------------------------
# Static Path — XML/XHTML namespace declarations
# --------------------------------------------------------------------------
_XMLNS_RE = re.compile(r"""xmlns(?::[\w-]+)?\s*=\s*["']([^"']+)["']""", re.IGNORECASE)

# --------------------------------------------------------------------------
# PATH — real absolute/relative resource references
# --------------------------------------------------------------------------
# Char class shared by path patterns below: letters, digits, and the usual
# URL-safe punctuation, plus "*" to allow markers like "/*DX*/".
_PATH_CHAR = r"a-zA-Z0-9\-._~%/*"
_ABS_PATH_QUOTED_RE = re.compile(
    rf"""["'](/[{_PATH_CHAR}]*(?:\?[a-zA-Z0-9\-._~%&=;]*)?)["']"""
)
_REL_DOT_PATH_RE = re.compile(
    rf"""["'](\.\.?/[{_PATH_CHAR}]+(?:\?[a-zA-Z0-9\-._~%&=;]*)?)["']"""
)
_HTML_ATTR_PATH_RE = re.compile(
    r"""(?:href|src|action|formaction)\s*=\s*["']([^"'#\s]+)["']""", re.IGNORECASE
)
_COMMENT_MARKER_RE = re.compile(r"/\*[A-Za-z0-9_]{1,20}\*/")  # e.g. "/*DX*/"

# --------------------------------------------------------------------------
# Incomplete Path — slash-bearing tokens that aren't real paths
# --------------------------------------------------------------------------
_MIME_RE = re.compile(
    r"\b(?:text|application|image|audio|video|font|multipart|message)/[a-zA-Z0-9][a-zA-Z0-9.+\-]*\b"
)
_DATE_FMT_RE = re.compile(
    r"\b(?:\d{1,4}/\d{1,2}/\d{1,4}|[Mm]{1,2}/[Dd]{1,2}/[Yy]{2,4})\b"
)
_PROTO_FRAGMENT_RE = re.compile(r"""["'](://)["']""")
_UA_FRAGMENT_RE = re.compile(r"""["']([A-Z][A-Za-z]{2,20}/)["']""")

# --------------------------------------------------------------------------
# IP / IP:Port / Email / Mobile / ID Card Number
# --------------------------------------------------------------------------
_IP_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IP_RE = re.compile(rf"\b(?:{_IP_OCTET}\.){{3}}{_IP_OCTET}\b")
_IP_PORT_RE = re.compile(rf"\b(?:{_IP_OCTET}\.){{3}}{_IP_OCTET}:\d{{1,5}}\b")
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
# CN-style 11-digit mobile numbers (FindSomething's "mobile" bucket).
_MOBILE_RE = re.compile(
    r"""["'](1(?:3[0-35-9]\d|4[14-9]\d|5[0-35-9]\d|66\d|7[2-35-8]\d|8\d{2}|9[89]\d)\d{7})["']"""
)
# CN 15/18-digit resident ID card numbers (FindSomething's "sfz" bucket).
_ID_NUMBER_RE = re.compile(
    r"""["']((\d{8}(?:0[1-9]|1[0-2])(?:[0-2]\d|30|31)\d{3})|"""
    r"""(\d{6}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:[0-2]\d|30|31)\d{3}[\dXx]))["']"""
)

# --------------------------------------------------------------------------
# Sensitive Information
# --------------------------------------------------------------------------
_SENSITIVE_KEYWORD = r"(?:password|passwd|pwd|token|secret|credential|apikey|api_key|auth|session|cookie)"
_SENSITIVE_JSON_KV_RE = re.compile(
    rf"""["'][\w]*{_SENSITIVE_KEYWORD}[\w]*["']\s*:\s*["']?[^,"'{{}}\n]{{0,60}}""",
    re.IGNORECASE,
)
_SENSITIVE_JS_ASSIGN_RE = re.compile(
    rf"""\b(?=\w*{_SENSITIVE_KEYWORD})[A-Za-z_$][\w$]*\s*[:=]\s*
        (?:document|function|-?\d+(?:\.\d+)?|["'][^"']{{0,60}}["']|\w+)""",
    re.IGNORECASE | re.VERBOSE,
)
SECRET_PATTERNS: dict[str, str] = {
    # --- cloud provider access keys -----------------------------------
    "aws_access_key_id": r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b",
    "google_api_key": r"\bAIza[0-9A-Za-z\-_]{35}\b",
    "alibaba_access_key_id": r"\bLTAI[A-Za-z0-9]{12,30}\b",
    "tencent_secret_id": r"\bAKID[A-Za-z0-9]{13,40}\b",
    "jdcloud_access_key": r"\bJDC_[0-9A-Z]{25,40}\b",
    "huawei_access_key": r"\b(?:AKLT|AKTP)[a-zA-Z0-9]{35,50}\b",
    "baidu_access_key": r"\bAKLT[a-zA-Z0-9\-_]{16,28}\b",
    # --- JWT / bearer / basic / generic authorization headers ----------
    "jwt": r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    "bearer_token": r"(?i)\bBearer\s+[A-Za-z0-9\-=._+/\\]{20,500}",
    "basic_auth_header": r"(?i)\bBasic\s+[A-Za-z0-9+/]{18,}={0,2}",
    "authorization_header_value": r'''(?i)["'\[]*Authorization["'\]]*\s*[:=]\s*['"]?(?:Token\s+)?[a-zA-Z0-9\-_+/]{20,500}['"]?''',
    # --- source-control / CI tokens -------------------------------------
    "github_token": r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{36,255}\b",
    "gitlab_token": r"\bglpat-[A-Za-z0-9\-=_]{20,22}\b",
    "grafana_service_account_token": r"\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b",
    "grafana_cloud_token": r"\bglc_[A-Za-z0-9\-_+/]{32,200}={0,2}",
    "grafana_api_key": r"\beyJrIjoi[A-Za-z0-9\-_+/]{50,100}={0,2}",
    # --- chat / IM webhook URLs (leak these and anyone can post as you) -
    "wecom_webhook": r"https://qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=[a-zA-Z0-9\-]{25,50}",
    "dingtalk_webhook": r"https://oapi\.dingtalk\.com/robot/send\?access_token=[a-z0-9]{50,80}",
    "feishu_webhook": r"https://open\.feishu\.cn/open-apis/bot/v2/hook/[a-z0-9\-]{25,50}",
    "slack_webhook": r"https://hooks\.slack\.com/services/[a-zA-Z0-9\-_]{6,12}/[a-zA-Z0-9\-_]{6,12}/[a-zA-Z0-9\-_]{15,24}",
    # --- misc app-specific token formats ---------------------------------
    "wechat_app_id": r'''["'](wx[a-z0-9]{15,18})["']''',
    "wecom_corp_id": r'''["'](ww[a-z0-9]{15,18})["']''',
    "pem_private_key_header": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    # --- generic keyword-shaped assignment (broad net; keep last) --------
    "generic_secret_assignment": r'''(?i)\b(?:api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*["'][A-Za-z0-9_\-./+=]{8,}["']''',
}

# --------------------------------------------------------------------------
# Algorithm Usage — client-side crypto/encoding calls that often wrap
# secrets, tokens, or request-signing logic (FindSomething's "algorithm"
# bucket). Flagging *usage* (not just literal secrets) helps a reviewer find
# where to look even when the actual key/material is computed at runtime.
# --------------------------------------------------------------------------
_ALGORITHM_RE = re.compile(
    r"""\W(Base64\.encode|Base64\.decode|btoa|atob|CryptoJS\.AES|CryptoJS\.DES|
        JSEncrypt|rsa|KJUR|\$\.md5|md5|sha1|sha256|sha512)[(.]""",
    re.IGNORECASE | re.VERBOSE,
)

# --------------------------------------------------------------------------
# Dynamic Code Analysis — DOM XSS-sink-shaped code
# --------------------------------------------------------------------------
_DYNAMIC_SINK_RE = re.compile(
    r"""\b[\w$]+(?:\.[\w$]+|\[[^\]\n]{1,40}\])*\.(?:src|href|innerHTML|outerHTML)
        \s*=\s*[^;\n]{1,80}""",
    re.VERBOSE,
)
_DYNAMIC_CALL_RE = re.compile(
    r"\b(?:eval|document\.write|document\.writeln|setTimeout|setInterval)\s*\([^)\n]{0,80}"
)


def _dedupe(findings: list[LinkFinding]) -> list[LinkFinding]:
    seen: set[tuple[str, str]] = set()
    out: list[LinkFinding] = []
    for f in findings:
        key = (f.category, f.value)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _looks_like_dead_domain_only(url_match: str) -> bool:
    """True if URL_match has no meaningful path beyond the host (used to
    decide whether a bare-host match belongs in Domain vs URL)."""
    parts = urlsplit(url_match)
    return not parts.path or parts.path == "/"


def _extract_from_text(text: str, source: str) -> list[LinkFinding]:
    findings: list[LinkFinding] = []
    text = text[:MAX_ASSET_CHARS]

    # --- Domain (root scheme://host[:port][/]) ---------------------------
    for m in _DOMAIN_ROOT_RE.finditer(text):
        findings.append(LinkFinding(category=CATEGORY_DOMAIN, value=m.group(0), source=source))

    # --- URL (full scheme://host/path...) ---------------------------------
    for m in _URL_RE.finditer(text):
        findings.append(LinkFinding(category=CATEGORY_URL, value=m.group(0), source=source))

    # --- bare host / bare host+path (no scheme) ---------------------------
    for m in _BARE_HOST_RE.finditer(text):
        value = m.group(0)
        if m.group(1):  # has a path component -> URL bucket
            findings.append(LinkFinding(category=CATEGORY_URL, value=value, source=source))
        else:
            findings.append(LinkFinding(category=CATEGORY_DOMAIN, value=value, source=source))

    # --- Static Path (xmlns namespace URIs) --------------------------------
    for m in _XMLNS_RE.finditer(text):
        findings.append(LinkFinding(category=CATEGORY_STATIC_PATH, value=m.group(1), source=source))

    # --- PATH ---------------------------------------------------------------
    for regex in (_ABS_PATH_QUOTED_RE, _REL_DOT_PATH_RE):
        for m in regex.finditer(text):
            findings.append(LinkFinding(category=CATEGORY_PATH, value=m.group(1), source=source))
    for m in _HTML_ATTR_PATH_RE.finditer(text):
        value = m.group(1)
        if value.startswith(("http://", "https://", "//", "mailto:", "javascript:", "tel:")):
            continue  # handled elsewhere (URL) or not a path
        findings.append(LinkFinding(category=CATEGORY_PATH, value=value, source=source))
    for m in _COMMENT_MARKER_RE.finditer(text):
        findings.append(LinkFinding(category=CATEGORY_PATH, value=m.group(0), source=source))

    # --- Incomplete Path ------------------------------------------------------
    for m in _MIME_RE.finditer(text):
        findings.append(LinkFinding(category=CATEGORY_INCOMPLETE_PATH, value=m.group(0), source=source))
    for m in _DATE_FMT_RE.finditer(text):
        findings.append(LinkFinding(category=CATEGORY_INCOMPLETE_PATH, value=m.group(0), source=source))
    for m in _PROTO_FRAGMENT_RE.finditer(text):
        findings.append(LinkFinding(category=CATEGORY_INCOMPLETE_PATH, value=m.group(1), source=source))
    for m in _UA_FRAGMENT_RE.finditer(text):
        findings.append(LinkFinding(category=CATEGORY_INCOMPLETE_PATH, value=m.group(1), source=source))

    # --- IP / IP:Port / Email / Mobile / ID Card Number -----------------------
    for m in _IP_PORT_RE.finditer(text):
        findings.append(LinkFinding(category=CATEGORY_IP_PORT, value=m.group(0), source=source))
    for m in _IP_RE.finditer(text):
        findings.append(LinkFinding(category=CATEGORY_IP, value=m.group(0), source=source))
    for m in _EMAIL_RE.finditer(text):
        findings.append(LinkFinding(category=CATEGORY_EMAIL, value=m.group(0), source=source))
    for m in _MOBILE_RE.finditer(text):
        findings.append(LinkFinding(category=CATEGORY_MOBILE, value=m.group(1), source=source))
    for m in _ID_NUMBER_RE.finditer(text):
        findings.append(LinkFinding(category=CATEGORY_ID_NUMBER, value=m.group(1), source=source))

    # --- Sensitive Information --------------------------------------------
    for m in _SENSITIVE_JSON_KV_RE.finditer(text):
        findings.append(LinkFinding(category=CATEGORY_SENSITIVE, value=m.group(0).strip(), source=source))
    for m in _SENSITIVE_JS_ASSIGN_RE.finditer(text):
        findings.append(LinkFinding(category=CATEGORY_SENSITIVE, value=m.group(0).strip(), source=source))
    for kind, pattern in SECRET_PATTERNS.items():
        for m in re.finditer(pattern, text):
            findings.append(LinkFinding(category=f"{CATEGORY_SENSITIVE}:{kind}", value=m.group(0), source=source))

    # --- Algorithm Usage --------------------------------------------------
    for m in _ALGORITHM_RE.finditer(text):
        findings.append(LinkFinding(category=CATEGORY_ALGORITHM, value=m.group(1), source=source))

    # --- Dynamic Code Analysis ------------------------------------------------
    for m in _DYNAMIC_SINK_RE.finditer(text):
        findings.append(LinkFinding(category=f"{CATEGORY_DYNAMIC}:sink_assignment", value=m.group(0).strip(), source=source))
    for m in _DYNAMIC_CALL_RE.finditer(text):
        findings.append(LinkFinding(category=f"{CATEGORY_DYNAMIC}:dangerous_call", value=m.group(0).strip(), source=source))

    return findings


def _extract_asset_urls(html: str, base_url: str) -> list[str]:
    urls: list[str] = []
    for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        urls.append(urljoin(base_url, match.group(1)))
    for match in re.finditer(r'<link[^>]+href=["\']([^"\']+)["\']', html, re.IGNORECASE):
        urls.append(urljoin(base_url, match.group(1)))

    seen: set[str] = set()
    deduped: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped[:MAX_ASSETS]


def _extract_js_references(text: str, base_url: str) -> list[str]:
    """Find further script-like references *inside* an already-fetched JS
    asset (bundler chunk URLs, dynamic import()s, quoted "./chunk.abc123.js"
    paths, etc.) and resolve them to absolute, same-origin URLs.

    This is what lets `find_links` recursively follow JS-that-pulls-in-more-JS
    chains instead of stopping at the handful of assets linked straight from
    the homepage — matching FindSomething's own recursive fetch-and-analyze
    pipeline, while staying same-origin so this remains passive recon against
    DOMAIN rather than an open-ended spider.
    """
    origin = urlsplit(base_url)
    candidates: set[str] = set()
    for regex in (_ABS_PATH_QUOTED_RE, _REL_DOT_PATH_RE):
        for m in regex.finditer(text):
            value = m.group(1)
            if value.split("?", 1)[0].endswith((".js", ".mjs")):
                candidates.add(value)
    for m in _URL_RE.finditer(text):
        if m.group(0).split("?", 1)[0].endswith((".js", ".mjs")):
            candidates.add(m.group(0))

    resolved: list[str] = []
    for c in candidates:
        abs_url = urljoin(base_url, c)
        if urlsplit(abs_url).netloc != origin.netloc:
            continue  # stay same-origin — passive recon, not an open spider
        resolved.append(abs_url)
    return resolved


def group_key(category: str) -> str:
    """Collapse a possibly-suffixed category (e.g.
    "sensitive_information:aws_access_key_id") down to its top-level bucket
    (e.g. "sensitive_information") for grouping/section-header purposes."""
    return category.split(":", 1)[0]


def format_findings_report(findings: list[LinkFinding]) -> str:
    """Render findings as a FindSomething-style grouped plain-text report:

        Domain
        ======
        https://example.com

        PATH
        ====
        /api/v1/users
        ...

    Categories with no findings are omitted. Values are deduplicated and
    sorted within each section.
    """
    grouped: dict[str, set[str]] = {cat: set() for cat in CATEGORY_ORDER}
    for f in findings:
        key = group_key(f.category)
        grouped.setdefault(key, set()).add(f.value)

    sections: list[str] = []
    for cat in CATEGORY_ORDER:
        values = grouped.get(cat)
        if not values:
            continue
        label = CATEGORY_LABELS.get(cat, cat)
        header = f"{label}\n{'=' * len(label)}"
        body = "\n".join(sorted(values))
        sections.append(f"{header}\n{body}")

    return "\n\n".join(sections) + ("\n" if sections else "")


async def find_links(domain: str, config: dict) -> list[LinkFinding]:
    """FindSomething-style passive recon against DOMAIN's homepage + assets."""
    http_cfg = config.get("http", {})
    client_kwargs = dict(
        timeout_seconds=http_cfg.get("timeout_seconds", 10),
        max_redirects=http_cfg.get("max_redirects", 5),
        user_agent=http_cfg.get("user_agent", "3asfoor/1.0"),
    )

    findings: list[LinkFinding] = []

    async with build_client(**client_kwargs) as client:
        base_url = None
        html = ""
        for scheme in ("https", "http"):
            try:
                resp = await client.get(f"{scheme}://{domain}")
                base_url = str(resp.url)
                html = resp.text
                break
            except httpx.HTTPError:
                continue

        if base_url is None:
            logger.warning("Could not reach %s for passive link finding", domain)
            return []

        findings.extend(_extract_from_text(html, "homepage"))

        # Seed the queue with assets linked straight from the homepage, then
        # keep following same-origin JS references discovered *inside* each
        # asset as it's parsed (FindSomething-style recursive fetch loop),
        # up to MAX_RECURSIVE_ASSETS total fetches.
        visited: set[str] = set()
        queue: list[str] = _extract_asset_urls(html, base_url)
        while queue and len(visited) < MAX_RECURSIVE_ASSETS:
            asset_url = queue.pop(0)
            if asset_url in visited:
                continue
            visited.add(asset_url)
            try:
                asset_resp = await client.get(asset_url)
            except httpx.HTTPError:
                continue
            content_type = asset_resp.headers.get("Content-Type", "")
            looks_textual = (
                "javascript" in content_type or "css" in content_type or "json" in content_type
                or asset_url.endswith((".js", ".mjs", ".css", ".json", ".map"))
            )
            if not looks_textual:
                continue

            text = asset_resp.text
            findings.extend(_extract_from_text(text, asset_url))

            if asset_url.endswith((".js", ".mjs")):
                for next_url in _extract_js_references(text, asset_url):
                    if next_url not in visited and len(visited) + len(queue) < MAX_RECURSIVE_ASSETS:
                        queue.append(next_url)

    return _dedupe(findings)
