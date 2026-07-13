"""Web Crawler module for dynamic sitemap building, form cataloging, and API discovery.
Supports Playwright headless browser rendering with a graceful HTTPX fallback.
Strictly defensive: catalogs form designs and inputs without submitting them.
"""
from __future__ import annotations

import asyncio
import logging
import random
import re
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

import httpx
from bs4 import BeautifulSoup

from asfoor.core.models import ApiEndpointResult, FormDetails, CrawlResponse
from asfoor.utils.http_client import build_client

logger = logging.getLogger("asfoor.crawler")

# A pool of realistic User-Agent strings to rotate per request/session
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
]


class RobotsTxtParser:
    """Parses and respects robots.txt rules and crawl delay."""

    def __init__(self, base_url: str, user_agent: str, proxy: str | None = None):
        self.base_url = base_url
        self.user_agent = user_agent
        self.proxy = proxy
        self.rp = RobotFileParser()
        self.crawl_delay = 0.1
        self.is_loaded = False

    async def load(self) -> None:
        robots_url = urljoin(self.base_url, "/robots.txt")
        try:
            # Fetch robots.txt using httpx
            limits = httpx.Limits(max_connections=5, max_keepalive_connections=2)
            async with httpx.AsyncClient(
                headers={"User-Agent": self.user_agent},
                proxy=self.proxy,
                verify=False,
                limits=limits,
                timeout=5.0
            ) as client:
                resp = await client.get(robots_url)
                if resp.status_code == 200:
                    self.rp.parse(resp.text.splitlines())
                    delay = self.rp.crawl_delay(self.user_agent)
                    if delay is not None:
                        self.crawl_delay = float(delay)
                    self.is_loaded = True
                    logger.debug("Loaded robots.txt successfully from %s", robots_url)
        except Exception as e:
            logger.debug("Failed to load robots.txt from %s: %s", robots_url, e)

    def can_fetch(self, url: str) -> bool:
        if not self.is_loaded:
            return True
        return self.rp.can_fetch(self.user_agent, url)


def _extract_forms(html: str, page_url: str) -> list[FormDetails]:
    """Parse forms from the HTML content without submitting them."""
    soup = BeautifulSoup(html, "html.parser")
    forms: list[FormDetails] = []
    
    for f in soup.find_all("form"):
        action = f.get("action", "")
        # Resolve absolute action URL
        resolved_action = urljoin(page_url, action) if action else page_url
        method = f.get("method", "get").strip().lower()
        
        inputs = []
        for inp in f.find_all(["input", "textarea", "select"]):
            inp_name = inp.get("name")
            if not inp_name:
                continue
            inp_type = inp.get("type", "text").strip().lower() if inp.name == "input" else inp.name
            inp_val = inp.get("value", "")
            if inp.name == "textarea" and not inp_val:
                inp_val = inp.string or inp.text or ""
            
            inputs.append({
                "name": inp_name,
                "type": inp_type,
                "value": inp_val
            })
            
        forms.append(FormDetails(
            url=page_url,
            action=resolved_action,
            method=method,
            inputs=inputs
        ))
        
    return forms


def _extract_api_endpoints_from_js(js_content: str) -> list[str]:
    """Parse JavaScript code to identify API fetch/XHR endpoints and Swagger files."""
    endpoints = []
    
    # fetch("/api/v1/resource?query")
    fetch_matches = re.finditer(r'''\bfetch\s*\(\s*["']([^"'\r\n]+)["']''', js_content)
    for m in fetch_matches:
        endpoints.append(m.group(1))
        
    # axios.get("/api/v1/resource") or axios.post(...)
    axios_matches = re.finditer(r'''\baxios(?:\.get|\.post|\.put|\.delete)?\s*\(\s*["']([^"'\r\n]+)["']''', js_content)
    for m in axios_matches:
        endpoints.append(m.group(1))

    # XHR open("GET", "/api/v1/resource")
    xhr_matches = re.finditer(r'''\b\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["']([^"'\r\n]+)["']''', js_content)
    for m in xhr_matches:
        endpoints.append(m.group(1))

    # Normalize and filter
    clean_endpoints = []
    for ep in endpoints:
        # Strip query parameters and hashes
        ep_base = ep.split("?")[0].split("#")[0].strip()
        ep_clean = ep_base.lstrip("/")
        if not ep_clean:
            continue
        # Only keep path-like references (avoid static assets or random words)
        if any(ep_clean.startswith(x) for x in ("api/", "v1/", "v2/", "graphql", "swagger", "openapi")):
            clean_endpoints.append(ep_clean)
        elif "/" in ep_clean and not ep_clean.startswith(("http://", "https://", "mailto:", "javascript:")):
            clean_endpoints.append(ep_clean)
            
    return list(set(clean_endpoints))


async def _run_playwright_crawler(
    base_url: str,
    domain: str,
    ignore_robots: bool,
    max_pages: int,
    politeness_delay: float,
    proxies_list: list[str],
    robots_parser: RobotsTxtParser,
) -> tuple[list[str], list[FormDetails], list[ApiEndpointResult], list[str], list[CrawlResponse]]:
    """Crawls targets dynamically using Playwright headless browser."""
    from playwright.async_api import async_playwright
    import time

    crawled_urls: set[str] = set()
    forms: list[FormDetails] = []
    api_endpoints: set[str] = set()
    external_domains: set[str] = set()
    crawl_responses: list[CrawlResponse] = []
    
    queue = [base_url]
    
    async with async_playwright() as p:
        # Launch browser
        browser = await p.chromium.launch(headless=True)
        
        while queue and len(crawled_urls) < max_pages:
            url = queue.pop(0)
            if url in crawled_urls:
                continue
                
            if not ignore_robots and not robots_parser.can_fetch(url):
                logger.debug("robots.txt Disallow rule blocks: %s", url)
                continue
                
            logger.debug("Crawling (Playwright): %s", url)
            crawled_urls.add(url)
            
            # Select proxy and user-agent
            proxy_str = random.choice(proxies_list) if proxies_list else None
            user_agent = random.choice(USER_AGENTS)
            
            context_args = {"user_agent": user_agent}
            if proxy_str:
                context_args["proxy"] = {"server": proxy_str}
                
            context = await browser.new_context(ignore_https_errors=True, **context_args)
            page = await context.new_page()
            
            # Intercept API calls dynamically
            intercepted_requests: list[str] = []
            
            def handle_request(request):
                req_url = request.url
                parsed = urlparse(req_url)
                if parsed.netloc == domain:
                    path = parsed.path.lstrip("/")
                    if any(x in path.lower() for x in ("api", "graphql", "swagger", "json")):
                        intercepted_requests.append(path)
                        
            page.on("request", handle_request)
            
            try:
                t0 = time.time()
                resp = await page.goto(url, wait_until="load", timeout=15000)
                # Wait slightly for JS to finish execution/AJAX
                await page.wait_for_timeout(1000)
                t1 = time.time()
                duration = t1 - t0

                # Fetch DOM content
                html = await page.content()
                
                # Record response
                status_code = resp.status if resp else 200
                headers = await resp.all_headers() if resp else {}
                crawl_responses.append(CrawlResponse(
                    url=url,
                    method="GET",
                    status_code=status_code,
                    response_time=duration,
                    body=html,
                    headers=headers
                ))

                # Extract same-origin links
                links = await page.eval_on_selector_all("a", "elements => elements.map(el => el.href)")
                for link in links:
                    if not link:
                        continue
                    parsed_link = urlparse(link)
                    if parsed_link.netloc == domain:
                        clean_link = urljoin(url, link).split("#")[0].rstrip("/")
                        if clean_link not in crawled_urls and clean_link not in queue:
                            queue.append(clean_link)
                    elif parsed_link.netloc and parsed_link.netloc != domain:
                        external_domains.add(parsed_link.netloc)
                        
                # Extract Forms
                page_forms = _extract_forms(html, url)
                forms.extend(page_forms)
                
                # Extract API endpoints from page JS scripts
                scripts = await page.eval_on_selector_all("script", "elements => elements.map(el => el.textContent || el.src)")
                for script in scripts:
                    if not script:
                        continue
                    if script.startswith(("http://", "https://", "/")):
                        # Resolve script URL and load script content for parsing
                        script_url = urljoin(url, script)
                        try:
                            async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                                script_resp = await client.get(script_url)
                                if script_resp.status_code == 200:
                                    endpoints = _extract_api_endpoints_from_js(script_resp.text)
                                    api_endpoints.update(endpoints)
                                    crawl_responses.append(CrawlResponse(
                                        url=script_url,
                                        method="GET",
                                        status_code=200,
                                        response_time=1.0,
                                        body=script_resp.text,
                                        headers=dict(script_resp.headers)
                                    ))
                        except Exception:
                            pass
                    else:
                        endpoints = _extract_api_endpoints_from_js(script)
                        api_endpoints.update(endpoints)
                        
            except Exception as e:
                logger.warning("Playwright failed to load URL %s: %s", url, e)
            finally:
                await context.close()
                
            # Add intercepted dynamic requests
            for req in intercepted_requests:
                api_endpoints.add(req)
                
            # Apply politeness delay
            await asyncio.sleep(politeness_delay)
            
        await browser.close()
        
    api_results = [
        ApiEndpointResult(path=ep, status_code=200, note="Discovered by web crawler")
        for ep in sorted(api_endpoints)
    ]
    return list(crawled_urls), forms, api_results, sorted(external_domains), crawl_responses


async def _run_httpx_crawler(
    base_url: str,
    domain: str,
    ignore_robots: bool,
    max_pages: int,
    politeness_delay: float,
    proxies_list: list[str],
    robots_parser: RobotsTxtParser,
) -> tuple[list[str], list[FormDetails], list[ApiEndpointResult], list[str], list[CrawlResponse]]:
    """Crawls targets using HTTPX and BeautifulSoup (static fallback)."""
    import time
    crawled_urls: set[str] = set()
    forms: list[FormDetails] = []
    api_endpoints: set[str] = set()
    external_domains: set[str] = set()
    crawl_responses: list[CrawlResponse] = []
    
    queue = [base_url]
    
    while queue and len(crawled_urls) < max_pages:
        url = queue.pop(0)
        if url in crawled_urls:
            continue
            
        if not ignore_robots and not robots_parser.can_fetch(url):
            logger.debug("robots.txt Disallow rule blocks: %s", url)
            continue
            
        logger.debug("Crawling (HTTPX Fallback): %s", url)
        crawled_urls.add(url)
        
        user_agent = random.choice(USER_AGENTS)
        proxy_str = random.choice(proxies_list) if proxies_list else None
        proxies = {"all://": proxy_str} if proxy_str else None
        
        try:
            async with httpx.AsyncClient(
                headers={"User-Agent": user_agent},
                proxy=proxy_str,
                verify=False,
                follow_redirects=True,
                timeout=10.0
            ) as client:
                t0 = time.time()
                resp = await client.get(url)
                t1 = time.time()
                duration = t1 - t0
                if resp.status_code != 200:
                    continue
                    
                html = resp.text
                soup = BeautifulSoup(html, "html.parser")
                
                # Record response
                crawl_responses.append(CrawlResponse(
                    url=url,
                    method="GET",
                    status_code=resp.status_code,
                    response_time=duration,
                    body=html,
                    headers=dict(resp.headers)
                ))

                # Extract links
                for a in soup.find_all("a", href=True):
                    link = a["href"]
                    resolved_link = urljoin(url, link).split("#")[0].rstrip("/")
                    parsed_link = urlparse(resolved_link)
                    if parsed_link.netloc == domain:
                        if resolved_link not in crawled_urls and resolved_link not in queue:
                            queue.append(resolved_link)
                    elif parsed_link.netloc and parsed_link.netloc != domain:
                        external_domains.add(parsed_link.netloc)
                        
                # Extract Forms
                page_forms = _extract_forms(html, url)
                forms.extend(page_forms)
                
                # Extract script files
                for script in soup.find_all("script"):
                    src = script.get("src")
                    if src:
                        script_url = urljoin(url, src)
                        parsed_src = urlparse(script_url)
                        if parsed_src.netloc == domain:
                            try:
                                script_resp = await client.get(script_url)
                                if script_resp.status_code == 200:
                                    endpoints = _extract_api_endpoints_from_js(script_resp.text)
                                    api_endpoints.update(endpoints)
                                    crawl_responses.append(CrawlResponse(
                                        url=script_url,
                                        method="GET",
                                        status_code=200,
                                        response_time=1.0,
                                        body=script_resp.text,
                                        headers=dict(script_resp.headers)
                                    ))
                            except Exception:
                                pass
                    elif script.string:
                        endpoints = _extract_api_endpoints_from_js(script.string)
                        api_endpoints.update(endpoints)
                        
        except Exception as e:
            logger.warning("HTTPX fallback failed to load URL %s: %s", url, e)
            
        # Apply politeness delay
        await asyncio.sleep(politeness_delay)
        
    api_results = [
        ApiEndpointResult(path=ep, status_code=200, note="Discovered by web crawler (static fallback)")
        for ep in sorted(api_endpoints)
    ]
    return list(crawled_urls), forms, api_results, sorted(external_domains), crawl_responses


async def crawl_site(
    domain: str,
    config: dict,
    ignore_robots: bool = False
) -> tuple[list[str], list[FormDetails], list[ApiEndpointResult], list[str], list[CrawlResponse]]:
    """Root crawler function. Chooses Playwright if available, or falls back to HTTPX/BeautifulSoup."""
    crawler_cfg = config.get("crawler", {})
    max_pages = crawler_cfg.get("max_pages", 30)
    config_delay = crawler_cfg.get("rate_limit_seconds", 0.5)
    proxies_list = crawler_cfg.get("proxies", [])
    
    # Establish base reachable URL
    base_url = None
    async with build_client() as client:
        for scheme in ("https", "http"):
            candidate = f"{scheme}://{domain}"
            try:
                resp = await client.get(candidate)
                base_url = str(resp.url).rstrip("/")
                break
            except Exception:
                continue
                
    if base_url is None:
        logger.warning("Could not reach target domain %s for web crawling", domain)
        return [], [], [], [], []
        
    # Check robots.txt
    user_agent = "3asfoor/1.0 (+educational use)"
    primary_proxy = proxies_list[0] if proxies_list else None
    robots_parser = RobotsTxtParser(base_url, user_agent, primary_proxy)
    await robots_parser.load()
    
    # Respect Crawl-delay if present in robots.txt
    politeness_delay = max(config_delay, robots_parser.crawl_delay)
    
    # Attempt to load Playwright
    playwright_available = False
    try:
        import playwright  # noqa: F401
        playwright_available = True
    except ImportError:
        logger.warning("Playwright is not installed. Falling back to static HTTPX crawler.")
        
    if playwright_available:
        try:
            return await _run_playwright_crawler(
                base_url, domain, ignore_robots, max_pages, politeness_delay, proxies_list, robots_parser
            )
        except Exception as e:
            logger.warning("Playwright crawler execution failed: %s. Falling back to HTTPX.", e)
            return await _run_httpx_crawler(
                base_url, domain, ignore_robots, max_pages, politeness_delay, proxies_list, robots_parser
            )
    else:
        return await _run_httpx_crawler(
            base_url, domain, ignore_robots, max_pages, politeness_delay, proxies_list, robots_parser
        )
