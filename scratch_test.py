import asyncio
import logging
from unittest.mock import patch, MagicMock, AsyncMock
from asfoor.modules.crawler import crawl_site
import httpx

# Enable logging
logging.basicConfig(level=logging.DEBUG)

mock_homepage = """
<html>
    <body>
        <a href="/about">About</a>
        <a href="https://external.com/page">External</a>
        <form action="/contact" method="post">
            <input name="email" type="email">
        </form>
        <script src="/static/app.js"></script>
    </body>
</html>
"""

mock_app_js = """
fetch('/api/v1/data');
"""

async def mock_get(url, *args, **kwargs):
    print("Mock get URL:", url)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.url = httpx.URL(str(url))
    if "/static/app.js" in str(url):
        mock_resp.text = mock_app_js
    else:
        mock_resp.text = mock_homepage
    return mock_resp

async def main():
    with patch("asfoor.modules.crawler.build_client") as mock_build_client:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_build_client.return_value.__aenter__.return_value = mock_client

        with patch("asfoor.modules.crawler.httpx.AsyncClient") as mock_httpx_client:
            mock_sub_client = AsyncMock()
            mock_sub_client.get = AsyncMock(side_effect=mock_get)
            mock_httpx_client.return_value.__aenter__.return_value = mock_sub_client

            try:
                crawled_urls, forms, api_endpoints, external_domains, crawl_responses = await crawl_site("example.com", {})
                print("Crawled URLs:", crawled_urls)
                print("Forms:", len(forms))
                print("API endpoints:", len(api_endpoints))
                print("Crawl responses:", len(crawl_responses))
            except Exception as e:
                import traceback
                traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
