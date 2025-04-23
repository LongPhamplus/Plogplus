import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from scanner.crawler.crawler import BaseCrawler

class RecursiveCrawler(BaseCrawler):
    async def crawl(self, url: str):
        await self._crawl_recursive(url)

    async def _crawl_recursive(self, url):
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)

        try:
            response = httpx.get(url, timeout=10)
            if response.status_code != 200:
                return
            soup = BeautifulSoup(response.text, "lxml")
            self._extract_forms(url, soup)
            self._extract_query_params(url)
            await self._extract_links(url, soup)

        except httpx.RequestError as e:
            print(f"[ERROR] Lỗi khi truy cập {url}: {e}")

    def _extract_forms(self, url, soup):
        for form in soup.find_all("form"):
            inputs = form.find_all("input")
            params = [inp.get("name") for inp in inputs if inp.get("name")]
            method = form.get("method", "GET").upper()
            if params:
                self.params[url] = {
                    "method": method,
                    "params": list(set(params))
                }

    def _extract_query_params(self, url):
        parsed = urlparse(url)
        query_params = list(parse_qs(parsed.query).keys())
        if query_params:
            self.params[url] = query_params

    async def _extract_links(self, base_url, soup):
        for link in soup.find_all("a", href=True):
            href = urljoin(base_url, link["href"])
            parsed = urlparse(href)
            if parsed.scheme.startswith("http"):
                await self._crawl_recursive(href)
