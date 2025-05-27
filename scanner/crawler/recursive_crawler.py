import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse

from scanner.core.http import Request
from scanner.core.http import HttpClient
from scanner.crawler.crawler import BaseCrawler
from scanner.utils.logger import log_error
from scanner.core.auth.login_handler import LoginHandler

def is_same_domain(base_url, target_url):
    return urlparse(base_url).netloc == urlparse(target_url).netloc

def strip_fragment(url):
    parsed = urlparse(url)
    return urlunparse(parsed._replace(fragment=''))

class RecursiveCrawler(BaseCrawler):

    def __init__(
            self,
            http_client=HttpClient(),
            login_handler=None,
            report=None
    ):
        super().__init__(http_client)
        self.http_client = http_client
        self.visited_urls = set()
        self.params = {}
        self.login_handler = login_handler or LoginHandler(http_client)
        self.report = report

    async def crawl(self, url: str):
        await self._crawl_recursive(url)

    async def _crawl_recursive(self, url):
        url = strip_fragment(url)
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)

        try:
            request = Request(
                method="GET",
                url=url
            )
            if "logout" not in url.lower():
                response = await self.http_client.send(request)
                login_handler = LoginHandler(http_client=self.http_client, report=self.report)
                request = Request(url=url)
                login_status = await login_handler.check_redirect_to_login(request)
                if (not login_status) and ("login" in url.lower()):
                    log_error("Đăng nhập thất bại")
                    return
                if response.status_code != 200:
                    return
                response = await self.http_client.send(request)
                soup = BeautifulSoup(response.text, "html5lib")
                self._extract_forms(url, soup)
                self._extract_query_params(url)
                await self._extract_links(url, soup)

        except httpx.RequestError as e:
            log_error(f"Lỗi khi truy cập {url}: {e}")

    def _extract_forms(self, url, soup):
        for form in soup.find_all("form"):
            inputs = form.find_all("input")
            params = [inp.get("name") for inp in inputs if inp.get("name")]
            method = form.get("method", "GET").upper()
            if params:
                self.params.setdefault(url, {})
                self.params[url] = {
                    "method": method,
                    "params": list(set(params))
                }

    def _extract_query_params(self, url):
        parsed = urlparse(url)
        query_params = list(parse_qs(parsed.query).keys())
        if query_params:
            self.params.setdefault(url, {})
            self.params[url] = query_params

    async def _extract_links(self, base_url, soup):
        base_url = strip_fragment(base_url)
        for link in soup.find_all("a", href=True):
            href = urljoin(base_url, link["href"])
            href = strip_fragment(href)
            parsed = urlparse(href)
            if parsed.scheme.startswith("http") and is_same_domain(base_url, href):
                await self._crawl_recursive(href)
