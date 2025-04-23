import httpx
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs

from scanner.core.http import HttpClient, Request
from scanner.crawler.crawler import BaseCrawler

class SinglePageCrawler(BaseCrawler):

    def __init__(self, http_client=HttpClient()):
        super().__init__(http_client)

        self.http_client=http_client
        self.params = {}
        self.hidden_params = {}
        self.submit_params = {}

    async def crawl(self, url: str):
        try:
            request = Request(
                url=url,
                method="GET",
            )
            response = await self.http_client.send(request)
            if response.status_code != 200:
                return
            soup = BeautifulSoup(response.text, "html5lib")
            self._extract_forms(url, soup)
            self._extract_query_params(url)
        except httpx.RequestError as e:
            print(f"[ERROR] Lỗi khi truy cập {url}: {e}")

    def _extract_forms(self, url, soup):
        for form in soup.find_all("form"):
            inputs = form.find_all("input")

            method = form.get("method").upper()
            self.method = method

            params = []
            hidden_params = []
            submit_params = []

            for inp in inputs:
                if inp.get("type") == "hidden":
                    hidden_params.append((inp.get("name"), inp.get("value")))
                elif inp.get("type") == "submit":
                    submit_params.append((inp.get("name"), inp.get("value")))
                else:
                    params.append(inp.get("name"))
            if params:
                self.params[url] = list(set(params))
            if hidden_params:
                self.hidden_params[url] = dict(hidden_params)
            if submit_params:
                self.submit_params[url] = dict(submit_params)

    #  Nên sửa thành phân biệt giữa param input và param submit
    def _extract_query_params(self, url):
        parsed = urlparse(url)
        query_params = list(parse_qs(parsed.query).keys())
        if query_params:
            self.params[url] = query_params
