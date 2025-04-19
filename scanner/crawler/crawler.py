
from abc import ABC, abstractmethod

class BaseCrawler(ABC):
    def __init__(self, http_client=None):
        self.visited_urls = set()
        self.params = {}  # key: url, value: list of params
        self.http_client = http_client

    @abstractmethod
    async def crawl(self, url: str):
        pass

