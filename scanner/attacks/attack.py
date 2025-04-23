# scanner/attacks/attack.py

from abc import ABC, abstractmethod


from scanner.crawler import SinglePageCrawler, RecursiveCrawler
from scanner.core.http.http_client import HttpClient
from scanner.core.mutator.mutator import Mutator



class Attack(ABC):

    name = "attack"

    def __init__(
            self,
            single_crawler: SinglePageCrawler = None,
            recursive_crawler: RecursiveCrawler = None,
            mutator: Mutator = None,
    ):
        super().__init__()
        self.http_client = HttpClient()
        self.single_crawler = single_crawler
        self.recursive_crawler = recursive_crawler
        self.mutator = mutator

    @abstractmethod
    async def run(self):
        """Chạy tấn công - phải được implement ở lớp con"""
        raise NotImplementedError("Override me please")

