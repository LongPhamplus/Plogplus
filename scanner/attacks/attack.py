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
            report=None,
    ):
        super().__init__()
        self.http_client = HttpClient()
        self.single_crawler = single_crawler
        self.recursive_crawler = recursive_crawler
        self.mutator = mutator
        self.report = report

    def log_vulnerability(self, vuln_type, url, param, payload, evidence):
        """Ghi log phát hiện vào report"""
        if self.report:
            self.report.add_entry(
                vuln_type=vuln_type,
                url=url,
                param=param,
                payload=payload,
                evidence=evidence
            )

    @abstractmethod
    async def run(self):
        """Chạy tấn công - phải được implement ở lớp con"""
        raise NotImplementedError("Override me please")

