import os

from scanner.attacks import Attack
from scanner.attacks.modules.upload import UploadDetector
from scanner.core.http import Request, HttpClient
from scanner.crawler import RecursiveCrawler
from scanner.utils.logger import log_info
from scanner.utils.payload_loader import load_all_payloads


class UploadAttack(Attack):
    def __init__(
            self,
            request: Request,
            single_crawler,
            mutator,
            http_client: HttpClient,
            recursive_crawler=RecursiveCrawler,
            section: str = None,
    ):
        super().__init__(single_crawler=single_crawler, mutator=mutator, recursive_crawler=recursive_crawler)

        payload_file = os.path.join(os.path.dirname(__file__), "payload.ini")

        self.request = request
        self.http_client = http_client
        self.payloads = load_all_payloads(payload_file, section=section)

    async def run(self):
        log_info(f"[UPLOAD] Bắt đầu quét: {self.request.base_url}")
        # Lấy danh sách param từ crawler
        post_params = {}
        if self.single_crawler.hidden_params:
            for hidden_url, params in self.single_crawler.hidden_params.items():
                for param_name, param_value in params.items():
                    # print(param_name, param_value)
                    post_params[param_name] = param_value
        if self.single_crawler.submit_params:
            for submit_url, params in self.single_crawler.submit_params.items():
                for param_name, param_value in params.items():
                    # print(param_name, param_value)
                    post_params[param_name] = param_value
        for url, params in self.single_crawler.params.items():

            evil_req = Request(
                url=url,
                method=self.single_crawler.method,
                file_params={param: ("test.jpg", "fake file content", "application/octet-stream") for param in params},
                post_params=post_params
            )

            for payload in self.payloads:
                mutated_requests = self.mutator.mutate(evil_req, [payload])
                for req, pay_inf in mutated_requests:
                    response = await self.http_client.send(req)
                    detector = UploadDetector()
                    if response and await detector.detect(response, pay_inf):
                        log_info(f"[UPLOAD] Có thể có lỗ hổng tại {req.base_url} với payload dạng {pay_inf.type}")