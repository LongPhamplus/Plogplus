import os
import time

from scanner.core.http import Request
from scanner.attacks import Attack
from scanner.crawler import RecursiveCrawler
from scanner.utils.payload_loader import load_all_payloads
from scanner.utils.logger import log_info
from .detector import CommandInjectionDetector

class ExecAttack(Attack):

    name = "exec"

    def __init__(
            self,
            request: Request,
            single_crawler,
            mutator,
            http_client,
            recursive_crawler = RecursiveCrawler,
            section: str = None,
    ):
        super().__init__(single_crawler=single_crawler, mutator=mutator, recursive_crawler=recursive_crawler)

        payload_file = os.path.join(os.path.dirname(__file__), "payload.ini")

        self.request = request
        self.payloads = load_all_payloads(payload_file, section=section)
        self.http_client = http_client
        self.timeout_threshold = 10

    async def run(self):
        log_info(f"[EXEC] Bắt đầu quét: {self.request.base_url}")

        for url, params in self.single_crawler.params.items():
            evil_req = Request(
                url=url,
                method=self.single_crawler.method,
                get_params=[[param, "test"] for param in params],
                post_params={param: "test" for param in params},
            )
            # Tách payloads delay và normal

            delay_payloads = [p for p in self.payloads if "delay" in p.name]
            normal_payloads = [p for p in self.payloads if "delay" not in p.name]

            delay_triggered = False

            # 1. Kiểm tra các payload delay trước
            for payload in delay_payloads:
                mutated_requests = self.mutator.mutate(evil_req, [payload])
                for req, pay_inf in mutated_requests:
                    response = await self.http_client.send(req)
                    elapsed = response.elapsed.total_seconds()

                    if response and elapsed > self.timeout_threshold:
                        log_info(
                            f"[EXEC_BLIND] Phản hồi chậm tại {req.base_url} với payload {pay_inf.payload} ({elapsed:.2f}s)")
                        delay_triggered = True
                        break
                if delay_triggered:
                    break

            # 2. Nếu delay đáng ngờ => thử payload bình thường
            if delay_triggered:
                for payload in normal_payloads:
                    mutated_requests = self.mutator.mutate(evil_req, [payload])
                    for req, pay_inf in mutated_requests:
                        response = await self.http_client.send(req)
                        detector = CommandInjectionDetector()
                        if response and detector.detect(response, pay_inf):
                            log_info(f"[EXEC] Có thể có lỗ hổng tại {req.base_url} với payload {pay_inf.payload}")