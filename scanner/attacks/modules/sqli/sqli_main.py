import os
import time

from scanner.core.http import Request
from scanner.attacks import Attack
from scanner.crawler import RecursiveCrawler
from scanner.utils.payload_loader import load_all_payloads
from scanner.utils.logger import log_info
from .detector import SQLIDetector

class SQLIAttack(Attack):

    name = "exec"

    def __init__(
            self,
            request: Request,
            single_crawler,
            mutator,
            http_client,
            recursive_crawler = RecursiveCrawler,
            section: str = None,
            report=None,
    ):
        super().__init__(single_crawler=single_crawler, mutator=mutator, recursive_crawler=recursive_crawler,
                         report=report)

        payload_file = os.path.join(os.path.dirname(__file__), "payload.ini")

        self.request = request
        self.payloads = load_all_payloads(payload_file, section=section)
        self.http_client = http_client
        self.timeout_threshold = 5

    async def run(self):
        log_info(f"[SQLI] Bắt đầu quét: {self.request.base_url}")
        for url, params in self.single_crawler.params.items():
            method = self.single_crawler.method

            # Dữ liệu gốc từ crawler
            hidden_params = self.single_crawler.hidden_params.get(url, {})
            submit_params = self.single_crawler.submit_params.get(url, {})

            # Chỉ thay đổi giá trị các param tấn công
            attack_values = {param: "1" for param in params}

            # Gộp lại tất cả param
            combined_params = {
                **hidden_params,
                **submit_params,
                **attack_values
            }

            if method.upper() == "GET":
                get_params = [[k, v] for k, v in combined_params.items()]
                post_params = {}
            else:
                get_params = []
                post_params = combined_params

            evil_req = Request(
                url=url,
                method=method,
                get_params=get_params,
                post_params=post_params,
            )
            # Tách payloads delay và normal
            delay_payloads = [p for p in self.payloads if "delay" in p.name]
            normal_payloads = [p for p in self.payloads if "delay" not in p.name]

            delay_triggered = False
            delay_payload_used = None  # Lưu lại payload gây delay

            # 1. Kiểm tra các payload delay trước
            for payload in delay_payloads:
                mutated_requests = self.mutator.mutate(evil_req, [payload])
                for req, pay_inf in mutated_requests:
                    response = await self.http_client.send(req)
                    if response:
                        elapsed = response.elapsed.total_seconds()
                        report_param = req.get_params if req.method == "GET" else req.post_data
                        if elapsed > self.timeout_threshold:
                            self.log_vulnerability(
                                vuln_type="SQLI_BLIND",
                                url=req.base_url,
                                param=report_param,
                                payload=pay_inf,
                                evidence="Có thể chèn mã độc và gây delay cho chương trình."
                            )
                            log_info(
                                f"[SQLI_BLIND] Phản hồi chậm tại {req.base_url} với payload {pay_inf.payload} ({elapsed:.2f}s)"
                            )
                            delay_triggered = True
                            delay_payload_used = pay_inf  # Lưu lại thông tin payload
                            break
                if delay_triggered:
                    break

            # 2. Nếu delay đáng ngờ => thử payload bình thường
            if delay_triggered:
                for payload in normal_payloads:
                    if payload.language == delay_payload_used.language:
                        mutated_requests = self.mutator.mutate(evil_req, [payload])
                        for req, pay_inf in mutated_requests:
                            response = await self.http_client.send(req)
                            detector = SQLIDetector()
                            report_param = req.get_params if req.method == "GET" else req.post_data
                            if response and await detector.detect(response, pay_inf):
                                self.log_vulnerability(
                                    vuln_type="SQLI",
                                    url=req.base_url,
                                    param=report_param,
                                    payload=pay_inf,
                                    evidence="Có thể chèn mã độc vào câu truy vấn."
                                )
                                log_info(f"[SQLI] Có thể có lỗ hổng tại {req.base_url} với payload {pay_inf.payload}")