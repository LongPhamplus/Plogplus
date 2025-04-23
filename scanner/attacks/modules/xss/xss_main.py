import os
import re

from scanner.crawler import RecursiveCrawler
from scanner.core.payload.payload import PayloadInfo

from scanner.core.http.request import Request
from scanner.utils.logger import log_info
from scanner.utils.payload_loader import load_all_payloads
from scanner.attacks import Attack
from scanner.core.http.http_client import HttpClient
from scanner.core.http.response import Response


def is_vulnerable(response: Response, payload_info: PayloadInfo) -> bool:
    """
    Kiểm tra phản hồi có dấu hiệu XSS dựa trên thông tin payload.
    Trả về True nếu phát hiện phản hồi chứa payload trong ngữ cảnh HTML hợp lệ.
    """
    if not response or not response.text:
        return False

    content = response.text
    value = payload_info.value
    tag = payload_info.tag
    case_sensitive = payload_info.case_sensitive.lower() == "yes"

    # Nếu không phân biệt hoa thường, chuẩn hóa value
    if not case_sensitive:
        value = value.lower()
        tag = tag.lower() if tag else None

    if (value not in content) and (not case_sensitive and value not in content.lower()):
        return False

    if tag:
        # Tạo regex với flag phù hợp
        flags = re.DOTALL
        if not case_sensitive:
            flags |= re.IGNORECASE

        tag_pattern = re.compile(
            rf"<{re.escape(tag)}[^>]*>(.*?)</{re.escape(tag)}>",
            flags
        )
        matches = tag_pattern.findall(content)
        for match in matches:
            # So sánh value với match (tùy case_sensitive)
            if (value in match) if case_sensitive else (value in match.lower()):
                return True
        return False
    else:
        return True  # Không yêu cầu kiểm tra tag, chỉ cần có value

class XSSAttack(Attack):

    name = "xss"

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
        self.payloads = load_all_payloads(payload_file, section=section)
        self.http_client = http_client

        # Tùy chọn: Nếu muốn sử dụng kỹ thuật callback
        # self.callback_domain = callback_domain

    async def run(self):
        log_info(f"[XSS] Bắt đầu quét: {self.request.base_url}")
        # Lấy danh sách param từ crawler
        for url, params in self.single_crawler.params.items():
            evil_req = Request(
                url=url,
                method=self.single_crawler.method,
                get_params=[[param, "test"] for param in params]
            )

            if isinstance(self.payloads, list):
                mutated_requests = self.mutator.mutate(evil_req, self.payloads)
            else:
                mutated_requests = []
                # Gửi các request và phân tích response
            for req, pay_inf in mutated_requests:
                response = await self.http_client.send(req)
                if response and is_vulnerable(response, pay_inf):
                    log_info(f"[XSS] Có thể có lỗ hổng tại {req.base_url} với payload {pay_inf.payload}")
                    # Sử dụng callback domain để kiểm tra thêm


