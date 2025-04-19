import os

from scanner.core.payload.payload import PayloadInfo
from scanner.crawler import SinglePageCrawler
from scanner.core.mutator.mutator import Mutator
from scanner.core.http.request import Request
from scanner.utils.logger import log_info, log_vuln, log_error
from scanner.utils.payload_loader import load_all_payloads
from scanner.attacks.attack import Attack
from scanner.core.http.http_client import HttpClient
from scanner.core.http.response import Response


def is_vulnerable(response: Response, payload_info: PayloadInfo) -> bool:
    """
    Kiểm tra phản hồi có dấu hiệu XSS dựa trên thông tin payload.
    """
    if response is None or response.text is None:
        return False

    content = response.text
    value = payload_info.value
    tag = payload_info.tag
    case_sensitive = payload_info.case_sensitive == "yes"

    # Nếu không phân biệt hoa thường
    if not case_sensitive:
        content = content.lower()
        value = value.lower()
        tag = tag.lower() if tag else None

    # Kiểm tra nếu `value` xuất hiện trong phản hồi
    if value not in content:
        return False

    # Nếu có tag, kiểm tra thêm cấu trúc tag <tag>...</tag>
    if tag:
        open_tag = f"<{tag}>"
        close_tag = f"</{tag}>"
        if open_tag in content and close_tag in content:
            start = content.find(open_tag)
            end = content.find(close_tag, start)
            if start != -1 and end != -1:
                inner_content = content[start + len(open_tag):end]
                if value in inner_content:
                    return True
        return False  # Có value nhưng không nằm trong đúng tag
    else:
        return True  # Không yêu cầu kiểm tra tag, chỉ cần có value là OK

class XSSAttack(Attack):

    name = "xss"

    def __init__(
            self,
            request: Request,
            single_crawler: SinglePageCrawler,
            mutator: Mutator,
            http_client: HttpClient,
            section: str = None,
            callback_domain: str = None,
    ):
        super().__init__(single_crawler=single_crawler, mutator=mutator)

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
                method="GET",
                get_params=[[param, "test"] for param in params]
            )

            if isinstance(self.payloads, list):
                mutated_requests = self.mutator.mutate_get(evil_req, self.payloads)
            else:
                mutated_requests = []
                # Gửi các request và phân tích response
            for req, pay_inf in mutated_requests:
                response = await self.http_client.send(req)
                if response and is_vulnerable(response, pay_inf):
                    log_info(f"[XSS] Có thể có lỗ hổng tại {req.base_url} với payload {pay_inf.payload}")
                    # Sử dụng callback domain để kiểm tra thêm


