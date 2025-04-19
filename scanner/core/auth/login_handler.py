import re
from urllib.parse import urljoin

from scanner.core.http.http_client import HttpClient
from scanner.core.http.request import Request
from scanner.core.http.response import Response
from scanner.utils import logger
from scanner.crawler import SinglePageCrawler
from scanner.core.auth.token_extractor import extract_csrf_token, extract_jwt_from_response

def get_redirect_url(response):
    """
    Trích xuất URL chuyển hướng từ header 'Location', xử lý cả đường dẫn tương đối và tuyệt đối.

    :param response: Đối tượng response từ httpx
    :return: URL đầy đủ (absolute URL) sau khi tính toán từ location header
    """
    location = response.headers.get("location")
    if location:
        # Kết hợp với URL gốc nếu location là tương đối
        return urljoin(str(response.url), location)
    return ""

class LoginHandler:
    def __init__(self, http_client: HttpClient):
        self.http_client = http_client

    async def check_redirect_to_login(self, request: Request) -> bool:
        response = await self.http_client.send(request, allow_redirects=True)

        if response is None:
            logger.log_error("Không thể gửi request để kiểm tra redirect.")
            return False

        wrapped_resp = Response(response)
        for step_response in wrapped_resp.history:
            location = get_redirect_url(step_response)
            if "login" in location.lower():
                logger.log_warning("Chuyển hướng qua trang đăng nhập, bạn có muốn đăng nhập ? [Y/n] ", "")
                login_question = input()
                if login_question.lower() == "y":
                    crawler = SinglePageCrawler()
                    await crawler.crawl(url=location)

                    for url, param_list in crawler.params.items():
                        logger.log_info(f"Tìm thấy form login tại: {url}")
                        logger.log_info(f"Tìm thấy các trường: {param_list}")

                        login_data = {}
                        for param in param_list:
                            value = input(f"Nhập giá trị cho '{param}': ")
                            login_data[param] = value

                        return await self.perform_login(url, login_data, response)
                else:
                    logger.log_info("Bỏ qua đăng nhập.")
        return False

    async def perform_login(self, login_path: str, login_data: dict, original_response) -> bool:
        login_url = urljoin(str(original_response.url), login_path)

        get_login_req = Request(url=login_url, method="GET")
        login_page_resp = await self.http_client.send(get_login_req)

        csrf_token = extract_csrf_token(login_page_resp.text)
        if csrf_token:
            logger.log_info(f"CSRF token phát hiện: {csrf_token}")
            login_data["user_token"] = csrf_token

        req = Request(
            url=login_url,
            method="POST",
            post_params=login_data,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": login_url
            }
        )

        try:
            login_resp = await self.http_client.send(req)
            wrapped_resp = Response(login_resp)

            cookies = self.http_client.client.cookies
            if (
                cookies and any(cookie.value for cookie in cookies.jar) and
                ("Logout" in wrapped_resp.text or "logout" in wrapped_resp.text)
            ):
                logger.log_success("Đăng nhập thành công với session cookies!")
                return True

            jwt_token = extract_jwt_from_response(wrapped_resp)
            if jwt_token:
                logger.log_success("Đăng nhập thành công với JWT token!")
                self.http_client.client.headers["Authorization"] = f"Bearer {jwt_token}"
                return True

            logger.log_error("Không xác định được kiểu đăng nhập (không có cookie hoặc token).")
            return False

        except Exception as e:
            logger.log_error(f"Lỗi khi đăng nhập: {e}")
            return False
