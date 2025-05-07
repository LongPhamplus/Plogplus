from urllib.parse import urljoin

from scanner.core.http.http_client import HttpClient
from scanner.core.http.request import Request
from scanner.core.http.response import Response
from scanner.core.mutator import Mutator
from scanner.utils import logger
from scanner.crawler import SinglePageCrawler
from scanner.core.auth.token_extractor import extract_csrf_token, extract_jwt_from_response
from scanner.attacks.modules.bruteforce import BruteForceAttack

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
    def __init__(
            self,
            http_client: HttpClient,
            report=None,
    ):
        self.http_client = http_client
        self.report = report

    async def check_redirect_to_login(self, request: Request) -> bool:
        response = await self.http_client.send(request, allow_redirects=True)
        check_login = False

        if response is None:
            logger.log_error("Không thể gửi request để kiểm tra redirect.")
            return False

        wrapped_resp = Response(response)
        for step_response in wrapped_resp.history:
            location = get_redirect_url(step_response)
            if "login" in location.lower():
                logger.log_warning("Chuyển hướng qua trang đăng nhập, bạn có muốn đăng nhập ? [Y/n] ", "")
                login_question = input()
                crawler = SinglePageCrawler()
                await crawler.crawl(url=location)
                method = crawler.method
                login_data = {}
                if login_question.lower() == "y":
                    for url, param_list in crawler.params.items():
                        logger.log_info(f"Tìm thấy form login tại: {url}")
                        logger.log_info(f"Tìm thấy các trường: {param_list}")

                        for param in param_list:
                            value = input(f"Nhập giá trị cho '{param}': ")
                            login_data[param] = value

                        if crawler.hidden_params:
                            for hidden_url, params in crawler.hidden_params.items():
                                for param_name, param_value in params.items():
                                    # print(param_name, param_value)
                                    login_data[param_name] = param_value
                        if crawler.submit_params:
                            for submit_url, params in crawler.submit_params.items():
                                for param_name, param_value in params.items():
                                    # print(param_name, param_value)
                                    login_data[param_name] = param_value
                        check_login = await self.perform_login(url, login_data, response, method)

                    return check_login
                else:
                    mutator = Mutator()
                    scanner = BruteForceAttack(
                        request=request,
                        single_crawler=crawler,
                        mutator=mutator,
                        http_client=self.http_client,
                        report=self.report,
                    )
                    check_login = await scanner.run()
                    return check_login

        return False

    async def perform_login(self, login_path: str, login_data: dict, original_response, method: str) -> bool:
        login_url = urljoin(str(original_response.url), login_path)

        get_login_req = Request(url=login_url, method=method)
        login_page_resp = await self.http_client.send(get_login_req)

        csrf_token = extract_csrf_token(login_page_resp.text)
        if csrf_token:
            logger.log_info(f"CSRF token phát hiện: {csrf_token}")
            login_data["user_token"] = csrf_token

        req = Request(
            url=login_url,
            method=method,
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

            logger.log_error("Không xác định được kiểu đăng nhập (không có cookie hoặc token) hoặc nhập sai tài khoản và mật khẩu.")
            return False

        except Exception as e:
            logger.log_error(f"Lỗi khi đăng nhập: {e}")
            return False
