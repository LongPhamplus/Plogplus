import os

from scanner.attacks import Attack
from scanner.core.http import Request, HttpClient, Response
from scanner.crawler import RecursiveCrawler
from scanner.utils.logger import log_info, log_success, log_error
from scanner.utils.payload_loader import load_credentials
from scanner.core.auth.token_extractor import extract_jwt_from_response


def is_login_success(response, http_client) -> bool:
    """
    Kiểm tra xem việc đăng nhập có thành công không dựa vào cookie hoặc JWT.

    :param response: Response object trả về sau khi gửi request đăng nhập
    :param http_client: HttpClient chứa thông tin cookies và headers
    :return: True nếu đăng nhập thành công, False nếu thất bại
    """
    wrapped_resp = Response(response)

    # Kiểm tra cookie session có tồn tại
    cookies = http_client.client.cookies
    has_valid_cookie = cookies and any(cookie.value for cookie in cookies.jar)

    # Kiểm tra nếu HTML trả về chứa dấu hiệu đã đăng nhập
    if has_valid_cookie and ("Logout" in wrapped_resp.text or "logout" in wrapped_resp.text):
        log_success("Đăng nhập thành công với session cookies!")
        return True

    # Kiểm tra nếu có JWT token trả về
    jwt_token = extract_jwt_from_response(wrapped_resp)
    if jwt_token:
        http_client.client.headers["Authorization"] = f"Bearer {jwt_token}"
        log_success("Đăng nhập thành công với JWT token!")
        return True

    return False

class BruteForceAttack(Attack):
    def __init__(
            self,
            request: Request,
            single_crawler,
            mutator,
            http_client: HttpClient,
            recursive_crawler=RecursiveCrawler,
            report=None,
    ):
        super().__init__(single_crawler=single_crawler, mutator=mutator,
                         recursive_crawler=recursive_crawler, report=report)

        username_file = os.path.join(os.path.dirname(__file__), "username.txt")
        password_file = os.path.join(os.path.dirname(__file__), "password.txt")

        self.request = request
        self.http_client = http_client
        self.payloads = load_credentials(username_file, password_file)
    async def run(self):
        log_info(f"[BRUTEFORCE] Bắt đầu quét: {self.request.base_url}")

        for url, params in self.single_crawler.params.items():
            method = self.single_crawler.method.upper()

            # Hidden + Submit parameters
            hidden_params = self.single_crawler.hidden_params.get(url, {})
            submit_params = self.single_crawler.submit_params.get(url, {})

            # Gộp lại tất cả param gốc
            base_params = {
                **hidden_params,
                **submit_params
            }
            # Xác định các tên trường đăng nhập
            username_field = "username"
            password_field = "password"
            for field in params:
                if "user" in field.lower():
                    username_field = field
                elif "pass" in field.lower():
                    password_field = field

            for payload in self.payloads:
                brute_params = base_params.copy()
                brute_params[username_field] = payload["username"]
                brute_params[password_field] = payload["password"]

                if method == "GET":
                    req = Request(
                        url=url,
                        method="GET",
                        get_params=[[k, v] for k, v in brute_params.items()]
                    )
                else:
                    req = Request(
                        url=url,
                        method="POST",
                        post_params=brute_params
                    )

                response = await self.http_client.send(req)
                if is_login_success(response, self.http_client):
                    self.log_vulnerability(
                        vuln_type="BRUTEFORCE",
                        url=req.base_url,
                        param={username_field: payload["username"], password_field: payload["password"]},
                        payload=payload,
                        evidence="Đăng nhập thành công với thông tin hợp lệ."
                    )
                    log_info(f"[BRUTEFORCE] Thành công với: {payload['username']}:{payload['password']}")
                    return True # hoặc tiếp tục thử nếu muốn tất cả

            return False