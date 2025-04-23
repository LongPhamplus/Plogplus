import sys
import os
import asyncio

from cli.parser import parse_args
from scanner.attacks.modules.sqli.sqli_main import SQLIAttack
from scanner.core.http.request import Request
from scanner.core.http.http_client import HttpClient
from scanner.core.mutator.mutator import Mutator
from scanner.crawler import SinglePageCrawler
from scanner.attacks.modules.xss.xss_main import XSSAttack
from scanner.attacks.modules.exec.exec_main import ExecAttack
from scanner.core.auth.login_handler import LoginHandler
from scanner.utils.logger import log_error, log_warning

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def parse_cookie_string(cookie_str: str, default_domain: str = "") -> dict:
    cookies = {}
    if cookie_str:
        for pair in cookie_str.split(";"):
            if "=" in pair:
                name, value = pair.strip().split("=", 1)
                cookies[name.strip()] = value.strip()

                if "domain" not in cookies:
                    cookies["domain"] = default_domain
    return cookies


async def main():
    args = parse_args()

    cookie_dict = parse_cookie_string(args.cookie)
    url = args.url

    http_client = HttpClient()
    login_handler = LoginHandler(http_client=http_client)

    request = Request(url=url)
    login_status = await login_handler.check_redirect_to_login(request)

    if not login_status:
        log_error("Đăng nhập thất bại")
        return

    if cookie_dict:
        http_client.set_cookies(cookie_dict, url=url)

    mutator = Mutator()
    single_crawler = SinglePageCrawler(http_client=http_client)
    await single_crawler.crawl(url=args.url)

    # Danh sách module hỗ trợ
    available_modules = {
        "xss": XSSAttack,
        "exec": ExecAttack,
        "sqli": SQLIAttack,
    }

    if args.module:
        selected_modules = [args.module]
    else:
        selected_modules = list(available_modules.keys())

    for module_name in selected_modules:
        attack_class = available_modules.get(module_name)
        if not attack_class:
            log_warning(f"[!] Module '{module_name}' không được hỗ trợ.")
            continue

        scanner = attack_class(
            request=request,
            single_crawler=single_crawler,
            mutator=mutator,
            http_client=http_client
        )
        await scanner.run()


if __name__ == "__main__":
    asyncio.run(main())
