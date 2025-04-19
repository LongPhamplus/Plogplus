import sys
import os
import asyncio

from cli.parser import parse_args
from scanner.core.http.request import Request
from scanner.core.http.http_client import HttpClient
from scanner.core.mutator.mutator import Mutator
from scanner.crawler import SinglePageCrawler
from scanner.attacks.modules.xss.xss_main import XSSAttack
from scanner.utils import logger
from scanner.core.auth.login_handler import LoginHandler

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

async def main():
    args = parse_args()

    http_client = HttpClient()
    login_handler = LoginHandler(http_client=http_client)

    request = Request(url=args.url, method="GET")
    login_success = await login_handler.check_redirect_to_login(request)

    if args.module == "xss":
        # Khởi tạo các component cần thiết
        mutator = Mutator()
        single_crawler = SinglePageCrawler(http_client=http_client)
        await single_crawler.crawl(url=args.url)  # Trích tham số từ URL để test


        # Khởi tạo XSSAttack và chạy
        scanner = XSSAttack(
            request=request,
            single_crawler=single_crawler,
            mutator=mutator,
            http_client=http_client,
        )
        await scanner.run()
    else:
        logger.log_warning(f"[!] Module '{args.module}' không được hỗ trợ.")

if __name__ == "__main__":
    asyncio.run(main())
