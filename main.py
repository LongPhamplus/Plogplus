import sys
import os
import asyncio
from reprlib import recursive_repr

from cli.parser import parse_args
from scanner.attacks.modules.sqli.sqli_main import SQLIAttack
from scanner.attacks.modules.upload.upload_main import UploadAttack
from scanner.core.http.request import Request
from scanner.core.http.http_client import HttpClient
from scanner.core.mutator.mutator import Mutator
from scanner.crawler import SinglePageCrawler, RecursiveCrawler
from scanner.attacks.modules.xss.xss_main import XSSAttack
from scanner.attacks.modules.exec.exec_main import ExecAttack
from scanner.core.auth.login_handler import LoginHandler
from scanner.reports.html_report import HTMLReport
from scanner.utils.logger import log_error, log_warning, log_info

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def print_banner():
    print("")
    print(r"""
    ----------------------------------------------------------------------------
     ███████████  ████                              ████                    
    ░░███░░░░░███░░███                             ░░███                    
     ░███    ░███ ░███   ██████   ███████ ████████  ░███  █████ ████  █████ 
     ░██████████  ░███  ███░░███ ███░░███░░███░░███ ░███ ░░███ ░███  ███░░  
     ░███░░░░░░   ░███ ░███ ░███░███ ░███ ░███ ░███ ░███  ░███ ░███ ░░█████ 
     ░███         ░███ ░███ ░███░███ ░███ ░███ ░███ ░███  ░███ ░███  ░░░░███
     █████        █████░░██████ ░░███████ ░███████  █████ ░░████████ ██████ 
    ░░░░░        ░░░░░  ░░░░░░   ░░░░░███ ░███░░░  ░░░░░   ░░░░░░░░ ░░░░░░  
                                 ███ ░███ ░███                              
                                ░░██████  █████                             
                                 ░░░░░░  ░░░░░                           
    ----------------------------------------------------------------------------   
    """)


def parse_cookie_string(cookie_str: str) -> dict:
    cookies = {}
    if cookie_str:
        for pair in cookie_str.split(";"):
            if "=" in pair:
                name, value = pair.strip().split("=", 1)
                cookies[name.strip()] = value.strip()
    return cookies


async def main():

    print_banner()
    # Start main function
    args = parse_args()

    if not args.crawl and not args.scan:
        log_warning("Vui lòng chỉ định --crawl hoặc --scan")
        return

    # Init field begin
    cookie_dict = parse_cookie_string(args.cookie)
    url = args.url
    report = HTMLReport()
    http_client = HttpClient()
    mutator = Mutator()
    # Init field end

    if cookie_dict:
        http_client.set_cookies(cookie_dict, url=url)

    if args.crawl:
        recursive_crawler = RecursiveCrawler(http_client=http_client, report=report)
        await recursive_crawler.crawl(url=args.url)
        with open("crawled_urls.txt", "w", encoding="utf-8") as f:
            for u in recursive_crawler.visited_urls:
                f.write(u + "\n")
        log_info(f"Đã lưu {len(recursive_crawler.visited_urls)} URL vào crawled_urls.txt")
        return
    if args.scan:
        # Load URL từ file
        try:
            with open("crawled_urls.txt", "r", encoding="utf-8") as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            log_error("Không tìm thấy file crawled_urls.txt")
            return

        available_modules = {
            "xss": XSSAttack,
            "exec": ExecAttack,
            "sqli": SQLIAttack,
            "upload": UploadAttack,
        }

        selected_modules = [args.module] if args.module else list(available_modules.keys())

        for url in urls:
            if "logout" not in url.lower():

                login_handler = LoginHandler(http_client=http_client, report=report)
                request = Request(url=url)
                login_status = await login_handler.check_redirect_to_login(request)
                if not login_status and "login" in url.lower():
                    log_error(f"Đăng nhập thất bại với URL: {url}")
                    continue

                single_crawler = SinglePageCrawler(http_client=http_client)
                await single_crawler.crawl(url=url)

                for module_name in selected_modules:
                    attack_class = available_modules.get(module_name)
                    if not attack_class:
                        log_warning(f"[!] Module '{module_name}' không được hỗ trợ.")
                        continue

                    scanner = attack_class(
                        request=request,
                        single_crawler=single_crawler,
                        mutator=mutator,
                        http_client=http_client,
                        report=report,
                    )
                    await scanner.run()

        report.save("scan_report.html")
        log_info("Báo cáo đã được lưu tại scan_report.html")

if __name__ == "__main__":
    asyncio.run(main())
