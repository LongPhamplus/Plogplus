import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="VulnScanner - Custom Web Vulnerability Scanner")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("-m", "--module", choices=["xss"], default="xss", help="Attack module to use")
    parser.add_argument("--cookie", help="Cookies to use")
    parser.add_argument("--user-agent", default="VulnScanner/1.0", help="User-Agent header")
    parser.add_argument("--proxy", help="Proxy (e.g. http://127.0.0.1:8080)")
    return parser.parse_args()
