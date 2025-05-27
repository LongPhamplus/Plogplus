import argparse

def parse_args():
    parser = argparse.ArgumentParser(
        description="VulnScanner - Custom Web Vulnerability Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # Required target URL
    parser.add_argument(
        "url",
        help="Target URL to scan"
    )

    # General options
    general = parser.add_argument_group("General Options")
    general.add_argument(
        "-m", "--module",
        choices=["xss", "exec", "sqli", "upload"],
        help="Select a specific attack module to run (if not set, all modules will run)"
    )
    general.add_argument(
        "-c", "--cookie",
        help="Cookies to use for authentication (e.g. 'sessionid=abc123; token=xyz456')"
    )

    # Actions
    actions = parser.add_argument_group("Actions")
    actions.add_argument(
        "-C", "--crawl",
        action="store_true",
        help="Enable recursive crawling to discover URLs"
    )
    actions.add_argument(
        "-S", "--scan",
        action="store_true",
        help="Enable vulnerability scanning (uses crawled URLs)"
    )

    return parser.parse_args()
