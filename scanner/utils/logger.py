import sys

class Color:
    RESET = "\033[0m"
    INFO = "\033[94m"     # Blue
    VULN = "\033[91m"     # Red
    SUCCESS = "\033[92m"  # Green
    WARNING = "\033[93m"  # Yellow
    ERROR = "\033[95m"    # Magenta

def log_info(message: str, end: str = None):
    print(f"{Color.INFO}[INFO]{Color.RESET} {message}", end=end)

def log_vuln(message: str, end: str = None):
    print(f"{Color.VULN}[VULN]{Color.RESET} {message}", end=end)

def log_success(message: str, end: str = None):
    print(f"{Color.SUCCESS}[OK]{Color.RESET} {message}", end=end)

def log_warning(message: str, end: str = None):
    print(f"{Color.WARNING}[WARN]{Color.RESET} {message}", end=end)

def log_error(message: str, end: str = None):
    print(f"{Color.ERROR}[ERROR]{Color.RESET} {message}", file=sys.stderr, end=end)
