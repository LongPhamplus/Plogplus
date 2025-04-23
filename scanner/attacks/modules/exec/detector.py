
from scanner.attacks import Detector
from scanner.core.http import Response
from scanner.core.payload import PayloadInfo


def _has_command_output_structure(content: str) -> bool:
    """Kiểm tra cấu trúc điển hình của output command"""
    lines = content.strip().split('\n')

    # Nếu output có nhiều dòng có cấu trúc giống nhau (như ls -la)
    if len(lines) >= 3:
        # Kiểm tra cấu trúc giống dạng danh sách file
        space_counts = [len(line) - len(line.lstrip()) for line in lines if line.strip()]
        if len(set(space_counts)) <= 2 and len(lines) > 5:
            return True

        # Kiểm tra dạng bảng (như ps, top, netstat)
        columns_count = [len(line.split()) for line in lines[:3] if line.strip()]
        if len(set(columns_count)) == 1 and columns_count[0] >= 3:
            return True

    return False


def _is_likely_command_output(content: str, payload: str) -> bool:
    """
    Kiểm tra xem nội dung có phải là output của lệnh hay không,
    loại trừ trường hợp server chỉ đơn giản echo lại payload
    """
    # Nếu content chỉ chứa payload và một số ký tự HTML/whitespace
    import re
    cleaned_content = re.sub(r'\s+', ' ', content).strip()
    cleaned_payload = re.sub(r'\s+', ' ', payload).strip()

    # Nếu nội dung khác biệt đáng kể so với payload
    if len(cleaned_content) > len(cleaned_payload) * 1.5:
        # Và chứa cấu trúc giống output lệnh
        lines = content.split('\n')
        if len(lines) > 2:  # Nhiều dòng thường là dấu hiệu của output lệnh
            return True

    return False


def _strip_html_tags(content: str) -> str:
    """Loại bỏ HTML tags từ content"""
    # Implement cơ bản, trong thực tế nên sử dụng thư viện như BeautifulSoup
    import re
    return re.sub(r'<[^>]+>', ' ', content)


class CommandInjectionDetector(Detector):
    def __init__(self):
        # Định nghĩa các indicators trong constructor để tránh khởi tạo lại mỗi lần gọi detect
        self.unix_indicators = {
            # Output của các lệnh Unix phổ biến
            "uid=", "gid=", "groups=", "root:x", "/etc/passwd", "/etc/shadow",
            # Thông tin hệ thống
            "linux", "ubuntu", "debian", "centos", "fedora", "redhat",
            # Shells và path
            "bash", "sh", "zsh", "/bin/", "/usr/bin/", "/var/www/",
            # Lệnh phổ biến
            "ls -la", "pwd", "whoami", "id", "uname -a", "cat /etc"
        }

        self.windows_indicators = {
            # Output của các lệnh Windows
            "volume in drive", "directory of", "microsoft windows", "system32",
            # Thông tin hệ thống
            "windows", "win32", "win64", "c:\\", "d:\\", "program files",
            # Command phổ biến
            "dir ", "type ", "net user", "ipconfig", "systeminfo", "tasklist",
            # Admin và users
            "administrator", "authority\\system", "users\\", "documents and settings\\"
        }

        # RegEx patterns cho phát hiện nâng cao
        self.regex_patterns = [
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP addresses
            r"([a-f0-9]{2}:){5}[a-f0-9]{2}",        # MAC addresses
            r"\w+@\w+\.\w+",                         # Email format (có thể là output của whoami)
            r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"   # Timestamp từ các lệnh như ls -la
        ]

    def detect(self, response: Response, payload_info: PayloadInfo) -> bool:
        """
        Phân tích phản hồi để xác định xem có bị command injection hay không.

        Args:
            response: Đối tượng Response chứa phản hồi từ server
            payload_info: Thông tin về payload đã gửi

        Returns:
            bool: True nếu phát hiện dấu hiệu của command injection
        """
        if not response.text:
            return False

        content = response.text.lower()

        # Loại bỏ HTML tags nếu response là HTML
        if "<html" in content:
            content = _strip_html_tags(content)

        # Chọn indicators dựa trên loại injection
        indicators = self.unix_indicators if payload_info.injection_type == "unix" else self.windows_indicators

        # 1. Kiểm tra các indicators
        indicator_match = any(indicator in content for indicator in indicators)
        if indicator_match:
            return True

        # 2. Kiểm tra mức độ tương đồng với payload
        # Nếu payload được echo lại đúng nguyên bản hoặc chỉ khác chút ít
        payload_echoed = payload_info.payload.lower() in content
        if payload_echoed and _is_likely_command_output(content, payload_info.payload.lower()):
            return True

        # 3. Phân tích cấu trúc đầu ra dựa trên regex patterns
        if self._check_regex_patterns(content):
            return True

        # 4. Kiểm tra nếu output có dạng của kết quả lệnh
        if _has_command_output_structure(content):
            return True

        return False

    def _check_regex_patterns(self, content: str) -> bool:
        """Kiểm tra các regex patterns đặc trưng của output command"""
        import re
        for pattern in self.regex_patterns:
            if re.search(pattern, content):
                return True
        return False

