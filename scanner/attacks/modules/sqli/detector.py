from scanner.attacks import Detector
from scanner.core.payload import PayloadInfo
from scanner.utils.logger import log_warning


class SQLIDetector(Detector):
    def __init__(self, delay_threshold: float = 5.0):
        """
        :param delay_threshold: thời gian tối thiểu để nghi ngờ delay base sqli
        """
        self.delay_threshold = delay_threshold

        # Signature lỗi cho SQLi error-based
        self.error_signatures = {
            "MySQL": [
                "you have an error in your sql syntax",
                "warning: mysql",
                "mysql_fetch",
                "unknown column",
                "mysql_num_rows()",
                "supplied argument is not a valid mysql"
            ],
            "PostgreSQL": [
                "pg_query():",
                "pg_fetch_array()",
                "syntax error at or near",
                "unterminated quoted string at or near"
            ],
            "MSSQL": [
                "unclosed quotation mark after the character string",
                "microsoft oledb",
                "microsoft sql server",
                "incorrect syntax near"
            ],
            "Oracle": [
                "ora-01756",
                "ora-00933",
                "ora-00936",
                "ora-00921",
                "quoted string not properly terminated"
            ]
        }

        # Signature đặc trưng khi thông tin bị tiết lộ
        self.info_signatures = {
            "MySQL": ["mysql", "version()", "@localhost", "user()"],
            "PostgreSQL": ["postgresql", "version()", "pg_", "postgres"],
            "MSSQL": ["microsoft sql server", "db_name", "master", "sa"],
            "Oracle": ["oracle", "dual", "sys", "dbms_", "session_user", "sys_context"]
        }

    async def detect(
            self,
            response,
            payload_info: PayloadInfo
    ) -> bool:
        """
        Phát hiện SQL Injection dựa trên lỗi hoặc thông tin bị lộ.

        Args:
            response: Đối tượng Response từ HTTPClient
            payload_info: Payload đã được gửi đi

        Returns:
            bool: True nếu nghi ngờ có SQLi
        """
        content = response.text.lower()

        # Kiểm tra lỗi SQLi
        for dbms, keywords in self.error_signatures.items():
            for keyword in keywords:
                if keyword in content:
                    # log_warning(f"[!] Possible SQLi detected via error message: {dbms}")
                    return True

        # Kiểm tra thông tin bị lộ (e.g., version, user)
        for dbms, indicators in self.info_signatures.items():
            for indicator in indicators:
                if indicator in content:
                    # log_warning(f"[!] Possible SQLi detected via info disclosure: {dbms}")
                    return True

        return False
