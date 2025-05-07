import re
import posixpath
from urllib.parse import urljoin, urlparse

from scanner.attacks import Detector
from scanner.core.http import Request
from scanner.core.payload import PayloadInfo
from scanner.core.http.http_client import HttpClient  # Hoặc bạn tự dùng httpx.get(
from scanner.utils.logger import log_warning, log_info, log_success


def get_file_path(response, payload_info: PayloadInfo):
    response_text = response.text
    filename = re.escape(payload_info.filename)
    pattern = rf'((?:\.\./)+[^\s"]*{filename})'
    match = re.search(pattern, response_text)
    if match:
        # Nếu có match, ta lấy được đường dẫn file
        file_path = match.group(1)  # Đoạn đường dẫn đến file
        log_info(f"File đã được upload tại: {file_path}")

        # Xử lý hoặc trả về thông tin về đường dẫn này
        return file_path
    else:
        # log_warning("Không tìm thấy đường dẫn mà file được upload.")
        return None

def normalize(base_url, relative_path):
    # Phân tích URL gốc
    parsed = urlparse(base_url)
    # Ghép phần path lại với relative path bằng posixpath
    base_path = parsed.path
    new_path = posixpath.normpath(posixpath.join(base_path, relative_path))
    final_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"

    return final_url


class UploadDetector(Detector):
    def __init__(self):
        self.http_client = HttpClient()

    async def detect(
            self,
            response,
            payload_info: PayloadInfo
    ):

        file_path = get_file_path(response, payload_info)

        if not file_path:
            return None

        upload_path = normalize(response.url, file_path)

        req = Request(
            url=upload_path,
            get_params={"cmd": "echo 'Plogplus inject successful'"},
        )
        file_response = await self.http_client.send(req)

        if payload_info.type == "detect":
            # Gửi yêu cầu GET đến file vừa upload để kiểm tra giá trị detect
            try:

                if (payload_info.value in file_response.text) and (payload_info.payload not in file_response.text):
                    # Cần kiểm tra thêm các trường hợp tải file html, svg bởi sẽ upload để khai thác xss
                    return True
                else:
                    return False
            except Exception as e:
                log_warning(f"Lỗi khi kiểm tra file đã upload: {e}")
                return False

        elif payload_info.type == "exploit":

            if "Plogplus inject successful" in file_response.text:
                return True
            # Có thể trả về đường dẫn để người dùng tự kiểm thử
            return False

        else:
            log_warning("[!] Loại payload không xác định")
            return None
