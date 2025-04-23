import re

from scanner.attacks import Detector
from scanner.core.payload import PayloadInfo
from scanner.utils.logger import log_warning


def get_file_path(response, payload_info: PayloadInfo):
    response_text = response.text
    filename = re.escape(payload_info.filename)
    pattern = rf'((?:\.\./)+[^\s"]*{filename})'
    match = re.search(pattern, response_text)
    if match:
        # Nếu có match, ta lấy được đường dẫn file
        file_path = match.group(1)  # Đoạn đường dẫn đến file
        print(f"File uploaded to: {file_path}")

        # Xử lý hoặc trả về thông tin về đường dẫn này
        return file_path
    else:
        print("No file path found in the response.")
        return None

class UploadDetector(Detector):
    def __init__(self):
        pass

    def detect(
            self,
            response,
            payload_info: PayloadInfo
    ):

        file_path = get_file_path(response, payload_info)
