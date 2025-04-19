import re
from scanner.utils import logger
from scanner.core.http.response import Response


def extract_csrf_token(html: str) -> str:
    """
    Trích xuất CSRF token từ HTML.
    Tìm thẻ <input> có name là 'user_token' và lấy giá trị của thuộc tính value.
    """
    try:
        match = re.search(r'<input[^>]+name=["\']user_token["\'][^>]+value=["\']([^"\']+)["\']', html)
        if match:
            return match.group(1)
    except Exception as e:
        logger.log_error(f"[extract_csrf_token] Lỗi khi trích xuất CSRF token: {e}")
    return ""


def extract_jwt_from_response(response: Response) -> str:
    """
    Trích xuất JWT token từ response (ưu tiên từ JSON body, sau đó là từ header).
    """
    # 1. Trích xuất từ JSON body
    try:
        json_data = response.json  # đây là thuộc tính đã parse sẵn
        for key in ["token", "access_token", "jwt"]:
            if key in json_data:
                return json_data[key]
    except Exception as e:
        logger.log_error(f"[extract_jwt_from_response] Lỗi khi đọc JSON từ phản hồi: {e}")

    # 2. Trích xuất từ Authorization header
    auth_header = response.headers.get("Authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()

    return ""
