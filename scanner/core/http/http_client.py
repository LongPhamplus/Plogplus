# scanner/core/http/http_client.py
from http.cookiejar import CookieJar
from typing import Union, Optional
from urllib.parse import urlparse

import httpx
import traceback


from scanner.core.http.request import Request
from scanner.core.http.response import Response
from scanner.utils import logger

class HttpClient:
    def __init__(self, time_out: int = 30):
        self._client = httpx.AsyncClient(timeout=time_out)
        self._timeout = time_out

    @property
    def cookies(self):
        return self._client.cookies  # Trả về cookies của session


    @property
    def client(self):
        return self._client

    def set_cookies(self, cookies: dict, url: str):
        parsed_url = urlparse(url)
        host = parsed_url.hostname

        # Truy cập CookieJar để xóa cookie trùng
        jar: CookieJar = self._client.cookies.jar
        to_remove = []

        for cookie in jar:
            if cookie.name in cookies:
                to_remove.append((cookie.domain, cookie.path, cookie.name))

        # Xóa các cookie trùng
        for domain, path, name in to_remove:
            jar.clear(domain, path, name)

        # Thêm cookies mới
        for name, value in cookies.items():
            self._client.cookies.set(name, value, domain=host)

        logger.log_info(f"Updated cookies: {self._client.cookies}")

    def set_client(self, client):
        self._client = client

    def reset_client(
            self,
            follow_redirects: bool = True,
            cookies: Optional[dict] = None,
    ):
        self._client = httpx.AsyncClient(
            follow_redirects=follow_redirects,
            cookies=cookies or {},
            timeout=self._timeout,
        )

    async def send(
            self,
            request: Request,
            allow_redirects: bool = True,

    ) -> Union[Response, None]:
        try:
            method = request.method.upper()

            if method == "GET":
                resp = await self._client.get(
                    url=request.base_url,
                    params=request.get_params,
                    follow_redirects=allow_redirects
                )

            elif method == "POST":
                enc_type = request.enc_type.lower()
                if not isinstance(request.post_data, (dict, str, bytes, list)):
                    logger.log_error(f"[ERROR] post_data không hợp lệ: {type(request.post_data)}")
                    return None

                if enc_type == "application/json":
                    # Gửi JSON object
                    resp = await self._client.post(
                        url=request.base_url,
                        json=request.post_data,
                        follow_redirects=allow_redirects
                    )

                elif enc_type == "multipart/form-data":
                    # Gửi multipart: file + form-data
                    resp = await self._client.post(
                        url=request.base_url,
                        headers=request.headers,
                        files=request.file_data,
                        data=request.post_data()
                    )

                else:  # application/x-www-form-urlencoded
                    # Gửi form thông thường
                    resp = await self._client.post(
                        url=request.base_url,
                        data=request.post_data,
                        follow_redirects=allow_redirects
                    )

            else:
                logger.log_warning(f"Method {method} không được hỗ trợ.")
                return None

            return Response(resp, url=str(resp.url))
        except httpx.HTTPError as e:
            method = request.method.upper()
            logger.log_error(f"HTTPException tại {request.base_url} với method {method}. Chi tiết lỗi: {e}")
            # logger.log_error(f"Chi tiết stack trace:\n{traceback.format_exc()}")
        except Exception as e:
            method = request.method.upper()
            # In ra chi tiết lỗi không phải HTTP
            logger.log_error(f"Lỗi không xác định khi gửi request tới {request.base_url} với method {method}. Lỗi: {e}")
            # logger.log_error(f"Chi tiết stack trace:\n{traceback.format_exc()}")
            return None


async def close(self):
        await self._client.aclose()
