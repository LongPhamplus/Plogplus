# scanner/core/http/http_client.py

from typing import Union, Optional
import httpx

from scanner.core.http.request import Request
from scanner.core.http.response import Response
from scanner.utils import logger

class HttpClient:
    def __init__(self, time_out: int = 10):
        self._client = httpx.AsyncClient(timeout=time_out)
        self._timeout = time_out

    @property
    def cookies(self):
        return self._client.cookies  # Trả về cookies của session


    @property
    def client(self):
        return self._client

    def set_cookies(self, cookies: dict):
        self._client.cookies.update(cookies)  # Cập nhật cookies

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

                if enc_type == "application/json":
                    # Gửi JSON object
                    resp = await self._client.post(
                        url=request.base_url,
                        json=request.post_data,
                        follow_redirects=allow_redirects
                    )

                # elif enc_type == "multipart/form-data":
                #     # Gửi multipart: file + form-data
                #     resp = await self._client.post(
                #         url=request.get_base_url,
                #         headers=request.get_headers,
                #         cookies=request.get_cookies,
                #         files=request.get_file_data(),
                #         data=request.get_post_data_as_dict()
                #     )

                else:  # application/x-www-form-urlencoded
                    # Gửi form thông thường
                    resp = await self._client.post(
                        url=request.base_url,
                        data=request.post_data,
                        follow_redirects=allow_redirects
                    )

            else:
                logger.log_warning(f"[WARN] Method {method} không được hỗ trợ.")
                return None

            return Response(resp, url=str(resp.url))
        except httpx.HTTPError as e:
            method = request.method.upper()
            logger.log_error(f"[ERROR] HTTPException tại {request.base_url} với method {method}. Chi tiết lỗi: {e}")
        except Exception as e:
            method = request.method.upper()
            logger.log_error(f"[ERROR] Lỗi không xác định khi gửi request tới {request.base_url} với method {method}. Lỗi: {e}")
            return None

    async def close(self):
        await self._client.aclose()
