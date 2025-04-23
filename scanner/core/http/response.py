import httpx
from typing import Optional, List

class Response:
    def __init__(
        self,
        response: httpx.Response,
        url: Optional[str] = None
    ):
        self._response = response
        self._url = url or str(self._response.url)
        self._json_data = None

    @property
    def elapsed(self):
        return self._response.elapsed

    @property
    def raw_response(self):
        return self._response

    @property
    def cookies(self):
        return self._response.cookies

    @property
    def json(self):
        if self._json_data is None:
            try:
                self._json_data = self._response.json()
            except Exception:
                self._json_data = None
        return self._json_data

    @property
    def history(self) -> List["Response"]:
        return [Response(response) for response in self._response.history]

    @property
    def headers(self):
        return self._response.headers

    @property
    def status_code(self):
        return self._response.status_code

    @property
    def text(self):
        return self._response.text

    def contains(self, string: str) -> bool:
        return string in self._response.text

    @property
    def url(self) -> str:
        return self._url
