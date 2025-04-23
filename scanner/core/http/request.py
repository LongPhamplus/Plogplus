from copy import deepcopy
from urllib.parse import urlparse, urlunparse, parse_qsl


class Request:
    def __init__(
            self,
            url,
            method: str = "GET",
            get_params=None,
            post_params=None,
            file_params=None,
            enc_type: str = "",
            headers: dict = None,
    ):
        """ Tạo ra 1 lớp request mới

            url: Đường dẫn của trang web
            method: Phương thức được sử dụng
            get_params: Các tham số của get dạng 1 líst "key": "value"
            post_params: Tương tự get
            file_params: Tương tự get nhưng ở dạng tuples (file_name, file_content)
        """

        url_parts = urlparse(url)
        try:
            port = url_parts.port
        except ValueError:
            port = None

        if (
                (url_parts.scheme == "http" and port == 80) or
                (url_parts.scheme == "https" and port == 443)
        ):
            # <scheme>://<netloc>/<path>;<params>?<query>#<fragment>
            url_parts = url_parts._replace(netloc=url_parts.netloc.rsplit(":", 1)[0])

        self._resource_path = urlunparse(
            (url_parts.scheme, url_parts.netloc, url_parts.path, url_parts.params, '', ''))

        if not method:
            if post_params or file_params:
                self._method = "POST"
            else:
                self._method = "GET"
        else:
            self._method = method

        self._enc_type = ""
        if self._method in ["POST", "PUT", "PATCH"]:
            if enc_type:
                self._enc_type = enc_type.lower().strip()
            else:
                if file_params:
                    self._enc_type = "multipart/form-data"
                else:
                    self._enc_type = "application/x-www-form-urlencoded"

        # --- GET params ---
        if not get_params:
            self._get_params = {}
            if url_parts.query:
                self._get_params = dict(parse_qsl(url_parts.query))
        else:
            if isinstance(get_params, dict):
                self._get_params = deepcopy(get_params)
            else:
                # fallback nếu là list kiểu [["key", "value"]]
                self._get_params = dict(get_params)

        # --- POST params ---
        if not post_params:
            self._post_params = {}
        elif isinstance(post_params, dict):
            self._post_params = deepcopy(post_params)
        elif isinstance(post_params, str):
            if "urlencoded" in self._enc_type or self.is_multipart:
                self._post_params = {}
                if post_params:
                    for post_param in post_params.split("&"):
                        if "=" in post_param:
                            key, value = post_param.split("=", 1)
                            self._post_params[key] = value
                        else:
                            self._post_params[post_param] = None
            else:
                # JSON, XML hoặc body text thuần
                self._post_params = post_params
        else:
            # các kiểu dữ liệu khác
            self._post_params = post_params

        if not file_params:
            self._file_params = {}
        else:
            if isinstance(file_params, dict):
                self._file_params = deepcopy(file_params)
            else:
                # Nếu là list hoặc tuple dạng [(key, value)] thì chuyển thành dict
                try:
                    self._file_params = dict(file_params)
                except Exception:
                    # Nếu không chuyển được, log lại hoặc gán rỗng để tránh lỗi
                    self._file_params = {}

        self._hostname = url_parts.hostname
        self._scheme = url_parts.scheme or ""
        self._netloc = url_parts.netloc
        self._headers = headers


    @property
    def headers(self):
        return self._headers

    @property
    def is_multipart(self):
        return self._enc_type == "multipart/form-data"

    @property
    def method(self):
        return deepcopy(self._method)

    @property
    def base_url(self):
        return deepcopy(self._resource_path)

    @property
    def get_params(self):
        return deepcopy(self._get_params)

    @property
    def post_data(self):
        return deepcopy(self._post_params)

    @property
    def file_params(self):
        return deepcopy(self._file_params)

    @property
    def enc_type(self):
        return deepcopy(self._enc_type)

