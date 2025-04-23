from typing import List, Tuple

from scanner.core.http import Request
from scanner.core.payload import PayloadInfo

PayloadSource = List[PayloadInfo] # Union[List[PayloadInfo], CallBackPayload] trong trường hợp cải tiến bằng callback domain

submit_names = [
    "submit", "Submit", "btnSubmit", "btnSave", "btnSend", "btnOK", "btnLogin", "login", "signIn", "btnUpload",
    "upload", "Upload", "submitBtn", "send", "Send", "next", "Next", "confirm", "Confirm", "continue", "Continue",
    "ok", "OK", "go", "Go", "doLogin", "doSubmit", "doSend", "save", "Save", "Login", "loginBtn",
]

hidden_names = [
    "__VIEWSTATE", "__EVENTVALIDATION", "__VIEWSTATEGENERATOR", "_csrf", "csrf_token", "authenticity_token",
    "token", "nonce", "sessionid", "sid", "form_build_id", "form_token", "form_id", "_token", "_wpnonce",
    "redirect", "hiddenField", "page_token", "state", "formHash", "dataToken"
]

def inject_payload_into_params(get_params, payload_info):
    """
    Tiêm payload vào các tham số GET, bỏ qua các trường có name nằm trong submit_names hoặc hidden_names.
    """
    mutated_params = []

    if isinstance(get_params, dict):
        get_params = [[k, v] for k, v in get_params.items()]

    for param in get_params:
        if isinstance(param, dict):
            param_name = param.get("name")
            param_value = param.get("value", "")
        elif isinstance(param, (list, tuple)) and len(param) == 2:
            param_name, param_value = param
        else:
            print(f"[!] Bỏ qua param không hợp lệ: {param}")
            continue

        # Không tiêm nếu nằm trong danh sách đặc biệt
        if param_name in submit_names or param_name in hidden_names:
            mutated_params.append([param_name, param_value])
        else:
            mutated_value = payload_info.payload if payload_info.payload else param_value
            mutated_params.append([param_name, mutated_value])

    return mutated_params


def inject_payload_into_post_data(post_data, payload_info):
    """
    Hàm này sẽ tiêm payload vào các tham số POST dạng dict.
    """
    mutated_data = {}

    # Kiểm tra các tham số hiện có và tiêm payload vào
    for param_name, param_value in post_data.items():
        if payload_info.payload:
            param_value = payload_info.payload

        mutated_data[param_name] = param_value

    return mutated_data

def inject_payload_into_file_data(file_param, payload_info):
    mutated_data = {}
    for param_name, param_value in file_param.items():
        if payload_info.payload:
            param_value = (payload_info.filename, payload_info.content, payload_info.mime_type)

        mutated_data[param_name] = param_value
    return mutated_data

class Mutator:

    @staticmethod
    def mutate(
            request: Request,
            payload: PayloadSource
    ) -> List[Tuple[Request, PayloadInfo]]:
        mutated_request = []

        # Ensure the payload is a list
        if not isinstance(payload, list):
            return mutated_request

        # Loop over each payload_info
        for payload_info in payload:
            if isinstance(payload_info, dict):
                payload_info = PayloadInfo(**payload_info)
            mutated_params = inject_payload_into_params(request.get_params, payload_info)
            mutated_data = inject_payload_into_post_data(request.post_data, payload_info)
            mutated_file = inject_payload_into_file_data(request.file_params, payload_info)
            if request.method == "GET":
                evil_request = Request(
                    url=request.base_url,
                    method=request.method,
                    get_params=mutated_params,
                )
            else:
                if request.enc_type == "multipart/form-data":
                    evil_request = Request(
                        url=request.base_url,
                        method=request.method,
                        file_params=mutated_file,
                        post_params=mutated_data,
                    )
                else:
                    evil_request = Request(
                        url=request.base_url,
                        method=request.method,
                        post_params=mutated_data,
                    )
            # Append both the mutated request and payload_info as a tuple
            mutated_request.append((evil_request, payload_info))

        return mutated_request