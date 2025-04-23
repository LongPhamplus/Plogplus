from typing import Union, List, Tuple

from scanner.core.http import Request
from scanner.core.payload import PayloadInfo

PayloadSource = List[PayloadInfo] # Union[List[PayloadInfo], CallBackPayload] trong trường hợp cải tiến bằng callback domain


def inject_payload_into_params(get_params, payload_info):
    """
    Hàm này sẽ tiêm payload vào các tham số GET
    """
    mutated_params = []
    # Kiểm tra các tham số hiện có và tiêm payload vào
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

        if payload_info.payload:
            param_value = payload_info.payload
        mutated_params.append([param_name, param_value])

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
            evil_request = Request(
                url=request.base_url,
                method=request.method,
                get_params=mutated_params,
                post_params=mutated_data,
            )
            # Append both the mutated request and payload_info as a tuple
            mutated_request.append((evil_request, payload_info))

        return mutated_request