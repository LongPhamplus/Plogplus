from dataclasses import dataclass


@dataclass
class PayloadInfo:
    name: str = ""
    payload: str = ""
    tag: str = ""
    value: str = ""
    case_sensitive: bool = True
    injection_type: str = ""
    delimiter: str = ""
    language: str = ""
    filename: str = ""
    content: str = ""
    mime_type: str = ""
    type: str = ""