from dataclasses import dataclass


@dataclass
class PayloadInfo:
    name: str = ""
    payload: str = ""
    tag: str = ""
    value: str = ""
    case_sensitive: bool = True