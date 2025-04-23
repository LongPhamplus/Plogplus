import configparser

from scanner.core.payload import PayloadInfo


def load_all_payloads(file_path: str, section: str = None) -> list[PayloadInfo]:
    config = configparser.RawConfigParser()
    config.read(file_path, encoding="utf-8")

    payloads = []

    if section:
        sections = [section] if section in config else []
    else:
        sections = config.sections()

    for sec in sections:
        entry = dict(config.items(sec, raw=True))
        entry["name"] = sec  # thêm tên section để tiện debug
        payload_info = PayloadInfo(**entry)
        payload_info.payload += ' '
        payloads.append(payload_info)

    return payloads
