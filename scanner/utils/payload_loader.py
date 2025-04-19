import configparser

def load_all_payloads(file_path: str, section: str = None) -> list[dict]:
    config = configparser.ConfigParser()
    config.read(file_path, encoding="utf-8")

    payloads = []

    if section:
        sections = [section] if section in config else []
    else:
        sections = config.sections()

    for sec in sections:
        entry = dict(config[sec])
        entry["name"] = sec  # thêm tên section để tiện debug
        payloads.append(entry)

    return payloads
