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


def load_credentials(user_path: str, pass_path: str) -> list[dict]:
    """
    Tải danh sách username và password từ 2 file,
    trả về danh sách dict: {"username": ..., "password": ...}
    """
    def load_lines(path):
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]

    usernames = load_lines(user_path)
    passwords = load_lines(pass_path)

    creds = []
    for username in usernames:
        for password in passwords:
            creds.append({
                "username": username,
                "password": password
            })

    return creds
