# reports/html_report.py
import os
import html

from scanner.reports.report import Report

class HTMLReport(Report):
    def __init__(self, title="Vulnerability Scan Report"):
        self.entries = []
        self.title = title

    def add_entry(self, vuln_type, url, param, payload, evidence):
        self.entries.append({
            "type": vuln_type,
            "url": url,
            "param": param,
            "payload": payload,
            "evidence": evidence
        })

    def generate(self):
        result_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{self.title}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
        }}
        h1 {{
            text-align: center;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th, td {{
            border: 1px solid #ccc;
            padding: 10px;
            text-align: left;
        }}
        th {{
            background-color: #333;
            color: #fff;
        }}
        tr:nth-child(even) {{
            background-color: #eee;
        }}
        .type {{
            font-weight: bold;
            color: #d9534f;
        }}
        .payload {{
            font-family: monospace;
            color: #5bc0de;
        }}
    </style>
</head>
<body>
    <h1>{self.title}</h1>
    <table>
        <thead>
            <tr>
                <th>Vulnerability Type</th>
                <th>URL</th>
                <th>Parameter</th>
                <th>Payload</th>
                <th>Evidence</th>
            </tr>
        </thead>
        <tbody>
"""
        for entry in self.entries:
            if isinstance(entry['payload'], dict):
                payload = entry['payload']
            else:
                payload = entry['payload'].payload
            result_html += f"""
                    <tr>
                        <td class="type">{html.escape(str(entry['type']))}</td>
                        <td>{html.escape(str(entry['url']))}</td>
                        <td>{html.escape(str(entry['param']))}</td>
                        <td class="payload">{html.escape(str(payload))}</td>
                        <td>{html.escape(str(entry['evidence']))}</td>
                    </tr>
                """

        result_html += """
        </tbody>
    </table>
</body>
</html>
"""
        return result_html

    def save(self, filepath):
        dir_path = os.path.dirname(filepath)
        if dir_path:  # Chỉ tạo thư mục nếu có
            os.makedirs(dir_path, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.generate())
