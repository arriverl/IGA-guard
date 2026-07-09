#!/usr/bin/env python3
"""POST multipart XXE 上传样本 — 调用本地 /api/detect（Windows 友好）。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import urllib.request
except ImportError:
    sys.exit("需要 Python 3")

ROOT = Path(__file__).resolve().parents[1]

jpeg_head = b"\xff\xd8\xff\xdb".decode("latin-1")
file_content = jpeg_head + """  <!-- JPG Magic Bytes -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
    <!ENTITY % local SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
    <!ENTITY % condition '
        <!ENTITY &#x25; target &#x53;&#x59;&#x53;&#x54;&#x45;&#x4d; "&#x66;&#x69;&#x6c;&#x65;&#x3a;&#x2f;&#x2f;&#x2f;etc/passwd">
        <!ENTITY &#x25; error "<!ENTITY &#x25; non_exist &#x53;&#x59;&#x53;&#x54;&#x45;&#x4d; &#x27;&#x66;&#x69;&#x6c;&#x65;&#x3a;&#x2f;&#x2f;&#x2f;invalid/&#x25;target;&#x27;>">
        &#x25;error;
        &#x25;non_exist;
    '>
    %local;
]>
<svg width="1" height="1" xmlns="http://www.w3.org/2000/svg"></svg>"""

MULTIPART_BODY = (
    "------WebKitFormBoundaryFullyObfuscated\r\n"
    'Content-Disposition: form-data; name="file"; filename="avatar.jpg"\r\n'
    "Content-Type: image/jpeg\r\n"
    "\r\n"
    + file_content
    + "\r\n"
    "------WebKitFormBoundaryFullyObfuscated--\r\n"
)

PAYLOAD = {
    "method": "POST",
    "url": "http://target.com/upload",
    "headers": {
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryFullyObfuscated",
    },
    "body": MULTIPART_BODY,
}


def main() -> None:
    api = "http://127.0.0.1:5000/api/detect"
    data = json.dumps(PAYLOAD, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        api,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    print(f"POST {api}")
    print("---")
    with urllib.request.urlopen(req, timeout=120) as resp:
        out = json.loads(resp.read().decode("utf-8"))
    det = out.get("detection", {})
    print(f"判定: {det.get('label')} · {det.get('confidence', 0):.1%} · {det.get('risk_level')}")
    for n in out.get("normalized", []):
        if n.get("location") == "multipart":
            print(f"字段: {n.get('field')} · decode_chain: {n.get('decode_chain')}")
    if out.get("explanation"):
        e = out["explanation"]
        print(f"片段: {e.get('malicious_span')}")
        print(f"解释: {e.get('natural_language')}")
    print("---")
    # 避免 Windows 控制台 GBK 无法打印 JPEG 二进制
    safe = {k: v for k, v in out.items() if k != "normalized"}
    safe["normalized"] = [
        {**n, "raw": "[binary omitted]", "normalized": (n.get("normalized") or "")[:200]}
        for n in out.get("normalized", [])
    ]
    print(json.dumps(safe, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
