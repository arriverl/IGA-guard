"""XXE 分类与定位 — 含拆分 SYSTEM 绕过。"""

from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import quote

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.obfuscation_signals import xxe_rescue_label, xxe_structure_score
from iga_guard.collector.http_parser import parse_http_request
from iga_guard.pipeline import IgaGuardEngine, load_config

XXE_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-16BE"?> <!DOCTYPE r [ '
    '<!ENTITY % a "SYS"> <!ENTITY % b "TEM"> '
    '<!ENTITY % test %a;%b; "file:///etc/passwd"> ]> <r>&test;</r>'
)


def test_xxe_structure_score_high():
    assert xxe_structure_score(XXE_PAYLOAD) >= 0.55


def test_xxe_rescue_label():
    hit = xxe_rescue_label(XXE_PAYLOAD)
    assert hit is not None
    assert hit[0] == "XXE"
    assert hit[1] >= 0.78


def test_engine_classifies_xxe_not_sqli():
    engine = IgaGuardEngine(load_config(ROOT / "configs" / "default.yaml"))
    report = engine.analyze_url("GET", "http://x/?xml=" + quote(XXE_PAYLOAD))
    assert report.detection.is_malicious
    assert report.detection.label == "XXE"
    assert report.explanation is not None
    assert "file://" in report.explanation.malicious_span.lower() or "entity" in report.explanation.malicious_span.lower()


def test_engine_classifies_null_interleave_xxe():
    encoded = "".join(f"%00%{ord(ch):02x}" for ch in XXE_PAYLOAD)
    engine = IgaGuardEngine(load_config(ROOT / "configs" / "default.yaml"))
    report = engine.analyze_url("GET", f"http://demo/api/data?xml={encoded}")
    assert report.detection.is_malicious
    assert report.detection.label == "XXE"
    chain = report.normalized[0].decode_chain if report.normalized else []
    assert "null_interleave_strip" in chain or "url_decode" in chain


SVG_XXE_INNER = """<?xml version="1.0" encoding="UTF-8"?>
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


def test_multipart_svg_hex_xxe_upload():
    jpeg_head = b"\xff\xd8\xff\xdb".decode("latin-1")
    body = (
        "------WebKitFormBoundaryFullyObfuscated\r\n"
        'Content-Disposition: form-data; name="file"; filename="avatar.jpg"\r\n'
        "Content-Type: image/jpeg\r\n"
        "\r\n"
        f"{jpeg_head}{SVG_XXE_INNER}\r\n"
        "------WebKitFormBoundaryFullyObfuscated--\r\n"
    )
    engine = IgaGuardEngine(load_config(ROOT / "configs" / "default.yaml"))
    req = parse_http_request(
        method="POST",
        url="http://target.com/upload",
        body=body,
        headers={
            "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryFullyObfuscated",
        },
    )
    report = engine.analyze_request(req)
    assert report.detection.is_malicious
    assert report.detection.label == "XXE"
    mp_parts = [n for n in report.normalized if n.location == "multipart"]
    assert mp_parts, "multipart 字段应被展开"
    chain = mp_parts[0].decode_chain
    assert "upload_magic_strip" in chain or "xml_entity_expand" in chain
    assert xxe_structure_score(mp_parts[0].raw_payload, mp_parts[0].normalized_payload) >= 0.55
