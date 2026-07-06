"""P1 协议规范化轨单元测试。"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.collector.http_parser import iter_payload_parts, protocol_score  # noqa: E402
from iga_guard.collector.protocol_normalize import flatten_json, parse_multipart  # noqa: E402
from iga_guard.collector.http_parser import parse_http_request  # noqa: E402


class TestProtocolNormalize:
    def test_hpp_duplicate_params(self):
        req = parse_http_request(
            "GET",
            "http://x.test/?id=1&id=merry@mcrspain.gg",
        )
        parts = iter_payload_parts(req)
        values = [v for _, _, v in parts if "mcrspain" in v]
        assert values, "HPP 恶意值应被展开"

    def test_json_deep_flatten(self):
        flat = flatten_json({"user": {"profile": {"name": "<script>"}}})
        paths = [p for p, _ in flat]
        assert any("profile" in p for p in paths)

    def test_multipart_boundary(self):
        body = (
            '------WebKitFormBoundary\r\n'
            'Content-Disposition: form-data; name="modo"\r\n\r\n'
            'login\r\n'
            '------WebKitFormBoundary--'
        )
        parts = parse_multipart(body)
        assert any(n == "modo" for n, _ in parts)

    def test_protocol_score_hpp(self):
        req = parse_http_request("GET", "http://x.test/?a=1&a=2&b=evil")
        assert protocol_score(req) >= 0.3
