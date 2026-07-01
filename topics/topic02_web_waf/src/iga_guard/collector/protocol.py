"""Multi-protocol HTTP request adapters."""

from __future__ import annotations

from iga_guard.collector.http_parser import parse_http_request
from iga_guard.models import HttpRequest


def parse_protocol_request(
    raw: str,
    protocol: str = "HTTP/1.1",
) -> HttpRequest:
    """Dispatch parser by protocol hint."""
    proto = protocol.upper()
    if proto in ("HTTP/2", "H2"):
        return _parse_http2_style(raw)
    if proto in ("HTTP/3", "QUIC"):
        return _parse_http3_log(raw)
    if proto in ("WEBSOCKET", "WS"):
        return _parse_websocket_frame(raw)
    return _parse_http1_raw(raw)


def _parse_http1_raw(raw: str) -> HttpRequest:
    lines = raw.strip().split("\n")
    if not lines:
        return parse_http_request()
    parts = lines[0].split()
    method = parts[0] if parts else "GET"
    url = parts[1] if len(parts) > 1 else ""
    headers: dict[str, str] = {}
    body = ""
    in_body = False
    for line in lines[1:]:
        if not in_body:
            if line.strip() == "":
                in_body = True
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        else:
            body += line + "\n"
    return parse_http_request(method=method, url=url, headers=headers, body=body.strip())


def _parse_http2_style(raw: str) -> HttpRequest:
    """Parse pseudo-JSON / log style HTTP/2 export."""
    import json

    try:
        obj = json.loads(raw)
        return HttpRequest(
            method=obj.get(":method", obj.get("method", "GET")),
            url=obj.get(":path", obj.get("url", "")),
            headers={k: str(v) for k, v in obj.get("headers", {}).items()},
            body=obj.get("body", ""),
            protocol="HTTP/2",
            source="http2",
        )
    except json.JSONDecodeError:
        req = _parse_http1_raw(raw)
        req.protocol = "HTTP/2"
        return req


def _parse_http3_log(raw: str) -> HttpRequest:
    req = _parse_http1_raw(raw)
    req.protocol = "HTTP/3"
    req.source = "quic"
    return req


def _parse_websocket_frame(raw: str) -> HttpRequest:
    return HttpRequest(
        method="WS",
        url="/websocket",
        body=raw,
        protocol="WebSocket",
        source="websocket",
    )
