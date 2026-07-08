"""HTTP request parsing from URL, logs, and API payloads."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from urllib.parse import parse_qs, unquote_plus, urlparse

from iga_guard.collector.protocol_normalize import iter_normalized_parts, protocol_anomaly_score
from iga_guard.models import HttpRequest


def parse_http_request(
    method: str = "GET",
    url: str = "",
    headers: dict[str, str] | None = None,
    body: str = "",
    *,
    source: str = "api",
) -> HttpRequest:
    return HttpRequest(
        method=method.upper(),
        url=url,
        headers=headers or {},
        body=body or "",
        cookies=_parse_cookies((headers or {}).get("Cookie", "")),
        source=source,
    )


def _parse_cookies(cookie_header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def iter_payload_parts(req: HttpRequest) -> list[tuple[str, str, str]]:
    """Yield (location, field_name, raw_value) from request."""
    parts: list[tuple[str, str, str]] = []

    parsed = urlparse(req.url)
    if parsed.query:
        for key, values in parse_qs(parsed.query, keep_blank_values=True).items():
            for val in values:
                parts.append(("query", key, val))

    if parsed.path:
        for segment in parsed.path.split("/"):
            if segment and _looks_like_payload(segment):
                parts.append(("path", "segment", unquote_plus(segment)))

    for key, val in req.headers.items():
        if key.lower() not in ("host", "user-agent", "accept", "connection"):
            parts.append(("header", key, val))

    for key, val in req.cookies.items():
        parts.append(("cookie", key, val))

    if req.body:
        parts.append(("body", "raw", req.body))
        if req.body.strip().startswith("{"):
            try:
                obj = json.loads(req.body)
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        parts.append(("json", k, str(v)))
            except json.JSONDecodeError:
                pass
        else:
            for key, values in parse_qs(req.body, keep_blank_values=True).items():
                for val in values:
                    parts.append(("form", key, val))

    # P1：WAFFLED 协议轨 — 深层 JSON / multipart / HPP 全值展开
    seen = {(loc, fld, val) for loc, fld, val in parts}
    for loc, fld, val in iter_normalized_parts(req):
        key = (loc, fld, val)
        if key not in seen:
            parts.append(key)
            seen.add(key)

    return parts


def protocol_score(req: HttpRequest) -> float:
    """请求级协议异常分（供融合检测加权）。"""
    return protocol_anomaly_score(req)


def _looks_like_payload(segment: str) -> bool:
    decoded = unquote_plus(segment)
    if len(decoded) < 3:
        return False
    suspicious = re.search(
        r"(union|select|script|alert|onerror|\.\./|etc/passwd|<|>|%27|%22)",
        decoded,
        re.I,
    )
    return bool(suspicious)


def load_csv_requests(path: str | Path) -> list[HttpRequest]:
    rows: list[HttpRequest] = []
    with open(path, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(
                HttpRequest(
                    method=row.get("method", "GET"),
                    url=row.get("url", ""),
                    body=row.get("body", ""),
                    source="csv",
                )
            )
    return rows
