"""WAFFLED 风格协议规范化：HPP / 深层 JSON / multipart 展开 + 协议异常分。"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, unquote_plus

from iga_guard.models import HttpRequest


def expand_hpp_pairs(raw_query: str) -> list[tuple[str, str]]:
    """保留重复键全部取值（HPP 双值解析）。"""
    if not raw_query:
        return []
    pairs: list[tuple[str, str]] = []
    for key, val in parse_qsl(raw_query, keep_blank_values=True):
        pairs.append((key, val))
    # 原始 & 切分兜底（应对未规范编码）
    if not pairs and "&" in raw_query:
        for chunk in raw_query.split("&"):
            if "=" in chunk:
                k, v = chunk.split("=", 1)
                pairs.append((unquote_plus(k), unquote_plus(v)))
            elif chunk:
                pairs.append(("", unquote_plus(chunk)))
    return pairs


def flatten_json(obj: Any, prefix: str = "") -> list[tuple[str, str]]:
    """深层 JSON 键展开为 (dotted.path, str_value)。"""
    out: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            out.extend(flatten_json(v, path))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            path = f"{prefix}[{i}]"
            out.extend(flatten_json(v, path))
    else:
        out.append((prefix or "value", str(obj)))
    return out


def parse_multipart(body: str, content_type: str = "") -> list[tuple[str, str]]:
    """模拟 multipart 边界解析，提取各 part 字段。"""
    boundary = ""
    m = re.search(r"boundary=([^\s;]+)", content_type, re.I)
    if m:
        boundary = m.group(1).strip('"')
    if not boundary:
        m = re.search(r"(-{2,}WebKitFormBoundary[\w-]+)", body)
        if m:
            boundary = m.group(1).lstrip("-")
    if not boundary:
        return []
    # RFC：part 分隔符为 -- + boundary（header 中的 boundary 值本身可含前导 -）
    core = boundary.lstrip("-")
    delim = f"--{core}"
    parts: list[tuple[str, str]] = []
    for chunk in body.split(delim):
        chunk = chunk.strip("\r\n-")
        if not chunk or chunk in ("--", ""):
            continue
        name_m = re.search(r'name="([^"]+)"', chunk, re.I)
        if not name_m:
            continue
        name = name_m.group(1)
        if "\r\n\r\n" in chunk:
            val = chunk.split("\r\n\r\n", 1)[1].strip()
        elif "\n\n" in chunk:
            val = chunk.split("\n\n", 1)[1].strip()
        else:
            val = chunk
        parts.append((name, val))
    return parts


def iter_normalized_parts(req: HttpRequest) -> list[tuple[str, str, str]]:
    """协议规范化后的 (location, field, value) 列表，供检测管线合并。"""
    from urllib.parse import urlparse

    parts: list[tuple[str, str, str]] = []
    parsed = urlparse(req.url)

    if parsed.query:
        for key, val in expand_hpp_pairs(parsed.query):
            parts.append(("query", key or "hpp", val))

    ct = ""
    for hk, hv in req.headers.items():
        if hk.lower() == "content-type":
            ct = hv
            break

    if req.body:
        body = req.body
        parts.append(("body", "raw", body))
        stripped = body.strip()
        if stripped.startswith("{"):
            try:
                obj = json.loads(body)
                for path, val in flatten_json(obj):
                    parts.append(("json", path, val))
            except json.JSONDecodeError:
                pass
        elif "multipart" in ct.lower() or "WebKitFormBoundary" in body:
            for name, val in parse_multipart(body, ct):
                parts.append(("multipart", name, val))
        else:
            for key, val in expand_hpp_pairs(body):
                parts.append(("form", key or "field", val))

    return parts


def protocol_anomaly_score(req: HttpRequest) -> float:
    """协议层异常分（0~1）：HPP 冲突、JSON 嵌套、multipart 边界模拟。"""
    score = 0.0
    from urllib.parse import urlparse

    parsed = urlparse(req.url)
    if parsed.query:
        keys = [k for k, _ in expand_hpp_pairs(parsed.query)]
        if len(keys) != len(set(keys)):
            score = max(score, 0.35)

    if req.body:
        if req.body.strip().startswith("{"):
            try:
                obj = json.loads(req.body)
                flat = flatten_json(obj)
                if any("." in p or "[" in p for p, _ in flat):
                    score = max(score, 0.25)
                if len(flat) > 3:
                    score = max(score, 0.15)
            except json.JSONDecodeError:
                score = max(score, 0.2)
        if "WebKitFormBoundary" in req.body or "multipart" in (
            req.headers.get("Content-Type", "") + req.headers.get("content-type", "")
        ).lower():
            score = max(score, 0.3)

    return min(score, 1.0)
