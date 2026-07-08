"""评测 / 红队共用 HTTP 传输层（OWASP HPP 安全）。

含 ``&``、换行或超长载荷必须走 POST body，避免 query 被 parse_qs 截断。
参考: OWASP WSTG HTTP Parameter Pollution、Imperva HPP 缓解（统一解析语义）。
"""

from __future__ import annotations

from urllib.parse import quote


def build_eval_request(
    payload: str,
    *,
    base_url: str = "http://eval.local/test",
) -> tuple[str, str, str]:
    """构造 (method, url, body) 三元组。"""
    if "&" in payload or "\n" in payload or "\r" in payload or len(payload) > 1800:
        return "POST", base_url, payload
    return "GET", f"{base_url}?p={quote(payload, safe='')}", ""


def build_http_request(payload: str, *, base_url: str = "http://eval.local/test"):
    """从 payload 构造 HttpRequest（供 log_failure / analyze_request）。"""
    from iga_guard.collector.http_parser import parse_http_request

    method, url, body = build_eval_request(payload, base_url=base_url)
    return parse_http_request(method=method, url=url, body=body)
