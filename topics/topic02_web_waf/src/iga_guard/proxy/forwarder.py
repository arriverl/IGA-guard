"""Inline WAF proxy: inspect real HTTP, block or forward to upstream."""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from flask import Response, request as flask_request

from iga_guard.collector.http_parser import parse_http_request
from iga_guard.models import HttpRequest
from iga_guard.pipeline import IgaGuardEngine

logger = logging.getLogger("iga_guard.proxy")

_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
})


@dataclass
class ProxyConfig:
    mode: str = "inline"
    upstream_url: str = "http://127.0.0.1:3000"
    block_on_malicious: bool = True
    block_status: int = 403
    forward_timeout_s: int = 30
    max_body_bytes: int = 1_048_576
    trust_x_forwarded: bool = True
    strip_request_headers: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    api_mirror_url: str = ""
    log_blocks: bool = True

    @classmethod
    def from_dict(cls, raw: dict) -> ProxyConfig:
        return cls(
            mode=str(raw.get("mode", "inline")),
            upstream_url=str(raw.get("upstream_url", "http://127.0.0.1:3000")).rstrip("/"),
            block_on_malicious=bool(raw.get("block_on_malicious", True)),
            block_status=int(raw.get("block_status", 403)),
            forward_timeout_s=int(raw.get("forward_timeout_s", 30)),
            max_body_bytes=int(raw.get("max_body_bytes", 1_048_576)),
            trust_x_forwarded=bool(raw.get("trust_x_forwarded", True)),
            strip_request_headers=[h.lower() for h in raw.get("strip_request_headers", [])],
            exclude_paths=list(raw.get("exclude_paths", [])),
            api_mirror_url=str(raw.get("api_mirror_url", "")),
            log_blocks=bool(raw.get("log_blocks", True)),
        )


def from_flask_request(req, *, trust_x_forwarded: bool = True) -> HttpRequest:
    """将 Flask/Werkzeug 请求转为 HttpRequest（含 X-Forwarded-*）。"""
    headers = {k: v for k, v in req.headers.items()}
    if trust_x_forwarded:
        if req.headers.get("X-Forwarded-For"):
            headers["X-Forwarded-For"] = req.headers.get("X-Forwarded-For")
        if req.headers.get("X-Real-IP"):
            headers["X-Real-IP"] = req.headers.get("X-Real-IP")

    scheme = req.headers.get("X-Forwarded-Proto", req.scheme)
    host = req.headers.get("X-Forwarded-Host") or req.host
    query = req.query_string.decode("utf-8", errors="replace") if req.query_string else ""
    path = req.path or "/"
    url = f"{scheme}://{host}{path}"
    if query:
        url = f"{url}?{query}"

    body = req.get_data(as_text=True) if req.method not in ("GET", "HEAD") else ""
    return parse_http_request(
        method=req.method,
        url=url,
        headers=headers,
        body=body,
        source="proxy",
    )


class TrafficForwarder:
    """检测 → 阻断或转发 upstream。"""

    def __init__(self, engine: IgaGuardEngine, config: ProxyConfig) -> None:
        self.engine = engine
        self.config = config
        self._block_count = 0
        self._forward_count = 0
        self._lock = threading.Lock()

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "mode": self.config.mode,
                "upstream": self.config.upstream_url,
                "blocks": self._block_count,
                "forwards": self._forward_count,
            }

    def is_excluded(self, path: str) -> bool:
        for prefix in self.config.exclude_paths:
            if path.startswith(prefix):
                return True
        return False

    def handle(self, req=None) -> Response:
        req = req or flask_request
        if self.is_excluded(req.path):
            return self._forward_only(req)

        http_req = from_flask_request(req, trust_x_forwarded=self.config.trust_x_forwarded)
        report = self.engine.analyze_request(http_req, explain=False)

        if self.config.mode == "mirror":
            self._mirror_async(http_req, report.to_dict())
            return self._forward_upstream(req)

        if (
            self.config.mode == "inline"
            and self.config.block_on_malicious
            and report.detection.is_malicious
        ):
            with self._lock:
                self._block_count += 1
            if self.config.log_blocks:
                logger.warning(
                    "blocked %s %s label=%s conf=%.3f",
                    http_req.method, http_req.url,
                    report.detection.label, report.detection.confidence,
                )
            return self._block_response(report.to_dict())

        with self._lock:
            self._forward_count += 1
        return self._forward_upstream(req)

    def _block_response(self, report: dict) -> Response:
        det = report.get("detection", {})
        body = {
            "blocked": True,
            "service": "IGA-Guard",
            "label": det.get("label"),
            "confidence": det.get("confidence"),
            "risk_level": det.get("risk_level"),
            "message": "Request blocked by IGA-Guard WAF",
        }
        return Response(
            json.dumps(body, ensure_ascii=False),
            status=self.config.block_status,
            mimetype="application/json",
        )

    def _forward_only(self, req) -> Response:
        with self._lock:
            self._forward_count += 1
        return self._forward_upstream(req)

    def _build_upstream_url(self, req) -> str:
        base = self.config.upstream_url.rstrip("/")
        path = req.path or "/"
        query = req.query_string.decode("utf-8", errors="replace") if req.query_string else ""
        target = urljoin(base + "/", path.lstrip("/"))
        if query:
            target = f"{target}?{query}"
        return target

    def _filtered_headers(self, req) -> dict[str, str]:
        skip = set(self.config.strip_request_headers) | _HOP_BY_HOP
        out: dict[str, str] = {}
        upstream_host = urlparse(self.config.upstream_url).netloc
        for key, val in req.headers.items():
            lk = key.lower()
            if lk in skip:
                continue
            out[key] = val
        if upstream_host:
            out["Host"] = upstream_host
        if self.config.trust_x_forwarded:
            client_ip = req.headers.get("X-Real-IP") or req.remote_addr
            if client_ip:
                prior = req.headers.get("X-Forwarded-For", "")
                out["X-Forwarded-For"] = f"{prior}, {client_ip}".strip(", ")
                out["X-Real-IP"] = client_ip
            out["X-Forwarded-Proto"] = req.headers.get("X-Forwarded-Proto", req.scheme)
            out["X-Forwarded-Host"] = req.headers.get("X-Forwarded-Host") or req.host
        out["X-IGA-Guard"] = "inline"
        return out

    def _forward_upstream(self, req) -> Response:
        url = self._build_upstream_url(req)
        headers = self._filtered_headers(req)
        data = None
        if req.method not in ("GET", "HEAD", "OPTIONS"):
            raw = req.get_data()
            if len(raw) > self.config.max_body_bytes:
                return Response(
                    json.dumps({"error": "payload too large"}),
                    status=413,
                    mimetype="application/json",
                )
            data = raw

        try:
            upstream = requests.request(
                method=req.method,
                url=url,
                headers=headers,
                data=data,
                allow_redirects=False,
                timeout=self.config.forward_timeout_s,
                stream=True,
            )
        except requests.RequestException as exc:
            logger.error("upstream error %s %s: %s", req.method, url, exc)
            return Response(
                json.dumps({"error": "upstream unreachable", "detail": str(exc)}),
                status=502,
                mimetype="application/json",
            )

        excluded = _HOP_BY_HOP | {"content-encoding", "content-length"}
        resp_headers = [
            (k, v) for k, v in upstream.headers.items()
            if k.lower() not in excluded
        ]
        return Response(
            upstream.content,
            status=upstream.status_code,
            headers=resp_headers,
        )

    def _mirror_async(self, http_req: HttpRequest, report: dict) -> None:
        mirror_url = self.config.api_mirror_url
        if not mirror_url:
            return

        def _post() -> None:
            try:
                requests.post(
                    mirror_url,
                    json={
                        "method": http_req.method,
                        "url": http_req.url,
                        "body": http_req.body,
                        "headers": http_req.headers,
                    },
                    timeout=3,
                )
            except Exception:
                pass

        threading.Thread(target=_post, daemon=True).start()
