"""
IGA-Guard 2.0 主流水线（Pipeline）
====================================
职责：串联「采集 → 时序缓存 → 解混淆 → 双路检测 → 可解释高亮 → 规则导出」

数据流：
  HttpRequest
    → iter_payload_parts() 拆分 URL/Body/Header 等字段
    → normalize_payload()   多层解码 + AST 还原
    → TimeSeriesBuffer      按源 IP 维护最近 T 步特征序列（供 DLinear）
    → DualTrackDetector     语义轨 TinyBERT + 统计轨 DLinear + RF 融合
    → webspotter_explain()  恶意片段定位 + highlight_html 前端高亮
    → generate_rule()       ModSecurity / Suricata 规则

性能优化：
  - @lru_cache 缓存归一化结果
  - 虚拟补丁 / 高置信度命中时 early-exit
"""

from __future__ import annotations

import time
from functools import lru_cache
from pathlib import Path

import yaml

from iga_guard.collector.http_parser import iter_payload_parts, parse_http_request
from iga_guard.collector.timeseries_buffer import TimeSeriesBuffer
from iga_guard.detector.dual_track import DualTrackDetector
from iga_guard.detector.fusion_model import FusionDetector
from iga_guard.explainer.nl_explanation import generate_nl_explanation
from iga_guard.explainer.webspotter import webspotter_explain
from iga_guard.models import DetectionResult, GuardReport, HttpRequest, NormalizedPayload, build_highlight_html
from iga_guard.normalizer import normalize_payload
from iga_guard.rules import generate_rule
from iga_guard.rules.virtual_patch import export_virtual_patch_rule, match_virtual_patch

# 置信度超过此阈值且判定为恶意时，跳过后续 payload 字段检测（降低延迟）
_EARLY_EXIT_CONF = 0.88


def _prefer_detection(candidate: DetectionResult, current: DetectionResult | None) -> bool:
    """恶意判定优先于高置信 Normal（修复多字段检测时被 Normal 覆盖）。"""
    if current is None:
        return True
    if candidate.is_malicious and not current.is_malicious:
        return True
    if not candidate.is_malicious and current.is_malicious:
        return False
    return candidate.confidence > current.confidence


def load_config(path: str | Path = "configs/default.yaml") -> dict:
    """加载 YAML 配置；默认路径相对于项目根目录 configs/default.yaml。"""
    cfg_path = Path(path)
    if not cfg_path.exists():
        return {}
    with cfg_path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


@lru_cache(maxsize=4096)
def _cached_normalize(raw: str, field: str, location: str, rounds: int) -> NormalizedPayload:
    """带 LRU 缓存的载荷归一化，避免重复解码开销。"""
    return normalize_payload(raw, field_name=field, location=location, max_decode_rounds=rounds)


def _create_detector(config: dict):
    """工厂：根据 detector.engine 创建 dual_track 或 legacy fusion 检测器。"""
    engine = config.get("detector", {}).get("engine", "dual_track")
    if engine == "dual_track":
        return DualTrackDetector(config)
    model_path = config.get("detector", {}).get("model_path", "models/fusion_detector.joblib")
    path = model_path if Path(model_path).exists() else None
    return FusionDetector(path)


class IgaGuardEngine:
    """
    IGA-Guard 2.0 检测引擎入口类。

    用法：
        engine = IgaGuardEngine()
        report = engine.analyze_url("GET", "http://x/login?id=1+union+select+1")
        print(report.detection.label, report.explanation.highlight_html)
    """

    def __init__(self, config: dict | None = None):
        self.config = config or load_config()
        self.detector = _create_detector(self.config)
        self.max_decode_rounds = self.config.get("normalizer", {}).get("max_decode_rounds", 6)
        self.nl_provider = self.config.get("explanation", {}).get("nl_provider", "template")
        self.virtual_patch = self.config.get("rules", {}).get("virtual_patch_enabled", True)
        ts_cfg = self.config.get("timeseries", {})
        # 时序缓冲：window 与 DLinear seq_len 对齐（默认 16）
        self.ts_buffer = TimeSeriesBuffer(window=ts_cfg.get("window", 16))

    def analyze_request(self, req: HttpRequest) -> GuardReport:
        """对完整 HTTP 请求做检测，返回含解释与高亮的 GuardReport。"""
        t0 = time.perf_counter()
        normalized: list[NormalizedPayload] = []
        best_detection: DetectionResult | None = None
        best_payload: NormalizedPayload | None = None
        # 以 X-Forwarded-For / X-Real-IP 区分流量源，用于时序分析
        source_id = req.headers.get("X-Forwarded-For", req.headers.get("X-Real-IP", "default"))

        for location, field, raw in iter_payload_parts(req):
            norm = _cached_normalize(raw, field, location, self.max_decode_rounds)
            normalized.append(norm)
            self.ts_buffer.push(source_id, norm)
            ts_matrix = self.ts_buffer.get_matrix(source_id)

            # --- 虚拟补丁：CVE 载荷快速拦截（Log4Shell 等）---
            if self.virtual_patch:
                vp = match_virtual_patch(norm.normalized_payload or raw)
                if vp:
                    best_detection = DetectionResult(
                        label=vp["label"],
                        confidence=0.99,
                        risk_level="high",
                        is_malicious=True,
                        all_probs={vp["label"]: 0.99, "Normal": 0.01},
                    )
                    best_payload = norm
                    break

            # --- 双路检测：传入时序矩阵 ts_matrix 供 DLinear 分支 ---
            if hasattr(self.detector, "predict"):
                det = self.detector.predict(norm, ts_matrix=ts_matrix)
            else:
                det = self.detector.predict(norm)
            if _prefer_detection(det, best_detection):
                best_detection = det
                best_payload = norm

            if best_detection and best_detection.confidence >= _EARLY_EXIT_CONF and best_detection.is_malicious:
                break

        if best_detection is None:
            best_detection = DetectionResult(
                label="Normal", confidence=1.0, risk_level="low", is_malicious=False,
            )
            best_payload = _cached_normalize(req.url, "", "query", self.max_decode_rounds)

        best_detection.latency_ms = (time.perf_counter() - t0) * 1000

        # --- 可解释性：WebSpotter 定位 + NL 解释 + HTML 高亮 ---
        explanation = webspotter_explain(best_payload, best_detection, normalized) if best_payload else None
        if explanation and best_payload:
            explanation.natural_language = generate_nl_explanation(
                best_payload, best_detection, explanation, provider=self.nl_provider,
            )
            text = best_payload.normalized_payload or best_payload.raw_payload
            if len(explanation.token_range) >= 2:
                explanation.highlight_html = build_highlight_html(
                    text, explanation.token_range[0], explanation.token_range[1],
                )

        rule = generate_rule(best_detection, explanation)
        if self.virtual_patch and best_payload:
            vp = match_virtual_patch(best_payload.normalized_payload or best_payload.raw_payload)
            if vp:
                rule = rule or {}
                rule["virtual_patch"] = vp
                rule["modsecurity_vp"] = export_virtual_patch_rule(vp)

        return GuardReport(
            request=req,
            normalized=normalized,
            detection=best_detection,
            explanation=explanation,
            generated_rule=rule,
        )

    def analyze_url(self, method: str, url: str, body: str = "") -> GuardReport:
        """便捷接口：仅 URL + Method 的检测入口。"""
        return self.analyze_request(parse_http_request(method=method, url=url, body=body))
