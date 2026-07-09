"""
WebSpotter 式可解释定位模块（Explainability / XAI）
====================================================
输出：
  - malicious_span / token_range  — 恶意字符区间
  - field_contributions           — 各 HTTP 字段贡献度
  - heatmap                       — 终端热力字符条
  - highlight_html（由 pipeline 生成）— 前端 <mark> 高亮

定位策略优先级：
  1. 复合锚点（union select / ignore previous / <script>）
  2. 正则模式匹配
  3. 单关键词锚点 + _refine_to_anchor 收紧 IoU
"""

from __future__ import annotations

import re

from iga_guard.explainer.locator import PATTERNS, _build_heatmap
from iga_guard.models import DetectionResult, ExplanationResult, NormalizedPayload

# Per-label anchor keywords for span validation
ANCHOR_KEYWORDS: dict[str, list[str]] = {
    "SQLi": ["union", "select", "or 1=1", "sleep"],
    "XSS": ["script", "onerror", "alert", "svg"],
    "CMD": ["wget", "curl", "jndi", ";"],
    "PathTraversal": ["../", "..\\", "passwd"],
    "FileInclusion": ["php://", "include"],
    "XXE": ["entity", "system", "xxe"],
    "PromptInjection": ["ignore", "prompt", "jailbreak", "disregard"],
}


def webspotter_explain(
    payload: NormalizedPayload,
    detection: DetectionResult,
    all_parts: list[NormalizedPayload] | None = None,
) -> ExplanationResult | None:
    if not detection.is_malicious:
        return None

    text = payload.normalized_payload or payload.raw_payload
    attack_type = detection.label
    best_span, best_range = _locate_span(text, attack_type)

    contributions = _field_contributions(all_parts or [payload], detection)
    heatmap = _build_heatmap(text, best_span)
    char_map = _char_level_map(text, best_range)

    return ExplanationResult(
        attack_type=attack_type,
        risk_level=detection.risk_level,
        malicious_field=payload.field_name or "unknown",
        malicious_span=best_span or text[:40],
        token_range=best_range,
        confidence=detection.confidence,
        heatmap=heatmap + char_map,
        method="webspotter_v2",
        field_contributions=contributions,
    )


def _locate_span(text: str, attack_type: str) -> tuple[str, list[int]]:
    patterns = PATTERNS.get(attack_type, [])
    anchors = ANCHOR_KEYWORDS.get(attack_type, [])
    candidates: list[tuple[str, int, int, float]] = []
    lower = text.lower()

    # Priority 1: compound anchors (e.g. union select)
    if attack_type == "SQLi" and "union" in text.lower() and "select" in text.lower():
        m = re.search(r"union\s+select", text, re.IGNORECASE)
        if m:
            candidates.append((m.group(0), m.start(), m.end(), 5.0))

    if attack_type == "XSS":
        m = re.search(r"<script[^>]*>", text, re.IGNORECASE)
        if m:
            candidates.append((m.group(0), m.start(), m.end(), 5.5))

    if attack_type == "PromptInjection":
        idx = lower.find("ignore")
        if idx >= 0:
            candidates.append((text[idx : idx + 6], idx, idx + 6, 5.8))
        m = re.search(r"ignore\s+previous", text, re.IGNORECASE)
        if m:
            candidates.append((m.group(0), m.start(), m.end(), 5.0))

    if attack_type == "XXE":
        for pat, pri in (
            (r"<!ENTITY\s+%[^>]+file:///", 6.5),
            (r"<!ENTITY\s+&#x25;[^>]+SYSTEM", 6.4),
            (r"&#x66;&#x69;&#x6c;&#x65;&#x3a;&#x2f;&#x2f;&#x2f;[^\s\"'>]+", 6.3),
            (r"<!DOCTYPE[^>]*\[", 6.0),
            (r"file:///[^\s\"'>]+", 5.8),
            (r"<!ENTITY[^>]+>", 5.0),
        ):
            m = re.search(pat, text, re.IGNORECASE | re.DOTALL)
            if m:
                candidates.append((m.group(0), m.start(), m.end(), pri))

    for pat in patterns:
        for m in re.finditer(pat, text, re.IGNORECASE):
            span = m.group(0)
            if not any(a.lower() in span.lower() for a in anchors):
                continue
            # Deprioritize alert() for XSS when script tag exists
            if attack_type == "XSS" and span.lower().startswith("alert"):
                candidates.append((span, m.start(), m.end(), 2.0))
            else:
                candidates.append((span, m.start(), m.end(), 4.0))

    for kw in anchors:
        idx = lower.find(kw.lower())
        if idx >= 0:
            end = idx + len(kw)
            pri = 3.5
            if attack_type == "PromptInjection" and kw == "system prompt":
                pri = 2.0
            candidates.append((text[idx:end], idx, end, pri))

    if candidates:
        best = max(candidates, key=lambda x: (x[3], - (x[2] - x[1])))
        span, start, end = best[0], best[1], best[2]
        span, start, end = _refine_to_anchor(text, span, start, end, anchors)
        return span, [start, end]

    for i, ch in enumerate(text):
        if ch in "'\"<>%;":
            start = max(0, i - 2)
            end = min(len(text), i + 12)
            return text[start:end], [start, end]

    return text[:40], [0, min(40, len(text))]


def _refine_to_anchor(
    text: str, span: str, start: int, end: int, anchors: list[str],
) -> tuple[str, int, int]:
    """Shrink span to tightest matching anchor for higher localization IoU."""
    sub = text[start:end]
    if re.search(r"union\s+select", sub, re.IGNORECASE):
        m = re.search(r"union\s+select", sub, re.IGNORECASE)
        if m:
            return m.group(0), start + m.start(), start + m.end()
    if re.search(r"ignore\s+previous", sub, re.IGNORECASE):
        m = re.search(r"ignore\s+previous", sub, re.IGNORECASE)
        if m:
            return m.group(0), start + m.start(), start + m.end()
    ent = re.search(r"entity", sub, re.IGNORECASE)
    if ent:
        return ent.group(0), start + ent.start(), start + ent.end()

    best_span, best_start, best_len = span, 0, len(sub)
    for a in sorted(anchors, key=len, reverse=True):
        idx = sub.lower().find(a.lower())
        if idx >= 0 and len(a) <= best_len:
            best_span = sub[idx : idx + len(a)]
            best_start = idx
            best_len = len(a)
            break
    return best_span, start + best_start, start + best_start + best_len


def _field_contributions(parts: list[NormalizedPayload], detection: DetectionResult) -> dict[str, float]:
    weights: dict[str, float] = {}
    anchors = ANCHOR_KEYWORDS.get(detection.label, [])
    for p in parts:
        key = f"{p.location}:{p.field_name}"
        text = (p.normalized_payload or p.raw_payload).lower()
        score = 0.1 + sum(0.25 for a in anchors if a.lower() in text)
        weights[key] = round(score, 3)
    total = sum(weights.values()) or 1.0
    return {k: round(v / total, 3) for k, v in weights.items()}


def _char_level_map(text: str, span_range: list[int]) -> list[str]:
    if len(span_range) < 2:
        return []
    start, end = span_range[0], span_range[1]
    return [f"█{text[i]}" for i in range(start, min(end, len(text)))][:20]
