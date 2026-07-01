"""Malicious payload localization and explanation."""

from __future__ import annotations

import re

from iga_guard.models import DetectionResult, ExplanationResult, NormalizedPayload

PATTERNS = {
    "SQLi": [r"union\s+select", r"or\s+1\s*=\s*1", r"sleep\s*\(", r"benchmark\s*\("],
    "XSS": [r"<script[^>]*>", r"onerror\s*=", r"javascript:", r"alert\s*\("],
    "CMD": [r"[;&|]`", r"\$\(", r"wget\s+", r"curl\s+", r"\$\{jndi:"],
    "PathTraversal": [r"\.\./", r"\.\.\\", r"/etc/passwd"],
    "FileInclusion": [r"php://", r"file://", r"include\s*\("],
    "XXE": [r"<!entity", r"system\s+[\"']file:", r"&\w+;"],
    "PromptInjection": [r"ignore\s+previous", r"system\s+prompt", r"jailbreak"],
}


def explain(
    payload: NormalizedPayload,
    detection: DetectionResult,
) -> ExplanationResult | None:
    if not detection.is_malicious:
        return None

    text = payload.normalized_payload or payload.raw_payload
    attack_type = detection.label
    patterns = PATTERNS.get(attack_type, [])

    best_span = ""
    best_range = [0, 0]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            best_span = m.group(0)
            best_range = [m.start(), m.end()]
            break

    if not best_span:
        tokens = text.split()
        for i, tok in enumerate(tokens):
            if any(c in tok for c in ("<", ">", "'", '"', ";", "%")):
                best_span = tok
                best_range = [i, i + 1]
                break

    heatmap = _build_heatmap(text, best_span)

    return ExplanationResult(
        attack_type=attack_type,
        risk_level=detection.risk_level,
        malicious_field=payload.field_name or "unknown",
        malicious_span=best_span or text[:40],
        token_range=best_range,
        confidence=detection.confidence,
        heatmap=heatmap,
        method="keyword_attention",
    )


def _build_heatmap(text: str, span: str) -> list[str]:
    if not span:
        return []
    lines: list[str] = []
    for token in text.split():
        if span.lower() in token.lower() or token.lower() in span.lower():
            lines.append("█" * min(len(token), 8) + " " + token)
        elif any(c in token for c in ("union", "select", "script", "alert")):
            lines.append("▓" * min(len(token), 6) + " " + token)
    return lines[:12]
