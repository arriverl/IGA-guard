"""Auto rule generation for WAF export."""

from __future__ import annotations

import re
from typing import Any

from iga_guard.models import DetectionResult, ExplanationResult


def generate_rule(
    detection: DetectionResult,
    explanation: ExplanationResult | None,
) -> dict[str, Any] | None:
    if not detection.is_malicious:
        return None

    span = explanation.malicious_span if explanation else ""
    pattern = _span_to_regex(span, detection.label)
    if not pattern:
        return None

    return {
        "type": detection.label,
        "pattern": pattern,
        "confidence": round(detection.confidence, 4),
        "modsecurity": f'SecRule ARGS "@rx {pattern}" "id:10001,phase:2,deny,msg:\'{detection.label} detected\'"',
        "suricata": f'alert http any any -> any any (msg:"IGA-Guard {detection.label}"; content:"{span[:20]}"; sid:90001;)',
    }


def export_modsecurity(rules: list[dict[str, Any]]) -> str:
    lines = ["# IGA-Guard auto-generated ModSecurity rules"]
    for r in rules:
        lines.append(r.get("modsecurity", ""))
    return "\n".join(lines)


def _span_to_regex(span: str, label: str) -> str:
    if span:
        escaped = re.escape(span.strip())
        return escaped.replace(r"\ ", r"\s+")

    defaults = {
        "SQLi": r"union\s+select",
        "XSS": r"<script",
        "CMD": r"[;&|]",
        "PathTraversal": r"\.\./",
        "FileInclusion": r"php://",
    }
    return defaults.get(label, "")
