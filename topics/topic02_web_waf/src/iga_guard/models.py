"""IGA-Guard core data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


ATTACK_LABELS = [
    "Normal",
    "SQLi",
    "XSS",
    "CMD",
    "PathTraversal",
    "FileInclusion",
    "XXE",
    "PromptInjection",
]


@dataclass
class HttpRequest:
    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    source: str = "api"
    protocol: str = "HTTP/1.1"


@dataclass
class NormalizedPayload:
    raw_payload: str
    normalized_payload: str
    decode_chain: list[str] = field(default_factory=list)
    field_name: str = ""
    location: str = "query"


@dataclass
class FeatureVector:
    statistical: dict[str, float] = field(default_factory=dict)
    semantic: dict[str, float] = field(default_factory=dict)
    combined: list[float] = field(default_factory=list)
    names: list[str] = field(default_factory=list)


@dataclass
class DetectionResult:
    label: str
    confidence: float
    risk_level: str
    is_malicious: bool
    latency_ms: float = 0.0
    all_probs: dict[str, float] = field(default_factory=dict)


@dataclass
class ExplanationResult:
    attack_type: str
    risk_level: str
    malicious_field: str
    malicious_span: str
    token_range: list[int]
    confidence: float
    heatmap: list[str]
    method: str = "webspotter"
    field_contributions: dict[str, float] = field(default_factory=dict)
    natural_language: str = ""
    highlight_html: str = ""


def build_highlight_html(text: str, start: int, end: int) -> str:
    """Wrap malicious span in highlight markup for frontend."""
    if start < 0 or end <= start or not text:
        return text
    start = max(0, min(start, len(text)))
    end = max(start, min(end, len(text)))
    return (
        text[:start]
        + "<mark class='iga-mal'>"
        + text[start:end]
        + "</mark>"
        + text[end:]
    )


@dataclass
class GuardReport:
    request: HttpRequest
    normalized: list[NormalizedPayload]
    detection: DetectionResult
    explanation: ExplanationResult | None = None
    generated_rule: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.request.method,
            "url": self.request.url,
            "normalized": [
                {
                    "raw": n.raw_payload,
                    "normalized": n.normalized_payload,
                    "decode_chain": n.decode_chain,
                    "field": n.field_name,
                    "location": n.location,
                }
                for n in self.normalized
            ],
            "detection": {
                "label": self.detection.label,
                "confidence": self.detection.confidence,
                "risk_level": self.detection.risk_level,
                "is_malicious": self.detection.is_malicious,
                "latency_ms": self.detection.latency_ms,
                "probs": self.detection.all_probs,
            },
            "explanation": None
            if self.explanation is None
            else {
                "attack_type": self.explanation.attack_type,
                "risk_level": self.explanation.risk_level,
                "malicious_field": self.explanation.malicious_field,
                "malicious_span": self.explanation.malicious_span,
                "token_range": self.explanation.token_range,
                "confidence": self.explanation.confidence,
                "heatmap": self.explanation.heatmap,
                "method": self.explanation.method,
                "field_contributions": self.explanation.field_contributions,
                "natural_language": self.explanation.natural_language,
                "highlight_html": self.explanation.highlight_html,
            },
            "rule": self.generated_rule,
        }
