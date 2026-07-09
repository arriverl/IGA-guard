"""Semantic homomorphism views for obfuscated web payloads.

This module turns syntactically different payload forms into a compact set of
semantic attack scores. It is intentionally lightweight: the detector can use it
on the hot path as a label-arbitration signal without changing binary gating.
"""

from __future__ import annotations

import base64
import html
import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote_plus

from iga_guard.models import ATTACK_LABELS


_B64_RE = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/])")
_HTML_ENTITY_RE = re.compile(r"&#x?[0-9a-f]+;?", re.I)


@dataclass(frozen=True)
class SemanticHomographReport:
    """Multi-view semantic representation of a payload."""

    views: dict[str, str] = field(default_factory=dict)
    scores: dict[str, float] = field(default_factory=dict)
    parser_discrepancy: bool = False
    dominant_label: str = "Normal"
    confidence: float = 0.0


def _bounded(text: str, limit: int = 4096) -> str:
    return text[:limit] if len(text) > limit else text


def _multi_unquote(text: str, rounds: int = 3) -> str:
    cur = text
    for _ in range(rounds):
        nxt = unquote_plus(cur)
        if nxt == cur:
            break
        cur = nxt
    return cur


def _decode_base64_fragments(text: str) -> str:
    parts: list[str] = []
    for m in _B64_RE.finditer(text):
        token = m.group(1)
        try:
            padded = token + "=" * (-len(token) % 4)
            decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
        except Exception:
            continue
        if decoded and any(c.isprintable() for c in decoded):
            parts.append(decoded)
    return " ".join(parts)


def _json_view(text: str) -> str:
    try:
        obj = json.loads(text)
    except Exception:
        return ""

    out: list[str] = []

    def walk(v) -> None:
        if isinstance(v, dict):
            for k, val in v.items():
                out.append(str(k))
                walk(val)
        elif isinstance(v, list):
            for item in v:
                walk(item)
        elif isinstance(v, (str, int, float, bool)):
            out.append(str(v))

    walk(obj)
    return " ".join(out)


def build_semantic_views(raw: str, norm: str | None = None) -> dict[str, str]:
    """Build raw/decoded/parser views used by semantic scoring."""
    raw = raw or ""
    norm = norm or raw
    url_once = unquote_plus(raw)
    url_deep = _multi_unquote(raw)
    html_decoded = html.unescape(url_deep)
    b64 = _decode_base64_fragments(html_decoded + " " + raw)
    json_text = _json_view(html_decoded) or _json_view(url_deep)
    params = " ".join(f"{k}={v}" for k, v in parse_qsl(url_deep.replace("?", "&"), keep_blank_values=True))
    return {
        "raw": _bounded(raw),
        "normalized": _bounded(norm),
        "url_once": _bounded(url_once),
        "url_deep": _bounded(url_deep),
        "html": _bounded(html_decoded),
        "base64": _bounded(b64),
        "json": _bounded(json_text),
        "params": _bounded(params),
    }


def _score_text(text: str) -> dict[str, float]:
    low = text.lower()
    scores = {k: 0.0 for k in ATTACK_LABELS}
    scores["Normal"] = 0.05

    if re.search(r"union\s+select|select\s+.+\s+from|or\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(", low):
        scores["SQLi"] += 0.70
    if any(x in low for x in ("information_schema", " waitfor ", " drop table", " insert into", " char(")):
        scores["SQLi"] += 0.40

    if any(x in low for x in ("<script", "javascript:", "onerror", "onload", "<svg", "alert(")):
        scores["XSS"] += 0.75
    if _HTML_ENTITY_RE.search(text) and any(x in low for x in ("script", "alert", "onerror", "&#60;", "&#x3c;")):
        scores["XSS"] += 0.45

    if any(x in low for x in ("$(echo", "&&", "||", ";wget", "|wget", "curl ", "bash ", " sh ", "wc -c")):
        scores["CMD"] += 0.70
    if "sleep" in low and any(x in low for x in (" -ne ", " -eq ", "str=$", "${#")):
        scores["CMD"] += 0.50

    if any(x in low for x in ("../", "..\\", "/etc/passwd", "%c0%af", "%2e%2e", "%u2215")):
        scores["PathTraversal"] += 0.70
    if any(x in low for x in ("php://", "zip://", "file://", "expect://", "data://")):
        scores["FileInclusion"] += 0.70
    if any(x in low for x in ("<!entity", "<!doctype", "&xxe;", "system \"file://", "xi:include")):
        scores["XXE"] += 0.75
    if any(x in low for x in ("ignore previous", "system prompt", "jailbreak", "validation: approved", "[system]")):
        scores["PromptInjection"] += 0.65

    return scores


def semantic_homograph_report(raw: str, norm: str | None = None) -> SemanticHomographReport:
    """Return semantic attack scores across multiple equivalent views."""
    views = build_semantic_views(raw, norm)
    agg = {k: 0.0 for k in ATTACK_LABELS}
    for name, text in views.items():
        if not text:
            continue
        weight = 1.25 if name in ("html", "url_deep", "json", "params") else 1.0
        for label, val in _score_text(text).items():
            agg[label] = max(agg.get(label, 0.0), val * weight)

    # WAFFLED-style discrepancy signal: raw parser form differs materially from
    # URL/JSON/param views. It is not malicious alone, but boosts structure scores.
    parser_discrepancy = bool(
        ("boundary" in views["raw"].lower() and "boundary" not in views["url_deep"].lower())
        or (views["json"] and views["json"] not in views["raw"])
        or (views["params"] and views["params"] not in views["raw"] and ("%3d" in views["raw"].lower()))
    )
    if parser_discrepancy:
        agg["SQLi"] = max(agg["SQLi"], 0.25)
        agg["XSS"] = max(agg["XSS"], 0.25)

    dominant = max((k for k in agg if k != "Normal"), key=lambda k: agg[k], default="Normal")
    conf = float(agg.get(dominant, 0.0))
    if conf < 0.20:
        dominant = "Normal"
        conf = max(conf, agg.get("Normal", 0.0))
    return SemanticHomographReport(
        views=views,
        scores=agg,
        parser_discrepancy=parser_discrepancy,
        dominant_label=dominant,
        confidence=conf,
    )

