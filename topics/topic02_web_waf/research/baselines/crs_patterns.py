"""OWASP CRS PL4 代表性规则子集（离线基线，无需 Docker）。

基于 CRS v4.x 942/941/932 系列常见签名，用于与 IGA-Guard 同集横向对比。
文献参考：ModSec-AdvLearn · 社区复现 CRS 混淆 TPR ~40–60%。
"""

from __future__ import annotations

import re
from urllib.parse import unquote

# CRS 942xxx SQLi · 941xxx XSS · 932xxx RCE 精简子集
_CRS_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("942100", re.compile(r"(?i)select\s+.+\s+from", re.DOTALL)),
    ("942110", re.compile(r"(?i)union\s+(all\s+)?select")),
    ("942120", re.compile(r"(?i)(?:/\*!?|\*/|--\s|#)")),
    ("942130", re.compile(r"(?i)'\s*(?:or|and)\s+'?\d")),
    ("942140", re.compile(r"(?i)'\s*or\s+'[^']*'\s*=\s*'")),
    ("942150", re.compile(r"(?i)(?:concat|group_concat|char\s*\(|0x[0-9a-f]{4,})")),
    ("942160", re.compile(r"(?i)(?:sleep\s*\(|benchmark\s*\(|waitfor\s+delay)")),
    ("942170", re.compile(r"(?i)(?:information_schema|sys\.|pg_catalog)")),
    ("942180", re.compile(r"(?i)(?:into\s+(?:outfile|dumpfile)|load_file\s*\()")),
    ("942190", re.compile(r"(?i)(?:;\s*(?:drop|delete|insert|update|alter)\s+)")),
    ("941100", re.compile(r"(?i)<script[\s>]")),
    ("941110", re.compile(r"(?i)(?:javascript|vbscript)\s*:")),
    ("941120", re.compile(r"(?i)on(?:error|load|click|mouse)\s*=")),
    ("941130", re.compile(r"(?i)<\s*(?:iframe|object|embed|svg)")),
    ("941140", re.compile(r"(?i)(?:alert\s*\(|prompt\s*\(|confirm\s*\()")),
    ("932100", re.compile(r"(?i)(?:\|\s*(?:cat|ls|id|whoami|uname)\b|;\s*(?:cat|ls|id)\b)")),
    ("932110", re.compile(r"(?i)(?:\$\([^)]+\)|`[^`]+`|\|\|)")),
    ("932120", re.compile(r"(?i)(?:&&\s*(?:echo|wget|curl)|;\s*(?:wget|curl)\s+)")),
    ("932130", re.compile(r"(?i)(?:/bin/(?:sh|bash)|cmd\.exe|powershell)")),
]


def _decode_layers(text: str, rounds: int = 2) -> str:
    out = text
    for _ in range(rounds):
        try:
            nxt = unquote(out, errors="replace")
        except Exception:
            break
        if nxt == out:
            break
        out = nxt
    return out


def crs_match(payload: str, *, decode_rounds: int = 1) -> tuple[bool, list[str]]:
    """对载荷执行 CRS 子集匹配（单层解码，模拟 PL4 默认行为）。"""
    text = _decode_layers(payload, decode_rounds)
    hits: list[str] = []
    for rule_id, pat in _CRS_RULES:
        if pat.search(text) or pat.search(payload):
            hits.append(rule_id)
    return bool(hits), hits


def crs_label(payload: str) -> str:
    """粗分类：返回 SQLi / XSS / CMD / Normal。"""
    matched, hits = crs_match(payload)
    if not matched:
        return "Normal"
    if any(h.startswith("942") for h in hits):
        return "SQLi"
    if any(h.startswith("941") for h in hits):
        return "XSS"
    if any(h.startswith("932") for h in hits):
        return "CMD"
    return "SQLi"
