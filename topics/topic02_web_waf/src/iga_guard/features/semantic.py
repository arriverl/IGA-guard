"""Attack semantic keyword features."""

from __future__ import annotations

import re

SQL_KEYWORDS = [
    "union", "select", "sleep", "benchmark", "or 1=1", "drop", "insert", "update",
]
XSS_KEYWORDS = [
    "script", "onerror", "svg", "iframe", "javascript", "alert", "onload",
]
CMD_KEYWORDS = [";", "|", "&&", "`", "$(", "wget", "curl", "bash"]
PATH_KEYWORDS = ["../", "..\\", "/etc/passwd", "windows/system32"]
FILE_KEYWORDS = ["php://", "file://", "include", "require"]
XXE_KEYWORDS = ["<!entity", "system", "file://", "&xxe;", "<!doctype"]
PROMPT_KEYWORDS = [
    "ignore previous", "ignore all", "disregard", "system prompt",
    "jailbreak", "dan mode", "developer mode", "绕过", "忽略之前",
]


def _keyword_hits(text: str, keywords: list[str]) -> float:
    lower = text.lower()
    return float(sum(1 for kw in keywords if kw in lower))


def extract_semantic(text: str) -> dict[str, float]:
    return {
        "sqli_score": _keyword_hits(text, SQL_KEYWORDS),
        "xss_score": _keyword_hits(text, XSS_KEYWORDS),
        "cmd_score": _keyword_hits(text, CMD_KEYWORDS),
        "path_score": _keyword_hits(text, PATH_KEYWORDS),
        "file_score": _keyword_hits(text, FILE_KEYWORDS),
        "xxe_score": _keyword_hits(text, XXE_KEYWORDS),
        "prompt_score": _keyword_hits(text, PROMPT_KEYWORDS),
        "tag_count": float(len(re.findall(r"<[^>]+>", text, re.I))),
    }
