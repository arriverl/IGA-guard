"""混淆载荷特征信号 — 检测器与评估脚本共用。"""

from __future__ import annotations

import re
from collections import defaultdict

OBFUSCATED_MARKERS: tuple[str, ...] = (
    "%", "/**/", "fromcharcode", "eval(", "&#", "\\u", "0x", "char(",
    "boundary=", "multipart", "/*!", "%0a", "%09", "webkitformboundary",
    "%252", "\\x", "concat(", "unhex(", "benchmark(", "sleep(",
    "%00", "atob(", "echo%20", "&&echo", "$(echo",
    "'+'", "\"+\"",
    # v3.1 新增
    "between", "1e0", "1E0", "${ifs}", "{cat,", "/???/", "php://filter",
    "zip://", "xi:include", "data:text/html", "ontoggle", "font-size:0",
    "boundary*0=", "%c0%af", "%u2215", "[SYSTEM]", "||", "BETWEEN",
)

_ATTACK_PATTERNS: dict[str, tuple[str, ...]] = {
    "SQLi": (
        "union", "select", "or 1=1", "information_schema", "sleep(", "benchmark(",
        "0x", "char(", "modo=", "login=", "pwd=", "password=",
        "\\u006d", "\\u006c", "\\u0070",  # unicode-escaped modo/login/pwd fragments
    ),
    "XSS": ("<script", "onerror", "javascript:", "alert(", "onload=", "<svg", "fromcharcode", "<scr"),
    "CMD": (
        "wget", "curl", "`", "${jndi:", "echo ", "sleep ",
        "echo%20", "%28echo", "$(echo", "str%3d%24%28echo", "str=$(echo",
        "%26%26", "sleep%20", "|echo", "%2528echo", "echo%2520", "%252526",
        "&&", "||", ";wget", "|wget", "%3bwget", "%7cwget",
    ),
    "PathTraversal": ("../", "..\\", "/etc/passwd", "%2e%2e"),
    "FileInclusion": ("php://", "file://", "expect://", "data://"),
    "XXE": ("<!entity", "&xxe;", "system ", "file:///"),
    "PromptInjection": (
        "ignore previous", "jailbreak", "system prompt", "disregard",
        "[system]", "validation: approved", "忽略", "ignore\u200b",
    ),
}

_HEX32_PARAM = re.compile(r"(?:^|[&?])(\w+)=([0-9a-f]{32})\b", re.I)
_HEX32_TOKEN = re.compile(r"\b[0-9a-f]{32}\b", re.I)
_FORM_INJ = re.compile(r"(pwd|passwd|password|login|user|modo)=", re.I)
_SCRIPT_SPLIT = re.compile(r"['\"]\s*\+\s*['\"]")
_PARAM_PAIRS = re.compile(r"(?:^|[&?])(\w+)=([^&]*)", re.I)
_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-f]{4})", re.I)
_NULL_IN_VALUE = re.compile(r"[\w.]%00|%00[\w.@]|%00%23|%3d%00|%00%3d", re.I)

# 强混淆：检测器 boost / 兜底专用（避免普通 URL 单次编码误触发）
_STRONG_OBFUSCATION_MARKERS: tuple[str, ...] = (
    "%252", "%00", "webkitformboundary", "/**/", "fromcharcode",
    "eval(", "\\u", "0x", "boundary=", "multipart", "\\x",
    "&&echo", "$(echo", "%0aecho", "atob(", "unhex(", "benchmark(",
    "concat(", "/*!", "echo%20", "echo%2520",
    # v3.1
    "boundary*0=", "php://filter", "zip://", "xi:include", "%c0%af",
    "data:text/html", "\u200b", "\u200c", "\u202e", "ontoggle=",
)


def has_strong_obfuscation(text: str) -> bool:
    """
    检测器专用强混淆判定：普通 URL 编码（仅含少量 %20 等）不触发 boost。
    评测子集仍用 is_obfuscated() 保持口径一致。
    """
    if not text:
        return False
    low = text.lower()
    if any(m in low for m in _STRONG_OBFUSCATION_MARKERS):
        return True
    if has_fullwidth(text):
        return True
    if _encoded_cmd_markers(low):
        return True
    if len(_UNICODE_ESCAPE.findall(text)) >= 3:
        return True
    pct = low.count("%")
    if pct >= 4 and pct / max(len(low), 1) > 0.18:
        return True
    weak_hits = sum(1 for m in ("%0a", "%09", "char(", "sleep(", "&#", "'+'") if m in low)
    if weak_hits >= 2 and pct >= 2:
        return True
    if any(c in text for c in ("\u200b", "\u200c", "\u200d", "\u202e")):
        return True
    if "boundary*0=" in low or "php://filter" in low:
        return True
    return False


def _encoded_cmd_markers(text: str) -> bool:
    """URL/双重编码 shell 片段（收紧：需 echo/subshell/链式运算符组合）。"""
    low = text.lower()
    return any(
        m in low
        for m in (
            "echo%20", "echo%2520", "%28echo", "%2528echo", "$(echo",
            "str%3d%24%28echo", "str%3d$(echo", "str%25253d%252524%252528echo",
            "str%25253d", "%26%26", "%252526", "&&echo", "%0aecho", "%25250aecho",
            "|echo", "%7cecho", "sleep%20", "sleep%200", "$%00(echo", "%00(echo",
        )
    )


def _unicode_escape_sqli_signal(text: str) -> bool:
    if len(_UNICODE_ESCAPE.findall(text)) >= 3:
        return True
    decoded = _UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)
    low = decoded.lower()
    return any(k in low for k in ("modo", "login", "pwd", "password", "union", "select", "insert"))


def is_obfuscated(text: str) -> bool:
    low = text.lower()
    if any(m in low for m in OBFUSCATED_MARKERS):
        return True
    return has_fullwidth(text)


def has_fullwidth(text: str) -> bool:
    return any("\uff00" <= c <= "\uffef" for c in text)


def _duplicate_params(raw_low: str) -> list[str]:
    """返回重复出现的参数名（HPP）。"""
    buckets: dict[str, list[str]] = defaultdict(list)
    for m in _PARAM_PAIRS.finditer(raw_low.replace("?", "&")):
        buckets[m.group(1).lower()].append(m.group(2))
    return [k for k, vals in buckets.items() if len(vals) > 1]


def _hex32_in_param_context(raw: str, norm: str) -> bool:
    return bool(_HEX32_PARAM.search(raw) or _HEX32_PARAM.search(norm))


def attack_keyword_scores(text: str) -> dict[str, float]:
    """对文本做规则打分，供混淆逃逸兜底。"""
    low = text.lower()
    scores = {k: 0.0 for k in _ATTACK_PATTERNS}
    scores["Normal"] = 0.05
    for label, patterns in _ATTACK_PATTERNS.items():
        for p in patterns:
            if p in low:
                scores[label] += 0.35
    if "union" in low and "select" in low:
        scores["SQLi"] += 0.4
    if _unicode_escape_sqli_signal(text):
        scores["SQLi"] += 0.35
    if _encoded_cmd_markers(low):
        scores["CMD"] += 0.35
    if _NULL_IN_VALUE.search(low):
        scores["SQLi"] += 0.35
    total = sum(scores.values()) or 1.0
    return {k: v / total for k, v in scores.items()}


def structural_attack_scores(
    raw: str,
    norm: str,
    *,
    decode_depth: int = 0,
) -> dict[str, float]:
    """
    结构级攻击信号（收紧版）：避免单独 hex token / 正常 CSIC 字段误报。
    """
    scores = {k: 0.0 for k in _ATTACK_PATTERNS}
    scores["Normal"] = 0.05
    low = norm.lower()
    raw_low = raw.lower()
    kw = attack_keyword_scores(low)
    kw_attack = max((v for k, v in kw.items() if k != "Normal"), default=0.0)

    dup_keys = _duplicate_params(raw_low)
    if dup_keys:
        scores["SQLi"] += 0.55

    if _hex32_in_param_context(raw, norm):
        if dup_keys or decode_depth >= 1 or kw_attack >= 0.2 or is_obfuscated(raw):
            scores["SQLi"] += 0.5

    if _FORM_INJ.search(low) and ("'" in low or "%27" in raw_low):
        scores["SQLi"] += 0.6

    if _SCRIPT_SPLIT.search(raw) and any(x in low for x in ("script", "alert", "scr", "ipt")):
        scores["XSS"] += 0.75

    if "webkitformboundary" in raw_low and any(x in low for x in ("script", "alert", "<scr")):
        scores["XSS"] += 0.75

    if "atob(" in raw_low and (decode_depth >= 1 or any(x in low for x in ("script", "alert", "select", "union"))):
        scores["XSS"] += 0.45
        if kw_attack >= 0.15:
            scores["SQLi"] += 0.25

    if has_fullwidth(raw) and _FORM_INJ.search(low):
        scores["SQLi"] += 0.4

    if "eval(" in raw_low and _FORM_INJ.search(low):
        scores["SQLi"] += 0.45

    if any(x in raw_low for x in ("&&echo", "$(echo", "%0aecho")):
        scores["CMD"] += 0.55

    if _encoded_cmd_markers(raw_low):
        scores["CMD"] += 0.55

    if "%252" in raw_low and _encoded_cmd_markers(raw_low):
        scores["CMD"] += 0.15

    if _NULL_IN_VALUE.search(raw_low):
        if _FORM_INJ.search(low) or decode_depth >= 1 or _encoded_cmd_markers(raw_low):
            scores["SQLi"] += 0.45
            if _encoded_cmd_markers(raw_low):
                scores["CMD"] += 0.35

    if _unicode_escape_sqli_signal(raw) or _unicode_escape_sqli_signal(norm):
        scores["SQLi"] += 0.55

    if any(m in raw_low for m in ("php://filter", "zip://", "xi:include")):
        scores["FileInclusion"] += 0.65

    if "data:text/html" in raw_low or "ontoggle=" in raw_low:
        scores["XSS"] += 0.55

    if "${ifs}" in raw_low or "{cat," in raw_low or "/???/" in raw_low:
        scores["CMD"] += 0.5

    if "%c0%af" in raw_low or "..;/" in raw_low or "%u2215" in raw_low:
        scores["PathTraversal"] += 0.55

    if "[system]" in raw_low or "validation: approved" in raw_low:
        scores["PromptInjection"] += 0.45

    if any(c in raw for c in ("\u200b", "\u200c", "\u200d", "\u202e")):
        if kw_attack >= 0.15 or _FORM_INJ.search(low):
            scores["PromptInjection"] += 0.35
            scores["SQLi"] += 0.2

    if "webkitformboundary" in raw_low:
        body = raw.split("\n\n", 1)[-1] if "\n\n" in raw else ""
        if _HEX32_TOKEN.search(body):
            scores["SQLi"] += 0.6
        if _encoded_cmd_markers(raw_low) or any(
            x in raw_low for x in ("&&echo", "%26%26", "|echo", "%7cecho", "%27&&")
        ):
            scores["CMD"] += 0.55

    total = sum(scores.values()) or 1.0
    return {k: v / total for k, v in scores.items()}
