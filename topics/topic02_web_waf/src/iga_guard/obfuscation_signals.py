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
_NULL_IN_VALUE = re.compile(
    r"[\w.]%00|%00[\w.@]|%00%23|%3d%00|%00%3d"
    r"|\w%00\w|%2500",
    re.I,
)
_RE_FORM_CTX = re.compile(r"(modo|login|pwd|password|insert|registro|entrar)=", re.I)
_BENIGN_CSIC_PARAMS = re.compile(
    r"(modo|login|password|nombre|apellidos|precio|pwd|insertar|registro|entrar|b1)=[^&]*",
    re.I,
)
_SQLI_INJECTION_MARKERS = re.compile(
    r"union\s+select|select\s+.+\s+from|insert\s+into|drop\s+table|sleep\s*\(|benchmark\s*\("
    r"|or\s+1\s*=\s*1|'[^']*'|--|%27|%2d%2d|0x[0-9a-f]{4,}|;\s*shutdown",
    re.I,
)
_RE_CONCAT_SPLIT = re.compile(r"'\s*\+\s*'")

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
    if "\x00" in text:
        return True
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
            "sleep%2520", "wc%2520", "tr%2520-d", "%25250a",
        )
    )


_RE_DOUBLE_PCT = re.compile(r"%25(?:25)?[0-9a-f]{2}", re.I)
_RE_DOUBLE_CMD = re.compile(
    r"(?:%2528|%28%25|%\d{2}%25)\s*(?:echo|wget|curl|sleep|bash|sh\b)|"
    r"(?:%2526%2526|%26%26%25|%25253b)\s*(?:echo|wget|curl)|"
    r"str%25(?:25)?3d%25(?:25)?(?:24|%24)%25(?:25)?28",
    re.I,
)
_RE_WEAK_SQLI_OBF = re.compile(
    r"(?:/\*!?\d*\*/|/\*\*/|#|%23)"
    r"|(?:sel|uni|ins|upd|del)(?:/\*.*?\*/|%09|%0a|%0b)(?:ect|on|ert|ete)"
    r"|(?:or|and)\s*(?:'[^']*'|1e\d*)\s*=\s*(?:'[^']*'|1e\d*)",
    re.I,
)
_RE_WEAK_CMD_OBF = re.compile(
    r"(?:\$\{IFS\}|\{cat,|\|\||%0a)(?:wget|curl|bash|sh\b)",
    re.I,
)


def evasion_rule_scores(
    raw: str,
    norm: str,
    *,
    decode_depth: int = 0,
) -> dict[str, float]:
    """五类高 FN 绕过规则（双重编码/null/unicode/multipart/弱混淆）。"""
    merged: dict[str, float] = {k: 0.0 for k in _ATTACK_PATTERNS}
    low = norm.lower()
    raw_low = raw.lower()
    kw = attack_keyword_scores(low)
    kw_peak = max((v for k, v in kw.items() if k != "Normal"), default=0.0)

    if _RE_DOUBLE_PCT.search(raw_low):
        if _RE_DOUBLE_CMD.search(raw_low) or _encoded_cmd_markers(raw_low):
            merged["CMD"] = max(merged["CMD"], 0.60)
        elif re.search(r"%2527|%2522|%252f", raw_low):
            merged["SQLi"] = max(merged["SQLi"], 0.40)

    if _NULL_IN_VALUE.search(raw_low) or "%00" in raw_low:
        if _FORM_INJ.search(low) or _RE_FORM_CTX.search(low) or decode_depth >= 1:
            merged["SQLi"] = max(merged["SQLi"], 0.55)
            merged["CMD"] = max(merged["CMD"], 0.40)
        elif re.search(r"\w%00\w", raw_low, re.I):
            merged["SQLi"] = max(merged["SQLi"], 0.42)

    if "eval(atob" in raw_low or "eval%28atob" in raw_low:
        if any(k in low for k in ("modo", "login", "pwd", "union", "select", "drop", "insert", "script")):
            merged["SQLi"] = max(merged["SQLi"], 0.62)
            merged["XSS"] = max(merged["XSS"], 0.45)
        elif decode_depth >= 1:
            merged["SQLi"] = max(merged["SQLi"], 0.48)

    if "webkitformboundary" in raw_low:
        if any(k in low for k in ("drop table", "union", "select", "modo=", "login=", "password=")):
            merged["SQLi"] = max(merged["SQLi"], 0.72)

    if _unicode_escape_sqli_signal(raw) or _unicode_escape_sqli_signal(norm):
        merged["SQLi"] = max(merged["SQLi"], 0.55)

    if "webkitformboundary" in raw_low or "boundary*0=" in raw_low:
        body = raw.split("\n\n", 1)[-1] if "\n\n" in raw else raw
        if _HEX32_TOKEN.search(body) or _encoded_cmd_markers(raw_low) or "str=" in low:
            merged["SQLi"] = max(merged["SQLi"], 0.65)
            merged["CMD"] = max(merged["CMD"], 0.65)

    if kw_peak >= 0.12:
        if _RE_WEAK_SQLI_OBF.search(low):
            merged["SQLi"] = max(merged["SQLi"], 0.35)
        if _RE_WEAK_CMD_OBF.search(low):
            merged["CMD"] = max(merged["CMD"], 0.35)

    return {k: v for k, v in merged.items() if v > 0}


def _unicode_escape_sqli_signal(text: str) -> bool:
    if len(_UNICODE_ESCAPE.findall(text)) >= 2:
        decoded = _UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)
        low = decoded.lower()
        if any(k in low for k in ("echo", "sleep", "str=", "union", "select", "modo", "login", "pwd")):
            return True
    return any(k in text.lower() for k in ("\\u006d", "\\u006c", "\\u0070"))


def is_obfuscated(text: str) -> bool:
    if "\x00" in text:
        return True
    low = text.lower()
    if any(m in low for m in OBFUSCATED_MARKERS):
        return True
    return has_fullwidth(text)


def has_fullwidth(text: str) -> bool:
    return any("\uff00" <= c <= "\uffef" for c in text)


def fold_homoglyphs(text: str) -> str:
    """全角/兼容字符折叠为 ASCII，用于 homoglyph echo 等绕过检测。"""
    if not text:
        return text
    out: list[str] = []
    cyr = {"\u0435": "e", "\u043e": "o", "\u0430": "a"}
    for c in text:
        o = ord(c)
        if 0xFF01 <= o <= 0xFF5E:
            out.append(chr(o - 0xFEE0))
        elif c in cyr:
            out.append(cyr[c])
        elif c == "\ufffd":
            continue
        else:
            out.append(c)
    return "".join(out)


def concat_reassembled(text: str) -> str:
    """还原 JS/SQL 字符串 '+' 拼接。"""
    t = _RE_CONCAT_SPLIT.sub("", text)
    return re.sub(r"\s*\+\s*", "", t)


def looks_like_benign_csic_form(raw: str, norm: str) -> bool:
    """
    CSIC 2010 正常登录/注册表单：含 modo/login/password 但无 SQL 注入痕迹。
    用于压误报（占当前 FP 主体）。
    """
    low = (norm or raw).lower()
    raw_low = raw.lower()
    if not _BENIGN_CSIC_PARAMS.search(low):
        return False
    if is_obfuscated(raw) or has_strong_obfuscation(raw):
        return False
    if _SQLI_INJECTION_MARKERS.search(low) or _SQLI_INJECTION_MARKERS.search(raw_low):
        return False
    if "'" in raw or "%27" in raw_low or "%2527" in raw_low:
        return False
    if _RE_CONCAT_SPLIT.search(raw):
        return False
    return True


def _mixed_case_hex32_token(text: str) -> bool:
    s = text.strip()
    if not re.fullmatch(r"[0-9a-fA-F]{32}", s):
        return False
    return any(c.isupper() for c in s) and any(c.islower() for c in s)


def _concat_split_attack_signal(raw: str, norm: str) -> tuple[str, float] | None:
    if not _RE_CONCAT_SPLIT.search(raw):
        return None
    reasm = concat_reassembled(raw).lower()
    kw = attack_keyword_scores(reasm)
    best = max((k for k in kw if k != "Normal"), key=lambda k: kw[k], default=None)
    if best and kw[best] >= 0.15:
        return best, max(kw[best], 0.62)
    if any(x in reasm for x in ("insert", "select", "union", "script", "alert", "drop")):
        return "SQLi", 0.60
    return None


_RE_NULL_SPLICE = re.compile(
    r"[a-z0-9]{2,}(?:%00|\x00)[a-z0-9@.]+"
    r"|(?:%00|\x00)[a-z0-9@.]{3,}"
    r"|[a-f0-9]{16,}(?:%00|\x00)[0-9a-f]*",
    re.I,
)
_RE_SHELL_ECHO_OBF = re.compile(
    r"(?:&&|\|\||%26%26|%7c%7c).{0,24}e?c?h?o"
    r"|(?:^|[?&])e?c?h?o\s*%20"
    r"|\$\(\s*e?c?h?o"
    r"|ech[o0]\$"
    r"|\$\(\s*\d+%2b",
    re.I,
)
_RE_URL_ENCODE_NAME = re.compile(
    r"%2b|%40|%ef%bf%bd|%2c%2b|%2e%2b",
    re.I,
)


def obfuscated_evasion_rescue(
    raw: str,
    norm: str,
    *,
    decode_depth: int = 0,
) -> tuple[str, float] | None:
    """
    混淆逃逸兜底：针对漏检分析 Top 模式（null_byte / echo / homoglyph / url_encode）。
    仅在 is_obfuscated 时触发，避免误伤明文 Normal。
    """
    if not raw or not is_obfuscated(raw):
        return None

    raw_low = raw.lower()
    norm_low = (norm or raw).lower()
    folded = fold_homoglyphs(raw)
    folded_low = folded.lower()

    concat_hit = _concat_split_attack_signal(raw, norm_low)
    if concat_hit is not None:
        return concat_hit
    if _RE_CONCAT_SPLIT.search(raw):
        return "SQLi", 0.58

    if _mixed_case_hex32_token(raw.strip()):
        return "SQLi", 0.65

    if _RE_NULL_SPLICE.search(raw) or _RE_NULL_SPLICE.search(raw_low):
        return "SQLi", 0.72

    if ("\x00" in raw or "%00" in raw_low) and (
        _FORM_INJ.search(raw_low)
        or _RE_FORM_CTX.search(norm_low)
        or _encoded_cmd_markers(raw_low)
    ):
        return "SQLi", 0.78

    shell_text = folded_low
    if _RE_SHELL_ECHO_OBF.search(raw_low) or _RE_SHELL_ECHO_OBF.search(shell_text):
        return "CMD", 0.75

    if folded != raw and re.search(r"echo|\$\(\s*echo", shell_text, re.I):
        return "CMD", 0.72

    if "webkitformboundary" in raw_low:
        if _encoded_cmd_markers(raw_low) or _HEX32_TOKEN.search(raw):
            return "CMD", 0.70
        return "SQLi", 0.62

    if "eval(atob" in raw_low and decode_depth >= 1:
        return "SQLi", 0.68

    pct = raw_low.count("%")
    if pct >= 2 and _RE_URL_ENCODE_NAME.search(raw_low):
        kw = attack_keyword_scores(norm_low)
        if max((v for k, v in kw.items() if k != "Normal"), default=0.0) >= 0.10:
            return "SQLi", 0.58
        if _FORM_INJ.search(norm_low) or _RE_FORM_CTX.search(norm_low):
            return "SQLi", 0.55

    if has_strong_obfuscation(raw_low) and decode_depth >= 1:
        kw = attack_keyword_scores(norm_low)
        best = max((k for k in kw if k != "Normal"), key=lambda k: kw[k], default=None)
        if best and kw[best] >= 0.12:
            return best, max(kw[best], 0.55)

    return None


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
    low = fold_homoglyphs(text).lower()
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

    evasion = evasion_rule_scores(raw, norm, decode_depth=decode_depth)
    for label, w in evasion.items():
        scores[label] = max(scores.get(label, 0.0), w)

    total = sum(scores.values()) or 1.0
    return {k: v / total for k, v in scores.items()}
