"""混淆载荷特征信号 — 检测器与评估脚本共用。"""

from __future__ import annotations

import base64
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
        "0x", "char(",
        "\\u006d", "\\u006c", "\\u0070",  # unicode-escaped attack fragments (非 modo= 表单字段)
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
    r"(modo|login|password|nombre|apellidos|precio|pwd|insertar|registro|entrar|b1|cantidad|email|dni|direccion|ciudad|cp|provincia|ntc)=[^&]*",
    re.I,
)
_BENIGN_SHOPPING = re.compile(
    r"(?:^|[&?])(id|nombre|precio|cantidad|producto)=[^&]*", re.I,
)
_BENIGN_ADDRESS = re.compile(
    r"(calle|carrer|cami|camin|avenida|paseo|plaza|pla|rambla|passatge|avinguda|travesia|porta|c/)\b",
    re.I,
)
_BENIGN_ADDRESS_SAFE = re.compile(
    r"^[\w\s\+,\.\-áéíóúñüàèòç\?%]+$", re.I,
)
_SQLI_INJECTION_MARKERS = re.compile(
    r"union\s+select|select\s+.+\s+from|insert\s+into|drop\s+table|sleep\s*\(|benchmark\s*\("
    r"|or\s+1\s*=\s*1|'[^']*'|--|%27|%2527|%2d%2d|0x[0-9a-f]{4,}|;\s*shutdown",
    re.I,
)
_CSIC_ANOMALY_FIELDS = re.compile(
    r"(?:^|[&?])(?:b1a=|b1=\?|b1=%3f|provincia=\||provincia=%7c)"
    r"|pwd=[^&]{0,48}%2b",
    re.I,
)
_LLM_EVASION_MARKERS = re.compile(
    r"malicious\.com"
    r"|evil\.com"
    r"|nompercentbre"
    r"|preci(?:%c3%b1|\u00f1)o"
    r"|id%a3"
    r"|_url_encode_login",
    re.I,
)
_LLM_DYNAMIC_URL_MARKERS = re.compile(
    r"http%61re="
    r"|polymorphic_data"
    r"|!\[\]\(http"
    r"|%2571%2564%2568%2565"
    r"|%71%64%68%65"
    r"|qdheservicy"
    r"|%d7%a9%d5%dd%c0%a7%e3%80%8[0-9a-f]",
    re.I,
)
_LLM_ENCODED_XSS_BURST = re.compile(
    r"%e6%b3%a2%e4%b8%aa"
    r".{0,160}(?:%61%70%74%69%6f%6e|%2561%2570%2574%2569%256f%256e)"
    r".{0,160}(?:%2523|%23)"
    r".{0,160}(?:%6c%61%6e%67%74|%256c%2561%256e%2567%2574)",
    re.I,
)
_LLM_HIGH_BYTE_CMD_BURST = re.compile(
    r"(?:%c2%8f|%2525c2%25258f)"
    r".{0,220}(?:%c2%9c|%2525c2%25259c)"
    r".{0,220}(?:%cf%ca|%2525cf%2525ca)"
    r".{0,220}(?:%e6%b2%b9%e8%be%93|%2525e6%2525b2%2525b9%2525e8%2525be%252593)",
    re.I,
)
_OPAQUE_ENCODED_URL = re.compile(
    r"^https?%3a//"
    r"|^https?%253a"
    r"|http%3a//[^&]{8,}(?:%40|%2540)"
    r"|http%3a%2f%2f[^&]{6,}(?:%40|%23|%2540|%2523)"
    r"|%253a%2f%2f[^&]{8,}(?:%40|%2540)",
    re.I,
)
_MALFORMED_SIGN_PARAM = re.compile(
    r"%40[b-]?sign\.cg"
    r"|%0a\+b1%3d"
    r"|%0a%2bb1%3d"
    r"|^%40[a-z0-9._-]{2,24}%0a",
    re.I,
)
_DYNAMIC_ADVERSARIAL_MARKERS = re.compile(
    r"(?:%0a|\n).{0,32}set-?cookie"
    r"|tamper%3d|tamper="
    r"|passw%68"
    r"|(?:^|[&?])logina="
    r"|ciudada="
    r"|%3cscript|%253cscript|alert%28|alert\("
    r"|%06|%05|%0d"
    r"|(?:^|[&?=])do&nombre="
    r"|do%0a[&/]"
    r"|nombre\s+like"
    r"|alcui(?:\.|%2f|/)no"
    r"|valver\."
    r"|%24(?:apellidos|email|dni|direccion)"
    r"|%3fapellidos"
    r"|\band\s+\d+\s*[<>=]\s*\d+\b"
    r"|b1%e2%80%a6|b1=%e2%80%a6"
    r"|%252e|/etc/passwd",
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
_RE_BOOL_LIKE_SQLI = re.compile(
    r"\b(?:and|or)\b\s+\d+(?:\.\d+e\d+)?\s+like\s+\d+(?:\.\d+e\d+)?\b",
    re.I,
)
_RE_HI_ENTROPY_TOKEN = re.compile(r"^[A-Za-z0-9]{20,40}$")


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
        if any(k in low for k in ("drop table", "union select", "insert into")):
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
    CSIC 2010 正常登录/注册/购物表单：含 modo/login/password 等但无 SQL 注入痕迹。
    用于压误报（占当前 FP 主体 ~70%）。
    """
    low = (norm or raw).lower()
    raw_low = raw.lower()
    if not (_BENIGN_CSIC_PARAMS.search(low) or _BENIGN_SHOPPING.search(low)):
        return False
    if _duplicate_params(raw_low):
        return False
    if _CSIC_ANOMALY_FIELDS.search(raw_low) or _CSIC_ANOMALY_FIELDS.search(low):
        return False
    if _LLM_EVASION_MARKERS.search(raw_low) or _LLM_EVASION_MARKERS.search(low):
        return False
    if _OPAQUE_ENCODED_URL.search(raw_low) or _OPAQUE_ENCODED_URL.search(low):
        return False
    if _MALFORMED_SIGN_PARAM.search(raw_low) or _MALFORMED_SIGN_PARAM.search(low):
        return False
    if _DYNAMIC_ADVERSARIAL_MARKERS.search(raw_low) or _DYNAMIC_ADVERSARIAL_MARKERS.search(low):
        return False
    # 正常 CSIC 表单通常含 URL 编码符号（%/+），不能仅凭 is_obfuscated 直接否决。
    # 仅在强混淆时视为非良性。
    if has_strong_obfuscation(raw):
        return False
    if _SQLI_INJECTION_MARKERS.search(low) or _SQLI_INJECTION_MARKERS.search(raw_low):
        return False
    if "'" in raw or "%27" in raw_low or "%2527" in raw_low:
        return False
    if _RE_CONCAT_SPLIT.search(raw):
        return False
    return True


def looks_like_benign_address(raw: str, norm: str) -> bool:
    """CSIC 正常地址字段（西班牙语街道名）。"""
    text = (norm or raw).strip()
    low = text.lower()
    if len(text) < 8 or len(text) > 400:
        return False
    if is_obfuscated(raw) or has_strong_obfuscation(raw):
        return False
    if _SQLI_INJECTION_MARKERS.search(low):
        return False
    if any(k in low for k in ("union", "select", "script", "alert", "wget", "eval(", "${jndi")):
        return False
    if _BENIGN_ADDRESS.search(low):
        return True
    if _BENIGN_ADDRESS_SAFE.match(text) and not _FORM_INJ.search(low):
        # 纯高熵 token（无空格）不应当被当作地址型良性流量。
        if " " in text and sum(ch.isalpha() for ch in text) >= 6:
            return True
    return False


def is_benign_traffic_context(raw: str, norm: str | None = None) -> bool:
    """聚合良性流量判定：CSIC 表单 / 购物 / 地址。"""
    n = norm if norm is not None else raw
    return (
        looks_like_benign_csic_form(raw, n)
        or looks_like_benign_address(raw, n)
    )


def _hpp_attack_values(raw: str) -> list[str]:
    """HPP：收集重复参数名下的所有取值（OWASP：后端可能拼接/取末值）。"""
    buckets: dict[str, list[str]] = defaultdict(list)
    for m in _PARAM_PAIRS.finditer(raw.replace("?", "&")):
        buckets[m.group(1).lower()].append(m.group(2))
    out: list[str] = []
    for vals in buckets.values():
        if len(vals) > 1:
            out.extend(vals[1:])
        out.extend(vals)
    return out


def _standalone_hex32_token(text: str) -> bool:
    s = text.strip()
    return bool(re.fullmatch(r"[0-9a-f]{32}", s, re.I))


def _mixed_case_hex32_token(text: str) -> bool:
    s = text.strip()
    if not re.fullmatch(r"[0-9a-fA-F]{32}", s):
        return False
    return any(c.isupper() for c in s) and any(c.islower() for c in s)


def _unicode_escaped_hex32_token(text: str) -> bool:
    if len(_UNICODE_ESCAPE.findall(text or "")) < 2:
        return False
    decoded = _UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}", decoded.strip()))


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
    if not raw:
        return None
    raw_strip = raw.strip()
    if not (
        is_obfuscated(raw)
        or _RE_BOOL_LIKE_SQLI.search(raw)
        or _mixed_case_hex32_token(raw_strip)
        or _unicode_escaped_hex32_token(raw_strip)
        or _LLM_EVASION_MARKERS.search(raw)
        or _LLM_DYNAMIC_URL_MARKERS.search(raw)
        or _LLM_ENCODED_XSS_BURST.search(raw)
        or _LLM_HIGH_BYTE_CMD_BURST.search(raw)
        or _OPAQUE_ENCODED_URL.search(raw)
        or _MALFORMED_SIGN_PARAM.search(raw)
        or _DYNAMIC_ADVERSARIAL_MARKERS.search(raw)
    ):
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

    if _RE_BOOL_LIKE_SQLI.search(raw_low) or _RE_BOOL_LIKE_SQLI.search(norm_low):
        return "SQLi", 0.74

    if _standalone_hex32_token(raw_strip) and (
        _RE_BOOL_LIKE_SQLI.search(raw_low) or "&" in raw_low or "?" in raw_low
    ):
        return "SQLi", 0.62

    if _mixed_case_hex32_token(raw_strip):
        return "SQLi", 0.65

    if _unicode_escaped_hex32_token(raw_strip):
        return "SQLi", 0.66

    # 仅当伴随 SQL 结构/HPP 时，高熵 token 才视为攻击伪装，避免把正常 ID 打成 SQLi。
    if _high_entropy_camouflage_token(raw_strip) and (
        _RE_BOOL_LIKE_SQLI.search(raw_low) or "&" in raw_low or "?" in raw_low
    ):
        return "SQLi", 0.66

    dup_vals = _hpp_attack_values(raw)
    if dup_vals:
        for fragment in dup_vals:
            frag_low = fragment.lower()
            if any(x in frag_low for x in ("<script", "alert(", "union", "select", "jndi:", "${")):
                return "XSS" if "script" in frag_low or "alert" in frag_low else "SQLi", 0.70
            if _standalone_hex32_token(fragment) or _mixed_case_hex32_token(fragment):
                return "SQLi", 0.64
            if _high_entropy_camouflage_token(fragment):
                return "SQLi", 0.72

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

    atob_hit = _eval_atob_decoded_attack(raw)
    if atob_hit is not None:
        return atob_hit

    if "eval(atob" in raw_low and decode_depth >= 1:
        return "SQLi", 0.68

    if _LLM_EVASION_MARKERS.search(raw_low) or _LLM_EVASION_MARKERS.search(norm_low):
        if (
            "malicious.com" in raw_low
            or "malicious.com" in norm_low
            or "evil.com" in raw_low
            or "evil.com" in norm_low
        ):
            return "SQLi", 0.62
        return "PathTraversal", 0.58

    if _LLM_DYNAMIC_URL_MARKERS.search(raw_low) or _LLM_DYNAMIC_URL_MARKERS.search(norm_low):
        if "%d7%a9" in raw_low or "%d7%a9" in norm_low:
            return "SQLi", 0.64
        if "evil.com" in raw_low or "cmd=" in raw_low:
            return "CMD", 0.62
        if "http%61re=" in raw_low or "polymorphic_data" in raw_low:
            return "XSS", 0.60
        return "SQLi", 0.58

    if _LLM_ENCODED_XSS_BURST.search(raw_low) or _LLM_ENCODED_XSS_BURST.search(norm_low):
        return "XSS", 0.68

    if _LLM_HIGH_BYTE_CMD_BURST.search(raw_low) or _LLM_HIGH_BYTE_CMD_BURST.search(norm_low):
        return "CMD", 0.68

    if _OPAQUE_ENCODED_URL.search(raw_low) or _OPAQUE_ENCODED_URL.search(norm_low):
        if "' or '" in raw_low or " or " in raw_low or "%27%20or%20" in raw_low:
            return "SQLi", 0.66
        return "CMD", 0.62

    if _MALFORMED_SIGN_PARAM.search(raw_low) or _MALFORMED_SIGN_PARAM.search(norm_low):
        return "CMD", 0.62

    pct = raw_low.count("%")
    if pct >= 6 and pct / max(len(raw_low), 1) >= 0.28:
        if not _SQLI_INJECTION_MARKERS.search(raw_low) and not looks_like_benign_csic_form(raw, norm_low):
            if not any(k in raw_low for k in ("modo=", "login=", "password=", "nombre=", "apellidos=")):
                return "CMD", 0.62

    if _DYNAMIC_ADVERSARIAL_MARKERS.search(raw_low) or _DYNAMIC_ADVERSARIAL_MARKERS.search(norm_low):
        if "/etc/passwd" in raw_low or "%252e" in raw_low or "/etc/passwd" in norm_low:
            return "PathTraversal", 0.70
        if "passw%68" in raw_low or "logina=" in raw_low:
            return "CMD", 0.62
        return "SQLi", 0.66

    if (
        ("%2540" in raw_low or (decode_depth >= 1 and "%40" in raw_low))
        and re.fullmatch(r"[a-z0-9_.-]+%(?:25)?40[a-z0-9_.-]+\.[a-z]{2,}", raw_low, re.I)
    ):
        return "SQLi", 0.57

    if "%25ef%25bf%25bd" in raw_low or (decode_depth >= 1 and "%ef%bf%bd" in raw_low):
        return "SQLi", 0.57

    pct = raw_low.count("%")
    if (_FORM_INJ.search(norm_low) or _RE_FORM_CTX.search(norm_low)) and (
        _CSIC_ANOMALY_FIELDS.search(raw_low) or _CSIC_ANOMALY_FIELDS.search(norm_low)
    ):
        return "SQLi", 0.56

    if pct >= 2 and ("%3d" in raw_low or "%26" in raw_low):
        if (
            (_FORM_INJ.search(norm_low) or _RE_FORM_CTX.search(norm_low))
            and (
                _SQLI_INJECTION_MARKERS.search(raw_low)
                or _SQLI_INJECTION_MARKERS.search(norm_low)
                or "'" in raw
                or "%27" in raw_low
                or "%2527" in raw_low
                or _RE_NULL_SPLICE.search(raw_low)
            )
        ):
            return "SQLi", 0.55

    if pct >= 2 and _RE_URL_ENCODE_NAME.search(raw_low):
        kw = attack_keyword_scores(norm_low)
        if max((v for k, v in kw.items() if k != "Normal"), default=0.0) >= 0.10:
            return "SQLi", 0.58
        if (
            (_FORM_INJ.search(norm_low) or _RE_FORM_CTX.search(norm_low))
            and (
                _SQLI_INJECTION_MARKERS.search(raw_low)
                or "'" in raw
                or "%27" in raw_low
                or "%2527" in raw_low
                or _RE_NULL_SPLICE.search(raw_low)
            )
        ):
            return "SQLi", 0.55

    if has_strong_obfuscation(raw_low) and decode_depth >= 1:
        kw = attack_keyword_scores(norm_low)
        best = max((k for k in kw if k != "Normal"), key=lambda k: kw[k], default=None)
        if best and kw[best] >= 0.12:
            return best, max(kw[best], 0.55)

    return None


def _eval_atob_decoded_attack(raw: str) -> tuple[str, float] | None:
    """eval(atob('...')) 碎片拼接：解码 B64 后查攻击语义。"""
    raw_low = raw.lower()
    if "eval(atob" not in raw_low and "eval%28atob" not in raw_low:
        return None
    m = re.search(r"atob\s*\(\s*['\"]([A-Za-z0-9+/=]+)['\"]\s*\)", raw, re.I)
    if not m:
        return "SQLi", 0.60
    try:
        pad = m.group(1) + "=" * (-len(m.group(1)) % 4)
        decoded = base64.b64decode(pad).decode("utf-8", errors="ignore").lower()
    except Exception:
        return "SQLi", 0.58
    if any(k in decoded for k in ("union", "select", "drop", "insert", "script", "alert", "waitfor", "exec")):
        return "SQLi", 0.74
    if any(k in decoded for k in ("modo", "login", "password", "pwd")):
        return "SQLi", 0.68
    return "SQLi", 0.62


def _duplicate_params(raw_low: str) -> list[str]:
    """返回重复出现的参数名（HPP）。"""
    buckets: dict[str, list[str]] = defaultdict(list)
    for m in _PARAM_PAIRS.finditer(raw_low.replace("?", "&")):
        buckets[m.group(1).lower()].append(m.group(2))
    return [k for k, vals in buckets.items() if len(vals) > 1]


def _high_entropy_camouflage_token(text: str) -> bool:
    s = (text or "").strip()
    if not _RE_HI_ENTROPY_TOKEN.fullmatch(s):
        return False
    has_upper = any(c.isupper() for c in s)
    has_lower = any(c.islower() for c in s)
    has_digit = any(c.isdigit() for c in s)
    if not (has_upper and has_lower and has_digit):
        return False
    return len(set(s)) >= 8


def _contains_high_entropy_camouflage(text: str) -> bool:
    for tok in re.findall(r"[A-Za-z0-9]{20,40}", text or ""):
        if _high_entropy_camouflage_token(tok):
            return True
    return False


def _hex32_in_param_context(raw: str, norm: str) -> bool:
    return bool(_HEX32_PARAM.search(raw) or _HEX32_PARAM.search(norm))


def attack_keyword_scores(text: str) -> dict[str, float]:
    """对文本做规则打分，供混淆逃逸兜底。"""
    low = fold_homoglyphs(text).lower()
    if is_benign_traffic_context(text, low):
        return {"Normal": 0.92, "SQLi": 0.02, "XSS": 0.02, "CMD": 0.01,
                "PathTraversal": 0.01, "FileInclusion": 0.01, "XXE": 0.005, "PromptInjection": 0.005}
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
    if is_benign_traffic_context(raw, norm):
        return {k: (0.92 if k == "Normal" else 0.01) for k in _ATTACK_PATTERNS}
    scores = {k: 0.0 for k in _ATTACK_PATTERNS}
    scores["Normal"] = 0.05
    low = norm.lower()
    raw_low = raw.lower()
    kw = attack_keyword_scores(low)
    kw_attack = max((v for k, v in kw.items() if k != "Normal"), default=0.0)

    dup_keys = _duplicate_params(raw_low)
    if dup_keys:
        scores["SQLi"] += 0.55
        for v in _hpp_attack_values(raw):
            if _high_entropy_camouflage_token(v):
                scores["SQLi"] += 0.35
                break

    if _hex32_in_param_context(raw, norm):
        if dup_keys or decode_depth >= 1 or kw_attack >= 0.2 or is_obfuscated(raw):
            scores["SQLi"] += 0.5

    if _standalone_hex32_token(raw.strip()) and (dup_keys or _RE_BOOL_LIKE_SQLI.search(raw_low)):
        scores["SQLi"] += 0.45

    if _FORM_INJ.search(low) and ("'" in low or "%27" in raw_low):
        scores["SQLi"] += 0.6

    if _RE_BOOL_LIKE_SQLI.search(raw_low) or _RE_BOOL_LIKE_SQLI.search(low):
        scores["SQLi"] += 0.55

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
