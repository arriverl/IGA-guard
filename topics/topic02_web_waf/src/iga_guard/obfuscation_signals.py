"""混淆载荷特征信号 — 检测器与评估脚本共用。"""

from __future__ import annotations

import base64
import re
from collections import defaultdict
from functools import lru_cache

OBFUSCATED_MARKERS: tuple[str, ...] = (
    "%", "/**/", "fromcharcode", "eval(", "&#", "\\u", "0x", "char(",
    "boundary=", "multipart", "/*!", "%0a", "%09", "webkitformboundary",
    "%252", "\\x", "concat(", "unhex(", "benchmark(", "sleep(",
    "%00", "atob(", "echo%20", "&&echo", "$(echo",
    "'+'", "\"+\"",
    # v3.1 新增
    "between", "${ifs}", "{cat,", "/???/", "php://filter",
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
    "XXE": (
        "<!entity", "<!doctype", "<?xml", "&xxe;", "file:///",
        "<!entity %", "system", "public",
    ),
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
    r"(?:calle|carrer|cami|camin|avenida|paseo|plaza|pla|rambla|passatge|avinguda|travesia|porta)"
    r"(?:\b|[+\s,%])"
    r"|c/(?:[+\s]|%2b|[A-Za-zÁÉÍÓÚÑáéíóúñ])",
    re.I,
)
_BENIGN_ADDRESS_SAFE = re.compile(
    r"^[\w\s\+,\.\-'áéíóúñüàèòç\?%/]+$", re.I,
)
_RE_SPANISH_NAME_TOKEN = re.compile(
    r"^[A-Za-zÁÉÍÓÚÑÜáéíóúñüàèòç]+(?:[+\s][A-Za-zÁÉÍÓÚÑÜáéíóúñüàèòç]+){0,3}$",
)
_SQLI_INJECTION_MARKERS = re.compile(
    r"union\s+select|select\s+.+\s+from|insert\s+into|drop\s+table|sleep\s*\(|benchmark\s*\("
    r"|or\s+1\s*=\s*1|'[^']*'|--|%27|%2527|%2d%2d|0x[0-9a-f]{4,}|;\s*shutdown",
    re.I,
)
_CSIC_ANOMALY_FIELDS = re.compile(
    r"(?:^|[&?])(?:b1a=|b1=\?|b1=%3f|provincia=\||provincia=%7c)"
    r"|pwd=[^&]{0,48}%2b"
    # 参数名尾缀异常：modoA / precioA / loginA / direccionA（CSIC 异常流量常见）
    r"|(?:^|[&?])(?:modo|precio|login|pwd|password|nombre|direccion|cantidad|email)[a-z]\s*="
    # 值内管道 / 问号 / 空格 / 空字段 / 尾斜杠污染
    r"|(?:modo|precio|nombre|cantidad|apellidos|direccion|ciudad)=[^&]*(?:\||%7c)"
    r"|(?:cantidad|b1)=[^&]*(?:\?|%3[fF]|/)"
    r"|(?:b1)=[^&]*/(?:$|&)"
    r"|(?:login|pwd|password|nombre|email|cp|b1)=(?:%20|\+|%2b|\s*|%00|\x00)(?:$|&)"
    r"|(?:login|pwd)=[^&]*%2b"
    r"|(?:pwd|password)=[^&]*[!*,]"
    r"|(?:pwd|password)=[^&]*%3f"
    r"|(?:direccion)=[^&]*\*"
    r"|(?:b1)=[^&]*%20(?:$|&)"
    r"|(?:b1)=[^&]+\s+(?:$|&)"
    r"|remember=on/"
    r"|remember=on%2[fF]"
    # 全 URL 编码表单中的异常参数名（modoA%3D / precioA%3D）
    r"|(?:modo|precio|login|pwd|password|nombre|direccion)[a-z]%3d"
    r"|(?:cantidad|b1)%3d[^&]*(?:%3[fF]|%3f)"
    r"|(?:login|pwd|password|nombre|apellidos|email|cp|b1)%3d(?:%20|%2b|$|%26)"
    r"|(?:apellidos|provincia|direccion)%3d(?:%7c|[^&]*%7c)"
    r"|remember%3don%2[fF]"
    # 解码后管道残留（direccion=... |）
    r"|(?:direccion|apellidos|ciudad)=[^&]*\|"
    r"|(?:email|cp|nombre|pwd)=\s*(?:$|&)",
    re.I,
)
_FULL_URL_ENCODED_FORM = re.compile(
    r"(?:modo|login|password|precio|nombre|b1|id)%3d"
    r".{0,40}%26"
    r".{0,80}(?:%3d|%26)",
    re.I,
)
_RE_HTML_ENTITY_XSS = re.compile(
    r"&#\d+;.{0,120}(?:script|alert|onerror|onload|svg|&#83;&#67;|&#115;&#99;)"
    r"|(?:script|alert|onerror|&#83;&#67;Ri|&#115;&#99;).{0,120}&#\d+;"
    r"|&#\d+;[^&]{0,40}@<&#"
    # 纯数字实体链：&#60;= <  &#115;/&#99;= s/c  &#97;&#108;&#101;&#114;&#116;= alert
    r"|&#\s*0*60\s*;(?:&#\s*\d+\s*;){2,80}"
    r"|(?:&#\s*0*115\s*;|&#\s*0*83\s*;).{0,40}(?:&#\s*0*99\s*;|&#\s*0*67\s*;)"
    r"|(?:&#\s*0*97\s*;).{0,20}(?:&#\s*0*108\s*;).{0,20}(?:&#\s*0*101\s*;).{0,20}(?:&#\s*0*114\s*;)",
    re.I,
)


def _html_entity_xss_signal(raw: str, raw_low: str | None = None) -> bool:
    """检测 HTML 实体 / 半实体 XSS（含破损实体 &#1&#49; 与混杂明文）。"""
    low = raw_low if raw_low is not None else raw.lower()
    if _RE_HTML_ENTITY_XSS.search(raw) or _RE_HTML_ENTITY_XSS.search(low):
        return True
    n_ent = raw.count("&#")
    if n_ent >= 4 and any(
        x in low for x in ("script", "alert", "onerror", "&#115;", "&#99;", "&#97;", "atob")
    ):
        return True
    if n_ent >= 5 and (
        "&#60;" in low or "&#060;" in low or "&#x3c;" in low or "onerror" in low or "atob" in low
    ):
        return True
    # 半实体半明文 / 破损实体
    if "&#" in raw and (
        re.search(r"&#\s*0*60\s*;?\s*s", low)
        or re.search(r"(?:scr|sc&#|s&#\s*0*99)", low)
        or re.search(r"ale&#\s*0*114|aler&#|&#\s*0*97\s*;?l", low)
        or ("onerror" in low and ("&#" in low or "<" in raw))
        or re.search(r"&#\s*1?\s*&#?\s*\d+", low)  # &#1&#49; 破损链
        or ("&&#35;" in low)  # &&#35; = &#
    ):
        return True
    return False
_RE_JSON_NESTED_FORM = re.compile(
    r'\{\s*"a"\s*:\s*\{\s*"b"\s*:\s*"(?:[^"\\]|\\.){4,}"\s*\}\s*\}',
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
    r"|@[b-]?sign\.cg"
    r"|%0a\+b1%3d"
    r"|%0a%2bb1%3d"
    r"|^%40[a-z0-9._-]{2,24}%0a"
    r"|^@[a-z0-9._-]{2,24}\n",
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
_RE_XXE_XML_DECL = re.compile(r"<\?xml\b", re.I)
_RE_XXE_DOCTYPE = re.compile(r"<!doctype\b", re.I)
_RE_XXE_ENTITY = re.compile(r"<!entity\b", re.I)
_RE_XXE_PARAM_ENTITY = re.compile(r"<!entity\s+%", re.I)
_RE_XXE_PE_CHAIN = re.compile(r"%\w+\s*;\s*%\w+", re.I)
_RE_XXE_FILE_URI = re.compile(r"file:///", re.I)
_RE_XXE_SYS_SPLIT = re.compile(
    r'<!entity\s+%[^>]+"sys"[^>]*>.*?<!entity[^>]+"tem"',
    re.I | re.S,
)
_RE_XXE_ENTITY_REF = re.compile(r"&\w+\s*;", re.I)
_RE_XXE_HEX_SYSTEM = re.compile(r"&#x53;&#x59;&#x53;&#x54;&#x45;&#x4d", re.I)
_RE_XXE_HEX_FILE = re.compile(r"&#x66;&#x69;&#x6c;&#x65;&#x3a;&#x2f;&#x2f;&#x2f;", re.I)
_RE_XXE_HEX_PERCENT_ENTITY = re.compile(r"<!ENTITY\s+&#x25;\s*\w+", re.I)
_RE_XXE_LOCAL_DTD = re.compile(r"\.dtd['\"]", re.I)
_RE_XXE_SVG = re.compile(r"<svg\b", re.I)


def _xxe_canonical_text(raw: str, norm: str = "") -> str:
    """XXE 规则匹配前去除 null 间隔等干扰。"""
    merged = f"{raw} {norm}".strip()
    merged = merged.replace("\x00", "")
    merged = re.sub(r"(?i)(?:%00)+", "", merged)
    return merged


def _xxe_deep_view(raw: str, norm: str = "") -> str:
    """上传伪装 + XML 实体展开后的深度视图（动态揭示 hex 混淆 SYSTEM/file:///）。"""
    from iga_guard.normalizer.decoder import (
        expand_xml_entities_for_scan,
        strip_upload_magic_prefix,
    )

    base = _xxe_canonical_text(raw, norm)
    stripped, _ = strip_upload_magic_prefix(base)
    expanded, _ = expand_xml_entities_for_scan(stripped)
    return expanded


def xxe_structure_score(raw: str, norm: str = "") -> float:
    """XML/XXE 结构分：参数实体、DOCTYPE、拆分 SYSTEM、file:///、hex 实体、本地 DTD 等。"""
    merged = _xxe_canonical_text(raw, norm)
    deep = _xxe_deep_view(raw, norm)
    if not merged and not deep:
        return 0.0
    low = deep.lower()
    score = 0.0
    for text in {merged, deep}:
        if _RE_XXE_XML_DECL.search(text):
            score += 0.22
            break
    for text in {merged, deep}:
        if _RE_XXE_DOCTYPE.search(text):
            score += 0.28
            break
    for text in {merged, deep}:
        if _RE_XXE_ENTITY.search(text):
            score += 0.24
            break
    for text in {merged, deep}:
        if _RE_XXE_PARAM_ENTITY.search(text):
            score += 0.32
            break
    if _RE_XXE_PE_CHAIN.search(merged) or _RE_XXE_PE_CHAIN.search(deep):
        score += 0.22
    if _RE_XXE_FILE_URI.search(merged) or _RE_XXE_FILE_URI.search(deep):
        score += 0.38
    if _RE_XXE_SYS_SPLIT.search(merged) or _RE_XXE_SYS_SPLIT.search(deep):
        score += 0.42
    if _RE_XXE_ENTITY_REF.search(deep) and _RE_XXE_ENTITY.search(deep):
        score += 0.18
    if "utf-16" in low and _RE_XXE_DOCTYPE.search(deep):
        score += 0.12
    if _RE_XXE_HEX_SYSTEM.search(merged) or (
        "system" in low and _RE_XXE_PARAM_ENTITY.search(deep)
    ):
        score += 0.36
    if _RE_XXE_HEX_FILE.search(merged) or "file:///" in deep:
        score += 0.40
    if _RE_XXE_HEX_PERCENT_ENTITY.search(merged):
        score += 0.34
    if _RE_XXE_LOCAL_DTD.search(merged) or _RE_XXE_LOCAL_DTD.search(deep):
        score += 0.32
    if _RE_XXE_SVG.search(deep) and _RE_XXE_DOCTYPE.search(deep):
        score += 0.26
    if re.search(r"%\w+\s*;", deep) and _RE_XXE_ENTITY.search(deep):
        score += 0.20
    if "fonts.dtd" in low or "fontconfig" in low:
        score += 0.18
    return min(1.0, score)


def xxe_rescue_label(raw: str, norm: str = "") -> tuple[str, float] | None:
    """明确 XXE 签名时覆盖误分类（如 SQLi / PathTraversal）。"""
    score = xxe_structure_score(raw, norm)
    merged = _xxe_canonical_text(raw, norm).lower()
    deep = _xxe_deep_view(raw, norm)
    deep_low = deep.lower()
    if score >= 0.55:
        return "XXE", max(0.78, score)
    if (
        "<!doctype" in deep_low
        and "<!entity" in deep_low
        and (
            "file:///" in deep_low
            or _RE_XXE_HEX_FILE.search(merged)
            or _RE_XXE_LOCAL_DTD.search(deep)
        )
    ):
        return "XXE", 0.90
    if _RE_XXE_PARAM_ENTITY.search(raw + norm) and (
        _RE_XXE_FILE_URI.search(raw + norm)
        or _RE_XXE_FILE_URI.search(deep)
        or _RE_XXE_HEX_FILE.search(merged)
    ):
        return "XXE", 0.86
    if _RE_XXE_HEX_PERCENT_ENTITY.search(merged) and _RE_XXE_DOCTYPE.search(deep):
        return "XXE", 0.84
    if (
        "<!doctype" in merged
        and "<!entity" in merged
        and "file://" in merged
    ):
        return "XXE", 0.88
    return None


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
        if (
            _RE_XXE_DOCTYPE.search(raw)
            or _RE_XXE_HEX_SYSTEM.search(raw)
            or _RE_XXE_HEX_PERCENT_ENTITY.search(raw)
        ):
            merged["XXE"] = max(merged["XXE"], 0.75)

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


_RE_SCI_NOTATION_OBF = re.compile(r"(?<![0-9a-f])1e0(?![0-9a-f])", re.I)


def is_obfuscated(text: str) -> bool:
    if "\x00" in text:
        return True
    low = text.lower()
    if any(m in low for m in OBFUSCATED_MARKERS):
        return True
    # 科学计数法混淆：需词界，避免误伤 hex token 内的 "1E0"
    if _RE_SCI_NOTATION_OBF.search(low):
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


def has_case_obfuscated_param(raw: str) -> bool:
    """检测参数名大小写混杂（case_random 混淆），不应视为纯良性 CSIC 表单。"""
    for m in _PARAM_PAIRS.finditer(raw or ""):
        name = m.group(1)
        if len(name) >= 3 and name != name.lower() and name != name.upper():
            switches = sum(
                1 for a, b in zip(name, name[1:]) if a.islower() != b.islower()
            )
            if switches >= 1:
                return True
    return False


def looks_like_benign_csic_form(raw: str, norm: str) -> bool:
    """
    CSIC 2010 正常登录/注册/购物表单：含 modo/login/password 等但无 SQL 注入痕迹。
    用于压误报（占当前 FP 主体 ~70%）。
    """
    low = (norm or raw).lower()
    raw_low = raw.lower()
    if has_case_obfuscated_param(raw):
        return False
    # 内联注释拆参（modo/**/=）属于混淆逃逸，不当作良性 CSIC
    if "/**/" in raw or "/*!*/" in raw or "/**/" in low:
        return False
    if not (_BENIGN_CSIC_PARAMS.search(low) or _BENIGN_SHOPPING.search(low)):
        return False
    if _duplicate_params(raw_low):
        return False
    if _CSIC_ANOMALY_FIELDS.search(raw_low) or _CSIC_ANOMALY_FIELDS.search(low):
        return False
    # 全 URL 编码表单（无明文 =）属于混淆逃逸，不当作良性
    if "%3d" in raw_low and "=" not in raw and (
        "modo" in raw_low or "precio" in raw_low or "login" in raw_low
    ):
        return False
    # 购物/登录值尾部异常空白或管道
    if re.search(r"(?:cantidad|b1|precio)=[^&]*(?:\?|%3f|\||%7c|%20(?:$|&))", raw_low):
        return False
    if re.search(r"(?:login|pwd)=[^&]*%2b", raw_low):
        return False
    if re.search(r"(?:pwd|password)=[^&]*%3f", raw_low):
        return False
    if re.search(r"(?:pwd|nombre|apellidos|email|cp)=(?:%20|\||%7c|\+|\s*)(?:$|&)", raw_low):
        return False
    # 任意字段值尾部编码空白污染（...%20 / ...%2520），含 JSON 引号收尾
    if re.search(r"=[^&=]*%(?:20|2520)(?:$|&|\")", raw_low):
        return False
    if "|" in (norm or raw) or "%7c" in raw_low:
        return False
    if "remember=on%2f" in raw_low or "remember%3don%2f" in raw_low:
        return False
    # 关键字段为空 / 仅空白
    if re.search(r"(?:email|cp|nombre|pwd)=\s*(?:$|&)", low):
        return False
    if _LLM_EVASION_MARKERS.search(raw_low) or _LLM_EVASION_MARKERS.search(low):
        return False
    if _MALFORMED_SIGN_PARAM.search(raw_low) or _MALFORMED_SIGN_PARAM.search(low):
        return False
    # 仅畸形 @sign 前缀，不把正常邮箱当成非良性
    if raw_low.startswith("%40") or (norm or raw).lstrip().startswith("@"):
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
    raw_low = (raw or "").lower()
    norm_low = (norm or "").lower()
    # Null-byte / fullwidth / unicode-escape / 管道污染 属混淆逃逸，不得按良性地址放行。
    # 注意：门牌号常用 10?A；加泰罗尼亚地名含 d'… / %27 —— 不得当作注入。
    if "%00" in raw_low or "\x00" in (raw or "") or "%00" in norm_low or "\x00" in (norm or ""):
        return False
    if has_fullwidth(raw) or has_fullwidth(norm or ""):
        return False
    # URL 传输后的全角 UTF-8（%ef%bc / %ef%bd）同样视为混淆
    if "%ef%bc" in raw_low or "%ef%bd" in raw_low or "%ef%bc" in norm_low or "%ef%bd" in norm_low:
        return False
    if len(_UNICODE_ESCAPE.findall(raw or "")) >= 1 or len(_UNICODE_ESCAPE.findall(norm or "")) >= 1:
        return False
    if "|" in (raw or "") or "|" in (norm or "") or "%7c" in raw_low or "%7c" in norm_low:
        return False
    if re.search(r"(?:%0d%0a|%0a|%0d|\r\n|\n)", raw_low) or "set-cookie" in raw_low:
        return False
    # JS/SQL 字符串拼接拆词（Mo'+'rell）属 keyword_concat_split，不当作姓名/地址
    if (
        _RE_CONCAT_SPLIT.search(raw or "")
        or _RE_CONCAT_SPLIT.search(norm or "")
        or "%27%2b%27" in raw_low
        or "%27%2b%27" in norm_low
        or "'+'" in (raw or "")
        or "'+'" in (norm or "")
    ):
        return False
    # 街道词用 %2B/%252B 拼接、或尾部 %2B 污染：数据集 url_encode/double_url 混淆，非正常地址
    if _pct_plus_address_obfuscation(raw_low, norm_low):
        return False
    # 商品字段尾部 %2B 污染（Vino+Rioja%2B）
    if _RE_URLENC_PRODUCT_TAIL.match(raw_low.strip()):
        return False
    text = (norm or raw).strip()
    # 传输层常把空格编成 + / %20；替换字符多为拉丁扩展名损坏
    text = (
        text.replace("+", " ")
        .replace("%20", " ")
        .replace("%2b", " ")
        .replace("%2B", " ")
        .replace("%ef%bf%bd", "a")
        .replace("%EF%BF%BD", "a")
        .replace("\ufffd", "a")
    )
    # 折叠后再判一次：若折叠前后差异大，说明存在同形字伪装
    folded = fold_homoglyphs(text)
    if folded != text and has_fullwidth(raw or norm or ""):
        return False
    low = text.lower()
    if len(text) < 4 or len(text) > 400:
        return False
    addr_like = bool(_BENIGN_ADDRESS.search(low))
    # 强 SQL 注入痕迹才否决；单独的 ' / %27 常见于加泰罗尼亚地名
    if re.search(
        r"union\s+select|select\s+.+\s+from|insert\s+into|drop\s+table|"
        r"sleep\s*\(|benchmark\s*\(|or\s+1\s*=\s*1|--|%2527|%2d%2d|0x[0-9a-f]{4,}",
        low,
        re.I,
    ) or any(
        k in low for k in ("union", "select", "script", "alert", "wget", "eval(", "${jndi")
    ):
        return False
    if addr_like:
        return True
    # 短西班牙姓名（无注入痕迹）；允许损坏的重音字母与 Catalan 撇号
    name_candidate = (
        text.replace("%20", " ").replace("%27", "'").replace("&#39;", "'")
    )
    if 4 <= len(name_candidate) <= 48 and (
        _RE_SPANISH_NAME_TOKEN.match(name_candidate.replace("'", ""))
        or re.fullmatch(
            r"[A-Za-zÁÉÍÓÚÑÜáéíóúñüàèòça'\s\-]{4,48}",
            name_candidate,
        )
    ):
        if not _FORM_INJ.search(low) and sum(ch.isalpha() for ch in name_candidate) >= 4:
            return True
    # SAFE：允许门牌 ? 与 URL 编码残留（%2C/%27 等）
    safe_text = text.replace("%27", "'").replace("%2c", ",").replace("%2C", ",")
    if _BENIGN_ADDRESS_SAFE.match(safe_text) or _BENIGN_ADDRESS_SAFE.match(
        re.sub(r"%[0-9a-fA-F]{2}", " ", text)
    ):
        if not _FORM_INJ.search(low):
            alpha_n = sum(ch.isalpha() for ch in text)
            if (" " in text or "+" in (raw or "") or "%2b" in raw_low) and alpha_n >= 6:
                return True
            if addr_like and alpha_n >= 4:
                return True
    if _BENIGN_ADDRESS_SAFE.match(text) and not _FORM_INJ.search(low):
        if " " in text and sum(ch.isalpha() for ch in text) >= 6:
            return True
    return False


def is_benign_traffic_context(raw: str, norm: str | None = None) -> bool:
    """聚合良性流量判定：CSIC 表单 / 购物 / 地址。"""
    n = norm if norm is not None else raw
    raw_low = (raw or "").lower()
    # 关键混淆形态：禁止走良性快路径
    if has_fullwidth(raw) or has_fullwidth(n or ""):
        return False
    if len(_UNICODE_ESCAPE.findall(raw or "")) >= 2:
        return False
    if "%00" in raw_low or "\x00" in (raw or ""):
        return False
    if "|" in (raw or "") or "%7c" in raw_low or _CSIC_ANOMALY_FIELDS.search(raw_low):
        return False
    if (
        _RE_CONCAT_SPLIT.search(raw or "")
        or "%27%2b%27" in raw_low
        or "'+'" in (raw or "")
    ):
        return False
    if re.search(r"(?:%0d%0a|%0a|%0d|\r\n|\n).{0,8}set-cookie", raw_low, re.I):
        return False
    if re.search(r"set-cookie\s*%3a", raw_low, re.I):
        return False
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


def _upper_hex32_token(text: str) -> bool:
    """全大写 32 位 hex（CSIC anomalous 常见伪装 token）。"""
    s = text.strip()
    return bool(re.fullmatch(r"[0-9A-F]{32}", s)) and any(c.isalpha() for c in s)


def _decode_url_form_once(text: str) -> str:
    """轻量 URL 解码，供 rescue 在 raw 全编码时对齐 norm。"""
    try:
        from urllib.parse import unquote_plus
        return unquote_plus(text)
    except Exception:
        return text


def _json_nested_inner(text: str) -> str | None:
    """提取 {"a":{"b":"..."}} 内层载荷。"""
    m = re.search(r'\{\s*"a"\s*:\s*\{\s*"b"\s*:\s*"(.*?)"\s*\}\s*\}', text or "", re.S)
    if not m:
        return None
    inner = m.group(1).replace('\\"', '"').replace("\\\\", "\\")
    return inner


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
_RE_URLENC_ADDRESS_TAIL = re.compile(
    r"^(?:calle|avenida|paseo|plaza|travesia|rambla|carrer|cami|passatge|avinguda)"
    r"(?:%252b|%2b)[^\r\n&]{1,120}$",
    re.I,
)
_RE_URLENC_PRODUCT_TAIL = re.compile(
    r"^(?:vino|queso|jam(?:on|%c3%b3n)|iberico)(?:\+|%2b|%252b)[^\r\n&]{0,48}(?:%2b|%252b)$",
    re.I,
)
_RE_PCT_STREET_JOIN = re.compile(
    r"(?:calle|avenida|paseo|plaza|travesia|rambla|carrer|cami|passatge|avinguda|c/%2f)"
    r"(?:%252b|%2b)",
    re.I,
)


def _pct_plus_address_obfuscation(raw_low: str, norm_low: str = "") -> bool:
    """url_encode / double_url_encode 地址：用 %2B 拼词或尾部 %2B。

    若 norm 已是「纯 + 分隔」地址（无 %），则 raw 中的 %2B 视为传输层 quote，不抬升。
    """
    s = (raw_low or "").strip()
    if not s or "=" in s or "&" in s:
        return False
    n = (norm_low or "").strip()
    # 解码态已是正常 + 地址：跳过（避免 Ballena,+91 / Calle+Cubas 被 quote 后误报）
    if n and "%" not in n and ("+" in n or " " in n):
        decoded_addr = bool(_BENIGN_ADDRESS.search(n.replace("+", " ").lower()))
        plain_safe = bool(
            _BENIGN_ADDRESS_SAFE.match(n.replace("+", " "))
            or _BENIGN_ADDRESS_SAFE.match(n)
        )
        if decoded_addr or plain_safe:
            # 仅保留双编码痕迹（%252），单层传输编码不抬升
            if "%252" not in s:
                return False
    decoded = (
        s.replace("%252b", " ")
        .replace("%2b", " ")
        .replace("%252c", ",")
        .replace("%2c", ",")
        .replace("+", " ")
        .replace("%252f", "/")
        .replace("%2f", "/")
    )
    streetish = bool(
        _RE_PCT_STREET_JOIN.search(s)
        or _RE_URLENC_ADDRESS_TAIL.match(s)
        or _BENIGN_ADDRESS.search(decoded)
    )
    if not streetish:
        return False
    if re.search(r"(?:%252b|%2b)$", s):
        return True
    if s.count("%252b") >= 2 or ("%252c" in s and "%252b" in s):
        return True
    if "%253f" in s:
        return True
    if (s.count("%2b") + s.count("%252b")) >= 2:
        return True
    return False


_DISCOVERED_STORE = None


def _discovered_rescue_store():
    global _DISCOVERED_STORE
    if _DISCOVERED_STORE is None:
        from iga_guard.evolution.discovered_rescue_rules import DiscoveredRescueRules

        _DISCOVERED_STORE = DiscoveredRescueRules()
    return _DISCOVERED_STORE


def reload_discovered_rescue_rules() -> None:
    """miss→rule 闭环写入后热重载动态规则。"""
    global _DISCOVERED_STORE
    if _DISCOVERED_STORE is not None:
        _DISCOVERED_STORE.load()
    obfuscated_evasion_rescue_cached.cache_clear()


@lru_cache(maxsize=8192)
def obfuscated_evasion_rescue_cached(
    raw: str,
    norm: str,
    decode_depth: int,
) -> tuple[str, float] | None:
    """
    混淆逃逸兜底：针对漏检分析 Top 模式（null_byte / echo / homoglyph / url_encode）。
    仅在 is_obfuscated 时触发，避免误伤明文 Normal。
    """
    if not raw:
        return None
    raw_strip = raw.strip()
    hpp_hex_camouflage = bool(
        _duplicate_params(raw.lower())
        and any(
            _standalone_hex32_token(v)
            or _mixed_case_hex32_token(v)
            or _upper_hex32_token(v)
            for v in _hpp_attack_values(raw)
        )
    )
    if not (
        is_obfuscated(raw)
        or _RE_BOOL_LIKE_SQLI.search(raw)
        or _mixed_case_hex32_token(raw_strip)
        or _unicode_escaped_hex32_token(raw_strip)
        or hpp_hex_camouflage
        or _FULL_URL_ENCODED_FORM.search(raw)
        or has_case_obfuscated_param(raw)
        or _json_nested_inner(raw) is not None
        or _RE_HTML_ENTITY_XSS.search(raw)
        or _html_entity_xss_signal(raw)
        or _LLM_EVASION_MARKERS.search(raw)
        or _LLM_DYNAMIC_URL_MARKERS.search(raw)
        or _LLM_ENCODED_XSS_BURST.search(raw)
        or _LLM_HIGH_BYTE_CMD_BURST.search(raw)
        or _OPAQUE_ENCODED_URL.search(raw)
        or _MALFORMED_SIGN_PARAM.search(raw)
        or _DYNAMIC_ADVERSARIAL_MARKERS.search(raw)
        or xxe_structure_score(raw, norm or raw) >= 0.45
    ):
        return None

    xxe_hit = xxe_rescue_label(raw, norm or raw)
    if xxe_hit is not None:
        return xxe_hit

    raw_low = raw.lower()
    norm_low = (norm or raw).lower()
    folded = fold_homoglyphs(raw)
    folded_low = folded.lower()
    decoded_form = _decode_url_form_once(raw)
    decoded_form_low = decoded_form.lower()

    # CSIC anomalous 字段污染：优先于其它分支，覆盖拆参前的整表单
    if (
        _CSIC_ANOMALY_FIELDS.search(raw_low)
        or _CSIC_ANOMALY_FIELDS.search(norm_low)
        or _CSIC_ANOMALY_FIELDS.search(decoded_form_low)
        or "|" in decoded_form
    ):
        if (
            _FORM_INJ.search(raw_low)
            or _RE_FORM_CTX.search(raw_low)
            or _BENIGN_CSIC_PARAMS.search(raw_low)
            or _BENIGN_SHOPPING.search(raw_low)
            or _FORM_INJ.search(decoded_form_low)
            or _RE_FORM_CTX.search(decoded_form_low)
            or _BENIGN_CSIC_PARAMS.search(decoded_form_low)
            or _BENIGN_SHOPPING.search(decoded_form_low)
            or _FORM_INJ.search(norm_low)
            or _RE_FORM_CTX.search(norm_low)
        ):
            cmd_hint = (
                _encoded_cmd_markers(raw_low)
                or _encoded_cmd_markers(decoded_form_low)
                or any(
                    k in raw_low
                    for k in (
                        "&&",
                        "%26%26",
                        "|echo",
                        "%7cecho",
                        "wget",
                        "curl",
                        "bash",
                        "sh%20",
                        "str%3d%24%28echo",
                        "$(echo",
                    )
                )
            )
            if cmd_hint:
                return "CMD", 0.68
            return "SQLi", 0.66

    concat_hit = _concat_split_attack_signal(raw, norm_low)
    if concat_hit is not None:
        return concat_hit
    if _RE_CONCAT_SPLIT.search(raw) or "%27%2b%27" in raw_low or "%27%2B%27" in raw:
        return "SQLi", 0.58

    if _RE_BOOL_LIKE_SQLI.search(raw_low) or _RE_BOOL_LIKE_SQLI.search(norm_low):
        return "SQLi", 0.74

    # CRLF / 响应头注入（CSIC anomalous + case_random）：%0aSet-Cookie / Set-cookie%3A+Tamper
    if re.search(
        r"(?:%0d%0a|%0a|%0d|\r\n|\n).{0,8}set-cookie",
        raw_low,
        re.I,
    ) or re.search(r"set-cookie\s*%3a\s*\+?tamper", raw_low, re.I):
        return "SQLi", 0.72

    # 独立 hex32 在 Normal 中大量出现（会话/哈希），禁止裸 token 直接判恶意。
    # 仅当伴随 SQL/HPP 结构时才抬升。
    if _standalone_hex32_token(raw_strip) and (
        _RE_BOOL_LIKE_SQLI.search(raw_low) or "&" in raw_low or "?" in raw_low
    ):
        return "SQLi", 0.62

    # 独立大小写混杂 hex32：CSIC anomalous 伪装 token（测试/数据集约定）
    if _mixed_case_hex32_token(raw_strip):
        return "SQLi", 0.65
    hex_val = raw_strip.split("=", 1)[-1] if "=" in raw_strip and "&" not in raw_strip else ""
    if hex_val and _mixed_case_hex32_token(hex_val) and (
        _RE_BOOL_LIKE_SQLI.search(raw_low)
        or _FORM_INJ.search(raw_low)
        or _RE_FORM_CTX.search(raw_low)
    ):
        return "SQLi", 0.65

    if _unicode_escaped_hex32_token(raw_strip):
        return "SQLi", 0.66

    # 仅当伴随 SQL 结构/HPP 时，高熵 token 才视为攻击伪装，避免把正常 ID 打成 SQLi。
    if _high_entropy_camouflage_token(raw_strip) and (
        _RE_BOOL_LIKE_SQLI.search(raw_low) or "&" in raw_low or "?" in raw_low
    ):
        return "SQLi", 0.66

    # 仅真实 HPP（重复参数名）才用重复值做 hex/高熵伪装抬升，避免 token=HEX 误报
    dup_keys = _duplicate_params(raw_low)
    if dup_keys:
        dup_vals = _hpp_attack_values(raw)
        for fragment in dup_vals:
            frag_low = fragment.lower()
            if any(x in frag_low for x in ("<script", "alert(", "union", "select", "jndi:", "${")):
                return "XSS" if "script" in frag_low or "alert" in frag_low else "SQLi", 0.70
            if _standalone_hex32_token(fragment) or _mixed_case_hex32_token(fragment):
                return "SQLi", 0.64
            if _high_entropy_camouflage_token(fragment):
                return "SQLi", 0.72

    # 空字节拼接：有明确 shell 痕迹时优先 CMD，避免被 SQLi 高置信覆盖
    if ("\x00" in raw or "%00" in raw_low) and (
        _encoded_cmd_markers(raw_low)
        or _RE_SHELL_ECHO_OBF.search(raw_low)
        or any(
            x in raw_low
            for x in (
                "$(echo", "str%3d%24", "str%3d%24%28echo", "sleep%20",
                " -ne ", " -eq ", "%20-ne%20", "%20-eq%20",
            )
        )
    ):
        return "CMD", 0.78

    if _RE_NULL_SPLICE.search(raw) or _RE_NULL_SPLICE.search(raw_low):
        return "SQLi", 0.72

    if ("\x00" in raw or "%00" in raw_low) and (
        _FORM_INJ.search(raw_low) or _RE_FORM_CTX.search(norm_low)
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
            xxe_pt = xxe_rescue_label(raw, norm_low)
            if xxe_pt is not None:
                return xxe_pt
            return "PathTraversal", 0.70
        if "passw%68" in raw_low or "logina=" in raw_low:
            return "CMD", 0.62
        return "SQLi", 0.66

    # 仅双重编码邮箱 (%2540) 视为逃逸；单次 %40 是传输层对正常邮箱的编码，禁止抬升
    if "%2540" in raw_low and re.fullmatch(
        r"[a-z0-9_.+-]+%2540[a-z0-9_.-]+\.[a-z]{2,}", raw_low, re.I,
    ):
        return "SQLi", 0.57

    # 替换字符逃逸：仅双重编码或伴随注入痕迹；单次 %EF%BF%BD 常见于拉丁姓名损坏
    if "%25ef%25bf%25bd" in raw_low:
        return "SQLi", 0.57
    if (
        "%ef%bf%bd" in raw_low
        and decode_depth >= 1
        and _SQLI_INJECTION_MARKERS.search(raw_low)
        and not looks_like_benign_address(raw, norm_low)
    ):
        return "SQLi", 0.57

    pct = raw_low.count("%")
    if (_FORM_INJ.search(norm_low) or _RE_FORM_CTX.search(norm_low)) and (
        _CSIC_ANOMALY_FIELDS.search(raw_low) or _CSIC_ANOMALY_FIELDS.search(norm_low)
    ):
        return "SQLi", 0.56

    # 全 URL 编码表单：解码后检查异常字段 / 注入痕迹
    if _FULL_URL_ENCODED_FORM.search(raw_low) or (
        pct >= 4 and "%3d" in raw_low and "%26" in raw_low
    ):
        if _CSIC_ANOMALY_FIELDS.search(raw_low) or _CSIC_ANOMALY_FIELDS.search(decoded_form_low):
            if _encoded_cmd_markers(raw_low) or _encoded_cmd_markers(decoded_form_low):
                return "CMD", 0.66
            return "SQLi", 0.66
        if (
            _FORM_INJ.search(decoded_form_low)
            or _RE_FORM_CTX.search(decoded_form_low)
            or "modo=" in decoded_form_low
            or "precio=" in decoded_form_low
        ):
            # 全编码 CSIC 表单本身即混淆逃逸样本（source=url_encode）
            if (
                _SQLI_INJECTION_MARKERS.search(decoded_form_low)
                or "|" in decoded_form
                or decoded_form_low.rstrip().endswith("/")
                or re.search(r"(?:modo|precio|login|pwd|password|nombre|direccion)[a-z]\s*=", decoded_form_low)
                or re.search(r"(?:cantidad|b1)=[^&]*[?%]", decoded_form_low)
                or "%20" in raw_low[-6:]
                or raw_low.rstrip().endswith("%2f")
                or "," in decoded_form  # pwd 内逗号等异常字符
            ):
                if _encoded_cmd_markers(raw_low) or _encoded_cmd_markers(decoded_form_low):
                    return "CMD", 0.64
                return "SQLi", 0.64
            # 纯全编码表单：仅在存在异常痕迹时抬升，避免误伤正常编码表单
            if (
                "=" not in raw
                and ("%3d" in raw_low or "%253d" in raw_low)
                and (
                    _CSIC_ANOMALY_FIELDS.search(decoded_form_low)
                    or "|" in decoded_form
                    or decoded_form_low.rstrip().endswith("/")
                    or re.search(r"(?:pwd|password)=[^&]*[!*,]", decoded_form_low)
                    or "remember=on/" in decoded_form_low
                )
            ):
                return "SQLi", 0.60

    if pct >= 2 and ("%3d" in raw_low or "%26" in raw_low):
        if _CSIC_ANOMALY_FIELDS.search(raw_low) or _CSIC_ANOMALY_FIELDS.search(norm_low):
            return "SQLi", 0.62
        if (
            (_FORM_INJ.search(norm_low) or _RE_FORM_CTX.search(norm_low)
             or _FORM_INJ.search(decoded_form_low) or _RE_FORM_CTX.search(decoded_form_low))
            and (
                _SQLI_INJECTION_MARKERS.search(raw_low)
                or _SQLI_INJECTION_MARKERS.search(norm_low)
                or "'" in raw
                or "%27" in raw_low
                or "%2527" in raw_low
                or _RE_NULL_SPLICE.search(raw_low)
                or "|" in decoded_form
            )
        ):
            return "SQLi", 0.55

    if pct >= 2 and _RE_URL_ENCODE_NAME.search(raw_low):
        kw = attack_keyword_scores(norm_low)
        if max((v for k, v in kw.items() if k != "Normal"), default=0.0) >= 0.10:
            return "SQLi", 0.58
        if _CSIC_ANOMALY_FIELDS.search(raw_low) or _CSIC_ANOMALY_FIELDS.search(decoded_form_low):
            return "SQLi", 0.60
        if (
            (_FORM_INJ.search(norm_low) or _RE_FORM_CTX.search(norm_low)
             or _FORM_INJ.search(decoded_form_low) or _RE_FORM_CTX.search(decoded_form_low))
            and (
                _SQLI_INJECTION_MARKERS.search(raw_low)
                or "'" in raw
                or "%27" in raw_low
                or "%2527" in raw_low
                or _RE_NULL_SPLICE.search(raw_low)
            )
        ):
            return "SQLi", 0.55

    # 长尾窄规则：地址/商品孤立片段 + 尾部编码污染。
    # 街道 %2B 拼接 / 尾 %2B / 双编码 即使「看起来像地址」也抬升（控 FPR：不含普通 + 分隔门牌）。
    if "=" not in raw and "&" not in raw and is_obfuscated(raw):
        if _pct_plus_address_obfuscation(raw_low, norm_low):
            return "SQLi", 0.74
        # 商品尾部 %2B：要求 norm/raw 仍带编码尾，避免纯 + 商品被 quote 误报
        if _RE_URLENC_PRODUCT_TAIL.match(raw_low) and (
            "%2b" in (norm_low or "")
            or "%252b" in raw_low
            or re.search(r"(?:vino|queso|jam).{0,40}%2b$", (norm_low or raw_low), re.I)
        ):
            return "SQLi", 0.74
        enc_hits = (
            raw_low.count("%2b")
            + raw_low.count("%252b")
            + raw_low.count("%20")
            + raw_low.count("%2520")
        )
        # null-byte splice in isolated field
        if "%00" in raw_low or "\x00" in raw:
            return "SQLi", 0.74
        # double-url / multi-encoding pollution（norm 已是纯 + 良性文本则跳过，防传输 quote 误报）
        norm_plain = (norm_low or "")
        transport_only = bool(
            norm_plain
            and "%" not in norm_plain
            and looks_like_benign_address(norm_plain, norm_plain)
        )
        if (
            (enc_hits >= 2 or "%252" in raw_low or raw_low.count("%25") >= 2)
            and not looks_like_benign_address(raw, norm_low)
            and not transport_only
        ):
            return "SQLi", 0.74
        # single encoding only when NOT address-like (avoid Normal street FP)
        if (
            enc_hits >= 1
            and 4 <= len(raw_strip) <= 96
            and not looks_like_benign_address(raw, norm_low)
            and not transport_only
        ):
            return "SQLi", 0.73

    # unicode_escape：独立于「孤立字段」门控（\\u0069d=| 等本身含 '='）
    # ≥2 即救援；单条则解码后查异常结构 / 注入痕迹（控 FPR）
    esc_n = len(_UNICODE_ESCAPE.findall(raw))
    if esc_n >= 2 and not looks_like_benign_address(raw, norm_low):
        return "SQLi", 0.73
    if esc_n >= 1:
        decoded_u = _UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), raw)
        decoded_u_low = decoded_u.lower()
        if (
            "|" in decoded_u
            or "?" in decoded_u
            or _CSIC_ANOMALY_FIELDS.search(decoded_u_low)
            or _FORM_INJ.search(decoded_u_low)
            or _SQLI_INJECTION_MARKERS.search(decoded_u_low)
            or re.search(r"(?:^|[&?])id\s*=", decoded_u_low)
        ):
            return "SQLi", 0.74

    # 全角同形字：CSIC unicode_normalization 关键逃逸，默认抬升（真正常地址极少含全角）
    if has_fullwidth(raw):
        folded_form = fold_homoglyphs(raw)
        folded_form_low = folded_form.lower()
        if (
            "|" in folded_form
            or "?" in folded_form
            or _CSIC_ANOMALY_FIELDS.search(folded_form_low)
            or _FORM_INJ.search(folded_form_low)
            or re.search(r"(?:^|[&?])id\s*=", folded_form_low)
            or _BENIGN_ADDRESS.search(folded_form_low)
            or _RE_SPANISH_NAME_TOKEN.match(folded_form.replace("+", " ").strip()[:48] or "")
            or (4 <= len(raw.strip()) <= 96 and "=" not in raw and "&" not in raw)
        ):
            return "SQLi", 0.74

    # 内联注释拆参：modo/**/=/**/registro 等（混淆逃逸 SQLi）
    if "/**/" in raw and (
        _BENIGN_CSIC_PARAMS.search(raw_low.replace("/**/", ""))
        or _RE_FORM_CTX.search(raw_low.replace("/**/", ""))
        or re.search(r"(?:modo|login|password|precio)/\*\*/=", raw_low)
    ):
        return "SQLi", 0.66

    # case_random：参数名大小写混杂，且伴随异常值才抬升
    if has_case_obfuscated_param(raw):
        if (
            _CSIC_ANOMALY_FIELDS.search(raw_low)
            or _CSIC_ANOMALY_FIELDS.search(norm_low)
            or "|" in raw
            or "%7c" in raw_low
            or re.search(r"(?:cantidad|b1|nombre)=[^&]*[?%|]", raw_low)
            or re.search(r"(?:direccion|apellidos)=[^&]*[?|]", raw_low)
        ):
            return "SQLi", 0.63

    # JSON 嵌套逃逸：展开内层，仅异常/注入痕迹抬升
    inner = _json_nested_inner(raw)
    if inner is not None:
        inner_low = inner.lower()
        if (
            _CSIC_ANOMALY_FIELDS.search(inner_low)
            or _SQLI_INJECTION_MARKERS.search(inner_low)
            or "|" in inner
            or "%3f" in inner_low
            or "%00" in inner_low
            or re.search(r"(?:b1|cantidad|nombre|pwd|email)=(?:%20|\+|%2b|\s*)(?:$|&|\")", inner_low)
            or re.search(r"=(?:[^&\"=]{0,80})%(?:20|2520)(?:$|&|\")", inner_low)
            or re.search(r"(?:pwd|password)=[^&\"%]*%3f", inner_low)
            or (len(inner.strip()) <= 8 and "%" in inner)  # 短异常片段 %2B / %20
        ):
            return "SQLi", 0.66

    # HTML 实体混淆 XSS（含纯数字实体链 / 实体与明文混杂 / 破损实体）
    if _html_entity_xss_signal(raw, raw_low):
        return "XSS", 0.70

    if has_strong_obfuscation(raw_low) and decode_depth >= 1:
        kw = attack_keyword_scores(norm_low)
        best = max((k for k in kw if k != "Normal"), key=lambda k: kw[k], default=None)
        if best and kw[best] >= 0.12:
            return best, max(kw[best], 0.55)

    discovered = _discovered_rescue_store().match(raw, norm_low)
    if discovered is not None:
        return discovered

    return None


def obfuscated_evasion_rescue(
    raw: str,
    norm: str,
    *,
    decode_depth: int = 0,
) -> tuple[str, float] | None:
    """对外入口：先查动态规则，再走 LRU 缓存的静态 rescue。"""
    if not raw:
        return None
    norm_text = norm or raw
    discovered = _discovered_rescue_store().match(raw, norm_text.lower())
    if discovered is not None:
        return discovered
    return obfuscated_evasion_rescue_cached(raw, norm_text, int(decode_depth))


def _eval_atob_decoded_attack(raw: str) -> tuple[str, float] | None:
    """eval(atob('...')) 碎片拼接：解码 B64 后查攻击语义。"""
    raw_low = raw.lower()
    if "eval(atob" not in raw_low and "eval%28atob" not in raw_low:
        return None
    m = re.search(r"atob\s*\(\s*['\"]([A-Za-z0-9+/=]+)['\"]\s*\)", raw, re.I)
    if not m:
        # 无完整 B64 时结合外层 shell 痕迹，避免默认 SQLi 吞掉 CMD
        if _encoded_cmd_markers(raw_low) or any(
            x in raw_low for x in ("sleep", "echo", "|tr", "wc-c", "wc%20", "%7c%7c")
        ):
            return "CMD", 0.62
        return "SQLi", 0.60
    try:
        pad = m.group(1) + "=" * (-len(m.group(1)) % 4)
        decoded = base64.b64decode(pad).decode("utf-8", errors="ignore").lower()
    except Exception:
        if _encoded_cmd_markers(raw_low):
            return "CMD", 0.60
        return "SQLi", 0.58
    # URL 二次解码（atob 内常嵌 %20/%24%28echo 等）
    try:
        from urllib.parse import unquote

        decoded_u = unquote(unquote(decoded)).lower()
    except Exception:
        decoded_u = decoded
    blob = f"{decoded} {decoded_u} {raw_low}"
    cmd_hits = (
        "echo", "wget", "curl", "sleep", "bash", "$(", "${",
        "&&", "||", "wc -c", "wc%20", "tr -d", "tr%20-d",
        "%28echo", "$(echo", "str=$(",
    )
    if any(k in blob for k in cmd_hits) or _encoded_cmd_markers(blob):
        return "CMD", 0.76
    if any(k in decoded_u for k in ("union", "select", "drop", "insert", "script", "alert", "waitfor")):
        return "SQLi", 0.74
    if any(k in decoded_u for k in ("modo", "login", "password", "pwd")):
        return "SQLi", 0.68
    # 外层已有 shell 管道/sleep 时优先 CMD
    if any(x in raw_low for x in ("sleep", "|tr", "wc -c", "%7c%7c", "||")):
        return "CMD", 0.68
    return "SQLi", 0.62


def arbitrate_attack_label(
    label: str,
    confidence: float,
    *,
    raw: str,
    norm: str,
    all_probs: dict[str, float] | None = None,
    kw: dict[str, float] | None = None,
    st: dict[str, float] | None = None,
    decode_depth: int = 0,
) -> tuple[str, float]:
    """
    多分类仲裁：在已判定恶意时纠正 CMD↔SQLi 等边界误分。
    不改变 Normal / 非恶意决策，避免抬高 FPR。
    """
    if label == "Normal":
        return label, confidence
    raw_low = (raw or "").lower()
    norm_low = (norm or "").lower()
    kw = kw or attack_keyword_scores(norm_low or raw_low)
    st = st or structural_attack_scores(raw, norm, decode_depth=decode_depth)
    probs = all_probs or {}
    kw_cmd = float(kw.get("CMD", 0.0))
    kw_sqli = float(kw.get("SQLi", 0.0))
    st_cmd = float(st.get("CMD", 0.0))
    st_sqli = float(st.get("SQLi", 0.0))
    p_cmd = float(probs.get("CMD", 0.0))
    p_sqli = float(probs.get("SQLi", 0.0))

    atob_hit = _eval_atob_decoded_attack(raw or "")
    if atob_hit is not None and atob_hit[0] == "CMD":
        return "CMD", max(confidence, atob_hit[1])

    cmd_marker = _encoded_cmd_markers(raw_low) or _encoded_cmd_markers(norm_low)
    shellish = any(
        x in raw_low or x in norm_low
        for x in (
            "$(echo", "&&echo", "%0aecho", "|echo", "sleep 0", "sleep 1",
            " -ne ", " -eq ", "%20-ne%20", "%20-eq%20",
            "wc -c", "tr -d", "${#str}", "str=$(", "str%3d%24%28echo",
        )
    )
    strong_cmd = cmd_marker or shellish or kw_cmd >= 0.45 or st_cmd >= 0.40

    # SQLi 被误标但规则强烈指向 CMD
    if label == "SQLi" and strong_cmd and (
        kw_cmd >= kw_sqli + 0.12
        or st_cmd >= st_sqli + 0.08
        or (cmd_marker and kw_cmd >= 0.35)
        or (shellish and "union" not in norm_low and "select" not in norm_low)
    ):
        return "CMD", max(confidence, 0.72, kw_cmd, st_cmd)

    # 融合概率 CMD 已领先但仍被标成 SQLi
    if label == "SQLi" and p_cmd >= p_sqli + 0.05 and (kw_cmd >= 0.30 or cmd_marker):
        return "CMD", max(confidence, p_cmd, 0.70)

    # 反向：明确 SQL 关键字时避免被弱 CMD 噪声翻走
    if label == "CMD" and (
        ("union" in norm_low and "select" in norm_low)
        or ("information_schema" in norm_low)
    ) and not cmd_marker and kw_sqli >= kw_cmd + 0.15:
        return "SQLi", max(confidence, 0.70, kw_sqli)

    kw_xss = float(kw.get("XSS", 0.0))
    st_xss = float(st.get("XSS", 0.0))
    kw_path = float(kw.get("PathTraversal", 0.0))
    st_path = float(st.get("PathTraversal", 0.0))
    kw_fi = float(kw.get("FileInclusion", 0.0))
    st_fi = float(st.get("FileInclusion", 0.0))
    p_xss = float(probs.get("XSS", 0.0))

    xss_markers = any(
        x in raw_low or x in norm_low
        for x in (
            "<script", "</script", "onerror=", "onload=", "onmouseover=",
            "javascript:", "svg/onload", "<svg", "<img", "fromcharcode",
            "document.cookie", "&#60;script", "%3cscript",
        )
    )
    path_markers = any(
        x in raw_low or x in norm_low
        for x in (
            "../", "..\\", "%2e%2e%2f", "%2e%2e/", "....//", "etc/passwd",
            "windows/system32", "boot.ini",
        )
    )
    fi_markers = any(
        x in raw_low or x in norm_low
        for x in (
            "php://", "file://", "expect://", "zip://", "phar://",
            "input://", "data://text", "filter/convert",
        )
    )

    # XSS mislabeled as SQLi / CMD
    if label in ("SQLi", "CMD") and (xss_markers or kw_xss >= 0.45 or st_xss >= 0.40) and (
        kw_xss >= kw_sqli + 0.08
        or st_xss >= st_sqli + 0.08
        or (xss_markers and "union" not in norm_low and "select" not in norm_low)
        or p_xss >= float(probs.get(label, 0.0)) + 0.05
    ):
        return "XSS", max(confidence, 0.72, kw_xss, st_xss, p_xss)

    # PathTraversal vs FileInclusion
    if label == "FileInclusion" and path_markers and not fi_markers and (
        kw_path + st_path >= kw_fi + st_fi + 0.05
    ):
        return "PathTraversal", max(confidence, 0.70, kw_path, st_path)
    if label == "PathTraversal" and fi_markers and (
        kw_fi + st_fi >= kw_path + st_path
        or "php://" in norm_low
        or "expect://" in norm_low
    ):
        return "FileInclusion", max(confidence, 0.72, kw_fi, st_fi)

    # SQLi mislabeled as XSS when clear SQL shape dominates
    if label == "XSS" and (
        ("union" in norm_low and "select" in norm_low)
        or "information_schema" in norm_low
    ) and not xss_markers and kw_sqli >= kw_xss + 0.12:
        return "SQLi", max(confidence, 0.70, kw_sqli)

    return label, confidence


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
    xxe_s = xxe_structure_score(text, text)
    if xxe_s >= 0.40:
        scores["XXE"] += 0.45 + xxe_s * 0.4
        scores["PathTraversal"] *= 0.4
        scores["SQLi"] *= 0.7
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
        # 关键混淆形态即使被误标良性，也不要一票否决结构分
        if not (
            has_fullwidth(raw)
            or has_fullwidth(norm or "")
            or len(_UNICODE_ESCAPE.findall(raw or "")) >= 2
            or "%00" in (raw or "").lower()
        ):
            return {k: (0.92 if k == "Normal" else 0.01) for k in _ATTACK_PATTERNS}
    scores = {k: 0.0 for k in _ATTACK_PATTERNS}
    scores["Normal"] = 0.05
    low = norm.lower()
    raw_low = raw.lower()
    # 全角同形字：折叠后补充结构分
    if has_fullwidth(raw) or has_fullwidth(norm or ""):
        scores["SQLi"] += 0.45
    if len(_UNICODE_ESCAPE.findall(raw or "")) >= 2:
        scores["SQLi"] += 0.40
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

    # 时间盲注式 shell（CSIC/CMD 混淆长尾）：sleep + 条件测试 / 管道
    if (
        ("sleep" in raw_low or "sleep%20" in raw_low)
        and any(x in raw_low for x in (" -ne ", " -eq ", "%20-ne%20", "%20-eq%20", "||", "%7c%7c", "wc"))
    ):
        scores["CMD"] += 0.50
    if "str%3d%24%28echo" in raw_low or "str=$(echo" in raw_low or "${#str}" in raw_low:
        scores["CMD"] += 0.45

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

    xxe_s = xxe_structure_score(raw, norm)
    if xxe_s >= 0.45:
        scores["XXE"] += 0.55 + xxe_s * 0.35
        scores["PathTraversal"] *= 0.35
        scores["SQLi"] *= 0.65

    if "data:text/html" in raw_low or "ontoggle=" in raw_low:
        scores["XSS"] += 0.55

    if "${ifs}" in raw_low or "{cat," in raw_low or "/???/" in raw_low:
        scores["CMD"] += 0.5

    if "%c0%af" in raw_low or "..;/" in raw_low or "%u2215" in raw_low:
        scores["PathTraversal"] += 0.55
    if re.search(r"(?:\.\.|%2e%2e).{0,8}%c0%af", raw_low):
        scores["PathTraversal"] += 0.45
    # overlong UTF-8 路径穿越：即使 passwd 被大小写打散也抬升
    if "%c0%af" in raw_low and ("etc" in raw_low or "passwd" in raw_low or "pas" in raw_low):
        scores["PathTraversal"] += 0.35

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
