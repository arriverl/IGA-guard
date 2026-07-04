"""
多层载荷解码器（Payload Decoder）
==================================
对抗混淆逃逸的核心预处理：迭代解码直至稳定或达到 max_rounds。

支持链式变换：
  URL 编码 → Base64 → HTML 实体 → Unicode 转义 → 十六进制

返回：(净化后文本, 解码链列表) 供特征提取与可解释性展示。
"""

from __future__ import annotations

import base64
import html
import re
from urllib.parse import unquote, unquote_plus


def decode_payload(raw: str, max_rounds: int = 5) -> tuple[str, list[str]]:
    """Iteratively decode until stable or max_rounds reached."""
    current = raw
    chain: list[str] = []
    fw = _normalize_fullwidth(current)
    if fw != current:
        current = fw
        chain.append("fullwidth_norm")

    for _ in range(max_rounds):
        prev = current
        current, step = _decode_once(current)
        if step:
            chain.append(step)
        if current == prev:
            break
    return current, chain


def _decode_once(text: str) -> tuple[str, str | None]:
    stripped = text.strip()

    # Base64 in eval(atob(...)) — common XSS/SQLi obfuscation
    if "atob(" in stripped.lower():
        import re as _re
        m = _re.search(r"atob\(['\"]([A-Za-z0-9+/=]+)['\"]\)", stripped, _re.I)
        if m:
            try:
                decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
                if decoded != stripped:
                    return decoded, "atob_decode"
            except Exception:
                pass

    # URL encoding
    if "%" in stripped:
        # 三重 URL 编码（%25253d 等）
        if "%2525" in stripped or stripped.count("%") >= 6:
            prev = stripped
            decoded = stripped
            for _ in range(3):
                try:
                    decoded = unquote(unquote_plus(decoded))
                except Exception:
                    break
            if decoded != prev:
                return decoded, "triple_url_decode"
        try:
            decoded = unquote(unquote_plus(stripped))
            if decoded != stripped:
                return decoded, "url_decode"
        except Exception:
            pass

    # 编码态 null byte：%00 / %2500
    if re.search(r"%(?:25)*0{2}", stripped, re.I):
        decoded = re.sub(r"%(?:25)*0{2}", "\x00", stripped, flags=re.I)
        if decoded != stripped:
            return decoded, "encoded_null_byte"

    # HTML entities
    if "&" in stripped and ";" in stripped:
        decoded = html.unescape(stripped)
        if decoded != stripped:
            return decoded, "html_entity"

    # JS \uXXXX
    if "\\u" in stripped.lower():
        try:
            decoded = _decode_js_unicode(stripped)
            if decoded != stripped:
                return decoded, "js_unicode"
        except Exception:
            pass

    # Hex \xNN
    if "\\x" in stripped.lower():
        try:
            decoded = bytes(stripped, "utf-8").decode("unicode_escape")
            if decoded != stripped:
                return decoded, "hex_escape"
        except Exception:
            pass

    # Base64 (heuristic: alphanumeric + padding, decodes to printable)
    if re.fullmatch(r"[A-Za-z0-9+/=]{8,}", stripped):
        try:
            decoded_bytes = base64.b64decode(stripped, validate=True)
            decoded = decoded_bytes.decode("utf-8", errors="strict")
            if decoded and decoded.isprintable():
                return decoded, "base64"
        except Exception:
            pass

    return stripped, None


def _normalize_fullwidth(text: str) -> str:
    """全角英数字 → 半角（社区 homoglyph 绕过）。"""
    out: list[str] = []
    for c in text:
        o = ord(c)
        if 0xFF01 <= o <= 0xFF5E:
            out.append(chr(o - 0xFEE0))
        elif o == 0x3000:
            out.append(" ")
        else:
            out.append(c)
    return "".join(out)


def _decode_js_unicode(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        return chr(int(match.group(1), 16))

    return re.sub(r"\\u([0-9a-fA-F]{4})", repl, text)
