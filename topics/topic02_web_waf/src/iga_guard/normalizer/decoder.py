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

    cleaned, null_step = strip_null_interleave(current)
    if null_step:
        current = cleaned
        chain.append(null_step)

    stripped, magic_step = strip_upload_magic_prefix(current)
    if magic_step:
        current = stripped
        chain.append(magic_step)

    expanded, entity_steps = expand_xml_entities_for_scan(current)
    if entity_steps:
        current = expanded
        chain.extend(entity_steps)

    return current, chain


_UPLOAD_MAGIC = (
    b"\xff\xd8\xff\xdb",
    b"\xff\xd8\xff\xe0",
    b"\xff\xd8\xff\xee",
    b"\x89PNG\r\n\x1a\n",
    b"GIF89a",
)


def strip_upload_magic_prefix(text: str) -> tuple[str, str | None]:
    """剥离上传伪装 Magic Bytes（JPEG/PNG/GIF）或二进制前缀后的 XML。"""
    if not text:
        return text, None
    try:
        blob = text.encode("latin-1")
    except Exception:
        blob = text.encode("utf-8", errors="ignore")
    for magic in _UPLOAD_MAGIC:
        if blob.startswith(magic):
            rest = blob[len(magic) :].decode("utf-8", errors="replace").lstrip("\x00\r\n\t ")
            return rest, "upload_magic_strip"
    m = re.search(r"<\?xml", text, re.I)
    if m and 0 < m.start() <= 64:
        return text[m.start() :], "binary_prefix_strip"
    return text, None


def expand_xml_entities_for_scan(text: str, max_rounds: int = 4) -> tuple[str, list[str]]:
    """展开 XML 数值/十六进制实体（&#x53; → S），用于动态揭示 XXE 混淆。"""
    chain: list[str] = []
    current = text
    for _ in range(max_rounds):
        prev = current
        current = re.sub(
            r"&#x([0-9a-fA-F]+);",
            lambda m: chr(int(m.group(1), 16))
            if int(m.group(1), 16) < 0x110000
            else m.group(0),
            current,
        )
        current = re.sub(
            r"&#(\d+);",
            lambda m: chr(int(m.group(1))) if int(m.group(1), 10) < 0x110000 else m.group(0),
            current,
        )
        if current != prev:
            chain.append("xml_entity_expand")
        else:
            break
    return current, chain


def strip_null_interleave(text: str) -> tuple[str, str | None]:
    """剥离字符间插入的 null byte（%00%3c%00%3f… 解码后的形态）。"""
    if not text:
        return text, None
    literal_nulls = text.count("\x00")
    if literal_nulls >= 3 and literal_nulls / max(len(text), 1) >= 0.08:
        cleaned = text.replace("\x00", "")
        if cleaned != text:
            return cleaned, "null_interleave_strip"
    return text, None


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
