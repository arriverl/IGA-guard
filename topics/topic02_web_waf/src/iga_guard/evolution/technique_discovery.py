"""从漏检样本推断新混淆手法并写入注册表。"""

from __future__ import annotations

import re
from urllib.parse import unquote_plus

from iga_guard.evolution.technique_registry import TechniqueRegistry

# 启发式：payload 特征 → (template, 建议 technique 名前缀)
_HEURISTICS: list[tuple[str, str, str]] = [
    (r"%25%25", "repeat_url_encode", "discovered_triple_url"),
    (r"%25[0-9a-fA-F]{2}", "double_url_encode_plus", "discovered_double_url"),
    (r"\\x00|%00|\x00", "insert_null_byte", "discovered_null_byte"),
    (r"/\*.*?\*/", "deep_inline_comment", "discovered_comment"),
    (r"[\u200b-\u200d\ufeff]", "zero_width_inject", "discovered_zero_width"),
    (r"0x[0-9a-fA-F]{2,}", "hex_wrap_keywords", "discovered_hex_wrap"),
]


def _encoding_depth(payload: str) -> int:
    depth = 0
    cur = payload
    for _ in range(6):
        if "%" not in cur:
            break
        nxt = unquote_plus(cur)
        if nxt == cur:
            break
        depth += 1
        cur = nxt
    return depth


def infer_templates(payload: str) -> list[str]:
    """从漏检载荷推断可能有效的 transform template。"""
    found: list[str] = []
    for pattern, template, _ in _HEURISTICS:
        if re.search(pattern, payload) and template not in found:
            found.append(template)
    depth = _encoding_depth(payload)
    if depth >= 3 and "repeat_url_encode" not in found:
        found.append("repeat_url_encode")
    elif depth == 2 and "double_url_encode_plus" not in found:
        found.append("double_url_encode_plus")
    # 大小写混乱
    if payload != payload.lower() and payload != payload.upper():
        if "mixed_case_burst" not in found:
            found.append("mixed_case_burst")
    return found


def discover_from_miss(
    registry: TechniqueRegistry,
    payload: str,
    attack_type: str,
    *,
    counter: int | None = None,
) -> list[str]:
    """
    分析漏检样本，注册尚未存在的新手法。
    返回本轮新注册的 technique 名列表。
    """
    registered: list[str] = []
    templates = infer_templates(payload)
    idx = counter if counter is not None else len(registry.techniques)
    for template in templates:
        if any(m.get("template") == template for m in registry.techniques.values()):
            continue
        name = f"discovered_{template}_{idx}"
        idx += 1
        if registry.register(
            name,
            template=template,
            attack_types=[attack_type] if attack_type != "Normal" else [],
            source_miss=payload,
        ):
            registered.append(name)
    return registered
