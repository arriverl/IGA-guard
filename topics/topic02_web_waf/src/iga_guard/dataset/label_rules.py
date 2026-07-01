"""
载荷标签推断规则（Label Inference）
====================================
将二分类/无标签的真实载荷映射为 IGA-Guard 8 类攻击标签。
规则基于 CSIC2010、OWASP、SecLists 常见模式，用于真实数据集对齐。
"""

from __future__ import annotations

import re

ATTACK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)ignore\s+previous|jailbreak|system\s+prompt|do\s+anything\s+now"), "PromptInjection"),
    (re.compile(r"(?i)<!entity|&xxe;|<!doctype[^>]+entity"), "XXE"),
    (re.compile(r"(?i)php://|file://|expect://|zip://|data://"), "FileInclusion"),
    (re.compile(r"(?i)\.\./|/etc/passwd|/proc/self|%2e%2e"), "PathTraversal"),
    (re.compile(r"(?i);\s*(wget|curl|bash|sh|nc|cat|ls|id)\b|\|cat\b|\$\{jndi|&&\s*\w+"), "CMD"),
    (re.compile(r"(?i)<script|onerror\s*=|onload\s*=|javascript:|<svg|<img[^>]+on\w+\s*="), "XSS"),
    (re.compile(
        r"(?i)union\s+select|'\s*or\s+'|;\s*drop\s+|insert\s+into|sleep\s*\(|benchmark\s*\(|"
        r"extractvalue\s*\(|updatexml\s*\(|'\s*=\s*'|information_schema"
    ), "SQLi"),
]


def infer_attack_label(text: str, raw_label: str | None = None) -> str:
    """
    从载荷文本推断攻击类型。

    Args:
        text: 载荷字符串（URL 参数、Body、Cookie 片段等）
        raw_label: 原始标签，如 CSIC 的 norm/anom、或已标注的赛题 label

    Returns:
        Normal 或 8 类攻击标签之一
    """
    if raw_label:
        rl = raw_label.strip()
        if rl in ("Normal", "norm", "0", "benign", "good"):
            return "Normal"
        if rl in ("SQLi", "XSS", "CMD", "PathTraversal", "FileInclusion", "XXE", "PromptInjection"):
            return rl
        if rl in ("anom", "1", "attack", "malicious"):
            pass  # 继续启发式细分
        elif rl != "":
            return rl

    if not text or not text.strip():
        return "Normal"

    sample = text.strip()
    for pat, label in ATTACK_PATTERNS:
        if pat.search(sample):
            return label
    # CSIC 异常样本默认 SQLi（文献：SQLi 占比最高）
    if raw_label in ("anom", "1", "attack", "malicious"):
        return "SQLi"
    return "Normal"


def is_likely_attack(text: str) -> bool:
    return infer_attack_label(text) != "Normal"
