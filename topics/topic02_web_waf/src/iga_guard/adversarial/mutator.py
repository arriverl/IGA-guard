"""
混淆变异器（Obfuscation Mutator）
==================================
为对抗训练 / 数据集扩充生成 SQLi、XSS、CMD 等载荷的混淆变体。

策略：case 大小写、comment 注释插入、encode URL 编码、split 关键词拆分。
供 scripts/generate_dataset.py 与 run_adversarial.py 调用。
"""

from __future__ import annotations

import random
import re
from urllib.parse import quote


def mutate_sqli(payload: str, strategy: str = "random") -> str:
    strategies = {
        "case": _case_obfuscate,
        "comment": _comment_obfuscate,
        "encode": _url_encode,
        "split": _keyword_split,
    }
    fn = strategies.get(strategy, random.choice(list(strategies.values())))
    return fn(payload)


def mutate_xss(payload: str, strategy: str = "random") -> str:
    strategies = {
        "html_encode": _html_encode_partial,
        "svg": _svg_wrap,
        "event": _event_inject,
    }
    fn = strategies.get(strategy, random.choice(list(strategies.values())))
    return fn(payload)


def mutate_batch(payload: str, attack_type: str, n: int = 5) -> list[str]:
    """生成 n 个混淆变体；优先使用 dataset 模块的文献级技术库。"""
    try:
        from iga_guard.dataset.obfuscation_techniques import expand_payload

        variants = expand_payload(payload, attack_type, n=n, seed=hash(payload) % (2**31))
        return [v["payload"] for v in variants]
    except ImportError:
        pass

    mutators = {
        "SQLi": mutate_sqli,
        "XSS": mutate_xss,
    }
    fn = mutators.get(attack_type, mutate_sqli)
    out = {payload}
    for _ in range(n * 2):
        out.add(fn(payload))
        if len(out) >= n + 1:
            break
    return list(out)[1:]


def _case_obfuscate(s: str) -> str:
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)


def _comment_obfuscate(s: str) -> str:
    return s.replace(" ", "/**/")


def _url_encode(s: str) -> str:
    return quote(s, safe="")


def _keyword_split(s: str) -> str:
    return re.sub(r"(?i)union", "uni'+'on", s)


def _html_encode_partial(s: str) -> str:
    return "".join(f"&#{ord(c)};" if random.random() > 0.6 else c for c in s)


def _svg_wrap(s: str) -> str:
    return f"<svg/onload={s}>"


def _event_inject(s: str) -> str:
    return f'<img src=x onerror="{s}">'
