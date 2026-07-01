"""AST-level obfuscation mutations for adversarial testing."""

from __future__ import annotations

import random
import re


def ast_obfuscate(payload: str, strategy: str = "random") -> str:
    strategies = {
        "logic_split": _logic_split,
        "charcode_wrap": _charcode_wrap,
        "nested_eval": _nested_eval,
        "comment_inject": _comment_inject,
    }
    fn = strategies.get(strategy, random.choice(list(strategies.values())))
    return fn(payload)


def ast_obfuscate_batch(payload: str, n: int = 5) -> list[str]:
    out = {payload}
    for strat in ("logic_split", "charcode_wrap", "nested_eval", "comment_inject"):
        out.add(ast_obfuscate(payload, strat))
        if len(out) >= n + 1:
            break
    return list(out)[1:]


def _logic_split(s: str) -> str:
    return re.sub(r"(?i)(union|select|script|alert)", lambda m: "'+'".join(m.group(0)), s)


def _charcode_wrap(s: str) -> str:
    if len(s) > 40:
        return s
    codes = ",".join(str(ord(c)) for c in s[:20])
    return f"String.fromCharCode({codes})"


def _nested_eval(s: str) -> str:
    return f"eval(atob('{s[:30]}'))" if len(s) < 30 else f"eval(/*x*/({s}))"


def _comment_inject(s: str) -> str:
    return s.replace(" ", "/**/")
