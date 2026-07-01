"""AST-style semantic restoration for obfuscated JS/SQL fragments."""

from __future__ import annotations

import re


def restore_ast(text: str) -> tuple[str, list[str]]:
    """Restore concatenation, char(), fromCharCode, eval wrappers."""
    current = text
    chain: list[str] = []

    restorers = [
        _restore_string_from_charcode,
        _restore_char_function,
        _restore_string_concat,
        _unwrap_eval,
    ]

    for restorer in restorers:
        updated, step = restorer(current)
        if step:
            chain.append(step)
            current = updated

    return current, chain


def _restore_string_from_charcode(text: str) -> tuple[str, str | None]:
    pattern = re.compile(
        r"String\.fromCharCode\(([\d,\s]+)\)",
        re.IGNORECASE,
    )

    def repl(m: re.Match[str]) -> str:
        nums = [int(x.strip()) for x in m.group(1).split(",") if x.strip()]
        return '"' + "".join(chr(n) for n in nums) + '"'

    updated = pattern.sub(repl, text)
    if updated != text:
        return updated, "js_charcode"
    return text, None


def _restore_char_function(text: str) -> tuple[str, str | None]:
    pattern = re.compile(r"char\(([\d,\s]+)\)", re.IGNORECASE)

    def repl(m: re.Match[str]) -> str:
        nums = [int(x.strip()) for x in m.group(1).split(",") if x.strip()]
        return "".join(chr(n) for n in nums)

    updated = pattern.sub(repl, text)
    if updated != text:
        return updated, "sql_char"
    return text, None


def _restore_string_concat(text: str) -> tuple[str, str | None]:
    # 'uni'+'on' or "sel"+"ect"
    pattern = re.compile(r"""(['"])(.*?)\1\s*\+\s*(['"])(.*?)\3""")

    updated = text
    for _ in range(10):
        new = pattern.sub(r"\2\4", updated)
        if new == updated:
            break
        updated = new

    if updated != text:
        return updated, "string_concat"
    return text, None


def _unwrap_eval(text: str) -> tuple[str, str | None]:
    pattern = re.compile(r"eval\s*\(\s*(.+?)\s*\)", re.IGNORECASE | re.DOTALL)
    m = pattern.search(text)
    if m:
        inner = m.group(1).strip().strip('"').strip("'")
        return inner, "eval_unwrap"
    return text, None
