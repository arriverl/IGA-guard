"""Payload AST and HTML DOM structural features."""

from __future__ import annotations

import re


def ast_depth(payload: str) -> float:
    """Approximate nesting depth from brackets/tags."""
    depth = 0
    max_depth = 0
    for ch in payload:
        if ch in "([{<":
            depth += 1
            max_depth = max(max_depth, depth)
        elif ch in ")]}>":
            depth = max(0, depth - 1)
    return float(max_depth)


def html_dom_node_count(payload: str) -> float:
    return float(len(re.findall(r"<[a-zA-Z][^>]*>", payload)))


def js_call_count(payload: str) -> float:
    return float(len(re.findall(r"\w+\s*\(", payload)))


def xml_entity_count(payload: str) -> float:
    return float(len(re.findall(r"&\w+;", payload)))


def extract_structural(payload: str) -> dict[str, float]:
    return {
        "ast_depth": ast_depth(payload),
        "html_nodes": html_dom_node_count(payload),
        "js_calls": js_call_count(payload),
        "xml_entities": xml_entity_count(payload),
        "angle_bracket_ratio": payload.count("<") / max(len(payload), 1),
    }
