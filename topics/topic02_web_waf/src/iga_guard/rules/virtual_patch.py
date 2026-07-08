"""Virtual patching for emerging CVE payloads."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import unquote

# Simplified CVE signature patterns for demo
CVE_PATTERNS: dict[str, dict] = {
    "CVE-2021-44228": {
        "name": "Log4Shell JNDI",
        "pattern": r"\$\{jndi:(ldap|rmi|dns)://",
        "label": "CMD",
    },
    "CVE-2022-22965": {
        "name": "Spring4Shell",
        "pattern": r"class\.module\.classLoader",
        "label": "CMD",
    },
    "CVE-2023-PROMPT": {
        "name": "LLM Prompt Leak",
        "pattern": r"(ignore\s+(all\s+)?previous|reveal\s+system\s+prompt)",
        "label": "PromptInjection",
    },
}

# Encoded / obfuscated Log4j variants (URL-encoded jndi, nested ${lower:...})
_LOG4J_EXTRA_PATTERNS = (
    r"%24%7[Bb]jndi",  # ${jndi URL-encoded
    r"jndi\s*:\s*(ldap|rmi|dns)\s*://",
    r"\$\{\$\{(?:lower|upper):",  # nested substitution obfuscation
)


def _expand_log4j_obfuscation(text: str) -> str:
    """Expand ${lower:x} / ${upper:x} nested Log4j obfuscation to literal chars."""

    def repl(match: re.Match[str]) -> str:
        op, ch = match.group(1), match.group(2)
        return ch.lower() if op.lower() == "lower" else ch.upper()

    prev = None
    cur = text
    while prev != cur:
        prev = cur
        cur = re.sub(r"\$\{(lower|upper):([^}])\}", repl, cur, flags=re.IGNORECASE)
    return cur


def _payload_variants(payload: str) -> list[str]:
    """Generate decoded / de-obfuscated views of a payload for pattern matching."""
    seen: set[str] = set()
    variants: list[str] = []

    def add(s: str) -> None:
        if s and s not in seen:
            seen.add(s)
            variants.append(s)

    add(payload)
    decoded = payload
    for _ in range(6):
        nxt = unquote(decoded)
        if nxt == decoded:
            break
        decoded = nxt
        add(decoded)
    add(_expand_log4j_obfuscation(decoded))
    add(_expand_log4j_obfuscation(payload))
    return variants


def _matches_log4j(candidate: str) -> bool:
    if re.search(CVE_PATTERNS["CVE-2021-44228"]["pattern"], candidate, re.IGNORECASE):
        return True
    for pat in _LOG4J_EXTRA_PATTERNS:
        if re.search(pat, candidate, re.IGNORECASE):
            return True
    expanded = _expand_log4j_obfuscation(candidate)
    return bool(re.search(r"jndi\s*:\s*(ldap|rmi|dns)\s*://", expanded, re.IGNORECASE))


def match_virtual_patch(payload: str) -> dict | None:
    for variant in _payload_variants(payload):
        for cve_id, meta in CVE_PATTERNS.items():
            if cve_id == "CVE-2021-44228":
                if _matches_log4j(variant):
                    return {
                        "cve_id": cve_id,
                        "name": meta["name"],
                        "label": meta["label"],
                        "pattern": meta["pattern"],
                        "action": "block",
                        "patch_type": "virtual",
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }
                continue
            if re.search(meta["pattern"], variant, re.IGNORECASE):
                return {
                    "cve_id": cve_id,
                    "name": meta["name"],
                    "label": meta["label"],
                    "pattern": meta["pattern"],
                    "action": "block",
                    "patch_type": "virtual",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
    return None


def export_virtual_patch_rule(patch: dict) -> str:
    return (
        f"# Virtual Patch {patch.get('cve_id')}\n"
        f"SecRule ARGS \"@rx {patch.get('pattern')}\" "
        f"\"id:99001,phase:2,deny,msg:'IGA-Guard VirtualPatch {patch.get('name')}'\""
    )
