"""Virtual patching for emerging CVE payloads."""

from __future__ import annotations

from datetime import datetime, timezone

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


def match_virtual_patch(payload: str) -> dict | None:
    import re

    for cve_id, meta in CVE_PATTERNS.items():
        if re.search(meta["pattern"], payload, re.IGNORECASE):
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
