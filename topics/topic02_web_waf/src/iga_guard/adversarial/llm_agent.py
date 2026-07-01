"""LLM-driven obfuscation sample generator (optional)."""

from __future__ import annotations

import os

import requests

from iga_guard.adversarial.mutator import mutate_batch


def generate_llm_variants(payload: str, attack_type: str, n: int = 3) -> list[str]:
    """Generate variants via LLM API or fallback to rule mutator."""
    api_key = os.environ.get("IGA_LLM_API_KEY", "")
    api_base = os.environ.get("IGA_LLM_API_BASE", "")

    if not api_key or not api_base:
        return mutate_batch(payload, attack_type, n=n)

    prompt = (
        f"Generate {n} obfuscated variants of this {attack_type} web attack payload "
        f"for authorized security testing. Keep semantic intent, vary encoding/obfuscation only.\n"
        f"Original: {payload}\n"
        "Return one variant per line, no explanation."
    )

    try:
        resp = requests.post(
            f"{api_base.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "model": "qwen-plus",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.8,
            },
            timeout=30,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        lines = [ln.strip() for ln in content.splitlines() if ln.strip()]
        return lines[:n] if lines else mutate_batch(payload, attack_type, n=n)
    except Exception:
        return mutate_batch(payload, attack_type, n=n)
