"""动态混淆手法注册表 — 运行时吸收漏检驱动的新手法。"""

from __future__ import annotations

import json
import random
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import quote

DEFAULT_REGISTRY_PATH = Path("data/cache/discovered_techniques.json")

TransformFn = Callable[[str, random.Random], str]


def _repeat_url_encode(s: str, r: random.Random, rounds: int = 3) -> str:
    out = s
    for _ in range(rounds):
        out = quote(out, safe="")
    return out


def _insert_null_byte(s: str, r: random.Random) -> str:
    pos = r.randint(1, max(1, len(s) - 1))
    return s[:pos] + "\x00" + s[pos:]


def _deep_inline_comment(s: str, r: random.Random) -> str:
    parts = re.split(r"(\s+)", s, maxsplit=2)
    if len(parts) < 2:
        return s + "/**/"
    return parts[0] + "/**/" + "".join(parts[1:])


def _zero_width_inject(s: str, r: random.Random) -> str:
    zw = "\u200b"
    pos = r.randint(0, len(s))
    return s[:pos] + zw + s[pos:]


def _mixed_case_burst(s: str, r: random.Random) -> str:
    return "".join(c.upper() if r.random() > 0.5 else c.lower() for c in s)


def _hex_wrap_keywords(s: str, r: random.Random) -> str:
    def repl(m: re.Match[str]) -> str:
        return "0x" + m.group(0).encode().hex()
    return re.sub(r"(?i)(union|select|script|alert|exec|or|and)", repl, s, count=1)


_TEMPLATE_DISPATCH: dict[str, TransformFn] = {
    "repeat_url_encode": lambda s, r: _repeat_url_encode(s, r, 3),
    "double_url_encode_plus": lambda s, r: _repeat_url_encode(s, r, 2),
    "insert_null_byte": _insert_null_byte,
    "deep_inline_comment": _deep_inline_comment,
    "zero_width_inject": _zero_width_inject,
    "mixed_case_burst": _mixed_case_burst,
    "hex_wrap_keywords": _hex_wrap_keywords,
    "md5_hex32_camouflage": lambda s, r: __import__(
        "iga_guard.dataset.obfuscation_techniques", fromlist=["apply_technique"]
    ).apply_technique(s, "md5_hex32_camouflage", r),
    "json_null_in_key": lambda s, r: __import__(
        "iga_guard.dataset.obfuscation_techniques", fromlist=["apply_technique"]
    ).apply_technique(s, "json_null_in_key", r),
}


class TechniqueRegistry:
    """持久化 + 运行时注册 discovered 混淆手法。"""

    def __init__(self, path: str | Path = DEFAULT_REGISTRY_PATH) -> None:
        self.path = Path(path)
        self._data: dict = {"version": 1, "techniques": {}}
        self.load()

    def load(self) -> None:
        if self.path.exists():
            self._data = json.loads(self.path.read_text(encoding="utf-8"))
        self._data.setdefault("techniques", {})

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self._data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    @property
    def techniques(self) -> dict[str, dict]:
        return self._data["techniques"]

    def names(self) -> list[str]:
        return list(self.techniques.keys())

    def register(
        self,
        name: str,
        *,
        template: str,
        attack_types: list[str],
        source_miss: str = "",
        params: dict | None = None,
    ) -> bool:
        """注册新手法的 template 名；已存在则仅 bump use_count。"""
        if name in self.techniques:
            self.techniques[name]["use_count"] = self.techniques[name].get("use_count", 0) + 1
            self.save()
            return False
        if template not in _TEMPLATE_DISPATCH:
            try:
                from iga_guard.dataset.obfuscation_techniques import _DISPATCH
                if template not in _DISPATCH:
                    return False
            except Exception:
                return False
        self.techniques[name] = {
            "template": template,
            "attack_types": attack_types,
            "source_miss": source_miss[:512],
            "params": params or {},
            "created_at": datetime.now(timezone.utc).isoformat(),
            "use_count": 1,
        }
        self.save()
        return True

    def apply(self, payload: str, name: str, rng: random.Random | None = None) -> str:
        r = rng or random.Random()
        meta = self.techniques.get(name)
        if not meta:
            return payload
        fn = _TEMPLATE_DISPATCH.get(meta["template"])
        if fn is None:
            try:
                from iga_guard.dataset.obfuscation_techniques import apply_technique
                return apply_technique(payload, meta["template"], r)
            except Exception:
                return payload
        try:
            meta["use_count"] = meta.get("use_count", 0) + 1
            return fn(payload, r)
        except Exception:
            return payload

    def applicable_for(self, attack_type: str) -> list[str]:
        out: list[str] = []
        for name, meta in self.techniques.items():
            types = meta.get("attack_types") or []
            if not types or attack_type in types:
                out.append(name)
        return out

    def stats(self) -> dict:
        return {
            "total": len(self.techniques),
            "templates": sorted({m["template"] for m in self.techniques.values()}),
            "path": str(self.path),
        }
