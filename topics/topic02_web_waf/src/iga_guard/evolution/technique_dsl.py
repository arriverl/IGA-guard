"""手法 DSL 解析器 — 声明式注册 discovered 混淆变换。

语法示例::

    technique discovered_triple_url:
      template: repeat_url_encode
      attack_types: [SQLi, XSS]
      match: "%25%25"
      note: "三重 URL 编码漏检驱动"
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_BLOCK_RE = re.compile(
    r"technique\s+([a-zA-Z_][\w-]*)\s*:\s*\n((?:[ \t]+[^\n]+\n?)+)",
    re.MULTILINE,
)
_KV_RE = re.compile(r"^[ \t]*([a-zA-Z_]\w*)\s*:\s*(.+)$", re.MULTILINE)


@dataclass
class TechniqueSpec:
    name: str
    template: str
    attack_types: list[str]
    match: str = ""
    note: str = ""
    params: dict | None = None


def _parse_list(val: str) -> list[str]:
    val = val.strip()
    if val.startswith("[") and val.endswith("]"):
        inner = val[1:-1].strip()
        if not inner:
            return []
        return [x.strip().strip("'\"") for x in inner.split(",") if x.strip()]
    return [val.strip("'\"")]


def parse_dsl(text: str) -> list[TechniqueSpec]:
    specs: list[TechniqueSpec] = []
    for name, body in _BLOCK_RE.findall(text):
        fields: dict[str, str] = {}
        for m in _KV_RE.finditer(body):
            fields[m.group(1)] = m.group(2).strip()
        template = fields.get("template", "")
        if not template:
            continue
        specs.append(
            TechniqueSpec(
                name=name,
                template=template,
                attack_types=_parse_list(fields.get("attack_types", "[]")),
                match=fields.get("match", "").strip("'\""),
                note=fields.get("note", "").strip("'\""),
            )
        )
    return specs


def load_dsl_file(path: str | Path) -> list[TechniqueSpec]:
    return parse_dsl(Path(path).read_text(encoding="utf-8"))


def register_specs(registry, specs: list[TechniqueSpec]) -> list[str]:
    """将 DSL 规格批量写入 TechniqueRegistry，返回新注册名列表。"""
    added: list[str] = []
    for spec in specs:
        if registry.register(
            spec.name,
            template=spec.template,
            attack_types=spec.attack_types,
            source_miss=spec.match or spec.note,
            params={"match": spec.match} if spec.match else None,
        ):
            added.append(spec.name)
    return added
