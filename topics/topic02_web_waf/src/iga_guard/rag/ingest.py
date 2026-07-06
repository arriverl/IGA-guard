"""将文献、漏检、社区情报切分为检索块。"""

from __future__ import annotations

import json
import re
from pathlib import Path

from iga_guard.rag.chunker import RagChunk

_HEADING_RE = re.compile(r"^(#{1,4})\s+(.+)$", re.MULTILINE)


def chunk_markdown(path: Path, category: str = "literature") -> list[RagChunk]:
    text = path.read_text(encoding="utf-8", errors="replace")
    parts = re.split(r"\n(?=#{1,4}\s)", text)
    chunks: list[RagChunk] = []
    for i, part in enumerate(parts):
        part = part.strip()
        if len(part) < 80:
            continue
        title = part.split("\n", 1)[0].lstrip("#").strip()[:80]
        chunks.append(
            RagChunk(
                doc_id=f"{path.stem}:{i}",
                source=str(path),
                category=category,
                text=part[:3000],
                meta={"title": title},
            )
        )
    return chunks


def chunk_failures_jsonl(path: Path) -> list[RagChunk]:
    if not path.exists():
        return []
    chunks: list[RagChunk] = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        payload = row.get("payload", "")[:500]
        label = row.get("true_label", row.get("label", ""))
        pred = row.get("predicted", row.get("pred", ""))
        src = row.get("source", "")
        text = (
            f"漏检样本 真实标签={label} 预测={pred} 来源={src}\n"
            f"载荷: {payload}\n"
            f"分析提示: 该变种绕过了当前检测，需加强对应混淆手法规则。"
        )
        chunks.append(
            RagChunk(
                doc_id=f"miss:{i}",
                source=str(path),
                category="miss_pattern",
                text=text,
                meta={"label": label, "source": src},
            )
        )
    return chunks


def chunk_technique_catalog(path: Path) -> list[RagChunk]:
    if not path.exists():
        return []
    chunks: list[RagChunk] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for m in re.finditer(r"^###?\s+`?([a-z0-9_]+)`?\s*$", text, re.MULTILINE | re.I):
        name = m.group(1)
        start = m.end()
        nxt = re.search(r"\n#{1,3}\s", text[start:])
        end = start + nxt.start() if nxt else start + 800
        body = text[m.start() : end].strip()
        if len(body) < 40:
            continue
        chunks.append(
            RagChunk(
                doc_id=f"tech:{name}",
                source=str(path),
                category="technique",
                text=body[:2000],
                meta={"technique": name},
            )
        )
    return chunks


def collect_project_chunks(root: Path) -> list[RagChunk]:
    """采集 Agent1–4 全量可检索知识。"""
    chunks: list[RagChunk] = []
    research = root / "research"
    if research.exists():
        for md in research.rglob("*.md"):
            if "AGENT_QUEUE" in md.name:
                continue
            cat = "literature"
            if "community" in md.parts:
                cat = "community"
            elif "agent2" in str(md):
                cat = "architecture"
            elif "agent4" in str(md) or "DATASET" in md.name:
                cat = "dataset"
            chunks.extend(chunk_markdown(md, category=cat))

    cache = root / "data" / "cache"
    chunks.extend(chunk_failures_jsonl(cache / "failures.jsonl"))
    chunks.extend(chunk_failures_jsonl(cache / "eval_obf_misses.jsonl"))

    miss_analysis = root / "results" / "miss_analysis.json"
    if miss_analysis.exists():
        data = json.loads(miss_analysis.read_text(encoding="utf-8"))
        summary = json.dumps(data, ensure_ascii=False, indent=2)[:4000]
        chunks.append(
            RagChunk(
                doc_id="miss_analysis",
                source=str(miss_analysis),
                category="miss_pattern",
                text=f"漏检聚类分析:\n{summary}",
                meta={},
            )
        )

    catalog = research / "agent1_literature" / "papers" / "06_obfuscation_v31_catalog.md"
    chunks.extend(chunk_technique_catalog(catalog))

    reg = cache / "discovered_techniques.json"
    if reg.exists():
        chunks.append(
            RagChunk(
                doc_id="discovered_techniques",
                source=str(reg),
                category="technique",
                text=reg.read_text(encoding="utf-8")[:4000],
                meta={},
            )
        )
    return chunks
