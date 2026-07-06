"""RAG 检索器与 LLM 上下文拼装。"""

from __future__ import annotations

from pathlib import Path

from iga_guard.rag.index import KnowledgeIndex

_DEFAULT_ROOT = Path(__file__).resolve().parents[3]


class RagRetriever:
    def __init__(self, index: KnowledgeIndex | None = None, root: str | Path | None = None) -> None:
        self.root = Path(root or _DEFAULT_ROOT)
        self.index = index or KnowledgeIndex.load(self.root / "data" / "cache" / "rag_index.npz")
        if not self.index.chunks:
            self.index.build(self.root)
            self.index.save(self.root / "data" / "cache" / "rag_index.npz")

    def retrieve(
        self,
        query: str,
        *,
        top_k: int = 5,
        categories: list[str] | None = None,
    ) -> list[tuple[str, float, str]]:
        """返回 (text, score, category)。"""
        if categories:
            hits: list[tuple[str, float, str]] = []
            per = max(1, top_k // len(categories))
            for cat in categories:
                for ch, score in self.index.search(query, top_k=per, category=cat):
                    hits.append((ch.text, score, ch.category))
            hits.sort(key=lambda x: -x[1])
            return hits[:top_k]
        return [(ch.text, score, ch.category) for ch, score in self.index.search(query, top_k=top_k)]

    def context_for_payload(self, payload: str, attack_type: str, *, top_k: int = 4) -> str:
        q = f"{attack_type} 混淆逃逸 WAF bypass {payload[:200]}"
        return build_context(self.retrieve(q, top_k=top_k, categories=["miss_pattern", "technique", "community", "literature"]))

    def context_for_misses(self, miss_samples: list[str], attack_type: str) -> str:
        q = f"{attack_type} 漏检 {' '.join(s[:80] for s in miss_samples[:3])}"
        return build_context(self.retrieve(q, top_k=6, categories=["miss_pattern", "technique", "community"]))


def build_context(hits: list[tuple[str, float, str]], max_chars: int = 3500) -> str:
    if not hits:
        return ""
    lines = ["【RAG 检索知识 — 文献/漏检/社区情报】"]
    used = 0
    for i, (text, score, cat) in enumerate(hits, 1):
        block = f"\n--- 片段{i} ({cat}, sim={score:.3f}) ---\n{text[:800]}"
        if used + len(block) > max_chars:
            break
        lines.append(block)
        used += len(block)
    return "\n".join(lines)
