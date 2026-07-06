"""RAG 知识块数据结构。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RagChunk:
    doc_id: str
    source: str
    category: str
    text: str
    meta: dict = field(default_factory=dict)

    def preview(self, max_len: int = 400) -> str:
        t = self.text.strip().replace("\n", " ")
        return t[:max_len] + ("…" if len(t) > max_len else "")
