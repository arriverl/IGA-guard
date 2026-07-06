"""向量索引：复用 FrozenTextEncoder + 余弦检索。"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from iga_guard.evolution.continual_cache import FrozenTextEncoder
from iga_guard.rag.chunker import RagChunk
from iga_guard.rag.ingest import collect_project_chunks

_DEFAULT_INDEX = Path("data/cache/rag_index.npz")
_DEFAULT_META = Path("data/cache/rag_index_meta.json")


class KnowledgeIndex:
    def __init__(self, encoder: FrozenTextEncoder | None = None) -> None:
        self.encoder = encoder or FrozenTextEncoder()
        self.chunks: list[RagChunk] = []
        self._matrix: np.ndarray | None = None

    def build(self, root: str | Path) -> int:
        self.chunks = collect_project_chunks(Path(root))
        if not self.chunks:
            self._matrix = None
            return 0
        vecs = [self.encoder.encode(c.text) for c in self.chunks]
        self._matrix = np.stack(vecs, axis=0)
        return len(self.chunks)

    def search(self, query: str, top_k: int = 5, category: str | None = None) -> list[tuple[RagChunk, float]]:
        if not self.chunks or self._matrix is None:
            return []
        q = self.encoder.encode(query)
        sims = self._matrix @ q
        idxs = np.argsort(-sims)
        out: list[tuple[RagChunk, float]] = []
        for idx in idxs:
            ch = self.chunks[int(idx)]
            if category and ch.category != category:
                continue
            out.append((ch, float(sims[int(idx)])))
            if len(out) >= top_k:
                break
        return out

    def save(self, path: str | Path | None = None, meta_path: str | Path | None = None) -> None:
        npz = Path(path or _DEFAULT_INDEX)
        meta = Path(meta_path or _DEFAULT_META)
        npz.parent.mkdir(parents=True, exist_ok=True)
        matrix = self._matrix if self._matrix is not None else np.zeros((0, self.encoder.dim), dtype=np.float32)
        np.savez_compressed(npz, matrix=matrix, dim=self.encoder.dim)
        payload = [
            {"doc_id": c.doc_id, "source": c.source, "category": c.category, "text": c.text, "meta": c.meta}
            for c in self.chunks
        ]
        meta.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path | None = None, meta_path: str | Path | None = None) -> KnowledgeIndex:
        npz = Path(path or _DEFAULT_INDEX)
        meta = Path(meta_path or _DEFAULT_META)
        idx = cls()
        if not npz.exists() or not meta.exists():
            return idx
        data = np.load(npz, allow_pickle=True)
        idx._matrix = np.asarray(data["matrix"], dtype=np.float32)
        rows = json.loads(meta.read_text(encoding="utf-8"))
        idx.chunks = [
            RagChunk(
                doc_id=r["doc_id"], source=r["source"], category=r["category"],
                text=r["text"], meta=r.get("meta", {}),
            )
            for r in rows
        ]
        return idx

    def stats(self) -> dict:
        from collections import Counter
        return {
            "chunks": len(self.chunks),
            "categories": dict(Counter(c.category for c in self.chunks)),
            "encoder": self.encoder.mode,
            "dim": self.encoder.dim,
        }
