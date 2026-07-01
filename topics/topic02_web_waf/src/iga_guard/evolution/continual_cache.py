"""
持续学习键值缓存（Continual Cache Adapter）
============================================
参考 Few-shot VLM + Tip-Adapter 思路，适配 Web 载荷文本分类：

  Stage-1（建库）：冻结预训练编码器，用少量样本 embedding 作 Key，标签作 Value
  Stage-2（推理）：测试样本查库，按余弦相似度加权修正基线分类器输出

创新点：
  - **不动主干**：编码器与 RF/TinyBERT 均不微调
  - **动态更新**：漏检反馈 / 对抗演化样本写入缓存（LRU + 近重复合并）
  - **持续学习**：新攻击场景通过扩库适应，无需全量重训

编码器优先级：sentence-transformers MiniLM → 字符 n-gram 哈希（零依赖回退）
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from iga_guard.models import ATTACK_LABELS

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_CACHE_PATH = _PROJECT_ROOT / "models" / "continual_cache.npz"
_DEFAULT_META_PATH = _PROJECT_ROOT / "models" / "continual_cache_meta.jsonl"


@dataclass
class CacheEntry:
    key: np.ndarray
    label: str
    payload_snippet: str
    source: str
    vision_key: np.ndarray | None = None
    ts: float = field(default_factory=time.time)
    hits: int = 0


class FrozenTextEncoder:
    """冻结文本编码器：优先 SentenceTransformer，回退 n-gram 哈希。"""

    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2", dim: int = 384):
        self.model_name = model_name
        self.dim = dim
        self._st = None
        self._mode = "hash"
        self._try_load_st()

    def _try_load_st(self) -> None:
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore

            self._st = SentenceTransformer(self.model_name)
            self._mode = "st"
            self.dim = int(self._st.get_sentence_embedding_dimension())
        except Exception:
            self._st = None
            self._mode = "hash"

    @property
    def mode(self) -> str:
        return self._mode

    def encode(self, text: str) -> np.ndarray:
        text = (text or "")[:512]
        if self._st is not None:
            vec = self._st.encode(text, normalize_embeddings=True, show_progress_bar=False)
            return np.asarray(vec, dtype=np.float32)
        return self._hash_embed(text)

    def _hash_embed(self, text: str) -> np.ndarray:
        """确定性字符 trigram 哈希嵌入（免训练、无 GPU）。"""
        vec = np.zeros(self.dim, dtype=np.float32)
        low = text.lower()
        if not low:
            return vec
        for i in range(len(low) - 2):
            tri = low[i : i + 3]
            idx = hash(tri) % self.dim
            vec[idx] += 1.0
        for w in low.split():
            if len(w) >= 3:
                idx = hash(w) % self.dim
                vec[idx] += 0.5
        norm = np.linalg.norm(vec)
        if norm > 1e-8:
            vec /= norm
        return vec


class ContinualCacheAdapter:
    """
    Tip-Adapter 风格 KV 缓存 + 动态持续更新。

    查库分数（类 c）::
        score(c) = Σ_i  exp(-β * (1 - cos(q, k_i))) * 𝟙[y_i = c]
    与基线融合::
        p_final = (1-λ) * p_base + λ * normalize(score)
    """

    def __init__(
        self,
        encoder: FrozenTextEncoder | None = None,
        labels: list[str] | None = None,
        *,
        max_size: int = 5000,
        beta: float = 5.0,
        top_k: int = 8,
        fusion_weight: float = 0.35,
        dedupe_threshold: float = 0.98,
        multimodal_alpha: float = 0.65,
    ):
        self.encoder = encoder or FrozenTextEncoder()
        self.labels = labels or list(ATTACK_LABELS)
        self.max_size = max_size
        self.beta = beta
        self.top_k = top_k
        self.fusion_weight = fusion_weight
        self.dedupe_threshold = dedupe_threshold
        self.multimodal_alpha = multimodal_alpha
        self._vision_encoder = None
        self._entries: list[CacheEntry] = []

    def _get_vision_encoder(self):
        if self._vision_encoder is None:
            from iga_guard.detector.multimodal_branch import ByteImageEncoder
            self._vision_encoder = ByteImageEncoder()
        return self._vision_encoder

    def encode_vision(self, raw: str) -> np.ndarray:
        return self._get_vision_encoder().encode(raw)

    # ------------------------------------------------------------------
    # 建库 / 查库
    # ------------------------------------------------------------------

    def build_from_samples(
        self,
        samples: list[tuple[str, str]],
        *,
        source: str = "few_shot",
    ) -> int:
        """Stage-1：批量写入 (payload, label) 样本。"""
        added = 0
        for payload, label in samples:
            if self.append(payload, label, source=source, save=False):
                added += 1
        return added

    def lookup_scores(self, text: str, vision: np.ndarray | None = None) -> dict[str, float]:
        """Stage-2：文本 Key + 可选视觉 Key 联合查库。"""
        if not self._entries:
            return {lb: 0.0 for lb in self.labels}

        q = self.encoder.encode(text)
        keys = np.stack([e.key for e in self._entries], axis=0)
        sims = keys @ q

        if vision is not None and any(e.vision_key is not None for e in self._entries):
            vkeys = []
            vmask = []
            for e in self._entries:
                if e.vision_key is not None:
                    vkeys.append(e.vision_key)
                    vmask.append(True)
                else:
                    vkeys.append(np.zeros_like(vision))
                    vmask.append(False)
            v_stack = np.stack(vkeys, axis=0)
            vsims = v_stack @ vision
            alpha = self.multimodal_alpha
            for i, has_v in enumerate(vmask):
                if has_v:
                    sims[i] = alpha * sims[i] + (1.0 - alpha) * vsims[i]

        k = min(self.top_k, len(sims))
        top_idx = np.argpartition(-sims, k - 1)[:k]

        scores = {lb: 0.0 for lb in self.labels}
        for idx in top_idx:
            sim = float(sims[idx])
            aff = float(np.exp(-self.beta * (1.0 - max(sim, 0.0))))
            entry = self._entries[idx]
            entry.hits += 1
            if entry.label in scores:
                scores[entry.label] += aff
        return scores

    def fuse_probs(
        self,
        base_probs: dict[str, float],
        text: str,
        raw_payload: str | None = None,
    ) -> dict[str, float]:
        """将缓存分与基线概率融合（支持多模态视觉 Key）。"""
        vision = self.encode_vision(raw_payload or text) if raw_payload or text else None
        cache_raw = self.lookup_scores(text, vision=vision)
        total_c = sum(cache_raw.values()) or 1.0
        cache_probs = {lb: cache_raw.get(lb, 0.0) / total_c for lb in self.labels}

        lam = self.fusion_weight
        fused = {
            lb: (1.0 - lam) * base_probs.get(lb, 0.0) + lam * cache_probs.get(lb, 0.0)
            for lb in self.labels
        }
        t = sum(fused.values()) or 1.0
        return {k: v / t for k, v in fused.items()}

    def cache_hit_strength(self, text: str) -> float:
        """最高缓存亲和度，用于可解释性。"""
        if not self._entries:
            return 0.0
        q = self.encoder.encode(text)
        keys = np.stack([e.key for e in self._entries], axis=0)
        return float(np.max(keys @ q))

    # ------------------------------------------------------------------
    # 动态更新（持续学习）
    # ------------------------------------------------------------------

    def append(
        self,
        payload: str,
        label: str,
        *,
        source: str = "feedback",
        save: bool = True,
    ) -> bool:
        """写入新样本；近重复则更新标签与时间戳。"""
        text = (payload or "")[:512]
        if not text or label not in self.labels:
            return False

        key = self.encoder.encode(text)
        vkey = self.encode_vision(payload)
        for entry in self._entries:
            sim = float(np.dot(entry.key, key))
            if entry.vision_key is not None:
                sim = 0.65 * sim + 0.35 * float(np.dot(entry.vision_key, vkey))
            if sim >= self.dedupe_threshold:
                entry.label = label
                entry.source = source
                entry.ts = time.time()
                entry.payload_snippet = text[:120]
                entry.vision_key = vkey
                if save:
                    self.save()
                return False

        self._entries.append(
            CacheEntry(
                key=key,
                label=label,
                payload_snippet=text[:120],
                source=source,
                vision_key=vkey,
            )
        )
        if len(self._entries) > self.max_size:
            self._evict_lru()
        if save:
            self.save()
        return True

    def _evict_lru(self) -> None:
        """淘汰最旧且命中最少的条目。"""
        self._entries.sort(key=lambda e: (e.hits, e.ts))
        drop = max(1, len(self._entries) - self.max_size)
        self._entries = self._entries[drop:]

    def update_from_feedback(self, payload: str, true_label: str) -> dict:
        added = self.append(payload, true_label, source="feedback")
        return {"cache_size": len(self._entries), "new_entry": added}

    # ------------------------------------------------------------------
    # 持久化
    # ------------------------------------------------------------------

    def save(
        self,
        path: str | Path | None = None,
        meta_path: str | Path | None = None,
    ) -> None:
        npz_path = Path(path or _DEFAULT_CACHE_PATH)
        meta = Path(meta_path or _DEFAULT_META_PATH)
        npz_path.parent.mkdir(parents=True, exist_ok=True)

        if self._entries:
            keys = np.stack([e.key for e in self._entries], axis=0)
            vision_keys = np.stack(
                [e.vision_key if e.vision_key is not None else np.zeros(64, dtype=np.float32)
                 for e in self._entries],
                axis=0,
            )
            labels = np.array([e.label for e in self._entries], dtype=object)
            sources = np.array([e.source for e in self._entries], dtype=object)
            snippets = np.array([e.payload_snippet for e in self._entries], dtype=object)
            hits = np.array([e.hits for e in self._entries], dtype=np.int32)
            ts = np.array([e.ts for e in self._entries], dtype=np.float64)
        else:
            keys = np.zeros((0, self.encoder.dim), dtype=np.float32)
            vision_keys = np.zeros((0, 64), dtype=np.float32)
            labels = sources = snippets = np.array([], dtype=object)
            hits = np.array([], dtype=np.int32)
            ts = np.array([], dtype=np.float64)

        np.savez_compressed(
            npz_path,
            keys=keys,
            vision_keys=vision_keys,
            labels=labels,
            sources=sources,
            snippets=snippets,
            hits=hits,
            ts=ts,
            encoder_mode=self.encoder.mode,
            dim=self.encoder.dim,
        )

        with meta.open("w", encoding="utf-8") as f:
            for e in self._entries[-200:]:
                f.write(
                    json.dumps(
                        {
                            "label": e.label,
                            "source": e.source,
                            "snippet": e.payload_snippet,
                            "hits": e.hits,
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )

    @classmethod
    def load(
        cls,
        path: str | Path | None = None,
        *,
        config: dict | None = None,
    ) -> ContinualCacheAdapter:
        cfg = config or {}
        npz_path = Path(path or cfg.get("path", _DEFAULT_CACHE_PATH))
        adapter = cls(
            labels=cfg.get("labels", ATTACK_LABELS),
            max_size=int(cfg.get("max_size", 5000)),
            beta=float(cfg.get("beta", 5.0)),
            top_k=int(cfg.get("top_k", 8)),
            fusion_weight=float(cfg.get("fusion_weight", 0.35)),
            dedupe_threshold=float(cfg.get("dedupe_threshold", 0.98)),
            multimodal_alpha=float(cfg.get("multimodal_alpha", 0.65)),
        )
        if not npz_path.exists():
            return adapter

        data = np.load(npz_path, allow_pickle=True)
        keys = data["keys"]
        labels = data["labels"]
        sources = data["sources"]
        snippets = data["snippets"]
        hits = data.get("hits", np.zeros(len(labels), dtype=np.int32))
        ts_arr = data.get("ts", np.zeros(len(labels), dtype=np.float64))
        vkeys = data.get("vision_keys", None)

        for i in range(len(labels)):
            vk = None
            if vkeys is not None and len(vkeys) > i:
                vk = np.asarray(vkeys[i], dtype=np.float32)
            adapter._entries.append(
                CacheEntry(
                    key=np.asarray(keys[i], dtype=np.float32),
                    label=str(labels[i]),
                    payload_snippet=str(snippets[i]),
                    source=str(sources[i]),
                    vision_key=vk,
                    ts=float(ts_arr[i]),
                    hits=int(hits[i]),
                )
            )
        return adapter

    def stats(self) -> dict:
        from collections import Counter

        return {
            "size": len(self._entries),
            "encoder_mode": self.encoder.mode,
            "multimodal_alpha": self.multimodal_alpha,
            "vision_keys": sum(1 for e in self._entries if e.vision_key is not None),
            "max_size": self.max_size,
            "by_label": dict(Counter(e.label for e in self._entries)),
            "by_source": dict(Counter(e.source for e in self._entries)),
        }
