"""
语义分支（Semantic Branch）
===========================
职责：对解混淆后的 HTTP 载荷做轻量级语义判别，为双路融合提供类别偏置。

推理策略（按优先级）：
  1. 若 ``models/tinybert_waf/`` 目录存在且含权重 → 加载本地微调 TinyBERT 做 8 类分类
  2. 否则 → 关键词密度启发式（零依赖、亚毫秒级）

与 ``scripts/train_bert.py`` 的标签映射保持一致：
  LABEL_0=Normal, LABEL_1=SQLi, …, LABEL_7=PromptInjection
"""

from __future__ import annotations

import re
from pathlib import Path

from iga_guard.models import ATTACK_LABELS, NormalizedPayload

# 项目根目录：src/iga_guard/detector/ → parents[3]
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_TINYBERT_DIR = _PROJECT_ROOT / "models" / "tinybert_waf"

# HuggingFace 训练产物中的 LABEL_n → IGA-Guard 攻击类型名
_HF_LABEL_TO_ATTACK: dict[str, str] = {
    f"LABEL_{i}": label for i, label in enumerate(ATTACK_LABELS)
}

# 关键词回退：可疑 token 集合（覆盖 SQLi / XSS / XXE / Prompt 等典型特征）
_SUSPICIOUS_TOKENS: frozenset[str] = frozenset({
    "union", "select", "script", "alert", "entity", "system", "ignore", "prompt",
    "drop", "insert", "onerror", "jailbreak", "eval", "exec",
})

# 判定本地目录是否“可加载”的权重文件名
_WEIGHT_FILES = ("model.safetensors", "pytorch_model.bin")


class SemanticBranch:
    """
    语义轨检测分支。

    自动探测 ``models/tinybert_waf/``；存在则懒加载分类器，否则走关键词密度。
    """

    def __init__(
        self,
        model_name: str = "distilbert-base-uncased",
        enabled: bool = False,
        local_model_dir: str | Path | None = None,
    ):
        # model_name / enabled 保留以兼容旧配置；本地目录存在时优先使用 TinyBERT
        self.model_name = model_name
        self.enabled = enabled
        self.local_model_dir = Path(local_model_dir) if local_model_dir else _DEFAULT_TINYBERT_DIR
        self._classifier = None  # transformers pipeline 实例
        self._mode: str = "pending"  # pending | bert | keyword

    # ------------------------------------------------------------------
    # 模型路径解析与懒加载
    # ------------------------------------------------------------------

    def _resolve_model_path(self) -> Path | None:
        """
        解析可用的本地模型目录。

        优先使用 ``tinybert_waf/`` 根目录；若根目录无权重则回退到最新 checkpoint-*。
        目录不存在或缺少 config + 权重时返回 None。
        """
        root = self.local_model_dir
        if not root.is_dir():
            return None

        def _has_weights(directory: Path) -> bool:
            return (directory / "config.json").is_file() and any(
                (directory / name).is_file() for name in _WEIGHT_FILES
            )

        if _has_weights(root):
            return root

        # 按 checkpoint 编号降序，取最新可用检查点
        checkpoints = sorted(
            root.glob("checkpoint-*"),
            key=lambda p: int(p.name.rsplit("-", 1)[-1]) if p.name.rsplit("-", 1)[-1].isdigit() else 0,
            reverse=True,
        )
        for ckpt in checkpoints:
            if _has_weights(ckpt):
                return ckpt
        return None

    def _tokenizer_path(self, model_path: Path) -> Path:
        """分词器优先从模型根目录加载（训练脚本将 tokenizer 保存在 out 根目录）。"""
        if (self.local_model_dir / "tokenizer.json").is_file():
            return self.local_model_dir
        return model_path

    def _lazy_load_classifier(self) -> bool:
        """
        懒加载 text-classification pipeline。

        成功 → ``_mode='bert'``；失败或目录缺失 → ``_mode='keyword'``。
        """
        if self._mode == "keyword":
            return False
        if self._classifier is not None:
            return True

        model_path = self._resolve_model_path()
        if model_path is None:
            self._mode = "keyword"
            return False

        try:
            from transformers import pipeline  # type: ignore

            tok_path = self._tokenizer_path(model_path)
            self._classifier = pipeline(
                "text-classification",
                model=str(model_path),
                tokenizer=str(tok_path),
                top_k=None,
                truncation=True,
                max_length=128,
            )
            self._mode = "bert"
            return True
        except Exception:
            self._classifier = None
            self._mode = "keyword"
            return False

    # ------------------------------------------------------------------
    # BERT 分类推理
    # ------------------------------------------------------------------

    def _map_hf_label(self, raw_label: str) -> str | None:
        """将 HuggingFace 标签名映射为 ATTACK_LABELS 中的标准名。"""
        if raw_label in _HF_LABEL_TO_ATTACK:
            return _HF_LABEL_TO_ATTACK[raw_label]
        if raw_label in ATTACK_LABELS:
            return raw_label
        # 兼容 id2label 为数字字符串的情况
        if raw_label.isdigit():
            idx = int(raw_label)
            if 0 <= idx < len(ATTACK_LABELS):
                return ATTACK_LABELS[idx]
        return None

    def _classify_with_bert(self, text: str) -> dict[str, float]:
        """
        调用微调 TinyBERT，返回 8 类 softmax 概率字典。

        pipeline(top_k=None) 返回形如 [{label, score}, ...] 的列表。
        """
        assert self._classifier is not None
        raw = self._classifier(text[:512])
        # batch_size=1 时可能再包一层 list
        items = raw[0] if raw and isinstance(raw[0], list) else raw

        probs: dict[str, float] = {label: 0.0 for label in ATTACK_LABELS}
        for item in items or []:
            mapped = self._map_hf_label(str(item.get("label", "")))
            if mapped is not None:
                probs[mapped] = float(item.get("score", 0.0))
        return probs

    # ------------------------------------------------------------------
    # 关键词密度回退
    # ------------------------------------------------------------------

    def _keyword_encode(self, text: str) -> dict[str, float]:
        """
        快速启发式：统计可疑 token 命中数与密度。

        不依赖 GPU / transformers，适合冷启动与 CI 冒烟测试。
        """
        tokens = re.findall(r"[a-z]{3,}", text)
        hits = sum(1 for t in tokens if t in _SUSPICIOUS_TOKENS)
        return {
            "semantic_mode": 0.0,  # 0=关键词回退，1=BERT
            "semantic_trigram_hits": float(hits),
            "semantic_token_density": float(hits / max(len(tokens), 1)),
        }

    def _keyword_class_bias(self, text: str) -> dict[str, float]:
        """
        基于规则的关键词类别偏置，供双路融合 30% 语义权重使用。
        """
        enc = self._keyword_encode(text)
        bias: dict[str, float] = {label: 0.05 if label == "Normal" else 0.0 for label in ATTACK_LABELS}

        if "union" in text and "select" in text:
            bias["SQLi"] += 0.4
        if "<script" in text or "onerror" in text:
            bias["XSS"] += 0.4
        if "<!entity" in text or "&xxe" in text:
            bias["XXE"] += 0.5
        if any(k in text for k in ("ignore previous", "jailbreak", "system prompt")):
            bias["PromptInjection"] += 0.5

        bias["semantic"] = enc.get("semantic_trigram_hits", 0.0)
        return bias

    def _apply_keyword_boosts(self, bias: dict[str, float], text: str) -> dict[str, float]:
        """
        在 BERT 概率基础上叠加轻量规则增强（应对训练集未覆盖的变体）。
        """
        if "union" in text and "select" in text:
            bias["SQLi"] = min(1.0, bias.get("SQLi", 0.0) + 0.15)
        if "<script" in text or "onerror" in text:
            bias["XSS"] = min(1.0, bias.get("XSS", 0.0) + 0.15)
        if "<!entity" in text or "&xxe" in text:
            bias["XXE"] = min(1.0, bias.get("XXE", 0.0) + 0.15)
        if any(k in text for k in ("ignore previous", "jailbreak", "system prompt")):
            bias["PromptInjection"] = min(1.0, bias.get("PromptInjection", 0.0) + 0.15)
        return bias

    # ------------------------------------------------------------------
    # 对外接口
    # ------------------------------------------------------------------

    def encode(self, payload: NormalizedPayload) -> dict[str, float]:
        """
        提取语义特征向量（供日志 / 可解释性模块使用）。

        Returns:
            BERT 模式：各类别概率 + semantic_mode=1
            关键词模式：trigram 命中统计 + semantic_mode=0
        """
        text = (payload.normalized_payload or payload.raw_payload).lower()

        if self._lazy_load_classifier() and self._classifier is not None:
            try:
                probs = self._classify_with_bert(text)
                features: dict[str, float] = {
                    "semantic_mode": 1.0,
                    "semantic_top_score": max(probs.values()) if probs else 0.0,
                }
                for label, score in probs.items():
                    features[f"sem_{label}"] = score
                return features
            except Exception:
                pass

        return self._keyword_encode(text)

    def _needs_semantic_deep(self, text: str) -> bool:
        """门控：仅可疑载荷走 TinyBERT，正常短文本走关键词回退（降延迟、减误报）。"""
        if len(text) < 4:
            return False
        low = text.lower()
        if any(k in low for k in _SUSPICIOUS_TOKENS):
            return True
        if any(m in low for m in ("%", "&#", "\\u", "/**/", "0x", "char(", "eval(", "boundary=")):
            return True
        return len(low) > 80

    def class_bias(self, payload: NormalizedPayload) -> dict[str, float]:
        """
        返回各类别偏置分，供 ``DualTrackDetector`` 以 35% 权重融合。

        本地 TinyBERT 可用时以分类概率为主；否则使用关键词规则偏置。
        """
        text = (payload.normalized_payload or payload.raw_payload).lower()

        if self._needs_semantic_deep(text) and self._lazy_load_classifier() and self._classifier is not None:
            try:
                probs = self._classify_with_bert(text)
                bias = {label: probs.get(label, 0.0) for label in ATTACK_LABELS}
                bias = self._apply_keyword_boosts(bias, text)
                bias["semantic"] = max(probs.values()) if probs else 0.0
                return bias
            except Exception:
                pass

        return self._keyword_class_bias(text)
