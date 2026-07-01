"""
双路并行检测引擎（Dual-Track Detector）
========================================
语义轨（Semantic Track）  : TinyBERT / 关键词密度 → 识别混淆 Payload 语义
统计轨（Statistical Track）: DLinear 时序分解     → 识别低速率/异常节奏逃逸
多模态轨（Multimodal）    : 协议轨 + 字节图视觉轨 → 混淆形态 / HPP / multipart

融合策略（IGA-Guard 3.0）：
  38% RF+规则  +  28% 语义  +  14% 多模态  +  12% DLinear  +  持续学习缓存

Online RL 可通过 adjust_threshold() 动态调整各类别判定阈值。
"""

from __future__ import annotations

from pathlib import Path

import numpy as np

from iga_guard.detector.dlinear_branch import DLinearBranch
from iga_guard.detector.fusion_model import FusionDetector
from iga_guard.detector.multimodal_branch import MultimodalBranch
from iga_guard.detector.semantic_branch import SemanticBranch
from iga_guard.evolution.continual_cache import ContinualCacheAdapter
from iga_guard.features import extract_features
from iga_guard.models import ATTACK_LABELS, DetectionResult, NormalizedPayload
from iga_guard.obfuscation_signals import (
    attack_keyword_scores,
    is_obfuscated,
    structural_attack_scores,
)


class DualTrackDetector:
    """IGA-Guard 2.0 核心检测器：双路融合 + 可演化阈值。"""

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        det = cfg.get("detector", {})
        dlinear_cfg = cfg.get("dlinear", {})
        mm_cfg = cfg.get("multimodal", {})

        model_path = det.get("model_path", "models/fusion_detector.joblib")
        path = model_path if Path(model_path).exists() else None
        self.base = FusionDetector(path)
        self.labels = det.get("labels", ATTACK_LABELS)

        self.semantic = SemanticBranch(
            model_name=det.get("semantic_model", "distilbert-base-uncased"),
            enabled=det.get("use_semantic_branch", False),
        )
        self.dlinear = DLinearBranch(
            seq_len=dlinear_cfg.get("seq_len", 16),
            moving_avg=dlinear_cfg.get("moving_avg", 4),
        )
        self.multimodal = MultimodalBranch(
            enabled=mm_cfg.get("enabled", True),
            vision_weight=float(mm_cfg.get("vision_weight", 0.45)),
        )
        self._w_base = float(mm_cfg.get("weight_base", 0.38))
        self._w_sem = float(mm_cfg.get("weight_semantic", 0.28))
        self._w_mm = float(mm_cfg.get("weight_multimodal", 0.14))
        self._w_dl = float(mm_cfg.get("weight_dlinear", 0.12))
        self.threshold = det.get("confidence_threshold", 0.35)
        self._rl_thresholds: dict[str, float] = {l: self.threshold for l in self.labels}

        cache_cfg = cfg.get("continual_cache", {})
        self.cache: ContinualCacheAdapter | None = None
        if cache_cfg.get("enabled", False):
            self.cache = ContinualCacheAdapter.load(config=cache_cfg)
            if cache_cfg.get("fusion_weight") is not None:
                self.cache.fusion_weight = float(cache_cfg["fusion_weight"])

    def predict(
        self,
        payload: NormalizedPayload,
        ts_matrix: list[list[float]] | None = None,
    ) -> DetectionResult:
        """
        对单条归一化载荷做双路检测。

        Args:
            payload: 解混淆后的载荷对象
            ts_matrix: 来自 TimeSeriesBuffer 的 [T,6] 矩阵；有则走真实 DLinear 时序编码
        """
        fv = extract_features(payload)
        base_result = self.base.predict(payload, fv=fv)

        sem_bias = self.semantic.class_bias(payload)
        mm_bias = self.multimodal.class_bias(payload)
        if ts_matrix and len(ts_matrix) >= 2:
            dlinear_enc = self.dlinear.encode_series(ts_matrix)
        else:
            dlinear_enc = self.dlinear.encode(payload, fv)
        anomaly = self.dlinear.score_anomaly(dlinear_enc)

        all_probs: dict[str, float] = {}
        for label in self.labels:
            p = self._w_base * base_result.all_probs.get(label, 0.0)
            p += self._w_sem * sem_bias.get(label, 0.0)
            p += self._w_mm * mm_bias.get(label, 0.0)
            if label != "Normal":
                p += self._w_dl * anomaly * max(
                    mm_bias.get(label, 0.0),
                    sem_bias.get(label, 0.0),
                    base_result.all_probs.get(label, 0.0),
                )
            else:
                p += self._w_dl * (1.0 - anomaly) * 0.5
            all_probs[label] = p

        total = sum(all_probs.values()) or 1.0
        all_probs = {k: v / total for k, v in all_probs.items()}

        # 混淆载荷：结构信号 + 关键词 + 解码链加权
        raw_low = payload.raw_payload.lower()
        if is_obfuscated(raw_low):
            norm = (payload.normalized_payload or payload.raw_payload).lower()
            kw = attack_keyword_scores(norm)
            st = structural_attack_scores(
                payload.raw_payload, norm, decode_depth=len(payload.decode_chain),
            )
            for label in self.labels:
                if label != "Normal":
                    all_probs[label] = (
                        0.55 * all_probs.get(label, 0.0)
                        + 0.25 * kw.get(label, 0.0)
                        + 0.2 * st.get(label, 0.0)
                    )
            if len(payload.decode_chain) >= 2:
                for label in self.labels:
                    if label != "Normal":
                        all_probs[label] *= 1.15
            t2 = sum(all_probs.values()) or 1.0
            all_probs = {k: v / t2 for k, v in all_probs.items()}

        label = max(all_probs, key=all_probs.get)
        confidence = all_probs[label]
        attack_peak = max((v for k, v in all_probs.items() if k != "Normal"), default=0.0)
        if label == "Normal" and attack_peak >= self.threshold:
            label = max(
                (k for k in all_probs if k != "Normal"),
                key=lambda k: all_probs[k],
            )
            confidence = all_probs[label]
        thresh = self._rl_thresholds.get(label, self.threshold)
        is_malicious = label != "Normal" and (confidence >= thresh or attack_peak >= thresh)
        if not is_malicious and is_obfuscated(raw_low):
            norm_text = (payload.normalized_payload or payload.raw_payload).lower()
            kw = attack_keyword_scores(norm_text)
            st = structural_attack_scores(
                payload.raw_payload, norm_text, decode_depth=len(payload.decode_chain),
            )
            kw_peak = max((v for k, v in kw.items() if k != "Normal"), default=0.0)
            st_peak = max((v for k, v in st.items() if k != "Normal"), default=0.0)
            if len(payload.decode_chain) >= 2 and kw_peak >= 0.3:
                label = max((k for k in kw if k != "Normal"), key=lambda k: kw[k])
                confidence = max(confidence, kw_peak, thresh)
                is_malicious = True
            elif st_peak >= 0.5 and kw_peak >= 0.15:
                label = max((k for k in st if k != "Normal"), key=lambda k: st[k])
                confidence = max(confidence, st_peak, thresh)
                is_malicious = True

        # Stage-2：持续学习 KV 缓存修正（冻结编码器，免训练查库）
        if self.cache and len(self.cache._entries) > 0:
            text = payload.normalized_payload or payload.raw_payload
            all_probs = self.cache.fuse_probs(
                all_probs, text, raw_payload=payload.raw_payload,
            )
            label = max(all_probs, key=all_probs.get)
            confidence = all_probs[label]
            attack_peak = max((v for k, v in all_probs.items() if k != "Normal"), default=0.0)
            hit = self.cache.cache_hit_strength(text)
            if hit >= 0.85 and label != "Normal":
                is_malicious = True
                confidence = max(confidence, hit * 0.9)
            elif label != "Normal" and confidence >= thresh:
                is_malicious = True

        return DetectionResult(
            label=label,
            confidence=confidence,
            risk_level=_risk(label, confidence),
            is_malicious=is_malicious,
            all_probs=all_probs,
        )

    def fit(self, X: np.ndarray, y: list[str]) -> None:
        self.base.fit(X, y)

    def save(self, path: str) -> None:
        self.base.save(path)

    def adjust_threshold(self, label: str, delta: float) -> None:
        """Online RL 反馈：调整某攻击类型的判定阈值。"""
        self._rl_thresholds[label] = float(np.clip(
            self._rl_thresholds.get(label, self.threshold) + delta, 0.2, 0.95
        ))


def _risk(label: str, confidence: float) -> str:
    if label == "Normal":
        return "low"
    if confidence >= 0.85:
        return "high"
    if confidence >= 0.6:
        return "medium"
    return "low"
