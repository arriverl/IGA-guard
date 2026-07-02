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
    has_strong_obfuscation,
    is_obfuscated,
    structural_attack_scores,
)


class DualTrackDetector:
    """IGA-Guard 2.0 核心检测器：双路融合 + 可演化阈值。"""

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        det = cfg.get("detector", {})
        self._det_cfg = det
        dlinear_cfg = cfg.get("dlinear", {})
        mm_cfg = cfg.get("multimodal", {})
        self._mm_cfg = mm_cfg

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
        self.threshold = det.get("confidence_threshold", 0.38)
        self._cache_force_hit = float(det.get("cache_force_hit_min", 0.92))
        self._cache_fusion_benign = float(det.get("cache_fusion_weight_benign", 0.12))
        self._fp_guard_conf_min = float(
            det.get("fp_guard_min_attack_conf", det.get("fp_guard_min_confidence", 0.55))
        )
        self._fp_guard_base_max = float(
            det.get("fp_guard_max_base_attack", det.get("fp_guard_base_attack_max", 0.32))
        )
        self._obf_boost_min_base = float(det.get("obfuscation_boost_min_base_attack", 0.25))
        self._rl_thresholds: dict[str, float] = {l: self.threshold for l in self.labels}

        cache_cfg = cfg.get("continual_cache", {})
        self.cache: ContinualCacheAdapter | None = None
        if cache_cfg.get("enabled", False):
            self.cache = ContinualCacheAdapter.load(config=cache_cfg)
            if cache_cfg.get("fusion_weight") is not None:
                self.cache.fusion_weight = float(cache_cfg["fusion_weight"])
            self.cache.use_vision_keys = bool(mm_cfg.get("enabled", False))

    def _fusion_weights(
        self,
        payload: NormalizedPayload,
        base_result: DetectionResult,
        mm_bias: dict[str, float],
    ) -> tuple[float, float, float, float]:
        """条件融合 + 门控：混淆样本压低 mm 权重，Normal 场景加强压 FP。"""
        cfg = self._mm_cfg
        raw_low = (payload.raw_payload or "").lower()
        obf = is_obfuscated(raw_low)

        if not self.multimodal.enabled:
            return self._w_base, self._w_sem, 0.0, self._w_dl

        if obf:
            w_base = float(cfg.get("weight_base_obfuscated", 0.42))
            w_sem = float(cfg.get("weight_semantic_obfuscated", 0.32))
            w_mm = float(cfg.get("weight_multimodal_obfuscated", 0.04))
            w_dl = float(cfg.get("weight_dlinear_obfuscated", 0.12))
        else:
            w_base = float(cfg.get("weight_base_benign", 0.34))
            w_sem = float(cfg.get("weight_semantic_benign", 0.24))
            w_mm = float(cfg.get("weight_multimodal_benign", 0.22))
            w_dl = float(cfg.get("weight_dlinear_benign", 0.10))

        attack_peak_base = max(
            (v for k, v in base_result.all_probs.items() if k != "Normal"), default=0.0,
        )
        mm_attack_peak = max(
            (v for k, v in mm_bias.items() if k != "Normal"), default=0.0,
        )
        gate_base = float(cfg.get("gate_base_attack_threshold", 0.45))
        gate_low = float(cfg.get("gate_base_low_threshold", 0.25))

        if attack_peak_base >= gate_base or obf:
            w_base += w_mm * 0.6
            w_sem += w_mm * 0.4
            w_mm = 0.0
        else:
            pf = self.multimodal.protocol.encode_features(payload)
            benign_proto = (
                pf.get("proto_hpp", 0) == 0
                and pf.get("proto_obfuscated", 0) == 0
                and pf.get("proto_pct_density", 0) < 0.2
                and attack_peak_base < gate_low
                and mm_attack_peak < 0.15
            )
            if benign_proto:
                w_mm *= float(cfg.get("gate_mm_boost", 1.5))

        return w_base, w_sem, w_mm, w_dl

    def _apply_fp_guard(
        self,
        *,
        label: str,
        confidence: float,
        is_malicious: bool,
        all_probs: dict[str, float],
        base_result: DetectionResult,
        base_attack_peak: float,
        strong_obf: bool,
        decode_depth: int,
        cache_hit: float = 0.0,
    ) -> tuple[str, float, bool]:
        """缓存/规则将 RF 判 Normal 翻为攻击时，要求更高置信或强混淆证据。"""
        if (
            label != "Normal"
            and is_malicious
            and base_result.label == "Normal"
            and base_attack_peak < self._fp_guard_base_max
            and not strong_obf
            and decode_depth < 2
            and confidence < self._fp_guard_conf_min
            and cache_hit < self._cache_force_hit
        ):
            return "Normal", max(
                all_probs.get("Normal", 0.0),
                base_result.all_probs.get("Normal", 0.5),
            ), False
        return label, confidence, is_malicious

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
        w_base, w_sem, w_mm, w_dl = self._fusion_weights(payload, base_result, mm_bias)
        if ts_matrix and len(ts_matrix) >= 2:
            dlinear_enc = self.dlinear.encode_series(ts_matrix)
        else:
            dlinear_enc = self.dlinear.encode(payload, fv)
        anomaly = self.dlinear.score_anomaly(dlinear_enc)

        all_probs: dict[str, float] = {}
        for label in self.labels:
            p = w_base * base_result.all_probs.get(label, 0.0)
            p += w_sem * sem_bias.get(label, 0.0)
            p += w_mm * mm_bias.get(label, 0.0)
            if label != "Normal":
                p += w_dl * anomaly * max(
                    mm_bias.get(label, 0.0),
                    sem_bias.get(label, 0.0),
                    base_result.all_probs.get(label, 0.0),
                )
            else:
                p += w_dl * (1.0 - anomaly) * 0.5
            all_probs[label] = p

        total = sum(all_probs.values()) or 1.0
        all_probs = {k: v / total for k, v in all_probs.items()}

        raw_low = payload.raw_payload.lower()
        base_attack_peak = max(
            (v for k, v in base_result.all_probs.items() if k != "Normal"), default=0.0,
        )
        strong_obf = has_strong_obfuscation(raw_low)
        decode_depth = len(payload.decode_chain)

        # 混淆 boost：强混淆 / 双轮解码 / base 攻击峰值达标
        should_boost = is_obfuscated(raw_low) and (
            strong_obf
            or decode_depth >= 2
            or base_attack_peak >= self._obf_boost_min_base
        )
        if should_boost:
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
        if not is_malicious and (
            strong_obf
            or (is_obfuscated(raw_low) and decode_depth >= 2)
        ):
            norm_text = (payload.normalized_payload or payload.raw_payload).lower()
            kw = attack_keyword_scores(norm_text)
            st = structural_attack_scores(
                payload.raw_payload, norm_text, decode_depth=decode_depth,
            )
            kw_peak = max((v for k, v in kw.items() if k != "Normal"), default=0.0)
            st_peak = max((v for k, v in st.items() if k != "Normal"), default=0.0)
            if decode_depth >= 2 and kw_peak >= 0.28:
                label = max((k for k in kw if k != "Normal"), key=lambda k: kw[k])
                confidence = max(confidence, kw_peak, thresh)
                is_malicious = True
            elif strong_obf and st_peak >= 0.48 and kw_peak >= 0.15:
                label = max((k for k in st if k != "Normal"), key=lambda k: st[k])
                confidence = max(confidence, st_peak, thresh)
                is_malicious = True
            elif decode_depth >= 2 and st_peak >= 0.52 and kw_peak >= 0.18:
                label = max((k for k in st if k != "Normal"), key=lambda k: st[k])
                confidence = max(confidence, st_peak, thresh)
                is_malicious = True

        hit = 0.0
        base_normal_peak = base_result.all_probs.get("Normal", 0.0)
        if self.cache and len(self.cache._entries) > 0:
            text = payload.normalized_payload or payload.raw_payload
            cache_lam = self.cache.fusion_weight
            if not strong_obf and base_attack_peak < 0.35:
                cache_lam = min(cache_lam, self._cache_fusion_benign)
            if base_normal_peak > 0.45 and base_attack_peak < 0.28:
                cache_lam *= 0.5
            all_probs = self.cache.fuse_probs(
                all_probs, text, raw_payload=payload.raw_payload, fusion_weight=cache_lam,
            )
            label = max(all_probs, key=all_probs.get)
            confidence = all_probs[label]
            attack_peak = max((v for k, v in all_probs.items() if k != "Normal"), default=0.0)
            hit = self.cache.cache_hit_strength(text)
            if (
                hit >= self._cache_force_hit
                and label != "Normal"
                and (strong_obf or base_attack_peak >= 0.30)
            ):
                is_malicious = True
                confidence = max(confidence, hit * 0.9)
            elif label != "Normal" and confidence >= thresh:
                is_malicious = True

        label, confidence, is_malicious = self._apply_fp_guard(
            label=label,
            confidence=confidence,
            is_malicious=is_malicious,
            all_probs=all_probs,
            base_result=base_result,
            base_attack_peak=base_attack_peak,
            strong_obf=strong_obf,
            decode_depth=decode_depth,
            cache_hit=hit,
        )

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
