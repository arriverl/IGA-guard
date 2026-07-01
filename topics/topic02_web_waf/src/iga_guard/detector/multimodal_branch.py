"""
多模态检测分支（Multimodal Branch）
====================================
IGA-Guard 3.0 显式多模态融合（冻结编码器，免训练）：

  模态 A · 协议轨：Content-Type / HPP / multipart / 字段位置
  模态 B · 视觉轨：载荷字节二维栅格 + 固定卷积特征（混淆形态）

与文本轨（TinyBERT）、时序轨（DLinear）late-fusion，不微调主干。
"""

from __future__ import annotations

import re
from collections import defaultdict

import numpy as np

from iga_guard.models import ATTACK_LABELS, NormalizedPayload
from iga_guard.obfuscation_signals import (
    attack_keyword_scores,
    is_obfuscated,
    structural_attack_scores,
)

_PARAM = re.compile(r"(?:^|[&?])(\w+)=", re.I)


class ByteImageEncoder:
    """将 payload 映射为 H×W 栅格，提取固定视觉特征（类 CNN，无训练）。"""

    HEIGHT = 32
    WIDTH = 64
    EMB_DIM = 64

    def payload_to_grid(self, raw: str) -> np.ndarray:
        data = (raw or "").encode("utf-8", errors="replace")[: self.HEIGHT * self.WIDTH]
        grid = np.zeros((self.HEIGHT, self.WIDTH), dtype=np.float32)
        for i, b in enumerate(data):
            grid[i // self.WIDTH, i % self.WIDTH] = b / 255.0
        return grid

    def encode(self, raw: str) -> np.ndarray:
        grid = self.payload_to_grid(raw)
        feats: list[float] = [
            float(grid.mean()),
            float(grid.std()),
            float((grid > 0.6).mean()),
            float((grid < 0.05).mean()),
        ]
        for br in range(8):
            for bc in range(16):
                block = grid[br * 4 : (br + 1) * 4, bc * 4 : (bc + 1) * 4]
                feats.append(float(block.mean()))
        gx = np.diff(grid, axis=1, prepend=grid[:, :1])
        gy = np.diff(grid, axis=0, prepend=grid[:1, :])
        feats.append(float(np.abs(gx).mean()))
        feats.append(float(np.abs(gy).mean()))
        high = (grid > 0.8).astype(np.float32)
        feats.append(float(high.sum() / max(grid.size, 1)))

        vec = np.array(feats[: self.EMB_DIM], dtype=np.float32)
        if vec.shape[0] < self.EMB_DIM:
            vec = np.pad(vec, (0, self.EMB_DIM - vec.shape[0]))
        norm = np.linalg.norm(vec)
        if norm > 1e-8:
            vec /= norm
        return vec


class ProtocolEncoder:
    """协议 / 结构模态：HTTP 字段位置 + HPP + multipart 等。"""

    def encode_features(self, payload: NormalizedPayload) -> dict[str, float]:
        raw = payload.raw_payload or ""
        norm = payload.normalized_payload or raw
        raw_low = raw.lower()
        loc = payload.location or "query"

        loc_w = {"query": 1.0, "body": 0.85, "header": 0.7, "cookie": 0.75, "json": 0.8}.get(loc, 0.6)
        buckets: dict[str, list[str]] = defaultdict(list)
        for m in _PARAM.finditer(raw_low.replace("?", "&")):
            buckets[m.group(1).lower()].append("1")
        hpp = 1.0 if any(len(v) > 1 for v in buckets.values()) else 0.0

        return {
            "proto_location": loc_w,
            "proto_decode_depth": min(len(payload.decode_chain), 6) / 6.0,
            "proto_obfuscated": 1.0 if is_obfuscated(raw) else 0.0,
            "proto_multipart": 1.0 if "webkitformboundary" in raw_low else 0.0,
            "proto_hpp": hpp,
            "proto_ampersand_density": min(raw.count("&") / 20.0, 1.0),
            "proto_pct_density": min(raw.count("%") / 30.0, 1.0),
            "proto_null_byte": 1.0 if "%00" in raw_low else 0.0,
        }

    def class_bias(self, payload: NormalizedPayload) -> dict[str, float]:
        feats = self.encode_features(payload)
        bias = {lb: 0.04 if lb == "Normal" else 0.0 for lb in ATTACK_LABELS}
        norm = (payload.normalized_payload or payload.raw_payload).lower()

        if feats["proto_hpp"] > 0 or feats["proto_ampersand_density"] > 0.3:
            bias["SQLi"] += 0.35
        if feats["proto_multipart"] > 0:
            bias["XSS"] += 0.3
            bias["CMD"] += 0.2
        if feats["proto_null_byte"] > 0:
            bias["SQLi"] += 0.25
            bias["CMD"] += 0.15
        if feats["proto_pct_density"] > 0.4 and is_obfuscated(payload.raw_payload):
            bias["SQLi"] += 0.2
            bias["XSS"] += 0.2
        if feats["proto_decode_depth"] >= 0.33:
            for lb, w in attack_keyword_scores(norm).items():
                if lb != "Normal":
                    bias[lb] += 0.15 * w

        st = structural_attack_scores(
            payload.raw_payload, norm, decode_depth=len(payload.decode_chain),
        )
        for lb in ATTACK_LABELS:
            if lb != "Normal":
                bias[lb] += 0.2 * st.get(lb, 0.0)

        total = sum(bias.values()) or 1.0
        return {k: v / total for k, v in bias.items()}


class VisionEncoder:
    """视觉模态 → 类别偏置（基于字节图纹理与攻击形态启发式）。"""

    def __init__(self) -> None:
        self.byte_enc = ByteImageEncoder()

    def encode(self, raw: str) -> np.ndarray:
        return self.byte_enc.encode(raw)

    def class_bias(self, payload: NormalizedPayload) -> dict[str, float]:
        raw = payload.raw_payload or ""
        vec = self.encode(raw)
        bias = {lb: 0.05 if lb == "Normal" else 0.0 for lb in ATTACK_LABELS}

        entropy_proxy = float(vec[1]) if vec.size > 1 else 0.0
        edge_energy = float(vec[-2]) if vec.size > 2 else 0.0
        high_byte_ratio = float(vec[-1]) if vec.size > 0 else 0.0

        if entropy_proxy > 0.15 and is_obfuscated(raw):
            bias["SQLi"] += 0.25
            bias["XSS"] += 0.2
        if edge_energy > 0.12:
            bias["XSS"] += 0.2
            bias["CMD"] += 0.15
        if high_byte_ratio > 0.08:
            bias["SQLi"] += 0.2

        norm = (payload.normalized_payload or raw).lower()
        if "union" in norm or "select" in norm:
            bias["SQLi"] += 0.25
        if "<script" in norm or "alert" in norm:
            bias["XSS"] += 0.3

        total = sum(bias.values()) or 1.0
        return {k: v / total for k, v in bias.items()}


class MultimodalBranch:
    """
    协议 + 视觉 双模态融合分支。
    输出与 semantic_branch 兼容的 class_bias 字典。
    """

    def __init__(self, enabled: bool = True, vision_weight: float = 0.45):
        self.enabled = enabled
        self.vision_weight = vision_weight
        self.protocol = ProtocolEncoder()
        self.vision = VisionEncoder()

    def encode_vision(self, raw: str) -> np.ndarray:
        return self.vision.encode(raw)

    def class_bias(self, payload: NormalizedPayload) -> dict[str, float]:
        if not self.enabled:
            return {lb: 0.0 for lb in ATTACK_LABELS}

        proto = self.protocol.class_bias(payload)
        vis = self.vision.class_bias(payload)
        vw = self.vision_weight
        fused = {
            lb: (1.0 - vw) * proto.get(lb, 0.0) + vw * vis.get(lb, 0.0)
            for lb in ATTACK_LABELS
        }
        total = sum(fused.values()) or 1.0
        return {k: v / total for k, v in fused.items()}

    def multimodal_vector(self, payload: NormalizedPayload) -> np.ndarray:
        """拼接协议标量 + 视觉 embedding，供缓存多 Key 使用。"""
        pf = self.protocol.encode_features(payload)
        proto_vec = np.array(list(pf.values()), dtype=np.float32)
        vis_vec = self.vision.encode(payload.raw_payload or "")
        out = np.concatenate([proto_vec, vis_vec], axis=0)
        norm = np.linalg.norm(out)
        if norm > 1e-8:
            out /= norm
        return out
