"""
DLinear 统计轨（Statistical Track）
===================================
参考 Zeng et al., AAAI 2023「Are Transformers Effective for Time Series Forecasting?」

将 HTTP 请求特征时序分解为：
  - Trend（移动平均趋势）
  - Seasonal/Residual（残差 = 原序列 - 趋势）

输出 anomaly 特征向量 [residual_energy, trend_slope, qps_mean]，
经 sigmoid 映射为 anomaly_score ∈ (0,1)，供 dual_track 融合。
"""

from __future__ import annotations

import numpy as np

from iga_guard.models import FeatureVector, NormalizedPayload


class DLinearBranch:
    """Trend + seasonal decomposition on per-source request feature sequences."""

    def __init__(self, seq_len: int = 16, moving_avg: int = 4, n_features: int = 6):
        self.seq_len = seq_len
        self.moving_avg = moving_avg
        self.n_features = n_features

    def _moving_average(self, x: np.ndarray, window: int) -> np.ndarray:
        if len(x) < window:
            return x
        kernel = np.ones(window) / window
        return np.convolve(x, kernel, mode="same")

    def encode_series(self, matrix: list[list[float]]) -> np.ndarray:
        """Encode [T, F] time-series matrix → anomaly features."""
        arr = np.array(matrix, dtype=np.float32)
        if arr.ndim == 1:
            arr = arr.reshape(-1, 1)
        if arr.shape[0] < self.seq_len:
            pad = np.zeros((self.seq_len - arr.shape[0], arr.shape[1]), dtype=np.float32)
            arr = np.vstack([pad, arr])

        # Use entropy channel (index 1) as primary series; aggregate all channels
        primary = arr[:, 1] if arr.shape[1] > 1 else arr[:, 0]
        trend = self._moving_average(primary, self.moving_avg)
        seasonal = primary - trend
        residual_energy = float(np.mean(np.abs(seasonal)))
        trend_slope = float(trend[-1] - trend[0]) if len(trend) > 1 else 0.0
        qps_mean = float(np.mean(arr[:, 0])) if arr.shape[1] > 0 else 0.0
        return np.array([residual_energy, trend_slope, qps_mean], dtype=np.float32)

    def encode(self, payload: NormalizedPayload, fv: FeatureVector) -> np.ndarray:
        """Fallback: single-request pseudo sequence from feature vector."""
        seq = np.array(fv.combined[: self.seq_len], dtype=np.float32)
        if len(seq) < self.seq_len:
            seq = np.pad(seq, (0, self.seq_len - len(seq)))
        trend = self._moving_average(seq, self.moving_avg)
        seasonal = seq - trend
        residual_energy = float(np.mean(np.abs(seasonal)))
        trend_slope = float(trend[-1] - trend[0]) if len(trend) > 1 else 0.0
        entropy_spike = float(fv.statistical.get("entropy", 0.0))
        return np.array([residual_energy, trend_slope, entropy_spike], dtype=np.float32)

    def score_anomaly(self, encoding: np.ndarray) -> float:
        return float(1.0 / (1.0 + np.exp(-(encoding[0] * 2 + abs(encoding[1]) + encoding[2] * 0.1))))
