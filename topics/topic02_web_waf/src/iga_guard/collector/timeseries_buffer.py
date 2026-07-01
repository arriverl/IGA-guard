"""
时序特征环形缓冲（TimeSeriesBuffer）
=====================================
为 DLinear 统计轨提供「按流量源聚合」的 HTTP 请求时序矩阵。

设计依据（Agent1 文献）：
  Zeng et al., AAAI 2023 — DLinear 对趋势/季节分量分解，适合捕获
  请求率突变、熵值波动等低速率混淆逃逸特征。

每个时间步记录 6 维特征：
  [qps_slot, entropy, special_ratio, encoded_ratio, payload_len, decode_depth]

输出 shape: [window, 6]，不足 window 时前部零填充。
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from iga_guard.features import extract_features
from iga_guard.models import NormalizedPayload


@dataclass
class TimeSeriesPoint:
    """单条 HTTP 请求在时序上的一个采样点。"""
    qps_slot: float = 0.0       # 近似 QPS = 1/Δt
    entropy: float = 0.0        # Payload Shannon 熵
    special_ratio: float = 0.0    # 特殊字符占比
    encoded_ratio: float = 0.0    # URL 编码字符占比
    payload_len: float = 0.0      # 载荷长度
    decode_depth: float = 0.0     # 解混淆层数（混淆强度代理）


class TimeSeriesBuffer:
    """
    按 source_id（通常为客户端 IP）维护最近 window 条请求的时序特征。

    示例：
        buf = TimeSeriesBuffer(window=16)
        buf.push("192.168.1.1", normalized_payload)
        matrix = buf.get_matrix("192.168.1.1")  # -> list[list[float]] 16x6
    """

    def __init__(self, window: int = 16):
        self.window = window
        self._buffers: dict[str, deque[TimeSeriesPoint]] = defaultdict(
            lambda: deque(maxlen=window)
        )
        self._last_ts: dict[str, float] = {}

    def push(self, source_id: str, payload: NormalizedPayload, ts: float | None = None) -> None:
        """将当前请求特征追加到指定源的环形缓冲。"""
        import time

        now = ts if ts is not None else time.perf_counter()
        fv = extract_features(payload)
        stat = fv.statistical
        prev = self._last_ts.get(source_id)
        dt = max(now - prev, 1e-6) if prev else 1.0
        self._last_ts[source_id] = now

        point = TimeSeriesPoint(
            qps_slot=1.0 / dt,
            entropy=stat.get("entropy", 0.0),
            special_ratio=stat.get("special_ratio", 0.0),
            encoded_ratio=stat.get("encoded_ratio", 0.0),
            payload_len=stat.get("length", 0.0),
            decode_depth=stat.get("decode_depth", 0.0),
        )
        self._buffers[source_id].append(point)

    def get_matrix(self, source_id: str) -> list[list[float]]:
        """返回 [T, 6] 时序矩阵，供 DLinearBranch.encode_series() 使用。"""
        buf = self._buffers.get(source_id, deque())
        rows = [
            [p.qps_slot, p.entropy, p.special_ratio, p.encoded_ratio, p.payload_len, p.decode_depth]
            for p in buf
        ]
        while len(rows) < self.window:
            rows.insert(0, [0.0] * 6)
        return rows[-self.window :]

    def source_key(self, ip: str = "default", session: str = "") -> str:
        """构造缓冲区分区键。"""
        return f"{ip}:{session}" if session else ip
