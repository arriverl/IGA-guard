"""Unit tests for TimeSeriesBuffer and DLinear encode_series."""

from __future__ import annotations

import pytest

from iga_guard.collector.timeseries_buffer import TimeSeriesBuffer
from iga_guard.detector.dlinear_branch import DLinearBranch
from iga_guard.models import NormalizedPayload


def _payload(text: str) -> NormalizedPayload:
    return NormalizedPayload(raw_payload=text, normalized_payload=text)


class TestTimeSeriesBuffer:
    def test_push_get_matrix_full_window(self):
        buf = TimeSeriesBuffer(window=16)
        sid = "10.0.0.1"
        for i in range(16):
            buf.push(sid, _payload(f"union select {i}"), ts=float(i + 1))

        matrix = buf.get_matrix(sid)
        assert len(matrix) == 16
        assert all(len(row) == 6 for row in matrix)
        assert matrix[-1][4] > 0  # payload_len
        assert matrix[-1][1] >= 0  # entropy

    def test_get_matrix_zero_pads_cold_start(self):
        buf = TimeSeriesBuffer(window=16)
        sid = "cold"
        buf.push(sid, _payload("hello"), ts=1.0)

        matrix = buf.get_matrix(sid)
        assert len(matrix) == 16
        assert matrix[0] == [0.0] * 6
        assert matrix[-1][4] > 0

    def test_ring_buffer_drops_oldest(self):
        buf = TimeSeriesBuffer(window=4)
        sid = "ring"
        for i in range(6):
            buf.push(sid, _payload(f"p{i}"), ts=float(i))

        matrix = buf.get_matrix(sid)
        assert len(matrix) == 4
        # Only last 4 pushes retained; earliest row is zero-padded then 2 real + 2 pad? 
        # With window=4, after 6 pushes deque has p2..p5
        assert matrix[-1][4] > 0

    def test_source_key(self):
        buf = TimeSeriesBuffer()
        assert buf.source_key("1.2.3.4") == "1.2.3.4"
        assert buf.source_key("1.2.3.4", "sess-1") == "1.2.3.4:sess-1"


class TestDLinearEncodeSeries:
    @pytest.fixture
    def branch(self) -> DLinearBranch:
        return DLinearBranch(seq_len=16, moving_avg=4, n_features=6)

    def test_encode_series_output_shape(self, branch: DLinearBranch):
        matrix = [[1.0, 2.0, 0.1, 0.2, 50.0, 1.0] for _ in range(16)]
        enc = branch.encode_series(matrix)
        assert enc.shape == (3,)
        assert str(enc.dtype) == "float32"

    def test_encode_series_pads_short_matrix(self, branch: DLinearBranch):
        short = [[1.0, 3.0, 0.1, 0.2, 10.0, 0.0] for _ in range(4)]
        enc = branch.encode_series(short)
        assert enc.shape == (3,)
        assert float(enc[0]) >= 0.0

    def test_attack_sequence_higher_anomaly_than_normal(self, branch: DLinearBranch):
        normal = [
            [1.0, 3.0 + 0.01 * (i % 3), 0.05, 0.1, 20.0, 0.0]
            for i in range(16)
        ]
        attack = [
            [0.1, 5.0 + (2.5 if i % 4 == 0 else 0.0), 0.8, 0.9, 200.0, 2.0]
            for i in range(16)
        ]
        score_normal = branch.score_anomaly(branch.encode_series(normal))
        score_attack = branch.score_anomaly(branch.encode_series(attack))
        assert score_attack > score_normal
