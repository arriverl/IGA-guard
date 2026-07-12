"""在线自适应：分层 / 回滚 / 晋升 基础行为。"""

from iga_guard.evolution.online_adaptive import OnlineAdaptiveController


class _FakeDet:
    def __init__(self):
        self.threshold = 0.38
        self._rl_thresholds = {
            "SQLi": 0.38, "XSS": 0.38, "CMD": 0.38, "Normal": 0.38,
        }

    def adjust_threshold(self, label: str, delta: float) -> None:
        self._rl_thresholds[label] = float(
            max(0.2, min(0.95, self._rl_thresholds.get(label, self.threshold) + delta))
        )


def test_traffic_tier_split(tmp_path):
    ctl = OnlineAdaptiveController(str(tmp_path / "oa.json"), canary_pct=10)
    tiers = {ctl.traffic_tier(f"k{i}") for i in range(200)}
    assert "canary" in tiers
    assert "stable" in tiers


def test_export_audit_threshold_policy(tmp_path):
    ctl = OnlineAdaptiveController(str(tmp_path / "oa.json"), canary_pct=100)
    path = tmp_path / "audit.json"
    payload = ctl.export_audit(path)
    assert path.exists()
    assert payload["policy_kind"] == "threshold_policy_bundle"
    assert "stable_thresholds" in payload["covers"]
    assert "model_weights" in payload["does_not_cover"]
