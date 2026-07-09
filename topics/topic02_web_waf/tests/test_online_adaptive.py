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


def test_rollback_on_bad_rewards(tmp_path):
    det = _FakeDet()
    ctl = OnlineAdaptiveController(
        str(tmp_path / "oa.json"),
        canary_pct=100,
        rollback_window=10,
        rollback_avg_reward=-0.2,
        promote_min_episodes=1000,
    )
    ctl.apply_tier(det, "canary")
    snap = dict(det._rl_thresholds)
    ctl.state["snapshot_thresholds"] = dict(snap)
    ctl.state["stable_thresholds"] = dict(snap)
    # 连续负反馈
    for i in range(12):
        ctl.feedback(det, "SQLi", "CMD", traffic_key=f"c{i}", lr=0.05)
    assert ctl.state["rollbacks"] >= 1
    assert det._rl_thresholds["SQLi"] == snap["SQLi"]
