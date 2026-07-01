"""Online reinforcement learning for threshold and feature weight adjustment."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from iga_guard.features import get_feature_selector

if TYPE_CHECKING:
    from iga_guard.detector.dual_track import DualTrackDetector


class OnlineRLController:
    """Lightweight online RL: reward correct detections, penalize misses."""

    def __init__(self, state_path: str = "data/cache/rl_state.json"):
        self.state_path = Path(state_path)
        self.state = self._load()

    def _load(self) -> dict:
        if self.state_path.exists():
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        return {"episodes": 0, "rewards": []}

    def _save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(self.state, indent=2), encoding="utf-8")

    def feedback(
        self,
        detector: DualTrackDetector,
        predicted: str,
        true_label: str,
        top_features: list[str] | None = None,
        lr: float = 0.05,
    ) -> dict:
        reward = 1.0 if predicted == true_label else -1.0
        if predicted != "Normal" and true_label != "Normal" and predicted != true_label:
            reward = -0.5  # wrong attack type

        if reward < 0:
            detector.adjust_threshold(true_label, delta=-lr * 0.5)
        else:
            detector.adjust_threshold(predicted, delta=lr * 0.1)

        selector = get_feature_selector()
        if top_features:
            for feat in top_features[:5]:
                selector.update_from_feedback(feat, reward, lr=lr)

        self.state["episodes"] += 1
        self.state["rewards"].append(reward)
        self.state["rewards"] = self.state["rewards"][-500:]
        self._save()

        return {
            "reward": reward,
            "episodes": self.state["episodes"],
            "avg_reward": sum(self.state["rewards"]) / len(self.state["rewards"]),
        }

    def history(self) -> list[dict]:
        rewards = self.state.get("rewards", [])
        return [{"episode": i + 1, "reward": r} for i, r in enumerate(rewards[-100:])]
