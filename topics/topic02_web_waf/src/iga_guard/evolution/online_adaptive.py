"""在线自适应控制器：自动学习 / 自动回滚 / 流量分层灰度。

相对批处理 feedback-cycle，本模块面向请求路径上的准在线闭环：
  1) canary 流量先应用候选阈值/缓存更新
  2) 滑动窗口监控 reward / FPR 代理指标
  3) 恶化则自动回滚到快照；稳定则晋升到 stable 层
"""

from __future__ import annotations

import copy
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from iga_guard.detector.dual_track import DualTrackDetector


def _bucket(key: str, n: int = 100) -> int:
    h = hashlib.md5(key.encode("utf-8", errors="ignore")).hexdigest()
    return int(h[:8], 16) % n


class OnlineAdaptiveController:
    """分层灰度 + 快照回滚的在线自适应控制器。"""

    def __init__(
        self,
        state_path: str = "data/cache/online_adaptive_state.json",
        *,
        canary_pct: int = 10,
        promote_min_episodes: int = 40,
        promote_min_avg_reward: float = 0.15,
        rollback_avg_reward: float = -0.25,
        rollback_window: int = 30,
        max_threshold_delta: float = 0.08,
    ):
        self.state_path = Path(state_path)
        self.canary_pct = int(canary_pct)
        self.promote_min_episodes = int(promote_min_episodes)
        self.promote_min_avg_reward = float(promote_min_avg_reward)
        self.rollback_avg_reward = float(rollback_avg_reward)
        self.rollback_window = int(rollback_window)
        self.max_threshold_delta = float(max_threshold_delta)
        self.state = self._load()

    def _default(self) -> dict[str, Any]:
        return {
            "policy_id": "policy-bootstrap",
            "stable_policy_id": "policy-bootstrap-stable",
            "canary_policy_id": "policy-bootstrap-canary",
            "snapshot_id": "snapshot-bootstrap",
            "mode": "canary",  # canary | stable | freeze
            "episodes": 0,
            "promotions": 0,
            "rollbacks": 0,
            "rewards": [],
            "tier_stats": {"canary": 0, "stable": 0, "shadow": 0},
            "stable_thresholds": {},
            "canary_thresholds": {},
            "snapshot_thresholds": {},
            "last_event": "",
            "updated_at": 0.0,
        }

    def _load(self) -> dict[str, Any]:
        if self.state_path.exists():
            try:
                data = json.loads(self.state_path.read_text(encoding="utf-8"))
                base = self._default()
                base.update(data)
                return base
            except Exception:
                return self._default()
        return self._default()

    def _save(self) -> None:
        self.state["updated_at"] = time.time()
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(
            json.dumps(self.state, indent=2, ensure_ascii=False), encoding="utf-8",
        )

    def traffic_tier(self, traffic_key: str) -> str:
        """按流量键哈希分层：canary / stable / shadow。"""
        mode = self.state.get("mode", "canary")
        if mode == "freeze":
            return "stable"
        b = _bucket(traffic_key or "default", 100)
        if b < self.canary_pct:
            return "canary"
        if b < min(100, self.canary_pct + 5):
            return "shadow"  # 观察但不写回
        return "stable"

    def _ensure_snapshots(self, detector: DualTrackDetector) -> None:
        if not self.state.get("stable_thresholds"):
            self.state["stable_thresholds"] = dict(detector._rl_thresholds)
        if not self.state.get("canary_thresholds"):
            self.state["canary_thresholds"] = dict(detector._rl_thresholds)
        if not self.state.get("snapshot_thresholds"):
            self.state["snapshot_thresholds"] = copy.deepcopy(self.state["stable_thresholds"])

    def apply_tier(self, detector: DualTrackDetector, tier: str) -> None:
        """将对应层阈值应用到检测器（请求前调用）。"""
        self._ensure_snapshots(detector)
        if tier == "canary":
            src = self.state.get("canary_thresholds") or self.state["stable_thresholds"]
        else:
            src = self.state.get("stable_thresholds") or detector._rl_thresholds
        for k, v in src.items():
            detector._rl_thresholds[k] = float(v)

    def policy_for_request(self, detector: DualTrackDetector, traffic_key: str) -> dict[str, Any]:
        """Apply request-tier policy and return policy metadata for GuardReport."""
        tier = self.traffic_tier(traffic_key)
        self.apply_tier(detector, tier)
        policy_key = "canary_policy_id" if tier == "canary" else "stable_policy_id"
        return {
            "traffic_tier": tier,
            "policy_id": self.state.get(policy_key) or self.state.get("policy_id"),
            "snapshot_id": self.state.get("snapshot_id"),
            "mode": self.state.get("mode", "canary"),
        }

    def feedback(
        self,
        detector: DualTrackDetector,
        predicted: str,
        true_label: str,
        *,
        traffic_key: str = "",
        top_features: list[str] | None = None,
        lr: float = 0.05,
        rl_controller: Any | None = None,
    ) -> dict[str, Any]:
        """在线反馈：仅 canary 层学习；监控恶化则回滚。"""
        self._ensure_snapshots(detector)
        tier = self.traffic_tier(traffic_key)
        self.state["tier_stats"][tier] = int(self.state["tier_stats"].get(tier, 0)) + 1

        reward = 1.0 if predicted == true_label else -1.0
        if predicted != "Normal" and true_label != "Normal" and predicted != true_label:
            reward = -0.5

        event = {"tier": tier, "reward": reward, "predicted": predicted, "true_label": true_label}

        if tier == "shadow" or self.state.get("mode") == "freeze":
            self.state["rewards"].append(reward)
            self.state["rewards"] = self.state["rewards"][-500:]
            self.state["episodes"] += 1
            self._save()
            return {**event, "applied": False, "reason": "shadow_or_freeze"}

        if tier == "stable":
            # stable 层只记指标，不直接改阈值（防全量漂移）
            self.state["rewards"].append(reward)
            self.state["rewards"] = self.state["rewards"][-500:]
            self.state["episodes"] += 1
            self._maybe_rollback(detector)
            self._save()
            return {**event, "applied": False, "reason": "stable_observe"}

        # canary：应用学习到 canary_thresholds
        self.apply_tier(detector, "canary")
        if rl_controller is not None:
            rl_out = rl_controller.feedback(
                detector, predicted, true_label, top_features=top_features, lr=lr,
            )
        else:
            if reward < 0:
                detector.adjust_threshold(true_label, delta=-lr * 0.5)
            else:
                detector.adjust_threshold(predicted, delta=lr * 0.1)
            rl_out = {"reward": reward}

        # 限制相对 stable 的最大漂移
        stable = self.state["stable_thresholds"]
        for lab, val in list(detector._rl_thresholds.items()):
            base = float(stable.get(lab, detector.threshold))
            lo, hi = base - self.max_threshold_delta, base + self.max_threshold_delta
            detector._rl_thresholds[lab] = float(max(lo, min(hi, val)))

        self.state["canary_thresholds"] = dict(detector._rl_thresholds)
        self.state["rewards"].append(reward)
        self.state["rewards"] = self.state["rewards"][-500:]
        self.state["episodes"] += 1

        promoted = self._maybe_promote(detector)
        rolled = self._maybe_rollback(detector)
        self.state["last_event"] = "promote" if promoted else ("rollback" if rolled else "learn")
        self._save()
        return {
            **event,
            "applied": True,
            "rl": rl_out,
            "promoted": promoted,
            "rolled_back": rolled,
            "mode": self.state.get("mode"),
            "avg_reward": self.avg_reward(),
        }

    def avg_reward(self, window: int | None = None) -> float:
        rewards = self.state.get("rewards") or []
        if not rewards:
            return 0.0
        w = window or self.rollback_window
        chunk = rewards[-w:]
        return sum(chunk) / len(chunk)

    def _maybe_rollback(self, detector: DualTrackDetector) -> bool:
        rewards = self.state.get("rewards") or []
        if len(rewards) < max(10, self.rollback_window // 2):
            return False
        avg = self.avg_reward(self.rollback_window)
        if avg > self.rollback_avg_reward:
            return False
        snap = self.state.get("snapshot_thresholds") or self.state.get("stable_thresholds") or {}
        if not snap:
            return False
        self.state["canary_thresholds"] = copy.deepcopy(snap)
        self.state["stable_thresholds"] = copy.deepcopy(snap)
        for k, v in snap.items():
            detector._rl_thresholds[k] = float(v)
        self.state["rollbacks"] = int(self.state.get("rollbacks", 0)) + 1
        self.state["mode"] = "canary"
        self.state["last_event"] = "rollback"
        self.state["canary_policy_id"] = f"policy-rollback-{_stamp()}"
        return True

    def _maybe_promote(self, detector: DualTrackDetector) -> bool:
        if self.state.get("mode") == "freeze":
            return False
        rewards = self.state.get("rewards") or []
        if len(rewards) < self.promote_min_episodes:
            return False
        # 最近窗口与更长窗口均需达标
        if self.avg_reward(self.rollback_window) < self.promote_min_avg_reward:
            return False
        if self.avg_reward(min(len(rewards), self.promote_min_episodes)) < self.promote_min_avg_reward:
            return False
        # 晋升 canary → stable，并刷新快照
        self.state["snapshot_thresholds"] = copy.deepcopy(self.state.get("stable_thresholds") or {})
        self.state["stable_thresholds"] = copy.deepcopy(self.state.get("canary_thresholds") or {})
        for k, v in self.state["stable_thresholds"].items():
            detector._rl_thresholds[k] = float(v)
        self.state["promotions"] = int(self.state.get("promotions", 0)) + 1
        self.state["snapshot_id"] = f"snapshot-{_stamp()}"
        self.state["stable_policy_id"] = f"policy-stable-{_stamp()}"
        self.state["canary_policy_id"] = f"policy-canary-{_stamp()}"
        self.state["mode"] = "stable" if self.canary_pct >= 100 else "canary"
        # 晋升后可逐步扩大 canary（上限 50%）
        if self.canary_pct < 50:
            self.canary_pct = min(50, self.canary_pct + 5)
            self.state["canary_pct"] = self.canary_pct
        return True

    def status(self) -> dict[str, Any]:
        return {
            "mode": self.state.get("mode"),
            "policy_id": self.state.get("policy_id"),
            "stable_policy_id": self.state.get("stable_policy_id"),
            "canary_policy_id": self.state.get("canary_policy_id"),
            "snapshot_id": self.state.get("snapshot_id"),
            "episodes": self.state.get("episodes"),
            "promotions": self.state.get("promotions"),
            "rollbacks": self.state.get("rollbacks"),
            "canary_pct": self.canary_pct,
            "avg_reward": round(self.avg_reward(), 4),
            "tier_stats": self.state.get("tier_stats"),
            "last_event": self.state.get("last_event"),
            "stable_thresholds": self.state.get("stable_thresholds"),
            "canary_thresholds": self.state.get("canary_thresholds"),
        }

    def freeze(self) -> None:
        self.state["mode"] = "freeze"
        self._save()

    def unfreeze(self) -> None:
        self.state["mode"] = "canary"
        self._save()


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
