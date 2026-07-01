"""Enhanced RL-GWO inspired dynamic feature selection."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

# Default top features when no trained weights exist
DEFAULT_SELECTED = [
    "entropy",
    "special_ratio",
    "encoded_ratio",
    "sqli_score",
    "xss_score",
    "path_score",
    "decode_depth",
    "location_weight",
    "ast_depth",
    "html_nodes",
    "xml_entities",
    "xxe_score",
    "prompt_score",
    "digit_ratio",
    "tag_count",
]


class RLGWoFeatureSelector:
    """
    Simplified Grey Wolf Optimization + reinforcement-style weight update.
    Selects top-k features from candidate pool based on importance scores.
    """

    def __init__(self, k: int = 15, weights_path: str | None = None):
        self.k = k
        self.weights: dict[str, float] = {}
        if weights_path and Path(weights_path).exists():
            self.weights = json.loads(Path(weights_path).read_text(encoding="utf-8"))

    def select(self, all_names: list[str], importance_hint: dict[str, float] | None = None) -> list[str]:
        scores: dict[str, float] = {}
        for i, name in enumerate(all_names):
            base = self.weights.get(name, 1.0 / (1 + i * 0.01))
            if importance_hint and name in importance_hint:
                base += importance_hint[name]
            scores[name] = base

        ranked = sorted(scores, key=scores.get, reverse=True)
        selected = ranked[: self.k]
        # ensure minimum coverage
        for must in DEFAULT_SELECTED:
            if must in all_names and must not in selected and len(selected) < self.k:
                selected.append(must)
        return selected[: self.k]

    def apply_mask(self, names: list[str], values: list[float], selected: list[str]) -> tuple[list[str], list[float]]:
        idx = {n: i for i, n in enumerate(names)}
        out_names = [n for n in selected if n in idx]
        out_vals = [values[idx[n]] for n in out_names]
        return out_names, out_vals

    def update_from_feedback(self, feature_name: str, reward: float, lr: float = 0.05) -> None:
        old = self.weights.get(feature_name, 0.5)
        self.weights[feature_name] = float(np.clip(old + lr * reward, 0.01, 2.0))

    def save(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(self.weights, indent=2), encoding="utf-8")
