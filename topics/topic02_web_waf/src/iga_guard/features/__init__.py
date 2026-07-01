"""Unified feature extraction with RL-GWO selection."""

from __future__ import annotations

from iga_guard.features.rl_gwo_selector import RLGWoFeatureSelector
from iga_guard.features.semantic import extract_semantic
from iga_guard.features.statistical import extract_statistical
from iga_guard.features.structural import extract_structural
from iga_guard.models import FeatureVector, NormalizedPayload

_selector = RLGWoFeatureSelector(k=15)


def extract_features(payload: NormalizedPayload, use_rl_gwo: bool = True) -> FeatureVector:
    text = payload.normalized_payload or payload.raw_payload
    statistical = extract_statistical(text)
    semantic = extract_semantic(text)
    structural = extract_structural(text)

    loc_map = {"query": 1.0, "body": 0.8, "header": 0.6, "cookie": 0.7, "json": 0.75}
    statistical["location_weight"] = loc_map.get(payload.location, 0.5)
    statistical["decode_depth"] = float(len(payload.decode_chain))

    merged: dict[str, float] = {}
    merged.update(statistical)
    merged.update(semantic)
    merged.update(structural)

    names = list(merged.keys())
    values = [merged[k] for k in names]

    if use_rl_gwo:
        selected = _selector.select(names)
        names, values = _selector.apply_mask(names, values, selected)

    return FeatureVector(
        statistical=statistical,
        semantic=semantic,
        combined=values,
        names=names,
    )


def get_feature_selector() -> RLGWoFeatureSelector:
    return _selector
