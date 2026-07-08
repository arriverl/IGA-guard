"""ModSec-AdvLearn 风格：离线校准融合权重并热加载。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_DEFAULT_PATH = Path("data/cache/fusion_calibration.json")


def load_fusion_calibration(path: str | Path | None = None) -> dict[str, Any]:
    p = Path(path) if path else _DEFAULT_PATH
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def apply_calibration(
    mm_cfg: dict,
    calibration: dict[str, Any],
    *,
    obfuscated: bool,
) -> dict[str, float]:
    """将校准系数叠加到 multimodal 配置权重上。"""
    key = "obfuscated" if obfuscated else "benign"
    base_key = f"weight_base_{key}"
    sem_key = f"weight_semantic_{key}"
    mm_key = f"weight_multimodal_{key}"
    dl_key = f"weight_dlinear_{key}"

    w_base = float(mm_cfg.get(base_key, mm_cfg.get("weight_base", 0.38)))
    w_sem = float(mm_cfg.get(sem_key, mm_cfg.get("weight_semantic", 0.28)))
    w_mm = float(mm_cfg.get(mm_key, mm_cfg.get("weight_multimodal", 0.14)))
    w_dl = float(mm_cfg.get(dl_key, mm_cfg.get("weight_dlinear", 0.12)))

    deltas = calibration.get(key, calibration.get("deltas", {}))
    w_base += float(deltas.get("base", 0.0))
    w_sem += float(deltas.get("semantic", 0.0))
    w_mm += float(deltas.get("multimodal", 0.0))
    w_dl += float(deltas.get("dlinear", 0.0))

    total = w_base + w_sem + w_mm + w_dl
    if total <= 0:
        return {"base": 0.38, "semantic": 0.28, "multimodal": 0.14, "dlinear": 0.12}
    return {
        "base": w_base / total,
        "semantic": w_sem / total,
        "multimodal": w_mm / total,
        "dlinear": w_dl / total,
    }
