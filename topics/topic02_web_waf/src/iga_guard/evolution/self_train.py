"""Self-evolving training on failure samples."""

from __future__ import annotations

import csv
import json
import random
from pathlib import Path

import numpy as np

from iga_guard.adversarial import mutate_batch
from iga_guard.detector.fusion_model import FusionDetector
from iga_guard.features import extract_features
from iga_guard.models import GuardReport
from iga_guard.normalizer import normalize_payload


def log_failure(cache_path: str, report: GuardReport, true_label: str) -> None:
    path = Path(cache_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "url": report.request.url,
        "true_label": true_label,
        "predicted": report.detection.label,
        "payload": report.normalized[0].raw_payload if report.normalized else "",
    }
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _rows_to_xy(
    rows: list[dict[str, str]],
    *,
    augment_attack: int = 0,
    seed: int = 42,
) -> tuple[list[list[float]], list[str]]:
    """将 payload/label 行转为特征矩阵；仅对漏检攻击样本做有限增强。"""
    rng = random.Random(seed)
    X_list: list[list[float]] = []
    y_list: list[str] = []

    for row in rows:
        raw = row.get("payload", "")
        label = row.get("true_label") or row.get("label", "Normal")
        norm = normalize_payload(raw)
        fv = extract_features(norm)
        X_list.append(fv.combined)
        y_list.append(label)

        if augment_attack > 0 and label != "Normal":
            variants = mutate_batch(raw, label, n=augment_attack)
            rng.shuffle(variants)
            for variant in variants[:augment_attack]:
                vn = normalize_payload(variant)
                vf = extract_features(vn)
                X_list.append(vf.combined)
                y_list.append(label)

    return X_list, y_list


def _load_base_train_csv(
    path: Path,
    max_samples: int | None,
    seed: int,
) -> list[dict[str, str]]:
    if not path.exists():
        return []
    rows: list[dict[str, str]] = []
    with path.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            rows.append({"payload": row["payload"], "label": row.get("label", "Normal")})
    if max_samples and len(rows) > max_samples:
        rng = random.Random(seed)
        rng.shuffle(rows)
        rows = rows[:max_samples]
    return rows


def incremental_retrain(
    detector: FusionDetector,
    cache_path: str,
    model_out: str,
    min_samples: int = 10,
    *,
    base_train_csv: str | None = None,
    max_base_samples: int | None = 80_000,
    failure_augment: int = 2,
    seed: int = 42,
) -> dict:
    """
    在**原有训练集 + 漏检样本**上重训 RF，避免仅用漏检覆盖模型。
    """
    path = Path(cache_path)
    if not path.exists():
        return {"updated": False, "reason": "no cache"}

    failure_rows = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len(failure_rows) < min_samples:
        return {"updated": False, "reason": f"need {min_samples} samples, got {len(failure_rows)}"}

    base_rows: list[dict[str, str]] = []
    if base_train_csv:
        base_rows = _load_base_train_csv(Path(base_train_csv), max_base_samples, seed)

    X_list: list[list[float]] = []
    y_list: list[str] = []

    if base_rows:
        bx, by = _rows_to_xy(base_rows, augment_attack=0, seed=seed)
        X_list.extend(bx)
        y_list.extend(by)

    fx, fy = _rows_to_xy(failure_rows, augment_attack=failure_augment, seed=seed + 1)
    X_list.extend(fx)
    y_list.extend(fy)

    X = np.array(X_list, dtype=np.float32)
    detector.fit(X, y_list)
    detector.save(model_out)
    return {
        "updated": True,
        "base_samples": len(base_rows),
        "failure_samples": len(failure_rows),
        "total_train_rows": len(y_list),
        "augmented_failures": len(fx),
    }
