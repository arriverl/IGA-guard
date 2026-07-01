#!/usr/bin/env python3
"""Train fusion detector from labeled CSV."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.detector.dual_track import DualTrackDetector
from iga_guard.detector.fusion_model import FusionDetector
from iga_guard.features import extract_features
from iga_guard.normalizer import normalize_payload


def load_labeled(path: Path) -> tuple[np.ndarray, list[str]]:
    X_rows: list[list[float]] = []
    y: list[str] = []
    with path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            payload = row.get("payload", "")
            label = row.get("label", "Normal")
            norm = normalize_payload(payload)
            fv = extract_features(norm)
            X_rows.append(fv.combined)
            y.append(label)
    return np.array(X_rows, dtype=np.float32), y


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default=str(ROOT / "data" / "samples" / "labeled_samples.csv"))
    parser.add_argument("--model", default=str(ROOT / "models" / "fusion_detector.joblib"))
    args = parser.parse_args()

    X, y = load_labeled(Path(args.data))
    detector = FusionDetector()
    detector.fit(X, y)
    detector.save(args.model)
    print(f"Trained on {len(y)} samples -> {args.model}")


if __name__ == "__main__":
    main()
