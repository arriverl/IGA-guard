#!/usr/bin/env python3
"""从评估漏检导出 failures 并 honest 增量重训（合并原训练集）。"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard import IgaGuardEngine
from iga_guard.evolution.self_train import incremental_retrain
from iga_guard.detector.fusion_model import FusionDetector
from iga_guard.obfuscation_signals import is_obfuscated
from iga_guard.pipeline import load_config


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default=str(ROOT / "data" / "master" / "test_obfuscated.csv"))
    parser.add_argument("--max-scan", type=int, default=5000)
    parser.add_argument("--cache", default=str(ROOT / "data" / "cache" / "failures.jsonl"))
    parser.add_argument("--base-train", default=str(ROOT / "data" / "master" / "train_obfuscated.csv"))
    parser.add_argument("--model", default=str(ROOT / "models" / "fusion_detector.joblib"))
    parser.add_argument("--export-only", action="store_true")
    args = parser.parse_args()

    engine = IgaGuardEngine(load_config(ROOT / "configs" / "default.yaml"))
    cache = Path(args.cache)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text("", encoding="utf-8")

    misses = 0
    with open(args.data, encoding="utf-8", newline="") as f:
        for i, row in enumerate(csv.DictReader(f)):
            if args.max_scan and i >= args.max_scan:
                break
            payload, label = row["payload"], row["label"]
            if label == "Normal":
                continue
            if not is_obfuscated(payload):
                continue
            rep = engine.analyze_url("GET", f"http://eval.local/?p={payload[:500]}")
            if rep.detection.is_malicious or rep.detection.label != "Normal":
                continue
            record = {
                "url": f"http://eval.local/?p={payload[:200]}",
                "true_label": label,
                "predicted": rep.detection.label,
                "payload": payload,
                "source": row.get("source", ""),
            }
            with cache.open("a", encoding="utf-8") as out:
                out.write(json.dumps(record, ensure_ascii=False) + "\n")
            misses += 1

    print(json.dumps({"exported_misses": misses, "cache": str(cache)}, indent=2))
    if args.export_only or misses < 20:
        return

    detector = FusionDetector(args.model if Path(args.model).exists() else None)
    result = incremental_retrain(
        detector,
        str(cache),
        args.model,
        min_samples=20,
        base_train_csv=args.base_train,
        max_base_samples=80_000,
        failure_augment=2,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
