#!/usr/bin/env python3
"""将对抗漏检 CSV 写入 failures.jsonl，并在原训练集+漏检上重训 RF。"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.detector.fusion_model import FusionDetector
from iga_guard.evolution.self_train import incremental_retrain
from iga_guard.pipeline import load_config


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--misses",
        default=str(ROOT / "results" / "v2_exp3_adversarial_rounds_misses.csv"),
    )
    parser.add_argument("--cache", default=str(ROOT / "data" / "cache" / "failures.jsonl"))
    parser.add_argument("--model", default=str(ROOT / "models" / "fusion_detector.joblib"))
    parser.add_argument(
        "--base-train",
        default=str(ROOT / "data" / "master" / "train_obfuscated.csv"),
        help="原训练集（必须与漏检合并重训，禁止仅漏检覆盖）",
    )
    parser.add_argument("--min-samples", type=int, default=20)
    parser.add_argument("--max-rows", type=int, default=300)
    parser.add_argument("--max-base", type=int, default=80_000)
    parser.add_argument("--failure-augment", type=int, default=2)
    args = parser.parse_args()

    misses_path = Path(args.misses)
    if not misses_path.exists():
        print(json.dumps({"updated": False, "reason": f"misses file missing: {misses_path}"}))
        return

    cache_path = Path(args.cache)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text("", encoding="utf-8")

    n = 0
    with misses_path.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            if n >= args.max_rows:
                break
            record = {
                "url": f"http://evolve.local/?p={row['payload'][:200]}",
                "true_label": row["label"],
                "predicted": row["predicted"],
                "payload": row["payload"],
            }
            with cache_path.open("a", encoding="utf-8") as out:
                out.write(json.dumps(record, ensure_ascii=False) + "\n")
            n += 1

    cfg = load_config(ROOT / "configs" / "default.yaml")
    model_path = cfg.get("detector", {}).get("model_path", args.model)
    detector = FusionDetector(model_path if Path(model_path).exists() else None)
    result = incremental_retrain(
        detector,
        str(cache_path),
        args.model,
        min_samples=args.min_samples,
        base_train_csv=args.base_train,
        max_base_samples=args.max_base,
        failure_augment=args.failure_augment,
    )
    print(json.dumps({"logged_misses": n, **result}, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
