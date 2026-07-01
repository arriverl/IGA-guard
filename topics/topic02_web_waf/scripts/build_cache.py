#!/usr/bin/env python3
"""Stage-1：从训练集少量样本构建持续学习 KV 缓存（免训练）。"""

from __future__ import annotations

import argparse
import csv
import random
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.evolution.continual_cache import ContinualCacheAdapter
from iga_guard.pipeline import load_config


def main() -> None:
    parser = argparse.ArgumentParser(description="构建 Tip-Adapter 风格持续学习缓存")
    parser.add_argument("--data", default=str(ROOT / "data" / "master" / "train_obfuscated.csv"))
    parser.add_argument("--per-class", type=int, default=30, help="每类 few-shot 样本数")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", default=str(ROOT / "models" / "continual_cache.npz"))
    args = parser.parse_args()

    cfg = load_config(ROOT / "configs" / "default.yaml")
    cache_cfg = cfg.get("continual_cache", {})
    adapter = ContinualCacheAdapter.load(config=cache_cfg)

    by_label: dict[str, list[str]] = defaultdict(list)
    with open(args.data, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            lab = row.get("label", "Normal")
            by_label[lab].append(row["payload"])

    rng = random.Random(args.seed)
    samples: list[tuple[str, str]] = []
    for lab, pool in by_label.items():
        if not pool:
            continue
        rng.shuffle(pool)
        for p in pool[: args.per_class]:
            samples.append((p, lab))

    adapter._entries.clear()
    n = adapter.build_from_samples(samples, source="few_shot_seed")
    adapter.save(args.output)
    print(f"Built cache: {n} entries, stats={adapter.stats()}")


if __name__ == "__main__":
    main()
