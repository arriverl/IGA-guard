#!/usr/bin/env python3
"""从 CSIC Normal 样本扩充持续学习缓存（仅追加 Normal，不清空攻击条目）。"""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.evolution.continual_cache import ContinualCacheAdapter
from iga_guard.pipeline import load_config


def _load_normal_payloads(*paths: Path) -> list[str]:
    rows: list[str] = []
    for path in paths:
        if not path.exists():
            continue
        with path.open(encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                if row.get("label", "Normal") == "Normal":
                    payload = row.get("payload", "")
                    if payload:
                        rows.append(payload)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="扩充 Normal 负样本到持续学习缓存")
    parser.add_argument(
        "--train",
        default=str(ROOT / "data" / "master" / "train_obfuscated.csv"),
    )
    parser.add_argument(
        "--test",
        default=str(ROOT / "data" / "master" / "test_obfuscated.csv"),
    )
    parser.add_argument("--sample", type=int, default=200, help="抽样 Normal 条数")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--input",
        default=str(ROOT / "models" / "continual_cache_v2.npz"),
        help="已有缓存路径（不存在则新建空库）",
    )
    parser.add_argument(
        "--output",
        default=str(ROOT / "models" / "continual_cache_v2.npz"),
    )
    args = parser.parse_args()

    cfg = load_config(ROOT / "configs" / "default.yaml")
    cache_cfg = dict(cfg.get("continual_cache", {}))
    input_path = Path(args.input)
    adapter = (
        ContinualCacheAdapter.load(path=input_path, config=cache_cfg)
        if input_path.exists()
        else ContinualCacheAdapter.load(config=cache_cfg)
    )

    pool = _load_normal_payloads(Path(args.train), Path(args.test))
    if not pool:
        print(json.dumps({"error": "no Normal rows found in train/test CSV"}))
        return

    rng = random.Random(args.seed)
    rng.shuffle(pool)
    n = min(args.sample, len(pool))
    samples = [(p, "Normal") for p in pool[:n]]

    added = adapter.expand_normal_seeds(samples, source="csic_normal_expand")
    adapter.save(args.output)
    stats = adapter.stats()
    print(json.dumps({
        "added": added,
        "sampled": n,
        "pool_size": len(pool),
        "cache_size": stats["size"],
        "encoder_mode": stats["encoder_mode"],
        "output": args.output,
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
