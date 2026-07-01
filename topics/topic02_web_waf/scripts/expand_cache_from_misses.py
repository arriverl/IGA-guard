#!/usr/bin/env python3
"""将 eval 漏检样本合法写入持续学习缓存（不覆盖 RF，仅扩库）。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.evolution.continual_cache import ContinualCacheAdapter
from iga_guard.pipeline import load_config


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--misses",
        default=str(ROOT / "data" / "cache" / "eval_obf_misses.jsonl"),
    )
    parser.add_argument("--max-rows", type=int, default=500)
    parser.add_argument("--output", default=str(ROOT / "models" / "continual_cache.npz"))
    args = parser.parse_args()

    misses_path = Path(args.misses)
    if not misses_path.exists():
        print(json.dumps({"error": f"missing {misses_path}"}))
        return

    cfg = load_config(ROOT / "configs" / "default.yaml")
    adapter = ContinualCacheAdapter.load(config=cfg.get("continual_cache", {}))

    added = updated = 0
    with misses_path.open(encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i >= args.max_rows:
                break
            row = json.loads(line)
            label = row.get("label", "Normal")
            payload = row.get("payload", "")
            if not payload or label == "Normal":
                continue
            is_new = adapter.append(
                payload, label, source="eval_miss", save=False,
            )
            if is_new:
                added += 1
            else:
                updated += 1

    adapter.save(args.output)
    stats = adapter.stats()
    print(json.dumps({
        "added": added,
        "dedupe_updated": updated,
        "cache_size": stats["size"],
        "output": args.output,
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
