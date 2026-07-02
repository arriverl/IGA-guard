#!/usr/bin/env python3
"""用 v3.1 新增混淆技术扩充训练集，合并写回 train_obfuscated.csv。"""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.dataset.obfuscation_techniques import (  # noqa: E402
    NEW_TECHNIQUES_V31,
    expand_payload,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="v3.1 混淆技术增量扩库")
    parser.add_argument(
        "--data",
        default=str(ROOT / "data" / "master" / "train_obfuscated.csv"),
    )
    parser.add_argument(
        "--output",
        default=str(ROOT / "data" / "master" / "train_obfuscated_v31.csv"),
    )
    parser.add_argument("--max-attack-rows", type=int, default=25000)
    parser.add_argument("--variants", type=int, default=2)
    parser.add_argument("--seed", type=int, default=20260702)
    parser.add_argument("--merge-original", action="store_true", default=True)
    args = parser.parse_args()

    src = Path(args.data)
    out = Path(args.output)
    rng = random.Random(args.seed)

    rows: list[dict[str, str]] = []
    with src.open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    attacks = [r for r in rows if r.get("label", "Normal") != "Normal"]
    rng.shuffle(attacks)
    attacks = attacks[: args.max_attack_rows]

    added: list[dict[str, str]] = []
    tech_stats: dict[str, int] = {}

    for i, row in enumerate(attacks):
        label = row["label"]
        payload = row["payload"]
        variants = expand_payload(
            payload,
            label,
            n=args.variants,
            seed=args.seed + i,
            techniques=NEW_TECHNIQUES_V31,
        )
        for v in variants:
            added.append({
                "payload": v["payload"],
                "label": label,
                "source": v["source"],
            })
            tech = v["source"].replace("obfuscation:", "").split("+")[0]
            tech_stats[tech] = tech_stats.get(tech, 0) + 1

    merged = list(rows) + added if args.merge_original else added
    fieldnames = ["payload", "label", "source"]
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(merged)

    summary = {
        "input_rows": len(rows),
        "attack_sampled": len(attacks),
        "added_variants": len(added),
        "output_rows": len(merged),
        "output": str(out),
        "top_techniques": sorted(tech_stats.items(), key=lambda x: -x[1])[:15],
    }
    summary_path = ROOT / "results" / "v3_augment_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
