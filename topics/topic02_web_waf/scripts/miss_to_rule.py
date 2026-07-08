#!/usr/bin/env python3
"""Miss 聚类 → 规则候选 → FP 回放 → discovered_rescue_rules.json。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.evolution.miss_rule_pipeline import process_miss_file, process_misses
from iga_guard.obfuscation_signals import reload_discovered_rescue_rules


def main() -> int:
    parser = argparse.ArgumentParser(description="漏检样本自动转 rescue 规则")
    parser.add_argument(
        "--input",
        default=str(ROOT / "data" / "cache" / "eval_obf_misses.jsonl"),
        help="漏检 JSONL",
    )
    parser.add_argument("--tail", type=int, default=50, help="仅处理末尾 N 条")
    parser.add_argument("--max-fp-rate", type=float, default=0.02)
    parser.add_argument("--output", default=str(ROOT / "data" / "cache" / "miss_rule_report.json"))
    args = parser.parse_args()

    result = process_miss_file(
        args.input,
        tail=args.tail,
        rules_path=ROOT / "data" / "cache" / "discovered_rescue_rules.json",
        benign_path=ROOT / "data" / "cache" / "eval_normal_fps.jsonl",
        max_fp_rate=args.max_fp_rate,
    )
    reload_discovered_rescue_rules()

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"Report -> {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
