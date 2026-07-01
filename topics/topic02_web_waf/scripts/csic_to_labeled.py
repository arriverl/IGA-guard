#!/usr/bin/env python3
"""CSIC 2010 → labeled_samples 格式转换（单文件入口）。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.dataset.csic_parser import iter_csic_file
from iga_guard.dataset.merge import write_csv


def main() -> int:
    parser = argparse.ArgumentParser(description="CSIC2010 转 payload,label CSV")
    parser.add_argument("--input", "-i", type=Path, required=True)
    parser.add_argument("--output", "-o", type=Path, required=True)
    parser.add_argument("--max-rows", type=int, default=None)
    parser.add_argument("--attack-only", action="store_true", help="仅保留非 Normal 标签")
    args = parser.parse_args()

    if not args.input.exists():
        print(f"文件不存在: {args.input}", file=sys.stderr)
        return 1

    rows = []
    for row in iter_csic_file(args.input, max_rows=args.max_rows):
        if args.attack_only and row["label"] == "Normal":
            continue
        rows.append({"payload": row["payload"], "label": row["label"]})

    n = write_csv(rows, args.output, fieldnames=["payload", "label"])
    print(f"Wrote {n} rows -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
