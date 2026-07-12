#!/usr/bin/env python3
"""E9 可复现协议：固定 seed × N 次取 pooled_recall 中位数，回写 canonical。"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run_once(seed: int, rounds: int, max_variants: int, no_llm: bool) -> dict:
    out = ROOT / "results" / f"v2_exp9_repro_seed{seed}.json"
    cmd = [
        sys.executable,
        "scripts/run_llm_redteam.py",
        "--rounds", str(rounds),
        "--max-variants", str(max_variants),
        "--seed", str(seed),
        "--output", str(out),
    ]
    if no_llm:
        cmd.append("--no-llm")
    rc = subprocess.call(cmd, cwd=ROOT)
    if rc != 0 or not out.exists():
        return {"seed": seed, "error": rc, "pooled_recall": 0.0}
    payload = json.loads(out.read_text(encoding="utf-8"))
    return {
        "seed": seed,
        "pooled_recall": float(payload.get("pooled_recall") or 0.0),
        "final_round_recall": float(payload.get("final_round_recall") or 0.0),
        "block_recall": float(payload.get("block_recall") or 0.0),
        "label_recall": float(payload.get("label_recall") or 0.0),
        "file": str(out.relative_to(ROOT)),
        "llm_enabled": payload.get("llm_enabled"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="E9 reproducible median protocol")
    parser.add_argument("--seeds", nargs="+", type=int, default=[41, 42, 43])
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--max-variants", type=int, default=80)
    parser.add_argument("--no-llm", action="store_true", default=True)
    parser.add_argument("--use-llm", action="store_true")
    parser.add_argument(
        "--output",
        default=str(ROOT / "results" / "v2_exp9_repro_median.json"),
    )
    parser.add_argument("--update-canonical", action="store_true")
    args = parser.parse_args()
    no_llm = not args.use_llm

    runs = [_run_once(s, args.rounds, args.max_variants, no_llm) for s in args.seeds]
    pooled = [r["pooled_recall"] for r in runs]
    median = statistics.median(pooled) if pooled else 0.0
    report = {
        "experiment": "E9_repro_median",
        "seeds": args.seeds,
        "rounds": args.rounds,
        "max_variants": args.max_variants,
        "no_llm": no_llm,
        "runs": runs,
        "pooled_recall_median": round(median, 4),
        "pooled_recall_mean": round(sum(pooled) / len(pooled), 4) if pooled else 0.0,
        "pooled_recall_min": round(min(pooled), 4) if pooled else 0.0,
        "pooled_recall_max": round(max(pooled), 4) if pooled else 0.0,
    }
    out = Path(args.output)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))

    if args.update_canonical:
        canon_path = ROOT / "results" / "canonical_metrics.json"
        canon = json.loads(canon_path.read_text(encoding="utf-8")) if canon_path.exists() else {}
        out_rel = str(out.resolve().relative_to(ROOT.resolve())).replace("\\", "/")
        canon["e9_80"] = {
            "file": out_rel,
            "pooled_recall": report["pooled_recall_median"],
            "final_round_recall": statistics.median(
                [r.get("final_round_recall", 0.0) for r in runs]
            ),
            "block_recall": statistics.median(
                [r.get("block_recall", 0.0) for r in runs]
            ),
            "protocol": "fixed_seed_x3_median",
            "seeds": args.seeds,
            "no_llm": no_llm,
        }
        canon_path.write_text(json.dumps(canon, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Updated {canon_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
