#!/usr/bin/env python3
"""自动闭环：评测 -> miss_to_rule -> expand_cache -> evolve -> 复评。"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _call(cmd: list[str]) -> int:
    return subprocess.call(cmd, cwd=ROOT)


def _run_eval_regression(profile: str, *, strict: bool = True) -> int:
    cmd = [sys.executable, str(ROOT / "scripts" / "eval_regression.py"), "--profile", profile]
    if strict:
        cmd.append("--strict")
    return _call(cmd)


def main() -> int:
    parser = argparse.ArgumentParser(description="IGA-Guard 自动反馈闭环")
    parser.add_argument("--profile", choices=("quick", "full"), default="quick")
    parser.add_argument("--tail", type=int, default=200)
    parser.add_argument("--max-fp-rate", type=float, default=0.02)
    parser.add_argument("--max-rows", type=int, default=200)
    parser.add_argument("--min-samples", type=int, default=20)
    parser.add_argument("--nightly-full", action="store_true", help="在 quick 闭环后追加 full 回归")
    parser.add_argument("--strict", action="store_true", help="任一步失败时返回非0")
    args = parser.parse_args()

    summary: dict[str, object] = {"profile": args.profile, "steps": []}

    # 1) 前置回归
    rc_pre = _run_eval_regression(args.profile, strict=args.strict)
    summary["steps"].append({"name": "pre_eval_regression", "exit_code": rc_pre})
    if rc_pre != 0 and args.strict:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return rc_pre

    # 2) 读取 miss 文件（优先 no-cache miss）
    miss_file = ROOT / "data" / "cache" / f"eval_obf_misses_regression_{args.profile}_nocache.jsonl"
    if not miss_file.exists():
        miss_file = ROOT / "data" / "cache" / f"eval_obf_misses_regression_{args.profile}.jsonl"
    summary["miss_file"] = str(miss_file)
    if not miss_file.exists():
        summary["steps"].append({"name": "miss_file_check", "exit_code": 2, "error": "miss file missing"})
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return 2 if args.strict else 0

    # 3) miss -> rule
    rule_report = ROOT / "results" / f"miss_rule_report_cycle_{args.profile}.json"
    rc_rule = _call(
        [
            sys.executable,
            str(ROOT / "scripts" / "miss_to_rule.py"),
            "--input",
            str(miss_file),
            "--tail",
            str(args.tail),
            "--max-fp-rate",
            str(args.max_fp_rate),
            "--output",
            str(rule_report),
        ],
    )
    summary["steps"].append({"name": "miss_to_rule", "exit_code": rc_rule, "report": str(rule_report)})
    if rc_rule != 0 and args.strict:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return rc_rule

    # 4) miss -> cache
    rc_cache = _call(
        [
            sys.executable,
            str(ROOT / "scripts" / "expand_cache_from_misses.py"),
            "--misses",
            str(miss_file),
            "--max-rows",
            str(args.max_rows),
        ],
    )
    summary["steps"].append({"name": "expand_cache", "exit_code": rc_cache})
    if rc_cache != 0 and args.strict:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return rc_cache

    # 5) miss -> evolve
    rc_evolve = _call(
        [
            sys.executable,
            str(ROOT / "scripts" / "evolve_from_obf_misses.py"),
            "--misses",
            str(miss_file),
            "--max-rows",
            str(args.max_rows),
            "--min-samples",
            str(args.min_samples),
        ],
    )
    summary["steps"].append({"name": "evolve_from_misses", "exit_code": rc_evolve})
    if rc_evolve != 0 and args.strict:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return rc_evolve

    # 6) 后置回归
    rc_post = _run_eval_regression(args.profile, strict=args.strict)
    summary["steps"].append({"name": "post_eval_regression", "exit_code": rc_post})
    if rc_post != 0 and args.strict:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return rc_post

    # 7) 夜间全量（可选）
    if args.nightly_full and args.profile == "quick":
        rc_full = _run_eval_regression("full", strict=args.strict)
        summary["steps"].append({"name": "nightly_full_eval_regression", "exit_code": rc_full})
        if rc_full != 0 and args.strict:
            print(json.dumps(summary, indent=2, ensure_ascii=False))
            return rc_full

    summary["pass"] = all(int(step["exit_code"]) == 0 for step in summary["steps"])  # type: ignore[index]
    out = ROOT / "results" / "feedback_cycle_latest.json"
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"Saved summary -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
