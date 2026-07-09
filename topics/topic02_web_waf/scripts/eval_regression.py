#!/usr/bin/env python3
"""固定回归命令：快速/全量评测（含 no-cache）。"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run_eval(
    *,
    profile: str,
    no_cache: bool,
    max_samples: int | None,
) -> tuple[int, Path]:
    suffix = f"{profile}{'_nocache' if no_cache else ''}"
    out_file = ROOT / "results" / f"v2_exp1_regression_{suffix}.json"
    miss_file = ROOT / "data" / "cache" / f"eval_obf_misses_regression_{suffix}.jsonl"
    fp_file = ROOT / "data" / "cache" / f"eval_normal_fps_regression_{suffix}.jsonl"
    cmd = [
        sys.executable,
        str(ROOT / "scripts" / "evaluate.py"),
        "--output",
        str(out_file),
        "--export-misses",
        str(miss_file),
        "--export-fps",
        str(fp_file),
    ]
    if max_samples is not None:
        cmd += ["--max-samples", str(max_samples)]
    if no_cache:
        cmd += ["--no-cache"]
    rc = subprocess.call(cmd, cwd=ROOT)
    return rc, out_file


def _read_metric(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="IGA-Guard 固定评测回归（cache + no-cache）")
    parser.add_argument("--profile", choices=("quick", "full"), default="quick")
    parser.add_argument("--skip-cache", action="store_true")
    parser.add_argument("--skip-nocache", action="store_true")
    parser.add_argument("--min-obf-recall", type=float, default=0.995)
    parser.add_argument("--max-fpr", type=float, default=0.013)
    parser.add_argument("--strict", action="store_true", help="门禁失败返回非0")
    args = parser.parse_args()

    max_samples = 2000 if args.profile == "quick" else None
    jobs: list[tuple[str, bool]] = []
    if not args.skip_cache:
        jobs.append(("cache", False))
    if not args.skip_nocache:
        jobs.append(("nocache", True))
    if not jobs:
        print(json.dumps({"error": "both cache and nocache are skipped"}, ensure_ascii=False))
        return 2

    summary: dict[str, dict] = {"profile": {"name": args.profile, "max_samples": max_samples or "full"}}
    failed = False
    for name, no_cache in jobs:
        rc, path = _run_eval(profile=args.profile, no_cache=no_cache, max_samples=max_samples)
        if rc != 0:
            summary[name] = {"status": "run_failed", "exit_code": rc, "result_file": str(path)}
            failed = True
            continue
        metric = _read_metric(path)
        obf = metric.get("obfuscated_attack_binary", {})
        normal = metric.get("normal_binary", {})
        obf_recall = float(obf.get("detection_recall", 0.0))
        fpr = float(normal.get("false_positive_rate", 0.0))
        gate_ok = obf_recall >= args.min_obf_recall and fpr <= args.max_fpr
        if not gate_ok:
            failed = True
        summary[name] = {
            "status": "ok" if gate_ok else "gate_failed",
            "result_file": str(path),
            "obf_recall": obf_recall,
            "fpr": fpr,
            "thresholds": {
                "min_obf_recall": args.min_obf_recall,
                "max_fpr": args.max_fpr,
            },
            "samples": metric.get("eval_samples"),
        }

    summary["overall"] = {"pass": not failed}
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 1 if failed and args.strict else 0


if __name__ == "__main__":
    raise SystemExit(main())
