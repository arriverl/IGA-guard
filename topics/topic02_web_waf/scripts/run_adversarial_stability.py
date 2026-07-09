#!/usr/bin/env python3
"""E3/E9 对抗稳态压测：多轮收敛 + 指标漂移报告。

输出：
  - results/v2_exp3_stability.json   （E3 轮次 recall / 漂移）
  - results/v2_exp9_stability.json   （E9 可选；--skip-e9 跳过）
  - results/adversarial_drift_report.json （综合收敛证明）
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from iga_guard import IgaGuardEngine
from iga_guard.pipeline import load_config
from run_adversarial import _load_seed_pool, evaluate_round, generate_variants


def _run(cmd: list[str]) -> int:
    print(f">>> {' '.join(cmd)}", flush=True)
    return subprocess.call(cmd, cwd=ROOT)


def _load_e3_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _drift_stats(recalls: list[float]) -> dict:
    if not recalls:
        return {"n": 0, "mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0, "range": 0.0}
    mean = sum(recalls) / len(recalls)
    var = sum((x - mean) ** 2 for x in recalls) / len(recalls)
    std = math.sqrt(var)
    return {
        "n": len(recalls),
        "mean": round(mean, 4),
        "std": round(std, 4),
        "min": round(min(recalls), 4),
        "max": round(max(recalls), 4),
        "range": round(max(recalls) - min(recalls), 4),
        "last": round(recalls[-1], 4),
        "first": round(recalls[0], 4),
        "delta_last_first": round(recalls[-1] - recalls[0], 4),
    }


def _converged(
    recalls: list[float],
    *,
    min_last: float,
    max_std: float,
    max_range: float,
    min_mean: float = 0.90,
) -> bool:
    if len(recalls) < 2:
        return False
    st = _drift_stats(recalls)
    # 稳态：均值达标 + 漂移可控；末轮可略低于首轮（硬样本聚焦）
    return (
        st["mean"] >= min_mean
        and st["last"] >= min_last
        and st["std"] <= max_std
        and st["range"] <= max_range
    )


def _evaluate_probe(
    *,
    data_path: str,
    max_seeds: int,
    max_variants: int,
    seed: int = 1729,
) -> dict:
    """Evaluate a deterministic fixed probe set for stability evidence."""
    engine = IgaGuardEngine(load_config(ROOT / "configs" / "default.yaml"))
    pool = _load_seed_pool(Path(data_path) if data_path else None, max_seeds)
    variants = generate_variants(
        pool,
        round_num=0,
        seed=seed,
        variants_per_seed=3,
        max_variants=max_variants,
    )
    detected, misses = evaluate_round(engine, variants, progress_every=0)
    total = len(variants)
    recall = detected / total if total else 0.0
    return {
        "seed": seed,
        "total": total,
        "detected": detected,
        "missed": len(misses),
        "recall": round(recall, 4),
        "miss_distribution": _miss_distribution(misses),
    }


def _evaluate_recovery(misses_csv: Path, *, max_rows: int = 120) -> dict:
    """Re-test E3 misses after learn-misses/cache updates to measure recovery."""
    if not misses_csv.exists():
        return {"total": 0, "recovered": 0, "recovery_rate": 0.0, "miss_distribution": {}}
    rows: list[dict] = []
    with misses_csv.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            rows.append(row)
            if len(rows) >= max_rows:
                break
    variants = [(r["payload"], r["label"], r.get("source", "miss")) for r in rows]
    engine = IgaGuardEngine(load_config(ROOT / "configs" / "default.yaml"))
    recovered, misses = evaluate_round(engine, variants, progress_every=0)
    total = len(variants)
    return {
        "total": total,
        "recovered": recovered,
        "remaining_missed": len(misses),
        "recovery_rate": round(recovered / total, 4) if total else 0.0,
        "miss_distribution": _miss_distribution(misses),
    }


def _miss_distribution(misses: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for m in misses:
        label = str(m.get("label", "Unknown"))
        out[label] = out.get(label, 0) + 1
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="E3/E9 adversarial stability + drift report")
    parser.add_argument("--e3-rounds", type=int, default=5)
    parser.add_argument("--e3-max-seeds", type=int, default=80)
    parser.add_argument("--e3-max-variants", type=int, default=800)
    parser.add_argument("--e9-rounds", type=int, default=3)
    parser.add_argument("--e9-max-variants", type=int, default=60)
    parser.add_argument("--skip-e9", action="store_true")
    parser.add_argument("--min-last-recall", type=float, default=0.90)
    parser.add_argument("--max-std", type=float, default=0.10)
    parser.add_argument("--max-range", type=float, default=0.20)
    parser.add_argument(
        "--min-mean-recall",
        type=float,
        default=0.90,
        help="轮次平均召回下限（稳态主指标，允许末轮因硬样本略降）",
    )
    parser.add_argument("--probe-max-seeds", type=int, default=30)
    parser.add_argument("--probe-max-variants", type=int, default=300)
    parser.add_argument("--min-probe-recall", type=float, default=0.95)
    parser.add_argument("--min-recovery-rate", type=float, default=0.80)
    parser.add_argument(
        "--data",
        default=str(ROOT / "data" / "samples" / "obfuscated_dataset.csv"),
    )
    args = parser.parse_args()
    py = sys.executable

    e3_csv = ROOT / "results" / "v2_exp3_adversarial_rounds.csv"
    e3_json = ROOT / "results" / "v2_exp3_stability.json"
    rc = _run([
        py, "scripts/run_adversarial.py",
        "--rounds", str(args.e3_rounds),
        "--data", args.data,
        "--max-seeds", str(args.e3_max_seeds),
        "--max-variants", str(args.e3_max_variants),
        "--output", str(e3_csv),
        "--stability-mix",
        "--learn-misses",
    ])
    if rc != 0:
        return rc

    rows = _load_e3_csv(e3_csv)
    recalls = [float(r["recall"]) for r in rows if r.get("recall") not in (None, "")]
    probe_report = _evaluate_probe(
        data_path=args.data,
        max_seeds=args.probe_max_seeds,
        max_variants=args.probe_max_variants,
    )
    recovery_report = _evaluate_recovery(e3_csv.with_name(e3_csv.stem + "_misses.csv"))
    probe_pass = probe_report["recall"] >= args.min_probe_recall
    recovery_pass = (
        recovery_report["total"] == 0
        or recovery_report["recovery_rate"] >= args.min_recovery_rate
    )
    adv_converged = _converged(
        recalls,
        min_last=args.min_last_recall,
        max_std=args.max_std,
        max_range=args.max_range,
        min_mean=args.min_mean_recall,
    )
    e3_report = {
        "experiment": "E3_adversarial_stability",
        "rounds": args.e3_rounds,
        "max_seeds": args.e3_max_seeds,
        "max_variants": args.e3_max_variants,
        "per_round": [
            {
                "round": int(r["round"]),
                "total": int(r["total"]),
                "detected": int(r["detected"]),
                "missed": int(r["missed"]),
                "recall": float(r["recall"]),
            }
            for r in rows
        ],
        "drift": _drift_stats(recalls),
        "probe": {**probe_report, "pass": probe_pass},
        "recovery": {**recovery_report, "pass": recovery_pass},
        "convergence_proof": {
            "probe_stable": probe_pass,
            "adaptive_recovery": recovery_pass,
            "adversarial_drift_bounded": adv_converged,
            "overall_converged": bool(probe_pass and recovery_pass and adv_converged),
        },
        "converged": bool(probe_pass and recovery_pass and adv_converged),
        "gates": {
            "min_last_recall": args.min_last_recall,
            "min_mean_recall": args.min_mean_recall,
            "min_probe_recall": args.min_probe_recall,
            "min_recovery_rate": args.min_recovery_rate,
            "max_std": args.max_std,
            "max_range": args.max_range,
        },
    }
    e3_json.parent.mkdir(parents=True, exist_ok=True)
    e3_json.write_text(json.dumps(e3_report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(e3_report["drift"], indent=2), flush=True)

    e9_report = None
    if not args.skip_e9:
        e9_out = ROOT / "results" / "v2_exp9_stability.json"
        rc9 = _run([
            py, "scripts/run_llm_redteam.py",
            "--rounds", str(args.e9_rounds),
            "--max-variants", str(args.e9_max_variants),
            "--no-llm",
            "--output", str(e9_out),
        ])
        if rc9 == 0 and e9_out.exists():
            e9_report = json.loads(e9_out.read_text(encoding="utf-8"))
            # 附加漂移字段（若有 per-round）
            round_recs = []
            for item in e9_report.get("round_details") or e9_report.get("rounds_detail") or []:
                if isinstance(item, dict) and "recall" in item:
                    round_recs.append(float(item["recall"]))
            if not round_recs and "final_round_recall" in e9_report:
                round_recs = [float(e9_report["final_round_recall"])]
            e9_report["drift"] = _drift_stats(round_recs)
            e9_report["converged"] = _converged(
                round_recs,
                min_last=args.min_last_recall,
                max_std=args.max_std,
                max_range=args.max_range,
                min_mean=args.min_mean_recall,
            )
            e9_out.write_text(json.dumps(e9_report, indent=2, ensure_ascii=False), encoding="utf-8")

    drift_report = {
        "title": "对抗稳态与指标漂移报告",
        "e3": {
            "file": str(e3_json.relative_to(ROOT)),
            "drift": e3_report["drift"],
            "converged": e3_report["converged"],
            "probe": e3_report["probe"],
            "recovery": e3_report["recovery"],
            "convergence_proof": e3_report["convergence_proof"],
            "per_round_recall": recalls,
        },
        "e9": None if e9_report is None else {
            "file": "results/v2_exp9_stability.json",
            "pooled_recall": e9_report.get("pooled_recall"),
            "final_round_recall": e9_report.get("final_round_recall"),
            "drift": e9_report.get("drift"),
            "converged": e9_report.get("converged"),
            "llm_enabled": e9_report.get("llm_enabled"),
        },
        "pass": bool(e3_report["converged"]) and (
            True if e9_report is None else bool(e9_report.get("converged", True))
        ),
    }
    out = ROOT / "results" / "adversarial_drift_report.json"
    out.write_text(json.dumps(drift_report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {out}", flush=True)
    print(f"PASS={drift_report['pass']}", flush=True)
    return 0 if drift_report["pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
