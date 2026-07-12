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


def _evaluate_recovery(
    misses_csv: Path,
    *,
    max_rows: int = 120,
    use_online_adaptive: bool = False,
) -> dict:
    """Re-test E3 misses after learn-misses/cache updates to measure recovery."""
    if not misses_csv.exists():
        return {
            "total": 0,
            "recovered": 0,
            "remaining_missed": 0,
            "recovery_rate": 0.0,
            "miss_distribution": {},
            "vacuous": True,
            "mode": "none",
        }
    rows: list[dict] = []
    with misses_csv.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            rows.append(row)
            if len(rows) >= max_rows:
                break
    if not rows:
        return {
            "total": 0,
            "recovered": 0,
            "remaining_missed": 0,
            "recovery_rate": 0.0,
            "miss_distribution": {},
            "vacuous": True,
            "mode": "none",
        }
    variants = [(r["payload"], r["label"], r.get("source", "miss")) for r in rows]
    cfg = load_config(ROOT / "configs" / "default.yaml")
    engine = IgaGuardEngine(cfg)
    adaptive_meta: dict = {}
    if use_online_adaptive:
        from iga_guard.evolution.online_adaptive import OnlineAdaptiveController

        ctl = OnlineAdaptiveController(
            str(ROOT / "data" / "cache" / "online_adaptive_recovery_state.json"),
            canary_pct=100,
            promote_min_episodes=max(8, len(variants) // 3),
            promote_min_avg_reward=0.05,
        )
        det = engine.detector
        # Use ephemeral cache updates that do NOT persist to models/continual_cache.npz
        cache = getattr(det, "cache", None)
        orig_autosave = None
        if cache is not None:
            orig_autosave = getattr(cache, "autosave", True)
            try:
                cache.autosave = False
            except Exception:
                pass
        for i, (payload, label, _src) in enumerate(variants):
            # Pre-learn on canary with true labels (simulated blue-team feedback).
            pred = "Normal"  # treat prior miss as FN
            ctl.feedback(det, pred, label, traffic_key=f"recovery-{i}", lr=0.08)
            if cache is not None:
                try:
                    cache.update_from_feedback(payload, label)
                    cache.update_from_feedback(payload, label)
                except Exception:
                    pass
        if cache is not None and orig_autosave is not None:
            try:
                cache.autosave = orig_autosave
            except Exception:
                pass
            # Reload pristine cache from disk for subsequent evaluations outside recovery.
            try:
                from iga_guard.evolution.continual_cache import ContinualCacheAdapter
                det.cache = ContinualCacheAdapter.load(config=engine.config.get("continual_cache", {}))
            except Exception:
                pass
        adaptive_meta = {
            "mode": "online_adaptive+cache",
            "promotions": ctl.state.get("promotions", 0),
            "rollbacks": ctl.state.get("rollbacks", 0),
            "episodes": ctl.state.get("episodes", 0),
            "avg_reward": ctl.avg_reward(),
        }
        ctl.export_audit(ROOT / "results" / "online_adaptive_audit.json")
    else:
        adaptive_meta = {"mode": "cache_only"}
    recovered, misses = evaluate_round(engine, variants, progress_every=0)
    total = len(variants)
    return {
        "total": total,
        "recovered": recovered,
        "remaining_missed": len(misses),
        "recovery_rate": round(recovered / total, 4) if total else 0.0,
        "miss_distribution": _miss_distribution(misses),
        "vacuous": False,
        **adaptive_meta,
    }


def _run_delayed_learn_recovery(
    *,
    data_path: str,
    max_seeds: int,
    max_variants: int,
    seed: int = 4242,
) -> dict:
    """Build a non-vacuous miss pool, learn, then measure recovery.

    Prefer real regression FNs when available; otherwise synthesize misses by
    temporarily disabling continual cache and using held-out hard variants.
    """
    miss_rows: list[dict] = []
    # Prefer authentic full-regression FNs (non-synthetic evidence).
    for cand in (
        ROOT / "data" / "cache" / "eval_obf_misses_regression_full_nocache.jsonl",
        ROOT / "data" / "cache" / "eval_obf_misses_regression_full.jsonl",
        ROOT / "data" / "cache" / "eval_obf_misses_regression_quick_nocache.jsonl",
        ROOT / "data" / "cache" / "eval_obf_misses.jsonl",
    ):
        if not cand.exists():
            continue
        with cand.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                payload = obj.get("payload") or obj.get("raw") or obj.get("text") or ""
                label = obj.get("label") or obj.get("true_label") or "SQLi"
                if payload:
                    miss_rows.append({
                        "payload": payload,
                        "label": label,
                        "source": f"regression_fn:{cand.name}",
                    })
                if len(miss_rows) >= 40:
                    break
        # Keep accumulating across files until we have a usable pool.
        if len(miss_rows) >= 20:
            break

    if not miss_rows:
        # Fallback: generate variants and keep only those missed with cache off.
        cfg = load_config(ROOT / "configs" / "default.yaml")
        cfg.setdefault("continual_cache", {})["enabled"] = False
        engine = IgaGuardEngine(cfg)
        pool = _load_seed_pool(Path(data_path) if data_path else None, max_seeds)
        variants = generate_variants(
            pool,
            round_num=1,
            seed=seed,
            variants_per_seed=4,
            max_variants=max_variants,
        )
        _detected, misses = evaluate_round(engine, variants, progress_every=0)
        miss_rows = [
            {
                "payload": m.get("payload", ""),
                "label": m.get("label", ""),
                "source": m.get("source", "delayed"),
            }
            for m in misses
            if m.get("payload")
        ]

    if not miss_rows:
        return {
            "total": 0,
            "recovered": 0,
            "remaining_missed": 0,
            "recovery_rate": 0.0,
            "miss_distribution": {},
            "vacuous": True,
            "mode": "delayed_learn_no_miss_pool",
            "pre_learn_misses": 0,
            "pre_learn_total": 0,
        }

    miss_csv = ROOT / "results" / "v2_exp3_delayed_learn_misses.csv"
    miss_csv.parent.mkdir(parents=True, exist_ok=True)
    with miss_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["payload", "label", "source"])
        w.writeheader()
        for m in miss_rows:
            w.writerow(m)

    report = _evaluate_recovery(miss_csv, use_online_adaptive=True)
    report["pre_learn_misses"] = len(miss_rows)
    report["pre_learn_total"] = len(miss_rows)
    report["delayed_learn"] = True
    report["mode"] = "regression_fn_pool+online_adaptive"
    return report



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
        "--force-delayed-learn",
        action="store_true",
        help="若对抗轮次零漏检，强制 no-cache 收集 miss 后再学习恢复",
    )
    parser.add_argument(
        "--use-online-adaptive-recovery",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="recovery 阶段走 OnlineAdaptiveController+cache（对照仅 cache）",
    )
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
    miss_csv = e3_csv.with_name(e3_csv.stem + "_misses.csv")
    recovery_report = _evaluate_recovery(
        miss_csv,
        use_online_adaptive=bool(args.use_online_adaptive_recovery),
    )
    # Vacuous recovery (zero misses) does NOT count as adaptive_recovery pass.
    if recovery_report.get("vacuous") or recovery_report.get("total", 0) == 0:
        delayed = _run_delayed_learn_recovery(
            data_path=args.data,
            max_seeds=min(40, args.e3_max_seeds),
            max_variants=min(200, args.e3_max_variants),
        )
        recovery_report = delayed
    probe_pass = probe_report["recall"] >= args.min_probe_recall
    vacuous = bool(recovery_report.get("vacuous"))
    recovery_pass = (not vacuous) and (
        recovery_report.get("total", 0) > 0
        and recovery_report.get("recovery_rate", 0.0) >= args.min_recovery_rate
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
        "recovery": {**recovery_report, "pass": recovery_pass, "vacuous": vacuous},
        "convergence_proof": {
            "probe_stable": probe_pass,
            "adaptive_recovery": recovery_pass,
            "recovery_non_vacuous": not vacuous,
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
