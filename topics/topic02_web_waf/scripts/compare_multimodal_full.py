#!/usr/bin/env python3
"""全量对比：多模态开/关（同一测试集、同一 RF/TinyBERT）。"""

from __future__ import annotations

import argparse
import copy
import csv
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard import IgaGuardEngine
from iga_guard.obfuscation_signals import is_obfuscated
from iga_guard.pipeline import load_config


def _run_eval(engine: IgaGuardEngine, data_path: Path, max_samples: int | None = None) -> dict:
    y_true: list[str] = []
    y_pred: list[str] = []
    bin_true: list[bool] = []
    bin_pred: list[bool] = []
    obf_true: list[bool] = []
    obf_pred: list[bool] = []
    normal_fp = normal_tn = 0

    with data_path.open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    if max_samples and max_samples > 0:
        rows = rows[:max_samples]

    for i, row in enumerate(rows):
        payload, label = row["payload"], row["label"]
        url = f"http://eval.local/test?p={payload}"
        report = engine.analyze_url("GET", url)
        pred = report.detection.label
        is_atk_pred = report.detection.is_malicious or pred != "Normal"
        is_atk_true = label != "Normal"

        y_true.append(label)
        y_pred.append(pred)
        bin_true.append(is_atk_true)
        bin_pred.append(is_atk_pred)

        if is_obfuscated(payload) and is_atk_true:
            obf_true.append(True)
            obf_pred.append(is_atk_pred)
        if label == "Normal":
            if is_atk_pred:
                normal_fp += 1
            else:
                normal_tn += 1

        if (i + 1) % 500 == 0:
            print(f"  [{i+1}/{len(rows)}] ...", flush=True)

    n = len(bin_true)
    tp = sum(1 for t, p in zip(bin_true, bin_pred) if t and p)
    fp = sum(1 for t, p in zip(bin_true, bin_pred) if not t and p)
    fn = sum(1 for t, p in zip(bin_true, bin_pred) if t and not p)
    obf_tp = sum(1 for t, p in zip(obf_true, obf_pred) if t and p)
    obf_fn = sum(1 for t, p in zip(obf_true, obf_pred) if t and not p)

    return {
        "eval_samples": n,
        "overall_binary": {
            "detection_recall": round(tp / (tp + fn), 4) if (tp + fn) else 0,
            "detection_precision": round(tp / (tp + fp), 4) if (tp + fp) else 0,
            "false_positive_rate": round(fp / (fp + normal_tn), 4) if (fp + normal_tn) else 0,
            "tp": tp, "fp": fp, "fn": fn, "tn": normal_tn,
        },
        "obfuscated_attack_binary": {
            "detection_recall": round(obf_tp / (obf_tp + obf_fn), 4) if (obf_tp + obf_fn) else 0,
            "detection_precision": round(obf_tp / (obf_tp + sum(1 for t, p in zip(obf_true, obf_pred) if not t and p)), 4) if obf_true else 0,
            "tp": obf_tp, "fn": obf_fn,
            "samples": len(obf_true),
        },
        "normal_binary": {
            "false_positive_rate": round(normal_fp / (normal_fp + normal_tn), 4) if (normal_fp + normal_tn) else 0,
            "fp": normal_fp, "tn": normal_tn,
            "samples": normal_fp + normal_tn,
        },
        "multiclass_accuracy": round(
            sum(1 for t, p in zip(y_true, y_pred) if t == p) / n, 4
        ) if n else 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default=str(ROOT / "data" / "master" / "test_obfuscated.csv"))
    parser.add_argument("--output", default=str(ROOT / "results" / "v2_compare_multimodal_full.json"))
    parser.add_argument("--max-samples", type=int, default=0, help="0=全量")
    args = parser.parse_args()
    data_path = Path(args.data)
    max_samples = args.max_samples if args.max_samples > 0 else None

    base_cfg = load_config(ROOT / "configs" / "default.yaml")
    results: dict = {
        "dataset": str(data_path),
        "max_samples": max_samples,
        "runs": {},
    }

    for name, mm_on in [("without_multimodal", False), ("with_multimodal", True)]:
        cfg = copy.deepcopy(base_cfg)
        cfg.setdefault("multimodal", {})["enabled"] = mm_on
        cfg.setdefault("continual_cache", {})["use_vision_keys"] = mm_on
        print(f"\n=== {name} (multimodal={mm_on}) ===", flush=True)
        t0 = time.perf_counter()
        engine = IgaGuardEngine(cfg)
        metrics = _run_eval(engine, data_path, max_samples=max_samples)
        metrics["elapsed_sec"] = round(time.perf_counter() - t0, 1)
        metrics["multimodal_enabled"] = mm_on
        if hasattr(engine.detector, "cache") and engine.detector.cache:
            metrics["cache_stats"] = engine.detector.cache.stats()
        results["runs"][name] = metrics
        print(json.dumps(metrics, indent=2, ensure_ascii=False), flush=True)

    w = results["runs"].get("with_multimodal", {})
    wo = results["runs"].get("without_multimodal", {})
    results["delta"] = {
        "obfuscated_recall_pp": round(
            w.get("obfuscated_attack_binary", {}).get("detection_recall", 0)
            - wo.get("obfuscated_attack_binary", {}).get("detection_recall", 0),
            4,
        ),
        "overall_recall_pp": round(
            w.get("overall_binary", {}).get("detection_recall", 0)
            - wo.get("overall_binary", {}).get("detection_recall", 0),
            4,
        ),
        "normal_fpr_pp": round(
            w.get("normal_binary", {}).get("false_positive_rate", 0)
            - wo.get("normal_binary", {}).get("false_positive_rate", 0),
            4,
        ),
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nWrote -> {out}", flush=True)
    print(json.dumps(results["delta"], indent=2), flush=True)


if __name__ == "__main__":
    main()
