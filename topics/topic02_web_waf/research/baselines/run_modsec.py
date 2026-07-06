#!/usr/bin/env python3
"""P8 · ModSecurity CRS 离线基线评测（同 test_obfuscated.csv 诚实对比）。

用法:
  python research/baselines/run_modsec.py
  python research/baselines/run_modsec.py --max-samples 5000
  python research/baselines/run_modsec.py --compare results/v2_exp1_overall.json
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "research" / "baselines"))

from crs_patterns import crs_label, crs_match  # noqa: E402

try:
    from iga_guard.obfuscation_signals import is_obfuscated  # noqa: E402
except ImportError:
    sys.path.insert(0, str(ROOT / "src"))
    from iga_guard.obfuscation_signals import is_obfuscated  # noqa: E402


def _binary_metrics(true: list[bool], pred: list[bool]) -> dict:
    if not true:
        return {"detection_recall": 0, "false_positive_rate": 0, "samples": 0}
    tp = sum(1 for t, p in zip(true, pred) if t and p)
    fp = sum(1 for t, p in zip(true, pred) if not t and p)
    fn = sum(1 for t, p in zip(true, pred) if t and not p)
    tn = sum(1 for t, p in zip(true, pred) if not t and not p)
    recall = tp / (tp + fn) if (tp + fn) else 0
    fpr = fp / (fp + tn) if (fp + tn) else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    return {
        "detection_recall": round(recall, 4),
        "detection_precision": round(precision, 4),
        "false_positive_rate": round(fpr, 4),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "samples": len(true),
    }


def evaluate_crs(data_path: Path, max_samples: int | None) -> dict:
    y_true_bin: list[bool] = []
    y_pred_bin: list[bool] = []
    obf_true: list[bool] = []
    obf_pred: list[bool] = []
    normal_true: list[bool] = []
    normal_pred: list[bool] = []
    rule_hits: dict[str, int] = {}

    with open(data_path, encoding="utf-8", newline="") as f:
        for i, row in enumerate(csv.DictReader(f)):
            if max_samples is not None and i >= max_samples:
                break
            payload = row["payload"]
            label = row["label"]
            is_attack = label != "Normal"
            pred_label = crs_label(payload)
            is_pred_attack = pred_label != "Normal"

            _, hits = crs_match(payload)
            for h in hits:
                rule_hits[h] = rule_hits.get(h, 0) + 1

            y_true_bin.append(is_attack)
            y_pred_bin.append(is_pred_attack)
            if is_obfuscated(payload) and is_attack:
                obf_true.append(True)
                obf_pred.append(is_pred_attack)
            if label == "Normal":
                normal_true.append(False)
                normal_pred.append(is_pred_attack)

    return {
        "baseline": "OWASP_CRS_PL4_subset_offline",
        "data": str(data_path),
        "overall": _binary_metrics(y_true_bin, y_pred_bin),
        "obfuscated_attack_subset": _binary_metrics(obf_true, obf_pred),
        "normal_subset": _binary_metrics(normal_true, normal_pred),
        "top_rules": dict(sorted(rule_hits.items(), key=lambda x: -x[1])[:15]),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="ModSecurity CRS 离线基线评测")
    parser.add_argument("--data", default=str(ROOT / "data" / "master" / "test_obfuscated.csv"))
    parser.add_argument("--max-samples", type=int, default=None)
    parser.add_argument("--output", default=str(ROOT / "results" / "v2_exp8_modsec_baseline.json"))
    parser.add_argument("--compare", default=None, help="IGA-Guard 结果 JSON 路径，生成对比表")
    args = parser.parse_args()

    result = evaluate_crs(Path(args.data), args.max_samples)

    if args.compare and Path(args.compare).exists():
        with open(args.compare, encoding="utf-8") as f:
            iga = json.load(f)
        result["comparison_vs_iga_guard"] = {
            "iga_obf_recall": iga.get("obfuscated_attack_binary", {}).get("detection_recall"),
            "crs_obf_recall": result["obfuscated_attack_subset"]["detection_recall"],
            "iga_fpr": iga.get("normal_binary", {}).get("false_positive_rate"),
            "crs_fpr": result["normal_subset"]["false_positive_rate"],
            "iga_overall_recall": iga.get("overall_binary", {}).get("detection_recall"),
            "crs_overall_recall": result["overall"]["detection_recall"],
        }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    obf = result["obfuscated_attack_subset"]
    print(json.dumps({
        "wrote": str(out),
        "crs_obf_recall": obf["detection_recall"],
        "crs_fpr": result["normal_subset"]["false_positive_rate"],
        "comparison": result.get("comparison_vs_iga_guard"),
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
