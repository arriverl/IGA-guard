#!/usr/bin/env python3
"""Evaluation with multi-class + binary WAF detection metrics (honest FP/FN split)."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard import IgaGuardEngine
from iga_guard.obfuscation_signals import is_obfuscated
from iga_guard.pipeline import load_config


def _eval_request(payload: str) -> tuple[str, str, str]:
    """构造评测 HTTP 请求：含 &/换行/超长载荷走 POST body，避免 query 被截断。"""
    if "&" in payload or "\n" in payload or "\r" in payload or len(payload) > 1800:
        return "POST", "http://eval.local/test", payload
    return "GET", f"http://eval.local/test?p={quote(payload, safe='')}", ""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default=str(ROOT / "data" / "master" / "test_obfuscated.csv"))
    parser.add_argument("--max-samples", type=int, default=None)
    parser.add_argument("--output", default=str(ROOT / "results" / "v2_exp1_overall.json"))
    parser.add_argument(
        "--export-misses",
        default=str(ROOT / "data" / "cache" / "eval_obf_misses.jsonl"),
    )
    args = parser.parse_args()
    max_samples = args.max_samples if args.max_samples and args.max_samples > 0 else None

    engine = IgaGuardEngine(load_config(ROOT / "configs" / "default.yaml"))
    y_true: list[str] = []
    y_pred: list[str] = []
    bin_true: list[bool] = []
    bin_pred: list[bool] = []
    obf_bin_true: list[bool] = []
    obf_bin_pred: list[bool] = []
    normal_bin_true: list[bool] = []
    normal_bin_pred: list[bool] = []

    misses_path = Path(args.export_misses)
    misses_path.parent.mkdir(parents=True, exist_ok=True)
    miss_rows: list[dict] = []

    with open(args.data, encoding="utf-8", newline="") as f:
        for i, row in enumerate(csv.DictReader(f)):
            if max_samples is not None and i >= max_samples:
                break
            payload = row["payload"]
            label = row["label"]
            method, url, body = _eval_request(payload)
            report = engine.analyze_url(method, url, body=body)
            pred = report.detection.label
            is_attack_pred = report.detection.is_malicious or pred != "Normal"
            is_attack_true = label != "Normal"

            if (
                is_obfuscated(payload)
                and is_attack_true
                and not is_attack_pred
            ):
                miss_rows.append({
                    "payload": payload,
                    "label": label,
                    "source": row.get("source", ""),
                    "pred": pred,
                })

            y_true.append(label)
            y_pred.append(pred)
            bin_true.append(is_attack_true)
            bin_pred.append(is_attack_pred)

            if is_obfuscated(payload) and is_attack_true:
                obf_bin_true.append(True)
                obf_bin_pred.append(is_attack_pred)
            if label == "Normal":
                normal_bin_true.append(False)
                normal_bin_pred.append(is_attack_pred)

    def multiclass_metrics(true: list[str], pred: list[str]) -> dict:
        if not true:
            return {"accuracy": 0, "recall_malicious": 0, "samples": 0}
        correct = sum(1 for t, p in zip(true, pred) if t == p)
        mal_idx = [(t, p) for t, p in zip(true, pred) if t != "Normal"]
        mal_exact = sum(1 for t, p in mal_idx if t == p)
        return {
            "accuracy": round(correct / len(true), 4),
            "recall_malicious_exact_class": round(mal_exact / len(mal_idx), 4) if mal_idx else 0,
            "samples": len(true),
        }

    def binary_metrics(true: list[bool], pred: list[bool]) -> dict:
        if not true:
            return {
                "detection_recall": 0,
                "detection_precision": 0,
                "f1": 0,
                "false_positive_rate": 0,
                "samples": 0,
            }
        tp = sum(1 for t, p in zip(true, pred) if t and p)
        fp = sum(1 for t, p in zip(true, pred) if not t and p)
        fn = sum(1 for t, p in zip(true, pred) if t and not p)
        tn = sum(1 for t, p in zip(true, pred) if not t and not p)
        recall = tp / (tp + fn) if (tp + fn) else 0
        precision = tp / (tp + fp) if (tp + fp) else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
        fpr = fp / (fp + tn) if (fp + tn) else 0
        return {
            "detection_recall": round(recall, 4),
            "detection_precision": round(precision, 4),
            "f1": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "samples": len(true),
        }

    obf_bin = binary_metrics(obf_bin_true, obf_bin_pred)
    normal_bin = binary_metrics(normal_bin_true, normal_bin_pred)
    result = {
        "dataset": str(args.data),
        "eval_samples": len(y_true),
        "overall_multiclass": multiclass_metrics(y_true, y_pred),
        "overall_binary": binary_metrics(bin_true, bin_pred),
        "obfuscated_attack_binary": obf_bin,
        "normal_binary": {
            "false_positive_rate": normal_bin["false_positive_rate"],
            "fp": normal_bin["fp"],
            "tn": normal_bin["tn"],
            "samples": normal_bin["samples"],
        },
        "target_obfuscated_recall": 0.995,
        "pass_binary_obfuscated": (
            obf_bin.get("detection_recall", 0) >= 0.995 if obf_bin_true else None
        ),
        "note": "混淆子集仅含带混淆标记的攻击样本；normal_binary 单独报告误报率",
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    with misses_path.open("w", encoding="utf-8") as mf:
        for row in miss_rows:
            mf.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"Exported {len(miss_rows)} obf misses -> {misses_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
