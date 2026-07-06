#!/usr/bin/env python3
"""P0: 分析 Normal 误报 (FP) 来源，输出聚类报告。"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from urllib.parse import quote

from iga_guard import IgaGuardEngine
from iga_guard.obfuscation_signals import is_obfuscated, looks_like_benign_csic_form
from iga_guard.pipeline import load_config


def _eval_request(payload: str) -> tuple[str, str, str]:
    if "&" in payload or "\n" in payload or "\r" in payload or len(payload) > 1800:
        return "POST", "http://eval.local/test", payload
    return "GET", f"http://eval.local/test?p={quote(payload, safe='')}", ""


def _classify_fp(payload: str, pred: str) -> str:
    low = payload.lower()
    if looks_like_benign_csic_form(payload, low):
        return "csic_form"
    if re.search(r"modo=|login=|password=|usuario=|clave=", low):
        return "login_form_other"
    if is_obfuscated(payload):
        return "obfuscated_normal"
    if "%" in payload and re.search(r"%2[0-9a-f]{2}", low):
        return "url_encoded"
    if re.search(r"<script|onerror|alert\(", low):
        return "xss_like"
    if re.search(r"union|select|insert|or\s+1", low):
        return "sqli_like"
    if re.search(r"\.\./|etc/passwd", low):
        return "path_like"
    if re.search(r"webkitformboundary|multipart", low):
        return "multipart_like"
    if len(payload) > 500:
        return "long_payload"
    return f"other_{pred}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default=str(ROOT / "data" / "master" / "test_obfuscated.csv"))
    parser.add_argument("--max-samples", type=int, default=0)
    parser.add_argument("--output", default=str(ROOT / "results" / "fp_analysis.json"))
    args = parser.parse_args()
    max_n = args.max_samples if args.max_samples > 0 else None

    engine = IgaGuardEngine(load_config(ROOT / "configs" / "default.yaml"))
    fps: list[dict] = []
    total_normal = 0

    with open(args.data, encoding="utf-8", newline="") as f:
        for i, row in enumerate(csv.DictReader(f)):
            if max_n and i >= max_n:
                break
            label = row["label"]
            if label != "Normal":
                continue
            total_normal += 1
            payload = row["payload"]
            method, url, body = _eval_request(payload)
            report = engine.analyze_url(method, url, body=body)
            if report.detection.is_malicious or report.detection.label != "Normal":
                fps.append({
                    "payload": payload[:300],
                    "pred": report.detection.label,
                    "confidence": round(report.detection.confidence, 4),
                    "category": _classify_fp(payload, report.detection.label),
                    "source": row.get("source", ""),
                })

    by_cat = Counter(fp["category"] for fp in fps)
    by_pred = Counter(fp["pred"] for fp in fps)
    fpr = len(fps) / total_normal if total_normal else 0

    report = {
        "total_normal": total_normal,
        "fp_count": len(fps),
        "fpr": round(fpr, 4),
        "by_category": dict(by_cat.most_common()),
        "by_predicted_label": dict(by_pred.most_common()),
        "samples": fps[:30],
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({
        "fpr": report["fpr"],
        "fp": len(fps),
        "normal": total_normal,
        "top_categories": dict(by_cat.most_common(8)),
    }, indent=2, ensure_ascii=False))
    print(f"Wrote -> {out}")


if __name__ == "__main__":
    main()
