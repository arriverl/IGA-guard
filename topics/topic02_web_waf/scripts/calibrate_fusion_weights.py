#!/usr/bin/env python3
"""基于 evaluate 漏检/FPR 统计微调融合权重，写入 fusion_calibration.json。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def _load_eval(path: Path) -> dict | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def calibrate_from_eval(eval_data: dict) -> dict:
    obf = eval_data.get("obfuscated_attack_binary", {})
    nb = eval_data.get("normal_binary", {})
    obf_recall = float(obf.get("detection_recall", 1.0))
    fpr = float(nb.get("false_positive_rate", 0.0))

    obf_delta = {"base": 0.0, "semantic": 0.0, "multimodal": 0.0, "dlinear": 0.0}
    benign_delta = {"base": 0.0, "semantic": 0.0, "multimodal": 0.0, "dlinear": 0.0}

    if obf_recall < 0.995:
        obf_delta["semantic"] += 0.03
        obf_delta["base"] += 0.02
        obf_delta["multimodal"] -= 0.02
    if fpr > 0.045:
        benign_delta["multimodal"] -= 0.03
        benign_delta["base"] += 0.02
        benign_delta["semantic"] -= 0.01

    return {
        "source_eval": eval_data.get("eval_samples"),
        "obfuscated_recall": obf_recall,
        "normal_fpr": fpr,
        "obfuscated": obf_delta,
        "benign": benign_delta,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--eval-json",
        default=str(ROOT / "results" / "v2_exp1_auto_2k.json"),
    )
    parser.add_argument(
        "--output",
        default=str(ROOT / "data" / "cache" / "fusion_calibration.json"),
    )
    args = parser.parse_args()

    eval_path = Path(args.eval_json)
    if not eval_path.is_absolute():
        eval_path = ROOT / eval_path
    data = _load_eval(eval_path)
    if not data:
        print(f"[ERR] missing eval json: {eval_path}", file=sys.stderr)
        return 1

    cal = calibrate_from_eval(data)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(cal, indent=2), encoding="utf-8")
    print(json.dumps(cal, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
