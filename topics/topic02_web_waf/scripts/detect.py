#!/usr/bin/env python3
"""CLI single-request detection."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard import IgaGuardEngine
from iga_guard.pipeline import load_config


def main() -> None:
    parser = argparse.ArgumentParser(description="IGA-Guard detect")
    parser.add_argument("--url", required=True, help="Request URL with query")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--body", default="")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    engine = IgaGuardEngine(load_config(ROOT / "configs" / "default.yaml"))
    report = engine.analyze_url(args.method, args.url, args.body)
    out = report.to_dict()

    if args.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        d = out["detection"]
        print(f"Label: {d['label']}  Confidence: {d['confidence']:.3f}")
        print(f"Risk: {d['risk_level']}  Latency: {d['latency_ms']:.2f} ms")
        if out.get("explanation"):
            e = out["explanation"]
            print(f"Malicious span: {e['malicious_span']} @ {e['malicious_field']}")
            for line in e.get("heatmap", []):
                print(f"  {line}")


if __name__ == "__main__":
    main()
