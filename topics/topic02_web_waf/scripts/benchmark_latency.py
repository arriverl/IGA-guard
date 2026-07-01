#!/usr/bin/env python3
"""Latency benchmark — IGA-Guard 2.0 target <5ms per request."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard import IgaGuardEngine
from iga_guard.pipeline import load_config

SAMPLE_URLS = [
    "http://example.com/login?id=1",
    "http://example.com/search?q=hello",
    "http://example.com/api?id=1%20union%20select%201,2--",
    "http://example.com/x?q=<script>alert(1)</script>",
    "http://example.com/file?p=../../../etc/passwd",
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--warmup", type=int, default=200)
    args = parser.parse_args()

    cfg = load_config(ROOT / "configs" / "default.yaml")
    target_ms = cfg.get("latency", {}).get("target_ms", 5)
    engine = IgaGuardEngine(cfg)

    for i in range(args.warmup):
        engine.analyze_url("GET", SAMPLE_URLS[i % len(SAMPLE_URLS)])

    latencies: list[float] = []
    for i in range(args.iterations):
        url = SAMPLE_URLS[i % len(SAMPLE_URLS)]
        t0 = time.perf_counter()
        engine.analyze_url("GET", url)
        latencies.append((time.perf_counter() - t0) * 1000)

    sorted_lat = sorted(latencies)
    result = {
        "version": "2.0",
        "iterations": args.iterations,
        "mean_ms": round(statistics.mean(latencies), 3),
        "p50_ms": round(statistics.median(latencies), 3),
        "p95_ms": round(sorted_lat[int(0.95 * len(sorted_lat)) - 1], 3),
        "p99_ms": round(sorted_lat[int(0.99 * len(sorted_lat)) - 1], 3),
        "max_ms": round(max(latencies), 3),
        "target_ms": target_ms,
        "pass": statistics.median(latencies) <= target_ms,
    }

    print(json.dumps(result, indent=2))
    out = ROOT / "results" / "v2_exp4_latency.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
