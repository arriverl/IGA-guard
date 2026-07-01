#!/usr/bin/env python3
"""Concurrent stress test for /api/detect."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
URL = "http://127.0.0.1:5000/api/detect"
PAYLOAD = {"method": "GET", "url": "http://demo/login?id=1+union+select+1"}


def one_request() -> float:
    t0 = time.perf_counter()
    requests.post(URL, json=PAYLOAD, timeout=5)
    return (time.perf_counter() - t0) * 1000


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=50)
    parser.add_argument("--requests", type=int, default=2000)
    args = parser.parse_args()

    latencies: list[float] = []
    errors = 0
    t0 = time.perf_counter()

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(one_request) for _ in range(args.requests)]
        for f in as_completed(futures):
            try:
                latencies.append(f.result())
            except Exception:
                errors += 1

    elapsed = time.perf_counter() - t0
    qps = args.requests / elapsed if elapsed > 0 else 0
    sorted_lat = sorted(latencies) if latencies else [0]

    result = {
        "requests": args.requests,
        "workers": args.workers,
        "errors": errors,
        "elapsed_s": round(elapsed, 2),
        "qps": round(qps, 1),
        "mean_ms": round(statistics.mean(latencies), 3) if latencies else 0,
        "p99_ms": round(sorted_lat[int(0.99 * len(sorted_lat)) - 1], 3) if latencies else 0,
    }
    print(json.dumps(result, indent=2))
    out = ROOT / "results" / "v2_exp4_stress.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
