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
DEFAULT_URL = "http://127.0.0.1:5000/api/detect"
HEALTH_URL = "http://127.0.0.1:5000/api/health"
PAYLOAD = {"method": "GET", "url": "http://demo/login?id=1+union+select+1"}


def check_server(base_url: str = "http://127.0.0.1:5000", timeout: float = 2.0) -> None:
    health = f"{base_url.rstrip('/')}/api/health"
    try:
        resp = requests.get(health, timeout=timeout)
        resp.raise_for_status()
    except Exception as exc:
        raise SystemExit(
            f"[stress_test] API 不可达 ({health}): {exc}\n"
            "请先启动服务: python run.py"
        ) from exc


def one_request(url: str) -> float:
    t0 = time.perf_counter()
    resp = requests.post(url, json=PAYLOAD, timeout=10)
    resp.raise_for_status()
    return (time.perf_counter() - t0) * 1000


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=50)
    parser.add_argument("--requests", type=int, default=2000)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--skip-health-check", action="store_true")
    parser.add_argument("--max-error-rate", type=float, default=0.01)
    args = parser.parse_args()

    if not args.skip_health_check:
        base = args.url.rsplit("/api/", 1)[0]
        check_server(base)

    latencies: list[float] = []
    errors = 0
    first_error: str | None = None
    t0 = time.perf_counter()

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(one_request, args.url) for _ in range(args.requests)]
        for f in as_completed(futures):
            try:
                latencies.append(f.result())
            except Exception as exc:
                errors += 1
                if first_error is None:
                    first_error = repr(exc)

    elapsed = time.perf_counter() - t0
    qps = args.requests / elapsed if elapsed > 0 else 0
    sorted_lat = sorted(latencies) if latencies else [0]
    error_rate = errors / args.requests if args.requests else 1.0

    result = {
        "requests": args.requests,
        "workers": args.workers,
        "errors": errors,
        "error_rate": round(error_rate, 4),
        "first_error": first_error,
        "elapsed_s": round(elapsed, 2),
        "qps": round(qps, 1),
        "mean_ms": round(statistics.mean(latencies), 3) if latencies else 0,
        "p99_ms": round(sorted_lat[int(0.99 * len(sorted_lat)) - 1], 3) if latencies else 0,
        "pass": error_rate <= args.max_error_rate and len(latencies) > 0,
    }
    print(json.dumps(result, indent=2))
    out = ROOT / "results" / "v2_exp4_stress.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")

    if not result["pass"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
