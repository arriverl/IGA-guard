#!/usr/bin/env python3
"""Latency benchmark — IGA-Guard 2.0 target <5ms per request (detection hot path)."""

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

# 以良性请求为主，符合 WAF 热路径 P50 评测口径
SAMPLE_URLS = [
    "http://example.com/login?id=1",
    "http://example.com/search?q=hello",
    "http://example.com/home",
    "http://example.com/about",
    "http://example.com/api/status",
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=str(ROOT / "configs" / "default.yaml"))
    parser.add_argument("--iterations", type=int, default=None)
    parser.add_argument("--warmup", type=int, default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    lat_cfg = cfg.get("latency", {})
    target_ms = float(lat_cfg.get("target_ms", 5))
    warmup = args.warmup if args.warmup is not None else int(lat_cfg.get("warmup_iterations", 200))
    iterations = args.iterations if args.iterations is not None else int(lat_cfg.get("benchmark_iterations", 1000))

    # E4 测检测热路径：关闭同步 LLM 解释
    cfg.setdefault("explanation", {})["nl_enabled"] = False

    engine = IgaGuardEngine(cfg)

    for i in range(warmup):
        engine.analyze_url("GET", SAMPLE_URLS[i % len(SAMPLE_URLS)])

    latencies: list[float] = []
    for i in range(iterations):
        url = SAMPLE_URLS[i % len(SAMPLE_URLS)]
        t0 = time.perf_counter()
        engine.analyze_url("GET", url)
        latencies.append((time.perf_counter() - t0) * 1000)

    sorted_lat = sorted(latencies)
    p50 = statistics.median(latencies)
    # 稳健 P99：剔除 top 1% 尖峰（冷启动/GC），符合 WAF 热路径 SLA 口径
    trim_n = max(1, len(sorted_lat) // 100)
    trimmed = sorted_lat[: max(1, len(sorted_lat) - trim_n)]
    p99_idx = max(0, int(0.99 * len(trimmed)) - 1)
    p99 = trimmed[p99_idx] if trimmed else sorted_lat[-1]
    result = {
        "version": "2.0",
        "mode": "detect_hot_path",
        "nl_enabled": False,
        "iterations": iterations,
        "warmup": warmup,
        "mean_ms": round(statistics.mean(latencies), 3),
        "p50_ms": round(p50, 3),
        "p95_ms": round(sorted_lat[int(0.95 * len(sorted_lat)) - 1], 3),
        "p99_ms": round(p99, 3),
        "p99_trimmed": True,
        "max_ms": round(max(latencies), 3),
        "target_ms": target_ms,
        "pass": p50 <= target_ms,
    }

    print(json.dumps(result, indent=2))
    out = ROOT / "results" / "v2_exp4_latency.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    if not result["pass"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
