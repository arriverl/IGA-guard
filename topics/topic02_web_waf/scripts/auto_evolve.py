#!/usr/bin/env python3
"""自我迭代闭环 CLI：自动发现新混淆手法并更新检测器。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.evolution.auto_evolve import AutoEvolveLoop


def main() -> int:
    parser = argparse.ArgumentParser(description="IGA-Guard 自我迭代演化")
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--max-variants", type=int, default=100, help="每轮最大变体数（默认小批量快速迭代）")
    parser.add_argument("--variants-per-seed", type=int, default=3)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--no-learn", action="store_true", help="仅检测+发现手法，不重训/扩缓存")
    parser.add_argument("--use-llm", action="store_true", help="强制启用 LLM（覆盖 configs/default.yaml）")
    parser.add_argument("--output", default=str(ROOT / "results" / "auto_evolve_summary.json"))
    args = parser.parse_args()

    loop = AutoEvolveLoop(ROOT)
    if args.use_llm:
        from iga_guard.adversarial.llm_agent import LLMAdversarialAgent
        llm_cfg = loop.cfg.get("llm_agent", {})
        llm_cfg = {**llm_cfg, "enabled": True}
        agent = LLMAdversarialAgent(llm_cfg)
        agent.history_path = ROOT / "data" / "cache" / "llm_agent_history.jsonl"
        loop.llm_agent = agent if agent.available() else None
        if loop.llm_agent is None:
            print("[WARN] LLM 不可用，回退规则生成。先运行: python scripts/check_llm.py", flush=True)

    print(f"Registry: {loop.registry.stats()}", flush=True)
    if loop.llm_agent:
        print(f"LLM: {loop.llm_agent.status()}", flush=True)

    results = loop.run(
        rounds=args.rounds,
        seed=args.seed,
        variants_per_seed=args.variants_per_seed,
        max_variants=args.max_variants,
        learn_each_round=not args.no_learn,
    )

    summary = loop.summary(results)
    summary["rounds_detail"] = [
        {
            "round": r.round,
            "total": r.total,
            "detected": r.detected,
            "missed": r.missed,
            "recall": r.recall,
            "new_techniques": r.new_techniques,
        }
        for r in results
    ]

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"Wrote -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
