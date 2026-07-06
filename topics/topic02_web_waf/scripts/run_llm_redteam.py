#!/usr/bin/env python3
"""P2 · E9 LLM 红队实验：固定种子 → LLM 自主变异 → 报告 LLM-Evasion Recall。

用法:
  python scripts/run_llm_redteam.py --rounds 3 --max-variants 50
  python scripts/run_llm_redteam.py --no-llm   # 规则回退基线（无 Ollama 时）
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.evolution.auto_evolve import AutoEvolveLoop
from iga_guard.pipeline import load_config


def main() -> int:
    parser = argparse.ArgumentParser(description="E9 LLM 红队对抗实验")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--max-variants", type=int, default=100)
    parser.add_argument("--variants-per-seed", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--use-llm", action="store_true", default=True)
    parser.add_argument("--no-llm", action="store_true", help="禁用 LLM，仅用规则变异")
    parser.add_argument("--no-learn", action="store_true")
    parser.add_argument("--output", default=str(ROOT / "results" / "v2_exp9_llm_redteam.json"))
    args = parser.parse_args()

    loop = AutoEvolveLoop(ROOT)
    use_llm = args.use_llm and not args.no_llm

    if use_llm:
        from iga_guard.adversarial.llm_agent import LLMAdversarialAgent
        llm_cfg = {**loop.cfg.get("llm_agent", {}), "enabled": True}
        agent = LLMAdversarialAgent(llm_cfg)
        agent.history_path = ROOT / "data" / "cache" / "llm_redteam_history.jsonl"
        loop.llm_agent = agent if agent.available() else None
        if loop.llm_agent is None:
            print("[WARN] LLM 不可用，回退规则生成。运行: python scripts/check_llm.py", flush=True)
            use_llm = False

    results = loop.run(
        rounds=args.rounds,
        seed=args.seed,
        variants_per_seed=args.variants_per_seed,
        max_variants=args.max_variants,
        learn_each_round=not args.no_learn,
    )

    summary = loop.summary(results)
    final_recall = results[-1].recall if results else 0.0
    total_detected = sum(r.detected for r in results)
    total_all = sum(r.total for r in results)
    pooled_recall = total_detected / total_all if total_all else 0.0

    report = {
        "experiment": "E9_llm_redteam",
        "llm_enabled": use_llm and loop.llm_agent is not None,
        "llm_status": loop.llm_agent.status() if loop.llm_agent else None,
        "rounds": args.rounds,
        "max_variants": args.max_variants,
        "total_variants": total_all,
        "total_detected": total_detected,
        "total_missed": sum(r.missed for r in results),
        "final_round_recall": round(final_recall, 4),
        "pooled_recall": round(pooled_recall, 4),
        "avg_recall": round(pooled_recall, 4),
        "new_techniques_discovered": summary.get("total_new_techniques", 0),
        "rounds_detail": [
            {
                "round": r.round,
                "total": r.total,
                "detected": r.detected,
                "missed": r.missed,
                "recall": round(r.recall, 4),
                "new_techniques": r.new_techniques,
            }
            for r in results
        ],
        "target": "LLM-Evasion Recall > 95%",
        "passed": pooled_recall >= 0.95,
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
