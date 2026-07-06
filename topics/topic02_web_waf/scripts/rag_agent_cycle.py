#!/usr/bin/env python3
"""RAG 增强多 Agent 深挖循环：情报检索 → 漏检分析 → 手法注册 → 红队演化。

用法:
  python scripts/rag_agent_cycle.py --build-index
  python scripts/rag_agent_cycle.py --rounds 2 --max-variants 100
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.evolution.auto_evolve import AutoEvolveLoop
from iga_guard.evolution.technique_discovery import discover_from_miss
from iga_guard.evolution.technique_registry import TechniqueRegistry
from iga_guard.pipeline import load_config
from iga_guard.rag.index import KnowledgeIndex
from iga_guard.rag.retriever import RagRetriever


def agent1_intel(retriever: RagRetriever) -> dict:
    """Agent1：RAG 深挖文献与社区情报。"""
    queries = [
        "WAFFLED 协议层绕过 HPP JSON multipart",
        "ModSec-AdvLearn 对抗学习 SQLi 混淆",
        "base64_fragment eval atob 混淆逃逸",
    ]
    hits: list[dict] = []
    for q in queries:
        for text, score, cat in retriever.retrieve(q, top_k=2):
            hits.append({"query": q, "category": cat, "score": round(score, 3), "preview": text[:200]})
    return {"agent": "intel", "rag_hits": hits[:12]}


def agent2_architecture(retriever: RagRetriever, misses: list[str]) -> dict:
    """Agent2：基于漏检 + RAG 输出优化建议。"""
    ctx = retriever.context_for_misses(misses[:5], "SQLi") if misses else ""
    recs = []
    if "base64" in ctx.lower() or "atob" in ctx.lower():
        recs.append("加强 eval(atob) 碎片拼接检测，避免 CSIC 护栏覆盖")
    if "multipart" in ctx.lower() or "webkitformboundary" in ctx.lower():
        recs.append("扩展 P1 协议轨 multipart 边界解析权重")
    if "hex32" in ctx.lower():
        recs.append("hex32 伪装需结合 HPP/上下文，勿单独标恶意")
    if not recs:
        recs.append("维持 P0 护栏，继续 Tip-Adapter 漏检扩库")
    return {"agent": "architecture", "recommendations": recs, "rag_context_len": len(ctx)}


def agent3_engineering(registry: TechniqueRegistry, misses: list[tuple[str, str]]) -> dict:
    """Agent3：漏检驱动手法注册。"""
    registered: list[str] = []
    for payload, label in misses[:20]:
        registered.extend(discover_from_miss(registry, payload, label))
    return {"agent": "engineering", "new_techniques": list(set(registered)), "registry": registry.stats()}


def agent4_dataset(retriever: RagRetriever) -> dict:
    """Agent4：RAG 挖掘数据集扩充方向。"""
    hits = retriever.retrieve("SecLists FuzzDB 混淆扩充 CSIC", top_k=3, categories=["dataset", "literature"])
    return {
        "agent": "dataset",
        "expansion_hints": [h[0][:300] for h in hits],
    }


def load_recent_misses(limit: int = 30) -> list[tuple[str, str]]:
    path = ROOT / "data" / "cache" / "failures.jsonl"
    if not path.exists():
        return []
    rows: list[tuple[str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines()[-limit:]:
        if not line.strip():
            continue
        row = json.loads(line)
        rows.append((row.get("payload", ""), row.get("true_label", row.get("label", "SQLi"))))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="RAG 多 Agent 深挖循环")
    parser.add_argument("--build-index", action="store_true")
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--max-variants", type=int, default=80)
    parser.add_argument("--use-llm", action="store_true")
    parser.add_argument("--output", default=str(ROOT / "results" / "rag_agent_cycle.json"))
    args = parser.parse_args()

    if args.build_index:
        idx = KnowledgeIndex()
        n = idx.build(ROOT)
        idx.save(ROOT / "data" / "cache" / "rag_index.npz")
        print(f"Built RAG index: {n} chunks", flush=True)

    retriever = RagRetriever(root=ROOT)
    misses = load_recent_misses()
    miss_payloads = [p for p, _ in misses]

    report = {
        "rag_stats": retriever.index.stats(),
        "agents": [
            agent1_intel(retriever),
            agent2_architecture(retriever, miss_payloads),
            agent3_engineering(TechniqueRegistry(ROOT / "data" / "cache" / "discovered_techniques.json"), misses),
            agent4_dataset(retriever),
        ],
    }

    miss_sources = Counter()
    for p, lbl in misses:
        if "atob" in p.lower():
            miss_sources["base64_fragment"] += 1
        elif "webkitformboundary" in p.lower():
            miss_sources["multipart"] += 1
        elif lbl:
            miss_sources[lbl] += 1
    report["miss_breakdown"] = dict(miss_sources)

    cfg = load_config(ROOT / "configs" / "default.yaml")
    if cfg.get("rag", {}).get("enabled", True):
        cfg.setdefault("llm_agent", {})["rag_enabled"] = True

    loop = AutoEvolveLoop(ROOT)
    if args.use_llm:
        from iga_guard.adversarial.llm_agent import LLMAdversarialAgent
        llm_cfg = {**loop.cfg.get("llm_agent", {}), "enabled": True, "rag_enabled": True}
        agent = LLMAdversarialAgent(llm_cfg, rag_retriever=retriever)
        loop.llm_agent = agent if agent.available() else None

    evo = loop.run(rounds=args.rounds, max_variants=args.max_variants, learn_each_round=True)
    report["evolution"] = loop.summary(evo)
    report["evolution"]["rounds"] = [
        {"round": r.round, "recall": r.recall, "missed": r.missed, "new_techniques": r.new_techniques}
        for r in evo
    ]

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False)[:4000])
    return 0


if __name__ == "__main__":
    sys.exit(main())
