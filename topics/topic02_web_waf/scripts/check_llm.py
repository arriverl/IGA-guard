#!/usr/bin/env python3
"""检查 LLM / Ollama 小模型是否可用。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.adversarial.llm_agent import LLMAdversarialAgent
from iga_guard.pipeline import load_config


def main() -> int:
    cfg = load_config(ROOT / "configs" / "default.yaml")
    llm_cfg = cfg.get("llm_agent", {})
    agent = LLMAdversarialAgent(llm_cfg)
    status = agent.status()
    print(json.dumps(status, indent=2, ensure_ascii=False))

    if not status.get("configured"):
        print("\n[!] LLM 未配置。请编辑 configs/default.yaml:")
        print('    llm_agent.enabled: true')
        print('    llm_agent.model: "qwen2.5:0.5b"')
        print("\n本地 Ollama 安装小模型:")
        print("    ollama pull qwen2.5:0.5b")
        return 1

    if status.get("provider") == "ollama" and not status.get("ollama_reachable"):
        print("\n[!] Ollama 未启动。请先运行: ollama serve")
        return 1

    if status.get("provider") == "ollama" and not status.get("model_available"):
        model = status.get("model", "qwen2.5:0.5b")
        print(f"\n[!] 模型 {model} 未安装。运行: ollama pull {model}")
        return 1

    # 快速冒烟
    variants = agent.generate_variants("1' OR 1=1--", "SQLi", n=2)
    print(f"\n[OK] 生成 {len(variants)} 条变种:")
    for v in variants:
        print(f"  - {v[:100]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
