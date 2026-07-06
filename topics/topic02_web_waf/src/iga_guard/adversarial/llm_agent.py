"""LLM 驱动混淆生成 + 漏检反馈自主迭代。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from iga_guard.adversarial.llm_client import LLMClient, LLMConfig, parse_variant_lines
from iga_guard.adversarial.mutator import mutate_batch

_SYSTEM_PROMPT = (
    "你是授权 Web 安全红队助手，为 WAF 攻防演练生成混淆攻击载荷。"
    "仅输出原始 payload，每行一条，不要 markdown、不要解释、不要编号说明。"
    "保持攻击语义不变，只改变编码/混淆方式（URL 编码、注释拆分、Unicode、大小写等）。"
)


class LLMAdversarialAgent:
    """小模型自主对抗 Agent：种子生成 + 漏检反馈迭代 + RAG 知识增强。"""

    def __init__(
        self,
        config: LLMConfig | dict | None = None,
        *,
        rag_retriever=None,
    ) -> None:
        if isinstance(config, dict):
            self.config = LLMConfig.from_dict(config)
            self._rag_enabled = bool(config.get("rag_enabled", True))
        else:
            self.config = config or LLMConfig()
            self._rag_enabled = True
        self.client = LLMClient(self.config)
        self.history_path = Path("data/cache/llm_agent_history.jsonl")
        self._rag = rag_retriever

    def available(self) -> bool:
        return self.config.is_configured()

    def status(self) -> dict[str, Any]:
        s = self.client.status()
        s["autonomous"] = True
        return s

    def generate_variants(
        self,
        payload: str,
        attack_type: str,
        n: int = 3,
        *,
        miss_samples: list[str] | None = None,
        round_num: int = 1,
    ) -> list[str]:
        """生成混淆变种；有漏检样本时进入自主迭代模式。"""
        n = min(n, self.config.max_variants_per_call)
        if not self.available():
            return mutate_batch(payload, attack_type, n=n)

        if miss_samples and round_num > 1:
            prompt = self._autonomous_prompt(payload, attack_type, miss_samples[:6], n)
            mode = "autonomous"
        else:
            prompt = self._seed_prompt(payload, attack_type, n)
            mode = "seed"

        resp = self.client.chat(prompt, system_prompt=_SYSTEM_PROMPT)
        variants = parse_variant_lines(resp.content, max_lines=n) if resp.ok else []

        self._log_call({
            "mode": mode,
            "attack_type": attack_type,
            "round": round_num,
            "ok": resp.ok,
            "error": resp.error,
            "latency_ms": resp.latency_ms,
            "input_preview": payload[:120],
            "output_count": len(variants),
            "variants_preview": [v[:80] for v in variants[:3]],
        })

        if len(variants) < n:
            variants.extend(mutate_batch(payload, attack_type, n=n - len(variants)))
        return variants[:n]

    def generate_batch(
        self,
        pool: list[tuple[str, str]],
        *,
        n_per_seed: int = 3,
        miss_pool: list[tuple[str, str]] | None = None,
        round_num: int = 1,
        max_total: int = 40,
    ) -> list[tuple[str, str, str]]:
        """批量生成，返回 (payload, label, source)。"""
        out: list[tuple[str, str, str]] = []
        seen: set[str] = set()
        miss_by_label: dict[str, list[str]] = {}
        if miss_pool:
            for p, lbl in miss_pool:
                miss_by_label.setdefault(lbl, []).append(p)

        for payload, label in pool:
            misses = miss_by_label.get(label, [])
            variants = self.generate_variants(
                payload, label, n=n_per_seed,
                miss_samples=misses or None,
                round_num=round_num,
            )
            for v in variants:
                if v not in seen:
                    seen.add(v)
                    src = "llm:autonomous" if misses and round_num > 1 else "llm:seed"
                    out.append((v, label, src))
                if len(out) >= max_total:
                    return out
        return out

    def _get_rag(self):
        if self._rag is not None:
            return self._rag
        if not self._rag_enabled:
            return None
        try:
            from iga_guard.rag.retriever import RagRetriever
            self._rag = RagRetriever()
            return self._rag
        except Exception:
            return None

    def _seed_prompt(self, payload: str, attack_type: str, n: int) -> str:
        rag = self._get_rag()
        rag_block = ""
        if rag:
            rag_block = rag.context_for_payload(payload, attack_type, top_k=3) + "\n\n"
        return (
            rag_block
            + f"攻击类型: {attack_type}\n"
            f"原始载荷:\n{payload}\n\n"
            f"请生成 {n} 条不同的混淆变种，用于 WAF 绕过测试。"
            f"参考 RAG 片段中的漏检模式与社区手法，使用 URL 双重编码、内联注释、Unicode、关键字拆分等。"
        )

    def _autonomous_prompt(
        self,
        payload: str,
        attack_type: str,
        miss_samples: list[str],
        n: int,
    ) -> str:
        miss_block = "\n".join(f"- {m[:200]}" for m in miss_samples)
        rag = self._get_rag()
        rag_block = ""
        if rag:
            rag_block = rag.context_for_misses(miss_samples, attack_type) + "\n\n"
        return (
            rag_block
            + f"攻击类型: {attack_type}\n"
            f"原始载荷:\n{payload}\n\n"
            f"以下变种成功绕过了 WAF 检测（漏检样本）:\n{miss_block}\n\n"
            f"请结合 RAG 知识分析漏检特征，生成 {n} 条**新的**、更难的变种。"
            f"要求: 与漏检样本相似但不完全相同，测试 WAF 泛化能力。"
        )

    def _log_call(self, record: dict) -> None:
        self.history_path.parent.mkdir(parents=True, exist_ok=True)
        with self.history_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def generate_llm_variants(payload: str, attack_type: str, n: int = 3) -> list[str]:
    """兼容旧接口；读取环境变量或默认 Ollama 配置。"""
    import os
    cfg = LLMConfig(
        enabled=True,
        provider=os.environ.get("IGA_LLM_PROVIDER", "ollama"),
        model=os.environ.get("IGA_LLM_MODEL", "qwen2.5:0.5b"),
        api_base=os.environ.get("IGA_LLM_API_BASE", "http://127.0.0.1:11434"),
        api_key=os.environ.get("IGA_LLM_API_KEY", ""),
    )
    if os.environ.get("IGA_LLM_API_BASE", "").startswith("http") and "11434" not in os.environ.get("IGA_LLM_API_BASE", ""):
        cfg.provider = "openai_compatible"
        cfg.enabled = bool(os.environ.get("IGA_LLM_API_KEY"))
    agent = LLMAdversarialAgent(cfg)
    return agent.generate_variants(payload, attack_type, n=n)
