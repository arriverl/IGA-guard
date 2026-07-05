"""LLM 客户端与解析测试（不依赖真实 Ollama）。"""

from __future__ import annotations

from iga_guard.adversarial.llm_client import LLMConfig, parse_variant_lines
from iga_guard.adversarial.llm_agent import LLMAdversarialAgent


class TestParseVariantLines:
    def test_strip_numbering(self):
        text = "1. 1' OR 1=1--\n2. %2527+union+select\n"
        lines = parse_variant_lines(text, max_lines=5)
        assert len(lines) == 2
        assert "union" in lines[1]

    def test_strip_markdown(self):
        text = "```\n<script>alert(1)</script>\n```"
        lines = parse_variant_lines(text)
        assert any("script" in ln for ln in lines)

    def test_empty(self):
        assert parse_variant_lines("") == []


class TestLLMAgentFallback:
    def test_fallback_when_disabled(self):
        agent = LLMAdversarialAgent(LLMConfig(enabled=False))
        variants = agent.generate_variants("1 union select", "SQLi", n=2)
        assert len(variants) == 2
        assert variants[0] != "1 union select"

    def test_autonomous_prompt_mode(self):
        agent = LLMAdversarialAgent(LLMConfig(enabled=False))
        batch = agent.generate_batch(
            [("1 union select", "SQLi")],
            miss_pool=[("%2527+union", "SQLi")],
            round_num=2,
            max_total=4,
        )
        assert len(batch) >= 1
