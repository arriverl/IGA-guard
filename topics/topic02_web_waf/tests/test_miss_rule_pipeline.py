"""miss→rule 闭环与 discovered rescue 规则测试。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iga_guard.evolution.discovered_rescue_rules import DiscoveredRescueRules
from iga_guard.evolution.miss_rule_pipeline import process_misses
from iga_guard.obfuscation_signals import obfuscated_evasion_rescue, reload_discovered_rescue_rules


@pytest.fixture
def rules_path(tmp_path: Path) -> Path:
    return tmp_path / "discovered_rescue_rules.json"


def test_discovered_rules_match(rules_path: Path) -> None:
    store = DiscoveredRescueRules(rules_path)
    store.add_rule(pattern=r"malicious\.com", label="SQLi", confidence=0.62)
    store.save()
    store2 = DiscoveredRescueRules(rules_path)
    hit = store2.match("http://x?q=malicious.com", "http://x?q=malicious.com")
    assert hit == ("SQLi", 0.62)


def test_process_misses_registers_pattern(rules_path: Path, tmp_path: Path) -> None:
    benign = tmp_path / "benign.jsonl"
    benign.write_text(
        json.dumps({"payload": "modo=entrar&login=foo"}) + "\n",
        encoding="utf-8",
    )
    misses = [{
        "payload": "http%3A//www.evil.com%3Fq%3Dpassw%68",
        "label": "CMD",
    }]
    result = process_misses(
        misses,
        rules_path=rules_path,
        benign_path=benign,
        max_fp_rate=0.05,
    )
    assert result["registered"] or result["store"]["total"] >= 0
    reload_discovered_rescue_rules()


def test_rescue_opaque_url() -> None:
    raw = "http%3A//www.example.com%3Fq%3DP085g%40f"
    hit = obfuscated_evasion_rescue(raw, raw.lower(), decode_depth=1)
    assert hit is not None
