"""自我迭代与手法发现单元测试。"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from iga_guard.evolution.technique_discovery import discover_from_miss, infer_templates
from iga_guard.evolution.technique_registry import TechniqueRegistry


class TestTechniqueDiscovery:
    def test_infer_triple_url_encode(self):
        templates = infer_templates("1%2527+union+select")
        assert "repeat_url_encode" in templates or "double_url_encode_plus" in templates

    def test_infer_null_byte(self):
        templates = infer_templates("admin%00' OR 1=1")
        assert "insert_null_byte" in templates

    def test_register_from_miss(self):
        with tempfile.TemporaryDirectory() as td:
            reg = TechniqueRegistry(Path(td) / "discovered.json")
            new = discover_from_miss(reg, "1%2527+union+select", "SQLi", counter=0)
            assert len(new) >= 1
            assert reg.stats()["total"] >= 1

    def test_apply_discovered(self):
        with tempfile.TemporaryDirectory() as td:
            reg = TechniqueRegistry(Path(td) / "discovered.json")
            reg.register("test_triple", template="repeat_url_encode", attack_types=["SQLi"])
            out = reg.apply("union select", "test_triple")
            assert "%" in out
            assert out != "union select"
