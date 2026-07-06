"""P5 手法 DSL 单元测试。"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.evolution.technique_dsl import parse_dsl, register_specs  # noqa: E402
from iga_guard.evolution.technique_registry import TechniqueRegistry  # noqa: E402


DSL_SAMPLE = """
technique test_triple_url:
  template: repeat_url_encode
  attack_types: [SQLi]
  match: "%25%25"
"""


class TestTechniqueDSL:
    def test_parse_dsl(self):
        specs = parse_dsl(DSL_SAMPLE)
        assert len(specs) == 1
        assert specs[0].name == "test_triple_url"
        assert specs[0].template == "repeat_url_encode"
        assert "SQLi" in specs[0].attack_types

    def test_register_specs(self):
        reg = TechniqueRegistry(Path(ROOT / "data" / "cache" / "_test_registry.json"))
        added = register_specs(reg, parse_dsl(DSL_SAMPLE))
        assert "test_triple_url" in added or "test_triple_url" in reg.names()
        Path(ROOT / "data" / "cache" / "_test_registry.json").unlink(missing_ok=True)
