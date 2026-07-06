#!/usr/bin/env python3
"""从 DSL 文件批量注册混淆手法到 TechniqueRegistry。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.evolution.technique_dsl import load_dsl_file, register_specs
from iga_guard.evolution.technique_registry import TechniqueRegistry


def main() -> int:
    parser = argparse.ArgumentParser(description="注册手法 DSL")
    parser.add_argument("dsl_file", nargs="?", default=str(ROOT / "data" / "cache" / "technique_dsl_examples.dsl"))
    parser.add_argument("--registry", default=str(ROOT / "data" / "cache" / "discovered_techniques.json"))
    args = parser.parse_args()

    registry = TechniqueRegistry(args.registry)
    specs = load_dsl_file(args.dsl_file)
    added = register_specs(registry, specs)
    print(json.dumps({"added": added, "total": registry.stats()}, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
