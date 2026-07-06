#!/usr/bin/env python3
"""构建 RAG 知识索引（文献 + 漏检 + 社区情报 + 手法库）。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.rag.index import KnowledgeIndex


def main() -> int:
    parser = argparse.ArgumentParser(description="构建 IGA-Guard RAG 索引")
    parser.add_argument("--output", default=str(ROOT / "data" / "cache" / "rag_index.npz"))
    parser.add_argument("--meta", default=str(ROOT / "data" / "cache" / "rag_index_meta.json"))
    args = parser.parse_args()

    idx = KnowledgeIndex()
    n = idx.build(ROOT)
    idx.save(args.output, args.meta)
    print(json.dumps({"chunks": n, "stats": idx.stats(), "wrote": args.output}, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
