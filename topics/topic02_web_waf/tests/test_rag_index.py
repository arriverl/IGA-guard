"""RAG 索引与 atob 检测单元测试。"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.obfuscation_signals import _eval_atob_decoded_attack  # noqa: E402
from iga_guard.rag.index import KnowledgeIndex  # noqa: E402


class TestRagIndex:
    def test_build_index(self):
        idx = KnowledgeIndex()
        n = idx.build(ROOT)
        assert n > 10
        hits = idx.search("base64 atob 混淆逃逸", top_k=3)
        assert hits

    def test_save_load(self, tmp_path):
        idx = KnowledgeIndex()
        idx.build(ROOT)
        npz = tmp_path / "rag.npz"
        meta = tmp_path / "rag_meta.json"
        idx.save(npz, meta)
        loaded = KnowledgeIndex.load(npz, meta)
        assert len(loaded.chunks) == len(idx.chunks)


class TestAtobRescue:
    def test_eval_atob_sqli(self):
        p = "eval(atob('bW9kbz1lbnRyYXImbG9naW49YnJlZ2xlYyZwd2Q9YWxFR3Lvv71uJnJl'))member=on"
        hit = _eval_atob_decoded_attack(p)
        assert hit is not None
        assert hit[0] == "SQLi"
        assert hit[1] >= 0.6
