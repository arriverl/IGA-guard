"""自我迭代与手法发现单元测试。"""

from __future__ import annotations

import tempfile
from pathlib import Path

import numpy as np
import pytest

from iga_guard.evolution.continual_cache import ContinualCacheAdapter, FrozenTextEncoder
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


class TestContinualCacheLoad:
    def test_drops_cache_when_encoder_mode_mismatches(self, monkeypatch):
        def _force_hash(self):
            self._st = None
            self._mode = "hash"

        monkeypatch.setattr(FrozenTextEncoder, "_try_load_st", _force_hash)

        with tempfile.TemporaryDirectory() as td:
            cache_path = Path(td) / "cache.npz"
            np.savez_compressed(
                cache_path,
                keys=np.zeros((1, 384), dtype=np.float32),
                vision_keys=np.zeros((1, 64), dtype=np.float32),
                labels=np.array(["SQLi"], dtype=object),
                sources=np.array(["test"], dtype=object),
                snippets=np.array(["payload"], dtype=object),
                hits=np.array([0], dtype=np.int32),
                ts=np.array([0.0], dtype=np.float64),
                encoder_mode="st",
                dim=384,
            )

            adapter = ContinualCacheAdapter.load(cache_path)

        assert adapter.encoder.mode == "hash"
        assert adapter.stats()["size"] == 0
