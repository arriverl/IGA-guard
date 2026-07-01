"""IGA-Guard 主流水线冒烟测试（不触发 TinyBERT 训练）。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.pipeline import IgaGuardEngine, load_config


@pytest.fixture(scope="module")
def engine() -> IgaGuardEngine:
    """使用默认配置创建检测引擎（不训练模型）。"""
    cfg = load_config(ROOT / "configs" / "default.yaml")
    return IgaGuardEngine(cfg)


class TestPipelineSmoke:
    """三条端到端冒烟用例，验证流水线基本可用。"""

    def test_normal_url_not_malicious(self, engine: IgaGuardEngine):
        """正常登录 URL 应判定为非恶意。"""
        report = engine.analyze_url("GET", "http://demo.example/login?user=alice&page=home")
        assert report.detection.label == "Normal"
        assert report.detection.is_malicious is False
        assert report.detection.confidence > 0

    def test_sqli_union_select_detected(self, engine: IgaGuardEngine):
        """经典 SQLi（union select）应被检出为恶意。"""
        report = engine.analyze_url(
            "GET",
            "http://demo.example/login?id=1+union+select+1,2,3--",
        )
        assert report.detection.is_malicious is True
        assert report.detection.label in ("SQLi", "XSS", "CMD", "PathTraversal", "FileInclusion", "XXE", "PromptInjection")
        assert report.detection.latency_ms >= 0

    def test_report_to_dict_has_explanation_fields(self, engine: IgaGuardEngine):
        """GuardReport 序列化应包含 detection 与 field_contributions。"""
        report = engine.analyze_url(
            "GET",
            "http://demo.example/search?q=<script>alert(1)</script>",
        )
        data = report.to_dict()
        assert "detection" in data
        assert data["detection"]["label"]
        assert "explanation" in data
        exp = data["explanation"]
        assert exp is not None
        assert "field_contributions" in exp
        assert isinstance(exp["field_contributions"], dict)
        assert len(exp["field_contributions"]) >= 1
