"""混淆逃逸兜底规则单元测试。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.obfuscation_signals import obfuscated_evasion_rescue  # noqa: E402
from iga_guard.pipeline import IgaGuardEngine, load_config  # noqa: E402


class TestObfuscatedEvasionRescue:
    def test_null_byte_splice(self):
        r = obfuscated_evasion_rescue("ben%00aderet@introito.io", "ben%00aderet@introito.io")
        assert r is not None
        assert r[0] == "SQLi"
        r2 = obfuscated_evasion_rescue("ben\x00aderet@introito.io", "ben\x00aderet@introito.io")
        assert r2 is not None
        assert r2[0] == "SQLi"

    def test_shell_echo_encoded(self):
        p = "&&echo%20TQHCUN$((6%2B71))$(echo%20TQHCUN)TQHCUN"
        r = obfuscated_evasion_rescue(p, p.lower())
        assert r is not None
        assert r[0] == "CMD"

    def test_url_encode_name_pattern(self):
        # 纯姓名 url_encode 不再 rescue（压误报）；含表单字段时仍触发
        assert obfuscated_evasion_rescue("Plumbago%2B39%2B", "plumbago+39+") is None
        r = obfuscated_evasion_rescue("modo%3Dinsertar%2Blogin%3Dx", "modo=insertar+login=x")
        assert r is not None

    def test_plain_normal_not_rescued(self):
        assert obfuscated_evasion_rescue("alice", "alice") is None

    def test_concat_split_rescue(self):
        r = obfuscated_evasion_rescue("1 uni'+'on sel'+'ect", "1 uni'+'on sel'+'ect")
        assert r is not None
        assert r[0] == "SQLi"

    def test_hex32_rescue(self):
        from iga_guard.obfuscation_signals import _mixed_case_hex32_token
        assert _mixed_case_hex32_token("BD29f96e42B921E01cDfB7ee7fD79B36")


@pytest.fixture(scope="module")
def engine() -> IgaGuardEngine:
    return IgaGuardEngine(load_config(ROOT / "configs" / "default.yaml"))


class TestEngineWithRescue:
    def test_null_byte_miss_now_detected(self, engine: IgaGuardEngine):
        report = engine.analyze_url("GET", "http://eval.local/test?p=ben%00aderet@introito.io")
        assert report.detection.is_malicious is True

    def test_normal_plain_unchanged(self, engine: IgaGuardEngine):
        report = engine.analyze_url("GET", "http://demo.example/login?user=alice&page=home")
        assert report.detection.is_malicious is False

    def test_benign_csic_form_not_sqli(self, engine: IgaGuardEngine):
        url = (
            "http://demo/login?modo=registro&login=rechelle&password=4ri9c4"
            "&nombre=Danna&apellidos=Gr"
        )
        report = engine.analyze_url("GET", url)
        assert report.detection.is_malicious is False
