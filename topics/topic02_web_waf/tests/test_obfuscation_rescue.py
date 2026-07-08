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
        # 纯姓名 / 正常 URL 编码表单不再 rescue（压误报）。
        assert obfuscated_evasion_rescue("Plumbago%2B39%2B", "plumbago+39+") is None
        assert obfuscated_evasion_rescue("modo%3Dinsertar%26precio%3D5548", "modo=insertar&precio=5548") is None
        r = obfuscated_evasion_rescue("modo%3Dlogin%26id%3D1%2527", "modo=login&id=1%27")
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

    def test_hpp_hex32_attack_context_rescued(self):
        payload = "id=1&id=BD29f96e42B921E01cDfB7ee7fD79B36"
        r = obfuscated_evasion_rescue(payload, payload.lower())
        assert r is not None
        assert r[0] == "SQLi"


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

    @pytest.mark.parametrize(
        "query",
        [
            "modo=insertar&precio=5548&B1=Confirmar",
            "id=1&nombre=Jamon+Iberico&precio=39&cantidad=14&B1=Anadir+al+carrito",
            "direccion=Carrer+De+Francesc+Boix+i+Campo,+194+10?G",
            "token=21E09EDEF8C4117C37914DB3DB5A210C",
        ],
    )
    def test_csic_normal_patterns_not_malicious(self, engine: IgaGuardEngine, query: str):
        report = engine.analyze_url("GET", f"http://demo.local/shop?{query}", explain=False)
        assert report.detection.label == "Normal"
        assert report.detection.is_malicious is False

    def test_mixed_case_hex32_camouflage_detected(self, engine: IgaGuardEngine):
        report = engine.analyze_url(
            "GET",
            "http://eval.local/test?p=BD29f96e42B921E01cDfB7ee7fD79B36",
            explain=False,
        )
        assert report.detection.is_malicious is True

    def test_hpp_hex32_camouflage_detected(self, engine: IgaGuardEngine):
        report = engine.analyze_url(
            "GET",
            "http://eval.local/test?id=1&id=BD29f96e42B921E01cDfB7ee7fD79B36",
            explain=False,
        )
        assert report.detection.is_malicious is True

    def test_malformed_encoded_csic_action_detected(self, engine: IgaGuardEngine):
        report = engine.analyze_url(
            "GET",
            "http://eval.local/test?p=modo%3Dinsertar%26precio%3D7924%26B1A%3DPasar%2Bpor%2Bcaja",
            explain=False,
        )
        assert report.detection.is_malicious is True

    def test_unicode_escaped_hex32_camouflage_detected(self, engine: IgaGuardEngine):
        payload = "\\u0043F2237\\u00463743B\\u0041\\u0043975\\u0046\\u0041A2\\u0041\\u0044F2352E37\\u0041"
        report = engine.analyze_url("GET", f"http://eval.local/test?p={payload}", explain=False)
        assert report.detection.is_malicious is True

    @pytest.mark.parametrize(
        "payload",
        [
            "malcolm_motaung%2540enlanzarote.com.yu",
            "ventr%25EF%25BF%25BDn",
        ],
    )
    def test_double_url_encoded_evasion_detected(self, engine: IgaGuardEngine, payload: str):
        report = engine.analyze_url("GET", f"http://eval.local/test?p={payload}", explain=False)
        assert report.detection.is_malicious is True

    @pytest.mark.parametrize(
        "payload",
        [
            "https%3A//example.com/?u=http%3A%2F%2Fmalicious.com%2Findex.php%3Fp%3D1%26c%3D1",
            "%26nompercentbre=Qu%E1so+Manc%C3%A9hego&preci%C3%B1o=100&cantidad=15&B1=A%CC%8Aadir+a%CC%8Al+carr%C3%ADto",
            "http%3A%2F%2Fexample.com%3Fmode%3Dregister&_url_encode_login%3Dfscocos&password%3Daut%C3%B4nticamente",
            "http%61re=http%69t%67p%2f%2Fexample.com%3fparam1%3dvalue1%26param2%3dvalue2%26x%3dpolymorphic_data",
            "![](http://evil.com/x?cmd=whoami",
            "%2571%2564%2568%2565%2573%2565%2572%2576%2569%2563%2579%2520%2573%2565%2573%2574%2572%256F%2577%256E%2565%2579%257C%2565%2578%2570%2572%256F%2561%256D%2540%2574%2572%2575%2569%256E%252E%256A%2565%256C%256C",
            "{\"a\":{\"b\":\"https%3A//example.com?a%26b=%D7%A9%D5%DD%C0%A7%E3%80%8A\"}}",
            "%E6%B3%A2%E4%B8%AA%61%70%74%69%6F%6E%2F68%70%282%29%3B%2523%6C%61%6E%67%74%28%22%2A%29%3B",
            "%2525E6%2525B3%2525A2%2525E4%2525B8%2525AA%252561%252570%252574%252569%25256F%25256E%25252F68%252570%2525282%252529%25253B%25252523%25256C%252561%25256E%252567%252574%252528%252522%25252A%252529%25253B",
            "%C2%8F%C2%9C%CF%CA%C2%A5%C2%AE%C2%BB%C2%84%C2%A1%C2%AC%E6%B2%B9%E8%BE%93%E7%9A%84%E6%9B%B4%E7%BA%A7",
            "%2525C2%25258F%2525C2%25259C%2525CF%2525CA%2525C2%2525A5%2525C2%2525AE%2525C2%2525BB%2525C2%252584%2525C2%2525A1%2525C2%2525AC%2525E6%2525B2%2525B9%2525E8%2525BE%252593%2525E7%25259A%252584%2525E6%25259B%2525B4%2525E7%2525BA%2525A7",
        ],
    )
    def test_llm_evasion_markers_detected(self, engine: IgaGuardEngine, payload: str):
        report = engine.analyze_url("GET", f"http://eval.local/test?p={payload}", explain=False)
        assert report.detection.is_malicious is True

    def test_opaque_encoded_url_cmd_detected(self, engine: IgaGuardEngine):
        for payload in (
            "http%3A//www.example.com%3Fq%3DP085g%40f",
            "http%253A%2F%2Fwww.example.com%253Fq%253DP085g%2540f",
            "http%3A%2F%2Fexample.com%40%23page%26query%3Dvalue",
            "http%3A%2F%2Fexample.com%40%23page%26query%3Dvalue' OR '1'='1",
            "%40b-sign.cg%0A+B1%3DReg157r4r",
        ):
            report = engine.analyze_url("GET", f"http://eval.local/test?p={payload}", explain=False)
            assert report.detection.is_malicious is True

    @pytest.mark.parametrize(
        "payload",
        [
            "http%3A%2F%2Fexample.com%2Flogin%3Fmodo%3Dentrar%26login%3Ddionysus%26pwd%3Dany%253F%0ASet-cookie%3A+Tamper%3D5765205567234876235%26remember%3Don%26B1%3DEntrar",
            "%252e/%252e/%252e/../../../etc/passwd",
            "modo=registro&loginA=eastreg&passw%68thepula1le=Carmen&email=dufresne%40mauvier.hk&B1=Registrar",
            "http%3A%2F%2Fexample.com%2Flogin%3Fmodo%3Dentrar%26login%3Ddionysus%26pwd%3Dany%253F%0ASet-cookie%3A+Tamper%3D5765205567234876235%26remember%3Don%26B1%3DEntrar AND 1 LIKE 1",
            "modo=registro%26login=rici%26password=aguiscar%26ntc=%3CSCRIPT%3Ealert%28%22Paros%22%29%3B%3C%2FSCRIPT%3E&B1=Registrar",
            "modo=registro%26login=rici%26password=%C3%A0guiscar%26ciudadA=Lerma%26ntc=5326981690610617&B1=Registrar",
            "do&nombre=Alcui./no&apellidos=Bori%2BRaich&email=varhelyi_krzyzewska@santacruzdelvoto.mw&dni=87721362Y",
            "do&nombre=Alcui./no&apellidos=Bori+Ra%C3%ADz&ntc=4412645005602 AND 0<1",
            "Do%0A&nombre=Alcui./no%24apellidos=Bori+Raich%24email=x@y.mw",
        ],
    )
    def test_dynamic_adversarial_web_payloads_detected(self, engine: IgaGuardEngine, payload: str):
        report = engine.analyze_url("GET", f"http://eval.local/test?p={payload}", explain=False)
        assert report.detection.is_malicious is True
