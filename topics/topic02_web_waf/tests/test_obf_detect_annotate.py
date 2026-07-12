"""关键混淆识别 + 可视化标注回归。"""

from iga_guard.eval_transport import build_eval_request
from iga_guard.explainer.webspotter import _locate_span, webspotter_explain
from iga_guard.models import DetectionResult, NormalizedPayload
from iga_guard.obfuscation_signals import (
    looks_like_benign_address,
    obfuscated_evasion_rescue,
)
from iga_guard.pipeline import IgaGuardEngine, load_config


def test_crlf_set_cookie_rescued():
    raw = "4320any%3F%0D%0ASet-cookie%3A+Tamper%3D1041264011025374727"
    hit = obfuscated_evasion_rescue(raw, raw, decode_depth=1)
    assert hit is not None and hit[0] == "SQLi"


def test_url_encode_street_tail_rescued():
    raw = "Calle%2BZubia%2B7%2B"
    assert looks_like_benign_address(raw, raw) is False
    hit = obfuscated_evasion_rescue(raw, raw, decode_depth=1)
    assert hit is not None and hit[0] == "SQLi"


def test_double_url_address_rescued():
    raw = "Travesia%252BEchavacoiz%252BAlto%252C%252B108%252C%252B"
    hit = obfuscated_evasion_rescue(raw, raw, decode_depth=1)
    assert hit is not None and hit[0] == "SQLi"


def test_json_nested_trailing_space_rescued():
    raw = '{"a":{"b":"errorMsg=Credenciales+incorrectas%20"}}'
    hit = obfuscated_evasion_rescue(raw, raw, decode_depth=1)
    assert hit is not None and hit[0] == "SQLi"


def test_fullwidth_address_not_benign():
    raw = "Calｌe+Loｓ+Hoteliｔｏｓ+S/N,+"
    assert looks_like_benign_address(raw, raw) is False
    hit = obfuscated_evasion_rescue(raw, raw, decode_depth=1)
    assert hit is not None
    assert hit[0] == "SQLi"


def test_sparse_unicode_escape_id_pipe_rescued():
    raw = "\\u0069d=|"
    hit = obfuscated_evasion_rescue(raw, raw, decode_depth=1)
    assert hit is not None
    assert hit[0] == "SQLi"


def test_csic_pipe_address_not_benign_and_detected():
    raw = "modo=registro&direccion=Calle%7c"
    assert looks_like_benign_address(raw, raw) is False
    hit = obfuscated_evasion_rescue(raw, raw, decode_depth=1)
    assert hit is not None
    cfg = load_config("configs/default.yaml")
    cfg.setdefault("continual_cache", {})["enabled"] = False
    eng = IgaGuardEngine(cfg)
    method, url, body = build_eval_request(raw)
    report = eng.analyze_url(method, url, body=body, explain=True)
    assert report.detection.is_malicious is True
    assert report.explanation is not None
    assert report.explanation.highlight_html


def test_engine_detects_fullwidth_and_highlights():
    cfg = load_config("configs/default.yaml")
    cfg.setdefault("continual_cache", {})["enabled"] = False
    eng = IgaGuardEngine(cfg)
    payload = "Calｌe+Loｓ+Hoteliｔｏｓ+S/N,+"
    method, url, body = build_eval_request(payload)
    report = eng.analyze_url(method, url, body=body, explain=True)
    assert report.detection.is_malicious is True
    assert report.explanation is not None
    assert report.explanation.highlight_html
    assert "iga-mal" in report.explanation.highlight_html


def test_locate_span_prefers_obfuscation_markers():
    text = "name=Calｌe+%00test"
    span, rng = _locate_span(text, "SQLi")
    assert rng[1] > rng[0]
    assert "%00" in span or "ｌ" in span or "Cal" in span


def test_webspotter_on_obfuscated_payload():
    payload = NormalizedPayload(
        location="query",
        field_name="p",
        raw_payload="1%2500union%2520select",
        normalized_payload="1\x00union select",
        decode_chain=["url"],
    )
    det = DetectionResult(label="SQLi", confidence=0.9, risk_level="high", is_malicious=True)
    exp = webspotter_explain(payload, det)
    assert exp is not None
    assert len(exp.token_range) == 2
    assert exp.malicious_span
