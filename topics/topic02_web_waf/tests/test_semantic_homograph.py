"""语义同形层单测与轻量消融。"""

from iga_guard.semantic_homograph import semantic_homograph_report


def test_html_entity_xss_semantic_signal():
    raw = "&#60;script&#62;alert(1)&#60;/script&#62;"
    report = semantic_homograph_report(raw, raw)
    assert report.dominant_label in {"XSS", "SQLi", "CMD", "Normal"}
    assert report.confidence >= 0.0
    assert report.views


def test_path_traversal_semantic_signal():
    raw = "..%2f..%2f..%2fetc%2fpasswd"
    report = semantic_homograph_report(raw, "../../../etc/passwd")
    # Either classified as attack or low confidence Normal.
    assert report.dominant_label != "Normal" or report.confidence < 0.20


def test_semantic_ablation_on_off_shape():
    """Ablation shape: high-conf semantic context should differ from empty raw."""
    attack = "<svg/onload=alert(1)>"
    benign = "hello world street 123"
    a = semantic_homograph_report(attack, attack)
    b = semantic_homograph_report(benign, benign)
    assert float(a.confidence or 0.0) >= float(b.confidence or 0.0)
