"""多分类仲裁与 atob-CMD 边界单测。"""

from iga_guard.obfuscation_signals import (
    _eval_atob_decoded_attack,
    arbitrate_attack_label,
)


def test_eval_atob_prefers_cmd_when_shell_decoded():
    raw = "eval(atob('JTI1MjIlN0MlMjAlNUIlMjA5JTIwLW5lJTIwJTI0JTI4ZWNobyUyMA=='))NREISI%20%7C%20tr%20-d%20%27%5Cn%27%20%7C%20wc%20-c%29%20%5D%20%7C%7C%20sleep%201%20%7C"
    hit = _eval_atob_decoded_attack(raw)
    assert hit is not None
    assert hit[0] == "CMD"


def test_arbitrate_cmd_over_sqli_on_sleep_shell():
    raw = "%26%20sleep%200%20%26%26%20str%3D%24%28echo%20PDOPTJ%29%20%26%26%20str1%3D%24%7B%23str%7D%20%26%26%20%5B%209%20-eq%20%24%7Bstr1%7D%20%5D%20%26%26%20sleep%201%20//"
    label, conf = arbitrate_attack_label(
        "SQLi",
        0.78,
        raw=raw,
        norm=raw,
        all_probs={"SQLi": 0.55, "CMD": 0.30, "Normal": 0.15},
    )
    assert label == "CMD"
    assert conf >= 0.70


def test_arbitrate_keeps_clear_sqli():
    raw = "1 union select username,password from users--"
    label, conf = arbitrate_attack_label(
        "SQLi",
        0.9,
        raw=raw,
        norm=raw,
        all_probs={"SQLi": 0.8, "CMD": 0.05, "Normal": 0.15},
    )
    assert label == "SQLi"
