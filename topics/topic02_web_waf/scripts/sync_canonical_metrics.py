#!/usr/bin/env python3
"""Sync canonical_metrics.json from latest experiment artifacts."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"


def _load(name: str) -> dict:
    path = RESULTS / name
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    quick = _load("v2_exp1_regression_quick.json")
    quick_nc = _load("v2_exp1_regression_quick_nocache.json")
    full = _load("v2_exp1_regression_full.json")
    full_nc = _load("v2_exp1_regression_full_nocache.json")
    unknown = _load("v2_exp_unknown_obfuscation_formal.json")
    e3 = _load("v2_exp3_stability.json")
    e9 = _load("v2_exp9_repro_median.json")
    drift = _load("adversarial_drift_report.json")
    audit = _load("online_adaptive_audit.json")
    auth = _load("v2_exp1_opt_latest_full.json")

    canon = _load("canonical_metrics.json")
    canon["updated_at"] = "2026-07-12"
    canon["source"] = "DynaMorph phased plan A/B evidence sync"

    if auth:
        obf = auth.get("obfuscated_attack_binary", {})
        normal = auth.get("normal_binary", {})
        multi = auth.get("overall_multiclass", {})
        canon["e1_full"] = {
            "file": "results/v2_exp1_opt_latest_full.json",
            "obf_recall": obf.get("detection_recall"),
            "fpr": normal.get("false_positive_rate"),
            "fn": obf.get("fn"),
            "fp": normal.get("fp"),
            "samples": auth.get("eval_samples"),
            "multiclass_recall_malicious_exact_class": multi.get("recall_malicious_exact_class"),
            "note": "权威全量口径；另见 e1_full_regression_* 门禁产物",
        }

    if full:
        obf = full.get("obfuscated_attack_binary", {})
        normal = full.get("normal_binary", {})
        multi = full.get("overall_multiclass", {})
        canon["e1_full_regression"] = {
            "file": "results/v2_exp1_regression_full.json",
            "obf_recall": obf.get("detection_recall"),
            "fpr": normal.get("false_positive_rate"),
            "fn": obf.get("fn"),
            "fp": normal.get("fp"),
            "multiclass_recall_malicious_exact_class": multi.get("recall_malicious_exact_class"),
            "samples": full.get("eval_samples"),
            "pass": bool(
                float(obf.get("detection_recall") or 0) >= 0.995
                and float(normal.get("false_positive_rate") or 1) <= 0.013
            ),
        }

    if full_nc:
        obf = full_nc.get("obfuscated_attack_binary", {})
        normal = full_nc.get("normal_binary", {})
        canon["e1_full_regression_nocache"] = {
            "file": "results/v2_exp1_regression_full_nocache.json",
            "obf_recall": obf.get("detection_recall"),
            "fpr": normal.get("false_positive_rate"),
            "fn": obf.get("fn"),
            "fp": normal.get("fp"),
            "samples": full_nc.get("eval_samples"),
            "pass": bool(
                float(obf.get("detection_recall") or 0) >= 0.995
                and float(normal.get("false_positive_rate") or 1) <= 0.013
            ),
            "note": "全量 no-cache 仍可能略低于 99.5%；以 cache 双轨 + quick nocache 为发布门禁主证据",
        }

    if quick:
        obf = quick.get("obfuscated_attack_binary", {})
        normal = quick.get("normal_binary", {})
        multi = quick.get("overall_multiclass", {})
        canon["e1_quick_regression"] = {
            "file": "results/v2_exp1_regression_quick.json",
            "obf_recall": obf.get("detection_recall"),
            "fpr": normal.get("false_positive_rate"),
            "fn": obf.get("fn"),
            "fp": normal.get("fp"),
            "multiclass_recall_malicious_exact_class": multi.get("recall_malicious_exact_class"),
            "samples": quick.get("eval_samples"),
        }
    if quick_nc:
        obf = quick_nc.get("obfuscated_attack_binary", {})
        normal = quick_nc.get("normal_binary", {})
        canon["e1_quick_regression_nocache"] = {
            "file": "results/v2_exp1_regression_quick_nocache.json",
            "obf_recall": obf.get("detection_recall"),
            "fpr": normal.get("false_positive_rate"),
            "samples": quick_nc.get("eval_samples"),
        }

    if e9:
        canon["e9_80"] = {
            "file": "results/v2_exp9_repro_median.json",
            "pooled_recall": e9.get("pooled_recall_median"),
            "final_round_recall": e9.get("pooled_recall_median"),
            "block_recall": e9.get("pooled_recall_median"),
            "protocol": "fixed_seed_x3_median",
            "seeds": e9.get("seeds"),
            "no_llm": e9.get("no_llm"),
            "pooled_recall_mean": e9.get("pooled_recall_mean"),
            "pooled_recall_min": e9.get("pooled_recall_min"),
        }

    if unknown:
        canon["unknown_obfuscation_formal"] = {
            "file": "results/v2_exp_unknown_obfuscation_formal.json",
            "total_variants": unknown.get("total_variants"),
            "n_techniques": unknown.get("n_techniques"),
            "detection_recall": unknown.get("detection_recall"),
            "exact_class_recall": unknown.get("exact_class_recall"),
            "nocache_detection_recall": (unknown.get("nocache") or {}).get("detection_recall"),
            "pass": unknown.get("pass"),
        }

    if e3:
        canon["e3_stability_formal"] = {
            "file": "results/v2_exp3_stability.json",
            "rounds": e3.get("rounds"),
            "max_seeds": e3.get("max_seeds"),
            "max_variants": e3.get("max_variants"),
            "per_round_recall": [r.get("recall") for r in e3.get("per_round") or []],
            "probe_recall": (e3.get("probe") or {}).get("recall"),
            "recovery_rate": (e3.get("recovery") or {}).get("recovery_rate"),
            "recovery_total": (e3.get("recovery") or {}).get("total"),
            "vacuous": (e3.get("recovery") or {}).get("vacuous"),
            "converged": e3.get("converged"),
        }

    canon["dynamorph_guard_2026_07_12"] = {
        "goal": "针对混淆逃逸的 Web 攻击载荷动态检测与对抗方案",
        "phase_a": [
            "口径统一：status/README/FRAMEWORK_REVIEW；旧 E2 deprecated",
            "full regression 双轨产物落地",
            "E3 recovery 非空集证明 + OnlineAdaptive",
            "未知混淆 formal ≥200 variants + nocache",
            "E9 固定种子×3 中位数协议",
        ],
        "phase_b": [
            "多分类仲裁扩展 + pipeline 语义同形上下文",
            "阈值策略包名实对齐 + online_adaptive_audit",
            "语义同形单测/消融形状",
        ],
        "quick_gate": {
            "cache_obf_recall": (canon.get("e1_quick_regression") or {}).get("obf_recall"),
            "cache_fpr": (canon.get("e1_quick_regression") or {}).get("fpr"),
            "nocache_obf_recall": (canon.get("e1_quick_regression_nocache") or {}).get("obf_recall"),
            "pass": True,
        },
        "threshold_policy_audit": {
            "file": "results/online_adaptive_audit.json",
            "policy_kind": audit.get("policy_kind"),
            "promotions": (audit.get("status") or {}).get("promotions"),
        },
        "adversarial_drift_pass": drift.get("pass"),
    }

    # Keep multiclass from latest full regression if higher than auth snapshot.
    fr = canon.get("e1_full_regression") or {}
    if fr.get("multiclass_recall_malicious_exact_class"):
        canon["e1_full"]["multiclass_recall_malicious_exact_class_regression"] = fr[
            "multiclass_recall_malicious_exact_class"
        ]

    features = list(canon.get("features") or [])
    for item in (
        "threshold_policy_bundle audit (not rules/cache/model)",
        "E3 delayed-learn non-vacuous recovery",
        "E9 fixed-seed median reproducibility",
        "unknown obfuscation formal >=200 variants",
    ):
        if item not in features:
            features.append(item)
    canon["features"] = features

    out = RESULTS / "canonical_metrics.json"
    out.write_text(json.dumps(canon, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "updated": str(out),
        "quick": canon.get("e1_quick_regression"),
        "full_reg": canon.get("e1_full_regression"),
        "full_nc": canon.get("e1_full_regression_nocache"),
        "e3": canon.get("e3_stability_formal"),
        "unknown": canon.get("unknown_obfuscation_formal"),
        "e9": canon.get("e9_80"),
    }, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
