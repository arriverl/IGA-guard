"""
融合检测器（Fusion Detector）
==============================
双路径融合：
  1. 规则快路径 — 高置信度正则/关键词命中，延迟 <1ms
  2. ML 慢路径  — RandomForest 对 extract_features() 向量分类

训练产物：models/fusion_detector.joblib（含 model + labels）
"""

from __future__ import annotations

import warnings
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.exceptions import InconsistentVersionWarning
from sklearn.ensemble import RandomForestClassifier

from iga_guard.features import extract_features
from iga_guard.models import ATTACK_LABELS, DetectionResult, FeatureVector, NormalizedPayload
from iga_guard.obfuscation_signals import (
    attack_keyword_scores,
    has_strong_obfuscation,
    is_obfuscated,
    looks_like_benign_csic_form,
    is_benign_traffic_context,
    structural_attack_scores,
)


class FusionDetector:
    """Dual-path fusion detector (feature branch + rule prior)."""

    def __init__(self, model_path: str | None = None):
        self.model_path = model_path
        self.model: RandomForestClassifier | None = None
        self.labels = ATTACK_LABELS
        if model_path and Path(model_path).exists():
            self.load(model_path)

    def load(self, path: str) -> None:
        path_obj = Path(path)
        version_stamp = path_obj.with_suffix(path_obj.suffix + ".sklearn_version")
        needs_refresh = (
            not version_stamp.is_file()
            or version_stamp.read_text(encoding="utf-8").strip() != sklearn.__version__
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", InconsistentVersionWarning)
            bundle = joblib.load(path)
        self.model = bundle["model"]
        self.labels = bundle.get("labels", ATTACK_LABELS)
        if hasattr(self.model, "n_jobs"):
            # 单条 predict_proba 时避免 joblib/sklearn 并行配置告警刷屏
            self.model.n_jobs = 1
        if needs_refresh:
            self.save(path)
            version_stamp.write_text(sklearn.__version__, encoding="utf-8")

    def save(self, path: str) -> None:
        path_obj = Path(path)
        path_obj.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self.model, "labels": self.labels}, path)
        path_obj.with_suffix(path_obj.suffix + ".sklearn_version").write_text(
            sklearn.__version__, encoding="utf-8",
        )

    def _rule_prior(self, payload: NormalizedPayload, fv: FeatureVector) -> dict[str, float]:
        text = (payload.normalized_payload or payload.raw_payload).lower()
        scores = {label: 0.0 for label in self.labels}
        scores["Normal"] = 0.1

        if any(k in text for k in ("union", "select", "or 1=1", "sleep(", "benchmark(", "information_schema")):
            scores["SQLi"] += 0.7
        if "union" in text and "select" in text:
            scores["SQLi"] += 0.5
        # 解混淆后仍残留的编码/注释痕迹（社区绕过常见）
        if any(m in text for m in ("/**/", "%27", "%20or%20", "char(", "concat(", "0x")):
            scores["SQLi"] += 0.35
        if any(k in text for k in ("<script", "onerror", "javascript:", "alert(", "onload=", "<svg")):
            scores["XSS"] += 0.7
        if "&#" in text or "\\u003c" in text or "%3cscript" in text:
            scores["XSS"] += 0.4
        if any(k in text for k in (";", "|", "wget", "curl", "`", "${jndi:", "&&", "||")):
            scores["CMD"] += 0.5
        if "../" in text or "..\\" in text or "%2e%2e" in text or "/etc/passwd" in text:
            scores["PathTraversal"] += 0.6
        if "php://" in text or "file://" in text or "expect://" in text:
            scores["FileInclusion"] += 0.6
        if "<!entity" in text or "&xxe;" in text:
            scores["XXE"] += 0.7
        if any(k in text for k in ("ignore previous", "jailbreak", "system prompt", "disregard")):
            scores["PromptInjection"] += 0.7
        # multipart / JSON 嵌套 / HPP 污染特征
        if "boundary=" in text or "content-disposition" in text:
            scores["XSS"] += 0.25
            scores["SQLi"] += 0.2
        if (
            text.count("=") >= 3
            and text.count("&") >= 2
            and any(
                k in text for k in (
                    "union", "select", "%27", "--", " or ", " and ", "sleep(", "benchmark(", "0x",
                )
            )
        ):
            scores["SQLi"] += 0.15
        # 多层解码后暴露的攻击痕迹
        if len(payload.decode_chain) >= 2:
            for label, w in attack_keyword_scores(text).items():
                if label != "Normal":
                    scores[label] += 0.25 * w
        if has_strong_obfuscation(payload.raw_payload) and len(payload.decode_chain) >= 1:
            scores["SQLi"] += 0.2
            scores["XSS"] += 0.15
        raw_low = payload.raw_payload.lower()
        if "%00" in raw_low or "atob(" in raw_low:
            scores["SQLi"] += 0.45
            scores["CMD"] += 0.35
        if "webkitformboundary" in raw_low or "content-disposition" in raw_low:
            scores["CMD"] += 0.5
            scores["XSS"] += 0.3
        if "&&echo" in raw_low or "$(echo" in raw_low or "%0aecho" in raw_low:
            scores["CMD"] += 0.55

        sem = fv.semantic
        scores["SQLi"] += 0.1 * sem.get("sqli_score", 0)
        scores["XSS"] += 0.1 * sem.get("xss_score", 0)

        struct = structural_attack_scores(payload.raw_payload, text, decode_depth=len(payload.decode_chain))
        for label in self.labels:
            scores[label] += 0.3 * struct.get(label, 0.0)

        if is_benign_traffic_context(payload.raw_payload, text):
            scores["Normal"] += 0.70
            for atk in ("SQLi", "XSS", "CMD"):
                scores[atk] *= 0.22
        elif looks_like_benign_csic_form(payload.raw_payload, text):
            scores["Normal"] += 0.35
            scores["SQLi"] *= 0.5
            scores["XSS"] *= 0.5

        total = sum(scores.values()) or 1.0
        return {k: v / total for k, v in scores.items()}

    def predict(self, payload: NormalizedPayload, fv: FeatureVector | None = None) -> DetectionResult:
        if fv is None:
            fv = extract_features(payload)
        rule_probs = self._rule_prior(payload, fv)
        rule_attack = max(
            (k for k in rule_probs if k != "Normal"),
            key=lambda k: rule_probs[k],
            default="Normal",
        )
        rule_attack_score = rule_probs.get(rule_attack, 0.0)

        # Fast path: strong rule signal → skip ML inference (<5ms target)
        if rule_attack_score >= 0.45:
            all_probs = rule_probs
        elif self.model is not None:
            X = np.array([fv.combined], dtype=np.float32)
            proba = self.model.predict_proba(X)[0]
            classes = list(self.model.classes_)
            ml_probs = {c: float(p) for c, p in zip(classes, proba)}
            rule_max = max(v for k, v in rule_probs.items() if k != "Normal")
            rule_weight = 0.7 if rule_max >= 0.4 else 0.4
            ml_weight = 1.0 - rule_weight
            all_probs = {
                label: ml_weight * ml_probs.get(label, 0.0) + rule_weight * rule_probs.get(label, 0.0)
                for label in self.labels
            }
        else:
            all_probs = rule_probs

        label = max(all_probs, key=all_probs.get)
        confidence = all_probs[label]
        # 任一攻击类概率超阈值即判恶意（提升召回，符合 WAF 实战）
        attack_score = max((v for k, v in all_probs.items() if k != "Normal"), default=0.0)
        if attack_score >= 0.35 and all_probs.get(label, 0) < attack_score:
            label = max(
                (k for k in all_probs if k != "Normal"),
                key=lambda k: all_probs[k],
            )
            confidence = all_probs[label]
        is_malicious = label != "Normal" and confidence >= 0.35
        # 混淆兜底：须解码链 + 明确攻击关键词（避免误报正常 hex token）
        if not is_malicious and has_strong_obfuscation(payload.raw_payload):
            norm = (payload.normalized_payload or payload.raw_payload).lower()
            kw = attack_keyword_scores(norm)
            kw_attack = max((v for k, v in kw.items() if k != "Normal"), default=0.0)
            struct = structural_attack_scores(
                payload.raw_payload, norm, decode_depth=len(payload.decode_chain),
            )
            st_peak = max((v for k, v in struct.items() if k != "Normal"), default=0.0)
            if len(payload.decode_chain) >= 2 and kw_attack >= 0.3:
                label = max((k for k in kw if k != "Normal"), key=lambda k: kw[k])
                confidence = max(attack_score, kw_attack, 0.45)
                is_malicious = True
                all_probs[label] = max(all_probs.get(label, 0.0), confidence)
            elif st_peak >= 0.5 and kw_attack >= 0.15:
                label = max((k for k in struct if k != "Normal"), key=lambda k: struct[k])
                confidence = max(attack_score, st_peak, 0.48)
                is_malicious = True
                all_probs[label] = max(all_probs.get(label, 0.0), confidence)
        risk = _risk_level(label, confidence)

        return DetectionResult(
            label=label,
            confidence=confidence,
            risk_level=risk,
            is_malicious=is_malicious,
            all_probs=all_probs,
        )

    def fit(self, X: np.ndarray, y: list[str]) -> None:
        self.model = RandomForestClassifier(
            n_estimators=128,
            max_depth=14,
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X, y)


def _risk_level(label: str, confidence: float) -> str:
    if label == "Normal":
        return "low"
    if confidence >= 0.85:
        return "high"
    if confidence >= 0.6:
        return "medium"
    return "low"
