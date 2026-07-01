"""
IGA-Guard 2.0 Flask REST API
==============================
端点一览：
  GET  /api/health           — 服务健康检查
  POST /api/detect           — 单条 HTTP 请求检测（返回 GuardReport JSON）
  GET  /api/alerts           — 最近告警列表
  GET  /api/stats            — 检测统计（攻击类型分布）
  GET  /api/metrics/latency  — 延迟统计（均值 / P99）
  GET  /api/metrics/overall  — v2 离线诚实指标摘要
  POST /api/obfuscate        — 对抗混淆变体生成
  POST /api/evolve           — 漏检样本 + base_train_csv 合并重训
  GET  /api/evolution/history — 自演化训练历史
  GET  /                      — 前端大屏 dashboard.html

依赖：IgaGuardEngine（pipeline.py）+ OnlineRLController（阈值演化）
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard import IgaGuardEngine, __version__
from iga_guard.collector.http_parser import parse_http_request
from iga_guard.evolution import incremental_retrain, log_failure
from iga_guard.evolution.online_rl import OnlineRLController
from iga_guard.pipeline import load_config

app = Flask(__name__, static_folder=str(ROOT / "frontend" / "static"))
CORS(app)

engine = IgaGuardEngine(load_config(ROOT / "configs" / "default.yaml"))
rl_controller = OnlineRLController(str(ROOT / "data" / "cache" / "rl_state.json"))
recent_alerts: list[dict] = []
latency_samples: list[float] = []


@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "IGA-Guard",
        "version": __version__,
        "engine": load_config(ROOT / "configs" / "default.yaml").get("detector", {}).get("engine"),
    })


@app.post("/api/detect")
def detect():
    data = request.get_json(force=True, silent=True) or {}
    req = parse_http_request(
        method=data.get("method", "GET"),
        url=data.get("url", ""),
        body=data.get("body", ""),
        headers=data.get("headers", {}),
    )
    report = engine.analyze_request(req)
    payload = report.to_dict()
    latency_samples.append(report.detection.latency_ms)
    if len(latency_samples) > 1000:
        del latency_samples[:500]
    if report.detection.is_malicious:
        recent_alerts.insert(0, payload)
        del recent_alerts[50:]
    return jsonify(payload)


@app.get("/api/alerts")
def alerts():
    return jsonify({"alerts": recent_alerts[:20]})


@app.get("/api/stats")
def stats():
    labels = [a.get("detection", {}).get("label", "Normal") for a in recent_alerts]
    counter = Counter(labels)
    return jsonify({
        "attack_distribution": dict(counter),
        "total_alerts": len(recent_alerts),
        "version": __version__,
    })


_OVERALL_METRICS_FALLBACK = {
    "obfuscated_attack_recall": 0.9186,
    "normal_false_positive_rate": 0.0293,
    "overall_detection_recall": 0.788,
    "eval_samples": 19411,
}


def _load_overall_metrics() -> dict:
    """从 results/v2_exp1_overall.json 读取离线评测摘要，缺失时使用硬编码兜底。"""
    metrics_path = ROOT / "results" / "v2_exp1_overall.json"
    if not metrics_path.exists():
        return {**_OVERALL_METRICS_FALLBACK, "source": "fallback"}

    data = json.loads(metrics_path.read_text(encoding="utf-8"))
    obf = data.get("obfuscated_attack_binary", {})
    normal = data.get("normal_binary", {})
    overall = data.get("overall_binary", {})
    return {
        "source": "results/v2_exp1_overall.json",
        "dataset": data.get("dataset"),
        "eval_samples": data.get("eval_samples", _OVERALL_METRICS_FALLBACK["eval_samples"]),
        "obfuscated_attack_recall": obf.get(
            "detection_recall", _OVERALL_METRICS_FALLBACK["obfuscated_attack_recall"]
        ),
        "normal_false_positive_rate": normal.get(
            "false_positive_rate", _OVERALL_METRICS_FALLBACK["normal_false_positive_rate"]
        ),
        "overall_detection_recall": overall.get(
            "detection_recall", _OVERALL_METRICS_FALLBACK["overall_detection_recall"]
        ),
        "target_obfuscated_recall": data.get("target_obfuscated_recall"),
    }


@app.get("/api/metrics/overall")
def metrics_overall():
    return jsonify(_load_overall_metrics())


@app.get("/api/metrics/latency")
def metrics_latency():
    if not latency_samples:
        return jsonify({"samples": 0, "mean_ms": 0, "p99_ms": 0})
    sorted_lat = sorted(latency_samples)
    p99_idx = max(0, int(0.99 * len(sorted_lat)) - 1)
    return jsonify({
        "samples": len(latency_samples),
        "mean_ms": round(sum(latency_samples) / len(latency_samples), 3),
        "p99_ms": round(sorted_lat[p99_idx], 3),
        "target_ms": load_config(ROOT / "configs" / "default.yaml").get("latency", {}).get("target_ms", 5),
    })


@app.get("/api/cache/stats")
def cache_stats():
    det = engine.detector
    if not hasattr(det, "cache") or det.cache is None:
        return jsonify({"enabled": False})
    return jsonify({"enabled": True, **det.cache.stats()})


@app.get("/api/evolution/history")
def evolution_history():
    return jsonify({"history": rl_controller.history()})
def feedback():
    data = request.get_json(force=True, silent=True) or {}
    true_label = data.get("true_label", "SQLi")
    report = engine.analyze_url(data.get("method", "GET"), data.get("url", ""))
    cache = ROOT / "data" / "cache" / "failures.jsonl"
    log_failure(str(cache), report, true_label)

    rl_result = {}
    cache_result = {}
    if hasattr(engine.detector, "cache") and engine.detector.cache is not None:
        payload_text = data.get("payload") or (
            report.normalized[0].raw_payload if report.normalized else ""
        )
        if payload_text:
            cache_result = engine.detector.cache.update_from_feedback(payload_text, true_label)

    if hasattr(engine.detector, "adjust_threshold"):
        from iga_guard.detector.dual_track import DualTrackDetector

        if isinstance(engine.detector, DualTrackDetector):
            top_feats = []
            if report.normalized:
                from iga_guard.features import extract_features
                fv = extract_features(report.normalized[0])
                top_feats = fv.names[:5]
            rl_result = rl_controller.feedback(
                engine.detector,
                report.detection.label,
                true_label,
                top_features=top_feats,
            )
    return jsonify({"logged": True, "rl": rl_result, "cache": cache_result})


@app.post("/api/evolve")
def evolve():
    cfg = load_config(ROOT / "configs" / "default.yaml")
    evo = cfg.get("evolution", {})
    detector = engine.detector
    if hasattr(detector, "base"):
        detector = detector.base
    result = incremental_retrain(
        detector,
        str(ROOT / "data" / "cache" / "failures.jsonl"),
        str(ROOT / "models" / "fusion_detector.joblib"),
        min_samples=evo.get("retrain_min_samples", 5),
        base_train_csv=str(ROOT / "data" / "master" / "train_obfuscated.csv"),
        max_base_samples=evo.get("max_base_samples", 80_000),
        failure_augment=evo.get("failure_augment", 2),
    )
    cache_result = {}
    cache_cfg = cfg.get("continual_cache", {})
    if cache_cfg.get("enabled") and hasattr(engine.detector, "cache") and engine.detector.cache:
        cache = engine.detector.cache
        fail_path = ROOT / "data" / "cache" / "failures.jsonl"
        if fail_path.exists():
            for line in fail_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                cache.append(
                    row.get("payload", ""),
                    row.get("true_label", "SQLi"),
                    source="evolve",
                    save=False,
                )
            cache.save()
        cache_result = cache.stats()
    return jsonify({**result, "continual_cache": cache_result})


@app.post("/api/obfuscate")
def obfuscate():
    """混淆生成器 API：对输入载荷生成 mutator + AST + 社区手法变体。"""
    from iga_guard.adversarial.ast_mutator import ast_obfuscate_batch
    from iga_guard.adversarial.mutator import mutate_batch
    from iga_guard.dataset.obfuscation_techniques import expand_payload

    data = request.get_json(force=True, silent=True) or {}
    payload = data.get("payload", "")
    label = data.get("attack_type", "SQLi")
    count = min(int(data.get("count", 8)), 30)
    if not payload:
        return jsonify({"error": "payload required"}), 400

    variants: list[dict] = [{"payload": payload, "source": "original"}]
    for v in mutate_batch(payload, label, n=count):
        variants.append({"payload": v, "source": "mutator"})
    for v in ast_obfuscate_batch(payload, n=count):
        variants.append({"payload": v, "source": "ast"})
    for item in expand_payload(payload, label, n=count, seed=hash(payload) % (2**31)):
        variants.append({"payload": item["payload"], "source": item.get("source", "obfuscation")})

    seen: set[str] = set()
    out: list[dict] = []
    for row in variants:
        if row["payload"] not in seen:
            seen.add(row["payload"])
            out.append(row)
        if len(out) >= count + 1:
            break

    return jsonify({
        "original": payload,
        "attack_type": label,
        "variants": out,
        "count": len(out),
    })


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "dashboard.html")


def create_app() -> Flask:
    return app
