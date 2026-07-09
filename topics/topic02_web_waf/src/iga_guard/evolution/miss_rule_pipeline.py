"""WAFBOOSTER 风格：漏检聚类 → 规则候选 → 正常流量 FP 回放 → 启用动态 rescue。"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus

from iga_guard.evolution.discovered_rescue_rules import DiscoveredRescueRules
from iga_guard.obfuscation_signals import is_benign_traffic_context

_SIGNATURE_PATTERNS: list[tuple[str, str, str, float]] = [
    (r"http%3a%2f%2f[^&]{6,}(?:%40|%23)", "opaque_encoded_url", "CMD", 0.62),
    (r"%40[b-]?sign\.cg", "malformed_sign_param", "CMD", 0.62),
    (r"(?:%c2%8f|%2525c2%25258f).{0,120}(?:%e6%b2%b9|%2525e6%2525b2%2525b9)", "high_byte_cmd", "CMD", 0.68),
    (r"(?:%0a|\n).{0,32}set-?cookie", "crlf_set_cookie", "SQLi", 0.66),
    (r"%252e|/etc/passwd", "double_encode_traversal", "PathTraversal", 0.70),
    (r"malicious\.com|evil\.com", "llm_evasion_url", "SQLi", 0.62),
    (r"passw%68|logina=", "malformed_form_cmd", "CMD", 0.62),
]


def _cluster_key(payload: str, label: str) -> str:
    low = payload.lower()
    for pat, name, _, _ in _SIGNATURE_PATTERNS:
        if re.search(pat, low, re.I):
            return f"{label}:{name}"
    pct = low.count("%")
    if pct >= 8:
        return f"{label}:high_pct_blob"
    if "union" in low or "select" in low:
        return f"{label}:sqli_keywords"
    if "<script" in low or "alert(" in low:
        return f"{label}:xss_keywords"
    return f"{label}:other"


def _pattern_for_cluster(cluster: str, samples: list[str]) -> tuple[str, str, float] | None:
    for pat, name, label, conf in _SIGNATURE_PATTERNS:
        if cluster.endswith(name):
            return pat, label, conf
    if cluster.endswith("high_pct_blob"):
        # 过泛 SQLi 百分号 blob 规则会吞掉 CMD 等类别（导致多分类塌缩）。
        # 仅允许用于非 SQLi 聚类；SQLi 交给更具体签名/规则处理。
        label = cluster.split(":")[0]
        if label == "SQLi":
            return None
        return r"(?:^|[?&=])[^&]{0,200}(?:%[0-9a-f]{2}){6,}", label, 0.62
    # 从样本提取最长公共子串（≥8）
    if not samples:
        return None
    base = samples[0].lower()
    for other in samples[1:]:
        o = other.lower()
        i = 0
        while i < min(len(base), len(o)) and base[i] == o[i]:
            i += 1
        base = base[:i]
    token = re.escape(base.strip()) if len(base.strip()) >= 8 else ""
    if token:
        return token, cluster.split(":")[0], 0.60
    return None


def _load_benign_samples(path: Path, limit: int = 500) -> list[str]:
    if not path.exists():
        return []
    out: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        p = row.get("payload") or row.get("url") or ""
        if p and is_benign_traffic_context(p, p.lower()):
            out.append(p)
        if len(out) >= limit:
            break
    return out


def _fp_rate(pattern: str, benign: list[str]) -> float:
    if not benign:
        return 0.0
    try:
        rx = re.compile(pattern, re.I)
    except re.error:
        return 1.0
    hits = sum(1 for b in benign if rx.search(b.lower()))
    return hits / len(benign)


def process_misses(
    misses: list[dict],
    *,
    rules_path: str | Path | None = None,
    benign_path: str | Path | None = None,
    max_fp_rate: float = 0.02,
    min_cluster_size: int = 1,
) -> dict[str, Any]:
    """分析 miss 批次，通过 FP 回放后写入 discovered_rescue_rules.json。"""
    store = DiscoveredRescueRules(rules_path)
    benign_file = Path(benign_path) if benign_path else Path("data/cache/eval_normal_fps.jsonl")
    benign = _load_benign_samples(benign_file)

    buckets: dict[str, list[dict]] = defaultdict(list)
    for m in misses:
        key = _cluster_key(m.get("payload", ""), m.get("label", "SQLi"))
        buckets[key].append(m)

    registered: list[dict] = []
    rejected: list[dict] = []

    for cluster, rows in buckets.items():
        if len(rows) < min_cluster_size:
            continue
        samples = [r["payload"] for r in rows]
        spec = _pattern_for_cluster(cluster, samples)
        if spec is None:
            rejected.append({"cluster": cluster, "reason": "no_pattern"})
            continue
        pattern, label, conf = spec
        fpr = _fp_rate(pattern, benign)
        if fpr > max_fp_rate:
            rejected.append({"cluster": cluster, "pattern": pattern, "fp_rate": round(fpr, 4)})
            continue
        if store.add_rule(
            pattern=pattern,
            label=label,
            confidence=conf,
            cluster=cluster,
            source="miss_rule_pipeline",
        ):
            registered.append({"cluster": cluster, "pattern": pattern, "label": label, "fp_rate": round(fpr, 4)})

    if registered:
        store.save()

    return {
        "processed": len(misses),
        "clusters": len(buckets),
        "registered": registered,
        "rejected": rejected,
        "store": store.stats(),
    }


def process_miss_file(
    path: str | Path,
    *,
    tail: int = 50,
    **kwargs: Any,
) -> dict[str, Any]:
    rows: list[dict] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    if tail > 0:
        rows = rows[-tail:]
    return process_misses(rows, **kwargs)
