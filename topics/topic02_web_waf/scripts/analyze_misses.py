#!/usr/bin/env python3
"""分析 eval_obf_misses.jsonl 漏检分布与模式，输出 results/miss_analysis.json。"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.obfuscation_signals import (  # noqa: E402
    attack_keyword_scores,
    structural_attack_scores,
)


def _source_prefix(source: str) -> str:
    return source.split(":")[0] if ":" in source else source


def _obfuscation_kind(source: str) -> str:
    if ":" in source:
        return source.split(":", 1)[1]
    return source


def _classify_pattern(payload: str, source: str, label: str) -> str:
    p = payload
    pl = p.lower()
    kind = _obfuscation_kind(source)

    if kind == "double_url_encode" or "%252" in pl:
        return "double_url_encode_cmd" if label == "CMD" else "double_url_encode_sqli"
    if kind == "null_byte" or "%00" in pl:
        return "null_byte_in_params"
    if kind == "unicode_escape" or re.search(r"\\u[0-9a-fA-F]{4}", p):
        return "unicode_escape_sqli"
    if kind == "multipart_boundary_sim" or "webkitformboundary" in pl:
        if label == "CMD":
            return "multipart_boundary_cmd"
        return "multipart_boundary_sqli"
    if kind == "url_encode" and ("echo" in pl or "str=" in pl or "str%3d" in pl):
        return "url_encode_cmd"
    if source == "seclists_cmd":
        if "str=" in pl or "str%3d" in pl or "$(echo" in pl or "echo" in pl:
            return "seclists_echo_shell"
        return "seclists_cmd_other"
    if kind == "base64_fragment":
        return "base64_fragment_sqli"
    if kind == "char_function":
        return "char_function_sqli"
    if kind == "case_random":
        return "case_random_cmd"
    if kind == "unicode_normalization":
        return "unicode_normalization"
    return f"other:{kind or source}"


def analyze_misses(path: Path) -> dict:
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))

    by_label = Counter(r["label"] for r in rows)
    by_source = Counter(r["source"] for r in rows)
    by_source_prefix = Counter(_source_prefix(r["source"]) for r in rows)
    by_pattern = Counter(_classify_pattern(r["payload"], r["source"], r["label"]) for r in rows)

    cross_label_source: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for r in rows:
        cross_label_source[r["label"]][_source_prefix(r["source"])] += 1

    # 当前规则对漏检样本的得分峰值（诊断用）
    kw_peaks: Counter[str] = Counter()
    st_peaks: Counter[str] = Counter()
    for r in rows:
        raw = r["payload"]
        norm = raw.lower()
        kw = attack_keyword_scores(norm)
        st = structural_attack_scores(raw, norm, decode_depth=1 if "%252" in raw.lower() else 0)
        kw_peak = max((v for k, v in kw.items() if k != "Normal"), default=0.0)
        st_peak = max((v for k, v in st.items() if k != "Normal"), default=0.0)
        kw_peaks[f"{kw_peak:.2f}"] += 1
        st_peaks[f"{st_peak:.2f}"] += 1

    top_patterns = [
        {"pattern": pat, "count": cnt, "pct": round(100 * cnt / len(rows), 1)}
        for pat, cnt in by_pattern.most_common(10)
    ]

    return {
        "total": len(rows),
        "by_label": dict(by_label),
        "by_source_prefix": dict(by_source_prefix),
        "by_source": dict(by_source.most_common()),
        "cross_label_source_prefix": {k: dict(v) for k, v in sorted(cross_label_source.items())},
        "top_patterns": top_patterns,
        "top_5_miss_patterns": top_patterns[:5],
        "score_diagnostics": {
            "kw_peak_distribution": dict(kw_peaks.most_common(10)),
            "st_peak_distribution": dict(st_peaks.most_common(10)),
            "fallback_would_catch": _fallback_coverage(rows),
        },
    }


def _fallback_coverage(rows: list[dict]) -> dict:
    """dual_track 混淆兜底阈值：st_peak>=0.5 且 kw_peak>=0.15。"""
    caught = 0
    by_pattern: dict[str, list[bool]] = defaultdict(list)
    for r in rows:
        raw = r["payload"]
        norm = raw.lower()
        dd = 1 if "%252" in norm else 0
        kw = attack_keyword_scores(norm)
        st = structural_attack_scores(raw, norm, decode_depth=dd)
        kw_peak = max((v for k, v in kw.items() if k != "Normal"), default=0.0)
        st_peak = max((v for k, v in st.items() if k != "Normal"), default=0.0)
        hit = kw_peak >= 0.15 and st_peak >= 0.5
        if hit:
            caught += 1
        pat = _classify_pattern(raw, r["source"], r["label"])
        by_pattern[pat].append(hit)
    top5_pats = [p for p, _ in Counter(
        _classify_pattern(r["payload"], r["source"], r["label"]) for r in rows
    ).most_common(5)]
    top5_cov = {
        pat: {
            "total": len(by_pattern[pat]),
            "caught": sum(by_pattern[pat]),
            "catch_rate_pct": round(100 * sum(by_pattern[pat]) / len(by_pattern[pat]), 1)
            if by_pattern[pat] else 0.0,
        }
        for pat in top5_pats
    }
    return {
        "total": len(rows),
        "caught": caught,
        "catch_rate_pct": round(100 * caught / len(rows), 1) if rows else 0.0,
        "top_5_pattern_coverage": top5_cov,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        default=str(ROOT / "data" / "cache" / "eval_obf_misses.jsonl"),
    )
    parser.add_argument(
        "--output",
        default=str(ROOT / "results" / "miss_analysis.json"),
    )
    args = parser.parse_args()

    result = analyze_misses(Path(args.input))
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
