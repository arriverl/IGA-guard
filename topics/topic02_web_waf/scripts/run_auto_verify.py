#!/usr/bin/env python3
"""IGA-Guard 全自动检验：单入口串联单元测试、E1(2k/4k)、E4、E6、E8、E9。

用法:
  python scripts/run_auto_verify.py
  python scripts/run_auto_verify.py --quick          # 跳过 E9 80
  python scripts/run_auto_verify.py --skip-e9      # 跳过全部 E9
  python scripts/run_auto_verify.py --only pytest,e1_2k,e4
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
LOG_DIR = ROOT / "data" / "cache" / "auto_verify_logs"
RESULTS.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

PY = sys.executable
ENV = {"PYTHONPATH": str(ROOT / "src"), **dict(__import__("os").environ)}

# 门槛（与 iga_dynamic_guard_final_report 对齐，略留余量）
GATES = {
    "pytest_pass_rate": 1.0,
    "e1_2k_obf_recall_min": 0.995,
    "e1_2k_fpr_max": 0.05,
    "e1_4k_obf_recall_min": 0.995,
    "e1_4k_fpr_max": 0.05,
    "e1_nocache_obf_recall_min": 0.992,
    "e9_pooled_recall_min": 0.95,
    "e9_final_recall_min": 0.95,
    "e9_block_recall_min": 0.95,
    "e4_p50_ms_max": 5.0,
    "e4_p99_ms_max": 50.0,
    "e6_span_hit_min": 1.0,
    "e8_block_rate_min": 1.0,
    "llm_reachable": True,
}


def _run_step(name: str, cmd: list[str], *, timeout: int | None = None) -> dict:
    log_path = LOG_DIR / f"{name}.log"
    t0 = time.perf_counter()
    print(f"\n>>> [{name}] {' '.join(cmd)}", flush=True)
    try:
        proc = subprocess.run(
            cmd,
            cwd=ROOT,
            env=ENV,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        elapsed = round(time.perf_counter() - t0, 2)
        log_path.write_text(proc.stdout + ("\n" + proc.stderr if proc.stderr else ""), encoding="utf-8")
        return {
            "name": name,
            "cmd": cmd,
            "returncode": proc.returncode,
            "elapsed_s": elapsed,
            "log": str(log_path),
            "ok": proc.returncode == 0,
        }
    except subprocess.TimeoutExpired as exc:
        elapsed = round(time.perf_counter() - t0, 2)
        log_path.write_text((exc.stdout or "") + (exc.stderr or ""), encoding="utf-8")
        return {
            "name": name,
            "cmd": cmd,
            "returncode": -1,
            "elapsed_s": elapsed,
            "log": str(log_path),
            "ok": False,
            "error": "timeout",
        }


def _load_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _gate(name: str, passed: bool, detail: str, **metrics) -> dict:
    return {"gate": name, "passed": passed, "detail": detail, **metrics}


def step_pytest() -> tuple[dict, list[dict]]:
    r = _run_step("pytest", [PY, "-m", "pytest", "tests/", "-q", "--tb=no"], timeout=600)
    gates = [_gate("pytest", r["ok"], "all tests pass" if r["ok"] else f"exit {r['returncode']}")]
    return r, gates


def step_check_llm() -> tuple[dict, list[dict]]:
    r = _run_step("check_llm", [PY, "scripts/check_llm.py"], timeout=120)
    reachable = r["ok"]
    gates = [_gate("llm", reachable or not GATES["llm_reachable"], "ollama reachable" if reachable else "ollama down")]
    return r, gates


def step_evaluate(tag: str, max_samples: int, output: str, *, no_cache: bool = False) -> tuple[dict, list[dict]]:
    cmd = [
        PY, "scripts/evaluate.py",
        "--max-samples", str(max_samples),
        "--output", output,
    ]
    if no_cache:
        cmd.append("--no-cache")
    r = _run_step(tag, cmd, timeout=3600)
    data = _load_json(RESULTS / Path(output).name) or _load_json(ROOT / output)
    gates: list[dict] = []
    if data:
        obf = data.get("obfuscated_attack_binary", {})
        nb = data.get("normal_binary", {})
        obf_r = float(obf.get("detection_recall", 0))
        fpr = float(nb.get("false_positive_rate", 1))
        prefix = tag.replace("e1_", "")
        obf_min = GATES.get(f"e1_{prefix.split('_')[0]}_obf_recall_min") if not no_cache else GATES["e1_nocache_obf_recall_min"]
        if no_cache:
            obf_min = GATES["e1_nocache_obf_recall_min"]
        elif "4k" in tag:
            obf_min = GATES["e1_4k_obf_recall_min"]
        else:
            obf_min = GATES["e1_2k_obf_recall_min"]
        fpr_max = GATES["e1_4k_fpr_max"] if "4k" in tag else GATES["e1_2k_fpr_max"]
        passed = obf_r >= obf_min and fpr <= fpr_max and r["ok"]
        gates.append(_gate(
            tag,
            passed,
            f"obf_recall>={obf_min}, fpr<={fpr_max}",
            obf_recall=obf_r,
            fpr=fpr,
            samples=data.get("eval_samples"),
        ))
    else:
        gates.append(_gate(tag, False, "missing result json"))
    return r, gates


def step_latency() -> tuple[dict, list[dict]]:
    out = RESULTS / "v2_exp4_latency_auto.json"
    r = _run_step("e4_latency", [PY, "scripts/benchmark_latency.py"], timeout=600)
    data = _load_json(RESULTS / "v2_exp4_latency.json")
    gates: list[dict] = []
    if data:
        p50 = float(data.get("p50_ms", 999))
        p99 = float(data.get("p99_ms", 999))
        passed = p50 <= GATES["e4_p50_ms_max"] and p99 <= GATES["e4_p99_ms_max"]
        gates.append(_gate(
            "e4_latency",
            passed,
            f"p50<={GATES['e4_p50_ms_max']}ms, p99<={GATES['e4_p99_ms_max']}ms",
            p50_ms=p50,
            p99_ms=p99,
        ))
        if out != RESULTS / "v2_exp4_latency.json":
            out.write_text(json.dumps(data, indent=2), encoding="utf-8")
    else:
        gates.append(_gate("e4_latency", False, "missing latency json"))
    return r, gates


def step_e6() -> tuple[dict, list[dict]]:
    r = _run_step("e6_explain", [PY, "scripts/eval_explainability.py"], timeout=300)
    data = _load_json(RESULTS / "v2_exp6_localization.json")
    gates: list[dict] = []
    if data:
        v2 = data.get("v2", {})
        hit = float(v2.get("span_hit_rate", 0))
        improvement = float(data.get("localization_improvement_ratio", 0))
        target_improve = float(data.get("target_improvement", 0.22))
        passed = r["ok"] and (
            hit >= GATES["e6_span_hit_min"]
            or improvement >= target_improve
            or bool(data.get("pass"))
        )
        gates.append(_gate(
            "e6_explain",
            passed,
            f"span_hit>={GATES['e6_span_hit_min']} or improvement>={target_improve}",
            span_hit_rate=hit,
            localization_improvement=improvement,
        ))
    else:
        gates.append(_gate("e6_explain", False, "missing result json"))
    return r, gates


def step_miss_to_rule() -> tuple[dict, list[dict]]:
    r = _run_step("miss_to_rule", [PY, "scripts/miss_to_rule.py", "--tail", "80"], timeout=120)
    gates = [_gate("miss_to_rule", r["ok"], "miss cluster → rescue rules")]
    return r, gates


def step_calibrate() -> tuple[dict, list[dict]]:
    r = _run_step(
        "calibrate_fusion",
        [PY, "scripts/calibrate_fusion_weights.py", "--eval-json", "results/v2_exp1_auto_2k.json"],
        timeout=60,
    )
    gates = [_gate("calibrate_fusion", r["ok"], "fusion weight calibration")]
    return r, gates


def step_e8() -> tuple[dict, list[dict]]:
    r = _run_step("e8_patch", [PY, "scripts/run_experiments_suite.py", "--experiments", "e8"], timeout=300)
    data = _load_json(RESULTS / "v2_exp8_virtual_patch.json")
    gates: list[dict] = []
    if data:
        rate = float(data.get("block_rate", 0))
        passed = rate >= GATES["e8_block_rate_min"]
        gates.append(_gate("e8_patch", passed, f"block_rate>={GATES['e8_block_rate_min']}", block_rate=rate))
    else:
        gates.append(_gate("e8_patch", False, "missing e8 json"))
    return r, gates


def step_e9(max_variants: int, output: str) -> tuple[dict, list[dict]]:
    tag = f"e9_{max_variants}"
    r = _run_step(
        tag,
        [
            PY, "scripts/run_llm_redteam.py",
            "--rounds", "3",
            "--max-variants", str(max_variants),
            "--output", output,
        ],
        timeout=1800,
    )
    data = _load_json(ROOT / output) if (ROOT / output).is_absolute() else _load_json(RESULTS / Path(output).name)
    if data is None:
        data = _load_json(Path(output))
    gates: list[dict] = []
    if data:
        pooled = float(data.get("pooled_recall", 0))
        final = float(data.get("final_round_recall", 0))
        block = float(data.get("block_recall", pooled))
        # E9 40 为快速冒烟：仅以 pooled/block 为准；E9 80 为 canonical 全量门禁。
        if max_variants <= 40:
            passed = (
                pooled >= GATES["e9_pooled_recall_min"]
                and block >= GATES["e9_block_recall_min"]
            )
            detail = "pooled/block recall gates (smoke)"
        else:
            passed = (
                pooled >= GATES["e9_pooled_recall_min"]
                and final >= GATES["e9_final_recall_min"]
                and block >= GATES["e9_block_recall_min"]
            )
            detail = "pooled/final/block recall gates"
        gates.append(_gate(
            tag,
            passed,
            detail,
            pooled_recall=pooled,
            final_round_recall=final,
            block_recall=block,
            total_missed=data.get("total_missed"),
        ))
    else:
        gates.append(_gate(tag, False, "missing e9 json"))
    return r, gates


def _markdown_report(report: dict) -> str:
    lines = [
        "# IGA-Guard Auto Verify Report",
        "",
        f"- **Started**: {report.get('started_at')}",
        f"- **Finished**: {report.get('finished_at')}",
        f"- **Overall**: {'PASS' if report.get('passed') else 'FAIL'}",
        f"- **Elapsed**: {report.get('elapsed_s')}s",
        "",
        "## Gates",
        "",
        "| Gate | Status | Detail |",
        "| --- | --- | --- |",
    ]
    for g in report.get("gates", []):
        status = "PASS" if g.get("passed") else "FAIL"
        extra = ", ".join(f"{k}={v}" for k, v in g.items() if k not in ("gate", "passed", "detail"))
        detail = g.get("detail", "")
        if extra:
            detail = f"{detail} ({extra})"
        lines.append(f"| {g.get('gate')} | {status} | {detail} |")
    lines.extend(["", "## Steps", ""])
    for s in report.get("steps", []):
        lines.append(f"- `{s['name']}`: rc={s['returncode']} elapsed={s['elapsed_s']}s log=`{s['log']}`")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="IGA-Guard 全自动检验")
    parser.add_argument("--quick", action="store_true", help="跳过 E9 80")
    parser.add_argument("--skip-e9", action="store_true")
    parser.add_argument("--skip-nocache", action="store_true")
    parser.add_argument(
        "--only",
        default="",
        help="逗号分隔子集: pytest,llm,e1_2k,e1_4k,e1_nocache,miss_to_rule,calibrate_fusion,e4,e6,e8,e9_40,e9_80",
    )
    args = parser.parse_args()

    all_steps = [
        "pytest", "llm", "e1_2k", "e1_4k", "e1_nocache",
        "miss_to_rule", "calibrate_fusion", "e4", "e6", "e8", "e9_40", "e9_80",
    ]
    if args.only:
        selected = [x.strip() for x in args.only.split(",") if x.strip()]
    else:
        selected = list(all_steps)
        if args.skip_e9:
            selected = [x for x in selected if not x.startswith("e9")]
        elif args.quick:
            selected = [x for x in selected if x != "e9_80"]
        if args.skip_nocache:
            selected = [x for x in selected if x != "e1_nocache"]

    started = datetime.now(timezone.utc)
    t0 = time.perf_counter()
    steps: list[dict] = []
    gates: list[dict] = []

    runners = {
        "pytest": step_pytest,
        "llm": step_check_llm,
        "e1_2k": lambda: step_evaluate("e1_2k", 2000, "results/v2_exp1_auto_2k.json"),
        "e1_4k": lambda: step_evaluate("e1_4k", 4000, "results/v2_exp1_auto_4k.json"),
        "e1_nocache": lambda: step_evaluate("e1_nocache", 2000, "results/v2_exp1_auto_nocache_2k.json", no_cache=True),
        "miss_to_rule": step_miss_to_rule,
        "calibrate_fusion": step_calibrate,
        "e4": step_latency,
        "e6": step_e6,
        "e8": step_e8,
        "e9_40": lambda: step_e9(40, "results/v2_exp9_auto_40.json"),
        "e9_80": lambda: step_e9(80, "results/v2_exp9_auto_80.json"),
    }

    for name in selected:
        if name not in runners:
            print(f"[WARN] unknown step: {name}", flush=True)
            continue
        step_result, step_gates = runners[name]()
        steps.append(step_result)
        gates.extend(step_gates)

    finished = datetime.now(timezone.utc)
    elapsed = round(time.perf_counter() - t0, 2)
    passed = all(g.get("passed") for g in gates) if gates else False

    report = {
        "experiment": "auto_verify",
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "elapsed_s": elapsed,
        "passed": passed,
        "gates": gates,
        "steps": steps,
        "selected_steps": selected,
        "thresholds": GATES,
    }

    json_path = RESULTS / "auto_verify_report.json"
    md_path = RESULTS / "auto_verify_report.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(_markdown_report(report), encoding="utf-8")

    print("\n========== AUTO VERIFY SUMMARY ==========", flush=True)
    print(f"Overall: {'PASS' if passed else 'FAIL'}  ({elapsed}s)", flush=True)
    for g in gates:
        mark = "OK" if g.get("passed") else "FAIL"
        print(f"  [{mark}] {g.get('gate')}: {g.get('detail')}", flush=True)
    print(f"Report: {json_path}", flush=True)
    print(f"Markdown: {md_path}", flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
