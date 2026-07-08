#!/usr/bin/env bash
# 补全 run_eval_full.sh 未跑/失败项 + 测试报告其余实验
set -uo pipefail
DEPLOY="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=setup_env.sh
source "${DEPLOY}/setup_env.sh"

LOG_DIR="${DEPLOY}/logs"
mkdir -p "$LOG_DIR"
LOG="${LOG_DIR}/supplemental.log"
exec > >(tee -a "$LOG") 2>&1

echo "=== IGA-Guard 补全流水线 $(date) ==="
echo "WAF_ROOT=${WAF_ROOT}"
cd "$WAF_ROOT"

step_done() { grep -q "^${1}$" "$LOG" 2>/dev/null; }
mark() { echo "$1"; }

PY="${PY:-python}"
SERVER_PID=""
SERVER_LOG="${LOG_DIR}/api_server.log"

start_api_server() {
  if curl -sf http://127.0.0.1:5000/api/health >/dev/null 2>&1; then
    echo "  [API] 已在运行"
    return 0
  fi
  echo "  [API] 启动 Flask (threaded)..."
  cd "$WAF_ROOT"
  nohup "$PY" run.py >>"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
  for i in $(seq 1 90); do
    if curl -sf http://127.0.0.1:5000/api/health >/dev/null 2>&1; then
      echo "  [API] 就绪 (${i}s)"
      return 0
    fi
    sleep 2
  done
  echo "  [API] 启动超时，见 $SERVER_LOG"
  return 1
}

stop_api_server() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    echo "  [API] 已停止 pid=$SERVER_PID"
  fi
  SERVER_PID=""
}

# ── 0. Ollama / LLM ──────────────────────────────────────────────
if ! step_done "SUPP_LLM_DONE"; then
  echo "[0] LLM 检查..."
  if ! curl -sf http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    echo "  启动 ollama serve..."
    ollama serve >/tmp/ollama_iga.log 2>&1 &
    sleep 4
  fi
  ollama list | grep -q "${IGA_LLM_MODEL:-qwen2.5:3b}" || ollama pull "${IGA_LLM_MODEL:-qwen2.5:3b}" || true
  "$PY" scripts/check_llm.py || echo "  [WARN] LLM 冒烟未完全通过"
  mark "SUPP_LLM_DONE"
fi

# ── 1. LLM 演化三连 ──────────────────────────────────────────────
if ! step_done "SUPP_EVOLVE_DONE"; then
  echo "[1/9] auto_evolve + rag_cycle + llm_redteam..."
  EV=0
  "$PY" scripts/auto_evolve.py --rounds 3 --max-variants 120 --use-llm || EV=1
  "$PY" scripts/rag_agent_cycle.py --rounds 2 --max-variants 80 --use-llm || EV=1
  "$PY" scripts/run_llm_redteam.py --rounds 3 --max-variants 100 || EV=1
  if [[ "$EV" -eq 0 ]]; then
    mark "SUPP_EVOLVE_DONE"
    # 同步主评测日志标记，避免下次全量重跑第 7 步
    grep -q "^IGA_EVOLVE_DONE$" "${LOG_DIR}/eval_full.log" 2>/dev/null || \
      echo "IGA_EVOLVE_DONE" >> "${LOG_DIR}/eval_full.log"
  else
    mark "SUPP_EVOLVE_PARTIAL"
    echo "  [WARN] 部分演化脚本未达阈值或退出非零，结果已落盘 results/"
  fi
fi

# ── 2. 漏检缓存 + 增量重训 ─────────────────────────────────────
if ! step_done "SUPP_MISS_DONE"; then
  echo "[2/9] expand_cache + evolve_obf_misses..."
  "$PY" scripts/expand_cache_from_misses.py --max-rows 500
  "$PY" scripts/evolve_from_obf_misses.py --max-rows 400 --min-samples 3
  mark "SUPP_MISS_DONE"
fi

# ── 3. pytest ────────────────────────────────────────────────────
if ! step_done "SUPP_PYTEST_DONE"; then
  echo "[3/9] pytest..."
  PYTHONPATH="${WAF_ROOT}/src" "$PY" -m pytest tests/ -q --tb=no
  mark "SUPP_PYTEST_DONE"
fi

# ── 4. 可解释性 E6 ───────────────────────────────────────────────
if ! step_done "SUPP_EXPLAIN_DONE"; then
  echo "[4/9] eval_explainability..."
  "$PY" scripts/eval_explainability.py
  mark "SUPP_EXPLAIN_DONE"
fi

# ── 5. 实验套件 E2/E5/E7/E8 ──────────────────────────────────────
if ! step_done "SUPP_EXPERIMENTS_DONE"; then
  echo "[5/9] run_experiments_suite..."
  "$PY" scripts/run_experiments_suite.py --experiments all --max-samples 3000 --rl-events 50
  mark "SUPP_EXPERIMENTS_DONE"
fi

# ── 6. 延迟基准（预热） ──────────────────────────────────────────
if ! step_done "SUPP_LATENCY_DONE"; then
  echo "[6/9] benchmark_latency (warmup 200, iter 5000)..."
  if "$PY" scripts/benchmark_latency.py --warmup 200 --iterations 5000 \
    | tee "${LOG_DIR}/latency_warm.json"; then
    cp -f results/v2_exp4_latency.json "${LOG_DIR}/v2_exp4_latency_latest.json" 2>/dev/null || true
    mark "SUPP_LATENCY_DONE"
  else
    echo "  [WARN] 延迟未达标，结果已写入 results/v2_exp4_latency.json"
    mark "SUPP_LATENCY_PARTIAL"
  fi
fi

# ── 7. 并发压测 E4b ──────────────────────────────────────────────
if ! step_done "SUPP_STRESS_DONE"; then
  echo "[7/9] stress_test..."
  start_api_server || exit 1
  trap stop_api_server EXIT
  if "$PY" scripts/stress_test.py --workers 50 --requests 2000; then
    mark "SUPP_STRESS_DONE"
  else
    echo "  [WARN] 压测未通过，见 results/v2_exp4_stress.json"
    mark "SUPP_STRESS_PARTIAL"
  fi
  stop_api_server
  trap - EXIT
fi

# ── 8. 多模态消融（全量） ─────────────────────────────────────────
if ! step_done "SUPP_MULTIMODAL_DONE"; then
  echo "[8/9] compare_multimodal_full (n=19411)..."
  "$PY" scripts/compare_multimodal_full.py --max-samples 0
  mark "SUPP_MULTIMODAL_DONE"
fi

# ── 9. 全量复评 E1 ───────────────────────────────────────────────
if ! step_done "SUPP_EVAL_DONE"; then
  echo "[9/9] evaluate 全量 n=19411..."
  "$PY" scripts/evaluate.py --data data/master/test_obfuscated.csv
  cp -f results/v2_exp1_overall.json "${LOG_DIR}/v2_exp1_overall_supplemental.json"
  mark "SUPP_EVAL_DONE"
fi

# ── 摘要 ─────────────────────────────────────────────────────────
"$PY" - <<'PY'
import json
from pathlib import Path

print("\n========== 补全流水线摘要 ==========")
for name, path in [
    ("E1 evaluate", "results/v2_exp1_overall.json"),
    ("E4 latency", "results/v2_exp4_latency.json"),
    ("E4b stress", "results/v2_exp4_stress.json"),
    ("E6 explain", "results/v2_exp6_localization.json"),
    ("E9 redteam", "results/v2_exp9_llm_redteam.json"),
    ("multimodal", "results/v2_compare_multimodal_full.json"),
]:
    p = Path(path)
    if p.exists():
        d = json.loads(p.read_text(encoding="utf-8"))
        print(f"\n{name}:")
        if "obfuscated_attack_binary" in d:
            oa = d["obfuscated_attack_binary"]
            print(f"  混淆 Recall={oa.get('detection_recall')} FPR={d.get('normal_binary',{}).get('false_positive_rate')}")
        elif "p50_ms" in d:
            print(f"  P50={d.get('p50_ms')}ms P99={d.get('p99_ms')}ms pass={d.get('pass')}")
        elif "delta_iou" in d:
            print(f"  delta_iou={d.get('delta_iou')}")
        elif "passed" in d:
            print(f"  passed={d.get('passed')} pooled_recall={d.get('pooled_recall')}")
        elif "qps" in d:
            print(f"  QPS={d.get('qps')} error_rate={d.get('error_rate')}")
        else:
            print(f"  keys={list(d.keys())[:6]}")
    else:
        print(f"\n{name}: [MISSING] {path}")
PY

echo "SUPPLEMENTAL_ALL_DONE $(date)"
