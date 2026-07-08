#!/usr/bin/env bash
# IGA-Guard 3.0 全量评测 + LLM/RAG/演化（对齐 qwen2.5:1.5b）
set -euo pipefail
DEPLOY="$(cd "$(dirname "$0")" && pwd)"
source "${DEPLOY}/setup_env.sh"

LOG_DIR="${DEPLOY}/logs"
PID_DIR="${DEPLOY}/pids"
MARKER_DIR="${LOG_DIR}/markers"
mkdir -p "$LOG_DIR" "$PID_DIR" "$MARKER_DIR"
LOG="${LOG_DIR}/eval_full.log"
LLM_MODEL="${IGA_LLM_MODEL:-qwen2.5:3b}"

# 用 marker 文件判步（避免对超大 eval_full.log 做 grep，曾导致误判/卡顿）
step_done() { [[ -f "${MARKER_DIR}/${1}" ]]; }
mark_step() {
  echo "$1"
  : >"${MARKER_DIR}/${1}"
}

# 从旧日志迁移已完成标记（一次性）
_migrate_markers_from_log() {
  local m
  for m in IGA_INSTALL_DONE IGA_STATUS_DONE IGA_OLLAMA_DONE IGA_RAG_DONE \
           IGA_EVAL_DONE IGA_LATENCY_DONE IGA_EVOLVE_DONE IGA_REEVAL_DONE \
           IGA_EVAL_FULL_DONE; do
    if ! step_done "$m" && grep -q "^${m}$" "$LOG" 2>/dev/null; then
      : >"${MARKER_DIR}/${m}"
    fi
  done
}
_migrate_markers_from_log

exec > >(tee -a "$LOG") 2>&1
echo "=== IGA-Guard 全量评测 $(date) ==="
echo "仓库: ${IGA_ROOT}"
echo "作品: ${WAF_ROOT}"
echo "LLM: ${LLM_MODEL}"
cd "$WAF_ROOT"

if ! step_done "IGA_INSTALL_DONE"; then
  echo "[1/8] 安装依赖..."
  pip install -r requirements.txt -q --root-user-action=ignore
  mark_step "IGA_INSTALL_DONE"
fi

if ! step_done "IGA_STATUS_DONE"; then
  echo "[2/8] 系统状态..."
  python scripts/iga_system.py status
  mark_step "IGA_STATUS_DONE"
fi

if ! step_done "IGA_OLLAMA_DONE"; then
  echo "[3/8] Ollama + ${LLM_MODEL}..."
  if command -v ollama >/dev/null && curl -sf http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    ollama list | grep -q "${LLM_MODEL}" || ollama pull "${LLM_MODEL}" || true
    python scripts/check_llm.py || echo "  [WARN] LLM 冒烟未通过，演化将回退规则"
  else
    echo "  Ollama 未运行，LLM 红队将回退 mutator/AST"
  fi
  mark_step "IGA_OLLAMA_DONE"
fi

if ! step_done "IGA_RAG_DONE"; then
  echo "[4/8] RAG 索引..."
  python scripts/rag_agent_cycle.py --build-index 2>/dev/null || python scripts/build_rag_index.py 2>/dev/null || true
  mark_step "IGA_RAG_DONE"
fi

if ! step_done "IGA_EVAL_DONE"; then
  echo "[5/8] 全量 evaluate n=19411..."
  python scripts/iga_system.py evaluate --max-samples 0
  cp -f results/v2_exp1_overall.json "${LOG_DIR}/v2_exp1_overall_latest.json" 2>/dev/null || true
  mark_step "IGA_EVAL_DONE"
fi

if ! step_done "IGA_LATENCY_DONE"; then
  echo "[6/8] 延迟基准..."
  python scripts/benchmark_latency.py 2>&1 | tee "${LOG_DIR}/latency.json" || true
  mark_step "IGA_LATENCY_DONE"
fi

if ! step_done "IGA_EVOLVE_DONE"; then
  echo "[7/8] LLM 红队 + RAG 演化..."
  EVOLVE_OK=1
  python scripts/auto_evolve.py --rounds 3 --max-variants 120 --use-llm || EVOLVE_OK=0
  python scripts/rag_agent_cycle.py --rounds 2 --max-variants 80 --use-llm || EVOLVE_OK=0
  python scripts/run_llm_redteam.py --rounds 3 --max-variants 100 || EVOLVE_OK=0
  if [[ "$EVOLVE_OK" -eq 1 ]]; then
    mark_step "IGA_EVOLVE_DONE"
  else
    echo "IGA_EVOLVE_FAILED"
  fi
fi

if ! step_done "IGA_REEVAL_DONE"; then
  echo "[8/8] 演化后复评..."
  python scripts/iga_system.py evaluate --max-samples 0
  cp -f results/v2_exp1_overall.json "${LOG_DIR}/v2_exp1_overall_post_evolve.json" 2>/dev/null || true
  mark_step "IGA_REEVAL_DONE"
fi

python - <<'PY'
import json
from pathlib import Path
p = Path("results/v2_exp1_overall.json")
if p.exists():
    d = json.loads(p.read_text())
    ob = d.get("overall_binary", {})
    nb = d.get("normal_binary", {})
    oa = d.get("obfuscated_attack_binary", {})
    print("\n========== 评测摘要 ==========")
    print(f"混淆 Recall: {oa.get('detection_recall', 'N/A')}")
    print(f"混淆 Precision: {oa.get('detection_precision', 'N/A')}")
    print(f"Normal FPR: {nb.get('false_positive_rate', 'N/A')} ({nb.get('fp', '?')} FP)")
    print(f"整体 F1: {ob.get('f1', 'N/A')}")
    print(f"P50 见: deploy/logs/latency.json")
PY

mark_step "IGA_EVAL_FULL_DONE"
touch "${PID_DIR}/iga_eval_full.done"
echo "完成时间: $(date)"
