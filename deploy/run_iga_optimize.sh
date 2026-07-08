#!/usr/bin/env bash
# IGA 优化验证（CPU 模式，不与 CHASM 抢 GPU）— tmux 会话 iga_opt
set -euo pipefail
DEPLOY="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=setup_env.sh
source "${DEPLOY}/setup_env.sh"

LOG_DIR="${DEPLOY}/logs"
mkdir -p "$LOG_DIR"
LOG="${LOG_DIR}/iga_optimize.log"
CFG="${WAF_ROOT}/configs/eval_cpu.yaml"

exec > >(tee -a "$LOG") 2>&1
echo "=== IGA 优化验证 $(date) ==="
echo "WAF_ROOT=${WAF_ROOT} CONFIG=${CFG}"
cd "$WAF_ROOT"
export IGA_CONFIG="${CFG}"

PY="${PY:-python}"

echo "[1] pytest..."
PYTHONPATH="${WAF_ROOT}/src" "$PY" -m pytest tests/test_obfuscation_rescue.py tests/test_pipeline_smoke.py -q --tb=short

echo "[2] HPP 传输层回归（auto_evolve 历史漏检样本）..."
"$PY" - <<'PY'
import json
from pathlib import Path
from iga_guard import IgaGuardEngine
from iga_guard.eval_transport import build_eval_request
from iga_guard.pipeline import load_config

root = Path(".")
cfg = load_config(root / "configs/eval_cpu.yaml")
engine = IgaGuardEngine(cfg)
fail_path = root / "data/cache/auto_evolve_failures.jsonl"
if not fail_path.exists():
    print("  skip: no failures file")
    raise SystemExit(0)

fixed = 0
total = 0
for line in fail_path.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    row = json.loads(line)
    payload = row.get("payload", "")
    label = row.get("true_label", "XSS")
    if not payload:
        continue
    total += 1
    method, url, body = build_eval_request(payload, base_url="http://auto.local/test")
    report = engine.analyze_url(method, url, body=body, explain=False)
    hit = report.detection.is_malicious or report.detection.label == label
    if hit:
        fixed += 1

print(f"  HPP failures replay: {fixed}/{total} detected ({fixed/max(total,1):.1%})")
PY

echo "[3] E9 红队快测 (2 rounds, max 40, CPU)..."
if curl -sf http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
  OLLAMA_NUM_GPU=0 "$PY" scripts/run_llm_redteam.py \
    --rounds 2 --max-variants 40 --output results/v2_exp9_redteam_opt.json \
    || echo "  [WARN] E9 快测未达 95%，见 results/v2_exp9_redteam_opt.json"
else
  echo "  skip: Ollama 未运行"
fi

echo "[4] E8 虚拟补丁..."
"$PY" scripts/run_experiments_suite.py --experiments e8

echo "IGA_OPTIMIZE_DONE $(date)"
