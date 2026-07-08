#!/usr/bin/env bash
# 按 V100S 32GB 服务器调研结果拉取/校验最优模型
set -euo pipefail
DEPLOY="$(cd "$(dirname "$0")" && pwd)"
source "${DEPLOY}/setup_env.sh"

LLM="${IGA_LLM_MODEL:-qwen2.5:3b}"
echo "=== IGA 最优模型部署 $(date) ==="
echo "WAF_ROOT=${WAF_ROOT}"
echo "目标 LLM: ${LLM}"

cd "$WAF_ROOT"
pip install -r requirements.txt -q --root-user-action=ignore

if command -v ollama >/dev/null; then
  if ! curl -sf http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    echo "[!] 启动 ollama serve..."
    ollama serve >/tmp/ollama_iga.log 2>&1 &
    sleep 3
  fi
  echo "[1] 拉取 Ollama ${LLM} (~1.9GB)..."
  ollama pull "${LLM}"
  echo "[2] LLM 冒烟..."
  python scripts/check_llm.py
else
  echo "[!] ollama 未安装，跳过 LLM"
fi

echo "[3] TinyBERT 权重检查..."
python - <<'PY'
from pathlib import Path
p = Path("models/tinybert_waf")
w = p / "model.safetensors"
ckpts = sorted(p.glob("checkpoint-*/model.safetensors"), key=lambda x: int(x.parent.name.split("-")[-1]))
print("  root weights:", w.exists())
print("  best checkpoint:", ckpts[-1].parent.name if ckpts else "none")
PY

echo "[4] RAG 索引（如需重建）..."
python scripts/build_rag_index.py 2>/dev/null || python scripts/rag_agent_cycle.py --build-index

echo "IGA_OPTIMAL_MODELS_DONE"
