#!/usr/bin/env bash
# IGA-Guard 部署镜像配置
IGA_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUTODL_TMP="$(dirname "$IGA_ROOT")"

# 兼容 IGA-Guard/IGA-guard 嵌套克隆
if [ -d "${IGA_ROOT}/IGA-guard/topics/topic02_web_waf" ]; then
  REPO_ROOT="${IGA_ROOT}/IGA-guard"
elif [ -d "${IGA_ROOT}/topics/topic02_web_waf" ]; then
  REPO_ROOT="${IGA_ROOT}"
else
  echo "[!] 未找到 topic02_web_waf，请检查仓库路径" >&2
  exit 1
fi

export IGA_ROOT REPO_ROOT
export WAF_ROOT="${REPO_ROOT}/topics/topic02_web_waf"
export PYTHONPATH="${WAF_ROOT}/src:${PYTHONPATH:-}"

# GitHub 镜像
git config --global url."https://ghproxy.net/https://github.com/".insteadOf "https://github.com/" 2>/dev/null || true

# HuggingFace / pip
export HF_ENDPOINT="${HF_ENDPOINT:-https://hf-mirror.com}"
export HF_HOME="${HF_HOME:-${AUTODL_TMP}/hf_cache}"
export HF_HUB_DISABLE_XET=1
export HF_HUB_ENABLE_HF_TRANSFER=0
mkdir -p "$HF_HOME"
export PIP_INDEX_URL="${PIP_INDEX_URL:-https://pypi.tuna.tsinghua.edu.cn/simple}"
export PIP_ROOT_USER_ACTION="${PIP_ROOT_USER_ACTION:-ignore}"
export TRANSFORMERS_NO_ADVISORY_WARNINGS="${TRANSFORMERS_NO_ADVISORY_WARNINGS:-1}"

# Ollama 优化：单模型驻留 VRAM，限制 KV（具体 num_ctx 由 llm_client 传参）
export IGA_LLM_MODEL="${IGA_LLM_MODEL:-qwen2.5:3b}"
export OLLAMA_MAX_LOADED_MODELS="${OLLAMA_MAX_LOADED_MODELS:-1}"
export OLLAMA_KEEP_ALIVE="${OLLAMA_KEEP_ALIVE:-15m}"

# VPS 流量转发
export IGA_UPSTREAM_URL="${IGA_UPSTREAM_URL:-http://127.0.0.1:3000}"
export IGA_PROXY_MODE="${IGA_PROXY_MODE:-inline}"
export IGA_PROXY_PORT="${IGA_PROXY_PORT:-8080}"
export IGA_API_PORT="${IGA_API_PORT:-5000}"
