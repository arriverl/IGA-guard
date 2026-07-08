#!/usr/bin/env bash
# IGA-Guard VPS 即插即用 — 一键启动 API + Inline 代理
set -euo pipefail
DEPLOY="$(cd "$(dirname "$0")" && pwd)"
source "${DEPLOY}/setup_env.sh"

UPSTREAM="${IGA_UPSTREAM_URL:-http://127.0.0.1:3000}"
PROXY_MODE="${IGA_PROXY_MODE:-inline}"
API_PORT="${IGA_API_PORT:-5000}"
PROXY_PORT="${IGA_PROXY_PORT:-8080}"
PID_DIR="${DEPLOY}/pids"
LOG_DIR="${DEPLOY}/logs"
mkdir -p "$PID_DIR" "$LOG_DIR"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --upstream) UPSTREAM="$2"; shift 2 ;;
    --mode) PROXY_MODE="$2"; shift 2 ;;
    --api-port) API_PORT="$2"; shift 2 ;;
    --proxy-port) PROXY_PORT="$2"; shift 2 ;;
    --proxy-only) PROXY_ONLY=1; shift ;;
    --api-only) API_ONLY=1; shift ;;
    -h|--help)
      cat <<EOF
用法: $0 [选项]
  --upstream URL     后端应用地址 (默认 http://127.0.0.1:3000)
  --mode MODE        inline | detect-only | mirror
  --api-port PORT    管理 API/大屏端口 (默认 5000)
  --proxy-port PORT  流量代理端口 (默认 8080)
  --proxy-only       仅启动代理
  --api-only         仅启动 API
EOF
      exit 0 ;;
    *) echo "未知参数: $1" >&2; exit 1 ;;
  esac
done

export IGA_UPSTREAM_URL="$UPSTREAM"
export IGA_PROXY_MODE="$PROXY_MODE"
export IGA_CONFIG="${WAF_ROOT}/configs/proxy.yaml"

cd "$WAF_ROOT"

start_api() {
  if [[ -f "${PID_DIR}/iga_api.pid" ]] && kill -0 "$(cat "${PID_DIR}/iga_api.pid")" 2>/dev/null; then
    echo "[api] 已在运行 pid=$(cat "${PID_DIR}/iga_api.pid")"
    return
  fi
  echo "[api] 启动管理 API :${API_PORT} ..."
  IGA_CONFIG="${WAF_ROOT}/configs/default.yaml" \
    nohup python run.py >>"${LOG_DIR}/iga_api.log" 2>&1 &
  echo $! > "${PID_DIR}/iga_api.pid"
}

start_proxy() {
  if [[ -f "${PID_DIR}/iga_proxy.pid" ]] && kill -0 "$(cat "${PID_DIR}/iga_proxy.pid")" 2>/dev/null; then
    echo "[proxy] 已在运行 pid=$(cat "${PID_DIR}/iga_proxy.pid")"
    return
  fi
  echo "[proxy] 启动 inline 代理 :${PROXY_PORT} -> ${UPSTREAM} (mode=${PROXY_MODE})"
  export IGA_UPSTREAM_URL IGA_PROXY_MODE IGA_CONFIG
  # 临时覆盖 proxy.yaml 中的端口/upstream（通过环境变量）
  PROXY_PORT="$PROXY_PORT" python - <<'PY' > "${WAF_ROOT}/configs/proxy.runtime.yaml"
import os, yaml
from pathlib import Path
root = Path(os.environ["WAF_ROOT"])
base = yaml.safe_load((root / "configs/proxy.yaml").read_text())
base.setdefault("server", {})["port"] = int(os.environ.get("PROXY_PORT", "8080"))
base.setdefault("proxy", {})["upstream_url"] = os.environ.get("IGA_UPSTREAM_URL", "http://127.0.0.1:3000")
base.setdefault("proxy", {})["mode"] = os.environ.get("IGA_PROXY_MODE", "inline")
base["include"] = "default.yaml"
(root / "configs/proxy.runtime.yaml").write_text(yaml.dump(base, allow_unicode=True))
PY
  export IGA_CONFIG="${WAF_ROOT}/configs/proxy.runtime.yaml"
  nohup python run_proxy.py >>"${LOG_DIR}/iga_proxy.log" 2>&1 &
  echo $! > "${PID_DIR}/iga_proxy.pid"
}

if [[ "${API_ONLY:-0}" != "1" ]]; then
  start_proxy
fi
if [[ "${PROXY_ONLY:-0}" != "1" ]]; then
  start_api
fi

sleep 2
echo ""
echo "========== IGA-Guard VPS 就绪 =========="
echo "  流量入口:  http://<VPS-IP>:${PROXY_PORT}/"
echo "  健康检查:  http://<VPS-IP>:${PROXY_PORT}/_iga/health"
echo "  管理大屏:  http://<VPS-IP>:${API_PORT}/"
echo "  上游后端:  ${UPSTREAM}"
echo "  代理模式:  ${PROXY_MODE}"
echo ""
echo "公网部署建议:"
echo "  1. 防火墙放行 ${PROXY_PORT} (或 80/443)"
echo "  2. 运行: sudo ${DEPLOY}/install_vps.sh --nginx"
echo "  3. 将域名 A 记录指向 VPS IP"
echo "========================================"
