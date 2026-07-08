#!/usr/bin/env bash
# VPS 一键安装：依赖 + systemd + 可选 nginx
set -euo pipefail
DEPLOY="$(cd "$(dirname "$0")" && pwd)"
source "${DEPLOY}/setup_env.sh"

INSTALL_NGINX=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --nginx) INSTALL_NGINX=1; shift ;;
    -h|--help)
      echo "用法: $0 [--nginx]  # --nginx 安装 nginx 反代到 IGA 代理"
      exit 0 ;;
    *) echo "未知: $1"; exit 1 ;;
  esac
done

cd "$WAF_ROOT"
pip install -r requirements.txt gunicorn -q --root-user-action=ignore

mkdir -p "${DEPLOY}/pids" "${DEPLOY}/logs"

# systemd unit
UNIT="/etc/systemd/system/iga-guard-proxy.service"
if [[ -w /etc/systemd/system ]] || [[ $(id -u) -eq 0 ]]; then
  cat > "$UNIT" <<EOF
[Unit]
Description=IGA-Guard Inline WAF Proxy
After=network.target

[Service]
Type=simple
User=${SUDO_USER:-root}
WorkingDirectory=${WAF_ROOT}
Environment=PYTHONPATH=${WAF_ROOT}/src
Environment=IGA_CONFIG=${WAF_ROOT}/configs/proxy.yaml
Environment=IGA_UPSTREAM_URL=${IGA_UPSTREAM_URL:-http://127.0.0.1:3000}
Environment=IGA_PROXY_MODE=${IGA_PROXY_MODE:-inline}
ExecStart=$(command -v python3) ${WAF_ROOT}/run_proxy.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  echo "[systemd] 已写入 $UNIT"
  echo "  启用: sudo systemctl enable --now iga-guard-proxy"
fi

if [[ "$INSTALL_NGINX" -eq 1 ]]; then
  if command -v apt-get >/dev/null; then
    apt-get update -qq && apt-get install -y nginx
  elif command -v yum >/dev/null; then
    yum install -y nginx
  fi
  CONF="/etc/nginx/sites-available/iga-guard"
  if [[ -d /etc/nginx/sites-available ]]; then
    cp "${DEPLOY}/nginx/iga-guard.conf" "$CONF"
    ln -sf "$CONF" /etc/nginx/sites-enabled/iga-guard
    rm -f /etc/nginx/sites-enabled/default
  else
    cp "${DEPLOY}/nginx/iga-guard.conf" /etc/nginx/conf.d/iga-guard.conf
  fi
  nginx -t && systemctl reload nginx
  echo "[nginx] 已配置 :80 -> localhost:8080"
fi

echo "安装完成。启动: ${DEPLOY}/start_vps.sh --upstream http://127.0.0.1:3000"
