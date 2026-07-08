#!/usr/bin/env bash
# 在 tmux 会话 iga 中运行 IGA-Guard 全量评测（SSH 断开不中断）
set -euo pipefail
DEPLOY="$(cd "$(dirname "$0")" && pwd)"
IGA_ROOT="$(dirname "$DEPLOY")"
chmod +x "${DEPLOY}/setup_env.sh" "${DEPLOY}/run_eval_full.sh"

command -v tmux >/dev/null || conda install -y -c conda-forge tmux

# 停止旧 iga 会话
tmux kill-session -t iga 2>/dev/null || true
pkill -f "run_iga_upgrade.sh" 2>/dev/null || true
pkill -f "run_iga_tmux.sh" 2>/dev/null || true

tmux new-session -d -s iga -n eval \
  "bash ${DEPLOY}/run_eval_full.sh; echo ''; echo '完成。Enter 退出'; read"

echo "tmux 会话 iga 已启动"
echo "  进入: tmux attach -t iga"
echo "  日志: tail -f ${DEPLOY}/logs/eval_full.log"
tmux ls
