#!/usr/bin/env bash
set -euo pipefail
DEPLOY="$(cd "$(dirname "$0")" && pwd)"
chmod +x "${DEPLOY}/run_iga_optimize.sh"
command -v tmux >/dev/null || conda install -y -c conda-forge tmux

tmux kill-session -t iga_opt 2>/dev/null || true
tmux new-session -d -s iga_opt -n optimize \
  "bash ${DEPLOY}/run_iga_optimize.sh; echo ''; echo '=== IGA 优化验证结束 ==='; read"

echo "tmux iga_opt 已启动"
echo "  attach: tmux attach -t iga_opt"
echo "  log: tail -f ${DEPLOY}/logs/iga_optimize.log"
tmux ls
