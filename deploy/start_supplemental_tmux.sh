#!/usr/bin/env bash
# tmux 中续跑 IGA 补全流水线（SSH 断开不中断）
set -euo pipefail
DEPLOY="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=setup_env.sh
source "${DEPLOY}/setup_env.sh"

command -v tmux >/dev/null || conda install -y -c conda-forge tmux

LOG="${DEPLOY}/logs/supplemental.log"
mkdir -p "${DEPLOY}/logs"

# 清除上次无效标记，强制重跑步骤 6-9
for marker in SUPP_LATENCY_DONE SUPP_STRESS_DONE SUPP_MULTIMODAL_DONE SUPP_EVAL_DONE; do
  if [[ -f "$LOG" ]]; then
    sed -i "/^${marker}$/d" "$LOG"
  fi
done

tmux kill-session -t iga 2>/dev/null || true

tmux new-session -d -s iga -n supplemental \
  "bash ${DEPLOY}/run_supplemental.sh; echo ''; echo '=== IGA 补全结束 $(date) ==='; echo 'Enter 退出'; read"

echo "tmux 会话 iga 已启动（补全流水线 6-9 步）"
echo "  进入: tmux attach -t iga"
echo "  日志: tail -f ${LOG}"
tmux ls
