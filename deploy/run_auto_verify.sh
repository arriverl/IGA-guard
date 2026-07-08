#!/usr/bin/env bash
# IGA-Guard 全自动检验（单入口）
set -euo pipefail
DEPLOY="$(cd "$(dirname "$0")" && pwd)"
source "${DEPLOY}/setup_env.sh"

LOG_DIR="${DEPLOY}/logs"
mkdir -p "$LOG_DIR"
LOG="${LOG_DIR}/auto_verify.log"

cd "$WAF_ROOT"
exec > >(tee -a "$LOG") 2>&1

echo "=== IGA-Guard Auto Verify $(date) ==="
echo "WAF_ROOT=${WAF_ROOT}"

python scripts/run_auto_verify.py "$@"
RC=$?

echo "=== Auto Verify exit=${RC} $(date) ==="
exit "$RC"
