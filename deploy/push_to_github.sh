#!/usr/bin/env bash
# 使用 GitHub Personal Access Token 推送当前分支
# 用法: GITHUB_TOKEN=ghp_xxx ./deploy/push_to_github.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "请设置 GITHUB_TOKEN 环境变量（需 repo 权限）" >&2
  echo "示例: GITHUB_TOKEN=ghp_xxx ./deploy/push_to_github.sh" >&2
  exit 1
fi

BRANCH="${1:-iga-latest-optimization-iteration}"
REMOTE="https://${GITHUB_TOKEN}@github.com/arriverl/IGA-guard.git"

echo "推送分支: ${BRANCH}"
git push "$REMOTE" "${BRANCH}:${BRANCH}"
echo "完成: https://github.com/arriverl/IGA-guard/tree/${BRANCH}"
