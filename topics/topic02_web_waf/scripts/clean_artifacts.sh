#!/usr/bin/env bash
# 选择性清理中间产物：保留最新/最全面版本，删除历史迭代快照。
# 用法: bash scripts/clean_artifacts.sh [--dry-run]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DRY=0
[[ "${1:-}" == "--dry-run" ]] && DRY=1

rm_safe() {
  for p in "$@"; do
    [[ -e "$p" ]] || continue
    if [[ "$DRY" -eq 1 ]]; then
      echo "[dry-run] rm -rf $p"
    else
      rm -rf "$p"
      echo "[removed] $p"
    fi
  done
}

cd "$ROOT"

echo "== TinyBERT: 保留 checkpoint-34380 + 根目录 model.safetensors =="
for ckpt in models/tinybert_waf/checkpoint-*; do
  [[ -d "$ckpt" ]] || continue
  base="$(basename "$ckpt")"
  [[ "$base" == "checkpoint-34380" ]] && continue
  rm_safe "$ckpt"
done

echo "== 日志: 保留训练/全量评测/延迟/对抗/可解释性主日志 =="
KEEP_LOGS=(
  train_bert_final.log
  train_bert_master.log
  eval_full_v3.log
  eval_full_master.log
  latency_full.log
  adversarial_full.log
  eval_explain_full.log
)
for f in logs/*; do
  [[ -f "$f" ]] || continue
  base="$(basename "$f")"
  keep=0
  for k in "${KEEP_LOGS[@]}"; do
    [[ "$base" == "$k" ]] && keep=1 && break
  done
  [[ "$keep" -eq 1 ]] || rm_safe "$f"
done

echo "== results: 保留 canonical + 最新迭代 v21/v22 =="
KEEP_RESULTS=(
  auto_verify_report.json
  auto_verify_report.md
  miss_analysis.json
  v2_exp1_auto_2k.json
  v2_exp1_auto_4k.json
  v2_exp1_auto_nocache_2k.json
  v2_exp1_overall.json
  v2_exp1_overall_dynamic_guard_final.json
  v2_exp1_overall_dynamic_guard_final_nocache.json
  v2_exp1_iter_opt_2k_v21_dynamic_guard.json
  v2_exp1_iter_opt_2k_v22_dynamic_guard.json
  v2_exp1_iter_opt_4k_v21_dynamic_guard.json
  v2_exp2_unknown.json
  v2_exp4_latency.json
  v2_exp4_stress.json
  v2_exp5_ablation.json
  v2_exp6_localization.json
  v2_exp7_evolution.json
  v2_exp8_virtual_patch.json
  v2_exp9_auto_40.json
  v2_exp9_auto_80.json
  v2_exp9_dynamic_guard_40_v8.json
  v2_exp9_dynamic_guard_80_v3.json
  v2_exp9_dynamic_guard_80_recheck.json
)
for f in results/v2_exp*.json; do
  [[ -f "$f" ]] || continue
  base="$(basename "$f")"
  keep=0
  for k in "${KEEP_RESULTS[@]}"; do
    [[ "$base" == "$k" ]] && keep=1 && break
  done
  [[ "$keep" -eq 1 ]] || rm_safe "$f"
done
rm_safe results/v2_exp4_latency_auto.json

echo "== data/cache eval 快照: 保留 v21/v22 + overall final =="
KEEP_EVAL=(
  eval_normal_fps.jsonl
  eval_obf_misses.jsonl
  eval_normal_fps_2k_v21_dynamic_guard.jsonl
  eval_normal_fps_2k_v22_dynamic_guard.jsonl
  eval_normal_fps_4k_v21_dynamic_guard.jsonl
  eval_normal_fps_overall_dynamic_guard_final.jsonl
  eval_normal_fps_overall_dynamic_guard_final_nocache.jsonl
  eval_obf_misses_2k_v21_dynamic_guard.jsonl
  eval_obf_misses_2k_v22_dynamic_guard.jsonl
  eval_obf_misses_4k_v21_dynamic_guard.jsonl
  eval_obf_misses_overall_dynamic_guard_final.jsonl
  eval_obf_misses_overall_dynamic_guard_final_nocache.jsonl
)
for f in data/cache/eval_*; do
  [[ -e "$f" ]] || continue
  base="$(basename "$f")"
  keep=0
  for k in "${KEEP_EVAL[@]}"; do
    [[ "$base" == "$k" ]] && keep=1 && break
  done
  [[ "$keep" -eq 1 ]] || rm_safe "$f"
done

echo "== 可再生成缓存 =="
rm_safe .pytest_cache data/cache/auto_verify_logs
find "$ROOT/src" "$ROOT/backend" "$ROOT/tests" -type d -name __pycache__ 2>/dev/null | while read -r d; do
  rm_safe "$d"
done

echo "== 重复 submission 副本（权威源: submission/） =="
rm_safe IGA-Guard3_submission IGA-Guard3_submission.zip _pack_staging

echo "完成。保留清单见 docs/ARTIFACTS.md"
