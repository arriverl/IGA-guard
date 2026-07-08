# IGA-Guard Dynamic Guard Final Report

## Topic Alignment

题目：针对混淆逃逸的 Web 攻击载荷动态检测与对抗方案。

本轮优化围绕动态检测闭环完成：

- 动态检测：在字段级检测之外新增聚合 query/body 动态 rescue，覆盖参数名畸形、CRLF/Set-Cookie 注入、嵌套 JSON 逃逸、编码 XSS burst、HPP/hex32 camouflage。
- 对抗方案：使用 LLM red-team 多轮生成与 `auto_evolve_round_misses.jsonl` 反馈，按 miss 模式持续补齐检测规则。
- 离线可靠性：默认开启 HuggingFace/Transformers 离线优先，SentenceTransformer 使用 `local_files_only=True`，避免镜像/联网 HEAD 重试影响评测。
- 可解释与补丁：保留 WebSpotter 定位和 E8 virtual patch 机制，形成检测、定位、补丁和红队验证闭环。

## Final Metrics

| Evaluation | Result | Status |
| --- | ---: | --- |
| Unit/smoke regression | 42 passed | Pass |
| 2k E1 dynamic guard | FPR 0.0432 / obf recall 0.9991 / multiclass acc 0.8380 | Pass |
| 4k E1 dynamic guard | FPR 0.0470 / obf recall 0.9981 / multiclass acc 0.8468 | Pass |
| Full E1 cache | FPR 0.0420 / obf recall 0.9965 / recall 0.8893 | Pass |
| Full E1 no-cache | FPR 0.0364 / obf recall 0.9925 / recall 0.8849 | Diagnostic |
| E9 LLM red-team 40 | pooled recall 1.0000 / final recall 1.0000 | Pass |
| E9 LLM red-team 80 | pooled recall 0.9683 / final recall 0.9057 | Pass |
| E4 latency final | P50 0.070ms / P95 28.499ms / P99 31.381ms | P50 pass; long-tail improved |
| E6 localization | span hit 1.0 / IoU 1.0 / improvement 0.3793 | Pass |
| E8 virtual patch | 20/20 blocked | Pass |

## Key Improvements

- 将 2k FPR 从约 0.0719 压到 0.0432，同时将混淆召回提升到 0.9991。
- 将 4k FPR 从约 0.0676 压到 0.0470，同时混淆召回保持 0.9981。
- E9 80 variants pooled recall 达到 0.9683，超过 0.95 目标。
- E4 P99 从旧结果约 106ms 降到 31.381ms；P50 继续满足 5ms 热路径目标。P95/P99 仍是长尾指标，应作为后续性能优化项继续跟踪。

## Remaining Risk

- no-cache 全量混淆召回为 0.9925，低于 0.995；cache 口径已通过。该差异说明持续缓存对长尾混淆样本仍有贡献。当前已加入 encoder mode/dim 校验，避免离线 fallback 时错误复用不兼容 cache。
- E9 80 的 final round recall 为 0.9057，pooled recall 已通过；若要求每轮都超过 0.95，需要继续对最新 round-3 miss 做规则泛化或增强 auto-evolve 的规则发现。

## Result Files

- `results/v2_exp1_iter_opt_2k_v21_dynamic_guard.json`
- `results/v2_exp1_iter_opt_4k_v21_dynamic_guard.json`
- `results/v2_exp1_overall_dynamic_guard_final.json`
- `results/v2_exp1_overall_dynamic_guard_final_nocache.json`
- `results/v2_exp9_dynamic_guard_40_v8.json`
- `results/v2_exp9_dynamic_guard_80_v1.json`
- `results/v2_exp4_latency.json`
- `results/v2_exp6_localization.json`
- `results/v2_exp8_virtual_patch.json`
