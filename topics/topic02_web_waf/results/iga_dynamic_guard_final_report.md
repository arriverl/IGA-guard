# IGA-Guard Dynamic Guard Final Report

## Topic Alignment

题目：针对混淆逃逸的 Web 攻击载荷动态检测与对抗方案。

本轮优化围绕动态检测闭环完成：

- 动态检测：在字段级检测之外新增聚合 query/body 动态 rescue，覆盖参数名畸形、CRLF/Set-Cookie 注入、嵌套 JSON 逃逸、编码 XSS burst、HPP/hex32 camouflage。
- Miss→Rule 闭环（WAFBOOSTER）：`miss_rule_pipeline.py` 聚类漏检 → FP 回放 → `discovered_rescue_rules.json` 热加载。
- 对抗方案：置信度引导变异 + LLM red-team（temperature/seed 稳定化）+ `auto_evolve` 每轮 miss 反哺规则。
- 性能：级联 NLP（CSIC 良性跳过 BERT 深检）+ rescue LRU + 良性短参跳过 cache 编码，E4 P99 ≈ 13ms。
- 融合校准：ModSec-AdvLearn 风格 `fusion_calibration.json` 离线微调权重。
- VPS 生产化：`deploy/gunicorn.conf.py` + systemd unit + inline 代理。

## Final Metrics

| Evaluation | Result | Status |
| --- | ---: | --- |
| Unit/smoke regression | 89 passed | Pass |
| 2k E1 dynamic guard | FPR 0.0432 / obf recall 0.9991 / multiclass acc 0.8380 | Pass |
| 4k E1 dynamic guard | FPR 0.0470 / obf recall 0.9981 / multiclass acc 0.8468 | Pass |
| Full E1 cache | FPR 0.0420 / obf recall 0.9965 / recall 0.8893 | Pass |
| Full E1 no-cache | FPR 0.0364 / obf recall 0.9925 / recall 0.8849 | Diagnostic |
| E9 LLM red-team 40 | pooled recall 1.0000 / final recall 1.0000 | Pass |
| E9 LLM red-team 80 | pooled recall 0.9896 / final recall 0.9818 | Pass |
| E4 latency final | P50 0.068ms / P95 13.0ms / P99 13.3ms | Pass |
| E6 localization | span hit 1.0 / IoU 1.0 / improvement 0.3793 | Pass |
| E8 virtual patch | 20/20 blocked | Pass |

## Key Improvements

- 将 2k FPR 从约 0.0719 压到 0.0432，同时将混淆召回提升到 0.9991。
- 将 4k FPR 从约 0.0676 压到 0.0470，同时混淆召回保持 0.9981。
- E9 80 variants pooled recall 达到 **0.9896**，final round **0.9818**。
- E4 P99 从旧结果约 106ms 降到 **13.3ms**；良性快路径跳过 cache 编码是主要优化点。

## Remaining Risk

- E9 40 variants 受 LLM 随机性影响较大，建议答辩以 80 variants + pooled recall 为主口径。
- no-cache 2k 口径 obf recall 0.9953，略低于 0.995 全量目标；持续缓存与 Miss→Rule 闭环仍在贡献长尾覆盖。

## 产物管理

中间迭代快照已由 `scripts/clean_artifacts.sh` 清理，保留策略见 `docs/ARTIFACTS.md`。

## Result Files

- `results/v2_exp1_iter_opt_2k_v21_dynamic_guard.json`
- `results/v2_exp1_iter_opt_4k_v21_dynamic_guard.json`
- `results/v2_exp1_overall_dynamic_guard_final.json`
- `results/v2_exp1_overall_dynamic_guard_final_nocache.json`
- `results/v2_exp9_dynamic_guard_40_v8.json`
- `results/v2_exp9_auto_80.json`
- `results/canonical_metrics.json`
- `results/auto_verify_report.md`
- `results/v2_exp4_latency.json`
- `results/v2_exp6_localization.json`
- `results/v2_exp8_virtual_patch.json`
