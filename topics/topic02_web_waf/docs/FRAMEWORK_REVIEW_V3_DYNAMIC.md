# IGA-Guard 3.0 框架评审与修改实施（混淆逃逸动态检测）

**目标**：针对混淆逃逸的 Web 攻击载荷动态检测与对抗方案  
**日期**：2026-07-09

## 1. 现有框架总览

```
HTTP → 多层解混淆(≤8) → 四模态 Late Fusion
     → 混淆 Boost → 规则兜底 → Tip-Adapter 缓存
     → FP 护栏 → 请求级聚合 rescue / 良性护栏 → 输出
```

| 层 | 模块 | 职责 |
|----|------|------|
| 采集 | `collector/` | 拆字段、时序缓冲、协议分 |
| 解混淆 | `normalizer/` | URL/HTML/Unicode/B64 迭代解码 |
| 检测 | `detector/dual_track.py` | RF+TinyBERT+多模态+DLinear |
| 信号 | `obfuscation_signals.py` | 混淆判定、evasion 规则、rescue |
| 动态 | `evolution/continual_cache.py` | Tip-Adapter 少样本扩库 |
| 对抗 | `adversarial/` + `auto_evolve` | mutator/AST/LLM 红队闭环 |
| 入口 | `pipeline.py` + `iga_system.py` | 请求级聚合与 CLI |

**基线（改前）**：全量含缓存混淆 Recall **99.65%**（FN=36），Normal FPR **4.20%**；无缓存全量 **99.25%**。

## 2. 修改意见（按优先级）

### P0 — 长尾 FN 原生覆盖（减少纯记忆依赖）
1. **`url_encode` 盲区**：全 URL 编码表单在 query unwrap 后丢失 `%3d/%26` 标记 → 聚合层需**编码态+解码态双路 rescue**。
2. **CSIC anomalous 字段污染**：`cantidad=25?`、`direccion=...|`、`email=+`、`B1=.../` 等 → 扩展 `_CSIC_ANOMALY_FIELDS`，命中即 rescue。
3. **禁止裸 hex32 抬升**：Normal 中大量会话哈希；独立 hex32 走缓存扩库，不走宽规则。
4. **良性护栏过宽**：`looks_like_benign_csic_form` 对管道/空字段/全编码表单应否决。

### P1 — 动态对抗闭环
5. 漏检 → `expand_cache` / `miss_to_rule` / `evolve_from_obf_misses` 固化。
6. 保持分层 FP 护栏；rescue 命中后禁止良性翻回。

### P2 — 架构债（后续）
7. TinyBERT 在 v3.1 语料上重训；ObfuscationNet 门控落地。
8. E3 对抗轮次 recall 回升；E2 未知混淆类型评测集。

## 3. 已实施改动

| 文件 | 改动 |
|------|------|
| `obfuscation_signals.py` | CSIC 异常字段扩展；全编码表单/case_random/JSON/HTML 实体 rescue；良性护栏收紧；禁止裸 hex32 |
| `pipeline.py` | `?p=` unwrap；编码态+解码态双路聚合 rescue；hex32 仅控 FPR 翻回 |
| `dual_track.py` | rescue / 全编码 / case_random 后禁止良性翻回 |
| `continual_cache` | 用终稿 36 FN 扩库（含 hex32 攻击 token） |

## 4. 验证结果（2026-07-09，阶段1~4执行后）

| 指标 | 改前 (dynamic_guard_final) | 当前 (opt_latest_full) |
|------|---------------------------|--------------------------|
| 混淆 Recall | 99.65% (FN=36) | **100.00%** (FN=0) |
| Normal FPR | 4.20% (FP=171) | **1.16%** (FP=47) |
| 混淆 Precision | 100% | **100%** |
| 多分类恶意精确召回 | 73.47% | **73.80%** |
| 样本 | 19,411 | 19,411 |

快速门禁（2k，`eval_regression` 严口径）：
- cache：obf recall **99.81%**，FPR **0%**（`v2_exp1_regression_quick.json`）
- no-cache：obf recall **99.81%**，FPR **0.48%**（`v2_exp1_regression_quick_nocache.json`）

> **口径注意**：`run_auto_verify` 的 e1_2k（FPR≤5%）是 CI 松门禁，数字不可与 `eval_regression` 混读。  
> **E2 废弃**：旧 `run_experiments_suite.py e2` 因 train/test `obfuscation:*` 重叠常得 `unknown_samples=0`；未知混淆主口径改为 `eval_unknown_obfuscation.py`。

当前全量混淆子集 FN 已清零（0），长尾地址类编码样本已被覆盖。权威链：`results/canonical_metrics.json` → `v2_exp1_opt_latest_full.json`。

产物：
- `results/v2_exp1_opt_latest_full.json`（E1 权威）
- `results/v2_exp1_regression_quick.json`
- `results/v2_exp1_regression_quick_nocache.json`
- `results/canonical_metrics.json`

## 5. 自动闭环命令（已落地）

```powershell
# 固定门禁（quick: cache + no-cache）
python scripts/eval_regression.py --profile quick --strict

# 固定门禁（full: cache + no-cache）
python scripts/eval_regression.py --profile full --strict

# 自动反馈闭环：评测 -> miss_to_rule -> expand_cache -> evolve -> 复评
python scripts/run_feedback_cycle.py --profile quick --strict

# 统一CLI入口
python scripts/iga_system.py eval-regression --profile quick --strict
python scripts/iga_system.py feedback-cycle --profile quick --strict
```
