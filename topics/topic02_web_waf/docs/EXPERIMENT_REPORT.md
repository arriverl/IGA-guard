# IGA-Guard 2.0 实验报告（草稿）

> Agent 2 第二轮 · 基于 `results/v2_*.json` 与 [`EXPERIMENTS.md`](EXPERIMENTS.md)  
> 生成日期：2026-06-30 · 状态：**部分达标，待阶段 2~4 补齐**

---

## 1. 实验概述

本轮已完成阶段 1（DLinear 时序窗接入）并跑通部分 E1 / E4 / E6 基准脚本，产出 3 份 v2 结果文件。E2、E3、E5、E7、E8 尚未执行，报告中以「待测」标注。

| 实验编号 | 名称 | 结果文件 | 状态 |
|----------|------|----------|------|
| E1 | 整体检测性能 | `results/v2_exp1_overall.json` | ✅ 已跑 |
| E2 | 未知混淆检测 | `results/v2_exp2_unknown.csv` | ⏳ 待测 |
| E3 | 对抗鲁棒性 | `results/v2_exp3_adversarial_rounds.csv` | ⏳ 待测 |
| E4 | 延迟与压力测试 | `results/v2_exp4_latency.json` | ✅ 已跑（仅 4a） |
| E5 | 消融实验 | `results/v2_exp5_ablation.csv` | ⏳ 待测 |
| E6 | 可解释性评估 | `results/v2_exp6_localization.json` | ✅ 已跑 |
| E7 | Online RL 演化 | `results/v2_exp7_evolution.json` | ⏳ 待测 |
| E8 | 虚拟补丁有效性 | `results/v2_exp8_virtual_patch.json` | ⏳ 待测 |

---

## 2. 核心指标对标

| 指标 | 2.0 目标 | 赛题基线 | 当前实测 | 达标 |
|------|----------|----------|----------|------|
| 混淆子集 Recall | **> 99.5%** | 高检出 | **90.0%**（E1, n=20） | ❌ |
| 整体 Recall（恶意） | — | — | 91.84%（E1, n=49） | — |
| 单次延迟 P99 | **< 5 ms** | ≤ 10 ms | **27.28 ms**（E4, n=50） | ❌ |
| 单次延迟 P50 | — | — | 0.55 ms | ✅ |
| 定位 IoU 提升 | **≥ +22%** | — | **+37.93%**（E6） | ✅ |
| 压测 10 万 QPS | 10 万级 | — | 未测 | ⏳ |

> **说明**：`v2_exp4_latency.json` 中 `pass: true` 与 P99 27.28 ms 矛盾，以下分析以 `EXPERIMENTS.md` 目标（P99 < 5 ms / 赛题 ≤ 10 ms）为准。

---

## 3. 分项实验结果

### E1：整体检测性能

**数据**：CSIC2010 + 自建混淆集（当前子集 49 条，其中混淆 20 条）

| 子集 | 样本数 | Accuracy | Recall（恶意） | 目标 | 达标 |
|------|--------|----------|----------------|------|------|
| 整体 | 49 | 0.9184 | 0.9184 | — | — |
| 混淆子集 | 20 | 0.9000 | **0.9000** | > 0.995 | ❌ |

**分析**：
- 混淆样本 Recall 距目标差 **9.5 个百分点**，是当前最大短板。
- 语义轨 `use_semantic_branch: false`（`configs/default.yaml`），TinyBERT 未启用，混淆载荷主要依赖规则 + DLinear 统计轨，检出上限受限。
- 样本量偏小（49 条），正式报告前需扩至完整 CSIC + 10 万混淆集。

### E4：延迟测试（4a 单请求）

**设置**：预热后 50 次迭代（正式方案为 50 000 次，当前为快速冒烟）

| 指标 | 实测 (ms) | 内部目标 | 赛题基线 | 达标 |
|------|-----------|----------|----------|------|
| Mean | 10.24 | — | — | — |
| P50 | 0.55 | — | — | ✅ |
| P95 | 26.13 | — | — | ❌ |
| P99 | **27.28** | < 5 | ≤ 10 | ❌ |
| Max | 27.66 | — | — | — |

**分析**：
- P50 极低说明规则快路径有效；P95/P99 长尾由冷启动、特征提取或偶发全路径推理拉高。
- 当前仅 50 次迭代，统计置信度不足；正式 benchmark 需 `benchmark_iterations: 50000`。
- 4b 压测（`stress_test.py`）尚未执行。

### E6：可解释性评估（Localization）

| 方法 | Span 命中率 | Mean IoU | 说明 |
|------|-------------|----------|------|
| v1 keyword | 1.000 | 0.725 | 基线关键词定位 |
| v2 WebSpotter | 1.000 | **1.000** | 字符级 span 定位 |

| 对比项 | 提升幅度 | 目标 | 达标 |
|--------|----------|------|------|
| Hit Rate Δ | 0.0% | — | — |
| IoU Δ | **+37.93%** | ≥ +22% | ✅ |

**分析**：WebSpotter 在 IoU 维度显著优于 v1 keyword，可解释性目标已达成；命中率两者均为 100%，区分度主要体现在 IoU 精度。

---

## 4. 未达标项汇总

| 优先级 | 指标 | 差距 | 根因假设 |
|--------|------|------|----------|
| **P0** | 混淆 Recall 90% → 99.5% | −9.5 pp | 语义轨未训练/未启用；混淆样本不足；DLinear 单独难以覆盖 AST/编码混淆 |
| **P1** | P99 27 ms → 5 ms | +22 ms | 长尾全路径推理；benchmark 样本过少；语义模型冷启动 |
| **P2** | E2~E5、E7~E8 缺失 | — | 实验脚本未批量执行 |
| **P3** | 压测 QPS 未验证 | — | `stress_test.py` 未跑 |

---

## 5. 改进计划

### 5.1 检测性能（对应阶段 2）

| 行动 | 负责模块 | 预期效果 |
|------|----------|----------|
| 执行 `scripts/train_bert.py`，启用 `use_semantic_branch: true` | `semantic_branch.py` | 混淆 Recall +5~8 pp |
| 扩充混淆集至 10 万条（`generate_dataset.py --variants 10`） | `adversarial/` | 覆盖 AST/UTF-7/LLM 变种 |
| 重跑 E1 全量评估 | `scripts/evaluate.py` | 获得可信 Macro-F1 / Recall |

### 5.2 延迟优化（对应阶段 1 收尾 + 配置调优）

| 行动 | 说明 |
|------|------|
| 规则早退阈值标定 | 当前 `_EARLY_EXIT_CONF=0.88`，可提高以减少全路径 |
| 语义轨按需触发 | 仅可疑请求（DLinear anomaly > τ）走 BERT |
| 正式 50k 次 benchmark | `scripts/benchmark_latency.py` |
| INT8 量化 TinyBERT | 目标 CPU P99 < 5 ms |

### 5.3 实验闭环（对应阶段 4）

```powershell
# 建议批量执行顺序
python scripts/evaluate.py --data data/samples/obfuscated_dataset.csv --out results/v2_exp1_overall.json
python scripts/benchmark_latency.py --iterations 50000 --out results/v2_exp4_latency.json
python scripts/stress_test.py --duration 60 --out results/v2_exp4_stress.json
python scripts/eval_explainability.py --out results/v2_exp6_localization.json
# E2/E3/E5/E7/E8 按 EXPERIMENTS.md 逐项补充
```

---

## 6. 结论（草稿）

1. **阶段 1 时序窗已落地**：`TimeSeriesBuffer` → `pipeline` → `DualTrackDetector` 链路贯通，DLinear 可接收真实 `[16, 6]` 特征矩阵。
2. **可解释性达标**：WebSpotter IoU 提升 37.93%，超过 22% 目标。
3. **检测与延迟未达标**：混淆 Recall 90%、P99 27 ms，需在阶段 2 启用语义轨并优化推理路径后方可冲击赛题指标。
4. **实验覆盖不足**：8 项实验中仅完成 3 项（部分），正式答辩前须补齐 E2~E5、E7~E8 及 E4 压测。

---

*本报告为 Agent 2 第二轮草稿，待全量实验与 TinyBERT 微调后更新终稿。*
