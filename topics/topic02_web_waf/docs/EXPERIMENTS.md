# IGA-Guard 2.0 实验方案

## 核心指标对标

| 指标 | 2.0 目标 | 赛题基线 | 验证脚本 |
|------|----------|----------|----------|
| 混淆检出率 | **> 99.5%** | 高检出 | `scripts/evaluate.py` |
| 单次延迟 P99 | **< 5 ms** | ≤ 10 ms | `scripts/benchmark_latency.py` |
| 定位准确度提升 | **≥ +22%** | — | `scripts/eval_explainability.py` |
| 压测 QPS | **10 万级** | — | `scripts/stress_test.py` |

---

## E1：整体检测性能

**数据**：CSIC2010 真实底稿 + 程序合成混淆集（129k 训练语料）；评测 `test_obfuscated.csv` **全量 19,411 条**

**指标**：Macro-F1、各类 Recall、正常流量 FPR

**目标**：混淆子集 Recall > 99.5%

### E1 实测结果（`results/v2_exp1_overall.json`，2026-07-01 诚实口径）

| 子集 | 样本数 | Recall | Precision | FPR | 达标 |
|------|--------|--------|-----------|-----|------|
| 整体二分类 | 19,411 | **78.8%** | **99.0%** | 2.93% | — |
| 混淆子集 | 10,317 | **91.86%** | **100.0%** | — | ❌（目标 > 99.5%） |
| 正常流量 | 4,068 | — | — | **2.93%** | — |
| 多分类 Accuracy | 19,411 | 77.7% | — | — | — |

> **方法论说明**：此前 5k 抽样报告混淆 Recall 100% 为规则过宽 + 漏检覆盖训练所致；已收紧规则并改为全量评测。混淆子集仅含 `variant_type` 带 `obfuscation:` 标记的攻击样本。

## E2：未知混淆检测

**设置**：训练集不含 AST 混淆、UTF-7、Prompt Injection

**测试**：`ast_mutator.py` + `llm_agent.py` 生成零日样本

**对比**：IGA-Guard 1.0（仅规则+XGB）vs 2.0（双路+RL）

---

## E3：对抗鲁棒性（LLM Agent）

**流程**：

```
for round in 1..5:
    agent.generate_variants(failures)
    evaluate → collect misses → evolution.retrain()
```

**记录**：每轮 Recall、漏检类型分布

---

## E4：延迟与压力测试

### 4a 单请求延迟

- 预热 500 次
- 测试 50000 次
- 报告 mean / P50 / P95 / **P99**

### 4b 10 万 QPS 模拟 (`scripts/stress_test.py`)

- 多进程并发 POST `/api/detect`
- 持续 60s
- 记录吞吐量、错误率、P99 延迟

---

## E5：消融实验

| 配置 | 移除组件 |
|------|----------|
| Full 2.0 | — |
| w/o Normalizer | 跳过解混淆 |
| w/o DLinear | 仅语义轨 |
| w/o Semantic | 仅统计轨 |
| w/o RL-GWO | 全 100+ 特征 |
| w/o Dual-Track | 单路 XGBoost |

---

## E6：可解释性评估（Localization Accuracy）

**方法**：

1. 人工标注 100 条恶意片段 `[start, end)`
2. 模型输出 `token_range`
3. 计算 IoU / 字符级命中率
4. 对比 1.0 keyword 定位 vs 2.0 WebSpotter

**目标**：2.0 较 1.0 提升 ≥ 22%

**脚本**：`scripts/eval_explainability.py`

---

## E7：Online RL 增量演化

**流程**：

1. T0 基线评估
2. 注入 200 条 Agent 生成漏检样本
3. `online_rl.py` 调整阈值 + `self_train.py` 增量训练
4. T1/T2/T3 重测

---

## E8：虚拟补丁有效性

**数据**：公开 CVE Web 载荷（Log4j JNDI、Spring4Shell 等简化 POC）

**验证**：`virtual_patch.py` 生成规则后拦截率

---

## 结果目录

```
results/
├── v2_exp1_overall.json
├── v2_exp2_unknown.csv
├── v2_exp3_adversarial_rounds.csv
├── v2_exp4_latency.json
├── v2_exp4_stress.json
├── v2_exp5_ablation.csv
├── v2_exp6_localization.json
├── v2_exp7_evolution.json
└── v2_exp8_virtual_patch.json
```

---

## 可视化（ECharts 大屏数据源）

| API | 用途 |
|-----|------|
| `GET /api/stats` | 攻击类型饼图 |
| `GET /api/alerts` | 实时告警流 |
| `GET /api/evolution/history` | 演化曲线 |
| `GET /api/metrics/latency` | 延迟趋势 |
