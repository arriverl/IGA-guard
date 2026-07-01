# Agent 2 可运行方案（整合稿）

> 基于 Agent 1 文献 + 现有 IGA-Guard 2.0 代码 · Solution Integrator 输出

---

## 一、技术选型决策（ADR 摘要）

| 决策 | 选择 | 理由 | 备选 |
|------|------|------|------|
| 时序模型 | **DLinear** | 轻量、可解释、AAAI'23 验证 | Informer（过重） |
| 语义模型 | **TinyBERT 6L** | 短文本、可蒸馏、≤10ms | DistilRoBERTa |
| 融合方式 | **动态门控** | 规则强时跳 ML；双路加权 | 仅 XGBoost |
| 解释 | **WebSpotter + 模板 NL** | 字符高亮 + 运维可读 | 纯 SHAP |
| 框架 | Flask + Vue3 + ECharts | 决赛现场演示稳定 | FastAPI |

---

## 二、可运行实现（四阶段）

### 阶段 1：DLinear 真实时序窗（3 天）✅ 已完成

**目标**：同 IP 最近 T=16 条请求构成时序，输出 anomaly_score

| 步骤 | 文件 | 命令/验证 | 状态 |
|------|------|-----------|------|
| 1.1 时序缓存 | `src/iga_guard/collector/timeseries_buffer.py` | `pytest tests/test_timeseries_buffer.py` | ✅ |
| 1.2 增强 DLinear | `src/iga_guard/detector/dlinear_branch.py`（`encode_series` / `score_anomaly`） | 接入真实 `[T,F]` 矩阵 | ✅ |
| 1.3 主管道接入 | `src/iga_guard/pipeline.py`（`push` → `get_matrix` → `ts_matrix`） | 同 IP 连续请求可填满窗 | ✅ |
| 1.4 双路融合 | `src/iga_guard/detector/dual_track.py`（`predict(norm, ts_matrix=...)`） | DLinear 异常分占融合 20% | ✅ |
| 1.5 配置 | `configs/default.yaml` → `timeseries.window: 16`、`dlinear.seq_len: 16` | — | ✅ |

**验收**：低速率攻击序列 anomaly_score > 正常序列（`tests/test_timeseries_buffer.py::TestDLinearEncodeSeries::test_attack_sequence_higher_anomaly_than_normal`）

---

### 阶段 2：TinyBERT 微调与启用（5 天）✅ 已完成

| 步骤 | 文件 | 命令/验证 | 状态 |
|------|------|-----------|------|
| 2.1 依赖 | `requirements.txt` 加 transformers, torch | `pip install` | ✅ |
| 2.2 训练脚本 | `scripts/train_bert.py` | master 数据集 | ✅ |
| 2.3 推理 | `semantic_branch.py` 加载 `models/tinybert_waf/` | 门控 + 关键词回退 | ✅ |
| 2.4 配置 | `use_semantic_branch: true` | `configs/default.yaml` | ✅ |

**验收**：混淆子集二分类 Recall 持续优化中（`evaluate.py` 新增 binary 指标）

---

### 阶段 3：可解释高亮前端（3 天）✅ 已完成

| 步骤 | 文件/说明 | 验证 | 状态 |
|------|-----------|------|------|
| 3.1 API 返回 `highlight_html` | `pipeline.py` | ✅ | ✅ |
| 3.2 大屏渲染 | `dashboard.html` | ✅ | ✅ |
| 3.3 字段贡献条形图 | ECharts `field_contributions` | ✅ | ✅ |

---

### 阶段 4：创新点与实验闭环（1 周）

| 步骤 | 产出 |
|------|------|
| 4.1 跑 E1~E8 | `results/v2_exp*.json` |
| 4.2 写 `INNOVATION.md` 终稿 | 答辩用 |
| 4.3 作品报告 | 官网模板 |

---

## 三、模块映射表（论文 → 代码）

```
Zeng 2023 DLinear          → dlinear_branch.py + timeseries_buffer.py
Jiao 2019 TinyBERT         → semantic_branch.py + train_bert.py
WebSpotter 定位思想        → webspotter.py
赛题混淆生成器             → mutator.py + ast_mutator.py
赛题 ≤10ms                 → fusion_model 规则快路径 + 特征缓存
```

---

## 四、团队分工建议

| 成员 | Agent 角色 | 工程任务 |
|------|------------|----------|
| A | Agent 2 主笔 | 架构、DLinear 时序、集成 |
| B | Agent 1 辅助 | 文献、数据集、TinyBERT 训练 |
| C | — | 可解释前端、高亮组件 |
| D | — | 混淆生成、实验报告、答辩 PPT |

---

## 五、风险与缓解

| 风险 | 缓解 |
|------|------|
| TinyBERT CPU 超 10ms | INT8 量化 / 仅可疑请求走 BERT |
| DLinear 误报 CDN | 语义轨 Normal 置信度高时降权 |
| 数据不足 99.5% | CSIC + 自建 10 万混淆样本 |
