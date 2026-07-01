# 双 Agent 研究流水线

> 题目二：**DLinear 时序 + TinyBERT 语义 + 可解释高亮**  
> 通过两个 Agent 分工完成「文献调研 → 方案整合 → 可运行实现 → 创新凝练」

---

## 一、流水线总览

```
┌─────────────────────────────────────────────────────────────┐
│  Agent 1 · 情报研究员 (Research Scout)                      │
│  论文检索 · 开源项目 · 赛题对标 · 思路卡片提取              │
└──────────────────────────┬──────────────────────────────────┘
                           │ research/agent1_output/
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Agent 2 · 方案架构师 (Solution Integrator)                 │
│  整合提炼 · 可运行设计 · 模块接口 · 实验计划                │
└──────────────────────────┬──────────────────────────────────┘
                           │ research/agent2_output/
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  工程实现 + 创新点凝练 → IGA-Guard 2.0 代码与答辩材料      │
└─────────────────────────────────────────────────────────────┘
```

---

## 二、Agent 1：信息收集与论文整理

### 2.1 职责

| 任务 | 产出 |
|------|------|
| 检索 DLinear / 时序异常检测论文 | 思路卡片 |
| 检索 TinyBERT / Web 攻击检测 / WAF ML 论文 | 思路卡片 |
| 检索可解释性（SHAP、Attention、WebSpotter） | 思路卡片 |
| 整理开源数据集与基线（CSIC、CICIDS） | 数据清单 |
| 提取可迁移到本赛题的方法论 | `LITERATURE_REVIEW.md` |

### 2.2 检索关键词

```
DLinear time series anomaly detection HTTP traffic
TinyBERT text classification web attack SQL injection XSS
obfuscated payload detection machine learning WAF
explainable AI malicious payload localization
adversarial training web security 2024 2025 2026
```

### 2.3 输出目录

```
research/agent1_literature/
├── LITERATURE_REVIEW.md      # 主报告（已预填核心文献）
├── papers/                   # 单篇思路卡片
│   ├── 01_dlinear_aaai2023.md
│   ├── 02_tinybert_distillation.md
│   └── 03_web_attack_ml_survey.md
├── datasets.md               # 数据集清单
└── baselines.md              # 可对比基线
```

### 2.4 Agent 1 提示词模板

```
你是网络安全与 ML 方向的研究助理。任务：为「混淆逃逸 Web 攻击检测」赛题整理文献。

重点方向：
1. DLinear 及线性时序模型在流量/异常检测中的应用
2. TinyBERT/BERT 类小模型在 Payload 分类中的应用
3. 可解释 AI 在恶意流量定位中的应用
4. 对抗样本与混淆逃逸检测

对每篇论文输出：
- 核心方法（3 句话）
- 可借鉴点（针对本赛题）
- 局限性
- 是否可复现（开源代码/数据）

输出 Markdown，保存到 research/agent1_literature/papers/
```

---

## 三、Agent 2：整合提炼与可运行方案

### 3.1 职责

| 任务 | 产出 |
|------|------|
| 阅读 Agent 1 全部输出 | 技术选型决策表 |
| 将论文思路映射到 IGA-Guard 模块 | 模块设计补丁 |
| 提出 **可运行** 的最小实现路径 | `RUNNABLE_PLAN.md` |
| 定义实验与验收标准 | 对接 `docs/EXPERIMENTS.md` |
| 凝练 3~4 个创新点 | `INNOVATION.md` |

### 3.2 输出目录

```
research/agent2_integration/
├── RUNNABLE_PLAN.md          # 可运行方案（分阶段）
├── ARCHITECTURE_DECISIONS.md # 技术选型 ADR
├── MODULE_MAPPING.md         # 论文思路 → 代码模块
└── INNOVATION.md             # 创新点终稿
```

### 3.3 Agent 2 提示词模板

```
你是系统架构师。输入：Agent 1 的 LITERATURE_REVIEW.md 与思路卡片。

任务：
1. 整合 DLinear（时序轨）+ TinyBERT（语义轨）+ 可解释高亮的统一架构
2. 在现有 IGA-Guard 2.0 代码基础上，给出可运行的分阶段实现计划
3. 每个阶段须包含：改哪些文件、如何验证、预期指标
4. 提炼 4 个可写进作品报告的创新点（含与现有工作的差异）

约束：
- 单请求检测 ≤10ms（赛题硬指标）
- 须有可演示前端高亮
- 须有混淆载荷生成器（赛题要求）

输出 RUNNABLE_PLAN.md 与 INNOVATION.md
```

---

## 四、人机协作节奏（建议）

| 阶段 | 时间 | Agent 1 | Agent 2 | 人工 |
|------|------|---------|---------|------|
| 第 1 轮 | 2 天 | 完成文献综述 | — | 审核检索范围 |
| 第 2 轮 | 2 天 | 补充数据集/基线 | 读文献 → 出 RUNNABLE_PLAN | 确认技术路线 |
| 第 3 轮 | 1 周 | 跟踪新论文 | 模块映射 + 创新凝练 | 编码实现 |
| 第 4 轮 | 持续 | 实验数据支撑 | 更新方案 | 跑实验写报告 |

---

## 五、与现有代码的映射

| 研究结论 | 代码落点 | 状态 |
|----------|----------|------|
| DLinear 时序分解 | `detector/dlinear_branch.py` | 骨架 ✓ |
| TinyBERT 语义分类 | `detector/semantic_branch.py` | 待启用训练 |
| 双路融合 | `detector/dual_track.py` | MVP ✓ |
| WebSpotter 高亮 | `explainer/webspotter.py` + 大屏 | ✓ |
| NL 解释 | `explainer/nl_explanation.py` | 模板 ✓ |
| 混淆生成 | `adversarial/` | ✓ |
| 自演化 | `evolution/online_rl.py` | 骨架 ✓ |

---

## 六、验收清单（Agent 2 交付标准）

- [ ] `RUNNABLE_PLAN.md` 中每阶段有明确命令与预期输出
- [ ] `INNOVATION.md` 含 4 条创新点 + 对比表
- [ ] TinyBERT 微调脚本可跑通
- [ ] DLinear 输入为真实时序窗（非单条伪序列）
- [ ] 前端可对恶意 span 做颜色高亮
- [ ] 实验 E1~E8 有 `results/` 数据支撑
