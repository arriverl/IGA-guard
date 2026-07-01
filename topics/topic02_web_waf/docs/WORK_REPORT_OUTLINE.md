# IGA-Guard 2.0 竞赛作品报告提纲

> 符合赛题交付物要求：**系统设计 · 工程实现 · 测试验证 · 创新点**  
> 正式撰写时替换 `[待填]` 为实测数据，图表引用 `results/v2_exp*` 与 `frontend/static/dashboard.html` 截图

---

## 封面与摘要

| 项 | 内容 |
|----|------|
| 作品名称 | IGA-Guard 2.0：面向混淆逃逸攻击的可解释自演化 Web 安全防御系统 |
| 团队信息 | [待填] |
| 关键词 | Web 攻击检测 · 混淆逃逸 · DLinear · TinyBERT · 可解释 AI · 对抗演化 |
| 摘要（300 字） | [待填：问题背景 → 方法概述 → 核心指标 → 创新贡献] |

---

## 第一章 引言与赛题分析

### 1.1 研究背景
- Web 攻击与 WAF 演进；混淆逃逸（AST 拆分、多重编码、LLM 生成）成为新威胁
- 赛题要求：8 类攻击检测、混淆载荷生成器、≤10 ms 延迟、可解释输出

### 1.2 问题陈述
- 传统规则 WAF 对混淆载荷漏检率高
- 纯深度学习 WAF 延迟高、黑盒不可运维
- 静态模型无法防御持续演化的对抗样本

### 1.3 设计目标与指标

| 维度 | 目标值 | 赛题对齐 |
|------|--------|----------|
| 混淆检出率 | > 99.5% | 高强度混淆测试集 |
| 单次延迟 P99 | < 5 ms（内部）/ ≤ 10 ms（赛题） | 实时防护 |
| 定位准确度提升 | ≥ +22% IoU | 可解释性 |
| 攻击类型覆盖 | SQLi/XSS/CMD/LFI/RFI/XXE/Prompt Injection | 8 类 |

### 1.4 报告结构说明
- 第二~四章对应交付物：**设计 · 实现 · 测试**
- 第五章凝练**创新点**；第六~七章总结与附录

---

## 第二章 系统设计（交付物：设计）

### 2.1 总体架构
- 防御闭环：流量感知 → 解混淆 → RL 特征筛选 → 双路检测 → WebSpotter 定位 → 虚拟补丁 → Online RL 演化
- 架构图（引用 `docs/PROJECT.md` §2 双路引擎示意图）
- 技术栈：Flask API + Vue3/ECharts 大屏 + XGBoost/DLinear/TinyBERT

### 2.2 双路并行检测引擎（Dual-Track）
- **语义轨**：TinyBERT-6L，解混淆后 Payload 8 类分类
- **统计轨**：DLinear 时序分解，同 IP 最近 T=16 请求特征矩阵
- **融合门控**：规则强信号快路径 + 动态加权（`dual_track.py`）
- ADR 决策摘要（引用 `research/agent2_integration/ARCHITECTURE_DECISIONS.md`）

### 2.3 智能解混淆与特征工程
- `normalizer.py`：URL/Unicode/注释剥离
- `ast_mutator.py` / `mutator.py`：赛题要求的混淆生成器（正向 + 对抗）
- EnhancedRLGWO：100+ 维 → 12~15 维核心特征

### 2.4 可解释性模块（XAI）
- WebSpotter：字段贡献度 + 字符级 span + `highlight_html`
- 自然语言模板解释（`nl_explanation.py`）
- API 响应结构：`token_range`、`field_contributions`、`natural_language`

### 2.5 自演化对抗闭环
- LLM Attack Agent → 漏检收集 → `online_rl.py` 阈值调整 → `self_train.py` 增量训练
- 虚拟补丁：`virtual_patch.py` 对 CVE 载荷的规则生成

### 2.6 接口与部署设计
- REST API：`POST /api/detect`、`GET /api/stats`、`GET /api/alerts` 等
- 配置：`configs/default.yaml`（时序窗、语义轨开关、延迟目标）
- 一键启动：`python run.py`

---

## 第三章 工程实现（交付物：实现）

### 3.1 代码结构与模块映射

| 模块 | 路径 | 职责 |
|------|------|------|
| 主管道 | `src/iga_guard/pipeline.py` | 请求入队 → 检测 → 解释 → 报告 |
| 时序缓存 | `collector/timeseries_buffer.py` | 同 IP `[T,F]` 矩阵 |
| DLinear 轨 | `detector/dlinear_branch.py` | 异常分 `anomaly_score` |
| 语义轨 | `detector/semantic_branch.py` | TinyBERT 推理 |
| 融合 | `detector/dual_track.py` | 双路门控 |
| 解释 | `explainer/webspotter.py` | span 定位与高亮 |
| 演化 | `evolution/online_rl.py` | 在线阈值 RL |
| 前端 | `frontend/static/dashboard.html` | 六区块 ECharts 大屏 |

### 3.2 关键实现细节
- 阶段 1：DLinear 真实时序窗接入（`push` → `get_matrix` → `ts_matrix`）
- 阶段 2：TinyBERT 训练脚本 `scripts/train_bert.py`、模型目录 `models/tinybert_waf/`
- 阶段 3：`build_highlight_html` + 前端 `v-html` 红色 `<mark>` 高亮
- 赛题混淆生成器演示：`scripts/generate_dataset.py`

### 3.3 性能优化策略
- 规则早退（`_EARLY_EXIT_CONF`）
- 语义轨条件启用 / INT8 量化（规划中）
- 特征缓存与批量推理

### 3.4 可演示场景脚本
- SQLi：`union select` 高亮 + 中文判定
- 对抗演化：5 轮 Recall 曲线（E3 数据）
- 大屏：攻击分布饼图、延迟趋势、Online RL 演化柱图

---

## 第四章 测试与验证（交付物：测试）

### 4.1 测试方案概述
- 引用 `docs/EXPERIMENTS.md` 八组实验 E1~E8
- 数据集：CSIC2010 + 自建 10 万混淆样本（规划）
- 环境：[待填：OS、Python 版本、CPU/GPU]

### 4.2 功能测试
- 单元测试：`pytest tests/`（时序窗、DLinear 编码、管道集成）
- API 冒烟：`POST /api/detect` 正常/恶意样本
- 前端：恶意 span 可见高亮、告警流刷新

### 4.3 性能与指标测试

| 实验 | 内容 | 结果文件 | 关键结论 |
|------|------|----------|----------|
| E1 | 整体/混淆 Recall | `v2_exp1_overall.json` | 混淆 90%，未达 99.5% |
| E3 | 5 轮对抗 Recall | `v2_exp3_adversarial_rounds.csv` | R5 Recall 21.29% |
| E4 | 单请求延迟 | `v2_exp4_latency.json` | P50 0.55 ms，P99 27.28 ms |
| E6 | 定位 IoU | `v2_exp6_localization.json` | +37.93%，达标 |
| E2/E5/E7/E8 | [待测] | — | 阶段 4 补齐 |

### 4.4 对比实验
- v1 keyword vs v2 WebSpotter（E6）
- IGA-Guard 1.0 vs 2.0（E2/E5 消融，待测）
- 基线 WAF / 纯规则 / 纯 BERT 对比表（答辩用）

### 4.5 测试结论与风险
- 已达标：可解释性 IoU、规则快路径 P50
- 未达标：混淆 Recall、对抗鲁棒性、P99 长尾
- 风险与缓解（引用 `RUNNABLE_PLAN.md` §五）

---

## 第五章 创新点（交付物：创新）

> 详述见 `research/agent2_integration/INNOVATION.md`

### 5.1 创新点一：DLinear-TinyBERT 双流融合检测架构
- 问题：单一模型无法同时覆盖低速率逃逸与混淆语义
- 方法：时序轨 + 语义轨 + 动态门控
- 实验支撑：E5 消融（待测）、E1 当前 91.84% 整体 Recall
- 与现有工作差异对比表

### 5.2 创新点二：WebSpotter 式可解释恶意流量高亮
- 问题：黑盒判定无法定位恶意片段
- 方法：字段贡献 + 字符 span + 前端实时高亮
- 实验支撑：**E6 IoU +37.93%**（已达标）
- 演示截图：[待填]

### 5.3 创新点三：RL 智能特征工程
- 问题：高维特征带来延迟与过拟合
- 方法：EnhancedRLGWO 筛选 + Online RL 阈值调整
- 实验支撑：E5 + E7（待测）

### 5.4 创新点四：LLM Attack Agent 自演化对抗闭环
- 问题：静态模型难以防御未见混淆
- 方法：漏检 → 三重混淆生成 → 增量训练 → RL 调参
- 实验支撑：**E3 五轮数据已产出**（Recall 待提升）
- 赛题对齐：混淆载荷自动生成器

### 5.5 创新点总结语
> IGA-Guard 2.0 用 **DLinear 看流量节奏、TinyBERT 读攻击语义、WebSpotter 标恶意片段**，在可解释、可演示、可进化的工程闭环中实现混淆逃逸 Web 攻击的精准检测。

---

## 第六章 总结与展望

### 6.1 工作总结
- 完成阶段 1~3 核心工程（时序窗、BERT 脚本、高亮前端）
- 实验 4/8 项有数据，可解释性达标

### 6.2 不足与改进方向
- 启用 TinyBERT 语义轨，冲击 99.5% 混淆 Recall
- P99 长尾优化与 10 万 QPS 压测
- 补齐 E2/E5/E7/E8

### 6.3 应用前景
- 企业 WAF 旁路检测、SOC 告警解释、红蓝对抗演练

---

## 第七章 附录

| 附录 | 内容 |
|------|------|
| A | 参考文献（`research/agent1_literature/`） |
| B | 核心 API 说明与请求/响应示例 |
| C | 配置文件说明 `configs/default.yaml` |
| D | 实验原始数据清单 `results/v2_exp*` |
| E | 团队分工与 Git 提交记录 |
| F | 答辩演示脚本（3 分钟版） |

---

## 撰写检查清单

- [ ] 四类交付物章节齐全：设计(Ch2) · 实现(Ch3) · 测试(Ch4) · 创新(Ch5)
- [ ] 所有指标引用 `research/agent2_integration/EXPERIMENT_REPORT.md` 最新数据
- [ ] 架构图、大屏截图、对抗 Recall 折线图已插入
- [ ] 混淆生成器功能有截图/日志证明
- [ ] 创新点各附 1 组实验或对比表支撑
