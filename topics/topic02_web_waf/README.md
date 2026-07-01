# IGA-Guard 2.0 — 面向混淆逃逸攻击的可解释自演化 Web 安全防御系统

> **IGA-Guard 2.0**: An Interpretable and Self-Evolving Web Security Defense System Against Obfuscated Evasion Attacks

## 2.0 核心升级

| 维度 | 1.0 | 2.0 |
|------|-----|-----|
| 架构 | XGBoost + 规则 | **Dual-Track**（TinyBERT + DLinear） |
| 攻击类型 | 6 类 | **8 类**（+XXE, PromptInjection） |
| 特征 | 固定 ~15 维 | **RL-GWO 动态筛选** 12~15/100+ |
| 解释 | 关键词热力图 | **WebSpotter + GPT 自然语言** |
| 演化 | 增量训练 | **Online RL + LLM Agent** |
| 延迟目标 | ≤10 ms | **< 5 ms** |
| 检出目标 | 高检出 | **> 99.5%** 混淆集 |
| 前端 | 单页监控 | **Vue3 + ECharts 6.0 六页大屏** |

完整设计：[`docs/PROJECT.md`](docs/PROJECT.md) · 技术路线：[`docs/TECHNICAL_APPROACH.md`](docs/TECHNICAL_APPROACH.md) · 双 Agent 研究：[`docs/MULTI_AGENT_RESEARCH.md`](docs/MULTI_AGENT_RESEARCH.md)

## 题目二核心思路

```
DLinear 流量时序分析  +  TinyBERT Payload 语义识别  +  可解释恶意高亮
        ↑                        ↑                           ↑
   Agent1 文献整理          Agent2 整合可运行方案          创新点凝练
```

| 文档 | 说明 |
|------|------|
| `research/agent1_literature/` | Agent 1：论文与数据集 |
| `research/agent2_integration/` | Agent 2：可运行方案与创新点 |

### 2.0 实测指标

| 指标 | 目标 | 当前（诚实口径） |
|------|------|------------------|
| 延迟 P50 | < 5 ms | **~2.92 ms** ✓（E4，1000 次） |
| 延迟 P99 | ≤ 10 ms | **~27.4 ms** ✗（语义轨长尾） |
| 定位 IoU 提升 | ≥ +22% | **+37.9%** ✓（E6） |
| 混淆检出率 | > 99.5% | **91.86%**（E1 全量）· 距目标差 7.6 pp |
| 多模态消融 Δ | 检出损失可控 | **−0.12 pp**（92.17% vs 92.05%，条件融合优化已完成） |

> **P0 进行中**：TinyBERT 全量 133k × 5 epoch 重训，目标冲击 99.5% 混淆 Recall。E2/E5/E7/E8 脚本已就绪，待批量执行。

---

## 快速开始

```powershell
cd d:\Code_development\gitproduct\caisa_contest_2026\topics\topic02_web_waf
pip install -r requirements.txt
python scripts/generate_dataset.py
python scripts/train.py --data data/samples/obfuscated_dataset.csv
python scripts/evaluate.py --data data/samples/obfuscated_dataset.csv
python scripts/eval_explainability.py
python scripts/benchmark_latency.py
python run.py
# 大屏: http://127.0.0.1:5000/static/dashboard.html
```

---

## 四大创新点（2026 一等奖）

1. **DLinear-Transformer 混合时序语义检测架构**
2. **GPT 驱动交互式恶意载荷语义解释**
3. **面向加密流量的 RL 智能特征工程（EnhancedRLGWO）**
4. **LLM Attack Agent 持续性对抗训练闭环**

---

## 模块索引

| 模块 | 路径 |
|------|------|
| 双路检测引擎 | `src/iga_guard/detector/dual_track.py` |
| DLinear 统计轨 | `src/iga_guard/detector/dlinear_branch.py` |
| 语义轨 | `src/iga_guard/detector/semantic_branch.py` |
| RL 特征筛选 | `src/iga_guard/features/rl_gwo_selector.py` |
| WebSpotter 定位 | `src/iga_guard/explainer/webspotter.py` |
| GPT 语义解释 | `src/iga_guard/explainer/nl_explanation.py` |
| AST 混淆生成 | `src/iga_guard/adversarial/ast_mutator.py` |
| Online RL | `src/iga_guard/evolution/online_rl.py` |
| 虚拟补丁 | `src/iga_guard/rules/virtual_patch.py` |
| 全协议采集 | `src/iga_guard/collector/protocol.py` |
