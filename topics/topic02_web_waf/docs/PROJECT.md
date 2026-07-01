# IGA-Guard 2.0 系统设计文档

> **中文**：IGA-Guard 2.0：面向混淆逃逸攻击的可解释自演化 Web 安全防御系统  
> **英文**：IGA-Guard 2.0: An Interpretable and Self-Evolving Web Security Defense System Against Obfuscated Evasion Attacks

**版本**：2.0 · 2026

---

## 一、总体设计目标

构建具备 **深度可解释性、自主对抗演化、超大规模实时适配** 能力的 Web 攻击检测系统。

| 维度 | 目标 |
|------|------|
| **检测覆盖** | SQLi · XSS · CMD · LFI/RFI · XXE · **LLM Prompt Injection** |
| **混淆检出率** | **> 99.5%**（高强度混淆测试集） |
| **单次延迟** | **< 5 ms** / HTTP 请求 |
| **解释准确度** | Localization Accuracy 较基线提升 **≥ 22%** |
| **演化能力** | 零日混淆样本自主适应 |

### 防御闭环

```
全协议流量感知 → 智能解混淆 → RL特征筛选 → 双路并行检测
    → WebSpotter定位 → GPT语义解释 → 规则/虚拟补丁 → 在线RL演化
```

---

## 二、核心架构（2026 科研成果融合）

### 2.1 双路并行检测引擎 (Dual-Track Engine)

```
                    ┌──────────────────┐
                    │  Normalized Payload │
                    └────────┬─────────┘
              ┌────────────────┴────────────────┐
              ▼                                 ▼
   ┌─────────────────────┐         ┌─────────────────────┐
   │ Semantic Track      │         │ Statistical Track   │
   │ TinyBERT-v2 /       │         │ DLinear 时序分解    │
   │ DistilRoBERTa       │         │ 熵波动·包间隔·频率  │
   │ 自注意力长程依赖    │         │ 低速率逃逸检测      │
   └──────────┬──────────┘         └──────────┬──────────┘
              └────────────────┬────────────────┘
                               ▼
                    ┌─────────────────────┐
                    │ Feature Fusion Gate │
                    │ + Rule Prior        │
                    └─────────────────────┘
```

| 分支 | 技术 | 作用 |
|------|------|------|
| 语义轨 | TinyBERT-v2 / DistilRoBERTa | 捕获混淆逻辑与长程依赖 |
| 统计轨 | DLinear 分解-线性 | 时序熵波动、请求间隔异常 |
| 融合 | 动态权重门控 | 根据分支置信度自适应加权 |

**实现**：`src/iga_guard/detector/dual_track.py`

---

### 2.2 深度可解释性模块 (XAI)

| 组件 | 技术 | 输出 |
|------|------|------|
| **WebSpotter 2026** | 字段贡献度权重 + 字符级定位 | `token_range`、热力图 |
| **GPT 语义解释** | 本地小模型 / API 可选 | 自然语言判定报告 |

示例解释：

> 此请求因在 **Cookie** 字段包含经过 **双重 URL 编码** 的 SQL 联表查询（`union select`）而被判定为 **高危 SQLi**。

**实现**：`src/iga_guard/explainer/webspotter.py`、`nl_explanation.py`

---

### 2.3 自演化对抗防御闭环

```
LLM Attack Agent → AST/逻辑混淆变种 → 检测评估
        ↑                                    ↓
   阈值/权重调整 ← Online RL ← 漏检样本缓存
```

| 组件 | 说明 |
|------|------|
| Adversarial Agent | Qwen/DeepSeek 生成零日混淆 |
| AST Mutator | 逻辑拆分、等价语句替换 |
| Online RL | 自动调整检测阈值与特征权重 |

**实现**：`src/iga_guard/evolution/online_rl.py`、`adversarial/ast_mutator.py`

---

## 三、系统功能模块

### 模块 1：全协议流量感知与预处理

| 协议 | 支持状态 |
|------|----------|
| HTTP/1.1 | ✅ 已实现 |
| HTTP/2 | 🔶 帧解析骨架 |
| HTTP/3 (QUIC) | 🔶 日志适配骨架 |
| WebSockets | 🔶 消息载荷提取骨架 |

**智能解混淆**：多层递归解码 + AST 语义恢复（同 1.0，增强 UTF-7/双重编码链追踪）

**实现**：`collector/protocol.py`、`normalizer/`

---

### 模块 2：多维特征工程（RL 驱动）

**EnhancedRLGWO 特征筛选**：从 100+ 维候选特征中动态筛选 **12~15** 个核心特征，降低推理开销。

| 特征族 | 示例 |
|--------|------|
| 统计 | 熵、编码比、特殊字符比 |
| 语义 | SQLi/XSS/XXE/Prompt 关键词 |
| 结构 | Payload AST 深度、HTML DOM 节点数 |
| 时序 | DLinear 趋势/季节分量 |

**实现**：`features/rl_gwo_selector.py`、`features/structural.py`

---

### 模块 3：自适应 WAF 规则联动

- 自动正则生成 → ModSecurity / Suricata
- **虚拟补丁 (Virtual Patching)**：新 CVE 载荷 → 临时策略 → 云端 WAF 推送接口

**实现**：`rules/generator.py`、`rules/virtual_patch.py`

---

## 四、2026 特色创新点（一等奖核心竞争力）

### 创新点 1：DLinear-Transformer 混合时序语义检测架构

突破传统 DL 在高频 Web 流量下计算开销大、长序列遗忘的问题；统计轨 DLinear 处理时序，语义轨 Transformer 处理 Payload 语义。

### 创新点 2：GPT 驱动交互式恶意载荷语义解释

将黑盒判定转为白盒可读报告，降低安全运维专业门槛；支持中英双语解释模板 + 可选本地 LLM。

### 创新点 3：面向加密流量与复杂协议的 RL 智能特征工程

在 DoH/HTTPS 等仅能获取统计特征的场景，通过 EnhancedRLGWO 筛选鲁棒特征，识别隐蔽混淆。

### 创新点 4：LLM Attack Agent 持续性对抗训练闭环

防御系统自主进化，可应对从未见过的零日混淆手段。

---

## 五、攻击类型覆盖

| 标签 | 说明 | 2.0 新增 |
|------|------|----------|
| Normal | 正常流量 | |
| SQLi | SQL 注入 | |
| XSS | 跨站脚本 | |
| CMD | 命令注入 | |
| PathTraversal | 路径遍历 | |
| FileInclusion | LFI/RFI | |
| XXE | XML 外部实体 | ✅ |
| PromptInjection | LLM 提示词注入 | ✅ |

---

## 六、前端大屏（Vue3 + ECharts 6.0）

| 页面 | 内容 |
|------|------|
| P1 监控大屏 | 实时攻击拓扑、QPS、告警流 |
| P2 攻击详情 | 请求全链路、解码链 |
| P3 载荷定位 | WebSpotter 热力图 |
| P4 风险热力图 | ECharts 攻击类型分布 |
| P5 模型演化 | 自演化曲线、阈值变化 |
| P6 规则中心 | 自动生成规则、虚拟补丁 |

**路径**：`frontend/static/dashboard.html`

---

## 七、实验设计

| 实验 | 目的 | 关键指标 |
|------|------|----------|
| E1 整体性能 | Precision/Recall/F1 | 混淆检出 >99.5% |
| E2 未知混淆 | 零日变种 | Recall |
| E3 对抗鲁棒 | LLM Agent 高强度混淆 | 漏检率 |
| E4 延迟压测 | 10 万级 QPS 模拟 | P99 < 5ms |
| E5 消融 | 净化/DLinear/RL/双路 | ΔF1 |
| E6 可解释性 | Localization Accuracy | +22% |
| E7 增量演化 | Online RL 3 轮 | Recall 提升 |
| E8 虚拟补丁 | CVE 载荷拦截 | 拦截率 |

详见 [`EXPERIMENTS.md`](EXPERIMENTS.md)。

---

## 八、目录结构（2.0）

```
topic02_web_waf/
├── src/iga_guard/
│   ├── collector/          # M1 全协议
│   ├── normalizer/         # 解混淆
│   ├── features/           # RL-GWO + 结构特征
│   ├── detector/
│   │   ├── dual_track.py   # 双路引擎 ★
│   │   ├── semantic_branch.py
│   │   ├── dlinear_branch.py
│   │   └── fusion_model.py
│   ├── explainer/
│   │   ├── webspotter.py   # 精确定位 ★
│   │   └── nl_explanation.py  # GPT解释 ★
│   ├── adversarial/
│   │   ├── ast_mutator.py  # AST混淆 ★
│   │   └── llm_agent.py
│   ├── evolution/
│   │   ├── online_rl.py    # 在线RL ★
│   │   └── self_train.py
│   └── rules/
│       ├── generator.py
│       └── virtual_patch.py  # 虚拟补丁 ★
├── frontend/static/dashboard.html
└── docs/PROJECT.md
```

---

## 九、里程碑（至 2026-08-02）

| 周 | 2.0 交付 |
|----|----------|
| W1 | 双路引擎 MVP + RL 特征筛选 |
| W2 | WebSpotter + NL 解释 + XXE/Prompt 标签 |
| W3 | LLM Agent + AST Mutator + 10万样本 |
| W4 | Online RL + 虚拟补丁 + <5ms 优化 |
| W5 | ECharts 六页大屏 + 八组实验 + 答辩材料 |

---

## 十、与赛题要求映射

| 赛题要求 | IGA-Guard 2.0 |
|----------|---------------|
| 载荷净化与特征提取 | M1 + M2 + RL-GWO |
| 对抗性检测模型 | Dual-Track Engine |
| 混淆载荷生成器 | AST Mutator + LLM Agent |
| 检测耗时 | 目标 <5ms（赛题 ≤10ms） |
| 可解释性 | WebSpotter + GPT NL |
