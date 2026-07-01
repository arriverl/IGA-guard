# 题目二技术路线：DLinear + TinyBERT + 可解释性

> **IGA-Guard 2.0** 核心技术叙事 · 对应赛题「混淆逃逸 Web 攻击动态检测」

---

## 一、总体思路（一句话）

**用 DLinear 做 HTTP 流量时序异常感知，用 TinyBERT 做 Payload 深度语义识别，用 WebSpotter 式可解释模块做恶意片段高亮，经双 Agent 研究流水线整合为可运行系统并注入创新点。**

---

## 二、为什么需要「双模型」而不是单模型？

| 攻击手法 | 单看 Payload 语义 | 单看时序统计 | 融合后 |
|----------|-------------------|--------------|--------|
| URL 编码混淆 SQLi | TinyBERT 可识别 | 熵突变可辅助 | ✓ 高检出 |
| 低速率分片逃逸 | 单条 payload 看似正常 | DLinear 发现间隔/频率异常 | ✓ 补盲区 |
| AST/JS 混淆 XSS | 语义轨恢复后识别 | 请求频率正常 | ✓ 语义主导 |
| CDN 正常高流量 | 可能误报 | 时序模式稳定 | ✓ 统计轨降误报 |

赛题强调 **混淆逃逸** 与 **≤10ms 延迟**：DLinear 轻量（分解+线性），TinyBERT 可用蒸馏小模型，二者并行后融合，兼顾精度与速度。

---

## 三、模块 A：DLinear 网络流量时序分析

### 3.1 输入是什么？

不是原始 PCAP 全包，而是 **按时间窗聚合的 HTTP 请求统计序列**：

```
t=1..T: [QPS, 平均熵, 特殊字符比, 编码比, 非GET占比, 平均Payload长度, ...]
```

每个 **单条 HTTP 请求** 也可构造 **短序列**：同一会话/同源 IP 最近 N 条请求的特征向量，形成长度 T 的多元时序。

### 3.2 DLinear 做什么？

参考 Zeng et al. (2023) **Decomposition-Linear** 思想：

1. **趋势分量 (Trend)**：移动平均捕获请求率缓慢变化（如扫描前奏）
2. **季节/残差分量 (Seasonal/Residual)**：捕获突发异常（如瞬间大量高熵查询）

```
X_t = Trend_t + Seasonal_t
ŷ = Linear(Trend) + Linear(Seasonal)  →  anomaly_score
```

### 3.3 在 IGA-Guard 中的落点

- 代码：`src/iga_guard/detector/dlinear_branch.py`
- 输出：`anomaly_score` + 趋势斜率 + 残差能量
- 与语义轨融合权重：低速率逃逸场景 **提高 DLinear 权重**

### 3.4 待深化（Agent 1 文献任务）

- [ ] 时序窗长 T、移动平均窗口的消融
- [ ] 是否引入 Autoformer/FEDformer 作对比（答辩用）
- [ ] 加密流量（仅统计特征）场景下的可迁移性

---

## 四、模块 B：TinyBERT Payload 深度语义识别

### 4.1 输入是什么？

经 **多层解混淆** 后的 `normalized_payload`（URL 解码、HTML 实体、AST 还原后的字符串）。

### 4.2 TinyBERT 做什么？

- 模型：`huawei-noah/TinyBERT_6L_768` 或 `prajjwal1/bert-tiny`（可本地推理）
- 任务：序列分类（SQLi / XSS / CMD / … / Normal）或 **[CLS] 嵌入 + 轻量分类头**
- 与统计特征 **Feature Fusion**：`P_final = α·P_bert + (1-α)·P_xgb`

### 4.3 为何不用大模型？

- 赛题 **≤10ms**：TinyBERT INT8 量化后单条推理可达 1~3ms（GPU）/ 5~8ms（CPU）
- 混淆 payload 多为 **短文本**，小模型足够

### 4.4 在 IGA-Guard 中的落点

- 代码：`src/iga_guard/detector/semantic_branch.py`
- 配置：`configs/default.yaml` → `use_semantic_branch: true`
- 训练：`scripts/train_bert.py`（待实现）

---

## 五、模块 C：可解释性 + 恶意流量高亮

### 5.1 三层解释

| 层级 | 技术 | 用户可见 |
|------|------|----------|
| L1 定位 | WebSpotter 字段贡献 + 字符级 span | 请求参数高亮 `union select` |
| L2 热力 | Token/字符热力图 | 大屏红色标注 |
| L3 语义 | 模板 / 本地 LLM | 「因在 Cookie 中发现双重编码 SQLi…」 |

### 5.2 前端高亮方案

```json
{
  "malicious_span": "union select",
  "token_range": [12, 24],
  "highlight_html": "<span class='mal'>union select</span>",
  "field_contributions": {"query:id": 0.92, "cookie:session": 0.08}
}
```

- 大屏：`frontend/static/dashboard.html`（ECharts + 高亮文本）
- API：`POST /api/detect` 返回 `explanation` 字段

### 5.3 可解释性指标

- Localization IoU / 片段命中率（`scripts/eval_explainability.py`）
- 2.0 目标：较关键词基线 **+22%**（当前约 **+38%**）

---

## 六、端到端数据流

```
HTTP 请求
    │
    ├─► [时序缓存] ──► DLinear ──► 时序异常分
    │
    └─► [解混淆] ──► TinyBERT ──► 语义分类分
              │
              ▼
         Feature Fusion Gate
              │
              ▼
         WebSpotter 定位 + NL 解释 + 前端高亮
              │
              ▼
         告警 / 规则导出 / 自演化反馈
```

---

## 七、与赛题要求逐条对齐

| 赛题要求 | 本方案 |
|----------|--------|
| 载荷净化与特征提取 | 解混淆 + RL-GWO 特征 + DLinear 时序特征 |
| 对抗性检测模型 | TinyBERT + XGBoost/RF 融合 |
| 混淆载荷生成器 | mutator + AST + LLM Agent |
| ≤10ms | 规则快路径 + 轻量模型 + 特征缓存 |
| 可演示 | Flask API + ECharts 高亮大屏 |

---

## 八、实现优先级（4 周）

| 周 | 任务 |
|----|------|
| W1 | Agent1 文献 → DLinear 窗长确定；TinyBERT 微调脚本 |
| W2 | 双路融合训练；WebSpotter 高亮组件完善 |
| W3 | 混淆数据集 1 万+；检出率实验 |
| W4 | 创新点凝练；作品报告 + 答辩 PPT |

详见 [`MULTI_AGENT_RESEARCH.md`](MULTI_AGENT_RESEARCH.md)。
