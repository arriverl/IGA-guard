# DLinear (Zeng et al., AAAI 2023) — 思路卡片

**标题**：Are Transformers Effective for Time Series Forecasting?  
**作者**：Ailing Zeng, Mingyue Chen, Lei Zhang, Qiang Xu  
**链接**：https://arxiv.org/abs/2205.13504 · https://github.com/cure-lab/LTSF-Linear

## 核心方法

1. 用移动平均核将时序分解为 **Trend（趋势）** 与 **Seasonal（季节/残差）**
2. 对两个分量分别施加 **单层线性映射**，再相加得到预测/表征
3. 证明在多个 LTSF 基准上优于复杂 Transformer

## 可借鉴点（题目二）

- HTTP 流量 [QPS, 熵, 编码比, …] 可视为多元时序
- **残差分量突增** 可指示异常请求突发（扫描、隧道、低速混淆）
- 计算量极低，适合赛题 **≤10ms** 约束

## 局限性

- 原论文面向 forecasting，需改造为 **anomaly scoring**
- 单条请求无时序上下文时需退化为统计特征

## 可复现性

- 官方 PyTorch 实现开源
- IGA-Guard 已实现轻量版：`detector/dlinear_branch.py`

## 本赛题映射

→ 升级 `collector/timeseries_buffer.py` 提供真实 T 步窗口  
→ 与 TinyBERT 语义轨在 `dual_track.py` 融合
