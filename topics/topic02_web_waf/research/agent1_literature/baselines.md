# 可对比基线清单（Agent 1）

> 面向 IGA-Guard 2.0 实验 E1/E5/E6 · 最后更新：2026-06

---

## 一、基线总览

| 编号 | 基线 | 类型 | 预期 Macro-F1 | 延迟 | 可解释 | 混淆鲁棒 |
|------|------|------|---------------|------|--------|----------|
| B0 | 纯规则 WAF（自研 regex） | 规则 | ~0.75 | <1 ms | 关键词 | 低 |
| B1 | ModSecurity CRS v3 | 规则 | ~0.74 (PL4) | 2~8 ms | 规则 ID | 低 |
| B2 | XGBoost + 统计特征 | ML | ~0.88 | <1 ms | SHAP | 中 |
| B3 | CNN-LSTM | DL | ~0.99* | 50~200 ms | 无 | 中 |
| B4 | BERT-Base 微调 | DL | ~0.99* | 30~80 ms | Attention | 中高 |
| B5 | TinyBERT-6L（本方案语义轨） | DL | ~0.95+ | 2~5 ms | Attention | 高 |
| B6 | IGA-Guard 2.0 Full | 混合 | **目标 >0.995** | **<5 ms** | WebSpotter | **高** |

\* 在 CSIC 原始集上；混淆子集会显著下降

---

## 二、B0 — 纯规则 WAF

### 描述

- 基于 OWASP CRS 精选子集的手工正则规则
- 实现：`src/iga_guard/rules/generator.py` 生成的规则集

### 典型性能（文献 + 内部冒烟）

| 指标 | 原始载荷 | 混淆载荷 |
|------|----------|----------|
| Recall | 85~92% | 40~60% |
| FPR | 3~8% | 3~8% |
| 延迟 P50 | <0.5 ms | <0.5 ms |

### 优劣势

| 优势 | 劣势 |
|------|------|
| 零训练、可解释（规则名） | 混淆逃逸极易绕过 |
| 延迟极低 | 误报随规则数膨胀 |
| 新 CVE 可快速加规则 | 无泛化能力 |

### 对比命令

```powershell
python scripts/evaluate.py --baseline rules --data data/samples/obfuscated_dataset.csv
```

---

## 三、B1 — ModSecurity + OWASP CRS

### 描述

- 业界标准开源 WAF 引擎 + Core Rule Set
- **Paranoia Level (PL1~PL4)** 控制规则严格度

### 文献基准数据

来源：ModSec-Learn (arXiv 2024)、MDPI App. Sci. 2022

| 配置 | TPR @ 1% FPR | 平均 Recall（7 数据集） |
|------|--------------|-------------------------|
| PL1 | 92.50% | ~52%（低敏感度） |
| PL2 | 75.45% | — |
| PL4 | 68.55% | **73.7%** |
| ModSec-Learn (SVM) | **99.02%** | — |

### 对抗场景（ModSec-AdvLearn, 2023）

| 场景 | Vanilla PL4 TPR @ 1% FPR |
|------|--------------------------|
| 干净 SQLi 测试集 | ~68% |
| 对抗 SQLi 测试集 | **<50%**（低于随机） |

### 本赛题映射

- B1 作为 **「传统 WAF 上限」** 基线
- PL4 误报高 + 混淆检出低 → 支撑「规则+ML 融合」叙事
- `rules/virtual_patch.py` 可输出 ModSecurity 格式规则

### 部署参考

```bash
# Docker 快速拉起（实验对比用）
docker run -d --name modsec -p 8080:80 \
  owasp/modsecurity-crs:nginx-alpine
```

---

## 四、B2 — XGBoost + 统计特征（IGA-Guard 1.0）

### 描述

- 15 维统计/语义特征 → XGBoost 二分类/多分类
- 实现：`detector/fusion_model.py`（单路模式）

### 典型性能

| 指标 | CSIC 原始 | 混淆子集 |
|------|-----------|----------|
| Macro-F1 | 0.88~0.92 | 0.70~0.80 |
| 延迟 P50 | 0.2~0.5 ms | 同左 |
| 定位 IoU | ~0.35（keyword） | — |

### 对比价值

- E5 消融 `w/o Dual-Track` 对照组
- 证明统计特征对混淆载荷不足，需语义轨补充

---

## 五、B3 — CNN / RNN / CNN-LSTM

### 描述

- 字符级 CNN 或 Word2Vec + LSTM/CNN-LSTM 混合
- 代表文献：Dawadi et al. Sci. Rep. 2023；ACIIDS 2022 Ensemble

### 文献性能（CSIC2010）

| 模型 | Accuracy | FPR | 推理时间 |
|------|----------|-----|----------|
| CNN-LSTM | 99.77% | 极低 | ~100 ms |
| CNN-LSTM (ACIIDS) | 99.83% SQLi | — | — |
| 纯 CNN | ~98.5% | 中 | ~50 ms |
| 纯 LSTM | ~99.5% | 低 | ~80 ms |

### 优劣势

| 优势 | 劣势 |
|------|------|
| 原始集精度高 | **无法满足 ≤5 ms** |
| 端到端学习 | 黑盒、无定位 |
| 实现成熟 | 混淆/对抗下骤降 |

### 本赛题对比设计

```
E1: B3 vs B5 vs B6 on obfuscated_dataset.csv
指标: Macro-F1, 混淆 Recall, P99 延迟
预期: B3 F1≈B5 但延迟 20~40× 更高
```

---

## 六、B4 — BERT 类模型对比

### 模型矩阵

| 模型 | 参数量 | CSIC F1（文献/经验） | CPU 推理 | 适合赛题 |
|------|--------|---------------------|----------|----------|
| BERT-Base | 110M | ~0.99 | 50~100 ms | ❌ 太慢 |
| DistilBERT | 66M | ~0.98 | 20~40 ms | 🔶 边缘 |
| TinyBERT-6L | 67M→14M* | ~0.96~0.98 | **2~5 ms** | ✅ 首选 |
| DistilRoBERTa | 82M | ~0.98 | 25~50 ms | 🔶 备选 |

\* 蒸馏后实际部署约 14M 有效参数（INT8 量化）

### TinyBERT vs BERT 关键差异

| 维度 | BERT-Base | TinyBERT-6L |
|------|-----------|-------------|
| 层数 | 12 | 6 |
| 推理加速 | 1× | **9.4×** |
| GLUE 保留 | 100% | ~100% |
| 安全领域微调 | 多 | 少（空白） |

### 本赛题策略

- B4-BERT-Base 仅作 **精度上界** 离线对比
- 线上部署 TinyBERT-6L + INT8 ONNX
- DistilRoBERTa 作为 E5 消融备选

---

## 七、B5/B6 — 本方案与完整系统

### B5: TinyBERT 语义轨（单路）

```
normalized_payload → TinyBERT-6L → 8-class softmax
```

### B6: IGA-Guard 2.0 Full

```
Normalizer → [TinyBERT | DLinear] → Fusion Gate → WebSpotter → Report
```

### 内部实测（README 披露）

| 指标 | B2 (1.0) | B6 (2.0) | 目标 |
|------|----------|----------|------|
| 延迟 P50 | ~0.5 ms | **~0.22 ms** | <5 ms |
| 定位 IoU 提升 | baseline | **+37.9%** | +22% |
| 混淆 Recall | ~80% | ~90% | >99.5% |

---

## 八、E5 消融对照表

| 配置 | 对应基线 | 验证假设 |
|------|----------|----------|
| Full 2.0 | B6 | 完整系统 |
| w/o Normalizer | B6 降级 | 解混淆贡献 |
| w/o DLinear | ≈ B5 | 时序轨必要性 |
| w/o Semantic | ≈ B2+时序 | 语义轨必要性 |
| w/o Dual-Track | B2 | 双路 > 单路 |
| w/o WebSpotter | B6 无定位 | 解释模块价值 |

---

## 九、基线实现优先级

| 优先级 | 基线 | 实现工作量 | 实验 |
|--------|------|------------|------|
| P0 | B0 规则 | ✅ 已有 | E1 |
| P0 | B2 XGBoost | ✅ 已有 | E1/E5 |
| P1 | B1 ModSecurity | Docker 部署 | E1 抽样 |
| P1 | B5 TinyBERT | ✅ 已有 | E1/E4 |
| P2 | B3 CNN-LSTM | 需新建脚本 | E1 |
| P3 | B4 BERT-Base | HuggingFace 微调 | 离线对比 |

---

## 十、参考文献

1. ModSec-Learn: Demontis et al., arXiv:2406.13547, 2024
2. ModSec-AdvLearn: Demontis et al., arXiv:2308.04964, 2023
3. Dawadi et al., Sci. Rep. 2023 — CNN-LSTM for XSS/SQLi
4. García-Teodoro et al., MDPI App. Sci. 2022 — SIDS Web Attack Detection
5. Jiao et al., EMNLP 2020 — TinyBERT
