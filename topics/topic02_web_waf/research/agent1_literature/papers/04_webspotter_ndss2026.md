# WebSpotter — 可解释 AI 恶意载荷定位（Cui et al., NDSS 2026）— 思路卡片

**标题**：Achieving Interpretable DL-based Web Attack Detection through Malicious Payload Localization  
**作者**：Cui et al.  
**链接**：https://www.ndss-symposium.org/ndss-paper/achieving-interpretable-dl-based-web-attack-detection-through-malicious-payload-localization/ · https://github.com/meifukun/WebSpotter

## 核心方法

1. 将 HTTP 请求分解为 **最小语义单元（MSU）**——对齐 method/URI/header/body 各字段
2. **Embedding Attribution**：梯度分析量化各 MSU 对 DL 检测模型预测的重要性
3. **HTTP-Structure Alignment**：将 token 级重要性映射回 HTTP 字段结构
4. 融合 **重要性分数 + 文本语义** 训练轻量二分类定位模型，仅需 **1% 位置标注** 即可高精度定位

## 可借鉴点（题目二）

- 直接对标赛题 **Localization Accuracy +22%** 指标；论文报告较基线提升 ≥22%
- 定位结果可 **自动生成 WAF 规则**，对接 `rules/generator.py` 虚拟补丁闭环
- 克服 SHAP/LIME 忽视 HTTP 结构的缺陷，字段级解释符合安全运维习惯
- 开源代码 + CSIC/PKDD/FPAD 带位置标注数据集，可复现 IoU 评估流程

## 局限性

- 依赖底层 DL 检测模型质量；检测模型误判时定位随之失效
- 对 **多字段分散攻击**（载荷跨 Cookie+Body）定位粒度有限
- 虚假相关（spurious correlation）问题需语义特征辅助缓解，仍可能误标高影响但非恶意字段
- NDSS 2026 论文较新，部分数据集（FPAD）需申请获取

## 可复现性

| 资源 | 状态 |
|------|------|
| 官方代码 | ✅ GitHub `meifukun/WebSpotter` |
| 定位标注数据 | ✅ CSIC、PKDD、FPAD、CVE 子集 |
| 端到端脚本 | ✅ `run_pipeline.sh` 一键训练+评估 |
| 预训练检测模型 | ⚠️ 需按论文配置自行训练 CNN/Transformer 检测器 |

## 本赛题映射

→ `explainer/webspotter.py`：MSU 分解 + 重要性 + 定位模型  
→ `explainer/locator.py`：输出 `token_range` 供前端热力图  
→ E6 实验：100 条人工标注 vs WebSpotter IoU，对比 1.0 keyword 定位  
→ 与 TinyBERT Attention 热力图融合为 L1+L2 双层解释
