# Web 攻击 ML 检测 — CNN-LSTM 混合模型（Dawadi et al., Sci. Rep. 2023）— 思路卡片

**标题**：Securing web applications against XSS and SQLi attacks using a novel deep learning approach  
**作者**：Bishal Raj Dawadi, et al.  
**链接**：https://doi.org/10.1038/s41598-023-48845-4 · PMC: https://pmc.ncbi.nlm.nih.gov/articles/PMC10799887/

## 核心方法

1. 对 HTTP 请求载荷进行 **解码 → 标准化 → Word2Vec 向量化 → Tokenization**
2. **CNN 提取局部 n-gram 特征**（SQL 关键字、XSS 标签片段），**LSTM 捕获长程序列依赖**
3. 单一混合模型同时检测 SQLi 与 XSS，在 CSIC2010 上达 **99.77%** 准确率

## 可借鉴点（题目二）

- 证明 **字符/词级深度学习** 在 Web 攻击检测上仍具强基线竞争力，可作为消融对比
- 预处理流水线（多层 URL 解码、查询标准化）与 IGA-Guard `normalizer/` 思路一致
- CNN 局部特征 + RNN 全局特征 ≈ 本赛题「统计轨 + 语义轨」双路思想的早期版本
- ACIIDS 2022 集成 CNN+LSTM 框架（99.83% SQLi / 99.47% XSS）验证了 **会话 Cookie 状态** 可进一步提升检测

## 局限性

- 推理延迟远高于 TinyBERT（Word2Vec + 双向 LSTM），**难以满足 ≤5 ms** 赛题约束
- 对 **混淆/编码逃逸**（双重 URL、UTF-7、AST 拆分）鲁棒性未系统评估
- 黑盒模型，**无可解释定位**能力；对抗样本下性能骤降（对比 ModSec-AdvLearn 实验）
- 仅覆盖 SQLi/XSS，不含 CMD、XXE、Prompt Injection

## 可复现性

| 资源 | 状态 |
|------|------|
| 论文方法描述 | ✅ 含架构图与预处理步骤 |
| 开源代码 | ❌ 未提供官方仓库 |
| 基准数据 | ✅ CSIC2010、OWASP Payload、自建 Burp 集 |
| 复现难度 | 🔶 中等（需重建 Word2Vec + CNN-LSTM） |

## 本赛题映射

→ `baselines.md` 中 **CNN-LSTM 传统 DL 基线**（E1 对比实验）  
→ 预处理对照：`normalizer/decoder.py` 多层解码是否优于论文方案（E5 消融）  
→ 混淆子集上预期 Recall 显著低于 TinyBERT+Normalizer（支撑双路架构必要性）
