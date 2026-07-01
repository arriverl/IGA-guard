# TinyBERT (Jiao et al., EMNLP 2020 Findings) — 思路卡片

**标题**：TinyBERT: Distilling BERT for Natural Language Understanding  
**作者**：Xiaoqi Jiao, Yichun Yin, Lifeng Shang, et al. (Huawei / HUST)  
**链接**：https://arxiv.org/abs/1909.10351 · https://github.com/huawei-noah/Pretrained-Language-Model/tree/master/TinyBERT

## 核心方法

1. 提出面向 Transformer 的 **专用蒸馏损失**（隐层注意力 + 隐层输出 + 预测层），将 BERT-Base 知识迁移至 4/6 层学生模型
2. **两阶段训练**：通用域预训练蒸馏 → 任务特定数据增强蒸馏，兼顾泛化与下游精度
3. TinyBERT-4L 在 GLUE 上达教师 96.8% 性能，体积 **7.5× 更小**、推理 **9.4× 更快**；6 层版本与 BERT-Base 持平

## 可借鉴点（题目二）

- HTTP Payload 本质是短文本序列，TinyBERT-6L 可在 **≤5 ms** 内完成 128 token 分类
- 蒸馏框架可复用：以 BERT/RoBERTa 为教师，在 CSIC+混淆集上蒸馏 **领域专用 TinyBERT**
- 最后一层 **Self-Attention 权重** 可直接用于 token 级恶意高亮（对接 WebSpotter L2）
- 安全领域已有延伸：钓鱼 URL 检测（TinyBERT+Stacking, IEEE IoT 2023）证明短序列语义分类可行

## 局限性

- 原论文面向 GLUE 自然语言任务，**未覆盖 Web 攻击/混淆载荷**领域
- 4 层模型在复杂长程依赖（多层嵌套 XSS）上弱于 12 层 BERT
- 蒸馏需教师模型与额外训练成本；INT8 量化后精度可能下降 1~2%

## 可复现性

| 资源 | 状态 |
|------|------|
| 官方代码 | ✅ GitHub `huawei-noah/Pretrained-Language-Model` |
| 预训练权重 | ✅ HuggingFace `huawei-noah/TinyBERT_General_6L_768D` |
| 蒸馏脚本 | ✅ 含 task-specific distillation 示例 |
| Web 攻击数据 | ⚠️ 需自行在 CSIC/自建集上微调 |

## 本赛题映射

→ `detector/semantic_branch.py`：TinyBERT-6L + 8 类线性头  
→ `normalizer/decoder.py` 输出 `normalized_payload` 作为输入  
→ 与 DLinear 统计轨在 `dual_track.py` 以 0.6/0.4 融合  
→ Attention 热力图 → `explainer/locator.py` token_range 初值
