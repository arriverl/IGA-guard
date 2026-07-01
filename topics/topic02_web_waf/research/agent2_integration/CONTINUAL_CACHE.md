# 持续学习 KV 缓存（Tip-Adapter 风格）

> 参考：Few-shot VLM 两阶段适配 + Tip-Adapter 免训练缓存修正

## 动机

Web 攻击混淆手法迭代快，全量微调 RF/TinyBERT 成本高，且易灾难性遗忘。  
本模块在**冻结预训练编码器**前提下，用少量样本建 KV 库，测试时查库修正分类；漏检反馈动态扩库，实现持续学习。

## 两阶段流程

| 阶段 | 操作 | 是否训练 |
|------|------|----------|
| Stage-1 建库 | 每类 few-shot（默认 30）→ 编码为 Key，标签为 Value | ❌ 冻结编码器 |
| Stage-2 推理 | `fuse_probs = (1-λ)·p_base + λ·p_cache` | ❌ 仅查表 |

缓存亲和度（Tip-Adapter）：

\[
\text{aff}(q, k_i) = \exp(-\beta \cdot (1 - \cos(q, k_i)))
\]

\[
\text{score}(c) = \sum_{y_i=c} \text{aff}(q, k_i)
\]

## 动态更新（创新点）

- `POST /api/feedback` → 写入缓存（近重复合并，LRU 淘汰）
- `POST /api/evolve` → 漏检批量入库 + 可选 RF 合并重训
- **主干网络（RF / TinyBERT / 编码器）均不更新**

## 代码位置

| 模块 | 路径 |
|------|------|
| 缓存核心 | `src/iga_guard/evolution/continual_cache.py` |
| 建库脚本 | `scripts/build_cache.py` |
| 融合接入 | `src/iga_guard/detector/dual_track.py` |
| 配置 | `configs/default.yaml` → `continual_cache` |

## 使用

```powershell
$env:PYTHONPATH="src"
python scripts/iga_system.py build-cache --per-class 30
python scripts/iga_system.py evaluate --max-samples 5000
curl http://127.0.0.1:5000/api/cache/stats
```

可选安装 `sentence-transformers` 获得更强语义 Key；未安装时自动回退字符 n-gram 哈希嵌入。
