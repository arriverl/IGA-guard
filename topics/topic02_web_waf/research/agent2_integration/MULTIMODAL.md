# IGA-Guard 3.0 多模态融合（v2 条件融合）

## 四模态架构

| 模态 | 模块 | 输入 | 训练 |
|------|------|------|------|
| 文本语义 | `semantic_branch` + TinyBERT | 解码后 payload | 已微调 |
| 协议结构 | `ProtocolEncoder` | location / HPP / multipart | ❌ 规则+特征 |
| 字节视觉 | `ByteImageEncoder` | 32×64 字节栅格 | ❌ 固定纹理特征 |
| 时序统计 | `DLinearBranch` | IP 时序窗 | ❌ 在线统计 |
| 持续学习 | `ContinualCacheAdapter` | 文本 Key + 视觉 Key | ❌ 动态扩库 |

## 条件融合 + 门控（`dual_track.py`）

| 场景 | base | semantic | multimodal | dlinear |
|------|------|----------|------------|---------|
| **混淆攻击** | 0.42 | 0.32 | **0.04** | 0.12 |
| **非混淆** | 0.34 | 0.24 | **0.22** | 0.10 |

门控规则：
- `base_attack_peak ≥ 0.45` 或 **已混淆** → `w_mm=0`，权重归还 base/semantic
- `mm_Normal > 0.5` 且 `base_attack < 0.25` → `w_mm × 1.5` 压误报

多模态 `class_bias` **不再含 Normal 先验**，仅输出攻击偏置。

## 配置（`configs/default.yaml`）

```yaml
continual_cache:
  multimodal_alpha: 0.85      # 查库偏文本
  use_vision_keys: true       # 关多模态消融时设为 false

multimodal:
  enabled: true
  weight_multimodal_obfuscated: 0.04
  weight_multimodal_benign: 0.22
  gate_base_attack_threshold: 0.45
```

## 消融实验

```powershell
$env:PYTHONPATH="src"
python scripts/compare_multimodal_full.py --max-samples 2000 --output results/v2_compare_mm_2k.json
python scripts/compare_multimodal_full.py
```

### 优化前（线性 14% mm 融合）

| 配置 | 混淆检出 | 整体检出 | Normal 误报率 |
|------|----------|----------|---------------|
| 关闭多模态 | **92.0%** | **78.6%** | 2.63% |
| 开启多模态 | 86.9% | 73.3% | **0.10%** |
| Δ | **-5.1pp** | -5.3pp | -2.5pp |

### 优化后（条件融合 + 门控 + 去 Normal 先验）

| 配置 | 混淆检出 | 整体检出 | Normal 误报率 |
|------|----------|----------|---------------|
| 关闭多模态 | **92.17%** | **78.91%** | 3.10% |
| 开启多模态 | **92.05%** | 78.64% | **2.75%** |
| Δ | **-0.12pp** | -0.27pp | **-0.35pp** |

2k 快测 `v2_compare_mm_2k.json`：混淆 Δ -0.19pp，FPR Δ -0.48pp。  
全量 `v2_compare_multimodal_full.json`：混淆 Δ **-0.12pp**，FPR Δ **-0.35pp**（相对优化前 -5.1pp 检出损失已消除）。

## 代码

- `src/iga_guard/detector/multimodal_branch.py` — 混淆视觉特征
- `src/iga_guard/detector/dual_track.py` — `_fusion_weights()` 条件融合
- `src/iga_guard/evolution/continual_cache.py` — 视觉 Key 门控
