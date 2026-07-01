# IGA-Guard 3.0 多模态融合

## 四模态架构

| 模态 | 模块 | 输入 | 训练 |
|------|------|------|------|
| 文本语义 | `semantic_branch` + TinyBERT | 解码后 payload | 已微调（主干可选冻结推理） |
| 协议结构 | `ProtocolEncoder` | location / HPP / multipart | ❌ 规则+特征 |
| 字节视觉 | `ByteImageEncoder` | 32×64 字节栅格 | ❌ 固定纹理特征 |
| 时序统计 | `DLinearBranch` | IP 时序窗 | ❌ 在线统计 |
| 持续学习 | `ContinualCacheAdapter` | 文本 Key + 视觉 Key | ❌ 动态扩库 |

## 融合权重（`configs/default.yaml`）

```yaml
multimodal:
  weight_base: 0.38
  weight_semantic: 0.28
  weight_multimodal: 0.14
  weight_dlinear: 0.12
```

缓存修正：`fuse_probs` 使用 `multimodal_alpha` 融合文本/视觉 Key 相似度。

## 代码

- `src/iga_guard/detector/multimodal_branch.py`
- `src/iga_guard/detector/dual_track.py`（接入）
- `src/iga_guard/evolution/continual_cache.py`（双 Key 查库）

## 使用

```powershell
$env:PYTHONPATH="src"
python scripts/iga_system.py build-cache --per-class 30
python scripts/iga_system.py evaluate --max-samples 3000
```

重建缓存后视觉 Key 自动写入 `models/continual_cache.npz` 的 `vision_keys` 数组。
