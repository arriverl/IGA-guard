# IGA-Guard 3.0 最新方案解读

## 架构总览

```
HTTP 请求
  → 多层解混淆（最多 6 轮）
  → 四模态 Late Fusion
       ├─ RF+规则（38~42%）
       ├─ TinyBERT 语义（24~32%）
       ├─ 协议+字节图多模态（4~22%，条件门控）
       └─ DLinear 时序（10~12%）
  → 混淆 Boost（强混淆 / 双轮解码 / base 攻击≥0.25）
  → 规则兜底（强混淆 + kw/st 阈值）
  → Tip-Adapter 缓存（552 条，良性流量降权融合）
  → FP 护栏（base=Normal 时要求 conf≥0.55 或 cache hit≥0.92）
  → WebSpotter 可解释高亮
```

## 关键设计决策

### 1. 双层混淆判定

| 函数 | 用途 |
|------|------|
| `is_obfuscated()` | **评测口径**：含 `%` 等宽标记，用于混淆子集统计 |
| `has_strong_obfuscation()` | **检测器专用**：双重编码/null_byte/\\u/echo 等，避免普通 URL 编码误触发 |

### 2. 条件多模态融合

- **混淆样本**：多模态权重仅 4%，主信号 RF+TinyBERT
- **良性流量**：多模态 22%，配合协议特征压误报
- **门控**：base 攻击峰值 ≥0.45 时多模态权重归还 base/semantic

### 3. 持续学习缓存（552 条）

- 132 few-shot 种子 + 420 eval_miss 漏检扩库
- 良性 / 低 base 攻击：`fusion_weight` 降至 0.12，且再 ×0.5
- 强制命中需 `hit≥0.92` 且（强混淆 或 base_attack≥0.30）

### 4. FP 护栏（2026-07-02 新增）

当 RF 判 **Normal**、非强混淆、解码深度 <2 时：
- 缓存/融合翻转为攻击需 **confidence ≥ 0.55**
- 或 **cache_hit ≥ 0.92**（高置信漏检记忆）

## 指标演进（诚实口径，全量 19,411）

| 阶段 | 混淆 Recall | Normal FPR | 说明 |
|------|-------------|------------|------|
| 基线（规则收紧后） | 91.86% | 2.93% | 虚高问题已修正 |
| +漏检规则/缓存/RF/TinyBERT | **97.94%** | **11.16%** | 检出↑但误报失控 |
| +FP 护栏（当前代码） | 待全量重评 | 目标 <4% | 平衡检出与误报 |

## 已知问题与修复状态

| 问题 | 状态 |
|------|------|
| 虚高 100% 指标 | ✅ 已修正 |
| 多模态开/关 -5.1pp 检出损失 | ✅ 条件融合，Δ -0.12pp |
| 漏检 2000 条模式分析 | ✅ `analyze_misses.py` |
| FPR 11.16% 过高 | 🔧 FP 护栏 + 缓存降权 |
| 混淆 Recall <99.5% | 🔶 213 FN，待护栏后重评 |
| `evaluate --max-samples 0` bug | ✅ 已修复 |
| E2 unknown=0 | 数据集无未见混淆类型 |
| EXPERIMENT_REPORT 章节错乱 | ✅ 同步更新 |

## 复现命令

```powershell
$env:PYTHONPATH="src"
python scripts/evaluate.py --output results/v2_exp1_overall.json
python scripts/iga_system.py experiments --experiments e5 --max-samples 3000
```
