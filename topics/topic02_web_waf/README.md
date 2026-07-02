# IGA-Guard 3.0 — 面向混淆逃逸攻击的可解释自演化 Web 安全防御系统

> **IGA-Guard 3.0**: 四模态融合 + Tip-Adapter 持续学习缓存 + FP 护栏 + WebSpotter 可解释定位

## 架构概览

```
HTTP → 解混淆 → 四模态融合(RF+TinyBERT+多模态+DLinear) → 混淆Boost → 缓存修正 → FP护栏 → 输出
```

| 模态 | 模块 | 说明 |
|------|------|------|
| 统计轨 | `fusion_model.py` + RF | 110k 混淆语料训练 |
| 语义轨 | `semantic_branch.py` + TinyBERT | 全量 5 epoch 微调 |
| 多模态轨 | `multimodal_branch.py` | 协议 + 字节图，条件门控融合 |
| 时序轨 | `dlinear_branch.py` | 流量窗异常分 |
| 持续学习 | `continual_cache.py` | 552 条 KV 缓存（文本 + 视觉 Key） |

详细方案：[`research/agent2_integration/SCHEME_V3.md`](research/agent2_integration/SCHEME_V3.md)  
实验报告：[`research/agent2_integration/EXPERIMENT_REPORT.md`](research/agent2_integration/EXPERIMENT_REPORT.md)

## 诚实口径指标（全量 19,411，`v2_exp1_overall.json`）

| 指标 | 赛题目标 | 当前 |
|------|----------|------|
| 混淆子集 Recall | > 99.5% | **97.94%**（FN 213） |
| 混淆 Precision | — | **100%** |
| Normal 误报率 FPR | 低误报 | **11.16%**（FP 护栏优化中，3k 快测 **4.55%**） |
| 延迟 P50 | < 5 ms | **2.92 ms** ✓ |
| WebSpotter IoU 提升 | ≥ +22% | **+37.9%** ✓ |
| 多模态消融 Δ | 可控 | **−0.12 pp**（条件融合） |

## 快速开始

```powershell
cd d:\Code_development\gitproduct\caisa_contest_2026\topics\topic02_web_waf
pip install -r requirements.txt

# 统一入口（推荐）
$env:PYTHONPATH="src"
python scripts/iga_system.py status
python scripts/iga_system.py train --epochs 5          # RF + TinyBERT 全量
python scripts/iga_system.py build-cache --per-class 30
python scripts/iga_system.py evaluate --max-samples 0  # 全量评估
python scripts/iga_system.py experiments --experiments all
python scripts/iga_system.py serve
# 大屏: http://127.0.0.1:5000/static/dashboard.html
```

### 常用子命令

| 命令 | 作用 |
|------|------|
| `iga_system.py pipeline` | 数据集 → 训练 → 评估 → 对抗演化 |
| `iga_system.py expand-cache` | 漏检样本写入持续学习缓存 |
| `iga_system.py evolve-obf` | 漏检诚实增量重训 RF |
| `iga_system.py compare-multimodal` | 多模态开/关消融 |
| `iga_system.py obfuscate -p "..." -t SQLi` | 混淆变种生成 |

## 文档索引

| 路径 | 内容 |
|------|------|
| `docs/FINAL_SYSTEM.md` | 系统说明与数据资产 |
| `research/agent1_literature/` | 论文与社区情报 |
| `research/agent2_integration/` | 架构、实验、多模态、缓存 |
| `configs/default.yaml` | 生产配置（FP 护栏、融合权重） |

## 核心模块

| 模块 | 路径 |
|------|------|
| 四模态检测引擎 | `src/iga_guard/detector/dual_track.py` |
| 混淆信号 / FP 分层 | `src/iga_guard/obfuscation_signals.py` |
| 持续学习缓存 | `src/iga_guard/evolution/continual_cache.py` |
| WebSpotter | `src/iga_guard/explainer/webspotter.py` |
| 对抗演化 | `scripts/run_adversarial.py` |
| 实验套件 E1–E8 | `scripts/run_experiments_suite.py` |

## 创新点（答辩）

1. **DLinear + TinyBERT + 多模态** 条件融合检测架构  
2. **Tip-Adapter 风格持续学习缓存**（冻结编码器 + 漏检扩库）  
3. **强/弱混淆分层判定 + FP 护栏**（评测口径与检测器解耦）  
4. **WebSpotter 恶意高亮** + 对抗演化闭环  
