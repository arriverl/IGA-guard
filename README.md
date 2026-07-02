# 2026 第二届大学生人工智能安全竞赛 — 定向式专项命题作品赛

> **参赛作品**：**IGA-Guard 3.0**（赛题 2 · Web 攻击载荷混淆逃逸检测）  
> **作品路径**：[`topics/topic02_web_waf/`](topics/topic02_web_waf/)  
> **竞赛官网**：https://ai-contest.sjtu.edu.cn/

---

## IGA-Guard 3.0 简介

**中文全称**：IGA-Guard 3.0 — 面向混淆逃逸攻击的可解释自演化 Web 安全防御系统

面向赛题 2「Web 攻击载荷混淆逃逸检测」，系统对经 URL 编码、Unicode、注释拆分、AST 变换等手法混淆的 HTTP 攻击载荷进行**多层解混淆 → 四模态融合检测 → 可解释定位 → 持续学习演化**。

### 赛题指标对标（诚实口径，全量 n=19,411）

| 指标 | 赛题目标 | 当前实测 | 状态 |
|------|----------|----------|------|
| 混淆子集 Recall | > 99.5% | **91.17%** | v3.1 重训 |
| 混淆 Precision | — | **100%** | ✓ |
| Normal 误报率 FPR | 低误报 | **3.42%** | ✓ |
| 单次延迟 P50 | < 5 ms | **2.92 ms** | ✓ |
| 定位 IoU 提升 | ≥ +22% | **+37.9%** | ✓ |

### 系统架构（一句话）

```
HTTP → 解混淆(6轮) → RF+TinyBERT+多模态+DLinear 条件融合 → 混淆Boost → 552条缓存 → FP护栏 → WebSpotter
```

### 四大创新点（答辩版）

1. **四模态条件融合**：统计轨 RF+规则、语义轨 TinyBERT、协议+字节图多模态、时序轨 DLinear，按混淆/非混淆分权门控
2. **Tip-Adapter 持续学习缓存**：冻结编码器 + 动态 KV 库，漏检样本扩库无需全量重训
3. **强/弱混淆分层 + FP 护栏**：评测口径与检测器解耦，抑制缓存/规则翻判导致的误报
4. **WebSpotter 可解释定位** + **LLM/AST 对抗演化闭环**

---

## 快速开始

```powershell
cd topics\topic02_web_waf
pip install -r requirements.txt
$env:PYTHONPATH="src"

python scripts/iga_system.py status          # 查看数据集/模型/最新评估
python scripts/iga_system.py train --epochs 5
python scripts/iga_system.py evaluate        # 全量评估 → results/v2_exp1_overall.json
python scripts/iga_system.py serve           # Web 大屏 http://127.0.0.1:5000/
```

单条检测示例：

```powershell
python scripts/detect.py --url "http://x/test?p=1%2527%20union%20select" --json
```

---

## 模块与功能总览

完整说明见 **[题目 README → 模块详解](topics/topic02_web_waf/README.md#模块详解)**。

| 层级 | 包/目录 | 职责 |
|------|---------|------|
| 入口 | `scripts/iga_system.py` | 统一 CLI：训练、评估、数据集、缓存、演化、实验、服务 |
| 流水线 | `src/iga_guard/pipeline.py` | `IgaGuardEngine`：采集→解混淆→检测→解释→规则 |
| 解混淆 | `src/iga_guard/normalizer/` | 6 轮 URL/HTML/Unicode 解码 + AST 还原 |
| 检测 | `src/iga_guard/detector/` | 四模态融合引擎 `dual_track.py` |
| 特征 | `src/iga_guard/features/` | 结构/统计特征 + RL-GWO 筛选 |
| 采集 | `src/iga_guard/collector/` | HTTP 解析、时序缓冲（DLinear 输入） |
| 数据集 | `src/iga_guard/dataset/` | CSIC/公开源拉取、25+ 混淆扩充 |
| 对抗 | `src/iga_guard/adversarial/` | 变种生成、AST 混淆、LLM Agent |
| 演化 | `src/iga_guard/evolution/` | 持续学习缓存、Online RL、漏检重训 |
| 可解释 | `src/iga_guard/explainer/` | WebSpotter 定位、NL 解释、高亮 HTML |
| 规则 | `src/iga_guard/rules/` | ModSecurity/Suricata 规则生成、虚拟补丁 |
| 信号 | `src/iga_guard/obfuscation_signals.py` | 混淆标记、强/弱混淆判定、结构规则 |
| Web | `run.py` + `backend/` | REST API + ECharts 可视化大屏 |

### 统一 CLI 子命令

| 命令 | 功能 |
|------|------|
| `status` | 数据集行数、模型文件、最新 E1 指标 |
| `dataset` | 重建 `data/master/` 混淆数据集 |
| `train` | RF 融合 + TinyBERT 微调 |
| `build-cache` / `expand-cache` | 构建/扩展持续学习 KV 缓存 |
| `evaluate` | 诚实口径全量/抽样评估 |
| `evolve-obf` | 漏检样本诚实增量重训 RF |
| `compare-multimodal` | 多模态开/关消融 |
| `experiments` | E2/E5/E7/E8 实验套件 |
| `adversarial` | 多轮对抗演化 |
| `obfuscate` | 单载荷混淆变种生成 |
| `pipeline` | 数据集→训练→评估→对抗 一键流程 |
| `serve` | 启动 Web 服务 |

---

## 文档索引

| 文档 | 说明 |
|------|------|
| [**IGA-Guard 题目 README**](topics/topic02_web_waf/README.md) | **项目主入口 · 模块/脚本/API 详解** |
| [IGA-Guard 3.0 方案](topics/topic02_web_waf/research/agent2_integration/SCHEME_V3.md) | 架构与融合策略 |
| [实验报告](topics/topic02_web_waf/research/agent2_integration/EXPERIMENT_REPORT.md) | E1–E8 实测数据 |
| [系统说明 FINAL_SYSTEM.md](topics/topic02_web_waf/docs/FINAL_SYSTEM.md) | 数据资产与 API |
| [多模态设计 MULTIMODAL.md](topics/topic02_web_waf/research/agent2_integration/MULTIMODAL.md) | 条件融合与视觉轨 |
| [竞赛指南摘要](docs/00_竞赛指南摘要.md) | 报名与评审流程 |
| [交付物清单](docs/03_交付物与提交清单.md) | 初赛材料核对 |

---

## 仓库结构

```
caisa_contest_2026/
├── README.md                          # 本文件（竞赛仓库入口）
├── docs/                              # 竞赛通用文档
└── topics/topic02_web_waf/            # IGA-Guard 3.0 作品
    ├── README.md                      # 模块/功能详细说明
    ├── configs/default.yaml           # 生产配置
    ├── src/iga_guard/                 # 核心 Python 包
    ├── scripts/                       # CLI 与实验脚本
    ├── backend/                       # Flask REST API
    ├── data/master/                   # 训练/测试数据集
    ├── models/                        # RF / TinyBERT / 缓存
    ├── results/                       # 实验结果 JSON
    └── research/                      # 文献、架构、实验文档
```

---

## 时间节点

| 日期 | 事项 |
|------|------|
| 07-02 ~ 08-02 | 提交作品 |
| 08-05 ~ 08-15 | 初赛评审 |
| 08-20 ~ 08-22 | 决赛答辩 |
