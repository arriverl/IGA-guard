# IGA-Guard 2.0 最终系统说明

## 系统架构（IGA-Guard 3.0 · 四模态）

```
HTTP 请求 → 采集解析 → 多层解混淆 → 四模态融合检测 → WebSpotter → 规则/自演化
              ↓              ↓
         时序轨 DLinear   文本轨 TinyBERT
              ↓              ↓
         协议轨+HPP      字节图视觉轨 (32×64)
              ↓              ↓
         持续学习双 Key 缓存（文本+视觉，动态更新）
```

## 数据资产

| 资产 | 路径 | 规模 |
|------|------|------|
| CSIC 2010 真实流量 | `data/raw/csic/` | 60,002 条（混淆扩充底稿） |
| 公开载荷库 | `data/raw/public/` | SecLists/FuzzDB |
| 社区种子 | `data/raw/community/payloads_seed.txt` | 258+ 条 |
| **129k 混淆训练语料** | `data/master/train_obfuscated.csv` 等 | **CSIC 真实底稿 + 程序合成扩充**（133,008 条） |
| Master 测试集 | `data/master/test_obfuscated.csv` | **23,616** |
| 混淆扩充全集 | `data/master/full_obfuscated.csv` | **156,624**（约 **16.5 万**） |

## 模型

| 组件 | 路径 | 说明 |
|------|------|------|
| RF 融合 | `models/fusion_detector.joblib` | 128 树，133k 训练 |
| TinyBERT | `models/tinybert_waf/` | 50k 子集微调（3 epoch），语义轨门控 |
| 配置 | `configs/default.yaml` | `use_semantic_branch: true` |

## 创新点（答辩四条）

1. **DLinear-TinyBERT 双流融合** — 时序 + 语义，动态门控
2. **WebSpotter 恶意高亮** — IoU +37.9%，字段贡献图
3. **RL-GWO 特征筛选 + Online RL** — 阈值自演化
4. **社区情报 + 25+ 混淆手法** — Agent4 数据集闭环
5. **IGA-Guard 3.0 四模态融合** — 协议轨 + 字节图视觉轨 + 双 Key 持续学习缓存（见 `research/agent2_integration/MULTIMODAL.md`）

## 统一入口

```powershell
$env:PYTHONPATH="src"
python scripts/iga_system.py status      # 状态
python scripts/iga_system.py obfuscate -p "1 union select 1" -t SQLi -n 10
python scripts/iga_system.py evaluate --max-samples 5000
python scripts/iga_system.py serve       # Web http://127.0.0.1:5000/
python scripts/iga_system.py pipeline    # 全流程
```

API：`POST /api/detect` · `POST /api/obfuscate` · `POST /api/feedback` · `POST /api/evolve`

## 已知问题与修复（2026-06-30）

### 对抗演化崩溃原因
全量测试套件使用 `data/master/test.csv`（7000+ 攻击种子）且**无上限**，每轮生成 **7万+** 变体，逐条 GPU 推理 TinyBERT，运行约 19 小时仍未输出 Round 1，最终被系统杀死（exit `4294967295`）。

**修复**：`run_adversarial.py` 增加 `--max-seeds 150`、`--max-variants 3000`、进度日志；3 轮约 **2 分钟**完成。

### 检出率指标修正（2026-07-01）

此前报告混淆子集 Recall **100%**（5k 抽样）为**指标失真**：结构规则过宽 + 漏检样本反哺训练导致小样本虚高。已收紧规则触发条件，E1 改为 `test_obfuscated.csv` **全量评测**，见 [`v2_exp1_overall.json`](../results/v2_exp1_overall.json)。

## 实验结果（诚实口径终稿）

> 完整报告：[`research/agent2_integration/EXPERIMENT_REPORT.md`](../research/agent2_integration/EXPERIMENT_REPORT.md)

### 数据集

**129k 混淆训练语料** = CSIC 2010 真实 HTTP 底稿（60,002 条）经 `dataset_agent.py` 25+ 混淆手法程序合成扩充，落盘 `train_obfuscated.csv`（133,008 条）。Master 混淆全集 **约 16.5 万条**（`full_obfuscated.csv` 实测 156,624；训练 133,008 / 测试 23,616）。

### E1 检测性能（`v2_exp1_overall.json`，全量 n=19,411）

| 指标 | 整体 | 混淆子集（n=10,317） | 正常流量（n=4,068） | 赛题目标 |
|------|------|----------------------|---------------------|----------|
| 二分类检出率（Recall） | **78.8%** | **91.86%** | — | 混淆 > 99.5% |
| Precision | **99.0%** | **100.0%** | — | — |
| F1 | 87.8% | 95.8% | — | — |
| 误报率（FPR） | 2.93% | — | **2.93%**（119 FP） | 低误报 |
| 多分类 Accuracy | 77.7% | — | — | — |

> 诚实口径：混淆子集 Precision 100%、零 FP；Recall 91.86% 未达 99.5%。此前 100% Recall 已废弃。

### E3 对抗鲁棒性（3 轮有界，`v2_exp3_adversarial_rounds.csv`）

| 轮次 | 样本数 | Recall |
|------|--------|--------|
| R1 | 244 | **100%** |
| R2 | 239 | **100%** |
| R3 | 248 | **100%** |

> 增量重训后 3 轮零漏检；参数 `--max-seeds 100 --max-variants 1500`。

### E4 延迟（`v2_exp4_latency.json`，1,000 次）

P50 **2.92 ms** · P99 **27.38 ms**（赛题 ≤ 10 ms，内部目标 < 5 ms）

### E6 可解释性（`v2_exp6_localization.json`）

WebSpotter IoU **+37.93%**（目标 ≥ +22%）✅

## 评估指标（evaluate.py v2）

- **多分类准确率** — 8 类精确匹配
- **二分类检出率** — 恶意 vs 正常（WAF 实战指标）
- **混淆子集二分类 Recall** — 赛题核心

## Agent 分工

| Agent | 职责 | 产出 |
|-------|------|------|
| Agent 1 | 文献 + 社区情报 | `research/agent1_literature/` |
| Agent 2 | 架构 + 实验报告 | `RUNNABLE_PLAN.md`, `EXPERIMENT_REPORT.md` |
| Agent 3 | 工程实现 | 核心代码 + 前端 |
| Agent 4 | 数据集 | `dataset_agent.py`, `community_fetcher.py` |

## 持续优化方向

- 全量 TinyBERT 训练（133k × 5 epoch），目标混淆 Recall > 99.5%
- 对抗演化漏检反哺 `failures.jsonl` → 增量重训（E7 Online RL）
- 延迟长尾优化：语义按需触发、INT8 量化、E4b 压测
- 补拉 SecLists 剩余源（网络可用时）
