# IGA-Guard 3.0 — 面向混淆逃逸攻击的可解释自演化 Web 安全防御系统

> 四模态融合 + Tip-Adapter 持续学习缓存 + FP 护栏 + WebSpotter 可解释定位  
> 上级仓库入口：[caisa_contest_2026/README.md](../../README.md)

---

## 目录

- [架构概览](#架构概览)
- [检测流水线](#检测流水线)
- [诚实口径指标](#诚实口径指标)
- [快速开始](#快速开始)
- [模块详解](#模块详解)
- [脚本说明](#脚本说明)
- [Web API 与服务](#web-api-与服务)
- [数据资产](#数据资产)
- [配置说明](#配置说明)
- [实验套件](#实验套件)
- [文档索引](#文档索引)

---

## 架构概览

```
                    ┌─────────────────────────────────────────────────────────┐
                    │                    IgaGuardEngine                        │
                    │                   (pipeline.py)                          │
  HTTP Request      │                                                          │
       │            │  collector/          normalizer/        detector/         │
       ▼            │  ┌──────────┐       ┌──────────┐      ┌──────────────┐   │
  parse_http ──────►│  │http_parser│────►│ decoder  │─────►│ dual_track   │   │
  iter_payload      │  │protocol   │      │ast_restore│      │  ├ fusion RF │   │
                    │  │timeseries │      │(6轮解码)  │      │  ├ semantic  │   │
                    │  │_buffer    │      └──────────┘      │  ├ multimodal│   │
                    │  └──────────┘                         │  ├ dlinear   │   │
                    │       │                               │  └ cache     │   │
                    │       └───────────────────────────────►│              │   │
                    │                                        └──────┬───────┘   │
                    │                                               │           │
                    │  explainer/          rules/                   ▼           │
                    │  ┌──────────┐       ┌──────────┐      DetectionResult    │
                    │  │webspotter│       │generator │      + highlight_html   │
                    │  │nl_explain│       │virtual   │                          │
                    │  └──────────┘       │_patch    │                          │
                    └─────────────────────────────────────────────────────────┘
```

| 模态 | 模块 | 权重（非混淆 / 混淆） | 说明 |
|------|------|----------------------|------|
| 统计轨 | `fusion_model.py` + RF | 38% / 42% | 128 棵 RF + 结构规则兜底，133k 混淆语料训练 |
| 语义轨 | `semantic_branch.py` + TinyBERT | 28% / 32% | 全量 110k×5 epoch 微调，关键词回退 |
| 多模态轨 | `multimodal_branch.py` | 14% / 4% | 协议特征 + 32×64 字节图，条件门控压 FP |
| 时序轨 | `dlinear_branch.py` | 12% / 12% | 按源 IP 滑动窗口异常分 |
| 持续学习 | `continual_cache.py` | fusion 0.28 | 552 条双 Key（文本+视觉）KV 缓存 |

详细方案：[`research/agent2_integration/SCHEME_V3.md`](research/agent2_integration/SCHEME_V3.md)  
实验报告：[`research/agent2_integration/EXPERIMENT_REPORT.md`](research/agent2_integration/EXPERIMENT_REPORT.md)

---

## 检测流水线

单条 HTTP 请求在 `IgaGuardEngine.analyze_url()` 中的处理顺序：

1. **采集解析**（`collector/http_parser.py`）  
   将 URL query、Body、Header 等拆为独立 `payload` 字段；记录 `src_ip` 供时序轨使用。

2. **多层解混淆**（`normalizer/decoder.py` + `ast_restore.py`）  
   最多 6 轮：URL 单/双编码、HTML 实体、Unicode、Hex、注释剥离、SQL/XSS AST 还原。

3. **特征提取**（`features/`）  
   结构特征（熵、特殊字符密度、HPP 等）+ 语义 n-gram；RL-GWO 筛选 Top-15 维送入 RF。

4. **四模态融合**（`detector/dual_track.py`）  
   - RF+规则基线 → 语义偏置 → 多模态偏置 → DLinear 异常加权  
   - **混淆 Boost**：强混淆 / 深解码 / base 攻击峰值达标时抬升攻击分  
   - **持续学习缓存**：余弦相似度查库修正融合概率  
   - **FP 护栏**：RF 判 Normal 却被缓存/规则翻为攻击时，要求更高置信或强混淆证据

5. **可解释输出**（`explainer/webspotter.py`）  
   字符级恶意 span 定位 → `highlight_html` 前端高亮 + 字段贡献条形图。

6. **规则导出**（`rules/generator.py`）  
   可选生成 ModSecurity / Suricata 规则或虚拟补丁。

---

## 诚实口径指标

全量评测集：`data/master/test_obfuscated.csv`（**19,411** 条）  
结果文件：`results/v2_exp1_overall.json`

| 指标 | 赛题目标 | 当前 |
|------|----------|------|
| 混淆子集 Recall | > 99.5% | **91.17%**（FN 912，`v2_exp1_v31.json`） |
| 混淆 Precision | — | **100%** |
| Normal 误报率 FPR | 低误报 | **3.42%**（FP 139） |
| 延迟 P50 | < 5 ms | **2.92 ms** ✓ |
| WebSpotter IoU 提升 | ≥ +22% | **+37.9%** ✓ |
| 多模态消融 Δ | 可控 | **−0.12 pp**（条件融合后） |

---

## 快速开始

```powershell
cd topics\topic02_web_waf
pip install -r requirements.txt
$env:PYTHONPATH="src"

python scripts/iga_system.py status
python scripts/iga_system.py train --epochs 5
python scripts/iga_system.py build-cache --per-class 30
python scripts/iga_system.py expand-cache --max-rows 500
python scripts/iga_system.py evaluate
python scripts/iga_system.py experiments --experiments all
python scripts/iga_system.py serve
# 大屏: http://127.0.0.1:5000/static/dashboard.html
```

---

## 模块详解

### `src/iga_guard/` — 核心包

#### 流水线与数据模型

| 文件 | 类/函数 | 功能 |
|------|---------|------|
| `pipeline.py` | `IgaGuardEngine`, `load_config` | 主流水线入口；串联采集→解混淆→检测→解释→规则；LRU 缓存归一化；高置信 early-exit |
| `models.py` | `HttpRequest`, `NormalizedPayload`, `DetectionResult`, `GuardReport` | 核心数据结构；`build_highlight_html()` 生成前端高亮 |

#### `collector/` — 请求采集与时序

| 文件 | 功能 |
|------|------|
| `http_parser.py` | 解析原始 HTTP/URL，拆分 query、body、cookie 等 payload 字段 |
| `protocol.py` | 多协议适配（HTTP/HTTPS 请求规范化） |
| `timeseries_buffer.py` | 按 `src_ip` 维护最近 T=16 步 `[T,6]` 特征矩阵，供 DLinear 时序编码 |

#### `normalizer/` — 解混淆

| 文件 | 功能 |
|------|------|
| `decoder.py` | 多层解码链（URL/HTML/Unicode/Hex/Base64）；记录 `decode_chain` 深度 |
| `ast_restore.py` | SQL `CONCAT`/`CHAR` 还原、XSS 事件处理器剥离等 AST 级修复 |
| `__init__.py` | `normalize_payload()` 统一入口 |

#### `detector/` — 四模态检测

| 文件 | 类 | 功能 |
|------|-----|------|
| `dual_track.py` | `DualTrackDetector` | **主检测引擎**：条件融合权重、混淆 Boost、缓存修正、FP 护栏、Online RL 阈值调整 |
| `fusion_model.py` | `FusionDetector` | RF 分类器 + 结构规则兜底；legacy `engine: fusion` 消融路径 |
| `semantic_branch.py` | `SemanticBranch` | TinyBERT 本地推理 / 关键词密度回退；输出各类别语义偏置 |
| `multimodal_branch.py` | `MultimodalBranch` | 协议轨（HPP、multipart、密度）+ 字节图视觉轨；混淆/非混淆门控 |
| `dlinear_branch.py` | `DLinearBranch` | 时序分解异常检测；`encode_series()` / `score_anomaly()` |

#### `features/` — 特征工程

| 文件 | 功能 |
|------|------|
| `structural.py` | 熵、特殊字符比、编码层数、引号不平衡等结构特征 |
| `semantic.py` | 攻击关键词密度、n-gram 统计 |
| `statistical.py` | 候选 100 维统计特征聚合 |
| `rl_gwo_selector.py` | RL-GWO 特征筛选，输出 Top-15 维用于 RF |

#### `obfuscation_signals.py` — 混淆信号（全局）

| 函数/常量 | 用途 |
|-----------|------|
| `OBFUSCATED_MARKERS` | 混淆标记元组（评测与检测共用） |
| `is_obfuscated()` | **评测口径**：是否计入混淆子集 |
| `has_strong_obfuscation()` | **检测器专用**：强混淆证据（double-url、null-byte 等） |
| `structural_attack_rules()` | 结构规则（HPP、hex32、multipart 等）兜底检出 |

#### `dataset/` — 数据集采集（Agent 4）

| 文件 | 功能 |
|------|------|
| `csic_parser.py` | 解析 CSIC 2010 真实 HTTP 流量（GSI 标注） |
| `fetchers.py` | 拉取 SecLists、FuzzDB、PayloadsAllTheThings |
| `community_fetcher.py` | 社区种子 `payloads_seed.txt` 采集 |
| `obfuscation_techniques.py` | 25+ 混淆手法：`expand_payload()` 程序合成变种 |
| `label_rules.py` | 基于关键词/结构的自动标注规则 |
| `merge.py` | 多源合并、train/test 划分、写 `data/master/*.csv` |

#### `adversarial/` — 对抗生成

| 文件 | 功能 |
|------|------|
| `mutator.py` | 编码/注释/空白符等变种 `mutate_batch()` |
| `ast_mutator.py` | AST 级 SQL/XSS 变换 `ast_obfuscate_batch()` |
| `llm_agent.py` | LLM 驱动难例生成（对抗演化闭环） |

#### `evolution/` — 自演化

| 文件 | 功能 |
|------|------|
| `continual_cache.py` | Tip-Adapter 风格 KV 缓存；文本+视觉双 Key；LRU 扩库 |
| `online_rl.py` | 在线强化学习调整检测阈值与特征权重 |
| `self_train.py` | 漏检样本 `failures.jsonl` 反哺增量训练 |

#### `explainer/` — 可解释性

| 文件 | 功能 |
|------|------|
| `webspotter.py` | 字符级恶意 span 定位；IoU 评测支持 |
| `locator.py` | v1 关键词定位基线 |
| `nl_explanation.py` | 自然语言攻击解释生成 |

#### `rules/` — 规则引擎

| 文件 | 功能 |
|------|------|
| `generator.py` | 从检出样本生成 ModSecurity / Suricata 规则 |
| `virtual_patch.py` | 虚拟补丁匹配与导出 `export_virtual_patch_rule()` |

---

## 脚本说明

统一入口：**`scripts/iga_system.py`**（推荐）

| 脚本 | 功能 | 典型用法 |
|------|------|----------|
| `iga_system.py` | 统一 CLI | `python scripts/iga_system.py status` |
| `dataset_agent.py` | 拉取公开源 + CSIC + 混淆扩充 | `python scripts/dataset_agent.py` |
| `train.py` | 训练 Fusion RF | `python scripts/train.py --data data/master/train_obfuscated.csv` |
| `train_bert.py` | 微调 TinyBERT | `python scripts/train_bert.py --epochs 5` |
| `evaluate.py` | 诚实口径 E1 评估 | 输出 `results/v2_exp1_overall.json` |
| `build_cache.py` | Stage-1 构建 KV 缓存 | `--per-class 30` |
| `expand_cache_from_misses.py` | 漏检写入缓存 | 420 条漏检 → 552 条总库 |
| `evolve_from_obf_misses.py` | 漏检诚实增量重训 RF | 不污染测试集 |
| `evolve_from_misses.py` | 对抗漏检 CSV 演化 | 配合 `run_adversarial.py` |
| `analyze_misses.py` | 漏检模式分析 | 输出 `results/miss_analysis.json` |
| `compare_multimodal_full.py` | 多模态开/关全量消融 | `v2_compare_multimodal_full.json` |
| `run_experiments_suite.py` | E2/E5/E7/E8 批量实验 | `--experiments all` |
| `run_adversarial.py` | 多轮对抗演化 | `--rounds 3 --max-seeds 150` |
| `benchmark_latency.py` | E4 延迟测试 | P50/P95/P99 |
| `eval_explainability.py` | E6 WebSpotter IoU | `v2_exp6_localization.json` |
| `stress_test.py` | E4b 压测（待执行） | QPS 压力 |
| `detect.py` | 单条 CLI 检测 | `--url "..." --json` |
| `generate_dataset.py` | 小规模样本集生成 | `data/samples/` 演示用 |
| `build_community_seed.py` | 构建社区种子库 | `payloads_seed.txt` |
| `download_csic.py` | CSIC 2010 下载 | `data/raw/csic/` |
| `csic_to_labeled.py` | CSIC 转标注 CSV | 预处理 |

### `iga_system.py` 子命令一览

| 子命令 | 说明 |
|--------|------|
| `status` | 数据集行数、模型存在性、最新 E1 JSON |
| `dataset` | 调用 `dataset_agent.py` 重建 master |
| `train` | RF + TinyBERT（`--skip-bert` / `--bert-samples 0` 全量） |
| `build-cache` | 初始 KV 缓存 |
| `expand-cache` | 漏检扩库 |
| `evaluate` | 全量/抽样评估（`--max-samples 0` 或不传为全量） |
| `evolve-obf` | 漏检诚实 RF 重训 |
| `compare-multimodal` | 多模态消融 |
| `experiments` | E2/E5/E7/E8 |
| `adversarial` | 对抗演化 |
| `obfuscate` | `-p` 载荷 `-t` 类型 `-n` 变种数 |
| `pipeline` | dataset → train → evaluate → adversarial |
| `serve` | 启动 `run.py` Web 服务 |

---

## Web API 与服务

启动：`python scripts/iga_system.py serve` 或 `python run.py`

| 端点 | 方法 | 功能 |
|------|------|------|
| `/api/health` | GET | 健康检查、版本号 |
| `/api/detect` | POST | 单条/批量检测，返回 label、confidence、highlight |
| `/api/obfuscate` | POST | 混淆变种生成 |
| `/api/feedback` | POST | 漏检/误报反馈 → 写入缓存队列 |
| `/api/evolve` | POST | 触发在线演化 |
| `/static/dashboard.html` | GET | ECharts 可视化大屏 |

后端代码：`backend/app.py` · 静态资源：`static/`

---

## 数据资产

| 路径 | 规模 | 说明 |
|------|------|------|
| `data/raw/csic/` | 60,002 | CSIC 2010 真实 HTTP |
| `data/raw/public/` | — | SecLists / FuzzDB / PAT |
| `data/raw/community/payloads_seed.txt` | 258+ | 社区手工种子 |
| `data/master/train_obfuscated.csv` | 133,008 | 混淆训练集 |
| `data/master/test_obfuscated.csv` | 23,616 | 混淆测试集（E1 用 19,411） |
| `data/master/full_obfuscated.csv` | 156,624 | 混淆全集 |
| `data/cache/eval_obf_misses.jsonl` | 213 | 全量评测漏检记录 |
| `data/cache/failures.jsonl` | 动态 | 在线反馈漏检 |

---

## 配置说明

主配置：`configs/default.yaml`（version **3.0.0**）

| 节 | 关键项 | 说明 |
|----|--------|------|
| `detector` | `engine: dual_track` | 主引擎；`fusion` 为 legacy 消融 |
| | `confidence_threshold: 0.40` | 二分类判定阈值 |
| | `fp_guard_max_base_attack: 0.32` | FP 护栏：RF 攻击峰值上限 |
| | `fp_guard_min_attack_conf: 0.55` | FP 护栏：翻判所需最低置信 |
| | `cache_fusion_weight_benign: 0.12` | 良性流量缓存降权 |
| `normalizer` | `max_decode_rounds: 6` | 解混淆轮数 |
| `multimodal` | `enabled: true` | 多模态轨开关 |
| | `weight_*_obfuscated` | 混淆子集融合权重 |
| | `weight_*` | 非混淆子集融合权重 |
| `continual_cache` | `fusion_weight: 0.28` | 缓存修正强度 |
| | `max_size: 5000` | 缓存容量上限 |
| | `use_vision_keys: true` | 字节图视觉 Key |
| `evolution` | `online_rl_enabled: true` | Online RL 开关 |

---

## 实验套件

| 编号 | 名称 | 脚本/结果 | 状态 |
|------|------|-----------|------|
| E1 | 整体检测 | `evaluate.py` → `v2_exp1_overall.json` | ✅ |
| E2 | 未知混淆 | `run_experiments_suite.py` → `v2_exp2_unknown.json` | ✅ |
| E3 | 对抗鲁棒性 | `run_adversarial.py` → `v2_exp3_*.csv` | ✅ |
| E4 | 延迟 | `benchmark_latency.py` → `v2_exp4_latency.json` | ✅ |
| E5 | 消融 | `run_experiments_suite.py` → `v2_exp5_ablation.json` | ✅ |
| E6 | 可解释性 | `eval_explainability.py` → `v2_exp6_localization.json` | ✅ |
| E7 | Online RL | `run_experiments_suite.py` → `v2_exp7_evolution.json` | ✅ |
| E8 | 虚拟补丁 | `run_experiments_suite.py` → `v2_exp8_virtual_patch.json` | ✅ |
| — | 多模态消融 | `compare_multimodal_full.py` → `v2_compare_multimodal_full.json` | ✅ |

---

## 文档索引

| 路径 | 内容 |
|------|------|
| `docs/FINAL_SYSTEM.md` | 系统说明、已知问题与修复记录 |
| `docs/PROJECT.md` | 六层架构与八大模块（设计稿） |
| `docs/EXPERIMENTS.md` | 七组实验设计 |
| `research/agent1_literature/` | 论文与社区情报 |
| `research/agent2_integration/SCHEME_V3.md` | 3.0 方案解读 |
| `research/agent2_integration/EXPERIMENT_REPORT.md` | 实验终稿 |
| `research/agent2_integration/MULTIMODAL.md` | 多模态条件融合 |
| `AGENTS.md` | 多 Agent 协作总览 |
| `configs/default.yaml` | 生产配置 |

---

## 创新点（答辩）

1. **四模态条件融合**：混淆/非混淆分权 + 门控，多模态开/关 Δ 仅 −0.12 pp  
2. **Tip-Adapter 持续学习缓存**：552 条双 Key 库，漏检扩库无需全量重训  
3. **强/弱混淆分层 + FP 护栏**：评测与检测解耦，抑制误报翻判  
4. **WebSpotter 恶意高亮**（IoU +37.9%）+ **对抗演化闭环**
