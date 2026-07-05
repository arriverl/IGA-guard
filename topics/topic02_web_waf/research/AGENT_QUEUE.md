# IGA-Guard 3.0 Agent 任务队列与进程状态
# 更新方式: 各 Agent 完成后在此勾选；统一入口 `scripts/iga_system.py`

## 常驻服务

| 进程 | 命令 | 端口/输出 | 状态 |
|------|------|-----------|------|
| Web API + 大屏 | `python run.py` | :5000 | **运行中** http://127.0.0.1:5000/ |
| TinyBERT 训练 | `python scripts/train_bert.py` | models/tinybert_waf/ | **运行中** ~35%+ 见 logs/train_bert_*.err |
| 对抗实验 E3 | `python scripts/run_adversarial.py` | results/v2_exp3_* | **运行中** 见 logs/adversarial_*.log |

## Agent 任务队列（完成后接下一项）

### Agent 1 · 情报研究员
- [x] LITERATURE_REVIEW.md + 4 篇思路卡片
- [x] datasets.md + baselines.md
- [x] **已完成**: 2024-2026 混淆逃逸 SOTA → `papers/05_evasion_sota_2024_2026.md`
- [x] **已完成**: CSIC2010 下载脚本 → `scripts/download_csic.py`

### Agent 2 · 方案架构师
- [x] RUNNABLE_PLAN + ADR + MODULE_MAPPING + INNOVATION
- [x] **已完成**: `research/agent2_integration/EXPERIMENT_REPORT.md`
- [x] **已完成**: 作品报告提纲 → `docs/WORK_REPORT_OUTLINE.md`

### Agent 3 · 工程实现
- [x] timeseries_buffer + dual_track + highlight_html
- [x] **已完成**: semantic_branch 加载本地 TinyBERT 权重 + 关键词回退
- [x] **已完成**: dashboard field_contributions ECharts 横向条形图
- [x] **已完成**: `tests/test_pipeline_smoke.py`（3 条冒烟 + 10 测试全通过）
- [x] **已完成**: 前端六页拆分 → `frontend/static/p1_monitor.html` … `p6_rules.html` + `hub.html`
- [x] **已完成**: 混淆逃逸兜底 `obfuscated_evasion_rescue` + pipeline 恶意优先合并
- [x] **已完成**: evaluate.py URL 编码/POST body 修复（含 `&` 载荷不再被 query 截断）
- [x] **已完成**: 全量重评 n=19,411 → 混淆 **99.95%** / FPR **5.63%** / 漏检 **5**（`v2_exp1_overall.json`）
- [x] **已完成**: 自我迭代闭环 `auto-evolve` — 漏检发现新手法 → 动态注册表 → 扩缓存/重训
- [ ] **下一项**: FPR 压至 <3% + EXPERIMENT_REPORT 刷新

### Agent 4 · 数据集采集代理（新增）
- [x] **核心库** `src/iga_guard/dataset/` — CSIC 解析、公开源拉取、20+ 混淆技术、合并划分
- [x] **入口** `scripts/dataset_agent.py` — 拉取 SecLists/FuzzDB/PAT + CSIC + 混淆扩充
- [x] **全流程** `scripts/iga_system.py pipeline` — 数据集 → RF + TinyBERT → 评估
- [x] **验收**: 社区种子 `payloads_seed.txt` + `community_fetcher.py` 已集成；`full_obfuscated.csv` 可达 15 万行

```powershell
python scripts/dataset_agent.py
python scripts/iga_system.py pipeline --skip-bert  # 或完整含 BERT
python scripts/iga_system.py status
```

日志目录: `logs/`
