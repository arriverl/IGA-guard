# IGA-Guard 2.0 — Agent 与进程总览

## 一键全量启动（推荐）

```powershell
cd d:\Code_development\gitproduct\caisa_contest_2026\topics\topic02_web_waf
powershell -ExecutionPolicy Bypass -File scripts\start_everything.ps1
```

启动内容：pip → 10k 数据集 → RF 训练 → **并行** TinyBERT / 对抗实验 / Web 服务 → 评估脚本

日志：`logs/` · 任务队列：`research/AGENT_QUEUE.md`

---

## Agent 角色

| ID | 角色 | 目录 | 下一任务 |
|----|------|------|----------|
| A1 | 情报研究员 | `research/agent1_literature/` | 混淆逃逸 SOTA + CSIC 下载脚本 |
| A2 | 方案架构师 | `research/agent2_integration/` | 实验报告 + 作品报告提纲 |
| A3 | 工程实现 | `src/iga_guard/` | TinyBERT 本地加载 + 前端六页 |
| E1 | 检测引擎 | `detector/dual_track.py` | 已标注 ✓ |
| E2 | DLinear 时序 | `collector/timeseries_buffer.py` | 已标注 ✓ |
| S1 | Web 服务 | `run.py :5000` | 随 start_everything 启动 |

## 访问地址

- 大屏：http://127.0.0.1:5000/
- 健康：http://127.0.0.1:5000/api/health

## 代码注释说明

核心模块均已添加模块级中文 docstring：
- `pipeline.py` — 主流水线数据流
- `timeseries_buffer.py` — DLinear 时序输入
- `dual_track.py` — 双路融合权重
- `dlinear_branch.py` / `webspotter.py` / `semantic_branch.py`
