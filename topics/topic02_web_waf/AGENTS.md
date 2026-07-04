# IGA-Guard 3.0 — Agent 与进程总览

## 统一入口（推荐）

```powershell
cd d:\Code_development\gitproduct\caisa_contest_2026\topics\topic02_web_waf
$env:PYTHONPATH="src"
python scripts/iga_system.py status
python scripts/iga_system.py pipeline    # 数据集 → 训练 → 评估 → 对抗
python scripts/iga_system.py serve       # Web 大屏
```

日志：`logs/` · 任务队列：`research/AGENT_QUEUE.md`

---

## Agent 角色

| ID | 角色 | 目录 | 下一任务 |
|----|------|------|----------|
| A1 | 情报研究员 | `research/agent1_literature/` | 混淆逃逸 SOTA + CSIC 下载脚本 |
| A2 | 方案架构师 | `research/agent2_integration/` | 实验报告 + 作品报告提纲 |
| A3 | 工程实现 | `src/iga_guard/` | 混淆 Recall 提升 + 决赛答辩排练 |
| E1 | 检测引擎 | `detector/dual_track.py` | 已标注 ✓ |
| E2 | DLinear 时序 | `collector/timeseries_buffer.py` | 已标注 ✓ |
| S1 | Web 服务 | `run.py :5000` | `iga_system.py serve` |

## 访问地址

- 大屏：http://127.0.0.1:5000/
- 健康：http://127.0.0.1:5000/api/health

## 代码注释说明

核心模块均已添加模块级中文 docstring：
- `pipeline.py` — 主流水线数据流
- `timeseries_buffer.py` — DLinear 时序输入
- `dual_track.py` — 双路融合权重
- `dlinear_branch.py` / `webspotter.py` / `semantic_branch.py`
