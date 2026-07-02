# IGA-Guard 2.0 周验收签收记录

> 周验收已并入 `iga_system.py pipeline` + `tests/`；历史记录见下表  
> 关联：[`RUNNABLE_PLAN.md`](RUNNABLE_PLAN.md) §八-A

| 周次 | 执行日期 | 执行人 | 命令 | 结果 | 阻塞项 | 签字 |
|------|----------|--------|------|------|--------|------|
| W0 | | | `pip install` + `train.py` + `run.py` | ☐ PASS | | |
| W1 | | | `week_acceptance.ps1 -Week 1` | ☐ PASS | — | buffer已接入 |
| W2 | | | `week_acceptance.ps1 -Week 2` | ☐ PASS | train_bert.py | |
| W3 | | | `week_acceptance.ps1 -Week 3` + curl 大屏 | ☐ PASS | highlight_html | |
| W4 | | | `week_acceptance.ps1 -Week 4` | ☐ PASS | run_adversarial.py | |
| W5 | | | `week_acceptance.ps1 -Week 5` + 演示排练 | ☐ PASS | — | |

## 指标快照（每周填写）

| 周次 | Macro-F1 | 混淆 Recall | P50 (ms) | P99 (ms) | IoU Δ | 备注 |
|------|----------|-------------|----------|----------|-------|------|
| W1 | | | | | — | buffer已接入（`timeseries_buffer` → `pipeline` → `dual_track`） |
| W2 | | | | | — | |
| W3 | | | | | | |
| W4 | | | | | | |
| W5 | | | | | | |
