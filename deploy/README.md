# IGA-Guard 3.0 服务器部署

## 目录

```
IGA-Guard/
├── deploy/                 # 部署脚本（本目录）
│   ├── setup_env.sh        # 镜像与环境变量
│   ├── run_eval_full.sh    # 全量诚实评测
│   ├── start_tmux.sh       # tmux 后台运行
│   └── logs/               # 运行日志
└── topics/topic02_web_waf/ # 作品主目录（或 IGA-guard/topics/...）
```

## 快速开始

```bash
cd /root/autodl-tmp/IGA-Guard
bash deploy/start_tmux.sh          # tmux 后台全量评测
tmux attach -t iga                 # 查看进度
tail -f deploy/logs/eval_full.log  # 看日志
```

## 手动运行

```bash
source deploy/setup_env.sh
cd topics/topic02_web_waf
python scripts/iga_system.py status
python scripts/iga_system.py evaluate --max-samples 0
```

## 目标指标（诚实全量 19411）

| 指标 | 目标 |
|------|------|
| 混淆 Recall | >99.5% |
| Normal FPR | <3% |
| P50 | <5ms |

最新仓库内参考结果：`topics/topic02_web_waf/results/v2_exp1_overall.json`
