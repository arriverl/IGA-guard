# IGA-Guard 3.0 服务器部署

## 目录

```
IGA-Guard/
├── deploy/                      # 部署脚本（本目录）
│   ├── setup_env.sh             # 环境变量
│   ├── start_vps.sh             # VPS 即插即用（API + Inline 代理）
│   ├── install_vps.sh           # systemd + 可选 nginx
│   ├── run_auto_verify.sh       # 全自动检验
│   ├── gunicorn.conf.py         # API 生产配置
│   └── systemd/                 # systemd unit 模板
└── topics/topic02_web_waf/      # 作品主目录
```

## 快速开始

### 本地 / 服务器评测

```bash
source deploy/setup_env.sh
cd topics/topic02_web_waf
python scripts/run_auto_verify.py
bash scripts/clean_artifacts.sh --dry-run   # 预览可删中间产物
```

### VPS 流量代理

```bash
bash deploy/start_vps.sh --upstream http://YOUR_BACKEND:3000
# 流量入口 :8080  管理 API :5000
bash deploy/install_vps.sh --nginx          # 可选 nginx 反代
```

## 目标指标（Dynamic Guard 终稿）

| 指标 | 目标 | 当前参考 |
|------|------|----------|
| 混淆 Recall（2k） | >99.5% | 99.91% |
| Normal FPR（2k） | <5% | 4.32% |
| P50 / P99 | <5ms / 实用 | 0.068ms / 13.3ms |

权威结果：`topics/topic02_web_waf/results/canonical_metrics.json`

## 产物清理

仅删除**中间迭代**快照，保留：

- `models/tinybert_waf/checkpoint-34380/` + 根目录 `model.safetensors`
- 最新结果 JSON（v21/v22、auto_*、overall_dynamic_guard_final）
- 主日志（训练/全量评测/延迟）

详见 [`topics/topic02_web_waf/docs/ARTIFACTS.md`](../topics/topic02_web_waf/docs/ARTIFACTS.md)
