# IGA-Guard VPS 流量转发 — 即插即用部署

## 架构

```
Internet → VPS:80 (nginx) → IGA Proxy:8080 → 检测 → 阻断/转发 → 你的后端 :3000
                                    ↓
                            管理 API :5000 (大屏/红队/指标)
```

## 最快启动（3 步）

```bash
# 1. 进入项目并配置上游（你的 Web 应用地址）
cd /root/autodl-tmp/IGA-Guard
export IGA_UPSTREAM_URL=http://127.0.0.1:3000   # 改成真实后端

# 2. 一键启动代理 + 管理 API
./deploy/start_vps.sh --upstream "$IGA_UPSTREAM_URL"

# 3. 验收
curl -s http://127.0.0.1:8080/_iga/health | python3 -m json.tool
curl -s "http://127.0.0.1:8080/?id=1"          # 正常流量 → 转发到 upstream
curl -s "http://127.0.0.1:8080/?p=1%20union%20select%201--"  # 攻击 → 403
```

## 代理模式

| 模式 | 行为 |
|------|------|
| `inline`（默认） | 检测恶意请求 → 403 阻断；正常请求 → 转发 upstream |
| `detect-only` | 始终转发，仅记录（适合灰度） |
| `mirror` | 异步旁路检测 + 始终转发 |

```bash
IGA_PROXY_MODE=detect-only ./deploy/start_vps.sh --upstream http://127.0.0.1:3000
```

## 公网 VPS 部署

```bash
# 安装依赖 + systemd + nginx(:80→:8080)
sudo ./deploy/install_vps.sh --nginx

# 启动服务
./deploy/start_vps.sh --upstream http://127.0.0.1:3000

# 防火墙
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp   # 若后续加 TLS
```

DNS：将域名 A 记录指向 VPS 公网 IP，访问 `http://your-domain/` 即自动过 IGA-Guard。

## 环境变量

| 变量 | 说明 | 默认 |
|------|------|------|
| `IGA_UPSTREAM_URL` | 后端应用 URL | `http://127.0.0.1:3000` |
| `IGA_PROXY_MODE` | inline / detect-only / mirror | inline |
| `IGA_CONFIG` | 配置文件 | `configs/proxy.yaml` |
| `IGA_PROXY_PORT` | 代理监听端口 | 8080 |
| `IGA_API_PORT` | 管理 API 端口 | 5000 |

## 配置文件

`configs/proxy.yaml` — 继承 `default.yaml` 检测能力，额外配置：

- `proxy.upstream_url` — 转发目标
- `proxy.block_on_malicious` — 是否阻断
- `proxy.exclude_paths` — 跳过检测的路径前缀

## systemd 开机自启

```bash
sudo systemctl enable --now iga-guard-proxy
sudo journalctl -u iga-guard-proxy -f
```

## 与评测脚本的区别

| 脚本 | 用途 |
|------|------|
| `deploy/run_eval_full.sh` | AutoDL 全量评测 |
| `deploy/run_auto_verify.sh` | 自动验收 |
| `deploy/start_vps.sh` | **VPS 生产流量转发** |

## 故障排查

```bash
tail -f deploy/logs/iga_proxy.log
curl http://127.0.0.1:8080/_iga/stats
# 确认 upstream 可达
curl -I "$IGA_UPSTREAM_URL"
```
