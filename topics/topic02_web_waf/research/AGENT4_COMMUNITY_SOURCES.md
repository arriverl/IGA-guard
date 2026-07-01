# Agent 4 · 安全社区情报来源

> 将 FreeBuf、先知社区等公开 writeup 中的 WAF 绕过 / SQLi / XSS 载荷落地到训练数据集。

## 数据源

| 来源 | 类型 | 抓取方式 | 本地路径 |
|------|------|----------|----------|
| **FreeBuf RSS** | 安全资讯 feed | `https://www.freebuf.com/feed` | `data/raw/community/cache/freebuf_rss.html` |
| **FreeBuf 搜索** | WAF/SQLi 关键词 | 公开搜索页 HTML | `cache/freebuf_search_*.html` |
| **先知社区** | 阿里云公开 writeup | `https://xz.aliyun.com/` 列表页 | `cache/xianzhi_index.html` |
| **本地种子** | 手工整理载荷 | 无需网络 | `data/raw/community/payloads_seed.txt` |

## 实现模块

- `src/iga_guard/dataset/community_fetcher.py`
  - `fetch_community_articles()` — 拉取标题与链接（遵守 robots.txt）
  - `parse_payloads_from_text()` — 从正文/种子提取载荷行
  - `iter_community_payloads()` — 合并种子 + 文章正文载荷
  - `collect_community_rows()` — 供 `dataset_agent.py` 调用

## robots 与失败回退

1. 每次 HTTP 请求前检查目标站点 `robots.txt`
2. 请求间隔 ≥ 1s，User-Agent: `IGA-Guard-CommunityFetcher/1.0`
3. 网络失败或 robots 禁止时：
   - 自动回退到 `payloads_seed.txt`（≥200 条真实载荷）
   - 控制台打印手动补充说明

### 手动补充步骤

```text
1) 打开 https://www.freebuf.com 搜索「WAF绕过」「SQL注入」「XSS」
2) 打开 https://xz.aliyun.com 浏览公开 writeup
3) 将载荷追加到 data/raw/community/payloads_seed.txt（每行一条，# 标注来源）
4) 重新运行: python scripts/dataset_agent.py --skip-fetch --skip-community-fetch
```

## 种子文件说明

`data/raw/community/payloads_seed.txt` 内容来自：

- SecLists Generic-SQLi / XSS-Jhaddix / Polyglot 风格
- WAF 绕过 writeup 常见手法（内联注释、双重编码、HPP、multipart、JSON 嵌套）
- Unicode 规范化与分块传输模拟样本

**非随机生成**；每行一条 payload，`#` 开头为来源注释。

## 混淆扩充（社区手法）

`obfuscation_techniques.py` 新增 5 种社区常见绕过：

| 技术名 | 说明 |
|--------|------|
| `hpp_duplicate_param` | HTTP 参数污染（重复参数名） |
| `multipart_boundary_sim` | multipart 边界混淆 |
| `json_nested_escape` | JSON 嵌套键逃逸 |
| `unicode_normalization` | Unicode 全角/兼容字符绕过 |
| `chunked_whitespace` | 分块传输思路（关键字间 %0d%0a） |

## 一键命令

```powershell
cd d:\Code_development\gitproduct\caisa_contest_2026\topics\topic02_web_waf
$env:PYTHONPATH="src"

# 全流程（含社区种子，跳过在线社区文章）
python scripts/dataset_agent.py --skip-csic-download --skip-fetch --skip-community-fetch

# 尝试在线拉取社区文章（需网络）
python scripts/dataset_agent.py --skip-csic-download --skip-fetch
```

## 合并到 master 数据集

`dataset_agent.py` 合并顺序：

```
seed → public (SecLists/FuzzDB/PAT) → community → CSIC
```

产出：`data/master/full.csv`（去重基线）、`full_obfuscated.csv`（混淆扩充）。

## 参考链接

- [FreeBuf](https://www.freebuf.com/)
- [先知社区](https://xz.aliyun.com/)
- [SecLists](https://github.com/danielmiessler/SecLists)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- WAFFLED / ModSec-AdvLearn 相关 WAF 绕过文献
