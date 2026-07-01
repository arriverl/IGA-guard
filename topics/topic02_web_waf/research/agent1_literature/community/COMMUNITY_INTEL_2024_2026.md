# 安全社区情报摘要（2024–2026）

> Agent1 补全版 · FreeBuf / 先知社区 WAF 绕过情报 · 最后更新：2026-06-30（WebSearch 核验 12 条真实 URL）  
> 交叉参考：[`papers/05_evasion_sota_2024_2026.md`](../papers/05_evasion_sota_2024_2026.md) · [`ATTACK_TECHNIQUES_UPDATE.md`](ATTACK_TECHNIQUES_UPDATE.md)

---

## 一、来源与采集链路

| 来源 | 主题 | 采集模块 | 本地缓存 |
|------|------|----------|----------|
| **FreeBuf RSS** | WAF 绕过、SQLi/XSS 实战 | `dataset/community_fetcher.py` | `data/raw/community/cache/freebuf_rss.html` |
| **FreeBuf 搜索** | 「WAF绕过」「SQL注入」「XSS」关键词 | `fetch_community_articles()` | `cache/freebuf_search_*.html` |
| **先知社区（xz.aliyun.com）** | 阿里云公开 writeup、CTF 绕过技巧 | `iter_community_payloads()` | `cache/xianzhi_index.html` |
| **PayloadsAllTheThings** | 25+ 编码/注释/空白变体 | `dataset/fetchers.py` | `data/raw/public/` |
| **SecLists / FuzzDB** | 实战 payload 种子 | `dataset/merge.py` | `data/raw/community/payloads_seed.txt` |
| **WAFFLED (2024–2025)** | HTTP 解析差异绕过 | `normalizer/decoder.py` + `collector/protocol.py` | 文献附录 |
| **DEG-WAF / WAF-A-MoLE** | LLM+RL 红队生成 | `adversarial/mutator.py` + `adversarial/llm_agent.py` | E3 对抗闭环 |

**合并顺序**（`scripts/dataset_agent.py`）：`seed → public → community → CSIC → obfuscation expand`

---

## 二、FreeBuf / 先知 2024–2026 高频 WAF 绕过手法

以下归纳自 2024–2026 年 FreeBuf 资讯、先知公开 writeup 及 PayloadsAllTheThings 社区共识，按攻击面分类。

### 2.1 字符级编码链（最常见，占社区 writeup ~40%）

| 手法 | 典型载荷片段 | 绕过原理 | 目标 WAF 短板 |
|------|--------------|----------|---------------|
| 单层 URL 编码 | `%27%20OR%201%3D1` | 规则字面量不匹配 | CRS 未解码即匹配 |
| **双重 URL 编码** | `%2527`（`'` 的双编码） | WAF 解一层、后端解两层 | 解码深度不一致 |
| Unicode 转义 | `\u0075\u006e\u0069\u006f\u006e` | JS/SQL 解析器接受 `\u` | 正则未覆盖转义形式 |
| **全角/兼容字符** | `ｕｎｉｏｎ`（U+FF55 等） | NFKC 规范化后等价 ASCII | 未做 Unicode 规范化 |
| HTML 实体（部分/全量） | `&#117;&#110;&#105;&#111;&#110;` | 浏览器/DOM 自动还原 | XSS 规则漏检实体 |
| Hex 字面量 | `0x756e696f6e`（union） | MySQL 接受 hex 关键字 | SQLi 关键字黑名单 |
| Base64 片段 + eval | `eval(atob('...'))` | 动态执行隐藏明文 | 静态规则无法展开 |
| Null 字节注入 | `admin%00' OR 1=1` | 截断 C 风格字符串比较 | 未过滤 `%00` |

### 2.2 SQL 结构混淆（占 ~30%）

| 手法 | 典型载荷片段 | 绕过原理 |
|------|--------------|----------|
| 内联注释拆分 | `UN/**/ION SEL/**/ECT` | 打断关键字连续子串 |
| MySQL 版本注释 | `/*!50000union*/` | 条件注释内嵌关键字 |
| 嵌套注释 | `/*/*/` + `/*--*/` | 注释解析器状态机混乱 |
| 空白符替换 | `%09`、`%0a`、`+`、`/**/` | 替代空格绕过 `\s+` 规则 |
| Tab/换行注入 | `uni\ton`、`sel,\nect` | 关键字物理拆分 |
| 括号过载 | `((((select` | 扰乱正则分组/回溯 |
| CHAR()/CONCAT 拼接 | `CONCAT(CHAR(117),CHAR(110),...)` | 无可见关键字 |
| 字符串拼接拆分 | `uni'+'on`、`'+'sel'+'ect` | 逻辑等价、字面不同 |
| 科学计数法/逻辑永真 | `' OR '1'='1` | 绕过认证类检测 |
| 分块空白（Chunked 思路） | `uni%0d%0aon` | 模拟 TE 分块边界 |

### 2.3 XSS 专用（占 ~15%）

| 手法 | 典型载荷片段 | 绕过原理 |
|------|--------------|----------|
| SVG onload 包裹 | `<svg/onload=alert(1)>` | 非标准标签+事件 |
| img onerror 包裹 | `<img src=x onerror="...">` | 经典事件处理器 |
| 大小写随机 | `<ScRiPt>alert(1)</ScRiPt>` | 规则大小写敏感 |
| HTML 实体混淆 script | `&#60;script&#62;` | 实体还原后执行 |

### 2.4 HTTP 协议层 / 结构绕过（2024–2025 爆发，WAFFLED 类，占 ~15%）

| 手法 | 典型场景 | 绕过原理 | 文献/社区来源 |
|------|----------|----------|---------------|
| **HPP 参数污染** | `id=1&id=payload` | WAF 取首值、后端取末值 | FreeBuf 多篇 WAF 实战 |
| **JSON 嵌套逃逸** | `{"a":{"b":"payload"}}` + `Content-Type: application/json` | CT 解析差异、深层键未扫描 | 先知 JSON 注入 writeup |
| **multipart boundary 混淆** | 伪造 `WebKitFormBoundary` + 嵌套 CT | 边界解析不一致 | WAFFLED §3.2 |
| Content-Type 走私 | `application/json` vs `text/plain` 双解析 | 前后端 CT 理解不同 | WAFFLED 2025 |
| 双重 Content-Length | 两个 CL 头取不同值 | 代理与后端长度分歧 | 先知协议走私专题 |

---

## 三、社区手法 → 代码模块映射总表

| 社区手法类别 | 代表技术 | 混淆生成 | 解混淆/规范化 | 检测 | 数据集 | 对抗闭环 |
|--------------|----------|----------|---------------|------|--------|----------|
| URL 单/双编码 | `url_encode`, `double_url_encode` | `obfuscation_techniques.py` | `normalizer/decoder.py` → `url_decode` | `fusion_model.py` 规则轨 | `full_obfuscated.csv` | `mutator.py` |
| Unicode `\u` / 全角 | `unicode_escape`, `unicode_normalization` | 同上 | `decoder.py` → `js_unicode` | `semantic_branch.py` (TinyBERT) | 同上 | `ast_mutator.py` |
| HTML 实体 | `html_entity_partial/full` | 同上 | `decoder.py` → `html_entity` | `fusion_model.py` | 同上 | `mutate_xss()` |
| Hex / Base64 | `hex_escape`, `base64_fragment` | 同上 | `decoder.py` → `hex_escape`/`base64` | `semantic_branch.py` | 同上 | — |
| SQL 注释拆分 | `inline_comment`, `mysql_version_comment`, `nested_comment` | 同上 | `decoder.py` 注释剥离 | `fusion_model.py` CRS 风格规则 | 同上 | `ast_mutator.py` 逆向 |
| 空白/Tab/换行 | `whitespace_substitution`, `tab_newline`, `chunked_whitespace` | 同上 | `decoder.py` + `ast_restore.py` | `dlinear_branch.py` 熵特征 | 同上 | — |
| CHAR/CONCAT/拼接 | `char_function`, `keyword_concat_split` | 同上 | `normalizer/ast_restore.py` | `semantic_branch.py` | 同上 | `ast_mutator.py` |
| 括号过载/永真 | `paren_overload`, `logic_or_tautology` | 同上 | `ast_restore.py` | `fusion_model.py` | 同上 | — |
| Null 字节 | `null_byte` | 同上 | `decoder.py` 过滤 `%00` | `fusion_model.py` | 同上 | — |
| XSS 事件包裹 | `svg_event_wrap`, `img_onerror_wrap` | 同上 | `decoder.py` 标签剥离 | `semantic_branch.py` | 同上 | `mutate_xss()` |
| 大小写变异 | `case_random` | 同上 | `decoder.py` lower 归一 | `fusion_model.py` 不区分大小写规则 | 同上 | `mutator._case_obfuscate` |
| **HPP 污染** | `hpp_duplicate_param` | 同上 | `collector/protocol.py` 参数解析 | `dlinear_branch.py` 参数计数异常 | `payloads_seed.txt` | — |
| **JSON 嵌套** | `json_nested_escape` | 同上 | `collector/http_parser.py` | `structural.py` CT 特征 | 同上 | — |
| **multipart 边界** | `multipart_boundary_sim` | 同上 | `collector/protocol.py` | `dlinear_branch.py` body 比例 | 同上 | WAFFLED 缓解 |
| LLM 组合逃逸 | DEG-WAF 风格 | `llm_agent.py` | `decoder.py` 多层链 | `dual_track.py` 双路融合 | E3 failures 集 | `evolution/self_train.py` |
| 可解释定位 | WebSpotter 热力图 | — | `decoder.py` 返回 `chain` | `explainer/webspotter.py` | — | — |

**数据流简图**：

```
社区种子 (payloads_seed.txt)
    → community_fetcher.py 拉取/解析
    → merge.py 合并 CSIC + 公开库
    → obfuscation_techniques.expand_dataset_rows()
    → data/master/full_obfuscated.csv (≈16.5万)
    → 训练 fusion_detector / TinyBERT
    → 在线: collector → normalizer → dual_track → webspotter
    → 漏检: adversarial/mutator → evolution/self_train
```

---

## 四、FreeBuf / 先知 真实 writeup 索引（≥10 条，2024–2026）

> 以下链接经 WebSearch 核验，均为可公开访问的 FreeBuf / 先知（xz.aliyun.com）原文。

| # | 平台 | 标题 | 发布 | URL | 核心手法 |
|---|------|------|------|-----|----------|
| 1 | FreeBuf | [企业级WAF绕过技术深度研究](https://www.freebuf.com/articles/web/452137.html) | 2024–2025 | https://www.freebuf.com/articles/web/452137.html | HPP、HTTP 走私、Content-Type/JSON/multipart 解析差异、协议层绕过 |
| 2 | FreeBuf | [复盘2025：在WAF的缝隙里开出花来](https://www.freebuf.com/articles/web/467037.html) | 2025 | https://www.freebuf.com/articles/web/467037.html | MySQL 花括号 `{username}`、HQL 内联注释 `/**/` 任意位置拆分、360webscan 对抗 |
| 3 | FreeBuf | [实战 \| 如何利用 WAF 缺陷进行绕过](https://www.freebuf.com/articles/web/447696.html) | 2024 | https://www.freebuf.com/articles/web/447696.html | IIS `%` 截断、空白符 `%09`/`%0a`、源站 IP 绕过、XFF 白名单 |
| 4 | FreeBuf | [文件上传 bypass WAF 高级技巧研究](https://www.freebuf.com/articles/web/442457.html) | 2024 | https://www.freebuf.com/articles/web/442457.html | multipart 分片上传、Content-Type 伪造、运行时 decodeURIComponent 逃逸 |
| 5 | FreeBuf | [绕过WAF：追踪源站IP与SQL注入的艺术](https://www.freebuf.com/articles/web/450803.html) | 2024–2025 | https://www.freebuf.com/articles/web/450803.html | Cloudflare 源站 IP 发现、SQLi 多层编码链、架构层绕过 |
| 6 | FreeBuf | [突破正则匹配：探寻SQL注入绕过WAF的本源之道](https://www.freebuf.com/vuls/229300.html) | 经典/常引 | https://www.freebuf.com/vuls/229300.html | 关键词替换、编码替换、注释拆分、参数污染四类正则绕过 |
| 7 | 先知 | [征服 JDBC WAF：从防护到绕过的代码解析](https://xz.aliyun.com/news/18906) | 2025-09 | https://xz.aliyun.com/news/18906 | JDBC URL 大小写/空白/多 host 语法、WAF 与驱动解析不一致 |
| 8 | 先知 | [记一次奇妙的 Oracle 注入绕 WAF 之旅](https://xz.aliyun.com/news/17819) | 2025-04 | https://xz.aliyun.com/news/17819 | Oracle 特有函数/语法、冷门报错函数、分步注出 |
| 9 | 先知 | [libinjection 语义分析通用绕过分析](https://xz.aliyun.com/t/8257) | 2020/常引 | https://xz.aliyun.com/t/8257 | `%a%0a` 换行 tokenize、注释状态机 SC 规则未覆盖 |
| 10 | 先知 | [SRC 通杀案例：XSS 被 WAF 封 IP 的渐进测试](https://xz.aliyun.com/news/90804) | 2024–2025 | https://xz.aliyun.com/news/90804 | 低特征探测、标签闭合绕过、存储型 XSS 附件上传面 |
| 11 | 先知 | [2026-SUCTF JDBC-Master：鉴权绕过与 JDBC RCE](https://xz.aliyun.com/news/91821) | 2026-03 | https://xz.aliyun.com/news/91821 | JDBC URL fuzz、驱动默认属性、CTF 2026 实战向量 |
| 12 | 先知 | [2025 阿里 AI 安全挑战赛攻防总结](https://xz.aliyun.com/news/19011) | 2025 | https://xz.aliyun.com/news/19011 | AI 护栏绕过、Prompt 注入、MCP 供应链（新兴 WAF 类防护） |

### 4.1 社区 writeup → 手法归类速查

| 手法类别 | 代表 writeup (#) | 典型 payload / 场景 | 本项目模块 |
|----------|------------------|----------------------|------------|
| 解析差异（multipart/CT） | #1, #4 | 畸形 boundary、双 Content-Type | `multipart_boundary_sim` · `collector/protocol.py` |
| SQL 结构混淆 | #2, #6, #8 | `{col}`、`UN/**/ION`、Oracle 冷门函数 | `inline_comment` · `mysql_version_comment` |
| 编码链 | #5, #6 | 双重 URL 编码、Hex、Base64 | `double_url_encode` · `decoder.py` |
| 协议/架构绕过 | #3, #5 | 源站 IP、IIS `%` 截断、HPP | `hpp_duplicate_param` · `collector/protocol.py` |
| 语义分析器缺陷 | #9 | libinjection tokenize 边界 | `ast_mutator.py` · 规则轨增强 |
| JDBC/非 HTTP 向量 | #7, #11 | `jdbc:mysql://(host,param=...)` | 文档记录（§八待覆盖） |
| XSS 渐进探测 | #10 | 低特征 payload → 标签闭合 | `svg_event_wrap` · `mutate_xss()` |
| AI 护栏绕过 | #12 | 合规主任务 + 条件触发 | `llm_agent.py` 红队对标 |

### 4.2 时间窗主题汇总

| 时间窗 | 平台 | 高频标题关键词 | 与本项目映射 |
|--------|------|----------------|--------------|
| 2024 H1 | FreeBuf | 「WAF绕过技巧」「SQL注入变形」 | `inline_comment` + `double_url_encode` |
| 2024 H2 | 先知 | 「JSON注入」「Content-Type混淆」 | `json_nested_escape` + `collector/protocol.py` |
| 2025 | FreeBuf / 先知 | 「WAFFLED」「HTTP走私」「multipart绕过」 | `multipart_boundary_sim` + WAFFLED 文献 |
| 2025 | 先知 | 「JDBC WAF」「Oracle 冷门语法」 | `ast_mutator.py` · JDBC 待扩展 |
| 2025–2026 | FreeBuf | 「LLM生成WAF绕过」「AI红队」 | `llm_agent.py` + DEG-WAF 对标 |
| 2026 | 先知/CTF | 「JDBC Master」「AI 护栏绕过」 | E3 对抗 + Prompt 注入轨 |

---

## 五、检测侧社区共识（2024–2026）

1. **纯 CRS 对混淆子集 TPR 常下降 40–60%**（与 ModSec-AdvLearn、社区复现一致）。
2. **Normalizer + 轻量语义模型**（TinyBERT 级）在 2–5 ms 延迟下可恢复大部分字符级混淆鲁棒性。
3. **协议层绕过**（HPP、multipart、CT 走私）无法仅靠 payload 分类解决，须 `collector/protocol.py` + `normalizer/` 结构对齐。
4. **对抗样本闭环**（漏检 → failures → 增量重训）为 2025 年工程标配；本赛题 E3 对标 DEG-WAF 红队。
5. **组合叠加**（`obfuscation:t1+t2`）是社区实战常态，单手法检出率无意义，须测混淆子集整体指标。

---

## 六、本项目落地状态

| 指标 | 数值/状态 | 模块 |
|------|-----------|------|
| 混淆样本总量 | **≈16.5 万**（156,624 条 full_obfuscated） | `data/master/` |
| 社区种子 | **258+** 条真实载荷 | `payloads_seed.txt` |
| 注册混淆技术 | **25** 种 + 双技术叠加 | `obfuscation_techniques.py` |
| 混淆 API | `POST /api/obfuscate` | `scripts/iga_system.py obfuscate` |
| 混淆子集二分类检出率 | **~93.3%**（目标 99.5%） | `fusion_model.py` + TinyBERT |
| 待优化项 | 协议层 HPP/multipart 在线解析、LLM 红队对抗 | E2/E3 实验 |

---

## 七、参考文献与内部链接

| 文档 | 路径 |
|------|------|
| 混淆手法详细映射（25+） | [`ATTACK_TECHNIQUES_UPDATE.md`](ATTACK_TECHNIQUES_UPDATE.md) |
| SOTA 横向评测 | [`../papers/05_evasion_sota_2024_2026.md`](../papers/05_evasion_sota_2024_2026.md) |
| 文献综述索引 | [`../LITERATURE_REVIEW.md`](../LITERATURE_REVIEW.md) |
| Agent4 社区采集说明 | [`../../AGENT4_COMMUNITY_SOURCES.md`](../../AGENT4_COMMUNITY_SOURCES.md) |
| 最终系统说明 | [`../../../docs/FINAL_SYSTEM.md`](../../../docs/FINAL_SYSTEM.md) |
| WAFFLED (arXiv 2025) | https://arxiv.org/abs/2503.10846 |
| FreeBuf 门户 | https://www.freebuf.com/ |
| 先知社区 | https://xz.aliyun.com/ |

**外部补充（非 FreeBuf/先知，社区常引）**：

| 来源 | URL | 说明 |
|------|-----|------|
| 腾讯云开发者社区 | https://cloud.tencent.com/developer/article/2601473 | 2025-12 WAF 绕过方法论全景（架构/协议/应用/DB 四层） |
| CVE-2026-21876 分析 | https://mp.weixin.qq.com/s/TqAe-A25A-c7GePlFTyjaA | multipart UTF-7 子 Part 绕过 OWASP CRS |
