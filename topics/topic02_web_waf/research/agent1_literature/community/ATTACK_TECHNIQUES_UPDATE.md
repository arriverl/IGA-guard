# 混淆手法与 `obfuscation_techniques.py` 映射表

> Agent1 补全 · 25+ 社区绕过手法 ↔ 代码实现对照 · 最后更新：2026-06-30  
> 源码：`src/iga_guard/dataset/obfuscation_techniques.py`  
> 交叉参考：[`COMMUNITY_INTEL_2024_2026.md`](COMMUNITY_INTEL_2024_2026.md) · [`../papers/05_evasion_sota_2024_2026.md`](../papers/05_evasion_sota_2024_2026.md)

---

## 一、总览

| 统计项 | 值 |
|--------|-----|
| `TECHNIQUES` 注册名 | **25** |
| 双技术叠加（`t1+t2`） | **+1**（`expand_payload` 自动组合） |
| 编排函数 | `apply_technique` · `expand_payload` · `expand_dataset_rows` |
| 下游消费 | `mutator.mutate_batch()` · `dataset_agent.py` · `POST /api/obfuscate` |
| 防御侧对应 | `normalizer/decoder.py` · `fusion_model.py` · `semantic_branch.py` |

**攻击类型标注**：`TECHNIQUES` 中空集 `set()` 表示**通用**（SQLi/XSS/CMD 均可）；否则仅对列出的类型生效。

---

## 二、完整映射表（25 项注册技术）

| # | 技术名 (`technique`) | 适用类型 | 社区手法名称 | 典型变换示例 | 实现函数 | 社区来源 |
|---|----------------------|----------|--------------|--------------|----------|----------|
| 1 | `case_random` | 通用 | 大小写随机化 | `UnIoN SeLeCt` | `_case_random` | [FreeBuf #6](https://www.freebuf.com/vuls/229300.html) |
| 2 | `inline_comment` | SQLi, XSS | 内联注释拆分 | `UN/**/ION` · `=/**/=` | `_inline_comment` | [FreeBuf #2](https://www.freebuf.com/articles/web/467037.html) · [先知 #9](https://xz.aliyun.com/t/8257) |
| 3 | `mysql_version_comment` | SQLi | MySQL 版本条件注释 | `/*!50000union*/` | `_mysql_version_comment` | [FreeBuf #6](https://www.freebuf.com/vuls/229300.html) |
| 4 | `url_encode` | 通用 | 单层 URL 编码 | `%27%20OR%201%3D1` | `_url_encode` | [FreeBuf #5](https://www.freebuf.com/articles/web/450803.html) |
| 5 | `double_url_encode` | 通用 | 双重 URL 编码 | `%2527` | `_double_url_encode` | [FreeBuf #1](https://www.freebuf.com/articles/web/452137.html) |
| 6 | `unicode_escape` | 通用 | JS `\uXXXX` 转义 | `\u0075\u006e\u0069\u006f\u006e` | `_unicode_escape` | [FreeBuf #1](https://www.freebuf.com/articles/web/452137.html) |
| 7 | `hex_escape` | SQLi | Hex 字面量关键字 | `0x756e696f6e` | `_hex_escape` | [FreeBuf #6](https://www.freebuf.com/vuls/229300.html) |
| 8 | `whitespace_substitution` | SQLi | 空白符替换 | 空格 → `%09`/`%0a`/`/**/`/`+` | `_whitespace_substitution` | [FreeBuf #3](https://www.freebuf.com/articles/web/447696.html) |
| 9 | `null_byte` | 通用 | Null 字节注入 | `admin%00' OR 1=1` | `_null_byte` | [FreeBuf #3](https://www.freebuf.com/articles/web/447696.html) |
| 10 | `html_entity_partial` | XSS | HTML 实体（部分） | `&#117;nion` | `_html_entity_partial` | [先知 #10](https://xz.aliyun.com/news/90804) |
| 11 | `html_entity_full` | XSS | HTML 实体（全量） | 全字符 `&#NN;` | `_html_entity_full` | [先知 #10](https://xz.aliyun.com/news/90804) |
| 12 | `base64_fragment` | 通用 | Base64 片段 + eval | `eval(atob('...'))` + 原文尾部 | `_base64_fragment` | [FreeBuf #4](https://www.freebuf.com/articles/web/442457.html) |
| 13 | `keyword_concat_split` | SQLi | 字符串拼接拆分 | `uni'+'on` · `scr'+'ipt` | `_keyword_concat_split` | [FreeBuf #6](https://www.freebuf.com/vuls/229300.html) |
| 14 | `tab_newline` | SQLi | Tab/换行物理拆分 | `uni\ton` · `sel,\nect` | `_tab_newline` | [先知 #9](https://xz.aliyun.com/t/8257) |
| 15 | `paren_overload` | SQLi | 括号过载 | `((((select` | `_paren_overload` | [FreeBuf #6](https://www.freebuf.com/vuls/229300.html) |
| 16 | `char_function` | SQLi | CHAR()/CONCAT 拼接 | `CONCAT(CHAR(117),...)` | `_char_function` | [FreeBuf #6](https://www.freebuf.com/vuls/229300.html) |
| 17 | `svg_event_wrap` | XSS | SVG 事件包裹 | `<svg/onload=...>` | `_svg_event_wrap` | [先知 #10](https://xz.aliyun.com/news/90804) |
| 18 | `img_onerror_wrap` | XSS | img onerror 包裹 | `<img src=x onerror="...">` | `_img_onerror_wrap` | [先知 #10](https://xz.aliyun.com/news/90804) |
| 19 | `logic_or_tautology` | SQLi | 逻辑永真追加 | `...' OR '1'='1` | `_logic_or_tautology` | [FreeBuf #5](https://www.freebuf.com/articles/web/450803.html) |
| 20 | `nested_comment` | SQLi | 嵌套注释 | `/*/*/` + `/*--*/` | `_nested_comment` | [先知 #9](https://xz.aliyun.com/t/8257) |
| 21 | `hpp_duplicate_param` | SQLi, XSS | **HPP 参数污染** | `id=1&id=payload` | `_hpp_duplicate_param` | [FreeBuf #1](https://www.freebuf.com/articles/web/452137.html) |
| 22 | `json_nested_escape` | SQLi, XSS | **JSON 嵌套键逃逸** | `{"a":{"b":"payload"}}` | `_json_nested_escape` | [FreeBuf #1](https://www.freebuf.com/articles/web/452137.html) |
| 23 | `unicode_normalization` | 通用 | **全角/兼容字符** | `ｕｎｉｏｎ` (U+FF55…) | `_unicode_normalization` | [FreeBuf #1](https://www.freebuf.com/articles/web/452137.html) |
| 24 | `multipart_boundary_sim` | 通用 | **multipart 边界混淆** | `WebKitFormBoundary` 伪造 | `_multipart_boundary_sim` | [FreeBuf #4](https://www.freebuf.com/articles/web/442457.html) · WAFFLED |
| 25 | `chunked_whitespace` | SQLi | **分块空白注入** | `uni%0d%0aon` | `_chunked_whitespace` | [FreeBuf #3](https://www.freebuf.com/articles/web/447696.html) |

---

## 三、第 26 项：双技术叠加（组合逃逸）

| # | 技术名 | 说明 | 实现位置 | 社区意义 |
|---|--------|------|----------|----------|
| 26 | `obfuscation:{t1}+{t2}` | 当单技术不足 `n` 个变体时，随机选取两种可用手法顺序叠加 | `expand_payload()` L99–111 | FreeBuf 实战均为**编码链+注释**等多层组合；单手法评测低估威胁 |

**常见有效组合**（社区 2024–2026 高频）：

| 组合 | 示例链路 | 对应 source 标记 |
|------|----------|------------------|
| 双重编码 + 注释 | `%252f` → `/**/` 再拆关键字 | `double_url_encode+inline_comment` |
| URL 编码 + MySQL 注释 | `%75nion` + `/*!50000select*/` | `url_encode+mysql_version_comment` |
| 全角 + 空白替换 | `ｕｎｉｏｎ` + `%0a` | `unicode_normalization+whitespace_substitution` |
| HPP + URL 编码 | `id=1&id=%27+OR+1%3D1` | `hpp_duplicate_param+url_encode` |
| JSON 嵌套 + Unicode | 深层 JSON + `\u` 转义 | `json_nested_escape+unicode_escape` |

---

## 四、按攻击类型索引

### 4.1 SQLi（20 种直接适用 + 5 种通用）

`inline_comment` · `mysql_version_comment` · `hex_escape` · `whitespace_substitution` · `keyword_concat_split` · `tab_newline` · `paren_overload` · `char_function` · `logic_or_tautology` · `nested_comment` · `hpp_duplicate_param` · `json_nested_escape` · `chunked_whitespace`  
+ 通用：`case_random` · `url_encode` · `double_url_encode` · `unicode_escape` · `null_byte` · `base64_fragment` · `unicode_normalization` · `multipart_boundary_sim`

### 4.2 XSS（9 种直接适用 + 通用子集）

`inline_comment` · `html_entity_partial` · `html_entity_full` · `svg_event_wrap` · `img_onerror_wrap` · `hpp_duplicate_param` · `json_nested_escape`  
+ 通用：`case_random` · `url_encode` · `double_url_encode` · `unicode_escape` · `null_byte` · `base64_fragment` · `unicode_normalization` · `multipart_boundary_sim`

### 4.3 协议/结构类（2024–2026 社区新增 5 项）

| 技术名 | 层级 | 仅靠 payload 分类能否防御 | 须配合模块 |
|--------|------|--------------------------|------------|
| `hpp_duplicate_param` | HTTP 参数 | ❌ | `collector/protocol.py` |
| `json_nested_escape` | Content-Type/Body | 🔶 部分 | `collector/http_parser.py` |
| `unicode_normalization` | 字符规范化 | ✅（若 normalizer 启用） | `normalizer/decoder.py` |
| `multipart_boundary_sim` | multipart 结构 | ❌ | `collector/protocol.py` |
| `chunked_whitespace` | 传输/空白 | 🔶 部分 | `normalizer/decoder.py` |

---

## 五、混淆生成 → 防御解码链映射

| 混淆技术 | `decoder.py` 解码步骤 | `ast_restore.py` | 检测轨 |
|----------|----------------------|------------------|--------|
| `url_encode` | `url_decode`（可迭代 2 轮 → 双编码） | — | 规则轨 |
| `double_url_encode` | `url_decode` ×2 | — | 规则轨 |
| `unicode_escape` | `js_unicode` | — | 语义轨 |
| `unicode_normalization` | NFKC 规范化（预处理） | — | 语义轨 |
| `html_entity_partial/full` | `html_entity` | — | 规则+语义 |
| `hex_escape` | `hex_escape` | AST 还原关键字 | 语义轨 |
| `base64_fragment` | `base64` | — | 语义轨 |
| `inline_comment` / `mysql_version_comment` / `nested_comment` | 注释剥离正则 | `ast_restore` | 规则轨 |
| `whitespace_substitution` / `tab_newline` / `chunked_whitespace` | 空白归一 | — | 规则+统计轨 |
| `char_function` / `keyword_concat_split` | — | `ast_restore` CONCAT 展开 | 语义轨 |
| `case_random` | `lower()` 归一 | — | 规则轨（i 标志） |
| `null_byte` | `%00` 过滤 | — | 规则轨 |
| `svg_event_wrap` / `img_onerror_wrap` | 标签/event 剥离 | — | 语义轨 |
| `hpp_duplicate_param` | — | — | `protocol.py` 全参数扫描 |
| `json_nested_escape` | JSON 递归展平 | — | `structural.py` |
| `multipart_boundary_sim` | multipart 解析 | — | `protocol.py` |

---

## 六、API 与数据集字段约定

### 6.1 `expand_payload` 输出格式

```json
{
  "payload": "<混淆后载荷>",
  "label": "SQLi | XSS | ...",
  "source": "obfuscation:<technique_name>"
}
```

双技术叠加时：`"source": "obfuscation:tech_a+tech_b"`

### 6.2 调用链

```
obfuscation_techniques.apply_technique(payload, technique)
    ↓
expand_payload(payload, attack_type, n=5)
    ↓
expand_dataset_rows(rows, variants_per_attack=3)   # dataset_agent.py
    ↓
data/master/full_obfuscated.csv
    ↓
mutator.mutate_batch()  # 对抗训练优先走 expand_payload
    ↓
run_adversarial.py / evolution/self_train.py
```

### 6.3 CLI 快速验证

```powershell
$env:PYTHONPATH="src"
python scripts/iga_system.py obfuscate -p "1 union select 1" -t SQLi -n 10
```

---

## 七、与 `mutator.py` 内置策略对照

`mutator.py` 保留轻量 fallback，优先委托 `obfuscation_techniques`：

| mutator 策略 | 等价/近似 obfuscation 技术 |
|--------------|---------------------------|
| `case` → `_case_obfuscate` | `case_random` |
| `comment` → `_comment_obfuscate` | `inline_comment`（简化版） |
| `encode` → `_url_encode` | `url_encode` |
| `split` → `_keyword_split` | `keyword_concat_split`（仅 union） |
| `html_encode` → `_html_encode_partial` | `html_entity_partial` |
| `svg` → `_svg_wrap` | `svg_event_wrap` |
| `event` → `_event_inject` | `img_onerror_wrap` |

**建议**：新社区手法只扩展 `obfuscation_techniques.py`（本次文档周期不修改代码）；`mutator.py` 通过 `expand_payload` 自动继承。

---

## 八、待覆盖社区手法（文档记录，未入代码）

以下在 FreeBuf/先知 2025–2026 writeup 中常见，**尚未**注册为 `TECHNIQUES` 独立项，供 E3 对抗实验参考：

| 社区手法 | 说明 | 来源 writeup | 建议落点 |
|----------|------|--------------|----------|
| MySQL 花括号列名 | `select{a\`username\`}from` 绕过正则 | [FreeBuf #467037](https://www.freebuf.com/articles/web/467037.html) | `ast_mutator.py` |
| HQL 任意位置 `/**/` | Hibernate 将注释解析为空格 | [FreeBuf #467037](https://www.freebuf.com/articles/web/467037.html) | `inline_comment` 扩展 |
| JDBC URL 多 host 语法 | `jdbc:mysql://(host,param=true)/db` | [先知 #18906](https://xz.aliyun.com/news/18906) | `collector/protocol.py` |
| JDBC equalsIgnoreCase | `MYSQL` vs `mysql` 驱动差异 | [先知 #91821](https://xz.aliyun.com/news/91821) | `decoder.py` 大小写链 |
| Oracle 冷门报错函数 | `updatexml`/`extractvalue` 变体 | [先知 #17819](https://xz.aliyun.com/news/17819) | `ast_mutator.py` |
| libinjection SC 规则盲区 | `%a%0a` 换行导致 token 错位 | [先知 #8257](https://xz.aliyun.com/t/8257) | 规则轨 tokenize 对齐 |
| multipart UTF-7 子 Part | `charset=utf-7` 分段编码 | [CVE-2026-21876](https://mp.weixin.qq.com/s/TqAe-A25A-c7GePlFTyjaA) | `decoder.py` charset 白名单 |
| `%u0027` IIS Unicode 编码 | Windows/IIS 特有 `%u` 编码 | FreeBuf #447696 | `decoder.py` 扩展 |
| `CONCAT_WS` / `GROUP_CONCAT` 拆分 | MySQL 函数等价替换 | FreeBuf #229300 | `ast_mutator.py` |
| `Content-Type` 双头走私 | 双 CT 头取不同解析路径 | [FreeBuf #452137](https://www.freebuf.com/articles/web/452137.html) | `collector/protocol.py` |
| `Transfer-Encoding: chunked` 走私 | TE.CL 组合 | [FreeBuf #452137](https://www.freebuf.com/articles/web/452137.html) | `collector/protocol.py` |
| LLM 语义改写（无固定模式） | DEG-WAF / AI 护栏绕过 | [先知 #19011](https://xz.aliyun.com/news/19011) | `llm_agent.py` |

---

## 八-B、FreeBuf / 先知 writeup 完整 URL 清单

| # | URL | 平台 | 与上表映射 |
|---|-----|------|-----------|
| 1 | https://www.freebuf.com/articles/web/452137.html | FreeBuf | #21–23, 双 CT/TE 待覆盖 |
| 2 | https://www.freebuf.com/articles/web/467037.html | FreeBuf | 花括号、HQL `/**/` |
| 3 | https://www.freebuf.com/articles/web/447696.html | FreeBuf | #8–9, #25, IIS `%u` |
| 4 | https://www.freebuf.com/articles/web/442457.html | FreeBuf | #12, #24 |
| 5 | https://www.freebuf.com/articles/web/450803.html | FreeBuf | #4, #19, 源站 IP |
| 6 | https://www.freebuf.com/vuls/229300.html | FreeBuf | #1–3, #7, #13, #15–16 |
| 7 | https://xz.aliyun.com/news/18906 | 先知 | JDBC WAF 绕过 |
| 8 | https://xz.aliyun.com/news/17819 | 先知 | Oracle 冷门语法 |
| 9 | https://xz.aliyun.com/t/8257 | 先知 | #2, #14, #20, libinjection |
| 10 | https://xz.aliyun.com/news/90804 | 先知 | #10–11, #17–18, XSS 渐进 |
| 11 | https://xz.aliyun.com/news/91821 | 先知 | JDBC CTF 2026 |
| 12 | https://xz.aliyun.com/news/19011 | 先知 | LLM 护栏绕过 |

---

## 九、评测对照（混淆子集）

| 防御配置 | 混淆子集 Recall（内部冒烟） | 主要漏检技术 |
|----------|----------------------------|--------------|
| CRS 规则 alone | ~40–50% | `double_url_encode` · `char_function` · `multipart_boundary_sim` |
| RF 融合（无 normalizer） | ~85% | `unicode_normalization` · `json_nested_escape` |
| RF + Normalizer + TinyBERT | **~93.3%** | `hpp_duplicate_param` · 双技术叠加 · LLM 变种 |
| 目标（赛题） | **99.5%** | 须 E2 规则增强 + E3 对抗闭环 |

---

## 十、变更记录

| 日期 | 变更 |
|------|------|
| 2026-06-30 | Agent1 初版 `COMMUNITY_INTEL` 骨架（网络中断） |
| 2026-06-30 | Agent1 补全：本文件 + `COMMUNITY_INTEL` 扩充；对齐 `obfuscation_techniques.py` 25 项注册表 |
| 2026-06-30 | WebSearch 核验：12 条 FreeBuf/先知真实 URL 写入 §八-B；社区来源列改为可点击链接 |
