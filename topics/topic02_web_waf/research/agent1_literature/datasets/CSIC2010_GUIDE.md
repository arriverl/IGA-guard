# CSIC 2010 HTTP Dataset — 下载、字段与 labeled_samples 对齐指南

> Agent 1 第二轮 · 面向 IGA-Guard E1 训练与冒烟评估 · 最后更新：2026-06-30

---

## 一、数据集概览

| 属性 | 说明 |
|------|------|
| 全称 | HTTP dataset CSIC 2010 |
| 来源 | 西班牙 CSIC 研究所模拟电商 Web 应用流量 |
| 规模 | 训练 36,000 正常；测试 36,000 正常 + 25,065 攻击 |
| 标注范式 | **异常检测**：训练集仅正常，测试集含攻击 |
| 攻击类型 | SQLi、XSS、Buffer Overflow、CRLF、SSI、参数篡改、目录遍历等（CSV 版多为二分类） |
| 引用 | Torrano Giménez, R., et al. "HTTP dataset CSIC 2010", 2010 |

---

## 二、下载链接（按推荐优先级）

### 2.1 GSI GitLab 镜像（推荐 · 含预处理标签）

| 资源 | URL |
|------|-----|
| 仓库根目录 | https://gitlab.fing.edu.uy/gsi/web-application-attacks-datasets |
| CSIC 子目录 | https://gitlab.fing.edu.uy/gsi/web-application-attacks-datasets/-/tree/master/csic_2010 |
| 训练/测试 TAR | `dataset_cisc_train_test.tar.gz`（仓库内） |

```powershell
cd d:\Code_development\gitproduct\caisa_contest_2026\topics\topic02_web_waf\data\raw
git clone https://gitlab.fing.edu.uy/gsi/web-application-attacks-datasets.git
cd web-application-attacks-datasets\csic_2010
tar -xzf dataset_cisc_train_test.tar.gz
# 产出：normalTrafficTraining.txt / normalTrafficTest.txt / anomalousTrafficTest.txt
```

### 2.2 Peter Scully CSV 版（ML 友好 · 18 列）

| 资源 | URL |
|------|-----|
| 说明页 | https://petescully.co.uk/research/csic-2010-http-dataset-in-csv-format-for-weka-analysis/ |
| 文件 | `normalTrafficTraining.csv`、`normalTrafficTest.csv`、`anomalousTrafficTest.csv`（v02） |

适合直接 pandas 读取，无需自行解析 HTTP 文本。

### 2.3 官方主页（可能失效）

http://www.isi.csic.es/dataset/

### 2.4 WebSpotter 定位标注扩展

https://github.com/meifukun/WebSpotter — 在 CSIC 子集上提供 `location_label`（字符级恶意区间），用于 E6 定位 IoU 评估。

---

## 三、原始 TXT 格式说明

每条记录为完整 HTTP/1.1 请求（多行），以请求行开头：

```
GET /tienda1/index.jsp HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 ...
Cookie: JSESSIONID=...
Content-Length: 42
...
（可选 body）
```

**块边界**：GSI 预处理版常以空行分隔相邻请求；攻击测试集 `anomalousTrafficTest.txt` 仅含恶意流量。

---

## 四、CSV 18 列字段说明

| 列名 | 类型 | 含义 | 本项目是否使用 |
|------|------|------|----------------|
| `index` | int | HTTP 包序号（多参数可拆多行） | 否 |
| `method` | str | GET / POST | 可选（结构特征） |
| `url` | str | 路径 + Query String | **是** → 提取 query payload |
| `protocol` | str | HTTP/1.1 | 否 |
| `userAgent` | str | User-Agent | 可选 |
| `pragma` ~ `connection` | str | 标准请求头 | 否 |
| `contentLength` | str | 长度（空为 `null`） | 否 |
| `contentType` | str | Content-Type | 可选 |
| `cookie` | str | `KEY=VALUE` 格式 | **是** → Cookie 注入面 |
| `payload` | str | POST body 或 URL 参数 `KEY=VALUE` | **是** → 主载荷 |
| `label` | str | `norm` 正常 / `anom` 攻击 | **是** → 映射为赛题 label |

> **注意**：同一 `index` 可能对应多行（每个参数一行）。合并策略见 §六脚本思路。

---

## 五、与本项目 `labeled_samples.csv` 格式对齐

### 5.1 目标 schema

当前冒烟集路径：`data/samples/labeled_samples.csv`

```csv
payload,label
1 union select 1,2,SQLi
<script>alert(1)</script>,XSS
hello world,Normal
```

| 字段 | 类型 | 取值 | 说明 |
|------|------|------|------|
| `payload` | str | 攻击或正常载荷字符串 | 经 `normalize_payload()` 后送入特征提取 |
| `label` | str | `Normal` / `SQLi` / `XSS` / `CMD` / `PathTraversal` / `FileInclusion` / `XXE` / `PromptInjection` 等 | `train.py` 多类分类标签 |

**不包含**（与 `obfuscated_dataset.csv` 区分）：`source`、`obfuscation` 等扩展列；`labeled_samples.csv` 保持最简两列供日冒烟。

### 5.2 CSIC → 赛题 label 映射

CSIC CSV 仅提供二分类 `norm`/`anom`。细粒度映射策略：

| CSIC 信号 | 赛题 `label` | 启发式规则 |
|-----------|--------------|------------|
| `label == norm` | `Normal` | 直接映射 |
| `label == anom` + payload/url 含 union/select/insert/delete | `SQLi` | 关键字 + 正则 |
| 含 `<script`、`onerror=`、`javascript:` | `XSS` | — |
| 含 `../`、`..%2f`、`/etc/passwd` | `PathTraversal` | — |
| 含 `php://`、`file://`、`expect://` | `FileInclusion` | — |
| 含 `;wget`、`\|cat`、`${jndi` | `CMD` | — |
| 其他 `anom` | `SQLi` | **默认回退**（CSIC 中 SQLi 占比最高） |

> 若需精准多类，可改用 GSI TXT 中的 ModSecurity 规则 ID 或 WebSpotter 标注；E1 主实验可接受二分类增强后再用 `generate_dataset.py` 扩混淆。

### 5.3 payload 提取优先级

对每一逻辑请求（按 `index` 分组）：

1. 若 `payload` 列非空 → 取 `payload` 的 value 部分（`key=value` 取 `=` 后）
2. 否则解析 `url` 的 query string
3. 若仍空且 `cookie` 含可疑片段 → 取 cookie value
4. 多字段攻击：取 **最长可疑子串** 或拼接（与 WebSpotter MSU 策略一致）

---

## 六、转 CSV 脚本思路（`scripts/csic_to_labeled.py` 待实现）

```python
#!/usr/bin/env python3
"""CSIC2010 CSV → labeled_samples.csv 格式转换（思路稿）."""

import csv
import re
from pathlib import Path

ATTACK_PATTERNS = [
    (re.compile(r"(?i)union\s+select|'\s*or\s+'1'\s*=\s*'1|;\s*drop\s+table"), "SQLi"),
    (re.compile(r"(?i)<script|onerror\s*=|javascript:"), "XSS"),
    (re.compile(r"\.\./|/etc/passwd"), "PathTraversal"),
    (re.compile(r"(?i)php://|file://"), "FileInclusion"),
    (re.compile(r"(?i);\s*wget|\|cat|jndi:"), "CMD"),
]

def infer_label(raw_label: str, text: str) -> str:
    if raw_label == "norm":
        return "Normal"
    for pat, lbl in ATTACK_PATTERNS:
        if pat.search(text):
            return lbl
    return "SQLi"  # CSIC 默认回退

def extract_payload(row: dict) -> str:
    for key in ("payload", "url", "cookie"):
        val = (row.get(key) or "").strip()
        if not val or val == "null":
            continue
        if "=" in val and key != "url":
            val = val.split("=", 1)[1]
        elif key == "url" and "?" in val:
            val = val.split("?", 1)[1]
        if val:
            return val
    return ""

def convert(csic_csv: Path, out_csv: Path, max_rows: int | None = None) -> None:
    rows_out: list[dict[str, str]] = []
    with csic_csv.open(encoding="utf-8", newline="") as f:
        for i, row in enumerate(csv.DictReader(f)):
            if max_rows and i >= max_rows:
                break
            payload = extract_payload(row)
            if not payload:
                continue
            label = infer_label(row.get("label", "norm"), payload)
            rows_out.append({"payload": payload, "label": label})

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["payload", "label"])
        w.writeheader()
        w.writerows(rows_out)
```

### 6.1 建议用法

```powershell
cd d:\Code_development\gitproduct\caisa_contest_2026\topics\topic02_web_waf

# 仅攻击测试集 → 扩充 labeled_samples
python scripts/csic_to_labeled.py `
  --input data/raw/csic/anomalousTrafficTest.csv `
  --output data/samples/labeled_samples_csic_attack.csv `
  --max-rows 5000

# 训练集正常样本（下采样避免不平衡）
python scripts/csic_to_labeled.py `
  --input data/raw/csic/normalTrafficTraining.csv `
  --output data/samples/labeled_samples_csic_normal.csv `
  --max-rows 5000

# 合并后供 train.py / evaluate.py
# type labeled_samples_csic_*.csv > data/samples/labeled_samples_merged.csv  # 需去重表头
```

### 6.2 与 `generate_dataset.py` 衔接

```
CSIC CSV ──► csic_to_labeled.py ──► labeled_samples_*.csv（基线）
                    │
                    └──► generate_dataset.py --variants 8
                              └──► obfuscated_dataset.csv（混淆增强）
```

---

## 七、目录布局建议

```
data/
├── raw/
│   └── csic/
│       ├── normalTrafficTraining.csv
│       ├── normalTrafficTest.csv
│       └── anomalousTrafficTest.csv
└── samples/
    ├── labeled_samples.csv          # 手工冒烟（当前 24 条）
    ├── labeled_samples_csic.csv     # CSIC 转换产出
    └── obfuscated_dataset.csv       # 混淆扩展
```

---

## 八、已知局限与应对

| 局限 | 影响 | 本项目应对 |
|------|------|------------|
| 无时间戳 | 无法做真实会话 DLinear | `timeseries_buffer.py` 按 IP 模拟窗口 |
| 无混淆变种 | 原始集过高准确率 | `mutator.py` / `ast_mutator.py` / `llm_agent.py` |
| Host 单一 | 泛化性有限 | ECML/PKDD 跨集测试（E2） |
| 二分类标签 | 多类指标粗糙 | 启发式细分 + 自建种子集 |

---

## 九、验收检查清单

- [ ] `data/raw/csic/` 下三个 CSV 已下载
- [ ] 转换脚本产出 `payload,label` 两列 UTF-8 CSV
- [ ] `python scripts/train.py --data data/samples/labeled_samples_csic.csv` 可运行
- [ ] `python scripts/evaluate.py --data ...` 冒烟通过
- [ ] 攻击/正常比例约 1:1~1:3（避免极度不平衡）
