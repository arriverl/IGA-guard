# 开源数据集清单（Agent 1）

> 面向 IGA-Guard 2.0 实验方案 · 最后更新：2026-06

---

## 一、总览

| 数据集 | 类型 | 规模 | 本赛题用途 | 优先级 |
|--------|------|------|------------|--------|
| **CSIC 2010** | HTTP 请求级 | 36K 正常 + 25K 攻击 | E1 主训练/测试、语义轨微调 | ⭐⭐⭐ |
| **ECML/PKDD 2007** | HTTP 请求级 + 上下文 | 24.5K 训练 + 25.6K 测试 | 多类攻击、定位标注、跨集泛化 | ⭐⭐⭐ |
| **CICIDS 2017** | 网络流级 | ~280 万流 / 14 类攻击 | DLinear 时序轨、统计特征 | ⭐⭐ |
| **自建混淆集** | HTTP + 混淆标签 | 可扩展 | E2/E3 零日混淆、对抗演化 | ⭐⭐⭐ |

---

## 二、CSIC 2010 HTTP Dataset

### 2.1 简介

- 西班牙电商 Web 应用自动生成的 HTTP 流量
- 攻击类型：SQLi、XSS、Buffer Overflow、CRLF、SSI、参数篡改、文件泄露等
- 标注策略：**异常检测范式**——训练集仅含正常流量，测试集含正常+攻击

### 2.2 下载方式

| 来源 | 链接 | 格式 |
|------|------|------|
| 官方主页 | http://www.isi.csic.es/dataset/ （可能失效） | 原始 TXT |
| GSI GitLab 镜像 | https://gitlab.fing.edu.uy/gsi/web-application-attacks-datasets/-/tree/master/csic_2010 | TXT + 预处理 TAR |
| Peter Scully CSV 版 | https://petescully.co.uk/research/csic-2010-http-dataset-in-csv-format-for-weka-analysis/ | CSV v02 |
| WebSpotter 定位标注 | https://github.com/meifukun/WebSpotter | 带 `location_label` |

**推荐下载步骤**（完整指南见 [`datasets/CSIC2010_GUIDE.md`](datasets/CSIC2010_GUIDE.md)）：

```bash
# 方式 A：GSI 预处理版（含 ModSecurity ID + Valid/Attack 标签）
git clone https://gitlab.fing.edu.uy/gsi/web-application-attacks-datasets.git
cd web-application-attacks-datasets/csic_2010
tar -xzf dataset_cisc_train_test.tar.gz

# 方式 B：CSV 版（Weka/ML 友好）
# 从 Peter Scully 页面下载 normalTraining / anomalousTest / normalTest
```

### 2.3 原始 TXT 格式

每条 HTTP 请求以 `HTTP/1.1` 行开始，包含完整请求头与 body：

```
GET /tienda1/index.jsp HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 ...
Cookie: JSESSIONID=...
...
```

### 2.4 CSV 字段说明（18 列）

| 字段 | 类型 | 说明 |
|------|------|------|
| `index` | int | HTTP 包序号（非唯一，多参数拆行） |
| `method` | str | GET / POST |
| `url` | str | 请求路径 + Query String |
| `protocol` | str | HTTP/1.1 |
| `userAgent` | str | User-Agent 头 |
| `pragma` | str | Pragma 头 |
| `cacheControl` | str | Cache-Control 头 |
| `accept` | str | Accept 头 |
| `acceptEncoding` | str | Accept-Encoding |
| `acceptCharset` | str | Accept-Charset |
| `acceptLanguage` | str | Accept-Language |
| `host` | str | Host |
| `connection` | str | Connection |
| `contentLength` | str | Content-Length（空值为 `null`） |
| `contentType` | str | Content-Type |
| `cookie` | str | Cookie，格式 `KEY=VALUE` |
| `payload` | str | POST body 或 URL 参数，格式 `KEY=VALUE` |
| `label` | str | `norm`（正常）/ `anom`（攻击） |

### 2.5 子集划分

| 文件 | 请求数 | 用途 |
|------|--------|------|
| `normalTrafficTraining.txt` | 36,000 正常 | 训练 |
| `normalTrafficTest.txt` | 36,000 正常 | 测试（正常） |
| `anomalousTrafficTest.txt` | 25,065 攻击 | 测试（攻击） |

### 2.6 已知局限

- 无时间戳 → 无法做会话级时序分析（需自建 `timeseries_buffer` 模拟）
- Host 单一 → 泛化性有限
- 无混淆变种 → 须配合 `mutator.py` / `ast_mutator.py` 增强

---

## 三、ECML/PKDD 2007 Discovery Challenge

### 3.1 简介

- 真实 Web 流量 + BeeWare 生成，含 **7 类攻击 + Valid**
- 独特优势：**服务器上下文**（OS/DB/技术栈）+ **攻击区间标注**（±3 字符）

### 3.2 下载方式

| 来源 | 链接 |
|------|------|
| 挑战赛主页 | https://www.lirmm.fr/pkdd2007-challenge/ |
| GSI GitLab | https://gitlab.fing.edu.uy/gsi/web-application-attacks-datasets/-/tree/master/ecml_pkdd |
| WebSpotter 定位版 | https://github.com/meifukun/WebSpotter |

```bash
cd web-application-attacks-datasets/ecml_pkdd
tar -xzf dataset_ecml_pkdd_train_test.tar.gz
# 另含 learning_dataset.xml（原始 XML 格式）
```

### 3.3 字段说明

**XML 原始格式**（`learning_dataset.xml`）：

| 元素 | 说明 |
|------|------|
| `id` | 唯一样本 ID |
| `reqContext/os` | UNIX / WINDOWS / UNKNOWN |
| `reqContext/webServer` | APACHE / MIIS / UNKNOWN |
| `reqContext/xpath` | TRUE / FALSE / UNKNOWN |
| `reqContext/ldap` | TRUE / FALSE / UNKNOWN |
| `reqContext/sql` | TRUE / FALSE / UNKNOWN |
| `class/type` | 攻击类型标签 |
| `class/attackInterval` | 攻击在请求中的字符区间 |
| `class/inContext` | 攻击在当前上下文是否成功 |
| `request` | 完整 HTTP（method, uri, query, headers, body） |

**GSI 预处理 TXT 格式**：

```
Start - id: 12345
class: SqlInjection
<完整 HTTP 请求>
End - id: 12345
```

### 3.4 类别分布

| 类别 | 训练集 | 测试集 |
|------|--------|--------|
| Valid | 24,504 | 10,502 |
| XSS | — | 含于攻击 |
| SqlInjection | — | 含于攻击 |
| LdapInjection | — | 含于攻击 |
| XPathInjection | — | 含于攻击 |
| PathTransversal | — | 含于攻击 |
| OsCommanding | — | 含于攻击 |
| SSI | — | 含于攻击 |
| **攻击合计** | 0（训练仅 Valid） | 15,110 |

### 3.5 本赛题用法

- E6 定位评估：`attackInterval` 作为 Ground Truth
- E2 跨集泛化：CSIC 训练 → PKDD 测试
- 上下文特征可映射到 `features/structural.py`

---

## 四、CICIDS 2017

### 4.1 简介

- 加拿大网络安全研究所（CIC/UNB）发布
- 5 天 PCAP + CICFlowMeter 提取的 **79~80 维流特征**
- 含 3 类 Web 攻击：Brute Force、XSS、SQL Injection

### 4.2 下载方式

| 资源包 | 链接 | 大小 |
|--------|------|------|
| 官方主页 | https://www.unb.ca/cic/datasets/ids-2017.html | — |
| PCAP 原始包 | 同上（分日下载） | ~50 GB |
| **MachineLearningCSV.zip** | 同上 | ~2.3 GB（推荐） |
| GeneratedLabelledFlows.zip | 同上 | 流级标注 |
| 修正版（WTMC 2021） | https://downloads.distrinet-research.be/WTMC2021/ | 标签清洗 |

```bash
# 仅需 ML 特征时
wget https://www.unb.ca/cic/datasets/ids-2017.html  # 页面内 MachineLearningCSV 链接
unzip MachineLearningCSV.zip
```

### 4.3 Web 攻击时段（周四）

| 攻击类型 | 时间窗口 |
|----------|----------|
| Web Attack – Brute Force | 09:20 – 10:00 |
| Web Attack – XSS | 10:15 – 10:35 |
| Web Attack – Sql Injection | 10:40 – 10:42 |

### 4.4 核心字段（CSV 前 20 列示例）

| 字段 | 说明 |
|------|------|
| `Destination Port` | 目标端口 |
| `Flow Duration` | 流持续时间 (µs) |
| `Total Fwd Packets` | 前向包数 |
| `Total Length of Fwd Packets` | 前向字节数 |
| `Fwd Packet Length Max/Min/Mean/Std` | 前向包长统计 |
| `Flow Bytes/s` | 字节率 |
| `Flow Packets/s` | 包率 |
| `Flow IAT Mean/Std/Max/Min` | 包间隔统计 |
| `Fwd IAT Total/Mean/Std/Max/Min` | 前向间隔 |
| … | 共 78 维数值特征 |
| **`Label`** | `BENIGN` / `Web Attack – XSS` / `Web Attack – Sql Injection` / `Web Attack – Brute Force` / 其他攻击 |

### 4.5 已知问题与建议

- **WTMC 2021 指出**：大量 Web 攻击流无实际 HTTP 载荷（空流），标签噪声高
- 建议：过滤 `Total Length of Fwd Packets = 0` 的流；或使用修正版数据集
- 本赛题主要用于 **DLinear 时序轨**（QPS/熵/间隔），非 Payload 语义训练

---

## 五、自建混淆数据集

### 5.1 生成方式

```powershell
cd d:\Code_development\gitproduct\caisa_contest_2026\topics\topic02_web_waf
python scripts/generate_dataset.py --variants 8
```

### 5.2 输出字段（`data/samples/obfuscated_dataset.csv`）

| 字段 | 说明 |
|------|------|
| `payload` | 原始或混淆后载荷 |
| `attack_type` | SQLi/XSS/CMD/LFI/RFI/XXE/PromptInjection/Normal |
| `obfuscation` | none/url_encode/double_encode/unicode/comment_split/ast/llm |
| `label` | 0 正常 / 1 恶意 |
| `source` | csic/synthetic/cve |

### 5.3 划分建议

| 子集 | 比例 | 用途 |
|------|------|------|
| 原始 | 1/3 | 基线性能 |
| 规则混淆 | 1/3 | mutator 变种 |
| LLM 混淆 | 1/3 | E2/E3 零日检测 |

---

## 六、数据管线对接

```
CSIC/ECML 原始下载
    ↓ scripts/generate_dataset.py（混淆增强）
data/samples/obfuscated_dataset.csv
    ↓ scripts/train.py
models/tinybert/ + models/xgb/
    ↓ scripts/evaluate.py / eval_explainability.py
results/v2_exp*.json
```

**引用格式**：

- CSIC: Torrano Giménez et al., "HTTP dataset CSIC 2010", 2010
- ECML/PKDD: LIRMM Challenge, 2007
- CICIDS2017: Sharafaldin et al., "Toward generating a new intrusion detection dataset", ICISSp 2018
