# IGA-Guard Master 数据集真实性说明

> Agent1 · 数据集溯源与评估规范 · 最后更新：2026-07-01  
> 数据产物目录：`data/master/` · 采集入口：`scripts/dataset_agent.py`  
> 交叉参考：[`datasets/CSIC2010_GUIDE.md`](../datasets/CSIC2010_GUIDE.md) · [`ATTACK_TECHNIQUES_UPDATE.md`](ATTACK_TECHNIQUES_UPDATE.md) · [`datasets.md`](../datasets.md)

---

## 一、文档目的

本文档说明 `data/master/` 下 master 数据集的**三层数据来源**、**真实性边界**、**当前实测规模**、**train/test 划分流程及其局限性**，并给出**可复现的评估规范**。  
所有规模数字均以仓库内 `data/master/*.csv` **实测行数**为准（不含表头），与 `dataset_agent.py` 流水线输出一致。

---

## 二、三层数据架构

```
┌─────────────────────────────────────────────────────────────────┐
│  第一层 · CSIC 2010 GSI 真实 HTTP 流量（异常检测范式还原）        │
│  source: csic_gsi:* / csic_csv:* / csic_txt:*                   │
├─────────────────────────────────────────────────────────────────┤
│  第二层 · SecLists / FuzzDB 公开载荷 + 社区手工种子               │
│  source: seclists_* / fuzzdb_* / community:* / seed:*             │
├─────────────────────────────────────────────────────────────────┤
│  第三层 · obfuscation_techniques 程序合成扩充（仅攻击类）         │
│  source: obfuscation:<technique> 或 obfuscation:t1+t2             │
└─────────────────────────────────────────────────────────────────┘
         ↓ merge.py 去重合并 → full.csv
         ↓ expand_dataset_rows() → full_obfuscated.csv（评测/训练主集）
```

### 2.1 第一层：CSIC 2010 GSI 真实流量

| 属性 | 说明 |
|------|------|
| **性质** | **真实** HTTP 请求级流量，非程序生成 |
| **来源** | GSI GitLab 镜像预处理 TXT（`scripts/download_csic.py --source gsi`） |
| **解析器** | `src/iga_guard/dataset/csic_parser.py` |
| **source 标记** | `csic_gsi:{文件名}`（当前 master 以 GSI 块格式为主） |
| **典型文件** | `cisc_normalTraffic_train.txt`、`cisc_normalTraffic_test.txt`、`cisc_anomalousTraffic_test.txt` |
| **标签** | GSI `class: Attack|Valid` → `infer_attack_label()` 细化为 SQLi/XSS/CMD/Normal 等 |
| **当前基线占比** | **39,111 / 47,584**（约 82.2%） |

**真实性要点：**

- 流量来自西班牙 CSIC 2010 电商 Web 应用实验环境，含正常购物与多种 Web 攻击请求。
- 解析时从完整 HTTP 块提取 URL 查询串、POST body、Cookie 值作为 `payload` 字段。
- 正常样本（`Normal`）几乎全部来自本层；攻击样本以 SQLi、CMD 为主。
- **局限**：Host/应用上下文单一；原始 CSIC 官方划分（训练仅正常、测试含攻击）在本项目中已被**打乱合并**进统一 master 集（见第四节），不再保留原始异常检测划分语义。

### 2.2 第二层：SecLists 公开载荷与社区种子

| 属性 | 说明 |
|------|------|
| **性质** | **真实公开字典/社区实战摘录**，非随机合成 |
| **SecLists/FuzzDB** | `src/iga_guard/dataset/fetchers.py` 从 GitHub 拉取并缓存至 `data/raw/public/` |
| **社区种子** | `src/iga_guard/dataset/community_fetcher.py`：本地 `payloads_seed.txt` + 可选 FreeBuf/先知文章正文解析 |
| **source 标记** | `seclists_*`、`fuzzdb_*`、`community:payloads_seed`、`community:{rss来源}`、`seed:labeled_samples` |
| **当前基线占比** | **8,473 / 47,584**（约 17.8%） |

**各 source 实测分布（`full.csv`）：**

| source | 行数 | 说明 |
|--------|------|------|
| `seclists_cmd` | 8,197 | SecLists 命令注入字典 |
| `community:payloads_seed` | 216 | 本地社区种子文件 |
| `fuzzdb_xss` | 37 | FuzzDB XSS 字典 |
| `seed:labeled_samples` | 23 | 项目手工冒烟种子（`data/samples/labeled_samples.csv`） |

**真实性要点：**

- SecLists、FuzzDB 为安全社区广泛使用的**真实攻击载荷词典**，经 `infer_attack_label()` 标注攻击类型。
- 社区种子来自 FreeBuf、先知等公开 writeup 摘录或人工整理，网络失败时回退至本地 `payloads_seed.txt`。
- 合并时若与 CSIC 载荷** payload 哈希重复**，按 `merge.py` 规则保留**先入库**的 source（批次顺序：seed → community → public → csic），故 SecLists SQLi 等可能与 CSIC 大量去重，当前快照以 `seclists_cmd` 为主。
- **局限**：词典条目未必在真实业务 URL 上下文中出现；部分为探针/片段，非完整 HTTP 请求。

### 2.3 第三层：obfuscation_techniques 程序合成扩充

| 属性 | 说明 |
|------|------|
| **性质** | **程序合成**——在第二层基线攻击样本上施加文献/社区混淆手法 |
| **实现** | `src/iga_guard/dataset/obfuscation_techniques.py`（`expand_payload` / `expand_dataset_rows`） |
| **触发** | `dataset_agent.py` 在 `full.csv` 生成后，对**全部非 Normal 样本**扩充（默认 `obf_variants=4`） |
| **source 标记** | `obfuscation:<technique_name>`；双技术叠加为 `obfuscation:t1+t2` |
| **当前扩充量** | **+81,840 行**（`full_obfuscated.csv` 相对 `full.csv` 增量） |

**真实性要点：**

- 混淆变换本身（URL 双编码、MySQL 版本注释、HPP、JSON 嵌套等）对应真实 WAF 绕过手法，见 [`ATTACK_TECHNIQUES_UPDATE.md`](ATTACK_TECHNIQUES_UPDATE.md)。
- 但**具体变体字符串由确定性随机算法生成**，不属于独立采集的真实流量；应视为**对抗增强集**，而非新的真实观测。
- **Normal 样本不做混淆扩充**；第三层仅增加攻击类行。
- 默认参数：`seed=42`，`variants_per_attack=4`，`max_obfuscated=150000`（当前未触顶）。

**扩充后 top 混淆技术（`full_obfuscated.csv`）：**

| 技术 | 行数 |
|------|------|
| `multipart_boundary_sim` | 8,940 |
| `base64_fragment` | 8,916 |
| `null_byte` | 8,911 |
| `case_random` | 8,249 |
| `unicode_escape` | 8,139 |
| … | （共 25 项注册技术 + 组合叠加） |

---

## 三、当前实测规模

> 统计命令：`python -c "import csv; print(len(list(csv.DictReader(open('data/master/full_obfuscated.csv')))))"`  
> 统计日期：2026-07-01

### 3.1 主集（混淆扩充后，训练/评测默认使用）

| 文件 | 行数 | 用途 |
|------|------|------|
| `full_obfuscated.csv` | **129,424** | 完整 master 集 |
| `train_obfuscated.csv` | **110,013** | RF / TinyBERT 训练（同步至 `data/samples/master_train.csv`） |
| `test_obfuscated.csv` | **19,411** | 评测默认集（`evaluate.py` 默认路径） |

**标签分布（`full_obfuscated.csv`）：**

| label | 行数 |
|-------|------|
| Normal | 27,124 |
| SQLi | 60,370 |
| CMD | 41,010 |
| XSS | 745 |
| PathTraversal | 145 |
| 其他 | 30 |

### 3.2 基线集（混淆前，溯源对照）

| 文件 | 行数 |
|------|------|
| `full.csv` | 47,584 |
| `train.csv` | 40,444 |
| `test.csv` | 7,140 |

关系：`47,584`（基线）+ `81,840`（第三层增量）= `129,424`（主集）。

---

## 四、CSV 字段与 source 溯源规范

每条样本统一三列（`merge.py` → `write_csv`）：

| 字段 | 说明 |
|------|------|
| `payload` | URL 参数、POST body 片段或词典行（最长 2048 字符） |
| `label` | `Normal` / `SQLi` / `XSS` / `CMD` / `PathTraversal` / … |
| `source` | **溯源键**，用于区分三层及具体子源 |

### source 前缀速查

| 前缀 | 层级 | 真实性 |
|------|------|--------|
| `csic_gsi:` / `csic_csv:` / `csic_txt:` | 第一层 | 真实 HTTP 流量 |
| `seclists_*` / `fuzzdb_*` | 第二层 | 真实公开词典 |
| `community:` / `seed:` | 第二层 | 社区/手工种子 |
| `obfuscation:` | 第三层 | 程序合成变体 |

**审计建议：** 报告实验结果时应注明使用的 CSV 路径，并按 `source` 前缀分层汇报指标（至少区分「含混淆」与「仅基线」）。

---

## 五、采集与合并流水线

入口：`scripts/dataset_agent.py`

```
1. 拉取/解析
   ├─ download_csic.py --source gsi  → data/raw/csic/
   ├─ fetch_all_public()           → data/raw/public/  (SecLists/FuzzDB)
   └─ collect_community_rows()     → data/raw/community/

2. 合并批次（dataset_agent.py L139）
   batches = [seed_rows, community_rows, public_rows, csic_rows]

3. merge_and_split()  → full.csv / train.csv / test.csv
   ├─ dedupe_rows()：按 payload_hash 去重，保留首次 source
   └─ train_test_split()：分层随机划分

4. expand_dataset_rows(full.csv)  → full_obfuscated.csv

5. train_test_split(obf_rows)  → train_obfuscated.csv / test_obfuscated.csv
   └─ 同步 data/samples/master_train.csv / master_test.csv
```

核心实现：`src/iga_guard/dataset/merge.py`

- **去重**：`payload_hash(payload)` 完全相同则只保留先出现的行。
- **划分**：`train_test_split(rows, test_ratio=0.15, seed=42)`，按 `label` 分组后各自 shuffle 切分。

### 5.1 默认划分参数

| 参数 | 默认值 | 含义 |
|------|--------|------|
| `test_ratio` | 0.15 | 各 label 组内约 15% 进测试集 |
| `seed` | 42 | 可复现随机种子 |
| Normal 特殊规则 | `n_test ≤ len(group)//5` | 正常样本测试占比上限约 20%，避免正常类测试过大 |

---

## 六、train/test 划分流程与局限性

### 6.1 两阶段划分（重要）

本项目对 master 集进行**两次独立** `train_test_split`：

1. **基线划分**：`full.csv` → `train.csv` / `test.csv`
2. **混淆主集划分**：`full_obfuscated.csv`（含全部基线行 + 混淆变体）→ `train_obfuscated.csv` / `test_obfuscated.csv`

**训练与评测脚本默认使用第二阶段产物**（`train_obfuscated.csv` / `test_obfuscated.csv`）。

### 6.2 已知局限性

#### （1）同底稿不同混淆变体可能跨集

第三层对每条攻击基线生成多个 `obfuscation:*` 变体。混淆集划分时**按行独立随机**，**不绑定**「母本与其变体」到同一子集。

实测（`seed=42`，2026-07-01）：

| 现象 | 数量 |
|------|------|
| 基线 `train.csv` 中的行，在 `test_obfuscated.csv` 重现 | 2,553 |
| 基线 `test.csv` 中的行，在 `train_obfuscated.csv` 重现 | 2,644 |
| 测试集混淆行中，与训练集某原始攻击行存在明显子串关联（启发式） | 5,359 / 12,362 |

**影响：**

- 测试集混淆样本可能在训练集中见过**同一攻击意图的不同编码形态**，混淆子集 Recall 可能**乐观偏高**。
- 不宜将 `test_obfuscated.csv` 上的混淆 Recall 直接等同于对**全新零日混淆**的泛化能力。

**缓解建议（报告时）：**

- 分层汇报：`source` 不含 `obfuscation:` 的基线子集 vs 仅 `obfuscation:*` 子集。
- 零日评测使用**held-out 种子**或时间切分的外部社区样本，不依赖本 master 随机划分。
- 若需严格隔离，应按**母本 payload 哈希**或**CSIC 原始请求 ID** 分组切分（当前流水线**未实现**，属已知技术债）。

#### （2）去重保留先入库 source

`merge.py` 按批次顺序去重，后到的 CSIC 行若与 SecLists 重复，source 显示为 SecLists/社区而非 CSIC。溯源审计应以 `payload` 内容为准，并结合原始 `data/raw/` 缓存核对。

#### （3）标签噪声

- CSIC 攻击类经 `infer_attack_label()` 二次推断，可能存在细分类误差。
- SecLists 词典行按默认类型或规则推断，个别条目标签可能不精确。
- 少量异常 label（如 `2`、`108`）来自原始解析残留，占比极低。

#### （4）时间与应用上下文

除第一层 CSIC 外，第二层词典与第三层混淆均**无时间戳与业务 URL 上下文**，与生产 WAF 日志分布存在域偏移。

---

## 七、评估规范

### 7.1 必须报告正常流量误报率（Normal FP Rate）

WAF 类任务中，**仅报告攻击 Recall 或混淆子集 Recall 是不充分的**。  
`scripts/evaluate.py` 已拆分输出：

| 指标块 | 含义 |
|--------|------|
| `overall_binary` | 全体样本二分类（攻击 vs 正常） |
| `obfuscated_attack_binary` | **仅含混淆标记的攻击样本**检出率 |
| `normal_binary.false_positive_rate` | **正常流量误报率（必报）** |

**规范要求：**

1. 任何对 master 集的评测报告，须同时给出 **`normal_binary.false_positive_rate`**（或等价 FP / FPR）。
2. 不得只引用 `obfuscated_attack_binary.detection_recall` 作为「系统可用」的唯一依据。
3. 若抽样评测，须注明 `max_samples` 与是否分层抽样。

### 7.2 禁止仅用漏检样本覆盖重训 RF

对抗演化增量训练（`scripts/evolve_from_misses.py` → `iga_guard/evolution/self_train.py`）明确要求：

- **必须**在 `base_train_csv`（默认 `train_obfuscated.csv`）**与**漏检样本**合并**后重训 RF。
- **禁止**仅用漏检 CSV 覆盖原模型，否则特征分布严重偏移，Normal FP 与整体泛化不可信。

```text
# evolve_from_misses.py 帮助文本（摘要）
--base-train  原训练集（必须与漏检合并重训，禁止仅漏检覆盖）
```

`incremental_retrain()` 文档字符串：

> 在**原有训练集 + 漏检样本**上重训 RF，避免仅用漏检覆盖模型。

**报告增量训练效果时**，应同时对比：

- 重训前后 `test_obfuscated.csv` 上的混淆 Recall **与** Normal FPR；
- 明确 `base_train` 行数、漏检增广行数（`failure_augment`）。

### 7.3 推荐评测命令

```bash
# 全量主集评测（含 Normal FPR）
python scripts/evaluate.py --data data/master/test_obfuscated.csv

# 仅基线子集（自行过滤 source 不含 obfuscation:）
# 建议在 evaluate 结果中额外记录 dataset 过滤条件
```

### 7.4 结果 JSON 字段说明（`evaluate.py` 输出）

| 字段 | 说明 |
|------|------|
| `pass_binary_obfuscated` | 混淆攻击 Recall ≥ 0.995 是否达标 |
| `note` | 明确混淆子集与 Normal 误报分报 |
| `normal_binary.fp` / `tn` | 误报与真负计数，便于复核 FPR |

---

## 八、复现与更新

```bash
# 全流程重建 master（需网络拉取 CSIC / SecLists）
python scripts/dataset_agent.py

# 离线：仅用本地缓存
python scripts/dataset_agent.py --skip-fetch --skip-csic-download

# 验证行数
python -c "
import csv
from pathlib import Path
for n in ['full_obfuscated','train_obfuscated','test_obfuscated']:
    p = Path('data/master') / f'{n}.csv'
    print(n, sum(1 for _ in csv.DictReader(p.open(encoding='utf-8'))))
"
```

更新 master 后，请同步修订本文档第三节实测规模，并重新运行分层 source 统计。

---

## 九、引用

- CSIC 2010: Torrano Giménez et al., "HTTP dataset CSIC 2010", 2010
- SecLists: Daniel Miessler, [SecLists](https://github.com/danielmiessler/SecLists)
- 混淆手法映射：本项目 [`ATTACK_TECHNIQUES_UPDATE.md`](ATTACK_TECHNIQUES_UPDATE.md)

---

*本文档描述的是 IGA-Guard 赛题工程化 master 集的真实性边界，不代表任何单一公开数据集的官方划分或统计结论。*
