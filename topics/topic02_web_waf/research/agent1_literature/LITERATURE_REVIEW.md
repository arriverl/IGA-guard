# Agent 1 文献综述（预填核心）

> 由 Research Scout Agent 维护 · 最后更新：2026-06-30

---

## 一、DLinear 与时序分析（流量轨）

### 核心文献

| 文献 | 要点 | 对本赛题的借鉴 |
|------|------|----------------|
| **Zeng et al., AAAI 2023** — *Are Transformers Effective for Time Series Forecasting?* | 提出 DLinear：移动平均分解 Trend/Seasonal + 双线性层；在多个基准上优于 Transformer | HTTP 请求率、熵值、Payload 长度构成多元时序；用残差能量作异常分，检测低速率混淆逃逸 |
| **LTSF-Linear (GitHub: cure-lab/LTSF-Linear)** | 官方实现，含 DLinear/NLinear | 可参考 `series_decomp` 与 `Linear` 层实现 |
| **An Analysis of Linear TS Models, arXiv 2024** | 系统分析 DLinear 族 | 答辩时解释为何选 DLinear 而非 Autoformer |

### 思路卡片：DLinear → Web 流量

```
问题：攻击者低速率发送混淆请求，单条 payload 看似正常
方法：对同 IP/会话最近 T 条请求提取 [QPS, entropy, special_ratio, ...] 构成时序
      DLinear 分解 → 残差分量能量突增 → anomaly_score
收益：补足 TinyBERT 对「单条看似正常」的盲区
风险：正常 CDN 突发流量可能误报 → 需与语义轨融合降误报
```

---

## 二、TinyBERT 与 Payload 语义（语义轨）

### 核心文献

| 文献 | 要点 | 对本赛题的借鉴 |
|------|------|----------------|
| **Jiao et al., 2020** — *TinyBERT* | 6 层蒸馏 BERT，体积缩小 7.5×，速度提升 9.4× | Payload 短文本分类，满足 ≤10ms 约束 → 详见 [`papers/02_tinybert_distillation.md`](papers/02_tinybert_distillation.md) |
| **CSIC 2010 HTTP Dataset** | 经典 Web 攻击 HTTP 数据集 | 训练/测试基线 → [`datasets.md`](datasets.md) · 下载/转 CSV → [`datasets/CSIC2010_GUIDE.md`](datasets/CSIC2010_GUIDE.md) |
| **Dawadi et al., 2023** — *CNN-LSTM XSS/SQLi* | 字符级 CNN/RNN 检测，CSIC 99.77% | 对比实验基线 → 详见 [`papers/03_web_attack_ml_cnn_lstm.md`](papers/03_web_attack_ml_cnn_lstm.md) |

### 思路卡片：TinyBERT → Payload

```
输入：解混淆后的 normalized_payload（max_len=128）
模型：TinyBERT_6L + 线性分类头（8 类）
训练：原始 + mutator 混淆 + AST 混淆 数据增强
推理：INT8 量化 / ONNX Runtime
融合：P = 0.6·P_tinybert + 0.4·P_xgb（可调）
```

---

## 三、可解释性与恶意高亮

| 方向 | 文献/方法 | 借鉴 |
|------|-----------|------|
| SHAP | Lundberg & Lee, 2017 | 特征贡献度（可选，离线分析） |
| Attention 可视化 | Transformer 自带 | TinyBERT 最后一层 attention → token 权重 |
| WebSpotter | Cui et al., NDSS 2026 | 字段级 + 字符级 span 高亮 → [`papers/04_webspotter_ndss2026.md`](papers/04_webspotter_ndss2026.md) |
| LIME | Ribeiro et al., 2016 | 局部解释备选 |

### 思路卡片：可解释高亮

```
L1: WebSpotter 正则 + 锚点词 → token_range
L2: 字符热力图 ████ → 前端 CSS .mal { background:#f87171 }
L3: NL 模板 → 「因在 query:id 发现 union select…」
指标：Localization IoU，目标 +22%
```

---

## 四、混淆逃逸与对抗

| 方向 | 要点 | 文献 |
|------|------|------|
| 赛题要求 | 须实现混淆载荷生成器 | `mutator.py` / `ast_mutator.py` |
| 对抗训练 | 漏检样本 → 增强 → 重训（Self-Evolving） | ModSec-AdvLearn (IEEE TIFS 2025) |
| LLM Agent | 生成未知混淆变种扩充样本池 | DEG-WAF (STIS 2025) |
| 协议层绕过 | Content-Type / body 解析差异 | WAFFLED (arXiv 2025) |
| ML-WAF 红队 | 语义保持 SQL 变异 fuzz | WAF-A-MoLE (ACM SAC 2020) |
| **社区实战手法** | FreeBuf/先知 2024–2026 writeup、25 种混淆映射 | [`community/COMMUNITY_INTEL_2024_2026.md`](community/COMMUNITY_INTEL_2024_2026.md) · [`community/ATTACK_TECHNIQUES_UPDATE.md`](community/ATTACK_TECHNIQUES_UPDATE.md) |

> 完整思路卡片见 [`papers/05_adversarial_evasion_2024.md`](papers/05_adversarial_evasion_2024.md)

---

## 五、开源数据集清单

> 完整字段说明与下载步骤见 [`datasets.md`](datasets.md)

| 数据集 | 用途 | 规模 | 链接 |
|--------|------|------|------|
| CSIC 2010 | Payload 语义训练/测试 | 36K+25K | GSI GitLab / Peter Scully CSV → [`datasets/CSIC2010_GUIDE.md`](datasets/CSIC2010_GUIDE.md) · 自动下载 → `scripts/download_csic.py` |
| ECML/PKDD 2007 | 多类攻击 + 定位标注 | 50K | GSI GitLab / WebSpotter |
| CICIDS 2017 | DLinear 时序轨 | ~280 万流 | UNB CIC 官方 |
| 自建混淆集 | 零日/对抗实验 | 可扩展 | `data/samples/obfuscated_dataset.csv` |

---

## 六、思路卡片索引

| 编号 | 论文 / 资源 | 文件 | 状态 |
|------|-------------|------|------|
| 01 | DLinear (AAAI 2023) | [`papers/01_dlinear_aaai2023.md`](papers/01_dlinear_aaai2023.md) | ✅ |
| 02 | TinyBERT (EMNLP 2020) | [`papers/02_tinybert_distillation.md`](papers/02_tinybert_distillation.md) | ✅ |
| 03 | CNN-LSTM Web 攻击检测 (Sci. Rep. 2023) | [`papers/03_web_attack_ml_cnn_lstm.md`](papers/03_web_attack_ml_cnn_lstm.md) | ✅ |
| 04 | WebSpotter 载荷定位 (NDSS 2026) | [`papers/04_webspotter_ndss2026.md`](papers/04_webspotter_ndss2026.md) | ✅ |
| 05 | 混淆逃逸与对抗 WAF (2024–2026) | [`papers/05_adversarial_evasion_2024.md`](papers/05_adversarial_evasion_2024.md) | ✅ |
| 05-SOTA | 混淆逃逸检测 SOTA 横向对比表 | [`papers/05_evasion_sota_2024_2026.md`](papers/05_evasion_sota_2024_2026.md) | ✅ |
| CI-01 | 社区情报摘要（FreeBuf/先知 2024–2026） | [`community/COMMUNITY_INTEL_2024_2026.md`](community/COMMUNITY_INTEL_2024_2026.md) | ✅ |
| CI-02 | 混淆手法 ↔ 代码映射（25+ 项 + 12 URL） | [`community/ATTACK_TECHNIQUES_UPDATE.md`](community/ATTACK_TECHNIQUES_UPDATE.md) | ✅ |
| DS-01 | CSIC2010 下载与预处理指南 | [`datasets/CSIC2010_GUIDE.md`](datasets/CSIC2010_GUIDE.md) | ✅ |
| DS-02 | CSIC2010 自动下载脚本 | [`scripts/download_csic.py`](../../scripts/download_csic.py) | ✅ |

基线对比详见 [`baselines.md`](baselines.md)

---

## 七、已补充调研（2026-06）

### 7.1 WebSpotter NDSS 2026 正式引用

**Cui et al., NDSS 2026** — *Achieving Interpretable DL-based Web Attack Detection through Malicious Payload Localization*

- 将 HTTP 请求分解为 MSU（最小语义单元），梯度归因 + 语义特征训练轻量定位模型
- 在 CSIC/PKDD/FPAD 上 F1 接近 1.0，较 SHAP/LIME 等基线 **Localization Accuracy 提升 ≥22%**
- 开源：https://github.com/meifukun/WebSpotter
- 本赛题直接映射 `explainer/webspotter.py`，E6 实验对标论文指标

### 7.2 2024–2026 混淆逃逸检测 SOTA 对比

> 思路卡片：[`papers/05_adversarial_evasion_2024.md`](papers/05_adversarial_evasion_2024.md)  
> **完整横向对比表（8 项方法）**：[`papers/05_evasion_sota_2024_2026.md`](papers/05_evasion_sota_2024_2026.md) ✅

| 方法 | 年份 | 核心技术 | 混淆鲁棒 | 延迟 | 可解释 |
|------|------|----------|----------|------|--------|
| ModSecurity CRS PL4 | — | 规则签名 | ❌ 对抗 TPR<50% | 2~8 ms | 规则 ID |
| ModSec-Learn (SVM) | 2024 | CRS 特征 + ML | 🔶 中等 | 5~10 ms | 特征权重 |
| ModSec-AdvLearn (RF) | 2023 | 对抗训练 + CRS | ✅ 提升 85% | 5~10 ms | 特征权重 |
| CNN-LSTM | 2023 | Word2Vec + 混合 DL | 🔶 未测混淆 | 50~200 ms | ❌ |
| BERT-Base 微调 | — | Transformer 全量 | 🔶 中等 | 30~80 ms | Attention |
| TinyBERT-6L | 2020/应用 2023+ | 蒸馏小模型 | ✅ 配合解混淆 | **2~5 ms** | Attention |
| WebSpotter + DL | 2026 | 定位 + 检测 | ✅ | +1~2 ms | ✅ 字段级 |
| **IGA-Guard 2.0** | 2026 | 双路+RL+演化 | **目标 >99.5%** | **<5 ms** | WebSpotter+NL |

**关键结论**：纯规则 WAF 在对抗混淆下崩溃；CNN-LSTM 精度高但无法满足延迟约束；TinyBERT + 解混淆 + 双路融合是当前最优平衡点。

### 7.3 TinyBERT 在安全领域已有工作

| 工作 | 年份 | 场景 | 结论 |
|------|------|------|------|
| TinyBERT Stacking 钓鱼检测 | IEEE IoT 2023 | URL 字符串分类 | Acc 99.14%，证明短文本语义可行 |
| DistilBERT WAF 载荷分类 | 2021~2023 多篇 | HTTP Payload | F1 0.96+，但体积仍偏大 |
| SecureBERT / SecBERT | 2022 | 安全文本预训练 | 领域词表优势，推理慢于 TinyBERT |
| **本赛题** | 2026 | 混淆 Web 攻击 8 类 | TinyBERT-6L + Normalizer + INT8 |

**空白点**：尚无 TinyBERT 在 **混淆逃逸 Web 载荷** 上的公开基准 → 本赛题可形成创新贡献。

### 7.4 DoH/HTTPS 仅统计特征场景

| 文献/方向 | 要点 | 本赛题映射 |
|-----------|------|------------|
| DoH 流量分类 (CISC 2020+) | 仅 DNS 报文长度/时序，无载荷明文 | `collector/protocol.py` HTTP/3 骨架 |
| TLS 指纹 (JA3/JA4) | 密码套件 + 扩展序列 | 未来 HTTPS 全加密适配 |
| Encrypted Traffic Classification | 流级统计 → CNN/GRU | DLinear 统计轨理论支撑 |
| CICIDS2017 流特征 | 79 维无载荷特征 | `dlinear_branch.py` 特征来源 |

**策略**：赛题当前以 HTTP 明文为主；DoH/HTTPS 场景下 **DLinear 统计轨 + 协议元数据** 可独立工作，语义轨退化为 TLS 指纹 + 流量行为分类（已在 `PROJECT.md` §2.1 标注 HTTP/3 骨架）。

### 7.5 安全社区情报（FreeBuf / 先知，2024–2026）

> 完整索引：[`community/COMMUNITY_INTEL_2024_2026.md`](community/COMMUNITY_INTEL_2024_2026.md)  
> 手法映射表：[`community/ATTACK_TECHNIQUES_UPDATE.md`](community/ATTACK_TECHNIQUES_UPDATE.md)

经 WebSearch 核验 **12 条** FreeBuf / 先知真实 writeup，归纳 2024–2026 社区高频绕过主题：

| 主题 | 代表来源 | 核心手法 | 本项目映射 |
|------|----------|----------|------------|
| 企业级 WAF 全景 | [FreeBuf #452137](https://www.freebuf.com/articles/web/452137.html) | HPP、HTTP 走私、JSON/multipart CT 差异 | `hpp_duplicate_param` · `multipart_boundary_sim` |
| 2025 实战复盘 | [FreeBuf #467037](https://www.freebuf.com/articles/web/467037.html) | MySQL `{col}` 花括号、HQL `/**/` 任意拆分 | `inline_comment` · `ast_mutator.py` |
| WAF 缺陷利用 | [FreeBuf #447696](https://www.freebuf.com/articles/web/447696.html) | IIS `%` 截断、空白符、源站 IP | `whitespace_substitution` · 架构层 |
| 上传 bypass | [FreeBuf #442457](https://www.freebuf.com/articles/web/442457.html) | multipart 分片、运行时解码 | `multipart_boundary_sim` |
| 云 WAF + SQLi | [FreeBuf #450803](https://www.freebuf.com/articles/web/450803.html) | 源站发现、多层编码链 | `double_url_encode` |
| 正则本源论 | [FreeBuf #229300](https://www.freebuf.com/vuls/229300.html) | 四类正则绕过（替换/编码/注释/污染） | 规则轨设计依据 |
| JDBC WAF | [先知 #18906](https://xz.aliyun.com/news/18906) | 连接串解析差异 | 待扩展（§八待覆盖） |
| Oracle 绕 WAF | [先知 #17819](https://xz.aliyun.com/news/17819) | 冷门报错函数、分步注出 | `ast_mutator.py` |
| libinjection 绕过 | [先知 #8257](https://xz.aliyun.com/t/8257) | tokenize 状态机 SC 盲区 | 规则轨 + normalizer |
| SRC XSS 渐进 | [先知 #90804](https://xz.aliyun.com/news/90804) | 低特征探测、存储型 XSS | `svg_event_wrap` |
| JDBC CTF 2026 | [先知 #91821](https://xz.aliyun.com/news/91821) | 驱动默认属性 fuzz | E3 红队参考 |
| AI 护栏绕过 | [先知 #19011](https://xz.aliyun.com/news/19011) | Prompt 注入、合规伪装 | `llm_agent.py` |

**关键结论**：社区 writeup 与学术论文（WAFFLED、ModSec-AdvLearn）形成互补——论文提供可复现向量与量化指标，社区提供最新实战变体（花括号、JDBC、AI 护栏）。`obfuscation_techniques.py` 已注册 **25 种**手法，另有 **12 种**待覆盖项记录在 `ATTACK_TECHNIQUES_UPDATE.md` §八。

---

## 八、Agent 1 第四轮完成项

- [x] 混淆逃逸检测 SOTA 对比表（≥5 项）→ [`papers/05_evasion_sota_2024_2026.md`](papers/05_evasion_sota_2024_2026.md)
- [x] CSIC2010 自动下载/解压脚本 → [`scripts/download_csic.py`](../../scripts/download_csic.py)
- [x] LITERATURE_REVIEW 索引与 §7.2 交叉引用更新
- [x] FreeBuf/先知社区情报（12 条真实 URL）→ [`community/COMMUNITY_INTEL_2024_2026.md`](community/COMMUNITY_INTEL_2024_2026.md)
- [x] 混淆手法映射表（25 项 + 待覆盖 12 项）→ [`community/ATTACK_TECHNIQUES_UPDATE.md`](community/ATTACK_TECHNIQUES_UPDATE.md)

---

## 九、Agent 1 第三轮完成项（历史）

- [x] 混淆逃逸检测 SOTA 对比表（≥5 项）→ [`papers/05_evasion_sota_2024_2026.md`](papers/05_evasion_sota_2024_2026.md)
- [x] CSIC2010 自动下载/解压脚本 → [`scripts/download_csic.py`](../../scripts/download_csic.py)
- [x] LITERATURE_REVIEW 索引与 §7.2 交叉引用更新

---

## 十、待后续深入

- [ ] FPAD 数据集申请与 FPAD-OOD 跨分布测试
- [ ] SecureBERT vs TinyBERT 领域微调对比实验
- [ ] CICIDS2017 修正版（WTMC 2021）清洗脚本集成
- [ ] ModSecurity Docker 基线自动化评测脚本
- [ ] `scripts/csic_to_labeled.py` CSIC → labeled_samples 转换脚本
- [ ] JDBC URL / `%u` IIS 编码纳入 `decoder.py`（见社区 §八待覆盖）
