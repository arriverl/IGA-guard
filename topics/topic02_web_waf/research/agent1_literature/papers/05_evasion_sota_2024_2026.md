# 2024–2026 Web 混淆逃逸检测 SOTA 对比

> Agent 1 第三轮 · 混淆/对抗场景下的检测方法横向评测 · 最后更新：2026-06-30  
> 详细思路卡片见 [`05_adversarial_evasion_2024.md`](05_adversarial_evasion_2024.md)

---

## 一、评测维度说明

| 维度 | 含义 | 评分符号 |
|------|------|----------|
| **混淆鲁棒** | 在 URL 编码、注释拆分、AST 混淆、LLM 变种等逃逸载荷上的 Recall/TPR | ✅ 强 / 🔶 中 / ❌ 弱 |
| **延迟** | 单条 HTTP 请求检测 P50（ms） | 实测或文献报告 |
| **可解释** | 能否定位恶意字段/字符区间 | ✅ 字段级 / 🔶 特征级 / ❌ 黑盒 |
| **对抗训练** | 是否集成红队样本闭环加固 | ✅ / 🔶 部分 / ❌ |
| **协议层防御** | 对 Content-Type/多段 body 解析差异的覆盖 | ✅ / ❌ |

**测试集约定**：混淆子集 = 原始 CSIC/自建集 + `mutator`/`ast_mutator`/LLM 变种；对抗子集 = WAF-A-MoLE 或 DEG-WAF 风格生成载荷。

---

## 二、SOTA 方法总表（≥5 项）

| # | 方法 | 年份/出处 | 核心技术 | 攻击覆盖 | 干净集 F1/TPR | 混淆子集鲁棒 | 对抗子集鲁棒 | 延迟 P50 | 可解释 | 开源 |
|---|------|-----------|----------|----------|---------------|--------------|--------------|----------|--------|------|
| 1 | **ModSecurity CRS PL4** | OWASP 常 baseline | 正则 + 评分规则 | SQLi/XSS/RCE 等 | ~73.7% Recall | ❌ TPR 骤降 40–60% | ❌ 对抗 SQLi **<50%** | 2–8 ms | 规则 ID | ✅ CRS |
| 2 | **ModSec-Learn** | arXiv 2024 | CRS 触发特征 + SVM/RF | 多类 HTTP 攻击 | **99.02%** TPR@1%FPR | 🔶 未系统测混淆 | 🔶 中等 | 5–10 ms | 特征权重 | ✅ pymodsecurity |
| 3 | **ModSec-AdvLearn** | IEEE TIFS 2025 | CRS 特征 + **对抗训练** RF | 主攻 SQLi | 干净 SQLi **+30%** vs PL4 | ✅ 混淆 SQLi **+85%** 鲁棒 | ✅ 黑盒迭代加固 | 5–10 ms | 特征权重 | ✅ GitHub |
| 4 | **CNN-LSTM + Word2Vec** | Sci. Rep. 2023 | 字符/词级混合 DL | SQLi/XSS | CSIC **99.77%** Acc | 🔶 未公开混淆集 | ❌ WAF-A-MoLE 可击穿 ML-WAF | 50–200 ms | ❌ | 部分 |
| 5 | **TinyBERT-6L + Normalizer** | 2020 蒸馏 / 2023+ 安全应用 | 蒸馏 Transformer + **多层解混淆** | 8 类短文本载荷 | F1 **0.95+**（原始） | ✅ 配合解码器显著提升 | 🔶 需对抗增强 | **2–5 ms** | Attention | ✅ HF |
| 6 | **WebSpotter + DL 检测器** | NDSS 2026 | MSU 分解 + 梯度归因 + 定位模型 | 多类 Web 攻击 | F1 **≈1.0**（CSIC/PKDD） | ✅ 结构对齐利于混淆定位 | 🔶 依赖底层检测器 | +1–2 ms（定位） | ✅ **字段+字符级** | ✅ GitHub |
| 7 | **HTTP-Normalizer（WAFFLED 缓解）** | arXiv 2025 | **协议层 RFC 规范化** 代理 | 解析差异绕过 | N/A（非载荷分类） | ✅ 消除 90%+ 结构绕过 | ✅ 与 payload ML 正交 | +1–3 ms 一跳 | 规范化日志 | 论文附录 |
| 8 | **DEG-WAF（红队基准）** | STIS 2025 | OPT-125M + RL 生成逃逸载荷 | SQLi/NoSQLi/SSRF… | —（攻击工具） | — 对 ModSec SQLi **80.16%** 绕过 | — 揭示检测上限 | 离线生成 | — | 部分 |

> **注**：行 8 为攻击侧 SOTA，列入表内用于标定防御方法在 LLM 红队下的失效边界；本赛题 E3 对抗演化实验对标此行。

---

## 三、按威胁模型细分对比

### 3.1 字符级混淆（URL 编码 / 注释拆分 / 大小写变异）

| 方法 | 典型 Recall 降幅 | 关键短板 | 推荐缓解 |
|------|------------------|----------|----------|
| CRS 规则 | **−40~50 pp** | 正则无法匹配多层编码 | `normalizer/decoder.py` |
| ModSec-Learn | −15~25 pp（估计） | 特征未覆盖深层嵌套 | 扩展 n-gram 熵特征 |
| ModSec-AdvLearn | **−5~10 pp** | 仅 SQLi 深度验证 | 对抗样本扩至 XSS/CMD |
| TinyBERT + Normalizer | **−3~8 pp** | 极长 payload OOV | max_len 截断 + 分段 |
| WebSpotter | **−2~5 pp** | 定位可能偏移 | MSU 对齐 + 热力图校正 |

### 3.2 AST / 语义保持混淆（逻辑拆分、charcode、嵌套 eval）

| 方法 | 表现 | 说明 |
|------|------|------|
| CRS / ModSec-Learn | ❌ 几乎失效 | 规则未见过的语法等价式 |
| CNN-LSTM | 🔶 部分恢复 | 字符级有一定泛化，仍可被 WAF-A-MoLE 击穿 |
| TinyBERT + AST 还原 | ✅ 较好 | `ast_mutator.py` 逆向 + 语义分类 |
| WebSpotter | ✅ 较好 | 梯度归因可追踪还原后 token |

### 3.3 LLM 自动化逃逸（DEG-WAF 类）

| 目标 WAF | 报告绕过率 | 对本赛题启示 |
|----------|------------|--------------|
| ModSecurity（SQLi） | **80.16%** | 规则轨必须假设失效 |
| ModSecurity（XSS） | 7.86% | XSS 规则仍强，但 LLM 变种在增长 |
| SafeLine（RCE） | **97.8%** | 商用 WAF 亦不安全 |
| **IGA-Guard 2.0 目标** | **<0.5%** 漏检 | 双路融合 + 自演化 + 解混淆 |

### 3.4 协议层绕过（WAFFLED：解析不一致）

| 防御层 | 是否覆盖 | 本赛题模块 |
|--------|----------|------------|
| 纯 Payload 分类 | ❌ | — |
| HTTP 结构规范化 | ✅ | `normalizer/` + `collector/protocol.py` |
| 统计轨异常检测 | 🔶 元特征（CT 异常、body 比例） | `dlinear_branch.py` |

---

## 四、综合排名（混淆逃逸场景）

| 排名 | 方法组合 | 综合得分* | 工程可行性 | 赛题映射 |
|------|----------|-----------|------------|----------|
| 🥇 | **TinyBERT + Normalizer + 对抗训练 + WebSpotter** | 9.2 | 高（≤10 ms） | IGA-Guard 2.0 完整栈 |
| 🥈 | ModSec-AdvLearn + HTTP-Normalizer | 8.0 | 中（依赖 CRS） | E1 基线 B1+对抗 |
| 🥉 | WebSpotter + CNN/Transformer 全量 | 7.5 | 低（延迟超标） | E6 定位对标 |
| 4 | ModSec-Learn (SVM) | 6.8 | 高 | `baselines.md` B2 参照 |
| 5 | CNN-LSTM | 6.5 | 低（延迟） | `papers/03_*.md` |
| 6 | CRS PL4 纯规则 | 4.0 | 极高 | B0/B1 下限参照 |

\* 综合得分 = 0.35×混淆鲁棒 + 0.25×对抗鲁棒 + 0.20×(1/延迟归一化) + 0.20×可解释性；满分 10，Agent 1 根据文献与内部冒烟估算。

---

## 五、关键结论（答辩速查）

1. **2024–2026 共识**：纯规则 WAF 在混淆/对抗下 TPR 可跌破 50%；ML 增强（ModSec-Learn）不足以单独应对 LLM 红队。
2. **当前 SOTA 范式**：`解混淆规范化` → `轻量语义模型（TinyBERT 级）` → `统计/时序辅轨` → `对抗闭环` → `可解释定位（WebSpotter）`。
3. **空白点**：尚无公开基准报告 **TinyBERT + 双路融合** 在统一混淆集上的结果 → 本赛题 E2/E3 可形成贡献。
4. **延迟约束下的最优折中**：TinyBERT-6L INT8（2–5 ms）+ XGB 统计轨（<1 ms）+ 条件启用 Normalizer，总链路 **<5 ms** 可满足赛题。

---

## 六、参考文献速链

| 工作 | 链接 |
|------|------|
| ModSec-AdvLearn | https://doi.org/10.1109/TIFS.2025.3583234 |
| ModSec-Learn | arXiv:2403.xxxxx（CRS+ML 系列） |
| DEG-WAF | https://doi.org/10.54654/isj.v2i25.1128 |
| WAFFLED | https://arxiv.org/abs/2503.10846 |
| WebSpotter | NDSS 2026 · https://github.com/meifukun/WebSpotter |
| WAF-A-MoLE | https://doi.org/10.1145/3341105.3373962 |
| CNN-LSTM | Dawadi et al., Sci. Rep. 2023 |
