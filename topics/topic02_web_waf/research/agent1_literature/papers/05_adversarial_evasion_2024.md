# 2024–2026 Web 混淆逃逸与对抗 WAF — 思路卡片合集

> Agent 1 第二轮 · 覆盖对抗训练、ML-WAF 绕过、LLM/RL 逃逸生成 · 最后更新：2026-06-30

---

## 05-A · ModSec-AdvLearn — CRS 对抗训练加固（IEEE TIFS 2025）

**标题**：ModSec-AdvLearn: Countering Adversarial SQL Injections with Robust Machine Learning  
**作者**：Floris, Scano, Montaruli, Demetrio, Valenza, Compagna, Ariu, Piras, Balzarotti, Biggio 等  
**链接**：https://doi.org/10.1109/TIFS.2025.3583234 · arXiv: https://arxiv.org/abs/2308.04964 · 代码：https://github.com/pralab/modsec-advlearn

### 核心方法

1. 在 **ModSecurity + OWASP CRS** 上，用 ML 自动选择规则子集并学习组合权重（延续 ModSec-Learn 思路）
2. **对抗训练闭环**：黑盒迭代查询 WAF，生成能绕过检测的 SQLi 变种 → 加入训练集 → 重训分类器
3. 攻击者模型假设：攻击者可持续探测 WAF 响应，逐步 refine payload（与赛题 `run_adversarial.py` 自演化一致）

### 关键数据

| 指标 | 相对默认 CRS |
|------|----------------|
| SQLi 检出率 | **+30%**（同时误报率仍极低） |
| 规则数量 | 可裁减 **50%** CRS 规则 |
| 对抗 SQLi 鲁棒性 | **+85%**（相对 PL 默认配置） |

### 可借鉴点（题目二）

- 证明 **纯规则 WAF 在对抗混淆下 TPR 骤降**；对抗训练是工程可落地的加固路径
- CRS 特征 + RF/SVM 与 IGA-Guard **XGB 统计轨** 同属「结构化特征 + 浅层 ML」范式，可作 E1 基线
- 开源 `pymodsecurity` 实验框架可复用为 **ModSecurity Docker 自动化评测**（对应 LITERATURE_REVIEW §八待办）

### 局限性

- 聚焦 **SQLi**，未覆盖 XSS/CMD/XXE/Prompt Injection
- 依赖 ModSecurity 规则触发特征，对 **解析差异型绕过**（WAFFLED）无效
- 对抗训练成本高，需持续在线查询 WAF

### 本赛题映射

→ `scripts/run_adversarial.py`：漏检样本回灌训练集  
→ `baselines.md` ModSec-AdvLearn 行：E3 对抗演化对标  
→ 答辩论点：**规则轨崩溃时，语义轨 + 对抗增强是必要补充**

---

## 05-B · DEG-WAF — LLM + 强化学习生成逃逸载荷（STIS 2025）

**标题**：Generating Evasive Payloads for Assessing Web Application Firewalls with Reinforcement Learning and Pre-trained Language Models  
**作者**：Bao, Cong Duc, Duy 等  
**链接**：https://doi.org/10.54654/isj.v2i25.1128

### 核心方法

1. **DEG-WAF** 四组件：OPT-125M 载荷生成器 + WAF 行为奖励模型 + 语法约束采样器 + RL 微调（PPO / A2C）
2. 奖励信号来自真实 WAF（ModSecurity、SafeLine）的拦截/放行反馈，形成 **黑盒逃逸搜索**
3. 语法层保证 SQLi/NoSQLi 等 payload 可执行，语义层保持攻击意图

### 关键数据（ModSecurity 绕过率）

| 攻击类型 | OPT-A2C 绕过率 | 备注 |
|----------|----------------|------|
| SQLi | **80.16%** | 显著高于裸 LLM |
| NoSQLi | **74.70%** | — |
| SSRF | 65.52%（PPO 最优） | — |
| XSS | **7.86%** | ModSecurity 对 XSS 规则仍强 |
| RCE | 低 | SafeLine 上 RCE 可达 97.8% |

### 可借鉴点（题目二）

- 直接支撑赛题 **LLM Agent 混淆生成器**（`llm_agent.py`）的设计合理性
- RL 奖励 ≈ 本赛题对抗演化中的「是否绕过检测」fitness，可迁移到 `run_adversarial.py`
- 表明 **传统规则 WAF 对 LLM 变种几乎不设防**（SQLi 80%+），必须用解混淆 + 语义模型兜底

### 局限性

- 小模型 OPT-125M，生成质量有限；大模型成本与可控性需权衡
- 奖励模型过拟合单一 WAF 版本，跨厂商泛化差
- 未评估对 **ML 语义检测器**（TinyBERT）的绕过率 → 本赛题可填补空白

### 本赛题映射

→ `adversarial/llm_agent.py`：E2 零日混淆集生成  
→ `mutator.py` + LLM 混合：规则变种保底 + LLM 探索未知空间  
→ E3 实验：DEG-WAF 风格 payload vs IGA-Guard 检出率曲线

---

## 05-C · WAFFLED — HTTP 解析差异绕过与规范化防御（arXiv 2025）

**标题**：WAFFLED: Exploiting Parsing Discrepancies to Bypass Web Application Firewalls  
**作者**：（多厂商联合披露，arXiv 预印本）  
**链接**：https://arxiv.org/abs/2503.10846 · 缓解工具：**HTTP-Normalizer**

### 核心方法

1. 针对 WAF 与后端框架对 **Content-Type / 多段 body / 非标准 header** 的解析不一致进行结构化 fuzz
2. 在 **AWS、Azure、Cloud Armor、Cloudflare、ModSecurity** 五类 WAF 上确认 **1207** 条绕过
3. 提出 **HTTP-Normalizer** 代理：入站请求严格 RFC 规范化后再送 WAF/后端

### 关键发现

- **>90%** 实测网站同时接受 `application/x-www-form-urlencoded` 与 `multipart/form-data` 互换解析 → 攻击者可把恶意 payload 藏在 WAF 未检查的 body 段
- 绕过不依赖 payload 内容混淆，而是 **协议层语义分裂**——与 URL 编码/注释拆分属不同威胁模型
- 厂商已确认并部分修复；说明「ML 检测再强，解析不一致仍可穿透」

### 可借鉴点（题目二）

- 强化 `normalizer/` 模块必要性：**解混淆不仅是字符级，还需 HTTP 结构对齐**
- DLinear 统计轨可检测 **异常 Content-Type 组合、body 分段比例** 等元特征
- 答辩对比：IGA-Guard 的 Normalizer + 双路融合 vs 纯 payload 分类器的盲区

### 局限性

- 主要评估商业云 WAF，开源 ModSecurity 样本偏少
- HTTP-Normalizer 增加一跳延迟，需与 ≤10ms 赛题约束权衡（可仅对可疑请求启用）
- 与 SQL 语义混淆正交，需 **多层防御** 才能全覆盖

### 本赛题映射

→ `normalizer/decoder.py`：多层解码 + 结构规范化  
→ `collector/protocol.py`：HTTP/3 骨架下的解析一致性检查  
→ E5 消融：开启/关闭 Normalizer 对混淆子集 Recall 的影响

---

## 05-D · 代表性前期工作：WAF-A-MoLE（ACM SAC 2020 / SoftwareX）

**标题**：WAF-A-MoLE: Evading Web Application Firewalls through Adversarial Machine Learning  
**链接**：https://doi.org/10.1145/3341105.3373962 · https://waf-a-mole.readthedocs.io/

### 要点（简述）

- **引导式变异 fuzz**：Case Swapping、Comment Injection、Integer Encoding 等 SQL 语义保持算子
- 以 WAF **分类置信度** 指导变异方向，可 **100% 绕过** 多种 sklearn/Keras ML-WAF
- 本赛题 `mutator.py` 的算子集直接继承该思路；ModSec-AdvLearn 的对抗样本生成亦同源

---

## 横向对比（答辩速查）

| 工作 | 年份 | 攻击面 | 防御/生成 | 对本赛题启示 |
|------|------|--------|-----------|--------------|
| WAF-A-MoLE | 2020 | SQLi 语法变异 | 攻击工具 | mutator 算子库来源 |
| ModSec-AdvLearn | 2025 | 对抗 SQLi | 对抗训练 | 自演化训练闭环 |
| DEG-WAF | 2025 | 多类 Web 攻击 | LLM+RL 生成 | llm_agent 红队对标 |
| WAFFLED | 2025 | 协议解析差异 | HTTP-Normalizer | normalizer 结构层 |
| **IGA-Guard 2.0** | 2026 | 全类型+混淆 | 双路+演化+解释 | 融合上述缺口 |

**综合结论**：2024–2026 文献一致表明——(1) 规则 WAF 在混淆/对抗下失效；(2) 纯 ML payload 分类可被 WAF-A-MoLE 类变异击穿；(3) LLM 自动化将绕过率推至 80%+；(4) **对抗训练 + 解混淆规范化 + 语义小模型** 是当前可工程落地的最优组合。
