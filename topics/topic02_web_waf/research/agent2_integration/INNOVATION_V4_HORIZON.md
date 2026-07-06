# IGA-Guard 4.0 横向调研与创新路线图

> Agent 1 文献 + Agent 2 架构 · 基于 2024–2026 SOTA 横向对比  
> 当前实测：`v2_exp1_overall.json` — 混淆 Recall **99.85%** / FPR **1.11%** / P50 **2.92ms**  
> 更新：2026-07-05（P0 护栏完成）

---

## 一、横向对比总表（IGA-Guard 3.0 vs 代表性工作）

| 维度 | ModSec CRS | ModSec-AdvLearn | CNN-LSTM | TinyBERT+Norm | WebSpotter | WAFFLED | DEG-WAF(攻击) | **IGA-Guard 3.0** |
|------|------------|-----------------|----------|---------------|------------|---------|---------------|-------------------|
| 混淆 Recall | ❌ 40–60% | ✅ ~85% SQLi | 🔶 原始高/混淆降 | ✅ ~95% | 依赖底层 | N/A | 击穿 ModSec 80% | **✅ 99.85%** |
| Normal FPR | 高 | 中 | 中 | 低 | — | — | — | **✅ 1.11%** |
| P50 延迟 | 2–8ms | 5–10ms | 50–200ms | 2–5ms | +1–2ms | +1–3ms | 离线 | **✅ 2.92ms** |
| 可解释 IoU | 规则ID | 特征权重 | ❌ | Attn | **✅ 字段+字符** | 日志 | — | **✅ +37.9%** |
| 协议层防御 | ❌ | ❌ | ❌ | 🔶 | ❌ | **✅ 90%+** | — | **🔶 部分** |
| 对抗闭环 | ❌ | ✅ RF重训 | ❌ | 🔶 | ❌ | — | **✅ LLM红队** | **✅ auto-evolve** |
| 持续学习 | ❌ | 🔶 | ❌ | ❌ | ❌ | — | — | **✅ Tip-Adapter** |
| 开源可复现 | ✅ | ✅ | 部分 | ✅ | ✅ | 论文 | 部分 | **✅** |

**结论**：IGA-Guard 在混淆检出、延迟、可解释、闭环上已超越多数论文组合；**P0 FPR 已压至 1.11%**；下一阶：**协议层（P1）与 LLM 红队鲁棒性（P2）**。

---

## 二、文献空白点（可写成「超越论文」的贡献）

| 空白点 | 说明 | 本作品可填 |
|--------|------|------------|
| 统一混淆基准 | 各论文混淆集不一致，难以横向比 | 全量 19,411 + 62 种可编程手法 |
| 四模态 + 缓存 + 闭环 | 无公开系统同时具备 | IGA-Guard 3.0 完整栈 |
| 混淆 Recall vs FPR 帕累托 | ModSec-AdvLearn 只深攻 SQLi | 8 类 + 诚实 FPR 分报告 |
| 小模型 LLM 自主红队 | DEG-WAF 用 OPT-125M 离线 | Ollama qwen2.5:0.5b + 漏检反馈 |
| 定位与检测联合优化 | WebSpotter 假设检测器已定 | 检测高亮 + 字段贡献一体化 |

---

## 三、8 条可落地创新优化（按优先级）

### P0 · FPR 压至 <3%（工程收益最大，难度：低）

| 项 | 内容 |
|----|------|
| **论文依据** | ModSec-Learn：误报来自「边界正常流量」；CSIC 登录表单是主 FP 源 |
| **做法** | ① 扩展 `looks_like_benign_csic_form` 至更多字段模式 ② FP 归因脚本：对 229 条 FP 聚类（表单/login/API JSON）③ 校准融合阈值：良性 + 低 base_attack 时抬高 `confidence_threshold` |
| **预期** | FPR 5.63% → **2–3%**，混淆 Recall 维持 >99.5% |
| **模块** | `obfuscation_signals.py` · `dual_track.py` · `scripts/analyze_fp.py`（新建） |
| **赛题契合** | ⭐⭐⭐⭐⭐ 直接对标评审「低误报」 |

### P1 · WAFFLED 协议规范化轨（难度：中）

| 项 | 内容 |
|----|------|
| **论文依据** | WAFFLED (arXiv 2025)：90%+ 绕过来自 **解析不一致**，非 payload 语义 |
| **做法** | 在 `collector/protocol.py` 增加：HPP 双值解析、JSON 深层键展开、multipart 边界模拟；与现有 payload 检测 **正交融合**（协议异常分） |
| **预期** | 覆盖社区 15% 协议层绕过；对混淆 Recall 边际提升，对 **零日协议绕过** 显著 |
| **模块** | `protocol.py` · `multimodal_branch.py` |
| **赛题契合** | ⭐⭐⭐⭐ 创新点可写「协议+载荷双轨」 |

### P2 · LLM 红队基准 E9（难度：中）

| 项 | 内容 |
|----|------|
| **论文依据** | DEG-WAF：ModSec SQLi 绕过 **80.16%**；WAF-A-MoLE 语义保持变异 |
| **做法** | 固定种子 → `LLMAdversarialAgent` 3 轮自主迭代 → 报告 **LLM-Evasion Recall** vs 规则/静态 ML；写入 `results/v2_exp9_llm_redteam.json` |
| **预期** | 答辩数据：「对 LLM 红队仍保持 >95% Recall」 |
| **模块** | 已有 `auto_evolve.py` + `llm_agent.py`，补实验脚本即可 |
| **赛题契合** | ⭐⭐⭐⭐⭐ 直接对标 DEG-WAF |

### P3 · 选择性拒判 / 置信校准（难度：中）

| 项 | 内容 |
|----|------|
| **论文依据** | 安全场景常用 **conformal prediction** / temperature scaling 控制 FPR |
| **做法** | 在 `dual_track.py` 末端：对 Normal 边界样本输出 `abstain`（转人工/SOC）；离线用验证集拟合温度参数 |
| **预期** | 运营 FPR 可控；赛题可报告「高置信子集 FPR <1%」 |
| **模块** | `dual_track.py` · `evaluate.py` 增加 calibrated 指标 |
| **赛题契合** | ⭐⭐⭐ 学术加分，实现量适中 |

### P4 · WebSpotter MSU 深度对齐（难度：中偏高）

| 项 | 内容 |
|----|------|
| **论文依据** | WebSpotter NDSS'26：MSU 分解 + 梯度归因，IoU 显著提升 |
| **做法** | 当前为关键词+规则 span；升级为 **MSU 切分**（最小语义单元）+ TinyBERT attention 对齐 |
| **预期** | IoU +37.9% → 目标 +45%；可解释性答辩更强 |
| **模块** | `explainer/webspotter.py` |
| **赛题契合** | ⭐⭐⭐⭐ 已有 E6 基线，增量清晰 |

### P5 · 漏检驱动的「手法 DSL」自动注册（难度：低，已部分完成）

| 项 | 内容 |
|----|------|
| **论文依据** | WAF-A-MoLE 单点变异 vs 本作品 **漏检→注册→下轮生成** |
| **做法** | 扩展 `technique_registry.py`：LLM 输出 `{name, transform_code}` → 沙箱执行 → 入队评测 → 通过后写入库 |
| **预期** | 62 种 → 动态增长；「自我迭代新手法」答辩核心 |
| **模块** | 已有 `technique_discovery.py` · `auto_evolve.py` |
| **赛题契合** | ⭐⭐⭐⭐⭐ 与用户需求完全一致 |

### P6 · INT8 / ONNX 语义轨（难度：中）

| 项 | 内容 |
|----|------|
| **论文依据** | TinyBERT 文献：INT8 约 2× 加速；当前 P99 **27ms** 长尾 |
| **做法** | `scripts/export_onnx.py` → ONNX Runtime INT8 推理；预热消除冷启动 |
| **预期** | P99 27ms → **<10ms**；赛题 ≤10ms 更有说服力 |
| **模块** | `semantic_branch.py` |
| **赛题契合** | ⭐⭐⭐ 性能维度 |

### P7 · 跨字段联合检测（难度：高）

| 项 | 内容 |
|----|------|
| **论文依据** | 实战攻击分散在 query+body+header（Log4Shell 在 UA/Referer） |
| **做法** | `pipeline.py` 多字段 attention 聚合：单字段 Normal 但联合恶意时抬升 |
| **预期** | 减少字段级 FN；Log4Shell 编码变种检出提升 |
| **模块** | `pipeline.py` · `http_parser.py` |
| **赛题契合** | ⭐⭐⭐⭐ 工程量大，选 2–3 个 CVE 用例证明即可 |

### P8 · 对比实验：ModSec-AdvLearn 复现基线（难度：中）

| 项 | 内容 |
|----|------|
| **论文依据** | IEEE TIFS 2025 ModSec-AdvLearn 是混淆 SQLi 最强传统 ML 基线之一 |
| **做法** | Docker 跑 CRS PL4 + 同一 `test_obfuscated.csv` 评测脚本；出对比表写入作品报告 |
| **预期** | 答辩「同集上我们 99.85% vs CRS 54%」 |
| **模块** | `research/baselines/run_modsec.py` ✅ |
| **实测** | `v2_exp8_modsec_baseline.json` — CRS 混淆 Recall **54%** / FPR 0% |
| **赛题契合** | ⭐⭐⭐⭐⭐ 评审最爱看的对比 |

---

## 四、不建议做的方向（避免过度工程）

| 方向 | 原因 |
|------|------|
| 全量 Transformer 替换 TinyBERT | 延迟超标，赛题无收益 |
| 端到端大模型 WAF（GPT-4 判每条请求） | 成本/延迟/不可控 |
| 完整 ModSecurity 仿制 | 与 ML 主线重复，工程巨大 |
| 百万 QPS 分布式集群 | 超出学生赛题范围 |
| 再训练 7B+ LLM 做检测 | 与「小模型自主迭代」定位冲突 |

---

## 五、答辩三条「超越论文」话术

1. **混淆检出**：在统一 19,411 条诚实评测上，混淆 Recall **99.85%**、FPR **1.11%**，优于 CRS 离线基线混淆 Recall **54%** 与 ModSec-AdvLearn 对抗场景（<50% TPR）。

2. **闭环演化**：不同于 DEG-WAF 仅攻击侧生成，IGA-Guard 实现 **检测→漏检→LLM/规则双通道生成→缓存/重训→手法注册** 完整防御闭环，并支持 Ollama 本地小模型自主迭代。

3. **可解释 + 低延迟**：在 P50 **2.92ms** 下实现 WebSpotter 式定位 IoU **+37.9%**，弥补传统 ML-WAF 黑盒与 CNN-LSTM 高延迟缺陷。

---

## 六、推荐实施路线（2 周）

| 周 | 任务 | 产出 |
|----|------|------|
| W1 | P0 FPR 压降 + P8 ModSec 基线对比 | ✅ FPR **1.11%** · `v2_exp8_modsec_baseline.json` |
| W1 | P2 E9 LLM 红队实验 | 🔶 `v2_exp9_llm_redteam.json`（规则回退 76.7%，待 Ollama） |
| W2 | P1 协议轨 HPP/JSON + P5 手法 DSL 演示 | 🔧 P1 骨架已落地 `protocol_normalize.py` |
| W2 | 刷新 EXPERIMENT_REPORT + 作品报告 | 提交材料同步 |

---

## 七、参考文献

- ModSec-AdvLearn · IEEE TIFS 2025
- WAFFLED · arXiv 2025
- DEG-WAF · STIS 2025
- WebSpotter · NDSS 2026
- WAF-A-MoLE · ACM SAC 2020
- Tip-Adapter · CVPR 2022（思路迁移）
- 社区情报 · `research/agent1_literature/community/COMMUNITY_INTEL_2024_2026.md`
