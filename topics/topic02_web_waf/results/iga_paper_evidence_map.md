# IGA-Guard 优化建议论文级证据映射

## WAFEC / OWASP-WASC

- 证据要点：WAF 评估不只比较拦截率，还要管理 false positives，并支持把合法请求纳入策略例外。
- IGA 映射：保留 `--export-fps`、FP 聚类和 CSIC 正常上下文护栏，把 FP 管理作为正式验证门槛。

## ModSec-Learn / ModSec-AdvLearn

- 证据要点：固定 CRS 规则权重通常不能获得最佳 TPR/FPR；用 ML 学习规则权重、特征选择和对抗训练可提高 SQLi 检测和鲁棒性。
- IGA 映射：不要继续依赖单个全局 threshold；优先收紧弱结构 SQLi 规则，把规则分、结构分、evasion 分作为可校准特征。

## Cascaded NLP SQLi Detection

- 证据要点：两阶段级联可先用快速模型高召回筛查，再用更重模型复核以压低误报。
- IGA 映射：保留 `FusionDetector` 快路径，扩展 `SemanticBranch._needs_semantic_deep()` 只对 hex32/HPP/高风险短载荷深检，避免对所有正常请求增加延迟。

## AdvSQLi / WAF-A-MoLE / WAFBOOSTER

- 证据要点：功能保持的 SQLi 变换、突变式 fuzzing 和 shadow-model 生成能系统发现 WAF 绕过，防御侧应把 miss 反哺规则和训练。
- IGA 映射：保留 `auto_evolve_round_misses.jsonl`，将 E9 miss 映射到 targeted rescue / rule discovery，而不是只重训 RF。

## LLM/RL WAF Red Teaming / GenSQLi

- 证据要点：LLM 与强化学习可自动生成多样化绕过载荷，也可自动归类 bypass 并生成防御规则。
- IGA 映射：E9 需要固定 40/80 variants 复测口径；通过后仍要保存 miss 明细和变异来源，作为下一轮规则修补输入。
