# 论文思路 → 代码模块映射表

> Agent 2 · Solution Integrator · 逐条对应文献/赛题要求与 `src/iga_guard/` 实现  
> 2026-06-30 深化 v6 · 已与 `pipeline.py` / `dual_track.py` / `models.py` 行号对齐  
> 图例：✅ 已实现 · 🔶 骨架/待接入 · 📋 计划新增  
> 关联：[`ARCHITECTURE_DECISIONS.md`](ARCHITECTURE_DECISIONS.md) · [`RUNNABLE_PLAN.md`](RUNNABLE_PLAN.md)

---

## 〇、技术路线文档 → 代码包映射

> 来源：[`docs/TECHNICAL_APPROACH.md`](../../docs/TECHNICAL_APPROACH.md)

| 技术路线章节 | 论文/方法 | 代码目录 | ADR |
|--------------|-----------|----------|-----|
| §三 模块 A | Zeng 2023 DLinear | `detector/dlinear_branch.py`, `collector/timeseries_buffer.py` | ADR-001 |
| §四 模块 B | Jiao 2019 TinyBERT | `detector/semantic_branch.py`, `scripts/train_bert.py` | ADR-002 |
| §五 模块 C | WebSpotter 定位 | `explainer/webspotter.py`, `explainer/locator.py` | ADR-004 |
| §六 数据流 | 端到端管线 | `pipeline.py`, `detector/dual_track.py` | ADR-003 |
| §七 赛题对齐 | 五项硬性要求 | 见本文 §十八 | ADR-001~010 |

---

## 一、总览映射

| 来源 | 核心思想 | 代码落点 | 状态 |
|------|----------|----------|------|
| Zeng 2023 DLinear | Trend/Seasonal 分解 + 线性映射 | `detector/dlinear_branch.py` | ✅ |
| Zeng 2023 DLinear | 同源 IP 多元时序窗 T=16 | `collector/timeseries_buffer.py` | 🔶 未接入主管道 |
| Jiao 2019 TinyBERT | 蒸馏小模型短文本分类 | `detector/semantic_branch.py` | 🔶 降级可用 |
| Jiao 2019 TinyBERT | 微调训练流水线 | `scripts/train_bert.py` | 📋 |
| WebSpotter 思想 | 字段贡献 + 字符 span 定位 | `explainer/webspotter.py` | ✅ |
| WebSpotter 思想 | 锚点词与热力图 | `explainer/locator.py` | ✅ |
| RL-GWO 启发 | 100+ → 15 维特征筛选 | `features/rl_gwo_selector.py` | ✅ |
| 赛题：解混淆 | 多层 URL/HTML/AST 还原 | `normalizer/decoder.py`, `ast_restore.py` | ✅ |
| 赛题：混淆生成 | SQLi/XSS 规则变异 | `adversarial/mutator.py` | ✅ |
| 赛题：混淆生成 | AST/逻辑等价替换 | `adversarial/ast_mutator.py` | ✅ |
| 赛题：混淆生成 | LLM 零日变种 | `adversarial/llm_agent.py` | 🔶 需 API |
| 赛题：≤10ms | 规则早退 + LRU 缓存 | `pipeline.py` | ✅ |
| 赛题：对抗模型 | XGB/RF 基座 + 双路融合 | `detector/fusion_model.py`, `dual_track.py` | ✅ |
| 赛题：可演示 | REST API + 大屏 | `backend/app.py`, `frontend/static/dashboard.html` | ✅ |
| Online RL | 阈值/权重在线调整 | `evolution/online_rl.py` | ✅ |
| 自演化 | 漏检样本增量训练 | `evolution/self_train.py` | ✅ |
| 虚拟补丁 | CVE 载荷临时规则 | `rules/virtual_patch.py` | ✅ |
| WAF 联动 | ModSecurity 规则导出 | `rules/generator.py` | ✅ |

---

## 二、端到端调用链（单请求）

```
run.py / backend/app.py
    └── IgaGuardEngine.analyze_request()          [pipeline.py]
            ├── parse_http_request()                [collector/http_parser.py]
            ├── iter_payload_parts()                [collector/http_parser.py]
            ├── normalize_payload()                 [normalizer/decoder.py, ast_restore.py]
            ├── match_virtual_patch()               [rules/virtual_patch.py]  ← 快路径
            ├── DualTrackDetector.predict()         [detector/dual_track.py]
            │       ├── extract_features()          [features/__init__.py]
            │       │       └── RLGWoFeatureSelector [features/rl_gwo_selector.py]
            │       ├── FusionDetector.predict()    [detector/fusion_model.py]
            │       ├── SemanticBranch.class_bias() [detector/semantic_branch.py]
            │       └── DLinearBranch.score_anomaly [detector/dlinear_branch.py]
            │               └── (W1) TimeseriesBuffer.get_sequence [collector/timeseries_buffer.py]
            ├── webspotter_explain()                [explainer/webspotter.py]
            ├── generate_nl_explanation()           [explainer/nl_explanation.py]
            └── generate_rule()                     [rules/generator.py]
                    └── GuardReport.to_dict()       [models.py] → API JSON
```

---

## 三、模块 A：DLinear 时序异常（Zeng 2023）

### 3.1 论文要点

```
X_t = Trend_t + Seasonal_t
ŷ = Linear(Trend) + Linear(Seasonal)
异常 → 残差能量 / 趋势斜率突变
```

### 3.2 代码映射

| 论文概念 | 实现位置 | 函数/配置 | 说明 |
|----------|----------|-----------|------|
| 移动平均分解 | `dlinear_branch.py` L20-24 | `_moving_average()` | `moving_avg=4` |
| Trend 分量 | `dlinear_branch.py` L31 | `encode()` → `trend` | 卷积平滑 |
| Seasonal/残差 | `dlinear_branch.py` L32 | `seasonal = seq - trend` | 高频异常载体 |
| 残差能量 | `dlinear_branch.py` L34 | `residual_energy` | 异常打分主信号 |
| 趋势斜率 | `dlinear_branch.py` L35 | `trend_slope` | 扫描前奏检测 |
| 异常打分 | `dlinear_branch.py` L40-42 | `score_anomaly()` | sigmoid 归一化 → [0,1] |
| 输入序列长度 T | `configs/default.yaml` L32-34 | `dlinear.seq_len: 16` | 与文献窗长消融一致 |
| 时序特征向量 | `features/statistical.py` | 熵、编码比等 | 填入 `fv.combined` |
| HTTP 时序窗 | `collector/timeseries_buffer.py` L21-44 | `push()`, `get_sequence()`, `update_from_payload()` | 🔶 W1 接入 pipeline |
| 全局单例 | `timeseries_buffer.py` L47-53 | `get_timeseries_buffer()` | 按 `src_ip` 分桶 |
| 与语义轨融合 | `dual_track.py` L45-56 | `predict()` | anomaly 权重 20% |
| 文献卡片 | `research/agent1_literature/papers/01_dlinear_aaai2023.md` | — | Agent 1 产出 |

### 3.3 数据流（目标态 W1 完成后）

```
HttpRequest (src_ip)
    → http_parser.py
    → timeseries_buffer.update_from_payload(key=src_ip)
    → get_sequence(dim=16) 替代 fv.combined[:16] 伪序列
    → DLinearBranch.encode() → score_anomaly()
    → dual_track 融合 20%
```

---

## 四、模块 B：TinyBERT 语义识别（Jiao 2019）

### 4.1 论文要点

- 6 层 BERT 蒸馏，短文本分类保留 96%+ 性能
- 适合 ≤512 token 的 WAF payload
- 可与统计特征后融合（非端到端联合训练）

### 4.2 代码映射

| 论文概念 | 实现位置 | 函数/配置 | 说明 |
|----------|----------|-----------|------|
| 模型懒加载 | `semantic_branch.py` L18-30 | `_lazy_load()` | `transformers.pipeline` |
| 输入文本 | `normalizer/` 输出 | `NormalizedPayload.normalized_payload` | 解混淆后 |
| 嵌入编码 | `semantic_branch.py` L32-39 | `encode()` | [CLS] 范数 |
| Trigram 降级 | `semantic_branch.py` L42-49 | 无 transformers 时 | 可疑词密度 |
| 类别偏置 | `semantic_branch.py` L51+ | `class_bias()` | 映射 8 类标签 |
| 模型配置 | `default.yaml` L12-13 | `semantic_model`, `use_semantic_branch` | 默认关闭 |
| 训练脚本 | `scripts/train_bert.py` | — | 📋 W2 |
| 模型权重 | `models/tinybert_waf/` | — | 📋 训练产出 |
| 与 XGB 融合 | `dual_track.py` L45, L52 | `sem_bias` 权重 30% | Feature Fusion |
| 8 类标签 | `models.py` L9-18 | `ATTACK_LABELS` | 含 XXE、PromptInjection |

---

## 五、模块 C：WebSpotter 可解释性

| 概念 | 实现位置 | 函数/输出字段 |
|------|----------|---------------|
| 字段贡献度 | `webspotter.py` | `_field_contributions()` → `field_contributions` |
| 锚点 span 定位 | `webspotter.py` L11-18, L51+ | `ANCHOR_KEYWORDS`, `_locate_span()` |
| 复合 SQLi 锚点 | `webspotter.py` L58-60 | `union\s+select` 正则 |
| 字符热力图 | `locator.py` | `_build_heatmap()` |
| 高亮 HTML | `webspotter.py` | `to_highlight_html()` → `highlight_html` | 📋 W3 待实现 |
| 自然语言解释 | `nl_explanation.py` | `generate_nl_explanation()` |
| 管道集成 | `pipeline.py` L95-99 | `GuardReport.explanation` |
| 前端渲染 | `frontend/static/dashboard.html` | `v-html` + ECharts 贡献条形图 |
| 评估脚本 | `scripts/eval_explainability.py` | IoU / 命中率 → E6 |

---

## 六、模块 D：特征工程与 RL-GWO

| 特征族 | 论文/赛题依据 | 代码文件 | 关键特征 |
|--------|---------------|----------|----------|
| 统计 | 熵、编码检测 | `features/statistical.py` | `entropy`, `encoded_ratio`, `special_char_ratio` |
| 语义 | 关键词/embedding | `features/semantic.py` | `sqli_score`, `xss_score`, `prompt_score` |
| 结构 | AST/DOM 深度 | `features/structural.py` | `ast_depth`, `html_nodes` |
| 时序 | DLinear 分量 | `dlinear_branch.py` | `residual_energy`, `trend_slope` |
| 筛选器 | GWO + RL 权重 | `rl_gwo_selector.py` | `select()`, `update_weights()` |
| 统一提取 | — | `features/__init__.py` | `extract_features()` → `FeatureVector` |

**赛题「载荷净化与特征提取」映射**：`normalizer/`（净化）→ `extract_features()`（提取）→ `rl_gwo_selector`（筛选）→ `fusion_model`（建模）。

---

## 七、模块 E：对抗生成与自演化

| 赛题/论文能力 | 实现 | 函数/入口 | 调用方 |
|---------------|------|-----------|--------|
| URL/注释/大小写混淆 | `mutator.py` | `mutate_payload()` | `generate_dataset.py` |
| AST 逻辑拆分 | `ast_mutator.py` | `ast_mutate()` | E2 零日测试 |
| LLM 变种生成 | `llm_agent.py` | `generate_variants()` | E3 对抗轮次 |
| 漏检缓存 | `default.yaml` L41 | `evolution.failure_cache` | `self_train.py` |
| 在线 RL 反馈 | `online_rl.py` | `feedback()` | 调 `_rl_thresholds` |
| 增量重训 | `self_train.py` | `retrain_from_failures()` | E7 演化实验 |
| 对抗自动化 | `scripts/run_adversarial.py` | — | 📋 W4 |

**赛题「混淆载荷自动生成器」映射**：三源生成器 + `generate_dataset.py` 批量产出 + E3 闭环验证。

---

## 八、模块 F：采集、协议与规则

| 功能 | 文件 | 关键符号 |
|------|------|----------|
| HTTP/1.1 解析 | `collector/http_parser.py` | `parse_http_request`, `iter_payload_parts` |
| HTTP/2/3/WS 骨架 | `collector/protocol.py` | 🔶 帧/日志适配 |
| 请求/报告模型 | `models.py` | `HttpRequest`, `DetectionResult`, `GuardReport` |
| 主管道 | `pipeline.py` | `IgaGuardEngine`, `_EARLY_EXIT_CONF` |
| 虚拟补丁 | `rules/virtual_patch.py` | `match_virtual_patch`, `export_virtual_patch_rule` |
| 规则导出 | `rules/generator.py` | ModSecurity 格式 |

---

## 九、入口与运维脚本

| 脚本 | 映射实验 | 产出文件 |
|------|----------|----------|
| `scripts/generate_dataset.py` | 混淆集构建 | `data/samples/obfuscated_*.csv` |
| `scripts/train.py` | XGB/RF 基座 | `models/fusion_detector.joblib` |
| `scripts/train_bert.py` | TinyBERT 微调 | `models/tinybert_waf/` 📋 |
| `scripts/evaluate.py` | **E1** 整体性能 | stdout + metrics |
| `scripts/benchmark_latency.py` | **E4a** 延迟 | `results/v2_exp4_latency.json` |
| `scripts/stress_test.py` | **E4b** 压测 | `results/v2_exp4_stress.json` |
| `scripts/eval_explainability.py` | **E6** 定位 | `results/v2_exp6_localization.json` |
| `scripts/run_adversarial.py` | **E3** 对抗 | `results/v2_exp3_adversarial_rounds.csv` 📋 |
| `scripts/detect.py` | CLI 单条检测 | — |
| `run.py` / `backend/app.py` | API 服务 | `/api/detect`, `/api/stats` |

---

## 十、配置 → 模块开关

| `default.yaml` 键 | 影响模块 | ADR |
|-------------------|----------|-----|
| `detector.engine` | `dual_track` vs `fusion` | ADR-003 |
| `detector.use_semantic_branch` | `semantic_branch.py` | ADR-002 |
| `dlinear.seq_len` | `dlinear_branch.py`, `timeseries_buffer.py` | ADR-001 |
| `features.rl_gwo_enabled` | `rl_gwo_selector.py` | ADR-007 |
| `evolution.online_rl_enabled` | `online_rl.py` | ADR-006 |
| `llm_agent.enabled` | `llm_agent.py` | ADR-006 |
| `explanation.nl_provider` | `nl_explanation.py` | ADR-004 |
| `rules.virtual_patch_enabled` | `virtual_patch.py` | ADR-003 |
| `detector.semantic_conditional` | `semantic_branch.py` `should_run()` | ADR-010 📋 W4 待写入 yaml |
| `latency.target_ms` | `benchmark_latency.py` 通过判定 | ADR-010 |

---

## 十-B、评估脚本输出 → 结果文件映射

| 脚本 | stdout / 落盘字段 | 含义 | 周验收阈值 |
|------|-------------------|------|------------|
| `evaluate.py` | `obfuscated_subset.recall_malicious` | 混淆子集 Recall | W1 ≥0.85 / W2 ≥0.95 / W4 ≥0.995 |
| `evaluate.py` | `pass` | 是否达 99.5% 硬线 | W5 必为 `true` |
| `evaluate.py` | → `results/v2_exp1_overall.json` | E1 主结果 | W5 |
| `benchmark_latency.py` | `p50_ms`, `p99_ms` | 延迟分位 | W1 P50<5 / W2 P99<10 / W4 P99<5 |
| `benchmark_latency.py` | → `results/v2_exp4_latency.json` | E4 主结果 | W4/W5 |
| `eval_explainability.py` | `delta_iou` | 较关键词基线提升 | W3 ≥0.22 |
| `eval_explainability.py` | → `results/v2_exp6_localization.json` | E6 主结果 | W3/W5 |
| `stress_test.py` | → `results/v2_exp4_stress.json` | QPS / 错误率 | W4 错误率 <0.1% |

**指标读取示例（周验收后自动判定）：**

```powershell
python -c "import json; d=json.load(open('results/v2_exp1_overall.json')); print('obf_recall', d['obfuscated_subset']['recall_malicious'], 'PASS' if d.get('pass') else 'CHECK')"
python -c "import json; d=json.load(open('results/v2_exp4_latency.json')); print('p99_ms', d['p99_ms'])"
```

---

## 十一、创新点 → 代码 → 实验 三角映射

| 创新点 | 核心代码 | 主实验 | 结果文件 |
|--------|----------|--------|----------|
| 1 双流融合 | `dual_track.py`, `dlinear_branch.py`, `semantic_branch.py` | E1, E5 | `v2_exp1_overall.json`, `v2_exp5_ablation.csv` |
| 2 可解释高亮 | `webspotter.py`, `locator.py`, `dashboard.html` | E6 | `v2_exp6_localization.json` |
| 3 RL 特征工程 | `rl_gwo_selector.py`, `online_rl.py` | E5, E7 | `v2_exp5_ablation.csv`, `v2_exp7_evolution.json` |
| 4 自演化闭环 | `mutator.py`, `ast_mutator.py`, `llm_agent.py`, `self_train.py` | E2, E3, E7, E8 | `v2_exp3_*.csv`, `v2_exp8_virtual_patch.json` |

---

## 十二、W1 接入规范（buffer → DLinear 目标态）

> 当前缺口：`pipeline.py` 未调用 `get_timeseries_buffer()`；`dlinear_branch.encode()` 仍用 `fv.combined[:16]` 伪序列；`HttpRequest` 无 `src_ip` 字段。

### 12.0 W1 前置：`models.py` 增加 `src_ip`

| 改动 | 文件 | 说明 |
|------|------|------|
| 新增字段 | `models.py` `HttpRequest` | `src_ip: str = ""` |
| API 注入 | `backend/app.py` `detect()` | 从 JSON `src_ip` 或 `X-Forwarded-For` 写入 |
| 解析注入 | `collector/http_parser.py` | `parse_http_request(..., src_ip="")` 可选参数 |

### 12.1 `pipeline.py` 改动点

```python
# 在 analyze_request() 循环内，normalize 之后、detector.predict 之前：
from iga_guard.collector.timeseries_buffer import get_timeseries_buffer

buf = get_timeseries_buffer(self.config.get("dlinear", {}).get("seq_len", 16))
key = req.src_ip or "global"
buf.update_from_payload(key, norm)
```

### 12.2 `dual_track.py` 改动点

```python
# predict() 内，替换 dlinear.encode 调用：
from iga_guard.collector.timeseries_buffer import get_timeseries_buffer

buf = get_timeseries_buffer(self.dlinear.seq_len)
seq = buf.get_sequence(payload.src_ip or "global", dim=self.dlinear.seq_len)
dlinear_enc = self.dlinear.encode_from_sequence(seq, fv)  # 新增方法
```

### 12.3 `dlinear_branch.py` 新增方法

| 方法 | 输入 | 输出 | 说明 |
|------|------|------|------|
| `encode_from_sequence(seq, fv)` | `np.ndarray` 时序窗 + 当前 `FeatureVector` | 3 维编码向量 | 替代 `fv.combined[:16]` |
| `encode(payload, fv)` | 保留 | 降级路径 | buffer 冷启动时 fallback |

### 12.4 W1 单元测试契约

| 测试文件 | 断言 |
|----------|------|
| `tests/test_timeseries_buffer.py` | 同源 IP 连续 push 16 次 → `get_sequence().shape == (16,)` |
| `tests/test_dlinear_anomaly.py` | 低速 SQLi 序列 `score_anomaly()` > 正常序列 +0.15 |

---

## 十三、待实现缺口（按周次）

| 周次 | 优先级 | 缺口 | 目标文件 | ADR |
|------|--------|------|----------|-----|
| W1 | P0 | `HttpRequest.src_ip` 字段 | `models.py`, `backend/app.py` | ADR-001 |
| W1 | P0 | buffer 接入主管道 | `pipeline.py`, `dual_track.py` | ADR-001 |
| W1 | P0 | 时序单元测试 | `tests/test_timeseries_buffer.py` | ADR-008 |
| W2 | P0 | TinyBERT 训练 | `scripts/train_bert.py` | ADR-002 |
| W3 | P1 | API `highlight_html` 字段 | `models.py` `to_dict()` | ADR-004 |
| W4 | P2 | E3 自动化 | `scripts/run_adversarial.py` | ADR-006 |

详见 [`RUNNABLE_PLAN.md`](RUNNABLE_PLAN.md) 五周里程碑。

---

## 十四、Agent 1 文献卡片 → 代码索引

| 文献卡片路径 | 论文 | 代码落点 | 状态 |
|--------------|------|----------|------|
| `research/agent1_literature/papers/01_dlinear_aaai2023.md` | Zeng AAAI'23 DLinear | `dlinear_branch.py`, `timeseries_buffer.py` | 🔶 buffer 待接入 |
| `research/agent1_literature/LITERATURE_REVIEW.md` §二 | Jiao 2019 TinyBERT | `semantic_branch.py`, `train_bert.py` | 🔶 训练待建 |
| `research/agent1_literature/LITERATURE_REVIEW.md` §三 | WebSpotter 思想 | `webspotter.py`, `locator.py` | ✅ |
| `research/agent1_literature/LITERATURE_REVIEW.md` §四 | 对抗/混淆逃逸 | `adversarial/`, `evolution/` | ✅ 生成器 / 🔶 E3 脚本 |

---

## 十五、当前代码审计快照（2026-06-30）

| 检查项 | 预期 | 实际 | 修复周次 |
|--------|------|------|----------|
| `pipeline.py` 调用 `get_timeseries_buffer()` | W1 前接入 | ❌ 未调用 | W1 |
| `dual_track.py` 传入 buffer 序列给 DLinear | W1 前 | ❌ 仍走 `fv.combined[:16]` | W1 |
| `use_semantic_branch` | W2 开启 | `false` | W2 |
| `tests/test_timeseries_buffer.py` | W1 存在 | ❌ `tests/` 目录缺失 | W1 |
| `scripts/train_bert.py` | W2 存在 | ❌ 缺失 | W2 |
| `scripts/run_adversarial.py` | W4 存在 | ❌ 缺失 | W4 |
| `virtual_patch.py` | 可用 | ✅ | — |
| `eval_explainability.py` | 可用 | ✅ | — |
| `models.py` `to_dict()` 含 `highlight_html` | W3 | ❌ 仅 `malicious_span` | W3 |
| `webspotter.py` `to_highlight_html()` | W3 | ❌ 函数未实现 | W3 |

---

## 十六、REST API 端点 → 代码映射

| HTTP | 路径 | 处理函数 | 后端文件 | 数据用途 |
|------|------|----------|----------|----------|
| POST | `/api/detect` | `detect()` | `backend/app.py` | 单请求检测 → `IgaGuardEngine.analyze_request()` |
| GET | `/api/stats` | `stats()` | `backend/app.py` | 攻击类型分布 → 大屏饼图 |
| GET | `/api/alerts` | `alerts()` | `backend/app.py` | 最近告警流 → 大屏滚动列表 |
| GET | `/api/evolution/history` | `evolution_history()` | `backend/app.py` | E7 演化曲线 → 大屏 P5 |
| GET | `/api/metrics/latency` | `latency_metrics()` | `backend/app.py` | E4 延迟趋势 → 大屏 P6 |
| GET | `/static/dashboard.html` | 静态文件 | `frontend/static/dashboard.html` | 六页演示大屏 |

**`POST /api/detect` 响应字段 → 代码产出：**

| JSON 字段 | 来源模块 | 函数/类 |
|-----------|----------|---------|
| `label`, `confidence`, `risk_level` | `detector/dual_track.py` | `DetectionResult` |
| `explanation.highlight_html` | `explainer/webspotter.py` | `to_highlight_html()` |
| `explanation.token_range` | `explainer/webspotter.py` | `_locate_span()` |
| `explanation.field_contributions` | `explainer/webspotter.py` | `_field_contributions()` |
| `explanation.nl_text` | `explainer/nl_explanation.py` | `generate_nl_explanation()` |
| `latency_ms` | `pipeline.py` | `analyze_request()` 计时 |
| `decode_chain` | `normalizer/decoder.py` | `NormalizedPayload.decode_chain` |

---

## 十七、函数级速查附录

| 文件 | 导出符号 | 调用方 |
|------|----------|--------|
| `features/__init__.py` | `extract_features()` | `dual_track.py`, `timeseries_buffer.py` |
| `normalizer/__init__.py` | `normalize_payload()` | `pipeline.py` |
| `detector/fusion_model.py` | `FusionDetector.predict()` | `dual_track.py` |
| `detector/semantic_branch.py` | `SemanticBranch.class_bias()` | `dual_track.py` |
| `detector/dlinear_branch.py` | `encode()`, `score_anomaly()` | `dual_track.py` |
| `collector/timeseries_buffer.py` | `get_timeseries_buffer()` | 📋 W1 `pipeline.py` |
| `adversarial/mutator.py` | `mutate_payload()` | `generate_dataset.py` |
| `evolution/online_rl.py` | `feedback()` | `self_train.py`, E7 |
| `evolution/self_train.py` | `retrain_from_failures()` | E3/E7 |
| `rules/virtual_patch.py` | `match_virtual_patch()` | `pipeline.py` 快路径 |
| `models.py` | `GuardReport.to_dict()` | `backend/app.py` JSON 序列化 |

---

## 十八、赛题五项要求逐条落地检查表

> 来源：`docs/PROJECT.md` §十 · 每条对应可运行验收命令

| # | 赛题硬性要求 | 论文/思路来源 | 核心代码路径 | 验收脚本 | 目标指标 | 状态 |
|---|--------------|---------------|--------------|----------|----------|------|
| 1 | 载荷净化与特征提取 | 多层解码 + RL-GWO | `normalizer/`, `features/rl_gwo_selector.py` | `evaluate.py` + E5 | 15 维不降 F1 | ✅ / 🔶 |
| 2 | 对抗性检测模型 | DLinear + TinyBERT 双流 | `detector/dual_track.py` | E1 `evaluate.py` | 混淆 Recall >99.5% | 🔶 W4 |
| 3 | 混淆载荷自动生成器 | mutator + AST + LLM | `adversarial/*.py`, `generate_dataset.py` | E2/E3 | 变种 ≥8、零日 ≥95% | 🔶 W3/W4 |
| 4 | 检测耗时 ≤10ms | 快路径 + 轻量模型 | `pipeline.py`, ADR-010 | E4 `benchmark_latency.py` | P99 ≤10ms（目标 <5ms） | 🔶 W4 |
| 5 | 可解释性 / 可演示 | WebSpotter + 大屏 | `explainer/`, `dashboard.html` | E6 + curl 大屏 | IoU +22%、3min 演示 | 🔶 W3 |

**一键自检（复制执行）：**

```powershell
cd d:\Code_development\gitproduct\caisa_contest_2026\topics\topic02_web_waf
python scripts/evaluate.py --data data/samples/labeled_samples.csv          # #1+#2 冒烟
python scripts/generate_dataset.py --variants 5                              # #3 生成器
python scripts/benchmark_latency.py --iterations 1000                        # #4 延迟
python scripts/eval_explainability.py                                          # #5 定位
python run.py   # Ctrl+C 后访问 /static/dashboard.html                       # #5 演示
```

---

## 十九、`FeatureVector` 字段 → 特征文件映射

| `FeatureVector` 子字典 | 键示例 | 产出文件 | 进入 RL-GWO |
|------------------------|--------|----------|-------------|
| `statistical` | `entropy`, `encoded_ratio`, `special_char_ratio` | `features/statistical.py` | ✅ 默认入选 |
| `semantic` | `sqli_score`, `xss_score`, `prompt_score` | `features/semantic.py` | ✅ |
| `structural` | `ast_depth`, `html_nodes`, `comment_ratio` | `features/structural.py` | ✅ |
| `combined` | 100+ 维拼接向量 | `features/__init__.py` `extract_features()` | 经 `rl_gwo_selector.select()` 降至 15 维 |
| DLinear 编码 | `residual_energy`, `trend_slope` | `dlinear_branch.py` `encode()` | 不经过 GWO，直接融合 20% |

---

## 二十、数据文件 → 实验 → 脚本依赖图

```
labeled_samples.csv ──────► evaluate.py (日冒烟)
        │
        ▼
generate_dataset.py ──► obfuscated_dataset.csv ──► train.py / train_bert.py
        │                        │
        │                        ├──► evaluate.py (E1)
        │                        └──► benchmark_latency.py (E4)
        ▼
obfuscated_10k.csv (W3) ──► evaluate.py + run_adversarial.py (E3)
        │
failures.jsonl ◄── 漏检缓存 ◄── self_train.py ◄── online_rl.py (E7)
        │
        ▼
results/v2_exp*.json / *.csv ──► INNOVATION.md 实测填入 + 大屏 API
```
