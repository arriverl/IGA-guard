# 产物保留策略

> 中间迭代快照可安全删除；权威结果与最新 checkpoint 必须保留。  
> 清理命令：`bash scripts/clean_artifacts.sh`（可加 `--dry-run` 预览）

## 保留清单

### 模型

| 路径 | 说明 |
|------|------|
| `models/tinybert_waf/model.safetensors` | 生产推理权重（≈17MB） |
| `models/tinybert_waf/checkpoint-34380/` | 最终训练 checkpoint（可复现/继续微调） |
| `models/tinybert_waf/tokenizer.*` | 分词器 |
| `models/fusion_detector.joblib` | RF 融合模型 |
| `models/continual_cache.npz` | Tip-Adapter 持续学习缓存 |

### 日志（`logs/`）

| 文件 | 说明 |
|------|------|
| `train_bert_final.log` | TinyBERT 全量训练主日志 |
| `train_bert_master.log` | 训练过程汇总 |
| `eval_full_v3.log` / `eval_full_master.log` | 全量 E1 评测 |
| `latency_full.log` | E4 延迟 benchmark |
| `adversarial_full.log` | 对抗演化 |
| `eval_explain_full.log` | E6 可解释性 |

### 结果 JSON（`results/`）

| 文件 | 说明 |
|------|------|
| `v2_exp1_auto_{2k,4k,nocache_2k}.json` | auto_verify E1 门禁 |
| `v2_exp1_overall_dynamic_guard_final*.json` | 全量 dynamic guard 终稿 |
| `v2_exp1_iter_opt_2k_v{21,22}_*.json` | 最新 2k 迭代 |
| `v2_exp1_iter_opt_4k_v21_*.json` | 最新 4k 迭代 |
| `v2_exp4_latency.json` | E4 延迟（P99≈13ms） |
| `v2_exp6_localization.json` | E6 WebSpotter |
| `v2_exp8_virtual_patch.json` | E8 虚拟补丁 |
| `v2_exp9_auto_{40,80}.json` | E9 LLM 红队 |
| `v2_exp9_dynamic_guard_80_v3.json` | E9 80 最佳轮次 |
| `auto_verify_report.json` | 全自动检验报告 |
| `iga_dynamic_guard_final_report.md` | 答辩综合报告 |

### 评测缓存（`data/cache/`）

| 文件 | 说明 |
|------|------|
| `eval_obf_misses.jsonl` | 当前漏检明细 |
| `eval_normal_fps.jsonl` | FP 回放基线 |
| `*_v21_*` / `*_v22_*` | 最新迭代快照 |
| `*_overall_dynamic_guard_final*` | 全量终稿快照 |
| `discovered_techniques.json` | 演化手法注册表 |
| `discovered_rescue_rules.json` | Miss→Rule 动态规则 |
| `rag_index.npz` | RAG 索引 |
| `auto_evolve_*.jsonl` | 演化审计链 |

## 可删除（已由 clean_artifacts.sh 处理）

- `checkpoint-5` … `checkpoint-27504`（中间训练步）
- `results/v2_exp1_iter_opt_*_v{4–20}_*.json` 等历史迭代
- `data/cache/eval_*_v{4–20}_*.jsonl`
- `__pycache__/`, `.pytest_cache/`, `data/cache/auto_verify_logs/`（可再生成）
- 重复目录 `IGA-Guard3_submission/`（权威源为 `submission/`）
