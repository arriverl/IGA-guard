# Agent 4 · 真实数据集采集代理

> 专职从公开源拉取真实 Web 攻击流量与载荷，应用文献级混淆手法扩充，产出 IGA-Guard 完整训练/测试集。

## 数据源（全部真实，非模拟）

| 来源 | 类型 | 路径 |
|------|------|------|
| **CSIC 2010** | 真实 HTTP 电商流量（GSI 标注版） | `data/raw/csic/cisc_*.txt` |
| **SecLists** | 社区维护渗透测试字典 | `data/raw/public/seclists/` |
| **FuzzDB** | 开源攻击载荷库 | `data/raw/public/fuzzdb/` |
| **PayloadsAllTheThings** | OWASP 风格实战 Payload | `data/raw/public/payloads_all_the_things/` |
| **项目种子集** | 手工标注 8 类攻击 | `data/samples/labeled_samples.csv` |

## 混淆扩充（20+ 技术）

基于 ModSec-AdvLearn、WAF-A-MoLE、WAFFLED 文献：

- URL 单/双编码、Unicode、Hex、HTML 实体、Base64
- MySQL 版本注释 `/*!50000*/`、内联注释 `/**/`
- 关键字 CONCAT 拆分、空白符替换、NULL 字节
- XSS：SVG/onload、img onerror 包裹

实现：`src/iga_guard/dataset/obfuscation_techniques.py`

## 一键命令

```powershell
cd d:\Code_development\gitproduct\caisa_contest_2026\topics\topic02_web_waf
$env:PYTHONPATH="src"

# 1. 采集 + 合并 + 混淆扩充
python scripts/dataset_agent.py

# 2. 完整流水线（RF + TinyBERT + 评估）
python scripts/run_full_pipeline.py

# 仅 RF + 评估（跳过 BERT）
python scripts/run_full_pipeline.py --skip-bert
```

## 产出文件

```
data/master/
  full.csv              # 去重后基线（~4.7 万）
  train.csv / test.csv
  full_obfuscated.csv   # 混淆扩充（~10 万+）
  train_obfuscated.csv / test_obfuscated.csv
```

## 与创新点对齐

| 创新点 | 数据集支撑 |
|--------|------------|
| DLinear 时序轨 | CSIC 按请求序列模拟同 IP 窗口 |
| TinyBERT 语义轨 | 真实多类 Payload 微调 |
| WebSpotter 可解释 | CSIC 攻击载荷定位评估 |
| 自演化对抗 | `obfuscation:*` 变体 + `run_adversarial.py` |
