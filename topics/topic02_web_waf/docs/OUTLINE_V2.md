# IGA-Guard 2.0 大纲速查

> 完整设计见 [PROJECT.md](PROJECT.md) · 实验见 [EXPERIMENTS.md](EXPERIMENTS.md)

## 作品名称

**IGA-Guard 2.0**：面向混淆逃逸攻击的可解释自演化 Web 安全防御系统

## 核心指标

| 指标 | 目标 |
|------|------|
| 混淆检出率 | > 99.5% |
| 单次延迟 | < 5 ms |
| 定位准确度提升 | ≥ +22% |
| 攻击类型 | SQLi/XSS/CMD/LFI/RFI/XXE/Prompt Injection |

## 架构三柱

1. **Dual-Track Engine** — TinyBERT 语义轨 + DLinear 统计轨  
2. **XAI** — WebSpotter 定位 + GPT 自然语言解释  
3. **Self-Evolving Loop** — LLM Agent + Online RL  

## 四大创新点

1. DLinear-Transformer 混合时序语义检测  
2. GPT 驱动交互式恶意载荷语义解释  
3. EnhancedRLGWO 智能特征工程（100+ → 12~15 维）  
4. LLM Attack Agent 持续性对抗训练闭环  

## 一键命令

```powershell
python scripts/generate_dataset.py    # 生成混淆数据集
python scripts/train.py --data data/samples/obfuscated_dataset.csv
python scripts/evaluate.py --data data/samples/obfuscated_dataset.csv
python scripts/eval_explainability.py  # 定位 IoU +22% ✓
python scripts/benchmark_latency.py      # P50 <5ms ✓
python run.py   # ECharts 大屏 → /static/dashboard.html
```
