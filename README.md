# 2026 第二届大学生人工智能安全竞赛 — 定向式专项命题作品赛

> **参赛作品**：**IGA-Guard 2.0**（题目 2）  
> **作品路径**：[`topics/topic02_web_waf/`](topics/topic02_web_waf/)  
> **竞赛官网**：https://ai-contest.sjtu.edu.cn/

---

## IGA-Guard 2.0

**中文**：IGA-Guard 2.0：面向混淆逃逸攻击的可解释自演化 Web 安全防御系统

| 2.0 目标 | 指标 |
|----------|------|
| 混淆检出率 | > 99.5% |
| 单次延迟 | < 5 ms |
| 定位准确度提升 | ≥ +22% |
| 攻击覆盖 | SQLi/XSS/CMD/LFI/RFI/XXE/Prompt Injection |

**四大创新点**：DLinear-Transformer 双路架构 · GPT 语义解释 · RL-GWO 特征工程 · LLM Agent 对抗闭环

```powershell
cd topics\topic02_web_waf
pip install -r requirements.txt
python scripts/train.py
python run.py
# http://127.0.0.1:5000  → ECharts 大屏
```

---

## 文档索引

| 文档 | 说明 |
|------|------|
| [IGA-Guard README](topics/topic02_web_waf/README.md) | 项目入口 |
| [系统设计 PROJECT.md](topics/topic02_web_waf/docs/PROJECT.md) | 六层架构与八大模块 |
| [实验方案 EXPERIMENTS.md](topics/topic02_web_waf/docs/EXPERIMENTS.md) | 七组实验 |
| [竞赛指南摘要](docs/00_竞赛指南摘要.md) | 报名与评审流程 |
| [交付物清单](docs/03_交付物与提交清单.md) | 初赛材料核对 |

---

## 四大创新点

1. 多层语义恢复载荷归一化（编码链 + AST 还原）
2. 细粒度恶意载荷定位（Token 级 + 热力图）
3. LLM 驱动混淆攻击自动生成
4. 自演化对抗训练闭环

---

## 时间节点

| 日期 | 事项 |
|------|------|
| 07-02 ~ 08-02 | 提交作品 |
| 08-05 ~ 08-15 | 初赛评审 |
| 08-20 ~ 08-22 | 决赛答辩 |
