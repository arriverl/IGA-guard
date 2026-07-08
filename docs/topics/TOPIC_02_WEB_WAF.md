# 题目 2：针对混淆逃逸的 Web 攻击载荷动态检测与对抗方案

## 实现状态

**作品路径**：[`topics/topic02_web_waf/`](../../topics/topic02_web_waf/)  
**主入口**：[`topics/topic02_web_waf/README.md`](../../topics/topic02_web_waf/README.md)

已实现模块：

- 多层解混淆 + 四模态融合检测（RF / TinyBERT / 多模态 / DLinear）
- Miss→Rule 闭环（`miss_rule_pipeline.py`）+ 动态 rescue 热加载
- LLM 红队对抗演化（E9）+ 置信度引导变异
- WebSpotter 可解释定位 + 虚拟补丁（E8）
- VPS Inline 流量代理（`deploy/start_vps.sh`）

## 最新指标（2026-07-08）

见 [`results/canonical_metrics.json`](../../topics/topic02_web_waf/results/canonical_metrics.json)

| 指标 | 实测 |
|------|------|
| E1 obf recall（2k） | 99.91% |
| E4 P99 | 13.3 ms |
| E9 pooled（80 variants） | 98.96% |
| pytest | 89 passed |

## 题目背景

传统 WAF 依赖已知特征库，攻击者通过编码混淆、SQL/命令变形、脚本模糊等绕过静态匹配。本赛题要求设计能应对混淆逃逸的动态检测方案。

## 系统模块

### 1. 载荷净化与特征提取

- 输入：HTTP URL、Body、Headers
- 净化：多层解码、HTML 实体还原、字符串拼接还原
- 输出：静态特征 + 动态特征向量

### 2. 对抗性检测模型

- 传统 ML（RF/SVM）或轻量 DL（TextCNN、字符级 LSTM）
- 针对混淆样本优化训练

### 3. 混淆对抗模拟

- 混淆载荷生成器：随机插字符、编码变换、等价语句替换
- 用于测试与数据增强

## 性能约束

- **单次 HTTP 请求检测 ≤10 毫秒**

## 技术方案建议

```
HTTP Request
    → Parser (URL/Body/Headers)
    → Normalizer (urldecode, html_unescape, concat_restore)
    → Feature Extractor (n-gram, entropy, special_char_ratio, ...)
    → Classifier (lightweight)
    → Label + confidence
```

### 性能优化要点

- 特征预计算模板
- 模型序列化 + ONNX
- 避免重复解码（缓存归一化结果）

## 评价标准

| 维度 | 权重 |
|------|------|
| 检测效果（混淆集漏报/误报） | 40% |
| 方案创新性与完整性 | 30% |
| 性能与实用性（≤10ms） | 20% |
| 文档与代码质量 | 10% |

## 可复用资源

- `ai-pentest-challenge/skills_hub/skills/waf_bypass.py`
- 公开数据集：SQLi/XSS payload lists、OWASP CRS 测试用例

## 实现目录（占位）

`topics/topic02_web_waf/`
