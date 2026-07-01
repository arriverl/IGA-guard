# 题目 5：基于流量特征的 DNS 隐蔽隧道检测

> **本仓库默认实现赛题**

## 题目背景

DNS 隐蔽隧道是数据外泄和 C2 常用手段。隧道流量在请求频率、域名熵、Payload 大小等方面与正常 DNS 存在差异，适合机器学习检测。

## 系统要求

### 1. DNS 流量解析

- 输入：PCAP 或 DNS 日志 CSV
- 解析：域名、查询类型、响应码、Payload 长度等

### 2. 特征提取（≥10 维）

| # | 特征 | 说明 |
|---|------|------|
| 1 | 查询频率 | 单位时间查询数 |
| 2 | 域名熵 | Shannon entropy |
| 3 | 子域名长度 | 最大/平均 |
| 4 | TXT/NULL 占比 | 非常规记录类型比例 |
| 5 | 请求-响应大小比 | Payload 比值 |
| 6 | CNAME 链长度 | 链式解析深度 |
| 7 | 知名 DNS 占比 | 8.8.8.8、114 等 |
| 8 | 唯一子域数 | 时间窗内 distinct subdomain |
| 9 | 数字字符比 | 域名中 digit 比例 |
| 10 | 非 A/AAAA 查询比 | 异常 qtype 分布 |

### 3. 检测模型

- Random Forest / XGBoost / Isolation Forest / 轻量 NN
- 二分类：正常 vs 隧道

### 4. 告警输出

```json
{
  "is_tunnel": true,
  "confidence": 0.92,
  "risk_level": "high",
  "key_features": {"domain_entropy": 4.8, "query_rate": 120},
  "domain_list": ["aGVsbG8.tunnel.example.com"]
}
```

## 挑战指标

| 指标 | 目标 |
|------|------|
| 检测率 | ≥85% |
| 误报率 | ≤10% |
| 隧道工具识别 | ≥2 种（iodine、dns2tcp、dnscat2） |
| 处理速度 | 10000 条 ≤5 秒 |
| CDN/动态 DNS | 较好区分能力 |

## 架构设计

```
PCAP/CSV → Parser → Per-domain/window Aggregator
                  → Feature Extractor (≥10 dims)
                  → Classifier (.joblib)
                  → Alert Formatter
```

## 数据集构建

### 正常流量

- 本机浏览、apt 更新产生的 DNS
- 公开 PCAP（如 malware-traffic-analysis.net 正常样本）

### 隧道流量

| 工具 | 特征 |
|------|------|
| iodine | 高熵子域、TXT 记录 |
| dnscat2 | 高频短查询、特定编码模式 |
| dns2tcp | CNAME 链、较大 payload |

在隔离 VLAN 中部署服务端与客户端，tcpdump 抓包后标注。

## 评价标准

| 维度 | 权重 |
|------|------|
| 检测效果 | 40% |
| 特征设计 | 20% |
| 模型效率 | 15% |
| 可解释性 | 15% |
| 工程完整度 | 10% |

## 实现路径

`topics/topic05_dns_tunnel/`
